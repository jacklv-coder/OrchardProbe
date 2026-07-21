//! Private, bounded materialization of one preflighted IPA app tree.
//!
//! Archive paths are validated before filesystem effects and are then walked
//! component-by-component through descriptor-relative, no-follow operations.
//! The returned worktree owns a fresh private temporary directory; dropping it
//! removes the tree. This layer never modifies the source IPA or publishes a
//! caller-selected output path.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Permissions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

use rustix::fs::{Mode, OFlags, fstat, mkdirat, open, openat};
use serde::Serialize;
use tempfile::TempDir;
use thiserror::Error;

use crate::ipa::{
    IpaEntry, IpaEntryKind, IpaEntryReadError, IpaInspectError, IpaInventory,
    MAX_IPA_ARCHIVE_BYTES, MAX_IPA_ENTRIES, MAX_IPA_ENTRY_COPY_BYTES,
    MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES, MAX_IPA_TOTAL_UNCOMPRESSED_BYTES, copy_ipa_entry_bounded,
    inspect_ipa,
};

/// Maximum implicit or explicit directories created beneath the private root.
pub const MAX_IPA_WORKTREE_DIRECTORIES: usize = MAX_IPA_ENTRIES;
/// Maximum total archive-derived filesystem nodes in one private worktree.
pub const MAX_IPA_WORKTREE_NODES: usize = MAX_IPA_ENTRIES * 2;

/// Why one validated archive entry was intentionally not materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaWorktreeExclusionReason {
    MasReceipt,
    ScInfo,
}

/// One canonical archive entry excluded from the private worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaWorktreeExcludedEntry {
    pub path: String,
    pub entry: IpaEntry,
    pub reason: IpaWorktreeExclusionReason,
}

/// The provenance of one materialized archive-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaWorktreeEntryKind {
    File,
    ExplicitDirectory,
    ImplicitDirectory,
}

/// One path created below the private root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaWorktreeEntry {
    pub path: String,
    pub kind: IpaWorktreeEntryKind,
    pub bytes_written: u64,
}

/// Owned private worktree and its source-bound materialization evidence.
pub struct IpaPrivateWorktree {
    root_fd: OwnedFd,
    root: TempDir,
    directory_identities: BTreeMap<String, FileIdentity>,
    file_identities: BTreeMap<String, FileIdentity>,
    inventory: IpaInventory,
    entries: Vec<IpaWorktreeEntry>,
    excluded_entries: Vec<IpaWorktreeExcludedEntry>,
    included_compressed_bytes: u64,
    included_uncompressed_bytes: u64,
}

impl IpaPrivateWorktree {
    /// Borrow the private, non-published host path while this owner is alive.
    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// Authoritative source inventory used to create this worktree.
    pub fn inventory(&self) -> &IpaInventory {
        &self.inventory
    }

    /// Canonical-path-sorted materialized records.
    pub fn entries(&self) -> &[IpaWorktreeEntry] {
        &self.entries
    }

    /// Canonical-path-sorted excluded source records.
    pub fn excluded_entries(&self) -> &[IpaWorktreeExcludedEntry] {
        &self.excluded_entries
    }

    /// Checked compressed bytes declared by included source files.
    pub fn included_compressed_bytes(&self) -> u64 {
        self.included_compressed_bytes
    }

    /// Checked uncompressed bytes declared by included source files.
    pub fn included_uncompressed_bytes(&self) -> u64 {
        self.included_uncompressed_bytes
    }

    pub(crate) fn root_fd(&self) -> &OwnedFd {
        &self.root_fd
    }

    pub(crate) fn directory_identities(&self) -> &BTreeMap<String, FileIdentity> {
        &self.directory_identities
    }

    pub(crate) fn file_identities(&self) -> &BTreeMap<String, FileIdentity> {
        &self.file_identities
    }
}

impl fmt::Debug for IpaPrivateWorktree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpaPrivateWorktree")
            .field("root", &"<private temporary directory>")
            .field("inventory", &self.inventory)
            .field("entries", &self.entries)
            .field("excluded_entries", &self.excluded_entries)
            .field("included_compressed_bytes", &self.included_compressed_bytes)
            .field(
                "included_uncompressed_bytes",
                &self.included_uncompressed_bytes,
            )
            .finish()
    }
}

/// Failure before a complete private worktree can be returned.
#[derive(Debug, Error)]
pub enum IpaWorktreeError {
    #[error("IPA preflight failed before worktree creation: {0}")]
    Inspect(#[from] IpaInspectError),

    #[error("regular entry `{ancestor}` is an ancestor of archive path `{path}`")]
    FileAncestor { ancestor: String, path: String },

    #[error("entry `{path}` declares {actual} {field} bytes; worktree maximum is {maximum}")]
    EntryOutsideStreamingProfile {
        path: String,
        field: &'static str,
        actual: u64,
        maximum: u64,
    },

    #[error("worktree exposes {actual} directories; maximum is {maximum}")]
    TooManyDirectories { actual: usize, maximum: usize },

    #[error("worktree exposes {actual} filesystem nodes; maximum is {maximum}")]
    TooManyNodes { actual: usize, maximum: usize },

    #[error("included worktree {field} byte total overflowed")]
    IncludedSizeOverflow { field: &'static str },

    #[error("included worktree {field} bytes {actual} exceed the {maximum}-byte limit")]
    IncludedAggregateTooLarge {
        field: &'static str,
        actual: u64,
        maximum: u64,
    },

    #[error("could not create a private temporary worktree: {source}")]
    TemporaryRoot {
        #[source]
        source: std::io::Error,
    },

    #[error("could not restrict the private temporary worktree: {source}")]
    RootPermissions {
        #[source]
        source: std::io::Error,
    },

    #[error("could not open the private temporary worktree without following links: {source}")]
    RootOpen {
        #[source]
        source: rustix::io::Errno,
    },

    #[error("could not duplicate the private directory handle for `{path}`: {source}")]
    DirectoryHandle {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("could not create private directory `{path}`: {source}")]
    DirectoryCreate {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("could not open private directory `{path}` without following links: {source}")]
    DirectoryOpen {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("private directory identity changed at `{path}`")]
    DirectoryIdentityChanged { path: String },

    #[error("could not query private directory identity for `{path}`: {source}")]
    DirectoryIdentity {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("could not create private file `{path}` without following links: {source}")]
    FileCreate {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("bounded copy into private file `{path}` failed: {source}")]
    EntryCopy {
        path: String,
        #[source]
        source: IpaEntryReadError,
    },

    #[error("IPA inventory changed while materializing `{path}`")]
    InventoryChanged { path: String },

    #[error("could not flush private file `{path}`: {source}")]
    FileFlush {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("could not query private file identity for `{path}`: {source}")]
    FileIdentity {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct WorktreePlan {
    directories: BTreeMap<String, bool>,
    files: Vec<IpaEntry>,
    excluded_entries: Vec<IpaWorktreeExcludedEntry>,
    included_compressed_bytes: u64,
    included_uncompressed_bytes: u64,
}

/// Materialize one validated IPA into a fresh owner-only temporary worktree.
///
/// Success owns all filesystem effects through the returned RAII value. Any
/// error drops the partial temporary directory. Files are created as `0600`
/// and directories as `0700`; archive ownership, timestamps, ACLs, extended
/// attributes, and executable bits are never trusted or preserved here.
pub fn materialize_ipa_private_worktree<R: Read + Seek>(
    reader: R,
    archive_size: u64,
) -> Result<IpaPrivateWorktree, IpaWorktreeError> {
    materialize_with_hook(reader, archive_size, |_, _| {})
}

fn materialize_with_hook<R, F>(
    mut reader: R,
    archive_size: u64,
    mut before_file: F,
) -> Result<IpaPrivateWorktree, IpaWorktreeError>
where
    R: Read + Seek,
    F: FnMut(&Path, &str),
{
    let inventory = inspect_ipa(&mut reader, archive_size)?;
    let plan = build_worktree_plan(&inventory)?;

    let root = tempfile::Builder::new()
        .prefix("orchardprobe-worktree-")
        .tempdir()
        .map_err(|source| IpaWorktreeError::TemporaryRoot { source })?;
    fs::set_permissions(root.path(), Permissions::from_mode(0o700))
        .map_err(|source| IpaWorktreeError::RootPermissions { source })?;
    let root_fd = open(root.path(), directory_open_flags(), Mode::empty())
        .map_err(|source| IpaWorktreeError::RootOpen { source })?;

    let mut identities = BTreeMap::new();
    identities.insert(String::new(), file_identity(&root_fd, "")?);
    let mut file_identities = BTreeMap::new();
    let mut entries = Vec::with_capacity(plan.directories.len() + plan.files.len());

    let mut directories = plan.directories.iter().collect::<Vec<_>>();
    directories.sort_by(|(left_path, _), (right_path, _)| {
        path_depth(left_path)
            .cmp(&path_depth(right_path))
            .then_with(|| left_path.cmp(right_path))
    });
    for (path, explicit) in directories {
        create_directory(&root_fd, path, &mut identities)?;
        entries.push(IpaWorktreeEntry {
            path: path.clone(),
            kind: if *explicit {
                IpaWorktreeEntryKind::ExplicitDirectory
            } else {
                IpaWorktreeEntryKind::ImplicitDirectory
            },
            bytes_written: 0,
        });
    }

    for entry in &plan.files {
        before_file(root.path(), &entry.path);
        let (parent, file_name) = split_parent(&entry.path);
        let parent_fd = open_verified_directory(&root_fd, parent, &identities)?;
        let file_fd = openat(
            &parent_fd,
            file_name,
            file_create_flags(),
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| IpaWorktreeError::FileCreate {
            path: entry.path.clone(),
            source,
        })?;
        let mut output = File::from(file_fd);
        let copied = copy_ipa_entry_bounded(
            &mut reader,
            archive_size,
            &entry.path,
            MAX_IPA_ENTRY_COPY_BYTES,
            &mut output,
        )
        .map_err(|source| IpaWorktreeError::EntryCopy {
            path: entry.path.clone(),
            source,
        })?;
        ensure_inventory_unchanged(&entry.path, &inventory, &copied.inventory)?;
        output
            .flush()
            .map_err(|source| IpaWorktreeError::FileFlush {
                path: entry.path.clone(),
                source,
            })?;
        file_identities.insert(
            entry.path.clone(),
            descriptor_identity(&output).map_err(|source| IpaWorktreeError::FileIdentity {
                path: entry.path.clone(),
                source,
            })?,
        );
        drop(output);
        entries.push(IpaWorktreeEntry {
            path: entry.path.clone(),
            kind: IpaWorktreeEntryKind::File,
            bytes_written: copied.bytes_written,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(IpaPrivateWorktree {
        root_fd,
        root,
        directory_identities: identities,
        file_identities,
        inventory,
        entries,
        excluded_entries: plan.excluded_entries,
        included_compressed_bytes: plan.included_compressed_bytes,
        included_uncompressed_bytes: plan.included_uncompressed_bytes,
    })
}

fn build_worktree_plan(inventory: &IpaInventory) -> Result<WorktreePlan, IpaWorktreeError> {
    validate_tree_shape(inventory)?;
    let mut directories = BTreeMap::new();
    let mut files = Vec::new();
    let mut excluded_entries = Vec::new();
    let mut included_compressed_bytes = 0u64;
    let mut included_uncompressed_bytes = 0u64;

    for entry in &inventory.entries {
        if let Some(reason) = exclusion_reason(&entry.path) {
            excluded_entries.push(IpaWorktreeExcludedEntry {
                path: entry.path.clone(),
                entry: entry.clone(),
                reason,
            });
            continue;
        }

        match entry.kind {
            IpaEntryKind::Directory => {
                add_parent_directories(&mut directories, &entry.path);
                directories
                    .entry(entry.path.clone())
                    .and_modify(|explicit| *explicit = true)
                    .or_insert(true);
            }
            IpaEntryKind::File => {
                validate_streaming_profile(entry)?;
                add_parent_directories(&mut directories, &entry.path);
                included_compressed_bytes = included_compressed_bytes
                    .checked_add(entry.compressed_size)
                    .ok_or(IpaWorktreeError::IncludedSizeOverflow {
                        field: "compressed",
                    })?;
                included_uncompressed_bytes = included_uncompressed_bytes
                    .checked_add(entry.uncompressed_size)
                    .ok_or(IpaWorktreeError::IncludedSizeOverflow {
                        field: "uncompressed",
                    })?;
                files.push(entry.clone());
            }
        }
    }

    if directories.len() > MAX_IPA_WORKTREE_DIRECTORIES {
        return Err(IpaWorktreeError::TooManyDirectories {
            actual: directories.len(),
            maximum: MAX_IPA_WORKTREE_DIRECTORIES,
        });
    }
    let node_count =
        directories
            .len()
            .checked_add(files.len())
            .ok_or(IpaWorktreeError::TooManyNodes {
                actual: usize::MAX,
                maximum: MAX_IPA_WORKTREE_NODES,
            })?;
    if node_count > MAX_IPA_WORKTREE_NODES {
        return Err(IpaWorktreeError::TooManyNodes {
            actual: node_count,
            maximum: MAX_IPA_WORKTREE_NODES,
        });
    }
    validate_aggregate(
        "compressed",
        included_compressed_bytes,
        MAX_IPA_ARCHIVE_BYTES,
    )?;
    validate_aggregate(
        "uncompressed",
        included_uncompressed_bytes,
        MAX_IPA_TOTAL_UNCOMPRESSED_BYTES,
    )?;

    Ok(WorktreePlan {
        directories,
        files,
        excluded_entries,
        included_compressed_bytes,
        included_uncompressed_bytes,
    })
}

fn validate_tree_shape(inventory: &IpaInventory) -> Result<(), IpaWorktreeError> {
    let kinds = inventory
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry.kind))
        .collect::<BTreeMap<_, _>>();
    for entry in &inventory.entries {
        let mut current = entry.path.as_str();
        while let Some((parent, _)) = current.rsplit_once('/') {
            if kinds.get(parent) == Some(&IpaEntryKind::File) {
                return Err(IpaWorktreeError::FileAncestor {
                    ancestor: parent.to_owned(),
                    path: entry.path.clone(),
                });
            }
            current = parent;
        }
    }
    Ok(())
}

fn exclusion_reason(path: &str) -> Option<IpaWorktreeExclusionReason> {
    if path.split('/').any(|component| component == "_MASReceipt") {
        Some(IpaWorktreeExclusionReason::MasReceipt)
    } else if path.split('/').any(|component| component == "SC_Info") {
        Some(IpaWorktreeExclusionReason::ScInfo)
    } else {
        None
    }
}

fn add_parent_directories(directories: &mut BTreeMap<String, bool>, path: &str) {
    let components = path.split('/').collect::<Vec<_>>();
    for end in 1..components.len() {
        directories
            .entry(components[..end].join("/"))
            .or_insert(false);
    }
}

fn validate_streaming_profile(entry: &IpaEntry) -> Result<(), IpaWorktreeError> {
    for (field, actual, maximum) in [
        (
            "compressed",
            entry.compressed_size,
            MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES,
        ),
        (
            "uncompressed",
            entry.uncompressed_size,
            MAX_IPA_ENTRY_COPY_BYTES,
        ),
    ] {
        if actual > maximum {
            return Err(IpaWorktreeError::EntryOutsideStreamingProfile {
                path: entry.path.clone(),
                field,
                actual,
                maximum,
            });
        }
    }
    Ok(())
}

fn validate_aggregate(
    field: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), IpaWorktreeError> {
    if actual > maximum {
        return Err(IpaWorktreeError::IncludedAggregateTooLarge {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn create_directory(
    root_fd: &OwnedFd,
    path: &str,
    identities: &mut BTreeMap<String, FileIdentity>,
) -> Result<(), IpaWorktreeError> {
    let (parent, directory_name) = split_parent(path);
    let parent_fd = open_verified_directory(root_fd, parent, identities)?;
    mkdirat(&parent_fd, directory_name, Mode::RWXU).map_err(|source| {
        IpaWorktreeError::DirectoryCreate {
            path: path.to_owned(),
            source,
        }
    })?;
    let directory_fd = openat(
        &parent_fd,
        directory_name,
        directory_open_flags(),
        Mode::empty(),
    )
    .map_err(|source| IpaWorktreeError::DirectoryOpen {
        path: path.to_owned(),
        source,
    })?;
    identities.insert(path.to_owned(), file_identity(&directory_fd, path)?);
    Ok(())
}

pub(crate) fn open_verified_directory(
    root_fd: &OwnedFd,
    path: &str,
    identities: &BTreeMap<String, FileIdentity>,
) -> Result<OwnedFd, IpaWorktreeError> {
    let mut current =
        rustix::io::dup(root_fd).map_err(|source| IpaWorktreeError::DirectoryHandle {
            path: path.to_owned(),
            source,
        })?;
    verify_identity(&current, "", identities)?;
    if path.is_empty() {
        return Ok(current);
    }

    let mut canonical = String::new();
    for component in path.split('/') {
        if !canonical.is_empty() {
            canonical.push('/');
        }
        canonical.push_str(component);
        current = openat(&current, component, directory_open_flags(), Mode::empty()).map_err(
            |source| IpaWorktreeError::DirectoryOpen {
                path: canonical.clone(),
                source,
            },
        )?;
        verify_identity(&current, &canonical, identities)?;
    }
    Ok(current)
}

fn verify_identity(
    fd: &OwnedFd,
    path: &str,
    identities: &BTreeMap<String, FileIdentity>,
) -> Result<(), IpaWorktreeError> {
    let actual = file_identity(fd, path)?;
    if identities.get(path) != Some(&actual) {
        return Err(IpaWorktreeError::DirectoryIdentityChanged {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn file_identity<Fd: AsFd>(fd: Fd, path: &str) -> Result<FileIdentity, IpaWorktreeError> {
    descriptor_identity(fd).map_err(|source| IpaWorktreeError::DirectoryIdentity {
        path: path.to_owned(),
        source,
    })
}

pub(crate) fn descriptor_identity<Fd: AsFd>(fd: Fd) -> Result<FileIdentity, rustix::io::Errno> {
    let stat = fstat(fd)?;
    Ok(FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

fn ensure_inventory_unchanged(
    path: &str,
    expected: &IpaInventory,
    actual: &IpaInventory,
) -> Result<(), IpaWorktreeError> {
    if expected != actual {
        return Err(IpaWorktreeError::InventoryChanged {
            path: path.to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn split_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn path_depth(path: &str) -> usize {
    path.bytes().filter(|byte| *byte == b'/').count() + 1
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn file_create_flags() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::rc::Rc;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    const APP_ROOT: &str = "Payload/Demo.app";
    const CORRUPT_PAYLOAD: &[u8] = b"corrupt-this-stored-payload";

    struct DenyPayloadReader {
        inner: Cursor<Vec<u8>>,
        denied_start: u64,
    }

    struct SwitchingReader {
        first: Cursor<Vec<u8>>,
        second: Cursor<Vec<u8>>,
        use_second: Rc<Cell<bool>>,
    }

    impl SwitchingReader {
        fn new(first: Vec<u8>, second: Vec<u8>, use_second: Rc<Cell<bool>>) -> Self {
            assert_eq!(first.len(), second.len());
            Self {
                first: Cursor::new(first),
                second: Cursor::new(second),
                use_second,
            }
        }

        fn active(&mut self) -> &mut Cursor<Vec<u8>> {
            if self.use_second.get() {
                &mut self.second
            } else {
                &mut self.first
            }
        }
    }

    impl Read for SwitchingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.active().read(output)
        }
    }

    impl Seek for SwitchingReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.active().seek(position)
        }
    }

    impl DenyPayloadReader {
        fn new(bytes: Vec<u8>, needle: &[u8]) -> Self {
            let denied_start = bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("find denied payload") as u64;
            Self {
                inner: Cursor::new(bytes),
                denied_start,
            }
        }
    }

    impl Read for DenyPayloadReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.inner.position() == self.denied_start {
                return Err(std::io::Error::other(
                    "payload read before destination-tree validation",
                ));
            }
            self.inner.read(output)
        }
    }

    impl Seek for DenyPayloadReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    fn options(method: CompressionMethod) -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o755)
    }

    fn fixture() -> Vec<u8> {
        fixture_with_info(b"plist bytes")
    }

    fn fixture_with_info(info: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_directory("Payload/", options(CompressionMethod::Stored))
            .expect("Payload directory");
        writer
            .add_directory(format!("{APP_ROOT}/"), options(CompressionMethod::Stored))
            .expect("app directory");
        for (path, bytes, method) in [
            (
                format!("{APP_ROOT}/Info.plist"),
                info,
                CompressionMethod::Stored,
            ),
            (
                format!("{APP_ROOT}/Implicit/Nested.bin"),
                b"deflated nested bytes".as_slice(),
                CompressionMethod::Deflated,
            ),
            (
                format!("{APP_ROOT}/_MASReceipt/receipt"),
                b"excluded receipt".as_slice(),
                CompressionMethod::Stored,
            ),
            (
                format!("{APP_ROOT}/SC_Info/secret.sinf"),
                b"excluded sc info".as_slice(),
                CompressionMethod::Stored,
            ),
            (
                format!("{APP_ROOT}/SC_Info.txt"),
                b"not an excluded component".as_slice(),
                CompressionMethod::Stored,
            ),
        ] {
            writer
                .start_file(path, options(method))
                .expect("start file");
            writer.write_all(bytes).expect("write file");
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    #[test]
    fn materializes_stored_and_deflated_bytes_with_exclusions_and_cleanup() {
        let bytes = fixture();
        let original = bytes.clone();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&bytes), bytes.len() as u64)
            .expect("materialize private worktree");

        assert_eq!(bytes, original);
        assert_eq!(
            fs::read(worktree.path().join(format!("{APP_ROOT}/Info.plist")))
                .expect("read stored output"),
            b"plist bytes"
        );
        assert_eq!(
            fs::read(
                worktree
                    .path()
                    .join(format!("{APP_ROOT}/Implicit/Nested.bin"))
            )
            .expect("read deflated output"),
            b"deflated nested bytes"
        );
        assert!(
            !worktree
                .path()
                .join(format!("{APP_ROOT}/_MASReceipt"))
                .exists()
        );
        assert!(!worktree.path().join(format!("{APP_ROOT}/SC_Info")).exists());
        assert_eq!(
            fs::read(worktree.path().join(format!("{APP_ROOT}/SC_Info.txt")))
                .expect("read similar non-excluded output"),
            b"not an excluded component"
        );
        assert_eq!(
            worktree
                .excluded_entries
                .iter()
                .map(|entry| (entry.path.as_str(), entry.reason))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Payload/Demo.app/SC_Info/secret.sinf",
                    IpaWorktreeExclusionReason::ScInfo,
                ),
                (
                    "Payload/Demo.app/_MASReceipt/receipt",
                    IpaWorktreeExclusionReason::MasReceipt,
                ),
            ]
        );
        assert!(worktree.entries.iter().any(|entry| {
            entry.path == "Payload/Demo.app/Implicit"
                && entry.kind == IpaWorktreeEntryKind::ImplicitDirectory
        }));

        let root_mode = fs::metadata(worktree.path()).expect("root metadata").mode() & 0o777;
        let file_mode = fs::metadata(worktree.path().join(format!("{APP_ROOT}/Info.plist")))
            .expect("file metadata")
            .mode()
            & 0o777;
        let directory_mode = fs::metadata(worktree.path().join(format!("{APP_ROOT}/Implicit")))
            .expect("directory metadata")
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let second = materialize_ipa_private_worktree(Cursor::new(&bytes), bytes.len() as u64)
            .expect("repeat materialization");
        assert_eq!(worktree.entries, second.entries);
        assert_eq!(worktree.excluded_entries, second.excluded_entries);
        assert_eq!(
            worktree.included_compressed_bytes,
            second.included_compressed_bytes
        );
        assert_eq!(
            worktree.included_uncompressed_bytes,
            second.included_uncompressed_bytes
        );

        let root_path = worktree.path().to_owned();
        drop(worktree);
        assert!(!root_path.exists());
    }

    #[test]
    fn rejects_file_ancestor_before_payload_reads() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .start_file(
                format!("{APP_ROOT}/_MASReceipt"),
                options(CompressionMethod::Stored),
            )
            .expect("ancestor file");
        writer.write_all(CORRUPT_PAYLOAD).expect("ancestor bytes");
        writer
            .start_file(
                format!("{APP_ROOT}/_MASReceipt/Child"),
                options(CompressionMethod::Stored),
            )
            .expect("descendant file");
        writer.write_all(b"child").expect("child bytes");
        let bytes = writer.finish().expect("finish IPA").into_inner();
        let size = bytes.len() as u64;

        assert!(matches!(
            materialize_ipa_private_worktree(DenyPayloadReader::new(bytes, CORRUPT_PAYLOAD), size,),
            Err(IpaWorktreeError::FileAncestor { .. })
        ));
    }

    #[test]
    fn descriptor_walk_rejects_symlink_replacement_without_escape() {
        let bytes = fixture();
        let outside = tempfile::tempdir().expect("outside tempdir");
        let outside_file = outside.path().join("sentinel");
        fs::write(&outside_file, b"unchanged").expect("outside sentinel");
        let observed_root = Rc::new(RefCell::new(None::<PathBuf>));
        let captured_root = Rc::clone(&observed_root);
        let outside_path = outside.path().to_owned();

        let result = materialize_with_hook(
            Cursor::new(&bytes),
            bytes.len() as u64,
            move |root, path| {
                *captured_root.borrow_mut() = Some(root.to_owned());
                if path.ends_with("Implicit/Nested.bin") {
                    let implicit = root.join(format!("{APP_ROOT}/Implicit"));
                    fs::remove_dir(&implicit).expect("remove planned directory");
                    symlink(&outside_path, &implicit).expect("replace with symlink");
                }
            },
        );

        assert!(matches!(
            result,
            Err(IpaWorktreeError::DirectoryOpen { .. })
        ));
        assert_eq!(
            fs::read(outside_file).expect("outside remains"),
            b"unchanged"
        );
        let root = observed_root
            .borrow()
            .clone()
            .expect("observe worktree root");
        assert!(!root.exists());
    }

    #[test]
    fn descriptor_walk_rejects_directory_identity_drift() {
        let bytes = fixture();
        let observed_root = Rc::new(RefCell::new(None::<PathBuf>));
        let captured_root = Rc::clone(&observed_root);
        let result = materialize_with_hook(
            Cursor::new(&bytes),
            bytes.len() as u64,
            move |root, path| {
                *captured_root.borrow_mut() = Some(root.to_owned());
                if path.ends_with("Implicit/Nested.bin") {
                    let implicit = root.join(format!("{APP_ROOT}/Implicit"));
                    // Keep the removed inode referenced until its replacement
                    // exists. Some Linux filesystems otherwise immediately
                    // reuse it, which would not represent identity drift.
                    let original = File::open(&implicit).expect("hold planned directory inode");
                    fs::remove_dir(&implicit).expect("remove planned directory");
                    fs::create_dir(&implicit).expect("replace planned directory");
                    drop(original);
                }
            },
        );

        assert!(matches!(
            result,
            Err(IpaWorktreeError::DirectoryIdentityChanged { .. })
        ));
        let root = observed_root
            .borrow()
            .clone()
            .expect("observe worktree root");
        assert!(!root.exists());
    }

    #[test]
    fn create_new_collision_fails_and_cleans_the_partial_tree() {
        let bytes = fixture();
        let observed_root = Rc::new(RefCell::new(None::<PathBuf>));
        let captured_root = Rc::clone(&observed_root);
        let result = materialize_with_hook(
            Cursor::new(&bytes),
            bytes.len() as u64,
            move |root, path| {
                *captured_root.borrow_mut() = Some(root.to_owned());
                if path.ends_with("Info.plist") {
                    fs::write(root.join(path), b"collision").expect("create collision");
                }
            },
        );

        assert!(matches!(result, Err(IpaWorktreeError::FileCreate { .. })));
        let root = observed_root
            .borrow()
            .clone()
            .expect("observe worktree root");
        assert!(!root.exists());
    }

    #[test]
    fn crc_failure_cleans_partial_output() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .start_file(
                format!("{APP_ROOT}/Corrupt.bin"),
                options(CompressionMethod::Stored),
            )
            .expect("corrupt file");
        writer.write_all(CORRUPT_PAYLOAD).expect("corrupt payload");
        let mut bytes = writer.finish().expect("finish IPA").into_inner();
        let offset = bytes
            .windows(CORRUPT_PAYLOAD.len())
            .position(|window| window == CORRUPT_PAYLOAD)
            .expect("find stored payload");
        bytes[offset] ^= 1;
        let observed_root = Rc::new(RefCell::new(None::<PathBuf>));
        let captured_root = Rc::clone(&observed_root);
        let result =
            materialize_with_hook(Cursor::new(&bytes), bytes.len() as u64, move |root, _| {
                *captured_root.borrow_mut() = Some(root.to_owned())
            });
        assert!(matches!(result, Err(IpaWorktreeError::EntryCopy { .. })));
        let root = observed_root
            .borrow()
            .clone()
            .expect("observe worktree root");
        assert!(!root.exists());
    }

    #[test]
    fn changed_source_inventory_fails_and_cleans_the_partial_tree() {
        let first = fixture_with_info(b"plist bytes");
        let second = fixture_with_info(b"other bytes");
        let use_second = Rc::new(Cell::new(false));
        let switch = Rc::clone(&use_second);
        let observed_root = Rc::new(RefCell::new(None::<PathBuf>));
        let captured_root = Rc::clone(&observed_root);
        let size = first.len() as u64;

        let result = materialize_with_hook(
            SwitchingReader::new(first, second, use_second),
            size,
            move |root, _| {
                *captured_root.borrow_mut() = Some(root.to_owned());
                switch.set(true);
            },
        );

        assert!(matches!(
            result,
            Err(IpaWorktreeError::InventoryChanged { .. })
        ));
        let root = observed_root
            .borrow()
            .clone()
            .expect("observe worktree root");
        assert!(!root.exists());
    }

    #[test]
    fn plan_bounds_entry_sizes_aggregates_and_implicit_directories() {
        let oversized = synthetic_inventory(vec![synthetic_entry(
            &format!("{APP_ROOT}/Huge.bin"),
            MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES + 1,
            1,
        )]);
        assert!(matches!(
            build_worktree_plan(&oversized),
            Err(IpaWorktreeError::EntryOutsideStreamingProfile {
                field: "compressed",
                ..
            })
        ));

        let aggregate = synthetic_inventory(
            (0..33)
                .map(|index| {
                    synthetic_entry(
                        &format!("{APP_ROOT}/F{index}.bin"),
                        MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES,
                        1,
                    )
                })
                .collect(),
        );
        assert!(matches!(
            build_worktree_plan(&aggregate),
            Err(IpaWorktreeError::IncludedAggregateTooLarge {
                field: "compressed",
                ..
            })
        ));

        let many_directories = synthetic_inventory(
            (0..600)
                .map(|index| {
                    let components = (0..29)
                        .map(|depth| format!("d{index}_{depth}"))
                        .collect::<Vec<_>>()
                        .join("/");
                    synthetic_entry(&format!("{APP_ROOT}/{components}/file"), 1, 1)
                })
                .collect(),
        );
        assert!(matches!(
            build_worktree_plan(&many_directories),
            Err(IpaWorktreeError::TooManyDirectories { .. })
        ));
    }

    fn synthetic_entry(path: &str, compressed_size: u64, uncompressed_size: u64) -> IpaEntry {
        IpaEntry {
            path: path.to_owned(),
            kind: IpaEntryKind::File,
            executable: false,
            compressed_size,
            uncompressed_size,
            crc32: 0,
        }
    }

    fn synthetic_inventory(entries: Vec<IpaEntry>) -> IpaInventory {
        IpaInventory {
            archive_size: 1,
            app_root: APP_ROOT.to_owned(),
            entry_count: entries.len(),
            file_count: entries.len(),
            directory_count: 0,
            total_compressed_size: entries.iter().map(|entry| entry.compressed_size).sum(),
            total_uncompressed_size: entries.iter().map(|entry| entry.uncompressed_size).sum(),
            entries,
        }
    }
}
