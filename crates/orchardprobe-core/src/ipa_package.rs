//! Deterministic, unsigned packaging of one owned private IPA worktree.
//!
//! Packaging consumes only the immutable records and retained descriptor
//! boundary of [`IpaPrivateWorktree`]. It never discovers archive entries from
//! host paths, publishes to a caller-selected destination, modifies Mach-O,
//! signs output, or claims that any payload is decrypted plaintext.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, Permissions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crc32fast::Hasher;
use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, openat};
use serde::Serialize;
use tempfile::NamedTempFile;
use thiserror::Error;
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::ipa::{
    IpaEntryKind, IpaInspectError, IpaInventory, MAX_IPA_ARCHIVE_BYTES, MAX_IPA_ENTRIES,
    inspect_ipa,
};
use crate::ipa_materialize::{
    FileIdentity, IpaPrivateWorktree, IpaWorktreeEntryKind, IpaWorktreeError,
    IpaWorktreeExcludedEntry, descriptor_identity, open_verified_directory, split_parent,
};

/// Maximum complete deterministic package length.
pub const MAX_IPA_PACKAGE_BYTES: u64 = MAX_IPA_ARCHIVE_BYTES;
/// Stable normalized-metadata policy version.
pub const IPA_PACKAGE_POLICY_VERSION: u32 = 1;
const IPA_PACKAGE_COMPRESSION_LEVEL: i64 = 6;
const IPA_PACKAGE_TIMESTAMP: &str = "1980-01-01T00:00:00";
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// The only semantic state produced by this device-free packaging layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaPackageState {
    UnsignedAnalysisOnly,
}

/// Deterministic ZIP and normalized metadata policy recorded with an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaPackagePolicy {
    pub version: u32,
    pub compression: &'static str,
    pub compression_level: i64,
    pub timestamp: &'static str,
    pub directory_mode: u32,
    pub executable_file_mode: u32,
    pub regular_file_mode: u32,
}

impl Default for IpaPackagePolicy {
    fn default() -> Self {
        Self {
            version: IPA_PACKAGE_POLICY_VERSION,
            compression: "deflate",
            compression_level: IPA_PACKAGE_COMPRESSION_LEVEL,
            timestamp: IPA_PACKAGE_TIMESTAMP,
            directory_mode: 0o755,
            executable_file_mode: 0o755,
            regular_file_mode: 0o644,
        }
    }
}

/// One canonical entry emitted under the deterministic metadata policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaPackageEntry {
    pub path: String,
    pub kind: IpaEntryKind,
    pub bytes: u64,
    pub crc32: u32,
    pub unix_mode: u32,
}

/// Owned, automatically cleaned, unsigned analysis IPA.
pub struct IpaAnalysisArchive {
    artifact: NamedTempFile,
    source_inventory: IpaInventory,
    output_inventory: IpaInventory,
    entries: Vec<IpaPackageEntry>,
    excluded_entries: Vec<IpaWorktreeExcludedEntry>,
    byte_len: u64,
    policy: IpaPackagePolicy,
    state: IpaPackageState,
}

impl IpaAnalysisArchive {
    /// Authoritative source inventory retained from the private worktree.
    pub fn source_inventory(&self) -> &IpaInventory {
        &self.source_inventory
    }

    /// Final bounded-preflight inventory of the emitted temporary IPA.
    pub fn output_inventory(&self) -> &IpaInventory {
        &self.output_inventory
    }

    /// Canonical-path-sorted package plan and normalized metadata evidence.
    pub fn entries(&self) -> &[IpaPackageEntry] {
        &self.entries
    }

    /// Canonical-path-sorted exclusions inherited from worktree materialization.
    pub fn excluded_entries(&self) -> &[IpaWorktreeExcludedEntry] {
        &self.excluded_entries
    }

    /// Exact complete archive length after finalization and preflight.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Deterministic normalization policy used for this artifact.
    pub fn policy(&self) -> &IpaPackagePolicy {
        &self.policy
    }

    /// Explicit non-decryption semantic state of this artifact.
    pub fn state(&self) -> IpaPackageState {
        self.state
    }
}

impl Read for IpaAnalysisArchive {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.artifact.as_file_mut().read(output)
    }
}

impl Seek for IpaAnalysisArchive {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.artifact.as_file_mut().seek(position)
    }
}

impl fmt::Debug for IpaAnalysisArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpaAnalysisArchive")
            .field("artifact", &"<private temporary IPA>")
            .field("source_inventory", &self.source_inventory)
            .field("output_inventory", &self.output_inventory)
            .field("entries", &self.entries)
            .field("excluded_entries", &self.excluded_entries)
            .field("byte_len", &self.byte_len)
            .field("policy", &self.policy)
            .field("state", &self.state)
            .finish()
    }
}

/// Failure before a complete validated temporary package can be returned.
#[derive(Debug, Error)]
pub enum IpaPackageError {
    #[error("private worktree boundary validation failed: {0}")]
    WorktreeBoundary(#[from] IpaWorktreeError),

    #[error("private worktree contents changed beneath directory `{directory}`")]
    TreeContentsChanged { directory: String },

    #[error("could not enumerate private directory `{directory}`: {source}")]
    DirectoryRead {
        directory: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("private worktree has no recorded identity for `{path}`")]
    MissingIdentity { path: String },

    #[error("could not open private file `{path}` without following links: {source}")]
    FileOpen {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("could not query private file metadata for `{path}`: {source}")]
    FileMetadata {
        path: String,
        #[source]
        source: rustix::io::Errno,
    },

    #[error("private worktree node `{path}` is no longer a regular file")]
    FileKindChanged { path: String },

    #[error("private worktree file identity changed at `{path}`")]
    FileIdentityChanged { path: String },

    #[error("private worktree file `{path}` has {actual} bytes; expected {expected}")]
    FileSizeChanged {
        path: String,
        expected: u64,
        actual: u64,
    },

    #[error("private worktree file `{path}` changed while packaging")]
    FileChangedDuringRead { path: String },

    #[error("could not read private worktree file `{path}`: {source}")]
    FileRead {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("private worktree file `{path}` ended after {actual} of {expected} bytes")]
    FileShortRead {
        path: String,
        expected: u64,
        actual: u64,
    },

    #[error("private worktree file `{path}` produced more than {expected} bytes")]
    FileLongRead { path: String, expected: u64 },

    #[error("could not create a private temporary analysis IPA: {source}")]
    TemporaryOutput {
        #[source]
        source: io::Error,
    },

    #[error("could not restrict the private temporary analysis IPA: {source}")]
    OutputPermissions {
        #[source]
        source: io::Error,
    },

    #[error("deterministic package exceeds the {maximum}-byte output limit")]
    OutputTooLarge { maximum: u64 },

    #[error("deterministic package needs {actual} entries; maximum is {maximum}")]
    TooManyEntries { actual: usize, maximum: usize },

    #[error("could not start deterministic archive entry `{path}`: {source}")]
    ArchiveEntry {
        path: String,
        #[source]
        source: ZipError,
    },

    #[error("could not write deterministic archive entry `{path}`: {source}")]
    ArchiveEntryWrite {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("could not finalize the deterministic analysis IPA: {source}")]
    ArchiveFinalize {
        #[source]
        source: ZipError,
    },

    #[error("could not flush the deterministic analysis IPA: {source}")]
    OutputFlush {
        #[source]
        source: io::Error,
    },

    #[error("could not query the deterministic analysis IPA length: {source}")]
    OutputMetadata {
        #[source]
        source: io::Error,
    },

    #[error("deterministic analysis IPA failed final preflight: {0}")]
    OutputInspect(#[source] IpaInspectError),

    #[error("deterministic analysis IPA does not match its packaging plan: {reason}")]
    OutputInventoryMismatch { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    identity: FileIdentity,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug)]
struct OutputLimitMarker;

impl fmt::Display for OutputLimitMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deterministic package output limit exceeded")
    }
}

impl std::error::Error for OutputLimitMarker {}

struct BoundedWriter<W> {
    inner: W,
    position: u64,
    high_water: u64,
    maximum: u64,
}

impl<W: Write + Seek> BoundedWriter<W> {
    fn new(mut inner: W, maximum: u64) -> io::Result<Self> {
        let position = inner.stream_position()?;
        Ok(Self {
            inner,
            position,
            high_water: position,
            maximum,
        })
    }

    fn high_water(&self) -> u64 {
        self.high_water
    }

    fn limit_error() -> io::Error {
        io::Error::other(OutputLimitMarker)
    }
}

impl<W: Write + Seek> Write for BoundedWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(input.len() as u64)
            .ok_or_else(Self::limit_error)?;
        if end > self.maximum {
            return Err(Self::limit_error());
        }
        let written = self.inner.write(input)?;
        self.position = self
            .position
            .checked_add(written as u64)
            .ok_or_else(Self::limit_error)?;
        self.high_water = self.high_water.max(self.position);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek> Seek for BoundedWriter<W> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let actual = self.inner.seek(position)?;
        if actual > self.maximum {
            return Err(Self::limit_error());
        }
        self.position = actual;
        Ok(actual)
    }
}

/// Rebuild one deterministic, unsigned, automatically cleaned analysis IPA.
pub fn package_ipa_analysis_worktree(
    worktree: &IpaPrivateWorktree,
) -> Result<IpaAnalysisArchive, IpaPackageError> {
    package_with_options(worktree, MAX_IPA_PACKAGE_BYTES, |_| {}, |_| {})
}

fn package_with_options<F, G>(
    worktree: &IpaPrivateWorktree,
    maximum_output: u64,
    observe_output: F,
    after_finalize: G,
) -> Result<IpaAnalysisArchive, IpaPackageError>
where
    F: FnOnce(&Path),
    G: FnOnce(&Path),
{
    validate_exact_tree(worktree)?;
    let policy = IpaPackagePolicy::default();
    let mut records = package_records(worktree, &policy)?;
    let source_entries = worktree
        .inventory()
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut artifact = tempfile::Builder::new()
        .prefix("orchardprobe-analysis-")
        .suffix(".ipa")
        .tempfile()
        .map_err(|source| IpaPackageError::TemporaryOutput { source })?;
    artifact
        .as_file()
        .set_permissions(Permissions::from_mode(0o600))
        .map_err(|source| IpaPackageError::OutputPermissions { source })?;
    observe_output(artifact.path());

    let mut snapshots = BTreeMap::new();
    let byte_len;
    {
        let bounded = BoundedWriter::new(artifact.as_file_mut(), maximum_output)
            .map_err(|source| IpaPackageError::OutputFlush { source })?;
        let mut archive = ZipWriter::new(bounded);
        for record in &mut records {
            match record.kind {
                IpaEntryKind::Directory => {
                    archive
                        .add_directory(&record.path, directory_options())
                        .map_err(|source| {
                            map_zip_entry_error(&record.path, source, maximum_output)
                        })?;
                }
                IpaEntryKind::File => {
                    let source_entry = source_entries.get(record.path.as_str()).ok_or({
                        IpaPackageError::OutputInventoryMismatch {
                            reason: "materialized file is absent from the source inventory",
                        }
                    })?;
                    archive
                        .start_file(
                            &record.path,
                            file_options(source_entry.executable, source_entry.uncompressed_size),
                        )
                        .map_err(|source| {
                            map_zip_entry_error(&record.path, source, maximum_output)
                        })?;
                    let (snapshot, crc32) =
                        copy_file_into_archive(worktree, record, &mut archive, maximum_output)?;
                    record.crc32 = crc32;
                    snapshots.insert(record.path.clone(), snapshot);
                }
            }
        }
        let mut bounded = archive
            .finish()
            .map_err(|source| map_zip_finalize_error(source, maximum_output))?;
        bounded
            .flush()
            .map_err(|source| map_output_io_error(source, maximum_output))?;
        byte_len = bounded.high_water();
    }
    after_finalize(artifact.path());

    let metadata_len = artifact
        .as_file()
        .metadata()
        .map_err(|source| IpaPackageError::OutputMetadata { source })?
        .len();
    if metadata_len != byte_len {
        return Err(IpaPackageError::OutputInventoryMismatch {
            reason: "final output length differs from bounded writer accounting",
        });
    }

    validate_exact_tree(worktree)?;
    validate_final_file_snapshots(worktree, &snapshots)?;

    artifact
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|source| IpaPackageError::OutputFlush { source })?;
    let output_inventory =
        inspect_ipa(artifact.as_file_mut(), byte_len).map_err(IpaPackageError::OutputInspect)?;
    validate_output_inventory(worktree, &records, &output_inventory)?;
    artifact
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(|source| IpaPackageError::OutputFlush { source })?;

    Ok(IpaAnalysisArchive {
        artifact,
        source_inventory: worktree.inventory().clone(),
        output_inventory,
        entries: records,
        excluded_entries: worktree.excluded_entries().to_vec(),
        byte_len,
        policy,
        state: IpaPackageState::UnsignedAnalysisOnly,
    })
}

fn package_records(
    worktree: &IpaPrivateWorktree,
    policy: &IpaPackagePolicy,
) -> Result<Vec<IpaPackageEntry>, IpaPackageError> {
    validate_package_entry_count(worktree.entries().len())?;
    let source_entries = worktree
        .inventory()
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut records = Vec::with_capacity(worktree.entries().len());
    for entry in worktree.entries() {
        let (kind, bytes, crc32, unix_mode) = match entry.kind {
            IpaWorktreeEntryKind::File => {
                let source = source_entries.get(entry.path.as_str()).ok_or({
                    IpaPackageError::OutputInventoryMismatch {
                        reason: "materialized file is absent from the source inventory",
                    }
                })?;
                if source.kind != IpaEntryKind::File
                    || source.uncompressed_size != entry.bytes_written
                {
                    return Err(IpaPackageError::OutputInventoryMismatch {
                        reason: "materialized file record differs from the source inventory",
                    });
                }
                (
                    IpaEntryKind::File,
                    entry.bytes_written,
                    0,
                    if source.executable {
                        policy.executable_file_mode
                    } else {
                        policy.regular_file_mode
                    },
                )
            }
            IpaWorktreeEntryKind::ExplicitDirectory | IpaWorktreeEntryKind::ImplicitDirectory => {
                (IpaEntryKind::Directory, 0, 0, policy.directory_mode)
            }
        };
        records.push(IpaPackageEntry {
            path: entry.path.clone(),
            kind,
            bytes,
            crc32,
            unix_mode,
        });
    }
    if !records.windows(2).all(|pair| pair[0].path < pair[1].path) {
        return Err(IpaPackageError::OutputInventoryMismatch {
            reason: "materialized records are not in strict canonical path order",
        });
    }
    Ok(records)
}

fn validate_package_entry_count(actual: usize) -> Result<(), IpaPackageError> {
    if actual > MAX_IPA_ENTRIES {
        return Err(IpaPackageError::TooManyEntries {
            actual,
            maximum: MAX_IPA_ENTRIES,
        });
    }
    Ok(())
}

fn validate_exact_tree(worktree: &IpaPrivateWorktree) -> Result<(), IpaPackageError> {
    let mut expected = BTreeMap::<String, BTreeSet<Vec<u8>>>::new();
    expected.entry(String::new()).or_default();
    for entry in worktree.entries() {
        let (parent, name) = split_parent(&entry.path);
        expected
            .entry(parent.to_owned())
            .or_default()
            .insert(name.as_bytes().to_vec());
        if entry.kind != IpaWorktreeEntryKind::File {
            expected.entry(entry.path.clone()).or_default();
        }
    }

    for (directory, expected_children) in expected {
        let fd = open_verified_directory(
            worktree.root_fd(),
            &directory,
            worktree.directory_identities(),
        )?;
        let mut stream = Dir::read_from(&fd).map_err(|source| IpaPackageError::DirectoryRead {
            directory: directory.clone(),
            source,
        })?;
        let mut actual = BTreeSet::new();
        for result in &mut stream {
            let entry = result.map_err(|source| IpaPackageError::DirectoryRead {
                directory: directory.clone(),
                source,
            })?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            actual.insert(name.to_vec());
            if actual.len() > expected_children.len() {
                return Err(IpaPackageError::TreeContentsChanged { directory });
            }
        }
        if actual != expected_children {
            return Err(IpaPackageError::TreeContentsChanged { directory });
        }
    }
    Ok(())
}

fn copy_file_into_archive<W: Write + Seek>(
    worktree: &IpaPrivateWorktree,
    record: &IpaPackageEntry,
    archive: &mut ZipWriter<W>,
    maximum_output: u64,
) -> Result<(FileSnapshot, u32), IpaPackageError> {
    let mut input = open_verified_file(worktree, &record.path, record.bytes)?;
    let before = file_snapshot(&input, &record.path)?;
    let crc32 = copy_exact_file_bytes(
        &mut input,
        archive,
        &record.path,
        record.bytes,
        maximum_output,
    )?;
    let after = file_snapshot(&input, &record.path)?;
    if before != after {
        return Err(IpaPackageError::FileChangedDuringRead {
            path: record.path.clone(),
        });
    }
    Ok((after, crc32))
}

fn copy_exact_file_bytes<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    path: &str,
    expected: u64,
    maximum_output: u64,
) -> Result<u32, IpaPackageError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut actual = 0u64;
    let mut hasher = Hasher::new();
    while actual < expected {
        let remaining = expected - actual;
        let capacity = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .expect("bounded copy capacity fits usize");
        let count =
            input
                .read(&mut buffer[..capacity])
                .map_err(|source| IpaPackageError::FileRead {
                    path: path.to_owned(),
                    source,
                })?;
        if count == 0 {
            return Err(IpaPackageError::FileShortRead {
                path: path.to_owned(),
                expected,
                actual,
            });
        }
        output
            .write_all(&buffer[..count])
            .map_err(|source| map_archive_write_error(path, source, maximum_output))?;
        hasher.update(&buffer[..count]);
        actual += count as u64;
    }
    let mut probe = [0u8; 1];
    if input
        .read(&mut probe)
        .map_err(|source| IpaPackageError::FileRead {
            path: path.to_owned(),
            source,
        })?
        != 0
    {
        return Err(IpaPackageError::FileLongRead {
            path: path.to_owned(),
            expected,
        });
    }
    Ok(hasher.finalize())
}

fn open_verified_file(
    worktree: &IpaPrivateWorktree,
    path: &str,
    expected_size: u64,
) -> Result<File, IpaPackageError> {
    let (parent, name) = split_parent(path);
    let parent_fd =
        open_verified_directory(worktree.root_fd(), parent, worktree.directory_identities())?;
    let fd = openat(
        &parent_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| IpaPackageError::FileOpen {
        path: path.to_owned(),
        source,
    })?;
    let stat = fstat(&fd).map_err(|source| IpaPackageError::FileMetadata {
        path: path.to_owned(),
        source,
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(IpaPackageError::FileKindChanged {
            path: path.to_owned(),
        });
    }
    let actual_identity =
        descriptor_identity(&fd).map_err(|source| IpaPackageError::FileMetadata {
            path: path.to_owned(),
            source,
        })?;
    let expected_identity =
        worktree
            .file_identities()
            .get(path)
            .ok_or_else(|| IpaPackageError::MissingIdentity {
                path: path.to_owned(),
            })?;
    if &actual_identity != expected_identity {
        return Err(IpaPackageError::FileIdentityChanged {
            path: path.to_owned(),
        });
    }
    let actual_size =
        u64::try_from(stat.st_size).map_err(|_| IpaPackageError::FileSizeChanged {
            path: path.to_owned(),
            expected: expected_size,
            actual: 0,
        })?;
    if actual_size != expected_size {
        return Err(IpaPackageError::FileSizeChanged {
            path: path.to_owned(),
            expected: expected_size,
            actual: actual_size,
        });
    }
    Ok(File::from(fd))
}

fn file_snapshot(file: &File, path: &str) -> Result<FileSnapshot, IpaPackageError> {
    let stat = fstat(file).map_err(|source| IpaPackageError::FileMetadata {
        path: path.to_owned(),
        source,
    })?;
    let size = u64::try_from(stat.st_size).map_err(|_| IpaPackageError::FileSizeChanged {
        path: path.to_owned(),
        expected: 0,
        actual: 0,
    })?;
    Ok(FileSnapshot {
        identity: descriptor_identity(file).map_err(|source| IpaPackageError::FileMetadata {
            path: path.to_owned(),
            source,
        })?,
        size,
        modified_seconds: stat.st_mtime as i64,
        modified_nanoseconds: stat.st_mtime_nsec as i64,
        changed_seconds: stat.st_ctime as i64,
        changed_nanoseconds: stat.st_ctime_nsec as i64,
    })
}

fn validate_final_file_snapshots(
    worktree: &IpaPrivateWorktree,
    expected: &BTreeMap<String, FileSnapshot>,
) -> Result<(), IpaPackageError> {
    for (path, snapshot) in expected {
        let file = open_verified_file(worktree, path, snapshot.size)?;
        if file_snapshot(&file, path)? != *snapshot {
            return Err(IpaPackageError::FileChangedDuringRead { path: path.clone() });
        }
    }
    Ok(())
}

fn validate_output_inventory(
    worktree: &IpaPrivateWorktree,
    records: &[IpaPackageEntry],
    output: &IpaInventory,
) -> Result<(), IpaPackageError> {
    if output.app_root != worktree.inventory().app_root {
        return Err(IpaPackageError::OutputInventoryMismatch {
            reason: "output app root differs from the authoritative source",
        });
    }
    if output.entries.len() != records.len() {
        return Err(IpaPackageError::OutputInventoryMismatch {
            reason: "output entry count differs from the packaging plan",
        });
    }
    for (actual, expected) in output.entries.iter().zip(records) {
        if actual.path != expected.path
            || actual.kind != expected.kind
            || actual.uncompressed_size != expected.bytes
            || actual.crc32 != expected.crc32
            || actual.executable
                != (expected.kind == IpaEntryKind::File && expected.unix_mode & 0o111 != 0)
        {
            return Err(IpaPackageError::OutputInventoryMismatch {
                reason: "output entry metadata differs from the packaging plan",
            });
        }
    }
    Ok(())
}

fn directory_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o755)
}

fn file_options(executable: bool, size: u64) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(IPA_PACKAGE_COMPRESSION_LEVEL))
        .last_modified_time(DateTime::default())
        .unix_permissions(if executable { 0o755 } else { 0o644 })
        .large_file(size >= u32::MAX as u64)
}

fn is_output_limit(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.downcast_ref::<OutputLimitMarker>().is_some())
}

fn map_zip_entry_error(path: &str, error: ZipError, maximum: u64) -> IpaPackageError {
    if matches!(&error, ZipError::Io(source) if is_output_limit(source)) {
        IpaPackageError::OutputTooLarge { maximum }
    } else {
        IpaPackageError::ArchiveEntry {
            path: path.to_owned(),
            source: error,
        }
    }
}

fn map_zip_finalize_error(error: ZipError, maximum: u64) -> IpaPackageError {
    if matches!(&error, ZipError::Io(source) if is_output_limit(source)) {
        IpaPackageError::OutputTooLarge { maximum }
    } else {
        IpaPackageError::ArchiveFinalize { source: error }
    }
}

fn map_archive_write_error(path: &str, error: io::Error, maximum: u64) -> IpaPackageError {
    if is_output_limit(&error) {
        IpaPackageError::OutputTooLarge { maximum }
    } else {
        IpaPackageError::ArchiveEntryWrite {
            path: path.to_owned(),
            source: error,
        }
    }
}

fn map_output_io_error(error: io::Error, maximum: u64) -> IpaPackageError {
    if is_output_limit(&error) {
        IpaPackageError::OutputTooLarge { maximum }
    } else {
        IpaPackageError::OutputFlush { source: error }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::rc::Rc;

    use zip::ZipArchive;

    use super::*;
    use crate::ipa_materialize::{IpaWorktreeExclusionReason, materialize_ipa_private_worktree};

    const APP_ROOT: &str = "Payload/Demo.app";
    const EXECUTABLE_PATH: &str = "Payload/Demo.app/Demo";
    const RESOURCE_PATH: &str = "Payload/Demo.app/Resources/config.json";

    fn fixture() -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_directory("Payload/", source_options(CompressionMethod::Stored, 0o777))
            .expect("Payload directory");
        writer
            .add_directory(
                format!("{APP_ROOT}/"),
                source_options(CompressionMethod::Stored, 0o700),
            )
            .expect("app directory");
        for (path, bytes, method, mode) in [
            (
                EXECUTABLE_PATH,
                b"synthetic executable bytes".as_slice(),
                CompressionMethod::Stored,
                0o711,
            ),
            (
                RESOURCE_PATH,
                b"{\"fixture\":true}".as_slice(),
                CompressionMethod::Deflated,
                0o666,
            ),
            (
                "Payload/Demo.app/SC_Info.txt",
                b"similar name remains".as_slice(),
                CompressionMethod::Deflated,
                0o600,
            ),
            (
                "Payload/Demo.app/_MASReceipt/receipt",
                b"excluded receipt".as_slice(),
                CompressionMethod::Stored,
                0o600,
            ),
            (
                "Payload/Demo.app/SC_Info/data.sinf",
                b"excluded sc info".as_slice(),
                CompressionMethod::Stored,
                0o600,
            ),
        ] {
            writer
                .start_file(path, source_options(method, mode))
                .expect("start source file");
            writer.write_all(bytes).expect("write source file");
        }
        writer.finish().expect("finish fixture").into_inner()
    }

    fn source_options(method: CompressionMethod, mode: u32) -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(method)
            .last_modified_time(
                DateTime::from_date_and_time(2025, 6, 7, 8, 9, 10).expect("source timestamp"),
            )
            .unix_permissions(mode)
    }

    fn package_bytes(archive: &mut IpaAnalysisArchive) -> Vec<u8> {
        archive.seek(SeekFrom::Start(0)).expect("rewind package");
        let mut bytes = Vec::new();
        archive.read_to_end(&mut bytes).expect("read package");
        bytes
    }

    #[test]
    fn packages_deterministic_unsigned_byte_identical_analysis_ipas() {
        let source = fixture();
        let original = source.clone();
        let first_worktree =
            materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
                .expect("first worktree");
        let second_worktree =
            materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
                .expect("second worktree");
        let mut first = package_ipa_analysis_worktree(&first_worktree).expect("first package");
        let mut second = package_ipa_analysis_worktree(&second_worktree).expect("second package");
        let first_bytes = package_bytes(&mut first);
        let second_bytes = package_bytes(&mut second);

        assert_eq!(source, original);
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first.state, IpaPackageState::UnsignedAnalysisOnly);
        assert_eq!(first.policy, IpaPackagePolicy::default());
        assert_eq!(first.byte_len, first_bytes.len() as u64);
        for record in &first.entries {
            let output = first
                .output_inventory
                .entries
                .iter()
                .find(|entry| entry.path == record.path)
                .expect("output evidence record");
            assert_eq!(output.crc32, record.crc32);
            if record.kind == IpaEntryKind::File {
                let source = first
                    .source_inventory
                    .entries
                    .iter()
                    .find(|entry| entry.path == record.path)
                    .expect("source evidence record");
                assert_eq!(source.crc32, record.crc32);
            }
        }
        assert_eq!(
            first
                .excluded_entries
                .iter()
                .map(|entry| (entry.path.as_str(), entry.reason))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Payload/Demo.app/SC_Info/data.sinf",
                    IpaWorktreeExclusionReason::ScInfo,
                ),
                (
                    "Payload/Demo.app/_MASReceipt/receipt",
                    IpaWorktreeExclusionReason::MasReceipt,
                ),
            ]
        );
        assert!(first.output_inventory.entries.iter().all(|entry| {
            !entry.path.contains("/_MASReceipt/") && !entry.path.contains("/SC_Info/")
        }));

        let mut zip = ZipArchive::new(Cursor::new(&first_bytes)).expect("read output ZIP");
        assert!(zip.comment().is_empty());
        let expected_names = first
            .entries
            .iter()
            .map(|entry| {
                if entry.kind == IpaEntryKind::Directory {
                    format!("{}/", entry.path)
                } else {
                    entry.path.clone()
                }
            })
            .collect::<Vec<_>>();
        let actual_names = (0..zip.len())
            .map(|index| {
                zip.by_index_raw(index)
                    .expect("raw entry")
                    .name()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_names, expected_names);

        for index in 0..zip.len() {
            let file = zip.by_index_raw(index).expect("metadata entry");
            let modified = file.last_modified().expect("fixed timestamp");
            assert_eq!(modified.year(), 1980);
            assert_eq!(modified.month(), 1);
            assert_eq!(modified.day(), 1);
            assert_eq!(modified.hour(), 0);
            assert_eq!(modified.minute(), 0);
            assert_eq!(modified.second(), 0);
            assert!(file.comment().is_empty());
            assert!(file.extra_data().is_none_or(|extra| extra.is_empty()));
            if file.is_dir() {
                assert_eq!(file.compression(), CompressionMethod::Stored);
                assert_eq!(file.unix_mode().expect("directory mode") & 0o777, 0o755);
            } else {
                assert_eq!(file.compression(), CompressionMethod::Deflated);
                let expected_mode = if file.name() == EXECUTABLE_PATH {
                    0o755
                } else {
                    0o644
                };
                assert_eq!(file.unix_mode().expect("file mode") & 0o777, expected_mode);
            }
        }

        for (path, expected) in [
            (EXECUTABLE_PATH, b"synthetic executable bytes".as_slice()),
            (RESOURCE_PATH, b"{\"fixture\":true}".as_slice()),
            (
                "Payload/Demo.app/SC_Info.txt",
                b"similar name remains".as_slice(),
            ),
        ] {
            let mut file = zip.by_name(path).expect("included file");
            let mut actual = Vec::new();
            file.read_to_end(&mut actual).expect("read included file");
            assert_eq!(actual, expected);
        }

        let artifact_path = first.artifact.path().to_owned();
        drop(first);
        assert!(!artifact_path.exists());
    }

    #[test]
    fn rejects_unexpected_nodes_before_output_creation() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        std::fs::write(
            worktree.path().join(format!("{APP_ROOT}/unexpected")),
            b"extra",
        )
        .expect("unexpected node");
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);

        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |_| {},
        );

        assert!(matches!(
            result,
            Err(IpaPackageError::TreeContentsChanged { .. })
        ));
        assert!(observed.borrow().is_none());
    }

    #[test]
    fn rejects_symlink_replacement_without_reading_outside() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        let outside = tempfile::tempdir().expect("outside directory");
        let outside_file = outside.path().join("sentinel");
        std::fs::write(&outside_file, b"outside remains").expect("outside sentinel");
        let target = worktree.path().join(RESOURCE_PATH);
        std::fs::remove_file(&target).expect("remove planned file");
        symlink(&outside_file, &target).expect("replace with symlink");
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);

        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |_| {},
        );

        assert!(matches!(result, Err(IpaPackageError::FileOpen { .. })));
        assert_eq!(
            std::fs::read(&outside_file).expect("read outside sentinel"),
            b"outside remains"
        );
        let output = observed.borrow().clone().expect("observe output");
        assert!(!output.exists());
    }

    #[test]
    fn rejects_same_size_regular_file_replacement() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        let target = worktree.path().join(RESOURCE_PATH);
        let original = File::open(&target).expect("hold original file inode");
        std::fs::remove_file(&target).expect("remove planned file");
        std::fs::write(&target, b"{\"fixture\":true}").expect("replace with same-size file");
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);

        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |_| {},
        );
        drop(original);

        assert!(matches!(
            result,
            Err(IpaPackageError::FileIdentityChanged { .. })
        ));
        let output = observed.borrow().clone().expect("observe output");
        assert!(!output.exists());
    }

    #[test]
    fn rejects_directory_identity_drift() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        let resources = worktree.path().join(format!("{APP_ROOT}/Resources"));
        let original = File::open(&resources).expect("hold old directory inode");
        std::fs::remove_file(worktree.path().join(RESOURCE_PATH)).expect("remove resource");
        std::fs::remove_dir(&resources).expect("remove resources directory");
        std::fs::create_dir(&resources).expect("replace resources directory");
        std::fs::write(resources.join("config.json"), b"{\"fixture\":true}")
            .expect("restore shape");
        drop(original);

        assert!(matches!(
            package_ipa_analysis_worktree(&worktree),
            Err(IpaPackageError::WorktreeBoundary(
                IpaWorktreeError::DirectoryIdentityChanged { .. }
            ))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_fifo_replacement_without_blocking() {
        use rustix::fs::mkfifoat;

        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        std::fs::remove_file(worktree.path().join(RESOURCE_PATH)).expect("remove resource");
        let (parent, name) = split_parent(RESOURCE_PATH);
        let parent_fd =
            open_verified_directory(worktree.root_fd(), parent, worktree.directory_identities())
                .expect("open resource parent");
        mkfifoat(&parent_fd, name, Mode::RUSR | Mode::WUSR).expect("replace with FIFO");
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);

        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |_| {},
        );

        assert!(matches!(
            result,
            Err(IpaPackageError::FileKindChanged { .. })
        ));
        let output = observed.borrow().clone().expect("observe output");
        assert!(!output.exists());
    }

    #[test]
    fn size_mutation_fails_with_output_cleanup() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        let resource = worktree.path().join(RESOURCE_PATH);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&resource)
            .expect("open resource for append");
        file.write_all(b"!").expect("grow resource");
        drop(file);
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);
        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |_| {},
        );
        assert!(matches!(
            result,
            Err(IpaPackageError::FileSizeChanged { .. })
        ));
        let output = observed.borrow().clone().expect("observe output");
        assert!(!output.exists());
    }

    #[test]
    fn final_preflight_failure_cleans_corrupted_output() {
        let source = fixture();
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("worktree");
        let observed = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&observed);

        let result = package_with_options(
            &worktree,
            MAX_IPA_PACKAGE_BYTES,
            move |path| *captured.borrow_mut() = Some(path.to_owned()),
            |path| {
                let mut artifact = std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .expect("open finalized output");
                artifact
                    .seek(SeekFrom::Start(0))
                    .expect("seek output header");
                artifact.write_all(b"NO").expect("corrupt output header");
                artifact.flush().expect("flush corrupt output");
            },
        );

        assert!(matches!(result, Err(IpaPackageError::OutputInspect(_))));
        let output = observed.borrow().clone().expect("observe output");
        assert!(!output.exists());
    }

    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic sink failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn exact_file_copy_rejects_short_long_and_sink_failures() {
        assert!(matches!(
            copy_exact_file_bytes(
                &mut Cursor::new(b"12"),
                &mut Vec::new(),
                RESOURCE_PATH,
                3,
                MAX_IPA_PACKAGE_BYTES,
            ),
            Err(IpaPackageError::FileShortRead { .. })
        ));
        assert!(matches!(
            copy_exact_file_bytes(
                &mut Cursor::new(b"123"),
                &mut Vec::new(),
                RESOURCE_PATH,
                2,
                MAX_IPA_PACKAGE_BYTES,
            ),
            Err(IpaPackageError::FileLongRead { .. })
        ));
        assert!(matches!(
            copy_exact_file_bytes(
                &mut Cursor::new(b"123"),
                &mut FailingSink,
                RESOURCE_PATH,
                3,
                MAX_IPA_PACKAGE_BYTES,
            ),
            Err(IpaPackageError::ArchiveEntryWrite { .. })
        ));
    }

    #[test]
    fn bounded_writer_rejects_seek_or_write_past_its_high_water_limit() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = BoundedWriter::new(cursor, 4).expect("bounded writer");
        writer.write_all(b"1234").expect("write to limit");
        assert_eq!(writer.high_water(), 4);
        assert!(is_output_limit(
            &writer.write_all(b"5").expect_err("write limit")
        ));
        assert!(is_output_limit(
            &writer
                .seek(SeekFrom::Start(5))
                .expect_err("seek beyond limit")
        ));
    }

    #[test]
    fn rejects_package_entry_count_over_the_archive_limit() {
        assert!(matches!(
            validate_package_entry_count(MAX_IPA_ENTRIES + 1),
            Err(IpaPackageError::TooManyEntries { .. })
        ));
    }
}
