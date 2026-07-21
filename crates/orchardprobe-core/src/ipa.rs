//! Bounded, read-only inspection of IPA archives.
//!
//! This module treats an IPA as an untrusted ZIP archive. It validates the
//! archive and local-entry metadata needed to build a deterministic inventory.
//! Separate opt-in APIs can return one bounded, CRC-checked entry in memory or
//! stream one exact entry to a caller-owned sink after the entire archive
//! passes that preflight. This module never chooses or derives a host path.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::str;

use serde::Serialize;
use thiserror::Error;
use zip::ZipArchive;
use zip::read::{ArchiveOffset, Config};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_ENTRY_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_ENTRY_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_FIXED_BYTES: usize = 22;
const ZIP64_LOCATOR_BYTES: u64 = 20;
const ZIP64_EOCD_FIXED_BYTES: usize = 56;
const CENTRAL_ENTRY_FIXED_BYTES: usize = 46;
const LOCAL_ENTRY_FIXED_BYTES: usize = 30;
const ZIP64_EOCD_MIN_RECORD_BYTES: u64 = 44;
const UTF8_NAME_FLAG: u16 = 1 << 11;
const ENCRYPTED_FLAG: u16 = 1;
const DATA_DESCRIPTOR_FLAG: u16 = 1 << 3;
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;
const UNIX_REGULAR_FILE: u32 = 0o100_000;
const UNIX_DIRECTORY: u32 = 0o040_000;
const UNIX_SYMLINK: u32 = 0o120_000;

/// Maximum accepted IPA byte length.
pub const MAX_IPA_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Maximum accepted central-directory byte length.
pub const MAX_IPA_CENTRAL_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum accepted number of archive entries.
pub const MAX_IPA_ENTRIES: usize = 16_384;
/// Maximum accepted UTF-8 byte length of one canonical archive path.
pub const MAX_IPA_PATH_BYTES: usize = 1_024;
/// Maximum accepted path-component depth.
pub const MAX_IPA_PATH_DEPTH: usize = 32;
/// Maximum accepted UTF-8 byte length of one path component.
pub const MAX_IPA_PATH_COMPONENT_BYTES: usize = 255;
/// Maximum accepted declared uncompressed byte length of one regular entry.
pub const MAX_IPA_ENTRY_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Maximum accepted aggregate declared uncompressed byte length.
pub const MAX_IPA_TOTAL_UNCOMPRESSED_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Maximum accepted declared uncompressed-to-compressed ratio.
pub const MAX_IPA_COMPRESSION_RATIO: u64 = 1_000;
/// Maximum caller-selected uncompressed byte length for one in-memory read.
pub const MAX_IPA_ENTRY_READ_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum declared compressed byte length accepted by one in-memory read.
pub const MAX_IPA_ENTRY_READ_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum caller-selected bytes for one streaming entry copy.
pub const MAX_IPA_ENTRY_COPY_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum declared compressed bytes accepted by one streaming entry copy.
pub const MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// The only entry kinds that can enter a future private work tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaEntryKind {
    File,
    Directory,
}

/// Deterministic metadata for one validated IPA entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaEntry {
    pub path: String,
    pub kind: IpaEntryKind,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
}

/// A read-only, device-free inventory of one structurally bounded IPA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaInventory {
    pub archive_size: u64,
    pub app_root: String,
    pub entry_count: usize,
    pub file_count: usize,
    pub directory_count: usize,
    pub total_compressed_size: u64,
    pub total_uncompressed_size: u64,
    pub entries: Vec<IpaEntry>,
}

/// Result of copying one exact IPA entry to a caller-owned sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaEntryCopy {
    pub bytes_written: u64,
    /// The complete inventory revalidated after and matched across the copy.
    pub inventory: IpaInventory,
}

/// Failure while validating IPA archive metadata.
#[derive(Debug, Error)]
pub enum IpaInspectError {
    #[error("I/O error while reading IPA metadata: {0}")]
    Io(#[from] io::Error),

    #[error("declared IPA size {declared} does not match readable size {actual}")]
    ArchiveSizeMismatch { declared: u64, actual: u64 },

    #[error("IPA size {actual} exceeds the {maximum}-byte safety limit")]
    ArchiveTooLarge { actual: u64, maximum: u64 },

    #[error("invalid ZIP archive metadata: {reason}")]
    InvalidArchive { reason: String },

    #[error("multi-disk ZIP archives are outside the IPA scope")]
    MultiDiskArchive,

    #[error("ZIP archive contains prepended data before offset {offset}")]
    PrependedData { offset: u64 },

    #[error("central directory size {actual} exceeds the {maximum}-byte safety limit")]
    CentralDirectoryTooLarge { actual: u64, maximum: u64 },

    #[error("IPA declares {actual} entries; maximum is {maximum}")]
    TooManyEntries { actual: u64, maximum: usize },

    #[error("entry {index} has an unsafe or ambiguous path: {reason}")]
    UnsafeEntryPath { index: usize, reason: &'static str },

    #[error("entry {index} path is not unambiguous UTF-8")]
    InvalidEntryNameEncoding { index: usize },

    #[error("entry path `{path}` appears more than once")]
    DuplicateEntryPath { path: String },

    #[error("entry paths `{first}` and `{second}` collide under ASCII case folding")]
    CaseCollidingEntryPaths { first: String, second: String },

    #[error("entry `{path}` is ZIP-encrypted; IPA entries must be readable metadata")]
    EncryptedEntry { path: String },

    #[error("entry `{path}` uses unsupported special-file mode {mode:#o}")]
    UnsupportedEntryKind { path: String, mode: u32 },

    #[error("entry `{path}` has inconsistent directory metadata")]
    InconsistentDirectoryKind { path: String },

    #[error("directory entry `{path}` declares non-zero payload sizes")]
    DirectoryHasPayload { path: String },

    #[error("entry `{path}` declares {actual} uncompressed bytes; maximum is {maximum}")]
    EntryTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },

    #[error(
        "entry `{path}` declares compression ratio above {maximum}: {uncompressed} bytes from {compressed}"
    )]
    CompressionRatioExceeded {
        path: String,
        compressed: u64,
        uncompressed: u64,
        maximum: u64,
    },

    #[error("aggregate {field} size overflowed")]
    AggregateSizeOverflow { field: &'static str },

    #[error("aggregate uncompressed size {actual} exceeds the {maximum}-byte safety limit")]
    AggregateUncompressedTooLarge { actual: u64, maximum: u64 },

    #[error("aggregate compressed size {actual} exceeds the {archive_size}-byte archive size")]
    AggregateCompressedTooLarge { actual: u64, archive_size: u64 },

    #[error("IPA contains overlapping local-entry regions")]
    OverlappingEntries,

    #[error("IPA has no immediate `Payload/*.app` root")]
    MissingAppRoot,

    #[error("IPA has multiple immediate app roots: {roots:?}")]
    MultipleAppRoots { roots: Vec<String> },

    #[error("entry `{path}` is outside the selected app bundle root")]
    EntryOutsideAppRoot { path: String },

    #[error("the selected app root `{path}` is encoded as a regular file")]
    AppRootIsFile { path: String },

    #[error("the selected app root `{path}` contains no regular files")]
    EmptyAppBundle { path: String },
}

/// Failure while reading one entry after a complete IPA metadata preflight.
#[derive(Debug, Error)]
pub enum IpaEntryReadError {
    #[error("IPA preflight failed: {0}")]
    Inspect(#[from] IpaInspectError),

    #[error("entry selector is unsafe or ambiguous: {reason}")]
    UnsafeSelector { reason: &'static str },

    #[error("entry read limit must be between 1 and {maximum} bytes; got {actual}")]
    InvalidOutputLimit { actual: u64, maximum: u64 },

    #[error("entry `{path}` is not present in the validated IPA inventory")]
    EntryNotFound { path: String },

    #[error("entry `{path}` is a directory, not a readable regular file")]
    EntryIsDirectory { path: String },

    #[error("entry `{path}` declares {actual} compressed bytes; read maximum is {maximum}")]
    CompressedInputTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },

    #[error("entry `{path}` declares {actual} output bytes; caller maximum is {maximum}")]
    DeclaredOutputTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },

    #[error("entry `{path}` produced more than the caller's {maximum}-byte maximum")]
    OutputLimitExceeded { path: String, maximum: u64 },

    #[error("entry `{path}` uses unsupported ZIP compression method {method}")]
    UnsupportedCompression { path: String, method: String },

    #[error("entry `{path}` metadata changed after IPA preflight")]
    MetadataChanged { path: String },

    #[error("could not reopen the validated IPA for entry reading: {reason}")]
    ArchiveChanged { reason: String },

    #[error("IPA inventory changed while an entry was being copied")]
    InventoryChangedDuringRead,

    #[error("could not read entry `{path}`: {source}")]
    ReadFailed {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("could not write entry `{path}` to the caller-owned sink: {source}")]
    WriteFailed {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("entry `{path}` produced {actual} bytes, but ZIP metadata declared {declared}")]
    ActualSizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },
}

#[derive(Debug)]
struct CentralDirectory {
    start: u64,
    entries: Vec<CentralEntry>,
}

#[derive(Debug)]
struct CentralEntry {
    raw_name: Vec<u8>,
    path: String,
    directory_name: bool,
    flags: u16,
    compression_method: u16,
    crc32: u32,
    compressed_size_32: u32,
    uncompressed_size_32: u32,
}

#[derive(Debug)]
struct LocalEntryExpectation {
    index: usize,
    header_start: u64,
    data_start: u64,
    raw_name: Vec<u8>,
    flags: u16,
    compression_method: u16,
    crc32: u32,
    compressed_size_32: u32,
    uncompressed_size_32: u32,
}

/// Inspect an IPA without decompressing or extracting any entry.
///
/// `archive_size` must come from a previously secured regular-file handle. The
/// function independently confirms the reader length before parsing.
pub fn inspect_ipa<R: Read + Seek>(
    mut reader: R,
    archive_size: u64,
) -> Result<IpaInventory, IpaInspectError> {
    if archive_size > MAX_IPA_ARCHIVE_BYTES {
        return Err(IpaInspectError::ArchiveTooLarge {
            actual: archive_size,
            maximum: MAX_IPA_ARCHIVE_BYTES,
        });
    }

    let actual_size = reader.seek(SeekFrom::End(0))?;
    if actual_size != archive_size {
        return Err(IpaInspectError::ArchiveSizeMismatch {
            declared: archive_size,
            actual: actual_size,
        });
    }

    let central = read_central_directory(&mut reader, archive_size)?;
    let app_root = select_app_root(&central.entries)?;

    reader.seek(SeekFrom::Start(0))?;
    let config = Config {
        archive_offset: ArchiveOffset::Known(0),
    };
    let mut archive = ZipArchive::with_config(config, reader).map_err(|error| {
        IpaInspectError::InvalidArchive {
            reason: error.to_string(),
        }
    })?;

    if archive.offset() != 0 {
        return Err(IpaInspectError::PrependedData {
            offset: archive.offset(),
        });
    }
    if archive.central_directory_start() != central.start {
        return Err(IpaInspectError::InvalidArchive {
            reason: "central-directory offset changed between bounded passes".to_owned(),
        });
    }
    if archive.len() != central.entries.len() {
        return Err(IpaInspectError::InvalidArchive {
            reason: "central-directory entry count became ambiguous after decoding".to_owned(),
        });
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut ranges = Vec::with_capacity(archive.len());
    let mut local_expectations = Vec::with_capacity(archive.len());
    let mut total_compressed_size = 0u64;
    let mut total_uncompressed_size = 0u64;
    let mut file_count = 0usize;
    let mut directory_count = 0usize;

    for (index, central_entry) in central.entries.iter().enumerate() {
        let file =
            archive
                .by_index_raw(index)
                .map_err(|error| IpaInspectError::InvalidArchive {
                    reason: format!("could not validate local header for entry {index}: {error}"),
                })?;

        if file.name_raw() != central_entry.raw_name {
            return Err(IpaInspectError::InvalidArchive {
                reason: format!("entry {index} name changed while parsing metadata"),
            });
        }
        if file.encrypted() || central_entry.flags & ENCRYPTED_FLAG != 0 {
            return Err(IpaInspectError::EncryptedEntry {
                path: central_entry.path.clone(),
            });
        }

        let kind = classify_entry_kind(
            &central_entry.path,
            central_entry.directory_name,
            file.unix_mode(),
        )?;
        let compressed_size = file.compressed_size();
        let uncompressed_size = file.size();

        match kind {
            IpaEntryKind::File => {
                file_count += 1;
                validate_declared_sizes(&central_entry.path, compressed_size, uncompressed_size)?;
            }
            IpaEntryKind::Directory => {
                directory_count += 1;
                if compressed_size != 0 || uncompressed_size != 0 {
                    return Err(IpaInspectError::DirectoryHasPayload {
                        path: central_entry.path.clone(),
                    });
                }
            }
        }

        (total_compressed_size, total_uncompressed_size) = add_declared_sizes(
            total_compressed_size,
            total_uncompressed_size,
            compressed_size,
            uncompressed_size,
            archive_size,
        )?;

        let header_start = file.header_start();
        let data_start = file.data_start();
        let data_end = data_start.checked_add(compressed_size).ok_or_else(|| {
            IpaInspectError::InvalidArchive {
                reason: format!("entry {index} data range overflowed"),
            }
        })?;
        if header_start >= data_start || data_end > central.start {
            return Err(IpaInspectError::InvalidArchive {
                reason: format!("entry {index} local range is outside the file-data region"),
            });
        }
        ranges.push(header_start..data_end);
        local_expectations.push(LocalEntryExpectation {
            index,
            header_start,
            data_start,
            raw_name: central_entry.raw_name.clone(),
            flags: central_entry.flags,
            compression_method: central_entry.compression_method,
            crc32: central_entry.crc32,
            compressed_size_32: central_entry.compressed_size_32,
            uncompressed_size_32: central_entry.uncompressed_size_32,
        });

        entries.push(IpaEntry {
            path: central_entry.path.clone(),
            kind,
            compressed_size,
            uncompressed_size,
            crc32: file.crc32(),
        });
    }

    reject_overlapping_ranges(&mut ranges)?;
    let mut reader = archive.into_inner();
    for expectation in &local_expectations {
        validate_local_header(&mut reader, expectation)?;
    }

    if entries
        .iter()
        .any(|entry| entry.path == app_root && entry.kind == IpaEntryKind::File)
    {
        return Err(IpaInspectError::AppRootIsFile {
            path: app_root.clone(),
        });
    }
    if !entries.iter().any(|entry| {
        entry.kind == IpaEntryKind::File
            && entry
                .path
                .strip_prefix(&app_root)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }) {
        return Err(IpaInspectError::EmptyAppBundle {
            path: app_root.clone(),
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(IpaInventory {
        archive_size,
        app_root,
        entry_count: entries.len(),
        file_count,
        directory_count,
        total_compressed_size,
        total_uncompressed_size,
        entries,
    })
}

/// Read one exact regular-file entry into memory after validating the full IPA.
///
/// The archive is never extracted or written to disk. `max_output_bytes` is a
/// caller-selected limit that must not exceed [`MAX_IPA_ENTRY_READ_BYTES`]. A
/// successful read reaches entry EOF, verifies the ZIP CRC, and confirms the
/// actual length against the metadata returned by [`inspect_ipa`].
pub fn read_ipa_entry_bounded<R: Read + Seek>(
    reader: R,
    archive_size: u64,
    path: &str,
    max_output_bytes: u64,
) -> Result<Vec<u8>, IpaEntryReadError> {
    read_ipa_entry_bounded_with_inventory(reader, archive_size, path, max_output_bytes)
        .map(|(output, _)| output)
}

pub(crate) fn read_ipa_entry_bounded_with_inventory<R: Read + Seek>(
    reader: R,
    archive_size: u64,
    path: &str,
    max_output_bytes: u64,
) -> Result<(Vec<u8>, IpaInventory), IpaEntryReadError> {
    let mut output = Vec::new();
    let copied = copy_ipa_entry_with_limits(
        reader,
        archive_size,
        path,
        max_output_bytes,
        MAX_IPA_ENTRY_READ_BYTES,
        MAX_IPA_ENTRY_READ_COMPRESSED_BYTES,
        &mut output,
    )?;
    Ok((output, copied.inventory))
}

/// Copy one exact regular-file entry after validating the full IPA.
///
/// The caller owns the output sink and any cleanup required after an error.
/// This function never interprets the entry path as a host path. It accepts
/// only Stored or Deflate entries, reads through entry EOF for ZIP CRC
/// validation, checks the observed length, and requires complete inventories
/// before and after the copy to match. It returns that revalidated inventory.
/// `max_output_bytes` must not exceed
/// [`MAX_IPA_ENTRY_COPY_BYTES`].
pub fn copy_ipa_entry_bounded<R: Read + Seek, W: Write>(
    reader: R,
    archive_size: u64,
    path: &str,
    max_output_bytes: u64,
    writer: &mut W,
) -> Result<IpaEntryCopy, IpaEntryReadError> {
    copy_ipa_entry_with_limits(
        reader,
        archive_size,
        path,
        max_output_bytes,
        MAX_IPA_ENTRY_COPY_BYTES,
        MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES,
        writer,
    )
}

fn copy_ipa_entry_with_limits<R: Read + Seek, W: Write>(
    mut reader: R,
    archive_size: u64,
    path: &str,
    max_output_bytes: u64,
    fixed_output_maximum: u64,
    compressed_input_maximum: u64,
    writer: &mut W,
) -> Result<IpaEntryCopy, IpaEntryReadError> {
    validate_output_limit(max_output_bytes, fixed_output_maximum)?;

    let inventory = inspect_ipa(&mut reader, archive_size)?;
    let canonical_path = validate_entry_selector(path)?;
    let expected = inventory
        .entries
        .iter()
        .find(|entry| entry.path == canonical_path)
        .cloned()
        .ok_or_else(|| IpaEntryReadError::EntryNotFound {
            path: canonical_path.clone(),
        })?;
    if expected.kind == IpaEntryKind::Directory {
        return Err(IpaEntryReadError::EntryIsDirectory {
            path: expected.path,
        });
    }
    validate_entry_read_limits(&expected, max_output_bytes, compressed_input_maximum)?;

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| IpaEntryReadError::ReadFailed {
            path: expected.path.clone(),
            source,
        })?;
    let config = Config {
        archive_offset: ArchiveOffset::Known(0),
    };
    let mut archive = ZipArchive::with_config(config, reader).map_err(|error| {
        IpaEntryReadError::ArchiveChanged {
            reason: error.to_string(),
        }
    })?;
    let index = archive.index_for_name(&expected.path).ok_or_else(|| {
        IpaEntryReadError::MetadataChanged {
            path: expected.path.clone(),
        }
    })?;

    let compression_method = {
        let file =
            archive
                .by_index_raw(index)
                .map_err(|error| IpaEntryReadError::ArchiveChanged {
                    reason: error.to_string(),
                })?;
        validate_reopened_entry(&file, &expected)?;
        file.compression()
    };
    if !matches!(
        compression_method,
        zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
    ) {
        return Err(IpaEntryReadError::UnsupportedCompression {
            path: expected.path,
            method: format!("{compression_method:?}"),
        });
    }

    let file = archive
        .by_index(index)
        .map_err(|error| IpaEntryReadError::ArchiveChanged {
            reason: error.to_string(),
        })?;
    validate_reopened_entry(&file, &expected)?;

    let read_limit = max_output_bytes
        .checked_add(1)
        .expect("fixed entry copy limits leave room for an overflow probe");
    // A successful entry declares at most `max_output_bytes`, so one byte of
    // capacity remains after its last payload byte. The next read therefore
    // reaches the underlying `ZipFile` EOF (and its CRC check) before `Take`
    // can synthesize EOF. Streams that produce the probe byte fail below.
    let mut input = file.take(read_limit);
    let mut buffer = [0u8; 64 * 1024];
    let mut actual = 0u64;
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|source| IpaEntryReadError::ReadFailed {
                path: expected.path.clone(),
                source,
            })?;
        if count == 0 {
            break;
        }
        actual = actual.checked_add(count as u64).ok_or_else(|| {
            IpaEntryReadError::OutputLimitExceeded {
                path: expected.path.clone(),
                maximum: max_output_bytes,
            }
        })?;
        if actual > max_output_bytes {
            return Err(IpaEntryReadError::OutputLimitExceeded {
                path: expected.path,
                maximum: max_output_bytes,
            });
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|source| IpaEntryReadError::WriteFailed {
                path: expected.path.clone(),
                source,
            })?;
    }
    if actual != expected.uncompressed_size {
        return Err(IpaEntryReadError::ActualSizeMismatch {
            path: expected.path,
            declared: expected.uncompressed_size,
            actual,
        });
    }
    drop(input);
    let mut reader = archive.into_inner();
    let post_read_inventory = inspect_ipa(&mut reader, archive_size)?;
    if inventory != post_read_inventory {
        return Err(IpaEntryReadError::InventoryChangedDuringRead);
    }
    Ok(IpaEntryCopy {
        bytes_written: actual,
        inventory: post_read_inventory,
    })
}

fn validate_reopened_entry<R: Read>(
    file: &zip::read::ZipFile<'_, R>,
    expected: &IpaEntry,
) -> Result<(), IpaEntryReadError> {
    if file.name() != expected.path
        || file.encrypted()
        || file.compressed_size() != expected.compressed_size
        || file.size() != expected.uncompressed_size
        || file.crc32() != expected.crc32
        || !file.is_file()
    {
        return Err(IpaEntryReadError::MetadataChanged {
            path: expected.path.clone(),
        });
    }
    Ok(())
}

fn validate_output_limit(
    max_output_bytes: u64,
    fixed_maximum: u64,
) -> Result<(), IpaEntryReadError> {
    if max_output_bytes == 0 || max_output_bytes > fixed_maximum {
        return Err(IpaEntryReadError::InvalidOutputLimit {
            actual: max_output_bytes,
            maximum: fixed_maximum,
        });
    }
    Ok(())
}

fn validate_entry_selector(path: &str) -> Result<String, IpaEntryReadError> {
    validate_entry_path(0, path, false).map_err(|error| match error {
        IpaInspectError::UnsafeEntryPath { reason, .. } => {
            IpaEntryReadError::UnsafeSelector { reason }
        }
        _ => IpaEntryReadError::UnsafeSelector {
            reason: "selector could not be canonicalized",
        },
    })
}

fn validate_entry_read_limits(
    entry: &IpaEntry,
    max_output_bytes: u64,
    compressed_input_maximum: u64,
) -> Result<(), IpaEntryReadError> {
    if entry.compressed_size > compressed_input_maximum {
        return Err(IpaEntryReadError::CompressedInputTooLarge {
            path: entry.path.clone(),
            actual: entry.compressed_size,
            maximum: compressed_input_maximum,
        });
    }
    if entry.uncompressed_size > max_output_bytes {
        return Err(IpaEntryReadError::DeclaredOutputTooLarge {
            path: entry.path.clone(),
            actual: entry.uncompressed_size,
            maximum: max_output_bytes,
        });
    }
    Ok(())
}

fn read_central_directory<R: Read + Seek>(
    reader: &mut R,
    archive_size: u64,
) -> Result<CentralDirectory, IpaInspectError> {
    let footer = read_footer(reader, archive_size)?;
    if footer.central_size > MAX_IPA_CENTRAL_DIRECTORY_BYTES {
        return Err(IpaInspectError::CentralDirectoryTooLarge {
            actual: footer.central_size,
            maximum: MAX_IPA_CENTRAL_DIRECTORY_BYTES,
        });
    }
    if footer.entry_count > MAX_IPA_ENTRIES as u64 {
        return Err(IpaInspectError::TooManyEntries {
            actual: footer.entry_count,
            maximum: MAX_IPA_ENTRIES,
        });
    }

    let end = footer
        .central_start
        .checked_add(footer.central_size)
        .ok_or_else(|| IpaInspectError::InvalidArchive {
            reason: "central-directory range overflowed".to_owned(),
        })?;
    if end != footer.central_end || end > archive_size {
        return Err(IpaInspectError::InvalidArchive {
            reason: "central-directory range is not contiguous with the footer".to_owned(),
        });
    }

    reader.seek(SeekFrom::Start(footer.central_start))?;
    let entry_capacity =
        usize::try_from(footer.entry_count).map_err(|_| IpaInspectError::TooManyEntries {
            actual: footer.entry_count,
            maximum: MAX_IPA_ENTRIES,
        })?;
    let mut entries = Vec::with_capacity(entry_capacity);
    let mut exact_paths = HashSet::with_capacity(entry_capacity);
    let mut folded_paths = HashMap::with_capacity(entry_capacity);

    for index in 0..entry_capacity {
        let record_start = reader.stream_position()?;
        let mut fixed = [0u8; CENTRAL_ENTRY_FIXED_BYTES];
        reader.read_exact(&mut fixed).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                IpaInspectError::InvalidArchive {
                    reason: format!("central entry {index} is truncated"),
                }
            } else {
                IpaInspectError::Io(error)
            }
        })?;
        if le_u32(&fixed, 0) != CENTRAL_ENTRY_SIGNATURE {
            return Err(IpaInspectError::InvalidArchive {
                reason: format!("central entry {index} has an invalid signature"),
            });
        }

        let flags = le_u16(&fixed, 8);
        if le_u16(&fixed, 34) != 0 {
            return Err(IpaInspectError::MultiDiskArchive);
        }
        let compression_method = le_u16(&fixed, 10);
        let crc32 = le_u32(&fixed, 16);
        let compressed_size_32 = le_u32(&fixed, 20);
        let uncompressed_size_32 = le_u32(&fixed, 24);
        let name_len = usize::from(le_u16(&fixed, 28));
        let extra_len = u64::from(le_u16(&fixed, 30));
        let comment_len = u64::from(le_u16(&fixed, 32));
        if name_len == 0 || name_len > MAX_IPA_PATH_BYTES + 1 {
            return Err(IpaInspectError::UnsafeEntryPath {
                index,
                reason: "encoded path length is outside the accepted range",
            });
        }

        let record_size = (CENTRAL_ENTRY_FIXED_BYTES as u64)
            .checked_add(name_len as u64)
            .and_then(|value| value.checked_add(extra_len))
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| IpaInspectError::InvalidArchive {
                reason: format!("central entry {index} length overflowed"),
            })?;
        let record_end = record_start.checked_add(record_size).ok_or_else(|| {
            IpaInspectError::InvalidArchive {
                reason: format!("central entry {index} range overflowed"),
            }
        })?;
        if record_end > end {
            return Err(IpaInspectError::InvalidArchive {
                reason: format!("central entry {index} exceeds the declared directory"),
            });
        }

        let mut raw_name = vec![0u8; name_len];
        reader.read_exact(&mut raw_name)?;
        let raw_path = str::from_utf8(&raw_name)
            .map_err(|_| IpaInspectError::InvalidEntryNameEncoding { index })?;
        if !raw_path.is_ascii() && flags & UTF8_NAME_FLAG == 0 {
            return Err(IpaInspectError::InvalidEntryNameEncoding { index });
        }

        let directory_name = raw_path.ends_with('/');
        let path = validate_entry_path(index, raw_path, directory_name)?;
        if !exact_paths.insert(path.clone()) {
            return Err(IpaInspectError::DuplicateEntryPath { path });
        }
        let folded = path.to_ascii_lowercase();
        if let Some(first) = folded_paths.insert(folded, path.clone()) {
            return Err(IpaInspectError::CaseCollidingEntryPaths {
                first,
                second: path,
            });
        }

        reader.seek(SeekFrom::Current(
            i64::try_from(extra_len + comment_len).expect("u16 lengths fit in i64"),
        ))?;
        entries.push(CentralEntry {
            raw_name,
            path,
            directory_name,
            flags,
            compression_method,
            crc32,
            compressed_size_32,
            uncompressed_size_32,
        });
    }

    if reader.stream_position()? != end {
        return Err(IpaInspectError::InvalidArchive {
            reason: "central-directory entry count does not consume its declared size".to_owned(),
        });
    }

    Ok(CentralDirectory {
        start: footer.central_start,
        entries,
    })
}

#[derive(Debug)]
struct Footer {
    entry_count: u64,
    central_start: u64,
    central_size: u64,
    central_end: u64,
}

fn read_footer<R: Read + Seek>(
    reader: &mut R,
    archive_size: u64,
) -> Result<Footer, IpaInspectError> {
    if archive_size < EOCD_FIXED_BYTES as u64 {
        return Err(IpaInspectError::InvalidArchive {
            reason: "archive is too small for an end-of-central-directory record".to_owned(),
        });
    }
    let tail_len = archive_size.min((EOCD_FIXED_BYTES + usize::from(u16::MAX)) as u64);
    let tail_start = archive_size - tail_len;
    reader.seek(SeekFrom::Start(tail_start))?;
    let mut tail = vec![0u8; tail_len as usize];
    reader.read_exact(&mut tail)?;

    let eocd_in_tail = (0..=tail.len().saturating_sub(EOCD_FIXED_BYTES))
        .rev()
        .find(|offset| {
            le_u32(&tail, *offset) == EOCD_SIGNATURE
                && offset
                    .checked_add(EOCD_FIXED_BYTES)
                    .and_then(|value| value.checked_add(usize::from(le_u16(&tail, *offset + 20))))
                    == Some(tail.len())
        })
        .ok_or_else(|| IpaInspectError::InvalidArchive {
            reason: "end-of-central-directory record was not found".to_owned(),
        })?;
    let eocd_offset = tail_start + eocd_in_tail as u64;
    let eocd = &tail[eocd_in_tail..eocd_in_tail + EOCD_FIXED_BYTES];

    let disk_number = le_u16(eocd, 4);
    let central_disk = le_u16(eocd, 6);
    let entries_on_disk = le_u16(eocd, 8);
    let entries_total = le_u16(eocd, 10);
    if disk_number != central_disk || entries_on_disk != entries_total {
        return Err(IpaInspectError::MultiDiskArchive);
    }

    let classic_size = le_u32(eocd, 12);
    let classic_start = le_u32(eocd, 16);
    let needs_zip64 =
        entries_total == u16::MAX || classic_size == u32::MAX || classic_start == u32::MAX;

    if !needs_zip64 {
        if disk_number != 0 {
            return Err(IpaInspectError::MultiDiskArchive);
        }
        return Ok(Footer {
            entry_count: u64::from(entries_total),
            central_start: u64::from(classic_start),
            central_size: u64::from(classic_size),
            central_end: eocd_offset,
        });
    }

    let locator_offset = eocd_offset
        .checked_sub(ZIP64_LOCATOR_BYTES)
        .ok_or_else(|| IpaInspectError::InvalidArchive {
            reason: "ZIP64 locator is missing".to_owned(),
        })?;
    let mut locator = [0u8; ZIP64_LOCATOR_BYTES as usize];
    read_exact_at(reader, locator_offset, &mut locator)?;
    if le_u32(&locator, 0) != ZIP64_LOCATOR_SIGNATURE {
        return Err(IpaInspectError::InvalidArchive {
            reason: "ZIP64 locator has an invalid signature".to_owned(),
        });
    }
    if le_u32(&locator, 4) != 0 || le_u32(&locator, 16) != 1 {
        return Err(IpaInspectError::MultiDiskArchive);
    }

    let zip64_offset = le_u64(&locator, 8);
    let mut zip64 = [0u8; ZIP64_EOCD_FIXED_BYTES];
    read_exact_at(reader, zip64_offset, &mut zip64)?;
    if le_u32(&zip64, 0) != ZIP64_EOCD_SIGNATURE {
        return Err(IpaInspectError::InvalidArchive {
            reason: "ZIP64 end record has an invalid signature".to_owned(),
        });
    }
    let record_size = le_u64(&zip64, 4);
    if record_size < ZIP64_EOCD_MIN_RECORD_BYTES {
        return Err(IpaInspectError::InvalidArchive {
            reason: "ZIP64 end record is shorter than its fixed fields".to_owned(),
        });
    }
    let record_end = zip64_offset
        .checked_add(12)
        .and_then(|value| value.checked_add(record_size))
        .ok_or_else(|| IpaInspectError::InvalidArchive {
            reason: "ZIP64 end-record range overflowed".to_owned(),
        })?;
    if record_end != locator_offset {
        return Err(IpaInspectError::InvalidArchive {
            reason: "ZIP64 footer records are not contiguous".to_owned(),
        });
    }
    if le_u32(&zip64, 16) != 0 || le_u32(&zip64, 20) != 0 {
        return Err(IpaInspectError::MultiDiskArchive);
    }
    let entries_on_disk = le_u64(&zip64, 24);
    let entries_total = le_u64(&zip64, 32);
    if entries_on_disk != entries_total {
        return Err(IpaInspectError::MultiDiskArchive);
    }

    Ok(Footer {
        entry_count: entries_total,
        central_size: le_u64(&zip64, 40),
        central_start: le_u64(&zip64, 48),
        central_end: zip64_offset,
    })
}

fn validate_local_header<R: Read + Seek>(
    reader: &mut R,
    expected: &LocalEntryExpectation,
) -> Result<(), IpaInspectError> {
    let mut fixed = [0u8; LOCAL_ENTRY_FIXED_BYTES];
    read_exact_at(reader, expected.header_start, &mut fixed).map_err(|error| match error {
        IpaInspectError::Io(source) if source.kind() == io::ErrorKind::UnexpectedEof => {
            IpaInspectError::InvalidArchive {
                reason: format!("local header for entry {} is truncated", expected.index),
            }
        }
        other => other,
    })?;
    if le_u32(&fixed, 0) != LOCAL_ENTRY_SIGNATURE {
        return Err(IpaInspectError::InvalidArchive {
            reason: format!(
                "local header for entry {} has an invalid signature",
                expected.index
            ),
        });
    }

    let flags = le_u16(&fixed, 6);
    let compression_method = le_u16(&fixed, 8);
    let name_len = usize::from(le_u16(&fixed, 26));
    let extra_len = u64::from(le_u16(&fixed, 28));
    let data_start = expected
        .header_start
        .checked_add(LOCAL_ENTRY_FIXED_BYTES as u64)
        .and_then(|value| value.checked_add(name_len as u64))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| IpaInspectError::InvalidArchive {
            reason: format!("local header for entry {} overflowed", expected.index),
        })?;
    if data_start != expected.data_start {
        return Err(IpaInspectError::InvalidArchive {
            reason: format!(
                "local header for entry {} has an inconsistent data offset",
                expected.index
            ),
        });
    }

    let mut raw_name = vec![0u8; name_len];
    reader.read_exact(&mut raw_name)?;
    if raw_name != expected.raw_name {
        return Err(IpaInspectError::InvalidArchive {
            reason: format!(
                "local and central names differ for entry {}",
                expected.index
            ),
        });
    }
    if flags != expected.flags || compression_method != expected.compression_method {
        return Err(IpaInspectError::InvalidArchive {
            reason: format!(
                "local and central flags or compression method differ for entry {}",
                expected.index
            ),
        });
    }
    if flags & ENCRYPTED_FLAG != 0 {
        return Err(IpaInspectError::EncryptedEntry {
            path: str::from_utf8(&expected.raw_name)
                .unwrap_or("<invalid-entry-name>")
                .trim_end_matches('/')
                .to_owned(),
        });
    }
    if flags & DATA_DESCRIPTOR_FLAG == 0
        && (le_u32(&fixed, 14) != expected.crc32
            || le_u32(&fixed, 18) != expected.compressed_size_32
            || le_u32(&fixed, 22) != expected.uncompressed_size_32)
    {
        return Err(IpaInspectError::InvalidArchive {
            reason: format!(
                "local and central CRC or sizes differ for entry {}",
                expected.index
            ),
        });
    }
    Ok(())
}

fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    output: &mut [u8],
) -> Result<(), IpaInspectError> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(output)?;
    Ok(())
}

fn validate_entry_path(
    index: usize,
    raw_path: &str,
    directory_name: bool,
) -> Result<String, IpaInspectError> {
    if raw_path.is_empty() || raw_path.starts_with('/') {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "path is empty or absolute",
        });
    }
    if raw_path.contains('\\') {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "backslash separators are forbidden",
        });
    }
    if raw_path.chars().any(char::is_control) {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "control characters are forbidden",
        });
    }

    let canonical = if directory_name {
        raw_path.strip_suffix('/').unwrap_or(raw_path)
    } else {
        raw_path
    };
    if canonical.is_empty() || canonical.len() > MAX_IPA_PATH_BYTES {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "canonical path length is outside the accepted range",
        });
    }

    let components: Vec<_> = canonical.split('/').collect();
    if components.len() > MAX_IPA_PATH_DEPTH {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "path depth exceeds the safety limit",
        });
    }
    if components.iter().any(|component| {
        component.is_empty()
            || *component == "."
            || *component == ".."
            || component.len() > MAX_IPA_PATH_COMPONENT_BYTES
    }) {
        return Err(IpaInspectError::UnsafeEntryPath {
            index,
            reason: "path contains an empty, dot, parent, or oversized component",
        });
    }

    Ok(canonical.to_owned())
}

fn select_app_root(entries: &[CentralEntry]) -> Result<String, IpaInspectError> {
    let mut roots = BTreeSet::new();
    for entry in entries {
        let components: Vec<_> = entry.path.split('/').collect();
        if components.first() != Some(&"Payload") {
            return Err(IpaInspectError::EntryOutsideAppRoot {
                path: entry.path.clone(),
            });
        }
        if components.len() == 1 {
            if !entry.directory_name {
                return Err(IpaInspectError::EntryOutsideAppRoot {
                    path: entry.path.clone(),
                });
            }
            continue;
        }

        let app_component = components[1];
        if app_component.len() <= ".app".len() || !app_component.ends_with(".app") {
            return Err(IpaInspectError::EntryOutsideAppRoot {
                path: entry.path.clone(),
            });
        }
        roots.insert(format!("Payload/{app_component}"));
    }

    if roots.is_empty() {
        return Err(IpaInspectError::MissingAppRoot);
    }
    if roots.len() != 1 {
        return Err(IpaInspectError::MultipleAppRoots {
            roots: roots.into_iter().collect(),
        });
    }

    let root = roots.into_iter().next().expect("one root was checked");
    for entry in entries {
        if entry.path == "Payload"
            || entry.path == root
            || entry
                .path
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            continue;
        }
        return Err(IpaInspectError::EntryOutsideAppRoot {
            path: entry.path.clone(),
        });
    }
    Ok(root)
}

fn classify_entry_kind(
    path: &str,
    directory_name: bool,
    unix_mode: Option<u32>,
) -> Result<IpaEntryKind, IpaInspectError> {
    let file_type = unix_mode.unwrap_or(0) & UNIX_FILE_TYPE_MASK;
    match file_type {
        0 => Ok(if directory_name {
            IpaEntryKind::Directory
        } else {
            IpaEntryKind::File
        }),
        UNIX_REGULAR_FILE if !directory_name => Ok(IpaEntryKind::File),
        UNIX_DIRECTORY if directory_name => Ok(IpaEntryKind::Directory),
        UNIX_REGULAR_FILE | UNIX_DIRECTORY => Err(IpaInspectError::InconsistentDirectoryKind {
            path: path.to_owned(),
        }),
        UNIX_SYMLINK => Err(IpaInspectError::UnsupportedEntryKind {
            path: path.to_owned(),
            mode: unix_mode.unwrap_or(file_type),
        }),
        _ => Err(IpaInspectError::UnsupportedEntryKind {
            path: path.to_owned(),
            mode: unix_mode.unwrap_or(file_type),
        }),
    }
}

fn validate_declared_sizes(
    path: &str,
    compressed: u64,
    uncompressed: u64,
) -> Result<(), IpaInspectError> {
    if uncompressed > MAX_IPA_ENTRY_UNCOMPRESSED_BYTES {
        return Err(IpaInspectError::EntryTooLarge {
            path: path.to_owned(),
            actual: uncompressed,
            maximum: MAX_IPA_ENTRY_UNCOMPRESSED_BYTES,
        });
    }
    let ratio_exceeded = uncompressed > 0
        && (compressed == 0
            || compressed
                .checked_mul(MAX_IPA_COMPRESSION_RATIO)
                .is_some_and(|maximum| uncompressed > maximum));
    if ratio_exceeded {
        return Err(IpaInspectError::CompressionRatioExceeded {
            path: path.to_owned(),
            compressed,
            uncompressed,
            maximum: MAX_IPA_COMPRESSION_RATIO,
        });
    }
    Ok(())
}

fn add_declared_sizes(
    total_compressed: u64,
    total_uncompressed: u64,
    compressed: u64,
    uncompressed: u64,
    archive_size: u64,
) -> Result<(u64, u64), IpaInspectError> {
    let total_compressed =
        total_compressed
            .checked_add(compressed)
            .ok_or(IpaInspectError::AggregateSizeOverflow {
                field: "compressed",
            })?;
    let total_uncompressed = total_uncompressed.checked_add(uncompressed).ok_or(
        IpaInspectError::AggregateSizeOverflow {
            field: "uncompressed",
        },
    )?;
    if total_uncompressed > MAX_IPA_TOTAL_UNCOMPRESSED_BYTES {
        return Err(IpaInspectError::AggregateUncompressedTooLarge {
            actual: total_uncompressed,
            maximum: MAX_IPA_TOTAL_UNCOMPRESSED_BYTES,
        });
    }
    if total_compressed > archive_size {
        return Err(IpaInspectError::AggregateCompressedTooLarge {
            actual: total_compressed,
            archive_size,
        });
    }
    Ok((total_compressed, total_uncompressed))
}

fn reject_overlapping_ranges(ranges: &mut [Range<u64>]) -> Result<(), IpaInspectError> {
    ranges.sort_by_key(|range| (range.start, range.end));
    if ranges.windows(2).any(|pair| pair[1].start < pair[0].end) {
        return Err(IpaInspectError::OverlappingEntries);
    }
    Ok(())
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    enum FixtureEntry<'a> {
        Directory(&'a str),
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
    }

    fn options_with_method(method: CompressionMethod) -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o644)
    }

    fn options() -> SimpleFileOptions {
        options_with_method(CompressionMethod::Stored)
    }

    fn make_archive(entries: &[FixtureEntry<'_>]) -> Vec<u8> {
        make_archive_with_file_method(entries, CompressionMethod::Stored)
    }

    fn make_archive_with_file_method(
        entries: &[FixtureEntry<'_>],
        file_method: CompressionMethod,
    ) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for entry in entries {
            match entry {
                FixtureEntry::Directory(path) => {
                    writer
                        .add_directory(*path, options())
                        .expect("add directory");
                }
                FixtureEntry::File(path, bytes) => {
                    writer
                        .start_file(*path, options_with_method(file_method))
                        .expect("start file");
                    writer.write_all(bytes).expect("write fixture bytes");
                }
                FixtureEntry::Symlink(path, target) => {
                    writer
                        .add_symlink(*path, *target, options())
                        .expect("add symlink");
                }
            }
        }
        writer.finish().expect("finish archive").into_inner()
    }

    fn valid_archive() -> Vec<u8> {
        make_archive(&[
            FixtureEntry::Directory("Payload"),
            FixtureEntry::Directory("Payload/Demo.app"),
            FixtureEntry::File("Payload/Demo.app/Info.plist", b"plist"),
            FixtureEntry::File("Payload/Demo.app/Demo", b"macho"),
        ])
    }

    fn inspect(bytes: &[u8]) -> Result<IpaInventory, IpaInspectError> {
        inspect_ipa(Cursor::new(bytes), bytes.len() as u64)
    }

    fn signature_offsets(bytes: &[u8], signature: u32) -> Vec<usize> {
        let signature = signature.to_le_bytes();
        bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == signature).then_some(offset))
            .collect()
    }

    fn eocd_offset(bytes: &[u8]) -> usize {
        *signature_offsets(bytes, EOCD_SIGNATURE)
            .last()
            .expect("EOCD signature")
    }

    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn central_offset_for(bytes: &[u8], path: &str) -> usize {
        signature_offsets(bytes, CENTRAL_ENTRY_SIGNATURE)
            .into_iter()
            .find(|offset| {
                let name_len = usize::from(le_u16(bytes, offset + 28));
                let name_start = offset + CENTRAL_ENTRY_FIXED_BYTES;
                bytes.get(name_start..name_start + name_len) == Some(path.as_bytes())
            })
            .expect("fixture central entry")
    }

    fn set_declared_uncompressed_size(bytes: &mut [u8], path: &str, size: u32) {
        let central = central_offset_for(bytes, path);
        let local = le_u32(bytes, central + 42) as usize;
        set_u32(bytes, central + 24, size);
        set_u32(bytes, local + 22, size);
    }

    #[test]
    fn valid_ipa_is_deterministic_and_does_not_modify_input() {
        let bytes = valid_archive();
        let original = bytes.clone();
        let mut cursor = Cursor::new(bytes);
        let size = cursor.get_ref().len() as u64;

        let first = inspect_ipa(&mut cursor, size).expect("valid inventory");
        let second = inspect(cursor.get_ref()).expect("repeat inventory");

        assert_eq!(first, second);
        assert_eq!(cursor.get_ref(), &original);
        assert_eq!(first.app_root, "Payload/Demo.app");
        assert_eq!(first.entry_count, 4);
        assert_eq!(first.file_count, 2);
        assert_eq!(first.directory_count, 2);
        assert_eq!(first.total_compressed_size, 10);
        assert_eq!(first.total_uncompressed_size, 10);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Payload",
                "Payload/Demo.app",
                "Payload/Demo.app/Demo",
                "Payload/Demo.app/Info.plist",
            ]
        );
    }

    #[test]
    fn reads_stored_entry_deterministically_without_modifying_input() {
        let bytes = valid_archive();
        let original = bytes.clone();
        let mut cursor = Cursor::new(bytes);
        let size = cursor.get_ref().len() as u64;

        let first = read_ipa_entry_bounded(&mut cursor, size, "Payload/Demo.app/Info.plist", 1024)
            .expect("read stored entry");
        let second = read_ipa_entry_bounded(&mut cursor, size, "Payload/Demo.app/Info.plist", 1024)
            .expect("repeat stored entry");

        assert_eq!(first, b"plist");
        assert_eq!(first, second);
        assert_eq!(cursor.get_ref(), &original);
    }

    #[test]
    fn reads_deflated_entry_and_checks_declared_size() {
        let payload = vec![b'A'; 2048];
        let bytes = make_archive_with_file_method(
            &[FixtureEntry::File("Payload/Demo.app/Info.plist", &payload)],
            CompressionMethod::Deflated,
        );

        let output = read_ipa_entry_bounded(
            Cursor::new(&bytes),
            bytes.len() as u64,
            "Payload/Demo.app/Info.plist",
            payload.len() as u64,
        )
        .expect("read deflated entry");

        assert_eq!(output, payload);
    }

    #[test]
    fn rejects_unsafe_missing_and_directory_selectors() {
        let bytes = valid_archive();
        let size = bytes.len() as u64;

        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&bytes), size, "../Info.plist", 1024),
            Err(IpaEntryReadError::UnsafeSelector { .. })
        ));
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&bytes), size, "Payload/Demo.app/Missing", 1024,),
            Err(IpaEntryReadError::EntryNotFound { .. })
        ));
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&bytes), size, "Payload/Demo.app", 1024,),
            Err(IpaEntryReadError::EntryIsDirectory { .. })
        ));
    }

    #[test]
    fn enforces_caller_and_fixed_read_limits_before_payload_read() {
        let bytes = valid_archive();
        let size = bytes.len() as u64;

        for invalid in [0, MAX_IPA_ENTRY_READ_BYTES + 1] {
            assert!(matches!(
                read_ipa_entry_bounded(
                    Cursor::new(&bytes),
                    size,
                    "Payload/Demo.app/Info.plist",
                    invalid,
                ),
                Err(IpaEntryReadError::InvalidOutputLimit { .. })
            ));
        }
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&bytes), size, "Payload/Demo.app/Info.plist", 4,),
            Err(IpaEntryReadError::DeclaredOutputTooLarge { .. })
        ));

        let oversized = IpaEntry {
            path: "Payload/Demo.app/large".to_owned(),
            kind: IpaEntryKind::File,
            compressed_size: MAX_IPA_ENTRY_READ_COMPRESSED_BYTES + 1,
            uncompressed_size: 1,
            crc32: 0,
        };
        assert!(matches!(
            validate_entry_read_limits(&oversized, 1, MAX_IPA_ENTRY_READ_COMPRESSED_BYTES),
            Err(IpaEntryReadError::CompressedInputTooLarge { .. })
        ));
    }

    #[test]
    fn copies_stored_and_deflated_entries_to_a_caller_sink() {
        let payload = vec![b'A'; 128 * 1024];
        for method in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            let path = "Payload/Demo.app/Demo";
            let bytes =
                make_archive_with_file_method(&[FixtureEntry::File(path, &payload)], method);
            let mut output = Vec::new();

            let copied = copy_ipa_entry_bounded(
                Cursor::new(&bytes),
                bytes.len() as u64,
                path,
                payload.len() as u64,
                &mut output,
            )
            .expect("copy bounded entry");

            assert_eq!(output, payload);
            assert_eq!(copied.bytes_written, payload.len() as u64);
            assert_eq!(copied.inventory.app_root, "Payload/Demo.app");
        }
    }

    #[test]
    fn copy_enforces_fixed_limits_and_surfaces_sink_failures() {
        let path = "Payload/Demo.app/Demo";
        let bytes = make_archive(&[FixtureEntry::File(path, b"data")]);

        for invalid in [0, MAX_IPA_ENTRY_COPY_BYTES + 1] {
            assert!(matches!(
                copy_ipa_entry_bounded(
                    Cursor::new(&bytes),
                    bytes.len() as u64,
                    path,
                    invalid,
                    &mut Vec::new(),
                ),
                Err(IpaEntryReadError::InvalidOutputLimit { .. })
            ));
        }
        assert!(matches!(
            copy_ipa_entry_bounded(
                Cursor::new(&bytes),
                bytes.len() as u64,
                path,
                3,
                &mut Vec::new(),
            ),
            Err(IpaEntryReadError::DeclaredOutputTooLarge { .. })
        ));

        let mut sink = FailingWriter;
        assert!(matches!(
            copy_ipa_entry_bounded(Cursor::new(&bytes), bytes.len() as u64, path, 4, &mut sink,),
            Err(IpaEntryReadError::WriteFailed { .. })
        ));
    }

    #[test]
    fn copy_reaches_eof_for_crc_and_rejects_unsupported_compression() {
        let path = "Payload/Demo.app/Demo";
        let mut corrupt = make_archive(&[FixtureEntry::File(path, b"data")]);
        let central = central_offset_for(&corrupt, path);
        let local = le_u32(&corrupt, central + 42) as usize;
        let name_len = usize::from(le_u16(&corrupt, local + 26));
        let extra_len = usize::from(le_u16(&corrupt, local + 28));
        corrupt[local + LOCAL_ENTRY_FIXED_BYTES + name_len + extra_len] ^= 0xff;
        assert!(matches!(
            copy_ipa_entry_bounded(
                Cursor::new(&corrupt),
                corrupt.len() as u64,
                path,
                1024,
                &mut Vec::new(),
            ),
            Err(IpaEntryReadError::ReadFailed { .. })
        ));

        let mut unsupported = make_archive(&[FixtureEntry::File(path, b"data")]);
        let central = central_offset_for(&unsupported, path);
        let local = le_u32(&unsupported, central + 42) as usize;
        set_u16(&mut unsupported, central + 10, 12);
        set_u16(&mut unsupported, local + 8, 12);
        assert!(matches!(
            copy_ipa_entry_bounded(
                Cursor::new(&unsupported),
                unsupported.len() as u64,
                path,
                1024,
                &mut Vec::new(),
            ),
            Err(IpaEntryReadError::UnsupportedCompression { .. })
        ));
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic sink failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn rejects_unsupported_compression_before_decompression() {
        let path = "Payload/Demo.app/Demo";
        let mut bytes = make_archive(&[FixtureEntry::File(path, b"data")]);
        let central = central_offset_for(&bytes, path);
        let local = le_u32(&bytes, central + 42) as usize;
        set_u16(&mut bytes, central + 10, 12);
        set_u16(&mut bytes, local + 8, 12);

        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&bytes), bytes.len() as u64, path, 1024),
            Err(IpaEntryReadError::UnsupportedCompression { ref method, .. })
                if method.contains("12")
        ));
    }

    #[test]
    fn rejects_reopened_entry_metadata_drift() {
        let path = "Payload/Demo.app/Demo";
        let bytes = make_archive(&[FixtureEntry::File(path, b"data")]);
        let mut expected = inspect(&bytes)
            .expect("valid inventory")
            .entries
            .into_iter()
            .find(|entry| entry.path == path)
            .expect("fixture entry");
        expected.crc32 ^= 1;

        let mut archive = ZipArchive::new(Cursor::new(&bytes)).expect("reopen fixture");
        let index = archive.index_for_name(path).expect("fixture entry index");
        let file = archive.by_index_raw(index).expect("raw fixture entry");

        assert!(matches!(
            validate_reopened_entry(&file, &expected),
            Err(IpaEntryReadError::MetadataChanged { .. })
        ));
    }

    #[test]
    fn rejects_crc_corruption_and_observed_output_over_limit() {
        let path = "Payload/Demo.app/Demo";
        let mut corrupt = make_archive(&[FixtureEntry::File(path, b"data")]);
        let central = central_offset_for(&corrupt, path);
        let local = le_u32(&corrupt, central + 42) as usize;
        let name_len = usize::from(le_u16(&corrupt, local + 26));
        let extra_len = usize::from(le_u16(&corrupt, local + 28));
        corrupt[local + LOCAL_ENTRY_FIXED_BYTES + name_len + extra_len] ^= 0xff;
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&corrupt), corrupt.len() as u64, path, 1024),
            Err(IpaEntryReadError::ReadFailed { .. })
        ));

        let mut understated = make_archive(&[FixtureEntry::File(path, b"data")]);
        set_declared_uncompressed_size(&mut understated, path, 3);
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&understated), understated.len() as u64, path, 3),
            Err(IpaEntryReadError::OutputLimitExceeded { .. })
        ));
        assert!(matches!(
            read_ipa_entry_bounded(Cursor::new(&understated), understated.len() as u64, path, 4),
            Err(IpaEntryReadError::ActualSizeMismatch {
                declared: 3,
                actual: 4,
                ..
            })
        ));
    }

    #[test]
    fn entry_read_propagates_full_preflight_failures() {
        let malformed = b"not a zip";
        assert!(matches!(
            read_ipa_entry_bounded(
                Cursor::new(malformed),
                malformed.len() as u64,
                "Payload/Demo.app/Demo",
                1024,
            ),
            Err(IpaEntryReadError::Inspect(
                IpaInspectError::InvalidArchive { .. }
            ))
        ));

        let symlink = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/Demo", b"data"),
            FixtureEntry::Symlink("Payload/Demo.app/link", "Demo"),
        ]);
        assert!(matches!(
            read_ipa_entry_bounded(
                Cursor::new(&symlink),
                symlink.len() as u64,
                "Payload/Demo.app/Demo",
                1024,
            ),
            Err(IpaEntryReadError::Inspect(
                IpaInspectError::UnsupportedEntryKind { .. }
            ))
        ));
    }

    #[test]
    fn rejects_size_mismatch_oversized_and_malformed_inputs() {
        let bytes = valid_archive();
        assert!(matches!(
            inspect_ipa(Cursor::new(&bytes), bytes.len() as u64 + 1),
            Err(IpaInspectError::ArchiveSizeMismatch { .. })
        ));
        assert!(matches!(
            inspect_ipa(Cursor::new(&bytes), MAX_IPA_ARCHIVE_BYTES + 1),
            Err(IpaInspectError::ArchiveTooLarge { .. })
        ));
        assert!(matches!(
            inspect(b"not a zip"),
            Err(IpaInspectError::InvalidArchive { .. })
        ));
        for tiny in [b"".as_slice(), b"P".as_slice(), b"PK\x03\x04".as_slice()] {
            assert!(matches!(
                inspect(tiny),
                Err(IpaInspectError::InvalidArchive { .. })
            ));
        }
    }

    #[test]
    fn rejects_unsafe_path_classes_and_limits() {
        let invalid = [
            "",
            "/Payload/Demo.app/Demo",
            "Payload\\Demo.app\\Demo",
            "Payload//Demo.app/Demo",
            "Payload/./Demo.app/Demo",
            "Payload/../Demo.app/Demo",
            "Payload/Demo.app/Demo\0suffix",
            "Payload/Demo.app/Demo\u{0085}suffix",
        ];
        for path in invalid {
            assert!(
                matches!(
                    validate_entry_path(0, path, false),
                    Err(IpaInspectError::UnsafeEntryPath { .. })
                ),
                "accepted {path:?}"
            );
        }

        let deep = std::iter::repeat_n("a", MAX_IPA_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_entry_path(0, &deep, false).is_err());
        let component = "a".repeat(MAX_IPA_PATH_COMPONENT_BYTES + 1);
        assert!(validate_entry_path(0, &format!("Payload/{component}"), false).is_err());
        let long = format!("Payload/Demo.app/{}", "a".repeat(MAX_IPA_PATH_BYTES));
        assert!(validate_entry_path(0, &long, false).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_entry_name() {
        let mut bytes = make_archive(&[FixtureEntry::File("Payload/Demo.app/x", b"data")]);
        let central = signature_offsets(&bytes, CENTRAL_ENTRY_SIGNATURE)[0];
        let name_start = central + CENTRAL_ENTRY_FIXED_BYTES;
        bytes[name_start + "Payload/Demo.app/".len()] = 0xff;

        assert!(matches!(
            inspect(&bytes),
            Err(IpaInspectError::InvalidEntryNameEncoding { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_and_case_colliding_destinations() {
        let mut duplicate = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/One", b"one"),
            FixtureEntry::File("Payload/Demo.app/Two", b"two"),
        ]);
        let central = signature_offsets(&duplicate, CENTRAL_ENTRY_SIGNATURE);
        let first_name_start = central[0] + CENTRAL_ENTRY_FIXED_BYTES;
        let second_name_start = central[1] + CENTRAL_ENTRY_FIXED_BYTES;
        let name_len = usize::from(le_u16(&duplicate, central[0] + 28));
        let first_name = duplicate[first_name_start..first_name_start + name_len].to_vec();
        duplicate[second_name_start..second_name_start + name_len].copy_from_slice(&first_name);
        assert!(matches!(
            inspect(&duplicate),
            Err(IpaInspectError::DuplicateEntryPath { .. })
        ));

        let collision = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/Demo", b"one"),
            FixtureEntry::File("Payload/Demo.app/demo", b"two"),
        ]);
        assert!(matches!(
            inspect(&collision),
            Err(IpaInspectError::CaseCollidingEntryPaths { .. })
        ));
    }

    #[test]
    fn rejects_missing_multiple_empty_and_out_of_scope_app_roots() {
        let missing = make_archive(&[FixtureEntry::Directory("Payload")]);
        assert!(matches!(
            inspect(&missing),
            Err(IpaInspectError::MissingAppRoot)
        ));

        let multiple = make_archive(&[
            FixtureEntry::File("Payload/One.app/One", b"one"),
            FixtureEntry::File("Payload/Two.app/Two", b"two"),
        ]);
        assert!(matches!(
            inspect(&multiple),
            Err(IpaInspectError::MultipleAppRoots { .. })
        ));

        let empty = make_archive(&[FixtureEntry::Directory("Payload/Demo.app")]);
        assert!(matches!(
            inspect(&empty),
            Err(IpaInspectError::EmptyAppBundle { .. })
        ));

        let outside = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/Demo", b"data"),
            FixtureEntry::File("metadata.plist", b"metadata"),
        ]);
        assert!(matches!(
            inspect(&outside),
            Err(IpaInspectError::EntryOutsideAppRoot { .. })
        ));
    }

    #[test]
    fn rejects_encrypted_symlink_and_special_entries() {
        let mut encrypted = make_archive(&[FixtureEntry::File("Payload/Demo.app/Demo", b"data")]);
        let central = signature_offsets(&encrypted, CENTRAL_ENTRY_SIGNATURE)[0];
        let flags = le_u16(&encrypted, central + 8) | ENCRYPTED_FLAG;
        set_u16(&mut encrypted, central + 8, flags);
        assert!(matches!(
            inspect(&encrypted),
            Err(IpaInspectError::EncryptedEntry { .. })
        ));

        let symlink = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/Demo", b"data"),
            FixtureEntry::Symlink("Payload/Demo.app/link", "Demo"),
        ]);
        assert!(matches!(
            inspect(&symlink),
            Err(IpaInspectError::UnsupportedEntryKind { .. })
        ));

        let mut fifo = make_archive(&[FixtureEntry::File("Payload/Demo.app/Demo", b"data")]);
        let central = signature_offsets(&fifo, CENTRAL_ENTRY_SIGNATURE)[0];
        fifo[central + 5] = 3;
        set_u32(&mut fifo, central + 38, 0o010_644 << 16);
        assert!(matches!(
            inspect(&fifo),
            Err(IpaInspectError::UnsupportedEntryKind { .. })
        ));
    }

    #[test]
    fn rejects_overlapping_local_entry_regions() {
        let mut bytes = make_archive(&[
            FixtureEntry::File("Payload/Demo.app/One", b"one"),
            FixtureEntry::File("Payload/Demo.app/Two", b"two"),
        ]);
        let central = signature_offsets(&bytes, CENTRAL_ENTRY_SIGNATURE);
        let first_header = le_u32(&bytes, central[0] + 42);
        set_u32(&mut bytes, central[1] + 42, first_header);

        assert!(matches!(
            inspect(&bytes),
            Err(IpaInspectError::OverlappingEntries)
        ));
    }

    #[test]
    fn rejects_local_and_central_header_disagreement() {
        let mut bytes = make_archive(&[FixtureEntry::File("Payload/Demo.app/Demo", b"data")]);
        let central = signature_offsets(&bytes, CENTRAL_ENTRY_SIGNATURE)[0];
        let local = le_u32(&bytes, central + 42) as usize;
        let local_name_start = local + LOCAL_ENTRY_FIXED_BYTES;
        bytes[local_name_start + "Payload/Demo.app/".len()] = b'X';

        assert!(matches!(
            inspect(&bytes),
            Err(IpaInspectError::InvalidArchive { .. })
        ));
    }

    #[test]
    fn rejects_entry_count_and_central_directory_limits_before_entry_walk() {
        let mut too_many = valid_archive();
        let eocd = eocd_offset(&too_many);
        let count = u16::try_from(MAX_IPA_ENTRIES + 1).expect("test limit fits u16");
        set_u16(&mut too_many, eocd + 8, count);
        set_u16(&mut too_many, eocd + 10, count);
        assert!(matches!(
            inspect(&too_many),
            Err(IpaInspectError::TooManyEntries { .. })
        ));

        let mut oversized_central = valid_archive();
        let eocd = eocd_offset(&oversized_central);
        set_u32(
            &mut oversized_central,
            eocd + 12,
            u32::try_from(MAX_IPA_CENTRAL_DIRECTORY_BYTES + 1)
                .expect("central-directory limit fits u32"),
        );
        assert!(matches!(
            inspect(&oversized_central),
            Err(IpaInspectError::CentralDirectoryTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_multidisk_markers_in_footer_or_entries() {
        let mut footer = valid_archive();
        let eocd = eocd_offset(&footer);
        set_u16(&mut footer, eocd + 4, 1);
        set_u16(&mut footer, eocd + 6, 1);
        assert!(matches!(
            inspect(&footer),
            Err(IpaInspectError::MultiDiskArchive)
        ));

        let mut entry = valid_archive();
        let central = signature_offsets(&entry, CENTRAL_ENTRY_SIGNATURE)[0];
        set_u16(&mut entry, central + 34, 1);
        assert!(matches!(
            inspect(&entry),
            Err(IpaInspectError::MultiDiskArchive)
        ));
    }

    #[test]
    fn declared_size_limits_and_arithmetic_fail_closed() {
        assert!(validate_declared_sizes("file", 1, MAX_IPA_COMPRESSION_RATIO).is_ok());
        assert!(matches!(
            validate_declared_sizes("file", 1, MAX_IPA_COMPRESSION_RATIO + 1),
            Err(IpaInspectError::CompressionRatioExceeded { .. })
        ));
        assert!(matches!(
            validate_declared_sizes("file", 0, 1),
            Err(IpaInspectError::CompressionRatioExceeded { .. })
        ));
        assert!(matches!(
            validate_declared_sizes("file", u64::MAX, MAX_IPA_ENTRY_UNCOMPRESSED_BYTES + 1),
            Err(IpaInspectError::EntryTooLarge { .. })
        ));

        assert!(matches!(
            add_declared_sizes(u64::MAX, 0, 1, 0, u64::MAX),
            Err(IpaInspectError::AggregateSizeOverflow {
                field: "compressed"
            })
        ));
        assert!(matches!(
            add_declared_sizes(0, u64::MAX, 0, 1, u64::MAX),
            Err(IpaInspectError::AggregateSizeOverflow {
                field: "uncompressed"
            })
        ));
        assert!(matches!(
            add_declared_sizes(0, MAX_IPA_TOTAL_UNCOMPRESSED_BYTES, 0, 1, u64::MAX),
            Err(IpaInspectError::AggregateUncompressedTooLarge { .. })
        ));
        assert!(matches!(
            add_declared_sizes(10, 0, 1, 0, 10),
            Err(IpaInspectError::AggregateCompressedTooLarge { .. })
        ));
    }

    #[test]
    fn adjacent_ranges_are_allowed_but_overlaps_are_rejected() {
        let mut adjacent = vec![0..10, 10..20];
        assert!(reject_overlapping_ranges(&mut adjacent).is_ok());

        let mut overlapping = vec![10..20, 0..11];
        assert!(matches!(
            reject_overlapping_ranges(&mut overlapping),
            Err(IpaInspectError::OverlappingEntries)
        ));
    }
}
