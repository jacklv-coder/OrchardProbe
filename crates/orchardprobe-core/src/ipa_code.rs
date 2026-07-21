//! Bounded Mach-O metadata inspection for the root executable in an IPA.
//!
//! The declared executable is resolved through the root `Info.plist`, streamed
//! to an anonymous automatically cleaned temporary file, and parsed by the
//! existing bounded Mach-O parser. The source IPA is never modified. Header
//! metadata does not prove that any payload byte is plaintext.

use std::io::{Read, Seek};

use serde::Serialize;
use thiserror::Error;

use crate::ipa::{
    IpaEntry, IpaEntryReadError, IpaInventory, MAX_IPA_ENTRY_COPY_BYTES, copy_ipa_entry_bounded,
};
use crate::ipa_app::{
    IpaAppMetadata, IpaAppMetadataError, inspect_ipa_app_metadata_with_inventory,
};
use crate::macho::{MachOParseError, MachOReport, parse_macho};

/// Maximum accepted bytes for the root app executable inspection stage.
pub const MAX_IPA_MAIN_EXECUTABLE_BYTES: u64 = MAX_IPA_ENTRY_COPY_BYTES;

/// Root app identity, exact entry metadata, and bounded Mach-O metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaMainExecutable {
    pub app: IpaAppMetadata,
    pub entry: IpaEntry,
    pub macho: MachOReport,
}

/// Failure while resolving, copying, or parsing the root IPA executable.
#[derive(Debug, Error)]
pub enum IpaMainExecutableError {
    #[error("IPA app metadata inspection failed: {0}")]
    AppMetadata(#[from] IpaAppMetadataError),

    #[error("root executable `{path}` declares {actual} bytes; inspection maximum is {maximum}")]
    ExecutableTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },

    #[error("declared root executable `{path}` disappeared from its bound inventory")]
    ExecutableEntryMissing { path: String },

    #[error("could not create an anonymous temporary file for Mach-O inspection: {source}")]
    TemporaryFile {
        #[source]
        source: std::io::Error,
    },

    #[error("bounded root executable copy failed: {0}")]
    EntryCopy(#[from] IpaEntryReadError),

    #[error("IPA inventory changed while copying the root executable")]
    InventoryChanged,

    #[error("root executable `{path}` is not a valid bounded Mach-O: {source}")]
    MachO {
        path: String,
        #[source]
        source: MachOParseError,
    },
}

/// Inspect the exact root executable declared by an IPA's `Info.plist`.
///
/// The reader must be the secured regular-file handle used to obtain
/// `archive_size`. A complete inventory is validated while reading the plist
/// and again while copying the executable. Any difference fails closed. The
/// anonymous temporary file is removed automatically on success or failure.
pub fn inspect_ipa_main_executable<R: Read + Seek>(
    reader: R,
    archive_size: u64,
) -> Result<IpaMainExecutable, IpaMainExecutableError> {
    inspect_ipa_main_executable_with_inventory(reader, archive_size).map(|(main, _)| main)
}

pub(crate) fn inspect_ipa_main_executable_with_inventory<R: Read + Seek>(
    mut reader: R,
    archive_size: u64,
) -> Result<(IpaMainExecutable, IpaInventory), IpaMainExecutableError> {
    let (app, metadata_inventory) =
        inspect_ipa_app_metadata_with_inventory(&mut reader, archive_size)?;
    let entry = metadata_inventory
        .entries
        .iter()
        .find(|entry| entry.path == app.executable_path)
        .ok_or_else(|| IpaMainExecutableError::ExecutableEntryMissing {
            path: app.executable_path.clone(),
        })?
        .clone();
    validate_main_entry_size(&entry)?;

    let mut temporary =
        tempfile::tempfile().map_err(|source| IpaMainExecutableError::TemporaryFile { source })?;
    let copied = copy_ipa_entry_bounded(
        &mut reader,
        archive_size,
        &app.executable_path,
        MAX_IPA_MAIN_EXECUTABLE_BYTES,
        &mut temporary,
    )?;
    ensure_inventory_unchanged(&metadata_inventory, &copied.inventory)?;

    let macho = parse_macho(&mut temporary).map_err(|source| IpaMainExecutableError::MachO {
        path: app.executable_path.clone(),
        source,
    })?;

    Ok((IpaMainExecutable { app, entry, macho }, copied.inventory))
}

fn validate_main_entry_size(entry: &IpaEntry) -> Result<(), IpaMainExecutableError> {
    if entry.uncompressed_size > MAX_IPA_MAIN_EXECUTABLE_BYTES {
        return Err(IpaMainExecutableError::ExecutableTooLarge {
            path: entry.path.clone(),
            actual: entry.uncompressed_size,
            maximum: MAX_IPA_MAIN_EXECUTABLE_BYTES,
        });
    }
    Ok(())
}

fn ensure_inventory_unchanged(
    expected: &IpaInventory,
    actual: &IpaInventory,
) -> Result<(), IpaMainExecutableError> {
    if expected != actual {
        return Err(IpaMainExecutableError::InventoryChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::ipa::{IpaEntryKind, inspect_ipa};
    use crate::macho::{EncryptionState, MachOContainer, PlaintextStatus};

    const APP_ROOT: &str = "Payload/Demo.app";
    const EXECUTABLE_PATH: &str = "Payload/Demo.app/Demo";

    fn options(method: CompressionMethod) -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o644)
    }

    fn minimal_arm64_macho() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn info_plist() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundleVersion</key><string>42</string>
<key>CFBundleExecutable</key><string>Demo</string>
</dict></plist>"#
    }

    fn make_ipa(executable: &[u8], method: CompressionMethod) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_directory("Payload/", options(CompressionMethod::Stored))
            .expect("add Payload");
        writer
            .add_directory(format!("{APP_ROOT}/"), options(CompressionMethod::Stored))
            .expect("add app root");
        writer
            .start_file(
                format!("{APP_ROOT}/Info.plist"),
                options(CompressionMethod::Stored),
            )
            .expect("start Info.plist");
        writer.write_all(info_plist()).expect("write Info.plist");
        writer
            .start_file(EXECUTABLE_PATH, options(method))
            .expect("start executable");
        writer.write_all(executable).expect("write executable");
        writer.finish().expect("finish IPA").into_inner()
    }

    #[test]
    fn inspects_stored_main_executable_without_modifying_input() {
        let bytes = make_ipa(&minimal_arm64_macho(), CompressionMethod::Stored);
        let original = bytes.clone();
        let report = inspect_ipa_main_executable(Cursor::new(&bytes), bytes.len() as u64)
            .expect("inspect stored main executable");

        assert_eq!(bytes, original);
        assert_eq!(report.app.executable_path, EXECUTABLE_PATH);
        assert_eq!(report.entry.path, EXECUTABLE_PATH);
        assert_eq!(report.macho.container, MachOContainer::Thin);
        assert_eq!(report.macho.slices.len(), 1);
        assert_eq!(
            report.macho.slices[0].encryption_state,
            EncryptionState::NotDeclared
        );
        assert_eq!(
            report.macho.slices[0].plaintext_status,
            PlaintextStatus::NotProven
        );
    }

    #[test]
    fn inspects_deflated_main_executable() {
        let bytes = make_ipa(&minimal_arm64_macho(), CompressionMethod::Deflated);
        let report = inspect_ipa_main_executable(Cursor::new(&bytes), bytes.len() as u64)
            .expect("inspect deflated main executable");

        assert_eq!(report.macho.file_size, 32);
        assert_eq!(report.macho.slices[0].architecture, "arm64");
    }

    #[test]
    fn rejects_non_macho_and_preflight_failures() {
        let non_macho = make_ipa(b"not a Mach-O", CompressionMethod::Stored);
        assert!(matches!(
            inspect_ipa_main_executable(Cursor::new(&non_macho), non_macho.len() as u64),
            Err(IpaMainExecutableError::MachO { .. })
        ));

        let malformed = b"not an IPA";
        assert!(matches!(
            inspect_ipa_main_executable(Cursor::new(malformed), malformed.len() as u64),
            Err(IpaMainExecutableError::AppMetadata(_))
        ));
    }

    #[test]
    fn enforces_main_size_and_complete_inventory_identity() {
        let oversized = IpaEntry {
            path: EXECUTABLE_PATH.to_owned(),
            kind: IpaEntryKind::File,
            executable: true,
            compressed_size: 1,
            uncompressed_size: MAX_IPA_MAIN_EXECUTABLE_BYTES + 1,
            crc32: 0,
        };
        assert!(matches!(
            validate_main_entry_size(&oversized),
            Err(IpaMainExecutableError::ExecutableTooLarge { .. })
        ));

        let bytes = make_ipa(&minimal_arm64_macho(), CompressionMethod::Stored);
        let first = inspect_ipa(Cursor::new(&bytes), bytes.len() as u64).expect("inventory");
        let mut changed = first.clone();
        changed.entries[0].crc32 ^= 1;
        assert!(matches!(
            ensure_inventory_unchanged(&first, &changed),
            Err(IpaMainExecutableError::InventoryChanged)
        ));
    }
}
