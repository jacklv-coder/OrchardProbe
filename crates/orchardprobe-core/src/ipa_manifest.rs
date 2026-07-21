//! Device-free binding of source, package, inventory, and per-code evidence.
//!
//! This layer consumes only bounded archive readers and evidence produced by
//! earlier host stages. Equal hashes prove unchanged bytes, not decryption or
//! plaintext. It never accepts a publication path or exposes a private path.

use std::io::{self, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ipa::{
    IpaEntry, IpaEntryKind, IpaEntryReadError, IpaInspectError, IpaInventory,
    MAX_IPA_ENTRY_COPY_BYTES, copy_ipa_entry_bounded, inspect_ipa,
};
use crate::ipa_catalog::{
    IpaCodeCandidateRejectionReason, IpaCodeInventory, IpaCodeInventoryCoverage,
    IpaCodeInventoryError, inspect_ipa_code_inventory,
};
use crate::ipa_materialize::IpaWorktreeExclusionReason;
use crate::ipa_package::{IpaAnalysisArchive, IpaPackageState};
use crate::macho::{MachOParseError, MachOReport, parse_macho};
use crate::{
    ArchiveArtifactEvidence, BinaryEvidence, EvidenceLevel, ExportManifest,
    MANIFEST_SCHEMA_VERSION, MAX_MANIFEST_BYTES, ManifestCodeCoverage,
    ManifestCodeInventoryEvidence, ManifestCodeRejectionReason, ManifestExcludedEntry,
    ManifestExclusionReason, ManifestPackagePolicy, ManifestPackageState,
    ManifestRejectedCodeCandidate, ManifestValidationError, Outcome, OutputPackageEvidence,
    SignatureInfo, SignatureKind, SignaturePresence, SignatureValidation, SliceIdentity,
    TargetSummary,
};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"OrchardProbe\0ipa-inventory\0v1\0";
const DEVICE_FREE_BACKEND: &str = "device_free_package";

/// Failure before a complete bounded package-evidence manifest is returned.
#[derive(Debug, Error)]
pub enum IpaManifestError {
    #[error("source IPA preflight failed while binding manifest evidence: {0}")]
    SourceInspect(#[source] IpaInspectError),

    #[error("output IPA preflight failed while binding manifest evidence: {0}")]
    OutputInspect(#[source] IpaInspectError),

    #[error("source IPA inventory differs from the package source evidence")]
    SourceInventoryChanged,

    #[error("output IPA inventory differs from the package output evidence")]
    OutputInventoryChanged,

    #[error("source code inventory could not be reproduced: {0}")]
    CodeInventoryInspect(#[source] IpaCodeInventoryError),

    #[error("source code inventory differs from the supplied bounded evidence")]
    CodeInventoryChanged,

    #[error("could not {operation} {artifact} archive bytes: {source}")]
    ArchiveIo {
        artifact: &'static str,
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("{artifact} archive ended after {actual} of {expected} bytes")]
    ArchiveShortRead {
        artifact: &'static str,
        expected: u64,
        actual: u64,
    },

    #[error("{artifact} archive produced more than its declared {expected} bytes")]
    ArchiveLongRead {
        artifact: &'static str,
        expected: u64,
    },

    #[error("{artifact} archive bytes changed while manifest evidence was collected")]
    ArchiveHashChanged { artifact: &'static str },

    #[error("could not rewind {artifact} archive after manifest evidence collection: {source}")]
    ArchiveRewind {
        artifact: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("code entry `{path}` differs from the authoritative source inventory")]
    CodeEntryChanged { path: String },

    #[error("code entry `{path}` is missing from the deterministic output inventory")]
    OutputCodeEntryMissing { path: String },

    #[error("bounded source code read failed for `{path}`: {source}")]
    SourceCodeRead {
        path: String,
        #[source]
        source: IpaEntryReadError,
    },

    #[error("bounded output code read failed for `{path}`: {source}")]
    OutputCodeRead {
        path: String,
        #[source]
        source: IpaEntryReadError,
    },

    #[error("archive inventory changed while hashing code entry `{path}`")]
    CodeEntryInventoryChanged { path: String },

    #[error("could not create an anonymous output-code inspection file for `{path}`: {source}")]
    TemporaryCodeFile {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("could not rewind output code entry `{path}` for structural inspection: {source}")]
    TemporaryCodeRewind {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("could not flush output code entry `{path}` before inspection: {source}")]
    TemporaryCodeFlush {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("output code entry `{path}` failed bounded Mach-O inspection: {source}")]
    OutputCodeInspect {
        path: String,
        #[source]
        source: MachOParseError,
    },

    #[error("output code entry `{path}` has different structural Mach-O evidence")]
    OutputCodeStructureChanged { path: String },

    #[error("code entry `{path}` differs between source and deterministic package")]
    CodeHashMismatch { path: String },

    #[error("manifest evidence has {actual} encoded bytes; maximum is {maximum}")]
    ManifestTooLarge { actual: usize, maximum: u64 },

    #[error("generated package-evidence manifest is invalid: {0}")]
    ManifestValidation(#[from] ManifestValidationError),

    #[error("could not encode package-evidence manifest for its size check: {0}")]
    ManifestEncoding(#[source] serde_json::Error),
}

/// Build one validated, deterministic, device-free package-evidence manifest.
///
/// Both readers are rewound to offset zero before every return. The source code
/// inventory is reproduced from the secured source reader; caller-provided
/// hashes, inventories, paths, or semantic outcomes are never accepted.
pub fn build_ipa_package_manifest<R: Read + Seek>(
    source: &mut R,
    source_size: u64,
    code_inventory: &IpaCodeInventory,
    package: &mut IpaAnalysisArchive,
    tool_version: &str,
    tool_revision: Option<&str>,
) -> Result<ExportManifest, IpaManifestError> {
    let result = build_manifest_inner(
        source,
        source_size,
        code_inventory,
        package,
        tool_version,
        tool_revision,
    );
    let source_rewind = source.seek(SeekFrom::Start(0));
    let output_rewind = package.seek(SeekFrom::Start(0));
    if let Err(source) = source_rewind {
        return Err(IpaManifestError::ArchiveRewind {
            artifact: "source",
            source,
        });
    }
    if let Err(source) = output_rewind {
        return Err(IpaManifestError::ArchiveRewind {
            artifact: "output",
            source,
        });
    }
    result
}

fn build_manifest_inner<R: Read + Seek>(
    source: &mut R,
    source_size: u64,
    code_inventory: &IpaCodeInventory,
    package: &mut IpaAnalysisArchive,
    tool_version: &str,
    tool_revision: Option<&str>,
) -> Result<ExportManifest, IpaManifestError> {
    let source_observed =
        inspect_ipa(&mut *source, source_size).map_err(IpaManifestError::SourceInspect)?;
    if &source_observed != package.source_inventory() {
        return Err(IpaManifestError::SourceInventoryChanged);
    }
    let reproduced = inspect_ipa_code_inventory(&mut *source, source_size)
        .map_err(IpaManifestError::CodeInventoryInspect)?;
    if &reproduced != code_inventory {
        return Err(IpaManifestError::CodeInventoryChanged);
    }

    let output_size = package.byte_len();
    let output_observed =
        inspect_ipa(&mut *package, output_size).map_err(IpaManifestError::OutputInspect)?;
    if &output_observed != package.output_inventory() {
        return Err(IpaManifestError::OutputInventoryChanged);
    }

    let source_hash = hash_exact_archive(&mut *source, source_size, "source")?;
    let output_hash = hash_exact_archive(&mut *package, output_size, "output")?;
    let mut binaries = Vec::with_capacity(code_inventory.binaries.len());
    for code in &code_inventory.binaries {
        binaries.push(bind_code_evidence(
            source,
            source_size,
            package,
            output_size,
            &source_observed,
            &output_observed,
            code,
        )?);
    }

    let source_final =
        inspect_ipa(&mut *source, source_size).map_err(IpaManifestError::SourceInspect)?;
    if source_final != source_observed {
        return Err(IpaManifestError::SourceInventoryChanged);
    }
    if hash_exact_archive(&mut *source, source_size, "source")? != source_hash {
        return Err(IpaManifestError::ArchiveHashChanged { artifact: "source" });
    }
    let output_final =
        inspect_ipa(&mut *package, output_size).map_err(IpaManifestError::OutputInspect)?;
    if output_final != output_observed {
        return Err(IpaManifestError::OutputInventoryChanged);
    }
    if hash_exact_archive(&mut *package, output_size, "output")? != output_hash {
        return Err(IpaManifestError::ArchiveHashChanged { artifact: "output" });
    }

    let manifest = ExportManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        tool_version: tool_version.to_owned(),
        tool_revision: tool_revision.map(str::to_owned),
        target: TargetSummary {
            bundle_id: code_inventory.app.bundle_identifier.clone(),
            display_name: None,
            version: code_inventory.app.bundle_version.clone(),
            short_version: code_inventory.app.short_version.clone(),
        },
        backend: DEVICE_FREE_BACKEND.to_owned(),
        capability_ids: Vec::new(),
        source_artifact: Some(archive_evidence(source_size, source_hash, &source_observed)),
        output_package: Some(output_package_evidence(
            package,
            output_hash,
            &output_observed,
        )),
        code_inventory: Some(code_inventory_evidence(code_inventory)),
        binaries,
        warnings: vec![
            "device-free package hashes prove unchanged bytes, not decryption or plaintext"
                .to_owned(),
            "the output is unsigned, analysis-only, and is not claimed to be installable"
                .to_owned(),
        ],
    };
    manifest.validate()?;
    let encoded = serde_json::to_vec(&manifest).map_err(IpaManifestError::ManifestEncoding)?;
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(IpaManifestError::ManifestTooLarge {
            actual: encoded.len(),
            maximum: MAX_MANIFEST_BYTES,
        });
    }
    Ok(manifest)
}

fn bind_code_evidence<R: Read + Seek>(
    source: &mut R,
    source_size: u64,
    package: &mut IpaAnalysisArchive,
    output_size: u64,
    source_inventory: &IpaInventory,
    output_inventory: &IpaInventory,
    code: &crate::ipa_catalog::IpaCodeObject,
) -> Result<BinaryEvidence, IpaManifestError> {
    let source_entry = source_inventory
        .entries
        .iter()
        .find(|entry| entry.path == code.path)
        .filter(|entry| *entry == &code.entry)
        .ok_or_else(|| IpaManifestError::CodeEntryChanged {
            path: code.path.clone(),
        })?;
    let output_entry = find_output_code_entry(output_inventory, &code.path)?;
    if output_entry.uncompressed_size != source_entry.uncompressed_size {
        return Err(IpaManifestError::CodeHashMismatch {
            path: code.path.clone(),
        });
    }

    let mut source_sink = HashSink::default();
    let source_copy = copy_ipa_entry_bounded(
        &mut *source,
        source_size,
        &code.path,
        MAX_IPA_ENTRY_COPY_BYTES,
        &mut source_sink,
    )
    .map_err(|source| IpaManifestError::SourceCodeRead {
        path: code.path.clone(),
        source,
    })?;
    if &source_copy.inventory != source_inventory {
        return Err(IpaManifestError::CodeEntryInventoryChanged {
            path: code.path.clone(),
        });
    }
    let source_sha256 = source_sink.finish();

    let mut temporary =
        tempfile::tempfile().map_err(|source| IpaManifestError::TemporaryCodeFile {
            path: code.path.clone(),
            source,
        })?;
    let output_sha256;
    {
        let mut output_sink = HashingWriter::new(&mut temporary);
        let output_copy = copy_ipa_entry_bounded(
            &mut *package,
            output_size,
            &code.path,
            MAX_IPA_ENTRY_COPY_BYTES,
            &mut output_sink,
        )
        .map_err(|source| IpaManifestError::OutputCodeRead {
            path: code.path.clone(),
            source,
        })?;
        if &output_copy.inventory != output_inventory {
            return Err(IpaManifestError::CodeEntryInventoryChanged {
                path: code.path.clone(),
            });
        }
        output_sink
            .flush()
            .map_err(|source| IpaManifestError::TemporaryCodeFlush {
                path: code.path.clone(),
                source,
            })?;
        output_sha256 = output_sink.finish();
    }
    temporary
        .seek(SeekFrom::Start(0))
        .map_err(|source| IpaManifestError::TemporaryCodeRewind {
            path: code.path.clone(),
            source,
        })?;
    let output_macho =
        parse_macho(&mut temporary).map_err(|source| IpaManifestError::OutputCodeInspect {
            path: code.path.clone(),
            source,
        })?;
    if output_macho != code.macho {
        return Err(IpaManifestError::OutputCodeStructureChanged {
            path: code.path.clone(),
        });
    }
    if source_sha256 != output_sha256 {
        return Err(IpaManifestError::CodeHashMismatch {
            path: code.path.clone(),
        });
    }

    let slices = slice_evidence(&code.macho);
    let (architecture, slice) = if slices.len() == 1 {
        (slices[0].architecture.clone(), Some(slices[0].clone()))
    } else {
        ("universal".to_owned(), None)
    };
    Ok(BinaryEvidence {
        path: code.path.clone(),
        role: code.role,
        architecture,
        slice,
        slices,
        input_size: Some(source_entry.uncompressed_size),
        output_size: Some(output_entry.uncompressed_size),
        outcome: Outcome::Inconclusive,
        evidence_level: EvidenceLevel::Structure,
        input_sha256: Some(source_sha256),
        output_sha256: Some(output_sha256),
        known_plaintext_sha256: None,
        known_plaintext_evaluated: false,
        signature: SignatureInfo {
            presence: SignaturePresence::Unknown,
            kind: SignatureKind::Unknown,
            validation: SignatureValidation::NotChecked,
        },
        ranges: Vec::new(),
        reason_codes: vec![
            "backend.not_implemented".to_owned(),
            "evidence.structure_only".to_owned(),
            "evidence.oracle_not_evaluated".to_owned(),
            "signature.not_checked".to_owned(),
        ],
        notes: Vec::new(),
    })
}

fn find_output_code_entry<'a>(
    output_inventory: &'a IpaInventory,
    path: &str,
) -> Result<&'a IpaEntry, IpaManifestError> {
    output_inventory
        .entries
        .iter()
        .find(|entry| entry.path == path && entry.kind == IpaEntryKind::File)
        .ok_or_else(|| IpaManifestError::OutputCodeEntryMissing {
            path: path.to_owned(),
        })
}

fn archive_evidence(
    byte_len: u64,
    sha256: String,
    inventory: &IpaInventory,
) -> ArchiveArtifactEvidence {
    ArchiveArtifactEvidence {
        byte_len,
        sha256,
        app_root: inventory.app_root.clone(),
        entry_count: inventory.entries.len() as u32,
        inventory_sha256: inventory_digest(inventory),
    }
}

fn output_package_evidence(
    package: &IpaAnalysisArchive,
    sha256: String,
    inventory: &IpaInventory,
) -> OutputPackageEvidence {
    let policy = package.policy();
    OutputPackageEvidence {
        artifact: archive_evidence(package.byte_len(), sha256, inventory),
        state: match package.state() {
            IpaPackageState::UnsignedAnalysisOnly => ManifestPackageState::UnsignedAnalysisOnly,
        },
        policy: ManifestPackagePolicy {
            version: policy.version,
            compression: policy.compression.to_owned(),
            compression_level: policy.compression_level,
            timestamp: policy.timestamp.to_owned(),
            directory_mode: policy.directory_mode,
            executable_file_mode: policy.executable_file_mode,
            regular_file_mode: policy.regular_file_mode,
        },
        exclusions: package
            .excluded_entries()
            .iter()
            .map(|entry| ManifestExcludedEntry {
                path: entry.path.clone(),
                reason: match entry.reason {
                    IpaWorktreeExclusionReason::MasReceipt => ManifestExclusionReason::MasReceipt,
                    IpaWorktreeExclusionReason::ScInfo => ManifestExclusionReason::ScInfo,
                },
            })
            .collect(),
    }
}

fn code_inventory_evidence(inventory: &IpaCodeInventory) -> ManifestCodeInventoryEvidence {
    ManifestCodeInventoryEvidence {
        coverage: match inventory.coverage {
            IpaCodeInventoryCoverage::DeclaredStandardBundles => {
                ManifestCodeCoverage::DeclaredStandardBundles
            }
        },
        rejected_candidates: inventory
            .rejected_candidates
            .iter()
            .map(|entry| ManifestRejectedCodeCandidate {
                path: entry.path.clone(),
                role: entry.role,
                reason: match entry.reason {
                    IpaCodeCandidateRejectionReason::EntryTooLarge => {
                        ManifestCodeRejectionReason::EntryTooLarge
                    }
                    IpaCodeCandidateRejectionReason::NotMacho => {
                        ManifestCodeRejectionReason::NotMacho
                    }
                    IpaCodeCandidateRejectionReason::InvalidMacho => {
                        ManifestCodeRejectionReason::InvalidMacho
                    }
                },
            })
            .collect(),
    }
}

fn slice_evidence(report: &MachOReport) -> Vec<SliceIdentity> {
    report
        .slices
        .iter()
        .map(|slice| SliceIdentity {
            cpu_type: slice.cpu_type,
            cpu_subtype: slice.cpu_subtype,
            file_offset: slice.offset,
            file_size: slice.size,
            architecture: slice.architecture.clone(),
        })
        .collect()
}

fn hash_exact_archive<R: Read + Seek>(
    reader: &mut R,
    expected: u64,
    artifact: &'static str,
) -> Result<String, IpaManifestError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| IpaManifestError::ArchiveIo {
            artifact,
            operation: "seek",
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    let mut actual = 0u64;
    while actual < expected {
        let remaining = expected - actual;
        let capacity = usize::try_from(remaining.min(HASH_BUFFER_BYTES as u64))
            .expect("bounded hash buffer length fits usize");
        let count =
            reader
                .read(&mut buffer[..capacity])
                .map_err(|source| IpaManifestError::ArchiveIo {
                    artifact,
                    operation: "read",
                    source,
                })?;
        if count == 0 {
            return Err(IpaManifestError::ArchiveShortRead {
                artifact,
                expected,
                actual,
            });
        }
        hasher.update(&buffer[..count]);
        actual += count as u64;
    }
    let mut probe = [0u8; 1];
    if reader
        .read(&mut probe)
        .map_err(|source| IpaManifestError::ArchiveIo {
            artifact,
            operation: "read",
            source,
        })?
        != 0
    {
        return Err(IpaManifestError::ArchiveLongRead { artifact, expected });
    }
    Ok(hex_digest(hasher.finalize()))
}

fn inventory_digest(inventory: &IpaInventory) -> String {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_DIGEST_DOMAIN);
    hash_string(&mut hasher, &inventory.app_root);
    hasher.update((inventory.entries.len() as u32).to_be_bytes());
    for entry in &inventory.entries {
        hash_string(&mut hasher, &entry.path);
        hasher.update([match entry.kind {
            IpaEntryKind::File => 1,
            IpaEntryKind::Directory => 2,
        }]);
        hasher.update([u8::from(entry.executable)]);
        hasher.update(entry.compressed_size.to_be_bytes());
        hasher.update(entry.uncompressed_size.to_be_bytes());
        hasher.update(entry.crc32.to_be_bytes());
    }
    hex_digest(hasher.finalize())
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Default)]
struct HashSink {
    hasher: Sha256,
}

impl HashSink {
    fn finish(self) -> String {
        hex_digest(self.hasher.finalize())
    }
}

impl Write for HashSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.hasher.update(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> String {
        hex_digest(self.hasher.finalize())
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(input)?;
        self.hasher.update(&input[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::ipa_catalog::inspect_ipa_code_inventory;
    use crate::ipa_materialize::materialize_ipa_private_worktree;
    use crate::ipa_package::package_ipa_analysis_worktree;

    const APP_ROOT: &str = "Payload/Demo.app";
    const MAIN_PATH: &str = "Payload/Demo.app/Demo";
    const FRAMEWORK_PATH: &str = "Payload/Demo.app/Frameworks/Kit.framework/Kit";

    fn options(method: CompressionMethod, mode: u32) -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(mode)
    }

    fn thin64(cpu_type: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes.extend_from_slice(&cpu_type.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn universal() -> Vec<u8> {
        let arm64 = thin64(0x0100_000c);
        let x86_64 = thin64(0x0100_0007);
        let first_offset = 48u32;
        let second_offset = first_offset + arm64.len() as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        for (cpu, offset, size) in [
            (0x0100_000cu32, first_offset, arm64.len() as u32),
            (0x0100_0007u32, second_offset, x86_64.len() as u32),
        ] {
            bytes.extend_from_slice(&cpu.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes.extend_from_slice(&offset.to_be_bytes());
            bytes.extend_from_slice(&size.to_be_bytes());
            bytes.extend_from_slice(&3u32.to_be_bytes());
        }
        bytes.extend_from_slice(&arm64);
        bytes.extend_from_slice(&x86_64);
        bytes
    }

    fn plist(identifier: &str, executable: &str, short_version: bool) -> Vec<u8> {
        format!(
            "<plist><dict>\
             <key>CFBundleIdentifier</key><string>{identifier}</string>\
             <key>CFBundleVersion</key><string>42</string>\
             {}\
             <key>CFBundleExecutable</key><string>{executable}</string>\
             </dict></plist>",
            if short_version {
                "<key>CFBundleShortVersionString</key><string>1.2.3</string>"
            } else {
                ""
            }
        )
        .into_bytes()
    }

    fn fixture() -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (path, bytes, method, mode) in [
            (
                "Payload/Demo.app/Info.plist",
                plist("com.example.demo", "Demo", true),
                CompressionMethod::Deflated,
                0o644,
            ),
            (
                MAIN_PATH,
                thin64(0x0100_000c),
                CompressionMethod::Stored,
                0o711,
            ),
            (
                "Payload/Demo.app/Frameworks/Kit.framework/Info.plist",
                plist("com.example.demo.kit", "Kit", false),
                CompressionMethod::Deflated,
                0o600,
            ),
            (
                FRAMEWORK_PATH,
                universal(),
                CompressionMethod::Deflated,
                0o755,
            ),
            (
                "Payload/Demo.app/Assets/bad.dylib",
                b"not a Mach-O".to_vec(),
                CompressionMethod::Stored,
                0o644,
            ),
            (
                "Payload/Demo.app/_MASReceipt/receipt",
                b"excluded receipt".to_vec(),
                CompressionMethod::Stored,
                0o600,
            ),
            (
                "Payload/Demo.app/SC_Info/data.sinf",
                b"excluded sc info".to_vec(),
                CompressionMethod::Stored,
                0o600,
            ),
        ] {
            writer
                .start_file(path, options(method, mode))
                .expect("start fixture entry");
            writer.write_all(&bytes).expect("write fixture entry");
        }
        writer.finish().expect("finish fixture").into_inner()
    }

    fn pipeline(source: &[u8]) -> (IpaCodeInventory, IpaAnalysisArchive) {
        let inventory = inspect_ipa_code_inventory(Cursor::new(source), source.len() as u64)
            .expect("code inventory");
        let worktree = materialize_ipa_private_worktree(Cursor::new(source), source.len() as u64)
            .expect("private worktree");
        let package = package_ipa_analysis_worktree(&worktree).expect("analysis package");
        (inventory, package)
    }

    fn direct_sha256(bytes: &[u8]) -> String {
        hex_digest(Sha256::digest(bytes))
    }

    #[test]
    fn binds_deterministic_device_free_package_evidence_without_plaintext_claims() {
        let source = fixture();
        let (first_inventory, mut first_package) = pipeline(&source);
        let (second_inventory, mut second_package) = pipeline(&source);
        let mut first_reader = Cursor::new(&source);
        let mut second_reader = Cursor::new(&source);

        let first = build_ipa_package_manifest(
            &mut first_reader,
            source.len() as u64,
            &first_inventory,
            &mut first_package,
            "0.1.0-test",
            Some("ab0123456789abcdef0123456789abcdef012345"),
        )
        .expect("first manifest");
        let second = build_ipa_package_manifest(
            &mut second_reader,
            source.len() as u64,
            &second_inventory,
            &mut second_package,
            "0.1.0-test",
            Some("ab0123456789abcdef0123456789abcdef012345"),
        )
        .expect("second manifest");

        assert_eq!(
            serde_json::to_vec(&first).expect("serialize first"),
            serde_json::to_vec(&second).expect("serialize second")
        );
        assert_eq!(first_reader.stream_position().expect("source position"), 0);
        assert_eq!(first_package.stream_position().expect("output position"), 0);
        assert_eq!(first.target.display_name, None);
        assert_eq!(first.target.short_version.as_deref(), Some("1.2.3"));
        let source_evidence = first.source_artifact.as_ref().expect("source evidence");
        assert_eq!(source_evidence.sha256, direct_sha256(&source));
        assert_eq!(source_evidence.app_root, APP_ROOT);

        let mut output_bytes = Vec::new();
        first_package
            .read_to_end(&mut output_bytes)
            .expect("read package bytes");
        let package = first.output_package.as_ref().expect("package evidence");
        assert_eq!(package.artifact.sha256, direct_sha256(&output_bytes));
        assert_eq!(package.state, ManifestPackageState::UnsignedAnalysisOnly);
        assert_eq!(package.policy.version, 1);
        assert_eq!(package.exclusions.len(), 2);
        assert_eq!(
            package
                .exclusions
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Payload/Demo.app/SC_Info/data.sinf",
                "Payload/Demo.app/_MASReceipt/receipt"
            ]
        );
        let code = first.code_inventory.as_ref().expect("code evidence");
        assert_eq!(code.coverage, ManifestCodeCoverage::DeclaredStandardBundles);
        assert_eq!(code.rejected_candidates.len(), 1);
        assert_eq!(
            code.rejected_candidates[0].path,
            "Payload/Demo.app/Assets/bad.dylib"
        );
        assert_eq!(
            first
                .binaries
                .iter()
                .map(|binary| binary.path.as_str())
                .collect::<Vec<_>>(),
            vec![MAIN_PATH, FRAMEWORK_PATH]
        );
        assert!(first.binaries.iter().all(|binary| {
            binary.outcome == Outcome::Inconclusive
                && binary.evidence_level == EvidenceLevel::Structure
                && binary.input_sha256 == binary.output_sha256
                && !binary.known_plaintext_evaluated
        }));
        let framework = first
            .binaries
            .iter()
            .find(|binary| binary.path == FRAMEWORK_PATH)
            .expect("framework evidence");
        assert_eq!(framework.architecture, "universal");
        assert_eq!(framework.slices.len(), 2);
        assert!(framework.slice.is_none());
        first.validate().expect("manifest remains valid");
    }

    #[test]
    fn rejects_supplied_code_inventory_drift_and_rewinds_both_readers() {
        let source = fixture();
        let (mut inventory, mut package) = pipeline(&source);
        inventory.rejected_candidates[0].path.push_str(".changed");
        let mut reader = Cursor::new(&source);

        let result = build_ipa_package_manifest(
            &mut reader,
            source.len() as u64,
            &inventory,
            &mut package,
            "0.1.0-test",
            None,
        );

        assert!(matches!(
            result,
            Err(IpaManifestError::CodeInventoryChanged)
        ));
        assert_eq!(reader.stream_position().expect("source rewound"), 0);
        assert_eq!(package.stream_position().expect("output rewound"), 0);
    }

    #[test]
    fn rejects_same_size_changed_package_code_bytes() {
        let source = fixture();
        let inventory = inspect_ipa_code_inventory(Cursor::new(&source), source.len() as u64)
            .expect("code inventory");
        let worktree = materialize_ipa_private_worktree(Cursor::new(&source), source.len() as u64)
            .expect("private worktree");
        let main = worktree.path().join(MAIN_PATH);
        let mut changed = thin64(0x0100_000c);
        changed[24..28].copy_from_slice(&1u32.to_le_bytes());
        std::fs::write(main, changed).expect("change worktree code in place");
        let mut package = package_ipa_analysis_worktree(&worktree).expect("changed package");
        let mut reader = Cursor::new(&source);

        assert!(matches!(
            build_ipa_package_manifest(
                &mut reader,
                source.len() as u64,
                &inventory,
                &mut package,
                "0.1.0-test",
                None,
            ),
            Err(IpaManifestError::CodeHashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_missing_output_code_entry() {
        let source = fixture();
        let (inventory, package) = pipeline(&source);
        let mut output_inventory = package.output_inventory().clone();
        output_inventory
            .entries
            .retain(|entry| entry.path != MAIN_PATH);

        assert!(matches!(
            find_output_code_entry(&output_inventory, &inventory.binaries[0].path),
            Err(IpaManifestError::OutputCodeEntryMissing { .. })
        ));
    }

    #[test]
    fn propagates_source_code_crc_failure_and_rewinds() {
        let source = fixture();
        let (inventory, mut package) = pipeline(&source);
        let needle = thin64(0x0100_000c);
        let offset = source
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("stored root Mach-O bytes");
        let mut corrupted = source.clone();
        corrupted[offset + 24] ^= 1;
        let mut reader = Cursor::new(&corrupted);

        assert!(matches!(
            build_ipa_package_manifest(
                &mut reader,
                corrupted.len() as u64,
                &inventory,
                &mut package,
                "0.1.0-test",
                None,
            ),
            Err(IpaManifestError::CodeInventoryInspect(_))
        ));
        assert_eq!(reader.stream_position().expect("source rewound"), 0);
        assert_eq!(package.stream_position().expect("output rewound"), 0);
    }

    #[test]
    fn exact_archive_hash_rejects_short_and_long_reads() {
        assert!(matches!(
            hash_exact_archive(&mut Cursor::new(b"12"), 3, "fixture"),
            Err(IpaManifestError::ArchiveShortRead { .. })
        ));
        assert!(matches!(
            hash_exact_archive(&mut Cursor::new(b"123"), 2, "fixture"),
            Err(IpaManifestError::ArchiveLongRead { .. })
        ));
    }

    #[test]
    fn inventory_digest_is_deterministic_and_sensitive_to_validated_metadata() {
        let source = fixture();
        let original = inspect_ipa(Cursor::new(&source), source.len() as u64).expect("inventory");
        let mut changed = original.clone();
        changed.entries[0].crc32 ^= 1;
        assert_eq!(inventory_digest(&original), inventory_digest(&original));
        assert_ne!(inventory_digest(&original), inventory_digest(&changed));
    }
}
