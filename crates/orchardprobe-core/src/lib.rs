//! Shared, device-independent parsing and report types for OrchardProbe.
//!
//! This crate intentionally contains no device access or DRM operations. It
//! models auditable evidence and validates the untrusted paths that may appear
//! in an export manifest.

pub mod ipa;
pub mod ipa_app;
pub mod ipa_bundle;
pub mod ipa_catalog;
pub mod ipa_code;
#[cfg(unix)]
pub mod ipa_manifest;
#[cfg(unix)]
pub mod ipa_materialize;
#[cfg(unix)]
pub mod ipa_package;
pub mod macho;
pub mod wire;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The manifest schema understood by this version of the crate.
pub const MANIFEST_SCHEMA_VERSION: u32 = 3;

/// Maximum encoded manifest size accepted by the CLI.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_BINARIES: usize = 256;
const MAX_CAPABILITY_IDS: usize = 16;
const MAX_BINARY_RANGES: usize = 256;
const MAX_TOTAL_RANGES: usize = 8192;
const MAX_RANGE_BYTES: u64 = 268_435_456;
const MAX_PATH_CHARS: usize = 1024;
const MAX_PATH_UTF8_BYTES: usize = 1024;
const MAX_PATH_DEPTH: usize = 32;
const MAX_PATH_COMPONENT_CHARS: usize = 255;
const MAX_PATH_COMPONENT_UTF8_BYTES: usize = 255;
const MAX_REASON_CODES: usize = 16;
const MAX_NOTES: usize = 16;
const MAX_WARNINGS: usize = 32;
const MAX_BINARY_SLICES: usize = 64;
const MAX_TOTAL_BINARY_SLICES: usize = 2_048;
const MAX_PACKAGE_EXCLUSIONS: usize = 512;
const MAX_REJECTED_CODE_CANDIDATES: usize = 256;

/// The schema used by non-manifest JSON command reports.
pub const CLI_OUTPUT_SCHEMA_VERSION: u32 = 1;

/// The outcome of an individual verification step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    Inconclusive,
    Skipped,
}

/// The strongest evidence collected for a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Metadata,
    Structure,
    RangeHash,
    KnownPlaintext,
}

/// The role of a Mach-O binary inside the selected app bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryRole {
    MainExecutable,
    Framework,
    DynamicLibrary,
    Extension,
    Other,
}

/// Whether an embedded code signature was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePresence {
    Absent,
    Present,
    Unknown,
}

/// The type of an embedded code signature, when known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    Cms,
    AdHoc,
    Unknown,
    NotApplicable,
}

/// The independently reported validation state of a code signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureValidation {
    Valid,
    Invalid,
    NotChecked,
    NotApplicable,
}

/// Orthogonal code-signature observations.
///
/// Presence, kind, and validity are deliberately separate: for example, an
/// exported analysis artifact can retain a CMS signature that is no longer
/// valid after its bytes change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureInfo {
    pub presence: SignaturePresence,
    pub kind: SignatureKind,
    pub validation: SignatureValidation,
}

/// Identifying information for the app that was examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSummary {
    pub bundle_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub short_version: Option<String>,
}

/// Whole-archive identity derived from bounded bytes and validated inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveArtifactEvidence {
    pub byte_len: u64,
    pub sha256: String,
    pub app_root: String,
    pub entry_count: u32,
    pub inventory_sha256: String,
}

/// Explicit semantic state of an output package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestPackageState {
    UnsignedAnalysisOnly,
}

/// Closed deterministic archive-normalization policy evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPackagePolicy {
    pub version: u32,
    pub compression: String,
    pub compression_level: i64,
    pub timestamp: String,
    pub directory_mode: u32,
    pub executable_file_mode: u32,
    pub regular_file_mode: u32,
}

/// Closed reason that a source archive path was excluded from packaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestExclusionReason {
    MasReceipt,
    ScInfo,
}

/// One canonical source path deliberately excluded from the output package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestExcludedEntry {
    pub path: String,
    pub reason: ManifestExclusionReason,
}

/// Output archive identity, deterministic policy, state, and exclusions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPackageEvidence {
    pub artifact: ArchiveArtifactEvidence,
    pub state: ManifestPackageState,
    pub policy: ManifestPackagePolicy,
    pub exclusions: Vec<ManifestExcludedEntry>,
}

/// Stable declared-code coverage represented by this manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestCodeCoverage {
    DeclaredStandardBundles,
}

/// Closed reason that a selected code candidate was not accepted as Mach-O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestCodeRejectionReason {
    EntryTooLarge,
    NotMacho,
    InvalidMacho,
}

/// One visible candidate that was not classified as code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRejectedCodeCandidate {
    pub path: String,
    pub role: BinaryRole,
    pub reason: ManifestCodeRejectionReason,
}

/// Scope and visible rejections for the code inventory bound to this manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCodeInventoryEvidence {
    pub coverage: ManifestCodeCoverage,
    pub rejected_candidates: Vec<ManifestRejectedCodeCandidate>,
}

/// Stable identity for one Mach-O slice when that identity was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceIdentity {
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub file_offset: u64,
    pub file_size: u64,
    pub architecture: String,
}

/// Bounded evidence for one helper-approved code range.
///
/// `file_offset` is relative to the containing Mach-O file, never the start of
/// a slice and never a VM address. The sizes record a typed operation over an
/// opaque, session-bound range handle; they are not caller-selected memory
/// coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeEvidence {
    pub file_offset: u64,
    pub requested_size: u64,
    pub accepted_size: u64,
    pub written_size: u64,
    #[serde(default)]
    pub accepted_sha256: Option<String>,
    #[serde(default)]
    pub written_sha256: Option<String>,
}

/// Evidence and outcome for one Mach-O binary in an app bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryEvidence {
    /// A bundle-relative path using `/` separators.
    pub path: String,
    pub role: BinaryRole,
    pub architecture: String,
    #[serde(default)]
    pub slice: Option<SliceIdentity>,
    /// Every structurally parsed slice; never collapsed for universal binaries.
    #[serde(default)]
    pub slices: Vec<SliceIdentity>,
    #[serde(default)]
    pub input_size: Option<u64>,
    #[serde(default)]
    pub output_size: Option<u64>,
    pub outcome: Outcome,
    pub evidence_level: EvidenceLevel,
    #[serde(default)]
    pub input_sha256: Option<String>,
    #[serde(default)]
    pub output_sha256: Option<String>,
    /// A first-party expected plaintext hash, when a real oracle exists.
    #[serde(default)]
    pub known_plaintext_sha256: Option<String>,
    pub known_plaintext_evaluated: bool,
    pub signature: SignatureInfo,
    pub ranges: Vec<RangeEvidence>,
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// A versioned, machine-readable account of an export attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub schema_version: u32,
    pub tool_version: String,
    #[serde(default)]
    pub tool_revision: Option<String>,
    pub target: TargetSummary,
    pub backend: String,
    pub capability_ids: Vec<String>,
    #[serde(default)]
    pub source_artifact: Option<ArchiveArtifactEvidence>,
    #[serde(default)]
    pub output_package: Option<OutputPackageEvidence>,
    #[serde(default)]
    pub code_inventory: Option<ManifestCodeInventoryEvidence>,
    pub binaries: Vec<BinaryEvidence>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// A semantic validation error in an export manifest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestValidationError {
    #[error("unsupported manifest schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, actual: u32 },

    #[error("manifest field `{field}` must not be empty")]
    EmptyField { field: String },

    #[error("manifest field `{field}` exceeds the maximum of {maximum}")]
    FieldTooLong { field: String, maximum: usize },

    #[error("manifest field `{field}` contains unsupported control characters")]
    UnsafeText { field: String },

    #[error("manifest field `{field}` is not a valid bounded identifier")]
    InvalidIdentifier { field: String },

    #[error("manifest collection `{field}` exceeds the maximum of {maximum} items")]
    TooManyItems { field: String, maximum: usize },

    #[error("manifest field `{field}` is outside its permitted interoperable integer range")]
    IntegerOutOfRange { field: String },

    #[error("source, output-package, and code-inventory evidence must appear together")]
    IncompletePackageEvidence,

    #[error("package evidence field `{field}` is inconsistent with its bounded contract")]
    InvalidPackageEvidence { field: String },

    #[error("package evidence path `{path}` is unsafe, duplicated, or out of order")]
    InvalidPackagePath { path: String },

    #[error("device-free package evidence contradicts field `{field}`")]
    InconsistentDeviceFreeEvidence { field: String },

    #[error("manifest must contain at least one binary")]
    NoBinaries,

    #[error("binary path `{path}` is not a safe bundle-relative path")]
    UnsafeBinaryPath { path: String },

    #[error("binary path `{path}` appears more than once")]
    DuplicateBinaryPath { path: String },

    #[error("capability ID `{capability_id}` appears more than once")]
    DuplicateCapabilityId { capability_id: String },

    #[error("reason code `{reason_code}` appears more than once for binary `{path}`")]
    DuplicateReasonCode { path: String, reason_code: String },

    #[error("binary `{path}` must contain at least one stable reason code")]
    NoReasonCodes { path: String },

    #[error("binary `{path}` has reason codes that contradict its evidence or outcome")]
    InconsistentReasonCodes { path: String },

    #[error("manifest field `{field}` must be a 64-character hexadecimal SHA-256")]
    InvalidSha256 { field: String },

    #[error("signature fields for binary `{path}` are inconsistent")]
    InconsistentSignature { path: String },

    #[error("slice architecture for binary `{path}` does not match its architecture field")]
    SliceArchitectureMismatch { path: String },

    #[error("slice identity for binary `{path}` is outside the recorded input size")]
    SliceOutOfBounds { path: String },

    #[error("slice identities for binary `{path}` are duplicated or out of order")]
    InvalidSliceOrder { path: String },

    #[error("binary `{path}` records a hash without its corresponding byte size")]
    MissingSizeForHash { path: String },

    #[error("range {index} for binary `{path}` is invalid: {reason}")]
    InvalidRange {
        path: String,
        index: usize,
        reason: String,
    },

    #[error("range {index} for binary `{path}` overlaps or is out of order")]
    OverlappingRange { path: String, index: usize },

    #[error("binary `{path}` requires complete range-hash evidence")]
    MissingRangeEvidence { path: String },

    #[error("range {index} for binary `{path}` has mismatched accepted and written hashes")]
    RangeHashMismatch { path: String, index: usize },

    #[error("binary `{path}` has an inconsistent known-plaintext evaluation flag")]
    InconsistentKnownPlaintextFlag { path: String },

    #[error("binary `{path}` declares pass without known-plaintext evidence")]
    InsufficientEvidenceForPass { path: String },

    #[error(
        "binary `{path}` declares known-plaintext evidence without both output and oracle hashes"
    )]
    MissingKnownPlaintextEvidence { path: String },

    #[error("binary `{path}` has a known-plaintext oracle at a different evidence level")]
    InconsistentEvidenceLevel { path: String },

    #[error(
        "binary `{path}` declares pass but its output hash does not match the known-plaintext oracle"
    )]
    KnownPlaintextMismatch { path: String },

    #[error("binary `{path}` has an outcome that contradicts its known-plaintext comparison")]
    KnownPlaintextOutcomeMismatch { path: String },
}

impl ExportManifest {
    /// Validate schema compatibility and security-sensitive manifest fields.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestValidationError::UnsupportedSchemaVersion {
                expected: MANIFEST_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }

        require_bounded_text("tool_version", &self.tool_version, 128)?;
        if let Some(tool_revision) = &self.tool_revision {
            if tool_revision.len() != 40
                || !tool_revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ManifestValidationError::InvalidIdentifier {
                    field: "tool_revision".to_owned(),
                });
            }
        }
        require_bounded_text("target.bundle_id", &self.target.bundle_id, 255)?;
        if let Some(display_name) = &self.target.display_name {
            require_bounded_text("target.display_name", display_name, 128)?;
        }
        require_bounded_text("target.version", &self.target.version, 128)?;
        if let Some(short_version) = &self.target.short_version {
            require_bounded_text("target.short_version", short_version, 128)?;
        }
        require_bounded_wire_id("backend", &self.backend, 64)?;

        require_max_items(
            "capability_ids",
            self.capability_ids.len(),
            MAX_CAPABILITY_IDS,
        )?;
        let mut capability_ids = HashSet::with_capacity(self.capability_ids.len());
        for (index, capability_id) in self.capability_ids.iter().enumerate() {
            let field = format!("capability_ids[{index}]");
            if !wire::is_known_capability_id(capability_id) {
                return Err(ManifestValidationError::InvalidIdentifier { field });
            }
            if !capability_ids.insert(capability_id.as_str()) {
                return Err(ManifestValidationError::DuplicateCapabilityId {
                    capability_id: capability_id.clone(),
                });
            }
        }
        validate_package_evidence(self)?;

        if self.binaries.is_empty() {
            return Err(ManifestValidationError::NoBinaries);
        }
        require_max_items("binaries", self.binaries.len(), MAX_BINARIES)?;
        require_max_items("warnings", self.warnings.len(), MAX_WARNINGS)?;

        let mut paths = HashSet::with_capacity(self.binaries.len());
        let mut total_ranges = 0usize;
        let mut total_slices = 0usize;
        for (index, binary) in self.binaries.iter().enumerate() {
            if !is_safe_relative_path(&binary.path) {
                return Err(ManifestValidationError::UnsafeBinaryPath {
                    path: binary.path.clone(),
                });
            }

            let architecture_field = format!("binaries[{index}].architecture");
            require_bounded_identifier(&architecture_field, &binary.architecture, 32)?;

            validate_optional_size(&format!("binaries[{index}].input_size"), binary.input_size)?;
            validate_optional_size(
                &format!("binaries[{index}].output_size"),
                binary.output_size,
            )?;

            if let Some(slice) = &binary.slice {
                require_bounded_identifier(
                    &format!("binaries[{index}].slice.architecture"),
                    &slice.architecture,
                    32,
                )?;
                if slice.architecture != binary.architecture {
                    return Err(ManifestValidationError::SliceArchitectureMismatch {
                        path: binary.path.clone(),
                    });
                }
                let slice_end = slice
                    .file_offset
                    .checked_add(slice.file_size)
                    .filter(|end| *end <= MAX_SAFE_JSON_INTEGER);
                if slice.file_size == 0
                    || slice_end.is_none()
                    || binary
                        .input_size
                        .is_some_and(|input_size| slice_end.is_some_and(|end| end > input_size))
                {
                    return Err(ManifestValidationError::SliceOutOfBounds {
                        path: binary.path.clone(),
                    });
                }
            }
            require_max_items(
                &format!("binaries[{index}].slices"),
                binary.slices.len(),
                MAX_BINARY_SLICES,
            )?;
            total_slices = total_slices
                .checked_add(binary.slices.len())
                .ok_or_else(|| ManifestValidationError::TooManyItems {
                    field: "binaries[].slices".to_owned(),
                    maximum: MAX_TOTAL_BINARY_SLICES,
                })?;
            if total_slices > MAX_TOTAL_BINARY_SLICES {
                return Err(ManifestValidationError::TooManyItems {
                    field: "binaries[].slices".to_owned(),
                    maximum: MAX_TOTAL_BINARY_SLICES,
                });
            }
            validate_slices(binary, index)?;

            if let Some(input_sha256) = &binary.input_sha256 {
                let input_hash_field = format!("binaries[{index}].input_sha256");
                require_sha256(&input_hash_field, input_sha256)?;
                if binary.input_size.is_none_or(|size| size == 0) {
                    return Err(ManifestValidationError::MissingSizeForHash {
                        path: binary.path.clone(),
                    });
                }
            }
            if let Some(output_sha256) = &binary.output_sha256 {
                let output_hash_field = format!("binaries[{index}].output_sha256");
                require_sha256(&output_hash_field, output_sha256)?;
                if binary.output_size.is_none_or(|size| size == 0) {
                    return Err(ManifestValidationError::MissingSizeForHash {
                        path: binary.path.clone(),
                    });
                }
            }
            if let Some(known_plaintext_sha256) = &binary.known_plaintext_sha256 {
                let oracle_hash_field = format!("binaries[{index}].known_plaintext_sha256");
                require_sha256(&oracle_hash_field, known_plaintext_sha256)?;
                if binary.output_size.is_none_or(|size| size == 0) {
                    return Err(ManifestValidationError::MissingSizeForHash {
                        path: binary.path.clone(),
                    });
                }
            }

            require_max_items(
                &format!("binaries[{index}].notes"),
                binary.notes.len(),
                MAX_NOTES,
            )?;
            for (note_index, note) in binary.notes.iter().enumerate() {
                let note_field = format!("binaries[{index}].notes[{note_index}]");
                require_bounded_text(&note_field, note, 256)?;
            }

            if !paths.insert(binary.path.as_str()) {
                return Err(ManifestValidationError::DuplicateBinaryPath {
                    path: binary.path.clone(),
                });
            }

            validate_reason_codes(binary)?;

            require_max_items(
                &format!("binaries[{index}].ranges"),
                binary.ranges.len(),
                MAX_BINARY_RANGES,
            )?;
            total_ranges = total_ranges
                .checked_add(binary.ranges.len())
                .ok_or_else(|| ManifestValidationError::TooManyItems {
                    field: "binaries[].ranges".to_owned(),
                    maximum: MAX_TOTAL_RANGES,
                })?;
            if total_ranges > MAX_TOTAL_RANGES {
                return Err(ManifestValidationError::TooManyItems {
                    field: "binaries[].ranges".to_owned(),
                    maximum: MAX_TOTAL_RANGES,
                });
            }
            validate_ranges(binary)?;

            if !signature_is_consistent(&binary.signature) {
                return Err(ManifestValidationError::InconsistentSignature {
                    path: binary.path.clone(),
                });
            }

            validate_evidence(binary)?;
        }

        for (index, warning) in self.warnings.iter().enumerate() {
            let warning_field = format!("warnings[{index}]");
            require_bounded_text(&warning_field, warning, 512)?;
        }

        validate_device_free_package_manifest(self)?;

        Ok(())
    }

    /// Aggregate outcomes declared by the manifest without evaluating evidence.
    ///
    /// Failure has the highest priority, followed by inconclusive and skipped
    /// results. `Pass` is returned only when at least one binary is present and
    /// every binary passed. An invalid empty manifest is treated as skipped.
    #[must_use]
    pub fn declared_overall_outcome(&self) -> Outcome {
        if self
            .binaries
            .iter()
            .any(|binary| binary.outcome == Outcome::Fail)
        {
            Outcome::Fail
        } else if self
            .binaries
            .iter()
            .any(|binary| binary.outcome == Outcome::Inconclusive)
        {
            Outcome::Inconclusive
        } else if self.binaries.is_empty()
            || self
                .binaries
                .iter()
                .any(|binary| binary.outcome == Outcome::Skipped)
        {
            Outcome::Skipped
        } else {
            Outcome::Pass
        }
    }
}

fn validate_package_evidence(manifest: &ExportManifest) -> Result<(), ManifestValidationError> {
    let evidence_count = usize::from(manifest.source_artifact.is_some())
        + usize::from(manifest.output_package.is_some())
        + usize::from(manifest.code_inventory.is_some());
    if evidence_count != 0 && evidence_count != 3 {
        return Err(ManifestValidationError::IncompletePackageEvidence);
    }
    let (Some(source), Some(package), Some(code)) = (
        &manifest.source_artifact,
        &manifest.output_package,
        &manifest.code_inventory,
    ) else {
        return Ok(());
    };

    validate_archive_artifact("source_artifact", source)?;
    validate_archive_artifact("output_package.artifact", &package.artifact)?;
    if source.app_root != package.artifact.app_root {
        return Err(ManifestValidationError::InvalidPackageEvidence {
            field: "output_package.artifact.app_root".to_owned(),
        });
    }
    let policy = &package.policy;
    if policy.version != 1
        || policy.compression != "deflate"
        || policy.compression_level != 6
        || policy.timestamp != "1980-01-01T00:00:00"
        || policy.directory_mode != 0o755
        || policy.executable_file_mode != 0o755
        || policy.regular_file_mode != 0o644
    {
        return Err(ManifestValidationError::InvalidPackageEvidence {
            field: "output_package.policy".to_owned(),
        });
    }

    require_max_items(
        "output_package.exclusions",
        package.exclusions.len(),
        MAX_PACKAGE_EXCLUSIONS,
    )?;
    let mut previous = None;
    for excluded in &package.exclusions {
        if !is_safe_relative_path(&excluded.path)
            || !excluded.path.starts_with(&format!("{}/", source.app_root))
            || previous.is_some_and(|path: &str| excluded.path.as_str() <= path)
        {
            return Err(ManifestValidationError::InvalidPackagePath {
                path: excluded.path.clone(),
            });
        }
        previous = Some(excluded.path.as_str());
    }

    require_max_items(
        "code_inventory.rejected_candidates",
        code.rejected_candidates.len(),
        MAX_REJECTED_CODE_CANDIDATES,
    )?;
    previous = None;
    for rejected in &code.rejected_candidates {
        if !is_safe_relative_path(&rejected.path)
            || !rejected.path.starts_with(&format!("{}/", source.app_root))
            || previous.is_some_and(|path: &str| rejected.path.as_str() <= path)
            || manifest
                .binaries
                .iter()
                .any(|binary| binary.path == rejected.path)
        {
            return Err(ManifestValidationError::InvalidPackagePath {
                path: rejected.path.clone(),
            });
        }
        previous = Some(rejected.path.as_str());
    }
    Ok(())
}

fn validate_archive_artifact(
    field: &str,
    artifact: &ArchiveArtifactEvidence,
) -> Result<(), ManifestValidationError> {
    if artifact.byte_len == 0
        || artifact.byte_len > ipa::MAX_IPA_ARCHIVE_BYTES
        || artifact.entry_count == 0
        || artifact.entry_count as usize > ipa::MAX_IPA_ENTRIES
        || !is_safe_relative_path(&artifact.app_root)
    {
        return Err(ManifestValidationError::InvalidPackageEvidence {
            field: field.to_owned(),
        });
    }
    require_sha256(&format!("{field}.sha256"), &artifact.sha256)?;
    require_sha256(
        &format!("{field}.inventory_sha256"),
        &artifact.inventory_sha256,
    )?;
    Ok(())
}

fn validate_slices(
    binary: &BinaryEvidence,
    binary_index: usize,
) -> Result<(), ManifestValidationError> {
    let mut previous_end = None;
    for (slice_index, slice) in binary.slices.iter().enumerate() {
        require_bounded_identifier(
            &format!("binaries[{binary_index}].slices[{slice_index}].architecture"),
            &slice.architecture,
            32,
        )?;
        let end = slice
            .file_offset
            .checked_add(slice.file_size)
            .filter(|end| *end <= MAX_SAFE_JSON_INTEGER);
        if slice.file_size == 0
            || end.is_none()
            || binary
                .input_size
                .is_some_and(|input_size| end.is_some_and(|end| end > input_size))
        {
            return Err(ManifestValidationError::SliceOutOfBounds {
                path: binary.path.clone(),
            });
        }
        if previous_end.is_some_and(|previous| slice.file_offset < previous) {
            return Err(ManifestValidationError::InvalidSliceOrder {
                path: binary.path.clone(),
            });
        }
        previous_end = end;
    }
    if binary
        .slice
        .as_ref()
        .is_some_and(|selected| !binary.slices.is_empty() && !binary.slices.contains(selected))
    {
        return Err(ManifestValidationError::InvalidSliceOrder {
            path: binary.path.clone(),
        });
    }
    Ok(())
}

fn validate_device_free_package_manifest(
    manifest: &ExportManifest,
) -> Result<(), ManifestValidationError> {
    if manifest.backend != "device_free_package" {
        return Ok(());
    }
    let (Some(source), Some(package), Some(_)) = (
        &manifest.source_artifact,
        &manifest.output_package,
        &manifest.code_inventory,
    ) else {
        return Err(ManifestValidationError::IncompletePackageEvidence);
    };
    if !manifest.capability_ids.is_empty() {
        return Err(ManifestValidationError::InconsistentDeviceFreeEvidence {
            field: "capability_ids".to_owned(),
        });
    }
    if source.app_root != package.artifact.app_root {
        return Err(ManifestValidationError::InconsistentDeviceFreeEvidence {
            field: "output_package.artifact.app_root".to_owned(),
        });
    }
    for binary in &manifest.binaries {
        let hashes_match = binary
            .input_sha256
            .as_deref()
            .zip(binary.output_sha256.as_deref())
            .is_some_and(|(input, output)| input.eq_ignore_ascii_case(output));
        if binary.outcome != Outcome::Inconclusive
            || binary.evidence_level != EvidenceLevel::Structure
            || binary.input_size.is_none()
            || binary.input_size != binary.output_size
            || !hashes_match
            || binary.known_plaintext_sha256.is_some()
            || binary.known_plaintext_evaluated
            || !binary.ranges.is_empty()
            || binary.slices.is_empty()
            || binary.signature.presence != SignaturePresence::Unknown
            || binary.signature.kind != SignatureKind::Unknown
            || binary.signature.validation != SignatureValidation::NotChecked
            || !binary.path.starts_with(&format!("{}/", source.app_root))
        {
            return Err(ManifestValidationError::InconsistentDeviceFreeEvidence {
                field: format!("binaries[{}]", binary.path),
            });
        }
    }
    Ok(())
}

fn validate_evidence(binary: &BinaryEvidence) -> Result<(), ManifestValidationError> {
    let has_oracle = binary.known_plaintext_sha256.is_some();

    if binary.known_plaintext_evaluated != has_oracle {
        return Err(ManifestValidationError::InconsistentKnownPlaintextFlag {
            path: binary.path.clone(),
        });
    }

    if has_oracle && binary.evidence_level != EvidenceLevel::KnownPlaintext {
        return Err(ManifestValidationError::InconsistentEvidenceLevel {
            path: binary.path.clone(),
        });
    }

    if matches!(
        binary.evidence_level,
        EvidenceLevel::RangeHash | EvidenceLevel::KnownPlaintext
    ) {
        if binary.ranges.is_empty() {
            return Err(ManifestValidationError::MissingRangeEvidence {
                path: binary.path.clone(),
            });
        }

        for (index, range) in binary.ranges.iter().enumerate() {
            let complete = range.requested_size == range.accepted_size
                && range.accepted_size == range.written_size;
            let hashes_match = range
                .accepted_sha256
                .as_deref()
                .zip(range.written_sha256.as_deref())
                .is_some_and(|(accepted, written)| accepted.eq_ignore_ascii_case(written));
            if !complete || !hashes_match {
                return Err(ManifestValidationError::RangeHashMismatch {
                    path: binary.path.clone(),
                    index,
                });
            }
        }
    }

    if binary.evidence_level == EvidenceLevel::KnownPlaintext
        && (binary.output_sha256.is_none() || !has_oracle)
    {
        return Err(ManifestValidationError::MissingKnownPlaintextEvidence {
            path: binary.path.clone(),
        });
    }

    if binary.evidence_level == EvidenceLevel::KnownPlaintext {
        let hashes_match = binary
            .output_sha256
            .as_deref()
            .zip(binary.known_plaintext_sha256.as_deref())
            .is_some_and(|(output, oracle)| output.eq_ignore_ascii_case(oracle));
        let expected_outcome = if hashes_match {
            Outcome::Pass
        } else {
            Outcome::Fail
        };
        if binary.outcome != expected_outcome {
            if binary.outcome == Outcome::Pass {
                return Err(ManifestValidationError::KnownPlaintextMismatch {
                    path: binary.path.clone(),
                });
            }
            return Err(ManifestValidationError::KnownPlaintextOutcomeMismatch {
                path: binary.path.clone(),
            });
        }
    }

    if binary.outcome == Outcome::Pass {
        if binary.evidence_level != EvidenceLevel::KnownPlaintext {
            return Err(ManifestValidationError::InsufficientEvidenceForPass {
                path: binary.path.clone(),
            });
        }

        let output = binary.output_sha256.as_deref().unwrap_or_default();
        let oracle = binary.known_plaintext_sha256.as_deref().unwrap_or_default();
        if !output.eq_ignore_ascii_case(oracle) {
            return Err(ManifestValidationError::KnownPlaintextMismatch {
                path: binary.path.clone(),
            });
        }
    }

    validate_reason_semantics(binary)?;

    Ok(())
}

fn validate_reason_semantics(binary: &BinaryEvidence) -> Result<(), ManifestValidationError> {
    let has = |reason: &str| {
        binary
            .reason_codes
            .iter()
            .any(|candidate| candidate == reason)
    };
    let hashes_match = binary
        .output_sha256
        .as_deref()
        .zip(binary.known_plaintext_sha256.as_deref())
        .is_some_and(|(output, oracle)| output.eq_ignore_ascii_case(oracle));

    let expected_evidence_reason = match binary.evidence_level {
        EvidenceLevel::Metadata => "evidence.metadata_only",
        EvidenceLevel::Structure => "evidence.structure_only",
        EvidenceLevel::RangeHash => "evidence.range_hash_match",
        EvidenceLevel::KnownPlaintext if hashes_match => "evidence.known_plaintext_match",
        EvidenceLevel::KnownPlaintext => "evidence.known_plaintext_mismatch",
    };

    let contradictory_evidence_reason = binary.reason_codes.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "evidence.metadata_only"
                | "evidence.structure_only"
                | "evidence.range_hash_match"
                | "evidence.known_plaintext_match"
                | "evidence.known_plaintext_mismatch"
        ) && reason != expected_evidence_reason
    });
    let oracle_reason_is_consistent = (!has("evidence.oracle_not_evaluated")
        || !binary.known_plaintext_evaluated)
        && (!has("evidence.oracle_missing") || binary.known_plaintext_sha256.is_none());
    let signature_reason_is_consistent = !has("signature.not_checked")
        || binary.signature.validation == SignatureValidation::NotChecked;
    let skipped_reason_is_consistent = !has("binary.skipped") || binary.outcome == Outcome::Skipped;
    let pass_reasons_are_consistent = binary.outcome != Outcome::Pass
        || binary.reason_codes.iter().all(|reason| {
            matches!(
                reason.as_str(),
                "evidence.known_plaintext_match" | "signature.not_checked"
            )
        });
    let failure_has_cause = binary.outcome != Outcome::Fail
        || binary.reason_codes.iter().any(|reason| {
            matches!(
                reason.as_str(),
                "backend.not_implemented"
                    | "binary.unsupported"
                    | "collection.incomplete"
                    | "evidence.known_plaintext_mismatch"
            )
        });

    if !has(expected_evidence_reason)
        || contradictory_evidence_reason
        || !oracle_reason_is_consistent
        || !signature_reason_is_consistent
        || !skipped_reason_is_consistent
        || !pass_reasons_are_consistent
        || !failure_has_cause
        || (binary.outcome == Outcome::Skipped && !has("binary.skipped"))
    {
        return Err(ManifestValidationError::InconsistentReasonCodes {
            path: binary.path.clone(),
        });
    }

    Ok(())
}

fn validate_reason_codes(binary: &BinaryEvidence) -> Result<(), ManifestValidationError> {
    if binary.reason_codes.is_empty() {
        return Err(ManifestValidationError::NoReasonCodes {
            path: binary.path.clone(),
        });
    }
    require_max_items(
        "binary.reason_codes",
        binary.reason_codes.len(),
        MAX_REASON_CODES,
    )?;

    let mut reason_codes = HashSet::with_capacity(binary.reason_codes.len());
    for reason_code in &binary.reason_codes {
        if !wire::is_known_reason_code(reason_code) {
            return Err(ManifestValidationError::InvalidIdentifier {
                field: format!("binaries[{}].reason_codes[]", binary.path),
            });
        }
        if !reason_codes.insert(reason_code.as_str()) {
            return Err(ManifestValidationError::DuplicateReasonCode {
                path: binary.path.clone(),
                reason_code: reason_code.clone(),
            });
        }
    }

    Ok(())
}

fn validate_ranges(binary: &BinaryEvidence) -> Result<(), ManifestValidationError> {
    let mut previous_end = None;

    for (index, range) in binary.ranges.iter().enumerate() {
        let invalid = |reason: &str| ManifestValidationError::InvalidRange {
            path: binary.path.clone(),
            index,
            reason: reason.to_owned(),
        };

        if range.file_offset > MAX_SAFE_JSON_INTEGER
            || range.requested_size == 0
            || range.requested_size > MAX_RANGE_BYTES
            || range.accepted_size > MAX_RANGE_BYTES
            || range.written_size > MAX_RANGE_BYTES
            || range.accepted_size > range.requested_size
            || range.written_size > range.accepted_size
        {
            return Err(invalid(
                "size or offset is outside the bounded relationship",
            ));
        }

        let requested_end = range
            .file_offset
            .checked_add(range.requested_size)
            .filter(|end| *end <= MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| invalid("requested range overflows"))?;
        let written_end = range
            .file_offset
            .checked_add(range.written_size)
            .filter(|end| *end <= MAX_SAFE_JSON_INTEGER)
            .ok_or_else(|| invalid("written range overflows"))?;

        if binary
            .input_size
            .is_some_and(|input_size| requested_end > input_size)
            || binary
                .output_size
                .is_some_and(|output_size| written_end > output_size)
        {
            return Err(invalid("range exceeds the recorded binary size"));
        }

        if let Some(slice) = &binary.slice {
            let slice_end = slice
                .file_offset
                .checked_add(slice.file_size)
                .ok_or_else(|| invalid("slice identity overflows"))?;
            if range.file_offset < slice.file_offset || requested_end > slice_end {
                return Err(invalid("range escapes the recorded slice"));
            }
        } else if !binary.slices.is_empty()
            && !binary.slices.iter().any(|slice| {
                slice
                    .file_offset
                    .checked_add(slice.file_size)
                    .is_some_and(|slice_end| {
                        range.file_offset >= slice.file_offset && requested_end <= slice_end
                    })
            })
        {
            return Err(invalid("range escapes every recorded slice"));
        }

        if previous_end.is_some_and(|end| range.file_offset < end) {
            return Err(ManifestValidationError::OverlappingRange {
                path: binary.path.clone(),
                index,
            });
        }
        previous_end = Some(requested_end);

        validate_range_hash(
            &binary.path,
            index,
            "accepted_sha256",
            range.accepted_size,
            range.accepted_sha256.as_deref(),
        )?;
        validate_range_hash(
            &binary.path,
            index,
            "written_sha256",
            range.written_size,
            range.written_sha256.as_deref(),
        )?;
    }

    Ok(())
}

fn validate_range_hash(
    path: &str,
    index: usize,
    name: &str,
    size: u64,
    hash: Option<&str>,
) -> Result<(), ManifestValidationError> {
    if (size == 0) != hash.is_none() {
        return Err(ManifestValidationError::InvalidRange {
            path: path.to_owned(),
            index,
            reason: format!("{name} presence does not match its byte count"),
        });
    }
    if let Some(hash) = hash {
        require_sha256(&format!("binaries[].ranges[{index}].{name}"), hash)?;
    }
    Ok(())
}

fn validate_optional_size(field: &str, value: Option<u64>) -> Result<(), ManifestValidationError> {
    if value.is_some_and(|size| size == 0 || size > MAX_SAFE_JSON_INTEGER) {
        Err(ManifestValidationError::IntegerOutOfRange {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn require_sha256(field: &str, value: &str) -> Result<(), ManifestValidationError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ManifestValidationError::InvalidSha256 {
            field: field.to_owned(),
        })
    }
}

fn signature_is_consistent(signature: &SignatureInfo) -> bool {
    match signature.presence {
        SignaturePresence::Absent => {
            signature.kind == SignatureKind::NotApplicable
                && signature.validation == SignatureValidation::NotApplicable
        }
        SignaturePresence::Present => {
            signature.kind != SignatureKind::NotApplicable
                && signature.validation != SignatureValidation::NotApplicable
        }
        SignaturePresence::Unknown => {
            signature.kind == SignatureKind::Unknown
                && signature.validation == SignatureValidation::NotChecked
        }
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ManifestValidationError> {
    if value.trim().is_empty() {
        Err(ManifestValidationError::EmptyField {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn require_bounded_text(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ManifestValidationError> {
    require_non_empty(field, value)?;
    if value.chars().count() > maximum {
        return Err(ManifestValidationError::FieldTooLong {
            field: field.to_owned(),
            maximum,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ManifestValidationError::UnsafeText {
            field: field.to_owned(),
        });
    }
    Ok(())
}

fn require_bounded_identifier(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ManifestValidationError> {
    require_bounded_text(field, value, maximum)?;
    let mut characters = value.chars();
    let first_is_valid = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    let remainder_is_valid = characters.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-')
    });
    if first_is_valid && remainder_is_valid {
        Ok(())
    } else {
        Err(ManifestValidationError::InvalidIdentifier {
            field: field.to_owned(),
        })
    }
}

fn require_bounded_wire_id(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), ManifestValidationError> {
    require_bounded_text(field, value, maximum)?;
    let mut bytes = value.bytes();
    let first_is_valid = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let remainder_is_valid = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    });
    if first_is_valid && remainder_is_valid {
        Ok(())
    } else {
        Err(ManifestValidationError::InvalidIdentifier {
            field: field.to_owned(),
        })
    }
}

fn require_max_items(
    field: &str,
    actual: usize,
    maximum: usize,
) -> Result<(), ManifestValidationError> {
    if actual > maximum {
        Err(ManifestValidationError::TooManyItems {
            field: field.to_owned(),
            maximum,
        })
    } else {
        Ok(())
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.chars().count() > MAX_PATH_CHARS
        || path.len() > MAX_PATH_UTF8_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || looks_like_windows_drive_path(path)
    {
        return false;
    }

    let mut depth = 0usize;
    path.split('/').all(|component| {
        depth += 1;
        depth <= MAX_PATH_DEPTH
            && !component.is_empty()
            && component != "."
            && component != ".."
            && component.chars().count() <= MAX_PATH_COMPONENT_CHARS
            && component.len() <= MAX_PATH_COMPONENT_UTF8_BYTES
    })
}

fn looks_like_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Produce a deterministic, device-free demonstration manifest.
///
/// DemoLab does not ship a plaintext oracle yet. The result is therefore
/// explicitly inconclusive and never claims known-plaintext verification.
#[must_use]
pub fn demo_manifest(tool_version: &str) -> ExportManifest {
    ExportManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        tool_version: tool_version.to_owned(),
        tool_revision: None,
        target: TargetSummary {
            bundle_id: "com.example.orchardprobe.demolab".to_owned(),
            display_name: Some("OrchardProbe DemoLab".to_owned()),
            version: "0.0.0-demo".to_owned(),
            short_version: None,
        },
        backend: "device_free_demo".to_owned(),
        capability_ids: Vec::new(),
        source_artifact: None,
        output_package: None,
        code_inventory: None,
        binaries: vec![BinaryEvidence {
            path: "Payload/DemoLab.app/DemoLab".to_owned(),
            role: BinaryRole::MainExecutable,
            architecture: "arm64".to_owned(),
            slice: None,
            slices: Vec::new(),
            input_size: None,
            output_size: None,
            outcome: Outcome::Inconclusive,
            evidence_level: EvidenceLevel::Structure,
            input_sha256: None,
            output_sha256: None,
            known_plaintext_sha256: None,
            known_plaintext_evaluated: false,
            signature: SignatureInfo {
                presence: SignaturePresence::Absent,
                kind: SignatureKind::NotApplicable,
                validation: SignatureValidation::NotApplicable,
            },
            ranges: Vec::new(),
            reason_codes: vec![
                "backend.not_implemented".to_owned(),
                "evidence.structure_only".to_owned(),
                "evidence.oracle_not_evaluated".to_owned(),
            ],
            notes: vec![
                "device-free first-party fixture description only; no plaintext oracle was evaluated"
                    .to_owned(),
            ],
        }],
        warnings: vec![
            "demo evidence is structural and must not be interpreted as verified plaintext".to_owned(),
        ],
    }
}

/// A local capability report used by the pre-alpha `doctor` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub report_type: String,
    pub tool_version: String,
    pub status: String,
    pub host_os: String,
    pub host_arch: String,
    pub device_backend: String,
    pub warnings: Vec<String>,
}

/// Report host facts without probing or accessing an iOS device.
#[must_use]
pub fn local_doctor_report(tool_version: &str) -> DoctorReport {
    DoctorReport {
        schema_version: CLI_OUTPUT_SCHEMA_VERSION,
        report_type: "doctor".to_owned(),
        tool_version: tool_version.to_owned(),
        status: "pre_alpha".to_owned(),
        host_os: std::env::consts::OS.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
        device_backend: "not_implemented".to_owned(),
        warnings: vec![
            "device discovery and export backends are not implemented in this pre-alpha build"
                .to_owned(),
            "this report reflects local host metadata only".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binary(path: &str, outcome: Outcome) -> BinaryEvidence {
        let (evidence_level, known_plaintext_sha256, known_plaintext_evaluated) =
            if outcome == Outcome::Pass {
                (EvidenceLevel::KnownPlaintext, Some("22".repeat(32)), true)
            } else {
                (EvidenceLevel::RangeHash, None, false)
            };
        let mut reason_codes = if outcome == Outcome::Pass {
            vec!["evidence.known_plaintext_match".to_owned()]
        } else {
            vec!["evidence.range_hash_match".to_owned()]
        };
        match outcome {
            Outcome::Fail => reason_codes.push("collection.incomplete".to_owned()),
            Outcome::Inconclusive => {
                reason_codes.push("evidence.oracle_not_evaluated".to_owned());
            }
            Outcome::Skipped => reason_codes.push("binary.skipped".to_owned()),
            Outcome::Pass => {}
        }
        reason_codes.push("signature.not_checked".to_owned());

        BinaryEvidence {
            path: path.to_owned(),
            role: BinaryRole::MainExecutable,
            architecture: "arm64".to_owned(),
            slice: Some(SliceIdentity {
                cpu_type: 0x0100_000c,
                cpu_subtype: 0,
                file_offset: 0,
                file_size: 4096,
                architecture: "arm64".to_owned(),
            }),
            slices: Vec::new(),
            input_size: Some(4096),
            output_size: Some(4096),
            outcome,
            evidence_level,
            input_sha256: Some("11".repeat(32)),
            output_sha256: Some("22".repeat(32)),
            known_plaintext_sha256,
            known_plaintext_evaluated,
            signature: SignatureInfo {
                presence: SignaturePresence::Present,
                kind: SignatureKind::Cms,
                validation: SignatureValidation::NotChecked,
            },
            ranges: vec![RangeEvidence {
                file_offset: 0,
                requested_size: 4096,
                accepted_size: 4096,
                written_size: 4096,
                accepted_sha256: Some("aa".repeat(32)),
                written_sha256: Some("AA".repeat(32)),
            }],
            reason_codes,
            notes: Vec::new(),
        }
    }

    fn manifest_with(binaries: Vec<BinaryEvidence>) -> ExportManifest {
        ExportManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tool_version: "0.1.0-test".to_owned(),
            tool_revision: None,
            target: TargetSummary {
                bundle_id: "com.example.test".to_owned(),
                display_name: Some("Test App".to_owned()),
                version: "1.0".to_owned(),
                short_version: None,
            },
            backend: "test_fixture".to_owned(),
            capability_ids: vec!["binary.code_range_stream".to_owned()],
            source_artifact: None,
            output_package: None,
            code_inventory: None,
            binaries,
            warnings: Vec::new(),
        }
    }

    fn device_free_package_manifest() -> ExportManifest {
        let mut binary = binary("Payload/Test.app/Test", Outcome::Inconclusive);
        binary.evidence_level = EvidenceLevel::Structure;
        binary.output_sha256 = binary.input_sha256.clone();
        binary.known_plaintext_sha256 = None;
        binary.known_plaintext_evaluated = false;
        binary.signature = SignatureInfo {
            presence: SignaturePresence::Unknown,
            kind: SignatureKind::Unknown,
            validation: SignatureValidation::NotChecked,
        };
        binary.ranges.clear();
        binary.slices = vec![binary.slice.clone().expect("fixture slice")];
        binary.reason_codes = vec![
            "backend.not_implemented".to_owned(),
            "evidence.structure_only".to_owned(),
            "evidence.oracle_not_evaluated".to_owned(),
            "signature.not_checked".to_owned(),
        ];
        let artifact = ArchiveArtifactEvidence {
            byte_len: 4096,
            sha256: "11".repeat(32),
            app_root: "Payload/Test.app".to_owned(),
            entry_count: 3,
            inventory_sha256: "22".repeat(32),
        };
        let mut manifest = manifest_with(vec![binary]);
        manifest.backend = "device_free_package".to_owned();
        manifest.capability_ids.clear();
        manifest.source_artifact = Some(artifact.clone());
        manifest.output_package = Some(OutputPackageEvidence {
            artifact: ArchiveArtifactEvidence {
                sha256: "33".repeat(32),
                inventory_sha256: "44".repeat(32),
                ..artifact
            },
            state: ManifestPackageState::UnsignedAnalysisOnly,
            policy: ManifestPackagePolicy {
                version: 1,
                compression: "deflate".to_owned(),
                compression_level: 6,
                timestamp: "1980-01-01T00:00:00".to_owned(),
                directory_mode: 0o755,
                executable_file_mode: 0o755,
                regular_file_mode: 0o644,
            },
            exclusions: vec![ManifestExcludedEntry {
                path: "Payload/Test.app/SC_Info/data.sinf".to_owned(),
                reason: ManifestExclusionReason::ScInfo,
            }],
        });
        manifest.code_inventory = Some(ManifestCodeInventoryEvidence {
            coverage: ManifestCodeCoverage::DeclaredStandardBundles,
            rejected_candidates: vec![ManifestRejectedCodeCandidate {
                path: "Payload/Test.app/Assets/rejected.dylib".to_owned(),
                role: BinaryRole::DynamicLibrary,
                reason: ManifestCodeRejectionReason::NotMacho,
            }],
        });
        manifest
    }

    #[test]
    fn validates_complete_device_free_package_evidence() {
        device_free_package_manifest()
            .validate()
            .expect("device-free package evidence");
    }

    #[test]
    fn rejects_partial_or_inconsistent_device_free_package_evidence() {
        let mut partial = device_free_package_manifest();
        partial.output_package = None;
        assert_eq!(
            partial.validate(),
            Err(ManifestValidationError::IncompletePackageEvidence)
        );

        let mut mismatch = device_free_package_manifest();
        mismatch.binaries[0].output_sha256 = Some("ff".repeat(32));
        assert!(matches!(
            mismatch.validate(),
            Err(ManifestValidationError::InconsistentDeviceFreeEvidence { .. })
        ));

        let mut capability = device_free_package_manifest();
        capability.capability_ids = vec!["binary.code_range_stream".to_owned()];
        assert!(matches!(
            capability.validate(),
            Err(ManifestValidationError::InconsistentDeviceFreeEvidence { .. })
        ));
    }

    #[test]
    fn rejects_unsafe_unsorted_or_conflicting_package_paths() {
        let mut unsafe_path = device_free_package_manifest();
        unsafe_path
            .output_package
            .as_mut()
            .expect("package")
            .exclusions[0]
            .path = "../escape".to_owned();
        assert!(matches!(
            unsafe_path.validate(),
            Err(ManifestValidationError::InvalidPackagePath { .. })
        ));

        let mut conflict = device_free_package_manifest();
        conflict
            .code_inventory
            .as_mut()
            .expect("code inventory")
            .rejected_candidates[0]
            .path = "Payload/Test.app/Test".to_owned();
        assert!(matches!(
            conflict.validate(),
            Err(ManifestValidationError::InvalidPackagePath { .. })
        ));
    }

    #[test]
    fn rejects_overlapping_complete_slice_inventory() {
        let mut manifest = device_free_package_manifest();
        let mut second = manifest.binaries[0].slices[0].clone();
        second.file_offset = 1;
        second.file_size -= 1;
        manifest.binaries[0].slices.push(second);
        assert!(matches!(
            manifest.validate(),
            Err(ManifestValidationError::InvalidSliceOrder { .. })
        ));
    }

    #[test]
    fn bounds_package_exclusions_rejections_and_slice_evidence() {
        let mut exclusions = device_free_package_manifest();
        let template = exclusions
            .output_package
            .as_ref()
            .expect("package")
            .exclusions[0]
            .clone();
        exclusions
            .output_package
            .as_mut()
            .expect("package")
            .exclusions = vec![template; MAX_PACKAGE_EXCLUSIONS + 1];
        assert!(matches!(
            exclusions.validate(),
            Err(ManifestValidationError::TooManyItems { .. })
        ));

        let mut rejections = device_free_package_manifest();
        let template = rejections
            .code_inventory
            .as_ref()
            .expect("code inventory")
            .rejected_candidates[0]
            .clone();
        rejections
            .code_inventory
            .as_mut()
            .expect("code inventory")
            .rejected_candidates = vec![template; MAX_REJECTED_CODE_CANDIDATES + 1];
        assert!(matches!(
            rejections.validate(),
            Err(ManifestValidationError::TooManyItems { .. })
        ));

        let mut slices = device_free_package_manifest();
        let template = slices.binaries[0].slices[0].clone();
        slices.binaries[0].slices = vec![template; MAX_BINARY_SLICES + 1];
        assert!(matches!(
            slices.validate(),
            Err(ManifestValidationError::TooManyItems { .. })
        ));
    }

    #[test]
    fn signature_fields_are_orthogonal_in_json() {
        let signature = SignatureInfo {
            presence: SignaturePresence::Present,
            kind: SignatureKind::AdHoc,
            validation: SignatureValidation::Invalid,
        };

        assert_eq!(
            serde_json::to_value(signature).expect("signature serializes"),
            json!({
                "presence": "present",
                "kind": "ad_hoc",
                "validation": "invalid"
            })
        );

        let not_checked: SignatureInfo = serde_json::from_value(json!({
            "presence": "unknown",
            "kind": "unknown",
            "validation": "not_checked"
        }))
        .expect("orthogonal signature state deserializes");
        assert_eq!(not_checked.validation, SignatureValidation::NotChecked);
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let manifest = manifest_with(vec![binary("Payload/Test.app/Test", Outcome::Pass)]);
        let mut value = serde_json::to_value(&manifest).expect("manifest serializes");
        value
            .as_object_mut()
            .expect("manifest is an object")
            .insert("unexpected".to_owned(), json!(true));

        let error = serde_json::from_value::<ExportManifest>(value)
            .expect_err("unknown fields must be rejected");
        assert!(error.to_string().contains("unknown field `unexpected`"));

        let mut nested = serde_json::to_value(&manifest).expect("manifest serializes");
        nested["binaries"][0]["signature"]["unexpected"] = json!(true);
        let error = serde_json::from_value::<ExportManifest>(nested)
            .expect_err("nested unknown fields must be rejected");
        assert!(error.to_string().contains("unknown field `unexpected`"));
    }

    #[test]
    fn rejects_unsupported_schema_and_empty_required_fields() {
        let mut manifest = manifest_with(vec![binary("Payload/Test.app/Test", Outcome::Pass)]);
        manifest.schema_version += 1;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestValidationError::UnsupportedSchemaVersion { .. })
        ));

        manifest.schema_version = MANIFEST_SCHEMA_VERSION;
        manifest.target.bundle_id = "  ".to_owned();
        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::EmptyField {
                field: "target.bundle_id".to_owned()
            })
        );
    }

    #[test]
    fn rejects_manifest_without_binary_evidence() {
        assert_eq!(
            manifest_with(Vec::new()).validate(),
            Err(ManifestValidationError::NoBinaries)
        );
    }

    #[test]
    fn rejects_invalid_sha256_values() {
        for value in [
            String::new(),
            "abc".to_owned(),
            "z".repeat(64),
            "1".repeat(63),
        ] {
            let mut evidence = binary("Payload/Test.app/Test", Outcome::Pass);
            evidence.output_sha256 = Some(value);

            assert_eq!(
                manifest_with(vec![evidence]).validate(),
                Err(ManifestValidationError::InvalidSha256 {
                    field: "binaries[0].output_sha256".to_owned()
                })
            );
        }
    }

    #[test]
    fn rejects_inconsistent_signature_fields() {
        let mut evidence = binary("Payload/Test.app/Test", Outcome::Pass);
        evidence.signature = SignatureInfo {
            presence: SignaturePresence::Absent,
            kind: SignatureKind::Cms,
            validation: SignatureValidation::Valid,
        };

        assert_eq!(
            manifest_with(vec![evidence]).validate(),
            Err(ManifestValidationError::InconsistentSignature {
                path: "Payload/Test.app/Test".to_owned()
            })
        );
    }

    #[test]
    fn signature_consistency_truth_table_is_closed() {
        let presences = [
            SignaturePresence::Absent,
            SignaturePresence::Present,
            SignaturePresence::Unknown,
        ];
        let kinds = [
            SignatureKind::Cms,
            SignatureKind::AdHoc,
            SignatureKind::Unknown,
            SignatureKind::NotApplicable,
        ];
        let validations = [
            SignatureValidation::Valid,
            SignatureValidation::Invalid,
            SignatureValidation::NotChecked,
            SignatureValidation::NotApplicable,
        ];

        for presence in presences {
            for kind in kinds {
                for validation in validations {
                    let signature = SignatureInfo {
                        presence,
                        kind,
                        validation,
                    };
                    let expected = match presence {
                        SignaturePresence::Absent => {
                            kind == SignatureKind::NotApplicable
                                && validation == SignatureValidation::NotApplicable
                        }
                        SignaturePresence::Present => {
                            kind != SignatureKind::NotApplicable
                                && validation != SignatureValidation::NotApplicable
                        }
                        SignaturePresence::Unknown => {
                            kind == SignatureKind::Unknown
                                && validation == SignatureValidation::NotChecked
                        }
                    };
                    assert_eq!(signature_is_consistent(&signature), expected);
                }
            }
        }
    }

    #[test]
    fn rejects_pass_without_matching_known_plaintext() {
        let path = "Payload/Test.app/Test";

        let mut insufficient = binary(path, Outcome::Pass);
        insufficient.evidence_level = EvidenceLevel::Metadata;
        insufficient.known_plaintext_sha256 = None;
        insufficient.known_plaintext_evaluated = false;
        assert_eq!(
            manifest_with(vec![insufficient]).validate(),
            Err(ManifestValidationError::InsufficientEvidenceForPass {
                path: path.to_owned()
            })
        );

        let mut missing = binary(path, Outcome::Pass);
        missing.known_plaintext_sha256 = None;
        missing.known_plaintext_evaluated = false;
        assert_eq!(
            manifest_with(vec![missing]).validate(),
            Err(ManifestValidationError::MissingKnownPlaintextEvidence {
                path: path.to_owned()
            })
        );

        let mut mismatch = binary(path, Outcome::Pass);
        mismatch.known_plaintext_sha256 = Some("33".repeat(32));
        assert_eq!(
            manifest_with(vec![mismatch]).validate(),
            Err(ManifestValidationError::KnownPlaintextMismatch {
                path: path.to_owned()
            })
        );
    }

    #[test]
    fn accepts_pass_with_a_matching_known_plaintext_oracle() {
        let mut evidence = binary("Payload/Test.app/Test", Outcome::Pass);
        evidence.output_sha256 = Some("ab".repeat(32));
        evidence.known_plaintext_sha256 = Some("AB".repeat(32));

        manifest_with(vec![evidence])
            .validate()
            .expect("case-insensitive hexadecimal hashes should match");
    }

    #[test]
    fn rejects_oracle_at_a_lower_evidence_level() {
        let path = "Payload/Test.app/Test";
        let mut evidence = binary(path, Outcome::Inconclusive);
        evidence.known_plaintext_sha256 = Some("22".repeat(32));
        evidence.known_plaintext_evaluated = true;

        assert_eq!(
            manifest_with(vec![evidence]).validate(),
            Err(ManifestValidationError::InconsistentEvidenceLevel {
                path: path.to_owned()
            })
        );
    }

    #[test]
    fn rejects_malicious_and_ambiguous_paths() {
        for path in [
            "../escape",
            "Payload/../escape",
            "/absolute/path",
            "\\\\server\\share",
            "C:\\absolute\\path",
            "Payload//Test.app/Test",
            "Payload/./Test.app/Test",
            "Payload/Test.app/..",
            "Payload/Test.app/Test/",
            "Payload/Test.app/Test\0suffix",
            "Payload/Test.app/Test\u{0085}suffix",
        ] {
            let manifest = manifest_with(vec![binary(path, Outcome::Pass)]);
            assert!(
                matches!(
                    manifest.validate(),
                    Err(ManifestValidationError::UnsafeBinaryPath { .. })
                ),
                "path should have been rejected: {path:?}"
            );
        }
    }

    #[test]
    fn enforces_relative_path_byte_component_and_depth_limits() {
        let component_at_limit = "a".repeat(MAX_PATH_COMPONENT_UTF8_BYTES);
        manifest_with(vec![binary(
            &format!("Payload/Test.app/{component_at_limit}"),
            Outcome::Pass,
        )])
        .validate()
        .expect("255-byte component is accepted");

        let paths = [
            format!("Payload/Test.app/{}", "a".repeat(256)),
            format!("Payload/Test.app/{}", "é".repeat(128)),
            std::iter::repeat_n("a", MAX_PATH_DEPTH + 1)
                .collect::<Vec<_>>()
                .join("/"),
            std::iter::repeat_n("é".repeat(127), 5)
                .collect::<Vec<_>>()
                .join("/"),
        ];
        for path in paths {
            assert!(matches!(
                manifest_with(vec![binary(&path, Outcome::Pass)]).validate(),
                Err(ManifestValidationError::UnsafeBinaryPath { .. })
            ));
        }
    }

    #[test]
    fn rejects_invalid_range_relationships_hashes_and_order() {
        let path = "Payload/Test.app/Test";

        let mut oversized_accept = binary(path, Outcome::Pass);
        oversized_accept.ranges[0].accepted_size = 4097;
        assert!(matches!(
            manifest_with(vec![oversized_accept]).validate(),
            Err(ManifestValidationError::InvalidRange { .. })
        ));

        let mut missing_hash = binary(path, Outcome::Pass);
        missing_hash.ranges[0].accepted_sha256 = None;
        assert!(matches!(
            manifest_with(vec![missing_hash]).validate(),
            Err(ManifestValidationError::InvalidRange { .. })
        ));

        let mut overlap = binary(path, Outcome::Pass);
        overlap.input_size = Some(8192);
        overlap.output_size = Some(8192);
        overlap.slice.as_mut().unwrap().file_size = 8192;
        overlap.ranges.push(RangeEvidence {
            file_offset: 2048,
            requested_size: 4096,
            accepted_size: 4096,
            written_size: 4096,
            accepted_sha256: Some("bb".repeat(32)),
            written_sha256: Some("BB".repeat(32)),
        });
        assert_eq!(
            manifest_with(vec![overlap]).validate(),
            Err(ManifestValidationError::OverlappingRange {
                path: path.to_owned(),
                index: 1,
            })
        );
    }

    #[test]
    fn rejects_slice_size_capability_and_reason_contradictions() {
        let path = "Payload/Test.app/Test";

        let mut zero_size = binary(path, Outcome::Pass);
        zero_size.input_size = Some(0);
        assert!(matches!(
            manifest_with(vec![zero_size]).validate(),
            Err(ManifestValidationError::IntegerOutOfRange { .. })
        ));

        let mut wrong_slice = binary(path, Outcome::Pass);
        wrong_slice.slice.as_mut().unwrap().architecture = "x86_64".to_owned();
        assert_eq!(
            manifest_with(vec![wrong_slice]).validate(),
            Err(ManifestValidationError::SliceArchitectureMismatch {
                path: path.to_owned(),
            })
        );

        let mut manifest = manifest_with(vec![binary(path, Outcome::Pass)]);
        manifest.capability_ids = vec!["session.cancel".to_owned(), "session.cancel".to_owned()];
        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::DuplicateCapabilityId {
                capability_id: "session.cancel".to_owned(),
            })
        );

        let mut contradictory = binary(path, Outcome::Pass);
        contradictory
            .reason_codes
            .push("backend.not_implemented".to_owned());
        assert_eq!(
            manifest_with(vec![contradictory]).validate(),
            Err(ManifestValidationError::InconsistentReasonCodes {
                path: path.to_owned(),
            })
        );

        let mut unexplained_failure = binary(path, Outcome::Fail);
        unexplained_failure
            .reason_codes
            .retain(|reason| reason != "collection.incomplete");
        assert_eq!(
            manifest_with(vec![unexplained_failure]).validate(),
            Err(ManifestValidationError::InconsistentReasonCodes {
                path: path.to_owned(),
            })
        );
    }

    #[test]
    fn known_plaintext_mismatch_must_be_a_failure() {
        let path = "Payload/Test.app/Test";
        let mut evidence = binary(path, Outcome::Pass);
        evidence.outcome = Outcome::Inconclusive;
        evidence.known_plaintext_sha256 = Some("33".repeat(32));
        evidence.reason_codes = vec![
            "evidence.known_plaintext_mismatch".to_owned(),
            "signature.not_checked".to_owned(),
        ];

        assert_eq!(
            manifest_with(vec![evidence]).validate(),
            Err(ManifestValidationError::KnownPlaintextOutcomeMismatch {
                path: path.to_owned(),
            })
        );

        let mut failed = binary(path, Outcome::Pass);
        failed.outcome = Outcome::Fail;
        failed.known_plaintext_sha256 = Some("33".repeat(32));
        failed.reason_codes = vec![
            "evidence.known_plaintext_mismatch".to_owned(),
            "signature.not_checked".to_owned(),
        ];
        manifest_with(vec![failed])
            .validate()
            .expect("an independently observed mismatch is an explicit failure");
    }

    #[test]
    fn rejects_duplicate_binary_paths() {
        let path = "Payload/Test.app/Test";
        let manifest = manifest_with(vec![
            binary(path, Outcome::Pass),
            binary(path, Outcome::Inconclusive),
        ]);

        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::DuplicateBinaryPath {
                path: path.to_owned()
            })
        );
    }

    #[test]
    fn outcome_priority_is_fail_then_inconclusive_then_skipped() {
        let cases = [
            (vec![Outcome::Pass, Outcome::Pass], Outcome::Pass),
            (vec![Outcome::Pass, Outcome::Skipped], Outcome::Skipped),
            (
                vec![Outcome::Skipped, Outcome::Inconclusive],
                Outcome::Inconclusive,
            ),
            (
                vec![Outcome::Inconclusive, Outcome::Fail, Outcome::Skipped],
                Outcome::Fail,
            ),
        ];

        for (outcomes, expected) in cases {
            let binaries = outcomes
                .into_iter()
                .enumerate()
                .map(|(index, outcome)| binary(&format!("Payload/Test.app/Binary{index}"), outcome))
                .collect();
            assert_eq!(manifest_with(binaries).declared_overall_outcome(), expected);
        }

        assert_eq!(
            manifest_with(Vec::new()).declared_overall_outcome(),
            Outcome::Skipped
        );
    }

    #[test]
    fn demo_manifest_is_deterministic_valid_and_honest() {
        let first = demo_manifest("0.1.0-test");
        let second = demo_manifest("0.1.0-test");

        assert_eq!(first, second);
        assert_eq!(first.target.bundle_id, "com.example.orchardprobe.demolab");
        assert_eq!(first.binaries[0].architecture, "arm64");
        assert_eq!(first.binaries[0].known_plaintext_sha256, None);
        assert_eq!(first.declared_overall_outcome(), Outcome::Inconclusive);
        assert!(
            first
                .binaries
                .iter()
                .all(|binary| binary.outcome == Outcome::Inconclusive)
        );
        assert!(
            first
                .binaries
                .iter()
                .all(|binary| binary.evidence_level != EvidenceLevel::KnownPlaintext)
        );
        first.validate().expect("demo manifest must be valid");
    }

    #[test]
    fn local_doctor_is_explicitly_pre_alpha_and_local_only() {
        let report = local_doctor_report("0.1.0-test");

        assert_eq!(report.status, "pre_alpha");
        assert_eq!(report.schema_version, CLI_OUTPUT_SCHEMA_VERSION);
        assert_eq!(report.report_type, "doctor");
        assert_eq!(report.host_os, std::env::consts::OS);
        assert_eq!(report.host_arch, std::env::consts::ARCH);
        assert_eq!(report.device_backend, "not_implemented");
        assert!(!report.warnings.is_empty());
    }
}
