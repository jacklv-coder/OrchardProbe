//! Shared, device-independent report types for OrchardProbe.
//!
//! This crate intentionally contains no device access or DRM operations. It
//! models auditable evidence and validates the untrusted paths that may appear
//! in an export manifest.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The manifest schema understood by this version of the crate.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

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
    pub display_name: String,
    pub version: String,
}

/// Evidence and outcome for one Mach-O binary in an app bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryEvidence {
    /// A bundle-relative path using `/` separators.
    pub path: String,
    pub architecture: String,
    pub outcome: Outcome,
    pub evidence_level: EvidenceLevel,
    pub input_sha256: Option<String>,
    pub output_sha256: Option<String>,
    /// A first-party expected plaintext hash, when a real oracle exists.
    pub known_plaintext_sha256: Option<String>,
    pub signature: SignatureInfo,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// A versioned, machine-readable account of an export attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub schema_version: u32,
    pub tool_version: String,
    pub target: TargetSummary,
    pub backend: String,
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

    #[error("manifest must contain at least one binary")]
    NoBinaries,

    #[error("binary path `{path}` is not a safe bundle-relative path")]
    UnsafeBinaryPath { path: String },

    #[error("binary path `{path}` appears more than once")]
    DuplicateBinaryPath { path: String },

    #[error("manifest field `{field}` must be a 64-character hexadecimal SHA-256")]
    InvalidSha256 { field: String },

    #[error("signature fields for binary `{path}` are inconsistent")]
    InconsistentSignature { path: String },

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

        require_non_empty("tool_version", &self.tool_version)?;
        require_non_empty("target.bundle_id", &self.target.bundle_id)?;
        require_non_empty("target.display_name", &self.target.display_name)?;
        require_non_empty("target.version", &self.target.version)?;
        require_non_empty("backend", &self.backend)?;

        if self.binaries.is_empty() {
            return Err(ManifestValidationError::NoBinaries);
        }

        let mut paths = HashSet::with_capacity(self.binaries.len());
        for (index, binary) in self.binaries.iter().enumerate() {
            let path_field = format!("binaries[{index}].path");
            require_non_empty(&path_field, &binary.path)?;

            let architecture_field = format!("binaries[{index}].architecture");
            require_non_empty(&architecture_field, &binary.architecture)?;

            if let Some(input_sha256) = &binary.input_sha256 {
                let input_hash_field = format!("binaries[{index}].input_sha256");
                require_sha256(&input_hash_field, input_sha256)?;
            }
            if let Some(output_sha256) = &binary.output_sha256 {
                let output_hash_field = format!("binaries[{index}].output_sha256");
                require_sha256(&output_hash_field, output_sha256)?;
            }
            if let Some(known_plaintext_sha256) = &binary.known_plaintext_sha256 {
                let oracle_hash_field = format!("binaries[{index}].known_plaintext_sha256");
                require_sha256(&oracle_hash_field, known_plaintext_sha256)?;
            }
            for (note_index, note) in binary.notes.iter().enumerate() {
                let note_field = format!("binaries[{index}].notes[{note_index}]");
                require_non_empty(&note_field, note)?;
            }

            if !is_safe_relative_path(&binary.path) {
                return Err(ManifestValidationError::UnsafeBinaryPath {
                    path: binary.path.clone(),
                });
            }

            if !paths.insert(binary.path.as_str()) {
                return Err(ManifestValidationError::DuplicateBinaryPath {
                    path: binary.path.clone(),
                });
            }

            if !signature_is_consistent(&binary.signature) {
                return Err(ManifestValidationError::InconsistentSignature {
                    path: binary.path.clone(),
                });
            }

            validate_evidence(binary)?;
        }

        for (index, warning) in self.warnings.iter().enumerate() {
            let warning_field = format!("warnings[{index}]");
            require_non_empty(&warning_field, warning)?;
        }

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

fn validate_evidence(binary: &BinaryEvidence) -> Result<(), ManifestValidationError> {
    let has_oracle = binary.known_plaintext_sha256.is_some();

    if has_oracle && binary.evidence_level != EvidenceLevel::KnownPlaintext {
        return Err(ManifestValidationError::InconsistentEvidenceLevel {
            path: binary.path.clone(),
        });
    }

    if binary.evidence_level == EvidenceLevel::KnownPlaintext
        && (binary.output_sha256.is_none() || !has_oracle)
    {
        return Err(ManifestValidationError::MissingKnownPlaintextEvidence {
            path: binary.path.clone(),
        });
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

    Ok(())
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

fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || looks_like_windows_drive_path(path)
    {
        return false;
    }

    path.split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
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
        target: TargetSummary {
            bundle_id: "com.example.orchardprobe.demolab".to_owned(),
            display_name: "OrchardProbe DemoLab".to_owned(),
            version: "0.0.0-demo".to_owned(),
        },
        backend: "device_free_demo".to_owned(),
        binaries: vec![BinaryEvidence {
            path: "Payload/DemoLab.app/DemoLab".to_owned(),
            architecture: "arm64".to_owned(),
            outcome: Outcome::Inconclusive,
            evidence_level: EvidenceLevel::Structure,
            input_sha256: None,
            output_sha256: None,
            known_plaintext_sha256: None,
            signature: SignatureInfo {
                presence: SignaturePresence::Absent,
                kind: SignatureKind::NotApplicable,
                validation: SignatureValidation::NotApplicable,
            },
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
        let (evidence_level, known_plaintext_sha256) = if outcome == Outcome::Pass {
            (EvidenceLevel::KnownPlaintext, Some("22".repeat(32)))
        } else {
            (EvidenceLevel::RangeHash, None)
        };

        BinaryEvidence {
            path: path.to_owned(),
            architecture: "arm64".to_owned(),
            outcome,
            evidence_level,
            input_sha256: Some("11".repeat(32)),
            output_sha256: Some("22".repeat(32)),
            known_plaintext_sha256,
            signature: SignatureInfo {
                presence: SignaturePresence::Present,
                kind: SignatureKind::Cms,
                validation: SignatureValidation::NotChecked,
            },
            notes: Vec::new(),
        }
    }

    fn manifest_with(binaries: Vec<BinaryEvidence>) -> ExportManifest {
        ExportManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tool_version: "0.1.0-test".to_owned(),
            target: TargetSummary {
                bundle_id: "com.example.test".to_owned(),
                display_name: "Test App".to_owned(),
                version: "1.0".to_owned(),
            },
            backend: "test_fixture".to_owned(),
            binaries,
            warnings: Vec::new(),
        }
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
    fn rejects_pass_without_matching_known_plaintext() {
        let path = "Payload/Test.app/Test";

        let mut insufficient = binary(path, Outcome::Pass);
        insufficient.evidence_level = EvidenceLevel::Metadata;
        insufficient.known_plaintext_sha256 = None;
        assert_eq!(
            manifest_with(vec![insufficient]).validate(),
            Err(ManifestValidationError::InsufficientEvidenceForPass {
                path: path.to_owned()
            })
        );

        let mut missing = binary(path, Outcome::Pass);
        missing.known_plaintext_sha256 = None;
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
            "Payload/Test.app/Test\0suffix",
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
