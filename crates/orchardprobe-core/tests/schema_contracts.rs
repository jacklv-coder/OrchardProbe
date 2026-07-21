use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::error::ValidationErrorKind;
use orchardprobe_core::{
    BinaryRole, EvidenceLevel, ExportManifest, ManifestCodeCoverage, ManifestCodeRejectionReason,
    ManifestExclusionReason, ManifestPackageState, Outcome, SignatureKind, SignaturePresence,
    SignatureValidation, demo_manifest,
    wire::{
        BundleEntryStreamLimits, BundleEnumerateLimits, CAPABILITY_MESSAGE_TYPE,
        CAPABILITY_SCHEMA_VERSION, Capability, CapabilityReport, CodeRangeStreamLimits,
        DisabledCapabilityReason, ERROR_MESSAGE_TYPE, ERROR_SCHEMA_VERSION, ErrorCategory,
        ErrorCode, ErrorContext, ErrorEnvelope, FramedJsonLimits, KNOWN_CAPABILITY_IDS,
        KNOWN_REASON_CODES, LimitKind, Operation, PROTOCOL_MAJOR_VERSION, ProtocolVersion,
        SessionState, TargetCatalogLimits, WireContract,
    },
};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

const SCHEMA_FILES: [&str; 5] = [
    "fixture-expectation.schema.json",
    "v0/capability-v1.schema.json",
    "v0/error-v1.schema.json",
    "v0/export-manifest-v2.schema.json",
    "v0/export-manifest-v3.schema.json",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureExpectation {
    format_version: u32,
    contract: String,
    contract_schema: String,
    instance: String,
    expected_valid: bool,
    expected_failure: ExpectedFailure,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFailure {
    accepted_keywords: Vec<String>,
    instance_pointer: String,
    reason_code: String,
    reason: String,
}

struct NoDuplicateJson;

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = NoDuplicateJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(NoDuplicateJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::with_capacity(map.size_hint().unwrap_or(0).min(64));
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(NoDuplicateJson)
    }
}

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut strict = serde_json::Deserializer::from_slice(&bytes);
    NoDuplicateJson::deserialize(&mut strict)
        .and_then(|_| strict.end())
        .unwrap_or_else(|error| panic!("parse {} as duplicate-free JSON: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {} as JSON: {error}", path.display()))
}

fn collect_json_files(path: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .map(|entry| entry.expect("directory entry is readable").path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            collect_json_files(&entry, files);
        } else if entry
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(entry);
        }
    }
}

fn serialized_strings<T: Serialize + Copy>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            serde_json::to_value(value)
                .expect("enum serializes")
                .as_str()
                .expect("enum serializes as a string")
                .to_owned()
        })
        .collect()
}

fn schema_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("schema value is an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("schema enum contains strings")
                .to_owned()
        })
        .collect()
}

fn validation_error_matches(
    error: &jsonschema::ValidationError<'_>,
    accepted_keywords: &[String],
    expected_pointer: &str,
) -> bool {
    let path = error.instance_path().as_str();
    let pointer_matches = expected_pointer.is_empty()
        || path == expected_pointer
        || path
            .strip_prefix(expected_pointer)
            .is_some_and(|suffix| suffix.starts_with('/'));
    if pointer_matches
        && accepted_keywords
            .iter()
            .any(|accepted| accepted == error.kind().keyword())
    {
        return true;
    }

    let nested = match error.kind() {
        ValidationErrorKind::AnyOf { context }
        | ValidationErrorKind::OneOfMultipleValid { context }
        | ValidationErrorKind::OneOfNotValid { context } => Some(context),
        _ => None,
    };
    nested.is_some_and(|branches| {
        branches.iter().flatten().any(|nested_error| {
            validation_error_matches(nested_error, accepted_keywords, expected_pointer)
        })
    })
}

#[test]
fn every_checked_in_json_file_parses_and_every_schema_is_meta_valid() {
    let root = schema_root();
    let mut json_files = Vec::new();
    collect_json_files(&root, &mut json_files);
    assert_eq!(json_files.len(), 31, "unexpected schema fixture inventory");
    for path in json_files {
        read_json(&path);
    }

    let mut duplicate = serde_json::Deserializer::from_slice(br#"{"key": 1, "key": 2}"#);
    assert!(NoDuplicateJson::deserialize(&mut duplicate).is_err());

    for relative in SCHEMA_FILES {
        let path = root.join(relative);
        let schema = read_json(&path);
        jsonschema::meta::validate(&schema).unwrap_or_else(|error| {
            panic!("{} is not a valid meta-schema: {error}", path.display())
        });
        jsonschema::draft202012::new(&schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", path.display()));
    }
}

#[test]
fn golden_instances_match_schema_and_rust_wire_types_exactly() {
    let root = schema_root();
    let cases = [
        (
            "v0/capability-v1.schema.json",
            "v0/examples/valid/capability.device-free.json",
        ),
        (
            "v0/error-v1.schema.json",
            "v0/examples/valid/error.incompatible-protocol.json",
        ),
        (
            "v0/export-manifest-v3.schema.json",
            "v0/examples/valid/export-manifest.demolab.json",
        ),
        (
            "v0/export-manifest-v3.schema.json",
            "v0/examples/valid/export-manifest.package-evidence.json",
        ),
    ];

    for (schema_path, instance_path) in cases {
        let schema = read_json(&root.join(schema_path));
        let instance = read_json(&root.join(instance_path));
        let validator = jsonschema::draft202012::new(&schema)
            .unwrap_or_else(|error| panic!("compile {schema_path}: {error}"));
        validator
            .validate(&instance)
            .unwrap_or_else(|error| panic!("{instance_path} failed {schema_path}: {error}"));

        let round_trip = match instance_path {
            "v0/examples/valid/capability.device-free.json" => {
                let report: CapabilityReport = serde_json::from_value(instance.clone())
                    .expect("golden capability report deserializes");
                report
                    .validate()
                    .expect("golden capability report validates");
                serde_json::to_value(report).expect("capability report serializes")
            }
            "v0/examples/valid/error.incompatible-protocol.json" => {
                let envelope: ErrorEnvelope = serde_json::from_value(instance.clone())
                    .expect("golden error envelope deserializes");
                envelope
                    .validate()
                    .expect("golden error envelope validates");
                serde_json::to_value(envelope).expect("error envelope serializes")
            }
            "v0/examples/valid/export-manifest.demolab.json" => {
                let manifest: ExportManifest = serde_json::from_value(instance.clone())
                    .expect("golden export manifest deserializes");
                manifest
                    .validate()
                    .expect("golden export manifest validates");
                assert_eq!(manifest, demo_manifest("0.1.0-alpha.1"));
                serde_json::to_value(manifest).expect("export manifest serializes")
            }
            "v0/examples/valid/export-manifest.package-evidence.json" => {
                let manifest: ExportManifest = serde_json::from_value(instance.clone())
                    .expect("golden package-evidence manifest deserializes");
                manifest
                    .validate()
                    .expect("golden package-evidence manifest validates");
                serde_json::to_value(manifest).expect("package-evidence manifest serializes")
            }
            _ => unreachable!("case list is closed"),
        };
        assert_eq!(
            round_trip, instance,
            "wire value drifted for {instance_path}"
        );
    }
}

#[test]
fn optional_manifest_fields_accept_both_missing_and_explicit_null() {
    let root = schema_root();
    let schema = read_json(&root.join("v0/export-manifest-v3.schema.json"));
    let validator = jsonschema::draft202012::new(&schema).expect("compile manifest schema");
    let mut instance = read_json(&root.join("v0/examples/valid/export-manifest.demolab.json"));

    instance
        .as_object_mut()
        .expect("manifest object")
        .remove("tool_revision");
    let binary = instance["binaries"][0]
        .as_object_mut()
        .expect("binary object");
    for optional in [
        "slice",
        "input_size",
        "output_size",
        "input_sha256",
        "output_sha256",
        "known_plaintext_sha256",
        "notes",
    ] {
        binary.remove(optional);
    }
    instance
        .as_object_mut()
        .expect("manifest object")
        .remove("warnings");

    validator
        .validate(&instance)
        .expect("schema accepts omitted optional fields");
    let manifest: ExportManifest =
        serde_json::from_value(instance).expect("Rust accepts omitted optional fields");
    manifest
        .validate()
        .expect("omitted optional fields preserve semantics");
}

#[test]
fn golden_examples_do_not_add_device_or_secret_channels() {
    let root = schema_root();
    for relative in [
        "v0/examples/valid/capability.device-free.json",
        "v0/examples/valid/error.incompatible-protocol.json",
        "v0/examples/valid/export-manifest.demolab.json",
        "v0/examples/valid/export-manifest.package-evidence.json",
    ] {
        let encoded = fs::read_to_string(root.join(relative)).expect("read golden example");
        let lowercase = encoded.to_ascii_lowercase();
        for forbidden in [
            "udid",
            "ecid",
            "serial_number",
            "pairing_record",
            "credential",
            "session_token",
            "process_id",
            "memory_address",
            "ip_address",
            "shell_output",
            "raw_log",
        ] {
            assert!(
                !lowercase.contains(forbidden),
                "{relative} contains forbidden device/secret channel `{forbidden}`"
            );
        }
    }
}

#[test]
fn every_closed_rust_wire_enum_matches_its_schema_values() {
    let root = schema_root();
    let export = read_json(&root.join("v0/export-manifest-v3.schema.json"));
    let capability = read_json(&root.join("v0/capability-v1.schema.json"));
    let error = read_json(&root.join("v0/error-v1.schema.json"));

    let binary_properties = &export["$defs"]["binary_evidence"]["properties"];
    assert_eq!(
        serialized_strings(&[
            BinaryRole::MainExecutable,
            BinaryRole::Framework,
            BinaryRole::DynamicLibrary,
            BinaryRole::Extension,
            BinaryRole::Other,
        ]),
        schema_strings(&binary_properties["role"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            Outcome::Pass,
            Outcome::Fail,
            Outcome::Inconclusive,
            Outcome::Skipped,
        ]),
        schema_strings(&binary_properties["outcome"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            EvidenceLevel::Metadata,
            EvidenceLevel::Structure,
            EvidenceLevel::RangeHash,
            EvidenceLevel::KnownPlaintext,
        ]),
        schema_strings(&binary_properties["evidence_level"]["enum"])
    );
    let signature = &export["$defs"]["signature"]["properties"];
    assert_eq!(
        serialized_strings(&[
            SignaturePresence::Absent,
            SignaturePresence::Present,
            SignaturePresence::Unknown,
        ]),
        schema_strings(&signature["presence"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            SignatureKind::Cms,
            SignatureKind::AdHoc,
            SignatureKind::Unknown,
            SignatureKind::NotApplicable,
        ]),
        schema_strings(&signature["kind"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            SignatureValidation::Valid,
            SignatureValidation::Invalid,
            SignatureValidation::NotChecked,
            SignatureValidation::NotApplicable,
        ]),
        schema_strings(&signature["validation"]["enum"])
    );
    assert_eq!(
        KNOWN_CAPABILITY_IDS.map(str::to_owned).to_vec(),
        schema_strings(&export["$defs"]["capability_id"]["enum"])
    );
    assert_eq!(
        KNOWN_REASON_CODES.map(str::to_owned).to_vec(),
        schema_strings(&binary_properties["reason_codes"]["items"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[ManifestPackageState::UnsignedAnalysisOnly]),
        vec![
            export["$defs"]["output_package"]["properties"]["state"]["const"]
                .as_str()
                .expect("package state const")
                .to_owned()
        ]
    );
    assert_eq!(
        serialized_strings(&[
            ManifestExclusionReason::MasReceipt,
            ManifestExclusionReason::ScInfo,
        ]),
        schema_strings(&export["$defs"]["excluded_entry"]["properties"]["reason"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[ManifestCodeCoverage::DeclaredStandardBundles]),
        vec![
            export["$defs"]["code_inventory"]["properties"]["coverage"]["const"]
                .as_str()
                .expect("coverage const")
                .to_owned()
        ]
    );
    assert_eq!(
        serialized_strings(&[
            ManifestCodeRejectionReason::EntryTooLarge,
            ManifestCodeRejectionReason::NotMacho,
            ManifestCodeRejectionReason::InvalidMacho,
        ]),
        schema_strings(&export["$defs"]["rejected_code_candidate"]["properties"]["reason"]["enum"])
    );

    assert_eq!(
        serialized_strings(&[
            DisabledCapabilityReason::UnknownOptional,
            DisabledCapabilityReason::PolicyBlocked,
            DisabledCapabilityReason::LimitOutOfBounds,
            DisabledCapabilityReason::VersionUnsupported,
            DisabledCapabilityReason::BackendNotImplemented,
            DisabledCapabilityReason::NotExercised,
        ]),
        schema_strings(&capability["$defs"]["disabled_capability"]["properties"]["reason"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            ErrorCategory::Policy,
            ErrorCategory::Capability,
            ErrorCategory::Transport,
            ErrorCategory::Protocol,
            ErrorCategory::Collection,
            ErrorCategory::Reconstruction,
            ErrorCategory::Verification,
            ErrorCategory::Reporting,
            ErrorCategory::Internal,
        ]),
        schema_strings(&error["properties"]["category"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            Operation::Authorization,
            Operation::Handshake,
            Operation::CapabilityReport,
            Operation::TargetCatalog,
            Operation::TargetSelect,
            Operation::BundleEnumerate,
            Operation::BundleEntryStream,
            Operation::CodeRangeStream,
            Operation::Cancel,
            Operation::Teardown,
            Operation::Reconstruct,
            Operation::ManifestValidate,
            Operation::EvidenceVerify,
            Operation::ReportWrite,
        ]),
        schema_strings(&error["properties"]["operation"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            SessionState::HostLocal,
            SessionState::Negotiating,
            SessionState::TargetSelected,
            SessionState::Collecting,
            SessionState::Reconstructing,
            SessionState::Verifying,
            SessionState::Reporting,
            SessionState::TearingDown,
            SessionState::Closed,
        ]),
        schema_strings(&error["properties"]["state"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            WireContract::Capability,
            WireContract::Error,
            WireContract::ExportManifest,
        ]),
        schema_strings(&error["$defs"]["version_context"]["properties"]["contract"]["enum"])
    );
    assert_eq!(
        serialized_strings(&[
            LimitKind::FrameBytes,
            LimitKind::MessageBytes,
            LimitKind::TargetCount,
            LimitKind::EntryCount,
            LimitKind::RelativePathUtf8Bytes,
            LimitKind::EntryBytes,
            LimitKind::RangeCount,
            LimitKind::RangeBytes,
            LimitKind::TotalBytes,
            LimitKind::DiagnosticContextCount,
        ]),
        schema_strings(&error["$defs"]["limit_context"]["properties"]["limit"]["enum"])
    );

    let schema_codes: Vec<String> = error["allOf"][0]["oneOf"]
        .as_array()
        .expect("category/code branches")
        .iter()
        .flat_map(|branch| {
            let code = &branch["properties"]["code"];
            code.get("enum")
                .map(schema_strings)
                .unwrap_or_else(|| vec![code["const"].as_str().expect("code const").to_owned()])
        })
        .collect();
    assert_eq!(
        serialized_strings(&[
            ErrorCode::AuthorizationRequired,
            ErrorCode::AcknowledgementRequired,
            ErrorCode::TargetNotAllowed,
            ErrorCode::IncompatibleSchemaVersion,
            ErrorCode::IncompatibleProtocolVersion,
            ErrorCode::RequiredCapabilityMissing,
            ErrorCode::TransportUnavailable,
            ErrorCode::TransportInterrupted,
            ErrorCode::MalformedMessage,
            ErrorCode::InvalidState,
            ErrorCode::LimitExceeded,
            ErrorCode::TargetChanged,
            ErrorCode::UnsafeRelativePath,
            ErrorCode::InvalidRange,
            ErrorCode::ResourceChanged,
            ErrorCode::UnsupportedBinary,
            ErrorCode::ReconstructionFailed,
            ErrorCode::InsufficientEvidence,
            ErrorCode::HashMismatch,
            ErrorCode::SignatureStateInconsistent,
            ErrorCode::ManifestInvalid,
            ErrorCode::OutputFailed,
            ErrorCode::InvariantFailed,
        ]),
        schema_codes
    );
}

#[test]
fn every_error_code_category_disposition_and_context_matches_the_schema() {
    let root = schema_root();
    let schema = read_json(&root.join("v0/error-v1.schema.json"));
    let validator = jsonschema::draft202012::new(&schema).expect("compile error schema");
    let codes = [
        ErrorCode::AuthorizationRequired,
        ErrorCode::AcknowledgementRequired,
        ErrorCode::TargetNotAllowed,
        ErrorCode::IncompatibleSchemaVersion,
        ErrorCode::IncompatibleProtocolVersion,
        ErrorCode::RequiredCapabilityMissing,
        ErrorCode::TransportUnavailable,
        ErrorCode::TransportInterrupted,
        ErrorCode::MalformedMessage,
        ErrorCode::InvalidState,
        ErrorCode::LimitExceeded,
        ErrorCode::TargetChanged,
        ErrorCode::UnsafeRelativePath,
        ErrorCode::InvalidRange,
        ErrorCode::ResourceChanged,
        ErrorCode::UnsupportedBinary,
        ErrorCode::ReconstructionFailed,
        ErrorCode::InsufficientEvidence,
        ErrorCode::HashMismatch,
        ErrorCode::SignatureStateInconsistent,
        ErrorCode::ManifestInvalid,
        ErrorCode::OutputFailed,
        ErrorCode::InvariantFailed,
    ];

    for code in codes {
        let context = match code {
            ErrorCode::IncompatibleSchemaVersion => vec![ErrorContext::Version {
                contract: WireContract::Capability,
                received: CAPABILITY_SCHEMA_VERSION + 1,
                supported: vec![CAPABILITY_SCHEMA_VERSION],
            }],
            ErrorCode::IncompatibleProtocolVersion => vec![ErrorContext::ProtocolVersion {
                received_major: PROTOCOL_MAJOR_VERSION + 1,
                received_minor: 0,
                supported_major: PROTOCOL_MAJOR_VERSION,
                minimum_minor: 0,
                maximum_minor: 1,
            }],
            ErrorCode::RequiredCapabilityMissing => vec![ErrorContext::Capability {
                capability_id: "future.required".to_owned(),
            }],
            ErrorCode::LimitExceeded => vec![ErrorContext::Limit {
                limit: LimitKind::RangeBytes,
                observed: 2,
                allowed: 1,
            }],
            ErrorCode::UnsafeRelativePath => vec![ErrorContext::RelativePath {
                relative_path: "Payload/DemoLab.app/DemoLab".to_owned(),
            }],
            ErrorCode::InvalidRange => vec![ErrorContext::Range {
                relative_path: "Payload/DemoLab.app/DemoLab".to_owned(),
                file_offset: 0,
                requested_size: 1,
            }],
            ErrorCode::InsufficientEvidence
            | ErrorCode::HashMismatch
            | ErrorCode::SignatureStateInconsistent => vec![ErrorContext::Evidence {
                evidence_level: EvidenceLevel::RangeHash,
                outcome: Outcome::Fail,
            }],
            _ => Vec::new(),
        };
        let (terminal, retryable) = code.disposition();
        let envelope = ErrorEnvelope {
            schema_version: ERROR_SCHEMA_VERSION,
            message_type: ERROR_MESSAGE_TYPE.to_owned(),
            category: code.category(),
            code,
            terminal,
            retryable,
            operation: Operation::Teardown,
            state: SessionState::TearingDown,
            context,
        };
        envelope
            .validate()
            .unwrap_or_else(|error| panic!("Rust rejected {code:?}: {error}"));
        let value = serde_json::to_value(envelope).expect("error serializes");
        validator
            .validate(&value)
            .unwrap_or_else(|error| panic!("schema rejected {code:?}: {error}"));
    }
}

#[test]
fn every_enabled_capability_shape_matches_schema_and_runtime_limits() {
    let root = schema_root();
    let schema = read_json(&root.join("v0/capability-v1.schema.json"));
    let validator = jsonschema::draft202012::new(&schema).expect("compile capability schema");
    let capabilities = vec![
        Capability::FramedJson {
            revision: 1,
            limits: FramedJsonLimits {
                max_frame_bytes: 1_024,
            },
        },
        Capability::TargetCatalog {
            revision: 1,
            limits: TargetCatalogLimits { max_targets: 1 },
        },
        Capability::BundleEnumerate {
            revision: 1,
            limits: BundleEnumerateLimits {
                max_entries: 1,
                max_relative_path_utf8_bytes: 1,
            },
        },
        Capability::BundleEntryStream {
            revision: 1,
            limits: BundleEntryStreamLimits {
                max_entry_bytes: 1_024,
                max_chunk_bytes: 1_024,
            },
        },
        Capability::CodeRangeStream {
            revision: 1,
            limits: CodeRangeStreamLimits {
                max_ranges_per_binary: 1,
                max_total_ranges: 1,
                max_range_bytes: 1_024,
                max_total_bytes: 1_024,
                max_chunk_bytes: 1_024,
            },
        },
        Capability::Cancel { revision: 1 },
    ];

    for capability in capabilities {
        let id = capability.id();
        let report = CapabilityReport {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            message_type: CAPABILITY_MESSAGE_TYPE.to_owned(),
            protocol_version: ProtocolVersion {
                major: PROTOCOL_MAJOR_VERSION,
                minor: 1,
            },
            backend_id: "test_fixture".to_owned(),
            capabilities: vec![capability],
            disabled_capabilities: Vec::new(),
        };
        report
            .validate()
            .unwrap_or_else(|error| panic!("Rust rejected {id}: {error}"));
        let value = serde_json::to_value(report).expect("capability report serializes");
        validator
            .validate(&value)
            .unwrap_or_else(|error| panic!("schema rejected {id}: {error}"));
    }
}

#[test]
fn declared_negative_fixtures_fail_for_the_expected_schema_reason() {
    let root = schema_root();
    let invalid_root = root.join("v0/examples/invalid");
    let expectation_schema = read_json(&root.join("fixture-expectation.schema.json"));
    let expectation_validator = jsonschema::draft202012::new(&expectation_schema)
        .expect("compile fixture expectation schema");

    let mut files = Vec::new();
    collect_json_files(&invalid_root, &mut files);
    let expectation_files: Vec<_> = files
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".invalid.expected.json"))
        })
        .collect();
    assert_eq!(
        expectation_files.len(),
        11,
        "unexpected negative fixture inventory"
    );

    for expectation_path in expectation_files {
        let expectation_value = read_json(&expectation_path);
        expectation_validator
            .validate(&expectation_value)
            .unwrap_or_else(|error| {
                panic!(
                    "{} has invalid expectation metadata: {error}",
                    expectation_path.display()
                )
            });
        let expectation: FixtureExpectation = serde_json::from_value(expectation_value)
            .expect("expectation metadata matches its Rust test type");
        assert_eq!(expectation.format_version, 1);
        assert!(!expectation.expected_valid);
        assert!(!expectation.contract.is_empty());
        assert!(!expectation.expected_failure.reason_code.is_empty());
        assert!(!expectation.expected_failure.reason.trim().is_empty());

        let fixture_dir = expectation_path.parent().expect("fixture has a parent");
        let schema_path = fixture_dir.join(&expectation.contract_schema);
        let instance_path = fixture_dir.join(&expectation.instance);
        assert!(schema_path.starts_with(&root));
        assert!(instance_path.starts_with(&invalid_root));

        let schema = read_json(&schema_path);
        let instance = read_json(&instance_path);
        let validator = jsonschema::draft202012::new(&schema)
            .unwrap_or_else(|error| panic!("compile {}: {error}", schema_path.display()));
        let errors: Vec<_> = validator.iter_errors(&instance).collect();
        assert!(
            !errors.is_empty(),
            "{} unexpectedly passed {}",
            instance_path.display(),
            schema_path.display()
        );

        let expected_pointer = &expectation.expected_failure.instance_pointer;
        let matched = errors.iter().any(|error| {
            validation_error_matches(
                error,
                &expectation.expected_failure.accepted_keywords,
                expected_pointer,
            )
        });
        assert!(
            matched,
            "{} failed, but not for {:?} at {} or below; actual: {}",
            instance_path.display(),
            expectation.expected_failure.accepted_keywords,
            expected_pointer,
            errors
                .iter()
                .map(|error| format!("{}@{}", error.kind().keyword(), error.instance_path()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}
