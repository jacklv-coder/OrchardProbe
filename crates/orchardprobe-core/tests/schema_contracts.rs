use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::error::ValidationErrorKind;
use orchardprobe_core::{
    BinaryRole, EvidenceLevel, ExportManifest, ManifestCodeCoverage, ManifestCodeRejectionReason,
    ManifestExclusionReason, ManifestPackageState, Outcome, SignatureKind, SignaturePresence,
    SignatureValidation, demo_manifest,
    lab002::{
        artifacts::{self as lab002_artifacts, ClosedArtifact as Lab002ClosedArtifact},
        canonical_json_with_limit,
    },
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
use serde_json::{Value, json};

const SCHEMA_FILES: [&str; 6] = [
    "fixture-expectation.schema.json",
    "lab002/lab-002-artifacts-v1.schema.json",
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

fn assert_lab002_codec<T>(value: &Value)
where
    T: Lab002ClosedArtifact + std::fmt::Debug + PartialEq,
{
    let artifact: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|error| panic!("deserialize {}: {error}", T::SCHEMA));
    artifact
        .validate()
        .unwrap_or_else(|error| panic!("validate {}: {error}", T::SCHEMA));
    assert_eq!(artifact.schema(), T::SCHEMA);
    let canonical = artifact
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode {}: {error}", T::SCHEMA));
    let encoded_value: Value = serde_json::from_slice(&canonical)
        .unwrap_or_else(|error| panic!("parse encoded {}: {error}", T::SCHEMA));
    assert_eq!(
        &encoded_value,
        value,
        "{} Rust/schema field drift",
        T::SCHEMA
    );
    let decoded = T::from_canonical_bytes(&canonical)
        .unwrap_or_else(|error| panic!("decode {}: {error}", T::SCHEMA));
    assert_eq!(decoded, artifact);
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
    assert_eq!(json_files.len(), 32, "unexpected schema fixture inventory");
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
fn lab002_schema_closes_every_artifact_family_and_fixed_order() {
    let schema_path = schema_root().join("lab002/lab-002-artifacts-v1.schema.json");
    let schema = read_json(&schema_path);
    let validator = jsonschema::draft202012::new(&schema)
        .unwrap_or_else(|error| panic!("compile {}: {error}", schema_path.display()));
    let top_level_refs: Vec<_> = schema["oneOf"]
        .as_array()
        .expect("LAB-002 oneOf is an array")
        .iter()
        .map(|branch| branch["$ref"].as_str().expect("branch has one $ref"))
        .collect();
    assert_eq!(
        top_level_refs,
        [
            "#/$defs/authorizedTargetManifest",
            "#/$defs/authorizedUseAcknowledgement",
            "#/$defs/installationEnrollmentCore",
            "#/$defs/collectionChallengeCore",
            "#/$defs/authorizedOperationEnvelope",
            "#/$defs/signedEnrollmentReceipt",
            "#/$defs/deviceSelectionConfirmation",
            "#/$defs/deviceEnrollmentBinding",
            "#/$defs/runCounterState",
            "#/$defs/installationNonceState",
            "#/$defs/labOracle",
            "#/$defs/collectionIntent",
            "#/$defs/signedSessionExport",
            "#/$defs/sessionReport",
            "#/$defs/roleReport",
            "#/$defs/collectionBinding"
        ]
    );
    let digest = |byte: u8| format!("{byte:02x}").repeat(32);
    let signature = |byte: u8| format!("{byte:02x}").repeat(64);
    let environment = json!({
        "hardware_model": "iPhone17,1",
        "ios_product_version": "26.0",
        "ios_build": "23A100"
    });
    let toolchain = json!({
        "xcode_version": "26.1",
        "xcode_build": "17B100",
        "iphoneos_sdk_version": "26.1",
        "iphoneos_sdk_build": "23B100",
        "xcodegen_version": "2.44.1",
        "xcodegen_architecture": "arm64",
        "xcodegen_executable_sha256": digest(0x01),
        "fastlane_version": "2.228.0",
        "gemfile_lock_sha256": digest(0x02)
    });
    let install_acknowledgement = json!({
        "schema": "orchardprobe.lab002.authorized-use-ack.v1",
        "profile": "orchardprobe.demolab.lab002.observation.v1",
        "authorization_policy_version": "orchardprobe.authorized-use.v1",
        "acknowledgement_id": digest(0x03),
        "experiment_id": digest(0x04),
        "operation": "install_and_enroll_exact_build",
        "build_binding_sha256": digest(0x05),
        "authorized_target_manifest_sha256": digest(0x06),
        "technique_profile": "first_party_fixed_range_disk_and_mapped_sha256",
        "run_ordinal": null,
        "data_categories": [
            "authorization_control_metadata",
            "sanitized_device_environment",
            "code_signature_metadata",
            "fixed_range_sha256",
            "closed_outcomes"
        ],
        "retention_profile": "owner_only_lab002_experiment_v1",
        "authorized_actions": [
            "install_exact_build",
            "import_installation_enrollment",
            "confirm_device_enrollment",
            "export_enrollment_receipt"
        ],
        "device_selection_nonce": digest(0x07),
        "expected_environment": environment.clone(),
        "expected_enrollment_binding_sha256": null,
        "acknowledged_at": 1000,
        "not_before": 1000,
        "not_after": 1900,
        "confirmed": true,
        "owns_or_explicitly_authorized_target": true,
        "within_authorized_scope": true,
        "understands_legal_limits": true,
        "will_protect_output_and_not_resign_install_or_redistribute": true
    });
    let mut run_acknowledgement = install_acknowledgement.clone();
    let run_acknowledgement_object = run_acknowledgement
        .as_object_mut()
        .expect("acknowledgement is an object");
    run_acknowledgement_object.insert("operation".into(), json!("collect_fixed_range_run"));
    run_acknowledgement_object.insert("run_ordinal".into(), json!(1));
    run_acknowledgement_object.insert("expected_environment".into(), Value::Null);
    run_acknowledgement_object.insert(
        "expected_enrollment_binding_sha256".into(),
        json!(digest(0x08)),
    );
    run_acknowledgement_object.insert(
        "authorized_actions".into(),
        json!([
            "import_collection_challenge",
            "start_clean_run",
            "observe_main_app",
            "observe_framework",
            "invoke_share_extension",
            "export_session_evidence",
            "confirm_export_received",
            "cleanup_report_subtree"
        ]),
    );

    let oracle_role = |role: &str, path: &str, byte: u8| {
        json!({
            "role": role,
            "fixture_relative_path": path,
            "target_identity_binding_sha256": digest(byte),
            "slices": [{
                "ordinal": 0,
                "cpu_type": 16777228,
                "cpu_subtype": 0,
                "macho_uuid": "00112233445566778899aabbccddeeff",
                "code_signature_sha256": digest(byte.wrapping_add(1)),
                "slice_file_offset": 0,
                "slice_file_size": 4096,
                "archive_cryptid": 0,
                "ipa_cryptid": 0,
                "section_slice_offset": 512,
                "section_file_offset": 512,
                "section_vm_offset": 512,
                "section_length": 256,
                "expected_plaintext_sha256": digest(byte.wrapping_add(2)),
                "ipa_section_sha256": digest(byte.wrapping_add(2))
            }]
        })
    };
    let observed_slice = |byte: u8| {
        json!({
            "ordinal": 0,
            "cpu_type": 16777228,
            "cpu_subtype": 0,
            "macho_uuid": "00112233445566778899aabbccddeeff",
            "slice_file_offset": 0,
            "slice_file_size": 4096,
            "section_slice_offset": 512,
            "section_file_offset": 512,
            "section_vm_offset": 512,
            "segment_name": "__TEXT",
            "section_name": "__oprobe",
            "section_length": 256,
            "encryption_command": "lc_encryption_info_64",
            "cryptoff": 0,
            "cryptsize": 4096,
            "crypt_file_start": 0,
            "crypt_file_end": 4096,
            "cryptid": 1,
            "encryption_covers_section": true,
            "disk_sha256": digest(byte),
            "mapped_sha256": digest(byte.wrapping_add(1))
        })
    };
    let unsigned_receipt = json!({
        "schema": "orchardprobe.lab002.device-enrollment-receipt-core.v1",
        "profile": "orchardprobe.demolab.lab002.observation.v1",
        "authorization_envelope_sha256": digest(0x11),
        "acknowledgement_sha256": digest(0x14),
        "authorization_policy_version": "orchardprobe.authorized-use.v1",
        "enrollment_challenge_response": digest(0x09),
        "experiment_id": digest(0x04),
        "build_binding_sha256": digest(0x05),
        "enrollment_public_key": digest(0x0c),
        "device_installation_binding_sha256": digest(0x0d),
        "environment": environment.clone(),
        "created_at": 1800
    });
    let unsigned_receipt_canonical = String::from_utf8(
        canonical_json_with_limit(&unsigned_receipt, 16 * 1024)
            .expect("unsigned enrollment receipt canonicalizes"),
    )
    .expect("canonical JSON is UTF-8");
    let unsigned_export = json!({
        "schema": "orchardprobe.lab002.session-export-core.v1",
        "profile": "orchardprobe.demolab.lab002.observation.v1",
        "collection_id": digest(0x0b),
        "session_id": digest(0x23),
        "run_ordinal": 1,
        "run_counter": "0000000000000001",
        "challenge_sha256": digest(0x19),
        "build_binding_sha256": digest(0x05),
        "enrollment_public_key": digest(0x0c),
        "device_installation_binding_sha256": digest(0x0d),
        "entries": [
            {"logical_filename": "session.json", "sha256": digest(0x24), "canonical_document": "{}"},
            {"logical_filename": "main-app.json", "sha256": digest(0x25), "canonical_document": "{}"},
            {"logical_filename": "framework.json", "sha256": digest(0x26), "canonical_document": "{}"},
            {"logical_filename": "share-extension.json", "sha256": digest(0x27), "canonical_document": "{}"}
        ]
    });
    let unsigned_export_canonical = String::from_utf8(
        canonical_json_with_limit(&unsigned_export, 512 * 1024)
            .expect("unsigned session export canonicalizes"),
    )
    .expect("canonical JSON is UTF-8");
    let artifacts = vec![
        json!({
            "schema": "orchardprobe.lab002.authorized-targets.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "identity_nonce": digest(0x50),
            "authorization_public_key": digest(0x16),
            "authorization_key_id": digest(0x0e),
            "targets": [
                {
                    "role": "main_app",
                    "bundle_id": "com.orchardprobe.demolab",
                    "code_directory_identifier": "com.orchardprobe.demolab",
                    "code_directory_team_identifier": "36XNX296J9",
                    "application_identifier": {
                        "presence": "present",
                        "value": "36XNX296J9.com.orchardprobe.demolab"
                    },
                    "developer_team_identifier": {
                        "presence": "present",
                        "value": "36XNX296J9"
                    },
                    "application_groups": {
                        "presence": "present",
                        "values": ["group.com.orchardprobe.demolab"]
                    }
                },
                {
                    "role": "framework",
                    "bundle_id": "com.orchardprobe.demolab.framework",
                    "code_directory_identifier": "com.orchardprobe.demolab.framework",
                    "code_directory_team_identifier": "36XNX296J9",
                    "application_identifier": {"presence": "required_absent"},
                    "developer_team_identifier": {"presence": "required_absent"},
                    "application_groups": {"presence": "required_absent"}
                },
                {
                    "role": "share_extension",
                    "bundle_id": "com.orchardprobe.demolab.share",
                    "code_directory_identifier": "com.orchardprobe.demolab.share",
                    "code_directory_team_identifier": "36XNX296J9",
                    "application_identifier": {
                        "presence": "present",
                        "value": "36XNX296J9.com.orchardprobe.demolab.share"
                    },
                    "developer_team_identifier": {
                        "presence": "present",
                        "value": "36XNX296J9"
                    },
                    "application_groups": {
                        "presence": "present",
                        "values": ["group.com.orchardprobe.demolab"]
                    }
                }
            ]
        }),
        install_acknowledgement.clone(),
        run_acknowledgement,
        json!({
            "schema": "orchardprobe.lab002.installation-enrollment-core.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "operation": "install_and_enroll_exact_build",
            "experiment_id": digest(0x04),
            "enrollment_challenge": digest(0x09),
            "build_binding_sha256": digest(0x05),
            "authorized_target_manifest_sha256": digest(0x06),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "device_selection_nonce": digest(0x07),
            "expected_environment": environment.clone(),
            "not_before": 1000,
            "not_after": 1900
        }),
        json!({
            "schema": "orchardprobe.lab002.collection-challenge-core.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "operation": "collect_fixed_range_run",
            "challenge": digest(0x0a),
            "collection_id": digest(0x0b),
            "run_ordinal": 1,
            "expected_run_counter": "0000000000000001",
            "build_binding_sha256": digest(0x05),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "expected_enrollment_binding_sha256": digest(0x08),
            "enrollment_public_key": digest(0x0c),
            "expected_device_installation_binding_sha256": digest(0x0d),
            "not_before": 2000,
            "not_after": 2900
        }),
        json!({
            "schema": "orchardprobe.lab002.authorized-operation-envelope.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "authorization_key_id": digest(0x0e),
            "acknowledgement_canonical": "{}",
            "operation_core_canonical": "{}",
            "signature": signature(0x0f)
        }),
        json!({
            "schema": "orchardprobe.lab002.device-enrollment-receipt.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "unsigned_receipt_canonical": unsigned_receipt_canonical,
            "enrollment_public_key": digest(0x0c),
            "signature": signature(0x10)
        }),
        json!({
            "schema": "orchardprobe.lab002.device-selection-confirmation.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "experiment_id": digest(0x04),
            "authorization_envelope_sha256": digest(0x11),
            "receipt_sha256": digest(0x12),
            "device_selection_fingerprint_sha256": digest(0x13),
            "enrollment_public_key": digest(0x0c),
            "device_installation_binding_sha256": digest(0x0d),
            "confirmed_at": 1800,
            "confirmed": true
        }),
        json!({
            "schema": "orchardprobe.lab002.device-enrollment-binding.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "experiment_id": digest(0x04),
            "installation_acknowledgement_sha256": digest(0x14),
            "authorization_envelope_sha256": digest(0x11),
            "receipt_sha256": digest(0x12),
            "selection_confirmation_sha256": digest(0x15),
            "enrollment_public_key": digest(0x0c),
            "device_installation_binding_sha256": digest(0x0d),
            "environment": environment.clone(),
            "completed_at": 1850
        }),
        json!({
            "schema": "orchardprobe.lab002.oracle.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "source_commit": "11".repeat(20),
            "fixture_source_root": "fixtures/DemoLab",
            "marketing_version": "1.0",
            "build_number": "1",
            "configuration": "Release",
            "observer_revision": "lab002-observer-v1",
            "generator_revision": "22".repeat(20),
            "build_binding_sha256": digest(0x05),
            "authorized_target_manifest_sha256": digest(0x06),
            "authorization_public_key": digest(0x16),
            "authorization_key_id": digest(0x0e),
            "target_identity_set_sha256": digest(0x17),
            "toolchain": toolchain.clone(),
            "ipa_size": 1048576,
            "ipa_sha256": digest(0x18),
            "roles": [
                oracle_role("main_app", "DemoLab.app/DemoLab", 0x20),
                oracle_role(
                    "framework",
                    "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
                    0x30
                ),
                oracle_role(
                    "share_extension",
                    "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
                    0x40
                )
            ]
        }),
        json!({
            "schema": "orchardprobe.lab002.collection-intent.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "challenge_file_sha256": digest(0x19),
            "collection_id": digest(0x0b),
            "run_ordinal": 1,
            "expected_run_counter": "0000000000000001",
            "prior_collection_binding_sha256": null,
            "not_before": 2000,
            "not_after": 2900,
            "source_commit": "11".repeat(20),
            "marketing_version": "1.0",
            "build_number": "1",
            "observer_revision": "lab002-observer-v1",
            "build_binding_sha256": digest(0x05),
            "installation_acknowledgement_sha256": digest(0x14),
            "device_enrollment_binding_sha256": digest(0x08),
            "run_acknowledgement_sha256": digest(0x1a),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "authorization_envelope_signature": signature(0x0f),
            "authorization_envelope_sha256": digest(0x1b),
            "authorized_target_manifest_sha256": digest(0x06),
            "expected_target_identity_set_sha256": digest(0x17),
            "enrollment_public_key": digest(0x0c),
            "expected_device_installation_binding_sha256": digest(0x0d),
            "toolchain": toolchain,
            "preupload_evidence_sha256": digest(0x1c),
            "ipa_sha256": digest(0x18),
            "oracle_sha256": digest(0x1d),
            "expected_inventory_sha256": digest(0x1e)
        }),
        json!({
            "schema": "orchardprobe.lab002.session-export.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "unsigned_export_canonical": unsigned_export_canonical,
            "enrollment_public_key": digest(0x0c),
            "signature": signature(0x1f)
        }),
        json!({
            "schema": "orchardprobe.lab002.run-counter-state.v1",
            "build_binding_sha256": digest(0x05),
            "counter": "0000000000000001"
        }),
        json!({
            "schema": "orchardprobe.lab002.installation-nonce-state.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "build_binding_sha256": digest(0x05),
            "enrollment_public_key": digest(0x0c),
            "installation_nonce": digest(0x51)
        }),
        json!({
            "schema": "orchardprobe.lab002.session-report.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "observer_revision": "lab002-observer-v1",
            "build_binding_sha256": digest(0x05),
            "collection_id": digest(0x0b),
            "run_ordinal": 1,
            "challenge_sha256": digest(0x19),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "acknowledgement_sha256": digest(0x1a),
            "authorization_envelope_sha256": digest(0x1b),
            "authorization_not_after": 2580,
            "device_enrollment_binding_sha256": digest(0x08),
            "enrollment_public_key": digest(0x0c),
            "device_installation_binding_sha256": digest(0x0d),
            "environment": environment.clone(),
            "session_id": digest(0x23),
            "run_counter": "0000000000000001",
            "created_at": 2100,
            "completed_at": 2700,
            "source_commit": "11".repeat(20),
            "marketing_version": "1.0",
            "build_number": "1",
            "state": "complete"
        }),
        json!({
            "schema": "orchardprobe.lab002.role-report.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "collection_id": digest(0x0b),
            "session_id": digest(0x23),
            "run_ordinal": 1,
            "run_counter": "0000000000000001",
            "challenge_sha256": digest(0x19),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "acknowledgement_sha256": digest(0x1a),
            "authorization_envelope_sha256": digest(0x1b),
            "authorization_not_after": 2580,
            "device_enrollment_binding_sha256": digest(0x08),
            "enrollment_public_key": digest(0x0c),
            "device_installation_binding_sha256": digest(0x0d),
            "environment": environment.clone(),
            "source_commit": "11".repeat(20),
            "marketing_version": "1.0",
            "build_number": "1",
            "observer_revision": "lab002-observer-v1",
            "build_binding_sha256": digest(0x05),
            "role": "main_app",
            "fixture_relative_path": "DemoLab.app/DemoLab",
            "target_identity_binding_sha256": digest(0x20),
            "installed_file_size": 4096,
            "container_kind": "thin",
            "active_slice_ordinal": 0,
            "active_cpu_type": 16777228,
            "active_cpu_subtype": 0,
            "active_macho_uuid": "00112233445566778899aabbccddeeff",
            "signature": {
                "presence": "present",
                "kind": "cms",
                "validation": "valid",
                "validator_id": "security-framework",
                "validator_revision": "lab002-observer-v1",
                "superblob_sha256": digest(0x52)
            },
            "phases": [
                {"phase": "disk_inspection", "completed_at": 2200},
                {"phase": "mapped_hash", "completed_at": 2300}
            ],
            "slices": [observed_slice(0x53)],
            "outcome": "pass",
            "reasons": []
        }),
        json!({
            "schema": "orchardprobe.lab002.collection-binding.v1",
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "installation_acknowledgement_sha256": digest(0x14),
            "run_acknowledgement_sha256": digest(0x1a),
            "authorization_policy_version": "orchardprobe.authorized-use.v1",
            "intent_sha256": digest(0x21),
            "device_enrollment_binding_sha256": digest(0x08),
            "authorization_envelope_signature": signature(0x0f),
            "authorization_envelope_sha256": digest(0x1b),
            "challenge_file_sha256": digest(0x19),
            "signed_session_export_sha256": digest(0x22),
            "collection_id": digest(0x0b),
            "run_ordinal": 1,
            "signed_run_counter": "0000000000000001",
            "collected_run_counter": "0000000000000001",
            "session_id": digest(0x23),
            "enrollment_public_key": digest(0x0c),
            "device_installation_binding_sha256": digest(0x0d),
            "environment": environment,
            "session_sha256": digest(0x24),
            "role_file_hashes": {
                "main_app_sha256": digest(0x25),
                "framework_sha256": digest(0x26),
                "share_extension_sha256": digest(0x27)
            },
            "completed_at": 2800
        }),
    ];
    assert_eq!(artifacts.len(), 17);
    for artifact in &artifacts {
        validator.validate(artifact).unwrap_or_else(|error| {
            panic!(
                "{} failed the LAB-002 artifact bundle: {error}",
                artifact["schema"]
            )
        });
        match artifact["schema"].as_str().expect("schema is a string") {
            lab002_artifacts::AuthorizedTargetManifest::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::AuthorizedTargetManifest>(artifact);
            }
            lab002_artifacts::AuthorizationAcknowledgement::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::AuthorizationAcknowledgement>(artifact);
            }
            lab002_artifacts::InstallationEnrollmentCore::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::InstallationEnrollmentCore>(artifact);
            }
            lab002_artifacts::CollectionChallengeCore::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::CollectionChallengeCore>(artifact);
            }
            lab002_artifacts::AuthorizedOperationEnvelope::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::AuthorizedOperationEnvelope>(artifact);
            }
            lab002_artifacts::SignedEnrollmentReceipt::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::SignedEnrollmentReceipt>(artifact);
            }
            lab002_artifacts::DeviceSelectionConfirmation::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::DeviceSelectionConfirmation>(artifact);
            }
            lab002_artifacts::DeviceEnrollmentBinding::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::DeviceEnrollmentBinding>(artifact);
            }
            lab002_artifacts::RunCounterState::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::RunCounterState>(artifact);
            }
            lab002_artifacts::InstallationNonceState::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::InstallationNonceState>(artifact);
            }
            lab002_artifacts::LabOracle::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::LabOracle>(artifact);
            }
            lab002_artifacts::CollectionIntent::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::CollectionIntent>(artifact);
            }
            lab002_artifacts::SignedSessionExport::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::SignedSessionExport>(artifact);
            }
            lab002_artifacts::SessionReport::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::SessionReport>(artifact);
            }
            lab002_artifacts::RoleReport::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::RoleReport>(artifact);
            }
            lab002_artifacts::CollectionBinding::SCHEMA => {
                assert_lab002_codec::<lab002_artifacts::CollectionBinding>(artifact);
            }
            other => panic!("unmatched LAB-002 artifact codec {other}"),
        }
    }

    let artifact_by_schema = |schema_name: &str| {
        artifacts
            .iter()
            .find(|artifact| artifact["schema"] == schema_name)
            .unwrap_or_else(|| panic!("missing test artifact {schema_name}"))
            .clone()
    };

    let mut substituted_challenge =
        artifact_by_schema("orchardprobe.lab002.collection-challenge-core.v1");
    substituted_challenge["expected_run_counter"] = json!("0000000000000002");
    assert!(validator.validate(&substituted_challenge).is_err());

    let mut substituted_intent = artifact_by_schema("orchardprobe.lab002.collection-intent.v1");
    substituted_intent["expected_run_counter"] = json!("0000000000000002");
    assert!(validator.validate(&substituted_intent).is_err());

    for schema_name in [
        "orchardprobe.lab002.session-report.v1",
        "orchardprobe.lab002.role-report.v1",
    ] {
        let mut substituted_report = artifact_by_schema(schema_name);
        substituted_report["run_counter"] = json!("0000000000000002");
        assert!(validator.validate(&substituted_report).is_err());
    }

    for counter_field in ["signed_run_counter", "collected_run_counter"] {
        let mut substituted_binding =
            artifact_by_schema("orchardprobe.lab002.collection-binding.v1");
        substituted_binding[counter_field] = json!("0000000000000002");
        assert!(
            validator.validate(&substituted_binding).is_err(),
            "run-1 binding must reject an independently substituted {counter_field}"
        );
    }

    let mut run_two_challenge =
        artifact_by_schema("orchardprobe.lab002.collection-challenge-core.v1");
    run_two_challenge["run_ordinal"] = json!(2);
    run_two_challenge["expected_run_counter"] = json!("0000000000000002");
    validator
        .validate(&run_two_challenge)
        .expect("run-2 challenge counter branch is valid");
    run_two_challenge["expected_run_counter"] = json!("0000000000000001");
    assert!(validator.validate(&run_two_challenge).is_err());

    let mut run_two_intent = artifact_by_schema("orchardprobe.lab002.collection-intent.v1");
    run_two_intent["run_ordinal"] = json!(2);
    run_two_intent["expected_run_counter"] = json!("0000000000000002");
    run_two_intent["prior_collection_binding_sha256"] = json!(digest(0x55));
    validator
        .validate(&run_two_intent)
        .expect("run-2 intent counter branch is valid");
    run_two_intent["expected_run_counter"] = json!("0000000000000001");
    assert!(validator.validate(&run_two_intent).is_err());

    for schema_name in [
        "orchardprobe.lab002.session-report.v1",
        "orchardprobe.lab002.role-report.v1",
    ] {
        let mut run_two_report = artifact_by_schema(schema_name);
        run_two_report["run_ordinal"] = json!(2);
        run_two_report["run_counter"] = json!("0000000000000002");
        validator
            .validate(&run_two_report)
            .unwrap_or_else(|error| panic!("{schema_name} run-2 branch failed: {error}"));
        run_two_report["run_counter"] = json!("0000000000000001");
        assert!(validator.validate(&run_two_report).is_err());
    }

    let mut run_two_binding = artifact_by_schema("orchardprobe.lab002.collection-binding.v1");
    run_two_binding["run_ordinal"] = json!(2);
    run_two_binding["signed_run_counter"] = json!("0000000000000002");
    run_two_binding["collected_run_counter"] = json!("0000000000000002");
    validator
        .validate(&run_two_binding)
        .expect("run-2 binding counter branch is valid");
    for counter_field in ["signed_run_counter", "collected_run_counter"] {
        let mut substituted_binding = run_two_binding.clone();
        substituted_binding[counter_field] = json!("0000000000000001");
        assert!(
            validator.validate(&substituted_binding).is_err(),
            "run-2 binding must reject an independently substituted {counter_field}"
        );
    }

    let mut reordered_oracle = artifact_by_schema("orchardprobe.lab002.oracle.v1");
    let oracle_slices = reordered_oracle["roles"][0]["slices"]
        .as_array_mut()
        .expect("oracle slices are an array");
    let mut second_slice = oracle_slices[0].clone();
    second_slice["ordinal"] = json!(1);
    oracle_slices.push(second_slice);
    oracle_slices.swap(0, 1);
    assert!(validator.validate(&reordered_oracle).is_err());

    for (schema_name, pointer) in [
        (
            "orchardprobe.lab002.oracle.v1",
            "/roles/0/slices/0/slice_file_offset",
        ),
        (
            "orchardprobe.lab002.oracle.v1",
            "/roles/0/slices/0/slice_file_size",
        ),
        (
            "orchardprobe.lab002.oracle.v1",
            "/roles/0/slices/0/section_slice_offset",
        ),
        (
            "orchardprobe.lab002.oracle.v1",
            "/roles/0/slices/0/section_file_offset",
        ),
        (
            "orchardprobe.lab002.oracle.v1",
            "/roles/0/slices/0/section_vm_offset",
        ),
        ("orchardprobe.lab002.role-report.v1", "/installed_file_size"),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/slice_file_offset",
        ),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/slice_file_size",
        ),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/section_slice_offset",
        ),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/section_file_offset",
        ),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/section_vm_offset",
        ),
        ("orchardprobe.lab002.role-report.v1", "/slices/0/cryptoff"),
        ("orchardprobe.lab002.role-report.v1", "/slices/0/cryptsize"),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/crypt_file_start",
        ),
        (
            "orchardprobe.lab002.role-report.v1",
            "/slices/0/crypt_file_end",
        ),
    ] {
        let mut oversized = artifact_by_schema(schema_name);
        *oversized
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("missing bounded field {pointer}")) = json!(104_857_601);
        assert!(
            validator.validate(&oversized).is_err(),
            "{schema_name}{pointer} must reject values above 100 MiB"
        );
    }

    let mut five_slice_oracle = artifact_by_schema("orchardprobe.lab002.oracle.v1");
    let oracle_slices = five_slice_oracle["roles"][0]["slices"]
        .as_array_mut()
        .expect("oracle slices are an array");
    for ordinal in 1..=4 {
        let mut slice = oracle_slices[0].clone();
        slice["ordinal"] = json!(ordinal);
        oracle_slices.push(slice);
    }
    assert!(validator.validate(&five_slice_oracle).is_err());

    let mut contradictory_pass = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    contradictory_pass["reasons"] = json!(["mapped_digest_mismatch"]);
    assert!(validator.validate(&contradictory_pass).is_err());

    let mut unexplained_failure = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    unexplained_failure["outcome"] = json!("fail");
    assert!(validator.validate(&unexplained_failure).is_err());

    let mut wrong_fixed_section = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    wrong_fixed_section["slices"][0]["section_name"] = json!("__other");
    assert!(validator.validate(&wrong_fixed_section).is_err());

    let mut zero_crypt_size = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    zero_crypt_size["slices"][0]["cryptsize"] = json!(0);
    zero_crypt_size["slices"][0]["crypt_file_end"] =
        zero_crypt_size["slices"][0]["crypt_file_start"].clone();
    assert!(validator.validate(&zero_crypt_size).is_err());
    let zero_crypt_size_canonical = canonical_json_with_limit(&zero_crypt_size, 32 * 1024)
        .expect("zero-crypt-size report canonicalizes");
    assert!(
        lab002_artifacts::RoleReport::from_canonical_bytes(&zero_crypt_size_canonical).is_err(),
        "Rust must enforce the executableSize minimum for cryptsize"
    );

    let mut contradictory_coverage = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    contradictory_coverage["slices"][0]["encryption_covers_section"] = json!(false);
    validator
        .validate(&contradictory_coverage)
        .expect("Schema admits the boolean before coordinate consistency validation");
    let contradictory_coverage_canonical =
        canonical_json_with_limit(&contradictory_coverage, 32 * 1024)
            .expect("contradictory coverage report canonicalizes");
    assert!(
        lab002_artifacts::RoleReport::from_canonical_bytes(&contradictory_coverage_canonical)
            .is_err(),
        "Rust must reject encryption coverage that contradicts slice coordinates"
    );

    let mut one_character_envelope =
        artifact_by_schema("orchardprobe.lab002.authorized-operation-envelope.v1");
    one_character_envelope["acknowledgement_canonical"] = json!("0");
    assert!(validator.validate(&one_character_envelope).is_err());
    let one_character_envelope_canonical =
        canonical_json_with_limit(&one_character_envelope, 16 * 1024)
            .expect("one-character embedded JSON envelope canonicalizes");
    assert!(
        lab002_artifacts::AuthorizedOperationEnvelope::from_canonical_bytes(
            &one_character_envelope_canonical
        )
        .is_err(),
        "Rust must enforce the embedded canonical string minimum"
    );

    let mut unknown_field = install_acknowledgement;
    unknown_field
        .as_object_mut()
        .expect("acknowledgement is an object")
        .insert("note".into(), json!("not allowed"));
    assert!(validator.validate(&unknown_field).is_err());
    let unknown_field_canonical =
        canonical_json_with_limit(&unknown_field, 3 * 1024).expect("unknown field fits byte limit");
    assert!(
        lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(
            &unknown_field_canonical
        )
        .is_err(),
        "Rust codec must reject schema-unknown fields"
    );

    let valid_acknowledgement = artifact_by_schema("orchardprobe.lab002.authorized-use-ack.v1");
    let valid_acknowledgement_canonical =
        canonical_json_with_limit(&valid_acknowledgement, 3 * 1024)
            .expect("valid acknowledgement canonicalizes");
    let mut noncanonical_acknowledgement = valid_acknowledgement_canonical.clone();
    noncanonical_acknowledgement.push(b'\n');
    assert!(
        lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(
            &noncanonical_acknowledgement
        )
        .is_err(),
        "Rust codec must require exact JCS bytes"
    );
    for required_nullable in [
        "run_ordinal",
        "expected_environment",
        "expected_enrollment_binding_sha256",
    ] {
        let mut missing = valid_acknowledgement.clone();
        missing
            .as_object_mut()
            .expect("acknowledgement is an object")
            .remove(required_nullable);
        assert!(
            validator.validate(&missing).is_err(),
            "Schema must require {required_nullable} even when its value may be null"
        );
        let canonical = canonical_json_with_limit(&missing, 3 * 1024)
            .expect("missing-field value canonicalizes");
        assert!(
            lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(&canonical)
                .is_err(),
            "Rust codec must require {required_nullable} even when its value may be null"
        );
    }
    let mut negative_window = valid_acknowledgement.clone();
    negative_window["acknowledged_at"] = json!(-900);
    negative_window["not_before"] = json!(-900);
    negative_window["not_after"] = json!(0);
    assert!(validator.validate(&negative_window).is_err());
    let negative_window_canonical = canonical_json_with_limit(&negative_window, 3 * 1024)
        .expect("negative exact window canonicalizes");
    assert!(
        lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(
            &negative_window_canonical
        )
        .is_err(),
        "Rust codec must reject a mathematically exact window outside unixTime"
    );

    let mut missing_superblob = artifact_by_schema("orchardprobe.lab002.role-report.v1");
    missing_superblob["signature"]
        .as_object_mut()
        .expect("signature evidence is an object")
        .remove("superblob_sha256");
    assert!(validator.validate(&missing_superblob).is_err());
    let missing_superblob_canonical = canonical_json_with_limit(&missing_superblob, 32 * 1024)
        .expect("missing-superblob report canonicalizes");
    assert!(
        lab002_artifacts::RoleReport::from_canonical_bytes(&missing_superblob_canonical).is_err(),
        "Rust codec must require the nullable superblob_sha256 field"
    );

    let mut missing_completed_at = artifact_by_schema("orchardprobe.lab002.session-report.v1");
    missing_completed_at
        .as_object_mut()
        .expect("session report is an object")
        .remove("completed_at");
    assert!(validator.validate(&missing_completed_at).is_err());
    let missing_completed_at_canonical =
        canonical_json_with_limit(&missing_completed_at, 32 * 1024)
            .expect("missing-completion report canonicalizes");
    assert!(
        lab002_artifacts::SessionReport::from_canonical_bytes(&missing_completed_at_canonical)
            .is_err(),
        "Rust codec must require the nullable completed_at field"
    );

    let mut missing_prior_binding = artifact_by_schema("orchardprobe.lab002.collection-intent.v1");
    missing_prior_binding
        .as_object_mut()
        .expect("collection intent is an object")
        .remove("prior_collection_binding_sha256");
    assert!(validator.validate(&missing_prior_binding).is_err());
    let missing_prior_binding_canonical =
        canonical_json_with_limit(&missing_prior_binding, 16 * 1024)
            .expect("missing-prior intent canonicalizes");
    assert!(
        lab002_artifacts::CollectionIntent::from_canonical_bytes(&missing_prior_binding_canonical)
            .is_err(),
        "Rust codec must require the nullable prior_collection_binding_sha256 field"
    );

    let mut wrong_schema_acknowledgement = valid_acknowledgement;
    wrong_schema_acknowledgement["schema"] = json!("orchardprobe.lab002.wrong.v1");
    let wrong_schema_canonical = canonical_json_with_limit(&wrong_schema_acknowledgement, 3 * 1024)
        .expect("wrong-schema acknowledgement canonicalizes");
    assert!(
        lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(
            &wrong_schema_canonical
        )
        .is_err(),
        "Rust codec must validate the fixed schema identifier"
    );
    assert!(
        lab002_artifacts::AuthorizationAcknowledgement::from_canonical_bytes(&vec![
            b' ';
            3 * 1024 + 1
        ])
        .is_err(),
        "Rust codec must enforce the acknowledgement byte limit before parsing"
    );

    let mut schema_valid_unsorted_groups =
        artifact_by_schema("orchardprobe.lab002.authorized-targets.v1");
    schema_valid_unsorted_groups["targets"][0]["application_groups"]["values"] =
        json!(["group.z.example", "group.a.example"]);
    validator
        .validate(&schema_valid_unsorted_groups)
        .expect("Schema accepts unique application groups independent of array order");
    assert_lab002_codec::<lab002_artifacts::AuthorizedTargetManifest>(
        &schema_valid_unsorted_groups,
    );
    for forbidden_null in ["application_identifier", "application_groups"] {
        let mut explicit_null = artifact_by_schema("orchardprobe.lab002.authorized-targets.v1");
        let field = if forbidden_null == "application_identifier" {
            "value"
        } else {
            "values"
        };
        explicit_null["targets"][1][forbidden_null]
            .as_object_mut()
            .expect("requirement is an object")
            .insert(field.into(), Value::Null);
        assert!(
            validator.validate(&explicit_null).is_err(),
            "Schema forbids explicit null in a required_absent branch"
        );
        let canonical = canonical_json_with_limit(&explicit_null, 16 * 1024)
            .expect("explicit-null target manifest canonicalizes");
        assert!(
            lab002_artifacts::AuthorizedTargetManifest::from_canonical_bytes(&canonical).is_err(),
            "Rust must distinguish an absent property from an explicit null"
        );
    }

    let mut unsigned_export_schema = schema.clone();
    let unsigned_export_schema_object = unsigned_export_schema
        .as_object_mut()
        .expect("schema is an object");
    unsigned_export_schema_object.remove("oneOf");
    unsigned_export_schema_object.insert("$ref".into(), json!("#/$defs/unsignedSessionExport"));
    let unsigned_export_validator = jsonschema::draft202012::new(&unsigned_export_schema)
        .expect("unsigned export schema compiles");
    let mut unsigned_export = unsigned_export;
    assert_lab002_codec::<lab002_artifacts::UnsignedSessionExport>(&unsigned_export);
    unsigned_export_validator
        .validate(&unsigned_export)
        .expect("fixed export order is valid");
    let mut substituted_export = unsigned_export.clone();
    substituted_export["run_counter"] = json!("0000000000000002");
    assert!(
        unsigned_export_validator
            .validate(&substituted_export)
            .is_err()
    );
    let mut run_two_export = unsigned_export.clone();
    run_two_export["run_ordinal"] = json!(2);
    run_two_export["run_counter"] = json!("0000000000000002");
    unsigned_export_validator
        .validate(&run_two_export)
        .expect("run-2 unsigned export counter branch is valid");
    run_two_export["run_counter"] = json!("0000000000000001");
    assert!(unsigned_export_validator.validate(&run_two_export).is_err());
    unsigned_export["entries"]
        .as_array_mut()
        .expect("entries is an array")
        .swap(1, 2);
    assert!(
        unsigned_export_validator
            .validate(&unsigned_export)
            .is_err()
    );
    let mut one_character_export = run_two_export;
    one_character_export["run_counter"] = json!("0000000000000002");
    one_character_export["entries"][0]["canonical_document"] = json!("0");
    assert!(
        unsigned_export_validator
            .validate(&one_character_export)
            .is_err()
    );
    let one_character_export_canonical =
        canonical_json_with_limit(&one_character_export, 512 * 1024)
            .expect("one-character export document canonicalizes");
    assert!(
        lab002_artifacts::UnsignedSessionExport::from_canonical_bytes(
            &one_character_export_canonical
        )
        .is_err(),
        "Rust must enforce the export document string minimum"
    );

    let mut unsigned_receipt_schema = schema;
    let unsigned_receipt_schema_object = unsigned_receipt_schema
        .as_object_mut()
        .expect("schema is an object");
    unsigned_receipt_schema_object.remove("oneOf");
    unsigned_receipt_schema_object
        .insert("$ref".into(), json!("#/$defs/unsignedEnrollmentReceipt"));
    let unsigned_receipt_validator = jsonschema::draft202012::new(&unsigned_receipt_schema)
        .expect("unsigned enrollment receipt schema compiles");
    unsigned_receipt_validator
        .validate(&unsigned_receipt)
        .expect("unsigned enrollment receipt core is closed and valid");
    assert_lab002_codec::<lab002_artifacts::UnsignedEnrollmentReceipt>(&unsigned_receipt);
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
