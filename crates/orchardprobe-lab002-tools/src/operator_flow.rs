use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use orchardprobe_core::ipa::{MAX_IPA_ENTRY_COPY_BYTES, copy_ipa_entry_bounded, inspect_ipa};
use orchardprobe_core::lab002::LAB002_PROFILE;
use orchardprobe_core::lab002::artifacts::{
    AuthorizationAcknowledgement, AuthorizedTargetManifest, ClosedArtifact,
    DeviceEnrollmentBinding, Environment, LabOracle,
};
use orchardprobe_core::lab002::host::{
    EnrollmentArtifactBytes, RunArtifactBytes, expected_inventory_sha256, verify_enrollment_chain,
    verify_run_chain, verify_two_run_chain,
};
use orchardprobe_core::lab002::operator::{
    AuthorizationAssertions, RunControlRequest, close_enrollment, close_run,
    create_installation_control, create_run_control,
};
use orchardprobe_core::lab002::{
    BuildBindingInput, build_binding_sha256, target_identity_binding_sha256,
    target_identity_set_sha256,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    CHECKPOINT_BUILD_NUMBER, CHECKPOINT_MARKETING_VERSION, MANIFEST_NAME, MAX_IPA_BYTES,
    MAX_PRIVATE_ARTIFACT_BYTES, MAX_UPLOAD_RESULT_BYTES, ORACLE_NAME, PREBUILD_NAME,
    PREBUILD_SCHEMA, PRIVATE_SEED_NAME, PrivateOutputRoot, canonical_json,
    is_bounded_utc_timestamp, is_lower_hex, lower_hex, open_directory_entry,
    parse_identity_component, publish_prebuild_directory, read_private_artifact,
    read_private_file_with_mode, read_request, sha256_hex, validate_bound_private_output_root,
    verify_private_artifact_inventory,
};

const START_ENROLLMENT_SCHEMA: &str = "orchardprobe.lab002.operator-start-enrollment.v1";
const START_RUN_SCHEMA: &str = "orchardprobe.lab002.operator-start-run.v1";
const OPERATOR_RESULT_SCHEMA: &str = "orchardprobe.lab002.operator-result.v1";
const EVIDENCE_NAME: &str = "demolab-pre-upload-evidence.json";
const UPLOAD_RESULT_NAME: &str = "demolab-upload-result.json";
const SOURCE_MANIFEST_NAME: &str = "authorized-target-manifest.json";
const SOURCE_ORACLE_NAME: &str = "frozen-oracle.json";
const SOURCE_EVIDENCE_NAME: &str = "preupload-evidence.json";
const INSTALL_ACK_NAME: &str = "installation-acknowledgement.json";
const INSTALL_ENVELOPE_NAME: &str = "installation-envelope.json";
const ENROLLMENT_RESULT_DIRECTORY: &str = "enrollment-result";
const RECEIPT_NAME: &str = "signed-enrollment-receipt.json";
const SELECTION_NAME: &str = "device-selection-confirmation.json";
const ENROLLMENT_BINDING_NAME: &str = "device-enrollment-binding.json";
const RUN_ACK_NAME: &str = "run-acknowledgement.json";
const RUN_ENVELOPE_NAME: &str = "collection-challenge.json";
const RUN_INTENT_NAME: &str = "collection-intent.json";
const RUN_EXPORT_NAME: &str = "signed-session-export.json";
const RUN_BINDING_NAME: &str = "collection-binding.json";
const MAX_OPERATOR_INPUT_BYTES: usize = 512 * 1024;
const UPLOAD_INDETERMINATE_NOTE: &str = "Reconcile this build in App Store Connect before retrying; the upload may succeed even if Apple altool later exits with an error.";
const UPLOAD_ACCEPTED_NOTE: &str = "Apple altool returned explicit success without product-errors for the evidence-bound upload; confirm TestFlight readiness in App Store Connect. This does not establish installed lineage, protection, or plaintext.";

#[derive(Debug, Serialize)]
pub(super) struct OperatorOutput {
    schema: &'static str,
    status: &'static str,
    phase: String,
    experiment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_ordinal: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    import_relative_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_selection_fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_disposition: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartEnrollmentRequest {
    schema: String,
    expected_environment: Environment,
    confirmed: bool,
    owns_or_explicitly_authorized_target: bool,
    within_authorized_scope: bool,
    understands_legal_limits: bool,
    will_protect_output_and_not_resign_install_or_redistribute: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRunRequest {
    schema: String,
    confirmed: bool,
    owns_or_explicitly_authorized_target: bool,
    within_authorized_scope: bool,
    understands_legal_limits: bool,
    will_protect_output_and_not_resign_install_or_redistribute: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadResult {
    schema_version: u8,
    source_commit: String,
    ipa_sha256: String,
    attempt_started_at: String,
    uploaded_at: Option<String>,
    destination: String,
    external_distribution: bool,
    status: String,
    note: String,
}

fn valid_upload_result(upload: &UploadResult) -> bool {
    match (upload.status.as_str(), upload.uploaded_at.as_deref()) {
        ("indeterminate", None) => upload.note == UPLOAD_INDETERMINATE_NOTE,
        ("accepted", Some(uploaded_at)) => {
            is_bounded_utc_timestamp(uploaded_at)
                && uploaded_at >= upload.attempt_started_at.as_str()
                && upload.note == UPLOAD_ACCEPTED_NOTE
        }
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreuploadEvidence {
    schema_version: u8,
    profile: String,
    purpose: String,
    decision: String,
    created_at: String,
    source: EvidenceSource,
    toolchain: EvidenceToolchain,
    build: EvidenceBuild,
    artifacts: EvidenceArtifacts,
    lab002: EvidenceLab002,
    lineage: EvidenceLineage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSource {
    commit: String,
    tree_clean: bool,
    fixture: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceToolchain {
    fastlane_version: String,
    xcodegen_version: String,
    xcode: Vec<String>,
    iphoneos_sdk_version: String,
    iphoneos_sdk_build: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBuild {
    configuration: String,
    marketing_version: String,
    build_number: String,
    distribution: String,
    bundle_identifiers: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceArtifacts {
    ipa: EvidenceIpa,
    archive_binaries: Vec<EvidenceBinary>,
    package: EvidencePackage,
    ipa_binaries: Vec<EvidenceBinary>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceIpa {
    filename: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBinary {
    role: String,
    relative_path: String,
    size: u64,
    sha256: String,
    #[serde(default)]
    architectures: Option<Vec<String>>,
    #[serde(default)]
    slices: Option<Vec<EvidenceSlice>>,
    initial_protection_status: String,
    expected_plaintext_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSlice {
    architecture: String,
    uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidencePackage {
    application: String,
    identity_validated: bool,
    export_compliance_validated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceLab002 {
    build_binding_sha256: String,
    target_identity_set_sha256: String,
    authorized_target_manifest: EvidenceArtifactIdentity,
    oracle: EvidenceArtifactIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceArtifactIdentity {
    name: String,
    device: String,
    inode: String,
    mode: u32,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceLineage {
    uploaded_ipa_bound: bool,
    installed_artifact_bound: bool,
    note: String,
}

struct FrozenEvidenceInputs<'a> {
    record: &'a super::PrebuildRecord,
    manifest_device: u64,
    manifest_inode: u64,
    manifest_size: u64,
    manifest_sha256: &'a str,
    oracle: &'a LabOracle,
    oracle_device: u64,
    oracle_inode: u64,
    oracle_size: u64,
    oracle_sha256: &'a str,
    ipa_size: u64,
    ipa_sha256: &'a str,
    ipa_bytes: &'a [u8],
}

struct SourceBundle {
    signing_key: SigningKey,
    manifest: Vec<u8>,
    oracle: Vec<u8>,
    evidence: Vec<u8>,
    build_binding_sha256: String,
}

struct PrebuildSource {
    signing_key: SigningKey,
    seed: super::ReadPrivateArtifact,
    manifest: super::ReadPrivateArtifact,
    record_artifact: super::ReadPrivateArtifact,
    record: super::PrebuildRecord,
}

struct EnrollmentFiles {
    manifest: Vec<u8>,
    acknowledgement: Vec<u8>,
    envelope: Vec<u8>,
    receipt: Vec<u8>,
    selection: Vec<u8>,
    binding: Vec<u8>,
}

struct RunFiles {
    acknowledgement: Vec<u8>,
    envelope: Vec<u8>,
    intent: Vec<u8>,
    export: Vec<u8>,
    binding: Vec<u8>,
}

fn assertions(
    confirmed: bool,
    owns_or_explicitly_authorized_target: bool,
    within_authorized_scope: bool,
    understands_legal_limits: bool,
    will_protect_output_and_not_resign_install_or_redistribute: bool,
) -> AuthorizationAssertions {
    AuthorizationAssertions {
        confirmed,
        owns_or_explicitly_authorized_target,
        within_authorized_scope,
        understands_legal_limits,
        will_protect_output_and_not_resign_install_or_redistribute,
    }
}

fn now() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "host clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "host clock does not fit the signed time field".into())
}

fn parse_bound(
    arguments: &[OsString],
    offset: usize,
    option: &str,
) -> Result<(PathBuf, (u64, u64)), String> {
    let device = format!("{option}-device");
    let inode = format!("{option}-inode");
    if arguments.get(offset) != Some(&OsString::from(option))
        || arguments.get(offset + 2) != Some(&OsString::from(&device))
        || arguments.get(offset + 4) != Some(&OsString::from(&inode))
    {
        return Err(format!(
            "operator command is missing fixed {option} arguments"
        ));
    }
    Ok((
        PathBuf::from(
            arguments
                .get(offset + 1)
                .ok_or_else(|| format!("{option} path is missing"))?,
        ),
        (
            parse_identity_component(
                arguments
                    .get(offset + 3)
                    .map(OsString::as_os_str)
                    .unwrap_or_else(|| OsStr::new("")),
                "operator directory device",
            )?,
            parse_identity_component(
                arguments
                    .get(offset + 5)
                    .map(OsString::as_os_str)
                    .unwrap_or_else(|| OsStr::new("")),
                "operator directory inode",
            )?,
        ),
    ))
}

fn held_root(
    path: PathBuf,
    identity: (u64, u64),
    descriptor: File,
) -> Result<PrivateOutputRoot, String> {
    validate_bound_private_output_root(&path, descriptor, identity)
}

fn read_raw(maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read bounded operator artifact: {error}"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("operator artifact is empty or oversized".into());
    }
    Ok(bytes)
}

fn split_fingerprint_and_receipt(bytes: &[u8]) -> Result<(String, Vec<u8>), String> {
    if bytes.len() <= 65 || bytes[64] != b'\n' {
        return Err("fingerprint and receipt input is malformed".into());
    }
    let fingerprint = std::str::from_utf8(&bytes[..64])
        .map_err(|_| "fingerprint must be lowercase hexadecimal")?;
    if !is_lower_hex(fingerprint, 64) {
        return Err("fingerprint must contain all 64 lowercase hex characters".into());
    }
    Ok((fingerprint.to_owned(), bytes[65..].to_vec()))
}

fn read_fingerprint_and_receipt() -> Result<(String, Vec<u8>), String> {
    let bytes = read_raw(MAX_PRIVATE_ARTIFACT_BYTES + 65)?;
    split_fingerprint_and_receipt(&bytes)
}

fn exact_inventory(directory: &File, expected: &[&str]) -> Result<(), String> {
    let mut observed = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)
        .map_err(|error| format!("could not enumerate private operator directory: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("operator directory entry is invalid: {error}"))?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        observed.push(
            String::from_utf8(name.to_vec())
                .map_err(|_| "operator directory entry is not UTF-8")?,
        );
        if observed.len() > expected.len() {
            return Err("operator directory contains an unexpected entry".into());
        }
    }
    observed.sort();
    let mut expected = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    if observed != expected {
        return Err("operator directory does not contain the exact expected entries".into());
    }
    Ok(())
}

fn open_owner_directory(parent: &File, name: &str) -> Result<File, String> {
    let directory = open_directory_entry(parent, name)
        .map_err(|error| format!("could not open private operator phase {name}: {error}"))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("could not inspect private operator phase {name}: {error}"))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(format!("private operator phase {name} is not owner-only"));
    }
    Ok(directory)
}

fn is_simple_version(value: &str, maximum_components: usize) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    !components.is_empty()
        && components.len() <= maximum_components
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_architecture(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_unique(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

const EVIDENCE_BINARY_SPECS: [(&str, &str); 3] = [
    ("main_executable", "DemoLab.app/DemoLab"),
    (
        "dynamic_framework",
        "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
    ),
    (
        "app_extension",
        "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
    ),
];

fn validate_evidence_binary(
    binary: &EvidenceBinary,
    expected: (&str, &str),
    archive: bool,
) -> Result<(), String> {
    if binary.role != expected.0
        || binary.relative_path != expected.1
        || binary.size == 0
        || binary.size > super::MAX_EXECUTABLE_BYTES
        || !is_lower_hex(&binary.sha256, 64)
        || binary.initial_protection_status != "not_observed"
        || binary.expected_plaintext_status != "candidate_pre_upload_archive_only"
    {
        return Err("pre-upload binary evidence is incomplete".into());
    }
    if archive {
        let architectures = binary
            .architectures
            .as_ref()
            .ok_or("Archive architecture evidence is missing")?;
        let slices = binary
            .slices
            .as_ref()
            .ok_or("Archive slice evidence is missing")?;
        if architectures.is_empty()
            || architectures.len() > 8
            || architectures.len() != slices.len()
            || !is_unique(architectures)
            || !architectures.iter().all(|value| is_architecture(value))
            || slices.iter().enumerate().any(|(index, slice)| {
                slice.architecture != architectures[index]
                    || !is_architecture(&slice.architecture)
                    || !is_uuid(&slice.uuid)
            })
        {
            return Err("Archive architecture evidence is incomplete".into());
        }
    } else if binary.architectures.is_some() || binary.slices.is_some() {
        return Err("IPA binary evidence contains unexpected Archive fields".into());
    }
    Ok(())
}

fn validate_evidence_artifact(
    artifact: &EvidenceArtifactIdentity,
    expected_name: &str,
    expected_device: u64,
    expected_inode: u64,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    if artifact.name != expected_name
        || artifact.device != expected_device.to_string()
        || artifact.inode != expected_inode.to_string()
        || artifact.mode != 0o400
        || artifact.size != expected_size
        || artifact.sha256 != expected_sha256
    {
        return Err(format!("pre-upload {expected_name} identity is invalid"));
    }
    Ok(())
}

fn verify_frozen_ipa_entries(
    ipa_bytes: &[u8],
    ipa_size: u64,
    evidence: &PreuploadEvidence,
) -> Result<(), String> {
    if u64::try_from(ipa_bytes.len()).ok() != Some(ipa_size) {
        return Err("frozen IPA bytes do not match their retained size".into());
    }
    let mut ipa = Cursor::new(ipa_bytes);
    let inventory = inspect_ipa(&mut ipa, ipa_size)
        .map_err(|error| format!("frozen IPA inventory is invalid: {error}"))?;
    if inventory.app_root != "Payload/DemoLab.app" {
        return Err("frozen IPA does not contain the fixed DemoLab app root".into());
    }
    let expected_paths = EVIDENCE_BINARY_SPECS
        .iter()
        .map(|(_, path)| format!("Payload/{path}"))
        .collect::<Vec<_>>();
    let executable_paths = inventory
        .entries
        .iter()
        .filter(|entry| entry.executable)
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    if !super::same_paths_ignoring_order(
        executable_paths,
        &expected_paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    ) {
        return Err("frozen IPA executable inventory is not the exact three roles".into());
    }

    for (binary, path) in evidence.artifacts.ipa_binaries.iter().zip(&expected_paths) {
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == *path)
            .ok_or_else(|| format!("frozen IPA is missing fixed executable {path}"))?;
        if entry.uncompressed_size != binary.size {
            return Err(format!(
                "frozen IPA executable {path} size does not match the pre-upload evidence"
            ));
        }
        let mut copied_file = tempfile::tempfile()
            .map_err(|error| format!("could not create private IPA verification file: {error}"))?;
        let copied = copy_ipa_entry_bounded(
            &mut ipa,
            ipa_size,
            path,
            super::MAX_EXECUTABLE_BYTES.min(MAX_IPA_ENTRY_COPY_BYTES),
            &mut copied_file,
        )
        .map_err(|error| format!("could not verify frozen IPA executable {path}: {error}"))?;
        if copied.inventory != inventory || copied.bytes_written != binary.size {
            return Err(format!(
                "frozen IPA inventory changed while verifying executable {path}"
            ));
        }
        copied_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("could not rewind frozen IPA executable {path}: {error}"))?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = copied_file
                .read(&mut buffer)
                .map_err(|error| format!("could not hash frozen IPA executable {path}: {error}"))?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| format!("frozen IPA executable {path} size overflowed"))?;
            if total > super::MAX_EXECUTABLE_BYTES {
                return Err(format!(
                    "frozen IPA executable {path} exceeds its size bound"
                ));
            }
            digest.update(&buffer[..read]);
        }
        if total != binary.size || lower_hex(&digest.finalize()) != binary.sha256 {
            return Err(format!(
                "frozen IPA executable {path} does not match the pre-upload evidence"
            ));
        }
    }
    let confirmed = inspect_ipa(&mut ipa, ipa_size)
        .map_err(|error| format!("could not revalidate frozen IPA inventory: {error}"))?;
    if confirmed != inventory {
        return Err("frozen IPA inventory changed during evidence verification".into());
    }
    Ok(())
}

fn validate_complete_evidence(
    evidence: &PreuploadEvidence,
    inputs: &FrozenEvidenceInputs<'_>,
) -> Result<(), String> {
    let record = inputs.record;
    let expected_xcode = [
        format!("Xcode {}", record.toolchain.xcode_version),
        format!("Build version {}", record.toolchain.xcode_build),
    ];
    if evidence.schema_version != 1
        || evidence.profile != "orchardprobe.demolab.testflight-preupload.v1"
        || evidence.purpose != "LAB-001 controlled first-party TestFlight preparation"
        || evidence.decision != "pending_controlled_device_observation"
        || !is_bounded_utc_timestamp(&evidence.created_at)
        || evidence.source.commit != record.source_commit
        || !evidence.source.tree_clean
        || evidence.source.fixture != record.fixture_source_root
        || evidence.toolchain.fastlane_version != record.toolchain.fastlane_version
        || evidence.toolchain.xcodegen_version != record.toolchain.xcodegen_version
        || evidence.toolchain.xcode.len() != expected_xcode.len()
        || evidence
            .toolchain
            .xcode
            .iter()
            .map(|line| line.trim())
            .ne(expected_xcode.iter().map(String::as_str))
        || !is_simple_version(&evidence.toolchain.xcodegen_version, 3)
        || evidence.toolchain.iphoneos_sdk_version != record.toolchain.iphoneos_sdk_version
        || evidence.toolchain.iphoneos_sdk_build != record.toolchain.iphoneos_sdk_build
        || evidence.build.configuration != "Release"
        || evidence.build.marketing_version != CHECKPOINT_MARKETING_VERSION
        || evidence.build.build_number != CHECKPOINT_BUILD_NUMBER
        || evidence.build.distribution != "app-store"
        || evidence.build.bundle_identifiers
            != "operator-provided first-party identifiers; redacted"
        || evidence.artifacts.ipa.filename != "DemoLab-3.ipa"
        || evidence.artifacts.ipa.size != inputs.ipa_size
        || evidence.artifacts.ipa.sha256 != inputs.ipa_sha256
        || evidence.artifacts.package.application != "DemoLab.app"
        || !evidence.artifacts.package.identity_validated
        || !evidence.artifacts.package.export_compliance_validated
        || evidence.artifacts.archive_binaries.len() != EVIDENCE_BINARY_SPECS.len()
        || evidence.artifacts.ipa_binaries.len() != EVIDENCE_BINARY_SPECS.len()
        || evidence.lab002.build_binding_sha256 != record.build_binding_sha256
        || evidence.lab002.target_identity_set_sha256 != record.target_identity_set_sha256
        || evidence.lineage.uploaded_ipa_bound
        || evidence.lineage.installed_artifact_bound
        || evidence.lineage.note
            != "Pre-upload bytes are candidates, not proof of installed plaintext."
    {
        return Err("pre-upload evidence is not the complete closed checkpoint record".into());
    }
    for (index, expected) in EVIDENCE_BINARY_SPECS.iter().copied().enumerate() {
        validate_evidence_binary(&evidence.artifacts.archive_binaries[index], expected, true)?;
        validate_evidence_binary(&evidence.artifacts.ipa_binaries[index], expected, false)?;
        let mut evidence_uuids = evidence.artifacts.archive_binaries[index]
            .slices
            .as_ref()
            .ok_or("Archive slice evidence is missing")?
            .iter()
            .map(|slice| slice.uuid.replace('-', ""))
            .collect::<Vec<_>>();
        let mut oracle_uuids = inputs.oracle.roles[index]
            .slices
            .iter()
            .map(|slice| slice.macho_uuid.clone())
            .collect::<Vec<_>>();
        evidence_uuids.sort_unstable();
        oracle_uuids.sort_unstable();
        if evidence_uuids != oracle_uuids {
            return Err("Archive UUID evidence does not match the frozen oracle".into());
        }
    }
    validate_evidence_artifact(
        &evidence.lab002.authorized_target_manifest,
        MANIFEST_NAME,
        inputs.manifest_device,
        inputs.manifest_inode,
        inputs.manifest_size,
        inputs.manifest_sha256,
    )?;
    validate_evidence_artifact(
        &evidence.lab002.oracle,
        ORACLE_NAME,
        inputs.oracle_device,
        inputs.oracle_inode,
        inputs.oracle_size,
        inputs.oracle_sha256,
    )?;
    verify_frozen_ipa_entries(inputs.ipa_bytes, inputs.ipa_size, evidence)
}

struct DerivedPrebuildBindings {
    build_binding_sha256: String,
    target_identity_set_sha256: String,
    targets: Vec<super::PreparedTarget>,
}

fn derive_prebuild_bindings(
    manifest: &AuthorizedTargetManifest,
    manifest_sha256: &str,
    record: &super::PrebuildRecord,
) -> Result<DerivedPrebuildBindings, String> {
    let build_input = BuildBindingInput {
        source_commit: record.source_commit.clone(),
        marketing_version: record.marketing_version.clone(),
        build_number: record.build_number.clone(),
        configuration: record.configuration.clone(),
        observer_revision: record.observer_revision.clone(),
        authorized_target_manifest_sha256: manifest_sha256.to_owned(),
        xcode_version: record.toolchain.xcode_version.clone(),
        xcode_build: record.toolchain.xcode_build.clone(),
        iphoneos_sdk_version: record.toolchain.iphoneos_sdk_version.clone(),
        iphoneos_sdk_build: record.toolchain.iphoneos_sdk_build.clone(),
        xcodegen_version: record.toolchain.xcodegen_version.clone(),
        xcodegen_architecture: record.toolchain.xcodegen_architecture.clone(),
        xcodegen_executable_sha256: record.toolchain.xcodegen_executable_sha256.clone(),
        fastlane_version: record.toolchain.fastlane_version.clone(),
        gemfile_lock_sha256: record.toolchain.gemfile_lock_sha256.clone(),
    };
    let expected_build_binding =
        build_binding_sha256(&build_input).map_err(|error| error.to_string())?;
    let mut target_digests = Vec::with_capacity(manifest.targets.len());
    let mut expected_targets = Vec::with_capacity(manifest.targets.len());
    for target in &manifest.targets {
        let identity_input = super::target_identity_input(&manifest.identity_nonce, target)?;
        let digest =
            target_identity_binding_sha256(&identity_input).map_err(|error| error.to_string())?;
        target_digests.push((target.role, digest.clone()));
        expected_targets.push(super::PreparedTarget {
            role: target.role,
            target_identity_binding_sha256: digest,
        });
    }
    let expected_identity_set =
        target_identity_set_sha256(&target_digests).map_err(|error| error.to_string())?;
    Ok(DerivedPrebuildBindings {
        build_binding_sha256: expected_build_binding,
        target_identity_set_sha256: expected_identity_set,
        targets: expected_targets,
    })
}

fn has_exact_derived_prebuild_bindings(
    record: &super::PrebuildRecord,
    derived: &DerivedPrebuildBindings,
) -> bool {
    record.build_binding_sha256 == derived.build_binding_sha256
        && record.target_identity_set_sha256 == derived.target_identity_set_sha256
        && record.targets == derived.targets
}

fn private_seed_and_record(prebuild: &PrivateOutputRoot) -> Result<PrebuildSource, String> {
    verify_private_artifact_inventory(&prebuild.directory)?;
    let seed = read_private_artifact(&prebuild.directory, PRIVATE_SEED_NAME, 32)?;
    let manifest = read_private_artifact(
        &prebuild.directory,
        MANIFEST_NAME,
        MAX_PRIVATE_ARTIFACT_BYTES,
    )?;
    let record = read_private_artifact(
        &prebuild.directory,
        PREBUILD_NAME,
        MAX_PRIVATE_ARTIFACT_BYTES,
    )?;
    let seed_bytes: [u8; 32] = seed
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| "authorization seed is not exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    if signing_key.verifying_key().is_weak() {
        return Err("authorization seed produces a weak key".into());
    }
    let manifest_value = AuthorizedTargetManifest::from_canonical_bytes(&manifest.bytes)
        .map_err(|error| format!("authorized-target manifest is invalid: {error}"))?;
    let record_value: super::PrebuildRecord = serde_json::from_slice(&record.bytes)
        .map_err(|error| format!("prebuild record is invalid: {error}"))?;
    let manifest_sha256 = sha256_hex(&manifest.bytes);
    let derived = derive_prebuild_bindings(&manifest_value, &manifest_sha256, &record_value)?;
    if canonical_json(&record_value).map_err(|error| error.to_string())? != record.bytes
        || record_value.schema != PREBUILD_SCHEMA
        || record_value.profile != LAB002_PROFILE
        || record_value.fixture_source_root != "fixtures/DemoLab"
        || !is_lower_hex(&record_value.source_commit, 40)
        || record_value.marketing_version != CHECKPOINT_MARKETING_VERSION
        || record_value.build_number != CHECKPOINT_BUILD_NUMBER
        || record_value.configuration != "Release"
        || record_value.observer_revision != "lab002-observer-v1"
        || record_value.generator_revision != record_value.source_commit
        || record_value.identity_nonce != manifest_value.identity_nonce
        || record_value.authorized_target_manifest_sha256 != manifest_sha256
        || record_value.authorization_public_key != manifest_value.authorization_public_key
        || record_value.authorization_key_id != manifest_value.authorization_key_id
        || !has_exact_derived_prebuild_bindings(&record_value, &derived)
        || manifest_value.authorization_public_key
            != lower_hex(signing_key.verifying_key().as_bytes())
    {
        return Err("private prebuild tuple is inconsistent".into());
    }
    Ok(PrebuildSource {
        signing_key,
        seed,
        manifest,
        record_artifact: record,
        record: record_value,
    })
}

fn candidate_inventory(directory: &File) -> Result<(), String> {
    exact_inventory(
        directory,
        &[
            "DemoLab.xcarchive",
            "DemoLab-3.ipa",
            EVIDENCE_NAME,
            UPLOAD_RESULT_NAME,
            ORACLE_NAME,
        ],
    )?;
    let archive = open_directory_entry(directory, "DemoLab.xcarchive")
        .map_err(|error| format!("could not open frozen Archive: {error}"))?;
    let metadata = archive
        .metadata()
        .map_err(|error| format!("could not inspect frozen Archive: {error}"))?;
    if !metadata.is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("frozen Archive is not an owned directory".into());
    }
    Ok(())
}

fn verify_frozen_archive_files(
    archive_app: &File,
    evidence: &PreuploadEvidence,
    expected_executables: &[&str],
) -> Result<(), String> {
    for (binary, relative_path) in evidence
        .artifacts
        .archive_binaries
        .iter()
        .zip(expected_executables.iter())
    {
        let components = relative_path.split('/').collect::<Vec<_>>();
        let label = format!("frozen Archive binary {relative_path}");
        let mut file = super::open_regular_beneath(
            archive_app,
            &components,
            super::MAX_EXECUTABLE_BYTES,
            &label,
        )?;
        let identity = super::stable_file_identity(&file, super::MAX_EXECUTABLE_BYTES, &label)?;
        let digest =
            super::hash_stable_file(&mut file, &identity, super::MAX_EXECUTABLE_BYTES, &label)?;
        if identity.size != binary.size || digest != binary.sha256 {
            return Err(format!("{label} does not match the pre-upload evidence"));
        }
        super::reopen_verified_regular_source(
            archive_app,
            &components,
            &identity,
            &digest,
            &label,
        )?;
    }
    Ok(())
}

fn verify_frozen_archive(
    candidate: &PrivateOutputRoot,
    evidence: &PreuploadEvidence,
) -> Result<(), String> {
    let archive_app = super::open_archive_app_beneath(&candidate.directory)?;
    let archive_identity = super::stable_directory_identity(&archive_app, "frozen Archive app")?;
    let expected_executables = EVIDENCE_BINARY_SPECS
        .iter()
        .map(|(_, path)| {
            path.strip_prefix("DemoLab.app/")
                .ok_or_else(|| "Archive evidence path is outside the fixed app".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let inventory = super::archive_executable_inventory(&archive_app)?;
    if !super::same_paths_ignoring_order(
        inventory.iter().map(String::as_str).collect(),
        &expected_executables,
    ) {
        return Err("frozen Archive executable inventory is not the exact three roles".into());
    }
    verify_frozen_archive_files(&archive_app, evidence, &expected_executables)?;
    let final_archive = super::reopen_expected_archive_app(&candidate.directory, archive_identity)?;
    if super::archive_executable_inventory(&final_archive)? != inventory {
        return Err("frozen Archive executable inventory changed during validation".into());
    }
    verify_frozen_archive_files(&final_archive, evidence, &expected_executables)
}

fn require_unchanged_source_artifact(
    observed: super::ReadPrivateArtifact,
    expected: &super::ReadPrivateArtifact,
    label: &str,
) -> Result<(), String> {
    if &observed != expected {
        return Err(format!("{label} changed after its initial validation"));
    }
    Ok(())
}

struct FrozenSourceArtifacts<'a> {
    seed: &'a super::ReadPrivateArtifact,
    manifest: &'a super::ReadPrivateArtifact,
    record: &'a super::ReadPrivateArtifact,
    oracle: &'a super::ReadPrivateArtifact,
    evidence: &'a super::ReadPrivateArtifact,
    ipa: &'a super::ReadPrivateArtifact,
    upload: &'a super::ReadPrivateArtifact,
}

fn revalidate_frozen_source_tuple(
    prebuild: &PrivateOutputRoot,
    candidate: &PrivateOutputRoot,
    artifacts: &FrozenSourceArtifacts<'_>,
    evidence: &PreuploadEvidence,
) -> Result<(), String> {
    verify_private_artifact_inventory(&prebuild.directory)?;
    require_unchanged_source_artifact(
        read_private_artifact(&prebuild.directory, PRIVATE_SEED_NAME, 32)?,
        artifacts.seed,
        "authorization seed",
    )?;
    require_unchanged_source_artifact(
        read_private_artifact(
            &prebuild.directory,
            MANIFEST_NAME,
            MAX_PRIVATE_ARTIFACT_BYTES,
        )?,
        artifacts.manifest,
        "authorized-target manifest",
    )?;
    require_unchanged_source_artifact(
        read_private_artifact(
            &prebuild.directory,
            PREBUILD_NAME,
            MAX_PRIVATE_ARTIFACT_BYTES,
        )?,
        artifacts.record,
        "prebuild record",
    )?;
    verify_private_artifact_inventory(&prebuild.directory)?;

    candidate_inventory(&candidate.directory)?;
    require_unchanged_source_artifact(
        read_private_artifact(
            &candidate.directory,
            ORACLE_NAME,
            MAX_PRIVATE_ARTIFACT_BYTES,
        )?,
        artifacts.oracle,
        "frozen oracle",
    )?;
    require_unchanged_source_artifact(
        read_private_file_with_mode(
            &candidate.directory,
            EVIDENCE_NAME,
            MAX_UPLOAD_RESULT_BYTES,
            0o600,
        )?,
        artifacts.evidence,
        "pre-upload evidence",
    )?;
    require_unchanged_source_artifact(
        read_private_file_with_mode(
            &candidate.directory,
            "DemoLab-3.ipa",
            MAX_IPA_BYTES as usize,
            0o644,
        )?,
        artifacts.ipa,
        "frozen IPA",
    )?;
    require_unchanged_source_artifact(
        read_private_file_with_mode(
            &candidate.directory,
            UPLOAD_RESULT_NAME,
            MAX_UPLOAD_RESULT_BYTES,
            0o600,
        )?,
        artifacts.upload,
        "upload audit record",
    )?;
    verify_frozen_archive(candidate, evidence)?;
    candidate_inventory(&candidate.directory)
}

fn load_source_bundle(
    prebuild: &PrivateOutputRoot,
    candidate: &PrivateOutputRoot,
) -> Result<SourceBundle, String> {
    let PrebuildSource {
        signing_key,
        seed,
        manifest,
        record_artifact,
        record,
    } = private_seed_and_record(prebuild)?;
    candidate_inventory(&candidate.directory)?;
    let oracle = read_private_artifact(
        &candidate.directory,
        ORACLE_NAME,
        MAX_PRIVATE_ARTIFACT_BYTES,
    )?;
    let evidence = read_private_file_with_mode(
        &candidate.directory,
        EVIDENCE_NAME,
        MAX_UPLOAD_RESULT_BYTES,
        0o600,
    )?;
    let ipa = read_private_file_with_mode(
        &candidate.directory,
        "DemoLab-3.ipa",
        MAX_IPA_BYTES as usize,
        0o644,
    )?;
    let upload = read_private_file_with_mode(
        &candidate.directory,
        UPLOAD_RESULT_NAME,
        MAX_UPLOAD_RESULT_BYTES,
        0o600,
    )?;
    let oracle_value = LabOracle::from_canonical_bytes(&oracle.bytes)
        .map_err(|error| format!("frozen oracle is invalid: {error}"))?;
    let evidence_value: PreuploadEvidence = serde_json::from_slice(&evidence.bytes)
        .map_err(|error| format!("pre-upload evidence is invalid: {error}"))?;
    let upload_value: UploadResult = serde_json::from_slice(&upload.bytes)
        .map_err(|error| format!("upload audit record is invalid: {error}"))?;
    let oracle_targets_match = record.targets.len() == oracle_value.roles.len()
        && record
            .targets
            .iter()
            .zip(&oracle_value.roles)
            .all(|(prepared, oracle_role)| {
                prepared.role == oracle_role.role
                    && prepared.target_identity_binding_sha256
                        == oracle_role.target_identity_binding_sha256
            });
    let manifest_sha256 = sha256_hex(&manifest.bytes);
    let oracle_sha256 = sha256_hex(&oracle.bytes);
    let ipa_sha256 = sha256_hex(&ipa.bytes);
    validate_complete_evidence(
        &evidence_value,
        &FrozenEvidenceInputs {
            record: &record,
            manifest_device: manifest.device,
            manifest_inode: manifest.inode,
            manifest_size: manifest.size,
            manifest_sha256: &manifest_sha256,
            oracle: &oracle_value,
            oracle_device: oracle.device,
            oracle_inode: oracle.inode,
            oracle_size: oracle.size,
            oracle_sha256: &oracle_sha256,
            ipa_size: ipa.size,
            ipa_sha256: &ipa_sha256,
            ipa_bytes: &ipa.bytes,
        },
    )?;
    verify_frozen_archive(candidate, &evidence_value)?;
    if oracle_value.profile != record.profile
        || oracle_value.source_commit != record.source_commit
        || oracle_value.fixture_source_root != record.fixture_source_root
        || oracle_value.marketing_version != record.marketing_version
        || oracle_value.build_number != record.build_number
        || oracle_value.configuration != record.configuration
        || oracle_value.observer_revision != record.observer_revision
        || oracle_value.generator_revision != record.generator_revision
        || oracle_value.build_binding_sha256 != record.build_binding_sha256
        || oracle_value.authorized_target_manifest_sha256 != manifest_sha256
        || oracle_value.authorization_public_key != record.authorization_public_key
        || oracle_value.authorization_key_id != record.authorization_key_id
        || oracle_value.authorization_public_key
            != lower_hex(signing_key.verifying_key().as_bytes())
        || oracle_value.target_identity_set_sha256 != record.target_identity_set_sha256
        || !oracle_targets_match
        || oracle_value.toolchain != record.toolchain
        || oracle_value.ipa_size != ipa.size
        || oracle_value.ipa_sha256 != ipa_sha256
        || upload_value.schema_version != 1
        || upload_value.source_commit != record.source_commit
        || upload_value.ipa_sha256 != oracle_value.ipa_sha256
        || !is_bounded_utc_timestamp(&upload_value.attempt_started_at)
        || upload_value.destination != "TestFlight internal preparation"
        || upload_value.external_distribution
        || !valid_upload_result(&upload_value)
    {
        return Err("frozen candidate, oracle, evidence, upload audit, and prebuild are not one exact tuple".into());
    }
    if !is_lower_hex(&record.build_binding_sha256, 64) {
        return Err("frozen build binding is invalid".into());
    }
    revalidate_frozen_source_tuple(
        prebuild,
        candidate,
        &FrozenSourceArtifacts {
            seed: &seed,
            manifest: &manifest,
            record: &record_artifact,
            oracle: &oracle,
            evidence: &evidence,
            ipa: &ipa,
            upload: &upload,
        },
        &evidence_value,
    )?;
    Ok(SourceBundle {
        signing_key,
        manifest: manifest.bytes,
        oracle: oracle.bytes,
        evidence: evidence.bytes,
        build_binding_sha256: record.build_binding_sha256,
    })
}

fn verify_retained_source_bundle(
    root: &PrivateOutputRoot,
    prebuild: &PrivateOutputRoot,
    candidate: &PrivateOutputRoot,
) -> Result<SourceBundle, String> {
    let source = load_source_bundle(prebuild, candidate)?;
    let retained_manifest = read_root_artifact(root, SOURCE_MANIFEST_NAME)?;
    let retained_oracle = read_root_artifact(root, SOURCE_ORACLE_NAME)?;
    let retained_evidence = read_root_artifact(root, SOURCE_EVIDENCE_NAME)?;
    require_retained_source_match(
        &source,
        &retained_manifest,
        &retained_oracle,
        &retained_evidence,
    )?;
    Ok(source)
}

fn require_retained_source_match(
    source: &SourceBundle,
    retained_manifest: &[u8],
    retained_oracle: &[u8],
    retained_evidence: &[u8],
) -> Result<(), String> {
    if retained_manifest == source.manifest
        && retained_oracle == source.oracle
        && retained_evidence == source.evidence
    {
        Ok(())
    } else {
        Err(
            "retained experiment source no longer matches the exact frozen prebuild/candidate tuple"
                .into(),
        )
    }
}

fn read_root_artifact(root: &PrivateOutputRoot, name: &str) -> Result<Vec<u8>, String> {
    read_private_artifact(&root.directory, name, MAX_OPERATOR_INPUT_BYTES).map(|value| value.bytes)
}

fn enrollment_files(root: &PrivateOutputRoot) -> Result<EnrollmentFiles, String> {
    let result = open_owner_directory(&root.directory, ENROLLMENT_RESULT_DIRECTORY)?;
    exact_inventory(
        &result,
        &[RECEIPT_NAME, SELECTION_NAME, ENROLLMENT_BINDING_NAME],
    )?;
    Ok(EnrollmentFiles {
        manifest: read_root_artifact(root, SOURCE_MANIFEST_NAME)?,
        acknowledgement: read_root_artifact(root, INSTALL_ACK_NAME)?,
        envelope: read_root_artifact(root, INSTALL_ENVELOPE_NAME)?,
        receipt: read_private_artifact(&result, RECEIPT_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes,
        selection: read_private_artifact(&result, SELECTION_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes,
        binding: read_private_artifact(&result, ENROLLMENT_BINDING_NAME, MAX_OPERATOR_INPUT_BYTES)?
            .bytes,
    })
}

fn exact_experiment_inventory(
    root: &PrivateOutputRoot,
    phase_directories: &[String],
) -> Result<(), String> {
    let mut expected = vec![
        SOURCE_MANIFEST_NAME.to_owned(),
        SOURCE_ORACLE_NAME.to_owned(),
        SOURCE_EVIDENCE_NAME.to_owned(),
        INSTALL_ACK_NAME.to_owned(),
        INSTALL_ENVELOPE_NAME.to_owned(),
    ];
    expected.extend_from_slice(phase_directories);
    let expected_refs = expected.iter().map(String::as_str).collect::<Vec<_>>();
    exact_inventory(&root.directory, &expected_refs)
}

fn verified_enrollment(
    root: &PrivateOutputRoot,
) -> Result<
    (
        EnrollmentFiles,
        orchardprobe_core::lab002::host::VerifiedEnrollment,
    ),
    String,
> {
    let files = enrollment_files(root)?;
    let verified = verify_enrollment_chain(EnrollmentArtifactBytes {
        authorized_target_manifest: &files.manifest,
        installation_acknowledgement: &files.acknowledgement,
        authorization_envelope: &files.envelope,
        signed_enrollment_receipt: &files.receipt,
        device_selection_confirmation: &files.selection,
        device_enrollment_binding: &files.binding,
    })
    .map_err(|error| format!("enrollment chain is invalid: {error}"))?;
    Ok((files, verified))
}

fn run_directory_name(ordinal: u8, suffix: &str) -> String {
    format!("run-{ordinal}-{suffix}")
}

fn run_files(root: &PrivateOutputRoot, ordinal: u8) -> Result<RunFiles, String> {
    let control_name = run_directory_name(ordinal, "control");
    let result_name = run_directory_name(ordinal, "result");
    let control = open_owner_directory(&root.directory, &control_name)?;
    let result = open_owner_directory(&root.directory, &result_name)?;
    exact_inventory(
        &control,
        &[RUN_ACK_NAME, RUN_ENVELOPE_NAME, RUN_INTENT_NAME],
    )?;
    exact_inventory(&result, &[RUN_EXPORT_NAME, RUN_BINDING_NAME])?;
    Ok(RunFiles {
        acknowledgement: read_private_artifact(&control, RUN_ACK_NAME, MAX_OPERATOR_INPUT_BYTES)?
            .bytes,
        envelope: read_private_artifact(&control, RUN_ENVELOPE_NAME, MAX_OPERATOR_INPUT_BYTES)?
            .bytes,
        intent: read_private_artifact(&control, RUN_INTENT_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes,
        export: read_private_artifact(&result, RUN_EXPORT_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes,
        binding: read_private_artifact(&result, RUN_BINDING_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes,
    })
}

fn verify_intent_source(root: &PrivateOutputRoot, intent_canonical: &[u8]) -> Result<(), String> {
    let intent = orchardprobe_core::lab002::artifacts::CollectionIntent::from_canonical_bytes(
        intent_canonical,
    )
    .map_err(|error| format!("collection intent is invalid: {error}"))?;
    let oracle_bytes = read_root_artifact(root, SOURCE_ORACLE_NAME)?;
    let evidence = read_root_artifact(root, SOURCE_EVIDENCE_NAME)?;
    let oracle = LabOracle::from_canonical_bytes(&oracle_bytes)
        .map_err(|error| format!("retained frozen oracle is invalid: {error}"))?;
    if intent.source_commit != oracle.source_commit
        || intent.marketing_version != oracle.marketing_version
        || intent.build_number != oracle.build_number
        || intent.observer_revision != oracle.observer_revision
        || intent.build_binding_sha256 != oracle.build_binding_sha256
        || intent.authorized_target_manifest_sha256 != oracle.authorized_target_manifest_sha256
        || intent.expected_target_identity_set_sha256 != oracle.target_identity_set_sha256
        || intent.toolchain != oracle.toolchain
        || intent.preupload_evidence_sha256 != sha256_hex(&evidence)
        || intent.ipa_sha256 != oracle.ipa_sha256
        || intent.oracle_sha256 != sha256_hex(&oracle_bytes)
        || intent.expected_inventory_sha256
            != expected_inventory_sha256(&oracle)
                .map_err(|error| format!("could not bind retained oracle inventory: {error}"))?
    {
        return Err("collection intent does not bind the retained frozen source tuple".into());
    }
    Ok(())
}

fn phase_exists(root: &PrivateOutputRoot, name: &str) -> Result<bool, String> {
    match rustix::fs::openat(
        &root.directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => {
            drop(file);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("could not inspect operator phase {name}: {error}")),
    }
}

fn next_run_ordinal(phases: (bool, bool, bool, bool)) -> Result<u8, String> {
    match phases {
        (false, false, false, false) => Ok(1),
        (true, true, false, false) => Ok(2),
        _ => Err("operator run phases are incomplete or already exhausted".into()),
    }
}

fn open_run_ordinal(phases: (bool, bool, bool, bool)) -> Result<u8, String> {
    match phases {
        (true, false, false, false) => Ok(1),
        (true, true, true, false) => Ok(2),
        _ => Err("there is no single open run to close".into()),
    }
}

fn experiment_id(root: &PrivateOutputRoot) -> Result<String, String> {
    let bytes = read_root_artifact(root, INSTALL_ACK_NAME)?;
    AuthorizationAcknowledgement::from_canonical_bytes(&bytes)
        .map(|value| value.experiment_id)
        .map_err(|error| format!("installation acknowledgement is invalid: {error}"))
}

fn start_enrollment(
    arguments: &[OsString],
    output_descriptor: File,
    prebuild_descriptor: File,
    candidate_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 19 {
        return Err("operator-start-enrollment requires exactly three bound directories".into());
    }
    let (output_path, output_identity) = parse_bound(arguments, 1, "--output-root")?;
    let (prebuild_path, prebuild_identity) = parse_bound(arguments, 7, "--prebuild-directory")?;
    let (candidate_path, candidate_identity) = parse_bound(arguments, 13, "--candidate-directory")?;
    let output = held_root(output_path, output_identity, output_descriptor)?;
    let prebuild = held_root(prebuild_path, prebuild_identity, prebuild_descriptor)?;
    let candidate = held_root(candidate_path, candidate_identity, candidate_descriptor)?;
    let request: StartEnrollmentRequest = read_request(io::stdin().lock())?;
    if request.schema != START_ENROLLMENT_SCHEMA {
        return Err("operator enrollment request schema is invalid".into());
    }
    let source = load_source_bundle(&prebuild, &candidate)?;
    let control = create_installation_control(
        &source.signing_key,
        &source.manifest,
        &source.build_binding_sha256,
        request.expected_environment,
        assertions(
            request.confirmed,
            request.owns_or_explicitly_authorized_target,
            request.within_authorized_scope,
            request.understands_legal_limits,
            request.will_protect_output_and_not_resign_install_or_redistribute,
        ),
        now()?,
        &mut OsRng,
    )
    .map_err(|error| format!("could not create installation control: {error}"))?;
    let acknowledgement =
        AuthorizationAcknowledgement::from_canonical_bytes(&control.acknowledgement)
            .map_err(|error| error.to_string())?;
    let final_name = format!("lab002-experiment-{}", acknowledgement.experiment_id);
    publish_prebuild_directory(
        &output,
        &final_name,
        &[
            (SOURCE_MANIFEST_NAME, &source.manifest),
            (SOURCE_ORACLE_NAME, &source.oracle),
            (SOURCE_EVIDENCE_NAME, &source.evidence),
            (INSTALL_ACK_NAME, &control.acknowledgement),
            (INSTALL_ENVELOPE_NAME, &control.authorization_envelope),
        ],
        &mut arm_publication,
    )?;
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: "control_published",
        phase: "installation_enrollment".into(),
        experiment_id: acknowledgement.experiment_id,
        run_ordinal: None,
        import_relative_path: Some(INSTALL_ENVELOPE_NAME.into()),
        device_selection_fingerprint_sha256: None,
        evidence_disposition: None,
    })
}

fn close_enrollment_phase(
    arguments: &[OsString],
    experiment_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 7 {
        return Err("operator-close-enrollment requires one bound experiment directory".into());
    }
    let (path, identity) = parse_bound(arguments, 1, "--experiment-directory")?;
    let root = held_root(path, identity, experiment_descriptor)?;
    exact_inventory(
        &root.directory,
        &[
            SOURCE_MANIFEST_NAME,
            SOURCE_ORACLE_NAME,
            SOURCE_EVIDENCE_NAME,
            INSTALL_ACK_NAME,
            INSTALL_ENVELOPE_NAME,
        ],
    )?;
    let (fingerprint, receipt) = read_fingerprint_and_receipt()?;
    let manifest = read_root_artifact(&root, SOURCE_MANIFEST_NAME)?;
    let acknowledgement = read_root_artifact(&root, INSTALL_ACK_NAME)?;
    let envelope = read_root_artifact(&root, INSTALL_ENVELOPE_NAME)?;
    let (closure, verified) = close_enrollment(
        &manifest,
        &acknowledgement,
        &envelope,
        &receipt,
        &fingerprint,
        now()?,
    )
    .map_err(|error| format!("could not close enrollment: {error}"))?;
    publish_prebuild_directory(
        &root,
        ENROLLMENT_RESULT_DIRECTORY,
        &[
            (RECEIPT_NAME, &receipt),
            (SELECTION_NAME, &closure.device_selection_confirmation),
            (ENROLLMENT_BINDING_NAME, &closure.device_enrollment_binding),
        ],
        &mut arm_publication,
    )?;
    let binding = DeviceEnrollmentBinding::from_canonical_bytes(&closure.device_enrollment_binding)
        .map_err(|error| error.to_string())?;
    drop(verified);
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: "enrollment_closed",
        phase: "installation_enrollment".into(),
        experiment_id: binding.experiment_id,
        run_ordinal: None,
        import_relative_path: None,
        device_selection_fingerprint_sha256: Some(fingerprint),
        evidence_disposition: None,
    })
}

fn start_run(
    arguments: &[OsString],
    experiment_descriptor: File,
    prebuild_descriptor: File,
    candidate_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 19 {
        return Err(
            "operator-start-run requires bound experiment, prebuild, and candidate directories"
                .into(),
        );
    }
    let (experiment_path, experiment_identity) =
        parse_bound(arguments, 1, "--experiment-directory")?;
    let (prebuild_path, prebuild_identity) = parse_bound(arguments, 7, "--prebuild-directory")?;
    let (candidate_path, candidate_identity) = parse_bound(arguments, 13, "--candidate-directory")?;
    let root = held_root(experiment_path, experiment_identity, experiment_descriptor)?;
    let prebuild = held_root(prebuild_path, prebuild_identity, prebuild_descriptor)?;
    let candidate = held_root(candidate_path, candidate_identity, candidate_descriptor)?;
    let request: StartRunRequest = read_request(io::stdin().lock())?;
    if request.schema != START_RUN_SCHEMA {
        return Err("operator run request schema is invalid".into());
    }
    let (_, enrollment) = verified_enrollment(&root)?;
    let source = verify_retained_source_bundle(&root, &prebuild, &candidate)?;
    let run_one_control = phase_exists(&root, &run_directory_name(1, "control"))?;
    let run_one_result = phase_exists(&root, &run_directory_name(1, "result"))?;
    let run_two_control = phase_exists(&root, &run_directory_name(2, "control"))?;
    let run_two_result = phase_exists(&root, &run_directory_name(2, "result"))?;
    let phase_state = (
        run_one_control,
        run_one_result,
        run_two_control,
        run_two_result,
    );
    let ordinal = next_run_ordinal(phase_state)?;
    let phases = if ordinal == 1 {
        vec![ENROLLMENT_RESULT_DIRECTORY.to_owned()]
    } else {
        vec![
            ENROLLMENT_RESULT_DIRECTORY.to_owned(),
            run_directory_name(1, "control"),
            run_directory_name(1, "result"),
        ]
    };
    exact_experiment_inventory(&root, &phases)?;
    let prior_run = if ordinal == 2 {
        let run_one = run_files(&root, 1)?;
        verify_intent_source(&root, &run_one.intent)?;
        Some(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    frozen_oracle: &source.oracle,
                    run_acknowledgement: &run_one.acknowledgement,
                    authorization_envelope: &run_one.envelope,
                    collection_intent: &run_one.intent,
                    signed_session_export: &run_one.export,
                    collection_binding: &run_one.binding,
                },
            )
            .map_err(|error| format!("run 1 chain is invalid before run 2: {error}"))?,
        )
    } else {
        None
    };
    let control = create_run_control(
        &source.signing_key,
        &enrollment,
        &source.oracle,
        RunControlRequest {
            preupload_evidence_sha256: sha256_hex(&source.evidence),
            run_ordinal: ordinal,
            prior_run: prior_run.as_ref(),
            assertions: assertions(
                request.confirmed,
                request.owns_or_explicitly_authorized_target,
                request.within_authorized_scope,
                request.understands_legal_limits,
                request.will_protect_output_and_not_resign_install_or_redistribute,
            ),
            acknowledged_at: now()?,
        },
        &mut OsRng,
    )
    .map_err(|error| format!("could not create run control: {error}"))?;
    let phase = run_directory_name(ordinal, "control");
    publish_prebuild_directory(
        &root,
        &phase,
        &[
            (RUN_ACK_NAME, &control.acknowledgement),
            (RUN_ENVELOPE_NAME, &control.authorization_envelope),
            (RUN_INTENT_NAME, &control.collection_intent),
        ],
        &mut arm_publication,
    )?;
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: "control_published",
        phase: format!("run_{ordinal}"),
        experiment_id: experiment_id(&root)?,
        run_ordinal: Some(ordinal),
        import_relative_path: Some(format!("{phase}/{RUN_ENVELOPE_NAME}")),
        device_selection_fingerprint_sha256: None,
        evidence_disposition: None,
    })
}

fn close_run_phase(
    arguments: &[OsString],
    experiment_descriptor: File,
    prebuild_descriptor: File,
    candidate_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 19 {
        return Err(
            "operator-close-run requires bound experiment, prebuild, and candidate directories"
                .into(),
        );
    }
    let (path, identity) = parse_bound(arguments, 1, "--experiment-directory")?;
    let (prebuild_path, prebuild_identity) = parse_bound(arguments, 7, "--prebuild-directory")?;
    let (candidate_path, candidate_identity) = parse_bound(arguments, 13, "--candidate-directory")?;
    let root = held_root(path, identity, experiment_descriptor)?;
    let prebuild = held_root(prebuild_path, prebuild_identity, prebuild_descriptor)?;
    let candidate = held_root(candidate_path, candidate_identity, candidate_descriptor)?;
    let source = verify_retained_source_bundle(&root, &prebuild, &candidate)?;
    let one_control_name = run_directory_name(1, "control");
    let one_result_name = run_directory_name(1, "result");
    let two_control_name = run_directory_name(2, "control");
    let (_, enrollment) = verified_enrollment(&root)?;
    let one_control = phase_exists(&root, &run_directory_name(1, "control"))?;
    let one_result = phase_exists(&root, &run_directory_name(1, "result"))?;
    let two_control = phase_exists(&root, &run_directory_name(2, "control"))?;
    let two_result = phase_exists(&root, &run_directory_name(2, "result"))?;
    let ordinal = open_run_ordinal((one_control, one_result, two_control, two_result))?;
    let phases = if ordinal == 1 {
        vec![ENROLLMENT_RESULT_DIRECTORY.to_owned(), one_control_name]
    } else {
        vec![
            ENROLLMENT_RESULT_DIRECTORY.to_owned(),
            one_control_name,
            one_result_name,
            two_control_name,
        ]
    };
    exact_experiment_inventory(&root, &phases)?;
    let control_name = run_directory_name(ordinal, "control");
    let control_directory = open_owner_directory(&root.directory, &control_name)?;
    exact_inventory(
        &control_directory,
        &[RUN_ACK_NAME, RUN_ENVELOPE_NAME, RUN_INTENT_NAME],
    )?;
    let acknowledgement =
        read_private_artifact(&control_directory, RUN_ACK_NAME, MAX_OPERATOR_INPUT_BYTES)?.bytes;
    let envelope = read_private_artifact(
        &control_directory,
        RUN_ENVELOPE_NAME,
        MAX_OPERATOR_INPUT_BYTES,
    )?
    .bytes;
    let intent = read_private_artifact(
        &control_directory,
        RUN_INTENT_NAME,
        MAX_OPERATOR_INPUT_BYTES,
    )?
    .bytes;
    verify_intent_source(&root, &intent)?;
    let export = read_raw(MAX_OPERATOR_INPUT_BYTES)?;
    let (closure, verified_run) = close_run(
        &enrollment,
        &source.oracle,
        &acknowledgement,
        &envelope,
        &intent,
        &export,
        now()?,
    )
    .map_err(|error| format!("could not close run {ordinal}: {error}"))?;
    let result_name = run_directory_name(ordinal, "result");
    publish_prebuild_directory(
        &root,
        &result_name,
        &[
            (RUN_EXPORT_NAME, &export),
            (RUN_BINDING_NAME, &closure.collection_binding),
        ],
        &mut arm_publication,
    )?;
    let evidence_disposition = if ordinal == 2 {
        let run_one = run_files(&root, 1)?;
        let verified_one = verify_run_chain(
            &enrollment,
            RunArtifactBytes {
                frozen_oracle: &source.oracle,
                run_acknowledgement: &run_one.acknowledgement,
                authorization_envelope: &run_one.envelope,
                collection_intent: &run_one.intent,
                signed_session_export: &run_one.export,
                collection_binding: &run_one.binding,
            },
        )
        .map_err(|error| format!("run 1 chain changed before final verification: {error}"))?;
        Some(
            verify_two_run_chain(&enrollment, &verified_one, &verified_run)
                .map_err(|error| format!("final two-run chain is invalid: {error}"))?
                .evidence_disposition()
                .as_str(),
        )
    } else {
        None
    };
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: if ordinal == 2 {
            "two_run_chain_closed"
        } else {
            "run_closed"
        },
        phase: format!("run_{ordinal}"),
        experiment_id: experiment_id(&root)?,
        run_ordinal: Some(ordinal),
        import_relative_path: None,
        device_selection_fingerprint_sha256: None,
        evidence_disposition,
    })
}

fn verify_complete(
    arguments: &[OsString],
    experiment_descriptor: File,
    prebuild_descriptor: File,
    candidate_descriptor: File,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 19 {
        return Err(
            "operator-verify requires bound experiment, prebuild, and candidate directories".into(),
        );
    }
    let (path, identity) = parse_bound(arguments, 1, "--experiment-directory")?;
    let (prebuild_path, prebuild_identity) = parse_bound(arguments, 7, "--prebuild-directory")?;
    let (candidate_path, candidate_identity) = parse_bound(arguments, 13, "--candidate-directory")?;
    let root = held_root(path, identity, experiment_descriptor)?;
    let prebuild = held_root(prebuild_path, prebuild_identity, prebuild_descriptor)?;
    let candidate = held_root(candidate_path, candidate_identity, candidate_descriptor)?;
    let source = verify_retained_source_bundle(&root, &prebuild, &candidate)?;
    exact_experiment_inventory(
        &root,
        &[
            ENROLLMENT_RESULT_DIRECTORY.to_owned(),
            run_directory_name(1, "control"),
            run_directory_name(1, "result"),
            run_directory_name(2, "control"),
            run_directory_name(2, "result"),
        ],
    )?;
    let (_, enrollment) = verified_enrollment(&root)?;
    let one = run_files(&root, 1)?;
    let two = run_files(&root, 2)?;
    verify_intent_source(&root, &one.intent)?;
    verify_intent_source(&root, &two.intent)?;
    let verified_one = verify_run_chain(
        &enrollment,
        RunArtifactBytes {
            frozen_oracle: &source.oracle,
            run_acknowledgement: &one.acknowledgement,
            authorization_envelope: &one.envelope,
            collection_intent: &one.intent,
            signed_session_export: &one.export,
            collection_binding: &one.binding,
        },
    )
    .map_err(|error| format!("run 1 chain is invalid: {error}"))?;
    let verified_two = verify_run_chain(
        &enrollment,
        RunArtifactBytes {
            frozen_oracle: &source.oracle,
            run_acknowledgement: &two.acknowledgement,
            authorization_envelope: &two.envelope,
            collection_intent: &two.intent,
            signed_session_export: &two.export,
            collection_binding: &two.binding,
        },
    )
    .map_err(|error| format!("run 2 chain is invalid: {error}"))?;
    let evidence_disposition = verify_two_run_chain(&enrollment, &verified_one, &verified_two)
        .map_err(|error| format!("two-run chain is invalid: {error}"))?
        .evidence_disposition()
        .as_str();
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: "two_run_chain_verified",
        phase: "complete".into(),
        experiment_id: experiment_id(&root)?,
        run_ordinal: None,
        import_relative_path: None,
        device_selection_fingerprint_sha256: None,
        evidence_disposition: Some(evidence_disposition),
    })
}

pub(super) fn execute(
    arguments: &[OsString],
    output_descriptor: File,
    secondary_descriptor: Option<File>,
    candidate_descriptor: Option<File>,
    arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    match arguments.first().and_then(|value| value.to_str()) {
        Some("operator-start-enrollment") => start_enrollment(
            arguments,
            output_descriptor,
            secondary_descriptor.ok_or("held prebuild directory is missing")?,
            candidate_descriptor.ok_or("held candidate directory is missing")?,
            arm_publication,
        ),
        Some("operator-close-enrollment") => {
            close_enrollment_phase(arguments, output_descriptor, arm_publication)
        }
        Some("operator-start-run") => start_run(
            arguments,
            output_descriptor,
            secondary_descriptor.ok_or("held prebuild directory is missing")?,
            candidate_descriptor.ok_or("held candidate directory is missing")?,
            arm_publication,
        ),
        Some("operator-close-run") => close_run_phase(
            arguments,
            output_descriptor,
            secondary_descriptor.ok_or("held prebuild directory is missing")?,
            candidate_descriptor.ok_or("held candidate directory is missing")?,
            arm_publication,
        ),
        Some("operator-verify") => verify_complete(
            arguments,
            output_descriptor,
            secondary_descriptor.ok_or("held prebuild directory is missing")?,
            candidate_descriptor.ok_or("held candidate directory is missing")?,
        ),
        _ => Err("unknown LAB-002 operator command".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Cursor, Write};

    use ed25519_dalek::SigningKey;
    use orchardprobe_core::lab002::artifacts::{
        AuthorizedTarget, AuthorizedTargetManifest, ClosedArtifact, Presence, RequiredAppGroups,
        RequiredEntitlement, Toolchain,
    };
    use orchardprobe_core::lab002::{LAB002_PROFILE, LabRole};
    use serde_json::{Value, json};
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::{
        EvidenceArtifactIdentity, MANIFEST_NAME, PreuploadEvidence, RUN_ACK_NAME,
        RUN_ENVELOPE_NAME, RUN_INTENT_NAME, SourceBundle, UploadResult, derive_prebuild_bindings,
        exact_inventory, has_exact_derived_prebuild_bindings, next_run_ordinal, open_run_ordinal,
        require_retained_source_match, require_unchanged_source_artifact,
        split_fingerprint_and_receipt, valid_upload_result, validate_evidence_artifact,
        verify_frozen_archive, verify_frozen_ipa_entries,
    };

    fn test_ipa() -> (Vec<u8>, Vec<Vec<u8>>) {
        let payloads = vec![
            b"main executable".to_vec(),
            b"framework".to_vec(),
            b"share".to_vec(),
        ];
        let paths = [
            "Payload/DemoLab.app/DemoLab",
            "Payload/DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
            "Payload/DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
        ];
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let directory_options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o755);
        for directory in [
            "Payload/",
            "Payload/DemoLab.app/",
            "Payload/DemoLab.app/Frameworks/",
            "Payload/DemoLab.app/Frameworks/DemoFramework.framework/",
            "Payload/DemoLab.app/PlugIns/",
            "Payload/DemoLab.app/PlugIns/DemoShareExtension.appex/",
        ] {
            writer.add_directory(directory, directory_options).unwrap();
        }
        let file_options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o755);
        for (path, bytes) in paths.into_iter().zip(&payloads) {
            writer.start_file(path, file_options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        (writer.finish().unwrap().into_inner(), payloads)
    }

    fn complete_evidence_json() -> Value {
        let archive_binary = |role: &str, relative_path: &str| {
            json!({
                "role": role,
                "relative_path": relative_path,
                "size": 1,
                "sha256": "11".repeat(32),
                "architectures": ["arm64"],
                "slices": [{
                    "architecture": "arm64",
                    "uuid": "11111111-1111-1111-1111-111111111111"
                }],
                "initial_protection_status": "not_observed",
                "expected_plaintext_status": "candidate_pre_upload_archive_only"
            })
        };
        let ipa_binary = |role: &str, relative_path: &str| {
            json!({
                "role": role,
                "relative_path": relative_path,
                "size": 1,
                "sha256": "22".repeat(32),
                "initial_protection_status": "not_observed",
                "expected_plaintext_status": "candidate_pre_upload_archive_only"
            })
        };
        let specs = [
            ("main_executable", "DemoLab.app/DemoLab"),
            (
                "dynamic_framework",
                "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
            ),
            (
                "app_extension",
                "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
            ),
        ];
        json!({
            "schema_version": 1,
            "profile": "orchardprobe.demolab.testflight-preupload.v1",
            "purpose": "LAB-001 controlled first-party TestFlight preparation",
            "decision": "pending_controlled_device_observation",
            "created_at": "2026-07-31T12:00:00Z",
            "source": {"commit": "11".repeat(20), "tree_clean": true, "fixture": "fixtures/DemoLab"},
            "toolchain": {
                "fastlane_version": "2.228.0",
                "xcodegen_version": "2.46.0",
                "xcode": ["Xcode 26.0\n", "Build version 17A100\n"],
                "iphoneos_sdk_version": "26.0",
                "iphoneos_sdk_build": "23A100"
            },
            "build": {
                "configuration": "Release",
                "marketing_version": "1.0",
                "build_number": "3",
                "distribution": "app-store",
                "bundle_identifiers": "operator-provided first-party identifiers; redacted"
            },
            "artifacts": {
                "ipa": {"filename": "DemoLab-3.ipa", "size": 1, "sha256": "33".repeat(32)},
                "archive_binaries": specs.iter().map(|(role, path)| archive_binary(role, path)).collect::<Vec<_>>(),
                "package": {"application": "DemoLab.app", "identity_validated": true, "export_compliance_validated": true},
                "ipa_binaries": specs.iter().map(|(role, path)| ipa_binary(role, path)).collect::<Vec<_>>()
            },
            "lab002": {
                "build_binding_sha256": "44".repeat(32),
                "target_identity_set_sha256": "55".repeat(32),
                "authorized_target_manifest": {"name": "lab-002-authorized-targets-v1.json", "device": "1", "inode": "2", "mode": 256, "size": 1, "sha256": "66".repeat(32)},
                "oracle": {"name": "lab-002-oracle-v1.json", "device": "1", "inode": "3", "mode": 256, "size": 1, "sha256": "77".repeat(32)}
            },
            "lineage": {
                "uploaded_ipa_bound": false,
                "installed_artifact_bound": false,
                "note": "Pre-upload bytes are candidates, not proof of installed plaintext."
            }
        })
    }

    fn target(role: LabRole, suffix: &str, app_group: bool) -> AuthorizedTarget {
        let team = "ABCDEFGHIJ";
        let bundle_id = format!("com.example.demolab.{suffix}");
        AuthorizedTarget {
            role,
            bundle_id: bundle_id.clone(),
            code_directory_identifier: bundle_id.clone(),
            code_directory_team_identifier: team.into(),
            application_identifier: if app_group {
                RequiredEntitlement {
                    presence: Presence::Present,
                    value: Some(format!("{team}.{bundle_id}")),
                }
            } else {
                RequiredEntitlement {
                    presence: Presence::RequiredAbsent,
                    value: None,
                }
            },
            developer_team_identifier: if app_group {
                RequiredEntitlement {
                    presence: Presence::Present,
                    value: Some(team.into()),
                }
            } else {
                RequiredEntitlement {
                    presence: Presence::RequiredAbsent,
                    value: None,
                }
            },
            application_groups: if app_group {
                RequiredAppGroups {
                    presence: Presence::Present,
                    values: Some(vec!["group.com.example.demolab".into()]),
                }
            } else {
                RequiredAppGroups {
                    presence: Presence::RequiredAbsent,
                    values: None,
                }
            },
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            xcode_version: "26.0".into(),
            xcode_build: "17A100".into(),
            iphoneos_sdk_version: "26.0".into(),
            iphoneos_sdk_build: "23A100".into(),
            xcodegen_version: "2.46.0".into(),
            xcodegen_architecture: "arm64".into(),
            xcodegen_executable_sha256: "22".repeat(32),
            fastlane_version: "2.228.0".into(),
            gemfile_lock_sha256: "33".repeat(32),
        }
    }

    fn phase_states() -> impl Iterator<Item = (bool, bool, bool, bool)> {
        (0_u8..16).map(|bits| (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0))
    }

    #[test]
    fn run_state_machine_accepts_only_the_next_closed_transition() {
        for state in phase_states() {
            let start = next_run_ordinal(state).ok();
            let close = open_run_ordinal(state).ok();
            assert_eq!(
                start,
                match state {
                    (false, false, false, false) => Some(1),
                    (true, true, false, false) => Some(2),
                    _ => None,
                }
            );
            assert_eq!(
                close,
                match state {
                    (true, false, false, false) => Some(1),
                    (true, true, true, false) => Some(2),
                    _ => None,
                }
            );
        }
    }

    #[test]
    fn control_phase_inventory_rejects_an_unaccounted_entry() {
        let temporary = tempdir().unwrap();
        for name in [RUN_ACK_NAME, RUN_ENVELOPE_NAME, RUN_INTENT_NAME] {
            File::create(temporary.path().join(name)).unwrap();
        }
        let directory = File::open(temporary.path()).unwrap();
        let expected = [RUN_ACK_NAME, RUN_ENVELOPE_NAME, RUN_INTENT_NAME];
        assert!(exact_inventory(&directory, &expected).is_ok());

        File::create(temporary.path().join("unexpected.json")).unwrap();
        assert!(exact_inventory(&directory, &expected).is_err());
    }

    #[test]
    fn fingerprint_frame_requires_full_lowercase_value_and_nonempty_receipt() {
        let fingerprint = "ab".repeat(32);
        let framed = format!("{fingerprint}\nreceipt");
        assert_eq!(
            split_fingerprint_and_receipt(framed.as_bytes()).unwrap(),
            (fingerprint, b"receipt".to_vec())
        );
        assert!(split_fingerprint_and_receipt(b"abcd\nreceipt").is_err());
        assert!(
            split_fingerprint_and_receipt(format!("{}\nreceipt", "AB".repeat(32)).as_bytes())
                .is_err()
        );
        assert!(
            split_fingerprint_and_receipt(format!("{}\n", "ab".repeat(32)).as_bytes()).is_err()
        );
    }

    #[test]
    fn retained_source_match_includes_preupload_evidence_bytes() {
        let source = SourceBundle {
            signing_key: SigningKey::from_bytes(&[7; 32]),
            manifest: b"manifest".to_vec(),
            oracle: b"oracle".to_vec(),
            evidence: b"evidence".to_vec(),
            build_binding_sha256: "11".repeat(32),
        };
        assert!(
            require_retained_source_match(&source, b"manifest", b"oracle", b"evidence").is_ok()
        );
        assert!(
            require_retained_source_match(&source, b"manifest", b"oracle", b"replacement").is_err()
        );
    }

    #[test]
    fn frozen_source_revalidation_rejects_byte_and_identity_replacement() {
        let expected = super::super::ReadPrivateArtifact {
            bytes: b"original".to_vec(),
            device: 17,
            inode: 29,
            owner: 501,
            mode: 0o400,
            size: 8,
            modified_seconds: 1,
            modified_nanoseconds: 2,
        };
        assert!(require_unchanged_source_artifact(expected.clone(), &expected, "source").is_ok());

        let mut changed_bytes = expected.clone();
        changed_bytes.bytes = b"replaced".to_vec();
        assert!(require_unchanged_source_artifact(changed_bytes, &expected, "source").is_err());

        let mut changed_identity = expected.clone();
        changed_identity.inode += 1;
        assert!(require_unchanged_source_artifact(changed_identity, &expected, "source").is_err());
    }

    #[test]
    fn preupload_evidence_requires_every_closed_field_and_rejects_unknown_fields() {
        let complete = complete_evidence_json();
        assert!(serde_json::from_value::<PreuploadEvidence>(complete.clone()).is_ok());

        let mut missing_export = complete.clone();
        missing_export["artifacts"]["package"]
            .as_object_mut()
            .unwrap()
            .remove("export_compliance_validated");
        assert!(serde_json::from_value::<PreuploadEvidence>(missing_export).is_err());

        let mut missing_archive_digest = complete.clone();
        missing_archive_digest["artifacts"]["archive_binaries"][0]
            .as_object_mut()
            .unwrap()
            .remove("sha256");
        assert!(serde_json::from_value::<PreuploadEvidence>(missing_archive_digest).is_err());

        let mut missing_lineage = complete.clone();
        missing_lineage.as_object_mut().unwrap().remove("lineage");
        assert!(serde_json::from_value::<PreuploadEvidence>(missing_lineage).is_err());

        let mut unknown = complete;
        unknown["source"]["replacement"] = json!(true);
        assert!(serde_json::from_value::<PreuploadEvidence>(unknown).is_err());
    }

    #[test]
    fn preupload_evidence_artifact_identity_must_match_the_held_descriptor() {
        let digest = "ab".repeat(32);
        let artifact = EvidenceArtifactIdentity {
            name: MANIFEST_NAME.into(),
            device: "17".into(),
            inode: "29".into(),
            mode: 0o400,
            size: 512,
            sha256: digest.clone(),
        };
        assert!(validate_evidence_artifact(&artifact, MANIFEST_NAME, 17, 29, 512, &digest).is_ok());
        assert!(
            validate_evidence_artifact(&artifact, MANIFEST_NAME, 18, 29, 512, &digest).is_err()
        );
        assert!(
            validate_evidence_artifact(&artifact, MANIFEST_NAME, 17, 30, 512, &digest).is_err()
        );
    }

    #[test]
    fn upload_audit_accepts_only_closed_indeterminate_or_terminal_success_records() {
        let base = json!({
            "schema_version": 1,
            "source_commit": "11".repeat(20),
            "ipa_sha256": "22".repeat(32),
            "attempt_started_at": "2026-07-31T12:00:00Z",
            "destination": "TestFlight internal preparation",
            "external_distribution": false,
            "status": "indeterminate",
            "note": super::UPLOAD_INDETERMINATE_NOTE
        });
        let indeterminate: UploadResult = serde_json::from_value(base.clone()).unwrap();
        assert!(valid_upload_result(&indeterminate));

        let mut accepted = base.clone();
        accepted["status"] = json!("accepted");
        accepted["uploaded_at"] = json!("2026-07-31T12:01:00Z");
        accepted["note"] = json!(super::UPLOAD_ACCEPTED_NOTE);
        let accepted: UploadResult = serde_json::from_value(accepted).unwrap();
        assert!(valid_upload_result(&accepted));

        let mut success_without_time = base.clone();
        success_without_time["status"] = json!("accepted");
        success_without_time["note"] = json!(super::UPLOAD_ACCEPTED_NOTE);
        let success_without_time: UploadResult =
            serde_json::from_value(success_without_time).unwrap();
        assert!(!valid_upload_result(&success_without_time));

        let mut indeterminate_with_time = base;
        indeterminate_with_time["uploaded_at"] = json!("2026-07-31T12:01:00Z");
        let indeterminate_with_time: UploadResult =
            serde_json::from_value(indeterminate_with_time).unwrap();
        assert!(!valid_upload_result(&indeterminate_with_time));
    }

    #[test]
    fn frozen_archive_cannot_be_an_empty_owned_directory() {
        let temporary = tempdir().unwrap();
        let candidate_path = temporary.path().join("candidate");
        fs::create_dir(&candidate_path).unwrap();
        fs::create_dir_all(
            candidate_path.join("DemoLab.xcarchive/Products/Applications/DemoLab.app"),
        )
        .unwrap();
        let candidate = super::super::PrivateOutputRoot {
            canonical_path: candidate_path.clone(),
            directory: File::open(candidate_path).unwrap(),
        };
        let evidence: PreuploadEvidence = serde_json::from_value(complete_evidence_json()).unwrap();
        assert!(verify_frozen_archive(&candidate, &evidence).is_err());
    }

    #[test]
    fn frozen_ipa_entries_must_match_their_claimed_sizes_and_hashes() {
        let (ipa, payloads) = test_ipa();
        let mut evidence: PreuploadEvidence =
            serde_json::from_value(complete_evidence_json()).unwrap();
        for (binary, bytes) in evidence.artifacts.ipa_binaries.iter_mut().zip(&payloads) {
            binary.size = bytes.len() as u64;
            binary.sha256 = super::sha256_hex(bytes);
        }
        assert!(verify_frozen_ipa_entries(&ipa, ipa.len() as u64, &evidence).is_ok());

        evidence.artifacts.ipa_binaries[0].sha256 = "ee".repeat(32);
        assert!(verify_frozen_ipa_entries(&ipa, ipa.len() as u64, &evidence).is_err());
    }

    #[test]
    fn prebuild_bindings_are_recomputed_from_manifest_metadata_and_toolchain() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let manifest = AuthorizedTargetManifest {
            schema: <AuthorizedTargetManifest as ClosedArtifact>::SCHEMA.into(),
            profile: LAB002_PROFILE.into(),
            identity_nonce: "44".repeat(32),
            authorization_public_key: super::lower_hex(signing_key.verifying_key().as_bytes()),
            authorization_key_id: super::sha256_hex(signing_key.verifying_key().as_bytes()),
            targets: vec![
                target(LabRole::MainApp, "app", true),
                target(LabRole::Framework, "framework", false),
                target(LabRole::ShareExtension, "share", true),
            ],
        };
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let manifest_sha256 = super::sha256_hex(&manifest_bytes);
        let mut record = super::super::PrebuildRecord {
            schema: super::super::PREBUILD_SCHEMA.into(),
            profile: LAB002_PROFILE.into(),
            source_commit: "11".repeat(20),
            fixture_source_root: "fixtures/DemoLab".into(),
            marketing_version: "1.0".into(),
            build_number: "3".into(),
            configuration: "Release".into(),
            observer_revision: "lab002-observer-v1".into(),
            generator_revision: "11".repeat(20),
            identity_nonce: manifest.identity_nonce.clone(),
            authorization_public_key: manifest.authorization_public_key.clone(),
            authorization_key_id: manifest.authorization_key_id.clone(),
            authorized_target_manifest_sha256: manifest_sha256.clone(),
            build_binding_sha256: "00".repeat(32),
            target_identity_set_sha256: "00".repeat(32),
            toolchain: toolchain(),
            targets: Vec::new(),
        };
        let derived = derive_prebuild_bindings(&manifest, &manifest_sha256, &record).unwrap();
        record.build_binding_sha256 = derived.build_binding_sha256.clone();
        record.target_identity_set_sha256 = derived.target_identity_set_sha256.clone();
        record.targets = derived.targets.clone();
        assert!(has_exact_derived_prebuild_bindings(&record, &derived));

        record.build_binding_sha256 = "55".repeat(32);
        assert!(!has_exact_derived_prebuild_bindings(&record, &derived));
        record.build_binding_sha256 = derived.build_binding_sha256.clone();
        record.targets.swap(0, 1);
        assert!(!has_exact_derived_prebuild_bindings(&record, &derived));

        record.targets = derived.targets.clone();
        record.toolchain.xcode_version = "26.1".into();
        let changed = derive_prebuild_bindings(&manifest, &manifest_sha256, &record).unwrap();
        assert!(!has_exact_derived_prebuild_bindings(&record, &changed));
    }
}
