use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use orchardprobe_core::lab002::LAB002_PROFILE;
use orchardprobe_core::lab002::artifacts::{
    AuthorizationAcknowledgement, AuthorizedTargetManifest, ClosedArtifact,
    DeviceEnrollmentBinding, Environment, LabOracle,
};
use orchardprobe_core::lab002::host::{
    EnrollmentArtifactBytes, RunArtifactBytes, verify_enrollment_chain, verify_run_chain,
    verify_two_run_chain,
};
use orchardprobe_core::lab002::operator::{
    AuthorizationAssertions, RunControlRequest, close_enrollment, close_run,
    create_installation_control, create_run_control, expected_inventory_sha256,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    destination: String,
    external_distribution: bool,
    status: String,
    note: String,
}

struct SourceBundle {
    signing_key: SigningKey,
    manifest: Vec<u8>,
    oracle: Vec<u8>,
    evidence: Vec<u8>,
    build_binding_sha256: String,
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

fn value_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("pre-upload evidence field {pointer} is missing"))
}

fn value_u64(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("pre-upload evidence field {pointer} is missing"))
}

fn private_seed_and_record(
    prebuild: &PrivateOutputRoot,
) -> Result<(SigningKey, Vec<u8>, super::PrebuildRecord), String> {
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
        || record_value.authorized_target_manifest_sha256 != sha256_hex(&manifest.bytes)
        || record_value.authorization_public_key != manifest_value.authorization_public_key
        || record_value.authorization_key_id != manifest_value.authorization_key_id
        || !is_lower_hex(&record_value.build_binding_sha256, 64)
        || !is_lower_hex(&record_value.target_identity_set_sha256, 64)
        || manifest_value.authorization_public_key
            != lower_hex(signing_key.verifying_key().as_bytes())
    {
        return Err("private prebuild tuple is inconsistent".into());
    }
    Ok((signing_key, manifest.bytes, record_value))
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

fn load_source_bundle(
    prebuild: &PrivateOutputRoot,
    candidate: &PrivateOutputRoot,
) -> Result<SourceBundle, String> {
    let (signing_key, manifest, record) = private_seed_and_record(prebuild)?;
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
    let evidence_value: Value = serde_json::from_slice(&evidence.bytes)
        .map_err(|error| format!("pre-upload evidence is invalid: {error}"))?;
    let upload_value: UploadResult = serde_json::from_slice(&upload.bytes)
        .map_err(|error| format!("upload audit record is invalid: {error}"))?;
    let evidence_oracle_sha = value_string(&evidence_value, "/lab002/oracle/sha256")?;
    let evidence_manifest_sha =
        value_string(&evidence_value, "/lab002/authorized_target_manifest/sha256")?;
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
    if evidence_value.get("schema_version").and_then(Value::as_u64) != Some(1)
        || value_string(&evidence_value, "/profile")?
            != "orchardprobe.demolab.testflight-preupload.v1"
        || value_string(&evidence_value, "/purpose")?
            != "LAB-001 controlled first-party TestFlight preparation"
        || value_string(&evidence_value, "/decision")? != "pending_controlled_device_observation"
        || evidence_value
            .pointer("/source/tree_clean")
            .and_then(Value::as_bool)
            != Some(true)
        || value_string(&evidence_value, "/source/commit")? != record.source_commit
        || value_string(&evidence_value, "/source/fixture")? != record.fixture_source_root
        || value_string(&evidence_value, "/build/marketing_version")?
            != CHECKPOINT_MARKETING_VERSION
        || value_string(&evidence_value, "/build/build_number")? != CHECKPOINT_BUILD_NUMBER
        || value_string(&evidence_value, "/build/configuration")? != "Release"
        || value_string(&evidence_value, "/build/distribution")? != "app-store"
        || value_string(&evidence_value, "/toolchain/fastlane_version")?
            != record.toolchain.fastlane_version
        || value_string(&evidence_value, "/toolchain/xcodegen_version")?
            != record.toolchain.xcodegen_version
        || value_string(&evidence_value, "/toolchain/xcode")? != record.toolchain.xcode_version
        || value_string(&evidence_value, "/toolchain/iphoneos_sdk_version")?
            != record.toolchain.iphoneos_sdk_version
        || value_string(&evidence_value, "/toolchain/iphoneos_sdk_build")?
            != record.toolchain.iphoneos_sdk_build
        || value_string(&evidence_value, "/lab002/build_binding_sha256")?
            != record.build_binding_sha256
        || value_string(&evidence_value, "/lab002/target_identity_set_sha256")?
            != record.target_identity_set_sha256
        || evidence_manifest_sha != sha256_hex(&manifest)
        || evidence_oracle_sha != sha256_hex(&oracle.bytes)
        || value_string(&evidence_value, "/artifacts/ipa/filename")? != "DemoLab-3.ipa"
        || value_string(&evidence_value, "/artifacts/ipa/sha256")? != sha256_hex(&ipa.bytes)
        || value_u64(&evidence_value, "/artifacts/ipa/size")? != ipa.size
        || oracle_value.profile != record.profile
        || oracle_value.source_commit != record.source_commit
        || oracle_value.fixture_source_root != record.fixture_source_root
        || oracle_value.marketing_version != record.marketing_version
        || oracle_value.build_number != record.build_number
        || oracle_value.configuration != record.configuration
        || oracle_value.observer_revision != record.observer_revision
        || oracle_value.generator_revision != record.generator_revision
        || oracle_value.build_binding_sha256 != record.build_binding_sha256
        || oracle_value.authorized_target_manifest_sha256 != sha256_hex(&manifest)
        || oracle_value.authorization_public_key != record.authorization_public_key
        || oracle_value.authorization_key_id != record.authorization_key_id
        || oracle_value.authorization_public_key
            != lower_hex(signing_key.verifying_key().as_bytes())
        || oracle_value.target_identity_set_sha256 != record.target_identity_set_sha256
        || !oracle_targets_match
        || oracle_value.toolchain != record.toolchain
        || oracle_value.ipa_size != ipa.size
        || oracle_value.ipa_sha256 != sha256_hex(&ipa.bytes)
        || upload_value.schema_version != 1
        || upload_value.source_commit != record.source_commit
        || upload_value.ipa_sha256 != oracle_value.ipa_sha256
        || !is_bounded_utc_timestamp(&upload_value.attempt_started_at)
        || upload_value.destination != "TestFlight internal preparation"
        || upload_value.external_distribution
        || upload_value.status != "indeterminate"
        || upload_value.note
            != "Reconcile this build in App Store Connect before retrying; the upload may succeed even if Apple altool later exits with an error."
    {
        return Err("frozen candidate, oracle, evidence, upload audit, and prebuild are not one exact tuple".into());
    }
    if !is_lower_hex(&record.build_binding_sha256, 64) {
        return Err("frozen build binding is invalid".into());
    }
    Ok(SourceBundle {
        signing_key,
        manifest,
        oracle: oracle.bytes,
        evidence: evidence.bytes,
        build_binding_sha256: record.build_binding_sha256,
    })
}

fn read_root_artifact(root: &PrivateOutputRoot, name: &str) -> Result<Vec<u8>, String> {
    read_private_artifact(&root.directory, name, MAX_OPERATOR_INPUT_BYTES).map(|value| value.bytes)
}

fn read_phase_artifact(
    root: &PrivateOutputRoot,
    directory_name: &str,
    name: &str,
) -> Result<Vec<u8>, String> {
    let directory = open_owner_directory(&root.directory, directory_name)?;
    read_private_artifact(&directory, name, MAX_OPERATOR_INPUT_BYTES).map(|value| value.bytes)
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
    })
}

fn start_run(
    arguments: &[OsString],
    experiment_descriptor: File,
    prebuild_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 13 {
        return Err("operator-start-run requires bound experiment and prebuild directories".into());
    }
    let (experiment_path, experiment_identity) =
        parse_bound(arguments, 1, "--experiment-directory")?;
    let (prebuild_path, prebuild_identity) = parse_bound(arguments, 7, "--prebuild-directory")?;
    let root = held_root(experiment_path, experiment_identity, experiment_descriptor)?;
    let prebuild = held_root(prebuild_path, prebuild_identity, prebuild_descriptor)?;
    let request: StartRunRequest = read_request(io::stdin().lock())?;
    if request.schema != START_RUN_SCHEMA {
        return Err("operator run request schema is invalid".into());
    }
    let (_, enrollment) = verified_enrollment(&root)?;
    let (signing_key, prebuild_manifest, _record) = private_seed_and_record(&prebuild)?;
    let retained_manifest = read_root_artifact(&root, SOURCE_MANIFEST_NAME)?;
    if prebuild_manifest != retained_manifest {
        return Err("operator prebuild no longer matches the enrolled experiment".into());
    }
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
    let prior = if ordinal == 2 {
        Some(sha256_hex(&run_files(&root, 1)?.binding))
    } else {
        None
    };
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
    let oracle = read_root_artifact(&root, SOURCE_ORACLE_NAME)?;
    let evidence = read_root_artifact(&root, SOURCE_EVIDENCE_NAME)?;
    let control = create_run_control(
        &signing_key,
        &enrollment,
        &oracle,
        RunControlRequest {
            preupload_evidence_sha256: sha256_hex(&evidence),
            run_ordinal: ordinal,
            prior_collection_binding_sha256: prior,
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
    })
}

fn close_run_phase(
    arguments: &[OsString],
    experiment_descriptor: File,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 7 {
        return Err("operator-close-run requires one bound experiment directory".into());
    }
    let (path, identity) = parse_bound(arguments, 1, "--experiment-directory")?;
    let root = held_root(path, identity, experiment_descriptor)?;
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
    let acknowledgement = read_phase_artifact(&root, &control_name, RUN_ACK_NAME)?;
    let envelope = read_phase_artifact(&root, &control_name, RUN_ENVELOPE_NAME)?;
    let intent = read_phase_artifact(&root, &control_name, RUN_INTENT_NAME)?;
    verify_intent_source(&root, &intent)?;
    let export = read_raw(MAX_OPERATOR_INPUT_BYTES)?;
    let (closure, verified_run) = close_run(
        &enrollment,
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
    if ordinal == 2 {
        let run_one = run_files(&root, 1)?;
        let verified_one = verify_run_chain(
            &enrollment,
            RunArtifactBytes {
                run_acknowledgement: &run_one.acknowledgement,
                authorization_envelope: &run_one.envelope,
                collection_intent: &run_one.intent,
                signed_session_export: &run_one.export,
                collection_binding: &run_one.binding,
            },
        )
        .map_err(|error| format!("run 1 chain changed before final verification: {error}"))?;
        verify_two_run_chain(&enrollment, &verified_one, &verified_run)
            .map_err(|error| format!("final two-run chain is invalid: {error}"))?;
    }
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
    })
}

fn verify_complete(
    arguments: &[OsString],
    experiment_descriptor: File,
) -> Result<OperatorOutput, String> {
    if arguments.len() != 7 {
        return Err("operator-verify requires one bound experiment directory".into());
    }
    let (path, identity) = parse_bound(arguments, 1, "--experiment-directory")?;
    let root = held_root(path, identity, experiment_descriptor)?;
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
            run_acknowledgement: &two.acknowledgement,
            authorization_envelope: &two.envelope,
            collection_intent: &two.intent,
            signed_session_export: &two.export,
            collection_binding: &two.binding,
        },
    )
    .map_err(|error| format!("run 2 chain is invalid: {error}"))?;
    verify_two_run_chain(&enrollment, &verified_one, &verified_two)
        .map_err(|error| format!("two-run chain is invalid: {error}"))?;
    Ok(OperatorOutput {
        schema: OPERATOR_RESULT_SCHEMA,
        status: "two_run_chain_verified",
        phase: "complete".into(),
        experiment_id: experiment_id(&root)?,
        run_ordinal: None,
        import_relative_path: None,
        device_selection_fingerprint_sha256: None,
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
            arm_publication,
        ),
        Some("operator-close-run") => {
            close_run_phase(arguments, output_descriptor, arm_publication)
        }
        Some("operator-verify") => verify_complete(arguments, output_descriptor),
        _ => Err("unknown LAB-002 operator command".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{next_run_ordinal, open_run_ordinal, split_fingerprint_and_receipt};

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
}
