//! Private, host-only build artifact tooling for the repository-owned DemoLab.
//!
//! This binary is invoked by the hardened Fastlane flow. It has no device,
//! upload, installation, decryption, or arbitrary-target operation.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use ed25519_dalek::SigningKey;
use orchardprobe_core::ipa::{MAX_IPA_ENTRY_COPY_BYTES, copy_ipa_entry_bounded, inspect_ipa};
use orchardprobe_core::ipa_app::{ParsedInfoPlist, parse_info_plist};
use orchardprobe_core::lab002::artifacts::{
    AuthorizedTarget, AuthorizedTargetManifest, ClosedArtifact, LabOracle, OracleRole, OracleSlice,
    Presence, RequiredAppGroups, RequiredEntitlement, Toolchain,
};
use orchardprobe_core::lab002::{
    AppGroups, BuildBindingInput, EntitlementValue, FixedSectionReport, LAB002_PROFILE, LabRole,
    PreuploadSigningMetadata, TargetIdentityInput, build_binding_sha256, canonical_json,
    parse_fixed_sections, target_identity_binding_sha256, target_identity_set_sha256,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_SCHEMA: &str = "orchardprobe.lab002.prebuild-request.v1";
const INSPECT_REQUEST_SCHEMA: &str = "orchardprobe.lab002.inspect-prebuild-request.v1";
const INSPECT_RESULT_SCHEMA: &str = "orchardprobe.lab002.inspect-prebuild-result.v1";
const ORACLE_REQUEST_SCHEMA: &str = "orchardprobe.lab002.oracle-request.v1";
const ORACLE_RESULT_SCHEMA: &str = "orchardprobe.lab002.oracle-result.v1";
const PREBUILD_SCHEMA: &str = "orchardprobe.lab002.prebuild.v1";
const PUBLICATION_IDENTITY_SCHEMA: &str = "orchardprobe.lab002.published-directory.v1";
const PUBLICATION_ACK_PATH: &str = "/dev/fd/3";
const PRIVATE_OUTPUT_ROOT_PATH: &str = "/dev/fd/4";
const PRIVATE_RUN_DIRECTORY_PATH: &str = "/dev/fd/5";
const MAX_REQUEST_BYTES: usize = 32 * 1024;
const PRIVATE_SEED_NAME: &str = "lab-002-authorization-seed-v1.bin";
const MANIFEST_NAME: &str = "lab-002-authorized-targets-v1.json";
const PREBUILD_NAME: &str = "lab-002-prebuild-v1.json";
const CHECKPOINT_MARKETING_VERSION: &str = "1.0";
const CHECKPOINT_BUILD_NUMBER: &str = "3";
const MAX_PRIVATE_ARTIFACT_BYTES: usize = 16 * 1024;
const MAX_IPA_BYTES: u64 = 250 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_INFO_PLIST_BYTES: u64 = 1024 * 1024;
const MAX_CODE_DIRECTORY_BYTES: usize = 4 * 1024 * 1024;
const MAX_CMS_SIGNATURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CERTIFICATE_BUNDLE_BYTES: usize = 512 * 1024;
const MAX_CERTIFICATE_PEM_BYTES: usize = 64 * 1024;
const MAX_EMBEDDED_CERTIFICATES: usize = 8;
const SYSTEM_OPENSSL_PATH: &str = "/usr/bin/openssl";
const SYSTEM_SECURITY_PATH: &str = "/usr/bin/security";
const SYSTEM_ROOT_KEYCHAIN_PATH: &str = "/System/Library/Keychains/SystemRootCertificates.keychain";
const ORACLE_NAME: &str = "lab-002-oracle-v1.json";

#[derive(Debug)]
struct PrivateOutputRoot {
    canonical_path: PathBuf,
    directory: File,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    schema: String,
    source_commit: String,
    marketing_version: String,
    build_number: String,
    configuration: String,
    observer_revision: String,
    toolchain: Toolchain,
    targets: Vec<AuthorizedTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectPrebuildRequest {
    schema: String,
    source_commit: String,
    marketing_version: String,
    build_number: String,
    configuration: String,
    observer_revision: String,
    toolchain: Toolchain,
    targets: Vec<AuthorizedTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleRequest {
    schema: String,
    source_commit: String,
    marketing_version: String,
    build_number: String,
    configuration: String,
    observer_revision: String,
    toolchain: Toolchain,
    targets: Vec<AuthorizedTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTarget {
    role: LabRole,
    target_identity_binding_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrebuildRecord {
    schema: String,
    profile: String,
    source_commit: String,
    fixture_source_root: String,
    marketing_version: String,
    build_number: String,
    configuration: String,
    observer_revision: String,
    generator_revision: String,
    identity_nonce: String,
    authorization_public_key: String,
    authorization_key_id: String,
    authorized_target_manifest_sha256: String,
    build_binding_sha256: String,
    target_identity_set_sha256: String,
    toolchain: Toolchain,
    targets: Vec<PreparedTarget>,
}

#[derive(Debug, Serialize)]
struct PrepareOutput {
    schema: &'static str,
    prebuild_directory: String,
    prebuild_directory_device: String,
    prebuild_directory_inode: String,
    authorized_target_manifest_sha256: String,
    build_binding_sha256: String,
    target_identity_set_sha256: String,
    private_artifacts: Vec<PrivateArtifactIdentity>,
}

#[derive(Debug, Serialize)]
struct InspectPrebuildOutput {
    schema: &'static str,
    prebuild_directory_device: String,
    prebuild_directory_inode: String,
    source_commit: String,
    marketing_version: String,
    build_number: String,
    identity_nonce: String,
    authorization_public_key: String,
    authorization_key_id: String,
    authorized_target_manifest_sha256: String,
    build_binding_sha256: String,
    target_identity_set_sha256: String,
    toolchain: Toolchain,
}

#[derive(Debug, Serialize)]
struct OracleOutput {
    schema: &'static str,
    oracle_name: &'static str,
    oracle_device: String,
    oracle_inode: String,
    oracle_mode: u32,
    oracle_size: u64,
    oracle_sha256: String,
    ipa_size: u64,
    ipa_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum CommandOutput {
    Prepare(PrepareOutput),
    InspectPrebuild(Box<InspectPrebuildOutput>),
    Oracle(OracleOutput),
}

#[derive(Debug, Serialize)]
struct PrivateArtifactIdentity {
    name: String,
    device: String,
    inode: String,
    mode: u32,
    size: u64,
    sha256: String,
}

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    // Fastlane deliberately duplicates its already-locked output-root
    // descriptor onto this fixed child descriptor. Opening its descriptor
    // node duplicates that held file description instead of reopening an
    // attacker-replaced output-root pathname.
    let output_root_directory = match File::open(PRIVATE_OUTPUT_ROOT_PATH) {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("error: could not receive the held prebuild output root: {error}");
            return ExitCode::FAILURE;
        }
    };
    let run_directory =
        if arguments.first().and_then(|value| value.to_str()) == Some("create-oracle") {
            match File::open(PRIVATE_RUN_DIRECTORY_PATH) {
                Ok(directory) => Some(directory),
                Err(error) => {
                    eprintln!("error: could not receive the held private run directory: {error}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            None
        };
    match execute(
        arguments,
        output_root_directory,
        run_directory,
        |staging_name, identity| {
            write_publication_identity(&mut stdout, staging_name, identity)?;
            wait_for_publication_ack()
        },
    ) {
        Ok(output) => {
            if let Err(error) = write_command_result(&mut stdout, &output) {
                eprintln!("error: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn wait_for_publication_ack() -> Result<(), String> {
    let mut acknowledgement = Vec::with_capacity(2);
    let mut file = File::open(PUBLICATION_ACK_PATH).map_err(|error| {
        format!("could not receive publication rollback acknowledgement: {error}")
    })?;
    let mut flags = rustix::fs::fcntl_getfl(&file)
        .map_err(|error| format!("could not inspect publication acknowledgement pipe: {error}"))?;
    flags.remove(rustix::fs::OFlags::NONBLOCK);
    rustix::fs::fcntl_setfl(&file, flags)
        .map_err(|error| format!("could not block on publication acknowledgement: {error}"))?;
    Read::by_ref(&mut file)
        .take(2)
        .read_to_end(&mut acknowledgement)
        .map_err(|error| {
            format!("could not receive publication rollback acknowledgement: {error}")
        })?;
    if acknowledgement != b"A" {
        return Err("publication rollback acknowledgement is invalid".into());
    }
    Ok(())
}

fn write_publication_identity(
    mut writer: impl Write,
    staging_name: &str,
    identity: (u64, u64),
) -> Result<(), String> {
    writeln!(
        writer,
        "{} {} {} {}",
        PUBLICATION_IDENTITY_SCHEMA, staging_name, identity.0, identity.1
    )
    .and_then(|()| writer.flush())
    .map_err(|error| format!("could not arm publication rollback: {error}"))
}

fn write_command_result(mut writer: impl Write, output: &CommandOutput) -> Result<(), String> {
    let bytes =
        canonical_json(output).map_err(|error| format!("could not encode result: {error}"))?;
    writer
        .write_all(&bytes)
        .and_then(|()| writeln!(writer))
        .map_err(|error| format!("could not write result: {error}"))
}

fn execute(
    arguments: Vec<std::ffi::OsString>,
    output_root_directory: File,
    run_directory: Option<File>,
    arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<CommandOutput, String> {
    match arguments.first().and_then(|value| value.to_str()) {
        Some("prepare") => {
            let (path, expected_identity) =
                parse_bound_directory_arguments(&arguments, "prepare", "--output-root")?;
            let output_root = validate_bound_private_output_root(
                &path,
                output_root_directory,
                expected_identity,
            )?;
            let request: PrepareRequest = read_request(io::stdin().lock())?;
            if request.schema != REQUEST_SCHEMA {
                return Err("prebuild request schema is invalid".into());
            }
            prepare_with_bound_publication_arm(output_root, request, arm_publication)
                .map(CommandOutput::Prepare)
        }
        Some("inspect-prebuild") => {
            let (path, expected_identity) = parse_bound_directory_arguments(
                &arguments,
                "inspect-prebuild",
                "--prebuild-directory",
            )?;
            let prebuild_directory = validate_bound_private_output_root(
                &path,
                output_root_directory,
                expected_identity,
            )?;
            let request: InspectPrebuildRequest = read_request(io::stdin().lock())?;
            if request.schema != INSPECT_REQUEST_SCHEMA {
                return Err("inspect-prebuild request schema is invalid".into());
            }
            inspect_prebuild_directory(prebuild_directory, request)
                .map(Box::new)
                .map(CommandOutput::InspectPrebuild)
        }
        Some("create-oracle") => {
            let directories = parse_oracle_directory_arguments(&arguments)?;
            let prebuild_directory = validate_bound_private_output_root(
                &directories.prebuild_path,
                output_root_directory,
                directories.prebuild_identity,
            )?;
            let run_directory = validate_bound_private_output_root(
                &directories.run_path,
                run_directory.ok_or_else(|| "held private run directory is missing".to_owned())?,
                directories.run_identity,
            )?;
            let request: OracleRequest = read_request(io::stdin().lock())?;
            if request.schema != ORACLE_REQUEST_SCHEMA {
                return Err("oracle request schema is invalid".into());
            }
            create_oracle(prebuild_directory, run_directory, request).map(CommandOutput::Oracle)
        }
        _ => Err(
            "usage: oprobe-lab002 prepare|inspect-prebuild|create-oracle with fixed private \
             directories"
                .into(),
        ),
    }
}

struct OracleDirectoryArguments {
    prebuild_path: PathBuf,
    prebuild_identity: (u64, u64),
    run_path: PathBuf,
    run_identity: (u64, u64),
}

fn parse_oracle_directory_arguments(
    arguments: &[std::ffi::OsString],
) -> Result<OracleDirectoryArguments, String> {
    let expected = [
        "create-oracle",
        "--prebuild-directory",
        "",
        "--prebuild-directory-device",
        "",
        "--prebuild-directory-inode",
        "",
        "--run-directory",
        "",
        "--run-directory-device",
        "",
        "--run-directory-inode",
        "",
    ];
    if arguments.len() != expected.len()
        || expected
            .iter()
            .enumerate()
            .filter(|(_, value)| !value.is_empty())
            .any(|(index, value)| arguments[index] != *value)
    {
        return Err(
            "usage: oprobe-lab002 create-oracle --prebuild-directory ABSOLUTE_DIRECTORY \
             --prebuild-directory-device DECIMAL --prebuild-directory-inode DECIMAL \
             --run-directory ABSOLUTE_DIRECTORY --run-directory-device DECIMAL \
             --run-directory-inode DECIMAL"
                .into(),
        );
    }
    Ok(OracleDirectoryArguments {
        prebuild_path: PathBuf::from(&arguments[2]),
        prebuild_identity: (
            parse_identity_component(&arguments[4], "prebuild-directory device")?,
            parse_identity_component(&arguments[6], "prebuild-directory inode")?,
        ),
        run_path: PathBuf::from(&arguments[8]),
        run_identity: (
            parse_identity_component(&arguments[10], "run-directory device")?,
            parse_identity_component(&arguments[12], "run-directory inode")?,
        ),
    })
}

fn parse_bound_directory_arguments(
    arguments: &[std::ffi::OsString],
    operation: &str,
    path_option: &str,
) -> Result<(PathBuf, (u64, u64)), String> {
    let device_option = format!("{path_option}-device");
    let inode_option = format!("{path_option}-inode");
    if arguments.len() != 7
        || arguments[0] != operation
        || arguments[1] != path_option
        || arguments[3] != device_option.as_str()
        || arguments[5] != inode_option.as_str()
    {
        return Err(format!(
            "usage: oprobe-lab002 {operation} {path_option} ABSOLUTE_PRIVATE_DIRECTORY \
             {device_option} DECIMAL {inode_option} DECIMAL"
        ));
    }
    Ok((
        PathBuf::from(&arguments[2]),
        (
            parse_identity_component(&arguments[4], "private-directory device")?,
            parse_identity_component(&arguments[6], "private-directory inode")?,
        ),
    ))
}

fn parse_identity_component(value: &std::ffi::OsStr, label: &str) -> Result<u64, String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("{label} must be canonical decimal"))?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{label} must be canonical decimal"));
    }
    value
        .parse()
        .map_err(|_| format!("{label} must fit in an unsigned 64-bit integer"))
}

fn read_request<T: serde::de::DeserializeOwned>(mut input: impl Read) -> Result<T, String> {
    let mut bytes = Vec::with_capacity(4096);
    input
        .by_ref()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read the bounded prebuild request: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("prebuild request is empty or oversized".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("prebuild request is invalid: {error}"))
}

#[cfg(test)]
fn prepare(output_root: &Path, request: PrepareRequest) -> Result<PrepareOutput, String> {
    prepare_with_publication_arm(output_root, request, |_, _| Ok(()))
}

#[cfg(test)]
fn prepare_with_publication_arm(
    output_root: &Path,
    request: PrepareRequest,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<PrepareOutput, String> {
    let output_root = validate_private_output_root(output_root)?;
    prepare_with_bound_publication_arm(output_root, request, &mut arm_publication)
}

fn prepare_with_bound_publication_arm(
    output_root: PrivateOutputRoot,
    request: PrepareRequest,
    mut arm_publication: impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<PrepareOutput, String> {
    validate_request(&request)?;
    let final_name = format!(
        "lab002-prebuild-{}-{}-{}",
        request.marketing_version, request.build_number, request.source_commit
    );

    let mut random = OsRng;
    let signing_key = loop {
        let candidate = SigningKey::generate(&mut random);
        if !candidate.verifying_key().is_weak() {
            break candidate;
        }
    };
    let mut identity_nonce = [0_u8; 32];
    random.fill_bytes(&mut identity_nonce);
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_hex = lower_hex(&public_key);
    let authorization_key_id = sha256_hex(&public_key);
    let identity_nonce_hex = lower_hex(&identity_nonce);

    let manifest = AuthorizedTargetManifest {
        schema: <AuthorizedTargetManifest as ClosedArtifact>::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        identity_nonce: identity_nonce_hex.clone(),
        authorization_public_key: public_key_hex.clone(),
        authorization_key_id: authorization_key_id.clone(),
        targets: request.targets.clone(),
    };
    let manifest_bytes = manifest
        .to_canonical_bytes()
        .map_err(|error| format!("authorized-target manifest is invalid: {error}"))?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);

    let build_input = BuildBindingInput {
        source_commit: request.source_commit.clone(),
        marketing_version: request.marketing_version.clone(),
        build_number: request.build_number.clone(),
        configuration: request.configuration.clone(),
        observer_revision: request.observer_revision.clone(),
        authorized_target_manifest_sha256: manifest_sha256.clone(),
        xcode_version: request.toolchain.xcode_version.clone(),
        xcode_build: request.toolchain.xcode_build.clone(),
        iphoneos_sdk_version: request.toolchain.iphoneos_sdk_version.clone(),
        iphoneos_sdk_build: request.toolchain.iphoneos_sdk_build.clone(),
        xcodegen_version: request.toolchain.xcodegen_version.clone(),
        xcodegen_architecture: request.toolchain.xcodegen_architecture.clone(),
        xcodegen_executable_sha256: request.toolchain.xcodegen_executable_sha256.clone(),
        fastlane_version: request.toolchain.fastlane_version.clone(),
        gemfile_lock_sha256: request.toolchain.gemfile_lock_sha256.clone(),
    };
    let build_binding = build_binding_sha256(&build_input).map_err(|error| error.to_string())?;

    let mut target_digests = Vec::with_capacity(request.targets.len());
    let mut prepared_targets = Vec::with_capacity(request.targets.len());
    for target in &request.targets {
        let identity_input = target_identity_input(&identity_nonce_hex, target)?;
        let digest =
            target_identity_binding_sha256(&identity_input).map_err(|error| error.to_string())?;
        target_digests.push((target.role, digest.clone()));
        prepared_targets.push(PreparedTarget {
            role: target.role,
            target_identity_binding_sha256: digest,
        });
    }
    let identity_set =
        target_identity_set_sha256(&target_digests).map_err(|error| error.to_string())?;

    let record = PrebuildRecord {
        schema: PREBUILD_SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        source_commit: request.source_commit.clone(),
        fixture_source_root: "fixtures/DemoLab".into(),
        marketing_version: request.marketing_version,
        build_number: request.build_number,
        configuration: request.configuration,
        observer_revision: request.observer_revision,
        generator_revision: request.source_commit.clone(),
        identity_nonce: identity_nonce_hex,
        authorization_public_key: public_key_hex,
        authorization_key_id,
        authorized_target_manifest_sha256: manifest_sha256.clone(),
        build_binding_sha256: build_binding.clone(),
        target_identity_set_sha256: identity_set.clone(),
        toolchain: request.toolchain,
        targets: prepared_targets,
    };
    let record_bytes = canonical_json(&record).map_err(|error| error.to_string())?;

    let published_identity = publish_prebuild_directory(
        &output_root,
        &final_name,
        &[
            (PRIVATE_SEED_NAME, signing_key.as_bytes().as_slice()),
            (MANIFEST_NAME, &manifest_bytes),
            (PREBUILD_NAME, &record_bytes),
        ],
        &mut arm_publication,
    )?;
    let private_artifacts = inspect_published_artifacts(
        &output_root.directory,
        &final_name,
        &[
            (PRIVATE_SEED_NAME, signing_key.as_bytes().as_slice()),
            (MANIFEST_NAME, &manifest_bytes),
            (PREBUILD_NAME, &record_bytes),
        ],
        published_identity,
    )?;

    Ok(PrepareOutput {
        schema: "orchardprobe.lab002.prebuild-result.v1",
        prebuild_directory: output_root
            .canonical_path
            .join(final_name)
            .display()
            .to_string(),
        prebuild_directory_device: published_identity.0.to_string(),
        prebuild_directory_inode: published_identity.1.to_string(),
        authorized_target_manifest_sha256: manifest_sha256,
        build_binding_sha256: build_binding,
        target_identity_set_sha256: identity_set,
        private_artifacts,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadPrivateArtifact {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn inspect_prebuild_directory(
    prebuild_directory: PrivateOutputRoot,
    request: InspectPrebuildRequest,
) -> Result<InspectPrebuildOutput, String> {
    validate_inspect_request(&request)?;
    verify_private_artifact_inventory(&prebuild_directory.directory)?;
    let seed = read_private_artifact(&prebuild_directory.directory, PRIVATE_SEED_NAME, 32)?;
    let manifest_artifact = read_private_artifact(
        &prebuild_directory.directory,
        MANIFEST_NAME,
        MAX_PRIVATE_ARTIFACT_BYTES,
    )?;
    let record_artifact = read_private_artifact(
        &prebuild_directory.directory,
        PREBUILD_NAME,
        MAX_PRIVATE_ARTIFACT_BYTES,
    )?;

    let seed_bytes: [u8; 32] = seed
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| "authorization seed must contain exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    if signing_key.verifying_key().is_weak() {
        return Err("authorization seed produces a weak Ed25519 public key".into());
    }
    let public_key = signing_key.verifying_key().to_bytes();
    let public_key_hex = lower_hex(&public_key);
    let authorization_key_id = sha256_hex(&public_key);

    let manifest = AuthorizedTargetManifest::from_canonical_bytes(&manifest_artifact.bytes)
        .map_err(|error| format!("authorized-target manifest is invalid: {error}"))?;
    let manifest_sha256 = sha256_hex(&manifest_artifact.bytes);
    let record: PrebuildRecord = serde_json::from_slice(&record_artifact.bytes)
        .map_err(|error| format!("prebuild record is invalid: {error}"))?;
    let canonical_record =
        canonical_json(&record).map_err(|error| format!("prebuild record is invalid: {error}"))?;
    if canonical_record != record_artifact.bytes {
        return Err("prebuild record is not exact canonical JSON".into());
    }

    let build_input = BuildBindingInput {
        source_commit: request.source_commit.clone(),
        marketing_version: request.marketing_version.clone(),
        build_number: request.build_number.clone(),
        configuration: request.configuration.clone(),
        observer_revision: request.observer_revision.clone(),
        authorized_target_manifest_sha256: manifest_sha256.clone(),
        xcode_version: request.toolchain.xcode_version.clone(),
        xcode_build: request.toolchain.xcode_build.clone(),
        iphoneos_sdk_version: request.toolchain.iphoneos_sdk_version.clone(),
        iphoneos_sdk_build: request.toolchain.iphoneos_sdk_build.clone(),
        xcodegen_version: request.toolchain.xcodegen_version.clone(),
        xcodegen_architecture: request.toolchain.xcodegen_architecture.clone(),
        xcodegen_executable_sha256: request.toolchain.xcodegen_executable_sha256.clone(),
        fastlane_version: request.toolchain.fastlane_version.clone(),
        gemfile_lock_sha256: request.toolchain.gemfile_lock_sha256.clone(),
    };
    let expected_build_binding =
        build_binding_sha256(&build_input).map_err(|error| error.to_string())?;
    let mut target_digests = Vec::with_capacity(manifest.targets.len());
    let mut expected_targets = Vec::with_capacity(manifest.targets.len());
    for target in &manifest.targets {
        let identity_input = target_identity_input(&manifest.identity_nonce, target)?;
        let digest =
            target_identity_binding_sha256(&identity_input).map_err(|error| error.to_string())?;
        target_digests.push((target.role, digest.clone()));
        expected_targets.push(PreparedTarget {
            role: target.role,
            target_identity_binding_sha256: digest,
        });
    }
    let expected_identity_set =
        target_identity_set_sha256(&target_digests).map_err(|error| error.to_string())?;

    if manifest.authorization_public_key != public_key_hex
        || manifest.authorization_key_id != authorization_key_id
        || manifest.targets != request.targets
        || record.schema != PREBUILD_SCHEMA
        || record.profile != LAB002_PROFILE
        || record.source_commit != request.source_commit
        || record.fixture_source_root != "fixtures/DemoLab"
        || record.marketing_version != request.marketing_version
        || record.build_number != request.build_number
        || record.configuration != request.configuration
        || record.observer_revision != request.observer_revision
        || record.generator_revision != request.source_commit
        || record.identity_nonce != manifest.identity_nonce
        || record.authorization_public_key != manifest.authorization_public_key
        || record.authorization_key_id != manifest.authorization_key_id
        || record.authorized_target_manifest_sha256 != manifest_sha256
        || record.build_binding_sha256 != expected_build_binding
        || record.target_identity_set_sha256 != expected_identity_set
        || record.toolchain != request.toolchain
        || record.targets != expected_targets
    {
        return Err("private LAB-002 prebuild artifacts are not one exact authorized tuple".into());
    }

    verify_private_artifact_inventory(&prebuild_directory.directory)?;
    for (name, expected) in [
        (PRIVATE_SEED_NAME, &seed),
        (MANIFEST_NAME, &manifest_artifact),
        (PREBUILD_NAME, &record_artifact),
    ] {
        let observed = read_private_artifact(
            &prebuild_directory.directory,
            name,
            MAX_PRIVATE_ARTIFACT_BYTES,
        )?;
        if &observed != expected {
            return Err("a private LAB-002 prebuild artifact changed during validation".into());
        }
    }
    verify_private_artifact_inventory(&prebuild_directory.directory)?;
    verify_private_output_root_path(&prebuild_directory)?;
    let directory_metadata = prebuild_directory
        .directory
        .metadata()
        .map_err(|error| format!("could not recheck private prebuild directory: {error}"))?;

    Ok(InspectPrebuildOutput {
        schema: INSPECT_RESULT_SCHEMA,
        prebuild_directory_device: directory_metadata.dev().to_string(),
        prebuild_directory_inode: directory_metadata.ino().to_string(),
        source_commit: request.source_commit,
        marketing_version: request.marketing_version,
        build_number: request.build_number,
        identity_nonce: manifest.identity_nonce,
        authorization_public_key: manifest.authorization_public_key,
        authorization_key_id: manifest.authorization_key_id,
        authorized_target_manifest_sha256: manifest_sha256,
        build_binding_sha256: expected_build_binding,
        target_identity_set_sha256: expected_identity_set,
        toolchain: request.toolchain,
    })
}

fn oracle_inspect_request(request: &OracleRequest) -> InspectPrebuildRequest {
    InspectPrebuildRequest {
        schema: INSPECT_REQUEST_SCHEMA.into(),
        source_commit: request.source_commit.clone(),
        marketing_version: request.marketing_version.clone(),
        build_number: request.build_number.clone(),
        configuration: request.configuration.clone(),
        observer_revision: request.observer_revision.clone(),
        toolchain: request.toolchain.clone(),
        targets: request.targets.clone(),
    }
}

fn create_oracle(
    prebuild_directory: PrivateOutputRoot,
    run_directory: PrivateOutputRoot,
    request: OracleRequest,
) -> Result<OracleOutput, String> {
    validate_request_fields(
        &request.source_commit,
        &request.marketing_version,
        &request.build_number,
        &request.configuration,
        &request.targets,
    )?;
    if request.observer_revision != "lab002-observer-v1" {
        return Err("oracle request observer revision is outside the closed checkpoint".into());
    }
    let inspected =
        inspect_prebuild_directory(prebuild_directory, oracle_inspect_request(&request))?;
    verify_private_output_root_path(&run_directory)?;

    let archive_paths: [&[&str]; 3] = [
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "DemoLab",
        ],
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "Frameworks",
            "DemoFramework.framework",
            "DemoFramework",
        ],
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "PlugIns",
            "DemoShareExtension.appex",
            "DemoShareExtension",
        ],
    ];
    let archive_plist_paths: [&[&str]; 3] = [
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "Info.plist",
        ],
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "Frameworks",
            "DemoFramework.framework",
            "Info.plist",
        ],
        &[
            "DemoLab.xcarchive",
            "Products",
            "Applications",
            "DemoLab.app",
            "PlugIns",
            "DemoShareExtension.appex",
            "Info.plist",
        ],
    ];
    let archive_reports = archive_paths
        .iter()
        .map(|components| {
            let mut file = open_regular_beneath(
                &run_directory.directory,
                components,
                MAX_EXECUTABLE_BYTES,
                "Archive executable",
            )?;
            let report =
                parse_stable_fixed_sections(&mut file, MAX_EXECUTABLE_BYTES, "Archive executable")?;
            cryptographically_verify_report(report, "Archive")
        })
        .collect::<Result<Vec<_>, String>>()?;
    let archive_identities = archive_plist_paths
        .iter()
        .map(|components| {
            let mut file = open_regular_beneath(
                &run_directory.directory,
                components,
                MAX_INFO_PLIST_BYTES,
                "Archive Info.plist",
            )?;
            let bytes =
                read_stable_file_bytes(&mut file, MAX_INFO_PLIST_BYTES, "Archive Info.plist")?;
            parse_info_plist(&bytes)
                .map_err(|error| format!("Archive Info.plist identity is invalid: {error}"))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let ipa_name = format!("DemoLab-{}.ipa", request.build_number);
    let mut ipa_file = open_regular_beneath(
        &run_directory.directory,
        &[ipa_name.as_str()],
        MAX_IPA_BYTES,
        "exported IPA",
    )?;
    let ipa_identity = stable_file_identity(&ipa_file, MAX_IPA_BYTES, "exported IPA")?;
    let ipa_sha256 = hash_stable_file(&mut ipa_file, &ipa_identity, MAX_IPA_BYTES, "exported IPA")?;
    let inventory = inspect_ipa(&mut ipa_file, ipa_identity.size)
        .map_err(|error| format!("exported IPA inventory is invalid: {error}"))?;
    if inventory.app_root != "Payload/DemoLab.app" {
        return Err("exported IPA does not contain the fixed DemoLab app root".into());
    }
    let ipa_paths = [
        "Payload/DemoLab.app/DemoLab",
        "Payload/DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
        "Payload/DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
    ];
    let ipa_plist_paths = [
        "Payload/DemoLab.app/Info.plist",
        "Payload/DemoLab.app/Frameworks/DemoFramework.framework/Info.plist",
        "Payload/DemoLab.app/PlugIns/DemoShareExtension.appex/Info.plist",
    ];
    let executable_entries = inventory
        .entries
        .iter()
        .filter(|entry| entry.executable)
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    if !same_paths_ignoring_order(executable_entries, &ipa_paths) {
        return Err("exported IPA executable inventory is not the exact three roles".into());
    }
    let mut ipa_reports = Vec::with_capacity(ipa_paths.len());
    for path in ipa_paths {
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| format!("exported IPA is missing fixed executable {path}"))?;
        if entry.uncompressed_size == 0 || entry.uncompressed_size > MAX_EXECUTABLE_BYTES {
            return Err(format!(
                "exported IPA executable {path} has an invalid size"
            ));
        }
        let mut temporary = tempfile::tempfile()
            .map_err(|error| format!("could not create private IPA measurement file: {error}"))?;
        let copied = copy_ipa_entry_bounded(
            &mut ipa_file,
            ipa_identity.size,
            path,
            MAX_EXECUTABLE_BYTES.min(MAX_IPA_ENTRY_COPY_BYTES),
            &mut temporary,
        )
        .map_err(|error| format!("could not read fixed IPA executable {path}: {error}"))?;
        if copied.inventory != inventory || copied.bytes_written != entry.uncompressed_size {
            return Err(format!(
                "exported IPA inventory changed while reading fixed executable {path}"
            ));
        }
        temporary
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("could not rewind fixed IPA executable {path}: {error}"))?;
        let report = parse_fixed_sections(&mut temporary)
            .map_err(|error| format!("fixed IPA executable {path} is invalid: {error}"))?;
        ipa_reports.push(cryptographically_verify_report(report, "IPA")?);
    }
    let mut ipa_identities = Vec::with_capacity(ipa_plist_paths.len());
    for path in ipa_plist_paths {
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| format!("exported IPA is missing fixed Info.plist {path}"))?;
        if entry.uncompressed_size == 0 || entry.uncompressed_size > MAX_INFO_PLIST_BYTES {
            return Err(format!(
                "exported IPA Info.plist {path} has an invalid size"
            ));
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(entry.uncompressed_size)
                .map_err(|_| format!("exported IPA Info.plist {path} size does not fit memory"))?,
        );
        let copied = copy_ipa_entry_bounded(
            &mut ipa_file,
            ipa_identity.size,
            path,
            MAX_INFO_PLIST_BYTES.min(MAX_IPA_ENTRY_COPY_BYTES),
            &mut bytes,
        )
        .map_err(|error| format!("could not read fixed IPA Info.plist {path}: {error}"))?;
        if copied.inventory != inventory || copied.bytes_written != entry.uncompressed_size {
            return Err(format!(
                "exported IPA inventory changed while reading fixed Info.plist {path}"
            ));
        }
        ipa_identities.push(
            parse_info_plist(&bytes)
                .map_err(|error| format!("IPA Info.plist identity is invalid: {error}"))?,
        );
    }
    let confirmed_inventory = inspect_ipa(&mut ipa_file, ipa_identity.size)
        .map_err(|error| format!("could not revalidate exported IPA inventory: {error}"))?;
    if confirmed_inventory != inventory {
        return Err("exported IPA inventory changed during oracle generation".into());
    }
    verify_stable_file(&ipa_file, &ipa_identity, "exported IPA")?;

    let mut roles = Vec::with_capacity(LabRole::ALL.len());
    for (index, role) in LabRole::ALL.into_iter().enumerate() {
        let target = request
            .targets
            .get(index)
            .ok_or_else(|| "oracle target inventory is incomplete".to_owned())?;
        let expected_input = target_identity_input(&inspected.identity_nonce, target)?;
        let expected_binding =
            target_identity_binding_sha256(&expected_input).map_err(|error| error.to_string())?;
        let archive_identity = archive_identities
            .get(index)
            .ok_or_else(|| "Archive bundle identity inventory is incomplete".to_owned())?;
        let ipa_identity = ipa_identities
            .get(index)
            .ok_or_else(|| "IPA bundle identity inventory is incomplete".to_owned())?;
        validate_bundle_identity(
            archive_identity,
            target,
            role,
            &request.marketing_version,
            &request.build_number,
            "Archive",
        )?;
        validate_bundle_identity(
            ipa_identity,
            target,
            role,
            &request.marketing_version,
            &request.build_number,
            "IPA",
        )?;
        if archive_identity != ipa_identity {
            return Err(format!(
                "Archive/IPA {} Info.plist identities differ",
                role.fixture_relative_path()
            ));
        }
        verify_report_signing_identity(
            &archive_reports[index],
            target,
            &archive_identity.bundle_identifier,
            &inspected.identity_nonce,
            &expected_binding,
            "Archive",
        )?;
        verify_report_signing_identity(
            &ipa_reports[index],
            target,
            &ipa_identity.bundle_identifier,
            &inspected.identity_nonce,
            &expected_binding,
            "IPA",
        )?;
        roles.push(close_oracle_role(
            role,
            expected_binding,
            &archive_reports[index].report,
            &ipa_reports[index].report,
        )?);
    }

    let oracle = LabOracle {
        schema: <LabOracle as ClosedArtifact>::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        source_commit: request.source_commit.clone(),
        fixture_source_root: "fixtures/DemoLab".into(),
        marketing_version: request.marketing_version,
        build_number: request.build_number,
        configuration: request.configuration,
        observer_revision: request.observer_revision,
        generator_revision: request.source_commit,
        build_binding_sha256: inspected.build_binding_sha256,
        authorized_target_manifest_sha256: inspected.authorized_target_manifest_sha256,
        authorization_public_key: inspected.authorization_public_key,
        authorization_key_id: inspected.authorization_key_id,
        target_identity_set_sha256: inspected.target_identity_set_sha256,
        toolchain: inspected.toolchain,
        ipa_size: ipa_identity.size,
        ipa_sha256: ipa_sha256.clone(),
        roles,
    };
    let oracle_bytes = oracle
        .to_canonical_bytes()
        .map_err(|error| format!("could not encode closed LAB-002 oracle: {error}"))?;
    let artifact = publish_oracle(&run_directory, &oracle_bytes)?;
    verify_private_output_root_path(&run_directory)?;
    Ok(OracleOutput {
        schema: ORACLE_RESULT_SCHEMA,
        oracle_name: ORACLE_NAME,
        oracle_device: artifact.device.to_string(),
        oracle_inode: artifact.inode.to_string(),
        oracle_mode: artifact.mode,
        oracle_size: artifact.size,
        oracle_sha256: artifact.sha256,
        ipa_size: ipa_identity.size,
        ipa_sha256,
    })
}

fn same_paths_ignoring_order(mut observed: Vec<&str>, expected: &[&str]) -> bool {
    let mut expected = expected.to_vec();
    observed.sort_unstable();
    expected.sort_unstable();
    observed == expected
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn open_directory_beneath(parent: &File, name: &str, label: &str) -> Result<File, String> {
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err(format!("{label} contains an unsafe fixed component"));
    }
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("could not open {label} component {name}: {error}"))?;
    let directory = File::from(descriptor);
    let metadata = directory
        .metadata()
        .map_err(|error| format!("could not inspect {label} component {name}: {error}"))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!("{label} component {name} has unsafe metadata"));
    }
    Ok(directory)
}

fn open_regular_beneath(
    root: &File,
    components: &[&str],
    maximum_size: u64,
    label: &str,
) -> Result<File, String> {
    let (file_name, directories) = components
        .split_last()
        .ok_or_else(|| format!("{label} path is empty"))?;
    let mut parent = root
        .try_clone()
        .map_err(|error| format!("could not retain {label} root: {error}"))?;
    for component in directories {
        parent = open_directory_beneath(&parent, component, label)?;
    }
    if file_name.is_empty() || file_name.contains('/') || matches!(*file_name, "." | "..") {
        return Err(format!("{label} contains an unsafe fixed filename"));
    }
    let descriptor = rustix::fs::openat(
        &parent,
        *file_name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("could not open {label}: {error}"))?;
    let file = File::from(descriptor);
    stable_file_identity(&file, maximum_size, label)?;
    Ok(file)
}

fn stable_file_identity(
    file: &File,
    maximum_size: u64,
    label: &str,
) -> Result<StableFileIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect {label}: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(format!("{label} has unsafe metadata"));
    }
    Ok(StableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn verify_stable_file(
    file: &File,
    expected: &StableFileIdentity,
    label: &str,
) -> Result<(), String> {
    let observed = stable_file_identity(file, expected.size, label)?;
    if &observed != expected {
        return Err(format!("{label} changed while it was measured"));
    }
    Ok(())
}

fn hash_stable_file(
    file: &mut File,
    expected: &StableFileIdentity,
    maximum_size: u64,
    label: &str,
) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("could not rewind {label}: {error}"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash {label}: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| format!("{label} size overflowed while hashing"))?;
        if total > maximum_size {
            return Err(format!("{label} exceeded its size bound while hashing"));
        }
        digest.update(&buffer[..read]);
    }
    if total != expected.size {
        return Err(format!("{label} size changed while hashing"));
    }
    verify_stable_file(file, expected, label)?;
    Ok(lower_hex(&digest.finalize()))
}

fn parse_stable_fixed_sections(
    file: &mut File,
    maximum_size: u64,
    label: &str,
) -> Result<FixedSectionReport, String> {
    let identity = stable_file_identity(file, maximum_size, label)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("could not rewind {label}: {error}"))?;
    let report =
        parse_fixed_sections(file).map_err(|error| format!("{label} is invalid: {error}"))?;
    if report.file_size != identity.size {
        return Err(format!("{label} parser size does not match its held file"));
    }
    verify_stable_file(file, &identity, label)?;
    Ok(report)
}

#[derive(Debug)]
struct CryptographicallyVerifiedReport {
    report: FixedSectionReport,
}

fn system_tool_identity(path: &str, label: &str) -> Result<StableFileIdentity, String> {
    let file =
        File::open(path).map_err(|error| format!("could not open the fixed {label}: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect the fixed {label}: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err(format!("the fixed {label} has unsafe metadata"));
    }
    Ok(StableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn verify_cms_signature(signing: &PreuploadSigningMetadata) -> Result<(), String> {
    if signing.is_ad_hoc
        || !signing.has_cms
        || signing.code_directory.is_empty()
        || signing.code_directory.len() > MAX_CODE_DIRECTORY_BYTES
        || signing.cms_signature.is_empty()
        || signing.cms_signature.len() > MAX_CMS_SIGNATURE_BYTES
    {
        return Err("code-signing material is outside the closed profile".into());
    }
    let openssl_before = system_tool_identity(SYSTEM_OPENSSL_PATH, "system OpenSSL")?;
    let security_before = system_tool_identity(SYSTEM_SECURITY_PATH, "system Security tool")?;
    let roots_before =
        system_tool_identity(SYSTEM_ROOT_KEYCHAIN_PATH, "Apple system-root keychain")?;
    let mut code_directory = tempfile::NamedTempFile::new()
        .map_err(|error| format!("could not create private CodeDirectory input: {error}"))?;
    code_directory
        .write_all(&signing.code_directory)
        .and_then(|_| code_directory.flush())
        .map_err(|error| format!("could not write private CodeDirectory input: {error}"))?;
    let mut cms = tempfile::NamedTempFile::new()
        .map_err(|error| format!("could not create private CMS input: {error}"))?;
    cms.write_all(&signing.cms_signature)
        .and_then(|_| cms.flush())
        .map_err(|error| format!("could not write private CMS input: {error}"))?;
    let mut signer = tempfile::NamedTempFile::new()
        .map_err(|error| format!("could not create private signer-certificate output: {error}"))?;
    let mut certificates = tempfile::NamedTempFile::new()
        .map_err(|error| format!("could not create private certificate-chain output: {error}"))?;

    let status = Command::new(SYSTEM_OPENSSL_PATH)
        .env_clear()
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(cms.path())
        .arg("-content")
        .arg(code_directory.path())
        .args(["-noverify", "-signer"])
        .arg(signer.path())
        .arg("-certsout")
        .arg(certificates.path())
        .args(["-out", "/dev/null"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not run the fixed CMS verifier: {error}"))?;
    if !status.success() {
        return Err("embedded CMS does not authenticate its CodeDirectory".into());
    }
    let signer_certificates =
        read_pem_certificates(signer.as_file_mut(), "CMS signer certificate")?;
    if signer_certificates.len() != 1 {
        return Err("CMS verifier did not return exactly one signer certificate".into());
    }
    let embedded_certificates =
        read_pem_certificates(certificates.as_file_mut(), "CMS embedded certificate chain")?;
    let signer_certificate = &signer_certificates[0];
    let mut chain_files = Vec::new();
    for certificate in embedded_certificates {
        if &certificate == signer_certificate {
            continue;
        }
        let mut file = tempfile::NamedTempFile::new().map_err(|error| {
            format!("could not create private chain-certificate input: {error}")
        })?;
        file.write_all(&certificate)
            .and_then(|_| file.flush())
            .map_err(|error| format!("could not write private chain-certificate input: {error}"))?;
        chain_files.push(file);
    }
    let mut trust_command = Command::new(SYSTEM_SECURITY_PATH);
    trust_command
        .env_clear()
        .args(["verify-cert", "-c"])
        .arg(signer.path());
    for certificate in &chain_files {
        trust_command.arg("-c").arg(certificate.path());
    }
    let trust_status = trust_command
        .args(["-N", "-k"])
        .arg(SYSTEM_ROOT_KEYCHAIN_PATH)
        .args(["-p", "codeSign", "-q", "-L"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not run the fixed code-signing trust verifier: {error}"))?;
    if !trust_status.success() {
        return Err("embedded CMS signer is not trusted for Apple code signing".into());
    }
    let subject = Command::new(SYSTEM_OPENSSL_PATH)
        .env_clear()
        .args(["x509", "-in"])
        .arg(signer.path())
        .args(["-noout", "-subject", "-nameopt", "RFC2253"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("could not inspect the trusted CMS signer: {error}"))?;
    if !subject.status.success() || subject.stdout.len() > 16 * 1024 {
        return Err("trusted CMS signer subject could not be inspected".into());
    }
    let expected_ou = format!("OU={}", signing.code_directory_team_identifier);
    let subject = std::str::from_utf8(&subject.stdout)
        .map_err(|_| "trusted CMS signer subject is not UTF-8".to_owned())?;
    if !subject
        .trim()
        .strip_prefix("subject=")
        .is_some_and(|subject| {
            subject
                .split(',')
                .any(|component| component.trim() == expected_ou)
        })
    {
        return Err("trusted CMS signer Team ID does not match the CodeDirectory".into());
    }
    let openssl_after = system_tool_identity(SYSTEM_OPENSSL_PATH, "system OpenSSL")?;
    let security_after = system_tool_identity(SYSTEM_SECURITY_PATH, "system Security tool")?;
    let roots_after =
        system_tool_identity(SYSTEM_ROOT_KEYCHAIN_PATH, "Apple system-root keychain")?;
    if openssl_before != openssl_after
        || security_before != security_after
        || roots_before != roots_after
    {
        return Err("a fixed system signature verifier changed during verification".into());
    }
    Ok(())
}

fn read_pem_certificates(file: &mut File, label: &str) -> Result<Vec<Vec<u8>>, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("could not rewind {label}: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_CERTIFICATE_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BUNDLE_BYTES {
        return Err(format!("{label} is empty or exceeds its fixed limit"));
    }
    parse_pem_certificates(&bytes, label)
}

fn parse_pem_certificates(bytes: &[u8], label: &str) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8 PEM"))?;
    let mut certificates = Vec::new();
    let mut current = None::<Vec<u8>>;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        match (current.as_mut(), line) {
            (None, BEGIN) => current = Some(format!("{BEGIN}\n").into_bytes()),
            (Some(certificate), END) => {
                certificate.extend_from_slice(END.as_bytes());
                certificate.push(b'\n');
                if certificate.len() > MAX_CERTIFICATE_PEM_BYTES {
                    return Err(format!("{label} contains an oversized certificate"));
                }
                certificates.push(current.take().expect("certificate is present"));
                if certificates.len() > MAX_EMBEDDED_CERTIFICATES {
                    return Err(format!("{label} contains too many certificates"));
                }
            }
            (Some(certificate), body)
                if !body.is_empty()
                    && body.len() <= 80
                    && body.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    }) =>
            {
                certificate.extend_from_slice(body.as_bytes());
                certificate.push(b'\n');
                if certificate.len() > MAX_CERTIFICATE_PEM_BYTES {
                    return Err(format!("{label} contains an oversized certificate"));
                }
            }
            (None, "") => {}
            _ => return Err(format!("{label} has malformed or unexpected PEM content")),
        }
    }
    if current.is_some() || certificates.is_empty() {
        return Err(format!("{label} has an incomplete certificate inventory"));
    }
    Ok(certificates)
}

fn cryptographically_verify_report(
    report: FixedSectionReport,
    artifact: &str,
) -> Result<CryptographicallyVerifiedReport, String> {
    if report.slices.is_empty() || report.slices.len() > 4 {
        return Err(format!("{artifact} has an invalid signed slice inventory"));
    }
    for slice in &report.slices {
        let signing = slice
            .signing
            .as_ref()
            .ok_or_else(|| format!("{artifact} slice has no embedded code signature"))?;
        verify_cms_signature(signing)
            .map_err(|error| format!("{artifact} signature verification failed: {error}"))?;
    }
    Ok(CryptographicallyVerifiedReport { report })
}

fn read_stable_file_bytes(
    file: &mut File,
    maximum_size: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    let identity = stable_file_identity(file, maximum_size, label)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("could not rewind {label}: {error}"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(identity.size).map_err(|_| format!("{label} size does not fit memory"))?,
    );
    file.take(maximum_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {label}: {error}"))?;
    if bytes.len() as u64 != identity.size {
        return Err(format!("{label} size changed while reading"));
    }
    verify_stable_file(file, &identity, label)?;
    Ok(bytes)
}

fn validate_bundle_identity(
    identity: &ParsedInfoPlist,
    target: &AuthorizedTarget,
    role: LabRole,
    marketing_version: &str,
    build_number: &str,
    artifact: &str,
) -> Result<(), String> {
    let expected_executable = match role {
        LabRole::MainApp => "DemoLab",
        LabRole::Framework => "DemoFramework",
        LabRole::ShareExtension => "DemoShareExtension",
    };
    if identity.bundle_identifier != target.bundle_id
        || identity.executable_name != expected_executable
        || identity.bundle_version != build_number
        || identity.short_version.as_deref() != Some(marketing_version)
    {
        return Err(format!(
            "{artifact} {} Info.plist identity is outside the authorized target",
            role.fixture_relative_path()
        ));
    }
    Ok(())
}

fn observed_entitlement(value: &Option<String>) -> EntitlementValue {
    value
        .as_ref()
        .map_or(EntitlementValue::RequiredAbsent, |value| {
            EntitlementValue::Present(value.clone())
        })
}

fn observed_app_groups(value: &Option<Vec<String>>) -> AppGroups {
    value.as_ref().map_or(AppGroups::RequiredAbsent, |value| {
        AppGroups::Present(value.clone())
    })
}

fn observed_target_input(
    identity_nonce: &str,
    target: &AuthorizedTarget,
    bundle_identifier: &str,
    signing: &PreuploadSigningMetadata,
) -> TargetIdentityInput {
    TargetIdentityInput {
        identity_nonce_hex: identity_nonce.into(),
        role: target.role,
        bundle_id: bundle_identifier.into(),
        code_directory_identifier: signing.code_directory_identifier.clone(),
        code_directory_team_identifier: signing.code_directory_team_identifier.clone(),
        application_identifier: observed_entitlement(&signing.application_identifier),
        developer_team_identifier: observed_entitlement(&signing.developer_team_identifier),
        app_groups: observed_app_groups(&signing.application_groups),
    }
}

fn verify_report_signing_identity(
    report: &CryptographicallyVerifiedReport,
    target: &AuthorizedTarget,
    bundle_identifier: &str,
    identity_nonce: &str,
    expected_binding: &str,
    artifact: &str,
) -> Result<(), String> {
    for slice in &report.report.slices {
        let signing = slice
            .signing
            .as_ref()
            .ok_or_else(|| format!("{artifact} slice has no embedded code signature"))?;
        if signing.is_ad_hoc
            || signing.code_directory_identifier != target.code_directory_identifier
            || signing.code_directory_team_identifier != target.code_directory_team_identifier
        {
            return Err(format!(
                "{artifact} code-signing identity is outside the authorized target"
            ));
        }
        let observed = target_identity_binding_sha256(&observed_target_input(
            identity_nonce,
            target,
            bundle_identifier,
            signing,
        ))
        .map_err(|error| format!("{artifact} target identity is invalid: {error}"))?;
        if observed != expected_binding {
            return Err(format!(
                "{artifact} target identity binding does not match the authorized tuple"
            ));
        }
    }
    Ok(())
}

fn close_oracle_role(
    role: LabRole,
    target_identity_binding_sha256: String,
    archive: &FixedSectionReport,
    ipa: &FixedSectionReport,
) -> Result<OracleRole, String> {
    if archive.container != ipa.container
        || archive.file_size != ipa.file_size
        || archive.slices.len() != ipa.slices.len()
        || archive.slices.is_empty()
        || archive.slices.len() > 4
    {
        return Err(format!(
            "Archive/IPA {} container or complete slice inventory differs",
            role.fixture_relative_path()
        ));
    }
    let mut slices = Vec::with_capacity(archive.slices.len());
    for (archive_slice, ipa_slice) in archive.slices.iter().zip(&ipa.slices) {
        let archive_encryption = archive_slice.encryption.as_ref().ok_or_else(|| {
            format!(
                "Archive {} slice has no encryption command",
                role.fixture_relative_path()
            )
        })?;
        let ipa_encryption = ipa_slice.encryption.as_ref().ok_or_else(|| {
            format!(
                "IPA {} slice has no encryption command",
                role.fixture_relative_path()
            )
        })?;
        let ipa_signing = ipa_slice.signing.as_ref().ok_or_else(|| {
            format!(
                "IPA {} slice has no code signature",
                role.fixture_relative_path()
            )
        })?;
        if archive_slice.ordinal != ipa_slice.ordinal
            || archive_slice.cpu_type != ipa_slice.cpu_type
            || archive_slice.cpu_subtype != ipa_slice.cpu_subtype
            || archive_slice.macho_uuid != ipa_slice.macho_uuid
            || archive_slice.slice_file_offset != ipa_slice.slice_file_offset
            || archive_slice.slice_file_size != ipa_slice.slice_file_size
            || archive_slice.section_slice_offset != ipa_slice.section_slice_offset
            || archive_slice.section_file_offset != ipa_slice.section_file_offset
            || archive_slice.section_vm_offset != ipa_slice.section_vm_offset
            || archive_slice.section_length != ipa_slice.section_length
            || archive_slice.section_sha256 != ipa_slice.section_sha256
            || archive_slice.fixup_layout_sha256 != ipa_slice.fixup_layout_sha256
            || archive_encryption != ipa_encryption
            || archive_encryption.cryptid != 0
            || ipa_encryption.cryptid != 0
        {
            return Err(format!(
                "Archive/IPA {} slice identity, range, fixup, encryption, or plaintext differs",
                role.fixture_relative_path()
            ));
        }
        slices.push(OracleSlice {
            ordinal: archive_slice.ordinal,
            cpu_type: archive_slice.cpu_type,
            cpu_subtype: archive_slice.cpu_subtype,
            macho_uuid: archive_slice.macho_uuid.clone(),
            code_signature_sha256: ipa_signing.superblob_sha256.clone(),
            slice_file_offset: archive_slice.slice_file_offset,
            slice_file_size: archive_slice.slice_file_size,
            archive_cryptid: archive_encryption.cryptid,
            ipa_cryptid: ipa_encryption.cryptid,
            section_slice_offset: archive_slice.section_slice_offset,
            section_file_offset: archive_slice.section_file_offset,
            section_vm_offset: archive_slice.section_vm_offset,
            section_length: archive_slice.section_length,
            expected_plaintext_sha256: archive_slice.section_sha256.clone(),
            ipa_section_sha256: ipa_slice.section_sha256.clone(),
        });
    }
    Ok(OracleRole {
        role,
        fixture_relative_path: role.fixture_relative_path().into(),
        target_identity_binding_sha256,
        slices,
    })
}

fn publish_oracle(
    run_directory: &PrivateOutputRoot,
    oracle_bytes: &[u8],
) -> Result<PrivateArtifactIdentity, String> {
    if oracle_bytes.is_empty() || oracle_bytes.len() > MAX_PRIVATE_ARTIFACT_BYTES {
        return Err("closed LAB-002 oracle has an invalid encoded size".into());
    }
    verify_private_output_root_path(run_directory)?;
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let staging_name = format!(".lab-002-oracle-{}.tmp", lower_hex(&random));
    write_private_file(&run_directory.directory, &staging_name, oracle_bytes)?;
    let mut published = false;
    let result = (|| {
        rustix::fs::renameat_with(
            &run_directory.directory,
            staging_name.as_str(),
            &run_directory.directory,
            ORACLE_NAME,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| format!("could not publish LAB-002 oracle exclusively: {error}"))?;
        published = true;
        run_directory
            .directory
            .sync_all()
            .map_err(|error| format!("could not fsync private run directory: {error}"))?;
        verify_private_output_root_path(run_directory)?;
        let artifact = read_private_artifact(
            &run_directory.directory,
            ORACLE_NAME,
            MAX_PRIVATE_ARTIFACT_BYTES,
        )?;
        if artifact.bytes != oracle_bytes {
            return Err("published LAB-002 oracle bytes changed before binding".into());
        }
        Ok(PrivateArtifactIdentity {
            name: ORACLE_NAME.into(),
            device: artifact.device.to_string(),
            inode: artifact.inode.to_string(),
            mode: artifact.mode,
            size: artifact.size,
            sha256: sha256_hex(&artifact.bytes),
        })
    })();
    if result.is_err() {
        let cleanup_name = if published {
            ORACLE_NAME
        } else {
            staging_name.as_str()
        };
        let cleanup = rustix::fs::unlinkat(
            &run_directory.directory,
            cleanup_name,
            rustix::fs::AtFlags::empty(),
        );
        let sync = run_directory.directory.sync_all();
        if cleanup.is_err() || sync.is_err() {
            return Err(format!(
                "LAB-002 oracle cleanup is indeterminate after publication failed: {}",
                result.as_ref().unwrap_err()
            ));
        }
    }
    result
}

fn read_private_artifact(
    directory: &File,
    name: &str,
    maximum_size: usize,
) -> Result<ReadPrivateArtifact, String> {
    read_private_artifact_with(directory, name, maximum_size, || {})
}

fn read_private_artifact_with(
    directory: &File,
    name: &str,
    maximum_size: usize,
    after_read: impl FnOnce(),
) -> Result<ReadPrivateArtifact, String> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("could not open private prebuild artifact {name}: {error}"))?;
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|error| format!("could not inspect private prebuild artifact {name}: {error}"))?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o777 != 0o400
        || before.len() == 0
        || before.len() > maximum_size as u64
    {
        return Err(format!(
            "private prebuild artifact {name} has unsafe metadata"
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum_size as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read private prebuild artifact {name}: {error}"))?;
    after_read();
    let after = file
        .metadata()
        .map_err(|error| format!("could not recheck private prebuild artifact {name}: {error}"))?;
    if bytes.len() as u64 != before.len()
        || bytes.len() > maximum_size
        || (
            after.dev(),
            after.ino(),
            after.uid(),
            after.mode() & 0o777,
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.uid(),
            before.mode() & 0o777,
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
        )
    {
        return Err(format!(
            "private prebuild artifact {name} changed while it was read"
        ));
    }
    Ok(ReadPrivateArtifact {
        bytes,
        device: before.dev(),
        inode: before.ino(),
        owner: before.uid(),
        mode: before.mode() & 0o777,
        size: before.len(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
    })
}

fn verify_private_artifact_inventory(directory: &File) -> Result<(), String> {
    let entries = rustix::fs::Dir::read_from(directory)
        .map_err(|error| format!("could not open private prebuild directory stream: {error}"))?;
    let mut observed = Vec::with_capacity(3);
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("could not enumerate private prebuild directory: {error}"))?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let name = String::from_utf8(name.to_vec())
            .map_err(|_| "private prebuild artifact name is not valid UTF-8".to_owned())?;
        observed.push(name);
        if observed.len() > 3 {
            return Err(
                "private prebuild directory does not contain the exact three artifacts".into(),
            );
        }
    }
    observed.sort();
    let mut expected = [
        PRIVATE_SEED_NAME.to_owned(),
        MANIFEST_NAME.to_owned(),
        PREBUILD_NAME.to_owned(),
    ];
    expected.sort();
    if observed != expected {
        return Err("private prebuild directory does not contain the exact three artifacts".into());
    }
    Ok(())
}

fn validate_request(request: &PrepareRequest) -> Result<(), String> {
    validate_request_fields(
        &request.source_commit,
        &request.marketing_version,
        &request.build_number,
        &request.configuration,
        &request.targets,
    )
}

fn validate_inspect_request(request: &InspectPrebuildRequest) -> Result<(), String> {
    validate_request_fields(
        &request.source_commit,
        &request.marketing_version,
        &request.build_number,
        &request.configuration,
        &request.targets,
    )
}

fn validate_request_fields(
    source_commit: &str,
    marketing_version: &str,
    build_number: &str,
    configuration: &str,
    targets: &[AuthorizedTarget],
) -> Result<(), String> {
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source commit must be exactly 40 lowercase hexadecimal characters".into());
    }
    if !valid_marketing_version(marketing_version) {
        return Err("marketing version must contain one to three numeric components".into());
    }
    if build_number.is_empty()
        || build_number.len() > 18
        || build_number.starts_with('0')
        || !build_number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("build number must be a positive decimal integer of at most 18 digits".into());
    }
    if marketing_version != CHECKPOINT_MARKETING_VERSION || build_number != CHECKPOINT_BUILD_NUMBER
    {
        return Err("this helper only authorizes the reviewed DemoLab 1.0 (3) checkpoint".into());
    }
    if configuration != "Release"
        || targets.len() != LabRole::ALL.len()
        || targets
            .iter()
            .zip(LabRole::ALL)
            .any(|(target, role)| target.role != role)
    {
        return Err("prebuild request is not the closed Release three-role profile".into());
    }
    Ok(())
}

fn valid_marketing_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    (1..=3).contains(&components.len())
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn target_identity_input(
    identity_nonce: &str,
    target: &AuthorizedTarget,
) -> Result<TargetIdentityInput, String> {
    Ok(TargetIdentityInput {
        identity_nonce_hex: identity_nonce.into(),
        role: target.role,
        bundle_id: target.bundle_id.clone(),
        code_directory_identifier: target.code_directory_identifier.clone(),
        code_directory_team_identifier: target.code_directory_team_identifier.clone(),
        application_identifier: entitlement_value(&target.application_identifier)?,
        developer_team_identifier: entitlement_value(&target.developer_team_identifier)?,
        app_groups: app_groups(&target.application_groups)?,
    })
}

fn entitlement_value(value: &RequiredEntitlement) -> Result<EntitlementValue, String> {
    match (value.presence, &value.value) {
        (Presence::RequiredAbsent, None) => Ok(EntitlementValue::RequiredAbsent),
        (Presence::Present, Some(value)) => Ok(EntitlementValue::Present(value.clone())),
        _ => Err("entitlement presence is contradictory".into()),
    }
}

fn app_groups(value: &RequiredAppGroups) -> Result<AppGroups, String> {
    match (value.presence, &value.values) {
        (Presence::RequiredAbsent, None) => Ok(AppGroups::RequiredAbsent),
        (Presence::Present, Some(values)) => Ok(AppGroups::Present(values.clone())),
        _ => Err("application-group presence is contradictory".into()),
    }
}

#[cfg(test)]
fn validate_private_output_root(path: &Path) -> Result<PrivateOutputRoot, String> {
    let directory = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| format!("could not hold prebuild output root safely: {error}"))?;
    let opened = directory
        .metadata()
        .map_err(|error| format!("could not inspect held prebuild output root: {error}"))?;
    validate_bound_private_output_root(path, directory, (opened.dev(), opened.ino()))
}

fn validate_bound_private_output_root(
    path: &Path,
    directory: File,
    expected_identity: (u64, u64),
) -> Result<PrivateOutputRoot, String> {
    if !path.is_absolute() {
        return Err("prebuild output root must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect prebuild output root: {error}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("prebuild output root must be an owner-only real directory".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("could not resolve prebuild output root: {error}"))?;
    if canonical != path {
        return Err("prebuild output root must already be canonical".into());
    }
    let repository = std::env::current_dir()
        .and_then(|path| path.canonicalize())
        .map_err(|error| format!("could not resolve repository root: {error}"))?;
    // Path::starts_with compares complete path components, not raw strings.
    if canonical.starts_with(&repository) {
        return Err("prebuild output root must be outside the repository".into());
    }
    let opened = directory
        .metadata()
        .map_err(|error| format!("could not inspect held prebuild output root: {error}"))?;
    if !opened.is_dir()
        || (opened.dev(), opened.ino()) != expected_identity
        || (metadata.dev(), metadata.ino()) != expected_identity
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.mode() & 0o777 != 0o700
    {
        return Err("prebuild output root changed before it could be held".into());
    }
    Ok(PrivateOutputRoot {
        canonical_path: canonical,
        directory,
    })
}

fn publish_prebuild_directory(
    output_root: &PrivateOutputRoot,
    final_name: &str,
    files: &[(&str, &[u8])],
    arm_publication: &mut impl FnMut(&str, (u64, u64)) -> Result<(), String>,
) -> Result<(u64, u64), String> {
    publish_prebuild_directory_with_arm(
        output_root,
        final_name,
        files,
        arm_publication,
        File::sync_all,
    )
}

#[cfg(test)]
fn publish_prebuild_directory_with(
    output_root: &PrivateOutputRoot,
    final_name: &str,
    files: &[(&str, &[u8])],
    mut sync_parent: impl FnMut(&File) -> io::Result<()>,
) -> Result<(u64, u64), String> {
    publish_prebuild_directory_with_arm(
        output_root,
        final_name,
        files,
        &mut |_, _| Ok(()),
        &mut sync_parent,
    )
}

fn publish_prebuild_directory_with_arm(
    output_root: &PrivateOutputRoot,
    final_name: &str,
    files: &[(&str, &[u8])],
    arm_publication: &mut impl FnMut(&str, (u64, u64)) -> Result<(), String>,
    mut sync_parent: impl FnMut(&File) -> io::Result<()>,
) -> Result<(u64, u64), String> {
    verify_private_output_root_path(output_root)?;
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let staging_name = format!(".lab002-prebuild-{}", lower_hex(&random));
    let parent = &output_root.directory;
    rustix::fs::mkdirat(
        parent,
        staging_name.as_str(),
        rustix::fs::Mode::from_raw_mode(0o700),
    )
    .map_err(|error| format!("could not create private prebuild staging directory: {error}"))?;
    let staging = match rustix::fs::openat(
        parent,
        staging_name.as_str(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(directory) => File::from(directory),
        Err(error) => {
            let cleanup = cleanup_unpublished_staging_entry(
                parent,
                staging_name.as_str(),
                None,
                &mut sync_parent,
            );
            if let Err(cleanup_error) = cleanup {
                return Err(format!(
                    "prebuild staging cleanup is indeterminate after its descriptor could not be \
                     opened: {cleanup_error}; original failure: {error}"
                ));
            }
            return Err(format!(
                "could not hold private prebuild staging directory safely: {error}"
            ));
        }
    };
    let staging_metadata = match staging.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            let cleanup = cleanup_unpublished_staging_entry(
                parent,
                staging_name.as_str(),
                Some(&staging),
                &mut sync_parent,
            );
            if let Err(cleanup_error) = cleanup {
                return Err(format!(
                    "prebuild staging cleanup is indeterminate after its metadata could not be \
                     inspected: {cleanup_error}; original failure: {error}"
                ));
            }
            return Err(format!(
                "could not inspect held private prebuild staging directory: {error}"
            ));
        }
    };
    if !staging_metadata.is_dir()
        || staging_metadata.uid() != rustix::process::geteuid().as_raw()
        || staging_metadata.mode() & 0o777 != 0o700
    {
        let cleanup = cleanup_unpublished_staging_entry(
            parent,
            staging_name.as_str(),
            Some(&staging),
            &mut sync_parent,
        );
        if let Err(cleanup_error) = cleanup {
            return Err(format!(
                "prebuild staging cleanup is indeterminate after unsafe metadata was observed: \
                 {cleanup_error}"
            ));
        }
        return Err("private prebuild staging directory has unsafe permissions".into());
    }
    let staging_identity = (staging_metadata.dev(), staging_metadata.ino());
    if let Err(error) = arm_publication(&staging_name, staging_identity) {
        let cleanup = cleanup_staging_directory_durably(
            &staging,
            staging_identity,
            &[],
            parent,
            &staging_name,
            None,
            &mut sync_parent,
        );
        if let Err(cleanup_error) = cleanup {
            return Err(format!(
                "prebuild staging cleanup is indeterminate after rollback could not be armed: \
                 {cleanup_error}; original failure: {error}"
            ));
        }
        return Err(format!("could not arm prebuild rollback: {error}"));
    }

    let mut publication_renamed_back = false;
    let mut publication_may_be_live = false;
    let result = (|| {
        for (name, bytes) in files {
            write_private_file(&staging, name, bytes)?;
        }
        staging
            .sync_all()
            .map_err(|error| format!("could not fsync prebuild staging directory: {error}"))?;

        publication_may_be_live = true;
        rustix::fs::renameat_with(
            parent,
            staging_name.as_str(),
            parent,
            final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| format!("could not publish prebuild directory exclusively: {error}"))?;
        if let Err(sync_error) = sync_parent(parent) {
            let rollback = rustix::fs::renameat_with(
                parent,
                final_name,
                parent,
                staging_name.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            );
            if rollback.is_ok() {
                publication_renamed_back = true;
                publication_may_be_live = false;
                return Err(format!(
                    "could not fsync prebuild output root after publication: {sync_error}"
                ));
            }
            return Err(format!(
                "prebuild publication is indeterminate after output-root fsync failed; \
                 do not retry this tuple until the private output root is reconciled: \
                 {sync_error}"
            ));
        }
        verify_private_output_root_path(output_root)?;
        verify_published_directory_identity(parent, final_name, staging_identity)?;
        Ok(())
    })();

    if result.is_err() {
        if let Err(cleanup_error) = cleanup_staging_directory_durably(
            &staging,
            staging_identity,
            files,
            parent,
            &staging_name,
            publication_may_be_live.then_some(final_name),
            &mut sync_parent,
        ) {
            return Err(format!(
                "prebuild staging cleanup is indeterminate after preparation failed: \
                 {cleanup_error}; original failure: {}",
                result.as_ref().unwrap_err()
            ));
        }
        if publication_renamed_back {
            return Err(format!(
                "prebuild publication was durably rolled back after preparation failed: {}",
                result.as_ref().unwrap_err()
            ));
        }
    }
    result.map(|()| staging_identity)
}

fn verify_published_directory_identity(
    parent: &File,
    final_name: &str,
    expected_identity: (u64, u64),
) -> Result<(), String> {
    let published = open_directory_entry(parent, final_name)
        .map_err(|error| format!("could not reopen published prebuild directory: {error}"))?;
    let metadata = published
        .metadata()
        .map_err(|error| format!("could not inspect published prebuild directory: {error}"))?;
    if (metadata.dev(), metadata.ino()) != expected_identity
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("published prebuild directory changed identity before success".into());
    }
    Ok(())
}

fn inspect_published_artifacts(
    parent: &File,
    final_name: &str,
    expected_files: &[(&str, &[u8])],
    expected_directory_identity: (u64, u64),
) -> Result<Vec<PrivateArtifactIdentity>, String> {
    let published = open_directory_entry(parent, final_name)
        .map_err(|error| format!("could not reopen published prebuild directory: {error}"))?;
    let directory_metadata = published
        .metadata()
        .map_err(|error| format!("could not inspect published prebuild directory: {error}"))?;
    if (directory_metadata.dev(), directory_metadata.ino()) != expected_directory_identity
        || directory_metadata.uid() != rustix::process::geteuid().as_raw()
        || directory_metadata.mode() & 0o777 != 0o700
    {
        return Err("published prebuild directory changed before artifact binding".into());
    }

    expected_files
        .iter()
        .map(|(name, expected_bytes)| {
            let descriptor = rustix::fs::openat(
                &published,
                *name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| format!("could not bind published private artifact: {error}"))?;
            let mut file = File::from(descriptor);
            let before = file.metadata().map_err(|error| {
                format!("could not inspect published private artifact: {error}")
            })?;
            let mut bytes = Vec::with_capacity(expected_bytes.len());
            file.read_to_end(&mut bytes)
                .map_err(|error| format!("could not read published private artifact: {error}"))?;
            let after = file.metadata().map_err(|error| {
                format!("could not recheck published private artifact: {error}")
            })?;
            if !before.is_file()
                || before.uid() != rustix::process::geteuid().as_raw()
                || before.mode() & 0o777 != 0o400
                || before.len() != expected_bytes.len() as u64
                || bytes != *expected_bytes
                || (after.dev(), after.ino(), after.len(), after.mtime())
                    != (before.dev(), before.ino(), before.len(), before.mtime())
            {
                return Err("published private artifact changed before binding".into());
            }
            Ok(PrivateArtifactIdentity {
                name: (*name).into(),
                device: before.dev().to_string(),
                inode: before.ino().to_string(),
                mode: before.mode() & 0o777,
                size: before.len(),
                sha256: sha256_hex(&bytes),
            })
        })
        .collect()
}

fn verify_private_output_root_path(output_root: &PrivateOutputRoot) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(&output_root.canonical_path)
        .map_err(|error| format!("prebuild output root changed during publication: {error}"))?;
    let held_metadata = output_root
        .directory
        .metadata()
        .map_err(|error| format!("held prebuild output root became invalid: {error}"))?;
    if !path_metadata.is_dir()
        || path_metadata.file_type().is_symlink()
        || (path_metadata.dev(), path_metadata.ino()) != (held_metadata.dev(), held_metadata.ino())
        || path_metadata.uid() != rustix::process::geteuid().as_raw()
        || held_metadata.uid() != rustix::process::geteuid().as_raw()
        || path_metadata.mode() & 0o777 != 0o700
        || held_metadata.mode() & 0o777 != 0o700
    {
        return Err("prebuild output root changed during publication".into());
    }
    Ok(())
}

fn cleanup_unpublished_staging_entry(
    parent: &File,
    staging_name: &str,
    staging: Option<&File>,
    sync_parent: &mut impl FnMut(&File) -> io::Result<()>,
) -> Result<(), String> {
    let staging_sync_error = staging.and_then(|directory| directory.sync_all().err());
    let removal_error =
        rustix::fs::unlinkat(parent, staging_name, rustix::fs::AtFlags::REMOVEDIR).err();
    let parent_sync_error = sync_parent(parent).err();
    if staging_sync_error.is_none() && removal_error.is_none() && parent_sync_error.is_none() {
        return Ok(());
    }
    Err(format!(
        "staging fsync: {}; removal: {}; parent fsync: {}",
        staging_sync_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "synced".into()),
        removal_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "removed".into()),
        parent_sync_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "synced".into())
    ))
}

fn cleanup_staging_directory_durably(
    staging: &File,
    staging_identity: (u64, u64),
    files: &[(&str, &[u8])],
    parent: &File,
    staging_name: &str,
    live_name: Option<&str>,
    sync_parent: &mut impl FnMut(&File) -> io::Result<()>,
) -> Result<(), String> {
    let cleanup_error = cleanup_staging_directory(
        staging,
        staging_identity,
        files,
        parent,
        staging_name,
        live_name,
    )
    .err();
    let sync_error = sync_parent(parent).err();
    if cleanup_error.is_none() && sync_error.is_none() {
        return Ok(());
    }

    let cleanup_detail = cleanup_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "removed, but parent-directory durability is unproven".into());
    let sync_detail = sync_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "parent directory synced".into());
    Err(format!(
        "cleanup error: {cleanup_detail}; parent fsync: {sync_detail}"
    ))
}

fn cleanup_staging_directory(
    staging: &File,
    staging_identity: (u64, u64),
    files: &[(&str, &[u8])],
    parent: &File,
    staging_name: &str,
    live_name: Option<&str>,
) -> io::Result<()> {
    let mut first_error = None;
    for (name, _) in files {
        if let Err(error) = rustix::fs::unlinkat(staging, *name, rustix::fs::AtFlags::empty()) {
            if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                first_error = Some(io::Error::from(error));
            }
        }
    }
    if let Err(error) = staging.sync_all() {
        if first_error.is_none() {
            first_error = Some(error);
        }
    }
    for candidate in [Some(staging_name), live_name].into_iter().flatten() {
        match open_directory_entry(parent, candidate) {
            Ok(directory) => {
                let metadata = directory.metadata()?;
                if (metadata.dev(), metadata.ino()) != staging_identity {
                    continue;
                }
                if let Err(error) =
                    rustix::fs::unlinkat(parent, candidate, rustix::fs::AtFlags::REMOVEDIR)
                {
                    if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                        first_error = Some(io::Error::from(error));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn open_directory_entry(parent: &File, name: &str) -> io::Result<File> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn write_private_file(directory: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o400),
    )
    .map_err(|error| format!("could not create private artifact: {error}"))?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not durably write private artifact: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect private artifact: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o400
        || metadata.len() != bytes.len() as u64
    {
        return Err("private artifact identity or permissions are invalid".into());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchardprobe_core::lab002::FixedSectionSlice;
    use orchardprobe_core::macho::{EncryptionCommand, EncryptionInfo, MachOContainer};
    use tempfile::TempDir;

    #[test]
    fn pem_certificate_inventory_is_bounded_and_canonical() {
        let bundle = b"\n-----BEGIN CERTIFICATE-----\r\nQUJD\r\n-----END CERTIFICATE-----\r\n\
-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n";
        assert_eq!(
            parse_pem_certificates(bundle, "test chain").unwrap(),
            vec![
                b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_vec(),
                b"-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n".to_vec(),
            ]
        );
        assert!(parse_pem_certificates(b"not a certificate", "test chain").is_err());
        assert!(
            parse_pem_certificates(b"-----BEGIN CERTIFICATE-----\nQUJD\n", "test chain",).is_err()
        );
    }

    fn target(role: LabRole, bundle_id: &str, team: &str, app_group: bool) -> AuthorizedTarget {
        AuthorizedTarget {
            role,
            bundle_id: bundle_id.into(),
            code_directory_identifier: bundle_id.into(),
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

    fn request() -> PrepareRequest {
        PrepareRequest {
            schema: REQUEST_SCHEMA.into(),
            source_commit: "11".repeat(20),
            marketing_version: "1.0".into(),
            build_number: "3".into(),
            configuration: "Release".into(),
            observer_revision: "lab002-observer-v1".into(),
            toolchain: Toolchain {
                xcode_version: "26.0".into(),
                xcode_build: "17A100".into(),
                iphoneos_sdk_version: "26.0".into(),
                iphoneos_sdk_build: "23A100".into(),
                xcodegen_version: "2.46.0".into(),
                xcodegen_architecture: "arm64".into(),
                xcodegen_executable_sha256: "22".repeat(32),
                fastlane_version: "2.228.0".into(),
                gemfile_lock_sha256: "33".repeat(32),
            },
            targets: vec![
                target(
                    LabRole::MainApp,
                    "com.example.orchardprobe.demolab",
                    "ABCDEFGHIJ",
                    true,
                ),
                target(
                    LabRole::Framework,
                    "com.example.orchardprobe.demolab.framework",
                    "ABCDEFGHIJ",
                    false,
                ),
                target(
                    LabRole::ShareExtension,
                    "com.example.orchardprobe.demolab.share",
                    "ABCDEFGHIJ",
                    true,
                ),
            ],
        }
    }

    fn inspect_request(source: &PrepareRequest) -> InspectPrebuildRequest {
        InspectPrebuildRequest {
            schema: INSPECT_REQUEST_SCHEMA.into(),
            source_commit: source.source_commit.clone(),
            marketing_version: source.marketing_version.clone(),
            build_number: source.build_number.clone(),
            configuration: source.configuration.clone(),
            observer_revision: source.observer_revision.clone(),
            toolchain: source.toolchain.clone(),
            targets: source.targets.clone(),
        }
    }

    fn inspect_prebuild_path(
        path: &Path,
        request: InspectPrebuildRequest,
    ) -> Result<InspectPrebuildOutput, String> {
        let directory = validate_private_output_root(path)?;
        inspect_prebuild_directory(directory, request)
    }

    #[test]
    fn prepare_publishes_closed_owner_only_artifacts() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let mut armed_publication = None;
        let output = prepare_with_publication_arm(&root, request(), |staging_name, identity| {
            armed_publication = Some((staging_name.to_owned(), identity));
            Ok(())
        })
        .unwrap();
        let directory = PathBuf::from(&output.prebuild_directory);
        assert!(directory.is_dir());
        let directory_metadata = directory.metadata().unwrap();
        assert_eq!(
            output.prebuild_directory_device,
            directory_metadata.dev().to_string()
        );
        assert_eq!(
            output.prebuild_directory_inode,
            directory_metadata.ino().to_string()
        );
        for name in [PRIVATE_SEED_NAME, MANIFEST_NAME, PREBUILD_NAME] {
            let metadata = fs::symlink_metadata(directory.join(name)).unwrap();
            assert!(metadata.is_file());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.mode() & 0o777, 0o400);
        }
        assert_eq!(output.private_artifacts.len(), 3);
        for (artifact, name) in
            output
                .private_artifacts
                .iter()
                .zip([PRIVATE_SEED_NAME, MANIFEST_NAME, PREBUILD_NAME])
        {
            let path = directory.join(name);
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(artifact.name, name);
            assert_eq!(artifact.device, metadata.dev().to_string());
            assert_eq!(artifact.inode, metadata.ino().to_string());
            assert_eq!(artifact.mode, 0o400);
            assert_eq!(artifact.size, metadata.len());
            assert_eq!(artifact.sha256, sha256_hex(&fs::read(path).unwrap()));
        }
        assert_eq!(
            fs::read(directory.join(PRIVATE_SEED_NAME)).unwrap().len(),
            32
        );
        let manifest_bytes = fs::read(directory.join(MANIFEST_NAME)).unwrap();
        let manifest = AuthorizedTargetManifest::from_canonical_bytes(&manifest_bytes).unwrap();
        assert_eq!(manifest.targets.len(), 3);
        assert_eq!(
            sha256_hex(&manifest_bytes),
            output.authorized_target_manifest_sha256
        );
        let mut wire_output = Vec::new();
        let (staging_name, armed_identity) = armed_publication.unwrap();
        write_publication_identity(&mut wire_output, &staging_name, armed_identity).unwrap();
        write_command_result(&mut wire_output, &CommandOutput::Prepare(output)).unwrap();
        let wire_output = String::from_utf8(wire_output).unwrap();
        let (identity_line, result_line) = wire_output.split_once('\n').unwrap();
        assert_eq!(
            identity_line,
            format!(
                "{} {} {} {}",
                PUBLICATION_IDENTITY_SCHEMA,
                staging_name,
                directory_metadata.dev(),
                directory_metadata.ino()
            )
        );
        let decoded: serde_json::Value = serde_json::from_str(result_line.trim()).unwrap();
        assert_eq!(
            decoded["prebuild_directory_device"],
            directory_metadata.dev().to_string()
        );
        assert_eq!(
            decoded["prebuild_directory_inode"],
            directory_metadata.ino().to_string()
        );
    }

    #[test]
    fn inspect_prebuild_closes_seed_manifest_record_and_expected_tuple() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let prepare_request = request();
        let prepared = prepare(&root, request()).unwrap();
        let directory = PathBuf::from(prepared.prebuild_directory);
        let inspected =
            inspect_prebuild_path(&directory, inspect_request(&prepare_request)).unwrap();

        assert_eq!(inspected.schema, INSPECT_RESULT_SCHEMA);
        assert_eq!(inspected.source_commit, prepare_request.source_commit);
        assert_eq!(
            inspected.authorized_target_manifest_sha256,
            prepared.authorized_target_manifest_sha256
        );
        assert_eq!(
            inspected.build_binding_sha256,
            prepared.build_binding_sha256
        );
        assert_eq!(
            inspected.target_identity_set_sha256,
            prepared.target_identity_set_sha256
        );
        let seed_bytes: [u8; 32] = fs::read(directory.join(PRIVATE_SEED_NAME))
            .unwrap()
            .try_into()
            .unwrap();
        let expected_public_key = SigningKey::from_bytes(&seed_bytes)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            inspected.authorization_public_key,
            lower_hex(&expected_public_key)
        );
        assert_eq!(
            inspected.authorization_key_id,
            sha256_hex(&expected_public_key)
        );
    }

    #[test]
    fn private_artifact_read_rejects_permissions_changed_during_read() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let artifact_path = root.path().join(PRIVATE_SEED_NAME);
        fs::write(&artifact_path, [0x42; 32]).unwrap();
        fs::set_permissions(
            &artifact_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )
        .unwrap();
        let directory = File::open(root.path()).unwrap();

        let error = read_private_artifact_with(&directory, PRIVATE_SEED_NAME, 32, || {
            fs::set_permissions(
                &artifact_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
        })
        .unwrap_err();

        assert!(error.contains("changed while it was read"));
    }

    #[test]
    fn inspect_prebuild_rejects_tuple_drift_and_extra_artifacts() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let prepared = prepare(&root, request()).unwrap();
        let directory = PathBuf::from(prepared.prebuild_directory);

        let mut changed_request = inspect_request(&request());
        changed_request.targets[0].bundle_id = "com.example.substituted".into();
        assert!(
            inspect_prebuild_path(&directory, changed_request)
                .unwrap_err()
                .contains("exact authorized tuple")
        );

        fs::write(directory.join("unexpected-private"), b"private").unwrap();
        assert!(
            inspect_prebuild_path(&directory, inspect_request(&request()))
                .unwrap_err()
                .contains("exact three artifacts")
        );
    }

    #[test]
    fn inspect_prebuild_rejects_seed_and_record_substitution() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let prepared = prepare(&root, request()).unwrap();
        let directory = PathBuf::from(prepared.prebuild_directory);
        let seed_path = directory.join(PRIVATE_SEED_NAME);
        fs::set_permissions(
            &seed_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        fs::write(&seed_path, [0x55; 32]).unwrap();
        fs::set_permissions(
            &seed_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )
        .unwrap();
        assert!(
            inspect_prebuild_path(&directory, inspect_request(&request()))
                .unwrap_err()
                .contains("one exact authorized tuple")
        );

        let second_root = TempDir::new().unwrap();
        fs::set_permissions(
            second_root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let second_root = second_root.path().canonicalize().unwrap();
        let second = prepare(&second_root, request()).unwrap();
        let second_directory = PathBuf::from(second.prebuild_directory);
        let record_path = second_directory.join(PREBUILD_NAME);
        let canonical = fs::read_to_string(&record_path).unwrap();
        fs::set_permissions(
            &record_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        fs::write(&record_path, format!("{canonical}\n")).unwrap();
        fs::set_permissions(
            &record_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )
        .unwrap();
        assert!(
            inspect_prebuild_path(&second_directory, inspect_request(&request()))
                .unwrap_err()
                .contains("exact canonical JSON")
        );
    }

    #[test]
    fn prepare_refuses_to_overwrite_an_existing_tuple() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        prepare(&root, request()).unwrap();
        let error = prepare(&root, request()).unwrap_err();
        assert!(error.contains("exclusively"));
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".lab002-prebuild-")
        }));
    }

    #[test]
    fn publication_rolls_back_when_the_first_parent_fsync_fails() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let root = validate_private_output_root(&root_path).unwrap();
        let mut sync_calls = 0;
        let error = publish_prebuild_directory_with(
            &root,
            "lab002-prebuild-test",
            &[("private.bin", b"private")],
            |_| {
                sync_calls += 1;
                if sync_calls == 1 {
                    Err(io::Error::other("injected parent fsync failure"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(error.contains("publication was durably rolled back"));
        assert_eq!(sync_calls, 2);
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
    }

    #[test]
    fn publication_arm_failure_cleans_before_private_bytes_are_written() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let root = validate_private_output_root(&root_path).unwrap();
        let error = publish_prebuild_directory_with_arm(
            &root,
            "lab002-prebuild-test",
            &[("private.bin", b"private")],
            &mut |_, _| Err("injected rollback-arm failure".into()),
            File::sync_all,
        )
        .unwrap_err();

        assert!(error.contains("could not arm prebuild rollback"));
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
    }

    #[test]
    fn failed_prepublication_is_durably_cleaned() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let root = validate_private_output_root(&root_path).unwrap();
        let mut sync_calls = 0;
        let error = publish_prebuild_directory_with(
            &root,
            "lab002-prebuild-test",
            &[("private.bin", b"private"), ("private.bin", b"duplicate")],
            |_| {
                sync_calls += 1;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("could not create private artifact"));
        assert_eq!(sync_calls, 1);
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
    }

    #[test]
    fn failed_prepublication_reports_indeterminate_cleanup_durability() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let root = validate_private_output_root(&root_path).unwrap();
        let mut sync_calls = 0;
        let error = publish_prebuild_directory_with(
            &root,
            "lab002-prebuild-test",
            &[("private.bin", b"private"), ("private.bin", b"duplicate")],
            |_| {
                sync_calls += 1;
                Err(io::Error::other("injected cleanup fsync failure"))
            },
        )
        .unwrap_err();

        assert!(error.contains("staging cleanup is indeterminate"));
        assert!(error.contains("injected cleanup fsync failure"));
        assert_eq!(sync_calls, 1);
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
    }

    #[test]
    fn cleanup_continues_when_a_staging_file_is_missing() {
        let root = TempDir::new().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("created-later.bin"), b"private").unwrap();
        let parent = File::open(root.path()).unwrap();
        let staging_handle = open_directory_entry(&parent, "staging").unwrap();
        let metadata = staging_handle.metadata().unwrap();

        cleanup_staging_directory(
            &staging_handle,
            (metadata.dev(), metadata.ino()),
            &[
                ("never-created.bin", b"" as &[u8]),
                ("created-later.bin", b"private" as &[u8]),
            ],
            &parent,
            "staging",
            None,
        )
        .unwrap();

        assert!(!staging.exists());
    }

    #[test]
    fn publication_detects_output_root_replacement_and_removes_private_files() {
        let parent = TempDir::new().unwrap();
        let root_path = parent.path().join("output");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(
            &root_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let canonical = root_path.canonicalize().unwrap();
        let root = validate_private_output_root(&canonical).unwrap();
        let moved_path = parent.path().join("moved-output");
        let mut replaced = false;

        let error = publish_prebuild_directory_with(
            &root,
            "lab002-prebuild-test",
            &[("private.bin", b"private")],
            |directory| {
                directory.sync_all()?;
                if !replaced {
                    fs::rename(&root_path, &moved_path)?;
                    fs::create_dir(&root_path)?;
                    fs::set_permissions(
                        &root_path,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )?;
                    replaced = true;
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("output root changed during publication"));
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
        assert!(fs::read_dir(&moved_path).unwrap().next().is_none());
    }

    #[test]
    fn inherited_output_root_rejects_a_replaced_path_before_preparation() {
        let parent = TempDir::new().unwrap();
        let root_path = parent.path().join("output");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(
            &root_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let canonical = root_path.canonicalize().unwrap();
        let held = File::open(&canonical).unwrap();
        let held_metadata = held.metadata().unwrap();
        let expected_identity = (held_metadata.dev(), held_metadata.ino());
        let moved_path = parent.path().join("held-output");
        fs::rename(&root_path, &moved_path).unwrap();
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(
            &root_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        let error =
            validate_bound_private_output_root(&canonical, held, expected_identity).unwrap_err();

        assert!(error.contains("changed before it could be held"));
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
        assert!(fs::read_dir(&moved_path).unwrap().next().is_none());
    }

    #[test]
    fn inherited_output_root_rejects_a_mismatched_expected_identity() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let held = File::open(&canonical).unwrap();
        let metadata = held.metadata().unwrap();

        let error = validate_bound_private_output_root(
            &canonical,
            held,
            (metadata.dev(), metadata.ino().wrapping_add(1)),
        )
        .unwrap_err();

        assert!(error.contains("changed before it could be held"));
    }

    #[test]
    fn publication_detects_final_entry_substitution_and_removes_private_files() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let held_root = validate_private_output_root(&root_path).unwrap();
        let final_name = "lab002-prebuild-test";
        let final_path = root_path.join(final_name);
        let moved_path = root_path.join("moved-published");
        let mut substituted = false;

        let error = publish_prebuild_directory_with(
            &held_root,
            final_name,
            &[("private.bin", b"private")],
            |directory| {
                directory.sync_all()?;
                if !substituted {
                    fs::rename(&final_path, &moved_path)?;
                    fs::create_dir(&final_path)?;
                    fs::set_permissions(
                        &final_path,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )?;
                    fs::write(final_path.join("replacement.bin"), b"replacement")?;
                    substituted = true;
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("changed identity before success"));
        assert!(!moved_path.join("private.bin").exists());
        assert_eq!(
            fs::read(final_path.join("replacement.bin")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn publication_detects_relaxed_output_root_permissions_and_rolls_back() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let held_root = validate_private_output_root(&root_path).unwrap();
        let mut relaxed = false;

        let error = publish_prebuild_directory_with(
            &held_root,
            "lab002-prebuild-test",
            &[("private.bin", b"private")],
            |directory| {
                directory.sync_all()?;
                if !relaxed {
                    fs::set_permissions(
                        &root_path,
                        std::os::unix::fs::PermissionsExt::from_mode(0o755),
                    )?;
                    relaxed = true;
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("output root changed during publication"));
        assert!(fs::read_dir(&root_path).unwrap().next().is_none());
        fs::set_permissions(
            &root_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn prepare_distinguishes_full_commits_with_the_same_short_prefix() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let first = request();
        let mut second = request();
        second.source_commit = format!("{}{}", &first.source_commit[..12], "22".repeat(14));

        let first_output = prepare(&root, first).unwrap();
        let second_output = prepare(&root, second).unwrap();
        assert_ne!(
            first_output.prebuild_directory,
            second_output.prebuild_directory
        );
    }

    #[test]
    fn prepare_rejects_path_shaping_fields_before_publication() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();

        for mutate in [
            |request: &mut PrepareRequest| request.source_commit = "../escape".into(),
            |request: &mut PrepareRequest| request.marketing_version = "1/escape".into(),
            |request: &mut PrepareRequest| request.build_number = "../3".into(),
            |request: &mut PrepareRequest| request.marketing_version = "1.1".into(),
            |request: &mut PrepareRequest| request.build_number = "4".into(),
        ] {
            let mut request = request();
            mutate(&mut request);
            assert!(prepare(&root, request).is_err());
        }
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    fn fixed_report(section_byte: u8, signature_byte: u8) -> FixedSectionReport {
        FixedSectionReport {
            container: MachOContainer::Thin,
            file_size: 4096,
            slices: vec![FixedSectionSlice {
                ordinal: 0,
                cpu_type: 0x0100_000c,
                cpu_subtype: 0,
                macho_uuid: "44".repeat(16),
                slice_file_offset: 0,
                slice_file_size: 4096,
                section_slice_offset: 512,
                section_file_offset: 512,
                section_vm_offset: 512,
                section_length: 256,
                section_sha256: format!("{section_byte:02x}").repeat(32),
                fixup_layout_sha256: "33".repeat(32),
                encryption: Some(EncryptionInfo {
                    command: EncryptionCommand::EncryptionInfo64,
                    cryptoff: 0,
                    cryptsize: 2048,
                    cryptid: 0,
                }),
                signing: Some(PreuploadSigningMetadata {
                    superblob_sha256: format!("{signature_byte:02x}").repeat(32),
                    code_directory_identifier: "com.example.orchardprobe.demolab".into(),
                    code_directory_team_identifier: "ABCDEFGHIJ".into(),
                    application_identifier: Some(
                        "ABCDEFGHIJ.com.example.orchardprobe.demolab".into(),
                    ),
                    developer_team_identifier: Some("ABCDEFGHIJ".into()),
                    application_groups: Some(vec!["group.com.example.demolab".into()]),
                    is_ad_hoc: false,
                    has_cms: true,
                    code_directory: vec![0x44],
                    cms_signature: vec![0x55],
                }),
            }],
        }
    }

    #[test]
    fn oracle_identity_requires_artifact_bundle_metadata_and_verified_cms() {
        let authorized = target(
            LabRole::MainApp,
            "com.example.orchardprobe.demolab",
            "ABCDEFGHIJ",
            true,
        );
        let identity = ParsedInfoPlist {
            bundle_identifier: authorized.bundle_id.clone(),
            bundle_version: "3".into(),
            short_version: Some("1.0".into()),
            executable_name: "DemoLab".into(),
        };
        validate_bundle_identity(
            &identity,
            &authorized,
            LabRole::MainApp,
            "1.0",
            "3",
            "Archive",
        )
        .unwrap();
        let mut substituted = identity;
        substituted.bundle_identifier = "com.example.substituted".into();
        assert!(
            validate_bundle_identity(
                &substituted,
                &authorized,
                LabRole::MainApp,
                "1.0",
                "3",
                "Archive",
            )
            .is_err()
        );

        let signing = PreuploadSigningMetadata {
            superblob_sha256: "44".repeat(32),
            code_directory_identifier: authorized.code_directory_identifier,
            code_directory_team_identifier: authorized.code_directory_team_identifier,
            application_identifier: None,
            developer_team_identifier: None,
            application_groups: None,
            is_ad_hoc: false,
            has_cms: false,
            code_directory: vec![0x30],
            cms_signature: Vec::new(),
        };
        assert!(verify_cms_signature(&signing).is_err());
    }

    #[test]
    fn oracle_role_closure_requires_exact_archive_ipa_parity() {
        let archive = fixed_report(0x44, 0x55);
        let ipa = fixed_report(0x44, 0x66);
        let role = close_oracle_role(LabRole::MainApp, "77".repeat(32), &archive, &ipa).unwrap();
        assert_eq!(role.slices[0].expected_plaintext_sha256, "44".repeat(32));
        assert_eq!(role.slices[0].ipa_section_sha256, "44".repeat(32));
        assert_eq!(role.slices[0].code_signature_sha256, "66".repeat(32));

        let mut changed_uuid = ipa.clone();
        changed_uuid.slices[0].macho_uuid = "88".repeat(16);
        assert!(
            close_oracle_role(LabRole::MainApp, "77".repeat(32), &archive, &changed_uuid,).is_err()
        );
        let mut changed_range = ipa.clone();
        changed_range.slices[0].section_slice_offset += 1;
        assert!(
            close_oracle_role(LabRole::MainApp, "77".repeat(32), &archive, &changed_range,)
                .is_err()
        );
        let mut changed_plaintext = ipa;
        changed_plaintext.slices[0].section_sha256 = "99".repeat(32);
        assert!(
            close_oracle_role(
                LabRole::MainApp,
                "77".repeat(32),
                &archive,
                &changed_plaintext,
            )
            .is_err()
        );

        let mut changed_fixups = archive.clone();
        changed_fixups.slices[0].fixup_layout_sha256 = "aa".repeat(32);
        assert!(
            close_oracle_role(
                LabRole::MainApp,
                "77".repeat(32),
                &changed_fixups,
                &fixed_report(0x44, 0x66),
            )
            .is_err()
        );
    }

    #[test]
    fn oracle_executable_inventory_is_order_independent_but_exact() {
        let expected = ["main", "framework", "extension"];
        assert!(same_paths_ignoring_order(
            vec!["extension", "main", "framework"],
            &expected,
        ));
        assert!(!same_paths_ignoring_order(
            vec!["main", "framework"],
            &expected,
        ));
        assert!(!same_paths_ignoring_order(
            vec!["main", "framework", "unexpected"],
            &expected,
        ));
    }

    #[test]
    fn oracle_publication_is_owner_only_atomic_and_non_overwriting() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let held = validate_private_output_root(&root_path).unwrap();
        let artifact = publish_oracle(&held, br#"{"schema":"test"}"#).unwrap();
        assert_eq!(artifact.name, ORACLE_NAME);
        assert_eq!(artifact.mode, 0o400);
        assert_eq!(
            fs::read(root_path.join(ORACLE_NAME)).unwrap(),
            br#"{"schema":"test"}"#
        );
        assert!(publish_oracle(&held, br#"{"schema":"replacement"}"#).is_err());
        assert_eq!(
            fs::read(root_path.join(ORACLE_NAME)).unwrap(),
            br#"{"schema":"test"}"#
        );
        assert_eq!(
            fs::read_dir(&root_path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from(ORACLE_NAME)]
        );
    }

    #[test]
    fn repository_boundary_uses_complete_path_components() {
        assert!(!Path::new("/tmp/orchardprobe-private").starts_with("/tmp/orchardprobe"));
        assert!(Path::new("/tmp/orchardprobe/private").starts_with("/tmp/orchardprobe"));
    }
}
