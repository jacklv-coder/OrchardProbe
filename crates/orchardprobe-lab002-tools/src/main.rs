//! Private, host-only build artifact tooling for the repository-owned DemoLab.
//!
//! This binary is invoked by the hardened Fastlane flow. It has no device,
//! upload, installation, decryption, or arbitrary-target operation.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use orchardprobe_core::lab002::artifacts::{
    AuthorizedTarget, AuthorizedTargetManifest, ClosedArtifact, Presence, RequiredAppGroups,
    RequiredEntitlement, Toolchain,
};
use orchardprobe_core::lab002::{
    AppGroups, BuildBindingInput, EntitlementValue, LAB002_PROFILE, LabRole, TargetIdentityInput,
    build_binding_sha256, canonical_json, target_identity_binding_sha256,
    target_identity_set_sha256,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_SCHEMA: &str = "orchardprobe.lab002.prebuild-request.v1";
const PREBUILD_SCHEMA: &str = "orchardprobe.lab002.prebuild.v1";
const MAX_REQUEST_BYTES: usize = 32 * 1024;
const PRIVATE_SEED_NAME: &str = "lab-002-authorization-seed-v1.bin";
const MANIFEST_NAME: &str = "lab-002-authorized-targets-v1.json";
const PREBUILD_NAME: &str = "lab-002-prebuild-v1.json";
const CHECKPOINT_MARKETING_VERSION: &str = "1.0";
const CHECKPOINT_BUILD_NUMBER: &str = "3";

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

#[derive(Debug, Serialize, Deserialize)]
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
    authorized_target_manifest_sha256: String,
    build_binding_sha256: String,
    target_identity_set_sha256: String,
}

fn main() -> ExitCode {
    match execute(std::env::args_os().skip(1).collect()) {
        Ok(output) => {
            if let Err(error) = writeln!(io::stdout().lock(), "{output}") {
                eprintln!("error: could not write result: {error}");
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

fn execute(arguments: Vec<std::ffi::OsString>) -> Result<String, String> {
    if arguments.len() != 3 || arguments[0] != "prepare" || arguments[1] != "--output-root" {
        return Err("usage: oprobe-lab002 prepare --output-root ABSOLUTE_PRIVATE_DIRECTORY".into());
    }
    let output_root = PathBuf::from(&arguments[2]);
    let request = read_request(io::stdin().lock())?;
    let result = prepare(&output_root, request)?;
    let bytes = canonical_json(&result).map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|_| "canonical result was not UTF-8".into())
}

fn read_request(mut input: impl Read) -> Result<PrepareRequest, String> {
    let mut bytes = Vec::with_capacity(4096);
    input
        .by_ref()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read the bounded prebuild request: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("prebuild request is empty or oversized".into());
    }
    let request: PrepareRequest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("prebuild request is invalid: {error}"))?;
    if request.schema != REQUEST_SCHEMA {
        return Err("prebuild request schema is invalid".into());
    }
    Ok(request)
}

fn prepare(output_root: &Path, request: PrepareRequest) -> Result<PrepareOutput, String> {
    validate_request(&request)?;
    let output_root = validate_private_output_root(output_root)?;
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

    publish_prebuild_directory(
        &output_root,
        &final_name,
        &[
            (PRIVATE_SEED_NAME, signing_key.as_bytes().as_slice()),
            (MANIFEST_NAME, &manifest_bytes),
            (PREBUILD_NAME, &record_bytes),
        ],
    )?;

    Ok(PrepareOutput {
        schema: "orchardprobe.lab002.prebuild-result.v1",
        prebuild_directory: output_root.join(final_name).display().to_string(),
        authorized_target_manifest_sha256: manifest_sha256,
        build_binding_sha256: build_binding,
        target_identity_set_sha256: identity_set,
    })
}

fn validate_request(request: &PrepareRequest) -> Result<(), String> {
    if request.source_commit.len() != 40
        || !request
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source commit must be exactly 40 lowercase hexadecimal characters".into());
    }
    if !valid_marketing_version(&request.marketing_version) {
        return Err("marketing version must contain one to three numeric components".into());
    }
    if request.build_number.is_empty()
        || request.build_number.len() > 18
        || request.build_number.starts_with('0')
        || !request
            .build_number
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err("build number must be a positive decimal integer of at most 18 digits".into());
    }
    if request.marketing_version != CHECKPOINT_MARKETING_VERSION
        || request.build_number != CHECKPOINT_BUILD_NUMBER
    {
        return Err("this helper only authorizes the reviewed DemoLab 1.0 (3) checkpoint".into());
    }
    if request.configuration != "Release"
        || request.targets.len() != LabRole::ALL.len()
        || request
            .targets
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

fn validate_private_output_root(path: &Path) -> Result<PathBuf, String> {
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
    Ok(canonical)
}

fn publish_prebuild_directory(
    output_root: &Path,
    final_name: &str,
    files: &[(&str, &[u8])],
) -> Result<(), String> {
    publish_prebuild_directory_with(output_root, final_name, files, File::sync_all)
}

fn publish_prebuild_directory_with(
    output_root: &Path,
    final_name: &str,
    files: &[(&str, &[u8])],
    mut sync_parent: impl FnMut(&File) -> io::Result<()>,
) -> Result<(), String> {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let staging_name = format!(".lab002-prebuild-{}", lower_hex(&random));
    let staging = output_root.join(&staging_name);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|error| format!("could not create private prebuild staging directory: {error}"))?;
    let staging_metadata = fs::symlink_metadata(&staging);
    if !matches!(
        staging_metadata,
        Ok(ref metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o777 == 0o700
    ) {
        let _ = fs::remove_dir(&staging);
        return Err("private prebuild staging directory has unsafe permissions".into());
    }
    let parent = match File::open(output_root) {
        Ok(parent) => parent,
        Err(error) => {
            let cleanup = cleanup_staging_directory(&staging, files);
            let cleanup_detail = cleanup
                .map(|()| "removal attempted, but durability is unproven".to_string())
                .unwrap_or_else(|cleanup_error| cleanup_error.to_string());
            return Err(format!(
                "prebuild staging cleanup is indeterminate because the output root could not be \
                 opened for fsync: {error}; cleanup attempt: {cleanup_detail}"
            ));
        }
    };

    let mut publication_renamed_back = false;
    let result = (|| {
        for (name, bytes) in files {
            write_private_file(&staging.join(name), bytes)?;
        }
        File::open(&staging)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("could not fsync prebuild staging directory: {error}"))?;

        rustix::fs::renameat_with(
            &parent,
            staging_name.as_str(),
            &parent,
            final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| format!("could not publish prebuild directory exclusively: {error}"))?;
        if let Err(sync_error) = sync_parent(&parent) {
            let rollback = rustix::fs::renameat_with(
                &parent,
                final_name,
                &parent,
                staging_name.as_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            );
            if rollback.is_ok() {
                publication_renamed_back = true;
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
        Ok(())
    })();

    if result.is_err() && staging.is_dir() {
        if let Err(cleanup_error) =
            cleanup_staging_directory_durably(&staging, files, &parent, &mut sync_parent)
        {
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
    result
}

fn cleanup_staging_directory_durably(
    staging: &Path,
    files: &[(&str, &[u8])],
    parent: &File,
    sync_parent: &mut impl FnMut(&File) -> io::Result<()>,
) -> Result<(), String> {
    let cleanup_error = cleanup_staging_directory(staging, files).err();
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

fn cleanup_staging_directory(staging: &Path, files: &[(&str, &[u8])]) -> io::Result<()> {
    let mut first_error = None;
    for (name, _) in files {
        if let Err(error) = fs::remove_file(staging.join(name)) {
            if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    if let Err(error) = fs::remove_dir(staging) {
        if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|error| format!("could not create private artifact: {error}"))?;
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
    use tempfile::TempDir;

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

    #[test]
    fn prepare_publishes_closed_owner_only_artifacts() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = root.path().canonicalize().unwrap();
        let output = prepare(&root, request()).unwrap();
        let directory = PathBuf::from(&output.prebuild_directory);
        assert!(directory.is_dir());
        for name in [PRIVATE_SEED_NAME, MANIFEST_NAME, PREBUILD_NAME] {
            let metadata = fs::symlink_metadata(directory.join(name)).unwrap();
            assert!(metadata.is_file());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.mode() & 0o777, 0o400);
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
        let root = root.path().canonicalize().unwrap();
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
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[test]
    fn failed_prepublication_is_durably_cleaned() {
        let root = TempDir::new().unwrap();
        let root = root.path().canonicalize().unwrap();
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
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[test]
    fn failed_prepublication_reports_indeterminate_cleanup_durability() {
        let root = TempDir::new().unwrap();
        let root = root.path().canonicalize().unwrap();
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
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[test]
    fn cleanup_continues_when_a_staging_file_is_missing() {
        let root = TempDir::new().unwrap();
        let staging = root.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("created-later.bin"), b"private").unwrap();

        cleanup_staging_directory(
            &staging,
            &[
                ("never-created.bin", b""),
                ("created-later.bin", b"private"),
            ],
        )
        .unwrap();

        assert!(!staging.exists());
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

    #[test]
    fn repository_boundary_uses_complete_path_components() {
        assert!(!Path::new("/tmp/orchardprobe-private").starts_with("/tmp/orchardprobe"));
        assert!(Path::new("/tmp/orchardprobe/private").starts_with("/tmp/orchardprobe"));
    }
}
