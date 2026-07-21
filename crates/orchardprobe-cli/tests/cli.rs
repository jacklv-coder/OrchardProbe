use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct TestFile(PathBuf);

impl TestFile {
    fn write(label: &str, contents: impl AsRef<[u8]>) -> Self {
        Self::write_with_extension(label, "json", contents)
    }

    fn write_macho(label: &str, contents: impl AsRef<[u8]>) -> Self {
        Self::write_with_extension(label, "macho", contents)
    }

    fn write_with_extension(label: &str, extension: &str, contents: impl AsRef<[u8]>) -> Self {
        let path = unique_path(label, extension);
        fs::write(&path, contents).expect("write temporary test file");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(label: &str) -> Self {
        let path = unique_path(label, "directory");
        fs::create_dir(&path).expect("create temporary test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn unique_path(label: &str, extension: &str) -> PathBuf {
    let sequence = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "orchardprobe-cli-{}-{sequence}-{label}.{extension}",
        std::process::id()
    ))
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn oprobe(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oprobe"))
        .args(args)
        .output()
        .expect("run oprobe")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn valid_manifest(binary_path: &str) -> Value {
    json!({
        "schema_version": 3,
        "tool_version": "0.1.0-test",
        "tool_revision": null,
        "target": {
            "bundle_id": "com.example.orchardprobe.test",
            "display_name": "OrchardProbe Test Fixture",
            "version": "1.0"
        },
        "backend": "test_fixture",
        "capability_ids": [],
        "binaries": [{
            "path": binary_path,
            "role": "main_executable",
            "architecture": "arm64",
            "slice": null,
            "input_size": null,
            "output_size": null,
            "outcome": "inconclusive",
            "evidence_level": "structure",
            "input_sha256": null,
            "output_sha256": null,
            "known_plaintext_sha256": null,
            "known_plaintext_evaluated": false,
            "signature": {
                "presence": "unknown",
                "kind": "unknown",
                "validation": "not_checked"
            },
            "ranges": [],
            "reason_codes": [
                "evidence.structure_only",
                "evidence.oracle_not_evaluated",
                "signature.not_checked"
            ],
            "notes": ["synthetic test data"]
        }],
        "warnings": []
    })
}

fn thin_macho64(cryptid: Option<u32>) -> Vec<u8> {
    const MACH_HEADER_64_SIZE: u32 = 32;
    const ENCRYPTION_COMMAND_SIZE: u32 = 24;
    const ENCRYPTED_BYTES: u32 = 8;

    let has_encryption = cryptid.is_some();
    let command_bytes = if has_encryption {
        ENCRYPTION_COMMAND_SIZE
    } else {
        0
    };
    let encrypted_offset = MACH_HEADER_64_SIZE + command_bytes;
    let mut bytes = Vec::with_capacity((encrypted_offset + ENCRYPTED_BYTES) as usize);

    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_000cu32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::from(has_encryption).to_le_bytes());
    bytes.extend_from_slice(&command_bytes.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());

    if let Some(cryptid) = cryptid {
        bytes.extend_from_slice(&0x2c_u32.to_le_bytes());
        bytes.extend_from_slice(&ENCRYPTION_COMMAND_SIZE.to_le_bytes());
        bytes.extend_from_slice(&encrypted_offset.to_le_bytes());
        bytes.extend_from_slice(&ENCRYPTED_BYTES.to_le_bytes());
        bytes.extend_from_slice(&cryptid.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }

    bytes.extend_from_slice(&[0xa5; ENCRYPTED_BYTES as usize]);
    bytes
}

fn thin_macho64_with_invalid_command_size() -> Vec<u8> {
    let mut bytes = thin_macho64(None);
    bytes.truncate(32);
    bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&8_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

#[test]
fn help_describes_the_safe_pre_alpha_commands() {
    let output = oprobe(&["--help"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("doctor"));
    assert!(text.contains("demo"));
    assert!(text.contains("inspect"));
    assert!(text.contains("verify"));
    assert!(text.contains("do not connect to an iOS device or process an IPA"));
}

#[test]
fn doctor_json_is_local_stable_and_accepts_trailing_global_flag() {
    let output = oprobe(&["doctor", "--json"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).is_empty());
    let text = stdout(&output);
    let report: Value = serde_json::from_str(&text).expect("doctor emits JSON");
    assert_eq!(report["status"], "pre_alpha");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["report_type"], "doctor");
    assert_eq!(report["device_backend"], "not_implemented");
    assert!(
        report["warnings"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let lower = text.to_ascii_lowercase();
    assert!(!lower.contains("timestamp"));
    assert!(!lower.contains("udid"));
    assert!(!lower.contains("device_id"));
}

#[test]
fn demo_is_device_free_and_explicitly_inconclusive() {
    let text_output = oprobe(&["demo"]);
    assert!(
        text_output.status.success(),
        "stderr: {}",
        stderr(&text_output)
    );
    let text = stdout(&text_output);
    assert!(text.contains("Device backend: not implemented"));
    assert!(text.contains("Declared outcome: inconclusive"));
    assert!(text.contains("manifest validation does not prove plaintext"));

    let json_output = oprobe(&["demo", "--json"]);
    assert!(
        json_output.status.success(),
        "stderr: {}",
        stderr(&json_output)
    );
    let manifest: Value =
        serde_json::from_slice(&json_output.stdout).expect("demo emits a JSON manifest");
    assert_eq!(manifest["schema_version"], 3);
    assert_eq!(manifest["backend"], "device_free_demo");
    assert_eq!(manifest["capability_ids"], json!([]));
    assert_eq!(manifest["binaries"][0]["outcome"], "inconclusive");
    assert_ne!(manifest["binaries"][0]["evidence_level"], "known_plaintext");
    assert_eq!(
        manifest["binaries"][0]["reason_codes"],
        json!([
            "backend.not_implemented",
            "evidence.structure_only",
            "evidence.oracle_not_evaluated"
        ])
    );
}

#[test]
fn inspect_json_reports_missing_encryption_metadata_without_plaintext_claims() {
    let file = TestFile::write_macho("no-encryption-command", thin_macho64(None));
    let path = file.path().to_str().expect("temporary path is UTF-8");

    let trailing_flag = oprobe(&["inspect", path, "--json"]);
    assert!(
        trailing_flag.status.success(),
        "stderr: {}",
        stderr(&trailing_flag)
    );
    assert!(stderr(&trailing_flag).is_empty());
    let report: Value = serde_json::from_slice(&trailing_flag.stdout).expect("inspect emits JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "inspect");
    assert_eq!(report["input_path"], path);
    assert_eq!(report["report"]["container"], "thin");
    assert_eq!(report["report"]["slices"][0]["architecture"], "arm64");
    assert_eq!(
        report["report"]["slices"][0]["encryption_state"],
        "not_declared"
    );
    assert!(report["report"]["slices"][0]["encryption"].is_null());
    assert_eq!(
        report["report"]["slices"][0]["plaintext_status"],
        "not_proven"
    );
    assert_eq!(report["evidence_level"], "metadata");
    assert_eq!(report["plaintext_proven"], false);
    assert_eq!(
        report["notice"],
        "Mach-O encryption metadata does not prove plaintext"
    );

    let leading_flag = oprobe(&["--json", "inspect", path]);
    assert!(
        leading_flag.status.success(),
        "stderr: {}",
        stderr(&leading_flag)
    );
    let leading_report: Value =
        serde_json::from_slice(&leading_flag.stdout).expect("leading --json emits JSON");
    assert_eq!(leading_report, report);
}

#[test]
fn inspect_json_distinguishes_cryptid_without_treating_zero_as_plaintext() {
    for (cryptid, expected_state) in [(0, "not_marked_encrypted"), (1, "marked_encrypted")] {
        let file =
            TestFile::write_macho(&format!("cryptid-{cryptid}"), thin_macho64(Some(cryptid)));
        let path = file.path().to_str().expect("temporary path is UTF-8");
        let output = oprobe(&["inspect", path, "--json"]);

        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(stderr(&output).is_empty());
        let report: Value = serde_json::from_slice(&output.stdout).expect("inspect emits JSON");
        let slice = &report["report"]["slices"][0];
        assert_eq!(slice["encryption_state"], expected_state);
        assert_eq!(slice["encryption"]["cryptid"], cryptid);
        assert_eq!(slice["plaintext_status"], "not_proven");
        assert_eq!(report["evidence_level"], "metadata");
        assert_eq!(report["plaintext_proven"], false);
    }
}

#[test]
fn inspect_text_is_clear_and_never_claims_plaintext() {
    for (label, cryptid, expected_metadata) in [
        (
            "text-no-command",
            None,
            "not declared (no encryption load command; not plaintext proof)",
        ),
        (
            "text-cryptid-zero",
            Some(0),
            "not marked encrypted by header metadata; not plaintext proof",
        ),
    ] {
        let file = TestFile::write_macho(label, thin_macho64(cryptid));
        let path = file.path().to_str().expect("temporary path is UTF-8");
        let output = oprobe(&["inspect", path]);

        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(stderr(&output).is_empty());
        let text = stdout(&output);
        assert!(text.contains("OrchardProbe inspect"));
        assert!(text.contains("Slice 0: arm64, 64-bit, little, execute"));
        assert!(text.contains(expected_metadata));
        assert!(text.contains("Evidence level: metadata"));
        assert!(text.contains("Plaintext proven: no"));
        assert!(text.contains("Mach-O encryption metadata does not prove plaintext."));
        assert!(text.contains("No device or IPA was accessed."));
        assert!(!text.contains("Plaintext proven: yes"));
    }
}

#[test]
fn inspect_rejects_non_macho_and_malformed_load_commands() {
    let non_macho = TestFile::write_macho("not-macho", b"ordinary text");
    let non_macho_path = non_macho.path().to_str().expect("temporary path is UTF-8");
    let non_macho_output = oprobe(&["inspect", non_macho_path, "--json"]);
    assert!(!non_macho_output.status.success());
    assert!(stdout(&non_macho_output).is_empty());
    let non_macho_error = stderr(&non_macho_output);
    assert!(non_macho_error.contains("error: invalid Mach-O"));
    assert!(non_macho_error.contains("unsupported Mach-O magic"));

    let malformed = TestFile::write_macho(
        "invalid-command-size",
        thin_macho64_with_invalid_command_size(),
    );
    let malformed_path = malformed.path().to_str().expect("temporary path is UTF-8");
    let malformed_output = oprobe(&["inspect", malformed_path]);
    assert!(!malformed_output.status.success());
    assert!(stdout(&malformed_output).is_empty());
    let malformed_error = stderr(&malformed_output);
    assert!(malformed_error.contains("error: invalid Mach-O"));
    assert!(malformed_error.contains("load command 0 has size 0"));
}

#[test]
fn inspect_rejects_truncated_macho() {
    let truncated = TestFile::write_macho("truncated", 0xfeed_facfu32.to_le_bytes());
    let path = truncated.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["inspect", path]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("error: invalid Mach-O"));
    assert!(stderr(&output).contains("Mach-O header"));
}

#[test]
fn inspect_rejects_directories() {
    let directory = TestDirectory::create("inspect-directory");
    let path = directory.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["inspect", path, "--json"]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("expected a regular file, found a directory"));
}

#[test]
fn inspect_rejects_missing_files() {
    let missing = unique_path("inspect-missing", "macho");
    let path = missing.to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["inspect", path, "--json"]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("file does not exist"));
}

#[cfg(unix)]
#[test]
fn inspect_rejects_unix_sockets_as_non_regular_files() {
    use std::os::unix::net::UnixListener;

    let socket_path = unique_path("inspect-socket", "socket");
    let listener = UnixListener::bind(&socket_path).expect("create temporary Unix socket");
    let socket = TestFile(socket_path);
    let path = socket.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["inspect", path]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("expected a regular file"));
    drop(listener);
}

#[cfg(unix)]
#[test]
fn inspect_rejects_symbolic_links_even_when_the_target_is_valid() {
    use std::os::unix::fs::symlink;

    let target = TestFile::write_macho("symlink-target", thin_macho64(None));
    let link_path = unique_path("inspect-symlink", "macho");
    symlink(target.path(), &link_path).expect("create temporary symbolic link");
    let link = TestFile(link_path);
    let path = link.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["inspect", path]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("refusing to inspect symbolic link"));
    assert!(stderr(&output).contains("provide the target regular file directly"));
}

#[test]
fn verify_accepts_a_valid_manifest_without_claiming_plaintext() {
    let file = TestFile::write(
        "valid",
        serde_json::to_vec(&valid_manifest("Payload/Test.app/Test")).expect("serialize manifest"),
    );
    let path = file.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["verify", path, "--json"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("verify emits JSON");
    assert_eq!(report["command"], "verify");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["manifest_structure_valid"], true);
    assert_eq!(report["declared_overall_outcome"], "inconclusive");
    assert_eq!(report["evidence_evaluated"], false);
    assert_eq!(report["plaintext_proven"], false);
    assert_eq!(
        report["notice"],
        "manifest validation does not prove plaintext"
    );
}

#[test]
fn verify_rejects_malformed_and_unsafe_manifests_on_stderr() {
    let malformed = TestFile::write("malformed", b"{ definitely not JSON");
    let malformed_path = malformed.path().to_str().expect("temporary path is UTF-8");
    let malformed_output = oprobe(&["verify", malformed_path]);
    assert!(!malformed_output.status.success());
    assert!(stdout(&malformed_output).is_empty());
    assert!(stderr(&malformed_output).contains("invalid OrchardProbe manifest JSON"));

    let unsafe_file = TestFile::write(
        "unsafe",
        serde_json::to_vec(&valid_manifest("Payload/../outside"))
            .expect("serialize unsafe manifest"),
    );
    let unsafe_path = unsafe_file
        .path()
        .to_str()
        .expect("temporary path is UTF-8");
    let unsafe_output = oprobe(&["verify", unsafe_path, "--json"]);
    assert!(!unsafe_output.status.success());
    assert!(stdout(&unsafe_output).is_empty());
    let unsafe_error = stderr(&unsafe_output);
    assert!(unsafe_error.contains("unsafe or invalid OrchardProbe manifest"));
    assert!(unsafe_error.contains("not a safe bundle-relative path"));
}

#[test]
fn verify_rejects_duplicate_json_keys_at_every_depth() {
    let base = serde_json::to_string(&valid_manifest("Payload/Test.app/Test"))
        .expect("serialize manifest");
    for (label, duplicate) in [
        (
            "duplicate-top-level",
            base.replacen(
                "\"schema_version\":3",
                "\"schema_version\":3,\"schema_version\":3",
                1,
            ),
        ),
        (
            "duplicate-nested",
            base.replacen(
                "\"architecture\":\"arm64\"",
                "\"architecture\":\"arm64\",\"architecture\":\"arm64\"",
                1,
            ),
        ),
    ] {
        let file = TestFile::write(label, duplicate);
        let path = file.path().to_str().expect("temporary path is UTF-8");
        let output = oprobe(&["verify", path, "--json"]);

        assert!(!output.status.success());
        assert!(stdout(&output).is_empty());
        assert!(stderr(&output).contains("duplicate object key"));
    }
}

#[test]
fn verify_rejects_oversized_manifests_before_parsing() {
    let oversized = TestFile::write("oversized", vec![b' '; 1024 * 1024 + 1]);
    let path = oversized.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["verify", path]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("1048576-byte safety limit"));
}

#[test]
fn verify_rejects_self_declared_pass_without_a_plaintext_oracle() {
    let mut manifest = valid_manifest("Payload/Test.app/Test");
    manifest["binaries"][0]["outcome"] = json!("pass");
    manifest["binaries"][0]["evidence_level"] = json!("metadata");

    let file = TestFile::write(
        "unsupported-pass",
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    );
    let path = file.path().to_str().expect("temporary path is UTF-8");
    let output = oprobe(&["verify", path, "--json"]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("declares pass without known-plaintext evidence"));
}
