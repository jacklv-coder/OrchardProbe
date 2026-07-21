use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct TestFile(PathBuf);

impl TestFile {
    fn write(label: &str, contents: impl AsRef<[u8]>) -> Self {
        let sequence = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "orchardprobe-cli-{}-{sequence}-{label}.json",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write temporary test manifest");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
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
        "schema_version": 1,
        "tool_version": "0.1.0-test",
        "target": {
            "bundle_id": "com.example.orchardprobe.test",
            "display_name": "OrchardProbe Test Fixture",
            "version": "1.0"
        },
        "backend": "test_fixture",
        "binaries": [{
            "path": binary_path,
            "architecture": "arm64",
            "outcome": "inconclusive",
            "evidence_level": "structure",
            "input_sha256": null,
            "output_sha256": null,
            "known_plaintext_sha256": null,
            "signature": {
                "presence": "unknown",
                "kind": "unknown",
                "validation": "not_checked"
            },
            "notes": ["synthetic test data"]
        }],
        "warnings": []
    })
}

#[test]
fn help_describes_the_safe_pre_alpha_commands() {
    let output = oprobe(&["--help"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("doctor"));
    assert!(text.contains("demo"));
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
    assert_eq!(manifest["backend"], "device_free_demo");
    assert_eq!(manifest["binaries"][0]["outcome"], "inconclusive");
    assert_ne!(manifest["binaries"][0]["evidence_level"], "known_plaintext");
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
