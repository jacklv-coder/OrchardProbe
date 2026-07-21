//! Safe, host-only pre-alpha command-line interface for OrchardProbe.

use std::collections::HashSet;
use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use orchardprobe_core::{
    CLI_OUTPUT_SCHEMA_VERSION, EvidenceLevel, ExportManifest, MAX_MANIFEST_BYTES, demo_manifest,
    local_doctor_report,
    macho::{EncryptionCommand, EncryptionState, MachOReport, parse_macho},
};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};

const PLAINTEXT_NOTICE: &str = "manifest validation does not prove plaintext";
const MACHO_PLAINTEXT_NOTICE: &str = "Mach-O encryption metadata does not prove plaintext";

#[derive(Debug, Parser)]
#[command(
    name = "oprobe",
    version,
    about = "Inspect OrchardProbe's local readiness, manifests, and Mach-O metadata",
    long_about = "A safe pre-alpha OrchardProbe interface. These commands do not connect to an iOS device or process an IPA."
)]
struct Cli {
    /// Emit machine-readable JSON on standard output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report local CLI readiness without contacting a device.
    Doctor,

    /// Print a synthetic, project-owned demonstration manifest.
    Demo,

    /// Inspect metadata from one local, regular Mach-O file.
    Inspect {
        /// Path to one Mach-O file (never an IPA or app bundle).
        #[arg(value_name = "MACH-O")]
        macho: PathBuf,
    },

    /// Parse and validate an OrchardProbe manifest (never an IPA).
    Verify {
        /// Path to an OrchardProbe manifest JSON file.
        #[arg(value_name = "MANIFEST.JSON")]
        manifest: PathBuf,
    },
}

#[derive(Serialize)]
struct VerifyOutput {
    schema_version: u32,
    command: &'static str,
    manifest_structure_valid: bool,
    declared_overall_outcome: orchardprobe_core::Outcome,
    evidence_evaluated: bool,
    plaintext_proven: bool,
    notice: &'static str,
}

#[derive(Serialize)]
struct InspectOutput<'a> {
    schema_version: u32,
    command: &'static str,
    input_path: String,
    report: &'a MachOReport,
    evidence_level: EvidenceLevel,
    plaintext_proven: bool,
    notice: &'static str,
}

struct StrictJson(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(256));
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value.0);
        }
        Ok(StrictJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        let mut keys = HashSet::with_capacity(map.size_hint().unwrap_or(0).min(64));
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<StrictJson>()?;
            values.insert(key, value.0);
        }
        Ok(StrictJson(serde_json::Value::Object(values)))
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(output) => match writeln!(std::io::stdout().lock(), "{output}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "error: could not write output: {error}"
                );
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Doctor => doctor(cli.json),
        Command::Demo => demo(cli.json),
        Command::Inspect { macho } => inspect(&macho, cli.json),
        Command::Verify { manifest } => verify(&manifest, cli.json),
    }
}

fn doctor(json: bool) -> Result<String, String> {
    let report = local_doctor_report(env!("CARGO_PKG_VERSION"));

    if json {
        pretty_json(&report)
    } else {
        let warnings = if report.warnings.is_empty() {
            "none".to_owned()
        } else {
            report.warnings.join("; ")
        };

        Ok(format!(
            "OrchardProbe doctor\n\
             Status: {}\n\
             Host: {}/{}\n\
             Device backend: {}\n\
             Warnings: {}\n\
             No device or IPA was accessed.",
            report.status, report.host_os, report.host_arch, report.device_backend, warnings
        ))
    }
}

fn demo(json: bool) -> Result<String, String> {
    let manifest = demo_manifest(env!("CARGO_PKG_VERSION"));

    if json {
        pretty_json(&manifest)
    } else {
        let outcome = json_scalar(&manifest.declared_overall_outcome())?;
        Ok(format!(
            "OrchardProbe demo\n\
             Device backend: not implemented; this uses a synthetic, project-owned manifest.\n\
             Declared outcome: {outcome}\n\
             {PLAINTEXT_NOTICE}.\n\
             No device or IPA was accessed."
        ))
    }
}

fn inspect(path: &Path, json: bool) -> Result<String, String> {
    let mut file = open_regular_file(path)?;
    let report = parse_macho(&mut file)
        .map_err(|error| format!("invalid Mach-O '{}': {error}", path.display()))?;

    if json {
        return pretty_json(&InspectOutput {
            schema_version: CLI_OUTPUT_SCHEMA_VERSION,
            command: "inspect",
            input_path: path.to_string_lossy().into_owned(),
            report: &report,
            evidence_level: EvidenceLevel::Metadata,
            plaintext_proven: false,
            notice: MACHO_PLAINTEXT_NOTICE,
        });
    }

    inspect_text(path, &report)
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!(
                "could not inspect '{}': file does not exist",
                path.display()
            )
        } else {
            format!("could not inspect '{}': {error}", path.display())
        }
    })?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!(
            "refusing to inspect symbolic link '{}': provide the target regular file directly",
            path.display()
        ));
    }
    if metadata.is_dir() {
        return Err(format!(
            "refusing to inspect '{}': expected a regular file, found a directory",
            path.display()
        ));
    }
    if !file_type.is_file() {
        return Err(format!(
            "refusing to inspect '{}': expected a regular file",
            path.display()
        ));
    }

    Ok(metadata)
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> Result<File, String> {
    let expected = regular_file_metadata(path)?;
    #[cfg(test)]
    run_after_preopen_metadata_hook();
    open_regular_file_matching(path, &expected)
}

#[cfg(all(test, unix))]
std::thread_local! {
    static AFTER_PREOPEN_METADATA_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn install_after_preopen_metadata_hook(hook: impl FnOnce() + 'static) {
    AFTER_PREOPEN_METADATA_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(slot.is_none(), "secure-open test hook is already installed");
        *slot = Some(Box::new(hook));
    });
}

#[cfg(all(test, unix))]
fn run_after_preopen_metadata_hook() {
    let hook = AFTER_PREOPEN_METADATA_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(unix)]
fn open_regular_file_matching(path: &Path, expected: &fs::Metadata) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            let raw_error = error.raw_os_error();
            // FreeBSD and DragonFly report EMLINK when O_NOFOLLOW rejects the
            // final path component; Linux and macOS report ELOOP.
            let no_follow_rejected_symlink =
                raw_error == Some(libc::ELOOP) || raw_error == Some(libc::EMLINK);
            if no_follow_rejected_symlink {
                format!(
                    "refusing to inspect '{}': symbolic link encountered while opening",
                    path.display()
                )
            } else {
                format!("could not inspect '{}': {error}", path.display())
            }
        })?;
    let opened = file
        .metadata()
        .map_err(|error| format!("could not inspect '{}': {error}", path.display()))?;

    if !opened.is_file() {
        return Err(format!(
            "refusing to inspect '{}': file type changed while opening",
            path.display()
        ));
    }
    if expected.dev() != opened.dev() || expected.ino() != opened.ino() {
        return Err(format!(
            "refusing to inspect '{}': file changed while opening",
            path.display()
        ));
    }

    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_file(path: &Path) -> Result<File, String> {
    regular_file_metadata(path)?;
    let file = File::open(path)
        .map_err(|error| format!("could not inspect '{}': {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| format!("could not inspect '{}': {error}", path.display()))?
        .is_file()
    {
        return Err(format!(
            "refusing to inspect '{}': file type changed while opening",
            path.display()
        ));
    }
    Ok(file)
}

fn inspect_text(path: &Path, report: &MachOReport) -> Result<String, String> {
    let mut output = format!(
        "OrchardProbe inspect\n\
         File: {}\n\
         Container: {} ({})\n\
         File size: {} bytes\n\
         Slices: {}",
        path.display(),
        json_scalar(&report.container)?,
        json_scalar(&report.container_endianness)?,
        report.file_size,
        report.slices.len()
    );

    for (index, slice) in report.slices.iter().enumerate() {
        let bits = if slice.is_64_bit { 64 } else { 32 };
        output.push_str(&format!(
            "\nSlice {index}: {}, {bits}-bit, {}, {}\n\
             Offset/size: {}/{} bytes\n\
             Load commands: {} ({} bytes)\n\
             Encryption metadata: {}",
            slice.architecture,
            json_scalar(&slice.endianness)?,
            slice.file_type_name,
            slice.offset,
            slice.size,
            slice.load_command_count,
            slice.load_command_bytes,
            encryption_text(slice.encryption_state, slice.encryption.as_ref())
        ));
    }

    output.push_str(&format!(
        "\nEvidence level: metadata\n\
         Plaintext proven: no\n\
         {MACHO_PLAINTEXT_NOTICE}.\n\
         No device or IPA was accessed."
    ));
    Ok(output)
}

fn encryption_text(
    state: EncryptionState,
    encryption: Option<&orchardprobe_core::macho::EncryptionInfo>,
) -> String {
    let Some(encryption) = encryption else {
        return "not declared (no encryption load command; not plaintext proof)".to_owned();
    };

    let command = match encryption.command {
        EncryptionCommand::EncryptionInfo => "LC_ENCRYPTION_INFO",
        EncryptionCommand::EncryptionInfo64 => "LC_ENCRYPTION_INFO_64",
    };
    let state = match state {
        EncryptionState::NotDeclared => "not declared by header metadata",
        EncryptionState::NotMarkedEncrypted => {
            "not marked encrypted by header metadata; not plaintext proof"
        }
        EncryptionState::MarkedEncrypted => "marked encrypted by header metadata",
    };

    format!(
        "{command} cryptoff={} cryptsize={} cryptid={} ({state})",
        encryption.cryptoff, encryption.cryptsize, encryption.cryptid
    )
}

fn verify(path: &Path, json: bool) -> Result<String, String> {
    let bytes = read_bounded(path)?;
    let value: StrictJson = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid OrchardProbe manifest JSON: {error}"))?;
    let manifest: ExportManifest = serde_json::from_value(value.0)
        .map_err(|error| format!("invalid OrchardProbe manifest JSON: {error}"))?;

    manifest
        .validate()
        .map_err(|error| format!("unsafe or invalid OrchardProbe manifest: {error}"))?;

    let outcome = manifest.declared_overall_outcome();
    if json {
        pretty_json(&VerifyOutput {
            schema_version: CLI_OUTPUT_SCHEMA_VERSION,
            command: "verify",
            manifest_structure_valid: true,
            declared_overall_outcome: outcome,
            evidence_evaluated: false,
            plaintext_proven: false,
            notice: PLAINTEXT_NOTICE,
        })
    } else {
        Ok(format!(
            "Manifest: valid\n\
             Manifest-declared outcome: {}\n\
             Scope: OrchardProbe manifest structure and safety invariants only\n\
             {PLAINTEXT_NOTICE}.\n\
             No device or IPA was accessed.",
            json_scalar(&outcome)?
        ))
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path)
        .map_err(|error| format!("could not open manifest '{}': {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read manifest '{}': {error}", path.display()))?;

    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest exceeds the {MAX_MANIFEST_BYTES}-byte safety limit"
        ));
    }

    Ok(bytes)
}

fn pretty_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|error| format!("could not encode JSON: {error}"))
}

fn json_scalar(value: &impl Serialize) -> Result<String, String> {
    match serde_json::to_value(value)
        .map_err(|error| format!("could not encode result: {error}"))?
    {
        serde_json::Value::String(value) => Ok(value),
        value => Ok(value.to_string()),
    }
}

#[cfg(all(test, unix))]
mod secure_open_tests {
    use std::os::unix::fs::{MetadataExt as _, symlink};
    use std::process::Command;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Duration;

    use super::*;

    static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(0);

    struct TestSandbox(PathBuf);

    impl TestSandbox {
        fn create(label: &str) -> Self {
            let sequence = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "orchardprobe-secure-open-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create secure-open test directory");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
            let path = self.path(name);
            fs::write(&path, contents).expect("write secure-open test file");
            path
        }
    }

    impl Drop for TestSandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn thin_macho64(cpu_subtype: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        bytes.extend_from_slice(&cpu_subtype.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes
    }

    fn create_fifo(path: &Path) {
        let output = Command::new("mkfifo")
            .arg(path)
            .output()
            .expect("run mkfifo for secure-open test");
        assert!(
            output.status.success(),
            "mkfifo failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rejects_regular_path_atomically_replaced_by_symlink_before_open() {
        let sandbox = TestSandbox::create("symlink-swap");
        let victim = sandbox.write("victim.macho", thin_macho64(0));
        let attacker = sandbox.write("attacker.macho", thin_macho64(2));
        let staged_link = sandbox.path("staged-link.macho");
        symlink(&attacker, &staged_link).expect("create staged symbolic link");
        let hook_victim = victim.clone();
        install_after_preopen_metadata_hook(move || {
            fs::rename(&staged_link, &hook_victim)
                .expect("atomically replace path with symbolic link");
        });

        let error = inspect(&victim, false)
            .expect_err("O_NOFOLLOW must reject the replacement before parsing");

        assert_eq!(
            error,
            format!(
                "refusing to inspect '{}': symbolic link encountered while opening",
                victim.display()
            )
        );
        assert!(!error.contains("invalid Mach-O"));
    }

    #[test]
    fn rejects_regular_path_atomically_replaced_by_fifo_without_hanging() {
        let sandbox = TestSandbox::create("fifo-swap");
        let victim = sandbox.write("victim.macho", thin_macho64(0));
        let staged_fifo = sandbox.path("staged.fifo");
        create_fifo(&staged_fifo);

        let worker_path = victim.clone();
        let hook_victim = victim.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            install_after_preopen_metadata_hook(move || {
                fs::rename(&staged_fifo, &hook_victim).expect("atomically replace path with FIFO");
            });
            let result = inspect(&worker_path, false);
            let _ = sender.send(result);
        });
        let result = match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                worker
                    .join()
                    .expect("FIFO inspection worker must report its result");
                panic!("FIFO inspection worker disconnected without a result");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // This is a regression watchdog: the production O_NONBLOCK
                // makes it unreachable in a correct build. A nonblocking
                // writer wakes a reader already blocked by a flag regression,
                // but returns immediately when no reader is waiting.
                let rescue_writer = OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&victim)
                    .map_err(|error| error.raw_os_error());
                match receiver.recv_timeout(Duration::from_secs(5)) {
                    Ok(late_result) => {
                        worker
                            .join()
                            .expect("released FIFO inspection worker must not panic");
                        drop(rescue_writer);
                        panic!(
                            "O_NONBLOCK did not keep FIFO inspection within the timeout: {late_result:?}"
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        worker
                            .join()
                            .expect("FIFO inspection worker disconnected after the timeout");
                        panic!("FIFO inspection worker disconnected without a late result");
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Joining could now hang forever if the worker entered
                        // a blocking open after the rescue attempt. Detaching
                        // is confined to this already-failing test process and
                        // keeps the watchdog strictly bounded.
                        drop(worker);
                        panic!(
                            "FIFO inspection remained blocked after bounded recovery; rescue writer result: {rescue_writer:?}"
                        );
                    }
                }
            }
        };
        worker
            .join()
            .expect("FIFO inspection worker must not panic");
        let error = result.expect_err("post-open validation must reject the FIFO");

        assert_eq!(
            error,
            format!(
                "refusing to inspect '{}': file type changed while opening",
                victim.display()
            )
        );
        assert!(!error.contains("invalid Mach-O"));
    }

    #[test]
    fn rejects_atomic_replacement_by_a_different_regular_inode() {
        let sandbox = TestSandbox::create("regular-swap");
        let victim = sandbox.write("victim.macho", thin_macho64(0));
        let replacement = sandbox.write("replacement.macho", thin_macho64(2));
        let expected = regular_file_metadata(&victim).expect("capture pre-open metadata");
        let replacement_metadata =
            regular_file_metadata(&replacement).expect("capture replacement metadata");
        assert_ne!(
            (expected.dev(), expected.ino()),
            (replacement_metadata.dev(), replacement_metadata.ino())
        );
        let hook_victim = victim.clone();
        install_after_preopen_metadata_hook(move || {
            fs::rename(&replacement, &hook_victim)
                .expect("atomically replace path with a different regular inode");
        });

        let error = inspect(&victim, false)
            .expect_err("identity comparison must reject replacement before parsing");

        assert_eq!(
            error,
            format!(
                "refusing to inspect '{}': file changed while opening",
                victim.display()
            )
        );
        assert!(!error.contains("invalid Mach-O"));
    }

    #[test]
    fn rejects_preexisting_fifo_and_device_before_open() {
        let sandbox = TestSandbox::create("special-files");
        let fifo = sandbox.path("existing.fifo");
        create_fifo(&fifo);

        let fifo_error = inspect(&fifo, false).expect_err("pre-open check must reject FIFO");
        assert_eq!(
            fifo_error,
            format!(
                "refusing to inspect '{}': expected a regular file",
                fifo.display()
            )
        );

        let device = Path::new("/dev/null");
        let device_error = inspect(device, false)
            .expect_err("pre-open check must reject character device before parsing");
        assert_eq!(
            device_error,
            "refusing to inspect '/dev/null': expected a regular file"
        );
    }

    #[test]
    fn rejects_explicit_preopen_and_fstat_identity_mismatch() {
        let sandbox = TestSandbox::create("identity-mismatch");
        let expected_path = sandbox.write("expected.macho", thin_macho64(0));
        let opened_path = sandbox.write("opened.macho", thin_macho64(2));
        let expected =
            regular_file_metadata(&expected_path).expect("capture expected file metadata");
        let opened = regular_file_metadata(&opened_path).expect("capture opened file metadata");
        assert_ne!(
            (expected.dev(), expected.ino()),
            (opened.dev(), opened.ino())
        );

        let error = open_regular_file_matching(&opened_path, &expected)
            .expect_err("fstat identity mismatch must be terminal");
        assert_eq!(
            error,
            format!(
                "refusing to inspect '{}': file changed while opening",
                opened_path.display()
            )
        );
    }
}
