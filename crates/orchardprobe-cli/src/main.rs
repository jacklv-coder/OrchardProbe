//! Safe, host-only pre-alpha command-line interface for OrchardProbe.

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
    CLI_OUTPUT_SCHEMA_VERSION, EvidenceLevel, ExportManifest, demo_manifest, local_doctor_report,
    macho::{EncryptionCommand, EncryptionState, MachOReport, parse_macho},
};
use serde::Serialize;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("could not inspect '{}': {error}", path.display()))?;
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
    let manifest: ExportManifest = serde_json::from_slice(&bytes)
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
