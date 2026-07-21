//! Safe, manifest-only pre-alpha command-line interface for OrchardProbe.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use orchardprobe_core::{
    CLI_OUTPUT_SCHEMA_VERSION, ExportManifest, demo_manifest, local_doctor_report,
};
use serde::Serialize;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const PLAINTEXT_NOTICE: &str = "manifest validation does not prove plaintext";

#[derive(Debug, Parser)]
#[command(
    name = "oprobe",
    version,
    about = "Inspect OrchardProbe's local readiness and manifests",
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
