# User guide: one IPA in, one analysis IPA out

[简体中文版](zh-CN/user-guide.md)

## Status

> [!IMPORTANT]
> The workflow in this guide is the target for the first usable alpha. It is
> not implemented in the current pre-alpha checkout. Today, OrchardProbe can
> inspect bounded metadata from one Mach-O file, validate its device-free
> schemas, and run a library-only IPA archive preflight. No current command
> accepts an IPA, connects to an iPhone, decrypts an app, or creates an IPA.

The intended experience is deliberately simple:

```text
oprobe decrypt MyApp.ipa
```

On a supported setup, that command will leave the original IPA unchanged and
create:

```text
MyApp.decrypted.ipa
MyApp.decrypted.manifest.json
```

The complexity of device discovery, installed-app matching, backend selection,
Mach-O enumeration, reconstruction, and verification belongs inside
OrchardProbe. Users should not have to provide a PID, memory address, device
path, SSH command, or list of executables.

## What the user provides

The normal workflow has two inputs, even though only one appears on the command
line:

1. **A local IPA that you are authorized to analyze.** OrchardProbe does not
   search for, purchase, download, or receive apps from an account.
2. **One connected, supported, explicitly authorized jailbroken test device**
   on which the exact same app build is already installed. OrchardProbe does
   not jailbreak the device, install the app, or replace the installed build.

An encrypted IPA is a disk artifact. The planned backend must obtain the
corresponding code bytes from the matching installed process or mapping on an
authorized device, then reconstruct the local IPA on the Mac. Supplying the IPA
alone is therefore not sufficient.

## Planned quick start

### 1. Check the prerequisites

Before running the future alpha command:

- confirm that you own the app and device, or have explicit authorization;
- check that the exact device, iOS build, and test environment appear in the
  published compatibility matrix;
- connect and unlock the device over USB;
- make sure the same bundle version and build as the input IPA is installed;
- keep enough free Mac disk space for the input, working copy, output, and
  validation data; and
- do not provide an Apple ID, password, pairing record, certificate, receipt,
  or signing identity to OrchardProbe.

The normal command will run its own preflight checks. `oprobe doctor` and
`oprobe devices` will remain available for troubleshooting, not as mandatory
steps in the happy path.

### 2. Run one command

```text
oprobe decrypt MyApp.ipa
```

An explicit output path will be optional:

```text
oprobe decrypt MyApp.ipa --output Artifacts/MyApp.decrypted.ipa
```

For automation, `--json` will replace the human terminal summary with one
machine-readable command result containing the outcome, output and manifest
paths, and binary counts. The separate manifest file remains the detailed,
authoritative evidence record.

If exactly one compatible device and one matching installed build are found,
OrchardProbe will select them automatically. If selection is ambiguous, it
will stop with a short explanation instead of guessing. A future noninteractive
selector will use an ephemeral device alias, never a raw UDID in normal logs.

### 3. Use the result

When every required in-scope Mach-O completes, OrchardProbe will atomically
publish the final IPA and its manifest. A successful terminal summary should
look conceptually like this:

```text
Input:      MyApp.ipa
Device:     device-1 (supported configuration)
Binaries:   3 processed, 0 failed, 0 skipped
Output:     MyApp.decrypted.ipa
Manifest:   MyApp.decrypted.manifest.json
Signature:  embedded signature retained but not valid for installation
Evidence:   reconstruction complete; see manifest for per-binary level
```

The exact wording may change before alpha, but the exit status, output paths,
binary counts, signature warning, and evidence summary must remain obvious.

## What “decrypted IPA” means here

The output is an **analysis artifact**:

- its app bundle layout and non-code content come from the authorized input;
- the validated matching installed build supplies only the identity evidence
  and backend-approved code ranges required for reconstruction;
- every required executable, framework, dynamic library, and extension in the
  supported scope is handled independently;
- encrypted code ranges are replaced only with bytes returned by the selected,
  session-bound backend for that exact binary and slice;
- non-code content is copied under strict archive and path-safety rules;
- the archive is never re-signed by OrchardProbe; and
- an embedded signature may remain present while no longer being valid.

The output is not advertised as installable, redistributable, functionally
equivalent, or safe to execute. OrchardProbe does not provide signing or
installation features.

For ordinary authorized apps, an independent known-plaintext oracle will often
be unavailable. The tool may complete reconstruction and structural checks
while the manifest still reports plaintext evidence as `inconclusive`. Only a
matching first-party oracle can upgrade that evidence; `cryptid == 0`, a valid
ZIP, or matching transfer hashes alone never prove correct plaintext.

## How the command behaves

The planned `decrypt` command performs these stages automatically:

1. Validate the IPA as an untrusted archive without extracting unsafe paths,
   links, special files, or unbounded data.
2. Inventory the app bundle and every in-scope Mach-O binary and slice.
3. Run host and device capability checks.
4. Match the IPA to the same installed app build; stop on ambiguity or mismatch.
5. Select one explicitly supported backend from observed capabilities.
6. Collect only session-bound bundle entries and code ranges.
7. Reconstruct each Mach-O in a private working directory.
8. Verify byte counts, hashes, structure, binary coverage, and evidence state.
9. Package to a temporary archive, validate it, and atomically rename it to the
   final `*.decrypted.ipa` path.
10. Write a separate versioned manifest that explains every result.

No final IPA should be promoted when a required binary fails, the target
changes, the device disconnects, limits are exceeded, or the output cannot be
validated. The original IPA is never modified in place.

## Common failures

| Message category | Meaning | User action |
|---|---|---|
| No supported device | No connected environment matches a verified support record. | Connect a listed test device or use a supported configuration. |
| Multiple devices | Automatic selection would be ambiguous. | Disconnect unused devices or choose the displayed ephemeral alias. |
| Installed build mismatch | The IPA and installed app are not the same validated build. | Install the matching authorized build outside OrchardProbe, then retry. |
| Unsupported binary or slice | At least one required Mach-O is outside the recorded capability set. | Read the manifest; do not treat partial output as a completed IPA. |
| Target changed | The app, mapping, device, or session identity changed during collection. | Start a clean run; OrchardProbe will not silently resume against a new target. |
| Disk or quota limit | A declared safety limit would be exceeded. | Free space or use a smaller authorized fixture; limits are not auto-relaxed. |
| Evidence inconclusive | Reconstruction completed, but no independent plaintext oracle was available. | Use the output only for authorized analysis and read the per-binary evidence. |

Errors must not suggest disabling no-follow checks, widening device privileges,
using a general shell, or switching to an unreviewed backend.

## Privacy and local data

OrchardProbe is local-first and has no automatic telemetry. The official tool
must not upload the input IPA, output IPA, app bytes, raw logs, stable device
identifiers, credentials, or session material. Public GitHub reports use only
the sanitized fields requested by the compatibility template.

Temporary working files stay on the Mac and are removed on normal completion.
Failure cleanup must be deterministic; a future `--keep-workdir` diagnostic
mode, if added, must be explicit and warn about sensitive local artifacts.

## Current pre-alpha commands

The commands that actually exist today are developer foundations:

```text
oprobe doctor [--json]
oprobe inspect <MACH-O> [--json]
oprobe demo [--json]
oprobe verify <manifest.json> [--json]
```

They do not process an IPA or contact a device. See the
[Rust workspace guide](development/getting-started.md) to run them from source,
and the [technical overview](technical-overview.md) to understand how they fit
into the planned pipeline. The future `oprobe verify <ipa-or-app>` interface is
separate from today's manifest-only `verify` command and is not implemented.
The internal [IPA preflight](development/ipa-preflight.md) is a tested library
foundation, not an additional command.

## Frequently asked questions

### Can I give OrchardProbe only an IPA and no device?

Not for an encrypted app. The local IPA is the reconstruction input; the
authorized matching installed build supplies the device-side code evidence.
Device-free mode can inspect metadata and demonstrate the pipeline with
project-owned synthetic fixtures only.

### Will OrchardProbe install or launch my IPA?

No. Installation, re-signing, and functional execution of the output are
outside project scope. A narrowly tested backend may cause only the minimum
target lifecycle required by its reviewed design; it may not become a general
launcher or app modifier.

### Can I use an App Store account with OrchardProbe?

No. OrchardProbe does not accept Apple ID credentials, buy apps, or download
account content. Bring an IPA and installed build obtained through your own
authorized workflow.

### Will the output work on every device or iOS version?

No. Support is added one physically tested tuple at a time. Nearby iOS versions
or jailbreaks are unverified until separately recorded.

### Why is there a manifest next to the IPA?

The IPA is the analysis artifact. The manifest is the audit record: it captures
the selected backend, exact per-binary outcomes, hashes, evidence levels,
signature state, warnings, and failure reasons without pretending that archive
creation alone proves success.
