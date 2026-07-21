# Technical overview

[简体中文版](zh-CN/technical-overview.md)

## Purpose and status

This document explains how OrchardProbe is intended to turn one authorized IPA
into one local, analysis-only reconstructed IPA while keeping the user-facing
command simple and the security-sensitive internals auditable.

> [!IMPORTANT]
> The end-to-end device workflow is a design contract, not current behavior.
> The pre-alpha repository implements the Rust CLI foundation, bounded Mach-O
> parsing, IPA archive metadata preflight and bounded memory/streaming entry
> reads, bounded root app identity parsing from XML/binary plist events,
> structural Mach-O inspection of the declared root executable, and a bounded
> declared-standard-bundle inventory for exact framework/extension declarations
> plus in-scope lowercase dylibs, with explicit unsupported coverage. A private
> bounded worktree and deterministic unsigned analysis-IPA packager now preserve
> unchanged fixture bytes behind library-only interfaces. A version-3 manifest
> builder binds complete archive/inventory hashes, package policy, exclusions,
> and every confirmed Mach-O slice while preserving an inconclusive result. The
> repository also has synthetic DemoLab fixtures and a bounded protocol
> specification. It has no device transport, helper, decryption backend, Mach-O
> reconstructor, output publisher, or `oprobe decrypt` command today.

Read the [user guide](user-guide.md) first for the intended command and output.
Read the [scope and threat model](architecture/RFC-0001-scope-and-threat-model.md)
before changing any device-facing boundary.

## The system contract

The planned happy path is:

```text
oprobe decrypt MyApp.ipa
```

The simple command does not make the underlying operation static or
device-free. OrchardProbe needs both:

- the **authorized source IPA**, used as the immutable local reconstruction
  input; and
- the **same validated installed build on one supported authorized device**,
  used by a narrowly reviewed backend to obtain only the required code ranges.

The output is a new, not re-signed IPA and a separate evidence manifest. The
source file is never modified in place. OrchardProbe does not acquire, install,
launch for general use, sign, or redistribute apps.

## End-to-end data flow

```mermaid
flowchart LR
  Input["Authorized input IPA"] --> Ingest["Bounded archive ingest"]
  Ingest --> Inventory["Bundle and Mach-O inventory"]
  Device["Supported matching device build"] --> Probe["Capability and identity probe"]
  Inventory --> Match["Build and target match"]
  Probe --> Match
  Match --> Session["Bounded authenticated session"]
  Session --> Handles["Opaque entry and code-range handles"]
  Handles --> Rebuild["Host-side Mach-O reconstruction"]
  Inventory --> Rebuild
  Rebuild --> Verify["Per-binary verification and evidence"]
  Verify --> Package["Deterministic temporary IPA"]
  Package --> Final["Atomic final IPA + manifest"]
```

The pipeline is fail-closed. A required mismatch, unsupported slice, target
change, malformed frame, short read, quota failure, or incomplete verification
prevents the temporary archive from becoming the final output.

## Why an IPA alone is not enough

The input IPA contains the on-disk Mach-O representation. OrchardProbe can
parse its encryption metadata, but metadata cannot produce the corresponding
plaintext bytes. The planned backend therefore binds the local artifact to the
same installed build on an explicitly supported device environment.

This distinction creates four separate identities that must not be conflated:

| Identity | Role |
|---|---|
| Source IPA | Immutable local input and bundle layout. |
| Installed build | Device-side target whose lineage must match the input. |
| Runtime or mapped code range | Session-bound bytes returned by the selected backend. |
| Reconstructed output | New host artifact created only after validation. |

A source commit is not automatically the identity of a distributed installed
artifact. Likewise, `cryptid == 0`, a missing encryption command, or a
successful transfer is not proof that returned bytes are correct plaintext.

## Pipeline stages

### 1. Authorization and preflight

The CLI confirms the authorized-use policy and checks host architecture, free
space, dependencies, connected-device ambiguity, supported environment tuple,
and helper/backend capabilities. Compatibility is selected from observed facts
and reviewed records, never inferred from an iOS version alone.

No Apple ID, password, receipt, certificate, pairing material, or signing
identity belongs in OrchardProbe input, logs, configuration, or reports.

### 2. Bounded IPA ingest

The IPA is untrusted input. Archive ingest must inspect entries before
materialization and enforce explicit limits for entry count, path bytes,
component depth, per-file size, total size, and compression ratio. It rejects:

- absolute paths, `..`, ambiguous separators, NULs, or duplicate destinations;
- symbolic links, hard links, FIFOs, sockets, devices, and other special files;
- entries outside the single selected `.app` root;
- receipts, `SC_Info`, and data-container content outside project scope; and
- archives whose declared or observed resource use exceeds the approved limits.

Extraction uses a private working directory. No archive path becomes an
authority to read or write an arbitrary host path.

The current library implements the read-only metadata preflight plus bounded
in-memory and caller-sink entry reads in
[`crates/orchardprobe-core/src/ipa.rs`](../crates/orchardprobe-core/src/ipa.rs).
It validates bounded ZIP/ZIP64 directory and local-header metadata, returns a
deterministic entry inventory, and can read or stream one exact validated
Stored/Deflate regular file with input, output, CRC, and actual-length checks.
The archive layer does not choose a host output path and is not wired to the
CLI. See the
[IPA preflight and entry-read contract](development/ipa-preflight.md).

The Unix-only
[`crates/orchardprobe-core/src/ipa_materialize.rs`](../crates/orchardprobe-core/src/ipa_materialize.rs)
layer plans the complete destination tree before payload reads, excludes exact
`_MASReceipt` and `SC_Info` path components, and streams included bytes into a
fresh `0700` RAII worktree through descriptor-relative no-follow and create-new
operations. Files are `0600`; archive ownership, times, attributes, and
executable bits are not copied. The tree is removed on drop or any error and
remains library-only. See the
[private bounded IPA worktree contract](development/ipa-private-worktree.md).

The Unix-only
[`crates/orchardprobe-core/src/ipa_package.rs`](../crates/orchardprobe-core/src/ipa_package.rs)
packager accepts only that owned worktree, not an arbitrary host directory or
caller path. It reopens the closed plan through retained descriptors and
identities, writes normalized entries in canonical order to a private `0600`
temporary archive, enforces a 16 GiB output bound, and applies the same bounded
IPA preflight before returning read-only access. The bytes and evidence are
labelled `unsigned_analysis_only`; no decryption is claimed. See the
[deterministic IPA packaging contract](development/ipa-deterministic-package.md).

The Unix-only
[`crates/orchardprobe-core/src/ipa_manifest.rs`](../crates/orchardprobe-core/src/ipa_manifest.rs)
builder revalidates and SHA-256 hashes both complete archives, binds their full
inventories through a versioned canonical digest, hashes and reparses every
confirmed source/output code entry, and records package policy, exclusions,
rejections, and every Mach-O slice in manifest version 3. Equal fixture hashes
remain `inconclusive` structural evidence. See the
[device-free package manifest contract](development/ipa-package-manifest.md).

The separate
[`crates/orchardprobe-core/src/ipa_app.rs`](../crates/orchardprobe-core/src/ipa_app.rs)
layer locates the case-sensitive root `Info.plist`, parses only bounded XML or
binary plist events, validates Bundle ID and version fields, and resolves
`CFBundleExecutable` to an exact regular-file inventory entry. It returns root
metadata only; the separate declared-standard-bundle inventory consumes it,
while the independent private-worktree layer consumes the lower archive
inventory. See the
[bounded Info.plist metadata contract](development/ipa-info-plist.md).

[`crates/orchardprobe-core/src/ipa_bundle.rs`](../crates/orchardprobe-core/src/ipa_bundle.rs)
reuses that event parser for bounded conventional framework and direct
extension plists. It resolves exact declared executable entries, including
nonstandard names, but does not read their payload bytes or call them Mach-O.
See the
[nested-bundle metadata contract](development/ipa-nested-bundles.md).

### 3. Bundle and Mach-O inventory

The host identifies the main executable, frameworks, dynamic libraries, and
extensions, then parses every relevant thin or FAT Mach-O slice with checked
arithmetic and bounded seek-based reads.

The current implementation of the generic parser lives in
[`crates/orchardprobe-core/src/macho.rs`](../crates/orchardprobe-core/src/macho.rs).
It validates container structure and encryption load-command metadata but never
reads or transforms encrypted payload bytes. See the
[inspect contract](development/macho-inspect.md).

[`crates/orchardprobe-core/src/ipa_code.rs`](../crates/orchardprobe-core/src/ipa_code.rs)
now binds the root app metadata inventory to a second complete IPA inventory,
streams the exact declared main executable into an automatically cleaned
anonymous temporary file, and invokes that parser. This is structural metadata
for the root executable only; see the
[IPA main-executable contract](development/ipa-main-executable.md).

[`crates/orchardprobe-core/src/ipa_catalog.rs`](../crates/orchardprobe-core/src/ipa_catalog.rs)
combines the exact root and supported nested declarations with lowercase dylibs
inside the same closed ancestry. Declaration roles override suffix conventions,
bundle-stem guesses are forbidden, and each selected entry must pass the same
parser before it is called code. False positives and malformed candidates stay
visible. Coverage is `declared_standard_bundles`, not arbitrary app-code
completeness. See the
[declared code inventory contract](development/ipa-code-inventory.md).

Inventory order is stable and each binary has an independent outcome. A ZIP is
not considered complete merely because the main executable was processed.

### 4. Device and build matching

The host derives an expected target identity from the IPA and asks the bounded
device service to resolve the installed match. The host never supplies a PID,
raw path, address, or arbitrary memory range.

The match must be unique and must stay stable for the session. The run stops if
the selected device, helper instance, app target, mapping, bundle entry, or
capability transcript changes.

Bundle identifier and marketing version alone are not a build identity. A
reviewed matching policy must compare the strongest stable fields available for
that backend, such as bundle identifier, bundle version, executable inventory,
architectures and slices, Mach-O UUIDs, and code-signature identity. The policy
and fields used are recorded in the manifest. A missing required field or any
conflict stops the run; a weaker fallback never silently becomes an exact
match.

### 5. Capability-driven backend selection

A backend is enabled only for a physically tested, sanitized environment record
and an accepted backend ADR. The helper reports exact public capability IDs and
numeric limits. The host chooses among reviewed adapters without silently
falling back to a broader primitive.

The project currently has no approved backend. The first candidate remains
blocked on a first-party protected DemoLab oracle and an authorized-device
Go/No-Go spike.

### 6. Bounded host/helper session

The accepted protocol design is in
[RFC-0002](architecture/RFC-0002-bounded-host-helper-protocol.md). Important
properties include:

- fresh session material and explicit protocol negotiation;
- transcript binding to the selected device, helper, target, and capability set;
- authenticated encryption and replay rejection;
- hard frame, message, stream, byte, item, and deadline limits;
- opaque, single-purpose, one-shot handles instead of paths, PIDs, or addresses;
- cancellation and disconnect behavior that converges on teardown; and
- no shell, executable upload, arbitrary filesystem, or arbitrary memory API.

The specification is accepted as a design gate, but no transport or helper
implements it yet.

### 7. Mach-O reconstruction

Reconstruction happens on the Rust host, not in a privileged helper:

1. Copy the validated source Mach-O into the private work tree.
2. Select one inventory record and one exact slice.
3. Derive the declared encrypted file ranges from validated load commands.
4. Ask the backend for an opaque handle representing only the corresponding
   approved device code range.
5. Receive bounded chunks with declared offsets, sizes, sequence, and hashes.
6. Revalidate total byte counts, containment, target identity, and stream hash.
7. Write only the approved file range in the working copy.
8. Reparse the result and record its structure and evidence.

Every offset addition and range end is checked. A backend may not round outward
into unrelated pages, return caller-selected memory, or widen access after a
short read. Relocation, fixup, PAC, mapping replacement, or slice ambiguity is a
terminal item failure unless the selected backend ADR proves a narrower safe
transformation.

### 8. Verification and evidence

Outcome and evidence strength are separate. The versioned manifest records each
binary and slice independently:

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| `metadata` | Header and declared encryption metadata were parsed. | Correct plaintext. |
| `structure` | The reconstructed Mach-O satisfies bounded structural checks. | That protected bytes transitioned to the right plaintext. |
| `range_hash` | Host and helper agree on bounded transferred ranges and hashes. | An independent plaintext oracle. |
| `known_plaintext` | Observed bytes match an independent first-party oracle. | General support beyond the exact recorded artifact and environment. |

For ordinary authorized apps, the strongest honest plaintext result may remain
`inconclusive` because no independent oracle exists. This does not erase an
operational reconstruction result; it prevents the CLI from overstating what
was proven.

Current Rust validation and schemas live in:

- [`crates/orchardprobe-core/src/lib.rs`](../crates/orchardprobe-core/src/lib.rs)
- [`crates/orchardprobe-core/src/wire.rs`](../crates/orchardprobe-core/src/wire.rs)
- [`schemas/`](../schemas/)
- [the schema guide](development/schemas.md)

### 9. Packaging and finalization

The current library packager walks the validated work tree through retained
directory descriptors and recorded identities. It includes the closed ordinary
bundle-file plan under deterministic path, timestamp, compression, comment, and
mode rules; rejects changed or special nodes; and does not reproduce ownership,
special bits, unrelated extended attributes, receipts, or app data. The result
is a private automatically cleaned temporary IPA, and final bounded preflight
must exactly match the intended paths, kinds, sizes, and executable classes.

The current manifest builder binds input/output hashes, inventories, package
policy, exclusions, declared code coverage, rejections, and unchanged
per-binary bytes for this device-free stage. Caller-selected destination
handling, device-derived reconstruction evidence, and atomic publication as
`*.decrypted.ipa` remain future stages. Packaging unchanged fixture bytes is
not evidence that Mach-O reconstruction or decryption occurred.

OrchardProbe never re-signs the result. An embedded signature can be retained as
evidence while being invalid for installation. Signature `presence`, `kind`,
and `validation` are reported separately so the UI cannot collapse them into a
misleading “signed” boolean.

## Trust boundaries

```mermaid
flowchart TB
  User["Authorized operator"] --> Host["Rust host policy and orchestration"]
  IPA["Untrusted IPA"] --> Host
  Host -->|"bounded encrypted protocol"| Helper["Short-lived narrow helper"]
  Helper --> Target["One session-bound app target"]
  Host --> Work["Private host working tree"]
  Work --> Output["Analysis-only IPA + manifest"]

  Attacker["Malformed archive / compromised peer"] -.-> Host
  Attacker -.-> Helper
```

The Rust host owns policy, parsing, resource accounting, reconstruction,
verification, packaging, redaction, and reporting. The future helper owns only
the smallest device API that cannot live on the host. Privilege never justifies
moving general parsing, paths, process selection, or packaging into the helper.

## Current code map

| Path | Current responsibility |
|---|---|
| `crates/orchardprobe-cli/src/main.rs` | Host-only CLI, safe file opening, `doctor`, `inspect`, `demo`, and manifest verification. |
| `crates/orchardprobe-core/src/ipa.rs` | Read-only ZIP/ZIP64 preflight, deterministic IPA inventory, and bounded CRC-checked memory/caller-sink entry reads. |
| `crates/orchardprobe-core/src/ipa_app.rs` | Bounded XML/binary root `Info.plist` event parsing, app identity validation, and exact main-executable entry resolution. |
| `crates/orchardprobe-core/src/ipa_bundle.rs` | Bounded conventional nested framework/extension discovery, plist parsing, and exact declared-executable entry resolution. |
| `crates/orchardprobe-core/src/ipa_code.rs` | Complete-inventory-bound root executable streaming and bounded Mach-O metadata inspection through an anonymous temporary file. |
| `crates/orchardprobe-core/src/ipa_catalog.rs` | Deterministic declared-standard-bundle selection, bounded Mach-O confirmation, precedence rules, and visible rejection reasons. |
| `crates/orchardprobe-core/src/ipa_materialize.rs` | Private bounded IPA app-tree planning and descriptor-relative materialization with deterministic exclusions and RAII cleanup. |
| `crates/orchardprobe-core/src/ipa_package.rs` | Deterministic unsigned analysis-IPA packaging from the retained private worktree, bounded output, final preflight, and RAII cleanup. |
| `crates/orchardprobe-core/src/ipa_manifest.rs` | Device-free archive/inventory SHA-256 binding, per-code structural/hash evidence, complete slice records, exclusions, and manifest-v3 construction. |
| `crates/orchardprobe-core/src/macho.rs` | Bounded thin/FAT Mach-O metadata parser. |
| `crates/orchardprobe-core/src/lib.rs` | Manifest model, invariants, device-free demo, and local doctor report. |
| `crates/orchardprobe-core/src/wire.rs` | Versioned capability and structured-error wire contracts. |
| `schemas/` | Machine-checked JSON Schema contracts and positive/negative fixtures. |
| `fixtures/DemoLab/` | Project-owned Swift app, Objective-C framework, and share extension. |
| `docs/architecture/` | Security and protocol design gates. |
| `docs/compatibility/` | Evidence vocabulary and support-record workflow. |

Future transport, backend, Mach-O reconstruction, device-derived evidence, and
atomic publication modules must be added only after their corresponding design
and evidence gates. Their names in diagrams are responsibilities, not existing
crates.

## Implementation status

| Capability | Status |
|---|---|
| Rust workspace and local CLI | Implemented |
| Secure bounded single-file Mach-O inspect | Implemented |
| Bounded read-only IPA archive preflight | Implemented as a library; no CLI integration |
| Bounded Stored/Deflate IPA entry read | Implemented for memory and caller sinks as a library; no CLI integration |
| Bounded root Info.plist identity parsing | Implemented for XML/binary events as a library; no CLI integration |
| Bounded nested framework/extension plist metadata | Implemented as a library and consumed by the catalog; no CLI integration |
| Root IPA main-executable Mach-O metadata | Implemented as a library; no CLI integration |
| Declared standard-bundle code inventory | Implemented for root, supported nested declarations, and in-scope lowercase dylibs; arbitrary bundle coverage and CLI integration remain unsupported |
| Private bounded IPA worktree | Implemented on Unix as a library with Receipt/`SC_Info` exclusions and automatic cleanup; no CLI or package publication |
| FAT/FAT64 adversarial parsing coverage | Implemented |
| Versioned manifest/capability/error schemas | Implemented |
| First-party DemoLab simulator fixture | Implemented |
| Bounded protocol specification | Accepted design; not implemented |
| Protected first-party oracle | Research blocked pending real evidence |
| Device discovery and transport | Not implemented |
| Device helper and backend | Not implemented |
| Deterministic unsigned analysis IPA packaging | Implemented on Unix as a library from the retained private worktree; no CLI or publication |
| Device-free package evidence manifest | Implemented on Unix as a version-3 library builder with archive/inventory/per-code hashes and complete slice evidence; no CLI publication or plaintext claim |
| Mach-O reconstruction | Not implemented |
| `oprobe decrypt` | Not implemented |
| Verified compatibility matrix | Empty until real-device evidence exists |

## Learning path

For a first code-reading pass:

1. Read the [user guide](user-guide.md) to understand the product contract.
2. Run the device-free commands in the
   [workspace guide](development/getting-started.md).
3. Read the [IPA preflight and entry-read contract](development/ipa-preflight.md),
   then follow `read_footer`, `read_central_directory`, `validate_local_header`,
   `read_ipa_entry_bounded`, and their adversarial tests in
   `crates/orchardprobe-core/src/ipa.rs`.
4. Read the [bounded Info.plist metadata contract](development/ipa-info-plist.md),
   then follow `inspect_ipa_app_metadata`, `parse_info_events`, `skip_value`,
   and their XML/binary limit tests in `crates/orchardprobe-core/src/ipa_app.rs`.
5. Read the [IPA main-executable contract](development/ipa-main-executable.md),
   then follow `copy_ipa_entry_bounded` and `inspect_ipa_main_executable` through
   their CRC, sink-failure, inventory-drift, and Mach-O tests.
6. Read the
   [nested-bundle metadata contract](development/ipa-nested-bundles.md), then
   follow `discover_bundle_roots`, `select_bundle_plists`,
   `inspect_ipa_nested_bundle_metadata`, and their scope/limit tests.
7. Read the [declared code inventory contract](development/ipa-code-inventory.md),
   then follow `discover_candidates`, `validate_candidate_set`,
   `inspect_ipa_code_inventory`, and their role/rejection tests.
8. Read the [private worktree contract](development/ipa-private-worktree.md),
   then follow `build_worktree_plan`, `open_verified_directory`,
   `materialize_ipa_private_worktree`, and their cleanup/adversarial tests.
9. Read the
   [deterministic IPA packaging contract](development/ipa-deterministic-package.md),
   then follow `package_records`, `validate_exact_tree`,
   `package_ipa_analysis_worktree`, and their determinism/adversarial tests.
10. Read the
   [device-free package manifest contract](development/ipa-package-manifest.md),
   then follow `build_ipa_package_manifest`, `bind_code_evidence`,
   `inventory_digest`, and the schema/golden tests.
11. Read `crates/orchardprobe-cli/src/main.rs` from `main` through `inspect` and
   `open_regular_file` to see CLI error and host file-safety conventions.
12. Read `crates/orchardprobe-core/src/macho.rs`: start at `parse_macho`, follow
   `parse_fat`, then `parse_slice`, range helpers, and adversarial tests.
13. Read `crates/orchardprobe-core/src/lib.rs` beside
   `schemas/v0/export-manifest-v3.schema.json` to compare Rust invariants with
   the wire contract.
14. Read `wire.rs`, the schema guide, and the golden/invalid fixtures.
15. Build DemoLab through `fixtures/DemoLab/README.md` and inspect only its
   project-generated binaries.
16. Read RFC-0001 before RFC-0002; then read the compatibility policy and test
   record to understand why implementation remains blocked on evidence.

When adding a module, preserve the invariant that untrusted values are evidence
to validate, not authority to select a path, target, process, address, range, or
privilege.

## Definition of the first usable alpha

The one-command workflow is not ready merely when a prototype can emit a ZIP.
The alpha gate requires, for one exact supported device tuple:

- `oprobe decrypt Input.ipa` automatically finds the unique matching build;
- all required binaries and slices in the declared MVP scope have explicit
  outcomes, with no silent skip;
- the original input is unchanged and final output publication is atomic;
- transport, helper, backend, reconstruction, verification, and packaging obey
  reviewed numeric limits and teardown rules;
- output signature limitations and per-binary evidence are visible;
- two clean DemoLab runs are reproducible under a reviewed test record; and
- the docs and compatibility matrix name only the exact physically tested
  environment, without generalizing to nearby devices or releases.

Until those conditions are met, examples of `oprobe decrypt` must remain marked
as planned rather than presented as working installation instructions.
