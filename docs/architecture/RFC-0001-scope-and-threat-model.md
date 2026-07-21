# RFC-0001: Scope and threat model for a device capability spike

- Status: Accepted for Sprint 0
- Date: 2026-07-21

## Summary

This RFC defines the scope, trust boundaries, misuse model, and mandatory safety controls for any OrchardProbe work that communicates with a real iOS device. It accepts a constrained design envelope for Sprint 0; it does **not** accept a device backend, prove that either backend candidate is feasible, or establish compatibility with any device, iOS version, jailbreak, or app format.

OrchardProbe currently has no device backend. Its implemented functionality is limited to device-free host foundations and project-owned fixtures. A future backend may proceed only after the Go/No-Go checklist in this RFC is satisfied and a separate ADR records the exact tested environment, operations, privileges, and limits.

The project is designed and supported only for apps that the operator or their organization owns, apps whose owner has explicitly authorized the proposed testing, and OrchardProbe's first-party fixtures. These boundaries govern maintainer support, examples, contributions, and official project infrastructure. They do not add a field-of-use restriction to, or modify, the Apache-2.0 license covering repository source code. See the [Legal and Authorization Notice](../../LEGAL.md) and [Acceptable Use Policy](../../ACCEPTABLE_USE.md).

The key rule is that device access must remain a narrow, auditable data path for one authorized target. It must never become a general remote administration, filesystem, process, or memory interface.

## Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe requirements for a future device spike or backend. They do not claim that the requirement is implemented today. An exception to a MUST or MUST NOT requires a new RFC or ADR with security review; a code comment or runtime flag is not sufficient.

## Scope

### In scope

Subject to the authorization prerequisite below, Sprint 0 may investigate whether one narrowly scoped backend can:

- negotiate capabilities with one explicitly selected candidate test device;
- identify one project-owned or explicitly authorized app without accepting a caller-selected PID or filesystem path;
- obtain only the exact mapped code ranges required for that selected app's Mach-O binaries;
- stream regular files contained by that app's bundle root under strict resource limits;
- reconstruct analysis-only output on the host;
- record provenance, hashes, failures, skipped items, evidence level, and signature state in a local manifest; and
- terminate cleanly and remove temporary device-side state after success, failure, cancellation, or disconnect.

The first device spike MUST use OrchardProbe's first-party DemoLab fixture, provisioned independently through a normal development workflow. OrchardProbe itself will not install, modify, re-sign, or relaunch an exported artifact for use.

### Out of scope

The project and the Sprint 0 spike do not provide:

- discovery, acquisition, hosting, or sharing of unauthorized third-party apps or decrypted IPAs;
- App Store authentication, purchasing, downloading, receipt handling, or bulk acquisition;
- purchase, subscription, license, anti-cheat, account-limit, access-control, or app-specific protection bypasses;
- jailbreaks, platform exploits, PAC/PPL bypasses, persistence, spyware, or malware;
- app data-container, Keychain, cookie, database, credential, token, or account extraction;
- output modification, re-signing, installation, cloning, redistribution, or deployability;
- arbitrary shell commands, command execution, paths, PIDs, process control, or memory reads;
- a LAN listener, internet-facing service, cloud upload, telemetry, or export-as-a-service workflow; or
- a claim of support based on theory, simulator behavior, header metadata, or another project's results.

## Terms

- **Operator:** the person running OrchardProbe and responsible for authorization, target selection, and output handling.
- **Authorization scope:** the documented apps, devices, techniques, data, and time period the operator is permitted to use.
- **Host:** the macOS system running the Rust CLI and all reconstruction, verification, packaging, and reporting logic.
- **Device:** the explicitly selected iOS device used in an approved spike. It is not assumed trustworthy merely because it is physically connected.
- **Helper:** a future short-lived Objective-C/C device process that performs only operations proven impossible or impractical on the host.
- **Backend adapter:** host and helper logic for one specific, documented device technique. The suspended-spawn and mapped-file approaches are candidates, not implemented or supported backends.
- **Selected target:** one app resolved from an allow-listed app identity within the authorized session. A target is not a caller-provided PID or path.
- **Bundle root:** the device-resolved root directory of the selected target's app bundle. It excludes the target's data container and other system or app directories.
- **Collector:** host and helper components that enumerate and stream allowed bundle entries beneath the bundle root.
- **Bundle-entry handle:** an opaque, session-bound identifier issued only after the helper has enumerated and contained a regular file beneath the bundle root. Its reported relative path is metadata, not request authority.
- **Code-range handle:** an opaque, session-bound identifier for a helper-validated mapped Mach-O code region. It is not a raw address and cannot be reused across targets or sessions.
- **Output:** a local, not re-signed, analysis-only bundle or archive plus its report. An embedded signature may remain present but invalid.
- **Manifest:** the versioned, machine-readable evidence report. It records claims and observations but is not proof of authorization or, without a known-plaintext oracle, proof of plaintext.
- **Supported:** verified on the exact documented device, OS, environment, backend, and OrchardProbe revision under the support-claim gate in this RFC.

## Assets to protect

The design protects the following assets even when the fixture or app itself is authorized:

- the operator's authorization boundaries and records;
- the host's files, credentials, processes, integrity, and availability;
- the device's integrity, stability, installed apps, personal data, and privileged state;
- app bundle bytes, reconstructed code, symbols, entitlements, and other proprietary output;
- the integrity and provenance of streamed ranges, collected files, hashes, and manifests;
- device identifiers, app identities, client names, environment details, and diagnostic logs;
- helper privileges, bootstrap material, session secrets, and temporary files; and
- the accuracy of public compatibility and plaintext claims.

Authorization records remain under the operator's control and MUST NOT be uploaded or embedded in output. A future CLI acknowledgment records that the operator accepted the project boundary; it does not validate the underlying authorization.

## Trust boundaries

Every boundary is treated as hostile or fallible, including boundaries between components maintained in this repository.

| Boundary | Untrusted input or failure | Required response |
|---|---|---|
| Operator to host CLI | target selectors, flags, paths, environment, output destination | Validate against allow-lists and explicit invariants; reject ambiguity. |
| Host to local filesystem | symlinks, races, special files, hostile existing output, low disk | Use handle-relative operations, no-follow semantics, bounded staging, and atomic publication where supported. |
| Host to USB tunnel | spoofed peers, replay, reordering, truncation, disconnect | Bind a fresh session to one device and target; frame, authenticate or otherwise securely bootstrap, sequence, bound, and time out messages. |
| Protocol to helper | unknown opcodes, oversized fields, invalid state transitions | Reject before allocation or privileged work and terminate the session on protocol confusion. |
| Helper to iOS/runtime | stale identity, target replacement, unexpected mappings, privilege failure | Re-resolve and validate identity and bounds at point of use; fail closed. |
| Device bundle/helper to host parsers | malformed Mach-O, plist, paths, metadata, short or inconsistent reads | Treat all bytes and metadata as untrusted; check arithmetic, structure, quotas, and hashes. |
| Host to output consumer | partial results, stale signatures, overstated evidence | Publish explicit per-item outcomes and evidence; never imply deployability or plaintext without proof. |

The USB cable, usbmuxd, a jailbroken environment, root access, and a successful capability response are transport or execution facts, not trust anchors and not authorization.

## Authorization prerequisite

Before **every** real-device operation, the future CLI MUST require an explicit authorized-use acknowledgment. Interactive use should present a concise confirmation; unattended use may use an explicit `--accept-authorized-use`-style flag whose meaning and policy version are recorded locally. Silence, a previous installation, device ownership, physical access, or possession of an app is not consent.

The acknowledgment MUST state that the operator:

- owns the target app or has explicit authorization from its owner;
- is acting within the authorized apps, devices, techniques, data, and time period;
- understands that authorization does not automatically make circumvention lawful in every jurisdiction; and
- will protect the local output and will not use OrchardProbe to re-sign, install, or redistribute it.

The CLI MUST NOT request or collect the authorization letter, client contract, Apple ID credentials, receipts, or other proof. Maintainers may request a sanitized statement of authorization context when triaging a report, but official project channels MUST NOT receive proprietary binaries, raw device identifiers, credentials, or confidential client material.

After acknowledgment, the operator chooses from a device-provided, bundle-scoped catalog. The helper MUST resolve the selected target itself and bind it to the session. User input MUST NOT be converted into a filesystem path, PID, raw address, or unrestricted process query.

## Attacker and misuse model

The design assumes any of the following may occur:

- an unauthorized or confused operator attempts to use official workflows outside the stated scope;
- a maliciously crafted or corrupted app bundle attacks host parsers, collectors, archives, or verifiers;
- a compromised device, jailbreak component, helper, or local usbmux peer sends false metadata or hostile protocol messages;
- a local process races path checks, replaces files with symlinks or special files, connects to a forwarded port, or tampers with staging output;
- a target exits, is replaced, changes mappings, or returns inconsistent bytes during collection;
- transport frames are replayed, reordered, duplicated, truncated, delayed, or associated with the wrong device or session;
- an app bundle contains traversal components, absolute paths, hard links, symlinks, sparse or oversized files, deep trees, or an excessive number of entries;
- an operation is interrupted by disconnect, timeout, cancellation, helper crash, host crash, low disk, or device reboot;
- stale or partial output is mistaken for a complete export;
- Mach-O encryption metadata, including `cryptid == 0`, is mistaken for proof of correct plaintext;
- a retained but invalid embedded signature is mistaken for a valid, installable signature; or
- logs, manifests, issue attachments, or CI artifacts accidentally disclose proprietary data or device identity.

The following are not assumed preventable by OrchardProbe alone: a fully compromised host kernel, physical extraction from an unlocked device by an independent attacker, malicious firmware, or an operator intentionally modifying source and removing safeguards. These residual conditions do not justify widening the official implementation or weakening default controls.

## Security goals

The future device workflow MUST:

1. enforce one acknowledged, session-bound target and one bundle root;
2. expose only typed operations necessary for capability negotiation, allowed target selection, validated code-range streaming, and contained bundle-file streaming;
3. keep privileged code, privileges, lifetime, open handles, and retained state to the minimum demonstrated by the spike;
4. prevent arbitrary host and device file, shell, process, PID, address, and memory access;
5. bound every message, allocation, file, range, count, depth, duration, retry, and total output size;
6. detect truncation, substitution, cross-session mixing, and incomplete collection;
7. fail closed without publishing ambiguous output as successful;
8. report every relevant binary as passed, failed, skipped, or inconclusive with an honest evidence level;
9. operate locally without telemetry, cloud processing, or implicit uploads; and
10. make compatibility and plaintext claims only from reproducible evidence on project-owned fixtures.

## Security non-goals

OrchardProbe does not promise to:

- make an unauthorized action authorized or provide legal advice;
- defend a modified build from an operator who deliberately removes safeguards;
- conceal use from the device owner, target app, platform, or an authorized assessment's audit controls;
- bypass app-specific runtime defenses or guarantee that a target can be launched or mapped;
- restore, preserve, or create an installable code signature;
- verify functional equivalence of reconstructed output by installing or executing it;
- establish plaintext from metadata or hash consistency alone when no independent oracle exists;
- support every device, SoC, iOS version, jailbreak, binary slice, extension, or bundle feature; or
- secure output after the operator deliberately moves it into an untrusted system or service.

## Mandatory controls

### Host controls

The Rust host owns policy acknowledgment, device and target selection, capability validation, protocol state, resource accounting, reconstruction, verification, packaging, and reporting. It MUST:

- treat all CLI values, environment values, filesystem state, device metadata, protocol messages, bundle bytes, and manifests as untrusted;
- use checked arithmetic before offset calculations, allocation, seek, slicing, or size conversion;
- reject unknown protocol fields or states where accepting them could change security semantics;
- apply explicit per-item and aggregate quotas before consuming bytes, not after an allocation or write;
- use timeouts and bounded retries without silently switching to a broader transport or backend;
- keep unsafe Rust forbidden unless a later ADR documents a minimal, reviewed exception;
- redact stable device identifiers, absolute local paths, session material, and proprietary app identity from default logs;
- keep diagnostic bundles opt-in, local, reviewable before sharing, and free of app bytes by default; and
- separate policy, capability, collection, reconstruction, verification, and reporting failures into stable error categories.

A device-provided path, PID, address, length, identity, hash, or capability is evidence to validate, never authority to trust.

### Device controls

The host MUST bind each session to one explicitly selected physical device and MUST stop if transport identity is missing, duplicated, or changes. Stable device identifiers may be used transiently where the platform requires them, but MUST be redacted from normal output and MUST NOT become public compatibility keys.

Capability reporting MUST describe exact observed facts and explicit unsupported reasons. It MUST NOT infer a backend from iOS version alone or treat jailbreak presence, root access, a device model, or a successful connection as proof that a code-range operation is safe. The spike MUST NOT modify, re-sign, reinstall, or persist changes in the selected target, and it MUST NOT inspect app data containers or unrelated processes.

The test plan MUST identify any device-wide state the helper could change, how that state is detected, and how it is restored. An unexpected reboot, respring, target modification, privilege change, or access outside the selected target is a stop-work event, not a recoverable warning.

### Helper controls

No helper exists today. A future helper MUST be purpose-built for one reviewed protocol and MUST:

- request only entitlements and privileges shown necessary by the approved spike;
- start on demand for one session, accept at most the intended session, and exit immediately after completion, cancellation, timeout, or protocol failure;
- close privileged handles and erase session tokens and temporary state on every exit path;
- avoid persistence, launch-at-boot behavior, background discovery, and LAN or internet listeners;
- resolve the selected app and any process identity through constrained platform data, not caller-supplied paths or PIDs;
- issue opaque, session-bound handles only after validating the target, Mach-O identity, mapped range, integer bounds, and requested operation;
- reject raw address reads, caller-selected range expansion, cross-process access, task-port brokerage, and general process control;
- expose no shell, executable upload, dynamic library injection service, arbitrary command, package manager, or unrestricted file RPC; and
- return the smallest metadata necessary for the host to make a capability decision.

If the necessary platform access cannot be expressed without a general-purpose primitive or a long-lived high-privilege service, the backend is No-Go.

### Minimum privilege and lifetime

Every proposed entitlement, sandbox exception, ownership mode, jailbreak dependency, bootstrap action, and elevated API MUST be listed with the exact operation that needs it. “Common for jailbreak tools” is not evidence. The spike MUST first attempt the least privileged design and document why any rejected lower-privilege alternative is insufficient.

Privileges MUST NOT be retained for host-side parsing, hashing, packaging, or reporting. The helper MUST have an explicit startup deadline, inactivity timeout, total session deadline, and deterministic teardown path. Numeric values must be approved in the backend ADR before implementation. A crash, transport loss, or host disappearance MUST converge on helper termination without requiring a later client to clean it up.

### Transport controls

The planned release transport is a USB-preferred tunnel, expected to use usbmuxd forwarding. The helper MUST bind only to the local endpoint required by that tunnel and MUST NOT listen on Wi-Fi, a LAN address, or the public internet.

The bootstrap design MUST prevent an unrelated local process from taking over the forwarded endpoint. Each connection MUST use fresh session material and bind messages to the selected device, helper instance, target, protocol version, and capability transcript. Session material MUST be unpredictable, expire with the helper, never appear in normal logs or manifests, and never be accepted in a later session.

Integrity and peer-binding requirements remain even if usbmuxd supplies part of the channel security. The backend ADR MUST state exactly which guarantees come from the platform and which are provided by OrchardProbe. Disconnect, duplicate connection, identity mismatch, timeout, or transcript mismatch MUST terminate the operation.

SSH MAY be evaluated only as an explicitly enabled development transport. It MUST be isolated from release configuration, MUST NOT convert protocol operations into caller-controlled shell commands, and MUST NOT be presented as a supported production path without a separate decision and threat review.

### Protocol controls

The protocol does not yet exist. Before device implementation begins, it MUST have a reviewed, versioned specification with:

- length-prefixed typed frames and a hard maximum frame size;
- a strict state machine, protocol version negotiation, request identifiers, and session binding;
- an allow-list of operations and fields, with unknown or out-of-state messages rejected;
- checked lengths, counts, offsets, and range arithmetic on both host and helper;
- per-operation deadlines, bounded retries, cancellation, and explicit terminal errors;
- end-to-end byte counts and cryptographic hashes for streamed ranges and files;
- protection against replay, cross-device, cross-target, and cross-session response mixing; and
- a capability transcript recorded in sanitized form for later diagnosis.

Allowed operation families are limited to handshake, bounded capability reporting, constrained target catalog and selection, server-resolved bundle enumeration, opaque bundle-entry and code-range metadata and streaming, cancellation, and teardown. The protocol MUST NOT accept shell text, executable payloads, raw filesystem paths, raw PIDs, task ports, raw addresses, arbitrary lengths, or generic read/write/process commands.

Capability negotiation MUST fail on an incompatible major version and MUST disable unrecognized optional capabilities. A failed narrow operation MUST NOT trigger an automatic fallback to SSH, a broader helper, another process, or unrestricted memory access.

### Collector and path controls

The helper MUST derive the bundle root from the selected app identity and retain a directory handle or equivalent stable reference. Enumeration and opens SHOULD be relative to that handle. Before the spike runs, the backend ADR MUST set hard numeric limits for:

- path-component and relative-path byte length;
- directory depth;
- total entries and entries per directory;
- individual file size and total collected bytes;
- concurrent open files and concurrent streams;
- bytes buffered in memory; and
- time spent enumerating, opening, and streaming.

The collector MUST:

- expose only relative, normalized display paths returned by constrained enumeration, and request a stream only through the corresponding opaque bundle-entry handle;
- reject empty components, `.` and `..`, absolute paths, platform prefixes, NUL bytes, and ambiguous encodings;
- reject symbolic links, hard links, sockets, pipes, devices, and other non-regular entries rather than following or materializing them;
- verify containment and file type at open time using no-follow, handle-relative operations where available;
- detect replacement between enumeration and open using stable file identity and metadata checks;
- stream only from the selected bundle root and never from the app data container, another app, shared containers, or system paths;
- exclude store receipts, `SC_Info`, credentials, tokens, and device-specific provisioning artifacts not required for analysis;
- stop on quota, identity, containment, short-read, growth, shrink, or hash inconsistency; and
- represent an intentionally excluded, unsupported, or unreadable relevant item explicitly in the manifest.

If platform APIs cannot provide race-resistant containment, the collector is No-Go until a safe alternative is designed. Canonicalization by string prefix is not sufficient.

### Code-range controls

The host MUST NOT request memory by address, PID, or caller-chosen length. For each selected Mach-O, the helper and backend MUST derive candidate ranges from the session-bound target and validated on-device image metadata. Any host request uses an opaque code-range handle plus an operation defined by the protocol.

Before returning bytes, the helper MUST revalidate that the handle belongs to the current session and target, that the mapping identity has not changed, and that the range is wholly contained in the exact code region approved by the backend. Integer overflow, partial mapping, unexpected page state, relocation or fixup ambiguity, target replacement, or unsupported slice state MUST fail the item. The helper MUST NOT round outward into unrelated pages merely to satisfy a page-sized read.

A hash proving that transported bytes equal bytes returned by the helper detects transfer corruption; it does not independently prove correct plaintext.

### Output controls

Output remains on the host. OrchardProbe MUST NOT upload it, send telemetry about it, or place it in CI artifacts. The host MUST:

- require an explicit output destination and validate each existing path component without following symlinks;
- create a private, unique staging area controlled by the current user and on a filesystem suitable for safe final publication;
- enforce free-space, per-file, total-size, entry-count, and archive expansion limits;
- preserve safe relative paths and necessary file modes without reproducing device ownership, special bits, extended attributes, or special files;
- keep separate sessions from sharing a staging directory or partial archive;
- publish only after collection, reconstruction, hashing, and manifest finalization reach a consistent terminal state;
- avoid replacing an existing destination unless a separate explicit overwrite design safely handles races and recovery;
- clearly mark failed or cancelled staging data and remove it safely, or retain it only through an explicit diagnostic option; and
- never re-sign, install, launch, or represent the output as deployable or redistributable.

Archive generation MUST be deterministic for the same accepted inputs once packaging is implemented. Archive entry validation MUST prevent Zip Slip, duplicate or colliding names, case-folding ambiguity where relevant, and decompression bombs.

### Manifest and evidence controls

The manifest is a local evidence report, not an authorization token and not a promise of functional equivalence. Its schema MUST be explicitly versioned and its parser MUST reject unsupported versions and security-relevant unknown structure.

For every discovered relevant Mach-O, including the main executable, frameworks, dylibs, and extensions, the manifest MUST record or explicitly omit with a reason:

- stable bundle-relative identity and binary role;
- input and output sizes and SHA-256 hashes;
- architecture and slice identity;
- backend, sanitized capability facts, and exact OrchardProbe revision;
- requested, accepted, and written code ranges with byte counts and hashes;
- outcome (`pass`, `fail`, `skipped`, or `inconclusive`) and stable reason codes;
- evidence level and whether a known-plaintext oracle was evaluated; and
- signature `presence`, `kind`, and `validation` as separate fields.

Signature presence MUST NOT imply signature validity. A present CMS or ad-hoc signature may be invalid after reconstruction. Signature validation that was not performed MUST be reported as `not_checked`, not inferred.

`cryptid == 0`, absence of an encryption load command, successful ZIP creation, helper/host hash agreement, or successful structural parsing MUST NOT be reported as proof of plaintext. A `pass` plaintext outcome requires comparison with an independent known-plaintext oracle. Without such an oracle, the strongest plaintext result is `inconclusive`, even when transport and structure checks pass.

Manifests, saved reports, and manifests supplied to `oprobe verify` remain untrusted input. They MUST be size-bounded and path-safe and MUST NOT direct the verifier to open arbitrary referenced files.

### Privacy and observability controls

OrchardProbe is local-first and planned without telemetry. The official CLI, helper, tests, and documentation MUST NOT include analytics SDKs, crash-report uploads, remote feature flags, automatic update reporting, implicit issue uploads, or cloud processing.

Default logs SHOULD use ephemeral device aliases and bundle-relative paths. Raw UDIDs, serial numbers, pairing records, client names, proprietary bundle identifiers, app bytes, code bytes, receipts, session material, and absolute user paths MUST NOT appear in normal logs. Any opt-in diagnostic export MUST show an inventory before it is shared and MUST be safe to inspect locally.

## Failure-closed behavior

The following conditions MUST terminate the affected item or session without publishing success:

- authorization acknowledgment is absent or its policy version is unsupported;
- device, helper, target, session, version, or capability identity is ambiguous or changes;
- the protocol receives an unknown critical field, invalid transition, replay, duplicate terminal message, or out-of-bounds value;
- a timeout, disconnect, short read, restart, crash, cancellation, or retry budget exhaustion occurs;
- a path escapes containment, resolves through a link, changes identity, or exceeds any quota;
- a code range is not fully validated or changes during collection;
- expected and observed byte counts or hashes differ;
- disk space is insufficient or atomic publication cannot be guaranteed; or
- a required binary is missing, unsupported, or lacks the evidence required for the requested outcome.

Failure of one optional binary may allow a complete, clearly marked diagnostic report, but it MUST NOT be collapsed into overall success. Partial output MUST remain non-final and unmistakable. The tool MUST NOT broaden privileges, switch targets, relax validation, or choose a more invasive backend merely to turn a failure into a success.

## Support-claim gate

A simulator build, local parser test, successful handshake, one successful range read, or a result from another tool is not a compatibility claim. A configuration may enter an OrchardProbe support matrix only when all of the following are true:

- the exact device model, SoC, iOS version/build, jailbreak and version, rootless/rootful state, backend revision, helper artifact hash, host version, and OrchardProbe commit are recorded in a sanitized test record;
- the target is the first-party DemoLab fixture, the exact installed build and
  its initial protection state have independently reviewable provenance, and
  its independently built expected bytes provide a known-plaintext oracle;
- at least two clean sessions, including helper teardown and restart, produce the expected range and output hashes;
- target binding, bundle containment, range containment, quotas, session binding, and helper teardown are directly tested;
- negative tests for malformed frames, wrong session, wrong target, oversized input, path traversal, symlink escape, short read, disconnect, cancellation, and low disk fail closed;
- every relevant main binary, framework, dylib, and extension is individually reported, including unsupported or skipped items;
- no output, proprietary byte, raw device identifier, receipt, credential, or session material is uploaded to CI or the repository;
- the backend ADR documents exact entitlements, privileges, lifecycle, transport bootstrap, protocol operations, numeric limits, known failures, and removal steps; and
- the reviewed compatibility record names only the native slices and exact configurations actually exercised.

Passing this gate establishes evidence for only that exact configuration. It MUST NOT be generalized to nearby iOS versions, another jailbreak, arm64e, another SoC generation, another app format, or “all jailbroken devices” without separate results. A previously supported row MUST be marked stale or unverified when a relevant dependency changes until it is retested.

An ordinary unencrypted development build may validate target binding,
transport, collection, reconstruction plumbing, and oracle comparison. It does
not exercise a protected-to-plaintext transition and therefore cannot establish
a decryption or end-to-end export support claim. A DemoLab source commit alone
does not establish the byte identity or protection state of the installed
artifact; the backend ADR must define a lawful, first-party, reproducible oracle
and artifact-lineage method before such a claim can pass this gate.

## Residual risks

Even with these controls:

- a compromised host or device kernel can forge data, steal output, or subvert cleanup;
- jailbreak changes may invalidate assumed privilege, path, process, or transport behavior without an obvious version signal;
- TOCTOU windows may remain in platform APIs that lack handle-relative or identity-stable operations;
- code pages may reflect relocations, PAC-related transformations, fixups, or runtime mutation that make reconstruction unsafe or inconclusive;
- target or extension lifecycle constraints may prevent complete collection;
- local output may contain copyrighted, confidential, export-controlled, or vulnerability-sensitive material;
- user acknowledgment cannot prove authorization or legal compliance;
- cryptographic hashes establish identity and transfer integrity only relative to the compared bytes; and
- a narrow privileged helper remains an attractive local attack surface and requires independent review and continued fuzzing.

These risks must appear in backend and compatibility documentation. A residual risk may justify a No-Go result even when a prototype can obtain bytes.

## Go/No-Go checklist for the first real-device spike

All Go items must be checked in a reviewed tracking issue or ADR before the helper is run on a real device.

### Authorization and test material

- [ ] The operator has documented authorization covering the exact app, device, techniques, data, and test period.
- [ ] The only initial target is the project-owned DemoLab fixture, provisioned independently; OrchardProbe will not install or modify it.
- [ ] Expected binary and code-range hashes were produced independently from the first-party build and are stored without device-derived proprietary material.
- [ ] The installed DemoLab build identity and initial protection state are
      independently documented; the planned claim is no broader than the state
      the fixture actually exercises.
- [ ] The test uses a dedicated, recoverable development device without unrelated personal or client data.
- [ ] The data-retention, log-redaction, output-directory, and cleanup plan has been reviewed.

### Environment and privilege review

- [ ] Device model, SoC, exact iOS build, jailbreak/version, rootless/rootful state, host version, and relevant dependency versions are recorded privately and have a sanitized reporting form.
- [ ] The candidate backend has a focused ADR and test plan; neither candidate is treated as the default in advance.
- [ ] Every helper entitlement, privilege, ownership mode, bootstrap step, and dependency is mapped to one required operation and a lower-privilege alternative was considered.
- [ ] The helper has no persistence, startup registration, LAN listener, arbitrary shell/path/PID/memory operation, executable upload, or general task-port brokerage.
- [ ] Installation, launch, timeout, cancellation, crash, disconnect, and removal paths for the helper are documented and reversible.

### Protocol and containment review

- [ ] The protocol specification, state machine, session bootstrap, peer binding, message schema, capability schema, and stable error classes have been reviewed.
- [ ] Hard numeric limits exist for frames, fields, ranges, files, total bytes, entries, depth, buffers, open handles, deadlines, retries, and helper lifetime.
- [ ] Target selection is server-resolved and session-bound; bundle streams use opaque entry handles; no caller-controlled PID, device path, or raw address crosses the protocol.
- [ ] Bundle-root containment uses no-follow, handle-relative or equivalently race-resistant operations; string-prefix canonicalization alone is not used.
- [ ] Code-range handles are opaque and constrained to helper-validated regions of the selected target.
- [ ] Fresh session material, replay rejection, cross-device/target/session binding, stream byte counts, and SHA-256 verification are designed on both sides.

### Failure and evidence review

- [ ] Tests cover malformed and oversized messages, unknown states, wrong session/target, path traversal, symlink and special-file entries, target replacement, mapping changes, short reads, disconnects, helper restart, cancellation, low disk, and quota exhaustion.
- [ ] Every failure above produces a terminal failure or explicit per-item incomplete outcome without broadening access or publishing final output.
- [ ] The manifest distinguishes signature presence, kind, and validation and never treats metadata as plaintext proof.
- [ ] The only planned `pass` plaintext result is backed by the independent DemoLab known-plaintext oracle; all other results remain `inconclusive`, `fail`, or `skipped`.
- [ ] Staging, atomic publication, partial-output handling, and helper cleanup have explicit assertions in the test plan.
- [ ] Private vulnerability reporting and a stop-work path are available for unexpected privilege, containment, or disclosure behavior.

### Decision

- [ ] A maintainer records **Go** for one exact candidate and environment, or **No-Go** with the failed assumptions and next decision.

The decision is automatically **No-Go** if authorization is incomplete, the initial target is not first-party, numeric limits are missing, a required operation needs a general-purpose primitive, bundle or code-range containment cannot be made race-resistant, the helper must persist or listen beyond the USB tunnel, cleanup is unreliable, or no independent known-plaintext oracle exists.

## Open questions

These questions are intentionally unresolved. They must not be answered through undocumented prototype behavior.

1. Which candidate, if either, can obtain the required DemoLab code ranges without modifying, re-signing, or reinstalling the selected target?
2. How can a lawful first-party DemoLab distribution exercise the relevant
   protected input state while retaining a reproducible, independently derived
   plaintext oracle and without publishing protected artifacts?
3. What exact device configuration will be used for the first spike, and which native slice does it exercise?
4. Which entitlements, privileges, ownership mode, and jailbreak APIs are strictly necessary for each candidate?
5. How will a fresh helper authenticate or securely bind to the intended usbmuxd-forwarded host session without creating a reusable device secret?
6. Which platform APIs provide stable target identity and race-resistant bundle-root and file-handle semantics in the first environment?
7. What opaque handle and state-machine design can express exact mapped code ranges without accepting raw addresses, arbitrary lengths, or caller-selected PIDs?
8. How will the backend detect relocation, PAC/fixup, mapping replacement, or runtime mutation that makes a returned range unsuitable for reconstruction?
9. What reviewed numeric limits are realistic for DemoLab while remaining safe against memory, disk, file-count, path-depth, and timeout exhaustion?
10. Are all symlinks rejectable for the first supported iOS app-bundle shape, or is a narrower, demonstrably safe representation required later?
11. What metadata is necessary for reproducibility without exposing stable device identity, proprietary app identity, or session secrets?
12. How will helper artifacts be built, identified, installed for development, removed, and audited without adding an installation workflow to OrchardProbe's user-facing product?
13. Which interruption points can support cleanup and atomic output, and which must leave a clearly labeled recoverable diagnostic state?
14. What evidence, beyond the first-party known-plaintext comparison, is useful but must still be labeled `inconclusive` for an authorized non-fixture target?
15. What criteria require a previously verified compatibility row to be marked stale after changes to iOS, the jailbreak, usbmuxd, helper privileges, or OrchardProbe?

## Consequences

- Sprint 0 may design and review a constrained device experiment, but implementation and execution remain blocked until the checklist is complete.
- The helper and protocol remain intentionally less capable than a shell, debugger, filesystem service, or generic memory reader.
- Some technically feasible environments will be rejected because their privilege or containment model is too broad to support safely.
- Device and backend support grows one reproducibly verified configuration at a time.
- Incomplete results remain useful as diagnostics, but cannot be promoted to successful plaintext or compatibility claims.
- The project stays local-first, analysis-only, and consistent with [ADR-0001](ADR-0001-rust-host.md), the [project plan](../../PROJECT_PLAN.md), and the [Security Policy](../../SECURITY.md).
