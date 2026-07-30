# OrchardProbe sequential execution plan

[简体中文](docs/zh-CN/execution-plan.md)

This file is the authoritative, repository-owned execution ledger for
OrchardProbe. `PROJECT_PLAN.md` explains the product direction and release
milestones; this file controls the order in which implementation work may
start.

Only the copy on `main` is authoritative. A status written on a feature branch
does not take effect until its pull request is merged.

## Sequential gate

The project deliberately works on one ledger step at a time:

1. A planned step receives a GitHub Issue with a bounded scope, dependencies,
   safety constraints, tests, documentation changes, and acceptance criteria.
2. A documentation-only activation PR changes that one row from `planned` to
   `active` and records both the Issue and activation PR. It must pass the
   normal review and merge gates before implementation starts.
3. No later ledger step may start while a row is `active` or `blocked`.
4. The implementation PR changes its row from `active` to `done`, links the
   implementation PR, and updates affected technical and user documentation.
   Because only `main` is authoritative, `done` takes effect only after that PR
   is merged.
5. The next step may be activated only after the completion gate below is
   satisfied and local `main` is synchronized with `origin/main`.

The bootstrap step `GOV-001` is the one exception to the activation-PR rule:
the ledger did not exist before its Issue and PR. This exception cannot be
reused.

## Status vocabulary

| Status | Meaning |
|---|---|
| `planned` | Ordered future work. Implementation has not started. |
| `active` | The only step permitted to receive implementation work. |
| `blocked` | Work has stopped on a documented external dependency or No-Go condition. No later step may silently bypass it. |
| `done` | The linked implementation PR is merged into `main` and every completion gate is satisfied. |

Reordering, splitting, combining, adding, or removing steps requires its own
reviewed plan PR before affected implementation starts. A plan mentioned only
in chat, a local note, or an unmerged branch is not authoritative.

## Completion gate

A step is complete only when all applicable conditions hold:

- its acceptance criteria and documentation are complete;
- local tests, formatting, linting, and safety checks pass;
- the final diff receives a read-only Codex CR covering correctness,
  concurrency and security risk, test gaps, and documentation consistency;
  every P1/P2 finding must be resolved before push or merge;
- the pushed branch matches the locally reviewed commit and exact diff;
- the PR is reviewed again from the remote GitHub diff;
- every required GitHub check succeeds and every review thread is resolved;
- the PR is squash-merged, the linked Issue is closed, and the merge is visible
  on `origin/main`;
- local `main` is fast-forwarded to that merge and the worktree contains no
  unexpected tracked changes.

If any condition fails, work remains on the same step. A safe No-Go result can
complete an experimental step only when the Issue explicitly defines No-Go as
an accepted, documented outcome; it must not be presented as working device or
decryption support.

## Current gate

`LAB-002` checkpoint 2 is complete on `main` through merged PR #59, while
Issue #55 remains open for checkpoints 3–5. On 2026-07-31 the operator
explicitly accepted the immediately preceding bounded proposal for first-party
DemoLab `1.0 (3)`: create the signed candidate and frozen pre-upload oracle,
without TestFlight upload, installation, or device observation. Checkpoint 3
is therefore `active` when activation
[PR #61](https://github.com/jacklv-coder/OrchardProbe/pull/61) is on `main`.
Its ordered work is
tracked in the
[checkpoint-3 progress ledger](docs/research/lab-002-checkpoint-3-progress.md).
The
[device-free design](docs/research/lab-002-oracle-design.md) fixes the
first-party DemoLab self-observation boundary, three-role/all-slice inventory,
role-specific authorized-target identity, fixed code range, independent
pre-upload oracle, bounded reports, two-clean-run procedure, and fail-closed
Go/No-Go rules. It also requires a fresh host-signed, policy-versioned
authorized-use envelope before installation and each run, then uses a device-
local enrollment key/receipt to bind both signed run exports to the same
physical device, app installation, hardware model, and iOS version/build.
Any later implementation may proceed only inside that reviewed design. The
design alone does not establish a protected oracle or authorize a signed
build, TestFlight upload, device observation, or device-backend work. The
2026-07-31 authorization above satisfies the signed-candidate/oracle gate only
for DemoLab `1.0 (3)`. Any different source, version/build, manifest, signing
tuple, upload, installation, or observation requires separate explicit
authorization. Its reviewed design/build manifest must be frozen before
observation. `DEVICE-001` remains blocked and
inactive unless LAB-002 completes with a Go result.
Issue #9 fixed the first-party DemoLab provenance, independent
initial-protection/plaintext-oracle evidence, redaction, explicit Go/No-Go,
documentation, and claim-narrowing criteria.

### LAB-002 checkpoint ledger

As with the main ledger, the status below becomes authoritative only when its
containing PR is on `main`.

| Order | Checkpoint | Status when this PR is on `main` | Evidence / next gate |
|---:|---|---|---|
| 1 | Device-free oracle design | `done` | [PR #58](https://github.com/jacklv-coder/OrchardProbe/pull/58) and the reviewed [design](docs/research/lab-002-oracle-design.md) |
| 2 | Device-free implementation and synthetic/Simulator verification | `done` | Merged [PR #59](https://github.com/jacklv-coder/OrchardProbe/pull/59) implements the closed protocol, Host chain, fixed device state/observer/export workflow, production authorization verification, and synthetic/Simulator gates; all required CI, review threads, and pre-merge Codex CR were clean |
| 3 | Exact signed DemoLab build and pre-upload oracle | `active` | Activation [PR #61](https://github.com/jacklv-coder/OrchardProbe/pull/61); checkpoint 2 is complete, and the 2026-07-31 authorization is limited to DemoLab `1.0 (3)`, its signed candidate, and frozen pre-upload oracle, with no upload, installation, or device observation |
| 4 | Installation enrollment and two clean device observations | `blocked` | Requires checkpoint 3, fresh per-operation authorization, the selected owned iPhone, and the reviewed two-run procedure |
| 5 | Sanitized LAB-002 Go/No-Go result | `blocked` | Requires checkpoint 4; updates Issue #55 and this ledger without weakening a No-Go |

Checkpoint 2 completion evidence is retained in the
[LAB-002 implementation progress ledger](docs/research/lab-002-implementation-progress.md).
The complete checkpoint-2 implementation is now on `main`. No 2A–2E substep independently
authorizes a signed build, TestFlight upload, or device observation.

The activation and workflow-preparation PRs are merged. The account-free
evidence audit and the first signed-candidate run are recorded in Issue #9.
The merged, parameterized, operator-controlled DemoLab archive/evidence/upload
workflow provides locked random build staging,
Gym export scratch constrained beneath and cleaned with that staging, exclusive
publication, an evidence-bound named-`.ipa` Apple upload, and explicit bounded
`altool` JSON success/error validation with a fixed process deadline. The
pre-upload record binds the exact XcodeGen version used for project generation;
the generator must be non-writable and match a reviewed version/architecture
SHA-256 allowlist before its verified bytes are copied through a stable
read-only descriptor and executed from a locked, read-only snapshot in the
private run workspace. Controlled child processes clear inherited dynamic-loader
overrides before execution. Archive binary paths reject symlinks at every
component and remain beneath one archive root; the three binaries are
remeasured immediately before the Apple upload process starts. Apple developer tools use root-owned
absolute paths from the system-selected Xcode plus
`/usr/bin/xcrun` and `/usr/bin/plutil`, with identities and SDK metadata checked
before and after use; both the check and signed build clear inherited Xcode
selection overrides. Configured and resolved temporary roots reject
shell-unsafe characters before Fastlane can construct export commands.
Upload-state transitions use fsynced atomic
publication/replacement so an interruption cannot leave the live recovery
record as partial JSON. The API key remains an anonymous read-only descriptor;
the evidence-bound IPA uses a locked, read-only `.ipa` snapshot in a random
private workspace because Apple rejects extensionless package paths. Its path,
inode, and digest are checked before and after use, and the retained `altool`
identity is checked immediately before and after execution. The phase does not
store Apple credentials or turn signing, distribution, or installation into an
`oprobe` capability.

Explicit upload authorization and a local least-privileged API key were
configured on 2026-07-29. The first upload attempt was rejected before Apple
accepted any IPA bytes because Xcode 26 `altool` cannot expand an extensionless
anonymous package path. App Store Connect UI and API reconciliation found no
build and no uploaded file for `1.0 (1)`; the local indeterminate record was
archived as absent before retry permission was restored.

PR #49 merged the named-`.ipa` compatibility fix. A replacement DemoLab
`1.0 (1)` candidate was then built from clean merged commit
`911db950cff8fc408294d56181477f7319442a36` with IPA SHA-256
`1bb541456d73d644e7c06a148c1e0c780f64f1eb622ae8af35ae482a75f4ec1b`.
The source commit, evidence, package metadata, version/build, and Apple
Distribution signatures were independently rechecked before the one permitted
upload. App Store Connect first reported that upload as `Processing`, then
listed TestFlight build `1` for version `1.0` as `Ready to Submit`. Apple
therefore accepted and processed the candidate; it must not be retried. The
local lane retained `status: indeterminate` because the terminal `altool`
stdout was not valid JSON, which is recorded as a tooling-observability gap
rather than a remote upload failure. No tester group, external distribution,
Beta App Review, or App Store submission was created.

The installed `1.0 (1)` build then exposed a separate launch blocker on an
owned, authorized iPhone. A controlled Mac-side launch captured `dyld`
rejecting both the app's DemoFramework dependency and the embedded framework's
install name because they used
`/Library/Frameworks/DemoFramework.framework/DemoFramework` instead of
`@rpath/DemoFramework.framework/DemoFramework`. The framework bytes were
present in the exported app bundle, so build `1` is retained as failure evidence
and must not be retried or used for the plaintext-oracle observation.

PR #51 merged the `@rpath` correction and fail-closed Archive/IPA linkage
checks. DemoLab `1.0 (2)` was built from clean merged commit
`5785c56e8bee8e30fdaefcb6e263852e9be874ab`; its IPA SHA-256 is
`e383fcf0ee550effb68b183965208b1ef274688cc5233649b8e452135aafde40`.
The evidence, signatures, package metadata, Archive linkage, and exported IPA
linkage were independently rechecked before one upload attempt. The local lane
retained `status: indeterminate` after `altool` returned an unparseable terminal
response, but the App Store Connect API reported the exact build as `VALID`,
with internal state `IN_BETA_TESTING` and no missing export compliance. The
existing internal group already covers all builds; no group mutation, public
link, external distribution, Beta App Review, or App Store submission was
performed.

On 2026-07-29, a read-only device query independently identified DemoLab
`1.0 (2)` on the same owned iPhone. A controlled terminate-existing launch
returned success, and the launched process was still present after both 12 and
32 seconds. This clears only the launch prerequisite and does not establish
installed lineage, initial protection, plaintext, or decryption.

All three binaries remain `initial_protection_status: not_observed` and
`expected_plaintext_status: candidate_pre_upload_archive_only`, so this is not
decryption evidence. The bounded Stage 3 observation confirmed that public
CoreDevice records do not expose per-binary installed identity or hashes, its
file service offers no installed-app-bundle domain, and the distribution-signed
app cannot expose executable images through public LLDB. Apple distribution
processing also prevents the pre-upload IPA hash from standing in for the
installed bytes. Exact installed lineage, initial protection, and plaintext
ranges therefore cannot be independently bound within the approved boundary.

The documented
[bounded No-Go](docs/research/lab-001-protected-oracle.md) completed LAB-001
and blocked `DEVICE-001`. Issue #55 defines the bounded replacement-oracle
research now ordered as `LAB-002`. Its complete in-scope inventory is the
DemoLab app, DemoFramework, and DemoShareExtension executables plus every
installed architecture/slice they contain in the recorded build. Before any
device observation, its reviewed design/build manifest must freeze the exact
DemoLab source commit and recorded build identity, a non-empty set of fixed
exact mapped-code ranges for every inventory slice, and an independently
generated expected-plaintext oracle artifact and SHA-256 for every range, all
bound to that same commit and build. The method must independently bind every
installed inventory item and slice to the recorded build, establish that its
initial installed state is protected, and then show that the same predeclared
mapped ranges are plaintext matching the frozen oracle. A range or inventory
item cannot be omitted or reclassified after observation; failure to prove any
binding or protected-to-plaintext transition records another bounded No-Go.
This activation PR satisfies the documentation gate before LAB-002
implementation. A separate explicit authorization remains required before any
new signed build or TestFlight upload. No device-backend work can start unless
LAB-002 completes with a Go result.

## Execution ledger

Issue and PR links are durable evidence. The linked PR exposes its merged commit
and required-check history, so merge SHAs are not duplicated in this table.

| Order | ID | Status on `main` | Deliverable / acceptance summary | Depends on | Issue | Activation PR | Implementation PR |
|---:|---|---|---|---|---|---|---|
| 1 | `GOV-001` | `done` | Establish this bilingual ledger, sequential gate, completion definition, and documentation links. | — | [#29](https://github.com/jacklv-coder/OrchardProbe/issues/29) | Bootstrap exception | [#30](https://github.com/jacklv-coder/OrchardProbe/pull/30) |
| 2 | `HOST-001` | `done` | Reject unsafe or ambiguous IPA archive structure without decompressing entries. | foundation | [#19](https://github.com/jacklv-coder/OrchardProbe/issues/19) | Predates ledger | [#20](https://github.com/jacklv-coder/OrchardProbe/pull/20) |
| 3 | `HOST-002` | `done` | Read or stream one exact Stored/Deflate entry with size, ratio, CRC, and inventory-consistency bounds. | `HOST-001` | [#21](https://github.com/jacklv-coder/OrchardProbe/issues/21) | Predates ledger | [#22](https://github.com/jacklv-coder/OrchardProbe/pull/22) |
| 4 | `HOST-003` | `done` | Parse bounded XML/binary root `Info.plist` identity and declared main executable metadata. | `HOST-002` | [#23](https://github.com/jacklv-coder/OrchardProbe/issues/23) | Predates ledger | [#24](https://github.com/jacklv-coder/OrchardProbe/pull/24) |
| 5 | `HOST-004` | `done` | Stream and structurally inspect the exact root main executable as Mach-O. | `HOST-003` | [#25](https://github.com/jacklv-coder/OrchardProbe/issues/25) | Predates ledger | [#26](https://github.com/jacklv-coder/OrchardProbe/pull/26) |
| 6 | `HOST-005` | `done` | Inventory bounded conventional framework, dylib, and extension candidates only after Mach-O parsing; report coverage as incomplete. | `HOST-004` | [#27](https://github.com/jacklv-coder/OrchardProbe/issues/27) | Predates ledger | [#28](https://github.com/jacklv-coder/OrchardProbe/pull/28) |
| 7 | `HOST-006` | `done` | Resolve bounded `Info.plist` metadata and exact declared executables for conventional nested bundles; reject missing, duplicate, escaping, oversized, or malformed declarations visibly. | `HOST-005` | [#31](https://github.com/jacklv-coder/OrchardProbe/issues/31) | [#32](https://github.com/jacklv-coder/OrchardProbe/pull/32) | [#33](https://github.com/jacklv-coder/OrchardProbe/pull/33) |
| 8 | `HOST-007` | `done` | Produce a deterministic declared-executable inventory for all supported standard bundle types, with explicit coverage and ambiguity semantics. | `HOST-006` | [#34](https://github.com/jacklv-coder/OrchardProbe/issues/34) | [#35](https://github.com/jacklv-coder/OrchardProbe/pull/35) | [#36](https://github.com/jacklv-coder/OrchardProbe/pull/36) |
| 9 | `HOST-008` | `done` | Materialize the immutable source IPA into a private bounded worktree without symlink/path escape, excluding receipts and `SC_Info`; do not modify the source. | `HOST-007` | [#37](https://github.com/jacklv-coder/OrchardProbe/issues/37) | [#38](https://github.com/jacklv-coder/OrchardProbe/pull/38) | [#39](https://github.com/jacklv-coder/OrchardProbe/pull/39) |
| 10 | `HOST-009` | `done` | Rebuild a deterministic, unsigned analysis-only IPA from unchanged fixture bytes; preserve required metadata and never claim decryption. | `HOST-008` | [#40](https://github.com/jacklv-coder/OrchardProbe/issues/40) | [#41](https://github.com/jacklv-coder/OrchardProbe/pull/41) | [#42](https://github.com/jacklv-coder/OrchardProbe/pull/42) |
| 11 | `HOST-010` | `done` | Bind input/output hashes, inventory, per-binary state, exclusions, and package evidence into the versioned manifest using device-free fixtures. | `HOST-009` | [#43](https://github.com/jacklv-coder/OrchardProbe/issues/43) | [#44](https://github.com/jacklv-coder/OrchardProbe/pull/44) | [#45](https://github.com/jacklv-coder/OrchardProbe/pull/45) |
| 12 | `LAB-001` | `done` | Record the bounded No-Go for the stock internal-TestFlight tuple: exact installed lineage, initial protection, and plaintext ranges were not independently observable inside the approved boundary. | `HOST-010` | [#9](https://github.com/jacklv-coder/OrchardProbe/issues/9) | [#46](https://github.com/jacklv-coder/OrchardProbe/pull/46) | [#54](https://github.com/jacklv-coder/OrchardProbe/pull/54) |
| 13 | `LAB-002` | `active` | Evaluate a DemoLab-only protected-to-plaintext self-observation oracle. Device-free checkpoint 2 is complete through PR #59; checkpoint 3 is authorized only for the exact DemoLab `1.0 (3)` signed candidate and frozen pre-upload oracle, without upload, installation, or device observation. The complete inventory is the app, DemoFramework, and DemoShareExtension executables plus every installed architecture/slice in the recorded build. Before device observation, freeze the exact DemoLab source commit/build identity, a non-empty exact mapped-code-range set for every inventory slice, and an independent expected-plaintext oracle artifact/hash for every range, all bound to that same commit/build. Independently bind every installed inventory item/slice to that build, prove its initial installed state is protected, and prove the same mapped ranges become plaintext matching the frozen oracle; no post-observation omission or reclassification is allowed, otherwise record a bounded No-Go. | `LAB-001` No-Go | [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55) | Initial: [#57](https://github.com/jacklv-coder/OrchardProbe/pull/57); checkpoint 3: [#61](https://github.com/jacklv-coder/OrchardProbe/pull/61) | Checkpoint 2: [#59](https://github.com/jacklv-coder/OrchardProbe/pull/59); final: — |
| 14 | `DEVICE-001` | `blocked` | Evaluate one narrowly scoped backend on an owned, authorized device and record reproducible Go/No-Go evidence without expanding the helper boundary. | `LAB-002` Go result | [#10](https://github.com/jacklv-coder/OrchardProbe/issues/10) | To record during activation | — |
| 15 | `DEVICE-002` | `planned` | Accept an ADR for exactly one supported backend and device tuple; publish no support claim without the required real-device record. | `DEVICE-001` Go result | To create during activation | To record during activation | — |
| 16 | `DEVICE-003` | `planned` | Implement the minimum helper and USB transport behind RFC-0002 limits, with no shell, arbitrary path, PID, or memory API. | `DEVICE-002` | To create during activation | To record during activation | — |
| 17 | `EXPORT-001` | `planned` | Reconstruct and verify the root main executable from exact device code-range evidence while preserving non-code bytes from the input IPA. | `DEVICE-003` | To create during activation | To record during activation | — |
| 18 | `EXPORT-002` | `planned` | Extend reconstruction and per-binary evidence to the supported declared-executable inventory; failures remain explicit and per file. | `EXPORT-001` | To create during activation | To record during activation | — |
| 19 | `UX-001` | `planned` | Implement the one-command `oprobe decrypt <input.ipa>` happy path with automatic diagnostics, atomic unsigned IPA output, and a separate manifest. | `EXPORT-002` | To create during activation | To record during activation | — |
| 20 | `RELEASE-001` | `planned` | Publish a reproducible narrow alpha, installation instructions, checksums/SBOM, bilingual troubleshooting, and an evidence-backed compatibility matrix. | `UX-001` | To create during activation | To record during activation | — |

## What this plan does not claim

`LAB-002` checkpoint 3 is active only for DemoLab `1.0 (3)` candidate/oracle
work. Its device-free checkpoint 2 implementation is complete, but neither it nor later
blocked or planned rows establish a product capability. In particular, the repository does not yet provide a protected
oracle, device backend, working decryption, device/build matching, Mach-O
reconstruction, caller-visible IPA publication, the `oprobe decrypt` command,
an installable release, or a supported-device claim. The output design remains
unsigned, analysis-only, and limited to apps the user is authorized to analyze.
