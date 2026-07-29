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

`LAB-001` is the only active planning step. Issue #9 fixes its first-party
DemoLab provenance, independent initial-protection/plaintext-oracle evidence,
redaction, explicit Go/No-Go, documentation, and claim-narrowing criteria.
The activation and workflow-preparation PRs are merged. The account-free
evidence audit and the first signed-candidate run are recorded in Issue #9.
The merged, parameterized, operator-controlled DemoLab archive/evidence/upload
workflow provides locked random build staging,
Gym export scratch constrained beneath and cleaned with that staging, exclusive
publication, descriptor-bound Apple upload, and explicit bounded `altool` JSON
success/error validation with a fixed process deadline. The
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
record as partial JSON. Anonymous IPA/key snapshots are reopened through
verified read-only descriptors, and the retained `altool` identity is checked
immediately before and after execution. The phase does not store Apple credentials or turn
signing, distribution, or installation into an `oprobe` capability.

Stage 1 completed locally on 2026-07-29 from clean merged commit
`01cd447a1205618c22f24a00f059e54f8a284fd1`: DemoLab version `1.0` build `1`
was exported as an evidence-bound App Store distribution candidate with IPA
SHA-256
`6589c290dbb9478a4744ee32398d67da87d411cf210745532ed970b4e331fcd0`.
The main App and Share Extension passed independent Apple Distribution
signature and provisioning-profile validation for the authorized team; the
public record intentionally redacts their identifiers. No TestFlight or App
Store Connect upload occurred. All three binaries remain
`initial_protection_status: not_observed` and
`expected_plaintext_status: candidate_pre_upload_archive_only`, so this is not
decryption evidence.

The next sequential gate requires separate explicit upload authorization and
least-privileged App Store Connect API-key configuration before the exact
candidate may be uploaded to internal TestFlight. Controlled owned-device
observation and the explicit Go/No-Go decision remain pending; `DEVICE-001`
and every later step remain untouched.

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
| 12 | `LAB-001` | `active` | Establish a first-party protected DemoLab oracle with independent initial-protection and expected-plaintext evidence, or record a bounded No-Go result. | `HOST-010` | [#9](https://github.com/jacklv-coder/OrchardProbe/issues/9) | [#46](https://github.com/jacklv-coder/OrchardProbe/pull/46) | — |
| 13 | `DEVICE-001` | `planned` | Evaluate one narrowly scoped backend on an owned, authorized device and record reproducible Go/No-Go evidence without expanding the helper boundary. | `LAB-001` | [#10](https://github.com/jacklv-coder/OrchardProbe/issues/10) | To record during activation | — |
| 14 | `DEVICE-002` | `planned` | Accept an ADR for exactly one supported backend and device tuple; publish no support claim without the required real-device record. | `DEVICE-001` Go result | To create during activation | To record during activation | — |
| 15 | `DEVICE-003` | `planned` | Implement the minimum helper and USB transport behind RFC-0002 limits, with no shell, arbitrary path, PID, or memory API. | `DEVICE-002` | To create during activation | To record during activation | — |
| 16 | `EXPORT-001` | `planned` | Reconstruct and verify the root main executable from exact device code-range evidence while preserving non-code bytes from the input IPA. | `DEVICE-003` | To create during activation | To record during activation | — |
| 17 | `EXPORT-002` | `planned` | Extend reconstruction and per-binary evidence to the supported declared-executable inventory; failures remain explicit and per file. | `EXPORT-001` | To create during activation | To record during activation | — |
| 18 | `UX-001` | `planned` | Implement the one-command `oprobe decrypt <input.ipa>` happy path with automatic diagnostics, atomic unsigned IPA output, and a separate manifest. | `EXPORT-002` | To create during activation | To record during activation | — |
| 19 | `RELEASE-001` | `planned` | Publish a reproducible narrow alpha, installation instructions, checksums/SBOM, bilingual troubleshooting, and an evidence-backed compatibility matrix. | `UX-001` | To create during activation | To record during activation | — |

## What this plan does not claim

Rows after `HOST-009` are plans, not implemented capabilities. In particular,
the repository does not yet provide a device backend, working decryption,
device/build matching, Mach-O reconstruction, caller-visible IPA publication,
the `oprobe decrypt` command, an installable release, or a supported-device
claim. The output design remains unsigned, analysis-only, and limited to apps
the user is authorized to analyze.
