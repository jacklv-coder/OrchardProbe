# LAB-002 checkpoint 4 progress ledger

[简体中文](../zh-CN/lab-002-checkpoint-4-progress.md)

Tracking Issue: [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

Activation PR: [#73](https://github.com/jacklv-coder/OrchardProbe/pull/73)

Current branch status: **checkpoint 4 active; 4A complete; 4B implementation
under Codex CR remediation**

This ledger controls the exact installation-enrollment and two-run execution
for the frozen first-party DemoLab `1.0 (3)` candidate. It does not authorize a
different source, build, target, device, distribution channel, or device
backend. Only the copy on `main` is authoritative.

On 2026-08-01 the operator authorized Codex to carry out the bounded checkpoint
4 workflow for the already frozen candidate: one internal-TestFlight upload,
Apple processing reconciliation, coordination of the operator's independent
TestFlight installation on the selected owned iPhone, enrollment, and two clean
observations. OrchardProbe does not install, modify, re-sign, or relaunch the
artifact; the installation remains an independent TestFlight provisioning
action performed by the operator or Codex acting as the operator's explicitly
authorized local assistant outside any OrchardProbe command. The authorization does
not permit external testing, Beta App Review, App Store submission, re-signing,
redistribution, arbitrary target selection, or generic device-backend work.

## Governance deviation

The one upload invocation and read-only Apple reconciliation occurred after the
operator's explicit bounded authorization but before this activation PR reached
`main`. That ordering violated the execution ledger's activation-before-work
rule. The external action cannot be undone, and the processed immutable build
must not be uploaded again. This ledger therefore preserves the deviation
explicitly instead of treating it as compliant, hiding it, or manufacturing a
retry. No installation, enrollment, or observation followed it. All remaining
checkpoint work stayed blocked, and the activation PR must merge before 4B may
start. This is not a precedent or an exception to the serial rule.

That workflow authorization does not replace the three time-bounded RFC-0001
authorized-use acknowledgements required by the reviewed design. The Host must
record one immediately before installation enrollment and one immediately
before each run, with fresh confirmation plus all four required scope assertions, the exact device/environment
and closed operation/data/retention scope. No installation or observation may
start until the matching signed one-shot envelope exists.

## Ordered checkpoint 4 plan

| Order | Step | Status | Completion gate |
|---:|---|---|---|
| 4A | Activation and closure of the early upload/reconciliation deviation | `complete when the activation PR is on main` | This ledger and the bilingual execution plan merge the explicit noncompliance record. Apple lists exact DemoLab `1.0 (3)` as processed and assigned to the existing internal group; the immutable build is not retried, and no external-testing or review state was created |
| 4B | Closed Host operator workflow | `complete when the implementation PR is on main` | The five reviewed Fastlane entry points create and atomically retain installation/run control phases, accept only bounded device-created Receipt/Export bytes, require fresh confirmation plus all four RFC-0001 scope assertions and the full 64-hex fingerprint, derive the Host-only Binding artifacts, and re-run the complete enrollment/run/two-run verifier. Every operation reparses the complete closed pre-upload evidence, rehashes the exact three frozen Archive executables, and revalidates the retained source against the original prebuild/candidate tuple; closure compares every signed role/slice report with the frozen Oracle, and the final chain requires identical normalized observations. Fixed owner-only directories are passed through held descriptors; no command installs, launches, uploads, addresses App Group state, or selects a target. Device-free tests, Codex CR, CI, PR, and merge must pass before installation |
| 4C | Exact installation and enrollment | `blocked on 4B` | Record the fresh installation acknowledgement and sign its one-shot envelope; independently provision only TestFlight `1.0 (3)` on the selected owned iPhone outside OrchardProbe; import the envelope, export and verify the device-signed receipt, compare all 64 fingerprint hex characters, and close the enrollment binding inside the signed window |
| 4D | Clean run 1 | `blocked on 4C` | Record a fresh run-1 acknowledgement; create and retain its distinct Host-side intent, import only its signed challenge, freshly launch the three fixed roles, then export, verify, bind, and safely retain the exact run before cleaning reports |
| 4E | Clean run 2 | `blocked on 4D` | Use a later non-overlapping authorization window and a distinct challenge chained to run 1; repeat the fresh three-role export and close the second binding without reinstall, device/OS change, or state reset |
| 4F | Checkpoint closure | `blocked on 4E` | Verify the complete enrollment plus two-run chain against the frozen manifest, IPA evidence, and external oracle; record a sanitized Go/No-Go without retrying away any failed or incomplete run |

Each row completes before the next starts. A crash, expiry, missing share
extension, failed fingerprint comparison, incomplete export, changed
installation/device/OS, or inconsistent normalized result is retained and
closed according to the reviewed No-Go rules; it is never silently retried into
a passing result.

## Upload reconciliation record

Exactly one reviewed `ios demolab_upload_testflight` invocation was made from
the clean detached source commit that produced the frozen candidate. The local
lane retained `status: indeterminate` because the terminal `altool` response
was not valid JSON and contained neither a structured product error nor a
validated success message. The local record remains unchanged as evidence.

The signed-in App Store Connect UI was then used only to reconcile remote
state. It lists DemoLab `1.0 (3)` as processed, with no missing export
compliance, in the existing internal group. Therefore Apple accepted the exact
build and the upload must not be retried. No tester group was created or
changed, no external testing was enabled, and no Beta App Review or App Store
submission was requested.

## Host tooling gate

Checkpoint 2 merged the closed artifact schemas, canonical encoders, signing
primitive, complete enrollment/run/two-run verifiers, device UI, and synthetic
tests. Step 4B adds the missing reviewed operator workflow as five private
Fastlane lanes: start/close enrollment, start/close the next run, and verify
the complete retained chain. Each publishing action uses a random owner-only
staging directory, exclusive rename, parent-directory sync, fixed filenames,
and exact phase inventory. The authorization seed remains only in the frozen
prebuild directory; device-created private keys remain only on the device.
Hand-authored JSON and filling records after an operation remain forbidden.

The 4B Codex CR rejected the initial implementation until the Host pinned the
reviewed signature-validator ID, rejected contradictory Thin/multi-slice
reports, bounded every observed slice by the installed file size, and Fastlane
serialized a complete invocation with an exclusive workflow-root lock. Those
four P2 findings require regression coverage, the complete local gate, a fresh
clean CR, CI, and merge before 4C may start.

The following complete-diff CR found two more P2 provenance gaps: the operator
accepted a partial pre-upload evidence object and treated any owned directory
as the frozen Archive. The remediated source now deserializes the entire
closed evidence tree with unknown fields denied, validates the package/export-
compliance, lineage, toolchain, manifest, oracle, IPA, and all six binary
records, and descriptor-relatively enumerates and rehashes the exact three
Archive executables. Archive architecture/UUID evidence is also normalized and
matched to every frozen Oracle slice. Regressions reject missing nested fields,
unknown fields, and an empty owned Archive. A temporary, uncommitted read-only
probe confirmed that the retained real candidate passes this stricter source-
bundle validation; it did not upload, install, enroll, or touch the device.

The next full Codex CR found one P1 and two P2 closure gaps. The frozen-source
loader modeled only the indeterminate upload-audit shape even though the
reviewed upload lane can atomically replace it with a terminal accepted shape;
the two-run verifier did not retain and compare each run's frozen-Oracle
digest; and start-run derived run 2's prior binding before fully verifying the
retained run-1 chain. The remediation models and strictly validates both
closed upload outcomes, including the terminal timestamp, retains and compares
the Oracle digest in `VerifiedRun`, and completes run-1 source and chain
verification before publishing any run-2 control. Regressions cover the two
upload shapes and rejected timestamp/state combinations plus cross-Oracle
two-run rejection. The full local gate and a fresh clean CR remain required
before the implementation PR may be opened or merged.

After committing that remediation, two independent complete Fastlane gates
each produced three identical Helper builds from source snapshot
`0cab364ef4b3964bf6de1b864c459cd8b7b25e1e27d2e0d962ff20af6665d281`.
All six products had size `3,179,072`, SHA-256
`0019b20af4d176fa62afe012fbf57cceac89009ffa2db47bdd1b54c2f3b4808f`,
and CodeDirectory CDHash `b0e3663ee3475784d787239f6ff9fdd7c3ff824c`.
The temporary measurement hook was removed before this tuple alone was added
to the reviewed allowlist; the following normal non-measurement gate rebuilt
and admitted the exact tuple and passed the unsigned Simulator fixture.

After the Rust verifier fix was committed, two independent complete Fastlane
gates rebuilt the private Helper from source snapshot
`252af3147edadf200a090cc818c2fd4da231d5721befaaa7aa5c7b0f990aabd9`
with the pinned toolchain and offline verified dependencies. All reproduced
size `3,062,032`, SHA-256
`5d4e47c52967331af2ea7d066d6cd9c6c443d837fb88c0a94860c743f1a1d29e`,
and CodeDirectory CDHash `42bd1c5f3d0e1c3841c5ef80216a21744529d37b`; only that tuple is admitted.
