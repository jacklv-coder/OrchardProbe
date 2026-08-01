# LAB-002 checkpoint 4 progress ledger

[简体中文](../zh-CN/lab-002-checkpoint-4-progress.md)

Tracking Issue: [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

Status when the activation PR is on `main`: **checkpoint 4 active; 4A complete**

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
before each run, with all four required assertions, the exact device/environment
and closed operation/data/retention scope. No installation or observation may
start until the matching signed one-shot envelope exists.

## Ordered checkpoint 4 plan

| Order | Step | Status | Completion gate |
|---:|---|---|---|
| 4A | Activation and closure of the early upload/reconciliation deviation | `complete when the activation PR is on main` | This ledger and the bilingual execution plan merge the explicit noncompliance record. Apple lists exact DemoLab `1.0 (3)` as processed and assigned to the existing internal group; the immutable build is not retried, and no external-testing or review state was created |
| 4B | Closed Host operator workflow | `planned` | A reviewed owner-only Host command creates and retains the installation acknowledgement/envelope, then receives, retains, and verifies the device-created signed receipt before creating the selection confirmation/enrollment binding. For each run it creates and retains the acknowledgement/challenge/intent, receives and retains the device-created signed export, creates the binding, and verifies the final two-run chain. Device-free tests, Codex CR, CI, PR, and merge pass before installation |
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
tests. The repository does not yet expose a reviewed operator command that
constructs and durably retains the exact real-operation Host artifact bundles.
Hand-authoring JSON, borrowing test fixtures, or installing first and filling
the records afterward would violate the frozen method. Step 4B closes that
operator gap before the exact TestFlight installation.
