# LAB-002 checkpoint 4 progress ledger

[简体中文](../zh-CN/lab-002-checkpoint-4-progress.md)

Tracking Issue: [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

Activation PR: [#73](https://github.com/jacklv-coder/OrchardProbe/pull/73)

Host workflow PR: [#74](https://github.com/jacklv-coder/OrchardProbe/pull/74)

Publication-pipe remediation PR: [#76](https://github.com/jacklv-coder/OrchardProbe/pull/76)

Frozen-Oracle compatibility PR: [#78](https://github.com/jacklv-coder/OrchardProbe/pull/78)

Host-reboot identity remediation PR: [#81](https://github.com/jacklv-coder/OrchardProbe/pull/81)

Closure PR: [#83](https://github.com/jacklv-coder/OrchardProbe/pull/83)

Current branch status: **checkpoint 4 closed as a retained No-Go; 4A and 4B
completed, and the prior Host compatibility remediations merged through PR
#81. The fresh 4C ceremony reached the selected owned iPhone: TestFlight
displayed and opened first-party DemoLab `1.0 (3)`, the app imported the
one-shot envelope, and it created and exported the signed Enrollment Receipt.
Host closure then failed before publication because the external Receipt and
diagnostic log had been placed inside the experiment
directory, violating its exact six-entry inventory. No Enrollment Binding was
published, so installed binary lineage remained unverified. The external files
and failed log remain owner-only outside that
strict child, but the 15-minute authorization subsequently expired. The
reviewed rules forbid recreating or retrying this failed ceremony into a pass;
4D and 4E were not executed**

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
| 4A | Activation and closure of the early upload/reconciliation deviation | `complete — PR #73` | This ledger and the bilingual execution plan merge the explicit noncompliance record. Apple lists exact DemoLab `1.0 (3)` as processed and assigned to the existing internal group; the immutable build is not retried, and no external-testing or review state was created |
| 4B | Closed Host operator workflow | `complete — PR #74` | The five reviewed Fastlane entry points create and atomically retain installation/run control phases, accept only bounded device-created Receipt/Export bytes, require fresh confirmation plus all four RFC-0001 scope assertions and the full 64-hex fingerprint, derive the Host-only Binding artifacts, and re-run the complete enrollment/run/two-run verifier. Every operation reparses the complete closed pre-upload evidence, rehashes the exact three frozen Archive executables, and revalidates the retained source against the original prebuild/candidate tuple; closure compares every signed role/slice report with the frozen Oracle, and the final chain requires identical normalized observations. Fixed owner-only directories are passed through held descriptors; no command installs, launches, uploads, addresses App Group state, or selects a target. Device-free tests, Codex CR, CI, PR, and merge passed before installation |
| 4C | Exact installation and enrollment | `terminal incomplete — evidence retained` | TestFlight displayed and opened first-party DemoLab `1.0 (3)` on the selected owned iPhone; the fresh one-shot envelope was imported and the device created and exported a signed Receipt. Host closure stopped before publishing Enrollment Binding, so installed binary lineage remained unverified. The external inputs and failure log were retained owner-only outside the strict experiment child, and the authorization then expired. The ceremony is not recreated or retried into a pass |
| 4D | Clean run 1 | `not executed — blocked by terminal 4C` | No run-1 acknowledgement, intent, device observation, or Export was created |
| 4E | Clean run 2 | `not executed — blocked by terminal 4C` | No run-2 acknowledgement, intent, device observation, or Export was created |
| 4F | Checkpoint closure | `complete — retained No-Go` | Record this sanitized pre-publication failure, preserve the private Receipt and failure evidence, publish no Enrollment Binding or fabricated run chain, and require a separately reviewed future checkpoint rather than retrying this ceremony |

Each row completes before the next starts. A crash, expiry, missing share
extension, failed fingerprint comparison, incomplete export, changed
installation/device/OS, or inconsistent normalized result is retained and
closed according to the reviewed No-Go rules; it is never silently retried into
a passing result.

## 4C device attempt record — 2026-08-04

The fresh installation envelope was created from the merged PR #81 source and
the exact frozen checkpoint-3 tuple. Read-only device preflight selected one
wired, booted, owned iPhone with the expected sanitized environment. TestFlight
displayed first-party DemoLab `1.0 (3)`, and that app opened successfully.
Because Host closure never published Enrollment Binding, the installed binary's
exact lineage remained unverified. The envelope was transferred through
AirDrop, imported by DemoLab, and consumed to create the device-bound enrollment
key, the complete displayed selection fingerprint, and the signed Enrollment
Receipt. DemoLab then exported that Receipt through the system share sheet back
to the Host.

The first Host-close invocation stopped at its pre-publication inventory gate
because two operator-supplied external files—the Receipt and the diagnostic
log—were siblings of the six fixed control artifacts. It published no
Enrollment Binding. The files were moved without deletion to the owner-only
outer private root, the failed log was retained, and the strict six-file
inventory was restored. By then the signed 15-minute window had expired, so the
Host close was not invoked again. No private path, experiment identifier,
fingerprint, Receipt content, or exact Host result is recorded here.

This is a procedural No-Go, not evidence that the cryptographic receipt or the
device observer was invalid. It nevertheless prevents enrollment closure for
this ceremony. Checkpoint 4 therefore ends without either observation run and
without claiming the future one-file IPA workflow is ready. A future attempt
requires a separately reviewed checkpoint that makes the external-file layout
unambiguous before any new build, installation state, or authorization is
created.

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

After that remediation was committed, two independent complete Fastlane gates
each rebuilt three Helpers from source snapshot
`8f468ee4a076008520070110dcafc9dc76e43208adaf568a61cab91c13c90207`
with toolchain `1.85.0-aarch64-apple-darwin`. All six products had size
`3,179,024`, SHA-256
`5789f1726bec7aa1f7df93adc131ff103608fc625a06ecac13275bc0ffcb0413`,
and CodeDirectory CDHash `59bafcc5867af9864bbf1b10d17d8ea375b2607a`.
The temporary measurement branch was removed completely before this exact
tuple was added to the reviewed allowlist. A normal non-measurement gate then
rebuilt and admitted it and passed the unsigned Simulator fixture.

The following Codex CR found one P2 compatibility regression: the new current-
Helper validation ran before the existing SHA-256 Git-repository skip, while
the LAB-002 v1 artifact contract deliberately accepts only a 40-hex source
commit. The gate now builds and validates the current Helper only for the same
40-hex checkpoint path; a 64-hex repository continues through the general
DemoLab checks while skipping all LAB-002-v1-only round trips. This Fastlane-
only correction does not change the measured Rust source snapshot or Helper
product tuple. A fresh complete gate and clean CR are still required.

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

The next complete-diff Codex CR found two P2 provenance gaps. Pre-upload
evidence carried manifest and Oracle device/inode identities but the operator
compared only their syntax, name, mode, size, and digest; and the reusable Host
run verifier did not independently retain the target bindings derived from the
enrolled manifest. The remediation now compares both evidence identities with
the actual held file descriptors, derives and retains the ordered three-role
target bindings plus their set digest while closing enrollment, and requires
every run Oracle role and set digest to match those retained manifest-derived
values. Regressions reject substituted descriptor identities and a
self-consistent Oracle target set derived from a different target. Because
this changes the Rust Helper, two new independent reproducibility measurements,
an updated single-tuple allowlist, the normal gate, full local tests, and a
fresh clean Codex CR are required before the 4B PR can open.

After committing that provenance remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`220f4cab162c91a9ae82fce85c534e09bf0f4f0c798695b369de99b40df24661`.
All six products were identical: toolchain
`1.85.0-aarch64-apple-darwin`, size `3,181,488`, SHA-256
`b586c9629ba827d9c5f158276ffaa6994952ea7ba916e4de62854750dc98bc46`,
and CodeDirectory CDHash `6777ec989e0c6ac034ea3905b3646f61fb1d1b98`.
The temporary measurement hook was removed completely before that exact tuple
was added to the reviewed allowlist. The normal non-measurement gate rebuilt
and admitted it and passed the unsigned Simulator fixture; formatting, locked
Clippy with warnings denied, all 271 Workspace tests, Ruby syntax, and the diff
check also pass. A fresh clean Codex CR remains required before the 4B PR.

That CR found two final P2 integrity gaps: close-run did not reject an extra
entry inside the current control phase, and the reusable artifact boundary did
not require the Oracle generator revision to equal its source commit. The
remediation holds the current control directory, verifies its exact three-file
inventory before reading any control artifact, and makes generator/source
revision equality part of `LabOracle` validation shared by control authoring
and run verification. Regressions reject both an unaccounted control entry and
a syntactically valid Oracle attributed to a different generator revision.
Because this changes the Rust Helper, a new two-build reproducibility
measurement, allowlist tuple, complete gate, and fresh clean CR are required.

After committing that remediation, two independent complete Fastlane gates
each rebuilt three Helpers from source snapshot
`87142c73a633b88df721cef1b008e53b76d455707870bc24a849da0debd93968`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,181,376`, SHA-256
`df9e5f1bc60ee537930c51f6875e964660056040c78ee22ab73fb797a63abeab`,
and CodeDirectory CDHash `c8206133f0885ab4e3b2d46179d71478f1e2912c`.
The temporary measurement hook was removed completely before that exact tuple
was added to the reviewed allowlist. The normal non-measurement gate rebuilt
and admitted it and passed the unsigned Simulator fixture; formatting, locked
Clippy with warnings denied, all 273 Workspace tests, Ruby syntax, and the diff
check also pass. A fresh clean Codex CR remains required before the 4B PR.

The fresh complete-diff CR then found three P2 boundary gaps. An output root
could alias the frozen prebuild or candidate directory, source artifacts were
not read back after all semantic and Archive validation, and Receipt/Export
paths were opened in blocking mode before their file type was known. The
remediation rejects duplicate directory device/inode identities before Helper
launch, revalidates the exact prebuild and candidate inventories plus every
artifact byte/identity and all three Archive executables immediately before
returning the retained source bundle, and routes Receipt/Export through the
existing owner-only outside-repository nonblocking snapshot boundary. Negative
regressions reject aliased bindings, replaced bytes or identities, and FIFO or
other special external inputs. Because the source revalidation changes the
Rust Helper, two new independent reproducibility measurements, a new sole
allowlist tuple, the normal gate, all local gates, and a fresh clean CR remain
required before the 4B PR can open.

After committing that boundary remediation, two independent complete Fastlane
gates each rebuilt three Helpers from source snapshot
`6dc02974b685a970d1e32b874142f6d26de92dab78605460a9ff82781a17502b`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,181,712`, SHA-256
`911ba178be1c0b20234ae72adeabe04c8c9ebbafe874c2cbdf9cdd5853e63c20`,
and CodeDirectory CDHash `8285d08248480782cf362abb0136a1b37b1a8b91`.
The temporary measurement hook was removed completely before that exact tuple
was added to the reviewed allowlist. The normal non-measurement gate rebuilt
and admitted it and passed the unsigned Simulator fixture; formatting, locked
Clippy with warnings denied, all 274 Workspace tests, Ruby syntax, the diff
check, and the explicit no-measurement-hook check also pass. A fresh clean
Codex CR remains required before the 4B PR.

That full-diff CR found two further P2 integrity gaps. Run control authoring
checked the Oracle's top-level build fields but did not reject per-role target
bindings or a target-set digest that differed from the closed enrollment; and
the frozen source loader accepted IPA binary size/hash claims without deriving
them again from the bound IPA entries. The remediation now applies the same
manifest-derived Oracle target-binding verifier before signing any run control,
then boundedly inspects and copies the exact three executable entries from the
held IPA and compares their actual sizes and SHA-256 values with the evidence.
Regressions reject both an out-of-enrollment Oracle binding and a fabricated IPA
entry hash. Because this changes the Rust Helper, two new independent
reproducibility measurements, a new sole allowlist tuple, the normal gate, all
local gates, and a fresh clean CR remain required before the 4B PR can open.

After committing that integrity remediation, two independent complete Fastlane
gates each rebuilt three Helpers from source snapshot
`ff4bdb2c9674d3e63019104e69d96a83aee2e054f609f52227e9016232885b5b`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,270,256`, SHA-256
`c840e1a92ddeabc18fc63376a5ec193c8f0710508cd2015085dcfba75af3f0b4`,
and CodeDirectory CDHash `03450ddbd3e5096f7c948abdf2c8bc73245b2e8e`.
The temporary measurement hook was removed completely before that exact tuple
was added to the reviewed allowlist. The normal non-measurement gate rebuilt
and admitted it and passed the unsigned Simulator fixture; formatting, locked
Clippy with warnings denied, all 276 Workspace tests, Ruby syntax, the diff
check, and the explicit no-measurement-hook check also pass. A fresh clean
Codex CR remains required before the 4B PR.

That fresh complete-diff CR found two P1 execution blockers. The Host required
an independently `valid` `security-framework` signature tuple even though the
checked-in iOS observer deliberately and truthfully emits the bounded parser's
`not_checked` tuple, so no real device export could close. It also allowed run
2 control authoring immediately after run 1, even though the final verifier
requires the signed 15-minute windows to be strictly non-overlapping. The
remediation accepts only the observer's exact
`not_checked`/`demolab-bounded-codesign-parser`/`1`, `inconclusive`, sole
`signature_invalid_or_unchecked` tuple as reproducible method-level No-Go
evidence while preserving every Oracle and protection comparison. Run 2 now
must receive the already verified run-1 object; Core derives the prior binding
itself and refuses authoring until Host time is strictly later than run 1's
signed `not_after`. Regressions cover false signature promotion, substituted
reasons/validators, the exact time boundary, and Oracle continuity. These Rust
changes require new reproducibility measurements, a replacement allowlist
tuple, the complete local gate, and another clean CR before the 4B PR.

The follow-up uncommitted CR found two P1 outcome-boundary defects in that
remediation. A run-2 control authored only after run 1's deadline/completion
could still overlap the device's accepted `created_at` when the full 120-second
clock skew was exercised; and the truthful unchecked tuple still surfaced from
the final lane as a generic verified success. Run-2 authoring now requires Host
time to be strictly later than both the signed run-1 `not_after` and retained
run-1 completion plus 120 seconds. The verified run and verified two-run chain
also carry a closed `go` or `no_go_signature_unchecked` disposition, which the
Helper returns for the second close and final verification and Fastlane renders
as an explicit method-level No-Go. The end-to-end fixtures now default to the
checked-in observer's exact unchecked tuple, while a separate regression keeps
the independently validated Go tuple closed. These additional Rust changes
again require fresh reproducibility measurements, the complete local gate, and
a clean CR before the 4B PR.

After committing the outcome-boundary remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`cbd037cd1b219dbeefeb994bce760cc9e3452a0657f0dc24d3eb0fca22089732`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,270,832`, SHA-256
`48b8fc4736b828c05b889cb691cf7a324fd1fa5202469e0863e4c02bc06ed51a`,
and CodeDirectory CDHash `f2be8b9daf358bbd866bade65f387454f6a44db6`.
The temporary absent-tuple measurement hook was then removed completely and
the exact single product tuple added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 278 Workspace tests, Ruby syntax, diff check, and the explicit
no-measurement-hook check also pass. A fresh clean Codex CR remains required
before the 4B PR.

That fresh complete-diff CR found one P1 finalization gap. Run 2 was published
before the complete two-run verifier ran, so different normalized observations
could close the phase and then fail verification without retaining any final
disposition. The remediation verifies the complete ordered two-run chain before
publishing run 2. A structurally valid repetition mismatch or different closed
per-run disposition now becomes generic `no_go`; replay, ordering, enrollment,
frozen-Oracle, and artifact-integrity failures still reject publication. This
Rust Helper change again requires two independent reproducibility measurements,
a replacement sole allowlist tuple, the normal and local gates, and a fresh
clean CR before the 4B PR.

After committing the finalization remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`775a15d6c019c39f99d110efb7dcc5bacc470fc0361e7d1061c6fff7468fa729`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,271,056`, SHA-256
`203b22526f7664d942b55c5742ed3649a4f829f192211c85f82e08cae95582b6`,
and CodeDirectory CDHash `66fc768edadb1f1a9e3b2a134d1fba8fdfe14927`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 281 Workspace tests, Ruby syntax, the diff check, and the explicit
no-measurement-hook check also pass. A fresh clean Codex CR remains required
before the 4B PR.

That final complete-diff CR found one P2 source-lifetime gap: the complete
operator verifier loaded and validated the frozen prebuild/candidate tuple
before checking both retained runs, but did not reopen it after chain
verification. A concurrent source replacement could therefore leave a result
derived from stale in-memory Oracle bytes. The remediation repeats the full
frozen-source and retained-source match after the two-run chain closes and
before returning its disposition. This Rust Helper change requires two new
independent reproducibility measurements, a replacement sole allowlist tuple,
the normal gate, all local gates, and a fresh clean CR before the 4B PR.

After committing that source-lifetime remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`e7edd34197e5b4aade1c74431dbe632eb7e46470f2ec412046b45d42b47a5299`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,270,944`, SHA-256
`1a173e6189cead86850e52332c6f6aadcddfc8f148698f4b7d8ca6777a91aa47`,
and CodeDirectory CDHash `71fb6ba2b6ed95c64d3d206d0913f9b0e4413347`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 278 Workspace tests, Ruby syntax, the diff check, and the explicit
no-measurement-hook check also pass. A fresh clean Codex CR remains required
before the 4B PR.

That fresh complete-diff CR found two further P2 close-path gaps. The run-2
close reverified run 1 without separately rebinding its retained Intent to the
frozen pre-upload evidence, and it returned the closed disposition without the
same post-chain source revalidation used by the final verifier. The remediation
now rechecks run 1's retained Intent before accepting the two-run chain and
reopens the complete frozen prebuild/candidate tuple after the chain closes and
before returning from every close. Because this changes the Rust Helper, two
new independent reproducibility measurements, a replacement sole allowlist
tuple, the normal gate, all local gates, and a fresh clean CR remain required
before the 4B PR.

After committing that close-path remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`c454b2084ce5abbe2f677e91fbc4423fed9a852d0c167c7f82200543f427de3f`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,270,944`, SHA-256
`fb57184babc4d7e6ba3bf2970ca2089ea345b0726c85b337f2c8d9ec4e405cf0`,
and CodeDirectory CDHash `5ffdb86cb678ac6ab670bccb811a28edbfb12a3e`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 278 Workspace tests, Ruby syntax, the diff check, and the explicit
no-measurement-hook check also pass. A fresh clean Codex CR remains required
before the 4B PR.

That fresh complete-diff CR found one P2 result-retention gap. Host closure
recognized only the all-Go tuple and the checked-in observer's exact
signature-unchecked tuple; a structurally valid signed report containing a
different failed evidence gate was rejected before it could become the
documented method-level No-Go. The remediation adds a closed generic `no_go`
disposition, checks the bounded observer's exact signature/outcome/reason
semantics, retains authorized identity and coordinate integrity, and converts
failed signature, protection, disk, or mapped-plaintext comparisons into that
No-Go instead of losing the result. Mixed role dispositions cannot be promoted
to the signature-only No-Go. Fastlane accepts and explicitly renders all three
closed values: `go`, `no_go_signature_unchecked`, and `no_go`. Because this
changes the Rust Helper, two new independent reproducibility measurements, a
replacement sole allowlist tuple, the normal gate, all local gates, and a fresh
clean CR remain required before the 4B PR.

The follow-up uncommitted CR found one remaining P2 case in that remediation:
an approved independent validator's explicit `present` / `cms` / `invalid`
assessment still fell outside both accepted branches and was rejected instead
of retained. That exact reviewed-validator tuple now closes as generic `no_go`
with the required signature reason, while altered validator identity,
revision, outcome, or reasons remain invalid. A regression pins the invalid
tuple beside the reviewed Go, bounded unchecked, ad-hoc, absent, protection,
and digest-failure cases. The follow-up remediation CR found no actionable
correctness issue. The same reproducibility, allowlist, normal-gate,
local-gate, and clean-CR requirements remain in force before the 4B PR.

After committing that result-retention remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`c562abef73db2ef844582793a80883c1ee64b88087c4abd607f1ac72e32fffa1`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,271,056`, SHA-256
`6ee4fd9ee2def07fad6dd512337a52d6a3ea30a3bbb9a3890dd743794f297a0f`,
and CodeDirectory CDHash `5d6319d37d5bdc0852fbb8631cf7e7179e86ba6f`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 280 Workspace tests, Ruby syntax, the diff check, and the explicit
no-measurement-hook check also pass. A fresh clean Codex CR remains required
before the 4B PR.

The subsequent pre-merge CR found one P1 Oracle-provenance gap. The operator
matched retained Archive/IPA report UUIDs against the Oracle but did not
re-derive the complete Oracle role/slice tuple from the exact frozen binaries.
The remediation now parses and cryptographically verifies the exact Archive
snapshots that were hashed and the exact entries held in the bounded IPA
snapshot; validates both sets of `Info.plist` identities, CMS trust, signing
identity, and entitlements; recomputes each target binding from the signed
manifest; and requires the fully re-derived Oracle role to be structurally
identical to the retained role. The same check runs whenever the source tuple
is loaded or revalidated. Follow-up CR also required identity values to be
recomputed from the signed reports and parsing to use the same in-memory bytes
that were hashed; both P2 gaps now have negative regressions. The second
uncommitted CR found no further correctness issue. Because this changes the
Rust Helper, two new independent reproducibility measurements, a replacement
sole allowlist tuple, the normal gate, all local gates, and one clean final CR
remain required before merge. The phone remains untouched while 4B is open.

After committing that Oracle-provenance remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`690aa31e3d0da4d562b974b8e368fbb13c44c37c59a045e2a304c4ed8b7e25ec`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,283,408`, SHA-256
`ba8bb79ac2f3bbf7ad3120b79f27e17c285aabcb3e784a5a1f2db818bce70246`,
and CodeDirectory CDHash `25138be1efb9132acaa555d4bf561ce52b0ff8ea`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the allowlisted Helper and passed
the unsigned Simulator fixture. Formatting, locked Clippy with warnings denied,
all 281 Workspace tests, Ruby syntax, the diff check, and the explicit
no-measurement-hook check also pass. One final clean CR remains required before
merge; the phone remains untouched.

That final complete-diff CR found one P1 lifecycle-state gap: enrollment could
publish another randomly named experiment below a reused non-empty output root,
allowing an abandoned or failed experiment to be bypassed instead of retained.
The remediation requires the held output-root descriptor to have an exact empty
inventory before reading the request, uses one fixed experiment slot, and
rechecks the exact one-entry staging/final inventory on both sides of the atomic
no-replace rename. Regressions reject a retained experiment child and roll back
a publication if a sibling appears at that boundary. Because this changes the
Rust Helper, two fresh independent reproducibility measurements, a replacement
sole allowlist tuple, the normal gate, all local gates, and another clean final
CR are required before merge. The phone remains untouched.

After committing the lifecycle remediation, two independent complete Fastlane
gates each rebuilt three Helpers from source snapshot
`87ae31a61d40199e20d3d9e50644660dbd6ebe6fe1ada9d0469e3d3174d27858`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,284,016`, SHA-256
`c6050562a0e036bda25fb36e7e51a9e90b3a7df01202de2e30402261a77bde91`,
and CodeDirectory CDHash `8b5f62771adf5fe02828201e41f13a90459e0f7f`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates also passed the unsigned Simulator fixture. The normal
non-measurement gate subsequently rebuilt and admitted the exact tuple, and
formatting, Clippy, Ruby syntax, diff hygiene, the fixture, and all 283 local
tests passed. One final clean CR remains required before push and merge; the
phone remains untouched.

That complete-diff CR found one P2 retry-lifecycle compatibility gap. A valid
indeterminate-upload reconciliation deliberately retains up to 32 audit
records beside the next active upload result, but the operator source loader
required an inventory containing only the five active candidate entries. The
remediation admits only the existing closed reconciliation filename shape and
bound, parses every retained record with the closed schema, binds it to the
same source commit and IPA digest, validates its timestamps, destination,
status, note, and operator reconciliation decision, and reopens every record
by identity during the final source revalidation. Unknown, malformed,
permission-relaxed, tuple-mismatched, added, removed, or replaced records still
fail closed. A regression covers the valid retained-history lifecycle and the
invalid-name and wrong-tuple cases. Because this changes the Rust Helper, two
fresh independent reproducibility measurements, replacement of the sole
allowlist tuple, the normal and complete local gates, and another clean final
CR remain required before push and merge. The phone remains untouched.

After committing the reconciliation-history remediation, two independent
complete Fastlane gates each rebuilt three Helpers from source snapshot
`8e94e44623985498c5b2f5873e1036bfc0979bca8fa3e3e326a0e659bec686fc`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,302,528`, SHA-256
`c87b63b0d00cd46569215f8ed0064b10973a18012931be6101c425654a6bf1e5`,
and CodeDirectory CDHash `31d712a0fa9ffa844603185d423e12b10157a7c8`.
The temporary absent-tuple measurement hook was removed completely before the
exact sole product tuple was added to the reviewed source-snapshot allowlist.
Both measurement gates passed the unsigned Simulator fixture. The normal
non-measurement gate then rebuilt and admitted the exact allowlisted Helper and
passed the fixture. Formatting, locked Clippy with warnings denied, all 284
Workspace tests, Ruby syntax, diff hygiene, and the explicit
no-measurement-hook check also pass. Push and merge now require one final clean
complete-diff CR; the phone remains untouched.

That complete-diff CR found three further P2 lifecycle boundaries. Enrollment
closure could publish a closed result after the frozen prebuild/candidate tuple
changed; retained reconciliation records did not enforce their causal time
order; and the enrollment-result plus run control/result publications used the
generic publisher without an exact inventory guard at the rename boundary.
The remediation passes held prebuild/candidate descriptors into enrollment
closure and fully revalidates the source before closure and publication,
requires `attempt_started_at <= reconciled_at <=` the active upload attempt,
and routes every operator phase through a phase-aware pre/post-rename inventory
guard. Regressions cover both impossible chronology directions and a same-user
unexpected sibling injected after staging but before rename. Because the Rust
Helper changed again, two fresh independent reproducibility measurements, the
replacement sole allowlist tuple, the normal and complete local gates, and a
new clean final CR remain required before push and merge. The phone remains
untouched.

The follow-up uncommitted CR found one remaining P2 race: enrollment closure's
last source check still preceded the publisher's acknowledgement wait. The
source check now runs inside both sides of the rename-boundary guard for every
operator control/result publication, so a source change during that wait rolls
back the publication. The same measurement and final-gate requirements remain;
the phone remains untouched.

A second follow-up uncommitted CR found that the operator loader enforced the
reconciliation chronology but the earlier upload gate and Fastlane record
validator accepted `reconciled_at < attempt_started_at`. Both now enforce that
independently knowable lower bound, while the operator loader additionally
enforces the upper bound against the later active retry. Rust and Fastlane
regressions cover the reversed chronology. The same reproducibility and final
gate requirements remain; the phone remains untouched.

The next uncommitted CR found two P2 failure-path defects. A backward host
clock could cause reconciliation to publish a terminal record before rejecting
its chronology, and enrollment closure registered its three directory handles
only after all opens succeeded. Reconciliation now validates the prospective
terminal record before atomic replacement and a regression proves the live
indeterminate record remains byte-identical on rejection. Enrollment closure
registers each handle immediately so every early failure closes all prior
descriptors. The measurement and final-gate requirements remain; the phone
remains untouched.

The following uncommitted CR found one P2 ordering race: a same-user writer
could add an unexpected phase sibling while the source guard was reopening the
frozen tuple, after the boundary's only inventory scan. Each boundary now
brackets source validation with inventory checks, including enrollment start,
and a regression injects the sibling from inside the source guard. Publication
rolls back and removes its staging directory. Reproducibility and final gates
remain required; the phone remains untouched.

The next uncommitted CR found one P2 source-publication boundary gap. Reopening
the frozen source only at validation points could miss a transient change and
restore by a second controlled lane while the first Helper invocation remained
active. Fastlane now acquires non-blocking exclusive locks for every bound
directory, in deterministic device/inode order, and retains all of them for the
complete Helper lifetime. A competing workflow that shares either frozen source
is rejected, and a regression also proves that a failed multi-lock acquisition
releases its earlier locks before retry. Reproducibility and final gates remain
required; the phone remains untouched.

The follow-up CR found one P2 interoperability gap: the operator locks excluded
other operator invocations, but the upload lane released its candidate lock
after the final gate and before creating or replacing the upload-result record;
reconciliation likewise held only the result-file lock. The final upload gate
now retains its output, prebuild, and candidate locks through the complete Apple
request and durable terminal result publication. Reconciliation retains the
same candidate-directory lock through atomic replacement and archival. A
regression proves the existing controlled-writer lock and the new operator
source lock exclude each other. Reproducibility and final gates remain required;
the phone remains untouched.

After committing the complete operator publication-boundary remediation, two
independent complete Fastlane gates each rebuilt three Helpers from source
snapshot
`e44ca6351bb9a9c69a0b5489e09faac97f90309dc5e2a0b9f90eae8cf3b93a21`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,303,744`, SHA-256
`11c78291e0d733c7355b8411c28376ef08ec129e43685bc7a9eb5db946f38951`,
and CodeDirectory CDHash `62aa4cabf5507bee36567b03d4766b8fa12e8c70`.
The temporary absent-tuple measurement hook was then removed completely and
the explicit no-hook search passed before the exact sole product tuple was
added to the reviewed source-snapshot allowlist. Both measurement gates passed
the unsigned Simulator fixture. The normal non-measurement gate then rebuilt
and admitted the exact allowlisted Helper and passed the fixture. Formatting,
locked Clippy with warnings denied, all 287 Workspace tests, Ruby syntax, diff
hygiene, and the explicit no-measurement-hook check also pass. The allowlist
commit and final complete-diff CR remain required before push and merge; the
phone remains untouched.

That final complete-diff CR found one P1 lifecycle-identity gap. Later lanes
accepted any owner-only experiment directory containing a structurally valid
copy of the retained phases, so a copied directory could be closed while the
original fixed lifecycle remained open. Enrollment publication now creates a
canonical binding for the held output-root and newly published experiment
device/inode identities plus the Enrollment experiment ID inside the same
staging directory before the atomic rename. The frozen Host authorization key
signs that binding. Every later operation authenticates it against the
independently reopened frozen source, requires the fixed child name, and
revalidates the persisted parent, held experiment, and current path identities
at entry and on both sides of each publication boundary. A follow-up
uncommitted CR rejected the initially unsigned binding; the regression now
proves that the original directory is accepted while both an unchanged copy
and an owner-rewritten copy under another parent are rejected. A second
uncommitted CR found no diff-scoped correctness issue after the signed-binding
remediation; all 55 Helper tests, locked Clippy with warnings denied, formatting,
Ruby syntax, and diff hygiene pass. Because the Rust Helper changed, two new
independent reproducibility measurements, replacement of the sole allowlist
tuple, the normal and complete local gates, and a new clean final CR remain
required before push and merge. The phone remains untouched.

The authenticated lifecycle remediation was then committed locally. The first
measurement attempt proved the temporary absent-tuple gate was too broad when
Fastlane's deliberate substituted-SHA regression reached it; that attempt
failed before a current Helper build and contributed no measurement. The gate
was narrowed to sources with no existing allowlist entry. Two subsequent,
independent complete Fastlane gates each rebuilt three Helpers from source
snapshot
`29bcf258ce3bb2a8ada0798ae65b6de1adaeed7c1c4c9cc97be38194eb645f67`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,360,384`, SHA-256
`3d9a39ad38ace5856c662120d867491cf53d81aa57bdf437a498ca3d6f1241fb`,
and CodeDirectory CDHash `95a4b27a75f08ac1337174dddac460aeb17ae028`;
both unsigned Simulator fixtures passed. The temporary gate was removed
completely and the explicit no-hook search passed before this exact sole
product tuple was added to the reviewed source-snapshot allowlist. The normal
non-measurement gate then rebuilt and admitted the exact Helper and passed the
unsigned Simulator fixture. Formatting, locked full-Workspace Clippy with
warnings denied, all 288 Workspace tests, Ruby syntax, diff hygiene, and the
explicit no-measurement-hook search also pass. The allowlist commit and a clean
final complete-diff CR remain required before push and merge. The phone remains
untouched.

That final complete-diff CR found one P1 compatibility regression. Moving the
generic upload attempt inside the LAB-002 source-lock block meant valid earlier
DemoLab evidence took the gate's non-checkpoint early return without yielding,
so the lane could finish without uploading or recording a result. The bypass
now explicitly yields the generic upload block, preserving the prior path while
checkpoint `1.0 (3)` still holds its three source locks through upload and
terminal-result publication. A Fastlane regression requires non-checkpoint
evidence to execute that block. Because this changes only Fastlane control flow,
the measured Rust source snapshot and Helper tuple are unchanged. The complete
Fastlane gate, all 288 Workspace tests, locked all-target Clippy with warnings
denied, Rust formatting, Ruby syntax, diff hygiene, and the explicit
no-measurement-hook search pass after the fix. A fix commit and a new clean
final CR remain required; the phone remains untouched.

The next complete-diff CR found one P2 representation-binding gap. The frozen
Oracle retained the complete slice tuples but omitted the source Mach-O
container kind, so Host comparison inferred only thin versus multi-slice and
could accept `fat32` evidence for a frozen `fat64` executable, or vice versa.
Each Oracle role now retains the exact `thin`, `fat32`, or `fat64` kind derived
from the mutually matching frozen Archive/IPA reports, and Host closure compares
that value exactly. Schema negatives reject a missing or unknown kind, the
generator regression binds it to the frozen binaries, and the Host regression
rejects FAT-kind substitution with an otherwise identical multi-slice
inventory. Because this changes the Rust Helper, two new independent complete
reproducibility measurements, a replacement sole allowlist tuple, the normal
and complete local gates, and a new clean final CR are required before push and
merge. The phone remains untouched.

After committing the exact-container remediation, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`5b17f8c1f0487364c896f9fe5e7d99ad9d0a78792644f6da1a5846c3b68d5fb6`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,361,856`, SHA-256
`6839cda7e73f0877998efdf59783bba849fc85772e14318d8c977d5097484986`,
and CodeDirectory CDHash `b1554d431c643b3232161e90abd500058012e0b7`;
both unsigned Simulator fixtures passed. The temporary hook applied only when
the source snapshot had no existing allowlist entry, so the existing
substituted-product regression remained fail-closed. It was then removed
completely, and the explicit no-hook search passed before the exact sole
product tuple was added to the reviewed source-snapshot allowlist. A normal
non-measurement gate rebuilt and admitted the allowlisted Helper and passed the
unsigned Simulator fixture. Rust formatting, locked all-target Workspace
Clippy with warnings denied, all 288 Workspace tests, Ruby syntax, diff
hygiene, and the explicit no-measurement-hook search also pass. The allowlist
commit and a new clean final complete-diff CR remain required before push and
merge. The phone remains untouched.

That clean complete-diff CR then found one P2 publication-content race. The
operator phase guard closed the directory inventory and frozen source but did
not rebind the individual staging files immediately before and after rename,
so a same-owner process could replace verified bytes under the same names. The
publisher now records every created artifact device/inode identity and performs
two bounded passes over the exact filename set at both publication boundaries;
each pass requires the original identity, owner, `0400` mode, length, and exact
bytes. Inventory enumeration stops as soon as it exceeds the fixed expected
count. Deterministic regressions cover staging rewrites, post-rename rewrites,
same-name replacement between the two passes, and above-bound inventory. Two
follow-up uncommitted CRs first identified the missing second pass and bound,
then found no remaining diff-scoped correctness issue. All 59 Helper tests,
locked Helper Clippy with warnings denied, Rust formatting, and diff hygiene
pass. Because the Rust Helper changed, two independent complete reproducibility
measurements, replacement of the sole allowlist tuple, normal and complete
local gates, and a new clean final CR remain required before push and merge.
The phone remains untouched.

The first post-fix measurement attempt produced two identical candidate Helper
identities but is not counted because the complete gate stopped before its
Simulator fixture. The selected Xcode 26.6 toolchain reports iPhoneOS SDK build
`23F81a`; the artifact schema and artifact validator already accept Apple's
uppercase train letter with an alphanumeric suffix, while the independently
implemented build-binding validator incorrectly rejected every lowercase
suffix. The binding and device-environment validators now share the closed
schema grammar: numeric prefix, one uppercase train letter, and a nonempty
alphanumeric suffix. Regressions accept the real SDK spelling while preserving
rejection of a lowercase train letter. Core, schema, fixture, and Helper tests,
locked all-target Workspace Clippy with warnings denied, Rust formatting, and
diff hygiene pass. This Rust change requires a new commit and restarts both
independent reproducibility measurements from zero. The phone remains
untouched.

After committing the Apple-build grammar correction, two independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`ba0cff84503f0ae35344420c3efdc60df6992fbf08336315d6948079a6457438`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,381,712`, SHA-256
`e3c354cf9e4a15de0afd7a886802d09066d3c6c7496096f3379a0cb8279f1047`,
and CodeDirectory CDHash `b114a781ed4799057138f237f8d334bf04aecbd7`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was then removed completely, and the explicit no-hook search
passed before this exact sole product tuple was added to the reviewed
source-snapshot allowlist. A normal non-measurement gate rebuilt and admitted
the allowlisted Helper and passed the unsigned Simulator fixture. The complete
local gates also pass: Rust formatting, locked all-target Workspace Clippy with
warnings denied, all 292 Workspace tests, Ruby syntax, diff hygiene, and the
explicit no-measurement-hook search. The allowlist/progress commit and a new
clean complete-diff CR remain required before push and merge. The phone remains
untouched.

The final complete-diff Codex CR against the unchanged reviewed `origin/main`
found no actionable correctness issue. Its focused tests, Clippy, Ruby syntax,
and diff validation passed; the separately executed normal local gate remains
green with all 292 Workspace tests. Checkpoint 4B is ready for its SSH push,
remote PR/CI inspection, pre-merge CR, and merge. The phone remains untouched.

Remote review of the pushed head then identified one P2 cross-clock ordering
failure before merge. A signed iPhone Receipt or completed Session may be up to
the bounded clock allowance ahead of the Mac observation while still remaining
inside its authorization window. The Host previously wrote the Mac `now()`
directly into its Selection/Binding, so the complete verifier could reject a
lawful chain because the Host closure appeared earlier than the signed device
event. Both closure paths now use the later of the Host observation and the
already verified signed device event. The existing complete-chain verifiers
continue to enforce the signed authorization deadline, so this preserves
causal order without widening any authorization window. Deterministic
regressions cover an iPhone event 120 seconds ahead and prove that a later Host
observation is never moved backward.

Because that fix changed the Rust Helper, two independent complete Fastlane
gates each rebuilt three products from source snapshot
`35af1682b7d2b7a98769ed64e5c4aa4bc7f227d60b5a7d4f2a2a745871a63d22`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,381,696`, SHA-256
`127f2821f48835dfd74aea409043dc0cb6abcd366d9fb29d3968e485438cecfc`,
and CodeDirectory CDHash `9eee8288d796fa943a6e308f8d98268e846ecea8`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely before this exact sole product tuple
was added to the reviewed source-snapshot allowlist, and the explicit no-hook
search passes. A normal non-measurement gate rebuilt and admitted only the
allowlisted Helper and passed the fixture. The complete local gates pass with
Rust formatting, locked all-target Workspace Clippy with warnings denied, all
294 Workspace tests, Ruby syntax, diff hygiene, and the no-hook search. The
allowlist/progress commit, clean complete-diff Codex CR, SSH push, remote CI and
review inspection, pre-merge CR, and merge remain strictly ordered. The phone
remains untouched.

The required complete-diff Codex CR against unchanged `origin/main`
`9bb4ee86b051e7794fb2d63c57bc1cdd31b9cde4` then completed with no actionable
correctness issue. Its independent Core and Operator test reruns passed. The
only Workspace rerun failure was the review sandbox denying Unix-socket
creation before the CLI test assertion; the same test and all 294 Workspace
tests pass in the normal local gate recorded above. The remaining order is now
SSH push, remote review-thread and CI closure, a fresh pre-merge Codex CR, and
merge. The phone remains untouched.

PR #74 then passed all three remote CI jobs, closed both review threads, and
was squash-merged to `main` as `4c021cb1f6a01f26f904ce90769c88fbaf54a1f0`.
The final pre-merge CR raised one proposed pre-upload/installed SuperBlob digest
equality check; a separate read-only adjudication rejected it because Apple
re-signs TestFlight artifacts and the frozen design deliberately binds the
installed target identity, UUID, slice/range tuple, signature state, and
two-run installed digest stability instead. Adding the proposed equality would
reject the legitimate first-party TestFlight installation. Checkpoint 4B is
therefore complete without a production change. No installation, enrollment,
or observation occurred; 4C remains gated on the immediately preceding fresh
RFC-0001 acknowledgement and one-shot installation envelope.

On 2026-08-03 the operator supplied the required fresh 4C acknowledgement for
the exact owned `Jack iPhone` and first-party DemoLab `1.0 (3)` tuple. The Host
locked the selected environment to `iPhone15,2`, iOS `26.6` build `23G5065a`
and validated the frozen candidate/prebuild structure. The first
`demolab_operator_start_enrollment` invocation then failed closed before any
publication: the Helper exited before emitting its staged-directory identity,
which closed the acknowledgement pipe, and Fastlane surfaced an unhandled
`Errno::EPIPE` instead of the Helper's bounded stderr. The new owner-only output
root remained empty; no envelope, experiment, TestFlight installation, app
import, enrollment key, receipt, or device observation was created. The root is
retained as failure evidence. The remediation preserves fail-closed behavior,
records whether the one-byte acknowledgement was delivered, continues bounded
stdout/stderr collection after `EPIPE`, and reports the Helper failure before a
secondary pipe diagnostic. Regression coverage exercises both successful
delivery and a reader that closes early. Because the original acknowledgement
was tied to the failed immediate attempt, 4C must receive a new fresh
acknowledgement after this fix passes CR, CI, PR, and merge; the failed attempt
must not be retried from unreviewed source.

The remediation's local gate passed: Ruby syntax and diff hygiene, Rust format,
locked all-target Clippy with warnings denied, all 294 Workspace tests, and the
complete device-free `demolab_check` including both acknowledgement-pipe
regressions and the unsigned Simulator fixture. The pre-push and fresh
pre-merge Codex CRs found no actionable correctness issue; all three remote CI
checks passed, and no review comment or thread remained. PR #76 was then
squash-merged to `main` as `1d617d63fabd576765b28a8ba88fb02e117ecf5a`.
No phone, TestFlight installation, app import, enrollment, or observation action
occurred during remediation. The next and only open 4C gate is a new fresh
RFC-0001 acknowledgement immediately before creating a new owner-only output
root and installation envelope.

After that new acknowledgement was supplied on 2026-08-03, the Host again
locked the same authorized device environment and revalidated the exact frozen
prebuild/candidate structure. It created a distinct empty owner-only output
root and invoked `demolab_operator_start_enrollment` from merged `main`. The
pipe remediation worked as intended and exposed the bounded Helper error:
the frozen Oracle could not decode as the current typed v1 artifact. The attempt
failed before publication, the new root remained empty and is retained as
failure evidence, and no phone, TestFlight installation, app import, enrollment
key, receipt, or observation action occurred.

Read-only diagnosis found no artifact mutation. The Oracle has the exact
checkpoint-3 ledger SHA-256
`326d7a3260600f13dd65c518fdbeafebbfb119deb31dced15eb4745ced5f9472`,
is exact canonical JSON without duplicate keys or trailing bytes, and contains
the frozen three-role/slice tuple. It was created before PR #74 made each v1
Oracle Role's `container_kind` mandatory. All three frozen Archive executables
independently identify as thin arm64 Mach-O files. The remediation therefore
keeps current Oracle decoding strict and admits only those exact historical
bytes by their full published digest, injects only `container_kind = thin` into
the typed in-memory projection, and still requires the operator to re-derive
the same complete Role/Slice/container tuple from both frozen Archive and IPA
before publication. A digest mismatch, noncanonical document, non-Thin binary,
or any other tuple change remains fail-closed. A regression proves strict
current decoding, rejection by the production pin of an arbitrary legacy
document, positive adaptation only under its exact digest, and rejection after
one-byte mutation. Because the Rust Helper changes, two independent complete
reproducibility measurements, replacement of its sole allowlist tuple, all
normal local/CI/CR/PR gates, and merge are required before requesting another
fresh acknowledgement.

Two independent complete Fastlane gates then each rebuilt three products from
source snapshot
`8718d9b88e496d4944e2c25a0186c9cd426f7aa3cdc7f69fa5555d7dd6d4c101`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,382,320`, SHA-256
`1b6b26a3d5a743c20d6836700b5ac42ff6d09262f0eae20b5ba4fda6252bf944`,
and CodeDirectory CDHash `265eae5cecd0812c582c09b84211722d83bae6e4`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely before this exact sole product tuple
was added to the reviewed source-snapshot allowlist. The explicit no-hook
search passed. A normal non-measurement gate rebuilt and admitted only the
allowlisted Helper and passed the unsigned Simulator fixture. The complete
local gates pass with Rust formatting, locked all-target Workspace Clippy with
warnings denied, all 295 Workspace tests, Ruby syntax, diff hygiene, and the
no-hook search. The allowlist/progress commit and complete-diff Codex CR remain
the next ordered gates; the phone remains untouched.

That complete-diff Codex CR found one P2 bounded-input regression: after strict
decoding rejected an oversized Oracle, the compatibility fallback hashed the
entire input before its bounded decoder ran. The fallback now rejects bytes
above the Oracle's fixed 16-KiB limit before computing the compatibility
digest, and a regression supplies an oversized input whose supplied digest
otherwise matches. This Rust Helper change invalidates the preceding product
measurement for the new source snapshot; two fresh independent complete
reproducibility measurements, a new sole allowlist tuple, the normal and
complete local gates, and a new clean complete-diff CR are required from zero.
The phone remains untouched.

After committing that bound, two fresh independent complete Fastlane gates
each rebuilt three products from source snapshot
`1c57b49686812fa59d7e4e76dd6b343150329153c565ff3ad6d99b05a2cf6706`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,382,320`, SHA-256
`9f6836b922b4b71961a59acf01d8701632f0b3ff8c971fe7be54d1d289c61d26`,
and CodeDirectory CDHash `c447cb4b4f1e597f1f5ffc47fa4cac93753f9119`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely before this exact sole product tuple
was added to the reviewed source-snapshot allowlist. The explicit no-hook
search passed. A normal non-measurement gate rebuilt and admitted only the
allowlisted Helper and passed the unsigned Simulator fixture. The complete
local gates pass with Rust formatting, locked all-target Workspace Clippy with
warnings denied, all 295 Workspace tests, Ruby syntax, diff hygiene, and the
no-hook search. The allowlist/progress commit and a new clean complete-diff
Codex CR remain next; the phone remains untouched.

That new complete-diff Codex CR traced the bounded, full-digest-pinned adapter
through every frozen Host/Operator caller and found no actionable defect or
P1/P2. Its isolated Workspace run could not create the CLI Unix-socket fixture
because the review sandbox denied that OS operation; the same test and all 295
Workspace tests had already passed in the normal local gate. Core and LAB-002
tool tests, locked all-target Clippy with warnings denied, Rust formatting,
Ruby syntax, diff hygiene, and the no-hook search all passed. The next ordered
steps are PR #78 remote CI/review closure, a fresh pre-merge Codex CR at the
exact head, and merge. Only after that merge may Host request a new fresh 4C
acknowledgement; the failed attempt's prior acknowledgement is not reused, and
the phone remains untouched.

PR #78 then passed all three required remote CI jobs with no review thread or
comment. A fresh pre-merge Codex CR at exact head
`5830371288decd1c906c86aec8baee357b89f604` traced the complete compatibility
path, reproduced the source-snapshot selection, reran focused Core and Tool
tests plus Clippy, formatting, Ruby syntax, and diff hygiene, and found no
actionable defect or P1/P2. The only full-Workspace rerun failure remained the
review sandbox denying Unix-socket creation before the CLI assertion; the same
test passed in the normal local and remote gates. PR #78 was squash-merged to
`main` as `867c8983b9ea603a7bca2bbbd5f772923626b394`. No phone, TestFlight
installation, app import, enrollment, or observation action occurred. The
failed attempt's acknowledgement remains consumed; the next and only open 4C
gate is a new fresh RFC-0001 acknowledgement immediately before creating a new
owner-only output root and one-shot installation envelope.

After PR #79 recorded that closure on `main`, the operator supplied the next
fresh 4C acknowledgement. Host revalidated clean merged source, the exact
frozen prebuild/candidate pair, its published Oracle digest, and the selected
`iPhone15,2` / iOS `26.6` (`23G5065a`) environment. The Mac also established
iPhone Mirroring without opening TestFlight. The orchestration that launched
`demolab_operator_start_enrollment` then treated its still-running Fastlane
session as a terminal failure and discarded the continuation handle. The
continuation handle could not then be recovered. Before authorizing any retry,
a terminal reconciliation found no Fastlane process and no
`demolab_operator_start_enrollment` process, reacquired exclusive nonblocking
locks on all three bound output/prebuild/candidate directories, and rechecked
the distinct owner-only output root as mode `0700` with zero entries. The
orphaned session therefore cannot publish later or retain an operator binding;
no installation envelope, experiment, TestFlight action, app import, enrollment
key, receipt, or observation exists. The same
merged source subsequently passed the complete device-free `demolab_check`,
including its private-Helper allowlist and unsigned Simulator fixture. This is
an operator-session interruption, not a product or device result. Its
acknowledgement is consumed, its empty root is retained as failure evidence,
and 4C again requires a new fresh acknowledgement. The next orchestration must
retain and poll any yielded Fastlane session until its actual terminal result.

After PR #80 merged that interruption closure, the operator supplied the next
fresh 4C acknowledgement. Host validated clean merged source, the same frozen
candidate/prebuild tuple and Oracle digest, and the same connected owned-device
environment, then retained and polled the Fastlane session to exit status 1.
The Helper failed before publication because the pre-upload authorized-target
manifest identity was invalid. The new owner-only output root remains mode
`0700` with zero entries; no envelope, experiment, TestFlight action, app
import, enrollment key, receipt, or observation exists, and the root is
retained as failure evidence.

Read-only reconciliation established that the Host had rebooted after the
evidence was frozen. The evidence records the same old filesystem device number
for its manifest and Oracle; both current held files report the same new device
number. Each file still matches its independently recorded inode, mode, size,
and SHA-256 exactly. The remediation remains pinned to the already published
checkpoint-3 legacy Oracle digest: it may ignore only that coupled old-to-new
device-number transition when both recorded device values are canonical
decimal identities and equal, both
current device values are equal and different from the recorded value, and
every other identity field matches. Current/non-pinned evidence remains strict;
an independently moved artifact or any inode, mode, size, or digest change is
rejected. Focused positive and negative regression coverage is required before
the complete local gate, Codex CR, CI, PR, and merge. This acknowledgement is
consumed, and the phone remains untouched.

The first uncommitted Codex CR found one P2 provenance gap in that boundary:
the two recorded device fields had to be equal but were not yet required to be
canonical decimal identities. The compatibility predicate now parses both
through the existing bounded identity parser before comparing them; regressions
reject arbitrary and leading-zero strings. The reproducibility, allowlist,
complete-gate, clean-CR, CI, PR, and merge requirements remain unchanged.

After committing the P2 remediation, two independent complete Fastlane gates
each rebuilt three Helpers from source snapshot
`5862d99f2b13c759bfdc4ae51092e03540a435c9dfa3896feda3dbe71a583928`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,399,296`, SHA-256
`ac58ecf872d42b5e6fb7ff49eda243afa20c5929832c9c6783702188e40e2993`,
and CodeDirectory CDHash `43d36eac4ebf50693d6e91038454b54d2dce5a7a`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely before this exact sole product tuple
was added to the reviewed source-snapshot allowlist. The subsequent complete
gate passed all Workspace tests but rejected a collapsible Helper conditional
under warnings-denied Clippy. That source snapshot and allowlist tuple were
therefore invalidated and removed; the one-line equivalent remediation requires
two fresh measurements from zero. The phone remains untouched.

Two fresh independent complete Fastlane gates then each rebuilt three Helpers
from source snapshot
`8571652a1e7d822070e5abdf32f89295c3f6b88bc4aa43b58d8d8ef1e56f7cb5`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,399,296`, SHA-256
`55c16316546e134e6b0594ccc283d6ec490e559a259e3c0541d34716de129f40`,
and CodeDirectory CDHash `0e9663164bb2dcb470dc1a771fb195fb1b0d9222`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely and the explicit no-hook search passed
before this exact sole product tuple was added to the reviewed source-snapshot
allowlist. A normal non-measurement gate, complete local gates, and a new clean
complete-diff Codex CR remain required before push; the phone remains untouched.

The normal non-measurement `demolab_check` then accepted only the reviewed
Helper tuple and passed its unsigned Simulator fixture. Rust format, locked
all-target warnings-denied Clippy, all 296 Workspace tests, Ruby syntax, diff
hygiene, and the explicit no-measurement-hook search passed. The complete-diff
Codex CR against unchanged `origin/main` found no actionable correctness issue
or P1/P2. The reviewed branch was pushed over the configured SSH remote and
opened as [PR #81](https://github.com/jacklv-coder/OrchardProbe/pull/81); its
remote head, base, commit list, and nine-file inventory matched the local
reviewed scope, and it opened with no review threads. The next ordered gate is
remote CI/review closure, followed by a fresh exact-head pre-merge Codex CR and
merge. Only after that merge may Host request another new acknowledgement and
create a new 15-minute installation envelope; the prior acknowledgement remains
consumed and the phone remains untouched.

PR #81's initial three required CI jobs passed, but remote Codex Review then
identified one P2 provenance gap before merge: the compatibility predicate
pinned the exact legacy Oracle digest while accepting any pair of identical
canonical recorded device values in the separate Evidence file. Because the
Oracle digest does not authenticate that file, a changed Evidence device pair
could be misclassified as the documented reboot transition. The remediation
now enables the exception only when both the Oracle bytes and the complete
frozen pre-upload Evidence bytes match their exact checkpoint-3 digests; the
existing coupled old/new device and every inode/mode/size/name/digest check
remain required. Regressions bind and mutate the Evidence digest. The prior
Helper source snapshot and allowlist tuple were removed, and two fresh
independent measurements, normal/complete local gates, clean CR, remote CI,
thread closure, pre-merge CR, and merge are required. The phone remains
untouched.

After committing the exact-Evidence pin, two fresh independent complete
Fastlane gates each rebuilt three Helpers from source snapshot
`b503cca5aeae01565d9a80117e5725c3a3d27c547feb5a892087b8fed4264ffd`.
All six products were identical with toolchain
`1.85.0-aarch64-apple-darwin`, size `3,399,408`, SHA-256
`4aa9e2c157dd2743d7141fe31733bbab59dc1b42f5e3a080623c308fd4c3137f`,
and CodeDirectory CDHash `ceae099c2b723df7842f7ba34eb311920deafdda`;
both unsigned Simulator fixtures passed. The temporary absent-source
measurement hook was removed completely before this exact sole product tuple
was added to the reviewed source-snapshot allowlist. A normal non-measurement
gate, complete local gates, clean CR, remote CI/thread closure, pre-merge CR,
and merge remain required; the phone remains untouched.

The normal non-measurement `demolab_check` rebuilt and admitted only that
reviewed Helper tuple and passed the unsigned Simulator fixture. Rust format,
locked all-target warnings-denied Clippy, all 297 Workspace tests, Ruby syntax,
diff hygiene, and the explicit no-hook/invalidated-tuple search passed. The
fresh complete-diff Codex CR found no actionable correctness issue or P1/P2.
The next ordered gates are commit, SSH push, remote CI/thread closure,
pre-merge CR, and merge. The phone remains untouched.

The evidence-pinned remediation commits were pushed through the configured SSH
remote. PR #81's remote head and nine-file inventory matched the reviewed local
scope, and its Build fixture, Foundation files, and Test and lint jobs all
completed successfully. The P2 thread was answered with the dual-digest pin,
regression, reproducibility, local-gate, CR, and CI evidence, then resolved.
The next ordered gate is a fresh Codex CR over the exact committed PR head;
after the resulting documentation-only update also passes remote CI and thread
inspection, PR #81 may merge. The consumed acknowledgement cannot be reused,
and the phone remains untouched.

PR #81 then passed the exact committed-head pre-merge Codex CR with no
actionable correctness issue, followed by a final successful three-job CI run.
Its remote head, clean mergeability, empty general-comment set, and sole
resolved/outdated P2 thread were rechecked immediately before squash merge.
The resulting merge is authoritative on `main`, and the remote topic branch is
gone. At that point Host could request one new acknowledgement immediately
before creating a new 15-minute installation envelope in a new owner-only
output root; the prior empty failed root remained private evidence and the
phone had not yet been operated. The later 2026-08-04 device attempt and its
terminal retained No-Go are the authoritative current status recorded above.
