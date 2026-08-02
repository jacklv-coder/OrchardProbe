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
