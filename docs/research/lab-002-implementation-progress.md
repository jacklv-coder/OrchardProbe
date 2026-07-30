# LAB-002 implementation progress ledger

Status: **Checkpoint 2 active in PR #59 final remote verification**

This is the working ledger for checkpoint 2 of
[LAB-002](lab-002-oracle-design.md). It records implementation progress without
claiming that unmerged work exists on `main`. The authoritative checkpoint
remains `planned` in [the execution plan](../../EXECUTION_PLAN.md) until one
complete implementation PR passes Codex CR, required CI, and merge review.

No row in this ledger authorizes a signed build, TestFlight upload, app
installation, device observation, or device-backend work.

| Order | Substep | Branch-local status | Completion evidence / next gate |
|---:|---|---|---|
| 2A | Closed protocol foundation and fixed Mach-O range | `done` | Domain-separated build/target/device bindings, bounded canonical JSON, Ed25519 authorization envelopes, two-run comparison, role-specific `__TEXT,__oprobe`, a fail-closed parser, fixture-only CI inspection, adversarial tests, and Codex CR are complete with no remaining P1/P2 |
| 2B | Closed schemas and complete host artifact chain | `done` | All 18 wire forms, the exact enrollment/run/two-run verifier chain, adversarial fixtures, the complete local gate, and final Codex CR pass with no remaining P1/P2 |
| 2C | DemoLab state coordinator and zero-argument observers | `done` | The documented 2C.1–2C.5 sequence is complete; no caller-selected target, range, path, PID, or address |
| 2D | Synthetic and Simulator verification | `done` | The documented 2D.1–2D.4 matrix now covers the two-run lifecycle, all three roles, every built Simulator slice, negative state/crash/replay boundaries, and explicit Simulator `inconclusive` semantics |
| 2E | Documentation, final CR, CI, PR, and merge | `active` | PR #59 passed its first CI run; production authorization, the usable device workflow, signed-archive capability injection, the interruption/durability review fixes, all local gates, and the final pre-push CR are complete; push, remote CI/review, the pre-merge CR, and merge remain |

## Current verified facts

- The three repository-owned DemoLab roles each emit exactly one deterministic
  256-byte `__TEXT,__oprobe` section per Simulator slice.
- Device-free Rust tests cover binding changes, canonical JSON rejection,
  authorization signature tampering, two-run replay/environment/inventory
  drift, protection/plaintext contradictions, and malformed Mach-O structure.
- Exact Debug and Release Simulator products pass the frozen three-role,
  two-slice inventory: each configuration has six distinct role/slice range
  hashes, with one 256-byte section per slice.
- The full local gate passes: 5 CLI unit tests, 17 CLI integration tests,
  171 core tests, 1 fixture integration test, 9 schema tests, formatting,
  Clippy with warnings denied, and the base-relative diff check.
- PR #59 is the checkpoint-2 implementation PR. Its first required CI run
  passed. Remote review then found three production-integration P1s rather
  than a protocol failure: the app lacked a production authorization
  validator, its coordinator actions were not reachable from the UI, and the
  archive lane retained the generic App Group. 2E now includes all three
  fixes. A later local CR's one P1 and three P2 findings around interruption
  recovery and durability-uncertain states are also closed. The next final
  re-review found three additional P2 ordering/recovery issues: run windows
  predating the retained enrollment receipt, pre-commit cleanup failures being
  made terminal, and exact persisted receipts losing recovery precedence after
  authorization expiry. All three now have focused regressions. The following
  final CR found two more P2 recovery gaps: missing enrollment receipts being
  reported ready, and pre-commit completion errors stranding
  `completion_pending`. Both now fail closed or roll back at the correct commit
  boundary, with focused regressions. The latest CR then found two P1 binding
  and recovery-window gaps plus one P2 weak-key gap: run acknowledgements did
  not retain the enrolled target-manifest digest, outside-window
  authorizations could remain stuck, and Apple-side validation did not reject
  every Ed25519 low-order public key. All three are now closed with focused
  regressions. The following CR found one P1 fail-closed UI gap and one P2
  receipt-handoff gap: a failed durable recovery could leave stale retry
  controls active, and run import could hide an enrollment receipt before the
  user confirmed saving it. Both are now closed by terminal recovery handling
  and an explicit receipt-save gate with regressions. The next CR found one P1
  persisted-session gap: in-progress or completed recovery did not revalidate
  the durable enrollment proof. Recovery now requires the authenticated
  receipt, installation state/key/binding, enrollment-control tuple, and exact
  counter before resuming or exporting, with two regressions. The latest
  pre-push CR also found that interrupted `session.json.tmp` publication was
  read but not promoted before observation; recovery now completes that exact
  atomic publication with an end-to-end regression. The Simulator suite now
  contains 65 tests. The
  dual-architecture fixture build, complete Rust/schema gate, and Fastlane
  unsigned-fixture lane also pass. Merge remains blocked until the post-fix
  gates and Codex re-review, remote CI, and PR review are clean.
- The final focused 2A Codex CR found no actionable P1/P2 after reviewing
  segment overlap, classic/chained fixups, chained import names, dynamic
  relocation tables, section bounds, and the non-public CLI boundary.
- Device-free success is named `consistent_synthetic_evidence`; it is never a
  LAB-002 Go result or proof that a physical device was observed.
- 2B.1 now has one self-contained Draft 2020-12 bundle covering 16 retained
  top-level artifact families plus the two embedded unsigned cores. Nine schema
  tests pass, including both-run counter substitution, independent binding
  counters, fixed role/slice order, all 100 MiB executable surfaces, fixed
  `__TEXT,__oprobe`, contradictory outcomes, and unknown fields.
- The final focused 2B.1 Codex CR found no remaining actionable P1/P2.
- 2B.2 now provides 18 exact `lab002::artifacts` Rust wire types with
  deny-unknown deserialization, required-null field distinction, bounded JCS
  generation/exact decoding, scalar and coordinate validation, and embedded
  canonical-core validation. Positive round trips and adversarial cases cover
  noncanonical bytes, missing or explicit-null fields, negative timestamps,
  byte limits, one-character embedded JSON, zero encryption sizes, and
  contradictory encryption coverage.
- The final split-scope 2B.2 Codex CR resolved all reported P1/P2 and its
  focused rechecks are clean.
- 2B.3b now verifies the exact six-artifact enrollment chain from the private
  target manifest through the host-signed installation envelope, device-signed
  receipt, physical-selection confirmation, and final enrollment binding.
  Focused tests reject acknowledgement-byte, receipt-signature,
  selection-fingerprint, final-binding, and timestamp-order substitutions.
- The focused 2B.3b Codex CR reviewed exact-byte binding, strict Ed25519 key
  handling, replay/substitution boundaries, cross-artifact equality, and the
  owner-confirmed physical fingerprint trust input; it found no remaining
  actionable P1/P2.
- 2B.3c now closes one exact run from the run acknowledgement and
  host-signed challenge through the intent, enrollment-key-signed export, four
  exact embedded reports, and final collection binding. It rejects experiment,
  entry-digest, role-document, environment, clock-skew, role-order, and final
  binding substitutions.
- The 2B.3c Codex CR found and resolved enrollment-to-run and cross-role time
  continuity gaps. A run window and its skew-tolerated session must begin
  after the verified enrollment binding, and main-app, framework, then
  share-extension phases cannot step backward. The final focused recheck is
  clean.
- 2B.3d now closes one Enrollment plus two distinct ordered runs. It rejects
  swapped/replayed runs, broken Run-2 prior binding, overlapping windows,
  authorization before Run-1 closure, repeated acknowledgement/challenge/
  collection/session identifiers, shared artifact hashes, counter drift, and
  enrollment/device/environment drift.
- The 2B.3d Codex CR found and resolved one-time acknowledgement ID, random
  challenge ID, and Run-1-binding-to-Run-2-authorization continuity gaps. Its
  focused recheck is clean.
- The final 2B.4 gate rebuilt exact Debug and Release Simulator products and
  passed the frozen fixture-product test. The complete Rust gate, formatting,
  Clippy with warnings denied, schema contracts, and base-relative diff check
  pass. The final all-change Codex CR found no actionable issue.
- 2C.2 now has one main-app-only fixed storage implementation with owner-only
  directories/files, no-follow bounded reads, an exclusive coordinator lock,
  descriptor/entry identity checks, no-replacement inbox publication,
  quarantine/restore/consume transitions, exact canonical counter records,
  checked monotonic counter commits, complete file protection, and backup
  exclusion. The extension compiles only the fixed names/limits.
- The generic App and Share Extension entitlements expand to the same generic
  App Group in Debug and Release. Six Simulator storage tests pass for
  duplicate/oversized/symlink import, current/expired/malformed discard,
  quarantine residue, counter skip, consumption, and canonical state. The
  final focused 2C.2 Codex CR has no remaining actionable P1/P2.
- The earlier four-field counter shape existed only in an unpushed,
  uninstalled branch-local draft. It is rejected rather than migrated because
  accepting bytes outside the frozen three-field schema would create trusted
  monotonic state from an invalid format; no released build wrote that draft.
- 2C.3 now has the exact five-field installation-nonce state and one fixed
  production Keychain tuple. Authenticated enrollment alone may create its
  Ed25519 key and 32-byte nonce; production items are non-synchronizable and
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The Keychain entitlement and
  Info.plist consume one explicit access-group build setting; the controlled
  signed lane injects the complete Team ID plus App bundle identifier. Every
  run only loads and compares the recorded build/public key, so missing,
  cross-build, or mismatched key state fails without creation or repair.
  Production enrollment/run/discard entry points take neither time nor build
  identity from their caller: time comes from the system clock and the exact
  lowercase 64-hex build binding comes from the compile-time-injected app
  Info.plist. The signed archive refuses a missing or malformed precomputed
  binding and injects the validated value; it cannot emit a production
  candidate with the checked-in empty setting. Test overrides exist only
  behind the Debug-only test initializer. The first focused CR found one
  interrupted-enrollment recovery gap: a Keychain item could survive while
  nonce/state persistence failed. The item now stores and checks its build
  binding, so only a later authenticated enrollment for that same build may
  recover the orphaned key and finish the exclusive state creation; a run
  cannot invoke that path and a different build is rejected. The next recheck
  found the complementary crash boundary after state persistence but before
  authorization deletion. Enrollment alone may now resume that exact
  quarantined authorization, revalidate it, strictly load the persisted
  state/key, and finish deletion. A fresh re-enrollment and every run still
  reject quarantine/state conflicts. Eleven synthetic Simulator tests and
  Debug/Release builds pass; the final focused Codex recheck found no remaining
  actionable P1/P2.
- 2C.4a now closes one immutable canonical `session.json` from the verified
  run envelope, compile-time build/observer/source facts, authenticated
  enrollment continuity, recomputed installation binding, fixed environment
  queries, exact run counter, system time, and 32 bytes of system randomness.
  Creation is exclusive beneath the fixed `reports/current` directory with
  bounded no-follow reads, atomic publication, complete protection, and backup
  exclusion. Nineteen synthetic Simulator tests cover exact canonical
  decoding, session exclusivity/size bounds, counter and authorization
  consumption, skipped counters, existing/staged sessions, interrupted
  transaction recovery, replay rejection, and invalid source provenance. The
  focused CR found and closed the state-ordering and recovery gaps: all
  fallible session validation and conflict preflight happen before a new
  counter commit; the exact authorization remains quarantined until the
  counter and session are durable; and only that pre-existing quarantine may
  recover a matching committed/staged transaction. A fresh replay is restored
  and rejected. CR also closed a source-provenance mismatch by making the
  archive lane reject Git object IDs outside the frozen 40-hex LAB-002 wire
  form before build staging.
- 2C.4b now implements the target-private installed-file and mapped-header
  Mach-O core. Its stable descriptor reader uses read-only `O_NOFOLLOW`,
  regular-file/100 MiB limits, exact `pread`, and post-parse identity and
  metadata revalidation. Bounded thin/FAT32/FAT64 parsing accepts at most four
  non-overlapping slices, binds CPU/subtype/ordinal/UUID and checked file/VM
  coordinates, requires exactly one 64–1,024 byte executable regular
  pure-instruction `__TEXT,__oprobe`, and rejects relocations, overlapping
  ranges, or classic/chained fixups targeting executable `__TEXT`. It also
  normalizes the single architecture-correct encryption interval and binds a
  mapped header plus compiled-anchor offset back to the installed slice.
  Caller-selected URL/header entry points exist only in the Debug test harness;
  production construction remains private for the 2C.4c zero-argument role
  wrappers. Twenty-eight synthetic Simulator tests, a Release Simulator build,
  and focused Codex CR pass with no remaining actionable P1/P2.
- 2C.4c1 now assembles the three zero-argument target-local observations.
  Each target supplies only its fixed bundle and compiled anchor, requires
  `dladdr` path binding, matches one mapped header to the installed
  CPU/subtype/UUID/range, checks readable executable VM containment, and hashes
  the exact mapped range only after disk inspection. A bounded embedded
  SuperBlob/primary-CodeDirectory parser records identifier, team, selected
  entitlements, CMS/ad-hoc/unknown kind, and SuperBlob SHA-256; the exact
  target-identity framing matches Core. Because iOS has no public
  `SecStaticCode` validator, validation is explicitly `not_checked` and can
  never produce a passing signature claim. Thirty Simulator tests, including
  synthetic signature/identity parity and zero-argument fail-closed checks,
  plus a Release Simulator build and focused Codex CR pass with no remaining
  actionable P1/P2.
- 2C.4c2 now canonically encodes and exclusively publishes the fixed role
  reports. Each target reopens only the compiled App Group and literal current
  report directory, acquires the shared coordinator lock, revalidates the
  complete directory/lock inode chain, and accepts only the exact prefix of
  session, main, framework, and share files. It reparses the immutable session
  and every predecessor, binds all run/build/environment facts, enforces
  nondecreasing phases and the maximum possible authorization window, and
  publishes one owner-only, protected, no-backup, at-most-32-KiB canonical
  report through data flush, post-metadata flush,
  rename-without-replacement, and directory flush.
  Unknown, temporary, duplicate, malformed, oversized, replaced, stale,
  conflicting, or out-of-order state fails closed. Since validation remains
  `not_checked`, the local report is explicitly `inconclusive`, not a
  signature or plaintext success. Thirty-three Simulator tests and a Release
  Simulator build pass. Focused CR found and closed one file-metadata
  durability gap; the final diff has no remaining actionable P1/P2.
- 2C.4d now wires Start to the fixed main/framework runner after durable
  authorization consumption, wires the Share Extension to its own fixed
  observer, and atomically completes only an exact three-report session.
  Completion revalidates the inode chain, canonical session/report bindings,
  fixed role order, nondecreasing phases, the persisted signed absolute
  authorization deadline, and the retained session/report identities and exact
  canonical byte strings through the `session.json` replacement. The rename is
  the explicit commit point, and
  post-commit durability/check failures return a non-retryable uncertain
  outcome. Missing, duplicate, completed, temporary, late, replaced,
  conflicting, or same-inode/same-size mutated pre-commit state remains
  unchanged. Thirty-nine
  Simulator tests, Debug/Release Simulator builds, Rust/schema gates, and
  focused CR pass with no remaining actionable P1/P2.
- 2C.5 now constructs the exact signed enrollment receipt only after the
  authenticated authorization, build, environment, device-only key, nonce,
  and installation binding agree. It returns the full physical-selection
  fingerprint, displays all 64 hex characters for the Host comparison, and
  atomically retains the fingerprint plus exact signed receipt for crash
  recovery. The receipt leaves only through a system share item. Recovery
  revalidates the canonical receipt, Host authorization and receipt signatures,
  build, enrollment key, authorization digest, and recomputed fingerprint. A completed run is
  revalidated into one immutable four-document
  snapshot in session/main/framework/share order; every canonical document
  digest and the distinct export-domain Ed25519 signature match the frozen
  Host schema. The actor retains identical export bytes until a separate
  explicit confirmation. Cleanup revalidates the exact snapshot twice, removes
  only the fixed completed report subtree, preserves the enrollment key,
  installation nonce, and counter, and returns a non-retryable uncertain
  outcome after its first deletion commit. Forty-three Simulator tests cover the
  signatures, fixed names/order, repeat export, explicit confirmation,
  mutation rejection, post-commit identity-failure mapping, cleanup-once
  semantics, and preserved state. Final Debug/Release, Rust/schema, diff, and
  focused CR gates pass with no remaining actionable P1/P2.

## Completed 2B gates

- Define exact closed schemas for acknowledgement, enrollment, oracle, intent,
  signed export, and collection binding.
- Implement the complete host-side artifact generator/verifier chain without
  adding a device transport or a public target/range selection command.
- Enforce every surface-specific byte limit, exact canonical encoding,
  unknown-field rejection, signature binding, freshness window, and replay
  boundary from the reviewed design.
- Add positive and negative fixtures for the entire artifact chain before 2C
  begins.

### 2B execution order

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2B.1 | Freeze the closed schema inventory and field contracts | `done` | All retained artifact families and embedded unsigned cores are closed and bounded; the 9-test schema gate and focused Codex CR pass with no P1/P2 |
| 2B.2 | Implement matching Rust codecs and validators | `done` | All 18 wire forms have exact Rust codecs and validators; 142 core tests, 9 schema tests, Clippy, diff check, and focused Codex CR pass with no remaining P1/P2 |
| 2B.3 | Assemble the host artifact chain and fixtures | `done` | A complete synthetic enrollment plus two-run chain verifies; size, replay, signature, freshness, ordering, digest, and unknown-field fixtures fail closed; all split-scope Codex CR findings are resolved |
| 2B.4 | Run the 2B gates and Codex CR | `done` | Debug/Release Simulator products, the fixture-product test, formatting, Clippy, 5 CLI unit + 17 CLI integration + 167 Core + 1 fixture integration + 9 Schema tests, diff check, and final all-change Codex CR pass with no remaining P1/P2 |

#### 2B.3 execution order

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2B.3a | Domain-separated signatures and exact artifact digests | `done` | Host authorization, enrollment receipt, session export, and device-selection fingerprint use the frozen binary domains; strict Ed25519 rejects weak keys and key/domain/byte substitution; 5 focused tests, Clippy, and focused Codex CR pass with no remaining P1/P2 |
| 2B.3b | Enrollment artifact chain | `done` | The exact six-file chain verifies every digest, host/device signature, challenge, environment, physical-selection fingerprint, key/binding tuple, and timestamp order; 10 focused host tests, Clippy, diff check, and Codex CR pass with no remaining P1/P2 |
| 2B.3c | Per-run export and collection binding | `done` | One exact run closes acknowledgement/challenge/intent/export/four reports/binding with strict signatures, digests, counter, enrollment, environment, and monotonic-time continuity; 19 focused host tests, Clippy, diff check, and Codex CR pass with no remaining P1/P2 |
| 2B.3d | Complete two-run chain and adversarial fixtures | `done` | One synthetic Enrollment plus Run 1 and Run 2 closes with exact ordinal/counters, prior binding, monotonic windows, unique acknowledgement/challenge/collection/session IDs and artifacts, and identical enrollment/device/environment facts; 25 focused host tests, Clippy, diff check, and Codex CR pass with no remaining P1/P2 |

The 2B.3a CR identified and closed a strict-Ed25519 gap in both the new host
path and the earlier authorization verifier: verification now uses
`verify_strict`, weak public keys are rejected, and signing also refuses a
weak derived key.

The 2B.3b CR confirmed that the self-signed enrollment receipt is accepted
only together with the host-signed challenge/envelope and the operator's
full-fingerprint comparison recorded in the owner-only selection artifact.
That explicit physical ceremony is the frozen first-party trust input; this
verifier does not claim hardware attestation.

The 2B.3c verifier returns sealed verified tokens: callers can pass them to the
next verifier but cannot construct or mutate their closed facts. This prevents
an API consumer from replacing a verified key, binding, environment, or time
before the two-run gate.

The 2B.3d CR additionally distinguished the random challenge value inside the
signed core from the SHA-256 of the complete challenge envelope. Both must be
fresh across runs, as must the one-time acknowledgement ID.

## Active 2C execution plan

2C remains device-free. Its implementation and tests use temporary local
containers, synthetic keys, and Simulator builds only. It does not authorize a
signed archive, TestFlight upload, app installation, or physical-device read.

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2C.1 | Freeze target-private API and storage boundaries | `done` | The bilingual device implementation contract freezes fixed relative names, state transitions, zero-argument observer entries, test-only dependency injection, and the prohibition on host/App-Group access or caller-selected path/target/range inputs |
| 2C.2 | Implement fixed inbox and durable state coordinator | `done` | Main-app-only Import/Start/Discard, fixed App Group production lookup, no-follow bounded reads, lock/quarantine identity checks, exact counter commits, atomic writes, protection/backup policy, 6 Simulator tests, Debug/Release builds, and focused Codex CR pass with no remaining P1/P2 |
| 2C.3 | Implement enrollment state and device-only key boundary | `done` | Installation-only synthetic/Keychain key creation, exact key/nonce/build binding, ThisDeviceOnly/non-synchronizable production attributes, authenticated same-envelope interruption recovery, and loss/reset/mismatch rejection; run paths cannot create or repair enrollment; 11 Simulator tests, Debug/Release builds, and focused Codex CR pass |
| 2C.4 | Implement session lifecycle and three zero-argument observers | `done` | Main App, Framework, and Share Extension observe only their compiled self target/range, publish once in fixed order, bind immutable session facts, and fail closed without public path/target/range/PID/address parameters; 39 Simulator tests, Debug/Release builds, and focused CR pass |
| 2C.5 | Implement signed export, receipt, and cleanup boundaries | `done` | Fixed four-document export and enrollment receipt are signed and share-sheet-only; cleanup requires a verified completed export and cannot reset fixed state/key; focused gates and Codex CR have no remaining P1/P2 |

### 2C.4 execution order

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2C.4a | Close and persist the immutable run session | `done` | Exact session-report fields come only from verified authorization, fixed build/runtime facts, enrollment continuity, the exact counter, and system randomness/time; interrupted counter/session publication is recoverable only from the pre-existing exact quarantine, `session.json` is exclusive, and 19 Simulator tests plus focused CR pass |
| 2C.4b | Implement the target-private Mach-O observer core | `done` | Stable no-follow descriptor reads, bounded thin/FAT parsing, exact fixed-section/encryption/fixup evidence, mapped-header/anchor binding, 28 Simulator tests, Release build, and focused CR pass without a production caller-selected input |
| 2C.4c1 | Assemble the three target-private zero-argument observations | `done` | Fixed bundle/anchor and `dladdr` binding, bounded installed signature identity, active mapped-header/range/VM binding, exact disk/mapped digests, 30 Simulator tests, Release build, and focused CR pass without production selector input |
| 2C.4c2 | Encode and publish the three fixed role reports | `done` | Exact canonical reports bind the immutable session, publish exclusively in main/framework/share order, reject duplicate/stale/conflicting/oversized/out-of-order state, and pass 33 Simulator tests, Release build, and focused CR with no remaining actionable P1/P2 |
| 2C.4d | Close the session and run focused gates | `done` | Exact absolute authorization deadline and ordering/completion transitions, explicit non-retryable post-rename uncertainty, retained session/report identity and canonical-byte revalidation, negative Simulator fixtures, 39 Simulator tests, Rust/schema gates, Debug/Release builds, docs, and focused Codex CR pass with no remaining actionable P1/P2 |

### 2C.5 execution order

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2C.5a | Construct the signed enrollment receipt and physical-selection fingerprint | `done` | Exact verified authorization/environment facts, device-only key, nonce, build and installation binding close the frozen receipt schema/domain; the fixed-name receipt is atomically retained for verified crash recovery and leaves only through the system share sheet; signature/fingerprint tests pass |
| 2C.5b | Construct and retain the signed four-document session export | `done` | One exact completed snapshot retains the four canonical documents and digests in fixed order, signs the frozen export domain, rejects key/schema/order substitutions, and repeats identical retained bytes |
| 2C.5c | Require explicit confirmation and clean only matching reports | `done` | Cleanup is impossible before export or on `false`; two exact snapshot revalidations reject mutation, one confirmed cleanup removes the fixed report subtree once and preserves key/state/counter |
| 2C.5d | Run focused implementation gates and Codex CR | `done` | 43 Simulator tests, Debug/Release builds, Rust/schema gates, diff checks, docs, and focused Codex CR pass with no remaining actionable P1/P2 |

## Active 2D verification plan

2D remains device-free and must not turn unsigned Simulator behavior into a
physical-device, protection, plaintext, or decryption claim. The positive
synthetic path proves only that the frozen protocols and state machine agree.
The built-product path must continue to classify Simulator signing/protection
evidence as `inconclusive`.

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2D.1 | Freeze the end-to-end verification matrix | `done` | The ledger requires one enrollment plus two distinct runs, exact counter/session/export/cleanup transitions, all three fixed roles, every Debug/Release Simulator product slice, host two-run verification, negative mutation/order/replay/crash boundaries, and explicit non-Go terminology |
| 2D.2 | Exercise the complete synthetic two-run device lifecycle | `done` | All 45 Simulator tests pass; the deterministic end-to-end test uses the real fixed storage, enrollment state, session/report store, signatures, four-document exports, cleanup, and retained counter across two distinct runs, while the existing adversarial tests close mutation, ordering, crash-recovery, replay, and uncertain-commit boundaries; all three fixed roles remain `inconclusive` |
| 2D.3 | Join XCTest, built-product inventory, and Host verification in CI | `done` | DemoLab CI selects an available iPhone Simulator, runs all 45 Swift tests, builds Debug/Release dual-slice products, verifies all three roles and all 12 role/configuration/slice intervals, and runs the 26-test closed Host chain; matching Host and runtime regressions keep Xcode 26 chained starts bounded by the file-backed segment prefix without confusing trailing zero-fill VM pages for serialized fixup pages |
| 2D.4 | Run complete local gates and Codex CR | `done` | Debug/Release dual-slice builds, 45 Simulator tests, all 12 product intervals, 5 CLI unit + 17 CLI integration + 171 Core + 1 product fixture + 9 Schema tests, formatting, Clippy, YAML/diff checks, bilingual docs, and final Codex CR pass with no remaining actionable P1/P2 |

## Active 2E completion plan

2E closes checkpoint 2 as one reviewed unit. It does not authorize or perform
a signed archive, TestFlight upload, app installation, or physical-device
observation.

| Order | Work item | Status | Exit gate |
|---:|---|---|---|
| 2E.1 | Close production authorization verification | `done` | The app reads one compile-time pinned 32-byte Ed25519 authorization public key, rejects noncanonical/unknown/mismatched enrollment and run envelopes, verifies the exact domain-separated signature, and derives only closed metadata; four focused Simulator tests and the Debug dual-architecture build pass |
| 2E.2 | Expose the fixed device workflow | `done` | One linear SwiftUI flow imports the signed JSON, selects enrollment or run from verified metadata, displays and durably recovers the complete device-selection fingerprint with its receipt, invokes the fixed app/framework/share roles, exports only through the system share sheet, recovers interrupted authorization publication, exposes a discard path for enrollment and run key/binding/counter prerequisite mismatches, and requires explicit receipt confirmation before fixed-report cleanup |
| 2E.3 | Bind signed-archive capabilities and update runbooks | `done` | The archive lane now requires validated local App Group and pinned-public-key inputs, injects both into the generated signed build, and the exact operator flow is documented in English and Chinese |
| 2E.4 | Repeat local gates and Codex CR | `done` | All 65 Simulator tests, including terminal relaunch, temporary-session publication, strict/skew-window recovery, persisted-enrollment proof, target-manifest, experiment, enrollment-binding, and weak-key regressions, pass; Debug/Release dual-slice builds, all 12 product intervals, the complete Rust/schema suite, formatting, Clippy, Ruby syntax, diff checks, and the Fastlane unsigned fixture lane pass; the final pre-push Codex CR found no actionable P1/P2 |
| 2E.5 | Push, repeat remote CI/review, and merge | `active` | Push only the reviewed commit over SSH, require all checks and review threads to be clean, run the pre-merge Codex CR, squash-merge PR #59, and fast-forward local `main`; Issue #55 remains open for checkpoints 3–5 |
