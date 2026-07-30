# LAB-002 implementation progress ledger

Status: **Checkpoint 2 active on a local implementation branch**

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
| 2C | DemoLab state coordinator and zero-argument observers | `in progress` | Execute the documented 2C.1–2C.5 sequence below; no caller-selected target, range, path, PID, or address |
| 2D | Synthetic and Simulator verification | `planned` | Exercise all three roles, all emitted slices, state transitions, negative fixtures, crash/replay boundaries, and explicit Simulator `inconclusive` semantics |
| 2E | Documentation, final CR, CI, PR, and merge | `planned` | Update bilingual architecture/user runbooks and compatibility template; resolve every P1/P2, pass all required checks, review the PR, then merge |

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
  167 core tests, 1 fixture integration test, 9 schema tests, formatting,
  Clippy with warnings denied, and the base-relative diff check.
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
| 2C.2 | Implement fixed inbox and durable state coordinator | `in progress` | Serialized Import/Start/Discard, no-follow regular-file checks, lock/quarantine identity checks, bounded canonical records, checked counter commit, exclusive atomic writes, and fail-closed residue handling compile for App and Extension |
| 2C.3 | Implement enrollment state and device-only key boundary | `planned` | Installation-only synthetic/Keychain key creation, exact key/nonce/build binding, ThisDeviceOnly/non-synchronizable production attributes, and loss/reset/mismatch rejection; run paths cannot create or repair enrollment |
| 2C.4 | Implement session lifecycle and three zero-argument observers | `planned` | Main App, Framework, and Share Extension observe only their compiled self target/range, publish once in fixed order, bind immutable session facts, and fail closed without public path/target/range/PID/address parameters |
| 2C.5 | Implement signed export, receipt, and cleanup boundaries | `planned` | Fixed four-document export and enrollment receipt are signed and share-sheet-only; cleanup requires a verified completed export and cannot reset fixed state/key; focused gates and Codex CR have no remaining P1/P2 |
