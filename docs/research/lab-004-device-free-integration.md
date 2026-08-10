# LAB-004 device-free Host integration

[简体中文](../zh-CN/lab-004-device-free-integration.md)

Tracking Issue: [#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

Status: **checkpoint 2 implementation proposed; device and external lanes closed**

This is the implementation ledger for LAB-004 checkpoint 2. It connects the
existing guarded Host/operator flow to the LAB-003 three-role layout without
creating or consuming an authorization, signing a build, contacting Apple, or
querying a device.

## Fixed operation profiles

The adapter accepts only these seven transitions. The operation name fixes the
pre-state, post-state, and external-input role; callers cannot supply a
lifecycle or input kind independently.

| Operation | Required pre-state | Required post-state | External input |
|---|---|---|---|
| `operator-start-enrollment` | empty `experiments` role | `base` | none |
| `operator-close-enrollment` | `base` | `enrollment-closed` | one bounded Receipt |
| `operator-start-run-1` | `enrollment-closed` | `run-1-control` | none |
| `operator-close-run-1` | `run-1-control` | `run-1-closed` | one bounded Export |
| `operator-start-run-2` | `run-1-closed` | `run-2-control` | none |
| `operator-close-run-2` | `run-2-control` | `complete` | one bounded Export |
| `operator-verify` | `complete` | `complete` | none |

The enrollment publisher now uses the signed random 64-lowercase-hex
`experiment_id` as the experiment child name. Its signed directory binding and
every later Host verification require that same name, parent identity, child
identity, and experiment ID. The historical fixed `lab002-experiment` name is
therefore no longer compatible with the guarded Helper.

## Enforcement chain

Before a callback can reach the guarded Helper, the adapter opens the private
root and all three roles, validates the exact selected lifecycle inventory,
holds every control/phase artifact, opens a Receipt or Export only through the
`external-inputs` descriptor, verifies non-aliasing and stable identity, and
reserves one new diagnostic name. The Helper additionally rejects execution
unless its primary directory descriptor is the held `experiments` role for
enrollment start or the held opaque experiment child for every later action.
Checkpoint 2 admits exactly that one role-owned binding and rejects every extra
descriptor; the three-descriptor Helper launch remains closed until a later
checkpoint reviews where each additional source binding belongs.
Receipt/Export bytes must exactly equal the bytes read from the held external
input descriptor. Successful validation records a one-shot Helper authorization
on the active boundary; transition capture and a success diagnostic both reject
calls that try to bypass that authorization.

Immediately before Helper authorization, Host repeats the exact inventory of
all three roles, reopens the selected lifecycle, and compares every retained
control/phase descendant with its held identity and opening-time SHA-256. A
nonblocking shared read lock is held from digest capture through closure so a
coordinated exclusive writer cannot enter; new transition artifacts join that
locked set before success. The existing exclusive operator-directory lock also
remains held while Host captures the exact post-transition lifecycle after the
Helper returns. Only then can Host publish a success diagnostic: every newly
published experiment, phase directory, and
artifact remains held through closure. Closure reopens the complete post-state
and compares every prior and newly captured descendant by relative role name,
type, device, inode, and file content digest. A same-name replacement,
metadata-preserving in-place rewrite, or uncaptured transition therefore fails
closed.

The Helper records only one fixed success/failure sentence through the held
`diagnostics` descriptor. Preflight reserves both one file slot and enough
aggregate bytes for the larger fixed sentence, so a ready result cannot defer a
known capacity failure until publication. On success, closure reopens and compares the root and
role identities, requires the exact post-state inventory, unchanged external
input identity and bytes, every retained diagnostic's held identity and opening
SHA-256 under a shared lock, the named bounded read-only diagnostic, and
complete non-aliasing. On callback failure it removes the diagnostic published by this
boundary before requiring the original pre-state to remain exact; a partial
lifecycle publication instead becomes a generic fail-closed closure error. Any
final closure failure also removes the exact boundary-owned diagnostic before
returning, scanning the diagnostics role by held device/inode identity so a
same-role rename or hard link cannot evade cleanup. If absence cannot be proved, the operation returns the distinct
terminal `diagnostic_cleanup_indeterminate` state instead of an ordinary
closure failure; the retained private evidence must not be treated as success.
Public results contain role names and operation state only, never a private
root, experiment ID, input name/content, or raw error.

## Ordered checkpoint-2 ledger

| Order | Step | Status when this PR is on `main` | Evidence / next gate |
|---:|---|---|---|
| 2A | Align the Host experiment directory with LAB-003 | `done` | Rust publication and signed binding use the random 64-hex experiment ID; copied, renamed, or fixed-name directories fail |
| 2B | Add held preflight and closure | `done` | Seven fixed profiles validate exact pre/post inventories, role identities, aliasing, and failure closure |
| 2C | Gate Helper input and diagnostics | `done` | Helper primary bindings must match the active boundary; exact roles and held descendants are rechecked before launch; Receipt/Export bytes match held external input; post-transition descendants are captured before a fixed, bounded, exclusive, owner-private diagnostic |
| 2D | Add synthetic regressions and CI | `done` | Ruby transition/adversarial tests, the existing LAB-003 suite, Rust tests, syntax, formatting, and CI wiring cover this device-free boundary |
| 2E | Publish checkpoint-2 completion | `active` | [PR #91](https://github.com/jacklv-coder/OrchardProbe/pull/91) must pass Codex CR, GitHub review, and all required CI before merge |

## Scope result

Checkpoint 2 can establish only that the Host boundary is ready for a later,
separately authorized first-party ceremony. It does not create the DemoLab
`1.0 (4)` candidate, freeze an oracle, upload to TestFlight, install or launch
an app, operate Jack iPhone, observe protected/plaintext bytes, unblock
`DEVICE-001`, or provide IPA decryption.

After this completion PR merges, checkpoint 3 remains a proposal gate. Signing
the exact candidate requires a separate reviewed activation and fresh explicit
authorization; it must not begin merely because the device-free code merged.
