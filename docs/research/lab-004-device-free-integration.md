# LAB-004 device-free Host integration

[简体中文](../zh-CN/lab-004-device-free-integration.md)

Tracking Issue: [#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

Status: **checkpoint 2 complete after PR #91 merges; device and external lanes closed**

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

No production callback can reach the guarded Helper in checkpoint 2. The
adapter opens the private root and all three roles, validates the exact selected lifecycle inventory,
holds every control/phase artifact, opens a Receipt or Export only through the
`external-inputs` descriptor, verifies non-aliasing and stable identity, and
reserves one new diagnostic name. Before its first diagnostics inventory it
also takes the nonblocking exclusive diagnostics-role lock and retains that lock
through validation, publication, cleanup, and descriptor closure. Every
controlled diagnostics writer must follow this lock contract. The production
authorization entry repeats the complete pre-state validation and then returns
the terminal `helper_launch_closed` result for every binding request. The real
Helper requires three directory bindings, while this role boundary can account
for only the primary `experiments` role or opaque experiment child. A later
checkpoint must review the two source bindings and bind every byte the Helper
actually consumes to the accepted snapshot before execution can open.
Receipt/Export bytes are retained through their held external-input descriptor,
but checkpoint 2 does not pass them to a Helper. Synthetic tests set an internal
authorization state only to exercise post-transition capture and closure;
production callers cannot obtain that state from the public authorization API.

Immediately before returning the closed authorization decision, Host repeats the exact inventory of
all three roles, reopens the selected lifecycle, and compares every retained
control/phase descendant with its held identity and opening-time SHA-256. A
nonblocking shared read lock is held from digest capture through closure so a
coordinated exclusive writer cannot enter; new transition artifacts join that
locked set before success. The existing exclusive operator-directory lock also
remains held while synthetic tests capture the exact post-transition lifecycle
after their callback returns. Only then can the synthetic closure path publish a
success diagnostic: every newly
published experiment, phase directory, and
artifact remains held through closure. Closure reopens the complete post-state
and compares every prior and newly captured descendant by relative role name,
type, device, inode, and file content digest. A same-name replacement,
metadata-preserving in-place rewrite, or uncaptured transition therefore fails
closed.

The boundary diagnostic API records only one fixed success/failure sentence
through the held `diagnostics` descriptor. Preflight reserves both one file slot and enough
aggregate bytes for the larger fixed sentence, so a ready result cannot defer a
known capacity failure until publication. A normally returning operation must
carry the `helper-success` status; a durable `helper-failure` sentence can never
close as success. On success, closure reopens and compares the root and
role identities, requires the exact post-state inventory, unchanged external
input identity and bytes, every retained diagnostic's held identity and opening
SHA-256 under a shared lock, and the newly published named bounded read-only
diagnostic with its single-link state rechecked after the final read. The new
single-link rule applies only to the boundary-owned result; it does not
reclassify previously retained operator evidence. After validation, the Host
deletes the boundary-owned diagnostic, syncs the role directory, requires the
held inode to have zero remaining links, and revalidates the original diagnostic
inventory before it can return `closed`. The sanitized return status is the only
success indication; the fixed diagnostic sentence is intentionally transient.
Closure also requires complete non-aliasing. On callback failure it removes the
diagnostic published by this boundary before requiring the original pre-state to
remain exact; a partial
lifecycle publication instead becomes a generic fail-closed closure error. Any
final closure failure also removes the exact boundary-owned diagnostic before
returning, scanning the diagnostics role by held device/inode identity so a
same-role rename or hard link cannot evade cleanup, then performs a checked
directory sync and requires the held inode to have no links left. An out-of-role
rename or hard link is therefore indeterminate rather than successful cleanup.
If absence or deletion durability cannot be proved, the
operation returns the distinct terminal `diagnostic_cleanup_indeterminate`
state instead of an ordinary closure failure; the retained private evidence
must not be treated as success.
The sink identity is retained before any fallible post-create write or
validation, so the same cleanup proof also covers publication rollback.
Public results contain role names and operation state only, never a private
root, experiment ID, input name/content, or raw error.

## Ordered checkpoint-2 ledger

| Order | Step | Status when this PR is on `main` | Evidence / next gate |
|---:|---|---|---|
| 2A | Align the Host experiment directory with LAB-003 | `done` | Rust publication and signed binding use the random 64-hex experiment ID; copied, renamed, or fixed-name directories fail |
| 2B | Add held preflight and closure | `done` | Seven fixed profiles validate exact pre/post inventories, role identities, aliasing, and failure closure |
| 2C | Keep Helper launch closed and test diagnostics | `done` | The production authorization API rechecks exact roles and held descendants, then returns `helper_launch_closed`; synthetic transitions exercise post-state capture and fixed, bounded, exclusive, owner-private diagnostic cleanup without claiming that a Helper ran |
| 2D | Add synthetic regressions and CI | `done` | Ruby transition/adversarial tests, the existing LAB-003 suite, Rust tests, syntax, formatting, and CI wiring cover this device-free boundary |
| 2E | Publish checkpoint-2 completion | `done after PR #91 merges` | [PR #91](https://github.com/jacklv-coder/OrchardProbe/pull/91) must pass Codex CR, GitHub review, and all required CI before merge |

## Scope result

Checkpoint 2 can establish only that the Host boundary is ready for a later,
separately authorized first-party ceremony. It does not create the DemoLab
`1.0 (4)` candidate, freeze an oracle, upload to TestFlight, install or launch
an app, operate Jack iPhone, observe protected/plaintext bytes, unblock
`DEVICE-001`, or provide IPA decryption.

After this completion PR merges, checkpoint 3 remains a proposal gate. Signing
the exact candidate requires a separate reviewed activation and fresh explicit
authorization; it must not begin merely because the device-free code merged.
