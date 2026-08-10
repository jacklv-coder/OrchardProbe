# LAB-004 fresh protected-oracle ceremony

[简体中文](../zh-CN/lab-004-protected-oracle-ceremony.md)

Tracking Issue: [#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

Status: **checkpoint 2 device-free implementation proposed; external actions closed**

LAB-004 is a new first-party experiment for DemoLab `1.0 (4)`. It asks whether
the existing fixed-range self-observer can close the protected-oracle evidence
chain when every external input and diagnostic uses the LAB-003 role boundary.
It does not retry, consume, repair, or reinterpret the closed DemoLab `1.0 (3)`
LAB-002 ceremony or its retained private evidence.

Merging this activation authorizes only the design and the next device-free
integration checkpoint. It does not authorize signing, App Store Connect or
TestFlight access, upload, installation, launch, authorization-envelope
creation or consumption, device queries, device observation, backend work, or
IPA decryption.

## Research question

For exactly one fresh, project-owned DemoLab `1.0 (4)` build and one later
selected owned iPhone, can every frozen slice of the main app, DemoFramework,
and DemoShareExtension independently establish all of the following?

1. the installed executable belongs to the exact frozen build lineage;
2. its predeclared `__TEXT,__oprobe` range is initially protected on disk; and
3. the same mapped range is plaintext and matches the oracle frozen before the
   one permitted internal-TestFlight upload.

Two cleared runs must produce identical normalized evidence while binding the
same physical device, installation, hardware model, and exact iOS
version/build. Any missing, extra, changed, unobservable, expired, replayed, or
partially verified item is a No-Go; inventory and ranges are never adjusted
after observation.

## Fixed scope and non-goals

- Only repository-owned DemoLab marketing version `1.0`, fresh build `4`, and
  an owned explicitly authorized iPhone are in scope.
- The complete inventory is the main app, DemoFramework, and
  DemoShareExtension plus every device slice frozen before signing.
- Exactly one later internal-TestFlight upload may be proposed. External
  testers, public links, Beta App Review, and App Store submission are out of
  scope.
- No third-party app, user IPA, executable bytes, stable device identifier,
  credential, Receipt/Export content, private path, or raw private log may be
  committed, uploaded to GitHub, or sent to CI.
- A Go is only protected-oracle evidence for the exact first-party tuple. It
  is not a backend, extraction or decryption capability, user workflow,
  compatibility claim, or permission to begin `DEVICE-001` without its own
  activation PR.

## Closed artifact roles

Every future Host operation must use one new owner-only LAB-003 private root:

```text
private-root/
├── experiments/<opaque-id>/  immutable controls and allow-listed phases
├── external-inputs/          exactly the current operator Receipt or Export
└── diagnostics/              bounded operator-visible diagnostics only
```

Before authorization creation or consumption, and again at closure, Host must
perform the complete LAB-003 containment, type, ownership, mode, size,
inventory, non-aliasing, and stable-identity checks. An external input is
opened through `external-inputs`; a diagnostic is created through
`diagnostics`; neither may appear inside the experiment child or become a
protocol input by redirection. Failure retains only bounded owner-private
evidence and never broadens or retries the action.

## Ordered checkpoints

| Order | Checkpoint | Status after activation merges | Gate |
|---:|---|---|---|
| 1 | Activation and successor design | `done after PR #90 merges` | Issue #89, [PR #90](https://github.com/jacklv-coder/OrchardProbe/pull/90), this bilingual contract, and the ledger insertion are on `main` |
| 2 | Device-free role integration and synthetic regressions | `done after this implementation PR merges` | The [checkpoint-2 ledger](lab-004-device-free-integration.md) requires LAB-003 prepare/preflight/closure around the existing guarded Host flow while every external and device lane remains closed |
| 3 | Exact signed `1.0 (4)` candidate and frozen oracle | `next proposal — not authorized` | A separate reviewed checkpoint and fresh explicit authorization are required; no upload or device action |
| 4 | One internal upload and installation enrollment | `planned` | The exact checkpoint-3 tuple must be merged and independently revalidated; upload, installation, and enrollment each require their stated fresh authorization |
| 5 | Two clean observations | `planned` | Enrollment must close with exact installed lineage; each distinct run requires a fresh envelope and immediately preceding explicit authorization |
| 6 | Sanitized Go/No-Go result | `planned` | Publish only non-secret evidence, update bilingual technical/user status, and close Issue #89 |

Only one checkpoint may be active. A later checkpoint cannot begin until the
previous completion PR is merged into `main`. A failed or indeterminate
external action is retained and reconciled; it is not silently repeated.

## Evidence and decision gate

A Go requires exact equality across the frozen build/oracle, installed
role/slice inventory, authorized identity bindings, mapped coordinates, and
both clean reports. Initial protection requires the installed encryption range
to cover the fixed section and its on-disk digest to differ from the frozen
plaintext digest; `cryptid == 1` alone is insufficient. Plaintext requires the
same mapped range digest to equal the independently frozen digest. All three
roles and all frozen slices must pass.

A safe No-Go is an accepted result. It keeps `DEVICE-001` blocked and records
which prerequisite could not be independently established. A Go permits only
a separate documentation activation proposal for `DEVICE-001`; it does not
start backend implementation or operate another app.

## Immediate next gate

After the checkpoint-2 implementation PR merges, checkpoint 3 may be proposed
but cannot execute until its separate activation is reviewed and fresh explicit
authorization is obtained. Jack iPhone is not needed and must not be queried or
operated during checkpoint 2. No signing or Apple access is authorized.
