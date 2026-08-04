# LAB-003 device-free implementation result

[简体中文](../zh-CN/lab-003-implementation-result.md)

Tracking Issue: [#84](https://github.com/jacklv-coder/OrchardProbe/issues/84)

Status: **checkpoint 3 active — sanitized closure record**

This record evaluates only the device-free filesystem-role gate defined by the
[LAB-003 layout contract](lab-003-external-artifact-layout.md). It contains no
private path, credential, stable device identifier, Receipt/Export content,
protected binary, or raw diagnostic output.

## Reviewed evidence

- Activation and the bilingual closed-layout contract merged in
  [PR #85](https://github.com/jacklv-coder/OrchardProbe/pull/85).
- The device-free implementation merged in
  [PR #86](https://github.com/jacklv-coder/OrchardProbe/pull/86) as squash
  commit `3994c6a` after all required checks passed: Repository quality, Rust,
  and DemoLab build.
- Two Ruby runtimes each passed all 33 LAB-003 layout tests with no failure,
  error, or skip. The locked Fastlane runtime exposed both new local lanes.
- The final base-relative Codex CR found no definite correctness or security
  defect. Both GitHub review threads were resolved and no unresolved review
  thread remained before merge.
- Review-driven regressions cover nonblocking rejection of special directory
  candidates, retention of a reserved diagnostic through the second identity
  check, exact experiment selection, one-input cardinality, caller-supplied
  owner validation, bounded inventory transport, role replacement, hard-link
  aliasing, and bounded diagnostic process groups.

No evidence above came from Apple, TestFlight, an iPhone, a fresh authorization
envelope, or retained LAB-002 private artifacts. Jack iPhone was not operated
by this checkpoint.

## Ordered closure steps

| Order | Step | Status | Gate |
|---:|---|---|---|
| 3A | Record sanitized implementation evidence | `done` | Only public PR, commit, CI, test, and review facts appear above; no private artifact was opened |
| 3B | Validate the bilingual result locally | `done` | English/Chinese meaning, links, patch formatting, documentation consistency, both Ruby regression runs, and Codex CR passed |
| 3C | Publish and close | `active` | Push over SSH, open the result PR, pass required CI and review, rerun pre-merge Codex CR, merge, then close Issue #84 |

## Decision

| Question | Decision | Meaning |
|---|---|---|
| Are the three filesystem roles and lifecycle inventories implemented and reproducibly tested without a device? | `Go — layout only` | The prepare/preflight boundary is suitable as a prerequisite for a separately reviewed proposal. |
| Did LAB-003 preserve the closed LAB-002 lifecycle boundary? | `Go` | Historical lifecycle lanes remain fail-closed; no envelope or retained evidence was consumed. |
| Does this result authorize a build, upload, installation, launch, envelope, or device action? | `No-Go` | A new proposal and fresh explicit authorization are still required before each external or device action. |
| Does this establish installed lineage, a protected-to-plaintext observation, a device backend, or working IPA decryption? | `No-Go` | None of those product gates was exercised or satisfied. |

The overall LAB-003 result is therefore **complete device-free layout Go,
device-ceremony No-Go**. This wording is intentionally narrower than a product
or compatibility claim.

## Next gate

LAB-003 may close after this record passes local checks, Codex CR, PR review,
required CI, and merge. A later real-device proposal must be a new sequential
checkpoint that names one exact first-party build/device tuple, states why the
protected-oracle prerequisite is satisfied, fixes the allowed external and
device actions, and obtains fresh explicit authorization immediately before
each such action. Until that happens, `DEVICE-001` remains blocked and the
connected phone is not needed.
