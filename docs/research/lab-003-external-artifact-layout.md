# LAB-003 external artifact layout contract

[简体中文](../zh-CN/lab-003-external-artifact-layout.md)

Tracking Issue: [#84](https://github.com/jacklv-coder/OrchardProbe/issues/84)

Status: **checkpoints 1–2 merged; checkpoint 3 sanitized result active**

LAB-002 ended with a retained procedural No-Go after an operator-supplied
Enrollment Receipt and diagnostic log were placed beside the six canonical
control artifacts. LAB-003 is a separately reviewed successor. It first makes
every filesystem role unambiguous and testable; it does not retry or amend the
closed LAB-002 ceremony.

## Scope and non-goals

This checkpoint may design, implement, and test path-role validation without a
device. It must not read or modify retained LAB-002 evidence, operate a phone,
create or consume an authorization envelope, sign or upload a build, install or
launch an app, or reactivate a closed lifecycle lane. It cannot establish
installed lineage, a protected-to-plaintext transition, a Go result, a device
backend, or working IPA decryption.

## Closed directory roles

One newly created owner-only private root has three non-overlapping children:

```text
private-root/                 mode 0700
├── experiments/             Host-created experiment children
│   └── <opaque-id>/          six base controls, then allow-listed phase dirs
├── external-inputs/         operator-supplied Receipt/Export files only
└── diagnostics/             operator-visible logs only
```

The names express roles, not a reusable private path. Implementations must use
held directory descriptors and must not print the resolved private root.

The three role roots must be distinct directories, direct children of the same
validated private root, and neither descendants nor aliases of one another.
Before an experiment is selected, `experiments/` must be empty; afterward it
must contain exactly the one selected opaque-ID child.
Every path component must be a real directory with the expected owner and
permissions; symlinks are rejected. Each experiment child continues to accept
exactly its six schema-defined base control files before enrollment closure.
After a valid transition, only the existing allow-listed enrollment/run
control or result directories may be appended through the atomic phase
publisher, and every phase has its own exact fixed inventory. No Receipt,
Export, log, temporary file, unknown phase, or other extra entry is permitted
at any lifecycle state.

The `external-inputs/` role may contain at most one bounded, owner-only,
non-symlink regular file, directly inside that role. A diagnostic destination
must be directly inside `diagnostics/`, created without replacement, and must
never be accepted as protocol input. Across all opened role objects, an
implementation must reject equal filesystem identity (device and inode),
including hard-link aliasing where the host filesystem exposes it.

Diagnostics are a closed retained output: at most 16 direct regular files,
each no larger than 1 MiB and no more than 4 MiB in aggregate. Subdirectories,
links, special files, replacement, and further writes after final validation
are rejected. The reviewed wrapper must create the sink, constrain child output
to the same per-file ceiling, enforce a maximum 30-second wall-clock lifetime,
and terminate the complete child process group before final validation;
arbitrary caller redirection is not a trusted diagnostic path.

## Preflight order

The implementation checkpoint must validate the complete layout before a
future authorization can be created or consumed:

1. open and validate the private root and all three fixed role roots;
2. open the selected experiment child and verify the exact inventory for its
   current lifecycle phase: six immutable base controls plus only the phase
   directories already valid at that state, each with its fixed contents;
3. open the external input or reserve the diagnostic output through the
   corresponding role-root descriptor;
4. verify containment, file type, ownership, mode, bounds, non-aliasing, and
   stable identity across a second check;
5. emit only sanitized role-level readiness, then permit the existing protocol
   parser or signer to see the descriptor.

The future close operation must repeat these checks. A separate device-free
prepare/preflight entry point must make the intended import and log locations
visible before an envelope exists. Redirecting a shell log into the experiment
child therefore creates an entry outside every valid phase inventory and fails
preflight before authorization creation.

## Failure, retention, and redaction

Failure is fail-closed and role-specific: for example, `external input is not
inside the external-inputs role` or `experiment phase inventory has an extra
entry`. Normal output must not contain absolute paths, experiment identifiers,
stable device identifiers, fingerprints, Receipt/Export contents, Host results,
or raw private errors.

The tool never moves, deletes, rewrites, or repairs an operator-supplied input.
It may clean only an unpublished temporary file that it created inside the
correct role root. A failure after publication keeps the new checkpoint's
owner-only evidence for explicit reconciliation. Retained LAB-002 files remain
outside this checkpoint and are never used to turn its No-Go into a pass.

## Ordered checkpoints

| Order | Checkpoint | Status | Gate |
|---:|---|---|---|
| 1 | Activation and closed layout design | `done` | Issue #84, [PR #85](https://github.com/jacklv-coder/OrchardProbe/pull/85), this bilingual contract, and the execution-ledger insertion are on `main` |
| 2 | Device-free implementation and regressions | `done` | [PR #86](https://github.com/jacklv-coder/OrchardProbe/pull/86) passed local gates, Codex CR, PR review, and CI for the path-role API, prepare/preflight UX, lifecycle revalidation, and synthetic tests while closed LAB-002 lanes remained guarded |
| 3 | Sanitized implementation result and later-ceremony proposal | `active` | The [sanitized result](lab-003-implementation-result.md) records a layout-only Go and device-ceremony No-Go. Merge of its result PR may close LAB-003; it does not authorize a build, upload, installation, envelope, or device action |

Checkpoint 2 began only after activation PR #85 merged, and checkpoint 3 began
only after PR #86 merged. Any later real-device ceremony requires a new
reviewed checkpoint and fresh explicit authorization immediately before each
external or device action.

## Acceptance tests for checkpoint 2

Synthetic tests must cover the valid three-root layout plus wrong-role nesting,
ancestor/descendant overlap, symlink components, regular-file substitution,
unsafe ownership or permissions, extra/missing strict-child entries, changed
identity between checks, and hard-link identity aliasing where supported. They
must also assert bounded input sizes; valid and invalid phase transitions;
exclusive diagnostic creation; diagnostic file, entry-count, aggregate, and
process-output maxima plus maximum-plus-one failures; cleanup ownership; and
the absence of private values from stdout, stderr, and retained sanitized
errors.
