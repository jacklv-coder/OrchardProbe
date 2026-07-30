# LAB-002 closed artifact contracts

Status: **checkpoint 2B branch-local contract**

This document explains the schema bundle at
[`schemas/lab002/lab-002-artifacts-v1.schema.json`](../../schemas/lab002/lab-002-artifacts-v1.schema.json).
It is subordinate to the reviewed
[LAB-002 oracle design](lab-002-oracle-design.md). It adds no device transport,
general target selection, path, process, address, or caller-selected range.

## Inventory

The bundle is self-contained Draft 2020-12 JSON Schema. Each accepted top-level
artifact has a unique fixed `schema` value. All profile-bearing artifacts use
the fixed `orchardprobe.demolab.lab002.observation.v1` profile; the deliberately
minimal run-counter state has no `profile` field.

| Artifact | Fixed `schema` value | Retention |
|---|---|---|
| Private authorized-target manifest | `orchardprobe.lab002.authorized-targets.v1` | One private, pre-build manifest per exact identity set; never packaged into the IPA |
| Authorized-use acknowledgement | `orchardprobe.lab002.authorized-use-ack.v1` | One installation acknowledgement and one per run |
| Installation enrollment core | `orchardprobe.lab002.installation-enrollment-core.v1` | Embedded canonical string in the signed authorization envelope |
| Collection challenge core | `orchardprobe.lab002.collection-challenge-core.v1` | Embedded canonical string in the signed authorization envelope |
| Authorized-operation envelope | `orchardprobe.lab002.authorized-operation-envelope.v1` | One for enrollment and one per run |
| Signed enrollment receipt | `orchardprobe.lab002.device-enrollment-receipt.v1` | One per experiment |
| Device-selection confirmation | `orchardprobe.lab002.device-selection-confirmation.v1` | One per experiment |
| Device-enrollment binding | `orchardprobe.lab002.device-enrollment-binding.v1` | One per experiment |
| Run-counter state | `orchardprobe.lab002.run-counter-state.v1` | One app-group state file, atomically replaced after each accepted run |
| Installation-nonce state | `orchardprobe.lab002.installation-nonce-state.v1` | One device-local app-group state file for the installed build |
| Frozen oracle | `orchardprobe.lab002.oracle.v1` | One externally hashed pre-upload oracle |
| Collection intent | `orchardprobe.lab002.collection-intent.v1` | One per run |
| Signed session export | `orchardprobe.lab002.session-export.v1` | One per run |
| Session report (`session.json`) | `orchardprobe.lab002.session-report.v1` | Exactly one per run inside the signed export |
| Role report | `orchardprobe.lab002.role-report.v1` | Exactly three per run: main app, framework, share extension |
| Collection binding | `orchardprobe.lab002.collection-binding.v1` | One per completed run |

The signed receipt and signed export each embed one exact canonical unsigned
core. Those internal cores are separate `$defs`, not additional retained
files. The authorization envelope likewise embeds the exact canonical
acknowledgement and operation core rather than parsed copies.

## Closed boundaries

- Every object uses `additionalProperties: false`.
- SHA-256, key, nonce, ID, UUID, signature, source-commit, and run-counter
  fields use exact lowercase-hex lengths.
- Policy, profile, technique, retention, role, logical filename, operation,
  action sequence, data category, and run-counter values are closed.
- Installation acknowledgements require the fixed environment and installation
  action sequence. Run acknowledgements require the enrollment binding and
  fixed observation/export/cleanup sequence.
- The oracle role array is exactly main app, framework, share extension. Each
  role has one through four slices in ordinal order, each executable extent is
  capped at 100 MiB, and the build configuration is fixed to `Release`. The
  signed export entry array is exactly session, main app, framework, share
  extension.
- Every observed slice names the fixed `__TEXT` segment and `__oprobe` section.
  A `pass` role has no reasons; `fail` and `inconclusive` roles require at least
  one closed reason code.
- The schema admits only safe-range integers and bounded strings. Runtime byte
  limits remain stricter: 3 KiB acknowledgements/operation cores, 16 KiB
  authorization and host control artifacts, 32 KiB internal reports, and
  512 KiB signed exports.
- Run 1 requires counter `0000000000000001` and a null prior binding. Run 2
  requires counter `0000000000000002` and a non-null prior binding. That
  ordinal/counter relationship is closed in the challenge, intent, unsigned
  export, session report, role report, and collection binding.

JSON Schema establishes shape, closed vocabulary, ordering, and scalar bounds.
Checkpoint 2B.2 must still enforce cross-artifact equality, exact 900-second
windows, canonical-byte equality, digest recomputation, Ed25519 domains and
signatures, freshness, one-time use, and replay/chain rules. Schema success
alone is never authorization, device evidence, or a LAB-002 Go result.
