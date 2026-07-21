# Versioned JSON contracts

OrchardProbe keeps its machine-readable, pre-v1 contracts in
[`schemas/v0`](../../schemas/v0). They use
[JSON Schema draft 2020-12](https://json-schema.org/draft/2020-12) and stable
`$id` values rooted at this repository. The checked-in schemas are the source
of truth for wire field names, enum spellings, and structural limits.

These files describe data shapes. They do not implement a device backend,
authorize access to an app, or establish compatibility with an iOS device.
Every example uses project-owned DemoLab or a synthetic `not_implemented`
backend and contains no device identifier, pairing material, credential,
address, process identifier, or third-party app data.

## Contract map and versions

| Contract | Schema | Wire version | Purpose |
| --- | --- | ---: | --- |
| Capability report | [`capability-v1.schema.json`](../../schemas/v0/capability-v1.schema.json) | `schema_version: 1` | Bounded negotiation facts and explicit handling of disabled optional capabilities |
| Error envelope | [`error-v1.schema.json`](../../schemas/v0/error-v1.schema.json) | `schema_version: 1` | Stable category/code plus typed, sanitized context |
| Export manifest | [`export-manifest-v2.schema.json`](../../schemas/v0/export-manifest-v2.schema.json) | `schema_version: 2` | Per-binary evidence, exact collected ranges, outcomes, and orthogonal signature observations |

The directory name `v0` is a lifecycle marker: none of these contracts is a
stable v1 API. Each schema accepts exactly its listed integer wire version.
The manifest moved to version 2 while still under `v0` because adding the
required evidence fields was intentionally breaking. A future incompatible
change increments that contract's integer and requires explicit parser support;
consumers must reject an unrecognized value. No compatibility promise extends
across pre-v1 breaking revisions.

Wire schema filenames and `$id` values are revision-bound and immutable. A future
wire revision adds a new versioned file and `$id`; it never replaces the
contents behind an existing identifier.

The capability protocol separately uses `{ "major": 0, "minor": N }`.
Consumers reject a different protocol major. A newer minor may name an optional
capability that an older consumer does not understand; it is recorded in
`disabled_capabilities` with `reason: "unknown_optional"` and must not be
executed. Unknown required behavior is never enabled: it fails closed with a
`required_capability_missing` error carrying only the bounded public capability
ID.

## Closed and bounded by default

Every object has `additionalProperties: false`. Arrays and strings have schema
limits, enum fields are closed, JSON integers that may represent file sizes or
offsets do not exceed `9,007,199,254,740,991`, and a requested code range is at
most 256 MiB. The principal collection limits are:

| Surface | Limit |
| --- | ---: |
| Enabled or disabled capability records | 16 each |
| Error context entries | 8 |
| Manifest binaries | 256 |
| Ranges per binary | 256 |
| Ranges across a manifest | 8,192 at runtime |
| Reason codes or notes per binary | 16 each |
| Manifest warnings | 32 |
| Relative path length | 1,024 JSON characters and 1,024 UTF-8 bytes at runtime |
| Capability or error input before negotiation | 64 KiB encoded JSON at runtime |
| Manifest input size | 1 MiB before parsing |

JSON Schema `maxLength` counts characters, not encoded bytes. Implementations
must apply the stated UTF-8 and raw-message byte limits before allocating or
parsing. They must also cap nesting and reject duplicate map keys even where a
JSON library would otherwise keep the last value.

The 64 KiB capability/error ceiling is a compile-time pre-negotiation limit;
it does not depend on a peer-provided `max_frame_bytes`. No live protocol parser
exists yet. A future parser must enforce this byte ceiling before allocation or
JSON decoding, then apply the lower of its local limits and any safely
negotiated limit.

Some relationships cannot be expressed portably in draft 2020-12 and remain
mandatory runtime validation:

- enabled and disabled capabilities are unique by `id`, not merely by complete
  JSON object; the two sets are disjoint; negotiated limits do not exceed local
  ceilings; known disabled IDs use revision 1 and never `unknown_optional`,
  unknown disabled IDs use only `unknown_optional`; and chunk, entry, range,
  frame, and total-byte limits stay within independent hard bounds;
- within a stream capability, entry chunk size does not exceed entry size,
  per-binary range count does not exceed total range count, and range chunk
  size does not exceed range size or total byte size;
- each error code maps to exactly one category and disposition, operation/state
  pairs match the protocol phase (except `invalid_state`, which reports the
  rejected pair), and selected codes require their corresponding typed context;
  protocol minor bounds are ordered and `limit_exceeded` records an observed
  value greater than the allowed value;
- binary paths are unique, remain beneath the selected bundle root after safe
  descriptor-based resolution, and contain no empty, dot, backslash, drive, or
  control-character component; depth is at most 32 and each component is at
  most 255 characters and 255 UTF-8 bytes;
- manifest range counts total at most 8,192 and each range satisfies
  `written_size <= accepted_size <= requested_size` using checked arithmetic;
  `file_offset + requested_size` must not overflow or exceed the selected
  slice or file;
- a nonzero accepted or written size has its corresponding SHA-256, a zero
  size has no hash, and `range_hash` or stronger evidence has complete accepted
  and written hashes for every range;
- for `range_hash` or stronger evidence, every range is complete
  (`requested_size == accepted_size == written_size`) and accepted/written
  hashes match; the future byte producer/evaluator, rather than the structural
  manifest validator, must make whole-binary sizes and hashes agree with the
  bytes actually written;
- a slice architecture matches its parent binary, slice extents are contained,
  and signed `cpu_type`/`cpu_subtype` values are interpreted as Mach-O header
  fields rather than device identity;
- `known_plaintext` means an independent first-party oracle was evaluated;
  `pass` requires matching output and oracle SHA-256 values and complete range
  evidence; and
- reason codes include exactly the evidence reason that matches the declared
  level, do not contradict oracle/outcome/signature state, give every `fail`
  result a stable cause, and use `binary.skipped` exactly for skipped results;
- signature presence, kind, and validation satisfy the same consistency rules
  enforced by the Rust `ExportManifest` validator.

Runtime validation is part of accepting a contract. Passing JSON Schema alone
is never sufficient for a security or plaintext claim.

Manifest producers must generate `notes` and `warnings` only from static or
explicitly sanitized templates. They must never copy peer/device input, raw log
or shell output, credentials, tokens, identifiers, addresses, or absolute paths
into those free-text fields; stable `reason_codes` are preferred whenever one
applies. The bounded validator cannot detect secrets embedded in otherwise
valid text.

## Capability report

`capabilities` contains only enabled, typed public IDs. Each known ID has a
closed object shape and revision-specific limits. `disabled_capabilities`
contains only an ID, revision, and a bounded reason code; it cannot smuggle a
fallback command, log, path, address, or credential. A backend ID is a public
implementation label, not a stable device identifier and not a support claim.

The current public IDs are:

- `transport.framed_json`
- `target.catalog`
- `bundle.enumerate`
- `bundle.entry_stream`
- `binary.code_range_stream`
- `session.cancel`

Disabled reasons are also closed: `backend_not_implemented` and
`not_exercised` distinguish absent implementation from an untested path;
`policy_blocked`, `limit_out_of_bounds`, and `version_unsupported` explain why
a known capability was withheld; `unknown_optional` is reserved for a bounded
future ID the current consumer does not understand.

The valid golden report intentionally uses `backend_id: "not_implemented"`
and offers no capabilities. It lists all six current IDs as disabled with
`backend_not_implemented`. It proves serialization and schema behavior only;
it does not prove that framing, cancellation, transport, or a device helper
exists.

## Error envelope

Errors use a stable `category` and `code`, explicit `terminal` and `retryable`
flags, and closed `operation` and `state` values. `context` is an array of typed
records for versions, capabilities, limits, safe relative paths, bounded file
ranges, or evidence state. There is deliberately no arbitrary message, raw log,
stack trace, shell output, absolute path, PID, memory address, or extensible
key/value object.

Schema versions in `version` context are contract-specific: capability and
error schemas support version 1, while the export manifest supports version 2.
Protocol major/minor mismatches use the separate `protocol_version` context.

## Export evidence manifest

The manifest records each Mach-O binary independently. `role`, optional slice
identity, optional input/output sizes and hashes, evidence level, oracle state,
exact ranges, reason codes, and signature observations remain separate fields.
`file_offset` in a range is an absolute file offset from the beginning of the
selected Mach-O binary. When a universal-binary slice is recorded, the range
must also fall within that slice's `[file_offset, file_offset + file_size)`
extent; it is not rebased to the slice. It is never a VM address and cannot
request an arbitrary memory read.

Evidence wire values match Rust exactly:

- outcomes: `pass`, `fail`, `inconclusive`, `skipped`;
- levels: `metadata`, `structure`, `range_hash`, `known_plaintext`;
- signature presence: `absent`, `present`, `unknown`;
- signature kind: `cms`, `ad_hoc`, `unknown`, `not_applicable`; and
- signature validation: `valid`, `invalid`, `not_checked`, `not_applicable`.

`cryptid == 0`, a missing encryption load command, successful structural
parsing, archive creation, or helper/host hash agreement does not prove
plaintext. Range hashes prove transfer integrity only. The strongest result
without an independently built, first-party known-plaintext oracle is
`inconclusive`. A retained CMS or ad-hoc signature may be invalid after bytes
change, so presence never implies validity. The manifest is an evidence report,
not an authorization token, file-open instruction, installability claim, or
source of paths to follow.

The current `oprobe verify --json` command validates manifest structure and
declared relationships only. Its output remains `evidence_evaluated: false` and
`plaintext_proven: false`; it does not reopen referenced artifacts or compare
real bytes. Likewise, the error envelope is a checked-in future wire contract,
not the format of today's CLI standard error.

## Golden and negative fixtures

Direct valid instances live in [`examples/valid`](../../schemas/v0/examples/valid).
Each deliberately invalid instance in
[`examples/invalid`](../../schemas/v0/examples/invalid) has a sibling
`*.invalid.expected.json` file. Expectation metadata is validated against
[`fixture-expectation.schema.json`](../../schemas/fixture-expectation.schema.json)
and contains:

- the contract and relative schema path;
- the relative invalid-instance path;
- `expected_valid: false`;
- one or more accepted JSON Schema failure keywords;
- an RFC 6901 instance pointer; and
- a stable reason code plus a short explanation.

Schema and instance paths are resolved relative to the expectation file.
Validators differ in whether a nested failure is surfaced as its leaf keyword
or as an enclosing `oneOf`, so `accepted_keywords` can list both without making
the test dependent on one validator's prose. A test passes only when the raw
instance fails the named contract for an accepted keyword at the named pointer
or below it. Composite `oneOf` errors are recursively inspected for those
structured child failures. The expectation file itself must validate before
its invalid instance is evaluated.

At minimum, repository checks parse every JSON file, validate the three golden
instances, validate every expectation record, prove every negative instance is
rejected for its declared reason, and round-trip the golden wire values through
the Rust types. `cargo test --workspace --locked` is the canonical local entry
point for those checks.
