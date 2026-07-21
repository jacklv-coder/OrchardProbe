# Bounded IPA preflight

The `orchardprobe_core::ipa` module performs the first implemented stage behind
the planned one-command workflow: a deterministic, read-only inventory of one
untrusted IPA archive.

> [!IMPORTANT]
> This is a library foundation, not a user-facing decrypt feature. No current
> CLI command accepts an IPA. The module does not connect to a device,
> decompress or extract entries, parse app identity, inspect embedded Mach-O
> payloads, decrypt code, reconstruct files, or create an output IPA.

## API contract

```rust
inspect_ipa(reader, archive_size) -> Result<IpaInventory, IpaInspectError>
```

The caller supplies an existing `Read + Seek` object and the byte length
observed from the same secured regular-file handle. `inspect_ipa` seeks to the
actual end and rejects any mismatch before interpreting ZIP metadata. A future
CLI must reuse the race-resistant regular-file opening pattern already used by
`oprobe inspect`; a pathname check by itself is not sufficient.

On success, `IpaInventory` contains only:

- the source archive byte length;
- one canonical immediate `Payload/*.app` root;
- deterministic entry, file, and directory counts;
- checked compressed and uncompressed totals; and
- stable path, kind, declared sizes, and CRC32 metadata for each entry.

Entries are sorted by canonical path. CRC32 is ZIP metadata and is not a
cryptographic integrity or plaintext claim.

## Validation order

The implementation fails closed in two bounded passes:

1. Read the bounded ZIP footer region and, when present, the ZIP64 footer.
2. Reject multi-disk archives and validate the central-directory range, byte
   size, and entry count before allocating the entry inventory.
3. Walk every central record with checked arithmetic; require unambiguous UTF-8
   `/`-separated paths and reject duplicate or ASCII case-colliding targets.
4. Require exactly one immediate `Payload/*.app` root and reject entries outside
   that root, except the optional `Payload/` directory ancestor.
5. Ask the pinned ZIP parser for raw entry metadata without decompression.
6. Reject encrypted entries, symbolic links, special files, inconsistent
   directory metadata, unsafe declared sizes, and excessive compression ratios.
7. Validate each local-header range, reject overlaps, and compare its name,
   flags, compression method, and applicable CRC/size fields with the central
   record.
8. Return the inventory only after every entry succeeds.

The parser necessarily reads raw archive byte ranges to find ZIP footers and
local headers. It never requests decompression, reads an entry as uncompressed
content, materializes an archive path, or returns payload bytes.

## Fixed limits

| Limit | Value |
|---|---:|
| IPA bytes | 16 GiB |
| Central-directory bytes | 64 MiB |
| Entries | 16,384 |
| Canonical path bytes | 1,024 |
| Path depth | 32 components |
| Component bytes | 255 |
| One declared uncompressed entry | 8 GiB |
| Aggregate declared uncompressed bytes | 32 GiB |
| Declared uncompressed/compressed ratio | 1,000:1 |

These are compile-time safety limits, not compatibility claims. The command
must not silently relax them. A future reviewed policy may lower a limit or
introduce an explicit bounded profile, but real-world pressure alone is not a
reason to retry with broader authority.

## ZIP dependency boundary

The workspace pins `zip` exactly to `5.1.1` with default features disabled.
At the 2026-07-22 decision point, that release declared Rust 1.83 compatibility,
while OrchardProbe pinned Rust 1.85; the then-current `zip` 8.6.0 release
required Rust 1.88. Disabling defaults keeps archive decryption and all
decompression backends out of this metadata-only stage. The crate's MIT license
is compatible with this Apache-2.0 project.

The project still performs its own pre-allocation footer/count checks, raw-name
policy, duplicate/collision checks, local/central consistency checks, overlap
checks, and resource accounting. A third-party parser result is evidence to
validate, not permission to create files.

## Test scope

All tests generate synthetic archives in memory. They cover the valid stable
inventory and adversarial size mismatch, malformed footer, unsafe path,
encoding, collision, app-root, encryption, special-file, overlap, header
disagreement, and numeric-limit paths. No test contains or processes a
third-party IPA.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa::tests --locked
```

The next safe implementation step is bounded plist and executable inventory
over individually streamed entries. It must be designed separately; this
preflight does not make extraction or payload parsing safe by implication.
