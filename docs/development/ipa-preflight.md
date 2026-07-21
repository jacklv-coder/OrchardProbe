# Bounded IPA preflight and entry read

The `orchardprobe_core::ipa` module performs the first implemented stages behind
the planned one-command workflow: a deterministic, read-only inventory of one
untrusted IPA archive plus opt-in bounded memory and streaming reads of one
validated entry.

> [!IMPORTANT]
> This is a library foundation, not a user-facing decrypt feature. No current
> CLI command accepts an IPA. The module does not connect to a device, choose
> host output paths, inspect embedded Mach-O payloads, decrypt code, reconstruct
> files, or create an output IPA. A single-entry API can either return one
> bounded in-memory buffer or copy one explicitly selected entry to a
> caller-owned sink after the full archive preflight succeeds.

## API contract

```rust
inspect_ipa(reader, archive_size) -> Result<IpaInventory, IpaInspectError>

read_ipa_entry_bounded(reader, archive_size, path, max_output_bytes)
    -> Result<Vec<u8>, IpaEntryReadError>

copy_ipa_entry_bounded(reader, archive_size, path, max_output_bytes, writer)
    -> Result<IpaEntryCopy, IpaEntryReadError>
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

`read_ipa_entry_bounded` independently repeats that complete preflight on the
same reader and declared size. It then requires an exact canonical regular-file
path from the validated inventory, reopens the archive at known offset zero,
and binds the selected ZIP metadata back to the inventory before reading. It
supports only Stored and Deflate, returns bytes in memory, and never interprets
the entry path as a host filesystem path.

A caller chooses an output limit from 1 byte through 16 MiB. The selected entry
must also declare at most 64 MiB of compressed input. A declared output above
the caller limit is rejected before decompression; a stream that produces more
than its declaration or caller limit is rejected after reading at most one
extra byte. A successful read reaches EOF so the ZIP implementation checks
CRC32, then OrchardProbe separately compares actual and declared lengths.
These checks detect corruption and inconsistent archive metadata; CRC32 still
does not prove origin, authorization, cryptographic authenticity, or decrypted
plaintext correctness.

`copy_ipa_entry_bounded` applies the same selector, full-preflight,
Stored/Deflate, reopened-metadata, EOF/CRC, actual-length, and overflow checks
while using a fixed 64 KiB transfer buffer. It allows a caller-selected limit
up to 512 MiB for both compressed input and uncompressed output and returns the
complete inventory only after a post-read preflight matches the pre-read
inventory. The archive module never turns the entry name into a host path. The
caller owns the sink: after any error, it must discard or truncate partial
bytes, and after success it decides when to flush or publish them.

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

The preflight parser necessarily reads raw archive byte ranges to find ZIP
footers and local headers. It never requests decompression or returns payload
bytes. Only the separate bounded entry APIs request decompression. The archive
module never materializes an archive path; the streaming caller alone chooses
whether its sink has filesystem effects.

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
| One in-memory entry output | 16 MiB |
| One in-memory entry compressed input | 64 MiB |
| One streaming entry output | 512 MiB |
| One streaming entry compressed input | 512 MiB |
| Streaming transfer buffer | 64 KiB |

These are compile-time safety limits, not compatibility claims. The command
must not silently relax them. A future reviewed policy may lower a limit or
introduce an explicit bounded profile, but real-world pressure alone is not a
reason to retry with broader authority.

## ZIP dependency boundary

The workspace pins `zip` exactly to `5.1.1` with default features disabled and
enables only its `deflate-flate2-zlib-rs` feature for Stored/Deflate entry reads.
At the 2026-07-22 decision point, that release declared Rust 1.83 compatibility,
while OrchardProbe pinned Rust 1.85; the then-current `zip` 8.6.0 release
required Rust 1.88. Disabling defaults keeps archive decryption and unrelated
compression backends out of the dependency graph. The preflight path itself
remains metadata-only. The crate's MIT license is compatible with this
Apache-2.0 project.

The project still performs its own pre-allocation footer/count checks, raw-name
policy, duplicate/collision checks, local/central consistency checks, overlap
checks, and resource accounting. A third-party parser result is evidence to
validate, not permission to create files.

## Test scope

All tests generate synthetic archives in memory. Preflight tests cover the
valid stable inventory and adversarial size mismatch, malformed footer, unsafe
path, encoding, collision, app-root, encryption, special-file, overlap, header
disagreement, and numeric-limit paths. Entry-read tests cover Stored and
Deflate success, deterministic input preservation, selectors, both resource
limits, unsupported compression, CRC corruption, observed output overflow,
declared/actual length disagreement, reopened metadata drift, and preflight
error propagation including special files. Streaming-copy tests add Stored and
Deflate success, fixed limits, sink errors, CRC failure, and unsupported
compression. No test contains or processes a third-party IPA.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa::tests --locked
```

Bounded root [`Info.plist` metadata parsing](ipa-info-plist.md) is now implemented
as a separate layer over this primitive. Preflight and bounded byte reads do not
make plist parsing, full extraction, or Mach-O payload interpretation safe by
implication; each later layer retains its own limits and typed failures. The
[root main-executable inspection layer](ipa-main-executable.md) uses the
streaming API with an automatically cleaned anonymous temporary file before
applying the separate Mach-O parser.
