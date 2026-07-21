# Bounded IPA nested-bundle metadata

The `orchardprobe_core::ipa_bundle` module is the metadata-only layer between
the root app parser and the declared-standard-bundle code inventory. It
discovers conventional nested framework and extension bundle roots, reads each
exact direct `Info.plist` through the existing bounded IPA entry API, and
resolves the declared executable to an exact regular entry.

> [!IMPORTANT]
> This is a device-free, library-only metadata layer. It does not read nested
> executable payload bytes, classify those entries as Mach-O, connect to a
> device, match an installed build, decrypt or rewrite code, prove plaintext,
> materialize an archive, package an IPA, or add a CLI command.

## API and result

```rust
inspect_ipa_nested_bundle_metadata(reader, archive_size)
    -> Result<IpaNestedBundleMetadata, IpaNestedBundleMetadataError>
```

The caller supplies the same secured `Read + Seek` regular-file handle and
observed size used by the lower IPA APIs. Success returns the already validated
root `IpaAppMetadata` plus a canonical-path-sorted list of nested bundles.

Each `IpaNestedBundle` records:

- a `framework` or `extension` metadata role;
- the canonical bundle root and exact direct `Info.plist` path;
- the validated plist entry sizes and CRC;
- `CFBundleIdentifier`, `CFBundleVersion`, and optional
  `CFBundleShortVersionString`;
- the safe single-component `CFBundleExecutable` value; and
- the exact declared executable path and its validated regular-entry metadata.

The entry metadata binds the result to the complete inventory observation. It
does not prove that the executable bytes are Mach-O, encrypted, decrypted,
correct, signed, or associated with an installed build.

## Discovery boundary

Discovery operates only on the canonical strings returned by IPA preflight. It
does not create host paths and does not require explicit ZIP directory entries.

The current closed scope is:

1. A framework root is a non-empty `*.framework` path component represented by
   a directory entry or a descendant. It may occur beneath the root app outside
   nested app/framework ancestry, or inside one in-scope extension.
2. An extension root is an exact direct `<app-root>/PlugIns/*.appex` component
   represented by a directory entry or a descendant.
3. A framework beneath that direct extension remains in scope.
4. A nested `*.app`, a framework nested inside another framework, an extension
   outside direct `PlugIns`, a bundle-looking regular file with no descendants,
   Watch content, and App Clip content are outside this stage and are ignored.
5. All suffix and path comparisons are case-sensitive. Lower preflight already
   rejects ASCII case collisions, duplicate paths, unsafe components, and
   special files.

For every discovered root, the exact direct `<bundle-root>/Info.plist` is
mandatory. Alternate locations such as `Resources/Info.plist`, basename
fallback, case fallback, and executable-name guessing are forbidden.

## Validation sequence

1. Parse root app metadata and retain its returned complete IPA inventory as
   the authoritative observation.
2. Discover all in-scope nested roots from that inventory and reject more than
   256 before reading any nested plist payload.
3. Resolve every exact direct plist entry. A missing or directory plist fails
   the whole call instead of silently omitting a bundle.
4. Reject an individual declared plist output above 1 MiB.
5. Sum all selected plist compressed sizes and all uncompressed sizes with
   checked arithmetic. Either aggregate above 64 MiB fails before nested plist
   reads.
6. Read plists sequentially through the bounded Stored/Deflate in-memory API.
   Each read repeats full preflight, reaches EOF for CRC, checks observed output
   length, and returns a complete pre/post-consistent inventory.
7. Require that returned inventory to equal the authoritative inventory for
   every field and entry.
8. Reuse the root parser's bounded XML/binary event stream and closed field
   policy. Duplicate, missing, wrong-type, malformed, oversized, or unsafe
   declarations retain the exact nested plist path in the outer error.
9. Join the validated single executable component beneath its bundle root and
   require one exact regular entry in the authoritative inventory.
10. Return bundles in canonical bundle-root order without modifying the source
    IPA or retaining plist payload bytes.

## Fixed limits

| Limit | Value |
|---|---:|
| Nested framework and extension roots | 256 |
| One uncompressed nested `Info.plist` | 1 MiB |
| Aggregate declared compressed nested plist bytes | 64 MiB |
| Aggregate declared uncompressed nested plist bytes | 64 MiB |
| Plists held concurrently | 1 |
| Plist parser events | 8,192 |
| Collection depth including root | 32 |
| Items or dictionary pairs per collection | 4,096 |
| Top-level keys | 512 |
| One top-level key | 1,024 UTF-8 bytes |
| Cumulative parser scalar bytes per plist | 2 MiB |

Identity and executable field limits are identical to the root
[`Info.plist` contract](ipa-info-plist.md): 255 ASCII bytes for Bundle ID, 128
ASCII bytes per version, and 255 UTF-8 bytes for the executable component.

## Failure semantics

The complete call fails closed for:

- any root app metadata or IPA preflight error;
- excessive bundle count, arithmetic overflow, or aggregate plist bytes;
- missing, directory, oversized, unreadable, unsupported-compression, or
  CRC-invalid nested plists;
- any complete-inventory change across observations;
- malformed XML/binary events, duplicate fields, invalid identity values, or
  an unsafe executable component; and
- a missing or directory declared executable.

There is no partial-success result. A returned empty nested list means the
validated root app contains no bundle root in this deliberately closed scope;
it does not mean arbitrary nested app types were enumerated.

## Tests and catalog integration

Tests use only synthetic in-memory IPAs. They cover XML and binary plists,
nonstandard declared executable names, implicit ZIP directories, a direct
extension and its nested framework, deterministic source-preserving output,
missing/directory/oversized/malformed/duplicate/unsafe declarations, missing or
directory executables, ignored Watch/nested-app/nonconventional shapes, bundle
count, aggregate bytes, overflow, inventory mismatch, and preflight failure.

Run the focused suite with:

```sh
cargo test -p orchardprobe-core ipa_bundle::tests --locked
```

The [`ipa_catalog` code inventory](ipa-code-inventory.md) now consumes this
metadata against the same authoritative complete inventory already bound to
the root main executable. It gives an exact nested declaration precedence over
a `.dylib` suffix, does not guess a conventional bundle-stem executable, and
streams every selected nested executable through the bounded Mach-O parser.
This module itself remains metadata-only and does not retain or classify those
payload bytes.
