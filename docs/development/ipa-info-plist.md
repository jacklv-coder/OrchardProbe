# Bounded IPA `Info.plist` metadata

The `orchardprobe_core::ipa_app` module implements the next device-free ingest
stage after [IPA preflight and bounded entry reads](ipa-preflight.md). It locates
the root iOS app's exact `Info.plist`, parses only bounded events, and resolves
the main executable to a regular-file entry in the same validated inventory.

> [!IMPORTANT]
> This is a library-only metadata foundation. No current CLI command accepts an
> IPA. The module does not inspect Mach-O payload bytes, connect to a device,
> match an installed build, decrypt code, reconstruct files, or package output.
> Parsed identifiers and versions are metadata, not proof of origin, signature,
> authorization, installed-build identity, or plaintext correctness.

## API and result

```rust
inspect_ipa_app_metadata(reader, archive_size)
    -> Result<IpaAppMetadata, IpaAppMetadataError>
```

The caller supplies the same secured `Read + Seek` regular-file handle and
observed length required by the IPA preflight API. On success, the result
contains:

- the canonical immediate `Payload/*.app` root;
- its case-sensitive root `Info.plist` entry path;
- `CFBundleIdentifier`;
- `CFBundleVersion`;
- optional `CFBundleShortVersionString`;
- `CFBundleExecutable`; and
- the exact executable archive path, confirmed as a regular file in the
  validated inventory.

The function never treats the executable name or archive path as a host path.
It returns metadata strings only, not the plist bytes or executable bytes.

## Validation sequence

1. Run the complete ZIP/ZIP64 IPA preflight and select the one app root.
2. Require an exact regular-file `<app-root>/Info.plist` entry with no ASCII
   case fallback and no alternate location.
3. Reject a declared `Info.plist` output above 1 MiB before decompression.
4. Read the exact entry through the bounded Stored/Deflate API. That repeats
   full preflight, binds reopened metadata, limits compressed and uncompressed
   bytes, reaches EOF for CRC32, and checks actual length.
5. Use the inventory returned by that same bounded read, rejecting an app-root
   change rather than combining metadata from two archive observations.
6. Parse either binary plist (`bplist00`) or UTF-8 XML plist events. Legacy
   ASCII/OpenStep plist input is rejected instead of silently widening syntax.
7. Require one root dictionary, unique bounded keys, complete key/value pairs,
   no trailing values, and explicit parser resource limits.
8. Require the identity fields to be strings and validate their values.
9. Join the validated single-component executable name beneath the app root
   and require an exact regular-file inventory entry there.

Unknown top-level keys are allowed because real Apple and application metadata
is extensible. Their values are consumed by a bounded event walker rather than
materialized into an arbitrary object tree. Nested dictionaries still require
string keys and complete values.

## Fixed parser limits

| Limit | Value |
|---|---:|
| Uncompressed `Info.plist` bytes | 1 MiB |
| Parser events | 8,192 |
| Collection depth including root | 32 |
| Items or dictionary pairs per collection | 4,096 |
| Root dictionary keys | 512 |
| One root key | 1,024 UTF-8 bytes |
| Cumulative emitted string/data bytes | 2 MiB |
| Bundle identifier | 255 ASCII bytes |
| Executable name | 255 UTF-8 bytes |
| Version field | 128 ASCII bytes |

Input size alone is not the only bound: binary plists can reference the same
object repeatedly, so a small file can emit the same large scalar many times.
The cumulative scalar and event limits bound that amplification. The pinned
binary parser also checks object-table and reference ranges against the bounded
input before its internal allocations.

## Field policy

- `CFBundleIdentifier` is non-empty ASCII. Period-separated components must be
  non-empty and contain only alphanumeric characters or hyphens, matching
  Apple's documented character set. The original case is preserved.
- `CFBundleVersion` and optional `CFBundleShortVersionString` contain non-empty
  decimal components separated by periods. Their strings are preserved; this
  stage does not compare version precedence.
- `CFBundleExecutable` is one non-empty, non-dot UTF-8 archive component with
  no `/`, backslash, control character, or path interpretation. Existence as a
  regular entry is mandatory; Mach-O structure is checked by a later stage.

Duplicate root keys are rejected even when the key is unknown. This prevents
different plist consumers from selecting different identity or policy values.

Apple's field definitions are the source contract for
[`Info.plist`](https://developer.apple.com/documentation/bundleresources/information-property-list),
[`CFBundleIdentifier`](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier),
[`CFBundleExecutable`](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleexecutable),
[`CFBundleVersion`](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleversion),
and
[`CFBundleShortVersionString`](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleshortversionstring).

## Dependency boundary

The workspace pins `plist` exactly to `1.8.0`, disables its default Serde
feature, and enables only its event-stream API. The exact pin is required
because that API is explicitly unstable across minor releases. Version 1.8.0
declares Rust 1.81 compatibility; `plist` 1.9.0 and 1.10.0 require Rust 1.88,
while OrchardProbe pins Rust 1.85.

`plist` permits `time ^0.3.30`. Cargo 1.85 otherwise resolves a newer
Rust-1.88-only release, so `Cargo.lock` deliberately holds `time 0.3.45`, the
reviewed Rust-1.85-compatible release. All CI and contributor commands use
`--locked`; a dependency update must re-check both MSRV and this parser boundary.

## Test scope and next step

Tests build only synthetic in-memory archives and XML/binary plists. They cover
successful identity resolution, unknown nested values, missing/wrong/duplicate
fields, invalid field values, missing or directory plist/executable entries,
malformed/trailing/non-dictionary documents, legacy encoding rejection,
preflight propagation, and every fixed parser resource class including repeated
binary scalar references.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa_app::tests --locked
```

The exact root executable is now consumed by the separate
[bounded IPA main-executable inspection](ipa-main-executable.md), which streams
it to an automatically cleaned anonymous temporary file and applies the
existing Mach-O parser. The following ingest step is a deterministic bundle
[code candidate inventory](ipa-code-inventory.md) for conventional framework,
dylib, and extension paths. Filename extensions and plist metadata remain
candidate signals, not proof that an entry is Mach-O. The separate
[bounded nested-bundle metadata layer](ipa-nested-bundles.md) now reuses this
parser for conventional framework and extension plists and resolves their exact
declared executable entries. It still does not promote those entries to Mach-O
code or make the convention-based code inventory complete.
