# Deterministic IPA code candidate inventory

The `orchardprobe_core::ipa_catalog` module is the first multi-code-object layer
over bounded IPA ingest. It discovers a deliberately narrow set of conventional
bundle paths, streams each candidate through the secured entry-copy boundary,
and classifies it as code only after the bounded Mach-O parser succeeds.

> [!IMPORTANT]
> The result explicitly reports `coverage: conventional_candidates`. It is not
> a complete declared-bundle code inventory: the separate nested metadata layer
> can resolve a framework or extension whose `CFBundleExecutable` differs from
> its directory stem, but this inventory does not consume that result yet.
> No current CLI accepts an IPA. This layer does not connect to a device, match
> an installed build, decrypt or rewrite bytes, validate signatures, package an
> IPA, or prove plaintext.

## API and result

```rust
inspect_ipa_code_inventory(reader, archive_size)
    -> Result<IpaCodeInventory, IpaCodeInventoryError>
```

The result contains the validated root app identity, one stable coverage enum,
confirmed `binaries`, and visible `rejected_candidates`.

Every confirmed code object includes:

- its exact canonical archive path;
- a `main_executable`, `framework`, `dynamic_library`, or `extension` role;
- the exact validated IPA entry sizes and CRC metadata; and
- a complete bounded `MachOReport` whose slice plaintext status remains
  `not_proven`.

Rejected candidates retain their path, proposed role, and one stable reason:

- `entry_too_large`: compressed or uncompressed bytes exceed the 512 MiB
  per-entry streaming profile;
- `not_macho`: the entry is shorter than a magic value or has unsupported
  magic; or
- `invalid_macho`: it starts as a recognized Mach-O/FAT container but fails
  bounded structural parsing.

An invalid filename candidate is therefore not silently promoted to code or
silently omitted. Archive, copy, temporary-file, or inventory-consistency
failures stop the complete call rather than appearing as a candidate rejection.

## Initial candidate rules

All comparisons are case-sensitive and operate only on canonical inventory
strings. They never create host paths.

1. The root main executable is the exact regular entry resolved from the root
   `Info.plist`; it is mandatory and must parse as Mach-O.
2. A framework candidate has an exact direct path
   `<bundle>.framework/<bundle>`, where the final filename equals the non-empty
   `.framework` directory stem.
3. A dynamic-library candidate is a regular entry whose final filename ends in
   lowercase `.dylib`.
4. An extension candidate has an exact direct path
   `<bundle>.appex/<bundle>`, where the filename equals the non-empty `.appex`
   directory stem.
5. Framework detection takes precedence inside an extension, so a conventional
   nested framework is a framework rather than an extension executable.
6. Exact paths are deduplicated and all returned lists are sorted by canonical
   path.

These conventions are discovery hints, not evidence. `Info.plist`, resources,
arbitrarily named bundle files, and nonstandard executable names are not probed
by guessing. The separate
[nested-bundle metadata layer](ipa-nested-bundles.md) now resolves declared
executable entries without widening this rule, but integration belongs to the
next ledger step.

## Resource and consistency limits

| Limit | Value |
|---|---:|
| Distinct candidates including main | 256 |
| Aggregate declared compressed candidate bytes | 8 GiB |
| Aggregate declared uncompressed candidate bytes | 8 GiB |
| One candidate compressed bytes | 512 MiB |
| One candidate uncompressed bytes | 512 MiB |
| Streaming transfer memory | 64 KiB |
| Concurrent candidate temporary files | 1 |

Candidate totals are checked with overflow-safe arithmetic before optional
candidate payload reads. The root executable is inspected first and yields an
authoritative complete IPA inventory. Every later successful candidate copy
performs its own complete pre/post inventory validation and must equal that
same authoritative inventory. A changed path, kind, size, CRC, count,
aggregate, app root, or archive size stops the call.

Candidates are processed sequentially through automatically cleaned anonymous
temporary files. Those bytes remain local but can reach host storage or swap;
the host and its temporary storage are part of the trusted analysis
environment. See the lower-level
[main-executable contract](ipa-main-executable.md) for the tempfile and sink
ownership details.

## Failure semantics

The inventory fails closed for:

- any root app, root executable, IPA preflight, CRC, or Mach-O error;
- candidate count or aggregate-byte excess;
- arithmetic overflow;
- temporary-file creation or capacity failure;
- unsupported candidate compression or another bounded copy error; and
- any complete-inventory mismatch between candidate observations.

Only convention false positives and per-entry size exclusions become visible
candidate rejections. Returning an inventory does not mean every code object in
the app was discovered or that every rejected candidate is harmless.

## Test scope and next step

Synthetic tests cover deterministic repeated output, all four roles, a
framework nested inside an extension, a false-positive `.dylib`, a recognized
but malformed Mach-O, exact conventional-name rules, directory exclusion,
candidate-count and aggregate-byte bounds, and full preflight propagation. The
lower IPA and Mach-O suites retain CRC, compression, path, FAT, load-command,
and arithmetic adversarial coverage.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa_catalog::tests --locked
```

Bounded nested `Info.plist` parsing is now implemented separately for in-scope
`.framework` and direct `PlugIns/*.appex` bundle roots. The next step is to
merge exact declared executable entries with conventional candidates, define
conflict behavior, apply Mach-O parsing, and advance the coverage enum only
after tests demonstrate the resulting declared-bundle code enumeration.
