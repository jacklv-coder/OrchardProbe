# Declared standard-bundle IPA code inventory

The `orchardprobe_core::ipa_catalog` module combines the exact root and nested
bundle declarations with a deliberately bounded lowercase `.dylib` convention.
It streams every selected non-root candidate through the secured entry-copy
boundary and calls an entry code only after the bounded Mach-O parser succeeds.

> [!IMPORTANT]
> The stable coverage value is `declared_standard_bundles`. It covers the root
> app, the framework and direct extension shapes resolved by
> [`ipa_bundle`](ipa-nested-bundles.md), and lowercase dylibs in that same closed
> ancestry. It does not claim arbitrary app-code completeness: nested `.app`,
> Watch/App Clip content, unsupported bundle types, and executable-looking
> resources remain outside the result. No current CLI accepts an IPA, and this
> layer does not connect to a device, decrypt or rewrite bytes, package an IPA,
> validate signatures, or prove plaintext.

## API and result

```rust
inspect_ipa_code_inventory(reader, archive_size)
    -> Result<IpaCodeInventory, IpaCodeInventoryError>
```

`IpaCodeInventory` returns:

- `coverage: declared_standard_bundles`;
- the validated root `app` metadata;
- canonical-path-sorted `nested_bundles`, including the exact declarations
  used to select framework and extension executables;
- canonical-path-sorted Mach-O-confirmed `binaries`; and
- canonical-path-sorted `rejected_candidates` for selected non-root entries
  that cannot be classified as code.

Each code object preserves its exact archive path, semantic role, validated
entry sizes and CRC, and bounded `MachOReport`. A report's encryption metadata
does not prove plaintext; every slice remains `not_proven` without stronger
independent evidence.

## Selection and precedence

All decisions use case-sensitive canonical inventory strings. No archive path
is interpreted as a host path.

1. The root main executable is the exact regular entry declared by the root
   `Info.plist`. It is mandatory and always has `main_executable` precedence.
2. Every in-scope nested framework or direct `PlugIns/*.appex` contributes the
   exact executable resolved from its direct `Info.plist`. A framework inside
   that extension is also in scope.
3. A regular entry whose final filename ends in lowercase `.dylib` is selected
   only when its ancestry stays within the closed rules below.
4. Exact nested declarations override the `.dylib` convention for the same
   path. A declared `Renamed.dylib` therefore retains `framework` or
   `extension`, never `dynamic_library`.
5. A conventional bundle-stem file is not guessed. If `Kit.framework` declares
   `Worker`, a sibling `Kit.framework/Kit` is neither confirmed nor rejected by
   this inventory unless another in-scope rule selects it.
6. Exact paths are deduplicated before count and aggregate-byte checks.

### Lowercase dylib ancestry

An otherwise valid lowercase `.dylib` path may be beneath the root app and may
optionally be beneath exactly one direct `PlugIns/<non-empty>.appex`. It may
traverse at most one non-empty `.framework` component.

The convention excludes a path containing:

- any component ending in `.app`, including empty-stem, normal Watch, and App
  Clip app shapes;
- an `.appex` anywhere other than the direct `PlugIns/<name>.appex` position;
- an empty-stem `.appex` or `.framework`, or more than one `.framework`
  component; or
- an uppercase or mixed-case suffix such as `.DYLIB`.

These exclusions are coverage boundaries, not claims that omitted bytes are
safe or non-code.

## Validation sequence

1. Inspect the exact root main executable and retain its complete IPA inventory
   as the single authoritative observation.
2. Resolve all nested bundle plists against that same inventory. Missing,
   directory, unsafe, oversized, unreadable, or malformed declarations fail
   before any optional code-candidate payload is copied.
3. Merge in-scope lowercase dylibs, exact nested declarations, and the root
   declaration in increasing precedence order.
4. Reject more than 256 deduplicated paths and checked aggregate compressed or
   uncompressed totals above 8 GiB before optional candidate reads.
5. Process non-root candidates sequentially through one automatically cleaned
   anonymous temporary file. Each copy repeats complete IPA preflight, reaches
   EOF for CRC, enforces observed length, and returns a complete inventory that
   must equal the authoritative one.
6. Parse the temporary file with the bounded thin/FAT Mach-O parser. Sort
   confirmed and rejected paths independently before returning.

The source IPA is never modified. Candidate temporary bytes remain local but
can reach host storage or swap, so the host and its temporary storage are part
of the trusted analysis environment.

## Resource limits

| Limit | Value |
|---|---:|
| Distinct deduplicated candidates including main | 256 |
| Aggregate declared compressed candidate bytes | 8 GiB |
| Aggregate declared uncompressed candidate bytes | 8 GiB |
| One candidate compressed bytes | 512 MiB |
| One candidate uncompressed bytes | 512 MiB |
| Streaming transfer memory | 64 KiB |
| Concurrent candidate temporary files | 1 |

Nested plist count, byte, parser-event, collection, and string limits remain
those documented in the [nested-bundle contract](ipa-nested-bundles.md).

## Rejections and fatal errors

A selected non-root path produces one visible rejection when:

- `entry_too_large`: its declared compressed or uncompressed size exceeds the
  per-entry streaming profile;
- `not_macho`: the copied entry is shorter than a Mach-O magic or has an
  unsupported magic; or
- `invalid_macho`: the entry starts as recognized Mach-O/FAT but fails bounded
  structural parsing.

Root app, root main, nested metadata, count, aggregate arithmetic, temporary
file, bounded copy, CRC, compression, or complete-inventory failures stop the
whole call. Root main Mach-O failure is also fatal. Returning a result means
only that this declared standard-bundle scope was handled deterministically;
it does not mean every executable in an arbitrary app was discovered.

## Test scope and next step

Synthetic in-memory IPA tests cover deterministic repeated output, every role,
nonstandard declarations, a declared executable ending in `.dylib`, precedence,
conventional-stem exclusion, direct-extension and nested-framework behavior,
standalone dylibs, Watch/nested-app/out-of-scope-extension/multiply-nested-
framework exclusions, visible non-Mach-O and invalid-Mach-O rejections, count,
aggregate and per-entry limits, malformed or missing nested metadata, inventory
mismatch, and malformed archive propagation. Lower IPA, plist, entry-copy, and
Mach-O adversarial suites retain the detailed CRC, compression, parser, path,
FAT, load-command, and arithmetic checks.

Run the focused tests with:

```sh
cargo test -p orchardprobe-core ipa_catalog::tests --locked
```

The next ledger step is `HOST-008`: materialize the already validated archive
into a private bounded worktree without symlink or path escape. That step is not
implemented or activated by this inventory.
