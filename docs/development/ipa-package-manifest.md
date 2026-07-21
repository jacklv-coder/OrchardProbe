# Device-free IPA package evidence manifest

`HOST-010` binds the device-free Host pipeline into one validated manifest:

```rust
build_ipa_package_manifest(
    source,
    source_size,
    &code_inventory,
    &mut analysis_package,
    tool_version,
    tool_revision,
) -> Result<ExportManifest, IpaManifestError>
```

The function accepts a secured source reader, the bounded
`IpaCodeInventory` produced from that source, and the private
`IpaAnalysisArchive` returned by `HOST-009`. It does not accept a host directory,
caller-selected output path, caller-supplied hash, caller-supplied archive
inventory, evidence level, or outcome.

This remains a Unix-only library stage. No current CLI command accepts an IPA.

## What the manifest proves

The result proves that:

- the complete source and output archive byte streams produced stable SHA-256
  values during the bounded run;
- their complete validated inventories are bound by a documented canonical
  digest;
- every Mach-O-confirmed code entry in the declared-standard-bundle scope has
  the same source and output file bytes;
- each output code entry still produces the same bounded structural Mach-O
  report, including every universal-binary slice; and
- the output package policy, unsigned state, exclusions, coverage, and visible
  candidate rejections are recorded without private host paths.

It does **not** prove plaintext. Equal source/output hashes deliberately mean
that this device-free stage did not change those code bytes. `cryptid == 0`, a
missing encryption command, successful parsing, CRC success, equal hashes, or a
valid ZIP is not converted into a decryption claim. Every generated binary is
`inconclusive` with `structure` evidence and no known-plaintext evaluation.

## Schema version 3

The pre-v1 export manifest moves from schema version 2 to version 3. Version 2
remains checked in as historical documentation, while the Rust model, CLI
verification, golden fixtures, error-version context, and active schema now
accept version 3.

Version 3 adds three optional top-level fields that must be absent/null
together or present together:

| Field | Meaning |
|---|---|
| `source_artifact` | Source archive length/hash, App root, entry count, and inventory digest. |
| `output_package` | Output artifact evidence, `unsigned_analysis_only` state, deterministic policy v1, and sorted exclusions. |
| `code_inventory` | `declared_standard_bundles` coverage and sorted visible candidate rejections. |

`BinaryEvidence.slices` records every parsed slice. The legacy single `slice`
and `architecture` summary remain during pre-v1 migration: a thin binary has
that one selected slice; a universal binary uses `architecture: universal`, no
single selected slice, and the complete sorted `slices` array.

The `device_free_package` backend requires all three package-evidence objects,
offers no device capabilities, and accepts only binaries with matching
input/output sizes and hashes, non-empty slice evidence, `inconclusive` /
`structure`, no ranges or plaintext oracle, and unknown/not-checked signature
state. Other manifests can omit the package fields.

## Collection sequence

The builder fails closed in this order:

1. Run complete source IPA preflight and compare it with the package-retained
   source inventory.
2. Rebuild the full declared code inventory from the secured source reader and
   require exact equality with the supplied bounded inventory.
3. Run output preflight and compare it with the package-retained output
   inventory.
4. Stream and SHA-256 the exact complete source and output lengths through one
   64 KiB buffer, including an EOF probe.
5. For each path-sorted confirmed code object, use the bounded Stored/Deflate
   entry-copy API to hash the exact source entry. Copy and hash the output entry
   into one anonymous temporary file, flush it, parse it as Mach-O, and require
   the same report and file hash.
6. Repeat source/output preflight and complete-archive hashes after per-binary
   work. Any inventory or byte drift fails.
7. Build the closed version-3 structures, run Rust semantic validation, encode
   once for the 1 MiB manifest limit, and rewind both archive readers to offset
   zero before every return.

The source and output archive can each be read twice, plus bounded per-code
entry reads. This is intentionally sequential and bounded, not optimized by
trusting earlier caller state.

## Canonical inventory digest v1

Inventory hashes never depend on Rust `Debug`, JSON serialization, map order,
host paths, or host metadata. SHA-256 input is exactly:

1. ASCII domain `OrchardProbe\0ipa-inventory\0v1\0`;
2. App-root UTF-8 byte length as big-endian `u32`, then exact bytes;
3. entry count as big-endian `u32`; and
4. for every already canonical-path-sorted entry:
   - path length as big-endian `u32`, then exact UTF-8 bytes;
   - kind byte `1` for file or `2` for directory;
   - execute-class byte `0` or `1`;
   - compressed and uncompressed sizes as big-endian `u64`; and
   - CRC-32 as big-endian `u32`.

Changing a path, order, kind, execute class, size, CRC, entry count, or App root
changes the digest. Source and deterministic-output inventory digests can
differ because compression and explicit-directory metadata are normalized.

## Bounds and cleanup

| Resource | Limit |
|---|---:|
| Complete source or output archive | 16 GiB |
| Hash/copy buffer | 64 KiB |
| Confirmed or rejected code candidates | 256 each |
| Slices in one binary | 64 |
| Slices across a manifest | 2,048 |
| Package exclusions in a manifest | 512 |
| Encoded manifest accepted by the CLI/builder | 1 MiB |
| Concurrent output-code temporary files | 1 |

Lower archive, per-entry, compression, ratio, CRC, path, aggregate-code, and
Mach-O bounds continue to apply. Anonymous code temporaries are removed on
success or error. The package stays private and owned by its RAII wrapper. Both
readers are rewound even when inventory comparison, CRC, hash, structural
inspection, semantic validation, or encoding fails.

## Tests

Project-generated Stored/Deflate fixtures cover repeated byte-identical JSON,
complete archive hashes, inventory-digest sensitivity, exact exclusions,
visible rejected candidates, thin and two-slice universal Mach-O evidence,
matching per-code hashes, honest inconclusive semantics, reader rewind, supplied
inventory drift, same-size output-code mutation, source CRC corruption, and
missing output-code entries, and short/long archive hashing. Manifest tests
cover incomplete package fields,
device capability/hash contradictions, unsafe/conflicting paths, overlapping
slices, collection bounds, legacy-version rejection, Rust/Schema enum parity,
and direct golden version-3 round trips.

Run focused checks with:

```sh
cargo test -p orchardprobe-core ipa_manifest::tests --locked
cargo test -p orchardprobe-core --test schema_contracts --locked
```

This module does not publish an IPA or manifest, modify Mach-O, access a device,
match an installed build, decrypt, prove plaintext, validate signatures, sign,
install, redistribute, or make a compatibility claim.
