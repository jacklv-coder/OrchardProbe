# LAB-002 fixed-range self-observation oracle design

Status: **Device-free design implemented and Simulator-verified; not signed or device-verified**

Tracking Issue: [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

This document is the reviewed design gate for LAB-002. It defines a
first-party-only experiment that may later determine whether the exact
TestFlight-installed DemoLab build exposes independently reviewable evidence
of a protected-on-disk to plaintext-in-memory transition.

Merging this design does not authorize a signed build, TestFlight upload,
installation, device observation, device backend, decryption implementation,
or IPA reconstruction. Those remain separate gates in the
[execution ledger](../../EXECUTION_PLAN.md).

## Research question and decision boundary

LAB-002 asks one narrow question:

> For the exact recorded DemoLab build, can every installed slice of the main
> app, DemoFramework, and DemoShareExtension prove that one predeclared code
> range is protected in its own installed file and that the same range is
> plaintext in its own mapped image, matching an oracle frozen before upload?

The answer may be **Go** or **No-Go**. A Go establishes only that this oracle
method worked for the exact recorded first-party tuple. It does not establish
a byte-for-byte identity between the uploaded IPA and Apple's installed
package, a reusable device backend, or a user-facing IPA workflow. In this
document, recorded build lineage means the frozen source/build, authorized
targets, Mach-O UUIDs, slices, coordinates, and range hashes, not whole-package
identity after Apple processing.

No partial inventory is accepted. The three executable roles and all slices
declared before observation remain in scope even if Apple processing changes
the installed artifact. A changed or unobservable item makes the method No-Go;
it is never removed after the fact.

## Non-negotiable invariants

1. Only repository-owned DemoLab code and an owned test device are in scope.
2. Observer entry points take no path, PID, image, address, offset, length,
   architecture, or executable argument.
3. Each target may inspect only its own fixed executable file and its own
   mapped Mach-O image.
4. No executable bytes leave the device. Reports contain closed metadata,
   numeric coordinates relative only to the Mach-O slice, executable-file
   start, or unslid image, SHA-256 digests, and bounded outcomes. They never
   contain an absolute path, runtime address, or caller-selected coordinate.
5. The expected plaintext digest is generated on the Mac from the immutable
   pre-upload artifact, never from a device report or mapped bytes.
6. The exact source commit, version/build, private authorized-target manifest
   digest, IPA digest, three-role inventory, expected slices, fixed range per
   slice, and oracle digest are frozen together before upload or observation.
7. Initial protection requires both encryption-command coverage and an
   on-disk range digest that differs from the frozen plaintext digest.
   `cryptid == 1` alone is insufficient.
8. Plaintext requires the mapped digest for the exact same range to equal the
   frozen oracle. A self-consistent pair of device hashes is insufficient.
9. Every expected installed slice must be the active mapped slice in a clean
   execution. An installed extra slice that cannot be mapped makes the result
   No-Go.
10. Two cleared, fresh executions must be bound to the same physical device,
    app installation, hardware model, iOS version, and iOS build, and must
    produce identical normalized evidence.
11. The operator must make a fresh RFC-0001 authorized-use acknowledgement
    before installation and before each of the two collection runs. A valid
    host-signed acknowledgement envelope and a device-signed enrollment receipt
    are required inputs, not inferred consequences of device ownership,
    installation, or an earlier approval.

## Trust and independence model

The method separates three evidence producers:

| Producer | Input | Output | It cannot prove alone |
|---|---|---|---|
| Pre-upload oracle generator | Private authorized-target manifest, source-built Archive, and evidence-bound exported DemoLab IPA from one clean commit/build | Frozen target-identity bindings, inventory, fixed coordinates, expected SHA-256 values, and artifact SHA-256 | Installed identity, installed protection, or mapped plaintext |
| Target-local observer | Its own installed bundle, executable, signature metadata, and mapped image | Authorized-target identity binding, installed identity, encryption coverage, on-disk digest, and mapped digest | That its mapped digest is expected plaintext |
| Host verifier | Private authorization manifest/key, pre-upload evidence, evidence-bound local IPA, externally digested frozen oracle, signed installation/enrollment set, and two signed per-run acknowledgement/intent/challenge/export/binding sets | Deterministic provenance, authorization/environment continuity, per-slice comparison, and Go/No-Go result | Hardware attestation, full installed-package identity, or new file, process, memory, Apple-signing, or device access |

Independence means no device-observed mapped bytes can influence the pre-upload
expected digest, and no caller can select a different target or range. The
observer remains fixture code, not a separate hardware trust root. Its claims
are accepted only when the independently frozen artifact, installed identity,
encryption coverage, disk digest, and mapped digest all agree.

LAB-002 does not use a CoreDevice, helper, or backend operation to access an
app or shared container. Challenge ingress and report egress are explicit
user-mediated document import/export through iOS system UI. DemoLab and its
extension use their own App Group only internally. This is not an exception to
RFC-0001 or RFC-0002 and contributes no plaintext claim.

## Complete inventory

The allowlist is compiled into the tooling and observer targets:

| Role | Fixture-relative executable | Observer owner |
|---|---|---|
| `main_app` | `DemoLab.app/DemoLab` | DemoLab main process |
| `framework` | `DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework` | DemoFramework code in the main process |
| `share_extension` | `DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension` | DemoShareExtension process after explicit invocation |

The pre-upload oracle enumerates every Mach-O slice under these exact paths.
For the first candidate, each role is expected to contain exactly one device
slice. That expectation is frozen, not inferred later from the phone.

At runtime the observer independently enumerates installed file slices. The
observed set must exactly equal the frozen set by role, CPU type, CPU subtype,
and slice ordinal. Thin/fat representation, slice count, or architecture drift
is a hard mismatch. An unexpected slice is recorded and never ignored.

## Fixed code range

Each target will contain exactly one role-specific Mach-O section named
`__TEXT,__oprobe`. The implementation must make that section:

- a non-empty pure-instruction section with role-specific deterministic code;
- between 64 and 1,024 bytes for every supported device slice;
- emitted exactly once per target and retained in Release builds;
- free of relocations, rebases, binds, chained fixups, mutable data, literals
  that require rewriting, and internal alignment padding; and
- discoverable from bounded Mach-O parsing without a symbol lookup or
  caller-provided coordinate.

The entire section is the one fixed range for its slice. A section is rejected
if it is missing, duplicated, empty, oversized, outside an executable
`__TEXT` segment, overlaps another section, or has relocation/fixup records.
The generator records its absolute slice file offset, unslid VM offset from
the image header, and length using checked arithmetic.

Using a dedicated section prevents selecting convenient bytes after seeing a
device result. It excludes normal compiler/linker padding, Swift metadata,
writable data, and address-bearing code that may be changed by loading.

Archive and exported-IPA identity, coordinate, length, and plaintext bytes must
match before upload. After distribution, different installed on-disk section
bytes are expected ciphertext and required by the protection gate; that
difference is not range drift. A changed installed inventory, UUID, coordinate,
length, or mapped plaintext digest is No-Go and is never adapted.

## Pre-upload build and oracle artifact

The future implementation extends the existing hardened DemoLab archive lane;
it does not create an `oprobe` command. From a clean, reviewed commit it will:

1. before compilation, create a private
   `lab-002-authorized-targets-v1.json` containing a random 256-bit identity
   nonce, a fresh Ed25519 authorization public key and key ID, and the exact
   authorized identity tuple for all three roles; keep the matching private key
   outside Git as a mode-`0400` owner-readable experiment input;
2. canonicalize source commit, version/build, configuration, observer
   revision, the authorized-target manifest SHA-256, and selected
   Xcode/SDK/XcodeGen/Fastlane identities into `build_binding_sha256`, then
   inject the same immutable value and identity nonce into all three targets;
3. build the exact authorized marketing version and build number;
4. retain existing Archive and exported-IPA pre-upload evidence;
5. reopen the evidence-bound IPA through bounded, no-follow private handling;
6. require exactly the three allowlisted executable entries;
7. enumerate every Archive and IPA slice and validate Mach-O structure, UUID,
   code-signature command, `__TEXT,__oprobe`, and relocation/fixup exclusions;
8. require every oracle-source Archive slice and corresponding exported-IPA
   slice to report `cryptid == 0`, while retaining the rule that this metadata
   is only a consistency check and never plaintext proof by itself;
9. derive the expected plaintext SHA-256 from the source-built Archive section,
   independently hash the corresponding exported-IPA section, and require
   exact slice identity, coordinate, length, and digest equality;
10. publish canonical `lab-002-oracle-v1.json` exclusively with mode `0400`,
    fsync, and atomic rename; and
11. hash the final canonical oracle bytes and bind that SHA-256 into the
    separate pre-upload evidence before upload is allowed.

For each role, the private authorized identity tuple contains its exact
`CFBundleIdentifier`, signed CodeDirectory identifier and team identifier, and
the exact selected entitlement values or required absence for
`application-identifier`, `com.apple.developer.team-identifier`, and
`com.apple.security.application-groups`. The generator independently reads
these values from the Archive and exported IPA and requires them to match the
authorized tuple before oracle publication.

The authorization key ID is exactly SHA-256 of the raw 32-byte public key.
That public key and key ID are compiled into the main app as part of the build
binding. The private key is used only by the host authorization
coordinator to sign the closed installation-enrollment and per-run challenge
envelopes described below. It is never copied into the source tree, IPA,
device, report, or public result.

The host key file contains exactly the raw 32-byte Ed25519 private seed, opened
owner-only without following symlinks; PEM and trailing bytes are rejected.
Mode `0400` is an accidental-disclosure boundary, not a non-exportability or
HSM claim: the owning host process/user can copy the private key. The approved
experiment therefore treats the uncompromised owner account and authorization
coordinator as trusted, destroys the key after the retention window, and makes
no authorization claim against a compromised host or a malicious operator.

For reports and oracle comparison, the generator computes a domain-separated
`target_identity_binding_sha256` over the identity nonce, role, and canonical
observed tuple. The target-local observer independently computes the same
digest from its own bundle and embedded signature metadata. The nonce is
compiled into target-private observer code, but is never a report field. A
different Bundle ID, signed identifier, team, App Group, selected entitlement,
or required-absence result therefore produces a different binding and fails
closed. This binding prevents accidental lineage substitution; it is not
claimed as tamper-resistant attestation against an attacker who can modify and
re-sign the observer itself.

The authorization manifest contains private identifiers and remains mode
`0400` in the owner-only experiment directory outside Git. It is never placed
in the IPA, oracle, report family, or public result. Its SHA-256 is bound into
the build, pre-upload evidence, oracle, and collection intent. The identity
nonce and authorization public key/key ID are the only manifest values
deliberately compiled into observer code; private target identifiers and the
authorization private key are never compiled or exported.

### Binding byte encodings

All four cross-producer bindings use SHA-256 over versioned binary encodings,
not implementation-specific JSON or string concatenation. `u32be(n)` is one
unsigned four-byte big-endian length or count. A framed string is
`u32be(utf8_length) || strict_UTF8_bytes`. Text must be NFC, contain no NUL or
control scalar, and satisfy the field's narrower identifier/version grammar;
otherwise generation or observation fails. Lowercase-hex fields must have
their exact required length. No implementation may add, omit, normalize, or
reorder a field. Quoted domain tags below are their ASCII bytes; `\0` denotes
one final zero byte, not the two printable characters backslash and zero. The
64-hex identity nonce is decoded to exactly 32 raw bytes before hashing.

`build_binding_sha256` hashes:

```text
"orchardprobe.demolab.lab002.build-binding.v1\0"
|| framed(source_commit)
|| framed(marketing_version)
|| framed(build_number)
|| framed(configuration)
|| framed(observer_revision)
|| framed(authorized_target_manifest_sha256)
|| framed(xcode_version)
|| framed(xcode_build)
|| framed(iphoneos_sdk_version)
|| framed(iphoneos_sdk_build)
|| framed(xcodegen_version)
|| framed(xcodegen_architecture)
|| framed(xcodegen_executable_sha256)
|| framed(fastlane_version)
|| framed(gemfile_lock_sha256)
```

The configuration is exactly `Release`; hashes and the source commit are
lowercase hex. Every listed tool field is mandatory.

For `target_identity_binding_sha256`, the domain is
`"orchardprobe.demolab.lab002.target-identity.v1\0"`, followed by the raw
32-byte identity nonce, one role byte (`1` main app, `2` framework, `3` share
extension), then framed Bundle ID, CodeDirectory identifier, and CodeDirectory
team identifier in that order. Each selected scalar entitlement follows as
one presence byte (`0` required absent, `1` present); a present value is
followed by one framed string. The scalar order is `application-identifier`,
then `com.apple.developer.team-identifier`. App Groups follow as one presence
byte; when present, append `u32be(count)` and each non-empty framed group in
strict UTF-8 bytewise ascending order. Duplicate groups are rejected. No
trailing bytes are permitted.

`target_identity_set_sha256` hashes the domain
`"orchardprobe.demolab.lab002.target-identity-set.v1\0"` followed by the three
raw 32-byte target-identity digests in role-byte order. The private
authorization-manifest SHA-256 and every canonical JSON artifact hash the
final exact bytes read through the stable descriptor; they are not hashes of
parsed or reserialized objects.

`device_installation_binding_sha256` hashes the domain
`"orchardprobe.demolab.lab002.device-installation.v1\0"`, the raw 32-byte
identity nonce, the raw 32-byte device-enrollment public key, the raw 32-byte
installation nonce, and framed canonical values for `identifierForVendor`,
hardware model identifier, iOS product version, and iOS build, in that order.
The identifier-for-vendor must be a non-null lowercase canonical UUID. The
main app reads it only during enrollment and session creation and never stores
or exports the raw value. The hardware and OS values come from fixed platform
queries, not caller input. The 256-bit installation nonce is generated once
with the system CSPRNG during authenticated enrollment and exclusively
persisted in the fixed, backup-excluded App Group state; it is never exported.
A missing binding input, state reset, reinstall, device change, or OS update
therefore changes or prevents the binding and invalidates the experiment.

The fixed environment queries are `UIDevice.identifierForVendor`,
`hw.machine`, `kern.osproductversion`, and `kern.osversion`. The last three
produce the report's sanitized hardware model, iOS product version, and iOS
build. Each is strict printable ASCII with a closed grammar and maximum 32
bytes; a missing query, unexpected character, or truncation fails rather than
substituting a marketing string. The verifier maps the hardware model to a SoC
family through a reviewed, versioned local table and records that table
revision and derived SoC only in the private test record and sanitized final
compatibility row. The mapping cannot select or broaden an observer operation.

Host authorization uses Ed25519 over exact canonical bytes. For either an
installation-enrollment core or a run-challenge core, the signature input is:

```text
"orchardprobe.demolab.lab002.authorized-operation.v1\0"
|| u32be(acknowledgement_canonical_byte_length)
|| acknowledgement_canonical_bytes
|| u32be(operation_core_canonical_byte_length)
|| operation_core_canonical_bytes
```

The imported envelope carries those exact two canonical byte strings, the
authorization-key ID, and one 128-lowercase-hex Ed25519 signature. Before any
enrollment or observation side effect, the main app decodes, rehashes, and
re-encodes both objects; requires exact byte equality; verifies the signature
with the compiled public key; and validates policy, operation, build, scope,
experiment/run, and time fields. A digest or Boolean without a valid signature
is never accepted as authorization. Keys are raw 32-byte Ed25519 public keys
and signatures are raw 64-byte values; PEM, certificate chains, algorithm
negotiation, and fallback are forbidden.

The enrollment receipt signature uses:

```text
"orchardprobe.demolab.lab002.enrollment-receipt.v1\0"
|| u32be(canonical_unsigned_receipt_byte_length)
|| canonical_unsigned_receipt_bytes
```

The signed envelope stores the exact
unsigned canonical bytes, public key, and signature as separate closed fields;
the verifier applies the same decode/re-encode/exact-byte rule before signature
verification. The receipt and session-export signature domains are distinct,
so neither artifact can be substituted for the other.

The source-built Archive is the plaintext-oracle provenance: the hardened lane
builds it directly from the recorded immutable DemoLab source commit before
Apple distribution processing. `cryptid == 0` on both local artifacts and
Archive/IPA fixed-range equality are mandatory independent consistency checks;
neither field alone is promoted to proof. A missing encryption command,
non-zero `cryptid`, or Archive/IPA mismatch rejects oracle publication.

The frozen oracle contains:

- schema/profile revision, `build_binding_sha256`, and the private
  authorized-target manifest SHA-256;
- the expected per-role `target_identity_binding_sha256` values;
- DemoLab source commit and fixture-relative source root;
- marketing version and build number;
- Xcode, SDK, XcodeGen, Fastlane, and generator identities;
- evidence-bound IPA size and SHA-256;
- the exact three-role inventory in deterministic order;
- for every slice: CPU type/subtype, ordinal, file extent, Mach-O UUID,
  sanitized code-signature digest, Archive and IPA `cryptid`, slice-relative
  section offset, absolute file offset, VM offset, length, Archive expected
  plaintext SHA-256, and matching exported-IPA section SHA-256.

The oracle JSON never contains its own SHA-256. Only after its final canonical
bytes are closed does the lane compute their digest and store it in the
separate pre-upload evidence. The upload gate rehashes the oracle and compares
that external field, avoiding a self-referential digest.

It never contains executable bytes, credentials, a private Bundle ID, the
identity nonce, an absolute path, or device identity. The full local artifact
stays in the owner-only experiment directory outside Git. A public result may
retain only its SHA-256 and sanitized rows.

The upload lane must refuse to proceed if the authorization manifest or oracle
is absent, either digest does not match pre-upload evidence, the worktree is
not the recorded clean commit, or any target-identity, inventory, or range
validation fails.

## Target-local observation

The fixture uses three closed, zero-argument entry points:

- the main app observes only `Bundle.main.executableURL` and its own anchor;
- DemoFramework observes only the bundle and mapped image containing its
  compiled anchor; and
- the share extension observes only its `Bundle.main.executableURL` and anchor.

No common public API accepts a URL, descriptor, header, role, range, or anchor.
Internal parser functions remain target-private and receive values only from
the corresponding fixed entry point.

For one component, observation is ordered:

1. Resolve the fixed executable URL from its own bundle.
2. Open it read-only without following symlinks and require a regular file.
3. Parse the complete bounded thin/fat container and Mach-O load commands.
4. Canonicalize only this target's Bundle ID, signed identifier, team, and
   selected entitlement presence/values, then compute its
   `target_identity_binding_sha256` with the compiled identity nonce.
5. Bind the active image to the compiled anchor, image header, Mach-O UUID,
   CPU identity, and `__TEXT,__oprobe` metadata.
6. Before mapped hashing, require one encryption command whose `cryptid == 1`.
   Treat its `cryptoff` and `cryptsize` as slice-relative, normalize their
   checked interval by adding the installed slice start, and require that
   absolute interval to cover the fixed absolute file range.
7. Hash the exact on-disk section through the stable descriptor.
8. Convert the fixed file coordinate to an unslid VM coordinate with the
   matching `__TEXT` segment; apply only this image's dyld slide.
9. Confirm containment in the mapped executable segment, then hash exactly
   that interval.
10. Close the descriptor and atomically publish only the bounded report.

The observer never receives the oracle. The host later compares the reported
disk and mapped hashes with the independently frozen expected hash.

## Installed identity and initial protection

Each role/slice must match all frozen fields expected to survive processing:

- role and fixture-relative path;
- version/build;
- role-specific `target_identity_binding_sha256`, proving an exact match to the
  privately authorized Bundle ID, signing identity, and selected entitlements;
- CPU type/subtype, slice count, and ordinal;
- Mach-O UUID;
- `__TEXT,__oprobe` file offset, VM offset, and length; and
- installed signature `presence`, `kind`, and `validation` as separate closed
  fields, plus the sanitized code-signature-superblob SHA-256 when present.

The installed signature digest identifies the observed installed artifact but
need not equal the pre-upload signature after Apple processing. Matching UUID,
range identity, build facts, and oracle evidence provide the source/build
binding. If UUID or range identity changes, lineage fails rather than falling
back to version/build.

The closed signature values reuse the export-manifest vocabulary: presence is
`present` or `absent`; kind is `cms`, `ad_hoc`, `unknown`, or
`not_applicable`; validation is `valid`, `invalid`, `not_checked`, or
`not_applicable`. Go requires exactly `present` / `cms` / `valid` for every
role. Validation must come from an explicit, reviewed validator operating on
that role's stable descriptor and signature structure; successful launch,
entitlements, a digest, UUID, or `cryptid` cannot be inferred as validation.
An independently validated report records the fixed validator ID
`security-framework` and the exact frozen observer revision as its validator
revision. If no public platform API or bounded independently tested
implementation can perform the validation, the checked-in observer instead
records the exact parser tuple `not_checked` /
`demolab-bounded-codesign-parser` / `1`, outcome `inconclusive`, and sole reason
`signature_invalid_or_unchecked`. The Host may close that exact truthful tuple
as reproducible No-Go evidence while still requiring every identity,
encryption, disk, and mapped-plaintext comparison to match. It never promotes
the tuple to valid or Go. Every inconsistent validator tuple is rejected; an
absent, ad-hoc, unknown, invalid, or unchecked signature remains method-level
No-Go. An approved independent validator's exact `present` / `cms` / `invalid`
tuple is retained as generic No-Go with
`signature_invalid_or_unchecked`; it is not rejected as missing evidence.
Likewise, a structurally valid signed report that preserves authorized identity
and bounded coordinate integrity but fails a protection, disk, or mapped-
plaintext comparison closes as generic No-Go. Only contradictory validator,
outcome, or reason semantics and substituted identity/integrity fields fail the
artifact verifier itself.

Initial protection is Pass only when:

- installed slice identity matches the frozen slice;
- installed signature state is exactly `present` / `cms` / `valid`;
- one valid encryption command reports `cryptid == 1`;
- its non-zero interval fully covers the fixed range;
- the exact disk range is readable through the component's own descriptor;
- its SHA-256 differs from frozen expected plaintext; and
- the later mapped SHA-256 equals frozen expected plaintext.

No individual field or hash is sufficient.

## Checked file-to-VM conversion

Generator and observer implement the same rules independently:

```text
range_slice_start = section.offset
range_file_start  = slice_file_start + range_slice_start
range_file_end    = range_file_start + section.size
crypt_file_start  = slice_file_start + cryptoff
crypt_file_end    = crypt_file_start + cryptsize
section_file_delta = section.offset - text_segment.fileoff
section_vm_delta   = section.addr - text_segment.vmaddr
require section_file_delta == section_vm_delta
range_vm_offset   = (text_segment.vmaddr - image_text_vmaddr)
                  + section_file_delta
mapped_start      = image_header + range_vm_offset
mapped_end        = mapped_start + section.size
```

Every operation is checked. The section must be contained in both the selected
slice and the file-backed part of an executable `__TEXT` segment. Its checked
`section.offset - segment.fileoff` must equal
`section.addr - segment.vmaddr`; a mismatch rejects the artifact before either
range hash. The derived VM offset must also equal
`section.addr - image_text_vmaddr`, and the mapped interval must be contained
in the corresponding mapped segment. Encryption coverage compares
`[crypt_file_start, crypt_file_end)` with
`[range_file_start, range_file_end)`; it never compares slice-relative
`cryptoff` directly with an absolute file offset. Reports label
slice-relative and absolute file coordinates separately and use unslid
image-relative VM offsets; absolute paths and runtime addresses are forbidden.

Any relocation, rebase/bind/chained-fixup target, mutable or zero-fill section,
or padding in the proposed range rejects the build. The runtime never
normalizes bytes. If Apple or dyld changes them, comparison fails closed.

## Report family

Implementation adds an immutable pre-v1 JSON contract with profile
`orchardprobe.demolab.lab002.observation.v1`. Four files form one session:

```text
session.json
main-app.json
framework.json
share-extension.json
```

`session.json` contains only schema/profile, observer revision,
`build_binding_sha256`, host collection ID, run ordinal, canonical
collection-challenge SHA-256, authorization policy version and acknowledgement
SHA-256, authorization-envelope SHA-256, device-enrollment-binding SHA-256 and
public key, `device_installation_binding_sha256`, sanitized hardware model and
iOS version/build, a random 256-bit lowercase-hex session ID, monotonically
increasing run counter, the exact signed `authorization_not_after`,
whole-second creation time, source commit,
version/build, and state `collecting`, `complete`, or `failed`.

The counter is allocated from a separate fixed
`state/run-counter-v1.json` record in the App Group, not from the disposable
report subtree. That closed record is at most 1 KiB and contains only schema,
the same build binding, and one counter encoded as exactly 16 lowercase
hexadecimal characters representing a big-endian unsigned 64-bit value. The
same fixed-width encoding is used in `session.json` and role reports; comparison
decodes it to an integer, never compares it lexically. A serialized main-app
state coordinator rejects symlinks and non-regular files, reads and validates
the complete bounded record, and performs checked `previous + 1`. Every signed
run challenge carries the exact expected result of that increment: run 1 is
`0000000000000001` and run 2 is `0000000000000002`. An absent record is valid
only for run 1 and initializes only to `0000000000000001`; any malformed or
build-mismatched existing record, unexpected previous value, run ordinal, or
signed expected-counter value fails rather than reinitializing. The coordinator
writes a same-directory exclusively created temporary file, flushes it, and atomically
replaces the fixed state record before creating `session.json`. A crash may
consume a counter value but can never reuse it. Report cleanup never removes or
resets this state record; reinstalling/resetting the app or changing its build
binding between the two required runs invalidates the experiment. The share
extension cannot allocate or update the counter. Value
`ffffffffffffffff` is exhausted and rejects a new run.

This exact signed next-counter binding is the device-side spent-challenge
record. A copied run-1 envelope presented after run 1 has committed its counter
expects `0000000000000001`, while durable state requires the next value to be
`0000000000000002`, so it is rejected before a new session or observation. A
copied run-2 envelope is likewise rejected once run 2 commits. The app never
accepts an arbitrary higher counter, skips a value, or treats report-directory
cleanup as challenge-state cleanup.

The same fixed state directory contains
`state/installation-nonce-v1.json`, a closed record of at most 1 KiB with the
schema/profile, build binding, the exact 64-character lowercase-hex raw
enrollment public key, and exactly one random
64-character lowercase-hex nonce. Only the authenticated installation-
enrollment action may exclusively create it through the same no-follow, flush,
and directory-fsync rules. That action also generates one Ed25519 signing key
in the Keychain under one fixed service/account and access group, with
`kSecAttrSynchronizable == false` and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and stores only the public key
in the fixed state record. Every later load derives the public key from the
Keychain private key and requires exact equality with that record before
computing its SHA-256 or device-installation binding. Neither run may create,
replace, repair, or export the private key or nonce. A missing, malformed,
replaced, backup-restored, build-mismatched, key-mismatched, or inaccessible
record fails before observation. Cleanup never removes either fixed state
record or the enrollment key; removal occurs only with experiment teardown or
app deletion.

Each role report contains:

- exact session, collection ID, run ordinal, challenge-digest binding, role,
  and fixture-relative path;
- source/build, observer revision, and `build_binding_sha256`;
- authorization policy version and the current run's authorization-
  acknowledgement SHA-256;
- authorization-envelope and device-enrollment-binding SHA-256 values plus the
  enrollment public key;
- the same `device_installation_binding_sha256` plus the sanitized hardware
  model identifier, iOS product version, and iOS build copied from the
  immutable session;
- role-specific `target_identity_binding_sha256`, never the underlying private
  identifier or identity nonce;
- installed file size, thin/fat kind, and complete slice inventory;
- active slice CPU identity, ordinal, and Mach-O UUID;
- installed signature presence/kind/validation, validator ID/revision, and
  sanitized SHA-256 of the installed code-signature blob when present;
- fixed segment/section, slice-relative and absolute file offsets,
  image-relative VM offset, and length;
- encryption-command kind, slice-relative `cryptoff`/`cryptsize`, normalized
  absolute encryption interval, `cryptid`, and coverage;
- exact disk and mapped range SHA-256 values;
- ordered phases showing disk inspection preceded mapped hashing;
- closed outcome `pass`, `fail`, or `inconclusive`; and
- up to eight closed reason codes.

There are no arbitrary notes or error strings. Stable reasons include:

```text
identity_mismatch
signature_invalid_or_unchecked
inventory_mismatch
missing_or_duplicate_fixed_section
fixed_section_out_of_bounds
fixed_section_has_fixups
encryption_command_invalid
encryption_does_not_cover_range
disk_digest_equals_plaintext
mapped_digest_mismatch
stale_or_conflicting_session
duplicate_role_report
unexpected_installed_slice
report_limit_exceeded
```

Schema and runtime validation reject unknown fields, duplicate JSON keys,
invalid UTF-8, non-canonical hashes, unsafe relative paths, non-integer
numbers, and contradictory outcome/reason combinations.

## Hard limits and deterministic encoding

| Surface | Hard limit |
|---|---:|
| Internal session/report JSON | 32 KiB each before parsing, for exactly the four session files |
| Files per session | Exactly 4 |
| Fixed installation/counter state | Exactly 2 App Group records, 1 KiB each, plus 1 device-only Keychain signing key |
| Host authorization private key | Exactly one raw 32-byte Ed25519 seed, mode `0400`, outside Git |
| Imported signed authorization envelope | Exactly 1 for enrollment and 1 per run, 16 KiB each |
| User-mediated session export | Exactly 1 per run, 512 KiB |
| Host authorization acknowledgements | Exactly 1 for enrollment and 1 per run, 3 KiB each |
| Embedded authorization operation cores | Exactly 1 for enrollment and 1 per run, 3 KiB each; not separate retained artifacts |
| Host signed authorization envelopes | Exactly 1 for enrollment and 1 per run, 16 KiB each |
| Host enrollment receipt/selection/binding records | Exactly 3 per experiment, 16 KiB each |
| Host run intent records | Exactly 1 per run and 2 across the experiment, 16 KiB each |
| Host collection-binding records | Exactly 1 per completed run and 2 across the required two-run experiment, 16 KiB each |
| Complete local collection set | Exactly 5 artifacts per run: authorization acknowledgement, challenge, intent, user export, and binding |
| Abandoned pre-enrollment control set | At most 1 acknowledgement (3 KiB) plus signed envelope (16 KiB); a second abandonment makes the method No-Go |
| Abandoned pre-observation control set | At most 1 run acknowledgement (3 KiB), challenge (16 KiB), and intent (16 KiB); a second abandonment makes the method No-Go |
| Executable roles | Exactly 3 |
| Installed slices per role | 4 maximum; Go still requires exact frozen equality and every slice active/observed |
| Fixed ranges per slice | Exactly 1 |
| Fixed range length | 64–1,024 bytes |
| Installed executable size | 100 MiB |
| Mach-O load commands | 4,096 and 4 MiB total |
| Reason codes per role | 8 |
| Relative path | 256 UTF-8 bytes |
| String | 256 Unicode scalar values unless more narrowly fixed |
| Embedded acknowledgement/operation-core string | 3 KiB decoded UTF-8 and 6 KiB after JCS string escaping, per field |
| Embedded canonical report string | 32 KiB decoded UTF-8 and 64 KiB after JCS string escaping, per entry |
| Observation deadline | 10 seconds per role |
| Retained device sessions | 1 current session |

Every canonical JSON artifact uses the JSON Canonicalization Scheme (JCS) in
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): UTF-8 without a BOM,
ECMAScript JSON string escaping, no insignificant whitespace, and property
ordering by UTF-16 code units. Inputs must also satisfy I-JSON, contain no
duplicate property names, contain only schema-bounded integers (no floating
point or negative zero), and have every string already in Unicode NFC; the
encoder never silently normalizes input. Schema hash fields are fixed-length
lowercase hexadecimal strings. A parser rejects invalid UTF-8, lone
surrogates, NUL or disallowed control characters, unknown fields, and
out-of-range integers. After schema validation, the verifier re-encodes the
value and requires byte-for-byte equality with the supplied canonical bytes,
so alternative escape, key-order, whitespace, or number spellings are
rejected. Embedded canonical reports in the session export use that same JCS
string-escaping rule; the decoded UTF-8 string bytes must equal and hash to the
standalone canonical report.

The embedded acknowledgement, operation-core, and report limits are field-
specific exceptions to the general 256-scalar string limit. These canonical
objects forbid control characters; under JCS, only quote and reverse-solidus
bytes can expand to two bytes when the complete object is embedded. Therefore
a decoded 3 KiB authorization object cannot exceed 6 KiB encoded, and a
decoded report of at most 32 KiB cannot exceed the separate 64 KiB encoded-
field ceiling. The two authorization fields plus their closed envelope remain
within 16 KiB; four reports plus their closed signed envelope remain within
512 KiB.

Role order is main app, framework, share extension. Slice order is frozen
ordinal. The verifier first validates every freshness/control field inside its
own run. It requires both runs to carry the same device-installation binding
and exact sanitized hardware/OS facts. It then constructs an observation-only
projection that removes collection ID, run ordinal, challenge digest, the
per-run authorization-acknowledgement digest and authorization-envelope
signature/hash, session ID, counter, session creation/completion time, and role
phase timestamps, and JCS-encodes that projection. The authorization policy
version and enrollment tuple remain in the projection. Every remaining source/
build identity, target identity, environment identity, inventory, coordinate,
digest, outcome, and reason must be byte-identical between runs.

## Session, collection, stale rejection, and cleanup

DemoLab and DemoShareExtension share one registered App Group. Code obtains its
directory only through
`containerURL(forSecurityApplicationGroupIdentifier:)`; it never constructs an
absolute container path. This is internal first-party app coordination only:
the OrchardProbe host, CoreDevice file service, and every current or future
helper/backend are forbidden from reading, writing, listing, or resolving that
container.

Import, Start, and Discard are all routed through one serialized main-app inbox
coordinator. Before inspecting or changing the inbox, it acquires an exclusive
advisory lock on a fixed owner-only regular lock file through a no-follow
descriptor; every app code path that can publish, consume, or discard the
record uses that lock, and the extension has no inbox operation. While locked,
the coordinator opens the inbox directory and record handle-relatively,
requires the no-follow directory entry identity to equal the opened
descriptor, and atomically renames that exact entry without replacement to one
fixed operation-owned quarantine name. It fsyncs the directory and rechecks
the quarantined descriptor identity before reading or deleting it. A mismatch,
pre-existing quarantine, lock failure, or crash residue blocks all inbox
operations and requires a documented failed attempt; no pathname unlink of an
unlocked or re-resolved entry is permitted.

The main app has a separate **Import LAB-002 authorization** document action. iOS
supplies the user-selected document URL; the handler reads at most 16 KiB,
accepts only the closed signed enrollment or run-challenge envelope profile,
ignores the source filename, and
publishes only validated canonical bytes without replacement to the fixed
internal inbox while holding the coordinator lock. It exposes no general file
browser, path, target, or range to the observer. Import failure creates no
inbox record.

The app also has a zero-argument **Discard stale LAB-002 authorization** action.
It can address only the fixed inbox record. Under the coordinator lock it
performs the atomic identity-checked quarantine above, requires a regular file
within the challenge-envelope limit, and verifies that the closed record is
expired, malformed, or build-mismatched. Only then may it unlink the already
quarantined descriptor-matched entry and fsync the inbox. It cannot discard a
currently valid challenge, accept a path, or replace a record. Using it
abandons the corresponding host enrollment or run intent; that experiment/
collection ID and challenge can never be reused, and the host must retain the
abandoned control records as a failed pre-operation attempt before creating a
fresh signed envelope.

The app exposes one **Start clean LAB-002 run** action without target inputs.
It first requires the fixed observer-owned report directory to be absent or
empty; it never deletes prior reports. Under the same coordinator lock it
atomically quarantines, validates, and consumes one valid host challenge from
the fixed observer inbox, then exclusively creates a random
session bound to that challenge, records main-app evidence, invokes the
framework's zero-argument observation, and prompts explicit share-extension
invocation. An absent, malformed, expired, previously consumed, or
build-mismatched challenge produces no observation session and cannot affect a
prior report subtree.

The extension reads the fixed current session, rejects an absent, completed,
expired, version/build-mismatched, or malformed record, publishes its role
once, and completes normally. The app marks the session complete only after
all three distinct role reports validate.

Files use owner-only temporary creation, full write, fsync,
rename-without-replacement, and directory fsync. They use complete file
protection while locked, are excluded from backup, and never overwrite a role.

Before the first installation, the host requires an interactive RFC-0001
authorized-use acknowledgement and exclusively records one canonical
`authorized-use-ack-v1.json`. Before each run it requires a new acknowledgement
and records another file of the same profile in that run's owner-only
directory. Each acknowledgement has a supported policy version, random
experiment ID, closed operation (`install_and_enroll_exact_build` or
`collect_fixed_range_run`), exact build binding, private authorized-target
manifest SHA-256, fixed technique profile, run ordinal when applicable,
closed data categories and retention profile, a random device-selection nonce,
expected sanitized hardware model/iOS version/build for installation (or the
closed enrollment-binding hash for a run), acknowledgement time and bounded
validity window, and `confirmed: true`. The confirmation UI names the selected
owned/dedicated physical device, first-party DemoLab, fixed-range disk/mapped
hashing, the exact imported/exported data categories, retention, and validity
period. It accepts no caller path, target, range, note, or reusable consent.

The acknowledgement also contains four required closed Boolean assertions,
each exactly `true`: `owns_or_explicitly_authorized_target`,
`within_authorized_scope`, `understands_legal_limits`, and
`will_protect_output_and_not_resign_install_or_redistribute`. Their displayed
text states the four RFC-0001 requirements verbatim in meaning: the operator
owns DemoLab or has explicit owner authorization; acts only within the named
apps, devices, techniques, data, and time; understands that authorization does
not automatically make circumvention lawful in every jurisdiction; and will
protect local output and never use OrchardProbe to re-sign, install, or
redistribute it. Missing/false assertions prevent signing and are also rejected
by the app and verifier. The workflow never requests or records an
authorization letter, client contract, Apple ID credential, receipt, or other
proof.

For LAB-002 the only accepted `authorization_policy_version` is the exact
ASCII value `orchardprobe.authorized-use.v1`. Unknown values fail closed; a
future policy revision requires a reviewed design/schema change rather than
negotiation or fallback.

Installation/enrollment and each complete
import/start/extension/export/cleanup sequence are separate real-device
operation bundles and require their own immediately preceding acknowledgement.
The acknowledgement enumerates that exact closed sequence; no unlisted action
is covered. Silence, possession, installation, a previous build authorization,
or either earlier acknowledgement is not consent. Expiry or unsupported policy
version rejects the operation.

For installation, the host creates a random enrollment challenge and an exact
closed `installation-enrollment-core-v1.json`, then signs it together with the
installation acknowledgement using the authorization encoding above. The
operator installs only that build on the acknowledged device, imports the
bounded signed envelope through DemoLab's document action, and confirms
enrollment. The app verifies the host signature and acknowledgement before it
creates any state. It first queries the fixed environment facts and requires
them to equal the signed expected hardware model/iOS version/build. It then
generates the device-only Ed25519 enrollment key and installation nonce, computes the
device-installation binding, and constructs one bounded
`device-enrollment-receipt-v1.json`. The receipt contains the authorization
envelope SHA-256, acknowledgement SHA-256 and policy, enrollment challenge
response, experiment/build binding, enrollment public key, device-installation
binding, and sanitized hardware/OS facts. The app signs the canonical receipt
with the enrollment private key and exports it only through the system share
sheet.

The host accepts one user-selected receipt inside the installation window,
verifies its self-signature, host-envelope challenge response, build and
environment fields, and computes a fixed display fingerprint from the
authorization-envelope SHA-256, enrollment public key, device-installation
binding, and device-selection nonce. DemoLab displays the same fingerprint on
the physical device. The operator must compare both displays and explicitly
confirm that the receipt came from the device selected in the installation
acknowledgement; the host exclusively records this closed
`device-selection-confirmation-v1.json`, with no free text. Only then may it
close `device-enrollment-binding-v1.json`. That binding records the
installation acknowledgement/envelope/receipt/selection-confirmation hashes,
enrollment public key, device-installation binding, environment facts,
experiment ID, and completion time.

The fingerprint is SHA-256 over the domain
`"orchardprobe.demolab.lab002.device-selection.v1\0"` followed by the four raw
32-byte values above, displayed as the complete 64 lowercase hexadecimal
characters in fixed four-character groups; it is never shortened. This
physical comparison is the explicit device-selection ceremony, not hardware
attestation. Within this first-party fixture threat model, the device-only key
then provides continuity. Run 1 cannot be created until this binding exists.
A stale envelope before device-side
enrollment may use the one bounded abandonment path. Once key/nonce creation
begins, a crash, partial receipt, signature mismatch, or missing export makes
the exact experiment No-Go; it cannot delete state and enroll again into a
passing result.

After each run acknowledgement, the host creates a distinct owner-only run
directory and exclusively publishes one private canonical run-challenge core.
It contains schema/profile, a random 256-bit lowercase-hex challenge, random
collection ID, run ordinal `1` or `2`, the exact next run counter
(`0000000000000001` or `0000000000000002` respectively),
`build_binding_sha256`, authorization
policy version, expected enrollment-binding SHA-256, enrollment public key,
the non-null device-installation binding from enrollment, and bounded
not-before/not-after whole seconds. The host signs the exact acknowledgement
and core into the imported `collection-challenge-v1.json` envelope. The host
then exclusively publishes canonical
`collection-intent-v1.json`, which contains the challenge-file SHA-256 plus the
same collection ID, run ordinal, exact next run counter, window, source/build,
build binding,
installation-acknowledgement and device-enrollment-binding SHA-256 values,
run-acknowledgement SHA-256 and policy version, authorization-envelope
signature/hash, authorized-target manifest SHA-256, expected target-identity-
set digest, enrollment public key, expected device-installation binding,
complete toolchain identity, pre-upload evidence SHA-256, IPA SHA-256,
external oracle SHA-256, expected inventory digest, and observer revision.

The expected inventory digest is SHA-256 over the domain
`"orchardprobe.demolab.lab002.expected-inventory.v1\0"`, one `u32be` byte
length, and the canonical JSON object whose only key is `roles` and whose value
is the frozen oracle's exact ordered role array. It therefore binds every role,
target-identity digest, slice identity, coordinate, and frozen range digest.
The complete intent remains Host-side; only its already-hashed signed challenge
envelope is imported to DemoLab.

All wall-clock fields are signed Unix UTC seconds. The Mac samples
`CLOCK_REALTIME` once when it closes each acknowledgement, sets `not_before` to
that sample and `not_after` to exactly `not_before + 900`, and rejects overflow
or a backward clock step across one operation. A run's challenge and intent
copy the exact acknowledgement window; installation must complete inside its
installation-acknowledgement window. The iPhone evaluates its system wall
clock at import, immediately before session creation, before each role phase,
and before completion. It accepts only when
`not_before - 120 <= device_now <= not_after + 120`, using checked arithmetic;
120 seconds is the maximum allowed Mac/iPhone clock skew and 900 seconds is the
maximum nominal authorization/challenge lifetime. The Host verifier requires
every exact 900-second encoded acknowledgement window, exact equality between
each run acknowledgement and its challenge/intent window, ordered
non-overlapping run windows, report times inside the same skew-expanded
interval, and no backward device time. A clock
offset outside 120 seconds, an expired transfer, or a clock step is
`stale_or_conflicting_session`; before observation it requires the bounded stale
purge and a wholly fresh collection, while after session creation it makes the
method No-Go.

Run 1's intent contains `prior_collection_binding_sha256: null` but already
contains the non-null enrollment-binding hash, public key, and exact device-
installation binding established during authenticated installation. Run 2 is
created only after run 1 is bound and contains the same enrollment tuple plus
the SHA-256 of run 1's final canonical binding.
The two windows must be ordered and non-overlapping. After closing the intent,
the operator explicitly transfers the already hashed challenge document to
the selected owned iPhone through AirDrop or Files and selects DemoLab's
import action. No OrchardProbe host/helper API addresses or accesses the App
Group. No intent, source path, target, range, or other caller free text enters
the observer.

The app opens that fixed challenge through the locked quarantine sequence,
validates the closed 16 KiB envelope and canonical embedded objects, verifies
the compiled-key Ed25519 signature, and checks build, ordinal, authorization
policy/scope, acknowledgement, enrollment-binding hash/public key, time window,
stable file identity, and the exact signed next-counter value against durable
state. It loads the existing device-only enrollment key and
installation nonce, obtains the fixed environment facts, recomputes the device-
installation binding, and requires every expected enrollment value to match
before observation in both runs. While the inbox record remains quarantined
and the coordinator lock remains held, it atomically commits that exact counter
increment, then unlinks only the descriptor-matched quarantined entry and
fsyncs the inbox before creating the session. A crash
after quarantine or consumption fails that run; the challenge is never reused
or silently recreated. `session.json` and all three role reports bind the
collection ID, run ordinal, authorization policy/version and acknowledgement
digest, authorization-envelope hash, enrollment public key/binding, device-
installation binding and sanitized environment facts, and SHA-256 of the exact
consumed challenge bytes. This signed one-shot response proves association
with the current host authorization and enrolled installation without exposing
a target-selection input.

After all four internal reports are complete, the main app exposes one
**Export LAB-002 evidence** action. It constructs canonical
`lab-002-session-export-v1.json` with fixed schema/profile, collection/session
bindings, and exactly four entries in fixed order. Each entry has one fixed
logical filename, SHA-256, and the exact canonical report UTF-8 bytes encoded
as a JSON string. The envelope contains the enrollment public key and one
Ed25519 signature by the device-only enrollment key over the domain
`"orchardprobe.demolab.lab002.session-export.v1\0"` followed by one `u32be`
length and the exact canonical unsigned-export bytes. The complete signed
export is limited to 512 KiB and contains no path, executable/mapped bytes,
arbitrary filename, or note. The system share sheet is the only egress; the
operator explicitly sends the document to the Mac through AirDrop or Files.

The fixed cleanup action is separate from Start and is enabled only after a
complete session export has been constructed and the operator explicitly
confirms that the export was safely received. It rehashes the exact four
reports against that export before removing only their fixed subtree. It
cannot clean a collecting, failed, unexported, or export-mismatched session.
Any incomplete or failed observation terminates the exact experiment as No-Go;
it cannot be cleaned and retried into a passing two-run result.

For each intent, the host accepts one user-selected local export created during
that intent's window. It opens the file privately without following symlinks,
validates the outer closed schema, extracts exactly four bounded canonical
documents, rehashes them, verifies the enrollment-key signature, and requires
matching build/challenge/enrollment bindings. It
copies the export without replacement into that run's local directory, then
exclusively publishes that run's `collection-binding-v1.json`, containing the
installation- and run-acknowledgement SHA-256 values and policy version, intent
SHA-256, device-enrollment-binding SHA-256, authorization-envelope signature
and hash, challenge-file SHA-256, signed session-export SHA-256, collection ID,
run ordinal, exact signed and collected run counter, collected session ID,
enrollment public key, device-installation
binding, canonical
`session.json` SHA-256, the three role-file SHA-256 values, and collection
completion time. The second collection, challenge, and session IDs must differ
from the first, their counters must be exactly `1` then `2`, and their device-installation
binding and sanitized hardware/OS facts must exactly match run 1. No challenge,
export, control record, or extracted report may be shared, overwritten, or
moved between run directories. No host control record contains raw executable
bytes, device paths, raw stable device identifiers, or free text.

The verifier requires one complete installation acknowledgement/envelope/
enrollment-receipt/device-selection-confirmation/enrollment-binding set,
exactly two complete run-
acknowledgement/signed-challenge/intent/signed-export/binding sets, and two
complete sessions. It rehashes every referenced local artifact, verifies the
host signature on every authorization envelope and the enrollment-key
signature on the receipt and both session exports, validates every
acknowledgement's supported policy version, scope, ordering, window, operation,
and one-time use, validates the private authorization manifest and external
oracle digests against pre-upload evidence, recomputes every expected target
identity binding from the private manifest, validates the one enrollment
challenge response and exact non-null enrollment tuple, distinct
collection/challenge/session IDs, challenge responses, export envelopes,
ordered non-overlapping windows, run ordinals, the run-2-to-run-1 binding
chain, the exact signed/session/report run counters `1` then `2`, identical
device-installation binding and sanitized hardware/OS facts,
and every per-file digest, then compares every report's build binding, target
identity, UUID, inventory, range, and digest with the frozen range tuple.

The IPA SHA-256 in each intent proves that the local pre-upload evidence and
oracle were generated for those exact IPA bytes. It is deliberately not a
device-reported field and does not prove that Apple's installed whole package
is byte-identical to the upload. The device side is bound only to the
artifact-stable authorized-target, UUID, slice, fixed-coordinate, and
fixed-range evidence. A missing, duplicate, swapped, reused, unchallenged,
unchained, malformed-export, or mismatched control/session artifact is
`stale_or_conflicting_session`. No report field is ever used as a file-service
request.

After collection, the fixed in-app cleanup action removes only the report
subtree; it cannot remove or reset either fixed state record or the enrollment
Keychain key. The next run requires an empty report directory, the same
enrollment tuple, a successfully persisted higher counter, different session
ID, fresh app/framework execution, and a freshly invoked extension. Stale,
duplicate, conflicting, rolled-back-counter, or replayed records make the run
Inconclusive and the method No-Go.

## Two-clean-run procedure

No device step begins until implementation, device-free tests, and exact build
manifest are merged and the user separately authorizes one exact version/build.
That build authorization does not replace the RFC-0001 acknowledgements below.

1. Build the authorized tuple from the recorded commit and freeze the oracle.
2. Run local CR and verify evidence/oracle binding before one upload.
3. Upload only that build to internal TestFlight. Do not change tester groups,
   enable external testing, request Beta App Review, or submit to the App Store.
4. Reconcile processing; never retry an accepted or indeterminate build
   without the existing explicit reconciliation gate.
5. Immediately before installation, record the policy-versioned installation
   acknowledgement and sign its enrollment envelope; install the exact build
   on the selected owned/dedicated iPhone, import that envelope, generate and
   explicitly export the signed device-enrollment receipt, compare the complete
   fingerprint displayed by that physical iPhone and the host, record the
   device-selection confirmation, and close the enrollment binding. Do not
   change the device, installation, or OS afterward.
6. Immediately before run 1, record its distinct policy-versioned run
   acknowledgement. Create and sign run 1's challenge and intent, with the
   non-null enrollment tuple already required; explicitly import the one-shot
   signed challenge through iOS document UI, terminate DemoLab, start run 1, collect
   app/framework reports, explicitly invoke the share extension, complete the
   session, explicitly export its evidence document to the Mac, and close run
   1's collection binding.
7. Clean reports, terminate app and extension, and confirm the directory empty.
8. Immediately before run 2, record a fresh policy-versioned acknowledgement.
   Create and sign run 2's challenge and intent chained to run 1's binding and
   exact enrollment/device-installation bindings, explicitly import the distinct one-shot
   challenge, freshly launch, start run 2, invoke a fresh extension, explicitly
   export again, and close run 2's binding.
9. Verify the three authorization acknowledgements and host signatures, the
   enrollment receipt/selection-confirmation/binding and device signatures,
   authorization manifest,
   pre-upload evidence, IPA, oracle, both intent/challenge/export/binding sets,
   and both sessions.
10. Publish only sanitized comparison and reasoning, then apply retention.

A crash, unavailable extension, incomplete role, changed inventory, or
non-identical normalized result is recorded and never silently retried away.

## Device-free implementation and validation gate

The next implementation PR must finish these without Apple code signing,
uploading, installing, or observing a phone; authorization/enrollment
cryptography is exercised only with simulator/synthetic keys:

- role-specific `__TEXT,__oprobe` sections and zero-argument entry points;
- bounded Mach-O parsing and checked range conversion;
- canonical authorization/oracle/report/challenge/control/state schemas,
  binding-byte encoders, and positive/adversarial fixtures;
- a host generator and two-session verifier using local/synthetic fixtures;
- proof of exactly one fixed section per target/slice without fixups;
- internal App Group lifecycle and document import/export tests for duplicate,
  stale, partial, oversized, escaping, and conflicting data; concurrent
  Import/Start/Discard, inode replacement, quarantine residue, and lock failure;
  plus proof that no host/helper container-access operation exists;
- deterministic tests covering every Go and No-Go rule;
- fail-closed tests for fat binaries, unexpected slices, overflow, malformed
  commands, Bundle ID/signed-identifier/team/App-Group/entitlement mismatch,
  identity-nonce mismatch, binding truncation/reordering/framing ambiguity,
  UUID/range mismatch, a non-zero FAT slice start, normalized encryption
  coverage, non-zero oracle-source `cryptid`, Archive/IPA range mismatch,
  installed `cryptid == 0`, uncovered encryption spans, disk/oracle equality,
  mapped/oracle mismatch, absent/ad-hoc/unknown/invalid/not-checked or
  contradictory signature state, changed validator revision,
  duplicate/swapped collection sets, malformed session
  export, malformed clock bounds, excessive clock skew or backward clock step,
  unsupported/missing/expired/reused authorization acknowledgement, any
  missing/false RFC-0001 consent assertion, invalid/
  forged/replayed host authorization signature, missing or mismatched
  enrollment receipt/public key/selection-confirmation/binding, invalid or
  shortened selection fingerprint, expected/observed environment mismatch,
  invalid receipt or session-export signature, run 1 on a non-enrolled installation, mixed physical
  device/install/OS facts, nil or malformed identifier-for-vendor,
  enrollment-key or installation-nonce loss/reset,
  missing/expired/reused challenge, copied challenge after cleanup, signed
  expected-counter mismatch or skipped counter,
  stale-inbox purge and a second
  abandoned pre-observation attempt, a broken run-2 binding chain, and
  file/VM segment-delta mismatch, counter overflow/rollback/reset or malformed
  fixed-width encoding, alternate JSON escaping/order/number
  spelling, non-NFC strings, and replay;
- threat model, runbook, compatibility template, and bilingual updates; and
- local/remote Codex CR, required CI, and resolved review threads.

Simulator can validate structure and plumbing only. Its unprotected binaries
must produce Inconclusive. Synthetic metadata may test comparison logic but
must never be labeled device evidence.

## Go / No-Go evaluation

LAB-002 is Go only when both sessions satisfy every row:

| Gate | Required result |
|---|---|
| Frozen provenance | Same source commit, version/build, private authorization-manifest digest, build binding, IPA digest, externally stored oracle digest, toolchain, and three-role inventory |
| Authorized targets | Every role's observed target-identity binding matches the private authorized Bundle ID, signed identifier/team, and selected entitlement tuple |
| Authorized operation | One fresh supported-policy acknowledgement precedes installation and one precedes each run; explicit confirmation plus all four RFC-0001 scope assertions are true, and each exact app/device/technique/data/retention/time scope is authenticated by the compiled host authorization key and validates as one-time |
| Fresh collection | Two distinct one-shot host challenges, valid response digests, ordered windows, and a valid run-2-to-run-1 binding chain |
| Physical environment | Authenticated installation enrollment and full host/device fingerprint comparison select the physical device before run 1; its device-only key signs the receipt and both exports, and both runs have the same non-null enrollment/device-installation bindings, hardware model, iOS product version, and iOS build, with no reinstall, state reset, device change, or OS update |
| Installed inventory | Exact role/slice equality; no missing, extra, inactive, or reclassified slice |
| Installed lineage | Matching UUID, CPU identity, fixed coordinate/length, and explicit installed signature state exactly `present` / `cms` / `valid` with validator revision and sanitized digest |
| Initial protection | Valid `cryptid == 1` interval covers the range and disk digest differs from oracle |
| Mapped plaintext | Same range's mapped digest equals frozen expected plaintext |
| Ordering | Disk identity/protection phases precede mapped hashing |
| Repetition | Two fresh sessions have identical normalized evidence |
| Boundary | No caller-selected target/range, raw bytes, broad primitive, private identifier, or unbounded report |

Any failed row makes the method No-Go. Missing evidence is Inconclusive and
also yields method-level No-Go. A documented No-Go completes LAB-002 but does
not permit weakening the oracle or activating DEVICE-001.

## Privacy, retention, and forbidden claims

The device retains at most one report session plus fixed backup-excluded
installation/counter state and the device-only enrollment key. The Mac
temporarily stores the private authorization manifest and nonce, authorization
acknowledgements and signing key, enrollment envelope/receipt/binding, Archive,
device-selection confirmation, IPA, upload result, oracle, and raw reports plus both
challenge/export/control-record sets only in the owner-only research directory
outside Git, then deletes them after the experiment and approved encrypted
backup period.

Public records may retain commits, version/build, tool versions,
authorization policy version, sanitized hardware model and OS version/build,
fixture-relative paths, architecture, UUID, slice-relative,
executable-file-relative, and unslid-image-relative coordinates, lengths,
SHA-256 values, closed reasons/outcomes, oracle artifact SHA-256, normalized
comparison, the boolean authorized-target match, and final reasoning. They
must not retain the authorization manifest, identity nonce, installation nonce,
raw identifier-for-vendor, device-installation binding, acknowledgement
artifacts/digests, authorization/enrollment public keys or signatures,
device-selection fingerprint/confirmation, enrollment-binding digest, or
per-role target-identity binding digests.

Never copy a certificate, profile, API key, App Store receipt, or pairing record into the
research directory or public record. Never publish a stable device identifier,
private Bundle ID, absolute path, runtime address, protected executable, IPA,
mapped bytes, or raw private log. The first-party IPA is permitted only in the
bounded owner-only research directory during the experiment and approved
encrypted-backup period described above; it must not remain there or elsewhere
as a project artifact after that period.

Even after a Go, the project must not claim arbitrary IPA decryption,
third-party support, a device backend, compatibility beyond the exact tuple,
byte-for-byte identity between the uploaded IPA and Apple's installed package,
that one metadata/hash field proves plaintext, reconstructed output, or
automatic completion of DEVICE-001.

## Apple platform references

- [App Groups entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.application-groups)
- [Configuring App Groups](https://developer.apple.com/documentation/Xcode/configuring-app-groups)
- [`containerURL(forSecurityApplicationGroupIdentifier:)`](https://developer.apple.com/documentation/foundation/filemanager/containerurl%28forsecurityapplicationgroupidentifier%3A%29)
- [Bundle executable URLs](https://developer.apple.com/documentation/foundation/bundle)
- [dyld image and slide APIs](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html)
- [Mach-O runtime interfaces](https://developer.apple.com/documentation/kernel/mach-o)
- [App thinning and binary processing](https://developer.apple.com/documentation/Xcode/reducing-your-app-s-size)
