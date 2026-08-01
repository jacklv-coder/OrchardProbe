# LAB-002 checkpoint 3 progress ledger

Status when activation [PR #61](https://github.com/jacklv-coder/OrchardProbe/pull/61)
is on `main`: **active for DemoLab `1.0 (3)`**

Tracking Issue: [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

On 2026-07-31 the operator explicitly accepted the immediately preceding
bounded proposal to create the first-party DemoLab `1.0 (3)` signed candidate
and frozen pre-upload oracle. This authorization excludes TestFlight upload,
installation, physical-device observation, and device-backend work. Those
operations remain separately gated.

This ledger becomes authoritative only when its activation PR is merged into
`main`. Work must proceed in order, and each row remains blocked until the
preceding row is complete.

| Order | Substep | Status | Completion gate |
|---:|---|---|---|
| 3A | Private pre-build input generator | `complete; PR #62 merged` | The local-only `ios demolab_prepare_lab002` lane builds the repository-internal `oprobe-lab002` helper from the pinned Rust toolchain and checksum-authenticated isolated Cargo sources, creates a fresh raw Ed25519 seed, public key/key ID, identity nonce, canonical authorized-target manifest, target-identity set, and domain-separated Build Binding from a clean commit already present in the authenticated live GitHub `main` history and a pinned build toolchain, then exclusively publishes the three private records outside Git with owner-only permissions and durability checks. Device-free unit/workspace tests, Codex CR, and CI passed; [PR #62](https://github.com/jacklv-coder/OrchardProbe/pull/62) merged as `0df9ee42fe5ac4de71ca9ae32a657b5f8f18deb6` |
| 3B | Archive/oracle/evidence closure | `complete; PRs #63-#65 merged` | The hardened archive flow consumes and revalidates the exact 3A artifacts, builds only the three allowlisted roles, compares Archive and IPA slice identity plus `__TEXT,__oprobe`, publishes the canonical frozen oracle, binds its external SHA-256 into pre-upload evidence, and rejects upload when the closed manifest/oracle tuple is absent or mismatched. [PR #65](https://github.com/jacklv-coder/OrchardProbe/pull/65) merged the final gate as `ca19db07a8badc5d7ce55cc556ab9205181056a5` |
| 3C | Device-free tests, Codex CR, CI, and implementation merge | `complete; PR #66 merged` | Temporary synthetic keys, unsigned Simulator products, and repository-owned fixtures cover weak keys, malformed/private paths, symlink/race/permission failures, target drift, slice/range/fixup mismatch, canonicalization, atomic publication, and upload-gate rejection. All P1/P2 findings were resolved, the full local verification set and required CI passed, and the reviewed implementation merged through PRs #62-#65 before any signed `1.0 (3)` candidate was built. [PR #66](https://github.com/jacklv-coder/OrchardProbe/pull/66) merged the closure and 3D transition as `e973f6057f5d03e3bab4f5857fdb47ed7699574a` |
| 3D | Exact signed DemoLab `1.0 (3)` candidate | `active; post-export fix in review` | The first-party App IDs and dedicated App Group are privately configured and an independent temporary signing preflight passed. The first controlled Archive reached signed Archive/export, then failed closed before oracle publication because the post-export helper reselected XcodeGen from the intentionally Xcode-only PATH. No candidate run was published and no upload, installation, or device observation occurred. Merge the absolute-identity XcodeGen recheck fix, then create fresh 3A inputs from the new live-`main` commit and rerun the exact candidate |
| 3E | Sanitized completion record | `blocked` | Independently rehash and verify the local candidate, manifest, oracle, and evidence bindings; record only non-secret hashes/toolchain/build facts in Issue #55 and bilingual docs, run final Codex CR/CI/review, and merge the checkpoint-3 result |

### 3D ordered execution gates

| Order | Gate | Status | Completion criterion |
|---:|---|---|---|
| 3D.1 | First-party signing capability | `complete locally` | A dedicated App Group is assigned to the existing first-party main App ID and Share Extension App ID; Xcode regenerated the affected profiles and a disposable signed Release preflight passed without retaining the product or publishing private identifiers |
| 3D.2 | Post-export pinned-XcodeGen recheck | `in implementation` | Capture the allowlisted absolute XcodeGen path/version/file identity before entering the pinned Xcode environment, revalidate that exact file without consulting the Xcode-only PATH while producing the oracle, restore the caller PATH, then repeat PATH-based verification before final publication |
| 3D.3 | Fresh exact candidate | `blocked by 3D.2 merge` | From the clean merged fix commit, create a new source-bound 3A tuple and publish exactly one verified owner-only `1.0 (3)` Archive/IPA/oracle/evidence run; do not reuse the pre-fix tuple and do not upload, install, or observe a device |

The failed pre-fix run is not a candidate: the Archive and export completed, but
the closed oracle/evidence publication did not. Its unpublished staging was
removed by the reviewed rollback path. The source-bound pre-build inputs remain
private historical diagnostics and cannot be reused after the fix changes
`main`.

### 3B ordered implementation slices

| Order | Slice | Status | Completion gate |
|---:|---|---|---|
| 3B.1 | Secure 3A consumption | `complete; PR #63 merged` | The archive lane derives the one expected pre-build directory from the locked output root and authenticated `source/version/build` tuple. The reviewed helper descriptor-relatively reads exactly the three mode-`0400` owner files, rederives the non-weak key, canonical manifest, Build Binding, three target bindings, target-identity set, and pinned toolchain, and returns only a bounded private IPC envelope. Fastlane injects the closed values without caller-supplied nonce, public-key, or Build-Binding variables. Device-free regressions, Codex CR, GitHub Codex review, and CI passed; [PR #63](https://github.com/jacklv-coder/OrchardProbe/pull/63) merged as `8d623d8e2391e4e110ff222c87fa3fc25aa2a23c` |
| 3B.2 | Archive/IPA oracle closure | `complete; PR #64 merged` | The helper and Fastlane hold and revalidate the final Archive App, IPA, all six Archive sources, oracle, and evidence across publication; signed special slots, zero-fill rules, per-entry IPA mutation, replacement, and indeterminate publication regressions passed Codex CR and all required CI. [PR #64](https://github.com/jacklv-coder/OrchardProbe/pull/64) merged as `5bf31bf305e30abb0121a0bcb76e5fcdf48eb3bc` |
| 3B.3 | Evidence and upload gate | `complete; PR #65 merged` | The manifest/oracle identities and external oracle SHA-256 are bound into pre-upload evidence; the upload lane rejects an absent, changed, or inconsistent closed tuple. [PR #65](https://github.com/jacklv-coder/OrchardProbe/pull/65) merged as `ca19db07a8badc5d7ce55cc556ab9205181056a5` |

### 3B.3 ordered execution gates

| Order | Gate | Status | Completion criterion |
|---:|---|---|---|
| 3B.3.1 | Closed Evidence binding | `complete` | Persist the exact owner-only manifest and oracle file identities, external oracle SHA-256, Build Binding, Target Identity Set, and IPA size/SHA-256 in the pre-upload record while the prebuild directory remains locked |
| 3B.3.2 | Upload-time private tuple verification | `complete` | Derive only the fixed sibling prebuild/run directories from the evidence source/version/build, pass their held descriptors to the reviewed helper, and reparse canonical Manifest, Prebuild, and Oracle artifacts before upload |
| 3B.3.3 | Fail-closed regressions | `complete` | Missing LAB-002 binding, changed manifest/oracle identity or digest, inconsistent Build Binding/Target Set/IPA tuple, noncanonical private artifacts, unsafe permissions, directory substitution, extra/missing run entries, and strictly bound reconciled-retry audit records are covered without any network action |
| 3B.3.4 | Documentation, Codex CR, CI, and merge | `complete; PR #65 merged` | Bilingual operator/technical documentation, workspace/Fastlane checks, reproducible Helper verification, two final Codex CR passes, and all required CI completed with no unresolved P1/P2 before merge |

The 3B.3 helper was independently built twice from the read-only source
snapshot at implementation commit
`da758e963e8516cbb38f04e7c7786a041b6a4d9d`; both products were
byte-identical. The registered tuple is Rust
`1.85.0-aarch64-apple-darwin`, source snapshot SHA-256
`4e59c359dcfa514ebfe1d22fcfa403f24b75fb2fb072aa46b12b339e2ea94116`,
size `2019584`, SHA-256
`d150dd40834f0578024e7949d4a736eae3dbc9078264850714af49e70a3ccb55`,
and CDHash `0382cc8dd78c61d6b0116f34f8ec81bb2002f7ed`.

### 3B.2 ordered execution gates

| Order | Gate | Status | Completion criterion |
|---:|---|---|---|
| 3B.2.1 | Closed measurement contract | `complete` | Reuse the accepted LAB-002 canonical oracle model and fixed three-role order; derive every executable path from the held Archive/IPA roots, enforce bounded regular-file reads, and reject unknown roles, slices, ranges, load commands, or fixup layouts |
| 3B.2.2 | Archive/IPA parity | `complete` | Independently parse each fixed Archive/IPA `Info.plist`; require its bundle/version/executable tuple plus every architecture, CPU subtype, Mach-O UUID, trusted CMS/CodeDirectory identity, slice extent, `__TEXT,__oprobe` coordinate/content, and accepted fixup layout to agree; no role or slice may be skipped |
| 3B.2.3 | Canonical private publication | `complete` | Encode one canonical oracle bound to the authenticated source/version/build, 3A manifest and Build Binding, then exclusively and durably publish it with mode `0400` beneath the identity-held owner-only run directory without printing its content |
| 3B.2.4 | Device-free closure tests | `complete; PR #64 merged` | Synthetic fixture tests cover parity success plus target, slice, UUID, range, fixup, signed-special-slot, plaintext, canonicalization, permission, substitution, per-entry IPA mutation, and atomic-publication failures; documentation, Codex CR, and all required CI passed before 3B.3 started |

The final P1/P2-fixed 3B.2 helper was independently built twice from the
read-only source snapshot at commit
`7db46b22e409ec635b015091f1eff0b3e6f8287a`; both products were
byte-identical. The registered tuple is Rust `1.85.0-aarch64-apple-darwin`, source
snapshot SHA-256
`ac687ac04a25cad4d57dc7de6f503081e4ee038cf55f7eb1a1924cf44bdeffbf`,
size `1884528`, SHA-256
`d4f2b1c089371d91eda6363e9df9c9efcd0ed284305b948db4dca20a7883d971`,
and CDHash `cadae3e5ba93f22c82aa811d7fb35c15dae16696`. This helper verifies every
present signed CodeDirectory special slot before accepting signing metadata and returns
the device/inode of the still-held final Archive App root, allowing Fastlane to
bind final evidence and publication validation to the exact helper-measured
directory rather than a replaceable pathname.

## 3C closure evidence

- PRs [#62](https://github.com/jacklv-coder/OrchardProbe/pull/62),
  [#63](https://github.com/jacklv-coder/OrchardProbe/pull/63),
  [#64](https://github.com/jacklv-coder/OrchardProbe/pull/64), and
  [#65](https://github.com/jacklv-coder/OrchardProbe/pull/65) merged the complete
  reviewed implementation in dependency order before any signed `1.0 (3)`
  candidate was built.
- The final local gate passed `cargo test --workspace --all-targets --locked`,
  workspace Clippy with warnings denied, all 36 `oprobe-lab002` helper tests,
  Fastfile syntax, `fastlane ios demolab_check`, and `git diff --check`.
- The final Codex CR found no actionable defect after earlier P1/P2 findings
  were fixed. PR #65 then passed Repository quality, Rust Test and lint, and
  the complete DemoLab Simulator fixture workflow with no review threads.
- Every 3C run remained device-free and used only repository-owned or synthetic
  inputs. No signed Archive, TestFlight upload, installation, connected-device
  observation, or Apple upload request occurred.

## Fixed safety boundaries

- Only the repository-owned DemoLab app, DemoFramework, and
  DemoShareExtension are in scope.
- The authorization private seed, identity nonce, private target identifiers,
  App Group, signing identities, Archive, IPA, and full oracle remain outside
  Git, issues, PRs, chat, and CI logs.
- The generator and archive lanes accept no caller-selected executable path,
  process, address, range, or inventory expansion.
- `1.0 (3)` is the only authorized signed tuple for this checkpoint. A source,
  toolchain, version, build, manifest, or signing-tuple change requires a new
  authorization and a fresh run directory.
- Checkpoint 3 completion proves only that an independently frozen local
  candidate/oracle pair exists. It does not prove installed protection,
  mapped plaintext, decryption, IPA reconstruction, or device support.

## 3A implementation boundary

The public implementation adds no `oprobe` user command. The internal
`oprobe-lab002` executable is built into a private temporary directory and is
invoked only by Fastlane. Its prepare operation accepts the fixed three-role
request on standard input and emits only a non-secret result envelope; private
target identifiers are never command-line arguments or result fields.

The published pre-build directory contains exactly:

- `lab-002-authorization-seed-v1.bin`: the raw 32-byte Ed25519 seed, mode
  `0400`;
- `lab-002-authorized-targets-v1.json`: the canonical private authorization
  manifest, mode `0400`; and
- `lab-002-prebuild-v1.json`: the canonical build/toolchain/binding record,
  mode `0400`.

The directory is created under an already-existing canonical mode-`0700`
output root outside the repository. The lane rejects a clean local commit that
is not an ancestor of the live GitHub `main` OID and rechecks the same source
immediately before generation. It obtains that OID with `git ls-remote` from a
hard-coded SSH repository URL while running outside the checkout, excluding
local, global, and system Git configuration, disabling prompts and SSH agent
use, and authenticating `ssh.github.com:443` against the GitHub Ed25519 host
key pinned in the reviewed source. SSH reads no user-controlled known-hosts
path: its `KnownHostsCommand` invokes the fixed, root-owned `/bin/echo` to emit
that in-source key, and both `/bin/echo` and `/usr/bin/ssh` are content- and
identity-revalidated after use. A mutable local remote-tracking ref is never
used as review evidence. Through that same restricted transport, a quiet fetch
materializes the advertised `main` history without writing `FETCH_HEAD` or a
local ref; a second live query must return the same OID, and that exact commit
object must then exist locally. The ancestry check and subsequent Git operations
explicitly disable replacement refs. The lane compiles the helper from a read-only Git archive
of that exact 40-hex commit in a separate private workspace, and the extracted
path/Blob OID inventory must exactly match
`git ls-tree`; external attribute transformations are rejected. Archive stdout
is piped directly to the extractor without a pathname-based intermediate
archive, and both process statuses are required to succeed. The
build does not read the mutable checkout and rehashes the complete source
snapshot afterward. Fastlane records and retains the reviewed source root
device/inode, forks the build child, and uses Darwin `fchdir(2)` to enter that
held directory before executing sandboxed Cargo; the source pathname must map
to the same identity before and after the build. The `gemfile_lock_sha256`
recorded in the Build Binding is
derived from that same authenticated snapshot and is revalidated with it; the
lane never hashes the mutable worktree `Gemfile.lock`. The helper build never
consumes the mutable extracted tree under Cargo's `registry/src`: it resolves
the operator's configured `CARGO_HOME` (falling back to the account default
only when it is unset), then authenticates every cached `.crate` archive
against the checksum recorded in the snapshotted
`Cargo.lock`, hashes the exact compressed bytes consumed by Gzip/Tar while
extracting only through held directory descriptors into an owner-private,
read-only temporary directory outside the build's writable workspace,
configures a fresh isolated `CARGO_HOME` to use only that directory, and
rehashes both each held archive and the complete dependency tree. Fastlane
also retains the verified vendor-root and Rust-toolchain directory
descriptors and requires their path identities to remain unchanged through
the build. Because a hostile same-UID process could still replace and restore
one of those path-based inputs between the before/after checks, the build is
made reproducible with fixed archive timestamps and remapped source, vendor,
and toolchain roots. Before any authorization seed is generated, the final
Mach-O must exactly match an independently reviewed
`source snapshot SHA-256 + Rust toolchain` allowlist entry containing its
size, complete SHA-256, and SHA-256 CodeDirectory CDHash. A transient
toolchain or vendor substitution therefore cannot publish an arbitrary helper
and then hide by restoring the reviewed tree; any changed product is rejected.
Changing the helper source or supported toolchain requires a newly reviewed
product tuple. The
temporary verified source has its directory permissions restored solely for
checked cleanup after the build. Cargo,
build scripts, and procedural macros run with an empty isolated `HOME` inside a
macOS sandbox that denies network access, denies reads of the operator home
except the reviewed source snapshot and pinned Rust toolchain, and denies
writes outside the private build workspace. Run `cargo fetch --locked` before
the lane if an authenticated archive is absent.
The XcodeGen path, version, device/inode, size, modification time, and SHA-256
used in the Build Binding are retained as one selection and reselected,
rehash-verified, and compared again after generation immediately before the
pre-build result returns.

The generator opens and retains directory descriptors for the output root and
its unique staging directory. Fastlane duplicates its already-locked
output-root descriptor into the helper and passes the expected device/inode;
the helper verifies that inherited descriptor and uses it directly, so it
never reopens a replaceable output-root pathname for publication. File
creation, directory sync, no-replace rename, rollback, and cleanup are
descriptor-relative with no-follow semantics; the reported output path is
revalidated against the held output-root identity. Fastlane retains its own
locked output-root descriptor across the helper call and descriptor-relatively
removes the exact published tuple if any subsequent result or root
revalidation fails. Before writing any private bytes, the helper
reports the unique staging name and its device/inode identity in a flushed
non-secret first-line record. Fastlane arms rollback from that record before
acknowledging the helper over a dedicated inherited pipe; the helper cannot
write private bytes until that acknowledgement arrives. Before sending the
request and again before that acknowledgement, Fastlane binds the running PID
to the verified Helper: system `lsof` must report the expected executable
device/inode, and Darwin `csops` must report the SHA-256 CodeDirectory CDHash
parsed from the held, fully hashed Mach-O. A pathname replacement therefore
cannot impersonate the reviewed Helper by restoring the original path.
Fastlane then removes
the identity-matching staging or final entry on any later failure, including an
interrupted helper, malformed result, or operator `Ctrl-C`; an `Interrupt`
continues to propagate after rollback. Before reporting success, the helper
reopens the final descriptor-relative entry and requires it to retain the
staging device/inode. After parsing the helper result, Fastlane independently
reopens the final entry from its held output-root descriptor and repeats that
identity check immediately before success. The helper result also binds each
of the three fixed private artifact names to its device/inode, mode, size, and
SHA-256 after publication. Fastlane validates that closed inventory, requires
the manifest file digest to match the reported manifest digest, and
descriptor-relatively reopens, rehashes, and identity-checks every artifact
before reopening the final directory one last time. Before, during, and after
those hashes, a forked child enters the already-held directory with
`fchdir(2)` and enumerates it; the entry set must equal exactly the three fixed
artifact names, so an added fourth entry fails closed. Any file mutation or
replacement fails the final check and invokes the already-armed,
identity-scoped rollback. Rollback refuses to touch a
substituted directory. If the armed identity disappears from both its staging
and final names, rollback reports the private state as indeterminate instead
of claiming cleanup. Every fixed artifact unlink must succeed, directory
removal must succeed, and the held directory descriptor is queried afterward
to prove that its inode was not concurrently renamed and left reachable.
Missing or renamed artifact entries, a post-open directory rename, or a
remaining/replaced descriptor path therefore makes rollback indeterminate
rather than successful; the lane will not silently retry that tuple.
Files use exclusive creation and `fsync`, and the parent directory is fsynced
after publication or cleanup. Reusing the same source/version/build tuple is
rejected instead of overwriting its private inputs. This lane performs no
signing, Archive/export, upload, installation, or device operation.

## 3B.1 implementation boundary

The archive lane no longer accepts `DEMO_LAB_BUILD_BINDING_SHA256`,
`DEMO_LAB_IDENTITY_NONCE`, or `DEMO_LAB_AUTHORIZATION_PUBLIC_KEY` from the
shell. It authenticates the live GitHub `main` source commit, fixes the
checkpoint to DemoLab `1.0 (3)`, and derives the exact 3A directory name below
the already locked private output root. Both the root and the derived
pre-build directory remain open and exclusively locked while the private
helper runs.

The helper's `inspect-prebuild` operation receives the held pre-build
directory on a fixed inherited descriptor plus its expected device/inode. It
enumerates that descriptor and accepts exactly the seed, manifest, and
pre-build record. Each entry is opened descriptor-relatively with no-follow
and nonblocking semantics, must be a nonempty owner-owned regular file with
mode `0400` and a fixed size bound, and is identity- and timestamp-checked
across each read. The helper derives the Ed25519 public key and key ID from the
seed; rejects weak keys; parses the manifest and record as exact canonical
artifacts; and recomputes the manifest hash, Build Binding, all three
role-specific target bindings, and target-identity-set hash against the
archive lane's expected source, version, build, configuration, observer,
toolchain, and three-role authorization request. It then repeats the exact
directory inventory, byte/identity reads, and held-path identity check before
returning.

The result is a bounded private standard-output IPC envelope consumed only by
Fastlane; it is not printed. Fastlane requires its exact schema and fields,
checks the held directory identity, source/version/build/toolchain, every
64-hex binding, and the non-weak public key, then revalidates the reviewed
helper, selected Xcode/XcodeGen, and held directory. Only those closed values
are injected into the repository-owned build. PRs #64 and #65 subsequently
closed the Archive/IPA oracle and upload-time evidence gates; this earlier
3B.1 boundary alone still makes neither claim.

## 3B.2 implementation boundary

The same `ios demolab_archive` lane now invokes the reviewed private helper
after export; the operator does not manually copy an Archive, unpack an IPA,
or upload an oracle. Fastlane passes held Archive and run-directory
descriptors on fixed inherited file descriptors, while the helper opens the
exported IPA from the held staging root, validates the exact bounded ZIP
inventory, and copies it into an owner-only private workspace before
measurement. It recursively enumerates the held Archive app before
measurement, accepts exactly the three allowlisted executable paths, and
retains the six enumerated executable/Info.plist descriptors used for
measurement. The final closure performs an exact executable inventory, reopens
and rehashes every retained path against its held identity and digest, then
performs the exact inventory again. A replacement between either inventory and
the path checks, or a newly introduced executable after the path checks,
therefore fails closed. The helper also rehashes the complete held IPA after
every entry read and requires that digest to equal the one captured before
parsing.

For each of the fixed main-app, framework, and share-extension roles, the
helper requires the exact Archive and IPA executable paths and every Mach-O
slice to agree on architecture, CPU subtype, UUID, slice extent, signing
identity, fixed-range coordinates and bytes, encryption state, and a
domain-separated digest of the accepted classic or chained-fixup layout.
It separately parses both fixed bundle `Info.plist` files and binds their
bundle identifier, version/build, and executable name instead of borrowing
those values from the authorization request. The closed CodeDirectory parser
requires indexed blobs to consume the declared SuperBlob exactly, rejects
scatter tables, accepts only complete SHA-256 page coverage, and checks the
signed entitlements special slot. Xcode's unsigned Simulator fixture may carry
the exact `0x20400` ad-hoc/linker-signed CodeDirectory profile with no team,
entitlements, or CMS slots; the parser accepts only that exact omission and
still requires the closed identifier grammar. It remains classified ad hoc and
therefore cannot pass the signed Archive/IPA oracle path. Before CMS
verification, selected
entitlements are read through a bounded XML/binary event stream with explicit
event, depth, collection, key, and cumulative scalar-byte budgets. Binary
inputs additionally receive a pre-allocation trailer, object-count, offset,
scalar-extent, reference, and collection-length preflight before the library
reader can construct reference vectors; duplicate root keys and oversized
unknown structures fail closed. The helper then verifies the
detached CMS over that exact CodeDirectory, requires its signer to pass
macOS's local `codeSign` trust policy using the bounded embedded certificate
chain plus the explicit root-owned Apple system-root keychain while disabling
the default/user keychain search list, and requires the signer-certificate
Team ID to equal the signed CodeDirectory Team ID. Unknown load commands,
mixed classic/chained fixups, omitted or extra executables, malformed or
untrusted signatures, range drift, or any byte mismatch fail closed.
Classic rebase and ordinary/weak-bind streams must contain a terminal DONE
opcode followed only by linker zero padding; lazy-bind streams instead accept
their required sequence of individually DONE-terminated records and still
reject a final unterminated record.

Immediately before publication, the helper reopens the fixed Archive app and
IPA from the current held run-directory path. It requires the Archive app
directory to retain its original device/inode, repeats the exact executable
inventory plus all six retained-file identity/digest checks from that reopened
root, and requires two current IPA opens to retain the original identity,
complete digest, and validated ZIP inventory. A renamed/replaced Archive app
or IPA therefore cannot make the oracle describe stale descriptors while the
following evidence step reads different current paths.

The helper returns the final IPA size/digest, the ordered size/digest tuple for
all six retained Archive files, and the device/inode of the still-held Archive
App directory from which those measurements were closed. Fastlane
independently binds that exact directory and snapshots the same three Mach-O
files and three Info.plists immediately before writing pre-upload evidence,
requiring an exact match. The evidence boundary therefore rejects a source or
Archive-root replacement both before and after helper publication instead of
trusting a pathname handoff.

The outer lane keeps Gym logs, result bundles, dSYM ZIPs, and other export
auxiliaries in a disposable private scratch directory and moves only the
returned IPA into final staging. The final publisher requires the top-level
inventory to contain exactly the Archive, IPA, oracle, and evidence; it then
keeps read-only descriptors open for the oracle-bound Archive App, IPA, all six
Archive sources, oracle, and serialized evidence. The same function repeats
their complete digests and current path identities, performs the exclusive
staging-directory rename, and revalidates every held descriptor through its
new published path before returning success. Device-free regressions publish a
valid fixture and reject replacements of the IPA, an Archive source, the whole
Archive App root, oracle, or evidence plus an injected top-level entry. They
also require an owner-only
`.demolab-staging-published-indeterminate-*.json` sibling gate containing the
expected published device/inode to be reserved before the directory rename,
reject publication if that exclusive reservation fails, and remove the gate
only after every post-rename descriptor check passes. Replacing the IPA after
the rename therefore retains the gate. Because the existing retained-staging
scan recognizes it, a failed final validation has an explicit reconciliation
path and cannot silently strand an unverified final run.

Only after all three roles pass does the helper encode the canonical
`orchardprobe.lab002.oracle.v1` record, bind it to the authenticated source,
version/build, authorization-manifest digest, target-identity set, and Build
Binding, and publish it atomically with mode `0400` below the locked private
run directory. The full oracle and its target identifiers remain outside
Git and logs. Publication retains the staging descriptor and exact
device/inode returned by the same metadata read that validates the file.
Because Darwin has no identity-bound unlink-by-descriptor primitive, any
failure after staging creation performs no pathname deletion. The helper
syncs the locked directory, reports publication as indeterminate, and retains
the owner-only staging or published state for explicit reconciliation before
retry. Fastlane arms outer staging retention immediately before attempting to
spawn the oracle helper and keeps it armed through result, oracle identity,
helper, toolchain, XcodeGen, and evidence validation. It disarms only after
the staging directory is atomically published as the final run. The helper's fixed
indeterminate marker adds the retained-path diagnostic, but spawn failure,
markerless termination, panic, broken output, malformed results, and any
downstream pre-publication failure retain the staging tree. Every later archive attempt enumerates
the held output directory before creating new staging and refuses to proceed
while any retained `.demolab-staging-*` entry remains, so retry requires
explicit operator reconciliation rather than silently accumulating private
artifacts. This deliberately preserves both the expected bytes and any
concurrently substituted name instead of risking deletion of an unrelated
same-user file. This implementation does not upload to TestFlight, inspect a
device, reconstruct an IPA, or provide the future one-file end-user decryption
command. PR #65 now binds the oracle and authorization manifest into pre-upload
evidence; the upload lane revalidates that exact closed tuple and rejects any
absent or mismatched binding before Apple network access.
