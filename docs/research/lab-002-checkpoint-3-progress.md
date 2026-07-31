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
| 3A | Private pre-build input generator | `implemented; PR #62 review/merge pending` | The local-only `ios demolab_prepare_lab002` lane builds the repository-internal `oprobe-lab002` helper from the pinned Rust toolchain and checksum-authenticated isolated Cargo sources, creates a fresh raw Ed25519 seed, public key/key ID, identity nonce, canonical authorized-target manifest, target-identity set, and domain-separated Build Binding from a clean commit already present in the authenticated live GitHub `main` history and a pinned build toolchain, then exclusively publishes the three private records outside Git with owner-only permissions and durability checks. Device-free unit/workspace tests pass; this row becomes complete only after [PR #62](https://github.com/jacklv-coder/OrchardProbe/pull/62) passes Codex CR/CI and merges |
| 3B | Archive/oracle/evidence closure | `blocked` | Make the hardened archive flow consume and revalidate the exact 3A artifacts, build only the three allowlisted roles, compare Archive and IPA slice identity plus `__TEXT,__oprobe`, publish the canonical frozen oracle, and bind its external SHA-256 into pre-upload evidence; the upload lane must reject absent or mismatched manifest/oracle evidence |
| 3C | Device-free tests, Codex CR, CI, and implementation merge | `blocked` | Use only temporary synthetic keys, unsigned Simulator products, and repository-owned fixtures; cover weak keys, malformed/private paths, symlink/race/permission failures, target drift, slice/range/fixup mismatch, canonicalization, atomic publication, and upload-gate rejection; merge the reviewed implementation before any signed candidate is built |
| 3D | Exact signed DemoLab `1.0 (3)` candidate | `blocked` | From the clean merged 3C commit, recover only validated first-party signing identifiers from private local configuration, create fresh 3A inputs, archive/export `1.0 (3)`, and freeze the 3B oracle/evidence in a new owner-only run directory; do not upload, install, or observe a device |
| 3E | Sanitized completion record | `blocked` | Independently rehash and verify the local candidate, manifest, oracle, and evidence bindings; record only non-secret hashes/toolchain/build facts in Issue #55 and bilingual docs, run final Codex CR/CI/review, and merge the checkpoint-3 result |

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
