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
| 3A | Private pre-build input generator | `planned` | Implement a local-only operator lane that creates a fresh raw Ed25519 seed, public key/key ID, identity nonce, canonical authorized-target manifest, and domain-separated Build Binding for exactly `1.0 (3)` from a clean merged commit and pinned toolchain; all private outputs are outside Git, owner-only, no-follow, fsynced, and atomically published |
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
