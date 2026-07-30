# LAB-002 device implementation contract

Status: **checkpoint 2C branch-local contract**

This document freezes the internal DemoLab boundary before the device-side
implementation is added. It is subordinate to the reviewed
[LAB-002 oracle design](lab-002-oracle-design.md). A conflict is resolved in
favor of that design and fails the implementation gate.

Nothing here authorizes a signed archive, TestFlight upload, installation, or
physical-device observation. Checkpoint 2C implementation and testing must use
temporary containers, synthetic keys, and unsigned Simulator builds until its
device-free gate is complete.

## Public capability boundary

DemoLab exposes only these user actions:

| Action | Input | Effect |
|---|---|---|
| Import LAB-002 authorization | One URL supplied by the system document picker | Copies at most one closed, canonical enrollment or run envelope into the fixed inbox |
| Confirm installation enrollment | None | Consumes one valid installation envelope and creates the fixed enrollment state exactly once |
| Start clean LAB-002 run | None | Consumes one valid run envelope, commits its exact next counter, and starts the fixed three-role session |
| Discard stale LAB-002 authorization | None | Removes only a fixed inbox record proven malformed, expired, or build-mismatched |
| Export LAB-002 evidence | None | Constructs one fixed signed four-document export and presents the system share sheet |
| Confirm export received and clean reports | One explicit Boolean UI confirmation | Rehashes the constructed export and removes only its matching completed report subtree |

The document-picker URL exists only at the import boundary. It is never stored
in a report, forwarded to an observer, accepted by Host/Core, or reused after
the bounded copy. No other production initializer or method accepts a URL,
path, file descriptor, bundle, image header, target, role, range, PID, process,
address, or logical filename.

The three observation entries are closed and zero-argument:

```text
Main app        observeCurrentMainExecutable()
DemoFramework   observeCurrentFrameworkImage()
Share extension observeCurrentShareExecutable()
```

Each entry resolves its own bundle, executable, compiled anchor, role, and
`__TEXT,__oprobe` range. The framework entry may be visible to the embedding
app, but it has no selectable input. Parser helpers and report builders remain
target-private.

There is no OrchardProbe CLI, Core, Host, Fastlane, or device-helper API for
resolving, listing, reading, writing, importing, exporting, or cleaning the App
Group container.

## Target-private Mach-O observer core

Checkpoint 2C.4b implements one source-level core that is compiled separately
into each consuming target. Production construction remains private so the
2C.4c zero-argument role entry is the only future path that may supply its
fixed bundle executable and compiled anchor. URL and mapped-header injection
exist only in the Debug test harness.

The installed-file reader opens the fixed executable read-only with
`O_NOFOLLOW`, requires a linked regular file no larger than 100 MiB, reads
exact ranges with `pread`, and rechecks descriptor identity, mode, link count,
size, modification time, and change time after parsing. The parser then:

1. accepts one thin, FAT32, or FAT64 container with at most four non-overlapping
   aligned slices;
2. bounds load-command count/bytes and every fixup payload;
3. binds FAT and Mach-O CPU identity, file type, UUID, slice ordinal, and
   checked file/VM coordinates;
4. requires exactly one executable regular pure-instruction
   `__TEXT,__oprobe` section of 64–1,024 bytes with no section relocation;
5. rejects overlapping sections/segments and classic or chained fixups that
   target executable `__TEXT`;
6. normalizes the single architecture-correct encryption command from
   slice-relative to absolute file coordinates and records exact coverage; and
7. reparses the bounded mapped header and requires its CPU identity, UUID,
   fixed coordinates, and compiled-anchor containment to match the installed
   slice before returning a mapped range.

The core returns only closed evidence structures and closed reason codes. It
does not perform oracle comparison, signing-identity validation, mapped-memory
hashing, or report publication; those remain ordered work in 2C.4c.

### Zero-argument local role assembly

Checkpoint 2C.4c1 compiles the same reviewed core separately into the app,
framework, and extension, then exposes only the three fixed zero-argument
entries. Each entry supplies its own fixed `Bundle` and compiled assembly
anchor internally. `dladdr` must bind that anchor to the same executable path
resolved by the fixed bundle before disk inspection starts.

The active 64-bit mapped header is bounded to 4,096 commands and 4 MiB, matched
to exactly one installed slice by CPU type/subtype, UUID, fixed coordinates,
and anchor containment. Both the mapped header and fixed section must be wholly
contained in one readable executable VM region before bytes are copied and
hashed. Disk inspection time precedes mapped-hash time.

The installed slice also parses one bounded embedded code-signature SuperBlob:
its primary CodeDirectory layout, identifier, team identifier, selected XML
entitlements, CMS/ad-hoc/unknown kind, and complete SuperBlob SHA-256. The
compiled 32-byte identity nonce and fixed role are framed with those selected
identity values using the same target-identity domain as Core. iOS exposes no
public `SecStaticCode` validation surface, so this parser deliberately records
`not_checked`; launch success, a CMS-shaped slot, identifiers, or a digest
never become `valid`. Consequently the future report is No-Go unless a
separately reviewed validator can supply real validation.

### Canonical fixed-role publication

Checkpoint 2C.4c2 makes each zero-argument entry close its local observation
into the exact `orchardprobe.lab002.role-report.v1` JSON shape. The report
copies every run/build/environment binding from the canonical immutable
`session.json`; compiled Bundle build binding, source commit, observer
revision, marketing version, and build number must match that session before
publication. Installed iOS executables must be thinned to the single loaded
slice so one observed mapped digest cannot be misrepresented as evidence for
an inactive FAT slice.

Publication opens only the compiled App Group and fixed
`lab-002-v1/reports/current` chain. After acquiring the shared coordinator
lock, it revalidates every directory and lock inode, rejects any unknown or
temporary entry, reparses the session and every preceding report canonically,
and requires nondecreasing phase times. The allowed pre-publication sets are
exactly session; session plus main; and session plus main plus framework.
Each 32 KiB role report is written to its fixed owner-only temporary name,
flushed, protected, excluded from backup, flushed again after metadata changes,
and renamed without replacement before the directory is flushed. Duplicate,
stale, conflicting, oversized, out-of-order, replaced, or malformed state
fails closed.

The device never receives the frozen plaintext oracle. The current bounded
signature parser deliberately emits `not_checked`, so these locally published
reports are `inconclusive` with
`signature_invalid_or_unchecked`; they are not plaintext or successful
signature claims. Exact oracle comparison remains Host work after export.

### Closed run wiring and completion

Checkpoint 2C.4d connects the lifecycle without adding a selector. After Start
has durably committed the counter and immutable collecting session, and after
the coordinator lock is released, one fixed production runner invokes the
main-app observer followed by the framework observer. A failure leaves the
already-consumed run as incomplete evidence; Start cannot silently retry it.
The Share Extension invokes only its own zero-argument observer when its fixed
view loads and reports that no valid collecting session exists when publication
fails.

The main app has one internal zero-argument completion operation for the later
2C.5 UI. It reopens the compiled App Group, takes the same coordinator lock,
revalidates the descriptor chain, and requires the directory to contain exactly
the collecting session plus the three canonical role reports. It reparses and
binds every report in main/framework/share order, requires nondecreasing phase
times no later than the session's persisted signed
`authorization_not_after + 120` absolute deadline, retains each validated
report identity and canonical byte string, and revalidates the collecting
session plus all three reports by identity and exact canonical bytes
immediately before replacement. It revalidates the completed session and all
three reports the same way after replacement. It then replaces only
`session.json` with a
canonical `complete` record using an owner-only temporary file, data and
metadata flushes, no-follow atomic replacement, and a directory flush. The
rename is the explicit commit point: all failures before it throw without
claiming completion; a directory-flush or identity-check failure after it
returns `committedDurabilityUncertain` instead of a retryable error. Missing,
repeated, completed, temporary, late, replaced, or conflicting pre-commit state
is unchanged and fails closed.

### Signed receipt, export, and cleanup

Checkpoint 2C.5 closes both device-signed egress artifacts under the frozen
Host/Core schemas. Confirm Enrollment first requires the verified
authorization to contain the exact acknowledgement digest, policy, challenge,
experiment, device-selection nonce, and expected environment. The runtime
environment must match before the installation state is created. Receipt
creation also requires the runtime clock to be inside the signed inclusive
`not_before` through `not_after` interval itself: the wider device-ingress
clock-skew tolerance cannot produce a receipt that the Host would reject. The
resulting canonical enrollment-receipt core is framed as the frozen receipt
domain, 4-byte big-endian length, and exact core bytes, then signed by the
device-only Ed25519 enrollment key. The returned full 64-hex device-selection
fingerprint binds the authorization-envelope digest, enrollment public key,
installation binding, and device-selection nonce. The fixed authorization is
deleted only after the receipt has been constructed successfully.

Export first obtains an exact completed snapshot under the coordinator lock; a
collecting session may be completed once, but malformed or conflicting state
cannot be converted into exportable evidence. The snapshot contains exactly
`session.json`, `main-app.json`, `framework.json`, and
`share-extension.json` in that order. Each entry retains its exact canonical
document and SHA-256. The canonical export core is framed with its distinct
frozen export domain and signed by the same enrollment key. Both signed
artifacts have fixed `.json` names and are held in memory behind an
`NSItemProvider`; production egress is a system `UIActivityViewController`, not
an arbitrary output URL, filesystem path, network request, pasteboard, or
caller-supplied filename.

The actor retains the first constructed export and returns identical bytes on
repeat presentation within that coordinator lifetime. A new coordinator must
not reconstruct an export from a session already marked complete: termination
after completion but before confirmed receipt is therefore a fail-closed
No-Go, not an opportunity to produce different signed bytes. Cleanup requires
a separate explicit `true` confirmation, the retained export, and two fresh
exact completed-snapshot validations under the same lock. It unlinks only the
four fixed report files, flushes that directory, removes only the empty
`reports/current` directory, and flushes `reports`. The first successful unlink
is the cleanup commit point; a later unlink, flush, identity check, or
directory removal failure returns `cleanedDurabilityUncertain` and cannot be
retried as if nothing happened. Enrollment key/state, installation nonce, run
counter, inbox, root, and coordinator lock are never cleanup targets. A crash,
partial receipt, signature mismatch, missing required export, or uncertain
cleanup makes that exact controlled experiment No-Go; cleanup cannot reset it
into a passing retry.

## Fixed production container

Production code obtains the container only from
`containerURL(forSecurityApplicationGroupIdentifier:)`. The checked-in
Simulator identifier is generic; a controlled signed build supplies its
registered first-party identifier without committing it.

Every component below is a literal compiled string:

```text
lab-002-v1/
  coordinator.lock
  inbox/
    authorization-v1.json
    authorization-quarantine-v1.json
  state/
    installation-nonce-v1.json
    run-counter-v1.json
  reports/
    current/
      session.json
      main-app.json
      framework.json
      share-extension.json
```

No production code accepts or joins a caller-provided path component. Logical
export names are the four literal report names and are not filesystem paths.
The enrollment key is not a file: it uses one fixed Keychain service/account/
access-group tuple.

`coordinator.lock`, `inbox`, and `state` survive report cleanup.
`installation-nonce-v1.json`, `run-counter-v1.json`, and the enrollment key are
removed only by app deletion or a separately reviewed experiment teardown;
normal Start, Export, Discard, and Cleanup cannot reset them.

## Serialized state transitions

All main-app Import, Confirm Enrollment, Start, Discard, Export, and Cleanup
operations pass through one serialized coordinator. Every inbox-changing
operation holds the exclusive coordinator lock.

### Inbox

```text
absent --Import valid/exclusive--> imported
imported --identity-checked rename--> quarantined
quarantined --valid Confirm/Start--> consumed
quarantined --proven stale/malformed/build-mismatch--> discarded
```

An unexpected quarantine, lock failure, non-regular file, symlink, entry/
descriptor identity mismatch, partial write, duplicate import, or crash residue
is a blocking failure. It is never repaired automatically. The sole narrow
exception is the explicit authenticated Enrollment resume below; it revalidates
the exact already-quarantined envelope and cannot be invoked by a run.

### Enrollment

```text
uninitialized --valid installation envelope--> creating
creating --explicit same-envelope authenticated resume--> creating
creating --key + nonce + receipt committed--> enrolled
creating --unrecognized/conflicting partial failure--> experiment failed
enrolled --every run--> read-only continuity check
```

Only the authenticated installation action may create the device-only key and
installation nonce. Run code cannot create, replace, repair, import, export, or
reset them. A missing/inaccessible key, missing/malformed nonce record, build
mismatch, or public-key mismatch fails before observation.

An interrupted Enrollment is resumable only while the same authorization
remains in the fixed quarantine. Explicit confirmation revalidates those exact
bytes and the current time/build. If the Keychain item exists but nonce state
does not, its stored build binding must match before state creation may finish.
If nonce state exists, the same-build key/public-key tuple must match before
the remaining Enrollment commit may finish. A fresh authorization cannot reuse
existing state, and no generic cleanup, run, or cross-build path can enter
either resume branch.

### Run

```text
idle
  --valid envelope + exact counter commit-->
collecting_main
  --> collecting_framework
  --> awaiting_share_extension
  --> complete_unexported
  --> export_constructed
  --explicit receipt confirmation + exact rehash-->
idle
```

The counter is durably incremented before `session.json` is created. The exact
validated authorization remains quarantined until both records are durable.
If interruption occurs after the counter commit or during atomic session
publication, only that already-quarantined authorization may resume the
matching transaction; a newly imported replay is restored and rejected.
Recovery accepts only the exact counter plus complete or staged canonical
session facts. Each role report is exclusively created once and never
overwritten. Missing, duplicate, out-of-order, expired, or conflicting state
makes the exact experiment fail; incomplete/failed evidence cannot be cleaned
and retried into a passing result.

## Storage invariants

The implementation must:

- open directories and files without following symlinks and require regular
  files where a regular file is expected;
- hold an owner-only exclusive advisory lock for every inbox transition;
- compare the opened descriptor identity with the directory entry before and
  after quarantine;
- use bounded full reads and exact canonical decoding before acting;
- create owner-only same-directory temporary files exclusively, fully write
  and flush them, publish without replacement, then fsync the directory;
- reject existing destination, temporary, quarantine, or unexpected entries;
- set complete file protection while locked and exclude state/reports from
  backup;
- never overwrite a role report, silently reset a counter, delete a current
  valid authorization, or clean an unexported/mismatched session.

Surface limits remain those in the reviewed schema contract: 16 KiB control
documents, 1 KiB fixed state records, 32 KiB role reports, 16 KiB session
reports, and 512 KiB signed exports.

## Production and test dependencies

Production assembly is fixed and internal:

- App Group locator: the one compiled group identifier;
- wall clock: whole-second system UTC;
- randomness: system cryptographic randomness, exactly 32 bytes where required;
- key store: one non-synchronizable
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` Ed25519 key;
- file store: the fixed container layout above;
- environment: sanitized hardware model and iOS product version/build;
- target observers: the three zero-argument compiled entries.

Tests may inject a temporary root, deterministic clock, deterministic random
source, and an in-memory synthetic signing key through internal protocols
visible only to the test target. Production app/extension initializers do not
expose those dependencies, and Release code has no environment-variable,
defaults, URL-scheme, pasteboard, network, command-line, or IPC override.

## 2C implementation gates

1. Fixed path and state types compile for the main app and extension.
2. The coordinator fails closed for duplicate, oversized, partial, symlinked,
   replaced, quarantined, locked, stale, and conflicting records.
3. Enrollment state proves device-only key/nonce/build continuity and cannot be
   created from a run path.
4. All three observers have zero selectable inputs and publish only one fixed
   role report.
5. Receipt/export signing uses the frozen domains and cleanup requires an exact
   completed-export match.
6. Simulator and synthetic tests never claim physical-device or plaintext
   evidence; their only successful conclusion is structural plumbing.
