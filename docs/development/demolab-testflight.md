# Controlled first-party DemoLab TestFlight runbook

This runbook prepares one project-owned DemoLab build for the `LAB-001`
protected-oracle experiment. It is maintainer research infrastructure, not the
future end-user workflow. A user who eventually runs
`oprobe decrypt <input.ipa>` must not need an Apple Developer account,
TestFlight, Fastlane, or this fixture.

The completed run did **not** establish that this TestFlight tuple provides a
usable protected oracle. It did not establish exact installed-artifact lineage,
expected plaintext ranges, a working device backend, extraction, decryption, or
IPA reconstruction. The bounded result is recorded in the
[LAB-001 research note](../research/lab-001-protected-oracle.md).

## Why this controlled build exists

The ordinary DemoLab CI product is an unsigned Simulator build. It can prove
that the source builds and that the app contains the expected main executable,
dynamic framework, and share extension. It cannot exercise an
Apple-processed installed artifact.

Apple documents that Xcode repackages archives for distribution and that
App Store/TestFlight delivery can apply app thinning and other processing.
Consequently, a pre-upload archive hash is only a candidate plaintext oracle;
it cannot by itself identify the exact bytes installed on a phone:

- [Distributing an app for beta testing and releases](https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases/)
- [Reducing an app's size](https://developer.apple.com/documentation/xcode/reducing-your-app-s-size)

## Fixed safety boundary

- Use only `fixtures/DemoLab`, its registered first-party identifiers, a
  maintainer-controlled Apple Developer team, and an owned test iPhone.
- Never substitute a commercial or third-party project, archive, IPA, icon,
  account, or device.
- Never commit or attach an IPA, archive, provisioning profile, certificate,
  API key, receipt, pairing record, stable device identifier, or raw private
  service log.
- The privileged lanes must be invoked manually from a clean, reviewed commit.
  They reject common CI-provider environments and also require an explicit
  local-run confirmation; they are not called by CI or by the `oprobe` CLI.
- The archive lane rejects inherited `GYM_*` variables so ambient Fastlane
  settings cannot redirect result bundles or change the controlled build.
- The upload lane accepts only an App Store Connect API key stored outside the
  repository. Evidence and key bytes are parsed from the same bounded,
  no-follow file descriptors whose owner, mode, inode, and path were validated;
  special-file key paths are opened nonblocking and rejected. The exact
  evidence-bound IPA bytes are copied to a locked, mode-`0400` `DemoLab.ipa`
  inside a random mode-`0700` workspace because Apple `altool` requires a
  `.ipa` filename. Its path, inode, descriptor access mode, size, and SHA-256
  are checked immediately before and after `altool`; the caller's IPA path is
  never passed to Apple. Key bytes remain in a separate anonymous, unlinked
  read-only descriptor. The lane does not accept an Apple ID password, patch
  TestFlight beta metadata, add tester groups, or
  distribute/notify external testers.
- Run signing and upload only in a trusted, dedicated local macOS login session.
  Directory locks and identity checks reject cooperating concurrent lanes and
  observable replacement, but a process already executing as the same macOS
  user can also access signing identities and is outside this maintainer-lane
  boundary. This does not weaken the future device collector's hostile-local-
  process requirements in RFC-0001.
- A successful build or upload remains `pending`, not `Go`.

The App Store Connect API key private key is downloaded once and must be
protected. Follow Apple's
[API key guidance](https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api).

## Public defaults and local identifiers

`fixtures/DemoLab/project.yml` retains generic public identifiers:

```text
com.example.orchardprobe.demolab
com.example.orchardprobe.demolab.framework
com.example.orchardprobe.demolab.share
```

The signed lane replaces them at build time. A contributor can therefore run
the Simulator fixture without knowing a maintainer's team or identifier.
Neither the maintainer team ID nor the registered identifiers are stored in
the Fastfile or generated evidence.

The main App ID and share-extension App ID must exist in the maintainer's
developer account. The framework is signed as embedded code and does not need
its own provisioning profile. App Store Connect needs only the main app
record.

## Install and verify Fastlane

The repository pins Fastlane 2.237.0 and Bundler 4.0.16 in `Gemfile.lock`.
Use Homebrew Ruby instead of the legacy system Ruby, install the locked bundle
inside the ignored `vendor/bundle` directory, and invoke Fastlane through that
bundle:

```sh
brew install ruby xcodegen
export PATH="$(brew --prefix ruby)/bin:$PATH"
gem install bundler -v 4.0.16
bundle _4.0.16_ config set --local path vendor/bundle
bundle _4.0.16_ install
bundle _4.0.16_ exec fastlane --version
bundle _4.0.16_ exec fastlane ios demolab_check
```

`demolab_check` copies only the tracked fixture sources to a temporary
directory, excluding ignored generated projects and `DerivedData`. It then
resolves the exact XcodeGen executable, requires it to be non-writable, and
checks its SHA-256 against the reviewed arm64 binary allowlist for XcodeGen
2.45.4 or 2.46.0. The verified bytes are copied through a stable read-only
source descriptor into a randomly named, owner-only executable inside the
private run workspace. The lane reopens that snapshot read-only, holds an
exclusive lock, executes only the snapshot, and checks its descriptor, path,
inode, size, mode, and SHA-256 before and after project generation. It also
revalidates the selected source executable afterward. A PATH wrapper that
merely prints an allowed version, or a pathname replacement between validation
and execution, is rejected. Dynamic-loader variables such as
`DYLD_INSERT_LIBRARIES` are removed from every controlled child environment, so
they cannot inject code into the allowlisted XcodeGen snapshot. The regression
lane launches a child Ruby process with a hostile loader override and requires
that the child observe it as absent. The lane then performs an unsigned Simulator
build, checks the expected products, and deletes the temporary directory. The
signed lane records the exact XcodeGen version in the pre-upload evidence so
the project-generation toolchain is auditable. Other architectures require a
separately reviewed binary hash before the signed workflow can run. The
Simulator build itself runs inside the same pinned Xcode environment described
below, so inherited developer-directory, SDK, toolchain, and xcconfig
overrides cannot change what the check verifies.

Apple developer tools are never selected from the caller's `PATH`. The lanes
read the system Xcode selection through `/usr/bin/xcode-select` with an
inherited `DEVELOPER_DIR` removed, require its developer directory and
`xcodebuild`, `dwarfdump`, `lipo`, and `otool` executables to be root-owned and
non-writable, and likewise pin `/usr/bin/xcrun` and `/usr/bin/plutil`. The
archive gives Gym the absolute `xcodebuild`, fixes
`DEVELOPER_DIR`, removes inherited SDK/toolchain/xcconfig selection, and uses a
minimal PATH whose first entry is the verified selected-Xcode toolchain
directory. This also pins Gym's bare `dwarfdump`/`lipo` calls during optional
dSYM and BCSymbolMap processing. Executable identities, hashes, Xcode version,
and iPhoneOS SDK version/build are captured before use and revalidated after
the archive and evidence passes. The regression lane prepends shadow
`xcodebuild`/`xcrun`/`plutil`/`dwarfdump`/`lipo`/`otool` files and proves none
can be selected.

Before the archive enters that minimal Xcode-only environment, it captures the
allowlisted XcodeGen absolute path, version, and file identity used to generate
the project. Oracle generation revalidates that exact non-writable executable
directly, without trying to discover XcodeGen through the deliberately reduced
`PATH`. After the caller's environment is restored, the lane repeats the normal
PATH-selected XcodeGen verification before it can publish the final candidate.
The regression lane proves that a missing version or mismatched file identity is
rejected even while the reduced environment is active.

The controlled App Store export explicitly sets `uploadSymbols` to `false`.
Current Xcode otherwise defaults that option to `true` and may add a top-level
`Symbols/` tree beside `Payload/`; LAB-002 deliberately keeps the IPA parser's
single-app-root boundary closed instead of broadening it for an export-only
sidecar. Gym still retains the Archive dSYM separately. After a normal helper
error, the verified helper uses the held directory descriptor to prove the
staging inventory is exactly Archive plus IPA with no oracle or temporary
oracle, syncs and revalidates the directory, and only then emits the exact
pre-publication cleanup marker that disarms retention. A crash, signal,
markerless failure, failed proof, or indeterminate-publication marker keeps the
private staging for reconciliation.

App Store export also re-signs the executable. Current Xcode can therefore
change only the trailing Code Signature/`__LINKEDIT` extent while preserving
the architecture, CPU subtype, Mach-O UUID, fixed-section coordinates and
bytes, fixup layout, encryption command, and authorized signing identity. The
oracle accepts a size difference only for one-slice thin Mach-O files when the
Archive and IPA have the same Code Signature start and each signature extent
ends exactly at its own slice EOF. It also hashes every byte before that shared
signature start after zeroing only the parsed `__LINKEDIT.filesize` and
`LC_CODE_SIGNATURE.datasize` fields. Those normalized prefix hashes must match;
an adjacent-byte or any other code/load-command difference therefore fails
closed even when both binaries are independently validly signed. The oracle
also normalizes that same parsed `__LINKEDIT.filesize` only when the parsed
Code Signature is contained in `__LINKEDIT` and both ranges end at the slice
EOF. Its actual value is still used to validate segment and fixup bounds; an
open/non-tail `__LINKEDIT` keeps the actual filesize in both identities. Every
other segment extent and the complete fixup payload remain bound. The oracle
records the IPA slice size used by the installed-build
verifier. Fat or multi-slice size changes, a moved signature start, growth
outside the closed signature tail, or any existing identity/range change still
fails closed.

Installation, dependency resolution, and this lane need no Apple login. The
signed archive later uses the Xcode account/certificates on this Mac; upload
uses an App Store Connect API key rather than a local Apple ID/password
session.

Every temporary workspace resolves the configured `TMPDIR` directly before
creation and rejects a location inside the checkout. This avoids relying on
Ruby's cached `Dir.tmpdir` value and keeps the regression check representative
of the lane's real path decision. Both the configured and resolved temporary
root must contain no apostrophe or control character because Fastlane Gym
constructs part of its archive-export command through shell paths; unsafe
values are rejected before any DemoLab temporary workspace is created.

DemoLab contains no non-exempt encryption. Its main `Info.plist` declares
`ITSAppUsesNonExemptEncryption=false`, so the processed build does not require
an undocumented manual export-compliance answer before internal TestFlight
installation.

## Local configuration

Do not put the following values in a tracked file or paste them into an issue,
PR, chat, or build log. Load them from a private shell file outside the Git
checkout, or export them only in the local terminal:

| Variable | Used by | Meaning |
|---|---|---|
| `DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN` | pre-build, archive, upload, reconciliation | Must equal `I_AM_RUNNING_LOCALLY_OUTSIDE_CI`; this supplements rejection of common CI-provider environments. |
| `DEMO_LAB_APP_BUNDLE_ID` | pre-build, archive, upload | Registered first-party main App ID. |
| `DEMO_LAB_SHARE_BUNDLE_ID` | pre-build, archive, upload | Registered first-party share-extension App ID below the main ID. |
| `DEMO_LAB_APP_GROUP_ID` | pre-build, archive | Registered first-party App Group enabled on both the main App ID and share-extension App ID. The archive lane rejects the checked-in `group.com.example.*` value and injects this exact group into both entitlements and Info.plists. |
| `DEMO_LAB_TEAM_ID` | pre-build, archive | Apple Developer team used by Xcode signing. |
| `DEMO_LAB_MARKETING_VERSION` | pre-build, archive | Optional dotted version; defaults to `1.0`. |
| `DEMO_LAB_BUILD_NUMBER` | pre-build, archive | Positive build number. Checkpoint 3 currently accepts only `3`. |
| `DEMO_LAB_OUTPUT_DIR` | pre-build, archive | Absolute dedicated directory outside the repository. It must already exist, be owned by the current user, not be a symlink, already have mode `0700`, and contain no single quote or control character; the lanes never create it or change its permissions. The archive lane derives and locks the exact 3A directory below this root. |
| `DEMO_LAB_EVIDENCE_PATH` | upload, reconciliation | Absolute path to the generated pre-upload evidence JSON. It must remain owned by the current user with no group/other access. |
| `DEMO_LAB_APPLE_ID` | upload | Numeric Apple ID of the existing App Store Connect app record; this binds Apple's package-upload command to the intended app. |
| `APP_STORE_CONNECT_KEY_ID` | upload | App Store Connect API key identifier. |
| `APP_STORE_CONNECT_KEY_TYPE` | upload | Exact key scope: `team` for a team API key or `individual` for an individual user key. Individual keys cause the lane to pass Apple `altool --api-key-subject user`; other values are rejected. |
| `APP_STORE_CONNECT_ISSUER_ID` | team-key upload only | App Store Connect team API issuer identifier. It is required for `team` and must be unset for `individual`. Apple individual API keys have no Issuer ID. |
| `APP_STORE_CONNECT_KEY_PATH` | upload | Absolute path to the `.p8` file outside the repository. |
| `DEMO_LAB_CONFIRM_UPLOAD` | upload | Exact explicit ownership confirmation required by the lane. |
| `DEMO_LAB_RECONCILED_ATTEMPT_STARTED_AT` | reconciliation | Exact `attempt_started_at` value from an indeterminate upload result. This binds a retry decision to one attempt. |
| `DEMO_LAB_CONFIRM_RETRY_AFTER_RECONCILIATION` | reconciliation | Must equal `I_CONFIRMED_THIS_EXACT_BUILD_IS_ABSENT_IN_APP_STORE_CONNECT`, and only after the exact version/build has been checked in App Store Connect. |

The LAB-002 artifact schema freezes `source_commit` as exactly 40 lowercase
hex characters. `demolab_archive` therefore rejects a checkout using a
different Git object-ID width before staging or archiving, even though shared
source-staging helpers remain capable of handling wider identifiers for other
workflows. On a SHA-256 Git repository, `demolab_check` keeps running its
general fixture checks but skips the checkpoint-specific private-input round
trip and reviewed-source snapshot regression because those LAB-002 v1 checks
cannot represent a 64-hex commit.

The `.p8` file must not be a symlink and must have owner-only permissions:

```sh
chmod 600 /absolute/private/path/AuthKey_EXAMPLE.p8
```

Prefer the least-privileged App Store Connect key that can upload this app.
The lane uses the key only for Apple's local `altool` package-upload command;
it does not create a Fastlane Pilot session.

## Checkpoint 4 Host operator workflow

This maintainer-only workflow must be merged on `main` before the exact
TestFlight installation. It is not an installation command and it never opens
an App Group, launches an app, uploads a build, or accepts a target/path/range
for observation. The five lanes are deliberately serial:

```sh
bundle _4.0.16_ exec fastlane ios demolab_operator_start_enrollment
bundle _4.0.16_ exec fastlane ios demolab_operator_close_enrollment
bundle _4.0.16_ exec fastlane ios demolab_operator_start_run
bundle _4.0.16_ exec fastlane ios demolab_operator_close_run
bundle _4.0.16_ exec fastlane ios demolab_operator_start_run
bundle _4.0.16_ exec fastlane ios demolab_operator_close_run
bundle _4.0.16_ exec fastlane ios demolab_operator_verify
```

`start_enrollment` accepts only the frozen prebuild/candidate tuple and creates
the fixed `lab002-experiment` child below an already existing mode-`0700`
operator output root. The root must be empty: any retained prior experiment
makes the command fail closed, so an abandoned or failed lifecycle cannot be
bypassed by publishing another enrollment beside it. The Helper checks the
exact one-entry staging/final inventory immediately before and after its atomic
no-replace rename. It retains the exact source controls and a fresh 15-minute
acknowledgement/envelope. Provisioning the already processed build
through TestFlight remains a separate operator action outside OrchardProbe;
only the fixed installation envelope is imported afterward.

`close_enrollment` accepts one bounded signed Receipt and the complete 64
lowercase-hex fingerprint after the operator compares the Mac and iPhone
displays. Before it closes or publishes enrollment, it also holds and fully
revalidates the original prebuild/candidate directories and requires their
source tuple to match the bytes retained in the experiment. `start_run`
automatically selects only the next legal ordinal,
retains the full Intent on the Mac, and exposes only the signed Challenge for
import. For run 2 it first re-verifies the complete run-1 chain and refuses to
publish until the current Host time is strictly later than both run 1's signed
15-minute `not_after` and its retained Host completion time plus the full
120-second device clock-skew allowance; rerun the same lane after both
boundaries instead of editing a timestamp or waiting inside the Helper. `close_run` accepts one
bounded signed Export and derives the Binding before re-running the complete
verifier. Before authoring, accepting, or finally verifying any run, the helper
reopens the original prebuild and frozen candidate and requires the retained
manifest, Oracle, and pre-upload evidence to remain byte-identical. A complete
chain verification repeats that full frozen-source revalidation after the
two-run chain closes and before returning a disposition, so a concurrent
source change cannot leave a successful result based on stale in-memory data.
The second close applies the same final source revalidation before returning
its closed disposition and rechecks run 1's retained Intent against the frozen
pre-upload evidence before accepting the two-run chain.
For every operation, the Helper parses and cryptographically verifies the exact
Archive executable snapshots it hashed and the exact executable entries held
in the bounded IPA snapshot. It independently validates each Archive/IPA
`Info.plist`, signing identity, entitlements, CMS trust, and the target binding
recomputed from the signed manifest, then re-derives the complete Oracle role
and slice tuple. Structural equality with the retained Oracle is mandatory;
UUID-only or self-consistent but substituted reports are insufficient. Every
signed role report must therefore match the Oracle's exact role/slice identity,
initial encryption coverage, and expected mapped plaintext digest. The second
close evaluates byte-identical normalized observations across the ordered
two-run chain before publishing run 2; a mismatch is atomically retained as
generic `no_go`, while replay, ordering, enrollment, and frozen-Oracle integrity
failures still reject publication. The checked-in iOS observer truthfully
reports its bounded signature parse as `not_checked`; Host closure accepts only
that exact `inconclusive`/`signature_invalid_or_unchecked` tuple as reproducible No-Go
evidence and never treats it as valid signature evidence or a Go result.
If an otherwise well-formed signed report preserves the authorized identity
and bounded evidence integrity but a signature, initial-protection, disk, or
mapped-plaintext gate fails, closure retains it as the generic `no_go`
disposition instead of rejecting and losing the result. Contradictory
validator/outcome/reason tuples and identity or coordinate substitutions still
fail closed. Both the second close and final verifier expose `go`,
`no_go_signature_unchecked`, or `no_go`; Fastlane prints either No-Go explicitly
rather than as a generic success.

Every publishing lane uses a random owner-only staging directory, fixed
filenames, exclusive rename, directory fsync, and exact phase inventory. It
rechecks that inventory at the immediate pre-rename and post-rename publication
boundaries, including every enrollment/run result and control phase, and rolls
back its own publication if an unexpected sibling appears. The same boundary
guard reopens the complete frozen source tuple before and after each rename;
changing it while publication waits cannot commit a stale control or result.
Each boundary guard checks the phase inventory both before and after that
source validation, so the validation window cannot admit an unaccounted sibling.
It refuses an existing/incomplete phase rather than overwriting or silently
retrying it.
Retained upload-reconciliation records must also satisfy
`attempt_started_at <= reconciled_at <=` the active upload attempt time; an
impossible audit chronology fails closed. The upload gate and reconciliation
lane enforce the independently knowable lower bound before an active retry
exists; the operator source loader additionally enforces the retry-time upper
bound. The authorization seed remains only in the frozen prebuild; the device
enrollment private key never leaves the device.
Fastlane also holds non-blocking exclusive locks on every bound directory for
the complete Helper invocation: the output or experiment root plus the frozen
prebuild and candidate directories used by that operation. It acquires them in
deterministic device/inode order and releases any partial acquisition on
failure. A competing controlled lane against the same workflow or either
frozen source fails before reading or publishing state. The upload lane holds
that same candidate-directory lock from its final Helper gate through creation
of the indeterminate record, the complete Apple request, and terminal result
replacement. Reconciliation holds it through atomic replacement and archival.

The operator lanes use these additional private environment values:

- `DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN` must equal
  `I_AM_RUNNING_LOCALLY_OUTSIDE_CI`; every lane rejects CI, a dirty checkout,
  and a `HEAD` that is not contained in the authenticated GitHub `main`
  history, then rechecks the clean reviewed source before completion;
- `DEMO_LAB_LAB002_OPERATOR_OUTPUT_ROOT`: new, empty, absolute mode-`0700`
  directory outside the repository;
- `DEMO_LAB_LAB002_PREBUILD_DIRECTORY`: exact frozen 3A prebuild directory;
- `DEMO_LAB_BUILD_OUTPUT_DIRECTORY`: exact frozen candidate directory;
- `DEMO_LAB_LAB002_EXPERIMENT_DIRECTORY`: the exclusively published experiment
  child used by every later lane;
- `DEMO_LAB_LAB002_HARDWARE_MODEL`, `DEMO_LAB_LAB002_IOS_PRODUCT_VERSION`, and
  `DEMO_LAB_LAB002_IOS_BUILD`: sanitized expected environment for the selected
  owned iPhone, with no stable device identifier;
- the five `DEMO_LAB_LAB002_CONFIRM_*` authorization variables shown by
  `lab002_operator_assertions!`: each must equal `true` only after the fresh
  RFC-0001 acknowledgement immediately preceding enrollment or a run;
- `DEMO_LAB_LAB002_RECEIPT_PATH` plus the full
  `DEMO_LAB_LAB002_DEVICE_SELECTION_FINGERPRINT` and
  `DEMO_LAB_LAB002_CONFIRM_FINGERPRINT_MATCH=true` for enrollment closure;
- `DEMO_LAB_LAB002_EXPORT_PATH` for the current run's signed Export.

Receipt/Export files may come from AirDrop or Files, but must be absolute-path,
owner-only, bounded, non-symlink regular files outside the repository. Their
nonblocking snapshots reject FIFOs and other special files. Do not paste
private values, experiment IDs,
fingerprints, paths, Receipt/Export contents, or Host results into GitHub or
logs. A failed/expired/post-start phase is retained and evaluated under the
reviewed No-Go rules; it is not deleted and recreated to obtain a pass.

## Stage 1: create the signed candidate

Before the first run, sign in to the correct development team in Xcode and
allow Xcode to manage signing for the two registered App IDs. Create the
private output root yourself, then invoke the lane from a clean, reviewed
commit:

```sh
mkdir -p /absolute/private/path/orchardprobe-demolab
chmod 700 /absolute/private/path/orchardprobe-demolab
export DEMO_LAB_OUTPUT_DIR=/absolute/private/path/orchardprobe-demolab
export DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI
export DEMO_LAB_BUILD_NUMBER=3
bundle _4.0.16_ exec fastlane ios demolab_prepare_lab002
bundle _4.0.16_ exec fastlane ios demolab_archive
```

The pre-build lane first publishes exactly one private three-file 3A tuple for
the authenticated live-`main` source and DemoLab `1.0 (3)`. The archive lane
derives that directory from the same locked output root, reads it only through
a held directory descriptor, and rederives and validates the manifest,
non-weak authorization public key, identity nonce, Build Binding, three target
bindings, target-identity set, and pinned toolchain before injecting those
values. The shell does not provide any of those private binding values.

The archive lane then validates identifier formats and ownership inputs,
records the clean commit, exports `fixtures/DemoLab` from that immutable Git
commit rather than copying the mutable checkout, generates the project in a
temporary directory,
asks Xcode to archive/export with automatic signing, and writes first to a new
random owner-only staging directory below `DEMO_LAB_OUTPUT_DIR`. The lane holds
exclusive advisory locks and open directory descriptors for the output root and
staging directory across the entire Xcode operation. Gym receives a separate
random mode-`0700` temporary root beneath that locked staging directory, so its
export plist, intermediate IPA, and other export scratch cannot be left in the
system temporary directory. The lane verifies Gym's actual export directory is
a direct child of that root, removes the root after a successful export, and
removes ordinary unpublished staging output on failures before the private
oracle helper is launched. Immediately before that launch it switches to
fail-safe retention: any spawn, helper, evidence, or later pre-publication
failure preserves the owner-only staging tree, and the next archive attempt
refuses to proceed until the retained `.demolab-staging-*` entry is explicitly
reconciled. It revalidates output and
staging filesystem identity and mode before and after the build, creates the
evidence inside staging, validates that the completed evidence satisfies the
same strict schema consumed by Stage 2, and then binds the exact Archive App
directory identity returned by the private oracle helper. Its final publisher
keeps read-only descriptors open for the IPA, six Archive sources, oracle, and
evidence while it rehashes them, performs Darwin's exclusive no-follow
directory rename, and revalidates every descriptor through the published path
before returning success. Immediately before the rename, the lane atomically
reserves an owner-only
`.demolab-staging-published-indeterminate-*.json` sibling gate bound to the
expected run device/inode. The gate is removed only after all descriptor-bound
post-rename checks pass. A gate reservation failure therefore prevents the
rename, while any later failure leaves a durable retry block for the normal
retained-staging scan until the operator reconciles that exact published run.
Concurrent controlled
invocations therefore cannot share, mix, or overwrite build output; an
existing final directory is never reused. A replaced or permission-weakened
directory is rejected and malformed evidence prevents publication without
deleting indeterminate private state. The lane refuses a missing output
root instead of creating it beneath a caller-controlled parent.

The LAB-002 checkpoint candidate `1.0 (3)` is uploadable only when its evidence
contains the closed 3B.3 binding. Archive records the exact owner-only manifest
and oracle identities, external oracle SHA-256, Build Binding, Target Identity
Set, and IPA size/SHA-256 while the prebuild directory remains locked. A legacy
or hand-edited `1.0 (3)` evidence record without that complete binding is
rejected before any credential or network action.

The run directory contains local sensitive research artifacts:

```text
DemoLab.xcarchive
DemoLab-<build>.ipa
lab-002-oracle-v1.json
demolab-pre-upload-evidence.json
```

It must remain outside Git. The evidence record binds:

- clean source commit and fixture path;
- Fastlane, Xcode, iPhoneOS SDK version, and SDK build;
- marketing version, build number, and Release/App Store configuration;
- IPA size and SHA-256;
- each archive main/framework/extension Mach-O role, relative path, size,
  SHA-256, architecture, and UUID;
- the packaged app/framework/extension identities plus the exact size and
  SHA-256 of all three executable entries inside the exported IPA;
- for LAB-002 `1.0 (3)`, the fixed manifest/oracle file identities, external
  oracle SHA-256, Build Binding, Target Identity Set, and the same IPA tuple.

Every binary is explicitly marked `initial_protection_status: not_observed`
and `expected_plaintext_status: candidate_pre_upload_archive_only`.
The IPA validator reads one bounded regular-file snapshot into memory and
derives package inspection, size, and SHA-256 from those same bytes. It also
requires `ITSAppUsesNonExemptEncryption=false` in the exported main app. The
upload lane likewise parses the evidence JSON only from a bounded, no-follow
regular-file snapshot. All source, build, plist, binary, and upload temporary
workspaces are newly created with mode `0700`. Their configured temporary base
must resolve outside the Git checkout and must be either private to the current
user or protected by the sticky bit; a custom `TMPDIR` inside the checkout, or
one whose configured/resolved path contains an apostrophe or control character,
is rejected before any temporary artifact is created.

## Stage 2: upload the exact candidate

Set `DEMO_LAB_EVIDENCE_PATH` to the evidence JSON from Stage 1. The lane derives
the IPA path from that record and refuses to upload if the current Git commit,
source cleanliness, evidence profile, fixture, distribution method, filename,
or SHA-256 differs. The complete Stage 1 record is mandatory: creation time,
source and clean-tree assertion, toolchain, Release/App Store build metadata,
all three archive binary measurements with architectures and UUIDs, all three
packaged binary measurements, explicit unknown-protection/candidate-plaintext
statuses, and unresolved upload/install lineage must all be present with the
expected schema. Keep the sibling `DemoLab.xcarchive` in place through upload:
the lane remeasures its three binaries and requires their sizes, hashes,
architectures, and UUIDs to match the evidence. Every archive path component is
checked with `lstat`; a symlinked app, framework, plug-in, or directory is
rejected, and every resolved binary must remain below the same archive root.
For LAB-002, do not copy or rename individual files. The lane derives the one
fixed sibling prebuild directory and run directory from the evidence
source/version/build, locks both, and invokes the reviewed private helper with
their held descriptors. The helper reparses canonical Manifest, Prebuild, and
Oracle bytes, rederives the authorization key, Build Binding, per-target
bindings and Target Identity Set, closes the three-role oracle inventory and
IPA tuple, and rejects changed permissions, identities, digests, or extra/run
missing entries. A retry may retain up to 32 reconciled upload audit records;
the helper accepts only the fixed lowercase name form and revalidates each
owner-only record's schema, source commit, IPA SHA-256, timestamps, destination,
and `reconciled_absent` decision. Every other additional entry is rejected. The
same gate is repeated after the read-only IPA snapshot is ready and before an
upload-attempt record or Apple network action is created. This final gate keeps
the frozen run-directory lock until the upload result is durably accepted or
retained as indeterminate, so an operator workflow cannot consume a changing
candidate.
After the API key descriptor and locked named IPA snapshot are ready, the lane
repeats the complete archive-binary measurement immediately before it
revalidates the selected Xcode and launches `altool`; a mismatch aborts before
any network action. It also reopens the IPA without extracting it and requires
exactly one `DemoLab.app`, the expected app/framework/extension identities and
executables, the marketing/build versions in all three bundles, safe ZIP
entries (including normal Xcode data-descriptor entries), and packaged-binary
hashes matching Stage 1. It then copies those validated bytes through an open
file descriptor into a new owner-only temporary snapshot, rechecks that
snapshot's exact size and SHA-256, closes the writable handle, reopens the same
inode through a no-follow read-only descriptor, locks it, and retains its
`.ipa` pathname inside a random private workspace. Xcode 26 `altool` rejects
extensionless `/dev/fd` package paths, so Fastlane passes this verified private
`DemoLab.ipa` path to `altool --upload-package --wait` and checks the same inode
and digest again after the process exits. The upload tool can read the locked
snapshot but never receives or reopens the caller's original IPA path. The API
key is handled by a separate read-only anonymous descriptor. The two first-party
Bundle ID environment variables and numeric App Store Connect Apple ID are
therefore required again at upload time, but are not written into evidence.

The first controlled upload attempt on 2026-07-29 exposed this filename
requirement: Apple created only an empty `AWAITING_UPLOAD` reservation and
returned a product error before accepting any IPA file bytes. Validation with
the same package and API key succeeded, while descriptor-path validation
reproduced `Cannot expand files with extension ""`. App Store Connect UI and
API reconciliation confirmed that no `1.0 (1)` build or uploaded file existed,
and the indeterminate local attempt was archived as `reconciled_absent` before
retry permission was restored. This is transport compatibility evidence, not
protection or plaintext evidence.

PR #49 merged the compatibility fix. The replacement `1.0 (1)` candidate was
built from clean merged commit
`911db950cff8fc408294d56181477f7319442a36`; its IPA SHA-256 is
`1bb541456d73d644e7c06a148c1e0c780f64f1eb622ae8af35ae482a75f4ec1b`.
After the single permitted upload, App Store Connect moved the upload from
`Processing` into the TestFlight build list as version `1.0`, build `1`, status
`Ready to Submit`. That remote state is authoritative evidence that Apple
accepted and processed the package, so the build must not be retried. The local
result remains `status: indeterminate` because terminal `altool` stdout was not
valid JSON. Keep that owner-only record unchanged: it documents a local
tooling-observability gap, not a remote upload failure. No tester group,
external distribution, Beta App Review, or App Store submission was created.

After build `1` was installed on an owned, authorized iPhone, a controlled
Mac-side launch reproduced the reported immediate exit. `dyld` showed that the
app requested
`/Library/Frameworks/DemoFramework.framework/DemoFramework`; the embedded
framework used the same invalid absolute install name. The framework was
present in the app bundle, so this was a linkage-configuration defect rather
than missing IPA content, TestFlight rejection, or decryption evidence. Build
`1` must remain unchanged as failure evidence and must not be retried.

The correction fixes DemoFramework's install-name base to `@rpath`. The
regression lane and the signed workflow use the pinned selected-Xcode `otool`
to require both the framework ID and every matching dependency in the app to
equal `@rpath/DemoFramework.framework/DemoFramework`. The check runs against
the Simulator product, signed Archive, exported IPA, and each upload-time
Archive revalidation. Any absolute or different matching path fails before
publication or upload. Because App Store Connect build numbers are immutable,
the next candidate was defined as `1.0 (2)` built from the merged correction.

PR #51 merged that correction. The `1.0 (2)` candidate was built from clean
merged commit `5785c56e8bee8e30fdaefcb6e263852e9be874ab`; its IPA SHA-256 is
`e383fcf0ee550effb68b183965208b1ef274688cc5233649b8e452135aafde40`.
Before upload, the evidence, signatures, package metadata, Archive linkage, and
exported IPA linkage were independently rechecked. The one upload call again
left a local `status: indeterminate` record because the terminal `altool`
response was not parseable JSON. Do not retry: the App Store Connect API
reported the exact build as `VALID`, with internal state `IN_BETA_TESTING` and
no missing export compliance. The existing internal group already covers all
builds. No group was created or changed, no public link was enabled, and no
external distribution, Beta App Review, or App Store submission was performed.

Set this exact confirmation only after checking the target account and build:

```sh
export DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI
export DEMO_LAB_CONFIRM_UPLOAD=I_OWN_AND_AUTHORIZE_THIS_FIRST_PARTY_FIXTURE
export DEMO_LAB_APPLE_ID=1234567890 # replace with the app's numeric Apple ID
export APP_STORE_CONNECT_KEY_TYPE=team # or individual, matching the key
# team only: export APP_STORE_CONNECT_ISSUER_ID=<issuer UUID>
# individual: unset APP_STORE_CONNECT_ISSUER_ID
bundle _4.0.16_ exec fastlane ios demolab_upload_testflight
```

The API key is read once through a no-follow descriptor into a size-bounded
in-memory snapshot after its ownership, permissions, stable pathname, and
repository boundary are checked. Its bytes are then written through a temporary
writable handle, reopened and verified through a genuinely read-only unlinked
descriptor, and passed directly to Apple `altool`; the caller-supplied path is
never reopened. Xcode 26 `altool` still requires an `--api-issuer` command
argument even though Apple individual API keys have no Issuer ID. For an
individual key, the lane supplies the key ID as that parser-compatibility
placeholder and also passes `--api-key-subject user`; users must not invent or
export an issuer UUID.

The lane uploads for internal TestFlight processing and waits for `altool` to
return its upload/build-status result. It writes a newly and exclusively
created `demolab-upload-result.json` beside the evidence and refuses an
existing file or symbolic link. Before any network action it also refuses
every inherited `PILOT_*` variable and `DEMO_ACCOUNT_REQUIRED`, and launches
`altool` with a minimal explicit environment, private temporary shell and
Foundation homes, an owner-only creation mask, and an explicit log directory
inside a mode-`0700` workspace. ContentDelivery may relax modes on its own log
directory and files, so the lane requires them to remain owned and not writable
by group/other while the private parent preserves confidentiality. Per-file and
aggregate log bounds prevent diagnostics from escaping into the user's
persistent log directory or growing without limit. That workspace is removed
when the command ends.
The lane resolves the `altool` entry selected by the current Xcode
configuration. On Xcode versions where that entry resolves to `altoolShim`, it
requires and launches the real sibling `altool` binary from the same resolved
ContentDelivery resource directory. This keeps the sanitized private empty
Home while avoiding the shim's external `Defaults.properties` dependency; the
account-free check verifies that the real binary can expose the required
package-upload arguments under that environment. Its path, inode metadata, and
SHA-256 are retained, revalidated immediately before process launch, and
checked again after the process exits. Fastlane Pilot is not used,
so no Pilot beta-review, tester, notification, or distribution option is
evaluated. The result is first serialized into a new owner-only temporary
record, fsynced, atomically published as `status: indeterminate`, and followed
by a containing-directory fsync immediately before Apple `altool` starts any
network action. It is changed through another fsynced atomic replacement to
`status: accepted` only when the process succeeds and its bounded
JSON response is valid, contains no `product-errors`, and includes an explicit
`success-message`. This status records upload acceptance, not that the build is
already ready in TestFlight; verify readiness in App Store Connect. The
`altool --wait` process has a fixed 30-minute deadline. At the deadline, the
lane terminates its process group and keeps `status: indeterminate`. If the
upload fails, times out, or returns an ambiguous result, reconcile the exact
version, build, and IPA SHA-256 in App Store Connect before retrying; the build
may already have been accepted remotely. The lane does not patch TestFlight
beta metadata, submit for beta review, add tester groups, distribute or notify
external testers, or install the app. The least-privileged App Store Connect
role capable of uploading this app is sufficient.

Never delete or rename an indeterminate result by hand. If App Store Connect
shows that the exact version and build are present, do not retry. If it confirms
that they are absent, copy `attempt_started_at` from the current result and run
the dedicated reconciliation lane:

```sh
export DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI
export DEMO_LAB_EVIDENCE_PATH=/absolute/private/path/demolab-pre-upload-evidence.json
export DEMO_LAB_RECONCILED_ATTEMPT_STARTED_AT=2026-07-29T00:00:00Z
export DEMO_LAB_CONFIRM_RETRY_AFTER_RECONCILIATION=\
I_CONFIRMED_THIS_EXACT_BUILD_IS_ABSENT_IN_APP_STORE_CONNECT
bundle _4.0.16_ exec fastlane ios demolab_reconcile_indeterminate_upload
```

The lane locks both the candidate directory and result against an upload that is still running, validates
that its commit, IPA hash, and attempt timestamp match the current evidence,
durably changes it through a fsynced atomic replacement to
`status: reconciled_absent`, and publishes it under a new
random archival filename with an exclusive no-follow rename. Only after that
record has been archived can `demolab_upload_testflight` exclusively create a
fresh current result and make another network attempt. Reconciliation does not
require either Bundle ID variable or any API-key/upload credential.

## Stage 3: manual owned-device observation

After App Store Connect reports the build ready, the maintainer manually
selects this exact version/build in TestFlight and installs it on an owned
iPhone. Record only sanitized facts allowed by the compatibility policy. Do
not publish the device UDID, serial number, pairing material, receipt,
protected executable, IPA, or private logs.

The installed `1.0 (1)` build cannot enter this observation because its invalid
DemoFramework install name prevents launch. On 2026-07-29, a read-only device
query independently identified corrected DemoLab `1.0 (2)` on the same owned
iPhone. A controlled terminate-existing launch returned success, and the exact
launched process was still present after both 12 and 32 seconds. The previous
immediate launch failure was not reproduced. This clears only the launch
prerequisite; it does not establish installed lineage, initial protection,
plaintext, or decryption.

The controlled observation must separately answer:

1. Can the exact installed build and slice be bound to the uploaded candidate
   beyond bundle ID, version, and build number?
2. Is initial protection independently observable for each claimed binary and
   exact slice before any backend output exists?
3. Can Apple transformations be normalized well enough to compare exact code
   ranges with an independently derived plaintext oracle?
4. Can another maintainer reproduce the method using only first-party inputs
   while public evidence remains sanitized?

If any required property cannot be established, `LAB-001` records the
corresponding bounded No-Go. A successful TestFlight upload alone is never a
Go result and does not activate `DEVICE-001`.

The 2026-07-29 controlled observation produced that bounded No-Go. Public
CoreDevice app/process metadata did not expose per-binary installed UUIDs,
signature identities, slices, or hashes; the file service did not offer an
installed-app-bundle domain; and the distribution-signed app had
`get-task-allow=false`. LLDB could identify a connected process but had no
executable images to enumerate or interrupt. The pre-upload arm64 binaries were
`cryptid=0` plaintext candidates, while Apple documents additional distribution
processing and DRM. The upload hash therefore could not substitute for exact
installed lineage or an independent protected/plaintext range comparison.

See the
[LAB-001 protected-oracle result](../research/lab-001-protected-oracle.md) for
the sanitized tuple, per-binary evidence, reproduction procedure, criteria, and
required plan change. LAB-001 completes as No-Go without activating
`DEVICE-001`.

## Retention and deletion

Keep the local run directory only for the controlled experiment and encrypted
backup period approved by the maintainer. Delete the IPA, archive, API key
working copy, raw Xcode/Fastlane logs, and device-side material when they are
no longer required. Public records may retain only reviewed source revisions,
tool versions, relative first-party paths, redacted metadata, digests, the
comparison method, and the final Go/No-Go reasoning.
