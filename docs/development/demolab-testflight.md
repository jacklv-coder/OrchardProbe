# Controlled first-party DemoLab TestFlight runbook

This runbook prepares one project-owned DemoLab build for the `LAB-001`
protected-oracle experiment. It is maintainer research infrastructure, not the
future end-user workflow. A user who eventually runs
`oprobe decrypt <input.ipa>` must not need an Apple Developer account,
TestFlight, Fastlane, or this fixture.

The runbook does **not** establish that TestFlight produces a representative
protected artifact. It also does not establish installed-artifact lineage,
expected plaintext, a working device backend, extraction, decryption, or IPA
reconstruction. Those are separate evidence questions in
[Issue #9](https://github.com/jacklv-coder/OrchardProbe/issues/9).

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
`xcodebuild`, `dwarfdump`, and `lipo` executables to be root-owned and
non-writable, and likewise pin `/usr/bin/xcrun` and `/usr/bin/plutil`. The
archive gives Gym the absolute `xcodebuild`, fixes
`DEVELOPER_DIR`, removes inherited SDK/toolchain/xcconfig selection, and uses a
minimal PATH whose first entry is the verified selected-Xcode toolchain
directory. This also pins Gym's bare `dwarfdump`/`lipo` calls during optional
dSYM and BCSymbolMap processing. Executable identities, hashes, Xcode version,
and iPhoneOS SDK version/build are captured before use and revalidated after
the archive and evidence passes. The regression lane prepends shadow
`xcodebuild`/`xcrun`/`plutil`/`dwarfdump`/`lipo` files and proves none can be
selected.

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
| `DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN` | archive, upload, reconciliation | Must equal `I_AM_RUNNING_LOCALLY_OUTSIDE_CI`; this supplements rejection of common CI-provider environments. |
| `DEMO_LAB_APP_BUNDLE_ID` | archive, upload | Registered first-party main App ID. |
| `DEMO_LAB_SHARE_BUNDLE_ID` | archive, upload | Registered first-party share-extension App ID below the main ID. |
| `DEMO_LAB_TEAM_ID` | archive | Apple Developer team used by Xcode signing. |
| `DEMO_LAB_MARKETING_VERSION` | archive | Optional dotted version; defaults to `1.0`. |
| `DEMO_LAB_BUILD_NUMBER` | archive | New positive integer for every App Store Connect upload. |
| `DEMO_LAB_OUTPUT_DIR` | archive | Absolute dedicated directory outside the repository. It must already exist, be owned by the current user, not be a symlink, already have mode `0700`, and contain no single quote or control character; the lane never creates it or changes its permissions. |
| `DEMO_LAB_EVIDENCE_PATH` | upload, reconciliation | Absolute path to the generated pre-upload evidence JSON. It must remain owned by the current user with no group/other access. |
| `DEMO_LAB_APPLE_ID` | upload | Numeric Apple ID of the existing App Store Connect app record; this binds Apple's package-upload command to the intended app. |
| `APP_STORE_CONNECT_KEY_ID` | upload | App Store Connect API key identifier. |
| `APP_STORE_CONNECT_KEY_TYPE` | upload | Exact key scope: `team` for a team API key or `individual` for an individual user key. Individual keys cause the lane to pass Apple `altool --api-key-subject user`; other values are rejected. |
| `APP_STORE_CONNECT_ISSUER_ID` | team-key upload only | App Store Connect team API issuer identifier. It is required for `team` and must be unset for `individual`. Apple individual API keys have no Issuer ID. |
| `APP_STORE_CONNECT_KEY_PATH` | upload | Absolute path to the `.p8` file outside the repository. |
| `DEMO_LAB_CONFIRM_UPLOAD` | upload | Exact explicit ownership confirmation required by the lane. |
| `DEMO_LAB_RECONCILED_ATTEMPT_STARTED_AT` | reconciliation | Exact `attempt_started_at` value from an indeterminate upload result. This binds a retry decision to one attempt. |
| `DEMO_LAB_CONFIRM_RETRY_AFTER_RECONCILIATION` | reconciliation | Must equal `I_CONFIRMED_THIS_EXACT_BUILD_IS_ABSENT_IN_APP_STORE_CONNECT`, and only after the exact version/build has been checked in App Store Connect. |

The `.p8` file must not be a symlink and must have owner-only permissions:

```sh
chmod 600 /absolute/private/path/AuthKey_EXAMPLE.p8
```

Prefer the least-privileged App Store Connect key that can upload this app.
The lane uses the key only for Apple's local `altool` package-upload command;
it does not create a Fastlane Pilot session.

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
bundle _4.0.16_ exec fastlane ios demolab_archive
```

The lane validates identifier formats and ownership inputs, records the clean
commit, exports `fixtures/DemoLab` from that immutable Git commit rather than
copying the mutable checkout, generates the project in a temporary directory,
asks Xcode to archive/export with automatic signing, and writes first to a new
random owner-only staging directory below `DEMO_LAB_OUTPUT_DIR`. The lane holds
exclusive advisory locks and open directory descriptors for the output root and
staging directory across the entire Xcode operation. Gym receives a separate
random mode-`0700` temporary root beneath that locked staging directory, so its
export plist, intermediate IPA, and other export scratch cannot be left in the
system temporary directory. The lane verifies Gym's actual export directory is
a direct child of that root, removes the root after a successful export, and
removes all unpublished staging output on failure. It revalidates output and
staging filesystem identity and mode before and after the build, creates the
evidence inside staging, validates that the completed evidence satisfies the
same strict schema consumed by Stage 2, and only then publishes the completed
directory with Darwin's exclusive, no-follow rename. Concurrent controlled
invocations therefore cannot share, mix, or overwrite build output; an
existing final directory is never reused. A replaced or permission-weakened
directory is rejected, malformed evidence prevents publication, and a failed
build removes unpublished staging output. The lane refuses a missing output
root instead of creating it beneath a caller-controlled parent.

The run directory contains local sensitive research artifacts:

```text
DemoLab.xcarchive
DemoLab-<build>.ipa
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
  SHA-256 of all three executable entries inside the exported IPA.

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

The lane locks the result against an upload that is still running, validates
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

## Retention and deletion

Keep the local run directory only for the controlled experiment and encrypted
backup period approved by the maintainer. Delete the IPA, archive, API key
working copy, raw Xcode/Fastlane logs, and device-side material when they are
no longer required. Public records may retain only reviewed source revisions,
tool versions, relative first-party paths, redacted metadata, digests, the
comparison method, and the final Go/No-Go reasoning.
