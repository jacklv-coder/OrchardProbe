# Compatibility evidence and support states

OrchardProbe compatibility is a claim about one exact, recorded combination of
device, operating-system build, environment, transport capabilities, backend
capabilities, tool commit, and first-party fixture commit. A result must not be
generalized to a nearby device, iOS release, jailbreak, backend, or commit.

There is no supported device matrix while OrchardProbe has no device backend.
An entry missing from a future matrix is unverified; it is not automatically
unsupported.

## Status definitions

### Verified

`Verified` is the only status that represents an official compatibility claim.
Maintainers may assign it only when all of the following are true:

- a maintainer reproduced the result on a project-owned device or a device the
  maintainer is explicitly authorized to test;
- the test used DemoLab built from the recorded commit;
- the record names the exact claim being verified and identifies the installed
  DemoLab build and its initial protection state with sanitized, independently
  reviewable evidence;
- every in-scope Mach-O binary was evaluated independently against a recorded
  known-plaintext SHA-256 oracle from that same DemoLab commit;
- the observed hash matched the oracle for every binary declared `Pass`, and no
  required binary was skipped;
- the complete procedure succeeded in at least two clean runs;
- the record passed its privacy and authorization checks; and
- a maintainer completed the Go/No-Go decision and verification sign-off in the
  [test record template](test-record-template.md).

An ordinary unencrypted development build can verify host parsing, transport,
containment, collection, and hash plumbing. It cannot verify a decryption or
protected-to-plaintext claim. Such a result is at most Experimental for that
claim, regardless of matching hashes. The source commit alone does not prove
the identity or initial protection state of an installed artifact.

A single user report never creates or upgrades an official support claim, even
when its observed behavior is successful. It remains an unverified intake until
the maintainer verification workflow above is complete.

### Experimental

`Experimental` means a maintainer has evidence that the exact combination can
exercise some intended behavior, but one or more Verified requirements are not
met. Typical reasons include incomplete binary coverage, a missing or mismatched
oracle, a skipped run, intermittent behavior, an unreviewed capability path, or
a pending regression retest. Experimental combinations carry no support or
reliability guarantee.

### Unsupported

`Unsupported` means maintainers have confirmed that the exact combination
cannot satisfy the required behavior, lacks a required capability, violates the
project's minimum-privilege boundary, or is outside the project's documented
scope. The record must state the observed reason. Lack of reports or maintainer
hardware alone is not evidence for this status.

## Unverified reports

Public compatibility issues are manual, opt-in, structured intake reports, not
automatic telemetry, test records, or support declarations. Their result always
begins with `Unverified report`. Maintainers first check authorization, fixture
provenance, completeness, and redaction. A useful report may lead to a separate
maintainer test record, but it does not itself change a compatibility status.

## Permitted record fields

A real-device test record collects only the minimum structured environment and
evidence needed to reproduce a result:

- device marketing model and SoC family;
- iOS version and build number;
- jailbreak or equivalent test-environment name and version, plus rootless or
  rootful mode;
- macOS host version and architecture, the exact OrchardProbe commit, and the
  future helper artifact SHA-256 when a helper is exercised;
- public, project-defined transport and backend capability IDs;
- the exact DemoLab commit;
- the narrowly worded claim under test and sanitized DemoLab build identity;
- per-binary initial-protection evidence, evidence level, and outcome; and
- the known-plaintext oracle source and SHA-256 value for each in-scope DemoLab
  binary.

Do not collect or publish UDIDs, ECIDs, serial numbers, IP addresses, host or
device usernames, credentials, tokens, proprietary application names or bundle
identifiers, IPAs, binary contents, or raw/unsanitized logs. Do not attach or
link to those materials. A maintainer's GitHub identity in the sign-off is
record process metadata, not host or device metadata.

Use DemoLab whenever it can reproduce the observation. Public diagnostic intake
may instead describe another original, publicly redistributable first-party
fixture, but that report cannot establish Verified compatibility under the
current policy. A third-party or proprietary application cannot be named or
used to establish public compatibility, even if the reporter says they are
authorized to test it. Maintainer verification currently uses DemoLab only.

## Evidence vocabulary

Evidence strength and outcome are separate:

- `metadata` records descriptive binary metadata only;
- `structure` validates binary structure but does not prove plaintext;
- `range_hash` confirms that the helper and host agree on bounded range byte
  counts and hashes; it establishes transfer integrity, not plaintext; and
- `known_plaintext` compares the observed output hash with an independently
  recorded SHA-256 oracle produced from the same DemoLab commit.

An internal test record may declare a binary `Pass` only at the
`known_plaintext` level with matching observed and oracle hashes. Missing or
weaker evidence is `Inconclusive`, `Fail`, or `Skipped` as appropriate. Public
issue intake deliberately avoids `Pass` so an unreviewed observation cannot be
mistaken for verified plaintext or official support.

Evidence is scoped to the claim. A matching known-plaintext hash proves the
observed output matches its oracle; it does not prove that the input exercised
decryption unless the installed input's protected state and artifact lineage
were independently established. Records must not silently broaden a verified
transport or collection result into an end-to-end export claim.

## Promotion and regression workflow

1. A reporter submits a sanitized compatibility issue; its status is
   unverified.
2. A maintainer reviews authorization, DemoLab provenance, structured fields,
   limitations, and redaction.
3. A maintainer reproduces the exact combination and creates a test record from
   the template.
4. The maintainer records per-binary evidence, performs clean repetitions, and
   makes a Go/No-Go decision.
5. Only a signed `Go — Verified` record can add or upgrade a matrix entry.

Any change to a recorded tuple requires new evidence. A regression demotes a
Verified entry to Experimental while it is investigated; a confirmed inability
or out-of-scope condition may become Unsupported with a recorded reason.
