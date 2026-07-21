# Security Policy

OrchardProbe is pre-alpha. The repository has working host-only parsing and test-fixture code, but no device backend, export capability, release, or supported production deployment. Security reports are welcome for committed code, designs, schemas, and documentation.

## Supported versions

| Version or branch | Status | Security handling |
| --- | --- | --- |
| Default development branch | Pre-alpha host code; no device compatibility guarantee | Reviewed on a best-effort basis |
| Tagged releases | None published | No released version is currently supported |

This table will be replaced with an explicit supported-version policy before the first public alpha.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue, discussion, pull request, log, or compatibility report.

Use the repository's **Security** tab and select **Report a vulnerability** to open a private report when that option is available. If private vulnerability reporting has not yet been enabled, open a public issue containing only a request for private maintainer contact—do not include technical details, exploit code, device identifiers, or affected artifacts.

Include, where possible:

- the affected commit, component, schema, or planned protocol operation;
- a concise impact statement and the authorization context for the research;
- reproducible steps using OrchardProbe DemoLab or another original, redistributable fixture;
- relevant sanitized logs and environment details;
- suggested mitigations and any known workarounds;
- your preferred disclosure timeline and whether you want public credit.

Never attach an IPA, proprietary binary, receipt, credential, raw UDID, client name, or other sensitive data. A minimal synthetic proof of concept is strongly preferred.

## What to expect

This is currently a volunteer, pre-alpha project. The initial response goals—not service-level guarantees—are:

- acknowledge a private report within three business days;
- provide an initial severity and scope assessment within seven business days;
- agree on remediation and coordinated disclosure timing after reproduction.

Maintainers will keep the reporter informed when these targets cannot be met. Confirmed issues will be fixed on the affected development branch and, after releases exist, documented through an appropriate security advisory and patched release. The project does not currently operate a bug bounty program.

## Priority areas

Reports are especially useful when they concern:

- unsafe Mach-O, plist, ZIP, or protocol parsing, including integer overflow and length confusion;
- path traversal, Zip Slip, symlink escape, archive bombs, or unsafe output replacement;
- helper behavior that enables arbitrary shell, path, PID, or memory access;
- unintended network listeners, uploads, telemetry, or sensitive log disclosure;
- protocol confusion, replay, unauthorized capability negotiation, or cross-device output mix-ups;
- privilege retention, insecure temporary files, or failures to terminate the helper;
- policy controls that can be bypassed to access data containers or other explicitly excluded material.

## Research safety and scope

Test only apps, devices, accounts, and environments that you own or are explicitly authorized to assess. Prefer generated fixtures and isolated test devices. Do not use social engineering, denial of service, destructive payloads, persistence, or collection of personal data.

Vulnerabilities in iOS, jailbreak implementations, third-party apps, Frida, or other dependencies should be reported to their respective maintainers unless OrchardProbe introduces or materially amplifies the issue. Requests to bypass a commercial app's protection or to weaponize a finding are outside project scope.

The planned security model is local-first and minimum-necessary-privilege: no telemetry, USB-preferred transport, a short-lived helper using only entitlements demonstrated as necessary by the technical spike, a restricted versioned protocol, and no arbitrary remote access primitives. See [PROJECT_PLAN.md](PROJECT_PLAN.md), [LEGAL.md](LEGAL.md), and [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) for the intended boundaries.
