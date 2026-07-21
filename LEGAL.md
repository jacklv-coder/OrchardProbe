# Legal and Authorization Notice

OrchardProbe is planned as a research and verification tool for apps that the user owns or is explicitly authorized to test. It is not a source of legal advice, and technical capability must not be interpreted as legal permission.

## Supported authorization context

Maintainers design, test, document, and support OrchardProbe only when at least one of the following is true:

- you or your organization owns the app and has authority to analyze it;
- the app owner has given you explicit authorization covering the app, device, techniques, and time period involved;
- you are working only with OrchardProbe's first-party DemoLab fixtures or other software you created and are entitled to analyze.

Keep a record of the authorization and remain within its scope. Access to a device, an installed copy of an app, source code, or a customer environment does not by itself establish authorization. An authorization confirmation in the future CLI is a reminder, not proof of permission or legality.

Laws governing copyright, technological protection measures, computer access, privacy, trade secrets, export controls, and security research vary by jurisdiction. Ownership or testing authorization does not automatically make circumvention lawful. Platform agreements and client contracts may impose additional restrictions. You are responsible for obtaining qualified legal advice when needed and for determining whether your proposed activity is lawful.

These project boundaries govern maintainer support and official project infrastructure. They do not add field-of-use restrictions to, or modify, the Apache-2.0 license covering repository source code.

## Project boundaries

OrchardProbe is designed to produce a not re-signed, analysis-only export and an evidence report. The project does not provide workflows for:

- obtaining unauthorized third-party apps or decrypted IPAs;
- automating store credentials, purchases, or downloads;
- bypassing purchases, subscriptions, licenses, anti-cheat controls, account limits, or app-specific protections;
- providing or executing jailbreaks, platform exploits, or PAC/PPL bypasses;
- re-signing, installing, modifying, or redistributing exported apps;
- extracting Keychain content or app data containers;
- operating an export-as-a-service platform.

These boundaries reduce misuse but do not replace the user's obligation to secure authorization and comply with law.

## Third-party rights and materials

The license covering OrchardProbe source code grants rights only to that source code. It does not grant any license or other rights to an app, binary, trademark, platform, device, data set, or other third-party material processed with the tool.

Do not upload proprietary apps, decrypted commercial binaries, receipts, credentials, device identifiers, customer artifacts, or confidential vulnerability details to this repository. Public examples, fixtures, screenshots, and test artifacts must be original, redistributable, and free of sensitive data.

Contributors must submit only work they have the right to contribute. Do not copy code from projects with unclear or incompatible licenses, decompiled commercial software, leaked materials, or confidential sources. Behavioral research of prior tools must result in an independent implementation with documented sources and contributor declarations. The project will not claim a clean-room process unless contributor roles and information flows are genuinely isolated and documented.

## Outputs and data handling

Planned outputs remain local and may contain copyrighted or confidential material belonging to the app owner. Users are responsible for securing, retaining, sharing, and deleting those outputs appropriately. OrchardProbe does not include a cloud upload service and is planned without telemetry.

An exported bundle is not re-signed. The report must keep signature presence, kind, and validation separate: for example, a present ad-hoc signature may still validate or fail validation. The output is intended only for authorized analysis and must not be treated as a deployable or redistributable app.

## No affiliation or warranty

OrchardProbe is an independent project and is not affiliated with or endorsed by Apple Inc. Product and company names remain the property of their respective owners.

The project is in a planning, pre-alpha state. No working implementation, supported-device guarantee, fitness for a particular purpose, or legal compliance guarantee is offered. Any warranty and liability terms in the repository's license apply when code is published.

Use of the project is also subject to the [Acceptable Use Policy](ACCEPTABLE_USE.md).
