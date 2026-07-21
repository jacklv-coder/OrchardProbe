# Acceptable Use Policy

OrchardProbe exists to support transparent, reproducible analysis of iOS apps that the researcher owns or has explicit authorization to test. This policy governs official project infrastructure, maintainer support, examples, and contributions. It is not an additional field-of-use restriction on, and does not modify, the Apache-2.0 license covering repository source code.

## Acceptable uses

Examples of acceptable use include:

- analyzing an app developed and owned by you or your organization;
- performing a mobile security assessment under explicit written authorization from the app owner;
- testing OrchardProbe's first-party DemoLab fixtures for education, parser development, or interoperability research;
- validating that an authorized export is complete, reproducible, and accurately reported.

For supported workflows, users should:

- confirm authorization before any real-device operation and retain evidence appropriate to the engagement;
- stay within the authorized targets, techniques, data, devices, and time period;
- use the least access necessary and protect all apps, reports, logs, and device details;
- comply with applicable law, platform terms, contracts, and third-party rights;
- sanitize diagnostic material before sharing it with the project.

## Unsupported and prohibited project-channel uses

Maintainers will not provide assistance for the following activities, accept contributions intended to enable them, or allow official project infrastructure and community channels to be used for them:

- target an app, account, device, or organization outside your authorization;
- discover, request, download, host, sell, or share unauthorized third-party decrypted IPAs or proprietary binaries;
- collect Apple ID credentials, automate purchases, or bulk-acquire App Store content;
- evade purchases, subscriptions, licensing, anti-cheat systems, account restrictions, access controls, or app-specific protections;
- create or distribute jailbreaks, kernel exploits, PAC/PPL bypasses, malware, spyware, or persistence mechanisms;
- re-sign, install, modify, clone, or redistribute exported apps;
- export Keychain items, Documents, cookies, databases, or other app data containers;
- expose the planned device helper as an arbitrary shell, file-access, PID, or memory service;
- operate a cloud or commercial export-as-a-service offering based on the project;
- publish confidential client material, raw device identifiers, receipts, credentials, tokens, or non-public vulnerability details;
- use commercial app names, icons, screenshots, or binaries as public demos without the rights to do so.

A claimed research, educational, archival, or interoperability purpose does not automatically establish authorization.

## Repository participation

Issues and pull requests must use first-party or safely generated fixtures. Maintainers may remove prohibited content, decline assistance, close requests, or restrict participation when activity conflicts with this policy. Attempts to disguise an unsupported use case are themselves a violation.

Report security vulnerabilities privately according to [SECURITY.md](SECURITY.md). For a suspected policy violation, open a moderation issue containing only the minimum non-sensitive information needed to locate the content; do not repost prohibited or confidential material.

This policy may become more specific as the implementation develops, but changes will not silently broaden the project's authorized-use-only scope.
