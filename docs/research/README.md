# Maintainer research records

This directory contains sanitized, reviewable results from narrowly scoped
maintainer experiments. A record must:

- use only project-owned DemoLab artifacts and owned or explicitly authorized
  test environments;
- identify the exact research tuple without publishing credentials, stable
  device identifiers, receipts, protected binaries, or raw private logs;
- distinguish observed evidence from inference;
- evaluate explicit Go/No-Go criteria and state limitations narrowly; and
- update the execution ledger and affected technical or compatibility
  documentation in the same result pull request.

A research record is evidence for only its named tuple. It does not establish a
device support claim, a general decryption capability, or a user-facing
`oprobe decrypt` workflow unless the corresponding execution gates separately
complete with the required evidence.

Research designs:

- [LAB-002 fixed-range self-observation oracle design](lab-002-oracle-design.md)
  defines the device-free trust model, complete inventory, fixed-range oracle,
  bounded report family, two-run procedure, and Go/No-Go gate. LAB-002 is now
  closed with a retained No-Go; the design remains historical evidence, not a
  device result.
- [LAB-003 external artifact layout](lab-003-external-artifact-layout.md)
  defines the device-free successor gate for strict control artifacts,
  operator inputs, diagnostics, preflight ordering, retention, and redaction.
- [LAB-003 device-free implementation result](lab-003-implementation-result.md)
  records the narrow layout Go and the continuing device-ceremony No-Go. It
  does not establish a device backend or working IPA decryption.
