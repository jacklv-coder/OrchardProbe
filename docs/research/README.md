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

Active research designs:

- [LAB-002 fixed-range self-observation oracle design](lab-002-oracle-design.md)
  defines the device-free trust model, complete inventory, fixed-range oracle,
  bounded report family, two-run procedure, and Go/No-Go gate. It is not an
  implementation or device result.
