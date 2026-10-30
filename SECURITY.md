# Security Policy

## Project status

ONE OS is a pre-release research kernel.
There are no supported production releases or security-support SLA.
The current x86_64 BIOS/QEMU target is not a daily-use operating system.

## Reporting a vulnerability

Do not publish exploit details, sensitive logs, credentials,
or weaponized proof-of-concept code in public issues or discussions.

Use the repository's **Security** tab and its private
**Report a vulnerability** workflow when that option is available.

Private vulnerability reporting has not yet been confirmed
as enabled for this repository. If the private workflow is unavailable,
do not submit sensitive details through a public issue.
Ask the maintainer through a non-sensitive public message
to establish a private reporting channel first.

This configuration gap is tracked in
[#85](https://github.com/musashimusashino666/one-os/issues/85).

## Scope

The repository's default branch and any artifacts explicitly
published by the project are in scope for triage.
There is currently no production release branch or supported
hardware matrix.

The project's [Security Model](docs/architecture/SECURITY_MODEL.md)
describes intended protections and known exclusions.
It is not a claim that those protections are fully implemented.

## Response expectations

No response-time or remediation SLA is currently promised.
The project must establish triage ownership, severity assessment,
coordination, disclosure, and support policy through #85
before inviting external security testing.

## Research limitations

QEMU and CI results are not hardware certification.
A bounded audit or passing test proves only the tested behavior.
See [Verification Strategy](docs/engineering/VERIFICATION.md).
