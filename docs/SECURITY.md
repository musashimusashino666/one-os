# Security Model and Current Limitations

## Security goals

ONE OS aims to reduce the amount of code that must be trusted, enforce least authority, isolate failures, preserve data confidentiality and integrity, and support auditable recovery.

## Preliminary threat model

Assets to protect:

- user documents and secrets;
- authentication material and cryptographic keys;
- process memory and service state;
- system integrity and update provenance;
- device access, network permissions, and audit records.

Threats in scope for future implementation:

- a malicious or compromised application;
- a compromised user-space service;
- malformed files and protocol input;
- accidental or malicious cross-process access;
- interrupted updates and storage failures;
- unauthorized downgrade or tampering with boot artifacts.

Out of scope for the initial prototype: physical attacks, compromised firmware, malicious hardware, and side-channel resistance. These must be revisited before any production or high-assurance claim.

## Required controls (not yet complete)

1. Memory-safe implementation for privileged components where practical.
2. Address-space isolation and a controlled user/kernel transition.
3. Kernel-enforced capabilities checked at each protected operation.
4. Authenticated boot and signed software updates.
5. Least-privilege service manifests and explicit device permission.
6. Secure key storage, data-at-rest encryption, and tested key recovery.
7. Fuzzing, sanitizers where applicable, static analysis, code review, and independent security testing.
8. Audit logs that do not leak secrets and have a documented retention policy.
9. A tested rollback strategy that does not permit booting known-vulnerable images without an explicit recovery policy.

## Capability reference model

The crates/oneos-core crate currently models an object ID, a set of rights, a generation-stamped capability, and revocation by generation change. Unit tests verify basic authorization decisions.

This model is **not a security boundary** by itself. Safe Rust visibility rules do not protect against arbitrary kernel memory corruption, unsafe code, a malicious caller with direct memory access, or a faulty kernel integration. Do not use it to protect real data until the kernel establishes and enforces the necessary isolation.

## Security reporting

Do not publish exploit details for an unpatched live deployment. For now, file reproducible, minimal reports as private communication to the maintainers where possible; do not include credentials, personal data, or production secrets in issues.

## Release gate

No release should be described as production-ready or secure solely because CI passes. A release requires a documented threat-model review, test results, reproducible build information, independent review of privileged code, and a tested recovery process.
