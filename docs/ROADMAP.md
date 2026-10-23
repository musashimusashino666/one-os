# ONE OS Roadmap

Work is milestone-driven. A milestone is complete only when its acceptance criteria are reproducibly demonstrated; writing code alone is not sufficient.

## M0 — Repository and kernel bootstrap

- [x] Rust workspace and formatting/CI baseline.
- [x] x86_64 kernel entry point and COM1 diagnostics.
- [x] Host-testable no_std capability reference model.
- [x] BIOS disk-image build tool.
- [x] Architecture, security, development, and roadmap documents.
- [x] Verify three independent QEMU boot attempts through CI.
- [x] Test the serial-log validator against panic output, missing completion markers, invalid-map markers, and unexpected QEMU exit statuses.

Exit criteria: three independent QEMU invocations emit the expected startup markers; output is captured for each attempt, and panic, missing completion markers, or unexpected exit statuses fail clearly.

## M1 — CPU and memory foundations

- [x] Structurally validate BootInfo memory-map ranges and reject empty, inverted, or overlapping regions.
- [ ] Define memory-region ownership and the physical page allocator.
- [ ] Set up and test kernel virtual-memory mappings.
- [x] Establish exception handlers and diagnostic fault output, including QEMU tests for invalid opcode, general protection, and page-fault/CR2 reporting (verified in CI Run #120 at `892b9268c9a6774229189c60557be4d0d22bf541`).
- [ ] Configure a TSS/IST stack for double-fault diagnostics and verify it with controlled QEMU fault injection.
- Keep unsafe code small and document safety invariants.

Exit criteria: allocator tests pass, invalid maps fail closed, controlled CPU exception injection produces expected vector/error-code/CR2 diagnostics without a false boot-completion marker, and memory-fault tests do not corrupt unrelated memory.

## M2 — Isolation and IPC

- Add user-mode entry/exit and independent address spaces.
- Implement a minimal scheduler and thread lifecycle.
- Define message formats with length and ownership validation.
- Introduce kernel-enforced capability checks at each privileged interface.
- Test denial, revocation, invalid pointers, and cross-process isolation.

Exit criteria: adversarial tests cannot use one process's authority to access another process's protected resources.

## M3 — Storage and recovery

- Add an initial read-only or minimal writable filesystem path.
- Define filesystem error semantics and integrity checks.
- Implement snapshots or transactional updates where appropriate.
- Add independent backup and restore tests.

Exit criteria: power-loss simulation and fault injection preserve documented filesystem invariants.

## M4 — Device and network services

- Establish a driver model with user-space isolation where practical.
- Add a minimal set of tested virtual and physical devices.
- Implement a bounded networking stack and permission policy.
- Fuzz parsers and protocol boundaries.

Exit criteria: supported-device matrix and protocol test results are published.

## M5 — Developer and application platform

- Define the native system ABI and compatibility policy.
- Add a secure package format and signed repository metadata.
- Prototype sandboxed portable applications.
- Provide SDK documentation and end-to-end examples.

Exit criteria: third parties can build, sign, install, update, and uninstall a sample app with scoped rights.

## M6 — UI, accessibility, and AI services

- Build an accessible shell and window/input abstraction.
- Implement settings and user-facing permission controls.
- Expose controlled APIs to local and remote AI models.
- Require approval for sensitive or irreversible operations.
- Audit all AI-initiated side effects.

Exit criteria: usability tests, permission tests, and AI-action audit tests pass.

## M7 — Performance, hardware, and independent review

- Publish repeatable benchmarks against defined reference systems.
- Optimize only after profiling representative workloads.
- Add architecture support based on demand and test capacity.
- Conduct external security review and vulnerability response exercises.

Exit criteria: public reports disclose hardware, workload, build, limitations, and outstanding risks.

## Prioritization rule

Security boundaries, bootability, and reproducibility take precedence over features. A smaller, verified capability is more valuable than a broad subsystem whose behavior cannot be tested.
