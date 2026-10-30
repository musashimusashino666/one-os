# World-Class OS: Definition and Design

## Status and authority

This document is the canonical long-term definition and target design for ONE OS. It consolidates the original world-class OS proposal into the repository's existing vision, architecture, evaluation, and roadmap structure.

It describes intended outcomes and target architecture, not the current implementation state. The [Vision](VISION.md) states why ONE OS exists; [Principles](PRINCIPLES.md) constrain decisions; the [Architecture Overview](../architecture/OVERVIEW.md) describes layers and boundaries; [Success Criteria](SUCCESS_CRITERIA.md) defines acceptance evidence; [Implementation Status](../project/IMPLEMENTATION_STATUS.md) reports what has actually been implemented and verified; and the [Roadmap](../project/ROADMAP.md) sequences the work. If this document and implementation evidence differ, implementation claims must follow the evidence, not the aspiration.

## 1. Definition of the world's best OS

**The world's best OS is an operating system that enables people, across diverse users and computing environments, to use the functions and services they need securely, comfortably, and efficiently, while continuously improving the value it provides as technology evolves.**

Its purpose is not merely to run hardware quickly. It is to maximize what people can reliably accomplish with computing while protecting their data, agency, time, and resources.

A fuller normative definition is:

> The world's best OS establishes security and reliability as non-negotiable foundations; combines performance, usability, compatibility, economic practicality, and adaptability at a high level; and enables diverse users to accomplish their goals with minimal unnecessary burden. Its claimed advantages must be demonstrated through published, reproducible measurements and independent review against declared users, workloads, hardware, threat models, and relevant alternatives.

“World's best” is not a claim about current ONE OS maturity, popularity, a name, an architectural label, or a single benchmark. No OS is necessarily best for every workload. ONE OS should claim superiority only within a clearly declared scope and only after satisfying safety-critical release gates and producing comparative evidence.

## 2. Long-term product scope

The long-term platform is one OS family that shares core security semantics and system contracts across:

- **PCs and workstations:** responsive interaction, productivity, broad application support, and user control.
- **Smartphones and mobile devices:** energy efficiency, secure sensors and radios, privacy, touch interaction, and application lifecycle management.
- **Servers:** throughput, predictable tail latency, resource isolation, virtualization, observability, and remote operations.
- **Embedded and edge devices:** bounded resource use, predictable timing where required, long service life, safe state transitions, and dependable recovery.

The four environments are not required to use identical binaries, drivers, user interfaces, or scheduling policies. They must share a coherent architecture, authority model, APIs where appropriate, and verification principles. Hardware and application support is claimed only for explicitly listed and tested configurations.

The current x86_64 BIOS/QEMU kernel is the initial research and verification platform, not evidence that all four product families already exist.

## 3. Seven dimensions of world-class quality

The initial strategic scorecard uses the following proposed weights. These weights help organize comparative evaluation; they do not replace the hard release gates in [Success Criteria](SUCCESS_CRITERIA.md). A catastrophic failure in isolation, integrity, or recovery cannot be compensated for by a high score elsewhere.

| Dimension | Weight | What success means | Evidence examples |
| --- | ---: | --- | --- |
| Security | 20% | Unauthorized access is prevented or contained; privileges are narrow, explicit, enforceable, observable, and revocable. | Adversarial authorization tests, threat-model review, vulnerability disposition, isolation and integrity tests. |
| Reliability | 20% | Failures are bounded; data and system integrity are preserved; recovery behavior is predictable and tested. | Failure-injection results, crash/recovery rates, data-integrity checks, update interruption and recovery tests. |
| Performance and efficiency | 15% | The system delivers responsive operation and adequate throughput while using CPU, memory, storage, and energy efficiently. | Workload-based latency, tail latency, throughput, memory footprint, and energy measurements against fair baselines. |
| Usability and accessibility | 15% | People with different experience, language, input method, and ability can understand and complete core tasks. | Task completion, error and recovery rates, learning time, comprehension, and accessibility testing. |
| Compatibility and extensibility | 10% | Declared hardware, software, devices, formats, and execution paths work through explicit and testable contracts. | Published support matrix, named application workflows, API compatibility tests, driver and runtime tests. |
| Ecosystem and social/economic value | 10% | Users and developers can create, distribute, maintain, and use software with reasonable cost, choice, accessibility, and sustainable governance. | Developer workflow studies, software availability, total cost of ownership, support policy, locale/accessibility coverage. |
| Adaptability and evolution | 10% | The OS can safely adopt new hardware and technology while preserving documented contracts and long-term maintainability. | Upgrade success, API compatibility, portability tests, support lifecycle, migration and rollback tests. |

### Evaluation rules

1. Publish the target profile, user group, threat model, hardware, workload, configuration, and exclusions before making a claim.
2. Establish thresholds and comparison methods before collecting results. Where no sound baseline exists, mark the target as TBD and perform a baseline study.
3. Compare equivalent workloads and configurations. Use at least two relevant alternatives for broad best-in-class claims when fair comparisons are possible.
4. Report each dimension separately as well as the weighted comparative score. Never let an average hide a failed safety-critical gate.
5. Include negative results, variance, known limitations, and the exact candidate revision. Tests support only the properties and cases they cover; they do not prove the absence of every vulnerability.
6. Use the 7-dimension scorecard to summarize value, and the detailed acceptance criteria in [Success Criteria](SUCCESS_CRITERIA.md) to define testable contracts and release decisions.

## 4. Target architecture

The target is a capability-oriented microkernel platform with a small trusted computing base, isolated user-space services, explicit application execution contracts, and hardware-specific profiles. This is a long-term architecture target, not a description of the present bootstrap kernel; the architectural decision is recorded in [ADR-0003](../project/decisions/ADR-0003-capability-microkernel-platform.md). Changes to the kernel structure must follow the repository's ADR and acceptance-test process.

### Layer model

1. **Hardware and boot trust base:** CPU and device abstractions, firmware/boot protocol, memory map validation, and eventual authenticated boot.
2. **Minimal microkernel:** address spaces, scheduling primitives, interrupts/exceptions, physical-memory and secure object lifecycle, core IPC mechanisms, and kernel enforcement of protected operations and capabilities.
3. **Isolated system services:** storage and filesystems, networking, device management and drivers, service supervision, update/recovery orchestration, and other services wherever the required isolation model allows them to run outside the kernel.
4. **Common APIs and application runtimes:** stable native APIs, explicit POSIX compatibility where needed, WebAssembly, containers for supported workloads, and virtual machines for execution of a separate guest OS. These mechanisms have different compatibility, isolation, and performance properties and must not be conflated.
5. **User and operator environments:** desktop, mobile, server-management, and embedded interfaces built on common access-control and system-management semantics.
6. **Automation and AI clients:** planning and delegated actions run with explicitly granted, bounded, inspectable, and revocable authority. AI is never a privileged exception.

### Kernel and trust-boundary rules

- Keep privileged code and the trusted computing base as small and auditable as practical.
- Enforce authorization at the protected operation through kernel-controlled authority state; a UI, manifest, library, or broker's allow decision is not sufficient.
- Default to denial for absent, invalid, stale, forged, ambiguous, or revoked authority.
- Isolate processes, services, and drivers so their faults or compromise do not automatically grant unrelated authority.
- Define IPC framing, caller identity, memory/resource ownership, cancellation, timeouts, transfer, and revocation.
- Preserve memory ownership and translation invariants; do not publish executable mappings until the declared physical-alias and TLB contract is complete.
- Define failure behavior and lifetime rules at every layer boundary.
- Use memory-safe abstractions where practical and document/test every required unsafe boundary.

### Device profiles over a common platform

| Profile | Primary optimization goals | Required profile-specific concerns |
| --- | --- | --- |
| Personal / PC | Responsiveness, usability, broad practical application support. | Windowing/input, GPU, audio, peripherals, compatibility, recovery UX. |
| Mobile | Capability per joule, privacy, responsive interaction. | Power states, modem/radio, camera and sensors, background execution, thermal limits. |
| Server | Throughput, tail latency, utilization, service continuity. | SMP, remote TLB shootdown, NUMA where applicable, virtualization, remote administration, observability. |
| Real-time / embedded | Bounded memory use and predictable behavior; hard deadlines only where explicitly supported and verified. | Priority and interrupt policy, timing analysis, watchdog, fail-safe states, storage/flash constraints, long-term maintenance. |
| Secure / regulated configuration | Auditability, constrained functionality, and verifiable configuration. | Reduced attack surface, policy enforcement, audit retention, controlled change and support process. |

The profiles are not separate products with unrelated security models. They are supported configurations over shared contracts. The OS must not claim hard-real-time behavior, SMP safety, specific hardware support, or compatibility until each is implemented and validated for a declared profile.

## 5. Security, privacy, and owner control

Security is a foundation, not one feature among many. The design requires:

- **Least authority:** each process or service receives only the resource and operations needed for its task.
- **Kernel enforcement:** protected operations validate authenticated callers and kernel-owned authority state. Grants have defined resource, operation, scope, lifetime, delegation, attenuation, and revocation semantics.
- **Isolation and containment:** compromise of one component must not automatically cross into unrelated processes or resources.
- **Integrity of execution:** authenticated boot, verified update artifacts, explicit key lifecycle, and anti-rollback policy before production security claims.
- **Data protection:** storage confidentiality and integrity, safe resource lifetime, and tested backup/recovery.
- **Privacy by default:** local operation where practical; explicit scope and disclosure when information is sent to external services.
- **Observable control:** users can inspect consequential access and revoke rights, with interface language suited to real users rather than kernel engineers.
- **AI under the same rules:** every AI-initiated action uses the normal authority path; high-impact or external actions use a proportionate confirmation policy, and all delegated powers are bounded and revocable.

Containment does not mean a compromised process will behave well within permissions explicitly granted to it. Grants therefore need to be narrow and attributable, and revocation and audit behavior must be tested.

## 6. Reliability, updates, and recovery

The system must not silently trade integrity for availability or treat a reboot as a recovery plan. The target design includes:

- signed and verifiable system/update artifacts and a documented signing-key lifecycle;
- atomic or otherwise interruption-safe installation transitions;
- protection against unauthorized downgrade to versions with known security defects;
- separation of system state and user data where practical;
- integrity checks, snapshots/backups, recovery modes, and explicit data-preservation guarantees;
- failure-injection tests at destructive transition boundaries;
- clear disclosure when a recovery mode is degraded or requires operator action.

A/B or immutable system partitions are possible implementation techniques, not guarantees by themselves. Any technique must satisfy the acceptance requirements and platform constraints.

## 7. Performance, portability, and application compatibility

Performance must be optimized using declared real workloads, not a single chosen benchmark. Measure latency (including tail latency where relevant), throughput, energy, memory, and resource contention. Security checks must not be disabled or weakened to achieve performance targets.

Compatibility is an explicit contract, not a promise that every application will run. Native, POSIX, WebAssembly, container, and virtual-machine paths must be separately documented and tested. Their available APIs, isolation, licensing requirements, hardware dependencies, and performance costs must be disclosed. A compatibility layer must not bypass the authority model.

Use a hardware-abstraction boundary to isolate architecture-specific code. x86_64 and AArch64 should be treated as separate validated platform targets, not assumed equivalent. Future targets (for example RISC-V) are added only after a defined support and verification plan exists.

## 8. Product and developer experience

The OS should be simple for ordinary users while remaining inspectable and controllable by developers and operators.

- Common settings and permission controls should make resource, action, scope, duration, and consequence understandable.
- Core tasks must be accessible through supported input methods and assistive technologies.
- Errors should explain the current state and safe next actions without exposing secrets.
- Developers need documented APIs, SDKs, debuggers, profilers, reproducible build/test workflows, and stable compatibility policies.
- Distribution must support practical software choice while clearly communicating provenance, permissions, support, and compatibility.
- Total cost of ownership, repair/recovery, localization, sustainable maintenance, and long-term support are part of quality, not afterthoughts.

## 9. Development strategy

Build the platform in evidence-gated increments:

1. **Kernel foundations:** memory ownership/protection, interrupt and fault behavior, address-space lifecycle, IPC/security boundaries, and tests that reject invalid states.
2. **Real process isolation and authority:** user-mode entry/return, independent address spaces, kernel-enforced capabilities, revocation, and adversarial cross-process tests.
3. **Minimum usable PC system:** persistent storage, networking, isolated drivers/services, service supervision, shell or desktop foundation, permissions/observability, and recovery.
4. **Usability and security integration:** permission and device controls, audit views, accessible workflows, AI/automation delegation, and representative user studies.
5. **Production integrity and release hardening:** authenticated boot, signed updates, anti-rollback, failure-injection recovery, fuzzing, independent security review, documented support matrix and benchmarks.
6. **Multi-architecture and device profiles:** port the validated contracts to AArch64 and real hardware, then establish server, embedded/real-time, and mobile profiles with profile-specific acceptance suites. Parallel prototypes are allowed, but no target is declared supported until its gates pass.
7. **Comparative evaluation and continuous evolution:** publish repeatable comparisons, compatibility results, limitations, support lifecycle, and plans for new hardware and technology.

The exact order of later device profiles may change based on product validation, hardware access, and engineering evidence. Such sequencing changes do not alter the long-term four-domain objective or relax common security gates.

## 10. What this definition does not claim

This document does not assert that ONE OS currently supports desktops, smartphones, servers, real-time workloads, broad application compatibility, AI delegation, signed updates, or production recovery. Nor does it assert zero vulnerabilities, universal compatibility, or present superiority over existing operating systems.

Current truth is recorded in [Implementation Status](../project/IMPLEMENTATION_STATUS.md). Any claim that ONE OS is best-in-class must be grounded in the applicable acceptance criteria, fair comparators, published methods, and evidence for the exact candidate revision.
