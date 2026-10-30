# ADR-0003: Adopt a Capability-Oriented Microkernel as the Long-Term OS Target

- **Status:** Accepted
- **Date:** 2026-10-29
- **Scope:** long-term system architecture and multi-device platform strategy

## Context

ONE OS's long-term objective is a general-purpose OS platform for PCs/workstations, smartphones/mobile devices, servers, and embedded/edge systems. The world-class OS definition requires security and reliability as hard foundations while also requiring practical performance, usability, compatibility, adaptability, and evidence-based comparison.

The current repository is an x86_64 BIOS/QEMU bootstrap kernel. Its current implementation and limitations are recorded in [Implementation Status](../IMPLEMENTATION_STATUS.md). It does not yet implement the complete user-mode process boundary, kernel-enforced capability system, integrated service environment, device profiles, application runtime, authenticated boot, or update/recovery system. The target architecture must not be confused with current implementation.

A monolithic kernel may simplify some early integrations, while a microkernel can keep drivers and core services outside the primary trust boundary. A microkernel also introduces IPC, service-lifecycle, and performance costs that must be measured and controlled. This decision selects the target design; it does not assume these trade-offs are already solved.

## Decision

ONE OS's long-term target architecture is a **capability-oriented microkernel platform with isolated user-space services and device-specific profiles over shared security and system contracts**.

The kernel's trusted responsibilities are to include the core mechanisms required for process/address-space control, scheduling primitives, interrupt/exception handling, physical-memory and secure resource lifecycle, core IPC, and mandatory enforcement of protected operations and capabilities. The kernel must remain as small and auditable as practical.

Filesystems, networking, device drivers, service supervision, update orchestration, user environments, and AI/automation clients SHOULD run in isolated user space where the target platform's guarantees permit. Any component that must remain privileged requires an explicit threat-model and engineering rationale.

The platform must share its security semantics, authority model, documented public contracts, and verification principles across these long-term device domains:

- PC and workstation.
- Smartphone and other mobile devices.
- Servers.
- Embedded and edge devices.

These domains MAY use different binaries, hardware support, drivers, application runtimes, interfaces, and scheduling policies. Shared design principles do not imply that one build supports every device. Each hardware/profile combination must have its own declared support scope and acceptance evidence.

Native APIs, POSIX compatibility, WebAssembly, containers, and virtual machines are distinct execution paths with different compatibility, isolation, licensing, and performance properties. Each path must be described and tested explicitly; none may bypass the authority model.

## Required safeguards

Before changing the existing kernel toward this target, the implementation plan MUST provide:

- An updated architecture specification identifying kernel mechanisms and user-space services.
- A threat model and trust-boundary analysis for each service and device profile.
- A measured IPC and context-switch baseline before performance-sensitive decisions are finalized.
- Acceptance tests for allowed and denied capability operations, caller identity, revocation, service compromise, resource lifetime, and IPC failure.
- Explicit SMP and remote-TLB synchronization requirements before enabling concurrent address-space mutation.
- Profile-specific validation for real-time guarantees, power efficiency, performance, hardware support, and compatibility; no property may be inferred from a different profile.
- Clear status reporting separating target architecture, partial implementation, verified-for-scope behavior, and production gates.

The existing memory-safety, executable-mapping, process-isolation, and recovery gates remain in force. This ADR does not complete or waive any current milestone or acceptance test.

## Consequences

- The platform has one long-term architecture direction instead of four unrelated OS designs.
- The kernel remains the primary enforcement boundary, while isolation reduces the authority automatically available to ordinary services and drivers.
- IPC, service lifecycle, authorization provenance, revocation, and observability become core architectural contracts.
- Compatibility and hardware breadth will grow incrementally; unsupported configurations must remain explicitly unsupported.
- Performance overhead and real-time suitability must be measured per profile. The project must not claim that microkernel structure is inherently faster or universally superior.
- The current bootstrap may be used to validate memory and protection mechanisms, but its present structure is not itself evidence that the final architecture is complete.

## Revisit when

Revisit this decision only if prototype measurements, threat-model analysis, hardware constraints, or comparative evidence show that a materially different architecture achieves the stated goals with better verified trade-offs. Any change must include alternatives considered, supporting measurements, security consequences, affected acceptance contracts, and migration implications.
