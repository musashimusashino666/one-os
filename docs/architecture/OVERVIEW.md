# Architecture Overview

## Status and scope

This document describes the intended system shape and marks which boundaries exist today. It is not evidence that target components have already been implemented.

ONE OS starts with a small x86_64 Rust kernel and grows incrementally toward a secure, user-controlled computing environment. Architecture should minimize the privileged core and make policy, resource ownership, and recovery explicit.

## Target layers

| Layer | Responsibilities | Placement target |
| --- | --- | --- |
| Hardware and boot | CPU features, boot protocol, memory map, integrity of initial image | Firmware/bootloader plus a small kernel handoff contract |
| Kernel core | Scheduling primitives, address spaces, interrupt/exception handling, physical memory, core IPC, kernel-enforced authority, secure object lifecycle | Capability-oriented microkernel; smallest trusted core practical as the long-term target, not a claim about the current bootstrap implementation |
| Authority and isolation | Capability validation, process boundaries, IPC primitives, resource transfer and revocation | Enforcement in kernel; policy and user-facing explanation outside it |
| System services | Storage, networking, device management, service supervision, update orchestration | Isolated user-space services where practical |
| Application runtime | Native ABI, sandboxing, compatibility or virtualized execution paths | Explicitly separated execution contracts |
| User environment | Shell/compositor or equivalent interaction model, settings, permission views, recovery UX | User space |
| Automation and AI | Planning, delegated actions, tool access, provenance and audit records | Untrusted or separately constrained clients; never an implicit authority bypass |

## World-class target architecture and device profiles

The canonical long-term definition and full target design are in [World-Class OS: Definition and Design](../vision/WORLD_CLASS_OS.md). ONE OS targets one coherent platform across four domains: **PC/workstation, smartphone/mobile, server, and embedded/edge**. Common security semantics, authority rules, interface contracts, and evidence policy are shared; binaries, drivers, UI, and scheduling policies may differ by profile.

The target architecture is a **capability-oriented microkernel** with a small trusted computing base, as recorded in [ADR-0003](../project/decisions/ADR-0003-capability-microkernel-platform.md). Core process/address-space management, interrupt and exception handling, essential scheduling primitives, core IPC, memory/resource lifecycle, and enforcement of protected operations remain in the kernel. Filesystems, networking, device drivers, service supervision, update orchestration, user environments, and AI/automation clients should run in isolated user space where the platform's required guarantees permit. Any security-boundary change must follow the ADR and acceptance-test process.

| Target profile | Primary priorities | Profile-specific requirements |
| --- | --- | --- |
| Personal / PC | Responsiveness, accessibility, productivity, practical application compatibility | Windowing/input, graphics/audio, peripherals, compatibility and recovery UX |
| Mobile | Energy efficiency, privacy, secure sensor/radio use | Power states, modem/camera/sensors, thermal limits and background lifecycle |
| Server | Throughput, tail latency, resource isolation and service continuity | SMP and remote TLB protocols, NUMA where relevant, virtualization and remote operation |
| Embedded / edge | Bounded resource use and predictable operation | Timing guarantees only where explicitly supported and verified, watchdogs, fail-safe state and long service life |

The application platform must declare separate contracts for native APIs, POSIX compatibility, WebAssembly, containers, and virtual machines. These are different execution and isolation mechanisms, not one interchangeable compatibility promise. Hardware architecture support (initially x86_64, then separately validated AArch64; additional architectures only under an explicit support plan) must be tested per target.

These are long-term targets. The current bootstrap does not yet implement the complete microkernel service architecture, four device profiles, application platform, or user environment.

## Required boundary rules

- Every transition between layers defines inputs, authority, ownership, error behavior, and lifetime.
- User space must not gain privilege through mutable metadata, fabricated handles, or assumptions enforced only by convention.
- The kernel validates resource ownership and authority at every protected boundary.
- An isolated service failure should not automatically compromise unrelated services or the kernel.
- The UI can request or explain an authorization decision but cannot substitute for the enforcement that makes the decision real.
- Cross-boundary IPC must define framing, resource ownership, cancellation, error reporting, and revocation.
- Each compatibility path must be distinguishable and constrained by an explicit policy.

## Current implementation boundary

As of the main-branch snapshot reviewed on 2026-10-28 (`d9b130e84da910da5057f71d924d277573b81bde`):

- The workspace contains a no_std core crate, x86_64 bare-metal kernel, and BIOS image build tool.
- The kernel validates the boot memory map, initializes a fixed-capacity frame allocator, inspects selected boot mappings, and performs guarded page-table operations.
- Selected supervisor-write, NX, mapping-transition, large-page-demotion, direct-map W^X, and asynchronous NMI-transition cases have scoped QEMU acceptance paths in CI. Root admission checks allocator ownership and permanent-reservation state; dedicated QEMU fault injection verifies rejection before a CR3 switch and rejection by the declared-root W^X audit when reservation metadata becomes inconsistent.
- Kernel-created roots, registry lifecycle, CPL 0 switching, and selected teardown/re-zero/reclaim scenarios are exercised. These tests do not constitute Ring 3 execution or independent process isolation.
- The capability crate is a host-testable authorization model, not kernel enforcement.
- Storage, networking, drivers, service management, a general scheduler, user-facing shell, and AI action-control UX are not implemented as a usable system.
- Complete frame-wide W^X, independent Ring 3 isolation, kernel-enforced capabilities, SMP coordination, secure boot, and signed update/recovery mechanisms remain incomplete.

See [implementation status](../project/IMPLEMENTATION_STATUS.md) for the maintained status snapshot and [roadmap](../project/ROADMAP.md) for ordering.

## Change control

A change to a trust boundary, execution layer, public kernel contract, or resource-lifetime model MUST have:
1. An updated specification.
2. A threat and failure analysis.
3. Tests for both allowed and denied operations.
4. A verification entry describing what the tests do and do not prove.
5. An ADR when the architectural decision is consequential or hard to reverse.
