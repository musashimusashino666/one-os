# Architecture Overview

## Status and scope

This document describes the intended system shape.
It also marks which boundaries exist today.

ONE OS starts with a small x86_64 Rust kernel.
It grows incrementally toward a secure, user-controlled environment.

Architecture should minimize privileged code.
Policy, resource ownership, and recovery must remain explicit.

## Target layers

### Hardware and boot

- CPU and device abstractions.
- Firmware and boot protocol.
- Memory-map validation.
- Integrity of the initial image.

**Placement:** firmware, bootloader, and a small kernel handoff contract.

### Kernel core

- Process and address-space control.
- Scheduling primitives.
- Interrupt and exception handling.
- Physical memory and secure object lifecycle.
- Core IPC and kernel-enforced authority.

**Placement:** a capability-oriented microkernel.
The trusted core should remain as small as practical.
This is a long-term target, not the current implementation.

### Authority and isolation

- Capability validation.
- Process boundaries.
- IPC primitives.
- Resource transfer and revocation.

**Placement:** enforcement in the kernel.
Policy and user-facing explanation remain outside it.

### System services

- Storage and filesystems.
- Networking.
- Device management and drivers.
- Service supervision.
- Update orchestration.

**Placement:** isolated user-space services where practical.

### Application runtime

- Native application interfaces.
- Sandboxing and compatibility.
- Virtualized execution paths.

Each path has a separate execution contract.

### User environment

- Shell, desktop, or compositor.
- Settings and permission views.
- Recovery experience.

**Placement:** user space.

### Automation and AI

- Planning and delegated actions.
- Tool access and provenance.
- Audit records.

Automation is untrusted or separately constrained.
It must never bypass the authority model.

## World-class target architecture

The canonical definition is in
[World-Class OS](../vision/WORLD_CLASS_OS.md).

ONE OS targets one coherent platform across four domains:

- PC and workstation.
- Smartphone and mobile.
- Server.
- Embedded and edge.

Security semantics, authority rules, interface contracts,
and evidence policy are shared across these profiles.

Binaries, drivers, interfaces, and scheduling policies may differ.

The target microkernel architecture is recorded in
[ADR-0003](../project/decisions/ADR-0003-capability-microkernel-platform.md).

Filesystems, networking, drivers, service supervision,
update orchestration, user environments, and AI clients
should run in isolated user space where guarantees permit.

Any security-boundary change follows the ADR and acceptance process.

## Target device profiles

### PC and workstation

- Responsiveness and accessibility.
- Productivity and application compatibility.
- Windowing, input, graphics, and audio.
- Peripheral support and recovery UX.

### Mobile

- Energy efficiency and privacy.
- Secure sensor and radio access.
- Power and thermal management.
- Background execution lifecycle.

### Server

- Throughput and tail latency.
- Resource isolation and service continuity.
- SMP, remote TLB, and NUMA where applicable.
- Virtualization and remote operations.

### Embedded and edge

- Bounded resource use.
- Predictable operation.
- Verified timing guarantees where supported.
- Watchdogs, fail-safe states, and long service life.

Profiles are not separate products with unrelated security models.
Each profile requires independent support and acceptance evidence.

## Application and architecture support

Native APIs, POSIX compatibility, WebAssembly, containers,
and virtual machines are distinct execution paths.

Their compatibility, isolation, licensing, and performance
properties must be documented and tested separately.

The initial architecture is x86_64.
AArch64 and other targets require independent validation.

These are long-term targets.
The current bootstrap does not implement the complete
microkernel service architecture or device profiles.

## Required boundary rules

- Every layer transition defines inputs and authority.
- Ownership, errors, and resource lifetimes are explicit.
- User space cannot gain privilege through forged handles.
- Protected operations validate authority in the kernel.
- A service failure must not automatically compromise others.
- UI decisions cannot substitute for kernel enforcement.
- IPC defines framing, ownership, cancellation, and errors.
- Compatibility paths are explicit and policy-constrained.

## Current implementation boundary

This document describes the target architecture, not the current bootstrap.
The current source state, tested scope, exact revision, and limitations
are maintained in
[Implementation Status](../project/IMPLEMENTATION_STATUS.md).

## Change control

A change to a trust boundary, execution layer,
kernel contract, or resource-lifetime model MUST have:

1. An updated specification.
2. Threat and failure analysis.
3. Tests for allowed and denied operations.
4. A verification entry with exclusions.
5. An ADR when the decision is consequential or hard to reverse.
