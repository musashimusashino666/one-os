# ADR-0002: Keep Page-Table Mutation Single-CPU Until Synchronization Exists

- **Status:** Accepted
- **Date:** 2026-10-27
- **Scope:** page-table mutation, address-space lifecycle, and physical-frame reclamation

## Context

Page-table mutation and frame ownership currently depend on one CPU and maskable interrupts disabled. Local TLB invalidation and root switching do not provide a protocol for other CPUs that may retain stale translations or access a root during teardown.

## Decision

The accepted implementation contract remains single-CPU with maskable interrupts disabled. CI uses a declared one-vCPU QEMU profile. SMP, preemption during sensitive mutation, and remote TLB shootdowns must not be enabled as incidental changes.

Before relaxing the contract, design and test:
- Serialization and lock ordering for mapping changes, allocator operations, ownership registries, root activation, and teardown.
- Per-CPU notification and acknowledgement for required TLB invalidation.
- Safe root lifetime and prevention of frame reuse until all CPUs are quiescent.
- Interrupt/NMI interactions and deadlock behavior.
- Concurrent map/unmap, activation, teardown, ownership transfer, and stale-translation rejection.

## Consequences

The current model is simpler to reason about and test, but it intentionally limits concurrency. Disabling maskable interrupts does not establish SMP safety and must never be described as doing so.

## Revisit when

A separate synchronization protocol has passed adversarial multi-CPU tests on supported hardware or a suitably justified emulator profile, and the documented assumptions are updated with the implementation.
