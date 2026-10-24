# Security Review Follow-up — 2026-10-24

## Scope

This note tracks the five findings from the static review of `main` at
`016586022f7a2ce5b23b7bb6627cd375de894736`. It distinguishes API-level hardening
in this change from controls that still require kernel integration and adversarial
runtime tests. It is not a certification or a claim that ONE OS is production-ready.

## Findings and disposition

| Finding | Disposition in this change | Remaining requirement |
| --- | --- | --- |
| P1 — An active address-space root can expose its frame token through `into_frame()`. | The CR3 activation path now returns `ActiveAddressSpaceRoot`. That handle exposes the physical address but no token extraction or conversion back to an inactive root. Dropping it intentionally leaks the allocation rather than making the page reusable. | Keep the active handle owned for its lifetime; add lifecycle/teardown tests before implementing address-space switching or teardown. This remains a single-CPU design. |
| P1 — An uninitialized frame can be mapped as user-readable data. | The safe user-data mapping API now requires `ZeroedFrame`. `initialize_user_frame` returns that type only after a `UserFrameInitializer` reports success and returns the original `Frame` on failure. Tests cover clearing a non-zero payload and preserving ownership on initialization failure. | Implement the real kernel initializer using a validated writable supervisor-only alias, connect it to the kernel user-address-space editor, and add QEMU proof before exposing real user pages. The user mapping API is not yet integrated into a live user process. |
| P1 — Process isolation and capability enforcement are not yet security boundaries. | Not claimed as fixed. The existing capability code remains a host-testable reference model. | Complete independent address spaces, ring-3 entry/return, adversarial memory-access tests, IPC, and kernel-enforced capability checks according to `docs/ISOLATION_PLAN.md`. |
| P2 — SMP/preemption synchronization and remote TLB shootdowns are absent. | Not claimed as fixed. The documented single-CPU, maskable-interrupts-disabled mutation contract remains in force. | Do not enable preemption or SMP until mutation serialization, ownership transitions, address-space teardown, and remote TLB shootdowns have their own design and tests. |
| P2 — Frame-wide W^X and complete boot-mapping validation are not established. | Not claimed as fixed. Executable mapping remains fail-closed in the concrete kernel editor where alias safety cannot be proved; boot inspection remains sampled. | Track direct-map/kernel/user aliases, large-page overlap and effective permissions; test permission transitions and improve the boot inspector's ELF `PT_LOAD` correspondence and coverage. |

## PR #22 review follow-up

The follow-up changes address three additional API-boundary concerns:

- Successful unmap returns a raw Frame, never ZeroedFrame. Every reuse path, including
  reuse in a different address space, must call initialize_user_frame again. A host
  regression test dirties the returned frame with simulated process-A data, reinitializes
  it, and maps it into address space B only after confirming the payload is zero.
- UserFrameInitializer is an unsafe trait with an explicit Safety contract. Implementers
  must use unsafe impl and are responsible for proving complete zeroing through a
  writable supervisor-only alias. The core crate denies unsafe code by default and
  annotates only these explicit contracts.
- ActiveAddressSpaceRoot::from_activated is an unsafe constructor with a Safety contract;
  the architecture layer uses it only after CR3 readback confirms the switched root.
  A compile-fail doc example checks that safe code cannot forge this state.

These are API-level mitigations only. The kernel-backed zeroing adapter and live user
mapping integration remain outstanding, as do process isolation, SMP synchronization,
remote TLB shootdowns and system-wide W^X.

## Validation gate

The required CI suite must pass on the exact latest PR HEAD before merge. It includes
formatting, host tests, Clippy, the bare-metal kernel check/build, optimized CR3
assembly validation, serial-log validation, normal QEMU boots, exception diagnostics,
IST selection, supervisor-write protection, NX protection, and mapping/TLB transitions.

Passing those tests validates only the scenarios actually executed under the configured
single-vCPU QEMU profile. It does not prove general process isolation, SMP safety,
system-wide W^X, correctness on untested hardware, or production readiness.
