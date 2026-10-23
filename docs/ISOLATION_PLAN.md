# User-Space Isolation Plan

## Status and scope

This document defines the implementation contract and acceptance criteria for the first user-space isolation milestone. It is a design and verification plan, not evidence that user-mode execution or process isolation has already been implemented.

The initial target remains x86_64 in the existing BIOS/QEMU environment with four-level paging. The current kernel is a bootstrap: it validates the boot memory map, manages a bounded set of usable physical frames, inspects selected boot mappings, and performs limited active-kernel 4 KiB map/unmap operations. The mapping editor assumes one CPU and maskable interrupts disabled. Independent address spaces, user-mode execution, a scheduler, kernel-enforced capabilities, and IPC are not implemented.

The existing capability types in `oneos-core` remain a host-testable reference authorization model. They must not be treated as an isolation boundary or trusted proof of provenance across process boundaries.

Implementation changes must preserve the current rule that the M1 host tests, Clippy checks, build checks, boot smoke tests, exception tests, and dedicated QEMU memory-protection/TLB acceptance tests pass on the exact reviewed PR head. A passing build or boot is not proof of process isolation.

## Goals

1. Establish a real privilege boundary between ring 3 user code and ring 0 kernel code.
2. Give each process an independently controlled virtual address space and prevent one process from reading or modifying another process's private memory.
3. Make the kernel, rather than user-provided data or library conventions, authoritative for page mappings, ownership, and access rights.
4. Define safe user-to-kernel entry and return paths before enabling preemption or external interrupts.
5. Preserve explicit frame ownership, fail-closed behavior, W^X, NX enforcement, and correct TLB invalidation.
6. Express isolation properties as reproducible adversarial tests, not as documentation-only assertions.

## Non-goals for the first isolation increment

The first increment must not expand into a general-purpose scheduler, time slicing, SMP support, general IPC, filesystem, network stack, device framework, or GUI. It is acceptable to use a small kernel-controlled test harness to switch between two address spaces and exercise a narrowly scoped user-mode entry/exit path.

Maskable interrupts may remain disabled and the legacy PIC masked during the initial proof of isolation, matching the current bootstrap assumptions. Do not imply that asynchronous preemption, scheduling under interrupts, or SMP safety exists until those execution models have separate designs and tests.

## Security invariants

### 1. Address-space ownership and construction

- Each user process has an independently controlled four-level page-table root. User mappings must not be copied or shared between processes merely because their virtual addresses match.
- Kernel mappings that need to remain available during a user-to-kernel transition may be shared deliberately, but their effective permissions must be supervisor-only. Shared kernel mappings must not expose kernel text, data, stacks, page tables, physical-memory aliases, or recursive page-table aliases to ring 3.
- The construction API must validate the root frame, canonical virtual addresses, alignment, physical-address width, table structure, leaf permissions, and every ancestor permission that determines effective access.
- A recursive page-table mapping must never become a user-accessible route into page-table memory. The recursive entry, root relationship, and all derived aliases must be checked before use.
- A process must not be allowed to choose arbitrary physical frames, edit page-table entries, widen ancestor permissions, or import a root page table from user memory.
- A partially constructed address space must not become active. All fallible allocation, initialization, ownership registration, and permission validation must finish before publication. Failure must leave existing active mappings unchanged and release only allocations still owned by the failed construction.
- Kernel mappings must be checked in every new root. Do not rely on a leaf U/S bit alone if another mapping or alias exposes the same physical page to user mode.

### 2. Effective access permissions

For each mapping, the implementation must verify the effective permissions across the complete page-table walk, not only the leaf entry.

- User access requires the U/S permission to allow user mode at every level. Any supervisor-only level must deny ring 3 access.
- Writable access requires writable permission at every level. Read-only user mappings must remain read-only to user code.
- Executable access requires NX to be clear at every level. When NX is requested, the relevant CPU capability must exist and EFER.NXE must be enabled before the mapping is published.
- Preserve W^X at physical-frame granularity across every live alias, not only within a single leaf entry. For a physical 4 KiB frame, mappings across all address spaces and kernel mappings must never simultaneously provide any writable effective alias and any executable effective alias. A writable mapping at one virtual address plus an executable mapping of the same frame at another address is a W^X violation, even though neither PTE is individually writable-and-executable.
- Track all mappings of each physical frame, using a reverse-mapping registry or an equivalent reviewed mechanism that can establish the effective permissions of every alias. Include kernel mappings, the physical-memory-offset/direct-map alias, shared mappings, every user address space, and aliases overlapping large-page mappings. A 2 MiB or 1 GiB mapping must be treated as an alias of every 4 KiB frame in its physical range. If the implementation cannot enumerate or conservatively constrain all aliases, it must fail closed and must not publish an executable mapping.
- Enforce the physical-frame-wide rule transactionally for map, unmap, remap, and permission changes. Check the proposed effective permissions before publishing page-table entries, and preserve ownership/rollback guarantees on rejection. Checking only a new leaf PTE's W and NX bits is necessary but not sufficient.
- To transition a frame from writable data to executable code, first remove or downgrade every writable alias, then complete the required TLB invalidation before publishing or using an executable alias. A permanently writable kernel direct-map alias must not remain for a frame that is executable elsewhere. If any writable alias or stale writable translation may remain, keep the frame non-executable. An executable frame may have multiple read-only or executable aliases only when no writable alias exists.
- Establish and verify CR0.WP before relying on read-only mappings to protect against supervisor writes.
- Check and establish the required paging CPU state before mutating active page tables. Unsupported or inconsistent CPU state must fail closed.
- A physical address returned by the frame allocator is not itself a usable virtual pointer. It may be dereferenced only through an explicitly validated alias appropriate to the frame's ownership and publication state.

### 3. Physical-frame and mapping lifetime

- Every allocated frame must have one explicit owner represented by an ownership token or an equivalent reviewed ownership record. Keep that ownership for as long as the frame is reachable from a live page table.
- Newly allocated page-table frames must be initialized before they become reachable.
- Keep data-frame ownership distinct from page-table-frame ownership. Removing a leaf mapping does not, by itself, prove that its physical frame can be freed.
- Do not release a frame until every mapping that can reach it has been removed and the required TLB invalidation has completed.
- Rollback and teardown must not free borrowed, shared, foreign, duplicate, or still-published frames.
- Exhaustion, invalid entries, failed alias resolution, or ownership-registry exhaustion must return through a defined failure path without exposing partially published state.

### 4. User-mode entry, exit, and exception handling

- Define and review one explicit x86_64 user-entry/return mechanism before implementation. Document the selected instructions, privilege levels, selectors, saved register state, stack transition, and exception/error paths. Do not combine mechanisms without a reviewed reason.
- Configure a kernel entry stack for the relevant privilege transition using the established GDT/TSS contract. User-controlled RSP must never become the active kernel stack pointer.
- Before entering ring 3, validate that RIP and RSP are canonical and mapped with the intended user permissions; verify the code is executable and the stack is writable and non-executable as appropriate.
- Construct user-visible selectors and RFLAGS from kernel-controlled constants. User code must not receive IOPL or other privileged control state. Document IF and interrupt policy explicitly.
- User-controlled register values, addresses, lengths, syscall numbers, and pointers must be validated at every kernel entry point. Kernel code must not blindly dereference raw user pointers. Future copy-in/copy-out helpers must define behavior for unmapped pages and page-boundary crossing.
- An expected protection test may recover only from its narrowly armed, fully matching exception context. Unexpected, nested, or mismatched faults must fail-stop. An ordinary user fault must never be mistaken for successful boot or successful isolation.
- Do not enable maskable interrupts or schedule an unrelated task from user mode until the entry stack, saved context, exception path, and state restoration are implemented and tested.

### 5. TLB and execution-model constraints

- The initial implementation must keep the current single-CPU, interrupts-disabled mutation assumption explicit. It must not imply SMP safety.
- On address-space switches, define the exact CR3/TLB policy and verify that a translation from the previous address space cannot authorize access in the next one. Do not rely on PCID or global-page behavior unless that feature is deliberately configured and its invalidation rules are covered by tests.
- For unmap, permission downgrade, process teardown, or frame reuse, invalidate any affected translation before the frame or address-space resources can be reused.
- Future SMP support requires a separate design for mutation serialization, concurrent process teardown, and remote TLB shootdowns. Local invalidation is not sufficient evidence for SMP correctness.

### 6. Capability boundary and future IPC

- The kernel must resolve a capability to kernel-owned authority state and check the requested right at the protected operation. A user-provided object ID, authority ID, generation, pointer, or serialized token is not proof of ownership.
- The existing process-local authority counter must not be used as a globally unique process identity or as authentication across address spaces.
- Before general IPC is added, define message framing, length limits, ownership transfer, sender/receiver identity, cancellation, and failure behavior. Validate all lengths and referenced memory at the kernel boundary.
- Capability delegation, revocation, and object lifetime need explicit rules for outstanding messages and concurrent operations. These are future implementation requirements, not features delivered by this document.

## Implementation sequence

### I0 — Contract and test plan

This document is the baseline for implementation PRs. Changes to any invariant require an explicit rationale in the relevant PR and corresponding updates to tests and documentation.

### I1 — Address-space primitives

Add host-testable primitives for constructing, inspecting, switching, and tearing down address spaces as practical for the abstraction. Reuse the existing page-table code instead of duplicating the walk or permission algorithms. Provide tests for invalid roots, non-canonical and unaligned addresses, malformed entries, ancestor-permission conflicts, duplicate mappings, reserved-frame rejection, allocation exhaustion, rollback, and ownership retention.

### I2 — Controlled ring 3 transition

Add the smallest kernel-controlled user entry and return path. Keep external interrupts and scheduling out of scope initially. Run a harmless user payload and return to a known kernel continuation through the explicitly reviewed exit mechanism. All register and stack state must be checked, and an unexpected fault must not emit a success marker.

### I3 — Adversarial isolation acceptance tests

Use dedicated QEMU test images or an equivalent deterministic harness to verify that:

1. User code executes at ring 3 and returns through the permitted path.
2. User-mode read and write attempts against kernel-only pages fail with the expected fault context.
3. Two independently created address spaces cannot read or modify each other's private frames, including when they use the same virtual address for different frames.
4. A user mapping cannot expose a page-table page, a recursive page-table alias, a kernel stack, or another supervisor-only alias.
5. Physical-frame-wide W^X is enforced across aliases: mapping one frame writable at one virtual address and executable at another is rejected in either insertion order, even when the mappings are in different address spaces.
6. W^X checks include kernel/direct-map aliases and any large-page mapping that covers the frame. A writable direct-map alias prevents an executable alias until the writable alias is removed or made read-only and its translation is invalidated.
7. W^X permission transitions are tested: a frame may become executable only after every writable alias is removed/downgraded and the required TLB invalidation completes; stale writable translations must not create a write-to-execute bypass. Multiple read-only aliases may coexist with executable aliases when no writable alias remains.
8. NX, CR0.WP, ancestor permissions, and effective leaf permissions have the documented effect.
9. Switching away from one address space and activating another cannot reuse stale TLB translations from the first address space.
10. Invalid addresses, malformed page tables, allocation failure, and teardown do not publish dangling mappings, free foreign frames, or permit use-after-free through a stale translation.
11. Existing M1 acceptance tests remain green on the same PR head.

For expected faults, validators must check the exact vector, CR2, saved instruction pointer, complete error code, test phase, and terminal status as appropriate to the chosen test. Each test must have a unique success marker. Missing or duplicate markers, a timeout, an unexpected exception, a panic, or the ordinary bootstrap-completion marker standing in for a test-specific pass must fail validation.

### I4 — Schedule and IPC only after isolation

After I1–I3 pass, design a minimal scheduler and thread lifecycle around validated kernel-owned contexts. Keep IPC and kernel-enforced capability operations as separate, reviewable increments. Before enabling preemption, add tests for context integrity, privilege transitions, stack ownership, cancellation, and failure recovery.

## Acceptance criteria for the first user-space isolation milestone

The milestone remains incomplete until all of the following are demonstrated on the exact reviewed commit:

- A kernel-controlled user-mode entry and return path executes successfully in QEMU.
- Independent address spaces are created with validated roots and explicit frame ownership.
- User code is unable to read or write kernel-only memory or another process's private memory.
- The kernel cannot be tricked by user-supplied mappings, pointers, IDs, or authority tokens into granting access outside the active process's rights.
- Effective U/S, R/W, NX, CR0.WP, and EFER.NXE behavior is tested rather than inferred from source-level flags; W^X is enforced across all aliases of the same physical frame, including aliases in other address spaces, kernel/direct-map aliases, and large-page overlaps.
- Address-space switching, unmapping, and teardown have tests for TLB invalidation and stale translations under the stated single-CPU execution model.
- Allocation failure and invalid state fail closed without leaking reachable mappings, freeing foreign frames, or leaving a partially published address space.
- All existing M1 format, test, lint, kernel check, build, normal boot, exception, mapping protection, and TLB-transition checks pass.
- CI evidence identifies the exact commit and reports any test not run or any environment limitation.

Passing this milestone demonstrates only the defined isolation scenarios in the tested QEMU environment. It does not establish SMP safety, general-purpose OS readiness, a complete capability system, production security, or correctness on untested physical hardware.

## Related documents

- [Roadmap](ROADMAP.md) — milestone scope and exit criteria.
- [Architecture](ARCHITECTURE.md) — target kernel/services boundaries and current implementation status.
- [Security model](SECURITY.md) — threat model and required future controls.
- [Kernel virtual-memory integration plan](VM_INTEGRATION_PLAN.md) — current page-table editor contract and M1 acceptance suite.
- [Development guide](DEVELOPMENT.md) — reproducible build, CI, and QEMU validation procedure.
