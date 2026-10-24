# User-Space Isolation Plan

## Status and scope

This document defines the implementation contract and acceptance criteria for the first user-space isolation milestone. It is a design and verification plan, not evidence that user-mode execution or process isolation has already been implemented.

The initial target remains x86_64 in the existing BIOS/QEMU environment with four-level paging. The current kernel is a bootstrap: it validates the boot memory map, manages a bounded set of usable physical frames, inspects selected boot mappings, and performs limited active-kernel 4 KiB map/unmap operations. The mapping editor assumes one CPU and maskable interrupts disabled. Independent address spaces, user-mode execution, a scheduler, kernel-enforced capabilities, and IPC are not implemented.

The existing capability types in `oneos-core` remain a host-testable reference authorization model. They must not be treated as an isolation boundary or trusted proof of provenance across process boundaries.

Implementation changes must preserve the current rule that the M1 host tests, Clippy checks, build checks, boot smoke tests, exception tests, and dedicated QEMU memory-protection/TLB acceptance tests pass on the exact reviewed PR head. A passing build or boot is not proof of process isolation.


## Reproducible QEMU test profile

All QEMU boots and acceptance tests used by CI and this plan must use this explicit profile:

```sh
-machine pc-i440fx-8.2,accel=tcg
-cpu qemu64,+nx
-smp 1
-m 128M
```

- `pc-i440fx-8.2` selects a versioned PC machine type rather than a moving `pc` alias.
- `accel=tcg` explicitly selects software emulation instead of relying on the host's accelerator selection.
- `qemu64,+nx` selects a named x86_64 CPU model and explicitly exposes NX. Kernel code must still verify NX support and enable EFER.NXE before relying on NX page-table entries.
- `-smp 1` keeps the guest single-CPU, matching the current paging-mutation contract; `-m 128M` fixes the guest's configured RAM size.

Use this profile for normal boots, exception diagnostics, memory-protection and TLB-transition tests, and the future I3 ring-3 instruction-fetch acceptance tests. Do not substitute QEMU defaults, `-cpu max`, or host passthrough in an individual test. The exact `0x14` and `0x15` page-fault error-code expectations below are valid only for the declared test profile and must be revalidated if it changes. Keep this section and the QEMU arguments in `.github/workflows/ci.yml` synchronized.

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

The first implementation slice adds an ownership-carrying root-frame handle, lower-half virtual-range validation, and a host-testable initializer for an inactive PML4 root. The kernel integration uses a checked recursive alias for the active source root and a verified physical-memory-offset alias for the owned, unpublished destination frame. The source recursive index may be in either canonical half; the initializer omits that source slot and reserves a separate, previously empty upper-half PML4 slot for the new root's supervisor-writable, non-executable self-reference. The normal-boot smoke test preflights the source root and every upper-half entry before writing, clears all lower-half entries, copies only supervisor-only kernel-half entries, verifies the resulting entries, and releases the root while it has never been active. It does not map user leaf pages, switch CR3, invalidate TLB entries, or tear down child tables. The current boot path executes through lower-half kernel mappings, so this root must not be activated until the kernel image, stack, exception state, BootInfo, and all required kernel mappings are available in a supervisor-only kernel half. Do not mark I1 complete until user mapping, permission validation, switching, teardown, rollback, and TLB contracts above are implemented and tested on the exact reviewed commit.

### I2 — Controlled ring 3 transition

Add the smallest kernel-controlled user entry and return path. Keep external interrupts and scheduling out of scope initially. Run a harmless user payload and return to a known kernel continuation through the explicitly reviewed exit mechanism. All register and stack state must be checked, and an unexpected fault must not emit a success marker.

### I3 — Adversarial isolation acceptance tests

Use dedicated QEMU test images or an equivalent deterministic harness to verify that:

1. User code executes at ring 3 and returns through the permitted path.
2. User-mode reads and writes against kernel-only pages fail with the expected fault context.
3. **Kernel instruction-fetch denial:** use a dedicated QEMU image to execute ring-3 code that branches to a known, present, supervisor-only, executable target page. Before the attempt, verify the target translation is present and executable (NX=0), that the effective U/S permissions make it supervisor-only, and that the test target contains a distinct fatal instruction such as `UD2` if the CPU ever executes it. Arm a narrowly scoped user-mode #PF expectation for that target, then require vector 14, `CR2` equal to the target VA, the saved RIP equal to the target VA, and the complete error code exactly `0x15` (P=1, W/R=0, U/S=1, RSVD=0, I/D=1, with all other bits clear for the declared QEMU CPU configuration). On this exact fault, redirect the saved user RIP to a dedicated user-executable recovery stub in the same address space; use the documented fault-recovery and kernel-entry protocol below. Emit the unique marker `ONE OS ISOLATION TEST PASS: ring3-kernel-instruction-fetch-denied` only from the kernel-side test-exit handler, then terminate through `isa-debug-exit` using success value `0x10`; require QEMU exit status 33 and the marker together. A timeout, unexpected #UD, mismatched exception metadata, missing/duplicate marker, or ordinary bootstrap-completion marker must fail the test.
4. **Cross-process private-code fetch denial:** create address spaces A and B. Map a private user-executable code page at the same target VA in B only; in A, verify that VA is non-present before switching to A and attempting an indirect branch to it. Require vector 14, `CR2` equal to the target VA, saved RIP equal to the target VA, and the complete error code exactly `0x14` (P=0, W/R=0, U/S=1, RSVD=0, I/D=1, with all other bits clear for the declared QEMU CPU configuration). The target code in B must contain a distinct fatal outcome if accidentally mapped and executed in A. On the exact armed fault, redirect the saved user RIP to a dedicated user-executable recovery stub in address space A and use the same documented fault-recovery and kernel-entry protocol. Emit the unique marker `ONE OS ISOLATION TEST PASS: cross-process-private-code-fetch-denied` only from the kernel-side test-exit handler, then terminate through `isa-debug-exit` with success value `0x10`; require QEMU exit status 33 and the marker together. This verifies that an executable mapping private to B cannot be fetched through A's address space.
5. Two independently created address spaces cannot read or modify each other's private frames, including when they use the same virtual address for different frames.
6. A user mapping cannot expose a page-table page, a recursive page-table alias, a kernel stack, or another supervisor-only alias.
7. Physical-frame-wide W^X is enforced across aliases: mapping one frame writable at one virtual address and executable at another is rejected in either insertion order, even when the mappings are in different address spaces.
8. W^X checks include kernel/direct-map aliases and any large-page mapping that covers the frame. A writable direct-map alias prevents an executable alias until the writable alias is removed or made read-only and its translation is invalidated.
9. W^X permission transitions are tested: a frame may become executable only after every writable alias is removed/downgraded and the required TLB invalidation completes; stale writable translations must not create a write-to-execute bypass. Multiple read-only aliases may coexist with executable aliases when no writable alias remains.
10. NX, CR0.WP, ancestor permissions, and effective leaf permissions have the documented effect.
11. Switching away from one address space and activating another cannot reuse stale TLB translations from the first address space.
12. Invalid addresses, malformed page tables, allocation failure, and teardown do not publish dangling mappings, free foreign frames, or permit use-after-free through a stale translation.
13. Existing M1 acceptance tests remain green on the same PR head.

For expected faults, validators must check the exact vector, CR2, saved instruction pointer, complete error code, test phase, and terminal status as appropriate to the chosen test. In particular, the supervisor-only instruction-fetch case must distinguish a present-page privilege violation (`error_code == 0x15`) from an NX violation or a not-present fault; the cross-process private-code case must distinguish the expected not-present instruction-fetch fault (`error_code == 0x14`). Each test must have a unique success marker. Missing or duplicate markers, a timeout, an unexpected exception (including execution of the fatal target instruction), a panic, or the ordinary bootstrap-completion marker standing in for a test-specific pass must fail validation.

#### Fault recovery and test termination protocol

A ring-3 #PF handler must not claim to return directly to a kernel continuation merely by changing the saved RIP. A normal `iretq` using a privilege-transition frame whose saved CS selects ring 3 returns to ring 3; it does not switch execution to ring 0. Both instruction-fetch tests above must use this explicit two-stage path:

1. **Validate and prepare recovery in ring 0.** The CPU delivers the user fault through the IDT on a kernel stack selected by the configured TSS privilege-transition stack. The test-only #PF handler must verify the exact armed test phase, vector 14, CR2, faulting saved RIP, complete error code, and a valid privilege-transition frame before changing anything. It may recover only from the exact expected fault. It must verify that the recovery stub is mapped user-executable in the current address space, that its address is canonical, and that the saved user RSP and SS identify the expected mapped user stack and user data selector. It must keep CS/SS/RSP as a valid ring-3 return context, sanitize RFLAGS to the documented user-safe value, and change the saved RIP to the recovery stub. Do not replace the user CS with a kernel CS while reusing a user privilege-transition frame, and do not treat a modified RIP alone as a kernel return.
2. **Return to ring 3, then enter the kernel normally.** Return from the exception with `iretq` using the validated ring-3 frame so the recovery stub executes at CPL 3. The stub must be distinct from the protected target page and mapped user-executable in the current address space. It then invokes a dedicated test-only software-interrupt vector whose IDT gate has DPL 3. That explicit `int imm8` causes a new CPL 3-to-0 transition and uses the configured TSS kernel entry stack; it is the normal kernel-entry path for these tests, not a direct return from the #PF handler. This test-only entry must not be described as the eventual system-call ABI.
3. **Validate the test exit in ring 0.** The test-exit handler must verify kernel-owned state that the exact expected #PF was observed once, that the current test phase matches, and that the saved ring-3 context identifies the expected post-`int` location in the recovery stub, with a valid user stack. It must reject early, duplicate, unarmed, or mismatched exit requests. Only then may the kernel emit the test-specific success marker, write the agreed success value to QEMU's `isa-debug-exit` device, and terminate. User code must not write the debug-exit port directly or be granted I/O privileges to do so.

For each case, the kernel entry stack and saved exception frame must be correctly aligned and fully within the reserved kernel stack bounds. Validate the saved frame's CS and SS privilege levels, RIP, RSP, and any address arithmetic before dereferencing or modifying it. The handler must fail-stop on malformed frames or unexpected exceptions. The test-specific success marker and exit status must be produced only after the second, validated kernel entry; reaching the recovery stub alone is not success.

### I4 — Schedule and IPC only after isolation

After I1–I3 pass, design a minimal scheduler and thread lifecycle around validated kernel-owned contexts. Define IPC framing, length and memory-ownership validation, sender/receiver identity, cancellation, and failure behavior as a separate implementation increment. Before enabling preemption, add tests for context integrity, privilege transitions, stack ownership, cancellation, and failure recovery.

This step may establish IPC transport and message validation, but it does not by itself complete kernel-enforced capability authorization. Do not claim that user-provided identifiers or capability-shaped values are trusted or enforced unless the separate I5 criteria pass.

### I5 — Kernel-enforced capability operations

Implement capability enforcement as a separate milestone after the address-space isolation boundary is established. The kernel must resolve each capability against kernel-owned authority state, determine the calling process from trusted kernel context, and check the requested right at every protected operation. User memory may carry a handle or request value, but its object ID, authority ID, generation, pointer, or serialized token is never proof of provenance or authorization.

Define and test object lifetime, rights attenuation, delegation, revocation, and behavior for outstanding IPC messages or concurrent requests. Numeric identifiers must not be treated as globally unique principals merely because they were allocated by a process-local counter. Missing, stale, foreign, malformed, or forged capabilities must fail closed without performing the protected operation.

Capability-specific acceptance tests must demonstrate denial for wrong-principal and insufficient-rights requests; correct revocation and stale-generation rejection; rejection of forged or modified user tokens; and preservation of object/frame ownership across IPC, cancellation, and teardown. These tests are required before claiming kernel-enforced capabilities, but their completion is not a prerequisite for declaring the narrower I1–I3 address-space isolation tests passed.

## Acceptance criteria for the first user-space isolation milestone

The milestone remains incomplete until all of the following are demonstrated on the exact reviewed commit:

- A kernel-controlled user-mode entry and return path executes successfully in QEMU.
- Independent address spaces are created with validated roots and explicit frame ownership.
- User code is unable to read, write, or execute kernel-only memory or another process's private memory; dedicated QEMU instruction-fetch tests verify denial of a present supervisor-only executable page and of private executable code mapped only in another address space.
- User-entry and address-space APIs reject user-controlled mapping metadata, addresses, lengths, and pointers that would bypass the active address space's memory permissions. This first isolation milestone does not claim that user-supplied object IDs or capability tokens are authenticated or enforced; kernel-enforced capability semantics are a separate later step.
- Effective U/S, R/W, NX, CR0.WP, and EFER.NXE behavior is tested rather than inferred from source-level flags; W^X is enforced across all aliases of the same physical frame, including aliases in other address spaces, kernel/direct-map aliases, and large-page overlaps.
- Address-space switching, unmapping, and teardown have tests for TLB invalidation and stale translations under the stated single-CPU execution model.
- Allocation failure and invalid state fail closed without leaking reachable mappings, freeing foreign frames, or leaving a partially published address space.
- All existing M1 format, test, lint, kernel check, build, normal boot, exception, mapping protection, and TLB-transition checks pass.
- CI evidence identifies the exact commit and reports any test not run or any environment limitation.

Passing this milestone demonstrates only the defined I1–I3 isolation scenarios in the tested QEMU environment. It does not establish SMP safety, general-purpose OS readiness, a complete capability system, production security, or correctness on untested physical hardware. Completing I1–I3 may be reported as completion of the initial user-space isolation phase, but it must not be reported as completion of Roadmap M2.

## Roadmap M2 completion gate

Roadmap M2 is the combined **Isolation and IPC** milestone. Its completion is stricter than the I1–I3 isolation phase criteria above. M2 must remain incomplete until every implementation phase I1–I5 has met its acceptance criteria on the exact reviewed commit:

- **I1–I3 — user-space isolation:** independent address spaces, controlled ring-3 entry/return, kernel-memory and cross-process access denial, physical-frame-wide W^X, correct TLB behavior, fail-closed construction and teardown, and the full existing M1 regression suite.
- **I4 — scheduler, thread lifecycle, and IPC:** a minimal scheduler and lifecycle operating only on validated kernel-owned contexts; IPC messages with validated framing, lengths, sender/receiver identity, and memory ownership; defined cancellation and failure semantics; and tests for context integrity, privilege transitions, stack ownership, malformed messages, invalid pointers, cancellation, and teardown. IPC must be exercised between isolated participants, not satisfied by documenting a format alone.
- **I5 — kernel-enforced capabilities:** each protected operation resolves authority through kernel-owned state and validates the calling principal and requested right. Tests must prove denial of insufficient-rights and wrong-principal requests, rejection of forged/modified/foreign/stale capabilities, correct revocation and stale-generation rejection, and preservation of resource ownership across IPC and teardown.

The M2 exit decision must cite reproducible test evidence for all three groups and the existing M1 suite. Passing I1–I3 alone, implementing IPC transport without enforced authorization, or passing compilation/normal boot does not satisfy M2. If I4 or I5 remains incomplete, report the relevant phase as incomplete and keep the overall M2 checkbox open. These criteria do not claim SMP support; SMP synchronization and remote TLB shootdowns still require a separate design and acceptance suite.

## Related documents

- [Roadmap](ROADMAP.md) — milestone scope and exit criteria.
- [Architecture](ARCHITECTURE.md) — target kernel/services boundaries and current implementation status.
- [Security model](SECURITY.md) — threat model and required future controls.
- [Kernel virtual-memory integration plan](VM_INTEGRATION_PLAN.md) — current page-table editor contract and M1 acceptance suite.
- [Development guide](DEVELOPMENT.md) — reproducible build, CI, and QEMU validation procedure.
