# Ring 3 Isolation Acceptance Contract

## Status

This is a normative acceptance contract for the first real user-mode isolation milestone. It is not an assertion that Ring 3 execution exists today. Keep the overall process/IPC roadmap milestone open until the isolation, IPC, and kernel-capability gates are each complete.

## Execution model

The initial target is x86_64 four-level paging in the pinned single-vCPU QEMU profile: machine `pc-i440fx-8.2,accel=tcg`, CPU `qemu64,+nx`, `-smp 1`, and `-m 128M`. Keep this profile synchronized with CI and the verification guide.

The initial isolation proof may keep external interrupts masked and scheduling disabled. Do not enable asynchronous preemption until kernel-entry stacks, saved contexts, exception recovery, and state restoration are tested.

## User-mode entry and return

The kernel must construct selectors, RFLAGS, instruction pointer, user stack, kernel entry stack, and saved register state from validated kernel-owned data. Reject non-canonical or unmapped pointers, invalid selectors, privileged IOPL/control state, invalid stack bounds/alignment, and malformed return frames.

User pointers, lengths, syscall numbers, registers, and serialized handles are untrusted at every kernel entry. Copy-in/copy-out helpers must define failure behavior for unmapped pages and ranges crossing page boundaries. A normal user fault must not be mistaken for a successful test or bootstrap completion.

## Adversarial acceptance cases

Dedicated QEMU test images (or an equivalently deterministic harness exercising the real kernel path) must demonstrate:

1. Harmless Ring 3 payload executes and returns through the reviewed kernel-controlled mechanism.
2. User reads and writes to kernel-only pages fault with the expected context.
3. **Fetch from a present supervisor-only executable page is denied.** Verify the target is present and executable, but effectively supervisor-only. Put a distinct fatal instruction such as `UD2` in the target. Arm an exact expected #PF and require vector 14, CR2 equal to target VA, saved RIP equal to target VA, and the complete error code exactly `0x15` for the declared QEMU profile. This distinguishes a user/supervisor privilege violation from an NX or not-present fault.
4. **Fetch from code private to another process is denied.** Map the target VA only in address space B. Verify it is non-present in address space A, switch to A, and branch to it. Require vector 14, CR2 and saved RIP equal to the target VA, and the complete error code exactly `0x14` for the declared profile. The target in B must have a distinct fatal outcome if accidentally executed.
5. Two isolated address spaces using the same VA for different frames cannot read or modify one another's private memory.
6. User mappings cannot expose page-table pages, recursive page-table aliases, kernel stacks, or any supervisor-only alias.
7. W^X rejects a physical frame mapped writable through one alias and executable through another, in either insertion order, across roots and direct-map aliases and across overlapping 4 KiB/2 MiB/1 GiB leaves.
8. NX, CR0.WP, ancestor permissions, effective leaf permissions, root switching, teardown, and stale-TLB behavior match the specified contract.
9. Invalid pointers, malformed page tables, allocation failures, and teardown failures do not publish dangling mappings, free foreign frames, or permit use-after-free through stale translations.
10. A data frame is fully initialized before it becomes user-accessible and is re-zeroed before allocator reuse.
11. Existing VM and bootstrap acceptance tests continue to pass.

## Exact expected-fault recovery

Expected-fault handling must exist only in a dedicated test image. It must be narrowly armed with the test phase, target VA, access type, expected error code, and permitted continuation. Record each event exactly once. Unexpected, nested, unarmed, or mismatched exceptions fail-stop.

For Ring 3 instruction-fetch tests, the page-fault handler executes at CPL 0 on the configured TSS kernel stack. Changing the saved RIP alone does not create a return to CPL 0. Recovery must follow two stages:

1. Validate the exact fault, complete error code, saved user CS/SS/RIP/RSP, and privilege-transition frame. Change only the saved user RIP to a known user-executable recovery stub. Keep a valid ring-3 return frame and sanitize RFLAGS; do not replace the user CS with a kernel CS while reusing a user frame.
2. Return to CPL 3 with `iretq`. The recovery stub then invokes a dedicated test-only software interrupt whose IDT gate has DPL 3. This creates a new, explicit CPL 3-to-0 transition using the TSS entry stack.
3. The kernel-side test-exit handler verifies the kernel-owned test phase, one-shot expected-fault state, and saved user continuation/stack. It alone emits the unique pass marker and triggers QEMU's `isa-debug-exit` success result. User code must not write the debug-exit port or obtain I/O privilege.

The marker and exit status are success only after the second, validated kernel entry. Reaching the user recovery stub alone is not success.

## Test termination and validators

Each case must have a unique marker. The validator must require the marker, expected QEMU exit status, and the expected exception metadata where applicable. Timeout, panic, unexpected #UD, wrong vector/CR2/RIP/error code, missing or duplicate marker, unexpected exit status, or an ordinary bootstrap-completion marker instead of test-specific success must fail the run.

The supervisor-only instruction-fetch case must distinguish exactly `0x15`; the cross-process private-code fetch case must distinguish exactly `0x14`. Compare the full error-code value under the declared CPU/access configuration rather than masking away unexpected bits.

## Capability, IPC, and milestone boundary

The kernel must resolve a capability against kernel-owned authority state and check the calling principal and requested right at each protected operation. A user-provided object ID, authority ID, generation, pointer, or serialized token is not proof of identity or authorization. The process-local counter in the current host model cannot serve as globally unique identity.

Before IPC is trusted, define framing, length limits, sender/receiver identity, memory ownership, resource transfer, cancellation, timeout, process death, and revocation of in-flight requests. Missing, stale, forged, foreign, or insufficient-rights capabilities must fail closed.

Ring 3 isolation acceptance does not by itself complete the broader process/IPC milestone. The broader milestone remains incomplete until a scheduler/thread lifecycle, IPC transport semantics, and kernel-enforced capability operations meet their own adversarial criteria.

## Acceptance reporting

The report must name the exact reviewed commit, QEMU profile, each test image, unique marker, exit status, relevant logs, skipped tests, and limitations. Passing compilation, normal boot, or CPL 0 address-space switching does not satisfy this contract.
