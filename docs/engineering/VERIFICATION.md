# Verification Strategy

## Evidence model

ONE OS uses layered evidence. Each layer proves a different scope; no layer substitutes for the others.

| Evidence layer | What it can establish | What it cannot establish alone |
| --- | --- | --- |
| Formatting and static lint | Formatting consistency and selected classes of compiler-detectable issues | Runtime correctness or security |
| Host unit tests | Deterministic behavior of pure/host-testable primitives and failure handling | Real hardware page-table enforcement |
| Bare-metal compilation | The kernel and build tool type-check for the configured target | Successful boot or correct CPU behavior |
| Static assembly validation | Required properties in a specified optimized assembly path | Correctness of all surrounding runtime states |
| QEMU normal boot | Startup and checked bootstrap invariants in the declared guest profile | Ring 3 isolation, SMP safety, hardware coverage |
| QEMU fault/protection tests | Specific faults, permissions, and TLB transitions under declared conditions | General correctness across all mappings or CPUs |
| Independent review and fuzzing | Additional defect discovery within the reviewed scope | Proof of absence of vulnerabilities |

## Current CI contract

The GitHub Actions workflow is the executable definition of automated acceptance. It currently includes formatting, core tests, Clippy for the core/kernel/build tool, kernel checking, CR3 assembly validation, Python validator tests, image build, three independent normal QEMU boots, and dedicated W^X runtime-audit checks. The same workflow includes selected exception, interrupt-stack, supervisor-write-protection, NX, and VM transition acceptance images.

The prescribed guest profile is:

- Machine: `pc-i440fx-8.2,accel=tcg`
- CPU: `qemu64,+nx`
- CPU count: `1`
- RAM: `128M`

The profile must remain consistent between the workflow, commands, and [boot/memory specification](../specs/BOOT_AND_MEMORY.md). Do not change the profile to hide a failing acceptance case.

## Security-sensitive acceptance

Tests should verify both the positive path and the denial path. Depending on the change, this includes:

- Malformed or overlapping memory maps fail before allocation.
- Allocator capacity exhaustion fails predictably and reserved regions are not allocated.
- Invalid page-table roots, entries, address widths, and ownership tokens are rejected.
- W^X audit reports incomplete scope distinctly from a complete clean audit.
- The W^X audit revalidates the active CR3 and exact registered-root set at completion; additions, removals, replacements, or duplicate roots fail closed.
- 4 KiB, 2 MiB, and 1 GiB physical overlaps are checked using effective ancestor permissions and full extents.
- The dedicated QEMU runtime-audit profile injects a writable alias in an inactive root for a frame with a controlled RX alias in the active root; the audit must report the physical overlap, and a second audit after restoring the original PTE must be complete and conflict-free.
- Large-page demotion preserves unrelated attributes and sibling-frame writability.
- Mapping changes invalidate the required local TLB state before frames are reused.
- Failure after a Present bit is cleared fails stop or preserves a recoverable ownership record.
- User-page initialization precedes publication; teardown zeroes data before allocator reuse.
- Cross-process negative tests eventually exercise the real Ring 3 and kernel-enforcement path.

## Reproducibility and reporting

- Record the exact commit SHA, command, guest profile, result, and relevant log artifact.
- A pass on a predecessor commit does not validate a successor commit.
- A missing marker, unexpected exit code, timeout, panic, truncated log, or incomplete inventory must fail the validator where it affects acceptance.
- Do not mark a milestone complete if any required test is skipped or its output is ambiguous.
- State when a result relies on QEMU emulation rather than physical hardware.
- Security claims must cite the acceptance cases that support them and name what those cases exclude.

## Current gaps

Global frame-wide W^X, Ring 3 process isolation, kernel-enforced capabilities, complete IPC, SMP/racing TLB validation, signed updates, and production recovery are not covered by the existing CI as complete system properties. The status and roadmap documents must not imply otherwise.
