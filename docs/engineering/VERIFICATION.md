# Verification Strategy

## Evidence model

ONE OS uses layered evidence.
Each layer proves a different scope.

- **Formatting and lint:** consistency and selected static checks.
  Not runtime correctness or security.
- **Host tests:** deterministic behavior of host-testable primitives.
  Not real hardware page-table enforcement.
- **Bare-metal compilation:** target type-checking.
  Not a successful boot or correct CPU behavior.
- **Assembly validation:** properties of a specified code path.
  Not correctness of every runtime state.
- **QEMU boot:** startup in the declared guest profile.
  Not Ring 3 isolation, SMP safety, or hardware coverage.
- **QEMU fault tests:** selected faults, permissions, and TLB transitions.
  Not correctness across every mapping or CPU.
- **Independent review and fuzzing:** additional defect discovery.
  Not proof that vulnerabilities are absent.

## Current CI contract

The GitHub Actions workflow defines automated acceptance.

It currently runs:

- Formatting and core tests.
- Clippy for core, kernel, and build tooling.
- Kernel target checks.
- CR3 source and optimized-assembly validation.
- Final linked-ELF CR3 write inventory.
- Python validator tests and BIOS image build.
- Three independent normal QEMU boots.
- W^X runtime-audit and CR3 rejection profiles.
- Selected exception, interrupt-stack, supervisor-write,
  NX, and virtual-memory transition tests.

The prescribed QEMU profile is:

- Machine: `pc-i440fx-8.2,accel=tcg`
- CPU: `qemu64,+nx`
- CPU count: `1`
- RAM: `128M`

Keep the profile consistent with
[Boot and Memory](../specs/BOOT_AND_MEMORY.md).
Do not change it to hide a failing acceptance case.

## Security-sensitive acceptance

Tests cover positive and denial paths.
Depending on the change, this includes:

### Memory and ownership

- Malformed or overlapping maps fail before allocation.
- Capacity exhaustion fails predictably.
- Reserved regions are not allocated.
- Invalid roots, entries, and address widths are rejected.
- Foreign and stale ownership tokens are rejected.

### CR3 control

- The final linked kernel ELF is inspected after image build.
- Exactly three CR3 writes must remain.
- Each write must match an exact reviewed symbol.
- Similar symbol names do not satisfy a reviewed role.
- The check currently inspects the normal, non-feature BIOS image.
- Feature-specific QEMU test-image ELFs are not included.

The source policy and optimized-assembly contract are in
[CR3 Write-Site Inventory](../specs/CR3_WRITE_INVENTORY.md).

These checks do not prove whole-program behavior.
They also do not prove complete boot-mapping coverage.

### W^X and paging

- Incomplete audit scope is distinct from a clean audit.
- The W^X audit revalidates the active CR3 and root registry.
- Changed, duplicated, or missing roots fail closed.
- 4 KiB, 2 MiB, and 1 GiB extents are checked.
- Effective ancestor permissions are included.
- Cross-root writable/executable conflicts are injected.
- PTE restoration is checked before a clean re-audit.
- Large-page demotion preserves sibling permissions.
- Local TLB state is invalidated before frame reuse.

The direct-map preflight checks all executable PT_LOAD pages
and their physical-offset aliases before permission changes.
It does not classify all bootloader mappings.
It does not establish transactional W^X across every alias.

The QEMU runtime audit also injects a late preflight failure.
It verifies that earlier mappings remain unchanged.

### Root lifecycle

- Active or allocated roots cannot be unregistered.
- Unowned and permanently reserved roots are rejected.
- Duplicate registrations are rejected.
- Missing registrations are rejected by the real CR3 switch path.
- Initial activation rejects invalid roots before the CR3 write.
- Reservation-state changes fail closed during activation and audit.
- Cleanup preserves ownership on failure.

### Fault and process tests

- Expected faults must match the armed phase and context.
- Unexpected or nested faults fail-stop.
- User-page initialization precedes publication.
- Teardown zeroes data before allocator reuse.
- Cross-process denial tests must use the real Ring 3 path
  when that path is implemented.

## Reproducibility and reporting

- Record the exact commit SHA and command.
- Record the guest profile and result.
- Retain relevant logs and artifacts.
- A predecessor's passing CI does not validate a new commit.
- Missing markers, unexpected status, timeout, panic,
  or incomplete inventory must fail acceptance.
- State when evidence relies on QEMU rather than hardware.
- Security claims name both supporting tests and exclusions.

## Current gaps

The current CI does not establish these system properties:

- Global frame-wide W^X.
- Ring 3 process isolation.
- Kernel-enforced capabilities.
- Complete IPC.
- SMP and racing TLB validation.
- Signed updates and production recovery.

The status and roadmap must not imply otherwise.
