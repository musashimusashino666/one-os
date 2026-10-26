# Kernel Virtual-Memory Integration Plan

## Status

This document defines the implementation contract and acceptance tests for the active x86_64 page-table editor. The initial integration is implemented: the kernel connects host-testable map/unmap primitives through checked page-table access, retains ownership tokens for reachable page-table frames, establishes paging control bits, and performs a normal-boot map/access/unmap smoke cycle. Dedicated QEMU cases validate supervisor write protection, NX instruction-fetch protection, and recoverable map/unmap/remap transitions with exact fault metadata and local TLB checks. These tests establish only the documented behavior in the CI QEMU environment, not SMP safety, general-purpose virtual-memory management, process isolation, or correctness across untested hardware.

The active mapping contract remains single-CPU with maskable interrupts disabled. Empty intermediate-table reclamation, cross-CPU TLB shootdowns, and independent user address spaces are not implemented. The required acceptance suite must pass on the exact PR candidate for changes affecting this contract; use the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml) for revision-specific evidence.

## Current baseline

- `oneos-core` provides host-testable `map_4k` and `unmap_4k` operations through
  `PageTableEditor`.
- The mutation helpers validate four-level canonical addresses, alignment, physical
  address width, ancestor permissions, and large-page conflicts; enforce W^X at the
  leaf; and roll back intermediate-table allocations on allocation failure.
- `kernel/src/paging.rs` inspects bootloader mappings and now contains a guarded
  `PageTableEditor` for active four-level page tables. It resolves reachable tables
  through recursive aliases and accesses only owned, unpublished Usable frames through
  a verified writable physical-memory-offset mapping.
- `kernel/src/memory.rs` allocates physical frames from bootloader-designated Usable
  memory. A returned `Frame` is an owned, non-`Copy` token; its physical address
  alone is not the ownership token.
- The kernel establishes `CR0.WP` and `EFER.NXE`, and the normal QEMU boot path
  performs an active map/access/unmap smoke cycle with local TLB invalidation.
- Dedicated QEMU images and required CI steps have been added for supervisor write
  protection (`error_code == 0x3`) and NX instruction fetch (`error_code == 0x11`).
  Their exact fault metadata and terminal `isa-debug-exit` status are checked by a
  separate serial-log validator. The required workflow runs these cases as part of the CI acceptance suite.
- A dedicated map/unmap/remap QEMU image now performs two expected non-present reads,
  recovers only from their exact #PF contexts, verifies the first frame's payload,
  unmaps and re-faults, remaps a distinct frame, and verifies its preloaded different
  payload. Its validator checks both full `error_code == 0x0` values, target CR2,
  exact saved RIPs, recovery order, and terminal QEMU exit status. These tests must
  still pass on the final reviewed head.

## W^X alias lifecycle integration (partial)

The 4 KiB mutation engine now has explicit editor hooks for reserving/committing writable or executable aliases and for retiring them during unmap. The kernel's fixed registry currently holds 64 managed alias records; exhaustion fails closed and does not enable executable mappings. The active kernel editor commits a reservation only after publishing the PTE and invalidates the local TLB before releasing a retiring record. The inactive address-space editor verifies the target root remains inactive and relies on the documented PCID-disabled CR3/PGE switch sequence, which flushes its non-global translations, before completing retirement. A host-testable mutation backend exercises conflict rejection before PTE publication and confirms a denied reservation leaves no stale registry entry.

This is deliberately not a global W^X guarantee. The registry presently accounts for aliases created through the managed 4 KiB mutation APIs; it is not seeded from pre-existing boot mappings, physical-memory-offset/direct-map aliases, inherited upper-half mappings, or every inactive root and large-page extent. The concrete kernel editors still reject new executable mappings. Do not relax that policy until complete reverse-alias accounting, direct-map downgrade/removal, and adversarial W-to-X tests are implemented.

## Goals

1. Use the existing tested mutation algorithms instead of duplicating paging logic in
   the kernel.
2. Add a concrete kernel `PageTableEditor` whose reads and writes are valid for the
   physical table frames and paging levels it receives.
3. Preserve unique ownership of newly allocated page-table frames for as long as the
   tables remain reachable.
4. Establish and check CPU-state, physical-address-width, synchronization, and TLB
   invalidation requirements at the kernel boundary.
5. Validate successful mapping and unmapping, translation and permission outcomes,
   and fail-closed behavior with reproducible host and QEMU tests.

## Required design decisions and invariants

### Page-table access and recursive mapping address resolution

A physical page-table frame address alone is not enough to derive its recursive-map
virtual address. The editor must receive enough path context to identify the table
being accessed. Do not leave this as implicit, mutable out-of-band state.

- Each `map_4k` / `unmap_4k` operation is for one target virtual address. Extend the
  editor callback contract to carry that target virtual address and the current table
  level (or pass an equivalent validated access-path value). Update host test backends
  if the `PageTableEditor` trait is changed.
- For a table already reachable through the active four-level page-table hierarchy,
  derive its recursive alias with
  `recursive_table_page_virtual_address(recursive_index, target_virtual_address, level)`.
  This helper computes the virtual address of the paging-structure page at the given
  level from the target VA's path; it does not reverse-map an arbitrary physical address.
- Derive the entry pointer by checked addition of `entry_index * size_of::<u64>()`
  to that table-page virtual address. Check multiplication/addition overflow, canonical
  form, alignment, valid level/index, and the recursive index before dereferencing.
  The PML4 frame must match CR3. At lower levels, the walker follows entries selected
  by the target VA and passes the child physical frame it just read; reject malformed
  entries, unavailable tables, and repeated physical frames rather than continuing with
  a mismatched or cyclic walk.
- The recursive alias only resolves tables already reachable via the path. A newly
  allocated table frame is not reachable through the recursive mapping until linked
  into a parent entry. Access such unpublished frames through the bootloader-provided
  physical-memory offset only when the frame came from the Usable-only allocator, the
  offset is present, all address arithmetic is checked, and the complete frame is in
  the approved region. Never use that alias as a general-purpose way to access
  Bootloader-owned or unknown frames.
- If the editor cannot establish a safe virtual alias for the exact table it was asked
  to access, it must fail closed before publishing a new mapping. Do not assume a
  physical address can be dereferenced as a virtual address.
- The current `PageTableEditor::write_entry` API returns `()`, so the core primitive
  cannot observe a failed store. Before the first page-table entry is changed, the
  concrete editor must preflight every write destination needed by the operation:
  validate the table frame and index/level, derive and validate the virtual address,
  check alignment and checked offset arithmetic, and prove that the full target table
  page is currently writable through the chosen alias. Newly allocated, unlinked
  tables must be preflighted through the checked Usable-frame access path. Complete
  all fallible alias resolution, allocation, ownership-registry reservation, and
  entry validation before publishing any parent entry. A preflight failure must leave
  existing table entries unchanged and return through the documented error path.
- After successful preflight, `write_entry` is contractually infallible. An unexpected
  memory fault or other violation while performing a store must fail-stop through the
  kernel's exception path; it must never be reported as a successful map/unmap or
  allow execution to continue using a partially modified hierarchy. Preserve the
  current single-CPU, interrupts-disabled mutation precondition until explicit
  synchronization is implemented. If the implementation cannot provide an
  infallible-after-preflight store, change the editor API to return a `Result` and
  implement/test rollback for partial writes; do not return an error while leaving
  published entries or ownership tokens in an ambiguous state.
- Keep the editor's access logic in one implementation and document the safety
  invariants for each unsafe pointer operation.

### Frame ownership, registry capacity, and publication

- Preserve each page-table allocation's `Frame` token. Do not discard the token after
  reading its physical address: dropping it leaks the allocation by design and loses
  the ability to release it correctly.
- The ownership registry must have an explicit capacity and a checked reservation
  path. Before allocating a table frame, reserve a registry slot. If no slot is
  available, return allocation failure without taking a physical frame. If frame
  allocation fails after a slot was reserved, release that empty reservation.
  Store the returned `Frame` token and physical address in the reserved slot before
  returning the physical address from `allocate_table`.
- `allocate_table` must fail closed when either registry capacity or physical frame
  capacity is exhausted. Never return a physical table frame to the core primitive
  unless the editor already retains its ownership token.
- The core primitive allocates all missing intermediate tables before starting its
  page-table writes. If a later allocation/registration fails, every earlier
  unpublished allocation must be released exactly once and the page-table tree must
  remain byte-for-byte unchanged. A registry-capacity failure is the same class of
  pre-publication failure as a physical allocation failure.
- Before active-kernel integration, ensure that newly created intermediate tables are
  fully initialized before they become reachable. Prefer staging all new table
  contents in unlinked frames and publishing the highest missing parent entry only
  after every fallible operation has completed. If the core primitive's publication
  order is changed to support this, retain its existing host-test guarantees for
  rollback, W^X, permissions, and recursive-reference rejection.
- On successful mapping, keep the tokens for published intermediate tables in the
  registry for their full reachable lifetime. On rollback, remove the matching
  unpublished registry entry and free its token exactly once. If an operation requests
  an unknown, duplicate, or already-published frame through the rollback-only
  `free_table` path, do not free it; treat this as an invariant violation and fail
  closed. If the trait is made fallible, propagate and test that error instead.
- The current `PageTableEditor::free_table` callback returns no result. If that
  signature is retained, the concrete editor must fail-stop on an invalid release
  request rather than silently releasing a foreign frame. Consider a fallible
  signature if recovery from editor-internal inconsistencies is required.
- Distinguish page-table frames from mapped data frames. `unmap_4k` clearing a leaf
  must not automatically free the mapped physical frame unless the caller can prove
  that the mapping owns that frame.
- The current `unmap_4k` primitive intentionally retains empty intermediate tables.
  Document this capacity cost. Reclaiming empty tables requires a separately reviewed
  ownership and reachability procedure; do not free a table still referenced elsewhere.

### CPU state, physical addresses, and permissions

- Query the active CPU's supported physical-address width and pass the validated
  value to `PageTableEditor::physical_address_bits`; reject unsupported or
  inconsistent results rather than assuming 52 physical-address bits.
- Establish and verify `CR0.WP` before treating read-only mappings as protection
  against supervisor writes.
- Establish and verify `EFER.NXE` before installing mappings whose NX bit is set.
  If a required CPU feature is unavailable, fail closed before changing active tables.
- Retain the existing W^X policy. Never widen existing ancestor permissions to make a
  requested mapping succeed. Validate both the bits in each entry and the resulting
  effective permissions across the complete walk. For a 4 KiB mapping, effective
  writable and user-accessible permissions require the corresponding bit to be set at
  every level; effective executable permission requires NX=0 at every level. A leaf
  PTE with U/S=0 is supervisor-only even when an ancestor U/S bit is 1.
- Intermediate-entry permissions are address-space aware. New intermediate entries
  for lower-half virtual addresses set PRESENT | WRITABLE | USER_ACCESSIBLE so valid
  user mappings can be created; new intermediate entries for upper-half virtual
  addresses set PRESENT | WRITABLE and keep U/S=0. Reject a user-accessible leaf
  request for an upper-half address. This is required because kernel-half PML4 entries
  are copied into future user address spaces and must remain supervisor-only.
  Host tests cover both policies. For leaf write/NX tests, still inspect the complete
  walk and verify that the intended leaf bit causes the expected hardware fault.
- Serialize page-table mutations. The bootstrap currently has a single CPU with
  maskable interrupts disabled; encode that as an explicit temporary precondition
  rather than pretending it provides SMP safety. Before SMP, add cross-CPU coordination
  and shootdowns.
- Invalidate the local TLB for the target virtual address after every successful
  map or unmap that changes a paging entry, before returning to code that may access
  the address. Treat a previously non-present translation as potentially cached too:
  installing a present mapping is not exempt merely because the prior access faulted.
  Use a checked, documented invalidation operation (for example, `INVLPG` for the
  target VA) and define its ordering relative to entry stores.
- Document that local invalidation is not sufficient for future shared address spaces
  on multiple CPUs; SMP requires coordination and remote TLB shootdowns.
- Do not treat a successful page-table entry write as proof that the CPU is enforcing
  the intended permissions; test the hardware-visible behavior.

## Suggested implementation sequence

1. Extend the editor contract with explicit target-VA/table-level path context so the
   recursive alias is derived deterministically, rather than guessed from a physical
   address.
2. Implement checked recursive-alias addressing for reachable tables and a separate,
   checked physical-memory-offset path for freshly allocated, still-unpublished Usable
   frames.
3. Implement registry-slot reservation and Frame-token retention before returning each
   newly allocated table frame; ensure registry exhaustion rolls back without mutation.
4. Stage new intermediate-table contents before publishing the highest missing parent
   entry. Keep the commit/publish portion free of fallible allocation or validation work.
5. Establish and verify `CR0.WP` and `EFER.NXE`; fail before mutation if a required
   precondition is missing. Integrate `map_4k` / `unmap_4k` without weakening tested
   core semantics.
6. Add dedicated QEMU memory test images for transition/TLB behavior, read-only write
   protection, and NX instruction-fetch protection. Keep fault-injection code out of
   the normal BIOS image and ensure the QEMU CPU configuration exposes NX.
7. Integrate the full required validation into CI and run it on the exact final PR
   head. Preserve the repository's explicit CI trigger policy: after the final push,
   create a fresh PR-context run using the documented Draft-to-Ready transition; do not
   rely on a green result from an earlier head or treat manual dispatch as the merge
   gate unless the repository's required-check policy explicitly says so. Retain logs
   and the result summary.

## Root activation and exception-entry contract

Before creating the replacement kernel root, the activation path reads CR0, CR4, EFER, RFLAGS, and RSP at runtime. It refuses activation unless CR0.PG and CR0.WP are set, EFER.NXE is set, CR4.LA57 and CR4.PCIDE are clear, and RFLAGS.IF is zero. Pure validation helpers cover each rejected CPU state, and the normal QEMU boot validator requires the interrupt/TSS initialization marker.

TSS.RSP0 is populated from the validated bootloader kernel-stack interval; IST1/2/3 are separate static stacks for double fault, NMI, and machine check. Their address and stack alignment contract is explicit, but guard pages are not yet mapped. Do not enable ring 3 or external interrupts based on these bootstrap settings alone. Guard pages, complete privilege-transition frame validation, and hardware-backed entry/return tests remain future work. Static IST stacks must not be described as overflow-protected.

## Current executable-mapping restriction

The generic host-testable mutation engine supports executable mappings only when its
editor explicitly confirms that frame-wide W^X can be maintained. The concrete kernel
editor currently denies new executable mappings: allocator-owned Usable frames retain
a writable physical-memory-offset alias, and the kernel does not yet have complete
reverse-alias tracking or a safe API for downgrading every alias before execution.
This is intentional fail-closed behavior. Do not enable executable user mappings until
all writable aliases, including large-page overlaps and aliases in every address space,
can be accounted for and the required TLB invalidations are completed. The existing
kernel text and boot mappings are outside the guarantees of this new mapping gate and
must not be treated as proof of system-wide frame-wide W^X.

## Acceptance tests

### Host tests

- Preserve and run every existing `oneos-core` test.
- Test the recursive-alias helper with each page-table level and multiple target VAs,
  including canonical boundaries, invalid indices/levels, checked entry-offset
  arithmetic, and alignment requirements.
- [x] Add host-testable fixed-capacity ownership-registry tests covering reserve-before-allocation, full-capacity rejection without invoking allocation, non-Copy token retention, single release of unpublished frames, published-frame retention, duplicate physical-address rejection, invalid/foreign release rejection, and metadata-slot reuse.
- [x] Combine the generic map mutation engine with a registry-backed test editor. Tests verify zeroed newly allocated table pages, slot reservation before allocation, capacity exhaustion for a three-intermediate-table mapping, unchanged root entries on failure, released reservations, and exactly-once token release in reverse allocation order.
- [x] Verify unmap returns the leaf physical address and permissions without calling the table-frame release path or registering/releasing the leaf data frame.
- [x] Add a target-specific integration assertion for the concrete `KernelPageTableEditor`'s physical-memory-offset alias and zero-before-publication path. The `test-vm-transitions` kernel checks all 512 entries through the validated offset alias before the editor returns the table frame; the QEMU log validator requires this assertion to be observed during the active-mapping smoke test before the dedicated transition sequence starts.
- [x] Validate required extended-CPUID leaf availability, NX feature presence, MAXPHYADDR range, CR0.WP, and EFER.NXE through pure host-testable helpers used by the kernel bootstrap; unit tests cover unsupported and valid states, and bootstrap propagates any failure before page-table mutation.

### QEMU integration tests

Use dedicated test images and serial-log validators. A normal boot must remain a
separate path and must still pass the existing repeated-boot and exception checks.
The production/default `page_fault_handler` remains fail-stop; it currently reports
the exception and halts. Do not make ordinary kernel page faults generally recoverable
just to support the transition tests below.

#### Recoverable page faults for transition tests only

The not-present-to-present and unmap-to-remap tests must use a dedicated test image
with a test-only #PF handler. Keep this handler separate from both the normal
fail-stop handler and the read-only-protection test's fail-stop path.

- Arm the handler immediately before one deliberately faulting instruction with the
  exact expected target VA, access type, and a known recovery continuation. Accept a
  fault only while that expectation is armed. Unexpected faults, nested faults, a
  wrong CR2, unexpected error-code bits, or an unexpected saved instruction pointer
  must go through the fail-stop diagnostic path.
- For a deliberately unmapped supervisor data read, require vector 14, CR2 equal to
  the exact target VA, and the full page-fault error code `error_code == 0x0`: P=0
  (not present), W/R=0 (read), U/S=0 (supervisor), RSVD=0, I/D=0, and every other
  defined or reserved error-code bit clear. Compare the complete value, not only a
  bit mask, so protection-key, shadow-stack, SGX, or future extension bits cannot be
  ignored. This exact expected value is part of the declared QEMU CPU/test-access
  contract; if the CPU model or access configuration changes, review the contract
  explicitly rather than weakening the comparison. Record each expected fault exactly
  once.
- Resume only at a known recovery continuation: the handler must update the actual
  saved exception-frame instruction pointer to a dedicated continuation after the
  faulting instruction, or use an equivalently explicit assembly-controlled recovery
  mechanism. Keep the faulting access in a small dedicated assembly sequence so the
  compiler does not assume that the faulting load returned a value. Do not return to
  the same faulting instruction, retry it before mapping, or modify an arbitrary RIP.
- After return from the expected fault, verify that the event was consumed exactly
  once, install the mapping, then perform a fresh read/write through the target VA.
  For the unmap/remap test, use the same controlled recovery mechanism for the
  expected non-present fault between unmap and remap, then map the distinct frame
  and verify its contents. Invalid recovery state must fail-stop.
- Emit a dedicated VM-test success marker only after all transition and TLB checks
  complete. Expected #PF events and failed recovery must never emit the normal
  bootstrap-completion marker.

- Map one allocated data frame into a reserved, previously unmapped canonical virtual
  address; verify the translation, page offset, and effective permissions.
- Write and read a sentinel only through a deliberately writable, non-executable test
  mapping, then unmap it and verify that the virtual address is no longer mapped.
- Verify W^X rejection and that no existing ancestor permissions are widened.
- Verify the not-present-to-present transition in a dedicated test image:
  access a canonical target VA before it is mapped and require the expected #PF with
  P=0; then map a known frame at that same VA, verify the page-table entry is present,
  and immediately read/write a sentinel successfully through the target VA. The map
  operation must invalidate any cached non-present translation before returning.
- Verify unmap and remap at the same target VA: map frame A and confirm its sentinel,
  unmap it and invalidate the target translation, access while unmapped and require a
  non-present #PF, then map distinct frame B at the same VA and immediately read B's
  sentinel successfully. Also verify the new translation points to B, not A. Fail if
  a stale positive or negative translation is observed.
- Add a dedicated QEMU image for supervisor write-protection testing; the current
  page-fault image tests a read from an unmapped address and is not a read-only-write
  protection test. Build and run the new image as a required CI case.
- In that new image, create a present supervisor-readable, supervisor-read-only
  mapping to a known physical data frame and initialize a known sentinel through a
  separate writable alias before removing that writable alias. Before attempting the
  protected write, read the sentinel successfully through the exact target virtual
  address and inspect the complete four-level walk. Require every entry to be present;
  require the PML4E, PDPTE, and PDE to have R/W=1 and NX=0. Do not require their U/S
  bits to be 0 solely to identify the leaf as the restriction under test; upper-half
  intermediates created by the current mapping helper are supervisor-only, while
  existing bootloader ancestors must be checked as actually present. Require the leaf
  PTE to have R/W=0 and U/S=0 and to point to the expected frame. Reject large-page entries in the ancestor path and verify
  `CR0.WP=1`. These checks prove the write denial comes from the leaf PTE's R/W bit,
  rather than an ancestor denying writes, and must pass before the faulting instruction
  executes.
- Attempt the supervisor-mode write using a controlled instruction sequence. The
  dedicated image must use a test-only #PF handler armed for that one target VA and
  known faulting instruction. Require vector 14, CR2 equal to the exact target virtual
  address, the saved RIP equal to the intended write instruction, and complete error
  code `error_code == 0x3`: P=1 (protection violation), W/R=1 (write), U/S=0
  (supervisor), RSVD=0, I/D=0, and all other defined or reserved bits clear. Exact
  equality is required; a masked comparison is insufficient. A fault with P=0, wrong
  CR2/RIP, an unexpected error-code bit, or an ancestor denying writes must fail.
- On that fully matching expected fault only, do not retry or recover to the faulting
  instruction. Emit exactly one `ONE OS VM TEST PASS: supervisor-write-protection`
  marker, then terminate the test through QEMU's `isa-debug-exit` device: launch the
  image with `-device isa-debug-exit,iobase=0xf4,iosize=0x04`, and write the agreed
  success value `0x10` to I/O port `0xf4`. The harness must require the resulting
  QEMU process exit status `33` (=(0x10 << 1) | 1) and the unique success marker.
  This is a controlled terminal pass, not general page-fault recovery. Any unarmed
  fault, wrong vector/CR2/RIP/error code, missing/duplicate marker, timeout, panic,
  or fail-stop path must fail CI. Never emit the normal bootstrap-completion marker.
- Verify NX protection with a dedicated QEMU test image and serial-log validator. The
  image must run under a QEMU CPU configuration that exposes the architectural NX
  capability; absence of NX support is a test/configuration failure, not a skipped test.
  Check the CPU feature before mutation, enable `EFER.NXE`, and read it back to verify
  it is set before installing an NX leaf.
- Prepare a known instruction payload in a data frame through a temporary
  writable alias, then remove that alias before the execution attempt. Map the same
  frame at a dedicated target VA as present, supervisor-only, read-only, and NX. Before
  attempting execution, inspect the complete four-level walk. Require every entry to
  be present; require the PML4E, PDPTE, and PDE to have NX=0 (execution permitted at
  all ancestor levels) and R/W=1. Newly created upper-half ancestors are supervisor-only
  by the current address-aware policy; verify the actual ancestor U/S bits without using
  them as the cause of the NX denial. Require the target PTE to point to the expected
  frame with NX=1, R/W=0, and U/S=0. Reject large-page entries in the ancestor path.
  This proves that the leaf PTE's NX bit, rather than an ancestor NX bit, prevents
  instruction fetch; the leaf U/S bit also ensures the effective mapping is
  supervisor-only. Ensure the exception handler,
  recovery continuation, stack, and serial code are not in the target page.
- Arm a narrowly scoped test-only page-fault expectation immediately before a
  controlled indirect branch to the exact target VA. Require vector 14, `CR2` equal
  to that VA, and the saved instruction pointer equal to the attempted target VA.
  Require the complete error code `error_code == 0x11`: P=1 (protection violation),
  W/R=0 (instruction fetch is not a data write), U/S=0 (supervisor), RSVD=0, and
  I/D=1, with every other defined or reserved error-code bit clear. Do not accept
  `(error_code & 0x1f) == 0x11` as sufficient; it ignores higher bits. The exact value
  is required for the declared QEMU CPU model and ordinary non-SGX, non-shadow-stack
  target access; any extra bit must fail until explicitly reviewed and specified.
- Recover only from that one armed, fully matching NX fault by replacing the actual
  saved exception-frame instruction pointer with a known continuation. Any wrong
  vector, `CR2`, saved RIP, error-code bit, nested/unarmed fault, or invalid recovery
  state must fail-stop. The target payload should cause a distinct fatal outcome (for
  example, `UD2`) if it is ever executed; if NX enforcement is absent, the test must
  fail rather than appear successful. Emit the NX success marker only after the handler
  confirms the expected fault exactly once and the continuation verifies all checks.
  Do not use the ordinary bootstrap-completion marker as a test result.
- Keep the future supervisor read-only write-protection test on its specified
  fail-stop path; do not make ordinary page faults or that test generally recoverable
  to support the NX test. The read-only write test and NX test must be explicit,
  dedicated QEMU images and separate required CI cases. The NX handler belongs only
  in its dedicated fault-injection image.
- Verify allocation/translation failures halt or return through the documented error
  path without publishing dangling entries or incorrectly freeing owned frames.
- Record the TLB behavior for both successful map and unmap. The two transition tests
  above must pass on the exact reviewed commit; a page-table update without the
  required invalidation is a test failure.
- Run formatting, all core tests, Clippy with warnings denied, kernel checks, image
  creation, the serial-log unit tests, repeated normal boots, exception tests, and the
  new memory-specific QEMU tests, including the NX instruction-fetch test.

## Validation and CI contract

PR #11 implements the initial active-kernel editor and smoke cycle, and adds dedicated
supervisor-write-protection, NX, and map/unmap/remap test images; narrowly armed
test-only fault handlers; exact serial validators; required CI steps; retained QEMU
logs; and host-testable fixed-capacity frame ownership registry logic. For each
reviewed revision, consult the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml)
and require a green result for the exact PR candidate. The transition test
verifies exact non-present fault metadata, recovery order, remapping to a distinct
physical frame, observable TLB behavior, and the checked-alias zero-before-publication
assertion.

- Integrate every acceptance test below into the required GitHub Actions check;
  do not leave memory-safety tests as manual-only checklist items. Preserve the
  repository's current trigger policy, which intentionally omits
  `pull_request.synchronize`: after the final code push, transition the PR from Draft
  to Ready for review to create a fresh PR-context run for that exact head. A green run
  for an earlier commit does not validate the new head. A `workflow_dispatch` run is
  diagnostic and must not be assumed to satisfy the required PR-context check.
- The required job builds the normal boot image and each dedicated memory-test image,
  runs all `oneos-core` tests, formatting, Clippy with warnings denied, kernel checks,
  image creation, serial-log validator tests, repeated normal boots, existing exception
  tests, supervisor write-protection, NX instruction-fetch, and map/unmap/remap
  transition/TLB QEMU tests. The ordinary unmapped-read #PF image does not replace the
  separate supervisor write-protection case.
- Serial-log validators must fail the job on timeout, panic/fail-stop, unexpected
  exceptions, missing or duplicate test success markers, an incorrect recovery path,
  or the normal bootstrap-completion marker being used in place of a memory-test
  success marker. For the supervisor write-protection case, the expected #PF is a
  controlled terminal pass only after vector, CR2, saved RIP, and complete
  `error_code == 0x3` validation: require its unique success marker and QEMU
  `isa-debug-exit` status 33 together. Do not classify this one explicitly validated
  completion as an unexpected fail-stop; every other timeout/fail-stop remains failure.
  A missing NX CPU feature or an unavailable test image must fail explicitly; it must
  not silently skip the NX acceptance test.
- For the exact tested commit, publish the full commit SHA and workflow-run URL, plus a
  per-check result for host tests, Clippy, kernel checks, image builds, normal boots,
  exception tests, map/unmap and TLB behavior, read-only protection, and NX protection.
  Retain the relevant QEMU serial logs and validator output as CI artifacts. The
  implementation PR description must summarize these results and disclose any
  unrun test or environment limitation; do not claim the milestone is complete from a
  successful build or host tests alone.

## Exit criteria

M1 may be marked complete only after the active-kernel integration and dedicated QEMU
mapping/protection tests pass on the exact reviewed commit. Host-side algorithm tests
alone, compilation alone, or successful normal boots do not satisfy this milestone.
Document any still-unimplemented reclaim policy, SMP requirement, or untested hardware
behavior without weakening the acceptance criteria.
