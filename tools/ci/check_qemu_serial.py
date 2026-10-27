#!/usr/bin/env python3
"""Validate QEMU serial output for the ONE OS bootstrap smoke test."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ENTRY_STACKS_READY_MARKER = "CPU privilege-entry and emergency stacks configured"
START_MARKER = "ONE OS kernel booted"
COMPLETE_MARKER = "ONE OS BOOTSTRAP COMPLETE"
ALLOCATOR_READY_MARKER = "ONE OS FRAME ALLOCATOR READY"
ALLOCATOR_FAILED_MARKER = "ONE OS FRAME ALLOCATOR FAILED"
PAGING_READY_MARKER = "ONE OS PAGE TABLE INSPECTION READY"
PAGING_FAILED_MARKER = "ONE OS PAGING INSPECTION FAILED"
PAGING_CONTROL_FAILED_MARKER = "ONE OS PAGING CONTROL INITIALIZATION FAILED"
MUTATION_READY_MARKER = "ONE OS VM MAPPING SMOKE TEST READY"
MUTATION_FAILED_MARKER = "ONE OS PAGING MUTATION FAILED"
DEMOTION_READY_MARKER = "ONE OS LARGE PAGE DEMOTION SMOKE TEST READY"
DEMOTION_SKIPPED_MARKER = "ONE OS LARGE PAGE DEMOTION SMOKE TEST SKIPPED (DIRECT MAP ALREADY 4K)"
ADDRESS_SPACE_READY_MARKER = "ONE OS ADDRESS SPACE ROOT INITIALIZATION READY"
ADDRESS_SPACE_FAILED_MARKER = "ONE OS ADDRESS SPACE ROOT INITIALIZATION FAILED"
ACTIVATION_READY_MARKER = "ONE OS KERNEL ADDRESS SPACE ACTIVATED"
ACTIVATION_FAILED_MARKER = "ONE OS KERNEL ADDRESS SPACE ACTIVATION FAILED"
SWITCH_PASS_MARKER = "ONE OS ADDRESS SPACE SWITCH PASS"
SWITCH_FAILED_MARKER = "ONE OS ADDRESS SPACE SWITCH FAILED"
USER_FRAME_ROOT_INDEX_LABEL = "ONE OS USER FRAME ZERO TEST RECURSIVE INDEX"
USER_FRAME_DIRTY_LABEL = "ONE OS USER FRAME ZERO TEST DIRTY"
USER_FRAME_VERIFIED_LABEL = "ONE OS USER FRAME ZERO TEST VERIFIED"
USER_FRAME_PASS_MARKER = "ONE OS USER FRAME ZERO TEST PASS"
USER_FRAME_FAILED_MARKER = "ONE OS USER FRAME ZERO TEST FAILED"
PANIC_MARKER = "ONE OS KERNEL PANIC"
INVALID_MAP_MARKER = "ONE OS MEMORY MAP INVALID"
EXCEPTION_MARKER = "ONE OS EXCEPTION"


def validate_serial_output(
    log: str, exit_status: int, require_large_page_demotion_smoke: bool = False
) -> tuple[bool, str]:
    """Return whether QEMU reached bootstrap completion without panicking."""
    if ALLOCATOR_FAILED_MARKER in log:
        return False, f"Physical frame allocator failure marker found: {ALLOCATOR_FAILED_MARKER}"
    if PAGING_FAILED_MARKER in log:
        return False, f"Page-table inspection failure marker found: {PAGING_FAILED_MARKER}"
    if PAGING_CONTROL_FAILED_MARKER in log:
        return False, f"Paging control initialization failure marker found: {PAGING_CONTROL_FAILED_MARKER}"
    if MUTATION_FAILED_MARKER in log:
        return False, f"Page-table mutation failure marker found: {MUTATION_FAILED_MARKER}"
    if ADDRESS_SPACE_FAILED_MARKER in log:
        return False, f"Address-space root initialization failure marker found: {ADDRESS_SPACE_FAILED_MARKER}"
    if ACTIVATION_FAILED_MARKER in log:
        return False, f"Kernel address-space activation failure marker found: {ACTIVATION_FAILED_MARKER}"
    if SWITCH_FAILED_MARKER in log:
        return False, f"Runtime address-space switch failure marker found: {SWITCH_FAILED_MARKER}"
    if USER_FRAME_FAILED_MARKER in log:
        return False, f"Kernel user-frame zeroing failure marker found: {USER_FRAME_FAILED_MARKER}"
    if INVALID_MAP_MARKER in log:
        return False, f"Invalid boot memory map marker found: {INVALID_MAP_MARKER}"
    if PANIC_MARKER in log:
        return False, f"Kernel panic marker found: {PANIC_MARKER}"
    if any(line.strip() == EXCEPTION_MARKER for line in log.splitlines()):
        return False, f"Unexpected exception marker found: {EXCEPTION_MARKER}"
    start_index = log.find(START_MARKER)
    if start_index < 0:
        return False, f"Kernel startup marker missing: {START_MARKER}"
    entry_stacks_index = log.find(ENTRY_STACKS_READY_MARKER)
    if entry_stacks_index < 0:
        return False, f"CPU privilege-entry stack marker missing: {ENTRY_STACKS_READY_MARKER}"
    if entry_stacks_index > start_index:
        return False, "CPU privilege-entry stacks were configured after kernel startup"
    complete_index = log.find(COMPLETE_MARKER)
    if complete_index < 0:
        return False, f"Bootstrap completion marker missing: {COMPLETE_MARKER}"
    if complete_index < start_index:
        return False, "Bootstrap completion marker appeared before startup marker"
    allocator_index = log.find(ALLOCATOR_READY_MARKER)
    if allocator_index < 0:
        return False, f"Physical frame allocator ready marker missing: {ALLOCATOR_READY_MARKER}"
    if allocator_index < start_index or allocator_index > complete_index:
        return False, "Physical frame allocator marker appeared outside startup/completion markers"
    paging_index = log.find(PAGING_READY_MARKER)
    if paging_index < 0:
        return False, f"Page-table inspection marker missing: {PAGING_READY_MARKER}"
    if paging_index < allocator_index or paging_index > complete_index:
        return False, "Page-table inspection marker appeared outside allocator/completion markers"
    mutation_index = log.find(MUTATION_READY_MARKER)
    if mutation_index < 0:
        return False, f"Active page-table mutation marker missing: {MUTATION_READY_MARKER}"
    if mutation_index < paging_index or mutation_index > complete_index:
        return False, "Active page-table mutation marker appeared outside inspection/completion markers"
    address_space_index = log.find(ADDRESS_SPACE_READY_MARKER)
    if address_space_index < 0:
        return False, f"Address-space root initialization marker missing: {ADDRESS_SPACE_READY_MARKER}"
    if address_space_index < mutation_index or address_space_index > complete_index:
        return False, "Address-space root initialization marker appeared outside mutation/completion markers"
    activation_index = log.find(ACTIVATION_READY_MARKER)
    if activation_index < 0:
        return False, f"Kernel address-space activation marker missing: {ACTIVATION_READY_MARKER}"
    if activation_index < address_space_index or activation_index > complete_index:
        return False, "Kernel address-space activation marker appeared outside root-initialization/completion markers"
    switch_lines = [line for line in log.splitlines() if line.startswith(SWITCH_PASS_MARKER)]
    if len(switch_lines) != 1 or switch_lines[0] != SWITCH_PASS_MARKER:
        return False, f"expected exactly one exact runtime address-space switch success marker: {SWITCH_PASS_MARKER}"
    switch_index = log.find(SWITCH_PASS_MARKER)
    if not activation_index < switch_index < complete_index:
        return False, "Runtime address-space switch marker appeared outside activation/completion markers"
    # QEMU is deliberately configured with -no-shutdown and the kernel halts
    # forever, so timeout(1)'s 124 is the expected result of a healthy run.
    if exit_status != 124:
        return False, f"Unexpected QEMU/timeout exit status {exit_status}; expected 124"

    def single_hex_field(label: str) -> tuple[str | None, str | None]:
        marker_lines = [line for line in log.splitlines() if line.startswith(label)]
        if len(marker_lines) != 1:
            return None, f"expected exactly one '{label}' field, found {len(marker_lines)}"
        match = re.fullmatch(rf"{re.escape(label)}: (0x[0-9a-fA-F]{{16}})", marker_lines[0])
        if match is None:
            return None, f"malformed '{label}' diagnostic field"
        return match.group(1).lower(), None

    recursive_index, error = single_hex_field(USER_FRAME_ROOT_INDEX_LABEL)
    if error:
        return False, error
    if not 256 <= int(recursive_index, 16) < 512:
        return False, "post-activation user-frame test requires an upper-half recursive index"

    dirty_frame, error = single_hex_field(USER_FRAME_DIRTY_LABEL)
    if error:
        return False, error
    zeroed_frame, error = single_hex_field(USER_FRAME_VERIFIED_LABEL)
    if error:
        return False, error
    dirty_value = int(dirty_frame, 16)
    if dirty_value == 0 or dirty_value % 4096:
        return False, "user-frame test requires a nonzero, 4 KiB-aligned physical frame"
    if dirty_frame != zeroed_frame:
        return False, "the initialized ZeroedFrame token must identify the exact dirty physical frame"

    pass_lines = [line for line in log.splitlines() if line.startswith(USER_FRAME_PASS_MARKER)]
    if len(pass_lines) != 1 or pass_lines[0] != USER_FRAME_PASS_MARKER:
        return False, f"expected exactly one exact user-frame success marker: {USER_FRAME_PASS_MARKER}"

    recursive_position = log.find(USER_FRAME_ROOT_INDEX_LABEL + ":")
    dirty_position = log.find(USER_FRAME_DIRTY_LABEL + ":")
    verified_position = log.find(USER_FRAME_VERIFIED_LABEL + ":")
    pass_position = log.find(USER_FRAME_PASS_MARKER)
    if not (
        activation_index < switch_index < recursive_position < dirty_position
        < verified_position < pass_position < complete_index
    ):
        return False, "runtime address-space switching and user-frame zeroing verification must follow CR3 activation in order"

    if require_large_page_demotion_smoke:
        demotion_outcomes = [
            marker for marker in (DEMOTION_READY_MARKER, DEMOTION_SKIPPED_MARKER)
            if marker in log
        ]
        if len(demotion_outcomes) != 1:
            return False, (
                "expected exactly one large-page demotion smoke outcome "
                f"({DEMOTION_READY_MARKER} or {DEMOTION_SKIPPED_MARKER})"
            )
        demotion_marker = demotion_outcomes[0]
        if log.count(demotion_marker) != 1:
            return False, f"expected exactly one large-page demotion smoke marker: {demotion_marker}"
        demotion_index = log.find(demotion_marker)
        mutation_index = log.find(MUTATION_READY_MARKER)
        address_space_index = log.find(ADDRESS_SPACE_READY_MARKER)
        if not mutation_index < demotion_index < address_space_index:
            return False, "Large-page demotion smoke outcome must follow mapping mutation and precede root initialization"

    return True, "QEMU reached bootstrap completion; private-root user-frame zeroing passed without a panic"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    parser.add_argument(
        "--require-large-page-demotion-smoke",
        action="store_true",
        help="require exactly one live-demotion smoke pass/skip marker (normal boot only)",
    )
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_serial_output(
        log, args.exit_status, args.require_large_page_demotion_smoke
    )
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
