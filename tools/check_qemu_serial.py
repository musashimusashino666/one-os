#!/usr/bin/env python3
"""Validate QEMU serial output for the ONE OS bootstrap smoke test."""

from __future__ import annotations

import argparse
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
ADDRESS_SPACE_READY_MARKER = "ONE OS ADDRESS SPACE ROOT INITIALIZATION READY"
ADDRESS_SPACE_FAILED_MARKER = "ONE OS ADDRESS SPACE ROOT INITIALIZATION FAILED"
ACTIVATION_READY_MARKER = "ONE OS KERNEL ADDRESS SPACE ACTIVATED"
ACTIVATION_FAILED_MARKER = "ONE OS KERNEL ADDRESS SPACE ACTIVATION FAILED"
PANIC_MARKER = "ONE OS KERNEL PANIC"
INVALID_MAP_MARKER = "ONE OS MEMORY MAP INVALID"
EXCEPTION_MARKER = "ONE OS EXCEPTION"


def validate_serial_output(log: str, exit_status: int) -> tuple[bool, str]:
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
    # QEMU is deliberately configured with -no-shutdown and the kernel halts
    # forever, so timeout(1)'s 124 is the expected result of a healthy run.
    if exit_status != 124:
        return False, f"Unexpected QEMU/timeout exit status {exit_status}; expected 124"
    return True, "QEMU reached bootstrap completion without a panic"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_serial_output(log, args.exit_status)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
