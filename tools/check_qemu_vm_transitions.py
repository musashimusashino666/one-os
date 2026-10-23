#!/usr/bin/env python3
"""Validate the exact QEMU map/unmap/remap and page-fault/TLB transition test."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


FAILURE_MARKERS = (
    "ONE OS VM TEST FAILED",
    "ONE OS KERNEL PANIC",
    "ONE OS EXCEPTION",
    "ONE OS EXCEPTION HALTED",
    "ONE OS PAGING MUTATION FAILED",
    "ONE OS BOOTSTRAP COMPLETE",
)
MATCHED_MARKERS = (
    "ONE OS VM TRANSITION FAULT MATCHED: initial-unmapped",
    "ONE OS VM TRANSITION FAULT MATCHED: after-unmap",
)
RECOVERY_MARKERS = (
    "ONE OS VM TRANSITION RECOVERY VERIFIED: initial-unmapped",
    "ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap",
)
START_MARKER = "ONE OS VM TEST: mapping-transitions"
TABLE_ZERO_MARKER = "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED"
FIRST_MAPPING_MARKER = "ONE OS VM TRANSITION FIRST MAPPING VERIFIED"
SECOND_MAPPING_MARKER = "ONE OS VM TRANSITION REMAP SECOND FRAME VERIFIED"
PASS_MARKER = "ONE OS VM TEST PASS: mapping-transitions"


def _hex_fields(log: str, label: str) -> tuple[list[str], str | None]:
    pattern = re.compile(rf"^{re.escape(label)}: (0x[0-9a-fA-F]{{16}})$", re.MULTILINE)
    values = [value.lower() for value in pattern.findall(log)]
    if not values:
        return [], f"missing or malformed '{label}' diagnostic fields"
    return values, None


def _single_hex_field(log: str, label: str) -> tuple[str | None, str | None]:
    values, error = _hex_fields(log, label)
    if error:
        return None, error
    if len(values) != 1:
        return None, f"expected exactly one '{label}' field, found {len(values)}"
    return values[0], None


def validate_vm_transition_output(log: str, exit_status: int) -> tuple[bool, str]:
    """Require two exact absent-page faults, both recoveries, and final isa-debug-exit."""
    if exit_status != 33:
        return False, f"unexpected QEMU exit status {exit_status}; expected 33 from isa-debug-exit"
    for marker in FAILURE_MARKERS:
        if marker in log:
            return False, f"failure marker found: {marker}"

    if log.count(START_MARKER) != 1:
        return False, f"expected exactly one start marker: {START_MARKER}"
    if log.count(PASS_MARKER) != 1:
        return False, f"expected exactly one success marker: {PASS_MARKER}"
    if log.count("ONE OS VM TRANSITION EXPECTED PAGE FAULT") != 2:
        return False, "expected exactly two controlled transition page faults"

    for marker in MATCHED_MARKERS + RECOVERY_MARKERS:
        if log.count(marker) != 1:
            return False, f"expected exactly one transition marker: {marker}"

    target, error = _single_hex_field(log, "ONE OS VM TRANSITION TARGET")
    if error:
        return False, error
    first_frame, error = _single_hex_field(log, "ONE OS VM TRANSITION FIRST FRAME")
    if error:
        return False, error
    second_frame, error = _single_hex_field(log, "ONE OS VM TRANSITION SECOND FRAME")
    if error:
        return False, error
    first_frame_value = int(first_frame, 16)
    second_frame_value = int(second_frame, 16)
    if first_frame_value == 0 or second_frame_value == 0 or first_frame_value == second_frame_value:
        return False, "transition requires two non-zero, distinct physical frames"
    if first_frame_value % 4096 or second_frame_value % 4096:
        return False, "transition physical frame addresses must be 4 KiB aligned"

    first_expected_rip, error = _single_hex_field(log, "ONE OS VM TRANSITION FIRST EXPECTED RIP")
    if error:
        return False, error
    second_expected_rip, error = _single_hex_field(log, "ONE OS VM TRANSITION SECOND EXPECTED RIP")
    if error:
        return False, error

    actual_rips, error = _hex_fields(log, "Instruction pointer")
    if error or len(actual_rips) != 2:
        return False, error or f"expected two saved-RIP fields, found {len(actual_rips)}"
    error_codes, error = _hex_fields(log, "Error code")
    if error or len(error_codes) != 2:
        return False, error or f"expected two page-fault error codes, found {len(error_codes)}"
    fault_addresses, error = _hex_fields(log, "Fault address (CR2)")
    if error or len(fault_addresses) != 2:
        return False, error or f"expected two CR2 fields, found {len(fault_addresses)}"

    if actual_rips != [first_expected_rip, second_expected_rip]:
        return False, (
            "saved RIP values do not match the exact first/second faulting loads: "
            f"{actual_rips}"
        )
    if error_codes != ["0x0000000000000000", "0x0000000000000000"]:
        return False, f"not-present reads must have full error_code == 0x0: {error_codes}"
    if fault_addresses != [target, target]:
        return False, f"both CR2 values must equal the transition target {target}: {fault_addresses}"

    for marker in (FIRST_MAPPING_MARKER, SECOND_MAPPING_MARKER):
        if log.count(marker) != 1:
            return False, f"expected exactly one mapping verification marker: {marker}"

    first_fault_position = log.find("ONE OS VM TRANSITION EXPECTED PAGE FAULT")
    second_fault_position = log.find(
        "ONE OS VM TRANSITION EXPECTED PAGE FAULT", first_fault_position + 1
    )
    first_mapping_position = log.find(FIRST_MAPPING_MARKER)
    second_mapping_position = log.find(SECOND_MAPPING_MARKER)
    positions = [
        first_fault_position,
        log.find(MATCHED_MARKERS[0]),
        log.find(RECOVERY_MARKERS[0]),
        first_mapping_position,
        second_fault_position,
        log.find(MATCHED_MARKERS[1]),
        log.find(RECOVERY_MARKERS[1]),
        second_mapping_position,
        log.find(PASS_MARKER),
    ]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        return False, "transition faults, mapping verifications, recoveries, and final success are out of order"

    for label in (
        "ONE OS VM TRANSITION TARGET",
        "ONE OS VM TRANSITION FIRST FRAME",
        "ONE OS VM TRANSITION SECOND FRAME",
        "ONE OS VM TRANSITION FIRST EXPECTED RIP",
        "ONE OS VM TRANSITION SECOND EXPECTED RIP",
    ):
        if log.find(label + ":") > first_fault_position:
            return False, f"expected transition metadata must precede the first fault: {label}"

    return True, "mapping transitions, exact non-present faults, recovery, remap data, and TLB checks verified"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_vm_transition_output(log, args.exit_status)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
