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
TABLE_ALLOCATED_PREFIX = "ONE OS VM TABLE FRAME ALLOCATED: "
TABLE_ZERO_PREFIX = "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: "
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


def _physical_frame_markers(
    log: str, prefix: str
) -> tuple[list[str], list[int], str | None]:
    """Read frame-address markers and reject malformed marker lines."""
    pattern = re.compile(rf"^{re.escape(prefix)}(0x[0-9a-fA-F]{{16}})\r?$", re.MULTILINE)
    matches = list(pattern.finditer(log))
    occurrences = [line for line in log.splitlines() if line.startswith(prefix)]
    if len(matches) != len(occurrences):
        return [], [], f"found malformed physical-frame marker for '{prefix.rstrip()}:'"
    values = [match.group(1).lower() for match in matches]
    positions = [match.start() for match in matches]
    return values, positions, None


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

    allocated_frames, allocated_positions, error = _physical_frame_markers(
        log, TABLE_ALLOCATED_PREFIX
    )
    if error:
        return False, error
    verified_frames, verified_positions, error = _physical_frame_markers(
        log, TABLE_ZERO_PREFIX
    )
    if error:
        return False, error
    if not allocated_frames:
        return False, "expected per-frame table-allocation markers"
    if len(set(allocated_frames)) != len(allocated_frames):
        return False, "duplicate physical frame in table-allocation markers"
    if len(set(verified_frames)) != len(verified_frames):
        return False, "duplicate physical frame in table zero-verification markers"
    if allocated_frames != verified_frames:
        return False, (
            "allocated table frames do not match zero-verified frames: "
            f"allocated={len(allocated_frames)}, verified={len(verified_frames)}"
        )
    for index, (allocated_at, verified_at) in enumerate(
        zip(allocated_positions, verified_positions, strict=True)
    ):
        if allocated_at >= verified_at:
            return False, "table frame was verified before its allocation marker"
        if index and verified_positions[index - 1] >= allocated_at:
            return False, "table frame verifications are not paired with allocations in order"

    mapping_smoke_marker = "ONE OS VM MAPPING SMOKE TEST READY"
    mapping_smoke_position = log.find(mapping_smoke_marker)
    transition_start_position = log.find(START_MARKER)
    zero_verified_before_publication = any(
        position < mapping_smoke_position for position in verified_positions
    )
    if mapping_smoke_position < 0 or log.count(mapping_smoke_marker) != 1:
        return False, "expected exactly one successful active-mapping smoke-test marker"
    if mapping_smoke_position >= transition_start_position:
        return False, "active-mapping smoke test must finish before transition tests start"
    if not zero_verified_before_publication:
        return False, (
            "the transition image must verify an individually identified table frame "
            "through the checked offset alias before the mapping smoke test completes"
        )

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

    return True, (f"{len(allocated_frames)} table frames individually zero-verified; " "mapping transitions, exact non-present faults, recovery, remap data, and TLB checks verified")


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
