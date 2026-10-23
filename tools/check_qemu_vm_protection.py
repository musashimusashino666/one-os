#!/usr/bin/env python3
"""Validate one dedicated supervisor-write-protection or NX QEMU test."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


PASS_MARKERS = {
    "supervisor-write-protection": "ONE OS VM TEST PASS: supervisor-write-protection",
    "nx-instruction-fetch": "ONE OS VM TEST PASS: nx-instruction-fetch",
}
EXPECTED_ERROR_CODES = {
    "supervisor-write-protection": "0x0000000000000003",
    "nx-instruction-fetch": "0x0000000000000011",
}
FAILURE_MARKERS = (
    "ONE OS VM TEST FAILED",
    "ONE OS KERNEL PANIC",
    "ONE OS EXCEPTION",
    "ONE OS EXCEPTION HALTED",
    "ONE OS PAGING MUTATION FAILED",
    "ONE OS BOOTSTRAP COMPLETE",
)


def _single_hex_field(log: str, label: str) -> tuple[str | None, str | None]:
    pattern = re.compile(rf"^{re.escape(label)}: (0x[0-9a-fA-F]{{16}})$", re.MULTILINE)
    matches = pattern.findall(log)
    if len(matches) != 1:
        return None, f"expected exactly one '{label}' field, found {len(matches)}"
    return matches[0].lower(), None


def validate_vm_protection_output(
    log: str, exit_status: int, case_name: str
) -> tuple[bool, str]:
    """Require exact fault metadata, one case-specific pass marker, and isa-debug-exit."""
    if case_name not in PASS_MARKERS:
        return False, f"unknown VM protection case: {case_name}"
    if exit_status != 33:
        return False, f"unexpected QEMU exit status {exit_status}; expected 33 from isa-debug-exit"
    for marker in FAILURE_MARKERS:
        if marker in log:
            return False, f"failure marker found: {marker}"

    pass_marker = PASS_MARKERS[case_name]
    if log.count(pass_marker) != 1:
        return False, f"expected exactly one success marker: {pass_marker}"

    target, error = _single_hex_field(log, "ONE OS VM TEST TARGET")
    if error:
        return False, error
    expected_rip, error = _single_hex_field(log, "ONE OS VM TEST EXPECTED RIP")
    if error:
        return False, error
    actual_rip, error = _single_hex_field(log, "Instruction pointer")
    if error:
        return False, error
    error_code, error = _single_hex_field(log, "Error code")
    if error:
        return False, error
    fault_address, error = _single_hex_field(log, "Fault address (CR2)")
    if error:
        return False, error

    expected_error = EXPECTED_ERROR_CODES[case_name]
    if error_code != expected_error:
        return False, (
            f"full page-fault error code mismatch: got {error_code}, "
            f"expected {expected_error}"
        )
    if fault_address != target:
        return False, f"CR2 does not match the target VA: {fault_address} != {target}"
    if actual_rip != expected_rip:
        return False, f"saved RIP does not match the exact faulting instruction: {actual_rip} != {expected_rip}"
    if case_name == "nx-instruction-fetch" and expected_rip != target:
        return False, "NX instruction-fetch saved RIP must equal the target VA"

    # For the NX case, require proof that IRETQ resumed at the known continuation
    # and the caller observed the armed fault before reporting the success marker.
    if case_name == "nx-instruction-fetch":
        recovery_markers = (
            "ONE OS VM TEST NX FAULT MATCHED",
            "ONE OS VM TEST NX RECOVERY VERIFIED",
        )
        recovery_positions = []
        for marker in recovery_markers:
            if log.count(marker) != 1:
                return False, f"expected exactly one NX recovery marker: {marker}"
            recovery_positions.append(log.find(marker))

        diagnostic_end = log.find("Fault address (CR2):")
        if not diagnostic_end < recovery_positions[0] < recovery_positions[1]:
            return False, "NX recovery markers are missing or out of order"

    # Require the positive result to be logged only after every diagnostic field.
    marker_position = log.find(pass_marker)
    for label in (
        "ONE OS VM TEST TARGET",
        "ONE OS VM TEST EXPECTED RIP",
        "Instruction pointer",
        "Error code",
        "Fault address (CR2)",
    ):
        field_position = log.find(label + ":")
        if field_position < 0 or field_position > marker_position:
            return False, f"success marker appeared before diagnostic field: {label}"

    if case_name == "nx-instruction-fetch" and recovery_positions[1] > marker_position:
        return False, "NX recovery was not verified before the success marker"

    return True, f"{case_name}: exact protection fault and isa-debug-exit status verified"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    parser.add_argument("--case", required=True, choices=sorted(PASS_MARKERS))
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_vm_protection_output(log, args.exit_status, args.case)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
