#!/usr/bin/env python3
"""Validate serial output for one controlled ONE OS CPU exception test."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


PANIC_MARKER = "ONE OS KERNEL PANIC"
COMPLETE_MARKER = "ONE OS BOOTSTRAP COMPLETE"
HALTED_MARKER = "ONE OS EXCEPTION HALTED"


@dataclass(frozen=True)
class ExceptionCase:
    trigger: str
    description: str
    vector: str
    error_code: str | None = None
    fault_address: str | None = None


CASES = {
    "ud": ExceptionCase(
        trigger="ONE OS EXCEPTION TEST: triggering invalid opcode",
        description="invalid opcode",
        vector="0x0000000000000006",
    ),
    "gp": ExceptionCase(
        trigger="ONE OS EXCEPTION TEST: triggering general protection fault",
        description="general protection fault",
        vector="0x000000000000000d",
        # Selector 0xffff has index 0x1fff and TI=1: 0xfff8 | 0x4 = 0xfffc.
        error_code="0x000000000000fffc",
    ),
    "pf": ExceptionCase(
        trigger="ONE OS EXCEPTION TEST: triggering page fault",
        description="page fault",
        vector="0x000000000000000e",
        # Supervisor read from a non-present page: P/W/U/RSVD/I-D all zero.
        error_code="0x0000000000000000",
        fault_address="0x0000400000000000",
    ),
}


def _find_after(lines: list[str], expected: str, start: int) -> tuple[int, str | None]:
    """Find an exact expected line after start, preserving order."""
    for index in range(start, len(lines)):
        if lines[index].strip() == expected:
            return index, None
    return -1, f"missing or out-of-order line: {expected}"


def validate_exception_output(
    log: str, exit_status: int, case_name: str
) -> tuple[bool, str]:
    """Validate exception identity, diagnostic fields, order, and fail-stop outcome."""
    if case_name not in CASES:
        return False, f"unknown exception case: {case_name}"
    if exit_status != 124:
        return False, f"unexpected QEMU/timeout exit status {exit_status}; expected 124"
    if PANIC_MARKER in log:
        return False, f"kernel panic marker found: {PANIC_MARKER}"
    if COMPLETE_MARKER in log:
        return False, f"fault-injection image incorrectly reported {COMPLETE_MARKER}"

    lines = log.splitlines()
    case = CASES[case_name]
    expected = [
        case.trigger,
        "ONE OS EXCEPTION",
        f"Exception: {case.description}",
        f"Exception vector: {case.vector}",
    ]

    position = -1
    for line in expected:
        position, error = _find_after(lines, line, position + 1)
        if error:
            return False, error

    # Check all saved machine-state fields, not only a hexadecimal prefix.
    state_patterns = [
        re.compile(r"Instruction pointer: 0x[0-9a-fA-F]{16}"),
        re.compile(r"Code segment: 0x[0-9a-fA-F]{16}"),
        re.compile(r"CPU flags: 0x[0-9a-fA-F]{16}"),
        re.compile(r"Stack pointer: 0x[0-9a-fA-F]{16}"),
        re.compile(r"Stack segment: 0x[0-9a-fA-F]{16}"),
    ]
    state_labels = [
        "Instruction pointer",
        "Code segment",
        "CPU flags",
        "Stack pointer",
        "Stack segment",
    ]
    for label, pattern in zip(state_labels, state_patterns, strict=True):
        found = -1
        for index in range(position + 1, len(lines)):
            if pattern.fullmatch(lines[index].strip()):
                found = index
                break
            if lines[index].strip().startswith(label + ":"):
                return False, f"malformed diagnostic field: {label}"
        if found < 0:
            return False, f"missing or out-of-order diagnostic field: {label}"
        value = int(lines[found].rsplit("0x", 1)[1], 16)
        if label in ("Instruction pointer", "Stack pointer") and value == 0:
            return False, f"diagnostic field must be non-zero: {label}"
        position = found

    if case.error_code is not None:
        position, error = _find_after(
            lines, f"Error code: {case.error_code}", position + 1
        )
        if error:
            return False, error

    if case.fault_address is not None:
        position, error = _find_after(
            lines, f"Fault address (CR2): {case.fault_address}", position + 1
        )
        if error:
            return False, error

    position, error = _find_after(lines, HALTED_MARKER, position + 1)
    if error:
        return False, error

    return True, f"{case_name}: expected exception diagnostics and halt verified"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_exception_output(log, args.exit_status, args.case)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
