#!/usr/bin/env python3
"""Validate the dedicated QEMU test for NMI and machine-check IST selection."""

from __future__ import annotations

import argparse
from pathlib import Path

EXPECTED_STATUS = 33  # isa-debug-exit with value 0x10
MARKERS = (
    "ONE OS IST TEST: triggering vector 2 through software INT",
    "ONE OS IST TEST PASS: NMI IST2 stack selection verified",
    "ONE OS IST TEST: triggering vector 18 through software INT",
    "ONE OS IST TEST PASS: Machine Check IST3 stack selection verified",
)
FAILURE_MARKERS = (
    "ONE OS IST TEST FAILED",
    "ONE OS KERNEL PANIC",
    "ONE OS EXCEPTION",
    "ONE OS BOOTSTRAP COMPLETE",
    "ONE OS TSS INIT FAILED",
)


def validate_ist_output(log: str, exit_status: int) -> tuple[bool, str]:
    """Require ordered NMI/MC vector markers, no failures, and exact QEMU status."""
    if exit_status != EXPECTED_STATUS:
        return False, (
            f"unexpected QEMU exit status {exit_status}; "
            f"expected {EXPECTED_STATUS} from isa-debug-exit"
        )

    for marker in FAILURE_MARKERS:
        if marker in log:
            return False, f"failure marker found: {marker}"

    positions: list[int] = []
    for marker in MARKERS:
        if log.count(marker) != 1:
            return False, f"expected exactly one marker: {marker}"
        positions.append(log.find(marker))

    if positions != sorted(positions):
        return False, "NMI and machine-check IST markers are out of order"

    return True, "NMI IST2 and machine-check IST3 stack selection verified"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="QEMU serial log path")
    parser.add_argument("--exit-status", required=True, type=int, help="QEMU command status")
    args = parser.parse_args()

    try:
        log = args.log.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        parser.error(f"cannot read QEMU serial log: {error}")

    valid, message = validate_ist_output(log, args.exit_status)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
