#!/usr/bin/env python3
"""Validate QEMU serial output for the ONE OS bootstrap smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path


START_MARKER = "ONE OS kernel booted"
COMPLETE_MARKER = "ONE OS BOOTSTRAP COMPLETE"
PANIC_MARKER = "ONE OS KERNEL PANIC"
INVALID_MAP_MARKER = "ONE OS MEMORY MAP INVALID"
EXCEPTION_MARKER = "ONE OS EXCEPTION\n"


def validate_serial_output(log: str, exit_status: int) -> tuple[bool, str]:
    """Return whether QEMU reached bootstrap completion without panicking."""
    if INVALID_MAP_MARKER in log:
        return False, f"Invalid boot memory map marker found: {INVALID_MAP_MARKER}"
    if PANIC_MARKER in log:
        return False, f"Kernel panic marker found: {PANIC_MARKER}"
    if EXCEPTION_MARKER in log:
        return False, f"Unexpected exception marker found: {EXCEPTION_MARKER.strip()}"
    start_index = log.find(START_MARKER)
    if start_index < 0:
        return False, f"Kernel startup marker missing: {START_MARKER}"
    complete_index = log.find(COMPLETE_MARKER)
    if complete_index < 0:
        return False, f"Bootstrap completion marker missing: {COMPLETE_MARKER}"
    if complete_index < start_index:
        return False, "Bootstrap completion marker appeared before startup marker"
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
