#!/usr/bin/env python3
"""Verify CR3 writes in the final linked kernel ELF, not only Rust source text."""

from __future__ import annotations

import argparse
from collections import Counter
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

EXPECTED_SYMBOL_ROLES = {
    "one_os_kernel::address_space::activate_supervisor_kernel_root":
        "activate_supervisor_kernel_root",
    "one_os_kernel::address_space::switch_address_space":
        "switch_address_space",
    "one_os_kernel::address_space::switch_address_space_flush_local_tlb":
        "switch_address_space_flush_local_tlb",
}
EXPECTED_FUNCTIONS = tuple(EXPECTED_SYMBOL_ROLES.values())
EXPECTED_CR3_WRITES = len(EXPECTED_FUNCTIONS)

SYMBOL_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+<(?P<symbol>.+)>:\s*$")
INSTRUCTION_RE = re.compile(
    r"^\s*(?P<address>[0-9a-fA-F]+):\s+"
    r"(?:(?:[0-9a-fA-F]{2})\s+)+(?P<instruction>\S.*)$"
)
ATT_CR3_WRITE_RE = re.compile(
    r"^mov[a-z0-9]*\s+.+,\s*%cr3(?:\s|$)", re.IGNORECASE
)
INTEL_CR3_WRITE_RE = re.compile(
    r"^mov[a-z0-9]*\s+cr3\s*,\s*[^,\s]+(?:\s|$)", re.IGNORECASE
)


def _is_cr3_write(instruction: str) -> bool:
    """Recognize decoded MOV instructions whose destination is CR3."""
    normalized = " ".join(instruction.strip().split())
    return bool(
        ATT_CR3_WRITE_RE.match(normalized)
        or INTEL_CR3_WRITE_RE.match(normalized)
    )


def _expected_function(symbol: str) -> str | None:
    """Map only an exact, demangled function symbol to an audited role."""
    return EXPECTED_SYMBOL_ROLES.get(symbol)


def validate_disassembly(disassembly: str) -> tuple[bool, str]:
    """Require one linked CR3 write in each exact reviewed function symbol."""
    current_symbol = "<no enclosing symbol>"
    counts: Counter[str] = Counter()
    writes: list[tuple[str, str, str | None, str]] = []
    errors: list[str] = []

    for line in disassembly.splitlines():
        symbol_match = SYMBOL_RE.match(line)
        if symbol_match is not None:
            current_symbol = symbol_match.group("symbol")
            continue

        instruction_match = INSTRUCTION_RE.match(line)
        if instruction_match is None:
            continue

        instruction = instruction_match.group("instruction").strip()
        if not _is_cr3_write(instruction):
            continue

        address = instruction_match.group("address")
        role = _expected_function(current_symbol)
        writes.append((address, current_symbol, role, instruction))
        if role is None:
            errors.append(
                f"CR3 write at 0x{address} occurs in unreviewed symbol "
                f"{current_symbol!r}: {instruction}"
            )
        else:
            counts[role] += 1

    if len(writes) != EXPECTED_CR3_WRITES:
        errors.append(
            f"expected exactly {EXPECTED_CR3_WRITES} CR3 writes in the linked ELF, "
            f"found {len(writes)}"
        )

    for function in EXPECTED_FUNCTIONS:
        count = counts[function]
        if count != 1:
            errors.append(
                f"expected exactly one linked CR3 write in {function}, found {count}"
            )

    if errors:
        detail = "; ".join(errors)
        write_detail = ", ".join(
            f"0x{address} {symbol}: {instruction}"
            for address, symbol, _role, instruction in writes
        ) or "none"
        return False, f"{detail}; decoded CR3 writes: {write_detail}"

    write_detail = ", ".join(
        f"0x{address} {role}: {instruction}"
        for address, _symbol, role, instruction in writes
    )
    return True, (
        f"linked ELF contains exactly {EXPECTED_CR3_WRITES} CR3 writes, one in each "
        f"reviewed function ({write_detail})"
    )


def inspect_elf(elf: Path, objdump: str = "objdump") -> tuple[bool, str]:
    """Run the system disassembler on the exact linked kernel executable."""
    if not elf.is_file():
        return False, f"kernel ELF does not exist: {elf}"

    executable = shutil.which(objdump)
    if executable is None:
        return False, f"disassembler not found on PATH: {objdump}"

    try:
        result = subprocess.run(
            [executable, "-d", "-C", str(elf)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        return False, f"cannot run disassembler {executable}: {error}"

    if result.returncode != 0:
        return False, (
            f"disassembler failed for {elf} (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )

    valid, message = validate_disassembly(result.stdout)
    return valid, f"{elf}: {message}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path, help="final linked kernel ELF")
    parser.add_argument(
        "--objdump",
        default=os.environ.get("OBJDUMP", "objdump"),
        help="ELF disassembler executable (default: OBJDUMP or objdump)",
    )
    args = parser.parse_args()

    valid, message = inspect_elf(args.elf, args.objdump)
    if not valid:
        print(f"FAIL: {message}", file=sys.stderr)
        return 1

    print(f"PASS: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
