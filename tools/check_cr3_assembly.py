#!/usr/bin/env python3
"""Check optimized x86_64 assembly for the kernel CR3/PGE switch sequence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FUNCTION_NAME = "activate_supervisor_kernel_root"
TYPE_RE = re.compile(r"^\s*\.type\s+([^,\s]+)\s*,\s*@function\b")
FUNCTION_END_RE = re.compile(r"^\s*\.Lfunc_end\d+\s*:")
SIZE_RE_TEMPLATE = r"^\s*\.size\s+{}\s*,"
INSTRUCTION_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9.]*)\s+(.+?)\s*$")


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return the emitted function body or bodies for the activation routine."""
    lines = assembly.splitlines()
    found: list[tuple[str, list[str]]] = []

    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        symbol = match.group(1)
        if FUNCTION_NAME not in symbol:
            continue

        label_re = re.compile(r"^\s*" + re.escape(symbol) + r"\s*:\s*$")
        label_index = next(
            (i for i in range(index + 1, len(lines)) if label_re.match(lines[i])),
            None,
        )
        if label_index is None:
            continue

        size_re = re.compile(SIZE_RE_TEMPLATE.format(re.escape(symbol)))
        end_index = next(
            (
                i
                for i in range(label_index + 1, len(lines))
                if FUNCTION_END_RE.match(lines[i]) or size_re.match(lines[i])
            ),
            len(lines),
        )
        found.append((symbol, lines[label_index + 1 : end_index]))

    return found


def _instruction(raw_line: str) -> tuple[str, str] | None:
    # LLVM x86_64 ELF output is normally AT&T syntax; accept Intel syntax too.
    line = raw_line.split("#", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return None
    match = INSTRUCTION_RE.match(line)
    if not match:
        return None
    return match.group(1).lower(), match.group(2).strip()


def _writes_control_register(raw_line: str, register: str) -> bool:
    parsed = _instruction(raw_line)
    if parsed is None:
        return False
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov"):
        return False

    parts = [part.strip() for part in operands.split(",")]
    if not parts:
        return False
    # AT&T puts the destination last; Intel puts it first.
    destination = parts[-1] if any("%" in part for part in parts) else parts[0]
    return re.fullmatch(r"%?" + re.escape(register), destination, re.IGNORECASE) is not None


def _clears_pge_bit(raw_line: str) -> bool:
    parsed = _instruction(raw_line)
    if parsed is None:
        return False
    mnemonic, operands = parsed
    operands_lower = operands.lower()

    # CR4.PGE is bit 7. AND with -129 clears that bit; accept hexadecimal too.
    if re.fullmatch(r"and(?:b|w|l|q)?", mnemonic):
        if re.search(r"(?<![\w])(?:\$)?-129(?!\d)", operands_lower):
            return True
        if re.search(r"0x0*ffffffffffffff7f\b", operands_lower):
            return True
        if re.search(r"18446744073709551487\b", operands_lower):
            return True
    if re.fullmatch(r"btr(?:b|w|l|q)?", mnemonic):
        return bool(re.search(r"(?:\$)?7\b", operands_lower))
    return False


def validate_function_body(body: list[str]) -> tuple[bool, str]:
    """Require PGE clear -> CR3 write -> PGE restore in optimized code."""
    cr4_writes = [
        index for index, line in enumerate(body) if _writes_control_register(line, "cr4")
    ]
    cr3_writes = [
        index for index, line in enumerate(body) if _writes_control_register(line, "cr3")
    ]

    if len(cr4_writes) < 2:
        return False, f"expected CR4 writes for PGE disable/restore; found {len(cr4_writes)}"
    if not cr3_writes:
        return False, "no actual CR3 write instruction found in activation routine"

    first_cr4_write = cr4_writes[0]
    last_cr4_write = cr4_writes[-1]
    if not any(_clears_pge_bit(line) for line in body[:first_cr4_write]):
        return False, "no instruction clearing CR4.PGE bit 7 before the first CR4 write"
    if not any(first_cr4_write < index < last_cr4_write for index in cr3_writes):
        return False, "CR3 write is not ordered between the PGE disable and restore writes"

    return True, "optimized activation assembly contains PGE clear -> CR3 write -> PGE restore"


def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure the CR3 inline asm retains the compiler memory clobber."""
    match = re.search(
        r'asm!\s*\(\s*"mov\s+cr3\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if match is None:
        return False, 'could not locate the CR3 asm block in address_space.rs'

    body = match.group("body")
    if re.search(r"\bnomem\b", body):
        return False, "CR3 inline asm must not specify nomem"
    if not re.search(r"\bin\(reg\)\s+root_physical\b", body):
        return False, "CR3 inline asm no longer uses the validated root_physical operand"
    return True, "CR3 inline asm preserves the compiler memory-ordering boundary"


def validate_assembly_directory(assembly_dir: Path) -> tuple[bool, list[str]]:
    paths = sorted(assembly_dir.rglob("*.s"))
    if not paths:
        return False, [f"no .s assembly files found under {assembly_dir}"]

    matches: list[tuple[Path, str, list[str]]] = []
    errors: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            errors.append(f"cannot read {path}: {error}")
            continue
        matches.extend((path, symbol, body) for symbol, body in activation_function_bodies(text))

    if not matches:
        return False, errors + [
            f"could not find optimized {FUNCTION_NAME} function in any .s file under {assembly_dir}"
        ]

    for path, symbol, body in matches:
        valid, message = validate_function_body(body)
        if not valid:
            errors.append(f"{path}: {symbol}: {message}")
        else:
            print(f"PASS: {path}: {symbol}: {message}")

    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assembly-dir", required=True, type=Path, help="directory containing optimized .s files")
    parser.add_argument("--source", required=True, type=Path, help="address_space.rs source path")
    args = parser.parse_args()

    valid, messages = validate_assembly_directory(args.assembly_dir)
    if not valid:
        for message in messages:
            print(f"FAIL: {message}", file=sys.stderr)
        return 1
    for message in messages:
        print(f"NOTE: {message}")

    try:
        source = args.source.read_text(encoding="utf-8")
    except OSError as error:
        print(f"FAIL: cannot read {args.source}: {error}", file=sys.stderr)
        return 1

    valid, message = validate_cr3_asm_memory_order(source)
    if not valid:
        print(f"FAIL: {args.source}: {message}", file=sys.stderr)
        return 1
    print(f"PASS: {args.source}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
