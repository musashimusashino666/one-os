#!/usr/bin/env python3
"""Check optimized x86_64 assembly for the kernel CR3/PGE switch sequence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FUNCTION_NAMES = ("activate_supervisor_kernel_root", "switch_address_space")
FUNCTION_NAME = "activate_supervisor_kernel_root"
TYPE_RE = re.compile(r"^\s*\.type\s+([^,\s]+)\s*,\s*@function\b")
FUNCTION_END_RE = re.compile(r"^\s*\.Lfunc_end\d+\s*:")
SIZE_RE_TEMPLATE = r"^\s*\.size\s+{}\s*,"
INSTRUCTION_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9.]*)(?:\s+(.+?))?\s*$")
GPR_RE = re.compile(
    r"^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?|"
    r"e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lhx]|[sd]il|bpl|spl)$",
    re.IGNORECASE,
)


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return emitted function bodies for all CR3-switch routines."""
    lines = assembly.splitlines()
    found: list[tuple[str, list[str]]] = []

    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        symbol = match.group(1)
        if not any(function_name in symbol for function_name in FUNCTION_NAMES):
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


def _instruction(raw_line: str) -> tuple[str, list[str]] | None:
    """Parse a simple emitted instruction, accepting ATT and Intel operand order."""
    line = raw_line.split("#", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return None
    match = INSTRUCTION_RE.match(line)
    if not match:
        return None
    operands = match.group(2)
    return match.group(1).lower(), (
        [part.strip() for part in operands.split(",")] if operands is not None else []
    )


def _att_syntax(operands: list[str]) -> bool:
    return any("%" in part for part in operands)


def _operand_register(operand: str) -> str | None:
    name = operand.strip().lstrip("%").lower()
    if not GPR_RE.fullmatch(name):
        return None

    aliases = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if name in aliases:
        return aliases[name]
    match = re.fullmatch(r"(r\d+)[dwb]?", name)
    if match:
        return match.group(1)
    return name


def _register_name(operand: str) -> str:
    return operand.strip().lstrip("%").lower()


def _source_destination(operands: list[str]) -> tuple[str, str] | None:
    if len(operands) < 2:
        return None
    if _att_syntax(operands):
        return operands[0], operands[-1]
    return operands[-1], operands[0]


def _destination(operands: list[str]) -> str | None:
    if not operands:
        return None
    return operands[-1] if _att_syntax(operands) else operands[0]


def _is_control_register(operand: str, register: str) -> bool:
    """Return whether an operand names the specified x86 control register."""
    return _register_name(operand) == register


def _control_register_write_source(raw_line: str, register: str) -> str | None:
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov"):
        return None
    pair = _source_destination(operands)
    if pair is None:
        return None
    source, destination = pair
    if _register_name(destination) != register:
        return None
    return _register_name(source)


def _pge_clear_destination(raw_line: str) -> str | None:
    """Return a register only for a CR4-derived AND/BTR that safely clears PGE."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if len(operands) != 2:
        return None

    destination = _destination(operands)
    if destination is None:
        return None
    destination_register = _operand_register(destination)
    if destination_register is None:
        return None

    # CR4 is read into a 64-bit GPR. A 32-bit AND would zero-extend its result,
    # destroying bits 32..63; require a 64-bit destination operation instead.
    raw_destination = destination.strip().lstrip("%").lower()
    gpr64 = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    }
    source_operand = operands[0] if _att_syntax(operands) else operands[1]

    if re.fullmatch(r"and(?:q)?", mnemonic):
        if raw_destination not in gpr64:
            return None
        token = source_operand.strip().lstrip("$")
        try:
            immediate = int(token, 0)
        except ValueError:
            return None

        # x86-64 AND r/m64, imm32 sign-extends its immediate. Verify against
        # the effective 64-bit mask. Only PGE (bit 7), LA57 (bit 12), and PCIDE
        # (bit 17) may be cleared: the latter two are checked clear immediately
        # before this path by validate_kernel_root_activation_state().
        if not -(1 << 31) <= immediate < (1 << 31):
            return None
        mask64 = immediate & ((1 << 64) - 1)
        cleared_bits = (~mask64) & ((1 << 64) - 1)
        permitted_clears = (1 << 7) | (1 << 12) | (1 << 17)
        if cleared_bits & (1 << 7) == 0:
            return None
        if cleared_bits & ~permitted_clears:
            return None
        return destination_register

    if re.fullmatch(r"btr(?:q|w)?", mnemonic):
        # BTR changes only the selected bit. BTR r32 is deliberately rejected
        # because writing the 32-bit register clears the upper 32 GPR bits.
        if mnemonic.endswith("w"):
            word_destinations = {
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            }
            if raw_destination not in word_destinations and not re.fullmatch(r"r\d+w", raw_destination):
                return None
        elif raw_destination not in gpr64:
            return None
        try:
            bit_index = int(source_operand.strip().lstrip("$"), 0)
        except ValueError:
            return None
        if bit_index != 7:
            return None
        return destination_register

    return None

def _clobbered_gpr(raw_line: str) -> str | None:
    """Return a destination register for common compiler-emitted write instructions."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if mnemonic.startswith(("cmp", "test", "j", "call", "ret", "push", "nop", "ud2")):
        return None
    if mnemonic.startswith(("mov", "and", "or", "xor", "add", "sub", "shl", "shr",
                            "sar", "sal", "rol", "ror", "not", "neg", "inc", "dec",
                            "lea", "imul", "bts", "btc", "btr", "xchg", "pop")):
        target = _destination(operands)
        if target is None:
            return None
        return _operand_register(target)
    return None


def validate_function_body(body: list[str]) -> tuple[bool, str]:
    """Require every reachable CR3 write to be bracketed by PGE disable/restore."""
    instructions: list[tuple[str, str, list[str]]] = []
    labels: dict[str, int] = {}
    for raw_line in body:
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            labels[stripped[:-1].strip()] = len(instructions)
            continue
        parsed = _instruction(raw_line)
        if parsed is not None:
            mnemonic, operands = parsed
            instructions.append((raw_line, mnemonic, operands))

    if not instructions:
        return False, "activation routine contains no instructions"

    # Build the CFG and analyze both edges of each conditional branch. This is
    # deliberately conservative: any reachable CR3 write must satisfy the
    # protocol, even if another path through the function is safe.
    successors: list[list[int]] = [[] for _ in instructions]
    for index, (_, mnemonic, operands) in enumerate(instructions):
        fallthrough = index + 1 if index + 1 < len(instructions) else None
        target = labels.get(operands[-1].strip()) if mnemonic.startswith("j") and operands else None
        if mnemonic.startswith("jmp"):
            if target is not None:
                successors[index].append(target)
        elif mnemonic.startswith("j"):
            if target is not None:
                successors[index].append(target)
            if fallthrough is not None and fallthrough not in successors[index]:
                successors[index].append(fallthrough)
        elif mnemonic.startswith(("ret", "iret", "ud2", "hlt")):
            continue
        elif fallthrough is not None:
            successors[index].append(fallthrough)

    registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    ]
    reg_index = {name: index for index, name in enumerate(registers)}
    NONE = "-"
    ORIGINAL = "original_cr4"
    CLEARED = "pge_cleared"

    # Protocol stage:
    #   0 = no verified CR4.PGE-clear write
    #   1 = PGE-cleared CR4 has been written; CR3 write is now permitted
    #   2 = CR3 was written; original CR4 must be restored before any exit
    #   3 = original CR4 was restored; completed switch
    def instruction_transfer(
        index: int, tags: tuple[str, ...], stage: int
    ) -> tuple[tuple[str, ...], int]:
        raw_line, mnemonic, operands = instructions[index]
        state = list(tags)

        if mnemonic.startswith("call"):
            # SysV x86-64 caller-saved registers are not preserved by calls.
            for name in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                state[reg_index[name]] = NONE
            return tuple(state), stage

        if mnemonic == "cpuid":
            for name in ("rax", "rbx", "rcx", "rdx"):
                state[reg_index[name]] = NONE
            return tuple(state), stage

        if mnemonic == "rdmsr":
            state[reg_index["rax"]] = NONE
            state[reg_index["rdx"]] = NONE
            return tuple(state), stage

        clear_destination = _pge_clear_destination(raw_line)
        if clear_destination is not None:
            slot = reg_index.get(clear_destination)
            if slot is not None and state[slot] in (ORIGINAL, CLEARED):
                state[slot] = CLEARED
            elif slot is not None:
                state[slot] = NONE
            return tuple(state), stage

        pair = _source_destination(operands) if mnemonic.startswith("mov") else None
        if pair is not None:
            source, destination = pair
            source_register = _operand_register(source)
            destination_register = _operand_register(destination)

            if _is_control_register(destination, "cr4"):
                source_tag = state[reg_index[source_register]] if source_register in reg_index else NONE
                if source_tag == CLEARED and stage in (0, 4):
                    stage = 1
                elif source_tag == ORIGINAL and stage == 1:
                    # Restoring CR4 before CR3 can re-enable PGE on the path.
                    # That path may still return an error safely, but a later
                    # CR3 write on it must not be accepted.
                    stage = 4
                elif source_tag == ORIGINAL and stage == 2:
                    stage = 3
                return tuple(state), stage

            if _is_control_register(destination, "cr3"):
                # The caller checks this edge before transfer; retain this
                # transition only for a path already proven to have PGE clear.
                if source_register in reg_index and stage == 1:
                    stage = 2
                return tuple(state), stage

            if _is_control_register(source, "cr4") and destination_register in reg_index:
                state[reg_index[destination_register]] = ORIGINAL
                return tuple(state), stage

            if destination_register in reg_index:
                destination_slot = reg_index[destination_register]
                state[destination_slot] = (
                    state[reg_index[source_register]]
                    if source_register in reg_index
                    else NONE
                )
            return tuple(state), stage

        clobbered = _clobbered_gpr(raw_line)
        if clobbered in reg_index:
            state[reg_index[clobbered]] = NONE
        if mnemonic.startswith("set") and operands:
            destination = _destination(operands)
            register = _operand_register(destination) if destination else None
            if register in reg_index:
                state[reg_index[register]] = NONE
        if mnemonic.startswith("xchg"):
            for operand in operands:
                register = _operand_register(operand)
                if register in reg_index:
                    state[reg_index[register]] = NONE
        return tuple(state), stage

    saw_clear_instruction = any(
        _pge_clear_destination(raw_line) is not None
        for raw_line, _, _ in instructions
    )
    saw_clear_write = False
    saw_cr3_write = False
    saw_restore_write = False
    saw_completed_switch = False
    unsafe_cr3_path: str | None = None
    incomplete_exit: tuple[int, str] | None = None

    from collections import deque

    initial_tags = tuple(NONE for _ in registers)
    pending = deque([(0, initial_tags, 0)])
    visited: set[tuple[int, tuple[str, ...], int]] = set()
    state_limit = max(100_000, len(instructions) * 4096)

    while pending:
        index, tags, stage = pending.popleft()
        key = (index, tags, stage)
        if key in visited:
            continue
        visited.add(key)
        if len(visited) > state_limit:
            return False, "control-flow path analysis exceeded its state limit"

        raw_line, mnemonic, operands = instructions[index]
        pair = _source_destination(operands) if mnemonic.startswith("mov") else None

        # Reject each unsafe CR3 edge immediately. Do not return success merely
        # because some other path completed the protocol.
        if pair is not None:
            source, destination = pair
            source_register = _operand_register(source)
            source_tag = tags[reg_index[source_register]] if source_register in reg_index else NONE
            if _is_control_register(destination, "cr3"):
                saw_cr3_write = True
                if source_register not in reg_index:
                    unsafe_cr3_path = (
                        f"unrecognized CR3 source at instruction {index}: {raw_line.strip()}"
                    )
                elif stage != 1 and unsafe_cr3_path is None:
                    unsafe_cr3_path = (
                        "reachable CR3 write is not dominated by a PGE-cleared CR4 write "
                        f"(stage={stage}, instruction {index}: {raw_line.strip()})"
                    )
            elif _is_control_register(destination, "cr4") and source_register in reg_index:
                if source_tag == CLEARED:
                    saw_clear_write = True
                elif source_tag == ORIGINAL:
                    saw_restore_write = True

        next_tags, next_stage = instruction_transfer(index, tags, stage)

        # A terminal instruction or a block that falls out of the function
        # cannot leave PGE disabled or CR4 unrestored after a CR3 write.
        is_terminal = mnemonic.startswith(("ret", "iret", "ud2", "hlt")) or not successors[index]
        if is_terminal:
            if next_stage in (1, 2) and incomplete_exit is None:
                incomplete_exit = (
                    next_stage,
                    f"instruction {index}: {raw_line.strip()}",
                )
            if next_stage == 3:
                saw_completed_switch = True
        for successor in successors[index]:
            pending.append((successor, next_tags, next_stage))

    if not saw_clear_instruction:
        return False, "no instruction clearing CR4.PGE bit 7 was found"
    if not saw_clear_write:
        return False, "PGE-cleared value did not reach a CR4 write"
    if not saw_cr3_write:
        return False, "no actual CR3 write instruction found in activation routine"
    if unsafe_cr3_path is not None:
        return False, unsafe_cr3_path
    if incomplete_exit is not None:
        stage, location = incomplete_exit
        if stage == 2:
            return False, (
                "original pre-switch CR4 value was not restored on every CR3-switch exit "
                f"({location})"
            )
        return False, f"CR4.PGE disable path exited before completing CR3 switch ({location})"
    if not saw_restore_write or not saw_completed_switch:
        return False, "original pre-switch CR4 value was not restored on every CR3-switch exit"
    return True, "all reachable CR3 writes are bracketed by PGE disable and original CR4 restore"

def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure every CR3 inline-asm block retains the compiler memory clobber."""
    blocks = re.findall(
        r'asm!\s*\(\s*"mov\s+cr3\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if not blocks:
        return False, "could not locate any CR3 asm block in address_space.rs"

    for index, block in enumerate(blocks, start=1):
        if re.search(r"\bnomem\b", block):
            return False, f"CR3 inline asm block {index} must not specify nomem"
        if not re.search(r"\bin\(reg\)\s+root_physical\b", block):
            return False, (
                f"CR3 inline asm block {index} no longer uses the validated "
                "root_physical operand"
            )
    return True, f"all {len(blocks)} CR3 asm blocks preserve the compiler memory-ordering boundary"


def validate_cr4_asm_pge_order(source: str) -> tuple[bool, str]:
    """Ensure every source-level CR3 switch clears PGE and restores original CR4."""
    blocks = re.findall(
        r'asm!\s*\(\s*"mov\s+cr4\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if len(blocks) < 2 or len(blocks) % 2 != 0:
        return False, "expected paired CR4 asm blocks for every PGE-clear/restore sequence"
    if not re.search(r"cr4_without_pge\s*=\s*cr4\s*&\s*!CR4_PGE\b", source):
        return False, "cr4_without_pge must be derived from cr4 with CR4_PGE cleared"

    for pair_index in range(0, len(blocks), 2):
        disable_block = blocks[pair_index]
        restore_block = blocks[pair_index + 1]
        switch_number = pair_index // 2 + 1
        if not re.search(r"\bin\(reg\)\s+cr4_without_pge\b", disable_block):
            return False, (
                f"CR3 switch sequence {switch_number} must first write the "
                "PGE-cleared cr4_without_pge value"
            )
        if not re.search(r"\bin\(reg\)\s+cr4\b", restore_block):
            return False, (
                f"CR3 switch sequence {switch_number} must restore the original cr4 value"
            )
    return True, f"all {len(blocks) // 2} source CR3 switch sequences clear PGE and restore original CR4"


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
            f"could not find optimized CR3-switch functions {FUNCTION_NAMES!r} "
            f"in any .s file under {assembly_dir}"
        ]

    found_functions = {
        function_name
        for _path, symbol, _body in matches
        for function_name in FUNCTION_NAMES
        if function_name in symbol
    }
    missing_functions = sorted(set(FUNCTION_NAMES) - found_functions)
    if missing_functions:
        errors.append(
            "optimized assembly did not contain required CR3-switch functions: "
            + ", ".join(missing_functions)
        )

    for path, symbol, body in matches:
        valid, message = validate_function_body(body)
        if not valid:
            errors.append(f"{path}: {symbol}: {message}\n--- CR3-switch function body ---\n" + "\n".join(body) + "\n--- end CR3-switch function body ---")
        else:
            print(f"PASS: {path}: {symbol}: {message}")
            for index, line in enumerate(body):
                if re.search(r"\bcr[34]\b", line) or _pge_clear_destination(line) is not None:
                    print(f"ASM[{index:04d}]: {line.strip()}")

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

    valid, message = validate_cr4_asm_pge_order(source)
    if not valid:
        print(f"FAIL: {args.source}: {message}", file=sys.stderr)
        return 1
    print(f"PASS: {args.source}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
