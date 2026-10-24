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
GPR_RE = re.compile(
    r"^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?|"
    r"e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lhx]|[sd]il|bpl|spl)$",
    re.IGNORECASE,
)


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return emitted function bodies for the activation routine."""
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


def _instruction(raw_line: str) -> tuple[str, list[str]] | None:
    """Parse a simple emitted instruction, accepting ATT and Intel operand order."""
    line = raw_line.split("#", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return None
    match = INSTRUCTION_RE.match(line)
    if not match:
        return None
    return match.group(1).lower(), [part.strip() for part in match.group(2).split(",")]


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
    """Return the GPR modified by an AND/BTR that clears CR4.PGE bit 7."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed

    clears_pge = False
    if re.fullmatch(r"and(?:b|w|l|q)?", mnemonic):
        # Compilers may combine adjacent facts. In this routine, PCIDE was
        # already proven clear, so LLVM can combine !CR4_PGE and !CR4_PCIDE
        # into a single immediate such as -131201. Accept any parsed AND
        # immediate whose bit 7 is zero, not only the literal -129.
        for operand in operands:
            token = operand.strip().lstrip("$")
            try:
                mask = int(token, 0)
            except ValueError:
                continue
            if mask & (1 << 7) == 0:
                clears_pge = True
                break
    elif re.fullmatch(r"btr(?:b|w|l|q)?", mnemonic):
        clears_pge = bool(re.search(r"(?:\$)?7\b", ", ".join(operands)))

    if not clears_pge:
        return None
    destination = _destination(operands)
    if destination is None:
        return None
    return _operand_register(destination)


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
    """Verify PGE clear -> CR3 write -> CR4 restore with control-flow-aware data flow."""
    # A textual scan is incorrect for optimized assembly: LLVM can place an
    # early-return epilogue before the successful path, so a POP in that
    # unreachable fall-through region must not kill the CR4 value on a
    # different branch. Build an instruction-level control-flow graph instead.
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

    successors: list[list[int]] = [[] for _ in instructions]
    for index, (raw_line, mnemonic, operands) in enumerate(instructions):
        fallthrough = index + 1 if index + 1 < len(instructions) else None
        target = None
        if mnemonic.startswith("j") and operands:
            target_name = operands[-1].strip()
            target = labels.get(target_name)

        if mnemonic.startswith("jmp"):
            if target is not None:
                successors[index].append(target)
        elif mnemonic.startswith("j"):
            if target is not None:
                successors[index].append(target)
            if fallthrough is not None and fallthrough not in successors[index]:
                successors[index].append(fallthrough)
        elif mnemonic.startswith(("ret", "iret", "ud2", "hlt")):
            pass
        elif fallthrough is not None:
            successors[index].append(fallthrough)

    reachable: set[int] = set()
    work = [0]
    while work:
        index = work.pop()
        if index in reachable:
            continue
        reachable.add(index)
        work.extend(successors[index])

    predecessors: list[list[int]] = [[] for _ in instructions]
    for index in reachable:
        for successor in successors[index]:
            if successor in reachable:
                predecessors[successor].append(index)

    registers = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    }
    for raw_line, mnemonic, operands in instructions:
        for operand in operands:
            register = _operand_register(operand)
            if register is not None:
                registers.add(register)

    TOP = "unknown"
    NONE = "none"
    ORIGINAL = "original_cr4"
    CLEARED = "pge_cleared"

    def unknown_state() -> dict[str, str]:
        return {register: TOP for register in registers}

    def entry_state() -> dict[str, str]:
        return {register: NONE for register in registers}

    def meet(left: dict[str, str], right: dict[str, str]) -> dict[str, str]:
        # Keep a provenance tag only when all incoming paths agree. UNKNOWN is
        # the lattice top and therefore contributes no additional restriction.
        result: dict[str, str] = {}
        for register in registers:
            a = left.get(register, NONE)
            b = right.get(register, NONE)
            if a == b:
                result[register] = a
            elif a == TOP:
                result[register] = b
            elif b == TOP:
                result[register] = a
            else:
                result[register] = NONE
        return result

    def transfer(index: int, incoming: dict[str, str]) -> dict[str, str]:
        raw_line, mnemonic, operands = instructions[index]
        state = dict(incoming)

        if mnemonic.startswith("call"):
            # SysV x86-64 caller-saved registers do not preserve provenance.
            for register in (
                "rax", "rcx", "rdx", "rsi", "rdi",
                "r8", "r9", "r10", "r11",
            ):
                state[register] = NONE
            return state

        if mnemonic == "cpuid":
            for register in ("rax", "rbx", "rcx", "rdx"):
                state[register] = NONE
            return state

        if mnemonic == "rdmsr":
            state["rax"] = NONE
            state["rdx"] = NONE
            return state

        clear_destination = _pge_clear_destination(raw_line)
        if clear_destination is not None:
            source_tag = state.get(clear_destination, NONE)
            if source_tag in (ORIGINAL, CLEARED):
                state[clear_destination] = CLEARED
            elif source_tag == TOP:
                state[clear_destination] = TOP
            else:
                state[clear_destination] = NONE
            return state

        pair = _source_destination(operands) if mnemonic.startswith("mov") else None
        if pair is not None:
            source, destination = pair
            source_register = _operand_register(source)
            destination_register = _operand_register(destination)

            if _is_control_register(destination, "cr4") or _is_control_register(destination, "cr3"):
                return state

            if _is_control_register(source, "cr4") and destination_register:
                state[destination_register] = ORIGINAL
                return state

            if destination_register:
                if source_register:
                    state[destination_register] = state.get(source_register, NONE)
                else:
                    state[destination_register] = NONE
            return state

        # Track common explicit GPR writes. Calls and implicit-register
        # instructions are handled above so saved CR4 provenance survives only
        # where the architecture and ABI guarantee it should.
        clobbered = _clobbered_gpr(raw_line)
        if clobbered:
            state[clobbered] = NONE
        if mnemonic.startswith("set") and operands:
            destination = _destination(operands)
            register = _operand_register(destination) if destination else None
            if register:
                state[register] = NONE
        return state

    in_states = [unknown_state() for _ in instructions]
    out_states = [unknown_state() for _ in instructions]
    in_states[0] = entry_state()

    # The finite provenance lattice converges quickly; the explicit bound
    # protects the validator from malformed or unexpectedly complex input.
    max_iterations = max(32, len(instructions) * len(registers) * 4)
    for _ in range(max_iterations):
        changed = False
        for index in sorted(reachable):
            if index == 0:
                merged = entry_state()
            else:
                incoming_states = [
                    out_states[pred]
                    for pred in predecessors[index]
                    if pred in reachable
                ]
                if not incoming_states:
                    continue
                merged = incoming_states[0]
                for candidate in incoming_states[1:]:
                    merged = meet(merged, candidate)

            if merged != in_states[index]:
                in_states[index] = merged
                changed = True
            outgoing = transfer(index, in_states[index])
            if outgoing != out_states[index]:
                out_states[index] = outgoing
                changed = True
        if not changed:
            break
    else:
        return False, "control-flow provenance analysis did not converge"

    saw_pge_clear = any(
        _pge_clear_destination(raw_line) is not None
        for raw_line, _, _ in instructions
    )
    pge_disable_indices: list[int] = []
    cr3_write_indices: list[int] = []
    pge_restore_indices: list[int] = []

    for index, (raw_line, mnemonic, operands) in enumerate(instructions):
        state = in_states[index]
        pair = _source_destination(operands) if mnemonic.startswith("mov") else None
        if pair is None:
            continue
        source, destination = pair
        source_register = _operand_register(source)
        if _is_control_register(destination, "cr4") and source_register:
            source_tag = state.get(source_register, NONE)
            if source_tag == CLEARED:
                pge_disable_indices.append(index)
            elif source_tag == ORIGINAL:
                pge_restore_indices.append(index)
        elif _is_control_register(destination, "cr3") and source_register:
            cr3_write_indices.append(index)

    if not pge_disable_indices:
        if not saw_pge_clear:
            return False, "no instruction clearing CR4.PGE bit 7 was found"
        return False, "PGE-cleared value did not reach a CR4 write"
    if not cr3_write_indices:
        return False, "no actual CR3 write instruction found in activation routine"
    if not pge_restore_indices:
        return False, "original pre-switch CR4 value was not restored"

    # Check reachability, not textual index order: alternate blocks can be
    # emitted out of source order by LLVM.
    cr3_nodes = set(cr3_write_indices)
    restore_nodes = set(pge_restore_indices)
    for disable_index in pge_disable_indices:
        pending = [(successor, 0) for successor in successors[disable_index]]
        visited: set[tuple[int, int]] = set()
        while pending:
            index, stage = pending.pop()
            if (index, stage) in visited:
                continue
            visited.add((index, stage))
            if stage == 0 and index in cr3_nodes:
                stage = 1
            elif stage == 1 and index in restore_nodes:
                return True, "optimized activation assembly validates PGE clear -> CR3 write -> PGE restore"
            pending.extend((successor, stage) for successor in successors[index])

    return False, "required order is PGE disable -> CR3 write -> PGE restore"

def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure the CR3 inline asm retains the compiler memory clobber."""
    match = re.search(
        r'asm!\s*\(\s*"mov\s+cr3\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if match is None:
        return False, "could not locate the CR3 asm block in address_space.rs"

    block = match.group("body")
    if re.search(r"\bnomem\b", block):
        return False, "CR3 inline asm must not specify nomem"
    if not re.search(r"\bin\(reg\)\s+root_physical\b", block):
        return False, "CR3 inline asm no longer uses the validated root_physical operand"
    return True, "CR3 inline asm preserves the compiler memory-ordering boundary"


def validate_cr4_asm_pge_order(source: str) -> tuple[bool, str]:
    """Ensure source-level CR4 writes disable PGE then restore the original CR4."""
    blocks = re.findall(
        r'asm!\s*\(\s*"mov\s+cr4\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if len(blocks) < 2:
        return False, "expected separate CR4 asm blocks for PGE disable and restore"
    if not re.search(r"\bin\(reg\)\s+cr4_without_pge\b", blocks[0]):
        return False, "first CR4 write must use the PGE-cleared cr4_without_pge value"
    if not re.search(r"cr4_without_pge\s*=\s*cr4\s*&\s*!CR4_PGE\b", source):
        return False, "cr4_without_pge must be derived from cr4 with CR4_PGE cleared"
    if not re.search(r"\bin\(reg\)\s+cr4\b", blocks[1]):
        return False, "second CR4 write must restore the original cr4 value"
    return True, "source CR4 writes disable PGE and restore the original CR4 value"


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
            errors.append(f"{path}: {symbol}: {message}\n--- activation function body ---\n" + "\n".join(body) + "\n--- end activation function body ---")
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
