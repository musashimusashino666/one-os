#!/usr/bin/env python3
"""Fail closed on unreviewed assembly-macro sites and source-loading aliases.

This deliberately uses a short, explicit inventory instead of attempting to
implement Rust name resolution or macro expansion in a regex-based lexer.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from rust_lexer import rust_macro_invocations

# Counts are reviewed source call-site inventory, not inferred semantic proofs.
# Any new site or moved site must be reviewed and explicitly approved here.
EXPECTED_ASM_COUNTS = {
    "kernel/src/address_space.rs": 30,
    "kernel/src/paging/inspection.rs": 4,
    "kernel/src/paging/editor.rs": 13,
    "kernel/src/paging/editor/acceptance.rs": 1,
    "kernel/src/main.rs": 13,
    "kernel/src/interrupts.rs": 16,
}
EXPECTED_GLOBAL_ASM_COUNTS = {"kernel/src/main.rs": 4}
EXPECTED_ASSEMBLY_IMPORTS = {
    "kernel/src/address_space.rs": {"use core::arch::asm;"},
    "kernel/src/interrupts.rs": {"use core::arch::asm;"},
    "kernel/src/main.rs": {
        "use core::arch::asm;",
        "use core::arch::global_asm;",
    },
    "kernel/src/paging/mod.rs": {"use core::arch::asm;"},
}
EXPECTED_MACRO_RULES = {
    "kernel/src/paging/editor.rs": 1,
    "kernel/src/interrupts.rs": 4,
}
SOURCE_PACKAGES = ("kernel", "crates/oneos-core")
ALLOWED_LOCAL_DEPENDENCY_MANIFESTS = {
    "crates/oneos-core/Cargo.toml",
}
ALLOWED_TARGET_PATHS = {
    "kernel": {"bin": {"src/main.rs"}},
    "crates/oneos-core": {"lib": {"src/lib.rs"}},
}

STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"', re.DOTALL)
GLOBAL_SYMBOL_RE = re.compile(r"^\.global\s+[A-Za-z_.$][A-Za-z0-9_.$@]*$")
LOCAL_LABEL_RE = re.compile(r"^\.L[A-Za-z0-9_.$]*:$")
FORBIDDEN_ESCAPED_STRING_RE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\})")
FORBIDDEN_DIRECT_MACRO_FORWARD_RE = re.compile(r"\$\s*[A-Za-z_]\w*\s*!")
FORBIDDEN_REPEATED_PATH_FORWARD_RE = re.compile(r"\$\s*\([^)]*\)\s*::\s*\+?!")
PATH_MODULE_ATTRIBUTE_RE = re.compile(r"#\s*\[\s*(?:r#)?path\b")
CFG_ATTR_PATH_MODULE_RE = re.compile(r"#\s*\[\s*cfg_attr\b[^\]]*\b(?:r#)?path\s*=")
TRUSTED_ROOT_SHADOW_RE = re.compile(
    r"\b(?:mod|struct|enum|trait|type|fn|const|static|let)\s+"
    r"(?:r#)?(?:core|std|alloc|bootloader_api)\b"
)
TRUSTED_ROOT_ALIAS_RE = re.compile(
    r"\buse\b[^;]*\bas\s+(?:core|std|alloc|bootloader_api)\b"
)
FORBIDDEN_ENV = (
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC_BOOTSTRAP",
    "CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER",
    "CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS",
)


def _macro_count(source: str, macro: str) -> int:
    return len(rust_macro_invocations(source, {macro}))


def _skip_quoted_string(source: str, start: int) -> int | None:
    """Return the first index after a normal or raw Rust string literal."""
    raw_prefix = re.match(r'(?:b)?r(?P<hashes>#{0,})"', source[start:])
    if raw_prefix is not None:
        closing = '"' + raw_prefix.group("hashes")
        end = source.find(closing, start + raw_prefix.end())
        return None if end < 0 else end + len(closing)

    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == '"':
            return index + 1
        else:
            index += 1
    return None


def _matching_macro_paren(source: str, opening: int) -> int | None:
    """Find a macro call's closing parenthesis, skipping Rust strings/comments."""
    depth = 0
    index = opening
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            comment_depth = 1
            index += 2
            while index < len(source) and comment_depth:
                if source.startswith("/*", index):
                    comment_depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    comment_depth -= 1
                    index += 2
                else:
                    index += 1
            if comment_depth:
                return None
            continue

        raw_prefix = re.match(r'(?:b)?r#{0,}"', source[index:])
        if raw_prefix is not None:
            end = _skip_quoted_string(source, index)
            if end is None:
                return None
            index = end
            continue
        if source[index] == '"':
            end = _skip_quoted_string(source, index)
            if end is None:
                return None
            index = end
            continue
        if source[index] == "'":
            char_literal = re.match(r"'(?:\\.|[^'\\])'", source[index:])
            if char_literal is not None:
                index += char_literal.end()
                continue
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _assembly_macro_bodies(source: str) -> tuple[list[tuple[int, str]], list[str]]:
    """Extract direct asm!/global_asm! bodies with comment-aware token matching."""
    bodies: list[tuple[int, str]] = []
    errors: list[str] = []
    for invocation in rust_macro_invocations(source, {"asm", "global_asm"}):
        if invocation.closing is None:
            line = source.count("\n", 0, invocation.start) + 1
            errors.append(f"assembly macro invocation at line {line} cannot be safely delimited")
            continue
        bodies.append(
            (
                invocation.opening + 1,
                source[invocation.opening + 1 : invocation.closing],
            )
        )
    return bodies, errors


def _rust_string_literals(source: str):
    """Yield (offset, decoded_value, escape_error) for Rust string literals."""
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        raw_prefix = re.match(r'(?:b)?r(?P<hashes>#{0,})"', source[index:])
        if raw_prefix is not None:
            hashes = raw_prefix.group("hashes")
            content_start = index + raw_prefix.end()
            closing = '"' + hashes
            end = source.find(closing, content_start)
            if end < 0:
                yield index, "", "unterminated raw Rust string literal"
                return
            yield index, source[content_start:end], None
            index = end + len(closing)
            continue

        quote_index = index
        if source.startswith('b"', index):
            quote_index += 1
        if quote_index < len(source) and source[quote_index] == '"':
            content_start = quote_index + 1
            cursor = content_start
            decoded: list[str] = []
            escape_error = None
            terminated = False
            while cursor < len(source):
                char = source[cursor]
                if char == '"':
                    terminated = True
                    cursor += 1
                    break
                if char != "\\":
                    decoded.append(char)
                    cursor += 1
                    continue

                cursor += 1
                if cursor >= len(source):
                    escape_error = "unterminated Rust string escape"
                    break
                escaped = source[cursor]
                simple_escapes = {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "0": "\0",
                    "\\": "\\",
                    '"': '"',
                    "'": "'",
                }
                if escaped in simple_escapes:
                    decoded.append(simple_escapes[escaped])
                    cursor += 1
                    continue
                if escaped == "\n":
                    cursor += 1
                    while cursor < len(source) and source[cursor] in " \t":
                        cursor += 1
                    continue
                if escaped == "\r" and cursor + 1 < len(source) and source[cursor + 1] == "\n":
                    cursor += 2
                    while cursor < len(source) and source[cursor] in " \t":
                        cursor += 1
                    continue
                if escaped in {"x", "u"}:
                    escape_error = "hexadecimal/Unicode escapes in assembly templates are denied"
                    cursor += 1
                    continue
                escape_error = f"unsupported Rust string escape \\{escaped}"
                cursor += 1

            if not terminated:
                yield index, "", escape_error or "unterminated Rust string literal"
                return
            yield index, "".join(decoded), escape_error
            index = cursor
            continue

        if source[index] == "'":
            character = re.match(r"'(?:\\.|[^'\\])'", source[index:])
            if character is not None:
                index += character.end()
                continue
        index += 1


def _is_indirect_control_transfer(statement: str) -> bool:
    """Recognize direct and indirect x86 call/jump forms; reject indirect forms."""
    candidate = statement.strip()
    candidate = re.sub(r"^[A-Za-z_.$][A-Za-z0-9_.$@]*:\s*", "", candidate)
    operation = re.match(
        r"^(?:jmp|jmpq|jmpl|ljmp|ljmpq|ljmpl|call|callq|calll)\s+(.+)$",
        candidate,
        re.IGNORECASE,
    )
    if operation is None:
        return False

    operand = operation.group(1).strip()
    if not operand:
        return False
    if operand.startswith("*") or "[" in operand or "]" in operand:
        return True

    # Intel-syntax register-indirect forms have no AT&T '*' prefix.
    register = re.compile(
        r"^%?(?:"
        r"rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|"
        r"eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|"
        r"ax|bx|cx|dx|si|di|bp|sp|ip|"
        r"al|bl|cl|dl|ah|bh|ch|dh|spl|bpl|sil|dil|"
        r"r(?:[8-9]|1[0-5])(?:[dwb])?"
        r")$",
        re.IGNORECASE,
    )
    return register.fullmatch(operand) is not None


def _assembler_directive_errors(relative_path: str, source: str) -> list[str]:
    path = Path(relative_path).as_posix()
    errors: list[str] = []
    bodies, delimiter_errors = _assembly_macro_bodies(source)
    errors.extend(f"{path}: {error}" for error in delimiter_errors)

    for body_start, body in bodies:
        for match_start, value, escape_error in _rust_string_literals(body):
            line = source.count("\n", 0, body_start + match_start) + 1
            if escape_error is not None:
                errors.append(f"{path}:{line}: {escape_error}")
                continue

            # Check directive statements after all accepted delimiters, including
            # tabs. Keep tabs in the control-flow view because they can separate
            # an opcode from its indirect operand.
            directive_statements = re.split(r"[;\r\n\t]+", value)
            for statement in directive_statements:
                candidate = statement.strip()
                if not candidate:
                    continue
                if candidate.startswith("."):
                    if not (GLOBAL_SYMBOL_RE.fullmatch(candidate) or LOCAL_LABEL_RE.fullmatch(candidate)):
                        errors.append(
                            f"{path}:{line}: assembler directive-like statement {candidate!r} is denied; "
                            "only .global symbol exports and local .L labels are allowed"
                        )
                else:
                    # Also detect a directive hidden after spaces within one statement.
                    # Ignore .L symbols, which are valid branch operands.
                    for directive in re.finditer(
                        r"(?<!\S)\.(?!L[A-Za-z0-9_.$@]*:?)([A-Za-z_][A-Za-z0-9_.$@]*)",
                        candidate,
                    ):
                        errors.append(
                            f"{path}:{line}: assembler directive-like token "
                            f".{directive.group(1)} is denied inside a statement"
                        )

            control_statements = re.split(r"[;\r\n]+", value)
            for statement in control_statements:
                candidate = statement.strip()
                if candidate and _is_indirect_control_transfer(candidate):
                    errors.append(
                        f"{path}:{line}: indirect x86 control transfer is denied: {candidate!r}"
                    )
    return errors

def source_policy_errors(relative_path: str, source: str) -> list[str]:
    """Apply simple deny rules and the explicit call-site count allowlist."""
    path = Path(relative_path).as_posix()
    errors: list[str] = []
    asm_count = _macro_count(source, "asm")
    global_count = _macro_count(source, "global_asm")
    naked_count = _macro_count(source, "naked_asm")
    include_count = _macro_count(source, "include")

    expected_asm = EXPECTED_ASM_COUNTS.get(path, 0)
    if asm_count != expected_asm:
        errors.append(
            f"{path}: asm! site count is {asm_count}, expected {expected_asm}; "
            "unreviewed or relocated assembly is denied"
        )
    expected_global = EXPECTED_GLOBAL_ASM_COUNTS.get(path, 0)
    if global_count != expected_global:
        errors.append(
            f"{path}: global_asm! site count is {global_count}, expected {expected_global}"
        )
    if naked_count:
        errors.append(f"{path}: naked_asm! is unsupported and denied")
    if include_count:
        errors.append(f"{path}: include! is denied because it hides source from the inventory")

    macro_rules_count = len(re.findall(r"\bmacro_rules\s*!", source))
    expected_rules = EXPECTED_MACRO_RULES.get(path, 0)
    if macro_rules_count != expected_rules:
        errors.append(
            f"{path}: macro_rules! count is {macro_rules_count}, expected {expected_rules}"
        )

    for import_match in re.finditer(r"\b(?:pub\s+)?use\b[^;]*;", source):
        statement = " ".join(import_match.group(0).split())
        imports_assembly_macro = re.search(
            r"\b(?:asm|global_asm|naked_asm|include)\b",
            statement,
        ) is not None
        if imports_assembly_macro and statement not in EXPECTED_ASSEMBLY_IMPORTS.get(path, set()):
            errors.append(
                f"{path}: unreviewed import of an assembly/include macro is denied: {statement}"
            )
        if re.search(r"\bcore\b[^;]*\barch\b[^;]*(?:\bas\b|\*)", statement):
            errors.append(
                f"{path}: aliases and wildcard imports involving core::arch are denied"
            )

    if re.search(r"\b(?:core|std|alloc)::arch::(?:asm|global_asm|naked_asm)\s*!", source):
        errors.append(f"{path}: qualified assembly macro paths are denied; use reviewed imports")
    if re.search(r"\bpub\s+use\b[^;]*\b(?:asm|global_asm|naked_asm)\b", source):
        errors.append(f"{path}: public re-exports of assembly macros are denied")
    if re.search(r"\b(?:pub\s+)?use\b[^;]*\b(?:asm|global_asm|naked_asm|include)\b[^;]*\bas\b", source):
        errors.append(f"{path}: aliases of assembly or include macros are denied")
    if re.search(r"\b(?:pub\s+)?use\b[^;]*\bas\b[^;]*\b(?:asm|global_asm|naked_asm|include)\b", source):
        errors.append(f"{path}: aliases of assembly or include macros are denied")
    if re.search(r"\b(?:pub\s+)?use\s+core::arch\s*(?:as\b|;)", source):
        errors.append(f"{path}: importing core::arch as a module alias is denied")
    if re.search(r"\bextern\s+crate\s+(?:core|std|alloc|bootloader_api)\s+as\b", source):
        errors.append(f"{path}: aliases of trusted macro roots are denied")
    if re.search(r"#\s*\[\s*macro_use\b", source) or re.search(r"\bmacro_use\b", source):
        errors.append(f"{path}: macro_use imports are denied")
    if PATH_MODULE_ATTRIBUTE_RE.search(source) or CFG_ATTR_PATH_MODULE_RE.search(source):
        errors.append(
            f"{path}: #[path] module source redirection is denied because it can load Rust code outside the inventory"
        )
    if TRUSTED_ROOT_SHADOW_RE.search(source) or TRUSTED_ROOT_ALIAS_RE.search(source):
        errors.append(f"{path}: local declarations or imports shadow a trusted macro root")
    if FORBIDDEN_DIRECT_MACRO_FORWARD_RE.search(source) or FORBIDDEN_REPEATED_PATH_FORWARD_RE.search(source):
        errors.append(f"{path}: macro forwarding through a metavariable is denied")
    if re.search(r"\bconcat\s*!\s*\(", source):
        errors.append(f"{path}: concat! is denied until assembly templates can be inspected without expansion")
    errors.extend(_assembler_directive_errors(path, source))

    return errors


def _walk_package(root: Path, relative_package: str) -> tuple[list[Path], list[str]]:
    package = root / relative_package
    errors: list[str] = []
    if not package.is_dir():
        return [], [f"source package directory missing: {package}"]

    rust_files: list[Path] = []
    for directory, names, filenames in os.walk(package, topdown=True, followlinks=False):
        directory_path = Path(directory)
        kept_names: list[str] = []
        for name in names:
            child = directory_path / name
            if name in {".git", "target"}:
                continue
            if child.is_symlink():
                errors.append(f"symlink in Rust inventory is denied: {child}")
                continue
            kept_names.append(name)
        names[:] = kept_names

        for filename in filenames:
            path = directory_path / filename
            if path.is_symlink():
                errors.append(f"symlink in Rust inventory is denied: {path}")
                continue
            if path.suffix in {".S", ".s", ".asm", ".sx"}:
                errors.append(f"native assembly input is outside the Rust inventory: {path}")
            if path.name == "build.rs":
                errors.append(f"build script is outside the Rust inventory: {path}")
            if path.suffix == ".rs":
                rust_files.append(path)
    return rust_files, errors


def _resolved_local_dependency_errors(root: Path, metadata: dict) -> list[str]:
    """Reject unscanned local crates; registry package source files are not scanned.

    Registry nodes remain in the traversal so local path packages nested beneath
    them cannot escape the explicit source-package allowlist.
    """
    errors: list[str] = []
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        return ["cargo metadata omitted package or resolve graph data"]

    packages_by_id = {
        package.get("id"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        return ["cargo metadata omitted resolved dependency nodes"]
    nodes_by_id = {
        node.get("id"): node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }

    source_package_ids: set[str] = set()
    allowed_manifests = {
        *((root / relative / "Cargo.toml").resolve() for relative in SOURCE_PACKAGES),
        *((root / relative).resolve() for relative in ALLOWED_LOCAL_DEPENDENCY_MANIFESTS),
    }
    for relative_package in SOURCE_PACKAGES:
        expected_manifest = (root / relative_package / "Cargo.toml").resolve()
        matches = [
            package_id
            for package_id, package in packages_by_id.items()
            if isinstance(package.get("manifest_path"), str)
            and Path(package["manifest_path"]).resolve() == expected_manifest
        ]
        if len(matches) != 1:
            errors.append(
                f"cargo metadata must resolve exactly one package for {expected_manifest}; found {len(matches)}"
            )
        else:
            source_package_ids.add(matches[0])

    if errors:
        return errors

    visited: set[str] = set()
    pending = list(source_package_ids)
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        visited.add(package_id)

        package = packages_by_id.get(package_id)
        node = nodes_by_id.get(package_id)
        if package is None or node is None:
            errors.append(f"cargo metadata dependency node is incomplete for package {package_id}")
            continue

        manifest_value = package.get("manifest_path")
        if not isinstance(manifest_value, str):
            errors.append(f"cargo metadata package has no manifest path: {package_id}")
            continue
        manifest_path = Path(manifest_value).resolve()

        # Cargo uses source=null for path/workspace packages. Only inventoried
        # packages and the reviewed oneos-core manifest may be in this closure.
        if package.get("source") is None and manifest_path not in allowed_manifests:
            errors.append(
                "unscanned local path dependency is denied in the resolved Cargo graph: "
                f"{manifest_path}"
            )

        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            errors.append(f"cargo metadata node has no dependency list: {package_id}")
            continue
        for dependency in dependencies:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("pkg"), str):
                errors.append(f"cargo metadata has an invalid dependency edge from {package_id}")
                continue
            pending.append(dependency["pkg"])

    return errors


def _cargo_metadata_errors(root: Path) -> list[str]:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--all-features",
        "--locked",
        "--manifest-path",
        str(root / "Cargo.toml"),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        return [f"cannot execute cargo metadata for resolved source closure: {error}"]

    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        return [f"cargo metadata failed; resolved source closure cannot be verified: {detail}"]
    try:
        metadata = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return [f"cargo metadata returned invalid JSON: {error}"]
    return _resolved_local_dependency_errors(root, metadata)


def _manifest_errors(root: Path) -> list[str]:
    errors: list[str] = []
    manifest_paths = [root / "Cargo.toml"] + [root / p / "Cargo.toml" for p in SOURCE_PACKAGES]
    for path in manifest_paths:
        try:
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"cannot read/parse Cargo manifest {path}: {error}")
            continue

        if "patch" in manifest or "replace" in manifest:
            errors.append(f"Cargo patch/replace tables are denied until their source closure is inventoried: {path}")

        rel_parent = path.parent.relative_to(root).as_posix()
        if rel_parent in SOURCE_PACKAGES:
            build = manifest.get("package", {}).get("build")
            if build not in (None, False):
                errors.append(f"custom package.build script is denied: {path}")

            targets = manifest.get("bin", [])
            if isinstance(targets, dict):
                targets = [targets]
            allowed_bin = ALLOWED_TARGET_PATHS.get(rel_parent, {}).get("bin", set())
            for target in targets:
                if not isinstance(target, dict):
                    continue
                target_path = target.get("path")
                if target_path is not None and target_path not in allowed_bin:
                    errors.append(f"unsupported Cargo bin target path {target_path!r} in {path}")
            lib = manifest.get("lib")
            allowed_lib = ALLOWED_TARGET_PATHS.get(rel_parent, {}).get("lib", set())
            if isinstance(lib, dict) and lib.get("path") is not None and lib["path"] not in allowed_lib:
                errors.append(f"unsupported Cargo library target path {lib['path']!r} in {path}")
            for target_name in ("example", "test", "bench"):
                if manifest.get(target_name):
                    errors.append(f"custom Cargo {target_name} targets are denied until inventoried: {path}")

    errors.extend(_cargo_metadata_errors(root))

    config_path = root / ".cargo" / "config.toml"
    legacy_config_path = root / ".cargo" / "config"
    if legacy_config_path.exists():
        errors.append(f"legacy Cargo config path is denied: {legacy_config_path}")
    if config_path.exists():
        try:
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"cannot read/parse Cargo config {config_path}: {error}")
        else:
            expected_config = {
                "target": {
                    "x86_64-unknown-none": {
                        "rustflags": ["-C", "relocation-model=pic"]
                    }
                }
            }
            if config != expected_config:
                errors.append(
                    f"Cargo config differs from the pinned target rustflags policy: {config_path}"
                )

    for variable in FORBIDDEN_ENV:
        if os.environ.get(variable):
            errors.append(f"environment override {variable} is denied")
    return errors


def validate_source_policy(root: Path) -> tuple[bool, list[str]]:
    """Check the bounded Rust source closure and fail closed on new code inputs."""
    errors = _manifest_errors(root)
    all_rust_files: list[Path] = []
    for package in SOURCE_PACKAGES:
        files, package_errors = _walk_package(root, package)
        all_rust_files.extend(files)
        errors.extend(package_errors)

    found_rel_paths = {path.relative_to(root).as_posix() for path in all_rust_files}
    for expected_path in EXPECTED_ASM_COUNTS:
        if expected_path not in found_rel_paths:
            errors.append(f"allowlisted assembly source is missing: {expected_path}")
    for expected_path in EXPECTED_GLOBAL_ASM_COUNTS:
        if expected_path not in found_rel_paths:
            errors.append(f"allowlisted global assembly source is missing: {expected_path}")

    for path in sorted(all_rust_files):
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"cannot read Rust source {path}: {error}")
            continue
        errors.extend(source_policy_errors(relative, source))

    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    valid, errors = validate_source_policy(args.root.resolve())
    if not valid:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: Rust assembly sites match the explicit allowlist; aliases, include!, and unsupported code inputs are denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
