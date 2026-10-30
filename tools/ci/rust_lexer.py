"""Small, fail-closed Rust lexer helpers for security-sensitive source checks.

Rust comments are whitespace, including nested block comments. This module
masks comments and literals while preserving offsets, then identifies direct
macro invocations from the resulting token-like source view. It deliberately
does not attempt Rust name resolution or macro expansion.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class RustStringLiteral:
    """Contents and source offsets for a Rust string literal."""

    start: int
    end: int
    value: str


@dataclass(frozen=True)
class RustMacroInvocation:
    """Source offsets for a macro invocation using a parenthesized token tree."""

    name: str
    start: int
    opening: int
    closing: int | None


_RAW_STRING_RE = re.compile(r'r(?P<hashes>#{0,})"')
_CHAR_LITERAL_RE = re.compile(
    r"'(?:\\(?:['\"\\nrt0]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\})|[^'\\\r\n])'"
)


def _skip_quoted_literal(source: str, start: int) -> int | None:
    """Return the end of a quoted literal beginning at start, if present."""
    raw = _RAW_STRING_RE.match(source, start)
    if raw is not None:
        terminator = '"' + raw.group("hashes")
        end = source.find(terminator, raw.end())
        return len(source) if end < 0 else end + len(terminator)

    if source[start] == '"':
        cursor = start + 1
        while cursor < len(source):
            if source[cursor] == "\\":
                cursor += 2
            elif source[cursor] == '"':
                return cursor + 1
            else:
                cursor += 1
        return len(source)

    if source[start] == "'":
        character = _CHAR_LITERAL_RE.match(source, start)
        if character is not None:
            return character.end()

    return None


def rust_string_literals(source: str) -> list[RustStringLiteral]:
    """Return string literal contents (without delimiters), including raw strings.

    Comments, character literals, and strings are skipped as opaque lexical
    units. The returned value preserves escape spelling, matching how the
    existing assembly-template validators inspect placeholders and mnemonics.
    """
    literals: list[RustStringLiteral] = []
    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            cursor = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", cursor):
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            continue

        literal_start = cursor
        raw_start = cursor
        if source[cursor] in {"b", "c"} and cursor + 1 < len(source):
            raw_start = cursor + 1
        raw = _RAW_STRING_RE.match(source, raw_start)
        if raw is not None:
            terminator = '"' + raw.group("hashes")
            value_start = raw.end()
            value_end = source.find(terminator, value_start)
            if value_end < 0:
                return literals
            end = value_end + len(terminator)
            literals.append(
                RustStringLiteral(literal_start, end, source[value_start:value_end])
            )
            cursor = end
            continue

        quote_index = cursor + 1 if source.startswith(("b\"", "c\""), cursor) else cursor
        if quote_index < len(source) and source[quote_index] == '"':
            value_start = quote_index + 1
            scan = value_start
            while scan < len(source):
                if source[scan] == "\\":
                    scan += 2
                elif source[scan] == '"':
                    literals.append(
                        RustStringLiteral(literal_start, scan + 1, source[value_start:scan])
                    )
                    cursor = scan + 1
                    break
                else:
                    scan += 1
            else:
                return literals
            continue

        if source[cursor] == "'":
            character = _CHAR_LITERAL_RE.match(source, cursor)
            if character is not None:
                cursor = character.end()
                continue

        cursor += 1

    return literals


def mask_rust_comments_and_literals(source: str) -> str:
    """Mask Rust comments/literals with spaces while preserving offsets/newlines."""
    masked = list(source)
    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            end = len(source) if newline < 0 else newline + 1
        elif source.startswith("/*", cursor):
            depth = 1
            end = cursor + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            end = _skip_quoted_literal(source, cursor)
            if end is None:
                cursor += 1
                continue

        for index in range(cursor, end):
            if source[index] not in "\r\n":
                masked[index] = " "
        cursor = end

    return "".join(masked)


def rust_macro_invocations(
    source: str, macro_names: set[str]
) -> list[RustMacroInvocation]:
    """Find named macro invocations, treating comments as whitespace.

    String/character literal contents are excluded from discovery and delimiter
    matching. Unbalanced calls are returned with closing=None so callers can
    fail closed instead of silently ignoring an incomplete token tree.
    """
    if not macro_names:
        return []

    names = "|".join(re.escape(name) for name in sorted(macro_names, key=len, reverse=True))
    pattern = re.compile(
        rf"(?<![\w])(?:r#)?(?P<name>{names})\b\s*!\s*"
        r"(?P<delimiter>[\(\[\{])"
    )
    code = mask_rust_comments_and_literals(source)
    invocations: list[RustMacroInvocation] = []

    for match in pattern.finditer(code):
        opening = code.find(match.group("delimiter"), match.start(), match.end())
        closing_for = {"(": ")", "[": "]", "{": "}"}
        closing_to = set(closing_for.values())
        stack = [closing_for[code[opening]]]
        closing: int | None = None
        for index in range(opening + 1, len(code)):
            character = code[index]
            if character in closing_for:
                stack.append(closing_for[character])
            elif character in closing_to:
                if not stack or character != stack[-1]:
                    break
                stack.pop()
                if not stack:
                    closing = index
                    break
        invocations.append(
            RustMacroInvocation(
                name=match.group("name"),
                start=match.start(),
                opening=opening,
                closing=closing,
            )
        )

    return invocations
