#!/usr/bin/env python3
"""Validate local Markdown links, anchors, navigation, and line lengths."""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_MAX_LINE_LENGTH = 88
BACKTICK = chr(96)
IGNORED_DIRS = {".git", "target", "vendor", "node_modules"}

REQUIRED_LINKS = {
    "README.md": (
        "docs/README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/project/IMPLEMENTATION_STATUS.md",
        "docs/engineering/DEVELOPMENT.md",
        "docs/engineering/VERIFICATION.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ),
    "docs/README.md": (
        "vision/WORLD_CLASS_OS.md",
        "vision/VISION.md",
        "vision/PRINCIPLES.md",
        "vision/SUCCESS_CRITERIA.md",
        "architecture/OVERVIEW.md",
        "architecture/SECURITY_MODEL.md",
        "architecture/USER_EXPERIENCE.md",
        "architecture/UPDATES_AND_RECOVERY.md",
        "specs/",
        "engineering/DEVELOPMENT.md",
        "engineering/VERIFICATION.md",
        "../CONTRIBUTING.md",
        "../SECURITY.md",
        "project/IMPLEMENTATION_STATUS.md",
        "project/ROADMAP.md",
        "project/decisions/README.md",
    ),
}


class DocProblem:
    def __init__(self, path: str, line: int, message: str) -> None:
        self.path = path
        self.line = line
        self.message = message

    def __str__(self) -> str:
        location = f"{self.path}:{self.line}" if self.line else self.path
        return f"{location}: {self.message}"


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _fenced_code_lines(lines: list[str]) -> set[int]:
    """Return zero-based line numbers inside Markdown fenced code blocks."""
    fenced: set[int] = set()
    marker: str | None = None
    marker_length = 0

    for index, line in enumerate(lines):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if indent <= 3:
            match = re.match(rf"({re.escape(BACKTICK)}{{3,}}|~{{3,}})(.*)$", stripped)
        else:
            match = None

        if marker is None:
            if match:
                candidate = match.group(1)
                info = match.group(2)
                if candidate[0] != BACKTICK or BACKTICK not in info:
                    marker = candidate[0]
                    marker_length = len(candidate)
                    fenced.add(index)
            continue

        fenced.add(index)
        close = re.match(rf" {{0,3}}{re.escape(marker)}{{{marker_length},}}\s*$", line)
        if close:
            marker = None
            marker_length = 0

    return fenced


def _inline_code_ranges(line: str) -> list[tuple[int, int]]:
    """Find matched inline-code spans, respecting escaped backticks."""
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(line):
        if line[index] != BACKTICK or _is_escaped(line, index):
            index += 1
            continue
        run_end = index + 1
        while run_end < len(line) and line[run_end] == BACKTICK:
            run_end += 1
        run_length = run_end - index
        search = run_end
        closing: tuple[int, int] | None = None
        while search < len(line):
            candidate = line.find(BACKTICK, search)
            if candidate < 0:
                break
            if _is_escaped(line, candidate):
                search = candidate + 1
                continue
            candidate_end = candidate + 1
            while candidate_end < len(line) and line[candidate_end] == BACKTICK:
                candidate_end += 1
            if candidate_end - candidate == run_length:
                closing = (candidate, candidate_end)
                break
            search = candidate_end
        if closing is None:
            index = run_end
            continue
        ranges.append((index, closing[1]))
        index = closing[1]
    return ranges


def _line_length_is_exempt(line: str, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> bool:
    """Allow only unbreakable inline code and URL spans to exceed the limit."""
    if line.count("|") >= 2:
        return False  # Wide Markdown table rows must be rewritten, not exempted.

    spans = _inline_code_ranges(line)
    spans.extend((match.start(), match.end()) for match in re.finditer(r"https?://\S+", line))
    if not spans:
        return False

    # Merge overlapping spans (for example, a URL inside inline code).
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    reduced = line
    for start, end in reversed(merged):
        reduced = reduced[:start] + "x" + reduced[end:]
    return len(reduced) <= max_line_length


def _mask_inline_code(text: str) -> str:
    """Mask fenced and inline code while preserving offsets and newlines."""
    lines = text.splitlines(keepends=True)
    fenced = _fenced_code_lines(lines)
    output = list(text)
    offset = 0
    for line_number, line in enumerate(lines):
        if line_number in fenced:
            for index in range(offset, offset + len(line)):
                if output[index] not in "\r\n":
                    output[index] = " "
            offset += len(line)
            continue
        for start, end in _inline_code_ranges(line):
            for index in range(offset + start, offset + end):
                if output[index] not in "\r\n":
                    output[index] = " "
        offset += len(line)
    return "".join(output)


def _find_closing_bracket(text: str, start: int) -> int | None:
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _parse_inline_destination(text: str, open_paren: int) -> tuple[str | None, int, str | None]:
    """Parse a Markdown inline destination and return (target, end, error)."""
    index = open_paren + 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return None, len(text), "link destination is not closed"
    if text[index] == ")":
        return None, index + 1, "link destination is empty"

    if text[index] == "<":
        start = index + 1
        index = start
        while index < len(text):
            if text[index] == ">" and not _is_escaped(text, index):
                target = text[start:index]
                index += 1
                while index < len(text) and text[index].isspace():
                    index += 1
                if index < len(text) and text[index] == ")":
                    return target, index + 1, None
                # An optional Markdown title may follow an angle-bracket destination.
                title_depth = 0
                while index < len(text):
                    title_char = text[index]
                    if not _is_escaped(text, index):
                        if title_char == "(":
                            title_depth += 1
                        elif title_char == ")":
                            if title_depth == 0:
                                return target, index + 1, None
                            title_depth -= 1
                    index += 1
                return target, len(text), "link destination is not closed"
            index += 1
        return None, len(text), "link has an unterminated angle-bracket destination"

    start = index
    depth = 0
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char == "(" and not _is_escaped(text, index):
            depth += 1
        elif char == ")":
            if depth == 0:
                target = text[start:index]
                if not target:
                    return None, index + 1, "link destination is empty"
                return target, index + 1, None
            depth -= 1
        elif char.isspace() and depth == 0:
            target = text[start:index]
            while index < len(text) and text[index].isspace():
                index += 1
            # The rest is an optional title; require the final outer ')'.
            title_depth = 0
            while index < len(text):
                title_char = text[index]
                if not _is_escaped(text, index):
                    if title_char == "(":
                        title_depth += 1
                    elif title_char == ")":
                        if title_depth == 0:
                            return target, index + 1, None
                        title_depth -= 1
                index += 1
            return None, len(text), "link destination is not closed"
        index += 1
    return None, len(text), "link destination is not closed"


def _unescape_destination(target: str) -> str:
    return re.sub(r"\\([\\*{}\[\]()#+\-.!_>])", r"\1", target).replace("\\" + BACKTICK, BACKTICK)


def _extract_links(text: str, path: str) -> tuple[list[tuple[str, int]], list[DocProblem]]:
    """Extract inline links and reference definitions, retaining source line numbers."""
    masked = _mask_inline_code(text)
    links: list[tuple[str, int]] = []
    problems: list[DocProblem] = []

    # Reference definitions are validated even if no use-site is found.
    definitions: dict[str, tuple[str, int]] = {}
    for line_number, line in enumerate(masked.splitlines(), 1):
        match = re.match(r"^ {0,3}\[([^\]]+)\]:\s*(?:<([^>]+)>|(\S+))", line)
        if match:
            label = " ".join(match.group(1).casefold().split())
            target = match.group(2) or match.group(3)
            definitions[label] = (target, line_number)

    # Inline links/images. The parser balances nested brackets and parentheses.
    index = 0
    while index < len(masked):
        if masked[index] != "[" or _is_escaped(masked, index):
            index += 1
            continue
        close_bracket = _find_closing_bracket(masked, index)
        if close_bracket is None:
            index += 1
            continue
        next_index = close_bracket + 1
        if next_index < len(masked) and masked[next_index] == "(":
            target, end, error = _parse_inline_destination(masked, next_index)
            line_number = masked.count("\n", 0, index) + 1
            if error:
                problems.append(DocProblem(path, line_number, error))
            elif target is not None:
                links.append((_unescape_destination(target), line_number))
            index = max(end, next_index + 1)
            continue
        if next_index < len(masked) and masked[next_index] == "[":
            close_reference = _find_closing_bracket(masked, next_index)
            if close_reference is not None:
                label_text = masked[next_index + 1:close_reference]
                label = label_text if label_text else masked[index + 1:close_bracket]
                normalized = " ".join(label.casefold().split())
                line_number = masked.count("\n", 0, index) + 1
                if normalized not in definitions:
                    problems.append(DocProblem(path, line_number, f"undefined Markdown reference: [{label}]"))
                index = close_reference + 1
                continue
        index = close_bracket + 1

    for target, line_number in definitions.values():
        links.append((_unescape_destination(target), line_number))

    return links, problems


def _strip_heading_markup(heading: str) -> str:
    heading = re.sub(re.escape(BACKTICK) + r"+([^" + re.escape(BACKTICK) + r"]*?)" + re.escape(BACKTICK) + r"+", r"\1", heading)
    heading = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"!?\[([^\]]*)\]\[[^]]*\]", r"\1", heading)
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"\\([\\*_{}\[\]()#+\-.!_>])", r"\1", heading).replace("\\" + BACKTICK, BACKTICK)
    heading = heading.replace("*", "").replace("_", "").replace("~", "")
    return heading.strip()


def _slugify_heading(heading: str) -> str:
    heading = _strip_heading_markup(heading).lower()
    output: list[str] = []
    for char in heading:
        category = unicodedata.category(char)
        if char.isspace():
            output.append("-")
        elif category.startswith("P") and char != "-":
            continue
        else:
            output.append(char)
    slug = "".join(output)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def _markdown_anchors(text: str) -> set[str]:
    lines = text.splitlines()
    fenced = _fenced_code_lines(lines)
    anchors: set[str] = set()
    counts: dict[str, int] = {}

    for index, line in enumerate(lines):
        if index in fenced:
            continue
        explicit_ids = re.findall(r"<a\s+[^>]*?id\s*=\s*[\"']([^\"']+)[\"']", line, re.IGNORECASE)
        anchors.update(explicit_ids)

        atx = re.match(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if atx:
            heading = atx.group(2)
        elif index + 1 < len(lines) and index + 1 not in fenced:
            underline = re.match(r"^ {0,3}(=+|-+)\s*$", lines[index + 1])
            heading = line.strip() if underline and line.strip() else None
        else:
            heading = None

        if heading:
            base = _slugify_heading(heading)
            count = counts.get(base, 0)
            slug = base if count == 0 else f"{base}-{count}"
            counts[base] = count + 1
            anchors.add(slug)

    return anchors


def _resolve_target(source: str, target: str) -> tuple[str | None, str | None, bool]:
    """Return (repository-relative path, fragment, external)."""
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return None, None, True

    path = unquote(parsed.path)
    fragment = unquote(parsed.fragment) if parsed.fragment else None
    if not path:
        resolved = source
    elif path.startswith("/"):
        resolved = posixpath.normpath(path.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))

    if resolved == ".":
        resolved = ""
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        return None, fragment, False
    return resolved, fragment, False


def validate_repository(root: Path, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> list[DocProblem]:
    root = root.resolve()
    markdown_files = sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in IGNORED_DIRS for part in path.relative_to(root).parts)
    )
    relative_files = {path.relative_to(root).as_posix(): path for path in markdown_files}
    file_contents: dict[str, str] = {}
    problems: list[DocProblem] = []
    discovered_links: dict[str, list[str]] = {}

    for relative, path in relative_files.items():
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            problems.append(DocProblem(relative, 0, f"Markdown is not valid UTF-8: {error}"))
            continue
        file_contents[relative] = content
        lines = content.splitlines()
        fenced = _fenced_code_lines(lines)
        for index, line in enumerate(lines):
            if index in fenced or len(line) <= max_line_length:
                continue
            # Inline code and URLs are atomic; the residual prose must still fit.
            if not _line_length_is_exempt(line, max_line_length):
                problems.append(
                    DocProblem(
                        relative,
                        index + 1,
                        f"line is {len(line)} characters (limit {max_line_length})",
                    )
                )

        links, parse_problems = _extract_links(content, relative)
        problems.extend(parse_problems)
        discovered_links[relative] = []
        for target, line_number in links:
            resolved, fragment, external = _resolve_target(relative, target)
            if external:
                continue  # External websites are intentionally not checked.
            if resolved is None:
                problems.append(DocProblem(relative, line_number, f"link escapes repository root: {target}"))
                continue

            target_path = root / resolved if resolved else root
            try:
                target_path.resolve().relative_to(root)
            except ValueError:
                problems.append(DocProblem(relative, line_number, f"link escapes repository root: {target}"))
                continue
            if not target_path.exists():
                problems.append(DocProblem(relative, line_number, f"missing internal link target: {target}"))
                continue
            if not target_path.is_file() and not target_path.is_dir():
                problems.append(DocProblem(relative, line_number, f"unsupported link target: {target}"))
                continue
            discovered_links[relative].append(resolved)

            if fragment:
                anchor_file = target_path
                if target_path.is_dir():
                    readme = target_path / "README.md"
                    if not readme.is_file():
                        problems.append(
                            DocProblem(relative, line_number, f"directory has no README.md for fragment: {target}")
                        )
                        continue
                    anchor_file = readme
                if not anchor_file.is_file() or anchor_file.suffix.lower() not in {".md", ".markdown"}:
                    problems.append(
                        DocProblem(relative, line_number, f"fragment target is not a Markdown file: {target}")
                    )
                    continue
                anchor_relative = anchor_file.relative_to(root).as_posix()
                anchor_text = file_contents.get(anchor_relative)
                if anchor_text is None:
                    try:
                        anchor_text = anchor_file.read_text(encoding="utf-8")
                        file_contents[anchor_relative] = anchor_text
                    except UnicodeDecodeError:
                        anchor_text = ""
                if fragment not in _markdown_anchors(anchor_text):
                    problems.append(
                        DocProblem(relative, line_number, f"missing heading anchor '#{fragment}' in {resolved or '.'}")
                    )

    # Required navigation is checked independently of whether a link target happens to exist.
    for source, required_targets in REQUIRED_LINKS.items():
        if source not in relative_files:
            problems.append(DocProblem(source, 0, "required canonical entry point is missing"))
            continue
        actual = set(discovered_links.get(source, []))
        for required in required_targets:
            resolved, _, external = _resolve_target(source, required)
            if external or resolved is None:
                continue
            required_path = root / resolved
            if not required_path.exists():
                problems.append(DocProblem(source, 0, f"required target does not exist: {required}"))
            elif resolved not in actual:
                problems.append(DocProblem(source, 0, f"required navigation link is missing: {required}"))

    return sorted(problems, key=lambda problem: (problem.path, problem.line, problem.message))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root (default: current directory)")
    parser.add_argument("--max-line-length", type=int, default=DEFAULT_MAX_LINE_LENGTH)
    args = parser.parse_args(argv)

    if args.max_line_length <= 0:
        parser.error("--max-line-length must be positive")
    if not args.root.is_dir():
        parser.error(f"repository root is not a directory: {args.root}")

    problems = validate_repository(args.root, args.max_line_length)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"documentation validation failed: {len(problems)} problem(s)", file=sys.stderr)
        return 1

    print(f"documentation validation passed ({args.max_line_length}-character limit; no external URL checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
