from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

BACKTICK = chr(96)
FENCE = BACKTICK * 3

from check_docs import (
    _extract_links,
    _line_length_is_exempt,
    _markdown_anchors,
    _resolve_target,
    _unescape_destination,
    _markdown_table_lines,
    _fenced_code_lines,
    validate_repository,
)


class LinkParsingTests(unittest.TestCase):
    def test_valid_inline_link_with_title(self):
        links, problems = _extract_links('[guide](guide.md "Guide")', "README.md")
        self.assertEqual(links, [("guide.md", 1)])
        self.assertEqual(problems, [])

    def test_escaped_parentheses_in_destination(self):
        links, problems = _extract_links(r"[guide](path\(draft\).md)", "README.md")
        self.assertEqual(links, [("path(draft).md", 1)])
        self.assertEqual(problems, [])

    def test_link_syntax_inside_inline_code_is_ignored(self):
        links, problems = _extract_links(BACKTICK + "[not a link](missing.md)" + BACKTICK, "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_escaped_link_syntax_is_ignored(self):
        links, problems = _extract_links(r"\[not a link\]\(missing.md\)", "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_malformed_unclosed_destination_is_reported(self):
        links, problems = _extract_links("[broken](docs/guide.md", "README.md")
        self.assertEqual(links, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("not closed", problems[0].message)

    def test_angle_bracket_destination_with_title(self):
        links, problems = _extract_links('[guide](<docs/guide with spaces.md> "Guide")', "README.md")
        self.assertEqual(links, [("docs/guide with spaces.md", 1)])
        self.assertEqual(problems, [])

    def test_undefined_reference_is_reported(self):
        _, problems = _extract_links("[guide][missing]", "README.md")
        self.assertEqual(len(problems), 1)
        self.assertIn("undefined Markdown reference", problems[0].message)

    def test_reference_definition_is_extracted(self):
        links, problems = _extract_links("[guide][ref]\n\n[ref]: docs/guide.md", "README.md")
        self.assertEqual(links, [("docs/guide.md", 1)])
        self.assertEqual(problems, [])
    
    def test_unused_reference_definition_is_not_a_navigation_link(self):
        links, problems = _extract_links("[docs]: docs/README.md", "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_duplicate_reference_uses_first_definition(self):
        links, problems = _extract_links(
            "[guide]: missing.md\n[guide]: docs/guide.md\n\n[Open][guide]",
            "README.md",
        )
        self.assertEqual(links, [("missing.md", 4)])
        self.assertTrue(any("duplicate Markdown reference definition" in p.message for p in problems))
        self.assertTrue(any("first definition on line 1" in p.message for p in problems))

    def test_multiline_inline_code_is_ignored(self):
        links, problems = _extract_links(
            "`\n[example](missing-file.md)\n`\n[actual](existing.md)",
            "README.md",
        )
        self.assertEqual(links, [("existing.md", 4)])
        self.assertEqual(problems, [])

    def test_blockquote_fenced_code_is_ignored(self):
        links, problems = _extract_links(
            "> ```md\n> [example](missing-file.md)\n> ```\n[actual](existing.md)",
            "README.md",
        )
        self.assertEqual(links, [("existing.md", 4)])
        self.assertEqual(problems, [])


    def test_quote_marker_does_not_close_plain_fence(self):
        links, problems = _extract_links(
            FENCE + "md\n> " + FENCE + "\n[example](missing-file.md)\n"
            + FENCE + "\n[actual](existing.md)",
            "README.md",
        )
        self.assertEqual(links, [("existing.md", 5)])
        self.assertEqual(problems, [])

    def test_nested_quote_is_not_a_closing_outer_fence(self):
        links, problems = _extract_links(
            "> " + FENCE + "md\n> > " + FENCE + "\n"
            + "> [example](missing-file.md)\n> " + FENCE
            + "\n[actual](existing.md)",
            "README.md",
        )
        self.assertEqual(links, [("existing.md", 5)])
        self.assertEqual(problems, [])


    def test_backslash_escape_for_colon_is_removed_from_destination(self):
        self.assertEqual(_unescape_destination(r"foo\:bar.md"), "foo:bar.md")
        self.assertEqual(_unescape_destination(r"foo\!bar\?baz.md"), "foo!bar?baz.md")



class AnchorTests(unittest.TestCase):
    def test_github_style_heading_anchors_and_duplicates(self):
        anchors = _markdown_anchors("# Hello, World!\n\n## Hello, World!\n\n## " + BACKTICK + "Code" + BACKTICK + " & More\n")
        self.assertIn("hello-world", anchors)
        self.assertIn("hello-world-1", anchors)
        self.assertIn("code-more", anchors)

    def test_fenced_headings_do_not_create_anchors(self):
        anchors = _markdown_anchors(FENCE + "md\n# hidden\n" + FENCE + "\n\n# visible\n")
        self.assertNotIn("hidden", anchors)
        self.assertIn("visible", anchors)

    def test_percent_decoded_fragment(self):
        self.assertEqual(_resolve_target("docs/index.md", "guide.md#Getting%20Started"),
                         ("docs/guide.md", "Getting Started", False))


class LineLengthTests(unittest.TestCase):
    def test_long_inline_code_can_be_atomic(self):
        self.assertTrue(_line_length_is_exempt("See " + BACKTICK + "x" * 90 + BACKTICK + " for details."))

    def test_long_url_can_be_atomic(self):
        self.assertTrue(_line_length_is_exempt("Read https://example.test/" + "x" * 90))

    def test_long_prose_is_not_exempt(self):
        self.assertFalse(_line_length_is_exempt("ordinary prose " + "x" * 90))

    def test_wide_table_is_never_exempt(self):
        self.assertFalse(
            _line_length_is_exempt(
                "| " + BACKTICK + "x" * 90 + BACKTICK + " | value |",
                is_table_row=True,
            )
        )

    def test_pipe_delimited_table_without_leading_pipe_is_not_exempt(self):
        self.assertFalse(
            _line_length_is_exempt(
                "cell | " + BACKTICK + "x" * 90 + BACKTICK + " | value",
                is_table_row=True,
            )
        )


    def test_two_column_table_without_edge_pipes_is_detected(self):
        lines = [
            "Name | Description\n",
            "--- | ---\n",
            "Docs | https://example.test/" + "x" * 100 + "\n",
        ]
        table_lines = _markdown_table_lines(lines, set())
        self.assertEqual(table_lines, {0, 1, 2})
        self.assertTrue(_line_length_is_exempt(lines[2].rstrip("\n")))
        self.assertFalse(
            _line_length_is_exempt(
                lines[2].rstrip("\n"), is_table_row=2 in table_lines
            )
        )



class RepositoryValidationTests(unittest.TestCase):
    def make_repo(self, root: Path):
        (root / "docs").mkdir()
        (root / "docs" / "guide.md").write_text("# Setup\n", encoding="utf-8")
        (root / "LICENSE-MIT").write_text("license\n", encoding="utf-8")
        (root / "LICENSE-APACHE").write_text("license\n", encoding="utf-8")
        (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
        (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
        (root / "docs" / "README.md").write_text("# Documentation\n", encoding="utf-8")
        (root / "docs" / "engineering").mkdir()
        (root / "docs" / "project").mkdir()
        (root / "docs" / "engineering" / "DEVELOPMENT.md").write_text("# Dev\n", encoding="utf-8")
        (root / "docs" / "engineering" / "VERIFICATION.md").write_text("# Verify\n", encoding="utf-8")
        (root / "docs" / "project" / "IMPLEMENTATION_STATUS.md").write_text("# Status\n", encoding="utf-8")
        (root / "README.md").write_text(
            "[docs](docs/README.md)\n[contrib](CONTRIBUTING.md)\n[security](SECURITY.md)\n"
            "[status](docs/project/IMPLEMENTATION_STATUS.md)\n"
            "[dev](docs/engineering/DEVELOPMENT.md)\n"
            "[verify](docs/engineering/VERIFICATION.md)\n"
            "[mit](LICENSE-MIT)\n[apache](LICENSE-APACHE)\n",
            encoding="utf-8",
        )
        (root / "docs" / "README.md").write_text(
            "[world](vision/WORLD_CLASS_OS.md)\n[vision](vision/VISION.md)\n"
            "[principles](vision/PRINCIPLES.md)\n[success](vision/SUCCESS_CRITERIA.md)\n"
            "[overview](architecture/OVERVIEW.md)\n[security](architecture/SECURITY_MODEL.md)\n"
            "[ux](architecture/USER_EXPERIENCE.md)\n[recovery](architecture/UPDATES_AND_RECOVERY.md)\n"
            "[specs](specs/)\n[dev](engineering/DEVELOPMENT.md)\n"
            "[verification](engineering/VERIFICATION.md)\n[contrib](../CONTRIBUTING.md)\n"
            "[policy](../SECURITY.md)\n[status](project/IMPLEMENTATION_STATUS.md)\n"
            "[roadmap](project/ROADMAP.md)\n[adrs](project/decisions/README.md)\n",
            encoding="utf-8",
        )
        for relative in (
            "vision/WORLD_CLASS_OS.md", "vision/VISION.md", "vision/PRINCIPLES.md",
            "vision/SUCCESS_CRITERIA.md", "architecture/OVERVIEW.md", "architecture/SECURITY_MODEL.md",
            "architecture/USER_EXPERIENCE.md", "architecture/UPDATES_AND_RECOVERY.md",
            "specs", "project/ROADMAP.md", "project/decisions/README.md",
        ):
            path = root / "docs" / relative
            if relative == "specs":
                path.mkdir()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Entry\n", encoding="utf-8")

    def test_valid_minimal_repository_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            self.assertEqual(validate_repository(root), [])

    def test_valid_internal_fragment_link_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[setup](docs/guide.md#setup)\n")
            self.assertEqual(validate_repository(root), [])

    def test_unused_reference_definition_does_not_satisfy_required_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text(
                "[docs]: docs/README.md\n", encoding="utf-8"
            )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    "required navigation link is missing: docs/README.md" in problem.message
                    for problem in problems
                )
            )

    def test_long_prose_line_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n" + "x" * 89 + "\n")
            problems = validate_repository(root)
            self.assertTrue(any(p.path == "README.md" and "89 characters" in p.message for p in problems))

    def test_missing_path_and_anchor_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text(
                "[missing](not-here.md) [bad anchor](docs/guide.md#missing)\n", encoding="utf-8"
            )
            problems = validate_repository(root)
            messages = "\n".join(problem.message for problem in problems)
            self.assertIn("missing internal link target", messages)
            self.assertIn("missing heading anchor", messages)

    def test_escaped_parentheses_path_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide(draft).md").write_text("# Draft\n", encoding="utf-8")
            (root / "README.md").write_text(
                "[draft](docs/guide\\(draft\\).md)\n", encoding="utf-8"
            )
            problems = validate_repository(root)
            self.assertTrue(any("required navigation link is missing" in p.message for p in problems))
            self.assertFalse(any("guide(draft).md" in p.message for p in problems))

    def test_repository_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text("[escape](../../outside.md)\n", encoding="utf-8")
            problems = validate_repository(root)
            self.assertTrue(any("escapes repository root" in p.message for p in problems))

    def test_escaped_colon_filename_is_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "foo:bar.md").write_text("# Colon\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("[colon](docs/foo\\:bar.md)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    "missing internal link target" in problem.message
                    and "foo" in problem.message
                    for problem in problems
                )
            )

    def test_single_pipe_two_column_table_url_row_fails_line_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            table = (
                "\nName | Description\n"
                "--- | ---\n"
                "Docs | https://example.test/" + "x" * 100 + "\n"
            )
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write(table)
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and "characters (limit 88)" in problem.message
                    for problem in problems
                )
            )

    def test_code_fence_does_not_trigger_line_or_link_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write("\n" + FENCE + "text\n" + "x" * 120 + " [bad](missing.md)\n" + FENCE + "\n")
            problems = validate_repository(root)
            self.assertFalse(any("missing internal link target" in p.message for p in problems))
            self.assertFalse(any(p.path == "CONTRIBUTING.md" for p in problems))


if __name__ == "__main__":
    unittest.main()
