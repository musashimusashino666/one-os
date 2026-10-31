from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

BACKTICK = chr(96)
FENCE = BACKTICK * 3

from check_docs import (
    _document_inline_code_ranges,
    _extract_links,
    _markdown_table_lines,
    _indented_code_lines,
    _inline_code_ranges,
    _line_length_is_exempt,
    _markdown_block_regions,
    _markdown_anchors,
    _resolve_target,
    _unescape_destination,
    _markdown_table_lines,
    _fenced_code_lines,
    _matching_bracket_pairs,
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

    def test_escaped_closing_parenthesis_adjacent_to_link_close_is_preserved(self):
        links, problems = _extract_links(r"[guide](guide\))", "README.md")
        self.assertEqual(links, [("guide)", 1)])
        self.assertEqual(problems, [])

    def test_link_syntax_inside_inline_code_is_ignored(self):
        links, problems = _extract_links(BACKTICK + "[not a link](missing.md)" + BACKTICK, "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_escaped_link_syntax_is_ignored(self):
        links, problems = _extract_links(r"\[not a link\]\(missing.md\)", "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_unquoted_invalid_inline_link_title_is_rejected(self):
        links, problems = _extract_links(
            "[docs](docs/README.md invalid-title)", "README.md"
        )
        self.assertEqual(links, [])
        self.assertTrue(any("link title must be quoted or parenthesized" in p.message
                            for p in problems))

    def test_valid_inline_link_title_forms_are_accepted(self):
        examples = (
            '[a](a.md "double quoted")',
            "[b](b.md 'single quoted')",
            "[c](c.md (parenthesized (nested) title))",
        )
        for source in examples:
            with self.subTest(source=source):
                links, problems = _extract_links(source, "README.md")
                self.assertEqual(len(links), 1)
                self.assertEqual(problems, [])

    def test_escaped_quotes_inside_quoted_link_title_are_accepted(self):
        links, problems = _extract_links(
            r'[guide](guide.md "a \"quoted\" title")',
            "README.md",
        )
        self.assertEqual(links, [("guide.md", 1)])
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

    def test_html_tag_like_angle_destinations_are_not_masked(self):
        text = (
            "[inline](<custom-element>)\n"
            "\n"
            "[reference]: <custom-element>\n"
            "\n"
            "[reference]"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(
            links,
            [("custom-element", 1), ("custom-element", 5)],
        )
        self.assertEqual(problems, [])

    def test_angle_bracket_reference_destination_with_title(self):
        text = (
            '[guide]: <docs/guide with spaces.md> "Guide"\n'
            '\n'
            '[guide]'
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("docs/guide with spaces.md", 3)])
        self.assertEqual(problems, [])

    def test_multiline_angle_bracket_reference_destinations_are_not_masked(self):
        cases = (
            (
                "[reference]:\n"
                "  <custom-element>\n"
                "\n"
                "[use][reference]",
            ),
            (
                "> [reference]:\n"
                ">   <custom-element>\n"
                ">\n"
                "> [use][reference]",
            ),
            (
                "- [reference]:\n"
                "    <custom-element>\n"
                "\n"
                "  [use][reference]",
            ),
        )
        for (source,) in cases:
            with self.subTest(source=source):
                links, problems = _extract_links(source, "README.md")
                self.assertEqual(links, [("custom-element", 4)])
                self.assertEqual(problems, [])

    def test_undefined_reference_is_reported(self):
        _, problems = _extract_links("[guide][missing]", "README.md")
        self.assertEqual(len(problems), 1)
        self.assertIn("undefined Markdown reference", problems[0].message)

    def test_reference_definition_inside_paragraph_is_not_recognized(self):
        links, problems = _extract_links(
            "Introduction\n[docs]: docs/README.md\n\n[docs]",
            "README.md",
        )
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

    def test_reference_definition_rejects_unquoted_invalid_title(self):
        links, problems = _extract_links(
            '[docs]: docs/README.md invalid-title\n[docs]',
            "README.md",
        )
        self.assertEqual(links, [])
        self.assertTrue(
            any("link title must be quoted or parenthesized" in p.message
                for p in problems)
        )

    def test_reference_definition_accepts_valid_title_forms(self):
        for title in ('"double quoted"', "'single quoted'", "(parenthesized (nested))"):
            with self.subTest(title=title):
                links, problems = _extract_links(
                    f"[docs]: docs/README.md {title}\n[docs]",
                    "README.md",
                )
                self.assertEqual(links, [("docs/README.md", 2)])
                self.assertEqual(problems, [])

    def test_reference_label_accepts_escaped_closing_bracket(self):
        text = "[Foo*bar\\]]: missing.md\n\n[open][Foo*bar\\]]"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 3)])
        self.assertEqual(problems, [])

    def test_reference_label_can_span_multiple_lines(self):
        text = "[Foo\n  Bar]: missing.md\n\n[open][Foo Bar]"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 4)])
        self.assertEqual(problems, [])

    def test_reference_definition_title_can_span_multiple_lines(self):
        text = (
            '[ref]: missing.md "first line\n'
            '  second line\n'
            '  third line"\n'
            '[open][ref]'
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 4)])
        self.assertEqual(problems, [])

    def test_reference_definition_title_can_start_on_following_line(self):
        text = '[ref]: missing.md\n  "title"\n[open][ref]'
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 3)])
        self.assertEqual(problems, [])

    def test_reference_destination_and_multiline_title_can_start_on_following_lines(self):
        text = (
            "[ref]:\n"
            "  missing.md\n"
            '  "first line\n'
            '  second line"\n'
            "\n"
            "[open][ref]"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 6)])
        self.assertEqual(problems, [])

    def test_markdown_links_inside_inline_html_attributes_are_ignored(self):
        text = '<span title="[sample](missing.md)">[visible](existing.md)</span>'
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 1)])
        self.assertEqual(problems, [])

    def test_html_attribute_backtick_does_not_hide_visible_markdown_link(self):
        text = (
            '<span title="` [attribute](attribute.md)">'
            '[visible](missing.md)`</span>'
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 1)])
        self.assertEqual(problems, [])

    def test_meta_tag_does_not_interrupt_open_paragraph_or_hide_following_link(self):
        text = (
            "Intro paragraph\n"
            '<meta charset="utf-8">\n'
            "[broken](missing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 3)])
        self.assertEqual(problems, [])
        self.assertNotIn(1, _markdown_block_regions(text.splitlines(keepends=True))[1])

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

    def test_consecutive_duplicate_reference_definitions_remain_block_definitions(self):
        links, problems = _extract_links(
            "[first]: first.md\n"
            "[first]: duplicate.md\n"
            "[second]: second.md\n"
            "[Open][second]",
            "README.md",
        )
        self.assertEqual(links, [("second.md", 4)])
        self.assertTrue(
            any("duplicate Markdown reference definition 'first'" in p.message
                for p in problems)
        )

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


    def test_blockquote_lazy_continuation_keeps_multiline_inline_code(self):
        text = (
            "> " + BACKTICK + "code\n"
            "[not-a-link](missing.md)" + BACKTICK + "\n"
            "\n"
            "[actual](existing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 4)])
        self.assertEqual(problems, [])

    def test_blockquote_lazy_continuation_link_is_extracted(self):
        text = "> [broken\nlink](missing.md)\n"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 1)])
        self.assertEqual(problems, [])

    def test_nested_blockquote_lazy_continuation_link_is_extracted(self):
        text = "> > [broken\n> link](missing.md)\n"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 1)])
        self.assertEqual(problems, [])

    def test_list_lazy_continuation_link_is_extracted(self):
        text = "- [broken\nlink](missing.md)\n"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 1)])
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



    def test_list_fenced_code_is_ignored(self):
        text = (
            "- item\n\n"
            "    " + FENCE + "md\n"
            "    [example](missing-file.md)\n"
            "    " + FENCE + "\n"
            "[actual](existing.md)"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 6)])
        self.assertEqual(problems, [])

    def test_multiline_reference_definitions_in_containers(self):
        text = (
            "[top]:\n"
            "  docs/guide.md\n"
            "[open][top]\n\n"
            "> [quoted]:\n"
            ">   docs/guide.md\n"
            "> [open][quoted]\n\n"
            "- [listed]:\n"
            "  docs/guide.md\n"
            "  [open][listed]\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(
            links,
            [("docs/guide.md", 3), ("docs/guide.md", 7), ("docs/guide.md", 11)],
        )
        self.assertEqual(problems, [])

    def test_html_comments_hide_links_and_reference_definitions(self):
        text = (
            "<!--\n"
            "[docs]: docs/README.md\n"
            "[broken](missing.md)\n"
            "# hidden heading\n"
            "-->\n"
            "[docs]\n"
            "[visible](existing.md)"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 7)])
        self.assertEqual(problems, [])

    def test_inline_html_comment_preserves_links_after_comment(self):
        text = (
            "[first](first.md) <!-- [hidden](missing.md) --> "
            "[second](second.md)"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("first.md", 1), ("second.md", 1)])
        self.assertEqual(problems, [])

    def test_empty_inline_and_reference_destinations_are_valid(self):
        text = "[self]()\n\n[empty]: <>\n[reference][empty]"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("", 1), ("", 4)])
        self.assertEqual(problems, [])

    def test_inline_code_spans_do_not_pair_across_blank_paragraphs(self):
        text = (
            "`" + "\n\n"
            "[broken](missing.md)\n\n"
            "`"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 3)])
        self.assertEqual(problems, [])

    def test_inline_code_spans_do_not_cross_atx_heading_blocks(self):
        text = (
            BACKTICK + "\n"
            "# Heading\n"
            "[broken](missing.md)\n"
            + BACKTICK
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 3)])
        self.assertEqual(problems, [])

    def test_inline_code_spans_do_not_cross_list_or_blockquote_boundaries(self):
        documents = (
            BACKTICK + "\n- item\n[broken](missing.md)\n" + BACKTICK,
            BACKTICK + "\n> quoted\n[broken](missing.md)\n" + BACKTICK,
            BACKTICK + "\n---\n[broken](missing.md)\n" + BACKTICK,
        )
        for text in documents:
            with self.subTest(text=text):
                links, problems = _extract_links(text, "README.md")
                self.assertIn(("missing.md", 3), links)
                self.assertEqual(problems, [])

    def test_indented_code_block_links_are_ignored(self):
        text = (
            "    [hidden](missing.md)\n"
            "    [hidden reference]: missing-ref.md\n"
            "\n"
            "[visible](existing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 4)])
        self.assertEqual(problems, [])

    def test_inline_and_reference_images_are_separated_from_clickable_links(self):
        text = (
            "![inline](assets/logo.png)\n"
            "![reference][docs-image]\n"
            "\n"
            "[docs-image]: docs/README.md\n"
            "[clickable](docs/README.md)\n"
        )
        images = []
        links, problems = _extract_links(
            text, "README.md", image_targets=images
        )
        self.assertEqual(links, [("docs/README.md", 5)])
        self.assertEqual(
            images,
            [("assets/logo.png", 1), ("docs/README.md", 2)],
        )
        self.assertEqual(problems, [])

    def test_unmatched_brackets_are_paired_in_linear_pass(self):
        self.assertEqual(_matching_bracket_pairs("[" * 100_000), {})
        self.assertEqual(
            _matching_bracket_pairs("[outer [inner]] \\[escaped]"),
            {7: 13, 0: 14},
        )
        links, problems = _extract_links("[" * 10_000, "README.md")
        self.assertEqual(links, [])
        self.assertEqual(problems, [])

class AnchorTests(unittest.TestCase):
    def test_github_style_heading_anchors_and_duplicates(self):
        anchors = _markdown_anchors("# Hello, World!\n\n## Hello, World!\n\n## " + BACKTICK + "Code" + BACKTICK + " & More\n")
        self.assertIn("hello-world", anchors)
        self.assertIn("hello-world-1", anchors)
        self.assertIn("code--more", anchors)

    def test_indented_code_blocks_do_not_create_markdown_or_html_anchors(self):
        anchors = _markdown_anchors(
            "    # hidden heading\n"
            "    <div id=\"hidden-html\"></div>\n"
            "\n"
            "# visible heading\n"
        )
        self.assertNotIn("hidden-heading", anchors)
        self.assertNotIn("hidden-html", anchors)
        self.assertIn("visible-heading", anchors)

    def test_setext_paragraph_lines_are_not_code_blocks(self):
        lines = ["Some\n", "Heading\n", "-------\n"]
        fenced, html = _markdown_block_regions(lines)
        self.assertEqual(fenced | html, set())
        self.assertEqual(_indented_code_lines(lines, fenced | html), set())

    def test_multiline_setext_heading_uses_all_text_lines(self):
        anchors = _markdown_anchors(
            "Some\n"
            "Heading\n"
            "-------\n"
        )
        self.assertIn("some-heading", anchors)
        self.assertNotIn("heading", anchors)

    def test_lazy_blockquote_line_is_included_in_multiline_setext_heading(self):
        anchors = _markdown_anchors(
            "> First\n"
            "Second\n"
            "> =====\n"
        )
        self.assertIn("first-second", anchors)
        self.assertNotIn("second", anchors)

    def test_setext_underline_cannot_be_a_lazy_blockquote_continuation(self):
        anchors = _markdown_anchors(
            "> First\n"
            "Second\n"
            "=====\n"
        )
        self.assertNotIn("first-second", anchors)

    def test_heading_inline_link_destination_with_nested_parentheses_is_removed(self):
        anchors = _markdown_anchors("## [Guide](guide_(draft).md)\n")
        self.assertIn("guide", anchors)
        self.assertNotIn("guide-draftmd", anchors)

    def test_heading_html_character_references_are_decoded(self):
        anchors = _markdown_anchors("## AT&amp;T\n")
        self.assertIn("att", anchors)
        self.assertNotIn("atampt", anchors)

    def test_fenced_headings_do_not_create_anchors(self):
        anchors = _markdown_anchors(FENCE + "md\n# hidden\n" + FENCE + "\n\n# visible\n")
        self.assertNotIn("hidden", anchors)
        self.assertIn("visible", anchors)

    def test_percent_decoded_fragment(self):
        self.assertEqual(_resolve_target("docs/index.md", "guide.md#Getting%20Started"),
                         ("docs/guide.md", "Getting Started", False))


    def test_blockquote_atx_and_setext_headings_create_anchors(self):
        anchors = _markdown_anchors(
            "> # Introduction\n\n"
            "> Quoted Setext Heading\n"
            "> ---------------------\n"
        )
        self.assertIn("introduction", anchors)
        self.assertIn("quoted-setext-heading", anchors)


    def test_raw_html_blocks_do_not_create_markdown_links_or_anchors(self):
        text = (
            "<div>\n"
            "[hidden](missing.md)\n"
            "# hidden heading\n"
            "</div>\n\n"
            "[visible](existing.md)\n"
            "# visible heading\n"
        )
        links, problems = _extract_links(text, "README.md")
        anchors = _markdown_anchors(text)
        self.assertEqual(links, [("existing.md", 6)])
        self.assertEqual(problems, [])
        self.assertNotIn("hidden-heading", anchors)
        self.assertIn("visible-heading", anchors)

    def test_html_block_classes_are_excluded_from_markdown_parsing(self):
        documents = (
            "<script>\n[hidden](missing.md)\n</script>\n\n[visible](ok.md)",
            "<?processor\n[hidden](missing.md)\n?>\n\n[visible](ok.md)",
            "<![CDATA[\n[hidden](missing.md)\n]]>\n\n[visible](ok.md)",
            "<!DOCTYPE html\n[hidden](missing.md)\n>\n\n[visible](ok.md)",
            "<custom-element>\n[hidden](missing.md)\n</custom-element>\n\n[visible](ok.md)",
        )
        for document in documents:
            with self.subTest(document=document.splitlines()[0]):
                links, problems = _extract_links(document, "README.md")
                self.assertEqual(links, [("ok.md", len(document.splitlines()))])
                self.assertEqual(problems, [])
    def test_type6_html_block_accepts_tag_name_at_end_of_line(self):
        text = (
            "<div\n"
            "[hidden](hidden.md)\n"
            "\n"
            "[visible](existing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 4)])
        self.assertEqual(problems, [])

    def test_type6_html_block_rejects_arbitrary_slash_after_tag_name(self):
        text = "<div/foo>\n[visible](missing.md)\n"
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 2)])
        self.assertEqual(problems, [])

    def test_type7_html_block_accepts_greater_than_in_quoted_attribute(self):
        text = (
            "\n"
            '<custom-element title="a > b">\n'
            "[hidden](hidden.md)\n"
            "</custom-element>\n"
            "\n"
            "[visible](existing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("existing.md", 6)])
        self.assertEqual(problems, [])

    def test_html_comment_backticks_do_not_pair_across_paragraph_boundary(self):
        text = (
            "\x60unmatched paragraph\n"
            "\n"
            "<!-- comment\n"
            "\x60\n"
            "\x60\x60\x60text\n"
            "[hidden](hidden.md)\n"
            "-->\n"
            "[visible](missing.md)\n"
        )
        links, problems = _extract_links(text, "README.md")
        self.assertEqual(links, [("missing.md", 8)])
        self.assertEqual(problems, [])

    def test_html_named_anchor_is_recognized(self):
        anchors = _markdown_anchors('<a name="custom-anchor"></a>\n')
        self.assertIn("custom-anchor", anchors)

    def test_emoji_is_removed_from_github_heading_slug(self):
        anchors = _markdown_anchors("## 😄 emoji\n")
        self.assertIn("-emoji", anchors)
        self.assertNotIn("😄-emoji", anchors)

class LineLengthTests(unittest.TestCase):
    def test_long_inline_code_can_be_atomic(self):
        self.assertTrue(_line_length_is_exempt("See " + BACKTICK + "x" * 90 + BACKTICK + " for details."))

    def test_long_url_can_be_atomic(self):
        self.assertTrue(_line_length_is_exempt("Read https://example.test/" + "x" * 90))

    def test_many_short_inline_code_spans_are_checked_without_rebuilding_the_line(self):
        line = (chr(96) + "x" + chr(96) + " ") * 4096
        self.assertTrue(_line_length_is_exempt(line.rstrip(), max_line_length=8192))

    def test_long_inline_code_with_spaces_is_not_atomic(self):
        line = "See " + BACKTICK + "x" * 45 + " " + "y" * 45 + BACKTICK
        self.assertFalse(_line_length_is_exempt(line))

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



    def test_one_column_table_without_edge_pipe_rows_are_never_line_exempt(self):
        lines = [
            "| URL |\n",
            "| --- |\n",
            "| https://example.test/" + "x" * 100 + " |\n",
        ]
        table_lines = _markdown_table_lines(lines, set())
        self.assertEqual(table_lines, {0, 1, 2})
        self.assertFalse(
            _line_length_is_exempt(
                lines[2].rstrip("\n"), is_table_row=2 in table_lines
            )
        )



    def test_list_and_nested_blockquote_tables_are_detected(self):
        documents = (
            (
                "- | URL |\n"
                "  | --- |\n"
                "  | https://example.test/" + "x" * 100 + " |\n",
                {0, 1, 2},
            ),
            (
                "- outer\n"
                "  - | URL |\n"
                "    | --- |\n"
                "    | https://example.test/" + "x" * 100 + " |\n",
                {1, 2, 3},
            ),
            (
                "> - | URL |\n"
                ">   | --- |\n"
                ">   | https://example.test/" + "x" * 100 + " |\n",
                {0, 1, 2},
            ),
        )
        for document, expected in documents:
            with self.subTest(document=document):
                lines = document.splitlines(keepends=True)
                table_lines = _markdown_table_lines(lines, set())
                self.assertEqual(table_lines, expected)
                for row in expected:
                    if row >= 2:
                        self.assertFalse(
                            _line_length_is_exempt(
                                lines[row].rstrip("\n"), is_table_row=True
                            )
                        )

    def test_list_contained_table_url_row_fails_repository_line_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            RepositoryValidationTests().make_repo(root)
            table = (
                "\n- | URL |\n"
                "  | --- |\n"
                "  | https://example.test/" + "x" * 100 + " |\n"
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

    def test_visible_text_in_raw_html_block_obeys_line_length_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            visible_line = "Visible HTML prose: " + "x" * 90
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write("\n<div>\n" + visible_line + "\n</div>\n")
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and f"{len(visible_line)} characters (limit 88)" in problem.message
                    for problem in problems
                )
            )

    def test_brackets_cannot_pair_across_blank_paragraph_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text(
                "[\n\n[broken](missing.md)\n\n](docs/README.md)\n",
                encoding="utf-8",
            )
            problems = validate_repository(root)
            messages = "\n".join(problem.message for problem in problems)
            self.assertIn("missing internal link target: missing.md", messages)
            self.assertIn(
                "required navigation link is missing: docs/README.md", messages
            )

    def test_paragraph_embedded_reference_definition_does_not_satisfy_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text(
                "Introduction\n"
                "[docs]: docs/README.md\n\n"
                "[docs]\n"
                "[contrib](CONTRIBUTING.md)\n"
                "[security](SECURITY.md)\n"
                "[status](docs/project/IMPLEMENTATION_STATUS.md)\n"
                "[dev](docs/engineering/DEVELOPMENT.md)\n"
                "[verify](docs/engineering/VERIFICATION.md)\n"
                "[mit](LICENSE-MIT)\n"
                "[apache](LICENSE-APACHE)\n",
                encoding="utf-8",
            )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    "required navigation link is missing: docs/README.md" in p.message
                    for p in problems
                )
            )

    def test_invalid_inline_link_title_does_not_satisfy_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8").replace(
                    "[docs](docs/README.md)",
                    "[docs](docs/README.md invalid-title)",
                ),
                encoding="utf-8",
            )
            problems = validate_repository(root)
            messages = "\n".join(p.message for p in problems)
            self.assertIn("link title must be quoted or parenthesized", messages)
            self.assertIn("required navigation link is missing: docs/README.md", messages)

    def test_invalid_reference_definition_title_does_not_satisfy_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            readme = root / "README.md"
            text = readme.read_text(encoding="utf-8")
            text = text.replace("[docs](docs/README.md)\n", "", 1)
            readme.write_text(
                "[docs]: docs/README.md invalid-title\n\n" + text,
                encoding="utf-8",
            )
            problems = validate_repository(root)
            messages = "\n".join(p.message for p in problems)
            self.assertIn("link title must be quoted or parenthesized", messages)
            self.assertIn("required navigation link is missing: docs/README.md", messages)

    def test_invalid_external_url_reports_path_and_line_instead_of_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write("\n[invalid](http://[)\n")
            problems = validate_repository(root)
            matches = [
                p for p in problems
                if p.path == "CONTRIBUTING.md" and "malformed link URL" in p.message
            ]
            self.assertEqual(len(matches), 1)
            self.assertGreater(matches[0].line, 0)

    def test_repository_resolves_escaped_reference_label_and_reports_missing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[Foo*bar\\]]: missing.md\n\n"
                    "[open][Foo*bar\\]]\n"
                )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "README.md"
                    and "missing internal link target: missing.md" in problem.message
                    for problem in problems
                )
            )

    def test_malformed_inline_link_does_not_hide_later_links(self):
        links, problems = _extract_links(
            "[broken](unterminated\n\n[missing](missing.md)",
            "README.md",
        )
        self.assertEqual(links, [("missing.md", 3)])
        self.assertTrue(
            any("link title must be quoted or parenthesized" in p.message
                for p in problems)
        )

    def test_nested_image_inside_link_is_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[![logo](assets/missing.png)](docs/README.md)\n"
                )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "README.md"
                    and "missing internal link target: assets/missing.png"
                    in problem.message
                    for problem in problems
                )
            )

    def test_repository_reports_visible_link_after_html_attribute_backtick(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write(
                    '\n<span title="` [attribute](attribute.md)">'
                    '[visible](missing.md)`</span>\n'
                )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and "missing internal link target: missing.md" in problem.message
                    for problem in problems
                )
            )
            self.assertFalse(
                any("attribute.md" in problem.message for problem in problems)
            )

    def test_repository_reports_missing_link_after_meta_inside_paragraph(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write(
                    '\nIntro paragraph\n'
                    '<meta charset="utf-8">\n'
                    '[broken](missing.md)\n'
                )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and "missing internal link target: missing.md" in problem.message
                    for problem in problems
                )
            )

    def test_html_like_angle_text_is_preserved_in_heading_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "docs" / "guide.md").open("a", encoding="utf-8") as output:
                output.write("\n## <3> <!-- heading comment -->\n")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[three](docs/guide.md#3)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    "missing heading anchor '#3'" in problem.message
                    for problem in problems
                )
            )

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

    def test_single_column_table_url_row_fails_line_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            table = (
                "\n| URL |\n"
                "| --- |\n"
                "| https://example.test/" + "x" * 100 + " |\n"
            )
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write(table)
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and problem.line > 0
                    and "characters (limit 88)" in problem.message
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


    def test_blockquote_heading_fragment_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide.md").write_text(
                "> # Introduction\n", encoding="utf-8"
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[quoted heading](docs/guide.md#introduction)\n")
            self.assertEqual(validate_repository(root), [])

    def test_list_fenced_code_is_excluded_from_link_and_line_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            block = (
                "\n- example\n\n"
                "    " + FENCE + "text\n"
                "    " + "x" * 120 + " [ignored](missing.md)\n"
                "    " + FENCE + "\n"
            )
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write(block)
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and (
                        "missing internal link target" in problem.message
                        or "characters (limit 88)" in problem.message
                    )
                    for problem in problems
                )
            )

    def test_markdown_extension_is_validated_like_md(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "reference.markdown").write_text(
                "[missing](not-found.md)\n" + "x" * 89 + "\n",
                encoding="utf-8",
            )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "docs/reference.markdown"
                    and "missing internal link target" in problem.message
                    for problem in problems
                )
            )
            self.assertTrue(
                any(
                    problem.path == "docs/reference.markdown"
                    and "characters (limit 88)" in problem.message
                    for problem in problems
                )
            )

    def test_comment_only_navigation_does_not_satisfy_required_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "README.md").write_text(
                "<!--\n[docs]: docs/README.md\n-->\n[docs]\n",
                encoding="utf-8",
            )
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    "required navigation link is missing: docs/README.md" in problem.message
                    for problem in problems
                )
            )

    def test_empty_destinations_resolve_to_the_current_markdown_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            self_doc = root / "docs" / "self.md"
            self_doc.write_text(
                "# Home\n"
                "[self]()\n"
                "[home](#home)\n"
                "[empty]: <>\n"
                "[reference][empty]\n",
                encoding="utf-8",
            )
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "docs/self.md"
                    and (
                        "link destination is empty" in problem.message
                        or "missing internal link target" in problem.message
                        or "missing heading anchor" in problem.message
                    )
                    for problem in problems
                )
            )

    def test_inline_code_heading_anchor_resolves_in_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide.md").write_text(
                "## `Code` & More\n",
                encoding="utf-8",
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[code heading](docs/guide.md#code--more)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "README.md"
                    and "missing heading anchor '#code--more'" in problem.message
                    for problem in problems
                )
            )
    def test_html_named_anchor_fragment_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide.md").write_text('<a name="custom-anchor"></a>\n',
                encoding="utf-8",
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[custom](docs/guide.md#custom-anchor)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "README.md"
                    and "missing heading anchor '#custom-anchor'" in problem.message
                    for problem in problems
                )
            )

    def test_emoji_heading_fragment_matches_github_slug(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide.md").write_text("## 😄 emoji\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[emoji](docs/guide.md#-emoji)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "README.md"
                    and "missing heading anchor '#-emoji'" in problem.message
                    for problem in problems
                )
            )

    def test_indented_code_block_is_excluded_from_links_anchors_and_line_length(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            code_line = "    " + "[hidden](missing.md) " + ("x" * 100)
            (root / "docs" / "guide.md").write_text(
                "    <div id=\"fake-anchor\"></div>\n"
                + code_line + "\n",
                encoding="utf-8",
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n[code fake link](docs/guide.md#fake-anchor)\n")
            problems = validate_repository(root)
            self.assertTrue(
                any("missing heading anchor '#fake-anchor'" in p.message for p in problems)
            )
            self.assertFalse(
                any("missing internal link target: missing.md" in p.message for p in problems)
            )
            self.assertFalse(
                any(p.path == "docs/guide.md" and "characters (limit 88)" in p.message
                    for p in problems)
            )

    def test_multiline_setext_heading_and_html_entity_fragment_resolve(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "guide.md").write_text(
                "Some\nHeading\n-------\n\n## AT&amp;T\n",
                encoding="utf-8",
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[setext](docs/guide.md#some-heading)\n"
                    "[entity](docs/guide.md#att)\n"
                )
            problems = validate_repository(root)
            self.assertFalse(any("missing heading anchor" in p.message for p in problems))


    def test_inline_link_destinations_decode_html_character_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "R&D.md").write_text("# Research and development\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[named](docs/R&amp;D.md)\n"
                    "[decimal](docs/R&#38;D.md)\n"
                    "[hex](docs/R&#x26;D.md)\n"
                )
            links, parse_problems = _extract_links(
                "[named](docs/R&amp;D.md)\n"
                "[decimal](docs/R&#38;D.md)\n"
                "[hex](docs/R&#x26;D.md)\n",
                "README.md",
            )
            self.assertEqual(
                links,
                [
                    ("docs/R&D.md", 1),
                    ("docs/R&D.md", 2),
                    ("docs/R&D.md", 3),
                ],
            )
            self.assertEqual(parse_problems, [])
            problems = validate_repository(root)
            self.assertFalse(
                any("missing internal link target" in problem.message for problem in problems)
            )

    def test_reference_destinations_decode_html_character_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "R&D.md").write_text("# Research and development\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[named][named]\n"
                    "[decimal][decimal]\n"
                    "[hex][hex]\n\n"
                    "[named]: docs/R&amp;D.md \"named entity\"\n"
                    "[decimal]: docs/R&#38;D.md\n"
                    "[hex]: docs/R&#x26;D.md\n"
                )
            links, parse_problems = _extract_links(
                "[named][named]\n"
                "[decimal][decimal]\n"
                "[hex][hex]\n\n"
                "[named]: docs/R&amp;D.md \"named entity\"\n"
                "[decimal]: docs/R&#38;D.md\n"
                "[hex]: docs/R&#x26;D.md\n",
                "README.md",
            )
            self.assertEqual(
                links,
                [
                    ("docs/R&D.md", 1),
                    ("docs/R&D.md", 2),
                    ("docs/R&D.md", 3),
                ],
            )
            self.assertEqual(parse_problems, [])
            problems = validate_repository(root)
            self.assertFalse(
                any("missing internal link target" in problem.message for problem in problems)
            )

    def test_escaped_and_invalid_html_character_references_remain_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "docs" / "R&amp;D.md").write_text("# Literal entity text\n", encoding="utf-8")
            (root / "docs" / "R&copy.md").write_text("# Missing semicolon\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[escaped](docs/R\\&amp;D.md)\n"
                    "[missing semicolon](docs/R&copy.md)\n"
                )
            links, parse_problems = _extract_links(
                r"[escaped](docs/R\&amp;D.md)" + "\n"
                "[missing semicolon](docs/R&copy.md)\n",
                "README.md",
            )
            self.assertEqual(
                links,
                [
                    ("docs/R&amp;D.md", 1),
                    ("docs/R&copy.md", 2),
                ],
            )
            self.assertEqual(parse_problems, [])
            problems = validate_repository(root)
            self.assertFalse(
                any("missing internal link target" in problem.message for problem in problems)
            )

    def test_repository_link_with_multiline_angle_bracket_reference_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            (root / "custom-element").write_text("target\n", encoding="utf-8")
            (root / "README.md").open("a", encoding="utf-8").write(
                "\n[reference]:\n"
                "  <custom-element>\n"
                "\n"
                "[use][reference]\n"
            )
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    "malformed Markdown reference" in problem.message
                    or "missing internal link target: custom-element" in problem.message
                    for problem in problems
                )
            )

    def test_image_to_required_target_does_not_satisfy_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            readme = root / "README.md"
            contents = readme.read_text(encoding="utf-8")
            contents = contents.replace(
                "[docs](docs/README.md)",
                "![docs](docs/README.md)",
                1,
            )
            readme.write_text(contents, encoding="utf-8")
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "README.md"
                    and "required navigation link is missing: docs/README.md" in problem.message
                    for problem in problems
                )
            )
            self.assertFalse(
                any(
                    "missing internal link target: docs/README.md" in problem.message
                    for problem in problems
                )
            )

    def test_image_fragments_are_not_validated_as_markdown_heading_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            assets = root / "assets"
            assets.mkdir()
            (assets / "diagram.svg").write_text(
                '<svg xmlns="http://www.w3.org/2000/svg"><rect id="third"/></svg>\n',
                encoding="utf-8",
            )
            with (root / "CONTRIBUTING.md").open("a", encoding="utf-8") as output:
                output.write("\n![region](assets/diagram.svg#third)\n")
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    problem.path == "CONTRIBUTING.md"
                    and "fragment target is not a Markdown file" in problem.message
                    for problem in problems
                )
            )

    def test_missing_image_target_is_still_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write("\n![missing asset](assets/missing.png)\n")
            problems = validate_repository(root)
            self.assertTrue(
                any(
                    problem.path == "README.md"
                    and "missing internal link target: assets/missing.png" in problem.message
                    for problem in problems
                )
            )



class GitHubCompatibilityTests(unittest.TestCase):
    def test_heading_slug_preserves_underscores(self):
        anchors = _markdown_anchors("# foo_bar\n")
        self.assertIn("foo_bar", anchors)
        self.assertNotIn("foobar", anchors)

    def test_heading_slug_requires_semicolon_terminated_entity_reference(self):
        anchors = _markdown_anchors("## AT&amp\n## AT&amp;\n")
        self.assertIn("atamp", anchors)
        self.assertIn("at", anchors)

    def test_heading_slug_keeps_github_unicode_symbol_exceptions(self):
        anchors = _markdown_anchors("# ⓔ emoji\n")
        self.assertIn("ⓔ-emoji", anchors)

    def test_heading_slug_preserves_repeated_hyphens(self):
        anchors = _markdown_anchors("# foo--bar\n")
        self.assertIn("foo--bar", anchors)
        self.assertNotIn("foo-bar", anchors)

    def test_duplicate_heading_slug_skips_existing_literal_suffix(self):
        anchors = _markdown_anchors("# foo\n# foo\n# foo-1\n")
        self.assertIn("foo", anchors)
        self.assertIn("foo-1", anchors)
        self.assertIn("foo-1-1", anchors)

    def test_html_id_is_collected_from_any_element(self):
        anchors = _markdown_anchors(
            '<div id="overview"></div>\n'
            '<h2 id="details">Details</h2>\n'
        )
        self.assertIn("overview", anchors)
        self.assertIn("details", anchors)

    def test_legacy_name_is_collected_only_from_anchor_elements(self):
        anchors = _markdown_anchors(
            '<a name="legacy-anchor"></a>\n'
            '<div name="not-an-anchor"></div>\n'
        )
        self.assertIn("legacy-anchor", anchors)
        self.assertNotIn("not-an-anchor", anchors)

    def test_repository_link_to_heading_with_missing_entity_semicolon_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            RepositoryValidationTests().make_repo(root)
            (root / "docs" / "guide.md").write_text("## AT&amp\n", encoding="utf-8")
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[literal entity](docs/guide.md#atamp)\n"
                    "[incorrect decoded form](docs/guide.md#at)\n"
                )
            problems = validate_repository(root)
            self.assertFalse(
                any("missing heading anchor '#atamp'" in problem.message for problem in problems)
            )
            self.assertTrue(
                any("missing heading anchor '#at'" in problem.message for problem in problems)
            )

    def test_repository_link_to_non_anchor_html_id_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            RepositoryValidationTests().make_repo(root)
            (root / "docs" / "guide.md").write_text(
                '<div id="overview"></div>\n<h2 id="details">Details</h2>\n',
                encoding="utf-8",
            )
            with (root / "README.md").open("a", encoding="utf-8") as output:
                output.write(
                    "\n[overview](docs/guide.md#overview)\n"
                    "[details](docs/guide.md#details)\n"
                )
            problems = validate_repository(root)
            self.assertFalse(
                any(
                    "missing heading anchor" in problem.message
                    for problem in problems
                )
            )

    def test_varied_unmatched_backtick_runs_are_processed_without_rescanning(self):
        class FindCountingText(str):
            def __new__(cls, value: str):
                instance = super().__new__(cls, value)
                instance.find_calls = 0
                return instance

            def find(self, *args, **kwargs):
                self.find_calls += 1
                return super().find(*args, **kwargs)

        text = FindCountingText(
            "".join(BACKTICK * run_length + "x" for run_length in range(1, 350))
        )
        self.assertEqual(_inline_code_ranges(text), [])
        self.assertEqual(text.find_calls, 0)

    def test_inline_code_matcher_pairs_exact_run_lengths(self):
        text = BACKTICK + "one " + BACKTICK * 2 + "two" + BACKTICK + " three " + BACKTICK * 2
        ranges = _inline_code_ranges(text)
        closing = text.index(BACKTICK, text.index("two") + 3)
        self.assertEqual(ranges, [(0, closing + 1)])



if __name__ == "__main__":
    unittest.main()
