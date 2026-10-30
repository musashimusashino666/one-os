"""Regression tests for the explicit CR3 source policy."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from check_cr3_source_policy import (
    EXPECTED_ASM_COUNTS,
    _assembly_macro_bodies,
    _assembler_directive_errors,
    _walk_package,
    _resolved_local_dependency_errors,
    source_policy_errors,
)


class Cr3SourcePolicyTests(unittest.TestCase):
    def test_allowlist_is_explicit_for_current_assembly_files(self):
        self.assertEqual(
            EXPECTED_ASM_COUNTS["kernel/src/address_space.rs"],
            30,
        )
        self.assertEqual(
            EXPECTED_ASM_COUNTS["kernel/src/paging/editor/acceptance.rs"],
            1,
        )

    def test_new_assembly_call_outside_allowlist_fails_closed(self):
        errors = source_policy_errors("kernel/src/new_writer.rs", 'asm!("mov cr3, {}");')
        self.assertTrue(any("asm! site count" in error for error in errors), errors)

    def test_changed_count_in_reviewed_file_fails_closed(self):
        errors = source_policy_errors("kernel/src/address_space.rs", 'asm!("mov cr3, {}");')
        self.assertTrue(any("asm! site count" in error for error in errors), errors)

    def test_assembly_macro_tokens_allow_comments_as_whitespace(self):
        cases = (
            'asm/* block comment */!("mov cr3, rax");',
            'asm// line comment\n!("mov cr3, rax");',
            'asm!/* after bang */("mov cr3, rax");',
            'asm/* outer /* nested */ inner */!("mov cr3, rax");',
            'asm /* delimiter comment */ ! { "mov cr3, rax" }',
        )
        for source in cases:
            with self.subTest(source=source):
                errors = source_policy_errors("kernel/src/new_writer.rs", source)
                self.assertTrue(
                    any("asm! site count is 1" in error for error in errors),
                    errors,
                )
                bodies, delimiter_errors = _assembly_macro_bodies(source)
                self.assertEqual(delimiter_errors, [])
                self.assertEqual(len(bodies), 1)

    def test_global_assembly_macro_tokens_allow_comments_as_whitespace(self):
        cases = (
            'global_asm/* block comment */!("nop; .byte 0x90");',
            'global_asm// line comment\n!/* before delimiter */("nop; .byte 0x90");',
            'global_asm/* outer /* nested */ inner */!("nop; .byte 0x90");',
            'global_asm /* delimiter comment */ ! ["nop; .byte 0x90"]',
        )
        for source in cases:
            with self.subTest(source=source):
                errors = source_policy_errors("kernel/src/new_writer.rs", source)
                self.assertTrue(
                    any("global_asm! site count is 1" in error for error in errors),
                    errors,
                )
                directive_errors = _assembler_directive_errors(
                    "kernel/src/new_writer.rs", source
                )
                self.assertTrue(any(".byte" in error for error in directive_errors), directive_errors)

    def test_raw_identifier_assembly_macro_is_counted_and_extracted(self):
        source = 'r#asm/* comment */!("mov cr3, rax");'
        errors = source_policy_errors("kernel/src/new_writer.rs", source)
        self.assertTrue(
            any("asm! site count is 1" in error for error in errors),
            errors,
        )
        bodies, delimiter_errors = _assembly_macro_bodies(source)
        self.assertEqual(delimiter_errors, [])
        self.assertEqual(len(bodies), 1)

        qualified = 'core::arch::r#asm!("mov cr3, rax");'
        qualified_errors = source_policy_errors(
            "kernel/src/new_writer.rs", qualified
        )
        self.assertTrue(
            any("qualified assembly macro paths are denied" in error for error in qualified_errors),
            qualified_errors,
        )

    def test_macro_text_inside_comments_and_literals_is_not_a_callsite(self):
        source = '''
            // asm!("mov cr3, rax");
            let ordinary = "global_asm!(.byte 0x90)";
            /* nested /* asm!("mov cr3, rax") */ comment */
        '''
        errors = source_policy_errors("kernel/src/new_writer.rs", source)
        self.assertFalse(any("asm! site count" in error for error in errors), errors)
        self.assertFalse(any("global_asm! site count" in error for error in errors), errors)
        bodies, delimiter_errors = _assembly_macro_bodies(source)
        self.assertEqual(delimiter_errors, [])
        self.assertEqual(bodies, [])

    def test_naked_assembly_and_include_are_denied(self):
        errors = source_policy_errors(
            "kernel/src/new_writer.rs",
            'naked_asm!("mov cr3, rax"); include!("hidden.rs");',
        )
        joined = "\n".join(errors)
        self.assertIn("naked_asm! is unsupported", joined)
        self.assertIn("include! is denied", joined)

    def test_assembly_macro_aliases_and_reexports_are_denied(self):
        source = """
            use core::arch::asm as raw_asm;
            pub use third_party::global_asm;
            raw_asm!("mov cr3, {}");
        """
        joined = "\n".join(source_policy_errors("kernel/src/new_writer.rs", source))
        self.assertIn("aliases of assembly or include macros", joined)
        self.assertIn("public re-exports of assembly macros", joined)

    def test_unreviewed_unaliased_assembly_import_is_denied(self):
        errors = source_policy_errors(
            "kernel/src/new_writer.rs",
            "use unrelated::asm;",
        )
        self.assertTrue(
            any("unreviewed import of an assembly/include macro" in error for error in errors),
            errors,
        )

    def test_core_arch_wildcards_and_grouped_aliases_are_denied(self):
        wildcard_errors = source_policy_errors(
            "kernel/src/new_writer.rs",
            "use core::arch::*;",
        )
        self.assertTrue(
            any("aliases and wildcard imports involving core::arch" in error for error in wildcard_errors),
            wildcard_errors,
        )
        grouped_alias_errors = source_policy_errors(
            "kernel/src/new_writer.rs",
            'use core::{arch as renamed_arch}; renamed_arch::asm!("mov cr3, rax");',
        )
        self.assertTrue(
            any("aliases and wildcard imports involving core::arch" in error for error in grouped_alias_errors),
            grouped_alias_errors,
        )

    def test_module_alias_and_root_shadowing_are_denied(self):
        joined = "\n".join(
            source_policy_errors(
                "kernel/src/new_writer.rs",
                "use core::arch as arch; mod core {}",
            )
        )
        self.assertIn("core::arch as a module alias", joined)
        self.assertIn("shadow a trusted macro root", joined)


    def test_directives_are_checked_after_every_template_separator(self):
        templates = (
            '"nop\\n.byte 0x0f, 0x22, 0xd8"',
            '"nop; .byte 0x0f, 0x22, 0xd8"',
            '"nop\\t.byte 0x0f, 0x22, 0xd8"',
            '"nop .byte 0x0f, 0x22, 0xd8"',
            '"nop\\r\\n.byte 0x0f, 0x22, 0xd8"',
            """r#"nop
.byte 0x0f, 0x22, 0xd8"#""",
        )
        for template in templates:
            with self.subTest(template=template):
                errors = _assembler_directive_errors(
                    "kernel/src/main.rs",
                    f"global_asm!({template});",
                )
                self.assertTrue(any(".byte" in error for error in errors), errors)

    def test_indirect_control_transfers_are_denied(self):
        templates = (
            'asm!("nop\\njmp *%rax");',
            'asm!("call *%r12");',
            'asm!("jmp\\t*%rax");',
            'asm!("call\\t%rax");',
            'asm!("jmp rax");',
            'asm!("call qword ptr [rax]");',
            'asm!("nop; jmp *symbol(%rip)");',
        )
        for source in templates:
            with self.subTest(source=source):
                errors = _assembler_directive_errors("kernel/src/address_space.rs", source)
                self.assertTrue(
                    any("indirect x86 control transfer is denied" in error for error in errors),
                    errors,
                )

    def test_direct_control_transfers_remain_allowed(self):
        source = 'asm!("jmp .Llocal\\ncall reviewed_function\\n.Llocal:");'
        self.assertEqual(
            _assembler_directive_errors("kernel/src/address_space.rs", source),
            [],
        )

    def test_resolved_workspace_dependency_graph_rejects_unscanned_path_crate(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests = {
                "kernel": root / "kernel" / "Cargo.toml",
                "core": root / "crates" / "oneos-core" / "Cargo.toml",
                "hidden": root / "crates" / "hidden-crate" / "Cargo.toml",
                "nested": root / "crates" / "nested-crate" / "Cargo.toml",
            }
            package_ids = {
                name: f"{name} 0.1.0 (path+file:///{name})"
                for name in manifests
            }
            metadata = {
                "packages": [
                    {
                        "id": package_ids[name],
                        "manifest_path": str(manifest),
                        "source": None,
                    }
                    for name, manifest in manifests.items()
                ],
                "resolve": {
                    "nodes": [
                        {"id": package_ids["kernel"], "deps": [{"pkg": package_ids["core"]}, {"pkg": package_ids["hidden"]}]},
                        {"id": package_ids["core"], "deps": []},
                        {"id": package_ids["hidden"], "deps": [{"pkg": package_ids["nested"]}]},
                        {"id": package_ids["nested"], "deps": []},
                    ]
                },
            }
            errors = _resolved_local_dependency_errors(root, metadata)
            joined = "\\n".join(errors)
            self.assertIn("hidden-crate", joined)
            self.assertIn("nested-crate", joined)

    def test_registry_nodes_are_traversed_for_unscanned_local_transitives(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel_id = "kernel 0.1.0 (path+file:///kernel)"
            core_id = "oneos-core 0.1.0 (path+file:///core)"
            registry_id = "third-party 1.2.3 (registry+https://example.invalid/index)"
            local_id = "hidden 0.1.0 (path+file:///hidden)"
            metadata = {
                "packages": [
                    {
                        "id": kernel_id,
                        "manifest_path": str(root / "kernel" / "Cargo.toml"),
                        "source": None,
                    },
                    {
                        "id": core_id,
                        "manifest_path": str(root / "crates" / "oneos-core" / "Cargo.toml"),
                        "source": None,
                    },
                    {
                        "id": registry_id,
                        "manifest_path": str(root / ".cargo" / "registry" / "third-party" / "Cargo.toml"),
                        "source": "registry+https://example.invalid/index",
                    },
                    {
                        "id": local_id,
                        "manifest_path": str(root / "crates" / "hidden" / "Cargo.toml"),
                        "source": None,
                    },
                ],
                "resolve": {
                    "nodes": [
                        {"id": kernel_id, "deps": [{"pkg": core_id}, {"pkg": registry_id}]},
                        {"id": core_id, "deps": []},
                        {"id": registry_id, "deps": [{"pkg": local_id}]},
                        {"id": local_id, "deps": []},
                    ]
                },
            }
            errors = _resolved_local_dependency_errors(root, metadata)
            self.assertTrue(any("crates/hidden/Cargo.toml" in error for error in errors), errors)

    def test_resolved_workspace_dependency_graph_allows_reviewed_core_path(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel_id = "kernel 0.1.0 (path+file:///kernel)"
            core_id = "oneos-core 0.1.0 (path+file:///core)"
            metadata = {
                "packages": [
                    {
                        "id": kernel_id,
                        "manifest_path": str(root / "kernel" / "Cargo.toml"),
                        "source": None,
                    },
                    {
                        "id": core_id,
                        "manifest_path": str(root / "crates" / "oneos-core" / "Cargo.toml"),
                        "source": None,
                    },
                ],
                "resolve": {
                    "nodes": [
                        {"id": kernel_id, "deps": [{"pkg": core_id}]},
                        {"id": core_id, "deps": []},
                    ]
                },
            }
            self.assertEqual(_resolved_local_dependency_errors(root, metadata), [])

    def test_target_named_rust_module_is_scanned_but_cargo_output_is_skipped(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "kernel"
            source_module = package / "src" / "target" / "mod.rs"
            generated_source = package / "target" / "debug" / "build" / "generated.rs"
            source_module.parent.mkdir(parents=True)
            generated_source.parent.mkdir(parents=True)
            source_module.write_text('asm!("mov cr3, rax");', encoding="utf-8")
            generated_source.write_text("fn generated() {}", encoding="utf-8")

            files, errors = _walk_package(
                root,
                "kernel",
                cargo_target_directory=package / "target",
            )
            found = {path.relative_to(root).as_posix() for path in files}

            self.assertEqual(errors, [])
            self.assertIn("kernel/src/target/mod.rs", found)
            self.assertNotIn("kernel/target/debug/build/generated.rs", found)

    def test_path_module_source_redirection_is_denied(self):
        sources = (
            '#[path = "../../outside.rs"] mod outside;',
            '# [ path = "../../outside.rs" ] mod outside;',
            '#[cfg_attr(feature = "external", path = "../../outside.rs")] mod outside;',
            '#[cfg_attr(feature = "outer", cfg_attr(feature = "inner", path = "../../outside.rs"))] mod outside;',
        )
        for source in sources:
            with self.subTest(source=source):
                errors = source_policy_errors("kernel/src/module.rs", source)
                self.assertTrue(
                    any("#[path] module source redirection is denied" in error for error in errors),
                    errors,
                )

    def test_qualified_assembly_and_macro_use_are_denied(self):
        joined = "\n".join(
            source_policy_errors(
                "kernel/src/new_writer.rs",
                'core::arch::asm!("mov cr3, rax"); #[macro_use] extern crate hidden;',
            )
        )
        self.assertIn("qualified assembly macro paths are denied", joined)
        self.assertIn("macro_use imports are denied", joined)

    def test_macro_metavariable_forwarding_is_denied(self):
        source = "macro_rules! invoke { ($m:ident) => { $m!() } }"
        joined = "\n".join(source_policy_errors("kernel/src/new_writer.rs", source))
        self.assertIn("macro_rules! count", joined)
        self.assertIn("macro forwarding through a metavariable is denied", joined)

    def test_concat_templates_and_encoded_strings_are_denied(self):
        source = 'asm!(concat!("mov ", "cr3, rax")); asm!("\\x6dov cr3, rax");'
        joined = "\n".join(source_policy_errors("kernel/src/new_writer.rs", source))
        self.assertIn("concat! is denied", joined)
        self.assertIn("hexadecimal/Unicode escapes in assembly templates are denied", joined)

    def test_assembly_template_macro_expansions_are_denied(self):
        cases = (
            'asm!(concat!("mov cr3, ", "rax"));',
            'asm!(include_str!("hidden-assembly.txt"));',
            'asm!("nop", custom_template!());',
            'asm!("nop", options!());',
            'global_asm!(custom_template!());',
        )
        for source in cases:
            with self.subTest(source=source):
                errors = _assembler_directive_errors(
                    "kernel/src/new_writer.rs", source
                )
                self.assertTrue(
                    any("macro expansion or computed template expressions are denied" in error for error in errors),
                    errors,
                )

    def test_multiple_direct_string_templates_and_raw_strings_remain_allowed(self):
        cases = (
            'asm!("mov cr3, {}", "nop", in(reg) root_physical);',
            'asm!(r#"mov cr3, {}"#, in(reg) root_physical);',
            'global_asm!(".global reviewed_symbol", r#".Lagain:"# ,);',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(
                    _assembler_directive_errors("kernel/src/new_writer.rs", source),
                    [],
                )

    def test_comment_separated_macro_rules_and_concat_are_still_detected(self):
        macro_rules_source = "macro_rules/* comment */! { ($value:expr) => { $value }; }"
        macro_rules_errors = source_policy_errors(
            "kernel/src/new_writer.rs", macro_rules_source
        )
        self.assertTrue(
            any("macro_rules! count is 1" in error for error in macro_rules_errors),
            macro_rules_errors,
        )

        concat_source = 'asm!(concat/* comment */!("mov ", "cr3, rax"));'
        concat_errors = source_policy_errors(
            "kernel/src/new_writer.rs", concat_source
        )
        self.assertTrue(
            any("concat! is denied" in error for error in concat_errors),
            concat_errors,
        )

    def test_non_assembly_rust_string_escapes_are_allowed(self):
        source = 'let elf_magic = b"\\x7fELF";'
        self.assertEqual(
            source_policy_errors("crates/oneos-core/src/elf64.rs", source),
            [],
        )

    def test_relocation_directive_is_rejected(self):
        errors = _assembler_directive_errors(
            "kernel/src/main.rs",
            'global_asm!(".reloc . - 3, R_X86_64_8, 0x0f");',
        )
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(".reloc", errors[0])

    def test_only_non_emitting_global_exports_and_local_labels_are_allowed(self):
        errors = _assembler_directive_errors(
            "kernel/src/main.rs",
            'global_asm!(".global reviewed_symbol", ".Lagain:", "nop");',
        )
        self.assertEqual(errors, [])

    def test_forwards_only_fails_for_actual_metavariable_invocation(self):
        source = "macro_rules! wrap { ($path:path) => { $($path)::+!() } }"
        joined = "\n".join(source_policy_errors("kernel/src/new_writer.rs", source))
        self.assertIn("macro forwarding through a metavariable is denied", joined)


if __name__ == "__main__":
    unittest.main()
