"""Regression tests for the explicit CR3 source policy."""

import unittest

from check_cr3_source_policy import (
    EXPECTED_ASM_COUNTS,
    _assembler_directive_errors,
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
        joined = "\n".join(
            source_policy_errors(
                "kernel/src/new_writer.rs",
                'asm!(concat!("mov ", "cr3, rax")); let hidden = "\\\\x2e";',
            )
        )
        self.assertIn("concat! is denied", joined)
        self.assertIn("hexadecimal/Unicode string escapes are denied", joined)

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
