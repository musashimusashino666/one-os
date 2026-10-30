"""Tests for final linked ELF CR3-write inventory validation."""

import unittest

from check_cr3_elf import _expected_function, _is_cr3_write, validate_disassembly


def normal_linked_disassembly() -> str:
    return """0000000000100000 <one_os_kernel::address_space::activate_supervisor_kernel_root>:
  100000: 0f 22 d8              mov    %rax,%cr3
0000000000100100 <one_os_kernel::address_space::switch_address_space>:
  100100: 0f 22 d9              mov    %rcx,%cr3
0000000000100200 <one_os_kernel::address_space::switch_address_space_flush_local_tlb>:
  100200: 0f 22 da              mov    %rdx,%cr3
"""


class Cr3ElfValidationTests(unittest.TestCase):
    def test_accepts_exactly_one_write_in_each_reviewed_function(self):
        valid, message = validate_disassembly(normal_linked_disassembly())
        self.assertTrue(valid, message)
        self.assertIn("exactly 3 CR3 writes", message)

    def test_extra_write_in_unreviewed_symbol_fails(self):
        disassembly = normal_linked_disassembly() + """0000000000100300 <hidden_writer>:
  100300: 0f 22 d8              mov    %rax,%cr3
"""
        valid, message = validate_disassembly(disassembly)
        self.assertFalse(valid)
        self.assertIn("expected exactly 3 CR3 writes", message)
        self.assertIn("unreviewed symbol 'hidden_writer'", message)

    def test_multiple_writes_inside_a_reviewed_function_fail(self):
        disassembly = normal_linked_disassembly().replace(
            "  100100: 0f 22 d9              mov    %rcx,%cr3",
            "  100100: 0f 22 d9              mov    %rcx,%cr3\n"
            "  100104: 0f 22 d8              mov    %rax,%cr3",
        )
        valid, message = validate_disassembly(disassembly)
        self.assertFalse(valid)
        self.assertIn("expected exactly 3 CR3 writes", message)
        self.assertIn(
            "expected exactly one linked CR3 write in switch_address_space, found 2",
            message,
        )

    def test_cr3_reads_are_not_mistaken_for_writes(self):
        disassembly = normal_linked_disassembly().replace(
            "  100100: 0f 22 d9              mov    %rcx,%cr3",
            "  1000fc: 0f 20 d8              mov    %cr3,%rax\n"
            "  100100: 0f 22 d9              mov    %rcx,%cr3",
        )
        valid, message = validate_disassembly(disassembly)
        self.assertTrue(valid, message)

    def test_recognizes_att_and_intel_destination_forms(self):
        self.assertTrue(_is_cr3_write("mov %rax,%cr3"))
        self.assertTrue(_is_cr3_write("mov cr3, rax"))
        self.assertFalse(_is_cr3_write("mov %cr3,%rax"))

    def test_symbol_role_requires_full_demangled_match(self):
        self.assertEqual(
            _expected_function("one_os_kernel::address_space::switch_address_space"),
            "switch_address_space",
        )
        for symbol in (
            "one_os_kernel::address_space::switch_address_space_extra",
            "other_crate::address_space::switch_address_space",
            "one_os_kernel::address_space::switch_address_space::inner",
        ):
            with self.subTest(symbol=symbol):
                self.assertIsNone(_expected_function(symbol))

    def test_suffix_spoof_cannot_claim_a_reviewed_role(self):
        disassembly = normal_linked_disassembly() + """0000000000100300 <one_os_kernel::address_space::switch_address_space_unreviewed>:
  100300: 0f 22 d8              mov    %rax,%cr3
"""
        valid, message = validate_disassembly(disassembly)
        self.assertFalse(valid)
        self.assertIn("unreviewed symbol", message)
        self.assertIn("switch_address_space_unreviewed", message)

    def test_missing_or_unowned_writes_fail(self):
        valid, message = validate_disassembly("no function symbols here\n")
        self.assertFalse(valid)
        self.assertIn("expected exactly 3 CR3 writes", message)


if __name__ == "__main__":
    unittest.main()
