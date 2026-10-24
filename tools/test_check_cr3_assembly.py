"""Regression tests for optimized CR3/PGE assembly validation."""

import unittest

from check_cr3_assembly import (
    activation_function_bodies,
    validate_cr3_asm_memory_order,
    validate_function_body,
)


SYMBOL = "_ZN12one_os_kernel13address_space30activate_supervisor_kernel_root17h0123456789abcdefE"


def assembly_with(body: str) -> str:
    return f""".section .text.{SYMBOL},"ax",@progbits
.type {SYMBOL},@function
{SYMBOL}:
{body}
.Lfunc_end0:
.size {SYMBOL}, .Lfunc_end0-{SYMBOL}
"""


class ActivationAssemblyTests(unittest.TestCase):
    def test_finds_activation_function_in_optimized_assembly(self):
        source = assembly_with(
            "    movq %cr4, %rbx\n"
            "    andq $-129, %rax\n"
            "    movq %rax, %cr4\n"
            "    movq %r12, %cr3\n"
            "    movq %rbx, %cr4\n"
            "    retq\n"
        )
        functions = activation_function_bodies(source)
        self.assertEqual(len(functions), 1)
        valid, message = validate_function_body(functions[0][1])
        self.assertTrue(valid, message)

    def test_rejects_missing_pge_clear(self):
        valid, message = validate_function_body(
            [
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("clearing CR4.PGE", message)

    def test_rejects_cr3_write_after_restore(self):
        valid, message = validate_function_body(
            [
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr4",
                "movq %r12, %cr3",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("ordered between", message)

    def test_rejects_missing_cr3_write(self):
        valid, message = validate_function_body(
            [
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no actual CR3 write", message)

    def test_accepts_intel_syntax(self):
        valid, message = validate_function_body(
            [
                "mov rbx, cr4",
                "and rax, -129",
                "mov cr4, rax",
                "mov cr3, r12",
                "mov cr4, rbx",
            ]
        )
        self.assertTrue(valid, message)


    def test_rejects_pge_mask_on_unrelated_register(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "andq $-129, %r10",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("not cleared in the register written to CR4", message)

    def test_rejects_restore_without_saved_cr4_source(self):
        valid, message = validate_function_body(
            [
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("pre-switch CR4 value", message)

    def test_cr3_inline_asm_must_retain_memory_ordering(self):
        source = '''
            asm!(
                "mov cr3, {}",
                in(reg) root_physical,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertTrue(valid, message)

    def test_cr3_inline_asm_rejects_nomem(self):
        source = '''
            asm!(
                "mov cr3, {}",
                in(reg) root_physical,
                options(nomem, nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("must not specify nomem", message)


if __name__ == "__main__":
    unittest.main()
