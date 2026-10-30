"""Regression tests for optimized CR3/PGE assembly validation."""

import unittest
from pathlib import Path

from check_cr3_assembly import (
    _instruction,
    activation_function_bodies,
    validate_cr3_asm_memory_order,
    validate_cr3_writer_contract,
    validate_cr4_asm_pge_order,
    validate_function_body,
)


SYMBOL = "_ZN12one_os_kernel13address_space30activate_supervisor_kernel_root17h0123456789abcdefE"


def assembly_with(body: str, symbol: str = SYMBOL) -> str:
    return f""".section .text.{symbol},"ax",@progbits
.type {symbol},@function
{symbol}:
{body}
.Lfunc_end0:
.size {symbol}, .Lfunc_end0-{symbol}
"""


class ActivationAssemblyTests(unittest.TestCase):
    def test_parses_operandless_control_flow_and_clobber_instructions(self):
        self.assertEqual(_instruction("retq"), ("retq", []))
        self.assertEqual(_instruction("cpuid"), ("cpuid", []))
        self.assertEqual(_instruction("rdmsr"), ("rdmsr", []))

    def test_finds_activation_function_in_optimized_assembly(self):
        source = assembly_with(
            "    movq %cr4, %rbx\n"
            "    movq %rbx, %rax\n"
            "    andq $-131201, %rax\n"
            "    movq %rax, %r11\n"
            "    movq %r11, %cr4\n"
            "    movq %r12, %cr3\n"
            "    movq %rbx, %r10\n"
            "    movq %r10, %cr4\n"
            "    retq\n"
        )
        functions = activation_function_bodies(source)
        self.assertEqual(len(functions), 1)
        valid, message = validate_function_body(functions[0][1])
        self.assertTrue(valid, message)

    def test_finds_runtime_switch_function_in_optimized_assembly(self):
        symbol = (
            "_ZN12one_os_kernel13address_space18switch_address_space17h0123456789abcdefE"
        )
        source = assembly_with(
            "    movq %cr4, %rbx\n"
            "    movq %rbx, %rax\n"
            "    andq $-131201, %rax\n"
            "    movq %rax, %r11\n"
            "    movq %r11, %cr4\n"
            "    movq %r12, %cr3\n"
            "    movq %rbx, %r10\n"
            "    movq %r10, %cr4\n"
            "    retq\n",
            symbol=symbol,
        )
        functions = activation_function_bodies(source)
        self.assertEqual(len(functions), 1)
        self.assertIn("switch_address_space", functions[0][0])
        valid, message = validate_function_body(functions[0][1])
        self.assertTrue(valid, message)


    def test_ignores_epilogue_clobber_on_alternate_control_flow_path(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %r13",
                "jne .Lfailure",
                "jmp .Lswitch",
                ".Lfailure:",
                "popq %r13",
                "retq",
                ".Lswitch:",
                "movq %r13, %rax",
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr3",
                "movq %r13, %cr4",
                "retq",
            ]
        )
        self.assertTrue(valid, message)

    def test_accepts_branching_paths_when_all_cr3_writes_are_safe(self):
        # Either branch may be taken, but both converge on the mandatory
        # PGE-clear -> CR3-write -> original-CR4-restore sequence.
        valid, message = validate_function_body(
            [
                "movq %cr4, %r13",
                "testb %r13b, %r13b",
                "jne .Lprepare",
                "jmp .Lswitch",
                ".Lprepare:",
                "movq %r13, %rax",
                ".Lswitch:",
                "movq %r13, %rax",
                "andq $-135297, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr3",
                "movq %r13, %cr4",
                "retq",
            ]
        )
        self.assertTrue(valid, message)

    def test_tracks_cr4_value_saved_around_cpuid_with_xchg(self):
        # LLVM may preserve RBX across CPUID by exchanging it with RDI.
        # The saved CR4 provenance must survive this equivalent register swap.
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rdi",
                "cpuid",
                "xchgq %rbx, %rdi",
                "movq %rbx, %rax",
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
                "retq",
            ]
        )
        self.assertTrue(valid, message)

    def test_rejects_partial_width_xchg_for_cr4_provenance(self):
        # A partial-width XCHG cannot preserve the original 64-bit CR4 value.
        # Without width-aware tracking, these sequences can appear valid even
        # though RBX/RDI no longer contain the original full-width value.
        partial_exchanges = (
            "xchgl %ebx, %edi",
            "xchgw %bx, %di",
            "xchgb %bl, %dil",
        )
        for exchange in partial_exchanges:
            with self.subTest(exchange=exchange):
                valid, message = validate_function_body(
                    [
                        "movq %cr4, %rbx",
                        "movq %rbx, %rdi",
                        "cpuid",
                        exchange,
                        "movq %rbx, %rax",
                        "andq $-129, %rax",
                        "movq %rax, %cr4",
                        "movq %r12, %cr3",
                        "movq %rbx, %cr4",
                        "retq",
                    ]
                )
                self.assertFalse(valid, f"{exchange}: {message}")

    def test_rejects_cr3_write_before_pge_disable(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %r13",
                "movq %rbx, %cr3",  # Unsafe: no PGE-clear CR4 write dominates this CR3 write.
                "movq %r13, %rax",
                "andq $-131201, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr3",
                "movq %r13, %cr4",
                "retq",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("reachable CR3 write is not dominated", message)

    def test_rejects_function_with_one_safe_and_one_unsafe_cr3_path(self):
        # The safe branch must not hide the unsafe branch. The old checker
        # returned success as soon as it found any completed safe path.
        valid, message = validate_function_body(
            [
                "movq %cr4, %r13",
                "testb %r13b, %r13b",
                "jne .Lsafe",
                "movq %rbx, %cr3",
                "jmp .Ldone",
                ".Lsafe:",
                "movq %r13, %rax",
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr3",
                "movq %r13, %cr4",
                ".Ldone:",
                "retq",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("reachable CR3 write is not dominated", message)

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
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $-131201, %rax",
                "movq %rax, %cr4",
                "movq %rbx, %cr4",
                "movq %r12, %cr3",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("reachable CR3 write is not dominated", message)

    def test_rejects_mask_that_keeps_pge_bit_set(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $-1, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no instruction clearing CR4.PGE bit 7", message)

    def test_accepts_mask_that_only_clears_pge_la57_and_pcide(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $-135297, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertTrue(valid, message)

    def test_rejects_zero_mask_that_destroys_all_cr4_bits(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $0, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no instruction clearing CR4.PGE bit 7", message)

    def test_rejects_mask_that_clears_unrelated_cr4_bit(self):
        # -385 clears PGE bit 7 and unrelated CR4 bit 8.
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $-385, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no instruction clearing CR4.PGE bit 7", message)

    def test_rejects_32_bit_and_that_zero_extends_cr4_value(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %eax",
                "andl $-129, %eax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no instruction clearing CR4.PGE bit 7", message)

    def test_rejects_btr_mask_that_targets_an_unrelated_bit(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "btrq $8, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("no instruction clearing CR4.PGE bit 7", message)

    def test_rejects_missing_cr3_write(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
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
                "mov rax, rbx",
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
                "movq %r10, %cr4",
                "movq %r12, %cr3",
                "movq %rbx, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("PGE-cleared value did not reach a CR4 write", message)

    def test_rejects_restore_from_masked_value(self):
        valid, message = validate_function_body(
            [
                "movq %cr4, %rbx",
                "movq %rbx, %rax",
                "andq $-129, %rax",
                "movq %rax, %cr4",
                "movq %r12, %cr3",
                "movq %rax, %cr4",
            ]
        )
        self.assertFalse(valid)
        self.assertIn("original pre-switch CR4 value was not restored", message)

    def test_source_restores_original_cr4_value(self):
        source = """
            let cr4_without_pge = cr4 & !CR4_PGE;
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4,
                 options(nomem, nostack, preserves_flags));
        """
        valid, message = validate_cr4_asm_pge_order(source)
        self.assertTrue(valid, message)

    def test_source_rejects_restoring_masked_cr4_value(self):
        source = """
            let cr4_without_pge = cr4 & !CR4_PGE;
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
        """
        valid, message = validate_cr4_asm_pge_order(source)
        self.assertFalse(valid)
        self.assertIn("restore the original cr4 value", message)

    def test_local_tlb_flush_may_reload_only_the_checked_active_cr3(self):
        source = """
            pub(super) fn switch_address_space_flush_local_tlb(
                expected_root_physical: u64,
            ) {
                validate_kernel_root_activation_state(cr0, cr4, efer, rflags)?;
                let cr3: u64;
                asm!(
                    "mov {}, cr3",
                    out(reg) cr3,
                    options(nomem, nostack, preserves_flags)
                );
                if cr3 & PHYSICAL_ADDRESS_MASK != expected_root_physical {
                    return;
                }
                asm!(
                    "mov cr3, {}",
                    in(reg) cr3,
                    options(nostack, preserves_flags)
                );
            }

            /// Performs the validated hardware CR3 transition.
        """
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertTrue(valid, message)

    def test_local_tlb_flush_rejects_unchecked_active_cr3_reload(self):
        source = """
            pub(super) fn switch_address_space_flush_local_tlb(
                expected_root_physical: u64,
            ) {
                validate_kernel_root_activation_state(cr0, cr4, efer, rflags)?;
                let cr3: u64;
                asm!(
                    "mov {}, cr3",
                    out(reg) cr3,
                    options(nomem, nostack, preserves_flags)
                );
                // Missing the check that the physical CR3 root matches
                // expected_root_physical.
                asm!(
                    "mov cr3, {}",
                    in(reg) cr3,
                    options(nostack, preserves_flags)
                );
            }

            /// Performs the validated hardware CR3 transition.
        """
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("the template operand must bind directly to in(reg) root_physical, or to the checked active CR3", message)

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

    def test_cr3_inline_asm_checks_every_switch_block(self):
        source = '''
            asm!(
                "mov cr3, {}",
                in(reg) root_physical,
                options(nostack, preserves_flags)
            );
            asm!(
                "mov cr3, {}",
                in(reg) root_physical,
                options(nomem, nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("block 2 must not specify nomem", message)

    def test_cr3_named_operand_template_is_still_checked(self):
        source = '''
            asm!(
                "mov cr3, {root}",
                root = in(reg) root_physical,
                options(nostack, preserves_flags)
            );
            asm!(
                "mov cr3, {root}",
                root = in(reg) root_physical,
                options(nomem, nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("block 2 must not specify nomem", message)

    def test_cr3_named_placeholder_must_bind_validated_root_physical(self):
        source = '''
            asm!(
                "mov cr3, {target}",
                target = in(reg) unvalidated_root,
                validated = in(reg) root_physical,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("must bind directly to in(reg) root_physical", message)

    def test_cr3_positional_placeholder_must_bind_validated_root_physical(self):
        source = '''
            asm!(
                "mov cr3, {}",
                in(reg) unvalidated_root,
                in(reg) root_physical,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("must bind directly to in(reg) root_physical", message)

    def test_cr3_anonymous_placeholder_uses_template_occurrence_order(self):
        source = '''
            asm!(
                "mov rax, {}",
                "mov cr3, {}",
                in(reg) root_physical,
                in(reg) unvalidated_root,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertFalse(valid)
        self.assertIn("must bind directly to in(reg) root_physical", message)

    def test_cr3_later_anonymous_placeholder_accepts_matching_root_input(self):
        source = '''
            asm!(
                "mov rax, {}",
                "mov cr3, {}",
                in(reg) unvalidated_root,
                in(reg) root_physical,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertTrue(valid, message)

    def test_cr3_named_placeholder_maps_by_name_with_other_inputs_present(self):
        source = '''
            asm!(
                "mov cr3, {root}",
                root = in(reg) root_physical,
                unrelated = in(reg) unvalidated_root,
                options(nostack, preserves_flags)
            );
        '''
        valid, message = validate_cr3_asm_memory_order(source)
        self.assertTrue(valid, message)

    def test_cr4_named_operand_template_is_supported(self):
        source = """
            let cr4_without_pge = cr4 & !CR4_PGE;
            asm!("mov cr4, {value}", value = in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {value}", value = in(reg) cr4,
                 options(nomem, nostack, preserves_flags));
        """
        valid, message = validate_cr4_asm_pge_order(source)
        self.assertTrue(valid, message)

    def test_cr4_source_validator_checks_every_switch_sequence(self):
        source = """
            let cr4_without_pge = cr4 & !CR4_PGE;
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) cr4_without_pge,
                 options(nomem, nostack, preserves_flags));
        """
        valid, message = validate_cr4_asm_pge_order(source)
        self.assertFalse(valid)
        self.assertIn("sequence 2 must restore the original cr4 value", message)





class Cr3WriterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.source_path = root / "kernel/src/address_space.rs"
        cls.source = cls.source_path.read_text(encoding="utf-8")

    def test_current_writer_contract_passes(self):
        valid, message = validate_cr3_writer_contract(self.source)
        self.assertTrue(valid, message)

    def test_extra_writer_outside_reviewed_functions_fails(self):
        extra_writer = """
fn unreviewed_cr3_writer(root_physical: u64) {
    unsafe {
        asm!("mov cr3, {}", in(reg) root_physical, options(nostack, preserves_flags));
    }
}
"""
        valid, message = validate_cr3_writer_contract(self.source + extra_writer)
        self.assertFalse(valid)
        self.assertIn("expected exactly 3 CR3-writing asm blocks", message)
        self.assertIn("unreviewed function", message)

    def test_renamed_writer_function_fails_closed(self):
        changed = self.source.replace(
            "fn switch_address_space(",
            "fn switch_address_space_renamed(",
            1,
        )
        valid, message = validate_cr3_writer_contract(changed)
        self.assertFalse(valid)
        self.assertIn("switch_address_space", message)

    def test_removing_root_registration_validation_fails(self):
        changed = self.source.replace(
            "validate_registered_root_for_activation(root_physical)",
            "validate_registered_root_for_activation(unreviewed_root)",
            1,
        )
        self.assertNotEqual(changed, self.source)
        valid, message = validate_cr3_writer_contract(changed)
        self.assertFalse(valid)
        self.assertIn("root-validation step", message)


if __name__ == "__main__":
    unittest.main()
