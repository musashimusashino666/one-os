"""Unit tests for the exact QEMU VM-protection log contract."""

import unittest

from check_qemu_vm_protection import validate_vm_protection_output


def valid_log(case: str) -> str:
    target = "0xffff820000000000"
    if case == "supervisor-write-protection":
        expected_rip = "0xffffffff80201234"
        error_code = "0x0000000000000003"
        marker = "ONE OS VM TEST PASS: supervisor-write-protection"
    else:
        expected_rip = target
        error_code = "0x0000000000000011"
        marker = "ONE OS VM TEST PASS: nx-instruction-fetch"
    recovery = (
        "ONE OS VM TEST NX FAULT MATCHED\n"
        "ONE OS VM TEST NX RECOVERY VERIFIED\n"
        if case == "nx-instruction-fetch"
        else ""
    )
    return (
        f"ONE OS VM TEST: {case}\n"
        f"ONE OS VM TEST TARGET: {target}\n"
        f"ONE OS VM TEST EXPECTED RIP: {expected_rip}\n"
        "ONE OS VM TEST EXPECTED PAGE FAULT\n"
        f"Instruction pointer: {expected_rip}\n"
        f"Error code: {error_code}\n"
        f"Fault address (CR2): {target}\n"
        f"{recovery}"
        f"{marker}\n"
    )


class ValidateVmProtectionOutputTests(unittest.TestCase):
    def test_supervisor_write_protection_passes_exact_terminal_fault(self):
        valid, message = validate_vm_protection_output(
            valid_log("supervisor-write-protection"), 33, "supervisor-write-protection"
        )
        self.assertTrue(valid, message)

    def test_nx_instruction_fetch_passes_with_rip_equal_to_target(self):
        valid, message = validate_vm_protection_output(
            valid_log("nx-instruction-fetch"), 33, "nx-instruction-fetch"
        )
        self.assertTrue(valid, message)

    def test_wrong_exit_status_fails(self):
        valid, message = validate_vm_protection_output(
            valid_log("nx-instruction-fetch"), 124, "nx-instruction-fetch"
        )
        self.assertFalse(valid)
        self.assertIn("expected 33", message)

    def test_any_extra_page_fault_error_code_bit_fails(self):
        log = valid_log("supervisor-write-protection").replace(
            "Error code: 0x0000000000000003",
            "Error code: 0x0000000000000023",
        )
        valid, message = validate_vm_protection_output(
            log, 33, "supervisor-write-protection"
        )
        self.assertFalse(valid)
        self.assertIn("full page-fault error code mismatch", message)

    def test_cr2_must_equal_the_target_address(self):
        log = valid_log("nx-instruction-fetch").replace(
            "Fault address (CR2): 0xffff820000000000",
            "Fault address (CR2): 0xffff820000001000",
        )
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("CR2 does not match", message)

    def test_saved_rip_must_match_exact_faulting_instruction(self):
        log = valid_log("supervisor-write-protection").replace(
            "Instruction pointer: 0xffffffff80201234",
            "Instruction pointer: 0xffffffff80201235",
        )
        valid, message = validate_vm_protection_output(
            log, 33, "supervisor-write-protection"
        )
        self.assertFalse(valid)
        self.assertIn("saved RIP", message)

    def test_duplicate_success_marker_fails(self):
        log = valid_log("nx-instruction-fetch")
        log += "ONE OS VM TEST PASS: nx-instruction-fetch\n"
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("exactly one success marker", message)

    def test_nx_requires_both_recovery_markers(self):
        log = valid_log("nx-instruction-fetch").replace(
            "ONE OS VM TEST NX RECOVERY VERIFIED\n", ""
        )
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("NX recovery marker", message)

    def test_nx_recovery_markers_must_precede_success_marker(self):
        log = valid_log("nx-instruction-fetch")
        log = log.replace(
            "ONE OS VM TEST NX RECOVERY VERIFIED\n",
            "ONE OS VM TEST PASS: nx-instruction-fetch\n"
            "ONE OS VM TEST NX RECOVERY VERIFIED\n",
        )
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("before the success marker", message)

    def test_normal_boot_completion_marker_fails(self):
        log = valid_log("nx-instruction-fetch") + "ONE OS BOOTSTRAP COMPLETE\n"
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("failure marker", message.lower())

    def test_nx_requires_target_address_as_saved_rip(self):
        log = valid_log("nx-instruction-fetch").replace(
            "ONE OS VM TEST EXPECTED RIP: 0xffff820000000000",
            "ONE OS VM TEST EXPECTED RIP: 0xffffffff80201234",
        ).replace(
            "Instruction pointer: 0xffff820000000000",
            "Instruction pointer: 0xffffffff80201234",
        )
        valid, message = validate_vm_protection_output(log, 33, "nx-instruction-fetch")
        self.assertFalse(valid)
        self.assertIn("saved rip", message.lower())


if __name__ == "__main__":
    unittest.main()
