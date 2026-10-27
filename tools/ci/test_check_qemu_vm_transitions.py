"""Unit tests for strict QEMU mapping-transition validation."""

import unittest

from check_qemu_vm_transitions import validate_vm_transition_output


def valid_log() -> str:
    target = "0xffff820000000000"
    first_rip = "0xffffffff80201010"
    second_rip = "0xffffffff80202020"
    return (
        "ONE OS kernel booted\n"
        "ONE OS VM TABLE FRAME ALLOCATED: 0x0000000000100000\n"
        "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: 0x0000000000100000\n"
        "ONE OS VM TABLE FRAME ALLOCATED: 0x0000000000101000\n"
        "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: 0x0000000000101000\n"
        "ONE OS VM MAPPING SMOKE TEST READY\n"
        "ONE OS VM TEST: mapping-transitions\n"
        "ONE OS USER FRAME ZERO TEST DIRTY: 0x0000000000102000\n"
        "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000\n"
        "ONE OS USER FRAME ZERO TEST PASS\n"
        f"ONE OS VM TRANSITION TARGET: {target}\n"
        "ONE OS VM TRANSITION FIRST FRAME: 0x0000000000100000\n"
        "ONE OS VM TRANSITION SECOND FRAME: 0x0000000000101000\n"
        f"ONE OS VM TRANSITION FIRST EXPECTED RIP: {first_rip}\n"
        f"ONE OS VM TRANSITION SECOND EXPECTED RIP: {second_rip}\n"
        "ONE OS VM TRANSITION EXPECTED PAGE FAULT\n"
        f"Instruction pointer: {first_rip}\n"
        "Error code: 0x0000000000000000\n"
        f"Fault address (CR2): {target}\n"
        "ONE OS VM TRANSITION FAULT MATCHED: initial-unmapped\n"
        "ONE OS VM TRANSITION RECOVERY VERIFIED: initial-unmapped\n"
        "ONE OS VM TRANSITION FIRST MAPPING VERIFIED\n"
        "ONE OS VM TRANSITION EXPECTED PAGE FAULT\n"
        f"Instruction pointer: {second_rip}\n"
        "Error code: 0x0000000000000000\n"
        f"Fault address (CR2): {target}\n"
        "ONE OS VM TRANSITION FAULT MATCHED: after-unmap\n"
        "ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap\n"
        "ONE OS VM TRANSITION REMAP SECOND FRAME VERIFIED\n"
        "ONE OS VM TEST PASS: mapping-transitions\n"
    )


class ValidateVmTransitionOutputTests(unittest.TestCase):
    def test_valid_two_fault_transition_passes(self):
        valid, message = validate_vm_transition_output(valid_log(), 33)
        self.assertTrue(valid, message)

    def test_user_frame_zeroing_requires_same_nonzero_physical_frame(self):
        log = valid_log().replace(
            "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000",
            "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000103000",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("exact dirty physical frame", message)

    def test_user_frame_zeroing_marker_is_required(self):
        log = valid_log().replace(
            "ONE OS USER FRAME ZERO TEST PASS\n",
            "",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("kernel user-frame zeroing marker", message)

    def test_user_frame_success_marker_rejects_trailing_text(self):
        log = valid_log().replace(
            "ONE OS USER FRAME ZERO TEST PASS\n",
            "ONE OS USER FRAME ZERO TEST PASS unexpected\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("exact kernel user-frame zeroing marker", message)

    def test_user_frame_failure_marker_is_rejected(self):
        log = valid_log().replace(
            "ONE OS VM TEST: mapping-transitions\n",
            "ONE OS VM TEST: mapping-transitions\n"
            "ONE OS USER FRAME ZERO TEST FAILED\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("failure marker found", message.lower())

    def test_user_frame_dirty_marker_rejects_malformed_duplicate(self):
        log = valid_log().replace(
            "ONE OS USER FRAME ZERO TEST DIRTY: 0x0000000000102000\n",
            "ONE OS USER FRAME ZERO TEST DIRTY: malformed\n"
            "ONE OS USER FRAME ZERO TEST DIRTY: 0x0000000000102000\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("expected exactly one", message)

    def test_user_frame_zeroed_marker_rejects_malformed_line_with_valid_line(self):
        log = valid_log().replace(
            "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000\n",
            "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000\n"
            "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000 trailing-data\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("expected exactly one", message)

    def test_every_allocated_table_frame_requires_its_zero_verification(self):
        log = valid_log().replace(
            "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: 0x0000000000101000\n",
            "",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("do not match zero-verified frames", message)

    def test_zero_verification_must_match_the_allocated_frame_address(self):
        log = valid_log().replace(
            "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: 0x0000000000101000",
            "ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: 0x0000000000102000",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("do not match zero-verified frames", message)

    def test_duplicate_table_allocation_marker_fails(self):
        log = valid_log().replace(
            "ONE OS VM TABLE FRAME ALLOCATED: 0x0000000000101000\n",
            "ONE OS VM TABLE FRAME ALLOCATED: 0x0000000000100000\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("duplicate physical frame", message)

    def test_physical_frames_must_be_distinct(self):
        log = valid_log().replace(
            "ONE OS VM TRANSITION SECOND FRAME: 0x0000000000101000",
            "ONE OS VM TRANSITION SECOND FRAME: 0x0000000000100000",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("distinct physical frames", message)

    def test_missing_payload_verification_fails(self):
        log = valid_log().replace(
            "ONE OS VM TRANSITION REMAP SECOND FRAME VERIFIED\n", ""
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("mapping verification marker", message)

    def test_unexpected_exit_status_fails(self):
        valid, message = validate_vm_transition_output(valid_log(), 124)
        self.assertFalse(valid)
        self.assertIn("expected 33", message)

    def test_error_code_must_be_exact_zero(self):
        log = valid_log().replace(
            "Error code: 0x0000000000000000",
            "Error code: 0x0000000000000002",
            1,
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("full error_code", message)

    def test_both_cr2_values_must_match_the_same_target(self):
        log = valid_log().replace(
            "Fault address (CR2): 0xffff820000000000",
            "Fault address (CR2): 0xffff820000001000",
            1,
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("both CR2 values", message)

    def test_saved_rip_must_match_each_exact_faulting_load(self):
        log = valid_log().replace(
            "Instruction pointer: 0xffffffff80201010",
            "Instruction pointer: 0xffffffff80201011",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("saved RIP values", message)

    def test_missing_second_recovery_fails(self):
        log = valid_log().replace(
            "ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap\n", ""
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("transition marker", message)

    def test_wrong_recovery_order_fails(self):
        log = valid_log().replace(
            "ONE OS VM TRANSITION RECOVERY VERIFIED: initial-unmapped\n", ""
        ).replace(
            "ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap\n",
            "ONE OS VM TRANSITION RECOVERY VERIFIED: initial-unmapped\n"
            "ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap\n",
        )
        valid, message = validate_vm_transition_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("out of order", message)

    def test_timeout_panics_and_normal_boot_completion_fail(self):
        for marker in (
            "ONE OS KERNEL PANIC",
            "ONE OS VM TEST FAILED",
            "ONE OS EXCEPTION",
            "ONE OS BOOTSTRAP COMPLETE",
        ):
            with self.subTest(marker=marker):
                valid, message = validate_vm_transition_output(
                    valid_log() + marker + "\n", 33
                )
                self.assertFalse(valid)
                self.assertIn("failure marker", message.lower())

    def test_duplicate_success_marker_fails(self):
        valid, message = validate_vm_transition_output(
            valid_log() + "ONE OS VM TEST PASS: mapping-transitions\n", 33
        )
        self.assertFalse(valid)
        self.assertIn("exactly one success marker", message)


if __name__ == "__main__":
    unittest.main()
