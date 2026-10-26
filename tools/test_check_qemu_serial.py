"""Unit tests for the QEMU serial-log validator."""

import unittest

from check_qemu_serial import validate_serial_output


ENTRY_STACKS_READY = "CPU privilege-entry and emergency stacks configured"
START = "ONE OS kernel booted"
COMPLETE = "ONE OS BOOTSTRAP COMPLETE"
ALLOCATOR_READY = "ONE OS FRAME ALLOCATOR READY"
ALLOCATOR_FAILED = "ONE OS FRAME ALLOCATOR FAILED"
PAGING_READY = "ONE OS PAGE TABLE INSPECTION READY"
PAGING_FAILED = "ONE OS PAGING INSPECTION FAILED"
MUTATION_READY = "ONE OS VM MAPPING SMOKE TEST READY"
DEMOTION_READY = "ONE OS LARGE PAGE DEMOTION SMOKE TEST READY"
DEMOTION_SKIPPED = "ONE OS LARGE PAGE DEMOTION SMOKE TEST SKIPPED (DIRECT MAP ALREADY 4K)"
MUTATION_FAILED = "ONE OS PAGING MUTATION FAILED"
ADDRESS_SPACE_READY = "ONE OS ADDRESS SPACE ROOT INITIALIZATION READY"
ADDRESS_SPACE_FAILED = "ONE OS ADDRESS SPACE ROOT INITIALIZATION FAILED"
ACTIVATION_READY = "ONE OS KERNEL ADDRESS SPACE ACTIVATED"
SWITCH_READY = "ONE OS ADDRESS SPACE SWITCH PASS"
SWITCH_FAILED = "ONE OS ADDRESS SPACE SWITCH FAILED"
USER_FRAME_TEST_LOG = (
    "ONE OS USER FRAME ZERO TEST RECURSIVE INDEX: 0x00000000000001fe\n"
    "ONE OS USER FRAME ZERO TEST DIRTY: 0x0000000000102000\n"
    "ONE OS USER FRAME ZERO TEST VERIFIED: 0x0000000000102000\n"
    "ONE OS USER FRAME ZERO TEST PASS\n"
)
ACTIVATION_FAILED = "ONE OS KERNEL ADDRESS SPACE ACTIVATION FAILED"
PANIC = "ONE OS KERNEL PANIC"
EXCEPTION = "ONE OS EXCEPTION"


class ValidateSerialOutputTests(unittest.TestCase):
    def test_healthy_boot_marker_and_expected_timeout_pass(self):
        valid, _ = validate_serial_output(f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n", 124)
        self.assertTrue(valid)

    def test_missing_large_page_demotion_smoke_marker_fails(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n"
            f"{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("large-page demotion smoke outcome", reason.lower())

    def test_large_page_demotion_skip_marker_is_explicitly_accepted(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{DEMOTION_SKIPPED}\n{ADDRESS_SPACE_READY}\n"
            f"{ACTIVATION_READY}\n{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, _ = validate_serial_output(log, 124)
        self.assertTrue(valid)

    def test_duplicate_large_page_demotion_smoke_marker_fails(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{DEMOTION_READY}\n{DEMOTION_READY}\n"
            f"{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n"
            f"{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("exactly one large-page demotion smoke marker", reason.lower())

    def test_missing_runtime_address_space_switch_marker_fails(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n"
            f"{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("runtime address-space switch success marker", reason.lower())

    def test_duplicate_runtime_address_space_switch_marker_fails(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n"
            f"{SWITCH_READY}\n{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("exactly one exact runtime address-space switch", reason.lower())

    def test_runtime_address_space_switch_failure_marker_fails(self):
        log = (
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n"
            f"{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n"
            f"{SWITCH_READY}\n{SWITCH_FAILED}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("runtime address-space switch failure marker", reason.lower())

    def test_missing_post_activation_user_frame_zeroing_fails(self):
        log = f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{COMPLETE}\n"
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("user frame zero test recursive index", reason.lower())

    def test_post_activation_recursive_index_must_be_upper_half(self):
        log = f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n"
        log = log.replace(
            "ONE OS USER FRAME ZERO TEST RECURSIVE INDEX: 0x00000000000001fe",
            "ONE OS USER FRAME ZERO TEST RECURSIVE INDEX: 0x0000000000000008",
        )
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("upper-half recursive index", reason)

    def test_post_activation_user_frame_test_must_follow_cr3_switch(self):
        log = f"{ENTRY_STACKS_READY}\n{START}\n{USER_FRAME_TEST_LOG}{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{COMPLETE}\n"
        valid, reason = validate_serial_output(log, 124)
        self.assertFalse(valid)
        self.assertIn("follow CR3 activation", reason)

    def test_invalid_memory_map_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\nONE OS MEMORY MAP INVALID\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("memory map", reason.lower())

    def test_panic_after_completion_marker_fails(self):
        valid, reason = validate_serial_output(f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n{PANIC}\n", 124)
        self.assertFalse(valid)
        self.assertIn("panic", reason.lower())

    def test_exception_after_completion_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n{EXCEPTION}\nException: invalid opcode\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("exception marker", reason.lower())

    def test_missing_completion_marker_fails(self):
        valid, reason = validate_serial_output(f"{ENTRY_STACKS_READY}\n{START}\n", 124)
        self.assertFalse(valid)
        self.assertIn("completion marker", reason.lower())

    def test_missing_startup_marker_fails(self):
        valid, reason = validate_serial_output(f"{COMPLETE}\n", 124)
        self.assertFalse(valid)
        self.assertIn("startup marker", reason.lower())

    def test_completion_before_startup_fails(self):
        valid, reason = validate_serial_output(f"{COMPLETE}\n{ENTRY_STACKS_READY}\n{START}\n", 124)
        self.assertFalse(valid)
        self.assertIn("before startup", reason.lower())


    def test_missing_entry_stack_marker_fails(self):
        valid, reason = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{COMPLETE}\n", 124)
        self.assertFalse(valid)
        self.assertIn("privilege-entry stack marker missing", reason.lower())

    def test_missing_allocator_ready_marker_fails(self):
        valid, reason = validate_serial_output(f"{ENTRY_STACKS_READY}\n{START}\n{COMPLETE}\n", 124)
        self.assertFalse(valid)
        self.assertIn("allocator ready marker", reason.lower())

    def test_allocator_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("allocator failure marker", reason.lower())

    def test_clean_exit_is_not_accepted_as_expected_halt(self):
        valid, reason = validate_serial_output(f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{USER_FRAME_TEST_LOG}{COMPLETE}\n", 0)
        self.assertFalse(valid)
        self.assertIn("expected 124", reason.lower())

    def test_missing_page_table_inspection_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection marker", reason.lower())

    def test_page_table_inspection_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_FAILED}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection failure marker", reason.lower())

    def test_missing_active_page_table_mutation_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("active page-table mutation marker missing", reason.lower())

    def test_page_table_mutation_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{MUTATION_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table mutation failure marker", reason.lower())

    def test_missing_address_space_root_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("address-space root initialization marker missing", reason.lower())

    def test_missing_kernel_address_space_activation_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("kernel address-space activation marker missing", reason.lower())

    def test_kernel_address_space_activation_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ACTIVATION_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("activation failure marker", reason.lower())

    def test_address_space_root_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{ENTRY_STACKS_READY}\n{START}\n{ADDRESS_SPACE_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{DEMOTION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{SWITCH_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("address-space root initialization failure marker", reason.lower())

if __name__ == "__main__":
    unittest.main()
