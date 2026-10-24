"""Unit tests for the QEMU serial-log validator."""

import unittest

from check_qemu_serial import validate_serial_output


START = "ONE OS kernel booted"
COMPLETE = "ONE OS BOOTSTRAP COMPLETE"
ALLOCATOR_READY = "ONE OS FRAME ALLOCATOR READY"
ALLOCATOR_FAILED = "ONE OS FRAME ALLOCATOR FAILED"
PAGING_READY = "ONE OS PAGE TABLE INSPECTION READY"
PAGING_FAILED = "ONE OS PAGING INSPECTION FAILED"
MUTATION_READY = "ONE OS VM MAPPING SMOKE TEST READY"
MUTATION_FAILED = "ONE OS PAGING MUTATION FAILED"
ADDRESS_SPACE_READY = "ONE OS ADDRESS SPACE ROOT INITIALIZATION READY"
ADDRESS_SPACE_FAILED = "ONE OS ADDRESS SPACE ROOT INITIALIZATION FAILED"
ACTIVATION_READY = "ONE OS KERNEL ADDRESS SPACE ACTIVATED"
ACTIVATION_FAILED = "ONE OS KERNEL ADDRESS SPACE ACTIVATION FAILED"
PANIC = "ONE OS KERNEL PANIC"
EXCEPTION = "ONE OS EXCEPTION"


class ValidateSerialOutputTests(unittest.TestCase):
    def test_healthy_boot_marker_and_expected_timeout_pass(self):
        valid, _ = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{COMPLETE}\n", 124)
        self.assertTrue(valid)

    def test_invalid_memory_map_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\nONE OS MEMORY MAP INVALID\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("memory map", reason.lower())

    def test_panic_after_completion_marker_fails(self):
        valid, reason = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n{PANIC}\n", 124)
        self.assertFalse(valid)
        self.assertIn("panic", reason.lower())

    def test_exception_after_completion_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n{EXCEPTION}\nException: invalid opcode\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("exception marker", reason.lower())

    def test_missing_completion_marker_fails(self):
        valid, reason = validate_serial_output(f"{START}\n", 124)
        self.assertFalse(valid)
        self.assertIn("completion marker", reason.lower())

    def test_missing_startup_marker_fails(self):
        valid, reason = validate_serial_output(f"{COMPLETE}\n", 124)
        self.assertFalse(valid)
        self.assertIn("startup marker", reason.lower())

    def test_completion_before_startup_fails(self):
        valid, reason = validate_serial_output(f"{COMPLETE}\n{START}\n", 124)
        self.assertFalse(valid)
        self.assertIn("before startup", reason.lower())


    def test_missing_allocator_ready_marker_fails(self):
        valid, reason = validate_serial_output(f"{START}\n{COMPLETE}\n", 124)
        self.assertFalse(valid)
        self.assertIn("allocator ready marker", reason.lower())

    def test_allocator_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("allocator failure marker", reason.lower())

    def test_clean_exit_is_not_accepted_as_expected_halt(self):
        valid, reason = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{COMPLETE}\n", 0)
        self.assertFalse(valid)
        self.assertIn("expected 124", reason.lower())

    def test_missing_page_table_inspection_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection marker", reason.lower())

    def test_page_table_inspection_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{PAGING_FAILED}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection failure marker", reason.lower())

    def test_missing_active_page_table_mutation_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("active page-table mutation marker missing", reason.lower())

    def test_page_table_mutation_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{MUTATION_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table mutation failure marker", reason.lower())

    def test_missing_address_space_root_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("address-space root initialization marker missing", reason.lower())

    def test_missing_kernel_address_space_activation_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\\n{ALLOCATOR_READY}\\n{PAGING_READY}\\n{MUTATION_READY}\\n{ADDRESS_SPACE_READY}\\n{COMPLETE}\\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("kernel address-space activation marker missing", reason.lower())

    def test_kernel_address_space_activation_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\\n{ACTIVATION_FAILED}\\n{ALLOCATOR_READY}\\n{PAGING_READY}\\n{MUTATION_READY}\\n{ADDRESS_SPACE_READY}\\n{ACTIVATION_READY}\\n{COMPLETE}\\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("activation failure marker", reason.lower())

    def test_address_space_root_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\n{ADDRESS_SPACE_FAILED}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{MUTATION_READY}\n{ADDRESS_SPACE_READY}\n{ACTIVATION_READY}\n{COMPLETE}\n",
            124,
        )
        self.assertFalse(valid)
        self.assertIn("address-space root initialization failure marker", reason.lower())

if __name__ == "__main__":
    unittest.main()
