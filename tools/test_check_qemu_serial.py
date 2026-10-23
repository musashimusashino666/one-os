"""Unit tests for the QEMU serial-log validator."""

import unittest

from check_qemu_serial import validate_serial_output


START = "ONE OS kernel booted"
COMPLETE = "ONE OS BOOTSTRAP COMPLETE"
ALLOCATOR_READY = "ONE OS FRAME ALLOCATOR READY"
ALLOCATOR_FAILED = "ONE OS FRAME ALLOCATOR FAILED"
PAGING_READY = "ONE OS PAGE TABLE INSPECTION READY"
PAGING_FAILED = "ONE OS PAGING INSPECTION FAILED"
PANIC = "ONE OS KERNEL PANIC"
EXCEPTION = "ONE OS EXCEPTION"


class ValidateSerialOutputTests(unittest.TestCase):
    def test_healthy_boot_marker_and_expected_timeout_pass(self):
        valid, _ = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 124)
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
        valid, reason = validate_serial_output(f"{START}\n{ALLOCATOR_READY}\n{PAGING_READY}\n{COMPLETE}\n", 0)
        self.assertFalse(valid)
        self.assertIn("expected 124", reason.lower())

    def test_missing_page_table_inspection_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\\n{ALLOCATOR_READY}\\n{COMPLETE}\\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection marker", reason.lower())

    def test_page_table_inspection_failure_marker_fails(self):
        valid, reason = validate_serial_output(
            f"{START}\\n{ALLOCATOR_READY}\\n{PAGING_FAILED}\\n{COMPLETE}\\n", 124
        )
        self.assertFalse(valid)
        self.assertIn("page-table inspection failure marker", reason.lower())

if __name__ == "__main__":
    unittest.main()
