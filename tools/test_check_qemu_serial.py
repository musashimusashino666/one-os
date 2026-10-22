"""Unit tests for the QEMU serial-log validator."""

import unittest

from check_qemu_serial import validate_serial_output


START = "ONE OS kernel booted"
COMPLETE = "ONE OS BOOTSTRAP COMPLETE"
PANIC = "ONE OS KERNEL PANIC"


class ValidateSerialOutputTests(unittest.TestCase):
    def test_healthy_boot_marker_and_expected_timeout_pass(self):
        valid, _ = validate_serial_output(f"{START}\n{COMPLETE}\n", 124)
        self.assertTrue(valid)

    def test_panic_after_completion_marker_fails(self):
        valid, reason = validate_serial_output(f"{START}\n{COMPLETE}\n{PANIC}\n", 124)
        self.assertFalse(valid)
        self.assertIn("panic", reason.lower())

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

    def test_clean_exit_is_not_accepted_as_expected_halt(self):
        valid, reason = validate_serial_output(f"{START}\n{COMPLETE}\n", 0)
        self.assertFalse(valid)
        self.assertIn("expected 124", reason.lower())


if __name__ == "__main__":
    unittest.main()
