"""Regression tests for NMI and machine-check IST QEMU output validation."""

import unittest

from check_qemu_ist import MARKERS, validate_ist_output


def valid_log() -> str:
    return "\r\n".join(MARKERS) + "\r\n"


class ValidateIstOutputTests(unittest.TestCase):
    def test_valid_nmi_and_machine_check_stack_markers_pass(self):
        valid, message = validate_ist_output(valid_log(), 33)
        self.assertTrue(valid, message)

    def test_wrong_qemu_exit_status_fails(self):
        valid, message = validate_ist_output(valid_log(), 124)
        self.assertFalse(valid)
        self.assertIn("expected 33", message)

    def test_missing_nmi_or_machine_check_marker_fails(self):
        for marker in MARKERS:
            with self.subTest(marker=marker):
                log = "\n".join(line for line in valid_log().splitlines() if line != marker)
                valid, message = validate_ist_output(log, 33)
                self.assertFalse(valid)
                self.assertIn("expected exactly one marker", message)

    def test_out_of_order_ist_markers_fail(self):
        log = "\n".join(reversed(MARKERS))
        valid, message = validate_ist_output(log, 33)
        self.assertFalse(valid)
        self.assertIn("out of order", message)

    def test_failure_markers_fail_even_with_success_markers(self):
        for marker in ("ONE OS IST TEST FAILED", "ONE OS KERNEL PANIC", "ONE OS EXCEPTION"):
            with self.subTest(marker=marker):
                valid, message = validate_ist_output(valid_log() + marker + "\n", 33)
                self.assertFalse(valid)
                self.assertIn("failure marker", message)


if __name__ == "__main__":
    unittest.main()
