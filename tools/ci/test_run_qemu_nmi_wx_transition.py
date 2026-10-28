"""Regression tests for the QMP-injected W^X transition NMI validator."""

import unittest

from run_qemu_nmi_wx_transition import (
    EXPECTED_STATUS,
    FAILURE_MARKERS,
    PASS_MARKER,
    READY_MARKER,
    validate_output,
)


def valid_log() -> str:
    return f"{READY_MARKER}\n{PASS_MARKER}\n"


class ValidateOutputTests(unittest.TestCase):
    def test_verified_non_present_then_real_nmi_passes(self):
        valid, message = validate_output(valid_log(), EXPECTED_STATUS)
        self.assertTrue(valid, message)

    def test_wrong_exit_status_fails(self):
        valid, message = validate_output(valid_log(), 124)
        self.assertFalse(valid)
        self.assertIn("expected 33", message)

    def test_missing_markers_fail(self):
        for marker in (READY_MARKER, PASS_MARKER):
            with self.subTest(marker=marker):
                log = "\n".join(line for line in valid_log().splitlines() if line != marker)
                valid, message = validate_output(log, EXPECTED_STATUS)
                self.assertFalse(valid)
                self.assertIn("expected exactly one marker", message)

    def test_duplicate_ready_or_pass_marker_fails(self):
        for marker in (READY_MARKER, PASS_MARKER):
            with self.subTest(marker=marker):
                valid, message = validate_output(valid_log() + marker + "\n", EXPECTED_STATUS)
                self.assertFalse(valid)
                self.assertIn("expected exactly one marker", message)

    def test_pass_before_ready_fails(self):
        log = f"{PASS_MARKER}\n{READY_MARKER}\n"
        valid, message = validate_output(log, EXPECTED_STATUS)
        self.assertFalse(valid)
        self.assertIn("before", message)

    def test_exception_page_fault_double_fault_and_panic_fail(self):
        markers = FAILURE_MARKERS + (
            "ONE OS EXCEPTION VECTOR: 0x000000000000000e",
            "ONE OS DOUBLE FAULT",
        )
        for marker in markers:
            with self.subTest(marker=marker):
                valid, message = validate_output(valid_log() + marker + "\n", EXPECTED_STATUS)
                self.assertFalse(valid)
                self.assertIn("failure marker", message)


if __name__ == "__main__":
    unittest.main()
