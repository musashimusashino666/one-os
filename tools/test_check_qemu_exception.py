"""Unit tests for the controlled CPU exception serial-log validator."""

import unittest

from check_qemu_exception import validate_exception_output


def valid_log(case: str, *, error_code: str | None = None, fault_address: str | None = None) -> str:
    cases = {
        "ud": ("invalid opcode", "0x0000000000000006", "ONE OS EXCEPTION TEST: triggering invalid opcode"),
        "gp": ("general protection fault", "0x000000000000000d", "ONE OS EXCEPTION TEST: triggering general protection fault"),
        "pf": ("page fault", "0x000000000000000e", "ONE OS EXCEPTION TEST: triggering page fault"),
    }
    description, vector, trigger = cases[case]
    lines = [
        trigger,
        "ONE OS EXCEPTION",
        f"Exception: {description}",
        f"Exception vector: {vector}",
        "Instruction pointer: 0x0000000000101234",
        "Code segment: 0x0000000000000008",
        "CPU flags: 0x0000000000000202",
        "Stack pointer: 0x0000000000200000",
        "Stack segment: 0x0000000000000010",
    ]
    if error_code is not None:
        lines.append(f"Error code: {error_code}")
    if fault_address is not None:
        lines.append(f"Fault address (CR2): {fault_address}")
    lines.append("ONE OS EXCEPTION HALTED")
    return "\r\n".join(lines) + "\r\n"


class ValidateExceptionOutputTests(unittest.TestCase):
    def test_valid_invalid_opcode_diagnostics_pass(self):
        valid, message = validate_exception_output(valid_log("ud"), 124, "ud")
        self.assertTrue(valid, message)

    def test_exact_general_protection_error_code_is_required(self):
        log = valid_log("gp", error_code="0x000000000000fffc")
        self.assertTrue(validate_exception_output(log, 124, "gp")[0])

        wrong = log.replace("Error code: 0x000000000000fffc", "Error code: 0x0000000000000000")
        valid, message = validate_exception_output(wrong, 124, "gp")
        self.assertFalse(valid)
        self.assertIn("Error code", message)

    def test_page_fault_error_code_and_cr2_must_match(self):
        log = valid_log(
            "pf",
            error_code="0x0000000000000000",
            fault_address="0x0000400000000000",
        )
        self.assertTrue(validate_exception_output(log, 124, "pf")[0])

        wrong_cr2 = log.replace(
            "Fault address (CR2): 0x0000400000000000",
            "Fault address (CR2): 0x0000000000001000",
        )
        valid, message = validate_exception_output(wrong_cr2, 124, "pf")
        self.assertFalse(valid)
        self.assertIn("Fault address (CR2)", message)

    def test_each_saved_state_field_is_required(self):
        for label in (
            "Instruction pointer",
            "Code segment",
            "CPU flags",
            "Stack pointer",
            "Stack segment",
        ):
            with self.subTest(label=label):
                log = valid_log("ud").replace(
                    f"{label}: 0x0000000000101234\n", ""
                )
                # Remove the exact sample field irrespective of its value.
                log = "\n".join(
                    line for line in log.splitlines() if not line.startswith(label + ":")
                )
                valid, message = validate_exception_output(log, 124, "ud")
                self.assertFalse(valid)
                self.assertIn(label, message)

    def test_out_of_order_diagnostics_fail(self):
        log = valid_log("ud")
        lines = log.splitlines()
        ip = lines.pop(next(i for i, line in enumerate(lines) if line.startswith("Instruction pointer:")))
        lines.insert(next(i for i, line in enumerate(lines) if line.startswith("Exception vector:")), ip)
        valid, message = validate_exception_output("\n".join(lines), 124, "ud")
        self.assertFalse(valid)
        self.assertIn("out-of-order", message)

    def test_missing_trigger_or_halt_marker_fails(self):
        log = valid_log("ud")
        for marker in (
            "ONE OS EXCEPTION TEST: triggering invalid opcode",
            "ONE OS EXCEPTION HALTED",
        ):
            with self.subTest(marker=marker):
                mutated = "\n".join(
                    line for line in log.splitlines() if line != marker
                )
                valid, _ = validate_exception_output(mutated, 124, "ud")
                self.assertFalse(valid)

    def test_boot_completion_or_panic_marker_fails(self):
        for marker in ("ONE OS BOOTSTRAP COMPLETE", "ONE OS KERNEL PANIC"):
            valid, message = validate_exception_output(valid_log("ud") + marker + "\n", 124, "ud")
            self.assertFalse(valid)
            self.assertIn("marker", message.lower())

    def test_unexpected_exit_status_fails(self):
        valid, message = validate_exception_output(valid_log("ud"), 0, "ud")
        self.assertFalse(valid)
        self.assertIn("expected 124", message)

    def test_unknown_case_fails(self):
        valid, message = validate_exception_output(valid_log("ud"), 124, "nmi")
        self.assertFalse(valid)
        self.assertIn("unknown exception case", message)


if __name__ == "__main__":
    unittest.main()
