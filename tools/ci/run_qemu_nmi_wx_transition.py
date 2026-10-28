#!/usr/bin/env python3
"""Run the dedicated W^X transition test and inject a genuine NMI via QMP."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

READY_MARKER = (
    "ONE OS WX NMI TEST READY: target direct-map PTE confirmed non-present"
)
PASS_MARKER = (
    "ONE OS WX NMI TEST PASS: vector 2 on IST2 during non-present window"
)
FAILURE_MARKERS = (
    "ONE OS WX NMI TEST FAILED",
    "ONE OS EXCEPTION",
    "ONE OS DOUBLE FAULT",
    "ONE OS PAGE FAULT",
    "ONE OS KERNEL PANIC",
    "ONE OS KERNEL W^X DIRECT-MAP TRANSITION FAILED",
    "ONE OS BOOTSTRAP COMPLETE",
    "ONE OS TSS INIT FAILED",
    "ONE OS INTERRUPT INIT FAILED",
)
EXPECTED_STATUS = 33


def validate_output(log: str, exit_status: int) -> tuple[bool, str]:
    """Require the ready/pass markers, ordered exactly once, with expected exit."""
    for marker in FAILURE_MARKERS:
        if marker in log:
            return False, f"failure marker found: {marker}"

    positions: list[int] = []
    for marker in (READY_MARKER, PASS_MARKER):
        if log.count(marker) != 1:
            return False, f"expected exactly one marker: {marker}"
        positions.append(log.find(marker))

    if positions != sorted(positions):
        return False, "NMI pass marker appeared before the non-present ready marker"

    if exit_status != EXPECTED_STATUS:
        return False, (
            f"unexpected QEMU exit status {exit_status}; "
            f"expected {EXPECTED_STATUS} from isa-debug-exit"
        )

    return True, "real QMP-injected NMI entered IST2 while the target PTE was non-present"


def read_qmp_message(reader) -> dict:
    line = reader.readline()
    if not line:
        raise RuntimeError("QMP connection closed before a response was received")
    message = json.loads(line.decode("utf-8"))
    if not isinstance(message, dict):
        raise RuntimeError("QMP returned a non-object response")
    return message


def qmp_execute(sock: socket.socket, reader, command: str, command_id: int) -> dict:
    payload = json.dumps({"execute": command, "id": command_id}).encode("utf-8") + b"\r\n"
    sock.sendall(payload)
    while True:
        message = read_qmp_message(reader)
        if message.get("id") != command_id:
            continue
        if "error" in message:
            raise RuntimeError(f"QMP command {command!r} failed: {message['error']}")
        if "return" not in message:
            raise RuntimeError(f"QMP command {command!r} returned an unexpected response")
        return message["return"]


def connect_qmp(socket_path: Path, process: subprocess.Popen, timeout: float):
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before QMP connected (status {process.returncode})")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        try:
            sock.connect(str(socket_path))
            reader = sock.makefile("rb")
            greeting = read_qmp_message(reader)
            if "QMP" not in greeting:
                raise RuntimeError("QMP greeting missing")
            qmp_execute(sock, reader, "qmp_capabilities", 1)
            return sock, reader
        except (OSError, RuntimeError, ValueError) as error:
            last_error = error
            try:
                sock.close()
            except OSError:
                pass
            time.sleep(0.05)
    raise RuntimeError(f"could not connect to QMP: {last_error}")


def read_log(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def wait_for_ready_marker(
    log_path: Path, process: subprocess.Popen, timeout: float
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        log = read_log(log_path)
        for marker in FAILURE_MARKERS:
            if marker in log:
                raise RuntimeError(f"guest failed before NMI injection: {marker}")
        count = log.count(READY_MARKER)
        if count > 1:
            raise RuntimeError("guest emitted the non-present ready marker more than once")
        if count == 1:
            return log
        if process.poll() is not None:
            raise RuntimeError(
                f"QEMU exited before the ready marker (status {process.returncode})"
            )
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for guest marker: {READY_MARKER}")


def run_test(args: argparse.Namespace) -> int:
    image_path = args.image.resolve()
    log_path = args.log.resolve()
    if not image_path.is_file():
        raise FileNotFoundError(f"BIOS image does not exist: {image_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="wx-nmi-") as temp_dir:
        qmp_path = Path(temp_dir) / "qmp.sock"
        command = [
            args.qemu,
            "-machine", args.machine,
            "-cpu", args.cpu,
            "-smp", str(args.smp),
            "-m", args.memory,
            "-drive", f"format=raw,file={image_path}",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-serial", f"file:{log_path}",
            "-display", "none",
            "-no-reboot",
            "-no-shutdown",
        ]
        print("Starting dedicated QEMU W^X/NMI profile")
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        qmp_sock = None
        qmp_reader = None
        try:
            qmp_sock, qmp_reader = connect_qmp(qmp_path, process, args.timeout_seconds)
            wait_for_ready_marker(log_path, process, args.timeout_seconds)
            print("Observed verified-non-present PTE marker; injecting guest NMI via QMP")
            qmp_execute(qmp_sock, qmp_reader, "inject-nmi", 2)
            try:
                status = process.wait(timeout=args.timeout_seconds)
            except subprocess.TimeoutExpired as error:
                raise TimeoutError(
                    "guest did not terminate after NMI injection; possible missed NMI or hang"
                ) from error
            log = read_log(log_path)
            print(log, end="" if log.endswith("\n") else "\n")
            valid, message = validate_output(log, status)
            print(message)
            return 0 if valid else 1
        finally:
            if qmp_reader is not None:
                qmp_reader.close()
            if qmp_sock is not None:
                qmp_sock.close()
            if process.poll() is None:
                process.kill()
                process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="test-only BIOS disk image")
    parser.add_argument("--log", type=Path, required=True, help="guest serial log path")
    parser.add_argument("--qemu", default="qemu-system-x86_64", help="QEMU executable")
    parser.add_argument("--machine", default=os.environ.get("QEMU_MACHINE", "pc-i440fx-8.2,accel=tcg"))
    parser.add_argument("--cpu", default=os.environ.get("QEMU_CPU", "qemu64,+nx"))
    parser.add_argument("--smp", type=int, default=int(os.environ.get("QEMU_SMP", "1")))
    parser.add_argument("--memory", default=os.environ.get("QEMU_MEMORY", "128M"))
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    args = parser.parse_args()

    try:
        return run_test(args)
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"QEMU W^X/NMI test failed: {error}", file=sys.stderr)
        print(read_log(args.log.resolve()), file=sys.stderr, end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
