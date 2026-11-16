import os
import signal
import subprocess
import time
from collections.abc import Sequence

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}


class IsolationUnavailable(RuntimeError):
    pass


class Commands:
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline

    def run(self, args: Sequence[str], *, data: str | None = None) -> subprocess.CompletedProcess[str]:
        result = self._capture(args, data.encode() if data is not None else None, 5.0)
        return subprocess.CompletedProcess(args, result.returncode, result.stdout.decode(), "")

    def _capture(self, args: Sequence[str], data: bytes | None, timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("command deadline")
        with subprocess.Popen(args, stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=SAFE_ENV, start_new_session=True) as proc:
            try:
                output, _ = proc.communicate(data, timeout=min(timeout_s, 5.0, remaining))
            except BaseException:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=1)
                raise
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            return subprocess.CompletedProcess(args, proc.returncode, output, b"")

    def openssl(self, args: Sequence[str], data: bytes, timeout_s: float) -> bytes:
        if tuple(args) not in {("x509", "-noout"), ("x509", "-pubkey", "-noout"),
                              ("pkey", "-pubin", "-outform", "DER"), ("pkey", "-pubout", "-outform", "DER")}:
            raise IsolationUnavailable("unsupported validation command")
        result = self._capture(["openssl", *args], data, timeout_s)
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, ["openssl", *args])
        return result.stdout

    def checked(self, args: Sequence[str], *, data: str | None = None) -> str:
        try:
            result = self.run(args, data=data)
        except (OSError, subprocess.SubprocessError) as exc:
            raise IsolationUnavailable("isolation command unavailable") from exc
        if result.returncode:
            raise IsolationUnavailable("isolation command failed")
        return result.stdout
