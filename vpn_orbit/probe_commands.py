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
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("command deadline")
        with subprocess.Popen(args, stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, env=SAFE_ENV, start_new_session=True) as proc:
            try:
                output, _ = proc.communicate(data, timeout=min(5.0, remaining))
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
            return subprocess.CompletedProcess(args, proc.returncode, output, "")

    def checked(self, args: Sequence[str], *, data: str | None = None) -> str:
        try:
            result = self.run(args, data=data)
        except (OSError, subprocess.SubprocessError) as exc:
            raise IsolationUnavailable("isolation command unavailable") from exc
        if result.returncode:
            raise IsolationUnavailable("isolation command failed")
        return result.stdout
