"""Wall-clock bounds and fail-safe cleanup at the probe boundary."""
import shutil
import signal
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType

from .runner import IsolationResources, ProbeRunner, ProcessHandle


class ProbeDeadline(TimeoutError):
    pass


def _expired(signum: int, frame: FrameType | None) -> None:
    raise ProbeDeadline("probe deadline exceeded")


@contextmanager
def bounded(deadline: float) -> Iterator[None]:
    # SIGALRM bounds even a stalled DNS resolver, injected callback, or setup.
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("probe requires the main thread")
    previous = signal.signal(signal.SIGALRM, _expired)
    timer = signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *timer)


def cleanup(runner: ProbeRunner, resources: IsolationResources | None,
            process: ProcessHandle | None, private_dir: Path | None, deadline: float) -> list[str]:
    failures: list[str] = []
    operations = []
    if process is not None:
        operations.append(("terminate", lambda: runner.terminate(process, graceful_s=3.0)))
    if resources is not None:
        operations.append(("teardown", lambda: runner.teardown_isolation(resources)))
        if resources.host_ip_forward_original is not None:
            original = resources.host_ip_forward_original
            operations.append(("restore_ip_forward", lambda: runner.restore_host_ip_forward(
                original)))
        operations.append(("supervisor_cleanup", lambda: runner.confirm_supervisor_cleanup(resources)))
    for name, operation in operations:
        if time.monotonic() >= deadline:
            failures.append("cleanup_deadline")
            break
        try:
            with bounded(deadline):
                ok, _ = operation()
            if not ok:
                failures.append(name + "_failed")
        except BaseException as exc:  # noqa: BLE001 -- cancellation must not skip remaining cleanup
            failures.append(name + "_error:" + type(exc).__name__)
    if private_dir is not None:
        try:
            with bounded(deadline):
                shutil.rmtree(private_dir, ignore_errors=False)
        except FileNotFoundError:
            return failures
        except OSError as exc:
            failures.append("file_cleanup_error:" + type(exc).__name__)
    return failures
