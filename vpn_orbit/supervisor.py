"""Independent owner of OpenVPN, command children, and privileged cleanup."""
from __future__ import annotations

import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .isolation import remove_resources
from .probe_commands import SAFE_ENV, Commands
from .runner_types import IsolationResources


def stop_group(proc: subprocess.Popen[bytes] | None, grace: float = 3.0) -> bool:
    if proc is None:
        return reap_children()
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.wait(timeout=1)
        return reap_children()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=1)
    return reap_children()


def reap_children() -> bool:
    children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
    for child in children:
        try:
            os.kill(int(child), signal.SIGKILL)
        except ProcessLookupError:
            pass
    until = time.monotonic() + 1
    while time.monotonic() < until:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            time.sleep(0.01)
    return False


def serve(channel: socket.socket, resources: IsolationResources) -> None:
    # Adopt orphan grandchildren so SIGKILL does not leave zombie helpers.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper unavailable")
    proc: subprocess.Popen[bytes] | None = None
    commands = Commands(resources.deadline)
    cleanup_ok = False
    stopped = False
    channel.send(b'{"ok":true}')
    try:
        while True:
            channel.settimeout(max(0.001, resources.deadline - time.monotonic()))
            packet = channel.recv(65536)
            if not packet:
                break
            request = json.loads(packet)
            match request["op"]:
                case "run":
                    result = commands.run(request["args"], data=request.get("data"))
                    reply = {"ok": True, "code": result.returncode, "stdout": result.stdout}
                case "start":
                    log_path = resources.private_dir / "openvpn.log"
                    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as log:
                        proc = subprocess.Popen(["ip", "netns", "exec", resources.netns,
                            "openvpn", "--config", str(resources.private_dir / "client.ovpn"),
                            "--verb", "3"], stdin=subprocess.DEVNULL, stdout=log,
                            stderr=subprocess.DEVNULL, cwd=resources.private_dir,
                            env=SAFE_ENV, start_new_session=True)
                    reply = {"ok": True, "pid": proc.pid}
                case "poll":
                    reply = {"ok": True, "code": proc.poll() if proc else 0}
                case "stop":
                    stopped = stop_group(proc)
                    reply = {"ok": stopped}
                case "cleanup":
                    stopped = stop_group(proc)
                    cleanup_ok = remove_resources(resources, Commands(time.monotonic() + 10)) and stopped
                    channel.send(json.dumps({"ok": cleanup_ok}).encode())
                    break
                case _:
                    raise RuntimeError("invalid supervisor operation")
            channel.send(json.dumps(reply).encode())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        cleanup_ok = False
    finally:
        channel.close()
        if not cleanup_ok:
            stopped = stop_group(proc)
            # Remain alive, retrying only owned resources, until absence is confirmed.
            while not (remove_resources(resources, Commands(time.monotonic() + 10)) and stopped):
                stopped = stop_group(proc)
                time.sleep(0.1)


def main() -> None:
    fd, resource_json = sys.argv[1:]
    data = json.loads(resource_json)
    resources = IsolationResources(netns=data["netns"], private_dir=Path(data["private_dir"]),
        veth_host=data["veth_host"], veth_ns=data["veth_ns"], remote_ip=data["remote_ip"],
        protocol=data["protocol"], port=data["port"])
    resources.deadline = data["deadline"]
    resources.host_ip_forward_original = data["original"]
    with socket.socket(fileno=int(fd)) as channel:
        serve(channel, resources)


if __name__ == "__main__":
    main()
