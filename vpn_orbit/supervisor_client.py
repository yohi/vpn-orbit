import base64
import json
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TypedDict

from .probe_commands import SAFE_ENV, Commands, IsolationUnavailable
from .runner_types import IsolationResources


class Reply(TypedDict):
    ok: bool
    code: int | None
    stdout: str
    pid: int


class SupervisorClient(Commands):
    def __init__(self, resources: IsolationResources) -> None:
        super().__init__(resources.deadline)
        self.resources = resources
        self.channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        data = {"netns": resources.netns, "private_dir": str(resources.private_dir),
                "veth_host": resources.veth_host, "veth_ns": resources.veth_ns,
                "remote_ip": resources.remote_ip, "protocol": resources.protocol,
                "port": resources.port, "deadline": resources.deadline,
                "original": resources.host_ip_forward_original}
        try:
            self.proc = subprocess.Popen([sys.executable, "-m", "vpn_orbit.supervisor",
                str(child.fileno()), json.dumps(data)], pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, env=SAFE_ENV, cwd=Path(__file__).resolve().parent.parent)
            self.channel.settimeout(min(5, max(0.001, self.deadline - time.monotonic())))
            ready = json.loads(self.channel.recv(65536))
            if not ready.get("ok"):
                raise RuntimeError("supervisor unavailable")
        except BaseException:
            self.channel.close()
            raise
        finally:
            child.close()

    def request(self, op: str, *, args: list[str] | None = None,
                data: str | None = None, timeout_s: float = 5.0) -> Reply:
        deadline = self.resources.deadline + 15 if op in ("stop", "cleanup") else self.deadline
        try:
            self.channel.settimeout(min(15.0, max(0.001, deadline - time.monotonic())))
            self.channel.send(json.dumps({"op": op, "args": args, "data": data, "timeout_s": timeout_s}).encode())
            raw = json.loads(self.channel.recv(65536))
        except TimeoutError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise IsolationUnavailable("supervisor response unavailable") from exc
        if not isinstance(raw, dict):
            raise IsolationUnavailable("invalid supervisor response")
        return {"ok": raw.get("ok", False), "code": raw.get("code"),
                "stdout": raw.get("stdout", ""), "pid": raw.get("pid", 0)}

    def run(self, args: Sequence[str], *, data: str | None = None) -> subprocess.CompletedProcess[str]:
        reply = self.request("run", args=list(args), data=data)
        code = reply["code"]
        if code is None:
            raise IsolationUnavailable("missing command result")
        return subprocess.CompletedProcess(args, code, reply["stdout"], "")

    def openssl(self, args: Sequence[str], data: bytes, timeout_s: float) -> bytes:
        reply = self.request("openssl", args=list(args), data=base64.b64encode(data).decode("ascii"),
                             timeout_s=timeout_s)
        if not reply["ok"] or reply["code"] != 0:
            raise OSError("supervised validation failed")
        return base64.b64decode(reply["stdout"], validate=True)

    def finish(self) -> bool:
        cleanup_deadline = self.resources.deadline + 15
        try:
            reply = self.request("cleanup")
            self.proc.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
            return reply.get("ok", False) and self.proc.returncode == 0
        finally:
            self.channel.close()


class SupervisedProcess:
    def __init__(self, client: SupervisorClient, pid: int) -> None:
        self.client = client
        self.pid = pid

    def poll(self) -> int | None:
        return self.client.request("poll").get("code")

    def terminate(self) -> None:
        self.client.request("stop")

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout: float) -> int:
        reply = self.client.request("stop")
        if not reply.get("ok"):
            raise TimeoutError("process cleanup failed")
        return 0
