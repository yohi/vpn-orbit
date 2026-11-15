"""ProbeRunner adapter protocol and implementations.

The real subprocess runner is intentionally stubbed out in Stage 1; live
namespace/veth/nft/OpenVPN orchestration is environment-dependent and left as
a documented concern.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class CurlOutcome:
    """Typed outcome of a curl-through-tunnel request.

    `safety_violation` is an optional stable code such as
    "unauthorized_egress" that indicates the probe must FAIL.
    """

    body: str | None
    error: str
    safety_violation: str | None = None

    def is_success(self) -> bool:
        return self.body is not None and self.safety_violation is None


class IsolationResources:
    """Opaque handle returned by a runner's setup_isolation."""

    def __init__(
        self,
        *,
        netns: str,
        private_dir: Path,
        veth_host: str,
        veth_ns: str,
        remote_ip: str,
        protocol: str,
        port: int,
    ) -> None:
        self.netns = netns
        self.private_dir = private_dir
        self.veth_host = veth_host
        self.veth_ns = veth_ns
        self.remote_ip = remote_ip
        self.protocol = protocol
        self.port = port
        self.host_ip_forward_original: str | None = None
        self.config_path: Path | None = None


class ProcessHandle(Protocol):
    """Minimal abstraction over a running OpenVPN process."""

    @property
    def pid(self) -> int: ...
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


class ProbeRunner(Protocol):
    """Adapter for privileged operations, commands, time, and cleanup."""

    def prerequisites_ok(self) -> bool: ...
    def setup_isolation(
        self, remote_ip: str, protocol: str, port: int, private_dir: Path
    ) -> IsolationResources: ...
    def teardown_isolation(self, resources: IsolationResources) -> tuple[bool, str]: ...
    def start_supervisor(self, resources: IsolationResources) -> tuple[bool, str]: ...
    def confirm_supervisor_cleanup(self, resources: IsolationResources) -> tuple[bool, str]: ...
    def start_openvpn(
        self,
        config_path: Path,
        resources: IsolationResources,
        *,
        env: dict[str, str] | None,
        cwd: Path | None,
    ) -> ProcessHandle: ...
    def wait_for_tun(
        self, process: ProcessHandle, resources: IsolationResources, deadline: float
    ) -> tuple[str | None, str]: ...
    def resolve_host(self, hostname: str, deadline: float) -> tuple[str | None, str]: ...
    def curl_via_tun(
        self,
        url: str,
        resolve: tuple[str, int, str],
        interface: str,
        resources: IsolationResources,
        deadline: float,
    ) -> CurlOutcome: ...
    def pre_tunnel_echo_check(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]: ...
    def route_get_via_tun0(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]: ...
    def host_default_route_unchanged(self) -> tuple[bool, str]: ...
    def save_host_ip_forward(self) -> tuple[bool, str]: ...
    def restore_host_ip_forward(self, original: str) -> tuple[bool, str]: ...
    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]: ...
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class _SubprocessHandle:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self._proc = proc

    @property
    def pid(self) -> int:
        return self._proc.pid

    def poll(self) -> int | None:
        return self._proc.poll()

    def terminate(self) -> None:
        self._proc.terminate()

    def kill(self) -> None:
        self._proc.kill()


class SubprocessRunner:
    """Real runner using ip/nft/openvpn/curl. Requires root privileges."""

    def prerequisites_ok(self) -> bool:
        for binary in ("ip", "nft", "openvpn", "curl", "openssl"):
            if not shutil.which(binary):
                return False
        if not Path("/dev/net/tun").exists():
            return False
        try:
            result = subprocess.run(
                ["ip", "netns", "add", "_vpn_orbit_test"],
                capture_output=True,
                timeout=5,
            )
            subprocess.run(["ip", "netns", "del", "_vpn_orbit_test"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def setup_isolation(self, remote_ip: str, protocol: str, port: int, private_dir: Path) -> IsolationResources:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def teardown_isolation(self, resources: IsolationResources) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def start_supervisor(self, resources: IsolationResources) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def confirm_supervisor_cleanup(self, resources: IsolationResources) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def start_openvpn(
        self,
        config_path: Path,
        resources: IsolationResources,
        *,
        env: dict[str, str] | None,
        cwd: Path | None,
    ) -> ProcessHandle:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def wait_for_tun(self, process: ProcessHandle, resources: IsolationResources, deadline: float) -> tuple[str | None, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def resolve_host(self, hostname: str, deadline: float) -> tuple[str | None, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def curl_via_tun(
        self,
        url: str,
        resolve: tuple[str, int, str],
        interface: str,
        resources: IsolationResources,
        deadline: float,
    ) -> CurlOutcome:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def pre_tunnel_echo_check(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def route_get_via_tun0(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def host_default_route_unchanged(self) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def save_host_ip_forward(self) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def restore_host_ip_forward(self, original: str) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
