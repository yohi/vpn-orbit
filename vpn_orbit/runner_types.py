"""Privileged probe contracts and per-probe resource identity."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
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
        self.table = "vo_" + hashlib.sha256(str(private_dir).encode()).hexdigest()[:12]
        self.deadline: float = 0.0
        self.echo_ip: str | None = None
        self.setup_started = False

    @classmethod
    def for_probe(cls, remote: Remote, private_dir: Path) -> IsolationResources:
        token = hashlib.sha256(str(private_dir).encode()).hexdigest()[:10]
        return cls(netns="vo-" + token, private_dir=private_dir,
                   veth_host="vh" + token, veth_ns="vn" + token,
                   remote_ip=remote.ip, protocol=remote.protocol, port=remote.port)


class Remote(Protocol):
    @property
    def ip(self) -> str: ...
    @property
    def port(self) -> int: ...
    @property
    def protocol(self) -> str: ...


class ProcessHandle(Protocol):
    """Minimal abstraction over a running OpenVPN process."""

    @property
    def pid(self) -> int: ...
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float) -> int: ...


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
    def host_direct_route_rejected(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]: ...
    def save_host_ip_forward(self) -> tuple[bool, str]: ...
    def restore_host_ip_forward(self, original: str) -> tuple[bool, str]: ...
    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]: ...
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
