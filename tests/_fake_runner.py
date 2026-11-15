"""Test double for ProbeRunner."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vpn_orbit.runner import CurlOutcome, IsolationResources, ProcessHandle


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self._pid = pid
        self.terminated = False
        self.killed = False

    @property
    def pid(self) -> int:
        return self._pid

    def poll(self) -> int | None:
        return 0

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float) -> int:
        return 0


@dataclass
class FakeRunner:
    """Test double that records calls and returns canned probe results."""

    tmp: Path
    prerequisites_ok_value: bool = True
    cleaned: bool = False
    supervisor_started: bool = False
    supervisor_cleanup_confirmed: bool = True
    supervisor_start_fails: bool = False
    wait_for_tun_result: tuple[str | None, str] = ("10.8.0.2", "ok")
    curl_result: CurlOutcome = field(default_factory=lambda: CurlOutcome(
        body="1.1.1.1", error="", safety_violation=None,
    ))
    exit_ip: str = "1.1.1.1"
    route_get_via_tun0_result: bool = True
    host_route_modified: bool = False
    has_default_route: bool = False
    has_remote_32_route: bool = True
    has_echo_32_route: bool = True
    pre_tunnel_echo_blocked: bool = True
    save_ip_forward_fails: bool = False
    restore_ip_forward_fails: bool = False
    ip_forward_saved: bool = False
    ip_forward_restored: bool = False
    commands: list[str] = field(default_factory=list)
    last_setup: tuple[str, str, int] | None = None
    last_config: bytes = b""
    last_openvpn_env: dict[str, str] | None = None
    last_openvpn_cwd: Path | None = None
    terminate_fails: bool = False
    teardown_fails: bool = False
    resolve_host_fails: bool = False
    _resources: IsolationResources | None = None

    def prerequisites_ok(self) -> bool:
        return self.prerequisites_ok_value

    def setup_isolation(
        self, remote_ip: str, protocol: str, port: int, private_dir: Path
    ) -> IsolationResources:
        self.last_setup = (remote_ip, protocol, port)
        self.commands.append("ip netns add test-ns")
        self.commands.append("ip link add veth0 type veth peer veth1")
        self.commands.append(f"ip route add {remote_ip}/32 via 10.200.1.1")
        if not self.has_default_route:
            self.commands.append("default route absent")
        assert self._resources is not None
        return self._resources

    def teardown_isolation(self, resources: IsolationResources) -> tuple[bool, str]:
        self.cleaned = True
        self.commands.append("ip netns del test-ns")
        self.commands.append("nft delete table ip vpn_orbit_probe")
        if self.teardown_fails:
            return False, "cleanup command failed"
        return True, ""

    def start_supervisor(self, resources: IsolationResources) -> tuple[bool, str]:
        if self.supervisor_start_fails:
            return False, "supervisor failed to start"
        self.supervisor_started = True
        self._resources = resources
        self.commands.append("supervisor started")
        return True, ""

    def confirm_supervisor_cleanup(self, resources: IsolationResources) -> tuple[bool, str]:
        self.commands.append("supervisor cleanup confirmed")
        return self.supervisor_cleanup_confirmed, ""

    def start_openvpn(
        self,
        config_path: Path,
        resources: IsolationResources,
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> ProcessHandle:
        self.last_config = config_path.read_bytes()
        self.last_openvpn_env = env
        self.last_openvpn_cwd = cwd
        return _FakeProcess(123)

    def wait_for_tun(
        self, process: ProcessHandle, resources: IsolationResources, deadline: float
    ) -> tuple[str | None, str]:
        return self.wait_for_tun_result

    def resolve_host(self, hostname: str, deadline: float) -> tuple[str | None, str]:
        if self.resolve_host_fails:
            return (None, "resolution failed")
        return (self.exit_ip, "ok")

    def curl_via_tun(
        self,
        url: str,
        resolve: tuple[str, int, str],
        interface: str,
        resources: IsolationResources,
        deadline: float,
    ) -> CurlOutcome:
        self.commands.append(
            f"curl --interface {interface} --resolve {resolve[0]}:{resolve[1]}:{resolve[2]} {url}"
        )
        return self.curl_result

    def pre_tunnel_echo_check(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]:
        self.commands.append(f"pre-tunnel echo check {echo_ip}")
        return (self.pre_tunnel_echo_blocked, "")

    def route_get_via_tun0(
        self, echo_ip: str, resources: IsolationResources, deadline: float
    ) -> tuple[bool, str]:
        self.commands.append(f"ip route get {echo_ip}")
        return (self.route_get_via_tun0_result, "")

    def host_default_route_unchanged(self) -> tuple[bool, str]:
        self.commands.append("host default route check")
        return (not self.host_route_modified, "")

    def host_direct_route_rejected(self, echo_ip: str, resources: IsolationResources,
                                  deadline: float) -> tuple[bool, str]:
        return True, "direct_route_rejected"

    def save_host_ip_forward(self) -> tuple[bool, str]:
        self.ip_forward_saved = True
        self.commands.append("save ip_forward")
        if self.save_ip_forward_fails:
            return False, "save failed"
        return True, "1"

    def restore_host_ip_forward(self, original: str) -> tuple[bool, str]:
        self.ip_forward_restored = True
        self.commands.append("restore ip_forward")
        if self.restore_ip_forward_fails:
            return False, "restore failed"
        return True, ""

    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]:
        if self.terminate_fails:
            return False, "terminate failed"
        return (True, "")

    def now(self) -> float:
        return 0.0

    def sleep(self, seconds: float) -> None:
        pass
