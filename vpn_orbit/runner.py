"""ProbeRunner adapter protocol and implementations.

The real subprocess runner is intentionally stubbed out in Stage 1; live
namespace/veth/nft/OpenVPN orchestration is environment-dependent and left as
a documented concern.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Protocol


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
    def start_supervisor(self, resources: IsolationResources) -> Any: ...
    def start_openvpn(self, config_path: Path, resources: IsolationResources) -> ProcessHandle: ...
    def wait_for_tun(
        self, process: ProcessHandle, resources: IsolationResources, deadline: float
    ) -> tuple[str | None, str]: ...
    def resolve_host(self, hostname: str) -> tuple[str | None, str]: ...
    def curl_via_tun(
        self,
        url: str,
        resolve: tuple[str, int],
        interface: str,
        resources: IsolationResources,
        deadline: float,
    ) -> tuple[str | None, str]: ...
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

    def start_supervisor(self, resources: IsolationResources) -> None:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def start_openvpn(self, config_path: Path, resources: IsolationResources) -> ProcessHandle:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def wait_for_tun(self, process: ProcessHandle, resources: IsolationResources, deadline: float) -> tuple[str | None, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def resolve_host(self, hostname: str) -> tuple[str | None, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def curl_via_tun(self, url: str, resolve: tuple[str, int], interface: str, resources: IsolationResources, deadline: float) -> tuple[str | None, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]:
        raise NotImplementedError("live runner is intentionally unimplemented in this stage")

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class FakeRunner:
    """Test double that records calls and returns canned probe results."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.prerequisites_ok_value = True
        self.cleaned = False
        self.supervisor_started = False
        self.wait_for_tun_result: tuple[str | None, str] = ("10.8.0.2", "ok")
        self.curl_result: tuple[str | None, str] = ("1.1.1.1", "ok")
        self.exit_ip = "1.1.1.1"
        self.unauthorized_egress = False
        self.cleanup_fail = False
        self.host_route_modified = False
        self.has_default_route = False
        self.has_remote_32_route = True
        self.has_echo_32_route = True
        self.commands: list[str] = []
        self.last_setup: tuple[str, str, int] | None = None
        self.last_config: bytes = b""
        self._resources: IsolationResources | None = None

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
        if self.unauthorized_egress:
            self.commands.append("unauthorized egress observed")
        self._resources = IsolationResources(
            netns="test-ns",
            private_dir=private_dir,
            veth_host="veth0",
            veth_ns="veth1",
            remote_ip=remote_ip,
            protocol=protocol,
            port=port,
        )
        return self._resources

    def teardown_isolation(self, resources: IsolationResources) -> tuple[bool, str]:
        self.cleaned = True
        self.commands.append("ip netns del test-ns")
        self.commands.append("nft delete table ip vpn_orbit_probe")
        if self.cleanup_fail:
            return False, "cleanup command failed"
        return True, ""

    def start_supervisor(self, resources: IsolationResources) -> None:
        self.supervisor_started = True
        self.commands.append("supervisor started")

    def start_openvpn(self, config_path: Path, resources: IsolationResources) -> ProcessHandle:
        self.last_config = config_path.read_bytes()
        return _FakeProcess(123)

    def wait_for_tun(self, process: ProcessHandle, resources: IsolationResources, deadline: float) -> tuple[str | None, str]:
        return self.wait_for_tun_result

    def resolve_host(self, hostname: str) -> tuple[str | None, str]:
        return (self.exit_ip, "ok")

    def curl_via_tun(
        self,
        url: str,
        resolve: tuple[str, int],
        interface: str,
        resources: IsolationResources,
        deadline: float,
    ) -> tuple[str | None, str]:
        if self.unauthorized_egress:
            return (None, "unauthorized egress observed")
        return self.curl_result

    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]:
        return (True, "")

    def now(self) -> float:
        return 0.0

    def sleep(self, seconds: float) -> None:
        pass


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self._pid = pid

    @property
    def pid(self) -> int:
        return self._pid

    def poll(self) -> int | None:
        return 0

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass
