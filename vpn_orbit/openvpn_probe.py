"""Isolated OpenVPN tunnel verifier.

Implements F-002/F-003: run a screened candidate inside a dedicated network
namespace with veth/nftables NAT, verify the exit IP is Tokyo via HTTPS,
and clean up aggressively via an independent supervisor.
"""
from __future__ import annotations

import ipaddress
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .config_synthesis import _reject_env_secrets, synthesize_openvpn_config
from .geoip import GeoDecision
from .phase1 import UnsupportedProfile, convert_ovpn
from .runner import FakeRunner, IsolationResources, ProbeRunner, SubprocessRunner

if TYPE_CHECKING:
    from .cloud_probe import ScreenedCandidate

__all__ = [
    "ProbeStatus",
    "ProbeResult",
    "synthesize_openvpn_config",
    "probe_one",
    "FakeRunner",
    "ProbeRunner",
    "IsolationResources",
]


class ProbeStatus(Enum):
    """Outcome of a single probe attempt."""

    PASS = "PASS"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED = "BLOCKED"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of a single probe attempt. Contains no secrets."""

    ingress_ip: str
    port: int
    protocol: str
    exit_ip: str | None
    status: ProbeStatus
    reason_code: str


def _global_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsupportedProfile("expected a globally routable IPv4 address") from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
        raise UnsupportedProfile("expected a globally routable IPv4 address")
    return str(ip)


def probe_one(
    candidate: "ScreenedCandidate",
    *,
    geo_lookup: Callable[[str], GeoDecision],
    timeout_s: int = 60,
    runner: ProbeRunner | None = None,
) -> ProbeResult:
    """Verify a single screened candidate inside an isolated namespace."""
    ingress_ip = candidate.remote.ip
    port = candidate.remote.port
    protocol = candidate.remote.protocol

    try:
        _reject_env_secrets()
    except UnsupportedProfile as exc:
        return ProbeResult(
            ingress_ip=ingress_ip,
            port=port,
            protocol=protocol,
            exit_ip=None,
            status=ProbeStatus.BLOCKED,
            reason_code=f"environment secret inheritance rejected: {exc}",
        )

    if runner is None:
        runner = SubprocessRunner()

    if not runner.prerequisites_ok():
        return ProbeResult(
            ingress_ip=ingress_ip,
            port=port,
            protocol=protocol,
            exit_ip=None,
            status=ProbeStatus.BLOCKED,
            reason_code="CAP_NET_ADMIN/TUN/nft/veth prerequisites unavailable",
        )

    try:
        endpoint = convert_ovpn(candidate.candidate.profile, expected_ip=ingress_ip)
    except UnsupportedProfile as exc:
        return ProbeResult(
            ingress_ip=ingress_ip,
            port=port,
            protocol=protocol,
            exit_ip=None,
            status=ProbeStatus.NOT_VERIFIED,
            reason_code=f"profile parse failed: {exc}",
        )

    private_dir = Path(tempfile.mkdtemp(prefix="vpn-orbit-", suffix=".probe"))
    private_dir.chmod(0o700)
    resources: IsolationResources | None = None
    process: Any = None
    exit_ip: str | None = None
    try:
        config_bytes = synthesize_openvpn_config(
            endpoint,
            remote_ip=ingress_ip,
            port=port,
            protocol=protocol,
            private_dir=private_dir,
        )
        resources = runner.setup_isolation(ingress_ip, protocol, port, private_dir)
        resources.config_path = private_dir / "client.ovpn"
        resources.config_path.write_bytes(config_bytes)

        runner.start_supervisor(resources)
        process = runner.start_openvpn(resources.config_path, resources)
        deadline = runner.now() + timeout_s

        tun_ip, reason = runner.wait_for_tun(process, resources, deadline)
        if tun_ip is None:
            return _finalize(
                candidate, runner, process, resources, private_dir, None,
                ProbeStatus.NOT_VERIFIED, f"tun not established: {reason}",
            )

        echo_host = "api.ipify.org"
        echo_port = 443
        echo_ip, reason = runner.resolve_host(echo_host)
        if echo_ip is None:
            return _finalize(
                candidate, runner, process, resources, private_dir, None,
                ProbeStatus.NOT_VERIFIED, f"exit host resolution failed: {reason}",
            )
        try:
            _global_ipv4(echo_ip)
        except UnsupportedProfile as exc:
            return _finalize(
                candidate, runner, process, resources, private_dir, None,
                ProbeStatus.FAIL, f"exit host IP not global: {exc}",
            )

        body, reason = runner.curl_via_tun(
            f"https://{echo_host}/",
            (echo_host, echo_port),
            "tun0",
            resources,
            deadline,
        )
        if body is None:
            if reason and "unauthorized egress" in reason:
                return _finalize(
                    candidate, runner, process, resources, private_dir, None,
                    ProbeStatus.FAIL, "observed unauthorized egress",
                )
            return _finalize(
                candidate, runner, process, resources, private_dir, None,
                ProbeStatus.NOT_VERIFIED, f"exit IP fetch failed: {reason}",
            )
        body_ip = body.strip()
        try:
            _global_ipv4(body_ip)
        except UnsupportedProfile as exc:
            return _finalize(
                candidate, runner, process, resources, private_dir, None,
                ProbeStatus.FAIL, f"exit IP body not global IPv4: {exc}",
            )
        exit_ip = body_ip

        decision = geo_lookup(exit_ip)
        if decision == GeoDecision.TOKYO:
            status = ProbeStatus.PASS
            reason_code = "exit IP verified as Tokyo, JP"
        elif decision == GeoDecision.NON_TOKYO:
            status = ProbeStatus.FAIL
            reason_code = "exit IP GeoIP is not Tokyo, JP"
        else:
            status = ProbeStatus.NOT_VERIFIED
            reason_code = "exit IP GeoIP decision unavailable"

        return _finalize(
            candidate, runner, process, resources, private_dir, exit_ip,
            status, reason_code,
        )
    except Exception as exc:  # noqa: BLE001 -- defensive catch for cleanup
        return _finalize(
            candidate, runner, process, resources, private_dir, exit_ip,
            ProbeStatus.FAIL, f"unexpected error: {exc}",
        )


def _finalize(
    candidate: "ScreenedCandidate",
    runner: ProbeRunner,
    process: Any,
    resources: IsolationResources | None,
    private_dir: Path,
    exit_ip: str | None,
    status: ProbeStatus,
    reason_code: str,
) -> ProbeResult:
    """Terminate the process, clean up, and return the result."""
    if process is not None:
        runner.terminate(process, graceful_s=3.0)
    cleanup_ok = True
    cleanup_reason = ""
    if resources is not None:
        ok, reason = runner.teardown_isolation(resources)
        if not ok:
            cleanup_ok = False
            cleanup_reason = reason
    try:
        for child in private_dir.iterdir():
            if child.is_file():
                child.unlink()
        private_dir.rmdir()
    except OSError as exc:
        cleanup_ok = False
        cleanup_reason = f"{cleanup_reason}; file cleanup failed: {exc}" if cleanup_reason else f"file cleanup failed: {exc}"
    if not cleanup_ok:
        status = ProbeStatus.FAIL
        reason_code = f"cleanup failed: {cleanup_reason}"
    return ProbeResult(
        ingress_ip=candidate.remote.ip,
        port=candidate.remote.port,
        protocol=candidate.remote.protocol,
        exit_ip=exit_ip,
        status=status,
        reason_code=reason_code,
    )
