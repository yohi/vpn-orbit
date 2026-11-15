"""Isolated OpenVPN tunnel verifier.

Implements F-002/F-003: run a screened candidate inside a dedicated network
namespace with veth/nftables NAT, verify the exit IP is Tokyo via HTTPS,
and clean up aggressively via an independent supervisor.
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .config_synthesis import _reject_env_secrets, synthesize_openvpn_config
from .geoip import GeoDecision
from .phase1 import UnsupportedProfile, convert_ovpn
from .runner import CurlOutcome, IsolationResources, ProbeRunner, SubprocessRunner

if TYPE_CHECKING:
    from .cloud_probe import ScreenedCandidate

__all__ = [
    "ProbeStatus",
    "ProbeResult",
    "synthesize_openvpn_config",
    "probe_one",
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


def _valid_ipv4(value: str) -> str:
    """Return a valid IPv4 address string. Does not require global routability."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsupportedProfile("expected a valid IPv4 address") from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise UnsupportedProfile("expected a valid IPv4 address")
    return str(ip)


def _time_left(deadline: float, runner: ProbeRunner) -> float:
    """Return remaining seconds before deadline, clamped to a positive value."""
    return max(0.0, deadline - runner.now())


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

    state: dict[str, Any] = {
        "status": ProbeStatus.NOT_VERIFIED,
        "reason_code": "not_verified",
        "exit_ip": None,
        "resources": None,
        "process": None,
    }
    private_dir = Path(tempfile.mkdtemp(prefix="vpn-orbit-", suffix=".probe"))
    private_dir.chmod(0o700)
    cleanup_failures: list[str] = []

    if runner is None:
        runner = SubprocessRunner()
    deadline = runner.now() + timeout_s

    def _do_cleanup() -> list[str]:
        failures: list[str] = []
        process = state.get("process")
        if process is not None:
            try:
                ok, reason = runner.terminate(process, graceful_s=3.0)
                if not ok:
                    failures.append(f"terminate_failed:{reason}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"terminate_error:{exc}")
        resources = state.get("resources")
        if resources is not None:
            if resources.host_ip_forward_original is not None:
                try:
                    ok, reason = runner.restore_host_ip_forward(resources.host_ip_forward_original)
                    if not ok:
                        failures.append(f"restore_ip_forward_failed:{reason}")
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"restore_ip_forward_error:{exc}")
            try:
                ok, reason = runner.teardown_isolation(resources)
                if not ok:
                    failures.append(f"teardown_failed:{reason}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"teardown_error:{exc}")
            try:
                ok, reason = runner.confirm_supervisor_cleanup(resources)
                if not ok:
                    failures.append(f"supervisor_cleanup_failed:{reason}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"supervisor_cleanup_error:{exc}")
        try:
            for child in private_dir.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink()
            private_dir.rmdir()
        except OSError as exc:
            failures.append(f"file_cleanup_error:{exc}")
        return failures

    def _probe_body() -> None:
        try:
            _reject_env_secrets()
        except UnsupportedProfile:
            state["status"] = ProbeStatus.BLOCKED
            state["reason_code"] = "environment_secret_inheritance_rejected"
            return

        if not runner.prerequisites_ok():
            state["status"] = ProbeStatus.BLOCKED
            state["reason_code"] = "prerequisites_unavailable"
            return

        try:
            endpoint = convert_ovpn(candidate.candidate.profile, expected_ip=ingress_ip)
        except UnsupportedProfile:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "profile_parse_failed"
            return

        try:
            config_bytes = synthesize_openvpn_config(
                endpoint,
                remote_ip=ingress_ip,
                port=port,
                protocol=protocol,
                private_dir=private_dir,
            )
        except UnsupportedProfile:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "config_synthesis_failed"
            return

        # Start the supervisor first so it records resource names and can
        # clean up even if the verifier is SIGKILLed before completing setup.
        supervisor_resources = IsolationResources(
            netns=f"vpn-orbit-{ingress_ip}-{port}",
            private_dir=private_dir,
            veth_host=f"veth-{ingress_ip}",
            veth_ns=f"vethns-{ingress_ip}",
            remote_ip=ingress_ip,
            protocol=protocol,
            port=port,
        )
        ok, reason = runner.start_supervisor(supervisor_resources)
        if not ok:
            state["status"] = ProbeStatus.BLOCKED
            state["reason_code"] = "supervisor_start_failed"
            return

        ip_forward_ok, ip_forward_original = runner.save_host_ip_forward()
        if not ip_forward_ok:
            state["status"] = ProbeStatus.BLOCKED
            state["reason_code"] = "ip_forward_save_failed"
            return

        resources = runner.setup_isolation(ingress_ip, protocol, port, private_dir)
        resources.host_ip_forward_original = ip_forward_original
        state["resources"] = resources
        resources.config_path = private_dir / "client.ovpn"
        fd = os.open(resources.config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(config_bytes)

        # Constrain the OpenVPN subprocess: clean env, cwd inside private_dir,
        # no inherited API keys or credentials.
        openvpn_env: dict[str, str] = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
        }
        process = runner.start_openvpn(
            resources.config_path,
            resources,
            env=openvpn_env,
            cwd=private_dir,
        )
        state["process"] = process

        tun_ip, reason = runner.wait_for_tun(process, resources, deadline)
        if tun_ip is None:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "tun_not_established"
            return
        try:
            _valid_ipv4(tun_ip)
        except UnsupportedProfile:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "tun_ip_invalid"
            return

        echo_host = "api.ipify.org"
        echo_port = 443
        echo_ip, reason = runner.resolve_host(echo_host, _time_left(deadline, runner))
        if echo_ip is None:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "exit_host_resolution_failed"
            return
        try:
            _global_ipv4(echo_ip)
        except UnsupportedProfile:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "echo_ip_not_global"
            return

        # Pre-tunnel safety: Echo must NOT be reachable before the tunnel is up.
        blocked, reason = runner.pre_tunnel_echo_check(echo_ip, resources, _time_left(deadline, runner))
        if not blocked:
            state["status"] = ProbeStatus.FAIL
            state["reason_code"] = "pre_tunnel_echo_reachable"
            return

        # Route evidence: echo IP must route via tun0.
        via_tun, reason = runner.route_get_via_tun0(echo_ip, resources, _time_left(deadline, runner))
        if not via_tun:
            state["status"] = ProbeStatus.FAIL
            state["reason_code"] = "echo_route_not_tun0"
            return

        # Host default route must remain untouched.
        host_route_ok, reason = runner.host_default_route_unchanged()
        if not host_route_ok:
            state["status"] = ProbeStatus.FAIL
            state["reason_code"] = "host_default_route_modified"
            return

        outcome = runner.curl_via_tun(
            f"https://{echo_host}/",
            (echo_host, echo_port, echo_ip),
            "tun0",
            resources,
            _time_left(deadline, runner),
        )
        if outcome.safety_violation is not None:
            state["status"] = ProbeStatus.FAIL
            state["reason_code"] = outcome.safety_violation
            return
        if not outcome.is_success():
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "exit_ip_fetch_failed"
            return
        body_ip = outcome.body.strip() if outcome.body else ""
        try:
            _global_ipv4(body_ip)
        except UnsupportedProfile:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "exit_ip_body_not_global_ipv4"
            return
        state["exit_ip"] = body_ip

        decision = geo_lookup(body_ip)
        if decision == GeoDecision.TOKYO:
            state["status"] = ProbeStatus.PASS
            state["reason_code"] = "exit_ip_tokyo_verified"
        elif decision == GeoDecision.NON_TOKYO:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "exit_ip_non_tokyo"
        else:
            state["status"] = ProbeStatus.NOT_VERIFIED
            state["reason_code"] = "exit_ip_geoip_unavailable"

    try:
        _probe_body()
    finally:
        cleanup_failures = _do_cleanup()

    if cleanup_failures:
        return ProbeResult(
            ingress_ip=ingress_ip,
            port=port,
            protocol=protocol,
            exit_ip=state.get("exit_ip"),
            status=ProbeStatus.FAIL,
            reason_code="cleanup_failed:" + ";".join(cleanup_failures),
        )
    return ProbeResult(
        ingress_ip=ingress_ip,
        port=port,
        protocol=protocol,
        exit_ip=state.get("exit_ip"),
        status=state["status"],
        reason_code=state["reason_code"],
    )


def probe_candidates(
    candidates: list["ScreenedCandidate"],
    *,
    geo_lookup: Callable[[str], GeoDecision],
    timeout_s: int = 60,
    runner: ProbeRunner | None = None,
) -> list[ProbeResult]:
    """Verify each screened candidate and return per-probe results.

    Exceptions from individual probes are isolated so one candidate failure does
    not abort the batch.
    """
    results: list[ProbeResult] = []
    for candidate in candidates:
        try:
            results.append(
                probe_one(candidate, geo_lookup=geo_lookup, timeout_s=timeout_s, runner=runner)
            )
        except BaseException:  # noqa: BLE001 -- defensive isolation
            results.append(
                ProbeResult(
                    ingress_ip=candidate.remote.ip,
                    port=candidate.remote.port,
                    protocol=candidate.remote.protocol,
                    exit_ip=None,
                    status=ProbeStatus.NOT_VERIFIED,
                    reason_code="probe_exception",
                )
            )
    return results
