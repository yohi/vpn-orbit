"""Fail-closed single-candidate probe boundary (F-002/F-003)."""
from __future__ import annotations

import ipaddress
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, assert_never

from .config_synthesis import _reject_env_secrets, synthesize_openvpn_config
from .geoip import GeoDecision
from .phase1 import UnsupportedProfile, convert_ovpn
from .probe_commands import IsolationUnavailable
from .probe_lifecycle import bounded, cleanup
from .probe_types import ProbeResult, ProbeStatus
from .runner import IsolationResources, ProbeRunner, ProcessHandle, SubprocessRunner

if TYPE_CHECKING:
    from .cloud_probe import ScreenedCandidate


def _global_ipv4(value: str) -> str:
    ip = ipaddress.IPv4Address(value)
    if not ip.is_global:
        raise UnsupportedProfile("expected global IPv4")
    return str(ip)


def probe_one(candidate: ScreenedCandidate, *, geo_lookup: Callable[[str], GeoDecision],
              timeout_s: int = 60, runner: ProbeRunner | None = None) -> ProbeResult:
    """Return only redacted outcomes; cleanup failures override every other status."""
    started = time.monotonic()
    total = min(60.0, max(0.05, float(timeout_s)))
    deadline = started + total
    work_deadline = deadline - min(15.0, total / 4)
    runner = runner or SubprocessRunner()
    private_dir: Path | None = None
    resources: IsolationResources | None = None
    process: ProcessHandle | None = None
    status, reason, exit_ip = ProbeStatus.NOT_VERIFIED, "not_verified", None
    evidence: list[str] = []

    def execute() -> tuple[ProbeStatus, str, str | None]:
        nonlocal resources, process, private_dir
        try:
            _reject_env_secrets()
        except UnsupportedProfile:
            return ProbeStatus.BLOCKED, "environment_secret_inheritance_rejected", None
        if candidate.remote.ip in {"119.105.93.237", "126.234.242.57"}:
            return ProbeStatus.NOT_VERIFIED, "fixed_remote_excluded", None
        if not runner.prerequisites_ok():
            return ProbeStatus.BLOCKED, "prerequisites_unavailable", None
        try:
            endpoint = convert_ovpn(candidate.candidate.profile, expected_ip=candidate.remote.ip)
        except UnsupportedProfile:
            return ProbeStatus.NOT_VERIFIED, "profile_parse_failed", None
        private_dir = Path(tempfile.mkdtemp(prefix="vpn-orbit-", suffix=".probe"))
        private_dir.chmod(0o700)
        resources = IsolationResources.for_probe(candidate.remote, private_dir)
        resources.deadline = work_deadline
        ok, original = runner.save_host_ip_forward()
        if not ok:
            resources = None
            return ProbeStatus.BLOCKED, "ip_forward_save_failed", None
        resources.host_ip_forward_original = original
        ok, _ = runner.start_supervisor(resources)
        if not ok:
            resources = None
            return ProbeStatus.BLOCKED, "supervisor_start_failed", None
        try:
            config = synthesize_openvpn_config(endpoint, remote_ip=candidate.remote.ip,
                port=candidate.remote.port, protocol=candidate.remote.protocol,
                private_dir=private_dir)
        except UnsupportedProfile:
            return ProbeStatus.NOT_VERIFIED, "config_synthesis_failed", None
        try:
            configured = runner.setup_isolation(candidate.remote.ip, candidate.remote.protocol,
                                                 candidate.remote.port, private_dir)
        except (OSError, IsolationUnavailable):
            return ProbeStatus.BLOCKED, "isolation_setup_failed", None
        if (configured.netns, configured.veth_host, configured.veth_ns) != (
                resources.netns, resources.veth_host, resources.veth_ns):
            return ProbeStatus.FAIL, "supervisor_target_mismatch", None
        resources.config_path = private_dir / "client.ovpn"
        fd = os.open(resources.config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(config)
        echo_ip, _ = runner.resolve_host("api.ipify.org", work_deadline)
        if echo_ip is None:
            return ProbeStatus.NOT_VERIFIED, "exit_host_resolution_failed", None
        try:
            _global_ipv4(echo_ip)
        except (ValueError, UnsupportedProfile):
            return ProbeStatus.NOT_VERIFIED, "echo_ip_not_global", None
        ok, detail = runner.pre_tunnel_echo_check(echo_ip, resources, work_deadline)
        if not ok:
            return ProbeStatus.FAIL, "pre_tunnel_echo_reachable", None
        evidence.append("pre_tunnel_echo_refused:" + detail)
        process = runner.start_openvpn(resources.config_path, resources,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}, cwd=private_dir)
        tun_ip, _ = runner.wait_for_tun(process, resources, work_deadline)
        if tun_ip is None:
            return ProbeStatus.NOT_VERIFIED, "tun_not_established", None
        try:
            ipaddress.IPv4Address(tun_ip)
        except ValueError:
            return ProbeStatus.NOT_VERIFIED, "tun_ip_invalid", None
        evidence.append("tls_tun_established:" + tun_ip)
        ok, detail = runner.route_get_via_tun0(echo_ip, resources, work_deadline)
        if not ok:
            return ProbeStatus.FAIL, "echo_route_not_tun0", None
        evidence.append("echo_route:" + detail)
        ok, detail = runner.host_direct_route_rejected(echo_ip, resources, work_deadline)
        if not ok:
            return ProbeStatus.FAIL, "host_direct_echo_route", None
        evidence.append("host_direct_rejected:" + detail)
        ok, _ = runner.host_default_route_unchanged()
        if not ok:
            return ProbeStatus.FAIL, "host_default_route_modified", None
        outcome = runner.curl_via_tun("https://api.ipify.org/",
            ("api.ipify.org", 443, echo_ip), "tun0", resources, work_deadline)
        if outcome.safety_violation is not None:
            return ProbeStatus.FAIL, outcome.safety_violation, None
        if not outcome.is_success():
            return ProbeStatus.NOT_VERIFIED, "exit_ip_fetch_failed", None
        body = outcome.body or ""
        try:
            if len(body.encode()) > 64 or body != body.strip():
                raise UnsupportedProfile("invalid echo body")
            observed = _global_ipv4(body)
        except (ValueError, UnsupportedProfile):
            return ProbeStatus.NOT_VERIFIED, "exit_ip_body_not_global_ipv4", None
        match geo_lookup(observed):
            case GeoDecision.TOKYO:
                return ProbeStatus.PASS, "exit_ip_tokyo_verified", observed
            case GeoDecision.NON_TOKYO:
                return ProbeStatus.NOT_VERIFIED, "exit_ip_non_tokyo", observed
            case GeoDecision.UNKNOWN:
                return ProbeStatus.NOT_VERIFIED, "exit_ip_geoip_unavailable", observed
            case unreachable:
                assert_never(unreachable)

    try:
        with bounded(work_deadline):
            status, reason, exit_ip = execute()
    except BaseException as exc:  # noqa: BLE001 -- public cancellation boundary; redact exception text
        status, reason = ProbeStatus.NOT_VERIFIED, "probe_exception:" + type(exc).__name__
    finally:
        try:
            with bounded(deadline):
                failures = cleanup(runner, resources, process, private_dir, deadline)
        except BaseException as exc:  # noqa: BLE001 -- cleanup failure must override PASS
            failures = ["cleanup_deadline:" + type(exc).__name__]
        if failures:
            status, reason = ProbeStatus.FAIL, "cleanup_failed:" + ";".join(failures)
        else:
            evidence.append("cleanup_complete")
    return ProbeResult(candidate.remote.ip, candidate.remote.port, candidate.remote.protocol,
                       exit_ip, status, reason, tuple(evidence))


def probe_candidates(candidates: list[ScreenedCandidate], *,
                     geo_lookup: Callable[[str], GeoDecision], timeout_s: int = 60,
                     runner: ProbeRunner | None = None) -> list[ProbeResult]:
    return [probe_one(c, geo_lookup=geo_lookup, timeout_s=timeout_s, runner=runner)
            for c in candidates[:10]]
