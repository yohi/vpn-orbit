"""Fail-closed single-candidate probe boundary (F-002/F-003)."""
from __future__ import annotations

import ipaddress
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, assert_never

from .config_synthesis import _reject_env_secrets, synthesize_openvpn_config
from .geoip import GeoDecision
from .openvpn_diagnostics import (
    OPENVPN_DIAGNOSTIC_CODES, OPENVPN_PROGRESS_CODES, PROCESS_STATES, LINK_IO_CODES,
)
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


@dataclass
class _ProbeState:
    private_dir: Path | None = None
    resources: IsolationResources | None = None
    process: ProcessHandle | None = None
    evidence: list[str] = field(default_factory=list)
    phase: str = "preflight"


def _prepare_probe(
    candidate: ScreenedCandidate, runner: ProbeRunner, work_deadline: float,
    state: _ProbeState,
) -> tuple[ProbeStatus, str] | None:
    try:
        _reject_env_secrets()
    except UnsupportedProfile:
        return ProbeStatus.BLOCKED, "environment_secret_inheritance_rejected"
    if candidate.remote.ip in {"119.105.93.237", "126.234.242.57"}:
        return ProbeStatus.NOT_VERIFIED, "fixed_remote_excluded"
    if not runner.prerequisites_ok():
        return ProbeStatus.BLOCKED, "prerequisites_unavailable"
    state.phase = "profile_parse"
    try:
        endpoint = convert_ovpn(candidate.candidate.profile, expected_ip=candidate.remote.ip)
    except UnsupportedProfile:
        return ProbeStatus.NOT_VERIFIED, "profile_parse_failed"

    state.phase = "resource_setup"
    state.private_dir = Path(tempfile.mkdtemp(prefix="vpn-orbit-", suffix=".probe"))
    state.private_dir.chmod(0o700)
    state.resources = IsolationResources.for_probe(candidate.remote, state.private_dir)
    state.resources.deadline = work_deadline
    ok, original = runner.save_host_ip_forward()
    if not ok:
        state.resources = None
        return ProbeStatus.BLOCKED, "ip_forward_save_failed"
    state.resources.host_ip_forward_original = original
    state.phase = "supervisor_start"
    ok, _ = runner.start_supervisor(state.resources)
    if not ok:
        state.resources = None
        return ProbeStatus.BLOCKED, "supervisor_start_failed"
    state.phase = "config_synthesis"
    try:
        config = synthesize_openvpn_config(
            endpoint, remote_ip=candidate.remote.ip, port=candidate.remote.port,
            protocol=candidate.remote.protocol, private_dir=state.private_dir,
            commands=runner.validation_commands(),
        )
    except UnsupportedProfile:
        return ProbeStatus.NOT_VERIFIED, "config_synthesis_failed"
    state.phase = "isolation_setup"
    try:
        configured = runner.setup_isolation(
            candidate.remote.ip, candidate.remote.protocol,
            candidate.remote.port, state.private_dir,
        )
    except (OSError, IsolationUnavailable):
        return ProbeStatus.BLOCKED, "isolation_setup_failed"
    resources = state.resources
    if (configured.netns, configured.veth_host, configured.veth_ns) != (
        resources.netns, resources.veth_host, resources.veth_ns,
    ):
        return ProbeStatus.FAIL, "supervisor_target_mismatch"
    state.phase = "config_write"
    resources.config_path = state.private_dir / "client.ovpn"
    fd = os.open(resources.config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(config)
    return None


def _verify_routes(
    runner: ProbeRunner, echo_ip: str, resources: IsolationResources,
    work_deadline: float, evidence: list[str],
) -> tuple[ProbeStatus, str] | None:
    ok, detail = runner.route_get_via_tun0(echo_ip, resources, work_deadline)
    if not ok:
        return ProbeStatus.FAIL, "echo_route_not_tun0"
    evidence.append("echo_route:" + detail)
    ok, detail = runner.host_direct_route_rejected(echo_ip, resources, work_deadline)
    if not ok:
        return ProbeStatus.FAIL, "host_direct_echo_route"
    evidence.append("host_direct_rejected:" + detail)
    return None


def _verify_tunnel(
    runner: ProbeRunner, work_deadline: float,
    state: _ProbeState, geo_lookup: Callable[[str], GeoDecision],
) -> tuple[ProbeStatus, str, str | None]:
    resources = state.resources
    private_dir = state.private_dir
    if resources is None or private_dir is None or resources.config_path is None:
        return ProbeStatus.FAIL, "probe_state_incomplete", None
    state.phase = "echo_resolution"
    echo_ip, _ = runner.resolve_host("api.ipify.org", work_deadline)
    if echo_ip is None:
        return ProbeStatus.NOT_VERIFIED, "exit_host_resolution_failed", None
    try:
        _global_ipv4(echo_ip)
    except (ValueError, UnsupportedProfile):
        return ProbeStatus.NOT_VERIFIED, "echo_ip_not_global", None
    state.phase = "pre_tunnel_echo"
    ok, detail = runner.pre_tunnel_echo_check(echo_ip, resources, work_deadline)
    if not ok:
        return ProbeStatus.FAIL, "pre_tunnel_echo_reachable", None
    state.evidence.append("pre_tunnel_echo_refused:" + detail)
    state.phase = "openvpn_start"
    state.process = runner.start_openvpn(
        resources.config_path, resources,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}, cwd=private_dir,
    )
    state.phase = "tun_wait"
    tun_ip, _ = runner.wait_for_tun(state.process, resources, work_deadline)
    if tun_ip is None:
        return ProbeStatus.NOT_VERIFIED, "tun_not_established", None
    try:
        ipaddress.IPv4Address(tun_ip)
    except ValueError:
        return ProbeStatus.NOT_VERIFIED, "tun_ip_invalid", None
    state.evidence.append("tls_tun_established:" + tun_ip)
    state.phase = "route_verification"
    route_failure = _verify_routes(runner, echo_ip, resources, work_deadline, state.evidence)
    if route_failure is not None:
        return route_failure[0], route_failure[1], None
    ok, _ = runner.host_default_route_unchanged()
    if not ok:
        return ProbeStatus.FAIL, "host_default_route_modified", None
    state.phase = "tunnel_echo"
    outcome = runner.curl_via_tun(
        "https://api.ipify.org/", ("api.ipify.org", 443, echo_ip),
        "tun0", resources, work_deadline,
    )
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
    state.phase = "exit_geoip"
    match geo_lookup(observed):
        case GeoDecision.TOKYO:
            return ProbeStatus.PASS, "exit_ip_tokyo_verified", observed
        case GeoDecision.NON_TOKYO:
            return ProbeStatus.NOT_VERIFIED, "exit_ip_non_tokyo", observed
        case GeoDecision.UNKNOWN:
            return ProbeStatus.NOT_VERIFIED, "exit_ip_geoip_unavailable", observed
        case unreachable:
            assert_never(unreachable)


def probe_one(candidate: ScreenedCandidate, *, geo_lookup: Callable[[str], GeoDecision],
              timeout_s: int = 60, runner: ProbeRunner | None = None) -> ProbeResult:
    """Return only redacted outcomes; cleanup failures override every other status."""
    started = time.monotonic()
    total = min(60.0, max(0.05, float(timeout_s)))
    deadline = started + total
    work_deadline = deadline - min(15.0, total / 4)
    runner = runner or SubprocessRunner()
    state = _ProbeState()
    status, reason, exit_ip = ProbeStatus.NOT_VERIFIED, "not_verified", None
    final_phase = state.phase
    cleanup_status = "not_required"
    try:
        with bounded(work_deadline):
            early_result = _prepare_probe(candidate, runner, work_deadline, state)
            if early_result is None:
                status, reason, exit_ip = _verify_tunnel(runner, work_deadline, state, geo_lookup)
            else:
                status, reason = early_result
    except Exception as exc:  # noqa: BLE001 -- redact unexpected probe exceptions
        status, reason = ProbeStatus.NOT_VERIFIED, "probe_exception:" + type(exc).__name__
    finally:
        # Preserve the failing work stage before starting cleanup. Never expose
        # untrusted exception text or OpenVPN output in this public field.
        final_phase = state.phase
        try:
            with bounded(deadline):
                failures = cleanup(runner, state.resources, state.process, state.private_dir, deadline)
        except BaseException as exc:  # noqa: BLE001 -- cleanup failure must override PASS
            failures = ["cleanup_deadline:" + type(exc).__name__]
        if failures:
            status, reason = ProbeStatus.FAIL, "cleanup_failed:" + ";".join(failures)
            final_phase = "cleanup"
            cleanup_status = "failed"
        else:
            state.evidence.append("cleanup_complete")
            if state.resources is not None:
                cleanup_status = "confirmed"
    # Fixed advisory code only: the original status, safety gates and cleanup
    # precedence remain unchanged, including when OpenVPN logs are hostile.
    if final_phase == "tun_wait" and status == ProbeStatus.NOT_VERIFIED:
        hint = getattr(runner, "openvpn_failure_code", "not_observed")
        if isinstance(hint, str) and hint in OPENVPN_DIAGNOSTIC_CODES and hint != "not_observed":
            reason += ":openvpn_" + hint
    # These observations are optional, fixed codes only, and never alter PASS,
    # FAIL, NOT_VERIFIED, or cleanup precedence.
    def safe_code(attribute: str, allowed: frozenset[str], default: str) -> str:
        value = getattr(runner, attribute, default)
        return value if type(value) is str and value in allowed else default

    progress = safe_code("openvpn_progress", OPENVPN_PROGRESS_CODES, "not_observed")
    process_state = safe_code("openvpn_process_state", PROCESS_STATES, "not_started")
    link_io = safe_code("link_io", LINK_IO_CODES, "not_observed")
    elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
    return ProbeResult(candidate.remote.ip, candidate.remote.port, candidate.remote.protocol,
                       exit_ip, status, reason, tuple(state.evidence),
                       final_phase, elapsed_ms, cleanup_status, progress, process_state, link_io)


def probe_candidates(candidates: list[ScreenedCandidate], *,
                     geo_lookup: Callable[[str], GeoDecision], timeout_s: int = 60,
                     runner: ProbeRunner | None = None) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    for candidate in candidates[:10]:
        result = probe_one(candidate, geo_lookup=geo_lookup, timeout_s=timeout_s, runner=runner)
        results.append(result)
        if result.reason_code.startswith("cleanup_failed"):
            break
    return results
