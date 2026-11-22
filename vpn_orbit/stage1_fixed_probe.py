"""Fixed-candidate single-attempt CLI (F-006)."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal

from .attempt_journal import AttemptJournal, EvidenceState, JournalResult, OwnerApproval
from .cloud_probe import ScreenedCandidate
from .fixed_candidates import (
    FixedCandidateError,
    candidate_id,
    fixed_shortlist,
    resolve_fixed_candidate,
)
from .geoip import GeoDecision, lookup_geoip
from .openvpn_probe import probe_one
from .phase1 import fetch_catalog
from .probe_types import ProbeResult, ProbeStatus
from .runner import ProbeRunner

_EvidenceState = EvidenceState
_CandidateIdRe: Final = re.compile(r"^[0-9a-f]{64}$")
_JournalRoot: Final = Path("/var/lib/vpn-orbit/stage1-attempts")
_HeadEnv: Final = "VPN_ORBIT_STAGE1_HEAD"
_ApiKeyEnv: Final = "IPAPI_IS_API_KEY"

# Fixed reason codes that may be projected from a finalized ProbeResult.
_ALLOWED_REASON_CODES: frozenset[str] = frozenset({
    "environment_secret_inheritance_rejected",
    "fixed_remote_excluded",
    "prerequisites_unavailable",
    "profile_parse_failed",
    "config_synthesis_failed",
    "ip_forward_save_failed",
    "supervisor_start_failed",
    "isolation_setup_failed",
    "supervisor_target_mismatch",
    "echo_route_not_tun0",
    "host_default_route_modified",
    "pre_tunnel_echo_reachable",
    "exit_host_resolution_failed",
    "echo_ip_not_global",
    "tun_not_established",
    "tun_ip_invalid",
    "exit_ip_fetch_failed",
    "exit_ip_body_not_global_ipv4",
    "exit_ip_non_tokyo",
    "exit_ip_geoip_unavailable",
    "exit_ip_tokyo_verified",
    "drop_curl_not_refused",
    "drop_counter_unavailable",
    "drop_counter_invalid",
    "drop_counter_not_advanced",
    "drop_route_unavailable",
    "drop_route_restore_failed",
    "drop_rule_cleanup_failed",
    "drop_evidence_unavailable",
    "stage_failure_unclassified",
    "not_verified",
})


class _CliExitReason:
    status: str | None
    recovery_state: str
    reason_codes: list[str]
    exit_code: int | None
    phase: str
    cleanup_status: str
    attempt_id: str | None
    candidate_id: str | None
    tun_evidence: _EvidenceState
    drop_evidence: _EvidenceState
    tunnel_https_evidence: _EvidenceState
    tokyo_geoip_evidence: _EvidenceState

    def __init__(
        self,
        *,
        status: str | None,
        recovery_state: Literal["NOT_STARTED", "FINALIZED", "RESULT_UNKNOWN"],
        reason_codes: list[str],
        exit_code: int | None,
        phase: str,
        cleanup_status: str,
        attempt_id: str | None,
        candidate_id: str | None,
        tun_evidence: _EvidenceState,
        drop_evidence: _EvidenceState,
        tunnel_https_evidence: _EvidenceState,
        tokyo_geoip_evidence: _EvidenceState,
    ) -> None:
        self.status = status
        self.recovery_state = recovery_state
        self.reason_codes = reason_codes
        self.exit_code = exit_code
        self.phase = phase
        self.cleanup_status = cleanup_status
        self.attempt_id = attempt_id
        self.candidate_id = candidate_id
        self.tun_evidence = tun_evidence
        self.drop_evidence = drop_evidence
        self.tunnel_https_evidence = tunnel_https_evidence
        self.tokyo_geoip_evidence = tokyo_geoip_evidence


def _current_head() -> str:
    head = os.environ.get(_HeadEnv, "").strip()
    if head:
        return head
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _journal_root() -> Path:
    return _JournalRoot


def _geo_lookup_default() -> Callable[[str], GeoDecision]:
    api_key = os.environ.get(_ApiKeyEnv, "").strip()
    if not api_key:
        raise RuntimeError("geoip_api_key_missing")
    return lambda ip: lookup_geoip(ip, api_key=api_key)


def _ingress(candidate: ScreenedCandidate) -> str:
    return f"{candidate.remote.ip}:{candidate.remote.port}/{candidate.remote.protocol}"


def _as_json(outcome: _CliExitReason) -> str:
    return json.dumps({
        "status": outcome.status,
        "recovery_state": outcome.recovery_state,
        "reason_codes": outcome.reason_codes,
        "exit_code": outcome.exit_code,
        "phase": outcome.phase,
        "cleanup_status": outcome.cleanup_status,
        "attempt_id": outcome.attempt_id,
        "candidate_id": outcome.candidate_id,
        "tun_evidence": outcome.tun_evidence,
        "drop_evidence": outcome.drop_evidence,
        "tunnel_https_evidence": outcome.tunnel_https_evidence,
        "tokyo_geoip_evidence": outcome.tokyo_geoip_evidence,
    }, separators=(",", ":"))


def _not_started(
    status: str,
    reason_codes: list[str],
    *,
    attempt_id: str | None = None,
    candidate_id: str | None = None,
) -> _CliExitReason:
    return _CliExitReason(
        status=status,
        recovery_state="NOT_STARTED",
        reason_codes=reason_codes,
        exit_code=None,
        phase="not_started",
        cleanup_status="not_required",
        attempt_id=attempt_id,
        candidate_id=candidate_id,
        tun_evidence="NOT_OBSERVED",
        drop_evidence="NOT_OBSERVED",
        tunnel_https_evidence="NOT_OBSERVED",
        tokyo_geoip_evidence="NOT_OBSERVED",
    )


def _result_unknown(
    reason_codes: list[str],
    *,
    attempt_id: str,
    candidate_id: str,
    phase: str = "not_started",
) -> _CliExitReason:
    return _CliExitReason(
        status=None,
        recovery_state="RESULT_UNKNOWN",
        reason_codes=reason_codes,
        exit_code=None,
        phase=phase,
        cleanup_status="not_required",
        attempt_id=attempt_id,
        candidate_id=candidate_id,
        tun_evidence="NOT_OBSERVED",
        drop_evidence="NOT_OBSERVED",
        tunnel_https_evidence="NOT_OBSERVED",
        tokyo_geoip_evidence="NOT_OBSERVED",
    )


def _allowed_reason_code(reason: str) -> str:
    if reason in _ALLOWED_REASON_CODES:
        return reason
    if reason.startswith("cleanup_failed:"):
        normalized = reason.split(":", 2)
        if len(normalized) >= 2 and all(
            _SAFE_CODE_FRAGMENT.fullmatch(part) for part in normalized
        ):
            return reason
    return "stage_failure_unclassified"


_SAFE_CODE_FRAGMENT: Final = re.compile(r"[a-z][a-z0-9_]*")


def _project_phase(result: ProbeResult) -> str:
    if result.phase == "cleanup":
        for marker in reversed(result.evidence):
            if marker.startswith("pre_cleanup_failure:"):
                parts = marker.split(":")
                if len(parts) >= 3:
                    return parts[1]
        return "cleanup"
    return result.phase


def _project_exit_code(status: ProbeStatus, cleanup_status: str) -> int | None:
    if status == ProbeStatus.PASS and cleanup_status == "confirmed":
        return 0
    return 1


def _project_evidence(evidence: tuple[str, ...]) -> dict[str, _EvidenceState]:
    def tun_verified(m: str) -> bool:
        return m.startswith("tls_tun_established:")

    def tun_failed(m: str) -> bool:
        return m.startswith("pre_cleanup_failure:tun_wait:")

    def drop_verified(m: str) -> bool:
        return m == "host_direct_rejected:direct_drop_counter_verified"

    def drop_failed(m: str) -> bool:
        return (
            m.startswith("pre_cleanup_failure:route_verification:drop_")
            or m.startswith("host_direct_echo_route:")
        )

    def https_verified(m: str) -> bool:
        return m == "tunnel_https_verified"

    def https_failed(m: str) -> bool:
        return m.startswith("pre_cleanup_failure:tunnel_echo:")

    def geo_verified(m: str) -> bool:
        return m == "exit_ip_tokyo_verified" or m.startswith("pre_cleanup_failure:exit_geoip:exit_ip_tokyo_verified")

    def geo_failed(m: str) -> bool:
        return m.startswith("pre_cleanup_failure:exit_geoip:exit_ip_non_tokyo")

    def state(verified: Callable[[str], bool], failed: Callable[[str], bool]) -> _EvidenceState:
        if any(verified(marker) for marker in evidence):
            return "VERIFIED"
        if any(failed(marker) for marker in evidence):
            return "FAILED"
        return "NOT_OBSERVED"

    return {
        "tun_evidence": state(tun_verified, tun_failed),
        "drop_evidence": state(drop_verified, drop_failed),
        "tunnel_https_evidence": state(https_verified, https_failed),
        "tokyo_geoip_evidence": state(geo_verified, geo_failed),
    }


def _project_result(result: ProbeResult) -> JournalResult:
    reason = _allowed_reason_code(result.reason_code)
    phase = _project_phase(result)
    evidence = _project_evidence(result.evidence)
    return JournalResult(
        status=result.status,
        recovery_state="FINALIZED",
        reason_codes=(reason,),
        exit_code=_project_exit_code(result.status, result.cleanup_status),
        phase=phase,
        cleanup_status=result.cleanup_status,
        tun_evidence=evidence["tun_evidence"],
        drop_evidence=evidence["drop_evidence"],
        tunnel_https_evidence=evidence["tunnel_https_evidence"],
        tokyo_geoip_evidence=evidence["tokyo_geoip_evidence"],
    )


def _from_journal(result: JournalResult, attempt_id: str, candidate_id: str) -> _CliExitReason:
    return _CliExitReason(
        status=result.status.value if result.status is not None else None,
        recovery_state=result.recovery_state,
        reason_codes=list(result.reason_codes),
        exit_code=result.exit_code,
        phase=result.phase,
        cleanup_status=result.cleanup_status,
        attempt_id=attempt_id,
        candidate_id=candidate_id,
        tun_evidence=result.tun_evidence,
        drop_evidence=result.drop_evidence,
        tunnel_https_evidence=result.tunnel_https_evidence,
        tokyo_geoip_evidence=result.tokyo_geoip_evidence,
    )


def _run_list(catalog: str, geo_lookup: Callable[[str], GeoDecision]) -> str:
    candidates = fixed_shortlist(catalog, geo_lookup)
    listed: list[dict[str, object]] = []
    for candidate in candidates:
        try:
            cid = candidate_id(candidate)
        except FixedCandidateError:
            cid = None
        listed.append({
            "candidate_id": cid,
            "ingress": _ingress(candidate),
            "country": candidate.candidate.country,
            "catalog_rank": candidate.catalog_rank,
        })
    return json.dumps({"candidates": listed}, separators=(",", ":"))


class _SummaryParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("invalid_arguments")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = _SummaryParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--probe-id")
    return parser.parse_args(argv)


def _run_probe_id(
    probe_id: str,
    catalog: str,
    geo_lookup: Callable[[str], GeoDecision],
    journal: AttemptJournal,
    runner: ProbeRunner | None,
    head: str,
) -> _CliExitReason:
    if _CandidateIdRe.fullmatch(probe_id) is None:
        return _not_started("BLOCKED", ["preflight_blocked"])

    try:
        snapshot = journal.inspect()
    except (OSError, ValueError, UnicodeError):
        return _not_started("BLOCKED", ["preflight_blocked"])
    if snapshot.has_unresolved or snapshot.has_active:
        return _not_started("BLOCKED", ["preflight_blocked"])
    if snapshot.legacy_hold:
        return _not_started("BLOCKED", ["legacy_unknown_owner_decision_required"])

    try:
        candidates = fixed_shortlist(catalog, geo_lookup)
        candidate = resolve_fixed_candidate(candidates, probe_id)
    except FixedCandidateError:
        return _not_started("BLOCKED", ["preflight_blocked"])
    if candidate is None:
        return _not_started("NOT_VERIFIED", ["candidate_not_found"])

    try:
        approval = journal.read_approval()
    except (OSError, ValueError, UnicodeError):
        return _not_started("BLOCKED", ["preflight_blocked"])
    if approval is None:
        return _not_started("BLOCKED", ["legacy_unknown_owner_decision_required"])
    if approval.candidate_id != probe_id or approval.approved_head != head:
        return _not_started("BLOCKED", ["preflight_blocked"])

    try:
        handle = journal.reserve(
            candidate_id=probe_id,
            ingress=_ingress(candidate),
            head=head,
            approval=approval,
        )
    except (OSError, ValueError, UnicodeError):
        return _not_started("BLOCKED", ["preflight_blocked"])

    with handle:
        try:
            journal.mark_running(handle)
        except OSError:
            return _not_started(
                "BLOCKED",
                ["probe_start_blocked"],
                attempt_id=handle.attempt_id,
                candidate_id=probe_id,
            )
        try:
            result = probe_one(
                candidate,
                geo_lookup=geo_lookup,
                runner=runner,
            )
        except Exception:
            return _result_unknown(
                ["attempt_result_unavailable"],
                attempt_id=handle.attempt_id,
                candidate_id=probe_id,
                phase="not_started",
            )
        journal_result = _project_result(result)
        try:
            journal.complete(handle, result=journal_result)
        except Exception:
            return _result_unknown(
                ["journal_finalization_failed"],
                attempt_id=handle.attempt_id,
                candidate_id=probe_id,
                phase=journal_result.phase,
            )
        return _from_journal(journal_result, handle.attempt_id, probe_id)


def _main(
    argv: list[str] | None = None,
    *,
    catalog: str | None = None,
    geo_lookup: Callable[[str], GeoDecision] | None = None,
    journal: AttemptJournal | None = None,
    runner: ProbeRunner | None = None,
    head: str | None = None,
) -> int:
    journal = journal or AttemptJournal(_journal_root())
    head = head or _current_head()
    try:
        args = _parse_args(argv)
    except ValueError:
        print(_as_json(_not_started("BLOCKED", ["preflight_blocked"])))
        return 1

    try:
        geo_lookup = geo_lookup or _geo_lookup_default()
    except RuntimeError:
        print(_as_json(_not_started("BLOCKED", ["input_unavailable"])))
        return 1

    try:
        catalog = catalog if catalog is not None else fetch_catalog()
    except (OSError, UnicodeError, ValueError):
        print(_as_json(_not_started("BLOCKED", ["input_unavailable"])))
        return 1

    if args.list:
        print(_run_list(catalog, geo_lookup))
        return 0

    if args.probe_id:
        outcome = _run_probe_id(
            args.probe_id,
            catalog,
            geo_lookup,
            journal,
            runner,
            head,
        )
        print(_as_json(outcome))
        return 0 if outcome.status == "PASS" else 1

    print(_as_json(_not_started("BLOCKED", ["preflight_blocked"])))
    return 1


def main(argv: list[str] | None = None) -> int:
    return _main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
