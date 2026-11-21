"""Cloud candidate screening: VPN Gate catalog -> ranked shortlist.

Implements F-001 selection order, fixed-IP exclusion, RemoteKey deduplication,
TCP/UDP windowing, per-IP GeoIP caching, deterministic ranking, and workflow
status aggregation.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Literal, NoReturn

from .geoip import GeoDecision, lookup_geoip
from .openvpn_diagnostics import OPENVPN_PROGRESS_CODES, PROCESS_STATES, LINK_IO_CODES
from .openvpn_probe import ProbeResult, ProbeStatus, probe_candidates, probe_one
from .phase1 import Candidate, convert_ovpn, fetch_catalog, parse_catalog


__all__ = [
    "aggregate_status",
    "RemoteKey",
    "ScreenedCandidate",
    "screen_candidates",
    "tcp_reachable",
    "probe_candidates",
    "ProbeStatus",
    "ProbeResult",
]


def aggregate_status(results: Iterable[ProbeStatus]) -> ProbeStatus:
    """Aggregate probe results into a single workflow status.

    Contract from F-004:
    - Any FAIL -> overall FAIL
    - Otherwise any PASS -> PASS
    - Otherwise any BLOCKED -> BLOCKED
    - Otherwise NOT_VERIFIED (including empty results)
    """
    seen = set(results)
    if ProbeStatus.FAIL in seen:
        return ProbeStatus.FAIL
    if ProbeStatus.PASS in seen:
        return ProbeStatus.PASS
    if ProbeStatus.BLOCKED in seen:
        return ProbeStatus.BLOCKED
    return ProbeStatus.NOT_VERIFIED


@dataclass(frozen=True, slots=True)
class RemoteKey:
    ip: str
    port: int
    protocol: Literal["tcp", "udp"]

    def __post_init__(self):
        try:
            parsed = ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"remote IP must be a valid IPv4 address: {self.ip}") from exc
        if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_global:
            raise ValueError(f"remote IP must be a globally routable IPv4 address: {self.ip}")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"remote port must be 1..65535: {self.port}")
        if self.protocol not in ("tcp", "udp"):
            raise ValueError(f"remote protocol must be tcp or udp: {self.protocol}")


@dataclass(frozen=True, slots=True)
class ScreenedCandidate:
    candidate: Candidate
    remote: RemoteKey
    ingress_geo: GeoDecision
    catalog_rank: int


_FIXED_PIN_IPS: frozenset[str] = frozenset({"119.105.93.237", "126.234.242.57"})
_PROTOCOL_QUOTA = 20
_SCAN_WINDOW = 40


def _to_ip_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


_PREFLIGHT_TIMEOUT_S = 3.0


def tcp_reachable(key: RemoteKey, timeout_s: float = _PREFLIGHT_TIMEOUT_S) -> bool:
    """Bounded TCP connect check; UDP cannot be verified and is never filtered out.

    RemoteKey guarantees a globally routable IPv4 address. Only a connect is
    attempted: no data is sent and no response content is read or logged.
    """
    if key.protocol != "tcp":
        return True
    try:
        with socket.create_connection((key.ip, key.port), timeout=timeout_s):
            return True
    except OSError:
        return False


def screen_candidates(
    catalog: str,
    *,
    existing_pins: frozenset[str],
    geo_lookup: Callable[[str], GeoDecision],
    scan_window: int = 40,
    limit: int = 10,
    reachable: Callable[[RemoteKey], bool] | None = None,
) -> list[ScreenedCandidate]:
    """Return a deterministic shortlist of screened VPN Gate candidates."""
    if scan_window != _SCAN_WINDOW:
        raise ValueError("Stage 1 scan_window must be 40")
    if not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")

    excluded_ips = _FIXED_PIN_IPS | existing_pins
    candidates = parse_catalog(catalog, country="JP")

    parsed: list[tuple[int, Candidate, RemoteKey]] = []
    seen_keys: set[RemoteKey] = set()
    for catalog_rank, candidate in enumerate(candidates, start=1):
        if candidate.ip in excluded_ips:
            continue
        try:
            endpoint = convert_ovpn(candidate.profile, expected_ip=candidate.ip)
        except (ValueError, KeyError, TypeError, UnicodeError):
            continue
        ip = endpoint.get("server")
        port = endpoint.get("server_port")
        network = endpoint.get("network")
        if not isinstance(ip, str) or not isinstance(port, int) or network not in ("tcp", "udp"):
            continue
        try:
            key = RemoteKey(ip=ip, port=port, protocol=network)
        except ValueError:
            continue
        if key in seen_keys:
            continue
        seen_keys.add(key)
        parsed.append((catalog_rank, candidate, key))

    tcp_window: list[tuple[int, Candidate, RemoteKey]] = []
    udp_window: list[tuple[int, Candidate, RemoteKey]] = []
    for catalog_rank, candidate, key in parsed:
        if key.protocol == "tcp" and len(tcp_window) < _PROTOCOL_QUOTA:
            tcp_window.append((catalog_rank, candidate, key))
        elif key.protocol == "udp" and len(udp_window) < _PROTOCOL_QUOTA:
            udp_window.append((catalog_rank, candidate, key))
        if len(tcp_window) >= _PROTOCOL_QUOTA and len(udp_window) >= _PROTOCOL_QUOTA:
            break

    selected_keys: set[RemoteKey] = {key for _, _, key in tcp_window + udp_window}
    window = list(tcp_window + udp_window)
    window.sort(key=lambda item: item[0])

    for catalog_rank, candidate, key in parsed:
        if len(window) >= scan_window:
            break
        if key in selected_keys:
            continue
        window.append((catalog_rank, candidate, key))
        selected_keys.add(key)
    window.sort(key=lambda item: item[0])

    geo_cache: dict[str, GeoDecision] = {}

    def get_geo(ip: str) -> GeoDecision:
        if ip not in geo_cache:
            geo_cache[ip] = geo_lookup(ip)
        return geo_cache[ip]

    ip_occurrence: dict[str, int] = {}
    entries: list[tuple[tuple[int, int, int, int, int, str], ScreenedCandidate]] = []
    for catalog_rank, candidate, key in window:
        round_index = ip_occurrence.get(key.ip, 0)
        ip_occurrence[key.ip] = round_index + 1
        geo_rank = get_geo(key.ip).value
        sort_key = (
            round_index,
            geo_rank,
            catalog_rank,
            _to_ip_int(key.ip),
            key.port,
            key.protocol,
        )
        entries.append((sort_key, ScreenedCandidate(
            candidate=candidate,
            remote=key,
            ingress_geo=geo_cache[key.ip],
            catalog_rank=catalog_rank,
        )))

    entries.sort(key=lambda item: item[0])
    if reachable is None:
        return [entry[1] for entry in entries[:limit]]
    # Pre-flight stays inside the fixed scan window and keeps its ranking;
    # it is evaluated lazily and stops once `limit` reachable candidates exist.
    selected: list[ScreenedCandidate] = []
    for _, screened in entries:
        if reachable(screened.remote):
            selected.append(screened)
            if len(selected) >= limit:
                break
    return selected


# probe_candidates is re-exported from openvpn_probe.


@dataclass(frozen=True, slots=True)
class CandidateDiagnostic:
    index: int
    status: str
    phase: str
    elapsed_ms: int
    cleanup_status: str
    reason_code: str
    protocol: str
    openvpn_progress: str
    openvpn_process_state: str
    link_io: str


@dataclass(frozen=True, slots=True)
class ProbeSummary:
    status: str
    tested_count: int = 0
    tokyo_confirmed_count: int = 0
    witness_ingress: str | None = None
    witness_exit: str | None = None
    reason_codes: tuple[str, ...] = ()
    candidate_diagnostics: tuple[CandidateDiagnostic, ...] = ()


class _SummaryParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse normally echoes untrusted argument values to stderr.
        raise ValueError("invalid_arguments")


def _summarize_results(results: list[ProbeResult]) -> ProbeSummary:
    status = aggregate_status(result.status for result in results)
    confirmed = [result for result in results if result.status == ProbeStatus.PASS]
    witness = next(iter(confirmed), None) if status == ProbeStatus.PASS else None
    return ProbeSummary(
        status.value,
        len(results),
        len(confirmed),
        f"{witness.ingress_ip}:{witness.port}/{witness.protocol}" if witness else None,
        witness.exit_ip if witness else None,
        tuple(sorted({result.reason_code for result in results})),
        tuple(CandidateDiagnostic(
            index=index, status=result.status.value,
            phase=result.phase, elapsed_ms=result.elapsed_ms,
            cleanup_status=result.cleanup_status,
            reason_code=result.reason_code,
            protocol=result.protocol if result.protocol in ("tcp", "udp") else "unknown",
            openvpn_progress=(
                result.openvpn_progress if type(result.openvpn_progress) is str
                and result.openvpn_progress in OPENVPN_PROGRESS_CODES else "not_observed"
            ),
            openvpn_process_state=(
                result.openvpn_process_state if type(result.openvpn_process_state) is str
                and result.openvpn_process_state in PROCESS_STATES else "not_started"
            ),
            link_io=(
                result.link_io if type(result.link_io) is str
                and result.link_io in LINK_IO_CODES else "not_observed"
            ),
        ) for index, result in enumerate(results, start=1)),
    )


def _run_pipeline(args: argparse.Namespace) -> ProbeSummary:
    if any(name in os.environ for name in ("VPN_ORBIT_USERNAME", "VPN_ORBIT_PASSWORD")):
        return ProbeSummary("BLOCKED", reason_codes=("environment_secret_inheritance_rejected",))
    if not os.environ.get("IPAPI_IS_API_KEY", "").strip():
        return ProbeSummary("BLOCKED", reason_codes=("geoip_api_key_missing",))
    try:
        api_key = os.environ["IPAPI_IS_API_KEY"]

        def geo_lookup(ip: str) -> GeoDecision:
            return lookup_geoip(ip, api_key=api_key)

        candidates = screen_candidates(
            fetch_catalog(), existing_pins=frozenset(), geo_lookup=geo_lookup,
            scan_window=args.scan_window, limit=args.limit,
            reachable=tcp_reachable,
        )
        results = probe_candidates(
            candidates, geo_lookup=geo_lookup, timeout_s=args.timeout_seconds,
        )
        return _summarize_results(results)
    except (OSError, UnicodeError, ValueError):
        return ProbeSummary("NOT_VERIFIED", reason_codes=("input_unavailable",))
    except Exception:  # noqa: BLE001 -- CLI boundary must never expose profiles or secrets
        return ProbeSummary("FAIL", reason_codes=("execution_failed",))


def main(argv: list[str] | None = None) -> int:
    """Run the bounded feasibility check, emitting one redacted JSON object only."""
    parser = _SummaryParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--scan-window", type=int, default=40, choices=(40,))
    parser.add_argument("--limit", type=int, default=10, choices=range(1, 11))
    parser.add_argument("--timeout-seconds", type=int, default=60, choices=range(1, 61))
    try:
        args = parser.parse_args(argv)
    except ValueError:
        summary = ProbeSummary("BLOCKED", reason_codes=("invalid_arguments",))
    else:
        summary = _run_pipeline(args)
    print(json.dumps(asdict(summary), separators=(",", ":")))
    return int(summary.status != ProbeStatus.PASS.value)


if __name__ == "__main__":
    raise SystemExit(main())
