"""Cloud candidate screening: VPN Gate catalog -> ranked shortlist.

Implements F-001 selection order, fixed-IP exclusion, RemoteKey deduplication,
TCP/UDP windowing, per-IP GeoIP caching, deterministic ranking, and workflow
status aggregation.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Iterable, Literal

from .geoip import GeoDecision
from .openvpn_probe import ProbeResult, ProbeStatus, probe_candidates, probe_one
from .phase1 import Candidate, convert_ovpn, parse_catalog


__all__ = [
    "aggregate_status",
    "RemoteKey",
    "ScreenedCandidate",
    "screen_candidates",
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
_MAX_SCAN_WINDOW = 1000


def _to_ip_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def screen_candidates(
    catalog: str,
    *,
    existing_pins: frozenset[str],
    geo_lookup: Callable[[str], GeoDecision],
    scan_window: int = 40,
    limit: int = 10,
) -> list[ScreenedCandidate]:
    """Return a deterministic shortlist of screened VPN Gate candidates."""
    if not 1 <= scan_window <= _MAX_SCAN_WINDOW:
        raise ValueError(f"scan_window must be between 1 and {_MAX_SCAN_WINDOW}")
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
    return [entry[1] for entry in entries[:limit]]


# probe_candidates is re-exported from openvpn_probe.
