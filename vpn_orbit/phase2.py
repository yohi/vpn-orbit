"""Phase 2: generate a native OpenVPN multi-remote sing-box profile.

Offline translation only. No VPN connection, remote profile update, or iOS daemon.
Multiple OpenVPN remotes share a TLS configuration: default grouping MUST retain
identical CA and settings, or fail closed. An explicit experimental CA-union
mode permits distinct trust roots but does not pin a root to an individual IP.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

from .phase1 import (
    Candidate, MAX_PROFILE, UnsupportedProfile, build_config, convert_ovpn,
    fetch_catalog, parse_catalog,
)


@dataclass(frozen=True)
class Rejection:
    source: str
    reason: str


@dataclass(frozen=True)
class Selection:
    endpoint: dict
    accepted: tuple[str, ...]
    rejected: tuple[Rejection, ...]
    ca_union: bool


def _compatible(base: dict, other: dict, allow_ca_union: bool) -> tuple[bool, str]:
    """All settings beyond the remote must match; never weaken TLS checks."""
    base_tls = copy.deepcopy(base.get("tls", {}))
    other_tls = copy.deepcopy(other.get("tls", {}))
    base_certs = base_tls.pop("certificate", None)
    other_certs = other_tls.pop("certificate", None)
    if base_tls != other_tls:
        return False, "TLS settings differ (including server identity/control-wrap)"
    if not allow_ca_union and base_certs != other_certs:
        return False, "CA certificate differs; requires explicit --allow-ca-union"
    keys = set(base) | set(other)
    keys.difference_update({"tag", "server", "server_port", "network", "tls"})
    for key in sorted(keys):
        if base.get(key) != other.get(key):
            return False, f"OpenVPN setting differs: {key}"
    return True, ""


def merge_profiles(
    inputs: Sequence[tuple[str, str]],
    *,
    max_servers: int = 5,
    allow_ca_union: bool = False,
) -> Selection:
    """Select compatible independent remotes, preserving order and all TLS gates.

    The first *valid* source is the reference for exact compatibility.
    Different CA roots are only merged on explicit, experimental opt-in.
    """
    if not 2 <= max_servers <= 20:
        raise ValueError("max_servers must be between 2 and 20")
    if len(inputs) < 2:
        raise UnsupportedProfile("at least two source profiles are required")
    parsed: list[tuple[str, dict]] = []
    rejected: list[Rejection] = []
    for source, raw in inputs:
        try:
            endpoint = convert_ovpn(raw)
        except (UnsupportedProfile, ValueError, UnicodeError) as exc:
            rejected.append(Rejection(source, f"invalid profile: {exc}"))
            continue
        parsed.append((source, endpoint))
    # The first ranked candidate may be an outlier. Prefer the largest compatible
    # group; break ties by the original source order. All group members still
    # preserve the original (ping-ranked) ordering.
    chosen_indices: list[int] = []
    for i, (_source, reference) in enumerate(parsed):
        cluster = []
        cluster_ips: set[str] = set()
        for j, (_label, candidate) in enumerate(parsed):
            if candidate["server"] not in cluster_ips and _compatible(reference, candidate, allow_ca_union)[0]:
                cluster.append(j)
                cluster_ips.add(candidate["server"])
        if len(cluster) > len(chosen_indices):
            chosen_indices = cluster
        if len(chosen_indices) == len(parsed):
            break
    chosen_indices = chosen_indices[:max_servers]
    if chosen_indices:
        reference = parsed[chosen_indices[0]][1]
        chosen_set = set(chosen_indices)
        for i, (source, candidate) in enumerate(parsed):
            if i not in chosen_set:
                reason = _compatible(reference, candidate, allow_ca_union)[1]
                if candidate["server"] in {parsed[j][1]["server"] for j in chosen_indices}:
                    reason = "duplicate public IPv4 server"
                rejected.append(Rejection(source, reason or "max_servers capacity reached"))
    endpoints = [parsed[i][1] for i in chosen_indices]
    accepted = [parsed[i][0] for i in chosen_indices]
    merged_ca: list[str] = []
    for endpoint in endpoints:
        for cert in endpoint["tls"]["certificate"]:
            if cert not in merged_ca:
                merged_ca.append(cert)
        if len(merged_ca) > 20:
            raise UnsupportedProfile("too many CA certificate bundles")
    if len(endpoints) < 2:
        reasons = Counter(r.reason for r in rejected)
        detail = "; ".join(f"{reason} ({count})" for reason, count in reasons.most_common(3))
        raise UnsupportedProfile(f"fewer than two compatible distinct servers; {detail or 'no eligible profiles'}")
    output = copy.deepcopy(endpoints[0])
    output.pop("server", None)
    output.pop("server_port", None)
    output.pop("network", None)
    output["servers"] = [
        {"server": e["server"], "server_port": e["server_port"], "network": e["network"]}
        for e in endpoints
    ]
    # Never output a fallback 'direct' outbound or a non-VPN DNS detour.
    output["tls"]["certificate"] = merged_ca
    output["ping_interval"] = "10s"
    output["ping_restart"] = "40s"
    output["block_ipv6"] = True
    return Selection(
        endpoint=output,
        accepted=tuple(accepted),
        rejected=tuple(rejected),
        ca_union=len(merged_ca) > 1,
    )


def read_source(path: Path) -> str:
    if path.stat().st_size > MAX_PROFILE:
        raise UnsupportedProfile("profile too large")
    return path.read_text(encoding="utf-8-sig")


def write_config(path: Path, config: dict) -> None:
    import os
    content = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 2 native OpenVPN multi-server retry profile (iOS runtime unverified)"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--ovpn", type=Path, action="append", nargs="+", help="2+ local .ovpn profiles")
    source.add_argument("--from-vpngate", action="store_true", help="fetch Japanese VPN Gate catalog")
    parser.add_argument("--max-servers", type=int, default=5, help="distinct eligible remotes, 2-20 (default 5)")
    parser.add_argument("--allow-ca-union", action="store_true", help="EXPERIMENTAL: trust CA roots across distinct remotes")
    parser.add_argument("--output", type=Path, required=True, help="new JSON path, 0600, overwrite forbidden")
    args = parser.parse_args(argv)
    try:
        if args.ovpn:
            paths = [p for group in args.ovpn for p in group]
            inputs = [(p.name, read_source(p)) for p in paths]
        else:
            candidates: list[Candidate] = parse_catalog(fetch_catalog())
            inputs = [(f"{c.host} ({c.ip})", c.profile) for c in candidates]
        selection = merge_profiles(
            inputs, max_servers=args.max_servers,
            allow_ca_union=args.allow_ca_union,
        )
        if selection.ca_union:
            print("WARNING: multiple CA roots are trusted by every server; no per-IP CA pinning", file=sys.stderr)
        write_config(args.output, build_config(selection.endpoint))
        print(f"Created {args.output} (0600), remotes={len(selection.accepted)}", file=sys.stderr)
        for label in selection.accepted:
            print(f"  ACCEPT {label}", file=sys.stderr)
        for rejected in selection.rejected[:12]:
            print(f"  SKIP {rejected.source}: {rejected.reason}", file=sys.stderr)
        print("NOT VERIFIED: actual sing-box MT failover, geo-IP, or leak prevention", file=sys.stderr)
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
