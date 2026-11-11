"""Offline .ovpn -> sing-box 1.14+ profile; optional official VPN Gate CSV source.

This module never executes imported OpenVPN directives and does not connect to VPNs.
It deliberately rejects configurations it cannot translate safely.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import ssl
import sys
from urllib.request import Request, urlopen

API_URL = "https://www.vpngate.net/api/iphone/"
MAX_CATALOG = 32 * 1024 * 1024
MAX_PROFILE = 128 * 1024
MAX_CANDIDATES = 1000
CIPHERS = {"AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM"}
AUTHS = {"SHA1", "SHA256", "SHA384", "SHA512"}
IGNORABLE = {
    "client", "dev", "dev-type", "nobind", "persist-key", "persist-tun",
    "resolv-retry", "verb", "mute", "remote-random", "remote-random-hostname",
    "connect-retry", "connect-retry-max", "server-poll-timeout",
    "ping", "ping-restart", "ping-timer-rem", "explicit-exit-notify",
    "reneg-sec", "sndbuf", "rcvbuf", "auth-nocache", "route-delay",
    "setenv", "setenv-safe", "pull", "tls-client", "remote-cert-eku",
}
PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END CERTIFICATE-----", re.S)
BLOCK = re.compile(r"(?m)^<([a-z][a-z0-9-]*)>\s*$([\s\S]*?)^</\1>\s*$")

class UnsupportedProfile(ValueError):
    """Configuration is unsupported and must not be silently weakened."""

@dataclass(frozen=True)
class Candidate:
    host: str
    ip: str
    country: str
    ping_ms: int
    speed_bps: int
    score: int
    profile: str


def require_global_ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsupportedProfile("remote must be a literal public IPv4 address") from exc
    if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
        raise UnsupportedProfile("remote must be a globally routable IPv4 address")
    return str(ip)


def fetch_catalog() -> str:
    request = Request(API_URL, headers={"User-Agent": "vpn-orbit-phase1/0.1", "Accept": "text/plain"})
    with urlopen(request, timeout=15) as response:
        if response.geturl().split("?", 1)[0] != API_URL:
            raise ValueError("unexpected redirect from official API")
        content = response.read(MAX_CATALOG + 1)
    if len(content) > MAX_CATALOG:
        raise ValueError("VPN Gate CSV exceeds size limit")
    return content.decode("utf-8-sig")


def parse_catalog(data: str, country: str = "JP") -> list[Candidate]:
    header = next((index for index, line in enumerate(data.splitlines()) if line.startswith("#HostName,") or line.startswith("HostName,")), None)
    if header is None:
        raise ValueError("VPN Gate CSV header not found")
    lines = data.splitlines()[header:]
    lines[0] = lines[0].removeprefix("#")
    reader = csv.DictReader(lines)
    if not {"HostName", "IP", "CountryShort", "Ping", "Speed", "Score", "OpenVPN_ConfigData_Base64"}.issubset(reader.fieldnames or ()):
        raise ValueError("VPN Gate CSV missing required columns")
    candidates = []
    for row in reader:
        if (row.get("CountryShort") or "").upper() != country:
            continue
        try:
            ip = require_global_ipv4(row["IP"])
            encoded = row["OpenVPN_ConfigData_Base64"]
            if not encoded or len(encoded) > MAX_PROFILE * 2:
                continue
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > MAX_PROFILE:
                continue
            profile = raw.decode("utf-8-sig")
            # Strictly validate the entire config, not only CSV metadata.
            convert_ovpn(profile, expected_ip=ip)
            candidates.append(Candidate(
                host=row["HostName"], ip=ip, country=country,
                ping_ms=int(row["Ping"]), speed_bps=int(row["Speed"]),
                score=int(row["Score"]), profile=profile,
            ))
        except (ValueError, KeyError, TypeError, UnicodeError, UnsupportedProfile):
            continue
        if len(candidates) >= MAX_CANDIDATES:
            break
    candidates.sort(key=lambda c: (c.ping_ms if c.ping_ms > 0 else 9999, -c.speed_bps, -c.score, c.ip))
    return candidates


def _one(directives: dict[str, list[list[str]]], name: str, default: list[str] | None = None) -> list[str] | None:
    values = directives.get(name, [])
    if len(values) > 1:
        raise UnsupportedProfile(f"multiple {name} directives")
    return values[0] if values else default


def _ca_pem(contents: str) -> str:
    certs = PEM_CERT.findall(contents.strip())
    if not certs or len(certs) > 6 or PEM_CERT.sub("", contents).strip():
        raise UnsupportedProfile("inline CA must contain only PEM certificates")
    for encoded in certs:
        try:
            ssl.PEM_cert_to_DER_cert("-----BEGIN CERTIFICATE-----\n" + encoded.strip() + "\n-----END CERTIFICATE-----")
        except ValueError as exc:
            raise UnsupportedProfile("malformed CA PEM") from exc
    return contents.strip() + "\n"


def _static_key(contents: str) -> str:
    body = contents.strip()
    match = re.fullmatch(r"-----BEGIN OpenVPN Static key V1-----\s+([0-9a-fA-F\s]+?)\s+-----END OpenVPN Static key V1-----", body, re.S)
    if not match or len(re.sub(r"\s+", "", match.group(1))) != 512:
        raise UnsupportedProfile("invalid inline tls-auth/tls-crypt key")
    return body + "\n"


def convert_ovpn(profile: str, *, expected_ip: str | None = None) -> dict:
    if len(profile.encode("utf-8")) > MAX_PROFILE:
        raise UnsupportedProfile("OpenVPN profile exceeds size limit")
    blocks: dict[str, str] = {}
    def pull_block(m: re.Match) -> str:
        name = m.group(1).lower()
        if name in blocks or name not in {"ca", "tls-auth", "tls-crypt"}:
            raise UnsupportedProfile(f"unsupported/duplicate inline block: {name}")
        blocks[name] = m.group(2)
        return "\n"
    stripped = BLOCK.sub(pull_block, profile)
    if re.search(r"(?m)^\s*</?\w", stripped):
        raise UnsupportedProfile("malformed or unrecognized inline section")
    directives: dict[str, list[list[str]]] = {}
    for raw in stripped.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        tokens = line.split()
        name = tokens[0].lower()
        if name not in IGNORABLE | {
            "proto", "remote", "cipher", "data-ciphers", "data-ciphers-fallback",
            "auth", "auth-user-pass", "key-direction", "remote-cert-tls", "verify-x509-name",
            "tls-auth", "tls-crypt",
        }:
            raise UnsupportedProfile(f"unhandled OpenVPN directive: {name}")
        directives.setdefault(name, []).append(tokens[1:])
    remote = _one(directives, "remote")
    if remote is None or len(remote) not in (2, 3):
        raise UnsupportedProfile("one remote IP and port are required")
    ip = require_global_ipv4(remote[0])
    if expected_ip and require_global_ipv4(expected_ip) != ip:
        raise UnsupportedProfile("profile remote differs from catalog IP")
    try:
        port = int(remote[1])
    except ValueError as exc:
        raise UnsupportedProfile("invalid remote port") from exc
    if not 1 <= port <= 65535:
        raise UnsupportedProfile("invalid remote port")
    proto = _one(directives, "proto", ["udp"])
    if len(proto) != 1:
        raise UnsupportedProfile("invalid proto")
    protocol = proto[0].lower()
    if len(remote) == 3:
        protocol = remote[2].lower()
    if protocol not in {"udp", "udp4", "tcp", "tcp-client", "tcp4", "tcp4-client"}:
        raise UnsupportedProfile("unsupported proto")
    network = "udp" if protocol.startswith("udp") else "tcp"
    if "ca" not in blocks:
        raise UnsupportedProfile("inline <ca> required (external trust paths not accepted)")
    tls = {"certificate": [_ca_pem(blocks["ca"])], "remote_certificate_tls": "server"}
    cert_name = _one(directives, "verify-x509-name")
    if cert_name:
        if not 1 <= len(cert_name) <= 2 or len(cert_name[0]) > 256:
            raise UnsupportedProfile("invalid verify-x509-name")
        name_type = cert_name[1] if len(cert_name) == 2 else "name"
        if name_type not in {"name", "subject", "name-prefix"}:
            raise UnsupportedProfile("unsupported verify-x509-name type")
        tls.update({"server_name": cert_name[0], "server_name_type": name_type})
    remote_cert = _one(directives, "remote-cert-tls")
    if remote_cert is not None and remote_cert != ["server"]:
        raise UnsupportedProfile("expected remote-cert-tls server")
    if "tls-auth" in blocks and "tls-crypt" in blocks:
        raise UnsupportedProfile("multiple TLS wraps")
    for key in ("tls-auth", "tls-crypt"):
        if key in directives and key not in blocks:
            # External file paths are never read.
            raise UnsupportedProfile(f"external {key} file not supported")
    for wrap in ("tls-auth", "tls-crypt"):
        if wrap in blocks:
            ctl = {"type": "tls_auth" if wrap == "tls-auth" else "tls_crypt", "key": _static_key(blocks[wrap])}
            if wrap == "tls-auth":
                direction = _one(directives, "key-direction")
                if direction:
                    if direction != ["1"]:
                        raise UnsupportedProfile("only client tls-auth key-direction 1 supported")
                    ctl["direction"] = "client"
            elif "key-direction" in directives:
                raise UnsupportedProfile("key-direction must not accompany tls-crypt")
            tls["control_wrap"] = ctl
    if "key-direction" in directives and "tls-auth" not in blocks:
        raise UnsupportedProfile("orphan key-direction")
    cipher = _one(directives, "cipher", ["AES-128-CBC"])
    if len(cipher) != 1 or cipher[0].upper() not in CIPHERS:
        raise UnsupportedProfile("unsupported cipher")
    cipher_name = cipher[0].upper()
    data_ciphers = _one(directives, "data-ciphers")
    if data_ciphers:
        if len(data_ciphers) != 1:
            raise UnsupportedProfile("invalid data-ciphers")
        allowed = data_ciphers[0].upper().split(":")
        if not allowed or any(c not in CIPHERS for c in allowed):
            raise UnsupportedProfile("unsupported data-ciphers")
    else:
        allowed = ["AES-256-GCM", "AES-128-GCM", cipher_name]
    fallback = _one(directives, "data-ciphers-fallback", [cipher_name])
    if len(fallback) != 1 or fallback[0].upper() not in CIPHERS:
        raise UnsupportedProfile("unsupported data-ciphers-fallback")
    auth = _one(directives, "auth", ["SHA1"])
    if len(auth) != 1 or auth[0].upper() not in AUTHS:
        raise UnsupportedProfile("unsupported auth")
    user_pass = _one(directives, "auth-user-pass")
    if user_pass is not None and user_pass:
        raise UnsupportedProfile("external credential files are not allowed")
    endpoint = {
        "type": "openvpn-client", "tag": "vpn-gate", "mode": "tls",
        "server": ip, "server_port": port, "network": network,
        "tls": tls, "data_ciphers": list(dict.fromkeys(allowed)),
        "data_ciphers_fallback": fallback[0].upper(), "auth": auth[0].upper(),
        "ping_interval": "10s", "ping_restart": "40s",
    }
    if user_pass is not None:
        endpoint["username"] = os.getenv("VPN_ORBIT_USERNAME", "vpn")
        endpoint["password"] = os.getenv("VPN_ORBIT_PASSWORD", "vpn")
    return endpoint


def build_config(endpoint: dict) -> dict:
    """Full single-VPN candidate config for a *manual* sing-box MT Phase 1 test."""
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{"type": "udp", "tag": "vpn-dns", "server": "1.1.1.1", "server_port": 53, "detour": "vpn-gate"}],
            "final": "vpn-dns",
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.28.250.1/30"],
                      "auto_route": True, "dns_mode": "hijack", "mtu": 1400}],
        "endpoints": [endpoint],
        "route": {"rules": [{"protocol": "dns", "action": "hijack-dns"}], "final": "vpn-gate"},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert one VPN Gate OpenVPN profile to a sing-box MT JSON (Phase 1)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--ovpn", type=Path, help="local .ovpn file; no network needed")
    source.add_argument("--from-vpngate", action="store_true", help="fetch JP candidates from official API")
    parser.add_argument("--index", type=int, default=1, help="1-based candidate index, API mode only")
    parser.add_argument("--list", action="store_true", help="list API candidates, do not generate config")
    parser.add_argument("--output", type=Path, help="write JSON (0600); otherwise print to stdout")
    args = parser.parse_args(argv)
    if args.index < 1 or (args.ovpn and (args.index != 1 or args.list)):
        parser.error("invalid --index/--list for selected input")
    try:
        if args.ovpn:
            if args.ovpn.stat().st_size > MAX_PROFILE:
                raise UnsupportedProfile("file too large")
            profile = args.ovpn.read_text(encoding="utf-8-sig")
        else:
            options = parse_catalog(fetch_catalog())
            if not options:
                raise UnsupportedProfile("no compatible JP candidates in current API response")
            if args.list:
                for i, c in enumerate(options[:20], 1):
                    print(f"{i:2d} {c.host} {c.ip} ping={c.ping_ms}ms speed={c.speed_bps // 1000000}Mbps")
                print("Country=JP only; Tokyo GeoIP status NOT verified", file=sys.stderr)
                return 0
            if args.index > len(options):
                raise UnsupportedProfile(f"candidate index {args.index} not available")
            profile = options[args.index - 1].profile
        content = json.dumps(build_config(convert_ovpn(profile)), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(args.output, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(content)
            print(f"Created: {args.output} (0600)", file=sys.stderr)
        else:
            print(content, end="")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
