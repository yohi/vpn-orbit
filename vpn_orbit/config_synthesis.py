"""Synthesize a locked-down OpenVPN CLI config from a sing-box Endpoint dict.

The generated config references only files under a private directory and uses
an allowlisted directive mapping. Raw untrusted ``.ovpn`` files are never
passed to ``openvpn --config``.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

from .phase1 import UnsupportedProfile

_ALLOWED_ENDPOINT_KEYS: frozenset[str] = frozenset({
    "type", "tag", "mode", "server", "server_port", "network",
    "tls", "data_ciphers", "data_ciphers_fallback", "auth",
    "block_ipv6", "ping_interval", "ping_restart", "username", "password",
})
_ALLOWED_TLS_KEYS: frozenset[str] = frozenset({
    "certificate", "remote_certificate_tls", "remote_certificate_eku",
    "client_certificate", "client_key", "server_name", "server_name_type", "control_wrap",
})
_ALLOWED_WRAP_KEYS: frozenset[str] = frozenset({"type", "key", "direction"})


def _reject_env_secrets() -> None:
    if os.getenv("VPN_ORBIT_USERNAME") is not None or os.getenv("VPN_ORBIT_PASSWORD") is not None:
        raise UnsupportedProfile("refusing to inherit VPN_ORBIT_USERNAME/PASSWORD from environment")


def _write_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


def _spki_match(cert_pem: bytes, key_pem: bytes) -> tuple[bool, str]:
    """Compare the public keys of a cert and a private key using OpenSSL."""
    try:
        cert_pub = subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout"],
            input=cert_pem,
            capture_output=True,
            check=True,
        ).stdout
        pub_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=cert_pub,
            capture_output=True,
            check=True,
        ).stdout
        key_der = subprocess.run(
            ["openssl", "pkey", "-pubout", "-outform", "DER"],
            input=key_pem,
            capture_output=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return False, "SPKI comparison failed"
    return pub_der == key_der, ""


def _quote_word(value: str) -> str:
    """Return a double-quoted word if it contains whitespace or quotes."""
    if re.search(r'[\s"]', value):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def synthesize_openvpn_config(
    parsed_endpoint: dict[str, Any],
    *,
    remote_ip: str,
    port: int,
    protocol: str,
    private_dir: Path,
) -> bytes:
    """Generate a locked-down OpenVPN CLI config from a sing-box Endpoint dict.

    Files are written under ``private_dir`` (expected to already exist with
    mode 0700) with mode 0600. The returned bytes are the generated config;
    raw untrusted ``.ovpn`` files are never referenced via ``--config``.
    """
    _reject_env_secrets()

    if not isinstance(parsed_endpoint, dict):
        raise UnsupportedProfile("endpoint must be a dict")

    unknown_keys = set(parsed_endpoint) - _ALLOWED_ENDPOINT_KEYS
    if unknown_keys:
        raise UnsupportedProfile(f"unknown endpoint keys: {sorted(unknown_keys)}")

    if parsed_endpoint.get("type") != "openvpn-client":
        raise UnsupportedProfile("only openvpn-client endpoints are supported")

    if protocol not in ("tcp", "udp"):
        raise UnsupportedProfile(f"unsupported probe protocol: {protocol}")
    if parsed_endpoint.get("network") not in ("tcp", "udp"):
        raise UnsupportedProfile("endpoint network must be tcp or udp")
    if parsed_endpoint.get("network") != protocol:
        raise UnsupportedProfile("probe protocol does not match endpoint network")

    tls = parsed_endpoint.get("tls")
    if not isinstance(tls, dict):
        raise UnsupportedProfile("tls section missing")
    unknown_tls = set(tls) - _ALLOWED_TLS_KEYS
    if unknown_tls:
        raise UnsupportedProfile(f"unknown tls keys: {sorted(unknown_tls)}")

    ca_certs = tls.get("certificate")
    if not isinstance(ca_certs, list) or not ca_certs or not isinstance(ca_certs[0], str):
        raise UnsupportedProfile("CA certificate missing")
    ca_pem = ca_certs[0].encode()

    cert_pem: bytes | None = None
    key_pem: bytes | None = None
    client_cert = tls.get("client_certificate")
    client_key = tls.get("client_key")
    if (client_cert is None) != (client_key is None):
        raise UnsupportedProfile("client certificate and key must be paired")
    if client_cert is not None:
        if not isinstance(client_cert, list) or not client_cert or not isinstance(client_cert[0], str):
            raise UnsupportedProfile("client certificate missing")
        if not isinstance(client_key, list) or not client_key or not isinstance(client_key[0], str):
            raise UnsupportedProfile("client key missing")
        cert_pem = client_cert[0].encode()
        key_pem = client_key[0].encode()
        matched, reason = _spki_match(cert_pem, key_pem)
        if not matched:
            raise UnsupportedProfile(f"client identity SPKI mismatch: {reason}")

    remote_cert_tls = tls.get("remote_certificate_tls")
    remote_cert_eku = tls.get("remote_certificate_eku")
    if remote_cert_eku and remote_cert_tls:
        raise UnsupportedProfile("remote-cert-tls and remote-cert-eku are mutually exclusive")

    server_name = tls.get("server_name")
    server_name_type = tls.get("server_name_type", "name")
    if server_name is not None and server_name_type not in ("name", "subject", "name-prefix"):
        raise UnsupportedProfile("unsupported verify-x509-name type")

    wrap = tls.get("control_wrap")
    wrap_path: str | None = None
    wrap_direction: str | None = None
    if wrap is not None:
        if not isinstance(wrap, dict):
            raise UnsupportedProfile("control_wrap must be a dict")
        unknown_wrap = set(wrap) - _ALLOWED_WRAP_KEYS
        if unknown_wrap:
            raise UnsupportedProfile(f"unknown control_wrap keys: {sorted(unknown_wrap)}")
        wrap_type = wrap.get("type")
        key_material = wrap.get("key")
        if not isinstance(key_material, str) or not key_material:
            raise UnsupportedProfile("control_wrap key missing")
        if wrap_type == "tls_auth":
            wrap_path = "tls-auth.key"
            direction = wrap.get("direction")
            if direction is not None:
                if direction == "client":
                    wrap_direction = "1"
                elif direction == "server":
                    wrap_direction = "0"
                else:
                    raise UnsupportedProfile(f"unknown tls-auth direction: {direction}")
        elif wrap_type == "tls_crypt":
            if wrap.get("direction") is not None:
                raise UnsupportedProfile("tls-crypt must not have a direction")
            wrap_path = "tls-crypt.key"
        else:
            raise UnsupportedProfile(f"unsupported control_wrap type: {wrap_type}")

    username = parsed_endpoint.get("username")
    password = parsed_endpoint.get("password")
    if (username is None) != (password is None):
        raise UnsupportedProfile("username and password must be paired")

    data_ciphers = parsed_endpoint.get("data_ciphers", [])
    if not isinstance(data_ciphers, list) or not data_ciphers:
        raise UnsupportedProfile("data_ciphers missing")
    fallback = parsed_endpoint.get("data_ciphers_fallback")
    auth = parsed_endpoint.get("auth")

    # Write files under private_dir.
    _write_private_file(private_dir / "ca.pem", ca_pem)
    if cert_pem is not None:
        _write_private_file(private_dir / "cert.pem", cert_pem)
        _write_private_file(private_dir / "key.pem", key_pem)
    if username is not None:
        _write_private_file(private_dir / "auth.txt", f"{username}\n{password}\n".encode())
    if wrap_path is not None:
        _write_private_file(private_dir / wrap_path, key_material.encode() + b"\n")

    # Build the CLI config from the allowlist only.
    lines: list[str] = [
        "client",
        "dev tun",
        "nobind",
        "persist-key",
        "persist-tun",
        "route-nopull",
        f"proto {'udp' if protocol == 'udp' else 'tcp-client'}",
        f"remote {remote_ip} {port}",
        "ca ca.pem",
    ]
    if cert_pem is not None:
        lines.extend(["cert cert.pem", "key key.pem"])
    if username is not None:
        lines.append("auth-user-pass auth.txt")
    if wrap_path is not None:
        directive_name = "tls-auth" if wrap_type == "tls_auth" else "tls-crypt"
        if wrap_direction is not None:
            lines.append(f"{directive_name} {wrap_path} {wrap_direction}")
        else:
            lines.append(f"{directive_name} {wrap_path}")
    if remote_cert_eku:
        lines.append(f"remote-cert-eku {_quote_word(remote_cert_eku)}")
    elif remote_cert_tls:
        lines.append(f"remote-cert-tls {remote_cert_tls}")
    if server_name is not None:
        lines.append(f"verify-x509-name {_quote_word(server_name)} {_quote_word(server_name_type)}")
    lines.append(f"data-ciphers {':'.join(data_ciphers)}")
    if fallback:
        lines.append(f"data-ciphers-fallback {fallback}")
    if auth:
        lines.append(f"auth {auth}")

    return ("\n".join(lines) + "\n").encode()
