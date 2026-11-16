"""Synthesize a locked-down OpenVPN CLI config from a sing-box Endpoint dict.

The generated config references only files under a private directory and uses
an allowlisted directive mapping. Raw untrusted ``.ovpn`` files are never
passed to ``openvpn --config``.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

from .config_validation import quote_word as _quote_word
from .config_validation import spki_match as _spki_match
from .config_validation import validate_pem as _validate_pem
from .phase1 import AUTHS, CIPHERS, UnsupportedProfile, require_global_ipv4
from .probe_commands import Commands

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


def _validated_identity(
    tls: dict[str, Any], commands: Commands | None,
) -> tuple[list[bytes], bytes | None, bytes | None]:
    ca_certs = tls.get("certificate")
    if not isinstance(ca_certs, list) or not ca_certs:
        raise UnsupportedProfile("CA certificate missing")
    validated_ca: list[bytes] = []
    for item in ca_certs:
        if not isinstance(item, str):
            raise UnsupportedProfile("CA certificate must be a string")
        _validate_pem(item, commands=commands)
        validated_ca.append(item.encode())

    client_cert = tls.get("client_certificate")
    client_key = tls.get("client_key")
    if (client_cert is None) != (client_key is None):
        raise UnsupportedProfile("client certificate and key must be paired")
    if client_cert is None:
        return validated_ca, None, None
    if (not isinstance(client_cert, list) or not client_cert
            or not isinstance(client_cert[0], str)):
        raise UnsupportedProfile("client certificate missing")
    if (not isinstance(client_key, list) or not client_key
            or not isinstance(client_key[0], str)):
        raise UnsupportedProfile("client key missing")
    cert_pem, key_pem = client_cert[0].encode(), client_key[0].encode()
    matched, reason = _spki_match(cert_pem, key_pem, commands=commands)
    if not matched:
        raise UnsupportedProfile(f"client identity SPKI mismatch: {reason}")
    return validated_ca, cert_pem, key_pem


def _validate_server_identity(tls: dict[str, Any]) -> tuple[str | None, str | None, str | None, str]:
    remote_cert_tls = tls.get("remote_certificate_tls")
    remote_cert_eku = tls.get("remote_certificate_eku")
    if remote_cert_eku and remote_cert_tls:
        raise UnsupportedProfile("remote-cert-tls and remote-cert-eku are mutually exclusive")
    if remote_cert_tls is not None and remote_cert_tls != "server":
        raise UnsupportedProfile("remote-cert-tls must be server")
    if remote_cert_tls is None and remote_cert_eku is None:
        raise UnsupportedProfile("server identity verification required")
    if remote_cert_eku is not None and remote_cert_eku not in (
        "TLS Web Server Authentication", "1.3.6.1.5.5.7.3.1",
    ):
        raise UnsupportedProfile("unsupported server EKU")

    server_name = tls.get("server_name")
    server_name_type = tls.get("server_name_type", "name")
    if server_name is not None and server_name_type not in ("name", "subject", "name-prefix"):
        raise UnsupportedProfile("unsupported verify-x509-name type")
    if server_name is not None:
        _quote_word(server_name)
    return remote_cert_tls, remote_cert_eku, server_name, server_name_type


def _validate_control_wrap(
    wrap: Any,
) -> tuple[str | None, str | None, str | None, str]:
    if wrap is None:
        return None, None, None, ""
    if not isinstance(wrap, dict):
        raise UnsupportedProfile("control_wrap must be a dict")
    unknown = set(wrap) - _ALLOWED_WRAP_KEYS
    if unknown:
        raise UnsupportedProfile(f"unknown control_wrap keys: {sorted(unknown)}")
    wrap_type, key_material = wrap.get("type"), wrap.get("key")
    if not isinstance(key_material, str) or not key_material:
        raise UnsupportedProfile("control_wrap key missing")
    if wrap_type == "tls_auth":
        direction = wrap.get("direction")
        if direction not in (None, "client", "server"):
            raise UnsupportedProfile(f"unknown tls-auth direction: {direction}")
        wrap_direction = "1" if direction == "client" else "0" if direction == "server" else None
        return "tls-auth.key", wrap_direction, wrap_type, key_material
    if wrap_type == "tls_crypt":
        if wrap.get("direction") is not None:
            raise UnsupportedProfile("tls-crypt must not have a direction")
        return "tls-crypt.key", None, wrap_type, key_material
    raise UnsupportedProfile(f"unsupported control_wrap type: {wrap_type}")


def _validated_crypto_options(
    endpoint: dict[str, Any],
) -> tuple[str | None, str | None, list[str], str, str]:
    username, password = endpoint.get("username"), endpoint.get("password")
    if (username is None) != (password is None):
        raise UnsupportedProfile("username and password must be paired")
    if username is not None and (username, password) != ("vpn", "vpn"):
        raise UnsupportedProfile("only public default credentials supported")
    data_ciphers = endpoint.get("data_ciphers", [])
    if not isinstance(data_ciphers, list) or not data_ciphers:
        raise UnsupportedProfile("data_ciphers missing")
    if any(not isinstance(cipher, str) or cipher not in CIPHERS for cipher in data_ciphers):
        raise UnsupportedProfile("unsupported data-ciphers")
    fallback = endpoint.get("data_ciphers_fallback")
    if not isinstance(fallback, str) or fallback not in CIPHERS:
        raise UnsupportedProfile("unsupported data-ciphers-fallback")
    auth = endpoint.get("auth")
    if not isinstance(auth, str) or auth not in AUTHS:
        raise UnsupportedProfile("unsupported auth")
    return username, password, data_ciphers, fallback, auth


def synthesize_openvpn_config(
    parsed_endpoint: dict[str, Any],
    *,
    remote_ip: str,
    port: int,
    protocol: str,
    private_dir: Path,
    commands: Commands | None = None,
) -> bytes:
    """Generate a locked-down OpenVPN CLI config from a sing-box Endpoint dict.

    Files are written under ``private_dir`` (expected to already exist with
    mode 0700) with mode 0600. The returned bytes are the generated config;
    raw untrusted ``.ovpn`` files are never referenced via ``--config``.

    The config uses absolute paths for file directives so the OpenVPN CWD is
    not security-critical.

    Live probes must supply the running supervisor's commands. Standalone calls
    without commands have bounded subprocesses, but no caller-SIGKILL guarantee.
    """
    _reject_env_secrets()

    if not isinstance(parsed_endpoint, dict):
        raise UnsupportedProfile("endpoint must be a dict")

    unknown_keys = set(parsed_endpoint) - _ALLOWED_ENDPOINT_KEYS
    if unknown_keys:
        raise UnsupportedProfile(f"unknown endpoint keys: {sorted(unknown_keys)}")

    if parsed_endpoint.get("type") != "openvpn-client":
        raise UnsupportedProfile("only openvpn-client endpoints are supported")
    require_global_ipv4(remote_ip)

    if protocol not in ("tcp", "udp"):
        raise UnsupportedProfile(f"unsupported probe protocol: {protocol}")
    if parsed_endpoint.get("network") not in ("tcp", "udp"):
        raise UnsupportedProfile("endpoint network must be tcp or udp")
    if parsed_endpoint.get("network") != protocol:
        raise UnsupportedProfile("probe protocol does not match endpoint network")

    endpoint_server = parsed_endpoint.get("server")
    endpoint_port = parsed_endpoint.get("server_port")
    if (endpoint_server != remote_ip or type(endpoint_port) is not int or
            endpoint_port != port or not 1 <= port <= 65535):
        raise UnsupportedProfile("synthesized remote does not match parsed endpoint")

    tls = parsed_endpoint.get("tls")
    if not isinstance(tls, dict):
        raise UnsupportedProfile("tls section missing")
    unknown_tls = set(tls) - _ALLOWED_TLS_KEYS
    if unknown_tls:
        raise UnsupportedProfile(f"unknown tls keys: {sorted(unknown_tls)}")

    validated_ca_certs, cert_pem, key_pem = _validated_identity(tls, commands)
    remote_cert_tls, remote_cert_eku, server_name, server_name_type = _validate_server_identity(tls)
    wrap_path, wrap_direction, wrap_type, key_material = _validate_control_wrap(tls.get("control_wrap"))
    username, password, data_ciphers, fallback, auth = _validated_crypto_options(parsed_endpoint)

    # Write files under private_dir.
    ca_path = private_dir / "ca.pem"
    _write_private_file(ca_path, b"\n".join(validated_ca_certs) + b"\n")
    cert_path = private_dir / "cert.pem"
    key_path = private_dir / "key.pem"
    if cert_pem is not None and key_pem is not None:
        _write_private_file(cert_path, cert_pem)
        _write_private_file(key_path, key_pem)
    auth_path = private_dir / "auth.txt"
    if username is not None:
        _write_private_file(auth_path, f"{username}\n{password}\n".encode())
    wrap_file_path: Path | None = None
    if wrap_path is not None:
        wrap_file_path = private_dir / wrap_path
        _write_private_file(wrap_file_path, key_material.encode() + b"\n")

    # Build the CLI config from the allowlist only, using absolute paths.
    def file_arg(name: str, path: Path) -> str:
        return f"{name} {shlex.quote(str(path))}"

    lines: list[str] = [
        "client",
        "dev tun0",
        "nobind",
        "persist-key",
        "persist-tun",
        "route-nopull",
        f"proto {'udp' if protocol == 'udp' else 'tcp-client'}",
        f"remote {remote_ip} {port}",
        file_arg("ca", ca_path),
    ]
    if cert_pem is not None:
        lines.extend([file_arg("cert", cert_path), file_arg("key", key_path)])
    if username is not None:
        lines.append(file_arg("auth-user-pass", auth_path))
    if wrap_file_path is not None:
        directive_name = "tls-auth" if wrap_type == "tls_auth" else "tls-crypt"
        if wrap_direction is not None:
            lines.append(f"{directive_name} {shlex.quote(str(wrap_file_path))} {wrap_direction}")
        else:
            lines.append(f"{directive_name} {shlex.quote(str(wrap_file_path))}")
    if remote_cert_eku:
        lines.append(f"remote-cert-eku {_quote_word(remote_cert_eku)}")
    elif remote_cert_tls:
        lines.append(f"remote-cert-tls {remote_cert_tls}")
    if server_name is not None:
        lines.append(f"verify-x509-name {_quote_word(server_name)} {_quote_word(server_name_type)}")
    lines.extend((
        f"data-ciphers {':'.join(data_ciphers)}",
        f"data-ciphers-fallback {fallback}",
        f"auth {auth}",
    ))

    return ("\n".join(lines) + "\n").encode()
