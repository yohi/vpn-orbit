"""Advisory OpenVPN failure categories. Never return raw, untrusted log data."""
from __future__ import annotations

import os
from pathlib import Path

MAX_LOG_TAIL = 64 * 1024
OPENVPN_DIAGNOSTIC_CODES = frozenset({
    "not_observed", "log_unavailable", "no_diagnostic_signal", "auth_failed",
    "tls_verification_failed", "tls_handshake_failed", "transport_timeout",
    "transport_error", "configuration_error", "tun_device_error",
    "initialization_observed",
})


def classify_openvpn_log(path: Path) -> str:
    """Read at most the last 64KiB, returning only a fixed advisory code.

    Pattern hits are diagnostic hints, never proof of TLS success or permission
    to bypass any transport, route, or network-isolation requirement.
    """
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - MAX_LOG_TAIL))
            log = stream.read(MAX_LOG_TAIL).decode("utf-8", errors="replace").lower()
    except OSError:
        return "log_unavailable"

    if "auth_failed" in log or "authentication failed" in log:
        return "auth_failed"
    if any(marker in log for marker in (
        "verify error", "certificate verify failed", "certificate verification failed",
    )):
        return "tls_verification_failed"
    if any(marker in log for marker in (
        "cannot open tun/tap dev", "cannot ioctl tunsetiff", "error opening tun/tap",
    )):
        return "tun_device_error"
    if any(marker in log for marker in (
        "options error:", "unrecognized option", "error opening configuration file",
    )):
        return "configuration_error"
    if any(marker in log for marker in (
        "tls key negotiation failed to occur", "connection timed out", "inactivity timeout",
    )):
        return "transport_timeout"
    if any(marker in log for marker in (
        "tls error: tls handshake failed", "tls error: tls object -> incoming plaintext read error",
    )):
        return "tls_handshake_failed"
    if any(marker in log for marker in (
        "connection refused", "network is unreachable", "connection reset by peer",
    )):
        return "transport_error"
    if "initialization sequence completed" in log:
        return "initialization_observed"
    return "no_diagnostic_signal"
