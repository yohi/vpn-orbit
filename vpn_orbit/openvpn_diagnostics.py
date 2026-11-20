"""Bounded and redacted advisory diagnostics for untrusted OpenVPN log output."""
from __future__ import annotations

import json
import os
from pathlib import Path

MAX_LOG_TAIL = 64 * 1024
OPENVPN_DIAGNOSTIC_CODES = frozenset({
    "not_observed", "log_unavailable", "no_diagnostic_signal", "auth_failed",
    "tls_verification_failed", "tls_handshake_failed", "transport_timeout",
    "transport_error", "configuration_error", "tun_device_error",
    "initialization_observed",
})
OPENVPN_PROGRESS_CODES = frozenset({
    "not_observed", "log_unavailable", "no_progress_signal", "remote_selected",
    "transport_connected", "tls_packet_seen", "peer_connected", "initialized",
})
PROCESS_STATES = frozenset({"not_started", "running", "exited", "unknown"})
LINK_IO_CODES = frozenset({
    "not_observed", "unavailable", "no_packets", "tx_only", "rx_only",
    "bidirectional",
})
_PROGRESS_ORDER = {
    "not_observed": 0, "log_unavailable": 0, "no_progress_signal": 0,
    "remote_selected": 1, "transport_connected": 2,
    "tls_packet_seen": 3, "peer_connected": 4, "initialized": 5,
}


def _read_log_tail(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - MAX_LOG_TAIL))
            return stream.read(MAX_LOG_TAIL).decode("utf-8", errors="replace").lower()
    except OSError:
        return None


def _failure_code(log: str) -> str:
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


def _progress_code(log: str) -> str:
    # These are advisory log markers, not a substitute for TLS/TUN verification.
    if "initialization sequence completed" in log:
        return "initialized"
    if "peer connection initiated" in log:
        return "peer_connected"
    if "tls: initial packet from" in log:
        return "tls_packet_seen"
    if "tcp connection established" in log:
        return "transport_connected"
    # OpenVPN 2.4+ prints e.g. "UDPv4 link remote:" / "TCPv4_CLIENT link remote:".
    if "link remote:" in log:
        return "remote_selected"
    return "no_progress_signal"


def observe_openvpn_log(path: Path) -> tuple[str, str]:
    """Read only a bounded tail; return two fixed codes, never raw content."""
    log = _read_log_tail(path)
    if log is None:
        return "log_unavailable", "log_unavailable"
    return _failure_code(log), _progress_code(log)


def classify_openvpn_log(path: Path) -> str:
    """Backward-compatible diagnostic error classifier."""
    return observe_openvpn_log(path)[0]


def advance_progress(previous: str, current: str) -> str:
    """Keep furthest connection progress; track latest pre-progress log state."""
    if (type(previous) is not str or type(current) is not str
            or previous not in OPENVPN_PROGRESS_CODES
            or current not in OPENVPN_PROGRESS_CODES):
        return "not_observed"
    if current == "not_observed":
        return previous
    if _PROGRESS_ORDER[current] == 0:
        return previous if _PROGRESS_ORDER[previous] > 0 else current
    return current if _PROGRESS_ORDER[current] > _PROGRESS_ORDER[previous] else previous


def classify_link_io(raw: str, interface: str) -> str:
    """Classify veth link-level packet counts, which can include ARP/non-VPN traffic.

    This is NOT proof that the selected VPN peer exchanged packets.
    """
    try:
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return "unavailable"
        row = rows[0]
        if row.get("ifname") != interface:
            return "unavailable"
        stats = row.get("stats64") or row.get("stats")
        if not isinstance(stats, dict):
            return "unavailable"
        rx = stats["rx"]["packets"]
        tx = stats["tx"]["packets"]
        if any(type(n) is not int or n < 0 for n in (rx, tx)):
            return "unavailable"
    except (ValueError, KeyError, TypeError, AttributeError):
        return "unavailable"
    if tx and rx:
        return "bidirectional"
    if tx:
        return "tx_only"
    if rx:
        return "rx_only"
    return "no_packets"
