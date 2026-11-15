"""Typed GeoIP decision and outbound HTTP adapter for ipapi.is.

No API key, raw response body, or bearer credential is ever written to logs,
stdout, stderr, or exceptions.
"""
from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from enum import Enum

API_URL = "https://api.ipapi.is/"
MAX_RESPONSE_BYTES = 64 * 1024


class GeoDecision(Enum):
    TOKYO = 0
    NON_TOKYO = 1
    UNKNOWN = 2


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable HTTP redirect following for GeoIP lookups.

    Returning None from redirect_request causes urllib to raise HTTPError,
    which lookup_geoip maps to GeoDecision.UNKNOWN.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def decide_tokyo(ip: str, response: dict) -> GeoDecision:
    """Return TOKYO only when response confirms the exact IP is in Tokyo, JP."""
    if not isinstance(response, dict):
        return GeoDecision.UNKNOWN
    if response.get("ip") != ip:
        return GeoDecision.UNKNOWN
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return GeoDecision.UNKNOWN
    if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_global:
        return GeoDecision.UNKNOWN
    location = response.get("location")
    if not isinstance(location, dict):
        return GeoDecision.UNKNOWN
    country = location.get("country_code")
    state = location.get("state")
    if country == "JP" and state == "Tokyo":
        return GeoDecision.TOKYO
    if isinstance(country, str) and isinstance(state, str):
        return GeoDecision.NON_TOKYO
    return GeoDecision.UNKNOWN


def _create_opener() -> urllib.request.OpenerDirector:
    """Build an HTTPS opener with default TLS verification and no redirects."""
    context = ssl.create_default_context()
    https_handler = urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(_NoRedirectHandler, https_handler)


def lookup_geoip(ip: str, *, api_key: str, timeout_s: float = 5.0) -> GeoDecision:
    """Query ipapi.is via POST JSON and return a GeoDecision.

    Any non-200 response, error field, malformed JSON, timeout, oversized body,
    or exception yields GeoDecision.UNKNOWN. Secrets are never emitted.
    """
    if not api_key.strip():
        return GeoDecision.UNKNOWN
    try:
        body = json.dumps({"q": ip, "key": api_key}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            API_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        opener = _create_opener()
        with opener.open(request, timeout=timeout_s) as response:
            if response.getcode() != 200:
                return GeoDecision.UNKNOWN
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                return GeoDecision.UNKNOWN
            data = json.loads(content)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return GeoDecision.UNKNOWN
    except Exception:
        return GeoDecision.UNKNOWN
    if not isinstance(data, dict):
        return GeoDecision.UNKNOWN
    if "error" in data or "error_code" in data:
        return GeoDecision.UNKNOWN
    return decide_tokyo(ip, data)
