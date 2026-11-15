"""Tests for GeoIP Tokyo decision and outbound HTTP adapter."""
from __future__ import annotations

import io
import json
import ssl
import sys
import unittest
import urllib.request
from unittest.mock import patch

from vpn_orbit.geoip import GeoDecision, _NoRedirectHandler, _create_opener, decide_tokyo, lookup_geoip


class FakeResponse:
    def __init__(self, code: int, body: bytes, headers: dict | None = None):
        self._code = code
        self._body = body
        self.headers = headers or {}

    def getcode(self) -> int:
        return self._code

    def read(self, size: int | None = None) -> bytes:
        if size is None:
            return self._body
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_opener(response: FakeResponse):
    class Opener:
        calls: list[dict] = []

        def open(self, request, timeout=None):
            Opener.calls.append({
                "url": request.full_url,
                "method": request.method,
                "headers": dict(request.headers),
                "body": request.data,
                "timeout": timeout,
            })
            return response

    return Opener()


class DecideTokyoTests(unittest.TestCase):
    def test_tokyo_when_ip_country_state_all_match(self):
        response = {"ip": "8.8.8.8", "location": {"country_code": "JP", "state": "Tokyo"}}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.TOKYO)

    def test_non_tokyo_for_valid_non_tokyo_response(self):
        response = {"ip": "8.8.8.8", "location": {"country_code": "JP", "state": "Osaka"}}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.NON_TOKYO)

    def test_unknown_when_response_ip_mismatches(self):
        response = {"ip": "1.1.1.1", "location": {"country_code": "JP", "state": "Tokyo"}}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.UNKNOWN)

    def test_unknown_for_bogon_ip(self):
        response = {"ip": "192.168.1.1", "location": {"country_code": "JP", "state": "Tokyo"}}
        self.assertEqual(decide_tokyo("192.168.1.1", response), GeoDecision.UNKNOWN)

    def test_unknown_when_country_code_missing(self):
        response = {"ip": "8.8.8.8", "location": {"state": "Tokyo"}}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.UNKNOWN)

    def test_unknown_when_state_missing(self):
        response = {"ip": "8.8.8.8", "location": {"country_code": "JP"}}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.UNKNOWN)

    def test_unknown_when_location_is_not_dict(self):
        response = {"ip": "8.8.8.8", "location": "Tokyo"}
        self.assertEqual(decide_tokyo("8.8.8.8", response), GeoDecision.UNKNOWN)

    def test_unknown_for_non_object_response(self):
        self.assertEqual(decide_tokyo("8.8.8.8", []), GeoDecision.UNKNOWN)


class LookupGeoIPTests(unittest.TestCase):
    def _patch_opener(self, response: FakeResponse):
        opener = fake_opener(response)
        return patch("vpn_orbit.geoip._create_opener", return_value=opener), opener

    def test_posts_json_with_key_and_returns_tokyo(self):
        body = json.dumps({"ip": "8.8.8.8", "location": {"country_code": "JP", "state": "Tokyo"}}).encode()
        patcher, opener = self._patch_opener(FakeResponse(200, body))
        with patcher:
            result = lookup_geoip("8.8.8.8", api_key="secret-key")
        self.assertEqual(result, GeoDecision.TOKYO)
        self.assertEqual(len(opener.calls), 1)
        call = opener.calls[0]
        self.assertEqual(call["url"], "https://api.ipapi.is/")
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"]["Content-type"], "application/json")
        self.assertEqual(json.loads(call["body"]), {"q": "8.8.8.8", "key": "secret-key"})
        self.assertNotIn("secret-key", call["url"])

    def test_non_200_returns_unknown(self):
        for code in (302, 429, 500):
            with self.subTest(code=code):
                patcher, _ = self._patch_opener(FakeResponse(code, b"service error"))
                with patcher:
                    self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_200_with_error_field_returns_unknown(self):
        body = json.dumps({"error": "invalid ip", "error_code": 400}).encode()
        patcher, _ = self._patch_opener(FakeResponse(200, body))
        with patcher:
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_200_with_error_code_field_returns_unknown(self):
        body = json.dumps({"error_code": 401}).encode()
        patcher, _ = self._patch_opener(FakeResponse(200, body))
        with patcher:
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_bad_json_returns_unknown(self):
        patcher, _ = self._patch_opener(FakeResponse(200, b"not json"))
        with patcher:
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_non_object_json_returns_unknown(self):
        patcher, _ = self._patch_opener(FakeResponse(200, b"[1, 2, 3]"))
        with patcher:
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_oversized_response_returns_unknown(self):
        body = b"x" * (64 * 1024 + 1)
        patcher, _ = self._patch_opener(FakeResponse(200, body))
        with patcher:
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_timeout_returns_unknown(self):
        opener = fake_opener(FakeResponse(200, b"{}"))

        def raise_timeout(*args, **kwargs):
            raise TimeoutError("timed out")

        opener.open = raise_timeout
        with patch("vpn_orbit.geoip._create_opener", return_value=opener):
            self.assertEqual(lookup_geoip("8.8.8.8", api_key="k"), GeoDecision.UNKNOWN)

    def test_ssl_error_returns_unknown_without_leaking_key(self):
        opener = fake_opener(FakeResponse(200, b"{}"))

        def raise_ssl(*args, **kwargs):
            raise ssl.SSLError("certificate verify failed")

        opener.open = raise_ssl
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        with (
            patch("vpn_orbit.geoip._create_opener", return_value=opener),
            patch.object(sys, "stdout", stdout_capture),
            patch.object(sys, "stderr", stderr_capture),
        ):
            result = lookup_geoip("8.8.8.8", api_key="secret-key")
        self.assertEqual(result, GeoDecision.UNKNOWN)
        combined_output = stdout_capture.getvalue() + stderr_capture.getvalue()
        self.assertNotIn("secret-key", combined_output)


class OpenerConfigurationTests(unittest.TestCase):
    def test_create_opener_disables_redirects(self):
        opener = _create_opener()
        redirect_handlers = [h for h in opener.handlers if isinstance(h, _NoRedirectHandler)]
        self.assertEqual(len(redirect_handlers), 1)
        handler = redirect_handlers[0]
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://example.com/"))

    def test_create_opener_enables_tls_verification(self):
        opener = _create_opener()
        https_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(len(https_handlers), 1)
        context = https_handlers[0]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
