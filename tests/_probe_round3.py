import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import JsonValue
from vpn_orbit.cloud_probe import RemoteKey, ScreenedCandidate
from vpn_orbit.config_synthesis import synthesize_openvpn_config
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.phase1 import Candidate, UnsupportedProfile


def _candidate() -> ScreenedCandidate:
    ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
    profile = ("client\nproto udp\nremote 8.8.8.8 1195\ncipher AES-128-CBC\n"
               f"auth SHA1\nremote-cert-tls server\n<ca>\n{ca}</ca>\n")
    return ScreenedCandidate(Candidate("test", "8.8.8.8", "JP", 1, 1, 1, profile),
                             RemoteKey("8.8.8.8", 1195, "udp"), GeoDecision.UNKNOWN, 0)


class Round3Tests(unittest.TestCase):
    def test_exception_is_redacted_and_cleanup_runs(self):
        for stage in ("setup_isolation", "wait_for_tun"):
            for failure in (RuntimeError("secret sentinel"), KeyboardInterrupt()):
                with self.subTest(stage=stage, error=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                    runner = FakeRunner(Path(directory))
                    with patch.object(runner, stage, side_effect=failure):
                        result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
                    self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
                    self.assertIn(type(failure).__name__, result.reason_code)
                    self.assertNotIn("secret sentinel", result.reason_code)
                    self.assertTrue(runner.cleaned)

    def test_pre_tunnel_evidence_precedes_openvpn(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            original = runner.start_openvpn
            def start(*args, **kwargs):
                self.assertTrue(any("pre-tunnel echo check" in c for c in runner.commands))
                return original(*args, **kwargs)
            with patch.object(runner, "start_openvpn", side_effect=start):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
            self.assertEqual(result.status, ProbeStatus.PASS)

    def test_malicious_profile_never_starts_openvpn(self):
        candidate = _candidate()
        for directive in ("up /tmp/evil", "plugin /tmp/evil", "management 127.0.0.1 1234"):
            with self.subTest(directive=directive), tempfile.TemporaryDirectory() as directory:
                evil = replace(candidate, candidate=replace(candidate.candidate,
                               profile=candidate.candidate.profile + directive + "\n"))
                runner = FakeRunner(Path(directory))
                with patch.object(runner, "start_openvpn", wraps=runner.start_openvpn) as start:
                    result = probe_one(evil, geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
                self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
                start.assert_not_called()

    def test_synthesis_rejects_invalid_boundary(self):
        ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
        for mutation in ("ca_der", "ca_extra", "cipher_type", "port_bool", "eku_injection",
                         "server", "port", "auth", "fallback", "cipher", "tls_client", "second_ca"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                tls: dict[str, JsonValue] = {"certificate": [ca], "remote_certificate_tls": "server"}
                endpoint: dict[str, JsonValue] = {"type": "openvpn-client", "server": "8.8.8.8", "server_port": 1195,
                    "network": "udp", "tls": tls, "auth": "SHA1", "data_ciphers": ["AES-128-GCM"],
                    "data_ciphers_fallback": "AES-128-CBC"}
                match mutation:
                    case "ca_der": tls["certificate"] = ["-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----"]
                    case "ca_extra": tls["certificate"] = [ca + ca]
                    case "cipher_type": endpoint["data_ciphers"] = [123]
                    case "port_bool": endpoint["server_port"] = True
                    case "server": endpoint["server"] = "1.1.1.1"
                    case "port": endpoint["server_port"] = 1196
                    case "auth": endpoint["auth"] = "MD5"
                    case "fallback": endpoint["data_ciphers_fallback"] = "BF-CBC"
                    case "cipher": endpoint["data_ciphers"] = ["BF-CBC"]
                    case "tls_client": tls["remote_certificate_tls"] = "client"
                    case "second_ca": tls["certificate"] = [ca, "invalid"]
                    case "eku_injection":
                        tls.pop("remote_certificate_tls")
                        tls["remote_certificate_eku"] = "server\nscript-security 3"
                private = Path(directory) / "private"
                private.mkdir(mode=0o700)
                with self.assertRaises(UnsupportedProfile):
                    synthesize_openvpn_config(endpoint, remote_ip="8.8.8.8", port=1 if mutation == "port_bool" else 1195,
                                              protocol="udp", private_dir=private)
                self.assertFalse(list(private.iterdir()))

    def test_whole_probe_deadline_includes_stalled_operations(self):
        for stage in ("setup_isolation", "resolve_host", "wait_for_tun", "teardown_isolation"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                runner = FakeRunner(Path(directory))
                start = time.monotonic()
                with patch.object(runner, stage, side_effect=lambda *a, **k: time.sleep(10)):
                    result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.TOKYO, timeout_s=1, runner=runner)
                self.assertLess(time.monotonic() - start, 2)
                self.assertNotEqual(result.status, ProbeStatus.PASS)

    def test_geo_lookup_is_bounded_by_whole_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            start = time.monotonic()
            def lookup(_: str) -> GeoDecision:
                time.sleep(10)
                return GeoDecision.UNKNOWN
            result = probe_one(_candidate(), geo_lookup=lookup, timeout_s=1, runner=runner)
            self.assertLess(time.monotonic() - start, 2)
            self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
            self.assertTrue(runner.cleaned)
