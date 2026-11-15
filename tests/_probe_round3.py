"""Regression contracts for Task 2 review round 3."""
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import JsonValue
from vpn_orbit.cloud_probe import RemoteKey, ScreenedCandidate
from vpn_orbit.config_synthesis import synthesize_openvpn_config
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.phase1 import Candidate, UnsupportedProfile


@pytest.fixture
def candidate(tmp_path: Path) -> ScreenedCandidate:
    ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
    profile = ("client\nproto udp\nremote 8.8.8.8 1195\ncipher AES-128-CBC\n"
               f"auth SHA1\nremote-cert-tls server\n<ca>\n{ca}</ca>\n")
    return ScreenedCandidate(Candidate("test", "8.8.8.8", "JP", 1, 1, 1, profile),
                             RemoteKey("8.8.8.8", 1195, "udp"), GeoDecision.UNKNOWN, 0)


@pytest.mark.parametrize("failure", [RuntimeError("secret sentinel"), KeyboardInterrupt()])
@pytest.mark.parametrize("stage", ["setup_isolation", "wait_for_tun"])
def test_exception_is_redacted_and_cleanup_runs(candidate, tmp_path, failure, stage):
    # Given an execution failure (including cancellation).
    runner = FakeRunner(tmp_path)
    with patch.object(runner, stage, side_effect=failure):
        # When the single-probe boundary executes.
        result = probe_one(candidate, geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
    # Then it fails closed, retains the exception class, and cleans resources.
    assert result.status == ProbeStatus.NOT_VERIFIED
    assert type(failure).__name__ in result.reason_code
    assert "secret sentinel" not in result.reason_code
    assert runner.cleaned


def test_pre_tunnel_evidence_precedes_openvpn(candidate, tmp_path):
    # Given an isolated candidate.
    runner = FakeRunner(tmp_path)
    def start(*args, **kwargs):
        assert any("pre-tunnel echo check" in c for c in runner.commands)
        return original(*args, **kwargs)
    original = runner.start_openvpn
    # When OpenVPN is started.
    with patch.object(runner, "start_openvpn", side_effect=start):
        result = probe_one(candidate, geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
    # Then the refusal was recorded before any tunnel existed.
    assert result.status == ProbeStatus.PASS


@pytest.mark.parametrize("directive", ["up /tmp/evil", "plugin /tmp/evil", "management 127.0.0.1 1234"])
def test_malicious_profile_never_starts_openvpn(candidate, tmp_path, directive):
    # Given an otherwise valid profile with an executable directive.
    evil = replace(candidate, candidate=replace(candidate.candidate,
                   profile=candidate.candidate.profile + directive + "\n"))
    runner = FakeRunner(tmp_path)
    # When the raw profile crosses the parser boundary.
    with patch.object(runner, "start_openvpn", wraps=runner.start_openvpn) as start:
        result = probe_one(evil, geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
    # Then OpenVPN is never executed.
    assert result.status == ProbeStatus.NOT_VERIFIED
    start.assert_not_called()


@pytest.mark.parametrize("mutation", ["ca_der", "ca_extra", "cipher_type", "port_bool", "eku_injection",
                                     "server", "port", "auth", "fallback", "cipher", "tls_client", "second_ca"])
def test_synthesis_rejects_invalid_boundary(tmp_path, mutation):
    # Given a parsed endpoint tampered with after conversion.
    ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
    tls: dict[str, JsonValue] = {"certificate": [ca], "remote_certificate_tls": "server"}
    endpoint: dict[str, JsonValue] = {"type": "openvpn-client", "server": "8.8.8.8", "server_port": 1195,
                "network": "udp", "tls": tls,
                "auth": "SHA1", "data_ciphers": ["AES-128-GCM"], "data_ciphers_fallback": "AES-128-CBC"}
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
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    # When synthesis revalidates the boundary.
    with pytest.raises(UnsupportedProfile):
        synthesize_openvpn_config(endpoint, remote_ip="8.8.8.8", port=1 if mutation == "port_bool" else 1195,
                                  protocol="udp", private_dir=private)
    # Then no generated material was accepted.
    assert not list(private.iterdir())


@pytest.mark.parametrize("stage", ["setup_isolation", "resolve_host", "wait_for_tun", "teardown_isolation"])
def test_whole_probe_deadline_includes_stalled_operations(candidate, tmp_path, stage):
    # Given an operation that blocks beyond the entire probe budget.
    runner = FakeRunner(tmp_path)
    start = time.monotonic()
    # When the public entry point runs with a small wall-clock budget.
    with patch.object(runner, stage, side_effect=lambda *a, **k: time.sleep(10)):
        result = probe_one(candidate, geo_lookup=lambda _: GeoDecision.TOKYO, timeout_s=1, runner=runner)
    # Then neither setup, network, execution nor teardown can overrun it.
    assert time.monotonic() - start < 2
    assert result.status != ProbeStatus.PASS


def test_geo_lookup_is_bounded_by_whole_deadline(candidate, tmp_path):
    # Given a callback ignoring its own HTTP timeout.
    runner = FakeRunner(tmp_path)
    start = time.monotonic()
    # When evidence gathering stalls.
    def lookup(_: str) -> GeoDecision:
        time.sleep(10)
        return GeoDecision.UNKNOWN
    result = probe_one(candidate, geo_lookup=lookup, timeout_s=1, runner=runner)
    # Then the outer deadline wins and cleanup still runs.
    assert time.monotonic() - start < 2
    assert result.status == ProbeStatus.NOT_VERIFIED
    assert runner.cleaned
