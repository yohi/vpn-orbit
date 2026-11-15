"""Tests for isolated OpenVPN tunnel verifier."""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

from vpn_orbit.cloud_probe import ProbeStatus, ScreenedCandidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import (
    ProbeResult,
    FakeRunner,
    probe_one,
    synthesize_openvpn_config,
)
from vpn_orbit.phase1 import Candidate, UnsupportedProfile


def _openssl_cmd(args: list[str], *, input_data: bytes | None = None) -> bytes:
    cmd = ["openssl", *args]
    result = subprocess.run(cmd, input=input_data, capture_output=True, check=True)
    return result.stdout


def _generate_cert_key(tmp: Path, name: str = "test") -> tuple[str, str]:
    key_path = tmp / f"{name}.key"
    cert_path = tmp / f"{name}.crt"
    _openssl_cmd([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", "1", "-subj", "/CN=test",
    ])
    return cert_path.read_text(), key_path.read_text()


def _mismatched_cert_key(tmp: Path) -> tuple[str, str]:
    cert_a, _ = _generate_cert_key(tmp, "a")
    _, key_b = _generate_cert_key(tmp, "b")
    return cert_a, key_b


def _static_key() -> str:
    return (
        "-----BEGIN OpenVPN Static key V1-----\n"
        + ("a" * 64 + "\n") * 8
        + "-----END OpenVPN Static key V1-----"
    )


def _endpoint(
    *,
    ca: str | None = None,
    cert: str | None = None,
    key: str | None = None,
    control_wrap: dict[str, Any] | None = None,
    username: str | None = None,
    password: str | None = None,
    remote_cert_tls: str = "server",
    remote_cert_eku: str | None = None,
    server_name: str | None = None,
    server_name_type: str = "name",
    data_ciphers: list[str] | None = None,
    fallback: str = "AES-128-CBC",
    auth: str = "SHA1",
) -> dict[str, Any]:
    if ca is None:
        ca = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpE\n-----END CERTIFICATE-----\n"
    tls: dict[str, Any] = {"certificate": [ca]}
    if remote_cert_eku:
        tls["remote_certificate_eku"] = remote_cert_eku
    else:
        tls["remote_certificate_tls"] = remote_cert_tls
    if cert is not None:
        tls["client_certificate"] = [cert]
    if key is not None:
        tls["client_key"] = [key]
    if control_wrap:
        tls["control_wrap"] = control_wrap
    if server_name:
        tls["server_name"] = server_name
        tls["server_name_type"] = server_name_type
    endpoint: dict[str, Any] = {
        "type": "openvpn-client",
        "tag": "vpn-gate",
        "mode": "tls",
        "server": "8.8.8.8",
        "server_port": 1195,
        "network": "udp",
        "tls": tls,
        "data_ciphers": data_ciphers or ["AES-256-GCM", "AES-128-GCM"],
        "data_ciphers_fallback": fallback,
        "auth": auth,
        "block_ipv6": True,
        "ping_interval": "10s",
        "ping_restart": "40s",
    }
    if username is not None and password is not None:
        endpoint["username"] = username
        endpoint["password"] = password
    return endpoint


class ConfigSynthesisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vpn-orbit-probe-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _synthesize(self, endpoint: dict[str, Any], *, remote_ip: str = "8.8.8.8", port: int = 1195, protocol: str = "udp") -> bytes:
        private_dir = self.tmp / "private"
        private_dir.mkdir(mode=0o700)
        return synthesize_openvpn_config(
            endpoint,
            remote_ip=remote_ip,
            port=port,
            protocol=protocol,
            private_dir=private_dir,
        )

    def _files(self) -> dict[str, Path]:
        private_dir = self.tmp / "private"
        return {p.name: p for p in private_dir.iterdir() if p.is_file()}

    def test_ca_file_written_with_0600(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        files = self._files()
        self.assertIn("ca.pem", files)
        self.assertEqual(files["ca.pem"].stat().st_mode & 0o777, 0o600)
        self.assertIn("ca ca.pem", config.decode())

    def test_cert_and_key_files_written(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key))
        files = self._files()
        self.assertIn("cert.pem", files)
        self.assertIn("key.pem", files)
        self.assertEqual(files["cert.pem"].stat().st_mode & 0o777, 0o600)
        self.assertIn("cert cert.pem", config.decode())
        self.assertIn("key key.pem", config.decode())

    def test_auth_user_pass_file_written_when_credentials_present(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key, username="vpn", password="vpn"))
        files = self._files()
        self.assertIn("auth.txt", files)
        content = files["auth.txt"].read_text()
        self.assertEqual(content.strip(), "vpn\nvpn")
        self.assertIn("auth-user-pass auth.txt", config.decode())

    def test_data_ciphers_and_fallback_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, data_ciphers=["AES-256-GCM"], fallback="AES-256-CBC"))
        text = config.decode()
        self.assertIn("data-ciphers AES-256-GCM", text)
        self.assertIn("data-ciphers-fallback AES-256-CBC", text)

    def test_auth_digest_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, auth="SHA256"))
        self.assertIn("auth SHA256", config.decode())

    def test_remote_cert_tls_server_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, remote_cert_tls="server"))
        self.assertIn("remote-cert-tls server", config.decode())

    def test_remote_cert_eku_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, remote_cert_eku="TLS Web Server Authentication"))
        self.assertIn("remote-cert-eku \"TLS Web Server Authentication\"", config.decode())

    def test_verify_x509_name_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, server_name="server", server_name_type="name"))
        self.assertIn("verify-x509-name server name", config.decode())

    def test_tls_auth_client_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key(), "direction": "client"}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        self.assertIn("tls-auth tls-auth.key 1", config.decode())

    def test_tls_auth_server_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key(), "direction": "server"}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        self.assertIn("tls-auth tls-auth.key 0", config.decode())

    def test_tls_auth_absent_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key()}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        self.assertIn("tls-auth tls-auth.key", config.decode())
        self.assertNotIn("tls-auth tls-auth.key 1", config.decode())
        self.assertNotIn("tls-auth tls-auth.key 0", config.decode())

    def test_tls_crypt_has_no_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_crypt", "key": _static_key()}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        self.assertIn("tls-crypt tls-crypt.key", config.decode())

    def test_tls_crypt_with_direction_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_crypt", "key": _static_key(), "direction": "client"}
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(ca=ca, control_wrap=wrap))

    def test_unknown_control_wrap_direction_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key(), "direction": "upstream"}
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(ca=ca, control_wrap=wrap))

    def test_mismatched_cert_key_rejected(self):
        cert, key = _mismatched_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(cert=cert, key=key))

    def test_cert_without_key_rejected(self):
        cert, _ = _generate_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(cert=cert, key=None))

    def test_unknown_endpoint_key_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        endpoint = _endpoint(ca=ca)
        endpoint["script-security"] = 2
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unknown_tls_field_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        endpoint = _endpoint(ca=ca)
        endpoint["tls"]["reneg-sec"] = 3600
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unsupported_endpoint_type_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        endpoint = _endpoint(ca=ca)
        endpoint["type"] = "direct"
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_no_raw_ovpn_passed_to_openvpn(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        text = config.decode()
        self.assertNotIn("--config", text)
        self.assertNotIn(".ovpn", text)
        self.assertIn("client", text)
        self.assertIn("route-nopull", text)

    def test_private_dir_files_are_under_private_dir_only(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key))
        text = config.decode()
        private_dir = self.tmp / "private"
        for line in text.splitlines():
            if line.startswith(("ca ", "cert ", "key ", "tls-auth ", "tls-crypt ", "auth-user-pass ")):
                path = private_dir / line.split(None, 1)[1].split()[0].strip('"')
                self.assertTrue(path.is_relative_to(private_dir), line)

    def test_error_messages_do_not_contain_private_key(self):
        cert, key = _mismatched_cert_key(self.tmp)
        try:
            self._synthesize(_endpoint(cert=cert, key=key))
        except UnsupportedProfile as exc:
            self.assertNotIn("BEGIN", str(exc))
            self.assertNotIn("KEY", str(exc).upper())

    def test_rejects_environment_secret_inheritance(self):
        cert, key = _generate_cert_key(self.tmp)
        endpoint = _endpoint(cert=cert, key=key, username="vpn", password="vpn")
        private_dir = self.tmp / "private2"
        private_dir.mkdir(mode=0o700)
        with patch.dict(os.environ, {"VPN_ORBIT_USERNAME": "vpn"}):
            with self.assertRaises(UnsupportedProfile):
                synthesize_openvpn_config(
                    endpoint,
                    remote_ip="8.8.8.8",
                    port=1195,
                    protocol="udp",
                    private_dir=private_dir,
                )


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vpn-orbit-probe-"))
        self.candidate = self._make_candidate()
        self.runner = FakeRunner(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_candidate(self, ip: str = "8.8.8.8", port: int = 1195, protocol: str = "udp") -> ScreenedCandidate:
        ca, _ = _generate_cert_key(self.tmp)
        profile = f"""client
proto {protocol}
remote {ip} {port}
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{ca}</ca>
"""
        return ScreenedCandidate(
            candidate=Candidate(
                host="test", ip=ip, country="JP", ping_ms=1,
                speed_bps=1, score=1, profile=profile,
            ),
            remote=type("RemoteKey", (), {"ip": ip, "port": port, "protocol": protocol}),
            ingress_geo=GeoDecision.TOKYO,
            catalog_rank=1,
        )

    def _geo(self, decision: GeoDecision = GeoDecision.TOKYO) -> Callable[[str], GeoDecision]:
        return lambda ip: decision

    def test_prerequisites_unavailable_returns_blocked(self):
        self.runner.prerequisites_ok_value = False
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.BLOCKED)

    def test_rejects_vpn_orbit_username_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_USERNAME": "vpn"}):
            result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
            self.assertEqual(result.status, ProbeStatus.BLOCKED)

    def test_rejects_vpn_orbit_password_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_PASSWORD": "vpn"}):
            result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
            self.assertEqual(result.status, ProbeStatus.BLOCKED)

    def test_setup_isolation_called_with_remote_parameters(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(self.runner.last_setup, ("8.8.8.8", "udp", 1195))

    def test_cleanup_called_on_success(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.cleaned)
        self.assertTrue(self.runner.supervisor_started)

    def test_timeout_returns_not_verified(self):
        self.runner.wait_for_tun_result = (None, "timeout")
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner, timeout_s=5)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertIn("timeout", result.reason_code.lower())

    def test_curl_failure_returns_not_verified(self):
        self.runner.curl_result = (None, "tls handshake failed")
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)

    def test_non_tokyo_geo_returns_fail(self):
        self.runner.exit_ip = "1.1.1.1"
        result = probe_one(self.candidate, geo_lookup=self._geo(GeoDecision.NON_TOKYO), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)

    def test_unknown_geo_returns_not_verified(self):
        self.runner.exit_ip = "1.1.1.1"
        result = probe_one(self.candidate, geo_lookup=self._geo(GeoDecision.UNKNOWN), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)

    def test_unexpected_exit_ip_format_rejected(self):
        self.runner.exit_ip = "not-an-ip"
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertIn(result.status, (ProbeStatus.FAIL, ProbeStatus.NOT_VERIFIED))

    def test_route_nopull_present_in_config(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        config = self.runner.last_config
        self.assertIn("route-nopull", config.decode())

    def test_no_default_route_in_namespace(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertNotIn("default via", self.runner.commands)
        self.assertFalse(self.runner.has_default_route)

    def test_only_remote_32_via_veth(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.has_remote_32_route)

    def test_echo_32_via_tun0(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.has_echo_32_route)

    def test_observed_unauthorized_egress_returns_fail(self):
        self.runner.unauthorized_egress = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)

    def test_cleanup_failure_returns_fail(self):
        self.runner.cleanup_fail = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)

    def test_host_default_route_untouched(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertFalse(self.runner.host_route_modified)


if __name__ == "__main__":
    unittest.main()
