"""Tests for isolated OpenVPN tunnel verifier."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from vpn_orbit.cloud_probe import ProbeStatus, RemoteKey, ScreenedCandidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import ProbeResult, probe_candidates, probe_one, synthesize_openvpn_config
from vpn_orbit.phase1 import Candidate, UnsupportedProfile
from vpn_orbit.runner import CurlOutcome


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
        ca, _ = _generate_cert_key(Path(tempfile.mkdtemp()), "default-ca")
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
        text = config.decode()
        self.assertIn("ca ", text)
        self.assertIn("ca.pem", text)

    def test_cert_and_key_files_written(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key))
        files = self._files()
        self.assertIn("cert.pem", files)
        self.assertIn("key.pem", files)
        self.assertEqual(files["cert.pem"].stat().st_mode & 0o777, 0o600)
        text = config.decode()
        self.assertIn("cert ", text)
        self.assertIn("key ", text)

    def test_auth_user_pass_file_written_when_credentials_present(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key, username="vpn", password="vpn"))
        files = self._files()
        self.assertIn("auth.txt", files)
        content = files["auth.txt"].read_text()
        self.assertEqual(content.strip(), "vpn\nvpn")
        self.assertIn("auth-user-pass", config.decode())

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
        self.assertIn('remote-cert-eku "TLS Web Server Authentication"', config.decode())

    def test_verify_x509_name_preserved(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca, server_name="server", server_name_type="name"))
        self.assertIn("verify-x509-name server name", config.decode())

    def test_tls_auth_client_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key(), "direction": "client"}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(" 1"))

    def test_tls_auth_server_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key(), "direction": "server"}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(" 0"))

    def test_tls_auth_absent_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_auth", "key": _static_key()}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        parts = lines[0].split()
        self.assertEqual(len(parts), 2)

    def test_tls_crypt_has_no_direction(self):
        ca, _ = _generate_cert_key(self.tmp)
        wrap = {"type": "tls_crypt", "key": _static_key()}
        config = self._synthesize(_endpoint(ca=ca, control_wrap=wrap))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-crypt ")]
        self.assertEqual(len(lines), 1)
        parts = lines[0].split()
        self.assertEqual(len(parts), 2)

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

    def test_remote_mismatch_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(ca=ca), remote_ip="1.1.1.1")

    def test_remote_certificate_tls_must_be_server(self):
        ca, _ = _generate_cert_key(self.tmp)
        endpoint = _endpoint(ca=ca)
        endpoint["tls"]["remote_certificate_tls"] = "client"
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_server_identity_verification_required(self):
        ca, _ = _generate_cert_key(self.tmp)
        endpoint = _endpoint(ca=ca)
        del endpoint["tls"]["remote_certificate_tls"]
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unsupported_data_ciphers_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(ca=ca, data_ciphers=["BLOWFISH-CBC"]))

    def test_unsupported_auth_rejected(self):
        ca, _ = _generate_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(ca=ca, auth="MD5"))

    def test_no_raw_ovpn_passed_to_openvpn(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        text = config.decode()
        self.assertNotIn("--config", text)
        self.assertNotIn(".ovpn", text)
        self.assertIn("client", text)
        self.assertIn("route-nopull", text)

    def test_uses_tun0(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        lines = [line for line in config.decode().splitlines() if line.startswith("dev ")]
        self.assertEqual(lines, ["dev tun0"])

    def test_paths_are_absolute(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        text = config.decode()
        private_dir = self.tmp / "private"
        for line in text.splitlines():
            if line.startswith(("ca ", "cert ", "key ", "tls-auth ", "tls-crypt ", "auth-user-pass ")):
                path_str = line.split(None, 1)[1].split()[0].strip('"')
                self.assertTrue(Path(path_str).is_absolute(), line)
                self.assertTrue(Path(path_str).is_relative_to(private_dir.resolve()), line)

    def test_error_messages_do_not_contain_private_key(self):
        cert, key = _mismatched_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile) as ctx:
            self._synthesize(_endpoint(cert=cert, key=key))
        message = str(ctx.exception)
        self.assertNotIn("BEGIN", message)
        self.assertNotIn("KEY", message.upper())

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
            remote=RemoteKey(ip=ip, port=port, protocol=protocol),  # type: ignore[arg-type]
            ingress_geo=GeoDecision.TOKYO,
            catalog_rank=1,
        )

    def _geo(self, decision: GeoDecision = GeoDecision.TOKYO):
        return lambda ip: decision

    def test_prerequisites_unavailable_returns_blocked(self):
        self.runner.prerequisites_ok_value = False
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "prerequisites_unavailable")

    def test_rejects_vpn_orbit_username_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_USERNAME": "vpn"}):
            result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
            self.assertEqual(result.status, ProbeStatus.BLOCKED)
            self.assertEqual(result.reason_code, "environment_secret_inheritance_rejected")

    def test_rejects_vpn_orbit_password_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_PASSWORD": "vpn"}):
            result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
            self.assertEqual(result.status, ProbeStatus.BLOCKED)

    def test_supervisor_starts_before_setup_isolation(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        idx_supervisor = self.runner.commands.index("supervisor started")
        idx_save = self.runner.commands.index("save ip_forward")
        idx_setup = self.runner.commands.index("ip netns add test-ns")
        self.assertLess(idx_supervisor, idx_save)
        self.assertLess(idx_save, idx_setup)

    def test_setup_isolation_called_with_remote_parameters(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(self.runner.last_setup, ("8.8.8.8", "udp", 1195))

    def test_ip_forward_saved_and_restored(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.ip_forward_saved)
        self.assertTrue(self.runner.ip_forward_restored)
        self.assertIn("save ip_forward", self.runner.commands)
        self.assertIn("restore ip_forward", self.runner.commands)

    def test_ip_forward_save_failure_returns_blocked(self):
        self.runner.save_ip_forward_fails = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "ip_forward_save_failed")

    def test_ip_forward_restore_failure_returns_fail(self):
        self.runner.restore_ip_forward_fails = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("restore_ip_forward_failed", result.reason_code)

    def test_cleanup_called_on_success(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.cleaned)
        self.assertTrue(self.runner.supervisor_started)

    def test_timeout_returns_not_verified(self):
        self.runner.wait_for_tun_result = (None, "timeout")
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner, timeout_s=5)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "tun_not_established")

    def test_curl_failure_returns_not_verified(self):
        self.runner.curl_result = CurlOutcome(body=None, error="tls handshake failed")
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_fetch_failed")

    def test_non_tokyo_geo_returns_not_verified(self):
        self.runner.exit_ip = "1.1.1.1"
        result = probe_one(self.candidate, geo_lookup=self._geo(GeoDecision.NON_TOKYO), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_non_tokyo")

    def test_unknown_geo_returns_not_verified(self):
        self.runner.exit_ip = "1.1.1.1"
        result = probe_one(self.candidate, geo_lookup=self._geo(GeoDecision.UNKNOWN), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_geoip_unavailable")

    def test_unexpected_exit_ip_format_rejected_not_verified(self):
        self.runner.exit_ip = "not-an-ip"
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "echo_ip_not_global")

    def test_unauthorized_egress_returns_fail(self):
        self.runner.curl_result = CurlOutcome(
            body=None, error="leak", safety_violation="unauthorized_egress"
        )
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "unauthorized_egress")

    def test_cleanup_failure_returns_fail(self):
        self.runner.teardown_fails = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertTrue(result.reason_code.startswith("cleanup_failed"))

    def test_terminate_failure_recorded_in_cleanup(self):
        self.runner.terminate_fails = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("terminate_failed", result.reason_code)

    def test_supervisor_cleanup_unconfirmed_returns_fail(self):
        self.runner.supervisor_cleanup_confirmed = False
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("supervisor_cleanup_failed", result.reason_code)

    def test_supervisor_start_failure_returns_blocked(self):
        self.runner.supervisor_start_fails = True
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "supervisor_start_failed")

    def test_host_default_route_unchanged(self):
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.PASS)
        self.assertIn("host default route check", self.runner.commands)

    def test_pre_tunnel_echo_reachable_returns_fail(self):
        self.runner.pre_tunnel_echo_blocked = False
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "pre_tunnel_echo_reachable")

    def test_route_not_via_tun0_returns_fail(self):
        self.runner.route_get_via_tun0_result = False
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "echo_route_not_tun0")

    def test_malicious_raw_profile_rejected_before_openvpn(self):
        profile = """client
proto udp
remote 8.8.8.8 1195
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
script-security 3
up /tmp/pwned.sh
<ca>
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpE
-----END CERTIFICATE-----
</ca>
"""
        candidate = ScreenedCandidate(
            candidate=Candidate(
                host="evil", ip="8.8.8.8", country="JP", ping_ms=1,
                speed_bps=1, score=1, profile=profile,
            ),
            remote=RemoteKey(ip="8.8.8.8", port=1195, protocol="udp"),  # type: ignore[arg-type]
            ingress_geo=GeoDecision.TOKYO,
            catalog_rank=1,
        )
        result = probe_one(candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "profile_parse_failed")
        self.assertFalse(self.runner.supervisor_started)

    def test_openvpn_env_is_allowlisted(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertIsNotNone(self.runner.last_openvpn_env)
        self.assertNotIn("IPAPI_IS_API_KEY", self.runner.last_openvpn_env)
        self.assertIn("PATH", self.runner.last_openvpn_env)
        self.assertEqual(self.runner.last_openvpn_cwd, self.runner._resources.private_dir)

    def test_no_default_route_recorded(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertIn("default route absent", self.runner.commands)
        self.assertFalse(self.runner.has_default_route)

    def test_only_remote_32_via_veth(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.has_remote_32_route)
        route_commands = [c for c in self.runner.commands if c.startswith("ip route add")]
        self.assertTrue(any("8.8.8.8/32" in c for c in route_commands))

    def test_echo_32_via_tun0(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertTrue(self.runner.has_echo_32_route)

    def test_curl_uses_resolve_and_interface(self):
        probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        curl_commands = [c for c in self.runner.commands if c.startswith("curl ")]
        self.assertEqual(len(curl_commands), 1)
        self.assertIn("--interface tun0", curl_commands[0])
        self.assertIn("--resolve api.ipify.org:443:1.1.1.1", curl_commands[0])

    def test_tun_ip_invalid_returns_not_verified(self):
        self.runner.wait_for_tun_result = ("not-an-ip", "ok")
        result = probe_one(self.candidate, geo_lookup=self._geo(), runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "tun_ip_invalid")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vpn-orbit-probe-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _candidate(self, ip: str = "8.8.8.8") -> ScreenedCandidate:
        ca, _ = _generate_cert_key(self.tmp)
        profile = f"""client
proto udp
remote {ip} 1195
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
            remote=RemoteKey(ip=ip, port=1195, protocol="udp"),  # type: ignore[arg-type]
            ingress_geo=GeoDecision.TOKYO,
            catalog_rank=1,
        )

    def test_private_dir_removed_after_success(self):
        runner = FakeRunner(self.tmp)
        candidate = self._candidate()
        probe_one(candidate, geo_lookup=lambda ip: GeoDecision.TOKYO, runner=runner)
        self.assertFalse(runner._resources.private_dir.exists())

    def test_private_dir_removed_after_timeout(self):
        runner = FakeRunner(self.tmp)
        runner.wait_for_tun_result = (None, "timeout")
        candidate = self._candidate()
        probe_one(candidate, geo_lookup=lambda ip: GeoDecision.UNKNOWN, runner=runner, timeout_s=5)
        self.assertFalse(runner._resources.private_dir.exists())

    def test_probe_candidates_isolates_exceptions(self):
        class ExplodingRunner(FakeRunner):
            def start_openvpn(self, *args, **kwargs):
                raise RuntimeError("boom")

        ca, _ = _generate_cert_key(self.tmp)
        profile = f"""client
proto udp
remote 8.8.8.8 1195
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{ca}</ca>
"""
        candidates = [
            ScreenedCandidate(
                candidate=Candidate(
                    host="test", ip="8.8.8.8", country="JP", ping_ms=1,
                    speed_bps=1, score=1, profile=profile,
                ),
                remote=RemoteKey(ip="8.8.8.8", port=1195, protocol="udp"),  # type: ignore[arg-type]
                ingress_geo=GeoDecision.TOKYO,
                catalog_rank=1,
            ),
        ]
        results = probe_candidates(
            candidates, geo_lookup=lambda ip: GeoDecision.UNKNOWN, runner=ExplodingRunner(self.tmp)
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(results[0].reason_code, "probe_exception")


if __name__ == "__main__":
    unittest.main()
