import os
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._probe_fixtures import (
    _endpoint,
    _generate_cert_key,
    _mismatched_cert_key,
    _static_key,
)
from vpn_orbit.config_synthesis import synthesize_openvpn_config
from vpn_orbit.phase1 import UnsupportedProfile


class ConfigSynthesisTests(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-orbit-probe-")
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)

    def _synthesize(self, endpoint, *, remote_ip="8.8.8.8", port=1195, protocol="udp"):
        private = self.tmp / "private"
        private.mkdir(mode=0o700)
        return synthesize_openvpn_config(endpoint, remote_ip=remote_ip, port=port,
            protocol=protocol, private_dir=private)

    def _files(self):
        return {p.name: p for p in (self.tmp / "private").iterdir() if p.is_file()}

    def test_ca_file_written_with_0600(self):
        ca, _ = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(ca=ca))
        files = self._files()
        self.assertEqual(files["ca.pem"].stat().st_mode & 0o777, 0o600)
        self.assertIn("ca ", config.decode())
        self.assertIn("ca.pem", config.decode())

    def test_relative_private_dir_generates_absolute_ca_reference(self):
        ca, _ = _generate_cert_key(self.tmp)
        private = self.tmp / "relative-private"
        private.mkdir(mode=0o700)
        previous_cwd = Path.cwd()
        try:
            os.chdir(self.tmp)
            config = synthesize_openvpn_config(
                _endpoint(ca=ca), remote_ip="8.8.8.8", port=1195,
                protocol="udp", private_dir=Path("relative-private"),
            )
        finally:
            os.chdir(previous_cwd)
        ca_directive = next(line for line in config.decode().splitlines() if line.startswith("ca "))
        ca_reference = Path(shlex.split(ca_directive)[1])
        self.assertTrue(ca_reference.is_absolute())
        self.assertEqual(ca_reference, private / "ca.pem")

    def test_cert_and_key_files_written(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key))
        files = self._files()
        self.assertIn("cert.pem", files)
        self.assertIn("key.pem", files)
        self.assertEqual(files["cert.pem"].stat().st_mode & 0o777, 0o600)
        self.assertIn("cert ", config.decode())
        self.assertIn("key ", config.decode())

    def test_auth_user_pass_file_written_when_credentials_present(self):
        cert, key = _generate_cert_key(self.tmp)
        config = self._synthesize(_endpoint(cert=cert, key=key, username="vpn", password="vpn"))
        self.assertEqual(self._files()["auth.txt"].read_text().strip(), "vpn\nvpn")
        self.assertIn("auth-user-pass", config.decode())

    def test_data_ciphers_and_fallback_preserved(self):
        config = self._synthesize(_endpoint(data_ciphers=["AES-256-GCM"], fallback="AES-256-CBC"))
        self.assertIn("data-ciphers AES-256-GCM", config.decode())
        self.assertIn("data-ciphers-fallback AES-256-CBC", config.decode())

    def test_auth_digest_preserved(self):
        self.assertIn("auth SHA256", self._synthesize(_endpoint(auth="SHA256")).decode())

    def test_remote_cert_tls_server_preserved(self):
        self.assertIn("remote-cert-tls server", self._synthesize(_endpoint()).decode())

    def test_remote_cert_eku_preserved(self):
        config = self._synthesize(_endpoint(remote_cert_eku="TLS Web Server Authentication"))
        self.assertIn('remote-cert-eku "TLS Web Server Authentication"', config.decode())

    def test_verify_x509_name_preserved(self):
        config = self._synthesize(_endpoint(server_name="server", server_name_type="name"))
        self.assertIn("verify-x509-name server name", config.decode())

    def test_tls_auth_client_direction(self):
        config = self._synthesize(_endpoint(control_wrap={"type":"tls_auth", "key":_static_key(), "direction":"client"}))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(" 1"))

    def test_tls_auth_server_direction(self):
        config = self._synthesize(_endpoint(control_wrap={"type":"tls_auth", "key":_static_key(), "direction":"server"}))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(" 0"))

    def test_tls_auth_absent_direction(self):
        config = self._synthesize(_endpoint(control_wrap={"type":"tls_auth", "key":_static_key()}))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-auth ")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(shlex.split(lines[0])), 2)

    def test_tls_crypt_has_no_direction(self):
        config = self._synthesize(_endpoint(control_wrap={"type":"tls_crypt", "key":_static_key()}))
        lines = [line for line in config.decode().splitlines() if line.startswith("tls-crypt ")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(shlex.split(lines[0])), 2)

    def test_tls_crypt_with_direction_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(control_wrap={"type":"tls_crypt", "key":_static_key(), "direction":"client"}))

    def test_unknown_control_wrap_direction_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(control_wrap={"type":"tls_auth", "key":_static_key(), "direction":"upstream"}))

    def test_mismatched_cert_key_rejected(self):
        cert, key = _mismatched_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(cert=cert, key=key))

    def test_cert_without_key_rejected(self):
        cert, _ = _generate_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(cert=cert))

    def test_unknown_endpoint_key_rejected(self):
        endpoint = _endpoint()
        endpoint["script-security"] = 2
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unknown_tls_field_rejected(self):
        endpoint = _endpoint()
        tls = endpoint["tls"]
        assert isinstance(tls, dict)
        tls["reneg-sec"] = 3600
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unsupported_endpoint_type_rejected(self):
        endpoint = _endpoint()
        endpoint["type"] = "direct"
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_remote_mismatch_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(), remote_ip="1.1.1.1")

    def test_remote_certificate_tls_must_be_server(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(remote_cert_tls="client"))

    def test_server_identity_verification_required(self):
        endpoint = _endpoint()
        tls = endpoint["tls"]
        assert isinstance(tls, dict)
        del tls["remote_certificate_tls"]
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(endpoint)

    def test_unsupported_data_ciphers_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(data_ciphers=["BLOWFISH-CBC"]))

    def test_unsupported_auth_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            self._synthesize(_endpoint(auth="MD5"))

    def test_no_raw_ovpn_passed_to_openvpn(self):
        text = self._synthesize(_endpoint()).decode()
        self.assertNotIn("--config", text)
        self.assertNotIn(".ovpn", text)
        self.assertIn("client", text)
        self.assertIn("route-nopull", text)

    def test_uses_tun0(self):
        config = self._synthesize(_endpoint()).decode()
        self.assertEqual([line for line in config.splitlines() if line.startswith("dev ")], ["dev tun0"])

    def test_paths_are_absolute(self):
        text = self._synthesize(_endpoint()).decode()
        for line in text.splitlines():
            if line.startswith(("ca ", "cert ", "key ", "tls-auth ", "tls-crypt ", "auth-user-pass ")):
                path = Path(shlex.split(line)[1])
                self.assertTrue(path.is_absolute())
                self.assertTrue(path.is_relative_to((self.tmp / "private").resolve()))

    def test_error_messages_do_not_contain_private_key(self):
        cert, key = _mismatched_cert_key(self.tmp)
        with self.assertRaises(UnsupportedProfile) as ctx:
            self._synthesize(_endpoint(cert=cert, key=key))
        self.assertNotIn("BEGIN", str(ctx.exception))
        self.assertNotIn("KEY", str(ctx.exception).upper())

    def test_rejects_environment_secret_inheritance(self):
        endpoint = _endpoint(username="vpn", password="vpn")
        private = self.tmp / "private"
        private.mkdir(mode=0o700)
        with patch.dict(os.environ, {"VPN_ORBIT_USERNAME":"vpn"}), self.assertRaises(UnsupportedProfile):
            synthesize_openvpn_config(endpoint, remote_ip="8.8.8.8", port=1195,
                                      protocol="udp", private_dir=private)
