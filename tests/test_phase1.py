import base64
import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpn_orbit.phase1 import UnsupportedProfile, build_config, convert_ovpn, main, parse_catalog

CA = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
PROFILE = f"""client
proto udp
remote 8.8.8.8 1195
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{CA}</ca>
"""


def catalog(profiles):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["HostName", "IP", "Score", "Ping", "Speed", "CountryShort", "OpenVPN_ConfigData_Base64"])
    for ip, country, ping, profile in profiles:
        writer.writerow(["test.opengw.net", ip, "123", str(ping), "30000000", country,
                         base64.b64encode(profile.encode()).decode()])
    return "*vpn_servers\n#" + stream.getvalue()


class Phase1Tests(unittest.TestCase):
    def test_safe_tls_config(self):
        endpoint = convert_ovpn(PROFILE)
        self.assertEqual(endpoint["type"], "openvpn-client")
        self.assertEqual(endpoint["server"], "8.8.8.8")
        self.assertEqual(endpoint["network"], "udp")
        self.assertEqual(endpoint["tls"]["remote_certificate_tls"], "server")
        self.assertIn("AES-128-CBC", endpoint["data_ciphers"])
        full = build_config(endpoint)
        self.assertEqual(full["route"]["final"], "vpn-gate")
        self.assertNotIn("outbounds", full)
        self.assertEqual(full["dns"]["servers"][0]["detour"], "vpn-gate")
        self.assertEqual(full["inbounds"][0]["route_exclude_address"], ["8.8.8.8/32"])
        self.assertNotIn("route_address", full["inbounds"][0])
        self.assertNotIn("inet6_route_address", full["inbounds"][0])
        self.assertEqual(full["inbounds"][0]["address"], ["172.28.250.1/30", "fd28:250::1/126"])
        self.assertTrue(endpoint["block_ipv6"])

    def test_route_exclusions_fail_closed_for_invalid_or_ambiguous_remotes(self):
        endpoint = convert_ovpn(PROFILE)
        for bad_ip in ("192.168.1.1", "203.0.113.4", "8.8.8.8/32"):
            with self.subTest(ip=bad_ip), self.assertRaises(UnsupportedProfile):
                build_config({**endpoint, "server": bad_ip})
        with self.assertRaises(UnsupportedProfile):
            build_config({**endpoint, "servers": [{"server": "9.9.9.9"}]})
        with self.assertRaises(UnsupportedProfile):
            build_config({**endpoint, "server": 134744072})
        with self.assertRaises(UnsupportedProfile):
            build_config({**endpoint, "server": "8.8.8.8", "type": "direct"})

    def test_credential_defaults_only_when_requested(self):
        self.assertNotIn("username", convert_ovpn(PROFILE))
        with patch.dict("os.environ", {"VPN_ORBIT_USERNAME":"vpn", "VPN_ORBIT_PASSWORD":"vpn"}):
            self.assertEqual(convert_ovpn(PROFILE + "auth-user-pass\n")["password"], "vpn")

    def test_untrusted_script_directives_rejected(self):
        for directive in ("up /tmp/inject", "plugin /tmp/a.so", "script-security 3", "route 0.0.0.0 0.0.0.0"):
            with self.subTest(directive=directive), self.assertRaises(UnsupportedProfile):
                convert_ovpn(PROFILE + directive + "\n")

    def test_reject_insecure_or_unsupported(self):
        cases = [
            PROFILE.replace("remote-cert-tls server", "remote-cert-tls client"),
            PROFILE.replace("remote 8.8.8.8", "remote 192.168.1.2"),
            PROFILE.replace("<ca>", "<unknown>"),
            PROFILE.replace("remote 8.8.8.8", "remote 8.8.8.8 1195\nremote 1.1.1.1"),
            PROFILE.replace("<ca>", "<ca>\nup /tmp/foo\n"),
            PROFILE + "auth-user-pass /tmp/password\n",
            PROFILE + "key-direction 1\n",
        ]
        for text in cases:
            with self.subTest(text=text[-70:]), self.assertRaises(UnsupportedProfile):
                convert_ovpn(text)

    def test_catalog_country_and_remote_identity(self):
        raw = catalog([
            ("8.8.8.8", "JP", 12, PROFILE),
            ("9.9.9.9", "JP", 4, PROFILE),
            ("8.8.8.8", "KR", 1, PROFILE),
        ])
        result = parse_catalog(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].ip, "8.8.8.8")

    def test_catalog_reject_missing_header(self):
        with self.assertRaises(ValueError):
            parse_catalog("not a valid API response")

    def test_local_cli_writes_private_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.ovpn"
            output = Path(tmp) / "profile.json"
            path.write_text(PROFILE)
            self.assertEqual(main(["--ovpn", str(path), "--output", str(output)]), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn('"openvpn-client"', output.read_text())
            self.assertEqual(main(["--ovpn", str(path), "--output", str(output)]), 1)

    def test_expected_ip_mismatch(self):
        with self.assertRaises(UnsupportedProfile):
            convert_ovpn(PROFILE, expected_ip="9.9.9.9")

    def test_verify_x509_name_preserved(self):
        endpoint = convert_ovpn(PROFILE + "verify-x509-name server name\n")
        self.assertEqual(endpoint["tls"]["server_name"], "server")

    def test_verify_x509_name_rejects_empty_value(self):
        with self.assertRaises(UnsupportedProfile):
            convert_ovpn(PROFILE + "verify-x509-name\n")

    def test_ca_rejects_non_x509_der_payload(self):
        malformed_ca = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n"
        profile = PROFILE.replace(CA, malformed_ca)
        with self.assertRaises(UnsupportedProfile):
            convert_ovpn(profile)

    def test_tun_directives_reject_tap_devices(self):
        for directive in ("dev tap", "dev-type tap"):
            with self.subTest(directive=directive), self.assertRaises(UnsupportedProfile):
                convert_ovpn(PROFILE + directive + "\n")

    def test_tun_directives_accept_tun_devices(self):
        endpoint = convert_ovpn(PROFILE + "dev tun0\ndev-type tun\n")
        self.assertEqual(endpoint["network"], "udp")

    def test_remote_cert_eku_is_preserved(self):
        profile = PROFILE.replace("remote-cert-tls server\n", "")
        endpoint = convert_ovpn(profile + 'remote-cert-eku "TLS Web Server Authentication"\n')
        self.assertEqual(endpoint["tls"]["remote_certificate_eku"], "TLS Web Server Authentication")
        self.assertNotIn("remote_certificate_tls", endpoint["tls"])

    def test_remote_cert_eku_rejects_unrepresentable_combination(self):
        profile = PROFILE + "remote-cert-tls server\nremote-cert-eku 1.3.6.1.5.5.7.3.1\n"
        with self.assertRaises(UnsupportedProfile):
            convert_ovpn(profile)

    def test_inline_client_identity_preserved(self):
        # Synthetic DER-shaped key only: no real private credential is committed.
        der = b"\x30\x1e" + b"\x01" * 30
        key = ("-----BEGIN RSA PRIVATE KEY-----\n"
               + base64.b64encode(der).decode() + "\n-----END RSA PRIVATE KEY-----\n")
        profile = PROFILE + f"<cert>\n{CA}</cert>\n<key>\n{key}</key>\n"
        endpoint = convert_ovpn(profile)
        self.assertEqual(endpoint["tls"]["client_certificate"], [CA.strip() + "\n"])
        self.assertEqual(endpoint["tls"]["client_key"], [key])
        self.assertEqual(build_config(endpoint)["endpoints"][0]["tls"]["client_key"], [key])

    def test_inline_client_identity_fails_closed_on_invalid_input(self):
        der = b"\x30\x1e" + b"\x01" * 30
        key = ("-----BEGIN RSA PRIVATE KEY-----\n"
               + base64.b64encode(der).decode() + "\n-----END RSA PRIVATE KEY-----\n")
        cert_block = f"<cert>\n{CA}</cert>\n"
        key_block = f"<key>\n{key}</key>\n"
        bad = (
            PROFILE + cert_block,
            PROFILE + key_block,
            PROFILE + cert_block + key_block + cert_block,
            PROFILE + cert_block + key_block.replace("RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
            PROFILE + cert_block + key_block.replace(base64.b64encode(der).decode(), "invalid!"),
            PROFILE + cert_block + key_block.replace(
                base64.b64encode(der).decode(),
                base64.b64encode(b"\x30\x21" + b"\x01" * 30).decode()),
        )
        for input_profile in bad:
            with self.subTest(length=len(input_profile)), self.assertRaises(UnsupportedProfile):
                convert_ovpn(input_profile)

    def test_tls_auth_inline(self):
        key = '-----BEGIN OpenVPN Static key V1-----\n' + ('a' * 64 + '\n') * 8 + '-----END OpenVPN Static key V1-----'
        profile = PROFILE + '<tls-auth>\n' + key + '\n</tls-auth>\nkey-direction 1\n'
        endpoint = convert_ovpn(profile)
        self.assertEqual(endpoint["tls"]["control_wrap"]["direction"], "client")

    def test_tls_auth_inline_directive_preserves_direction(self):
        key = '-----BEGIN OpenVPN Static key V1-----\n' + ('a' * 64 + '\n') * 8 + '-----END OpenVPN Static key V1-----'
        profile = PROFILE + 'tls-auth [inline] 1\n<tls-auth>\n' + key + '\n</tls-auth>\n'
        endpoint = convert_ovpn(profile)
        self.assertEqual(endpoint["tls"]["control_wrap"]["direction"], "client")

    def test_tls_auth_rejects_conflicting_directions(self):
        key = '-----BEGIN OpenVPN Static key V1-----\n' + ('a' * 64 + '\n') * 8 + '-----END OpenVPN Static key V1-----'
        profile = (PROFILE + 'tls-auth [inline] 1\nkey-direction 0\n'
                   + '<tls-auth>\n' + key + '\n</tls-auth>\n')
        with self.assertRaises(UnsupportedProfile):
            convert_ovpn(profile)


if __name__ == "__main__":
    unittest.main()
