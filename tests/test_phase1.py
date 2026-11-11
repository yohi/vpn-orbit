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

    def test_tls_auth_inline(self):
        key = '-----BEGIN OpenVPN Static key V1-----\n' + ('a' * 64 + '\n') * 8 + '-----END OpenVPN Static key V1-----'
        profile = PROFILE + '<tls-auth>\n' + key + '\n</tls-auth>\nkey-direction 1\n'
        endpoint = convert_ovpn(profile)
        self.assertEqual(endpoint["tls"]["control_wrap"]["direction"], "client")


if __name__ == "__main__":
    unittest.main()
