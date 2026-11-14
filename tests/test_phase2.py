import base64
import json
from pathlib import Path
import tempfile
import unittest

from vpn_orbit.phase1 import UnsupportedProfile, build_config
from vpn_orbit.phase2 import merge_profiles, main

CA = (Path(__file__).parent / 'fixtures' / 'test-ca.pem').read_text()
CA2 = (Path(__file__).parent / 'fixtures' / 'test-ca-alt.pem').read_text()


def profile(ip='8.8.8.8', ca=CA, extra=''):
    return f'''client
proto udp
remote {ip} 1195
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{ca}</ca>
{extra}'''


class Phase2Tests(unittest.TestCase):
    def test_same_ca_multiremote_preserves_tls_and_route(self):
        result = merge_profiles([('a', profile()), ('b', profile('9.9.9.9'))])
        endpoint = result.endpoint
        self.assertEqual(len(endpoint['servers']), 2)
        self.assertEqual([s['server'] for s in endpoint['servers']], ['8.8.8.8', '9.9.9.9'])
        self.assertNotIn('server', endpoint)
        self.assertTrue(endpoint['block_ipv6'])
        self.assertEqual(endpoint['tls']['remote_certificate_tls'], 'server')
        config = build_config(endpoint)
        self.assertEqual(config['route']['final'], 'vpn-gate')
        self.assertEqual(config['dns']['servers'][0]['detour'], 'vpn-gate')
        self.assertEqual(config['inbounds'][0]['route_exclude_address'],
                         ['8.8.8.8/32', '9.9.9.9/32'])
        self.assertNotIn('route_address', config['inbounds'][0])
        self.assertNotIn('inet6_route_address', config['inbounds'][0])
        self.assertNotIn('outbounds', config)
        self.assertFalse(result.ca_union)

    def test_default_ca_mismatch_fails_closed(self):
        with self.assertRaisesRegex(UnsupportedProfile, 'fewer than two compatible'):
            merge_profiles([('a', profile()), ('b', profile('9.9.9.9', CA2))])

    def test_explicit_ca_union_reports_trust_expansion(self):
        result = merge_profiles(
            [('a', profile()), ('b', profile('9.9.9.9', CA2))], allow_ca_union=True,
        )
        self.assertTrue(result.ca_union)
        self.assertEqual(len(result.endpoint['tls']['certificate']), 2)

    def test_identity_constraints_not_removed_on_union(self):
        with self.assertRaises(UnsupportedProfile):
            merge_profiles([
                ('a', profile(extra='verify-x509-name first name\n')),
                ('b', profile('9.9.9.9', CA2, extra='verify-x509-name second name\n')),
            ], allow_ca_union=True)

    def test_different_client_identities_not_merged_even_with_ca_union(self):
        def key(n):
            der = b"\x30\x1e" + bytes([n]) * 30
            return ("-----BEGIN RSA PRIVATE KEY-----\n"
                    + base64.b64encode(der).decode()
                    + "\n-----END RSA PRIVATE KEY-----\n")
        a = profile(extra=f"<cert>\n{CA}</cert>\n<key>\n{key(1)}</key>\n")
        b = profile('9.9.9.9', extra=f"<cert>\n{CA}</cert>\n<key>\n{key(2)}</key>\n")
        with self.assertRaisesRegex(UnsupportedProfile, "fewer than two compatible"):
            merge_profiles([('a', a), ('b', b)], allow_ca_union=True)

    def test_tls_wrap_difference_skipped(self):
        key = '-----BEGIN OpenVPN Static key V1-----\n' + ('a' * 64 + '\n') * 8 + '-----END OpenVPN Static key V1-----'
        wrapped = profile('9.9.9.9', extra=f'<tls-auth>\n{key}\n</tls-auth>\nkey-direction 1\n')
        with self.assertRaises(UnsupportedProfile):
            merge_profiles([('a', profile()), ('b', wrapped)], allow_ca_union=True)

    def test_duplicate_ip_skipped(self):
        with self.assertRaises(UnsupportedProfile):
            merge_profiles([('a', profile()), ('duplicate', profile())])

    def test_invalid_first_candidate_does_not_block_good_pair(self):
        result = merge_profiles([('broken', 'up /bin/sh\n'), ('a', profile()), ('b', profile('9.9.9.9'))])
        self.assertEqual(result.accepted, ('a', 'b'))
        self.assertEqual(len(result.rejected), 1)

    def test_mismatched_auth_or_ciphers_fails_closed(self):
        with self.assertRaises(UnsupportedProfile):
            merge_profiles([('a', profile()), ('b', profile('9.9.9.9').replace('auth SHA1', 'auth SHA256'))])

    def test_command_does_not_overwrite_and_sets_private_mode(self):
        with tempfile.TemporaryDirectory() as td:
            a, b, target = (Path(td) / name for name in ('a.ovpn', 'b.ovpn', 'out.json'))
            a.write_text(profile())
            b.write_text(profile('9.9.9.9'))
            self.assertEqual(main(['--ovpn', str(a), str(b), '--output', str(target)]), 0)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(json.loads(target.read_text())['endpoints'][0]['servers']), 2)
            self.assertEqual(main(['--ovpn', str(a), str(b), '--output', str(target)]), 1)

    def test_one_input_rejected(self):
        with self.assertRaises(UnsupportedProfile):
            merge_profiles([('a', profile())])

    def test_max_server_limit_and_skip(self):
        result = merge_profiles([
            ('a', profile()), ('bad', profile('9.9.9.9', CA2)),
            ('b', profile('9.9.9.9')), ('c', profile('1.1.1.1'))
        ], max_servers=2)
        self.assertEqual(result.accepted, ('a', 'b'))
        self.assertEqual(len(result.rejected), 2)

if __name__ == '__main__':
    unittest.main()

# Distinct CA/crypto defaults often mean the top-ranked server is an outlier.
# Choose a compatible group from lower-ranked candidates instead of failing.
class GroupSelectionTests(unittest.TestCase):
    def test_selects_largest_compatible_group(self):
        group = merge_profiles([
            ('outlier', profile('1.1.1.1', CA2)),
            ('one', profile('8.8.8.8')),
            ('two', profile('9.9.9.9')),
        ])
        self.assertEqual(group.accepted, ('one', 'two'))
        self.assertEqual(group.rejected[0].source, 'outlier')
