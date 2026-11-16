import tempfile
import unittest
from pathlib import Path

from vpn_orbit.openvpn_diagnostics import (
    OPENVPN_DIAGNOSTIC_CODES, classify_openvpn_log,
)


class OpenVPNDiagnosticTests(unittest.TestCase):
    def test_fixed_categories_and_redaction(self):
        samples = {
            'AUTH_FAILED token=ULTRA-SECRET': 'auth_failed',
            'VERIFY ERROR: depth=0, secret=ULTRA-SECRET': 'tls_verification_failed',
            'Cannot open TUN/TAP dev /dev/net/tun': 'tun_device_error',
            'Options error: unknown option: ULTRA-SECRET': 'configuration_error',
            'TLS Error: TLS key negotiation failed to occur within 60 seconds': 'transport_timeout',
            'TLS Error: TLS handshake failed': 'tls_handshake_failed',
            'TCP: connect to 1.2.3.4:443 failed: Connection refused': 'transport_error',
            'Initialization Sequence Completed': 'initialization_observed',
            'UDP link remote: [AF_INET]1.2.3.4:1234': 'no_diagnostic_signal',
        }
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'openvpn.log'
            for raw, expected in samples.items():
                with self.subTest(expected=expected):
                    log.write_text(raw)
                    result = classify_openvpn_log(log)
                    self.assertEqual(result, expected)
                    self.assertIn(result, OPENVPN_DIAGNOSTIC_CODES)
                    self.assertNotIn('ULTRA-SECRET', result)
                    self.assertNotIn('1.2.3.4', result)

    def test_tail_limit_and_absent_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'openvpn.log'
            self.assertEqual(classify_openvpn_log(log), 'log_unavailable')
            log.write_bytes(b'options error:' + b'Z' * 70000 + b'AUTH_FAILED secret')
            self.assertEqual(classify_openvpn_log(log), 'auth_failed')

    def test_priority_prefers_verification_over_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'openvpn.log'
            log.write_text('TLS Error: TLS handshake failed\nVERIFY ERROR: cert mismatch')
            self.assertEqual(classify_openvpn_log(log), 'tls_verification_failed')


if __name__ == '__main__':
    unittest.main()
