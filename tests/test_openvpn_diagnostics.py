import json
import tempfile
import unittest
from pathlib import Path

from vpn_orbit.openvpn_diagnostics import (
    OPENVPN_DIAGNOSTIC_CODES, OPENVPN_PROGRESS_CODES, PROCESS_STATES,
    LINK_IO_CODES, MAX_LOG_TAIL, advance_progress, classify_link_io,
    classify_openvpn_log, observe_openvpn_log,
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
            self.assertEqual(MAX_LOG_TAIL, 65536)

    def test_priority_prefers_verification_over_handshake(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'openvpn.log'
            log.write_text('TLS Error: TLS handshake failed\nVERIFY ERROR: cert mismatch')
            self.assertEqual(classify_openvpn_log(log), 'tls_verification_failed')

    def test_progress_is_redacted_and_monotonic(self):
        samples = {
            'UDP link remote: [AF_INET]1.2.3.4:1195 SECRET': 'remote_selected',
            'TCP connection established with 1.2.3.4': 'transport_connected',
            'TLS: Initial packet from 1.2.3.4:5678': 'tls_packet_seen',
            'Peer Connection Initiated with [AF_INET]1.2.3.4:5678': 'peer_connected',
            'Initialization Sequence Completed': 'initialized',
            'any-other-log SECRET': 'no_progress_signal',
        }
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'openvpn.log'
            for raw, expected in samples.items():
                log.write_text(raw)
                code, progress = observe_openvpn_log(log)
                self.assertEqual(progress, expected)
                self.assertIn(progress, OPENVPN_PROGRESS_CODES)
                self.assertNotIn('SECRET', progress)
            self.assertEqual(advance_progress('peer_connected', 'remote_selected'), 'peer_connected')
            self.assertEqual(advance_progress('remote_selected', 'tls_packet_seen'), 'tls_packet_seen')
            self.assertEqual(advance_progress('evil_secret', 'tls_packet_seen'), 'not_observed')

    def test_link_packets_are_only_advisory_codes(self):
        for rx, tx, expected in ((0, 0, 'no_packets'), (0, 5, 'tx_only'),
                                 (2, 0, 'rx_only'), (4, 3, 'bidirectional')):
            raw = json.dumps([{'ifname': 'vn-test', 'stats64': {
                'rx': {'packets': rx}, 'tx': {'packets': tx}}}])
            self.assertEqual(classify_link_io(raw, 'vn-test'), expected)
            self.assertIn(expected, LINK_IO_CODES)
        for bad in ('broken', '{}', '[]', '[{"ifname":"evil", "stats":{}}]',
                    '[{"ifname":"vn-test","stats":{"rx":{"packets":true},"tx":{"packets":0}}}]'):
            self.assertEqual(classify_link_io(bad, 'vn-test'), 'unavailable')
        self.assertIn('running', PROCESS_STATES)


if __name__ == '__main__':
    unittest.main()
