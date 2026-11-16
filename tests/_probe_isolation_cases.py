import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import _candidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.runner import CurlOutcome


class IsolationTests(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-orbit-probe-")
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)
        self.candidate = _candidate(self.tmp)
        self.runner = FakeRunner(self.tmp)

    def _probe(self, decision=GeoDecision.TOKYO, **kwargs):
        return probe_one(self.candidate, geo_lookup=lambda _: decision, runner=self.runner, **kwargs)

    def test_prerequisites_unavailable_returns_blocked(self):
        self.runner.prerequisites_ok_value = False
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "prerequisites_unavailable")

    def test_rejects_vpn_orbit_username_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_USERNAME":"vpn"}):
            result = self._probe()
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "environment_secret_inheritance_rejected")

    def test_rejects_vpn_orbit_password_env(self):
        with patch.dict(os.environ, {"VPN_ORBIT_PASSWORD":"vpn"}):
            self.assertEqual(self._probe().status, ProbeStatus.BLOCKED)

    def test_supervisor_starts_before_setup_isolation(self):
        self._probe()
        commands = self.runner.commands
        self.assertLess(commands.index("save ip_forward"), commands.index("supervisor started"))
        self.assertLess(commands.index("supervisor started"), commands.index("ip netns add test-ns"))

    def test_setup_isolation_called_with_remote_parameters(self):
        self._probe()
        self.assertEqual(self.runner.last_setup, ("8.8.8.8", "udp", 1195))

    def test_ip_forward_saved_and_restored(self):
        self._probe()
        self.assertTrue(self.runner.ip_forward_saved)
        self.assertTrue(self.runner.ip_forward_restored)
        self.assertIn("save ip_forward", self.runner.commands)
        self.assertIn("restore ip_forward", self.runner.commands)

    def test_ip_forward_save_failure_returns_blocked(self):
        self.runner.save_ip_forward_fails = True
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "ip_forward_save_failed")

    def test_ip_forward_restore_failure_returns_fail(self):
        self.runner.restore_ip_forward_fails = True
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("restore_ip_forward_failed", result.reason_code)

    def test_cleanup_called_on_success(self):
        self._probe()
        self.assertTrue(self.runner.cleaned)
        self.assertTrue(self.runner.supervisor_started)

    def test_timeout_returns_not_verified(self):
        self.runner.wait_for_tun_result = (None, "timeout")
        result = self._probe(timeout_s=5)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "tun_not_established")

    def test_curl_failure_returns_not_verified(self):
        self.runner.curl_result = CurlOutcome(None, "tls handshake failed")
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_fetch_failed")

    def test_non_tokyo_geo_returns_not_verified(self):
        result = self._probe(GeoDecision.NON_TOKYO)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_non_tokyo")

    def test_unknown_geo_returns_not_verified(self):
        result = self._probe(GeoDecision.UNKNOWN)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "exit_ip_geoip_unavailable")

    def test_unexpected_exit_ip_format_rejected_not_verified(self):
        self.runner.exit_ip = "not-an-ip"
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "echo_ip_not_global")

    def test_unauthorized_egress_returns_fail(self):
        self.runner.curl_result = CurlOutcome(None, "leak", "unauthorized_egress")
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "unauthorized_egress")

    def test_cleanup_failure_returns_fail(self):
        self.runner.teardown_fails = True
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertTrue(result.reason_code.startswith("cleanup_failed"))

    def test_terminate_failure_recorded_in_cleanup(self):
        self.runner.terminate_fails = True
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("terminate_failed", result.reason_code)

    def test_supervisor_cleanup_unconfirmed_returns_fail(self):
        self.runner.supervisor_cleanup_confirmed = False
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertIn("supervisor_cleanup_failed", result.reason_code)

    def test_supervisor_start_failure_returns_blocked(self):
        self.runner.supervisor_start_fails = True
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.BLOCKED)
        self.assertEqual(result.reason_code, "supervisor_start_failed")

    def test_host_default_route_unchanged(self):
        self.assertEqual(self._probe().status, ProbeStatus.PASS)
        self.assertIn("host default route check", self.runner.commands)

    def test_pre_tunnel_echo_reachable_returns_fail(self):
        self.runner.pre_tunnel_echo_blocked = False
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "pre_tunnel_echo_reachable")

    def test_route_not_via_tun0_returns_fail(self):
        self.runner.route_get_via_tun0_result = False
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "echo_route_not_tun0")

    def test_malicious_raw_profile_rejected_before_openvpn(self):
        evil = replace(self.candidate.candidate,
                       profile=self.candidate.candidate.profile + "script-security 3\nup /tmp/pwned.sh\n")
        result = probe_one(replace(self.candidate, candidate=evil),
            geo_lookup=lambda _: GeoDecision.TOKYO, runner=self.runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "profile_parse_failed")
        self.assertFalse(self.runner.supervisor_started)

    def test_openvpn_env_is_allowlisted(self):
        self._probe()
        self.assertIsNotNone(self.runner.last_openvpn_env)
        env = self.runner.last_openvpn_env
        resources = self.runner._resources
        assert env is not None and resources is not None
        self.assertNotIn("IPAPI_IS_API_KEY", env)
        self.assertIn("PATH", env)
        self.assertEqual(self.runner.last_openvpn_cwd, resources.private_dir)

    def test_curl_uses_resolve_and_interface(self):
        self._probe()
        commands = [c for c in self.runner.commands if c.startswith("curl ")]
        self.assertEqual(len(commands), 1)
        self.assertIn("--interface tun0", commands[0])
        self.assertIn("--resolve api.ipify.org:443:1.1.1.1", commands[0])

    def test_tun_ip_invalid_returns_not_verified(self):
        self.runner.wait_for_tun_result = ("not-an-ip", "ok")
        result = self._probe()
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "tun_ip_invalid")
