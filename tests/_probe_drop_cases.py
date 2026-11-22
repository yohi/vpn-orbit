import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_live_cases import RecordingCommands
from tests._probe_round3 import _candidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.live_runner import SubprocessRunner
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.runner_types import IsolationResources


class DropEvidenceTests(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.r = IsolationResources(netns="vo-test", private_dir=Path(self.temp.name),
            veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
        self.r.deadline = time.monotonic() + 30
        self.commands = RecordingCommands()
        self.runner = SubprocessRunner()
        self.runner.commands = self.commands
        self.runner.resources = self.r

    def test_curl_refused_and_counter_advanced_is_verified(self):
        ok, marker = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertTrue(ok)
        self.assertEqual(marker, "direct_drop_counter_verified")

    def test_curl_timeout_without_counter_increment_is_fail(self):
        self.commands.drop_counter_increment = False
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_counter_not_advanced")

    def test_fake_runner_success_marker_matches_drop_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            ok, marker = runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
            result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertTrue(ok)
        self.assertEqual(marker, "direct_drop_counter_verified")
        self.assertIn("host_direct_rejected:direct_drop_counter_verified", result.evidence)

    def test_drop_rule_arguments_are_fully_scoped(self):
        self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        add_rule = next(args for args, _ in self.commands.calls
                        if "nft" in args and args[args.index("nft") + 1] == "add")
        nft_index = add_rule.index("nft")
        self.assertEqual(add_rule[nft_index + 1:], [
            "add", "rule", "inet", self.r.table, "output", "oifname", "vn-test",
            "ip", "daddr", "1.1.1.1", "tcp", "dport", "443", "counter", "drop",
            "comment", "vpn-orbit-drop-evidence",
        ])

    def test_fake_runner_legacy_success_marker_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.object(runner, "host_direct_route_rejected", return_value=(True, "direct_route_rejected")):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_evidence_unavailable")

    def test_counter_read_failure_is_fail(self):
        self.commands.counter_read_fails = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_counter_unavailable")
        self.assertFalse(self._has_temporary_route_or_curl())

    def test_malformed_nft_json_is_fail(self):
        self.commands.malformed_counter_json = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_counter_invalid")

    def test_unexpected_counter_identity_is_fail(self):
        self.commands.wrong_counter_identity = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_counter_invalid")
        self.assertFalse(self._has_temporary_route_or_curl())

    def _has_temporary_route_or_curl(self) -> bool:
        return any(
            ("curl" in args) or
            ("route" in args and "replace" in args and "vn-test" in args)
            for args, _ in self.commands.calls
        )

    def test_direct_curl_success_is_fail(self):
        self.commands.curl_returncode = 0
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_curl_not_refused")

    def test_drop_rule_installed_before_temporary_route(self):
        self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        calls = [args for args, _ in self.commands.calls]
        self.assertLess(next(i for i, args in enumerate(calls) if "nft" in args and args[args.index("nft") + 1] == "add"),
                        next(i for i, args in enumerate(calls) if "route" in args and "replace" in args))

    def test_no_packet_if_drop_rule_missing(self):
        self.commands.drop_rule_install_fails = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_evidence_unavailable")
        self.assertFalse(any("curl" in args for args, _ in self.commands.calls))

    def test_temporary_echo_32_route_points_to_veth(self):
        self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        route_commands = [args for args, _ in self.commands.calls if "route" in args and "replace" in args]
        self.assertEqual(route_commands[0][-4:], ["via", "10.253.240.1", "dev", "vn-test"])
        self.assertEqual(route_commands[0][route_commands[0].index("replace") + 1], "1.1.1.1/32")
        route_operations = []
        for args, _ in self.commands.calls:
            if "route" not in args:
                continue
            route_index = args.index("route")
            operation = args[route_index + 1]
            if operation in ("add", "replace", "delete"):
                route_operations.append((operation, args[route_index + 2]))
        self.assertEqual(route_operations, [
            ("replace", "1.1.1.1/32"), ("replace", "1.1.1.1/32"),
        ])
        self.assertEqual(route_commands[0][route_commands[0].index("replace") + 1],
                         route_commands[1][route_commands[1].index("replace") + 1])

    def test_only_one_bounded_echo_packet_is_attempted(self):
        self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        curls = [args for args, _ in self.commands.calls if "curl" in args]
        self.assertEqual(len(curls), 1)
        args = curls[0]
        for flag, expected in (("--interface", "if!vn-test"),
                               ("--resolve", "api.ipify.org:443:1.1.1.1"),
                               ("--noproxy", "*"), ("--proto", "=https"),
                               ("--connect-timeout", "1"), ("--max-time", "2")):
            self.assertEqual(args[args.index(flag) + 1], expected)

    def test_tun0_echo_route_restored_before_drop_rule_removed(self):
        ok, marker = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertTrue(ok)
        self.assertEqual(marker, "direct_drop_counter_verified")
        calls = [args for args, _ in self.commands.calls]
        restore = max(i for i, args in enumerate(calls) if "route" in args and "replace" in args
                      and "tun0" in args)
        remove = next(i for i, args in enumerate(calls)
                      if "nft" in args and args[args.index("nft") + 1] == "delete")
        self.assertLess(restore, remove)

    def test_route_restore_failure_returns_fixed_runner_failure(self):
        self.commands.route_restore_fails = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_route_restore_failed")
        self.assertFalse(any("nft" in args and args[args.index("nft") + 1] == "delete"
                             for args, _ in self.commands.calls))

    def test_rule_is_not_removed_when_route_restore_is_unconfirmed(self):
        self.commands.route_restore_unconfirmed = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_route_restore_failed")
        self.assertFalse(any("nft" in args and args[args.index("nft") + 1] == "delete"
                             for args, _ in self.commands.calls))

    def test_drop_rule_cleanup_failure_yields_probe_fail(self):
        self.commands.rule_cleanup_fails = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertEqual(reason, "drop_rule_cleanup_failed")

    def test_counter_increment_without_route_restoration_is_not_pass(self):
        self.commands.route_restore_fails = True
        ok, reason = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)
        self.assertNotEqual((ok, reason), (True, "direct_drop_counter_verified"))

    def test_saved_route_attributes_are_restored(self):
        self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        restore = next(args for args, _ in reversed(self.commands.calls)
                       if "route" in args and "replace" in args and "tun0" in args)
        route_index = restore.index("route")
        self.assertEqual(restore[route_index + 2], "1.1.1.1/32")
        self.assertEqual(restore[route_index + 3:], [
            "dev", "tun0", "scope", "link", "proto", "static", "metric", "77", "src", "10.8.0.2",
        ])

    def test_route_restore_failure_yields_probe_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory), host_direct_result=(False, "drop_route_restore_failed"))
            result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_route_restore_failed")
        self.assertFalse(any("curl --interface tun0" in command for command in runner.commands))

    def test_drop_rule_cleanup_failure_stops_tunnel_https(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory), host_direct_result=(False, "drop_rule_cleanup_failed"))
            result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_rule_cleanup_failed")
        self.assertFalse(any("curl --interface tun0" in command for command in runner.commands))

    def test_drop_counter_error_yields_probe_fail_not_not_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.object(runner, "host_direct_route_rejected", side_effect=OSError("SECRET")):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_evidence_unavailable")
        self.assertNotIn("SECRET", result.reason_code)

    def test_drop_json_error_yields_probe_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.object(runner, "host_direct_route_rejected", return_value=(False, "{SECRET}")):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_evidence_unavailable")

    def test_drop_rule_mismatch_yields_probe_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.object(runner, "host_direct_route_rejected", return_value=(True, "wrong_rule")):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_evidence_unavailable")

    def test_drop_counter_no_increment_yields_probe_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.object(runner, "host_direct_route_rejected", return_value=(False, "drop_counter_not_advanced")):
                result = probe_one(_candidate(), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.reason_code, "drop_counter_not_advanced")
