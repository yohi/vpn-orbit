import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_orbit.isolation import provision
from vpn_orbit.live_runner import SubprocessRunner
from vpn_orbit.probe_commands import Commands
from vpn_orbit.runner_types import IsolationResources


class RecordingCommands(Commands):
    def __init__(self):
        super().__init__(time.monotonic() + 30)
        self.calls = []

    def run(self, args, *, data=None):
        self.calls.append((list(args), data))
        text = ""
        if args[:4] == ["ip", "-j", "-4", "addr"]:
            text = "[]"
        elif args[:5] == ["ip", "-j", "-4", "route", "get"]:
            text = '[{"dev":"eth0"}]'
        elif args[:4] == ["ip", "-j", "-4", "route"]:
            text = "[]"
        elif "route" in args and "show" in args and "-j" in args:
            text = json.dumps([{"dst":"8.8.8.8", "dev":"vn-test"},
                {"dst":"10.253.240.0/30", "dev":"vn-test", "protocol":"kernel"}])
        elif "route" in args and "get" in args:
            if "oif" in args:
                return subprocess.CompletedProcess(args, 2, "", "")
            text = "1.1.1.1 dev tun0 src 10.8.0.2"
        elif "curl" in args:
            if "--write-out" in args:
                text = "8.8.4.4\n200"
            else:
                return subprocess.CompletedProcess(args, 7, "", "")
        return subprocess.CompletedProcess(args, 0, text, "")


class LiveRunnerTests(unittest.TestCase):
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

    def test_short_lived_openvpn_error_reports_fixed_code_only(self):
        class ExitedProcess:
            def poll(self):
                return 1

        (self.r.private_dir / "openvpn.log").write_text(
            "VERIFY ERROR: test certificate failure, secret=DO_NOT_PRINT"
        )
        result, reason = self.runner.wait_for_tun(ExitedProcess(), self.r, self.r.deadline)
        self.assertIsNone(result)
        self.assertEqual(reason, "tun_unavailable")
        self.assertEqual(self.runner.openvpn_failure_code, "tls_verification_failed")
        self.assertNotIn("DO_NOT_PRINT", self.runner.openvpn_failure_code)

    def test_process_exit_and_progress_are_fixed_codes(self):
        class Exited:
            def poll(self):
                return 1

        (self.r.private_dir / "openvpn.log").write_text(
            "TLS: Initial packet from 8.8.8.8; VERIFY ERROR: SECRET_NOT_TO_LOG"
        )
        tun, code = self.runner.wait_for_tun(Exited(), self.r, self.r.deadline)
        self.assertIsNone(tun)
        self.assertEqual(code, "tun_unavailable")
        self.assertEqual(self.runner.openvpn_process_state, "exited")
        self.assertEqual(self.runner.openvpn_progress, "tls_packet_seen")
        self.assertEqual(self.runner.openvpn_failure_code, "tls_verification_failed")

    def test_passive_link_io_observation_only_reads_veth_statistics(self):
        report = json.dumps([{"ifname": "vn-test", "stats64": {
            "rx": {"packets": 2}, "tx": {"packets": 3},
        }}])
        with patch.object(self.commands, "run",
                          return_value=subprocess.CompletedProcess([], 0, report, "")) as run:
            self.runner._sample_link_io(self.r)
        self.assertEqual(self.runner.link_io, "bidirectional")
        self.assertEqual(run.call_args.args[0], [
            "ip", "netns", "exec", "vo-test", "ip", "-s", "-j",
            "link", "show", "dev", "vn-test",
        ])
        self.assertNotIn("SECRET", self.runner.link_io)

    def test_passive_link_io_failure_does_not_raise(self):
        with patch.object(self.commands, "run", side_effect=OSError("SENSITIVE_LOG")):
            self.runner._sample_link_io(self.r)
        self.assertEqual(self.runner.link_io, "unavailable")

    def test_actual_setup_commands_confine_remote_and_drop_other_traffic(self):
        # Given a real command builder with the privileged syscall seam recorded.
        with patch("vpn_orbit.isolation.Path.write_text") as forward:
            # When it provisions isolation.
            provision(self.r, self.commands)
        # Then only the remote /32 gets a veth route, with dedicated deny rules.
        calls = self.commands.calls
        self.assertIn((["ip", "netns", "add", "vo-test"], None), calls)
        self.assertIn((["ip", "addr", "add", "10.253.240.1/30", "dev", "vh-test"], None), calls)
        route_args = [args for args, _ in calls if "route" in args and "add" in args]
        self.assertEqual(route_args, [["ip", "netns", "exec", "vo-test", "ip", "-4", "route", "add",
            "8.8.8.8/32", "via", "10.253.240.1", "dev", "vn-test"]])
        rules = [data for _, data in calls if data]
        self.assertIn("ip daddr 8.8.8.8 udp dport 1195 masquerade", rules[0])
        self.assertIn('iifname "vh-test" drop', rules[0])
        self.assertIn('oifname "vh-test" drop', rules[0])
        self.assertEqual(rules[1].count("policy drop"), 2)
        self.assertNotIn("ip6", rules[1])
        self.assertNotIn("dport 53", rules[1])
        forward.assert_called_once_with("1")

    def test_real_route_evidence_installs_echo_only_on_tun0(self):
        # Given the allowed transport and connected veth route.
        # When the tunnel evidence is gathered.
        ok, detail = self.runner.route_get_via_tun0("1.1.1.1", self.r, self.r.deadline)
        # Then the production command includes tun0 and records the route output.
        self.assertTrue(ok)
        self.assertIn("dev tun0", detail)
        self.assertIn((["ip", "netns", "exec", "vo-test", "ip", "-4", "route", "add",
                        "1.1.1.1/32", "dev", "tun0"], None), self.commands.calls)

    def test_real_curl_command_pins_resolve_and_tls_interface(self):
        # Given the resolved echo target, independent of the observed exit.
        self.r.echo_ip = "1.1.1.1"
        # When the production HTTPS runner executes.
        result = self.runner.curl_via_tun("https://api.ipify.org/", ("api.ipify.org", 443, "1.1.1.1"),
                                         "tun0", self.r, self.r.deadline)
        # Then it is bound, pinned, proxy-free, TLS verified, and bounded.
        args = self.commands.calls[-1][0]
        self.assertEqual(result.body, "8.8.4.4")
        for flag, expected in (("--interface", "tun0"), ("--resolve", "api.ipify.org:443:1.1.1.1"),
            ("--noproxy", "*"), ("--proto", "=https"), ("--max-filesize", "64")):
            self.assertEqual(args[args.index(flag) + 1], expected)
        self.assertNotIn("-k", args)
        self.assertNotIn("--location", args)

    def test_direct_route_rejection_uses_veth_not_host_echo(self):
        # Given the actual adapter after the tunnel is up.
        # When the bypass is tested.
        ok, detail = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        # Then route and connection refusal are both required inside the namespace.
        self.assertTrue(ok)
        self.assertEqual(detail, "route_exit_2;curl_exit_7")
        route, curl = [args for args, _ in self.commands.calls]
        self.assertEqual(route[-2:], ["oif", "vn-test"])
        self.assertEqual(curl[curl.index("--interface") + 1], "vn-test")
