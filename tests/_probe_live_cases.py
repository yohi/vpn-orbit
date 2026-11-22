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
        self.drop_counter_increment = True
        self.counter_read_fails = False
        self.malformed_counter_json = False
        self.wrong_counter_identity = False
        self.drop_rule_install_fails = False
        self.route_restore_fails = False
        self.route_restore_unconfirmed = False
        self.rule_cleanup_fails = False
        self.curl_returncode = 7
        self.drop_rule_installed = False
        self.route_via_veth = False
        self.original_route_record = {
            "dst": "1.1.1.1/32", "dev": "tun0", "scope": "link", "protocol": "static",
            "metric": 77, "prefsrc": "10.8.0.2",
        }
        self.current_route_record = self.original_route_record.copy()
        self.counter = 0
        self.counter_reads = 0

    def run(self, args, *, data=None):
        self.calls.append((list(args), data))
        text = ""
        if "nft" in args and "add" in args:
            if self.drop_rule_install_fails:
                return subprocess.CompletedProcess(args, 1, "", "")
            self.drop_rule_installed = True
        elif "nft" in args and "list" in args and "chain" in args:
            self.counter_reads += 1
            if self.counter_read_fails and self.counter_reads == 1:
                return subprocess.CompletedProcess(args, 1, "", "")
            if self.malformed_counter_json and self.counter_reads == 1:
                return subprocess.CompletedProcess(args, 0, "{invalid", "")
            if self.drop_rule_installed:
                expression = [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}},
                               "right": "different" if self.wrong_counter_identity else "vn-test"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                               "right": "1.1.1.1"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                               "right": 443}},
                    {"counter": {"packets": self.counter, "bytes": 0}},
                    {"drop": None},
                ]
                text = json.dumps({"nftables": [{"rule": {"family": "inet", "table": args[-2],
                    "chain": "output", "handle": 42, "comment": "vpn-orbit-drop-evidence",
                    "expr": expression}}]})
            else:
                text = json.dumps({"nftables": []})
        elif "nft" in args and "delete" in args and "rule" in args:
            if self.rule_cleanup_fails:
                return subprocess.CompletedProcess(args, 1, "", "")
            self.drop_rule_installed = False
        elif "route" in args and "replace" in args:
            if "tun0" in args and self.route_restore_fails:
                return subprocess.CompletedProcess(args, 1, "", "")
            route_index = args.index("route")
            destination_index = route_index + 2
            parsed_route: dict[str, str | int] = {"dst": args[destination_index]}
            if parsed_route["dst"] == "unicast":
                parsed_route["type"] = "unicast"
                destination_index += 1
                parsed_route["dst"] = args[destination_index]
            options = {"dev": "dev", "scope": "scope", "proto": "protocol",
                       "metric": "metric", "src": "prefsrc", "table": "table", "via": "gateway"}
            option_index = destination_index + 1
            while option_index < len(args):
                option = args[option_index]
                field_name = options.get(option)
                if field_name is None:
                    option_index += 1
                    continue
                parsed_value = args[option_index + 1]
                parsed_route[field_name] = int(parsed_value) if field_name == "metric" else parsed_value
                option_index += 2
            if "tun0" in args and self.route_restore_unconfirmed:
                self.route_via_veth = True
            else:
                self.current_route_record = parsed_route
                self.route_via_veth = parsed_route.get("dev") == "vn-test"
        elif "route" in args and "show" in args and "-j" in args:
            if "exact" in args:
                text = json.dumps([self.current_route_record])
            elif "netns" in args:
                text = json.dumps([{"dst": "8.8.8.8/32", "dev": "vn-test"},
                    {"dst": "10.253.240.0/30", "dev": "vn-test", "protocol": "kernel"}])
            else:
                text = "[]"
        elif args[:4] == ["ip", "-j", "-4", "addr"]:
            text = "[]"
        elif "route" in args and "get" in args and "-j" in args:
            text = '[{"dev":"eth0"}]'
        elif "route" in args and "get" in args:
            if "oif" in args:
                return subprocess.CompletedProcess(args, 2, "", "")
            text = ("1.1.1.1 via 10.253.240.1 dev vn-test src 10.253.240.2"
                    if self.route_via_veth else "1.1.1.1 dev tun0 src 10.8.0.2")
        elif "curl" in args:
            if "--write-out" in args:
                text = "8.8.4.4\n200"
            else:
                if self.drop_rule_installed and self.route_via_veth and self.curl_returncode in (7, 28) and self.drop_counter_increment:
                    self.counter += 1
                return subprocess.CompletedProcess(args, self.curl_returncode, "", "")
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

    def test_direct_rejection_ignores_route_get_exit_but_requires_curl_refusal(self):
        self.commands.curl_returncode = 28
        ok, detail = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertTrue(ok)
        self.assertEqual(detail, "direct_drop_counter_verified")
        self.commands = RecordingCommands()
        self.runner.commands = self.commands
        self.commands.curl_returncode = 0
        ok, _ = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        self.assertFalse(ok)

    def test_direct_route_rejection_uses_veth_not_host_echo(self):
        # Given the actual adapter after the tunnel is up.
        # When the bypass is tested.
        ok, detail = self.runner.host_direct_route_rejected("1.1.1.1", self.r, self.r.deadline)
        # Then route and connection refusal are both required inside the namespace.
        self.assertTrue(ok)
        self.assertEqual(detail, "direct_drop_counter_verified")
        curl = next(args for args, _ in self.commands.calls if "curl" in args)
        self.assertEqual(curl[curl.index("--interface") + 1], "if!vn-test")
