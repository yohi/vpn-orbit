import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_round3 import _candidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.isolation import remove_resources
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.probe_commands import Commands
from vpn_orbit.runner_types import IsolationResources


class CleanupCommands(Commands):
    def __init__(self, resources: IsolationResources) -> None:
        super().__init__(time.monotonic() + 5)
        self.resources = resources
        self.present = {"link", "table", "netns"}
        self.delete_fails = False
        self.delete_reports_error = False
        self.confirm_fails = False
        self.malformed = False
        self.calls: list[list[str]] = []

    def run(self, args, *, data=None):
        args = list(args)
        self.calls.append(args)
        if "del" in args or "delete" in args:
            kind = "table" if args[0] == "nft" else args[1]
            if not self.delete_fails:
                self.present.discard(kind)
            return subprocess.CompletedProcess(args, 1 if self.delete_fails or self.delete_reports_error else 0, "", "")
        if self.confirm_fails and args != ["ip", "netns", "list"]:
            return subprocess.CompletedProcess(args, 1, "permission denied", "")
        if self.malformed:
            return subprocess.CompletedProcess(args, 0, "malformed", "")
        if args == ["ip", "-j", "link", "show"]:
            body = json.dumps([{"ifname": self.resources.veth_host}] if "link" in self.present else [])
        elif args == ["nft", "-j", "list", "tables"]:
            body = json.dumps({"nftables": [{"table": {"family": "inet", "name": self.resources.table}}]
                               if "table" in self.present else []})
        elif args == ["ip", "netns", "list"]:
            body = self.resources.netns if "netns" in self.present else ""
        else:
            body = ""
            return subprocess.CompletedProcess(args, 0 if self.present else 1, body, "")
        return subprocess.CompletedProcess(args, 0, body, "")


class CleanupConfirmationTests(unittest.TestCase):
    def test_nonzero_delete_is_not_ignored_even_if_resource_disappears(self):
        with tempfile.TemporaryDirectory() as directory:
            r = IsolationResources(netns="vo-test", private_dir=Path(directory) / "private",
                veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
            commands = CleanupCommands(r)
            commands.delete_reports_error = True
            self.assertFalse(remove_resources(r, commands))
            self.assertFalse(commands.present)
            self.assertTrue(remove_resources(r, commands))

    def test_confirmation_denial_forces_probe_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            def teardown(resources: IsolationResources) -> tuple[bool, str]:
                commands = CleanupCommands(resources)
                commands.confirm_fails = True
                with patch("vpn_orbit.isolation.Path.write_text"):
                    return remove_resources(resources, commands), "confirmation_unavailable"
            with patch.object(runner, "teardown_isolation", side_effect=teardown):
                result = probe_one(_candidate(), runner=runner, geo_lookup=lambda _: GeoDecision.TOKYO)
            self.assertEqual(result.status, ProbeStatus.FAIL)
            self.assertIn("teardown_failed", result.reason_code)

    def test_confirmation_denial_is_not_absence(self):
        # Given successful deletes but an unavailable confirmation operation.
        with tempfile.TemporaryDirectory() as directory:
            r = IsolationResources(netns="vo-test", private_dir=Path(directory) / "private",
                veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
            commands = CleanupCommands(r)
            commands.confirm_fails = True
            # When cleanup tries to confirm absence.
            result = remove_resources(r, commands)
            # Then failed inspection cannot authorize PASS.
            self.assertFalse(result)

    def test_nonzero_delete_does_not_confirm_cleanup(self):
        # Given delete failures that leave the owned resources present.
        with tempfile.TemporaryDirectory() as directory:
            r = IsolationResources(netns="vo-test", private_dir=Path(directory) / "private",
                veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
            commands = CleanupCommands(r)
            commands.delete_fails = True
            # When cleanup runs.
            result = remove_resources(r, commands)
            # Then it retains responsibility and reports failure.
            self.assertFalse(result)

    def test_successful_enumeration_confirms_idempotent_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            r = IsolationResources(netns="vo-test", private_dir=Path(directory) / "private",
                veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
            commands = CleanupCommands(r)
            self.assertTrue(remove_resources(r, commands))
            commands.calls.clear()
            self.assertTrue(remove_resources(r, commands))
            self.assertFalse(any("del" in c or "delete" in c for c in commands.calls))

    def test_malformed_success_output_cannot_confirm_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            r = IsolationResources(netns="vo-test", private_dir=Path(directory) / "private",
                veth_host="vh-test", veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
            commands = CleanupCommands(r)
            commands.malformed = True
            self.assertFalse(remove_resources(r, commands))
