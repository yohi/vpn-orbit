import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from vpn_orbit.isolation import _forward_rules, _install_forward_rules, _remove_forward_rules
from vpn_orbit.probe_commands import Commands
from vpn_orbit.runner_types import IsolationResources


class FakeIptables(Commands):
    def __init__(self, *, available=True, delete_fails=False):
        super().__init__(time.monotonic() + 5)
        self.available, self.delete_fails = available, delete_fails
        self.rules: list[list[str]] = []
        self.calls: list[list[str]] = []

    def run(self, args, *, data=None):
        args = list(args)
        self.calls.append(args)
        if not self.available:
            raise FileNotFoundError("iptables")
        op = args[3]
        if op == "-S":
            body = "-P FORWARD DROP\n" + "\n".join("-A FORWARD " + " ".join(r) for r in self.rules)
            return subprocess.CompletedProcess(args, 0, body, "")
        if op == "-I":
            self.rules.insert(0, args[6:])
        elif op == "-D" and not self.delete_fails:
            self.rules.remove(args[5:])
        return subprocess.CompletedProcess(args, 1 if (op == "-D" and self.delete_fails) else 0, "", "")


def _resources(root: Path, protocol="tcp") -> IsolationResources:
    return IsolationResources(netns="vo-t", private_dir=root / "p", veth_host="vh-t",
                              veth_ns="vn-t", remote_ip="8.8.8.8", protocol=protocol, port=443)


class ForwardRuleTests(unittest.TestCase):
    def test_rules_are_scoped_and_tagged(self):
        with tempfile.TemporaryDirectory() as d:
            r = _resources(Path(d))
            out, back = _forward_rules(r)
            self.assertIn("vh-t", out)
            self.assertIn("8.8.8.8", out)
            self.assertIn("443", out)
            self.assertIn("ESTABLISHED", back)
            for rule in (out, back):
                self.assertIn(f"vo:{r.table}", rule)
                self.assertEqual(rule[-2:], ["-j", "ACCEPT"])

    def test_install_then_remove_leaves_no_rules(self):
        with tempfile.TemporaryDirectory() as d:
            r = _resources(Path(d))
            cmds = FakeIptables()
            _install_forward_rules(r, cmds)
            self.assertEqual(len(cmds.rules), 2)
            self.assertTrue(_remove_forward_rules(r, cmds))
            self.assertEqual(cmds.rules, [])

    def test_failed_delete_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            r = _resources(Path(d))
            cmds = FakeIptables()
            _install_forward_rules(r, cmds)
            cmds.delete_fails = True
            self.assertFalse(_remove_forward_rules(r, cmds))

    def test_missing_iptables_is_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            r = _resources(Path(d))
            self.assertTrue(_remove_forward_rules(r, FakeIptables(available=False)))

    def test_install_skips_forward_rules_when_iptables_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            commands = FakeIptables(available=False)

            _install_forward_rules(_resources(Path(d)), commands)

            self.assertEqual(len(commands.calls), 1)
            self.assertEqual(commands.rules, [])


if __name__ == "__main__":
    unittest.main()
