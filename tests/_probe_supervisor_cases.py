import json
import multiprocessing
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from vpn_orbit.isolation import _install_forward_rules
from vpn_orbit.runner_types import IsolationResources
from vpn_orbit.probe_commands import CommandUnavailable, IsolationUnavailable
from vpn_orbit.supervisor import serve
from vpn_orbit.supervisor_client import SupervisorClient


def _serve_with_tools(channel, other_fd, resources, binary_dir, state):
    from vpn_orbit.probe_commands import SAFE_ENV
    os.close(other_fd)
    os.setsid()
    SAFE_ENV.update(PATH=str(binary_dir) + ":/usr/bin:/bin", VPN_TEST_STATE=str(state))
    serve(channel, resources)


def _tools(tmp_path):
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    tool = binary_dir / "tool"
    tool.write_text(f"#!{sys.executable}\n" + '''
import json, os, signal, socket, subprocess, sys
from pathlib import Path
root = Path(os.environ["VPN_TEST_STATE"])
args = sys.argv[1:]
name = Path(sys.argv[0]).name
if name in ("openvpn", "openssl"):
    (root / (name + ".pid")).write_text(str(os.getpid()))
    (root / (name + ".parent")).write_text(str(os.getppid()))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([sys.executable, "-c", "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); signal.pause()"], stdout=subprocess.PIPE)
    child.stdout.readline()
    (root / "helper.pid").write_text(str(child.pid))
    with socket.socket(socket.AF_UNIX) as ready:
        ready.connect(str(root / "ready.sock"))
    print("Initialization Sequence Completed", flush=True)
    signal.pause()
elif name == "ip" and args[:2] == ["netns", "exec"]:
    os.execvp(args[3], args[3:])
elif name == "ip" and args[:2] == ["netns", "del"]:
    (root / "netns").unlink(missing_ok=True)
elif name == "ip" and args[:2] == ["netns", "list"]:
    print("vo-test" if (root / "netns").exists() else "")
elif name == "ip" and args[:2] == ["link", "del"]:
    (root / "veth").unlink(missing_ok=True)
elif name == "ip" and args == ["-j", "link", "show"]:
    print(json.dumps([{"ifname":"vh-test"}] if (root / "veth").exists() else []))
elif name == "nft" and args[0] == "delete":
    (root / "nft").unlink(missing_ok=True)
elif name == "nft" and args == ["-j", "list", "tables"]:
    if (root / "deny_confirmation").exists():
        sys.exit(1)
    print(json.dumps({"nftables":[{"table":{"family":"inet", "name":(root / "nft").read_text()}}]
                     if (root / "nft").exists() else []}))
''')
    tool.chmod(0o700)
    for name in ("ip", "nft", "openvpn", "openssl"):
        (binary_dir / name).symlink_to(tool)
    return binary_dir


def _check_supervisor_kills_reaps_and_cleans(tmp_path, termination):
    # Given real supervisor and verifier processes, with OS network calls sandboxed at executable boundaries.
    binaries = _tools(tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    (private / "client.ovpn").write_text("client")
    for name in ("netns", "veth", "nft"):
        (tmp_path / name).touch()
    r = IsolationResources(netns="vo-test", private_dir=private, veth_host="vh-test",
        veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
    r.deadline = time.monotonic() + (1 if termination in ("deadline", "race") else 20)
    (tmp_path / "nft").write_text(r.table)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(tmp_path / "ready.sock"))
    listener.listen(1)
    listener.settimeout(5)
    owner_channel, supervisor_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    context = multiprocessing.get_context("fork")
    supervisor = context.Process(target=_serve_with_tools,
        args=(supervisor_channel, owner_channel.fileno(), r, binaries, tmp_path))
    supervisor.start()
    supervisor_channel.close()
    verifier_code = '''
import json, signal, socket, sys
from types import SimpleNamespace
from vpn_orbit.supervisor_client import SupervisorClient
with socket.socket(fileno=int(sys.argv[1])) as channel:
    client = SupervisorClient.__new__(SupervisorClient)
    client.channel = channel
    client.deadline = float(sys.argv[2])
    client.resources = SimpleNamespace(deadline=client.deadline)
    channel.recv(65536)
    channel.send(b'{"op":"start"}')
    reply = json.loads(channel.recv(65536))
    print(reply["pid"], flush=True)
    def finish(signum, frame):
        assert client.request("stop")["ok"]
        assert client.request("cleanup")["ok"]
        sys.exit(0)
    signal.signal(signal.SIGUSR1, finish)
    signal.pause()
'''
    verifier = subprocess.Popen([sys.executable, "-c", verifier_code, str(owner_channel.fileno()), str(r.deadline)],
        pass_fds=(owner_channel.fileno(),), stdout=subprocess.PIPE, text=True)
    owner_channel.close()
    output = verifier.stdout
    assert output is not None
    try:
        assert select.select([output], [], [], 5)[0]
        pid = int(output.readline())
        ready, _ = listener.accept()
        ready.close()
        helper_file = tmp_path / "helper.pid"
        assert helper_file.exists()
        helper = int(helper_file.read_text())
        # When the verifier is forcibly killed, without finally/atexit.
        match termination:
            case "sigkill":
                verifier.kill()
                verifier.wait(timeout=2)
            case "normal":
                verifier.send_signal(signal.SIGUSR1)
                assert verifier.wait(timeout=8) == 0
            case "deadline":
                assert verifier.poll() is None
            case "race":
                # Wait for autonomous cleanup, not a guessed scheduling delay.
                until = time.monotonic() + 8
                while private.exists() and time.monotonic() < until:
                    time.sleep(0.01)
                assert not private.exists()
                verifier.send_signal(signal.SIGUSR1)
                assert verifier.wait(timeout=8) == 0
        supervisor.join(timeout=12)
        # Then its independent supervisor kills and reaps both generations and removes owned resources.
        assert supervisor.exitcode == 0
        assert not Path(f"/proc/{pid}").exists()
        assert not Path(f"/proc/{helper}").exists()
        assert not private.exists()
        assert all(not (tmp_path / name).exists() for name in ("netns", "veth", "nft"))
    finally:
        if verifier.poll() is None:
            verifier.kill()
            verifier.wait(timeout=2)
        if supervisor.is_alive():
            supervisor.kill()
            supervisor.join(timeout=2)
        output.close()
        listener.close()


class SupervisorTests(unittest.TestCase):
    def test_missing_iptables_keeps_supervisor_available_through_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = _tools(root)
            private = root / "private"
            private.mkdir(mode=0o700)
            resources = IsolationResources(
                netns="vo-test", private_dir=private, veth_host="vh-test",
                veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195,
            )
            resources.deadline = time.monotonic() + 15
            owner_channel, supervisor_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            supervisor = multiprocessing.get_context("fork").Process(
                target=_serve_with_tools,
                args=(supervisor_channel, owner_channel.fileno(), resources, binaries, root),
            )
            supervisor.start()
            supervisor_channel.close()
            owner_channel.settimeout(5)
            self.assertEqual(json.loads(owner_channel.recv(65536)), {"ok": True})
            client = SupervisorClient.__new__(SupervisorClient)
            client.channel = owner_channel
            client.resources = resources
            client.deadline = resources.deadline

            try:
                with self.assertRaises(CommandUnavailable):
                    client.checked(["iptables", "-w", "2", "-S", "FORWARD"])
                self.assertEqual(client.checked(["ip", "-j", "link", "show"]), "[]\n")
                self.assertTrue(client.request("cleanup")["ok"])
                supervisor.join(timeout=5)
                self.assertEqual(supervisor.exitcode, 0)
                self.assertFalse(private.exists())
            finally:
                owner_channel.close()
                if supervisor.is_alive():
                    supervisor.kill()
                    supervisor.join(timeout=2)

    def test_missing_supervisor_reply_is_normalized(self):
        client = SupervisorClient.__new__(SupervisorClient)
        client.resources = type("Resources", (), {"deadline": time.monotonic() + 5})()
        client.deadline = client.resources.deadline
        client.channel = type("Channel", (), {
            "settimeout": lambda self, timeout: None,
            "send": lambda self, payload: None,
            "recv": lambda self, size: b"",
        })()

        with self.assertRaises(IsolationUnavailable):
            client.request("run")

    def test_missing_command_code_is_normalized(self):
        client = SupervisorClient.__new__(SupervisorClient)
        client.request = lambda *args, **kwargs: {
            "ok": True, "code": None, "stdout": "", "pid": 0, "error": None,
        }

        with self.assertRaises(IsolationUnavailable):
            client.run(["iptables"])

    def test_sigkill_owner_kills_reaps_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            _check_supervisor_kills_reaps_and_cleans(Path(directory), "sigkill")

    def test_deadline_kills_reaps_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            _check_supervisor_kills_reaps_and_cleans(Path(directory), "deadline")

    def test_normal_completion_kills_reaps_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            _check_supervisor_kills_reaps_and_cleans(Path(directory), "normal")

    def test_cleanup_rpc_after_autonomous_deadline_has_explicit_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            _check_supervisor_kills_reaps_and_cleans(Path(directory), "race")
