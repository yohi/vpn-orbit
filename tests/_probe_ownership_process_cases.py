import json
import multiprocessing
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from multiprocessing.process import BaseProcess
from pathlib import Path

from tests._probe_supervisor_cases import _serve_with_tools, _tools
from vpn_orbit.runner_types import IsolationResources


def _resources(root: Path) -> IsolationResources:
    private = root / "private"
    private.mkdir(mode=0o700)
    (private / "key.pem").write_text("private test sentinel")
    r = IsolationResources(netns="vo-test", private_dir=private, veth_host="vh-test",
        veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
    r.deadline = time.monotonic() + 20
    for name in ("netns", "veth", "nft"):
        (root / name).write_text(r.table if name == "nft" else "")
    return r


def _start(root: Path, resources: IsolationResources) -> tuple[BaseProcess, socket.socket]:
    binaries = _tools(root)
    owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = multiprocessing.get_context("fork").Process(target=_serve_with_tools,
        args=(child, owner.fileno(), resources, binaries, root))
    process.start()
    child.close()
    owner.settimeout(5)
    return process, owner


class OwnershipProcessTests(unittest.TestCase):
    def test_openssl_sigkill_reaps_all_validation_steps_and_helpers(self):
        steps = [["x509", "-noout"], ["x509", "-pubkey", "-noout"],
                 ["pkey", "-pubin", "-outform", "DER"], ["pkey", "-pubout", "-outform", "DER"]]
        for args in steps:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as directory:
                # Given an independent supervisor and an uncooperative validator/helper pair.
                root = Path(directory)
                resources = _resources(root)
                with socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(str(root / "ready.sock"))
                    listener.listen(1)
                    listener.settimeout(5)
                    supervisor, owner = _start(root, resources)
                    code = '''
import json, socket, sys, time
from vpn_orbit.supervisor_client import SupervisorClient
class ConnectedClient(SupervisorClient):
    def __init__(self, fd):
        self.channel = socket.socket(fileno=fd)
        self.deadline = time.monotonic() + 15
client = ConnectedClient(int(sys.argv[1]))
client.channel.recv(65536)
client.openssl(json.loads(sys.argv[2]), b"validation-input", 2)
'''
                    verifier = subprocess.Popen([sys.executable, "-c", code, str(owner.fileno()), json.dumps(args)],
                        pass_fds=(owner.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    owner.close()
                    validator: int | None = None
                    try:
                        ready, _ = listener.accept()
                        ready.close()
                        validator = int((root / "openssl.pid").read_text())
                        helper = int((root / "helper.pid").read_text())
                        self.assertEqual(int((root / "openssl.parent").read_text()), supervisor.pid)
                        # When the verifier dies while OpenSSL is running, without finally/atexit.
                        verifier.kill()
                        verifier.wait(timeout=2)
                        supervisor.join(timeout=10)
                        # Then the owning supervisor reaps both processes and confirms resource deletion.
                        self.assertEqual(supervisor.exitcode, 0)
                        self.assertFalse(Path(f"/proc/{validator}").exists())
                        self.assertFalse(Path(f"/proc/{helper}").exists())
                        self.assertFalse(resources.private_dir.exists())
                        self.assertTrue(all(not (root / name).exists() for name in ("netns", "veth", "nft")))
                    finally:
                        if verifier.poll() is None:
                            verifier.kill()
                            verifier.wait(timeout=2)
                        supervisor.join(timeout=1)
                        if supervisor.is_alive():
                            if validator is not None:
                                try:
                                    os.killpg(validator, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            supervisor.kill()
                            supervisor.join(timeout=2)

    def test_confirmation_denial_retains_supervisor_until_retry_confirms_absence(self):
        # Given inaccessible firewall confirmation, even after successful deletes.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resources = _resources(root)
            denial = root / "deny_confirmation"
            denial.touch()
            supervisor, owner = _start(root, resources)
            try:
                self.assertTrue(json.loads(owner.recv(65536))["ok"])
                # When cleanup cannot prove absence.
                owner.send(b'{"op":"cleanup"}')
                self.assertFalse(json.loads(owner.recv(65536))["ok"])
                self.assertTrue(supervisor.is_alive())
                # Then it retains responsibility until successful enumeration becomes possible.
                denial.unlink()
                owner.close()
                supervisor.join(timeout=8)
                self.assertEqual(supervisor.exitcode, 0)
                self.assertFalse(resources.private_dir.exists())
            finally:
                owner.close()
                if supervisor.is_alive():
                    supervisor.kill()
                    supervisor.join(timeout=2)
