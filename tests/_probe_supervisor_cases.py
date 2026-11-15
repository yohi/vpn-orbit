import multiprocessing
import os
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vpn_orbit.runner_types import IsolationResources
from vpn_orbit.supervisor import serve


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
import os, signal, socket, subprocess, sys
from pathlib import Path
root = Path(os.environ["VPN_TEST_STATE"])
args = sys.argv[1:]
name = Path(sys.argv[0]).name
if name == "openvpn":
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
elif name == "ip" and args[:2] == ["link", "show"]:
    sys.exit(0 if (root / "veth").exists() else 1)
elif name == "nft" and args[0] == "delete":
    (root / "nft").unlink(missing_ok=True)
elif name == "nft" and args[0] == "list":
    sys.exit(0 if (root / "nft").exists() else 1)
''')
    tool.chmod(0o700)
    for name in ("ip", "nft", "openvpn"):
        (binary_dir / name).symlink_to(tool)
    return binary_dir


@pytest.mark.parametrize("termination", ["sigkill", "deadline", "normal"])
def test_supervisor_kills_reaps_and_cleans(tmp_path, termination):
    # Given real supervisor and verifier processes, with OS network calls sandboxed at executable boundaries.
    binaries = _tools(tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    (private / "client.ovpn").write_text("client")
    for name in ("netns", "veth", "nft"):
        (tmp_path / name).touch()
    r = IsolationResources(netns="vo-test", private_dir=private, veth_host="vh-test",
        veth_ns="vn-test", remote_ip="8.8.8.8", protocol="udp", port=1195)
    r.deadline = time.monotonic() + (1 if termination == "deadline" else 20)
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
with socket.socket(fileno=int(sys.argv[1])) as channel:
    channel.recv(65536)
    channel.send(b'{"op":"start"}')
    reply = json.loads(channel.recv(65536))
    print(reply["pid"], flush=True)
    def finish(signum, frame):
        channel.send(b'{"op":"cleanup"}')
        assert json.loads(channel.recv(65536))["ok"]
        sys.exit(0)
    signal.signal(signal.SIGUSR1, finish)
    signal.pause()
'''
    verifier = subprocess.Popen([sys.executable, "-c", verifier_code, str(owner_channel.fileno())],
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
