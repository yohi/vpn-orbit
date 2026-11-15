from __future__ import annotations

import ipaddress
import json
import os
import shutil
import time
from pathlib import Path

from .isolation import ns_command, provision
from .probe_commands import Commands
from .runner_types import CurlOutcome, IsolationResources, ProcessHandle
from .supervisor_client import SupervisedProcess, SupervisorClient


class SubprocessRunner:
    def __init__(self) -> None:
        self.commands: Commands = Commands(time.monotonic() + 5)
        self.client: SupervisorClient | None = None
        self.resources: IsolationResources | None = None
        self.default_routes = ""
        self.cleanup_ok = False

    def prerequisites_ok(self) -> bool:
        return os.geteuid() == 0 and Path("/dev/net/tun").exists() and all(
            shutil.which(binary) for binary in ("ip", "nft", "openvpn", "curl", "openssl", "getent"))

    def validation_commands(self) -> Commands:
        if self.client is None:
            raise RuntimeError("validation requires supervisor ownership")
        return self.client

    def start_supervisor(self, resources: IsolationResources) -> tuple[bool, str]:
        self.resources = resources
        self.client = SupervisorClient(resources)
        self.commands = self.client
        self.default_routes = self.commands.checked(["ip", "-4", "route", "show", "default"])
        return True, ""

    def setup_isolation(self, remote_ip: str, protocol: str, port: int,
                        private_dir: Path) -> IsolationResources:
        r = self.resources
        if r is None or (r.remote_ip, r.protocol, r.port, r.private_dir) != (remote_ip, protocol, port, private_dir):
            raise RuntimeError("supervisor target mismatch")
        r.setup_started = True
        provision(r, self.commands)
        return r

    def start_openvpn(self, config_path: Path, resources: IsolationResources, *,
                      env: dict[str, str] | None, cwd: Path | None) -> ProcessHandle:
        if self.client is None or config_path != resources.private_dir / "client.ovpn" or cwd != resources.private_dir:
            raise RuntimeError("unsupervised OpenVPN rejected")
        reply = self.client.request("start")
        return SupervisedProcess(self.client, reply["pid"])

    def wait_for_tun(self, process: ProcessHandle, resources: IsolationResources,
                     deadline: float) -> tuple[str | None, str]:
        while time.monotonic() < deadline and process.poll() is None:
            log = resources.private_dir / "openvpn.log"
            if log.exists() and "Initialization Sequence Completed" in log.read_text(errors="replace"):
                result = self.commands.run(ns_command(resources, "ip", "-j", "-4", "addr", "show", "dev", "tun0"))
                if result.returncode == 0:
                    for row in json.loads(result.stdout):
                        for addr in row.get("addr_info", []):
                            if addr.get("family") == "inet":
                                return str(ipaddress.IPv4Address(addr["local"])), "tls_established"
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        return None, "tun_unavailable"

    def resolve_host(self, hostname: str, deadline: float) -> tuple[str | None, str]:
        result = self.commands.run(["getent", "ahostsv4", hostname])
        for line in result.stdout.splitlines():
            ip = ipaddress.IPv4Address(line.split()[0])
            if ip.is_global:
                return str(ip), "resolved"
        return None, "resolution_failed"

    def pre_tunnel_echo_check(self, echo_ip: str, resources: IsolationResources,
                              deadline: float) -> tuple[bool, str]:
        resources.echo_ip = echo_ip
        result = self.commands.run(ns_command(resources, "curl", "-4", "--silent", "--noproxy", "*",
            "--connect-timeout", "1", "--max-time", "2", "--resolve", f"api.ipify.org:443:{echo_ip}",
            "--proto", "=https", "https://api.ipify.org/"))
        return result.returncode in (7, 28), f"curl_exit_{result.returncode}"

    def route_get_via_tun0(self, echo_ip: str, resources: IsolationResources,
                          deadline: float) -> tuple[bool, str]:
        r = resources
        routes = json.loads(self.commands.checked(ns_command(r, "ip", "-j", "-4", "route", "show")))
        if any(row.get("dst") == "default" or row.get("dev") not in (r.veth_ns, "tun0") or
               (row.get("dev") == r.veth_ns and row.get("dst") not in (r.remote_ip, r.remote_ip + "/32")
                and not (row.get("dst") == "10.253.240.0/30" and row.get("protocol") == "kernel")) or
               (row.get("dev") == "tun0" and row.get("protocol") != "kernel") for row in routes):
            return False, "unexpected_routes"
        self.commands.checked(ns_command(r, "ip", "-4", "route", "add", echo_ip + "/32", "dev", "tun0"))
        self.commands.checked(ns_command(r, "nft", "add", "rule", "inet", r.table, "output",
            "oifname", "tun0", "ip", "daddr", echo_ip, "tcp", "dport", "443", "accept"))
        self.commands.checked(ns_command(r, "nft", "add", "rule", "inet", r.table, "input",
            "iifname", "tun0", "ip", "saddr", echo_ip, "tcp", "sport", "443", "ct", "state", "established", "accept"))
        result = self.commands.run(ns_command(r, "ip", "-4", "route", "get", echo_ip))
        words = result.stdout.split()
        return result.returncode == 0 and "dev" in words and words[words.index("dev") + 1] == "tun0", result.stdout.strip()

    def host_direct_route_rejected(self, echo_ip: str, resources: IsolationResources,
                                    deadline: float) -> tuple[bool, str]:
        result = self.commands.run(ns_command(resources, "ip", "-4", "route", "get", echo_ip,
                                             "oif", resources.veth_ns))
        curl = self.commands.run(ns_command(resources, "curl", "-4", "--silent", "--interface", resources.veth_ns,
            "--resolve", f"api.ipify.org:443:{echo_ip}", "--noproxy", "*", "--proto", "=https",
            "--connect-timeout", "1", "--max-time", "2", "https://api.ipify.org/"))
        return result.returncode != 0 and curl.returncode in (7, 28), f"route_exit_{result.returncode};curl_exit_{curl.returncode}"

    def curl_via_tun(self, url: str, resolve: tuple[str, int, str], interface: str,
                     resources: IsolationResources, deadline: float) -> CurlOutcome:
        if url != "https://api.ipify.org/" or interface != "tun0" or resolve != ("api.ipify.org", 443, resources.echo_ip):
            return CurlOutcome(None, "invalid_echo_request", "unauthorized_egress")
        result = self.commands.run(ns_command(resources, "curl", "-4", "--silent", "--fail",
            "--interface", interface, "--resolve", f"{resolve[0]}:{resolve[1]}:{resolve[2]}",
            "--noproxy", "*", "--proto", "=https", "--connect-timeout", "2", "--max-time", "4",
            "--max-filesize", "64", "--write-out", "\n%{http_code}", url))
        body, _, code = result.stdout.rpartition("\n")
        if result.returncode or code != "200" or len(body.encode()) > 64:
            return CurlOutcome(None, "echo_failed")
        return CurlOutcome(body, "")

    def host_default_route_unchanged(self) -> tuple[bool, str]:
        current = self.commands.checked(["ip", "-4", "route", "show", "default"])
        return current == self.default_routes, "default_route_comparison"

    def save_host_ip_forward(self) -> tuple[bool, str]:
        value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        return value in ("0", "1"), value

    def restore_host_ip_forward(self, original: str) -> tuple[bool, str]:
        # The supervisor restores this itself, including after owner SIGKILL.
        return self.cleanup_ok, "supervisor_restore"

    def teardown_isolation(self, resources: IsolationResources) -> tuple[bool, str]:
        if self.client is None:
            return False, "supervisor_unavailable"
        self.cleanup_ok = self.client.finish()
        return self.cleanup_ok, "supervisor_cleanup"

    def confirm_supervisor_cleanup(self, resources: IsolationResources) -> tuple[bool, str]:
        return self.cleanup_ok, "supervisor_cleanup_confirmed"

    def terminate(self, process: ProcessHandle, graceful_s: float) -> tuple[bool, str]:
        if self.client is None:
            return False, "supervisor_unavailable"
        self.client.deadline = time.monotonic() + 4
        return self.client.request("stop").get("ok", False), "process_group_reaped"

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
