import ipaddress
import json
import shutil
import subprocess
from pathlib import Path

from .probe_commands import Commands, IsolationUnavailable
from .runner_types import IsolationResources


def ns_command(resources: IsolationResources, *args: str) -> list[str]:
    return ["ip", "netns", "exec", resources.netns, *args]


def provision(resources: IsolationResources, commands: Commands) -> None:
    r = resources
    addresses = json.loads(commands.checked(["ip", "-j", "-4", "addr", "show"]))
    for link in addresses:
        for addr in link.get("addr_info", []):
            network = ipaddress.ip_network(f"{addr['local']}/{addr['prefixlen']}", strict=False)
            if network.overlaps(ipaddress.ip_network("10.253.240.0/30")):
                raise IsolationUnavailable("isolation address conflict")
    routes = json.loads(commands.checked(["ip", "-j", "-4", "route", "show", "table", "all"]))
    if any(row.get("dst") != "default" and ipaddress.ip_network(row["dst"], strict=False).overlaps(
            ipaddress.ip_network("10.253.240.0/30")) for row in routes if "dst" in row):
        raise IsolationUnavailable("isolation route conflict")
    route = json.loads(commands.checked(["ip", "-j", "-4", "route", "get", r.remote_ip]))
    wan = route[0]["dev"]
    if not wan.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise IsolationUnavailable("invalid interface")
    commands.checked(["ip", "netns", "add", r.netns])
    commands.checked(["ip", "link", "add", r.veth_host, "type", "veth", "peer", "name", r.veth_ns])
    commands.checked(["ip", "link", "set", r.veth_ns, "netns", r.netns])
    commands.checked(["ip", "addr", "add", "10.253.240.1/30", "dev", r.veth_host])
    commands.checked(ns_command(r, "ip", "addr", "add", "10.253.240.2/30", "dev", r.veth_ns))
    commands.checked(ns_command(r, "ip", "link", "set", "lo", "up"))
    commands.checked(ns_command(r, "ip", "link", "set", r.veth_ns, "up"))
    commands.checked(ns_command(r, "ip", "-4", "route", "add", r.remote_ip + "/32",
                                "via", "10.253.240.1", "dev", r.veth_ns))
    host_rules = f'''table inet {r.table} {{
 chain input {{ type filter hook input priority -200; policy accept;
  iifname "{r.veth_host}" drop
 }}
 chain forward {{ type filter hook forward priority -200; policy accept;
  iifname "{r.veth_host}" oifname "{wan}" ip saddr 10.253.240.2 ip daddr {r.remote_ip} {r.protocol} dport {r.port} accept
  iifname "{wan}" oifname "{r.veth_host}" ip saddr {r.remote_ip} ip daddr 10.253.240.2 {r.protocol} sport {r.port} ct state established,related accept
  iifname "{r.veth_host}" drop
  oifname "{r.veth_host}" drop
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
  oifname "{wan}" ip saddr 10.253.240.2 ip daddr {r.remote_ip} {r.protocol} dport {r.port} masquerade
 }}
}}'''
    namespace_rules = f'''table inet {r.table} {{
 chain input {{ type filter hook input priority -200; policy drop;
  iifname "lo" accept
  iifname "{r.veth_ns}" ip saddr {r.remote_ip} {r.protocol} sport {r.port} ct state established accept
 }}
 chain output {{ type filter hook output priority -200; policy drop;
  oifname "lo" accept
  oifname "{r.veth_ns}" ip daddr {r.remote_ip} {r.protocol} dport {r.port} accept
 }}
}}'''
    commands.checked(["nft", "-f", "-"], data=host_rules)
    commands.checked(ns_command(r, "nft", "-f", "-"), data=namespace_rules)
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    commands.checked(["ip", "link", "set", r.veth_host, "up"])


def _present_resources(r: IsolationResources, commands: Commands) -> frozenset[str]:
    links = json.loads(commands.checked(["ip", "-j", "link", "show"]))
    tables = json.loads(commands.checked(["nft", "-j", "list", "tables"]))
    if not isinstance(links, list) or not isinstance(tables, dict) or not isinstance(tables.get("nftables"), list):
        raise IsolationUnavailable("invalid resource enumeration")
    present: set[str] = set()
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
            raise IsolationUnavailable("invalid link enumeration")
        if link["ifname"] == r.veth_host:
            present.add("link")
    for record in tables["nftables"]:
        if not isinstance(record, dict):
            raise IsolationUnavailable("invalid table enumeration")
        if "table" in record:
            table = record["table"]
            if not isinstance(table, dict) or not isinstance(table.get("name"), str) or not isinstance(table.get("family"), str):
                raise IsolationUnavailable("invalid table identity")
            if table["family"] == "inet" and table["name"] == r.table:
                present.add("table")
        elif set(record) != {"metainfo"} or not isinstance(record["metainfo"], dict):
            raise IsolationUnavailable("unrecognized table enumeration record")
    namespaces = commands.checked(["ip", "netns", "list"])
    if r.netns in {line.split()[0] for line in namespaces.splitlines() if line.split()}:
        present.add("netns")
    return frozenset(present)


def _restore_ip_forward(value: str) -> bool:
    path = Path("/proc/sys/net/ipv4/ip_forward")
    if value == "0":
        path.write_text("0")
    elif value == "1":
        path.write_text("1")
    else:
        return False
    return True


def remove_resources(r: IsolationResources, commands: Commands) -> bool:
    """Only successful, parsed enumeration can confirm cleanup; command failure is never absence."""
    ok = True
    try:
        present = _present_resources(r, commands)
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError):
        ok = False
        present = frozenset({"table", "link", "netns"})
    for kind, args in (("table", ["nft", "delete", "table", "inet", r.table]),
                       ("link", ["ip", "link", "del", r.veth_host]),
                       ("netns", ["ip", "netns", "del", r.netns])):
        if kind not in present:
            continue
        try:
            if commands.run(args).returncode != 0:
                ok = False
        except (OSError, TimeoutError, subprocess.SubprocessError):
            ok = False
    if r.host_ip_forward_original is not None:
        try:
            if not _restore_ip_forward(r.host_ip_forward_original):
                ok = False
        except OSError:
            ok = False
    try:
        shutil.rmtree(r.private_dir)
    except FileNotFoundError:
        pass
    except OSError:
        ok = False
    try:
        ok = not _present_resources(r, commands) and ok
        ok = not r.private_dir.exists() and ok
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError):
        ok = False
    return ok
