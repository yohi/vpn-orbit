"""Execute one scoped DROP-evidence attempt and restore its route and rule."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json

from .drop_evidence_json import drop_handle_absent, find_owned_drop_handle, parse_drop_counter
from .isolation import ns_command
from .probe_commands import Commands
from .runner_types import IsolationResources


@dataclass(frozen=True, slots=True)
class DropEvidenceAttempt:
    commands: Commands
    resources: IsolationResources
    echo_ip: str

    def execute(self) -> tuple[bool, str]:
        resources = self.resources
        echo_ip = self.echo_ip
        route = echo_ip + "/32"
        original_route_record: dict[str, str | int | list[str]] | None = None
        drop_rule_installed = False
        drop_handle: int | None = None
        counter_before: int | None = None
        evidence_passed = False
        reason = "drop_evidence_unavailable"

        try:
            route_result = self.commands.run(ns_command(
                resources, "ip", "-j", "-4", "route", "show", "exact", route,
            ))
            route_rows = json.loads(route_result.stdout) if route_result.returncode == 0 else None
            if (route_result.returncode != 0 or not isinstance(route_rows, list) or
                    len(route_rows) != 1 or not isinstance(route_rows[0], dict)):
                reason = "drop_route_unavailable"
            else:
                route_record = route_rows[0]
                allowed_fields = {"dst", "dev", "scope", "protocol", "metric", "prefsrc", "table", "type", "flags"}
                valid_attributes = (
                    route_record.get("dst") in (route, echo_ip) and
                    route_record.get("dev") == "tun0" and
                    "gateway" not in route_record and
                    set(route_record).issubset(allowed_fields)
                )
                if "flags" in route_record:
                    valid_attributes = valid_attributes and route_record["flags"] == []
                for field_name in ("scope", "protocol", "table", "type"):
                    if field_name in route_record:
                        attribute = route_record[field_name]
                        is_integer_id = (field_name in ("protocol", "table") and
                                         type(attribute) is int and 0 <= attribute <= 0xFFFFFFFF)
                        is_safe_name = (type(attribute) is str and bool(attribute) and
                                        all(char.isalnum() or char in "_.-" for char in attribute))
                        valid_attributes = valid_attributes and (is_integer_id or is_safe_name)
                if "type" in route_record:
                    valid_attributes = valid_attributes and route_record["type"] == "unicast"
                if "metric" in route_record:
                    metric = route_record["metric"]
                    valid_attributes = valid_attributes and type(metric) is int and metric >= 0
                if "prefsrc" in route_record:
                    try:
                        valid_attributes = valid_attributes and (
                            str(ipaddress.IPv4Address(route_record["prefsrc"])) == route_record["prefsrc"]
                        )
                    except (ipaddress.AddressValueError, TypeError):
                        valid_attributes = False
                if valid_attributes:
                    original_route_record = route_record
                else:
                    reason = "drop_route_unavailable"

            if original_route_record is not None:
                add = self.commands.run(ns_command(
                    resources, "nft", "add", "rule", "inet", resources.table, "output",
                    "oifname", resources.veth_ns, "ip", "daddr", echo_ip,
                    "tcp", "dport", "443", "counter", "drop",
                    "comment", "vpn-orbit-drop-evidence",
                ))
                if add.returncode != 0:
                    reason = "drop_evidence_unavailable"
                else:
                    drop_rule_installed = True
                    before_result = self.commands.run(ns_command(
                        resources, "nft", "-j", "-a", "list", "chain", "inet", resources.table, "output",
                    ))
                    if before_result.returncode != 0:
                        reason = "drop_counter_unavailable"
                    else:
                        counter = parse_drop_counter(
                            before_result.stdout, resources.table, echo_ip, resources.veth_ns,
                        )
                        if counter is None or counter.packets != 0:
                            reason = "drop_counter_invalid"
                        else:
                            drop_handle = counter.handle
                            counter_before = counter.packets
                            switch_args = ["ip", "-4", "route", "replace", route]
                            for field_name, option in (("table", "table"), ("protocol", "proto"),
                                                       ("metric", "metric")):
                                if field_name in original_route_record:
                                    switch_args.extend((option, str(original_route_record[field_name])))
                            switch_args.extend(("via", "10.253.240.1", "dev", resources.veth_ns))
                            switch = self.commands.run(ns_command(
                                resources, *switch_args,
                            ))
                            if switch.returncode != 0:
                                reason = "drop_route_unavailable"
                            else:
                                get = self.commands.run(ns_command(
                                    resources, "ip", "-4", "route", "get", echo_ip,
                                ))
                                route_result = self.commands.run(ns_command(
                                    resources, "ip", "-j", "-4", "route", "show", "exact", route,
                                ))
                                active_rows = (
                                    json.loads(route_result.stdout)
                                    if route_result.returncode == 0 else None
                                )
                                words = get.stdout.split()
                                veth_route_confirmed = (
                                    get.returncode == 0 and "dev" in words and
                                    words[words.index("dev") + 1] == resources.veth_ns and
                                    "via" in words and words[words.index("via") + 1] == "10.253.240.1" and
                                    route_result.returncode == 0 and isinstance(active_rows, list) and
                                    len(active_rows) == 1 and isinstance(active_rows[0], dict) and
                                    active_rows[0].get("dst") in (route, echo_ip) and
                                    active_rows[0].get("dev") == resources.veth_ns and
                                    active_rows[0].get("gateway") == "10.253.240.1"
                                )
                                if not veth_route_confirmed:
                                    reason = "drop_route_unavailable"
                                else:
                                    curl = self.commands.run(ns_command(
                                        resources, "curl", "-4", "--silent", "--noproxy", "*",
                                        "--connect-timeout", "1", "--max-time", "2",
                                        "--resolve", f"api.ipify.org:443:{echo_ip}",
                                        "--proto", "=https", "--interface", "if!" + resources.veth_ns,
                                        "https://api.ipify.org/",
                                    ))
                                    if curl.returncode not in (7, 28):
                                        reason = "drop_curl_not_refused"
                                    else:
                                        after_result = self.commands.run(ns_command(
                                            resources, "nft", "-j", "-a", "list", "chain",
                                            "inet", resources.table, "output",
                                        ))
                                        if after_result.returncode != 0:
                                            reason = "drop_counter_unavailable"
                                        else:
                                            after = parse_drop_counter(
                                                after_result.stdout, resources.table,
                                                echo_ip, resources.veth_ns,
                                            )
                                            if after is None or after.handle != drop_handle:
                                                reason = "drop_counter_invalid"
                                            elif after.packets <= counter_before:
                                                reason = "drop_counter_not_advanced"
                                            else:
                                                evidence_passed = True
        except Exception:  # noqa: BLE001 -- normalize failures at the privileged command boundary
            reason = "drop_evidence_unavailable"
        finally:
            route_restored = original_route_record is None
            if original_route_record is not None:
                try:
                    restore_args = ["ip", "-4", "route", "replace"]
                    if "type" in original_route_record:
                        restore_args.append(str(original_route_record["type"]))
                    restore_args.append(route)
                    restore_args.extend(("dev", "tun0"))
                    for field_name, option in (
                        ("table", "table"), ("scope", "scope"), ("protocol", "proto"),
                        ("metric", "metric"), ("prefsrc", "src"),
                    ):
                        if field_name in original_route_record:
                            restore_args.extend((option, str(original_route_record[field_name])))
                    restore = self.commands.run(ns_command(
                        resources, *restore_args,
                    ))
                    get = self.commands.run(ns_command(resources, "ip", "-4", "route", "get", echo_ip))
                    route_result = self.commands.run(ns_command(
                        resources, "ip", "-j", "-4", "route", "show", "exact", route,
                    ))
                    restored_rows = json.loads(route_result.stdout)
                    words = get.stdout.split()
                    route_restored = (
                        restore.returncode == 0 and get.returncode == 0 and
                        "dev" in words and words[words.index("dev") + 1] == "tun0" and
                        route_result.returncode == 0 and isinstance(restored_rows, list) and
                        len(restored_rows) == 1 and isinstance(restored_rows[0], dict) and
                        all(restored_rows[0].get(key) == value
                            for key, value in original_route_record.items())
                    )
                except Exception:  # noqa: BLE001 -- inability to confirm restoration is a hard failure
                    route_restored = False

            rule_removed = not drop_rule_installed
            if drop_rule_installed and drop_handle is None and route_restored:
                try:
                    listing = self.commands.run(ns_command(
                        resources, "nft", "-j", "-a", "list", "chain", "inet", resources.table, "output",
                    ))
                    if listing.returncode == 0:
                        drop_handle = find_owned_drop_handle(listing.stdout, resources.table)
                except Exception:  # noqa: BLE001 -- only a positively identified owned rule may be removed
                    drop_handle = None
            if drop_rule_installed and route_restored and drop_handle is not None:
                try:
                    remove = self.commands.run(ns_command(
                        resources, "nft", "delete", "rule", "inet", resources.table,
                        "output", "handle", str(drop_handle),
                    ))
                    remaining = self.commands.run(ns_command(
                        resources, "nft", "-j", "-a", "list", "chain", "inet", resources.table, "output",
                    ))
                    rule_removed = (
                        remove.returncode == 0 and remaining.returncode == 0 and
                        drop_handle_absent(remaining.stdout, resources.table, drop_handle)
                    )
                except Exception:  # noqa: BLE001 -- inability to confirm deletion is a hard failure
                    rule_removed = False
            elif drop_rule_installed and route_restored:
                rule_removed = False

        if not route_restored:
            return False, "drop_route_restore_failed"
        if not rule_removed:
            return False, "drop_rule_cleanup_failed"
        if evidence_passed:
            return True, "direct_drop_counter_verified"
        return False, reason
