"""Validate identity and counter values from nftables JSON at the boundary."""
from __future__ import annotations

from dataclasses import dataclass
import json


@dataclass(frozen=True, slots=True)
class DropCounter:
    handle: int
    packets: int


def parse_drop_counter(output: str, table: str, echo_ip: str, veth: str) -> DropCounter | None:
    try:
        document = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        return None

    identified: list[dict[str, object]] = []
    for entry in document["nftables"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
            continue
        rule = entry["rule"]
        if rule.get("comment") == "vpn-orbit-drop-evidence":
            identified.append(rule)
    if len(identified) != 1:
        return None

    rule = identified[0]
    handle = rule.get("handle")
    expressions = rule.get("expr")
    if (rule.get("family") != "inet" or rule.get("table") != table or
            rule.get("chain") != "output" or type(handle) is not int or
            not isinstance(expressions, list)):
        return None

    matches: set[tuple[str, str, str | int]] = set()
    match_count = 0
    counters: list[int] = []
    drop_count = 0
    for expression in expressions:
        if not isinstance(expression, dict):
            return None
        match = expression.get("match")
        if isinstance(match, dict):
            match_count += 1
            left = match.get("left")
            right = match.get("right")
            if match.get("op") != "==" or not isinstance(left, dict):
                return None
            meta = left.get("meta")
            payload = left.get("payload")
            if isinstance(meta, dict) and meta.get("key") == "oifname" and isinstance(right, str):
                matches.add(("oifname", "", right))
            elif (isinstance(payload, dict) and payload.get("protocol") == "ip" and
                  payload.get("field") == "daddr" and isinstance(right, str)):
                matches.add(("ip", "daddr", right))
            elif (isinstance(payload, dict) and payload.get("protocol") == "tcp" and
                  payload.get("field") == "dport" and type(right) is int):
                matches.add(("tcp", "dport", right))
            else:
                return None
        elif isinstance(expression.get("counter"), dict):
            packets = expression["counter"].get("packets")
            if type(packets) is not int or packets < 0:
                return None
            counters.append(packets)
        elif "drop" in expression and expression["drop"] is None:
            drop_count += 1
        else:
            return None

    expected = {("oifname", "", veth), ("ip", "daddr", echo_ip), ("tcp", "dport", 443)}
    if matches != expected or match_count != 3 or len(counters) != 1 or drop_count != 1:
        return None
    return DropCounter(handle, counters[0])


def drop_handle_absent(output: str, table: str, handle: int) -> bool:
    try:
        document = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        return False
    for entry in document["nftables"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
            continue
        rule = entry["rule"]
        if rule.get("family") == "inet" and rule.get("table") == table and rule.get("handle") == handle:
            return False
    return True


def find_owned_drop_handle(output: str, table: str) -> int | None:
    try:
        document = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        return None
    handles: list[int] = []
    for entry in document["nftables"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
            continue
        rule = entry["rule"]
        handle = rule.get("handle")
        if (rule.get("family") == "inet" and rule.get("table") == table and
                rule.get("chain") == "output" and rule.get("comment") == "vpn-orbit-drop-evidence" and
                type(handle) is int):
            handles.append(handle)
    return handles[0] if len(handles) == 1 else None
