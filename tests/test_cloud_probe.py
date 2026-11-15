"""Tests for cloud candidate screening pipeline."""
from __future__ import annotations

import base64
import csv
import io
from pathlib import Path
import unittest

from vpn_orbit.cloud_probe import GeoDecision, RemoteKey, ScreenedCandidate, screen_candidates
from vpn_orbit.phase1 import Candidate

CA = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()

FIXED_IPS = ("119.105.93.237", "126.234.242.57")


def _profile(ip: str = "8.8.8.8", port: int = 1195, protocol: str = "udp") -> str:
    return f"""client
proto {protocol}
remote {ip} {port}
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{CA}</ca>
"""


def _catalog(rows: list[tuple[str, str, int, str]]) -> str:
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["HostName", "IP", "Score", "Ping", "Speed", "CountryShort", "OpenVPN_ConfigData_Base64"])
    for ip, country, ping, profile in rows:
        writer.writerow(["test.opengw.net", ip, "123", str(ping), "30000000", country,
                         base64.b64encode(profile.encode()).decode()])
    return "*vpn_servers\n#" + stream.getvalue()


def _geo(decisions: dict[str, GeoDecision]):
    calls: list[str] = []

    def lookup(ip: str) -> GeoDecision:
        calls.append(ip)
        return decisions.get(ip, GeoDecision.UNKNOWN)

    return lookup, calls


class ScreenCandidatesTests(unittest.TestCase):
    def test_returns_limited_count(self):
        rows = [(f"8.8.{i}.8", "JP", i, _profile(f"8.8.{i}.8")) for i in range(1, 12)]
        lookup, _ = _geo({row[0]: GeoDecision.TOKYO for row in rows})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=10)
        self.assertEqual(len(result), 10)

    def test_invalid_limit_rejected(self):
        with self.assertRaises(ValueError):
            screen_candidates(_catalog([]), existing_pins=frozenset(), geo_lookup=lambda ip: GeoDecision.UNKNOWN, limit=0)
        with self.assertRaises(ValueError):
            screen_candidates(_catalog([]), existing_pins=frozenset(), geo_lookup=lambda ip: GeoDecision.UNKNOWN, limit=11)

    def test_fixed_ips_excluded_across_all_ports_and_protocols(self):
        rows = []
        for ip in FIXED_IPS:
            for port in (1279, 1281, 1195):
                for protocol in ("tcp", "udp"):
                    rows.append((ip, "JP", 1, _profile(ip, port, protocol)))
        rows.append(("8.8.8.8", "JP", 1, _profile("8.8.8.8")))
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].remote.ip, "8.8.8.8")

    def test_existing_pins_excluded_as_ips(self):
        rows = [("9.9.9.9", "JP", 1, _profile("9.9.9.9")), ("8.8.8.8", "JP", 2, _profile("8.8.8.8"))]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset({"9.9.9.9"}), geo_lookup=lookup)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].remote.ip, "8.8.8.8")

    def test_same_ip_different_port_or_protocol_is_kept(self):
        rows = [
            ("8.8.8.8", "JP", 1, _profile("8.8.8.8", 1195, "udp")),
            ("8.8.8.8", "JP", 2, _profile("8.8.8.8", 1196, "udp")),
            ("8.8.8.8", "JP", 3, _profile("8.8.8.8", 1195, "tcp")),
        ]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=10)
        self.assertEqual(len(result), 3)
        self.assertEqual({(r.remote.port, r.remote.protocol) for r in result},
                         {(1195, "udp"), (1196, "udp"), (1195, "tcp")})

    def test_same_remote_key_deduplicated_keeping_first(self):
        rows = [
            ("8.8.8.8", "JP", 1, _profile("8.8.8.8", 1195, "udp")),
            ("8.8.8.8", "JP", 2, _profile("8.8.8.8", 1195, "udp")),
        ]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].catalog_rank, 1)

    def test_scan_window_uses_tcp_and_udp_top_20_each(self):
        rows = []
        for i in range(1, 41):
            protocol = "tcp" if i % 2 == 1 else "udp"
            ip = f"8.8.{i}.8" if protocol == "tcp" else f"9.9.{i}.9"
            rows.append((ip, "JP", i, _profile(ip, 1195, protocol)))
        decisions = {row[0]: GeoDecision.TOKYO for row in rows}
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=10)
        tcp_count = sum(1 for r in result if r.remote.protocol == "tcp")
        udp_count = sum(1 for r in result if r.remote.protocol == "udp")
        self.assertGreaterEqual(tcp_count, 1)
        self.assertGreaterEqual(udp_count, 1)
        self.assertLessEqual(len(result), 10)

    def test_one_protocol_can_fill_window_when_other_absent(self):
        rows = [(f"8.8.{i}.8", "JP", i, _profile(f"8.8.{i}.8", 1195, "tcp")) for i in range(1, 45)]
        lookup, _ = _geo({row[0]: GeoDecision.TOKYO for row in rows})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=10)
        self.assertEqual(len(result), 10)
        self.assertTrue(all(r.remote.protocol == "tcp" for r in result))

    def test_round_priority_over_geo_rank(self):
        # IP A appears twice (rounds 0 and 1); round 0 is NON_TOKYO, round 1 is TOKYO.
        # First-round non-Tokyo must come before second-round Tokyo.
        rows = [
            ("1.1.1.1", "JP", 1, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.2", "JP", 2, _profile("1.1.1.2", 1195, "udp")),
            ("1.1.1.1", "JP", 3, _profile("1.1.1.1", 1196, "udp")),
        ]
        decisions = {"1.1.1.1": GeoDecision.NON_TOKYO, "1.1.1.2": GeoDecision.TOKYO}
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=10)
        self.assertEqual(len(result), 3)
        # Round 0 items: 1.1.1.1:1195 (NON_TOKYO), 1.1.1.2:1195 (TOKYO)
        # Round 1 item: 1.1.1.1:1196 (NON_TOKYO)
        # Sorted: round0 first. Within round0, TOKYO before NON_TOKYO. Then round1.
        expected_order = [
            RemoteKey("1.1.1.2", 1195, "udp"),
            RemoteKey("1.1.1.1", 1195, "udp"),
            RemoteKey("1.1.1.1", 1196, "udp"),
        ]
        self.assertEqual([r.remote for r in result], expected_order)

    def test_tokyo_preferred_within_same_round(self):
        rows = [
            ("1.1.1.1", "JP", 1, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.2", "JP", 2, _profile("1.1.1.2", 1195, "udp")),
        ]
        decisions = {"1.1.1.1": GeoDecision.NON_TOKYO, "1.1.1.2": GeoDecision.TOKYO}
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(result[0].remote.ip, "1.1.1.2")
        self.assertEqual(result[1].remote.ip, "1.1.1.1")

    def test_geo_lookup_cached_per_ip(self):
        rows = [
            ("1.1.1.1", "JP", 1, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.1", "JP", 2, _profile("1.1.1.1", 1196, "udp")),
            ("1.1.1.1", "JP", 3, _profile("1.1.1.1", 1197, "udp")),
        ]
        lookup, calls = _geo({"1.1.1.1": GeoDecision.TOKYO})
        screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(calls, ["1.1.1.1"])

    def test_limit_one_returns_top_sorted_candidate(self):
        rows = [
            ("1.1.1.1", "JP", 1, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.2", "JP", 2, _profile("1.1.1.2", 1195, "udp")),
        ]
        decisions = {"1.1.1.1": GeoDecision.NON_TOKYO, "1.1.1.2": GeoDecision.TOKYO}
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].remote.ip, "1.1.1.2")

    def test_non_jp_country_is_excluded_by_parse_catalog(self):
        rows = [("8.8.8.8", "US", 1, _profile("8.8.8.8"))]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(len(result), 0)

    def test_invalid_profile_is_skipped(self):
        rows = [("8.8.8.8", "JP", 1, "not a valid openvpn profile")]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(len(result), 0)

    def test_aggregate_status_distribution_is_preserved(self):
        rows = [
            ("1.1.1.1", "JP", 1, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.2", "JP", 2, _profile("1.1.1.2", 1195, "udp")),
            ("1.1.1.3", "JP", 3, _profile("1.1.1.3", 1195, "udp")),
        ]
        decisions = {
            "1.1.1.1": GeoDecision.TOKYO,
            "1.1.1.2": GeoDecision.NON_TOKYO,
            "1.1.1.3": GeoDecision.UNKNOWN,
        }
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=3)
        statuses = [r.ingress_geo for r in result]
        self.assertIn(GeoDecision.TOKYO, statuses)
        self.assertIn(GeoDecision.NON_TOKYO, statuses)
        self.assertIn(GeoDecision.UNKNOWN, statuses)

    def test_screened_candidate_is_typed_value_object(self):
        rows = [("8.8.8.8", "JP", 1, _profile("8.8.8.8"))]
        lookup, _ = _geo({"8.8.8.8": GeoDecision.TOKYO})
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup)
        self.assertEqual(len(result), 1)
        sc = result[0]
        self.assertIsInstance(sc, ScreenedCandidate)
        self.assertIsInstance(sc.remote, RemoteKey)
        self.assertIsInstance(sc.candidate, Candidate)
        self.assertEqual(sc.ingress_geo, GeoDecision.TOKYO)
        self.assertEqual(sc.catalog_rank, 1)


if __name__ == "__main__":
    unittest.main()
