"""Tests for cloud candidate screening pipeline."""
from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import unittest
from unittest.mock import patch

from vpn_orbit import cloud_probe

from vpn_orbit.cloud_probe import (
    GeoDecision,
    ProbeResult,
    ProbeStatus,
    RemoteKey,
    ScreenedCandidate,
    aggregate_status,
    probe_candidates,
    screen_candidates,
)
from vpn_orbit.phase1 import Candidate
from tests._fake_runner import FakeRunner

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

    def test_scan_window_exactly_40_with_20_tcp_and_20_udp(self):
        rows = []
        tcp_ips = [f"8.8.{i}.8" for i in range(1, 31)]
        udp_ips = [f"9.9.{i}.9" for i in range(1, 31)]
        for i, ip in enumerate(tcp_ips, start=1):
            rows.append((ip, "JP", i, _profile(ip, 1195, "tcp")))
        for i, ip in enumerate(udp_ips, start=1):
            rows.append((ip, "JP", i + 30, _profile(ip, 1195, "udp")))
        decisions = {row[0]: GeoDecision.TOKYO for row in rows}
        lookup, calls = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, scan_window=40, limit=10)
        self.assertEqual(len(result), 10)
        # Window is built before limit; geo_lookup is called once per unique IP in window.
        tcp_window_ips = set(calls) & set(tcp_ips)
        udp_window_ips = set(calls) & set(udp_ips)
        self.assertEqual(len(tcp_window_ips), 20)
        self.assertEqual(len(udp_window_ips), 20)
        self.assertEqual(set(tcp_window_ips), set(tcp_ips[:20]))
        self.assertEqual(set(udp_window_ips), set(udp_ips[:20]))
        self.assertEqual(len(calls), 40)
        self.assertEqual(len(set(calls)), 40)

    def test_catalog_rank_tie_break_within_same_round_and_geo(self):
        # parse_catalog sorts by ping ascending, so we assign pings in reverse
        # IP order to make catalog_rank order the opposite of IP ascending order.
        # This discriminates catalog_rank from the downstream ip_int tie-breaker.
        rows = [
            ("1.1.1.1", "JP", 3, _profile("1.1.1.1", 1195, "udp")),
            ("1.1.1.2", "JP", 2, _profile("1.1.1.2", 1195, "udp")),
            ("1.1.1.3", "JP", 1, _profile("1.1.1.3", 1195, "udp")),
        ]
        decisions = {"1.1.1.1": GeoDecision.TOKYO, "1.1.1.2": GeoDecision.TOKYO, "1.1.1.3": GeoDecision.TOKYO}
        lookup, _ = _geo(decisions)
        result = screen_candidates(_catalog(rows), existing_pins=frozenset(), geo_lookup=lookup, limit=3)
        # catalog_rank: 1.1.1.3=1, 1.1.1.2=2, 1.1.1.1=3
        self.assertEqual([r.remote.ip for r in result], ["1.1.1.3", "1.1.1.2", "1.1.1.1"])

    def test_scan_window_upper_bound_enforced(self):
        with self.assertRaises(ValueError):
            screen_candidates(_catalog([]), existing_pins=frozenset(), geo_lookup=lambda ip: GeoDecision.UNKNOWN, scan_window=1001)

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

    def test_aggregate_status_fail_plus_pass_returns_fail(self):
        self.assertEqual(
            aggregate_status([ProbeStatus.PASS, ProbeStatus.NOT_VERIFIED, ProbeStatus.FAIL, ProbeStatus.PASS]),
            ProbeStatus.FAIL,
        )

    def test_aggregate_status_pass_without_fail_returns_pass(self):
        self.assertEqual(
            aggregate_status([ProbeStatus.NOT_VERIFIED, ProbeStatus.PASS, ProbeStatus.NOT_VERIFIED]),
            ProbeStatus.PASS,
        )

    def test_aggregate_status_blocked_without_pass_or_fail_returns_blocked(self):
        self.assertEqual(
            aggregate_status([ProbeStatus.NOT_VERIFIED, ProbeStatus.BLOCKED]),
            ProbeStatus.BLOCKED,
        )

    def test_aggregate_status_empty_returns_not_verified(self):
        self.assertEqual(aggregate_status([]), ProbeStatus.NOT_VERIFIED)

    def test_ingress_geo_decision_distribution_is_preserved(self):
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


class RemoteKeyTests(unittest.TestCase):
    def test_accepts_valid_global_ipv4(self):
        key = RemoteKey("8.8.8.8", 1195, "udp")
        self.assertEqual(key.ip, "8.8.8.8")

    def test_rejects_private_ip(self):
        with self.assertRaises(ValueError):
            RemoteKey("192.168.1.1", 1195, "udp")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            RemoteKey("8.8.8.8", 0, "udp")
        with self.assertRaises(ValueError):
            RemoteKey("8.8.8.8", 70000, "udp")

    def test_rejects_invalid_protocol(self):
        with self.assertRaises(ValueError):
            RemoteKey("8.8.8.8", 1195, "icmp")


class ProbeCandidatesTests(unittest.TestCase):
    def test_empty_candidates_returns_empty_results(self):
        results = probe_candidates([], geo_lookup=lambda ip: GeoDecision.UNKNOWN)
        self.assertEqual(results, [])

    def test_probe_candidates_returns_blocked_when_prerequisites_unavailable(self):
        ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
        profile = f"""client
proto udp
remote 8.8.8.8 1195
cipher AES-128-CBC
auth SHA1
remote-cert-tls server
<ca>
{ca}</ca>
"""
        candidate = ScreenedCandidate(
            candidate=Candidate(
                host="test", ip="8.8.8.8", country="JP", ping_ms=1,
                speed_bps=1, score=1, profile=profile,
            ),
            remote=RemoteKey("8.8.8.8", 1195, "udp"),
            ingress_geo=GeoDecision.TOKYO,
            catalog_rank=1,
        )
        runner = FakeRunner(Path(tempfile.mkdtemp(prefix="vpn-orbit-cloud-probe-")))
        runner.prerequisites_ok_value = False
        results = probe_candidates([candidate], geo_lookup=lambda ip: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ProbeStatus.BLOCKED)
        self.assertEqual(aggregate_status(r.status for r in results), ProbeStatus.BLOCKED)
        shutil.rmtree(runner.tmp, ignore_errors=True)

    def test_probe_result_is_typed_value_object(self):
        result = ProbeResult(
            ingress_ip="8.8.8.8", port=1195, protocol="udp",
            exit_ip="1.1.1.1", status=ProbeStatus.PASS, reason_code="ok",
        )
        self.assertIsInstance(result.status, ProbeStatus)


class CloudProbeCliTests(unittest.TestCase):
    args = ["--scan-window", "40", "--limit", "10", "--timeout-seconds", "60"]

    def invoke(self, results=(), *, error=None, args=None, env=None):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"IPAPI_IS_API_KEY": "test-key"} if env is None else env, clear=True), \
                patch.object(cloud_probe, "fetch_catalog", return_value="catalog") as fetch, \
                patch.object(cloud_probe, "screen_candidates", return_value=[]) as screen, \
                patch.object(cloud_probe, "probe_candidates", return_value=list(results), side_effect=error) as probe, \
                redirect_stdout(output), redirect_stderr(errors):
            code = cloud_probe.main(self.args if args is None else args)
            if probe.called:
                self.assertEqual(probe.call_args.kwargs["timeout_s"], 60)
            if not screen.called:
                fetch.assert_not_called()
                probe.assert_not_called()
        self.assertEqual(errors.getvalue(), "")
        return code, json.loads(output.getvalue()), screen

    def test_summary_allowlist_and_status_contract(self):
        for status in ProbeStatus:
            with self.subTest(status=status):
                result = ProbeResult("8.8.8.8", 1195, "udp", "1.1.1.1", status, "ok",
                                     ("RAW_OVPN_SECRET",))
                code, summary, _ = self.invoke([result])
                self.assertEqual(set(summary), {"status", "tested_count", "tokyo_confirmed_count",
                                               "witness_ingress", "witness_exit", "reason_codes"})
                self.assertEqual(summary["status"], status.value)
                self.assertEqual(summary["tested_count"], 1)
                self.assertEqual(summary["tokyo_confirmed_count"], int(status == ProbeStatus.PASS))
                self.assertEqual(code, int(status != ProbeStatus.PASS))
                self.assertNotIn("RAW_OVPN_SECRET", json.dumps(summary))
                if status == ProbeStatus.PASS:
                    self.assertEqual(summary["witness_ingress"], "8.8.8.8:1195/udp")
                    self.assertEqual(summary["witness_exit"], "1.1.1.1")
                else:
                    self.assertIsNone(summary["witness_ingress"])
                    self.assertIsNone(summary["witness_exit"])

    def test_empty_shortlist_is_not_verified(self):
        code, summary, _ = self.invoke()
        self.assertEqual((code, summary["status"], summary["tested_count"]), (1, "NOT_VERIFIED", 0))

    def test_cli_forwards_exact_bounds_and_key_to_geoip_only(self):
        with patch.object(cloud_probe, "lookup_geoip", return_value=GeoDecision.TOKYO) as lookup:
            _, _, screen = self.invoke(env={"IPAPI_IS_API_KEY": "test-secret"})
            self.assertEqual(screen.call_args.kwargs["scan_window"], 40)
            self.assertEqual(screen.call_args.kwargs["limit"], 10)
            screen.call_args.kwargs["geo_lookup"]("8.8.8.8")
            lookup.assert_called_once_with("8.8.8.8", api_key="test-secret")

    def test_rejects_personal_credentials_before_network(self):
        for name in ("VPN_ORBIT_USERNAME", "VPN_ORBIT_PASSWORD"):
            with self.subTest(name=name):
                code, summary, screen = self.invoke(env={name: ""})
                self.assertEqual((code, summary["status"]), (1, "BLOCKED"))
                self.assertEqual(summary["reason_codes"], ["environment_secret_inheritance_rejected"])
                screen.assert_not_called()

    def test_missing_key_blocks_before_any_network_or_probe(self):
        for env in ({}, {"IPAPI_IS_API_KEY": ""}, {"IPAPI_IS_API_KEY": "  "}):
            with self.subTest(env=env), patch.object(cloud_probe, "lookup_geoip") as lookup:
                code, summary, screen = self.invoke(env=env)
                self.assertEqual((code, summary["status"], summary["reason_codes"]),
                                 (1, "BLOCKED", ["geoip_api_key_missing"]))
                lookup.assert_not_called()
                screen.assert_not_called()

    def test_stage1_window_is_fixed_at_api_and_cli_boundaries(self):
        for window in (1, 10, 41):
            with self.subTest(window=window):
                with self.assertRaises(ValueError):
                    screen_candidates(_catalog([("8.8.8.8", "JP", 1, _profile())]), existing_pins=frozenset(),
                                      geo_lookup=lambda ip: GeoDecision.UNKNOWN, scan_window=window)
                code, summary, screen = self.invoke(args=["--scan-window", str(window)])
                self.assertEqual((code, summary["status"], summary["reason_codes"]),
                                 (1, "BLOCKED", ["invalid_arguments"]))
                screen.assert_not_called()

    def test_invalid_arguments_emit_redacted_json(self):
        for args in (["--limit", "11"], ["--scan-window", "0"], ["--timeout-seconds", "61"],
                     ["--timeout-seconds", "0"], ["--scan-window", "1001"], ["--limit", "secret"]):
            with self.subTest(args=args):
                code, summary, screen = self.invoke(args=args)
                self.assertEqual((code, summary["status"], summary["reason_codes"]),
                                 (1, "BLOCKED", ["invalid_arguments"]))
                screen.assert_not_called()

    def test_exception_text_is_not_emitted(self):
        code, summary, _ = self.invoke(error=RuntimeError("RAW_OVPN_SECRET"))
        self.assertEqual((code, summary["status"], summary["reason_codes"]),
                         (1, "FAIL", ["execution_failed"]))
        self.assertNotIn("RAW_OVPN_SECRET", json.dumps(summary))

    def test_fail_overrides_pass_without_witness(self):
        results = [ProbeResult("8.8.8.8", 1195, "udp", "1.1.1.1", ProbeStatus.PASS, "ok"),
                   ProbeResult("9.9.9.9", 1195, "udp", None, ProbeStatus.FAIL, "cleanup_failed")]
        code, summary, _ = self.invoke(results)
        self.assertEqual((code, summary["status"], summary["witness_exit"]), (1, "FAIL", None))

    def test_module_entrypoint_rejects_credentials_offline(self):
        result = subprocess.run([sys.executable, "-m", "vpn_orbit.cloud_probe", *self.args],
                                env={**os.environ, "VPN_ORBIT_USERNAME": "do-not-log"},
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")
        self.assertNotIn("do-not-log", result.stdout)

    def test_cli_pipeline_keeps_geoip_secret_out_of_openvpn_environment(self):
        catalog = _catalog([("8.8.8.8", "JP", 1, _profile())])
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            with patch.dict(os.environ, {"IPAPI_IS_API_KEY": "test-secret"}, clear=True), \
                    patch.object(cloud_probe, "fetch_catalog", return_value=catalog), \
                    patch.object(cloud_probe, "lookup_geoip", return_value=GeoDecision.TOKYO), \
                    patch("vpn_orbit.openvpn_probe.SubprocessRunner", return_value=runner), \
                    redirect_stdout(output):
                code = cloud_probe.main(self.args)
            self.assertEqual(code, 0)
            self.assertEqual(runner.last_openvpn_env,
                             {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            self.assertTrue(runner.cleaned)
        self.assertEqual(json.loads(output.getvalue())["tokyo_confirmed_count"], 1)
        self.assertNotIn("test-secret", output.getvalue())


class ProbeWorkflowTests(unittest.TestCase):
    def test_manual_only_bounded_workflow(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/probe-tokyo-vpn.yml"
        self.assertTrue(workflow.exists(), "manual probe workflow is missing")
        text = workflow.read_text()
        top_level = re.findall(r"^(\w[\w-]*):", text, re.MULTILINE)
        self.assertIn("on", top_level)
        triggers = text.split("on:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(triggers.strip(), "workflow_dispatch:")
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("permissions:\n  contents: read", text)
        timeout = re.search(r"timeout-minutes: (\d+)", text)
        assert timeout is not None
        self.assertLessEqual(int(timeout[1]), 20)
        self.assertIn("group: vpn-orbit-tokyo-probe", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("--scan-window 40 --limit 10 --timeout-seconds 60", text)
        self.assertIn("IPAPI_IS_API_KEY: ${{ secrets.IPAPI_IS_API_KEY }}", text)
        self.assertIn("sudo --preserve-env=IPAPI_IS_API_KEY -- python3 -m vpn_orbit.cloud_probe", text)
        self.assertIn("persist-credentials: false", text)
        for forbidden in ("push:", "pull_request:", "schedule:", "CLOUDFLARE", "wrangler",
                          "upload-artifact", "run: curl", "sudo -E", "--preserve-env "):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
