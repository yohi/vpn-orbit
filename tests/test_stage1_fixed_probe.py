"""Tests for the fixed-candidate Stage 1 CLI."""
from __future__ import annotations

import io
import json
import os
import sys
import warnings
import tempfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Literal
from unittest.mock import MagicMock, patch

import unittest

from tests.test_phase1 import PROFILE
from vpn_orbit.attempt_journal import AttemptJournal, JournalResult, OwnerApproval
from vpn_orbit.cloud_probe import RemoteKey, ScreenedCandidate
from vpn_orbit.fixed_candidates import candidate_id
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.phase1 import Candidate
from vpn_orbit.probe_types import ProbeResult, ProbeStatus
from vpn_orbit.stage1_fixed_probe import _current_head, _main, main


HEAD = "head-for-tests"
_SECRET_MARKER = "secret_marker_do_not_emit"


def _catalog_with_one(*, profile: str | None = None) -> str:
    import base64, csv
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["HostName", "IP", "Score", "Ping", "Speed", "CountryShort",
                     "OpenVPN_ConfigData_Base64"])
    raw = (profile or PROFILE).encode()
    writer.writerow(["test.opengw.net", "8.8.8.8", "123", "12", "30000000", "JP",
                     base64.b64encode(raw).decode("ascii")])
    return "*vpn_servers\n#" + stream.getvalue()


def _candidate_from_catalog(catalog: str) -> ScreenedCandidate:
    from vpn_orbit.fixed_candidates import fixed_shortlist
    selected = fixed_shortlist(catalog, geo_lookup=lambda _ip: GeoDecision.NON_TOKYO)
    assert len(selected) == 1
    return selected[0]


def _allow_test_root(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("test journal store must be a real directory")


def _allow_test_file(path: Path, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise PermissionError("test journal file must be a regular file")


class _JournalTestCase(unittest.TestCase):
    """Base case that disables root-ownership checks for the journal store."""

    def setUp(self) -> None:
        root_patch = patch("vpn_orbit.attempt_journal._require_root_owner",
                           side_effect=_allow_test_root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        file_patch = patch("vpn_orbit.attempt_journal._require_root_file",
                           side_effect=_allow_test_file)
        file_patch.start()
        self.addCleanup(file_patch.stop)


def _make_journal() -> tuple[AttemptJournal, Path, tempfile.TemporaryDirectory[str]]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name) / "attempts"
    root.mkdir(mode=0o700, parents=True)
    journal = AttemptJournal(root)
    return journal, root, tmp


def _approval(candidate_id: str = "candidate-a", head: str = HEAD) -> OwnerApproval:
    return OwnerApproval(
        approval_id="approval-a",
        issue_ref="yohi/vpn-orbit#9",
        legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN",
        candidate_id=candidate_id,
        approved_head=head,
        scope="ONE_NEW_ATTEMPT",
        approved_at="2026-11-22T00:00:00Z",
    )


def _write_approval(journal: AttemptJournal, approval: OwnerApproval) -> None:
    path = journal.root / "owner-approval.json"
    path.write_text(json.dumps({
        "approval_id": approval.approval_id,
        "issue_ref": approval.issue_ref,
        "legacy_disposition": approval.legacy_disposition,
        "candidate_id": approval.candidate_id,
        "approved_head": approval.approved_head,
        "scope": approval.scope,
        "approved_at": approval.approved_at,
    }))
    path.chmod(0o600)


def _run(argv: list[str], *, catalog: str | None = None,
         journal: AttemptJournal | None = None,
         runner: object | None = None,
         head: str = HEAD,
         geo_lookup: Callable[[str], GeoDecision] | None = None) -> tuple[int, dict]:
    captured = io.StringIO()
    geo = geo_lookup or (lambda _ip: GeoDecision.NON_TOKYO)
    with patch("vpn_orbit.stage1_fixed_probe.fetch_catalog", return_value=catalog):
        with patch("sys.stdout", new=captured):
            rc = _main(argv, catalog=catalog, journal=journal, runner=runner,
                       head=head, geo_lookup=geo)
    output = captured.getvalue().strip()
    return rc, json.loads(output) if output else {}


def _pass_result() -> ProbeResult:
    return ProbeResult(
        ingress_ip="8.8.8.8", port=1195, protocol="udp", exit_ip="1.1.1.1",
        status=ProbeStatus.PASS, reason_code="exit_ip_tokyo_verified",
        evidence=("tls_tun_established:10.8.0.2",
                  "host_direct_rejected:direct_drop_counter_verified",
                  "tunnel_https_verified",
                  "exit_ip_tokyo_verified"),
        phase="exit_geoip", elapsed_ms=100, cleanup_status="confirmed",
    )


def _fail_result(reason: str = "tun_not_established",
                 phase: str = "tun_wait") -> ProbeResult:
    return ProbeResult(
        ingress_ip="8.8.8.8", port=1195, protocol="udp", exit_ip=None,
        status=ProbeStatus.FAIL, reason_code=reason,
        evidence=(f"pre_cleanup_failure:{phase}:{reason}",),
        phase=phase, elapsed_ms=100, cleanup_status="confirmed",
    )


class ListTests(_JournalTestCase):
    def test_current_head_ignores_environment_override(self) -> None:
        with patch.dict(os.environ, {"VPN_ORBIT_STAGE1_HEAD": "forged-head"}):
            with patch(
                "vpn_orbit.stage1_fixed_probe.subprocess.run",
                return_value=type("Result", (), {"stdout": "actual-head\n"})(),
            ) as run:
                self.assertEqual(_current_head(), "actual-head")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["git", "rev-parse", "HEAD"])

    def test_module_invocation_runs_cli(self) -> None:
        import runpy

        with patch.dict(os.environ, {"IPAPI_IS_API_KEY": "test-key"}):
            with patch("vpn_orbit.phase1.fetch_catalog", return_value=_catalog_with_one()):
                with patch("vpn_orbit.geoip.lookup_geoip", return_value=GeoDecision.NON_TOKYO):
                    with patch.object(sys, "argv", ["vpn_orbit.stage1_fixed_probe", "--list"]):
                        with patch("sys.stdout", new=io.StringIO()) as output:
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore", RuntimeWarning)
                                with self.assertRaises(SystemExit) as raised:
                                    runpy.run_module("vpn_orbit.stage1_fixed_probe", run_name="__main__")
        self.assertEqual(raised.exception.code, 0)
        self.assertIn('"candidates"', output.getvalue())

    def test_list_never_invokes_probe(self) -> None:
        catalog = _catalog_with_one()
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--list"], catalog=catalog)
        self.assertFalse(probe.called)
        self.assertEqual(rc, 0)
        self.assertEqual(len(payload["candidates"]), 1)

    def test_list_json_redacts_raw_profile(self) -> None:
        catalog = _catalog_with_one()
        rc, payload = _run(["--list"], catalog=catalog)
        self.assertEqual(rc, 0)
        text = json.dumps(payload)
        self.assertNotIn(PROFILE, text)
        self.assertNotIn("profile_raw_bytes", text)


class ProbeIdLifecycleTests(_JournalTestCase):
    def test_journal_preflight_errors_return_blocked_json(self) -> None:
        catalog = _catalog_with_one()
        cid = candidate_id(_candidate_from_catalog(catalog))
        for method in ("inspect", "read_approval", "reserve"):
            with self.subTest(method=method):
                journal, _root, tmp = _make_journal()
                self.addCleanup(tmp.cleanup)
                _write_approval(journal, _approval(candidate_id=cid))
                with patch.object(journal, method, side_effect=BlockingIOError("busy")):
                    rc, payload = _run(["--probe-id", cid],
                                       catalog=catalog, journal=journal)
                self.assertEqual(rc, 1)
                self.assertEqual(payload["status"], "BLOCKED")
                self.assertEqual(payload["reason_codes"], ["preflight_blocked"])

    def test_missing_api_key_returns_blocked_json(self) -> None:
        captured = io.StringIO()
        with patch.dict(os.environ, {"IPAPI_IS_API_KEY": ""}):
            with patch("sys.stdout", new=captured):
                rc = _main(["--list"], catalog=_catalog_with_one())
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(captured.getvalue())["reason_codes"], ["input_unavailable"])

    def test_exact_id_invokes_probe_once(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = _pass_result()
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result) as probe:
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["recovery_state"], "FINALIZED")
        self.assertEqual(payload["candidate_id"], cid)
        self.assertEqual(payload["exit_code"], 0)
        self.assertTrue(list(root.glob("attempt-*.json")))

    def test_missing_candidate_never_reserves_or_probes(self) -> None:
        catalog = _catalog_with_one()
        journal, root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id="candidate-a"))
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", "0" * 64], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["status"], "NOT_VERIFIED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")
        self.assertEqual(payload["reason_codes"], ["candidate_not_found"])
        self.assertIsNone(payload["attempt_id"])
        self.assertIsNone(payload["exit_code"])
        self.assertEqual(len(list(root.glob("attempt-*.json"))), 0)

    def test_issue9_unknown_blocks_empty_journal_without_owner_decision(self) -> None:
        catalog = _catalog_with_one()
        journal, _root, _tmp = _make_journal()
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", "0" * 64], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")
        self.assertEqual(payload["reason_codes"], ["legacy_unknown_owner_decision_required"])

    def test_owner_approval_must_reference_issue9_and_new_single_attempt(self) -> None:
        catalog = _catalog_with_one()
        journal, _root, _tmp = _make_journal()
        bad = OwnerApproval(
            approval_id="approval-b",
            issue_ref="other/repo#9",
            legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN",
            candidate_id="candidate-a",
            approved_head=HEAD,
            scope="ONE_NEW_ATTEMPT",
            approved_at="2026-11-22T00:00:00Z",
        )
        _write_approval(journal, bad)
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", "0" * 64], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")

    def test_issue9_unknown_blocks_different_candidate_without_owner_decision(self) -> None:
        catalog = _catalog_with_one()
        cid = candidate_id(_candidate_from_catalog(catalog))
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id="different-candidate"))
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")
        self.assertEqual(payload["reason_codes"], ["preflight_blocked"])
        self.assertIsNone(payload["attempt_id"])
        self.assertIsNone(payload["exit_code"])
        self.assertEqual(rc, 1)

    def test_used_approval_cannot_relaunch(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=_pass_result()):
            _run(["--probe-id", cid], catalog=catalog, journal=journal)
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")

    def test_existing_unknown_attempt_blocks_probe(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with journal.reserve(candidate_id=cid, ingress="8.8.8.8:1195/udp",
                               head=HEAD, approval=issued) as handle:
            journal.mark_running(handle)
        # journal state is now RUNNING -> unresolved
        with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")
        self.assertEqual(payload["reason_codes"], ["preflight_blocked"])
        self.assertIsNone(payload["attempt_id"])

    def test_mark_running_failure_never_calls_probe(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with patch.object(journal, "mark_running", side_effect=OSError("disk")):
            with patch("vpn_orbit.stage1_fixed_probe.probe_one") as probe:
                rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertFalse(probe.called)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertEqual(payload["recovery_state"], "NOT_STARTED")
        self.assertEqual(payload["reason_codes"], ["probe_start_blocked"])
        self.assertIsNotNone(payload["attempt_id"])

    def test_journal_complete_failure_never_reports_pass(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with patch.object(journal, "complete", side_effect=OSError("disk")):
            with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=_pass_result()):
                rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertIsNone(payload["status"])
        self.assertEqual(payload["recovery_state"], "RESULT_UNKNOWN")
        self.assertEqual(payload["reason_codes"], ["journal_finalization_failed"])
        self.assertIsNone(payload["exit_code"])

    def test_started_attempt_without_result_is_unknown(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", side_effect=RuntimeError("crash")):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertIsNone(payload["status"])
        self.assertEqual(payload["recovery_state"], "RESULT_UNKNOWN")
        self.assertEqual(payload["reason_codes"], ["attempt_result_unavailable"])


class ProjectionTests(_JournalTestCase):
    def test_pass_exit_code_zero(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=_pass_result()):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["tun_evidence"], "VERIFIED")
        self.assertEqual(payload["drop_evidence"], "VERIFIED")
        self.assertEqual(payload["tunnel_https_evidence"], "VERIFIED")
        self.assertEqual(payload["tokyo_geoip_evidence"], "VERIFIED")

    def test_pass_without_confirmed_cleanup_returns_nonzero(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = replace(_pass_result(), cleanup_status="failed")
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(rc, 1)

    def test_fail_exit_code_one(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = _fail_result("drop_counter_not_advanced", "route_verification")
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["drop_evidence"], "FAILED")

    def test_result_unknown_has_null_exit_code(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        issued = _approval(candidate_id=cid)
        _write_approval(journal, issued)
        with patch.object(journal, "complete", side_effect=OSError("disk")):
            with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=_pass_result()):
                rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(rc, 1)
        self.assertIsNone(payload["status"])
        self.assertEqual(payload["recovery_state"], "RESULT_UNKNOWN")
        self.assertIsNone(payload["exit_code"])

    def test_unreached_is_not_observed(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = _fail_result("tun_not_established", "tun_wait")
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(payload["tunnel_https_evidence"], "NOT_OBSERVED")
        self.assertEqual(payload["tokyo_geoip_evidence"], "NOT_OBSERVED")

    def test_cleanup_failure_overrides_pass(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = ProbeResult(
            ingress_ip="8.8.8.8", port=1195, protocol="udp", exit_ip="1.1.1.1",
            status=ProbeStatus.FAIL, reason_code="cleanup_failed:teardown",
            evidence=("tls_tun_established:10.8.0.2",
                      "host_direct_rejected:direct_drop_counter_verified",
                      "tunnel_https_verified",
                      "pre_cleanup_failure:exit_geoip:exit_ip_tokyo_verified"),
            phase="cleanup", elapsed_ms=100, cleanup_status="failed",
        )
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["phase"], "exit_geoip")
        self.assertEqual(payload["tunnel_https_evidence"], "VERIFIED")

    def test_untrusted_errors_emit_fixed_codes_only(self) -> None:
        catalog = _catalog_with_one()
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        result = ProbeResult(
            ingress_ip="8.8.8.8", port=1195, protocol="udp", exit_ip=None,
            status=ProbeStatus.FAIL, reason_code="leaked_secret_123",
            evidence=(), phase="preflight", elapsed_ms=1, cleanup_status="confirmed",
        )
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=result):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        self.assertEqual(payload["reason_codes"], ["stage_failure_unclassified"])
        self.assertNotIn("leaked_secret_123", json.dumps(payload))

    def test_json_redacts_secrets_and_raw_profile(self) -> None:
        secret_profile = PROFILE + "\n# " + _SECRET_MARKER + "\n"
        catalog = _catalog_with_one(profile=secret_profile)
        candidate = _candidate_from_catalog(catalog)
        cid = candidate_id(candidate)
        journal, _root, _tmp = _make_journal()
        _write_approval(journal, _approval(candidate_id=cid))
        with patch("vpn_orbit.stage1_fixed_probe.probe_one", return_value=_pass_result()):
            rc, payload = _run(["--probe-id", cid], catalog=catalog, journal=journal)
        text = json.dumps(payload)
        self.assertNotIn(_SECRET_MARKER, text)
        self.assertNotIn(PROFILE, text)


if __name__ == "__main__":
    unittest.main()
