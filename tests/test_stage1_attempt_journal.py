"""Behavioral tests for the fixed-candidate attempt journal."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Literal, final
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vpn_orbit.attempt_journal import (
    AttemptJournal,
    JournalResult,
    OwnerApproval,
    _require_root_file,
    _require_root_owner,
)
from vpn_orbit.probe_types import ProbeStatus


def approval(candidate_id: str = "candidate-a", head: str = "head-a") -> OwnerApproval:
    return OwnerApproval(
        approval_id="approval-a",
        issue_ref="yohi/vpn-orbit#9",
        legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN",
        candidate_id=candidate_id,
        approved_head=head,
        scope="ONE_NEW_ATTEMPT",
        approved_at="2026-11-22T00:00:00Z",
    )


def result(
    status: ProbeStatus | None = ProbeStatus.PASS,
    recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"] = "FINALIZED",
    exit_code: int | None = 0,
    reason_codes: tuple[str, ...] = (),
) -> JournalResult:
    """Build a redacted result fixture."""
    return JournalResult(
        status=status,
        recovery_state=recovery_state,
        reason_codes=reason_codes,
        exit_code=exit_code,
        phase="complete",
        cleanup_status="confirmed",
        tun_evidence="VERIFIED",
        drop_evidence="VERIFIED",
        tunnel_https_evidence="VERIFIED",
        tokyo_geoip_evidence="VERIFIED",
    )


def _allow_test_store(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("test journal store must be a real directory")


@final
class AttemptJournalTests(unittest.TestCase):
    tempdir: tempfile.TemporaryDirectory[str]
    root: Path
    journal: AttemptJournal

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name) / "attempts"
        self.journal = AttemptJournal(self.root)

    def setUp(self) -> None:
        root_owner_patch = patch("vpn_orbit.attempt_journal._require_root_owner", side_effect=_allow_test_store)
        root_owner_patch.start()
        self.addCleanup(root_owner_patch.stop)
        file_owner_patch = patch("vpn_orbit.attempt_journal._require_root_file")
        file_owner_patch.start()
        self.addCleanup(file_owner_patch.stop)

    def approval_file(self, owner_approval: OwnerApproval) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.root / "owner-approval.json"
        path.write_text(json.dumps({
            "approval_id": owner_approval.approval_id,
            "issue_ref": owner_approval.issue_ref,
            "legacy_disposition": owner_approval.legacy_disposition,
            "candidate_id": owner_approval.candidate_id,
            "approved_head": owner_approval.approved_head,
            "scope": owner_approval.scope,
            "approved_at": owner_approval.approved_at,
        }))
        path.chmod(0o600)

    def test_empty_journal_still_blocks_issue9_legacy_unknown_without_owner_approval(self) -> None:
        self.assertTrue(self.journal.inspect().legacy_hold)
        self.assertIsNone(self.journal.read_approval())

    def test_read_approval_rejects_wrong_issue_or_scope(self) -> None:
        self.root.mkdir(mode=0o700, parents=True)
        path = self.root / "owner-approval.json"
        path.write_text(json.dumps({
            "approval_id": "x", "issue_ref": "other#9",
            "legacy_disposition": "ACKNOWLEDGED_RESULT_UNKNOWN",
            "candidate_id": "candidate-a", "approved_head": "head-a",
            "scope": "ALL_ATTEMPTS", "approved_at": "2026-11-22T00:00:00Z",
        }))
        path.chmod(0o600)
        self.assertIsNone(self.journal.read_approval())

    def test_approval_is_one_time_and_candidate_head_scoped(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued) as handle:
            self.journal.mark_running(handle)
            self.journal.complete(handle, result=result())
        self.assertIsNone(self.journal.read_approval())
        self.assertFalse(self.journal.inspect().has_unresolved)

    def test_global_lock_blocks_different_candidate_ids(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.addCleanup(handle.__exit__, None, None, None)
        second_approval = approval("candidate-b")
        self.approval_file(second_approval)
        with self.assertRaises(BlockingIOError):
            self.journal.reserve(candidate_id="candidate-b", ingress="1.2.3.5:443/tcp", head="head-a", approval=second_approval)
        self.assertEqual(len(list(self.root.glob("attempt-*.json"))), 1)

    def test_reserve_rechecks_under_lock(self) -> None:
        self.assertTrue(self.journal.inspect().legacy_hold)
        with self.assertRaises(PermissionError):
            self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=approval())

    def test_duplicate_approval_id_is_blocked(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued) as handle:
            self.journal.mark_running(handle)
            self.journal.complete(handle, result=result())
        self.assertFalse(self.journal.inspect().has_unresolved)
        with self.assertRaises(PermissionError):
            self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)

    def test_wrong_head_is_blocked(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with self.assertRaises(PermissionError):
            self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="other-head", approval=issued)

    def test_reserve_writes_restricted_durable_record(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued):
            record = next(self.root.glob("attempt-*.json"))
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(record.read_text())["state"], "RESERVED")

    def test_reserved_or_running_after_crash_is_result_unknown(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        handle.__exit__(None, None, None)
        self.assertTrue(self.journal.inspect().has_unresolved)

    def test_unresolved_blocks_all_candidates(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        handle.__exit__(None, None, None)
        second = OwnerApproval(
            approval_id="approval-b",
            issue_ref="yohi/vpn-orbit#9",
            legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN",
            candidate_id="candidate-b",
            approved_head="head-a",
            scope="ONE_NEW_ATTEMPT",
            approved_at="2026-11-22T00:00:00Z",
        )
        self.approval_file(second)
        with self.assertRaises(PermissionError):
            self.journal.reserve(candidate_id="candidate-b", ingress="1.2.3.5:443/tcp", head="head-a", approval=second)

    def test_mark_running_failure_prevents_probe(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        with patch.object(self.journal, "_write_record", side_effect=OSError):
            with self.assertRaises(OSError):
                self.journal.mark_running(handle)
        self.assertTrue(self.journal.inspect().has_unresolved)
        handle.__exit__(None, None, None)

    def test_symlink_or_wrong_owner_is_blocked(self) -> None:
        real = Path(self.tempdir.name) / "real"
        real.mkdir(mode=0o700)
        link = Path(self.tempdir.name) / "linked"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises((OSError, PermissionError)):
            AttemptJournal(link).inspect()
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000),
        ), self.assertRaises(PermissionError):
            _require_root_owner(real)

    def test_require_root_file_rejects_symlink(self) -> None:
        target = Path(self.tempdir.name) / "owner-approval.json"
        target.touch()
        link = Path(self.tempdir.name) / "approval-link.json"
        link.symlink_to(target)
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
        ), self.assertRaises(PermissionError):
            _require_root_file(link)

    def test_require_root_file_rejects_non_root_uid(self) -> None:
        target = Path(self.tempdir.name) / "owner-approval.json"
        target.touch()
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=2000),
        ), self.assertRaises(PermissionError):
            _require_root_file(target)

    def test_require_root_file_rejects_permissive_mode(self) -> None:
        target = Path(self.tempdir.name) / "owner-approval.json"
        target.touch()
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0),
        ), self.assertRaises(PermissionError):
            _require_root_file(target)

    def test_read_approval_fails_closed_on_unsafe_approval_file(self) -> None:
        self.approval_file(approval())
        with patch(
            "vpn_orbit.attempt_journal._require_root_file",
            new=_require_root_file,
        ), patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0),
        ):
            self.assertIsNone(self.journal.read_approval())

    def test_unwritable_store_is_blocked(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with patch.object(self.journal, "_write_record", side_effect=OSError):
            with self.assertRaises(OSError):
                self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)

    def test_complete_failure_leaves_unknown_and_never_reports_pass(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        with patch.object(self.journal, "_write_record", side_effect=OSError):
            with self.assertRaises(OSError):
                self.journal.complete(handle, result=result())
        self.assertTrue(self.journal.inspect().has_unresolved)
        record = json.loads(next(self.root.glob("attempt-*.json")).read_text())
        self.assertEqual(record["state"], "RUNNING")
        self.assertIsNone(record["status"])

    def test_directory_fsync_failure_after_replace_leaves_attempt_unresolved(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        real_fsync = os.fsync

        def fail_directory_fsync(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory fsync failed")
            real_fsync(fd)

        with patch("vpn_orbit.attempt_journal.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(OSError):
                self.journal.complete(handle, result=result())
        self.assertTrue(self.journal.inspect().has_unresolved)
        record = json.loads(next(self.root.glob("attempt-*.json")).read_text())
        self.assertEqual(record["state"], "RESULT_UNKNOWN")
        self.assertIsNone(record["status"])

    def test_failed_unknown_rewrite_persists_unresolved_marker(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        real_write_record = self.journal._write_record
        calls = 0

        def fail_rewrite_after_replace(path, record):
            nonlocal calls
            calls += 1
            if calls == 1:
                real_write_record(path, record)
                raise OSError("directory fsync failed")
            raise OSError("rewrite failed before replace")

        with patch.object(self.journal, "_write_record", side_effect=fail_rewrite_after_replace):
            with self.assertRaises(OSError):
                self.journal.complete(handle, result=result())

        self.assertTrue(self.journal.inspect().has_unresolved)
        self.assertTrue(list(self.root.glob("failure-*.json")))
        self.assertTrue(AttemptJournal(self.root).inspect().has_unresolved)
        record = json.loads(next(self.root.glob("attempt-*.json")).read_text())
        self.assertEqual(record["state"], "COMPLETED")

    def test_existing_failure_marker_is_tolerated(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        marker = self.root / "failure-existing.json"
        marker.write_text("existing")

        self.journal._mark_persistence_failure("existing")

        self.assertEqual(marker.read_text(), "existing")

    def test_unknown_result_remains_unresolved_after_complete(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        self.journal.complete(
            handle,
            result=result(status=None, recovery_state="RESULT_UNKNOWN", exit_code=None),
        )
        self.assertTrue(self.journal.inspect().has_unresolved)

    def test_null_exit_code_for_unknown(self) -> None:
        self.assertIsNone(result(status=None, recovery_state="RESULT_UNKNOWN", exit_code=None).exit_code)

    def test_secret_values_are_not_serialized(self) -> None:
        issued = approval()
        self.approval_file(issued)
        with self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued):
            payload = next(self.root.glob("attempt-*.json")).read_text()
        self.assertNotIn("secret", payload.lower())
        self.assertNotIn("profile-bytes", payload)

    def test_secret_like_result_text_is_rejected_before_serialization(self) -> None:
        issued = approval()
        self.approval_file(issued)
        handle = self.journal.reserve(candidate_id="candidate-a", ingress="1.2.3.4:443/tcp", head="head-a", approval=issued)
        self.journal.mark_running(handle)
        with self.assertRaises(PermissionError):
            self.journal.complete(
                handle,
                result=result(reason_codes=("raw_api_key=do-not-store",)),
            )
        payload = next(self.root.glob("attempt-*.json")).read_text()
        self.assertNotIn("do-not-store", payload)


if __name__ == "__main__":
    unittest.main()
