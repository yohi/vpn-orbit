"""Durable authorization and exclusion for fixed-candidate probe attempts."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Final, Literal, assert_never, final
from types import TracebackType

from .probe_types import ProbeStatus

EvidenceState = Literal["VERIFIED", "FAILED", "NOT_OBSERVED"]
JournalRecord = dict[str, str | int | None | list[str]]
_APPROVAL_FILE: Final = "owner-approval.json"
_LOCK_FILE: Final = "attempts.lock"
_APPROVAL_FIELDS: Final = frozenset({
    "approval_id", "issue_ref", "legacy_disposition", "candidate_id",
    "approved_head", "scope", "approved_at",
})
_RECORD_FIELDS: Final = frozenset({
    "attempt_id", "candidate_id", "ingress", "head", "approval_id",
    "state", "started_at", "completed_at", "status", "recovery_state",
    "reason_codes", "exit_code", "phase", "cleanup_status", "tun_evidence",
    "drop_evidence", "tunnel_https_evidence", "tokyo_geoip_evidence",
})
_SAFE_CODE: Final = re.compile(r"[a-z][a-z0-9_]*(?::[a-z][a-z0-9_]*)*")


@dataclass(frozen=True, slots=True)
class OwnerApproval:
    approval_id: str
    issue_ref: Literal["yohi/vpn-orbit#9"]
    legacy_disposition: Literal["ACKNOWLEDGED_RESULT_UNKNOWN"]
    candidate_id: str
    approved_head: str
    scope: Literal["ONE_NEW_ATTEMPT"]
    approved_at: str


@dataclass(frozen=True, slots=True)
class JournalSnapshot:
    legacy_hold: bool
    has_active: bool
    has_unresolved: bool


@dataclass(frozen=True, slots=True)
class JournalResult:
    status: ProbeStatus | None
    recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"]
    reason_codes: tuple[str, ...]
    exit_code: int | None
    phase: str
    cleanup_status: str
    tun_evidence: EvidenceState
    drop_evidence: EvidenceState
    tunnel_https_evidence: EvidenceState
    tokyo_geoip_evidence: EvidenceState


def _require_root_owner(path: Path) -> None:
    """Require real root ownership, rejecting symlinks and permissive modes."""
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError("journal store must be a real directory")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PermissionError("journal store ownership or permissions are unsafe")


def _require_root_file(path: Path, mode: int = 0o600) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("journal file must be a regular file")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise PermissionError("journal file ownership or permissions are unsafe")


def _safe_file(path: Path, mode: int = 0o600) -> bytes:
    _require_root_file(path, mode)
    return path.read_bytes()


@final
class AttemptHandle:
    """Owns the global lock and the reservation record lifecycle."""

    def __init__(self, attempt_id: str, record_path: Path, lock_fd: int) -> None:
        self.attempt_id = attempt_id
        self._record_path = record_path
        self._lock_fd: int | None = lock_fd

    def __enter__(self) -> AttemptHandle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()

    def release(self) -> None:
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None


@final
class AttemptJournal:
    """Manage owner approvals and the serialized fixed-CLI attempt ledger."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _prepare(self) -> None:
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=True)
            os.chmod(self.root, 0o700)
        _require_root_owner(self.root)

    def _records(self) -> list[tuple[Path, JournalRecord]]:
        records: list[tuple[Path, JournalRecord]] = []
        for path in sorted(self.root.glob("attempt-*.json")):
            data = json.loads(_safe_file(path))
            if (
                not isinstance(data, dict)
                or set(data) != _RECORD_FIELDS
                or data.get("state") not in {"RESERVED", "RUNNING", "COMPLETED", "RESULT_UNKNOWN"}
            ):
                raise OSError("journal record schema is invalid")
            records.append((path, data))
        return records

    def read_approval(self) -> OwnerApproval | None:
        self._prepare()
        path = self.root / _APPROVAL_FILE
        if not path.exists():
            return None
        try:
            payload = json.loads(_safe_file(path))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict) or set(payload) != _APPROVAL_FIELDS:
            return None
        if (payload["issue_ref"] != "yohi/vpn-orbit#9" or
                payload["legacy_disposition"] != "ACKNOWLEDGED_RESULT_UNKNOWN" or
                payload["scope"] != "ONE_NEW_ATTEMPT" or
                not all(isinstance(payload[key], str) and payload[key] for key in _APPROVAL_FIELDS)):
            return None
        if any(data["approval_id"] == payload["approval_id"] for _, data in self._records()):
            return None
        return OwnerApproval(
            approval_id=payload["approval_id"],
            issue_ref=payload["issue_ref"],
            legacy_disposition=payload["legacy_disposition"],
            candidate_id=payload["candidate_id"],
            approved_head=payload["approved_head"],
            scope=payload["scope"],
            approved_at=payload["approved_at"],
        )

    def inspect(self) -> JournalSnapshot:
        self._prepare()
        records = self._records()
        consumed = {str(data["approval_id"]) for _, data in records}
        owner_approval = self.read_approval()
        valid_unused = owner_approval is not None and owner_approval.approval_id not in consumed
        unresolved = any(data["state"] in ("RESERVED", "RUNNING", "RESULT_UNKNOWN") for _, data in records)
        active = any(data["state"] == "RUNNING" for _, data in records)
        return JournalSnapshot(not valid_unused, active, unresolved)

    def _write_record(self, path: Path, record: JournalRecord) -> None:
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        temporary = self.root / f".{path.name}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()

    def reserve(
        self, *, candidate_id: str, ingress: str, head: str, approval: OwnerApproval,
    ) -> AttemptHandle:
        self._prepare()
        lock_path = self.root / _LOCK_FILE
        if lock_path.exists():
            _safe_file(lock_path)
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_transferred = False
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _require_root_owner(self.root)
            records = self._records()
            consumed = {str(data["approval_id"]) for _, data in records}
            current = self.read_approval()
            if (current != approval or approval.approval_id in consumed or
                    approval.candidate_id != candidate_id or approval.approved_head != head or
                    any(data["state"] in ("RESERVED", "RUNNING", "RESULT_UNKNOWN") for _, data in records)):
                raise PermissionError("attempt reservation is blocked")
            attempt_id = secrets.token_hex(16)
            path = self.root / f"attempt-{attempt_id}.json"
            record: JournalRecord = {
                "attempt_id": attempt_id, "candidate_id": candidate_id, "ingress": ingress,
                "head": head, "approval_id": approval.approval_id, "state": "RESERVED",
                "started_at": None, "completed_at": None, "status": None,
                "recovery_state": "RESULT_UNKNOWN", "reason_codes": [], "exit_code": None,
                "phase": "not_started", "cleanup_status": "not_required",
                "tun_evidence": "NOT_OBSERVED", "drop_evidence": "NOT_OBSERVED",
                "tunnel_https_evidence": "NOT_OBSERVED", "tokyo_geoip_evidence": "NOT_OBSERVED",
            }
            self._write_record(path, record)
            lock_transferred = True
            return AttemptHandle(attempt_id, path, lock_fd)
        finally:
            if not lock_transferred:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def _record_for(self, handle: AttemptHandle) -> JournalRecord:
        _require_root_owner(self.root)
        payload = json.loads(_safe_file(handle._record_path))
        if not isinstance(payload, dict) or payload.get("attempt_id") != handle.attempt_id:
            raise OSError("attempt record identity is invalid")
        return payload

    def mark_running(self, handle: AttemptHandle) -> None:
        record = self._record_for(handle)
        if record["state"] != "RESERVED":
            raise OSError("attempt is not reserved")
        record["state"] = "RUNNING"
        record["started_at"] = datetime.now(UTC).isoformat()
        self._write_record(handle._record_path, record)

    def complete(self, handle: AttemptHandle, *, result: JournalResult) -> None:
        try:
            record = self._record_for(handle)
            if record["state"] != "RUNNING":
                raise OSError("attempt is not running")
            codes = (*result.reason_codes, result.phase, result.cleanup_status)
            if any(
                not _SAFE_CODE.fullmatch(code) or len(code) > 96
                for code in codes
            ):
                raise PermissionError("result contains unsafe journal text")
            match result.recovery_state:
                case "FINALIZED":
                    if result.status is None or result.exit_code not in (0, 1):
                        raise PermissionError("result does not match its recovery state")
                case "RESULT_UNKNOWN":
                    if result.status is not None or result.exit_code is not None:
                        raise PermissionError("result does not match its recovery state")
                case unreachable:
                    assert_never(unreachable)
            record.update(asdict(result))
            record["status"] = result.status.value if result.status is not None else None
            record["reason_codes"] = list(result.reason_codes)
            match result.recovery_state:
                case "FINALIZED":
                    record["state"] = "COMPLETED"
                case "RESULT_UNKNOWN":
                    record["state"] = "RESULT_UNKNOWN"
                case unreachable:
                    assert_never(unreachable)
            record["completed_at"] = datetime.now(UTC).isoformat()
            self._write_record(handle._record_path, record)
        finally:
            handle.release()
