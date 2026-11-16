"""Redacted probe outcomes and independently checkable evidence."""
from dataclasses import dataclass
from enum import Enum


class ProbeStatus(Enum):
    PASS = "PASS"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED = "BLOCKED"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    ingress_ip: str
    port: int
    protocol: str
    exit_ip: str | None
    status: ProbeStatus
    reason_code: str
    evidence: tuple[str, ...] = ()
