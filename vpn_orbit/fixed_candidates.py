from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Sequence

from .cloud_probe import ScreenedCandidate, screen_candidates
from .geoip import GeoDecision


class FixedCandidateError(ValueError):
    pass


_CANDIDATE_ID = re.compile(r"[0-9a-f]{64}")


def candidate_id(candidate: ScreenedCandidate) -> str:
    raw = candidate.candidate.profile_raw_bytes
    if raw is None:
        raise FixedCandidateError("candidate_identity_unavailable")
    try:
        profile = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FixedCandidateError("candidate_identity_unavailable") from exc
    if profile != candidate.candidate.profile:
        raise FixedCandidateError("candidate_identity_unavailable")

    remote_identity = f"{candidate.remote.ip}:{candidate.remote.port}/{candidate.remote.protocol}\n".encode("ascii")
    return hashlib.sha256(remote_identity + raw).hexdigest()


def fixed_shortlist(
    catalog: str, geo_lookup: Callable[[str], GeoDecision],
) -> tuple[ScreenedCandidate, ...]:
    return tuple(screen_candidates(
        catalog,
        existing_pins=frozenset(),
        geo_lookup=geo_lookup,
        scan_window=40,
        limit=10,
        reachable=None,
    ))


def resolve_fixed_candidate(
    candidates: Sequence[ScreenedCandidate], requested_id: str,
) -> ScreenedCandidate | None:
    if _CANDIDATE_ID.fullmatch(requested_id) is None:
        raise FixedCandidateError("invalid_candidate_id")

    identities: set[str] = set()
    match: ScreenedCandidate | None = None
    for candidate in candidates:
        identity = candidate_id(candidate)
        if identity in identities:
            raise FixedCandidateError("duplicate_candidate_id")
        identities.add(identity)
        if identity == requested_id:
            match = candidate
    return match
