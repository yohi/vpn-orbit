from __future__ import annotations

import base64
import csv
import hashlib
import io
import unittest
from typing import Callable
from unittest.mock import patch

from vpn_orbit.cloud_probe import RemoteKey, ScreenedCandidate
from vpn_orbit.fixed_candidates import (
    FixedCandidateError,
    candidate_id,
    fixed_shortlist,
    resolve_fixed_candidate,
)
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.phase1 import Candidate, parse_catalog
from tests.test_phase1 import PROFILE

def make_catalog(raw_profiles: tuple[bytes, ...], ips: tuple[str, ...] | None = None) -> str:
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["HostName", "IP", "Score", "Ping", "Speed", "CountryShort", "OpenVPN_ConfigData_Base64"])
    addresses = ips or tuple(f"8.8.8.{index + 1}" for index in range(len(raw_profiles)))
    for ip, raw in zip(addresses, raw_profiles, strict=True):
        writer.writerow(["test.opengw.net", ip, "123", "12", "30000000", "JP", base64.b64encode(raw).decode("ascii")])
    return "*vpn_servers\n#" + stream.getvalue()


def screened(profile: str = PROFILE, raw: bytes | None = None, ip: str = "8.8.8.8") -> ScreenedCandidate:
    return ScreenedCandidate(
        candidate=Candidate("host", ip, "JP", 12, 30_000_000, 123, profile, raw),
        remote=RemoteKey(ip, 1195, "udp"),
        ingress_geo=GeoDecision.NON_TOKYO,
        catalog_rank=1,
    )


class FixedCandidateTests(unittest.TestCase):
    def test_candidate_id_uses_exact_profile_bytes(self):
        raw = PROFILE.encode()
        candidate = screened(raw=raw)
        expected = hashlib.sha256(b"8.8.8.8:1195/udp\n" + raw).hexdigest()
        self.assertEqual(candidate_id(candidate), expected)

    def test_profile_change_changes_id(self):
        first = screened(raw=PROFILE.encode())
        changed_raw = PROFILE.replace("client\n", "client\n#changed\n").encode()
        second = screened(
            profile=changed_raw.decode(),
            raw=changed_raw,
        )
        self.assertNotEqual(candidate_id(first), candidate_id(second))

    def test_fixed_shortlist_passes_empty_existing_pins_and_preserves_exclusions(self):
        catalog = make_catalog((PROFILE.encode(), PROFILE.encode()), ("119.105.93.237", "8.8.8.8"))
        geo_lookup: Callable[[str], GeoDecision] = lambda _ip: GeoDecision.NON_TOKYO
        with patch("vpn_orbit.fixed_candidates.screen_candidates", return_value=[]) as screening:
            result = fixed_shortlist(catalog, geo_lookup)
        screening.assert_called_once()
        self.assertEqual(screening.call_args.args, (catalog,))
        self.assertEqual(screening.call_args.kwargs, {
            "existing_pins": frozenset(),
            "geo_lookup": geo_lookup,
            "scan_window": 40,
            "limit": 10,
            "reachable": None,
        })
        self.assertEqual(result, ())

    def test_bom_only_difference_changes_id(self):
        raw = PROFILE.encode()
        with_bom = b"\xef\xbb\xbf" + raw
        self.assertNotEqual(
            candidate_id(screened(raw=raw)),
            candidate_id(screened(raw=with_bom)),
        )

    def test_nonbom_legacy_id_stays_identical(self):
        raw = PROFILE.encode()
        legacy = hashlib.sha256(b"8.8.8.8:1195/udp\n" + raw).hexdigest()
        self.assertEqual(candidate_id(screened(raw=raw)), legacy)

    def test_missing_id_never_selects_another_candidate(self):
        selected = screened(raw=PROFILE.encode())
        self.assertIsNone(resolve_fixed_candidate((selected,), "0" * 64))

    def test_invalid_id_is_rejected(self):
        with self.assertRaises(FixedCandidateError):
            _ = resolve_fixed_candidate((), "not-an-id")

    def test_duplicate_id_is_blocked(self):
        candidate = screened(raw=PROFILE.encode())
        with self.assertRaises(FixedCandidateError):
            _ = resolve_fixed_candidate((candidate, candidate), candidate_id(candidate))

    def test_empty_catalog_never_probes(self):
        header = "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryShort,OpenVPN_ConfigData_Base64\n"
        self.assertEqual(fixed_shortlist(header, lambda _: GeoDecision.NON_TOKYO), ())

    def test_missing_raw_profile_bytes_is_blocked(self):
        with self.assertRaises(FixedCandidateError):
            _ = candidate_id(screened())

    def test_inconsistent_raw_profile_bytes_is_blocked(self):
        with self.assertRaises(FixedCandidateError):
            _ = candidate_id(screened(raw=b"different profile"))

    def test_bom_old_normalized_id_never_authorizes_probe(self):
        raw = b"\xef\xbb\xbf" + PROFILE.encode()
        candidate = screened(raw=raw)
        legacy_normalized_id = hashlib.sha256(
            b"8.8.8.8:1195/udp\n" + PROFILE.encode()
        ).hexdigest()
        self.assertIsNone(resolve_fixed_candidate((candidate,), legacy_normalized_id))

    def test_issue9_legacy_id_is_not_auto_migrated(self):
        raw = b"\xef\xbb\xbf" + PROFILE.encode()
        candidate = screened(raw=raw)
        issue9_legacy_id = hashlib.sha256(
            b"8.8.8.8:1195/udp\n" + PROFILE.encode()
        ).hexdigest()
        self.assertIsNone(resolve_fixed_candidate((candidate,), issue9_legacy_id))

    def test_parse_catalog_preserves_raw_profile_bytes(self):
        raw = b"\xef\xbb\xbf" + PROFILE.encode()
        parsed = parse_catalog(make_catalog((raw,), ("8.8.8.8",)))
        self.assertEqual(parsed[0].profile, PROFILE)
        self.assertEqual(parsed[0].profile_raw_bytes, raw)


if __name__ == "__main__":
    _ = unittest.main()
