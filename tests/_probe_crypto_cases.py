import tempfile
import time
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_round3 import _candidate
from vpn_orbit.config_validation import spki_match, validate_pem
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.live_runner import SubprocessRunner
from vpn_orbit.openvpn_probe import ProbeStatus, probe_one
from vpn_orbit.probe_commands import Commands


class CryptoRecorder(Commands):
    def __init__(self) -> None:
        super().__init__(time.monotonic() + 5)
        self.calls: list[tuple[list[str], bytes, float]] = []
        self.outputs = [b"certificate-public", b"matching-DER", b"matching-DER"]

    def openssl(self, args: Sequence[str], data: bytes, timeout_s: float) -> bytes:
        self.calls.append((list(args), data, timeout_s))
        return self.outputs.pop(0)


class CryptoOwnershipTests(unittest.TestCase):
    def test_probe_passes_validation_owner_through_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner(Path(directory))
            owner = CryptoRecorder()
            with patch.object(runner, "validation_commands", return_value=owner) as requested:
                result = probe_one(_candidate(), runner=runner, geo_lookup=lambda _: GeoDecision.TOKYO)
            self.assertEqual(result.status, ProbeStatus.PASS)
            requested.assert_called_once_with()
            self.assertEqual([call[0] for call in owner.calls], [["x509", "-noout"]])

    def test_ca_validation_uses_supplied_owner(self):
        # Given the adapter that owns validation subprocesses.
        owner = CryptoRecorder()
        ca = (Path(__file__).parent / "fixtures" / "test-ca.pem").read_text()
        # When a CA crosses the synthesis boundary.
        validate_pem(ca, commands=owner)
        # Then the owner receives its input, not an untracked verifier child.
        self.assertEqual(len(owner.calls), 1)
        self.assertEqual(owner.calls[0][:2], (["x509", "-noout"], ca.strip().encode()))

    def test_spki_steps_share_supplied_owner(self):
        # Given distinct certificate and private-key input values.
        owner = CryptoRecorder()
        # When the three-step SPKI comparison executes.
        matched, reason = spki_match(b"cert-input", b"key-input", commands=owner)
        # Then every subprocess goes through the owner with a bounded timeout.
        self.assertTrue(matched, reason)
        self.assertEqual([call[0] for call in owner.calls], [
            ["x509", "-pubkey", "-noout"], ["pkey", "-pubin", "-outform", "DER"],
            ["pkey", "-pubout", "-outform", "DER"]])
        self.assertEqual([call[1] for call in owner.calls], [b"cert-input", b"certificate-public", b"key-input"])
        self.assertTrue(all(0 < call[2] <= 5 for call in owner.calls))

    def test_live_adapter_has_no_unsupervised_validation_fallback(self):
        # Given a live adapter with no supervisor.
        owner = SubprocessRunner()
        # When validation ownership is requested before startup.
        with self.assertRaises(RuntimeError):
            owner.validation_commands()
