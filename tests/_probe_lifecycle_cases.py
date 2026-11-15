import tempfile
import unittest
from pathlib import Path

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import _candidate
from vpn_orbit.geoip import GeoDecision
from vpn_orbit.openvpn_probe import ProbeStatus, probe_candidates, probe_one


class LifecycleTests(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-orbit-probe-")
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)

    def test_private_dir_removed_after_success(self):
        runner = FakeRunner(self.tmp)
        probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
        assert runner._resources is not None
        self.assertFalse(runner._resources.private_dir.exists())

    def test_private_dir_removed_after_timeout(self):
        runner = FakeRunner(self.tmp)
        runner.wait_for_tun_result = (None, "timeout")
        probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner, timeout_s=5)
        assert runner._resources is not None
        self.assertFalse(runner._resources.private_dir.exists())

    def test_probe_candidates_isolates_exceptions(self):
        class ExplodingRunner(FakeRunner):
            def start_openvpn(self, *args, **kwargs):
                raise RuntimeError("boom")
        results = probe_candidates([_candidate(self.tmp)], geo_lookup=lambda _: GeoDecision.UNKNOWN,
                                   runner=ExplodingRunner(self.tmp))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(results[0].reason_code, "probe_exception:RuntimeError")
