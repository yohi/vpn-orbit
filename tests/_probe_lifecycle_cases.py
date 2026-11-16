import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import _candidate
from vpn_orbit.geoip import GeoDecision
import vpn_orbit.openvpn_probe as openvpn_probe
from vpn_orbit.openvpn_probe import ProbeStatus, probe_candidates, probe_one
from vpn_orbit.probe_lifecycle import bounded


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

    def test_probe_candidates_stops_after_cleanup_failure(self):
        candidate = _candidate(self.tmp)
        cleanup_failed = openvpn_probe.ProbeResult(
            candidate.remote.ip, candidate.remote.port, candidate.remote.protocol,
            None, ProbeStatus.FAIL, "cleanup_failed:teardown_failed",
        )
        with patch.object(openvpn_probe, "probe_one", return_value=cleanup_failed) as probe:
            results = probe_candidates([candidate, candidate], geo_lookup=lambda _: GeoDecision.UNKNOWN)
        self.assertEqual(results, [cleanup_failed])
        probe.assert_called_once()

    def test_nested_bounded_restores_remaining_outer_deadline(self):
        alarms: list[tuple[int, float, float]] = []
        with patch("vpn_orbit.probe_lifecycle.threading.current_thread", return_value=threading.main_thread()), \
             patch("vpn_orbit.probe_lifecycle.signal.signal"), \
             patch("vpn_orbit.probe_lifecycle.signal.getitimer", side_effect=[(0, 0), (8, 0)]), \
             patch("vpn_orbit.probe_lifecycle.signal.setitimer", side_effect=lambda which, seconds, interval=0: alarms.append((which, seconds, interval)) or (0, 0)), \
             patch("vpn_orbit.probe_lifecycle.time.monotonic", side_effect=[10.0, 10.0, 12.0, 15.0]):
            with bounded(20.0):
                with bounded(30.0):
                    pass
        self.assertEqual([seconds for _, seconds, _ in alarms], [10.0, 8.0, 0, 6.0, 0])
