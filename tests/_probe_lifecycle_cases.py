import threading
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests._fake_runner import FakeRunner
from tests._probe_fixtures import _candidate
from vpn_orbit.geoip import GeoDecision
import vpn_orbit.openvpn_probe as openvpn_probe
from vpn_orbit.openvpn_probe import ProbeStatus, probe_candidates, probe_one
from vpn_orbit.probe_lifecycle import ProbeDeadline, bounded


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

    def test_shared_runner_diagnostics_do_not_leak_to_later_parse_failure(self):
        class ObservingRunner(FakeRunner):
            openvpn_failure_code = "not_observed"
            openvpn_progress = "not_observed"
            openvpn_process_state = "not_started"
            link_io = "not_observed"

            def wait_for_tun(self, *args, **kwargs):
                self.openvpn_progress = "tls_packet_seen"
                self.openvpn_process_state = "exited"
                self.link_io = "tx_only"
                return None, "unavailable"

        runner = ObservingRunner(self.tmp)
        valid = _candidate(self.tmp)
        invalid = replace(valid, candidate=replace(valid.candidate, profile="invalid"))

        results = probe_candidates(
            [valid, invalid], geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner,
        )

        self.assertEqual(results[1].reason_code, "profile_parse_failed")
        self.assertEqual(results[1].openvpn_progress, "not_observed")
        self.assertEqual(results[1].openvpn_process_state, "not_started")
        self.assertEqual(results[1].link_io, "not_observed")

    def test_deadline_reports_tun_wait_and_redacted_cleanup(self):
        class DeadlineRunner(FakeRunner):
            def wait_for_tun(self, *args, **kwargs):
                raise ProbeDeadline("must-not-appear-in-output")

        runner = DeadlineRunner(self.tmp)
        result = probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.UNKNOWN, runner=runner)
        self.assertEqual(result.status, ProbeStatus.NOT_VERIFIED)
        self.assertEqual(result.reason_code, "probe_exception:ProbeDeadline")
        self.assertEqual(result.phase, "tun_wait")
        self.assertEqual(result.cleanup_status, "confirmed")
        self.assertGreaterEqual(result.elapsed_ms, 0)
        self.assertNotIn("must-not-appear-in-output", str(result))

    def test_tun_timeout_attaches_fixed_hint_and_preserves_cleanup(self):
        class DeadlineRunner(FakeRunner):
            openvpn_failure_code = "tls_handshake_failed"
            openvpn_progress = "tls_packet_seen"
            openvpn_process_state = "running"
            link_io = "tx_only"

            def wait_for_tun(self, *args, **kwargs):
                raise ProbeDeadline("UNTRUSTED_SECRET")

        result = probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.UNKNOWN,
                           runner=DeadlineRunner(self.tmp))
        self.assertEqual(result.reason_code, "probe_exception:ProbeDeadline:openvpn_tls_handshake_failed")
        self.assertEqual(result.phase, "tun_wait")
        self.assertEqual(result.cleanup_status, "confirmed")
        self.assertEqual(result.openvpn_progress, "tls_packet_seen")
        self.assertEqual(result.openvpn_process_state, "running")
        self.assertEqual(result.link_io, "tx_only")
        self.assertNotIn("UNTRUSTED_SECRET", str(result))

    def test_unknown_openvpn_hint_is_rejected(self):
        class DeadlineRunner(FakeRunner):
            openvpn_failure_code = "SECRET_DO_NOT_EMIT"
            openvpn_progress = "SECRET_DO_NOT_EMIT"
            openvpn_process_state = "SECRET_DO_NOT_EMIT"
            link_io = "SECRET_DO_NOT_EMIT"

            def wait_for_tun(self, *args, **kwargs):
                raise ProbeDeadline("ALSO_SECRET")

        result = probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.UNKNOWN,
                           runner=DeadlineRunner(self.tmp))
        self.assertEqual(result.reason_code, "probe_exception:ProbeDeadline")
        self.assertEqual(result.openvpn_progress, "not_observed")
        self.assertEqual(result.openvpn_process_state, "not_started")
        self.assertEqual(result.link_io, "not_observed")
        self.assertNotIn("SECRET", str(result))

    def test_cleanup_failure_cannot_be_reported_as_success(self):
        runner = FakeRunner(self.tmp)
        runner.teardown_isolation = lambda resources: (False, "secret-not-logged")
        result = probe_one(_candidate(self.tmp), geo_lookup=lambda _: GeoDecision.TOKYO, runner=runner)
        self.assertEqual(result.status, ProbeStatus.FAIL)
        self.assertEqual(result.phase, "cleanup")
        self.assertEqual(result.cleanup_status, "failed")
        self.assertNotIn("secret-not-logged", str(result))

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
