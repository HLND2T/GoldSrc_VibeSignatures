from __future__ import annotations

import os
import unittest
import unittest.mock
from types import SimpleNamespace
from unittest.mock import Mock

from analysis_memory import (
    ANALYSIS_CONCURRENCY_ENV,
    ANALYSIS_MEMORY_ENV,
    AnalysisMemoryAuthority,
    AnalysisMemoryConfigError,
    AnalysisMemoryGate,
    AnalysisMemoryLimits,
    COORDINATED_CHILD_ENV,
    is_coordinated_child,
    parse_analysis_concurrency,
    parse_analysis_memory_budget_bytes,
    resolve_analysis_limits,
    validate_limits_for_effective_concurrency,
)
from warmup_memory import MIB, MemorySnapshot


def controller_factory(job_bytes: int = 0):
    controller = SimpleNamespace(
        snapshot=Mock(return_value=MemorySnapshot(job_bytes=job_bytes)),
        budget_bytes=None,
    )
    return Mock(return_value=controller), controller


class ParseConcurrencyTests(unittest.TestCase):
    def test_unset_and_blank_default_to_one(self):
        self.assertEqual(parse_analysis_concurrency(None), 1)
        self.assertEqual(parse_analysis_concurrency(""), 1)
        self.assertEqual(parse_analysis_concurrency("   "), 1)

    def test_valid_boundaries(self):
        self.assertEqual(parse_analysis_concurrency("1"), 1)
        self.assertEqual(parse_analysis_concurrency("32"), 32)
        self.assertEqual(parse_analysis_concurrency(" 8 "), 8)

    def test_malformed_values_fail_closed(self):
        for value in ("0", "-1", "33", "1.5", "0x10", "two", "①", "+4", "1e3", "999999999999999999999"):
            with self.subTest(value=value):
                with self.assertRaises(AnalysisMemoryConfigError):
                    parse_analysis_concurrency(value)


class ParseMemoryBudgetTests(unittest.TestCase):
    def test_unset_disables_guard(self):
        self.assertIsNone(parse_analysis_memory_budget_bytes(None))
        self.assertIsNone(parse_analysis_memory_budget_bytes(" "))

    def test_valid_values(self):
        self.assertEqual(parse_analysis_memory_budget_bytes("1"), MIB)
        self.assertEqual(parse_analysis_memory_budget_bytes(" 6144 "), 6144 * MIB)

    def test_malformed_values_fail_closed(self):
        for value in ("0", "-512", "12.5", "0x100", "NaN", "∞", "+64"):
            with self.subTest(value=value):
                with self.assertRaises(AnalysisMemoryConfigError):
                    parse_analysis_memory_budget_bytes(value)


class ResolveLimitsTests(unittest.TestCase):
    def test_defaults(self):
        limits = resolve_analysis_limits(concurrency_raw=None, memory_raw=None)
        self.assertEqual(
            limits,
            AnalysisMemoryLimits(max_concurrency=1, memory_budget_bytes=None),
        )
        self.assertFalse(limits.memory_guard_enabled)

    def test_environment_is_used_when_raw_is_none(self):
        with unittest.mock.patch.dict(
            os.environ,
            {ANALYSIS_CONCURRENCY_ENV: "4", ANALYSIS_MEMORY_ENV: "8192"},
        ):
            limits = resolve_analysis_limits()
        self.assertEqual(limits.max_concurrency, 4)
        self.assertEqual(limits.memory_budget_bytes, 8192 * MIB)

    def test_effective_concurrency_above_one_requires_memory(self):
        limits = resolve_analysis_limits(concurrency_raw="4", memory_raw=None)
        with self.assertRaises(AnalysisMemoryConfigError):
            validate_limits_for_effective_concurrency(limits, 2)

    def test_effective_concurrency_one_without_memory_is_compatible(self):
        limits = resolve_analysis_limits(concurrency_raw=None, memory_raw=None)
        validate_limits_for_effective_concurrency(limits, 1)

    def test_memory_set_allows_parallel(self):
        limits = resolve_analysis_limits(concurrency_raw="2", memory_raw="8192")
        validate_limits_for_effective_concurrency(limits, 2)


class CoordinatedChildMarkerTests(unittest.TestCase):
    def test_marker_detection(self):
        self.assertFalse(is_coordinated_child({}))
        self.assertFalse(is_coordinated_child({COORDINATED_CHILD_ENV: ""}))
        self.assertFalse(is_coordinated_child({COORDINATED_CHILD_ENV: "0"}))
        self.assertFalse(is_coordinated_child({COORDINATED_CHILD_ENV: "false"}))
        self.assertTrue(is_coordinated_child({COORDINATED_CHILD_ENV: "1"}))


class AnalysisMemoryAuthorityTests(unittest.TestCase):
    def test_initialization_failure_never_leaks_a_gate(self):
        failing = SimpleNamespace(
            snapshot=Mock(side_effect=OSError("query failed")),
        )
        with self.assertRaises(OSError):
            AnalysisMemoryAuthority(10 * MIB, controller_factory=Mock(return_value=failing))

    def test_unsatisfiable_budget_fails_with_structured_error(self):
        factory, _ = controller_factory(job_bytes=0)
        with self.assertRaises(AnalysisMemoryConfigError) as ctx:
            AnalysisMemoryAuthority(
                10 * MIB,
                controller_factory=factory,
                initial_worker_reservation_bytes=8 * MIB,
                soft_limit_ratio=0.5,
            )
        self.assertIn("cannot satisfy one worker reservation", str(ctx.exception))

    def test_authority_reuses_one_gate_across_phases(self):
        factory, _ = controller_factory(job_bytes=0)
        authority = AnalysisMemoryAuthority(
            64 * MIB,
            controller_factory=factory,
            initial_worker_reservation_bytes=4 * MIB,
        )
        self.assertIsInstance(authority.gate, AnalysisMemoryGate)
        self.assertIs(authority.gate, authority.gate)

    def test_gate_admission_respects_host_headroom(self):
        class FakeHostProbe:
            def __init__(self, available: int) -> None:
                self.available = available

            def available_physical_bytes(self) -> int:
                return self.available

        constrained_factory, _ = controller_factory(job_bytes=0)
        authority = AnalysisMemoryAuthority(
            64 * MIB,
            controller_factory=constrained_factory,
            host_probe=FakeHostProbe(1 * MIB),
            initial_worker_reservation_bytes=4 * MIB,
            launch_interval_seconds=0.0,
        )
        gate = authority.gate
        with self.assertRaises(TimeoutError) as ctx:
            gate.wait_for_launch("worker-a", timeout_seconds=0.2)
        self.assertIn("host available", str(ctx.exception))

        roomy_factory, _ = controller_factory(job_bytes=0)
        authority_with_headroom = AnalysisMemoryAuthority(
            64 * MIB,
            controller_factory=roomy_factory,
            host_probe=FakeHostProbe(8 * MIB),
            initial_worker_reservation_bytes=4 * MIB,
            launch_interval_seconds=0.0,
        )
        authority_with_headroom.gate.wait_for_launch("worker-a", timeout_seconds=1.0)
        authority_with_headroom.gate.worker_finished()

    def test_memory_set_with_concurrency_one_still_enables_guard(self):
        limits = resolve_analysis_limits(concurrency_raw="1", memory_raw="4096")
        validate_limits_for_effective_concurrency(limits, 1)
        self.assertTrue(limits.memory_guard_enabled)


if __name__ == "__main__":
    unittest.main()
