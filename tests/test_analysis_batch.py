from __future__ import annotations

import unittest
from pathlib import Path

from analysis_batch import (
    PHASE_PARALLEL,
    PHASE_SERIAL,
    BatchPlanError,
    BatchSchedule,
    BinaryIdentity,
    WorkerResultError,
    WorkItem,
    build_batch_schedule,
    classify_tag_plan,
    run_batch,
    validate_worker_result,
)
from analysis_planner import ExecutionPlan, PlanEdge, PlanNode


def make_node(module: str, platform: str, skill: str, order: int) -> PlanNode:
    return PlanNode(
        id=f"{module}:{platform}:{skill}",
        module=module,
        skill=skill,
        platform=platform,
        required_inputs=(),
        optional_inputs=(),
        required_outputs=(),
        optional_outputs=(),
        prerequisites=(),
        skip_if_exists=(),
        max_retries=3,
        aliases=(),
        order=order,
    )


def make_plan(nodes, edges=()) -> ExecutionPlan:
    return ExecutionPlan(
        tag="tag-1",
        nodes=tuple(nodes),
        edges=tuple(PlanEdge(source, target, kind) for source, target, kind in edges),
    )


def binary_paths_for(plan) -> dict[tuple[str, str], str]:
    paths = {}
    for node in plan.nodes:
        paths.setdefault((node.module, node.platform), f"{node.module}/{node.platform}.bin")
    return paths


class ClassifyTagPlanTests(unittest.TestCase):
    def test_no_cross_binary_edges_puts_everything_in_parallel(self):
        plan = make_plan(
            [make_node("a", "windows", "s1", 0), make_node("a", "windows", "s2", 1), make_node("a", "linux", "s1", 2)],
            edges=[("a:windows:s1", "a:windows:s2", "prerequisite")],
        )
        parallel, serial = classify_tag_plan("tag-1", plan, binary_paths_for(plan))
        self.assertEqual(serial, [])
        self.assertEqual(len(parallel), 2)
        by_binary = {(item.binary.module, item.binary.platform): item for item in parallel}
        self.assertEqual(by_binary[("a", "windows")].node_ids, ("a:windows:s1", "a:windows:s2"))
        self.assertEqual(by_binary[("a", "linux")].node_ids, ("a:linux:s1",))
        self.assertEqual({item.phase for item in parallel}, {PHASE_PARALLEL})

    def test_cross_binary_edge_moves_target_and_downstream_closure_only(self):
        plan = make_plan(
            [
                make_node("a", "windows", "a1", 0),
                make_node("a", "windows", "a2", 1),
                make_node("b", "windows", "b1", 2),
                make_node("b", "windows", "b2", 3),
                make_node("a", "windows", "a3", 4),
            ],
            edges=[
                ("a:windows:a2", "b:windows:b2", "artifact"),
                ("b:windows:b2", "a:windows:a3", "optional_input"),
            ],
        )
        parallel, serial = classify_tag_plan("tag-1", plan, binary_paths_for(plan))
        parallel_ids = [node_id for item in parallel for node_id in item.node_ids]
        serial_ids = [node_id for item in serial for node_id in item.node_ids]
        self.assertEqual(parallel_ids, ["a:windows:a1", "a:windows:a2", "b:windows:b1"])
        self.assertEqual(serial_ids, ["b:windows:b2", "a:windows:a3"])

    def test_binary_cycle_a1_b1_a2_is_segmented_not_rejected(self):
        plan = make_plan(
            [
                make_node("a", "windows", "a1", 0),
                make_node("b", "windows", "b1", 1),
                make_node("a", "windows", "a2", 2),
            ],
            edges=[
                ("a:windows:a1", "b:windows:b1", "artifact"),
                ("b:windows:b1", "a:windows:a2", "artifact"),
            ],
        )
        parallel, serial = classify_tag_plan("tag-1", plan, binary_paths_for(plan))
        self.assertEqual([item.node_ids for item in parallel], [("a:windows:a1",)])
        self.assertEqual(
            [(item.binary.module, item.node_ids) for item in serial],
            [("b", ("b:windows:b1",)), ("a", ("a:windows:a2",))],
        )

    def test_serial_queue_merges_only_consecutive_same_binary_nodes(self):
        plan = make_plan(
            [
                make_node("a", "windows", "a1", 0),
                make_node("a", "windows", "a2", 1),
                make_node("b", "windows", "b1", 2),
                make_node("a", "windows", "a3", 3),
            ],
            edges=[("a:windows:a1", "b:windows:b1", "artifact"), ("b:windows:b1", "a:windows:a3", "artifact")],
        )
        # Force a1, a2, a3 serial: b1 depends on a2 as well.
        plan = make_plan(
            list(plan.nodes),
            edges=[("a:windows:a2", "b:windows:b1", "artifact"), ("b:windows:b1", "a:windows:a3", "artifact")],
        )
        parallel, serial = classify_tag_plan("tag-1", plan, binary_paths_for(plan))
        self.assertEqual(
            [(item.binary.module, item.node_ids) for item in serial],
            [("b", ("b:windows:b1",)), ("a", ("a:windows:a3",))],
        )

    def test_unknown_edge_endpoint_fails(self):
        plan = make_plan([make_node("a", "windows", "s1", 0)], edges=[("a:windows:s1", "ghost:linux:x", "artifact")])
        with self.assertRaises(BatchPlanError):
            classify_tag_plan("tag-1", plan, binary_paths_for(plan))

    def test_build_batch_schedule_preserves_tag_order_and_rejects_duplicate_binaries(self):
        plan_a = make_plan([make_node("a", "windows", "s1", 0)])
        plan_b = make_plan([make_node("b", "windows", "s1", 0)])
        schedule = build_batch_schedule(
            [("tag-1", plan_a, binary_paths_for(plan_a)), ("tag-2", plan_b, binary_paths_for(plan_b))]
        )
        self.assertEqual(
            [item.binary.tag for item in schedule.parallel_items],
            ["tag-1", "tag-2"],
        )
        with self.assertRaises(BatchPlanError):
            build_batch_schedule(
                [("tag-1", plan_a, binary_paths_for(plan_a)), ("tag-1", plan_a, binary_paths_for(plan_a))]
            )


def make_result_payload(
    item: WorkItem, *, run_id="run-1", status="succeeded", exit_code=0, node_status="succeeded"
) -> dict:
    node_results = [{"node_id": node_id, "status": node_status, "reason": None} for node_id in item.node_ids]
    successful = sum(1 for entry in node_results if entry["status"] == "succeeded")
    skipped = sum(1 for entry in node_results if entry["status"] == "skipped")
    failed = len(node_results) - successful - skipped
    return {
        "schema_version": 1,
        "run_id": run_id,
        "work_item_id": item.work_item_id,
        "phase": item.phase,
        "tag": item.binary.tag,
        "module": item.binary.module,
        "platform": item.binary.platform,
        "binary_relative_path": item.binary.binary_relative_path,
        "node_ids": list(item.node_ids),
        "node_results": node_results,
        "status": status,
        "exit_code": exit_code,
        "summary": {"successful": successful, "failed": failed, "skipped": skipped},
        "failure_reason": None if status == "succeeded" else "worker_failure",
    }


def make_item(tag="tag-1", module="a", platform="windows", phase=PHASE_PARALLEL) -> WorkItem:
    return WorkItem(
        work_item_id=f"{phase}-0000",
        phase=phase,
        binary=BinaryIdentity(
            tag=tag, module=module, platform=platform, binary_relative_path=f"{module}/{platform}.bin"
        ),
        node_ids=(f"{module}:{platform}:s1", f"{module}:{platform}:s2"),
    )


class WorkerResultContractTests(unittest.TestCase):
    def test_valid_result_passes(self):
        item = make_item()
        result = validate_worker_result(make_result_payload(item), item, run_id="run-1")
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.summary, {"successful": 2, "failed": 0, "skipped": 0})

    def test_exact_key_set_is_enforced(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["extra"] = 1
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")

    def test_identity_mismatch_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["work_item_id"] = "parallel-9999"
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")

    def test_node_ids_order_mismatch_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["node_ids"] = list(reversed(payload["node_ids"]))
        payload["node_results"] = list(reversed(payload["node_results"]))
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")

    def test_summary_inconsistency_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["summary"]["successful"] = 5
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")

    def test_succeeded_with_failed_node_fails(self):
        item = make_item()
        payload = make_result_payload(item, node_status="failed", status="succeeded", exit_code=0)
        payload["failure_reason"] = None
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")

    def test_zero_exit_code_cannot_mask_failure(self):
        item = make_item()
        payload = make_result_payload(item, node_status="aborted", status="failed", exit_code=0)
        result = validate_worker_result(payload, item, run_id="run-1")
        self.assertEqual(result.status, "failed")

    def test_negative_counts_fail(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["summary"]["successful"] = -1
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id="run-1")


class FakeProcess:
    def __init__(self, exit_code=0, polls_until_exit=1) -> None:
        self.exit_code = exit_code
        self.remaining_polls = polls_until_exit
        self.pid = 4242
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.remaining_polls is None or self.remaining_polls > 0:
            if self.remaining_polls is not None:
                self.remaining_polls -= 1
            return None
        return self.exit_code

    def wait(self, timeout=None):
        return self.exit_code

    def terminate(self):
        self.terminated = True
        self.remaining_polls = 0

    def kill(self):
        self.killed = True
        self.remaining_polls = 0


class FakeGate:
    def __init__(self, capacity=8) -> None:
        self.capacity = capacity
        self.active = 0
        self.launch_calls: list[str] = []
        self.sleep = lambda seconds: None

    def try_admit(self, worker_name):
        if self.active >= self.capacity:
            return "fake gate saturated"
        self.launch_calls.append(worker_name)
        self.active += 1
        return None

    def worker_finished(self):
        self.active -= 1


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.clock = [0.0]
        self.temp_paths: list[Path] = []

    def _sleep(self, seconds):
        self.clock[0] += seconds

    def _launch(self, process, payload):
        import json
        import tempfile

        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(payload, handle)
        handle.close()
        path = Path(handle.name)
        self.temp_paths.append(path)
        return process, path

    def _run(self, schedule, launches, *, max_concurrency=2, gate=None, skip_error=False):
        import json

        return run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda item: launches[item.work_item_id],
            max_concurrency=max_concurrency,
            memory_gate=gate,
            skip_error=skip_error,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
            read_result_payload=lambda path: json.loads(path.read_text(encoding="utf-8")),
        )

    def test_parallel_success_runs_serial_after_barrier(self):
        p_item = make_item()
        s_item = make_item(phase=PHASE_SERIAL)
        schedule = BatchSchedule(parallel_items=(p_item,), serial_items=(s_item,))
        launches = {
            "parallel-0000": self._launch(FakeProcess(), make_result_payload(p_item)),
            "serial-0000": self._launch(FakeProcess(), make_result_payload(s_item)),
        }
        outcome = self._run(schedule, launches)
        self.assertTrue(outcome.succeeded)
        self.assertEqual(outcome.successful, 4)

    def test_parallel_failure_blocks_serial_and_aborts(self):
        p_item = make_item()
        s_item = make_item(phase=PHASE_SERIAL)
        schedule = BatchSchedule(parallel_items=(p_item,), serial_items=(s_item,))
        launches = {
            "parallel-0000": self._launch(
                FakeProcess(exit_code=1),
                make_result_payload(p_item, status="failed", exit_code=1, node_status="failed"),
            ),
        }
        outcome = self._run(schedule, launches)
        self.assertFalse(outcome.succeeded)
        self.assertIn("tag-1:a:windows:s1", outcome.aborted_node_ids)
        self.assertNotIn("serial-0000", [item_id for item_id, _ in outcome.work_item_summaries])

    def test_first_failure_stops_new_admission_without_skip_error(self):
        items = [
            WorkItem(
                work_item_id=f"parallel-{index:04d}",
                phase=PHASE_PARALLEL,
                binary=BinaryIdentity(
                    tag="tag-1", module=f"m{index}", platform="windows", binary_relative_path=f"m{index}/x.bin"
                ),
                node_ids=(f"m{index}:windows:s1",),
            )
            for index in range(3)
        ]
        schedule = BatchSchedule(parallel_items=tuple(items), serial_items=())
        launches = {
            "parallel-0000": self._launch(
                FakeProcess(exit_code=1),
                make_result_payload(items[0], status="failed", exit_code=1, node_status="failed"),
            ),
            "parallel-0001": self._launch(FakeProcess(polls_until_exit=2), make_result_payload(items[1])),
            "parallel-0002": self._launch(FakeProcess(), make_result_payload(items[2])),
        }
        outcome = self._run(schedule, launches, max_concurrency=2)
        self.assertFalse(outcome.succeeded)
        started = [item_id for item_id, _ in outcome.work_item_summaries]
        self.assertEqual(started, ["parallel-0000", "parallel-0001"])
        self.assertIn("tag-1:m2:windows:s1", outcome.aborted_node_ids)

    def test_skip_error_continues_parallel_diagnostics_but_blocks_serial(self):
        items = [
            WorkItem(
                work_item_id=f"parallel-{index:04d}",
                phase=PHASE_PARALLEL,
                binary=BinaryIdentity(
                    tag="tag-1", module=f"m{index}", platform="windows", binary_relative_path=f"m{index}/x.bin"
                ),
                node_ids=(f"m{index}:windows:s1",),
            )
            for index in range(2)
        ]
        serial_item = WorkItem(
            work_item_id="serial-0000",
            phase=PHASE_SERIAL,
            binary=BinaryIdentity(tag="tag-1", module="m0", platform="windows", binary_relative_path="m0/x.bin"),
            node_ids=("m0:windows:s9",),
        )
        schedule = BatchSchedule(parallel_items=tuple(items), serial_items=(serial_item,))
        launches = {
            "parallel-0000": self._launch(
                FakeProcess(exit_code=1),
                make_result_payload(items[0], status="failed", exit_code=1, node_status="failed"),
            ),
            "parallel-0001": self._launch(FakeProcess(), make_result_payload(items[1])),
        }
        outcome = self._run(schedule, launches, skip_error=True)
        self.assertFalse(outcome.succeeded)
        started = sorted(item_id for item_id, _ in outcome.work_item_summaries)
        self.assertEqual(started, ["parallel-0000", "parallel-0001"])
        self.assertIn("tag-1:m0:windows:s9", outcome.aborted_node_ids)

    def test_worker_timeout_terminates_worker(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        process = FakeProcess(polls_until_exit=None)
        outcome = self._run(
            schedule,
            {"parallel-0000": self._launch(process, make_result_payload(item))},
            max_concurrency=1,
        )
        self._run  # keep reference
        self.assertFalse(outcome.succeeded)
        self.assertTrue(process.terminated)

    def test_malformed_result_fails_worker(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())

        class _BadPayload:
            pass

        path = Path("unused.json")

        def read_payload(_path):
            return {"unexpected": True}

        outcome = run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda _item: (FakeProcess(), path),
            max_concurrency=1,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
            read_result_payload=read_payload,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failed, 2)

    def test_memory_gate_slots_bound_admission(self):
        items = [
            WorkItem(
                work_item_id=f"parallel-{index:04d}",
                phase=PHASE_PARALLEL,
                binary=BinaryIdentity(
                    tag="tag-1", module=f"m{index}", platform="windows", binary_relative_path=f"m{index}/x.bin"
                ),
                node_ids=(f"m{index}:windows:s1",),
            )
            for index in range(3)
        ]
        schedule = BatchSchedule(parallel_items=tuple(items), serial_items=())
        gate = FakeGate(capacity=1)
        gate.sleep = self._sleep
        launches = {
            f"parallel-{index:04d}": self._launch(FakeProcess(polls_until_exit=2), make_result_payload(items[index]))
            for index in range(3)
        }
        outcome = self._run(schedule, launches, max_concurrency=3, gate=gate)
        self.assertTrue(outcome.succeeded, self.logs)
        self.assertEqual(gate.active, 0)


if __name__ == "__main__":
    unittest.main()
