from __future__ import annotations

import json
import unittest
import unittest.mock
import contextlib
import io
import os
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

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
    work_item_run_id,
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
    def test_selected_schedule_classifies_complete_dag_before_filtering(self):
        from analysis_batch import select_batch_schedule

        nodes = [
            make_node("a", "windows", "first", 0),
            make_node("b", "windows", "bridge", 1),
            make_node("a", "windows", "last", 2),
        ]
        plan = make_plan(nodes, [(nodes[0].id, nodes[1].id, "artifact"), (nodes[1].id, nodes[2].id, "artifact")])
        schedule = select_batch_schedule(
            build_batch_schedule([("tag-1", plan, binary_paths_for(plan))]), {"tag-1": (nodes[0].id, nodes[2].id)}
        )
        self.assertEqual([(nodes[0].id,)], [item.node_ids for item in schedule.parallel_items])
        self.assertEqual([(nodes[2].id,)], [item.node_ids for item in schedule.serial_items])
        self.assertEqual(schedule.parallel_items[0].binary, schedule.serial_items[0].binary)

    def test_batch_manifest_rejects_invalid_structure_without_correction(self):
        from analysis_batch import validate_batch_selections

        valid = {"schema_version": 1, "selections": [{"tag": "tag-1", "node_ids": ["a:windows:first"]}]}
        self.assertEqual({"tag-1": ("a:windows:first",)}, validate_batch_selections(valid, ["tag-1"]))
        invalid = [
            None,
            [],
            {},
            {**valid, "schema_version": True},
            {**valid, "schema_version": 2},
            {**valid, "extra": 1},
            {**valid, "selections": []},
        ]
        for entry in [
            None,
            {},
            {"tag": "unknown", "node_ids": ["n"]},
            {"tag": "tag-1", "node_ids": []},
            {"tag": "tag-1", "node_ids": ["n", "n"]},
            {"tag": "tag-1", "node_ids": [1]},
            {"tag": "tag-1", "node_ids": "n"},
            {"tag": "tag-1", "node_ids": [" n"]},
        ]:
            invalid.append({**valid, "selections": [entry]})
        invalid.append({**valid, "selections": valid["selections"] * 2})
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(BatchPlanError):
                validate_batch_selections(payload, ["tag-1"])

    def test_selected_serial_segments_merge_only_after_filtering_without_losing_order(self):
        from analysis_batch import select_batch_schedule

        nodes = [
            make_node("a", "windows", "first", 0),
            make_node("b", "windows", "one", 1),
            make_node("c", "windows", "middle", 2),
            make_node("b", "windows", "two", 3),
        ]
        plan = make_plan(nodes, [(nodes[index].id, nodes[index + 1].id, "artifact") for index in range(3)])
        schedule = select_batch_schedule(
            build_batch_schedule([("tag-1", plan, binary_paths_for(plan))]), {"tag-1": (nodes[1].id, nodes[3].id)}
        )
        self.assertEqual((), schedule.parallel_items)
        self.assertEqual([(nodes[1].id, nodes[3].id)], [item.node_ids for item in schedule.serial_items])

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

    def test_build_batch_schedule_preserves_tag_order_and_rejects_duplicate_nodes(self):
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

    def test_build_batch_schedule_accepts_cross_phase_binary_reopen(self):
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
        schedule = build_batch_schedule([("tag-1", plan, binary_paths_for(plan))])
        parallel_binaries = [(item.binary.module, item.binary.platform) for item in schedule.parallel_items]
        serial_binaries = [(item.binary.module, item.binary.platform) for item in schedule.serial_items]
        self.assertEqual(parallel_binaries, [("a", "windows")])
        self.assertEqual(serial_binaries, [("b", "windows"), ("a", "windows")])

    def test_build_batch_schedule_numbers_work_item_ids_across_the_whole_batch(self):
        plans = []
        for tag in ("tag-1", "tag-2", "tag-3"):
            plan = make_plan([make_node("a", "windows", "s1", 0), make_node("b", "windows", "s1", 1)])
            plans.append((tag, plan, binary_paths_for(plan)))
        schedule = build_batch_schedule(plans)
        parallel_ids = [item.work_item_id for item in schedule.parallel_items]
        self.assertEqual(
            parallel_ids,
            ["parallel-0000", "parallel-0001", "parallel-0002", "parallel-0003", "parallel-0004", "parallel-0005"],
        )
        self.assertEqual(len(set(parallel_ids)), len(parallel_ids))
        cross_tag_plan = make_plan([make_node("a", "windows", "s1", 0)])
        other_tag = make_plan([make_node("a", "windows", "s1", 0)])
        mixed = build_batch_schedule(
            [
                ("tag-1", cross_tag_plan, binary_paths_for(cross_tag_plan)),
                ("tag-2", other_tag, binary_paths_for(other_tag)),
            ]
        )
        self.assertEqual([item.work_item_id for item in mixed.parallel_items], ["parallel-0000", "parallel-0001"])
        self.assertEqual({item.binary.tag for item in mixed.parallel_items}, {"tag-1", "tag-2"})


def make_result_payload(
    item: WorkItem, *, run_id=None, status="succeeded", exit_code=0, node_status="succeeded"
) -> dict:
    if run_id is None:
        run_id = work_item_run_id("run-1", item.work_item_id)
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
        result = validate_worker_result(
            make_result_payload(item), item, run_id=work_item_run_id("run-1", item.work_item_id)
        )
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.summary, {"successful": 2, "failed": 0, "skipped": 0})

    def test_exact_key_set_is_enforced(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["extra"] = 1
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))

    def test_identity_mismatch_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["work_item_id"] = "parallel-9999"
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))

    def test_node_ids_order_mismatch_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["node_ids"] = list(reversed(payload["node_ids"]))
        payload["node_results"] = list(reversed(payload["node_results"]))
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))

    def test_summary_inconsistency_fails(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["summary"]["successful"] = 5
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))

    def test_succeeded_with_failed_node_fails(self):
        item = make_item()
        payload = make_result_payload(item, node_status="failed", status="succeeded", exit_code=0)
        payload["failure_reason"] = None
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))

    def test_zero_exit_code_cannot_mask_failure(self):
        item = make_item()
        payload = make_result_payload(item, node_status="aborted", status="failed", exit_code=0)
        result = validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))
        self.assertEqual(result.status, "failed")

    def test_negative_counts_fail(self):
        item = make_item()
        payload = make_result_payload(item)
        payload["summary"]["successful"] = -1
        with self.assertRaises(WorkerResultError):
            validate_worker_result(payload, item, run_id=work_item_run_id("run-1", item.work_item_id))


class FakeProcess:
    def __init__(self, exit_code=0, polls_until_exit=1, stubborn=False, interrupt_wait=False) -> None:
        self.exit_code = exit_code
        self.remaining_polls = polls_until_exit
        self.pid = 4242
        self.terminated = False
        self.killed = False
        self.stubborn = stubborn
        self.interrupt_wait = interrupt_wait
        self.tree_killed = False

    def _running(self):
        return self.remaining_polls is None or self.remaining_polls > 0

    def poll(self):
        if self._running():
            if self.remaining_polls is not None:
                self.remaining_polls -= 1
            return None
        return self.exit_code

    def wait(self, timeout=None):
        if self.interrupt_wait and self._running():
            raise KeyboardInterrupt
        if self.stubborn and self._running():
            import subprocess

            raise subprocess.TimeoutExpired(cmd="fake-worker", timeout=timeout)
        self.remaining_polls = 0
        return self.exit_code

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
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
        import tempfile

        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(payload, handle)
        handle.close()
        path = Path(handle.name)
        self.temp_paths.append(path)
        return process, path

    def _run(self, schedule, launches, *, max_concurrency=2, gate=None, skip_error=False, kill_tree=None):
        import json

        return run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda item: launches[item.work_item_id],
            max_concurrency=max_concurrency,
            memory_gate=gate,
            skip_error=skip_error,
            kill_process_tree=kill_tree,
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

    def test_worker_timeout_hard_kills_tree_even_when_root_would_exit_first(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        # A lenient root exits as soon as terminate() touches it; the tree kill
        # must still run while the root is alive, because descendants cannot be
        # attributed to the worker after the root exits.
        process = FakeProcess(polls_until_exit=None)
        tree_kills = []

        def kill_tree(target):
            tree_kills.append(target)
            target.tree_killed = True
            target.remaining_polls = 0

        outcome = run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda _item: self._launch(process, make_result_payload(item)),
            max_concurrency=1,
            worker_timeout_seconds=0.5,
            kill_process_tree=kill_tree,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(tree_kills, [process])
        self.assertTrue(process.tree_killed)

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

    def test_worker_result_run_id_must_be_scoped_to_work_item(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        launches = {
            "parallel-0000": self._launch(FakeProcess(), make_result_payload(item, run_id="run-1")),
        }
        outcome = self._run(schedule, launches)
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.work_item_summaries, (("parallel-0000", "failed"),))
        self.assertTrue(any("run_id mismatch" in line for line in self.logs), self.logs)

    def test_worker_level_failure_without_failed_nodes_fails_the_batch(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        launches = {
            "parallel-0000": self._launch(
                FakeProcess(exit_code=1),
                make_result_payload(item, status="failed", exit_code=1),
            ),
        }
        outcome = self._run(schedule, launches)
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_failed")
        self.assertEqual(outcome.successful, 2)
        self.assertEqual(outcome.failed, 0)
        self.assertEqual(outcome.work_item_summaries, (("parallel-0000", "failed"),))

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

    def test_worker_timeout_hard_kills_stubborn_process_tree(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        process = FakeProcess(polls_until_exit=None, stubborn=True)
        tree_kills = []

        def kill_tree(target):
            tree_kills.append(target)
            target.tree_killed = True
            target.remaining_polls = 0

        outcome = run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda _item: self._launch(process, make_result_payload(item)),
            max_concurrency=1,
            worker_timeout_seconds=0.5,
            kill_process_tree=kill_tree,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_timeout")
        self.assertFalse(process.terminated)
        self.assertTrue(process.tree_killed)
        self.assertEqual(tree_kills, [process])

    def test_serial_timeout_hard_kills_stubborn_process_tree(self):
        p_item = make_item()
        s_item = make_item(phase=PHASE_SERIAL)
        schedule = BatchSchedule(parallel_items=(p_item,), serial_items=(s_item,))
        serial_process = FakeProcess(polls_until_exit=None, stubborn=True)
        tree_kills = []

        def kill_tree(target):
            tree_kills.append(target)
            target.tree_killed = True
            target.remaining_polls = 0

        outcome = run_batch(
            schedule,
            run_id="run-1",
            launch_worker=lambda item: (
                self._launch(FakeProcess(), make_result_payload(item))
                if item.phase == PHASE_PARALLEL
                else self._launch(serial_process, make_result_payload(item))
            ),
            max_concurrency=1,
            worker_timeout_seconds=0.5,
            kill_process_tree=kill_tree,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_timeout")
        self.assertFalse(serial_process.terminated)
        self.assertTrue(serial_process.tree_killed)
        self.assertEqual(tree_kills, [serial_process])

    def test_cancellation_tears_down_active_workers_and_reraises(self):
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
        schedule = BatchSchedule(parallel_items=tuple(items), serial_items=())
        process = FakeProcess(polls_until_exit=None, stubborn=True)
        tree_kills = []

        def kill_tree(target):
            tree_kills.append(target)
            target.tree_killed = True
            target.remaining_polls = 0

        def launch(item):
            if item.work_item_id == "parallel-0000":
                return self._launch(process, make_result_payload(item))
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            run_batch(
                schedule,
                run_id="run-1",
                launch_worker=launch,
                max_concurrency=2,
                kill_process_tree=kill_tree,
                poll_interval_seconds=0.1,
                monotonic=lambda: self.clock[0],
                sleep=self._sleep,
                log=self.logs.append,
            )
        self.assertTrue(process.tree_killed)
        self.assertEqual(tree_kills, [process])
        self.assertTrue(any("tearing down owned worker process trees" in line for line in self.logs), self.logs)

    def test_serial_cancellation_tears_down_in_flight_serial_worker(self):
        p_item = make_item()
        s_item = make_item(phase=PHASE_SERIAL)
        schedule = BatchSchedule(parallel_items=(p_item,), serial_items=(s_item,))
        # wait() raises KeyboardInterrupt while the serial worker is still
        # running; the worker must stay in `active` so the cancellation sweep
        # owns its process-tree teardown.
        serial_process = FakeProcess(polls_until_exit=None, interrupt_wait=True)
        tree_kills = []

        def kill_tree(target):
            tree_kills.append(target)
            target.tree_killed = True
            target.remaining_polls = 0

        def launch(item):
            if item.phase == PHASE_PARALLEL:
                return self._launch(FakeProcess(), make_result_payload(item))
            return self._launch(serial_process, make_result_payload(item))

        with self.assertRaises(KeyboardInterrupt):
            run_batch(
                schedule,
                run_id="run-1",
                launch_worker=launch,
                max_concurrency=1,
                kill_process_tree=kill_tree,
                poll_interval_seconds=0.1,
                monotonic=lambda: self.clock[0],
                sleep=self._sleep,
                log=self.logs.append,
            )
        self.assertTrue(serial_process.tree_killed)
        self.assertEqual(tree_kills, [serial_process])
        self.assertTrue(any("tearing down owned worker process trees" in line for line in self.logs), self.logs)

    def _run_with_cleanup_failure(self, *, kill_tree, launch, schedule, gate, skip_error):
        return run_batch(
            schedule,
            run_id="run-1",
            launch_worker=launch,
            max_concurrency=1,
            memory_gate=gate,
            skip_error=skip_error,
            worker_timeout_seconds=0.5,
            kill_process_tree=kill_tree,
            poll_interval_seconds=0.1,
            monotonic=lambda: self.clock[0],
            sleep=self._sleep,
            log=self.logs.append,
        )

    def test_kill_command_failure_keeps_worker_tracked_with_slot_reserved(self):
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
        schedule = BatchSchedule(parallel_items=tuple(items), serial_items=())
        process = FakeProcess(polls_until_exit=None, stubborn=True)
        kill_attempts = []

        def kill_tree(target):
            kill_attempts.append(target)
            raise RuntimeError("taskkill unavailable")

        gate = FakeGate(capacity=4)
        # skip_error must not re-arm admission behind an unconfirmed worker.
        outcome = self._run_with_cleanup_failure(
            kill_tree=kill_tree,
            launch=lambda item: self._launch(process, make_result_payload(item)),
            schedule=schedule,
            gate=gate,
            skip_error=True,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_cleanup_failed")
        self.assertEqual(outcome.uncleaned_work_item_ids, ("parallel-0000",))
        self.assertEqual(gate.active, 1)
        self.assertEqual(kill_attempts, [process])
        self.assertEqual(outcome.work_item_summaries, (("parallel-0000", "failed"),))
        self.assertIn("tag-1:m1:windows:s1", outcome.aborted_node_ids)
        self.assertTrue(any("process tree kill failed" in line for line in self.logs), self.logs)

    def test_exit_wait_timeout_after_kill_is_a_cleanup_failure(self):
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        process = FakeProcess(polls_until_exit=None, stubborn=True)
        tree_kills = []

        def kill_tree(target):
            # The kill command "succeeds" but the worker never exits.
            tree_kills.append(target)
            target.tree_killed = True

        gate = FakeGate(capacity=4)
        outcome = self._run_with_cleanup_failure(
            kill_tree=kill_tree,
            launch=lambda _item: self._launch(process, make_result_payload(item)),
            schedule=schedule,
            gate=gate,
            skip_error=False,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_cleanup_failed")
        self.assertEqual(outcome.uncleaned_work_item_ids, ("parallel-0000",))
        self.assertEqual(gate.active, 1)
        self.assertEqual(tree_kills, [process])
        self.assertTrue(any("exit could not be confirmed" in line for line in self.logs), self.logs)

    def test_kill_failure_with_root_exit_is_still_a_cleanup_failure(self):
        # The kill command fails while the root subsequently exits on its own:
        # a root exit never proves the reparented descendants exited, so the
        # slot must stay reserved and the worker must stay tracked.
        item = make_item()
        schedule = BatchSchedule(parallel_items=(item,), serial_items=())
        process = FakeProcess(polls_until_exit=None)
        kill_attempts = []

        def kill_tree(target):
            kill_attempts.append(target)
            raise RuntimeError("taskkill unavailable")

        gate = FakeGate(capacity=4)
        outcome = self._run_with_cleanup_failure(
            kill_tree=kill_tree,
            launch=lambda _item: self._launch(process, make_result_payload(item)),
            schedule=schedule,
            gate=gate,
            skip_error=True,
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_cleanup_failed")
        self.assertEqual(outcome.uncleaned_work_item_ids, ("parallel-0000",))
        self.assertEqual(gate.active, 1)
        self.assertEqual(kill_attempts, [process])
        self.assertTrue(any("owned tree exit cannot be confirmed" in line for line in self.logs), self.logs)

    def test_serial_cleanup_failure_keeps_slot_reserved_and_blocks_remaining_segments(self):
        p_item = make_item()
        s_items = [
            WorkItem(
                work_item_id=f"serial-{index:04d}",
                phase=PHASE_SERIAL,
                binary=BinaryIdentity(
                    tag="tag-1", module=f"m{index}", platform="windows", binary_relative_path=f"m{index}/x.bin"
                ),
                node_ids=(f"m{index}:windows:s1",),
            )
            for index in range(2)
        ]
        schedule = BatchSchedule(parallel_items=(p_item,), serial_items=tuple(s_items))
        serial_process = FakeProcess(polls_until_exit=None, stubborn=True)

        def kill_tree(target):
            raise RuntimeError("taskkill unavailable")

        def launch(item):
            if item.phase == PHASE_PARALLEL:
                return self._launch(FakeProcess(), make_result_payload(item))
            return self._launch(serial_process, make_result_payload(item))

        gate = FakeGate(capacity=4)
        outcome = self._run_with_cleanup_failure(
            kill_tree=kill_tree, launch=launch, schedule=schedule, gate=gate, skip_error=False
        )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.failure_reason, "worker_cleanup_failed")
        self.assertEqual(outcome.uncleaned_work_item_ids, ("serial-0000",))
        self.assertEqual(gate.active, 1)
        self.assertIn("tag-1:m1:windows:s1", outcome.aborted_node_ids)


if __name__ == "__main__":
    unittest.main()


class InternalWorkerEntryTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.addCleanup(self._temp.cleanup)

    def _write_request(self, item: WorkItem, result_path: Path) -> Path:
        import ida_analyze_bin as iab

        options = {
            "configyaml": "configs/tag-1.yaml",
            "bindir": "bin",
            "artifactdir": "bin_artifacts",
            "platforms": ["windows"],
            "agent": "claude",
            "agent_model": "",
            "llm_model": "gpt-4o",
            "llm_baseurl": None,
            "llm_temperature": None,
            "llm_effort": "medium",
            "llm_fake_as": None,
            "maxretry": 3,
            "skip_error": False,
            "skip_pp": False,
            "debug": False,
            "ida_args": "",
            "process_reporter": "none",
            "redis_url": None,
            "redis_prefix": "gsvibe",
        }
        request = {
            "run_id": work_item_run_id("run-1", item.work_item_id),
            "work_item_id": item.work_item_id,
            "phase": item.phase,
            "tag": item.binary.tag,
            "module": item.binary.module,
            "platform": item.binary.platform,
            "binary_relative_path": item.binary.binary_relative_path,
            "node_ids": list(item.node_ids),
            "result_path": str(result_path),
            "options": options,
        }
        request_path = self.root / f"{item.work_item_id}.request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        return request_path

    def test_worker_success_writes_valid_result_contract(self):
        import ida_analyze_bin as iab

        item = make_item()
        result_path = self.root / "result.json"
        request_path = self._write_request(item, result_path)
        calls = {}

        from process_reporter import ProcessEvent, ProcessEventType, ProcessPhase, TaskStatus

        def fake_analyze(**kwargs):
            calls.update(kwargs)
            summary = kwargs["summary"]
            selected = list(kwargs["selected_node_ids"])
            summary.successful += len(selected)
            reporter = kwargs["reporter"]
            plan = {
                "nodes": [
                    {"id": f"task-{index}", "data": {"planner_node_id": node_id}}
                    for index, node_id in enumerate(selected)
                ]
            }
            reporter.initialize_run(plan, run_id=kwargs["run_id"])
            for index, _node_id in enumerate(selected):
                reporter.emit(
                    ProcessEvent(
                        run_id=kwargs["run_id"],
                        event_type=ProcessEventType.TASK_STATUS_CHANGED,
                        task_id=f"task-{index}",
                        status=TaskStatus.SUCCEEDED,
                        phase=ProcessPhase.FINISHED,
                    )
                )

        with (
            unittest.mock.patch.object(iab, "analyze", side_effect=fake_analyze),
            unittest.mock.patch.object(iab, "create_process_reporter", return_value=iab.NullProcessReporter()),
        ):
            exit_code = iab._batch_worker_main(str(request_path))
        self.assertEqual(exit_code, 0)
        self.assertEqual(calls["gamever"], "tag-1")
        self.assertIsNone(calls["oldgamever"])
        self.assertEqual(tuple(calls["selected_node_ids"]), item.node_ids)
        self.assertTrue(calls["force_all"])
        result = validate_worker_result(
            json.loads(result_path.read_text(encoding="utf-8")), item, run_id=f"run-1-{item.work_item_id}"
        )
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.summary["successful"], 2)

    def test_worker_failure_marks_remaining_nodes_not_executed(self):
        import ida_analyze_bin as iab

        item = make_item()
        result_path = self.root / "result.json"
        request_path = self._write_request(item, result_path)

        def fake_analyze(**kwargs):
            raise iab.AnalysisRunError("boom")

        with (
            unittest.mock.patch.object(iab, "analyze", side_effect=fake_analyze),
            unittest.mock.patch.object(iab, "create_process_reporter", return_value=iab.NullProcessReporter()),
        ):
            exit_code = iab._batch_worker_main(str(request_path))
        self.assertEqual(exit_code, 1)
        result = validate_worker_result(
            json.loads(result_path.read_text(encoding="utf-8")), item, run_id=f"run-1-{item.work_item_id}"
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.summary["failed"], 2)
        self.assertEqual({entry.reason for entry in result.node_results}, {"not_executed"})

    def test_worker_flag_requires_exactly_one_request_path(self):
        import ida_analyze_bin as iab

        self.assertEqual(iab.main([iab._BATCH_WORKER_FLAG]), 2)

    def test_batch_worker_options_contains_no_secrets(self):
        import argparse

        import ida_analyze_bin as iab

        args = argparse.Namespace(
            gamever="tag-1",
            configyaml=None,
            bindir="bin",
            artifactdir="bin_artifacts",
            platforms=["windows"],
            agent="claude",
            agent_model="",
            llm_model="gpt-4o",
            llm_apikey="sk-secret",
            llm_baseurl=None,
            llm_temperature=None,
            llm_effort="medium",
            llm_fake_as=None,
            maxretry=3,
            skip_error=False,
            skip_pp=False,
            debug=False,
            ida_args="",
            process_reporter="none",
            redis_url=None,
            redis_prefix="gsvibe",
        )
        with unittest.mock.patch.object(iab, "resolve_analysis_config", return_value=Path("configs/tag-1.yaml")):
            options = iab._batch_worker_options(args)
        self.assertNotIn("llm_apikey", options)
        self.assertNotIn("api_key", options)
        self.assertNotIn("sk-secret", json.dumps(options))


class MainRoutingTests(unittest.TestCase):
    def test_batch_selection_cli_conflicts_are_explicit(self):
        import ida_analyze_bin as analyzer

        flags_list = [
            ["-gamever", "hl-8684"],
            ["-allgamever"],
            ["-node", "a:windows:x"],
            ["-modules", "*"],
            ["-platform", "windows"],
            ["-force_all"],
            ["-oldgamever", "none"],
            ["-configyaml", "x.yaml"],
            ["-skill", "x"],
            ["-skip_error"],
        ]
        for flags in flags_list:
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                analyzer.parse_args(["-batch_selection", "selection.json", *flags])
        with unittest.mock.patch.object(analyzer, "_run_full_batch", return_value=0) as coordinator:
            self.assertEqual(0, analyzer.main(["-batch_selection", "selection.json"]))
        self.assertEqual("selection.json", coordinator.call_args.args[0].batch_selection)

    def test_full_force_all_routes_to_batch_coordinator(self):
        import ida_analyze_bin as iab

        called = {}
        with (
            unittest.mock.patch.object(
                iab, "_run_full_batch", side_effect=lambda args: (called.__setitem__("args", args), 7)[1]
            ),
            unittest.mock.patch.object(iab, "run_all", return_value=0) as legacy,
        ):
            rc = iab.main(["-allgamever", "-force_all", "-agent", "claude", "-llm_apikey", "k"])
        self.assertEqual(rc, 7)
        legacy.assert_not_called()

    def test_non_full_allgamever_keeps_legacy_path(self):
        import ida_analyze_bin as iab

        with (
            unittest.mock.patch.object(iab, "_run_full_batch", return_value=0) as batch,
            unittest.mock.patch.object(iab, "run_all", return_value=0) as legacy,
        ):
            rc = iab.main(["-allgamever", "-agent", "claude", "-llm_apikey", "k"])
        self.assertEqual(rc, 0)
        batch.assert_not_called()
        legacy.assert_called_once()


class SelectedBatchCoordinatorTests(unittest.TestCase):
    def setUp(self):
        import ida_analyze_bin as analyzer

        self.analyzer = analyzer
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.node = make_node("engine", "windows", "first", 0)
        self.plan = make_plan([self.node])
        self.manifest = self.root / "selection.json"
        self.write_manifest([("tag-1", [self.node.id]), ("tag-2", [self.node.id])])
        self.arguments = [
            "-batch_selection",
            str(self.manifest),
            "-artifactdir",
            str(self.root / "artifacts"),
            "-batch_diagnostics",
            str(self.root / "diagnostics"),
        ]
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(unittest.mock.patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(
            unittest.mock.patch.object(analyzer, "iter_analysis_config_tags", return_value=["tag-1", "tag-2"])
        )
        self.stack.enter_context(
            unittest.mock.patch.object(
                analyzer, "resolve_analysis_config", side_effect=lambda tag, *args: Path(f"configs/{tag}.yaml")
            )
        )
        self.stack.enter_context(
            unittest.mock.patch.object(
                analyzer, "load_config", return_value=({}, [{"name": "engine", "module_windows": "hw.dll"}])
            )
        )
        self.planner = self.stack.enter_context(
            unittest.mock.patch.object(analyzer, "_build_execution_plan", return_value=self.plan)
        )

    def write_manifest(self, entries):
        self.manifest.write_text(
            json.dumps(
                {"schema_version": 1, "selections": [{"tag": tag, "node_ids": node_ids} for tag, node_ids in entries]}
            ),
            encoding="utf-8",
        )

    def test_invalid_late_tag_or_node_never_starts_a_worker(self):
        for entries in [
            [("tag-1", [self.node.id]), ("unknown", [self.node.id])],
            [("tag-1", [self.node.id]), ("tag-2", ["unknown"])],
        ]:
            self.write_manifest(entries)
            with self.subTest(entries=entries), unittest.mock.patch.object(self.analyzer.subprocess, "Popen") as launch:
                self.assertEqual(1, self.analyzer.main(self.arguments))
                launch.assert_not_called()

    def test_duplicate_json_keys_rejected(self):
        self.manifest.write_text('{"schema_version":1,"schema_version":1,"selections":[]}', encoding="utf-8")
        with unittest.mock.patch.object(self.analyzer.subprocess, "Popen") as launch:
            self.assertEqual(1, self.analyzer.main(self.arguments))
            launch.assert_not_called()

    def test_validate_only_defers_materialized_inputs_and_never_launches(self):
        self.planner.return_value = make_plan([replace(self.node, required_inputs=("engine/external.yaml",))])
        with unittest.mock.patch.object(self.analyzer.subprocess, "Popen") as launch:
            self.assertEqual(0, self.analyzer.main([*self.arguments, "-validate_selection_only"]))
            launch.assert_not_called()
        self.assertFalse(self.planner.call_args.kwargs["validate_external_inputs"])

    def test_all_tags_external_inputs_checked_before_first_launch(self):
        consumer = replace(self.node, required_inputs=("engine/external.yaml",))
        self.planner.return_value = make_plan([consumer])
        materialized = self.root / "artifacts/tag-1/engine/external.yaml"
        materialized.parent.mkdir(parents=True)
        materialized.write_text("baseline", encoding="utf-8")
        with unittest.mock.patch.object(self.analyzer.subprocess, "Popen") as launch:
            self.assertEqual(1, self.analyzer.main(self.arguments))
            launch.assert_not_called()

    def test_required_inputs_distinguish_selected_producers_from_external_inputs(self):
        producer = replace(self.node, required_outputs=("engine/input.yaml",))
        consumer = replace(make_node("client", "windows", "last", 1), required_inputs=("engine/input.yaml",))
        plan = make_plan([producer, consumer], [(producer.id, consumer.id, "artifact")])
        self.analyzer._validate_selected_inputs(plan, plan.nodes, self.root)
        with self.assertRaisesRegex(self.analyzer.AnalysisRunError, "client:windows:last: engine/input.yaml"):
            self.analyzer._validate_selected_inputs(plan, (consumer,), self.root)

    def test_effective_multitag_concurrency_requires_shared_memory_budget_before_launch(self):
        with (
            unittest.mock.patch.dict(os.environ, {"GSVIBE_ANALYSIS_MAX_CONCURRENCY": "2"}),
            unittest.mock.patch.object(self.analyzer.subprocess, "Popen") as launch,
        ):
            self.assertEqual(1, self.analyzer.main(self.arguments))
            launch.assert_not_called()

    def test_structural_planning_defers_only_file_checks(self):
        from analysis_planner import AnalysisPlanError, build_execution_plan
        from tests.test_analysis_planner import module, skill

        modules = module(
            [
                skill("first", output=["produced.yaml"], required_input=["external.yaml"]),
                skill("last", required_input=["produced.yaml"]),
            ]
        )
        options = dict(platforms=["windows"], bin_dir=self.root, tag="tag-1")
        with self.assertRaisesRegex(AnalysisPlanError, "external.yaml"):
            build_execution_plan(modules, **options)
        plan = build_execution_plan(modules, **options, validate_external_inputs=False)
        self.assertEqual(2, len(plan.nodes))
        self.assertEqual([(plan.nodes[0].id, plan.nodes[1].id)], [(edge.source, edge.target) for edge in plan.edges])
        cyclic = module([skill("first", prerequisite=["last"]), skill("last", prerequisite=["first"])])
        with self.assertRaises(AnalysisPlanError):
            build_execution_plan(cyclic, **options, validate_external_inputs=False)

    def test_multitag_subprocess_diagnostics_survive_success_and_failure(self):
        original_popen = subprocess.Popen
        original_run = run_batch
        fixture = """
import json, pathlib, sys
request = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
failed = sys.argv[2] == 'failed'
status = 'failed' if failed else 'succeeded'
result = {key: request[key] for key in ('run_id', 'work_item_id', 'phase', 'tag', 'module', 'platform', 'binary_relative_path', 'node_ids')}
result.update(schema_version=1, status=status, exit_code=int(failed), failure_reason='fixture_failure' if failed else None,
              node_results=[{'node_id': node, 'status': status, 'reason': 'fixture_failure' if failed else None} for node in request['node_ids']],
              summary={'successful': 0 if failed else len(request['node_ids']), 'failed': len(request['node_ids']) if failed else 0, 'skipped': 0})
print('fixture log secret-value', flush=True)
pathlib.Path(request['result_path']).write_text(json.dumps(result), encoding='utf-8')
sys.exit(int(failed))
"""
        for status in ("succeeded", "failed"):
            launched = []

            def launch(command, **kwargs):
                launched.append(command[-1])
                return original_popen([sys.executable, "-c", fixture, command[-1], status], **kwargs)

            with (
                unittest.mock.patch.object(self.analyzer.subprocess, "Popen", side_effect=launch),
                unittest.mock.patch.object(
                    self.analyzer,
                    "run_batch",
                    side_effect=lambda *args, **kwargs: original_run(*args, **kwargs, poll_interval_seconds=0.01),
                ),
            ):
                self.assertEqual(
                    0 if status == "succeeded" else 1,
                    self.analyzer.main([*self.arguments, "-llm_apikey", "secret-value"]),
                )
            self.assertEqual(2 if status == "succeeded" else 1, len(launched))
            summaries = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (self.root / "diagnostics").glob("*/summary.json")
            ]
            summary = next(summary for summary in summaries if summary["status"] == status)
            self.assertEqual(["tag-1", "tag-2"], [task["tag"] for task in summary["tasks"]])
            self.assertEqual(
                [status, status if status == "succeeded" else "not_executed"],
                [task["status"] for task in summary["tasks"]],
            )
            for task in summary["tasks"]:
                if task["status"] == "not_executed":
                    continue
                text = Path(task["log_path"]).read_text(encoding="utf-8")
                self.assertIn("fixture log [REDACTED]", text)
                self.assertNotIn("secret-value", text)
                self.assertGreater(task["elapsed_seconds"], 0)
            self.assertFalse(list((self.root / "diagnostics").rglob("*.request.json")))
            self.assertFalse(list((self.root / "diagnostics").rglob("*.result.json")))


class BatchDiagnosticTests(unittest.TestCase):
    def test_json_redaction_preserves_structure_and_escapes(self):
        from analysis_batch import BatchDiagnostics

        with tempfile.TemporaryDirectory() as directory:
            secret = 'credential"with\\escapes'
            diagnostics = BatchDiagnostics(Path(directory), "run-1", BatchSchedule((), ()), sensitive_values=[secret])
            diagnostics.finish("failed", f"failure: {secret}")
            payload = json.loads((diagnostics.root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual("failure: [REDACTED]", payload["failure_reason"])
            self.assertEqual("failed", payload["status"])

    def test_cancelled_and_not_executed_tasks_survive_cleanup(self):
        from analysis_batch import BatchDiagnostics

        items = tuple(replace(make_item(), work_item_id=f"parallel-{index:04d}") for index in range(3))
        schedule = BatchSchedule(items, ())
        processes = [FakeProcess(polls_until_exit=None), FakeProcess(polls_until_exit=None)]
        gate = FakeGate()
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            diagnostics = BatchDiagnostics(Path(directory), "run-1", schedule)
            with self.assertRaises(KeyboardInterrupt):
                run_batch(
                    schedule,
                    run_id="run-1",
                    launch_worker=lambda item: (processes[items.index(item)], Path(directory) / "unused.json"),
                    max_concurrency=2,
                    memory_gate=gate,
                    on_event=diagnostics.event,
                    sleep=lambda seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
                    kill_process_tree=lambda process: process.kill(),
                    log=lambda text: None,
                )
            diagnostics.finish("cancelled", "KeyboardInterrupt")
            payload = json.loads((diagnostics.root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(["cancelled", "cancelled", "not_executed"], [task["status"] for task in payload["tasks"]])
            self.assertTrue(all(process.killed for process in processes))
            self.assertEqual(0, gate.active)

    def test_diagnostic_write_failure_does_not_interrupt_cancellation_sweep(self):
        items = tuple(replace(make_item(), work_item_id=f"parallel-{index:04d}") for index in range(2))
        processes = [FakeProcess(polls_until_exit=None), FakeProcess(polls_until_exit=None)]
        with self.assertRaises(KeyboardInterrupt):
            run_batch(
                BatchSchedule(items, ()),
                run_id="run-1",
                launch_worker=lambda item: (processes[items.index(item)], Path("unused.json")),
                max_concurrency=2,
                on_event=lambda *args: (_ for _ in ()).throw(OSError("disk full")),
                sleep=lambda seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
                kill_process_tree=lambda process: process.kill(),
                log=lambda text: None,
            )
        self.assertTrue(all(process.killed for process in processes))


class ProcessTreeKillHelperTests(unittest.TestCase):
    def test_windows_tree_kill_invokes_taskkill_with_tree_flag(self):
        import analysis_batch as ab

        calls = []

        def record_run(*args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0)

        with unittest.mock.patch.object(ab.subprocess, "run", side_effect=record_run):
            ab._kill_windows_process_tree(4242)
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[0], ["taskkill", "/F", "/T", "/PID", "4242"])
        self.assertFalse(kwargs.get("check", True))
        # The tree-kill command itself must be bounded, not just the exit wait.
        self.assertGreater(kwargs.get("timeout", 0), 0)
        self.assertEqual(kwargs["timeout"], ab.TREE_KILL_COMMAND_TIMEOUT_SECONDS)

    def test_windows_tree_kill_raises_on_nonzero_taskkill_exit(self):
        import analysis_batch as ab

        with unittest.mock.patch.object(ab.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(RuntimeError):
                ab._kill_windows_process_tree(4242)

    def test_posix_tree_kill_reports_root_kill_failure(self):
        import analysis_batch as ab

        def fake_kill(pid, _sig):
            if pid == 10:
                raise OSError("no such process")

        with (
            unittest.mock.patch.object(ab, "_posix_descendant_pids", return_value=[11]),
            unittest.mock.patch.object(ab.os, "kill", side_effect=fake_kill),
        ):
            with self.assertRaises(OSError):
                ab._kill_posix_process_tree(10)

    def test_posix_tree_kill_keeps_descendant_signal_failures(self):
        import analysis_batch as ab

        def fake_kill(pid, _sig):
            if pid == 11:
                raise PermissionError(13, "permission denied")

        with (
            unittest.mock.patch.object(ab, "_posix_descendant_pids", return_value=[11]),
            unittest.mock.patch.object(ab.os, "kill", side_effect=fake_kill),
        ):
            # A descendant we cannot signal keeps the tree exit unconfirmed
            # even though the root itself kills and exits cleanly.
            with self.assertRaises(OSError):
                ab._kill_posix_process_tree(10)

    def test_posix_tree_kill_treats_missing_descendant_as_exited(self):
        import analysis_batch as ab

        killed = []

        def fake_kill(pid, _sig):
            killed.append(pid)
            if pid == 11:
                raise ProcessLookupError()

        with (
            unittest.mock.patch.object(ab, "_posix_descendant_pids", return_value=[11]),
            unittest.mock.patch.object(ab.os, "kill", side_effect=fake_kill),
        ):
            ab._kill_posix_process_tree(10)
        self.assertEqual(killed, [11, 10])

    def test_posix_tree_kill_sweeps_descendants_before_root(self):
        import analysis_batch as ab

        killed = []
        with (
            unittest.mock.patch.object(ab, "_posix_descendant_pids", return_value=[11, 12]),
            unittest.mock.patch.object(ab.os, "kill", side_effect=lambda pid, _sig: killed.append(pid)),
        ):
            ab._kill_posix_process_tree(10)
        # Descendants are killed deepest-first and the root last, while the
        # parent chain still attributes them to this worker.
        self.assertEqual(killed, [12, 11, 10])

    def test_posix_descendant_walk_collects_transitive_children_only(self):
        import analysis_batch as ab

        stats = {
            "/proc/10/stat": "python (10) S 1",
            "/proc/11/stat": "ida (11) S 10",
            "/proc/12/stat": "mcp (12) S 11",
            "/proc/13/stat": "other (13) S 1",
        }

        def fake_read_text(self, *args, **kwargs):
            normalized = str(self).replace("\\", "/")
            return stats[normalized]

        with (
            unittest.mock.patch.object(ab.os, "listdir", return_value=["10", "11", "12", "13", "cpuinfo"]),
            unittest.mock.patch.object(ab.Path, "read_text", fake_read_text),
        ):
            descendants = ab._posix_descendant_pids(10)
        self.assertEqual(sorted(descendants), [11, 12])
