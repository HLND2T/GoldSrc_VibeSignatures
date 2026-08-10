import io
import json
import unittest

from process_reporter import (
    BestEffortProcessReporter,
    ConsoleProcessReporter,
    EdgeType,
    ExecutionEdge,
    ExecutionJob,
    ExecutionNode,
    ExecutionPlan,
    ExecutionStage,
    PlanNodeType,
    ProcessEvent,
    ProcessEventType,
    ProcessPhase,
    ProcessReason,
    RunStatus,
    NullProcessReporter,
    TaskStatus,
    build_job_id,
    build_stage_id,
    build_task_id,
    is_valid_run_transition,
    is_valid_task_transition,
)


class TestProcessReporterDomain(unittest.TestCase):
    def test_null_reporter_preserves_supplied_run_id_and_generates_one(self) -> None:
        reporter = NullProcessReporter()

        self.assertEqual("scheduler-run", reporter.initialize_run({}, run_id="scheduler-run"))
        generated_run_id = reporter.initialize_run({})

        self.assertEqual(26, len(generated_run_id))
        self.assertTrue(generated_run_id.isalnum())

    def test_process_event_serializes_enums_and_payload(self) -> None:
        event = ProcessEvent(
            run_id="run-1",
            event_type=ProcessEventType.TASK_STATUS_CHANGED,
            task_id="stage-0000-engine-windows/find-target",
            status=TaskStatus.FAILED,
            phase=ProcessPhase.FINISHED,
            reason=ProcessReason.MISSING_INPUT,
            payload={"attempt": 2},
        )

        payload = event.to_dict()

        self.assertEqual("task.status_changed", payload["event_type"])
        self.assertEqual("failed", payload["status"])
        self.assertEqual("finished", payload["phase"])
        self.assertEqual("missing_input", payload["reason"])

    def test_best_effort_reporter_swallows_backend_errors(self) -> None:
        class FailingReporter(NullProcessReporter):
            def initialize_run(self, plan, run_id=None):
                raise RuntimeError("offline")

            def emit(self, event):
                raise RuntimeError("offline")

        warnings = []
        reporter = BestEffortProcessReporter(FailingReporter(), warning_callback=warnings.append)

        run_id = reporter.initialize_run({}, run_id="fallback-run")
        reporter.emit(ProcessEvent(run_id=run_id, event_type=ProcessEventType.HEARTBEAT))

        self.assertEqual("fallback-run", run_id)
        self.assertEqual(2, len(warnings))

    def test_best_effort_reporter_also_swallows_warning_callback_errors(self) -> None:
        class FailingReporter(NullProcessReporter):
            def emit(self, event):
                raise RuntimeError("offline")

        def fail_warning(_message):
            raise BrokenPipeError("closed output")

        reporter = BestEffortProcessReporter(FailingReporter(), warning_callback=fail_warning)
        reporter.emit(ProcessEvent(run_id="run-1", event_type=ProcessEventType.HEARTBEAT))

    def test_console_reporter_emits_only_the_current_jsonl_contract(self) -> None:
        stream = io.StringIO()
        reporter = ConsoleProcessReporter(stream)

        run_id = reporter.initialize_run({"schema_version": 1}, run_id="console-run")
        reporter.emit(
            ProcessEvent(
                run_id,
                ProcessEventType.TASK_STATUS_CHANGED,
                task_id="stage-0000-engine-windows/find-target",
                status=TaskStatus.RUNNING,
                phase=ProcessPhase.PREPROCESSING,
            )
        )
        reporter.heartbeat(run_id)
        reporter.flush()

        events = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(
            ["run.initialized", "task.status_changed", "heartbeat"], [item["event_type"] for item in events]
        )
        self.assertEqual("console-run", events[0]["run_id"])
        self.assertEqual(1, events[0]["payload"]["plan"]["schema_version"])

    def test_builds_stable_execution_identifiers(self) -> None:
        stage_id = build_stage_id(8, "engine")
        job_id = build_job_id(stage_id, "windows")

        self.assertEqual("stage-0008-engine", stage_id)
        self.assertEqual("stage-0008-engine-windows", job_id)
        self.assertEqual(
            "stage-0008-engine-windows/find-target",
            build_task_id(job_id, "find-target"),
        )

    def test_rejects_invalid_execution_identifier_parts(self) -> None:
        with self.assertRaises(ValueError):
            build_stage_id(-1, "engine")
        with self.assertRaises(ValueError):
            build_job_id("stage-0001-engine", "")
        with self.assertRaises(ValueError):
            build_task_id("stage-0001-engine-windows", "nested/task")

    def test_status_transitions_are_idempotent_and_terminal(self) -> None:
        self.assertTrue(is_valid_task_transition(TaskStatus.PENDING, TaskStatus.RUNNING))
        self.assertTrue(is_valid_task_transition(TaskStatus.RUNNING, TaskStatus.SUCCEEDED))
        self.assertTrue(is_valid_task_transition(TaskStatus.RUNNING, TaskStatus.SKIPPED))
        self.assertTrue(is_valid_task_transition(TaskStatus.SUCCEEDED, TaskStatus.SUCCEEDED))
        self.assertFalse(is_valid_task_transition(TaskStatus.SUCCEEDED, TaskStatus.RUNNING))
        self.assertTrue(is_valid_run_transition(RunStatus.RUNNING, RunStatus.STALE))
        self.assertTrue(is_valid_run_transition(RunStatus.STALE, RunStatus.RUNNING))
        self.assertFalse(is_valid_run_transition(RunStatus.FAILED, RunStatus.RUNNING))

    def test_execution_plan_serializes_to_api_shape(self) -> None:
        stage = ExecutionStage(
            id="stage-0000-engine",
            stage_index=0,
            module_name="engine",
            description="Engine analysis stage",
        )
        job = ExecutionJob(
            id="stage-0000-engine-windows",
            stage_id=stage.id,
            stage_index=0,
            module_name="engine",
            platform="windows",
            binary_path="bin/svencoop-10257/engine/hw.dll",
        )
        node = ExecutionNode(
            id=f"{job.id}/find-target",
            job_id=job.id,
            stage_id=stage.id,
            name="find-target",
            node_type=PlanNodeType.SKILL,
            order=0,
            layer=0,
            description="Locate the target function",
            data={"status": TaskStatus.PENDING, "phase": ProcessPhase.PREFLIGHT},
        )
        plan = ExecutionPlan(
            stages=[stage],
            jobs=[job],
            nodes=[node],
            edges=[
                ExecutionEdge(
                    source=stage.id,
                    target=job.id,
                    edge_type=EdgeType.STAGE_ORDER,
                )
            ],
            warnings=[ProcessReason.GRAPH_INVALID],
        )

        payload = plan.to_dict()

        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("Engine analysis stage", payload["stages"][0]["description"])
        self.assertEqual("skill", payload["nodes"][0]["node_type"])
        self.assertEqual("Locate the target function", payload["nodes"][0]["description"])
        self.assertEqual("pending", payload["nodes"][0]["data"]["status"])
        self.assertEqual("preflight", payload["nodes"][0]["data"]["phase"])
        self.assertEqual("stage_order", payload["edges"][0]["edge_type"])
        self.assertEqual(["graph_invalid"], payload["warnings"])


if __name__ == "__main__":
    unittest.main()
