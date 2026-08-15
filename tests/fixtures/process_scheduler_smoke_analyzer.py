"""Minimal Analyzer stand-in used by the Scheduler process-boundary smoke test."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from process_reporter import ProcessEvent, ProcessEventType, RunStatus  # noqa: E402
from process_reporter_redis import RedisProcessReporter  # noqa: E402

PLAN = {"schema_version": 1, "stages": [], "jobs": [], "nodes": [], "edges": [], "warnings": []}
SUMMARY = {"total": 0, "pending": 0, "running": 0, "succeeded": 0, "failed": 0, "skipped": 0, "aborted": 0}


def main() -> None:
    run_id = os.environ["GSVIBE_RUN_ID"]
    reporter = RedisProcessReporter(
        os.environ["GSVIBE_REDIS_URL"],
        os.environ["GSVIBE_REDIS_PREFIX"],
        heartbeat_interval=60,
    )
    try:
        reporter.initialize_run(PLAN, run_id=run_id)
        reporter.emit(ProcessEvent(run_id, ProcessEventType.RUN_STATUS_CHANGED, status=RunStatus.RUNNING))
        reporter.emit(ProcessEvent(run_id, ProcessEventType.RUN_STATUS_CHANGED, status=RunStatus.SUCCEEDED))
        reporter.finalize_run(run_id, RunStatus.SUCCEEDED, SUMMARY)
    finally:
        reporter.flush()
        reporter.close()


if __name__ == "__main__":
    main()
