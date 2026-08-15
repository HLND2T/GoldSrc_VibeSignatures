"""Public FastAPI response models for process status queries."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from process_reporter import ProcessPhase, RunStatus, TaskStatus


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProgressSummary(ApiModel):
    total: int
    pending: int
    running: int
    succeeded: int
    failed: int
    skipped: int
    aborted: int
    completed: int
    percent: float


class RunView(ApiModel):
    run_id: str
    status: RunStatus
    effective_status: RunStatus
    is_stale: bool
    heartbeat_alive: bool
    gamever: str | None = None
    agent: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None
    finished_at: datetime | None = None
    current_stage_id: str | None = None
    current_job_id: str | None = None
    current_skill_id: str | None = None
    last_event_id: str = "0-0"
    error_summary: str | None = None
    progress: ProgressSummary


class ExecutionStageView(ApiModel):
    id: str
    stage_index: int
    module_name: str
    description: str | None = None


class ExecutionJobView(ApiModel):
    id: str
    stage_id: str
    stage_index: int
    module_name: str
    platform: str
    binary_path: str | None = None


class ExecutionNodeView(ApiModel):
    id: str
    job_id: str
    stage_id: str
    name: str
    node_type: str
    order: int
    layer: int
    description: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class ExecutionEdgeView(ApiModel):
    source: str
    target: str
    edge_type: str
    artifact: str | None = None


class ExecutionPlanView(ApiModel):
    schema_version: int
    stages: list[ExecutionStageView]
    jobs: list[ExecutionJobView]
    nodes: list[ExecutionNodeView]
    edges: list[ExecutionEdgeView]
    warnings: list[Any]


class TaskView(ApiModel):
    task_id: str
    task_type: str
    name: str
    description: str | None = None
    stage_id: str | None = None
    job_id: str | None = None
    status: TaskStatus
    phase: ProcessPhase
    reason: str | None = None
    attempt: int | None = None
    max_attempts: int | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None
    finished_at: datetime | None = None
    message: str | None = None
    error: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    event_type: str
    revision: int


class TaskDetail(TaskView):
    dependencies: list[str]
    dependents: list[str]


class EventView(ApiModel):
    id: str
    type: str
    run_id: str
    task_id: str | None = None
    status: str | None = None
    phase: str | None = None
    reason: str | None = None
    occurred_at: datetime | None = None
    revision: int
    data: dict[str, Any] = Field(default_factory=dict)


class RunPageResponse(ApiModel):
    items: list[RunView]
    offset: int
    next_offset: int | None = None
    has_more: bool


class TaskPageResponse(ApiModel):
    items: list[TaskView]
    offset: int
    next_offset: int | None = None
    has_more: bool


class EventPageResponse(ApiModel):
    items: list[EventView]
    next_after: str
    has_more: bool


class SnapshotResponse(ApiModel):
    run: RunView
    graph: ExecutionPlanView | None
    tasks: list[TaskView]
    snapshot_event_id: str


class HealthResponse(ApiModel):
    status: str
