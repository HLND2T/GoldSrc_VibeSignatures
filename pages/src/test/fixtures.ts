import type { RunView, SnapshotResponse, TaskView } from '../api/types'

export function makeRun(overrides: Partial<RunView> = {}): RunView {
  return {
    run_id: 'run-1',
    status: 'running',
    effective_status: 'running',
    is_stale: false,
    heartbeat_alive: true,
    gamever: 'svencoop-10257',
    agent: 'codex',
    created_at: '2026-07-13T00:00:00Z',
    started_at: '2026-07-13T00:00:01Z',
    updated_at: '2026-07-13T00:00:02Z',
    finished_at: null,
    current_stage_id: 'stage-0000-engine',
    current_job_id: 'stage-0000-engine-windows',
    current_skill_id: 'stage-0000-engine-windows/find-target',
    last_event_id: '1-0',
    error_summary: null,
    progress: {
      total: 1,
      pending: 0,
      running: 1,
      succeeded: 0,
      failed: 0,
      skipped: 0,
      aborted: 0,
      completed: 0,
      percent: 0,
    },
    ...overrides,
  }
}

export function makeTask(overrides: Partial<TaskView> = {}): TaskView {
  return {
    task_id: 'stage-0000-engine-windows/find-target',
    task_type: 'skill',
    name: 'find-target',
    description: 'Locate the target function',
    stage_id: 'stage-0000-engine',
    job_id: 'stage-0000-engine-windows',
    status: 'running',
    phase: 'preprocessing',
    reason: null,
    attempt: null,
    max_attempts: null,
    started_at: '2026-07-13T00:00:01Z',
    updated_at: '2026-07-13T00:00:02Z',
    finished_at: null,
    message: null,
    error: null,
    payload: {},
    event_type: 'task.status_changed',
    revision: 1,
    ...overrides,
  }
}

export function makeSnapshot(): SnapshotResponse {
  const task = makeTask()
  return {
    run: makeRun(),
    graph: {
      schema_version: 1,
      stages: [{ id: 'stage-0000-engine', stage_index: 0, module_name: 'engine', description: 'Engine analysis stage' }],
      jobs: [
        {
          id: 'stage-0000-engine-windows',
          stage_id: 'stage-0000-engine',
          stage_index: 0,
          module_name: 'engine',
          platform: 'windows',
          binary_path: 'bin/engine2.dll',
        },
      ],
      nodes: [
        {
          id: task.task_id,
          job_id: task.job_id!,
          stage_id: task.stage_id!,
          name: task.name,
          node_type: 'skill',
          order: 0,
          layer: 0,
          description: task.description,
          data: { expected_output: ['target.yaml'] },
        },
      ],
      edges: [],
      warnings: [],
    },
    tasks: [task],
    snapshot_event_id: '1-0',
  }
}
