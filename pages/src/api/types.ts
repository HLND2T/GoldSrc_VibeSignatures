export type RunStatus =
  | 'queued'
  | 'starting'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'aborted'
  | 'stale'

export type TaskStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'aborted'

export type ProcessPhase =
  | 'preflight'
  | 'waiting_for_mcp'
  | 'validating_binary'
  | 'validating_inputs'
  | 'preprocessing'
  | 'validating_outputs'
  | 'agent_fallback'
  | 'vcall_export'
  | 'postprocessing'
  | 'finished'

export type EdgeType =
  | 'artifact'
  | 'prerequisite'
  | 'cross_stage_artifact'
  | 'stage_order'

export type TaskType = 'job' | 'skill' | 'vcall_target' | 'post_process' | string

export interface ProgressSummary {
  total: number
  pending: number
  running: number
  succeeded: number
  failed: number
  skipped: number
  aborted: number
  completed: number
  percent: number
}

export interface RunView {
  run_id: string
  status: RunStatus
  effective_status: RunStatus
  is_stale: boolean
  heartbeat_alive: boolean
  gamever: string | null
  agent: string | null
  created_at: string | null
  started_at: string | null
  updated_at: string | null
  finished_at: string | null
  current_stage_id: string | null
  current_job_id: string | null
  current_skill_id: string | null
  last_event_id: string
  error_summary: string | null
  progress: ProgressSummary
}

export interface ExecutionStageView {
  id: string
  stage_index: number
  module_name: string
  description: string | null
}

export interface ExecutionJobView {
  id: string
  stage_id: string
  stage_index: number
  module_name: string
  platform: string
  binary_path: string | null
}

export interface ExecutionNodeView {
  id: string
  job_id: string
  stage_id: string
  name: string
  node_type: string
  order: number
  layer: number
  description: string | null
  data: Record<string, unknown>
}

export interface ExecutionEdgeView {
  source: string
  target: string
  edge_type: EdgeType
  artifact: string | null
}

export interface ExecutionPlanView {
  schema_version: number
  stages: ExecutionStageView[]
  jobs: ExecutionJobView[]
  nodes: ExecutionNodeView[]
  edges: ExecutionEdgeView[]
  warnings: unknown[]
}

export interface TaskView {
  task_id: string
  task_type: TaskType
  name: string
  description: string | null
  stage_id: string | null
  job_id: string | null
  status: TaskStatus
  phase: ProcessPhase
  reason: string | null
  attempt: number | null
  max_attempts: number | null
  started_at: string | null
  updated_at: string | null
  finished_at: string | null
  message: string | null
  error: string | null
  payload: Record<string, unknown>
  event_type: string
  revision: number
}

export interface TaskDetail extends TaskView {
  dependencies: string[]
  dependents: string[]
}

export interface EventView {
  id: string
  type: string
  run_id: string
  task_id: string | null
  status: string | null
  phase: string | null
  reason: string | null
  occurred_at: string | null
  revision: number
  data: Record<string, unknown>
}

export interface RunPageResponse {
  items: RunView[]
  offset: number
  next_offset: number | null
  has_more: boolean
}

export interface SnapshotResponse {
  run: RunView
  graph: ExecutionPlanView | null
  tasks: TaskView[]
  snapshot_event_id: string
}

export interface HealthResponse {
  status: string
}

export interface ApiErrorDetail {
  code: string
  message: string
}

export const TERMINAL_RUN_STATUSES: RunStatus[] = ['succeeded', 'failed', 'aborted']

export function isTerminalRun(status: RunStatus): boolean {
  return TERMINAL_RUN_STATUSES.includes(status)
}
