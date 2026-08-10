import { create } from 'zustand'
import type {
  EventView,
  ExecutionPlanView,
  RunView,
  SnapshotResponse,
  TaskView,
} from '../../api/types'
import type { StreamStatus } from '../../api/sse'

export type ApplyEventResult = 'accepted' | 'ignored' | 'unknown'

interface LiveRunState {
  runId: string | null
  run: RunView | null
  graph: ExecutionPlanView | null
  tasksById: Record<string, TaskView>
  snapshotCursor: string
  snapshotVersion: number
  streamStatus: StreamStatus
  replaceSnapshot(snapshot: SnapshotResponse): void
  applyEvent(event: EventView): ApplyEventResult
  updateRun(run: RunView): void
  setStreamStatus(status: StreamStatus): void
  clear(): void
}

function taskMap(tasks: TaskView[]): Record<string, TaskView> {
  return Object.fromEntries(tasks.map((task) => [task.task_id, task]))
}

function mergedTask(current: TaskView, event: EventView): TaskView {
  const patch = event.data as Partial<TaskView>
  return {
    ...current,
    ...patch,
    task_id: current.task_id,
    name: current.name,
    description: current.description,
    stage_id: current.stage_id,
    job_id: current.job_id,
    revision: event.revision,
  }
}

const initialState = {
  runId: null,
  run: null,
  graph: null,
  tasksById: {},
  snapshotCursor: '0-0',
  snapshotVersion: 0,
  streamStatus: 'closed' as StreamStatus,
}

export const useRunLiveStore = create<LiveRunState>((set, get) => ({
  ...initialState,
  replaceSnapshot: (snapshot) =>
    set({
      runId: snapshot.run.run_id,
      run: snapshot.run,
      graph: snapshot.graph,
      tasksById: taskMap(snapshot.tasks),
      snapshotCursor: snapshot.snapshot_event_id,
      snapshotVersion: get().snapshotVersion + 1,
    }),
  applyEvent: (event) => {
    const current = event.task_id ? get().tasksById[event.task_id] : undefined
    if (!event.task_id) {
      set({ snapshotCursor: event.id })
      return 'ignored'
    }
    if (!current) return 'unknown'
    if (event.revision <= current.revision) {
      set({ snapshotCursor: event.id })
      return 'ignored'
    }
    set({
      snapshotCursor: event.id,
      tasksById: { ...get().tasksById, [event.task_id]: mergedTask(current, event) },
    })
    return 'accepted'
  },
  updateRun: (run) => set({ run, runId: run.run_id }),
  setStreamStatus: (streamStatus) => set({ streamStatus }),
  clear: () => set(initialState),
}))
