import { beforeEach, describe, expect, it } from 'vitest'
import type { EventView } from '../../api/types'
import { makeSnapshot } from '../../test/fixtures'
import { useRunLiveStore } from './liveStore'

function event(revision: number): EventView {
  return {
    id: `${revision + 1}-0`,
    type: 'task.status_changed',
    run_id: 'run-1',
    task_id: 'stage-0000-engine-windows/find-target',
    status: 'succeeded',
    phase: 'finished',
    reason: null,
    occurred_at: '2026-07-13T00:00:03Z',
    revision,
    data: { status: 'succeeded', phase: 'finished', revision },
  }
}

describe('live run store', () => {
  beforeEach(() => useRunLiveStore.getState().clear())

  it('merges newer task events without losing graph descriptors', () => {
    useRunLiveStore.getState().replaceSnapshot(makeSnapshot())
    expect(useRunLiveStore.getState().applyEvent(event(2))).toBe('accepted')
    const task = useRunLiveStore.getState().tasksById['stage-0000-engine-windows/find-target']
    expect(task.name).toBe('find-target')
    expect(task.status).toBe('succeeded')
  })

  it('ignores stale revisions and reports unknown task ids', () => {
    useRunLiveStore.getState().replaceSnapshot(makeSnapshot())
    expect(useRunLiveStore.getState().applyEvent(event(1))).toBe('ignored')
    expect(
      useRunLiveStore.getState().applyEvent({ ...event(2), task_id: 'unknown/task' }),
    ).toBe('unknown')
  })
})
