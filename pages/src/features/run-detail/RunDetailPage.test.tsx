import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { makeSnapshot, makeTask } from '../../test/fixtures'
import { useRunLiveStore } from './liveStore'
import { RunDetailPage } from './RunDetailPage'

vi.mock('./useRunLive', () => ({
  useRunLive: () => ({
    snapshotQuery: { isLoading: false, error: null, refetch: vi.fn() },
    runQuery: {},
  }),
}))

vi.mock('./RunViewTabs', () => ({
  RunViewTabs: ({ dag, mindMap }: { dag: { nodes: unknown[] }; mindMap: { nodes: unknown[] } }) => (
    <>
      <div data-testid="dag-node-count">{dag.nodes.length}</div>
      <div data-testid="mindmap-node-count">{mindMap.nodes.length}</div>
    </>
  ),
}))

vi.mock('./TaskDrawer', () => ({ TaskDrawer: () => null }))

describe('RunDetailPage', () => {
  afterEach(cleanup)

  beforeEach(() => {
    const snapshot = makeSnapshot()
    snapshot.graph = null
    useRunLiveStore.getState().replaceSnapshot(snapshot)
  })

  it('keeps queued runs visible while the graph is not initialized', () => {
    render(
      <MemoryRouter initialEntries={['/runs/run-1']}>
        <Routes><Route path="/runs/:runId" element={<RunDetailPage />} /></Routes>
      </MemoryRouter>,
    )
    expect(screen.getByText(/等待 ExecutionPlan 初始化/)).toBeInTheDocument()
  })

  it('shows nodes from every job in DAG mode when no scope filter is selected', () => {
    const snapshot = makeSnapshot()
    const graph = snapshot.graph!
    const firstJob = graph.jobs[0]
    const firstNode = graph.nodes[0]
    const secondJobId = `${firstJob.stage_id}-linux`
    const secondNodeId = `${secondJobId}/find-other-target`
    graph.jobs.push({ ...firstJob, id: secondJobId, platform: 'linux', binary_path: 'bin/libengine2.so' })
    graph.nodes.push({ ...firstNode, id: secondNodeId, job_id: secondJobId, name: 'find-other-target' })
    snapshot.tasks.push(makeTask({ task_id: secondNodeId, job_id: secondJobId, name: 'find-other-target' }))
    useRunLiveStore.getState().replaceSnapshot(snapshot)

    render(
      <MemoryRouter initialEntries={['/runs/run-1?view=dag']}>
        <Routes><Route path="/runs/:runId" element={<RunDetailPage />} /></Routes>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('dag-node-count')).toHaveTextContent('2')
  })

  it('shows all dependency levels in the mind map by default', () => {
    const snapshot = makeSnapshot()
    const graph = snapshot.graph!
    const root = graph.nodes[0]
    const childId = `${root.job_id}/child`
    const grandchildId = `${root.job_id}/grandchild`
    graph.nodes.push(
      { ...root, id: childId, name: 'child', order: 1, layer: 1 },
      { ...root, id: grandchildId, name: 'grandchild', order: 2, layer: 2 },
    )
    graph.edges.push(
      { source: root.id, target: childId, edge_type: 'artifact', artifact: null },
      { source: childId, target: grandchildId, edge_type: 'artifact', artifact: null },
    )
    snapshot.tasks.push(
      makeTask({ task_id: childId, name: 'child' }),
      makeTask({ task_id: grandchildId, name: 'grandchild' }),
    )
    useRunLiveStore.getState().replaceSnapshot(snapshot)

    render(
      <MemoryRouter initialEntries={['/runs/run-1?view=mindmap']}>
        <Routes><Route path="/runs/:runId" element={<RunDetailPage />} /></Routes>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('mindmap-node-count')).toHaveTextContent('6')
  })
})
