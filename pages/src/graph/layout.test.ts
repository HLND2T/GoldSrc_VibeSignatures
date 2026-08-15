import { describe, expect, it } from 'vitest'
import { layoutGraph } from './layout'
import type { VisualGraph } from './model'

function visualNode(id: string, kind: string, layoutOrder?: number) {
  return {
    id,
    label: id,
    subtitle: kind,
    kind,
    status: 'pending',
    descendantCount: 0,
    ...(layoutOrder === undefined ? {} : { layoutOrder }),
  }
}

describe('ELK layout', () => {
  it('lays out a 500-node graph', async () => {
    const graph: VisualGraph = {
      nodes: Array.from({ length: 500 }, (_, index) => ({
        id: `node-${index}`,
        label: `Node ${index}`,
        subtitle: 'skill',
        kind: 'skill',
        status: 'pending',
        descendantCount: 0,
      })),
      edges: Array.from({ length: 499 }, (_, index) => ({
        id: `edge-${index}`,
        source: `node-${index}`,
        target: `node-${index + 1}`,
        edgeType: 'artifact',
        secondary: false,
        layout: true,
      })),
      parentById: {},
      expandable: new Set(),
    }
    const positions = await layoutGraph(graph)
    expect(Object.keys(positions)).toHaveLength(500)
  }, 15_000)

  it('keeps stage subtrees in ascending execution order', async () => {
    const stages = [0, 1, 2].map((index) => visualNode(`stage-${index}`, 'stage', index))
    const jobs = stages.flatMap((stage) => [0, 1].map((index) => visualNode(`${stage.id}-job-${index}`, 'job')))
    const parentById = Object.fromEntries([
      ...stages.map((stage) => [stage.id, 'run']),
      ...jobs.map((job) => [job.id, job.id.replace(/-job-\d+$/, '')]),
    ])
    const graph = {
      nodes: [visualNode('run', 'run'), ...stages, ...jobs],
      edges: Object.entries(parentById).map(([child, parent]) => ({
        id: `${parent}:${child}`,
        source: parent,
        target: child,
        edgeType: 'hierarchy',
        secondary: false,
        layout: true,
      })),
      parentById,
      expandable: new Set(Object.values(parentById)),
    } as VisualGraph

    const positions = await layoutGraph(graph)
    const bounds = stages.map((stage) => {
      const subtree = [stage, ...jobs.filter((job) => parentById[job.id] === stage.id)]
      return {
        minY: Math.min(...subtree.map((node) => positions[node.id].y)),
        maxY: Math.max(...subtree.map((node) => positions[node.id].y + 76)),
      }
    })

    expect(positions['stage-0'].y).toBeLessThan(positions['stage-1'].y)
    expect(positions['stage-1'].y).toBeLessThan(positions['stage-2'].y)
    expect(bounds[0].maxY).toBeLessThan(bounds[1].minY)
    expect(bounds[1].maxY).toBeLessThan(bounds[2].minY)
  })
})
