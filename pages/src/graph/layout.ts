import ELK from 'elkjs/lib/elk.bundled.js'
import type { VisualGraph, VisualNode } from './model'

export interface NodePosition {
  x: number
  y: number
}

const elk = new ELK()
const NODE_HEIGHT = 76
const DESCRIPTION_NODE_HEIGHT = 112
const NODE_SPACING = 36

interface VerticalBounds {
  minY: number
  maxY: number
}

function nodeHeight(node: VisualNode): number {
  return node.description ? DESCRIPTION_NODE_HEIGHT : NODE_HEIGHT
}

function findStageId(id: string, stageIds: Set<string>, parentById: Record<string, string>): string | undefined {
  const visited = new Set<string>()
  let current: string | undefined = id
  while (current && !visited.has(current)) {
    if (stageIds.has(current)) return current
    visited.add(current)
    current = parentById[current]
  }
  return undefined
}

function stageSubtrees(graph: VisualGraph): Array<{ stage: VisualNode; nodes: VisualNode[] }> {
  const stages = graph.nodes
    .filter((node) => node.kind === 'stage' && Number.isFinite(node.layoutOrder))
    .sort((left, right) => left.layoutOrder! - right.layoutOrder! || left.id.localeCompare(right.id))
  const stageIds = new Set(stages.map((stage) => stage.id))
  const nodesByStage = new Map(stages.map((stage) => [stage.id, [] as VisualNode[]]))
  graph.nodes.forEach((node) => {
    const stageId = findStageId(node.id, stageIds, graph.parentById)
    if (stageId) nodesByStage.get(stageId)?.push(node)
  })
  return stages.map((stage) => ({ stage, nodes: nodesByStage.get(stage.id) || [] }))
}

function verticalBounds(nodes: VisualNode[], positions: Record<string, NodePosition>): VerticalBounds | undefined {
  let minY = Number.POSITIVE_INFINITY
  let maxY = Number.NEGATIVE_INFINITY
  nodes.forEach((node) => {
    const position = positions[node.id]
    if (!position) return
    minY = Math.min(minY, position.y)
    maxY = Math.max(maxY, position.y + nodeHeight(node))
  })
  return Number.isFinite(minY) && Number.isFinite(maxY) ? { minY, maxY } : undefined
}

function orderStageSubtrees(graph: VisualGraph, positions: Record<string, NodePosition>): Record<string, NodePosition> {
  const subtrees = stageSubtrees(graph)
  const bounds = subtrees.map(({ nodes }) => verticalBounds(nodes, positions))
  if (subtrees.length < 2 || bounds.some((item) => !item)) return positions
  const next = Object.fromEntries(Object.entries(positions).map(([id, position]) => [id, { ...position }]))
  const top = Math.min(...bounds.map((item) => item!.minY))
  let cursor = top
  subtrees.forEach(({ nodes }, index) => {
    const bound = bounds[index]!
    const offset = cursor - bound.minY
    nodes.forEach((node) => {
      if (next[node.id]) next[node.id].y += offset
    })
    cursor = bound.maxY + offset + NODE_SPACING
  })
  const run = graph.nodes.find((node) => node.kind === 'run')
  const bottom = cursor - NODE_SPACING
  if (run && next[run.id]) next[run.id].y = top + (bottom - top - nodeHeight(run)) / 2
  return next
}

export async function layoutGraph(graph: VisualGraph): Promise<Record<string, NodePosition>> {
  const result = await elk.layout({
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'RIGHT',
      'elk.spacing.nodeNode': '36',
      'elk.layered.spacing.nodeNodeBetweenLayers': '80',
      'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
    },
    children: graph.nodes.map((node) => ({ id: node.id, width: 220, height: nodeHeight(node) })),
    edges: graph.edges.filter((edge) => edge.layout).map((edge) => ({ id: edge.id, sources: [edge.source], targets: [edge.target] })),
  })
  const positions = Object.fromEntries((result.children || []).map((node) => [node.id, { x: node.x || 0, y: node.y || 0 }]))
  return orderStageSubtrees(graph, positions)
}
