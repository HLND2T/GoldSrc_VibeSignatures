import type {
  EdgeType,
  ExecutionNodeView,
  ExecutionPlanView,
  RunView,
  TaskStatus,
  TaskView,
} from '../api/types'

export interface GraphFilters {
  query: string
  status?: TaskStatus
  phase?: string
  taskType?: string
  stageId?: string
  jobId?: string
}

export interface VisualNode {
  id: string
  label: string
  subtitle: string
  description?: string | null
  layoutOrder?: number
  kind: string
  status: string
  descendantCount: number
}

export interface VisualEdge {
  id: string
  source: string
  target: string
  edgeType: EdgeType | 'hierarchy'
  secondary: boolean
  layout: boolean
}

export interface VisualGraph {
  nodes: VisualNode[]
  edges: VisualEdge[]
  parentById: Record<string, string>
  expandable: Set<string>
}

function byTaskId(tasks: TaskView[]): Record<string, TaskView> {
  return Object.fromEntries(tasks.map((task) => [task.task_id, task]))
}

function displayParents(graph: ExecutionPlanView): Record<string, string> {
  const nodes = Object.fromEntries(graph.nodes.map((node) => [node.id, node]))
  const candidates: Record<string, ExecutionNodeView[]> = {}
  graph.edges.forEach((edge) => {
    if (!['artifact', 'prerequisite'].includes(edge.edge_type)) return
    const source = nodes[edge.source]
    const target = nodes[edge.target]
    if (!source || !target || source.job_id !== target.job_id) return
    ;(candidates[target.id] ||= []).push(source)
  })
  return Object.fromEntries(
    graph.nodes.map((node) => {
      const parents = candidates[node.id] || []
      parents.sort((left, right) => right.layer - left.layer || left.order - right.order || left.id.localeCompare(right.id))
      return [node.id, parents[0]?.id || node.job_id]
    }),
  )
}

export function defaultMindMapExpansion(graph: ExecutionPlanView): Set<string> {
  const parents = displayParents(graph)
  const nodesWithChildren = new Set(Object.values(parents))
  return new Set(
    graph.nodes
      .filter((node) => nodesWithChildren.has(node.id))
      .map((node) => node.id),
  )
}

function hierarchyParents(run: RunView, graph: ExecutionPlanView): Record<string, string> {
  const runNodeId = `run:${run.run_id}`
  const parents: Record<string, string> = {}
  graph.stages.forEach((stage) => (parents[stage.id] = runNodeId))
  graph.jobs.forEach((job) => (parents[job.id] = job.stage_id))
  return { ...parents, ...displayParents(graph) }
}

function childrenByParent(parents: Record<string, string>): Record<string, string[]> {
  const children: Record<string, string[]> = {}
  Object.entries(parents).forEach(([child, parent]) => (children[parent] ||= []).push(child))
  return children
}

function descendantCount(id: string, children: Record<string, string[]>): number {
  return (children[id] || []).reduce((total, child) => total + 1 + descendantCount(child, children), 0)
}

function pathToRoot(id: string, parents: Record<string, string>): string[] {
  const path = [id]
  let current = id
  while (parents[current]) {
    current = parents[current]
    path.push(current)
  }
  return path
}

function includesQuery(query: string, ...values: Array<string | null | undefined>): boolean {
  return values.some((value) => value?.toLowerCase().includes(query))
}

function taskMatches(node: ExecutionNodeView, task: TaskView | undefined, filters: GraphFilters): boolean {
  const query = filters.query.trim().toLowerCase()
  if (query && !includesQuery(query, node.name, node.id, node.description, task?.description)) return false
  if (filters.status && task?.status !== filters.status) return false
  if (filters.phase && filters.phase !== 'all' && task?.phase !== filters.phase) return false
  if (filters.taskType && filters.taskType !== 'all' && node.node_type !== filters.taskType) return false
  if (filters.stageId && filters.stageId !== 'all' && node.stage_id !== filters.stageId) return false
  return !filters.jobId || filters.jobId === 'all' || node.job_id === filters.jobId
}

function hasTaskFilters(filters: GraphFilters): boolean {
  return Boolean(filters.query || filters.status || (filters.phase && filters.phase !== 'all') || (filters.taskType && filters.taskType !== 'all'))
}

function baseVisibleNodes(
  graph: ExecutionPlanView,
  parents: Record<string, string>,
  expanded: Set<string>,
): Set<string> {
  const visible = new Set<string>([...graph.stages.map((item) => item.id), ...graph.jobs.map((item) => item.id)])
  graph.nodes.forEach((node) => {
    const parent = parents[node.id]
    if (graph.jobs.some((job) => job.id === parent) || expanded.has(parent)) visible.add(node.id)
  })
  return visible
}

function matchingPaths(
  graph: ExecutionPlanView,
  tasks: Record<string, TaskView>,
  filters: GraphFilters,
  parents: Record<string, string>,
): Set<string> {
  const visible = new Set<string>()
  graph.nodes.forEach((node) => {
    if (taskMatches(node, tasks[node.id], filters)) pathToRoot(node.id, parents).forEach((id) => visible.add(id))
  })
  const query = filters.query.trim().toLowerCase()
  const hierarchyOnlyQuery = query && !filters.status && !filters.phase && !filters.taskType
  if (!hierarchyOnlyQuery) return visible
  graph.stages.forEach((stage) => {
    if (filters.stageId && filters.stageId !== 'all' && filters.stageId !== stage.id) return
    if (includesQuery(query, stage.id, stage.module_name, stage.description)) {
      pathToRoot(stage.id, parents).forEach((id) => visible.add(id))
    }
  })
  graph.jobs.forEach((job) => {
    if (filters.stageId && filters.stageId !== 'all' && filters.stageId !== job.stage_id) return
    if (filters.jobId && filters.jobId !== 'all' && filters.jobId !== job.id) return
    if (includesQuery(query, job.id, job.module_name, job.platform, tasks[job.id]?.description)) {
      pathToRoot(job.id, parents).forEach((id) => visible.add(id))
    }
  })
  return visible
}

function aggregateStatus(statuses: string[]): string {
  for (const status of ['running', 'failed', 'aborted', 'pending', 'skipped', 'succeeded']) {
    if (statuses.includes(status)) return status
  }
  return 'pending'
}

function visualNodes(
  run: RunView,
  graph: ExecutionPlanView,
  tasks: Record<string, TaskView>,
  visible: Set<string>,
  children: Record<string, string[]>,
): VisualNode[] {
  const runId = `run:${run.run_id}`
  const result: VisualNode[] = [{ id: runId, label: run.run_id, subtitle: 'Run', kind: 'run', status: run.effective_status, descendantCount: descendantCount(runId, children) }]
  graph.stages.filter((item) => visible.has(item.id)).forEach((stage) => {
    const jobStatuses = graph.jobs.filter((job) => job.stage_id === stage.id).map((job) => tasks[job.id]?.status || 'pending')
    result.push({ id: stage.id, label: stage.module_name, subtitle: `Stage ${stage.stage_index}`, description: stage.description, layoutOrder: stage.stage_index, kind: 'stage', status: aggregateStatus(jobStatuses), descendantCount: descendantCount(stage.id, children) })
  })
  graph.jobs.filter((item) => visible.has(item.id)).forEach((job) => {
    result.push({ id: job.id, label: `${job.module_name} · ${job.platform}`, subtitle: 'Binary Job', kind: 'job', status: tasks[job.id]?.status || 'pending', descendantCount: descendantCount(job.id, children) })
  })
  graph.nodes.filter((item) => visible.has(item.id)).forEach((node) => {
    result.push({ id: node.id, label: node.name, subtitle: node.node_type, description: node.description, kind: node.node_type, status: tasks[node.id]?.status || 'pending', descendantCount: descendantCount(node.id, children) })
  })
  return result
}

function mindMapEdges(graph: ExecutionPlanView, parents: Record<string, string>, visible: Set<string>): VisualEdge[] {
  const primary = Object.entries(parents).filter(([child, parent]) => visible.has(child) && visible.has(parent)).map(([child, parent]) => ({ id: `tree:${parent}:${child}`, source: parent, target: child, edgeType: 'hierarchy' as const, secondary: false, layout: true }))
  const primaryPairs = new Set(primary.map((edge) => `${edge.source}>${edge.target}`))
  const secondary = graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target) && !primaryPairs.has(`${edge.source}>${edge.target}`)).map((edge, index) => ({ id: `secondary:${index}:${edge.source}:${edge.target}`, source: edge.source, target: edge.target, edgeType: edge.edge_type, secondary: true, layout: false }))
  return [...primary, ...secondary]
}

export function buildMindMap(
  run: RunView,
  graph: ExecutionPlanView,
  taskList: TaskView[],
  filters: GraphFilters,
  expanded: Set<string>,
): VisualGraph {
  const tasks = byTaskId(taskList)
  const parents = hierarchyParents(run, graph)
  const children = childrenByParent(parents)
  const runId = `run:${run.run_id}`
  let visible = baseVisibleNodes(graph, parents, expanded)
  visible.add(runId)
  if (hasTaskFilters(filters)) visible = new Set([runId, ...matchingPaths(graph, tasks, filters, parents)])
  if (run.current_skill_id) pathToRoot(run.current_skill_id, parents).forEach((id) => visible.add(id))
  return {
    nodes: visualNodes(run, graph, tasks, visible, children),
    edges: mindMapEdges(graph, parents, visible),
    parentById: parents,
    expandable: new Set(Object.keys(children).filter((id) => children[id].length > 0)),
  }
}

export function buildDag(
  graph: ExecutionPlanView,
  taskList: TaskView[],
  filters: GraphFilters,
  showStageOrder: boolean,
): VisualGraph {
  const tasks = byTaskId(taskList)
  const included = new Set(graph.nodes.filter((node) => taskMatches(node, tasks[node.id], filters)).map((node) => node.id))
  const nodes = graph.nodes.filter((node) => included.has(node.id)).map((node) => ({ id: node.id, label: node.name, subtitle: node.node_type, description: node.description, kind: node.node_type, status: tasks[node.id]?.status || 'pending', descendantCount: 0 }))
  const edges = graph.edges.filter((edge) => included.has(edge.source) && included.has(edge.target) && (showStageOrder || edge.edge_type !== 'stage_order')).map((edge, index) => ({ id: `dag:${index}:${edge.source}:${edge.target}`, source: edge.source, target: edge.target, edgeType: edge.edge_type, secondary: false, layout: true }))
  return { nodes, edges, parentById: {}, expandable: new Set() }
}
