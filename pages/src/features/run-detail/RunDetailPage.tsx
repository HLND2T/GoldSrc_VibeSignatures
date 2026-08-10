import { ArrowLeftOutlined, ReloadOutlined, WarningOutlined } from '@ant-design/icons'
import { Alert, Button, Card, Empty, Progress, Space, Spin, Tag, Typography } from 'antd'
import type { TFunction } from 'i18next'
import { useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { ProcessPhase, TaskStatus } from '../../api/types'
import { StatusTag } from '../../components/StatusTag'
import { buildDag, buildMindMap, defaultMindMapExpansion, type GraphFilters } from '../../graph/model'
import type { ExecutionPlanView, TaskView } from '../../api/types'
import { useRunLiveStore } from './liveStore'
import { RunFilterBar } from './RunFilterBar'
import { TaskDrawer } from './TaskDrawer'
import { RunViewTabs } from './RunViewTabs'
import { useRunLive } from './useRunLive'

type ViewMode = 'mindmap' | 'dag' | 'list'

function filtersFromParams(params: URLSearchParams): GraphFilters {
  return {
    query: params.get('q') || '',
    status: (params.get('status') || undefined) as TaskStatus | undefined,
    phase: (params.get('phase') || undefined) as ProcessPhase | undefined,
    taskType: params.get('type') || undefined,
    stageId: params.get('stage') || undefined,
    jobId: params.get('job') || undefined,
  }
}

function writeFilters(params: URLSearchParams, filters: GraphFilters): URLSearchParams {
  const next = new URLSearchParams(params)
  const values: Record<string, string | undefined> = {
    q: filters.query || undefined,
    status: filters.status,
    phase: filters.phase,
    type: filters.taskType,
    stage: filters.stageId,
    job: filters.jobId,
  }
  Object.entries(values).forEach(([key, value]) => value ? next.set(key, value) : next.delete(key))
  return next
}

function streamLabel(status: string, t: TFunction): string {
  return {
    connecting: t('detail.sseConnecting'),
    connected: t('detail.sseConnected'),
    reconnecting: t('detail.sseReconnecting'),
    closed: t('detail.sseClosed'),
  }[status] || status
}

function RunHeader({ onRefresh }: { onRefresh(): void }) {
  const run = useRunLiveStore((state) => state.run)
  const streamStatus = useRunLiveStore((state) => state.streamStatus)
  const { t } = useTranslation()
  if (!run) return null
  return (
    <Card>
      <div className="run-header-grid">
        <div>
          <Space wrap><StatusTag status={run.effective_status} /><Tag>{streamLabel(streamStatus, t)}</Tag></Space>
          <Typography.Title level={2}>{run.run_id}</Typography.Title>
          <Typography.Text type="secondary">{run.current_skill_id || t('detail.noCurrentTask')}</Typography.Text>
        </div>
        <div className="run-progress">
          <Progress type="dashboard" percent={run.progress.percent} status={run.progress.failed ? 'exception' : 'normal'} />
          <Typography.Text type="secondary">{t('detail.progressSummary', {
            succeeded: run.progress.succeeded,
            failed: run.progress.failed,
            skipped: run.progress.skipped,
            aborted: run.progress.aborted,
          })}</Typography.Text>
          <Button icon={<ReloadOutlined />} onClick={onRefresh}>{t('detail.refreshSnapshot')}</Button>
        </div>
      </div>
      {run.error_summary && <Alert type="error" showIcon message={run.error_summary} className="run-error" />}
    </Card>
  )
}

interface DetailContentProps {
  runId: string
  graph: ExecutionPlanView | null
  tasks: TaskView[]
  filters: GraphFilters
  view: ViewMode
  selectedTask?: string
  mindMap: ReturnType<typeof buildMindMap> | null
  dag: ReturnType<typeof buildDag> | null
  showStageOrder: boolean
  onRefresh(): void
  onFilters(filters: GraphFilters): void
  onParam(key: string, value?: string): void
  onSelect(id: string): void
  onToggle(id: string): void
  onShowStageOrder(value: boolean): void
}

function RunDetailContent(props: DetailContentProps) {
  const { t } = useTranslation()
  return (
    <Space orientation="vertical" size="large" className="full-width">
      <Link to="/runs"><ArrowLeftOutlined /> {t('detail.backToRuns')}</Link>
      <RunHeader onRefresh={props.onRefresh} />
      {!props.graph ? <Card><Empty description={t('detail.waitingForPlan')} /></Card> : (
        <>
          {props.graph.warnings.length > 0 && <Alert type="warning" showIcon icon={<WarningOutlined />} message={t('detail.executionPlanWarnings')} description={<pre className="warning-block">{JSON.stringify(props.graph.warnings, null, 2)}</pre>} />}
          <Card><RunFilterBar graph={props.graph} filters={props.filters} onChange={props.onFilters} /></Card>
          {props.mindMap && props.dag && <RunViewTabs view={props.view} mindMap={props.mindMap} dag={props.dag} tasks={props.tasks} filters={props.filters} selectedTask={props.selectedTask} showStageOrder={props.showStageOrder} onView={(key) => props.onParam('view', key)} onSelect={props.onSelect} onToggleExpand={props.onToggle} onShowStageOrder={props.onShowStageOrder} />}
          <TaskDrawer runId={props.runId} taskId={props.selectedTask} graph={props.graph} onClose={() => props.onParam('task')} onNavigate={props.onSelect} />
        </>
      )}
    </Space>
  )
}

export function RunDetailPage() {
  const { runId = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const [mindMapExpansion, setMindMapExpansion] = useState<{ runId: string; nodes: Set<string> } | null>(null)
  const [showStageOrder, setShowStageOrder] = useState(false)
  const { snapshotQuery } = useRunLive(runId)
  const { t } = useTranslation()
  const run = useRunLiveStore((state) => state.run)
  const graph = useRunLiveStore((state) => state.graph)
  const tasksById = useRunLiveStore((state) => state.tasksById)
  const filters = filtersFromParams(params)
  const tasks = useMemo(() => Object.values(tasksById), [tasksById])
  const expanded = useMemo(
    () => mindMapExpansion?.runId === runId ? mindMapExpansion.nodes : graph ? defaultMindMapExpansion(graph) : new Set<string>(),
    [graph, mindMapExpansion, runId],
  )
  const defaultView: ViewMode = window.innerWidth < 900 ? 'list' : 'mindmap'
  const view = (params.get('view') || defaultView) as ViewMode
  const selectedTask = params.get('task') || undefined
  const mindMap = useMemo(() => run && graph ? buildMindMap(run, graph, tasks, filters, expanded) : null, [expanded, filters, graph, run, tasks])
  const dag = useMemo(() => graph ? buildDag(graph, tasks, filters, showStageOrder) : null, [filters, graph, showStageOrder, tasks])

  function updateParam(key: string, value?: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  function selectTask(id: string) {
    if (tasksById[id]) updateParam('task', id)
  }

  function toggleExpanded(id: string) {
    setMindMapExpansion((current) => {
      const currentNodes = current?.runId === runId ? current.nodes : expanded
      const next = new Set(currentNodes)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return { runId, nodes: next }
    })
  }

  if (snapshotQuery.isLoading || !run) return <div className="page-spinner"><Spin size="large" /></div>
  if (snapshotQuery.error) return <Alert type="error" showIcon message={snapshotQuery.error.message} description={t('detail.snapshotError')} />

  return <RunDetailContent runId={runId} graph={graph} tasks={tasks} filters={filters} view={view} selectedTask={selectedTask} mindMap={mindMap} dag={dag} showStageOrder={showStageOrder} onRefresh={() => void snapshotQuery.refetch()} onFilters={(next) => setParams(writeFilters(params, next), { replace: true })} onParam={updateParam} onSelect={selectTask} onToggle={toggleExpanded} onShowStageOrder={setShowStageOrder} />
}
