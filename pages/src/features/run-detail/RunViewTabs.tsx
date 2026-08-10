import { Card, Space, Spin, Switch, Tabs, Typography } from 'antd'
import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import type { TaskView } from '../../api/types'
import type { GraphFilters, VisualGraph } from '../../graph/model'
import { TaskTable } from './TaskTable'

type ViewMode = 'mindmap' | 'dag' | 'list'
const GraphCanvas = lazy(() => import('../../graph/GraphCanvas').then((module) => ({ default: module.GraphCanvas })))

interface Props {
  view: ViewMode
  mindMap: VisualGraph
  dag: VisualGraph
  tasks: TaskView[]
  filters: GraphFilters
  selectedTask?: string
  showStageOrder: boolean
  onView(view: string): void
  onSelect(id: string): void
  onToggleExpand(id: string): void
  onShowStageOrder(value: boolean): void
}

function graphFallback() {
  return <div className="page-spinner"><Spin /></div>
}

function MindMapTab({ props }: { props: Props }) {
  const { t } = useTranslation()
  return (
    <Space orientation="vertical" className="full-width">
      <Typography.Text type="secondary">{t('views.mindMapHint')}</Typography.Text>
      <Suspense fallback={graphFallback()}>
        <GraphCanvas
          graph={props.mindMap}
          selectedId={props.selectedTask}
          onSelect={props.onSelect}
          onToggleExpand={(id) => props.mindMap.expandable.has(id) && props.onToggleExpand(id)}
        />
      </Suspense>
    </Space>
  )
}

function DagTab({ props }: { props: Props }) {
  const { t } = useTranslation()
  return (
    <Space orientation="vertical" className="full-width">
      <Space>
        <Switch checked={props.showStageOrder} onChange={props.onShowStageOrder} />{t('views.showStageOrder')}
      </Space>
      <Suspense fallback={graphFallback()}>
        <GraphCanvas graph={props.dag} selectedId={props.selectedTask} onSelect={props.onSelect} />
      </Suspense>
    </Space>
  )
}

export function RunViewTabs(props: Props) {
  const { t } = useTranslation()
  const items = [
    { key: 'mindmap', label: t('views.mindMap'), children: <MindMapTab props={props} /> },
    { key: 'dag', label: t('views.dag'), children: <DagTab props={props} /> },
    { key: 'list', label: t('views.taskList'), children: <TaskTable tasks={props.tasks} filters={props.filters} onSelect={props.onSelect} /> },
  ]
  return <Card className="view-card"><Tabs activeKey={props.view} onChange={props.onView} items={items} /></Card>
}
