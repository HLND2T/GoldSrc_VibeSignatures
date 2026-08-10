import { useQuery } from '@tanstack/react-query'
import { Button, Descriptions, Drawer, Empty, List, Space, Spin, Typography } from 'antd'
import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { getTaskDetail } from '../../api/client'
import type { ExecutionPlanView, TaskView } from '../../api/types'
import { useApiConfig } from '../../app/apiContext'
import { StatusTag } from '../../components/StatusTag'
import { phaseLabel } from '../../components/status'

function duration(task: TaskView, t: TFunction): string {
  if (!task.started_at) return t('common.notAvailable')
  const end = task.finished_at ? dayjs(task.finished_at) : dayjs()
  return t('taskDetail.seconds', { count: Math.max(0, end.diff(dayjs(task.started_at), 'second')) })
}

function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>
}

function planValue(value: unknown, t: TFunction): string {
  if (Array.isArray(value)) return value.join('\n') || t('common.notAvailable')
  return value == null || value === '' ? t('common.notAvailable') : String(value)
}

interface Props {
  runId: string
  taskId?: string
  graph: ExecutionPlanView
  onClose(): void
  onNavigate(id: string): void
}

export function TaskDrawer({ runId, taskId, graph, onClose, onNavigate }: Props) {
  const { baseUrl } = useApiConfig()
  const { t } = useTranslation()
  const query = useQuery({
    queryKey: ['task', baseUrl, runId, taskId],
    queryFn: ({ signal }) => getTaskDetail(baseUrl, runId, taskId!, signal),
    enabled: Boolean(taskId),
  })
  const node = graph.nodes.find((item) => item.id === taskId)
  const job = graph.jobs.find((item) => item.id === (query.data?.job_id || taskId))
  return (
    <Drawer title={t('taskDetail.title')} open={Boolean(taskId)} onClose={onClose} width={620}>
      {query.isLoading && <Spin />}
      {query.error && <Empty description={query.error.message} />}
      {query.data && (
        <Space orientation="vertical" size="large" className="full-width">
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label={t('taskDetail.name')}>{query.data.name}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.description')}><Typography.Paragraph className="task-description">{query.data.description || t('common.notAvailable')}</Typography.Paragraph></Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.taskId')}><Typography.Text copyable>{query.data.task_id}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.type')}>{query.data.task_type}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.status')}><StatusTag status={query.data.status} /></Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.phase')}>{phaseLabel(query.data.phase, t)}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.stageJob')}>{query.data.stage_id || t('common.notAvailable')} / {query.data.job_id || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.attempt')}>{query.data.attempt ?? t('common.notAvailable')} / {query.data.max_attempts ?? t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.startedAt')}>{query.data.started_at || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.updatedAt')}>{query.data.updated_at || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.finishedAt')}>{query.data.finished_at || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.duration')}>{duration(query.data, t)}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.reason')}>{query.data.reason || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.message')}>{query.data.message || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.error')}>{query.data.error || t('common.notAvailable')}</Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.binaryPath')}><Typography.Text copyable>{job?.binary_path || t('common.notAvailable')}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.expectedInputs')}><Typography.Text code>{planValue(node?.data.expected_input, t)}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('taskDetail.expectedOutputs')}><Typography.Text code>{planValue(node?.data.expected_output, t)}</Typography.Text></Descriptions.Item>
          </Descriptions>
          <div><Typography.Title level={5}>{t('taskDetail.executionPlanData')}</Typography.Title><JsonBlock value={node?.data || {}} /></div>
          <div><Typography.Title level={5}>{t('taskDetail.eventPayload')}</Typography.Title><JsonBlock value={query.data.payload} /></div>
          <List header={t('taskDetail.dependencies')} dataSource={query.data.dependencies} locale={{ emptyText: t('common.notAvailable') }} renderItem={(id) => <List.Item><Button type="link" onClick={() => onNavigate(id)}>{id}</Button></List.Item>} />
          <List header={t('taskDetail.dependents')} dataSource={query.data.dependents} locale={{ emptyText: t('common.notAvailable') }} renderItem={(id) => <List.Item><Button type="link" onClick={() => onNavigate(id)}>{id}</Button></List.Item>} />
        </Space>
      )}
    </Drawer>
  )
}
