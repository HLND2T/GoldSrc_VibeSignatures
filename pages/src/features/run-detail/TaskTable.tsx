import { Button, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import type { TaskView } from '../../api/types'
import { StatusTag } from '../../components/StatusTag'
import { phaseLabel } from '../../components/status'
import type { GraphFilters } from '../../graph/model'

function matches(task: TaskView, filters: GraphFilters): boolean {
  const query = filters.query.trim().toLowerCase()
  if (query && !`${task.name} ${task.task_id} ${task.description || ''}`.toLowerCase().includes(query)) return false
  if (filters.status && task.status !== filters.status) return false
  if (filters.phase && task.phase !== filters.phase) return false
  if (filters.taskType && task.task_type !== filters.taskType) return false
  if (filters.stageId && filters.stageId !== 'all' && task.stage_id !== filters.stageId) return false
  return !filters.jobId || filters.jobId === 'all' || task.job_id === filters.jobId
}

function columns(onSelect: (id: string) => void, t: TFunction): ColumnsType<TaskView> {
  return [
    { title: t('taskTable.task'), dataIndex: 'name', width: 260, render: (name, task) => <Button type="link" onClick={() => onSelect(task.task_id)}>{name}</Button> },
    { title: t('taskTable.description'), dataIndex: 'description', width: 360, ellipsis: true, render: (value) => <Typography.Text title={value || undefined}>{value || t('common.notAvailable')}</Typography.Text> },
    { title: t('runs.status'), dataIndex: 'status', width: 105, render: (status) => <StatusTag status={status} /> },
    { title: t('phase.label'), dataIndex: 'phase', width: 170, render: (phase) => phaseLabel(phase, t) },
    { title: t('taskTable.type'), dataIndex: 'task_type', width: 130 },
    { title: t('taskTable.stage'), dataIndex: 'stage_id', width: 190, ellipsis: true },
    { title: t('taskTable.job'), dataIndex: 'job_id', width: 220, ellipsis: true },
    { title: t('taskTable.updatedAt'), dataIndex: 'updated_at', width: 170, render: (value) => value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : t('common.notAvailable') },
    { title: t('taskTable.reason'), dataIndex: 'reason', ellipsis: true, render: (value) => value || t('common.notAvailable') },
  ]
}

export function TaskTable({ tasks, filters, onSelect }: { tasks: TaskView[]; filters: GraphFilters; onSelect(id: string): void }) {
  const rows = tasks.filter((task) => matches(task, filters))
  const { t } = useTranslation()
  return <Table rowKey="task_id" virtual columns={columns(onSelect, t)} dataSource={rows} pagination={{ pageSize: 100, showSizeChanger: false }} scroll={{ x: 1760, y: 520 }} />
}
