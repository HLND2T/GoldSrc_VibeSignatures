import { Input, Select, Space } from 'antd'
import { useTranslation } from 'react-i18next'
import type { ExecutionPlanView, ProcessPhase, TaskStatus } from '../../api/types'
import { phaseLabel, statusLabel } from '../../components/status'
import type { GraphFilters } from '../../graph/model'

const STATUSES: TaskStatus[] = ['pending', 'running', 'succeeded', 'failed', 'skipped', 'aborted']
const PHASES: ProcessPhase[] = ['preflight', 'waiting_for_mcp', 'validating_binary', 'validating_inputs', 'preprocessing', 'validating_outputs', 'agent_fallback', 'vcall_export', 'postprocessing', 'finished']

interface Props {
  graph: ExecutionPlanView
  filters: GraphFilters
  onChange(filters: GraphFilters): void
}

export function RunFilterBar({ graph, filters, onChange }: Props) {
  const { t } = useTranslation()
  const patch = (next: Partial<GraphFilters>) => onChange({ ...filters, ...next })
  const jobs = filters.stageId && filters.stageId !== 'all'
    ? graph.jobs.filter((job) => job.stage_id === filters.stageId)
    : graph.jobs
  return (
    <Space wrap className="filter-row">
      <Input.Search
        allowClear
        placeholder={t('filters.search')}
        value={filters.query}
        onChange={(event) => patch({ query: event.target.value })}
        style={{ width: 260 }}
      />
      <Select allowClear placeholder={t('filters.status')} value={filters.status} onChange={(status) => patch({ status })} options={STATUSES.map((value) => ({ value, label: statusLabel(value, t) }))} style={{ width: 130 }} />
      <Select allowClear placeholder={t('phase.label')} value={filters.phase} onChange={(phase) => patch({ phase })} options={PHASES.map((value) => ({ value, label: phaseLabel(value, t) }))} style={{ width: 170 }} />
      <Select allowClear placeholder={t('filters.taskType')} value={filters.taskType} onChange={(taskType) => patch({ taskType })} options={[...new Set(graph.nodes.map((node) => node.node_type))].map((value) => ({ value, label: value }))} style={{ width: 150 }} />
      <Select
        allowClear
        placeholder={t('filters.allStages')}
        value={filters.stageId}
        onChange={(stageId) => patch({ stageId, jobId: undefined })}
        options={[{ value: 'all', label: t('filters.allStages') }, ...graph.stages.map((stage) => ({ value: stage.id, label: `${stage.stage_index} · ${stage.module_name}` }))]}
        style={{ width: 190 }}
      />
      <Select
        allowClear
        placeholder={t('filters.allJobs')}
        value={filters.jobId}
        onChange={(jobId) => patch({ jobId })}
        options={[{ value: 'all', label: t('filters.allJobs') }, ...jobs.map((job) => ({ value: job.id, label: `${job.module_name} · ${job.platform}` }))]}
        style={{ width: 220 }}
      />
    </Space>
  )
}
