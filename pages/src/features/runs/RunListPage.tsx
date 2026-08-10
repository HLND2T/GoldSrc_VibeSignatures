import { ReloadOutlined } from '@ant-design/icons'
import { useInfiniteQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Input, Progress, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ApiError, listRuns } from '../../api/client'
import type { RunStatus, RunView } from '../../api/types'
import { useApiConfig } from '../../app/apiContext'
import { StatusTag } from '../../components/StatusTag'
import { statusLabel } from '../../components/status'

const STATUS_OPTIONS: RunStatus[] = [
  'queued',
  'starting',
  'running',
  'succeeded',
  'failed',
  'aborted',
  'stale',
]

function formatTime(value: string | null): string {
  return value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '—'
}

function columns(t: TFunction): ColumnsType<RunView> {
  return [
    {
      title: t('runs.run'),
      dataIndex: 'run_id',
      width: 220,
      render: (value: string) => <Link to={`/runs/${encodeURIComponent(value)}`}>{value}</Link>,
    },
    { title: t('runs.status'), dataIndex: 'effective_status', width: 110, render: (value) => <StatusTag status={value} /> },
    { title: t('runs.version'), dataIndex: 'gamever', width: 100, render: (value) => value || t('common.notAvailable') },
    { title: t('runs.agent'), dataIndex: 'agent', width: 100, render: (value) => value || t('common.notAvailable') },
    {
      title: t('runs.progress'),
      dataIndex: 'progress',
      width: 220,
      render: (progress: RunView['progress']) => (
        <Progress percent={progress.percent} size="small" status={progress.failed ? 'exception' : 'normal'} />
      ),
    },
    { title: t('runs.currentTask'), dataIndex: 'current_skill_id', ellipsis: true, render: (value) => value || t('common.notAvailable') },
    { title: t('runs.createdAt'), dataIndex: 'created_at', width: 170, render: formatTime },
  ]
}

function errorDescription(error: Error, t: TFunction): string {
  if (error instanceof ApiError && error.detail.code === 'redis_unavailable') return t('runs.redisUnavailable')
  return t('runs.error')
}

interface ToolbarProps {
  status?: RunStatus
  gamever: string
  refreshing: boolean
  onStatus(status?: RunStatus): void
  onGamever(value: string): void
  onRefresh(): void
}

function RunListToolbar(props: ToolbarProps) {
  const { t } = useTranslation()
  return (
    <>
      <div className="page-title-row">
        <div><Typography.Title level={2}>{t('runs.title')}</Typography.Title><Typography.Text type="secondary">{t('runs.subtitle')}</Typography.Text></div>
        <Button icon={<ReloadOutlined />} loading={props.refreshing} onClick={props.onRefresh}>{t('runs.refresh')}</Button>
      </div>
      <Card>
        <Space wrap className="filter-row">
          <Select allowClear placeholder={t('runs.allStatuses')} value={props.status} onChange={props.onStatus} options={STATUS_OPTIONS.map((value) => ({ value, label: statusLabel(value, t) }))} style={{ width: 150 }} />
          <Input allowClear placeholder={t('runs.gameVersion')} value={props.gamever} onChange={(event) => props.onGamever(event.target.value)} style={{ width: 180 }} />
        </Space>
      </Card>
    </>
  )
}

interface ResultsProps {
  rows: RunView[]
  loading: boolean
  fetchingNext: boolean
  hasNext: boolean
  onNext(): void
}

function RunResults(props: ResultsProps) {
  const { t } = useTranslation()
  return (
    <Card className="table-card">
      <Table rowKey="run_id" columns={columns(t)} dataSource={props.rows} loading={props.loading} pagination={false} scroll={{ x: 1200 }} />
      {props.hasNext && <div className="load-more"><Button loading={props.fetchingNext} onClick={props.onNext}>{t('runs.loadMore')}</Button></div>}
    </Card>
  )
}

export function RunListPage() {
  const { baseUrl } = useApiConfig()
  const { t } = useTranslation()
  const [status, setStatus] = useState<RunStatus | undefined>()
  const [gamever, setGamever] = useState('')
  const query = useInfiniteQuery({
    queryKey: ['runs', baseUrl, status, gamever],
    queryFn: ({ pageParam, signal }) => listRuns(baseUrl, pageParam, { status, gamever: gamever || undefined }, signal),
    initialPageParam: 0,
    getNextPageParam: (page) => page.next_offset ?? undefined,
    refetchInterval: () => (document.visibilityState === 'visible' ? 10_000 : false),
  })
  const rows = query.data?.pages.flatMap((page) => page.items) || []

  return (
    <Space orientation="vertical" size="large" className="full-width">
      <RunListToolbar status={status} gamever={gamever} refreshing={query.isFetching} onStatus={setStatus} onGamever={setGamever} onRefresh={() => void query.refetch()} />
      {query.error && <Alert type="error" showIcon message={query.error.message} description={errorDescription(query.error, t)} />}
      <RunResults rows={rows} loading={query.isLoading} fetchingNext={query.isFetchingNextPage} hasNext={query.hasNextPage} onNext={() => void query.fetchNextPage()} />
    </Space>
  )
}
