import { Badge, Tag } from 'antd'
import { useTranslation } from 'react-i18next'
import type { RunStatus, TaskStatus } from '../api/types'
import { statusLabel } from './status'

const COLORS: Record<string, string> = {
  queued: 'default',
  starting: 'processing',
  pending: 'default',
  running: 'processing',
  succeeded: 'success',
  failed: 'error',
  skipped: 'warning',
  aborted: '#4b5563',
  stale: 'orange',
}

export function StatusTag({ status }: { status: RunStatus | TaskStatus }) {
  const color = COLORS[status]
  const { t } = useTranslation()
  return (
    <Tag color={color} className={status === 'running' ? 'status-running' : undefined}>
      <Badge status={status === 'running' ? 'processing' : 'default'} /> {statusLabel(status, t)}
    </Tag>
  )
}
