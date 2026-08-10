import { ApiOutlined, SettingOutlined } from '@ant-design/icons'
import { Alert, Button, Card, Space, Typography } from 'antd'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { ApiError } from '../api/client'
import { useApiConfig } from '../app/apiContext'

function connectionHint(error: Error, t: TFunction): string {
  if (error instanceof ApiError && error.detail.code === 'redis_unavailable') {
    return t('connection.redisUnavailable')
  }
  return t('connection.hint')
}

export function ConnectionGate({ onSettings }: { onSettings(): void }) {
  const { baseUrl, connect, connecting, connectionError } = useApiConfig()
  const { t } = useTranslation()
  return (
    <div className="connection-wrap">
      <Card className="connection-card">
        <Space orientation="vertical" size="large" className="full-width">
          <div>
            <Typography.Title level={2}>{t('connection.title')}</Typography.Title>
            <Typography.Paragraph type="secondary">
              {t('connection.descriptionBefore')}<Typography.Text code>{baseUrl}</Typography.Text>{t('connection.descriptionAfter')}
            </Typography.Paragraph>
          </div>
          {connectionError && (
            <Alert
              type="error"
              showIcon
              message={connectionError.message}
              description={connectionHint(connectionError, t)}
            />
          )}
          <Space>
            <Button
              type="primary"
              size="large"
              icon={<ApiOutlined />}
              loading={connecting}
              onClick={() => void connect().catch(() => undefined)}
            >
              {t('connection.connect')}
            </Button>
            <Button size="large" icon={<SettingOutlined />} onClick={onSettings}>
              {t('connection.changeAddress')}
            </Button>
          </Space>
        </Space>
      </Card>
    </div>
  )
}
