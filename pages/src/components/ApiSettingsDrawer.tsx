import { Alert, Button, Drawer, Form, Input, Space, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useApiConfig } from '../app/apiContext'

interface Props {
  open: boolean
  onClose(): void
}

export function ApiSettingsDrawer({ open, onClose }: Props) {
  const { baseUrl, changeBaseUrl, disconnect } = useApiConfig()
  const { t } = useTranslation()
  const [value, setValue] = useState(baseUrl)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => setValue(baseUrl), [baseUrl, open])

  function save() {
    try {
      changeBaseUrl(value)
      setError(null)
      onClose()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : t('errors.invalidApiAddress'))
    }
  }

  return (
    <Drawer title={t('settings.title')} open={open} onClose={onClose} width={440}>
      <Form layout="vertical">
        <Form.Item label={t('settings.baseUrl')}>
          <Input value={value} onChange={(event) => setValue(event.target.value)} />
        </Form.Item>
        {error && <Alert type="error" message={error} showIcon />}
        <Typography.Paragraph type="secondary" className="settings-help">
          {t('settings.help')}
        </Typography.Paragraph>
        <Space>
          <Button type="primary" onClick={save}>
            {t('settings.saveAndReconnect')}
          </Button>
          <Button onClick={disconnect}>{t('settings.disconnect')}</Button>
        </Space>
      </Form>
    </Drawer>
  )
}
