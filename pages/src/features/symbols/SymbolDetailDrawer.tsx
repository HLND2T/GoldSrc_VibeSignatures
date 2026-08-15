import { Descriptions, Drawer, Space, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { symbolKindLabel } from './model'
import type { GameSymbolRecord } from './types'

interface Props {
  record?: GameSymbolRecord
  onClose(): void
}

type SignatureField = { labelKey: string; field: string }

const SIGNATURE_FIELDS: Record<string, SignatureField[]> = {
  function: [{ labelKey: 'symbols.signature.func', field: 'func_sig' }],
  virtualFunction: [
    { labelKey: 'symbols.signature.vfunc', field: 'vfunc_sig' },
    { labelKey: 'symbols.signature.func', field: 'func_sig' },
  ],
  global: [{ labelKey: 'symbols.signature.global', field: 'gv_sig' }],
  structMember: [{ labelKey: 'symbols.signature.structOffset', field: 'offset_sig' }],
}

function signatureValue(record: GameSymbolRecord): { label: string; value: string } | null {
  const specs = SIGNATURE_FIELDS[record.kind]
  if (!specs) return null
  for (const spec of specs) {
    const raw = record.payload[spec.field]
    if (typeof raw === 'string' && raw.length > 0) return { label: spec.labelKey, value: raw }
  }
  return null
}

type ExtraField = { labelKey: string; field: string }

const VFUNC_EXTRA_FIELDS: ExtraField[] = [
  { labelKey: 'symbols.vfuncIndex', field: 'vfunc_index' },
  { labelKey: 'symbols.vfuncOffset', field: 'vfunc_offset' },
]

const STRUCT_MEMBER_EXTRA_FIELDS: ExtraField[] = [
  { labelKey: 'symbols.memberOffset', field: 'offset' },
]

function extraFieldsFor(record: GameSymbolRecord): ExtraField[] {
  const specs = record.kind === 'virtualFunction'
    ? VFUNC_EXTRA_FIELDS
    : record.kind === 'structMember'
      ? STRUCT_MEMBER_EXTRA_FIELDS
      : []
  return specs.filter((spec) => {
    const raw = record.payload[spec.field]
    return typeof raw === 'number' || (typeof raw === 'string' && raw.length > 0)
  })
}

export function SymbolDetailDrawer({ record, onClose }: Props) {
  const { t } = useTranslation()
  const sig = record ? signatureValue(record) : null
  const extras = record ? extraFieldsFor(record) : []
  return (
    <Drawer title={t('symbols.detailTitle')} open={Boolean(record)} onClose={onClose} width={720}>
      {record && (
        <>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t('symbols.symbolName')}>{record.symbolName}</Descriptions.Item>
            <Descriptions.Item label={t('symbols.module')}>{record.module}</Descriptions.Item>
            <Descriptions.Item label={t('symbols.platform')}><Tag color={record.platform === 'windows' ? 'blue' : 'gold'}>{record.platform}</Tag></Descriptions.Item>
            <Descriptions.Item label={t('symbols.kind')}>{symbolKindLabel(record.kind, t)}</Descriptions.Item>
            <Descriptions.Item label={t('symbols.artifact')}>{record.artifact}</Descriptions.Item>
            <Descriptions.Item label={t('symbols.aliases')}>
              {record.aliases && record.aliases.length > 0 ? (
                <Space wrap size={[4, 4]}>
                  {record.aliases.map((alias) => <Tag key={alias} color="geekblue">{alias}</Tag>)}
                </Space>
              ) : <Typography.Text type="secondary">—</Typography.Text>}
            </Descriptions.Item>
            <Descriptions.Item label={t('symbols.sourcePath')}><Typography.Text copyable>{record.id}</Typography.Text></Descriptions.Item>
            {sig && (
              <Descriptions.Item label={t(sig.label)}>
                <Typography.Paragraph copyable style={{ margin: 0 }} className="symbol-signature">{sig.value}</Typography.Paragraph>
              </Descriptions.Item>
            )}
            {extras.map((spec) => (
              <Descriptions.Item key={spec.field} label={t(spec.labelKey)}>
                <Typography.Text copyable>{String(record.payload[spec.field])}</Typography.Text>
              </Descriptions.Item>
            ))}
          </Descriptions>
          <Typography.Title level={4} className="symbol-payload-title">{t('symbols.payload')}</Typography.Title>
          <pre className="json-block symbol-payload">{JSON.stringify(record.payload, null, 2)}</pre>
        </>
      )}
    </Drawer>
  )
}
