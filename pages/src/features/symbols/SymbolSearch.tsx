import { Button, Empty, Input, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { symbolKindLabel } from './model'
import type { GameSymbolPlatform, GameSymbolRecord, SymbolFilters } from './types'

interface Props {
  records: GameSymbolRecord[]
  modules: string[]
  filters: SymbolFilters
  onChange(filters: SymbolFilters): void
  onSelect(record: GameSymbolRecord): void
}

function columns(onSelect: (record: GameSymbolRecord) => void, t: TFunction): ColumnsType<GameSymbolRecord> {
  return [
    {
      title: t('symbols.symbolName'),
      dataIndex: 'symbolName',
      width: 280,
      render: (name: string, record) => <Button type="link" onClick={() => onSelect(record)}>{name}</Button>,
    },
    { title: t('symbols.kind'), dataIndex: 'kind', width: 150, render: (kind: string) => symbolKindLabel(kind, t) },
    { title: t('symbols.module'), dataIndex: 'module', width: 150 },
    {
      title: t('symbols.platform'),
      dataIndex: 'platform',
      width: 120,
      render: (platform: GameSymbolPlatform) => <Tag color={platform === 'windows' ? 'blue' : 'gold'}>{platform}</Tag>,
    },
  ]
}

export function SymbolSearch({ records, modules, filters, onChange, onSelect }: Props) {
  const { t } = useTranslation()
  const patch = (next: Partial<SymbolFilters>) => onChange({ ...filters, ...next })
  return (
    <>
      <Space wrap className="filter-row symbol-filter-row">
        <Select
          allowClear
          showSearch
          optionFilterProp="label"
          aria-label={t('symbols.allModules')}
          placeholder={t('symbols.allModules')}
          value={filters.module}
          onChange={(module) => patch({ module })}
          options={modules.map((module) => ({ value: module, label: module }))}
          style={{ width: 180 }}
        />
        <Input.Search
          allowClear
          placeholder={t('symbols.searchPlaceholder')}
          value={filters.query}
          onChange={(event) => patch({ query: event.target.value })}
          style={{ width: 320 }}
        />
        <Select
          allowClear
          aria-label={t('symbols.allPlatforms')}
          placeholder={t('symbols.allPlatforms')}
          value={filters.platform}
          onChange={(platform) => patch({ platform })}
          options={[
            { value: 'windows', label: t('symbols.windows') },
            { value: 'linux', label: t('symbols.linux') },
          ]}
          style={{ width: 160 }}
        />
      </Space>
      <Typography.Text type="secondary" className="symbol-result-count">{t('symbols.resultCount', { count: records.length })}</Typography.Text>
      <Table
        rowKey="id"
        columns={columns(onSelect, t)}
        dataSource={records}
        locale={{ emptyText: <Empty description={t('symbols.noMatches')} /> }}
        pagination={{ pageSize: 100, showSizeChanger: false }}
        scroll={{ x: 1000, y: 520 }}
      />
    </>
  )
}
