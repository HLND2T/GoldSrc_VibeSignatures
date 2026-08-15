import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Select, Space, Spin, Typography } from 'antd'
import dayjs from 'dayjs'
import { useDeferredValue, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getGameSymbolDataset, getGameSymbolIndex } from './data'
import { groupGameVersions } from './gameVersion'
import { filterSymbolRecords } from './model'
import { SymbolDetailDrawer } from './SymbolDetailDrawer'
import { SymbolSearch } from './SymbolSearch'
import { SymbolTree } from './SymbolTree'
import type { GameSymbolRecord, SymbolFilters } from './types'

const EMPTY_FILTERS: SymbolFilters = { query: '' }

export function ExploreSymbolsPage() {
  const { t } = useTranslation()
  const [selectedVersion, setSelectedVersion] = useState<string>()
  const [selectedRecord, setSelectedRecord] = useState<GameSymbolRecord>()
  const [filters, setFilters] = useState<SymbolFilters>(EMPTY_FILTERS)
  const deferredQuery = useDeferredValue(filters.query)
  const indexQuery = useQuery({
    queryKey: ['gamesymbols', 'index'],
    queryFn: ({ signal }) => getGameSymbolIndex(signal),
    staleTime: 5 * 60 * 1000,
  })
  const versionOptions = useMemo(
    () => groupGameVersions(indexQuery.data?.versions.map((version) => version.gameVersion) ?? []).map((group) => ({
      label: group.family,
      options: group.versions.map((version) => ({ value: version, label: version })),
    })),
    [indexQuery.data?.versions],
  )
  const gameVersion = selectedVersion ?? versionOptions[0]?.options[0]?.value
  const versionEntry = indexQuery.data?.versions.find((version) => version.gameVersion === gameVersion)
  const datasetQuery = useQuery({
    queryKey: ['gamesymbols', gameVersion, versionEntry?.url],
    queryFn: ({ signal }) => getGameSymbolDataset(versionEntry!, signal),
    enabled: Boolean(versionEntry),
    staleTime: Infinity,
  })
  const dataset = datasetQuery.data
  const versionMetadata = versionEntry
    ? t('symbols.versionMetadata', {
        time: dayjs(versionEntry.lastPublishTime).format('YYYY-MM-DD HH:mm:ss'),
        count: versionEntry.fileCount,
      })
    : undefined
  const filteredRecords = useMemo(
    () => dataset ? filterSymbolRecords(dataset.records, { ...filters, query: deferredQuery }) : [],
    [dataset, deferredQuery, filters],
  )

  function changeVersion(version: string) {
    setSelectedVersion(version)
    setSelectedRecord(undefined)
    setFilters(EMPTY_FILTERS)
  }

  return (
    <Space orientation="vertical" size="large" className="full-width">
      <div className="page-title-row">
        <div>
          <Typography.Title level={2}>{t('symbols.title')}</Typography.Title>
          <Typography.Text type="secondary">{t('symbols.subtitle')}</Typography.Text>
        </div>
        <div className="symbol-version-controls">
          {versionMetadata && <Typography.Text type="secondary" className="symbol-version-metadata">{versionMetadata}</Typography.Text>}
          <Select
            showSearch
            optionFilterProp="label"
            aria-label={t('symbols.gameVersion')}
            placeholder={t('symbols.gameVersion')}
            value={gameVersion}
            loading={indexQuery.isLoading}
            onChange={changeVersion}
            options={versionOptions}
          />
        </div>
      </div>

      {indexQuery.error && <Alert type="error" showIcon message={t('symbols.indexError')} description={indexQuery.error.message} />}
      {datasetQuery.error && <Alert type="error" showIcon message={t('symbols.datasetError')} description={datasetQuery.error.message} />}
      {(indexQuery.isLoading || datasetQuery.isLoading) && <div className="page-spinner"><Spin size="large" tip={t('symbols.loading')} /></div>}

      {dataset && (
        <div className="symbol-browser-grid">
          <Card title={t('symbols.treeTitle')} className="symbol-tree-card">
            <SymbolTree records={dataset.records} selectedRecordId={selectedRecord?.id} onSelect={setSelectedRecord} />
          </Card>
          <Card title={t('symbols.searchTitle')} className="symbol-search-card">
            <SymbolSearch
              records={filteredRecords}
              modules={dataset.modules.map((module) => module.name)}
              filters={filters}
              onChange={setFilters}
              onSelect={setSelectedRecord}
            />
          </Card>
        </div>
      )}
      <SymbolDetailDrawer record={selectedRecord} onClose={() => setSelectedRecord(undefined)} />
    </Space>
  )
}
