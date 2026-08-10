import { Empty, Tree } from 'antd'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createSymbolTree } from './model'
import type { GameSymbolRecord } from './types'

interface Props {
  records: GameSymbolRecord[]
  selectedRecordId?: string
  onSelect(record: GameSymbolRecord): void
}

export function SymbolTree({ records, selectedRecordId, onSelect }: Props) {
  const { t } = useTranslation()
  const recordsById = useMemo(() => new Map(records.map((record) => [record.id, record])), [records])
  const treeData = useMemo(() => createSymbolTree(records, t), [records, t])
  if (records.length === 0) return <Empty description={t('symbols.noSymbols')} />
  return (
    <Tree
      blockNode
      showLine
      height={620}
      treeData={treeData}
      selectedKeys={selectedRecordId ? [`record:${selectedRecordId}`] : []}
      onSelect={(_, info) => {
        const key = String(info.node.key)
        if (!key.startsWith('record:')) return
        const record = recordsById.get(key.slice('record:'.length))
        if (record) onSelect(record)
      }}
    />
  )
}
