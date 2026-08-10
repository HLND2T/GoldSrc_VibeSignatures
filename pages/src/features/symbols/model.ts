import type { DataNode } from 'antd/es/tree'
import type { TFunction } from 'i18next'
import type { GameSymbolRecord, SymbolFilters } from './types'

export function filterSymbolRecords(records: GameSymbolRecord[], filters: SymbolFilters): GameSymbolRecord[] {
  const query = filters.query.trim().toLowerCase()
  return records.filter((record) => {
    if (filters.module && record.module !== filters.module) return false
    if (filters.platform && record.platform !== filters.platform) return false
    if (!query) return true
    const haystack = `${record.symbolName} ${record.artifact} ${record.id} ${(record.aliases ?? []).join(' ')}`.toLowerCase()
    return haystack.includes(query)
  })
}

export function symbolKindLabel(kind: string, t: TFunction): string {
  const labels: Record<string, string> = {
    function: t('symbols.kinds.function'),
    virtualFunction: t('symbols.kinds.virtualFunction'),
    global: t('symbols.kinds.global'),
    vtable: t('symbols.kinds.vtable'),
    structMember: t('symbols.kinds.structMember'),
    patch: t('symbols.kinds.patch'),
    unknown: t('symbols.kinds.unknown'),
  }
  return labels[kind] ?? kind
}

export function createSymbolTree(records: GameSymbolRecord[], t: TFunction): DataNode[] {
  const modules = new Map<string, Map<string, GameSymbolRecord[]>>()
  records.forEach((record) => {
    const symbols = modules.get(record.module) ?? new Map<string, GameSymbolRecord[]>()
    const platforms = symbols.get(record.artifact) ?? []
    platforms.push(record)
    symbols.set(record.artifact, platforms)
    modules.set(record.module, symbols)
  })

  return [...modules.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([module, symbols]) => ({
      key: `module:${module}`,
      title: `${module} (${[...symbols.values()].reduce((count, entries) => count + entries.length, 0)})`,
      children: [...symbols.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([artifact, entries]) => {
          const symbolName = entries[0]?.symbolName ?? artifact
          return {
            key: `symbol:${module}/${artifact}`,
            title: symbolName === artifact ? symbolName : `${symbolName} (${artifact})`,
            children: entries
              .sort((left, right) => right.platform.localeCompare(left.platform))
              .map((record) => ({
                key: `record:${record.id}`,
                title: record.platform === 'windows' ? t('symbols.windows') : t('symbols.linux'),
                isLeaf: true,
              })),
          }
        }),
    }))
}
