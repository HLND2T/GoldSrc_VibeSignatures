export type GameSymbolPlatform = 'windows' | 'linux'

/**
 * Metadata of the ORIGINAL game binary file covered by the hashes/size fields.
 * `isBlob: true` means that original Windows file is a fully verified Metahook
 * blob container (not a plain PE); it never describes the decrypted rebuild.
 */
export interface GameSymbolBinary {
  sha256: string
  md5: string
  crc32: string
  crc64: string
  size: number
  isBlob: boolean
}

export type GameSymbolBinaries = Record<string, Partial<Record<GameSymbolPlatform, GameSymbolBinary>>>

export interface GameSymbolIndexVersion {
  gameVersion: string
  url: string
  sha256: string
  size: number
  snapshotSchemaVersion: number
  fileCount: number
  lastPublishTime: string
}

export interface GameSymbolIndex {
  schemaVersion: 4
  versions: GameSymbolIndexVersion[]
}

export interface GameSymbolRecord {
  id: string
  module: string
  artifact: string
  symbolName: string
  platform: GameSymbolPlatform
  kind: string
  payload: Record<string, unknown>
  aliases?: string[]
}

export interface GameSymbolDataset {
  schemaVersion: 5
  source: {
    gameVersion: string
    snapshotSchemaVersion: number
    configDigestVersion: number
    analysisOutputContractVersion: number
    configSha256: string
    fileCount: number
    lastPublishTime: string
  }
  binaries: GameSymbolBinaries
  modules: Array<{
    name: string
    count: number
    windowsCount: number
    linuxCount: number
  }>
  records: GameSymbolRecord[]
}

export interface SymbolFilters {
  module?: string
  query: string
  platform?: GameSymbolPlatform
}
