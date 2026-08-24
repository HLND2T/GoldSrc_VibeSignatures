import { createHash } from 'node:crypto'
import { readFile, readdir, stat } from 'node:fs/promises'
import { basename, join } from 'node:path'
import type { Plugin } from 'vite'
import { parse } from 'yaml'
import {
  compareGameVersions,
  GAME_SYMBOL_ASSET_PATH_PATTERN,
  GAME_VERSION_PATTERN,
  SNAPSHOT_FILE_PATTERN,
} from './src/features/symbols/gameVersion'

const SYMBOL_PATH_PATTERN = /^([^/]+)\/([^/]+)\.(windows|linux)\.yaml$/

type JsonObject = Record<string, unknown>

export type GameSymbolPlatform = 'windows' | 'linux'

export interface GameSymbolBinary {
  path?: string
  sha256: string
  md5: string
  crc32: string
  crc64: string
  size: number
}

export type GameSymbolBinaries = Record<string, Partial<Record<GameSymbolPlatform, GameSymbolBinary>>>

export interface GameSymbolRecord {
  id: string
  module: string
  artifact: string
  symbolName: string
  platform: GameSymbolPlatform
  kind: string
  payload: JsonObject
  aliases?: string[]
}

export interface GameSymbolDataset {
  schemaVersion: 3
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

export interface GameSymbolIndex {
  schemaVersion: 4
  versions: GameSymbolIndexVersion[]
}

export interface GameSymbolIndexVersion {
  gameVersion: string
  url: string
  sha256: string
  size: number
  snapshotSchemaVersion: number
  fileCount: number
  lastPublishTime: string
}

export interface EncodedGameSymbolAsset {
  dataset: GameSymbolDataset
  bytes: Uint8Array
  sha256: string
  size: number
  url: string
}

interface CachedDataset {
  mtimeMs: number
  size: number
  metadataMtimeMs: number
  metadataSize: number
  dataset: GameSymbolDataset
}

export interface MetadataAliasIndex {
  aliases: Map<string, string[]>
}

function exactKeys(value: JsonObject, expected: string[], source: string): void {
  const actual = Object.keys(value).sort()
  const canonical = [...expected].sort()
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${source}: unexpected fields`)
  }
}

function requiredAliasArray(value: unknown, field: string, source: string): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${source}: ${field} must be a non-empty string array`)
  const aliases: string[] = []
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0 || item.trim() !== item) throw new Error(`${source}: ${field} contains an invalid alias`)
    if (aliases.includes(item)) throw new Error(`${source}: ${field} contains duplicate alias ${item}`)
    aliases.push(item)
  }
  return aliases
}

export function buildMetadataAliasIndex(
  raw: unknown,
  expectedGameVersion: string,
  snapshotSha256: string,
  dataset: GameSymbolDataset,
  source: string,
): MetadataAliasIndex {
  if (!isObject(raw)) throw new Error(`${source}: metadata root must be a mapping`)
  exactKeys(raw, ['schema_version', 'game_version', 'snapshot_sha256', 'config_digest_version', 'config_sha256', 'modules'], source)
  if (raw.schema_version !== 1) throw new Error(`${source}: schema_version must be 1`)
  if (raw.game_version !== expectedGameVersion) throw new Error(`${source}: game_version does not match snapshot`)
  if (raw.snapshot_sha256 !== snapshotSha256) throw new Error(`${source}: snapshot_sha256 does not match snapshot bytes`)
  if (raw.config_digest_version !== dataset.source.configDigestVersion) throw new Error(`${source}: config_digest_version does not match snapshot`)
  const configSha256 = requiredString(raw.config_sha256, 'config_sha256', source)
  if (!/^[0-9a-f]{64}$/.test(configSha256) || dataset.source.configSha256 !== `sha256:${configSha256}`) {
    throw new Error(`${source}: config_sha256 does not match snapshot`)
  }
  const modules = raw.modules
  if (!Array.isArray(modules)) throw new Error(`${source}: modules must be an array`)
  const aliases = new Map<string, string[]>()
  const recordKeys = new Set(dataset.records.map(record => `${record.module}/${record.platform}/${record.artifact}`))
  const seenModules = new Set<string>()
  for (const [moduleIndex, moduleEntry] of modules.entries()) {
    if (!isObject(moduleEntry)) throw new Error(`${source}: modules[${moduleIndex}] must be a mapping`)
    exactKeys(moduleEntry, ['name', 'symbols'], `${source}: modules[${moduleIndex}]`)
    const moduleName = requiredString(moduleEntry.name, `modules[${moduleIndex}].name`, source)
    if (seenModules.has(moduleName.toLowerCase())) throw new Error(`${source}: duplicate module ${moduleName}`)
    seenModules.add(moduleName.toLowerCase())
    const symbols = moduleEntry.symbols
    if (!Array.isArray(symbols) || symbols.length === 0) throw new Error(`${source}: modules[${moduleIndex}].symbols must be non-empty`)
    const seenSymbols = new Set<string>()
    for (const [symbolIndex, symbolEntry] of symbols.entries()) {
      if (!isObject(symbolEntry)) throw new Error(`${source}: symbol entry must be a mapping`)
      exactKeys(symbolEntry, ['name', 'artifacts', 'alias'], `${source}: symbol entry`)
      const name = requiredString(symbolEntry.name, `modules[${moduleIndex}].symbols[${symbolIndex}].name`, source)
      if (seenSymbols.has(name.toLowerCase())) throw new Error(`${source}: duplicate symbol ${moduleName}.${name}`)
      seenSymbols.add(name.toLowerCase())
      const aliasValues = requiredAliasArray(symbolEntry.alias, `modules[${moduleIndex}].symbols[${symbolIndex}].alias`, source)
      const artifacts = symbolEntry.artifacts
      if (!Array.isArray(artifacts) || artifacts.length === 0) throw new Error(`${source}: alias symbol has no artifacts`)
      let priorPlatform = -1
      for (const artifactEntry of artifacts) {
        if (!isObject(artifactEntry)) throw new Error(`${source}: artifact entry must be a mapping`)
        exactKeys(artifactEntry, ['platform', 'artifact'], `${source}: artifact entry`)
        const platform = artifactEntry.platform
        if (platform !== 'windows' && platform !== 'linux') throw new Error(`${source}: invalid alias platform`)
        const platformIndex = platform === 'windows' ? 0 : 1
        if (platformIndex <= priorPlatform) throw new Error(`${source}: artifacts are not in canonical platform order`)
        priorPlatform = platformIndex
        const artifact = requiredString(artifactEntry.artifact, 'artifact', source)
        const key = `${moduleName}/${platform}/${artifact}`
        if (!recordKeys.has(key)) throw new Error(`${source}: alias owner ${key} is absent from snapshot`)
        if (aliases.has(key)) throw new Error(`${source}: duplicate alias owner ${key}`)
        aliases.set(key, aliasValues)
      }
    }
  }
  return { aliases }
}

export function attachAliasesToDataset(dataset: GameSymbolDataset, aliasIndex: MetadataAliasIndex): GameSymbolDataset {
  if (aliasIndex.aliases.size === 0) return dataset
  let changed = false
  const records = dataset.records.map((record) => {
    const key = `${record.module}/${record.platform}/${record.artifact}`
    const aliases = aliasIndex.aliases.get(key)
    if (!aliases || aliases.length === 0) return record
    changed = true
    return { ...record, aliases }
  })
  return changed ? { ...dataset, records } : dataset
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requiredString(value: unknown, field: string, source: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${source}: ${field} must be a non-empty string`)
  return value
}

function requiredInteger(value: unknown, field: string, source: string): number {
  if (!Number.isInteger(value)) throw new Error(`${source}: ${field} must be an integer`)
  return value as number
}

function requiredNonNegativeInteger(value: unknown, field: string, source: string): number {
  const integer = requiredInteger(value, field, source)
  if (integer < 0) throw new Error(`${source}: ${field} must be a non-negative integer`)
  return integer
}

function optionalInteger(value: unknown, fallback: number, field: string, source: string): number {
  if (value === undefined) return fallback
  return requiredInteger(value, field, source)
}

function requiredPublishTime(value: unknown, source: string): string {
  const publishTime = requiredString(value, 'last_publish_time', source)
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(publishTime) || Number.isNaN(Date.parse(publishTime))) {
    throw new Error(`${source}: last_publish_time must be UTC ISO 8601 with second precision and Z suffix`)
  }
  return publishTime
}

function normalizeBinaries(value: unknown, snapshotSchemaVersion: number, source: string): GameSymbolBinaries {
  if (!isObject(value)) throw new Error(`${source}: binaries must be a mapping`)
  const binaries: GameSymbolBinaries = {}
  for (const [module, platformsValue] of Object.entries(value).sort(([left], [right]) => left.localeCompare(right))) {
    if (!module || module === '.' || module === '..' || module.includes('/') || module.includes('\\')) {
      throw new Error(`${source}: invalid binary module ${module}`)
    }
    if (!isObject(platformsValue)) throw new Error(`${source}: binaries.${module} must be a mapping`)
    const platforms: Partial<Record<GameSymbolPlatform, GameSymbolBinary>> = {}
    for (const [platform, metadataValue] of Object.entries(platformsValue)) {
      if (platform !== 'windows' && platform !== 'linux') throw new Error(`${source}: unsupported binary platform ${platform}`)
      if (!isObject(metadataValue)) throw new Error(`${source}: binaries.${module}.${platform} must be a mapping`)
      let path: string | undefined
      if (snapshotSchemaVersion === 5) {
        path = requiredString(metadataValue.path, `binaries.${module}.${platform}.path`, source)
      } else if (metadataValue.path !== undefined) {
        throw new Error(`${source}: binaries.${module}.${platform}.path is not allowed in schema 6`)
      }
      const sha256 = requiredString(metadataValue.sha256, `binaries.${module}.${platform}.sha256`, source)
      const md5 = requiredString(metadataValue.md5, `binaries.${module}.${platform}.md5`, source)
      const crc32 = requiredString(metadataValue.crc32, `binaries.${module}.${platform}.crc32`, source)
      const crc64 = requiredString(metadataValue.crc64, `binaries.${module}.${platform}.crc64`, source)
      const size = requiredNonNegativeInteger(metadataValue.size, `binaries.${module}.${platform}.size`, source)
      if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error(`${source}: binaries.${module}.${platform}.sha256 is invalid`)
      if (!/^[0-9a-f]{32}$/.test(md5)) throw new Error(`${source}: binaries.${module}.${platform}.md5 is invalid`)
      if (!/^[0-9a-f]{8}$/.test(crc32)) throw new Error(`${source}: binaries.${module}.${platform}.crc32 is invalid`)
      if (!/^[0-9a-f]{16}$/.test(crc64)) throw new Error(`${source}: binaries.${module}.${platform}.crc64 is invalid`)
      platforms[platform] = { ...(path === undefined ? {} : { path }), sha256, md5, crc32, crc64, size }
    }
    binaries[module] = platforms
  }
  return binaries
}

function symbolKind(payload: JsonObject): string {
  if (typeof payload.patch_name === 'string') return 'patch'
  if (typeof payload.vtable_class === 'string') return 'vtable'
  if (typeof payload.struct_name === 'string' && typeof payload.member_name === 'string') return 'structMember'
  if (typeof payload.gv_name === 'string') return 'global'
  if (Number.isInteger(payload.vfunc_index)) return 'virtualFunction'
  if (typeof payload.func_name === 'string') return 'function'
  return 'unknown'
}

function symbolName(payload: JsonObject, artifact: string): string {
  if (typeof payload.func_name === 'string') return payload.func_name
  if (typeof payload.gv_name === 'string') return payload.gv_name
  if (typeof payload.patch_name === 'string') return payload.patch_name
  if (typeof payload.struct_name === 'string' && typeof payload.member_name === 'string') return `${payload.struct_name}.${payload.member_name}`
  if (typeof payload.vtable_class === 'string') return payload.vtable_class
  return artifact
}

export function normalizeGameSymbolSnapshot(raw: unknown, expectedGameVersion: string, source: string): GameSymbolDataset {
  if (!GAME_VERSION_PATTERN.test(expectedGameVersion)) throw new Error(`${source}: invalid game version ${expectedGameVersion}`)
  if (!isObject(raw)) throw new Error(`${source}: snapshot root must be a mapping`)

  const gameVersion = requiredString(raw.game_version, 'game_version', source)
  if (gameVersion !== expectedGameVersion) throw new Error(`${source}: game_version ${gameVersion} does not match filename ${expectedGameVersion}`)
  const snapshotSchemaVersion = requiredInteger(raw.schema_version, 'schema_version', source)
  if (snapshotSchemaVersion !== 5 && snapshotSchemaVersion !== 6) {
    throw new Error(`${source}: schema_version must be 5 or 6`)
  }

  const files = raw.files
  if (!isObject(files)) throw new Error(`${source}: files must be a mapping`)
  const fileCount = requiredInteger(raw.file_count, 'file_count', source)
  const fileEntries = Object.entries(files)
  if (fileEntries.length !== fileCount) throw new Error(`${source}: file_count ${fileCount} does not match ${fileEntries.length} files`)
  const lastPublishTime = requiredPublishTime(raw.last_publish_time, source)
  const binaries = normalizeBinaries(raw.binaries, snapshotSchemaVersion, source)

  const moduleCounts = new Map<string, { count: number; windowsCount: number; linuxCount: number }>()
  const records = fileEntries.map(([id, payloadValue]) => {
    const pathMatch = SYMBOL_PATH_PATTERN.exec(id)
    if (!pathMatch) throw new Error(`${source}: invalid symbol path ${id}`)
    if (!isObject(payloadValue)) throw new Error(`${source}: ${id} payload must be a mapping`)

    const module = pathMatch[1]
    const artifact = pathMatch[2]
    if (module === '.' || module === '..' || artifact === '.' || artifact === '..' || module.includes('\\') || artifact.includes('\\')) {
      throw new Error(`${source}: invalid symbol path ${id}`)
    }
    const platform = pathMatch[3] as GameSymbolPlatform
    const counts = moduleCounts.get(module) ?? { count: 0, windowsCount: 0, linuxCount: 0 }
    counts.count += 1
    if (platform === 'windows') counts.windowsCount += 1
    else counts.linuxCount += 1
    moduleCounts.set(module, counts)

    return {
      id,
      module,
      artifact,
      symbolName: symbolName(payloadValue, artifact),
      platform,
      kind: symbolKind(payloadValue),
      payload: payloadValue,
    }
  })

  return {
    schemaVersion: 3,
    source: {
      gameVersion,
      snapshotSchemaVersion,
      configDigestVersion: optionalInteger(raw.config_digest_version, 1, 'config_digest_version', source),
      analysisOutputContractVersion: optionalInteger(raw.analysis_output_contract_version, 1, 'analysis_output_contract_version', source),
      configSha256: requiredString(raw.config_sha256, 'config_sha256', source),
      fileCount,
      lastPublishTime,
    },
    binaries,
    modules: [...moduleCounts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, counts]) => ({ name, ...counts })),
    records,
  }
}

export function encodeGameSymbolAsset(dataset: GameSymbolDataset): EncodedGameSymbolAsset {
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  return {
    dataset,
    bytes,
    sha256,
    size: bytes.byteLength,
    url: `${dataset.source.gameVersion}.${sha256}.json`,
  }
}

export function createGameSymbolIndex(assets: EncodedGameSymbolAsset[]): GameSymbolIndex {
  return {
    schemaVersion: 4,
    versions: assets
      .map((asset) => ({
        gameVersion: asset.dataset.source.gameVersion,
        url: asset.url,
        sha256: asset.sha256,
        size: asset.size,
        snapshotSchemaVersion: asset.dataset.source.snapshotSchemaVersion,
        fileCount: asset.dataset.source.fileCount,
        lastPublishTime: asset.dataset.source.lastPublishTime,
      }))
      .sort((left, right) => compareGameVersions(left.gameVersion, right.gameVersion)),
  }
}

export function gameSymbolsPlugin(symbolsDirectory: string): Plugin {
  const cache = new Map<string, CachedDataset>()

  async function snapshotFiles(): Promise<string[]> {
    const entries = await readdir(symbolsDirectory, { withFileTypes: true })
    return entries
      .filter((entry) => entry.isFile() && SNAPSHOT_FILE_PATTERN.test(entry.name))
      .map((entry) => join(symbolsDirectory, entry.name))
  }

  async function loadDataset(filePath: string): Promise<GameSymbolDataset> {
    const fileStat = await stat(filePath)
    const fileName = basename(filePath)
    const match = SNAPSHOT_FILE_PATTERN.exec(fileName)
    if (!match) throw new Error(`Invalid gamesymbol snapshot filename: ${fileName}`)
    const metadataPath = join(symbolsDirectory, `${match[1]}.metadata.yaml`)
    const metadataStat = await stat(metadataPath)

    const cached = cache.get(filePath)
    if (
      cached?.mtimeMs === fileStat.mtimeMs && cached.size === fileStat.size
      && cached.metadataMtimeMs === metadataStat.mtimeMs && cached.metadataSize === metadataStat.size
    ) return cached.dataset

    const snapshotBytes = await readFile(filePath)
    const raw = parse(snapshotBytes.toString('utf8')) as unknown
    let dataset = normalizeGameSymbolSnapshot(raw, match[1], filePath)
    const snapshotSha256 = createHash('sha256').update(snapshotBytes).digest('hex')
    const metadataRaw = parse(await readFile(metadataPath, 'utf8')) as unknown
    dataset = attachAliasesToDataset(dataset, buildMetadataAliasIndex(metadataRaw, match[1], snapshotSha256, dataset, metadataPath))

    cache.set(filePath, {
      mtimeMs: fileStat.mtimeMs,
      size: fileStat.size,
      metadataMtimeMs: metadataStat.mtimeMs,
      metadataSize: metadataStat.size,
      dataset,
    })
    return dataset
  }

  async function loadAll(): Promise<GameSymbolDataset[]> {
    return Promise.all((await snapshotFiles()).map(loadDataset))
  }

  async function loadAllAssets(): Promise<EncodedGameSymbolAsset[]> {
    return (await loadAll()).map(encodeGameSymbolAsset)
  }

  function sendBytes(response: import('node:http').ServerResponse, bytes: Uint8Array): void {
    response.statusCode = 200
    response.setHeader('Content-Type', 'application/json; charset=utf-8')
    response.setHeader('Cache-Control', 'no-cache')
    response.setHeader('Content-Length', bytes.byteLength)
    response.end(bytes)
  }

  function sendJson(response: import('node:http').ServerResponse, value: unknown): void {
    sendBytes(response, Buffer.from(JSON.stringify(value), 'utf8'))
  }

  return {
    name: 'gamesymbol-assets',
    configureServer(server) {
      server.watcher.add(symbolsDirectory)
      server.middlewares.use(async (request, response, next) => {
        const pathname = new URL(request.url ?? '/', 'http://localhost').pathname
        if (pathname.endsWith('/gamesymbols/index.json')) {
          try {
            sendJson(response, createGameSymbolIndex(await loadAllAssets()))
          } catch (error) {
            next(error instanceof Error ? error : new Error(String(error)))
          }
          return
        }

        const match = GAME_SYMBOL_ASSET_PATH_PATTERN.exec(pathname)
        if (!match) {
          next()
          return
        }
        try {
          const asset = encodeGameSymbolAsset(await loadDataset(join(symbolsDirectory, `${match[1]}.yaml`)))
          if (asset.sha256 !== match[2]) {
            response.statusCode = 404
            response.end()
            return
          }
          sendBytes(response, asset.bytes)
        } catch (error) {
          next(error instanceof Error ? error : new Error(String(error)))
        }
      })
    },
    async buildStart() {
      const files = await snapshotFiles()
      files.forEach((filePath) => this.addWatchFile(filePath))
      files.forEach((filePath) => {
        const match = SNAPSHOT_FILE_PATTERN.exec(basename(filePath))
        if (match) this.addWatchFile(join(symbolsDirectory, `${match[1]}.metadata.yaml`))
      })
    },
    async generateBundle() {
      const files = await snapshotFiles()
      const assets = (await Promise.all(files.map(loadDataset))).map(encodeGameSymbolAsset)
      assets.forEach((asset) => {
        this.emitFile({
          type: 'asset',
          fileName: `gamesymbols/${asset.url}`,
          source: asset.bytes,
        })
      })
      this.emitFile({
        type: 'asset',
        fileName: 'gamesymbols/index.json',
        source: JSON.stringify(createGameSymbolIndex(assets)),
      })
    },
  }
}
