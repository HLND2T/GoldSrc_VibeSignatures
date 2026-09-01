import { createHash } from 'node:crypto'
import { access, mkdir, rm, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const configuredDirectory = process.env.GSVIBE_GAMESYMBOLS_DIR
if (configuredDirectory) {
  await access(resolve(configuredDirectory))
  process.exit(0)
}

const fixtureRoot = resolve('.test-gamesymbols')
await rm(fixtureRoot, { force: true, recursive: true })
await mkdir(fixtureRoot, { recursive: true })

const dataset = {
  schemaVersion: 3,
  source: {
    gameVersion: 'test-1',
    snapshotSchemaVersion: 6,
    configDigestVersion: 2,
    analysisOutputContractVersion: 1,
    configSha256: `sha256:${'a'.repeat(64)}`,
    fileCount: 1,
    lastPublishTime: '2026-01-02T03:04:05Z',
  },
  binaries: {
    engine: {
      windows: {
        sha256: '1'.repeat(64),
        md5: '2'.repeat(32),
        crc32: '3'.repeat(8),
        crc64: '4'.repeat(16),
        size: 1,
      },
    },
  },
  modules: [{ name: 'engine', count: 1, windowsCount: 1, linuxCount: 0 }],
  records: [
    {
      id: 'engine/Demo.windows.yaml',
      module: 'engine',
      artifact: 'Demo',
      symbolName: 'Demo',
      platform: 'windows',
      kind: 'function',
      payload: { func_name: 'Demo', func_rva: '0x1' },
    },
  ],
}

const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
const sha256 = createHash('sha256').update(bytes).digest('hex')
const url = `test-1.${sha256}.json`
await writeFile(resolve(fixtureRoot, url), bytes)

const index = {
  schemaVersion: 4,
  versions: [
    {
      gameVersion: 'test-1',
      url,
      sha256,
      size: bytes.byteLength,
      snapshotSchemaVersion: 6,
      fileCount: 1,
      lastPublishTime: '2026-01-02T03:04:05Z',
    },
  ],
}
await writeFile(resolve(fixtureRoot, 'index.json'), Buffer.from(JSON.stringify(index), 'utf8'))
