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

const snapshot = `schema_version: 6
last_publish_time: '2026-01-02T03:04:05Z'
binaries:
  engine:
    windows:
      sha256: '${'1'.repeat(64)}'
      md5: '${'2'.repeat(32)}'
      crc32: '${'3'.repeat(8)}'
      crc64: '${'4'.repeat(16)}'
      size: 1
config_digest_version: 2
analysis_output_contract_version: 1
config_sha256: 'sha256:${'a'.repeat(64)}'
file_count: 1
files:
  engine/Demo.windows.yaml:
    func_name: Demo
    func_rva: '0x1'
game_version: test-1
`

const { createHash } = await import('node:crypto')
const snapshotSha256 = createHash('sha256').update(Buffer.from(snapshot, 'utf8')).digest('hex')
const metadata = `schema_version: 1
game_version: test-1
snapshot_sha256: '${snapshotSha256}'
config_digest_version: 2
config_sha256: '${'a'.repeat(64)}'
modules: []
`

await writeFile(resolve(fixtureRoot, 'test-1.yaml'), snapshot, 'utf8')
await writeFile(resolve(fixtureRoot, 'test-1.metadata.yaml'), metadata, 'utf8')
