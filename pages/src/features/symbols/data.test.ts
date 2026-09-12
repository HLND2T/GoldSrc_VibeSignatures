import { createHash, webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getGameSymbolDataset, getGameSymbolIndex } from './data'
import type { GameSymbolDataset, GameSymbolIndexVersion } from './types'

const dataset: GameSymbolDataset = {
  schemaVersion: 5,
  source: {
    gameVersion: 'svencoop-10257',
    snapshotSchemaVersion: 8,
    configDigestVersion: 2,
    analysisOutputContractVersion: 1,
    configSha256: 'sha256:test',
    fileCount: 0,
    lastPublishTime: '2026-07-27T04:42:43Z',
  },
  binaries: {
    server: {
      windows: {
        sha256: '1'.repeat(64),
        md5: '2'.repeat(32),
        crc32: '3'.repeat(8),
        crc64: '4'.repeat(16),
        size: 123,
        isBlob: false,
      },
    },
  },
  modules: [],
  records: [],
}

function encodedDataset(): { bytes: Uint8Array; version: GameSymbolIndexVersion } {
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  return {
    bytes,
    version: {
      gameVersion: 'svencoop-10257',
      url: `svencoop-10257.${sha256}.json`,
      sha256,
      size: bytes.byteLength,
      snapshotSchemaVersion: 8,
      fileCount: 0,
      lastPublishTime: '2026-07-27T04:42:43Z',
    },
  }
}

async function fetchDataset(invalidDataset: unknown, versionOverride?: Partial<GameSymbolIndexVersion>) {
  const bytes = Buffer.from(JSON.stringify(invalidDataset), 'utf8')
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  const version: GameSymbolIndexVersion = {
    gameVersion: 'svencoop-10257',
    url: `svencoop-10257.${sha256}.json`,
    sha256,
    size: bytes.byteLength,
    snapshotSchemaVersion: 8,
    fileCount: 0,
    lastPublishTime: '2026-07-27T04:42:43Z',
    ...versionOverride,
  }
  vi.stubGlobal('fetch', vi.fn(async () => new Response(bytes)))
  return getGameSymbolDataset(version)
}

describe('game-symbol asset loading', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('accepts index schema v4 only when URL, SHA-256, and size metadata are valid', async () => {
    const { version } = encodedDataset()
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ schemaVersion: 4, versions: [version] }), {
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(getGameSymbolIndex()).resolves.toEqual({ schemaVersion: 4, versions: [version] })
  })

  it('rejects an index URL that does not strictly match the content-addressed filename', async () => {
    const { version } = encodedDataset()
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      schemaVersion: 4,
      versions: [{ ...version, url: 'svencoop-10257.json' }],
    }))))

    await expect(getGameSymbolIndex()).rejects.toThrow(/content-addressed url/)
  })

  it('verifies the response body bytes before parsing the snapshot JSON', async () => {
    const { bytes, version } = encodedDataset()
    const fetchMock = vi.fn(async () => new Response(bytes))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getGameSymbolDataset(version)).resolves.toEqual(dataset)
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining(`/gamesymbols/${version.url}`), { signal: undefined })
  })

  it('rejects size and SHA-256 mismatches without parsing altered JSON', async () => {
    const { bytes, version } = encodedDataset()
    vi.stubGlobal('fetch', vi.fn(async () => new Response(bytes)))

    await expect(getGameSymbolDataset({ ...version, size: version.size + 1 })).rejects.toThrow(/size mismatch/)
    await expect(getGameSymbolDataset({
      ...version,
      url: `svencoop-10257.${'0'.repeat(64)}.json`,
      sha256: '0'.repeat(64),
    })).rejects.toThrow(/SHA-256 mismatch/)
  })

  it('rejects a verified dataset with invalid binary integrity metadata', async () => {
    const invalidDataset = {
      ...dataset,
      binaries: {
        server: {
          windows: { ...dataset.binaries.server.windows, crc64: 'invalid' },
        },
      },
    }
    await expect(fetchDataset(invalidDataset)).rejects.toThrow(/binary crc64/)
  })

  it('rejects datasets that are not schema v5 derived from snapshot schema v8', async () => {
    const legacyDataset = { ...dataset, schemaVersion: 4 }
    await expect(fetchDataset(legacyDataset)).rejects.toThrow(/dataset schema v5/)

    const staleSnapshotDataset = { ...dataset, source: { ...dataset.source, snapshotSchemaVersion: 7 } }
    await expect(fetchDataset(staleSnapshotDataset)).rejects.toThrow(/dataset schema v5/)
  })

  it('rejects binary metadata without a real isBlob boolean', async () => {
    for (const isBlob of [undefined, null, 'false', 0, 1]) {
      const metadata: Record<string, unknown> = {
        sha256: '1'.repeat(64),
        md5: '2'.repeat(32),
        crc32: '3'.repeat(8),
        crc64: '4'.repeat(16),
        size: 123,
      }
      if (isBlob !== undefined) metadata.isBlob = isBlob
      const invalidDataset = { ...dataset, binaries: { server: { windows: metadata } } }
      await expect(fetchDataset(invalidDataset)).rejects.toThrow(/binary isBlob/)
    }
  })

  it('rejects linux binaries flagged as blobs', async () => {
    const invalidDataset = {
      ...dataset,
      binaries: {
        server: {
          linux: { ...dataset.binaries.server.windows, isBlob: true },
        },
      },
    }
    await expect(fetchDataset(invalidDataset)).rejects.toThrow(/isBlob/)
  })
})
