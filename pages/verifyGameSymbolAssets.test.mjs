import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  mergeImmutableArchive,
  verifyGameSymbolAssetDirectory,
  verifyRemoteGameSymbolAssets,
  writeGameSymbolVerificationManifest,
} from './verifyGameSymbolAssets.mjs'

const temporaryRoots = []

async function temporaryRoot() {
  const root = await mkdtemp(join(tmpdir(), 'gamesymbol-pages-'))
  temporaryRoots.push(root)
  return root
}

async function writeCurrentAssets(directory, gameVersion, marker) {
  await mkdir(directory, { recursive: true })
  const dataset = {
    schemaVersion: 5,
    source: { gameVersion, snapshotSchemaVersion: 8 },
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
    records: [{ marker }],
  }
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const digest = createHash('sha256').update(bytes).digest('hex')
  const url = `${gameVersion}.${digest}.json`
  await writeFile(join(directory, url), bytes)
  await writeFile(join(directory, 'index.json'), JSON.stringify({
    schemaVersion: 4,
    versions: [{
      gameVersion,
      url,
      sha256: digest,
      size: bytes.byteLength,
      snapshotSchemaVersion: 8,
      fileCount: 1,
      lastPublishTime: '2026-07-28T00:00:00Z',
    }],
  }))
  return { bytes, digest, url }
}

async function writeLegacySnapshot(directory, gameVersion, marker) {
  await mkdir(directory, { recursive: true })
  const dataset = {
    schemaVersion: 3,
    source: { gameVersion, snapshotSchemaVersion: 6 },
    records: [{ marker }],
  }
  const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
  const digest = createHash('sha256').update(bytes).digest('hex')
  const url = `${gameVersion}.${digest}.json`
  await writeFile(join(directory, url), bytes)
  return { bytes, digest, url }
}

async function writeIndex(directory, gameVersion, asset) {
  await writeFile(join(directory, 'index.json'), JSON.stringify({
    schemaVersion: 4,
    versions: [{
      gameVersion,
      url: asset.url,
      sha256: asset.digest,
      size: asset.bytes.byteLength,
      snapshotSchemaVersion: 4,
      fileCount: 1,
      lastPublishTime: '2026-07-28T00:00:00Z',
    }],
  }))
}

afterEach(async () => {
  vi.unstubAllGlobals()
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })))
})

describe('immutable game-symbol asset verification', () => {
  it('verifies index v4 metadata against the exact snapshot bytes', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const asset = await writeCurrentAssets(current, 'svencoop-10257', '最终字节')

    await expect(verifyGameSymbolAssetDirectory(current)).resolves.toEqual(expect.objectContaining({ snapshotCount: 1 }))
    await writeFile(join(current, asset.url), Buffer.concat([asset.bytes, Buffer.from('\n')]))
    await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/filename SHA-256/)
  })

  it('keeps old digests and adds a new file when the same game version changes', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const first = await writeCurrentAssets(current, 'svencoop-10257', 'first')
    await mergeImmutableArchive(current, archive)

    await rm(current, { recursive: true, force: true })
    const second = await writeCurrentAssets(current, 'svencoop-10257', 'second')
    const result = await mergeImmutableArchive(current, archive)

    expect(first.url).not.toBe(second.url)
    expect(result.added).toBe(1)
    expect(result.archived).toBe(2)
    expect(await readdir(archive)).toEqual(expect.arrayContaining([first.url, second.url]))
    expect(await readFile(join(current, first.url))).toEqual(first.bytes)
    expect(await readFile(join(current, second.url))).toEqual(second.bytes)
  })

  it('preserves legacy schema v3 datasets as immutable archive history', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const legacy = await writeLegacySnapshot(archive, 'svencoop-10257', 'legacy')
    const latest = await writeCurrentAssets(current, 'svencoop-10257', 'latest')

    const result = await mergeImmutableArchive(current, archive)

    expect(result.added).toBe(1)
    expect(result.archived).toBe(2)
    expect(await readFile(join(archive, latest.url))).toEqual(latest.bytes)
    expect(await readFile(join(current, legacy.url))).toEqual(legacy.bytes)
  })

  it('rejects legacy datasets when the current index points to them', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const legacy = await writeLegacySnapshot(current, 'svencoop-10257', 'legacy')
    await writeIndex(current, 'svencoop-10257', legacy)

    await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/dataset body must be schema v5/)
  })

  it('rejects current datasets whose isBlob violates the contract', async () => {
    for (const mutation of [
      (metadata) => ({ ...metadata, isBlob: 'false' }),
      (metadata) => ({ ...metadata, isBlob: 1 }),
      (metadata) => ({ sha256: metadata.sha256, md5: metadata.md5, crc32: metadata.crc32, crc64: metadata.crc64, size: metadata.size }),
    ]) {
      const root = await temporaryRoot()
      const current = join(root, 'current')
      await mkdir(current, { recursive: true })
      const dataset = {
        schemaVersion: 5,
        source: { gameVersion: 'svencoop-10257', snapshotSchemaVersion: 8 },
        binaries: { server: { windows: mutation({
          sha256: '1'.repeat(64),
          md5: '2'.repeat(32),
          crc32: '3'.repeat(8),
          crc64: '4'.repeat(16),
          size: 123,
          isBlob: false,
        }) } },
        records: [],
      }
      const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
      const digest = createHash('sha256').update(bytes).digest('hex')
      const url = `svencoop-10257.${digest}.json`
      await writeFile(join(current, url), bytes)
      await writeIndex(current, 'svencoop-10257', { url, digest, bytes })

      await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/isBlob/)
    }
  })

  it('rejects a linux binary flagged as a blob in current datasets', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    await mkdir(current, { recursive: true })
    const dataset = {
      schemaVersion: 5,
      source: { gameVersion: 'svencoop-10257', snapshotSchemaVersion: 8 },
      binaries: { server: { linux: {
        sha256: '1'.repeat(64),
        md5: '2'.repeat(32),
        crc32: '3'.repeat(8),
        crc64: '4'.repeat(16),
        size: 123,
        isBlob: true,
      } } },
      records: [],
    }
    const bytes = Buffer.from(JSON.stringify(dataset), 'utf8')
    const digest = createHash('sha256').update(bytes).digest('hex')
    const url = `svencoop-10257.${digest}.json`
    await writeFile(join(current, url), bytes)
    await writeIndex(current, 'svencoop-10257', { url, digest, bytes })

    await expect(verifyGameSymbolAssetDirectory(current)).rejects.toThrow(/isBlob/)
  })

  it('rejects any modification of an archived content-addressed snapshot', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const asset = await writeCurrentAssets(current, 'svencoop-10257', 'first')
    await mergeImmutableArchive(current, archive)
    await writeFile(join(archive, asset.url), Buffer.from('tampered', 'utf8'))

    await expect(mergeImmutableArchive(current, archive)).rejects.toThrow(/filename SHA-256/)
  })

  it('waits for this build index and verifies every current and historical CDN body', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const manifestPath = join(root, 'verification.json')
    const legacy = await writeLegacySnapshot(archive, 'svencoop-10257', 'legacy')
    const first = await writeCurrentAssets(current, 'svencoop-10257', 'first')
    const staleIndex = await readFile(join(current, 'index.json'))
    await mergeImmutableArchive(current, archive)
    await rm(current, { recursive: true, force: true })
    const second = await writeCurrentAssets(current, 'svencoop-10257', 'second')
    await mergeImmutableArchive(current, archive)
    const manifest = await writeGameSymbolVerificationManifest(current, manifestPath)
    const currentIndex = await readFile(join(current, 'index.json'))

    let indexRequests = 0
    const fetchMock = vi.fn(async (input) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/index.json')) {
        indexRequests += 1
        return new Response(indexRequests === 1 ? staleIndex : currentIndex)
      }
      return new Response(await readFile(join(current, url.pathname.split('/').at(-1))))
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(verifyRemoteGameSymbolAssets('https://example.test/gamesymbols/', manifest, {
      attempts: 2,
      delayMs: 0,
      batchSize: 2,
    })).resolves.toEqual(expect.objectContaining({ verified: 3 }))
    expect(indexRequests).toBe(2)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(legacy.url))).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(first.url))).toBe(true)
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes(second.url))).toBe(true)
  })

  it('fails CDN verification when an archived digest is no longer reachable', async () => {
    const root = await temporaryRoot()
    const current = join(root, 'current')
    const archive = join(root, 'archive')
    const first = await writeCurrentAssets(current, 'svencoop-10257', 'first')
    await mergeImmutableArchive(current, archive)
    await rm(current, { recursive: true, force: true })
    await writeCurrentAssets(current, 'svencoop-10257', 'second')
    await mergeImmutableArchive(current, archive)
    const manifest = await writeGameSymbolVerificationManifest(current, join(root, 'verification.json'))
    const currentIndex = await readFile(join(current, 'index.json'))

    vi.stubGlobal('fetch', vi.fn(async (input) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/index.json')) return new Response(currentIndex)
      if (url.pathname.endsWith(first.url)) return new Response(null, { status: 404 })
      return new Response(await readFile(join(current, url.pathname.split('/').at(-1))))
    }))

    await expect(verifyRemoteGameSymbolAssets('https://example.test/gamesymbols/', manifest, {
      attempts: 1,
      delayMs: 0,
    })).rejects.toThrow(/failed after 1 attempts/)
  })
})
