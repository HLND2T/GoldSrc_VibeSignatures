import { describe, expect, it } from 'vitest'
import {
  compareGameVersions,
  GAME_SYMBOL_ASSET_PATH_PATTERN,
  GAME_SYMBOL_FILE_PATTERN,
  groupGameVersions,
  parseGameVersion,
  SNAPSHOT_FILE_PATTERN,
} from './gameVersion'

describe('GoldSrc game versions', () => {
  it('parses the final numeric segment as the build', () => {
    expect(parseGameVersion('half-life-12345')).toEqual({ family: 'half-life', build: '12345' })
    expect(() => parseGameVersion('14141')).toThrow(/Invalid GoldSrc game version/)
    expect(() => parseGameVersion('SvenCoop-10257')).toThrow(/Invalid GoldSrc game version/)
  })

  it('sorts families stably and builds from newest to oldest', () => {
    const versions = ['svencoop-6153', 'cstrike-10210', 'svencoop-10257', 'cstrike-9999']
    expect([...versions].sort(compareGameVersions)).toEqual([
      'cstrike-10210',
      'cstrike-9999',
      'svencoop-10257',
      'svencoop-6153',
    ])
    expect(groupGameVersions(versions)).toEqual([
      { family: 'cstrike', versions: ['cstrike-10210', 'cstrike-9999'] },
      { family: 'svencoop', versions: ['svencoop-10257', 'svencoop-6153'] },
    ])
  })

  it('keeps Decay as a standalone family without a fabricated build number', () => {
    expect(parseGameVersion('decay')).toEqual({ family: 'decay', build: '' })
    expect(groupGameVersions(['hl-8684', 'decay', 'cstrike-10210', 'hl-10210'])).toEqual([
      { family: 'cstrike', versions: ['cstrike-10210'] },
      { family: 'decay', versions: ['decay'] },
      { family: 'hl', versions: ['hl-10210', 'hl-8684'] },
    ])
  })

  it('recognizes Decay snapshot and content-addressed asset paths', () => {
    const digest = 'a'.repeat(64)
    expect(SNAPSHOT_FILE_PATTERN.exec('decay.yaml')?.[1]).toBe('decay')
    expect(GAME_SYMBOL_FILE_PATTERN.exec(`decay.${digest}.json`)?.slice(1)).toEqual(['decay', digest])
    expect(GAME_SYMBOL_ASSET_PATH_PATTERN.exec(`/gamesymbols/decay.${digest}.json`)?.slice(1)).toEqual(['decay', digest])
  })

  it('continues rejecting unknown unversioned and malformed tags', () => {
    for (const tag of ['othermod', 'Decay', 'decay-extra', '../decay']) {
      expect(() => parseGameVersion(tag)).toThrow(/Invalid GoldSrc game version/)
      expect(SNAPSHOT_FILE_PATTERN.test(`${tag}.yaml`)).toBe(false)
      expect(GAME_SYMBOL_FILE_PATTERN.test(`${tag}.${'a'.repeat(64)}.json`)).toBe(false)
      expect(GAME_SYMBOL_ASSET_PATH_PATTERN.test(`/gamesymbols/${tag}.${'a'.repeat(64)}.json`)).toBe(false)
    }
  })
})
