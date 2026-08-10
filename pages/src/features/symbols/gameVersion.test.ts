import { describe, expect, it } from 'vitest'
import { compareGameVersions, groupGameVersions, parseGameVersion } from './gameVersion'

describe('GoldSrc game versions', () => {
  it('parses the final numeric segment as the build', () => {
    expect(parseGameVersion('half-life-12345')).toEqual({ family: 'half-life', build: '12345' })
    expect(() => parseGameVersion('14141')).toThrow(/Invalid GoldSrc game version/)
    expect(() => parseGameVersion('SvenCoop-10257')).toThrow(/Invalid GoldSrc game version/)
  })

  it('sorts families stably and builds from newest to oldest', () => {
    const versions = ['svencoop-6153', 'cstrike-10120', 'svencoop-10257', 'cstrike-9999']
    expect([...versions].sort(compareGameVersions)).toEqual([
      'cstrike-10120',
      'cstrike-9999',
      'svencoop-10257',
      'svencoop-6153',
    ])
    expect(groupGameVersions(versions)).toEqual([
      { family: 'cstrike', versions: ['cstrike-10120', 'cstrike-9999'] },
      { family: 'svencoop', versions: ['svencoop-10257', 'svencoop-6153'] },
    ])
  })
})
