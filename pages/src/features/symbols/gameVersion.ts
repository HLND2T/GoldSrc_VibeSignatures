// Decay is the only explicitly supported tag without a build number.
const GAME_VERSION_SOURCE = '(?:[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+|decay)'
const GAME_SYMBOL_FILE_SOURCE = String.raw`(${GAME_VERSION_SOURCE})\.([0-9a-f]{64})\.json`

export const GAME_VERSION_PATTERN = new RegExp(`^${GAME_VERSION_SOURCE}$`)
export const SNAPSHOT_FILE_PATTERN = new RegExp(String.raw`^(${GAME_VERSION_SOURCE})\.yaml$`)
export const GAME_SYMBOL_FILE_PATTERN = new RegExp(`^${GAME_SYMBOL_FILE_SOURCE}$`)
export const GAME_SYMBOL_ASSET_PATH_PATTERN = new RegExp(`/gamesymbols/${GAME_SYMBOL_FILE_SOURCE}$`)

export interface ParsedGameVersion {
  family: string
  build: string
}

export interface GameVersionGroup {
  family: string
  versions: string[]
}

export function parseGameVersion(value: string): ParsedGameVersion {
  if (!GAME_VERSION_PATTERN.test(value)) throw new Error(`Invalid GoldSrc game version: ${value}`)
  const separator = value.lastIndexOf('-')
  if (separator === -1) return { family: value, build: '' }
  return { family: value.slice(0, separator), build: value.slice(separator + 1) }
}

function compareBuildsDescending(left: string, right: string): number {
  const normalizedLeft = left.replace(/^0+(?=\d)/, '')
  const normalizedRight = right.replace(/^0+(?=\d)/, '')
  if (normalizedLeft.length !== normalizedRight.length) return normalizedRight.length - normalizedLeft.length
  return normalizedRight.localeCompare(normalizedLeft)
}

export function compareGameVersions(left: string, right: string): number {
  const parsedLeft = parseGameVersion(left)
  const parsedRight = parseGameVersion(right)
  const familyDifference = parsedLeft.family.localeCompare(parsedRight.family)
  return familyDifference || compareBuildsDescending(parsedLeft.build, parsedRight.build)
}

export function groupGameVersions(versions: string[]): GameVersionGroup[] {
  const grouped = new Map<string, string[]>()
  for (const version of [...versions].sort(compareGameVersions)) {
    const { family } = parseGameVersion(version)
    const entries = grouped.get(family) ?? []
    entries.push(version)
    grouped.set(family, entries)
  }
  return [...grouped].map(([family, groupedVersions]) => ({ family, versions: groupedVersions }))
}
