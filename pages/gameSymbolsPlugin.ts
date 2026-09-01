import { readFile, readdir } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'
import type { Plugin } from 'vite'
import { GAME_SYMBOL_ASSET_PATH_PATTERN } from './src/features/symbols/gameVersion'

const DATASET_FILE_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+\.[0-9a-f]{64}\.json$/

// The release ships the exact browser-consumable JSON bytes; this plugin only
// relays them into the Vite dev server and build output. Derivation and
// validation happen in the release pipeline and in verifyGameSymbolAssets.mjs.
export function gameSymbolsPlugin(symbolsDirectory: string): Plugin {
  const root = resolve(symbolsDirectory)

  async function assetFiles(): Promise<string[]> {
    const entries = await readdir(root, { withFileTypes: true })
    return entries
      .filter((entry) => entry.isFile() && (entry.name === 'index.json' || DATASET_FILE_PATTERN.test(entry.name)))
      .map((entry) => join(root, entry.name))
      .sort()
  }

  function sendBytes(response: import('node:http').ServerResponse, bytes: Uint8Array): void {
    response.statusCode = 200
    response.setHeader('Content-Type', 'application/json; charset=utf-8')
    response.setHeader('Cache-Control', 'no-cache')
    response.setHeader('Content-Length', bytes.byteLength)
    response.end(bytes)
  }

  return {
    name: 'gamesymbol-assets',
    configureServer(server) {
      server.watcher.add(root)
      server.middlewares.use(async (request, response, next) => {
        const pathname = new URL(request.url ?? '/', 'http://localhost').pathname
        const match = GAME_SYMBOL_ASSET_PATH_PATTERN.exec(pathname)
        if (pathname.endsWith('/gamesymbols/index.json') || match) {
          const name = match ? `${match[1]}.${match[2]}.json` : 'index.json'
          try {
            sendBytes(response, await readFile(join(root, name)))
          } catch (error) {
            next(error instanceof Error ? error : new Error(String(error)))
          }
          return
        }
        next()
      })
    },
    async buildStart() {
      for (const file of await assetFiles()) this.addWatchFile(file)
    },
    async generateBundle() {
      for (const file of await assetFiles()) {
        this.emitFile({ type: 'asset', fileName: `gamesymbols/${basename(file)}`, source: await readFile(file) })
      }
    },
  }
}
