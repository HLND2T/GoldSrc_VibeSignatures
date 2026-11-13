# GoldSrc VibeSignatures Symbol Explorer

React + TypeScript + Vite application for browsing static game symbol snapshots. Search symbols and inspect their details without configuring a backend. Language and color theme preferences are saved locally.

## Development

```powershell
npm ci
npm run build
npm run dev
```

## Pages deployment

`esa.jsonc` publishes the static `dist/` directory and uses SPA fallback routing. All symbol data is served alongside the application; no API service is required.

The production workflow downloads and extracts the `gamesymbols-*.7z` asset from the immutable published GitHub Release selected by the release event; the archive already contains the release-derived schema-4 index plus content-addressed schema-5 datasets, which the Vite plugin relays unchanged into the build. Local and CI builds use a generated minimal JSON fixture unless `GSVIBE_GAMESYMBOLS_DIR` points to an explicit downloaded asset directory. Each binary entry in a version JSON carries raw-byte MD5, SHA-256, CRC-32/ISO-HDLC, CRC-64/XZ, and byte size. Every version entry carries the SHA-256 and byte size of the exact UTF-8 JSON response body, and its URL is strictly `<gameVersion>.<sha256>.json`. The browser verifies those bytes before decoding or parsing the dataset.

The Pages workflow keeps finalized snapshot bytes in the append-only `pages-snapshots` branch. Its history is required to contain additions only, pushes are non-forced, and an existing digest file must remain byte-identical. A same-version content change therefore adds a new digest file, while every previously archived digest is copied into later Pages artifacts. After deployment, the workflow fetches the public Pages responses and recomputes their size and SHA-256 so CDN delivery is checked against index v4 as well.

## Verification

```powershell
npm run lint
npm test
npm run build
npm run verify:gamesymbols
npm run test:e2e
```
