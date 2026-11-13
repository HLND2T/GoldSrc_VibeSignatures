[Back to README](../../README.md) | [中文](../zh-CN/symbol-browser.md)

# Static Symbol Explorer and Pages

The React application in `pages/` browses published game symbol snapshots. It loads the static version index and
content-addressed datasets directly, with no backend connection or service setup. Search by module, platform, symbol
name or artifact; open symbol details; switch language and color theme from the header.

Build locally:

```bash
cd pages
npm ci
npm run build
npm run verify:gamesymbols
npm run preview
```

Local and CI builds generate a minimal fixture unless `GSVIBE_GAMESYMBOLS_DIR` points to a downloaded release dataset
directory. Production downloads the immutable published Release's `gamesymbols-*.7z` asset and relays its exact bytes
into `pages/dist`. The browser verifies dataset size and SHA-256 before parsing.

GitHub Pages publishes the static `pages/dist` artifact. The `pages-snapshots` branch is an append-only presentation
mirror of published Releases; existing digest files remain byte-identical. See [Pages development](../../pages/README.md)
for deployment and verification details.
