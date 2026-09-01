[Back to README](../../README.md) | [中文](../zh-CN/snapshot-and-gamedata.md)

# Snapshots, gamedata, and publication

Per-symbol analysis YAML is Git-tracked only under `bin_artifacts/<GAMEVER>/<module>/`. `bin/` contains binaries and
rebuildable IDA state; it is never an artifact truth source. `gamesymbols/`, `gamedata/`, and release manifests are
release-derived outputs and are not versioned in the repository.

## Immutable candidate transaction

Build candidates into an explicit staging directory. The snapshot reads binary metadata from `bin/` and symbol YAML from
`bin_artifacts/`; gamedata must be generated from the same immutable candidate and marked before publication:

```bash
CANDIDATE_DIR="$(mktemp -d)"
uv run python gamesymbol_candidate.py build -gamever cstrike-10210 -bindir bin \
  -artifactdir bin_artifacts -output "$CANDIDATE_DIR/cstrike-10210.yaml" \
  -session "$CANDIDATE_DIR/symbol-session.json"
uv run python gamedata_candidate.py build -gamever cstrike-10210 -build-id local-1 \
  -snapshot "$CANDIDATE_DIR/cstrike-10210.yaml" -configyaml configs/cstrike-10210.yaml \
  -candidate-root "$CANDIDATE_DIR/gamedata" -session "$CANDIDATE_DIR/gamedata-session.json"
uv run python gamesymbol_candidate.py mark -candidate "$CANDIDATE_DIR/cstrike-10210.yaml" \
  -session "$CANDIDATE_DIR/symbol-session.json" -step gamedata \
  -gamedata-session "$CANDIDATE_DIR/gamedata-session.json"
```

Candidate sessions bind the snapshot and metadata bytes, filesystem identities, config, and matching gamedata session.
Gamedata has a canonical self-excluding manifest even for an empty generator inventory. Local `publish` commands copy
verified bytes only to an explicit caller-owned staging directory; normal development and PR validation do not write
repository-root `gamesymbols/` or `gamedata/` trees.

## Release bundle

`release-build.yml` force-rebuilds all configured artifacts in a fresh external root and compares exact bytes with Git
`bin_artifacts`. Per game version it derives a snapshot and metadata, deterministically derives the browser JSON dataset
(schema 3, `<tag>.<sha256>.json`) from them with `gamesymbols_json.py`, marks `json`, and publishes the snapshot/metadata;
`release_bundle.py` then assembles the index (schema 4), packs a single all-in-one archive, and builds a closed bundle
containing:

- `gamesymbols/<tag>.yaml` and `<tag>.metadata.yaml` (canonical snapshot/metadata used for re-derivation);
- `gamesymbols-json/<tag>.<sha256>.json` and `gamesymbols-json/index.json`;
- `archives/gamesymbols-<version>.7z` — the sole published payload, containing `gamesymbols/index.json` and every dataset;
- `evidence/ida-runtime.json`, `evidence/cache-selection.json`;
- `release-manifest-<version>.json` and `SHA256SUMS-<version>.txt`.

The GitHub Release publishes only three assets: `gamesymbols-<version>.7z`, `release-manifest-<version>.json`, and
`SHA256SUMS-<version>.txt`. A GitHub-hosted verifier checks the exact source SHA/bin gitlink, repository artifact
inventory, snapshot/metadata contracts, **independently re-derives the JSON and compares it byte-for-byte with the
bundle's `gamesymbols-json/`**, the 7z contents, bundle allowlist, canonical manifest, and every checksum. Only that
exact verified bundle reaches the protected publisher. GitHub Release assets are the public publication layer; Actions
Artifacts are transport only.

gamedata generation is no longer part of the release pipeline; the snapshot candidate's gamedata consistency gate is
enforced by `gamesymbol-pr-validation.yml` (`mark -step gamedata`) and `update_gamedata.py`.

## Restore and verification

Snapshot restore is an explicit compatibility/migration operation. The Release no longer publishes snapshot YAML; supply
a snapshot from a local candidate build (`gamesymbol_candidate.py build`). Verification reads, and restore writes, only
the explicit artifact root:

```bash
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py restore-legacy -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir <compatibility-artifact-root>
```

The writer emits schema 6 and the reader accepts schemas 1–6. Restore and verification reject links, path escapes,
undeclared or missing YAML, non-canonical bytes, and contract drift.
