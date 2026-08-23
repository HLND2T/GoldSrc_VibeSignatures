[Back to README](../../README.md) | [中文](../zh-CN/snapshot-and-gamedata.md)

# Snapshots, gamedata, and publication

Per-symbol YAML remains ignored under `bin/<GAMEVER>/<module>/`. Each published version has a Git-tracked canonical pair: `gamesymbols/<GAMEVER>.yaml` contains the analysis lockfile, while `gamesymbols/<GAMEVER>.metadata.yaml` freezes the display aliases and their resolved module/platform/artifact owners.

## Immutable candidate transaction

After a successful top-level analysis transaction, build one candidate immediately. Both downstream consumers read that same immutable candidate; publication copies its original bytes only after the gamedata guard succeeds:

```bash
CANDIDATE_DIR="$(mktemp -d)"
CANDIDATE_SNAPSHOT="$CANDIDATE_DIR/cstrike-10210.yaml"
CANDIDATE_METADATA="$CANDIDATE_DIR/cstrike-10210.metadata.yaml"
CANDIDATE_SESSION="$CANDIDATE_DIR/session.json"
GAMEDATA_ROOT="$CANDIDATE_DIR/gamedata-candidate"
GAMEDATA_SESSION="$CANDIDATE_DIR/gamedata.session.json"

uv run python gamesymbol_candidate.py build -gamever cstrike-10210 -bindir bin -output "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION"
uv run python gamedata_candidate.py build -gamever cstrike-10210 -build-id local-1 -snapshot "$CANDIDATE_SNAPSHOT" -configyaml configs/cstrike-10210.yaml -candidate-root "$GAMEDATA_ROOT" -session "$GAMEDATA_SESSION"
uv run python gamedata_candidate.py guard -session "$GAMEDATA_SESSION"
uv run python gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step gamedata -gamedata-session "$GAMEDATA_SESSION"
uv run python gamesymbol_candidate.py publish -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -destination gamesymbols/cstrike-10210.yaml
uv run python gamedata_candidate.py publish -session "$GAMEDATA_SESSION" -outputdir gamedata/cstrike-10210
uv run python gamedata_candidate.py stage -session "$GAMEDATA_SESSION" -repo-root .
```

Notes:

- `gamesymbol_candidate.py mark -step gamedata` requires a `-gamedata-session` whose gamever and candidate SHA-256 match the symbol candidate.
- `gamedata_candidate.py publish -outputdir` must end with the exact tag. Publication is an atomic replace.
- Candidate build also generates `$CANDIDATE_METADATA`. The session binds both exact paths, hashes, filesystem identities, and the metadata-to-snapshot SHA-256.
- Local pair publication uses a recovery journal and fixed replacement order. A verifier rejects any intermediate mismatch; the Git commit/tree is the externally visible atomic boundary.
- Every gamedata directory contains canonical `gamedata-manifest.json`, even when no generator emits payload files. It binds the snapshot, config, generator contract, and a self-excluding payload inventory.
- The gamedata config identity normalizes CRLF to LF and rejects bare CR. Repository attributes pin tracked configs to LF, so Windows candidate generation and exact Git-blob verification share one digest.
- `stage` guards the candidate, builds and verifies a temporary Git tree, then uses `git add -f -- <exact-path>` only for the candidate manifest paths. The repository keeps `gamedata/*/` ignored; broad glob staging is forbidden.
- An absent or empty generator root produces an empty, hashed inventory that still satisfies the gamedata step after `guard` succeeds.

Generate or independently verify a tracked companion with:

```bash
uv run python gamesymbol_metadata.py generate -snapshot gamesymbols/hl-10210.yaml -configyaml configs/hl-10210.yaml -gamever hl-10210 -metadata gamesymbols/hl-10210.metadata.yaml
uv run python gamesymbol_metadata.py verify -snapshot gamesymbols/hl-10210.yaml -configyaml configs/hl-10210.yaml -gamever hl-10210 -metadata gamesymbols/hl-10210.metadata.yaml
```

Pages never reads live config aliases. A missing, non-canonical, hash-mismatched, or owner-mismatched companion fails the build.

## Release content inventory

The schema-1 release content manifest is a second, Git-tree-level contract. For one tag it inventories the exact
`gamesymbols/<tag>.yaml`, `gamesymbols/<tag>.metadata.yaml`, and `gamedata/<tag>/**` blobs with their Git mode, size, and
raw SHA-256. `release-manifests/<tag>.json` is excluded from that digest, so the manifest never hashes itself.

The verifier cross-checks the companion's snapshot/config bindings, the gamedata manifest's snapshot/config/generator
bindings, the snapshot binary inventory, and the `bin` gitlink. A missing companion or gamedata manifest, unexpected
gamedata payload, executable-mode payload, non-canonical bytes, or default-branch drift fails closed. Shadow output is
evidence only and does not change canonical publication authority.

## Generate gamedata directly

To convert a canonical symbol snapshot into versioned gamedata without the full candidate transaction:

```bash
uv run python update_gamedata.py -gamever cstrike-10210 -snapshot gamesymbols/cstrike-10210.yaml -modulesdir gamedata-generators -outputdir gamedata/cstrike-10210
```

## Restore and verify snapshots

Restore a clean analysis baseline or verify the current workspace without modifying the tracked snapshot:

```bash
uv run python gamesymbol_snapshot.py restore -gamever cstrike-10210
uv run python gamesymbol_snapshot.py restore -gamever cstrike-10210 -replace
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10210
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10210
```

Default restore creates missing YAML and refuses to overwrite semantically different files. `-replace` removes only YAML under `bin/<GAMEVER>/`, preserves binaries and IDA databases, then rebuilds the snapshot contents.

The writer emits schema 6 with config digest v2, canonical file payloads, and path-independent binary hash metadata; the reader accepts schemas 1–6. Schema 5 remains readable with its required legacy binary `path`. Restore and verification reject links, path escapes, undeclared YAML, missing required YAML, non-canonical bytes, and contract drift.

`check-contract` is a read-only trust probe: exit `0` means trusted, exit `3` reports a machine-readable untrusted reason, and invocation, configuration, or operational errors remain hard failures.

## Scope: no C++ layout validation

Unlike the CS2 project, GoldSrc VibeSignatures does not run C++ layout validation against source headers — there is no `run_cpp_tests.py` or HL2SDK checkout. The gamedata step is the sole downstream guard before publication.
