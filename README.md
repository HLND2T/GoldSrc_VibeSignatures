# GoldSrc VibeSignatures

GoldSrc VibeSignatures is a reproducible Python 3.10+ framework for producing and publishing x86 game-symbol
snapshots. It validates PE32/I386 and ELF32/I386 inputs, executes a dependency-checked analysis graph, records an
immutable candidate, and exposes a strict local contract to downstream gamedata generators.

The initial production configuration intentionally contains no signatures. It covers Counter-Strike build 10120 and
Sven Co-op build 10257, with `engine`, `client`, `gameui`, and `server` modules on Windows and Linux.

## Setup

```console
uv sync --locked
```

Downloaded depots, binaries, IDA databases, candidates, and generated outputs are ignored. Existing local files below
`bin/svencoop/` are read-only smoke inputs and are never moved or rewritten.

## Workflow

```console
uv run python download_depot.py -tag cstrike-10120 -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform all-platform
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform windows -checkonly
uv run python ida_analyze_bin.py -gamever cstrike-10120 -oldgamever cstrike-previous-10000

uv run python gamesymbol_candidate.py build -gamever cstrike-10120 -bindir bin -output .candidates/candidate.yaml -session .candidates/session.json
uv run python gamesymbol_candidate.py guard -candidate .candidates/candidate.yaml -session .candidates/session.json

uv run python gamedata_candidate.py build -gamever cstrike-10120 -snapshot .candidates/candidate.yaml -configyaml configs/cstrike-10120.yaml -candidate-root .gamedata-candidates/build -session .gamedata-candidates/session.json
uv run python gamedata_candidate.py guard -session .gamedata-candidates/session.json
uv run python gamedata_candidate.py publish -session .gamedata-candidates/session.json -outputdir gamedata/cstrike-10120

uv run python gamesymbol_candidate.py mark -candidate .candidates/candidate.yaml -session .candidates/session.json -step gamedata -gamedata-session .gamedata-candidates/session.json
uv run python gamesymbol_candidate.py publish -candidate .candidates/candidate.yaml -session .candidates/session.json -destination gamesymbols/cstrike-10120.yaml
```

Snapshots can be restored and verified independently:

```console
uv run python gamesymbol_snapshot.py restore -gamever cstrike-10120
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10120
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10120
```

## Analysis contract

Analysis order is fixed: a unique old-version signature, deterministic preprocessor, LLM preprocessor, then Agent
skill. Required and optional artifacts plus explicit prerequisites form one DAG. Unsafe paths, cycles, duplicate or
case-colliding names, missing required inputs, wrong architectures, and binary mutation are fatal.

The flat artifact path is `bin/<tag>/<module>/<symbol>.<platform>.yaml`. Supported categories are `func`, `gv`,
`vfunc`, `vtable`, `patch`, `struct`, and `structmember`. There is no implicit RTTI or generic vtable finder; a
specific skill, historical artifact, or explicit address must provide vtables and vfuncs. x86 virtual-function slots
are four bytes.

See [docs/architecture.md](docs/architecture.md) and [docs/generator-contract.md](docs/generator-contract.md).

## Verification

```console
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

Commercial IDA integration is skipped unless `RUN_IDA_INTEGRATION=1` and an activated `idalib` environment are
available. A skipped integration test is not evidence that real IDA analysis passed.

## Scope

This repository does not include a web service, cache-backed scheduler, UI, C++ layout extraction, automatic version
bumping, hosted release promotion, production symbols, or a target-specific gamedata generator.

Licensed under the [MIT License](LICENSE.md).
