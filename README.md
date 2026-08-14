# GoldSrc VibeSignatures

GoldSrc VibeSignatures is a reproducible Python 3.10+ framework for producing and publishing x86 game-symbol
snapshots. It validates PE32/I386 and ELF32/I386 inputs, executes a dependency-checked analysis graph, records an
immutable candidate, and exposes a strict local contract to downstream gamedata generators.

Production configuration covers Half-Life build 10120, Counter-Strike build 10120, and Sven Co-op build 10257.
Half-Life and Sven Co-op include `engine`, `client`, `gameui`, and `server` modules on Windows and Linux;
Counter-Strike includes `client` and `server`. Half-Life and Sven Co-op register the production finder
`engine/R_RenderView`, anchored by `"R_RenderView: NULL worldmodel"` in `hw.dll` and `hw.so`.

## Setup

```console
uv sync --locked
```

Downloaded depots, binaries, IDA databases, candidates, and generated outputs are ignored. Existing local files below
`bin/svencoop/` are read-only smoke inputs and are never moved or rewritten.

## Workflow

```console
uv run python download_depot.py -tag cstrike-10120 -depotdir depots
uv run python download_depot.py -all -depotdir depots
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform all-platform
uv run python copy_depot_bin.py -gamever cstrike-10120 -platform windows -checkonly
uv run python ida_analyze_bin.py -gamever cstrike-10120 -configyaml configs/cstrike-10120.yaml -platform windows,linux
uv run python ida_analyze_bin.py -gamever hl-10120 -modules engine -skill find-R_RenderView -platform windows,linux -debug
uv run python ida_analyze_bin.py -gamever svencoop-10257 -modules engine -skill find-R_RenderView -platform windows,linux -debug

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

Analysis order is one skill-specific Preprocessor followed by Agent fallback. The Preprocessor runs through a bound IDA
MCP session, may explicitly opt into `llm_config`, and returns `success`, `absent_ok`, `no_script`, or `failed`. Unsafe
raw history copying remains disabled: `-oldgamever` selects the latest older build from the same game family and passes
an old-YAML map to the Preprocessor. A `major_update: true` download entry disables automatic old-version selection.

Required and optional artifacts plus explicit prerequisites form one DAG. Outputs stay module-local; inputs may use a
safe sibling reference such as `../engine/X.{platform}.yaml`, normalized within the game-version root and connected as
a real cross-module DAG edge. Unsafe paths, cycles, duplicate or case-colliding names, missing required inputs, wrong
architectures, and binary mutation are fatal.

The artifact path is `bin/<tag>/<module>/<symbol>.<platform>.yaml`. Config symbols use `name` plus the sole classifier
`category`; `type` and `kind` are rejected. Artifacts reject generic `name/type/kind` and use `func_name`, `gv_name`,
`patch_name`, `vtable_class`, or `struct_name/member_name` according to category. Payload identity is not required to
equal the config symbol name, matching the CS2 loader contract. Supported categories are `func`, `gv`, `vfunc`,
`vtable`, `patch`, `struct`, and `structmember`. Shared primary/ordinal vtable helpers are explicit and fail closed;
Source2-only dispatch protocols are excluded. x86 virtual-function slots are four bytes.

See [docs/architecture.md](docs/architecture.md) and [docs/generator-contract.md](docs/generator-contract.md).

## Analyzer CLI and environment

`ida_analyze_bin.py` uses the CS2-style CLI contract with the GoldSrc-specific `GSVIBE_*` environment namespace.
Explicit CLI values override environment values, which override program defaults. Copy `.env.example` to `.env` for a
local template. The supported environment variables are:

- `GSVIBE_GAMEVER`;
- `GSVIBE_AGENT` and `GSVIBE_AGENT_MODEL`;
- `GSVIBE_LLM_MODEL`, `GSVIBE_LLM_APIKEY`, `GSVIBE_LLM_BASEURL`, `GSVIBE_LLM_TEMPERATURE`,
  `GSVIBE_LLM_FAKE_AS`, and `GSVIBE_LLM_EFFORT`.
- `GSVIBE_PROCESS_REPORTER` (`none`, `console`, or `redis`), `GSVIBE_REDIS_URL`, `GSVIBE_REDIS_PREFIX`, and
  `GSVIBE_RUN_ID`.
- `GSVIBE_API_HOST`, `GSVIBE_API_PORT`, `GSVIBE_API_CORS_ORIGINS`, `GSVIBE_API_ALLOW_PRIVATE_NETWORK`,
  `GSVIBE_SSE_BLOCK_MS`, and `GSVIBE_SSE_BATCH_SIZE` for the read-only Process API.

The analyzer accepts `-configyaml`, comma-separated `-platform` and `-modules`, `-skill`, `-agent`, `-agent_model`, the
matching `-llm_*` arguments, `-maxretry`, `-oldgamever`, `-ida_args`, `-debug`, `-skip_error`, `-skip_pp`,
`-process_reporter`, `-redis_url`, `-redis_prefix`, and `-run_id`. Per-skill `max_retries` overrides `-maxretry`.
`-skip_pp` bypasses the single Preprocessor and runs the Agent directly; `-skip_error` continues after runtime failures
but the final exit status remains nonzero. `-process_reporter=console` emits typed `ProcessEvent` JSONL; `redis` is
best-effort and writes the `gsvibe:analysis:v1` Redis protocol.

Claude and OpenCode load the project skill-runner policies directly. Before using Codex, copy
`.codex/skill_runner.config.toml` to `$CODEX_HOME/skill_runner.config.toml`; the runner selects that profile with
`--profile skill_runner`. Agent retries preserve their CLI session, stream both output pipes, and report structured
attempt failures through the configured progress reporter.

The old `-config`, analyzer `all-platform`, and `-plan-only` spellings are removed without aliases. Generic
`-vcall_finder` is excluded for GoldSrc. Pending work starts one owned `idalib-mcp` lifecycle per binary on
`127.0.0.1:13337`; `-ida_args` appends IDA startup arguments. `-rename` and Source2-only finder semantics remain
excluded. There is no legacy `ProgressEvent`, emit-only reporter, `-console-events`, or legacy output format.

## Process service and dashboard

The analyzer can report a versioned stage/job/task execution graph to Redis. `process_scheduler_cli.py submit` appends a
validated request and `process_scheduler_cli.py run` executes one FIFO analyzer at a time, reclaims stale pending entries,
holds a renewable global Redis lease, tracks heartbeats, and finalizes terminal runs after worker exit. Scheduler recovery
atomically aborts unfinished tasks and recomputes the run summary. The request contract is intentionally minimal:
`run_id`, `gamever`, `platforms`, `modules`, `skill_filter`, `agent`, and `created_at`; the scheduler controls its own argv
and environment.

`process_api.py` is a read-only FastAPI service. It exposes `/healthz`, `/readyz`, run list/detail, execution graph,
snapshot, task, event-page, and SSE stream routes below `/api/v1`. SSE supports `Last-Event-ID` and emits a reset event
when the retained Redis cursor is too old, including when trimming overtakes a live connection; the default live cursor is
anchored to a concrete Stream ID before blocking. The default bind is loopback and there is no built-in authentication; expose it
only behind a trusted private-network boundary and set explicit CORS origins.

The React dashboard in `pages/` consumes this API and also provides a static Symbol Explorer. GitHub Pages publishes only
the static `pages/dist` artifact; it does not host the API/SSE process. The `pages-snapshots` branch is append-only and
stores every content-addressed `<family-build>.<sha256>.json` snapshot. `npm run verify:gamesymbols` and the deployment job
verify exact response bytes and digests.

## Verification

```console
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
```

Pages checks run independently:

```powershell
cd pages
npm ci
npm test
npm run lint
npm run build
npm run verify:gamesymbols
npm run test:e2e
```

Commercial IDA integration is skipped unless `RUN_IDA_INTEGRATION=1` and an activated `idalib` environment are
available. A skipped integration test is not evidence that real IDA analysis passed.

## Scope

This repository includes the Redis-backed process reporter, single-concurrency scheduler, read-only Process API/SSE, and
the React dashboard. Commercial IDA execution still requires the configured local/self-hosted environment; broad symbol
coverage, automatic version bumping, remote API hosting, C++ layout extraction, and target-specific gamedata generators
remain outside this repository's default hosted CI scope.

Licensed under the [MIT License](LICENSE.md).
