[Back to README](../../README.md) | [中文](../zh-CN/requirements.md)

# Requirements and environment setup

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader), with `depotdownloader.exe` available in `PATH`
3. One supported agent CLI: Claude Code, Codex, or OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib), required by `ida_analyze_bin.py`

Install the Python dependencies after cloning the repository:

```bash
uv sync --locked
```

## Environment variables

Copy `.env.example` to `.env` for a local template. The analyzer uses the GoldSrc-specific `GSVIBE_*` namespace; explicit CLI values override environment values, which override program defaults. Key variables:

- `GSVIBE_AGENT` and `GSVIBE_AGENT_MODEL` select the Agent CLI and model.
- `GSVIBE_LLM_MODEL`, `GSVIBE_LLM_APIKEY`, `GSVIBE_LLM_BASEURL`, `GSVIBE_LLM_TEMPERATURE`, `GSVIBE_LLM_FAKE_AS`, and `GSVIBE_LLM_EFFORT` configure LLM-backed workflows.
- `GSVIBE_PROCESS_REPORTER` (`none`, `console`, or `redis`), `GSVIBE_REDIS_URL`, `GSVIBE_REDIS_PREFIX`, and `GSVIBE_RUN_ID` configure process reporting.
- `GSVIBE_API_HOST`, `GSVIBE_API_PORT`, `GSVIBE_API_CORS_ORIGINS`, `GSVIBE_API_ALLOW_PRIVATE_NETWORK`, `GSVIBE_SSE_BLOCK_MS`, and `GSVIBE_SSE_BATCH_SIZE` configure the read-only Process API.
- `GSVIBE_REFERENCE_GAMEVER` (default `hl-10210`) selects the canonical reference game version for `LLM_DECOMPILE`.
- `DEPOTDOWNLOADER_STEAM_USERNAME` and `DEPOTDOWNLOADER_STEAM_PASSWORD` are read by `download_depot.py` when depot authentication is required.

## IDB cache host requirements

The warm-cache runtime probe requires `python` with `idapro`, `idalib-mcp`, and `IDADIR` on the dedicated runner. The
Python executable must be beside `idalib-mcp` or own the `Scripts` directory containing it. CI queries
`idaapi.get_kernel_version()` through that exact Python installation and uses `IDADIR` to identify the pinned loader
modules and allowlisted plugins. The cache CLI receives an explicit persisted root; CI later exposes it as
`PERSISTED_WORKSPACE` only inside the protected dedicated Windows runner job. That root must be outside the checkout
and `bin/`, must not traverse a reparse point, and must reside on storage that supports atomic same-filesystem rename.

The runner account needs exclusive write access to its cache root. Cache warming is single-concurrency at the scheduler
layer through a repository-wide `idb-warmup-*` concurrency group, and each tag's publish/restore/prune is further
serialized by `<PERSISTED_WORKSPACE>/idb-cache/.locks/<tag>.lock`; a separate local file lock still protects the fixed
MCP port. The byte-range locks must be mutually exclusive across two independent runner processes, not just threads in
one process. A shared cache is valid only when all consumers use the same controlled storage and ACL authority; Actions
artifacts are evidence/selection transport and `READY.json` is a probe hint, never a cache transport or truth source.

Official analysis is unconditionally warm; `GSVIBE_IDB_CACHE_MODE` is not read. Do not enable or dispatch those workflows
until the runner and storage evidence above is complete. No manually maintained IDA-version variable is required. Store
the absolute persisted path as the Environment secret `PERSISTED_WORKSPACE`. The opened runtime must match the
dynamically detected kernel, loader, and plugin identity before publication, so PATH or installation drift fails closed
instead of selecting a cache under a stale configured version.

## Release runner and GitHub governance requirements

The release build runs on the same `[self-hosted, windows, x64]` runner as source analysis. Its protected `win64`
Environment supplies only analysis/runtime secrets and the checkout-external `PERSISTED_WORKSPACE`; the `idb-cache` and
binary-only accepted-cache subtrees require runner-account ACLs and same-filesystem atomic rename support. The build has
read-only repository permission and no PAT, push, tag, or Release authority. PR routing must keep untrusted/fork analysis
off this runner.

Production release dispatch is restricted to `HLND2T/GoldSrc_VibeSignatures` and per-version concurrency. Configure a
separate protected `release` Environment for the GitHub-hosted `publish-release` job; it is the only job granted
`contents: write`. Branch protection requires the unique Actions-owned `pr-validate`, no direct/admin-bypass pushes to
`main`, protected release tags, and the required approval policy for that Environment. No GitHub App token,
`HLND2T_GH_TOKEN`, generated-output branch, or merge-time promotion is part of the release authority. Repository tests
cannot activate or prove these external controls.
