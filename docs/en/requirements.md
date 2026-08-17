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

## Initialize the game binaries

Use the `/init-gamebin` slash command to download every depot declared in `download.yaml` with `download_depot.py -all`, then copy the configured binaries into `bin/<tag>/<module>` with `copy_depot_bin.py`. Steam credentials are read from `.env`; without them DepotDownloader prompts interactively.

## Agent skill-runner policies

Claude and OpenCode load the project skill-runner policies directly. Before using Codex, copy `.codex/skill_runner.config.toml` to `$CODEX_HOME/skill_runner.config.toml`; the runner selects that profile with `--profile skill_runner`.

## Troubleshooting

### `error: could not create 'ida.egg-info': access denied`

Run `python py-activate-idalib.py` with administrator privileges from:

```text
C:\Program Files\IDA Professional 9.0\idalib\python
```

### `Could not find idalib64.dll in .........`

Set `IDADIR` for the current shell or add it to the system environment:

```batch
set IDADIR=C:\Program Files\IDA Professional 9.0
```
