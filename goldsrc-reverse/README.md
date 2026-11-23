# goldsrc-reverse: Debug-Symbol + IDA-MCP Gamedata Generator

Automatically generates `GoldSrc_VibeSignatures`-contract per-symbol YAML artifacts (and optional Schema-5 gamedata JSON catalogs) for self-built or symbol-bearing GoldSrc binaries that ship with **PDB (Windows PE)** or **ELF `.symtab` + DWARF (Linux ELF)** debug information, combining direct offline debug-symbol lookup with the repository's native IDA-MCP signature engine.

## Directory Layout

- `generate_gamedata.py`: Main CLI entry point coordinating offline debug-symbol indexing, IDA-MCP signature generation, and gamedata JSON export.
- `debug_providers.py`: Offline symbol and type-layout indexing layer for PDB (`llvm-pdbutil` + `llvm-readobj` + `llvm-undname`) and ELF/DWARF (`llvm-readelf` + `c++filt` + `llvm-dwarfdump`).
- `configs/svencoop-10257.engine.yaml`: External module-level extraction configuration (symbol aliases, global struct prefixes, nested field paths, callsite mappings, and external patch preprocessor rules; automatically discovered from `configs/<gamever>.<module>.yaml` when `--module-config` is omitted).

## Quick Start

### 1. Offline Dry-Run Probe (No IDA Required; Fast Coverage Check)

```bash
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --pdb "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.pdb" \
  --module-config goldsrc-reverse/configs/svencoop-10257.engine.yaml \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --dry-run
```

### 2. Full Generation (Auto-Launches `idalib-mcp` or Attaches via `--mcp-port`)

```bash
# Windows (hw.dll + hw.pdb), also exporting upstream Schema-5 gamedata.json + Schema-4 index.json
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --pdb "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.pdb" \
  --module-config goldsrc-reverse/configs/svencoop-10257.engine.yaml \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/svencoop-10257/gamedata.json

# If per-symbol YAMLs already exist, use --export-only to export gamedata.json + index.json without starting IDA
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/svencoop-10257/gamedata.json \
  --export-only

# Export directly in MetaHookSv pruned runtime format (<gamever>.json + index.json), ready to drop into metahook/gamedata/<custom-subdir>/
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/metahook-gamedata \
  --gamedata-format metahook \
  --export-only

# Optionally filter symbols against a MetaHookSv host or plugin manifest via --metahook-manifest
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/metahook-gamedata-host \
  --gamedata-format metahook \
  --metahook-manifest "D:\MetaHookSv\MetaHook\scripts\manifests\metahook.json" \
  --export-only

# Linux (DWARF-enabled hw.so; omitting --module-config auto-loads configs/svencoop-10257.engine.yaml)
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\linuxdbg\hw.so" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine
```

If a shared local `ida-pro-mcp` instance is already running (for example on `127.0.0.1:13337`), pass `--mcp-port 13337` to reuse it directly.

## Supported Categories and Limitations

- **Auto-generated**: `func`, `gv`, `vtable`, `vfunc` (both pure virtual interface slots and concrete overrides), `structmember`, `scalar`, `<Caller>_to_<Callee>_callsite_N`, explicit callsites listed under `patch_callsites`, and specialized patch preprocessors declared under `patch_preprocessors` (such as `Sys_InitMemory_HeapLimitPatches_*` and `VGUIClient001_CreateInterface`).
- **Skipped and reported**: Any remaining non-callsite instruction-level special patches not registered under `patch_preprocessors` (such as `vgui2_Panel_SetSize_Const_callsite_*`) are marked `skipped` in the report and can be enabled on demand by adding an entry to `patch_preprocessors` in the external module config.
