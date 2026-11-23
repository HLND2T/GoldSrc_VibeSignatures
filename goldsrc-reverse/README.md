# goldsrc-reverse: Debug-Symbol + IDA-MCP Gamedata Generator

针对自带 **PDB（Windows PE）** 或 **ELF `.symtab` + DWARF（Linux ELF）** 的自编译/带符号 GoldSrc 二进制，利用调试符号直查定位 + 仓库原生 IDA-MCP 签名引擎，自动生成符合 `GoldSrc_VibeSignatures` 契约的 per-symbol YAML 产物。

## 目录结构

- `generate_gamedata.py`：主入口 CLI，驱动离线符号索引与 IDA-MCP 签名/契约输出。
- `debug_providers.py`：PDB（`llvm-pdbutil` + `llvm-readobj` + `llvm-undname`）与 ELF/DWARF（`llvm-readelf` + `c++filt` + `llvm-dwarfdump`）离线索引层。
- `configs/svencoop-10257.engine.yaml`：外置的模块级提取配置（符号别名、全局结构体前缀、嵌套字段路径、callsite 映射及外部预处理脚本规则；未传入 `--module-config` 时自动按 `configs/<gamever>.<module>.yaml` 发现加载）。

## 快速使用

### 1. 纯离线探测（不启动 IDA，秒级验证映射覆盖率）

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

### 2. 完整生成（自动启动 `idalib-mcp` 或挂载已有 `--mcp-port`）

```bash
# Windows (hw.dll + hw.pdb)，同时导出 Schema-5 gamedata.json + Schema-4 index.json
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --pdb "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.pdb" \
  --module-config goldsrc-reverse/configs/svencoop-10257.engine.yaml \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/svencoop-10257/gamedata.json

# 如已存在 YAML 目录，可用 --export-only 直接导出 gamedata.json + index.json（不启动 IDA）
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/svencoop-10257/gamedata.json \
  --export-only

# 直接导出 MetaHookSv 运行时裁剪格式（<gamever>.json + index.json），可直接放入 metahook/gamedata/<自定义子目录>/
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\win32dbg\Release\hw.dll" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine \
  --emit-gamedata-json .tmp/goldsrc-reverse-out/metahook-gamedata \
  --gamedata-format metahook \
  --export-only

# 如需按 MetaHook 宿主或插件 manifest 进一步裁剪符号，可额外传入 --metahook-manifest
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

# Linux (带 DWARF 的 hw.so；省略 --module-config 时自动加载 configs/svencoop-10257.engine.yaml)
uv run python goldsrc-reverse/generate_gamedata.py \
  --config configs/svencoop-10257.yaml \
  --module engine \
  --binary "D:\goldsrc-reverse\reports\re-agent\svencoop-engine-10257\linuxdbg\hw.so" \
  --output-dir .tmp/goldsrc-reverse-out/svencoop-10257/engine \
  --reference-dir bin_artifacts/svencoop-10257/engine
```

如果本地已启动共享 `ida-pro-mcp`（如 `127.0.0.1:13337`），可传入 `--mcp-port 13337` 直接复用。

## 支持类别与局限

- **自动生成**：`func`、`gv`、`vtable`、`vfunc`（含纯虚接口与具体实现）、`structmember`、`scalar`、`<Caller>_to_<Callee>_callsite_N`、模块配置 `patch_callsites` 登记的 callsite，以及 `patch_preprocessors` 声明的专用预处理脚本补丁（如 `Sys_InitMemory_HeapLimitPatches_*`、`VGUIClient001_CreateInterface`）。
- **跳过并报告**：未在 `patch_preprocessors` 中登记的其余非 callsite 特殊补丁（如 `vgui2_Panel_SetSize_Const_callsite_*`），在报告中标记为 `skipped`，可按需添加到外置模块配置 `patch_preprocessors` 中自动加载。
