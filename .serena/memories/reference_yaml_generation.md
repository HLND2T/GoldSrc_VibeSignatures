# LLM_DECOMPILE Reference YAML Generation

## 触发信号

- 新建或更新 Pattern C/D/E finder，需要 `reference_yaml_paths`。
- predecessor artifact 尚未生成，或需刷新带 IDA/Hex-Rays 上下文的 reference。

## 根因 / 约束

- reference 路径跨 gamever 共享；不得按所有版本反复覆盖。
- 输出固定且仅含 `func_name`、`func_va`、`disasm_code`、`procedure`；地址限 x86，disassembly 非空。
- 仅支持 PE32/I386 与 ELF32/I386；attach/auto-start 都必须验证 bound IDB identity。
- auto-start 必须使用仓库 `IdaMcpLifecycle`，且 `-binary` 必须等于 config 声明的 binary。
- Windows/Linux 共用 owned MCP host/port，必须串行；只处理 selected config 实际声明的平台。

## 正确做法

- 唯一生成入口：`.claude/skills/generate-reference-yaml/SKILL.md` + `generate_reference_yaml.py`；不手写初始 YAML、不直接调用 IDA API。该 backend skill 的 `policy.allow_implicit_invocation` 为 false，由上层流程显式调用。
- `REFERENCE_GAMEVER` 强制来自 `.env` 的 `GSVIBE_REFERENCE_GAMEVER`（当前 `hl-10210`）；缺失或为空即停止，不做自动选择，也不回退到用户命名版本。校验 `configs/<tag>.yaml` 存在且声明 predecessor module；两平台均声明时必须由同一 `REFERENCE_GAMEVER` 提供。
- 新 predecessor：注册 deterministic predecessor/downstream scripts → predecessor-only analyzer 运行 `<SUPPORTED_PLATFORMS>` → 各支持平台串行 generate → 同步注释 `disasm_code` 与 `procedure` → downstream/full validation。
- regeneration 后以 Git removed lines 恢复仍有效的注释，不凭记忆重建。

## 验证方式

- `uv run python -m unittest -v tests.test_generate_reference_yaml`
- `uv run python tests/run_test_suite.py unit -b --durations 30`
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`
- 两个相关 skill 均通过 `skill-creator/scripts/quick_validate.py`；再运行 `generate_reference_yaml.py -h` 和 `git diff --check`。

## 适用范围

- GoldSrc x86 的 LLM_DECOMPILE Patterns C/D/E reference 生成与 create-preprocessor-scripts 工作流。
