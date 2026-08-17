[返回 README](../../README_CN.md) | [English](../en/reference-yaml.md)

# `LLM_DECOMPILE` reference YAML

`LLM_DECOMPILE` 是 fail-closed 的回退路径，只在确定性 signature 与 xref 路径全部失败后使用。finder 通过接受
`llm_config=None` 并把 `llm_decompile_specs` 与 `llm_config` 传给 `preprocess_common_skill` 来启用。

Reference YAML 文件存放在：

```text
ida_preprocessor_scripts/references/<gamever>/<module>/<func_name>.<platform>.yaml
```

## Prompt 与响应合约

共享 prompt 是 `ida_preprocessor_scripts/prompt/call_llm_decompile.md`。运行时格式化支持
`{reference_blocks}`、`{target_blocks}`、`{symbol_name_list}`、`{platform}`、`{module}`、`{module_name}`。

响应必须是包含全部五个 section 的 canonical YAML mapping：

```yaml
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

每个非空条目必须包含来自导出当前二进制 target 的精确 `insn_va` / `insn_disasm` 对。运行时校验请求的 symbol
identity、允许的 section、指令对、可选指令 regex、vcall 或 struct displacement 与可选 struct size。非法 YAML 或
语义结果会收到有界的纠正请求；只有瞬时传输故障使用指数退避。重试耗尽或不可重试的失败返回完整空结果，
preprocessor 以 fail-closed 结束。

共享 `(model, prompt path, reference paths, temperature)` 的请求会在每个确定性快速路径失败或返回不完整候选后
批量合并。依赖策略与 config input 分类在快速路径前校验；缺失的可选 predecessor 只跳过其 reference/target 对。
func、vfunc、gv 与 structmember 结果仍由普通 x86 MCP helper 消费，它们校验 tail chunks、要求唯一
target/anchor signature、跟随请求的直接调用 jump thunk，并强制 4 字节 vtable slot。

## Canonical reference 游戏版本

`reference_yaml_paths` 条目可以使用 `{gamever}`。运行时解析为当前正在分析的 gamever；当该 reference 文件缺失
时，回退到 canonical reference gamever（`GSVIBE_REFERENCE_GAMEVER`，默认 `hl-10210`）。这让共享的
`hl-*`/`cstrike-*`/`cof-*` family 只保留一个 `hl-10210` reference，而 body 略有差异的 engine（如
`svencoop-10257`）可以提供自己的 `references/svencoop-10257/...` 文件。

当前路径与 canonical 路径都必须解析在 `ida_preprocessor_scripts/references` 之下。canonical gamever 必须是
有效仓库 tag；非法或 path-like 环境值 fail closed，而不会选择 reference 命名空间之外的资源。生成命令必须显式
传入所选 `-gamever`：共享 body 用 canonical gamever，只有确认 per-gamever body 覆盖时才用被分析的 gamever。

## 生成

只允许用 `generate_reference_yaml.py` 或 `generate-reference-yaml` skill 生成 reference YAML。mapping 只包含
`func_name`、`func_va`、`disasm_code`、`procedure`。`disasm_code` 必须非空；`procedure` 必须是字符串。在两个
字段中都标注期望的 call、vcall、global 或 struct 访问。

独立 CLI：

```bash
uv run python generate_reference_yaml.py -gamever hl-10210 -module engine -platform windows -func_name SV_SendServerinfo -mcp_host 127.0.0.1 -mcp_port 13337
```

从 CLI 自动启动 `idalib-mcp`：

```bash
uv run python generate_reference_yaml.py -gamever hl-10210 -module engine -platform windows -func_name SV_SendServerinfo -auto_start_mcp -binary bin/hl-10210/engine/hw.dll
```

`-gamever` 默认取 `GSVIBE_REFERENCE_GAMEVER`，随后可从当前 IDA 二进制路径推断；省略时 `-module` 与
`-platform` 也从二进制路径推断。还支持 `-mcp_database`、`-ida_args`、`-debug`、`-output_filename`。

## 已接入的 reference 文件

仓库现有 reference 包括：

- `references/hl-10210/engine/ClientDLL_Init.{platform}.yaml`
- `references/hl-10210/engine/LoadBlobFile_Caller.{platform}.yaml`
- `references/hl-10210/engine/SV_SendServerinfo.{platform}.yaml`
- `references/svencoop-10257/engine/SV_SendServerinfo.{platform}.yaml`

## 配置示例

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "build_number",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "SV_SendServerinfo.{platform}.yaml": "required",
        },
    },
]
```

合法的结果 section 是 `found_call`、`found_vcall`、`found_funcptr`、`found_gv`、`found_struct_offset`。一个
symbol 使用多个 `reference_yaml_paths`，而不是在多个 specification 中重复同一 symbol。每个被引用工件必须有匹配
的 `dependency_policy` 条目，值为 `required` 或 `optional`；required 工件属于 expected-input 集合，optional
工件属于 optional-input 集合。`required` 依赖放在 config `expected_input`，`optional` 依赖放在
`optional_input`；两个集合不得重叠。

`LLM_DECOMPILE` 使用共享 Analyzer 参数 `-llm_model`、`-llm_apikey`、`-llm_baseurl`、`-llm_temperature`、
`-llm_effort`、`-llm_fake_as`。

## 测试

单元测试注入假文本传输或 mock 批量调用，绝不发送真实网络请求。运行：

```console
uv run python -m unittest -v tests.test_ida_llm_decompile
uv run python -m unittest -v tests.test_ida_skill_preprocessor
uv run python tests/run_test_suite.py repository-contract -b --durations 30
```
