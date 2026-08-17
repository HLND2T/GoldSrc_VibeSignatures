[返回 README](../../README_CN.md) | [English](../en/creating-skills.md)

# 创建符号分析 skill

符号分析 skill 是在 PE32 或 ELF32 二进制中定位 GoldSrc x86 符号的 IDAPython preprocessor。每个 skill 在
`configs/<GAMEVER>.yaml` 的目标模块 `skills` 列表中注册，声明其 `expected_output` 工件与可选的
`expected_input` 前置依赖。

## `create-preprocessor-scripts`

让 Agent 创建新的 `find-XXXX.py` preprocessor，并在 game-version config 中注册：

```text
/create-preprocessor-scripts Create "find-R_RenderView" in engine by xref_strings "R_RenderView: NULL worldmodel".
```

该 skill 会：

1. 用 CS2 兼容的 `preprocess_common_skill` 入口创建 `ida_preprocessor_scripts/find-XXXX.py`，仅面向 GoldSrc x86。
2. 在每个目标 `configs/<GAMEVER>.yaml` 中注册 skill 与其 `category` symbol（`func`、`gv`、`vfunc`、`vtable`、
   `patch`、`struct` 或 `structmember`）。
3. 为 `LLM_DECOMPILE` 模式生成带注释的 reference YAML 到 `ida_preprocessor_scripts/references/`（参见
   [`LLM_DECOMPILE` reference YAML](reference-yaml.md)）。
4. 校验 Windows/Linux 的 PE32/ELF32 工件。

当用户未指定游戏版本时，该 skill 以 `configs/` 中声明的每个 gamever 为目标，并用
`ida_analyze_bin.py -allgamever` 验证。

## Finder/helper API

Preprocessor 调用共享 helper：

```python
async def preprocess_common_skill(
    session,
    expected_outputs,
    old_yaml_map=None,
    llm_decompile_specs=None,
    llm_config=None,
):
```

共享 GoldSrc x86 helper 保持 CS2 Finder API，覆盖 func/vfunc、GV、patch、structmember、primary/ordinal vtable、
继承 slot、xref filter 与受验证的 LLM fallback。preprocessor 只有显式声明 `llm_config` 才会收到 LLM runtime 配置。

## Finder 模式

### 带字符串锚点的普通函数

`find-R_RenderView` 通过 `hw.dll` / `hw.so` 中的 `"R_RenderView: NULL worldmodel"` 定位
`engine/R_RenderView`。`find-SV_SendServerinfo` 用同一模式定位 `SV_SendServerinfo`。

### 带 LLM-decompile predecessor 的函数

`find-build_number` 使用 `LLM_DECOMPILE`，以必需的 `SV_SendServerinfo.{platform}.yaml` reference 把
`build_number` 定位为 predecessor 内部被调用的函数。

### 通过 expected input 的函数链

`find-NLoadBlobFile` 把 `find-NLoadBlob` 声明为 `expected_input`；前置 finder 先定位 `NLoadBlob`，再定位
依赖它的函数。`find-FreeBlob` 使用相同的链式模式。

### 私有 engine 函数

`find-Sys_Error`、`find-ClientDLL_Init`、`find-DispatchDirectUserMsg`、`find-Cvar_DirectSet` 通过稳定的函数内
字符串锚点与官方源码交叉引用定位私有 engine 函数。在 `hl-*` 或 `svencoop-*` Windows/Linux 二进制中定位匿名函数、
全局变量以及全局变量式指令操作数，参见 `find-anchor-to-goldsrc-symbol` skill。

## Signature 生成 skill

在 IDA 中定位并重命名符号后，用 `write-*-as-yaml` 系列 skill 持久化结果（`write-func-as-yaml`、
`write-vfunc-as-yaml`、`write-globalvar-as-yaml`、`write-patch-as-yaml`、`write-structoffset-as-yaml`、
`write-vtable-as-yaml`）。用 `generate-signature-for-function`、`generate-signature-for-globalvar`、
`generate-signature-for-patch`、`generate-signature-for-structoffset`、`generate-signature-for-vfuncoffset` 与
`get-vtable-index` / `get-vtable-address` 生成并校验字节 signature。Preprocessor 与 Agent 产物经过同一层 YAML、
symbol schema 与当前 IDB 地址校验。

## 在 config 中注册 skill

已注册的 skill 条目形如：

```yaml
- name: find-Sys_Error
  expected_output:
    - Sys_Error.{platform}.yaml
```

Symbol 只使用 `name + category`；拒绝 `type` 与 `kind`。Artifact payload 使用 category 专属 identity
（`func_name`、`gv_name`、`patch_name`、`vtable_class`、`struct_name`/`member_name`），且不要求与 config symbol
name 相等。
