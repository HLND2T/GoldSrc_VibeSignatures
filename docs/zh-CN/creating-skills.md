[返回 README](../../README_CN.md) | [English](../en/creating-skills.md)

# 创建符号分析 skill

符号分析 skill 是在 PE32 或 ELF32 二进制中定位 GoldSrc x86 符号的 IDAPython preprocessor。每个 skill 在
`configs/<GAMEVER>.yaml` 的目标模块 `skills` 列表中注册，声明其 `expected_output` 工件与可选的
`expected_input` 前置依赖。

## `create-preprocessor-scripts`

让 Agent 创建新的 `find-XXXX.py` preprocessor，并在 game-version config 中注册：

```text
/create-preprocessor-scripts Create "find-XXXX" in <MODULE> by xref_strings "<STABLE_ANCHOR>".
```

该 skill 会：

1. 用 CS2 兼容的 `preprocess_common_skill` 入口创建 `ida_preprocessor_scripts/find-XXXX.py`，仅面向 GoldSrc x86。
2. 在每个目标 `configs/<GAMEVER>.yaml` 中注册 skill 与其 `category` symbol（`func`、`gv`、`vfunc`、`vtable`、
   `patch`、`struct` 或 `structmember`）。
3. 为 `LLM_DECOMPILE` 模式生成带注释的 reference YAML 到 `ida_preprocessor_scripts/references/`（参见
   [`LLM_DECOMPILE` reference YAML](reference-yaml.md)）。
4. 校验 Windows/Linux 的 PE32/ELF32 工件。

当用户未指定游戏版本时，该 skill 以 `configs/` 中声明的每个 gamever 为目标，并用
`ida_analyze_bin.py -allgamever -cache_mode cold` 验证。

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

当稳定字符串能够唯一标识所属函数时，使用 `xref_strings`。若同一字符串存在多个代码引用，则增加 include 或
exclude 锚点进行消歧。

### 带 LLM-decompile predecessor 的函数

当目标可通过 predecessor 函数内部的调用、全局变量访问、函数指针、虚调用或结构成员识别时，使用
`LLM_DECOMPILE` 并声明必需的 predecessor reference。

### 通过 expected input 的函数链

把 predecessor 工件声明为 `expected_input`；其 finder 会先运行，依赖 finder 再通过分析 DAG 消费经过验证的
YAML。

### 私有函数与全局变量

定位私有函数时，将稳定的函数内锚点与官方源码交叉引用结合使用。基于 decompile 的 finder 可以消费该函数工件，
继续恢复相关全局变量。在 Windows/Linux 二进制中定位匿名函数、全局变量以及全局变量式指令操作数，参见
`find-anchor-to-goldsrc-symbol` skill。

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
- name: find-XXXX
  expected_output:
    - XXXX.{platform}.yaml
```

Symbol 只使用 `name + category`；拒绝 `type` 与 `kind`。Artifact payload 使用 category 专属 identity
（`func_name`、`gv_name`、`patch_name`、`vtable_class`、`struct_name`/`member_name`），且不要求与 config symbol
name 相等。
