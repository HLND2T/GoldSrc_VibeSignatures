---
title: CASDocumentation server registration
type: note
permalink: goldsrc-vibesignatures/locators/casdocumentation-server-registration
tags:
- svencoop
- server
- angelscript
- locator
---

# CASDocumentation server registration

## 范围与触发信号

Issue #349 Part B：在 Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 Windows/Linux x86 `server` 模块定位 CASDocumentation 的十个注册方法。十项全部为独立函数 `server / func`，四个输入均存在方法本体，没有缺失、版本专属或已内联的目标。前置注册函数也单独发布为 func；参考中的注册调用点与字段偏移仅为定位证据，不发布成函数或全局变量。

用户确认了下列具体 anchors 后才实施。finder 不使用旧 artifacts 进行发现（`old_yaml_map=None`）；没有硬编码 VA、调用次序或原版插件签名。输出 `func_sig` 用于验证已发现入口，不参与 discovery。

## 已确认 anchors

四个字符串前置函数：

- `RegisterSCScriptCustomEntityDependencies`：自身 `FULLMATCH:Function definition for custom entity Think functions`，四个输入各一个 owner。
- `RegisterSCScriptColor24`：自身 `FULLMATCH:Color24 structure`，四个输入各一个 owner。
- `RegisterSCScriptOpenFileFlag`：自身 `FULLMATCH:Flags passed to FileSystem::OpenFile.`；排除 `FULLMATCH:Global file system instance`。Windows 同一 flags 文档另被内联进 VFS 注册函数，排除后留下独立 flags helper；Linux 原本只有一个 owner。
- `FULLMATCH:bool isalnum(char character)`：Windows 属于独立的字符注册 helper，描述性身份为 `RegisterSCScriptCharacterFunctions`；Linux 属于真实 `RegisterSCScriptVarious`。两个平台保留不同的前置身份，不能把 Windows helper 冒充完整 Various。

| 方法 | 发现方式 |
| --- | --- |
| RegisterObjectType | CustomEntityDependencies 中注册 CCustomEntityFuncs 的直接调用 |
| RegisterGlobalProperty | 同一前置中注册 CCustomEntityFuncs g_CustomEntityFuncs 的直接调用 |
| RegisterObjectMethod | 同一前置中注册 IsCustomEntity 的直接调用 |
| RegisterFuncDef | 同一前置中注册 void ThinkFunction() 的直接调用 |
| RegisterObjectBehaviour | Color24 中默认 void color24()、behaviour=0 的注册调用 |
| RegisterObjectProperty | Windows 自身 property 诊断；Linux Color24 中 int8 r、offset=0 的注册调用 |
| RegisterGlobalFunction | 字符注册前置中 bool isalnum(char character) 的注册调用；不能选 asSFuncPtr 保存的回调地址 |
| RegisterEnum | OpenFileFlag 中 OpenFile、ENUM_TYPE=0 的注册调用 |
| RegisterEnumValue | Windows 和 Linux 5.16 自身 enum-value 诊断；Linux 5.15 用 OpenFileFlag 中 READ=1 注册调用 |
| SetDefaultNamespace | OpenFileFlag 中设置 OpenFile namespace 的直接调用 |

自身诊断的完整字符串（property 的文本实际写 RegisterMethod）：

```text
CASDocumentation::RegisterMethod: class '%s' not registered prior to property '%s' registration!\n
CASDocumentation::RegisterEnumValue: enum '%s' not registered prior to value '%s' registration!\n
```

Windows 两个诊断均唯一命中各自方法。Linux 两版本 property 诊断没有 IDA 字符串 xrefs；5.15 EnumValue 同样没有记录 xrefs，5.16 EnumValue 有唯一 owner。方法仍存在，不可把 xref 缺失解释为函数不存在。

## 根因 / 约束与正确做法

- Method/Behaviour 的诊断与工作流程相近，字符串不足以区分；使用不同注册语义的直接调用。
- 模块 hook-manager 注册路径中的 RegisterFuncDef 在 Windows 被内联，不能作为独立函数入口 anchor。CustomEntityDependencies 的 ThinkFunction 注册在四个输入都有直接方法调用。
- Windows callback-handler 注册 helper 被内联进 CustomEntityDependencies；Linux 保留单独 helper。用 CCustomEntityFuncs 注册作为跨平台 ObjectType/Method 的语义参照；不要假定内联边界相同。
- Windows 字符注册 helper 与另一个字符串注册 helper 在首 256 字节的 masked 输出签名上碰撞。独立字符串发现已成功，失败发生在输出签名唯一性阶段。只对该前置扩展输出预算到 512/1024 字节，严格限定其函数体；5.15 实际需要 555 字节签名。没有添加 discovery 签名。
- 小型 SDK 转发包装函数的 masked 签名可能需要相邻指令。八个方法 artifacts 明确带 `func_sig_allow_across_function_boundary: true` 且签名实际跨边界：两个版本 Windows 的 ObjectProperty/EnumValue，两个版本 Linux 的 Enum，以及 5.16 Linux 的 GlobalFunction/GlobalProperty。全部对当前完整可执行区域验证唯一命中；这是每个已知二进制的输出签名，不构成跨版本通用 finder anchor。
- 5.15 Linux 注册前置调用 PLT；所有 found_call 输出都启用 `func_sig_resolve_jmp_thunk:true`，最终地址和大小与真实 ELF 方法符号一致。不要发布 PLT trampoline。
- config/文件身份保留 `CASDocumentation_Method`；artifact 的 `func_name` 使用真实 `CASDocumentation::Method(...)` 声明。元数据 helper 只更新已验证 payload 的身份，没有地址发现逻辑。
- repository-contract 的 artifacts 库存检查使用 Git tracked/index paths；新增 artifacts 在磁盘存在但尚未 git add 时会报告 missing。先暂存限定的任务文件再运行该门禁；不能修改测试绕过正式库存契约。

## ABI 与必要布局

Windows 当前机器码为 MSVC thiscall：this 在 ECX，显式参数在栈上，由 callee 清栈；asext 的 `SC_SERVER_DECL` fastcall 加 dummy EDX 是消费方适配。Linux 为 i386 Itanium/C++、cdecl 栈调用，this 是首个栈参数，由调用方清栈。

Linux ELF 的 flags/callConv 使用 `unsigned long`（i386 为 4 字节）；Windows 对应 `unsigned int`（4 字节）。`asSFuncPtr const&` 是指针参数，引用对象 flag 的已核验偏移为 Windows +32 / Linux +28（最小参考 storage 总大小分别 36/32）。局部 IDB 类型保留已观测 CASDocumentation 字段：Windows collectDoc+32 / engine+36 / defaultNamespace+40，Linux +28 / +32 / +36。这些是不完整的参考布局，没有发布 struct 或 global artifacts，也不替代 Part J 的 CASServerManager 结构验证。

完整私有 server 源码与可用 DWARF 未提供。参考原型及局部类型依据当前机器码、带符号 5.15 peer 与消费方 SDK；未知字段保留未知，保留 MSVC 内联/SEH 和 Linux asSFuncPtr 初始化循环。Windows 中脚本注册名为 CCustomEntityFuncs，原生回调名称依据 ELF peer 标注为 CASCustomEntityFuncs；stripped singleton helper 使用描述性 GetCustomEntityFuncsInstance，不伪称可见导出符号。

## 二进制证据

下表均为函数本体 RVA；PE imagebase=0x10000000，ELF imagebase=0：

| 方法 | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
| --- | --- | --- | --- | --- |
| RegisterObjectType | 0xa82c0 | 0x1d2918 | 0xaba00 | 0x11990a |
| RegisterObjectProperty | 0xa84e0 | 0x1d2ff0 | 0xabc10 | 0x11a0ea |
| RegisterGlobalProperty | 0xa8160 | 0x1d285c | 0xab8b0 | 0x119732 |
| RegisterGlobalFunction | 0xa8110 | 0x1d27f4 | 0xab860 | 0x1196bc |
| RegisterObjectMethod | 0xa8390 | 0x1d2dd8 | 0xabad0 | 0x119ea6 |
| RegisterObjectBehaviour | 0xa8430 | 0x1d2ed4 | 0xabb60 | 0x119fb8 |
| RegisterFuncDef | 0xa86f0 | 0x1d2ab2 | 0xabe20 | 0x119bf2 |
| RegisterEnum | 0xa8570 | 0x1d29e0 | 0xabca0 | 0x1199f8 |
| RegisterEnumValue | 0xa85d0 | 0x1d3128 | 0xabd00 | 0x119a64 |
| SetDefaultNamespace | 0xa80e0 | 0x1d27b8 | 0xab830 | 0x11967c |

Linux 5.15 实际符号：

```text
_ZN16CASDocumentation18RegisterObjectTypeEPKcS1_im
_ZN16CASDocumentation22RegisterObjectPropertyEPKcS1_S1_i
_ZN16CASDocumentation22RegisterGlobalPropertyEPKcS1_Pv
_ZN16CASDocumentation22RegisterGlobalFunctionEPKcS1_RK10asSFuncPtrmPv
_ZN16CASDocumentation20RegisterObjectMethodEPKcS1_S1_RK10asSFuncPtrm
_ZN16CASDocumentation23RegisterObjectBehaviourEPKcS1_13asEBehavioursS1_RK10asSFuncPtrmPv
_ZN16CASDocumentation15RegisterFuncDefEPKcS1_
_ZN16CASDocumentation12RegisterEnumEPKcS1_NS_9ENUM_TYPEE
_ZN16CASDocumentation17RegisterEnumValueEPKcS1_S1_i
_ZN16CASDocumentation19SetDefaultNamespaceEPKc
```

Linux 5.16 私有方法名称已 stripped；分别以调用语义、方法体中 SDK 注册 slot、实参流与 5.15 有符号 peer 对应，不从单版本地址推算。

四个二进制 SHA-256（本地 sha256sum 和 MCP survey 一致）：

- 8948 Windows：`61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849`
- 8948 Linux：`18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643`
- 10257 Windows：`f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0`
- 10257 Linux：`7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca`

用户要求的本地完整 clone 在 `~/metamod-fallguys`，recursive submodules。主仓 revision `c719f3fa3cbdaac07853e15667783afb7a943821`；asext revision `df03faf88e7e547d3f4f84b75ed0385bec5a0678`。源码仅作参考，四个当前二进制为事实来源。

## 验证方式与结果

2026-10-09，两个 tags 的 deterministic caller 节点各 Successful 2 / Failed 0 / Skipped 0。后续真实 LLM found_call 和诊断节点：8948 Successful 9 / Failed 0 / Skipped 0；10257 Successful 10 / Failed 0 / Skipped 0。未使用 fake LLM 或手填目标 artifacts。

两个版本确有不同前置函数体，为每个 tag 的四个前置、两个平台分别通过 `generate_reference_yaml.py` 生成 references，共 16 份。每份严格四字段，disasm_code/procedure 双视图标注方法。复查 Windows 原生回调名称之后，对两个版本的 CustomEntityDependencies Windows 节点各再执行一次（Successful 1 / Failed 0）。references 的最终文本使用 generator serializer，仅格式改变、payload 不变。

产物共 40 个方法 artifacts + 16 个前置 artifacts。对原始 PE 可执行 sections / ELF 可执行 LOAD segments 独立扫描全部 56 个签名，均唯一命中预先独立核验的 VA，VA/RVA 一致；10 个 Linux 5.15 方法的名称与 size 同 readelf/c++filt 完全吻合。单独核对 16 份 references 地址和双视图标注。全 server 模块流程两个 tags exit 0、Failed 0；已有有效 artifacts 被复用，8948 Skipped 17 / 10257 Skipped 18，不能把该复用统计冒充新的 finder 执行证据。

复现命令：

```bash
uv run python ida_analyze_bin.py -gamever svencoop-8948 -modules server -platform windows,linux -oldgamever none -debug
uv run python ida_analyze_bin.py -gamever svencoop-10257 -modules server -platform windows,linux -oldgamever none -debug
```

强制重新发现时，用明确 `-node server:windows/linux:<skill>` 清单；不能与 `-modules` 或 `-platform` 同用。新前置先运行 caller finder，再导出 references，再运行 decompile finders。

质量门禁：

- `format_repo_files.py --check`：699 Python、30 YAML，exit 0。
- `tests/run_test_suite.py unit -b --durations 30`：1417 tests，exit 0，9 skips。
- `tests/run_test_suite.py repository-contract -b --durations 30`：15 tests，exit 0（新增 artifacts 暂存后）。
- `tests/run_test_suite.py all -b --durations 30`：1436 tests，exit 0，13 skips（Windows 专属、opt-in notes CLI、未启用 Redis、opt-in IDA integration；真实二进制分析另已执行）。
- Git diff whitespace 检查无错误。

## 适用范围

仅上述四个 x86 server 输入。保持既有 Part A 覆盖；没有 asext/fallguys hook 改动，没有独立 global、callsite 或派生 offset artifacts。Part B 十个目标全部覆盖；其他 issue 部分不由此工作宣称完成。
