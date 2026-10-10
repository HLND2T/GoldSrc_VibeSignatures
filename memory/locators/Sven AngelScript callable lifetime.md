---
title: Sven AngelScript callable lifetime
type: note
permalink: goldsrc-vibesignatures/locators/sven-angel-script-callable-lifetime
tags:
- svencoop
- server
- angelscript
- locators
---

# Sven AngelScript callable lifetime

## Overview
Issue #349 Part D 覆盖 server 模块的五个普通函数，支持 svencoop-8948 (5.15) 和 svencoop-10257 (5.16) 的 Windows PE32 / Linux ELF32。用户已确认全部 anchor。未实现消费方 hook；五个函数在四个目标中均独立存在，无缺失或内联导致的未覆盖项。

## Responsibilities
- 通过当前二进制自身语义定位，保留 consumer artifact stem，func_name 使用真实 C++ 方法 identity。
- 三个直接 body anchors 各共用三条 pattern；Array Release 和 variadic Call 使用唯一 caller 字符串 + 真实 LLM found_call + 机器码验证。
- 所有输出均为 func；caller 的 call 指令是定位证据，GOT slot 是解析步骤，字段偏移是 reference 中的派生布局，均不冒充独立全局变量或目标函数。

## Involved Files & Symbols
- ida_preprocessor_scripts/find-AS-reference-counted-callable-bodies.py — CASRefCountedBaseClass_InternalRelease / CScriptAny_Release / CASFunction_Create。
- ida_preprocessor_scripts/find-AS-callable-predecessors.py — CClassicMode_SetItemMappings，Windows CASReflection_GetReturnValue，Linux CASConCommandSystem_VisitClientCommand。
- ida_preprocessor_scripts/find-CClassicMode_SetItemMappings-decompiles.py — CScriptArray_Release。
- ida_preprocessor_scripts/find-CASBaseCallable_Call-decompiles.py — CASBaseCallable_Call。
- as_callable_artifacts.py — 经验证 artifact 的实际函数 identity。
- ida_elf.py / ida_analyze_util.py — ELF32 EBX-relative .plt.got fallback。
- configs/svencoop-8948.yaml / configs/svencoop-10257.yaml — server DAG 与 symbols。
- bin_artifacts/svencoop-*/server/ — 本部分新增 28 份 artifacts（20 份目标，8 份 supporting callers）。
- ida_preprocessor_scripts/references/svencoop-*/server/ — 本部分新增 8 份 reference，均由 generate_reference_yaml.py 导出，再标注 disasm / procedure。

## Architecture

### Current-binary target evidence
Windows imagebase 0x10000000；Linux imagebase 0。以下为实际函数 VA，不是 caller 或 thunk VA。

| func_name | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
| --- | --- | --- | --- | --- |
| CASRefCountedBaseClass::InternalRelease() const | 0x100cbd30 | 0x2210ac | 0x100cb220 | 0x16d35c |
| CScriptAny::Release() const | 0x1032c830 | 0x1a35b8 | 0x103482c0 | 0xe10f0 |
| CScriptArray::Release() const | 0x1032db50 | 0x1a8786 | 0x10349570 | 0xe7812 |
| CASBaseCallable::Call(int, ...) | 0x100cd8a0 | 0x220ec6 | 0x100cce60 | 0x16d170 |
| CASFunction::Create(asIScriptFunction*, CASModule*, bool) | 0x100cfe70 | 0x222764 | 0x100cf570 | 0x16eafc |

5.15 ELF identity:
- _ZNK22CASRefCountedBaseClass15InternalReleaseEv
- _ZNK10CScriptAny7ReleaseEv
- _ZNK12CScriptArray7ReleaseEv
- _ZN15CASBaseCallable4CallEiz
- _ZN11CASFunction6CreateEP17asIScriptFunctionP9CASModuleb

### Anchors
- InternalRelease: 非原子递减当前子对象 +0 的 count，然后返回是否为零。Windows 完整七字节 83 01 FF 0F 94 C0 C3；Linux 两种 body 从 this load 之后开始。Windows 必须验证唯一匹配、精确入口和七字节函数边界，避免 generic owner backtracking 被邻近 CALL entries 干扰。
- Any Release: 清 gcFlag，asAtomicDec(refCount)，非零路径读取剩余 count；独立于 Array 的返回值/布局。
- Create: bool 参数为真时通过 asIScriptFunction vtable +8 释放输入引用，再返回新 CASFunction；同时核验空输入、分配/构造及引用获取路径。
- Array Release: SetItemMappings 旧数组释放和错误类型输入释放，两调用必须指向同一 Release body。own literal 为 CClassicMode::SetItemMappings: Invalid array type passed! 加换行。
- Call: Windows CASReflection::GetReturnValue 创建 CASMethod assignment callable，设置 returnDestination 后调用；唯一 own literal 为 no assignment operator found for type '%s::%s'。Linux Visit 检查 invoking player / plugin admin rights 后调用 command callback；own literal 为 You do not have rights needed to use this command 加换行。保留实际字符串里的 CASCPPReflection 名称，但 ELF source class 名为 CASReflection。

### ABI / necessary partial layout
- InternalRelease 返回 bool，需要引用计数基类子对象的 this。该子对象 count 为 +0；CASBaseCallable 内联使用的 count 为整体对象 +4。函数本体不调用 asGetActiveContext()，不能据 issue 备注省略 this 或传入整个 vptr 地址。
- Any Release 返回 int。Windows 原生 ECX this（消费方 fastcall adapter 的 dummy EDX 不属于函数实际参数），refCount +8 / gcFlag +12；Linux cdecl 栈 this，refCount +4 / gcFlag +8。
- Array Release 返回 void。Windows ECX this；Linux cdecl 栈 this。两平台观察到 refCount +4 / gcFlag +8；零计数后 virtual destructor 与 userFreeSA。
- BaseCallable Call 返回 bool，两个平台均在栈上传 this、固定 int 和 variadic args。与 Call(int, va_list) overload 区分。
- Function Create 为 static factory / cdecl，没有 this。bool 控制输入 script-function 引用释放；新对象分配 20 bytes。
- Reference partial fields: CClassicMode.itemMappings +8；Windows CASMethod.returnDestination +20；Linux CASClientCommand.callback +128 / pluginName +152，visit state.commandArguments +0 / status +4。只恢复已使用字段，未产出独立 structmember/global artifacts。

## Dependencies
- preprocess_common_skill，真实 LLM_DECOMPILE / found_call 验证，generate-reference-yaml / reverse-engineer-goldsrc-function。
- 当前目标二进制优先于 D:/metamod-fallguys 源码线索。复用已有 server 模块与 helper 约定。
- [[CASHook server hooks]]，[[idalib-mcp]]。

## Notes

### Windows Any caller misidentification
触发信号：asext 的 CScriptAny_Release caller pattern 指向与 CScriptArray_Release 相同的函数。
根因：consumer 字段名与真实被调用函数不一致。
正确做法：用 count/gcFlag 布局、返回剩余 count 的路径、构造/RTTI/vtable 与 ELF peer 独立确认 Any；Array 通过 SetItemMappings 的所有权流确认。
验证：四个函数地址与各自 layout 已独立核对；输出 func_name 分别为 CScriptAny::Release() const / CScriptArray::Release() const。
适用范围：上述四个 server 输入。

### ELF32 .plt.got with missing thunk target
触发信号：5.15 SetItemMappings 调用 0x192900，而 calc_thunk_func_target 返回 BADADDR。
根因：6-byte FF A3 disp32 使用 EBX 相对 GOT，IDA 没有 stub -> slot data xref。GOT[0] 的 _DYNAMIC 位于 LOAD segment，未单独命名 .dynamic。
正确做法：严格限制 ELF32 风格 .plt.got 六字节 thunk；GOT[0] 定位 dynamic entries，DT_PLTGOT 必须唯一且等于 .got.plt base；signed disp 定位 .got/.got.plt 槽，要求完整加载、loader code-pointer data ref、可执行且精确的非 PLT 目标入口。证据缺失或歧义则保持未解析。
实例：base 0x8b0000，disp -0x6a4，slot 0x8af95c，目标 0x1a8786。这里只解析目标函数，不输出该槽为 global。
验证：真实 IDA fallback 及 LLM downstream 解析成功；shared tests 覆盖错误 opcode/architecture/dynamic/GOT segment/pointer/reference/entry 与 non-executable target 的拒绝。
适用范围：加载后已解析的 ELF32 i386 .plt.got，不猜测任意 PIC register，也不处理 lazy unresolved slots。

### Validation evidence (2026-10-10)
- 四个 finder × 四个二进制，最终执行均 successful，failed 0；LLM 为真实 deepseek-flash 请求，schema/semantic validation 无错误。
- 原始二进制可执行段扫描：28 份 func_sig 均唯一，20 个目标 VA 与独立定位表一致。
- uv run python tests/run_test_suite.py unit -b --durations 30：1419 tests，OK，skipped 5。
- uv run python format_repo_files.py --check：通过。
- uv run python tests/run_test_suite.py repository-contract -b --durations 30：暂存全部 artifacts 后 15 tests，OK。
- Artifact contract 要求 Git tracked inventory；新 artifacts 必须先 git add 再跑 repository-contract。未暂存时的 tracked inventory mismatch 不等于机器码定位失败。

### Binary SHA256
- svencoop-8948/server/server.dll: 61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849
- svencoop-8948/server/server.so: 18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643
- svencoop-10257/server/server.dll: f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0
- svencoop-10257/server/server.so: 7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca

Owned IDBs 已按 idb_open -> idb_close(save=True) 原位保存到 bin/<tag>/server/server.dll.i64 / server.so.i64；仅修改分析 metadata，没有 patch 原始二进制。IDA 类型恢复仍保留非目标 SDK virtual calls、编译器内联及匿名 logging helper，不将这些猜测为新 symbols。

## Callers
- CClassicMode::SetItemMappings -> CScriptArray::Release（old mappings / rejected array）。
- CASReflection::GetReturnValue -> CASBaseCallable::Call（Windows assignment callable）。
- CASConCommandSystem::Visit(CASClientCommand&, void*) -> CASBaseCallable::Call（Linux command callback）。
