---
title: CASHook server hooks
type: note
permalink: goldsrc-vibesignatures/locators/cashook-server-hooks
tags:
- svencoop
- server
- angelscript
- locator
---

# CASHook server hooks

## 范围与触发信号

Issue #349 Part A：在 Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 PE32/ELF32 `server` 模块增加 CASHook 构造函数与 `Call(int, ...)`，或为后续 AngelScript server finder 复用 map-end 前置函数。

## 已确认 anchors

- 用户明确禁止用函数体签名作为 finder；三个 finder 均传 `old_yaml_map=None`。生成的 `func_sig` 只作 artifacts 输出和唯一性校验。
- `CASHook_CASHook / func`：自身 `FULLMATCH:Hook function`；四个输入各一处精确字符串及一个函数 owner。构造函数在 arguments.docs 为空时使用默认文档，再按 DLL type mask 注册 hook 链表。
- `CASBaseManager_OnMapEnd / func`：自身 `FULLMATCH:Active module was not set to null!\n`；四个输入各一个字符串及函数 owner。作为独立正式 artifacts 输出，允许后续 finder 复用。
- `CASHook_Call / func`：从 OnMapEnd 地图切换 hook 调用经 `LLM_DECOMPILE / found_call` 恢复；required input 是 `CASBaseManager_OnMapEnd.{platform}.yaml`，不按 call ordinal、固定偏移或原版签名定位。
- Linux 5.15 OnMapEnd 调用 `CASHook::Call` 的 PLT `0x190990`；共享 `func_sig_resolve_jmp_thunk:true` 实际解析到 body `0x1ca762`。不能发布 PLT thunk 作为方法入口。

## 版本差异与 ABI

5.15 的地图切换调用为 `g_MapChangeHook.Call(0)`；5.16 在 enabled 分支中构造临时 map-name CString，调用 `g_MapChangeHook.Call(0, &mapName)` 后析构 CString。两个版本分别生成 Windows/Linux reference，共四份，均用 `generate_reference_yaml.py`，不复用旧版参数模型。

Windows constructor 是 MSVC thiscall（this 在 ECX，六个栈实参，ret 0x18）；asext 的 fastcall/unused EDX dummy 是消费方适配。Linux constructor 的 this 和六个实参都在栈上。两平台 `Call(int, ...)` 均为可变参数栈调用，由调用方清栈；Windows 内部向 VCall 转发时把 this 放入 ECX。不要选择 `Call(CBasePlayer*, int, ...)` 重载。

Linux 5.15 实际符号：

- constructor：`_ZN7CASHookC2EhhPKcS1_S1_RK16CASHookArguments`，C1/C2 同址。
- Call：`_ZN7CASHook4CallEiz`。
- predecessor：`_ZN14CASBaseManager8OnMapEndEv`。5.16 的 predecessor 另有 map-name 参数，不能套用此原型。

## 二进制证据

| 输入 | constructor RVA | OnMapEnd RVA | Call RVA | OnMapEnd hook call VA |
| --- | --- | --- | --- | --- |
| 8948 Windows | 0xa28f0 | 0xa3a50 | 0xa2c70 | 0x100a3a7f |
| 8948 Linux | 0x1ca5b0 | 0x1cfa06 | 0x1ca762 | 0x1cfa28 |
| 10257 Windows | 0xa10e0 | 0xa1df0 | 0xa1460 | 0x100a1e41 |
| 10257 Linux | 0x1112e4 | 0x116764 | 0x111496 | 0x116883 |

SHA-256（本地 sha256sum 与 MCP survey 一致）：

- 8948 Windows：`61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849`
- 8948 Linux：`18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643`
- 10257 Windows：`f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0`
- 10257 Linux：`7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca`

源码线索来自 `metamod-fallguys/asext` 的固定 revision `df03faf88e7e547d3f4f84b75ed0385bec5a0678`，文件 `src/signatures.h`、`src/serverdef.h`、`src/meta_api.cpp`；主仓的 `asext` 已变成 submodule。源码只提供线索，四个当前二进制为事实来源。server 私有完整源码未提供；reference 的最小布局和语义名称依据机器码及带符号 5.15 peer，还保留了未知字段、MSVC 内联树清理和 SEH 控制流。

## 根因 / 约束与正确做法

- `CBaseEntity::Create` 不能作为跨版本统一直接 predecessor：5.15 直接调用 Call，5.16 经新增 helper 调用。
- VCall 自身的 hook-id 错误字符串不能直接定位 Call；反向 xrefs 有两个重载。
- 5.16 Windows OnMapEnd 的 SEH prologue 在默认短输出签名预算下不唯一：字符串 discovery 成功，但 helper 移除了无效 func_sig，导致 emit 拒绝。使用已有扩展输出签名预算 `func_sig_allow_across_function_boundary:true`，不增加 discovery 签名。当前四个生成签名实际均在已核验函数体内。
- 强制局部分析用明确的 `-node module:platform:skill` 清单。CLI 的 `-force_all` 不保留 `-modules` 过滤；`-node` 不能同时带 `-modules` 或显式 `-platform`。selected-node 路径本身强制执行，不需要 `-force_all`。

## 验证方式与证据

2026-10-09 对两个 gamever 分别运行六个 `server:windows/linux:find-*` selected nodes（constructor、OnMapEnd、OnMapEnd-decompiles），实际 LLM found_call 在四个平台都选中上表调用指令。每个 tag 的 analyzer summary 为 Successful 6 / Failed 0 / Skipped 0，输出 12 个 production artifacts（8 个 Part A 目标与 4 个 predecessor）。未使用 fake LLM 或手填 artifacts。

复核每个 YAML 的分类身份、VA/RVA/size、唯一 func_sig；生成四份带两视图目标标注的 reference。另以原始 PE32/ELF32 文件独立匹配全部 12 个签名，均唯一命中正确 VA，VA/RVA 一致，签名范围在函数体内。

单元门禁 `tests/run_test_suite.py unit -b --durations 30`：1417 tests，exit 0，9 skips。完整 `tests/run_test_suite.py all -b --durations 30`：1436 tests，exit 0，13 skips（7 个 Windows 专属测试、2 个 opt-in notes CLI 测试、3 个 Redis integration classes 因服务未运行、1 个 opt-in IDA integration）。最后一项 skip 不代替上面的四个真实二进制分析证据。`format_repo_files.py --check`：692 Python / 30 YAML，exit 0；Git diff whitespace 检查无错误。

## 适用范围

仅以上两个 Sven tags 的 x86 server DLL/SO；不用于引擎 RCON globals，不新增 CASHook、CASBaseManager 或 CString 的 struct/global artifacts。所列字段布局仅辅助 IDB/reference 还原，不能替代后续 Part J 的独立结构验证。
