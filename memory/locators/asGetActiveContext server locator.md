---
title: asGetActiveContext server locator
type: note
permalink: goldsrc-vibesignatures/locators/as-get-active-context
tags:
- svencoop
- server
- angelscript
- locators
---

# asGetActiveContext server locator

## 范围与触发信号

Issue #349 Part F。在 Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 PE32/ELF32 `server` 模块新增 C-linkage AngelScript SDK 访问器 `asGetActiveContext()`，供 asext/fallguys 之类消费方解析当前脚本上下文。

## 已确认 anchor

- 目标：`server` / `func`，artifact stem `asGetActiveContext`，`func_name` 为 C 名 `asGetActiveContext`（无 mangling）。
- 该函数无参数、无字符串、无浮点常量，只有一条源码语句可锚定：
  `return tld->activeContexts[tld->activeContexts.GetLength()-1];`
  （`asCThreadLocalData` 的 `+0` 为 active-context 数组指针、`+4` 为元素 count，为 AngelScript SDK 固定布局，两个 Sven 构建一致）。
- 采用**函数体不变量**（`find-anchor-to-goldsrc-symbol` step 3 code signature，起点在 count 载入、终点在末尾索引载入，**非函数头/prologue**）：
  - Windows (MSVC，count 装 ecx)：`8B 48 04 85 C9 74 ?? 8B 00 8B 44 88 FC`
  - Linux (Itanium，count 装 edx)：`8B 50 04 85 D2 74 ?? 8B 00 8B 44 90 FC`
- 两条签名即覆盖全部 4 个目标，远低于仓库 ≤4 签名预算。finder 传 `old_yaml_map=None`。

### 关键版本差异（决定了按平台而非按版本分签名）

- metamod-fallguys 的 `asGetActiveContext_Signature` 只命中 10257（两个平台），在 **8948 两平台 0 命中**，不可跨版本复用。
- 同一末尾索引语句，**8948 两平台用 edx，10257 两平台用 ecx**（编译器族内稳定）：PE32 用 ecx，ELF32 用 edx。因此按平台选签名，两个签名覆盖四目标。

## 二进制证据

| 输入 | func_va | func_rva | func_size | 不变量命中 VA |
| --- | --- | --- | --- | --- |
| 8948 Windows | 0x10059670 | 0x59670 | 0x1a | 0x10059679 |
| 8948 Linux | 0x626ae8 | 0x626ae8 | 0x31 | 0x626b00 |
| 10257 Windows | 0x10053220 | 0x53220 | 0x1a | 0x10053229 |
| 10257 Linux | 0x5f1a02 | 0x5f1a02 | 0x31 | 0x5f1a1a |

- 8948 Linux 的**完整 symtab 保留 LOCAL 符号 `asGetActiveContext` @ 0x626ae8**（size 49），可作为事实交叉验证；10257 已 strip（仅 303 个 `_Z` 符号），仅能靠 body 签名定位。
- SHA-256（与既有 Part A–D 记录一致）：
  - 8948 Windows：`61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849`
  - 8948 Linux：`18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643`
  - 10257 Windows：`f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0`
  - 10257 Linux：`7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca`

## ABI / 派生布局

- 无参数 `__cdecl`，返回 `asIScriptContext*`（32-bit 指针）。
- 内部经 `asCThreadManager::GetLocalData()` 取 TLS；`asCThreadLocalData` `+0` 数组指针、`+4` count。
- 上述 +0/+4 与 `GetLocalData` 结果都是**派生布局**，只作为 artifact 的 body 语义/参考，**不产出独立 global/structmember artifact**，不冒充全局变量。

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-asGetActiveContext.py` — 按平台选 body 签名，`old_yaml_map=None`。
- `configs/svencoop-8948.yaml` / `configs/svencoop-10257.yaml` — `server` 模块新增 `find-asGetActiveContext` skill 与 `asGetActiveContext` func symbol。
- `bin_artifacts/svencoop-{8948,10257}/server/asGetActiveContext.{windows,linux}.yaml` — 4 份 production artifacts。
- `tests/test_as_get_active_context_preprocessor.py` — 平台→签名路由与 `old_yaml_map=None` 契约。

## 验证方式与证据

- analyzer：`ida_analyze_bin.py -gamever svencoop-8948|svencoop-10257 -modules server -skill find-asGetActiveContext -platform windows,linux`，各自 `Successful 2 / Failed 0 / Skipped 0`，产出 4 份 artifacts。
- 原始 PE32/ELF32 独立复核 4 个 `func_sig`：各唯一命中目标函数（PE 文件偏移与 RVA 相差 0xC00 段对齐；ELF 偏移等于 RVA）。
- `tests/run_test_suite.py unit -b`：1490 tests，OK，skipped 9。
- `tests/run_test_suite.py repository-contract -b`：15 tests，OK（需先 `git add` 全部新 artifacts，否则 tracked inventory mismatch）。
- `format_repo_files.py --check`：0。

## 适用范围

仅上述两个 Sven tags 的 x86 server DLL/SO。Part F 范围内**无未覆盖项**：四个目标独立成型、非内联、无版本专属缺失。E（CString/CScriptBuilder）、G（CScriptDictionary）、H（CIterator）、I 剩余（CPlayerMove_PlayStepSound / PM_PlaySoundFX_SERVER）、J（g_pServerManager）**不在本轮范围**，留待后续。
