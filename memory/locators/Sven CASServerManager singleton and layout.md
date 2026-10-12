---
title: Sven CASServerManager singleton and layout
type: note
permalink: goldsrc-vibesignatures/locators/sven-casservermanager-singleton-and-layout
tags:
- svencoop
- server
- angelscript
- locator
---

# Sven CASServerManager singleton and layout

## 范围与触发信号

Issue #349 Part J：Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 PE32/ELF32 `server` 模块需要定位 asext 的 `CASServerManager** g_pServerManager`，并读取 manager 的脚本引擎、当前模块。用户于 2026-10-12 确认下述两条复用 anchor 后实施。

## 已确认 anchors 与根因 / 约束

- `CASPersistence_KeepIfPrevious` 已由自身 `FULLMATCH:CASPersistence::KeepIfPrevious: array type must be string!\n` 定位。四个输入各一处字符串、一个函数 owner。复用 Part C 的四份已由 CLI 生成且还原过的 references，补充两视图注释，保留原 GetTypeInfoByName 调用标注。
- `find-CASPersistence_KeepIfPrevious-manager-decompiles` 将两个同上下文、同平台范围目标分组：`found_gv` 恢复取单例、判空、构造、写回的 pointer storage；`found_struct_offset` 恢复从单例对象取 `scriptEngine` 后调用 SDK GetTypeInfoById 的字段访问。
- `CASBaseManager_OnMapEnd` 已由自身 `FULLMATCH:Active module was not set to null!\n` 定位。复用 Part A 的四份 CLI references，保留原 CASHook_Call 注释。`find-CASBaseManager_OnMapEnd-structmembers` 用 `found_struct_offset` 恢复诊断前检查、诊断后清零的当前模块字段。
- CASServerManager 构造函数将同一对象地址传给 CASBaseManager 构造函数，再替换 vtable；无基址调整。OnMapEnd 的 base-view `activeModule` 对应消费方 `curModule`。不要把它与 `moduleHandle` 混淆。
- 5.15 Linux 的 VCall hook-id 字符串没有 IDA PIC xrefs，不能直接以字符串定位 VCall；最终方案复用上述已有 owner，避免新增 VCall/Call 链路。
- 5.15 Linux 的 GOT load 取得 `&pInstance`，下一条间接 load 才取得 manager；5.16 Linux 的 GOTOFF load 直接取得 manager。单例存储、GOT 槽、manager 对象为三个不同地址。
- 所有新 finder 都传 `old_yaml_map=None`。发现阶段不用旧签名、mangled-name lookup、固定偏移或 call ordinal。已有前置 artifact 是显式 DAG 输入；生成的签名仅用于输出和当前二进制唯一性验证。

## 正确输出与最小布局

配置与文件查找名为 `g_pServerManager`，分类 `gv`；payload `gv_name` 保留真实身份 `CASServerManager::GetInstance()::pInstance`。5.15 ELF 真实符号 `_ZZN16CASServerManager11GetInstanceEvE9pInstance` 是 4-byte OBJECT。字段分类为 `structmember`，父分类为 metadata-only `struct`，不创建独立字段全局变量。

```cpp
// Verified x86 prefix view only; unknown fields and complete class size are not claimed.
struct CASServerManagerView {
    unsigned char unknown_00[12];
    asIScriptEngine* scriptEngine; // +0x0c, size 4
    unsigned char unknown_10[8];
    CASModule* curModule;          // +0x18, size 4; inherited activeModule
};
```

字段位移由当前指令恢复，未硬编码为 finder 的预期值。Windows owner 方法使用 MSVC thiscall，this 在 ECX；asext 的 fastcall/unused EDX dummy 是适配方式。Linux 为 i386 Itanium/C++ 栈传 this；均为 4-byte pointer。Part J 不引入 iterator、string 或其他方法 ABI 产物。

## 二进制证据

| 输入 | pInstance VA / RVA | 单例定位指令 / disp | scriptEngine 指令 | curModule 指令 |
| --- | --- | --- | --- | --- |
| 8948 Windows | 0x105608a8 / 0x5608a8 | 0x100ad5ed / 2 | 0x100ad62a | 0x100a3aaa |
| 8948 Linux | 0x99e284 / 0x99e284 | 0x1d8b8a / 2 | 0x1d8ba0 | 0x1cfa63 |
| 10257 Windows | 0x104f70f0 / 0x4f70f0 | 0x100b15b0 / 1 | 0x100b15e7 | 0x100a1e7b |
| 10257 Linux | 0xb24764 / 0xb24764 | 0x121078 / 2 | 0x121086 | 0x1167b0 |

Windows image base 为 `0x10000000`，Linux 为 0。Windows absolute dword 直接解析存储地址。Linux `gv_pic_addend` 分别为 `0x9a0e9c`、`0xb14000`；按匹配版本的 `module_base + uint32(embedded_dword + gv_pic_addend)` 恢复真实 pointer storage。5.15 addend 包括经当前 GOT relocation 验证的间接目标差值，不能误当为纯 GOT base：`0x8ad3e8` 的 `R_386_GLOB_DAT` 指向 `0x99e284`。不要把 5.15 的 addend 套到 5.16。

SHA-256（MCP survey 与原始文件一致）：

- 8948 Windows：`61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849`
- 8948 Linux：`18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643`
- 10257 Windows：`f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0`
- 10257 Linux：`7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca`

源码只作线索：`/home/hztest2/metamod-fallguys/asext/src/{serverdef.h,signatures.h,meta_api.cpp,server_hook.cpp}`。字段与寻址事实以四个当前二进制为准。共享 supervisor 的 `idb_list` 初始无 session；通过 `idb_open` 逐份取得 session，核验 survey/path/hash，均以 `idb_close(save=True)` 成功保存关闭。分析 CLI 随后使用独立受管 lifecycle；warm strict cache 模式不保存分析 worker，IDA scratch 不纳入交付。

## 验证方式

2026-10-12：两个 tag 各自强制执行两个新 finder 的 Windows/Linux selected nodes，每个 tag 为 Successful 4 / Failed 0 / Skipped 0，真实 LLM 的 schema/semantic issues 均为空。生产产物共 12 个（4 个 gv、8 个 structmember）。

独立从原始 PE executable sections / ELF executable LOAD regions 扫描 12 个 masked signatures，均唯一命中已核验 owner；检查 VA/RVA、嵌入 dword/PIC addend 解析、目标数据 segment、实际 disp8 和 4-byte width，全部正确。输出签名实际均在 owner 函数体内，扩展输出预算没有实际跨函数边界。

复用 references 的既有消费者也强制定向回归：两个 tag 各自运行 Windows/Linux `find-CASBaseManager_OnMapEnd-decompiles` 和 Linux `find-CASPersistence_KeepIfPrevious-decompiles`，每个 tag 为 Successful 3 / Failed 0 / Skipped 0，旧 artifacts 无 diff。完整 server 流程两份配置均 exit 0 / Failed 0，分别 Skipped 55 / 56（复用有效产物；不替代上面的强制执行证据）。

单元门禁 `uv run python tests/run_test_suite.py unit -b --durations 30`：1494 tests / exit 0 / 9 skips（环境专属或 opt-in 项）。`repository-contract -b --durations 30`：15 tests / exit 0；新 artifacts 先显式 stage，以满足门禁读取 Git tracking inventory 的要求。`format_repo_files.py --check`：732 Python / 32 YAML，exit 0；Git diff whitespace 检查无错误。最终主会话复核分类身份、DAG、两视图标注、signature extent 和 PIC/GOT 解析，未发现问题。共享 runtime、依赖、CI 和 `docs/` 均未改动；不新增锁定 finder/config 文本的测试。

## 适用范围

仅上述四个 x86 server 输入。Part J 无缺失、版本专属或被内联消除的目标；Linux 5.16 缺少名称不等于变量不存在。其他 #349 分组保持独立范围，本变更不关闭整项 issue，也不实现消费方 hooks。
