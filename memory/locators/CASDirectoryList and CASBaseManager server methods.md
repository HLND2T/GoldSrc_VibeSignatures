---
title: CASDirectoryList and CASBaseManager server methods
type: note
permalink: goldsrc-vibesignatures/locators/casdirectory-list-and-casbase-manager-server-methods
tags:
- svencoop
- server
- angelscript
- locator
---

# CASDirectoryList and CASBaseManager server methods

## 范围与触发信号

Issue #349 Part C：定位 Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 `CASDirectoryList::CreateDirectory` 与 `CASBaseManager::GetTypeInfoByName`，或为后续 finder 复用 `CASPersistence::KeepIfPrevious(CScriptArray const*)` 前置函数。三项均为 `server / func`，四个输入都存在独立函数体，无版本专属、缺失或内联掉的目标。

## 已确认 anchors

用户先确认方案再实施。两个 finder 都传 `old_yaml_map=None`，不以历史签名、mangled 名称、调用序号或固定偏移发现目标。

- `CASDirectoryList_CreateDirectory`：自身 `FULLMATCH:CASDirectoryList::CreateDirectory: Directory '%s' already exists!\n`。四个输入各一处精确字符串、一个函数 owner；已核验查找重复目录、处理路径、构造目录对象和链接父子目录的行为。
- Windows `CASBaseManager_GetTypeInfoByName`：自身 `FULLMATCH:CASBaseManager::GetTypeInfoByName: failed to insert object type '%s' in cache! (cache size: %u)\n`。两个输入各一处字符串、一个 owner。函数查类型缓存，miss 时经引擎查询，成功缓存后 AddRef，缓存插入失败报错并返回 null。
- Linux `CASBaseManager_GetTypeInfoByName`：目标自身同一诊断字符串存在，但两个 IDB 都没有记录它的 PIC xref，不能交给现有通用字符串 finder。使用前置函数自身 `FULLMATCH:CASPersistence::KeepIfPrevious: array type must be string!\n`，四个输入均一处字符串、一个 owner；选择数组重载，不是 CString 重载。
- 下游 `find-CASPersistence_KeepIfPrevious-decompiles` 仅注册 Linux，required input 为 `CASPersistence_KeepIfPrevious.linux.yaml`。以 `LLM_DECOMPILE / found_call` 识别 manager 对临时 `std::string("string")` 的查询，其结果与引擎 `GetTypeInfoById(array->GetElementTypeId())` 比较后才报 array-type 错误。
- 引擎 `GetTypeInfoById` 的 vtable byte offset 为 `0xdc`，目标体中 `GetTypeInfoByName(const char*)` SDK 查询为 `0xe0`。这是核验角色的调用证据，不是新的 vfunc/struct/global artifacts。
- 5.15 Linux 实际调用为 `0x1d8bd1 -> PLT 0x18aa30 -> body 0x1cfc38`；启用 `func_sig_resolve_jmp_thunk:true` 后发布真实方法体。5.16 为 `0x1210c2 -> body 0x116a68`。

## 版本差异与 ABI

Windows 是 MSVC thiscall：this 在 ECX，显式参数在栈上；asext 用 fastcall 加 unused EDX dummy 适配，并不意味着原函数使用两个有效寄存器参数。CreateDirectory callee 清理五个显式栈参数，GetTypeInfoByName 清理一个。Linux 是 i386 Itanium/C++ cdecl，this 为第一个栈参数，调用方清栈。

CreateDirectory 实际返回 `CASDirectory*`（EAX），asext `serverdef.h` 的 void typedef 忽略返回值。四个 unsigned-char 参数逐项传入目录构造函数。GetTypeInfoByName 返回 `asITypeInfo*`。

两平台当前 `std::string` 都为 24 字节，但布局不同：Windows buffer/pointer+0、length+16、capacity+20；Linux libstdc++ `__cxx11` data+0、length+4、local-buffer/capacity+8。Linux 5.15 的真实参数是 `std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&`，5.16 的实参构造及 callee 同样使用该布局。artifacts 的 `func_name` 保留这个 ABI 身份，文件名和 config name 使用稳定逻辑名称。

KeepIfPrevious 5.15 Linux 仍调用 CString 重载；5.16 将该重载内联为字符串比较及 keep 标记更新。Windows 两版本同样内联，5.16 先执行元素类型 SDK 查询再执行 manager 查询。references 保留真实调用次序和 inline/SEH/loop 控制流，不能复用某个平台的调用顺序。

IDB/reference 的最小 view 类型只表达当前核验字段：manager.scriptEngine+12；Persistence 的 matchName / keep 标记分别为 Windows +20/+92、Linux +52/+124。未发布这些字段、singleton 或完整 class 布局为符号，不替代 Part J。两份 Linux ELF 均无 `.debug*` sections；完整私有 server 源码未提供，布局来自当前机器码与带符号 5.15 peer。消费方源码和 SDK只作线索。

## 二进制证据

| 输入 | CreateDirectory RVA | GetTypeInfoByName RVA | KeepIfPrevious(array) RVA |
| --- | --- | --- | --- |
| 8948 Windows | 0xc8960 | 0xa4180 | 0xad560 |
| 8948 Linux | 0x216fa0 | 0x1cfc38 | 0x1d8b5a |
| 10257 Windows | 0xc8030 | 0xa2560 | 0xb1520 |
| 10257 Linux | 0x1625c2 | 0x116a68 | 0x12104c |

Windows image base 为 `0x10000000`，Linux 为 0。5.15 实际 ELF 符号：

- `_ZN16CASDirectoryList15CreateDirectoryEPKchhhh`
- `_ZN14CASBaseManager17GetTypeInfoByNameERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE`
- `_ZN14CASPersistence14KeepIfPreviousEPK12CScriptArray`

SHA-256（MCP survey 与本地原始文件一致）：

- 8948 Windows：`61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849`
- 8948 Linux：`18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643`
- 10257 Windows：`f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0`
- 10257 Linux：`7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca`

消费方为 `/home/hztest2/metamod-fallguys/asext` revision `df03faf88e7e547d3f4f84b75ed0385bec5a0678`：`src/serverdef.h`、`src/signatures.h`、`src/meta_api.cpp`、`src/server_hook.cpp` 与 `include/std_string.h`；SDK 的 engine query 声明为 `thirdparty/angelscript-sdk/angelscript/include/angelscript.h`。

## 根因 / 约束与正确做法

- 字符串存在而 IDA 没有 PIC xrefs，不代表目标函数缺失。不要补手工 xrefs后声称 finder 可从原始 IDB定位；以稳定调用者语义恢复 callee。
- 同名 SDK 引擎 GetTypeInfoByName 接受 C 字符串且是虚调用；本 Part C manager 方法接受 C++ string 引用且是 direct call，不能混淆。
- `func_sig_allow_across_function_boundary:true` 扩展通用输出预算以应对 SEH 和同型 wrapper。当前生成的全部 12 个签名实际都在已核验函数体内并包含真实 body 指令；生成签名只用于消费方匹配和唯一性验证，不作为 finder anchors。
- 两个版本的 predecessor body 有差异：以各自明确的 reference gamever (`svencoop-8948` / `svencoop-10257`) 生成 Windows/Linux references，共四份。初始生成均通过 `generate_reference_yaml.py`，先在 IDB 还原原型、callee、singleton 与最小 view，再在 disasm_code/procedure 两视图标注目标 call。
- 生产 artifact inventory 门禁读取 Git 跟踪清单。新 artifacts 尚未加入索引时，repository-contract 会报告 missing；明确 stage 本任务新 artifacts 后再跑门禁，不修改测试放宽契约。

## 验证方式与证据

2026-10-09：两个 tag 分别执行 Windows/Linux `find-CASDirectoryList-CASBaseManager` selected nodes，每个 tag Successful 2 / Failed 0 / Skipped 0；最终平台过滤改为按 symbol 名排除后重跑四个 direct nodes，仍全部成功。两个 Linux 下游 selected nodes 各 Successful 1 / Failed 0，真实 LLM 返回上述两个 call VA，schema/semantic issues 为空；未 fake LLM，未手填 artifacts。

产物共 12 个 func artifacts（8 个 Part C 目标、4 个前置函数）及4份 reference。独立以 Python struct 读取 PE executable sections / ELF executable LOAD regions，扫描全部 masked 签名：每个均唯一命中目标 VA，VA/RVA 正确，签名长度不跨方法体。对 `readelf -Ws` / `c++filt` 独立核对三个 5.15 Linux 方法：artifact 身份、VA、size 均一致。reference 四字段契约、predecessor VA、双视图标注和实参模型已复核，无 local-variable-allocation 警告。

两个 tag 完整 server 流程 exit 0 / Failed 0；已有有效 artifacts 被复用，8948 Skipped 20 / 10257 Skipped 21。这不替代上述强制 selected-node 执行证据。

单元门禁：`uv run python tests/run_test_suite.py unit -b --durations 30`，1417 tests / exit 0 / 9 skips（Windows 专属和 opt-in notes CLI）。`repository-contract -b --durations 30` 最终 15 tests / exit 0。`format_repo_files.py --check` exit 0；未新增具体 finder/config/source-text 锁定测试，未修改共享 runtime或 docs。

IDA session 从共享 supervisor 的 `idb_open` 获取；每份生成前核对 survey/hash/health，生成后显式 `idb_close(save=True)` 全部成功。IDA scratch 留在 `bin/`，不纳入交付。

## 适用范围

仅两个 Sven tags 的 x86 server DLL/SO。其他 issue #349 分组继续独立确认 anchors；本变更不实现 asext/fallguys hooks，不关闭整个 #349。
