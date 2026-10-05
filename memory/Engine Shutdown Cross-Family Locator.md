---
title: Engine Shutdown Cross-Family Locator
type: note
permalink: goldsrc-vibesignatures/engine-shutdown-cross-family-locator
tags:
- locator
- engine
- shutdown
- native-rcon
- cross-family
---

# Engine Shutdown Cross-Family Locator

## 结论

`Host_Shutdown` 与 `NET_Shutdown` 的定位已从 Sven(PR #331,仅 Windows 且依赖 Sven 专有字符串)扩展到全部 11 个经典 engine 家族 + Sven,Windows PE32 与 Linux ELF32 全平台,共 15 个 engine 输入。finder 为 `ida_preprocessor_scripts/find-native-rcon-shutdown-symbols.py`,纯确定性、无 LLM、无 reference YAML、无固定地址。

## 触发信号

- 需要把某个 Sven-only 的字符串锚 finder 扩展到经典引擎家族。
- `cstrike/czero/czeror` 的 config **没有 engine 模块**(只带 client.dll + mp.dll),因此"全引擎家族"不包含它们。

## 根因 / 关键约束

1. **PR #331 的锚点是 Sven 专有的**:`"Recursive shutdown!"` 与 `"Threaded networking stopped successfully.\n"` 只存在于 Sven。
2. **经典引擎的锚点不同**:Host_Shutdown 拥有唯一的 `"recursive shutdown"`(小写);PE 上带 `\n`,而 `hw.so` 上来自源码字面量的裸字符串**不带 `\n`**。因此锚点必须用大小写敏感的**子串**匹配,而非 FULLMATCH。
3. **NET_Shutdown 无自有字符串**:必须由结构定位。
4. **Linux 的 `NET_Config` 被内联**进 NET_Shutdown,因此"callee 调用 NET_Config"这一判据在 ELF 上失效;Sven 的 NET_Shutdown 改调 `Sock_Config` 而非 `NET_Config`。
5. **GCC PLT 间接**:ELF 上 callee 走 PLT stub,直接 `CodeRefsTo` 观察不到真实调用边,必须用 `ida_elf.resolve_elf_plt` 解析后再比对目标。

## 正确做法(统一谓词)

- **Host_Shutdown**:拥有递归关闭字面量的唯一函数。needles = `["recursive shutdown", "Recursive shutdown!"]`(大小写敏感子串);要求 owner 集合大小恰为 1,否则 fail-closed。
- **NET_Shutdown**:`Host_Shutdown` 的**直接 callee**中,满足下列任一者(唯一命中才接受):
  - 调用了配置函数(`NET_Config` 或 Sven 的 `Sock_Config`,EA 由既有 artifact 提供);或
  - 引用了 `ip_sockets` 数组(经典 Linux 内联路径)。
  - PLT 感知:callee 自身的调用也要 `resolve_elf_plt`。
- 依赖只经由 DAG 既有产物:`NET_Config`、`ip_sockets`、Sven 的 `Sock_Config`。config 的 `expected_input` 必须显式声明 `NET_Config.{platform}.yaml` 与 `ip_sockets.{platform}.yaml`,否则 DAG 不保证顺序。
- 覆盖集合 = 11 classic(hl-3248..10210 含 4 个 BLOB→`hw.decrypt.dll`,cof-5936) + 2 Sven;平台 = 9 classic Windows + hl-8684/10210 Linux + 2 Sven 双平台。

## 验证方式

- 逐输入 pipeline 运行(15 node),全部 preprocessor 成功,无 Agent fallback。
- `format_repo_files.py --check` exit 0;`repository-contract` 15 tests OK;`unit` 1379 tests OK(skipped=5)。
- artifacts 为 canonical(== `canonical_symbol_yaml_bytes`)且与 config 声明一致(需 `git add` 后 inventory 才匹配)。
- 四份 Sven Windows(#331)保持不变,新 finder 独立复现同一 VA。

## 适用范围

本仓库 GoldSrc x86 engine 模块的关闭/lifecycle 符号定位;同类"把 Sven-only finder 泛化到经典引擎"的任务。

## 陷阱

- `preprocess_common_skill` 不支持注入自定义起始地址;"已知地址 + 只要生成 func_sig"应走 `_inspect_function_via_mcp` + `write_func_yaml`。
- MCP `py_eval` 的 exec 顶层作用域对**推导式(comprehension)隔离局部变量**;多函数相互调用必须用 `def ...` + `globals().update(locals())` 惯用法。
- 直接结论:本地 ad-hoc `idb_open` 会留下 `.id0` 锁文件;pipeline 一旦发现 `.id0` 存在即判定"另一个 IDA 实例持有",其自带回收路径在锁存在时同样拒绝。清理需人工确认。
