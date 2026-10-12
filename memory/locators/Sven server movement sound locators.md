---
title: Sven server movement sound locators
type: note
permalink: goldsrc-vibesignatures/locators/sven-server-movement-sound-locators
tags:
- svencoop
- server
- fallguys
- locators
---

# Sven server movement sound locators

## Overview

Issue #349 Part I：为 Sven Co-op 5.15 (`svencoop-8948`) 与 5.16 (`svencoop-10257`) 的 x86 `server.dll/server.so` 补齐移动音效函数定位。用户明确禁止长段 signature 作为 anchor；确认了字符串/浮点筛选及 LLM 调用链方案。交付符号与 artifacts，不实现消费方 hook。

## Responsibilities

- `CPlayerMove_PlayStepSound`：`FULLMATCH:player/pl_tile5.wav` + 实际 scalar read `220.0`。四个输入中，音效字符串各出现一次，引用归属 ClientPrecache、CBaseMonster::PlayStepSound 和玩家方法；只有玩家方法读取水平速度门限 220，筛选后唯一。
- `PM_PlaySoundFX_SERVER`：无自有字符串。24.0 单独不唯一（5.16 Windows 有 21 个引用函数），不使用字节签名发现目标。对确定性定位的 PlayStepSound 使用 `LLM_DECOMPILE / found_call`，验证当前调用点、函数范围、目标唯一性和 ELF PLT 解析。
- `RegisterSCScriptColor24`：复用 Part B 已有 `find-CASDocumentation-registration-callers` 的 `FULLMATCH:Color24 structure` 与四份 artifacts，不重复注册。

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-CPlayerMove_PlayStepSound.py` — 字符串与浮点 anchor，`old_yaml_map=None`。
- `ida_preprocessor_scripts/find-CPlayerMove_PlayStepSound-decompiles.py` — 配置输出选择 direct/wrapper branch。
- `ida_preprocessor_scripts/find-CPlayerMove_PlaySoundFX-decompiles.py` — 仅 8948 Linux 的包装层→PM。
- `player_move_artifacts.py` — 输出真实 identity；不参与地址发现。Linux保留 `_ZN11CPlayerMove13PlayStepSoundEifb`、`_ZN11CPlayerMove11PlaySoundFXEiPfiPcffii`，PM保留C名。
- `configs/svencoop-{8948,10257}.yaml` — server skills/symbols，包装层仅在8948 Linux声明。
- `ida_preprocessor_scripts/references/svencoop-{8948,10257}/server/CPlayerMove_PlayStepSound.{windows,linux}.yaml` — 当前 IDB 恢复后经项目 CLI 生成，disasm与procedure均标注音效调用。
- `ida_preprocessor_scripts/references/svencoop-8948/server/CPlayerMove_PlaySoundFX.linux.yaml` — 包装层reference。
- `bin_artifacts/svencoop-*/server/` — 新增8份目标函数artifacts和1份8948 Linux包装函数artifact。

## Architecture

Windows两个版本及10257 Linux：字符串/220→PlayStepSound→PM_PlaySoundFX_SERVER。8948 Linux：字符串/220→PlayStepSound→PlaySoundFX→PM_PlaySoundFX_SERVER。后者是实际9参数cdecl成员包装函数，忽略this，将playerindex加一并转发其余8个PM参数；PIC thunk不是业务目标。包装层是显式artifact/DAG依赖，不能按调用顺序猜测或发布PLT地址为函数体。

| tag/platform | PlayStepSound RVA | PM RVA | Color24 RVA |
| --- | --- | --- | --- |
| 8948 Windows | 0xe75a0 | 0x23b840 | 0x2b93b0 |
| 8948 Linux | 0x23cf78 | 0x540e9e | 0x268888 |
| 10257 Windows | 0x341150 | 0x249390 | 0x2c8c80 |
| 10257 Linux | 0x577638 | 0x4f0caa | 0x1b64f4 |

8948 Linux PlaySoundFX RVA=0x23cf36、size=0x42。Windows imagebase=0x10000000，Linux=0。这些是精确输入的验证值，不是 finder anchor。

## Dependencies

- `preprocess_common_skill`、共享 SSE/x87/PIC float reader、`select_llm_specs`、x86调用解析和签名验证。
- 参考源码：`D:/metamod-fallguys/fallguys/src/{serverdef.h,signatures.h,meta_api.cpp,server_hook.cpp}`。私有server源码不可用；二进制、5.15 ELF符号和同版本平台peer是事实依据。
- [[idalib-mcp]]：先idb_list，无现有session后idb_open。所有本次打开的IDB均idb_close(save=True)，未提交bin/ scratch。CLI analyzer使用strict restored/no-save。

## Notes

- ABI：Windows PlayStepSound为真实thiscall（ECX=this、retn 0xC）；消费方fastcall+dummy EDX是适配方式。Linux为cdecl、this在首个栈参数。PM与Color24均为cdecl，PM接受8个栈参数，内部重建声源位置并遍历其他玩家。
- 必要IDB局部布局：CPlayerMove movement=+0x460、onLadder=+0x464；movement playerindex=0、multiplayer=8、origin=0x38、velocity=0x5C、stepLeft=0x98。movevars/randomLong/runfuncs在5.15为0x4F4F0/0x4F588/0x4F5B0，在5.16为0x84B90/0x84C28/0x84C50；movevars footsteps=+0x40。均由当前指令验证，只用于reference阅读，不伪装成独立global或structmember产物。
- 5.16 Linux的误标注 displacement 曾渲染为 `stru_84*.r_offset`；按真实寄存器+成员位移恢复数值operand后，partial structure能正确表示这些访问。
- 5.16 Linux Hex-Rays仍省略randomLong实参；reference两个字段明确记录此限制，disassembly保留(0,1)/(0,4)的实际栈参数。PM调用参数已完整恢复，定位不依赖省略的randomLong参数。
- 触发信号：anchor得到唯一候选，finder却失败。根因可能是默认输出签名预算只有24个fixed bytes，仍停留在共享PIC/零向量初始化；不是anchor失败。正确做法：保持字符串/常量发现，扩展输出验证预算，涵盖stepLeft切换、runfuncs门禁与randomLong调用；小包装函数涵盖参数转发、编号增量和PM调用。输出func_sig仅用于artifact验证/运行时消费者，不作为finder的发现anchor或old-YAML捷径。
- 用户禁用的4条PM长段body discovery signatures已撤回，生产finder没有xref_signatures。
- 范围内四个输入均有独立函数体；无缺失或目标内联。PlaySoundFX只在8948 Linux作为独立定位依赖，在其他三输入的step方法中内联。

### Verification (2026-10-12)

空输出目录 `.tmp/part_i/fresh_artifacts` 定向重跑3个finder、两tag、全部声明平台：9个节点成功、0失败、0跳过；最终9份YAML复制到bin_artifacts。独立原始文件验证13份（含复用Color24）VA/RVA、PE32/ELF32映射和每个func_sig唯一匹配。初次完整server调度两tag均0失败、各56缓存节点跳过。同步main的Part J之后再次调度，两tag均0失败、各60缓存节点跳过，不能宣称重新执行了全部既有finder。

- `uv run python tests/run_test_suite.py unit -b --durations 30`：1494 tests，OK，12 skipped。
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`：15 tests，OK。
- `uv run python format_repo_files.py --check`：通过。
- `git diff --cached --check`：生成reference的空白行尾空格清理后复核。
- 原始SHA256：
  - 8948 Windows：61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849
  - 8948 Linux：18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643
  - 10257 Windows：f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0
  - 10257 Linux：7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca

## Callers

- 已确认的PlayStepSound音效分支→PM（Windows两个版本、10257 Linux）。
- 8948 Linux PlayStepSound→PlaySoundFX→PM。
- 消费方fallguys的InstallServerHooks对PlayStepSound/PM安装inline hook；RegisterAngelScriptMethods按需调用Color24注册。本仓库不实现这些hook。
