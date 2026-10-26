---
title: Client Career MatchEnd vtable and OnCommand locator
type: note
permalink: goldsrc-vibesignatures/locators/client-career-match-end-vtable-and-on-command-locator
tags:
- client
- career
- issue-409
---

# Client Career MatchEnd vtable and OnCommand (#409)

## 触发信号与职责

MetaHookSv #957 的 VGUI2Extension 需要 czero-10210 / czero-8684 的 client canonical records：`CCSCareerMatchEndMenu`（vtable）和 `CCSCareerMatchEndMenu::OnCommand(char const*)`（virtualFunction）。本仓库交付 gamedata，不修改下游 hook，也不以静态分析证明游戏运行时修复。

## 根因 / 约束

Issue 描述的调用链为 ESC Cancel/Close → MatchEnd::OnCommand → unpause / close / OnMatchEndMenuClose，音乐淡出并清除当前 track identity；未到期的服务器 MATCH deadline 在 unpause 后重发 MATCH，引发再次 StartTrack(MatchWin)。MatchEnd 与 RoundEnd 必须各有独立主表；Frame 的 Pressed/Typed 可复用。

## 正确做法与涉及文件

- `ida_preprocessor_scripts/find-client-frame-keys.py`：只有请求 MatchEnd 输出时，增加 `CSCareerMatchEnd` 与 `Resource/UI/CSCareerMatchEnd.res` 的共同 constructor owner 检查，验证当前 this+0 写入精确 RTTI 主表，并排除与 RoundEnd AP 相同。保留 Frame 主基类无调整及键槽继承校验。
- `ida_preprocessor_scripts/find-CCSCareerMatchEndMenu_OnCommand.py`：Pattern B，Credits / career_restart / unpause 换行 / vguicancel 的 exact string owners 交集唯一，且必须是当前 MatchEnd 主表唯一成员。Linux 另从原始输入 ELF symbol table 验证 `_ZN21CCSCareerMatchEndMenu9OnCommandEPKc`。
- 配置仅增加 `configs/czero-10210.yaml` 与 `configs/czero-8684.yaml` 的新 producer / consumer DAG、vtable 和 vfunc 注册。
- 不消费旧 YAML、固定 RVA、固定槽位、先前 artifacts 或生成签名来发现目标；签名仅作发现后的唯一性验证。

## 当前二进制独立核验

以下地址是当前输入核验结果，不是 finder 常量。

| gamever | platform | primary AP | OnCommand VA | index / offset | constructor |
|---|---|---|---|---|---|
| czero-10210 | Windows | 0x100c8688 | 0x1002b810 | 87 / 0x15c | 0x1002b2b0 |
| czero-10210 | Linux | 0x17f34c | 0x82610 | 88 / 0x160 | 0x81630 |
| czero-8684 | Windows | 0x019ca464 | 0x01925050 | 87 / 0x15c | 0x01924450 |
| czero-8684 | Linux | 0x1bf3c8 | 0xd9ee0 | 88 / 0x160 | 0xd9fc0 |

Windows 为 x86 thiscall（ECX=this、栈 command、ret 4）；Linux 为 i386 SysV/cdecl（栈 this / command，恢复栈后尾调度）。四个入口均是本类业务实现，非 Frame 实现或 this-adjusting thunk。Credits 分支打开 credits 后关闭；普通命令先 unpause，vguicancel 通知 viewport，否则转发原命令，关闭并调用 Frame::OnCommand，再以 career_restart 比较结果通知 CareerUI。

原始 PE 表成员和 Linux R_386_RELATIVE / R_386_32 重定位后的成员均独立吻合；IDB 输入 SHA-256 与原文件一致：

- 10210 Windows: `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2`
- 10210 Linux: `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a`
- 8684 Windows: `b017e06a5551f3db8c7c817b72a65433362d8b3c8394edb02cac919528e3f73c`
- 8684 Linux: `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798`

## 验证方式与适用范围

2026-10-26 bounded batch 强制执行 10 tags / 21 nodes（17 Frame + 4 MatchEnd OnCommand），全部成功，零失败/跳过；8 份新 artifacts 从当前二进制生成，既有 artifacts 无改动。交互 IDA 会话正常保存并关闭以收拢数据库临时文件，batch 使用 strict restored / no-save；bin 子模块和 IDA scratch 不提交。

原始证据及本地校验脚本保存在 `.tmp/issue409-*`，不作为 CI 输入。发布选择为 `v20261026a / tracked`，发布及线上 catalog 验证另行执行。

## 相关知识

- [[Client Career RoundEnd and Frame KeyCode slots]]
- [[Client Career RoundEnd OnCommand locator]]

## 本地完成门禁

- 10 个完整 schema-8 snapshots / metadata 与 catalog dataset guards 全部通过；两个 CZ dataset 共 8 条新 canonical records，kind / payload / 唯一表成员一致，其他 gamevers 未新增 MatchEnd 导出。
- Unit：1568 tests，OK，12 skips；repository-contract：15 tests，OK。完整 all 首轮共 1587 tests，唯一错误为并行生成 artifacts 前的 inventory 缺失，生成齐全后 repository-contract 已独立重跑通过；其余 Redis / IDA opt-in 等 4 skips 加 unit 12 skips，共 16。
- `format_repo_files.py --check` 与 staged diff whitespace 检查通过。四个生产目标均有真实 IDA 分析证据，独立于跳过的 opt-in integration。
