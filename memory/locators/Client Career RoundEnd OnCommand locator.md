---
title: Client Career RoundEnd OnCommand locator
type: note
permalink: goldsrc-vibesignatures/memory/locators/client-career-round-end-on-command-locator
tags:
- client
- career
- issue-399
---

# Client Career RoundEnd OnCommand (#399)

## 触发信号与根因

MetaHookSv #936：RoundEnd 打开 CareerBoxSurrender 后，确认框 ESC 的 Cancel 会沿 action target 回到同一 RoundEnd。RoundEnd 的业务 OnCommand 对普通命令执行 unpause、转发命令、OnClose 和 CareerUI 的 OnRoundEndMenuClose；Cancel/Close 不会成为 career_continue。此前 #397 的两个 Frame 键槽保护不能独立覆盖来自确认框的命令入口。

本任务只交付符号与正式 catalog，不修改下游行为，不把旧双键 hook 的成功记录或静态分析当作新增 command guard 的运行时验证。

## Identity、发现与实现

- module: client；catalog kind: virtualFunction。
- canonical name: `CCSCareerRoundEndMenu::OnCommand(char const*)`。
- artifact/config identity: `CCSCareerRoundEndMenu_OnCommand`，category: vfunc。
- Linux 原始 ELF 符号：`_ZN21CCSCareerRoundEndMenu9OnCommandEPKc`。
- finder: `ida_preprocessor_scripts/find-CCSCareerRoundEndMenu_OnCommand.py`。
- Pattern B：函数自己的三个 exact literal（CareerBoxSurrender、#Career_Surrender、#GameUI_QuitConfirmationText）各有唯一字符串和唯一 owner，三者 owner 必须相同；另检查 disconnect、surrender、unpause 换行、vguicancel 分支字面量。
- 使用 `preprocess_common_skill(old_yaml_map=None)`，消费 #397 生成的当前 RoundEnd 主表 artifact，反查唯一成员得到槽位。签名仅用于发现后的唯一性验证，不消费旧签名，不按 RVA、槽位或 SDK 布局发现。
- Linux 另用共享 `current_elf_symbols` 读取原始输入文件的 symbol table，验证原始方法符号与 anchor owner 相同。IDA 数据库中的名字可能已经被 analyzer 改写，不能只信 IDB 名字。
- 用户在实现前确认了此 anchor 方案，正式发布选择为 v20261023b / tracked。

## 身份交叉验证与近似实现排除

10210 Linux：目标 0x840c0，disconnect 分支调用 CCareerQueryBox 构造函数 0x7e140，并在 0x84204 调用 `Panel::AddActionSignalTarget(query, this)`。RoundEnd 构造函数创建以自己为 parent 的 ok / surrender 按钮，保存为 m_pContinueButton / m_pSurrenderButton，加载 Resource/UI/CSCareerRoundEnd.res，并写入自己的 primary vptr。

CCareerQueryBox 主表 AP 0x17d6f8 的命令槽实际是继承的 `CCareerBaseBox::OnCommand` 0x80300；该方法对非 close/engine 命令构造 `Command(command=原命令)` 并 PostActionSignal。它不是待导出的 RoundEnd 业务 override。`Frame::OnCommand` 为 0x1164a0，RoundEnd 在自身业务处理后调用它，也不能代替 RoundEnd 的入口。`Button::FireActionSignal` 0x10b410 复制 action message 并通过 PostActionSignal 投递；官方源码 Panel.cpp:1415、1447 和 Button.cpp:610 仅作消息语义参照，不推定其修订与目标相同。

Windows 10210 的当前目标 0x1002cbc0 同样构造确认框、将同一个 RoundEnd this 设为 action target，普通命令走 unpause / forwarding / close / CareerUI 通知。原始输入矩阵各代表方法均检查了反编译与构造路径。目标在全部适用输入均真实存在、非 inline、非合并的 Frame/QueryBox 方法；无 this-adjusting thunk。

## 继承与 ABI

继承与构造证据复用 [[Client Career RoundEnd and Frame KeyCode slots]]：RoundEnd → CCSCareerBaseMenu → vgui2::Frame → EditablePanel → Panel → IClientPanel。当前主对象 vptr 在 this+0；Windows COL.offset=0，主基类 PMD 无调整；Linux offset-to-top=0，原始 _ZTV 是 header，AP 为 +8。

- Windows x86 thiscall：ECX=this，栈上传 char const* command，正常返回 ret 4。SEH 的独立共享异常尾块不能算作普通参数 cleanup 返回。
- Linux i386 SysV/cdecl：this 和 command 均通过栈传入，由 caller 清栈；非 Windows thiscall。
- 下表地址/槽位为本次输入的核验结果，不是 finder 常量。原文件与 IDB SHA-256、原始 PE 表成员、ELF 表成员加 R_386_32/RELATIVE relocation 均独立核对。

| gamever | platform | primary AP | method VA | RVA | index / offset |
|---|---|---|---|---|---|
| cstrike-3248 | Windows | 0x019c39ac | 0x01926720 | 0x26720 | 87 / 0x15c |
| cstrike-3647 | Windows | 0x019c39ac | 0x01926720 | 0x26720 | 87 / 0x15c |
| cstrike-4554 | Windows | 0x019c99c0 | 0x019277e0 | 0x277e0 | 87 / 0x15c |
| cstrike-6153 | Windows | 0x019c9a0c | 0x01926430 | 0x26430 | 87 / 0x15c |
| cstrike-6153 | Linux | 0x1c0748 | 0xdc1a0 | 0xdc1a0 | 88 / 0x160 |
| cstrike-8684 | Windows | 0x019caa0c | 0x019264c0 | 0x264c0 | 87 / 0x15c |
| cstrike-8684 | Linux | 0x1bfc68 | 0xdb3c0 | 0xdb3c0 | 88 / 0x160 |
| cstrike-10210 | Windows | 0x100c8c8c | 0x1002cbc0 | 0x2cbc0 | 87 / 0x15c |
| cstrike-10210 | Linux | 0x17fbc0 | 0x840c0 | 0x840c0 | 88 / 0x160 |
| czero-8684 | Windows | 0x019caa0c | 0x019264c0 | 0x264c0 | 87 / 0x15c |
| czero-8684 | Linux | 0x1bfc68 | 0xdb3c0 | 0xdb3c0 | 88 / 0x160 |
| czero-10210 | Windows | 0x100c8c8c | 0x1002cbc0 | 0x2cbc0 | 87 / 0x15c |
| czero-10210 | Linux | 0x17fbc0 | 0x840c0 | 0x840c0 | 88 / 0x160 |

CZDS czeror-8684/10210 的 Windows/Linux 四个输入中均无 RoundEnd RTTI/ELF 类名、构造资源和确认框 anchor，故不适用，不注册虚构记录。早期 CS Linux 未配置。完整 17 项输入哈希、适用性与 ABI 记录在 `memory/issues/issue-399-validation.json`。

## 验证与会话收尾

- 最终 bounded batch 强制执行 13 个目标节点：13 successful、0 failed、0 skipped；未使用 LLM/Agent fallback。8 个 CS/CZ 配置共生成 13 份 vfunc artifacts。
- 10 个完整 schema-8 snapshot 及 metadata、catalog dataset guard 均通过；13 条新增记录与主表/原文件/独立 IDA evidence 一致，CZDS 无对应记录。
- 交互分析先 idb_list，再 idb_open exact binary；survey 核对 x86/base/hash，全部 owned 会话以 idb_close(save=True) 成功收尾。批量 analyzer 使用 strict restored IDB、no-save。未提交 bin 子模块/IDA scratch。
- 回归策略：不改共享 runtime/helper，使用真实二进制定向矩阵及现有 unit/repository-contract；不新增固化 finder 文本或配置清单的测试。
- 最终 `tests/run_test_suite.py all -b --durations 30`：1565 tests，OK，16 skips（10 个 POSIX、2 个 opt-in CLI、3 个不可用 Redis integration class、1 个 opt-in IDA integration）。独立 repository-contract 15 tests OK；`format_repo_files.py --check` 与 staged diff whitespace 检查通过。真实 IDA 矩阵证据独立于被跳过的 opt-in integration。
- 本地校验脚本与完整日志在 `.tmp/issue399-*`，不是 CI 必需输入；结构化身份记录和此笔记供长期复核。
