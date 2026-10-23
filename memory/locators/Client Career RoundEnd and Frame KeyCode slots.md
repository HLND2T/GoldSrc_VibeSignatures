---
title: Client Career RoundEnd and Frame KeyCode slots
type: note
permalink: goldsrc-vibesignatures/memory/locators/client-career-round-end-and-frame-key-code-slots
tags:
- client
- vgui
- career
- issue-397
---

# Client Career RoundEnd and Frame KeyCode slots (#397)

## 触发信号与职责

MetaHookSv #936 的 Career ESC 兼容修复需要 client/CCSCareerRoundEndMenu 的独立主表，以及继承的两个 Frame KeyCode 虚槽。本任务仅交付 gamedata，不实现下游 hook，不将静态分析当作游戏运行时回归。

Canonical identities：
- client / vtable / CCSCareerRoundEndMenu；artifact CCSCareerRoundEndMenu_vtable。
- client / virtualFunction / vgui2::Frame::OnKeyCodePressed(vgui2::KeyCode)；artifact vgui2_Frame_OnKeyCodePressed。
- client / virtualFunction / vgui2::Frame::OnKeyCodeTyped(vgui2::KeyCode)；artifact vgui2_Frame_OnKeyCodeTyped。

下游 manifest 已用这些名称，无需迁移 identity。原始 ELF 方法符号为 _ZN5vgui25Frame16OnKeyCodePressedENS_7KeyCodeE 和 _ZN5vgui25Frame14OnKeyCodeTypedENS_7KeyCodeE。

## 根因 / 约束

- 10210 Pressed 在 ESC + SupportsFeature(3) 时投递 CloseFrameButtonPressed 和 Command(command=Cancel)；8684 及更早版本只投递 Cancel。不能将两个消息同时存在作为通用 anchor。
- Typed 的 ESC 路径要求 GetAppModalSurface()==GetVPanel()，调用 CloseModal：释放当前模态状态、必要时恢复 previous-modal 成员并清零、投递 Close。只保护 Pressed 不够。
- CS 3248/3647 Typed 存在但无 ESC 分支；以 modifier/F4 关闭消息、Enter 默认按钮 Hotkey 识别。OnKeyTyped(wchar_t) 是另一独立事件，不能混名。
- GCC 10210 的 GetVPanel / CloseModal 有 guarded devirtualization，多个消息分支共用投递代码。验证当前表比较后，沿实际 virtual fallback 做数据流，并将消息构造对象关联到最终投递。
- GCC 的 xchg ax, ax 是对齐 no-op。旧共享追踪器把它当未知写入，导致 EAX 返回值变成 None；新增精确的同寄存器交换处理，保持完整寄存器和 flags，不放宽其他未知指令。
- CZ 10210 0x1002bfec 是构造 vptr 写入，0x1002c75c 属于删除析构函数。后者不可作为构造锚点。
- 普通 Close/Cancel 不变成 career_continue；RoundEnd::OnCommand 仍执行 unpause、转发命令、OnClose、关闭通知。

## 正确做法与涉及文件

- find-client-frame-keys.py：当前 RTTI 表 + 精确资源/消息字面量 + decoded receiver/参数/CFG。反查当前表唯一槽位。完全不消费 old_yaml_map，不用固定 RVA/槽位/SDK 顺序发现目标。
- _frame_key_identity.py：按实际消息对象、receiver、KeyCode 条件、正向 SupportsFeature 分支判定 Pressed；modifier/F4/Enter 消息判定 Typed。
- _x86_vcall_flow.py：保留同寄存器 xchg 的值与 flags；独立合成回归覆盖 byte/word/dword operand。
- 复用 _career_player_name_common 的 RTTI、构造 this+0 vptr store 和 ABI 校验；复用 function_payload、write_func_yaml、write_vtable_yaml 与 analyzer 签名验证。
- RoundEnd 使用 CSCareerRoundEnd / Resource/UI/CSCareerRoundEnd.res 的交叉 owner；必须写入自己精确 RTTI 的 primary address point，且继承主基类不调整 this。
- MatchEnd 仅检查共享实现，不导出新 hook 目标，不推定具有相同运行时故障。

## 平台、继承与 ABI

10 个配置 / 17 个平台目标 / 13 份不同 SHA-256：
cstrike-3248/3647/4554 Windows；cstrike-6153/8684/10210、czero-8684/10210、czeror-8684/10210 Windows+Linux。
CS/CZ 全部含 RoundEnd/MatchEnd；CZDS 四个平台输入的两个 Career 类不存在，只输出 Frame 方法。早期 CS Linux 未配置。

RoundEnd/MatchEnd → CCSCareerBaseMenu → vgui2::Frame → EditablePanel → Panel → IClientPanel。
Windows COL.offset=0、base PMD=(0,-1,0)，ECX=this、KeyCode 栈参数、ret 4。
Linux R_386_32 typeinfo relocation 指向 __si_class_type_info，offset-to-top=0；_ZTV21CCSCareerRoundEndMenu 是 header，实际 AP 为 +8。Linux 使用 i386 SysV/cdecl，this/key 均栈传参，不是 Windows thiscall。
所有方法表项直接指向普通 Frame 实现，无 this-adjusting thunk，RoundEnd 和 MatchEnd 无这两项 override。

以下槽值是当前输入的核验结果，不是 finder 常量：Windows Pressed 100/0x190、Typed 101/0x194；Linux Pressed 101/0x194、Typed 102/0x198。字符事件分别为 Windows 102 / Linux 103。

| CZ 目标 | RoundEnd AP | Pressed VA | Typed VA |
|---|---|---|---|
| 10210 Windows | 0x100c8c8c | 0x1007bfb0 | 0x1007c0a0 |
| 8684 Windows | 0x019caa0c | 0x01973c60 | 0x01973e20 |
| 10210 Linux | 0x17fbc0 | 0x1155b0 | 0x1173a0 |
| 8684 Linux | 0x1bfc68 | 0x168a10 | 0x167250 |

## 输入身份

相同字节分组：CS 3248=3647 Windows；CS/CZ 10210 Windows；CS/CZ 10210 Linux；CS/CZ 8684 Linux。CS/CZ 8684 Windows 哈希不同，分别验证。3248/3647 以仓库现有 client.decrypt.dll 分析，原 blob 不可用字符串缺失来证明类缺失。

| 代表输入 | platform | SHA-256 |
|---|---|---|
| czero-8684 | windows | `b017e06a5551f3db8c7c817b72a65433362d8b3c8394edb02cac919528e3f73c` |
| czero-8684 | linux | `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798` |
| cstrike-3248 | windows | `2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b` |
| cstrike-4554 | windows | `733d4b48a64991d2cd2a60c20d99f72b6533cc401c47f97cc0e6073bd482b6dc` |
| cstrike-6153 | windows | `221f4c8f8eb6348f90c72c11c252fcf0024d3b3032e503cfab80b3f4c5bee841` |
| cstrike-6153 | linux | `0d379680b7545ed352a696539a8049432651edb7056efbf2ce8354347d0feded` |
| cstrike-8684 | windows | `ef7a0f40989cb79ba95d40f528534da36866892ee871147ca82e133b7a5edc3d` |
| czeror-8684 | windows | `e28ef031c1810a913227fbdf8075a367a60165d209b8071a94020a448ff76286` |
| czeror-8684 | linux | `515bf1bc95ae8ec161cb99a2d25f53efe0744375dde85879b567710074844971` |
| czeror-10210 | windows | `7eccfa2fd50e391dfeca4ada44110b5e6336523f9d5dd1433f043a0daecbb584` |
| czeror-10210 | linux | `37933b1a6afa92c584b4a0b01cc93401317c288bce0eee268d45035ce5ab9890` |
| czero-10210 | windows | `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2` |
| czero-10210 | linux | `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a` |

## 验证方式与适用范围

2026-10-23 最终强制 bounded batch对 17 个 find-client-frame-keys 节点全部成功、零失败/跳过，生成 13 个 vtable + 34 个 vfunc = 47 份 artifacts。分析使用 owned lifecycle；成功结果不经过 LLM/Agent fallback。交互会话按 idb_list → idb_open → idb_close(save=True) 收尾。

源语义参照 D:/HLND2T_official/vgui2/controls/Frame.cpp 的 CloseModal、OnKeyCodePressed、OnKeyCodeTyped、OnKeyTyped。源修订不等于 10210：尤其 Pressed 少额外关闭消息。本笔记不证明下游正式插件运行时修复已生效。


### Task 2 completion gates

- Final forced 17-node matrix: 17 successful, 0 failed, 0 skipped.
- All 10 full schema-8 snapshots and companion metadata built and guarded; catalog dataset guards passed. All 47 new records independently matched the Task 1 address/slot/AP evidence; CZDS contained no Career vtable record.
- Unit: 1546 tests, OK with 12 skips (10 POSIX-only checks on Windows and 2 opt-in release-notes CLI checks). Repository-contract: 15 tests, OK. Format check passed.
- Requested release: v20261023a, tracked mode. Publication is a separate subsequent operation; these local checks do not assert that a release or downstream runtime fix is live.
