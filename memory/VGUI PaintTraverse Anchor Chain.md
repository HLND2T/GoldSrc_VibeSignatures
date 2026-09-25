---
title: VGUI PaintTraverse Anchor Chain
type: note
permalink: goldsrc-vibesignatures/vgui-paint-traverse-anchor-chain
tags:
- engine
- vgui2
- anchors
---

# VGUI PaintTraverse Anchor Chain

## Overview
Issue #243 的 VGUI 绘制链跨越 gameui、engine、vgui2。配置标识沿用 MetaHookSv 字段名，产物身份使用目标二进制的真实类名；VPanelWrapper 属于全局命名空间，VPanel/Panel 属于 vgui2。

## Responsibilities
- 通过当前二进制字符串、RTTI、参数来源和控制流恢复虚函数槽位，避免固定调用序号、偏移或参考版本地址。
- slot-only 接口产物只输出槽位；VPanel::Client 输出函数与槽位元数据但不需要 func_sig。
- 复用已有 BaseUISurface_vtable，跨模块依赖形成真实 DAG。

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-CGameUI_RunFrame.py`、`find-CGameUI_RunFrame-vfuncs.py`：gameui 中 RunFrame 和 ISurface 两个槽。
- `ida_preprocessor_scripts/find-BaseUISurface_PaintTraverse.py`、`find-BaseUISurface_PaintTraverse-vfuncs.py`：engine 中 BaseUISurface 和 IPanel 三个槽。
- `ida_preprocessor_scripts/find-vgui2_VPanel-vtables.py`、`find-vgui2_VPanelWrapper_PaintTraverse.py`：vgui2 中 Wrapper/VPanel 主表、Client getter 和 IClientPanel 绘制槽。
- `ida_preprocessor_scripts/find-vgui2_EditablePanel_CreateControlByName.py`、`find-vgui2_Panel_ctor.py`、`find-vgui2_Panel_vtable.py`、`find-vgui2_Panel_PaintTraverse.py`：engine 内链接的控件实现。
- `ida_preprocessor_scripts/_x86_vcall_flow.py`：有界 x86 CFG 值流；`_vgui_paint_common.py`：IDA 解码与当前 RTTI 适配。
- 参考源码：`D:/HLND2T_official/gameui/GameUI_Interface.cpp:637`、`engine/vgui2/BaseUISurface.cpp:1427`、`vgui2/src/VPanelWrapper.cpp:243`、`vgui2/controls/EditablePanel.cpp:971`、`vgui2/controls/Panel.cpp:61`。

## Architecture
1. gameui 的 `FULLMATCH:ActiveGameName` 唯一 xref 定位 CGameUI::RunFrame，并确认 CGameUI 主虚表成员身份。同源 surface getter 的 GetScreenSize 参数形态、modal 判零控制流和 static panel VPANEL 参数确定 GetModalPanel/PaintTraverse。
2. engine BaseUISurface 从 ISurface 的当前槽位继承。函数入口的 panel 可见性 guard、循环内 popup false 写入和多处 true/true 绘制参数确定 IPanel 三个槽。
3. vgui2 的 VPanelWrapper 主表验证 IPanel RTTI 基类及 VGUI_Panel007 注册。继承 IPanel paint 槽后，沿 Wrapper::Client → VPanel::Client → IClientPanel::PaintTraverse 恢复内层槽位；VPanel getter 必须返回 client-panel 成员。
4. engine 工厂由 `FULLMATCH:MessageBoxText` 与 `FULLMATCH:ResourceImagePanel` 的 xref 交集定位。其 Panel 相等分支中分配对象、传入两个 null 的构造调用必须安装当前 Panel 主虚表。Panel 从 IClientPanel paint 槽继承实际可调用入口。

## Dependencies
- 全部 11 个 engine 家族标签：hl-3248/3266/3329/3647/4554/6153/8684/10210、cof-5936、svencoop-8948/10257。
- Linux 仅配置声明的 hl-8684、hl-10210 与两个 Sven 标签，共 15 个版本/平台组合、45 个模块二进制。其余 Linux 不属于生产配置；没有 CS-only client 目标。
- 旧四版 BLOB engine 使用现有 hw.decrypt.dll；不能把加密 hw.dll 无匹配误报为符号缺失。
- [[idalib-mcp]]：每个二进制使用自有生命周期与 expected_binary 绑定，验证数据库输入身份。

## Notes
- 触发信号：HL25/SvEngine Linux 的间接调用数量与旧版不同。根因：两级 Client 去虚化，以及 HL25 最后的间接尾跳。正确做法：跟踪函数指针比较、内联成员加载与慢路径返回的合流，确认同一 Client 对象和 forceRepaint/allowForce 转发；不能计数 call。验证：在两种 ABI 的当前虚表和反汇编上复核，运行所有适用 finder。
- 触发信号：布尔参数来源在 Linux 合流后丢失。根因：编译器使用 byte spill 与 movzx。正确做法：保留窄值来源用于布尔参数/guard，同时禁止窄值成为虚表指针；处理隐式寄存器写入、调用覆盖和栈别名。验证：`tests/test_x86_vcall_flow.py` 的合成 CFG 行为测试及全版本二进制运行。
- 触发信号：Sven Linux Panel 工厂有明确构造调用但无候选。根因：operator new 经导入 PLT，local_call_target 不返回本地函数。正确做法：允许静态导入分配调用，仍要求 null/null 参数和构造体安装当前 Panel vptr。验证：Sven Windows/Linux 的实际工厂分支。
- 触发信号：已定位构造函数但短 func_sig 不唯一。根因：内联 message-map 初始化让不同构造函数共享超过 256 字节的前缀。正确做法：保持地址/分支操作数通配，在函数体内逐步扩展签名预算并验证唯一命中；不能固化 vtable 地址。验证：当前 IDB find_bytes 必须仅命中已确认入口。
- 参考源码使用 vgui 命名空间，当前 Linux 二进制使用 vgui2；最终身份以二进制为准。Panel::PaintTraverse 的 .part/.constprop 热片段不能替代虚表内实际入口。
- observed ABI slots（仅核验记录，不是 finder 常量）：Windows/Linux 分别为 CGameUI RunFrame 7/8、ISurface modal 53/54、surface paint 78/79、IPanel visible 15/16、popup 26/27、paint 41/42、Wrapper Client 58/59、VPanel Client 38/39；IClientPanel paint 均为 3。所有槽宽为 4 字节。

- 触发信号：CoF Windows 的 Wrapper PaintTraverse 反编译把三个参数交给 Client，最终 PaintTraverse 却似乎没有布尔参数。根因：编译器提前 push 两个 paint 参数，IDA 错把这些 push 都计入 Client 清栈量，且布尔值只写 AL/CL。正确做法：保留低字节参数来源，从当前 Wrapper 主表解析 Client 实现并读取一致的 RET 清栈量，在临时 IR 中校正后续栈位置；不修改 IDB、不固化调用参数数目。验证：合成的提前压栈与错误 SP delta 测试，以及 CoF 的 11 个 production 节点。

- 2026-09-25 最终二进制验证：全 11 个标签、15 个平台组合、45 个二进制的 bounded batch 执行 165 个节点（10 个新增 finder 加既有 EngineSurface-vtables），90 个调度工作项全部成功，退出码 0。生成 240 份新增 YAML；逐份检查身份字段、32 位地址、4 字节槽位、slot-only/no-signature 边界及跨模块虚表继承一致性。函数签名经当前 IDB 唯一命中验证。完整 unit 运行 1167 项，成功，5 项跳过。
