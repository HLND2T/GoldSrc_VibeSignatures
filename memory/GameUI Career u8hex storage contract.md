---
title: GameUI Career u8hex storage contract
type: note
permalink: goldsrc-vibesignatures/game-ui-career-u8hex-storage-contract
tags:
- gameui
- career
- gamedata
- abi
---

# GameUI Career u8hex storage contract

## 范围与职责

对应上游 [#390](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/390)、消费端 [VGUI2Extension #20](https://github.com/MetaHookSv/VGUI2Extension/issues/20) 与原始 [MetaHookSv #939](https://github.com/MetaHookSv/MetaHookSv/issues/939)。交付语义 finder、函数/虚函数、12 组 patch、容量/策略/ABI scalar、3 个成员，以及静态证据。模块始终是共享 Half-Life `gameui`，不是 `czero/client`。

Windows hl-10210、hl-8684 与 issue 940 附件 cstrikegameui-8684 有完整静态消费契约；Linux hl-10210 和 hl-8684 独立导出用于语义/ABI 交叉核验，不代表 Windows 插件已支持 Linux。其他 GameUI 均经过调查，未证明完整性的 identity 不启用记录。插件 handler、文件迁移、游戏内验收和偶发磁盘错误仍属于消费端任务。本记录不是运行验证报告。

固定新键为 `u8hex-` + 完整原始 UTF-8 名字的 lowercase hex。31 字节输入得到 68 字符键，另需 NUL。不得经过旧 32 字节 sanitizer/button/selected-name 存储。原始显示名字保留在 CZP。

## 文件与发现流程

- `ida_preprocessor_scripts/find-GameUI-career-storage.py`：DAG 入口，复用已发布 `CCareerDifficultyBox_ctor` 输入。
- `_career_storage_collect.py`：从全部 CZProfile 路径引用、CFG 命令、UI 命令与当前 RTTI 交集定位完整 owner，使用真实 x86 数据流恢复实参、成员和调用点；验证唯一性、原始指令、清栈及所有消费者覆盖。
- `_career_storage_identity.py`：纯粹的分支能力、容量与连续编号检查。
- `_career_storage_common.py`：准备完整集合后写 YAML；当前入口/调用点特征必须唯一。既有签名和调查地址均不参与发现。
- `configs/hl-10210.yaml` 和 `configs/hl-8684.yaml`：Windows/Linux storage，Windows runtime；`configs/cstrikegameui-8684.yaml`：issue 940 附件的 Windows storage/runtime。其余 identity 未新增注册。
- `tests/test_career_storage_identity.py`：直接/间接调用、错误 JMP/非调用、容量、歧义、编号与重复覆盖负例。
- [逐构建调查](evidence/career-storage/support-audit.json)、各 identity 的 JSON 机器证据与 [CZP 格式指令](evidence/career-storage/czp-format.windows.md)。JSON 绑定输入 SHA-256，保留 entry/return/call 指令、调用点附近字节、完整数据流与 owner。地址表均为测量结果，不能作为别的构建的发现常量。

在支持 identity 上必须整体解析成功后才能安装 hooks；消费端还须按既有初始化阶段的 `g_bIsCZero` 判定运行模式。缺失、冲突、策略/ABI 或编号错误应 fail closed，不引入运行时扫描 fallback。

## 入口 ABI

Windows PE32/I386 imagebase 为 `0x10000000`，Linux ELF32/I386 imagebase 为 0。下面全部地址是 RVA。所有运行入口均为真实 standalone 公开包装器；`OnCommand` 是实际虚槽，其余非虚函数不伪装成虚函数。

Windows 普通成员入口：`ECX=this`，显式参数从进入函数时 `[ESP+4]` 起按声明顺序，callee 清理表列字节；void 无返回契约，bool 为 AL，profile 指针为 EAX。GetProfileForName/DeleteProfile 的 this 在实现中未读取，但应保留成员调用约定。Linux 公开普通成员入口为 cdecl，`[ESP+4]=this`，随后显式参数，caller 清理全部参数；bool 为 AL、指针为 EAX。PopulateProfiles 返回 EAX 中的档案数量 int（vector finish-start 除以指针宽度），不是 void；Windows 返回值计算与两个 Linux DWARF 的 int 声明分别保留在证据中。这些结论由调用者实参/返回值用途、入口与返回指令共同核对，不能用反编译器自动原型替代。

| 完整 symbolName | Win10210 RVA / size / 清栈 | Linux10210 RVA / size | Linux8684 RVA / size | 返回值 |
|---|---|---|---|---|
| `CCareerGame::CreateBlankProfile()` | 0x19a50 / 0x1fc / 0 | 0x6d8b0 / 0x55a | 0xbdcf0 / 0x7ce | void |
| `CCareerGame::SaveProfile(bool)` | 0x1a890 / 0x1ad / 4 | 0x6f840 / 0x33b | 0xbe690 / 0x2e8 | bool in AL |
| `CCareerGame::LoadProfile(CareerDifficultyType)` | 0x1a190 / 0x127 / 4 | 0x6fb80 / 0x2b4 | 0xbe980 / 0x26b | bool in AL |
| `CCareerGame::GetProfileForName(char const*)` | 0x19e10 / 0x2fa / 4 | 0x6ed60 / 0x482 | 0xbd800 / 0x4ec | native profile pointer in EAX |
| `CCareerGame::DeleteProfile(char const*)` | 0x19da0 / 0x61 / 4 | 0x6d6c0 / 0x131 | 0xbe4c0 / 0x10a | void |
| `CCareerGame::SendMatchCommand()` | 0x147b0 / 0xd19 / 0 | 0x656e0 / 0xd52 | 0xb3d30 / 0x1041 | void |
| `CCareerProfileFrame::PopulateProfiles()` | 0x1c940 / 0x3cf / 0 | 0x70820 / 0x772 | 0xc0300 / 0x6f7 | int profile count in EAX |
| `CProfileButton::SetProfileName(char const*)` | 0x1b4c0 / 0x27 / 4 | 0xc4c90 / 0x33 | 0x104680 / 0x33 | void |
| `CCareerProfileFrame::UpdateSelectedProfile(char const*)` | 0x1cd50 / 0x93 / 4 | 0x71010 / 0x80 | 0xc12d0 / 0x75 | void |
| `CCareerProfileFrame::OnCommand(char const*)` | 0x1be50 / 0x711 / 4 | 0x71890 / 0x8c2 | 0xc0a00 / 0x869 | void |
| `CCareerNewProfileBox::OnCommand(char const*)` | 0xfa70 / 0x3d / 4 | 0x61120 / 0x15c | 0xaf8d0 / 0x140 | void |

两个 OnCommand 的 Windows 实际槽均为 87（byte offset 348），两个 Linux identity 均为 88（352）；artifact 提供地址/槽位，两者一起核对。

复用的完整构造函数 symbolName 是 `CCareerDifficultyBox::CCareerDifficultyBox(char const*, vgui2::Panel*)`：Win10210 RVA `0xf070`，ECX=this，栈上先 panelName 后 parent，EAX=this，`ret 8`；Linux10210 `0x61590`、Linux8684 `0xb02e0`，C1/C2 同址完整入口，cdecl(this,panelName,parent)，构造函数声明无返回值。不能改成父控件在前的猜测原型。GetProfileForName 所有直接调用者均属于该已发布完整构造函数，输入来自独立 sanitizer 的返回值，是 LegacyKey，不是 raw name；JSON 保存调用点和 provenance。

### 仅分析入口与 clone

这些入口不要求 detour；BuildProfileList 尤其不能当作可跨 CRT 返回 vector 的普通函数。

| symbolName | Windows10210 RVA / ABI | Linux10210 RVA / ABI | Linux8684 RVA / ABI |
|---|---|---|---|
| `CCareerGame::GetSaveGamePlayerName(char const*)` | 0x1a110 / static cdecl(rawName)，EAX=static char*，caller 清栈；无 this | 0x6d800 / 同左 | 0xbe5d0 / 同左 |
| `CCareerGame::BuildProfileList()` | 0x194e0 / ECX=this（未使用），隐藏返回对象地址位于第一个栈参数，EAX=返回对象，ret 4 | 0x6e760 / 隐藏返回地址先于 this，callee 仅弹隐藏参数 4 字节；其余 caller 清栈 | 0xbebf0 / 隐藏返回地址先于 this，callee 仅弹隐藏参数 4 字节；其余 caller 清栈 |
| `CCareerGame::CreateProfileBuffer(CCareerProfileData*, unsigned char*, int, bool)` | 0x19c50 / thiscall(save,buffer,length,blank)，ret 16，EAX=int size | 0x6d240 / cdecl(this,save,buffer,length,blank)，EAX=int size | 0xbcbf0 / cdecl(this,save,buffer,length,blank)，EAX=int size |
| `CCareerGame::ParseSavedProfile(unsigned char const*, int, CCareerProfileData*)` | 0x1a560 / ECX=this 未使用，栈 data,length,save，ret 12，AL=bool | 0x6e6a0 / 公开 cdecl(this,data,length,save)，AL=bool；与内部 clone 不同 | 0xbc5e0 / 公开 cdecl(this,data,length,save)，AL=bool；与内部 clone 不同 |
| `CCareerGame::StopMatch(int, int)` | 0x155c0 / thiscall(ctWins,tWins)，ret 8，void | 0x65150 / 公开 cdecl(this,ctWins,tWins)，void | 0xb2e80 / 公开 cdecl(this,ctWins,tWins)，void |
| `CProfileButton::OnMouseDoublePressed(vgui2::MouseCode)` | 0x1b360 / thiscall(MouseCode)，ret 4，void | 0xc4cd0 / cdecl(this,MouseCode)，void | 0x1043a0 / cdecl(this,MouseCode)，void |

Linux10210 ParseSavedProfile 的 `.part.59.constprop.63` 位于 `0x6e170`：this=EAX、data=EDX、length=ECX、save 为栈参数，caller 清栈。StopMatch `.part.91` 位于 `0x62b80`：this=EAX、ctWins=EDX、tWins=ECX。公开包装器先恢复这些寄存器再尾跳；不得将内部 ABI 套到公开函数。

Linux8684 CreateProfileBuffer `.constprop.78` 位于 `0xbcfc0`：this=EAX、save=EDX、buffer=ECX，blank 为栈参数，容量在 clone 中固定为 0x4000，EAX=size；公开 `0xbcbf0` 仍是 5 参数 cdecl ABI。finder 分别记录 clone 与公开包装器，不将 clone 作为运行入口导出。

两个 Linux 输入都有 `.symtab` 与 `.debug_info/.debug_loc`；`dwarf-*.txt` 来自对对应 binary 执行 GDB ptype，仅作类型交叉证据。优化后的寄存器、隐藏返回与清栈以指令为准，DWARF 声明不会自动成为可调用 hook ABI。

## 路径消费者与身份覆盖

RawName=原始玩家显示名字；LegacyKey=原版净化后的键；CanonicalKey=消费端作用域拥有的新键；RealFilename=枚举返回的磁盘真实文件名（不能再套 CZProfile 前缀）。下面 Windows 表的组均为完整组名去掉末尾 `_N`。每个调用点都另发 `_instruction_length`、`_hook_strategy`、`_abi` scalar；组发 `_count`，格式化组发 `_destination_capacity`。原始目标、寄存器/栈实参和指令上下文见 JSON。

| owner → 调用组 | Win patch RVA | 输入 → 输出 | 容量/边界 | ABI / 策略 |
|---|---|---|---|---|
| `CCareerGame_CreateBlankProfile_profile_path_format_callsite_0` | 0x19bbd | saveDir + LegacyKey → CZProfile 路径；替代键来自当前操作 RawName scope | 260 | 1 / 0，5 字节 `e8 9e 9a fe ff` |
| `CCareerGame_SaveProfile_profile_path_format_callsite_0` | 0x1a909 | saveDir + LegacyKey → CZProfile 路径；替代键来自当前操作 RawName scope | 260 | 1 / 0，5 字节 `e8 52 8d fe ff` |
| `CCareerGame_LoadProfile_profile_path_format_callsite_0` | 0x1a1de | saveDir + LegacyKey → CZProfile 路径；替代键来自当前操作 RawName scope | 260 | 1 / 0，5 字节 `e8 7d 94 fe ff` |
| `CCareerGame_GetProfileForName_profile_path_format_callsite_0` | 0x19e5f | saveDir + LegacyKey → CZProfile 路径；替代键来自当前操作 RawName scope | 260 | 1 / 0，5 字节 `e8 fc 97 fe ff` |
| `CCareerGame_DeleteProfile_profile_path_format_callsite_0` | 0x19dd4 | saveDir + LegacyKey → CZProfile 路径；替代键来自当前操作 RawName scope | 260 | 1 / 0，5 字节 `e8 87 98 fe ff` |
| `CCareerGame_SaveProfile_config_command_format_callsite_0` | 0x1aa03 | LegacyKey → Save CFG 写入/读取命令；替代键来自操作 scope | 260 | 2 / 0，5 字节 `e8 18 8c fe ff` |
| `CCareerGame_SendMatchCommand_config_command_format_callsite_0` | 0x152f4 | LegacyKey → Save CFG 写入/读取命令；替代键来自操作 scope | 1024 | 2 / 0，5 字节 `e8 27 e3 fe ff` |
| `CCareerProfileFrame_PopulateProfiles_select_command_format_callsite_0` | 0x1ca7e | 枚举所得完整 RawName → SelectProfileAndFocus 命令；应替换为 sidecar 身份 token | 62 | 2 / 0，5 字节 `e8 9d 6b fe ff` |
| `CCareerProfileFrame_selected_name_copy_callsite_0` | 0x1cbb4 | 完整选择输入 → frame 截断名字；在复制前捕获身份，原复制仍保持有界 | 32 | 5 / 0，6 字节 `ff 15 bc 01 09 10` |
| `CCareerProfileFrame_selected_name_copy_callsite_1` | 0x1cd63 | 完整选择输入 → frame 截断名字；在复制前捕获身份，原复制仍保持有界 | 32 | 5 / 0，6 字节 `ff 15 bc 01 09 10` |
| `CCareerProfileFrame_ResumeProfile_name_set_callsite_0` | 0x1c1a9 | frame 截断名字 → Cvar_Set(name,value)；scope 中替换为完整 RawName | 不向名字缓冲区写入 | 11 / 2，2 字节 `ff d0` |
| `CProfileButton_OnMouseDoublePressed_select_command_format_callsite_0` | 0x1b394 | button 截断名字 → UTIL_va 返回 SelectProfile 命令；由 sidecar 构造 token | 不向名字缓冲区写入 | 6 / 0，5 字节 `e8 97 9b 01 00` |
| `CCareerGame_BuildProfileList_ReadFile_callsite_0` | 0x195d7 | saveDir + RealFilename → rb Open；重复 legacy 项返回无文件继续枚举 | 不向名字缓冲区写入 | 7 / 1，3 字节 `ff 52 28` |

Create/Save/Load/Delete 中 sanitizer 可能内联，GetProfileForName 接收已净化键；因此只 detour 独立 GetSaveGamePlayerName 不构成覆盖。StopMatch 调用 SaveProfile；它的 `exec config.cfg` 不含玩家身份，不属于 Save/<key> 路径。全部 5 个 CZProfile-%s owner 与两个 Save CFG 命令均逐项核验。

`CProfileButton::SetProfileName(rawName)` 在原 `strncpy(...,32)` 前接收完整名字，捕获到 button sidecar。PopulateProfiles 的首选/默认 focus 命令在按钮复制之外也要替换。Frame 的 UpdateSelectedProfile 及所有内联副本在截断前捕获选择身份：Win 为 `_0` 0x1cbb4 与 `_1` 0x1cd63；Linux10210 为 8 个，Linux8684 为 7 个，不能盲目照搬 `_1` 数量。双击使用 button.m_name 生成命令，有独立补充组。ResumeProfile 名字设定必须取 sidecar 的完整 RawName。UI token 与显示名字不同，不能将 CanonicalKey 写入 UI 旧名字字段。

Windows PopulateProfiles 目的临时区物理边界为 64 字节，原 snprintf 限额为 62，发布的是实际可用 62。UTIL_va 原始实现有四槽 1024 字节 ring；替代 handler 应为同步命令链持有自己的结果，不能依赖截断 button 字符串或将返回字符串写回旧字段。Button receiver 可由当前字符串实参减去发布的 m_name 偏移恢复。

### Hook 能力与恢复

- 策略 0：现有 MetaHook `InlinePatchRedirectBranch` 接受 E8 rel32、FF15 import 和至少 5 字节的间接 CALL。Win 字符串复制为 FF15/6 字节；Linux Resume 是 `FF 90 e4 01 00 00`/6 字节。对 register-relative 目标，不可依赖原始目标解码器；从真实 public 实例/表取得原调用目标。hook handle 保存并恢复整条原始指令及 NOP 填充长度。
- 策略 1：Win BuildProfileList 的 ReadFile 已内联，patch 0x195d7 是 `FF 52 28`/3 字节的 filesystem Open。使用已有 VFTHook/VFTHookEx 钩住实际 GameUI filesystem 的 public Open，仅在返回地址为 site+3、receiver 一致、options=rb 且处于枚举 scope 时过滤。返回无文件沿原失败分支继续枚举；不能覆盖短指令。卸载用现有 hook handle 恢复槽。
- 策略 2：Win Resume patch 0x1c1a9 是 `FF D0`/2 字节 call eax；0x1c1a3 是装载 engine+0x1e4 的 MOV，不是 CALL。由现有 InlineHook 钩住 public engine Cvar_Set，仅对 site+2 且 name/scope 匹配的调用替换完整名字，其他调用原样透传；卸载恢复入口。无需扩展 MetaHook 公共 API。
- Linux10210 ReadFile 0x6e85e 为直接 CALL，但内部 static ReadFile 0x6c750 通过 EAX=path、EDX=int*length 返回 EAX=buffer（ABI 10），不是普通 cdecl。Linux8684 同样是 register ReadFile（ABI 10），调用点 0xbecb5；ABI 9 只保留为真正 cdecl 版本的编码，不将其套在该构建。保留函数原有分配/释放协议；本交付不跨 DLL 传 vector。

ABI scalar 编码：1 cdecl sprintf(dst,fmt,...), 2 cdecl snprintf(dst,n,fmt,...), 3 cdecl __sprintf_chk(dst,flag,objectSize,fmt,...), 4 cdecl __snprintf_chk(dst,n,flag,objectSize,fmt,...), 5 cdecl strncpy(dst,src,n), 6 cdecl UTIL_va(fmt,...)→char*, 7 thiscall Open(path,options,pathID)→FileHandle（ret12）,8 cdecl Open(this,path,options,pathID),9 cdecl ReadFile(path,int*),10 register ReadFile(EAX path,EDX int*)→EAX,11 cdecl Cvar_Set(name,value)。所有 formatter 都是 caller-cleanup 变参，必须保留全部实参；变参 wrapper 不能仅按 Hex-Rays 显示的参数数目实现。

### 容量、成员与 filesystem

Win profile 路径均 260，SaveProfile writecfg 命令 260，SendMatchCommand exec 命令 1024，枚举路径 260；Linux profile/枚举路径 4096，SaveProfile writecfg 4096，SendMatchCommand 1024。名字字段/legacy key 均 32，序列化 scratch 16384，均由各 identity 的数据流独立得出并发布语义 scalar。

成员布局独立恢复如下，偏移/大小均来自对应 identity：

| Identity | CProfileButton.m_name | CProfileButton.m_active | CCareerProfileFrame.m_name |
|---|---|---|---|
| hl-10210 Windows | 0x13c / 32 | 0x110 / 1 | 0x1f8 / 32 |
| hl-10210 Linux | 0x13c / 32 | 0x10f / 1 | 0x1f8 / 32 |
| hl-8684 Linux | 0x138 / 32 | 0x10b / 1 | 0x1f0 / 32 |

UI 生命周期、父控件和重绘继续用公开 VGUI 接口，不复制 STL 布局。

Win GameUI `vgui2::filesystem()`（RVA 0x50b90）与初始化（0x508a0）使用同一实例，factory 请求 `VFileSystem009`。此 GameUI 实际调用 legacy IFileSystem（Open槽10、Write槽22），不能按 engine build>=10000 推断文件系统接口布局。#20 czero 10210 运行断点确认 GameUI 实例等于消费端 g_pFileSystem，g_pFileSystem_HL25 为 null；消费端安装时核对同一 legacy 公共实例后使用 SDK 的 Open/Write/Close/Flush/IsOk。MetaHook 的接口判断由实际 vtable 决定，HL25 引擎版本不保证插入 GetFileChangeTime 的接口存在。Linux 多析构槽仍需遵循自己的平台 ABI，不复制 Windows 槽位。

基础 v20261020b 契约仅在路径 formatter 处交付 activeCareer.saveDir，不提供操作入口的提前读取。消费端 #20 后续采用更强的入口预检和序列化溢出检查；经用户明确授权，另增 Windows hl-10210 的 runtime contract v1（14 条，尚待独立发布），见下节。只读取最小指针链/标志，不复制 CCareerProfileData STL 布局。

## Legacy 与 CZP 有界 inspector 证据

独立 GetSaveGamePlayerName 是 static cdecl，无 this。向静态缓冲区 strncpy32，显式写 byte31=NUL，循环前31字节，允许字符为 `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789`，其他非零字节换为 `_`；原 UTF-8 多字节逐字节丢失。它返回共享静态指针；内联副本也采用此行为。消费端应在外层保存 RawName，不把临时 LegacyKey 当身份。

Windows serializer 写 NUL 结尾 `CZP`（前4字节 `43 5a 50 00`），offset4 写 LE32 version=4，offset8 起是原始显示名字的 NUL 结尾字节串。随后 slider LE32、version4 lastDifficulty 字节、4 个 medal 字节、4 组 difficulty 数据、tutoring count 和数据，最后 LE32 checksum。Parse 接受 version1..4；lastDifficulty 只在4存在，旧格式不能按固定4布局向后猜测。

checksum 是对末尾 checksum 前的全部无符号字节求 `sum((i+1)*byte[i]) mod 2^32`，末尾4字节按 little-endian 比较。WriteString/WriteLong、parser、scalar/SSE checksum 指令见格式证据。只检查 checksum 不是完整 CZP 结构有效性的证明。

安全 inspector 可先限制文件总长（原写入scratch16384）、至少保证 header/name/末尾checksum边界，验证 magic、LE版本1..4，在 checksum 前有界找 name NUL，按产品输入规则限制 UTF-8 名字后比较完整原始名字，并独立计算 checksum。完整的可加载性还须独立有界解析所有变长区或由原游戏正常读取，不靠 header/checksum 宣称整份文件有效。不要调用 native BEGIN_READ/READ_*：它们修改 GameUI 全局 reader 的 message/length/cursor/error，可能破坏嵌套解析。checksum 本身没有身份认证能力。

## 支持矩阵与证据缺口

| Identity | 平台 | 结果 |
|---|---|---|
| hl-10210 | Windows | 导出92条，11入口、13调用点、12连续组；消费端 Windows 唯一启用 identity |
| hl-10210 | Linux | 独立导出116条，11入口、19调用点；静态交叉核验 |
| hl-8684 | Linux | 独立导出112条，11入口、18调用点；static clone 单独记录 |
| hl-8684 | Windows | storage 92条 + runtime 14条；已修复间接调用清栈和旧 frame 别名造成的分析拒绝，见下文 issue 940 补充 |
| cstrikegameui-8684 | Windows | issue 940 非 Steam GameUI 变体，独立 CRC64；storage 92条 + runtime 14条 |
| hl-3248/3266/3329/3647/4554/6153 | Windows | 尚未重新验证：原调查的 frame-item 60/CRT 62 拒绝记录仍是历史证据，不能推断修正已覆盖这些 identity |
| cof-5936 | Windows | 无新记录：m_active 布局/写入身份无法唯一确认 |
| svencoop-8948/10257 | Windows/Linux | Career 路径实现不存在，无新依赖 |
| cstrike/czero/czeror client identities | 仓库声明平台 | 不在 client 放共享 GameUI 记录；issue 940 的 GameUI 使用独立 cstrikegameui-8684 tag |

所有已配置 gameui identity 的输入 SHA-256、实际拒绝原因或 absence 负例在 support-audit.json；10210 的两项 SHA 在各自证据 JSON。未验证版本不从10210复制偏移/长度/ABI。

## 验证与交付

对三个注册节点，在隔离 artifactdir 只预置已发布的完整 difficulty ctor 输入后执行标准 `ida_analyze_bin.py -skill find-GameUI-career-storage -oldgamever none`：10210 Windows/Linux 成功2、失败0、跳过0；8684 Linux 成功1、失败0、跳过0。重建320条产物逐字节等于待提交 YAML，不把 skip 当重建通过。每个函数/patch 的唯一特征由标准产物验证器核对。

消费端更新 manifest G25（hl-10210/gameui Windows，92条及12个编号组）、validator 和中英文 gamedata 文档。必须用实际完整 snapshot→metadata→JSON catalog→真实 manifest 裁剪→同步器/validator 检查；容量/策略/ABI 在裁剪后仍须存在。最终执行结果和发布版本由对应 PR/release 记录，未发布前不部署该 manifest。PR/release 应在 #390 与 #20 互链；静态成功不能替代真实游戏验收。

最终本地检查：1552 项完整仓库测试通过、13 项按环境/平台/opt-in 条件跳过；消费端6项回归通过。完整21版本 catalog 通过真实 manifest 裁剪后，同步器目录哈希/coverage 与正式 validator 均通过，92条 Windows新记录全部保留；见 [验证报告](evidence/career-storage/validation.json)。原始 catalog 总记录数与裁剪记录数不同，不能仅以原始 JSON 候选存在作为消费通过。

## Windows hl-10210 runtime contract v1（#20 后续，待发布）

触发信号：消费端必须在创建目录前取得活动 saveDir，并在 `wb Open` 截断目标前证明完整序列化未溢出；公开 v20261020b 没有交付这些入口证据。根因/约束：serializer 即使溢出仍返回已写长度，WriteString 会以空串替代放不下的字符串，不能只检查返回长度或 checksum。

`find-GameUI-career-runtime.py` / `_career_runtime_common.py` / `_career_runtime_identity.py` 从当前 IDB 的五个独立路径消费者共同恢复相同三层 pointer chain，解码真实绝对操作数生成 GV 特征；不是按旧 VA 定位。该直接 GV 方法作为比邻近全局/模型猜测更强的证据例外，原因写在 helper docstring。只注册 Windows hl-10210；输入 GameUI.dll SHA256 `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811`。

新增 14 条：

| 类别 | symbolName / 数据（RVA 或 member offset） |
|---|---|
| global | `CareerStorage_Definitions` 0xc2068；`CareerStorage_Game` 0xc206c；`CareerStorage_FileSystem` 0xc6b6c |
| structMember | `CCareerDefinitionManager.m_activeCareer` 12 / pointer4；`CCareerDefinition.m_saveDir` 24 / pointer4（不是内联字符数组） |
| structMember | `CCareerGame.m_profileWriter` 8 / pointer4；`BufferWriter.m_overflow` 8 / bool1；`CCareerGame.m_needAutosave` 66 / bool1 |
| structMember | `CCareerNewProfileBox.m_pNameEntry` 324 / pointer4；`vgui2::TextEntry.m_textLength` 136 / int4 |
| function | `CCareerGame::CreateProfileBuffer(CCareerProfileData*, unsigned char*, int, bool)` RVA 0x19c50 / size0x143；thiscall，ret16，EAX=int length |
| virtualFunction | `vgui2::TextEntry::GetText(wchar_t*, int)` RVA0x62ec0 / size0x42；slot136，thiscall ret8；消费端忽略返回值 |
| scalar | `CareerStorage_runtime_contract_version=1`；`CCareerNewProfileBox_native_input_capacity=64` |

正确做法与指令证据：

- saveDir：Create path 在 0x19ba1 载入 root，0x19bab 读取 manager+12，0x19bae **push dword ptr [active+24]**。五个消费者一致证明它是字符串指针。提前读取后仍与 formatter 的实参核对。
- writer：Init RVA0x1950 设置 cursor+0、remaining+4、overflow+8=false、capacity+12。WriteByte0x1ad0、WriteLong0x1b00、WriteString0x1b50 在容量不足时置 overflow+8=true；WriteString 0x1b88 还会改写输入为空串。serializer 之后、Open 之前必须读取 overflow 并有界解析整个返回 buffer、核对 raw name。Create 的 serializer call0x19be2 在 wb Open0x19c00 前；Save 同样先 serializer 后 Open0x1a9b9。原生写入均一次 Write（legacy槽22），一次 Close（槽11）；不能把 bool 返回当作短写检查。
- needAutosave：Save0x1a8a6 比较 byte[this+66]，为0则在0x1a8ac设置AL=1并于0x1a8bc ret4，完全绕过分配/formatter/I/O。消费端保留此 no-op 语义。
- 输入：原 NewProfileBox Ok 调 Apply(1)，其 char[64] 最多取得63字节。宽 getter0x62ed8 比较 **length >= argument-1**，0x62ee0 wcsncpy 的第三实参直接为 wchar_t 元素数，随后0x62eeb写 Destination[length]=0；没有除以2。因此本 binary 的 int 参数是**字符数**，虽然外部 SDK header 写 bufLenInBytes。不要按其他 SDK 实现改成字节数。读取 m_textLength 后分配 length+1 wchar_t 并传 length+1。
- NewProfileBox0xfa70 的 Ok 分支只做 Apply 后把 command 换成 CreateProfile；公共基类 handler0xf980 对非 close 命令 PostActionSignal(Command)，之后调用关闭虚槽。消费端可转发携带完整无损身份的私有命令跳过 Apply，保留 native 分配/销毁。当前接入用 CareerStorageNew + canonical key 传递身份，在覆盖确认与预检后才设置引擎 raw cvar，验证回读并在写入失败时恢复旧值；取消覆盖不改变 name。

验证方式：标准 `ida_analyze_bin.py -gamever hl-10210 -modules gameui -skill find-GameUI-career-runtime -platform windows -oldgamever none` 已重建14条；纯 pointer-chain 合成布局/歧义负例测试、完整 unit/repository-contract、格式门禁另行记录在消费端交付说明。该节是静态 ABI 证据，不等同所有故障或兼容构建的运行保证。

适用范围：仅此 Windows GameUI identity。v1..v3 CZP 的完整变长结构依指令和合成测试覆盖；现有真实样本与 #20 新创建/保存样本为 v4，不能声称已取得真实旧版本样本。

## Runtime v1 本地验证补充（2026-10-20）

14 条标准 analyzer 产物已重建，unit 套件通过（12 项跳过）、repository-contract 15 项通过、仓库格式门禁通过。消费端真实 manifest G26 裁剪后 hl-10210 为 202 条（原 188 + 14）；21 个版本经正式同步器离线缓存发布和 validator 检查通过。这里的本地发布指生成消费目录，公共 catalog 尚未发布 runtime v1；历史 evidence/career-storage/validation.json 仍记录基础 v20261020b 的 92 条交付，不作为本次 runtime v1 的报告。

Definitions artifact 的 GV 锚点选择 Create 中较早的 0x19b1f 六字节 root load；上述 0x19ba1 五字节 load 是同函数后续 path 消费链的交叉证据，两者读取同一个 global 0xc2068。

消费端 Windows x86 czero 10210 实机覆盖了两种碰撞中文名、全下划线旧键、31字节前缀相同的长名、A/a；两次实际开赛/StopMatch 保存与重启恢复独立 cfg；自建 mission pack 中 legacy-only 读取/正常保存迁移、去重、删除两份同身份 CZP 并保留 cfg；损坏 canonical、只读 Open 失败和旧 ASCII 占用 canonical namespace 均拒绝覆盖且目标哈希未变。最终 DLL 再验取消覆盖与写失败后 name 不变，正常新建进入难度框。原游戏 31 文件恢复并逐项 SHA256 核对；测试目录清理。短写/flush/overflow 失败由纯策略注入覆盖，未在真实磁盘接口注入；真实 v1..v3 样本、其他构建/CZDS 仍未做运行验收。

## Issue 940：旧 Windows 栈分析与独立 GameUI 输入（2026-10-21）

- 触发信号：CS 8684 报 `CGameConsoleDialog::CGameConsoleDialog()`，状态为模块 CRC64 未登记；补做 HL10210/HL8684 覆盖比对时，旧 Windows storage 被 `CRT limit exceeds the destination` 拒绝。
- 根因与约束：附件 GameUI.dll SHA256 `a07b97c42292aab1b12c791b3b6847e47da1c8bbb8d430c1900d2f60cd65db86`、CRC64 `647fc98d499b3a1c`，不在 CS Steam depot 清单内。不能给官方 Steam tag 虚构 depot 路径；独立注册 `cstrikegameui-8684`，仅含 GameUI 和必要的 HL8684 engine/vgui2 DAG 前驱。
- 栈分析根因：PopulateProfiles 中局部化 vcall 只有三次实际参数 PUSH，旧 IDB 却把先前保存的 EBX 算入参数，产生16字节推测清栈而实际为12。局部化输出与 ProfileButton 构造输入因此被误认为相差4字节，frame 又保留两个同一对象的别名边界，形成虚假的60字节命令缓冲区。
- 正确做法：`normalize_population` 同时验证三次压栈、叶 getter 返回的全局接口和局部化输出/构造输入的地址关系。只在两份证据一致时修正自身 first-pass trace；排除不执行 producer 的空列表分支，并按相同 LEA 指令的前后地址重定位 frame 对象边界。保留 `checked_capacity` 的严格上界，实际缓冲区64字节、原 CRT 限额62。无推测修正，不修改或保存原 IDB。
- Runtime 差异：旧版以 MOV AL,[this+0x46] / TEST AL,AL 检查 autosave，不能只识别 CMP byte ptr；旧版 wb writer 是 Create/Save 共享直接子函数。由当前字节读取 provenance 与共享 writer 的 wb Open 定位，继续恢复真实 filesystem getter/global。旧版 m_needAutosave=0x46、TextEntry.m_textLength=0x84，不能复制 HL25 的0x42/0x88。
- 验证方式：两个新 Windows storage 各重建92条、runtime各14条；HL10210 Windows 及 HL10210/HL8684 Linux 回归产物逐字节不变。额外的指令清栈、空分支、frame歧义和字节来源纯逻辑测试保留在两个 identity 测试模块。最终测试与消费端裁剪证据另见 [issue 940 验证记录](evidence/issue940-validation.json)。
- 适用范围：本次只新增 HL8684 Windows 与 issue 940 附件的静态支持。其他旧 Windows 的历史 unsupported 调查未自动翻转；此处不是游戏运行验收报告。消费端清单请求新增记录，是否安装 Career hooks 仍服从消费端原有运行逻辑。

跨仓库 tag 约束：新增 tag 前同时验证上游 `analysis_config.TAG_RE`、`gamesymbols_json.GAME_VERSION_PATTERN`、snapshot 文件名解析和消费端 `sync-gamedata.py:GAME_VERSION_PATTERN`。上游不允许下划线，消费端不允许 game 前缀内的连字符；共同可用形式是纯小写字母/数字前缀加数字 build。本次正式 tag 为 `cstrikegameui-8684`，不能使用中间讨论的其他拼写。
