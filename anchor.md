# Issue #312 — Task 1 / Stage1–3 anchor 汇总（已确认）

> 用户于 2026-10-01 回复“全部确认”，已批准本文全部方案。第 11 节记录 Task 2 的生产实现与验证结果；其余 Task 1 采集记录保留为确认时的证据。

来源：[GitHub Issue #312](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/312)。

采集日期：2026-10-01（Asia/Singapore）。开始二进制核验前已执行 `git pull --ff-only origin main`，工作基线为 `cd03d476`。

本文件汇总 A/B 全部 31 个编号以及用户追加的 Stage1–3；#24 合并到 #23，#7/#28 复用已有记录，#25 仅补齐缺少的 14 份。三阶段首选定位链见第 2A 节；ISurface/IInput/ISchemeManager 只记录共享接口的 slot-only vfunc。下述 locator 是本次提交确认的方案；文中的槽位、RVA 和布局值是当前二进制的核验结果，不是 finder 的输入常量。生产 finder、配置及 artifacts 尚未修改，Task 2 要在用户确认本文件后开始。

## 1. 结论与范围

- 原 issue A/B 交付项：26 个 module-specific virtualFunction 身份和 2 个 structMember 身份。预计新增 421 份 YAML：GameUI 374 份，engine/serverbrowser/client 的 SetProportional 47 份。数量不含可复用的已有记录或三阶段的中间定位节点。
- 检查矩阵：62 份 x86 二进制，gameui 15、engine 15、serverbrowser 15、CS/CZ/CZDS client 17。所有矩阵项的本地 SHA-256 与所属 IDA survey 一致。
- **AddPage 的真实签名是 `vgui2::PropertySheet::AddPage(vgui2::Panel*, char const*)`**，不是 issue lead 中的四参数 SDK 签名。三个未剥离 Linux 目标的 ELF 符号和 Windows 的参数使用/清栈均支持两个显式参数。
- **目标的 PropertySheet 继承 Panel**；MetaHookSv 当前 SDK 的 PropertySheet 继承 EditablePanel，且插入 IsDraggableTab、RemoveAllPages、RemovePage 等额外虚函数。该 SDK 的声明次序不能证明本次二进制的槽位。
- #5 属于 `vgui2::EditablePanel`，COptionsDialog 继承该 entry；#6 属于 `vgui2::FocusNavGroup`；#29 是 **`CBasePanel::ApplySchemeSettings(vgui2::IScheme*)` 覆写**。
- Windows/Linux 的 Panel、PropertySheet、EditablePanel 和 Options 页面槽位不同；FocusNavGroup 没有虚析构，GetCurrentFocus 在本矩阵两个平台均观察到 7。仍应从当前表推导，不能将 7 写进 locator。
- `_activePage`：HL25 Windows/Linux 为 `0x94`，其余 13 份为 `0x90`。`_currentFocus`：15 份均为 `0x0c`，类型为 VPanelHandle，大小 4 字节；它不是直接的 `Panel*`。

### 支持集合

| 集合 | gamever 与平台 | 数量 |
| --- | --- | --- |
| G：gameui / engine / serverbrowser | Windows：cof-5936、hl-3248/3266/3329/3647/4554/6153/8684/10210、svencoop-8948/10257；Linux：hl-8684/10210、svencoop-8948/10257 | 每模块 15 |
| C：client | Windows：cstrike-3248/3647/4554/6153/8684/10210、czero-8684/10210、czeror-8684/10210；Linux：cstrike-6153/8684/10210、czero-8684/10210、czeror-8684/10210 | 17 |

覆盖集合以当前 configs 声明为准。这里的 czeror Linux SetProportional 是其实际 client 二进制里的共享 Panel 实现，不代表 CZDS 特有 UI 类在 Linux 中存在。早期 BLOB engine/client 使用已解密的 `.decrypt.dll`，具体输入列在附录。

未覆盖原因：早期 HL 和 CoF 未配置 Linux 对应模块；CS/CZ/CZDS 未配置独立 gameui/serverbrowser 模块；HL/Sven/CoF client 不包含本次要求的共享 Panel 实现。没有把这些不适用组合当作缺失匹配，也不复制其他模块的地址或布局。

## 2. 共用定位与验收规则

### R：当前二进制的类表

复用 #299 的 RTTI 路线：MSVC 解析 exact type descriptor / complete-object locator 的 primary table；Itanium 使用 exact `_ZTV...` 的 address point，剥离目标使用保留的 typeinfo。核对 class 名、primary table、继承关系及可执行条目。对需要对象归属的场景，再核对 constructor 的实际 vptr store。

枚举表中的函数候选，先验证目标的源码行为、接收者、参数与相关成员，再反向映射 `entry == verified_method` 得到唯一 index。不能用“该 entry 被继承/覆写”“位于另一个已知 slot 旁边”来命名方法。

对本轮三阶段的方法，优先使用第 2A 节的字符串 predecessor 与调用/注册数据流，R 用于核验真实 class、callee 和当前 entry。其余无 literal 的 getter 沿用 `_vgui_private_method_identity.py` 的类表加成员/调用身份方式；它们没有目标自有的稳定字符串或浮点集合。函数签名只在定位后生成并验证；`old_yaml_map` 不能绕过定位链。

### L：目标自有 literal

扫描非执行段中的完整 `literal + NUL`，核对代码 xref；GCC PIC 漏 xref 时核对实际传给调用的字符串地址。字符串查询必须 FULLMATCH，不能用子串或其他版本的 VA。

ResetData/ApplyChanges 等消息名在全模块被复用。不能直接声称它们有唯一 owning function：应先与当前类表求交，再验证消息分发行为。遇到 0 个或多个满足身份条件的候选即失败。

### F：数据流与 helper

使用当前 CFG、ABI this/显式参数、返回值、member load/store、direct call/tail jump 和 register-loaded vcall。需要支持：

- MSVC thiscall 与 GCC cdecl；bool/wchar_t 的截断和转换。
- inline 容器操作，以及调试版 out-of-line Count/FindElement/operator[] helper。
- VPanelHandle::Get、operator bool、conversion operator 的不同组合。
- PIC/GOT 形成的指针和 vptr；不能把无 IDA data xref 判成不存在。
- 对 `__chkesp` 等辅助调用保留真实返回值语义，不能把它误当目标业务调用。

复核 hl-3266 时，反汇编的 `add ecx, 78h` 才是容器地址；反编译显示的 `this + 30` 是其推断类型的缩放表达式。所有成员值以指令和 this 数据流为准。

### S：输出签名

定位后使用现有 `_function_payload` / `_inspect_function_via_mcp` 生成当前二进制唯一签名。短 getter 可能与其他函数共用归一化指令；必要时使用现有显式 `func_sig_allow_across_function_boundary` 支持。相邻指令只用于输出签名判别，不参与方法发现。

Task 1 已对 5 个代表目标、12 个短方法分别调用现有签名检查，共 60/60 成功。全矩阵生产 YAML 生成及 repository artifact validation 属于 Task 2，尚未执行。

## 2A. 用户指定的 Stage1–3（已确认的优先定位链）

本节纳入用户追加的三个阶段，并更新 #1–#6/#31 的首选发现入口。仍处于 Task 1：中间函数、wrapper、调用点用于证实身份；尚未新增生产 finder、config 或 artifacts。第 1 节的 421 份统计只针对原 issue 的 A/B 交付项；不把这里的中间定位节点自动算作新增产物。

**模块与共享接口约定**：Panel/BuildGroup/Frame/EditablePanel/FocusNavGroup 的实现与表均取自当前宿主模块，支持 G 的 engine/gameui/serverbrowser 各 15 份、C 的 client 17 份。`ISurface`、`IInput`、`ISchemeManager` 是抽象接口，本轮只提取 **slot-only virtualFunction**：`func_name`、`vtable_name`、`vfunc_index`、`vfunc_offset`；不提供接口实现的 `func_va`、`func_rva` 或函数签名。同一引擎版本的 hw/gameui/client/serverbrowser/vgui2 共用接口定义；按同引擎维护一份接口身份，各宿主只是槽位证据来源。这里“共享 vgui2”指接口 ABI 归属；现有 `gameui/ISurface_GetModalPanel.*.yaml` 就是可复用的 slot-only 格式，不要求新增一套按宿主重复的接口定义或改动模块配置。不能把某个模块的 interface getter、接口实例或实现地址当成接口方法身份。

当前 62 个宿主的三条接口槽位，按引擎身份及平台合并为 16 组，组内无冲突。未另开 vgui2 实现数据库：本轮验证的是当前宿主调用的共享接口槽位，不寻找 ISurface/IInput 实现地址。槽位仍按当前二进制推导，不按平台或版本直接写常量。

### Stage1：BuildGroup → Panel 设置关系

**入口 S1**：完整 `ControlFactory`、`ControlName`、`PanelPtr` 字符串 xrefs 的 owning-function 交集，再沿当前数据流消歧。

1. `controlKeys->GetString("ControlName")` 提供 factory 请求参数；BuildContext 接收 RequestInfo；`GetPtr("PanelPtr")` 返回 newPanel，随后请求对象 deleteThis。
2. 所有后续配置调用使用这个 **newPanel 返回值作为 this**。SetPos 取函数的显式 x/y 参数；SetName 取 controlKeys->GetName 的返回值；ApplySettings 使用同一个 controlKeys；SetParent/ActionSignalTarget 取同一个 parent member；SetBuildGroup 的实参是当前 BuildGroup this。
3. `EditablePanel::RequestInfo` 使用相同三个字符串，却通过 SetPtr 写回 PanelPtr，返回成功标志。它没有上述 newPanel 的 x/y 配置链，必须排除。
4. GCC 部分版本把 NewControl 内联进 `BuildGroup::ApplySettings`，那条配置链的 x/y 为 0/0。若同一二进制还存在使用显式 x/y 的独立 NewControl，优先选后者；只有内联实例时，保留它作为 predecessor 的调用点，不把 enclosing ApplySettings 命名成独立 NewControl。

真实入口名称：`vgui2::BuildGroup::NewControl(KeyValues*, int, int)`，**非虚 function**。`NewControl(char const*, int, int)` 是不同重载，没有这组 factory/PanelPtr/ApplySettings 链，不能混用。源码：[BuildGroup.cpp:972](D:/HLND2T_official/vgui2/controls/BuildGroup.cpp:972)。

62 份均有唯一通过参数/接收者关系的配置链；其中 56 份有独立 NewControl，6 份 HL25 Windows 只有位于 ApplySettings 的内联实例：hl-10210 的 engine/gameui/serverbrowser，以及 cstrike/czero/czeror-10210 的 client。原始 owning-function 交集可以有 1–3 个候选；这不是字符串唯一命中的方案。实现必须显式做消歧，满足身份条件的候选为 0 或多个时失败，不能取第一个 xref。

**从配置调用恢复方法**：direct call 解码当前 callee；vcall 解码 receiver/vptr/displacement 后取当前 Panel 表条目。命名还须验证 callee 的行为，不能靠调用序号或 SDK 的槽位顺序。

| S1 真实目标（省略 `vgui2::Panel::` 前缀） | 类别 | 具体身份/验收条件 |
| --- | --- | --- |
| `SetParent(vgui2::Panel*)` | virtualFunction | parent Panel* 非空时取它的 GetVPanel，再对 newPanel 调用另一个 SetParent 重载；空路径传 VPANEL 0。 |
| `SetBuildGroup(vgui2::BuildGroup*)` | virtualFunction | newPanel 保存 BuildGroup 参数，然后对该 group 调用 PanelAdded(newPanel)。 |
| `SetPos(int, int)` | function，非虚 | 使用当前 panel 的 GetVPanel，将 x/y 交给 IPanel::SetPos；参数来自 NewControl 的两个显式参数或已证明的内联 0/0。 |
| `SetName(char const*)` | function，非虚 | 释放旧 name，按传入非空字符串长度分配/复制新 name；参数是 controlKeys->GetName 返回值。 |
| `ApplySettings(KeyValues*)` | virtualFunction | controlKeys 为接收者参数；callee 使用 xpos/ypos/wide/tall 等资源键，并应用位置、尺寸、可见/可用状态。其自有资源键还可直接交叉验证。 |
| `AddActionSignalTarget(vgui2::Panel*)` | virtualFunction | 把 parent Panel* 经 GetVPanel/PanelToHandle 转为 handle，去重后加入 action target 容器；与 VPANEL 重载区分。 |
| `SetBuildModeEditable(bool)` | function，非虚 | 接收 true；操作 build-mode flags 中的 editable 位（源码语义掩码 1）。当前目标处理 bool 的 set/clear 方式可能不同于旧源码的 OR 写法。 |
| `SetBuildModeDeletable(bool)` | function，非虚 | 同一个 flags member，deletable 位（源码语义掩码 2）；不按前后调用顺序命名。 |
| `SetAutoDelete(bool)` | virtualFunction | 直接写入 auto-delete bool，当前实参 true；与两种非虚 build-mode flag helper 区分。 |

#### S1-P：SetParent 重载与状态继承

从已验证的 `SetParent(Panel*)` 恢复其 VPANEL 转发调用，得到真实 `vgui2::Panel::SetParent(unsigned int)`（SDK typedef 为 VPANEL）。当前表证明 Windows 的两个重载为 Panel*=37 / VPANEL=36，Linux 为 Panel*=36 / VPANEL=37；这些是观察值，不能用跨平台 +1 计算。

**用户参考链的两处校正**：实际名字是 `IsProportional()`，不存在本轮目标名 `GetProportional()`。当前 62 份 SetParent(VPANEL) 使用 `GetVParent()` 和 `IPanel` 查询 parent 的状态，随后调用本对象的状态 setter；它没有直接调用 `Panel::GetParent()->IsProportional()`。该实际路径与 [MetaHookSv Panel.cpp:1267](D:/MetaHookSv/include/vgui_controls/Panel.cpp:1267) 相符。官方旧 Panel.cpp 的 GetParent 版本用于理解意图，不能替代实际调用关系。

| S1-P 真实目标（均为当前模块的 Panel virtualFunction） | 具体恢复与交叉验证 |
| --- | --- |
| `SetProportional(bool)` | SetParent 的 bool 实参来自 IPanel::IsProportional(GetVParent())。callee 比较/写 proportional 状态、对子 Panel 在自己的当前虚位置递归、最后 InvalidateLayout；与原 Task 1 的 62 个候选完全相同。 |
| `GetVParent()` | 恢复 SetParent 中重复用于 parent 状态查询的 this dispatch；callee 将 GetVPanel 交给 IPanel::GetParent，返回 VPANEL。 |
| `GetParent()` | 补充关系验证：枚举当前 Panel 表，要求先调用与 GetVParent 相同的 IPanel::GetParent，再经 GetControlsModuleName/IPanel::GetPanel 返回 Panel*；空路径 null。它是独立转换方法，不标成 SetParent 的直接 callee。 |
| `IsProportional()` | SetProportional 向子对象传播的 bool 来源；getter 返回与 setter 写入相同的状态。优化目标可以比较当前 getter 函数指针后直接读该字段，仍验证 virtual fallback 与字段一致。 |
| `SetKeyBoardInputEnabled(bool)` | SetParent 的 parent/current 差异条件成立后调用；callee 将状态传给 IPanel，并遍历子对象，在自己的当前虚位置传播同一 bool。 |
| `IsKeyBoardInputEnabled()` | 与 parent 的 IPanel keyboard 查询结果比较的 this getter；callee 查询当前 GetVPanel 的 keyboard 状态。 |
| `SetMouseInputEnabled(bool)` | 同样由 parent/current mouse 状态差异触发；callee 设置 IPanel mouse 状态并要求 surface 重新计算 mouse visibility，无 keyboard 的子递归。 |
| `IsMouseInputEnabled()` | 与 parent mouse 查询结果比较的 this getter；callee 查询当前 GetVPanel 的 mouse 状态。 |

SetName/SetPos/两种 build-mode setter 有真实非虚入口，不能产出 virtualFunction。SetParent 和 AddActionSignalTarget 的重载必须按参数数据流验证。全部 18 个 S1 方法在 62 份均有当前入口或表条目；16 份保留相应私有 ELF 符号的 Linux 输入共 288 项符号名/地址与推导一致。Sven-10257 的三个 Linux 宿主私有符号已剥离，使用行为证据，不宣称有名称导出。

### Stage2：Frame::OnKeyCodeTyped → 方法与共享接口槽位

**入口 S2**：`FULLMATCH:CloseFrameButtonPressed` 与 `FULLMATCH:Hotkey` 的代码 owners 交集，在全部 62 份为唯一函数，且等于当前 Frame 表中的 `vgui2::Frame::OnKeyCodeTyped(vgui2::KeyCode)`。单独 Hotkey 会命中 OnKeyTyped；单独 CloseFrameButtonPressed 会命中双击关闭路径，不能单用一个字符串。源码：[Frame.cpp:1646](D:/HLND2T_official/vgui2/controls/Frame.cpp:1646)。

| S2 目标 | module / 类别 | 定位方案 |
| --- | --- | --- |
| `vgui2::Frame::OnKeyCodeTyped(vgui2::KeyCode)` | 当前宿主 / virtualFunction，入口节点 | 双 literal；验证三组 modifier polls、Alt+F4 关闭消息、Enter 的默认按钮/Hotkey 路径及当前 Frame entry。 |
| `vgui2::EditablePanel::GetFocusNavGroup()` | 当前宿主 / virtualFunction | Enter 分支：this getter 返回嵌入 NavGroup 地址，接着调用 GetCurrentDefaultButton，取得的 VPANEL 经可见/可用检查后接收 Hotkey。恢复当前 EditablePanel/Frame entry，再和 Stage3 的 m_NavGroup 比较。 |
| `vgui2::Panel::PostMessage(unsigned int, KeyValues*, float)` | 当前宿主 / virtualFunction | Hotkey 的目标来自 GetCurrentDefaultButton，不是 Panel*；消息来自 KeyValues("Hotkey") 构造，delay=0。callee 把 VPANEL、消息、源 GetVPanel 和 delay 交给 IVGui::PostMessage。 |
| `vgui2::Panel::InvalidateLayout(bool, bool)` | 当前宿主 / virtualFunction | reload 分支取 embedded panel，经 IPanel::GetPanel 转换后作为 receiver，以 false/true 调用；验证 layout/scheme 状态与递归失效。 |
| `vgui2::ISchemeManager::ReloadSchemes()` | 共享 vgui2 / slot-only virtualFunction | 同一 reload 分支、scheme() 返回对象上的无显式参数 vcall；不把 scheme getter 或当前实现函数当成接口产物。 |
| `vgui2::ISurface::SupportsFeature(vgui2::ISurface::SurfaceFeature_e)` | 共享 vgui2 / slot-only virtualFunction | ESCAPE 路径，surface() receiver 与 GetEmbeddedPanel 的 receiver 来源一致；实际实参为源 enum ESCAPE_KEY=3。 |
| `vgui2::IInput::GetAppModalSurface()` | 共享 vgui2 / slot-only virtualFunction | receiver 来源与 modifier polls 的 input() 一致；返回的 VPANEL 与当前 this 的 GetVPanel 比较。不按其他无参 input 调用的邻近位置选取。 |

**重载差异**：Alt+F4 使用 `PostMessage(Panel*, KeyValues*, float)`，Hotkey 使用 VPANEL 重载。当前 Windows 的 Panel* 重载 index=31，Linux=46；VPANEL 重载在本矩阵两平台 index=32。恢复目标参数类型和消息对象关系，不能从一个平台换算另一个平台的槽位。

**早期入口补充（14 份 Windows）**：cstrike-3248/3647 client，以及 hl-3248/3266/3329/3647 的 engine/gameui/serverbrowser 中，OnKeyCodeTyped 没有 ESCAPE 分支。这里不是接口不存在。

- SupportsFeature：用当前 Frame 表与 `Command`/`command`/`Cancel` 三个自有 literal 求交，定位 `Frame::OnKeyCodePressed(vgui2::KeyCode)`；验证 ESCAPE_KEY=3、surface() receiver 与 Cancel 消息投递，提取该 vcall 的 slot。
- GetAppModalSurface：在当前 Frame 表中验证 `Frame::OnClose()` 的模态释放行为：input() query 的返回值与 GetVPanel 比较、条件成立时同一 input() receiver 来源执行 ReleaseAppModalSurface，然后隐藏 Frame，并链到基类 OnClose。该旧版本路径没有现代源码的 previous-modal 保存字段，不能强加 DoModal member-store 条件。
- 这 14 份的两个补充入口均唯一；对应 call RVA 列入附录。跨模块复用只复用同引擎的接口槽位，不复制某个宿主的调用点地址。

全部 62 份当前槽位观察值：ReloadSchemes Windows 2/Linux 3；SupportsFeature Windows 50/Linux 51；GetAppModalSurface Windows 18/Linux 19。输出仍由实际 vcall displacement / 当前输入推导，不以这些数字作为 locator。现代 Linux 的 Frame::CloseModal 可能内联，必须把 modal query 与随后 Release/SetAppModalSurface 区分。

### Stage3：SetFocus 注册 → OnSetFocus → 嵌入 NavGroup / current handle

**入口 S3**：完整 `SetFocus` message 注册及 `Panel` message-map 类身份。二者可以在同一 owning function，也可以通过 AddToMap/GetPanelClassName helper 相连。不能要求所有平台都有独立 InitVar 函数，也不能把全部包含 SetFocus 的 constructor 当成互相冲突的目标。

源码：[MessageMap.h:84](D:/HLND2T_official/public/vgui/MessageMap.h:84)、[:150](D:/HLND2T_official/public/vgui/MessageMap.h:150)，Panel.h 的 MESSAGE_FUNC(OnSetFocus,"SetFocus")。当前证据必须将 message name、callback/PMF、参数个数 0 和 Panel map 消费者绑定到同一注册项，不能只取附近的可执行常量。

| 注册形式 | 本轮实际验证 | 恢复规则 / 未输出原因 |
| --- | --- | --- |
| MSVC | 43 个 Windows 输入，共 49 个独立/内联注册实例 | 从 SetFocus entry 的 callback 或 AddToMap 的 callback 参数恢复 wrapper；wrapper 必须以原 this 进行唯一的 vcall/tail jump。按当前 displacement/4 得到 OnSetFocus index，不使用参考 356。 |
| Itanium，entry 内联组装 | 7 个 Linux 输入，共 28 个 constructor 注册实例 | 同一 entry 内的 `func.__pfn` 是奇数编码，`func.__delta=0`；按 `(pfn-1)/4` 得到当前虚位置。验证 entry 被加入 Panel map；该整数不是可执行地址。 |
| Itanium，AddToMap constprop/regparm helper | 12 个 Linux 输入，共 48 个 constructor 注册实例 | 当前 helper 把 eax 的 SetFocus name、edx 的 pfn、ecx 的 delta 组装成同一 entry。验证 helper 的 Panel literal、参数/entry store 及 map 消费；不能把 GCC 的寄存器 ABI 当成标准栈参数。 |

Linux 的 InitVar 在四个 Panel constructor 中内联；本轮没有强行创建独立 InitVar/OnSetFocus_wrapper function 产物。Windows 的 hl-3647 serverbrowser 同时有独立注册函数和四个 constructor 中的内联实例，hl-4554/6153 serverbrowser 各有两个 constructor 内联实例；其他 Windows 输入有一个注册实例。所有 125 个实例各自恢复的当前 slot，在对应输入内一致。

MessageMapItem 的 func 字段位置要从当前 entry 组装/消费者核对；不能把示例 `v5[4]` 复制到各 ABI/SDK。例如 CoF 的 Windows AddToMap helper 组装 record 时把 callback 放在 name 之后的 byte offset 8，普通目标的内联 record 则观察到 16。当前 Windows callback 是实际可执行 thunk；Itanium pfn 编码不是 wrapper VA，两类证据不互相套用。

1. 以注册恢复的 slot 读取当前 Panel entry，验证 **`vgui2::Panel::OnSetFocus()` 调用 Repaint**。50 份是单次 this vcall；12 份优化 Linux 输入会比较当前 Repaint 函数指针并内联本类路径，保留 virtual fallback；不要求整个函数只有一个 call。
2. 核对 RTTI 继承关系，在 EditablePanel 当前表中按这个已经证明身份的 slot 取得覆写 entry；验证 **`vgui2::EditablePanel::OnSetFocus()`** 的行为，而不是只凭覆写关系命名：current focus 非空且非 this 时 RequestFocus；否则取 default panel，RequestFocus 并对 child 执行同一个 OnSetFocus；所有路径调用 Panel 的基类实现。62 份均有到当前基类入口的 direct call/tail jump。
3. current/default 两个 group 调用使用同一个 `&this->m_NavGroup` 地址。从 this-relative LEA/ADD 提取嵌入对象 offset，和 Stage2 的 GetFocusNavGroup 返回值、当前 Group 方法/表身份一致。gameui 的 15 份还与前轮已验证的 constructor 安装 FocusNavGroup vptr 关系交叉核对；没有宣称另 47 个宿主也单独采集了其 EditablePanel constructor。
4. current focus 的返回值参与与 this 的比较，据此区分 GetCurrentFocus 与 GetDefaultPanel。Windows 常使用虚调用；Linux 可直接调用已去虚化的 getter，仍要求它等于当前 FocusNavGroup 表的唯一 entry。
5. `FocusNavGroup::GetCurrentFocus()` 中，用于非空检查/VPANEL 解码的同一 VPanelHandle member 才是 `_currentFocus`。从实际 member address/load 提取 offset，62 份均与 SetCurrentFocus 把 VPANEL 参数传给同一 member 的 handle setter 关系交叉核对；gameui 15 份还核对了 constructor 初始化。它不是 `Panel*`，也不是外层 m_NavGroup offset。

| S3 结果 | module / 类别 | 支持与核验结果 |
| --- | --- | --- |
| `vgui2::Panel::PanelMessageFunc_OnSetFocus::InitVar` | 当前宿主 / 注册函数或内联注册调用点 | 43 Windows / 19 Linux，具体形式见上表；内联实例只作为 caller/call-site 证据。 |
| `vgui2::Panel::OnSetFocus_wrapper` | 当前宿主 / ABI thunk 证据 | 43 Windows 可恢复实际 thunk；Linux 没有强制 wrapper 输出，使用 PMF 编码。 |
| `vgui2::Panel::OnSetFocus()` | 当前宿主 / virtualFunction | 全部 62，当前观察值 Windows 89/Linux 90。 |
| `vgui2::EditablePanel::OnSetFocus()` | 当前宿主 / virtualFunction | 全部 62，同一已验证方法的覆写 entry；当前观察值 Windows 89/Linux 90。 |
| `vgui2::EditablePanel.m_NavGroup` | 当前宿主 / structMember，嵌入 FocusNavGroup 对象 | 全部 62；HL25 Windows/Linux 0x7c，其余 0x78；从 this 数据流取得，不能把对象地址当偏移。 |
| `vgui2::FocusNavGroup::GetCurrentFocus()` | 当前宿主 / virtualFunction | 全部 62，与当前 Group 表 entry 相等；当前观察值 7。gameui 的原 #6 复用同一结果。 |
| `vgui2::FocusNavGroup._currentFocus` | 当前宿主 / structMember，4-byte VPanelHandle | 全部 62 当前观察值 0x0c；gameui 的原 #31 复用同一结果。 |

行为参照：[EditablePanel.cpp:697](D:/HLND2T_official/vgui2/controls/EditablePanel.cpp:697)、[FocusNavGroup.cpp:387](D:/HLND2T_official/vgui2/controls/FocusNavGroup.cpp:387)。m_NavGroup 是用户本轮追加的结果；它与 GetFocusNavGroup、_currentFocus 的意义和类别分别记录。

### 三阶段实现时必须保留的约束

- 发现入口优先使用本节 S1/S2/S3；旧 P/N/H 的类表行为和 constructor 关系继续作为 callee/成员的验证条件。不再把 SetProportional 或 GetFocusNavGroup 的单独表枚举当成首选入口。
- 不用历史 YAML、版本 slot 常量、call ordinal 或窗口位移代替数据流；同一 receiver、返回值/参数角色和当前 table entry 必须吻合。
- `_chkesp` 在 hl-3266/3329 GameUI 调试构建中正常路径保留寄存器。先核对真实 helper 的 push/pop 与 trap 路径，再保留业务调用的返回值；不能把它的新 result token 当成 PanelPtr/GetName 结果。
- Windows 有提前压入 bool、然后调用无参数 GetVPanel、最后调用 IPanel setter 的序列。IDA 推断的 stack delta 可能误把 bool 算成 GetVPanel 的参数。应以当前 callee 的实际 `ret` 清栈及反汇编参数传递纠正，不能依赖错误的反编译参数列表。
- hl-3248/3266/3329 serverbrowser 的部分当前表 entry 已标记为 code head，但缺少 IDA function 元数据。本轮只为未被任何现有函数拥有、且来自已核验 RTTI 表的入口补全分析，未拆分/覆盖其他函数；新生产验证也必须正确处理此情况。
- 字节签名只在确认实际身份后生成。新的中间方法和三阶段候选尚未执行全矩阵生产签名生成或 repository artifact gate；这些仍属于 Task 2。

## 3. #1–#4：Panel::SetProportional

真实 payload：`vgui2::Panel::SetProportional(bool)`；category：virtualFunction（config 的 `vfunc`）。

| 编号 | module | 支持 | 建议 lookup/file stem |
| --- | --- | --- | --- |
| #1 | serverbrowser | G 全部 15 | `vgui2_Panel_SetProportional` |
| #2 | gameui | G 全部 15 | `vgui2_Panel_SetProportional` |
| #3 | engine（BaseUI 所在 hw） | G 全部 15 | `vgui2_Panel_SetProportional` |
| #4 | client | C 全部 17 | `ClientVGUI_Panel_SetProportional` |

**方案 P：S1 的 BuildGroup factory 配置链 → 两个 SetParent 重载 → SetProportional → R/完整行为验证 → 当前 Panel table index。**

在当前 Panel 表中枚举：比较传入 bool 与本对象 proportional 状态、将传入状态写回本对象、遍历子 Panel、对子 Panel 在候选自己的 virtual position 调用 SetProportional，参数来自本对象 IsProportional，最后对 this 执行 InvalidateLayout。恢复 getter/child 的关系，不硬编码它们的 slot 或 proportional 字段偏移。

必须同时满足状态写入、子 receiver 的自位置递归及最后的布局失效。只识别递归会把 SetVisible、InvalidateLayout、SetKeyBoardInputEnabled 等误当目标；本次枚举中这些 sibling 已被后续行为条件排除。

源码：`D:/HLND2T_official/vgui2/controls/Panel.cpp:2726`。62 份逐表筛选均收敛为 1 个候选；Windows 观察到 113，Linux 114，具体 RVA/哈希见附录。四个 Panel::Init hook 已有记录，不新增 hook 本体产物。

## 4. #5/#6/#31：FocusNavGroup

| 编号 | module / category | 真实身份 | 支持 / 建议 stem |
| --- | --- | --- | --- |
| #5 | gameui / virtualFunction | `vgui2::EditablePanel::GetFocusNavGroup()`（返回 FocusNavGroup 引用，ABI 返回地址） | G 全部 15 / `GameUI_EditablePanel_GetFocusNavGroup` |
| #6 | gameui / virtualFunction | `vgui2::FocusNavGroup::GetCurrentFocus()` | G 全部 15 / `GameUI_FocusNavGroup_GetCurrentFocus` |
| #31 | gameui / structMember | `vgui2::FocusNavGroup._currentFocus`，4-byte VPanelHandle | G 全部 15 / `GameUI_FocusNavGroup__currentFocus` |

### 方案 N：GetFocusNavGroup

S2 的 Frame::OnKeyCodeTyped Enter 路径恢复 GetFocusNavGroup 的调用和当前 entry，R 确认 EditablePanel 和 FocusNavGroup 表。验证 getter 返回 `&this->member`，并与 S3 的 EditablePanel::OnSetFocus 嵌入对象地址相同。gameui 的 15 份再验证该 member 在 EditablePanel constructor 中传给 FocusNavGroup constructor，后者在这个对象上安装当前 FocusNavGroup vptr 并初始化句柄。COptionsDialog/OptionsSub 当前表继承相同 entry，是额外核验。

Constructor 验证可由当前 `EditablePanel` class literal 的 owners 中筛选实际 this vptr store 和上述嵌入对象构造调用。hl-8684 Linux 的 PIC vptr 缺少直接 table xref，本次用独立 ELF constructor 符号补充验证：EditablePanel C2 `0x10e9d0` 在 call `0x10ea98` 把 `this+0x78` 和 this 传给 FocusNavGroup C2 `0x10f830`，后者实际安装当前 FocusNavGroup 表。符号只用于本次独立核验，生产发现应核对字符串 owners/计算出来的 vptr，不依赖未剥离符号。

15 份 getter 唯一；观察到 Windows 153/Linux 154。m_NavGroup 的对象偏移 HL25 两个平台为 `0x7c`，其余 `0x78`；这两个值是验证结果，不是 getter 定位条件。

源码：`D:/HLND2T_official/vgui2/controls/EditablePanel.cpp:651`、`public/vgui_controls/EditablePanel.h:123`。

### 方案 H：GetCurrentFocus 与 _currentFocus

S3 先从 SetFocus 注册恢复 OnSetFocus 身份和当前 slot，再进入 EditablePanel 覆写。以返回值参与 `focus != this` 比较的 group 调用恢复 GetCurrentFocus，并映射到当前 FocusNavGroup entry。callee 验证“检查同一 handle member 非空 → 解码该 member 的 VPANEL → ipanel/GetControlsModuleName → GetPanel → 返回 Panel*；空路径返回 null”。读同一 handle 的检查/转换可为 Get 调用，也可分别调用 operator bool / conversion helper。排除需要传入 panel/key 参数、遍历子项或修改本对象的 focus-navigation 方法。

从已验证 GetCurrentFocus 中参与检查及转换的 **this-relative member address** 提取 `_currentFocus` 偏移，再用 SetCurrentFocus 写入路径及 constructor 的 handle 初始化交叉核对。记录该指令的当前 VA/RVA、LEA/ADD 形式及 member displacement；输出 structMember 值和拥有者签名。不得把句柄内容、IPanel interface pointer 或嵌入 FocusNavGroup 在外层对象中的位置当作这个 offset。

15 份方法均有唯一匹配；当前 index 均为 7、member 为 `0x0c`。hl-3266/3329/CoF 将检查与转换拆成两个 helper；hl-10210 和 Sven 的优化版本可以重复调用同一 Get。附录给出实际 method RVA。

源码：`D:/HLND2T_official/vgui2/controls/FocusNavGroup.cpp:387`（getter）、`:395`（setter）；`public/vgui_controls/FocusNavGroup.h:58`（member）。

## 5. #8–#24/#30：PropertySheet

以下全部属于 **gameui**，支持 **G 全部 15 份**。方法 category 为 virtualFunction；#30 为 structMember。建议方法 stem 统一 `GameUI_PropertySheet_<method>`，成员 stem 为 `GameUI_PropertySheet__activePage`。

本组先通过 R 确认当前 PropertySheet/Panel 表，复用已有 HasHotkey/PerformLayout 的身份结果。以下是按方法独立验证的条件，绝不按 AddPage+N、连续声明顺序或固定 134–149 选择方法。

| 编号 / 方法（真实 payload 的 `vgui2::PropertySheet::` 前缀省略） | 提交确认的 anchor 与消歧条件 | 官方旧源码行号 |
| --- | --- | --- |
| #8 `AddPage(vgui2::Panel*, char const*)` | **L：`tab` + `ResetData`**。验证 page 非空/去重，创建或内联创建 PageTab，用 title 和当前 tab width 初始化，加入 pages/pageTabs，parent/action-signal 接收者为当前 sheet，对传入 page 投递 ResetData 并隐藏。`tab` 由 AddPage 作为构造参数使用，不应把 TabPressed 的注册 helper 当 AddPage。 | PropertySheet.cpp:221 |
| #9 `SetActivePage(vgui2::Panel*)` | **F：pages 查找 → ChangeActiveTab**。在与 ResetAllData/AddPage 相同的 pages 容器中找参数 page，非负位置调用当前已验证 ChangeActiveTab entry；无删除/成员替换副作用。支持 FindElement helper。 | :255 |
| #10 `SetTabWidth(int)` | **F：tabWidth store → InvalidateLayout**。唯一把显式 int 参数写入 AddPage 创建 PageTab 时使用的 width member，并使 this 布局失效的方法。 | :270 |
| #11 `GetActivePage()` | **F：同一 activePage 的 getter**。返回从已有 HasHotkey 的 active-page 接收者恢复出的 member；与 ChangeActiveTab 的 page store、PerformLayout 的 page receiver 一致。 | :304 |
| #12 `ResetAllData()` | **L：`ResetData`，限定 sheet 表并排除 AddPage**。验证循环取同一 pages 容器、GetVPanel 和 IVGui::PostMessage，而非向传入 page 一次投递。 | :279 |
| #13 `ApplyChanges()` | **L：`ApplyChanges` 与 sheet 表求交**。验证与 ResetAllData 同一个 pages 容器的循环及消息投递；不要选择含该注册名的 constructor/MessageMap helper。 | :291 |
| #14 `GetPage(int)` | **F：pages 的 indexed getter**。使用同一个 pages 容器，参数是元素索引，返回对应 Panel*，没有 GetText/页面切换/删除。追踪 out-of-line operator[] 的返回值和 bounds/null 行为。 | :540 |
| #15 `DeletePage(vgui2::Panel*)` | **F：查找与删除 page/tab pair**。定位传入 page，删除两个容器中对应元素；当前 page 命中时调用已验证 ChangeActiveTab；对 page 和 tab 执行相同 MarkForDeletion dispatch，最后调用已验证 PerformLayout。不能接受仅查找切换的 SetActivePage。 | :635 |
| #16 `GetActiveTab()` | **F：activeTab 的 getter**。返回与 ChangeActiveTab 的 tab store 和 GetActiveTabTitle 的 receiver 相同的 member；必须与 activePage getter 区分。 | :313 |
| #17 `GetActiveTabTitle(char*, int)` | **F：activeTab → GetText**。非空 activeTab 是 receiver，把两个显式参数作为输出 buffer/长度原样传给 Label::GetText，没有按索引取 pageTabs。由当前 dispatch 恢复 GetText 的位置。 | :331 |
| #18 `GetTabTitle(int, char*, int)` | **F：pageTabs[index] → 同一个 GetText**。第一个参数索引 pageTabs，第二/第三参数为 buffer/长度，与 #17 的 GetText dispatch 一致，并返回 bool。不能拿 pages 容器的 GetPage 替代。 | :340 |
| #19 `GetActivePageNum()` | **F：pages 搜索 activePage → index/-1**。无 page 参数，循环比较同一 pages 的元素和已验证 activePage，找到返回位置，未找到返回 -1。支持容器 helper 和 debug epilogue。 | :354 |
| #20 `GetNumPages()` | **F：相同 pages 容器的 count getter**。返回 #12/#13 循环边界的 count；调试版可调用已验证 Count helper。不得把 pageTabs count 或其他标量 getter 命名为此方法。 | :322 |
| #21 `DisablePage(char const*)` | **F：同一 EnDisPage helper，state=false**。转发 this/title/false；helper 要验证 pageTabs 获取文本、大小写无关标题比较和 SetEnabled，以及 combo 路径。false 必须是实际传入的状态。 | :555、:573 |
| #22 `EnablePage(char const*)` | **F：同一 EnDisPage helper，state=true**。与 #21 同一当前 callee/virtual position，this/title 不变；不能按前后相邻 slot 区分两个方法。 | :564、:573 |
| #23 `ChangeActiveTab(int)`；#24 同一方法 | **L：`PageHide` + `PageShow` + `PageChanged`**。验证旧页面消息/隐藏、新 page/tab 配对切换、活动指针和索引写入、focus/visibility 处理。从当前页/标签容器取参数 index 对应元素。PageTabActivated/panel 是额外证据，不使用 call ordinal。 | :670 |
| #30 `_activePage` | **派生值：已有 HasHotkey receiver → getter/load 与切页/store 交叉验证**。从真实 this-relative load/store 提取 member offset，大小 4；不要扫描 `[0x90,0x94]` 或按版本选值。 | header member；cpp:304、:707 |

上述源码均在 `D:/HLND2T_official/vgui2/controls/PropertySheet.cpp`，header 在 `D:/HLND2T_official/public/vgui_controls/PropertySheet.h`。

### 验证证据与源码差异

- 15 份当前 sheet 表中，AddPage 的 `tab`/ResetData 组合、ChangeActiveTab 的三消息组合、ApplyChanges，以及从 ResetData 排除 AddPage 后的 ResetAllData，均各得到 1 个候选。
- 已有 HasHotkey 的当前 body 在每份目标只读一个非零 this member。新 GetActivePage 返回同一 member，ChangeActiveTab 写该 member；activeTab getter、title 转发和切页的另一指针一致。
- DisablePage/EnablePage 在 15 份各转发一个实际 false/true，当前 helper position 相同。观察到 helper Windows 157/Linux 158，不将其作为 locator 常量。
- hl-8684、hl-10210、svencoop-8948 三份 Linux 的全部 16 个方法均与独立 `llvm-nm --demangle --defined-only` 地址/符号对应。svencoop-10257 Linux 已剥离，使用 RTTI 和与源码对应的函数/成员/消息数据流核验。
- 旧源码的 GetPage/GetTabTitle 曾写 `i < 0 && i > count`，各二进制还可能通过 operator[] 补做检查。定位不能要求它们都具备现代正确的 `i < 0 || i >= count` guard，否则会漏掉真实旧方法。不要在 Task 2 中“修正”目标二进制语义。
- 本轮分别核对各候选 body 和实际表项；附录里的连续 index 是核验结果。辅助地址矩阵曾用已观察的声明映射整理数据，**不能把该整理方式移入 finder**；无 literal 的方法仍须按上表逐一证明身份并唯一化。

## 6. #25–#27：Options 页面 OnApplyChanges

全部位于 gameui，category：virtualFunction。实际方法名与 class RTTI 相同。

| 编号 | 真实 payload | 支持 / 建议 stem | anchor |
| --- | --- | --- | --- |
| #25 | `COptionsSubVideo::OnApplyChanges()` | G 全部 15；新补 14 / `COptionsSubVideo_OnApplyChanges` | **V：已有 ApplyVidSettings 自有 `_setvideomode ...` anchor → 唯一当前 virtual caller** |
| #26 | `COptionsSubAudio::OnApplyChanges()` | G 全部 15 / `COptionsSubAudio_OnApplyChanges` | **A：构造出的音频控件 member + 真实 ApplyChanges callee + 当前 PropertyPage 虚拟位置** |
| #27 | `COptionsSubMultiplayer::OnApplyChanges()` | G 全部 15 / `COptionsSubMultiplayer_OnApplyChanges` | **M：自有 `cl_logofile %s\n` → 当前 Multiplayer table entry** |

### 方案 V

复用 `find-COptionsSubVideo-ApplyVidSettings.py` 已确认的 owning literal：GoldSrc/CoF 的 `_setvideomode %i %i %i\n`、Sven 的 `_setvideomode %i %i\n`。14 份非内联目标中，查询该已验证 ApplyVidSettings 的 direct callers，并与当前 COptionsSubVideo 表求交，得到唯一 OnApplyChanges entry。

独立核对：同一 brightness/gamma slider 的 HasBeenModified 检查，调用它们的 ApplyChanges，再把布尔结果传给 ApplyVidSettings(this, bool)。不要把非虚 ApplyVidSettings 的 entry 本身当作 virtualFunction，也不接受其他简单调用该函数的 helper。

hl-10210 Windows 复用已有 `COptionsSubVideo_OnApplyChanges`，保留其 table/index 身份，不新增重名产物。直接 owned format 在这份目标已经位于虚 OnApplyChanges 内部。

15 份与既有视频 predecessor 的表/调用关系均只有 1 个匹配；Windows 观察为 159、Linux 160。

源码：`D:/HLND2T_official/gameui/OptionsSubVideo.cpp:260`、`:296`。

### 方案 A

复用 Audio constructor 的 `SFX Slider` anchor，按实际控件创建 literal 和指针 store 恢复 SFX/Suit/MP3 等成员，不按 `184/188/...` 排列字段。

从方案 V 中“修改检查结束后，对相同 brightness/gamma receiver 执行的两次 ApplyChanges”恢复当前 CCvarSlider::ApplyChanges callee。Audio 方法必须将 constructor 中对应三个音量 slider member 传给该 callee，并对 sound-quality combo 调用其实际 ApplyChanges。早期 Audio 还有两个 toggle/check 控件，不能要求所有版本刚好四次 call。本矩阵早期 Windows/CoF 为六个业务 direct calls，后期为四个。

由已验证 Video 虚函数和 PropertyPage 继承关系恢复当前 OnApplyChanges virtual position，再在 Audio 表核对该 override 的上述独立语义。仅凭“同 slot override”或“三次同 callee”都不充分；OnResetData 的同一批 receiver 会调用 Reset，应排除。

15 份均核对了三个 slider 的 Apply callee 与 Video 相同；当前 Audio entry Windows 159/Linux 160。三个未剥离 Linux 的实际符号独立确认归属与名字。

源码：`D:/HLND2T_official/gameui/OptionsSubAudio.cpp:19`、`:61`、`:69`。消息机制的虚函数声明来自 `public/vgui_controls/PropertyPage.h:41` / `public/vgui/MessageMap.h:150`。

### 方案 M

`cl_logofile %s\n` 是实际 OnApplyChanges 内构造 client command 的 format，不是 caller 的页面标题。完整 literal owning function 与当前 COptionsSubMultiplayer 表求交，要求唯一；核对对多个构造出的控件提交修改、logo name 的输出 buffer 和 engine ClientCmd。logos/remapped.bmp、TGA 路径及 crosshair 分支会变，不作为跨版本必须的正向 anchor。

15 份对应表项均直接拥有此 literal，身份与方案 V 恢复的当前 OnApplyChanges position 一致；Windows 159/Linux 160。未剥离 Linux 符号支持真实类名。

源码：`D:/HLND2T_official/gameui/OptionsSubMultiplayer.cpp:939`、`:970`。

## 7. #29：CBasePanel::ApplySchemeSettings

module：gameui；category：virtualFunction；支持 G 全部 15；真实 payload：`CBasePanel::ApplySchemeSettings(vgui2::IScheme*)`；建议 stem：`CBasePanel_ApplySchemeSettings`。

**方案 B：自有 `resource/BackgroundLayout.txt` → CBasePanel override。**

FULLMATCH owning literal 与当前 CBasePanel 表求交，核对 this/scheme 参数先交给当前 Panel::ApplySchemeSettings，再 Open/Read/Parse 背景布局文件并创建 texture。`resolution`、`.tga`、`scaled` 作为行为交叉验证。用现有 `CBasePanel_ctor` 的 BasePanel owning literal 和 this vptr store 再核对类归属。

HL25 同一 body 还引用 `resource/HD_BackgroundLayout.txt`、`fit`；原 BackgroundLayout literal 仍在该函数中。15 份均唯一映射到真实 CBasePanel override，Windows 79/Linux 80。不是继承的 Panel entry，也不是 MessageBox 的同名 override。

源码：`D:/HLND2T_official/gameui/BasePanel.cpp:99`、`:107`。复用 finder：`ida_preprocessor_scripts/find-GameUI-base-taskbar.py`。

## 8. #7/#28 与 C 组：直接复用

| 对象 | 处理 |
| --- | --- |
| #7 PropertySheet::HasHotkey | 复用 `GameUI_PropertySheet_HasHotkey`，也是 #11/#30 的已确认身份前置；不重复新增。 |
| #28 CTaskbar::OnCommand | 复用 `CTaskbar_OnCommand`，也可使用已有 `CTaskbar_vtable`/`CTaskbar_ctor`；真实类名是 CTaskbar。15 份已有记录，Windows 87/Linux 88。 |
| #25 hl-10210 Windows | 复用唯一已存在的 `COptionsSubVideo_OnApplyChanges`；其他 14 份补虚函数记录，现有 ApplyVidSettings 非虚记录继续保留。 |
| C 组其余已有 TextEntry、TabCatchingTextEntry、PropertySheet::PerformLayout、MessageBox 及 PropertyDialog._propertySheet | 消费现有方案与记录，不再实现；不要拿 MessageBox::ApplySchemeSettings 代替 #29 的 BasePanel override。 |

旁证核对：现有 `GameUI_PropertyDialog__propertySheet` 在 hl-10210 Windows/Linux 均为 `0x118`，与 #299 已记录的结论一致。它不等于本次 PropertySheet 自身的 `_activePage`，也不等于 EditablePanel 嵌入 NavGroup 的位置。

## 9. Task 2 的实施边界（已确认并执行）

- 优先扩展 `find-GameUI-private-symbols.py` 和 `_vgui_private_method_identity.py`：上述 R/L/F 关系共用一次当前类表采集、消息/成员和方法身份验证。
- Panel 方法身份抽为共享逻辑，使 engine/serverbrowser/client 适配层复用；复用既有 Panel class/Init finder 的当前二进制验证，不新增四份相同实现。具体注册依赖在 Task 2 中按 config DAG 整理。
- 复用已有 constructor、ApplyVidSettings、HasHotkey、PerformLayout、BasePanel/Taskbar 等前置，不重复生成已覆盖符号。私有实现输出保持 module-local，真实 payload 名与 lookup stem 分开；抽象接口沿用已有 slot-only 约定，维护同引擎共享的接口身份供各宿主复用。
- 类表/成员 helper 只有在实现定位和验证确实需要时新增输出；本任务不要求新增无下游需求的 EnDisPage、容器字段等生产记录。
- 必须为新方法身份覆盖 moved slots、wrong receiver、同形 getter/Reset impostor、absent/ambiguous、inline/out-of-line/PIC 等有价值的回归情形，并执行当前仓库要求的全矩阵生成和 artifact validation。
- 结构体值从当前方法推导；用相应当前拥有者和 referencing instruction 生成 offset signature。短 vfunc 的跨边界签名必须显式标记，不能把字节签名变成发现 anchor。
- 不修改 MetaHookSv 消费代码。本文件确认也不代表其现有四参数 AddPage 调用 ABI 已经验证正确；下游应按本次真实双参数签名处理。

## 10. 本轮执行和验证边界

本轮临时 probe 位于 `C:/Users/HZDEV/AppData/Local/Temp/issue312/`，只收集/核验证据，未写 production YAML、finder 或 config。主要执行：

```powershell
git pull --ff-only origin main
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/batch.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/cross_batch.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/audit.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/follow_probe.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/nav_probe.py
```

- 两个主 probe batch 均退出 0；15 GameUI + 47 cross-module 输入全部采集成功。
- identity audit：62/62 x86-32、survey SHA-256 与本地输入一致、owned session 正常结束、IDB 存在、port released。
- anchor audit：SetProportional 62/62 唯一；GameUI 的 8 个直接/结构性根身份在 15 份各唯一。成员 getter/store、NavGroup 嵌入对象、Disable/Enable 转发、视频 predecessor 和 Audio slider apply 关系均无冲突。
- 独立 ELF 函数符号：hl-8684、hl-10210、svencoop-8948 gameui.so 每份 23 个方法地址/真实名一致，共 69 项；Sven-10257 已剥离，不宣称其私有 ELF 方法名有符号表证据。
- 签名可行性：hl-3248 Windows、hl-3266 Windows、hl-8684 Linux、hl-10210 Windows、svencoop-10257 Linux 的 12 个 PropertySheet 短方法，共 60 个当前候选，全部得到唯一输出签名。
- 每次 IDA 操作位于 exact-binary `IdaMcpLifecycle` 内：strict restored database，动态独占 port；调用 survey/server_health；正常退出自动 idb_save、targeted graceful quit 和 supervisor cleanup。主批次记录均有 port-release 与最终 IDB 证据。健康查询报告执行中的 config_json_get、queued_calls=0，没有跨绑定数据库。
- 两次大型 py_eval 的返回文本被服务截断；没有使用截断响应作为成功证据。改用 worker 端完整文件导出/精简结构化结果后重跑。初版粗筛中的递归 sibling 和 focus-navigation impostor 均被补充语义排除。
- 不宣称生产 finder/所有输出签名或项目测试已通过：本轮只交付 anchors 与候选核验；Task 2 的产物和测试门禁还未执行。

以下附录由本轮实际采集结果整理。RVA 加各输入 image base 得到 VA；Linux 本矩阵 image base 为 0。所有值只适用于所列 SHA-256。

## 11. Task 2 生产实现与交付验证

用户于 2026-10-01 全部确认本文件后，在 `dev` 分支实施；基线保持 `cd03d476`。本节记录生产结果，前文“尚未实施”等描述属于 Task 1 采集时的状态。

### 实现与产物

- 扩展既有 `find-GameUI-private-symbols.py`、`find-vgui2_Panel_Init.py`，共用 `_vgui_private_method_identity.py` 和新增 `_vgui_private_symbols_common.py`。前者只处理身份关系，后者负责当前 IDA 数据采集、签名生成和输出。
- Stage1 的 factory 返回值/接收者及两个 SetParent 重载恢复 SetProportional；Stage2 的 Frame 调用关系恢复 GetFocusNavGroup 和三个抽象接口槽位；Stage3 的当前消息注册 thunk/Itanium PMF 与 OnSetFocus 覆写恢复 m_NavGroup、GetCurrentFocus 和 _currentFocus。中间函数与调用点用于身份证据，未扩大成全部独立产物。
- PropertySheet 的 16 个方法使用各自消息、成员和参数关系验证，不使用连续槽位序号。Video 复用已声明 predecessor，Audio 核对三处 slider 的构造与 ApplyChanges 接收者，Multiplayer/BasePanel 使用其当前表内的自有 literal。
- 新增 **579 份 YAML**：原 issue A/B 的 421 份、三阶段的 m_NavGroup 62 份、抽象接口 96 份。按模块分为 gameui **434**、engine **30**、serverbrowser **30**、client **85**。支持版本与平台仍为第 1 节的 G/C 集合。
- `m_NavGroup` 是嵌入对象，产物不猜测其 size；`_activePage` 和 VPanelHandle `_currentFocus` 的 size 均为 4。偏移签名锚定当前拥有者及实际 LEA/ADD/load 指令；需要跨函数边界的短签名显式标记。
- 三个接口每个产物严格只有 `func_name`、`vtable_name`、`vfunc_index`、`vfunc_offset`。G 集合由 gameui 单一生产者输出，engine/serverbrowser 通过同 tag/platform 的 declared input 和当前调用槽位交叉核验；CS-only 集合由 client 输出。不同宿主的实现地址不用于接口身份。
- 新增配置覆盖 21 个 tag，声明单一生产者及同 tag 依赖。`hl-10210` Windows 的既有 Video OnApplyChanges 原样复用，Linux 和其余缺少的 13 份由新路线补齐。#7、#28 与 C 组既有记录没有重复实现；既有 tracked artifacts 无内容差异。
- AddPage 产物采用真实 `vgui2::PropertySheet::AddPage(vgui2::Panel*, char const*)` 双参数签名。本轮只交付本仓库数据与 finder，MetaHookSv 的下游迁移另行处理。

### 验证证据

最终生产批次：`analysis-batch-20261001T141923-add05655fcaa47748f130eab39664f09`，选择 62 个 finder 节点，forced execution、owned strict restored/no-save 生命周期；**Successful 62 / Failed 0 / Skipped 0**。每个输出经 analyzer 的 artifact validation。临时 selection 与诊断保存在 `C:/Users/HZDEV/AppData/Local/Temp/issue312/`，未加入仓库。

独立临时 `check_artifacts.py` 将生成 YAML 与本文件确认时的 Stage verified facts / GameUI audit 对比，核对当前方法 RVA、vfunc_index、VA/RVA arithmetic、成员偏移、接口四字段及同引擎槽位一致性：**CHECKED 580 / EXPECTED 580 / ERRORS []**；580 含原有 HL25 Windows Video 的 1 条复用记录。

行为测试增加 moved slots、错误接收者、歧义/缺失候选、消息记录位置变化、Itanium this adjustment、透明 stack-check、嵌入对象 dispatch、容器 getter 展开、符号索引寻址和字段引用指令等情形。结果：

```powershell
uv run python tests/run_test_suite.py unit -b --durations 30
# Ran 1319 tests; OK (skipped=5)
uv run python tests/run_test_suite.py repository-contract -b --durations 30
# Ran 15 tests; OK
```

`uv run python format_repo_files.py --check` 退出 0（635 files already formatted，29 YAML unchanged）；Git whitespace check 退出 0。配置/依赖独立核验为 21/21 通过；第二个识别逻辑核验代理因运行错误未返回结论，关键逻辑改由主会话复核。

### PR #317：CI warm-IDB 回归修复

[首次 CI job](https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/36827440899/job/110259340618?pr=317) 在 `svencoop-8948 / engine / Windows` 的 SetFocus callback 身份处失败（1 个失败，后续 45 个节点未执行；此前 465 个成功）。本地已补充分析的 IDB 未暴露这个问题。

用与 CI 缓存选择清单 SHA-256 一致的 hw.dll，在隔离目录仅运行仓库 warmup 自动分析，再通过 owned strict/no-save probe 复现：当前注册里的 callback 已是 decoded code，但没有 IDA function object，所以原 collector 的 `describe` 没有采集其 flow。没有把数据库状态差异当成目标不存在。

修复将当前 SetFocus construction block / explicit registration call 的 callback 常量提取为共享 helper；对其中映射到已解码、未归属 code entry 的地址补建函数元数据。已有函数不拆分、不替换。随后仍验证实际 this 接收者、单个虚调用和当前 Panel/EditablePanel 表及 NavGroup 关系；没有加入 RVA、槽位、字节模式或缓存状态分支。

修复后在同一份隔离 warm-IDB 恢复 SetFocus slot，并用生产 analyzer 按 CI 的前置顺序执行 7 个节点：批次 `analysis-batch-20261001T160819-5d9db5dbe13e40e384b7431bc9c25977`，**7 succeeded / 0 failed / 0 skipped**，artifacts 无内容差异。新增行为测试排除其他 construction block 和缺少 block 身份的 callback 候选；当前 unit **1320 项 OK（5 skipped）**，repository-contract **15 项 OK**，formatter / whitespace check 退出 0。修复推送后继续核对完整矩阵和 GitHub CI；后续状态在 PR 中报告。

### PR #317 review：绑定实际注册记录与 GetPage 返回值

2026-10-01 的 review 发现两处身份验证弱于已批准的方案：SetFocus 原先只收集同一 construction block 的常量，不能证明名称、callback 和零参数计数属于同一条被 Panel map 消费的记录；GetPage 原先只验证计数成员和输入参数的使用，可能接受始终返回 null 的候选。

- SetFocus 现在从当前 Panel 消息分发器的零参数分支恢复 callback/count 字段位置，并从实际 GetMessageMap 返回值恢复 entries 数组字段。沿当前 `Panel` 查询和注册调用的真实寄存器/栈参数跟踪记录，要求完整字段被复制到该数组；支持 REP、逐字循环及 SSE 逐字段复制。名称、callback/PMF、零参数计数和 this adjustment 均取自同一条消费记录。只有绑定后的 Windows callback 才补建缺失的函数对象。
- 内联 map 查询的非零路径和经过当前表验证的去虚拟化分支用于保留明确的 map 来源；复制目标不能仅因来自 map 的任意字段就被接受。没有添加版本、槽位或成员位置常量。
- GetPage 必须实际返回由输入索引寻址的 pages 元素；pages 存储成员与 ResetAllData/ApplyChanges 一致。允许独立的越界 null 分支以及已验证的无副作用叶子 helper，拒绝仅返回 null、未知值、其他容器、错误索引/步长或元素地址的候选。
- 回归测试覆盖缺失消费证据、错误名称/计数/PMF adjustment、不完整复制、未覆盖的注册 owner、错误 map/storage 来源、动态消息布局、SSE 字段复制和上述 GetPage 伪候选。
- Sven-10257 Linux engine 的初次完整验证触及单次 IDA tool 请求的 60 秒累计期限。采集现按当前表、依赖方法、注册与身份验证拆为连续请求；使用同一 owned worker 中的唯一临时 namespace 保留原始对象，结束或失败时清理。规则与分析数据不因拆分改变，行为测试验证跨阶段状态及错误清理。

最终代码使用两组互不重叠的 forced、owned strict restored/no-save 生产选择完成验证：`analysis-batch-20261001T192058-b2344548964a48e18837258aa5bf05df` 为 **55 succeeded / 0 failed / 0 skipped**；`analysis-batch-20261001T192010-a162e5773b84482ca5f71f175fa70af7` 为 **7 succeeded / 0 failed / 0 skipped**。独立集合检查确认二者恰好覆盖原 62 个目标；输出均通过 analyzer 验证。

与已批准 Task 1 facts 的独立对比为 **580/580，ERRORS []**（含复用的 HL25 Windows Video），`bin_artifacts` 无内容差异。隔离 warm-only Sven-8948 Windows engine probe 恢复 SetFocus slot 89，owned session 正常释放。最终 unit **1332 项 OK（5 skipped）**、repository-contract **15 项 OK**；formatter 和 Git whitespace check 退出 0。临时探针、selection 和日志保留在仓库外。

## 附录 A：62 份输入身份与 SetProportional 结果

每行均有一个通过状态写入/递归/布局失效条件的 Panel 候选。表 RVA 是 primary address point 的 RVA。`VA = image base + RVA`。

| 输入（相对于 `bin/`） | SHA-256 | image base | Panel 表 RVA | SetProportional RVA / index |
| --- | --- | --- | --- | --- |
| `cof-5936/engine/hw.dll` | `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875` | `0x1d00000` | `0x1907cc` | `0x12d69d` / 113 |
| `cof-5936/gameui/GameUI.dll` | `8255926f84eaa08e9096f2f78dea7f2827c3733e7af8f4408efa0b423acca838` | `0x10000000` | `0xd0038` | `0x62c5d` / 113 |
| `cof-5936/serverbrowser/ServerBrowser.dll` | `5469f30878c12d5b789bfafca6db1f9690e281ec27a1c03a8c60138c18e68ead` | `0x10000000` | `0x62e94` | `0x1be50` / 113 |
| `cstrike-10210/client/client.so` | `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a` | `0x0` | `0x194028` | `0x12db10` / 114 |
| `cstrike-10210/client/client.dll` | `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2` | `0x10000000` | `0xd1cd8` | `0x77bd0` / 113 |
| `cstrike-3248/client/client.decrypt.dll` | `2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b` | `0x1900000` | `0xc907c` | `0x781c0` / 113 |
| `cstrike-3647/client/client.decrypt.dll` | `2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b` | `0x1900000` | `0xc907c` | `0x781c0` / 113 |
| `cstrike-4554/client/client.dll` | `733d4b48a64991d2cd2a60c20d99f72b6533cc401c47f97cc0e6073bd482b6dc` | `0x1900000` | `0xcf378` | `0x7ccf0` / 113 |
| `cstrike-6153/client/client.so` | `0d379680b7545ed352a696539a8049432651edb7056efbf2ce8354347d0feded` | `0x0` | `0x1d48e8` | `0x178570` / 114 |
| `cstrike-6153/client/client.dll` | `221f4c8f8eb6348f90c72c11c252fcf0024d3b3032e503cfab80b3f4c5bee841` | `0x1900000` | `0xcf404` | `0x7a800` / 113 |
| `cstrike-8684/client/client.so` | `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798` | `0x0` | `0x1d3f08` | `0x1788d0` / 114 |
| `cstrike-8684/client/client.dll` | `ef7a0f40989cb79ba95d40f528534da36866892ee871147ca82e133b7a5edc3d` | `0x1900000` | `0xd03fc` | `0x7bb80` / 113 |
| `czero-10210/client/client.so` | `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a` | `0x0` | `0x194028` | `0x12db10` / 114 |
| `czero-10210/client/client.dll` | `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2` | `0x10000000` | `0xd1cd8` | `0x77bd0` / 113 |
| `czero-8684/client/client.so` | `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798` | `0x0` | `0x1d3f08` | `0x1788d0` / 114 |
| `czero-8684/client/client.dll` | `b017e06a5551f3db8c7c817b72a65433362d8b3c8394edb02cac919528e3f73c` | `0x1900000` | `0xd03fc` | `0x7bb80` / 113 |
| `czeror-10210/client/client.so` | `37933b1a6afa92c584b4a0b01cc93401317c288bce0eee268d45035ce5ab9890` | `0x0` | `0x163dc8` | `0x114100` / 114 |
| `czeror-10210/client/client.dll` | `7eccfa2fd50e391dfeca4ada44110b5e6336523f9d5dd1433f043a0daecbb584` | `0x10000000` | `0xb36a0` | `0x683f0` / 113 |
| `czeror-8684/client/client.so` | `515bf1bc95ae8ec161cb99a2d25f53efe0744375dde85879b567710074844971` | `0x0` | `0x1a6948` | `0x15e480` / 114 |
| `czeror-8684/client/client.dll` | `e28ef031c1810a913227fbdf8075a367a60165d209b8071a94020a448ff76286` | `0x27000000` | `0xb2364` | `0x69ed0` / 113 |
| `hl-10210/engine/hw.so` | `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78` | `0x0` | `0x26835c` | `0x200ea0` / 114 |
| `hl-10210/engine/hw.dll` | `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295` | `0x10000000` | `0x2dfcdc` | `0x2770c0` / 113 |
| `hl-10210/gameui/gameui.so` | `6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a` | `0x0` | `0x156c14` | `0xf8740` / 114 |
| `hl-10210/gameui/GameUI.dll` | `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811` | `0x10000000` | `0xa4908` | `0x4c9f0` / 113 |
| `hl-10210/serverbrowser/serverbrowser_linux.so` | `13c95a4df32f04fdb52112068e97ba3372c3157c0dcaf421e6c28864a0c7de0b` | `0x0` | `0xc113c` | `0x7f8c0` / 114 |
| `hl-10210/serverbrowser/ServerBrowser.dll` | `0c8dff5862b7e8209cdf9690f49a0bf4e29cc3410e9fb6ee77ed240f428b563c` | `0x10000000` | `0x58a0c` | `0x19640` / 113 |
| `hl-3248/engine/hw.decrypt.dll` | `7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0` | `0x1d00000` | `0x18b184` | `0xdb770` / 113 |
| `hl-3248/gameui/GameUI.dll` | `2f1424c3e9a471c5b92d42aaaad6e63227fd6af5967915482c48c75028a8ced9` | `0x10000000` | `0x128f24` | `0x482c0` / 113 |
| `hl-3248/serverbrowser/ServerBrowser.dll` | `32aa55403b7f5aa3e816ae05b1ea7624865a46800931e9483b9feafc841b62d7` | `0x10000000` | `0xd81ec` | `0x1e050` / 113 |
| `hl-3266/engine/hw.decrypt.dll` | `d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21` | `0x1d00000` | `0x18b184` | `0xdb770` / 113 |
| `hl-3266/gameui/GameUI.dll` | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` | `0x10000000` | `0x1694dc` | `0x500b0` / 113 |
| `hl-3266/serverbrowser/ServerBrowser.dll` | `32aa55403b7f5aa3e816ae05b1ea7624865a46800931e9483b9feafc841b62d7` | `0x10000000` | `0xd81ec` | `0x1e050` / 113 |
| `hl-3329/engine/hw.decrypt.dll` | `4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480` | `0x1d00000` | `0x167154` | `0xdb040` / 113 |
| `hl-3329/gameui/GameUI.dll` | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` | `0x10000000` | `0x1694dc` | `0x500b0` / 113 |
| `hl-3329/serverbrowser/ServerBrowser.dll` | `32aa55403b7f5aa3e816ae05b1ea7624865a46800931e9483b9feafc841b62d7` | `0x10000000` | `0xd81ec` | `0x1e050` / 113 |
| `hl-3647/engine/hw.decrypt.dll` | `7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110` | `0x1d00000` | `0x166114` | `0xda200` / 113 |
| `hl-3647/gameui/GameUI.dll` | `b3588b7ca8f25c70cb062dc12f680e2e8abd75d271026d6e219055fe03a7b172` | `0x10000000` | `0x128f14` | `0x477d0` / 113 |
| `hl-3647/serverbrowser/ServerBrowser.dll` | `32118234f5fa38248e03e4e25846b8b4ce78fdfaffbd44cbfad8205139e25e2d` | `0x10000000` | `0xab9ac` | `0x246e0` / 113 |
| `hl-4554/engine/hw.dll` | `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3` | `0x1d00000` | `0x14d41c` | `0xfaa30` / 113 |
| `hl-4554/gameui/GameUI.dll` | `5359ffc4589711c625f88ba717391a05cfa91ce273e580a26e27298ad91f38ec` | `0x10000000` | `0x9eec0` | `0x48d40` / 113 |
| `hl-4554/serverbrowser/ServerBrowser.dll` | `da3e67ab250acee2740204381bbf9ad9beea0afb3cf3f97ae97b5204e9a90af2` | `0x10000000` | `0x62184` | `0x1d070` / 113 |
| `hl-6153/engine/hw.dll` | `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257` | `0x1d00000` | `0x11ecec` | `0xdee60` / 113 |
| `hl-6153/gameui/GameUI.dll` | `0c43c0c20f33c5d79fe48e3fa0fefcf37f626ce5a74581a1048171dbf000c10b` | `0x10000000` | `0x9c0ac` | `0x482f0` / 113 |
| `hl-6153/serverbrowser/ServerBrowser.dll` | `da3e67ab250acee2740204381bbf9ad9beea0afb3cf3f97ae97b5204e9a90af2` | `0x10000000` | `0x62184` | `0x1d070` / 113 |
| `hl-8684/engine/hw.so` | `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1` | `0x0` | `0x289a88` | `0x233870` / 114 |
| `hl-8684/engine/hw.dll` | `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10` | `0x1d00000` | `0x120cfc` | `0xe11b0` / 113 |
| `hl-8684/gameui/gameui.so` | `fa1ff86540bd216d4d280bf18c02d8835fb7bfad5e58c8f17028bbb40b97cd74` | `0x0` | `0x17f4e8` | `0x12c280` / 114 |
| `hl-8684/gameui/GameUI.dll` | `684fb5615f0c3ab7d07fcf5503eb214d064c70e25eb0eb22bbf043b4d73c162f` | `0x10000000` | `0x9d09c` | `0x48440` / 113 |
| `hl-8684/serverbrowser/serverbrowser_linux.so` | `5cbc7799a16c2ebf62d263ca81686e5e4f7f9a47fbf7841b7bc14be2363f1400` | `0x0` | `0xdab48` | `0xa2780` / 114 |
| `hl-8684/serverbrowser/ServerBrowser.dll` | `b16954a16690755c0ed5970d9b6263a5913fd2b318ef2f2e75f3580259fa52f0` | `0x10000000` | `0x62ebc` | `0x1c430` / 113 |
| `svencoop-10257/engine/hw.so` | `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd` | `0x0` | `0x2e1a50` | `0x21e5d0` / 114 |
| `svencoop-10257/engine/hw.dll` | `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596` | `0x1d00000` | `0x194860` | `0x105760` / 113 |
| `svencoop-10257/gameui/gameui.so` | `7bd0deabeb1ff8537c144043d0ba591587fb3e3090d14c6b18ffe14b511e3c39` | `0x0` | `0x11b33c` | `0xaf540` / 114 |
| `svencoop-10257/gameui/GameUI.dll` | `99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75` | `0x10000000` | `0x898a0` | `0x253f0` / 113 |
| `svencoop-10257/serverbrowser/serverbrowser_linux.so` | `2161eb755d4eb4e0730188e4e8ff782763fd7da1fc2a08d862f6166c19f5dd33` | `0x0` | `0xedf0c` | `0x89fa0` / 114 |
| `svencoop-10257/serverbrowser/serverbrowser.dll` | `cde3069779a3869165b45302231a6b163a5a175502c316390ee800bf89b1bf05` | `0x10000000` | `0x6cb6c` | `0x170e0` / 113 |
| `svencoop-8948/engine/hw.so` | `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e` | `0x0` | `0x32d310` | `0x26a4e0` / 114 |
| `svencoop-8948/engine/hw.dll` | `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8` | `0x1d00000` | `0x18d270` | `0x1020c0` / 113 |
| `svencoop-8948/gameui/gameui.so` | `b0eb4ecdc1d79853ba159346b824fc9b7665e8aae75cb5d51330084be273b6e3` | `0x0` | `0x1332fc` | `0xc72f0` / 114 |
| `svencoop-8948/gameui/GameUI.dll` | `0f653d41010add218b1baeea57ffaeb9875eba1cc78157bc0cf17d300a90a524` | `0x10000000` | `0x868a0` | `0x250e0` / 113 |
| `svencoop-8948/serverbrowser/serverbrowser_linux.so` | `f5945a38879655cb72f82fd0f9d451908e0e5eb7f19042e5c3c306acb444b62f` | `0x0` | `0xf9eec` | `0x96860` / 114 |
| `svencoop-8948/serverbrowser/serverbrowser.dll` | `c9f441d3a9edff1a7839d354504552b008ea939f41a2ad200cf7bd3e11c9b720` | `0x10000000` | `0x69b6c` | `0x16d50` / 113 |

## 附录 B：GameUI 方法地址与成员结果

各段为对应当前二进制的候选记录。格式 `#编号 = RVA@index`；所有 Windows GameUI 的 image base 为 `0x10000000`，Linux 为 0。#8 的真实双参数身份、#24 的复用关系见正文。此地址表没有批准任何 index 常量或连续位置发现法。

### cof-5936.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x62c5d` | 113 |
| #5 GetFocusNavGroup | `0x6cf2f` | 153 |
| #6 GetCurrentFocus | `0xa3dd0` | 7 |
| #8 AddPage | `0xa9390` | 134 |
| #9 SetActivePage | `0xa94f0` | 135 |
| #10 SetTabWidth | `0xa952b` | 136 |
| #11 GetActivePage | `0xa9698` | 137 |
| #12 ResetAllData | `0xa9556` | 138 |
| #13 ApplyChanges | `0xa95f7` | 139 |
| #14 GetPage | `0xa9cc2` | 140 |
| #15 DeletePage | `0xa9e1b` | 141 |
| #16 GetActiveTab | `0xa96ac` | 142 |
| #17 GetActiveTabTitle | `0xa96d6` | 143 |
| #18 GetTabTitle | `0xa9711` | 144 |
| #19 GetActivePageNum | `0xa976a` | 145 |
| #20 GetNumPages | `0xa96c0` | 146 |
| #21 DisablePage | `0xa9cf8` | 147 |
| #22 EnablePage | `0xa9d19` | 148 |
| #23 ChangeActiveTab | `0xa9f21` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x5717d` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x5072e` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x5618c` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x206d4` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-10210.gameui.linux

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0xf8740` | 114 |
| #5 GetFocusNavGroup | `0xcf640` | 154 |
| #6 GetCurrentFocus | `0xd27a0` | 7 |
| #8 AddPage | `0x1032a0` | 135 |
| #9 SetActivePage | `0x102cc0` | 136 |
| #10 SetTabWidth | `0x102d10` | 137 |
| #11 GetActivePage | `0x102d40` | 138 |
| #12 ResetAllData | `0x103c20` | 139 |
| #13 ApplyChanges | `0x103d10` | 140 |
| #14 GetPage | `0x102e50` | 141 |
| #15 DeletePage | `0x103e50` | 142 |
| #16 GetActiveTab | `0x102d50` | 143 |
| #17 GetActiveTabTitle | `0x102d70` | 144 |
| #18 GetTabTitle | `0x103b40` | 145 |
| #19 GetActivePageNum | `0x102da0` | 146 |
| #20 GetNumPages | `0x102d60` | 147 |
| #21 DisablePage | `0x102e80` | 148 |
| #22 EnablePage | `0x102eb0` | 149 |
| #23 ChangeActiveTab | `0x105c80` | 150 |
| #25 COptionsSubVideo::OnApplyChanges | `0xafb50` | 160 |
| #26 COptionsSubAudio::OnApplyChanges | `0xa71e0` | 160 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0xaafc0` | 160 |
| #29 CBasePanel::ApplySchemeSettings | `0x73640` | 80 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x94` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x98`；EditablePanel.m_NavGroup=`0x7c`。
### hl-10210.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x4c9f0` | 113 |
| #5 GetFocusNavGroup | `0x51bc0` | 153 |
| #6 GetCurrentFocus | `0x80410` | 7 |
| #8 AddPage | `0x856f0` | 134 |
| #9 SetActivePage | `0x86fb0` | 135 |
| #10 SetTabWidth | `0x87000` | 136 |
| #11 GetActivePage | `0x7c4d0` | 137 |
| #12 ResetAllData | `0x86ea0` | 138 |
| #13 ApplyChanges | `0x85a00` | 139 |
| #14 GetPage | `0x863a0` | 140 |
| #15 DeletePage | `0x85f40` | 141 |
| #16 GetActiveTab | `0x73070` | 142 |
| #17 GetActiveTabTitle | `0x86270` | 143 |
| #18 GetTabTitle | `0x863e0` | 144 |
| #19 GetActivePageNum | `0x86230` | 145 |
| #20 GetNumPages | `0x4e450` | 146 |
| #21 DisablePage | `0x86100` | 147 |
| #22 EnablePage | `0x86210` | 148 |
| #23 ChangeActiveTab | `0x85ba0` | 149 |
| #25 COptionsSubVideo::OnApplyChanges（已有，复用） | `0x38650` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x32590` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x36f00` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x7d10` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x94` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x98`；EditablePanel.m_NavGroup=`0x7c`。
### hl-3248.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x482c0` | 113 |
| #5 GetFocusNavGroup | `0x4e720` | 153 |
| #6 GetCurrentFocus | `0x74600` | 7 |
| #8 AddPage | `0x77f70` | 134 |
| #9 SetActivePage | `0x784f0` | 135 |
| #10 SetTabWidth | `0x78530` | 136 |
| #11 GetActivePage | `0x78670` | 137 |
| #12 ResetAllData | `0x78550` | 138 |
| #13 ApplyChanges | `0x785e0` | 139 |
| #14 GetPage | `0x78ab0` | 140 |
| #15 DeletePage | `0x78c00` | 141 |
| #16 GetActiveTab | `0x78680` | 142 |
| #17 GetActiveTabTitle | `0x786a0` | 143 |
| #18 GetTabTitle | `0x786c0` | 144 |
| #19 GetActivePageNum | `0x78710` | 145 |
| #20 GetNumPages | `0x78690` | 146 |
| #21 DisablePage | `0x78ae0` | 147 |
| #22 EnablePage | `0x78b00` | 148 |
| #23 ChangeActiveTab | `0x78d80` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3dc60` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x39240` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3cfa0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b80` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-3266.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x500b0` | 113 |
| #5 GetFocusNavGroup | `0x5ce20` | 153 |
| #6 GetCurrentFocus | `0xace00` | 7 |
| #8 AddPage | `0xb4ba0` | 134 |
| #9 SetActivePage | `0xb5410` | 135 |
| #10 SetTabWidth | `0xb5480` | 136 |
| #11 GetActivePage | `0xb56c0` | 137 |
| #12 ResetAllData | `0xb54e0` | 138 |
| #13 ApplyChanges | `0xb55d0` | 139 |
| #14 GetPage | `0xb5f70` | 140 |
| #15 DeletePage | `0xb61a0` | 141 |
| #16 GetActiveTab | `0xb56f0` | 142 |
| #17 GetActiveTabTitle | `0xb5760` | 143 |
| #18 GetTabTitle | `0xb57d0` | 144 |
| #19 GetActivePageNum | `0xb5860` | 145 |
| #20 GetNumPages | `0xb5720` | 146 |
| #21 DisablePage | `0xb5fd0` | 147 |
| #22 EnablePage | `0xb6020` | 148 |
| #23 ChangeActiveTab | `0xb6300` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3dc90` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x39270` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3cfd0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b80` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-3329.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x500b0` | 113 |
| #5 GetFocusNavGroup | `0x5ce20` | 153 |
| #6 GetCurrentFocus | `0xace00` | 7 |
| #8 AddPage | `0xb4ba0` | 134 |
| #9 SetActivePage | `0xb5410` | 135 |
| #10 SetTabWidth | `0xb5480` | 136 |
| #11 GetActivePage | `0xb56c0` | 137 |
| #12 ResetAllData | `0xb54e0` | 138 |
| #13 ApplyChanges | `0xb55d0` | 139 |
| #14 GetPage | `0xb5f70` | 140 |
| #15 DeletePage | `0xb61a0` | 141 |
| #16 GetActiveTab | `0xb56f0` | 142 |
| #17 GetActiveTabTitle | `0xb5760` | 143 |
| #18 GetTabTitle | `0xb57d0` | 144 |
| #19 GetActivePageNum | `0xb5860` | 145 |
| #20 GetNumPages | `0xb5720` | 146 |
| #21 DisablePage | `0xb5fd0` | 147 |
| #22 EnablePage | `0xb6020` | 148 |
| #23 ChangeActiveTab | `0xb6300` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3dc90` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x39270` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3cfd0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b80` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-3647.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x477d0` | 113 |
| #5 GetFocusNavGroup | `0x4dcf0` | 153 |
| #6 GetCurrentFocus | `0x74210` | 7 |
| #8 AddPage | `0x77bb0` | 134 |
| #9 SetActivePage | `0x78130` | 135 |
| #10 SetTabWidth | `0x78170` | 136 |
| #11 GetActivePage | `0x782b0` | 137 |
| #12 ResetAllData | `0x78190` | 138 |
| #13 ApplyChanges | `0x78220` | 139 |
| #14 GetPage | `0x786f0` | 140 |
| #15 DeletePage | `0x78840` | 141 |
| #16 GetActiveTab | `0x782c0` | 142 |
| #17 GetActiveTabTitle | `0x782e0` | 143 |
| #18 GetTabTitle | `0x78300` | 144 |
| #19 GetActivePageNum | `0x78350` | 145 |
| #20 GetNumPages | `0x782d0` | 146 |
| #21 DisablePage | `0x78720` | 147 |
| #22 EnablePage | `0x78740` | 148 |
| #23 ChangeActiveTab | `0x789c0` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3d110` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x38680` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3c430` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b40` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-4554.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x48d40` | 113 |
| #5 GetFocusNavGroup | `0x4f590` | 153 |
| #6 GetCurrentFocus | `0x768b0` | 7 |
| #8 AddPage | `0x7a3a0` | 134 |
| #9 SetActivePage | `0x7a920` | 135 |
| #10 SetTabWidth | `0x7a960` | 136 |
| #11 GetActivePage | `0x7aaa0` | 137 |
| #12 ResetAllData | `0x7a980` | 138 |
| #13 ApplyChanges | `0x7aa10` | 139 |
| #14 GetPage | `0x7af10` | 140 |
| #15 DeletePage | `0x7b060` | 141 |
| #16 GetActiveTab | `0x7aab0` | 142 |
| #17 GetActiveTabTitle | `0x7aad0` | 143 |
| #18 GetTabTitle | `0x7aaf0` | 144 |
| #19 GetActivePageNum | `0x7ab40` | 145 |
| #20 GetNumPages | `0x7aac0` | 146 |
| #21 DisablePage | `0x7af40` | 147 |
| #22 EnablePage | `0x7af60` | 148 |
| #23 ChangeActiveTab | `0x7b1e0` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3e210` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x39550` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3d4d0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x176b0` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-6153.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x482f0` | 113 |
| #5 GetFocusNavGroup | `0x4eab0` | 153 |
| #6 GetCurrentFocus | `0x73ef0` | 7 |
| #8 AddPage | `0x77880` | 134 |
| #9 SetActivePage | `0x77e00` | 135 |
| #10 SetTabWidth | `0x77e40` | 136 |
| #11 GetActivePage | `0x77f80` | 137 |
| #12 ResetAllData | `0x77e60` | 138 |
| #13 ApplyChanges | `0x77ef0` | 139 |
| #14 GetPage | `0x783c0` | 140 |
| #15 DeletePage | `0x78510` | 141 |
| #16 GetActiveTab | `0x77f90` | 142 |
| #17 GetActiveTabTitle | `0x77fb0` | 143 |
| #18 GetTabTitle | `0x77fd0` | 144 |
| #19 GetActivePageNum | `0x78020` | 145 |
| #20 GetNumPages | `0x77fa0` | 146 |
| #21 DisablePage | `0x783f0` | 147 |
| #22 EnablePage | `0x78410` | 148 |
| #23 ChangeActiveTab | `0x78690` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3db70` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x38150` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3cd90` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b70` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-8684.gameui.linux

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x12c280` | 114 |
| #5 GetFocusNavGroup | `0x10c470` | 154 |
| #6 GetCurrentFocus | `0x10ecb0` | 7 |
| #8 AddPage | `0x13a170` | 135 |
| #9 SetActivePage | `0x138d10` | 136 |
| #10 SetTabWidth | `0x138d60` | 137 |
| #11 GetActivePage | `0x138d90` | 138 |
| #12 ResetAllData | `0x1390e0` | 139 |
| #13 ApplyChanges | `0x139040` | 140 |
| #14 GetPage | `0x138e80` | 141 |
| #15 DeletePage | `0x139f40` | 142 |
| #16 GetActiveTab | `0x138da0` | 143 |
| #17 GetActiveTabTitle | `0x138dc0` | 144 |
| #18 GetTabTitle | `0x139ee0` | 145 |
| #19 GetActivePageNum | `0x138df0` | 146 |
| #20 GetNumPages | `0x138db0` | 147 |
| #21 DisablePage | `0x138eb0` | 148 |
| #22 EnablePage | `0x138ee0` | 149 |
| #23 ChangeActiveTab | `0x139180` | 150 |
| #25 COptionsSubVideo::OnApplyChanges | `0xf3680` | 160 |
| #26 COptionsSubAudio::OnApplyChanges | `0xebe90` | 160 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0xef940` | 160 |
| #29 CBasePanel::ApplySchemeSettings | `0xc2390` | 80 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### hl-8684.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x48440` | 113 |
| #5 GetFocusNavGroup | `0x4ec00` | 153 |
| #6 GetCurrentFocus | `0x740c0` | 7 |
| #8 AddPage | `0x77a50` | 134 |
| #9 SetActivePage | `0x77fd0` | 135 |
| #10 SetTabWidth | `0x78010` | 136 |
| #11 GetActivePage | `0x78150` | 137 |
| #12 ResetAllData | `0x78030` | 138 |
| #13 ApplyChanges | `0x780c0` | 139 |
| #14 GetPage | `0x78590` | 140 |
| #15 DeletePage | `0x786e0` | 141 |
| #16 GetActiveTab | `0x78160` | 142 |
| #17 GetActiveTabTitle | `0x78180` | 143 |
| #18 GetTabTitle | `0x781a0` | 144 |
| #19 GetActivePageNum | `0x781f0` | 145 |
| #20 GetNumPages | `0x78170` | 146 |
| #21 DisablePage | `0x785c0` | 147 |
| #22 EnablePage | `0x785e0` | 148 |
| #23 ChangeActiveTab | `0x78860` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x3dcd0` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x382a0` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x3cef0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x16b80` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### svencoop-10257.gameui.linux

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0xaf540` | 114 |
| #5 GetFocusNavGroup | `0x7caa0` | 154 |
| #6 GetCurrentFocus | `0x7fd90` | 7 |
| #8 AddPage | `0xbd810` | 135 |
| #9 SetActivePage | `0xbcc00` | 136 |
| #10 SetTabWidth | `0xbcc50` | 137 |
| #11 GetActivePage | `0xbcc80` | 138 |
| #12 ResetAllData | `0xbe000` | 139 |
| #13 ApplyChanges | `0xbe140` | 140 |
| #14 GetPage | `0xbcd70` | 141 |
| #15 DeletePage | `0xbd610` | 142 |
| #16 GetActiveTab | `0xbcc90` | 143 |
| #17 GetActiveTabTitle | `0xbccb0` | 144 |
| #18 GetTabTitle | `0xbd4b0` | 145 |
| #19 GetActivePageNum | `0xbcce0` | 146 |
| #20 GetNumPages | `0xbcca0` | 147 |
| #21 DisablePage | `0xbcda0` | 148 |
| #22 EnablePage | `0xbcdd0` | 149 |
| #23 ChangeActiveTab | `0xbfc60` | 150 |
| #25 COptionsSubVideo::OnApplyChanges | `0x5bda0` | 160 |
| #26 COptionsSubAudio::OnApplyChanges | `0x53800` | 160 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x57950` | 160 |
| #29 CBasePanel::ApplySchemeSettings | `0x2bdd0` | 80 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### svencoop-10257.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x253f0` | 113 |
| #5 GetFocusNavGroup | `0x2b3b0` | 153 |
| #6 GetCurrentFocus | `0x4ddc0` | 7 |
| #8 AddPage | `0x52b90` | 134 |
| #9 SetActivePage | `0x54310` | 135 |
| #10 SetTabWidth | `0x54350` | 136 |
| #11 GetActivePage | `0x443b0` | 137 |
| #12 ResetAllData | `0x54220` | 138 |
| #13 ApplyChanges | `0x52ea0` | 139 |
| #14 GetPage | `0x53800` | 140 |
| #15 DeletePage | `0x533c0` | 141 |
| #16 GetActiveTab | `0x3d130` | 142 |
| #17 GetActiveTabTitle | `0x536d0` | 143 |
| #18 GetTabTitle | `0x53840` | 144 |
| #19 GetActivePageNum | `0x53690` | 145 |
| #20 GetNumPages | `0x267e0` | 146 |
| #21 DisablePage | `0x53550` | 147 |
| #22 EnablePage | `0x53670` | 148 |
| #23 ChangeActiveTab | `0x53020` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x1d710` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x173f0` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x1bcb0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x1750` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### svencoop-8948.gameui.linux

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0xc72f0` | 114 |
| #5 GetFocusNavGroup | `0x94850` | 154 |
| #6 GetCurrentFocus | `0x97b40` | 7 |
| #8 AddPage | `0xd55c0` | 135 |
| #9 SetActivePage | `0xd49b0` | 136 |
| #10 SetTabWidth | `0xd4a00` | 137 |
| #11 GetActivePage | `0xd4a30` | 138 |
| #12 ResetAllData | `0xd5db0` | 139 |
| #13 ApplyChanges | `0xd5ef0` | 140 |
| #14 GetPage | `0xd4b20` | 141 |
| #15 DeletePage | `0xd53c0` | 142 |
| #16 GetActiveTab | `0xd4a40` | 143 |
| #17 GetActiveTabTitle | `0xd4a60` | 144 |
| #18 GetTabTitle | `0xd5260` | 145 |
| #19 GetActivePageNum | `0xd4a90` | 146 |
| #20 GetNumPages | `0xd4a50` | 147 |
| #21 DisablePage | `0xd4b50` | 148 |
| #22 EnablePage | `0xd4b80` | 149 |
| #23 ChangeActiveTab | `0xd7a10` | 150 |
| #25 COptionsSubVideo::OnApplyChanges | `0x73b50` | 160 |
| #26 COptionsSubAudio::OnApplyChanges | `0x6b5b0` | 160 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x6f700` | 160 |
| #29 CBasePanel::ApplySchemeSettings | `0x43b80` | 80 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。
### svencoop-8948.gameui.windows

| 编号 / 身份 | RVA | 当前 index / offset |
| --- | --- | --- |
| #2 SetProportional | `0x250e0` | 113 |
| #5 GetFocusNavGroup | `0x2b080` | 153 |
| #6 GetCurrentFocus | `0x4d640` | 7 |
| #8 AddPage | `0x52330` | 134 |
| #9 SetActivePage | `0x53ac0` | 135 |
| #10 SetTabWidth | `0x53b10` | 136 |
| #11 GetActivePage | `0x43cf0` | 137 |
| #12 ResetAllData | `0x539b0` | 138 |
| #13 ApplyChanges | `0x52630` | 139 |
| #14 GetPage | `0x52fc0` | 140 |
| #15 DeletePage | `0x52b70` | 141 |
| #16 GetActiveTab | `0x3cb20` | 142 |
| #17 GetActiveTabTitle | `0x52e90` | 143 |
| #18 GetTabTitle | `0x53000` | 144 |
| #19 GetActivePageNum | `0x52e50` | 145 |
| #20 GetNumPages | `0x26510` | 146 |
| #21 DisablePage | `0x52d20` | 147 |
| #22 EnablePage | `0x52e30` | 148 |
| #23 ChangeActiveTab | `0x527d0` | 149 |
| #25 COptionsSubVideo::OnApplyChanges | `0x1d5f0` | 159 |
| #26 COptionsSubAudio::OnApplyChanges | `0x17430` | 159 |
| #27 COptionsSubMultiplayer::OnApplyChanges | `0x1bbe0` | 159 |
| #29 CBasePanel::ApplySchemeSettings | `0x1770` | 79 |
| #30 PropertySheet._activePage | 从 HasHotkey/getter/切页指令推导 | `0x90` |
| #31 FocusNavGroup._currentFocus | 从 GetCurrentFocus 的 handle receiver 推导 | `0xc` |

交叉布局结果：activeTab=`0x94`；EditablePanel.m_NavGroup=`0x78`。

## 附录 C：字符串与 owning-function 数量

每格为 `字节中完整 NUL literal 出现数 / IDA code-xref owning-function 数`。某些片段（如 tab）可能还作为别的字符串尾部出现，只有有代码引用并满足正文身份的候选才有意义。PIC 实际参数与类表交叉验证补充普通 xref；不能用下表的全局数量冒充唯一目标函数。

| GameUI 输入 | tab | ResetData | ApplyChanges | PageHide | PageShow | PageChanged | cl_logofile format | BackgroundLayout |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cof-5936.gameui.windows | 1/1 | 3/3 | 3/3 | 2/3 | 2/2 | 1/1 | 1/1 | 1/1 |
| hl-10210.gameui.linux | 1/1 | 1/3 | 1/5 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-10210.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-3248.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-3266.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-3329.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-3647.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-4554.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-6153.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-8684.gameui.linux | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| hl-8684.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| svencoop-10257.gameui.linux | 1/1 | 1/3 | 1/5 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| svencoop-10257.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| svencoop-8948.gameui.linux | 1/1 | 1/3 | 1/5 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |
| svencoop-8948.gameui.windows | 1/1 | 1/3 | 1/3 | 1/3 | 1/2 | 1/1 | 1/1 | 1/1 |

## 附录 D：生命周期与 IDB 保存结果

每个主采集 lifecycle 正常退出时自动 save 成功；其 owned worker/supervisor cleanup 后 port-release 为 true。后续短方法/constructor 核验也仅使用该任务自己创建的 lifecycle。下表为汇总时再次查询到的最终 IDB 修改时间，UTC。

| 输入身份 | 最终 IDB（相对于 `bin/`） | 最终修改时间 UTC | save / graceful lifecycle exit / port release |
| --- | --- | --- | --- |
| cof-5936.engine.windows | `cof-5936/engine/hw.dll.i64` | 2026-09-30T16:15:38+00:00 | success / success / true |
| cof-5936.gameui.windows | `cof-5936/gameui/GameUI.dll.i64` | 2026-09-30T16:10:07+00:00 | success / success / true |
| cof-5936.serverbrowser.windows | `cof-5936/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:21:25+00:00 | success / success / true |
| cstrike-10210.client.linux | `cstrike-10210/client/client.so.i64` | 2026-09-30T16:25:24+00:00 | success / success / true |
| cstrike-10210.client.windows | `cstrike-10210/client/client.dll.i64` | 2026-09-30T16:25:13+00:00 | success / success / true |
| cstrike-3248.client.windows | `cstrike-3248/client/client.decrypt.dll.i64` | 2026-09-30T16:24:00+00:00 | success / success / true |
| cstrike-3647.client.windows | `cstrike-3647/client/client.decrypt.dll.i64` | 2026-09-30T16:24:09+00:00 | success / success / true |
| cstrike-4554.client.windows | `cstrike-4554/client/client.dll.i64` | 2026-09-30T16:24:19+00:00 | success / success / true |
| cstrike-6153.client.linux | `cstrike-6153/client/client.so.i64` | 2026-09-30T16:24:40+00:00 | success / success / true |
| cstrike-6153.client.windows | `cstrike-6153/client/client.dll.i64` | 2026-09-30T16:24:28+00:00 | success / success / true |
| cstrike-8684.client.linux | `cstrike-8684/client/client.so.i64` | 2026-09-30T16:25:02+00:00 | success / success / true |
| cstrike-8684.client.windows | `cstrike-8684/client/client.dll.i64` | 2026-09-30T16:24:50+00:00 | success / success / true |
| czero-10210.client.linux | `czero-10210/client/client.so.i64` | 2026-09-30T16:26:08+00:00 | success / success / true |
| czero-10210.client.windows | `czero-10210/client/client.dll.i64` | 2026-09-30T16:25:57+00:00 | success / success / true |
| czero-8684.client.linux | `czero-8684/client/client.so.i64` | 2026-09-30T16:25:46+00:00 | success / success / true |
| czero-8684.client.windows | `czero-8684/client/client.dll.i64` | 2026-09-30T16:25:34+00:00 | success / success / true |
| czeror-10210.client.linux | `czeror-10210/client/client.so.i64` | 2026-09-30T16:26:52+00:00 | success / success / true |
| czeror-10210.client.windows | `czeror-10210/client/client.dll.i64` | 2026-09-30T16:26:41+00:00 | success / success / true |
| czeror-8684.client.linux | `czeror-8684/client/client.so.i64` | 2026-09-30T16:26:30+00:00 | success / success / true |
| czeror-8684.client.windows | `czeror-8684/client/client.dll.i64` | 2026-09-30T16:26:18+00:00 | success / success / true |
| hl-10210.engine.linux | `hl-10210/engine/hw.so.i64` | 2026-09-30T16:18:26+00:00 | success / success / true |
| hl-10210.engine.windows | `hl-10210/engine/hw.dll.i64` | 2026-09-30T16:18:01+00:00 | success / success / true |
| hl-10210.gameui.linux | `hl-10210/gameui/gameui.so.i64` | 2026-09-30T16:12:58+00:00 | success / success / true |
| hl-10210.gameui.windows | `hl-10210/gameui/GameUI.dll.i64` | 2026-09-30T16:28:58+00:00 | success / success / true |
| hl-10210.serverbrowser.linux | `hl-10210/serverbrowser/serverbrowser_linux.so.i64` | 2026-09-30T16:23:07+00:00 | success / success / true |
| hl-10210.serverbrowser.windows | `hl-10210/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:22:55+00:00 | success / success / true |
| hl-3248.engine.windows | `hl-3248/engine/hw.decrypt.dll.i64` | 2026-09-30T16:15:53+00:00 | success / success / true |
| hl-3248.gameui.windows | `hl-3248/gameui/GameUI.dll.i64` | 2026-09-30T16:28:30+00:00 | success / success / true |
| hl-3248.serverbrowser.windows | `hl-3248/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:21:34+00:00 | success / success / true |
| hl-3266.engine.windows | `hl-3266/engine/hw.decrypt.dll.i64` | 2026-09-30T16:16:08+00:00 | success / success / true |
| hl-3266.gameui.windows | `hl-3266/gameui/GameUI.dll.i64` | 2026-09-30T16:28:38+00:00 | success / success / true |
| hl-3266.serverbrowser.windows | `hl-3266/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:21:44+00:00 | success / success / true |
| hl-3329.engine.windows | `hl-3329/engine/hw.decrypt.dll.i64` | 2026-09-30T16:16:22+00:00 | success / success / true |
| hl-3329.gameui.windows | `hl-3329/gameui/GameUI.dll.i64` | 2026-09-30T16:11:04+00:00 | success / success / true |
| hl-3329.serverbrowser.windows | `hl-3329/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:21:53+00:00 | success / success / true |
| hl-3647.engine.windows | `hl-3647/engine/hw.decrypt.dll.i64` | 2026-09-30T16:16:37+00:00 | success / success / true |
| hl-3647.gameui.windows | `hl-3647/gameui/GameUI.dll.i64` | 2026-09-30T16:11:19+00:00 | success / success / true |
| hl-3647.serverbrowser.windows | `hl-3647/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:22:03+00:00 | success / success / true |
| hl-4554.engine.windows | `hl-4554/engine/hw.dll.i64` | 2026-09-30T16:16:52+00:00 | success / success / true |
| hl-4554.gameui.windows | `hl-4554/gameui/GameUI.dll.i64` | 2026-09-30T16:11:34+00:00 | success / success / true |
| hl-4554.serverbrowser.windows | `hl-4554/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:22:13+00:00 | success / success / true |
| hl-6153.engine.windows | `hl-6153/engine/hw.dll.i64` | 2026-09-30T16:17:07+00:00 | success / success / true |
| hl-6153.gameui.windows | `hl-6153/gameui/GameUI.dll.i64` | 2026-09-30T16:11:49+00:00 | success / success / true |
| hl-6153.serverbrowser.windows | `hl-6153/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:22:23+00:00 | success / success / true |
| hl-8684.engine.linux | `hl-8684/engine/hw.so.i64` | 2026-09-30T16:17:40+00:00 | success / success / true |
| hl-8684.engine.windows | `hl-8684/engine/hw.dll.i64` | 2026-09-30T16:17:22+00:00 | success / success / true |
| hl-8684.gameui.linux | `hl-8684/gameui/gameui.so.i64` | 2026-09-30T16:31:47+00:00 | success / success / true |
| hl-8684.gameui.windows | `hl-8684/gameui/GameUI.dll.i64` | 2026-09-30T16:12:03+00:00 | success / success / true |
| hl-8684.serverbrowser.linux | `hl-8684/serverbrowser/serverbrowser_linux.so.i64` | 2026-09-30T16:22:45+00:00 | success / success / true |
| hl-8684.serverbrowser.windows | `hl-8684/serverbrowser/ServerBrowser.dll.i64` | 2026-09-30T16:22:33+00:00 | success / success / true |
| svencoop-10257.engine.linux | `svencoop-10257/engine/hw.so.i64` | 2026-09-30T16:21:15+00:00 | success / success / true |
| svencoop-10257.engine.windows | `svencoop-10257/engine/hw.dll.i64` | 2026-09-30T16:20:33+00:00 | success / success / true |
| svencoop-10257.gameui.linux | `svencoop-10257/gameui/gameui.so.i64` | 2026-09-30T16:29:07+00:00 | success / success / true |
| svencoop-10257.gameui.windows | `svencoop-10257/gameui/GameUI.dll.i64` | 2026-09-30T16:13:54+00:00 | success / success / true |
| svencoop-10257.serverbrowser.linux | `svencoop-10257/serverbrowser/serverbrowser_linux.so.i64` | 2026-09-30T16:23:50+00:00 | success / success / true |
| svencoop-10257.serverbrowser.windows | `svencoop-10257/serverbrowser/serverbrowser.dll.i64` | 2026-09-30T16:23:38+00:00 | success / success / true |
| svencoop-8948.engine.linux | `svencoop-8948/engine/hw.so.i64` | 2026-09-30T16:19:50+00:00 | success / success / true |
| svencoop-8948.engine.windows | `svencoop-8948/engine/hw.dll.i64` | 2026-09-30T16:19:08+00:00 | success / success / true |
| svencoop-8948.gameui.linux | `svencoop-8948/gameui/gameui.so.i64` | 2026-09-30T16:13:37+00:00 | success / success / true |
| svencoop-8948.gameui.windows | `svencoop-8948/gameui/GameUI.dll.i64` | 2026-09-30T16:13:15+00:00 | success / success / true |
| svencoop-8948.serverbrowser.linux | `svencoop-8948/serverbrowser/serverbrowser_linux.so.i64` | 2026-09-30T16:23:28+00:00 | success / success / true |
| svencoop-8948.serverbrowser.windows | `svencoop-8948/serverbrowser/serverbrowser.dll.i64` | 2026-09-30T16:23:16+00:00 | success / success / true |

## 附录 E：Stage1–3 的逐输入证据

与附录 A 的相同 SHA-256/input identity 配对。RVA 为当前二进制中的函数或引用指令，不用于其他版本发现。`F`=独立 NewControl；`I`=NewControl 内联于 BuildGroup::ApplySettings。`K`=OnKeyCodeTyped 本体接口证据；`P/C`=OnKeyCodePressed / OnClose 补充入口。

### E1. 三阶段根、对象与注册证据

| 输入 | S1 owner RVA / 形式 / 原候选数 | Frame OnKeyCodeTyped RVA@index | GetFocusNavGroup RVA@index / m_NavGroup | Panel / EditablePanel OnSetFocus RVA@index | GetCurrentFocus RVA@index / _currentFocus | SetFocus 注册 owner RVA / ABI形式 |
| --- | --- | --- | --- | --- | --- | --- |
| cof-5936.engine.windows | `0x138836` / F / 2 | `0x15d7d6@101` | `0x13143f@153` / `0x78` | `0x12b390` / `0x1314d1` @89 | `0x13a300@7` / `0xc` | 0x12dce0/W |
| cof-5936.gameui.windows | `0x704c6` / F / 2 | `0x69d66@101` | `0x6cf2f@153` / `0x78` | `0x60950` / `0x6cfc1` @89 | `0xa3dd0@7` / `0xc` | 0x632a0/W |
| cof-5936.serverbrowser.windows | `0x3ac30` / F / 2 | `0x2e720@101` | `0x227f0@153` / `0x78` | `0x28e40` / `0x22860` @89 | `0x3f480@7` / `0xc` | 0x1f0c0/W |
| cstrike-10210.client.linux | `0x108d30` / F / 2 | `0x1173a0@102` | `0x111030@154` / `0x7c` | `0x12bd20` / `0x113b40` @90 | `0x114120@7` / `0xc` | 0x131660/L-reg, 0x131e20/L-reg, 0x132570/L-reg, 0x132d10/L-reg |
| cstrike-10210.client.windows | `0x80d60` / I / 2 | `0x7c0a0@101` | `0x792f0@153` / `0x7c` | `0x72530` / `0x79850` @89 | `0x990f0@7` / `0xc` | 0x72240/W |
| cstrike-3248.client.windows | `0x7d320` / F / 2 | `0x70820@101` | `0x71b10@152` / `0x78` | `0x76ad0` / `0x71b70` @89 | `0x8cd80@7` / `0xc` | 0x73a70/W |
| cstrike-3647.client.windows | `0x7d320` / F / 2 | `0x70820@101` | `0x71b10@152` / `0x78` | `0x76ad0` / `0x71b70` @89 | `0x8cd80@7` / `0xc` | 0x73a70/W |
| cstrike-4554.client.windows | `0x82040` / F / 2 | `0x74bf0@101` | `0x760f0@153` / `0x78` | `0x7b500` / `0x76170` @89 | `0x96790@7` / `0xc` | 0x78290/W |
| cstrike-6153.client.linux | `0x15e390` / F / 3 | `0x166ef0@102` | `0x163370@154` / `0x78` | `0x1758f0` / `0x1639f0` @90 | `0x165b60@7` / `0xc` | 0x17c280/L-entry, 0x17d5e0/L-entry, 0x17e980/L-entry, 0x17fd30/L-entry |
| cstrike-6153.client.windows | `0x7f9e0` / F / 2 | `0x72aa0@101` | `0x73fd0@153` / `0x78` | `0x78ee0` / `0x74030` @89 | `0x93c40@7` / `0xc` | 0x76fa0/W |
| cstrike-8684.client.linux | `0x15e6f0` / F / 3 | `0x167250@102` | `0x1636d0@154` / `0x78` | `0x175c50` / `0x163d50` @90 | `0x165ec0@7` / `0xc` | 0x17c5e0/L-entry, 0x17d940/L-entry, 0x17ece0/L-entry, 0x180090/L-entry |
| cstrike-8684.client.windows | `0x80d60` / F / 2 | `0x73e20@101` | `0x75350@153` / `0x78` | `0x7a260` / `0x753b0` @89 | `0x95040@7` / `0xc` | 0x78320/W |
| czero-10210.client.linux | `0x108d30` / F / 2 | `0x1173a0@102` | `0x111030@154` / `0x7c` | `0x12bd20` / `0x113b40` @90 | `0x114120@7` / `0xc` | 0x131660/L-reg, 0x131e20/L-reg, 0x132570/L-reg, 0x132d10/L-reg |
| czero-10210.client.windows | `0x80d60` / I / 2 | `0x7c0a0@101` | `0x792f0@153` / `0x7c` | `0x72530` / `0x79850` @89 | `0x990f0@7` / `0xc` | 0x72240/W |
| czero-8684.client.linux | `0x15e6f0` / F / 3 | `0x167250@102` | `0x1636d0@154` / `0x78` | `0x175c50` / `0x163d50` @90 | `0x165ec0@7` / `0xc` | 0x17c5e0/L-entry, 0x17d940/L-entry, 0x17ece0/L-entry, 0x180090/L-entry |
| czero-8684.client.windows | `0x80d60` / F / 2 | `0x73e20@101` | `0x75350@153` / `0x78` | `0x7a260` / `0x753b0` @89 | `0x95040@7` / `0xc` | 0x78320/W |
| czeror-10210.client.linux | `0x143940` / F / 2 | `0xf7a20@102` | `0xf16b0@154` / `0x7c` | `0x112310` / `0xf41c0` @90 | `0xf47a0@7` / `0xc` | 0x117c50/L-reg, 0x118410/L-reg, 0x118b60/L-reg, 0x119300/L-reg |
| czeror-10210.client.windows | `0x91850` / I / 2 | `0x6c900@101` | `0x69b10@153` / `0x7c` | `0x62c60` / `0x6a070` @89 | `0x94140@7` / `0xc` | 0x62970/W |
| czeror-8684.client.linux | `0x1881a0` / F / 3 | `0x148300@102` | `0x144780@154` / `0x78` | `0x15b800` / `0x144e00` @90 | `0x146f70@7` / `0xc` | 0x162190/L-entry, 0x1634f0/L-entry, 0x164890/L-entry, 0x165c40/L-entry |
| czeror-8684.client.windows | `0x884d0` / F / 2 | `0x62190@101` | `0x636c0@153` / `0x78` | `0x685b0` / `0x63720` @89 | `0x89240@7` / `0xc` | 0x66670/W |
| hl-10210.engine.linux | `0x229320` / F / 2 | `0x237bf0@102` | `0x1ec170@154` / `0x7c` | `0x1ff0b0` / `0x1eec80` @90 | `0x1ef260@7` / `0xc` | 0x2049f0/L-reg, 0x2051b0/L-reg, 0x205900/L-reg, 0x2060a0/L-reg |
| hl-10210.engine.windows | `0x27d470` / I / 2 | `0x29dd80@101` | `0x2783b0@153` / `0x7c` | `0x271940` / `0x278910` @89 | `0x27fbd0@7` / `0xc` | 0x271680/W |
| hl-10210.gameui.linux | `0xc6e50` / F / 2 | `0xd5a20@102` | `0xcf640@154` / `0x7c` | `0xf6950` / `0xd2150` @90 | `0xd27a0@7` / `0xc` | 0xfc290/L-reg, 0xfca50/L-reg, 0xfd1a0/L-reg, 0xfd940/L-reg |
| hl-10210.gameui.windows | `0x570e0` / I / 2 | `0x54a20@101` | `0x51bc0@153` / `0x7c` | `0x47280` / `0x521c0` @89 | `0x80410@7` / `0xc` | 0x46fd0/W |
| hl-10210.serverbrowser.linux | `0xa9590` / F / 2 | `0x5cc90@102` | `0x568b0@154` / `0x7c` | `0x7dad0` / `0x593c0` @90 | `0x59a10@7` / `0xc` | 0x83410/L-reg, 0x83bd0/L-reg, 0x84320/L-reg, 0x84ac0/L-reg |
| hl-10210.serverbrowser.windows | `0x3f7c0` / I / 2 | `0x33490@101` | `0x1d100@153` / `0x7c` | `0x13c40` / `0x1d700` @89 | `0x420b0@7` / `0xc` | 0x13950/W |
| hl-3248.engine.windows | `0xe1f10` / F / 2 | `0xfb5f0@101` | `0xdcdc0@153` / `0x78` | `0xedb50` / `0xdce20` @89 | `0xe2b60@7` / `0xc` | 0xd71d0/W |
| hl-3248.gameui.windows | `0x50fd0` / F / 2 | `0x4d430@101` | `0x4e720@153` / `0x78` | `0x46bc0` / `0x4e780` @89 | `0x74600@7` / `0xc` | 0x43b60/W |
| hl-3248.serverbrowser.windows | `0x3b5d0` / F / 1 | `0x34000@101` | `0x179e0@153` / `0x78` | `0x1c950` / `0x17a40` @89 | `0x3c270@7` / `0xc` | 0x198f0/W |
| hl-3266.engine.windows | `0xe1f10` / F / 2 | `0xfb5f0@101` | `0xdcdc0@153` / `0x78` | `0xedb50` / `0xdce20` @89 | `0xe2b60@7` / `0xc` | 0xd71d0/W |
| hl-3266.gameui.windows | `0x617f0` / F / 2 | `0x5b090@101` | `0x5ce20@153` / `0x78` | `0x4d0e0` / `0x5cf70` @89 | `0xace00@7` / `0xc` | 0x47760/W |
| hl-3266.serverbrowser.windows | `0x3b5d0` / F / 1 | `0x34000@101` | `0x179e0@153` / `0x78` | `0x1c950` / `0x17a40` @89 | `0x3c270@7` / `0xc` | 0x198f0/W |
| hl-3329.engine.windows | `0xe1920` / F / 2 | `0xfb0d0@101` | `0xdc620@153` / `0x78` | `0xed4d0` / `0xdc680` @89 | `0xe2540@7` / `0xc` | 0xd69e0/W |
| hl-3329.gameui.windows | `0x617f0` / F / 2 | `0x5b090@101` | `0x5ce20@153` / `0x78` | `0x4d0e0` / `0x5cf70` @89 | `0xace00@7` / `0xc` | 0x47760/W |
| hl-3329.serverbrowser.windows | `0x3b5d0` / F / 1 | `0x34000@101` | `0x179e0@153` / `0x78` | `0x1c950` / `0x17a40` @89 | `0x3c270@7` / `0xc` | 0x198f0/W |
| hl-3647.engine.windows | `0xe0b60` / F / 2 | `0xfa360@101` | `0xdb870@153` / `0x78` | `0xec7a0` / `0xdb8d0` @89 | `0xe1780@7` / `0xc` | 0xd5b50/W |
| hl-3647.gameui.windows | `0x50540` / F / 2 | `0x4ca00@101` | `0x4dcf0@153` / `0x78` | `0x46040` / `0x4dd50` @89 | `0x74210@7` / `0xc` | 0x42f80/W |
| hl-3647.serverbrowser.windows | `0x4c710` / F / 2 | `0x403a0@101` | `0x32fd0@153` / `0x78` | `0x23ca0` / `0x33030` @89 | `0x523e0@7` / `0xc` | 0x27dd0/W, 0x28a80/W, 0x28e90/W, 0x292d0/W, 0x29720/W |
| hl-4554.engine.windows | `0x102110` / F / 2 | `0x11da70@101` | `0xfc810@153` / `0x78` | `0xf9240` / `0xfc890` @89 | `0x102f90@7` / `0xc` | 0xf5fd0/W |
| hl-4554.gameui.windows | `0x51eb0` / F / 2 | `0x4e090@101` | `0x4f590@153` / `0x78` | `0x47550` / `0x4f610` @89 | `0x768b0@7` / `0xc` | 0x442e0/W |
| hl-4554.serverbrowser.windows | `0x3b100` / F / 2 | `0x2f130@101` | `0x22f70@153` / `0x78` | `0x294b0` / `0x22fd0` @89 | `0x3f660@7` / `0xc` | 0x20540/W, 0x20970/W |
| hl-6153.engine.windows | `0xe6360` / F / 2 | `0x101330@101` | `0xe0bc0@153` / `0x78` | `0xdd540` / `0xe0c20` @89 | `0xe7140@7` / `0xc` | 0xdb600/W |
| hl-6153.gameui.windows | `0x51300` / F / 2 | `0x4d5a0@101` | `0x4eab0@153` / `0x78` | `0x469d0` / `0x4eb10` @89 | `0x73ef0@7` / `0xc` | 0x44a90/W |
| hl-6153.serverbrowser.windows | `0x3b100` / F / 2 | `0x2f130@101` | `0x22f70@153` / `0x78` | `0x294b0` / `0x22fd0` @89 | `0x3f660@7` / `0xc` | 0x20540/W, 0x20970/W |
| hl-8684.engine.linux | `0x257560` / F / 3 | `0x25fcd0@102` | `0x224140@154` / `0x78` | `0x230bf0` / `0x2247c0` @90 | `0x2269c0@7` / `0xc` | 0x237580/L-entry, 0x2388e0/L-entry, 0x239c80/L-entry, 0x23b030/L-entry |
| hl-8684.engine.windows | `0xe86d0` / F / 2 | `0x1036a0@101` | `0xe2f10@153` / `0x78` | `0xdf890` / `0xe2f70` @89 | `0xe94b0@7` / `0xc` | 0xdd950/W |
| hl-8684.gameui.linux | `0x107000` / F / 3 | `0x110040@102` | `0x10c470@154` / `0x78` | `0x129600` / `0x10caf0` @90 | `0x10ecb0@7` / `0xc` | 0x12ff90/L-entry, 0x1312f0/L-entry, 0x132690/L-entry, 0x133a40/L-entry |
| hl-8684.gameui.windows | `0x51450` / F / 2 | `0x4d6f0@101` | `0x4ec00@153` / `0x78` | `0x46b20` / `0x4ec60` @89 | `0x740c0@7` / `0xc` | 0x44be0/W |
| hl-8684.serverbrowser.linux | `0xc6990` / F / 3 | `0x86570@102` | `0x829a0@154` / `0x78` | `0x9fb00` / `0x83020` @90 | `0x851e0@7` / `0xc` | 0xa6490/L-entry, 0xa77f0/L-entry, 0xa8b90/L-entry, 0xa9f40/L-entry |
| hl-8684.serverbrowser.windows | `0x3af70` / F / 2 | `0x2ec90@101` | `0x22d20@153` / `0x78` | `0x1bbe0` / `0x22d90` @89 | `0x3f790@7` / `0xc` | 0x1f600/W |
| svencoop-10257.engine.linux | `0x1dde00` / F / 2 | `0x1f2240@102` | `0x1eb970@154` / `0x78` | `0x21b0c0` / `0x1ee580` @90 | `0x1eebf0@7` / `0xc` | 0x220ec0/L-reg, 0x221950/L-reg, 0x222150/L-reg, 0x2229c0/L-reg |
| svencoop-10257.engine.windows | `0x10c490` / F / 2 | `0x126b40@101` | `0x106aa0@153` / `0x78` | `0x104360` / `0x107010` @89 | `0x10ce40@7` / `0xc` | 0x100c00/W |
| svencoop-10257.gameui.linux | `0x6f260` / F / 2 | `0x833e0@102` | `0x7caa0@154` / `0x78` | `0xac030` / `0x7f6b0` @90 | `0x7fd90@7` / `0xc` | 0xb1e30/L-reg, 0xb28c0/L-reg, 0xb30c0/L-reg, 0xb3930/L-reg |
| svencoop-10257.gameui.windows | `0x4d510` / F / 2 | `0x2df10@101` | `0x2b3b0@153` / `0x78` | `0x20dd0` / `0x2b9c0` @89 | `0x4ddc0@7` / `0xc` | 0x20b20/W |
| svencoop-10257.serverbrowser.linux | `0x49770` / F / 2 | `0x5dd00@102` | `0x573c0@154` / `0x78` | `0x86a90` / `0x59fd0` @90 | `0x5a6b0@7` / `0xc` | 0x8c890/L-reg, 0x8d320/L-reg, 0x8db20/L-reg, 0x8e390/L-reg |
| svencoop-10257.serverbrowser.windows | `0x352a0` / F / 2 | `0x2ae20@101` | `0x1a010@153` / `0x78` | `0x12950` / `0x1a620` @89 | `0x35b50@7` / `0xc` | 0x12690/W |
| svencoop-8948.engine.linux | `0x229d10` / F / 2 | `0x23e150@102` | `0x237880@154` / `0x78` | `0x266fd0` / `0x23a490` @90 | `0x23ab00@7` / `0xc` | 0x26cdd0/L-reg, 0x26d860/L-reg, 0x26e060/L-reg, 0x26e8d0/L-reg |
| svencoop-8948.engine.windows | `0x108d00` / F / 2 | `0x1230d0@101` | `0x1033d0@153` / `0x78` | `0x100d80` / `0x103930` @89 | `0x1096b0@7` / `0xc` | 0xfd730/W |
| svencoop-8948.gameui.linux | `0x87010` / F / 2 | `0x9b190@102` | `0x94850@154` / `0x78` | `0xc3de0` / `0x97460` @90 | `0x97b40@7` / `0xc` | 0xc9be0/L-reg, 0xca670/L-reg, 0xcae70/L-reg, 0xcb6e0/L-reg |
| svencoop-8948.gameui.windows | `0x4cd90` / F / 2 | `0x2db70@101` | `0x2b080@153` / `0x78` | `0x20ca0` / `0x2b680` @89 | `0x4d640@7` / `0xc` | 0x209f0/W |
| svencoop-8948.serverbrowser.linux | `0x56030` / F / 2 | `0x6a5c0@102` | `0x63c80@154` / `0x78` | `0x93350` / `0x66890` @90 | `0x66f70@7` / `0xc` | 0x99150/L-reg, 0x99be0/L-reg, 0x9a3e0/L-reg, 0x9ac50/L-reg |
| svencoop-8948.serverbrowser.windows | `0x34b10` / F / 2 | `0x2a810@101` | `0x19c90@153` / `0x78` | `0x12790` / `0x1a290` @89 | `0x353c0@7` / `0xc` | 0x124d0/W |

### E2. 共享接口的调用证据（slot-only）

本表只列 interface vcall 的引用指令 RVA 和推导 slot，**没有接口实现函数地址**。每个槽位记录按同引擎的共享 vgui2 身份合并。

| 输入 | ReloadSchemes call RVA / slot | SupportsFeature call RVA / slot / 入口 | GetAppModalSurface call RVA / slot / 入口 | 补充 owning-function RVA@index（如适用） |
| --- | --- | --- | --- | --- | --- |
| cof-5936.engine.windows | `0x15d9a4` / 2 | `0x15daf2` / 50 / K | `0x15db11` / 18 / K | — |
| cof-5936.gameui.windows | `0x69f34` / 2 | `0x6a082` / 50 / K | `0x6a0a1` / 18 / K | — |
| cof-5936.serverbrowser.windows | `0x2e860` / 2 | `0x2e9ae` / 50 / K | `0x2e9cc` / 18 / K | — |
| cstrike-10210.client.linux | `0x117583` / 3 | `0x11766b` / 51 / K | `0x117683` / 19 / K | — |
| cstrike-10210.client.windows | `0x7c1e3` / 2 | `0x7c32c` / 50 / K | `0x7c33b` / 18 / K | — |
| cstrike-3248.client.windows | `0x7092c` / 2 | `0x70677` / 50 / P | `0x7028d` / 18 / C | ISurface `0x70660@100`; IInput `0x70280@156` |
| cstrike-3647.client.windows | `0x7092c` / 2 | `0x70677` / 50 / P | `0x7028d` / 18 / C | ISurface `0x70660@100`; IInput `0x70280@156` |
| cstrike-4554.client.windows | `0x74cfc` / 2 | `0x74e07` / 50 / K | `0x74e1a` / 18 / K | — |
| cstrike-6153.client.linux | `0x1670d9` / 3 | `0x1671ab` / 51 / K | `0x1671c3` / 19 / K | — |
| cstrike-6153.client.windows | `0x72bac` / 2 | `0x72cb7` / 50 / K | `0x72cca` / 18 / K | — |
| cstrike-8684.client.linux | `0x167439` / 3 | `0x16750b` / 51 / K | `0x167523` / 19 / K | — |
| cstrike-8684.client.windows | `0x73f2c` / 2 | `0x74037` / 50 / K | `0x7404a` / 18 / K | — |
| czero-10210.client.linux | `0x117583` / 3 | `0x11766b` / 51 / K | `0x117683` / 19 / K | — |
| czero-10210.client.windows | `0x7c1e3` / 2 | `0x7c32c` / 50 / K | `0x7c33b` / 18 / K | — |
| czero-8684.client.linux | `0x167439` / 3 | `0x16750b` / 51 / K | `0x167523` / 19 / K | — |
| czero-8684.client.windows | `0x73f2c` / 2 | `0x74037` / 50 / K | `0x7404a` / 18 / K | — |
| czeror-10210.client.linux | `0xf7c03` / 3 | `0xf7ceb` / 51 / K | `0xf7d03` / 19 / K | — |
| czeror-10210.client.windows | `0x6ca43` / 2 | `0x6cb8c` / 50 / K | `0x6cb9b` / 18 / K | — |
| czeror-8684.client.linux | `0x1484e9` / 3 | `0x1485bb` / 51 / K | `0x1485d3` / 19 / K | — |
| czeror-8684.client.windows | `0x6229c` / 2 | `0x623a7` / 50 / K | `0x623ba` / 18 / K | — |
| hl-10210.engine.linux | `0x237dd3` / 3 | `0x237ebb` / 51 / K | `0x237ed3` / 19 / K | — |
| hl-10210.engine.windows | `0x29dec3` / 2 | `0x29e00c` / 50 / K | `0x29e01b` / 18 / K | — |
| hl-10210.gameui.linux | `0xd5c03` / 3 | `0xd5ceb` / 51 / K | `0xd5d03` / 19 / K | — |
| hl-10210.gameui.windows | `0x54b63` / 2 | `0x54cac` / 50 / K | `0x54cbb` / 18 / K | — |
| hl-10210.serverbrowser.linux | `0x5ce73` / 3 | `0x5cf5b` / 51 / K | `0x5cf73` / 19 / K | — |
| hl-10210.serverbrowser.windows | `0x335d3` / 2 | `0x3371c` / 50 / K | `0x3372b` / 18 / K | — |
| hl-3248.engine.windows | `0xfb6fc` / 2 | `0xfb467` / 50 / P | `0xfb08d` / 18 / C | ISurface `0xfb450@100`; IInput `0xfb080@157` |
| hl-3248.gameui.windows | `0x4d53c` / 2 | `0x4d287` / 50 / P | `0x4ce9d` / 18 / C | ISurface `0x4d270@100`; IInput `0x4ce90@157` |
| hl-3248.serverbrowser.windows | `0x3410c` / 2 | `0x33e57` / 50 / P | `0x33a6d` / 18 / C | ISurface `0x33e40@100`; IInput `0x33a60@157` |
| hl-3266.engine.windows | `0xfb6fc` / 2 | `0xfb467` / 50 / P | `0xfb08d` / 18 / C | ISurface `0xfb450@100`; IInput `0xfb080@157` |
| hl-3266.gameui.windows | `0x5b2bf` / 2 | `0x5ad17` / 50 / P | `0x5a3bf` / 18 / C | ISurface `0x5ace0@100`; IInput `0x5a390@157` |
| hl-3266.serverbrowser.windows | `0x3410c` / 2 | `0x33e57` / 50 / P | `0x33a6d` / 18 / C | ISurface `0x33e40@100`; IInput `0x33a60@157` |
| hl-3329.engine.windows | `0xfb1dc` / 2 | `0xfaf47` / 50 / P | `0xfab6d` / 18 / C | ISurface `0xfaf30@100`; IInput `0xfab60@157` |
| hl-3329.gameui.windows | `0x5b2bf` / 2 | `0x5ad17` / 50 / P | `0x5a3bf` / 18 / C | ISurface `0x5ace0@100`; IInput `0x5a390@157` |
| hl-3329.serverbrowser.windows | `0x3410c` / 2 | `0x33e57` / 50 / P | `0x33a6d` / 18 / C | ISurface `0x33e40@100`; IInput `0x33a60@157` |
| hl-3647.engine.windows | `0xfa46c` / 2 | `0xfa1d7` / 50 / P | `0xf9dfd` / 18 / C | ISurface `0xfa1c0@100`; IInput `0xf9df0@157` |
| hl-3647.gameui.windows | `0x4cb0c` / 2 | `0x4c857` / 50 / P | `0x4c46d` / 18 / C | ISurface `0x4c840@100`; IInput `0x4c460@157` |
| hl-3647.serverbrowser.windows | `0x404ce` / 2 | `0x401ca` / 50 / P | `0x3fdcd` / 18 / C | ISurface `0x401a0@100`; IInput `0x3fdc0@157` |
| hl-4554.engine.windows | `0x11db7c` / 2 | `0x11dc87` / 50 / K | `0x11dc9a` / 18 / K | — |
| hl-4554.gameui.windows | `0x4e19c` / 2 | `0x4e2a7` / 50 / K | `0x4e2ba` / 18 / K | — |
| hl-4554.serverbrowser.windows | `0x2f26f` / 2 | `0x2f396` / 50 / K | `0x2f3b5` / 18 / K | — |
| hl-6153.engine.windows | `0x10143c` / 2 | `0x101547` / 50 / K | `0x10155a` / 18 / K | — |
| hl-6153.gameui.windows | `0x4d6ac` / 2 | `0x4d7b7` / 50 / K | `0x4d7ca` / 18 / K | — |
| hl-6153.serverbrowser.windows | `0x2f26f` / 2 | `0x2f396` / 50 / K | `0x2f3b5` / 18 / K | — |
| hl-8684.engine.linux | `0x25feb9` / 3 | `0x25ff8b` / 51 / K | `0x25ffa3` / 19 / K | — |
| hl-8684.engine.windows | `0x1037ac` / 2 | `0x1038b7` / 50 / K | `0x1038ca` / 18 / K | — |
| hl-8684.gameui.linux | `0x110229` / 3 | `0x1102fb` / 51 / K | `0x110313` / 19 / K | — |
| hl-8684.gameui.windows | `0x4d7fc` / 2 | `0x4d907` / 50 / K | `0x4d91a` / 18 / K | — |
| hl-8684.serverbrowser.linux | `0x86759` / 3 | `0x8682b` / 51 / K | `0x86843` / 19 / K | — |
| hl-8684.serverbrowser.windows | `0x2edd0` / 2 | `0x2ef1e` / 50 / K | `0x2ef3c` / 18 / K | — |
| svencoop-10257.engine.linux | `0x1f2466` / 3 | `0x1f2317` / 51 / K | `0x1f254a` / 19 / K | — |
| svencoop-10257.engine.windows | `0x126c85` / 2 | `0x126d36` / 50 / K | `0x126d49` / 18 / K | — |
| svencoop-10257.gameui.linux | `0x83606` / 3 | `0x834b7` / 51 / K | `0x836ea` / 19 / K | — |
| svencoop-10257.gameui.windows | `0x2e055` / 2 | `0x2e106` / 50 / K | `0x2e119` / 18 / K | — |
| svencoop-10257.serverbrowser.linux | `0x5df26` / 3 | `0x5ddd7` / 51 / K | `0x5e00a` / 19 / K | — |
| svencoop-10257.serverbrowser.windows | `0x2af65` / 2 | `0x2b016` / 50 / K | `0x2b029` / 18 / K | — |
| svencoop-8948.engine.linux | `0x23e376` / 3 | `0x23e227` / 51 / K | `0x23e45a` / 19 / K | — |
| svencoop-8948.engine.windows | `0x123213` / 2 | `0x1232c4` / 50 / K | `0x1232d7` / 18 / K | — |
| svencoop-8948.gameui.linux | `0x9b3b6` / 3 | `0x9b267` / 51 / K | `0x9b49a` / 19 / K | — |
| svencoop-8948.gameui.windows | `0x2dcb3` / 2 | `0x2dd64` / 50 / K | `0x2dd77` / 18 / K | — |
| svencoop-8948.serverbrowser.linux | `0x6a7e6` / 3 | `0x6a697` / 51 / K | `0x6a8ca` / 19 / K | — |
| svencoop-8948.serverbrowser.windows | `0x2a953` / 2 | `0x2aa04` / 50 / K | `0x2aa17` / 18 / K | — |

### E3. 三阶段方法 RVA 与成员引用

以下每段列出 18 个 S1 方法及 S2 的 VPANEL PostMessage / InvalidateLayout。`RVA@index` 表示该函数等于当前表条目；`RVA` 单独出现表示非虚函数。GetParent 的关系是 GetVParent 所用 IPanel 查询加 GetPanel 转换，不是 SetParent 中的直接调用。

<details>
<summary>展开 62 份输入的方法与注册引用</summary>


#### cof-5936.engine.windows

```text
Panel::SetPos = 0x128aeb (nonvirtual)
Panel::SetBuildGroup = 0x12b185@67
Panel::SetName = 0x128a18 (nonvirtual)
Panel::SetAutoDelete = 0x12998b@39
Panel::SetBuildModeEditable = 0x12a9dd (nonvirtual)
Panel::SetBuildModeDeletable = 0x12aa34 (nonvirtual)
Panel::SetParent(Panel*) = 0x1294da@37
Panel::AddActionSignalTarget(Panel*) = 0x12ad19@41
Panel::ApplySettings = 0x12b598@80
Panel::SetParent(VPANEL) = 0x129518@36
Panel::SetProportional = 0x12d69d@113
Panel::SetKeyBoardInputEnabled = 0x12d725@115
Panel::IsKeyBoardInputEnabled = 0x12d7e2@117
Panel::SetMouseInputEnabled = 0x12d798@114
Panel::IsMouseInputEnabled = 0x12d810@116
Panel::IsProportional = 0x21d0@21
Panel::GetVParent = 0x128c19@35
Panel::GetParent = 0x128c44@34
Panel::PostMessage(VPANEL) = 0x12d2df@32 (reference 0x15daca)
Panel::InvalidateLayout = 0x12b274@58 (reference 0x15d9b3)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1314e6
FocusNavGroup::SetCurrentFocus handle setter reference = 0x13a369; current table index = 8
SetFocus callback thunk = 0x12e9e0; decoded slot = 89
```

#### cof-5936.gameui.windows

```text
Panel::SetPos = 0x5e0ab (nonvirtual)
Panel::SetBuildGroup = 0x60745@67
Panel::SetName = 0x5dfd8 (nonvirtual)
Panel::SetAutoDelete = 0x5ef4b@39
Panel::SetBuildModeEditable = 0x5ff9d (nonvirtual)
Panel::SetBuildModeDeletable = 0x5fff4 (nonvirtual)
Panel::SetParent(Panel*) = 0x5ea9a@37
Panel::AddActionSignalTarget(Panel*) = 0x602d9@41
Panel::ApplySettings = 0x60b58@80
Panel::SetParent(VPANEL) = 0x5ead8@36
Panel::SetProportional = 0x62c5d@113
Panel::SetKeyBoardInputEnabled = 0x62ce5@115
Panel::IsKeyBoardInputEnabled = 0x62da2@117
Panel::SetMouseInputEnabled = 0x62d58@114
Panel::IsMouseInputEnabled = 0x62dd0@116
Panel::IsProportional = 0x3180@21
Panel::GetVParent = 0x5e1d9@35
Panel::GetParent = 0x5e204@34
Panel::PostMessage(VPANEL) = 0x6289f@32 (reference 0x6a05a)
Panel::InvalidateLayout = 0x60834@58 (reference 0x69f43)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x6cfd6
FocusNavGroup::SetCurrentFocus handle setter reference = 0xa3e39; current table index = 8
SetFocus callback thunk = 0x63fa0; decoded slot = 89
```

#### cof-5936.serverbrowser.windows

```text
Panel::SetPos = 0x19a90 (nonvirtual)
Panel::SetBuildGroup = 0x1b4b0@67
Panel::SetName = 0x199f0 (nonvirtual)
Panel::SetAutoDelete = 0x1a260@39
Panel::SetBuildModeEditable = 0x1af70 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1afa0 (nonvirtual)
Panel::SetParent(Panel*) = 0x19eb0@37
Panel::AddActionSignalTarget(Panel*) = 0x1d3b0@41
Panel::ApplySettings = 0x1c840@80
Panel::SetParent(VPANEL) = 0x19ef0@36
Panel::SetProportional = 0x1be50@113
Panel::SetKeyBoardInputEnabled = 0x1bec0@115
Panel::IsKeyBoardInputEnabled = 0x1bf60@117
Panel::SetMouseInputEnabled = 0x1bf20@114
Panel::IsMouseInputEnabled = 0x1bf90@116
Panel::IsProportional = 0x9cb0@21
Panel::GetVParent = 0x19bb0@35
Panel::GetParent = 0x19be0@34
Panel::PostMessage(VPANEL) = 0x1bb60@32 (reference 0x2e97d)
Panel::InvalidateLayout = 0x1b560@58 (reference 0x2e870)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x2286d
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3faff; current table index = 8
SetFocus callback thunk = 0x1c030; decoded slot = 89
```

#### cstrike-10210.client.linux

```text
Panel::SetPos = 0x12c6d0 (nonvirtual)
Panel::SetBuildGroup = 0x12a070@68
Panel::SetName = 0x12c660 (nonvirtual)
Panel::SetAutoDelete = 0x129f50@39
Panel::SetBuildModeEditable = 0x12d430 (nonvirtual)
Panel::SetBuildModeDeletable = 0x12d460 (nonvirtual)
Panel::SetParent(Panel*) = 0x12a3a0@36
Panel::AddActionSignalTarget(Panel*) = 0x12aeb0@40
Panel::ApplySettings = 0x12fb70@81
Panel::SetParent(VPANEL) = 0x12a420@37
Panel::SetProportional = 0x12db10@114
Panel::SetKeyBoardInputEnabled = 0x12dbd0@116
Panel::IsKeyBoardInputEnabled = 0x12adf0@118
Panel::SetMouseInputEnabled = 0x12ad70@115
Panel::IsMouseInputEnabled = 0x12ae50@117
Panel::IsProportional = 0x12a110@21
Panel::GetVParent = 0x12a920@35
Panel::GetParent = 0x12a980@34
Panel::PostMessage(VPANEL) = 0x12ad00@32 (reference 0x11764c)
Panel::InvalidateLayout = 0x12dc90@59 (reference 0x11759a)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x113b55
FocusNavGroup::SetCurrentFocus handle setter reference = 0x114ad9; current table index = 8
SetFocus AddToMap call = 0x13197d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x1320f5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x13286d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x133025; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### cstrike-10210.client.windows

```text
Panel::SetPos = 0x77b90 (nonvirtual)
Panel::SetBuildGroup = 0x77630@67
Panel::SetName = 0x77910 (nonvirtual)
Panel::SetAutoDelete = 0x77540@39
Panel::SetBuildModeEditable = 0x776a0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x77670 (nonvirtual)
Panel::SetParent(Panel*) = 0x77b50@37
Panel::AddActionSignalTarget(Panel*) = 0x72760@41
Panel::ApplySettings = 0x728e0@80
Panel::SetParent(VPANEL) = 0x77a00@36
Panel::SetProportional = 0x77bd0@113
Panel::SetKeyBoardInputEnabled = 0x77780@115
Panel::IsKeyBoardInputEnabled = 0x74f10@117
Panel::SetMouseInputEnabled = 0x778d0@114
Panel::IsMouseInputEnabled = 0x74f50@116
Panel::IsProportional = 0x74fd0@21
Panel::GetVParent = 0x73ad0@35
Panel::GetParent = 0x73510@34
Panel::PostMessage(VPANEL) = 0x76e60@32 (reference 0x7c2f7)
Panel::InvalidateLayout = 0x74cb0@58 (reference 0x7c1ee)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x7985a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x9990f; current table index = 8
SetFocus callback thunk = 0x72545; decoded slot = 89
```

#### cstrike-3248.client.windows

```text
Panel::SetPos = 0x73cc0 (nonvirtual)
Panel::SetBuildGroup = 0x76960@67
Panel::SetName = 0x73900 (nonvirtual)
Panel::SetAutoDelete = 0x75390@39
Panel::SetBuildModeEditable = 0x76170 (nonvirtual)
Panel::SetBuildModeDeletable = 0x761a0 (nonvirtual)
Panel::SetParent(Panel*) = 0x74f70@37
Panel::AddActionSignalTarget(Panel*) = 0x763f0@41
Panel::ApplySettings = 0x76c40@80
Panel::SetParent(VPANEL) = 0x74fa0@36
Panel::SetProportional = 0x781c0@113
Panel::SetKeyBoardInputEnabled = 0x78220@115
Panel::IsKeyBoardInputEnabled = 0x782c0@117
Panel::SetMouseInputEnabled = 0x78280@114
Panel::IsMouseInputEnabled = 0x782f0@116
Panel::IsProportional = 0x1e940@21
Panel::GetVParent = 0x74120@35
Panel::GetParent = 0x74140@34
Panel::PostMessage(VPANEL) = 0x77f00@32 (reference 0x709f3)
Panel::InvalidateLayout = 0x76a00@58 (reference 0x70937)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x71b7c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x8cdcd; current table index = 8
SetFocus callback thunk = 0x753f0; decoded slot = 89
```

#### cstrike-3647.client.windows

```text
Panel::SetPos = 0x73cc0 (nonvirtual)
Panel::SetBuildGroup = 0x76960@67
Panel::SetName = 0x73900 (nonvirtual)
Panel::SetAutoDelete = 0x75390@39
Panel::SetBuildModeEditable = 0x76170 (nonvirtual)
Panel::SetBuildModeDeletable = 0x761a0 (nonvirtual)
Panel::SetParent(Panel*) = 0x74f70@37
Panel::AddActionSignalTarget(Panel*) = 0x763f0@41
Panel::ApplySettings = 0x76c40@80
Panel::SetParent(VPANEL) = 0x74fa0@36
Panel::SetProportional = 0x781c0@113
Panel::SetKeyBoardInputEnabled = 0x78220@115
Panel::IsKeyBoardInputEnabled = 0x782c0@117
Panel::SetMouseInputEnabled = 0x78280@114
Panel::IsMouseInputEnabled = 0x782f0@116
Panel::IsProportional = 0x1e940@21
Panel::GetVParent = 0x74120@35
Panel::GetParent = 0x74140@34
Panel::PostMessage(VPANEL) = 0x77f00@32 (reference 0x709f3)
Panel::InvalidateLayout = 0x76a00@58 (reference 0x70937)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x71b7c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x8cdcd; current table index = 8
SetFocus callback thunk = 0x753f0; decoded slot = 89
```

#### cstrike-4554.client.windows

```text
Panel::SetPos = 0x78080 (nonvirtual)
Panel::SetBuildGroup = 0x7b390@67
Panel::SetName = 0x77d20 (nonvirtual)
Panel::SetAutoDelete = 0x79d70@39
Panel::SetBuildModeEditable = 0x7aba0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x7abd0 (nonvirtual)
Panel::SetParent(Panel*) = 0x799b0@37
Panel::AddActionSignalTarget(Panel*) = 0x7ae20@41
Panel::ApplySettings = 0x7b670@80
Panel::SetParent(VPANEL) = 0x799e0@36
Panel::SetProportional = 0x7ccf0@113
Panel::SetKeyBoardInputEnabled = 0x7cd50@115
Panel::IsKeyBoardInputEnabled = 0x7cdf0@117
Panel::SetMouseInputEnabled = 0x7cdb0@114
Panel::IsMouseInputEnabled = 0x7ce20@116
Panel::IsProportional = 0x1f630@21
Panel::GetVParent = 0x78590@35
Panel::GetParent = 0x785b0@34
Panel::PostMessage(VPANEL) = 0x7ca30@32 (reference 0x74dcf)
Panel::InvalidateLayout = 0x7b430@58 (reference 0x74d07)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x7617c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x967dd; current table index = 8
SetFocus callback thunk = 0x79f80; decoded slot = 89
```

#### cstrike-6153.client.linux

```text
Panel::SetPos = 0x179ea0 (nonvirtual)
Panel::SetBuildGroup = 0x175820@68
Panel::SetName = 0x179e30 (nonvirtual)
Panel::SetAutoDelete = 0x175650@39
Panel::SetBuildModeEditable = 0x17aa50 (nonvirtual)
Panel::SetBuildModeDeletable = 0x17aa80 (nonvirtual)
Panel::SetParent(Panel*) = 0x176650@36
Panel::AddActionSignalTarget(Panel*) = 0x176420@40
Panel::ApplySettings = 0x177880@81
Panel::SetParent(VPANEL) = 0x175be0@37
Panel::SetProportional = 0x178570@114
Panel::SetKeyBoardInputEnabled = 0x178650@116
Panel::IsKeyBoardInputEnabled = 0x175ad0@118
Panel::SetMouseInputEnabled = 0x175ec0@115
Panel::IsMouseInputEnabled = 0x175a80@117
Panel::IsProportional = 0xd38b0@21
Panel::GetVParent = 0x175e80@35
Panel::GetParent = 0x176260@34
Panel::PostMessage(VPANEL) = 0x175f80@32 (reference 0x16718c)
Panel::InvalidateLayout = 0x178910@59 (reference 0x1670f0)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x163a05
FocusNavGroup::SetCurrentFocus handle setter reference = 0x166609; current table index = 8
SetFocus PMF store = 0x17c66f; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17da0d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17edbd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x1800f5; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### cstrike-6153.client.windows

```text
Panel::SetPos = 0x75ab0 (nonvirtual)
Panel::SetBuildGroup = 0x78d70@67
Panel::SetName = 0x75a20 (nonvirtual)
Panel::SetAutoDelete = 0x76640@39
Panel::SetBuildModeEditable = 0x78580 (nonvirtual)
Panel::SetBuildModeDeletable = 0x785b0 (nonvirtual)
Panel::SetParent(Panel*) = 0x76270@37
Panel::AddActionSignalTarget(Panel*) = 0x78800@41
Panel::ApplySettings = 0x79050@80
Panel::SetParent(VPANEL) = 0x762a0@36
Panel::SetProportional = 0x7a800@113
Panel::SetKeyBoardInputEnabled = 0x7a860@115
Panel::IsKeyBoardInputEnabled = 0x7a900@117
Panel::SetMouseInputEnabled = 0x7a8c0@114
Panel::IsMouseInputEnabled = 0x7a930@116
Panel::IsProportional = 0x1d810@21
Panel::GetVParent = 0x75bd0@35
Panel::GetParent = 0x75bf0@34
Panel::PostMessage(VPANEL) = 0x7a540@32 (reference 0x72c7f)
Panel::InvalidateLayout = 0x78e10@58 (reference 0x72bb7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x7403c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x93c8d; current table index = 8
SetFocus callback thunk = 0x79e10; decoded slot = 89
```

#### cstrike-8684.client.linux

```text
Panel::SetPos = 0x17a200 (nonvirtual)
Panel::SetBuildGroup = 0x175b80@68
Panel::SetName = 0x17a190 (nonvirtual)
Panel::SetAutoDelete = 0x1759b0@39
Panel::SetBuildModeEditable = 0x17adb0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x17ade0 (nonvirtual)
Panel::SetParent(Panel*) = 0x1769b0@36
Panel::AddActionSignalTarget(Panel*) = 0x176780@40
Panel::ApplySettings = 0x177be0@81
Panel::SetParent(VPANEL) = 0x175f40@37
Panel::SetProportional = 0x1788d0@114
Panel::SetKeyBoardInputEnabled = 0x1789b0@116
Panel::IsKeyBoardInputEnabled = 0x175e30@118
Panel::SetMouseInputEnabled = 0x176220@115
Panel::IsMouseInputEnabled = 0x175de0@117
Panel::IsProportional = 0xd2ad0@21
Panel::GetVParent = 0x1761e0@35
Panel::GetParent = 0x1765c0@34
Panel::PostMessage(VPANEL) = 0x1762e0@32 (reference 0x1674ec)
Panel::InvalidateLayout = 0x178c70@59 (reference 0x167450)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x163d65
FocusNavGroup::SetCurrentFocus handle setter reference = 0x166969; current table index = 8
SetFocus PMF store = 0x17c9cf; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17dd6d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17f11d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x180455; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### cstrike-8684.client.windows

```text
Panel::SetPos = 0x76e30 (nonvirtual)
Panel::SetBuildGroup = 0x7a0f0@67
Panel::SetName = 0x76da0 (nonvirtual)
Panel::SetAutoDelete = 0x779c0@39
Panel::SetBuildModeEditable = 0x79900 (nonvirtual)
Panel::SetBuildModeDeletable = 0x79930 (nonvirtual)
Panel::SetParent(Panel*) = 0x775f0@37
Panel::AddActionSignalTarget(Panel*) = 0x79b80@41
Panel::ApplySettings = 0x7a3d0@80
Panel::SetParent(VPANEL) = 0x77620@36
Panel::SetProportional = 0x7bb80@113
Panel::SetKeyBoardInputEnabled = 0x7bbe0@115
Panel::IsKeyBoardInputEnabled = 0x7bc80@117
Panel::SetMouseInputEnabled = 0x7bc40@114
Panel::IsMouseInputEnabled = 0x7bcb0@116
Panel::IsProportional = 0x1d8a0@21
Panel::GetVParent = 0x76f50@35
Panel::GetParent = 0x76f70@34
Panel::PostMessage(VPANEL) = 0x7b8c0@32 (reference 0x73fff)
Panel::InvalidateLayout = 0x7a190@58 (reference 0x73f37)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x753bc
FocusNavGroup::SetCurrentFocus handle setter reference = 0x9508d; current table index = 8
SetFocus callback thunk = 0x7b190; decoded slot = 89
```

#### czero-10210.client.linux

```text
Panel::SetPos = 0x12c6d0 (nonvirtual)
Panel::SetBuildGroup = 0x12a070@68
Panel::SetName = 0x12c660 (nonvirtual)
Panel::SetAutoDelete = 0x129f50@39
Panel::SetBuildModeEditable = 0x12d430 (nonvirtual)
Panel::SetBuildModeDeletable = 0x12d460 (nonvirtual)
Panel::SetParent(Panel*) = 0x12a3a0@36
Panel::AddActionSignalTarget(Panel*) = 0x12aeb0@40
Panel::ApplySettings = 0x12fb70@81
Panel::SetParent(VPANEL) = 0x12a420@37
Panel::SetProportional = 0x12db10@114
Panel::SetKeyBoardInputEnabled = 0x12dbd0@116
Panel::IsKeyBoardInputEnabled = 0x12adf0@118
Panel::SetMouseInputEnabled = 0x12ad70@115
Panel::IsMouseInputEnabled = 0x12ae50@117
Panel::IsProportional = 0x12a110@21
Panel::GetVParent = 0x12a920@35
Panel::GetParent = 0x12a980@34
Panel::PostMessage(VPANEL) = 0x12ad00@32 (reference 0x11764c)
Panel::InvalidateLayout = 0x12dc90@59 (reference 0x11759a)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x113b55
FocusNavGroup::SetCurrentFocus handle setter reference = 0x114ad9; current table index = 8
SetFocus AddToMap call = 0x13197d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x1320f5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x13286d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x133025; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### czero-10210.client.windows

```text
Panel::SetPos = 0x77b90 (nonvirtual)
Panel::SetBuildGroup = 0x77630@67
Panel::SetName = 0x77910 (nonvirtual)
Panel::SetAutoDelete = 0x77540@39
Panel::SetBuildModeEditable = 0x776a0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x77670 (nonvirtual)
Panel::SetParent(Panel*) = 0x77b50@37
Panel::AddActionSignalTarget(Panel*) = 0x72760@41
Panel::ApplySettings = 0x728e0@80
Panel::SetParent(VPANEL) = 0x77a00@36
Panel::SetProportional = 0x77bd0@113
Panel::SetKeyBoardInputEnabled = 0x77780@115
Panel::IsKeyBoardInputEnabled = 0x74f10@117
Panel::SetMouseInputEnabled = 0x778d0@114
Panel::IsMouseInputEnabled = 0x74f50@116
Panel::IsProportional = 0x74fd0@21
Panel::GetVParent = 0x73ad0@35
Panel::GetParent = 0x73510@34
Panel::PostMessage(VPANEL) = 0x76e60@32 (reference 0x7c2f7)
Panel::InvalidateLayout = 0x74cb0@58 (reference 0x7c1ee)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x7985a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x9990f; current table index = 8
SetFocus callback thunk = 0x72545; decoded slot = 89
```

#### czero-8684.client.linux

```text
Panel::SetPos = 0x17a200 (nonvirtual)
Panel::SetBuildGroup = 0x175b80@68
Panel::SetName = 0x17a190 (nonvirtual)
Panel::SetAutoDelete = 0x1759b0@39
Panel::SetBuildModeEditable = 0x17adb0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x17ade0 (nonvirtual)
Panel::SetParent(Panel*) = 0x1769b0@36
Panel::AddActionSignalTarget(Panel*) = 0x176780@40
Panel::ApplySettings = 0x177be0@81
Panel::SetParent(VPANEL) = 0x175f40@37
Panel::SetProportional = 0x1788d0@114
Panel::SetKeyBoardInputEnabled = 0x1789b0@116
Panel::IsKeyBoardInputEnabled = 0x175e30@118
Panel::SetMouseInputEnabled = 0x176220@115
Panel::IsMouseInputEnabled = 0x175de0@117
Panel::IsProportional = 0xd2ad0@21
Panel::GetVParent = 0x1761e0@35
Panel::GetParent = 0x1765c0@34
Panel::PostMessage(VPANEL) = 0x1762e0@32 (reference 0x1674ec)
Panel::InvalidateLayout = 0x178c70@59 (reference 0x167450)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x163d65
FocusNavGroup::SetCurrentFocus handle setter reference = 0x166969; current table index = 8
SetFocus PMF store = 0x17c9cf; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17dd6d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x17f11d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x180455; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### czero-8684.client.windows

```text
Panel::SetPos = 0x76e30 (nonvirtual)
Panel::SetBuildGroup = 0x7a0f0@67
Panel::SetName = 0x76da0 (nonvirtual)
Panel::SetAutoDelete = 0x779c0@39
Panel::SetBuildModeEditable = 0x79900 (nonvirtual)
Panel::SetBuildModeDeletable = 0x79930 (nonvirtual)
Panel::SetParent(Panel*) = 0x775f0@37
Panel::AddActionSignalTarget(Panel*) = 0x79b80@41
Panel::ApplySettings = 0x7a3d0@80
Panel::SetParent(VPANEL) = 0x77620@36
Panel::SetProportional = 0x7bb80@113
Panel::SetKeyBoardInputEnabled = 0x7bbe0@115
Panel::IsKeyBoardInputEnabled = 0x7bc80@117
Panel::SetMouseInputEnabled = 0x7bc40@114
Panel::IsMouseInputEnabled = 0x7bcb0@116
Panel::IsProportional = 0x1d8a0@21
Panel::GetVParent = 0x76f50@35
Panel::GetParent = 0x76f70@34
Panel::PostMessage(VPANEL) = 0x7b8c0@32 (reference 0x73fff)
Panel::InvalidateLayout = 0x7a190@58 (reference 0x73f37)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x753bc
FocusNavGroup::SetCurrentFocus handle setter reference = 0x9508d; current table index = 8
SetFocus callback thunk = 0x7b190; decoded slot = 89
```

#### czeror-10210.client.linux

```text
Panel::SetPos = 0x112cc0 (nonvirtual)
Panel::SetBuildGroup = 0x110660@68
Panel::SetName = 0x112c50 (nonvirtual)
Panel::SetAutoDelete = 0x110540@39
Panel::SetBuildModeEditable = 0x113a20 (nonvirtual)
Panel::SetBuildModeDeletable = 0x113a50 (nonvirtual)
Panel::SetParent(Panel*) = 0x110990@36
Panel::AddActionSignalTarget(Panel*) = 0x1114a0@40
Panel::ApplySettings = 0x116160@81
Panel::SetParent(VPANEL) = 0x110a10@37
Panel::SetProportional = 0x114100@114
Panel::SetKeyBoardInputEnabled = 0x1141c0@116
Panel::IsKeyBoardInputEnabled = 0x1113e0@118
Panel::SetMouseInputEnabled = 0x111360@115
Panel::IsMouseInputEnabled = 0x111440@117
Panel::IsProportional = 0x110700@21
Panel::GetVParent = 0x110f10@35
Panel::GetParent = 0x110f70@34
Panel::PostMessage(VPANEL) = 0x1112f0@32 (reference 0xf7ccc)
Panel::InvalidateLayout = 0x114280@59 (reference 0xf7c1a)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xf41d5
FocusNavGroup::SetCurrentFocus handle setter reference = 0xf5159; current table index = 8
SetFocus AddToMap call = 0x117f6d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x1186e5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x118e5d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x119615; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### czeror-10210.client.windows

```text
Panel::SetPos = 0x683b0 (nonvirtual)
Panel::SetBuildGroup = 0x67e10@67
Panel::SetName = 0x68130 (nonvirtual)
Panel::SetAutoDelete = 0x67d20@39
Panel::SetBuildModeEditable = 0x67e80 (nonvirtual)
Panel::SetBuildModeDeletable = 0x67e50 (nonvirtual)
Panel::SetParent(Panel*) = 0x68370@37
Panel::AddActionSignalTarget(Panel*) = 0x62e90@41
Panel::ApplySettings = 0x63010@80
Panel::SetParent(VPANEL) = 0x68220@36
Panel::SetProportional = 0x683f0@113
Panel::SetKeyBoardInputEnabled = 0x67fa0@115
Panel::IsKeyBoardInputEnabled = 0x656f0@117
Panel::SetMouseInputEnabled = 0x680f0@114
Panel::IsMouseInputEnabled = 0x65730@116
Panel::IsProportional = 0x657b0@21
Panel::GetVParent = 0x642a0@35
Panel::GetParent = 0x63ce0@34
Panel::PostMessage(VPANEL) = 0x67640@32 (reference 0x6cb57)
Panel::InvalidateLayout = 0x65480@58 (reference 0x6ca4e)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x6a07a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x9495f; current table index = 8
SetFocus callback thunk = 0x62c75; decoded slot = 89
```

#### czeror-8684.client.linux

```text
Panel::SetPos = 0x15fdb0 (nonvirtual)
Panel::SetBuildGroup = 0x15b730@68
Panel::SetName = 0x15fd40 (nonvirtual)
Panel::SetAutoDelete = 0x15b560@39
Panel::SetBuildModeEditable = 0x160960 (nonvirtual)
Panel::SetBuildModeDeletable = 0x160990 (nonvirtual)
Panel::SetParent(Panel*) = 0x15c560@36
Panel::AddActionSignalTarget(Panel*) = 0x15c330@40
Panel::ApplySettings = 0x15d790@81
Panel::SetParent(VPANEL) = 0x15baf0@37
Panel::SetProportional = 0x15e480@114
Panel::SetKeyBoardInputEnabled = 0x15e560@116
Panel::IsKeyBoardInputEnabled = 0x15b9e0@118
Panel::SetMouseInputEnabled = 0x15bdd0@115
Panel::IsMouseInputEnabled = 0x15b990@117
Panel::IsProportional = 0xdd6f0@21
Panel::GetVParent = 0x15bd90@35
Panel::GetParent = 0x15c170@34
Panel::PostMessage(VPANEL) = 0x15be90@32 (reference 0x14859c)
Panel::InvalidateLayout = 0x15e820@59 (reference 0x148500)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x144e15
FocusNavGroup::SetCurrentFocus handle setter reference = 0x147a19; current table index = 8
SetFocus PMF store = 0x16257f; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x16391d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x164ccd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x166005; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### czeror-8684.client.windows

```text
Panel::SetPos = 0x65180 (nonvirtual)
Panel::SetBuildGroup = 0x68440@67
Panel::SetName = 0x650f0 (nonvirtual)
Panel::SetAutoDelete = 0x65d10@39
Panel::SetBuildModeEditable = 0x67c50 (nonvirtual)
Panel::SetBuildModeDeletable = 0x67c80 (nonvirtual)
Panel::SetParent(Panel*) = 0x65940@37
Panel::AddActionSignalTarget(Panel*) = 0x67ed0@41
Panel::ApplySettings = 0x68720@80
Panel::SetParent(VPANEL) = 0x65970@36
Panel::SetProportional = 0x69ed0@113
Panel::SetKeyBoardInputEnabled = 0x69f30@115
Panel::IsKeyBoardInputEnabled = 0x69fd0@117
Panel::SetMouseInputEnabled = 0x69f90@114
Panel::IsMouseInputEnabled = 0x6a000@116
Panel::IsProportional = 0x30350@21
Panel::GetVParent = 0x652a0@35
Panel::GetParent = 0x652c0@34
Panel::PostMessage(VPANEL) = 0x69c10@32 (reference 0x6236f)
Panel::InvalidateLayout = 0x684e0@58 (reference 0x622a7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x6372c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x8928d; current table index = 8
SetFocus callback thunk = 0x694e0; decoded slot = 89
```

#### hl-10210.engine.linux

```text
Panel::SetPos = 0x1ffa60 (nonvirtual)
Panel::SetBuildGroup = 0x1fd400@68
Panel::SetName = 0x1ff9f0 (nonvirtual)
Panel::SetAutoDelete = 0x1fd2e0@39
Panel::SetBuildModeEditable = 0x2007c0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x2007f0 (nonvirtual)
Panel::SetParent(Panel*) = 0x1fd730@36
Panel::AddActionSignalTarget(Panel*) = 0x1fe240@40
Panel::ApplySettings = 0x202f00@81
Panel::SetParent(VPANEL) = 0x1fd7b0@37
Panel::SetProportional = 0x200ea0@114
Panel::SetKeyBoardInputEnabled = 0x200f60@116
Panel::IsKeyBoardInputEnabled = 0x1fe180@118
Panel::SetMouseInputEnabled = 0x1fe100@115
Panel::IsMouseInputEnabled = 0x1fe1e0@117
Panel::IsProportional = 0x1fd4a0@21
Panel::GetVParent = 0x1fdcb0@35
Panel::GetParent = 0x1fdd10@34
Panel::PostMessage(VPANEL) = 0x1fe090@32 (reference 0x237e9c)
Panel::InvalidateLayout = 0x201020@59 (reference 0x237dea)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1eec95
FocusNavGroup::SetCurrentFocus handle setter reference = 0x1efc19; current table index = 8
SetFocus AddToMap call = 0x204d0d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x205485; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x205bfd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x2063b5; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-10210.engine.windows

```text
Panel::SetPos = 0x277080 (nonvirtual)
Panel::SetBuildGroup = 0x276b50@67
Panel::SetName = 0x276e00 (nonvirtual)
Panel::SetAutoDelete = 0x276a60@39
Panel::SetBuildModeEditable = 0x276bc0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x276b90 (nonvirtual)
Panel::SetParent(Panel*) = 0x277040@37
Panel::AddActionSignalTarget(Panel*) = 0x271b70@41
Panel::ApplySettings = 0x271c40@80
Panel::SetParent(VPANEL) = 0x276ef0@36
Panel::SetProportional = 0x2770c0@113
Panel::SetKeyBoardInputEnabled = 0x276c70@115
Panel::IsKeyBoardInputEnabled = 0x274460@117
Panel::SetMouseInputEnabled = 0x276dc0@114
Panel::IsMouseInputEnabled = 0x2744a0@116
Panel::IsProportional = 0x274520@21
Panel::GetVParent = 0x272e60@35
Panel::GetParent = 0x2728a0@34
Panel::PostMessage(VPANEL) = 0x276380@32 (reference 0x29dfd7)
Panel::InvalidateLayout = 0x274200@58 (reference 0x29dece)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x27891a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x2803ef; current table index = 8
SetFocus callback thunk = 0x271955; decoded slot = 89
```

#### hl-10210.gameui.linux

```text
Panel::SetPos = 0xf7300 (nonvirtual)
Panel::SetBuildGroup = 0xf4ca0@68
Panel::SetName = 0xf7290 (nonvirtual)
Panel::SetAutoDelete = 0xf4b80@39
Panel::SetBuildModeEditable = 0xf8060 (nonvirtual)
Panel::SetBuildModeDeletable = 0xf8090 (nonvirtual)
Panel::SetParent(Panel*) = 0xf4fd0@36
Panel::AddActionSignalTarget(Panel*) = 0xf5ae0@40
Panel::ApplySettings = 0xfa7a0@81
Panel::SetParent(VPANEL) = 0xf5050@37
Panel::SetProportional = 0xf8740@114
Panel::SetKeyBoardInputEnabled = 0xf8800@116
Panel::IsKeyBoardInputEnabled = 0xf5a20@118
Panel::SetMouseInputEnabled = 0xf59a0@115
Panel::IsMouseInputEnabled = 0xf5a80@117
Panel::IsProportional = 0xf4d40@21
Panel::GetVParent = 0xf5550@35
Panel::GetParent = 0xf55b0@34
Panel::PostMessage(VPANEL) = 0xf5930@32 (reference 0xd5ccc)
Panel::InvalidateLayout = 0xf88c0@59 (reference 0xd5c1a)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xd2165
FocusNavGroup::SetCurrentFocus handle setter reference = 0xd3159; current table index = 8
SetFocus AddToMap call = 0xfc5ad; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xfcd25; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xfd49d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xfdc55; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-10210.gameui.windows

```text
Panel::SetPos = 0x4c9b0 (nonvirtual)
Panel::SetBuildGroup = 0x4c410@67
Panel::SetName = 0x4c730 (nonvirtual)
Panel::SetAutoDelete = 0x4c320@39
Panel::SetBuildModeEditable = 0x4c480 (nonvirtual)
Panel::SetBuildModeDeletable = 0x4c450 (nonvirtual)
Panel::SetParent(Panel*) = 0x4c970@37
Panel::AddActionSignalTarget(Panel*) = 0x474b0@41
Panel::ApplySettings = 0x47630@80
Panel::SetParent(VPANEL) = 0x4c820@36
Panel::SetProportional = 0x4c9f0@113
Panel::SetKeyBoardInputEnabled = 0x4c5a0@115
Panel::IsKeyBoardInputEnabled = 0x49cf0@117
Panel::SetMouseInputEnabled = 0x4c6f0@114
Panel::IsMouseInputEnabled = 0x49d30@116
Panel::IsProportional = 0x49db0@21
Panel::GetVParent = 0x488a0@35
Panel::GetParent = 0x48260@34
Panel::PostMessage(VPANEL) = 0x4bc40@32 (reference 0x54c77)
Panel::InvalidateLayout = 0x49a90@58 (reference 0x54b6e)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x521ca
FocusNavGroup::SetCurrentFocus handle setter reference = 0x80c2f; current table index = 8
SetFocus callback thunk = 0x47295; decoded slot = 89
```

#### hl-10210.serverbrowser.linux

```text
Panel::SetPos = 0x7e480 (nonvirtual)
Panel::SetBuildGroup = 0x7be20@68
Panel::SetName = 0x7e410 (nonvirtual)
Panel::SetAutoDelete = 0x7bd00@39
Panel::SetBuildModeEditable = 0x7f1e0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x7f210 (nonvirtual)
Panel::SetParent(Panel*) = 0x7c150@36
Panel::AddActionSignalTarget(Panel*) = 0x7cc60@40
Panel::ApplySettings = 0x81920@81
Panel::SetParent(VPANEL) = 0x7c1d0@37
Panel::SetProportional = 0x7f8c0@114
Panel::SetKeyBoardInputEnabled = 0x7f980@116
Panel::IsKeyBoardInputEnabled = 0x7cba0@118
Panel::SetMouseInputEnabled = 0x7cb20@115
Panel::IsMouseInputEnabled = 0x7cc00@117
Panel::IsProportional = 0x7bec0@21
Panel::GetVParent = 0x7c6d0@35
Panel::GetParent = 0x7c730@34
Panel::PostMessage(VPANEL) = 0x7cab0@32 (reference 0x5cf3c)
Panel::InvalidateLayout = 0x7fa40@59 (reference 0x5ce8a)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x593d5
FocusNavGroup::SetCurrentFocus handle setter reference = 0x5a3c9; current table index = 8
SetFocus AddToMap call = 0x8372d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x83ea5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x8461d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x84dd5; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-10210.serverbrowser.windows

```text
Panel::SetPos = 0x19600 (nonvirtual)
Panel::SetBuildGroup = 0x19090@67
Panel::SetName = 0x19380 (nonvirtual)
Panel::SetAutoDelete = 0x18fa0@39
Panel::SetBuildModeEditable = 0x19100 (nonvirtual)
Panel::SetBuildModeDeletable = 0x190d0 (nonvirtual)
Panel::SetParent(Panel*) = 0x195c0@37
Panel::AddActionSignalTarget(Panel*) = 0x13e70@41
Panel::ApplySettings = 0x13ff0@80
Panel::SetParent(VPANEL) = 0x19470@36
Panel::SetProportional = 0x19640@113
Panel::SetKeyBoardInputEnabled = 0x191f0@115
Panel::IsKeyBoardInputEnabled = 0x16960@117
Panel::SetMouseInputEnabled = 0x19340@114
Panel::IsMouseInputEnabled = 0x169a0@116
Panel::IsProportional = 0x16a20@21
Panel::GetVParent = 0x15370@35
Panel::GetParent = 0x14d30@34
Panel::PostMessage(VPANEL) = 0x188c0@32 (reference 0x336e7)
Panel::InvalidateLayout = 0x16700@58 (reference 0x335de)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1d70a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x428cf; current table index = 8
SetFocus callback thunk = 0x13c55; decoded slot = 89
```

#### hl-3248.engine.windows

```text
Panel::SetPos = 0xd7420 (nonvirtual)
Panel::SetBuildGroup = 0xd9fa0@67
Panel::SetName = 0xd7060 (nonvirtual)
Panel::SetAutoDelete = 0xd8ac0@39
Panel::SetBuildModeEditable = 0xd9830 (nonvirtual)
Panel::SetBuildModeDeletable = 0xd9860 (nonvirtual)
Panel::SetParent(Panel*) = 0xd86b0@37
Panel::AddActionSignalTarget(Panel*) = 0xd9a90@41
Panel::ApplySettings = 0xda240@80
Panel::SetParent(VPANEL) = 0xd86e0@36
Panel::SetProportional = 0xdb770@113
Panel::SetKeyBoardInputEnabled = 0xdb7d0@115
Panel::IsKeyBoardInputEnabled = 0xdb870@117
Panel::SetMouseInputEnabled = 0xdb830@114
Panel::IsMouseInputEnabled = 0xdb8a0@116
Panel::IsProportional = 0x1d20@21
Panel::GetVParent = 0xd7880@35
Panel::GetParent = 0xd78a0@34
Panel::PostMessage(VPANEL) = 0xdb4c0@32 (reference 0xfb7c3)
Panel::InvalidateLayout = 0xda030@58 (reference 0xfb707)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xdce2c
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe2bad; current table index = 8
SetFocus callback thunk = 0xd8b20; decoded slot = 89
```

#### hl-3248.gameui.windows

```text
Panel::SetPos = 0x43db0 (nonvirtual)
Panel::SetBuildGroup = 0x46a50@67
Panel::SetName = 0x439f0 (nonvirtual)
Panel::SetAutoDelete = 0x45480@39
Panel::SetBuildModeEditable = 0x46260 (nonvirtual)
Panel::SetBuildModeDeletable = 0x46290 (nonvirtual)
Panel::SetParent(Panel*) = 0x45060@37
Panel::AddActionSignalTarget(Panel*) = 0x464e0@41
Panel::ApplySettings = 0x46d30@80
Panel::SetParent(VPANEL) = 0x45090@36
Panel::SetProportional = 0x482c0@113
Panel::SetKeyBoardInputEnabled = 0x48320@115
Panel::IsKeyBoardInputEnabled = 0x483c0@117
Panel::SetMouseInputEnabled = 0x48380@114
Panel::IsMouseInputEnabled = 0x483f0@116
Panel::IsProportional = 0x2760@21
Panel::GetVParent = 0x44210@35
Panel::GetParent = 0x44230@34
Panel::PostMessage(VPANEL) = 0x48000@32 (reference 0x4d603)
Panel::InvalidateLayout = 0x46af0@58 (reference 0x4d547)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x4e78c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x7464d; current table index = 8
SetFocus callback thunk = 0x454e0; decoded slot = 89
```

#### hl-3248.serverbrowser.windows

```text
Panel::SetPos = 0x19b40 (nonvirtual)
Panel::SetBuildGroup = 0x1c7e0@67
Panel::SetName = 0x19780 (nonvirtual)
Panel::SetAutoDelete = 0x1b210@39
Panel::SetBuildModeEditable = 0x1bff0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1c020 (nonvirtual)
Panel::SetParent(Panel*) = 0x1adf0@37
Panel::AddActionSignalTarget(Panel*) = 0x1c270@41
Panel::ApplySettings = 0x1cac0@80
Panel::SetParent(VPANEL) = 0x1ae20@36
Panel::SetProportional = 0x1e050@113
Panel::SetKeyBoardInputEnabled = 0x1e0b0@115
Panel::IsKeyBoardInputEnabled = 0x1e150@117
Panel::SetMouseInputEnabled = 0x1e110@114
Panel::IsMouseInputEnabled = 0x1e180@116
Panel::IsProportional = 0x1d30@21
Panel::GetVParent = 0x19fa0@35
Panel::GetParent = 0x19fc0@34
Panel::PostMessage(VPANEL) = 0x1dd90@32 (reference 0x341d3)
Panel::InvalidateLayout = 0x1c880@58 (reference 0x34117)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x17a4c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3c2bd; current table index = 8
SetFocus callback thunk = 0x1b270; decoded slot = 89
```

#### hl-3266.engine.windows

```text
Panel::SetPos = 0xd7420 (nonvirtual)
Panel::SetBuildGroup = 0xd9fa0@67
Panel::SetName = 0xd7060 (nonvirtual)
Panel::SetAutoDelete = 0xd8ac0@39
Panel::SetBuildModeEditable = 0xd9830 (nonvirtual)
Panel::SetBuildModeDeletable = 0xd9860 (nonvirtual)
Panel::SetParent(Panel*) = 0xd86b0@37
Panel::AddActionSignalTarget(Panel*) = 0xd9a90@41
Panel::ApplySettings = 0xda240@80
Panel::SetParent(VPANEL) = 0xd86e0@36
Panel::SetProportional = 0xdb770@113
Panel::SetKeyBoardInputEnabled = 0xdb7d0@115
Panel::IsKeyBoardInputEnabled = 0xdb870@117
Panel::SetMouseInputEnabled = 0xdb830@114
Panel::IsMouseInputEnabled = 0xdb8a0@116
Panel::IsProportional = 0x1d20@21
Panel::GetVParent = 0xd7880@35
Panel::GetParent = 0xd78a0@34
Panel::PostMessage(VPANEL) = 0xdb4c0@32 (reference 0xfb7c3)
Panel::InvalidateLayout = 0xda030@58 (reference 0xfb707)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xdce2c
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe2bad; current table index = 8
SetFocus callback thunk = 0xd8b20; decoded slot = 89
```

#### hl-3266.gameui.windows

```text
Panel::SetPos = 0x477f0 (nonvirtual)
Panel::SetBuildGroup = 0x4cca0@67
Panel::SetName = 0x473f0 (nonvirtual)
Panel::SetAutoDelete = 0x4a260@39
Panel::SetBuildModeEditable = 0x4be90 (nonvirtual)
Panel::SetBuildModeDeletable = 0x4bf30 (nonvirtual)
Panel::SetParent(Panel*) = 0x499d0@37
Panel::AddActionSignalTarget(Panel*) = 0x4c4f0@41
Panel::ApplySettings = 0x4d510@80
Panel::SetParent(VPANEL) = 0x49a50@36
Panel::SetProportional = 0x500b0@113
Panel::SetKeyBoardInputEnabled = 0x50180@115
Panel::IsKeyBoardInputEnabled = 0x502c0@117
Panel::SetMouseInputEnabled = 0x50230@114
Panel::IsMouseInputEnabled = 0x50330@116
Panel::IsProportional = 0x2760@21
Panel::GetVParent = 0x47cc0@35
Panel::GetParent = 0x47d20@34
Panel::PostMessage(VPANEL) = 0x4fa50@32 (reference 0x5b421)
Panel::InvalidateLayout = 0x4cef0@58 (reference 0x5b2d7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x5cf9b
FocusNavGroup::SetCurrentFocus handle setter reference = 0xaceb7; current table index = 8
SetFocus callback thunk = 0x4a2a0; decoded slot = 89
```

#### hl-3266.serverbrowser.windows

```text
Panel::SetPos = 0x19b40 (nonvirtual)
Panel::SetBuildGroup = 0x1c7e0@67
Panel::SetName = 0x19780 (nonvirtual)
Panel::SetAutoDelete = 0x1b210@39
Panel::SetBuildModeEditable = 0x1bff0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1c020 (nonvirtual)
Panel::SetParent(Panel*) = 0x1adf0@37
Panel::AddActionSignalTarget(Panel*) = 0x1c270@41
Panel::ApplySettings = 0x1cac0@80
Panel::SetParent(VPANEL) = 0x1ae20@36
Panel::SetProportional = 0x1e050@113
Panel::SetKeyBoardInputEnabled = 0x1e0b0@115
Panel::IsKeyBoardInputEnabled = 0x1e150@117
Panel::SetMouseInputEnabled = 0x1e110@114
Panel::IsMouseInputEnabled = 0x1e180@116
Panel::IsProportional = 0x1d30@21
Panel::GetVParent = 0x19fa0@35
Panel::GetParent = 0x19fc0@34
Panel::PostMessage(VPANEL) = 0x1dd90@32 (reference 0x341d3)
Panel::InvalidateLayout = 0x1c880@58 (reference 0x34117)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x17a4c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3c2bd; current table index = 8
SetFocus callback thunk = 0x1b270; decoded slot = 89
```

#### hl-3329.engine.windows

```text
Panel::SetPos = 0xd69b0 (nonvirtual)
Panel::SetBuildGroup = 0xd97f0@67
Panel::SetName = 0xd66e0 (nonvirtual)
Panel::SetAutoDelete = 0xd82e0@39
Panel::SetBuildModeEditable = 0xd9080 (nonvirtual)
Panel::SetBuildModeDeletable = 0xd90b0 (nonvirtual)
Panel::SetParent(Panel*) = 0xd7f20@37
Panel::AddActionSignalTarget(Panel*) = 0xd92e0@41
Panel::ApplySettings = 0xd9a70@80
Panel::SetParent(VPANEL) = 0xd7f50@36
Panel::SetProportional = 0xdb040@113
Panel::SetKeyBoardInputEnabled = 0xdb0a0@115
Panel::IsKeyBoardInputEnabled = 0xdb140@117
Panel::SetMouseInputEnabled = 0xdb100@114
Panel::IsMouseInputEnabled = 0xdb170@116
Panel::IsProportional = 0x1d00@21
Panel::GetVParent = 0xd6e30@35
Panel::GetParent = 0xd6f70@34
Panel::PostMessage(VPANEL) = 0xdad80@32 (reference 0xfb2a3)
Panel::InvalidateLayout = 0xd9880@58 (reference 0xfb1e7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xdc68c
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe258d; current table index = 8
SetFocus callback thunk = 0xd83e0; decoded slot = 89
```

#### hl-3329.gameui.windows

```text
Panel::SetPos = 0x477f0 (nonvirtual)
Panel::SetBuildGroup = 0x4cca0@67
Panel::SetName = 0x473f0 (nonvirtual)
Panel::SetAutoDelete = 0x4a260@39
Panel::SetBuildModeEditable = 0x4be90 (nonvirtual)
Panel::SetBuildModeDeletable = 0x4bf30 (nonvirtual)
Panel::SetParent(Panel*) = 0x499d0@37
Panel::AddActionSignalTarget(Panel*) = 0x4c4f0@41
Panel::ApplySettings = 0x4d510@80
Panel::SetParent(VPANEL) = 0x49a50@36
Panel::SetProportional = 0x500b0@113
Panel::SetKeyBoardInputEnabled = 0x50180@115
Panel::IsKeyBoardInputEnabled = 0x502c0@117
Panel::SetMouseInputEnabled = 0x50230@114
Panel::IsMouseInputEnabled = 0x50330@116
Panel::IsProportional = 0x2760@21
Panel::GetVParent = 0x47cc0@35
Panel::GetParent = 0x47d20@34
Panel::PostMessage(VPANEL) = 0x4fa50@32 (reference 0x5b421)
Panel::InvalidateLayout = 0x4cef0@58 (reference 0x5b2d7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x5cf9b
FocusNavGroup::SetCurrentFocus handle setter reference = 0xaceb7; current table index = 8
SetFocus callback thunk = 0x4a2a0; decoded slot = 89
```

#### hl-3329.serverbrowser.windows

```text
Panel::SetPos = 0x19b40 (nonvirtual)
Panel::SetBuildGroup = 0x1c7e0@67
Panel::SetName = 0x19780 (nonvirtual)
Panel::SetAutoDelete = 0x1b210@39
Panel::SetBuildModeEditable = 0x1bff0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1c020 (nonvirtual)
Panel::SetParent(Panel*) = 0x1adf0@37
Panel::AddActionSignalTarget(Panel*) = 0x1c270@41
Panel::ApplySettings = 0x1cac0@80
Panel::SetParent(VPANEL) = 0x1ae20@36
Panel::SetProportional = 0x1e050@113
Panel::SetKeyBoardInputEnabled = 0x1e0b0@115
Panel::IsKeyBoardInputEnabled = 0x1e150@117
Panel::SetMouseInputEnabled = 0x1e110@114
Panel::IsMouseInputEnabled = 0x1e180@116
Panel::IsProportional = 0x1d30@21
Panel::GetVParent = 0x19fa0@35
Panel::GetParent = 0x19fc0@34
Panel::PostMessage(VPANEL) = 0x1dd90@32 (reference 0x341d3)
Panel::InvalidateLayout = 0x1c880@58 (reference 0x34117)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x17a4c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3c2bd; current table index = 8
SetFocus callback thunk = 0x1b270; decoded slot = 89
```

#### hl-3647.engine.windows

```text
Panel::SetPos = 0xd5b20 (nonvirtual)
Panel::SetBuildGroup = 0xd8990@67
Panel::SetName = 0xd5850 (nonvirtual)
Panel::SetAutoDelete = 0xd7450@39
Panel::SetBuildModeEditable = 0xd8210 (nonvirtual)
Panel::SetBuildModeDeletable = 0xd8240 (nonvirtual)
Panel::SetParent(Panel*) = 0xd7090@37
Panel::AddActionSignalTarget(Panel*) = 0xd8480@41
Panel::ApplySettings = 0xd8c30@80
Panel::SetParent(VPANEL) = 0xd70c0@36
Panel::SetProportional = 0xda200@113
Panel::SetKeyBoardInputEnabled = 0xda260@115
Panel::IsKeyBoardInputEnabled = 0xda300@117
Panel::SetMouseInputEnabled = 0xda2c0@114
Panel::IsMouseInputEnabled = 0xda330@116
Panel::IsProportional = 0x1d00@21
Panel::GetVParent = 0xd5fa0@35
Panel::GetParent = 0xd60e0@34
Panel::PostMessage(VPANEL) = 0xd9f40@32 (reference 0xfa533)
Panel::InvalidateLayout = 0xd8a20@58 (reference 0xfa477)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xdb8dc
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe17cd; current table index = 8
SetFocus callback thunk = 0xd7550; decoded slot = 89
```

#### hl-3647.gameui.windows

```text
Panel::SetPos = 0x42f50 (nonvirtual)
Panel::SetBuildGroup = 0x45ed0@67
Panel::SetName = 0x42c80 (nonvirtual)
Panel::SetAutoDelete = 0x448b0@39
Panel::SetBuildModeEditable = 0x456e0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x45710 (nonvirtual)
Panel::SetParent(Panel*) = 0x444e0@37
Panel::AddActionSignalTarget(Panel*) = 0x45960@41
Panel::ApplySettings = 0x461b0@80
Panel::SetParent(VPANEL) = 0x44510@36
Panel::SetProportional = 0x477d0@113
Panel::SetKeyBoardInputEnabled = 0x47830@115
Panel::IsKeyBoardInputEnabled = 0x478d0@117
Panel::SetMouseInputEnabled = 0x47890@114
Panel::IsMouseInputEnabled = 0x47900@116
Panel::IsProportional = 0x2740@21
Panel::GetVParent = 0x433d0@35
Panel::GetParent = 0x43510@34
Panel::PostMessage(VPANEL) = 0x47510@32 (reference 0x4cbd3)
Panel::InvalidateLayout = 0x45f70@58 (reference 0x4cb17)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x4dd5c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x7425d; current table index = 8
SetFocus callback thunk = 0x449c0; decoded slot = 89
```

#### hl-3647.serverbrowser.windows

```text
Panel::SetPos = 0x21fe0 (nonvirtual)
Panel::SetBuildGroup = 0x23a90@67
Panel::SetName = 0x21f40 (nonvirtual)
Panel::SetAutoDelete = 0x22770@39
Panel::SetBuildModeEditable = 0x23530 (nonvirtual)
Panel::SetBuildModeDeletable = 0x23560 (nonvirtual)
Panel::SetParent(Panel*) = 0x22420@37
Panel::AddActionSignalTarget(Panel*) = 0x26250@41
Panel::ApplySettings = 0x25450@80
Panel::SetParent(VPANEL) = 0x22450@36
Panel::SetProportional = 0x246e0@113
Panel::SetKeyBoardInputEnabled = 0x24790@115
Panel::IsKeyBoardInputEnabled = 0x24880@117
Panel::SetMouseInputEnabled = 0x24840@114
Panel::IsMouseInputEnabled = 0x248b0@116
Panel::IsProportional = 0x39b0@21
Panel::GetVParent = 0x22140@35
Panel::GetParent = 0x22160@34
Panel::PostMessage(VPANEL) = 0x24450@32 (reference 0x405c8)
Panel::InvalidateLayout = 0x23b50@58 (reference 0x404d9)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x3303c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x5242d; current table index = 8
SetFocus callback thunk = 0x24310; decoded slot = 89
SetFocus callback thunk = 0x24310; decoded slot = 89
SetFocus callback thunk = 0x24310; decoded slot = 89
SetFocus callback thunk = 0x24310; decoded slot = 89
SetFocus callback thunk = 0x24310; decoded slot = 89
```

#### hl-4554.engine.windows

```text
Panel::SetPos = 0xf5dc0 (nonvirtual)
Panel::SetBuildGroup = 0xf90d0@67
Panel::SetName = 0xf5a60 (nonvirtual)
Panel::SetAutoDelete = 0xf7ab0@39
Panel::SetBuildModeEditable = 0xf88e0 (nonvirtual)
Panel::SetBuildModeDeletable = 0xf8910 (nonvirtual)
Panel::SetParent(Panel*) = 0xf76f0@37
Panel::AddActionSignalTarget(Panel*) = 0xf8b60@41
Panel::ApplySettings = 0xf93b0@80
Panel::SetParent(VPANEL) = 0xf7720@36
Panel::SetProportional = 0xfaa30@113
Panel::SetKeyBoardInputEnabled = 0xfaa90@115
Panel::IsKeyBoardInputEnabled = 0xfab30@117
Panel::SetMouseInputEnabled = 0xfaaf0@114
Panel::IsMouseInputEnabled = 0xfab60@116
Panel::IsProportional = 0x1cb0@21
Panel::GetVParent = 0xf62d0@35
Panel::GetParent = 0xf62f0@34
Panel::PostMessage(VPANEL) = 0xfa770@32 (reference 0x11dc4f)
Panel::InvalidateLayout = 0xf9170@58 (reference 0x11db87)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xfc89c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x102fdd; current table index = 8
SetFocus callback thunk = 0xf7cc0; decoded slot = 89
```

#### hl-4554.gameui.windows

```text
Panel::SetPos = 0x440d0 (nonvirtual)
Panel::SetBuildGroup = 0x473e0@67
Panel::SetName = 0x43d70 (nonvirtual)
Panel::SetAutoDelete = 0x45dc0@39
Panel::SetBuildModeEditable = 0x46bf0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x46c20 (nonvirtual)
Panel::SetParent(Panel*) = 0x45a00@37
Panel::AddActionSignalTarget(Panel*) = 0x46e70@41
Panel::ApplySettings = 0x476c0@80
Panel::SetParent(VPANEL) = 0x45a30@36
Panel::SetProportional = 0x48d40@113
Panel::SetKeyBoardInputEnabled = 0x48da0@115
Panel::IsKeyBoardInputEnabled = 0x48e40@117
Panel::SetMouseInputEnabled = 0x48e00@114
Panel::IsMouseInputEnabled = 0x48e70@116
Panel::IsProportional = 0x2730@21
Panel::GetVParent = 0x445e0@35
Panel::GetParent = 0x44600@34
Panel::PostMessage(VPANEL) = 0x48a80@32 (reference 0x4e26f)
Panel::InvalidateLayout = 0x47480@58 (reference 0x4e1a7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x4f61c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x768fd; current table index = 8
SetFocus callback thunk = 0x45fd0; decoded slot = 89
```

#### hl-4554.serverbrowser.windows

```text
Panel::SetPos = 0x1ac90 (nonvirtual)
Panel::SetBuildGroup = 0x1c6a0@67
Panel::SetName = 0x1abf0 (nonvirtual)
Panel::SetAutoDelete = 0x1b470@39
Panel::SetBuildModeEditable = 0x1c160 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1c190 (nonvirtual)
Panel::SetParent(Panel*) = 0x1b0c0@37
Panel::AddActionSignalTarget(Panel*) = 0x1e640@41
Panel::ApplySettings = 0x1db10@80
Panel::SetParent(VPANEL) = 0x1b100@36
Panel::SetProportional = 0x1d070@113
Panel::SetKeyBoardInputEnabled = 0x1d0e0@115
Panel::IsKeyBoardInputEnabled = 0x1d180@117
Panel::SetMouseInputEnabled = 0x1d140@114
Panel::IsMouseInputEnabled = 0x1d1b0@116
Panel::IsProportional = 0x98b0@21
Panel::GetVParent = 0x1adb0@35
Panel::GetParent = 0x1ade0@34
Panel::PostMessage(VPANEL) = 0x1cd90@32 (reference 0x2f377)
Panel::InvalidateLayout = 0x1c740@58 (reference 0x2f27f)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x22fdf
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3fcdd; current table index = 8
SetFocus callback thunk = 0x1d2e0; decoded slot = 89
SetFocus callback thunk = 0x1d2e0; decoded slot = 89
```

#### hl-6153.engine.windows

```text
Panel::SetPos = 0xda110 (nonvirtual)
Panel::SetBuildGroup = 0xdd3d0@67
Panel::SetName = 0xda080 (nonvirtual)
Panel::SetAutoDelete = 0xdaca0@39
Panel::SetBuildModeEditable = 0xdcbe0 (nonvirtual)
Panel::SetBuildModeDeletable = 0xdcc10 (nonvirtual)
Panel::SetParent(Panel*) = 0xda8d0@37
Panel::AddActionSignalTarget(Panel*) = 0xdce60@41
Panel::ApplySettings = 0xdd6b0@80
Panel::SetParent(VPANEL) = 0xda900@36
Panel::SetProportional = 0xdee60@113
Panel::SetKeyBoardInputEnabled = 0xdeec0@115
Panel::IsKeyBoardInputEnabled = 0xdef60@117
Panel::SetMouseInputEnabled = 0xdef20@114
Panel::IsMouseInputEnabled = 0xdef90@116
Panel::IsProportional = 0x1d20@21
Panel::GetVParent = 0xda230@35
Panel::GetParent = 0xda250@34
Panel::PostMessage(VPANEL) = 0xdeba0@32 (reference 0x10150f)
Panel::InvalidateLayout = 0xdd470@58 (reference 0x101447)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xe0c2c
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe718d; current table index = 8
SetFocus callback thunk = 0xde470; decoded slot = 89
```

#### hl-6153.gameui.windows

```text
Panel::SetPos = 0x435a0 (nonvirtual)
Panel::SetBuildGroup = 0x46860@67
Panel::SetName = 0x43510 (nonvirtual)
Panel::SetAutoDelete = 0x44130@39
Panel::SetBuildModeEditable = 0x46070 (nonvirtual)
Panel::SetBuildModeDeletable = 0x460a0 (nonvirtual)
Panel::SetParent(Panel*) = 0x43d60@37
Panel::AddActionSignalTarget(Panel*) = 0x462f0@41
Panel::ApplySettings = 0x46b40@80
Panel::SetParent(VPANEL) = 0x43d90@36
Panel::SetProportional = 0x482f0@113
Panel::SetKeyBoardInputEnabled = 0x48350@115
Panel::IsKeyBoardInputEnabled = 0x483f0@117
Panel::SetMouseInputEnabled = 0x483b0@114
Panel::IsMouseInputEnabled = 0x48420@116
Panel::IsProportional = 0x2870@21
Panel::GetVParent = 0x436c0@35
Panel::GetParent = 0x436e0@34
Panel::PostMessage(VPANEL) = 0x48030@32 (reference 0x4d77f)
Panel::InvalidateLayout = 0x46900@58 (reference 0x4d6b7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x4eb1c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x73f3d; current table index = 8
SetFocus callback thunk = 0x47900; decoded slot = 89
```

#### hl-6153.serverbrowser.windows

```text
Panel::SetPos = 0x1ac90 (nonvirtual)
Panel::SetBuildGroup = 0x1c6a0@67
Panel::SetName = 0x1abf0 (nonvirtual)
Panel::SetAutoDelete = 0x1b470@39
Panel::SetBuildModeEditable = 0x1c160 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1c190 (nonvirtual)
Panel::SetParent(Panel*) = 0x1b0c0@37
Panel::AddActionSignalTarget(Panel*) = 0x1e640@41
Panel::ApplySettings = 0x1db10@80
Panel::SetParent(VPANEL) = 0x1b100@36
Panel::SetProportional = 0x1d070@113
Panel::SetKeyBoardInputEnabled = 0x1d0e0@115
Panel::IsKeyBoardInputEnabled = 0x1d180@117
Panel::SetMouseInputEnabled = 0x1d140@114
Panel::IsMouseInputEnabled = 0x1d1b0@116
Panel::IsProportional = 0x98b0@21
Panel::GetVParent = 0x1adb0@35
Panel::GetParent = 0x1ade0@34
Panel::PostMessage(VPANEL) = 0x1cd90@32 (reference 0x2f377)
Panel::InvalidateLayout = 0x1c740@58 (reference 0x2f27f)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x22fdf
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3fcdd; current table index = 8
SetFocus callback thunk = 0x1d2e0; decoded slot = 89
SetFocus callback thunk = 0x1d2e0; decoded slot = 89
```

#### hl-8684.engine.linux

```text
Panel::SetPos = 0x2351a0 (nonvirtual)
Panel::SetBuildGroup = 0x230b20@68
Panel::SetName = 0x235130 (nonvirtual)
Panel::SetAutoDelete = 0x230950@39
Panel::SetBuildModeEditable = 0x235d50 (nonvirtual)
Panel::SetBuildModeDeletable = 0x235d80 (nonvirtual)
Panel::SetParent(Panel*) = 0x231950@36
Panel::AddActionSignalTarget(Panel*) = 0x231720@40
Panel::ApplySettings = 0x232b80@81
Panel::SetParent(VPANEL) = 0x230ee0@37
Panel::SetProportional = 0x233870@114
Panel::SetKeyBoardInputEnabled = 0x233950@116
Panel::IsKeyBoardInputEnabled = 0x230dd0@118
Panel::SetMouseInputEnabled = 0x2311c0@115
Panel::IsMouseInputEnabled = 0x230d80@117
Panel::IsProportional = 0x20d7a0@21
Panel::GetVParent = 0x231180@35
Panel::GetParent = 0x231560@34
Panel::PostMessage(VPANEL) = 0x231280@32 (reference 0x25ff6c)
Panel::InvalidateLayout = 0x233c10@59 (reference 0x25fed0)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x2247d5
FocusNavGroup::SetCurrentFocus handle setter reference = 0x227469; current table index = 8
SetFocus PMF store = 0x23796f; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x238d0d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x23a0bd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x23b3f5; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-8684.engine.windows

```text
Panel::SetPos = 0xdc460 (nonvirtual)
Panel::SetBuildGroup = 0xdf720@67
Panel::SetName = 0xdc3d0 (nonvirtual)
Panel::SetAutoDelete = 0xdcff0@39
Panel::SetBuildModeEditable = 0xdef30 (nonvirtual)
Panel::SetBuildModeDeletable = 0xdef60 (nonvirtual)
Panel::SetParent(Panel*) = 0xdcc20@37
Panel::AddActionSignalTarget(Panel*) = 0xdf1b0@41
Panel::ApplySettings = 0xdfa00@80
Panel::SetParent(VPANEL) = 0xdcc50@36
Panel::SetProportional = 0xe11b0@113
Panel::SetKeyBoardInputEnabled = 0xe1210@115
Panel::IsKeyBoardInputEnabled = 0xe12b0@117
Panel::SetMouseInputEnabled = 0xe1270@114
Panel::IsMouseInputEnabled = 0xe12e0@116
Panel::IsProportional = 0x1d20@21
Panel::GetVParent = 0xdc580@35
Panel::GetParent = 0xdc5a0@34
Panel::PostMessage(VPANEL) = 0xe0ef0@32 (reference 0x10387f)
Panel::InvalidateLayout = 0xdf7c0@58 (reference 0x1037b7)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0xe2f7c
FocusNavGroup::SetCurrentFocus handle setter reference = 0xe94fd; current table index = 8
SetFocus callback thunk = 0xe07c0; decoded slot = 89
```

#### hl-8684.gameui.linux

```text
Panel::SetPos = 0x12dbb0 (nonvirtual)
Panel::SetBuildGroup = 0x129530@68
Panel::SetName = 0x12db40 (nonvirtual)
Panel::SetAutoDelete = 0x129360@39
Panel::SetBuildModeEditable = 0x12e760 (nonvirtual)
Panel::SetBuildModeDeletable = 0x12e790 (nonvirtual)
Panel::SetParent(Panel*) = 0x12a360@36
Panel::AddActionSignalTarget(Panel*) = 0x12a130@40
Panel::ApplySettings = 0x12b590@81
Panel::SetParent(VPANEL) = 0x1298f0@37
Panel::SetProportional = 0x12c280@114
Panel::SetKeyBoardInputEnabled = 0x12c360@116
Panel::IsKeyBoardInputEnabled = 0x1297e0@118
Panel::SetMouseInputEnabled = 0x129bd0@115
Panel::IsMouseInputEnabled = 0x129790@117
Panel::IsProportional = 0xa8700@21
Panel::GetVParent = 0x129b90@35
Panel::GetParent = 0x129f70@34
Panel::PostMessage(VPANEL) = 0x129c90@32 (reference 0x1102dc)
Panel::InvalidateLayout = 0x12c620@59 (reference 0x110240)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x10cb05
FocusNavGroup::SetCurrentFocus handle setter reference = 0x10f759; current table index = 8
SetFocus PMF store = 0x13037f; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x13171d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x132acd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0x133e05; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-8684.gameui.windows

```text
Panel::SetPos = 0x436f0 (nonvirtual)
Panel::SetBuildGroup = 0x469b0@67
Panel::SetName = 0x43660 (nonvirtual)
Panel::SetAutoDelete = 0x44280@39
Panel::SetBuildModeEditable = 0x461c0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x461f0 (nonvirtual)
Panel::SetParent(Panel*) = 0x43eb0@37
Panel::AddActionSignalTarget(Panel*) = 0x46440@41
Panel::ApplySettings = 0x46c90@80
Panel::SetParent(VPANEL) = 0x43ee0@36
Panel::SetProportional = 0x48440@113
Panel::SetKeyBoardInputEnabled = 0x484a0@115
Panel::IsKeyBoardInputEnabled = 0x48540@117
Panel::SetMouseInputEnabled = 0x48500@114
Panel::IsMouseInputEnabled = 0x48570@116
Panel::IsProportional = 0x2870@21
Panel::GetVParent = 0x43810@35
Panel::GetParent = 0x43830@34
Panel::PostMessage(VPANEL) = 0x48180@32 (reference 0x4d8cf)
Panel::InvalidateLayout = 0x46a50@58 (reference 0x4d807)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x4ec6c
FocusNavGroup::SetCurrentFocus handle setter reference = 0x7410d; current table index = 8
SetFocus callback thunk = 0x47a50; decoded slot = 89
```

#### hl-8684.serverbrowser.linux

```text
Panel::SetPos = 0xa40b0 (nonvirtual)
Panel::SetBuildGroup = 0x9fa30@68
Panel::SetName = 0xa4040 (nonvirtual)
Panel::SetAutoDelete = 0x9f860@39
Panel::SetBuildModeEditable = 0xa4c60 (nonvirtual)
Panel::SetBuildModeDeletable = 0xa4c90 (nonvirtual)
Panel::SetParent(Panel*) = 0xa0860@36
Panel::AddActionSignalTarget(Panel*) = 0xa0630@40
Panel::ApplySettings = 0xa1a90@81
Panel::SetParent(VPANEL) = 0x9fdf0@37
Panel::SetProportional = 0xa2780@114
Panel::SetKeyBoardInputEnabled = 0xa2860@116
Panel::IsKeyBoardInputEnabled = 0x9fce0@118
Panel::SetMouseInputEnabled = 0xa00d0@115
Panel::IsMouseInputEnabled = 0x9fc90@117
Panel::IsProportional = 0x667c0@21
Panel::GetVParent = 0xa0090@35
Panel::GetParent = 0xa0470@34
Panel::PostMessage(VPANEL) = 0xa0190@32 (reference 0x8680c)
Panel::InvalidateLayout = 0xa2b20@59 (reference 0x86770)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x83035
FocusNavGroup::SetCurrentFocus handle setter reference = 0x85c89; current table index = 8
SetFocus PMF store = 0xa687f; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0xa7c1d; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0xa8fcd; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus PMF store = 0xaa305; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### hl-8684.serverbrowser.windows

```text
Panel::SetPos = 0x1a050 (nonvirtual)
Panel::SetBuildGroup = 0x1ba60@67
Panel::SetName = 0x19fb0 (nonvirtual)
Panel::SetAutoDelete = 0x1a820@39
Panel::SetBuildModeEditable = 0x1b520 (nonvirtual)
Panel::SetBuildModeDeletable = 0x1b550 (nonvirtual)
Panel::SetParent(Panel*) = 0x1a470@37
Panel::AddActionSignalTarget(Panel*) = 0x1d8f0@41
Panel::ApplySettings = 0x1ce10@80
Panel::SetParent(VPANEL) = 0x1a4b0@36
Panel::SetProportional = 0x1c430@113
Panel::SetKeyBoardInputEnabled = 0x1c4a0@115
Panel::IsKeyBoardInputEnabled = 0x1c540@117
Panel::SetMouseInputEnabled = 0x1c500@114
Panel::IsMouseInputEnabled = 0x1c570@116
Panel::IsProportional = 0xa000@21
Panel::GetVParent = 0x1a170@35
Panel::GetParent = 0x1a1a0@34
Panel::PostMessage(VPANEL) = 0x1c140@32 (reference 0x2eeed)
Panel::InvalidateLayout = 0x1bb00@58 (reference 0x2ede0)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x22d9d
FocusNavGroup::SetCurrentFocus handle setter reference = 0x3fe0f; current table index = 8
SetFocus callback thunk = 0x1c600; decoded slot = 89
```

#### svencoop-10257.engine.linux

```text
Panel::SetPos = 0x21c750 (nonvirtual)
Panel::SetBuildGroup = 0x219100@68
Panel::SetName = 0x21c6e0 (nonvirtual)
Panel::SetAutoDelete = 0x218fe0@39
Panel::SetBuildModeEditable = 0x21df00 (nonvirtual)
Panel::SetBuildModeDeletable = 0x21df30 (nonvirtual)
Panel::SetParent(Panel*) = 0x219af0@36
Panel::AddActionSignalTarget(Panel*) = 0x219fe0@40
Panel::ApplySettings = 0x21ce80@81
Panel::SetParent(VPANEL) = 0x219b80@37
Panel::SetProportional = 0x21e5d0@114
Panel::SetKeyBoardInputEnabled = 0x21c250@116
Panel::IsKeyBoardInputEnabled = 0x2197f0@118
Panel::SetMouseInputEnabled = 0x219750@115
Panel::IsMouseInputEnabled = 0x219860@117
Panel::IsProportional = 0x1beb40@21
Panel::GetVParent = 0x21a630@35
Panel::GetParent = 0x21a590@34
Panel::PostMessage(VPANEL) = 0x2196c0@32 (reference 0x1f2535)
Panel::InvalidateLayout = 0x21e6d0@59 (reference 0x1f2476)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1ee5a4
FocusNavGroup::SetCurrentFocus handle setter reference = 0x1ef648; current table index = 8
SetFocus AddToMap call = 0x221245; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x221f97; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x2227c7; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x223077; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-10257.engine.windows

```text
Panel::SetPos = 0x105720 (nonvirtual)
Panel::SetBuildGroup = 0x105300@67
Panel::SetName = 0x1054e0 (nonvirtual)
Panel::SetAutoDelete = 0x105200@39
Panel::SetBuildModeEditable = 0x105350 (nonvirtual)
Panel::SetBuildModeDeletable = 0x105320 (nonvirtual)
Panel::SetParent(Panel*) = 0x1056d0@37
Panel::AddActionSignalTarget(Panel*) = 0x101010@41
Panel::ApplySettings = 0x101180@80
Panel::SetParent(VPANEL) = 0x105570@36
Panel::SetProportional = 0x105760@113
Panel::SetKeyBoardInputEnabled = 0x105410@115
Panel::IsKeyBoardInputEnabled = 0x103010@117
Panel::SetMouseInputEnabled = 0x1054a0@114
Panel::IsMouseInputEnabled = 0x103050@116
Panel::IsProportional = 0x11010@21
Panel::GetVParent = 0x102160@35
Panel::GetParent = 0x101c70@34
Panel::PostMessage(VPANEL) = 0x1049b0@32 (reference 0x126dfd)
Panel::InvalidateLayout = 0x102e90@58 (reference 0x126c90)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x10701a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x10d59f; current table index = 8
SetFocus callback thunk = 0x100ed2; decoded slot = 89
```

#### svencoop-10257.gameui.linux

```text
Panel::SetPos = 0xad6c0 (nonvirtual)
Panel::SetBuildGroup = 0xaa070@68
Panel::SetName = 0xad650 (nonvirtual)
Panel::SetAutoDelete = 0xa9f50@39
Panel::SetBuildModeEditable = 0xaee70 (nonvirtual)
Panel::SetBuildModeDeletable = 0xaeea0 (nonvirtual)
Panel::SetParent(Panel*) = 0xaaa60@36
Panel::AddActionSignalTarget(Panel*) = 0xaaf50@40
Panel::ApplySettings = 0xaddf0@81
Panel::SetParent(VPANEL) = 0xaaaf0@37
Panel::SetProportional = 0xaf540@114
Panel::SetKeyBoardInputEnabled = 0xad1c0@116
Panel::IsKeyBoardInputEnabled = 0xaa760@118
Panel::SetMouseInputEnabled = 0xaa6c0@115
Panel::IsMouseInputEnabled = 0xaa7d0@117
Panel::IsProportional = 0x2b830@21
Panel::GetVParent = 0xab5a0@35
Panel::GetParent = 0xab500@34
Panel::PostMessage(VPANEL) = 0xaa630@32 (reference 0x836d5)
Panel::InvalidateLayout = 0xaf640@59 (reference 0x83616)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x7f6d4
FocusNavGroup::SetCurrentFocus handle setter reference = 0x807e8; current table index = 8
SetFocus AddToMap call = 0xb21b5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xb2f07; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xb3737; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xb3fe7; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-10257.gameui.windows

```text
Panel::SetPos = 0x253b0 (nonvirtual)
Panel::SetBuildGroup = 0x24f90@67
Panel::SetName = 0x25170 (nonvirtual)
Panel::SetAutoDelete = 0x24e90@39
Panel::SetBuildModeEditable = 0x24fe0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x24fb0 (nonvirtual)
Panel::SetParent(Panel*) = 0x25360@37
Panel::AddActionSignalTarget(Panel*) = 0x20ef0@41
Panel::ApplySettings = 0x21060@80
Panel::SetParent(VPANEL) = 0x25200@36
Panel::SetProportional = 0x253f0@113
Panel::SetKeyBoardInputEnabled = 0x250a0@115
Panel::IsKeyBoardInputEnabled = 0x22d80@117
Panel::SetMouseInputEnabled = 0x25130@114
Panel::IsMouseInputEnabled = 0x22dc0@116
Panel::IsProportional = 0x1610@21
Panel::GetVParent = 0x22010@35
Panel::GetParent = 0x21b30@34
Panel::PostMessage(VPANEL) = 0x24640@32 (reference 0x2e1cd)
Panel::InvalidateLayout = 0x22c20@58 (reference 0x2e060)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x2b9ca
FocusNavGroup::SetCurrentFocus handle setter reference = 0x4e51f; current table index = 8
SetFocus callback thunk = 0x20de5; decoded slot = 89
```

#### svencoop-10257.serverbrowser.linux

```text
Panel::SetPos = 0x88120 (nonvirtual)
Panel::SetBuildGroup = 0x84ad0@68
Panel::SetName = 0x880b0 (nonvirtual)
Panel::SetAutoDelete = 0x849b0@39
Panel::SetBuildModeEditable = 0x898d0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x89900 (nonvirtual)
Panel::SetParent(Panel*) = 0x854c0@36
Panel::AddActionSignalTarget(Panel*) = 0x859b0@40
Panel::ApplySettings = 0x88850@81
Panel::SetParent(VPANEL) = 0x85550@37
Panel::SetProportional = 0x89fa0@114
Panel::SetKeyBoardInputEnabled = 0x87c20@116
Panel::IsKeyBoardInputEnabled = 0x851c0@118
Panel::SetMouseInputEnabled = 0x85120@115
Panel::IsMouseInputEnabled = 0x85230@117
Panel::IsProportional = 0x24640@21
Panel::GetVParent = 0x86000@35
Panel::GetParent = 0x85f60@34
Panel::PostMessage(VPANEL) = 0x85090@32 (reference 0x5dff5)
Panel::InvalidateLayout = 0x8a0a0@59 (reference 0x5df36)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x59ff4
FocusNavGroup::SetCurrentFocus handle setter reference = 0x5b108; current table index = 8
SetFocus AddToMap call = 0x8cc15; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x8d967; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x8e197; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x8ea47; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-10257.serverbrowser.windows

```text
Panel::SetPos = 0x170a0 (nonvirtual)
Panel::SetBuildGroup = 0x16c80@67
Panel::SetName = 0x16e60 (nonvirtual)
Panel::SetAutoDelete = 0x16b80@39
Panel::SetBuildModeEditable = 0x16cd0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x16ca0 (nonvirtual)
Panel::SetParent(Panel*) = 0x17050@37
Panel::AddActionSignalTarget(Panel*) = 0x12aa0@41
Panel::ApplySettings = 0x12c10@80
Panel::SetParent(VPANEL) = 0x16ef0@36
Panel::SetProportional = 0x170e0@113
Panel::SetKeyBoardInputEnabled = 0x16d90@115
Panel::IsKeyBoardInputEnabled = 0x14a60@117
Panel::SetMouseInputEnabled = 0x16e20@114
Panel::IsMouseInputEnabled = 0x14aa0@116
Panel::IsProportional = 0x4ac0@21
Panel::GetVParent = 0x13c70@35
Panel::GetParent = 0x13790@34
Panel::PostMessage(VPANEL) = 0x16330@32 (reference 0x2b0dd)
Panel::InvalidateLayout = 0x14900@58 (reference 0x2af70)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1a62a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x362af; current table index = 8
SetFocus callback thunk = 0x12965; decoded slot = 89
```

#### svencoop-8948.engine.linux

```text
Panel::SetPos = 0x268660 (nonvirtual)
Panel::SetBuildGroup = 0x265010@68
Panel::SetName = 0x2685f0 (nonvirtual)
Panel::SetAutoDelete = 0x264ef0@39
Panel::SetBuildModeEditable = 0x269e10 (nonvirtual)
Panel::SetBuildModeDeletable = 0x269e40 (nonvirtual)
Panel::SetParent(Panel*) = 0x265a00@36
Panel::AddActionSignalTarget(Panel*) = 0x265ef0@40
Panel::ApplySettings = 0x268d90@81
Panel::SetParent(VPANEL) = 0x265a90@37
Panel::SetProportional = 0x26a4e0@114
Panel::SetKeyBoardInputEnabled = 0x268160@116
Panel::IsKeyBoardInputEnabled = 0x265700@118
Panel::SetMouseInputEnabled = 0x265660@115
Panel::IsMouseInputEnabled = 0x265770@117
Panel::IsProportional = 0x20aa50@21
Panel::GetVParent = 0x266540@35
Panel::GetParent = 0x2664a0@34
Panel::PostMessage(VPANEL) = 0x2655d0@32 (reference 0x23e445)
Panel::InvalidateLayout = 0x26a5e0@59 (reference 0x23e386)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x23a4b4
FocusNavGroup::SetCurrentFocus handle setter reference = 0x23b558; current table index = 8
SetFocus AddToMap call = 0x26d155; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x26dea7; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x26e6d7; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x26ef87; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-8948.engine.windows

```text
Panel::SetPos = 0x102080 (nonvirtual)
Panel::SetBuildGroup = 0x101c70@67
Panel::SetName = 0x101e50 (nonvirtual)
Panel::SetAutoDelete = 0x101b90@39
Panel::SetBuildModeEditable = 0x101cc0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x101c90 (nonvirtual)
Panel::SetParent(Panel*) = 0x102030@37
Panel::AddActionSignalTarget(Panel*) = 0xfdb40@41
Panel::ApplySettings = 0xfdcb0@80
Panel::SetParent(VPANEL) = 0x101ee0@36
Panel::SetProportional = 0x1020c0@113
Panel::SetKeyBoardInputEnabled = 0x101d80@115
Panel::IsKeyBoardInputEnabled = 0xffb00@117
Panel::SetMouseInputEnabled = 0x101e10@114
Panel::IsMouseInputEnabled = 0xffb40@116
Panel::IsProportional = 0x110b0@21
Panel::GetVParent = 0xfec40@35
Panel::GetParent = 0xfe760@34
Panel::PostMessage(VPANEL) = 0x1013c0@32 (reference 0x123387)
Panel::InvalidateLayout = 0xff980@58 (reference 0x12321e)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x10393a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x109dcf; current table index = 8
SetFocus callback thunk = 0xfd9fe; decoded slot = 89
```

#### svencoop-8948.gameui.linux

```text
Panel::SetPos = 0xc5470 (nonvirtual)
Panel::SetBuildGroup = 0xc1e20@68
Panel::SetName = 0xc5400 (nonvirtual)
Panel::SetAutoDelete = 0xc1d00@39
Panel::SetBuildModeEditable = 0xc6c20 (nonvirtual)
Panel::SetBuildModeDeletable = 0xc6c50 (nonvirtual)
Panel::SetParent(Panel*) = 0xc2810@36
Panel::AddActionSignalTarget(Panel*) = 0xc2d00@40
Panel::ApplySettings = 0xc5ba0@81
Panel::SetParent(VPANEL) = 0xc28a0@37
Panel::SetProportional = 0xc72f0@114
Panel::SetKeyBoardInputEnabled = 0xc4f70@116
Panel::IsKeyBoardInputEnabled = 0xc2510@118
Panel::SetMouseInputEnabled = 0xc2470@115
Panel::IsMouseInputEnabled = 0xc2580@117
Panel::IsProportional = 0x435e0@21
Panel::GetVParent = 0xc3350@35
Panel::GetParent = 0xc32b0@34
Panel::PostMessage(VPANEL) = 0xc23e0@32 (reference 0x9b485)
Panel::InvalidateLayout = 0xc73f0@59 (reference 0x9b3c6)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x97484
FocusNavGroup::SetCurrentFocus handle setter reference = 0x98598; current table index = 8
SetFocus AddToMap call = 0xc9f65; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xcacb7; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xcb4e7; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0xcbd97; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-8948.gameui.windows

```text
Panel::SetPos = 0x250a0 (nonvirtual)
Panel::SetBuildGroup = 0x24c90@67
Panel::SetName = 0x24e70 (nonvirtual)
Panel::SetAutoDelete = 0x24bb0@39
Panel::SetBuildModeEditable = 0x24ce0 (nonvirtual)
Panel::SetBuildModeDeletable = 0x24cb0 (nonvirtual)
Panel::SetParent(Panel*) = 0x25050@37
Panel::AddActionSignalTarget(Panel*) = 0x20dc0@41
Panel::ApplySettings = 0x20f30@80
Panel::SetParent(VPANEL) = 0x24f00@36
Panel::SetProportional = 0x250e0@113
Panel::SetKeyBoardInputEnabled = 0x24da0@115
Panel::IsKeyBoardInputEnabled = 0x22c00@117
Panel::SetMouseInputEnabled = 0x24e30@114
Panel::IsMouseInputEnabled = 0x22c40@116
Panel::IsProportional = 0x1630@21
Panel::GetVParent = 0x21e90@35
Panel::GetParent = 0x219c0@34
Panel::PostMessage(VPANEL) = 0x243e0@32 (reference 0x2de27)
Panel::InvalidateLayout = 0x22aa0@58 (reference 0x2dcbe)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x2b68a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x4dd5f; current table index = 8
SetFocus callback thunk = 0x20cb5; decoded slot = 89
```

#### svencoop-8948.serverbrowser.linux

```text
Panel::SetPos = 0x949e0 (nonvirtual)
Panel::SetBuildGroup = 0x91390@68
Panel::SetName = 0x94970 (nonvirtual)
Panel::SetAutoDelete = 0x91270@39
Panel::SetBuildModeEditable = 0x96190 (nonvirtual)
Panel::SetBuildModeDeletable = 0x961c0 (nonvirtual)
Panel::SetParent(Panel*) = 0x91d80@36
Panel::AddActionSignalTarget(Panel*) = 0x92270@40
Panel::ApplySettings = 0x95110@81
Panel::SetParent(VPANEL) = 0x91e10@37
Panel::SetProportional = 0x96860@114
Panel::SetKeyBoardInputEnabled = 0x944e0@116
Panel::IsKeyBoardInputEnabled = 0x91a80@118
Panel::SetMouseInputEnabled = 0x919e0@115
Panel::IsMouseInputEnabled = 0x91af0@117
Panel::IsProportional = 0x30f00@21
Panel::GetVParent = 0x928c0@35
Panel::GetParent = 0x92820@34
Panel::PostMessage(VPANEL) = 0x91950@32 (reference 0x6a8b5)
Panel::InvalidateLayout = 0x96960@59 (reference 0x6a7f6)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x668b4
FocusNavGroup::SetCurrentFocus handle setter reference = 0x679c8; current table index = 8
SetFocus AddToMap call = 0x994d5; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x9a227; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x9aa57; encoded pfn = 0x169; delta=0; decoded slot=90
SetFocus AddToMap call = 0x9b307; encoded pfn = 0x169; delta=0; decoded slot=90
```

#### svencoop-8948.serverbrowser.windows

```text
Panel::SetPos = 0x16d10 (nonvirtual)
Panel::SetBuildGroup = 0x16900@67
Panel::SetName = 0x16ae0 (nonvirtual)
Panel::SetAutoDelete = 0x16820@39
Panel::SetBuildModeEditable = 0x16950 (nonvirtual)
Panel::SetBuildModeDeletable = 0x16920 (nonvirtual)
Panel::SetParent(Panel*) = 0x16cc0@37
Panel::AddActionSignalTarget(Panel*) = 0x128e0@41
Panel::ApplySettings = 0x12a50@80
Panel::SetParent(VPANEL) = 0x16b70@36
Panel::SetProportional = 0x16d50@113
Panel::SetKeyBoardInputEnabled = 0x16a10@115
Panel::IsKeyBoardInputEnabled = 0x14860@117
Panel::SetMouseInputEnabled = 0x16aa0@114
Panel::IsMouseInputEnabled = 0x148a0@116
Panel::IsProportional = 0x4b90@21
Panel::GetVParent = 0x13a60@35
Panel::GetParent = 0x13590@34
Panel::PostMessage(VPANEL) = 0x16050@32 (reference 0x2aac7)
Panel::InvalidateLayout = 0x14700@58 (reference 0x2a95e)
EditablePanel::OnSetFocus -> GetCurrentFocus reference = 0x1a29a
FocusNavGroup::SetCurrentFocus handle setter reference = 0x35adf; current table index = 8
SetFocus callback thunk = 0x127a5; decoded slot = 89
```

</details>

### E4. 三阶段 IDA 生命周期与执行核验

下表为追加三阶段采集（包括定向补分析）结束时的 IDB 时间，替代附录 D 对这些 IDB 的较早时间快照；附录 D 保留原 Task 1 的历史证据。全部 exact-binary survey SHA-256 与附录 A、本地文件一致。健康查询后正常生命周期退出，save-on-success 完成，targeted quit / supervisor cleanup 后端口释放。

| 输入 | 最终 IDB 修改时间 UTC | save-on-success / port released |
| --- | --- | --- |
| cof-5936.engine.windows | 2026-10-01T03:46:21+00:00 | success / true |
| cof-5936.gameui.windows | 2026-10-01T03:46:37+00:00 | success / true |
| cof-5936.serverbrowser.windows | 2026-10-01T03:46:52+00:00 | success / true |
| cstrike-10210.client.linux | 2026-10-01T03:47:15+00:00 | success / true |
| cstrike-10210.client.windows | 2026-10-01T03:47:33+00:00 | success / true |
| cstrike-3248.client.windows | 2026-10-01T03:47:48+00:00 | success / true |
| cstrike-3647.client.windows | 2026-10-01T03:48:03+00:00 | success / true |
| cstrike-4554.client.windows | 2026-10-01T03:48:18+00:00 | success / true |
| cstrike-6153.client.linux | 2026-10-01T03:48:43+00:00 | success / true |
| cstrike-6153.client.windows | 2026-10-01T03:48:58+00:00 | success / true |
| cstrike-8684.client.linux | 2026-10-01T03:49:23+00:00 | success / true |
| cstrike-8684.client.windows | 2026-10-01T03:49:38+00:00 | success / true |
| czero-10210.client.linux | 2026-10-01T03:50:00+00:00 | success / true |
| czero-10210.client.windows | 2026-10-01T03:50:18+00:00 | success / true |
| czero-8684.client.linux | 2026-10-01T03:50:41+00:00 | success / true |
| czero-8684.client.windows | 2026-10-01T03:50:55+00:00 | success / true |
| czeror-10210.client.linux | 2026-10-01T03:51:19+00:00 | success / true |
| czeror-10210.client.windows | 2026-10-01T03:51:36+00:00 | success / true |
| czeror-8684.client.linux | 2026-10-01T03:51:59+00:00 | success / true |
| czeror-8684.client.windows | 2026-10-01T03:52:14+00:00 | success / true |
| hl-10210.engine.linux | 2026-10-01T03:52:47+00:00 | success / true |
| hl-10210.engine.windows | 2026-10-01T03:53:11+00:00 | success / true |
| hl-10210.gameui.linux | 2026-10-01T03:53:32+00:00 | success / true |
| hl-10210.gameui.windows | 2026-10-01T03:53:47+00:00 | success / true |
| hl-10210.serverbrowser.linux | 2026-10-01T03:54:09+00:00 | success / true |
| hl-10210.serverbrowser.windows | 2026-10-01T03:54:26+00:00 | success / true |
| hl-3248.engine.windows | 2026-10-01T03:54:44+00:00 | success / true |
| hl-3248.gameui.windows | 2026-10-01T03:54:57+00:00 | success / true |
| hl-3248.serverbrowser.windows | 2026-10-01T04:13:18+00:00 | success / true |
| hl-3266.engine.windows | 2026-10-01T03:55:33+00:00 | success / true |
| hl-3266.gameui.windows | 2026-10-01T04:08:01+00:00 | success / true |
| hl-3266.serverbrowser.windows | 2026-10-01T04:14:32+00:00 | success / true |
| hl-3329.engine.windows | 2026-10-01T03:56:25+00:00 | success / true |
| hl-3329.gameui.windows | 2026-10-01T04:09:30+00:00 | success / true |
| hl-3329.serverbrowser.windows | 2026-10-01T04:16:36+00:00 | success / true |
| hl-3647.engine.windows | 2026-10-01T03:57:16+00:00 | success / true |
| hl-3647.gameui.windows | 2026-10-01T03:57:31+00:00 | success / true |
| hl-3647.serverbrowser.windows | 2026-10-01T03:57:47+00:00 | success / true |
| hl-4554.engine.windows | 2026-10-01T03:58:05+00:00 | success / true |
| hl-4554.gameui.windows | 2026-10-01T03:58:19+00:00 | success / true |
| hl-4554.serverbrowser.windows | 2026-10-01T03:58:35+00:00 | success / true |
| hl-6153.engine.windows | 2026-10-01T03:58:54+00:00 | success / true |
| hl-6153.gameui.windows | 2026-10-01T03:59:08+00:00 | success / true |
| hl-6153.serverbrowser.windows | 2026-10-01T03:59:24+00:00 | success / true |
| hl-8684.engine.linux | 2026-10-01T03:59:52+00:00 | success / true |
| hl-8684.engine.windows | 2026-10-01T04:00:10+00:00 | success / true |
| hl-8684.gameui.linux | 2026-10-01T03:42:55+00:00 | success / true |
| hl-8684.gameui.windows | 2026-10-01T03:41:41+00:00 | success / true |
| hl-8684.serverbrowser.linux | 2026-10-01T04:00:34+00:00 | success / true |
| hl-8684.serverbrowser.windows | 2026-10-01T04:00:50+00:00 | success / true |
| svencoop-10257.engine.linux | 2026-10-01T04:01:38+00:00 | success / true |
| svencoop-10257.engine.windows | 2026-10-01T04:02:19+00:00 | success / true |
| svencoop-10257.gameui.linux | 2026-10-01T04:02:42+00:00 | success / true |
| svencoop-10257.gameui.windows | 2026-10-01T04:02:56+00:00 | success / true |
| svencoop-10257.serverbrowser.linux | 2026-10-01T04:03:20+00:00 | success / true |
| svencoop-10257.serverbrowser.windows | 2026-10-01T04:03:35+00:00 | success / true |
| svencoop-8948.engine.linux | 2026-10-01T04:04:25+00:00 | success / true |
| svencoop-8948.engine.windows | 2026-10-01T04:05:04+00:00 | success / true |
| svencoop-8948.gameui.linux | 2026-10-01T04:05:27+00:00 | success / true |
| svencoop-8948.gameui.windows | 2026-10-01T04:05:41+00:00 | success / true |
| svencoop-8948.serverbrowser.linux | 2026-10-01T04:06:06+00:00 | success / true |
| svencoop-8948.serverbrowser.windows | 2026-10-01T04:06:23+00:00 | success / true |

实际执行：

```powershell
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_batch.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_follow.py hl-3266 gameui windows
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_follow.py hl-3329 gameui windows
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_follow.py hl-3248 serverbrowser windows
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_follow.py hl-3266 serverbrowser windows
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_follow.py hl-3329 serverbrowser windows
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_verify.py
uv run python C:/Users/HZDEV/AppData/Local/Temp/issue312/stage_report.py
```

上述 IDA 批次和五个定向补采命令正常退出；stage_verify 的最终结果为 62 个 OK、0 个 failure。stage_report 核对 62 个本地/IDA/前轮 hash、62 个 SetProportional 前后身份、288 个实际 ELF 符号、16 个共享接口身份组及 125 个注册实例，并确认 62 份 current-focus setter 及 15 份 gameui constructor 的交叉证据。它们是 Task 1 证据核查命令，不是 production finder 或项目测试。初筛歧义和分析元数据不足在最终结果中已解决，没有把早期失败日志当成目标不存在的证据。

文档已人工核对方案、覆盖限制和抽象接口类别；使用独立临时 Git index 执行 `git diff --cached --check`，退出 0。真实工作区中仅 `anchor.md` 为 untracked，未暂存、未提交；生产实现与 artifact validation 留待本文件确认后执行。

## 确认清单（2026-10-01 全部确认）

- [x] 同意 Stage1 的 factory/参数消歧、两个 SetParent 重载和状态继承关系；#1–#4 使用此入口并保持四模块覆盖。
- [x] 同意 Stage2 的双字符串 Frame 入口及方法身份；ISurface/IInput/ISchemeManager 只输出同引擎共享的 slot-only vfunc，早期版本使用已验证的补充入口。
- [x] 同意 Stage3 的 Windows thunk / Itanium PMF / 内联注册处理，以及 OnSetFocus、m_NavGroup、GetCurrentFocus/_currentFocus 的数据流；#5/#6/#31 复用这三阶段结果。
- [x] 同意 #8–#23/#30 的逐方法身份与共享成员关系；#24 复用 #23。
- [x] 同意 AddPage 输出采用目标真实双参数签名。
- [x] 同意 #25 的 14 份补齐路线、#26 的控件/callee 核验及 #27 的自有 format 路线。
- [x] 同意 #29 使用 CBasePanel 自有背景布局 literal，并复用 #7/#28/C 组已有记录。

用户已一次性确认上述全部项目，Task 2 的结果见第 11 节。
