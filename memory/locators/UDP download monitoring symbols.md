---
title: UDP download monitoring symbols
type: note
permalink: goldsrc-vibesignatures/locators/udp-download-monitoring-symbols
---

# UDP 下载监控所需的 engine 符号（Issue 388）

## 范围与消费者清单

为 [GoldSrc_VibeSignatures #388](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/388) 和
[metamod-fallguys #34](https://github.com/hzqst/metamod-fallguys/issues/34) 提供定位器、正式 YAML 和可导出的
function/global 记录。本次没有实现 Metamod 插件。

以下记录全部属于 `engine`，文件为目标版本的 `hw.dll` / `hw.so`。
`symbolName` 来自产物的 `func_name` / `gv_name`，不是文件名或 config 的逻辑标识。

| 逻辑名称 | kind | Windows、HL Linux、Sven 10257 Linux 的 symbolName | Sven 8948 Linux 的 symbolName | 插件接收类型 |
| --- | --- | --- | --- | --- |
| SV_BeginFileDownload_f | function | SV_BeginFileDownload_f | _Z22SV_BeginFileDownload_fv | `void (__cdecl *)(void)` |
| SV_DropClient | function | SV_DropClient | _Z13SV_DropClientP8client_siPcz | `void (__cdecl *)(client_t *, int, char *, ...)` |
| host_client | global | host_client | host_client | `client_t **` |
| cmd_source | global | cmd_source | cmd_source | `cmd_source_t *`（32 位枚举） |
| sv_player | global | sv_player | sv_player | `edict_t **` |

两个 C++ 名称从 Sven 8948 当前 ELF 符号表读取，且地址与独立定位结果一致。Sven 10257 Linux 没有保留这两个源符号；
其记录采用定位后确定的逻辑名称，并不声称 ELF 导出了同名符号。消费者必须使用实际记录中的名称。

三个 global 都返回变量存储地址；每次请求解引用读取当前值。`host_client` 只作不透明客户端指针使用。
`cmd_source == src_client`（0）才是客户端命令；`src_command` 为 1。全局指针非空不等于当前存在有效请求上下文。
没有发布 `client_t` / `netchan_t` 布局，也没有增加 resolver kind。

## 文件与定位链

- `ida_preprocessor_scripts/find-udp-download-symbols.py`：一个生产 finder，消费当前 `Cmd_ExecuteString` 产物，输出五个符号。
- `ida_preprocessor_scripts/_udp_download_common.py`：注册参数、反编译数据流及字段交叉校验。
- 11 个包含 engine 模块的 `configs/<tag>.yaml`：显式输入、五个输出及 `func` / `gv` 注册。
- `bin_artifacts/<tag>/engine/<logical-name>.<platform>.yaml`：75 个正式产物。
- `tests/test_udp_download_dataflow.py`：冲突定义、递归别名、指针缩放、寄存器伪参数、存储宽度和歧义回归。
- [完整证据与消费者 manifest](../issues/issue-388-validation.json)：输入身份、VA/RVA、45 处访问指令及平台名称。

`dlfile` 字符串的拥有者是注册函数，不是下载处理函数。定位器从实际注册调用的两个参数恢复 callback，要求唯一注册及真实函数起点。
MSVC 的长注册函数可能无法反编译；这时只接受相邻且完整的 `push callback; push dlfile; call rel32` 指令。
GCC 路径从调用表达式恢复，包含字符串池中 `sv_allow_dlfile` 的 `dlfile` 后缀引用。
callback 必须引用自己的 `!MD5` / `custom.hpk` 分支，并包含不同的普通文件（三参数）和 buffer（五参数）分片调用；
两者传入的客户端 netchan 字节偏移必须一致。单独交集 `!MD5` / `custom.hpk` 仍有多个拥有者，不能直接选地址。

`host_client` 必须同时是下载入口访问的全局量、消息处理器写入当前客户端实参的存储，以及两条分片调用的客户端基址。
`cmd_source` 必须同时参与下载入口与 1 的比较，以及命令执行器从第二个真实栈实参的赋值。
HL25 Windows 的权限包装器以第三参数 1 转发；定位器验证前两个参数不变，再检查唯一核心执行器的写入。
`sv_player` 从消息处理器的 `cl->edict` 赋值恢复，并要求 `SV_DropClient` 的间接 GameDLL 断开回调读取同一客户端字段。
消息处理器仅作为内部验证拥有者，没有增加其公开产物。

当前 IDB 的确定性数据流在全部 15 个输入上得到交叉验证，因此采用 global 定位规范允许的直接定位例外，没有 LLM 依赖。
只合并结果相同的临时变量定义；冲突定义、未知指针宽度、缺失或多个候选均失败。
Hex-Rays 推断的寄存器 live-in 不作 cdecl 实参，指针/数组索引先转换为字节偏移。
不使用固定 RVA、参考版本字段偏移、函数序言锚或旧同名产物的签名来发现符号。

函数的输出签名包含前 128 字节内的真实 body：下载入口的参数/来源检查或 ModuleC 初始化，断开函数的变参准备及格式化。
这些签名只作当前二进制验证。global 签名从访问指令开始，四字节操作数通配，`gv_inst_offset=0`。
Sven Linux 的 PIC/GOT 操作数保留 `gv_pic_addend`；HL Linux 的绝对操作数可能由 `R_386_32` 加载重定位填写，磁盘上的 0 不能直接当地址。
global 目标必须是可写、非代码段内的四字节对齐存储，不能返回 GOT 槽、字段或指令操作数自身。

## Sven soundcache 与参考源码差异

已反编译 Sven 8948 / 10257 的 Windows/Linux client 和 server，共 8 个匹配输入。两版客户端均从当前关卡名生成
`maps/soundcache/<mapname>.txt`，格式化 `dlfile %s\n` 后提交到公开 engine 表的 `pfnClientCmd`（偏移 `0x50`）。
`Initialize` 的 `0x218` 字节表复制确认了表基址；Sven 10257 Linux 的该槽包装器继续调用命令缓冲加入函数。
服务端生成函数以 `%s/%s/%s.txt` 拼接游戏目录、`maps/soundcache` 和地图名，并写入 sound list。
这些 VA、SHA-256、表基址及请求/生成拥有者都记录在证据文件中。

Sven 下载入口中没有 soundcache 专用字面量或独立的 soundcache 分片分支；该相对文件名进入普通文件分支。
其客户端显式发出 `dlfile`，不先进入普通 FastDL 文件队列。静态证据不代替真实服务器的连接阶段与拒绝路径联调。
两份 issue 参考源码均未包含这套 Sven 游戏代码，不能从参考引擎源码推断其不存在。

custom decal 的真实分支要求名称长 36，前四字符与 `!MD5` 不区分大小写比较，再从 `custom.hpk` 获取 buffer 下发。
不能豁免所有 `!` 开头文件。普通下载与 decal 分片调用均已核对；Sven 当前入口没有参考源码中的 `!ModuleC.dll` 安全模块分支。
消费者应只豁免当前地图的完整 `maps/soundcache/<mapname>.txt`，不能只比较 basename `soundcache.txt`。
豁免请求仍可记录日志。踢人前保存文件名和身份、记录日志；调用 `SV_DropClient` 后返回，不再调用原下载处理函数。

源码语义对照实际读取了 `/home/hztest2/HLND2T_official/engine/{sv_main.c,sv_user.c,cmd.c,host.c,APIProxy.h}`。
issue 中的 BarsTech 源码目录在此机器不可用，没有声称已重新核对该副本。参考源码版本不是发行版地址或 ABI 的证明。
`SV_DropClient` 已核对格式化变参、svc_disconnect、GameDLL 回调、netchan 清理与客户端状态清除；不采用 Hex-Rays 偶然推断的返回值/固定第四参数作为 ABI。

## 覆盖、验证与发布边界

静态覆盖为 HL 3248/3266/3329/3647/4554/6153/8684/10210 Windows，HL 8684/10210 Linux，
Sven 8948/10257 Windows/Linux，以及 CoF 5936 Windows。其他平台未声明、未生成、未验证。
BLOB 的原始 `hw.dll` 身份用于发布记录；IDA 和字节签名校验使用对应的 `hw.decrypt.dll`，两份身份分别记录。

- 正式入口逐个运行 11 个 gamever，`-modules engine -skill find-udp-download-symbols -platform windows,linux -oldgamever none -maxretry 1`：15 成功、0 失败、0 跳过。
- 在重新运行前，只备份并移开本任务的 75 个新产物；正式入口重建与独立共享会话生成的结果逐字节一致。
- 独立 PE/ELF 原始可执行区扫描：75/75 签名唯一；处理 ELF 加载重定位后，45/45 global 解析到正确存储。
- `uv run --no-sync python tests/run_test_suite.py unit -b --durations 10`：共 1525 项，1516 项通过，9 项跳过。
- `uv run --no-sync python tests/run_test_suite.py repository-contract -b --durations 10`：15 项通过。
- `uv run --no-sync python format_repo_files.py --check`、`git diff --check`：通过。
- 11 个完整候选分别执行 snapshot build/guard、gamedata build/guard、JSON build/guard 及对应 mark。
- 使用 Metamod `f0449c80e024751113b158fe1aea962868395ed1` 的真实 `GameData::Initialize` / `ComputeFileCRC64` /
  `QueryByCRC64`，加载完整 index/JSON 并核对实际模块文件 CRC64、symbolName、kind、RVA 和 size：Linux 20 条通过。
  同一 POSIX 构建仅将平台筛选常量改为 Windows，再查询 Windows 的 55 条记录，全部通过；这不是 Windows 进程的运行时验证。
- 完整数据集的 vtable 整数键在普通 JSON 解析后会变成字符串，重新编码会改变排序。预览 index 绑定守卫通过的原始 JSON 文件字节，
  没有对解析后的副本重编码并替换数据集；标准 `encode_index` 应消费 `encode_dataset` 返回的原始对象。

本地预览位于 `gamedata/issue388-preview/`：完整 `index.json`、内容寻址 JSON 和 `engine-symbols.json`。
此目录不入库；正式发布仍由仓库现有 release 流程从合并后的 `origin/main` 派生，不另建受版本控制的 gamedata 树。
本次没有发起 GitHub Release，也没有向 issue 发消息或关闭 issue。

共享 IDA supervisor 最初没有会话；手动阶段按 `idb_list -> idb_open` 获取输入，任务打开的会话均以 `idb_close(save=True)` 完成。
正式入口另按 restored-strict/no-save 契约运行并释放自有 worker。IDB 路径和最后修改时间在证据文件中；没有保存或关闭用户管理的会话。

尚未进行真实游戏进程内 `pfnResolveGameSymbol`、detour、kick、日志开关、服务器控制台及 FastDL 回退联调。
目录查询与 RVA 验证不等价于真实加载验证，尤其不证明 Metamod 能取得旧 BLOB 引擎的普通模块句柄。
这些运行时边界不通过伪造客户端/引擎导出或公开内部结构体来绕过。

## 引擎身份与地址速查

以下均为当前输入的证据，不是下一版本的定位常量。完整 VA、SHA-256、访问指令与 PIC/重定位细节见 JSON。

| 游戏 / 平台 | engine CRC64 | 分析输入 SHA-256 | 下载 RVA | Drop RVA | host_client RVA | cmd_source RVA | sv_player RVA |
| --- | --- | --- | --- | --- | --- | --- | --- |
| cof-5936 / windows | 015f8476be9396f4 | 9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875 | 0xe2dbe | 0x7e2d6 | 0xafc11c | 0x107da1c | 0x80e07c |
| hl-10210 / linux | 727eaa19926a236c | fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78 | 0xeb4e0 | 0xa7ca0 | 0x94d680 | 0x94a928 | 0xb9655c |
| hl-10210 / windows | 6ef7192cd8254e2d | 9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295 | 0x206a60 | 0x1d4190 | 0x1249e90 | 0x124cc00 | 0xf779d8 |
| hl-3248 / windows | 7e07685c707cb53e | 7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0 | 0xac6d0 | 0x56970 | 0xb0dee8 | 0x105e0b8 | 0x8069bc |
| hl-3266 / windows | 8d3b22546891b7a8 | d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21 | 0xac6d0 | 0x56950 | 0xb0dee8 | 0x105e0b8 | 0x8069bc |
| hl-3329 / windows | bcd73e6d3ca715a4 | 4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480 | 0xabd40 | 0x566b0 | 0xada808 | 0x102a9d8 | 0x7d32dc |
| hl-3647 / windows | a4f5787a83b57d53 | 7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110 | 0xaad40 | 0x567e0 | 0xad9688 | 0x1029858 | 0x7d215c |
| hl-4554 / windows | af713d75d839d5c7 | 482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3 | 0xb7190 | 0x61dd0 | 0xa8343c | 0xfd3d5c | 0x7bbd9c |
| hl-6153 / windows | 6a2fadd69b9795c9 | 5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257 | 0x9ba80 | 0x55560 | 0xab403c | 0x1004d5c | 0x7f2de4 |
| hl-8684 / linux | ec79b6fb0c5688c4 | 1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1 | 0x14b2e0 | 0x10e3e0 | 0x963980 | 0x960b98 | 0xbab940 |
| hl-8684 / windows | f9b2f43f1509eb5c | be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10 | 0x9db10 | 0x56990 | 0xab753c | 0x100827c | 0x7f6304 |
| svencoop-10257 / linux | f486c097bcc00fd7 | 8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd | 0xb5a40 | 0x79b90 | 0x30a49c | 0x2f4a64 | 0x1488068 |
| svencoop-10257 / windows | f469129b520b2e16 | e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596 | 0xaba60 | 0x66bd0 | 0x6746c88 | 0x1025800 | 0x78d1398 |
| svencoop-8948 / linux | 550d53bb48ba07cd | aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e | 0x104440 | 0xc89d0 | 0x357a5c | 0x342024 | 0x149f388 |
| svencoop-8948 / windows | 2f9d6118f0ebea99 | 22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8 | 0xaa660 | 0x666d0 | 0x6706af8 | 0xfe5670 | 0x785bb68 |
