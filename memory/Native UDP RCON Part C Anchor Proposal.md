---
title: Native UDP RCON Part C Anchor Proposal
type: note
permalink: goldsrc-vibesignatures/native-udp-rcon-part-c-anchor-proposal
---

# Native UDP RCON Part C Anchor Proposal

## Overview

Issue [#326](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/326) Part C 的源码、已有覆盖与当前二进制调查已完成。用户已于 2026-10-04 明确认可全部 Part C anchors，授权实现、验证、提交、推送并创建 PR。当前在 dev 分支实施 finder、配置、references 与 artifacts。

本轮适用 module 全部为 `engine`：11 个 engine configs，15 个实际输入，PE32/I386 或 ELF32/I386。Windows logical module 为 `hw.dll`，Linux 为 `hw.so`；HL3248/3266/3329/3647 BLOB 实际分析 `hw.decrypt.dll`。没有 engine 模块的 cstrike/czero/czeror configs 和未声明的平台不注册。

## Responsibilities

- 复用全部 15 个 `host_initialized` gv artifacts；不新增重复 finder。
- 提议新增 8 个真 global：`ip_sockets`、`net_from`、`net_message`、`sv`、`giActive`、`sv_redirected`、`sv_redirectto`、`outputbuf`，共 120 个 gv artifacts。
- 提议为必要字段输出 3 个 scalar：`sv_active_offset`、`sizebuf_t_data_offset`、`sizebuf_t_cursize_offset`，共 45 个 numeric derived-value artifacts；字段偏移不冒充全局变量。
- 提议新增 Sven 专属、真实存在的前置函数 `Sock_Config`（4 个 func artifacts），为 socket 数组恢复提供 owning function。总计拟新增 169 个 artifacts，复用 15 个 host_initialized artifacts。
- 地址、字段宽度、socket 槽数和 outputbuf 容量按当前输入验证。buffer 容量及其余 ABI 元数据记入覆盖/布局说明；本方案不额外新增 outputbuf_capacity、netadr_size 或 socket-slot global artifacts。
- 不实现 halflife-cli hooks/protocol，不扩展 Part D，不新增 NET_GetServerAddress、socket-open hooks、cvar/table scans 或 stdout hooks。

## Involved Files & Symbols

现有可复用文件：

- `ida_preprocessor_scripts/find-SPR_Shutdown-host_initialized.py` + `SPR_Shutdown` / `CGame_AppActivate` artifacts：host_initialized 已完整覆盖。
- `find-native-rcon-string-symbols.py`：SV_FlushRedirect 自身 FULLMATCH:Redirected Text。
- `find-native-rcon-frame-symbols.py`：SV_CheckForRcon 的既定主帧/dispatch call graph。
- `find-native-rcon-path-string-symbols.py`：NET_SendPacket 自身 FULLMATCH:NET_SendPacket: bad address type。
- `find-native-rcon-packet-symbols.py`：SV_SendBan 的已确认 banned literal/native send/clear 路径。
- `find-Host_ClearMemory.py`、`find-Host_Init.py`（以实际仓内 finder/config 为准）与已存在 artifacts：独立结构基址和初始化状态检查。
- `_native_rcon_common.py`、`_native_rcon_path_common.py`、`_engine_private_globals_common.py`、`renderer_elf_symbols.py`：当前 operand/PIC/call graph、retained ELF identity 和 signature validators。
- `references/{hl-10210,svencoop-10257}/engine/SV_CheckForRcon.{windows,linux}.yaml`：已由 CLI 生成的 Part B references，复用并仅补齐有效注解。
- `configs/<tag>.yaml` / `bin_artifacts/<tag>/engine/`：确认后登记与交付路径。当前没有 Part C 产物。

拟按 owning context 分组 finder；不为同一 reference/policy/platform 的每个 global 拆独立脚本。必要的新 references 经 `generate-reference-yaml` skill / `generate_reference_yaml.py` 生成，canonical HL10210，真正不同的 Sven body 使用 Sven10257 override；已有符合要求的 references 优先复用。

## Architecture

### 逐 anchor 待确认方案

下表所有 global/derived targets 支持上述全部 15 个输入；Sock_Config 仅支持 Sven8948/10257 Windows/Linux 四个输入。发现阶段 `old_yaml_map=None`；已确认的现有 predecessor artifacts 只作当前输入身份/signature 检查。新 gv 默认使用 `LLM_DECOMPILE / found_gv`，正常 x86 decoder 验证所选当前 instruction 的数据地址，最终生成 unique gv_sig。

| target / category | owning anchor 与选择语义 | 独立接受条件 / 必要 ABI |
| --- | --- | --- |
| ip_sockets / gv（数组基址） | HL/CoF：已确认 NET_SendPacket；found_gv 选择 NA_IP/NA_BROADCAST 分支按 netsrc 索引读取的 **IP** socket 表，排除 IPX 表。Sven：下述 Sock_Config；选择 NS_CLIENT 起始槽的地址承载指令，恢复整个 IP socket 数组首址。 | 当前 NET_Config/Sock_Config 的 close/zero、slot stride/count；server socket 建立/getsockname 路径或对应当前 helper 交叉检查。输出数组基址；NS_SERVER 槽地址是 base+4，槽里的值才是 socket handle/fd。Windows SOCKET32，Linux int fd32，元素 4B，NS_SERVER=1。HL/CoF 3 槽；Sven 2 槽。 |
| net_from / gv | 已确认 SV_SendBan；与 net_message 同一 LLM context，选择 native NET_SendPacket 的来源地址对象复制/装载源首址。 | NET_GetPacket 成功路径写同一对象；poller/filter/认证路径读同一包来源。HL/CoF 20B，Sven 36B；完整对象复制，不发布独立 net_from.ip global。 |
| net_message / gv | 同一 SV_SendBan context；选择重复传给 native SZ_Clear/MSG_Write* 的 sizebuf 对象首址，不能选 data 指针槽或 backing buffer。 | 自身 FULLMATCH:net_message 唯一 literal/NET_Init owner（15/15），初始化以及 NET_GetPacket 的 data/cursize 写入；SV_SendBan 的 NET_SendPacket length/data 读取交叉验证。 |
| sizebuf_t_data_offset / scalar | 同一 SV_SendBan reference 的 found_scalar；从当前 length/data 参数数据流识别 data 字段，再以当前已定位对象首址求 byte offset。 | 与 NET_GetPacket/NET_Init 的实际访问一致；当前 15/15 data+8，4B pointer。独立计算 expected_value 后要求 LLM 同值；不能硬套参考偏移。 |
| sizebuf_t_cursize_offset / scalar | 同上，映射 native send 的 length 字段。 | 当前 15/15 cursize+16，4B int；验证当前写入与读取。只发布必要字段，不复制完整 sizebuf/server 类型或假定 flags 类型。sizebuf 必要布局跨度为 20B。 |
| sv / gv（结构首址） | 已确认 SV_CheckForRcon context；found_gv 选择活动服务器 guard 的数据对象，和 giActive / sv_active_offset 分组。 | 已存在 Host_ClearMemory 的整对象 Q_memset 实际起点必须相同；独立 Spawn Server %s\n owner 的 active 读/写 corroboration。排除 cls.state 与 svs/client active。不依赖第一条读、源码顺序或固定清零长度作生产 anchor。 |
| sv_active_offset / scalar（field-derived value） | 同一 poller reference 的 found_scalar，将当前 active 读地址与经 clear/spawn 验证的结构首址求差。 | 15/15 差为 0；qboolean/int32 4B。输出 numeric scalar，消费者访问 sv+offset；不输出 gv_name:sv.active，也不要求完整 server_t。 |
| host_initialized / 已有 gv | 复用 find-SPR_Shutdown-host_initialized，read-never-written + CGame_AppActivate 交叉引用 + early-out。 | 全部 15 个既有 artifacts；本轮 poller 的当前 guard 地址与每个既有 gv_va 一致。qboolean 4B，不按 C bool 读。 |
| giActive / gv | 同一 SV_CheckForRcon context；found_gv 选择退出状态比较的全局整型。 | 15/15 当前 guard 与 DLL_CLOSE=3 比较；现有 Host_Init 写入 DLL_ACTIVE=1 的对象相同（含寄存器值传播/PIC）。排除其它状态/退出旗标。int32 4B，DLL_* 0..5 语义依据源码，3 的实际比较逐输入核验。 |
| sv_redirected / gv | 已确认 SV_FlushRedirect 自身 Redirected Text anchor；和 sv_redirectto / outputbuf 共用 LLM reference，选择 native redirect 模式分派读取。 | 复用 Part B redirect_storage 的当前 RD_PACKET=2、RD_CLIENT=1 dispatch；Begin/Rcon 的参数或 RD_PACKET store、End/Rcon 的 zero store 按实际 retained/inline 路径验证。enum/int32 4B，RD_NONE/CLIENT/PACKET=0/1/2。 |
| sv_redirectto / gv | 同一 Flush reference，选择传给 NS_SERVER native send 的 netadr **by-value** reply 地址装载/复制源基址。 | 和 retained BeginRedirect 或 inline Rcon 的 incoming-address copy destination 相同；20B/36B完整复制。不能选 net_from、局部 sockaddr 或 host_client 指针。 |
| outputbuf / gv | 同一 Flush reference，选择 Q_strlen / MSG_WriteString 使用的原生 redirect 文本对象首址及末尾 byte clear。 | 同一对象的 append/flush 代码经 mode/output current xrefs 取得，验证 1399+NUL 的 1400B 代码容量；三个有 ELF object sizes 的输入都实测 st_size=1400。所有 15 个独立检查，不以 IDA 旧 char/item_size=1 metadata 或参考声明推导容量。 |

### Sven 专属前置函数 anchor（也需要确认）

`Sock_Config` 的自己拥有的 exact literal：

```text
FULLMATCH:Local IP address: %s, SV port: %d, CL port: %d\n
```

四个 Sven 输入均 **1 literal / 1 owning function**；该 owner 也是当前已确认 NET_Config 的 direct callee。其 body 建立/关闭 IP sockets，而同级 P2P_Config 管理 Steam P2P，不可混淆。

| 输入 | Sock_Config RVA | literal VA / owning funcs |
| --- | --- | --- |
| svencoop-10257.linux | `0xea090` | `0x268208` / 1 |
| svencoop-10257.windows | `0xd0d0` | `0x1e62d14` / 1 |
| svencoop-8948.linux | `0x136cd0` | `0x2b3dc4` / 1 |
| svencoop-8948.windows | `0xd220` | `0x1e5bcd0` / 1 |

Sv8948 Linux 实际 STT_FUNC identity 为 `_Z11Sock_Configi`。其余 stripped/Windows 使用已验证的 `Sock_Config` source role；logical config/file stem 仍为 Sock_Config。cdecl，一个 int32 配置输入；它作为定位 predecessor，无需消费者调用，返回值不纳入本轮消费者 ABI 契约。没有函数边界恢复/二进制 patch 的新增需求。

`Closed IP networking.\n` 只在 Sven10257 的两个输入出现；8948 不包含它，所以**不选它作跨版本 anchor**。`Local IP address...` 对四个版本的覆盖已经逐一核验。

### 必要布局与平台差异

| 项目 | HL/CoF（11 输入） | Sven（4 输入） |
| --- | --- | --- |
| ip_sockets | 3 个 4B 元素 | 2 个 4B 元素 |
| NS_SERVER | index 1，slot address=base+4 | 相同 |
| native netadr 完整复制宽度 | 20B | 36B |
| net_message data / cursize | +8 / +16，字段各 4B | 相同 |
| NET_Init 的 net_message.maxsize（仅上下文） | 0x10000 | 0x40000 |
| sv.active | offset 0，4B qboolean | 相同；经巨大 server object clear 独立验证 |
| outputbuf 代码容量 | 1400，1399+NUL | 相同；逐二进制验证 |
| DLL_CLOSE / redirect enum | 3 / 0,1,2，4B | 相同 |

HL netadr 的源码 type@0/ip@4/ipx@8/port@18 与当前 copies 相符；Sven 按当前 IPv4/filter 读取确认 type@0/ip@4，余下地址字节保持不透明并完整复制，不能把 HL 的 20B 定义搬过去。这里不发布全 server_t，也不将其非常不同的 clear sizes 用作固定布局/发现条件。

HL25 Windows 的 Begin/EndRedirect 等函数 inline-only 不妨碍本轮全局定位：独立 Flush、Ban、poller 和真实 inline 写入仍在。先前 IDB 类型/命名只是可读性线索，当前机器指令和原始 ELF symbol size 是最终依据。

### 当前逐输入 RVA 证据

下面是精确 SHA-256 输入的调查值，**不是 finder 常量，不可用于另一 build**。最终 finder 必须独立重发现并通过 signature/operand validators。

| 输入 | ip_sockets | net_from | net_message | sv | giActive | sv_redirected | sv_redirectto | outputbuf |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cof-5936.windows | `0x6ddefc` | `0xaf7340` | `0xae7300` | `0x8203a0` | `0x80d988` | `0x8160d4` | `0x8160c0` | `0x9fd680` |
| hl-10210.linux | `0x3447d4` | `0xbc0c48` | `0xbaf4ac` | `0x9bbf80` | `0x9aca1c` | `0x9bbf64` | `0x9acea0` | `0xb45fc0` |
| hl-10210.windows | `0x4bb8b8` | `0x1246000` | `0x1245fe0` | `0xfd1000` | `0xf776a4` | `0xfc9a54` | `0xfc9a40` | `0xfc9a60` |
| hl-3248.windows | `0x6e1e40` | `0xb09120` | `0xaf90e0` | `0x818840` | `0x8062c8` | `0x80ea14` | `0x80ea00` | `0xa1f4a0` |
| hl-3266.windows | `0x6e1e40` | `0xb09120` | `0xaf90e0` | `0x818840` | `0x8062c8` | `0x80ea14` | `0x80ea00` | `0xa1f4a0` |
| hl-3329.windows | `0x6aece8` | `0xad5a40` | `0xac5a00` | `0x7e5160` | `0x7d2be8` | `0x7db334` | `0x7db320` | `0x9ebdc0` |
| hl-3647.windows | `0x6adb90` | `0xad48c0` | `0xac4880` | `0x7e3fe0` | `0x7d1a68` | `0x7da1b4` | `0x7da1a0` | `0x9eac40` |
| hl-4554.windows | `0x697eb4` | `0xa7e660` | `0xa6e620` | `0x7cdbc0` | `0x7bb6a8` | `0x7c3df4` | `0x7c3de0` | `0x9949a0` |
| hl-6153.windows | `0x654a28` | `0xaaf260` | `0xa9f220` | `0x804c00` | `0x7f26e8` | `0x7fae34` | `0x7fae20` | `0x9cb9e0` |
| hl-8684.linux | `0x35e4d0` | `0xbd58d8` | `0xbc48f0` | `0x9d22e0` | `0x9c2d60` | `0x9d22b0` | `0x9c31e0` | `0xb5b380` |
| hl-8684.windows | `0x657f40` | `0xab2760` | `0xaa2720` | `0x808100` | `0x7f5c08` | `0x7fe354` | `0x7fe340` | `0x9ceee0` |
| svencoop-10257.linux | `0x15ba7c4` | `0x153a620` | `0x14fa600` | `0xf9ff80` | `0xd3f4a4` | `0xd45544` | `0xd45520` | `0xd45560` |
| svencoop-10257.windows | `0x34d3a0` | `0x674b344` | `0x674b368` | `0x73e7028` | `0x78d2238` | `0x73cf90c` | `0x73dae88` | `0x73da910` |
| svencoop-8948.linux | `0x15d1ae4` | `0x1551940` | `0x1511920` | `0xfb72a0` | `0xd8ca64` | `0xd91f04` | `0xd91ee0` | `0xd91f20` |
| svencoop-8948.windows | `0x344700` | `0x670b1b4` | `0x670b1d8` | `0x7112840` | `0x785caf0` | `0x77f4564` | `0x77ffae0` | `0x77ff568` |

### HL10210 Linux 的数据引用示例

其他输入的 reference instruction/length/disp、所有 VA/RVA 与布局证据见本轮本地 `evidence-summary.json`；实现后每个输出还需通过正式 gv 签名唯一性门禁。

| global | VA | reference instruction / length / disp32 offset |
| --- | --- | --- |
| ip_sockets | `0x3447d4` | `0x10cca7`: `mov     ebx, ds:ip_sockets[eax*4]` / 7 / 3 |
| net_from | `0xbc0c48` | `0xe447b`: `mov     eax, ds:net_from.type` / 5 / 1 |
| net_message | `0xbaf4ac` | `0xe4431`: `mov     [esp+7Ch+buf], offset net_message; buf` / 7 / 3 |
| sv | `0x9bbf80` | `0xebc06`: `mov     eax, ds:sv.active` / 5 / 1 |
| giActive | `0x9aca1c` | `0xebc20`: `cmp     ds:giActive, 3` / 7 / 2 |
| sv_redirected | `0x9bbf64` | `0xe3132`: `mov     eax, ds:sv_redirected` / 5 / 1 |
| sv_redirectto | `0x9acea0` | `0xe3220`: `mov     eax, ds:sv_redirectto.type` / 5 / 1 |
| outputbuf | `0xb45fc0` | `0xe3149`: `mov     ds:outputbuf, 0` / 7 / 2 |

绝对 x86-32 operands 按 matched instruction+gv_inst_offset+gv_inst_disp 读取 uint32 地址，不套 RIP-relative 公式。Sven Linux 的 GOT-indirect 与 GOTOFF 形式采用仓库现有 PIC resolution fields，要求解码后真实 writable data object 与当前 expected global 一致；GOT slot 本身不能冒充对象首址。gv_sig 从已验证的 address-bearing instruction 生成，wildcard 地址 displacement，唯一性校验后才写 YAML。

## Dependencies

- [[Native UDP RCON Part A Locators]]、[[Native UDP RCON Part B Symbols]]、[[host_initialized locator]]、[[idalib-mcp]]。
- Official tree `5a2a0b6559dacb23e5c079c9b75bf2682e247335`：
  `engine/net_ws.c:78-89` (storage), `engine/net.h:42-56` (NS_SERVER/declarations), `common/netadr.h:22-38`, `engine/common.h:57-64`, `engine/server.h:37-42,409-415`, `engine/sv_main.c:3529-3594,7804`, `public/dll_state.h:7-12`, `engine/host.c` 初始化/clear 状态。
- DG snapshot `fc59dcb1307986c430859122a33f2a64ea756569`：
  `engine/net_ws.cpp:88-97,2091-2120`、`engine/sv_main.cpp:3572-3650,7922+` 等。当前 DG HEAD 与这些涉及文件的该 snapshot 内容相同，调查仍以指定 snapshot 为参考语义。
- `D:/MetaHookSv/memory/metahook-privatevars.md` 不存在；实际 vendored privatevars note 已读取，九个目标均没有相关私有定位证据。公开 SDK 形参 net_from 不构成 global 线索。
- 本地原始日志/JSON/temporary survey scripts 位于 `C:/Users/HZDEV/AppData/Local/Temp/gsvibe-issue326-part-c/`；它们是调查材料，生产 finder 不依赖这些文件。

## Notes

### 已运行的调查验证

- 所有 15 个实际 engine inputs 逐个检查 `survey_binary` 的 32-bit/imagebase/SHA-256、当前 input/IDB identity 与两轮 owner/dataflow survey；输入 SHA-256 在会话前后不变。
- 当前 12 个相关已存在 functions（按平台真实存在性跳过 inline-only entries）由既有 helpers 重验当前 function start/signature。新增 globals 尚未生成 YAML，**不宣称正式 finder/artifact gates 已通过**。
- `net_message` literal/NET_Init owner：每个输入 1/1；`SV_FlushRedirect` Redirected Text anchor 已复用并检查。
- 15 个 server guard 与 Host_ClearMemory 整对象 clear 起点相同；giActive 与 Host_Init 的当前写入相同；每个 host_initialized artifact 的 gv_va 在当前 poller 中出现。
- 数据/长度字段读取与 source roles 核验；当前 Ban reply、GetPacket 成功 copy、redirect reply-copy 和 append/flush body 验证地址用途。下表/JSON 中的 addresses 仅为调查证据。
- 独立原始 ELF32 symbol record 读取：HL8684/HL10210/Sven8948 的八个对象均 STT_OBJECT，真实名称都是表中 plain global name；ip_sockets st_size=12/12/8，netadr objects=20/20/36，net_message=20，outputbuf=1400。Sven10257 Linux stripped，不能依赖符号表作发现 anchor。
- 本地 `evidence_summary.py` 退出 0：汇总 15 inputs，检查 135 个 global/已覆盖 global 地址具有当前 instruction+disp32 reference、3 field hypotheses 与 current accesses、capacity owner、Sock_Config 1/1 与当前 NET_Config direct-edge、save/port release。这是调查 audit，不是正式 finder 测试。

### IDA 获取、保存与关闭证据

1. 按用户要求首先在 shared 13337 `idb_list`，返回空。随后 `idb_open` exact HL10210 Linux .i64 成功，`survey_binary` 与已知输入 hash 相符。
2. shared endpoint 未开启 `py_eval`；仓库 helper preflight 不能完成。实际 bound call `py_eval(code=1)` 返回 `Method 'py_eval' not found`，因此才 fallback 到 owned IdaMcpLifecycle。没有修改/重启原共享服务。
3. shared-open sessions `89044f30`、`c7e29fff` 都显式 `idb_close(save=True)`，返回 success=true/saved=true。未借用或关闭外部会话。
4. 最后各输入的 owned worker 也在正常探测结束后显式 `idb_close(save=True)` 并检查返回结果，然后生命周期停止自己拥有的 supervisor；全部 15 个最终记录 saved=true、port_released=true。没有依靠默认 600s TTL 保存。
5. server_health 曾报告短暂 busy/config_json_get；路径/架构/hash 来自独立 survey 和 lifecycle exact binding，而不是把 busy 说成 ready。最终 save/close 明确成功。
6. 新版 worker close 保留 .id0/.id1/.id2/.nam/.til loose sidecars，旧 lifecycle 将存在的 .id0 当作 lock。只对本轮已成功 close 的 sidecars，在 exclusive-open 确认无持有者后移至本轮临时归档；不删除、不触碰 active DB working files，最终 .i64 保留并检查 mtime。首次异常 probe 没有改写 metadata，不记为验证成功；后续正常全部重跑。
7. 最后 shared `idb_list` 仍为 []；所有 owned dynamic ports 已释放。

| 输入 | SHA-256 | IDB 最后写入（UTC） |
| --- | --- | --- |
| cof-5936.windows | `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875` | 2026-10-04T15:24:07.919Z |
| hl-10210.linux | `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78` | 2026-10-04T15:21:17.749Z |
| hl-10210.windows | `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295` | 2026-10-04T15:21:30.404Z |
| hl-3248.windows | `7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0` | 2026-10-04T15:22:09.213Z |
| hl-3266.windows | `d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21` | 2026-10-04T15:22:20.401Z |
| hl-3329.windows | `4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480` | 2026-10-04T15:22:31.648Z |
| hl-3647.windows | `7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110` | 2026-10-04T15:22:42.743Z |
| hl-4554.windows | `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3` | 2026-10-04T15:22:53.974Z |
| hl-6153.windows | `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257` | 2026-10-04T15:23:05.081Z |
| hl-8684.linux | `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1` | 2026-10-04T15:23:28.500Z |
| hl-8684.windows | `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10` | 2026-10-04T15:23:16.121Z |
| svencoop-10257.linux | `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd` | 2026-10-04T15:32:51.363Z |
| svencoop-10257.windows | `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596` | 2026-10-04T15:32:39.268Z |
| svencoop-8948.linux | `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e` | 2026-10-04T15:32:24.270Z |
| svencoop-8948.windows | `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8` | 2026-10-04T15:32:11.810Z |

### 确认后实施与交付门禁

1. 在 dev 进行 task-owned changes；创建 Sock_Config deterministic producer（Sven-only），先在 Sven10257 两平台 materialize，才生成其 reference。
2. 按 owner 分组实现 LLM global/scalar finders；literal LLM_DECOMPILE 声明、DAG expected_input、category-correct output、old_yaml_map=None；复用 host_initialized 和已有 Part A/B context，不改其语义。
3. 新 references 只经 CLI 生成，HL10210 canonical + Sven10257 genuinely different body override，两个平台 disasm/procedure 都注解并核验。包括 SV_SendBan、SV_FlushRedirect、HL NET_SendPacket、Sven Sock_Config；已有 poller references 复用。
4. 每个 gv 检查所选当前 instruction 地址/宽度/displacement/PIC、mapped object、unique signature；每个 numeric field 独立得当前 expected_value，再要求 found_scalar 一致。保留真实 ELF identity。
5. 覆盖所有适用 engine config/platform 的强制 finder batch（-allgamever 或等效显式完整 selection）、输出 schema/identity/RVA/signature audit、input SHA-256 不变检查。
6. 运行实际 `uv run python format_repo_files.py --check` 和仓库要求的 unit/repository-contract/all source gates。测试仅在 shared behavior 变化时补充 reusable regression，不锁 finder/config/reference/generated artifact 文本。
7. 按要求的 type(scope) commit + Codex trailer，push 并创建 Part C PR；确认前不实施/提交/发布。

### 可复用经验：MCP 能打开 IDB但缺少 locator API

- 触发信号：idb_list/idb_open/survey 都成功，现有 locator 却 fail-closed；直接调用 py_eval 返回 method-not-found。
- 根因/约束：shared supervisor 的可用性不等于仓库需要的工具合同齐备；同时 close 保留 loose files，不能仅凭 .id0 存在就推断还活着。
- 正确做法：先优先 shared lookup/open，显式保存关闭自己打开的会话；确认 required tool 不可用后才用已有 owned lifecycle。按所有权处理保存/退出；对 closed task-created loose files 先核对保存结果与 exclusive handle，必要时安全归档。
- 验证方式：survey exact identity/hash、实际 API 返回、idb_close saved=true、final .i64 mtime、端口释放；不靠 TTL，不删除未确认的 working files。
- 适用范围：本仓库 Windows GoldSrc IDA investigation，shared supervisor 缺少 py_eval 的配置；未要求修改 MCP/CI/infrastructure。

## Callers

- SV_CheckForRcon 与 active-server SV_ReadPackets 共用 engine receive state，消费者需要 sv.active 避免双重消费。
- NET_GetPacket 写当前 packet/source；SV_SendBan/SV_Rcon 等读它们。
- native Begin/inline Rcon 写 redirect mode/address；Flush/append 读取文本和状态。这里只定位，不声称目标已具有 DG 的 1200-byte splitting 或 recursive redirect protection。

## Implementation Progress — 2026-10-05

用户已认可全部 anchors。dev 分支已登记 11 个 engine configs、5 个分组 global/scalar finder，以及 Sven-only Sock_Config producer（前置 NET_Config）。12 份新 canonical references 由 generate_reference_yaml.py 在已恢复的 HL10210/Sven10257 Windows/Linux IDB 中生成；4 份已有 SV_CheckForRcon references 保留 Part B 注释并追加 global/field 说明。

字段独立恢复解析当前 x86 cdecl pushes/GCC outgoing slots，读取 native NET_SendPacket 的 length/data 字段和 Host_ClearMemory 的 zero-fill 参数；无需参考版本偏移、调用序号或旧产物地址。全局发布仍经过 found_gv，scalar 经 found_scalar 与 independently recovered expected_value 核对。

共享 13337 已按 idb_list/idb_open 优先尝试，打开成功但没有 py_eval；task-owned shared sessions 均 idb_close(save=True)。fallback 使用 IdaMcpLifecycle，所有 IDB 会话显式保存关闭；idle TTL 不能作为保存机制。HL10210 Windows 的最终 4 个节点已通过标准 run_analysis_pipeline 输入/输出验证；其余 14 个输入正在验证。GV 签名使用仓库现有 operand wildcard/segment walk，在选中引用指令开始，gv_inst_offset=0，并独立核对 unique match 和四字节 operand wildcard。

单元测试：2026-10-05 执行 uv run python tests/run_test_suite.py unit -b --durations 10，1379 tests，OK，skipped=5。最终格式、repository-contract、全覆盖 artifact audit、commit/push/PR 尚待后续门禁；不得把当前进度称作完成。

### Signature generation constraint

- 触发信号：make_signature 的输出使用单字符 `?`，且 push imm32 地址可能保留为固定字节；直接调用该工具不足以满足 Part C 的 operand wildcard 门禁。
- 根因/约束：通用 found_gv writer 使用 owner signature + instruction offset；Part C 明确采用引用指令起点签名，并要求地址操作数完整通配。
- 正确做法：保留普通 found_gv 解码与 absolute/PIC resolution metadata，复用 ida_analyze_util 现有 _signature executable segment/padding walk，从选中 instruction 生成签名。owner 仍是已验证真实函数，不能在 instruction 位置创建函数；优先限制在 owner 内，必要时使用有界跨函数预算并记录 flag。
- 验证方式：gv_inst_offset=0；gv_inst_disp 对应连续四个 `??`；_find_unique_bytes 唯一命中等于 gv_sig_va；标准 pipeline input/output validation 与调查地址表独立对照。
- 适用范围：本轮 x86 PE32/ELF32 Part C global finders，不修改共享 artifact schema 或现有 producers。

## Final Local Verification — 2026-10-05

- 已完成 Part C 实现：6 个 finder（5 个 LLM 分组 + Sven Sock_Config）、1 个 Part C 共用 helper、11 个 engine configs；复用 host_initialized 的全部 15 份已有 artifacts，没有新增其 producer。
- 标准 run_analysis_pipeline 全部 15 个实际 engine inputs、64 个新节点通过 required-input 与 produced-output 验证，old_artifact_root=None、force_execution=True，全部由 preprocessor 成功产出，无 Agent fallback 交付。临时执行 wrapper 使用仓库现有 pipeline，并在退出前显式 idb_close(save=True)。
- 169 份新增 artifacts（120 globals、45 scalars、4 functions）逐一与实施前独立调查的 hash/address/instruction 表比较，通过 category normalization、whole-object VA/RVA、reference instruction、四字节 wildcard、scalar-only payload 与 retained ELF symbol identity 检查。已有 host_initialized 产物保持不变。
- Sven8948 Linux 的旧 GCC PIC 通过 GOT 取得对象指针；依据当前 DataRefs 的 GOT slot 识别 address origin，再区分后续 member contents。未知寄存器写入使旧来源失效，避免沿用陈旧字段值。最终 15 inputs 重新独立验证 message/server layouts 和 message/poller/redirect cross-checks 全部通过。
- `uv run python format_repo_files.py --check`：exit 0。
- `uv run python tests/run_test_suite.py unit -b --durations 30`：1379 tests，134.188s，OK（skipped=5）。
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`：15 tests，49.435s，OK。
- 本地代码审查确认没有 binary address/peer offset/call ordinal discovery constants、fake field globals、consumer hooks/protocol changes 或 Part D lifecycle symbols。12 个新 references 通过 CLI 生成，4 个已有 poller references 保留 Part B 注释。
- 所有 task-owned worker 会话显式保存关闭，确认 port released；未依赖 idle TTL 保存。临时证据和 bin/ IDA scratch 不提交。
- 本地交付门禁完成，按用户已授权的步骤提交 dev、推送并创建 Part C PR。本次验证属于符号与 artifacts，不声称游戏中的 halflife-cli UDP RCON 移植已经完成。
