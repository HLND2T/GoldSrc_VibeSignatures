---
title: NET_StartThread network-thread symbols
type: note
permalink: goldsrc-vibesignatures/locators/net-startthread-network-thread-symbols
tags:
- locator
- engine
- network
- windows
- issue-338
---

# NET_StartThread / NET_ThreadFunc / dwNetThreadId (#338)

## 触发信号与交付 identity

ThreadGuard 需要识别创建的网络线程及其 DWORD ID 存储,在已核验的循环末尾协调退出。
本任务生产符号,不实现退出 hook。相关需求: GoldSrc_VibeSignatures #338、ThreadGuard #4、halflife-cli #6。
开始时检查了现有 finder/config/artifacts:已有 Host_Shutdown/NET_Shutdown,没有本次三项符号。

| 模块 | Config category | Symbol / payload identity | Catalog record ID |
| --- | --- | --- | --- |
| engine | func | NET_StartThread / func_name | engine/NET_StartThread.windows.yaml |
| engine | func | NET_ThreadFunc / func_name | engine/NET_ThreadFunc.windows.yaml |
| engine | gv | dwNetThreadId / gv_name | engine/dwNetThreadId.windows.yaml |

`dwNetThreadId` 是 `CreateThread(..., &dwNetThreadId)` 指向的四字节可写全局存储地址。
消费者读取该地址处的 DWORD 得到运行时 ID;该符号没有发布运行时 ID 值或 hNetThread 句柄槽。
Catalog JSON 的 kind 分别为 `function`、`function`、`global`。

## 根因 / 定位约束

- 经典 HL/CoF 的唯一精确 C 字符串为 `Couldn't initialize network thread, run without -net_thread\n`。
- Sven 8948/10257 改为 `Couldn't initialize network thread, run with -nonetthread\n`。
  同一字面量有三处代码引用:NET_Init、队列初始化宿主中的内联副本、独立 NET_StartThread。
  不能要求任意 string owner 唯一,也不能按第一处引用命名函数。
- hl-3248/3266/3329/3647/6153/8684 的独立创建代码被 IDA 分配给队列初始化函数的尾块。
  旧 BLOB IDB 还会在 Sys_Error 处截断尾块,将 guard 跳到的 RET 定义为单独 nullsub。
- Sven Windows 的独立创建函数没有代码调用引用,初始 IDB 未定义它。它不是 NET_Init。
- hl-10210 Windows 只有 NET_Init 内的内联创建路径。本次明确不发布 NET_StartThread。
- 四个旧 HL 的 hw.dll 是加密 BLOB;字符串、指令及函数证据来自已解密的 hw.decrypt.dll。

## 正确做法 / finder

`ida_preprocessor_scripts/find-NET_StartThread-symbols.py`:

1. 在当前可读数据段查找两种精确、带 NUL 结束的错误文案,要求总共一个字面量。
   不依赖 IDA 全局 string-list 设置,不使用旧 NET_* YAML 或签名进行发现。
2. 从真实 data xrefs 获取候选代码块。已有尾块使用其入口;未定义代码从相邻对齐边界提议入口,
   再完整跟随当前指令 CFG 验证边界。读取范围有上限,未知跳转/指令/边界失败关闭。
3. 使用导入表身份确认 InitializeCriticalSection、CreateThread、DeleteCriticalSection。
   使用已由独立 finder 产出的当前 Sys_Error artifact 验证致命错误调用,并保留旧引擎允许的扩展签名。
4. 复用 `x86_call_arguments.recover_call_arguments` 恢复六个参数和 reaching-definition provenance。
   参数 3 必须是可执行入口的地址;参数 6 必须是可写 DWORD 存储的地址。
   即时数、寄存器传递及绝对 LEA 均保留真实定义指令/operand offset;
   `[ThreadId]` 运行时读取不能变成 `&ThreadId`。其余四参数验证为零。
5. 验证初始化和失败删除针对同一临界区,CreateThread 返回的 EAX 被写入另一 handle 槽,
   零返回分支进入删除/两个状态清零/Sys_Error。兼容 TEST/MOV/JNZ 和 CMP handle,0/JNZ。
   CFG 证明初始化状态赋值、初始化、创建、handle 保存、删除和回滚支配错误路径;
   不能只按指令地址先后认定清理已执行。
6. 仅将包含两个状态 guard、上述创建/回滚和可选 networking diagnostics 的完整最小代码体
   认定为 NET_StartThread。宿主的分配、注册或其他写入使其属于 inline 路径。
   多个有效创建路径的 callback/ID/临界区/handle 必须一致。
7. 分离已核验的经典共享尾块前,要求唯一外部 tail JMP 来自原 owner。
   仅吸收没有外部入口的 POP/RET 后缀;不修改二进制字节。Sven 未定义入口按已验证边界定义。
   这些分析定义在正式 restored_strict/no-save 生命周期内重新生成。
8. 用共享函数/GV inspection、writer 和 analyzer validator 生成并验证唯一签名。
   Sven inline 副本可能使 lpThreadId PUSH 的字节相同,GV 使用唯一 owner 签名及非零
   gv_inst_offset;地址 operand 本身仍被通配。必要时 owner 签名保留模块内部 rel32 调用,
   用于区分相同副本,不把它用作跨版本发现规则。

运行时 GV 解码是 x86 绝对地址:

```cpp
dwNetThreadId_address = *(uint32_t *)(match + gv_inst_offset + gv_inst_disp);
```

这里的指令为 `push <DWORD-global-address>`,operand offset 为 1、instruction length 为 5。
发布的是解码后的数据存储地址。Sven 10257 的引用指令 RVA 为 0x793a3,
owner 签名 RVA 为 0x79360,gv_inst_offset 为 0x43。

## Windows / BLOB 覆盖证据

以下是本次确切镜像的 RVA 证据,不是 finder 中的地址规则。所有行的平台均为 Windows x86。

| 快照 | 模块 / 分析镜像 | NET_StartThread (func) | NET_ThreadFunc (func) | dwNetThreadId (gv) | CreateThread RVA | 函数边界结果 |
| --- | --- | --- | --- | --- | --- | --- |
| cof-5936 | engine / hw.dll | 0x93943 | 0x937fb | 0xad7298 | 0x93983 | 独立入口 |
| hl-10210 | engine / hw.dll | 不发布 | 0x1e0230 | 0x12247a4 | 0x1df25e | NET_Init 中内联 |
| hl-3248 | engine / hw.decrypt.dll | 0x68250 | 0x68180 | 0xae9078 | 0x68289 | 可调用共享尾块 |
| hl-3266 | engine / hw.decrypt.dll | 0x68230 | 0x68160 | 0xae9078 | 0x68269 | 可调用共享尾块 |
| hl-3329 | engine / hw.decrypt.dll | 0x67f90 | 0x67ec0 | 0xab5998 | 0x67fc9 | 可调用共享尾块 |
| hl-3647 | engine / hw.decrypt.dll | 0x68100 | 0x68030 | 0xab4818 | 0x68139 | 可调用共享尾块 |
| hl-4554 | engine / hw.dll | 0x72d90 | 0x72ca0 | 0xa5e5b8 | 0x72dc9 | 独立入口 |
| hl-6153 | engine / hw.dll | 0x66a80 | 0x669a0 | 0xa8f1b8 | 0x66ab9 | 可调用共享尾块 |
| hl-8684 | engine / hw.dll | 0x68390 | 0x682b0 | 0xa926b8 | 0x683c9 | 可调用共享尾块 |
| svencoop-10257 | engine / hw.dll | 0x79360 | 0x79200 | 0x67cb3b8 | 0x793b5 | 独立入口;另有两个 inline 副本 |
| svencoop-8948 | engine / hw.dll | 0x786e0 | 0x78570 | 0x678b228 | 0x78735 | 独立入口;另有两个 inline 副本 |

三项符号在 Sven 两版均完整覆盖。共 21 个函数 + 11 个 GV = 32 份产物。
hl-10210 不能满足要求独立 NET_StartThread 的消费者 manifest,必须按缺失符号处理。
cstrike-* / czero-* / czeror-* 的生产配置没有 engine 模块,本次不适用。

## 线程 ABI 与 Sleep 安全边界

CreateThread 的真实参数语义确认单个 `LPVOID` 参数(当前传 NULL)、DWORD 返回契约及 Windows x86
LPTHREAD_START_ROUTINE ABI。IDA 由 Win32 导入类型推导 callback 为 `DWORD __stdcall(LPVOID)`。
Sven 两版的实际线程体为无返回无限循环,不使用传入参数;因此不存在可用 RET 来另行证明返回清栈。
CoF 的不可达末尾有普通 RET,不将 IDA 推导的类型冒充该死代码分支的清栈证据。
消费者仅识别线程入口,不应把它当普通可返回函数调用。

本次逐一读取所有 11 个 Windows callback 的指令流和锁/Sleep wrappers:

- 经典引擎遍历三个消息来源,Sven 遍历两个。所有正常的收包、网络/Steam 接口调用、分配和复制
  在本轮 Sys_Sleep 前返回;每个已分配消息在解锁前链入全局消息队列或从全局备用队列转移。
- 网络锁释放后才离开每轮消息处理,然后调用 Sys_Sleep(1)。共享 wrapper 继续调用对应引擎 Sleep IAT。
  Sven 10257 明确可复核为 EnterCriticalSection RVA 0x7925c、收包 RVA 0x79263、
  LeaveCriticalSection RVA 0x79329、Sys_Sleep(1) RVA 0x79346、wrapper Sleep IAT call RVA 0xbb7c4。
  Sven 8948 对应的 Enter RVA 0x785d9、Leave RVA 0x786a9、Sleep call RVA 0x786ca、
  wrapper Sleep IAT call RVA 0xba224。
- Sven callback 的局部值是标量/指针,无观察到的待析构 C++ 局部对象。正常走到该边界时,
  调用栈已退出所有本轮网络/Steam 调用;这里的结论不需要检查或修改 steamclient 私有锁。
- Enter/Leave 的条件都依赖 use_thread/net_thread_initialized。消费者在协调等待期间应保持这两个
  引擎状态不变,使用独立退出信号;提前清零可能跳过 Leave。ThreadGuard 自身锁/RAII 仍需由消费者核验。

| 快照 | NET_ThreadUnlock / Leave 调用 RVA | Sys_Sleep(1) 调用 RVA | Sys_Sleep 入口 RVA |
| --- | --- | --- | --- |
| cof-5936 | 0x9391d | 0x9392e | 0xf2638 |
| hl-10210 | 0x1e03f9 | 0x1e041e | 0x2201d0 |
| hl-3248 | 0x68220 | 0x6823d | 0xb94e0 |
| hl-3266 | 0x68200 | 0x6821d | 0xb94e0 |
| hl-3329 | 0x67f60 | 0x67f7d | 0xb8ba0 |
| hl-3647 | 0x680d0 | 0x680ed | 0xb7d80 |
| hl-4554 | 0x72d49 | 0x72d74 | 0xc38c0 |
| hl-6153 | 0x66a44 | 0x66a66 | 0xa8430 |
| hl-8684 | 0x68354 | 0x68376 | 0xaa5b0 |
| svencoop-10257 | 0x79329 | 0x79346 | 0xbb7c0 |
| svencoop-8948 | 0x786a9 | 0x786ca | 0xba220 |

这些是静态边界证据,不是实机退出测试。此次没有运行任何游戏或复现/修复挂起。
只有 issue 中的 10257 原始挂起是用户提供的实测,不能推广到其他版本。
10257 的 NET_Sleep(参数)普通 select 分支在参数为零时传 20ms timeout,非零时传 NULL;
超时分支 NET_Sleep_Timeout 使用非 NULL timeval。持续收包的内层循环也可能推迟末尾 Sleep。
所以“存在安全退出边界”没有证明退出请求一定及时到达;消费者仍需验证唤醒/饥饿/等待可达性。

## Linux 审查与排除原因

四个 ELF32 输入均审查了实际 NET_StartThread 或错误文案引用,不生成本次 Windows finder 的 Linux 产物。

| 快照 | 代码证据 | 结果 |
| --- | --- | --- |
| hl-8684 Linux | NET_StartThread RVA 0x1680d0 仅检查 use_thread 并置 initialized=true | 经典错误 anchor 不存在;无对应网络 CreateThread callback/DWORD 输出模型 |
| hl-10210 Linux | NET_StartThread RVA 0x10c1e0 同上 | 不发布 Windows 线程 identity |
| svencoop-8948 Linux | NET_StartThread RVA 0x134720;pthread_create call 0x134774,callback 0x1344b0 | netThreadId = pthread_create 返回错误码;pthread_t 输出到另一 netThread 存储 |
| svencoop-10257 Linux | 错误文案 0x267c2c;独立 start 0xe7ac0;pthread_create call 0xe7b14,callback 0xe7850 | 返回错误码保存于 0x14ba59c,pthread_t 输出到 0x14ba5a0;不冒充 dwNetThreadId |

Sven Linux 的两个函数确实存在,但 pthread ABI、mutex 和错误码变量语义需独立 finder/交付,
本次没有承诺 Linux 函数产出。Linux 原始 SHA-256:

- hl-8684: `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1`
- hl-10210: `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78`
- svencoop-8948: `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e`
- svencoop-10257: `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd`

## 输入身份 / 来源 / 会话

源码语义依据为 issue 提供的 DiligentGraphics net_ws.cpp 片段和本地
`/home/hztest2/HLND2T_official/engine/net_ws.c`:dwNetThreadId 1070、NET_ThreadFunc 1162、
末尾 Sys_Sleep 1215、NET_StartThread 1222、CreateThread 1235、失败清理 1236–1243。
本地源码是不同参考修订,没有 DiligentGraphics 的逐字节一致性假设。

以下 SHA-256 为 MCP survey/IDA input identity 与实际文件相符的分析镜像;
BLOB 行是解密 PE,正式 snapshot/catalog 另记录原始 hw.dll 的 BLOB binary identity。

| 分析快照 | SHA-256 |
| --- | --- |
| cof-5936 | `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875` |
| hl-10210 | `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295` |
| hl-3248 | `7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0` |
| hl-3266 | `d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21` |
| hl-3329 | `4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480` |
| hl-3647 | `7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110` |
| hl-4554 | `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3` |
| hl-6153 | `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257` |
| hl-8684 | `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10` |
| svencoop-10257 | `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596` |
| svencoop-8948 | `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8` |

交互证据遵循 [[idalib-mcp]]:首先 idb_list(初始 sessions=[]),然后对确切镜像 idb_open。
没有借用外部 session;每个自己打开的 session 最终 idb_close(save=True) 返回 success=true/saved=true。
对应数据库是 `bin/<tag>/engine/<分析镜像>.i64`;Sven 最终证据审查后 mtime 为
10257 2026-10-06 17:51:20 +08:00、8948 17:51:25 +08:00。
生产 analyzer 使用独立 restored_strict/no-save worker,验证完成后退出并释放 MCP 端口;
交互数据库不进入提交。没有 LLM 或 Agent fallback 参与成功产出。

## 验证方式与适用范围

- 有行为影响的新 finder 使用定向 TDD:TEST/MOV/JNZ、handle memory compare、跳过清理、
  跳过初始化赋值和 inline 宿主 WORD store 的反例先失败再修复;八个合成行为测试不约束配置/产物文本。
- 最终用 schema-1 batch selection 选择 11 个 `engine:windows:find-NET_StartThread-symbols` 节点,
  强制重建全部现有输出:Successful=11,Failed=0,Skipped=0。
  32 份产物 SHA-256 与首次生成一致,实际签名和解析字段均由 analyzer 验证。
- 普通 `-skill` 会跳过已有完整输出;强制复核使用 `-batch_selection`,而不是非法的 `-force_all -skill`。
- 在临时目录为每个 tag 使用 schema-8 `build_candidate_snapshot`/`guard_candidate`,
  再经 SnapshotSymbolStore.require 核验新 identity,生成并 guard 内容寻址的 catalog JSON。
  Snapshot、metadata 和 JSON 属于派生验证产物,发布由已有 release 流程负责。
- `uv run python tests/run_test_suite.py all -b --durations 30`:1418 tests,exit 0,13 skips。
  skips 为七个 Windows 平台门禁、两个 opt-in notes CLI、三个无 Redis 服务的集成类、一个 opt-in IDA 测试。
  本次商业 IDA 证据由上述 11 个真实分析任务提供,不使用 skipped 测试作为证明。
- `uv run python format_repo_files.py --check`:exit 0;680 Python、29 YAML checked。

适用范围仅为上述已绑定哈希的 Windows/BLOB 快照及正式 config 注册。新镜像应重新生成符号,
并独立核验消费者使用的退出边界;catalog 覆盖不能代替实机 hook/死锁修复验收。
