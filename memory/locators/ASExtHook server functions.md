---
title: ASExtHook server functions
type: note
permalink: goldsrc-vibesignatures/locators/asexthook-server-functions
---

# ASExtHook server functions — Issue #395

## 范围与定位证据

2026-10-22，逐 binary 核对 Sven Co-op 5.15 (`svencoop-8948`) / 5.16 (`svencoop-10257`) 的 PE32/I386 与 ELF32/I386 server。全部使用 Issue 请求的稳定 alias，输出普通 `function` records；consumer manifest 无需映射变更。

- 旧 consumer 基线：[628c28c](https://github.com/hzqst/asexthook/tree/628c28c)。
- 当前 consumer manifest：[825222f0](https://github.com/hzqst/asexthook/blob/825222f0ad62fd68e1382758f12afd3d95a8b22e/scripts/manifests/asexthook.json)。
- 同步及运行时契约：[metamod d9df0311](https://github.com/metamod-svencoop/metamod/tree/d9df03115c0f561ba2a50d8323910df8c14efa2f)。
- Linux 8948 保留的 `_ZN...` 方法符号和 `_ZTV...` 虚表提供实现名；Linux 10257 已剥离这些方法名，通过当前 RTTI、相同槽位、参数访问和函数行为逐项核对。Linux binary 未提供可用 `.debug_*` DWARF。
- Windows 通过 RTTI 虚表、实体工厂的构造/虚表引用、目标函数行为及参数/返回清栈指令核对；没有把旧槽号当作未经验证的跨版本事实。
- Grapple 通过 `monster_babycrab`、`monster_stukabat`、`monster_tentacle` 的函数引用交集唯一定位，并核对来自 `CBarnacleGrappleTongue` 虚表方法的调用/回调引用链。旧 Windows 签名在两个版本均唯一命中；旧 Linux 签名仅在 10257 命中，8948 为零命中。生产 finder 不使用这些签名或旧 YAML 定位。

## 实际入口与继承

| consumer alias | 实际实现 | 取址证据 |
| --- | --- | --- |
| `GrappleGetMonsterType` | `CBarnacleGrappleTongue::GetMonsterType(CBaseEntity*)` | classname 分类；小型怪物返回 1，tentacle 返回 4，其余返回 2 |
| `ApacheTraceAttack` | `CApache::TraceAttack` | monster_apache / CApache slot 20 |
| `OspreyTraceAttack` | `COsprey::TraceAttack` | monster_osprey / COsprey slot 20 |
| `TurretTraceAttack` | `CBaseTurret::TraceAttack` | monster_turret / CTurret slot 20 == CBaseTurret slot 20 |
| `BreakableTraceAttack` | `CBreakable::TraceAttack` | func_breakable / CBreakable slot 20 |
| `BreakableTakeDamage` | `CBreakable::TakeDamage` | func_breakable / CBreakable slot 21；10257 Linux 必须保留 0x36f5bc 包装入口，不跳到内部实现 0x36edd8 |
| `BreakableKilled` | `CBaseEntity::Killed` | CBreakable slot 24 == CBaseEntity slot 24 |
| `BaseMonsterTraceAttack` | `CBaseMonster::TraceAttack` | monster_bloater / CBloater slot 20 == CBaseMonster slot 20 |
| `PlayerPostTakeDamage` | `CBasePlayer::TakeDamage` | player / CBasePlayer slot 21；post 为 consumer 回调时机 |
| `PlayerTakeHealth` | `CBasePlayer::TakeHealth` | player slot 22；不同于 CBaseMonster slot 22，内部继续调用基类 |
| `IRelationship` | `CBaseEntity::IRelationship` | player / CBasePlayer slot 17 == CBaseEntity slot 17 |

共享函数上的 detour 会影响使用同一实现入口的其他实体；这些 alias 不意味着实体专用函数。

## x86 ABI

槽位均为 0-based，指针宽 4 字节；Linux `_ZTV` 的首函数指针位于符号地址 +8。以下栈偏移以函数刚进入时的 ESP 为准，+0 为返回地址。

| 原型族 | Windows | Linux |
| --- | --- | --- |
| TraceAttack | ECX=this；+4 attacker，+8 float damage，+0xc/+0x10/+0x14 为 Vector 三个 float，+0x18 trace，+0x1c damageType；`ret 0x1c` | cdecl；+4 this，+8 attacker，+0xc float damage，+0x10 指向 Vector 临时对象，+0x14 trace，+0x18 damageType；`ret` |
| TakeDamage | ECX=this；+4 inflictor，+8 attacker，+0xc float damage，+0x10 damageType；`ret 0x10` | cdecl；+4 this，+8 inflictor，+0xc attacker，+0x10 float damage，+0x14 damageType；`ret` |
| TakeHealth | ECX=this；+4 float health，+8 damageType，+0xc cap；`ret 0xc` | cdecl；+4 this，+8 float health，+0xc damageType，+0x10 cap；`ret` |
| Killed | ECX=this；+4 attacker，+8 gib；`ret 8` | cdecl；+4 this，+8 attacker，+0xc gib；`ret`；本次继承的基类实现未使用后两参数 |
| IRelationship | ECX=this；+4 other，+8 friendly；`ret 8` | cdecl；+4 this，+8 other，+0xc friendly；`ret` |
| Grapple classifier | 调用点设置 ECX=this、push entity；+4 entity；`ret 4`；函数体不使用 this | cdecl；+4 this，+8 entity；`ret` |

`TakeDamage`、`TakeHealth`、`IRelationship` 和 Grapple 返回 int（EAX）。`TraceAttack`、`Killed` 为 void；反编译器推测出的残留 EAX/AX 返回值不是返回类型证据。friendly 只使用 bool 的低字节，栈参数占一个 4 字节槽。

8948 ELF 的 TraceAttack mangled name 为 `...EP9entvars_sf6VectorP11TraceResulti`，明确为源级按值 `Vector`。实际机器指令通过指针访问方向，Windows 则内联传递三个 float。consumer 必须分别使用匹配两平台 ABI 的 Vector 类型/适配层，不能仅凭 `vec3_t` 或裸指针原型断言源级 ABI 相同。

## Binary identity

完整快照携带 SHA256、MD5、CRC32、CRC64、size 和 isBlob。metamod 当前运行时使用 **CRC64/XZ** 选择模块记录；下载快照使用 SHA256 校验。consumer 同步脚本裁剪后按契约仅保留 runtime CRC64。

| binary | SHA256 | CRC64/XZ | size |
| --- | --- | --- | --- |
| svencoop-8948/windows | `61c5955cc3bcb1d4a23f8d65b5c19dd042c026e776ded937439bcdcd21973849` | `8f298238cd79d41b` | 5941248 |
| svencoop-8948/linux | `18ba7ee4e7ccd109dd43172446f463d9a12d9154dfa1f1230cb8345aadd43643` | `e74c6ca22b6a46d0` | 11148956 |
| svencoop-10257/windows | `f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0` | `5d7b59ae83608095` | 5533184 |
| svencoop-10257/linux | `7a980bbd4b03f7380092e45d0a7515085ffb5142e62589d87e2596e90d89d2ca` | `d45a52e4977c4341` | 11745592 |

## 已验证地址

下表为 `func_rva / func_size`（十六进制），Windows image base 为 `0x10000000`，Linux 为 `0`。

| alias | 8948 Windows | 8948 Linux | 10257 Windows | 10257 Linux |
| --- | --- | --- | --- | --- |
| `GrappleGetMonsterType` | `0xfd2e0 / 0x14a` | `0x36003e / 0x163` | `0xf6970 / 0x14a` | `0x2d8aca / 0x16e` |
| `ApacheTraceAttack` | `0xf5de0 / 0x88` | `0x353956 / 0xd0` | `0xef4f0 / 0x88` | `0x2caef4 / 0xbe` |
| `OspreyTraceAttack` | `0x1f65b0 / 0xdc` | `0x4dbca6 / 0x113` | `0x212350 / 0xd8` | `0x47e4a0 / 0xfe` |
| `TurretTraceAttack` | `0x28c170 / 0x27a` | `0x58c5a8 / 0x2d7` | `0x296ab0 / 0x238` | `0x53f122 / 0x2ff` |
| `BreakableTraceAttack` | `0x14de00 / 0x257` | `0x3dd4b0 / 0x2be` | `0x1526e0 / 0x268` | `0x36ea68 / 0x370` |
| `BreakableTakeDamage` | `0x14d8d0 / 0x52c` | `0x3dd76e / 0x64f` | `0x152190 / 0x548` | `0x36f5bc / 0x32` |
| `BreakableKilled` | `0x104a80 / 0x24` | `0x380fda / 0x35` | `0xfe130 / 0x24` | `0x2fac12 / 0x37` |
| `BaseMonsterTraceAttack` | `0x125f60 / 0x1bb` | `0x3a7da2 / 0x29a` | `0x11fec0 / 0x1be` | `0x32729e / 0x2e6` |
| `PlayerPostTakeDamage` | `0x213380 / 0x656` | `0x4f7280 / 0x9fc` | `0x1fb030 / 0x661` | `0x49aac2 / 0xd6b` |
| `PlayerTakeHealth` | `0x213160 / 0x79` | `0x4fde16 / 0xc7` | `0x1fada0 / 0x79` | `0x4a4da4 / 0xd6` |
| `IRelationship` | `0x1c0360 / 0x8a` | `0x469f30 / 0x9e` | `0x1c89a0 / 0x85` | `0x405fdc / 0x9c` |

## 验证与交付边界

- 新 finder 已连接四份真实 IDA 数据库，逐项验证 x86、可执行函数起点、非零大小、四组继承关系、Player TakeHealth override、返回清栈以及 Grapple 归属链，并生成 44 条产物。
- 44 条记录通过仓库的 runtime artifact 字段/地址校验；另在四份原始 binary 的 `.text` 中独立扫描，每条签名均唯一命中对应 RVA。
- 两个配置的完整 canonical artifact inventory 通过检查，分别为 1773 / 1767 条；生成 schema-8 完整候选 YAML、metadata 与 schema-5 JSON dataset。
- 使用上述固定版本的 consumer manifest 与原版 `sync-gamedata.py`，通过仅监听本机的 HTTPS 服务下载两个候选快照，验证 SHA256、裁剪与 `--validate-only` manifest coverage；每个版本保留 22 条 function records，四个 CRC64 与完整快照一致。
- 本地候选目录位于 `/tmp/gsvibe-395/`；它们不是已发布的线上快照，不应把本地下载验收解释为正式站点发布完成。
- 未运行测试套件、工程构建或真实 Sven server detour 冒烟；运行时按 CRC64 查表及 base+RVA 的路径已对照 metamod 源码，实际服务器验收仍需部署后执行。
- 正式发布遵循 `trigger-release-build`：变更与产物须先合并 origin/main，再指定新 release version 和 rebuild/tracked 模式。
