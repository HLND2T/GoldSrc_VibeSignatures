---
title: Engine private physics and clipping symbols — Issue 350 Part A
type: note
permalink: goldsrc-vibesignatures/memory/engine/engine-private-physics-and-clipping-symbols-issue-350-part-a
tags:
- engine
- physics
- abi
- issue-350
---

# Scope and evidence

Issue #350 Part A adds engine function locators and artifacts only. No fallguys hooks or Part B global locators are implemented. Evidence comes from PE32/ELF32 IDA disassembly, Hex-Rays argument flow, current-binary string ownership and validated call sites. Source signatures are reference clues, not locators.

## Coverage

Module: engine. All outputs below are category `func`, actual function entries, not call-site or layout artifacts. Supported Windows tags: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257. Supported Linux tags: hl-8684, hl-10210, svencoop-8948, svencoop-10257. The four oldest Windows builds use the restored hw.decrypt.dll image. Tags without an engine module and config-absent Linux modules are not applicable.

| Function identity | Coverage | Locator / ABI evidence |
| --- | --- | --- |
| SV_Physics | All 15 binaries | Unique owned `SV_Physics: %s bad movetype %d` string; void(void). |
| SV_PushRotate | All 15 | Owned `Out of edicts in simulator!` fatal diagnostic and Sys_Error call; edict pointer and float movetime. SvEngine PIC references require folding the actual Sys_Error format argument. |
| SV_PushMove | All 15 | MOVETYPE_PUSH branch in SV_Physics, via SV_Physics_Pusher when not inlined; edict pointer and float movetime. |
| SV_PushEntity | All 15 | SV_PushRotate's displaced entity push with pusher solidity temporarily disabled; source return is trace by value, with an x86 hidden return buffer. It is not a trace-pointer source API. |
| SV_WriteMovevarsToClient | All 15 | SV_SendServerinfo callee that serializes svc_newmovevars (44), float fields and sky name; sizebuf pointer. Existing SV_SendServerinfo references reused. |
| SV_ClipToLinks | All 15 | Owned `Trigger in clipping list` fatal diagnostic, recursive area-tree traversal and clipping call arguments. |
| SV_ClipMoveToEntity | All 15 | Classic Windows clipping callee; on Linux and SvEngine Windows recover retained wrapper by inverse callers of validated SingleClip entry/implementation and argument forwarding. Source trace return by value; source args ent,start,mins,maxs,end, plus passedict in SvEngine 10257. |
| SV_SingleClipMoveToEntity | 12 binaries | Six source arguments ent,start,mins,maxs,end,trace output. Excludes hl-10210 Windows and both svencoop-10257 platforms. |
| SV_SingleClipMoveToEntity_10152 | svencoop-10257 Windows/Linux | Seven source arguments; last passedict flows from moveclip_t.passedict into hull clipping. Config/file identity carries ABI suffix; payload func_name is the actual source function name SV_SingleClipMoveToEntity. |
| SV_Physics_Pusher | 12 binaries, helper artifact | Standalone helper on classic Windows/CoF and all Linux platforms. Selected Windows HL25/SvEngine physics dispatchers inline its logic and locate PushMove directly. A dead retained pusher copy may exist; these locators do not claim its absence or emit it. |

## Clipping ABI and availability

The 10152 ABI boundary is SvEngine-specific. HL25 build 10210 still uses the six-argument SingleClip ABI on Linux. Never select the seven-argument ABI from a numerically larger HL build alone.

HL25 Linux has a compiler split: the clipping call goes to SV_SingleClipMoveToEntity.part.0 at 0x105d10, whose first three arguments use eax/edx/ecx. The public six-stack-argument cdecl entry at 0x1063b0 guards null arguments and forwards all six unchanged. The finder validates this relationship and emits 0x1063b0. The retained trace-return wrapper is at 0x106410.

HL25 Windows has SingleClip logic inlined into SV_ClipMoveToEntity at 0x10235b80. Its caller SV_ClipToLinks is at 0x10236210. The body and hull-clipping callers were inspected; no independent six-argument SingleClip entry was established. Config intentionally omits its Windows SingleClip symbol rather than labeling the six-machine-slot hidden-return-buffer wrapper as SingleClip.

SvEngine 8948: Linux SingleClip 0x12d450, wrapper 0x12db70, ClipToLinks 0x12dbc0; Windows SingleClip 0x1dd19b0, wrapper 0x1dd0020, ClipToLinks 0x1dd1f40. Six SingleClip arguments; wrapper has a hidden return pointer followed by five visible source arguments.

SvEngine 10257: Linux SingleClip 0xdf1f0, wrapper 0xe0220, ClipToLinks 0xe0270; Windows SingleClip 0x1dd3350, wrapper 0x1dd1940, ClipToLinks 0x1dd39f0. Seven SingleClip arguments; wrapper has a hidden return pointer followed by six source arguments, including passedict. The wrapper forwards passedict unchanged; TraceModel supplies NULL at its own call site. Do not require NULL inside the wrapper.

The clipping trace initialization/copies use 56 bytes: allsolid@0, startsolid@4, inopen@8, inwater@12, fraction@16, endpos@20, plane.normal@32, plane.dist@44, ent@48, hitgroup@52. Wrapper return storage can be written directly or through a local trace copy. Linux GCC hidden return slots can use `retn 4`; IDA's inferred stdcall/userpurge label is not the source API. No edict layout is assumed portable across builds or platforms. Annotated reference types contain only binary-verified fields/padding; these do not create Part B layout artifacts.

## Reuse and exclusions

Existing build_number and movevars artifacts cover all 15 engine binaries. fallguys `pmovevars` consumes the existing engine `movevars` identity, the same storage written by SV_WriteMovevarsToClient; no duplicate pmovevars artifact is added. Part B globals and their layout/offset artifacts remain outside this delivery.

## Reusable lesson

Trigger: a clipping callee has a plausible six/seven argument count or a trace-return wrapper was inlined. Constraint: hidden structure-return slots and compiler-created register-argument bodies can mimic the requested source ABI. Correct approach: distinguish source output-parameter API from structure return, validate every forwarded argument, normalize compiler implementations to public callable entries, and retain platform-specific absence. Verification: current-binary instruction/call argument evidence, unique-signature artifact validation, all production-platform finder DAG execution and repository contract checks. Scope: 32-bit GoldSrc/HL25/SvEngine private function locators.

Classic Windows wrapper→Single evidence: hl-3248/3266 0x1dce890→0x1dce400; hl-3329 0x1dce010→0x1dcdb80; hl-3647 0x1dcd180→0x1dcccf0; hl-4554 0x1dde020→0x1dddb90; hl-6153 0x1dc4f30→0x1dc4b30; hl-8684 0x1dc7280→0x1dc6e80; cof-5936 0x1e1104d→0x1e10b3e. Each standalone Single has its wrapper as its sole caller in these binaries. Call instruction counts are obtained from disassembly, not duplicated conditional calls rendered by Hex-Rays.
