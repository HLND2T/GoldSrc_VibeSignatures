---
title: CGame_AppActivate locator
type: note
permalink: goldsrc-vibesignatures/locators/cgame-app-activate-locator
tags:
- locator
- engine
- func
---

# CGame_AppActivate

## Symbol

- **Name**: `CGame_AppActivate`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CGame_AppActivate.py`

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Windows on all 11; Linux on hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Not applicable to cstrike/czero/czeror because those configs declare no engine module.
- The symbol is `CGame::AppActivate(bool)` from `engine/sys_mainwind.cpp` (Windows) and
  `engine/sys_sdlwind.cpp` (Linux). The legacy `AppActivate(BOOL fActive, BOOL minimize)` in
  `engine/vid_win.c` / `engine/gl_vidnt.c` is a **different** function that prints neither
  literal — never conflate the two.

## Predecessors

- None. `find-CGame_AppActivate` has no `expected_input`.

## How it is located

1. Both branch diagnostics are required as exact anchors: `AppActive: active\n` and
   `AppActive: not active\n`. Each must occur exactly once and have at least one code
   reference; an early PE IDB without push-immediate xrefs falls back to an operand scan.
2. Every anchor site must land in one containing function.
3. Inside that function, the anchor's **control-flow root** is recovered by walking the
   FlowChart predecessor closure to the unique root block. This root — not IDA's containing
   function start — is the method entry.
4. When the root differs from the containing function start, the merged owner is split
   (see Pitfalls). Otherwise the root is used as-is.
5. `_inspect_function_via_mcp` then emits `func_name / func_sig / func_va / func_rva / func_size`.
   Generated signatures are output validation only and never participate in discovery.

## Verified results

| Build | Platform | `func_va` | `func_size` | Shape |
| --- | --- | --- | --- | --- |
| hl-3248 | windows | `0x1dbe030` | `0x111` | merged owner `0x1dbe000` split |
| hl-3266 | windows | `0x1dbe030` | `0x111` | merged owner `0x1dbe000` split |
| hl-3329 | windows | `0x1dbd780` | `0x111` | merged owner `0x1dbd750` split |
| hl-3647 | windows | `0x1dbc900` | `0x111` | merged owner `0x1dbc8d0` split |
| hl-4554 | windows | `0x1dc8790` | `0x111` | merged owner `0x1dc8760` split |
| hl-6153 | windows | `0x1dae730` | `0x136` | already a clean function |
| hl-8684 | windows | `0x1db0960` | `0x136` | already a clean function |
| hl-8684 | linux | `0x205650` | `0x197` | base symbol chosen over `.constprop.4` clone |
| hl-10210 | windows | `0x102231c0` | `0x13e` | already a clean function |
| hl-10210 | linux | `0x1b5ac0` | `0x197` | already a clean function |
| svencoop-8948 | windows | `0x1dbed80` | `0xe0` | already a clean function |
| svencoop-8948 | linux | `0x1d0430` | `0x162` | already a clean function |
| svencoop-10257 | windows | `0x1dc0390` | `0xe0` | already a clean function |
| svencoop-10257 | linux | `0x184520` | `0x162` | already a clean function |
| cof-5936 | windows | `0x1df897f` | `0x132` | already a clean function |

Treat these as regression evidence for those exact inputs, never as a locator for another build.

## Pitfalls

- **A plain `xref_strings` finder does not work on five builds.** On hl-3248/3266/3329/3647
  and hl-4554, IDA merges the whole `CGame` static constructor/destructor cluster with the
  method into one oversized function (`0x87a`–`0x89a` bytes) whose *start* is an `atexit`
  registration thunk (`mov ecx, <object>; jmp <ctor>`). `preprocess_common_skill` would happily
  return that start: the emitted `func_va` points at the thunk, `func_size` is ~7x too large,
  and the ten-byte `B9 ?? ?? ?? ?? E9 ?? ?? ?? ??` signature is not even unique. The artifact
  passes schema validation while being wrong, so the failure is silent — this is why the
  finder recovers the control-flow root instead.
- The split truncates the merged owner at the recovered entry (`set_func_end`), defines the
  method with its exact component span, then re-plans the remainder. It is guarded: the entry
  must be interior to the owner, the component span must be contiguous and ≤ `0x4000` bytes,
  stay in one executable segment, and be reached by a direct `call` from outside itself. Any
  failed guard fails closed rather than mutating the IDB.
- **hl-8684 Linux ships two bodies.** `_ZN5CGame11AppActivateEb` (`0x205650`) and
  `_ZN5CGame11AppActivateEb.constprop.4` (`0x204d10`) are both `0x197` bytes and both
  reference the literals. The clone takes `fActive` in a register (`mov bl, al`) instead of
  on the stack, so only the base symbol has the declared ABI; the finder drops a suffixed
  clone only when exactly one non-clone shares its base name. The clone's only callers are
  inside `CGame::SleepUntilInput`.
- The literals are byte-exact including the trailing newline. `FULLMATCH`-style equality is
  required; a substring match would also hit the other branch's string.

## Relations

- produces context for [[host_initialized locator]]
