---
title: Sys_InitMemory locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory
tags:
  - locator
  - engine
  - func
---

# Sys_InitMemory

## Symbol

- **Name**: `Sys_InitMemory`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory.py` (hl-*/cof-*)
  and `ida_preprocessor_scripts/find-Sys_InitMemory-svencoop.py` (svencoop-10257)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210,
  cof-5936 (generic finder); svencoop-10257 (`-svencoop` variant). The two producers are registered on
  disjoint config sets.
- Platforms: Windows + Linux. Both producers branch internally on `platform`; neither is config-gated.
  Linux artifacts exist for hl-8684 (`0x139c90`, `symtab _Z14Sys_InitMemoryv`), hl-10210 and svencoop-10257.
- Inlined / absent: never absent, but the body shape varies — hl-3248/3266/3329/3647/4554 ship a
  *frameless* form (`83 EC 24`, size `0x124`, no EBP frame), while hl-6153/8684 and hl-10210/cof-5936 keep
  a standard `55 8B EC` frame. hl-10210 `hw.so` is unstripped (DWARF `_Z14Sys_InitMemoryv`, `sys_dll2.cpp:538`).

## Predecessors

- None. Neither producer has an `expected_input`; both pass `old_yaml_map=None`.
- `Sys_InitMemory` is the required `expected_input` of `find-Sys_InitMemory_HeapLimitPatches`.

## How it is located

Both producers use the same Pattern A machinery (`preprocess_common_skill` → `preprocess_func_xrefs_via_mcp`):
one `FULLMATCH:` string anchor, `XrefsTo` → owning function via `_ensure_function_owner`, require exactly one
candidate, then a wildcarded prologue signature validated by `_find_unique_bytes`. Emitted fields:
`func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

**Per-family anchors**

| Producer / family | Platform | Anchor |
| --- | --- | --- |
| `find-Sys_InitMemory` (hl-*/cof-*) | windows | `FULLMATCH:Available memory less than 15MB!!! %i\n` |
| `find-Sys_InitMemory` (hl-*/cof-*) | linux | `FULLMATCH:-heapsize` |
| `find-Sys_InitMemory-svencoop` | windows | `FULLMATCH:Available memory less than the %.2f MB requirement (%.2f MB).\nCheck your hardware against the system requirements.\n` |
| `find-Sys_InitMemory-svencoop` | linux | `FULLMATCH:/proc/meminfo` |

Rationale recorded in the scripts: the 15MB wording exists on Windows for every family, and on Linux only in
the HL25-era builds; the older Linux engines (hl-8684) drop it but still parse `-heapsize` inside the same
function. SvEngine Windows reworded the diagnostic, and SvEngine Linux dropped it entirely in favour of
reading `/proc/meminfo`.

## Pitfalls

- **Never assume the 15MB literal exists everywhere.** SvEngine Linux has no memory-shortage string at all
  (`/proc/meminfo` is the only anchor); hl-8684 `hw.so` dropped the 15MB wording but keeps `-heapsize`.
  The two Linux anchors are not interchangeable across families.
- `-heapsize` must stay `FULLMATCH:` — as a substring it would match unrelated help/console text.
- The in-body validation is the **heap-limit immediate family**: SvEngine bodies only carry `0x20000000`
  (512MB) sites; hl-*/cof-* only carry `0x2000000` / `0x2800000` / `0x8000000` (32/40/128MB) sites, and the
  families never mix. cof-5936 contains both `0x2800000` and `0x8000000` even though its build number is
  below 6153 — do not gate `0x8000000` on `buildnum >= 6153`.
- Windows ref site shape is `push offset aAvailableMemor; call Sys_Error; add esp, 8`; the callee matches the
  tracked `Sys_Error` artifact, which is the cross-check that the owner is really `Sys_InitMemory`.
- The frameless hl-3248-family form means any EBP-based prologue heuristic would reject a correct match; the
  finder does not use one.
- The two producers must not both be registered on the same config, or both would write
  `Sys_InitMemory.{platform}.yaml`.
