---
title: engine locator
type: note
permalink: goldsrc-vibesignatures/locators/engine
tags:
  - locator
  - engine
  - gv
---

# eng

## Symbol

- **Name**: `eng` (the engine module's `IEngine*` slot; exact ELF/DWARF identity)
- **Former artifact identity**: `engine` (renamed in issue #303; the module remains `engine`)
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-RunListenServer.py`
- **Outputs**: `RunListenServer.{platform}.yaml` (`func`) and `eng.{platform}.yaml` (`gv`), sharing the same discovery and inspected function.

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- The 15 configured platform pairs comprise 11 Windows binaries and Linux for hl-8684,
  hl-10210, svencoop-8948 and svencoop-10257. The four old BLOB versions use hw.decrypt.dll.
- Platforms: Windows + Linux.
- Inlined / absent: the slot itself always exists. Note it is *not* an inline case but a
  data slot whose neighbours get inlined away — see the `Sys_InitArgv` pitfall.

## Predecessors

- None. `expected_input` is empty; the anchor is a target-owned literal.

## How it is located

1. Find the exact literal `"Sys_InitArgv( OrigCmd )"` (owned by `RunListenServer`,
   `engine/sys_dll2.cpp`) and require exactly one function owner.
2. Locate the string-reference instruction in that body: an absolute dword operand, or a PIC
   `lea reg, [ebx+disp32]` resolved against the owner's ebx GOT anchor.
3. Within the next `TRACEINIT_WINDOW = 6` instructions find the first `call` — that is the
   `TraceInit` call.
4. Starting after the `TraceInit` instruction, scan up to `SCAN_WINDOW = 60` instructions for
   the first `mov reg, [abs]` (or PIC `lea reg, [ebx+disp32]`) whose target is writable data
   and whose **static dword value** is non-zero and points at writable data. The loaded
   register must be dereferenced within the next `DEREF_WINDOW = 6` instructions by a
   `mov r, [reg+disp]`.
5. That slot is `eng` (the code immediately runs `eng->SetQuitting(QUIT_NOTQUITTING)`).
6. Emit the GV with `gv_va` = the slot, `gv_sig` = `RunListenServer`'s `func_sig`,
   `gv_inst_offset/length/disp` from the load, plus `gv_resolution_fields_via_mcp` (which
   carries `gv_pic_addend` for PIC sites).

## Pitfalls

- Inlined `Sys_InitArgv` (hl-10210 hw.so) loads `com_argc`/`com_argv` *before* `eng`. Those
  slots are zero in the static image, so the non-zero-static-pointer requirement rejects
  them — do not relax it.
- hl-10210 / svencoop Windows place the `CEngine` object 8 bytes after the slot; adjacency is
  normal and must not be treated as a mismatch.
- The vtable index confirms the role: `SetQuitting` is vtable `+0x40` on Windows, `+0x44` on
  Linux.
- Discovery never uses a byte signature or a prior artifact signature; the `gv_sig` prologue
  signature is generated only after the locator validates the current-binary instruction.

## Issue #303 consolidation

- Trigger: `engine` was a MetaHook-side field name; the ELF/DWARF global is `eng`.
- Constraint: module identity remains `engine`; only the symbol/artifact identity changes.
- Approach: merge the old global finder into `find-RunListenServer.py`, discover the owner once, and emit both the function and the global using the same validated signature.
- Verification: the 2026-09-29 all-gamever finder run reported zero failed skills. All 15 new `eng` payloads matched the old `engine` payloads exactly after excluding `gv_name`. `hl-3266` was generated through the user-owned IDA session at port 13337 and then skipped as already present by the batch; that session was neither saved nor closed.
- Scope: all 11 engine configurations / 15 platform pairs; no compatibility alias for the old global name. Existing note permalink is retained for incoming memory links.
