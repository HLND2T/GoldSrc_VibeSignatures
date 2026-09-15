---
title: cl_parsefuncs locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-parsefuncs
tags:
  - locator
  - engine
  - gv
---

# cl_parsefuncs

## Symbol

- **Name**: `cl_parsefuncs`
- **Category**: `gv` (static table in mapped data)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-cl_parsefuncs.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-10257, cof-5936.
- Platforms: Windows + Linux. Not applicable to cstrike/czero/czeror (no engine module in this repo).
- Never inlined: it is a static `svc_func_t[]` in every build. The *access encoding* differs — absolute operand on Windows, GOT-relative on SvEngine Linux.

## Predecessors

- None. `find-cl_parsefuncs` has no `expected_input`.
- `CL_ParseServerMessage` is resolved *inside* this same finder to supply `gv_sig`; it is not a separate predecessor artifact.

## How it is located

1. Find the unique `FULLMATCH:svc_bad` C string. It is unique in every current engine binary and lives inside the table, never in a function body.
2. Scan non-executable segments for dwords pointing at that string. Each slot sits at entry offset `+4` (`pszname`); back up 4 bytes to obtain the table base.
3. Validate the 12-byte table prefix: opcodes `0/1/2/3`, names `svc_bad`/`svc_nop`/`svc_disconnect`, first two `pfnParse` NULL, third `pfnParse` executable; then walk entries until opcode `0xFF` / `"End of List"`.
4. Require exactly one surviving table.
5. `gv_sig` is taken from the owning function of `FULLMATCH:CL_ParseServerMessage: Illegible server message - %s\n`.
6. Anchor instruction = the instruction inside that owner which encodes `table+4` (preferred) or `table+8`; compilers never encode the table base. Fallbacks: scan executable segments for the encoded dword, then `XrefsTo(table+4/+8)` (SvEngine Linux PIC).
7. Emit `gv_va` = table base. Runtime resolution uses `gv_inst_offset/length/disp` plus `gv_pic_addend` when present.

## Pitfalls

- Compilers never encode the table *base*; `+4`/`+8` member addresses are the only encoded operands. An LLM `found_gv` would return the wrong address — do not use LLM discovery here.
- SvEngine Linux is PIC: `mov reg, [ebx+eax*4+disp]` with a GOT-relative displacement. Fall back to `XrefsTo(table+4)` instead of scanning for an absolute VA.
- Discovery must not use a byte signature or old YAML. MetaHook's `.data` byte-pattern scan is a hint only.
- Preserve `gv_pic_addend`: the embedded dword is not always the absolute VA (same PIC contract as the player-model GVs).
