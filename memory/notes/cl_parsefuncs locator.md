---
title: cl_parsefuncs locator
type: note
permalink: goldsrc-vibesignatures/notes/cl-parsefuncs-locator
tags:
- cl_parsefuncs
- svc_func_t
- gv-finder
- svc_bad
---

# cl_parsefuncs locator

## Trigger
Need the client SVC parse table (`svc_func_t cl_parsefuncs[]`) in `hw.dll` / `hw.so`.

## Facts
- Official source: `engine/cl_parse.c` defines `svc_func_t { unsigned char opcode; char *pszname; void (*pfnParse)(void); }` and `static svc_func_t cl_parsefuncs[]` starting with `{ svc_bad, "svc_bad", NULL }`.
- Compiled x86 layout is 12 bytes per entry (opcode stored as a 4-byte slot, then pszname, then pfnParse). Terminator is opcode `0xFF` / `"End of List"`.
- `FULLMATCH:svc_bad` is unique in every current engine binary. It lives in the table, not in a function; code xrefs to the string are empty or incidental.
- Compilers never encode the table *base* as a 32-bit immediate. Accesses use `cl_parsefuncs+4` (pszname) or `+8` (pfnParse). LLM `found_gv` would emit the wrong address.
- MetaHook scans `.data` for a byte pattern then checks `"svc_bad"`. That pattern is a hint only; the robust locator is the unique string pointer plus prefix validation (`opcode 0/1/2/3`, `svc_nop`, `svc_disconnect`, first two pfn NULL, third pfn executable).
- `FULLMATCH:CL_ParseServerMessage: Illegible server message - %s\n` uniquely identifies `CL_ParseServerMessage` and is used only for the owning-function `gv_sig`.
- SvEngine Linux is PIC: `mov reg, [ebx+eax*4+disp]` where disp is GOT-relative. Fall back to `XrefsTo(table+4)` instead of scanning for the absolute VA.

## Correct approach
1. Find the unique `svc_bad` C string.
2. Scan non-executable data for the unique dword pointing at it at entry offset +4.
3. Validate the 12-byte prefix and `End of List` terminator.
4. Emit `gv_va` = table base. Build `gv_sig` from `CL_ParseServerMessage`.
5. Do not use LLM, old YAML, or a byte signature as discovery.

## Verification
`-allgamever -modules engine -skill find-cl_parsefuncs -platform windows,linux`: all engine gamevers succeed (cstrike has no engine module).

## Scope
All engine configs (`hl-*`, `cof-5936`, `svencoop-10257`). Not cstrike.
