---
title: Cvar Blob capability matrix
type: note
permalink: goldsrc-vibesignatures/notes/cvar-blob-capability-matrix
tags:
- cvar_hooks
- Cvar_Set
- Cvar_DirectSet
- NLoadBlob
- FreeBlob
- patch
---

# Cvar / Blob capability matrix

Issue #77: missing artifacts must not be read as native unsupported. Status is per gamever / module / platform / binary.

Module is always `engine` (`hw.dll` / `hw.so`). Blob engines `hl-3248`–`hl-3647` are analyzed from decrypted `hw.decrypt.dll` (source blob remains `hw.dll`). cstrike/czero/czeror have no engine module in this repo; they consume the matching `hl-*` engine by CRC64 when the GoldSrc `hw.dll` is shared.

Status key:

- `located`: artifact produced and IDA-verified
- `native_unsupported`: confirmed absent in the binary; no fake symbol
- `n/a`: this repo does not ship that platform/module

## Matrix

| gamever | plat | binary | Cvar_Set | Cvar_DirectSet | cvar_hooks | NLoadBlob | FreeBlob | callsite_0 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hl-3248 | windows | hw.decrypt.dll | located | located | native_unsupported | located | located | located (jmp) |
| hl-3266 | windows | hw.decrypt.dll | located | located | native_unsupported | located | located | located (jmp) |
| hl-3329 | windows | hw.decrypt.dll | located | located | native_unsupported | located | located | located (jmp) |
| hl-3647 | windows | hw.decrypt.dll | located | located | native_unsupported | located | located | located (jmp) |
| hl-4554 | windows | hw.dll | located | located | native_unsupported | located | located | located (call) |
| hl-6153 | windows | hw.dll | located | located | native_unsupported | located | located | located (call) |
| hl-8684 | windows | hw.dll | located | located | located | located | located | native_unsupported (native cvar_hooks) |
| hl-8684 | linux | hw.so | located | located | located | native_unsupported | located | native_unsupported (native cvar_hooks) |
| hl-10210 | windows | hw.dll | located | located | located | located | located | native_unsupported (native cvar_hooks) |
| hl-10210 | linux | hw.so | located | located | located | native_unsupported | located | native_unsupported (native cvar_hooks) |
| svencoop-10257 | windows | hw.dll | located | located | native_unsupported | native_unsupported | native_unsupported | located (call) |
| svencoop-10257 | linux | hw.so | located | located | native_unsupported | native_unsupported | native_unsupported | located (jmp) |
| cof-5936 | windows | hw.dll | located | located | native_unsupported | located | located | located (call) |
| cstrike-* / czero-* / czeror-* | any | (no engine) | n/a | n/a | n/a | n/a | n/a | n/a |

Linux `NLoadBlob` is native unsupported: the `85 BC 32 7A` blob marker is absent from every `hw.so`. Sven Co-op has no blob load/unload (`NLoadBlob` marker absent; no FreeBlob unload fork). `cvar_hooks` exists only on hl-8684 and hl-10210 (HL25 hook list; Linux DWARF name `cvar_hooks` / `Cvar_HookVariable`).

## Patch contract

Name: `Cvar_Set_to_Cvar_DirectSet_callsite_N` with N from 0 in Cvar_Set-body instruction-address order.

Every current binary that needs MetaHook self-managed callbacks has exactly one site (`callsite_0`). Older GoldSrc tail-calls (`jmp Cvar_DirectSet`); later ones `call`.

Fields:

- `patch_va` / `patch_rva`: unique `patch_sig` match start
- `patch_sig_disp`: byte displacement from match start to the CALL/JMP; this finder always starts the signature at the branch, so the value is `0x0`
- no `patch_bytes`: consumer computes `MH_InlinePatchRedirectBranch` at runtime. Do not hook `Cvar_DirectSet` globally.

## MetaHook consumer compatibility

JSON already exports `kind: "patch"` from `patch_name`. Current MetaHook `GameData.cpp` only normalizes `function` and `global`; other kinds are stored as `unsupportedKind`. `validate-gamedata.py` skips unknown kinds and treats missing `cvar_hooks` as requiring `Cvar_Set` + `Cvar_DirectSet` + `Cvar_Set.symbolSize`.

Required MetaHook changes (do not ship fake symbols here):

1. Append `MH_GAMESYMBOL_KIND_PATCH = 3` (ABI-stable append).
2. Parse `patch_rva`, `patch_sig`, `patch_sig_disp` (default 0). Address = `moduleBase + patch_rva + patch_sig_disp` after unique `patch_sig` match, or RVA if the catalog trusts RVA like functions.
3. Query `Cvar_Set_to_Cvar_DirectSet_callsite_0` .. `_N` until `SYMBOL_NOT_FOUND`. Redirect each CALL/JMP with `MH_InlinePatchRedirectBranch` to `MH_Cvar_DirectSet`, then use `g_ManagedCvarCallbackList`.
4. If `cvar_hooks` query succeeds, use the native list and do not apply callsite patches.
5. Distinguish native gap vs analysis gap: this matrix is the native-capability source. `MH_GAMESYMBOL_SYMBOL_NOT_FOUND` for a combination marked `located` here is analysis/catalog failure; `native_unsupported` must not hard-error.
6. Blob TODO is `NLoadBlob` (not `NLoadBlobFile` / `LoadBlobFile`). Sven must not require `NLoadBlob`/`FreeBlob`.

## Finders
- `find-Cvar_Set`: unique `Cvar_Set: variable %s not found\n` owner; printable C-strings of length >= 2; optional `Cvar_DirectSet` call/jmp (including PLT thunk) when multiple owners remain. Small bodies may set `func_sig_allow_across_function_boundary`.
- `find-Cvar_DirectSet`: existing `FULLMATCH:***PROTECTED***`.
- `find-cvar_hooks`: unchanged; hl-8684 / hl-10210 only.
- `find-Cvar_Set_to_Cvar_DirectSet_callsites`: direct `E8`/`E9` in Cvar_Set whose xref resolves to Cvar_DirectSet.
- `find-FreeBlob`: LLM_DECOMPILE from `ClientDLL_Init` (inlined Shutdown). Registered on hl-10210 Windows+Linux and hl-8684 Linux. hl-8684 Linux predecessor body differs (`0xb2d`, inlined LoadInsecureClient); reference is `references/hl-8684/engine/ClientDLL_Init.linux.yaml` rather than the hl-10210 fallback.
- `find-ClientDLL_Shutdown`: unique `ClientDLL_Init` callee that is larger than the FreeBlob wrapper and calls FreeLibrary/dlclose. Old GoldSrc + hl-8684 Windows.
- `find-FreeBlob-legacy`: LLM_DECOMPILE from standalone `ClientDLL_Shutdown`. Reference: `references/hl-6153/engine/ClientDLL_Shutdown.windows.yaml` (public leak comments out FreeBlob; this body keeps the call).
- `find-NLoadBlob`: existing Windows-only xref signatures.
