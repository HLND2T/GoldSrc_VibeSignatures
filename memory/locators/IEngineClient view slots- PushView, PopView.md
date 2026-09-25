---
title: 'IEngineClient view slots: PushView, PopView'
type: note
permalink: goldsrc-vibesignatures/locators/iengineclient-view-slots
tags:
  - locator
  - client
  - vfunc
  - issue-245
---

# IEngineClient view slots

Covers `IEngineClient_PushView` and `IEngineClient_PopView` (slot-only `vfunc` artifacts). Producer:
`ida_preprocessor_scripts/find-IEngineClient-view-slots.py`.

## Symbol

- Real symbols: `CEngineClient::PushView(RenderTarget*, bool, bool)` and `CEngineClient::PopView()`
  (`_ZN13CEngineClient8PushViewEP12RenderTargetbb`, `_ZN13CEngineClient7PopViewEv`, from the retained `.symtab` of
  `bin/svencoop-8948/engine/hw.so`). The interface is `IEngineClient`; `PushView` carries the argument list, so the
  artifact identity is `IEngineClient::PushView` / `IEngineClient::PopView`.
- **Module: client.** The engine module only *implements* `IEngineClient`; both callers that carry the anchor live in
  `client.dll` / `client.so`. Analysing the engine module would open the `hw.*` IDB, where the client bodies do not
  exist.

## Availability

| Slot | svencoop-8948 W | svencoop-8948 L | svencoop-10257 W | svencoop-10257 L |
| --- | --- | --- | --- | --- |
| `PushView` | `0x24` / 9 | `0x28` / 10 | `0x2c` / 11 | `0x30` / 12 |
| `PopView` | `0x28` / 10 | `0x2c` / 11 | `0x30` / 12 | `0x34` / 13 |

- Declared in both configs, both platforms, as `category: vfunc`.
- Slot-only output: `func_name` + `vtable_name` + `vfunc_offset` + `vfunc_index`, no `func_va` and no signature —
  the same contract as `IEngineSurface_drawFlushText`.

## Predecessors

- `ClientPortalManager_RenderPortals` and `ClientPortalManager_DrawPortals` (both `expected_input`).

## How it is located

The slots are read out of the two already-covered client callers rather than from the engine implementation class:

1. Accept only real C++ virtual calls: `call [V+disp]` where `V` was defined by `mov V, [O]` with a **zero**
   displacement and `O` is not `esp`. This rejects the `gEngfuncs` tables (loaded through a non-zero displacement)
   and the GCC PIC GOT-relative indirect calls.
2. `DrawPortals` must carry exactly one such call — the trailing `g_pEngineClient->PopView()` — giving the `PopView`
   offset `P`.
3. `RenderPortals` must carry exactly three, at exactly `P-4`, `P` and `P+4` (one site each): `PushView`,
   `RenderView`, `PopView`. Any other count or spacing fails closed. `RenderView` is used as the ordering witness and
   is not emitted.
4. Both artifacts are written with the absolute per-build offset; no index is reused across builds.

Independent cross-checks (not consumed by the finder): the engine `CEngineClient` vtable located through RTTI on all
four engine builds — 8948 W `0x1E5AE6C`, 8948 L `0x32D65C`, 10257 W `0x1E61E94`, 10257 L `0x2E1D9C` — agrees with
every slot above, and the 8948 Linux symbol table names slots 10/11/12 directly.

## Pitfalls

- **A single hardcoded index is wrong by design.** The interface gained two slots between the `SCEngineClient001` and
  `SCEngineClient002` revisions, and MSVC emits one deleting-destructor slot fewer than the Itanium ABI: Windows
  `PushView` is slot 9 on 8948 but 11 on 10257, and Linux is always one slot higher than its Windows peer.
- Do not anchor on `call dword ptr [reg+0Ch]` / `[reg+8]` style sites: those are `gEngfuncs` table dispatches, and
  the `gEngfuncs` slots are loaded through a non-zero displacement, which is exactly what the zero-displacement
  requirement excludes.
- 8948 Windows `PopView` is a thunk (`0x1d5e000` → `0x1d5e9b0`); the finder deliberately records the slot, not the
  body, so the thunk does not matter.
- The engine-side implementation functions are *not* the requested symbols and are out of scope here.

## Relations

- relates_to [[ClientPortalManager_DrawPortals]]
- relates_to [[ClientPortalManager_RenderPortals]]
