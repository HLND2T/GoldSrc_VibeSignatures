---
title: 'ClientPortalManager shader chain: InitShader, EnableShader, DisableShader'
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-shader-chain
tags:
  - locator
  - client
  - func
  - issue-245
---

# ClientPortalManager shader chain

Covers `ClientPortalManager_InitShader`, `ClientPortalManager_EnableShader` and
`ClientPortalManager_DisableShader`. Producer: `ida_preprocessor_scripts/find-ClientPortalManager-shader-chain.py`.
Source roles: create/compile/link (and release) the portal program; select it; deselect it.

## Availability

| Symbol | svencoop-8948 W | svencoop-8948 L | svencoop-10257 W | svencoop-10257 L |
| --- | --- | --- | --- | --- |
| `InitShader` | `0x10095a00` | `0x157a52` | `0x1004d640` | `0xf5b8c` |
| `EnableShader` | inlined | `0x157b88` | inlined | `0xf5cda` |
| `DisableShader` | inlined | `0x157bce` | inlined | inlined |

- `InitShader` is declared on both platforms in both configs. `EnableShader` is declared `platform: linux` in both;
  `DisableShader` is declared `platform: linux` in **svencoop-8948 only** — 10257's GCC splits it into the
  `InitShader` call plus the shared `glUseProgram(0)` reset helper, so no standalone function carries that
  identity and the symbol is not declared there.
- The 8948 and 10257 Linux names come from the retained `.symtab`
  (`_ZN19ClientPortalManager10InitShaderEv`, `…12EnableShaderEv`, `…13DisableShaderEv`).

## Predecessors

- `ClientPortalManager_DrawPortals` (`expected_input` in config).

## How it is located

All three are recovered from the DrawPortals artifact with one deterministic instruction walk; no byte signature
and no LLM step participates.

1. **Reachable set**: direct callees of DrawPortals plus their direct callees (depth 2), resolving ELF PLT stubs to
   their local definitions and dropping `__x86.get_pc_thunk.*` and other ≤8-byte call-transparent helpers.
2. **InitShader** is the unique member of that set whose body materialises both `GL_VERTEX_SHADER` (`0x8B31`) and
   `GL_FRAGMENT_SHADER` (`0x8B30`) — the immediates of its two `glCreateShader` calls. Unique on all four builds
   (`0x10095a00`, `0x157a52`, `0x1004d640`, `0xf5b8c`).
3. **EnableShader / DisableShader** are the members that (a) call `InitShader` first, (b) compare a **byte** member
   under a zero `cmp` whose base register is the same function-entry argument slot, and (c) contain exactly one
   indirect branch — the GLEW `glUseProgram` slot. The one whose final stack-stored argument is the immediate `0`
   is `DisableShader`; the one that reloads a `dword` member through the same entry argument is `EnableShader`.
4. **Cross-check** (fails closed): the flag displacement the wrappers report must appear as a 1-byte store and the
   program displacement as a 4-byte store inside `InitShader` itself. Measured `0x1D4` / `0x1D8` on both Linux
   builds — the offsets are read from the located bodies, never hardcoded. Windows layouts differ (`0x1E0` / `0x1E4`)
   but carry no wrappers, so no offset is ever compared across builds.

## Pitfalls

- **Do not port MetaHookSv's `EnableShader` / `DisableShader` to Windows.** Both are inlined into DrawPortals by
  MSVC, which calls `InitShader` twice and issues `glUseProgram(handle)` / `glUseProgram(0)` inline. The
  bodies the compiler kept out of line (8948 `0x10095B80` / `0x10095BB0`, 10257 `0x1004D7C0` / `0x1004D7F0`)
  are dead code: a full-image scan finds no `E8`/`E9` rel32 call and no 4-byte absolute pointer to them, and IDA
  does not even define them as functions. Hook them and nothing runs.
- 10257 Linux has no standalone `DisableShader`: `0xf5d22` is a zero-reference dead copy, and the live path inlines
  `InitShader` + `0xf4176` (`glUseProgram(0)` only). Emitting `0xf4176` under that name would be wrong — it is
  missing the `InitShader` call.
- `InitShader` is the one hook point that exists on all four builds. It is also what the Core 4.4 audit
  (`memory/research/Sven Co-op client legacy OpenGL patch locations and Core 4.4 audit.md`, section A2) lists for
  taking over the portal shader.
- The `EnableShader` / `DisableShader` signatures necessarily extend past the wrapper body
  (`func_sig_allow_across_function_boundary: true`): the bodies are only `0x46` / `0x44` bytes on 8948 Linux.

## Relations

- relates_to [[ClientPortalManager_DrawPortals]]
- relates_to [[ClientPortalManager_RenderPortals]]
