---
title: GL_BuildLightmaps locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-buildlightmaps
tags:
  - locator
  - engine
  - func
---

# GL_BuildLightmaps

## Symbol

- **Name**: `GL_BuildLightmaps`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_BuildLightmaps.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: present as a standalone entry on every validated branch; only the discovery anchor differs per branch.

## Predecessors

- `R_NewMap.{platform}.yaml` (produced by `find-R_NewMap`, consumed via `expected_input`) — used by the default branch only.

## How it is located

The branch is chosen from the current `(gamever, platform)` tag; unknown tags fall back to the R_NewMap chain. Addresses, byte patterns and call ordinals are never used for discovery — the signature is generated afterwards for validation.

1. `hl-10210/windows`: the UTF-16LE assertion literal `surface->polys->next == NULL` is resolved through the shared `xref_unicode_strings` STRTYPE_C_16 collector; it has exactly one owner, GL_BuildLightmaps.
2. `svencoop-10257/linux`: ASCII `FULLMATCH:AllocBlock: full`, a single-owner literal inside GL_BuildLightmaps' lightmap block allocator.
3. Every other validated branch: LLM_DECOMPILE `found_call` against the annotated reference `references/{gamever}/engine/R_NewMap.{platform}.yaml`; the covered R_NewMap body calls GL_BuildLightmaps directly, so the call (or tail `jmp`) resolves the entry.

Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- Two branches use in-binary literals; the rest depend on the R_NewMap artifact plus its annotated reference YAML. When the analyzed gamever has no reference, `{gamever}` falls back to the canonical reference gamever (hl-10210), so the default chain still resolves for the shared hl/cof family.
- The UTF-16 branch fails closed if the literal is present but no owning function boundary is recoverable (`_unicode_string_candidates` records such hits instead of silently returning zero owners).
- `AllocBlock: full` is SvEngine-only wording — do not expect it on the hl/cof builds, and do not use it as a cross-engine anchor.

### Body guard (post-validation)

Discovery is followed by `_verified_body`, which re-checks the artifact's own
`func_va` against lightmap-rebuilder evidence before the run may report success:

- the surface-name asterisk compare (`cmp ..., 2Ah`, i.e. `if (m->name[0] == '*') continue;`), and
- the lightmap upload texparameter arguments (`0DE1h` plus `2800h`/`2801h` for
  `qglTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER/MAG_FILTER, ...)`).

The second feature alone also matches `R_LoadSkys`; the pair separates
GL_BuildLightmaps from every sibling R_NewMap callee. Rejection deletes the
artifact and fails the node, so a wrong entry can never reach
`find-GL_BuildLightmaps-decompiles` or the artifact comparison.

## Pitfalls

- **A wrong LLM `found_call` is self-consistent and cannot be caught downstream.** Observed on
  hl-3248 (2026-09-25): the model mapped GL_BuildLightmaps to the third R_NewMap call
  (`sub_1DC9E50` = `V_InitLevel`) instead of the fourth (`sub_1D4A830`) — it enumerated the four
  reference/target pairs correctly in its reasoning and then miscounted. The artifact it wrote was
  valid YAML for the wrong function, so only `find-GL_BuildLightmaps-decompiles` (no `GL_Bind` /
  `GL_SelectTexture` in that body) exposed it. The branch is nondeterministic even at
  temperature 0: the same prompt answered correctly in an earlier run of the same day. Treat the
  LLM chain as unverified until the body guard passes.
- **`py_eval` templates must not rely on module-level names inside functions.** MCP `py_eval`
  executes the payload with *separate* global and local namespaces, so a function defined in that
  payload resolves free names against the caller's globals, not against the constants assigned
  above it — a template that reads as valid Python raises `NameError` in the worker. Pass constants
  as function parameters (as `find-CClient_SoundEngine_LoadSoundList-decompiles.py` does) and keep
  the IDA imports function-local. A test harness that execs the template with a single shared
  namespace hides this; mirror `py_eval` with `exec(code, globals_ns, locals_ns)` and the IDA
  modules present in `globals_ns`.
- Two branches use in-binary literals; the rest depend on the R_NewMap artifact plus its annotated reference YAML. When the analyzed gamever has no reference, `{gamever}` falls back to the canonical reference gamever (hl-10210), so the default chain still resolves for the shared hl/cof family.
- The UTF-16 branch fails closed if the literal is present but no owning function boundary is recoverable (`_unicode_string_candidates` records such hits instead of silently returning zero owners).
- `AllocBlock: full` is SvEngine-only wording — do not expect it on the hl/cof builds, and do not use it as a cross-engine anchor.
- Verified 2026-09-26 against all 15 branch binaries: 133 R_NewMap callee candidates guarded, exactly the committed entry accepted on every branch, no false rejection and no false acceptance. A scoped analyzer run of `engine:windows:find-GL_BuildLightmaps` on hl-10210 reproduced the committed artifact byte-for-byte with the guard in place.
