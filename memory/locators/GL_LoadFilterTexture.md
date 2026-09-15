---
title: GL_LoadFilterTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-loadfiltertexture
tags:
  - locator
  - engine
  - func
---

# GL_LoadFilterTexture

## Symbol

- **Name**: `GL_LoadFilterTexture`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_LoadFilterTexture.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config). The finder itself rejects any platform other than `windows`/`linux` and requires `pointer_size == 4`.
- Inlined / absent: the function itself is always standalone; what changes is whether it calls `GL_Bind` directly. SvEngine keeps the constants but restructures the `GL_Bind` call out of the body, and Linux builds inline `GL_Bind` entirely.

## Predecessors

- `<none>` — this finder has no required `expected_input`.
- `GL_Bind.{platform}.yaml` is declared as **`optional_input`** in all ten engine configs (produced by `find-GL_BuildLightmaps-decompiles`). When present it supplies the strongest discriminator; the scheduler owns that dependency edge.

## How it is located

The function owns no diagnostic string, so the anchor is its constant pair: an `8*8*3` (`0xC0`) byte RGB (`0x1907`) buffer in `engine/gl_draw.c`.

1. **Byte prefilter** over all functions with `MIN_FUNCTION_SIZE <= size <= MAX_FUNCTION_SIZE` (0x40..0x600): the raw body must contain both `C0 00 00 00` and `07 19 00 00`.
2. **Instruction-level verification** — each surviving candidate must expose `0xC0` and `0x1907` as real `o_imm` operands of the decoded instruction stream. Values are normalized by the operand's actual dtype width (`ida_ua.get_dtype_size(op.dtype)`, mask 0xFFFF for 2-byte, 0xFF for 1-byte, 0xFFFFFFFF for >= 4), so a wider immediate such as `0x100C0` or `0x11907` can never truncate into a match, and addresses/branch targets (`o_mem`/`o_displ`/`o_near`) never satisfy the pair.
3. **Discriminator waterfall**, strongest first, each stage accepted only when it leaves exactly one candidate:
   - `glbind` — the body directly calls `GL_Bind` (Windows hl/cof families). Requires the optional `GL_Bind.{platform}.yaml` artifact; its `func_va` must be >= `image_base`.
   - `allocfree` — the body calls a **named** allocator: `free`, `_ZdlPv`, `_ZdaPv`, `malloc`. Target names are checked through both the named-EA lookup and the generated disassembly line, which also covers WON blobs that call `free` through an unnamed thunk while `_malloc` is named.
   - `constants` — the bare constant pair, accepted only if it is unique on its own (this is the stage that survives hl-8684/linux).
   - A stage that leaves more than one candidate is skipped (except the terminal `constants` stage), and the whole run reports `GL_LoadFilterTexture constant pair is not unique` when no stage narrows to one.
4. The winner is renamed in the IDB and then verified through `_inspect_function_via_mcp`; if the standard window yields no unique signature, the inspection is retried with `allow_across_function_boundary=True` and the payload carries `func_sig_allow_across_function_boundary`.
5. The inspected `func_va` must equal the located EA and be >= `image_base`, otherwise the finder fails closed.

## Pitfalls

- Only `o_imm` operands count. `hl-8684/linux Draw_AlphaSubPic` passes the byte prefilter (both 4-byte words appear in its body) but fails the immediate check.
- Never normalize immediates with an unconditional `& 0xFFFF`: `0x100C0` and `0x11907` would then impersonate the pair. Mask by the decoded operand width instead.
- The constant pair is genuinely non-unique on hl-8684/linux even after correct masking — that build only resolves through the allocator stage.
- The `GL_Bind` artifact is optional by contract: its absence must not turn the skill into a hard failure, and the waterfall must still fall through to the next stage.
- Because the artifact records whether the across-boundary window was used, downstream consumers must honour `func_sig_allow_across_function_boundary`.
