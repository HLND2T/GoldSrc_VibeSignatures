---
title: particletexture locator
type: note
permalink: goldsrc-vibesignatures/locators/particletexture-locator
tags:
- locator
- engine
- gv
---

# particletexture

## Symbol

- **Name**: `particletexture`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-particletexture.py`

## Availability

Declared in every engine config (cof-5936, hl-3248 through hl-10210, svencoop-8948/10257). Windows + Linux wherever `hw.so` ships. BLOB tags use `hw.decrypt.dll`.

## Predecessors

- `R_DrawParticles` (`expected_input`)
- `GL_Bind` (`expected_input`)

## How it is located

1. Revalidate the `R_DrawParticles` artifact as a function start.
2. Require exactly one direct call to the `GL_Bind` artifact (PLT resolved).
3. Require `GL_ALPHA_TEST` (`0x0BC0`) in the short window after that call.
4. The unique writable-data load among `mov`/`lea`/`push` before the call, skipping security-cookie `xor eax, ebp/esp`, is `particletexture`.
5. PIC SvEngine Linux uses `lea eax, (gv-GOT)[ebx]` / GOT-slot load; `gv_pic_addend` is the GOT RVA.

## Pitfalls

- Do not count the PIC `add ebx, GOT` as a data load; restrict to `mov`/`lea`/`push`.
- A second `0x0BC0` later in the function is `qglDisable(GL_ALPHA_TEST)`; the check is the first one after `GL_Bind`.
