---
title: GL_LoadTexture2 locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-loadtexture2
tags:
  - locator
  - engine
  - func
---

# GL_LoadTexture2

## Symbol

- **Name**: `GL_LoadTexture2`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: three producers, selected per config/platform:
  - `ida_preprocessor_scripts/find-GL_LoadTexture2.py` — string anchor, the primary producer.
  - `ida_preprocessor_scripts/find-Draw_MiptexTexture-decompiles.py` — hl-10210 Linux only.
  - `ida_preprocessor_scripts/find-DT_LoadDetailTexture-decompiles.py` — svencoop-10257 Linux only.

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: `find-GL_LoadTexture2` is **Windows-gated** where it is declared with a platform (`hl-10210` and `svencoop-10257`); in the other eight configs it is registered ungated. The two `-decompiles` producers are Linux-gated (`find-Draw_MiptexTexture-decompiles` on hl-10210, `find-DT_LoadDetailTexture-decompiles` on svencoop-10257).
- Inlined / absent: the function is always standalone; only the anchor differs. The hl-10210 and svencoop-10257 **Linux** branches have no single-owner string anchor, which is exactly why the two decompile chains exist.

## Predecessors

- `find-GL_LoadTexture2.py` — none.
- `find-Draw_MiptexTexture-decompiles.py` — `Draw_MiptexTexture.{platform}.yaml` (produced by `find-Draw_MiptexTexture`, required).
- `find-DT_LoadDetailTexture-decompiles.py` — `DT_LoadDetailTexture.{platform}.yaml` (produced by `find-DT_LoadDetailTexture`, required).

## How it is located

**A. `find-GL_LoadTexture2` (string waterfall).** Two specs tried in order, each `xref_strings` with the `FULLMATCH:` exact-text prefix; the first single-owner match wins:

1. `FULLMATCH:Texture Overflow: MAX_GLTEXTURES` — the `gltextures` overflow diagnostic owned by GL_LoadTexture2 (engine/gl_rmisc.c) on most validated branches.
2. `FULLMATCH:NULL Texture\n` — the SvEngine Windows wording, emitted when the wrapper returns without a slot.

Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. No byte signature or old artifact is used for discovery.

**B. `find-Draw_MiptexTexture-decompiles` (hl-10210 Linux).** `Draw_MiptexTexture` uploads a cached wad miptex through the full **nine-argument** `GL_LoadTexture2` (engine/gl_draw.c). An LLM_DECOMPILE `found_call` spec runs against the annotated reference `references/{gamever}/engine/Draw_MiptexTexture.{platform}.yaml` with a required dependency on the `Draw_MiptexTexture.{platform}.yaml` artifact. The annotated reference pins the nine-argument call site; the same body also contains a **specialized upload entry that must not be mistaken for the canonical wrapper** (the eight-argument `Draw_MiptexTexture` decal specialization is rejected).

**C. `find-DT_LoadDetailTexture-decompiles` (svencoop-10257 Linux).** The SvEngine body genuinely differs from the shared hl family, so it keeps its own reference. LLM_DECOMPILE `found_call` against `references/{gamever}/engine/DT_LoadDetailTexture.{platform}.yaml`, required dependency on the `DT_LoadDetailTexture.{platform}.yaml` artifact. The annotation pins the nine-argument call site and rejects both the eight-argument `Draw_MiptexTexture` decal specialization and the internal register-ABI upload body.

In both decompile variants the runtime validates the returned `insn_va`/`insn_disasm` pair, requires the call's `code_refs` to be a single unique target, then inspects that entry for the standard five function fields.

## Pitfalls

- There are **three** producers for one symbol: whichever branch runs is determined by the config's `platform:` gate plus the registered finder name. Do not add a fourth string-anchor producer for the two Linux branches — those builds have no single-owner string anchor, which is the documented reason the decompile chains exist.
- Inside the decompile chains, registering a second `found_call` for the same reference would break `_prepare_llm_dependency_contract` (one dependency per reference func name). The wrapper-vs-specialization ambiguity is resolved by the reference annotation, not by a second spec.
- The `NULL Texture\n` literal is the SvEngine-only spelling and carries a trailing newline; the `Texture Overflow: MAX_GLTEXTURES` literal is the hl/cof spelling. A substring/prefix anchor on either would be fragile.
