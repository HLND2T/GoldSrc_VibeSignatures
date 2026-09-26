---
title: Sven client particle functions
type: note
permalink: goldsrc-vibesignatures/locators/sven-client-particle-functions
tags:
- locator
- client
- func
- svencoop
---

# Sven client particle functions

## Scope and names

Issue #250 adds `HUD_DrawTransparentTriangles`, `CParticleEngine_EngineThink`, and `CParticleSystem_ParticleDraw`, category `func`, to the client module of svencoop-8948 and svencoop-10257 on Windows and Linux. These are client.dll/client.so functions, not engine wrappers. HUD coverage outside Sven is not claimed here.

8948 ELF names the private functions `_ZN15CParticleEngine11EngineThinkEv` and `_ZN15CParticleSystem12ParticleDrawEP13CParticleUnit`. 10257 is stripped; matching bodies and callers establish the same roles. Artifact identities use the existing class_method spelling.

## Locators

- `find-HUD_DrawTransparentTriangles`: exact public export; require one entry at a function start, then a unique output signature.
- `find-CParticleEngine_EngineThink`: consume and revalidate HUD's artifact. In priority order, scan `68 01 85 00 00 68 00 85 00 00` (both Windows builds and 8948 Linux) and `C7 44 24 04 01 85 00 00 C7 04 24 00 85 00 00 E8 ?? ?? ?? ??` (10257 Linux). The first matching pattern must have one owning function. Decode the two argument instructions and require the next call to target the imported `glTexEnvf`; require a direct HUD call to that owner, resolving local ELF PLT/GOT indirection. The source role is `glTexEnvf(GL_TEXTURE_FILTER_CONTROL, GL_TEXTURE_LOD_BIAS, cl_texture_lod->value)`, followed by particle-system updates/removal. No layout offset or call ordinal participates in discovery.
- `find-CParticleSystem_ParticleDraw`: exact target-owned diagnostic `Particle_Engine: Couldn't get sprite pointer for "%s"!\n`. All four IDBs have one literal and one direct xref owner; no portal predecessor, PIC fallback or LLM is required.

The two private finders pass `old_yaml_map=None`; generated signatures validate outputs and cannot bypass discovery.

## Verification

The production analyzer exact selection included all three nodes for all four binaries. Run `analysis-batch-20260926T112108-c28c3708dc634c78ad8449c896f5926e` completed 12 successful, 0 failed, 0 skipped nodes. All emitted function starts and unique signatures agree with the prior owned-IDB anchor investigation. Windows image base is 0x10000000; Linux image base is 0.

| Build/platform | HUD RVA | EngineThink RVA | ParticleDraw RVA |
|---|---|---|---|
| 8948 Windows | 0xa3aa0 | 0x8dc80 | 0x91df0 |
| 8948 Linux | 0x1675f8 | 0x14fa78 | 0x155d24 |
| 10257 Windows | 0x5bb10 | 0x45c50 | 0x49ac0 |
| 10257 Linux | 0x107140 | 0xecefc | 0xf39c2 |

Binary SHA-256:
- 8948 Windows: `5e3bd90c24e829c43344f0fe18368a71cad3c9b3405695e2489b469cf694624c`
- 8948 Linux: `8b5fbb8f3533b38ab3fd53dfc6078012bc2f9259ba4e347b5bf301f3d0ebacc4`
- 10257 Windows: `f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6`
- 10257 Linux: `50580344e1c59b3c77e8e4e52ed9f185fcec7da2da936873ec122f12c735a022`

## Pitfalls and source limits

Trigger: following MetaHookSv hints for a Sven private particle function.
Constraint: Windows push patterns do not cover 10257 Linux's stack stores; a proposed caller may not be the best anchor. The particle implementation is absent from the supplied HLND2T_official source tree. Its cl_dll/Exports.h and tri.cpp confirm only the public callback, while MetaHookSv/Plugins/Renderer/gl_hooks.cpp supplies the LOD-bias patch clue.
Correct approach: verify the 8948 ELF names, inspect all target bodies, prefer ParticleDraw's own diagnostic, and validate API/call provenance independently of pattern uniqueness. Require unique output signatures on each binary.
Scope: the four Sven clients above; do not extend their addresses or compiler patterns to other games.

CreateInvisiblePortalTextures and RenderPortals already have production finders and were deliberately skipped in #250. 8948 ELF calls these GenerateInvisibleTexture and PortalRender; their existing artifact naming was not migrated.

## Relations

- relates_to [[ClientPortalManager_DrawPortals]]
- relates_to [[Sven Co-op client legacy OpenGL patch locations and Core 4.4 audit]]
