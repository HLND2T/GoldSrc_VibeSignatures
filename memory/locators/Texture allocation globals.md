---
title: Texture allocation globals
type: note
permalink: goldsrc-vibesignatures/locators/texture-allocation-globals
---

# Texture allocation globals

## Overview

Issue #197 adds engine texture-allocation locators for the configured HL/CoF and SvEngine inputs. Reuse the existing GL_LoadTexture2 producers; do not rediscover already covered texture_extension_number under MetaHook's local allocated_textures name.

## Responsibilities

- GoldSrc/HL25/CoF: recover the static gltextures array, numgltextures and gHostSpawnCount.
- SvEngine: recover the CUtlVector<gltexture_t> gltextures object, peakgltextures and gHostSpawnCount, plus realloc.
- Windows SvEngine exposes qualified member storage addresses as gv: gltextures.m_Size and gltextures.m_Memory.m_nAllocationCount (user-approved classification). Linux exposes the vector's pointer/count/capacity accesses as structmember artifacts.

## Involved Files & Symbols

- ida_preprocessor_scripts/find-GL_LoadTexture2-globals.py
- ida_preprocessor_scripts/find-GL_LoadTextureFilterMode-body.py
- ida_preprocessor_scripts/find-GL_LoadTextureFilterMode-decompiles.py
- ida_preprocessor_scripts/find-CUtlVector_gltexture_t_InsertBefore-decompiles.py
- Canonical references: references/hl-10210/engine/GL_LoadTexture2.*.yaml; SvEngine overrides under references/svencoop-10257/engine/.
- ida_analyze_util.py: structmember LLM recovery honors the existing offset_sig_allow_across_function_boundary option.
- ida_analyze_bin.py: runtime function validation permits an executable .plt function entry only when the current x86 indirect jump resolves through a GOT slot to an external import.

## Architecture

HL/CoF uses the verified GL_LoadTexture2 predecessor directly. HL25 Linux already locates the canonical nine-argument entry through Draw_MiptexTexture because its diagnostic literals have three owners.

SvEngine Windows inlines vector insertion into the texture loader. Linux uses the existing DT_LoadDetailTexture -> GL_LoadTextureFilterMode wrapper (artifact GL_LoadTexture2) -> register-ABI .part.14 body -> CUtlVector<gltexture_t>::InsertBefore chain. The internal function is not a cdecl replacement for the public wrapper.

The three Linux structmembers are m_Memory.m_pMemory, m_Memory.m_nAllocationCount and m_Size of CUtlVector_gltexture_t. In the two verified Sven builds their offsets are 0, 4 and 12; derive them from each current predecessor's operands instead of copying these values.

## Dependencies

- D:/HLND2T_official/engine/gl_draw.c and public/utlvector.h / public/utlmemory.h explain source roles. This is not matching SvEngine source; target instructions take precedence.
- Sven 8948 ELF retains _ZL10gltextures (20-byte vector), _ZL14peakgltextures and gHostSpawnCount. 10257 private names are stripped, so those identities are recovered by corresponding behavior.
- References are generated through generate_reference_yaml.py after restoring the relevant names/prototypes/types in the owned IDB session.

## Notes

### Member storage versus independent globals

- Trigger: MetaHook names numgltextures/maxgltextures suggest standalone Sven globals; stale IDB pointer types can even render count accesses with a nonexistent extra dereference.
- Constraint: Sven stores these values inside gltextures. Windows inlining emits absolute member addresses rather than base-relative member-offset instructions.
- Correct approach: inspect actual loads/stores. Emit qualified Windows member gv addresses; preserve Linux structmember identities and offsets. The gltextures gv itself is the container base, not its heap pointer value.
- Verification: compare typed reference pseudocode with current disassembly and retained 8948 ELF symbols; validate emitted addresses against the matching binary.
- Scope: Sven 8948/10257 Windows and Linux.

### PLT signatures and callable entries

- Trigger: the generic function signature generator cannot distinguish realloc's PLT stub because it masks the relocation selector, whose small integer happens to lie in ELF's first mapped segment.
- Constraint: Linux realloc is undefined in hw.so; its local callable entry is a PLT stub, not libc's implementation. Windows has a static CRT wrapper.
- Correct approach: within the verified InsertBefore body, decode a direct call to .plt, verify its current ELF32 R_386_JUMP_SLOT record names realloc, then generate an output-only signature preserving the lazy-binding selector and wildcarding the GOT address/relative jump. Require image-wide uniqueness. Do not use this byte pattern as discovery.
- Verification: both Sven ELF inputs exercise the relocation binding and generated signature; runtime validation rejects unverified .plt addresses, non-code sections and interior function addresses. Generic regression tests cover the validation gate and explicit structmember signature budgets.
- Scope: current x86 ELF FF25 lazy PLT stubs; unsupported encodings fail closed.

### Existing coverage

MetaHook allocated_textures is texture_extension_number: HL 3248/3266/3329/3647/4554 and CoF 5936 already have matching artifacts. No duplicate locator or renamed artifact is added.

## Callers

- Production engine entries in configs/hl-*.yaml, configs/cof-5936.yaml and configs/svencoop-*.yaml.
