---
title: 'Sven Co-op 8948 port: ELF indirections and legacy portal layouts'
type: note
permalink: goldsrc-vibesignatures/notes/sven-co-op-8948-port-elf-indirections-and-legacy-portal-layouts
---

# Sven Co-op 8948 port: ELF indirections and legacy portal layouts

## Trigger

Porting `configs/svencoop-10257.yaml` to 8948 produced missing call-edge matches and apparently successful globals pointing into GOT. Portal fields also differed between releases.

## Root cause and constraints

- The supplied `bin/svencoop-8948/engine/hw.so` has `.symtab` and `.dynsym`, but no `.debug_info` or debuglink. Do not describe its symbols or reconstructed types as DWARF evidence. The shipped binary remains authoritative; `D:/MetaHookSv/Plugins/Renderer/gl_portal.cpp` is supporting context only.
- Preemptible ELF definitions are called through PLT, and global addresses are loaded through GOT. A GOT slot is not the requested array/object address. Accept only mapped, verified local targets; preserve unresolved external imports.
- 8948 uses `PortalSource` and `ClientPortal` with different responsibilities. Source vectors are not the live entity transform.

## Correct approach

`ida_elf.py` provides local PLT resolution and reverse call/data edges. Shared LLM global analysis follows GOT pointees and validates effective member stores. Special structural locators must apply the same semantics. Review emitted addresses as well as success status: check no requested local function is a PLT stub and no object/array result is its GOT slot.

Reference lookup is current version → canonical same-family reference (`svencoop-10257` for Sven) → configured global reference (`hl-10210` by default). Never use `-oldgamever` to select a newer source tag.

## Verified 8948 portal layout

| Artifact field | Windows | Linux |
|---|---:|---:|
| PortalSource origin / angles | 0 / 12 | 0 / 12 |
| PortalSource texture id / width / height | 204 / 208 / 212 | 196 / 200 / 204 |
| ClientPortal mode / entity pointer | 40 / 112 | 40 / 112 |
| cl_entity origin / angles | 2888 / 2900 | 2888 / 2900 |
| Manager vector begin / end | 140 / 144 | 132 / 136 |

`PortalSource_CalculateClipPlane` takes the mode and entity transform from the same `ClientPortal`, plus that portal's source vectors. Windows passes addresses directly. Linux calls small getters; `GetOrigin` and `GetAngles` load the entity pointer then add 0xB48/0xB54. Constructor vec3 copies may use bounded `rep movsd` with ECX=3. Follow the actual instruction/ABI evidence before requesting LLM scalar agreement.

## Verification

The scalar finder independently proves each offset and requires the LLM result to agree. References are generated with `generate_reference_yaml.py` from owned IDA sessions. Unit coverage includes equivalent load/add accessors, entity-owner mismatches, cdecl this arguments, vec3 copies, GOT loads, PLT reverse edges and unresolved imports. Full target E2E and source-version regression must be completed before declaring the port finished.

## Scope

8948 engine/client port and shared x86 ELF analysis. Do not flatten the ClientPortal entity indirection or reuse 10257 offset artifacts unchanged.

## Other version differences

- 8948 Windows `studioapi_SetupPlayerModel` has one verified call to `R_StudioChangePlayerModel`, so only callsite 0 is declared; 10257 has two.
- Linux `V_StartPitchDrift` uses an x87 `fstp` global store instead of the SSE `movss` used by newer reference bodies. Callback registration loads its function pointer through GOT.
- 8948 Linux renderer vtable symbol `_ZTV24CGameStudioModelRenderer` is 132 bytes at `0x2fd220`: the address point is `0x2fd228` and there are 31 function entries after the two Itanium header words. Do not count adjacent non-executable data as another function.
- 8948 StudioDrawPlayer compares the current entity pointer with `gEngfuncs.GetLocalPlayer()`. The user confirmed that `g_ViewEntityIndex_SCClient` was introduced in 10257 and approved removing it and its finder node from the 8948 config. Do not fabricate an alias to a function or unrelated engine state.

The same virtual-table boundary check corrects a pre-existing 10257 artifact: slot 31 at `0x5ed9c8` is an ELF relocation against `_ZTVN10__cxxabiv120__si_class_type_infoE` (the next RTTI object's vptr), not a renderer method. Thus the address point `0x5ed94c` also has 31 callable slots. Its old IDA synthetic external address `0xac6f7c` must not be emitted as a renderer function.

Address auditing must use allocated ELF sections (`SHF_ALLOC`); metadata sections with address zero must not make a null global look mapped. `g_bRenderingPortals_SCClient` is an alias for the whole `g_bRenderingPortals` global (`0x7a40f4`), not a field merely because its canonical name has an underscore suffix.

## Port validation status (2026-09-16)
The user confirmed that `g_ViewEntityIndex_SCClient` was introduced in 10257 and authorized removing its symbol and finder from the 8948 configuration. Both platform nodes are now removed; the port's supported output contract is complete.

- The earlier forced 8948 run successfully executed all 237 retained nodes. The two failures belonged solely to the now-removed 10257-only variable. Subsequent targeted runs revalidated `V_CalcRefdef`, `V_StartPitchDrift`, and both `ResetAll` platforms after final fixes; all four succeeded.
- The final analyzer run against the approved config exits successfully: zero failures, 237 existing-output skips. This final run reuses the artifacts already generated and verified; it is not another forced regeneration.
- All 332 8948 artifacts pass the formal canonical inventory contract. No obsolete Portal artifacts remain. All 160 Linux artifacts pass allocated-section checks and exact-symbol comparisons where applicable: no PLT/GOT-slot/null/unmapped targets. `DM_PlayerState=0xd27a20`, `engine`/`eng=0x33ceec`, `g_bRenderingPortals_SCClient=0x7a40f4`.
- 10257 forced regression exercised 237 nodes: 236 succeeded initially; the one x87 classification failure was fixed (`fstp st` is not a global store), and its targeted rerun succeeded. Both ResetAll nodes also reran successfully with ordinary signatures preserved where sufficient. All 329 source-version artifacts pass inventory validation.
- Full test suite: 853 tests, OK, 6 skips for opt-in/unavailable external integration environments. The artifact tracking gate was exercised with newly generated artifacts temporarily staged; the original empty staging state was restored after testing.
- Portal reference paths are complete literal declarations so the PR dependency index can discover them. All five new 8948 reference files have the correct consuming nodes. Follow-up source-index/locator tests: 159 tests, OK. Runtime and source-index lookup share the family mapping in `analysis_config.py`; `ida_elf.py` is registered for global impact and dependency ownership.
- Formatting and `git diff --check` pass. Work remains uncommitted.