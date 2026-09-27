---
title: Engine entity interpolation locators (issue 266)
type: note
permalink: goldsrc-vibesignatures/locators/engine-entity-interpolation-locators-issue-266
tags:
- locator
- engine
- issue-266
---

# Engine entity interpolation locators (issue #266)

## Scope

The engine module has 15 configured targets: 11 Windows `hw.dll` inputs (the four old BLOB tags use `hw.decrypt.dll`) and four Linux `hw.so` inputs. The CS/CZ tags do not declare an engine module. Issue #266 adds `CL_LinkPacketEntities`, `CL_InterpolateModel`, `CL_FindInterpolationUpdates`, and the `cls_timedemo`, `cl_moving`, and `cl_onground` field-address globals.

## Anchor chain

- `find-CL_LinkPacketEntities` owns the exact, unique `Tried to link edict %i without model\n` string from `engine/cl_ents.c`; its artifact replaces repeated literal discovery in `find-R_ResetLatched`.
- `find-CL_InterpolateModel` walks that verified function's direct callees and requires the model-name `'*'` branch and a unique history-ring callee. The suggested 360/±180 float set did not uniquely locate the function in the representative shipped builds, so those values are identity evidence rather than discovery bytes.
- The second issue entry called `CL_InterpolateModel` is actually `CL_FindInterpolationUpdates` in `engine/cl_extrap.c`. Its body repeatedly applies `HISTORY_MASK` (`0x3f`) to a 64-slot pose history. `0.0` may compile as `fldz` or integer tests and is not a standalone locator.
- `find-CL_InterpolateModel-globals` recovers `cls.timedemo` from its early zero guard and the two adjacent `cl` fields from their own accesses. It revalidates the existing `cl_waterlevel` artifact and requires current-binary accesses at `waterlevel-4` (moving) and `waterlevel-8` (onground). The source-level three-int layout is a cross-check; no absolute address or whole-struct offset is copied across builds. The global writer validates each x86 operand and unique runtime signature.

## ELF naming and split body

`svencoop-8948/hw.so` retains C++ symbols `_Z21CL_LinkPacketEntitiesv`, `_Z19CL_InterpolateModelP11cl_entity_s`, and `_Z27CL_FindInterpolationUpdatesP11cl_entity_sfPP18position_history_tS3_Pi`; their artifact payload identities use those names. Stripped SvEngine 10257 uses source identities. `hl-8684/hw.so` has a public `CL_InterpolateModel` wrapper at `0x17bfe0` and a private `CL_InterpolateModel.part.1` core at `0x17b4a0`; `CL_LinkPacketEntities` calls the core. The timedemo access is in the wrapper, while moving/onground and the history call are in the core. Both functions have distinct artifacts for that target.

## Corrected R_ResetLatched regression

The previous `find-R_ResetLatched` locator accepted candidates called at least twice and chose the candidate with the fewest extra callers. On `hl-8684/hw.so`, this selected `CL_InterpolateModel.part.1` (three calls from the packet linker) at `0x17b4a0` and mislabeled its three call sites as reset patches. The true ELF `R_ResetLatched` is `0x1367b0`, called from `CL_LinkPacketEntities` at `0x17deb9` and `0x17e187`. The corrected finder consumes the verified packet-linker artifact and requires exactly two calls from it, as in `engine/cl_ents.c:1359,1415`. The false `callsite_2` config declaration and artifact were retired. This is a source-role failure that a unique byte signature alone did not catch.

## Verification
Owned IDA sessions checked the exact 32-bit binary identity and hash for all 15 targets. The new finders produced 91 function/GV artifacts, including the Linux split core; direct artifact checks verified the field relation on all 15. The corrected reset finder was independently run against fresh scratch outputs for every target: 15/15 outputs matched the reviewed repository artifacts. The `hl-8684/hw.so` corrected reset addresses are `0x1367b0`, `0x17deb9`, and `0x17e187`. The repository's format gate, 1,212 unit tests, and 14 repository-contract tests passed.