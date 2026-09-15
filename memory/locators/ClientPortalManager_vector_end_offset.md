---
title: ClientPortalManager_vector_end_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-vector-end-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortalManager_vector_end_offset

## Symbol

- **Name**: `ClientPortalManager_vector_end_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate), emitted as
  `ClientPortalManager_vector_end_offset.{platform}.yaml`.
- Inlined / absent: not a code symbol. The manager layout differs per compiler (Windows +144 /
  Linux +136), so cross-platform reuse is invalid.

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`)
- `ClientPortalManager_EnableClipPlane` (produced by `find-ClientPortalManager_EnableClipPlane`)
- `ClientPortal_Constructor` (produced by `find-ClientPortal_Constructor`)

## How it is located

Identical anchor chain to `ClientPortalManager_vector_begin_offset`; the two values are always
recovered as **one** candidate pair by `_client_portal_offsets._vector_offsets`:

1. RenderPortals YAML is validated (`func_name` match, `func_va >= image_base`).
2. The function body is decoded in-worker and handed to the abstract interpreter, seeded with the
   platform's `this`/manager root (`ecx` on Windows, `[esp+4]` from `_value`'s Linux stack rule).
3. An accepted candidate is a `cmp` of two manager-relative memory loads with
   `end - begin == 4`, followed by a `jz`/`je` empty-vector guard (the instruction two slots later is
   among the branch's successors) and a `mov reg, [reg+0]` that dereferences the pointer loaded from
   `manager[begin]` on the fallthrough path.
4. The larger of the two displacements becomes this symbol (`end`); the smaller becomes
   `vector_begin`. Exactly one candidate pair must survive or the walk raises
   `portal vector evidence is missing or ambiguous`.
5. `preprocess_common_skill` then emits `scalar_name` / `scalar_value` after requiring the value to
   agree with an LLM extraction from
   `references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml`
   (`dependency_policy` requires `ClientPortalManager_RenderPortals.{platform}.yaml`).
6. Result: Windows end = 144 (0x90) / Linux end = 136 (0x88).

## Pitfalls

- The name of the game here is the **adjacency** constraint (`end - begin == POINTER_SIZE`): a
  `std::vector`-style pair is proven by its two adjacent 4-byte slots. If a build used a different
  container (or inserted padding), this pair would be rejected rather than mis-reported.
- Because begin and end come from one shared proof, a change that breaks one breaks both — do not
  treat the two artifacts as independently repairable.
- The GCC/Linux layout is 8 bytes smaller for this pair than MSVC's. Copying the Windows constant to
  Linux (or vice versa) silently corrupts any consumer that indexes the manager.
- The interpreter only follows forward successors and stops at `ret`/`loop`; a prologue rewritten
  with a backward branch before the guard would fail the walk rather than produce a wrong offset.
