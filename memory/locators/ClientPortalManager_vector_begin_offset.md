---
title: ClientPortalManager_vector_begin_offset locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-vector-begin-offset
tags:
  - locator
  - client
  - scalar
---

# ClientPortalManager_vector_begin_offset

## Symbol

- **Name**: `ClientPortalManager_vector_begin_offset`
- **Category**: `scalar` (artifact fields are exactly `scalar_name` + uint32 `scalar_value`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal-offsets-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate). Produced per platform:
  `ClientPortalManager_vector_begin_offset.{platform}.yaml`.
- Inlined / absent: not applicable — this is a numeric field offset, not a code symbol. The manager
  layout itself differs between the MSVC and GCC builds (see Pitfalls), so a single value must never
  be transferred across platforms.

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`)
- `ClientPortalManager_EnableClipPlane` (produced by `find-ClientPortalManager_EnableClipPlane`)
- `ClientPortal_Constructor` (produced by `find-ClientPortal_Constructor`)

All three are `expected_input` artifacts; the walk itself consumes RenderPortals (and the other two
for the constructor/mode scalars emitted by the same finder).

## How it is located

1. RenderPortals' YAML is read from `new_binary_dir`; `func_name` must match and `func_va` must be
   `>= image_base`, else the finder fails closed.
2. The whole RenderPortals body is decoded **inside the IDA worker** (the offsets walk ships its own
   decoder plus `_client_portal_offsets.py` via `py_eval` and returns only the recovered offsets,
   because the decoded instruction list exceeds the MCP result limit). Each instruction is reduced
   to `mnemonic` / `operands` (`reg|imm|api|mem` with base+disp) / `writes` (partial-register writes
   normalized to their full register) / `successors` (intra-function code-ref indices).
3. `_client_portal_offsets._vector_offsets` runs an abstract interpretation over the function
   prologue (max 40 instructions, max 256 states, branch-aware, exploring only forward successors):
   - seed: `esp` = stack pointer; on Windows additionally `ecx` = `("address","manager",0)` — i.e.
     the `this` pointer; on Linux the manager arrives as the first cdecl stack argument and
     `_value` maps `[esp+4]` to `("address","manager",0)`.
   - a candidate is a `cmp` whose two memory operands both resolve to loads off the **manager** root;
   - gates: `end - begin == 4` (POINTER_SIZE — an adjacent begin/end pair), the immediately following
     instruction is a `jz`/`je` whose successor list contains the instruction two slots later (the
     empty-vector guard), and on the fallthrough path a `mov reg, [reg+0]` dereferences the pointer
     loaded from `manager[begin]` (the iterator's first element) — adjacent field loads alone are not
     accepted.
   - exactly one candidate pair must survive, otherwise `ValueError` (`portal vector evidence is
     missing or ambiguous`) and no artifact.
4. The pair is split into the two symbols; each is passed to `preprocess_common_skill` as a
   `scalar_name`, together with an LLM_DECOMPILE spec whose `expected_value` is the deterministically
   recovered number and whose `dependency_policy` requires
   `ClientPortalManager_RenderPortals.{platform}.yaml`. The LLM extraction runs against
   `references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml`. Verified value
   and LLM value must agree (`select_scalar_value`), else the artifact is rejected.
5. Result: Windows begin = 140 (0x8C) / Linux begin = 132 (0x84).

## Pitfalls

- **Begin and end are one proof, not two**: `_vector_offsets` returns the pair from a single accepted
  `cmp`, and the finder raises unless it has exactly one candidate. If either symbol fails, the other
  must not be emitted on its own evidence.
- The MSVC and GCC manager layouts genuinely differ (portal vector at +140/+144 on Windows but
  +132/+136 on Linux). Never reuse a Windows value on Linux; the finder emits per platform.
- Rooting matters: an earlier revision accepted adjacent displacements without proving they came
  from the manager object. The current code requires the `("address","manager",…)` root, the
  empty-vector guard and the iterator dereference, and rejects unrelated null checks.
- The value produced here is compared against LLM output, but the deterministic walk is the source
  of truth — the LLM cannot repair a failed walk.
- Do not confuse this manager-side portal **vector** (std::vector-like begin/end slots) with any
  `ClientPortal` per-object field; the manager and `ClientPortal` are different objects with
  different sizes (W 0x1EC, L 0x1E0 for the manager singleton).
