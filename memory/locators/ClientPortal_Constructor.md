---
title: ClientPortal_Constructor locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-constructor
tags:
  - locator
  - client
  - func
---

# ClientPortal_Constructor

## Symbol

- **Name**: `ClientPortal_Constructor`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal_Constructor.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate).
- Inlined / absent: a real standalone function on both builds (W 0x10050860 / L 0xF554E on 10257);
  an earlier inlining hypothesis was disproved — Linux's constructor is standalone and called by the
  portal factory. The constructor is **not** an ancestor of RenderPortals; it sits two call edges
  *below* it through the factory.

## Predecessors

- `ClientPortalManager_RenderPortals` (produced by `find-ClientPortalManager_RenderPortals`,
  consumed via `expected_input` and loaded from `<new_binary_dir>/ClientPortalManager_RenderPortals.<platform>.yaml`).

## How it is located

1. The RenderPortals YAML must exist, have `func_name == ClientPortalManager_RenderPortals`, and
   yield a parsable `func_va`; otherwise the finder returns False.
2. `run_layout_walk` executes a walk inside the IDA worker (`_portal_layout_ida.run_layout_walk`
   concatenates `_portal_layout.py` with a compact in-worker instruction decoder):
   ```
   for factory in callees(values['render']):
       for target in callees(factory):
           offsets = constructor_offsets(decode_function(target), values['platform'])
   ```
   i.e. every callee of RenderPortals that is a function start, then every callee of that callee,
   each candidate tested by `_portal_layout.constructor_offsets`.
3. `constructor_offsets` proves the candidate by dataflow, not by address:
   - a `Trace` is seeded with all GPRs as opaque entry registers and `this` = `ecx` on Windows;
   - it walks up to 400 instructions, stopping at the first `j*` / `ret` / `pop` (straight-line only);
   - it collects stores whose address is `("ptr","this",off)` and whose value is a load from a
     stack slot recognized as an **entry argument** (Windows: `[esp+8]` upward; Linux cdecl:
     `[esp+12]` upward, with `[esp+4]` treated as `this`);
   - only Word- or 2-Word-wide copies are considered, grouped per argument, mapped byte by byte.
   - The next three consecutive arguments must each map a **complete, contiguous 12-byte vec3**
     (VECTOR_BYTES), and the three destination ranges must not overlap.
4. Exactly one candidate must survive (`len(candidates) != 1` raises); the survivor is inspected via
   `_inspect_function_via_mcp` and written with
   `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`
   (`func_sig_allow_across_function_boundary` when the body had to cross a boundary).
5. The walk also returns `origin` = first vec3 destination offset and `angles` = second; the caller
   (`find-ClientPortal-offsets-decompiles`) discards them and re-derives them, because the finder's
   own output contract is the function only.

## Pitfalls

- The gate is "copies three complete vec3 entry-argument values into the same `this`", i.e. any
  function with that shape two call edges below RenderPortals qualifies by construction. The
  uniqueness requirement is what protects it; a build where the factory constructs two different
  3-vec3 objects fails closed.
- Straight-line-only tracing means a constructor that branches before finishing the copies (or is
  compiled without a `this` prologue) is not recognized.
- The walk return values must not be published as scalars from this finder — scalar emission happens
  in `find-ClientPortal-offsets-decompiles`, which runs `constructor_offsets` again next to
  `source_mode_offset` and requires LLM agreement.
- The 4-byte stack-slot convention differs per platform (`[esp+4]`/`[esp+8]` on Windows vs
  `[esp+8]`/`[esp+12]` on Linux); the trace only interprets stack slots in the constructor mode, so
  non-constructor traces do not accidentally resolve argument registers.
- Stored research addresses (factory W 0x1004CED0 / L 0xF5EC2, ctor W 0x10050860 / L 0xF554E) are
  evidence only and are never used as production locators.
