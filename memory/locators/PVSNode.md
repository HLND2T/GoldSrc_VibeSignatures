---
title: PVSNode locator
type: note
permalink: goldsrc-vibesignatures/locators/pvsnode
tags:
  - locator
  - engine
  - func
---

# PVSNode

## Symbol

- **Name**: `PVSNode`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-PVSNode.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only. Validated on GoldSrc, HL25, SvEngine and CoF, Windows and Linux alike.
- Inlined / absent: never inlined. The name is MetaHookSv's; the engine source name is `R_PVSNode` (`engine/pr_cmds.c`). It carries no literal and no cvar, so the table slot is the only anchor.

## Predecessors

- None.

## How it is located

1. Structurally identify the engine `triangleapi_t` table (`engine/r_triangle.c`) in data segments: a dword `1` (`TRI_API_VERSION`) followed by **19** consecutive dwords that are all exact function starts.
   - Non-executable segments only (`.text`/`.plt`/`.got` prefixes are skipped); every 4-byte offset is tested.
   - Sibling version-1 tables (event/demo/net APIs) also match this shape, so the shape alone is not the answer.
2. Read slot index `TRI_SLOT_BOXINPVS = 16` (the `BoxInPVS` / `tri_BoxinPVS` slot, counting the leading version dword) and require it to be an exact function start.
3. Find the candidate `PVSNode` among `BoxInPVS`'s direct callees: the candidate must be self-recursive (`cand` is in `callers(cand)`) and must have at least `MIN_CALLERS = 4` distinct callers. `PVSNode` is the only self-recursive helper of `BoxInPVS`; the version-1 sibling tables never expose a self-recursive slot-16 callee.
4. Require exactly **one** `(table, hit)` pair across the whole database, then emit the function artifact (retrying with `allow_across_function_boundary` if the strict window fails).

## Pitfalls

- Scanning with `DataRefsTo` is not reliable on ELF builds — the table is registered through relocations and may have no recorded code xref — so the locator reads the stored pointer image out of the segment bytes instead.
- The self-recursion plus `>= 4` callers gate is what separates the real table from the sibling version-1 tables; weakening either accepts a decoy.
- Multiple `triangleapi_t`-shaped runs can exist in one binary (the code counts them); the uniqueness requirement is on the final *hit*, not on the table list.
- `BoxInPVS` itself is never emitted; only the self-recursive callee is.
