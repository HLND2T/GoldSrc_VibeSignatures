---
title: ClientPortalManager_RenderPortals_to_AngleVectors_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-renderportals-to-anglevectors-callsite-0
tags:
  - locator
  - client
  - patch
---

# ClientPortalManager_RenderPortals_to_AngleVectors_callsite_0

## Symbol

- **Name**: `ClientPortalManager_RenderPortals_to_AngleVectors_callsite_0`
- **Category**: `patch`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_RenderPortals_to_AngleVectors_callsite_0.py`
- **Callee**: the Sven client's `AngleVectors`. Sven publishes the symbol on 8948
  (`_Z12AngleVectorsRK6VectorPS_S2_S2_`, `0xba41a`); the 10257 databases spell the same function
  `View_AngleVectors`, a restored local name, so the artifact name uses the published one.

## Availability

- Declared in 2 configs: svencoop-8948 and svencoop-10257, client module only. This is Sven Co-op
  client state; the `hl-*` / `cstrike-*` / `czero-*` / `cof-*` clients carry no portal manager.
- Platforms: Windows + Linux (no `platform:` gate). All four validated builds produce exactly one
  artifact each.
- Consumer: MetaHookSv's `R_SCClientRedirectRenderPortalAngleVectors`, which currently finds this
  branch with a local first-match byte pattern and redirects it to its own
  `ClientPortalManager_AngleVectors` wrapper to capture the portal being rendered.

## Predecessors

- `ClientPortalManager_RenderPortals`, produced by `find-ClientPortalManager_RenderPortals` from the
  exact diagnostic literal `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn.\n"`.

## How it is located

1. Revalidate the current-binary `ClientPortalManager_RenderPortals` artifact through MCP.
2. Search set = host body plus the host's direct rel32 call targets, with ELF `.plt` stubs resolved
   through the repository's `resolve_elf_plt`; capped at 96 functions in body order.
3. Candidate = a direct call whose preceding `lea` / `push` / `mov` / `nop` window (at most 12
   instructions) loads `[r+0x18]`, `[r+0x24]` and `[r+0x30]` from one base register `r`: the
   `ref_params_t` forward/right/up triple of `AngleVectors(p->viewangles, p->forward, p->right, p->up)`.
4. The candidate's resolved callee must also be one of the host's own direct callees, it must be a
   function start, and exactly one candidate must survive in the whole search set.
5. Generate a unique patch signature from the branch and the following instructions, wildcarding
   relocatable operand bytes. `patch_sig_disp = 0`; runtime redirect bytes are not stored.

## Pitfalls

- The MetaHookSv byte pattern is a reference hint only. It matches exactly once in both Windows
  clients and never on Linux, because GCC does not encode that statement the same way. It is not
  used for discovery.
- The statement is not always inside the host body, because GCC outlines it: 10257 Linux keeps it in
  `sub_F78A2`; 8948 Linux keeps it in `PortalSource::SetupRendering(ClientPortalManager*,
  ref_params_s*)`, which the host reaches through that function's `.plt` stub. A search set without
  PLT resolution silently misses the 8948 Linux site.
- The host also calls the same callee with the manager's own view vectors, so call order alone does
  not distinguish the two sites. The `ref_params_t` argument triple, not an index, selects this
  artifact; the `callsite_0` suffix only numbers the single rule-matching site.
- Do not treat 10257's `View_AngleVectors` and 8948's mangled `AngleVectors` as different functions.
- Validation evidence (not consumed by the finder): 10257 W call `0x1004ec64` in
  `ClientPortalManager_RenderPortals`, L `0xf7943` in `sub_F78A2`; 8948 W `0x100971a4` in
  `ClientPortalManager_RenderPortals`, L `0x158ee3` in `PortalSource::SetupRendering`.

## Relations

- relates_to [[ClientPortalManager_RenderPortals]]
