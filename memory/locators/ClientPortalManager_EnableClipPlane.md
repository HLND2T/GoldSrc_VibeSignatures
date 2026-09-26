---
title: ClientPortalManager_EnableClipPlane locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-enableclipplane
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_EnableClipPlane

## Symbol

- **Name**: `ClientPortalManager_EnableClipPlane`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_EnableClipPlane.py`

## Availability and independently verified results

| Build | Windows | Linux |
| --- | --- | --- |
| 10257 | `0x1004f960` | `0xf7684` |
| 8948 | `0x10097ea0` | `0x158c7e` |

These addresses are validation evidence, never discovery constants.

## Predecessor and proof

`ClientPortalManager_RenderPortals` is the required predecessor. Walk its direct callees
and their callees, resolving ELF PLT targets. Windows calls the setup function directly;
Linux reaches it through SetupRendering. Require exactly one candidate with:

- `glLoadIdentity`, `glClipPlane`, then `glEnable`, with the same `GL_CLIP_PLANE0 + index`
  argument for ClipPlane and Enable and a stack-local equation.
- A caller supplying manager this and index/viewangles/view/plane, including the relation
  `viewangles = view + sizeof(Vector)`. Windows uses ECX plus four stack arguments; Linux
  uses five stack arguments. GCC's retained-register and spilled aliases are checked through
  dominating definitions or separate forward control-flow paths.
- A generated unique function signature from the current IDB.

## Issue 255: diagnostic-owner identity correction

Trigger: hooking the old 10257 record intercepted plane calculation, leaving GL setup active.
Root cause: the old finder assigned the setup name to the owner of the “Too many clip planes”
diagnostic. Both 10257 platforms were affected, not just Windows.

The diagnostic now belongs exclusively to `find-ClientPortal_CalculateClipPlane`:

| Build | Calculation identity | Windows | Linux |
| --- | --- | --- | --- |
| 10257 | `ClientPortal_CalculateClipPlane` | `0x10050cb0` | `0xfb97e` |
| 8948 | `PortalSource_CalculateClipPlane` | `0x10099310` | `0x15d0ac` |

The 10257 class name follows the repository's recovered constructor/layout identity;
8948 retains its ELF PortalSource name. Neither calculation function is a manager method.
The existing exact diagnostic/PIC fallback remains the calculation locator. Its callers
still provide the source-mode/entity-vector evidence; the 10257 offsets finder now explicitly
depends on `ClientPortal_CalculateClipPlane` instead of the corrected GL setup record.

Validation: all four current-IDB setup/calculation finders and both versions' downstream
layout nodes were rerun. Synthetic behavior regressions reject a diagnostic-only owner,
an unrelated GL cap, and mismatched view vectors. Scope is static x86 binary/data validation;
the MetaHookSv runtime consumer is a separate change.
