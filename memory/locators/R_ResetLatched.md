---
title: R_ResetLatched locator
type: note
permalink: goldsrc-vibesignatures/locators/r-resetlatched
tags:
  - locator
  - engine
  - func
---

# R_ResetLatched

## Symbol

- **Name**: `R_ResetLatched`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py`

## Availability
- Declared in 11 engine configs: cof-5936; hl-3248/3266/3329/3647/4554/6153/8684/10210; svencoop-8948/10257.
- Platforms: Windows for all 11 and Linux for hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- The function remains standalone in `engine/r_studio.c:4696`. Exactly two direct `CL_LinkPacketEntities` call sites exist in every configured target.
## Predecessors
- `CL_LinkPacketEntities.{platform}.yaml` is required. Its independent finder resolves the unique missing-model diagnostic string and supplies a signature-verified current-binary owner.
## How it is located
1. Revalidate the `CL_LinkPacketEntities` artifact against the current IDB; do not relocate the diagnostic string inside this finder.
2. Enumerate its direct calls and keep candidates called **exactly twice**, matching the full reset and `EF_NOINTERP` reset in `engine/cl_ents.c:1359,1415`.
3. Keep a candidate only if its current body is 100–1200 bytes and it has 1–4 additional callers among the entity-linking helpers. Choose the unique candidate with the fewest total callers; ties fail closed.
4. Inspect and emit the function artifact, then emit exactly two unique direct callsite patches in address order. The expected-output count must agree.
## Pitfalls
- The old `>= 2` call-count test misidentified `CL_InterpolateModel.part.1` as `R_ResetLatched` on hl-8684 Linux. That interpolator core has three calls from `CL_LinkPacketEntities`; the true `R_ResetLatched` has two. The old three patch sites and `callsite_2` declaration were wrong.
- On hl-8684 Linux, the verified `R_ResetLatched` RVA is `0x1367b0`, with reset call sites `0x17deb9` and `0x17e187`; these addresses are regression evidence for that binary only, never discovery anchors.
- The 100–1200-byte and 1–4-extra-caller bounds remain secondary filters. A source-role check is essential; uniqueness of the emitted byte signature does not establish function identity.
- The predecessor artifact and every selected function/callsite signature are revalidated in the current IDB. See [[Engine entity interpolation locators (issue 266)]].