---
title: GL_Init locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-init
tags:
  - locator
  - engine
  - func
---

# GL_Init

## Symbol

- **Name**: `GL_Init`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_Init.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: none observed; the vendor-report family differs per engine but each literal has exactly one owner.

## Predecessors

- None.

## How it is located

- Two string specs are tried **in order**, each with `xref_strings` and the `FULLMATCH:` exact-text prefix; the first spec that yields a single-owner match wins:
  1. `FULLMATCH:GL_VENDOR: %s\n` — the non-SvEngine vendor report printed from `GL_Init` (engine/gl_rmain.c).
  2. `FULLMATCH:Failed to query GL vendor string` — the SvEngine fail-closed wording used instead.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery uses only the own-literal anchor; no byte signature or old artifact is consulted.

## Pitfalls

- The two literals are mutually exclusive per engine family; the ordered waterfall exists precisely because the first spec has no match at all on SvEngine. If a future build prints both, the first spec wins and the second is never tried.
- The anchor is a **string-item** scan over the shared C string list (`STRTYPE_C`, with the spec's `minlen` applied and the setup state cached in a netnode). A build whose literal is stored without a string item will not be found by this path.
- `xref_strings` requires the literal to have an owning function; un-promoted code fails closed.
