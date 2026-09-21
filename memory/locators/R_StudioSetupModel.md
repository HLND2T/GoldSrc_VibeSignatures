---
title: R_StudioSetupModel locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosetupmodel
tags:
  - locator
  - engine
  - func
---

# R_StudioSetupModel

## Symbol

- **Name**: `R_StudioSetupModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupModel.py`

## Availability

- Declared in 11 engine configs with `expected_input: studioapi_SetupModel.{platform}.yaml`.
- Platforms: Windows + Linux where a distinct function exists.
- Inlined / absent: Windows always has a distinct callee of slot 20. GoldSrc/HL25 Linux
  and SvEngine Linux keep a standalone copy even though the wrapper also inlines the
  body; excluding slot 20 leaves that copy. Never emit this artifact at the wrapper VA.

## Predecessors

- `studioapi_SetupModel` (used only as `exclude_funcs`).

## How it is located

`preprocess_common_skill` with `old_yaml_map=None`:

```python
xref_strings: ["FULLMATCH:R_StudioSetupModel: no such bodypart %d\\n"]
exclude_funcs: ["studioapi_SetupModel"]
```

The literal is unique in every legal PE/ELF (including blob `hw.decrypt.dll`). After
dropping the slot-20 wrapper, exactly one owning function must remain.

## Pitfalls

- A plain string xref without the exclusion matches two functions on GoldSrc/HL25 Linux
  and SvEngine Linux.
- `pbodypart` / `psubmodel` are recovered from the wrapper, not from this function.
