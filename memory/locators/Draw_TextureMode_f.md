---
title: Draw_TextureMode_f locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-texturemode-f
tags:
  - locator
  - engine
  - func
---

# Draw_TextureMode_f

## Symbol

- **Name**: `Draw_TextureMode_f`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_TextureMode_f.py`
- **Source**: `engine/gl_draw.c`, the `gl_texturemode` handler that maps a filter
  name onto `gl_filter_min` / `gl_filter_max` and re-uploads every mipmapped
  texture.

## Availability

- All 11 engine configs, every declared platform. BLOB tags analyse
  `hw.decrypt.dll`.
- The artifact identity is `Draw_TextureMode_f` everywhere, including the two
  families where the build's own symbol differs, because the config owns one
  lookup identity (see Pitfalls).

## Predecessors

- None. The finder has no `expected_input`.

## How it is located

One exact literal, one string instance, one owning function:

| Family | Literal | Real symbol in the non-stripped `.so` |
| --- | --- | --- |
| BLOB, hl-4554, hl-6153, cof-5936 | `bad filter name\n` | (no `.so`) |
| hl-8684, hl-10210 | `bad filter name\n` | `gl_texturemode_hook_callback` |
| svencoop-8948, svencoop-10257 | `Invalid filter name\n` | `GL_TextureMode_f` |

`_anchor_literal` picks the literal from the gamever; `FULLMATCH:` keeps the
classic and SvEngine literals from ever selecting each other. `preprocess_common_skill`
runs with `old_yaml_map=None`, so no prior artifact signature participates.

## Pitfalls

- **`"current filter is unknown???\n"` is not the anchor.** It exists only on
  BLOB / hl-4554 / hl-6153 / cof-5936, and it sits in the *same* function as
  `"bad filter name\n"`, so the survivor literal covers strictly more configs.
  hl-8684 / hl-10210 dropped it entirely.
- **The real symbol name is not stable.** hl-10210 / hl-8684 renamed the command
  callback into a cvar hook callback and changed its ABI to `void (cvar_t *)`;
  SvEngine calls it `GL_TextureMode_f`. The config symbol stays
  `Draw_TextureMode_f` so one identity covers every build.
- **SvEngine Windows leaves the handler outside every function** in both IDBs.
  The literal then has a code xref with no owning function and the shared walk
  finds zero candidates. `_engine_texture_mode_common.recover_registered_owner`
  recovers the entry from `Cmd_AddCommand("gl_texturemode", ...)` and defines it
  in memory; see [[SvEngine Windows IDBs leave GL_TextureMode_f outside any function]].
- Validation evidence (not consumed by the finder): hl-10210 W `0x1023aa70` /
  L `0x149070`, hl-8684 L `0x1a0e20`, cof-5936 `0x1d5daac`,
  svencoop-8948 W `0x1d4fe40` / L `0x172d20`,
  svencoop-10257 W `0x1d500f0` / L `0x126230`.

## Relations

- relates_to [[gl_filter_min]]
- relates_to [[gl_filter_max]]
