---
title: SvEngine Windows IDBs leave GL_TextureMode_f outside any function
type: note
permalink: goldsrc-vibesignatures/lessons/svengine-windows-texturemode-function-gap
tags:
  - lesson
  - engine
  - idb
  - svencoop
---

# SvEngine Windows IDBs leave GL_TextureMode_f outside any function

## Trigger

A string-anchored finder fails on `svencoop-8948/hw.dll` and `svencoop-10257/hw.dll`
with a zero-candidate result, while the same script succeeds on the matching
`hw.so`, on every `hl-*`/`cof-*` `hw.dll`, and on the BLOB `hw.decrypt.dll`.

## Root cause / constraint

Both SvEngine Windows IDBs contain `GL_TextureMode_f` as analysed code that is
**not part of any function**. The literal `"Invalid filter name\n"` therefore has
a code xref whose `frm` has no owning function, so the shared string-owner walk
(`FUNC_XREFS` -> containing function) sees zero owners.

The reason is the call graph: the handler is never reached by a code call. Its
only entry is the address pushed into `Cmd_AddCommand("gl_texturemode", ...)`,
which IDA records as a data reference. The Linux builds define the function
normally.

Measured on `svencoop-8948/hw.dll`: the literal xref site is `0x1d4febc`, the
nearest preceding function is `GL_SelectTexture` ending at `0x1d500ef`, and the
next defined function starts at `0x1d50240`; the whole `0x151`-byte gap is code
with no function. `svencoop-10257/hw.dll` behaves identically.

## Correct approach

Recover the entry from the registration itself and define it in-memory before
running the shared owner walk:

```
push offset <handler>          ; the immediate is the function entry
push offset "gl_texturemode"
call Cmd_AddCommand
```

`_engine_texture_mode_common.recover_registered_owner` does this and calls
`ida_funcs.add_func(entry)` (an established pattern in this repository, e.g.
`find-svengine-fill-rgba`). The recovery is **never saved**: the analysis pipeline
runs restored-strict with `save_on_success=False`, so each owned lifecycle starts
from the pristine IDB again. Every finder that revalidates the handler therefore
has to repeat the definition — `ensure_function_defined` exists for that, and
`find-Draw_TextureMode_f-globals` calls it before `owner_context`.

Do not conclude "the symbol does not exist on SvEngine": the bytes are present and
the address is recoverable. Equally, do not fall back to the classic literal
`"bad filter name\n"` there — it does not exist in any SvEngine binary.

## Verification

- `find-Draw_TextureMode_f` succeeds on all 11 engine configs and both platforms.
- The recovered entries are `svencoop-8948/hw.dll 0x1d4fe40` and
  `svencoop-10257/hw.dll 0x1d500f0`, both `0x149` bytes, matching the Linux
  handler shape.
- `find-Draw_TextureMode_f-globals` produces `gl_filter_min`/`gl_filter_max`
  without a saved IDB.

## Scope

Any finder that anchors on a string inside an address-only-referenced function on
these IDBs, and any downstream finder that revalidates such an artifact.
