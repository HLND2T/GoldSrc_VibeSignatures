---
title: Engine private globals and language patches (#260)
type: note
permalink: goldsrc-vibesignatures/locators/engine-private-globals-language-patches-260
tags:
- locator
- engine
- gv
- patch
- issue-260
---

# Engine private globals and language patches (#260)

Issue #260 ("TODO: Add engine private globals") asked for the `hw.dll` / `hw.so`
targets behind five MetaHookSv `Engine_FillAddress_*` / `Engine_PatchAddress_*`
routines. Three of the five overlapped symbols already covered by this repository
and were reused as-is; four new symbols were delivered.

## Symbols delivered

| Symbol | Category | Module | Producer | Predecessor |
| --- | --- | --- | --- | --- |
| `realtime` | gv | engine | `find-realtime.py` | `Host_Init` |
| `staticEngineSurface` | gv | engine | `find-staticEngineSurface.py` | — |
| `VGUIClient001_CreateInterface` | patch | engine | `find-VGUIClient001_CreateInterface.py` | `CBaseUI__Initialize` |
| `V_strncpy` | patch | engine | `find-V_strncpy.py` | — |

A shared helper `_patch_signature_common.run_signature(session, ea)` generates the
`patch_sig` for the three patch finders: the worker emits progressively longer
forward byte patterns with displacement operands wildcarded, and each candidate is
accepted only when `find_bytes` resolves it to exactly one address equal to `ea`.

## Overlap resolved (reused, not re-implemented)

- `Sys_InitializeGameDLL` / `hostparam_basedir` anchors of
  `Engine_FillAddress_Sys_InitializeGameDLL` are already produced by
  `find-Host_InitializeGameDLL.py` and `find-host_basepal.py`.
- `g_pClientFactory` and the `CBaseUI::Initialize` body are already produced by
  `find-CBaseUI__Initialize*.py`; `find-VGUIClient001_CreateInterface` consumes the
  latter as `expected_input`.
- `Host_Init` (the `realtime` owner) is already produced by `find-Host_Init.py`.

## Availability and version-specific absence

- `realtime`: declared in all 11 engine configs; 15 artifacts (Windows + Linux).
- `staticEngineSurface`: declared in all 11 engine configs; 15 artifacts.
- `VGUIClient001_CreateInterface`: 13 artifacts. `svencoop-8948` / `svencoop-10257`
  pin the finder and symbol to `platform: windows`, inheriting the Windows-only gate
  of their `find-CBaseUI__Initialize`.
- `V_strncpy`: partially registered, 10 artifacts, in six engine configs only —
  `cof-5936`, `hl-6153`, `hl-8684` (Windows + Linux), `hl-10210`,
  `svencoop-8948`, `svencoop-10257` (Windows + Linux).
  **hl-3248 / hl-3266 / hl-3329 / hl-3647 / hl-4554 are intentionally not
  registered**: their `hw.dll` is a Metahook blob and the decrypted
  `hw.decrypt.dll` references the `english` literal only through `__strcmpi`,
  with `Q_strncpy` inlined as a length-prechecked byte loop — there is no copy
  call to anchor on. The finder returns `PREPROCESS_STATUS_ABSENT_OK` if a
  registered build loses the call, but these tags declare no symbol so no artifact
  is expected.

## How `realtime` is located

`find-Host_Init.py` is revalidated, then the `Host_Init` body is walked for a
zero store to an aligned 8-byte writable global. Five shipped encodings are
recognised: `xorps xmm0,xmm0` + `movsd`, `fldz` + `fstp`, `xor r,r` + paired
`mov` over `gv`/`gv+4`, a stack slot copied by a callee over `gv`/`gv+4`, and a
plain `mov dword_X, 0`. Zero tracking is ABI-aware: a `call` clears only
`eax`/`ecx`/`edx` and the x87/SSE zero flags, while `ebx`/`esi`/`edi`/`ebp`
survive. When the store shape alone is ambiguous the candidate must have at least
`MIN_EXTERNAL_READERS = 8` readers outside `Host_Init`; a lone candidate is
accepted without that filter because PIC builds hide the readers behind a GOT
slot. The `gv_sig` is generated from the guard owner body.

## How `staticEngineSurface` is located

The `EngineSurface007` interface literal owns two functions (the singleton
registrar / factory path and `VGuiWrap_Startup`). Inside each owner, the guard is
the null test *closest above* the literal reference site — `cmp [gv], 0`, or
`mov reg,[gv]` followed within three instructions by `test reg,reg`, allowing only
intervening `push` and `mov [esp|ebp+disp],reg` spills. The guard global must also
be written later in the same body, which separates the cached surface pointer from
the sibling `staticPanel`. SvEngine Windows outlines the store, so there the
entry-read / body-write pair alone identifies the owner. Exactly one candidate or
the finder fails closed.

## How `VGUIClient001_CreateInterface` is located

The `VClientVGUI001` literal has exactly one owning function on every configured
build, and inside `CBaseUI__Initialize` it is referenced once, as the factory
call's argument. The finder revalidates that owner artifact, requires exactly one
reference site, and takes the first `call`/`jmp` within `CALL_WINDOW = 8`
instructions after it, bounded to the owner body.

## How `V_strncpy` is located

The anchor is the source argument: every `english` literal instance (builds embed
one to five copies) whose first following branch is a string-copy call
(`strncpy`/`strcpy`/`q_strncpy`/`v_strncpy`/`strlcpy`/`strncpy_s`). Copy sites are
deduplicated by address, and the lowest-addressed copy in the lowest-addressed
owner is emitted — that is `FileSystem_SetGameDirectory`, which runs before the
fallback-directory pass in the same translation unit. The literal is also compared
with `stricmp`/`strcasecmp`, so the callee class (copy, never compare) is the
discriminator.

## Pitfalls

- **"First literal only" bug.** An earlier revision stopped at the first `english`
  instance, so hl-6153 and hl-8684 Windows (five literal copies, copy call not on
  the first) reported `absent_ok`. The finder must examine every literal.
- **Verifying older tags against `hw.dll` is wrong.** hl-3248…hl-3647 ship a
  Metahook blob; byte-level checks must use `hw.decrypt.dll`. Checking the raw blob
  makes it look as if the string and function set is missing entirely.
- **Blob-backed tags still have `english`.** The absence of the copy call on those
  tags is a real inlining fact, not a decryption artefact — verify on
  `hw.decrypt.dll`, not the blob.
- **`-allgamever -skill` abort.** `-allgamever -skill find-V_strncpy` aborts at the
  first tag that does not register the skill (hl-3248). Validate partially
  registered skills per registered gamever; see
  `memory/notes/allgamever skill-filter abort trap.md`.
- Configs must declare the skill and its symbol **together**. A declared symbol
  with no producer makes `required_paths` unsatisfiable, and a produced file with
  no declared symbol is rejected as "Undeclared symbol YAML".

## Verification

Finder addresses matched retained `.symtab` ground truth on the Linux builds where
symbols exist, and were derived from the confirmed reference-probe evidence
tables otherwise.

| Symbol | hl-10210 | hl-8684 | svencoop-8948 |
| --- | --- | --- | --- |
| `realtime` | W `0x11249e98`, L `0x94d678` | W `0x27b7600`, L `0x963970` | W `0x8406ac8`, L `0x357a70` |
| `staticEngineSurface` | W `0x1063dc30`, L `0x824aac` | W `0x24c9564`, L `0x83a4c0` | L `0x798b34c` |
| `VGUIClient001_CreateInterface` | W `0x1022c281`, L `0x1c1e38` | W `0x1d0121b`, L `0x20cf46` | W `0x1d0fbf8` |
| `V_strncpy` | W `0x101c8b63`, L `0x9f099` | W `0x1d3b23f`, L `0x108cfc` | W `0x1d4db98`, L `0xbf9ca` |

- Per registered gamever: 53 skill/tag/platform runs executed, 0 failed.
- Full `-allgamever -modules engine`: 21 gamevers, `Failed: 0`.
- `format_repo_files.py --check`, `run_test_suite.py unit` (1201 OK, 9 skipped),
  `run_test_suite.py repository-contract` (14 OK) all pass.

## Not covered

`host_parms` (the `gv_name` half of `Engine_FillAddress_Sys_InitializeGameDLL`)
was not delivered. Its `basedir` member is written through different instructions
per family — a direct operand on MSVC builds, SvEngine registers it through an
indirection, and GCC copies a module-indexed array — so a single robust locator
could only resolve uniquely on 9 of 15 builds. It is left as a follow-up.
