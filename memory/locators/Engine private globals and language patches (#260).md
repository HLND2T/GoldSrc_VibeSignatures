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
and were reused as-is. PR #262's review corrected the factory-call ABI and split
the language patches by filesystem owner.

## Symbols delivered

| Symbol | Category | Module | Producer | Predecessor |
| --- | --- | --- | --- | --- |
| `realtime` | gv | engine | `find-realtime.py` | `Host_Init` |
| `staticEngineSurface` | gv | engine | `find-staticEngineSurface.py` | — |
| `VGUIClient001_CreateInterface` | patch | engine | `find-VGUIClient001_CreateInterface.py` | `CBaseUI__Initialize` |
| `V_strncpy` | patch | engine | `find-V_strncpy.py` | — |
| `V_strncpy_FallbackGameDir` | patch | engine | `find-V_strncpy.py` | — |

A shared helper `_patch_signature_common.run_signature(session, ea)` generates the
`patch_sig` for both patch finders: the worker emits progressively longer
forward byte patterns with operand fields wildcarded **including the first
instruction**, and each candidate is
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
- `VGUIClient001_CreateInterface`: seven artifacts, on hl-6153 Windows,
  hl-8684 / hl-10210 Windows+Linux, and svencoop-8948 / svencoop-10257 Windows.
  BLOB hl-3248/3266/3329/3647/4554 and cof-5936 use the zero-argument
  `ClientFactory()` callback instead of `Sys_GetFactory(hClientDLL)`; reuse
  `g_pClientFactory` there and emit no module-factory patch.
  `svencoop-8948` / `svencoop-10257`
  pin the finder and symbol to `platform: windows`, inheriting the Windows-only gate
  of their `find-CBaseUI__Initialize`.
- `V_strncpy` and `V_strncpy_FallbackGameDir`: 20 artifacts together, in six engine configs only —
  `cof-5936`, `hl-6153`, `hl-8684` (Windows + Linux), `hl-10210`,
  `svencoop-8948`, `svencoop-10257` (Windows + Linux).
  **hl-3248 / hl-3266 / hl-3329 / hl-3647 / hl-4554 are intentionally not
  registered**: their `hw.dll` is a Metahook blob and the decrypted
  `hw.decrypt.dll` references the `english` literal only through `__strcmpi`,
  with `Q_strncpy` inlined as a length-prechecked byte loop — there is no copy
  call to anchor on. A registered build must yield exactly one copy for each
  filesystem owner; unexpected absence or ambiguity fails closed.

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

Revalidate `CBaseUI__Initialize`, require a unique literal reference, and decode
the indirect interface query's arguments (`"VClientVGUI001"`, null). Trace that
query's callee through registers/local spills back to a dominating call return.
The selected call must be direct, receive a global module handle, and target a
body referencing the exact export name `CreateInterface`. The interface query
itself has the wrong ABI and is never the patch site. Callback engines reuse
the existing global slot instead.

## How `V_strncpy` is located

Follow every exact `english` reference along its basic block and direct jumps
to the first call. Decode arguments as `(local buffer, english, 128)`; reject
two-argument copies and unrelated object-field writes without consulting IDA
callee names. Owners must reference `GAME` and `%s/%s_%s`; `DEFAULTGAME`
identifies `FileSystem_SetGameDirectory` (`V_strncpy`), while its absence
identifies `FileSystem_AddFallbackGameDir` (`V_strncpy_FallbackGameDir`).
Require one site for each role. Consumers redirect both sites. Compiler-shared
Steam/default-language call tails are followed, including Sven Linux's backward
jump to the copy. Address order does not define either role.

## Pitfalls

- **Wrong ABI despite a unique signature.** The interface query returns an
  interface object; MetaHookSv's replacement accepts a module and returns a
  factory. Verify the callee's source role and argument dataflow, then use the
  signature only to validate uniqueness.
- **IDA-resolved relocation bytes.** A direct ELF call may contain an
  `R_386_PC32` relocation into an external function. IDA's resolved displacement
  differs from both raw bytes and process-dependent loader results. Wildcard
  the first instruction's operands too; verify generated patterns against raw
  mapped sections. This applies to all shared patch signature generation.
- **Source order is not binary order.** hl-10210 and Sven Linux place the fallback
  owner before the main owner. The original minimum-address selection missed
  the main copy; CoF even selected an unrelated two-argument strcpy. Verify
  both owner roles and the full copy ABI, and test shared jump tails explicitly.

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
| `VGUIClient001_CreateInterface` | W `0x1022c264`, L `0x1c1e17` | W `0x1d011fa`, L `0x20cf25` | W `0x1d0fbdb` |
| `V_strncpy` | W `0x101c8d35`, L `0x9fd79` | W `0x1d3b23f`, L `0x108cfc` | W `0x1d4db98`, L `0xc0270` |
| `V_strncpy_FallbackGameDir` | W `0x101c8b63`, L `0x9f099` | W `0x1d3b861`, L `0x109204` | W `0x1d4e32d`, L `0xbf9ca` |

Review-fix verification (2026-09-27):

- Forced execution with `python ida_analyze_bin.py -gamever <tag> -node
  engine:<platform>:<finder> -oldgamever none -debug`: all 17 registered patch
  finder/platform nodes succeeded, no skips, producing 27 patch artifacts.
  `-skill` alone can skip existing output and is not a regeneration check.
- Sven 8948 Linux's original IDB was held by an interactive IDA process. Used an
  identical binary copy under the task's temporary `pr262-bin` directory and
  built a fresh IDB through an owned `IdaMcpLifecycle`; the original process was
  untouched. The owned rebuild saved and closed successfully; analyzer runs used
  the repository's strict restored/no-save lifecycle policy.
- Independent raw PE/ELF mapped-section scans: all 27 signatures match exactly
  their emitted VA, RVA agrees with the image base, and every covered PE HIGHLOW
  or ELF 32-bit dynamic relocation byte is wildcarded. This catches the previous
  IDA-only ELF signatures.
- `python ida_analyze_bin.py -allgamever -modules engine`: exit 0, failed 0,
  3642 cached nodes skipped. This is the full inventory check, not 3642 reruns.
- `python tests/run_test_suite.py unit -b`: 1209 tests, OK (5 skipped).
- `python tests/run_test_suite.py repository-contract -b`: 14 tests, OK after
  staging the corrected artifact inventory.
- Shared-helper regressions cover first-instruction relocations, byte-sized
  memory operands, both owner roles, wrong copy ABI, backward shared tails,
  loops/unknown branches, return-register overwrites, and bypassed producers.

Exact patch-validation inputs (SHA-256):

| Build | Platform | SHA-256 |
| --- | --- | --- |
| cof-5936 | Windows | `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875` |
| hl-6153 | Windows | `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257` |
| hl-8684 | Windows | `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10` |
| hl-8684 | Linux | `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1` |
| hl-10210 | Windows | `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295` |
| hl-10210 | Linux | `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78` |
| svencoop-8948 | Windows | `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8` |
| svencoop-8948 | Linux | `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e` |
| svencoop-10257 | Windows | `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596` |
| svencoop-10257 | Linux | `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd` |

## Not covered

`host_parms` (the `gv_name` half of `Engine_FillAddress_Sys_InitializeGameDLL`)
was not delivered. Its `basedir` member is written through different instructions
per family — a direct operand on MSVC builds, SvEngine registers it through an
indirection, and GCC copies a module-indexed array — so a single robust locator
could only resolve uniquely on 9 of 15 builds. It is left as a follow-up.
