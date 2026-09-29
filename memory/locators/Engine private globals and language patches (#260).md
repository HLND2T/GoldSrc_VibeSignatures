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
| `FileSystem_SetGameDirectory_V_strncpy_callsite_0` | patch | engine | `find-FileSystem_SetGameDirectory_V_strncpy_callsite_0.py` | — |
| `FileSystem_AddFallbackGameDir_V_strncpy_callsite_0` | patch | engine | `find-FileSystem_SetGameDirectory_V_strncpy_callsite_0.py` | — |

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
- `FileSystem_SetGameDirectory_V_strncpy_callsite_0` and `FileSystem_AddFallbackGameDir_V_strncpy_callsite_0`: 20 artifacts together, in six engine configs only —
  `cof-5936`, `hl-6153`, `hl-8684` (Windows + Linux), `hl-10210`,
  `svencoop-8948`, `svencoop-10257` (Windows + Linux).
  **hl-3248 / hl-3266 / hl-3329 / hl-3647 / hl-4554 are intentionally not
  registered**: both filesystem owners read `Software\\Valve\\Steam` / `Language`
  into a local 128-byte buffer through `Sys_GetRegKeyValueUnderRoot`, with an
  empty default. Their `english` references are comparison operands only; no
  default-English copy exists in either owner. The earlier claim that this copy
  was inlined was incorrect (see the 2026-09-28 audit below). The first four tags
  use `hw.decrypt.dll`; hl-4554 uses ordinary PE `hw.dll`. A registered build must
  yield exactly one copy for each filesystem owner; unexpected absence or
  ambiguity fails closed.

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

## How `FileSystem_SetGameDirectory_V_strncpy_callsite_0` is located

Follow every exact `english` reference along its basic block and direct jumps
to the first call. Decode arguments as `(local buffer, english, 128)`; reject
two-argument copies and unrelated object-field writes without consulting IDA
callee names. Owners must reference `GAME` and `%s/%s_%s`; `DEFAULTGAME`
identifies `FileSystem_SetGameDirectory` (`FileSystem_SetGameDirectory_V_strncpy_callsite_0`), while its absence
identifies `FileSystem_AddFallbackGameDir` (`FileSystem_AddFallbackGameDir_V_strncpy_callsite_0`).
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
- **Old tags still have `english`, but only as a comparison baseline in these
  filesystem owners.** Absence of a language-copy CALL is not proof of inlining.
  Trace the buffer producer: all five old tags obtain it through the registry
  helper. Its successful read invokes an out-of-line `Q_strncpy` on registry data.
  Inspect `hw.decrypt.dll` for hl-3248/3266/3329/3647 and `hw.dll` for hl-4554.
- **`-allgamever -skill` abort.** `-allgamever -skill find-FileSystem_SetGameDirectory_V_strncpy_callsite_0` aborts at the
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
| `FileSystem_SetGameDirectory_V_strncpy_callsite_0` | W `0x101c8d35`, L `0x9fd79` | W `0x1d3b23f`, L `0x108cfc` | W `0x1d4db98`, L `0xc0270` |
| `FileSystem_AddFallbackGameDir_V_strncpy_callsite_0` | W `0x101c8b63`, L `0x9f099` | W `0x1d3b861`, L `0x109204` | W `0x1d4e32d`, L `0xbf9ca` |

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
## Follow-up completed (PR #267)

`host_parms` (the `gv` half of `Engine_FillAddress_Sys_InitializeGameDLL`) was
delivered in PR #267 after the anchor was reworked. The LoadEntityDLLs call
argument is the invariant: `LoadEntityDLLs` owns the exact literal
`"GetNewDLLFunctions"` and resolves to exactly one function on every engine
build; the single argument of the direct call from the revalidated
`Host_InitializeGameDLL` is `host_parms.basedir` (= `&host_parms`, first
`quakeparms_t` member). Six encodings are supported and cross-verified:

| Build | Platform | gv_va | Encoding |
| --- | --- | --- | --- |
| hl-10210 | W / L | `0x11249ec0` / `0x94d684` | push abs / `mov eax, ds:host_parms.basedir` |
| hl-8684 | W / L | `0x27b7580` / `0x963984` | `mov ecx, dword_…` / GCC separated-tail-body `mov` |
| hl-3248…4554, 6153 | W | per-build `dword_…` | `mov ecx, dword_…` |
| cof-5936 | W | `0x27fc160` | `mov ecx, dword_…` |
| svencoop-10257 | W / L | `0x8446c60` / `0x30a4c4` | push abs / GOTOFF `lea` |
| svencoop-8948 | W / L | `0x8406ad0` / `0x357a84` | push abs / GOT-slot pointer load |

Pitfalls fixed along the way:

- **Stack-operand text may embed a register name.** hl-8684 Linux's
  `mov [esp+2Ch+szBaseDir], eax` decodes `op.type == o_phrase` with the base in
  the SIB byte, while the disassembly text contains `edi` inside `szBaseDir`.
  A text regex (`'[esp' in text and no register in text`) misclassifies it. Use
  the structural SIB test (`op.specflag1` set, `specflag2` low byte: base==4 and
  index==4). The encoded displacement is 0 (`op.addr`); `ida_frame.get_spd` at
  the call site already accounts for the frame, so `stack = spd + encoded_disp`.
- **GCC tail split.** On hl-8684 Linux the LoadEntityDLLs call (and the
  `host_parms` reference) live in `Host_InitializeGameDLL_0`, reached by an
  unconditional `jmp` from the diagnostic body. Follow the tail `jmp` target and
  anchor the artifact to whichever body actually contains the reference
  instruction via `owner_context`.
- **GOT-slot pointer load still emits a normal gv artifact.** svencoop-8948
  Linux loads `host_parms` through `mov eax, (host_parms_ptr-GOT)[ebx]`; the
  shared `_gv_resolution_fields` writes `gv_pic_addend` from the raw addend and
  the resolver treats the decoded value as the object address. Cross-check
  `gv_va` against `FileSystem_Init`/`Sys_InitArgv` `basedir = s_pBaseDir`
  writes and `Sys_InitGame`'s `push offset &host_parms`.
- **String anchor must not rebuild the shared string list.** Use the
  `anchor_string_owners` segment scan (readable perm + NUL-delimited literal +
  `DataRefsTo`), never `idautils.Strings().setup()`.

## Legacy filesystem language dataflow audit (2026-09-28)

### Trigger and corrected conclusion

The proposed replacement was to export the instruction taking the address of
`"english"` in both filesystem owners, then substitute a plugin language buffer.
Actual analysis of all ten owners disproved the earlier inlining explanation:
none has a default-English copy. Each reads the Steam registry language with an
empty default, then uses `"english"` solely as the case-insensitive comparison
baseline. Replacing that baseline does not replace the language buffer.

### Scope and evidence

Inspected existing PE32/I386 IDBs using owned `IdaMcpLifecycle` sessions,
`restored_strict`, `save_on_success=False`, health checks before/after queries,
and port-release checks after exit. The first four targets use
`bin/<tag>/engine/hw.decrypt.dll`; hl-4554 uses `bin/hl-4554/engine/hw.dll`
(an ordinary PE, not a BLOB).

Function roles are inferred from machine-code behavior: registry Language input,
localized `%s/%s_%s` formatting, GAME/DEFAULTGAME search-path calls, and the
short fallback owner's unconditional base GAME addition. Existing IDA names
remain `sub_*`; guessed Hex-Rays extra register parameters are not ABI evidence.
The later source in `D:/HLND2T_official/engine/filesystem.cpp:349-513`
contains additional language/default paths and is only a role reference, not
matching source for these old builds.

Addresses below are preferred-image VAs (image base `0x01D00000`), not runtime
addresses and not validated unique patch signatures.

| Build | SetGameDirectory entry | Its language-read CALL | AddFallbackGameDir entry | Its language-read CALL |
| --- | --- | --- | --- | --- |
| hl-3248 | 0x01D3BB50 | 0x01D3BBFF | 0x01D3C100 | 0x01D3C126 |
| hl-3266 | 0x01D3BB30 | 0x01D3BBDF | 0x01D3C0E0 | 0x01D3C106 |
| hl-3329 | 0x01D3B830 | 0x01D3B8DF | 0x01D3BDE0 | 0x01D3BE06 |
| hl-3647 | 0x01D3B960 | 0x01D3BA0F | 0x01D3BF10 | 0x01D3BF36 |
| hl-4554 | 0x01D468F0 | 0x01D4699F | 0x01D46EB0 | 0x01D46ED6 |

| Build | Registry helper | Q_strncpy helper | Set english PUSH (comparison only) | Fallback english PUSH (comparison only) |
| --- | --- | --- | --- | --- |
| hl-3248 | 0x01DB9980 | 0x01D2C490 | 0x01D3BC50 | 0x01D3C149 |
| hl-3266 | 0x01DB9980 | 0x01D2C470 | 0x01D3BC30 | 0x01D3C129 |
| hl-3329 | 0x01DB9040 | 0x01D2C120 | 0x01D3B930 | 0x01D3BE29 |
| hl-3647 | 0x01DB8220 | 0x01D2C240 | 0x01D3BA60 | 0x01D3BF59 |
| hl-4554 | 0x01DC3D50 | 0x01D36720 | 0x01D469F0 | 0x01D46EF9 |

### Complete relevant dataflow

1. Both owners allocate `char language[128]`, zero its first byte, and call the
   five-argument registry helper with subkey `Software\\Valve\\Steam`, value
   `Language`, destination `language`, capacity 128, and an empty default.
   All ten default pointers are in the PE .data zero-fill region.
2. The registry helper first does `sprintf(destination, "%s", defaultValue)`.
   For these callers the default is empty. It accepts a capacity at most 1024
   and queries into its own 1024-byte stack buffer, passing 128 as the query
   size for language.
3. On a successful REG_SZ query it calls an out-of-line
   `Q_strncpy(destination, registryBuffer, capacity)`, then explicitly writes
   `destination[capacity - 1] = 0`. If a key is newly created or the query fails,
   it writes the default value to the registry; other failure/type paths retain
   the initially copied default.
4. Q_strncpy obtains source/destination/count from stack arguments, checks source
   and current character, decrements the runtime count, and copies one byte at
   a time. It terminates on NUL or exhausted count and appends NUL when the
   remaining signed count is positive. No fixed 7/8-byte copy optimization exists
   in these five copy helpers. At capacity 128, the registry caller's final
   store guarantees byte 127 is NUL.
5. Back in each owner, `repne scasb; not ecx; dec ecx` computes language length.
   Empty language bypasses localization. Nonempty language is passed to
   `__strcmpi(language, "english")`; zero result also bypasses localization.
6. SetGameDirectory retains this boolean and formats localized GAME (when the
   game differs from the default) and DEFAULTGAME paths using the local language
   buffer. Its helper for liblist fallback paths also receives this boolean and
   buffer. Subscription gating may return before path construction.
   AddFallbackGameDir formats `base/game_language`, adds it under GAME when
   localized, and always adds the original game directory under GAME.
   Neither inspected owner has a SteamApps-language or default-English copy
   branch.

For example, hl-3248 fallback: registry CALL `0x01D3C126`; strlen scan
`0x01D3C137`; English operand PUSH `0x01D3C149`; strcmpi CALL
`0x01D3C14F`; local language address `0x01D3C15B`; localized format PUSH
`0x01D3C16E`; sprintf CALL `0x01D3C174`; localized AddSearchPath
`0x01D3C191`; unconditional base-path AddSearchPath `0x01D3C1A2`.

### Correct consumer direction and constraints
The user selected a function-level InlineHook on the five-argument registry
reader, filtered by the complete implicit-HKCU subkey `Software\\Valve\\Steam`
and the exact value name `Language`, both case-insensitive. This supersedes the
earlier recommendation to export two filesystem call-site patches. Other values,
keys and roots pass through unchanged. All engine callers of that same language
item intentionally share the override.

The hook invokes the original trampoline with unchanged arguments/default first,
then applies nonempty `-forcelang` to the output buffer with capacity enforcement
and NUL termination. Without a forced value, the old engines' existing registry
language is retained (they already read Steam language, regardless of
`-steamlang`). The effective output, including truncation, is copied to
`m_szCurrentGameLanguage`.

These old readers recognize an HKLM prefix but do not strip an explicit HKCU
prefix, so only the unprefixed complete Steam key is matched. Do not conflate
this five-argument engine ABI with VGUI2Extension's existing six-argument
`Sys_GetRegKeyValueUnderRoot(HKEY, ...)` helper. Changing the default-value pointer
would not force a language and could persist it through missing-value writes;
the implemented override changes only the output after the original read.
### Verification and reproducibility

The temporary audit is in `.candidates/language-inline-audit/`: `probe.py`,
five `<tag>.json/.txt` IDA exports, `verify_raw.py`, five `<tag>-copy.txt`
raw Capstone helper dumps, `summary.txt`, and `raw-verification.json`.
All 2,779 exported instructions (ten filesystem owners plus five registry
helpers) matched bytes independently read from PE section mappings:
556 each for hl-3248/3266/3329/3647 and 555 for hl-4554, zero mismatches.
Copy helpers were separately decoded directly from PE bytes.
These are static checks; no game launch or runtime patch test was performed.

| Analysis binary | SHA-256 |
| --- | --- |
| hl-3248 hw.decrypt.dll | 7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0 |
| hl-3266 hw.decrypt.dll | d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21 |
| hl-3329 hw.decrypt.dll | 4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480 |
| hl-3647 hw.decrypt.dll | 7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110 |
| hl-4554 hw.dll | 482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3 |

## Registry reader finder and consumer implementation (2026-09-28)

- Producer: `ida_preprocessor_scripts/find-Sys_GetRegKeyValueUnderRoot.py`;
  Pattern A through `preprocess_common_skill`, intersecting exact
  `HKEY_LOCAL_MACHINE` and `String` string owners. Exactly one owner and a unique
  generated function signature are required. Old YAML is not used as a discovery
  shortcut. The short `%s` string is not a locator input because normal IDA string
  lists can omit it.
- Registered as a Windows `func` in hl-3248/3266/3329/3647/4554 only. All five
  artifacts match the audited VAs above, have function size 0x132, and contain
  a 46-byte signature. Raw PE section scans independently require exactly one
  match at the expected VA/RVA and wildcard every overlapping HIGHLOW relocation.
- Consumer: `D:/MetaHookSv/Plugins/VGUI2Extension/LanguageRegistry.h` contains
  tested filtering, original-call sequencing, bounded override and effective
  language capture. `exportfuncs.cpp` supplies command-line policy.
  `privatefuncs.cpp` resolves the optional function through the real engine
  module identity, installs/removes the InlineHook in Engine_InstallHooks /
  Engine_UninstallHooks, and skips the old language-call scan when this reader
  is present. Other engine identities retain the prior FileSystem_SetGameDirectory_V_strncpy_callsite_0 path.
- MetaHook's catalog gate requires this FUNCTION on those five engine snapshots
  and validates its kind/module when present elsewhere; client-only snapshots
  do not acquire an engine requirement.
- Validation: all five exact finder nodes ran (5 succeeded, 0 failed, no skips);
  all five raw signatures matched uniquely at the audited addresses;
  `format_repo_files.py --check` passed;
  `tests/run_test_suite.py all -b --durations 10` ran 1232 tests, OK (9 skipped,
  including unavailable local Redis integration and opt-in IDA integration).
  The real IDA finder runs above are independent of the skipped integration test.
- MetaHook validation: isolated Win32 C++ tests first failed without the override
  and then passed; they cover original/default preservation, exact key/value/root
  filtering, case handling, empty/absent overrides, truncation, capacity 1/0/-1,
  null buffers, and bounded capture of a nonterminated source. Script tests:
  153 passed, 2 skipped, 635 subtests passed. VGUI2Extension Release and Debug
  Win32 builds succeeded.
- Local catalog: generated five guarded snapshots/JSON datasets from current
  artifacts, retaining the other 16 existing datasets. Offline integrity and
  all consumer gates passed for the resulting 21-snapshot catalog, then for
  `D:/MetaHookSv/Build/svencoop/metahook/gamedata`. Original local catalog is
  retained in `intermediate/language-registry/original-gamedata`.
  No online release/push was performed and no in-game execution was tested.
