---
title: engine locator
type: note
permalink: goldsrc-vibesignatures/locators/engine
tags:
  - locator
  - engine
  - gv
---

# eng

## Symbol

- **Name**: `eng` (the engine module's `IEngine*` slot; exact ELF/DWARF identity)
- **Former artifact identity**: `engine` (renamed in issue #303; the module remains `engine`)
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-RunListenServer.py`
- **Outputs**: `RunListenServer.{platform}.yaml` (`func`) and `eng.{platform}.yaml` (`gv`), sharing the same discovery and inspected function.

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- The 15 configured platform pairs comprise 11 Windows binaries and Linux for hl-8684,
  hl-10210, svencoop-8948 and svencoop-10257. The four old BLOB versions use hw.decrypt.dll.
- Platforms: Windows + Linux.
- Inlined / absent: the slot itself always exists. Note it is *not* an inline case but a
  data slot whose neighbours get inlined away — see the `Sys_InitArgv` pitfall.

## Predecessors

- None. `expected_input` is empty; the anchor is a target-owned literal.

## How it is located

1. Find the exact literal `"Sys_InitArgv( OrigCmd )"` (owned by `RunListenServer`,
   `engine/sys_dll2.cpp`) and require exactly one function owner.
2. Locate the string-reference instruction in that body: an absolute dword operand, or a PIC
   `lea reg, [ebx+disp32]` resolved against the owner's ebx GOT anchor.
3. Within the next `TRACEINIT_WINDOW = 6` instructions find the first `call` — that is the
   `TraceInit` call.
4. Starting after the `TraceInit` instruction, scan up to `SCAN_WINDOW = 60` instructions for
   the first `mov reg, [abs]` (or PIC `lea reg, [ebx+disp32]`) whose target is writable data
   and whose **static dword value** is non-zero and points at writable data. The loaded
   register must be dereferenced within the next `DEREF_WINDOW = 6` instructions by a
   `mov r, [reg+disp]`.
5. That slot is `eng` (the code immediately runs `eng->SetQuitting(QUIT_NOTQUITTING)`).
6. Emit the GV with `gv_va` = the slot, `gv_sig` = `RunListenServer`'s `func_sig`,
   `gv_inst_offset/length/disp` from the load, plus `gv_resolution_fields_via_mcp` (which
   carries `gv_pic_addend` for PIC sites).

## Pitfalls

- Inlined `Sys_InitArgv` (hl-10210 hw.so) loads `com_argc`/`com_argv` *before* `eng`. Those
  slots are zero in the static image, so the non-zero-static-pointer requirement rejects
  them — do not relax it.
- hl-10210 / svencoop Windows place the `CEngine` object 8 bytes after the slot; adjacency is
  normal and must not be treated as a mismatch.
- The vtable index confirms the role: `SetQuitting` is vtable `+0x40` on Windows, `+0x44` on
  Linux.
- Discovery never uses a byte signature or a prior artifact signature; the `gv_sig` prologue
  signature is generated only after the locator validates the current-binary instruction.

## Issue #303 consolidation

- Trigger: `engine` was a MetaHook-side field name; the ELF/DWARF global is `eng`.
- Constraint: module identity remains `engine`; only the symbol/artifact identity changes.
- Approach: merge the old global finder into `find-RunListenServer.py`, discover the owner once, and emit both the function and the global using the same validated signature.
- Verification: the 2026-09-29 all-gamever finder run reported zero failed skills. All 15 new `eng` payloads matched the old `engine` payloads exactly after excluding `gv_name`. `hl-3266` was generated through the user-owned IDA session at port 13337 and then skipped as already present by the batch; that session was neither saved nor closed.
- Scope: all 11 engine configurations / 15 platform pairs; no compatibility alias for the old global name. Existing note permalink is retained for incoming memory links.

## Runtime interface anchors (#303, A3–A5)

- `find-engine-runtime-vtables.py` produces `CEngine_vtable` and `CGame_vtable` for all 15 engine/platform pairs. Exact MSVC TypeDescriptor/primary COL ownership or exact Itanium symbols plus typeinfo establish class identity. Entry scanning rejects null pointers and never copies a reference build's length.
- HL25 Windows keeps raw RTTI but its restored IDB does not name these tables: raw RTTI resolves `CEngine` at `0x102c83a4` and `CGame` at `0x102c86d8`. Substring lookup for `CEngine` can incorrectly select `CEnginePanel`; do not use it.
- `eng`'s static object vptr is not a universal derived-table validator. Old BLOB objects are uninitialized; Sven's static object initially carries the IEngine base table. Constructors establish the derived vptr at runtime.
- `find-IVideoMode_UpdateWindowPosition.py` uses Pattern F slot-only inheritance from the existing `CVideoMode_Common_UpdateWindowPosition` artifact. It emits `func_name: IVideoMode::UpdateWindowPosition`, `vtable_name`, index and offset only. HL25's inserted slot is inherited from its own producer, not hardcoded again.
- Verification on 2026-09-30: both all-gamever finder runs exited successfully; 30 generated vtables matched the independently recorded current-IDB entries, and all 15 interface slot artifacts matched their current concrete producers. No new body locator or shared-helper contract was introduced.

## Launcher interface roles (#303, A6–A7)

- Trigger: interface slots differ across ABI and HL25 layouts; the issue's IEngine_Init spelling actually refers to IGame::Init.
- Constraint: derive slots from current RunListenServer dataflow and CFG, without a version-specific slot list, call ordinal or instruction window. Initialization argument/branch roles, dominating SetQuitting(0), cyclic GetQuitting/Frame dispatch and Load-failure cleanup identify eight roles; duplicate cleanup sites must agree. Actual this must match the dispatch receiver, and current concrete tables bound all slots.
- Implementation: find-RunListenServer-slots.py uses the shared x86 virtual-call decoder and the pure _engine_runtime_slots selector. Slot-only artifacts contain only source-qualified identity, interface name, byte offset and index. find-CEngine_Frame.py uses Pattern F inheritance with IEngine_Frame and the current CEngine_vtable, generating the concrete signature after discovery.
- Verification on 2026-09-30: both real all-gamever runs succeeded for all 15 configured engine/platform pairs, zero failed. All 120 interface outputs match separately captured current-IDB role evidence; all 15 concrete Frame outputs match their current slot/table. Six new synthetic behavioral tests cover unrelated slot numbering, ABI arguments, cleanup ambiguity, dominance, receiver agreement and alignment. Full suite: 1256 tests, OK with 9 environment/opt-in skips. Formatting and staged diff checks passed.
- Scope: all 11 configured engine versions, including four decrypted BLOB inputs, HL25, Sven and CoF; Linux is tested for the four configured Linux engines. No unsupported Windows-only path is imposed on Linux.

## Frame activity/audio slots and native wait signature policy (#303, A8–A9)

- Trigger: recover IGame::IsActiveApp, IGame::SleepUntilInput and ICDAudio::Frame through CEngine::Frame; inherit the concrete CGame::SleepUntilInput from its current primary table.
- Constraint/approach: the activity call's zero-only reachable region contains a same-receiver wait dispatch; the sole other global-receiver virtual dispatch dominates the activity test. Require receiver/argument agreement, unique aligned slots, and current CGame table bounds. Do not use call ordinals, known indices or the 20/50 timeout values (merged reaching values may lose the latter).
- User-approved exception: omit func_sig for the short native CGame::SleepUntilInput wrapper. The finder recognizes its sole MsgWaitForMultipleObjects dispatch from imports and actual instructions, without a version list or size threshold. It retains func_va, func_rva, func_size and current vtable slot. SDL event-loop implementations retain normal unique signatures.
- Boundary handling: several old restored IDBs do not define this virtual-only function. Reuse the existing exact-entry recovery before Pattern F, including the signature-disabled path; the entry is proven by the current CGame table, never by scanning back to a guessed prologue.
- Verification on 2026-09-30: both all-gamever runs succeeded for all 15 engine/platform pairs, zero failed. 45 interface artifacts match separately captured flow evidence; 15 inherited Sleep addresses match the current table. Six native outputs (hl-3248/3266/3329/3647/4554 and cof-5936, Windows) omit func_sig; nine SDL outputs retain it. Shared CFG refactoring was checked against all 15 captured RunListenServer flows and 15 Frame flows. Seven new synthetic behavioral tests pass; full suite: 1263 tests, OK with 9 environment/opt-in skips. Formatter and staged diff checks passed.

## Native CGame window methods (#303, A10–A11)

- Scope: Windows hl-3248/3266/3329/3647/4554 and cof-5936 only. SDL engines and Linux do not consume this native-path finder.
- find-CGame-native-window.py locates CGame::CreateGameWindow through exact Valve001/game.ico ownership intersected with the current CGame_vtable (Pattern B); the resulting index comes from that table. Missing virtual-only function definitions are recovered only at current table-proven exact entries using the existing recovery helper.
- CGame::WindowProc uses two source-owned instruction constants, SC_CLOSE (0xF060) and SC_SCREENSAVE (0xF140), via the shared signature-xref locator (Pattern A). Both must also be decoded cmp immediates in the chosen body; a current eng/IEngine_GetQuitting dispatch verifies receiver and method identity before either output is written.
- Constraint: do not require bytes 00 00 CB 84 for CreateGameWindow. Five HL builds encode that style directly, while CoF computes it with OR/AND; both target-owned strings plus table membership are unique on all six builds. Generated function signatures only validate the located outputs and never participate in discovery.
- Verification on 2026-09-30: all six applicable engine binaries produced both artifacts; twelve addresses and sizes match the independent current-IDB evidence, and signatures are unique. The all-gamever invocation successfully processed five HL targets then stopped when it reached an SDL config where the finder is intentionally absent; CoF was run separately and succeeded. Full suite: 1263 tests, OK with 9 environment/opt-in skips; formatting and staged diff checks passed. No new shared algorithm was introduced, so real-binary checks and existing regression tests provide the meaningful coverage instead of finder-source inventory tests.

## Event-interface slots (#303, A12)

- Module/category: engine, six slot-only interface vfuncs. Producer: find-engine-event-slots.py, using the pure select_event_slots role selector and existing x86 dataflow/exact-entry recovery.
- IEngine::TrapKey_Event: the unique current CEngine table method whose resolved direct callee is current Key_Event. Use the decoder's resolved direct identity: svencoop-8948 Linux encodes a PLT call, not the Key_Event body address.
- IEngine::TrapMouse_Event: the unique method guarding the same trapping byte and reciprocally writing the button argument/key-zero fields inferred from TrapKey_Event's key-argument/button-zero stores. No member offsets are fixed; svencoop-8948 Linux uses a different trapping-field layout.
- IEngine::IsTrapping: the unique getter returning that trapping-byte load without calls or non-stack writes. SDL event processing does not call it directly, but the getter exists in every current CEngine table.
- IEngine::GetState: the unique getter returning Frame's zero-tested DLL-state dword, cross-checked against an eng dispatch in the event owner. A cmp-return-to-1 anchor is not universal after Linux optimization/devirtualization.
- IVideoMode::IsWindowedMode: the unique event-owner videomode slot after excluding the already verified IVideoMode::UpdateWindowPosition; validate receiver/argument agreement and current table bounds.
- IGame::SetWindowXY: establish game from the existing Frame activity/wait relationship. Native WindowProc has one game dispatch; SDL position/size setters are distinguished by the IsWindowedMode true-only region. Stop traversal on re-entry to the condition block, otherwise the event loop makes both branches reach subsequent iterations.
- Verification: all 15 engine/platform pairs ran successfully with zero failed skills and produced 90 artifacts matching independent current-IDB role evidence. All slots fit their current class tables. Exported production flow payloads are approximately 14–19 KB, avoiding the large research response truncation seen when exporting unused decoder state.

## HandleSDLEvent inline coverage (#303, A13)

- Trigger/constraint: the requested helper may be inline; its source name must not be assigned to the entire SleepUntilInput caller.
- On all nine configured SDL targets, the common owner of SDL_DestroyWindow, SDL_GetRelativeMouseState and SDL_WarpMouseInWindow is CGame::SleepUntilInput. Excluding SDL_WaitEventTimeout leaves no standalone candidate. Current IDB/ELF names contain no separate HandleSDLEvent or SDLEventWatcher, and the event cases are visible in the Sleep body.
- Approved handling: record the inline status and reuse CGame_SleepUntilInput for the event slots. Do not emit a fabricated CGame_HandleSDLEvent function alias or an unvalidated standalone fallback. Native Windows engines have no SDL path, so this helper is not applicable there.

| SDL target | Platform | Verified inline owner VA |
| --- | --- | --- |
| hl-6153 | Windows | 0x1dadd10 |
| hl-8684 | Windows | 0x1daff40 |
| hl-8684 | Linux | 0x205050 |
| hl-10210 | Windows | 0x102241d0 |
| hl-10210 | Linux | 0x1b5c60 |
| svencoop-8948 | Windows | 0x1dbe6b0 |
| svencoop-8948 | Linux | 0x1d05a0 |
| svencoop-10257 | Windows | 0x1dbfcc0 |
| svencoop-10257 | Linux | 0x184690 |

These addresses are evidence for these binaries, never finder constants.

## Issue #303 delivered identities and support

All rows below are in module engine. Universal coverage means the 11 Windows targets and four Linux targets listed under Availability; native coverage means Windows hl-3248/3266/3329/3647/4554 and cof-5936. Unconfigured Linux engine versions are not claimed as tested.

| Results | Category | Support / evidence |
| --- | --- | --- |
| RunListenServer, Key_Event | func | Universal; exact target-owned literals and unique signatures |
| eng (formerly engine) | gv | Universal; shared RunListenServer discovery; prior global payload preserved apart from identity |
| CEngine, CGame | primary vtable | Universal; exact class RTTI/ELF ownership and current entries |
| IGame::Init, IEngine::Load, IVideoMode::Init | slot-only vfunc | Universal; launcher arguments and initialization branches |
| IEngine::Frame, IEngine::SetQuitting, IEngine::GetQuitting | slot-only vfunc | Universal; launcher CFG/call roles |
| IGame::Shutdown, IVideoMode::Shutdown | slot-only vfunc | Universal; Load-failure cleanup with consistent slots |
| CEngine::Frame | concrete vfunc | Universal; inherited current interface slot/table and unique signature |
| IGame::IsActiveApp, IGame::SleepUntilInput, ICDAudio::Frame | slot-only vfunc | Universal; Frame receiver/control-flow roles |
| CGame::SleepUntilInput | concrete vfunc | Universal; current CGame inheritance; six native short functions intentionally omit func_sig, nine SDL functions retain it |
| CGame::CreateGameWindow | concrete vfunc | Native only; exact strings and CGame table membership |
| CGame::WindowProc | func | Native only; decoded SC_* constants and eng quitting dispatch |
| IEngine::TrapKey_Event, IEngine::TrapMouse_Event, IEngine::IsTrapping, IEngine::GetState | slot-only vfunc | Universal; current CEngine method semantics and event cross-check |
| IVideoMode::IsWindowedMode, IGame::SetWindowXY | slot-only vfunc | Universal; event receiver/branch roles |
| IVideoMode::UpdateWindowPosition | slot-only vfunc | Universal; inherits existing CVideoMode_Common_UpdateWindowPosition instead of duplicating its locator |
| CGame::HandleSDLEvent | inline helper, no separate artifact | Nine SDL targets inline it; non-SDL targets are not applicable |

The issue's IEngine_Init spelling was corrected to IGame::Init. Frame/SetQuitting/GetQuitting belong to IEngine, and the concrete Frame belongs to CEngine, not CGame. Interface outputs contain only identity/table/offset/index; internal inferred member values are not extra artifacts. The issue-wide artifact audit covers 270 interface slots, 72 concrete functions (66 signatures and six native waits intentionally lacking func_sig), 30 primary tables and 15 renamed eng globals.

Final verification on 2026-09-30: all configured finder targets completed their real-binary checks, including 15/15 for the final event-slot finder and 6/6 native-window targets. The final artifact audit matched all 90 new event slots to separately captured role evidence and checked the issue-wide identities, interface field contracts, inherited addresses, table bounds, signature-presence policy and platform exclusions. Full suite: 1272 tests in 133.067s, OK (9 environment/opt-in skips); formatter and staged diff checks passed. New synthetic tests cover PLT resolution, reciprocal stores, getter ambiguity/side effects, receiver agreement and cyclic SDL branch exclusivity.
