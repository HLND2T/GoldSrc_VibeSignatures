---
title: ServerBrowser history date callsites
type: note
permalink: locators/serverbrowser-history-date-callsites
---

# ServerBrowser history date callsites

## Trigger and root cause

MetaHookSv/MetaHookSv#925 reports Chinese corruption in the history list's
LastPlayed column. ServerBrowser initializes LC_TIME from the system locale,
formats `%a %d %b %I:%M%p` with narrow strftime, and passes those locale-encoded
bytes to KeyValues::SetString. ListPanel::GetCellText requests GetWString;
VGUI's GetLocalizedFromANSI ultimately decodes CP_UTF8. Chinese CP936 output is
therefore misdecoded. The date producer belongs to ServerBrowser, not GameUI.

Both hl-10210 and svencoop-10257 Windows VGUI2 binaries use code page 65001 at
the final conversion. An isolated Windows CRT experiment reproduced the
corruption; this is not an in-game runtime verification of a plugin fix.

## Locator and consumer contract

`ida_preprocessor_scripts/find-CBaseGamesPage-history.py` publishes:

- `CBaseGamesPage_ServerResponded` (the row-writing overload, not the thin
  matchmaking callback overload).
- `CBaseGamesPage_ApplyGameFilters`.
- `CBaseGamesPage_ServerResponded_to_strftime_callsite_0`.
- `CBaseGamesPage_ApplyGameFilters_to_strftime_callsite_0`, only where present.

The callsites are patch artifacts with unique signatures and instruction
addresses, without patch_bytes. They identify both indirect import calls and
direct calls into static CRT/PLT code. Consumers decode the actual instruction.
Do not require a strftime IAT entry: Sven statically links its Windows CRT.

Intended repair: scope the original row-processing calls, intercept only these
formatting calls to capture a correct wide date, and forward the matching
SetString("LastPlayed", buffer) to native SetWString. Leave the original narrow
buffer available to the original lowercase logic. This avoids patching Windows
_strlwr and Linux's inlined tolower loops. The plugin repair is separate work.

## Current-binary evidence

The player-count format discovers row writers. Exact column literals narrow
their ownership. An x86 dataflow walk verifies the stack-local date buffer,
64-byte capacity, exact date format, time-producer result, and the same buffer's
unique LastPlayed write. The server pointer comes from a parameter in
ServerResponded and from stored/fetched entries in ApplyGameFilters.

Legacy filter loops lack the date call. Their two filter dispatch slots are
recovered from the current ServerResponded body and matched on the same page
and fetched server. No fixed vtable offsets or old-version artifacts discover
the owners. ABI checks inspect reachable returns; Sven tail calls are checked
against the current primary CBaseGamesPage vtable and its callee's cleanup.

GCC leaves outgoing argument slots live across later calls such as
__ctype_tolower_loc. A matching stale format pointer is insufficient: the
formatter must be the first call consuming the time-producer result.

## ABI differences: do not install one global wrapper signature

Windows ServerResponded:

- hl-3248/3266/3329/3647: one explicit server argument, RET 4. The callback body
  receives the interface subobject pointer used by its original caller.
- Other configured Windows targets: server index and server pointer, RET 8.

Windows ApplyGameFilters:

- hl-3248/3266/3329, hl-10210, svencoop-8948/10257: this in ECX, no stack arguments.
- hl-4554/6153/8684: this passed on the stack, RET 4 (optimized internal ABI).
- hl-3647 and cof-5936: this in EAX, no stack arguments (optimized internal ABI).

Linux uses the ordinary i386 explicit-this calling convention. All four
configured Linux nodes have both formatting callsites.

The six Windows hl-3248/3266/3329/3647/4554/6153 nodes and cof-5936 do not format
LastPlayed in ApplyGameFilters. Their configs deliberately omit that patch.
Do not manufacture a callsite, reinterpret another call, or assume that absence
means the ApplyGameFilters function itself is absent.

## Validation procedure

Run all configured ServerBrowser nodes with a fresh artifact directory, using
copies of the original binary and i64 files if the originals have IDA locks:

```text
uv run python ida_analyze_bin.py -allgamever -modules serverbrowser -skill find-CBaseGamesPage-history -platform windows,linux -bindir <copies> -artifactdir <fresh-output> -maxretry 1 -debug
```

Expected inventory: 11 game versions, 15 platform nodes, 53 YAML artifacts
(30 functions and 23 callsites). CS-family client-only configs do not declare
ServerBrowser; shared Half-Life platform binaries are covered by the hl tags.
Check unique signatures, identities, and config coverage, then run the unit,
repository-contract and repository-format suites. No source-text/config snapshot
tests are needed for this routine finder addition.

2026-10-17 verification: a fresh-output allgamever run passed all 15 nodes with
zero failures, producing 53 validated artifacts. The 15 analyzed native binary
copies matched the originals by SHA-256. Unit suite: 1516 tests, 12 skipped;
repository-contract suite: 15 tests; repository format check and the finder's
explicit Ruff format check passed. No plugin runtime change was made.
