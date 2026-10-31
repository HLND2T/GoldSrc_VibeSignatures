---
title: ClientPortalManager_m_bStudioRenderPlayerPending locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-studio-render-player-pending
tags:
  - locator
  - client
  - structmember
---

# ClientPortalManager.m_bStudioRenderPlayerPending

Producer: `find-ClientPortalManager_m_bStudioRenderPlayerPending`.
Required predecessor: `ClientPortalManager_ResetAll`.
Artifact identity: `struct_name: ClientPortalManager`,
`member_name: m_bStudioRenderPlayerPending`, `size: 1`.

The member name describes recovered behavior, not a confirmed C++ source name.
It is a one-shot request consumed by
`P_ShouldGameStudioModelRendererRenderPlayerModel` (the 8948 Linux symbol names
the accessor). It is not shader availability or the persistent portal-rendering
global. Studio can consume it before a map/local player exists.

## Independent binary evidence

| Build | Platform | Offset | Reset store VA | Read/clear accessor VA |
| --- | --- | --- | --- | --- |
| 10257 | Windows | `0x1e8` | `0x1004dd46` | `0x1004b1e0` |
| 8948 | Windows | `0x1e8` | `0x1009611b` | `0x100934a0` |
| 10257 | Linux | `0x1dc` | `0xf99ea` | `0xf9fdc` |
| 8948 | Linux | `0x1dc` | `0x15b758` | `0x15bd9a` |

These addresses are evidence only, never finder inputs/constants. Each offset
is independently decoded from its own binary; do not transfer the Windows
displacement to Linux.

## Locator and signature contract

1. Read and identity-check the current `ResetAll` predecessor.
2. Trace the reset prefix from the ABI's manager argument (Windows ECX, Linux
   first stack argument), including register copies, stack adjustment, forward
   branches, GCC PC thunks and MSVC's SSE stack-local zeroing.
3. Collect only this-owned one-byte zero stores before native cleanup calls.
   Do not accept the later shader-availability clear or stack-local stores.
4. Inspect the reset's callers and at most two further caller levels. Resolve
   ELF PLT references with the shared resolver. This covers Windows's inlined
   singleton creation and Linux's shared `P_PortalInit` helper.
5. Require a matching one-byte read into AL (or zero-extension into EAX),
   immediately followed by clearing the same memory operand, with that old
   byte preserved to the return. The accessor must call the reset or its
   bounded initializer chain. Missing/conflicting evidence fails closed.
6. Generate the shortest unique forward instruction signature from the reset
   store. Fix **every byte of the first instruction**, including its
   displacement and zero immediate. Subsequent instructions retain the shared
   relocation masking. Expand only on complete instruction boundaries.

All four binaries already have a unique seven-byte first instruction:

- Windows: `C6 87 E8 01 00 00 00`.
- Linux: `C6 86 DC 01 00 00 00`.

Both signatures start at the member access (`offset_sig_disp: 0`); no absolute
address, scan fallback, global artifact, or invented scalar is published.

## Validation boundaries

2026-10-31: independently disassembled all four original binaries from the
pinned binary submodule with Capstone, replayed the pure reset/accessor proof,
decoded store width/displacement, and verified each emitted signature matches
exactly once in the entire corresponding binary. Synthetic tests vary layouts
and cover ABI differences, initializer indirection, PC thunks, SSE locals,
wrong object/width/value, mismatched clears, return clobbers and ambiguity.
Both tags passed local snapshot build/verification and snapshot, JSON and
gamedata candidate guards. The derived JSON was checked for the canonical
`ClientPortalManager.m_bStudioRenderPlayerPending` identity, `structMember`
kind, platform-specific displacement and exact unique signature. These checks
did not publish any release or modify the binary submodule pointer.
`tests/run_test_suite.py all -b --durations 15`: 1594 tests, OK, 17 skips
(including unavailable Redis and opt-in/platform-specific integration gates).
`format_repo_files.py --check` passed.

The local machine has no activated IDA/idalib environment. Full current-IDB
preprocessor execution remains an upstream IDA validation gate; Capstone and
mocked adapter tests are not claimed as commercial IDA execution.

The consuming StandaloneView change and publication/release are separate.
