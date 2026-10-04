---
title: Native UDP RCON Part A Locators
type: note
permalink: goldsrc-vibesignatures/native-udp-rcon-part-a-locators
---

# Native UDP RCON Part A Locators

## Overview

Issue [#326](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/326) Part A supplies engine-private function locations and the main-frame Cbuf call context for halflife-cli native UDP RCON. This repository delivers finders and artifacts; it does not implement consumer hooks or claim that the shipped engines already implement the behavior of HLND2T-DiligentGraphics `fc59dcb1307986c430859122a33f2a64ea756569`.

The anchors were surveyed in all 15 configured engine inputs and confirmed by the user before implementation. Part B/C/D remain outside this delivery, except `SV_CheckChallenge`, which is the approved prerequisite for recovering `NET_IsLocalAddress`.

## Responsibilities

- Locate the eight Part A functions with current-binary anchors, preserving actual ELF identities and genuine optimized entries.
- Locate `_Host_Frame(float)` and publish its unique Cbuf call instruction as a `patch`, never as a function.
- Reuse existing `Host_InitializeGameDLL` and `CEngine_Frame` finders/artifacts. Discovery always passes `old_yaml_map=None`; generated signatures are output checks.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-native-rcon-string-symbols.py`: `SV_CheckChallenge`, `SVC_ServiceChallenge`, `SV_Rcon`, `SV_Rcon_Validate`, `SV_FlushRedirect`; HL 8684 Linux companions.
- `ida_preprocessor_scripts/find-Host_InitializeGameDLL-rcon-decompiles.py`: grouped semantic recovery of `Cbuf_Execute` and `NET_Config`.
- `ida_preprocessor_scripts/find-SV_CheckChallenge-rcon-decompiles.py`: semantic recovery of `NET_IsLocalAddress`.
- `ida_preprocessor_scripts/find-native-rcon-frame-symbols.py`: `_Host_Frame`, `SV_CheckForRcon`.
- `ida_preprocessor_scripts/find-_Host_Frame_to_Cbuf_Execute_callsite_0.py`: main-frame `patch`.
- `ida_preprocessor_scripts/_native_rcon_common.py`: retained ELF identities, current-artifact verification, direct/tail-call graph traversal with ELF PLT resolution.
- `ida_preprocessor_scripts/references/{hl-10210,svencoop-10257}/engine/{Host_InitializeGameDLL,SV_CheckChallenge}.{windows,linux}.yaml`: eight references generated with `generate_reference_yaml.py` after restoring verified names and prototypes in exact-bound owned IDBs. Calls are named in disassembly and pseudocode. SvEngine netadr trailing address bytes remain opaque.
- `configs/<tag>.yaml`: engine skill dependencies and func/patch declarations. `bin_artifacts/<tag>/engine/<logical-name>.<platform>.yaml`: authoritative output path.

## Architecture

### Anchors and result contracts

All entries below belong to module `engine`. Except the explicit inline case, every function is an independently validated x86 function start. C functions use x86 cdecl; references recover prototypes rather than treating narrow Hex-Rays pseudo-parameters as a callable ABI.

| Result | Category / coverage | Anchor and verification | ABI / consumer limitation |
| --- | --- | --- | --- |
| `Cbuf_Execute` | func / 15 inputs | Existing initializer, anchored by exact `Sys_InitializeGameDLL called twice, skipping second call\n`; grouped LLM `found_call` selects command-buffer execution and checks current instruction/callee | `void(void)`; preserve the multi-buffer wrapper where present; initializer calls do not establish first-frame timing |
| `NET_Config` | func / 15 inputs | Same initializer/reference group; identify the network-configuration call with `svs.maxclients > 1`, not a call ordinal | `void(int32/qboolean)`; SvEngine has a short wrapper; output signature may cross its function boundary, explicitly flagged; consumer must preserve socket and bind choices |
| `SV_CheckChallenge` | func / 15 inputs, approved prerequisite | Exact own `SV_CheckChallenge:  Null address\n` (two spaces after colon), one literal/owner per input | `int32(netadr_t *, int32)`; supplies independently anchored predecessor |
| `NET_IsLocalAddress` | func / 15 inputs | LLM `found_call` from the local-address challenge bypass; own strings unavailable; tested byte candidates collide or exceed the four-pattern discovery budget | `int32(netadr_t by value)`; 20 bytes HL/CoF, 36 bytes SvEngine, verified by call-site copies; all inputs retain independent entries |
| `SVC_ServiceChallenge` | func / 15 inputs | Exact own `%c%c%c%cchallenge %s %u\n`; HL 8684 Linux additionally verifies current ELF wrapper identity, `Cmd_Argc()==2`, and the core edge | `void(void)`; on HL 8684 Linux menu dispatch reaches `.part.6`; hook the actual core if covering that path |
| `SV_Rcon` | func / 15 inputs | Exact own `Empty rcon\n`; HL 8684 Linux checks the two literal owners against current ELF entries | `void(netadr_t *)`; HL 8684 Linux menu uses `SV_Rcon.constprop.20(void)` with fixed `net_from` |
| `SV_Rcon_Validate` | func / 14 inputs; inline on HL 10210 Windows | Exact own `Banning %s for rcon hacking attempts\n`, excluding functions owning `Empty rcon\n` | `int32(void)`: 0 success, 1 password/parameter refusal, 2 challenge refusal, 3 failure/ban refusal; shipped targets reject empty password. SvEngine Windows also inlines validation into Rcon, so a standalone detour does not cover that copy |
| `SV_FlushRedirect` | func / 15 inputs | Exact own `Redirected Text`; RD_PACKET OOB print / NS_SERVER send, RD_CLIENT branch and buffer clearing corroborate identity | `void(void)`; observed native single-packet path lacks the reference branch's new 1200-byte chunk loop and redirect clear/restore protection; buffer capacity belongs to Part C |
| `SV_CheckForRcon` | func / 15 inputs | Main-frame direct callee uniquely reaching both current challenge and Rcon bodies directly or through one HandleRconPacket layer | `void(void)`; observed guards are dedicated, `!sv.active`, `giActive != DLL_CLOSE` (3), `host_initialized`; then NS_SERVER packet/ban/OOB dispatch. Calling it unchanged does not serve a listen-client main menu |
| `_Host_Frame` | func / 15 inputs, main-frame context | Current `CEngine_Frame` direct callee also calling Cbuf identifies outer Host_Frame; its unique direct callee also calling Cbuf identifies inner `_Host_Frame` | `void(float)`; outer frame remains an intermediate, not a new artifact |
| `_Host_Frame_to_Cbuf_Execute_callsite_0` | patch / 15 inputs | Unique direct call in the verified inner frame; current callsite/signature helper checks uniqueness | Five-byte E8 rel32 instruction; runtime return address is relocated callsite + 5. Distinguishes initializer, state-change and nested exec calls; artifact generation does not patch game bytes |

Graph traversal includes E8 calls and E9 tail calls to real function starts, resolves ELF PLT entries, and rejects ambiguous candidates. No discovery relies on hardcoded RVAs, field offsets, call ordinals, or a previous artifact signature.

### Coverage matrix

Logical module files are `hw.dll` on Windows and `hw.so` on Linux. Actual BLOB analysis uses the decrypted sibling. All supported inputs are PE32/I386 or ELF32/I386; absent platforms and configurations without an engine module are not registered.

| Tag | Platform / actual input | New func / patch count | Local-address semantics | Main Cbuf call RVA (evidence only) |
| --- | --- | --- | --- | --- |
| hl-3248 | Windows `hw.decrypt.dll` | 10 / 1 | NA_LOOPBACK only | 0x583b3 |
| hl-3266 | Windows `hw.decrypt.dll` | 10 / 1 | NA_LOOPBACK only | 0x58393 |
| hl-3329 | Windows `hw.decrypt.dll` | 10 / 1 | NA_LOOPBACK only | 0x580f3 |
| hl-3647 | Windows `hw.decrypt.dll` | 10 / 1 | NA_LOOPBACK only | 0x58213 |
| hl-4554 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK only | 0x62b73 |
| hl-6153 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK only | 0x56253 |
| hl-8684 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK or NA_IP exact 127.0.0.1 | 0x57683 |
| hl-8684 | Linux `hw.so` | 12 / 1 | NA_LOOPBACK or NA_IP exact 127.0.0.1 | 0x10f79e |
| hl-10210 | Windows `hw.dll` | 9 / 1; Validate inline | NA_LOOPBACK or NA_IP exact 127.0.0.1 | 0x1d4672 |
| hl-10210 | Linux `hw.so` | 10 / 1 | NA_LOOPBACK or NA_IP exact 127.0.0.1 | 0xa8fbb |
| svencoop-8948 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK only | 0x674b3 |
| svencoop-8948 | Linux `hw.so` | 10 / 1 | NA_LOOPBACK only | 0xca016 |
| svencoop-10257 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK only | 0x679b3 |
| svencoop-10257 | Linux `hw.so` | 10 / 1 | NA_LOOPBACK only | 0x7b1e6 |
| cof-5936 | Windows `hw.dll` | 10 / 1 | NA_LOOPBACK only | 0x7f171 |

Total: 151 function artifacts and 15 patch artifacts. HL 8684/10210's four platform inputs already satisfy the requested local-address predicate; the other eleven require consumer adaptation if that predicate is needed.

### ELF identities

HL 8684 Linux publishes the genuine independent `SVC_ServiceChallenge.part.6` (VA 0x13e000) and `SV_Rcon.constprop.20` (VA 0x144670), in addition to canonical `SVC_ServiceChallenge` (0x142150) and `SV_Rcon` (0x144940). These are binary evidence, never addresses used by finders. The clone has no address argument; the canonical Rcon retains the pointer argument.

SvEngine 8948 Linux retains C++ ELF symbols. Logical config names and file stems remain stable, while `func_name` is checked against and preserves the real ELF name:

| Logical identity | ELF func_name |
| --- | --- |
| Cbuf_Execute | `_Z12Cbuf_Executev` |
| NET_Config | `_Z10NET_Configi` |
| NET_IsLocalAddress | `_Z18NET_IsLocalAddress8netadr_s` |
| SVC_ServiceChallenge | `_Z20SVC_ServiceChallengev` |
| SV_Rcon | `_Z7SV_RconP8netadr_s` |
| SV_Rcon_Validate | `_Z16SV_Rcon_Validatev` |
| SV_FlushRedirect | `_Z16SV_FlushRedirectv` |
| SV_CheckForRcon | `_Z15SV_CheckForRconv` |
| SV_CheckChallenge | `_Z17SV_CheckChallengeP8netadr_si` |
| _Host_Frame | `_Z11_Host_Framef` |

Other configured ELF entries use C source identities or the verified source identity in stripped SvEngine 10257. The callsite patch keeps its own patch identity.

## Dependencies

- Existing `find-Host_InitializeGameDLL.py` and `find-CEngine_Frame.py`; their applicable artifacts were reused and left unchanged.
- `_engine_private_globals_common` current disassembly/walk/function-signature utilities, `_direct_gv_common` owner-artifact checks, `_func_to_func_callsites_common` callsite helper, and `renderer_elf_symbols` exact-current-file ELF parser.
- Static literal `LLM_DECOMPILE` declarations and repository semantic prompt; HL 10210 canonical references, SvEngine 10257 body overrides.
- Exact-input owned `IdaMcpLifecycle`, strict restored warm IDBs, project output/schema/unique-signature checks. Normal analyzer execution does not save IDB edits.

## Notes

### Source and binary evidence

- Official source: `D:/HLND2T_official/engine/host_cmd.c:63`, `cmd.c:188`, `net_ws.c:469,2090`, `sv_main.c:1998,2821,3541,3746,3776,7804`, `host.c:1088,1164,1264,1289`; common `netadr.h` gives the HL 20-byte layout.
- Reference behavior checked with `git show` at `fc59dcb1307986c430859122a33f2a64ea756569` in `D:/HLND2T-DiligentGraphics`; native UDP prerequisites also predate that commit. HLCLI helpers are not original engine symbols.
- Target code is the final truth. The official tree's unusual auth conditions do not justify transferring them into shipped-binary results. Findings here concern the configured binaries, not arbitrary builds with the same display version.
- No new private globals, field artifacts, shutdown functions, cvar scans, socket-open hooks, stdout hooks, or halflife-cli implementation are included.

### Verification evidence (2026-10-04)

- Before implementation, all 15 exact-input owned sessions surveyed strings/xrefs, current machine code/procedures, main-frame graph and ABI. Each relevant string/owner count and each graph layer was unique after documented optimizer handling; input paths, SHA-256 and 32-bit architecture were checked.
- Canonical predecessor batch: 4 nodes succeeded, no failures/skips. All eight reference CLI generations exited 0 after verified metadata restoration. An initial CLI start used the occupied default port; rerunning on allocated task-owned ports succeeded without touching the existing service.
- Complete forced batch selection: 11 tags, 15 binaries, 75 nodes. Successful run `analysis-batch-20261004T184155-4ab0bc5b407f48b185d0e0e1a2087ddc`: 75 successful, 0 failed, 0 skipped, exit 0. Configured LLM was deepseek-flash/high, concurrency 6 with 24000 MiB aggregate memory budget.
- Initial complete batch exposed non-unique short SvEngine NET_Config signatures. The existing explicitly flagged cross-function signature option corrected the output verification; all 15 binaries were then rerun. This is not a discovery-anchor change.
- Final rerun after explicit leading-underscore artifact declarations and E8 callsite enforcement: `final-analysis.log`, 75 successful, 0 failed/skipped, exit 0. Initial source-all exposed the repository's default filename sanitization; config `artifact` overrides preserve `_Host_Frame` and its patch path without changing shared contracts. Repository-contract rerun: 15 tests, OK (88.232s). Format check: 655 Python files unchanged and 29 YAML files unchanged, exit 0. Reference blank-line trailing whitespace was removed without changing instruction/procedure content.
- Required source-compatible suite: `uv run python tests/run_test_suite.py all -b --durations 30`, exit 0; 1389 tests in 194.574s, OK with 9 skips. Skips: three platform-specific POSIX/Linux cases, two opt-in release CLI smoke cases, three Redis suites (127.0.0.1:6379 unavailable), one opt-in IDA integration case. The separate actual finder batch covers all 15 exact engine inputs. Validation strategy uses real-binary semantic/address/signature checks and existing reusable tests, without tests freezing finder/config/reference/artifact text. Final `git diff --cached --check` is clean.
- Independent artifact audit: all 166 output identities/categories/VAs/RVAs agree with the pre-implementation binary survey, current input SHA-256 values are unchanged, and all eight references have exactly the four required keys with desired calls named in both representations. HL25 Windows has no fake Validate artifact.
- Local detailed discovery, lifecycle health, CLI logs, hash/address audit and selection files are in `C:/Users/HZDEV/AppData/Local/Temp/gsvibe-issue326-anchor/`; batch diagnostics are in `C:/Users/HZDEV/AppData/Local/Temp/gsvibe-analysis-diagnostics/`. These are local evidence paths, not required checkout inputs.

### Reusable failure pattern

- Trigger: a current function is semantically identified, but its normal function-only masked signature is ambiguous (e.g. a short SvEngine configuration wrapper).
- Cause: a wrapper's call relocations are masked and its remaining instruction shape is shared.
- Correct action: preserve the source-role anchor, enable the repository's explicit cross-function-boundary output-signature option, inspect the resulting artifact, and rerun the relevant binary validation. Never substitute a peer RVA or silently invent a different entry.
- Applicability: verified short wrappers only; this does not turn adjacent bytes into a cross-version discovery anchor.

## Callers

- `Host_InitializeGameDLL` calls Cbuf execution and network configuration during initialization.
- `CEngine::Frame -> Host_Frame -> _Host_Frame` establishes the main-frame context; the inner frame has one Cbuf call and calls the inactive-server RCON poller.
- HL 8684 Linux menu dispatch reaches the challenge core and no-argument Rcon clone. Active-server connectionless dispatch is a separate path; consumer menu polling must avoid duplicate queue consumption when `sv.active` is true.
