---
title: Native UDP RCON Part B Symbols
type: note
permalink: goldsrc-vibesignatures/native-udp-rcon-part-b-symbols
---

# Native UDP RCON Part B Symbols

## Overview

Issue [#326](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/326) Part B locates the native packet, ban, authentication helper, command and redirect functions for halflife-cli. Anchors, current-data-xref derivation and four Sven Windows function-boundary recoveries were confirmed by the user before implementation. This delivers engine symbols and artifacts; protocol integration remains a consumer task.

## Responsibilities

- Produce 146 new `func` artifacts for 10 logical functions across 15 applicable x86 engine inputs.
- Reuse all 15 existing `SV_CheckChallenge` artifacts from merged Part A [PR #327](https://github.com/HLND2T/GoldSrc_VibeSignatures/pull/327); do not add another producer.
- Preserve actual ELF names and distinguish retained callable helpers from inline blocks.
- Keep intermediate data addresses internal. No Part C global/field artifacts or Part D shutdown locators are added.

## Involved Files & Symbols

- `ida_preprocessor_scripts/_native_rcon_common.py`: current dependency verification and retained Sv8948 ELF identities.
- `_native_rcon_path_common.py`: exact literal bytes, current operand/xref walks, PLT-aware call edges, parameter provenance and proven orphan boundary recovery.
- `find-native-rcon-path-string-symbols.py`: NET_SendPacket, SV_AddFailedRcon.
- `find-SV_CheckForRcon-native-path-decompiles.py`: NET_GetPacket and Windows SV_FilterPacket.
- `find-SV_Rcon-native-path-decompiles.py`: Cmd_ExecuteString.
- `find-native-rcon-packet-symbols.py`: SV_SendBan, SV_HandleRconPacket.
- `find-native-rcon-filter-symbols.py`: retained Linux SV_FilterPacket.
- `find-native-rcon-failure-symbols.py`: SV_CheckRconFailure.
- `find-native-rcon-redirect-symbols.py`: SV_BeginRedirect, SV_EndRedirect.
- Eleven engine configs register 92 new applicable skill nodes; `bin_artifacts/<tag>/engine/<logical-name>.<platform>.yaml` contains authoritative outputs.
- Eight CLI-generated references: `SV_CheckForRcon` and `SV_Rcon`, Windows/Linux, under `references/hl-10210/engine/` and `references/svencoop-10257/engine/`.

## Architecture

Every result below is module `engine`, category `func`, an actual callable x86 entry. Addresses used during derivation are evidence, never separate global/field symbols.

| Logical function | Discovery and acceptance | Support | cdecl ABI |
| --- | --- | --- | --- |
| NET_GetPacket | LLM `found_call` from verified SV_CheckForRcon: Boolean NS_SERVER receive loop. Exact target instruction/callee is validated; queue/loopback and net_from/net_message writes corroborated in the source/binary survey. | All 15 | int32(int32 netsrc) |
| SV_FilterPacket | Windows grouped `found_call` from the same poller rejection predicate. Linux current float32 filterban operand and its data xrefs, with mask comparison, expiry/removal and conversion-to-reject body checks; only optional memmove calls. HL8684 Linux retains a direct filtering call, so its current callees seed the same operand search. HL10210/Sven Linux inline filtering in the poller but retain independent helper bodies. | All 15 | int32(void), nonzero rejects |
| SV_SendBan | Own exact `You have been banned from this server.\n` bytes/xrefs; exclude NET_GetPacket callers; require current NET_SendPacket edge, -1/108/NS_SERVER constants and repeated native clear call. Raw bytes support Linux constant DWORD-array literals. | All 15 | void(void) |
| SV_HandleRconPacket | Own getchallenge/challenge/rcon xref intersection; exclude connect owners and NET_GetPacket callers. Require current SVC/Rcon dispatch edges, including genuine HL8684 Linux optimized cores. Full MSG read/tokenize/Argv protocol body corroborated in survey. | 14; HL25 Windows inline only | void(void) |
| SV_CheckChallenge | Reuse Part A finder/artifacts unchanged. | All 15 | int32(netadr *, int32 challenge) |
| SV_CheckRconFailure | From independently anchored AddFailedRcon's actual storage xrefs and comparator; require separate read-only active/address/reject Boolean loop. Candidate proximity only seeds a search; comparison call, global writes, backward loop and true/false exits determine acceptance. No reference-build record offset/stride is an output. | 14; HL25 Windows inline only | int32(netadr *) |
| SV_AddFailedRcon | Own exact `User %s will be banned for rcon hacking\n`; exclude `Banning %s for rcon hacking attempts\n` owner to remove HL8684 Linux's inline Validate copy. Current clamps, history and shouldreject writes corroborated in survey. | All 15 | void(netadr *) |
| Cmd_ExecuteString | LLM `found_call` from verified SV_Rcon: strip rcon/challenge/password, execute synchronously with src_command=1 within native redirect. Keep the real two-argument privilege wrapper; do not substitute the compiler's internal command core. | All 15 | void(char *, int32 cmd_source) |
| SV_BeginRedirect | FlushRedirect's actual mode operand (RD_PACKET=2 dispatch) and terminal output-byte clear -> current storage xrefs. Require incoming mode parameter store, reply-copy address shared with Flush, incoming address pointer and same buffer clear; current 20/36-byte copy ABI corroborated in survey. | 14; HL25 Windows inline only | void(int32 redirect, netadr *) |
| SV_EndRedirect | Current direct/PLT-resolved FlushRedirect callers and actual mode. Separate body's only semantic call is FlushRedirect, then mode=0 and return. Inline Rcon/Drop/printf owners are excluded by current body evidence. | 14; HL25 Windows inline only | void(void) |
| NET_SendPacket | Own exact `NET_SendPacket: bad address type`, unique literal/owner on all inputs. Current NA_LOOPBACK/native non-loopback dispatch corroborated. Sven entry delegates non-loopback transport to its native internal wrapper; that wrapper is not the requested symbol. | All 15 | void(int32 netsrc, int32 length, void *, netadr **by value**) |

### Coverage and ABI

- All supported binaries are PE32/I386 or ELF32/I386; pointers, integer arguments and enum representations are 4 bytes.
- Windows HL3248/3266/3329/3647 are BLOB inputs: config module hw.dll, actual analysis input hw.decrypt.dll. Remaining Windows engine inputs use hw.dll; Linux uses hw.so.
- HL/CoF netadr is 20 bytes; Sven is 36 bytes. NS_SERVER=1, src_command=1, RD_NONE=0, RD_CLIENT=1, RD_PACKET=2. Incidental decompiler EAX/char returns do not turn source void routines into value-return APIs.
- HL10210 Windows has no independently callable HandleRconPacket, CheckRconFailure, BeginRedirect or EndRedirect. Those four outputs and config symbols are Linux-only on that tag; do not call an inline owner as a replacement.
- Platform binaries absent from repository configs are not registered. cstrike/czero/czeror have no engine module here.
- SV_SendBan builds and clears net_message around its native reply; callers must preserve this side effect.
- Native SV_CheckForRcon retains dedicated/state restrictions. Calling the new helpers enables a consumer to implement equivalent menu polling; this repository does not alter those restrictions.
- Reconstructed canonical sizebuf metadata is a verified 20-byte minimal layout (data +8, cursize +16). It is reference readability evidence only, not a Part C layout artifact or a claim about every build.
- Reference outputbuf metadata models only the verified first byte. No cross-version capacity is inferred.

### Real ELF identities

HL8684/HL10210 Linux retain the source identities. Sv10257 Linux is stripped and uses the source identity after semantic discovery. Sv8948 Linux payload `func_name` preserves these exact STT_FUNC names; config names and file stems remain logical:

| Logical stem | Sv8948 Linux func_name |
| --- | --- |
| NET_GetPacket | _Z13NET_GetPacket8netsrc_s |
| SV_FilterPacket | _Z15SV_FilterPacketv |
| SV_SendBan | _Z10SV_SendBanv |
| SV_HandleRconPacket | _Z19SV_HandleRconPacketv |
| SV_CheckRconFailure | _Z19SV_CheckRconFailureP8netadr_s |
| SV_AddFailedRcon | _Z16SV_AddFailedRconP8netadr_s |
| Cmd_ExecuteString | _Z17Cmd_ExecuteStringPc12cmd_source_t |
| SV_BeginRedirect | _Z16SV_BeginRedirect10redirect_tP8netadr_s |
| SV_EndRedirect | _Z14SV_EndRedirectv |
| NET_SendPacket | _Z14NET_SendPacket8netsrc_siPv8netadr_s |

### Sven Windows orphan code

Original IDBs had code items but no function owners for:

| Input | SV_EndRedirect span | SV_HandleRconPacket span |
| --- | --- | --- |
| svencoop-8948.windows | 0x1da5ad0–0x1da5ae0 | 0x1daa9d0–0x1daaa40 |
| svencoop-10257.windows | 0x1da6d30–0x1da6d40 | 0x1dabdd0–0x1dabe40 |

These are recorded evidence addresses, never finder constants. Recovery follows current Flush/literal xrefs backwards to actual padding after the prior function, decodes the whole span and validates call/store/return or protocol/dispatch edges before add_func. No bytes are patched.

### Per-input artifacts and evidence

The following RVAs are audit results, never locators. Filename is `bin_artifacts/<input tag>/engine/<column>.<platform>.yaml`; each cell is an independently surveyed function entry. `inline` means no separate func artifact.

| Input | NET_GetPacket | SV_FilterPacket | SV_SendBan | SV_HandleRconPacket | SV_CheckRconFailure | SV_AddFailedRcon | Cmd_ExecuteString | SV_BeginRedirect | SV_EndRedirect | NET_SendPacket |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cof-5936.windows | 0x93ace | 0xdc729 | 0xdc85b | 0xe32b3 | 0xdbe49 | 0xdbadb | 0x4542c | 0xdba87 | 0xdbaae | 0x93f1e |
| hl-10210.linux | 0x10c2f0 | 0xe4310 | 0xe4410 | 0xebb30 | 0xe3a50 | 0xe3350 | 0x8c1c0 | 0xe32e0 | 0xe3330 | 0x10cbc0 |
| hl-10210.windows | 0x1dea20 | 0x20a310 | 0x20d720 | inline | inline | 0x205b30 | 0x1b5e30 | inline | inline | 0x1dfce0 |
| hl-3248.windows | 0x683a0 | 0xa7b10 | 0xa7bd0 | 0xacab0 | 0xa70b0 | 0xa6d80 | 0x2b6b0 | 0xa6d20 | 0xa6d50 | 0x68720 |
| hl-3266.windows | 0x68380 | 0xa7af0 | 0xa7bb0 | 0xacab0 | 0xa7090 | 0xa6d60 | 0x2b690 | 0xa6d00 | 0xa6d30 | 0x68700 |
| hl-3329.windows | 0x680e0 | 0xa7150 | 0xa7210 | 0xac120 | 0xa66f0 | 0xa63c0 | 0x2b340 | 0xa6360 | 0xa6390 | 0x68460 |
| hl-3647.windows | 0x68250 | 0xa6160 | 0xa6220 | 0xab120 | 0xa5700 | 0xa53d0 | 0x2b460 | 0xa5370 | 0xa53a0 | 0x685d0 |
| hl-4554.windows | 0x72ee0 | 0xb2440 | 0xb2530 | 0xb7570 | 0xb1c60 | 0xb1940 | 0x35920 | 0xb18e0 | 0xb1910 | 0x73260 |
| hl-6153.windows | 0x66bf0 | 0x96ca0 | 0x96d70 | 0x9be70 | 0x96530 | 0x96210 | 0x27d70 | 0x961b0 | 0x961e0 | 0x66f30 |
| hl-8684.linux | 0x1681e0 | 0x144e60 | 0x144f80 | 0x14b930 | 0x143f10 | 0x143b30 | 0xf79d0 | 0x143ac0 | 0x143b10 | 0x1688c0 |
| hl-8684.windows | 0x68500 | 0x98b60 | 0x98c30 | 0x9df00 | 0x983f0 | 0x980d0 | 0x286a0 | 0x98070 | 0x980a0 | 0x68840 |
| svencoop-10257.linux | 0xe7d40 | 0xbc350 | 0xbc460 | 0xc34a0 | 0xbbce0 | 0xbb4a0 | 0x58530 | 0xbb430 | 0xbb470 | 0xe8760 |
| svencoop-10257.windows | 0x77840 | 0xa7cb0 | 0xa7d80 | 0xabdd0 | 0xa70c0 | 0xa6d60 | 0x39cc0 | 0xa6d00 | 0xa6d30 | 0x77ac0 |
| svencoop-8948.linux | 0x1349a0 | 0x10aea0 | 0x10afb0 | 0x111fb0 | 0x10a650 | 0x109e10 | 0xa7340 | 0x109da0 | 0x109de0 | 0x1353c0 |
| svencoop-8948.windows | 0x770d0 | 0xa6870 | 0xa6940 | 0xaa9d0 | 0xa5e60 | 0xa5b00 | 0x39980 | 0xa5aa0 | 0xa5ad0 | 0x77350 |

### Actual input SHA256

| Input | SHA256 of actual analysis binary |
| --- | --- |
| cof-5936.windows | 9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875 |
| hl-10210.linux | fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78 |
| hl-10210.windows | 9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295 |
| hl-3248.windows | 7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0 |
| hl-3266.windows | d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21 |
| hl-3329.windows | 4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480 |
| hl-3647.windows | 7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110 |
| hl-4554.windows | 482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3 |
| hl-6153.windows | 5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257 |
| hl-8684.linux | 1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1 |
| hl-8684.windows | be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10 |
| svencoop-10257.linux | 8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd |
| svencoop-10257.windows | e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596 |
| svencoop-8948.linux | aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e |
| svencoop-8948.windows | 22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8 |

## Dependencies

- Reuses Part A SV_CheckForRcon, SV_Rcon, SVC_ServiceChallenge and SV_FlushRedirect outputs. HL8684 Linux packet discovery also validates existing SV_Rcon.constprop.20 and SVC_ServiceChallenge.part.6.
- `old_yaml_map=None` for discovery. Current dependency signatures validate their identity; previous new-symbol signatures do not locate entries.
- LLM_DECOMPILE is a static module literal. Windows NET_GetPacket/FilterPacket share one reference/policy/platform group; Linux requests only GetPacket. SV_Rcon requests Cmd_ExecuteString separately.
- Canonical reference HL10210; Sven10257 overrides both platforms because its real protocol/helper body and 36-byte address ABI differ.
- Reference source snapshots: HLND2T-DiligentGraphics fc59dcb1307986c430859122a33f2a64ea756569, official source 5a2a0b6559dacb23e5c079c9b75bf2682e247335. See official engine/net_ws.c (NET_GetPacket/SendPacket), engine/cmd.c (Cmd_ExecuteString), engine/sv_main.c (filter/ban/failure/redirect/parser/poller).

## Notes

### Verification evidence

- Forced selected batch: `uv run python ida_analyze_bin.py -batch_selection <Part-B all-selection.json> -debug`: **92 successful, 0 failed, 0 skipped**, covering all 15 binary inputs.
- Independent pre-implementation survey vs emitted artifacts: **146 function VA/RVA/identity matches**, unchanged input SHA256, exact categories, no callable output for four HL25 Windows inline-only targets.
- Independent raw PE/ELF executable-file-range signature scan: **146/146 match exactly once at their expected entry**. Thirteen artifacts explicitly opt into cross-function-boundary signatures (10 Windows EndRedirect, 2 Windows Cmd_ExecuteString wrappers, HL8684 Linux CheckRconFailure); uniqueness remains required.
- Eight references generated by `generate_reference_yaml.py`, exactly func_name/func_va/disasm_code/procedure, desired calls present in both representations, exact current predecessor addresses.
- Four canonical IDBs restored in owned lifecycles: verified names/prototypes, 20/36-byte address types, current globals/minimal sizebuf fields and local RCON buffers. Function analyses, forced recompilation, type/member inspection, stack frames and server health captured. Normal saves/exits released all owned ports and final IDB modification times were checked.
- Ordinary local-array typing/stack-name operations rejected some decompiler-inferred names. Current lvar definitions/locations were re-inspected, source buffer use established, then exact stack members and saved MLI_NAME/MLI_TYPE settings were applied. Final decompilation confirmed rcon_buff[512] and remaining[1024]; failed intermediate operations were not treated as success.
- Initial Part B formatting evidence used bounded external path batches over the complete 663 Python/29 YAML inventory. This bypassed the shared CLI's single-command launch and did not verify that CI entrypoint. The follow-up below fixes the CLI itself and validates the exact CI command.
- `git diff --cached --check` passed after removal of eight CLI-generated whitespace-only lines.

- Final required source suite: `uv run python tests/run_test_suite.py all -b --durations 30`: **1389 tests, OK (skipped=9), 186.198 s**. Skips: 3 POSIX-only checks on Windows, 2 opt-in external-CLI checks, 3 Redis integration classes (localhost:6379 unavailable), 1 opt-in real-IDA test. The real 15-input finder batch above was executed independently of that opt-in test.
- Tracked-artifact repository contract also passed after the 146 audited new artifacts were staged. An earlier full suite exposed missing Git tracking; staging resolved this requirement without changing runtime/schema/test assertions.

### CI formatter follow-up: Windows command-line limits

- **Trigger:** [Windows CI job 111451845703](https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/37207561321/job/111451845703) failed at Check formatting with WinError 206.
- **Root cause:** `format_repo_files.py` supplied all 663 Python paths to one subprocess. The serialized command requires 33,040 UTF-16 units, exceeding CreateProcess's 32,767-unit limit. External verification batches had bypassed this defect.
- **Correct approach:** shared formatter now batches arguments within a 30,000-unit budget, including command prefix, separators, Windows quoting, UTF-16 characters and terminating NUL. It processes every path in order and preserves the first nonzero batch exit status. An individually oversized argument reports a clear error.
- **Verification:** nine new shared-behavior tests cover long lists, flags/path preservation, quoting/backslashes, non-BMP Unicode, exact boundaries, failed batches and unsplittable commands. Tests first failed against the old code, then all 12 formatter tests passed. The exact CI command `uv run python format_repo_files.py --check` passed on Windows, with Python batches of 29,985 and 3,075 units and all 29 YAML files. Full source suite: **1398 tests, OK (skipped=9), 188.090 s**.
- **Scope:** repository formatter execution on all platforms. Engine locators and the 146 artifacts are unchanged. Verify the real CI entrypoint when fixing its process-launch behavior.

### Reusable lessons

**Trigger:** retained small/uncalled helpers or inline native paths defeat a direct-caller-only locator.

**Constraint:** compilers can retain an uncalled exported helper, inline the same source elsewhere, omit function ownership in an IDB, or make a short callable wrapper non-unique within its body. Existing source declarations/IDA names do not prove that every target shares those details.

**Correct approach:** derive storage from the exact current anchored body (or its current direct helper when the call is retained), traverse data xrefs, require actual source behavior and a unique independent entry. Recover orphan metadata only after padding/instruction/control-flow proof. Use explicit across-boundary signature options only after semantic discovery and uniqueness verification.

**Verification:** independently compare pre-implementation entry/ABI evidence, scan emitted signatures on raw executable bytes, preserve exact current ELF identity, run all applicable producers and the repository quality gates.

**Scope:** Part B x86 GoldSrc/HL25/SvEngine/BLOB engine inputs. Do not copy this coverage, record offsets, output capacity or netadr size to another build without current-binary evidence.

Sven Windows reference keeps the anonymous compiler float-to-integer conversion stub at 0x1e2b450; its result converts banpenalty for addip, not command execution. Outgoing argument-area reuse remains visible in optimized Sven pseudocode. No fabricated helper call/name or capacity is introduced.

### Consumer boundaries

- This is not a completed UDP RCON migration or a game-runtime test. No hooks, socket binding overrides, stdout hooks or authentication behavior changes are implemented here.
- Authentication/output fixes in the reference branch do not prove shipped targets share the same bugs. Preserve native target semantics while applying consumer policy.
- SV_CheckForRcon's internal guards still require consumer attention for a listen-client menu; Part C state/global access is a separate deliverable.
- No NET_GetServerAddress helper, cvar static scan, challenge table or failure table artifact is added.

## Callers

- Native SV_CheckForRcon calls NET_GetPacket and, where retained as calls, SV_FilterPacket/SV_SendBan; active SV_ReadPackets also consumes the same engine queue.
- Native SV_Rcon calls Cmd_ExecuteString synchronously under native redirect and FlushRedirect afterward; Begin/End/CheckFailure may be inline in these callers while independent copies remain callable elsewhere.
- Native inactive-server parser dispatches getchallenge/challenge/rcon to current SVC/Rcon routines.

Related: [[Native UDP RCON Part A Locators]], [[idalib-mcp]].
