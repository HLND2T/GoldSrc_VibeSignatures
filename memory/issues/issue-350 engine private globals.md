---
title: Issue 350 engine private globals
type: note
permalink: goldsrc-vibesignatures/issues/issue-350-engine-private-globals
---

# Issue 350 Part B — engine private physics globals

## Scope and approved anchors

The user approved the Part B anchors on 2026-10-12 and requested artifacts for
ModelFrames, SV_LinkEdict, SV_LinkContents and Host_FilterTime as well. Engine
functions in Part A and fallguys hooks are outside this change. Existing
movevars artifacts remain the consumer of fallguys `pmovevars`; build_number
also remains unchanged.

- ModelFrames owns `Bad sprite index!\n`. Its guarded model-indexed read identifies
  the embedded `sv.models` pointer array, published as `sv_models`.
- SV_LinkEdict owns `Inserted %s with no model\n`. Its collision-tree root is
  `sv_areanodes`.
- SV_LinkContents owns `Invalid contents on trigger field: %s\n`. The AND/NAND
  branch uses `g_groupop` and the bitwise mask uses `g_groupmask`. Independent
  PF_SetGroupMask(mask, op) parameter stores cross-check both objects.
- Host_FilterTime owns `-sys_ticrate` where it is independent. Four decrypted
  WON engines lack the literal: the verified _Host_Frame's direct callees select
  the single filter that clamps an eight-byte frame-time object.

These diagnostic strings each have one literal/owner on all 15 configured
engine/platform pairs. HL25 Windows inlines Host_FilterTime into _Host_Frame;
there is no independent Host_FilterTime artifact on that platform. The same
inline body still produces host_frametime. No call ordinal, old signature,
reference address or reference-build server member offset is a discovery input.

## Artifacts and consumer ABI

All objects are engine `gv` artifacts. Signatures begin at the verified current
access and wildcard its four-byte address operand; Linux keeps the measured
PIC addend/GOT resolution. The signature address is code; the decoded gv address
is data. `sv_models` names an embedded array, not an independent ELF symbol.
Retained ELF names are applied only after validating current addresses.

- `host_frametime`: double, eight bytes; fallguys consumes `double *`.
- `g_groupop`, `g_groupmask`: four-byte int objects; fallguys fields are
  `pg_groupop`, `pg_groupmask`. PF_SetGroupMask's first/second parameters must
  store to mask/op respectively.
- `sv_models`: four-byte model pointers. ModelFrames proves usable indexes
  `1..sv_models_count-1`; index zero is reserved. Capacity, total bytes and
  `sv_models_offset = sv_models - sv` are per-binary scalar artifacts.
- `sv_areanodes`: node i is `base + i * sv_areanodes_element_size`, root i=0.
  Allocated count and total bytes come from the current zeroing call, not the
  consumer's declaration. Consumers must follow the initialized tree.
- `areanode_t`: structmember artifacts for axis (int), dist (float), children
  (two pointers), trigger_edicts and solid_edicts (each a two-pointer circular
  link head). Member offsets come from current CFG dataflow and memory operands.
  No trace_t/edict_t ABI from Part A is promised by this Part B delivery.

The additional function artifacts use the measured x86 cdecl ABI:

| Function | Return / parameters | Coverage |
| --- | --- | --- |
| ModelFrames | int / int modelIndex | All 15 pairs |
| SV_LinkEdict | void / edict_t pointer, 32-bit qboolean touchTriggers | All 15 pairs |
| SV_LinkContents | int / areanode_t pointer, const float pointer | All 15 pairs |
| Host_FilterTime | 32-bit qboolean / float time | 14 pairs; inlined on HL25 Windows |

## Reference generation

ModelFrames, SV_LinkEdict and SV_LinkContents references were generated through
`generate_reference_yaml.py` after source-name/prototype/minimal-type restoration
in owned IDBs. Shared GoldSrc/HL25/CoF references use hl-10210, both platforms.
SvEngine 10257 has both-platform overrides because its bodies/layout differ.
Source intent comes from HLND2T_official/engine/{pr_cmds.c,world.c,host.c}; actual
instructions and current binary identities remain authoritative. The public
source is not assumed to be the exact SvEngine revision.

The attempted LLM model-table mapping exposed a generic inspector limitation:
SvEngine indexes through a GOT-loaded server pointer, so selecting the GOT load
would identify sv, and selecting the indexed field load was rejected as unresolved.
The final model locator uses an independently validated ModRM/SIB/base-dataflow
walk within the same ModelFrames anchor. References remain binary evidence;
they are not runtime discovery inputs for sv_models. host_frametime similarly
uses the validated direct clamp-store exception; area/group globals use LLM
references plus the independent current-instruction layout/setter checks.

## Dataflow constraints and lessons

Trigger: correct owning strings still yielded missing frame clamps/node fields.
Root constraints: IDA can expose an implicit x87 stack operand before the actual
memory operand; compilers also split traversal into basic blocks, spill node
pointers, and emit double literals as two dword immediate writes.
Correct approach: measure explicit memory width, model x87 stack moves, reconstruct
adjacent double bits only when an eight-byte access corroborates the object,
and meet register/stack-slot provenance across the current CFG. Treat unknown
or conflicting origins as unknown and fail closed on an ambiguous object/layout.
Verification: run production finders on every configured engine/platform and
cross-check group setter argument roles, model bounds/stride and node clear size.
Scope: x86 GoldSrc engine Part B locators, including decrypted BLOB and SvEngine
PIC/GOT forms. Concurrent analyzers against one IDB lock must run sequentially.

## Verification status

The final forced production batch completed all 15 engine/platform pairs:
104 successful analysis nodes, zero failed and zero skipped. Unit verification
passed 1500 tests (nine skipped); repository-contract passed all 15 tests.
The six new regression cases exercise x87 width/stack handling, CFG pointer
spills/merges and indexed model-field resolution. An existing 30 ms concurrency
timing test failed while the IDA batch was active; it passed in isolation and
the complete unit suite passed after the batch finished. Format checks passed. IDBs opened through shared-supervisor idb_open were
finalized with idb_close(save=True); analyzer runs use the repository lifecycle.
Binary/IDA scratch is excluded from the commit.

## Current-binary evidence

| Tag/platform | Models offset / count | Area nodes stride / count | Binary SHA-256 |
| --- | --- | --- | --- |
| cof-5936/windows | 0x41d50 / 768 | 32 / 32 | `9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875` |
| hl-10210/windows | 0x30950 / 512 | 32 / 32 | `9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295` |
| hl-10210/linux | 0x30948 / 512 | 32 / 32 | `fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78` |
| hl-3248/windows | 0x30950 / 512 | 32 / 32 | `7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0` |
| hl-3266/windows | 0x30950 / 512 | 32 / 32 | `d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21` |
| hl-3329/windows | 0x30950 / 512 | 32 / 32 | `4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480` |
| hl-3647/windows | 0x30950 / 512 | 32 / 32 | `7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110` |
| hl-4554/windows | 0x30950 / 512 | 32 / 32 | `482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3` |
| hl-6153/windows | 0x30950 / 512 | 32 / 32 | `5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257` |
| hl-8684/windows | 0x30950 / 512 | 32 / 32 | `be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10` |
| hl-8684/linux | 0x30948 / 512 | 32 / 32 | `1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1` |
| svencoop-10257/windows | 0x276150 / 8192 | 32 / 32 | `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596` |
| svencoop-10257/linux | 0x276148 / 8192 | 32 / 32 | `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd` |
| svencoop-8948/windows | 0x276150 / 8192 | 32 / 32 | `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8` |
| svencoop-8948/linux | 0x276148 / 8192 | 32 / 32 | `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e` |

The measured x86 node fields are axis=0, dist=4, children=8, trigger_edicts=16,
solid_edicts=24 on all covered pairs; width is 32 bytes and allocated count is
32. Model-table count is 512 for HL, 768 for CoF, and 8192 for SvEngine. Sven
Windows and Linux models offsets differ (0x276150 versus 0x276148); both values
are derived again from their respective current instructions.
