# Server physent locator validation

This is **static binary evidence**, recorded on 2026-10-25 for issue #405.
No hook was installed, no engine bytes were patched, and no live collision,
network correction, crouching/standing, stuck or landing regression was run.
Source-branch regressions do not validate these binary hooks.

The exact hashes, all inspected function entry windows/callers, and decoded
GV addresses are in [server-physent-evidence.json](server-physent-evidence.json).
These validation records live under `docs/validation`: they are not analysis
inputs consumed by a preprocessor. `ida_preprocessor_scripts/references` is
reserved for analysis resources with mapped consumers in the PR impact plan.
Each new function/GV signature and the reused sv_models, sv_player, host_client,
and g_groupop signatures was independently rescanned for uniqueness; VAs/RVAs
and the encoded address + PIC addend + field offset were checked in its own IDB.
Scalars were regenerated from current instructions, independent of IDA types.

The 16 config/platform combinations below contain 15 distinct binaries.
The cstrikegameui engine is byte-identical to hl-8684 Windows: use that HL
engine's model table/capacity artifacts with its matching binary identity.
Ordinary cstrike tags do not declare a separate hw module.

| Target | Platform | Movement hook | RVA | Whole-instruction entry cover for 5-byte JMP |
| --- | --- | --- | --- | --- |
| hl-3248 | windows | SV_CopyEdictToPhysent post-hook | 0xb6020 | 6 bytes |
| hl-3266 | windows | SV_CopyEdictToPhysent post-hook | 0xb6020 | 6 bytes |
| hl-3329 | windows | SV_CopyEdictToPhysent post-hook | 0xb5660 | 6 bytes |
| hl-3647 | windows | SV_CopyEdictToPhysent post-hook | 0xb4840 | 6 bytes |
| hl-4554 | windows | SV_CopyEdictToPhysent post-hook | 0xc02c0 | 6 bytes |
| hl-6153 | windows | SV_CopyEdictToPhysent post-hook | 0xa4dd0 | 5 bytes |
| hl-8684 | windows | SV_CopyEdictToPhysent post-hook | 0xa6ef0 | 5 bytes |
| hl-8684 | linux | SV_CopyEdictToPhysent post-hook | 0x15add0 | 5 bytes |
| hl-10210 | windows | SV_CopyEdictToPhysent post-hook | 0x21be40 | 6 bytes |
| hl-10210 | linux | SV_AddLinksToPM_ replacement | 0xfc130 | 7 bytes |
| cof-5936 | windows | SV_CopyEdictToPhysent post-hook | 0xee365 | 7 bytes |
| svencoop-8948 | windows | SV_CopyEdictToPhysent post-hook | 0xb78d0 | 5 bytes |
| svencoop-8948 | linux | SV_AddLinksToPM_ replacement | 0x122150 | 9 bytes |
| svencoop-10257 | windows | SV_CopyEdictToPhysent post-hook | 0xb8ec0 | 5 bytes |
| svencoop-10257 | linux | SV_AddLinksToPM_ replacement | 0xd3c80 | 9 bytes |
| cstrikegameui-8684 | windows | SV_CopyEdictToPhysent post-hook | 0xa6ef0 | 5 bytes |

All entry points use x86 cdecl. The conversion ABI is
`void (physent_t *pe, int e, edict_t *check)`; the area walker ABI is
`void (areanode_t *node, float *pmove_mins, float *pmove_maxs)`.
Incidental EAX values in untyped decompilations are not a return-value contract.
The conversion's three argument roles agree with its caller and field copies.
Use a real detour relocator and the per-binary instruction boundaries in the
JSON; these lengths are inspection evidence, not executable patch payloads.

HL10210 Linux retains an uncalled SV_CopyEdictToPhysent (also catalogued), but
SV_AddLinksToPM_ contains its own inline conversion. HL8684 Linux calls the
standalone conversion. Both Sven ELF area walkers inline the conversion.
Do not infer hook coverage merely from the existence of a named function.
The area-walker external callers and self-recursion were checked. A complete
replacement must recurse into itself, never into the original trampoline.

The first 9 bytes of both Sven ELF walkers contain the PIC get-PC thunk call.
Moving that CALL into a trampoline requires preserving its original PC semantics;
merely relocating its relative target is insufficient for the subsequent GOT
setup. A complete replacement need not execute the original trampoline.

Runtime dependencies for a post-hook are the conversion and the existing
sv_models/table-capacity metadata. Dependencies for the three inline paths are
SV_AddLinksToPM_, NUM_FOR_EDICT, pmove, sv_player, g_groupop, sv_models,
pr_strings, host_client, svs_maxclients, sv_unlag_value, truepositions, plus
the emitted private-layout scalars and existing areanode metadata.
pmove is the **pointer variable**, not the fixed g_svmove/g_clmove object;
pr_strings and host_client are pointer variables; truepositions and sv_models
are array bases; svs_maxclients and sv_unlag_value are scalar field addresses.

For Sven PIC globals, gv_pic_addend is the link-time GOT base and must acquire
the module's runtime load bias. svs_maxclients additionally has gv_address_offset
0x8, decoded from the immediately following field read. On relocated absolute
operands the loader already relocates the embedded pointer; do not add the
module base twice. All address calculations are x86-32, not RIP-relative.

| Inline target | physents offset/count | moveents offset/count | visents offset/count | client active/lw/lc |
| --- | --- | --- | --- | --- |
| hl-10210 Linux | 592 / 600 | 134996 / 64 | 149336 / 600 | 0 / 25924 / 25928 |
| svencoop-8948 Linux | 592 / 600 | 134996 / 64 | 149336 / 600 | 0 / 204376 / 204380 |
| svencoop-10257 Linux | 592 / 1024 | 229972 / 64 | 244312 / 1024 | 0 / 204376 / 204380 |

The count fields precede these arrays by 4 bytes. The walker increments
numvisent without a capacity guard; this change does not add or change that
behavior. The emitted capacities describe the guarded physents and moveents
arrays. visents shares MAX_PHYSENTS in the SDK layout: its end was separately
checked against the caller's usercmd copy beginning at offset 283736 (HL10210:
0xff1e2, SC8948: 0x12462c) or 473688 (SC10257: 0xd612c). Subtracting the
observed visents start and dividing by the fixed 224-byte physent size yields
the per-binary capacity above; an unguarded increment alone is not evidence
for this limit. truepositions has an observed 88-byte stride, active/needrelink
at 0/4, oldorg at 20, oldabsmin/oldabsmax at 44/56. These positions are
cross-checked by both the origin and bounds consumer paths. No offset signatures
were added for edict_t, physent_t or model_t.

SC10257's producer was independently checked at SV_SetupMove (current IDB
0xd51c0): the 0xb00-byte clear at 0xd51f1 covers 32 entries of 88 bytes;
0xd52b5..0xd5323 copy oldorg, oldabsmin, oldabsmax and set active, and
0xd5979 sets needrelink. SV_RestoreMove at 0xd59b0 independently walks by
88 bytes and reads active/needrelink/oldorg at the same offsets. These are
analysis evidence addresses, not extra runtime dependencies.

Keep the current binary's filtering order, entity/list copies, bounded name
copy, lag-compensation qualification, capacity exits and area-tree recursion.
In particular, the current SC10257 ELF walker omits the classic zero-height
mins.z/maxs.z exclusion; its full-physents path returns rather than recursing.
The reference source is D:/HLND2T_official/engine/sv_user.c,
pm_shared/pm_defs.h and engine/world.h; its revision is not assumed byte-identical.

The only intended collision change in a downstream hook/replacement is to set
studiomodel for SOLID_SLIDEBOX with a valid non-null Studio model carrying
FMODEL_TRACE_HITBOX. Indexes are 1..sv_models_count-1: HL=512, CoF=768,
Sven=8192 slots including reserved slot zero. Keep all other fields unchanged;
do not route SLIDEBOX through the entire BBOX branch or change client hull rules.

References were generated with generate_reference_yaml.py for hl-10210 and
svencoop-10257, both Windows/Linux; calls/globals were annotated from the
current code. The older compiler families use the canonical/family references.
The shared supervisor's externally opened SC10257 ELF session was reused
without saving or closing it; task-owned IDB sessions were finalized with
idb_close(save=True). No binary/IDB scratch is part of this delivery.

Validation used the exact-bound MCP sessions to execute the registered
preprocessors in config dependency order and independently rescan their
outputs. The normal -allgamever analyzer was attempted but rejected existing
.id0 lock files; none were deleted and no unrelated process was stopped.
This is not a claim that the ordinary analyzer completed successfully.
