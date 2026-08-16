# IDA and Hex-Rays Reconstruction Reference

Load this reference while analyzing binary or DWARF evidence, designing target-specific partial structures, mutating a PE/ELF IDB, or repairing Hex-Rays locals.

## Build the Evidence Map

Start with three synchronized views when all are available:

- Official source: complete target body, nearby declarations, macros, and inlineable helpers.
- Cross-platform peer: machine code plus any symbols or DWARF for the matching function.
- Current target: instructions, ABI, call sites, data references, stack frame, and current pseudocode.

A useful working map has these columns:

| Source construct | Peer evidence | Target evidence | Planned IDB action | Confidence |
| --- | --- | --- | --- | --- |
| Function parameter | DWARF formal parameter or peer ABI use | calling convention/register/stack use | set prototype | high/medium/low |
| Helper call | named symbol or inline DIE | call target or inline range | rename/prototype/comment | high/medium/low |
| Global access | symbol/type | absolute data reference | rename and apply type | high/medium/low |
| Structure field | member DIE or peer operand offset | target memory operand offset | partial target field | high/medium/low |
| Constant | source enum/macro | immediate operand | enum/comment | high/medium/low |

Require at least two independent signals for callee renames when no symbol directly identifies the target.

## Extract Useful DWARF

Begin with:

```powershell
llvm-dwarfdump --name=<function> --show-children <path-to-symbolized-peer.so>
```

Inspect these DIEs and attributes:

- `DW_TAG_subprogram`: linkage/name, declaration location, return type, address ranges.
- `DW_TAG_formal_parameter`: parameter names, types, and locations.
- `DW_TAG_variable`: source local names, types, scopes, and locations.
- `DW_TAG_lexical_block`: which same-named locals belong to different scopes.
- `DW_TAG_inlined_subroutine`: helper identity, call file/line, and address ranges.
- `DW_TAG_structure_type`, `DW_TAG_member`, and `DW_AT_data_member_location`: Linux layout.
- `DW_TAG_call_site`: call order and parameter provenance when emitted.

Resolve referenced DIE offsets far enough to recover the needed type chain. Do not dump the entire binary when a named subtree and a few referenced types answer the question.

DWARF locations may describe optimized or split live ranges. Treat them as identity hints; use current-target def-use behavior for the final local mapping.

### When DWARF Is Unavailable

An empty named `llvm-dwarfdump` result, missing `.debug_*` sections, or a stripped ELF file does not block reconstruction. Record the absence and build the same evidence map from:

- Current-target machine code, ABI, strings and xrefs, call graph, call-site arguments, globals, and data references.
- ELF symbols that survived stripping, relocations, imports, exports, and section metadata.
- Matching peer machine code, using control-flow shape, constants, strings, call order, and global-access patterns rather than address equality.
- Official source declarations and nearby helpers, checked operation-by-operation against emitted target behavior.
- Caller behavior and downstream callee contracts that constrain parameter, return, and field types.

Require corroboration before semantic renames. For anonymous callees, prefer two independent signals such as a distinctive string plus call-site arguments, or matching source order plus a peer control-flow/constant signature. Do not treat lack of DWARF as permission to copy source names or peer layouts speculatively.

## Inspect Before Mutation

Typical IDA MCP sequence:

1. `server_health` — verify IDB/input/module/image base.
2. `analyze_function` — collect a compact semantic snapshot.
3. `disasm` and `decompile` — correlate instructions with pseudocode.
4. `callees`, `xref_query`, or `xrefs_to` — identify dependencies and global references.
5. `stack_frame` — record current stack members.
6. `type_inspect` and `type_query` — avoid conflicting with useful existing types.

Capture the original target name, address, prototype, callee addresses, and important data addresses before renaming anything.

## Restore Types with Minimum Commitment

Declare only types required to explain the target. A partial target structure can use padding:

```c
typedef struct client_partial_s
{
    unsigned char _pad_0000[TARGET_FIELD_OFFSET];
    edict_t *edict;
} client_partial_t;
```

Choose `TARGET_FIELD_OFFSET` from the current target's instruction operand, not a peer offset. In one real GoldSrc build, `client->edict` was at `0x61F4` in Linux but at `0x630C` in Windows. Applying either platform's structure directly to the other would have produced convincing but false pseudocode.

For multiple fields:

- Sort fields by verified current-target offset.
- Insert explicit padding between them.
- Check alignment and pointer width against the target ABI.
- Use neutral field types until loads, stores, and downstream calls establish signedness or pointee type.
- Inspect the finished type and compare every used offset to disassembly.

Apply a structure type to a global base only when data references consistently use that base. Otherwise name individual globals or retain an opaque byte array.

## Repair MEMORY and Displaced Globals

Treat these renderings as the same class of unresolved global-boundary problem:

- `MEMORY[0xADDRESS]`.
- A neighboring symbol plus a constant offset.
- `dword_BASE[index]` or an equivalent oversized-array element that target evidence identifies as a standalone global.

For each target expression:

1. Correlate every use with the current instruction and resolve the current-target address. For PIC ELF, calculate the effective address from the current GOT/base register and displacement rather than transferring a peer address.
2. Record address, width, section, instruction sites, proposed name/type, peer/source evidence, and confidence.
3. Inspect `get_item_head`, item size, current name, and type before editing.
4. Use `make_data` to create a real item boundary at the exact address, supplying both the type declaration and the `name` field. Apply `rename` and `set_type` afterward when needed.
5. If the address is inside a broad array or opaque item, split and recreate the affected item as prefix, named field, necessary gap, and suffix items whose total range equals the original. Preserve unrelated symbols and types.
6. Use a neutral address-based name plus a callable pointer type for an unidentified indirect function target.
7. Call `force_recompile` and inspect the actual cfunc text. Do not accept a successful `set_name`, name lookup, or tool result when the decompiler still emits the unresolved expression.

Repair all verified standalone globals used by the target. Search the final cfunc for `MEMORY[` and re-check any neighboring-array expressions. Leave uncertain data neutral and documented instead of forcing a semantic name.

## Mutate the IDB in Dependency Order

Use the available equivalents of:

- `declare_type` for typedefs, enums, and minimal structures.
- `rename` for functions, globals, stack members, and ordinary locals.
- `set_type` or `type_apply_batch` for function prototypes and global types.
- `enum_upsert` plus operand-enum application for protocol constants.
- `set_comments` or `append_comments` for inline/source-conflict annotations.
- `force_recompile` after foundational type or prototype changes.

Recommended order:

1. Types and enums.
2. Globals and their types.
3. Callee names and prototypes.
4. Target prototype.
5. Forced recompilation.
6. Stack and Hex-Rays locals.
7. Operand enums and comments.
8. Final recompilation and validation.

Use a batch operation only when every address and declaration has already been verified. Check partial failures instead of assuming the whole batch applied.

## Recover Stack Variables and Hex-Rays Locals

IDA stores stack-frame member names separately from Hex-Rays lvar settings. Restore both when both are visible.

After a forced recompilation:

1. Enumerate current lvars again; do not rely on stale `v1`, `v2`, or locator identities.
2. Match a local using its definition address, storage location, use sites, and source/DWARF role.
3. Apply its name with ordinary rename facilities first.
4. Apply its type with ordinary type facilities first.
5. Re-decompile and confirm the setting persisted and did not merge unrelated live ranges.

If ordinary lvar typing fails, use `py_eval` with the installed IDAPython/Hex-Rays API. The relevant primitives are:

- `ida_hexrays.lvar_saved_info_t`
- `ida_hexrays.modify_user_lvar_info`
- `ida_hexrays.MLI_TYPE`
- `ida_hexrays.save_user_lvar_settings`

Construct the saved-info locator from the current decompilation's lvar, assign a parsed `tinfo_t`, apply `MLI_TYPE`, save user settings, and decompile again. Adapt to the installed IDA SDK; inspect API signatures rather than assuming cross-version compatibility.

When the decompiler creates a register-backed copy of an existing parameter, use lvar mapping only if def-use analysis proves there is no independent value. The relevant operations are `lvar_mapping_insert` and `save_user_lvar_settings`. An incorrect mapping can hide real assignments, so validate the final microcode-derived pseudocode against disassembly.

## Represent Protocol Constants

Create or extend an enum with `enum_upsert`, then apply it to the specific immediate operand rather than globally changing every equal integer. If the high-level tool cannot select the operand, use `ida_bytes.op_enum` through `py_eval`.

Prefer enums for stable protocol opcodes, flags, service-message identifiers, and mode values. Prefer comments for one-off lengths, offsets, or compiler artifacts whose symbolic name would overstate certainty.

## Mark Inlined Source Helpers

Do not manufacture a call that the compiler removed. Keep the target's real control flow and add repeatable comments at the inline range boundaries:

```text
inlined <helper>: begin (source <file>:<line>)
inlined <helper>: end
```

Recover the helper's local names and types inside the target when supported by DWARF and live-range behavior. If optimized blocks interleave, comment the meaningful entry points instead of pretending there is one contiguous range.

## Handle Source/Binary Conflicts

Use target code as the final truth. Determine whether the mismatch is:

- A platform ABI or layout difference.
- A compiler optimization or inlining artifact.
- A public-source revision mismatch.
- A real type difference in the shipped binary.
- A current IDB type error.

Corroborate with cross-platform machine code when possible. For example, a public declaration may describe a value as an integer boolean while both shipped Windows and Linux code load and compare it as a floating-point value. Keep the target's floating-point behavior in the IDB and annotate the source mismatch; do not coerce the type solely to make pseudocode resemble the public file.

## Validation Gate

Before the final save:

1. Call `force_recompile` and `analyze_function`.
2. Inspect the real target prototype, not only the rendered declaration line.
3. Enumerate callees and explain any remaining target-owned anonymous functions on the mapped source path.
4. Use `type_inspect` to verify structure size and every referenced member offset.
5. Use `stack_frame` to verify stack member names and sizes.
6. Decompile and compare every branch, loop, call, write, and return with disassembly and the evidence map.
7. Confirm comments identify inline helpers and unresolved source mismatches.
8. Save the active target IDB in place. Do not create a backup copy unless the user explicitly requested one.
9. Call `server_health` and confirm the active IDB is still the intended PE or ELF target.
10. Verify the final IDB exists and inspect its modification time.

Record failed or unavailable checks explicitly. A source-like decompilation alone is not completion evidence.
