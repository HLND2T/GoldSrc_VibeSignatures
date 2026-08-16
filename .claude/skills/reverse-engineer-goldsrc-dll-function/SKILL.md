---
name: reverse-engineer-goldsrc-dll-function
description: Restore or reconstruct a GoldSrc function in a PE DLL or ELF .so IDA database so Hex-Rays resembles maintainable source, using the target machine code, official GoldSrc or HLDS source, and an optional cross-platform or DWARF peer. Use when recovering hw.dll, sw.dll, hw.so, engine, or game-module functions, including stripped ELF binaries without DWARF; renaming callees, globals, stack variables, and Hex-Rays locals; rebuilding prototypes, partial structs, and protocol enums; reconciling Windows and Linux layouts; documenting compiler inlining or source/binary mismatches; or validating and saving a reconstructed IDB.
---

# Reverse-Engineer a GoldSrc Binary Function

Reconstruct one target function semantically inside its PE DLL or ELF `.so` IDB. Make the decompiler output as source-like as the evidence permits without hiding machine-code behavior or inventing unsupported layout details. DWARF is optional evidence, never a prerequisite for reconstructing an ELF target.

## Required Inputs

Collect or discover:

- The target PE DLL or ELF `.so` binary or IDB and the target function name or address.
- The matching GoldSrc/HLDS source tree, including nearby helpers and type declarations.
- A matching cross-platform peer when available, plus `llvm-dwarfdump` or an equivalent DWARF reader when that peer or the target actually contains DWARF.
- A writable backup location for the IDB.
- `D:\HLND2T_official` as full source code reference.

If the source build, target binary, or cross-platform peer does not match exactly, continue only with an explicit version-mismatch warning. Never silently merge evidence from different versions. If DWARF is absent or contains no entry for the function, record that fact and continue with the non-DWARF evidence path; do not skip the `.so` target.

## Evidence Order

Resolve conflicts in this order:

1. Current target instructions, ABI, data references, calling convention, and observed offsets are authoritative for runtime behavior.
2. Matching machine code from the other platform provides structural and behavioral corroboration.
3. DWARF, symbols, relocations, imports, and exports provide names, types, source locations, and provenance when present.
4. Official source provides intent, control-flow vocabulary, and original declarations.
5. Existing IDB names, guessed types, and decompiler output are hypotheses until verified.

Do not force the target binary to visually match public source when the emitted code disagrees. Preserve the binary behavior and explain the divergence with a repeatable comment.

## Workflow

Maintain a short visible task list while working. Keep only one mutation phase in progress.

### 1. Establish the Target Session

- Call `server_health` before analysis.
- Record the IDB path, input path, module, image base, processor, and target address.
- Confirm the function belongs to the expected PE or ELF image and record its architecture and ABI.
- If switching to another IDB to inspect a cross-platform peer, record both sessions and call `server_health` again immediately after switching back.

Do not begin IDB mutations until the active target is unambiguous.

### 2. Gather Source, Binary, and Optional DWARF Evidence

- Locate the exact official function definition and read its complete body.
- Read declarations for parameters, referenced globals, accessed fields, macros, enums, and small helpers that may be inlined.
- Query the target and peer for DWARF. If present, extract the function subtree, including formal parameters, local variables, lexical scopes, inline subroutines, source call sites, and referenced structure members.
- If DWARF is absent, recover evidence from target instructions, strings and xrefs, call graph and call-site arguments, globals and data references, relocation/import/export tables, any retained symbols, and the matching peer's machine code.
- Compare the target disassembly/decompilation against the source call sequence and all available peer evidence.
- Build a compact evidence table mapping each source operation to its target instruction range, callee, global, field offset, or inline block.

Use `llvm-dwarfdump --name=<function> --show-children <binary-or-peer.so>` as the usual first DWARF query. Empty output, missing debug sections, or a stripped binary selects the non-DWARF path; it is not a stop condition. Read [references/ida-reconstruction.md](references/ida-reconstruction.md) when interpreting evidence or performing IDA/Hex-Rays mutations.

### 3. Form a Reconstruction Plan

Before editing, identify:

- The target function prototype.
- Anonymous target-owned callees that correspond to named source functions.
- Globals that can be named and typed.
- The smallest reliable set of structures, fields, typedefs, and enums.
- Stack variables, Hex-Rays locals, parameter copies, and inlined regions.
- Any source/binary or cross-platform disagreement requiring a comment rather than a forced type.

Prefer a minimal partial structure with explicit padding over a guessed full SDK structure. Always derive offsets from the current target: use Windows offsets in a Windows IDB and Linux offsets in a Linux IDB, even when peer symbols or DWARF expose a different layout.

### 4. Save a Pre-Mutation Backup

Save a separate IDB before the first rename or type change. Use a stable name such as:

`<binary>.before_<function>_restore.i64`

Confirm that the backup exists. Do not overwrite it during later saves.

### 5. Restore Dependencies Before the Target

Apply changes from foundational to derived:

1. Declare minimal typedefs, enums, and partial structures.
2. Name and type structure-backed globals.
3. Rename mapped callees and set their real prototypes.
4. Set the target function prototype.
5. Force a fresh decompilation.
6. Rename and type stack variables and Hex-Rays locals using the newly stabilized microcode.
7. Apply operand enums and comments to constants and inline regions.

Correct callee prototypes often fix argument recovery more effectively than local-variable renaming alone. Avoid cosmetic renames until the data model and calling conventions are stable.

### 6. Reconcile Layouts and Compiler Artifacts

- Treat every peer member offset as evidence, not as the current target's layout declaration.
- Derive target offsets from actual current-target memory operands and data references.
- Represent only fields used by the target and enough padding to place them correctly.
- Keep true compiler-inlined control flow inline; mark its source helper and boundaries with repeatable comments.
- If Hex-Rays creates register copies of parameters, map them back only when def-use evidence proves identity.
- Keep stack-frame names and Hex-Rays local names synchronized; they are separate stores.
- Use low-level Hex-Rays lvar APIs only after ordinary type and rename operations fail.

### 7. Validate Against All Evidence

Re-run analysis and require all applicable checks:

- The active session is still the intended target IDB and its format, architecture, and ABI match the recorded session.
- The target prototype matches observed argument and return behavior.
- Each restored callee name and prototype matches its call site.
- No mapped source call remains as an unexplained target-owned `sub_*`.
- Structure sizes and member offsets match current-target operands.
- Stack variables and Hex-Rays locals have stable, meaningful names and types.
- Protocol constants render as enums where useful.
- Inline regions remain behaviorally faithful and are clearly annotated.
- Final decompilation preserves every meaningful branch, loop, side effect, and call in the target code.
- Any source/binary disagreement is visible and justified.

Use `analyze_function`, `type_inspect`, `stack_frame`, `callees`, `disasm`, and `decompile` as appropriate. Save the target IDB, then call `server_health` once more and verify both the final IDB and the pre-mutation backup on disk.

## Safety Rules

- Mutate IDB metadata only unless the user explicitly requests byte patching.
- Never copy a full structure definition from one platform into another platform's IDB without independently validating its layout.
- Never rename an anonymous callee from source order alone; corroborate it with arguments, strings, globals, control flow, or Linux symbols.
- Never claim source-level recovery for an expression whose type or semantics remain ambiguous. Use a neutral type/name and record the uncertainty.
- Preserve unrelated user changes in the IDB and repository.

## Completion Report

Report:

- Target binary, IDB, function name, and address.
- Target format and architecture, whether usable DWARF was present, and the official source and peer evidence used.
- When DWARF was unavailable, the alternative binary evidence used to establish names, types, layout, and inline provenance.
- Restored prototype, callees, globals, structures, locals, enums, and inline annotations.
- Important platform-layout or source/binary conflicts and their resolution.
- Validation operations actually run and their results.
- Final IDB path and pre-mutation backup path.

Do not say the reconstruction is complete if the final IDB was not saved or the critical validation evidence could not be obtained.
