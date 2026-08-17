---
name: reverse-engineer-goldsrc-function
description: Restore or reconstruct a GoldSrc function in a PE DLL or ELF .so IDA database so Hex-Rays resembles maintainable source, using the target machine code, official GoldSrc or HLDS source, and an optional cross-platform or DWARF peer. Use when recovering hw.dll, sw.dll, hw.so, engine, or game-module functions, including stripped ELF binaries without DWARF; repairing unresolved globals rendered as MEMORY[...] or neighboring-array offsets; renaming callees, globals, stack variables, and Hex-Rays locals; rebuilding prototypes, partial structs, and protocol enums; reconciling Windows and Linux layouts; documenting compiler inlining or source/binary mismatches; or validating and saving a reconstructed IDB.
---

# Reverse-Engineer a GoldSrc Binary Function

Reconstruct one target function semantically inside its PE DLL or ELF `.so` IDB. Make the decompiler output as source-like as the evidence permits without hiding machine-code behavior or inventing unsupported layout details. DWARF is optional evidence, never a prerequisite for reconstructing an ELF target.

## Required Inputs

Collect or discover:

- The target PE DLL or ELF `.so` binary or IDB and the target function name or address.
- The matching GoldSrc/HLDS source tree, including nearby helpers and type declarations.
- A matching cross-platform peer when available, plus `llvm-dwarfdump` or an equivalent DWARF reader when that peer or the target actually contains DWARF.
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

- Read Basic Memory [[idalib-mcp]] before opening IDA. Use one owned `IdaMcpLifecycle` for the exact target binary; do not launch `idalib-mcp` directly or bind an arbitrary active IDB.
- Keep all IDA MCP analysis and mutations inside that owned lifecycle. On normal exit it saves the verified owned IDB with `idb_save`, requests targeted `qexit`, stops the supervisor, and waits for port release.
- Call `server_health` before analysis.
- Record the IDB path, input path, module, image base, processor, and target address.
- Confirm the function belongs to the expected PE or ELF image and record its architecture and ABI.
- If switching to another IDB to inspect a cross-platform peer, record both sessions and call `server_health` again immediately after switching back.

Do not begin IDB mutations until the active target is unambiguous. Attach to an externally managed session only when the user explicitly requires it; never save or close that external worker.

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
- Every unresolved global expression in the target, including `MEMORY[0x...]`, a neighboring symbol plus offset, and oversized-array indexing that hides a standalone global.
- The smallest reliable set of structures, fields, typedefs, and enums.
- Stack variables, Hex-Rays locals, parameter copies, and inlined regions.
- Any source/binary or cross-platform disagreement requiring a comment rather than a forced type.

Prefer a minimal partial structure with explicit padding over a guessed full SDK structure. Always derive offsets from the current target: use Windows offsets in a Windows IDB and Linux offsets in a Linux IDB, even when peer symbols or DWARF expose a different layout.

### 4. Restore Dependencies Before the Target

Apply changes from foundational to derived:

1. Declare minimal typedefs, enums, and partial structures.
2. Name and type structure-backed globals.
3. Rename mapped callees and set their real prototypes.
4. Set the target function prototype.
5. Force a fresh decompilation.
6. Rename and type stack variables and Hex-Rays locals using the newly stabilized microcode.
7. Apply operand enums and comments to constants and inline regions.

Correct callee prototypes often fix argument recovery more effectively than local-variable renaming alone. Avoid cosmetic renames until the data model and calling conventions are stable.

### Reference Function Standard

When the reconstructed function will be exported as an `LLM_DECOMPILE` reference, restore its IDB
representation as close to the matching source form as current-binary evidence permits **before**
generating the reference YAML. At minimum, recover the source function name, prototype, mapped
callees, confirmed parameters and locals, and the globals or minimal structures needed for its
decompilation to communicate the source-level role. Retain a source/binary mismatch comment instead
of forcing unsupported names or types.

Keep finder artifact identity and source-like IDB names aligned unless a dependency contract requires
otherwise. Reference annotations complement this reconstruction; they must not substitute for it.

### 5. Repair Unresolved Global Expressions

Treat `MEMORY[0x...]`, a neighboring global plus offset, and `dword_BASE[index]` forms as unresolved global boundaries until target evidence proves otherwise. Repair every such expression used by the target function:

1. Resolve the exact current-target address, access width, section, instruction sites, and semantic role. For PIC ELF code, derive the target from the current GOT/base register and displacement; never copy a peer's absolute address.
2. Map the target address to a name and type using current-target behavior first, then matching peer symbols/decompilation and official source. Reuse peer names only for equivalent data roles and layouts.
3. Inspect the existing item head, size, name, and type. Materialize a real standalone data item at the exact address with `make_data`, then apply the verified name and type. `rename` or `set_type` alone is insufficient when Hex-Rays still lacks a data boundary.
4. If the address lies inside an oversized array or opaque item, split that item only as much as required into prefix, named field, gap, and suffix items. Preserve the original covered range and unrelated names/types; do not leave neighboring references degraded.
5. Give unresolved function pointers a neutral address-based name and verified callable type rather than inventing an API identity.
6. Force a fresh decompilation and inspect the actual rendered target. A successful name lookup or mutation result is not proof that Hex-Rays stopped emitting `MEMORY[...]`.

Repeat until the target contains no unexplained `MEMORY[...]` or displaced-array expression for a verified standalone global. If a boundary cannot be repaired safely, retain the neutral expression, document the ambiguity, and report the reconstruction as partial.

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
- Final decompilation contains no unexplained `MEMORY[...]` or neighboring-array expression for any verified standalone global used by the target.
- Any source/binary disagreement is visible and justified.

Use `analyze_function`, `type_inspect`, `stack_frame`, `callees`, `disasm`, and `decompile` as appropriate. Before normal lifecycle exit, call `server_health` once more. Let the owned lifecycle save the active IDB in place and close IDA gracefully, then verify the final IDB on disk and its modification time. Use manual `idb_save` only for an intentional intermediate checkpoint.

## Safety Rules

- Mutate IDB metadata only unless the user explicitly requests byte patching.
- Never copy a full structure definition from one platform into another platform's IDB without independently validating its layout.
- Never rename an anonymous callee from source order alone; corroborate it with arguments, strings, globals, control flow, or Linux symbols.
- Never claim source-level recovery for an expression whose type or semantics remain ambiguous. Use a neutral type/name and record the uncertainty.
- Do not create, copy, export, or save a pre-mutation backup IDB unless the user explicitly requests one. The owned lifecycle performs the final in-place `idb_save` on normal exit.
- Preserve unrelated user changes in the IDB and repository.

## Completion Report

Report:

- Target binary, IDB, function name, and address.
- Target format and architecture, whether usable DWARF was present, and the official source and peer evidence used.
- When DWARF was unavailable, the alternative binary evidence used to establish names, types, layout, and inline provenance.
- Restored prototype, callees, globals, structures, locals, enums, and inline annotations.
- Important platform-layout or source/binary conflicts and their resolution.
- Validation operations actually run and their results.
- Lifecycle ownership, final IDB path and modification time, `idb_save` result, graceful worker close, and port-release result.

Do not say the reconstruction is complete if the final IDB was not saved or the critical validation evidence could not be obtained.
