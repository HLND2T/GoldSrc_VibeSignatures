---
name: find-anchor-to-goldsrc-symbol
description: Locate a named or anonymous GoldSrc x86 symbol—function, global variable, or global-style instruction-operand locator—in hw.dll, hw.so, or a related engine module from stable anchors, official source cross-references, and IDA MCP evidence. Use when adding or repairing a GoldSrc finder/preprocessor; locating private symbols across hl-* or svencoop-* Windows/Linux binaries; choosing deterministic anchors before LLM_DECOMPILE; or validating a generated function/global-variable YAML.
---

# Find a GoldSrc Symbol from an Anchor

Locate a GoldSrc x86 symbol from deterministic evidence. For a function, anchor a literal inside its own body. For a global variable, first anchor an owning function, then recover and validate the exact data reference or instruction operand. Prefer deterministic xrefs over a byte signature, a source-order guess, or LLM interpretation.

## Establish Evidence

1. Identify the exact game tag, platform, module, binary path, requested symbol, and intended category (`func`, `gv`, `patch`, `vtable`, or another supported category).
2. Read Basic Memory [[idalib-mcp]], then open one owned `IdaMcpLifecycle` for that exact binary. Keep every MCP operation inside it:
   - Do not start `idalib-mcp` directly or bind an arbitrary active database. The lifecycle starts the supervisor, binds and verifies the exact IDB, and owns only its worker.
   - Use `survey_binary` and `server_health` to record architecture, image base, input path, IDB path, and SHA-256 while the lifecycle is active.
   - Finish anchor validation and call `server_health` before normal lifecycle exit. That exit automatically calls `idb_save`, requests targeted `qexit`, stops the supervisor, and waits for port release. Afterwards, verify the final IDB exists and record its modification time.
   - Use manual `idb_save` only for an intentional intermediate checkpoint. Attach to an externally managed session only when the user explicitly requires it; never save or close that external worker.
3. Treat the current target binary as authoritative. Use `D:\HLND2T_official` to identify intent, exact literals, caller/callee roles, and global-storage semantics; do not assume its revision is byte-identical to the target.
4. Read `D:\MetaHookSv\memory\metahook-privatevars.md` and relevant project artifacts only when they cover the target or provide a proven anchor.

Fail closed when the IDB input path or recorded hash does not match the requested binary. Rebuild rather than trusting a copied or stale IDB.

## Classify the Requested Symbol

Decide what the requested name represents before choosing an anchor. Do not force every address-like target into the `gv` schema.

- **Function (`func`)**: a callable code entry. Emit `func_name`, `func_va`, `func_rva`, and a unique `func_sig`.
- **True global variable (`gv`)**: an object or pointer stored in mapped data (`.data` or `.bss`) and referenced by x86 code. Emit `gv_name`, `gv_va`, `gv_rva`, and a unique instruction-based `gv_sig`; the signature wildcards the absolute-address displacement and runtime resolution reads that displacement.
- **Global-style instruction operand**: a logical slot represented by bytes inside an instruction, rather than a data object. First recover the containing function, then preserve the instruction address, operand offset, operand value, and extraction rule. Do not emit it as a normal `gv` unless the runtime consumer expects the operand's *value* as the global address.

`cl_enginefuncs` is the important boundary case. The embedded pointer operand in `ClientDLL_Init` decodes to the `cl_enginefuncs` engine-function table in data; the operand field itself lives in code. Name a normal `gv` target after the decoded data table, and establish whether the consumer instead needs the operand-field address before selecting the artifact category.

For this pattern, anchor `ClientDLL_Init` through its `"ScreenShake"` registration, then validate the client `Initialize` call and its interface-version argument. Windows commonly encodes it as `push 7; push <engine-table-va>; call ...`, while Linux may use register/stack `mov` instructions such as `mov dword ptr [esp], <engine-table-va>`. The source role must agree, but the Windows byte form is never a Linux locator.

## Choose the Locator

Use this order. Do not advance to a weaker method after a stronger method produced one validated candidate.

Byte signatures are output validation only. Never put a byte pattern in `xref_signatures` or
`exclude_signatures` to locate or disambiguate a target. A finder governed by this skill must pass
`old_yaml_map=None` to `preprocess_common_skill` so a prior artifact's `func_sig` cannot bypass the
required string/LLM discovery chain.

### 1. Direct `xref_strings` for the Owning Function

Find a static literal referenced **inside the requested function**, or inside the function that owns the requested global's reference. Favor an invariant diagnostic, assertion, protocol label, or format string that is unlikely to be localized or reused.

Use an exact query whenever source and target agree:

```python
FUNC_XREFS = [
    {
        "func_name": "Target",
        "xref_strings": ["FULLMATCH:exact literal\\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
```

`xref_strings` maps each matching string's data references to their containing functions. Multiple data xrefs are acceptable only when they collapse to one function; zero or multiple function candidates is a failure. A global-variable request continues from that verified function into [Recover a Global Symbol](#recover-a-global-symbol); it does not pretend that the string xref directly identifies a data address.

Use a plain substring only when an exact literal is impossible and record why it is still unique. Never use a raw address as a cross-platform anchor.

### 2. `LLM_DECOMPILE` from a Predecessor

Use this only if no direct `xref_strings` anchor can identify one target function. Locate the
predecessor itself through direct `xref_strings`; do not use a signature to locate it.

1. Deterministically locate a predecessor with its own stable string or existing artifact.
2. Export the predecessor's current-binary disassembly and pseudocode.
3. Configure `LLM_DECOMPILE` with the smallest relevant reference YAML and `expected_result_sections: ["found_call"]`.
4. Require the returned `insn_va` and `insn_disasm` to match the current target IDB and resolve exactly one direct call target.
5. Inspect the callee and generate its YAML only after the normal x86 validators accept it.

Do not use LLM output to bypass a zero/multiple-candidate result, and do not copy addresses from the reference game version.

## Cross-Reference Source Correctly

Separate target-owned and caller-owned literals before writing a finder.

- A literal used in the target function directly locates that function through `xref_strings`.
- A literal used by a caller locates the caller, not its callee. Use it only to establish a deterministic predecessor for `LLM_DECOMPILE`.
- Confirm the role in both source and current IDA xrefs before promoting an anchor.

For `Sys_Error`, `D:\HLND2T_official\engine\sys_dll.c` places `"FATAL ERROR (shutting down): %s\\n"` in `Sys_Error` itself. The client-link failure strings live in `LoadInsecureClient` in `D:\HLND2T_official\engine\cdll_int.c`; they must not be passed to the generic `Sys_Error` `xref_strings` finder.

## Recover a Global Symbol

After anchoring the owning function, use current-IDB disassembly and source semantics to recover the global reference. Never select an operand merely because it is near the string anchor.

1. Confirm the instruction participates in the requested behavior: a load/store of the global, or the argument that passes the requested table/object to a verified call.
2. Decode the operand in the current IDB and record its instruction VA, instruction length, operand/displacement offset, and decoded 32-bit value.
3. For a true global, require the decoded value to resolve to the intended mapped data object. Generate the signature with `generate-signature-for-globalvar`; it must begin at the referencing instruction, wildcard the four-byte absolute-address displacement, and resolve uniquely.
4. Persist a true global with `write-globalvar-as-yaml`. The runtime resolver is x86-32 absolute addressing: `gv_address = *(uint32_t *)(matched_instruction + gv_inst_disp)`. Never apply a RIP-relative formula.
5. For a global-style instruction operand, report both the operand-field address and decoded value. The operand field is `matched_instruction + operand_offset`; decoding it yields the table/object address. Do not use the normal GV resolver when the consumer needs the operand-field address itself.

For `cl_enginefuncs`, retain the distinction in the delivery: report the operand field separately when a consumer needs a code-operand locator, while the decoded immediate is the `cl_enginefuncs` data-table address emitted by a normal `gv` artifact. On each platform, validate the interface version and indirect `Initialize` call in the same basic block before accepting either value.

## Validate the Candidate

Require every applicable check:

1. The MCP session remains bound to the requested binary and reports 32-bit x86.
2. The exact string occurs once, and all of its code xrefs resolve to one owning function start.
3. A function's RVA is `func_va - image_base`; a true global's RVA is `gv_va - image_base`. Persist RVA and a category-appropriate signature, never a process-load address alone.
4. The generated `func_sig` or `gv_sig` is unique in the current binary and passes the repository artifact validator. A code-operand locator must separately validate its instruction form, operand offset, and decoded value.
5. Cross-platform peers have the same source role and compatible ABI/control-flow evidence; do not require equal VAs, RVAs, sizes, or compiler output.
6. For an anonymous function candidate, use `disasm` or `decompile` to verify the source role before assigning the requested name. For a global, verify the data object's role and every selected instruction operand.

For `Sys_Error`, additionally require a variadic format entry, an approximately 1024-byte formatted error buffer, fatal-error reporting, and a terminating `exit` or `longjmp` path.

## Worked `Sys_Error` Anchor

Use this direct locator first:

```python
"FULLMATCH:FATAL ERROR (shutting down): %s\\n"
```

It resolves to one function in the verified smoke inputs:

| Binary | Function RVA |
| --- | --- |
| `hl-10210/hw.dll` | `0x21fc20` |
| `hl-10210/hw.so` | `0xd4770` |
| `svencoop-10257/hw.dll` | `0xabb050` |
| `svencoop-10257/hw.so` | `0xaf0a0` |

Treat these values only as regression evidence for their exact SHA-256 inputs, never as a locator for another build.

## Repository Integration

- Implement deterministic discovery in `ida_preprocessor_scripts/find-<symbol>.py` through `preprocess_common_skill`, `func_xrefs`, and the target category's supported field set.
- Direct target strings are the first locator. When a function or a global's owning function has no usable in-function string, add a string-located predecessor finder, generate its reference YAML, and use `LLM_DECOMPILE` to recover the direct call target or data reference.
- Pass `old_yaml_map=None` for string/LLM discovery. The shared helper must validate the emitted category-appropriate signature after discovery, but must not use a prior artifact signature to locate the symbol.
- Add `LLM_DECOMPILE` only for the explicit predecessor fallback described above. Its result section must match the target: `found_call` for functions and `found_gv` for globals.
- Use the repository's owned lifecycle described in [[idalib-mcp]] on `127.0.0.1:13337`. The installed `ida-pro-mcp` command is an IDA plugin configurator, not this repository's HTTP supervisor.
- Add Windows and Linux expected outputs, category-correct config symbols, and tests whenever the finder is registered in a production config.

## Report Completion

Report the target binary hash, platform, module, requested category, selected anchor, number of matching strings and candidate owning functions, final VA/RVA, source files consulted, fallback status, and validation commands actually run. For globals, include the reference instruction VA, operand/displacement offset, decoded value, and whether the consumer needs the global value or the operand-field address. Include lifecycle ownership, final IDB path and modification time, `idb_save` result, graceful worker close, and port-release evidence. State any IDB identity or source-version mismatch explicitly.
