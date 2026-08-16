---
name: find-anchor-to-goldsrc-function
description: Locate a named or anonymous GoldSrc x86 function in hw.dll, hw.so, or a related engine module from stable in-function string anchors, official source cross-references, and IDA MCP evidence. Use when adding or repairing a GoldSrc finder/preprocessor; locating private functions across hl-* or svencoop-* Windows/Linux binaries; choosing deterministic xref anchors before LLM_DECOMPILE; or validating a generated function YAML.
---

# Find a GoldSrc Function from an Anchor

Locate the function from evidence inside its own body. Prefer a deterministic `xref_strings` result over a byte signature, a source-order guess, or LLM interpretation.

## Establish Evidence

1. Identify the exact game tag, platform, module, binary path, and requested symbol.
2. Read Basic Memory [[idalib-mcp]], then open one owned `IdaMcpLifecycle` for that exact binary. Keep every MCP operation inside it:
   - Do not start `idalib-mcp` directly or bind an arbitrary active database. The lifecycle starts the supervisor, binds and verifies the exact IDB, and owns only its worker.
   - Use `survey_binary` and `server_health` to record architecture, image base, input path, IDB path, and SHA-256 while the lifecycle is active.
   - Finish anchor validation and call `server_health` before normal lifecycle exit. That exit automatically calls `idb_save`, requests targeted `qexit`, stops the supervisor, and waits for port release. Afterwards, verify the final IDB exists and record its modification time.
   - Use manual `idb_save` only for an intentional intermediate checkpoint. Attach to an externally managed session only when the user explicitly requires it; never save or close that external worker.
3. Treat the current target binary as authoritative. Use `D:\HLND2T_official` to identify intent, exact literals, and caller/callee roles; do not assume its revision is byte-identical to the target.
4. Read `D:\MetaHookSv\memory\metahook-privatevars.md` and relevant project artifacts only when they cover the target or provide a proven anchor.

Fail closed when the IDB input path or recorded hash does not match the requested binary. Rebuild rather than trusting a copied or stale IDB.

## Choose the Locator

Use this order. Do not advance to a weaker method after a stronger method produced one validated candidate.

### 1. Direct `xref_strings`

Find a static literal referenced **inside the requested function**. Favor an invariant diagnostic, assertion, protocol label, or format string that is unlikely to be localized or reused.

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

`xref_strings` maps each matching string's data references to their containing functions. Multiple data xrefs are acceptable only when they collapse to one function; zero or multiple function candidates is a failure.

Use a plain substring only when an exact literal is impossible and record why it is still unique. Never use a raw address as a cross-platform anchor.

### 2. `LLM_DECOMPILE` from a Predecessor

Use this only if no direct `xref_strings` anchor can identify one target function.

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

## Validate the Candidate

Require every applicable check:

1. The MCP session remains bound to the requested binary and reports 32-bit x86.
2. The exact string occurs once, and all of its code xrefs resolve to one function start.
3. The candidate's RVA is `func_va - image_base`; persist RVA and signature, never a process-load address alone.
4. The generated function signature is unique in the current binary and passes the repository artifact validator.
5. Cross-platform peers have the same source role and compatible ABI/control-flow evidence; do not require equal VAs, RVAs, sizes, or compiler output.
6. For an anonymous candidate, use `disasm` or `decompile` to verify the source role before assigning the requested name.

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

- Implement deterministic discovery in `ida_preprocessor_scripts/find-<symbol>.py` through `preprocess_common_skill` and `func_xrefs`.
- Let the normal pipeline try prior validated signatures, then `xref_strings`; the shared helper rejects non-unique candidates and verifies the emitted signature.
- Add `LLM_DECOMPILE` only for the explicit predecessor fallback described above.
- Use the repository's owned lifecycle described in [[idalib-mcp]] on `127.0.0.1:13337`. The installed `ida-pro-mcp` command is an IDA plugin configurator, not this repository's HTTP supervisor.
- Add Windows and Linux expected outputs and tests whenever the finder is registered in a production config.

## Report Completion

Report the target binary hash, platform, module, selected anchor, number of matching strings and candidate functions, final VA/RVA, source files consulted, fallback status, and validation commands actually run. Include lifecycle ownership, final IDB path and modification time, `idb_save` result, graceful worker close, and port-release evidence. State any IDB identity or source-version mismatch explicitly.
