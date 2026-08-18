---
name: find-cvar_callbacks
description: |
  Final-guarantee Agent fallback for the find-cvar_callbacks preprocessor. Recovers the GoldSrc HL25
  cvarhook_t list-head global from Cvar_Set dispatch semantics and Cvar_HookVariable registration semantics
  when the deterministic finder cannot match the exact call/fall-through assembly shape. Use only for the
  engine cvar_callbacks output on PE32/I386 or ELF32/I386.
  Trigger: cvar_callbacks, cvar_hooks, find-cvar_callbacks
disable-model-invocation: true
---

# Find cvar_callbacks (final-guarantee fallback)

Recover `cvar_callbacks`, the process-global head of the HL25 `cvarhook_t` linked list, from the loaded
GoldSrc `hw.dll` or `hw.so` with IDA Pro MCP tools. This fallback runs only after
`ida_preprocessor_scripts/find-cvar_callbacks.py` fails. Do not repeat its strict requirement that the global
load immediately follow the `Cvar_DirectSet` call; recover the variable from the surrounding semantics.

The output is cross-platform and consists of exactly one non-empty mapping beside the loaded binary:
`cvar_callbacks.windows.yaml` for PE32/I386 or `cvar_callbacks.linux.yaml` for ELF32/I386.

## Realworld Function References

Read the current platform's artifacts first. These tracked `bin/` files are read-only reference-build evidence;
their addresses and offsets must never be copied into a different binary without verification.

- `bin/hl-10210/engine/Cvar_Set.windows.yaml`
- `bin/hl-10210/engine/Cvar_Set.linux.yaml`
- `bin/hl-10210/engine/Cvar_DirectSet.windows.yaml`
- `bin/hl-10210/engine/Cvar_DirectSet.linux.yaml`
- `bin/hl-10210/engine/cvar_callbacks.windows.yaml`
- `bin/hl-10210/engine/cvar_callbacks.linux.yaml`
- `bin/hl-8684/engine/cvar_callbacks.windows.yaml`
- `bin/hl-8684/engine/cvar_callbacks.linux.yaml`

Reference observations, for orientation only:

| Build | Platform | `Cvar_Set` | callback head | dispatch access |
|---|---|---:|---:|---:|
| `hl-10210` | Windows | `0x101be0b0` | `0x104b74c8` | `0x101be0e1` |
| `hl-10210` | Linux | `0x96fc0` | `0x2d4a40` | `0x9701d` |
| `hl-8684` | Windows | `0x1d2e850` | `0x1ff5710` | `0x1d2e883` |
| `hl-8684` | Linux | `0xffad0` | `0x2ee2a0` | `0xffb2d` |

On `hl-10210` Linux, symbols additionally identify `Cvar_HookVariable` at `0x97e30` and the same global as
`cvar_hooks` at `0x2d4a40`. Treat those names as corroboration, not as a portable lookup strategy. The artifact
name remains `cvar_callbacks` on both platforms.

## Semantic model

`Cvar_Set(name, value)` finds a `cvar_t`, calls `Cvar_DirectSet(cvar, value)`, then walks a list of 12-byte
`cvarhook_t` nodes. Each node has callback `+0`, associated `cvar_t *` at `+4`, and next pointer at `+8`. The
dispatch side starts from the global list head, compares node `+4` with the changed cvar, follows node `+8`,
and invokes node `+0` on a match.

`Cvar_HookVariable(name, node)` provides independent registration-side evidence. It rejects an invalid node,
resolves the named cvar, stores that pointer at node `+4`, then either stores the node into an empty global head
or walks the same global list through `+8` and appends the node. Compiler inlining, instruction scheduling, and
helper extraction may move either side without changing these field relationships.

Do not confuse this global with `cvar_vars`. The latter is the `cvar_t` list searched by name and advances via
`cvar_t + 0x10` in the reference builds. The target list advances through `cvarhook_t + 8`, compares `+4`, and
calls `+0`.

## Step 0 — skip an existing output

Determine the current binary directory and platform. If the corresponding `cvar_callbacks.<platform>.yaml`
already exists and parses as a non-empty YAML mapping, stop successfully without overwriting it:

```text
mcp__ida-pro-mcp__py_eval code="import idaapi, os, yaml; d=os.path.dirname(idaapi.get_input_file_path()); p='windows' if idaapi.get_input_file_path().lower().endswith('.dll') else 'linux'; f=os.path.join(d, f'cvar_callbacks.{p}.yaml'); print({'path': f, 'exists': os.path.isfile(f), 'data': yaml.safe_load(open(f, encoding='utf-8')) if os.path.isfile(f) else None})"
```

Reject 64-bit inputs and binaries other than PE32/I386 or ELF32/I386.

## Step 1 — load the two required function artifacts

Always use `/get-func-from-yaml` twice against the current binary directory:

1. `func_name=Cvar_Set`
2. `func_name=Cvar_DirectSet`

Both artifacts are configured prerequisites of this fallback. If either is missing, invalid, or does not resolve
to a real function start in the current IDB, stop and report the missing prerequisite; do not substitute a
reference-build address.

Decompile and disassemble `Cvar_Set`. Identify the call whose concrete target is the current
`Cvar_DirectSet.func_va`. Keep the returned/found `cvar_t *` data flow and inspect the reachable code after the
call. Do not require the call to be unique until control-flow and argument semantics have been considered.

## Step 2 — recover the dispatch-side candidate

Find a loop, inline region, tail, or called helper reachable after `Cvar_DirectSet` that implements all three
hook-node operations on one node value:

1. compare `[node + 4]` with the changed `cvar_t *`;
2. advance with `node = [node + 8]`;
3. invoke `[node + 0]`, either directly or after loading it into a register.

Trace the initial node value backward to the global pointer that seeds the traversal. Accept stack adjustment,
branches, unrelated instructions, register copies, a basic-block split, or a de-inlined helper between the
`Cvar_DirectSet` call and the head load. If the three operations are absent from `Cvar_Set`, follow plausible
callees reached after the direct-set operation for up to two levels, preserving the changed-cvar argument/data
flow. Also handle the reverse case where a helper used by a reference build has been inlined into `Cvar_Set`.

Record the candidate global address and every instruction that directly references it. The candidate must be a
4-byte aligned pointer slot in a writable, non-executable segment. A symbol named `cvar_hooks` on Linux is useful
only after this semantic verification.

## Step 3 — confirm from the registration side

Seek an independent `Cvar_HookVariable`-like function or inline region. Prefer these discovery routes:

- On Linux, resolve the `Cvar_HookVariable` symbol when present, then verify its body.
- Otherwise, recover the `Cvar_FindVar`-like operation from the pre-`Cvar_DirectSet` portion of `Cvar_Set`,
  inspect its callers or equivalent inlined searches, and find the function accepting a hook node.
- As a structural search, look for a function that validates node `+0`, node `+4`, and node `+8`, resolves a
  cvar by name, assigns node `+4`, and appends through a `+8` linked list.

The registration region must reference the same candidate global found in Step 2 and implement both cases:

- empty list: store the supplied node into the global head;
- non-empty list: load the global head, follow node `+8` to the tail, and store the supplied node at tail `+8`.

If Step 2 could not identify a candidate, reverse the process: derive the global from this append operation,
then inspect its data xrefs until the Step-2 dispatch semantics are found. Prefer a candidate proven from both
sides. If only one side survives because the other was optimized away, require all field relationships for the
surviving side plus at least one additional xref consistent with a list-head load/store; explain the missing
side in the final report.

## Step 4 — generate and write the artifact

Rename the verified global to `cvar_callbacks` in IDA when doing so does not overwrite a stronger existing name.
Choose a direct x86 absolute-address load or store referencing the verified global, preferring the dispatch head
load. Then:

1. Use `/generate-signature-for-globalvar` with `target_gv=<verified global EA>` and
   `target_inst=<chosen direct-reference instruction EA>`. Increase `max_sig_bytes` only if the first signature
   is not unique. The signature must start at the global-referencing instruction, and the four-byte absolute
   address displacement must be wildcarded.
2. Use `/write-globalvar-as-yaml` with `gv_name=cvar_callbacks`, `gv_addr`, `gv_sig`, `gv_sig_va`,
   `gv_inst_length`, and `gv_inst_disp` returned by the generator.

For this fallback's generated signature, `gv_inst_offset` is `0`; the signature begins at the selected
instruction. At runtime on x86-32, the global address is the little-endian dword stored at
`scan_result + gv_inst_disp`. Do not apply an x86-64 RIP-relative formula.

The runtime artifact validator requires every address/size/offset/length/displacement field to be a normalized,
quoted hexadecimal scalar. `/write-globalvar-as-yaml` may emit the three instruction metadata fields as YAML
integers, so reopen the file after that skill completes and normalize these six fields before validation:
`gv_va`, `gv_rva`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, and `gv_inst_disp`. Preserve field order and
all other values; `gv_inst_offset` must become `'0x0'`, not numeric `0`. This is a schema-normalization step, not
permission to hand-author or guess the artifact.

The YAML payload may contain only `gv_name` and the global-variable data fields emitted by
`/write-globalvar-as-yaml`; never add generic `name`, `type`, or `kind` keys.

## Completion and failure handling

Before reporting success, reopen `cvar_callbacks.<platform>.yaml`, verify it is a non-empty mapping with
`gv_name: cvar_callbacks`, and confirm that the six numeric fields named above are quoted lowercase hexadecimal
strings. Confirm that its signature uniquely matches the selected instruction in the current binary. Re-read
the encoded four-byte displacement at `gv_sig_va + gv_inst_disp` and confirm it equals the verified global
address.

If no candidate satisfies the hook-node semantics, or no unique representable absolute-reference signature can
be generated, do not write guessed YAML. Report which stage failed, the functions and candidates inspected,
and whether dispatch-side or registration-side evidence was missing.
