---
name: find-cl_resourcesonhand
description: |
  Final-guarantee Agent fallback for the find-cl_resourcesonhand preprocessor. Recovers the GoldSrc client
  on-hand precache-resource list sentinel (&cl.resourcesonhand, the resource_t node embedded at +4 of the
  engine global client_state_t cl) from CL_PrecacheResources circular-list walk semantics when the
  deterministic paired-reference scan cannot match the exact cmp/lea plus [V+0x80] load instruction shapes.
  Use only for the engine cl_resourcesonhand gv output on PE32/I386 or ELF32/I386.
  Trigger: cl_resourcesonhand, find-cl_resourcesonhand
disable-model-invocation: true
---

# Find cl_resourcesonhand (final-guarantee fallback)

Recover `cl_resourcesonhand` — the address of `cl.resourcesonhand`, the sentinel node of the client's
on-hand precache-resource circular doubly-linked list — from the loaded GoldSrc `hw.dll` or `hw.so` with
IDA Pro MCP tools. This fallback runs only after `ida_preprocessor_scripts/find-cl_resourcesonhand.py`
fails. Do not repeat its strict requirements: a `cmp`/`lea`-then-`cmp` reference within a fixed window, a
`mov reg, [mem]` load of `V+0x80`, or a unique candidate set. Recover the sentinel from the list-walk
semantics instead, tolerating instruction-encoding drift, register allocation changes, basic-block
splits, and helper de-inlining.

The output is cross-platform and consists of exactly one non-empty mapping at the invocation contract's
exact artifact path: `cl_resourcesonhand.windows.yaml` for PE32/I386 or `cl_resourcesonhand.linux.yaml`
for ELF32/I386.

## Realworld Function References

Read the current platform's artifacts first. These Git-tracked `bin_artifacts/` files are read-only
reference-build evidence; their addresses and offsets must never be copied into a different binary
without verification.

- `bin_artifacts/hl-10210/engine/CL_PrecacheResources.windows.yaml`
- `bin_artifacts/hl-10210/engine/CL_PrecacheResources.linux.yaml`
- `bin_artifacts/hl-10210/engine/cl_resourcesonhand.windows.yaml`
- `bin_artifacts/hl-10210/engine/cl_resourcesonhand.linux.yaml`
- `bin_artifacts/hl-8684/engine/CL_PrecacheResources.linux.yaml`
- `bin_artifacts/hl-8684/engine/cl_resourcesonhand.linux.yaml`
- `bin_artifacts/svencoop-10257/engine/CL_PrecacheResources.windows.yaml`
- `bin_artifacts/svencoop-10257/engine/CL_PrecacheResources.linux.yaml`
- `bin_artifacts/svencoop-10257/engine/cl_resourcesonhand.windows.yaml`
- `bin_artifacts/svencoop-10257/engine/cl_resourcesonhand.linux.yaml`
- `bin_artifacts/cof-5936/engine/CL_PrecacheResources.windows.yaml`
- `bin_artifacts/cof-5936/engine/cl_resourcesonhand.windows.yaml`

Reference observations, for orientation only:

| Build | Platform | `CL_PrecacheResources` | sentinel `gv_va` | sentinel reference form |
|---|---|---:|---:|---|
| `hl-10210` | Windows | `0x101a44c0` | `0x11257f64` | `cmp esi, imm32` at `+0x90` |
| `hl-10210` | Linux | `0x136be0` | `0xc2fa84` | `cmp eax, imm32` at `+0x55` |
| `hl-8684` | Windows | `0x1d16c60` | `0x2d602e4` | `cmp esi, imm32` at `+0x4c` |
| `hl-8684` | Linux | `0x18e910` | `0xc44744` | structured `cmp ebx, (offset m1+4)` at `+0x5c` |
| `svencoop-10257` | Windows | `0x1d26540` | `0x21092d4` | `cmp esi, imm32` at `+0x75` |
| `svencoop-10257` | Linux | `0x113350` | `0x15d7d64` | PIC GOTOFF `lea ecx, [ebx+V-GOT]` + `cmp esi, ecx` at `+0x73` |
| `cof-5936` | Windows | `0x1d2ffb6` | `0x2dd5a84` | `cmp [ebp+var], imm32` at `+0x5e` |

On `hl-10210` Linux the symtab/DWARF names the owning global `cl` (LOCAL OBJECT, `.bss`, size `0x1b0e68`)
and the sentinel is exactly `cl + 4`. Treat symbol names as corroboration, never as a portable lookup
strategy.

## Semantic model

`cl` is the engine-global `client_state_t`. Its member `resourcesonhand` (offset +4) is not a pointer
but an embedded engine-private `resource_t` node used as the sentinel of a circular doubly-linked list of
on-hand precache resources. The engine-private `resource_s` ABI differs from the public HLSDK
`custom.h` layout: `szFileName` +0 (64 bytes), `type` +0x40, `nIndex` +0x44, `ucFlags` +0x4C, `pNext`
+0x80, `pPrev` +0x84, `sizeof` 0x88.

`CL_PrecacheResources` (reconstructed GoldSrc engine source, `cl_main.c`) walks that list:

```
for (pResource = cl.resourcesonhand.pNext;
     pResource && pResource != &cl.resourcesonhand;
     pResource = pResource->pNext)
```

which compiles to three semantic fingerprints on the same absolute address V = `&cl.resourcesonhand`:

1. **init** — `pResource = [V + 0x80]` (load through the sentinel's `pNext`);
2. **condition** — compare the walking pointer against V itself (the loop terminator);
3. **advance** — `pResource = [pResource + 0x80]` (register-relative, no absolute).

The loop body then consumes `pResource` for per-resource work (type/flag checks and the client download
request path). Compiler updates may change every encoding around these fingerprints, but any build that
walks the list keeps at least fingerprints 1 and 2 on the same absolute V.

Decoys: `cl.resourcesneeded` and `cl.resourcelist` (other `client_state_t` members) are additional
`resource_t` list sentinels with the identical `+0x80/+0x84` ABI, walked by the `CL_ParseResourceList`
family. If the de-inline search reaches those functions, their loops look exactly like the target. The
distinguishing context is purpose: `CL_PrecacheResources`'s walk drives per-resource download/verify
requests from the on-hand list, not the resource-list parse/upload pipeline. Within `CL_PrecacheResources`
itself the on-hand sentinel reference is unique across every reference build.

IDA naming traps: on `hl-10210` Linux the DWARF-loaded IDB displays the `cl` global as `nMax`
(type `client_state_t_9`), and on `hl-8684` Linux a structured IDB shows the sentinel operand as
`(offset m1+4)`. Neither name exists in symtab or source; the member path (`+4` inside `cl`) is what
matters.

## Step 0 — skip an existing output

Determine the current platform and select the exact `cl_resourcesonhand.<platform>.yaml` output from the
invocation artifact contract. If it already exists and parses as a non-empty YAML mapping, stop
successfully without overwriting it:

```text
mcp__ida-pro-mcp__py_eval code="import idaapi, os, yaml; p='windows' if idaapi.get_input_file_path().lower().endswith('.dll') else 'linux'; f=os.path.abspath(r'<EXACT_OUTPUT_ARTIFACT_PATH_FROM_INVOCATION_CONTRACT>'); assert os.path.basename(f) == f'cl_resourcesonhand.{p}.yaml'; print({'path': f, 'exists': os.path.isfile(f), 'data': yaml.safe_load(open(f, encoding='utf-8')) if os.path.isfile(f) else None})"
```

Reject 64-bit inputs and binaries other than PE32/I386 or ELF32/I386.

## Step 1 — load the owner function artifact

Always use `/get-func-from-yaml` with `func_name=CL_PrecacheResources` against the exact input path in
the invocation artifact contract (`CL_PrecacheResources.<platform>.yaml`, a configured prerequisite). If
it is missing, invalid, or does not resolve to a real function start in the current IDB, stop and report
the missing prerequisite; do not substitute a reference-build address.

Then decompile and disassemble `CL_PrecacheResources`:

```text
mcp__ida-pro-mcp__decompile addr="<CL_PrecacheResources.func_va>"
```

Note that this is a plain C function of the global `cl` (no `this` pointer): list accesses go through
absolute addresses, GOT-relative encodings, or structured operand names. Keep the list of called
functions for the de-inline search.

## Step 2 — recover the sentinel candidate

Inside `CL_PrecacheResources`, find the circular-list walk and the absolute address V it is seeded from.
Work from semantics, not encodings:

1. Identify the walking register/stack slot (the loop variable `pResource`) from the loop structure.
2. Find the **init** evidence: an absolute reference whose memory at `+0x80` seeds the loop variable.
   Accept any encoding that carries the absolute address: `mov reg, [V+0x80]`, `lea` of `V+0x80` followed
   by an indirect load, GOTOFF/GOT-indirect forms, or a structured operand IDA renders as a struct
   member. Collect the absolute target through BOTH channels — operand decoding (immediate values and
   direct memory addresses) and IDA data cross-references (`DataRefsFrom`/`DataRefsTo`, which resolve
   GOTOFF and PIC forms; structured IDBs may normalize cross-references onto the struct base, so decode
   operands too).
3. Find the **condition** evidence: the loop compares the walking pointer against the same absolute V.
   Accept `cmp reg, imm32`, `cmp [ebp+x], imm32`, `cmp reg2, reg` after a `lea` of V into `reg`, or any
   equivalent shape; the compare may sit in a different basic block than the init.
4. Prefer a walk whose body also shows the **advance** (`+0x80` register load) and per-resource
   consumption (type/flag field checks near `+0x40/+0x4C`, download-request calls on `szFileName`), but
   do not require them if compiler restructuring moved them.

If the walk is absent from `CL_PrecacheResources`, follow the de-inline boundary: enumerate its callees,
decompile the plausible ones (up to two levels), and search there. A de-inlined helper receives either
`&cl.resourcesonhand` or `cl` as an argument, so the same `[x+0x80]` load and comparison against `x`
(or `x+4`) reappear with x in a register or stack slot instead of an absolute. Also handle the reverse
case: a helper used by a reference build may have been inlined back into `CL_PrecacheResources`.

Validate the candidate V:

- V lies in a writable, non-executable data segment (`.data`/`.bss`) and is 4-byte aligned;
- V−4 is the `cl` base; when the IDB carries symtab/DWARF (some Linux builds), a `client_state_t`-sized
  global at V−4 is strong corroboration, and the member at +4 resolves as `resourcesonhand`;
- reject candidates whose surrounding walk belongs to the resource-list parse/upload pipeline
  (`cl.resourcesneeded`, `cl.resourcelist` decoys) rather than the on-hand download/verify walk.

Exactly one surviving candidate is the normal outcome. If several survive and cannot be separated by the
context rules above, stop and report them instead of guessing.

## Step 3 — generate and write the artifact

Rename the verified global to `cl_resourcesonhand` in IDA when doing so does not overwrite a stronger
existing name (preserve DWARF-backed names like the `cl`/`m1` struct base). Choose the reference
instruction for the signature — prefer the condition compare, which embeds V directly. Then:

1. Use `/generate-signature-for-globalvar` with `target_gv=<verified sentinel EA>` and
   `target_inst=<chosen reference instruction EA>`. Increase `max_sig_bytes` only if the first signature
   is not unique. The signature must start at the sentinel-referencing instruction, and the four-byte
   absolute-address displacement must be wildcarded.
2. Use `/write-globalvar-as-yaml` with `gv_name=cl_resourcesonhand`, `gv_addr`, `gv_sig`, `gv_sig_va`,
   `gv_inst_length`, and `gv_inst_disp` returned by the generator.

For this fallback's generated signature, `gv_inst_offset` is `0`; the signature begins at the selected
instruction. At runtime on x86-32, the global address is the little-endian dword stored at
`scan_result + gv_inst_disp`. Do not apply an x86-64 RIP-relative formula.

**PIC exception (GOTOFF builds).** `/generate-signature-for-globalvar` only accepts instructions whose
embedded dword equals the target address. On a PIC build (Sven Co-op Linux) every reference may be
`lea/mov reg, [ebx+disp32]` where the disp32 encodes `V - GOT`, so the sub-skill legitimately fails. In
that case follow the repository-wide convention already encoded by every existing svencoop-10257 Linux
gv artifact: select the GOTOFF reference instruction, set `gv_inst_disp` to the disp32's byte offset
inside it, and construct the signature manually using the same rules (start at that instruction,
wildcard the four displacement bytes and all relative call/branch offsets, extend forward instruction by
instruction until the pattern is unique module-wide). Verify the GOTOFF encoding first: for every
on-hand sentinel reference in the function, `V - dword_at(disp)` must yield one identical GOT base; if
the deltas disagree, the candidate V is wrong. Then write via `/write-globalvar-as-yaml` as above.

The runtime artifact validator requires every address/size/offset/length/displacement field to be a
normalized, quoted hexadecimal scalar. `/write-globalvar-as-yaml` may emit the three instruction
metadata fields as YAML integers, so reopen the file after that skill completes and normalize these six
fields before validation: `gv_va`, `gv_rva`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, and
`gv_inst_disp`. Preserve all other values; the trusted analyzer pipeline, not this skill, finalizes
field order and line wrapping. `gv_inst_offset` must become `'0x0'`, not numeric `0`. This is a
schema-normalization step, not permission to hand-author or guess the artifact.

The YAML payload may contain only `gv_name` and the global-variable data fields emitted by
`/write-globalvar-as-yaml`; never add generic `name`, `type`, or `kind` keys.

## Completion and failure handling

Before reporting success, reopen `cl_resourcesonhand.<platform>.yaml`, verify it is a non-empty mapping
with `gv_name: cl_resourcesonhand`, and confirm that the six numeric fields named above are quoted
lowercase hexadecimal strings. Confirm that its signature uniquely matches the selected instruction in
the current binary. Re-read the encoded four-byte displacement at `gv_sig_va + gv_inst_disp` and confirm
it equals the verified sentinel address on absolute builds, or `sentinel - GOT` with the GOT base
consistent across the function's on-hand references on PIC builds.

If no candidate satisfies the list-walk semantics, or the walk exists but no representable unique
signature can be generated, do not write guessed YAML. Report which stage failed, the functions and
candidates inspected, and how the reference encodings differed from the current binary.
