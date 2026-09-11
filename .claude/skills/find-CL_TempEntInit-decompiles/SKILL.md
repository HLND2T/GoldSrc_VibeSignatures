---
name: find-CL_TempEntInit-decompiles
description: Recover the GoldSrc Windows gTempEnts pool from CL_TempEntInit using live IDA disassembly when the LLM preprocessor returns no usable match. Distinguish the pool base from next members and free/active pointer slots, then generate the required global-variable artifact.
disable-model-invocation: true
---

# Find gTempEnts from CL_TempEntInit

Use IDA Pro MCP to recover the complete temporary-entity pool in the loaded GoldSrc Windows PE32/I386 engine. This is the fallback for `ida_preprocessor_scripts/find-CL_TempEntInit-decompiles.py`; a failed or empty LLM result is not evidence that the pool is absent. Inspect the current binary independently.

## Realworld Function References

- `ida_preprocessor_scripts/references/cof-5936/engine/CL_TempEntInit.windows.yaml`
- `bin_artifacts/cof-5936/engine/gTempEnts.windows.yaml`
- `bin_artifacts/hl-3266/engine/CL_TempEntInit.windows.yaml`
- `bin_artifacts/hl-3266/engine/gTempEnts.windows.yaml`

These are read-only reference-build evidence. Reference and target may be different binaries: neither addresses nor IDA names must match. Never use a reference function VA to replace a missing current input.

## Artifact contract and scope

| Role | Symbol | Bound filename |
|---|---|---|
| Required input | CL_TempEntInit | `CL_TempEntInit.windows.yaml` |
| Required output | gTempEnts | `gTempEnts.windows.yaml` |

Select the exact absolute paths from the invocation artifact contract. For manual use, require explicit input/output artifact paths. Never derive paths from the binary location or write into the `bin/` submodule. This finder is configured for Windows only; do not produce Linux outputs or additional symbols.

If the output already exists, skip it only after checking its identity, required fields, and signature resolution against the current binary. If it is invalid, recover it at the same bound path. The required fields are `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, and `gv_inst_disp`.

## Load the current initializer

Use `/get-func-from-yaml` with `func_name=CL_TempEntInit` and the bound input path. Confirm its address belongs to the loaded binary, then use IDA decompilation and disassembly to inspect its body. Missing or invalid current input is an error; do not fall back to a reference-build address.

If the body forwards to a helper or tail-jumps to another function, follow that target. If pool initialization was de-inlined, inspect plausible direct callees and track the destination argument into them. Bound this search to two call levels and avoid revisiting functions; report unresolved evidence rather than searching the whole binary indefinitely. Decompilation failure alone is not fatal when disassembly establishes the data flow.

## Identify the complete pool

Establish a single base address B from these cooperating behaviors:

1. A memset-like operation clears the complete pool at B. Recover the first argument from actual x86 argument setup (typically right-to-left pushes); the nearest push before the call supplies the destination. Verify the callee's clearing behavior if unnamed. An inlined clear is also valid when its destination and extent can be established.
2. A loop links successive entries with stride S. Stores at `B + M + i*S` write next pointers whose values are `B + (i+1)*S`. An optimized loop can hold the member address P and store `P + (S-M)` before advancing P by S.
3. The last next member is zeroed, a free-list pointer is assigned B, and an active-list pointer is cleared. Use these operations to corroborate the pool identity, not merely a matching allocation size.

The reference clears `0x176830 = 500 * 0xBFC` bytes, uses a `0xBFC` (3068-byte) stride, and places `next` at `+0x2C`. These are reference values to verify, not universal constants or a requirement to reject other layouts. GoldSrc pointers here are 4 bytes.

### Avoid the known base/member confusion

In the cof-5936 reference, **gTempEnts is 0x01EF4810**. **dword_1EF483C is B + 0x2C**, the first entry's next member, not another name for the pool base. The first `Q_memset` argument and the value assigned to the free-list head identify B. An anonymous member label never implies a zero member offset.

In the hl-3266 reference build, B is `0x01EF9EB0`; `0x01EF9EDC` is its first next member. The instructions at `0x01D295F7` (push B) and `0x01D29627` (store B into the free-list pointer) reference the pool base. These addresses illustrate the relationship only; recover all addresses from the current binary.

Do not output the first next-member address, the final next-member address, the free-list pointer slot, or the active-list pointer slot as `gv_va`. Do not reject an unnamed target merely because the reference names its counterpart `gTempEnts`. If multiple candidates survive, use their loop and head-assignment data flow to disambiguate; do not choose the first candidate or fabricate a match.

## Generate and write the artifact

After confirming B is mapped data and uniquely supported by the initializer, name it `gTempEnts` in IDA. Preserve unrelated names and types.

Use `/generate-signature-for-globalvar` with `target_gv=B` and a verified instruction referencing B as `target_inst`. Prefer the instruction passing the immediate base to the clear operation. If necessary, use another direct base reference, checking the correct operand: a store into the free-list slot contains both the slot address and B.

Require a unique signature in the current binary, starting at that referencing instruction, with relocatable address bytes wildcarded. Decode the actual instruction to obtain its length and the offset of the 4-byte operand encoding B. In PE32 this operand is an absolute address, not an x64 RIP-relative displacement. If no valid unique signature can be generated, report failure instead of writing a partial artifact.

Use `/write-globalvar-as-yaml` with `gv_name=gTempEnts`, `gv_addr=B`, and the generated signature metadata at the exact bound output path. This writer uses `gv_inst_offset=0`; calculate `gv_rva` from the current image base. Do not copy a reference signature or its nonzero instruction offset. Emit the category-specific fields only, without generic `name`, `type`, or `kind` keys.

## Completion and failure handling

Reopen the written YAML and verify all required fields. Scan its signature and confirm the unique match is `gv_sig_va`; decode the 4-byte operand at `match + gv_inst_offset + gv_inst_disp` and require it to equal B. Confirm the recorded instruction length and RVA are consistent with the current binary.

Report the output path, resolved pool base, instruction anchor, and validation result. If IDA/MCP, current input, semantic identification, or signature validation fails, report the specific blocker and missing output. Never write an empty or guessed YAML just to satisfy the pipeline. This fallback adds an independent recovery path; it cannot guarantee success when the binary evidence is insufficient.
