---
title: cl_resourcesonhand locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-resourcesonhand
tags:
  - locator
  - engine
  - gv
---

# cl_resourcesonhand

## Symbol

- **Name**: `cl_resourcesonhand`
- **Category**: `gv` (member of the engine global `client_state_t cl`, at **`cl+4`**)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-cl_resourcesonhand.py`
- Agent fallback: `.claude/skills/find-cl_resourcesonhand/SKILL.md` (used only when the
  deterministic pairing scan fails)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: never inlined — it is a data member of `cl`. The *reference encoding*
  differs across four instruction forms (below), and the SvEngine Linux build is PIC.

## Predecessors

- `CL_PrecacheResources.{platform}.yaml` (produced by `find-CL_PrecacheResources`), consumed
  via `expected_input`. **This is the reuse-mode anchor**: the owner function is already
  covered, so the GV finder consumes the existing artifact instead of doing its own string
  discovery (see the `-decompiles`/reuse rule below).
- The finder re-inspects the artifact against the current IDB via `_inspect_function_via_mcp`
  (start + re-generated `func_sig`, honoring `func_sig_allow_across_function_boundary`) and
  fails closed if `func_va` does not match.

## How it is located

The sentinel is `&cl.resourcesonhand`. `CL_PrecacheResources` walks that circular list:
`pResource = cl.resourcesonhand.pNext` loads through `[sentinel+0x80]`, and the loop condition
compares `pResource != &cl.resourcesonhand`.

1. Decode every instruction of the owner (`idautils.FuncItems` + `DecodeInstruction`).
2. Collect candidate sentinel values V from **two channels, unioned**:
   - operand level — `o_imm` value and `o_mem` addr of each instruction operand;
   - IDA data xrefs — `idautils.DataRefsFrom(ea)` (this covers PIC GOTOFF forms whose
     `o_displ` carries only a GOT-relative displacement).
3. A value qualifies as a **compare reference** when it is used by a `cmp` and lies in a
   writable data segment; or as a **LEA reference** when `lea reg, V` is followed within
   `LEA_CMP_WINDOW = 6` instructions by a `cmp` operand mentioning the same register.
4. A value qualifies as a **load reference** when a `mov reg, <memory>` in the same function
   targets `V + PNEXT_OFFSET` (`0x80`; the engine-private `resource_s::pNext`).
5. Emit only when exactly one V satisfies both the compare/LEA reference **and** the `+0x80`
   load; otherwise fail closed with the candidate list. `gv_va` = V, `gv_sig`/`gv_sig_va`
   come from the owner function, and `gv_inst_offset/length/disp` come from the reference
   instruction (`disp` is the operand byte offset of the encoded dword).

Four reference forms are observed and all are covered by the two channels (cross-version
evidence recorded in the finder docstring):

| form | example (owner function entry, then the paired references) |
| --- | --- |
| `cmp reg, imm` | hl-10210 hw.dll `CL_PrecacheResources` @0x101A44C0: `cmp esi, offset 0x11257F64` + `mov esi, [0x11257FE4]`; svencoop-10257 hw.dll @0x1D26540: `cmp esi, offset 0x21092D4` + `mov esi, [0x2109354]` |
| `cmp [ebp+x], imm` (stack slot) | cof-5936 hw.dll @0x1D2FFB6: `cmp [ebp+var], offset 0x2DD5A84` + `mov eax, [0x2DD5B04]` |
| GOTOFF `lea reg,[ebx+V-GOT]` + `cmp reg,reg` | svencoop-10257 hw.so @0x113350: `lea ecx, [ebx+sentinel-GOT]` + `cmp esi, ecx` + `mov esi, [ebx+sentinel+0x80-GOT]` |
| structured `(offset m1+4)` operand decode | hl-8684 hw.so |

In every row the load operand is exactly `sentinel + 0x80` (GOT-relative in the PIC row),
which is the pairing invariant the locator relies on. For the PIC row the compare operand is
reached through `lea` rather than an immediate, so the candidate is picked up from the
LEA+`cmp` window instead of the `cmp`-immediate branch.

## Pitfalls

- **Dual channel is mandatory.** Operand-level absolutes survive IDB-structured references;
  `DataRefsFrom` is what recovers PIC GOTOFF. Using `DataRefsFrom` alone returns zero
  candidates on the structured `hl-8684` hw.so IDB (xrefs normalize onto the struct base
  `cl`); using operands alone misses the PIC form.
- **`cl+0` vs `cl+4`**: the target is the `resourcesonhand` member, not `cl` itself. The
  paired `+0x80` load is what disambiguates the member from the struct base.
- **IDA naming trap**: in `hw.so.i64` IDA renders `0xC2FA80` (the `cl` base) as `nMax` with
  type `client_state_t_9`. `nMax` exists in neither symtab, DWARF, official source nor repo
  configs — it is an IDA-side artifact. The member path `…resourcesonhand` (+4) is the
  DWARF-consistent reading; do not adopt `nMax` as a symbol name.
- **Engine-private `resource_s` ABI** (DWARF cross-checked; also matches MetaHook
  `privatehook.h`): `szFileName` +0 (64 B), `type` +0x40, `nIndex` +0x44, `ucFlags` +0x4C,
  `pNext` +0x80, `pPrev` +0x84, `sizeof` 0x88 = 136. The offsets agree with the DWARF member
  progression (`resourcesneeded@cl+140`, `resourcelist@cl+276`).
- **SvEngine Linux is PIC**: the embedded dword is not the absolute VA. The artifact must
  carry `gv_pic_addend` (e.g. svencoop-10257 hw.so records `gv_pic_addend: 0x2ee000`, the
  GOT base, while `gv_va` is `0x15d7d64`). Non-PIC builds embed the absolute value and carry
  no addend. Same contract as `cl_parsefuncs` and the player-model GVs.
- **Reuse rule for `-decompiles`/predecessor consumption**: the owner function artifact is
  the discovery anchor here, and it is legitimate (SKILL.md allows a predecessor to be
  located by "its own stable string **or existing artifact**"). Before concluding that an
  owner is uncovered, check all three of `ida_preprocessor_scripts/`,
  `configs/*.yaml` and `bin_artifacts/` — `bin/` is only the working copy and holds no YAML.
  Note that `old_yaml_map=None` only forbids reusing the **same-named** old GV artifact to
  bypass the discovery chain; it does not forbid consuming a predecessor artifact.
- **Agent fallback**: when the deterministic pairing scan yields zero candidates (encoding
  drift, register reallocation, split basic blocks, de-inlined helper), the skill recovers
  the sentinel from list-walk semantics (init load `[V+0x80]`, conditional compare against V,
  advance `+0x80`). Local note: `.env` sets `GSVIBE_AGENT=claude.cmd`, which has no
  `.cmd` shim to resolve — pass `-agent claude` explicitly or the run fails fast with
  `agent_not_found`.
- CoF (`cof-5936`) is Windows-only in this repo; cstrike/czero/czeror have no engine module
  in this repo, so this finder does not apply there.
