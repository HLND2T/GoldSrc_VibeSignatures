---
title: g_pClientFactory locator
type: note
permalink: goldsrc-vibesignatures/locators/g-pclientfactory
tags:
  - locator
  - engine
  - gv
---

# g_pClientFactory

## Symbol

- **Name**: `g_pClientFactory`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CBaseUI__Initialize-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: metadata records Windows-only; in practice the gate is only literal for svencoop-10257. The other nine configs have no `platform:` on the finder and the script accepts `windows` and `linux`, so Linux artifacts exist for hl-10210 and hl-8684 (`bin_artifacts/hl-10210/engine/g_pClientFactory.linux.yaml`).
- Inlined / absent: always a real writable-data global; never inlined. What changes per build is the *guard encoding* that references it, not its existence.

## Predecessors

- `CBaseUI__Initialize.{platform}.yaml` (produced by `find-CBaseUI__Initialize`, consumed via `expected_input`). The artifact is read from the current binary dir (`bin/<gamever>/engine/`), not from `bin_artifacts/`.

## How it is located

Despite the `-decompiles` suffix this finder is **not** LLM-based: it runs one direct `py_eval` locator (`LOCATE_PY`) inside the owner function and fails closed on any ambiguity.

1. Load the `CBaseUI__Initialize` artifact; require `func_name == "CBaseUI__Initialize"` and a parseable `func_va`.
2. Re-inspect that owner over MCP to regenerate `func_sig` from the live database and require the inspected `func_va` to equal the artifact `func_va` (stale or shifted artifacts abort). The regenerated signature becomes `gv_sig`, its address `gv_sig_va`; a `func_sig_allow_across_function_boundary` flag on the artifact is propagated.
3. Inside the owner, collect every item that references the exact `VClientVGUI001` string and require **exactly one** xref, otherwise fail closed.
4. For each instruction `ea` in the owner with `0 < string_xref - ea <= 0x100`, try `zero_test_branch`, which accepts both shipped guard forms:
   - `cmp [abs], 0` — operand 0 must be `o_mem` with an immediate-zero operand 1, or
   - `mov reg, [abs]` — followed by `test reg, reg` (or `cmp reg, 0`) on the same destination register.
   It then walks at most 4 code heads (`mov`/`lea`/`nop`) to the first `jz`/`je`/`jnz`/`jne` that has exactly one code target.
5. `encoded_absolute_memory` gate on the memory operand: it must be `o_mem`, re-decoding the raw instruction bytes at the operand displacement must reproduce the operand address exactly, the address must be dword-aligned (`value & 3 == 0`), and it must live in a writable segment. Anything else (register-indirect, unaligned, readonly) is rejected.
6. The candidate must also satisfy `insn_ea < string_xref < branch_target`, i.e. the skip branch jumps *over* the `VClientVGUI001` factory call. Exactly one such candidate is required.
7. Emit `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset` (= `insn_ea - owner_ea`), `gv_inst_length`, `gv_inst_disp`.

## Pitfalls

- Two guard encodings exist and both must stay accepted: hl-10210 / cof-5936 / svencoop-10257 use 7-byte `cmp dword ptr ds:[abs], 0` (`gv_inst_disp` 2), while hl-8684 uses 5-byte `mov eax, ds:[abs]; test eax, eax` (`gv_inst_disp` 1). Verified offsets: hl-10210 win `0x125`, cof-5936 win `0x1b4`, svencoop-10257 win `0x1aa`, hl-8684 win `0x11b`; hl-10210 linux `0x110` with a 6-byte `mov esi, ds:[abs]`.
- The locator depends on **absolute** operand encodings plus a writable segment. A build that reaches this global through a GOT-relative PIC reference would fail the `encoded_absolute_memory` gate rather than silently emit a wrong address — that is intended.
- `gv_sig_va` is the `CBaseUI__Initialize` entry, so it inherits that symbol's Linux ABI caveat (usercall hot body `0x1c1cf0` for hl-10210, not the outlined cdecl entry). Do not repoint it.
- The unicity requirements are strict by design (one string xref, one guard candidate, one jump target). If a future build aliases the guard or duplicates the factory call, the finder returns `False` with a `debug` diagnostic instead of picking one.
- svencoop-10257 pins the predecessor and this finder to `platform: windows`; there is no svencoop Linux path.
