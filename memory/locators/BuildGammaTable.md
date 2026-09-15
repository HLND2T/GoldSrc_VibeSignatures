---
title: BuildGammaTable locator
type: note
permalink: goldsrc-vibesignatures/locators/buildgammatable
tags:
  - locator
  - engine
  - func
---

# BuildGammaTable

## Symbol

- **Name**: `BuildGammaTable`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-BuildGammaTable.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257. Symbol entry declares it `platform: windows` in svencoop-10257.
- Platforms: Windows on every config that ships `hw.dll`; additionally Linux on the two configs that ship `hw.so` and register the finder ungated (hl-8684, hl-10210). The other seven configs have no Linux engine module.
- Inlined / absent: never inlined — it is a standalone `view.c` function in every build, including the old 3248/3266/3329/3647 builds (3248/3266 share `0x1dc8c20`, 3329 `0x1dc83a0`, 3647 `0x1dc7510`). **Absent on SvEngine Linux by design**: that build is PIC and symtab-stripped, so the constant set is not recoverable; svencoop-10257 registers Windows only.

## Predecessors

- None.

## How it is located

1. `xref_floats = ["1023.0", "0.075", "0.875"]` is the *sole* positive source (`positive_sets` stays empty, so the float set becomes the candidate set).
2. The three constants are the invariant gamma-table coefficients: the 1024-entry tables normalize by `1023.0`; `g3 = 0.125 - brightness^2 * 0.075`; `f = 0.125 + (f - g3)/(1 - g3) * 0.875`. No other engine function references that combination, so the set is a unique positive anchor.
3. Candidate = every function whose body references all three constants. The shared matcher accepts absolute `.rdata`/`.rodata` float operands read by SSE (`movss`-family with an xmm operand, width 4) or by x87 memory-float mnemonics (`fld`/`fmul`/`fdiv`/`fadd`/`fsub`/`fcom`, width taken from the decoded operand dtype — `fld` may load dword or qword under the same mnemonic).
4. hl-10210 `hw.dll` reaches the pools through SSE; every other build uses x87 memory floats.
5. Emits `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`; no byte signature participates in discovery.

## Pitfalls

- The `xref_floats` spec values must be **strings**. `_normalize_func_xref_specs` requires `isinstance(value, str)`; a float object silently fails normalization.
- Width matters: floats must be read at the decoded operand's actual 4/8-byte width. A `fld qword [1023.0]` (f64 pool) is *not* a reference to float `0.0`, and an f64 entry whose low word reinterprets as a wanted f32 must not credit a double reader.
- The `"2.5"`/`"2.0"` gamma clamps live in the caller `V_CheckGamma`, **not** in `BuildGammaTable` — do not anchor on them.
- SvEngine Linux: PIC codegen hides `.rodata` operands behind `[ebx+disp32]` GOT offsets and the symtab is stripped, so no sanctioned anchor exists there.
- The PIC float fallback (`_float_fallback_owners`) must keep its module-level cache; without it every candidate function triggers a full read-only-segment scan and the worker stalls (leaves `.id0` locks).
