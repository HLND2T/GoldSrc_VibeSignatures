---
title: Cache_Alloc locator
type: note
permalink: goldsrc-vibesignatures/locators/cache-alloc
tags:
  - locator
  - engine
  - func
---

# Cache_Alloc

## Symbol

- **Name**: `Cache_Alloc`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Cache_Alloc.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux. The finder itself is not platform-gated; Linux artifacts exist for the three configs that analyze `hw.so` (hl-8684, hl-10210, svencoop-10257), the other six engine configs declare `module_windows` only.
- Inlined / absent: none observed — a standalone entry with the owner diagnostic is present in every analyzed build.

## Predecessors

- None. `find-Cache_Alloc` has no `expected_input` and passes `old_yaml_map=None`, so it never reuses a previous artifact.

## How it is located

1. `xref_strings = ["FULLMATCH:Cache_Alloc: size %i"]` — exact-match C string lookup (`_string_candidates` requires `text == needle`), then `XrefsTo` maps each referencing instruction to its owning function via the shared `_ensure_function_owner` recovery.
2. Candidate set = every function that references the literal. The engine prints this diagnostic from `Cache_Alloc` only, so exactly one candidate must survive (`len(candidates) == 1`); an empty set or multiple owners fails closed.
3. `func_sig` is generated from that function's prologue (operand bytes of near/mem/displ/imm-to-segment operands wildcarded as `??`, call/jmp targets wildcarded) and is kept only when `_find_unique_bytes` resolves the signature to the same VA; otherwise the field is dropped and `func_va` / `func_rva` / `func_size` are still emitted.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- No `FULLMATCH:` prefix would substring-match any unrelated literal containing `Cache_Alloc: size`; the exact form is what keeps the owner unique.
- On Linux the literal lives in `.rodata` and is reached through PIC addressing; the wildcarding of displacement operands is what keeps the prologue signature reusable there.
- The size argument is `%i`, so the format literal is the *only* stable anchor — do not try to anchor on a constant size value.
