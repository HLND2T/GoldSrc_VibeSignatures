---
title: Host_ClearMemory locator
type: note
permalink: goldsrc-vibesignatures/locators/host-clearmemory
tags:
  - locator
  - engine
  - func
---

# Host_ClearMemory

## Symbol

- **Name**: `Host_ClearMemory`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Host_ClearMemory.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux. Producer is not platform-gated; Linux artifacts exist for hl-8684, hl-10210 and svencoop-10257 (the configs with `module_linux: hw.so`).
- Inlined / absent: none observed.

## Predecessors

- None. `find-Host_ClearMemory` has no `expected_input` and passes `old_yaml_map=None`.

## How it is located

1. `xref_strings = ["FULLMATCH:Clearing memory\n"]` — exact-match C string including the trailing newline, so the `engine/host.c` memory-scrub report does not collide with longer messages.
2. The literal is referenced from `Host_ClearMemory` only, so `_string_candidates` + `_ensure_function_owner` must yield exactly one owning function.
3. The signature is the function prologue with operand bytes wildcarded, kept only if unique by `_find_unique_bytes`.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- The trailing `\n` is load-bearing: without it the anchor would substring-match any literal embedding `Clearing memory`.
- The literal sits in `.data`/`.rdata` depending on build family; the exact-match string scan works across both, so no segment assumption is needed.
- Signature uniqueness is not the anchor's job — the string gives identity, the prologue only gives a reusable byte pattern. A prologue collision drops `func_sig` rather than failing the whole artifact.
