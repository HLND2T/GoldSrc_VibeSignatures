---
title: CL_FxBlend locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-fxblend
tags:
  - locator
  - engine
  - func
---

# CL_FxBlend

## Symbol

- **Name**: `CL_FxBlend`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_FxBlend.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: always a standalone `cl_tent.c` function. Never inlined into `studioapi_StudioSetRenderamt` or its callers.

## Predecessors

None. The finder has no config inputs. `studioapi_StudioSetRenderamt` remains a confirmed caller but is no longer a discovery dependency.

## How it is located

1. Call `preprocess_common_skill` with `old_yaml_map=None` and `xref_floats: ["363.0", "20.0", "16.0"]` as the sole positive source.
2. Search current-IDB functions for scalar SSE/x87 reads of all three numeric constants. The shared reader matches f32/f64 memory width; its PIC fallback follows recorded data xrefs from readonly constant pools.
3. Require exactly one candidate. Source roles in `engine/cl_tent.c`: 363 de-syncs effects by entity number, 20 scales strobe/flicker, and 16 scales fast pulse or selected effect frequencies.
4. Emit `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size` after shared x86 and unique-signature validation. No old signature or predecessor can bypass float discovery.

Validation on 2026-09-16: `uv run python ida_analyze_bin.py -allgamever -modules engine -skill find-CL_FxBlend -platform windows,linux -artifactdir .tmp/cl-fxblend-artifacts -debug` executed with a fresh artifact directory: 13 successful, 0 failed, 0 skipped across all 10 configured engine versions. Every regenerated YAML payload exactly matched its tracked predecessor-based artifact, including VA/RVA, size, and signature. Unit, repository-contract, format, and both modified skill validators passed.

## Pitfalls

- Trigger: a function has no distinctive string but contains characteristic coefficients. Use a verified combination of target-owned scalar float reads, not mere constant-pool bytes.
- Source literals need not be float32; instruction and operand widths distinguish f32 from f64. Do not reinterpret an arbitrary immediate or half of a double as a valid float read.
- SvEngine Linux uses PIC/GOT-relative pools. The shared fallback succeeded on the configured binary through recorded IDA data xrefs; it does not evaluate arbitrary GOT register dataflow.
- Existing output YAML can cause the analyzer to skip a finder. Validate replacements with fresh artifact paths and compare their results with the previous verified locator.
- A missing or ambiguous candidate fails closed. Recheck current-IDB references and compiler transformations before choosing another independently validated anchor.
- Scope: the 13 configured platform pairs above. Future builds still require independent uniqueness and semantic validation.
