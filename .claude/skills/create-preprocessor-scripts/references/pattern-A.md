# Pattern A — ordinary function via xrefs

Use for a non-virtual function discovered from one or more positive xref sources.

```python
from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["{FUNC_NAME}"]

FUNC_XREFS = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": ["{XREF_STRING}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{FUNC_NAME}", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

Rules:

- Use `FULLMATCH:` for short/generic strings.
- Platform-specific strings may use separate Windows/Linux specs selected in `preprocess_skill`.
- `xref_gvs` accepts current artifact stems (including `../engine/X`) or explicit `0x...` addresses.
- `xref_funcs` requires the callee artifact in `expected_input` so its current `func_va` is known.
- All positive sources intersect; exclusions subtract; exactly one function and one generated signature must remain.
- Config category is `func`; artifact identity is `func_name`.

Checklist:

- [ ] No vtable relation or LLM config.
- [ ] Desired fields contain `func_name` and the required function metadata.
- [ ] Production Windows/Linux signatures are unique.

## Floating-point reference pattern

Use `xref_floats` when source semantics expose a distinctive combination of coefficients.
With no other positive source, the shared helper searches all functions for bodies referencing
every required value; with other positive sources, floats filter their intersection.

```python
FUNC_XREFS = [
    {
        "func_name": "CL_FxBlend",
        "xref_floats": ["363.0", "20.0", "16.0"],
    },
]
```

In `engine/cl_tent.c`, 363 de-syncs effects by entity number, 20 scales strobe/flicker,
and 16 supplies fast pulse amplitude and some effect frequencies. Another example is
`find-BuildGammaTable.py`, with `["1023.0", "0.075", "0.875"]`.
These are numeric values, not a requirement for source literals ending in `f`.

The CL_FxBlend set was validated on 2026-09-16 across all 13 configured engine/platform
pairs: Windows for hl-3248/3266/3329/3647/4554/6153/8684/10210, cof-5936, and
svencoop-10257; Linux for hl-8684, hl-10210, and svencoop-10257. Freshly generated
artifacts matched the prior accessor-based locator's complete YAML payloads.
This is evidence for those configured binaries, not a promise for future builds.

- Reuse `preprocess_common_skill`; pass `old_yaml_map=None` so old signatures cannot
  bypass discovery. Emit and validate a unique `func_sig` only after locating the function.
- The shared reader checks scalar SSE/x87 reads of f32 or f64 values in `.rdata` /
  `.rodata*`, using instruction/operand width. Do not reinterpret an arbitrary immediate
  or the low half of an f64 as proof of an f32 use.
- PIC/GOT operands may require the shared constant-pool/data-xref fallback. The IDB must
  record the referencing instruction, and its scalar read width must match the stored value.
  Pool bytes alone are insufficient; this is not a general GOT register dataflow evaluator.
- Verify constants survive optimization and all belong to the target body. Do not require
  equal pool addresses, instruction order, occurrence counts, or f32/f64 storage across builds.
- Require exactly one candidate on every requested version/platform, then verify its source
  role. Zero or multiple candidates fail closed; investigate missing xrefs, transformed
  constants, or shared coefficients before choosing another independently verified anchor.
- During replacement, execute the finder with fresh output paths (existing artifacts can
  cause a skip), compare the resulting addresses with the previously verified locator, and
  check every generated signature. Remove obsolete config dependencies only once the new
  finder no longer consumes them.
