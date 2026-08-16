# LLM_DECOMPILE

`LLM_DECOMPILE` is a fail-closed fallback used only after deterministic signature and xref paths fail. A finder opts in by
accepting `llm_config=None` and passing `llm_decompile_specs` plus `llm_config` to `preprocess_common_skill`.

## Prompt and response contract

The shared prompt is `ida_preprocessor_scripts/prompt/call_llm_decompile.md`. Runtime formatting supports
`{reference_blocks}`, `{target_blocks}`, `{symbol_name_list}`, `{platform}`, `{module}`, and `{module_name}`.

The response must be one canonical YAML mapping with all five sections:

```yaml
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Each non-empty entry must include an exact `insn_va` / `insn_disasm` pair from the exported current-binary target. The
runtime validates the requested symbol identity, permitted section, instruction pair, optional instruction regexes,
vcall or struct displacement, and optional struct size. Invalid YAML or semantic results receive a bounded correction
request; only transient transport failures use exponential backoff. Exhausted or non-retryable failures return a complete
empty result and the preprocessor fails closed.

Requests sharing `(model, prompt path, reference paths, temperature)` are batched after every deterministic fast path has
failed or returned an incomplete candidate. Dependency policy and config input classification are validated before fast
paths; a missing optional predecessor skips only its reference/target pair. Function, virtual-function, global-variable,
and struct-member results are still consumed by the normal x86 MCP helpers, which validate tail chunks, require unique
target/anchor signatures, follow requested direct-call jump thunks, and enforce four-byte vtable slots.

## Reference YAML

Reference files live at:

```text
ida_preprocessor_scripts/references/<gamever>/<module>/<func_name>.<platform>.yaml
```

Generate them only with `generate_reference_yaml.py` or the `generate-reference-yaml` skill. The mapping contains exactly
`func_name`, `func_va`, `disasm_code`, and `procedure`. `disasm_code` must be non-empty; `procedure` must be a string.
Annotate the desired call, vcall, global, or struct access in both fields.

A `reference_yaml_paths` entry may use `{gamever}`. At runtime it resolves to the gamever currently being
analyzed; when that reference file is absent, it falls back to the canonical reference gamever
(`GSVIBE_REFERENCE_GAMEVER`, default `hl-10210`). This lets the shared `hl-*`/`cstrike-*`/`cof-*` family
keep one `hl-10210` reference while an engine with a slightly different body (e.g. `svencoop-10257`)
supplies its own `references/svencoop-10257/...` file.

Example Pattern D specification:

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "build_number",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "SV_SendServerinfo.{platform}.yaml": "required",
        },
    },
]
```

A `required` dependency belongs in config `expected_input`; an `optional` dependency belongs in `optional_input`. The two
sets must not overlap. The current `find-build_number` production finder uses required `SV_SendServerinfo` artifacts on
every configured engine platform.

## Tests

Unit tests inject a fake text transport or mock the batch call. They never send a real network request. Run:

```console
uv run python -m unittest -v tests.test_ida_llm_decompile
uv run python -m unittest -v tests.test_ida_skill_preprocessor
uv run python tests/run_test_suite.py repository-contract -b --durations 30
```
