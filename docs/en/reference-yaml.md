[Back to README](../../README.md) | [中文](../zh-CN/reference-yaml.md)

# Reference YAML for `LLM_DECOMPILE`

`LLM_DECOMPILE` is a fail-closed fallback used only after deterministic signature and xref paths fail. A finder opts in by accepting `llm_config=None` and passing `llm_decompile_specs` plus `llm_config` to `preprocess_common_skill`.

Reference YAML files are stored at:

```text
ida_preprocessor_scripts/references/<gamever>/<module>/<func_name>.<platform>.yaml
```

## Prompt and response contract

The shared prompt is `ida_preprocessor_scripts/prompt/call_llm_decompile.md`. Runtime formatting supports `{reference_blocks}`, `{target_blocks}`, `{symbol_name_list}`, `{platform}`, `{module}`, and `{module_name}`.

The response must be one canonical YAML mapping with all five sections:

```yaml
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Each non-empty entry must include an exact `insn_va` / `insn_disasm` pair from the exported current-binary target. The runtime validates the requested symbol identity, permitted section, instruction pair, optional instruction regexes, vcall or struct displacement, and optional struct size. Invalid YAML or semantic results receive a bounded correction request; only transient transport failures use exponential backoff. Exhausted or non-retryable failures return a complete empty result and the preprocessor fails closed.

Requests sharing `(model, prompt path, reference paths, temperature)` are batched after every deterministic fast path has failed or returned an incomplete candidate. Dependency policy and config input classification are validated before fast paths; a missing optional predecessor skips only its reference/target pair. Function, virtual-function, global-variable, and struct-member results are still consumed by the normal x86 MCP helpers, which validate tail chunks, require unique target/anchor signatures, follow requested direct-call jump thunks, and enforce four-byte vtable slots.

## Canonical reference game version

A `reference_yaml_paths` entry may use `{gamever}`. At runtime it resolves to the gamever currently being analyzed; when that reference file is absent, it falls back to the canonical reference gamever (`GSVIBE_REFERENCE_GAMEVER`, default `hl-10210`). This lets the shared `hl-*`/`cstrike-*`/`cof-*` family keep one `hl-10210` reference while an engine with a slightly different body (e.g. `svencoop-10257`) supplies its own `references/svencoop-10257/...` file.

Both the current and canonical paths must resolve below `ida_preprocessor_scripts/references`. The canonical gamever must be a valid repository tag; invalid or path-like environment values fail closed instead of selecting a resource outside the reference namespace. Generation commands must pass the chosen `-gamever` explicitly: use the canonical gamever for a shared body and the analyzed gamever only for a confirmed per-gamever body override.

## Generation

Generate reference YAML files only with `generate_reference_yaml.py` or the `generate-reference-yaml` skill. The mapping contains exactly `func_name`, `func_va`, `disasm_code`, and `procedure`. `disasm_code` must be non-empty; `procedure` must be a string. Annotate the desired call, vcall, global, or struct access in both fields.

Standalone CLI:

```bash
uv run python generate_reference_yaml.py -gamever hl-10210 -module engine -platform windows -func_name SV_SendServerinfo -mcp_host 127.0.0.1 -mcp_port 13337
```

To auto-start `idalib-mcp` from the CLI:

```bash
uv run python generate_reference_yaml.py -gamever hl-10210 -module engine -platform windows -func_name SV_SendServerinfo -auto_start_mcp -binary bin/hl-10210/engine/hw.dll
```

`-gamever` defaults to `GSVIBE_REFERENCE_GAMEVER`, then infers from the current IDA binary path; `-module` and `-platform` also infer from the binary path when omitted. `-mcp_database`, `-ida_args`, `-debug`, and `-output_filename` are also supported.

## Wired-in reference files

Repository references currently include:

- `references/hl-10210/engine/ClientDLL_Init.{platform}.yaml`
- `references/hl-10210/engine/LoadBlobFile_Caller.{platform}.yaml`
- `references/hl-10210/engine/SV_SendServerinfo.{platform}.yaml`
- `references/svencoop-10257/engine/SV_SendServerinfo.{platform}.yaml`

## Specification example

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

Valid result sections are `found_call`, `found_vcall`, `found_funcptr`, `found_gv`, and `found_struct_offset`. Use multiple `reference_yaml_paths` for one symbol instead of repeating the same symbol in multiple specifications. Every referenced artifact must have a matching `dependency_policy` entry whose value is `required` or `optional`; required artifacts belong to the expected-input set, while optional artifacts belong to the optional-input set. A `required` dependency belongs in config `expected_input`; an `optional` dependency belongs in `optional_input`. The two sets must not overlap.

`LLM_DECOMPILE` uses the shared Analyzer flags `-llm_model`, `-llm_apikey`, `-llm_baseurl`, `-llm_temperature`, `-llm_effort`, and `-llm_fake_as`.

## Tests

Unit tests inject a fake text transport or mock the batch call. They never send a real network request. Run:

```console
uv run python -m unittest -v tests.test_ida_llm_decompile
uv run python -m unittest -v tests.test_ida_skill_preprocessor
uv run python tests/run_test_suite.py repository-contract -b --durations 30
```
