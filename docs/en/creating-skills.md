[Back to README](../../README.md) | [中文](../zh-CN/creating-skills.md)

# Creating symbol-analysis skills

Symbol-analysis skills are IDAPython preprocessors that locate a GoldSrc x86 symbol in a PE32 or ELF32 binary. Each skill is registered in `configs/<GAMEVER>.yaml` under the target module's `skills` list with its `expected_output` artifacts and optional `expected_input` prerequisites.

## `create-preprocessor-scripts`

Ask the agent to create a new `find-XXXX.py` preprocessor and register it in the game-version config(s):

```text
/create-preprocessor-scripts Create "find-XXXX" in <MODULE> by xref_strings "<STABLE_ANCHOR>".
```

The skill:

1. Creates `ida_preprocessor_scripts/find-XXXX.py` using the CS2-compatible `preprocess_common_skill` entry point, targeting GoldSrc x86 only.
2. Registers the skill and its `category` symbol in each targeted `configs/<GAMEVER>.yaml` (`func`, `gv`, `vfunc`, `vtable`, `patch`, `struct`, or `structmember`).
3. Generates annotated reference YAML under `ida_preprocessor_scripts/references/` for `LLM_DECOMPILE` patterns (see [Reference YAML for `LLM_DECOMPILE`](reference-yaml.md)).
4. Validates the Windows/Linux PE32/ELF32 artifacts.

When the user does not name a game version, the skill targets every gamever declared in `configs/` and validates with `ida_analyze_bin.py -allgamever`.

## Finder/helper API

Preprocessors call the shared helper:

```python
async def preprocess_common_skill(
    session,
    expected_outputs,
    old_yaml_map=None,
    llm_decompile_specs=None,
    llm_config=None,
):
```

The shared GoldSrc x86 helper preserves the CS2 Finder API for function/vfunc, global, patch, struct-member, primary/ordinal vtable, inherited slot, xref filtering, and validated LLM fallback. A preprocessor receives LLM runtime configuration only when it explicitly declares `llm_config`.

## Finder patterns

### Regular function with a string anchor

Use `xref_strings` when a stable string uniquely identifies the containing function. Add include or exclude anchors when one string has multiple code references.

### Function with an LLM-decompile predecessor

Use `LLM_DECOMPILE` with a required predecessor reference when the target is identifiable from a call, global access, function pointer, virtual dispatch, or structure member inside that function.

### Function chain via expected input

Declare the predecessor artifact as `expected_input`; its finder runs first, and the dependent finder consumes the validated YAML through the analysis DAG.

### Private functions and globals

Combine stable in-function anchors with official-source cross-references when locating private functions. A decompile-based finder may consume that function artifact to recover related globals. See the `find-anchor-to-goldsrc-symbol` skill for locating anonymous functions, global variables, and global-style instruction operands across Windows/Linux binaries.

## Signature generation skills

After a symbol is located and renamed in IDA, persist the result with the `write-*-as-yaml` skills (`write-func-as-yaml`, `write-vfunc-as-yaml`, `write-globalvar-as-yaml`, `write-patch-as-yaml`, `write-structoffset-as-yaml`, `write-vtable-as-yaml`). Generate and validate byte signatures with `generate-signature-for-function`, `generate-signature-for-globalvar`, `generate-signature-for-patch`, `generate-signature-for-structoffset`, `generate-signature-for-vfuncoffset`, and `get-vtable-index` / `get-vtable-address`. Preprocessor and Agent outputs pass the same YAML, symbol-schema, and current-IDB address validator.

## Registering the skill in config

A registered skill entry looks like:

```yaml
- name: find-XXXX
  expected_output:
    - XXXX.{platform}.yaml
```

Symbols use `name + category` only; `type` and `kind` are rejected. Artifact payloads use category-specific identities (`func_name`, `gv_name`, `patch_name`, `vtable_class`, `struct_name`/`member_name`) and are not required to equal the config symbol name.
