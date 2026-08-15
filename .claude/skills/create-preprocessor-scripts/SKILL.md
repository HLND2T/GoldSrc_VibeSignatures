---
name: create-preprocessor-scripts
description: Create a new GoldSrc find-XXXX IDAPython preprocessor, register it in the game-version config(s), generate annotated reference YAML for LLM_DECOMPILE patterns, and validate Windows/Linux PE32/ELF32 artifacts. Use when a requested native function, vfunc, global, patch, vtable, or struct member has no existing finder skill.
---

# Create GoldSrc Preprocessor Scripts

Create `ida_preprocessor_scripts/find-XXXX.py` and the matching `configs/<GAMEVER>.yaml`
entries. Preserve the CS2_VibeSignatures finder/helper API and config schema, but target GoldSrc
x86 only and omit Source2-only discovery protocols.

Resolve `GAMEVER` only from the explicit request. When the user does not name a game version, target
every gamever declared in `configs/`: register the skill and symbol in each `configs/<GAMEVER>.yaml`
and validate with `ida_analyze_bin.py -allgamever`. `GSVIBE_GAMEVER` is not supported. Stop if a
targeted `configs/<GAMEVER>.yaml` does not exist. Never edit another version as a fallback.

## Hard contracts

### Target binary profile

- Windows: PE32, I386.
- Linux: ELF32, Intel 80386.
- Vtable pointer/slot width is always 4 bytes.
- `vfunc_offset == vfunc_index * 4` on every emitted artifact.
- Environment names use `GSVIBE_*`.

### Config symbol schema

Config keeps the CS2 identity contract:

```yaml
- name: R_RenderView
  category: func
```

- `name` is the config symbol identity.
- `category` is the only classifier. Supported values are `func`, `gv`, `vfunc`, `vtable`,
  `patch`, `structmember`, and metadata-only `struct`.
- Reject `type` and `kind`; do not preserve or generate them.
- A `structmember` also requires `struct` and `member`, and its parent `category: struct`
  declaration must exist in the same module.
- `alias`, `source_alias`, `shared`, and `platform` retain their repository meanings.

### Artifact identity schema

Artifacts never contain generic `name`, `type`, or `kind` fields.

| category | required artifact identity |
|---|---|
| `func` / `vfunc` | `func_name` |
| `gv` | `gv_name` |
| `patch` | `patch_name` |
| `vtable` | `vtable_class` |
| `structmember` | `struct_name` and `member_name` |

The payload identity is not required to equal the config symbol `name`. This deliberately matches
the CS2 loader behavior: config owns lookup/registration identity, while the category-specific
payload field describes the producer result.

### Artifact paths and DAG

- Outputs, `optional_output`, `skip_if_exists`, and explicit symbol artifact paths are module-local
  filenames.
- Inputs may be module-local or a safe sibling reference such as
  `../engine/INetworkMessages_FindNetworkGroup.{platform}.yaml`.
- Input normalization is relative to the current module and must remain under the current
  game-version root.
- Cross-module producers and consumers form real DAG edges. Do not rely on incidental file order.
- A sibling-module artifact is schema-validated, but its address is not validated against the
  current module's IDB.

## Finder/helper API

Use the CS2-compatible entry point exactly:

```python
async def preprocess_common_skill(
    session,
    expected_outputs,
    old_yaml_map=None,
    new_binary_dir=None,
    platform="windows",
    image_base=0,
    func_names=None,
    gv_names=None,
    patch_names=None,
    struct_member_names=None,
    vtable_class_names=None,
    inherit_vfuncs=None,
    func_xrefs=None,
    func_vtable_relations=None,
    generate_yaml_desired_fields=None,
    llm_decompile_specs=None,
    llm_config=None,
    mangled_class_names=None,
    debug=False,
    canonical_vtable_symbols=None,
):
```

Common writers are also contract-compatible:

- `write_func_yaml`
- `write_gv_yaml`
- `write_patch_yaml`
- `write_vtable_yaml`
- `write_struct_offset_yaml`

Additional shared helpers:

- `preprocess_vtable_via_mcp`
- `preprocess_index_based_vfunc_via_mcp`
- `preprocess_indirect_vcall_target_skill`
- `preprocess_ordinal_vtable_via_mcp`

All helpers fail closed on malformed MCP payloads, non-x86 IDBs, ambiguity, misaligned slots, or
non-unique signatures.

## Pattern selection

| Pattern | Use case | GoldSrc status |
|---|---|---|
| A | ordinary function via string/GV/signature/callee xrefs | retained |
| B | vfunc via xrefs plus vtable relation | retained, 4-byte slots |
| C | vfunc via validated LLM decompile | retained, 4-byte slots |
| D | ordinary function via validated LLM decompile | retained |
| E | struct member via validated LLM decompile | retained |
| F | inherit a base vfunc slot | retained, 4-byte slots |
| H | secondary/ordinal vtable | retained for 32-bit MSVC/Itanium ABI |
| I | bespoke indirect thunk walk | compatibility entry; implement with Pattern L |
| L | unique indirect `call/jmp dword ptr [reg+disp]` slot | retained; canonical I/L implementation |
| M | inline/noinline fallback chain | retained |

Removed Source2-only patterns:

- G: `RegisterConCommand` x64 callback recovery.
- J: `IGameSystem_DispatchCall` callback protocol.
- K: `IGameSystem_Loop*AllSystems` slot dispatcher protocol.

Do not recreate them under the old names. A future GoldSrc command-registration finder must be a
new, explicitly GoldSrc protocol.

Unnumbered general targets are supported directly:

- Global variables via `gv_names` and `preprocess_gv_sig_via_mcp`.
- Patches via `patch_names` and `preprocess_patch_via_mcp`.
- Primary vtables via `vtable_class_names` and `preprocess_vtable_via_mcp`.

Read the chosen reference before implementation:

- [Pattern A](references/pattern-A.md)
- [Pattern B](references/pattern-B.md)
- [Pattern C](references/pattern-C.md)
- [Pattern D](references/pattern-D.md)
- [Pattern E](references/pattern-E.md)
- [Pattern F](references/pattern-F.md)
- [Pattern H](references/pattern-H.md)
- [Pattern I compatibility entry](references/pattern-I.md)
- [Pattern L](references/pattern-L.md)
- [Pattern M](references/pattern-M.md)

## `func_xrefs` contract

Each entry uses `func_name` and any combination of:

```python
{
    "func_name": "Target",
    "xref_strings": [],
    "xref_gvs": [],
    "xref_signatures": [],
    "xref_funcs": [],
    "inline_alias": None,
    "xref_floats": [],
    "exclude_funcs": [],
    "exclude_strings": [],
    "exclude_gvs": [],
    "exclude_signatures": [],
    "exclude_floats": [],
    "exclude_callees": [],
}
```

- Positive string/GV/signature/function/inline-alias sources are intersected.
- Exclusions are applied after the positive intersection.
- Float filters are post-intersection filters and do not count as a positive source.
- Symbolic GV/function references are loaded from current-version YAML; explicit `0x...` GV
  addresses are permitted.
- `FULLMATCH:` requires exact string equality.
- `inline_alias` selects direct callers/jumpers and falls back to the alias body when no caller
  exists.
- Exactly one function must remain.
- The generated `func_sig` must also resolve uniquely to that function.

## Desired YAML fields

Every target needs one `(symbol_name, fields)` entry. Fields are exact; omitted fields are not
written. A trailing `?` makes a field optional.

Supported generation directives retain CS2 spelling:

- `func_sig_allow_across_function_boundary:true`
- `func_sig_resolve_jmp_thunk:true`
- `gv_sig_allow_across_function_boundary:true`
- `vfunc_sig_allow_across_function_boundary:true`
- `offset_sig_allow_across_function_boundary:true`
- `vfunc_sig_max_match:N`
- `offset_sig_max_match:N`

Bare directive field names are invalid.

## LLM decompile contract (Patterns C/D/E)

Use dict specs, one per symbol:

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "Target",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{module}/Predecessor.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "Predecessor.{platform}.yaml": "required",
        },
    },
]
```

Allowed result sections are `found_vcall`, `found_call`, `found_funcptr`, `found_gv`, and
`found_struct_offset`.

- Every reference artifact must appear exactly once in `dependency_policy`.
- `required` dependencies belong in config `expected_input`; `optional` dependencies belong in
  `optional_input`.
- The runtime rejects ambiguous input basenames and expected/optional overlap.
- Returned instruction addresses must lie inside the current predecessor function.
- Optional `instruction_rules` validate the actual IDA disassembly with regexes.
- Optional `expected_size` is valid only for struct members.
- Pattern C must emit `vfunc_sig`; pure slot-only LLM output is invalid.
- Reference generation and annotation must cover both `disasm_code` and `procedure`.
- Generate reference files only through the `generate-reference-yaml` skill and
  `generate_reference_yaml.py`; do not hand-build the initial YAML or call IDA APIs directly.

## Workflow

### 1. Inspect repository context

Read the selected game config(s) — or every `configs/<GAMEVER>.yaml` when running all gamevers — plus
nearby finder scripts, helper implementation, tests, and any relevant reference YAML. Confirm the
requested module and both binary paths from each config.

### 2. Choose the smallest sufficient pattern

Prefer deterministic xrefs/slots over LLM. Split chained LLM predecessors into separate scripts,
because a downstream target requires the predecessor artifact to exist before its own run.

### 3. Create the script

Path: `ida_preprocessor_scripts/find-{SKILL_NAME}.py`.

The filename must equal the config skill `name`. The public script ABI is:

```python
async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
```

Add `llm_config=None` immediately before `debug=False` only when the script uses LLM decompile.

### 4. Update config

When no gamever is requested, repeat this registration in every `configs/<GAMEVER>.yaml` so
`-allgamever` covers all game versions. When the user names a version, edit only that config.

```yaml
skills:
  - name: find-Target
    expected_output:
      - Target.{platform}.yaml
    expected_input:
      - ../engine/Dependency.{platform}.yaml
symbols:
  - name: Target
    category: func
```

Do not add `type`, `kind`, or category-specific artifact identity fields to config symbols.

### 5. Generate references when needed

Patterns C, D, and E require each predecessor reference at:

`ida_preprocessor_scripts/references/<REFERENCE_MODULE>/<PREDECESSOR>.<platform>.yaml`

Use the `generate-reference-yaml` skill as the only generation backend. Never call IDA APIs directly
and never hand-build the initial reference YAML.

#### Select one reference gamever

Reference paths are shared across game versions and therefore must not be regenerated once per
gamever. Always read the reference gamever from the `GSVIBE_REFERENCE_GAMEVER` environment variable
in `.env`. `GSVIBE_REFERENCE_GAMEVER` is mandatory: stop if it is unset or empty, and never fall back
to auto-selection or to a user-named gamever. Validate that `configs/<GSVIBE_REFERENCE_GAMEVER>.yaml`
exists and declares the predecessor module. Use the resolved value as `REFERENCE_GAMEVER` throughout
this workflow and record it in the delivery summary.

Generate references only for platforms declared by the selected module config. A Windows-only tag
such as `cof-5936` requires only Windows. When both Windows and Linux are declared, the same
`REFERENCE_GAMEVER` must provide both and both references are required. Stop if the configured
`GSVIBE_REFERENCE_GAMEVER` does not satisfy the module/platform/binary checks for this predecessor;
do not silently substitute another game family.

#### Generate supported platforms sequentially

Read each supported `module_<platform>` value from `configs/<REFERENCE_GAMEVER>.yaml`; do not guess
binary names from the module name. Run the applicable commands sequentially because they share one
owned MCP host/port:

```powershell
# Windows -- run only when module_windows is declared
uv run python generate_reference_yaml.py -gamever <REFERENCE_GAMEVER> -module <REFERENCE_MODULE> -func_name <PREDECESSOR> -auto_start_mcp -binary "bin/<REFERENCE_GAMEVER>/<REFERENCE_MODULE>/<WINDOWS_BINARY>" -platform windows -debug

# Linux -- run only when module_linux is declared; wait for Windows first when both are supported
uv run python generate_reference_yaml.py -gamever <REFERENCE_GAMEVER> -module <REFERENCE_MODULE> -func_name <PREDECESSOR> -auto_start_mcp -binary "bin/<REFERENCE_GAMEVER>/<REFERENCE_MODULE>/<LINUX_BINARY>" -platform linux -debug
```

The generator accepts only PE32/I386 and ELF32/I386, binds the exact database, resolves `func_va`
from the current predecessor artifact before falling back to config aliases, and writes the reference
atomically.

#### Annotate the generated references

The generated YAML has exactly `func_name`, `func_va`, `disasm_code`, and `procedure`. Rename known
symbols and add the target annotations in both `disasm_code` and `procedure`:

- Direct call: rename the `sub_XXXXXXXX` call target to the desired function name.
- Virtual call: annotate `call dword ptr [reg+offset]` with the desired vfunc name and mirror the
  byte offset in the procedure comment. GoldSrc slots are four bytes.
- Global: rename `dword_XXXXXXXX` or the corresponding named address in both fields.
- Struct access: add
  `(structmember, struct=StructName, member=member_name)` at every relevant access in both fields.

If Hex-Rays is unavailable, the generator may emit an empty `procedure`, but a Patterns C/D/E
delivery still requires an annotatable procedure reference. Treat that as a blocked reference build
rather than silently delivering disassembly-only context.

#### New predecessor: mandatory multi-phase workflow

When the predecessor is new, `generate_reference_yaml.py` cannot initially read its current
`func_va`. Use this sequence:

1. Create all deterministic predecessor and downstream LLM scripts, and update the target config(s).
2. On `REFERENCE_GAMEVER`, run only the predecessor-producing finder so it writes the current output
   YAML for each supported platform:

   ```powershell
   uv run python ida_analyze_bin.py -gamever <REFERENCE_GAMEVER> -modules <REFERENCE_MODULE> -skill <PREDECESSOR_SKILL> -platform <SUPPORTED_PLATFORMS> -oldgamever none -debug
   ```

3. Run `generate_reference_yaml.py` sequentially for every supported platform using the applicable
   commands above.
4. Annotate both generated fields and inspect each generated YAML for the expected predecessor
   semantics.
5. Run the downstream LLM finder and then the full requested `-gamever` or `-allgamever` validation.

Keep chained LLM predecessors in separate scripts. Every link must produce its artifact before the
next link's reference can be generated.

#### Preserve annotations on regeneration

Generation replaces an existing reference YAML. Immediately inspect:

```powershell
git diff -- ida_preprocessor_scripts/references/<REFERENCE_MODULE>/<PREDECESSOR>.windows.yaml
git diff -- ida_preprocessor_scripts/references/<REFERENCE_MODULE>/<PREDECESSOR>.linux.yaml
```

Restore any still-valid annotation comments verbatim from removed `-` lines into the regenerated
`disasm_code` and `procedure`. Do not reconstruct comments from memory.

### 6. Validate

Run the finder against every gamever by default (`-allgamever`), or against the explicitly requested
version with `-gamever <GAMEVER>`:

```powershell
uv run python ida_analyze_bin.py -allgamever -modules <MODULE> -skill find-Target -platform windows,linux -debug
uv run python ida_analyze_bin.py -gamever <GAMEVER> -modules <MODULE> -skill find-Target -platform windows,linux -oldgamever none -debug
```

`-allgamever` disables old-version comparison (it is mutually exclusive with `-oldgamever`), so the
batch command omits it.

`-gamever` or `-allgamever` is mandatory; there is no `GSVIBE_GAMEVER` fallback. Then run:

```powershell
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
```

Inspect every emitted YAML for category-specific identity fields, x86 addresses, unique signatures,
and 4-byte vfunc offset/index consistency. Generated `bin/` artifacts are validation outputs and
must not be staged.

### 7. Switch/create `dev` and commit

After validation succeeds, ensure the delivery branch is `dev`. Never commit directly to `main`.

```powershell
if (git show-ref --verify --quiet refs/heads/dev) {
    git switch dev
} else {
    git switch main
    git switch -c dev
}
```

Review `git status --short`. Stage only task-related code/config/skill/reference/test/docs files;
never use `git add -A` and never stage `bin/` output YAML.

Commit format:

```text
feat(preprocessor): add find-Target

Co-Authored-By: Codex <codex@openai.com>
```

Do not push or open a PR unless separately requested.

## Completion checklist

- [ ] Script name and config skill name match exactly.
- [ ] Config uses only `name` + `category` for classification/identity.
- [ ] Artifacts use only category-specific identities and contain no `name/type/kind`.
- [ ] Cross-module inputs stay within the game-version root and produce DAG edges.
- [ ] Pattern-specific invariants pass.
- [ ] Patterns C/D/E references were generated through `generate_reference_yaml.py`, use one recorded
      reference gamever, and contain matching annotations in `disasm_code` and `procedure`.
- [ ] A new predecessor was materialized in a predecessor-only analyzer run before reference
      generation, then the downstream LLM finder was rerun.
- [ ] When no gamever was requested, the skill is registered in every `configs/<GAMEVER>.yaml`.
- [ ] Every config-declared production platform succeeds with zero failed skills (`-allgamever` by
      default, or `-gamever <GAMEVER>` when requested).
- [ ] Unit, repository-contract, and format checks pass.
- [ ] Current branch is `dev`.
- [ ] Only task-related files are staged.
- [ ] Commit includes the exact Codex trailer.
- [ ] No push or PR was performed.
