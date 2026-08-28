---
name: rename-preprocessor-scripts
description: |
  Rename a GoldSrc x86 preprocessor symbol across finder scripts, configs/GAMEVER.yaml,
  downstream dependencies, reference YAML, tests, and existing bin output. Use when a function,
  vfunc, vtable, global variable, struct member, or patch name changes, or when an inline finder
  must be renamed to the inlined stage of an inline/noinline fallback chain.
---

# Rename GoldSrc Preprocessor Scripts

Rename `OldName` to `NewName` consistently across the GoldSrc preprocessor pipeline. Update the
finder source, every affected game-version config, dependent finder inputs, reference YAML, tests,
and ignored `bin/` artifacts. Preserve binary-derived values such as addresses, signatures, and
vfunc offsets.

Resolve the target game versions from the explicit request. If the request names no game version,
apply the change to every `configs/<GAMEVER>.yaml` and validate with `-allgamever`. Do not use a
`GSVIBE_GAMEVER` fallback and do not silently edit one version when all versions are requested.

## When to Use

- Rename a function, vfunc, vtable, global variable, struct member, or patch symbol.
- Correct a naming convention in one or more existing finder scripts.
- Split a finder whose helper changed from inline to noinline. Rename the original finder to the
  `-inlined` stage, then follow Pattern M in
  [create-preprocessor-scripts](../create-preprocessor-scripts/references/pattern-M.md) for the
  helper and `-noinline` stages.

## Inputs

| Field | Description | Example |
|---|---|---|
| **Old name** | Current config/artifact symbol name | `ILoopType_EngineLoop` |
| **New name** | Replacement symbol name | `CLoopTypeBase_EngineLoop` |
| **Old class** | Old vtable class, when applicable | `ILoopType` |
| **New class** | Replacement vtable class | `CLoopTypeBase` |
| **Game version** | Optional explicit version; omit to target all configs | `hl-10210` |

If only a symbol suffix changes and the vtable class remains unchanged, skip class-specific edits.
For multiple renames, complete every step in one pass and batch independent replacements.

## Step 1: Find Affected Files

Search tracked source/configuration and ignored output before editing:

```powershell
rg -l --glob '*.py' --glob '*.yaml' 'OldName|OldClass|OldClass::' .
rg -n --glob '*.py' --glob '*.yaml' 'OldName\.(windows|linux)\.yaml|skip_if_exists|expected_input' .
```

Classify every hit before changing it:

| File type | Path pattern | Required change |
|---|---|---|
| Finder script | `ida_preprocessor_scripts/find-OldName.py` | Rename file and update identity strings |
| Game config | `configs/<GAMEVER>.yaml` | Update skill, artifact, symbol, alias, and dependency entries |
| Output YAML | `bin/*/<module>/OldName.<platform>.yaml` | Rename file and update category identity fields |
| Reference YAML | `ida_preprocessor_scripts/references/**/*.yaml` | Rename symbol-named files or update annotations/comments |
| Tests | `tests/**/*.py` | Update fixtures, paths, assertions, and test names |

Also search for downstream `expected_input`, `optional_input`, `skip_if_exists`,
`INHERIT_VFUNCS`, `LLM_DECOMPILE`, and `FUNC_XREFS` references. Do not assume that a hit in the
producer script is the only dependency.

Before changing files, inspect `git status --short` and preserve unrelated user changes. Never use
`git reset --hard` or discard existing work.

## Step 2: Rename the Finder Script

Use `git mv` so history follows the finder:

```powershell
git mv -- ida_preprocessor_scripts/find-OldName.py ida_preprocessor_scripts/find-NewName.py
```

For compound names containing `-AND-` or an `-impl` suffix, rename only the changed component and
leave the other target names and suffix intact.

## Step 3: Update Finder Contents

In the renamed `.py` file, replace only symbol identity values. Keep the GoldSrc-compatible
`preprocess_skill`/`preprocess_common_skill` ABI and all generated binary data unchanged.

Update fields when present:

| Location | Replacement |
|---|---|
| Module docstring and skill name | `find-OldName` -> `find-NewName` |
| `INHERIT_VFUNCS` target and vtable class | `OldName`/`OldClass` -> `NewName`/`NewClass` |
| `GENERATE_YAML_DESIRED_FIELDS` keys | Rename the symbol key |
| `FUNC_XREFS.func_name` | Rename the function target |
| `FUNC_VTABLE_RELATIONS` target/class | Rename both identity values |
| `LLM_DECOMPILE` target or predecessor | Rename the symbol identity |
| `TARGET_FUNCTION_NAMES` or struct-member lists | Rename listed identities |
| `base_vfunc_name` paths | Replace `../client/OldName` or the applicable module path |

Do not rename unrelated substrings, generated signatures, virtual offsets, virtual indices, or
addresses. GoldSrc vtable slots remain 4-byte slots, so a name-only change must not alter slot data.

## Step 4: Update Game-Version Configs

Edit only the requested `configs/<GAMEVER>.yaml` files, or every config when no version was named.
Update all applicable occurrences:

### Skill registration

```yaml
- name: find-OldName
  expected_output:
    - OldName.{platform}.yaml
```

becomes:

```yaml
- name: find-NewName
  expected_output:
    - NewName.{platform}.yaml
```

Change `expected_input`, `optional_input`, `skip_if_exists`, and `optional_output` only when they
refer to the renamed artifact. Keep the DAG explicit; do not replace a dependency with incidental
file order.

### Symbol registration

```yaml
- name: OldName
  category: vfunc
  alias:
    - OldClass::OldMethodSuffix
```

becomes:

```yaml
- name: NewName
  category: vfunc
  alias:
    - NewClass::NewMethodSuffix
```

Keep the GoldSrc config schema: `category` is the classifier and valid categories are `func`,
`gv`, `vfunc`, `vtable`, `patch`, `structmember`, and metadata-only `struct`. Do not add or retain
`type` or `kind` fields.

An underscore-form symbol and a C++ alias are different strings. Replace both explicitly, for
example `IGameSystemFactory_Allocate` and `IGameSystemFactory::Allocate`; do not rely on one
replacement to update the other.

## Step 5: Rename and Update `bin/` Outputs

`bin/` YAML is generated output and normally ignored by git, but it must remain consistent for
local validation. Locate the module directory from Step 1, then rename each existing platform file:

```powershell
Get-ChildItem -Path bin -Recurse -File -Filter 'OldName.*.yaml' | ForEach-Object {
    $newPath = Join-Path $_.DirectoryName ($_.Name.Replace('OldName', 'NewName'))
    Move-Item -LiteralPath $_.FullName -Destination $newPath
}
```

Update only the category-specific artifact identity inside each renamed file:

- `func` and `vfunc`: `func_name`
- `gv`: `gv_name`
- `patch`: `patch_name`
- `vtable`: `vtable_class`
- `structmember`: `struct_name` and/or `member_name`

Do not change `func_va`, `func_sig`, `gv_va`, `vfunc_offset`, `vfunc_index`, patch bytes, or other
binary-derived fields. If an output is absent, do not create a placeholder.

## Step 6: Update Reference YAML

Inspect `ida_preprocessor_scripts/references/` for both filenames and embedded annotations.

If a reference is named after the old symbol, rename the applicable Windows/Linux files and update
its identity fields. If it is named after another symbol, update only comments, `func_name`, or
other annotations that mention the old identity. Preserve `func_va`, disassembly, procedure text,
and all valid annotations generated for the current GoldSrc binary.

Reference files used by `LLM_DECOMPILE` must continue to match the exact `reference_yaml_paths`
and dependency basenames in the finder and config. Do not hand-edit generated addresses or generate
a new reference merely because a symbol was renamed.

## Step 7: Update Tests

For every test hit from Step 1, update fixture data, skill names, output paths, artifact identity
assertions, relation tuples, and test class/method names. When a vtable class changes, inspect
`func_vtable_relations` assertions separately; replacing the symbol name does not automatically
replace the class name.

Do not change tests that intentionally document a historical name unless the assertion describes
the current pipeline contract.

## Step 8: Update Downstream Finders

If another finder consumes `OldName`, update its Python constants and every corresponding config
dependency. Pay special attention to:

- `INHERIT_VFUNCS` base-vfunc paths such as `../client/OldName` without `.yaml`.
- `LLM_DECOMPILE` predecessor names and `dependency_policy` basenames.
- `FUNC_XREFS` symbolic function/global references.
- `expected_input`, `optional_input`, `prerequisite`, and `skip_if_exists` entries.

If the rename is the first step of a de-inline fix, stop after the original finder has become
`find-X-inlined` and use Pattern M for the helper and `find-X-noinline` chain. Register only `X` as
the public config symbol; the helper is an intermediate artifact.

## Step 9: Verify No Stale Identity Remains

Run searches for both the symbol and class forms:

```powershell
rg -n --glob '*.py' --glob '*.yaml' 'OldName|OldClass|OldClass::'
rg -n --glob '*.py' --glob '*.yaml' 'NewName|NewClass|NewClass::'
```

The old identity may remain only in an explicit historical note. Confirm that no stale finder
filename, artifact filename, downstream input, alias, or vtable relation remains. Review the diff
for accidental changes to addresses, signatures, bytes, or 4-byte vfunc offsets.

## Step 10: Run Regression Checks

For a named game version, run the affected module and platform(s) with old-version reuse disabled:

```powershell
uv run python ida_analyze_bin.py -gamever <GAMEVER> -modules <MODULE> -skill find-NewName -platform windows,linux -oldgamever none -debug
```

For an all-version rename, use:

```powershell
uv run python ida_analyze_bin.py -allgamever -modules <MODULE> -skill find-NewName -platform windows,linux -debug
```

Then run repository checks:

```powershell
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
```

Inspect every emitted YAML for the correct category identity, x86 address, unique signature, and
`vfunc_offset == vfunc_index * 4`. Generated `bin/` files are validation outputs and must not be
staged.

If the repository's non-MCP unittest command is needed for a fast pass, exclude only the IDA MCP
adapter/smoke modules and require zero selected failures:

```powershell
uv run python -c "from pathlib import Path; import sys, unittest; excluded={'test_ida_mcp_session', 'test_smoke_ida_mcp_2'}; modules=[f'tests.{path.stem}' for path in Path('tests').glob('test_*.py') if path.stem not in excluded]; result=unittest.TextTestRunner(buffer=True).run(unittest.defaultTestLoader.loadTestsFromNames(modules)); sys.exit(not result.wasSuccessful())"
```

## Step 11: Review Delivery

Review `git status --short`, `git diff`, and the final stale-name search. Keep unrelated existing
changes untouched, and stage only task-related tracked files; never use `git add -A` and never stage
`bin/` output. The repository delivery branch is `dev`; switch or create it only when the task
explicitly requests a commit. If committing is requested, use:

```text
refactor(preprocessor): rename OldName to NewName

Co-Authored-By: Codex <codex@openai.com>
```

Do not push or open a pull request unless separately requested.

## Checklist

- [ ] Finder file renamed with `git mv` and all identity strings updated
- [ ] Targeted `configs/<GAMEVER>.yaml` skill and symbol registrations updated
- [ ] Alias, downstream inputs, prerequisites, optional outputs, and skip entries updated
- [ ] GoldSrc artifact identity fields updated without changing binary-derived values
- [ ] Existing `bin/` outputs renamed locally and kept out of the index
- [ ] Reference YAML filenames and annotations updated where applicable
- [ ] Tests and vtable relation assertions updated where applicable
- [ ] No stale old identity remains outside historical documentation
- [ ] Named-version or all-version analyzer validation completed as applicable
- [ ] Format, unit, and repository-contract checks pass
- [ ] Only task-related tracked paths are staged if a commit was requested
- [ ] No push or PR was performed without a separate request

## Examples

### Simple function rename

For `ILoopType_EngineLoop` -> `CLoopTypeBase_EngineLoop`, rename the finder, update its
`GENERATE_YAML_DESIRED_FIELDS` key and function target, update every targeted config's skill/output/
symbol/alias entries, and rename matching `bin/*/engine` YAML files. Keep function signatures and
addresses unchanged.

### Class and downstream rename

For `ILoopType_DeallocateLoopMode` -> `CLoopTypeBase_DeallocateLoopMode`, update the vtable class in
`FUNC_VTABLE_RELATIONS`, config aliases, output `vtable_class` fields, dependent `skip_if_exists`
entries, and any tests asserting `(symbol, class)` tuples. A bulk symbol replacement alone is not
enough.

### Batch and compound names

For two renames in a compound finder filename, change only each renamed component. Update shared
downstream finders, reference comments, and both underscore and `::` alias forms in one reviewed
pass. Do not rename unrelated targets in the compound script.

### De-inline fix

When a helper carrying the original anchor becomes a separate function, rename the original finder
to `find-X-inlined`, then follow [Pattern M](../create-preprocessor-scripts/references/pattern-M.md)
to add the helper and `find-X-noinline` stages. Validate one inlined and one de-inlined GoldSrc
build on both declared platforms with old-version reuse disabled.
