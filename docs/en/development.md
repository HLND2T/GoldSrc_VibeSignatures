[Back to README](../../README.md) | [中文](../zh-CN/development.md)

# Development checks

## Formatting

This repository formats Git-tracked `*.py` files with `ruff format` and Git-tracked `*.yaml` files with `yamlfix`.

Format locally before committing:

```bash
uv run python format_repo_files.py
```

Run the same formatting gate used by GitHub Actions:

```bash
uv run python format_repo_files.py --check
```

The formatter only uses files returned by `git ls-files --cached -- '*.py' '*.yaml'`, so ignored files and untracked scratch files are skipped.

## Tests

Use the fast isolated suite during local edit-test loops:

```bash
uv run python tests/run_test_suite.py unit -b --durations 30
```

The remaining source-owned suites keep repository structure and Redis coverage explicit:

```bash
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
```

Run every source-compatible assigned test before completion:

```bash
uv run python tests/run_test_suite.py all -b --durations 30
```

`all` is the declared disjoint union of unit, Redis integration, repository contract, and IDA integration groups. Release
bundle and publisher contracts are ordinary unit tests; live GitHub publication and commercial IDA evidence remain
separate operational gates.

Commercial IDA integration is skipped unless `RUN_IDA_INTEGRATION=1` and an activated `idalib` environment are available. A skipped integration test is not evidence that real IDA analysis passed.

## Static LLM declarations

Every preprocessor that owns LLM specs declares one unconditional module-level `LLM_DECOMPILE = ...`.
Use a literal list of spec dictionaries; use a literal `dict[str, list[dict]]` when runtime branches need different
references or policies. Each branch is independently normalized by the same pure rules used by the runtime.
Names, f-strings, comprehensions, calls, dictionary unpacking, duplicate keys and declaration mutation are rejected.
The permitted path placeholders are `{gamever}`, `{platform}`, `{module_name}` and `{module}`.

Pass `LLM_DECOMPILE` or a selected branch directly as `llm_decompile_specs`. For a subset, runtime scalar values,
or verified instruction rules, import `select_llm_specs` from `llm_spec`:

```python
specs = select_llm_specs(
    LLM_DECOMPILE,
    branch=selected_branch,
    symbols=verified_symbols,
    expected_values=verified_values,
)
```

This copies the selected specs. Only `expected_value` and `instruction_rules` can be supplied at runtime;
symbols, prompts, references and dependency policies stay in the declaration. Helpers forwarding specs accept a
keyword-only `llm_decompile_specs` argument. They may still read artifacts during actual analysis.

The existing repository-contract suite audits every preprocessor source. Its AST checker accepts direct selections,
scoped aliases, literal kwargs dictionaries and the shared selection function. Arbitrary spec factories, dynamic kwargs,
mutation and reflective Python dataflow are outside this authoring contract. Scanner validation never imports or executes
preprocessor code. Import ownership includes existing package initializers and children in `from package import helper`,
including aliases, relative imports and namespace packages; imported attributes do not invent missing submodules.

The planner collects the union of all branch resources, so a reference change may select extra nodes across runtime
branches. Current/family/default reference fallback is unchanged. Historical trees with unsupported declarations remain
usable for source ownership, but **any reference or prompt change conservatively selects their consumers**, including
new/deleted/renamed resources. Warnings identify the affected sources and node count. Strict current-tree auditing prevents
new declarations from relying on this compatibility fallback; orphan-reference diagnostics remain warnings.

PR planning still runs the trusted base's tooling. Merge the scanner support before depending on it for new authoring
forms. This migration emits ordinary literal resource paths already readable by the previous scanner; the new strict
source audit runs through the existing tests. Rerunning an old workflow does not upgrade its planner.
