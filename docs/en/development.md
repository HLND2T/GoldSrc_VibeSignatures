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
