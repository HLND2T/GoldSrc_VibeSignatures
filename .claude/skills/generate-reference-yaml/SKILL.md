---
name: generate-reference-yaml
description: Generate one GoldSrc LLM-decompile reference YAML through the project CLI under the module-specific ida_preprocessor_scripts/references directory. Use when a preprocessor needs annotated disassembly and pseudocode for an LLM_DECOMPILE predecessor.
---

# Generate GoldSrc Reference YAML

Use this skill as the single backend entrypoint for reference YAML generation. Do not call IDA APIs
directly and do not hand-build the initial YAML. Always run `generate_reference_yaml.py`, then make
only the semantic annotations required by the downstream `LLM_DECOMPILE` target.

## Required target identity

- `func_name`: canonical predecessor artifact name.
- `gamever`: GoldSrc tag such as `hl-10210`.
- `module`: module that owns the predecessor artifact.
- `platform`: `windows` or `linux`.

The CLI can infer `gamever`, `module`, and `platform` from the currently bound IDB path when it is
under `bin/<gamever>/<module>/<binary>`. Prefer explicit values in scripted workflows. There is no
`GSVIBE_GAMEVER` fallback.

## Command modes

### 1. Attach to an existing MCP database

Use this when the exact binary is already open through the repository MCP lifecycle:

```powershell
uv run python generate_reference_yaml.py -gamever <GAMEVER> -module <MODULE> -platform windows -func_name <FUNC_NAME> -mcp_host 127.0.0.1 -mcp_port 13337
```

When the MCP supervisor exposes more than one active database, pass
`-mcp_database <SESSION_ID>`. Database selection fails closed rather than binding an arbitrary IDB.

### 2. Auto-start an owned MCP lifecycle

Use the exact binary filename declared by `module_windows` or `module_linux` in the selected
`configs/<GAMEVER>.yaml`:

```powershell
# Windows -- always pass -platform windows explicitly
uv run python generate_reference_yaml.py -gamever <GAMEVER> -module <MODULE> -func_name <FUNC_NAME> -auto_start_mcp -binary "bin/<GAMEVER>/<MODULE>/<WINDOWS_BINARY>" -platform windows -debug

# Linux -- always pass -platform linux explicitly
uv run python generate_reference_yaml.py -gamever <GAMEVER> -module <MODULE> -func_name <FUNC_NAME> -auto_start_mcp -binary "bin/<GAMEVER>/<MODULE>/<LINUX_BINARY>" -platform linux -debug
```

Auto-start accepts only PE32/I386 for Windows and ELF32/I386 for Linux. It uses the repository's
owned `IdaMcpLifecycle`, verifies the exact opened database identity, and cleans up only the worker
it owns.

Always pass `-platform` explicitly in skill workflows. Generate only the platforms declared by the
selected module in `configs/<GAMEVER>.yaml`. When both are declared, run Windows and Linux
sequentially, never in parallel: both commands use the same MCP host and port.

### 3. Custom output name

Use `-output_filename` only when the reference filename intentionally differs from
`<func_name>.<platform>.yaml`:

```powershell
uv run python generate_reference_yaml.py -gamever <GAMEVER> -module <MODULE> -platform windows -func_name <FUNC_NAME> -output_filename <REFERENCE_NAME>.windows.yaml -mcp_host 127.0.0.1 -mcp_port 13337
```

The value must be a `.yaml` filename, not a path. The file remains below
`ida_preprocessor_scripts/references/<module>/`, and its `func_name` remains the canonical value
passed to `-func_name`.

## Address resolution

The generator resolves the predecessor address in this order:

1. `bin/<gamever>/<module>/<func_name>.<platform>.yaml` `func_va`.
2. The config symbol's canonical `name` and `alias` values looked up in the bound IDB.

Alias lookup must resolve to exactly one function start. Missing and ambiguous matches fail closed.

## Output contract

Default path:

`ida_preprocessor_scripts/references/<module>/<func_name>.<platform>.yaml`

The generated mapping contains exactly:

```yaml
func_name: <canonical predecessor name>
func_va: <x86 virtual address>
disasm_code: |-
  <IDA disassembly, including existing comments>
procedure: |-
  <Hex-Rays pseudocode; may be empty when Hex-Rays is unavailable>
```

After generation, verify that `func_va` belongs to the selected binary and `disasm_code` is non-empty.
The canonical name alone does not prove that address resolution was correct.

## `LLM_DECOMPILE` wiring and annotation

In a target `ida_preprocessor_scripts/find-*.py`, use the path relative to
`ida_preprocessor_scripts/`:

```python
"reference_yaml_paths": [
    "references/<module>/<func_name>.<platform>.yaml",
]
```

Rename or comment the desired calls, globals, vcalls, and struct accesses in both `disasm_code` and
`procedure`. Struct members require the exact
`(structmember, struct=StructName, member=member_name)` tag. Do not change `func_name` or `func_va`
while annotating.

Regeneration replaces the file. Inspect its Git diff and restore any still-valid annotation comments
verbatim from removed diff lines; do not reconstruct them from memory.
