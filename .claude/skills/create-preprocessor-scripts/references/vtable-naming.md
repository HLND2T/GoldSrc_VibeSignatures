# Vtable naming convention

Use for every `category: vtable` target: primary vtables via `vtable_class_names` /
`preprocess_vtable_via_mcp`, secondary/ordinal vtables via Pattern H, and any finder that emits a
vtable artifact.

## Rule

The vtable symbol name and the artifact stem are `<vtable_class>_vtable`, with **`vtable`
spelled in full and never abbreviated to `vftable`**.

| Item | Value |
|---|---|
| Config symbol `name` | `<vtable_class>_vtable` |
| Artifact file | `<vtable_class>_vtable.<platform>.yaml` |
| Config `category` | `vtable` |
| Artifact payload identity | `vtable_class: <vtable_class>` |
| Secondary/ordinal table (Pattern H) | `<vtable_class>_vtable2`, `<vtable_class>_vtable3`, ... |

`<vtable_class>` is the real C++ class name recovered from RTTI or the demangled vtable symbol,
with no suffix. The `_vtable` suffix belongs only to the config/artifact identity, never to the
payload `vtable_class`.

```yaml
- name: CEngine_vtable
  category: vtable
```

```yaml
# bin_artifacts/<tag>/<module>/CEngine_vtable.windows.yaml
vtable_class: CEngine
vtable_symbol: ??_7CEngine@@6B@
vtable_va: '0x102c83a4'
```

## Why one spelling

`vftable` is MSVC/IDA decompiler terminology for the same object. Using it as an artifact
identity creates two spellings of one concept, so `grep _vtable` and any tooling keyed on the
materialized filename silently miss the `_vftable` outputs. The repository spelling is `vtable`;
`write_vtable_yaml`, the `vtable` category, and the `vtable_*` payload fields all already use it.

A decompiler-rendered `::\`vftable'` or `_vptr_*_vftable` inside reference YAML is generated
binary text, not an artifact identity — do not rewrite it.

## Migration

Renaming an existing `_vftable` identity to `_vtable` is a symbol rename: update the finder,
every config `expected_output`/`name`, the `bin_artifacts/` filenames, and any downstream
`expected_input`/`skip_if_exists`/`base_vfunc_name` reference. Payload `vtable_class`, addresses,
and entries are unchanged. Follow
[rename-preprocessor-scripts](../../rename-preprocessor-scripts/SKILL.md).
