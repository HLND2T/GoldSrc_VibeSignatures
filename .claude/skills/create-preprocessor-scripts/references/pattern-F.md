# Pattern F — inherit a virtual slot

Use when a target shares a vtable slot with an already-produced base/concrete vfunc artifact.

## Standard mode

```python
INHERIT_VFUNCS = [
    ("{DERIVED_FUNC}", "{DERIVED_VTABLE}", "{BASE_VFUNC_ARTIFACT}", True),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "{DERIVED_FUNC}",
        [
            "func_name", "func_va", "func_rva", "func_size", "func_sig",
            "vtable_name", "vfunc_offset", "vfunc_index",
        ],
    ),
]
```

Config inputs include the base vfunc artifact and derived vtable artifact.

## Slot-only mode

```python
INHERIT_VFUNCS = [
    ("{INTERFACE_FUNC}", "{INTERFACE}", "{CONCRETE_IMPL_ARTIFACT}", False),
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{INTERFACE_FUNC}", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"]),
]
```

Slot-only mode activates only when `generate_func_sig=False` and the desired field set is exactly
the four fields above. It does not require an interface vtable artifact.

`base_vfunc_name` may be cross-module, for example
`../engine/INetworkMessages_FindNetworkGroup`.

Rules:

- Base offset/index must agree under 4-byte slot arithmetic.
- Standard mode reads the same index from the derived vtable and inspects the real function.
- Config category is `vfunc`; artifact identity is `func_name`.
