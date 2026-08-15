# Pattern M — inline/noinline fallback chain

Use when a helper carrying the original anchor is inlined into target `X` on some builds and
de-inlined on others.

Create this three-skill chain:

1. `find-{HELPER}`: Pattern A on the helper anchor; `optional_output`; `skip_if_exists: X`.
2. `find-{X}-noinline`: locate callers of HELPER, plus vtable relation if X is a vfunc;
   `optional_output`; prerequisite on HELPER.
3. `find-{X}-inlined`: original finder renamed; `expected_output`; `skip_if_exists: X`;
   prerequisite on the noinline finder.

```yaml
- name: find-{HELPER}
  optional_output:
    - {HELPER}.{platform}.yaml
  skip_if_exists:
    - {X}.{platform}.yaml
- name: find-{X}-noinline
  optional_output:
    - {X}.{platform}.yaml
  prerequisite:
    - find-{HELPER}
- name: find-{X}-inlined
  expected_output:
    - {X}.{platform}.yaml
  skip_if_exists:
    - {X}.{platform}.yaml
  prerequisite:
    - find-{X}-noinline
```

Add the vtable artifact as `expected_input` on both target paths when X is a vfunc. Depend on the
optional helper through `prerequisite`, never `expected_input`.

Rules:

- Register only X as a config symbol; HELPER is an intermediate artifact.
- Keep/drop `func_sig` consistently on both X paths.
- Keep it for substantial bodies and regular functions; omit it for tiny forwarding vfunc thunks.
- Preserve the original inlined finder as the final load-bearing fallback.
- Validate one inlined and one de-inlined build on both platforms with old-version reuse disabled.
