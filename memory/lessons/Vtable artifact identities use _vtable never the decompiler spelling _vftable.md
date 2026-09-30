---
title: Vtable artifact identities use _vtable, never the decompiler spelling _vftable
type: note
permalink: goldsrc-vibesignatures/lessons/vtable-artifact-identities-use-vtable-never-vftable
tags:
- lesson
- preprocessor
- vtable
- artifact
- naming
---

# Vtable artifact identities use `_vtable`, never the decompiler spelling `_vftable`

## Trigger

Reviewing or adding a `category: vtable` symbol, or finding an artifact whose stem ends in
`_vftable`. The repository held both spellings: 191 artifacts with `_vtable` and 47 with
`_vftable`, so `grep _vtable` over `bin_artifacts/` silently missed the 47.

## Root cause / constraints

- All 47 divergent artifacts belonged to one class. `KeyValues_vftable` (30, gameui/serverbrowser)
  and `ClientVGUI_KeyValues_vftable` (17, client) were introduced by
  `ida_preprocessor_scripts/find-client-vgui-keyvalues.py`, which carried MetaHookSv terminology
  (`vftable[2]`) instead of the repository convention.
- The convention is already fixed on the other side: `write_vtable_yaml` in
  `write-vtable-as-yaml` asserts `{vtable_class}_vtable.{platform}.yaml`, the config classifier is
  `vtable`, and every payload field is `vtable_*`. There is no semantic distinction between the two
  spellings — only terminology drift.
- The payload identity was never wrong: `vtable_class: KeyValues` was correct in every divergent
  file. Only the symbol/config/artifact stem carried the abbreviation.

## Correct approach

- Name a vtable symbol and its artifact stem `<vtable_class>_vtable`; secondary tables append an
  ordinal, `<vtable_class>_vtable2`. Never abbreviate `vtable` to `vftable`. Authoritative rule:
  `.claude/skills/create-preprocessor-scripts/references/vtable-naming.md`.
- A decompiler-rendered `` ::\`vftable' `` or `_vptr_*_vftable` inside a reference YAML is
  generated binary text, not an artifact identity — leave it untouched.
- Migrating an existing `_vftable` identity is a plain symbol rename: finder, config
  `expected_output`/`name`, downstream inputs, and the `bin_artifacts/` filenames. Payload
  `vtable_class`, addresses, and entries do not change. Use `rename-preprocessor-scripts`.

## Verification

2026-09-30: renamed both KeyValues identities across 47 artifact files (`git mv`, all reported as
renames), 21 configs, and the finder. `uv run python tests/run_test_suite.py repository-contract -b`
passed 14/14 both before and after; no `KeyValues_vftable` remained in `configs/`,
`ida_preprocessor_scripts/`, or `memory/`.

## Scope

Every `category: vtable` symbol in `configs/<tag>.yaml` and every `bin_artifacts/**/*_vtable*.yaml`
stem. See [[analysis-planner-and-artifact-contract]] for the artifact identity contract and
[[client-private-vgui-abi-and-artifact-identities]] for the KeyValues finder that drifted.
