---
name: create-agent-skill-fallback
description: |
  Create an Agent SKILL.md fallback for an existing find-XXXX finder that relies on a fragile discovery
  foundation — above all LLM_DECOMPILE (patterns C/D/E), which matches the decompiled shape of a predecessor
  function against a stored reference and breaks when a symbol is inlined or de-inlined in a way the reference
  does not cover. The generated fallback coexists with the preprocessor and runs only when it returns failure,
  recovering every target robustly by decompiling the predecessor and following the inline/de-inline boundary
  with semantic anchors. Use when a finder broke on a game update, or you want to durably backstop one before it
  does. The recipe generalizes to any finder foundation.
  Triggers: create agent skill fallback, add SKILL.md fallback, robust fallback for finder, backstop LLM_DECOMPILE finder, final guarantee skill
disable-model-invocation: true
---

# Create an Agent SKILL.md Fallback for a Finder (GoldSrc)

Given a target `find-XXXX` finder whose preprocessor uses a fragile foundation (most often **LLM_DECOMPILE**),
author `.claude/skills/find-XXXX/SKILL.md` — the **Agent fallback** that the GoldSrc pipeline
(`ida_analyze_bin.py`) runs only when the preprocessor returns failure (`failed` / `no_script`). The preprocessor
stays as-is; this skill adds a durable backstop beside it.

This is the robustness-oriented sibling of `/create-preprocessor-scripts` (that skill creates a GoldSrc
find-XXXX preprocessor; this one gives an existing preprocessor a SKILL.md *fallback*). It preserves the
CS2 recipe but targets **GoldSrc x86 only**: PE32/ELF32, I386, 4-byte vtable slots, no Source2-only
discovery protocols.

## When to Use

- A `find-XXXX` finder failed on a new game version because a member/vfunc/function was **inlined or
  de-inlined** relative to what its LLM_DECOMPILE reference expects (classic symptom: one target in a
  multi-target `-decompiles` skill can no longer be found, aborting the module).
- You want to **pre-emptively** backstop an LLM_DECOMPILE-based finder (patterns C/D/E) whose correctness hinges
  on a predecessor keeping a fixed decompiled shape.
- The recipe also applies to xref-string / found_call / index-based finders — the foundation differs, but the
  same "self-contained, skip-existing, anchor semantically, follow the callee" method holds.

Do **not** use this to replace a working preprocessor. The fallback is a safety net; the preprocessor remains
the fast path.

## The one constraint that drives the whole design

When the preprocessor fails, `agent_runner.run_skill` launches the agent with a prompt of **only
`/{skill_name}`** (see `_build_claude_command`, profile `sig-finder`; Codex/OpenCode get
`.claude/skills/<skill_name>/SKILL.md`). The skill's `expected_yaml_paths` is used **only** for post-run
missing-file verification (`_missing_expected_outputs` / `_result_failure`) — it is **never** injected into the
prompt, and the missing list is not fed back to the agent on retry.

Consequence: the fallback SKILL.md you generate MUST be **fully self-contained**. It must enumerate every
output, gate each by platform, and tell the agent to **skip outputs whose YAML already exists** (the
preprocessor may have written most of them before failing; earlier fallback skills may have written others).

## Inputs to gather (read these before writing anything)

For target finder `find-XXXX` in module `<module>` (`engine`, `client`, `server`, `gameui`, …):

1. **Preprocessor** `ida_preprocessor_scripts/find-XXXX.py` — the source of truth for *what* to find:
   - `TARGET_FUNCTION_NAMES`, `TARGET_STRUCT_MEMBER_NAMES`, `TARGET_GLOBALVAR_NAMES`, `TARGET_VTABLE_CLASS_NAMES`
     and any `*_WINDOWS` / `*_LINUX` variants → the output symbols and their **platform gating**.
   - `LLM_DECOMPILE` (and `_WINDOWS`/`_LINUX`) → the **predecessor** reference each target is mined from.
     Render `{gamever}` with the current gamever first; if that file is absent, render it with the
     canonical reference gamever from `GSVIBE_REFERENCE_GAMEVER` (default `hl-10210`).
   - `FUNC_VTABLE_RELATIONS` → which targets are vtable-related (`vtable_name`).
   - `GENERATE_YAML_DESIRED_FIELDS` → the **exact fields and kind** for each target (this tells you whether a
     target is a struct member, an indirect-vcall vfunc, a real vfunc, a regular func, or a global var — see the
     kind table below).
   - any `FUNC_XREFS` (string/gv anchors) — extra fingerprints you can reuse.
2. **`configs/<GAMEVER>.yaml` skill entry** — `expected_output` / `expected_output_windows` /
   `expected_output_linux` (authoritative output list per platform), `expected_input` (the predecessor YAML),
   `expected_input_windows`/`expected_input_linux`, `prerequisite`.
3. **Reference YAMLs**
   `ida_preprocessor_scripts/references/<REFERENCE_GAMEVER>/<module>/<predecessor>.{platform}.yaml` — resolve
   `REFERENCE_GAMEVER` with the current-then-canonical rule above. The `disasm_code` + `procedure` carry the
   annotations (`; 0xNN = Class::member` / `; 0xNN = Class::vfunc` / `// NNNN = 0xNN = …`) at each access/call
   site. **These annotations are the semantic fingerprints** you translate into the fallback's anchors. Also
   collect any real-world helper or alternate inline/de-inline reference YAML that materially helps locate the
   targets.
4. **Ground-truth output YAMLs** `bin/<gamever>/<module>/<target>.{platform}.yaml` — the **authoritative**
   offsets, vfunc indices, and signature styles the finder currently produces. Mine these for the reference
   values in the inventory table. `<gamever>` comes from the explicit request; **there is no `GSVIBE_GAMEVER`
   fallback**. `bin/` is a tracked git submodule (see below) — read whatever versions exist, never edit it.

Cross-check every value across the reference annotation AND the ground-truth YAML; where they disagree, trust
the ground-truth YAML and note the discrepancy (references occasionally mis-annotate — see the decoy caution).

### GoldSrc x86 profile — keep these invariants in every emitted YAML

- Windows binary is **PE32 / I386**; Linux binary is **ELF32 / I386**.
- `this`/receiver register: **ECX** (MSVC thiscall, Windows) or the **first stack argument `[esp+4]`/`[ebp+8]`**
  (GCC i386, Linux). All member accesses are relative to that pointer.
- **Vtable pointer/slot width is always 4 bytes** ⇒ `vfunc_offset == vfunc_index * 4`. This is not CS2's 8-byte
  x64 model; never multiply by 8.
- Indirect virtual calls are **`call dword ptr [reg + disp]`** (Windows) / **`call dword ptr [reg + disp]`**
  (Linux) on a 32-bit pointer — the displacement `disp` is the `vfunc_offset`, `vfunc_index = disp / 4`.
- Environment variables and config values use the `GSVIBE_*` namespace only; reject `OPENAI_*` / `CS2VIBE_*`.

## Workflow

### Step 1 — Build the output inventory

From the preprocessor `.py` + config entry, list every output as `(symbol, kind, platform, predecessor,
desired-fields)`. Determine `kind` from `GENERATE_YAML_DESIRED_FIELDS` using this table (GoldSrc x86:

| Kind | Tell-tale desired fields | Sig-gen skill | Writer skill |
|------|--------------------------|---------------|-------------|
| struct member | `struct_name, member_name, offset, offset_sig[, size, offset_sig_disp]` | `/generate-signature-for-structoffset` | `/write-structoffset-as-yaml` |
| indirect vcall (`call dword ptr [reg+disp]`, no body) | `vfunc_sig, vfunc_offset, vfunc_index, vtable_name` and **no** `func_va`/`func_sig` | `/generate-signature-for-vfuncoffset` | `/write-vfunc-as-yaml` (`func_addr=None`, `func_sig=None`, 4-byte slots) |
| real vtable vfunc (has a body) | `func_va/func_sig` **and** `vtable_name/vfunc_offset/vfunc_index` | `/generate-signature-for-function` | `/write-vfunc-as-yaml` (+ vtable fields, `vfunc_index = offset/4`) |
| regular function | `func_name, func_sig, func_va, func_rva, func_size` (no vtable fields) | `/generate-signature-for-function` | `/write-func-as-yaml` |
| global variable | `gv_name, gv_va, gv_sig, gv_inst_*` | `/generate-signature-for-globalvar` | `/write-globalvar-as-yaml` |

The indirect-vcall kind is easy to miss: its YAML has **no `func_va`** and its `vfunc_sig` is the signature of
the *call instruction itself* (e.g. `FF 90 80 00 00 00` = `call dword ptr [eax+80h]`), not of any target
function body. Treat it as such — do not try to resolve a concrete implementation address.

GoldSrc artifact schema: a YAML payload may contain **only** its category-specific identity fields
(`func_name` / `gv_name` / `patch_name` / `vtable_class` / `struct_name`+`member_name`) plus the data fields —
never generic `name`, `type`, or `kind`. The payload identity is not required to equal the config symbol `name`.

### Step 2 — Confirm platform gating and the predecessor

From the config entry, record which outputs are cross-platform vs `expected_output_windows` /
`expected_output_linux`, and the predecessor(s) from `expected_input` / `expected_input_windows` /
`expected_input_linux`. A symbol that is de-inlined into a separate function on one platform but inlined on the
other is common (that asymmetry is often *why* the finder is fragile).

### Step 3 — Extract per-target fingerprints

For each target, read its access/call site in the reference `disasm_code` + `procedure` and write down:
- the **semantic anchor**: the nearest stable landmark — a string literal, a magic constant, a named
  global/interface call, a distinctive helper — that identifies the site independent of address;
- the **`this`-relative offset** (members) or **call displacement** (indirect vcalls) or **vtable index**;
- the **reference value** from the ground-truth `bin/` YAML (both platforms where they differ).

### Step 4 — Write the fallback SKILL.md

Create `.claude/skills/find-XXXX/SKILL.md` from the template below. Fill every placeholder; keep only the
target kinds that actually occur. The output filename MUST equal the finder's skill name so
`agent_runner.run_skill` finds it.

The generated fallback MUST contain `## Realworld Function References` near the top, before the background.
List one exact repo-relative YAML path per bullet for every platform-relevant predecessor and useful
inline/de-inline helper or variant. Spell out `.windows.yaml` and `.linux.yaml` paths separately; do not use
`{platform}` shorthand in this section, because the agent must be able to open each reference directly. State
that addresses and offsets are reference-build values that still require verification against the current
binary.

**GoldSrc self-containment:** the fallback references the GoldSrc sub-skill set that ships in this repo —
`get-func-from-yaml`, `get-vtable-from-yaml`, `get-vtable-address`, `get-vtable-index`,
`generate-signature-for-function`, `generate-signature-for-globalvar`, `generate-signature-for-patch`,
`generate-signature-for-structoffset`, `generate-signature-for-vfuncoffset`, `write-func-as-yaml`,
`write-globalvar-as-yaml`, `write-patch-as-yaml`, `write-structoffset-as-yaml`, `write-vfunc-as-yaml`,
`write-vtable-as-yaml`. The fallback MUST use these skills by name (e.g. `/write-func-as-yaml`) rather than
inlining raw snippets, and must not reference any skill outside that set. All of them enforce the GoldSrc x86
schema (category-specific identity, no `name/type/kind`, 4-byte vfunc slots).

### Step 5 — Validate

- `uv run python format_repo_files.py --check`
- `uv run python tests/run_test_suite.py unit -b --durations 30`
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`
  (guard; a pure-doc addition should not affect tests.)
- Re-read the generated SKILL.md against the inventory: is every output listed, platform-gated, and mapped to an
  sub-skill pair with correct params? Are all x86 invariants (4-byte slots, ECX/stack `this`)
  present and consistent?
- Run the fallback itself in the real IDA/MCP environment, bypassing both old-version reuse and preprocessing:

  ```bash
  uv run python ida_analyze_bin.py -gamever <gamever> -oldgamever none -modules <module> -skill find-XXXX -platform windows,linux -skip_pp -debug
  ```

  The selected game version must contain the module binary and every configured `expected_input`. Ensure at
  least one expected output for each tested platform is absent; if all outputs already exist, use a disposable
  game-version copy or temporarily back up the target outputs outside the binary directory and restore them
  afterward. A run that says all outputs already exist and skips the skill is **not** a valid Agent-Skill-only
  test.

  `-gamever` or `-allgamever` is required — there is no `GSVIBE_GAMEVER` fallback. `-oldgamever none` disables
  old-version reuse. `-platform windows,linux` is passed explicitly.

- Require the log to show `Agent Skill only mode: enabled (-skip_pp)` and a summary of
  `Successful: N / Failed: 0 / Skipped: M`, then verify the agent actually started (e.g. an `AGENT_FALLBACK`
  / attempt progress event in `-debug`, or that the previously-absent YAMLs now exist). The GoldSrc pipeline does
  **not** print a `Skipping preprocess: …` or `Starting agent skill: …` line for the skill itself; do not grep
  for those. Verify that every expected YAML for the tested platform was produced and parses as a non-empty
  mapping.

Do not report the fallback as complete unless this end-to-end Agent-Skill-only test passes. If the real IDA/MCP
environment is unavailable, report the validation as blocked rather than substituting a preprocessor run or a
ground-truth-only review.

### Step 6 — Commit Changes to `dev`

After the end-to-end fallback test has produced and verified its YAMLs, record the required one-line memory
pointer per the repo workflow. Ensure the delivery branch is `dev`; never commit directly to `main`. If the
local `dev` branch exists, switch to it. Otherwise, switch to `main` first and create `dev` from `main`:

```bash
if git show-ref --verify --quiet refs/heads/dev; then
  git switch dev
else
  git switch main
  git switch -c dev
fi
```

If any branch switch fails, stop and report the error. Review `git status --short`, then explicitly stage the new
fallback skill and that memory update; never use `git add -A`:

```bash
git add -- .claude/skills/find-XXXX/SKILL.md <memory-pointer-path>
git diff --cached --name-only
```

`bin/` is a tracked **git submodule** (a separate repo). Never stage `bin/` paths — the ground-truth YAMLs there
are validation inputs, not deliverables of this task. Stop if the staged-path list contains anything unrelated
to this task. Commit only the staged task changes using the repository commit format:

```bash
git commit -m "feat(skills): add find-XXXX fallback" -m "Co-Authored-By: Codex"
```

Do not push the branch, call `/create-pr`, or open a pull request unless the user separately requests it. Finish
by reporting the commit hash, tested game version, format/unit/repository-contract results, and Agent-Skill-only
result.

---

## Fallback SKILL.md template (GoldSrc)

Fill placeholders `<...>`; drop sections for kinds that do not apply.

````markdown
---
name: find-XXXX
description: |
  Final-guarantee fallback for the find-XXXX preprocessor. Recovers <one-line summary of the targets> in GoldSrc
  <module> binaries by decompiling <PREDECESSOR> and following de-inlined callees when a target is no longer
  accessed directly. Use when the deterministic/LLM preprocessor (ida_preprocessor_scripts/find-XXXX.py) could
  not resolve every target because a symbol was inlined or de-inlined in a way the LLM_DECOMPILE references do
  not cover.
  Trigger: <every target symbol, comma-separated>
disable-model-invocation: true
---

# Find XXXX (final-guarantee fallback)

Recover every symbol the find-XXXX preprocessor produces, in GoldSrc `<binary.dll>` / `<binary.so>` (PE32/I386
and ELF32/I386), using IDA Pro MCP tools. This is the Agent fallback: it runs only when the preprocessor returned
failure — which almost always means a target's access pattern **moved** across the inline/de-inline boundary.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. Treat their addresses and offsets as
reference-build values only; verify every result against the current binary.

- `ida_preprocessor_scripts/references/<REFERENCE_GAMEVER>/<module>/<predecessor>.windows.yaml`
- `ida_preprocessor_scripts/references/<REFERENCE_GAMEVER>/<module>/<predecessor>.linux.yaml`
- `ida_preprocessor_scripts/references/<REFERENCE_GAMEVER>/<module>/<relevant-helper-or-variant>.windows.yaml`
- `ida_preprocessor_scripts/references/<REFERENCE_GAMEVER>/<module>/<relevant-helper-or-variant>.linux.yaml`

Resolve `REFERENCE_GAMEVER` independently for each reference: prefer the current gamever when that exact file
exists, otherwise use the canonical reference gamever. Spell out each resolved, existing path literally and
drop non-applicable placeholders or platforms.

## Background — <PREDECESSOR> and what it wires up

<2–5 sentences: what the predecessor does and which targets it touches, in source terms. Note that all member
accesses are relative to `this` (arg1: ECX on Windows thiscall, first stack arg on Linux GCC i386) — the key to
robustness.>

## Robustness principle — follow the de-inline boundary

For every target: (1) look for its access pattern inside `<PREDECESSOR>`; (2) if absent, it was de-inlined —
enumerate the functions `<PREDECESSOR>` calls, decompile the plausible ones, and search there (the helper
receives `this` as its first argument, so the same `this + offset` reappears; recurse a level or two);
(3) conversely a target the reference expected in a separate function may have been inlined back into
`<PREDECESSOR>`. Anchor each target by its semantic fingerprint (string / constant / neighboring call), never by
a fixed address or containing function.

## Output inventory

`struct_name` is `<STRUCT>` where applicable. Offsets/indices are **reference values from build <gamever> —
verify against the binary, do not assume**. Vtable slots are 4 bytes: `vfunc_offset == vfunc_index * 4`.

| # | Output symbol | Kind | Windows | Linux | Writer snippet |
|---|---------------|------|---------|-------|---------------|
| 1 | `<symbol>` | <kind> | `<value or "inlined — skip">` | `<value or "inlined — skip">` | `/write-...-as-yaml` |
| … | | | | | |

Platform gating: <list cross-platform vs windows-only / linux-only outputs>.

## Step 0. Skip targets already produced

For each output, if `<name>.<platform>.yaml` already exists beside the binary and parses to a non-empty mapping,
skip it — the preprocessor or an earlier fallback wrote it. List the directory with:

```
mcp__ida-pro-mcp__py_eval code="import idaapi, os; d=os.path.dirname(idaapi.get_input_file_path()); print('\n'.join(sorted(f for f in os.listdir(d) if f.endswith('.yaml'))))"
```

For functions/vfuncs, resolving the predecessor (Step 1) also reports whether its YAML exists.

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=<PREDECESSOR>` to get its `func_va`. If it errors,
**STOP** and report to user. Then:

```
mcp__ida-pro-mcp__decompile addr="<PREDECESSOR.func_va>"
```

Note the `this` register (ECX on Windows thiscall / `[ebp+8]`-style stack arg on Linux GCC i386) and keep the list
of called functions for the de-inline search.

## Step 2…N. Resolve each target

<One subsection per target (or per cluster sharing a call site). For each: the semantic anchor, the
this-relative offset / call displacement / vtable index, the reference value, and how to handle de-inline. Note
any decoys.>

## Signatures and YAML output

For each resolved target, produce its YAML via the appropriate **GoldSrc sub-skill** (see the kind table in
Step 1): `/generate-signature-for-function`, `/generate-signature-for-globalvar`,
`/generate-signature-for-structoffset`, or `/generate-signature-for-vfuncoffset` for the signature, then
`/write-func-as-yaml`, `/write-globalvar-as-yaml`, `/write-structoffset-as-yaml`, or `/write-vfunc-as-yaml` to
persist it beside the binary. For vtable-backed targets, resolve the vtable with `/get-vtable-from-yaml` or
`/get-vtable-address`, and find a function's slot with `/get-vtable-index`.

For **struct members**, write `struct_name`, `member_name`, `offset`, and `offset_sig` (offset is the must-have;
the signature may be omitted when a unique one can't be found). For **indirect vcalls**, write `vtable_name`,
`vfunc_offset = disp`, `vfunc_index = disp/4`, and a `vfunc_sig` pinning the `call dword ptr [reg+disp]`
instruction — **no `func_va`** (use `/write-vfunc-as-yaml` with `func_addr=None`, `func_sig=None`). For **real
vtable vfuncs**, include `func_va`/`func_sig` and the vtable fields.

## Failure handling

- Predecessor YAML missing → check the current gamever path, then the canonical reference gamever path.
  Only stop after both candidates are absent, and report both attempted paths.
- A required target unresolved even after following callees → resolve the rest, then **STOP** and report exactly
  which output(s) failed so the user can extend the references.
- Never emit a platform-gated symbol on the wrong platform.

## Output YAML filenames

Written beside the binary, one per symbol: `<symbol>.windows.yaml` / `<symbol>.linux.yaml`.
````

---

## Robustness principles (the heart of a good fallback)

1. **Anchor semantically, not positionally.** A fixed address or "it's in function F" breaks on the next update.
   A string literal, a magic constant (e.g. a CRC32/random seed, an engine string), a named interface call, or a
   distinctive helper survives.
2. **`this + offset` is stable across the inline boundary.** Struct offsets are relative to the class pointer
   (arg1: ECX on Windows thiscall, first stack arg on Linux GCC i386). Whether the access is inlined in the
   predecessor or de-inlined into a helper that receives `this`, the same `this + offset` appears — so members
   are recoverable either way.
3. **Follow the callee (the core move).** If a target isn't in the predecessor, enumerate the predecessor's
   calls, decompile them, and recurse. This is what makes the fallback a *guarantee* rather than a re-run of the
   fragile reference match. Cover the inline-back case too.
4. **Know the x86 indirect-vcall shape.** For `call dword ptr [reg + disp]` on an interface pointer, the output
   is `vtable_name` + `vfunc_offset = disp` + `vfunc_index = disp/4` + a `vfunc_sig` pinning the call instruction;
   there is **no `func_va`**. Resolve the interface from the receiver global's type. Slots are always 4 bytes.
5. **Watch for decoys.** References sometimes annotate two nearby offsets with the same member name. Trust the
   ground-truth `bin/` YAML. (GoldSrc precedent: two closely spaced `this+disp` accesses can share a field label;
   the true member is the one the reference value matches.)
6. **The offset is the must-have; the signature is best-effort.** For struct members, `offset` is the required
   output; `offset_sig` is for relocation and may legitimately be omitted (write offset only) when a unique
   signature can't be found — especially for members whose access spans a function boundary.
7. **GoldSrc x86 invariants are non-negotiable.** PE32/ELF32, I386, 4-byte vtable slots
   (`vfunc_offset == vfunc_index * 4`), `GSVIBE_*` namespace, and artifact payloads with category-specific
   identity only.

## Checklist

- [ ] Read the target preprocessor `.py`, its config entry, its reference YAMLs, and its `bin/` ground-truth
      output YAMLs.
- [ ] Output inventory lists **every** symbol with kind + platform + predecessor + reference value.
- [ ] Fallback SKILL.md filename equals the finder's skill name.
- [ ] `## Realworld Function References` lists exact, directly openable repo-relative YAML paths for each
      relevant platform and inline/de-inline helper or variant; it contains no `{platform}` shorthand.
- [ ] SKILL.md is fully self-contained: references only the GoldSrc sub-skill set that exists in this repo
      (`get-func-from-yaml`, `get-vtable-from-yaml`, `get-vtable-address`, `get-vtable-index`,
      `generate-signature-for-*`, `write-*-as-yaml`); enumerates all outputs, gates by platform, has the Step-0
      skip-existing step.
- [ ] Each target has a semantic anchor and the follow-the-callee instruction; decoys are called out.
- [ ] Each kind is mapped to the correct sub-skill with correct params (indirect vcalls use
      `/write-vfunc-as-yaml` with `func_addr=None`/`func_sig=None` + `vfunc_index = disp/4`; real vfuncs use
      `vfunc_index = offset/4`).
- [ ] x86 invariants present and consistent (PE32/ELF32, `this`=ECX/stack-arg, 4-byte slots).
- [ ] Failure handling + output-filename sections present.
- [ ] `format_repo_files.py --check`, `unit`, and `repository-contract` suites pass.
- [ ] Values cross-checked against `bin/` ground truth.
- [ ] Real Agent-Skill-only test passed with `uv run python ida_analyze_bin.py -gamever <gamever> -oldgamever
      none -modules <module> -skill find-XXXX -platform windows,linux -skip_pp -debug`; the log proves
      preprocessing was skipped (`Agent Skill only mode: enabled (-skip_pp)`), the Agent actually started and
      produced the previously-absent expected YAMLs, and the summary reports `Failed: 0`.
- [ ] The current branch is `dev` (created from `main` when it did not already exist).
- [ ] New SKILL.md and memory pointer are explicitly staged; no `bin/` (submodule) paths staged.
- [ ] No push or PR was performed without a separate user request.
