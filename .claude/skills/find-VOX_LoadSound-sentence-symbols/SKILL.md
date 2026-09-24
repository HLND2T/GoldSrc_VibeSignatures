---
name: find-VOX_LoadSound-sentence-symbols
description: |
  Final-guarantee Agent fallback for the find-VOX_LoadSound-sentence-symbols preprocessor. Recovers the GoldSrc
  sentence-lookup symbols (SequenceGetSentenceByIndex, cszrawsentences, rgpszrawsentence, and — only where the
  lookup is a real standalone callee — VOX_LookupString) from VOX_LoadSound's `pszin[0] == '#'` lookup when the
  deterministic walk cannot match because the lookup moved across the inline/de-inline boundary.
  Use only for the engine module on PE32/I386 or ELF32/I386.
  Trigger: VOX_LoadSound-sentence-symbols, find-VOX_LoadSound-sentence-symbols, SequenceGetSentenceByIndex, cszrawsentences, rgpszrawsentence, VOX_LookupString
disable-model-invocation: true
---

# Find VOX sentence-lookup symbols (final-guarantee fallback)

Recover the GoldSrc sentence-lookup symbols from `VOX_LoadSound` in the loaded `hw.dll` (PE32/I386) or `hw.so`
(ELF32/I386) with IDA Pro MCP tools. This fallback runs only after
`ida_preprocessor_scripts/find-VOX_LoadSound-sentence-symbols.py` fails.

**Do not repeat the preprocessor's strict requirements.** It requires an exact instruction shape: a single
`cmp byte ptr [reg], 23h` (or `movsx` + `cmp reg, 23h`) with `jz`/`jnz` immediately after, exactly two calls on
the straight-line equal branch, exactly one loop re-reading the count, and exactly one other global reaching
that loop. Recover the same symbols from the *semantics* of the lookup instead, tolerating encodings, register
allocation, basic-block layout, and — most importantly — the inline/de-inline boundary.

## Realworld Function References

Read the platform-relevant YAMLs first. These are Git-tracked reference-build evidence: never copy an address
from them into a different binary without verifying it.

- `bin_artifacts/hl-10210/engine/VOX_LoadSound.windows.yaml`
- `bin_artifacts/hl-10210/engine/VOX_LoadSound.linux.yaml`
- `bin_artifacts/hl-10210/engine/SequenceGetSentenceByIndex.windows.yaml`
- `bin_artifacts/hl-10210/engine/SequenceGetSentenceByIndex.linux.yaml`
- `bin_artifacts/hl-8684/engine/VOX_LookupString.windows.yaml`
- `bin_artifacts/hl-8684/engine/cszrawsentences.windows.yaml`
- `bin_artifacts/hl-8684/engine/rgpszrawsentence.windows.yaml`
- `bin_artifacts/hl-8684/engine/cszrawsentences.linux.yaml`
- `bin_artifacts/hl-8684/engine/rgpszrawsentence.linux.yaml`
- `bin_artifacts/hl-3248/engine/VOX_LookupString.windows.yaml`
- `bin_artifacts/hl-3248/engine/cszrawsentences.windows.yaml`
- `bin_artifacts/hl-3248/engine/rgpszrawsentence.windows.yaml`
- `bin_artifacts/cof-5936/engine/VOX_LookupString.windows.yaml`
- `bin_artifacts/cof-5936/engine/cszrawsentences.windows.yaml`
- `bin_artifacts/cof-5936/engine/rgpszrawsentence.windows.yaml`
- `bin_artifacts/svencoop-8948/engine/VOX_LoadSound.windows.yaml`
- `bin_artifacts/svencoop-8948/engine/VOX_LoadSound.linux.yaml`
- `bin_artifacts/svencoop-8948/engine/cszrawsentences.linux.yaml`
- `bin_artifacts/svencoop-8948/engine/rgpszrawsentence.linux.yaml`

Reference observations, for orientation only:

| Build | Platform | VOX_LoadSound | Lookup body | SequenceGetSentenceByIndex | cszrawsentences | rgpszrawsentence |
|---|---|---:|---|---:|---:|---:|
| `hl-3248` | Windows | `0x1d9c600` | separate `VOX_LookupString` `0x1d9ce00` | `0x1d94f90` | `0x2489734` | `0x27779e0` |
| `hl-8684` | Windows | `0x1d907f0` | separate `VOX_LookupString` `0x1d90ed0` | `0x1d8a900` | `0x23bb248` | `0x2723400` |
| `hl-8684` | Linux | `0x1ee980` | inlined into `VOX_LoadSound` | `0x1cb790` | `0x83d4e0` | `0x1359ae0` |
| `hl-10210` | Windows | `0x102023a0` | inlined into `VOX_LoadSound` | `0x101fb470` | `0x10530cbc` | `0x111ab160` |
| `hl-10210` | Linux | `0x19d030` | inlined into `VOX_LoadSound` | `0x176cf0` | `0x827800` | `0x13c1940` |
| `cof-5936` | Windows | `0x1dd0077` | separate `VOX_LookupString` `0x1dd0b67` | `0x1dc6987` | `0x2491d60` | `0x2755be0` |
| `svencoop-8948` | Windows | `0x1d99c40` | inlined into `VOX_LoadSound` | `0x1d94930` | `0x8e0a218` | `0x8e08218` |
| `svencoop-8948` | Linux | `0x1b6bf0` | inlined into `VOX_LoadSound` | `0x18ea60` | `0x7992580` | `0x79925a0` |

Windows `hw.dll` from the `hl-3248`…`hl-6153`/`cof-5936` family loads at image base `0x1d00000`; the newer
`hl-10210` `hw.dll` loads at `0x10000000`; every Linux `hw.so` is an ELF with base `0`. Read the base from the
current IDB rather than assuming.

## Semantic model

`VOX_LoadSound(channel_t *pchan, char *pszin)` (`snd_mix.c`) resolves its sentence name through
`VOX_LookupString(pszin, NULL)`. `VOX_LookupString` begins with a `#` test that is the single stable
fingerprint of the whole group:

```c
if (pszin[0] == '#')
{
    indexAsString = pszin + 1;
    sentenceEntry = SequenceGetSentenceByIndex(atoi(indexAsString));   // call 1: atoi, call 2: the sequence lookup
    if (sentenceEntry)
        return sentenceEntry->data;                                    // [entry + 0] is the sentence text
}

for (i = 0; i < cszrawsentences; i++)                                  // the count global
{
    if (!Q_strcasecmp(pszin, rgpszrawsentence[i]))                     // the sentence-pointer array
    {
        if (psentencenum) *psentencenum = i;
        cptr = &rgpszrawsentence[i][Q_strlen(rgpszrawsentence[i]) + 1];
        while (*cptr == ' ' || *cptr == '\t') cptr++;
        return cptr;
    }
}
return NULL;
```

`SequenceGetSentenceByIndex(index)` (`Sequence.c`) walks `g_sentenceGroupList`, a chain of
`sentenceGroupEntry_s`: `groupName` `+0`, `numSentences` `+4`, `firstSentence` `+8`, `nextEntry` `+0xC`; each
`sentenceEntry_s` has `data` `+0`, `nextEntry` `+4`. The `+4`/`+8`/`+0xC` traversal is what distinguishes it
from every other small function reachable from the lookup.

`cszrawsentences` is an `int` count and `rgpszrawsentence` is `char *rgpszrawsentence[1536]`
(`CVOXFILESENTENCEMAX`, `sound.h`). They are written by `VOX_ReadSentenceFile` and read by the lookup loop.

## Robustness principle — follow the inline/de-inline boundary

This is the whole point of the fallback. **The lookup lives in one of two places and they swap between
builds**, so never assume a fixed containing function:

1. Search `VOX_LoadSound` itself for the `pszin[0] == '#'` test → **inlined**: everything below happens inside
   `VOX_LoadSound`.
2. If it is absent there, enumerate `VOX_LoadSound`'s direct callees and search them → **de-inlined**: the
   lookup is a separate helper (conventionally `VOX_LookupString`), and it is what receives `pszin` as its
   first argument. The same `'#'` test, the same `atoi`, the same count/array loop reappear there.
3. Conversely, a build whose reference shows a separate helper may have it inlined back into
   `VOX_LoadSound` — always test case 1 first.

Anchor every target by its semantic fingerprint (the `'#'` test, the `atoi`-then-lookup call pair, the
count/array loop), never by a fixed address or by "it was in function F on the reference build". On Linux,
route every call target through the PLT: an intra-module call may be
`call ._Z26SequenceGetSentenceByIndexj` → `.got.plt` slot → real `.text` function, so a raw `CodeRefsFrom`
walk sees the stub, not the definition.

## Output inventory

Offsets are **reference values — verify against the current binary, do not assume**. Platform gating is
authoritative and comes from the invocation artifact contract:

| # | Output symbol | Kind | Windows | Linux | Writer |
|---|---------------|------|---------|-------|--------|
| 1 | `SequenceGetSentenceByIndex` | func | always | always | `/write-func-as-yaml` |
| 2 | `cszrawsentences` | gv | always | always | `/write-globalvar-as-yaml` |
| 3 | `rgpszrawsentence` | gv | always | always | `/write-globalvar-as-yaml` |
| 4 | `VOX_LookupString` | func | **only where the lookup is a separate callee** | **only where it is a separate callee** | `/write-func-as-yaml` |

`VOX_LookupString` is deliberately **not** an output on builds whose lookup is inlined into `VOX_LoadSound`
(`hl-10210` on both platforms, `svencoop-8948`/`svencoop-10257` on both platforms, and `hl-8684` Linux). On
those builds GCC/MSVC still emits an uncalled external copy of `VOX_LookupString`; it is **not** what
`VOX_LoadSound` calls, so it must **not** be emitted. Emit `VOX_LookupString` only when you have positively
identified it as the function that `VOX_LoadSound` calls for its lookup. If the invocation artifact contract
does not list a `VOX_LookupString` output for the current platform, skip it entirely.

## Step 0. Skip targets already produced

For each output above, select its exact path from the invocation artifact contract. If it already exists and
parses to a non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it. Never derive the
YAML path from the binary:

```
mcp__ida-pro-mcp__py_eval code="import os; p=os.path.abspath(r'<EXACT_OUTPUT_ARTIFACT_PATH_FROM_INVOCATION_CONTRACT>'); print({'path': p, 'exists': os.path.isfile(p)})"
```

## Step 1. Load the owner and decompile it

**ALWAYS** use SKILL `/get-func-from-yaml` with `func_name=VOX_LoadSound` against the exact input path in the
invocation artifact contract (`VOX_LoadSound.<platform>.yaml`, a configured prerequisite). If it is missing,
invalid, or does not resolve to a real function start in the current IDB, stop and report the missing
prerequisite; do not substitute a reference-build address.

```
mcp__ida-pro-mcp__decompile addr="<VOX_LoadSound.func_va>"
```

Keep the list of direct callees — that is the de-inline search space for Step 2.

## Step 2. Establish the lookup body

Find the `pszin[0] == '#'` test: a byte compare of the sentence-name pointer's first byte against `0x23`,
either directly (`cmp byte ptr [reg], 23h`) or through a widened register
(`movsx/movzx reg, byte ptr [..]` then `cmp reg, 23h`). The self-contained identity check is that the compared
byte comes from the same pointer that `VOX_LoadSound` received as its second argument (`pszin`).

- Found inside `VOX_LoadSound` → **inlined**; the lookup body is `VOX_LoadSound` itself.
- Not present → enumerate `VOX_LoadSound`'s direct callees, decompile the small ones, and search for the test.
  The lookup helper takes `pszin` as its first argument, so the same `'#'` test on `arg1` reappears. Bound this
  at one or two levels and do not revisit functions.
- If more than one candidate shows the test, keep the one that also satisfies Steps 3 and 4 (the `atoi`-then-
  lookup call pair and the count/array loop); that conjunction is what makes it unique.

Record which case you are in: it determines whether `VOX_LookupString` is an output.

## Step 3. SequenceGetSentenceByIndex

On the taken (equal) side of the `'#'` test, find the **second** direct call on that straight-line path: the
first is `atoi`/`strtol` on `pszin + 1`, the second is the sentence lookup. Resolve PLT stubs before accepting
a target.

Verify the candidate is `SequenceGetSentenceByIndex` by its traversal, not by its name: it loops over a linked
list of sentence groups accumulating a per-group count and then walks that group's sentence list. In the
disassembly this appears as `+4` (count), `+8` (first sentence) and `+0xC` (next group) field accesses on the
group pointer. Reject a candidate that lacks this traversal — a bare `atoi` wrapper or an unrelated small
helper can sit at the same position.

## Step 4. cszrawsentences and rgpszrawsentence

On the not-equal side of the `'#'` test, follow the straight-line path:

1. The first global read is `cszrawsentences` — a scalar `int` count compared against a loop index.
   Reject a candidate that is indexed (`[reg*4]`) or is not a 4-byte scalar.
2. The loop that re-reads that count is the sentence loop. Collect every global the loop touches *plus* the
   block that enters it — an optimised build may take the array's address once before the loop
   (`mov edi, offset rgpszrawsentence`) and advance the pointer inside it, so the array may never appear in the
   loop body itself. In that form the loop indexes a walking pointer instead of the array symbol.
3. Exactly one other global must remain: `rgpszrawsentence`. Confirm it is an array of sentence pointers by an
   element access scaled by 4 (`[reg*4]` relative to the array) somewhere in the lookup body.
4. Cross-check both addresses against the reference values above and, on builds that kept `.symtab`
   (`hl-8684`, `hl-10210`, `svencoop-8948` Linux), against `nm bin/<tag>/engine/hw.so`. Symbol names are
   corroboration only — never the lookup strategy.

An independent confirmation of the pair is `VOX_ReadSentenceFile` (its own literal
`VOX_ReadSentenceFile: Couldn't load %s\n`): it *writes* both globals. If the two Step-4 candidates do not
appear in that function, re-examine them.

## Step 5. VOX_LookupString (only where it applies)

- **De-inlined** (Step 2 case 2): the lookup helper you already identified is `VOX_LookupString`. Confirm it is
  the function `VOX_LoadSound` calls, and that it is the caller of the Step-3 `SequenceGetSentenceByIndex`.
- **Inlined** (Step 2 case 1): if — and only if — the invocation artifact contract lists a
  `VOX_LookupString` output, and the build nevertheless has a separate function that also passes the Step-2/3/4
  tests, that function is the de-inlined `VOX_LookupString`. Otherwise **do not emit it**: an uncalled
  external copy exists on these builds but is not the lookup `VOX_LoadSound` uses, and emitting it would be
  wrong.

## Signatures and YAML output

Functions (`SequenceGetSentenceByIndex`, `VOX_LookupString`): generate the signature with
`/generate-signature-for-function` and persist with `/write-func-as-yaml` (`func_name`, `func_va`, `func_rva`,
`func_size`, `func_sig`).

Globals (`cszrawsentences`, `rgpszrawsentence`): these artifacts anchor to the **owning function's** signature
rather than starting at the referencing instruction. Generate the anchoring function's signature with
`/generate-signature-for-function` against the lookup body (the inlined `VOX_LoadSound`, or the separate
`VOX_LookupString`), then persist with `/write-globalvar-as-yaml` using `gv_name`, `gv_va`, `gv_rva`, and:

- `gv_sig` — the anchoring function's `func_sig`,
- `gv_sig_va` — the anchoring function's `func_va`,
- `gv_inst_offset` — the offset of the chosen referencing instruction **within that function**,
- `gv_inst_length` — the length of that instruction,
- `gv_inst_disp` — the byte offset of the 4-byte absolute-address displacement inside that instruction.

Choose the instruction that embeds the address most directly (the count compare or the array element load).
On a PIC Linux build the displacement is `gv - GOT`; record `gv_pic_addend` as the existing Linux
`rgpszrawsentence` artifacts do, and verify `gv_va - dword_at(disp)` is one identical GOT base across the
function's references.

At runtime on x86-32 the global address is the little-endian dword at
`matched_instruction + gv_inst_offset + gv_inst_disp`. Never apply an x86-64 RIP-relative formula. Every
address/length/offset/displacement field must be a quoted lowercase hexadecimal scalar.

The YAML payload may contain only the category identity (`func_name` / `gv_name`) and that category's data
fields — never generic `name`, `type`, or `kind`.

## Failure handling

- `VOX_LoadSound` artifact missing, invalid, or not a function start → stop and report; do not use a reference
  address.
- No `'#'` test found in `VOX_LoadSound` or any of its callees → stop and report the callees inspected.
- The equal branch has no two-call pattern, or the second call does not pass the group-traversal check → stop
  and report the call sites and the candidate's disassembly.
- The count/array pair cannot be separated uniquely → report the candidates with their references instead of
  guessing.
- Never emit `VOX_LookupString` on a build where the lookup is inlined, and never emit a symbol the invocation
  artifact contract does not list for the current platform.

## Output YAML filenames

Written only to the invocation contract's exact artifact paths, one per symbol:
`SequenceGetSentenceByIndex.<platform>.yaml`, `cszrawsentences.<platform>.yaml`,
`rgpszrawsentence.<platform>.yaml`, and `VOX_LookupString.<platform>.yaml` where applicable.
