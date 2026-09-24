---
title: VOX sentence-lookup chain locator (#235)
type: note
permalink: goldsrc-vibesignatures/locators/vox-sentence-lookup-chain-locator-235
tags:
- locator
- engine
- sound
- vox
- issue-235
---

# VOX sentence-lookup chain (#235)

## Trigger signal

A finder needs `VOX_LoadSound`, `VOX_LookupString`, `SequenceGetSentenceByIndex`, `cszrawsentences`, or
`rgpszrawsentence` in `hw.dll`/`hw.so`.

## Constraint and cause

`VOX_LoadSound` owns the exact literal `"VOX_LoadSound: no sentence named %s\n"` (`snd_mix.c`), which anchors
it directly. Everything else hangs off the `pszin[0] == '#'` test at the head of `VOX_LookupString`
(`snd_mix.c:2697`), the single stable fingerprint of the group.

**The lookup moves across the inline/de-inline boundary between builds.** Old MSVC builds keep
`VOX_LookupString` as a separate callee that owns the only `'#'` compare; newer MSVC and every GCC build inline
it into `VOX_LoadSound`, which then owns the compare itself. GCC additionally emits an *uncalled* external copy
of `VOX_LookupString` on the inlined Linux builds — it is not what `VOX_LoadSound` calls, so emitting it would
be wrong. Detect the mode structurally: one `'#'` compare in `VOX_LoadSound` with no such callee means
inlined; no compare in `VOX_LoadSound` with exactly one such callee means standalone.

The issue's suggested anchors for the two globals (`COM_ExplainDisconnection` /
`COM_ExtendedExplainDisconnection`) were copy-paste from #234 and are unrelated to the sentence tables.

## Correct locator

1. Anchor `VOX_LoadSound` by `FULLMATCH:VOX_LoadSound: no sentence named %s\n`; the literal occurs once and all
   its references belong to that function.
2. Resolve the lookup body from the `'#'` compare, accepting both `cmp byte ptr [reg], 23h` and the CoF form
   `movsx reg, byte ptr [..]` + `cmp reg, 23h`.
3. On the straight-line equal branch there are exactly two calls: `atoi`/`strtol`, then the sequence lookup.
   Take the second, resolving ELF PLT stubs (Sven 8948 Linux routes through
   `._Z26SequenceGetSentenceByIndexj` → `.got.plt`). Verify it by the `sentenceGroupEntry_s` traversal
   `numSentences +4`, `firstSentence +8`, `nextEntry +0xC` — not by name.
4. On the not-equal branch the first global read is `cszrawsentences` (scalar `int`); the one loop re-reading it
   touches exactly one other global, `rgpszrawsentence`, which must also see a `[reg*4]` element access. **Include
   the loop's entry blocks in the scan region**: hl-4554 takes the array's address once before the loop
   (`mov edi, offset rgpszrawsentence`) and advances the pointer inside, so the array never appears in the loop
   body. Cross-check the pair against `VOX_ReadSentenceFile` (own literal), which writes both.
5. Emit the globals anchored to the lookup body's signature plus `gv_inst_offset` / `gv_inst_length` /
   `gv_inst_disp`; the shared PIC/GOTOFF decoder covers the Linux families.

## Verification

All 15 configured engine binary/platform pairs resolve. `hl-8684`, `hl-10210`, and `svencoop-8948` Linux keep
`.symtab`, and `nm` matches every emitted address exactly (12/12). 68 emitted artifacts and 60 signatures were
re-checked against the binaries: every signature resolves uniquely and every gv carrier decodes to its
recorded address. `hl-10210` `hw.dll` uses image base `0x10000000` while the `hl-3248`…`hl-6153`/`cof-5936`
family uses `0x1d00000`; Linux ELF base is 0.

`VOX_LookupString` is emitted only for the eight standalone Windows builds (`hl-3248`…`hl-6153`, `cof-5936`,
`hl-8684`). It is absent on `hl-10210`, `svencoop-8948`, `svencoop-10257` (both platforms — inlined, no callee)
and on every Linux build. On those Linux builds the uncalled external copy exists but must not be emitted.

## Scope

Engine module across `hl-3248`..`hl-10210`, `svencoop-8948`/`10257`, and `cof-5936` as configured.
Client-only cstrike/czero/czeror configs have no engine module. `.claude/skills/find-VOX_LoadSound-sentence-symbols/`
carries the Agent fallback, which was validated end-to-end with `-skip_pp` on `hl-10210` Windows and Linux
(the inlined case on both platforms).
