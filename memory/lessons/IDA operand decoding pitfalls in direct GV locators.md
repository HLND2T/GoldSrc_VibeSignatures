---
title: IDA operand decoding pitfalls in direct GV locators
type: note
permalink: goldsrc-vibesignatures/lessons/ida-operand-decoding-pitfalls-in-direct-gv-locators
tags:
- lesson
- preprocessor
- gv
- ida
- operand-decoding
---

# IDA operand decoding pitfalls in direct GV locators

## Trigger

Writing direct global-variable locators (`preprocess_currenttexture`, the `envmap`
probe, the `detTexSupported` scan) produced a sequence of false negatives and one
false positive that all looked like wrong anchors rather than decoding bugs:

- `currenttexture` reported "candidate missing" on svencoop Linux although GL_Bind
  clearly stores it.
- `envmap` reported no candidates at all in `R_DrawViewModel`.
- `detTexSupported`'s first-read rule picked `___security_cookie` on hl-10210
  Windows and picked the neighbouring `g_detTexLoaded` byte before that.

## Root cause

1. **IDA leaves a stale `op.reg` on `o_mem` operands.** `cmp dword_10322B6C, eax`
   decodes with `op0.type == o_mem` and `op0.reg == ebp` (leftover, not a base).
   Any `reg_name(op0) in ('esp','ebp')` guard applied to an absolute operand
   therefore rejected it. Only read `op.reg` for `o_displ`/`o_phrase`.
2. **A register-only memory operand is `o_phrase` (3), not `o_displ` (4).**
   `mov [edx], eax` and `lea edx, [ebx]` decode as `o_phrase`; a "is this a store"
   test limited to `o_mem`/`o_displ` silently drops them. `disp32_offset` already
   accepted `o_phrase`, so the inconsistency was easy to miss.
3. **`ida_segment.SEGPERM_EXEC` is 1**, not 4. `is_writable_data` helpers that use
   `getattr(ida_segment, 'SEGPERM_EXEC', 4)` are wrong whenever the attribute is
   absent, because they then also exclude every readable+writable `.data`
   (`perm == 0x6`). `SEGPERM_WRITE == 2`, `SEGPERM_READ == 4`.
4. **`py_eval` runs with separate globals/locals dicts.** A module-level generator
   expression or lambda cannot see module-level names assigned in the same block
   (`NameError: name 'read' is not defined`), even though plain statements can. The
   repository idiom is `globals().update(locals())` before the failing expression,
   or a plain `for` loop plus `list.sort()`.
5. A byte-sized discriminator is required when scanning for a `bool` global:
   `mov al, byte_X` / `cmp byte_X, 0` are byte operands (`op.dtype == dt_byte`),
   while the 4-byte `mov eax, ___security_cookie` prologue load is `dt_dword`.
   Filtering on operand size is what separates them.
6. **`CF_CHG1` is `0x80`, not `0x10`.** The `CF_USE5`/`CF_USE6` extension shifted the
   operand-change bits, so a hardcoded `insn.get_canon_feature() & 0x10` silently
   matches `CF_USE4` and reports *reads* as writes. `#245`'s shader-chain walk hit
   this twice: `member_writes` returned an empty list for a body that clearly stores
   two members, and the register-definition scan stopped at `push esi` (which is not
   a write to `esi`). Same failure mode as pitfall 2 — a plausible-looking rule that
   quietly discards every real candidate. Read the bit through the SDK
   (`getattr(ida_idp, 'CF_CHG%d' % (i + 1))`), never as a literal.

## Correct approach

- Resolve an operand's base register only for `o_displ`/`o_phrase`; treat `o_mem`
  as absolute and never consult `op.reg` on it.
- When classifying a destination as memory, accept `o_mem`, `o_displ` and
  `o_phrase`; exclude stack frames by rejecting a *tracked base* of `esp`/`ebp`,
  not by rejecting the operand type.
- Track address-bearing registers only from real address loads: `lea reg, [abs]`
  and the PIC form `mov reg, [.got/.got.plt slot]` (whose pointee is the data
  object). Do **not** track a plain `mov reg, [abs]` value load as a base.
- Use `int(getattr(ida_segment, 'SEGPERM_EXEC', 1))` with the correct default.
- Ask whether an instruction *changes* an operand with
  `insn.get_canon_feature() & getattr(ida_idp, 'CF_CHG%d' % (index + 1))`; a
  register written by `push reg` is unchanged, and only a written register
  counts as a definition when walking backwards for the value of an operand.
- Prefer plain loops over genexpr/lambda in `py_eval` payloads, or re-run
  `globals().update(locals())` after the last assignment the expression needs.

## Verification

Each fix was checked against the real IDBs before the finders were written: the
prototype locators reproduced the manually-read global addresses on all 15
Windows/Linux engine binaries, and the shipped finders then reproduced them through
`ida_analyze_bin.py`. The `detTexSupported` case is the sharpest check — the
byte-size filter is the difference between `___security_cookie` (4-byte),
`g_detTexLoaded` (adjacent 1-byte) and `detTexSupported` itself.

## Scope

Any IDAPython locator that inspects x86 operands (direct GV, patch, struct-offset
patterns) on PE32/ELF32, and any `py_eval` payload that defines module-level
helpers. The decoding rules are IDA-wide, not GoldSrc-specific.
