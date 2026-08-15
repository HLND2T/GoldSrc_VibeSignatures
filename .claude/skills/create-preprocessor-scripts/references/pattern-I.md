# Pattern I — compatibility entry

Pattern I is not implemented as a separate bespoke thunk walker in GoldSrc_VibeSignatures.

Use [Pattern L](pattern-L.md) for every interface-vfunc thunk previously classified as Pattern I.
The shared helper scans all indirect `call`/`jmp dword ptr [reg+disp]` operands, deduplicates slots,
uses 4-byte alignment/index arithmetic, and requires exactly one result.

Do not copy the CS2 Pattern I implementation: it took the first `jmp`, used 8-byte slots, and
could silently accept ambiguity. If a custom operand filter is genuinely required, extend Pattern L's
shared helper and tests rather than creating a per-finder walker.
