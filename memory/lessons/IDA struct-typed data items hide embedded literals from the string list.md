---
title: IDA struct-typed data items hide embedded literals from the string list
type: note
permalink: goldsrc-vibesignatures/lessons/ida-struct-typed-data-items-hide-embedded-literals-from-the-string-list
tags:
- lesson
- ida
- strings
- xref
- elf
---

# IDA struct-typed data items hide embedded literals from the string list

## Trigger

A shared `xref_strings` / `FULLMATCH:` finder fails closed with zero owning functions for a literal
whose bytes are demonstrably present and code-referenced. Worked example: #291
`ProfileSelectionBackground` in `hl-8684 gameui.so`. `MapSelectionBackground` and `PoolBackground`
resolve normally in the same database, and all three resolve in `hl-10210 gameui.so`.

## Root cause / constraints

1. The binary carries DWARF, and IDA typed the whole `.rodata` object around the literal as one data
   item: `0x167919`, size `0x4b4`, `type = const CCareerProfileData`, name `save`. The literal is the
   `tutorData` member, so IDA renders its reference as
   `mov eax, (offset save.tutorData+56h)`, and `get_item_head(0x167a23) == 0x167919`.
2. Because the string starts inside a larger defined item, IDA never creates a string item for it.
   Rebuilding the C-string index (`Strings.setup(strtypes=[STRTYPE_C], minlen=4)`) does not help: the
   literal stays absent, so the string-list candidate set is empty and no data xref is ever followed.
3. The bytes are healthy (`get_bytes(0x167a23, 28) == b"ProfileSelectionBackground\0"`), and the literal
   is not a suffix of a longer literal (preceding byte is NUL).

## Correct approach

Discover the literal by scanning raw bytes of non-executable segments for `literal + b"\0"` and
following `XrefsTo(addr)` from each hit, then keep the normal owner-uniqueness requirement. This is
already the repository pattern in `find-client-vgui-worldmap.py` (`exact_code_ref`) and
`find-QueryBox_ctor.py`; prefer it whenever the anchor literal might sit inside a compiler- or
DWARF-merged data item, and do not rely on IDA's string item for the anchor.

Do not "fix" this by re-defining the item or undefining the struct in the IDB: finders must work on the
restored databases the analyzer ships, and the raw-byte scan is strictly broader and unaffected.

## Verification

- `hl-8684 gameui.so`: raw scan yields one code reference `0xbf864` inside `CCareerProfileFrame::C1/C2`
  (`0xbf790`), which the vtable-store and caller checks confirm; the string-list path yields `set()`.
  `hl-10210 gameui.so` and every Windows `GameUI.dll` yield the same owner through both paths.
- Regression: the string-based `find-GameUI-dialog-constructors` targets (`ConsoleSubmit`,
  `CSBotConfig`, `#GameUI_Keyboard`) are untouched by this change.

## Scope

Any finder that anchors on a literal, especially ELF databases with DWARF (`gameui.so`, `client.so`) or
GCC-pooled literals. Not a property of the binary build itself.
