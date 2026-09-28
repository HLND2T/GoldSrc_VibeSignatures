---
title: Client registration discovery must scan raw bytes, not IDA's string list
type: note
permalink: goldsrc-vibesignatures/lessons/client-registration-discovery-must-scan-raw-bytes-not-idas-string-list
tags:
- lesson
- preprocessor
- registration
- elf
- ida
- czeror
---


# Client registration discovery must scan raw bytes, not IDA's string list

## Trigger

`_client_registration_common.REGISTRATION_QUERY` returned **zero** callbacks for a label whose literal
was demonstrably present in the bound IDB. Worked example: `find-client-ScoreInfo-handler` on
`czeror-8684 client.so` reported `{'error': 'ScoreInfo callback is not unique', 'callbacks': []}`,
while the same finder resolved `czeror-10210 client.so` normally.

## Root cause / constraints

1. The query built its candidate address set from `idautils.Strings()`:
   `{s.ea + len(str(s)) - len(label) for s in Strings() if str(s).endswith(label)}`.
   **IDA's string list can omit a fully analyzed `.rodata` region in a warmed database.** In
   `czeror-8684 client.so` the list held 6775 entries spanning `0x1eccd`–`0x1ab9c1`, but nothing in
   `.rodata` around `0x19831e` — so the set came back empty and no data xref was ever followed.
2. The literal itself was healthy: `get_bytes(0x19831e, 10) == b"ScoreInfo\0"` and `get_qword` decoded
   `53 63 6F 72 65 49 6E 66 6F`. IDA just had not surfaced it as a string item.
3. The same binary layout was fine on `czeror-10210`, so this is a per-database string-list gap, not a
   property of the build.

## Correct approach

Discover the label by scanning raw bytes of non-executable segments for `label + b"\0"`, then keep the
existing data-xref → flow-chart walk unchanged:

```python
needle = label.encode("ascii") + b"\0"
strings = set()
for seg_ea in idautils.Segments():
    segment = ida_segment.getseg(seg_ea)
    if segment.perm & ida_segment.SEGPERM_EXEC: continue
    base = int(segment.start_ea)
    data = ida_bytes.get_bytes(base, int(segment.end_ea) - base) or b""
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0: break
        strings.add(base + index)
        start = index + 1
```

This keeps the documented GCC pooling behaviour (`"centerview"` inside `"force_centerview"` is still
found, because the suffix match ends at the string's NUL) and is strictly broader than the old set.

## Verification

- `czeror-8684 client.so`: raw scan yields `{0x19831e}` and resolves callback `0xfa710`; the string-list
  path yields `set()` and `[]`.
- Regression: `find-V_StartPitchDrift` (the only other consumer) reproduced all four
  `V_StartPitchDrift.{windows,linux}.yaml` artifacts byte-identically on `svencoop-8948` and
  `svencoop-10257`.
- Regression: `find-client-ScoreInfo-handler` reproduced all ten
  `ClientScoreInfoHandler.windows.yaml` artifacts byte-identically across `cstrike-3248/3647/4554/6153/8684/10210`,
  `czero-8684/10210`, `czeror-8684/10210`.

## Scope

`ida_preprocessor_scripts/_client_registration_common.py` (`REGISTRATION_QUERY`), and therefore every
registration-based finder. Re-check any finder that consumes `registered_callbacks` when the IDB
string list is trusted elsewhere.
