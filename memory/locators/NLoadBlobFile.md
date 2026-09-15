---
title: NLoadBlobFile locator
type: note
permalink: goldsrc-vibesignatures/locators/nloadblobfile
tags:
  - locator
  - engine
  - func
---

# NLoadBlobFile

## Symbol

- **Name**: `NLoadBlobFile`
- **Category**: `func`
- **Module**: engine (`hw.dll`)
- **Producer**: `ida_preprocessor_scripts/find-NLoadBlobFile.py` (thin wrapper over
  `preprocess_common_skill`)

## Availability

- Declared in the same 9 configs as `NLoadBlob`: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: **Windows-only** (`platform: windows` on the finder, `platform: windows` on the
  symbol in every config).
- Inlined / absent: same native-unsupported set as `NLoadBlob` — no Linux `hw.so` and no
  svencoop-10257 artifact. `NLoadBlobFile` is the *caller-visible* blob entry used by
  `ClientDLL_Init` (`NLoadBlobFile(g_szfullClientName, &g_blobfootprintClient, &cl_funcs, 1)`),
  so it is the blob symbol MetaHook consumers actually see on the secure-client path.

## Predecessors

- `NLoadBlob.{platform}.yaml` (produced by `find-NLoadBlob`, consumed via `expected_input`).

## How it is located

1. `FUNC_XREFS` declares three sources handled by `preprocess_common_skill`:
   - `xref_funcs: ["NLoadBlob"]` — resolved to a `func_va` through the predecessor artifact's
     dependency address, then expanded to the functions that reference it (`_functions_referencing`).
     This is the canonical example of the `xref_funcs` reuse pattern: an existing artifact is used
     as a symbolic dependency instead of re-discovering the anchor.
   - `xref_signatures: ["6A 02 6A 00"]`.
   - `exclude_signatures: ["04 00 21 43"]`.
2. Positive sets are intersected in collection order (signatures first, then `xref_funcs`
   callers), so the survivor set is: functions whose body contains `6A 02 6A 00` **and** that call
   `NLoadBlob`.
3. `exclude_signatures` are turned into match addresses and then into their containing function
   starts, which are subtracted from the candidate set — the `04 00 21 43` pattern identifies a
   sibling that must not be mistaken for the target.
4. Exactly one function must remain. Emits `func_name` / `func_va` / `func_rva` / `func_size` /
   `func_sig` (no across-boundary fallback variant in the desired-fields list).

## Pitfalls

- The result depends on the `NLoadBlob` artifact being present and correct. If the predecessor
  YAML is missing, `_dependency_address` fails and the finder returns False before touching the
  IDB — it does not fall back to a signature-only scan.
- `exclude_signatures` excludes a *function*, not an instruction: any function containing
  `04 00 21 43` is dropped wholesale. A future build where the target itself contains that byte
  pattern would produce no artifact rather than a wrong one.
- `6A 02 6A 00` (push 2; push 0) is a call-argument shape, not a function identity; it is only
  usable because it is intersected with the `NLoadBlob` caller set.
- Windows-only gating and the blob decrypt rule are identical to `NLoadBlob`: analysis runs on
  `hw.decrypt.dll` for hl-3248/hl-3266/hl-3329/hl-3647 while the config says `hw.dll`, and IDA may
  display the function as `sub_XXXXXXXX`. Never conclude absence from a scan of the encrypted blob.
- Blob TODO naming: consumers should request `NLoadBlob` (this symbol), not
  `NLoadBlobFile`/`LoadBlobFile`, and Sven must not require either.
