---
title: FreeBlob locator
type: note
permalink: goldsrc-vibesignatures/locators/freeblob
tags:
  - locator
  - engine
  - func
---

# FreeBlob

## Symbol

- **Name**: `FreeBlob`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-FreeBlob.py` (Windows/Linux where Shutdown is
  inlined) and `ida_preprocessor_scripts/find-FreeBlob-legacy.py` (standalone
  `ClientDLL_Shutdown` builds). Both are thin wrappers over `preprocess_common_skill` with an
  `LLM_DECOMPILE` spec.

## Availability

- Declared in 9 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684.
- Platforms:
  - `find-FreeBlob` — hl-10210 **both** platforms (no `platform:` gate in that config);
    hl-8684 **Linux only**.
  - `find-FreeBlob-legacy` — `platform: windows` on every declaring config.
- Inlined / absent: `FreeBlob` itself is never inlined, but its *call site* moves. HL25 inlines
  `ClientDLL_Shutdown` into `ClientDLL_Init`, so `find-FreeBlob` reads the call out of
  `ClientDLL_Init`; older GoldSrc and hl-8684 Windows keep a standalone `ClientDLL_Shutdown` and
  use `find-FreeBlob-legacy`. **svencoop-10257 has no `FreeBlob` at all** — it declares no
  `FreeBlob` symbol and registers neither finder (Sven has no blob load/unload fork); `native_unsupported`,
  not an analysis gap. Linux `NLoadBlob` is likewise unsupported, but Linux `FreeBlob` exists on
  hl-10210/hl-8684.

## Predecessors

- `find-FreeBlob`: `ClientDLL_Init.{platform}.yaml` (`dependency_policy: required`).
- `find-FreeBlob-legacy`: `ClientDLL_Shutdown.{platform}.yaml` (`dependency_policy: required`).

## How it is located

Both variants use the `LLM_DECOMPILE` chain with `expected_result_sections: ["found_call"]`:

1. The predecessor YAML supplies an annotated disassembly/pseudocode reference:
   - `find-FreeBlob`: `references/{gamever}/engine/ClientDLL_Init.{platform}.yaml` — the
     reference is resolved **per game version**, which matters because hl-8684 Linux has a
     different predecessor body (`0xb2d`, `LoadInsecureClient` inlined) and must not fall back to
     the hl-10210 reference.
   - `find-FreeBlob-legacy`: the fixed reference
     `references/hl-6153/engine/ClientDLL_Shutdown.{platform}.yaml` (public leak comments the
     call out; the hl-6153 body keeps it).
2. The LLM returns a `found_call` entry naming the instruction inside the predecessor that calls
   `FreeBlob`; `_llm_entry_instruction_is_valid` re-inspects that instruction and requires exactly
   one distinct code target.
3. The resolved target is inspected with `_inspect_function_via_mcp`. `FreeBlob` wrappers are
   tiny (Windows `0x11` bytes: `push ebp; mov ebp,esp; mov eax,[ebp+8]; mov ecx,[eax]; push ecx;
   call [import]; pop ebp; retn`; Linux `0x19` bytes), so when the plain signature is not unique
   the finder retries with `allow_across_function_boundary=True` and records the flag on the YAML.
4. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`
   (+ `func_sig_allow_across_function_boundary: true` when used).

## Pitfalls

- The tiny-wrapper body is the reason `find-FreeBlob-legacy` ships the across-boundary
  desired-fields variant; a plain 5-instruction signature is not unique.
- `find-FreeBlob` must not be pointed at a global reference. hl-8684 Linux resolves to its own
  `references/hl-8684/engine/ClientDLL_Init.linux.yaml`; using the hl-10210 file gives the wrong
  call site.
- Public source/binary mismatch: the public tree comments out `FreeBlob(&g_blobfootprintClient)`
  on the shutdown path, but these binaries keep the secure-client branch (`cls_fSecureClient`
  guarded). The reference YAMLs record this explicitly; do not "correct" the artifact to match the
  leak.
- The consumer's blob TODO is `NLoadBlob`, not `NLoadBlobFile`/`LoadBlobFile`, and Sven Co-op must
  not require `NLoadBlob`/`FreeBlob`. Absence in svencoop-10257 is native, not a catalog failure.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may name neighbours `sub_XXXXXXXX`. Match by artifact `func_va`.
