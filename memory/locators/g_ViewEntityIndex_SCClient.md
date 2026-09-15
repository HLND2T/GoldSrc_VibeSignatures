---
title: g_ViewEntityIndex_SCClient locator
type: note
permalink: goldsrc-vibesignatures/locators/g-viewentityindex-scclient
tags:
  - locator
  - client
  - gv
---

# g_ViewEntityIndex_SCClient

## Symbol

- **Name**: `g_ViewEntityIndex_SCClient`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-GameStudioRenderer_StudioDrawPlayer-globals.py`

## Availability

- Declared in 1 config: svencoop-10257 only.
- Platforms: Windows + Linux (svencoop-10257 is one of the configs whose client module ships
  both `client.dll` and `client.so`).
- SvEngine-only symbol (Sven has no counterpart in CS/CZ/CZDS/HL/CoF client modules).

## Predecessors

- `GameStudioRenderer_StudioDrawPlayer.<platform>.yaml` (Sven's client-built wrapper), consumed
  via `expected_input` and declared as the **required** dependency of the LLM spec.

## How it is located

1. The producer calls `preprocess_common_skill` with
   `gv_names = ["g_ViewEntityIndex_SCClient"]`, `llm_decompile_specs` pointing at the Sven
   reference, and `old_yaml_map=None`.
2. With no old artifact the `preprocess_gv_sig_via_mcp` fast path yields nothing, so discovery
   always runs through the LLM spec: prompt `prompt/call_llm_decompile.md`, reference
   `references/svencoop-10257/client/GameStudioRenderer_StudioDrawPlayer.<platform>.yaml`,
   `expected_result_sections = ["found_gv"]`.
3. The annotated reference carries the access in both forms — Windows disassembly
   `cmp eax, g_ViewEntityIndex_SCClient` with the matching pseudocode
   (`result != g_ViewEntityIndex_SCClient`), and SvEngine Linux PIC
   `lea esi, (g_ViewEntityIndex_SCClient - 61E000h)[ebx]` with `if ( v23->index == g_ViewEntityIndex_SCClient )`.
   The global is the saved view-entity index used to suppress drawing of the local player.
4. The emitted artifact contains `gv_name`, `gv_va`/`gv_rva`, `gv_sig` (the owning function's
   prologue signature), `gv_sig_va`, `gv_inst_offset`/`gv_inst_length`/`gv_inst_disp`,
   `gv_sig_allow_across_function_boundary: true`, plus the resolution metadata returned by
   `gv_resolution_fields_via_mcp` (including `gv_pic_addend` on SvEngine Linux).
5. Recorded evidence for the current svencoop-10257 binaries: Windows `gv_va = 0x106458c0`
   (RVA `0x6458c0`) anchored at instruction offset `0xc6`, `gv_inst_disp = 0x2`; Linux
   `gv_va = 0xaa3b8c` with `gv_pic_addend = 0x61e000` and `gv_inst_disp = 0x2`.

## Pitfalls

- **SvEngine Linux is PIC.** The access is a two-hop `lea reg, (X - 61E000h)[ebx]`: the embedded
  dword is not the absolute address. `gv_pic_addend` must be preserved and applied as
  `uint32(embedded + addend)` before adding the module base; recomputing the address from the raw
  displacement alone resolves to the wrong VA.
- Sven-only scope: `g_ViewEntityIndex_SCClient`, `allow_cheats` and
  `g_bRenderingPortals_SCClient` are Sven-only. Do not look for this global in the
  CS/CZ/CZDS/HL/CoF clients.
- The literal `0x61E000` in the reference is evidence for one binary, never a selector; the
  addend is re-derived per binary.
- `GameStudioRenderer_StudioDrawPlayer` can be short and split (GCC `.part.N`), hence the
  always-emitted `gv_sig_allow_across_function_boundary: true` on the owning-function signature.
