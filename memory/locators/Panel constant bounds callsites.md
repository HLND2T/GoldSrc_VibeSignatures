---
title: Panel constant bounds callsites
type: note
permalink: goldsrc-vibesignatures/locators/panel-constant-bounds-callsites
---

# Panel constant bounds callsites

## Overview

`find-vgui2_Panel-bounds-callsites` emits GameUI direct CALL patch artifacts for `vgui2::Panel::SetBounds(int,int,int,int)`. It extends the current-method identity discovery from [[Panel constant size callsites]]. SetSizeable and receiver-pair matching are explicitly outside this task.

## Responsibilities

- `Const`: all four explicit arguments are direct constants, including coordinates and zero. Retained on HL25 as well as old HL, CoF and Sven.
- `ScaledConst`: each nonzero coordinate and both dimensions are unmodified returns of the verified current `GetProportionalScaledValue(constant)` on the final Panel receiver. Literal zero is additionally allowed for x/y. Mixed units, modified returns, unknown/ambiguous receivers and variable arguments are excluded.
- Emit actual direct CALL addresses, with unique signatures, `patch_sig_disp=0`, and no replacement bytes. Numbering is per binary and per mode, not a cross-version business identity.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-vgui2_Panel-bounds-callsites.py`: GameUI producer entry point.
- `_panel_bounds_callsites_common.py`: current input validation, exact mode counts, unique signature validation and patch writing.
- `_panel_bounds_collect.py`: current SetPos/SetBounds discovery, caller enumeration and anomalous stack cleanup handling.
- `_panel_bounds_identity.py`: four-argument provenance, exact forwarding semantics, constructor-vptr and CFG predicates.
- `_panel_size_collect.py`: shared `IDENTIFY` prefix; the existing size collector's parsed AST is unchanged by this extraction.
- `tests/test_panel_bounds_identity.py`: both ABIs, direct/inlined forwarding, zero-coordinate scaling, wrong receivers, mixed/variable inputs, side effects, CFG bypass, constructor proof, cleanup correction/quarantine, output count and signature gates.

## Architecture

1. Consume the current module-local `vgui2_Panel_Init` artifact and recover Panel/GetVPanel/IPanel identities through the existing Frame minimum-size evidence.
2. Recover SetPos from Panel::Init's first two arguments and SetSize from its third/fourth arguments. Resolve their standalone wrappers by current forwarding behavior.
3. Search callers of those wrappers and the current IPanel accessor for SetBounds. Require exactly SetPos(this,arg1,arg2), then SetSize(this,arg3,arg4); accept direct wrappers or equivalent inlined interface dispatches. Reject additional operations, object/global stores and paths bypassing either setter. Windows also verifies four-argument callee cleanup.
4. Enumerate direct calls including ELF PLT paths. Track stack/register provenance and classify the complete four-argument tuple, preserving distinct entry-register identities.
5. Validate exact declared mode counts before generating signatures, validate every signature before writing any YAML. Existing per-file patch writer semantics are retained; the set is not a filesystem-wide transaction.

## Dependencies

- [[idalib-mcp]] strict restored/no-save owned lifecycles.
- Existing x86 symbolic flow, RTTI discovery, ELF call resolution and shared callsite signature generation.
- Source reference: `D:/HLND2T_official/vgui2/controls/Panel.cpp`, SetBounds forwards SetPos then SetSize. Current instructions remain authoritative for inlining and ABI behavior.

## Notes

### Anomalous inferred stack cleanup

Trigger: HL25 Windows PanelListPanel constructor showed `(0,0,20,2)` in symbolic flow at `0x10087247`, although raw instructions push `(0,0,20,20)`. Root cause: IDA assigned a 136-byte cleanup to the earlier virtual call at `0x100871f8`, whose real callee returns with 4-byte cleanup. This made the EH state byte at `[ebp-4]` alias an outgoing argument in the model.

Correct approach: inspect oversized cleanup before all reachable SetBounds calls, independently of whether the uncorrected arguments already look constant. Require the immediate vptr load to correlate the table register with ECX. Follow non-null receiver construction (including a preserved allocation pointer), prove the returned object and unavoidable vptr store, read the current virtual method, and use its actual RET cleanup. No fixed slot, member offset, version address or business dimensions are lookup constants. Unknown cleanup quarantines only downstream affected calls; it is not a constant match and does not invalidate earlier unrelated calls. Other caller-analysis failures remain fatal.

Validation: a synthetic regression reproduces the bogus EH-state argument and verifies corrected constant/variable behavior; another test executes the actual worker functions with a synthetic adapter to verify downstream quarantine even for initially unknown arguments. Real HL25 and both Sven Windows binaries pass the final matrix. On HL25 Windows, unresolved cleanup excludes `0x10023777`, `0x100237e1` and `0x100259f8`; none belonged to the approved constant/same-receiver-scaled set before correction. This is a conservative provenance finder, not a list of every dynamic SetBounds call.

### Coverage and evidence

11 configured GameUI tags / 15 binaries; 402 artifacts: 386 Const and 16 ScaledConst (Windows 291, Linux 111). CS/CZ/CZDS tags do not declare separate GameUI modules and are not given fabricated registrations.

| Tag | Windows Const | Linux Const | ScaledConst W/L |
| --- | ---: | ---: | ---: |
| cof-5936 | 31 | - | 0/- |
| hl-3248 | 29 | - | 0/- |
| hl-3266 | 29 | - | 0/- |
| hl-3329 | 29 | - | 0/- |
| hl-3647 | 29 | - | 0/- |
| hl-4554 | 29 | - | 0/- |
| hl-6153 | 28 | - | 0/- |
| hl-8684 | 28 | 44 | 0/0 |
| hl-10210 | 13 | 13 | 8/8 |
| svencoop-8948 | 19 | 23 | 0/0 |
| svencoop-10257 | 19 | 23 | 0/0 |

The user's CContentControlDialog example is `hl-8684` Windows VA `0x10032510`, calling SetBounds at `0x100437b0`, arguments `(0,0,372,160)`, artifact `vgui2_Panel_SetBounds_Const_callsite_13.windows.yaml`. HL25 Windows retains its direct constant call at `0x1001d47a` (`Const_callsite_3`).

Final forced selected-node batch `analysis-batch-20261002T122328-9eb4b9793c7d4560bd2612e1e967e9e8`: 15 binaries succeeded. Independent PE/ELF byte audit verified all 402 identities, VA/RVA arithmetic, CALL destinations, signature bytes/uniqueness and exploratory address sets; ELF text relocations were applied when comparing loaded-code signatures. Unit suite: 1,359 tests OK, 5 skipped. After staging the complete artifact inventory, repository-contract suite: 15 tests OK. Repository format check and staged diff whitespace check exited 0. All 402 artifacts are newly added; existing tracked artifacts have no content changes.

## Callers

Consumers may redirect selected CALL sites using the new gamedata artifacts. ScaledConst already denotes scaled arguments; consumers must not blindly scale those values again. No MetaHookSv consumer changes are included.

### PR #322: cold IDB merged-function input failure

Trigger: CI run 36966414604 attempt 3 stopped at `hl-3248/serverbrowser:windows:find-vgui2_Panel-size-callsites` input validation, before the finder ran. The `Panel::Init` artifact points to `0x10019240..0x100192d2`; fresh IDA analysis assigns that range to a merged function `0x10016610..0x10019516`. The existing local i64 has separate function boundaries, which concealed this in restored-IDB validation. The next 28 serial nodes were aborted, not independently failing.

Root cause/constraint: extracting shared sizing identity code correctly selected the existing SetSize consumers for CI. The shared function-owner recovery rejected every interior entry, even an independently called, disconnected routine. Rebuilding a cold IDB reproduces the same failure, so merely retrying or replacing the cache is insufficient.

Correct approach: `_recover_merged_function_entry` in `ida_analyze_util.py` requires an explicit size and matching non-wildcard signature, a bounded executable span, a single original main chunk, and an external direct CALL. The entry's reachable basic blocks must cover exactly the requested interval with no incoming predecessor from outside it and no outgoing CFG edge beyond it. Only then truncate the merged owner and define the entry; failed definition restores the original owner. No bytes are deleted and the owned validation database is not saved.

Validation: isolated original binary cold analysis reproduced the CI owner; runtime input validation then recovered the entry, and the real SetSize preprocessor regenerated all declared ServerBrowser artifacts byte-identically. Behavioral unit cases cover connected/escaping/incomplete regions, missing calls or signature/size evidence, mismatched signatures and rollback. Applicable to artifact-backed function-entry recovery, not arbitrary interior addresses.
