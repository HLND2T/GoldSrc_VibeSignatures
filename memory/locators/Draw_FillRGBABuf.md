---
title: Draw_FillRGBABuf
type: note
permalink: goldsrc-vibesignatures/locators/draw-fill-rgbabuf
tags:
- locator
- engine
- func
---

# Draw_FillRGBABuf

## Overview

SvEngine's buffered rectangle function, `engine / func`, with eight x86 cdecl integer arguments `(x, y, w, h, r, g, b, a)`. Published for svencoop-10257 and svencoop-8948 on Windows and Linux. The real Linux 8948 symbol is `_Z16Draw_FillRGBABufiiiiiiii`; Windows and Linux 10257 identity is established from matching ABI, buffer operations and callers.

Issue #148 replaces the incorrect historical `NET_DrawRect` catalog name. The user explicitly chose no compatibility alias. [[D_FillRect locator]] remains the separate HL/CoF two-pointer function; [[Draw_FillRGBABlend locator]] remains the separate direct alpha-blend function.

## Responsibilities

Append four vertices, each containing six floats (`x/y/r/g/b/a`, stride 24 bytes), to the engine's vertex buffer. Flush at capacity 1024 with `glDrawArrays(GL_QUADS, 0, count)` and `glBlendFunc(GL_SRC_ALPHA, GL_ONE)`. The count is not screen width.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-Draw_FillRGBABuf.py`: unique semantic candidate discovery and output generation.
- `ida_preprocessor_scripts/x86_call_arguments.py`: conservative backward recovery of concrete arguments from decoded stack/register writes.
- `ida_preprocessor_scripts/renderer_draw_signatures.py`: shared shortest-unique signature output, with immediates preserved.
- `configs/svencoop-10257.yaml`, `configs/svencoop-8948.yaml`: both platforms registered; old `NET_DrawRect` registrations removed.
- `bin_artifacts/<game>/engine/Draw_FillRGBABuf.<platform>.yaml`: four outputs.
- `tests/test_x86_call_arguments.py`: synthetic push order, register/stack writes, zeroing, overwrites, branch boundaries and call-clobber tests.

## Architecture

No target-owned string or distinctive float set separates this body from the other RGBA helpers. Reuse the verified buffer instruction semantics across both compiler forms rather than a byte pattern, prior YAML, address, or symbol spelling:

1. Walk x86 functions sized 100..900 bytes. Within the first 24 decoded instructions require `cmp` against 1024 or 1023 (Windows `< 1024`; Linux `<= 1023`).
2. Resolve the exact sequence of 13 GL calls: enable vertex/color client state, disable texture, enable blending, set texture environment, set blend factors, set vertex/color pointers, draw arrays, disable both client states, restore texture and disable blending. Windows register-held imports and Linux PLT jumps are supported. Reject other callees except a verified Linux get-PC thunk.
3. Recover actual integer call arguments using stack deltas and backward dataflow: state enums, texture-environment enums, blend `(0x302,1)`, vertex `(2,0x1406,24)`, color `(4,0x1406,24)`, draw `(7,0)`. Mere occurrence of constants is insufficient. Unknown writes/branches or caller-clobbered values do not establish an argument.
4. Require reads of all eight incoming stack arguments, integer-to-float conversion of x/y/r/g/b/a, a cdecl return, and exactly 24 non-stack memory float stores. IDA's hidden ST(0) operands must not be counted as memory stores.
5. Require exactly one candidate, then generate and uniquely validate the runtime signature. Neither old artifacts nor signatures locate the body.

The old Windows finder and two `NET_DrawRect` artifacts are removed. There is one production identity per body, not two independent locators or two hook targets.

## Dependencies

Owned `IdaMcpLifecycle`, current IDA decoded functions/imports/stack deltas, shared signature generator and repository analyzer validators. No input artifact or LLM predecessor is required.

## Notes

| Build | RVA | func_size |
| --- | --- | --- |
| svencoop-10257 Windows | `0x51600` | `0x1f1` |
| svencoop-8948 Windows | `0x513b0` | `0x1f4` |
| svencoop-10257 Linux | `0x12a590` | `0x25b` |
| svencoop-8948 Linux | `0x177080` | `0x25b` |

Windows image base is `0x1d00000`; Linux is zero. Hashes, full ABI audit and original connection-message replacement evidence are recorded in [[D_FillRect locator]]. The inferred EAX integer result in decompilation is not proof of a source-level return declaration.

Consumers adopting this catalog must rename `NET_DrawRect` lookups/hooks to `Draw_FillRGBABuf` and use eight integer parameters. Skip `D_FillRect` on Sven; the connection-message fill is already intercepted through `Draw_FillRGBABlend`. MetaHookSv modifications are outside this repository.

Initial real-binary analyzer runs passed all four requested targets with one candidate each, zero failures and unique runtime signatures. Local logs: `.candidates/issue148/analyze-10257.log`, `analyze-8948.log`. The shared argument helper has five passing synthetic tests, including a red/green regression preventing inference from stale stack contents across a call. Full unit suite: 893 tests, two skipped. No game-rendering/hook-installation test is claimed.

## Callers

Linux 8948 `NET_FillRect` at RVA `0x137970`, size `0x5b`, has real name `_Z12NET_FillRectP7vrect_sPhh` and expands `(rect, color, alpha)` into eight integer arguments for this body. That three-argument adapter is not `D_FillRect`. Windows netgraph routines call the buffered body directly; their ABI was inspected during the issue #148 audit.

## Final implementation validation

- Final finder rerun in the initially empty `.candidates/issue148/final-artifacts` directory for each requested game with `-modules engine -skill find-Draw_FillRGBABuf -platform windows,linux -oldgamever none`: four successful targets, zero failed or skipped. All four outputs are byte-identical to production artifacts.
- `uv run python tests/run_test_suite.py unit -b --durations 30`: 893 tests passed, two skipped.
- `uv run python tests/run_test_suite.py repository-contract -b --durations 30`: 14 tests passed.
- `uv run python format_repo_files.py --check` and `git diff --check` passed.
- The analyzer enforces exact-binary identity and signature/address validation. No consumer integration or runtime rendering test was run.
