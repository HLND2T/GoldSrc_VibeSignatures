---
title: host_initialized locator
type: note
permalink: goldsrc-vibesignatures/locators/host-initialized-locator
tags:
- locator
- engine
- gv
---

# host_initialized

## Symbol

- **Name**: `host_initialized`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SPR_Shutdown-host_initialized.py`

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Windows on all 11; Linux on hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- `engine/host.c` declares it `qboolean host_initialized` — a four-byte flag, not a `bool`.

## Predecessors

- `SPR_Shutdown.{platform}.yaml` — the owning function whose signature anchors the artifact.
- `CGame_AppActivate.{platform}.yaml` — the independent cross-check. See [[CGame_AppActivate locator]].

Both artifacts are re-validated in the current IDB (function start + `func_sig`) through
`inspect_owner_artifact` before discovery runs; a missing or stale artifact fails closed.

## How it is located

`engine/cl_draw.c` opens `SPR_Shutdown` with `if (!host_initialized) return;` and clears every
sprite global it touches (`gSpriteList`, `gSpriteCount`, `gpSprite`, `ghCrosshair`) before
returning. Three judgements must agree, and each alone is insufficient:

1. **Read-never-written** — the only writable global the `SPR_Shutdown` body reads without ever
   storing to. The four sprite globals are all `mov`-stored to zero, so they drop out.
2. **Cross-function intersection** — the candidate must also appear in `CGame::AppActivate`,
   which guards both of its activation branches with the same flag. The two bodies share no
   other global.
3. **Early-out shape** — a four-byte reference followed by a conditional jump within four
   instructions. This is what separates the flag from a `___security_cookie`-style prologue read.

Any zero-or-multiple result fails closed and reports the rejected candidates with reasons.
The signature is generated from the re-validated `SPR_Shutdown` body afterwards; it is output
validation only, never a discovery anchor.

## Verified results

| Build | Platform | `gv_va` | Anchor instruction | Encoding |
| --- | --- | --- | --- | --- |
| hl-3248 | windows | `0x23cdd30` | `mov eax, dword_23CDD30` | absolute, disp 1 |
| hl-3266 | windows | `0x23cdd30` | `mov eax, ...` | absolute, disp 1 |
| hl-3329 | windows | `0x239abd8` | `mov eax, ...` | absolute, disp 1 |
| hl-3647 | windows | `0x2399a80` | `mov eax, ...` | absolute, disp 1 |
| hl-4554 | windows | `0x2383da4` | `mov eax, ...` | absolute, disp 1 |
| hl-6153 | windows | `0x234092c` | `mov eax, ...` | absolute, disp 1 |
| hl-8684 | windows | `0x2343e44` | `mov eax, ...` | absolute, disp 1 |
| hl-8684 | linux | `0x2eea50` | `mov eax, ds:host_initialized` | absolute, disp 1 |
| hl-10210 | windows | `0x104b8ccc` | `cmp dword_104B8CCC, 0` | absolute, disp 2 |
| hl-10210 | linux | `0x2d5164` | `mov eax, ds:host_initialized` | absolute, disp 1 |
| svencoop-8948 | windows | `0x8406ae4` | `cmp dword_8406AE4, 0` | absolute, disp 2 |
| svencoop-8948 | linux | `0x357a80` | `mov eax, ds:(host_initialized_ptr - 33A000h)[ebx]` | PIC GOT-indirect, `gv_pic_addend 0x357d84` |
| svencoop-10257 | windows | `0x8446c74` | `cmp dword_8446C74, 0` | absolute, disp 2 |
| svencoop-10257 | linux | `0x30a4c0` | `lea eax, (dword_30A4C0 - 2EE000h)[ebx]` | PIC GOTOFF, `gv_pic_addend 0x2ee000` |
| cof-5936 | windows | `0x23c9de4` | `cmp dword_23C9DE4, 0` | absolute, disp 2, after prologue |

Regression evidence for those exact inputs only.

## Pitfalls

- **Operand decoding rules apply in full** — see
  [[IDA operand decoding pitfalls in direct GV locators]]. `o_mem` carries a stale `op.reg`, so
  a base register is read only for `o_displ`/`o_phrase`; `SEGPERM_EXEC` is 1, not 4; and
  `py_eval` genexprs cannot see module-level names without `globals().update(locals())`.
- **Indirect `call`/`jmp` operands are excluded.** They address IAT/PLT slots that live in
  writable data and would otherwise pollute the candidate set.
- **Two distinct PIC forms exist on SvEngine Linux.** svencoop-10257 materialises the address
  with `lea eax, [ebx+GOTOFF]`, while svencoop-8948 loads a GOT pointer with
  `mov eax, [ebx+GOT]` and then dereferences it. Both resolve through the shared `.got`/`.got.plt`
  pointee handling; an `lea` or GOT load is accepted as address-bearing without a dword-size check,
  because it carries the address rather than the value.
- Register tracking follows only real address loads (`lea reg, [...]`, a PIC GOT load, an
  immediate address, and register-to-register propagation), and is invalidated across `call`
  for the caller-saved registers.
- The flag is `qboolean` (four bytes). Do not apply a byte-size filter as if it were a C `bool`.

## Relations

- depends on [[CGame_AppActivate locator]]
- depends on [[SPR_Shutdown locator]]
