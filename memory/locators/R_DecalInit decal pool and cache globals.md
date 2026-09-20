---
title: R_DecalInit decal pool and cache globals
type: note
permalink: goldsrc-vibesignatures/locators/r-decal-init-decal-pool-and-cache-globals
tags:
- locator
- engine
- func
- gv
- decal
- renderer
- byte-signature
---

# R_DecalInit and the decal pool/cache globals

## Symbols

- **Function**: `R_DecalInit(void)` — `category: func`
- **Globals**: `gDecalPool` (`decal_t[4096]`, `static`), `gDecalCache` (`decalcache_t[256]`) — `category: gv`
- **Module**: engine (`hw.dll` / `hw.so` / `hw.decrypt.dll` for the BLOB builds)
- **Source**: `engine/gl_rsurf.c` (`gDecalPool` 2179, `gDecalCache` 2207, `R_DecalInit` 2211 in `D:/HLND2T_official`); sole caller is `R_NewMap` (`engine/gl_rmisc.c:342`)
- **Producer**: `ida_preprocessor_scripts/find-R_DecalInit.py` (one skill, three outputs)

```c
static decal_t   gDecalPool[ MAX_DECALS ];           // 4096 * 28 = 0x1C000
decalcache_t     gDecalCache[ DECAL_CACHEENTRY ];    //  256 * 116 = 0x7400

void R_DecalInit( void ) {
    Q_memset( gDecalPool, 0, sizeof( decal_t ) * MAX_DECALS );
    gDecalCount = 0;
    for( i = 0; i < DECAL_CACHEENTRY; i++ )
        gDecalCache[i].decalIndex = -1;
}
```

## Availability

- Declared in all 11 engine configs (hl-3248/3266/3329/3647/4554/6153/8684/10210,
  svencoop-8948/10257, cof-5936) → 15 Windows/Linux platform pairs.
- No predecessor artifact: the finder has no `expected_input`.
- Never inlined on any validated build; `R_DecalInit` is a standalone function everywhere.

## How it is located

Two code signatures (repository budget: at most four covering every gamever/platform). The
finder tries them in order and requires the first one that matches to resolve to exactly one
owning function across the whole image.

| Signature | Encodes | Coverage | Hit offset |
| --- | --- | --- | --- |
| `C7 00 FF FF FF FF 83 C0 74` | `mov dword ptr [eax], -1` + `add eax, 74h` (`decalscache[i].decalIndex = -1` and the `sizeof(decalcache_t)` stride) | 14/15 — all four Linux builds and ten Windows builds | `+0x23`…`+0x36` |
| `68 00 C0 01 00 6A 00` | `push 1C000h` + `push 0` (`sizeof(decal_t) * MAX_DECALS` memset size/fill) | 11/11 Windows, including cof-5936 | `0x0`, or `+0x4` on cof-5936 |

Both signatures must exist because the compiler families differ:

- Linux gcc builds `Q_memset(gDecalPool, 0, 0x1C000)` as `mov eax, 1C000h` + `mov [esp+N], …`,
  never as `push imm32; push imm8`, so they miss the second signature.
- cof-5936 emits the cache loop in indexed form (`imul ecx, 74h; mov dword_2BFE2C0[ecx], -1`)
  instead of pointer-walk, so it misses the first signature.

The two globals are recovered from the located body, never from an address or a second pattern:

- `gDecalCache` is the array base of the `-1` store — the address loaded into the store's base
  register (`mov reg, offset X`; PIC `lea reg, (X - GOT)[ebx]` recovered through the
  `call __x86.get_pc_thunk.*; add reg, imm32` prologue), or the absolute displacement of an
  indexed store (cof-5936: `C7 81 C0 E2 BF 02 FF FF FF FF`, operand offset 2).
- `gDecalPool` is the destination the body's single non-thunk call (`Q_memset`) zeroes, found by
  scanning back from that call. The `__x86.get_pc_thunk.*` call is excluded by its ≤4-byte body.

If the chosen signature matches zero functions or more than one owning function, or the body
does not contain exactly one non-thunk call plus one reusable `-1` store with a displacement, the
finder writes nothing.

## Evidence

ELF symbol tables (non-stripped Linux peers) match the emitted addresses exactly:

| Binary | `R_DecalInit` | `gDecalPool` (size) | `gDecalCache` (size) |
| --- | --- | --- | --- |
| hl-10210 `hw.so` | `0x182a10` | `0x807ba0` (`0x1c000`) | `0xf9f820` (`0x7400`) |
| hl-8684 `hw.so` | `0x1d50e0` | `0x81d8a0` (`0x1c000`) | `0xf47880` (`0x7400`) |
| svencoop-8948 `hw.so` | `0x19ac80` (`_Z11R_DecalInitv`) | `0x796d060` (`_ZL10gDecalPool`, `0x1c000`) | `0x38d80a0` (`0x7400`) |

svencoop-10257 `hw.so` is stripped; its addresses (`R_DecalInit` `0x14eca0`, `gDecalPool`
`0x798d200`, `gDecalCache` `0x38f8240`) are validated by the PIC `lea [ebx+disp]` operands plus
the `0x7400` loop bound. Both PIC artifacts carry `gv_pic_addend`.

Validation run: `uv run python ida_analyze_bin.py -allgamever -modules engine -skill
find-R_DecalInit -platform windows,linux -debug` → 13 successful / 0 failed (hl-10210's two
nodes were produced by the earlier targeted run and skipped as already present) = all 15 pairs.
`format_repo_files.py --check`, `ruff check --ignore N999`, unit (927 tests) and
repository-contract (14 tests) all pass.

## Pitfalls

- **A `-1` memory store alone is not unique.** hl-10210's `GL_UnloadTextures` also stores
  `0xFFFFFFFF` (`mov dword_10F288C0[eax], 0FFFFFFFFh`, stride `0x308`). The chosen `loop_store`
  signature pins the decal-cache statement together with its `0x74` stride, and the body-level
  checks (exactly one non-thunk call, one qualifying store) reject the sibling.
- **Do not resolve the global through the `-1` store when the store has no address
  displacement.** `mov dword ptr [eax], 0FFFFFFFFh` encodes the immediate at offset 2, so a
  naive operand scan would emit the constant instead of an address. Use the instruction that
  materialises the base (`mov reg, offset X`, `lea reg, (X-GOT)[ebx]`).
- **`disp32_offset` returns the first operand with a 4-byte displacement.** For cof-5936's
  `C7 81 …` that is the memory operand at offset 2 (correct); for `mov [esp+N], offset X` it is
  the immediate at offset 3 (correct). Validate the decoded value against the array base rather
  than trusting the offset alone — `gv_address_offset`/`gv_pic_addend` being absent or zero is
  the confirmation.
- **The `push 1C000h; push 0` pattern is Windows-only.** It is absent from all four Linux
  builds, so it cannot be the sole anchor for a cross-platform finder (same class of mistake as
  [[MetaHookSv byte patterns are hints, not portable anchors]]).
