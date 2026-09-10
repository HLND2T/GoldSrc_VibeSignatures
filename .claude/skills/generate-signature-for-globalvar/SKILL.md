---
name: generate-signature-for-globalvar
description: |
  Generate and validate unique byte signatures for global variables using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a global variable that can reliably locate it across binary updates.
  Triggers: global variable signature, signature for global variable
---

# Generate Signature for Global Variable (GoldSrc)

Generate a unique hex byte signature that locates an **instruction accessing a global variable** using fully programmatic wildcard detection and validation — no manual byte analysis required. Applies to GoldSrc **PE32/I386** (Windows) and **ELF32/I386** (Linux) binaries only.

## Core Concept

Since global variable addresses change between binary updates, we don't signature the GV itself. Instead, we:
1. Find an instruction that **references** the global variable (mov/lea/cmp/etc.)
2. Generate a signature to locate that **instruction**
3. At runtime, parse the instruction to **resolve** the actual GV address

### Absolute Addressing (x86-32)

GoldSrc is **x86-32**. Most global variable accesses encode the GV's **absolute virtual address** directly in the
instruction displacement:

```
mov eax, ds:dword_1000        ; A1 00 10 00 00
mov edx, dword_1000           ; 8B 15 00 10 00 00
cmp dword_1000, 0             ; 83 3D 00 10 00 00 00
lea eax, dword_1000           ; 8D 05 00 10 00 00
```

So the runtime resolution is:

```
GV_Address = *(uint32_t*)(inst_addr + gv_inst_disp)
```

The 4-byte displacement bytes **are** the GV's absolute address. There is **no RIP-relative formula** (that is
x86-64 Source2-specific and must not be used).

### PIC GOTOFF Addressing (SvEngine Linux)

SvEngine Linux (e.g. svencoop hw.so) is position-independent and accesses globals through a GOT-anchored
register (`call __i686.get_pc_thunk.ax; add eax, _GLOBAL_OFFSET_TABLE_` then `mov [eax+disp32], edx`).
The embedded disp32 is then the **GOTOFF displacement** (`var - GOT base`), not an address:

```
89 90 D4 88 A3 00    mov [eax+0xA388D4], edx   ; r_model = 0xD268D4 = 0xA388D4 + GOT 0x2EE000
```

No relocation patches these sites, so the runtime dword stays the GOTOFF displacement forever. Such
artifacts must emit the optional **gv_pic_addend** field (the target RVA minus the embedded dword) and consumers must add
it (see Runtime Resolution Formula below). Absolute-form sites never emit it; their embedded dword is
either the link-time address (`R_386_RELATIVE`) or loader-filled from the symbol (`R_386_32`), both of
which hold the true runtime address after loading.

## Prerequisites

- Global variable address. `dword_XXXXXX` for example.
- IDA Pro MCP connection

## Method

### 1. Generate and Validate Signature (Single Step)

Use a single `py_eval` call that:
- Discovers candidate instructions accessing the GV via `DataRefsTo`
- Verifies each candidate resolves to the target GV via its **absolute 32-bit displacement**
- Collects instruction stream with auto-wildcarding for each candidate
- Tracks instruction boundaries so prefixes always cover complete instructions
- Progressively tests at each instruction boundary via binary search
- Outputs the shortest unique signature with full metadata

**Note**: If you already know the GV-accessing instruction address, set `target_inst = <inst_addr>`. If you know the containing function, set `target_func = <func_addr>`.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, ida_segment, json

def main():
    target_gv = <gv_addr>
    target_inst = None       # Set to instruction address if known, e.g. 0x10244610
    target_func = None       # Set to function address to restrict search, e.g. 0x10244000
    min_sig_bytes = 8
    max_sig_bytes = 96
    max_instructions = 64
    max_candidates = 32

    # --- Binary search wrapper (IDA 9.0+ find_bytes -> older bin_search fallback) ---
    def raw_bin_search(ea, max_ea, data, mask, flags=0):
        if hasattr(ida_bytes, 'find_bytes'):
            return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)

    # --- Search bounds ---
    seg = ida_segment.get_segm_by_name(".text")
    if seg:
        search_start, search_end = seg.start_ea, seg.end_ea
    else:
        search_start, search_end = idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea

    def resolve_disp_off(insn_ea, insn, raw):
        # x86-32: the 4-byte displacement is the GV's absolute address.
        cand_offsets = set()
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                continue
            offb = int(getattr(op, 'offb', 0))
            offo = int(getattr(op, 'offo', 0))
            if offb > 0 and offb + 4 <= insn.size:
                cand_offsets.add(offb)
            if offo > 0 and offo + 4 <= insn.size:
                cand_offsets.add(offo)
        for off in sorted(cand_offsets):
            disp_u32 = int.from_bytes(raw[off:off + 4], 'little', signed=False)
            if (disp_u32 & 0xFFFFFFFF) == (target_gv & 0xFFFFFFFF):
                return off
        return None

    def collect_and_validate(inst_ea, disp_off):
        f = idaapi.get_func(inst_ea)
        if not f:
            return None
        limit_end = min(f.end_ea, inst_ea + max_sig_bytes)
        sig_tokens = []
        inst_boundaries = []
        cursor = inst_ea
        first_len = None
        while cursor < f.end_ea and cursor < limit_end and len(sig_tokens) < max_sig_bytes:
            insn = idautils.DecodeInstruction(cursor)
            if not insn or insn.size <= 0:
                break
            raw = ida_bytes.get_bytes(cursor, insn.size)
            if not raw:
                break
            wild = set()
            for op in insn.ops:
                ot = int(op.type)
                if ot == int(idaapi.o_void):
                    continue
                if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
                    offb = int(getattr(op, 'offb', 0))
                    if offb > 0 and offb < insn.size:
                        dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                        if dsz <= 0:
                            dsz = insn.size - offb
                        for i in range(offb, min(insn.size, offb + dsz)):
                            wild.add(i)
                    offo = int(getattr(op, 'offo', 0))
                    if offo > 0 and offo < insn.size:
                        dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                        if dsz2 <= 0:
                            dsz2 = insn.size - offo
                        for i in range(offo, min(insn.size, offo + dsz2)):
                            wild.add(i)
            b0 = raw[0]
            if b0 in (0xE8, 0xE9, 0xEB):
                for i in range(1, insn.size):
                    wild.add(i)
            elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:
                for i in range(2, insn.size):
                    wild.add(i)
            elif 0x70 <= b0 <= 0x7F:
                for i in range(1, insn.size):
                    wild.add(i)
            if cursor == inst_ea:
                first_len = insn.size
                # The GV absolute-address displacement is volatile across builds.
                for i in range(disp_off, min(insn.size, disp_off + 4)):
                    wild.add(i)
            for idx in range(insn.size):
                sig_tokens.append("??" if idx in wild else f"{raw[idx]:02X}")
            inst_boundaries.append(len(sig_tokens))
            cursor += insn.size
        if not sig_tokens or first_len is None:
            return None
        for boundary in inst_boundaries:
            if boundary < min_sig_bytes:
                continue
            prefix_tokens = sig_tokens[:boundary]
            if all(t == "??" for t in prefix_tokens):
                continue
            data = bytes(0 if t == "??" else int(t, 16) for t in prefix_tokens)
            mask = bytes(0x00 if t == "??" else 0xFF for t in prefix_tokens)
            flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
            matches = []
            ea = raw_bin_search(search_start, search_end, data, mask, flags)
            while ea != idaapi.BADADDR and len(matches) < 2:
                matches.append(ea)
                ea = raw_bin_search(ea + 1, search_end, data, mask, flags)
            if len(matches) == 1 and matches[0] == inst_ea:
                return {
                    "gv_sig": " ".join(prefix_tokens),
                    "sig_bytes": boundary,
                    "gv_sig_va": hex(inst_ea),
                    "gv_inst_length": first_len,
                    "gv_inst_disp": disp_off,
                }
        return None

    # --- Discover candidate GV-accessing instructions ---
    candidates_tried = 0
    best = None
    seen = set()

    def try_candidate(iea):
        nonlocal candidates_tried, best
        if iea in seen:
            return
        seen.add(iea)
        insn = idautils.DecodeInstruction(iea)
        if not insn or insn.size <= 0:
            return
        raw = ida_bytes.get_bytes(iea, insn.size)
        if not raw:
            return
        doff = resolve_disp_off(iea, insn, raw)
        if doff is None:
            return
        candidates_tried += 1
        result = collect_and_validate(iea, doff)
        if result is not None:
            if best is None or result["sig_bytes"] < best["sig_bytes"]:
                best = result

    if target_inst is not None:
        try_candidate(target_inst)
    elif target_func is not None:
        f = idaapi.get_func(target_func)
        if f:
            ea = f.start_ea
            while ea < f.end_ea and candidates_tried < max_candidates:
                fl = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_code(fl):
                    try_candidate(ea)
                    if best is not None:
                        break
                nea = ida_bytes.next_head(ea, f.end_ea)
                if nea == idaapi.BADADDR or nea <= ea:
                    break
                ea = nea
    else:
        for ref in idautils.DataRefsTo(target_gv):
            if candidates_tried >= max_candidates:
                break
            fl = ida_bytes.get_full_flags(ref)
            if not ida_bytes.is_code(fl):
                continue
            try_candidate(ref)
            if best is not None:
                break

    if best:
        best["gv_va"] = hex(target_gv)
        best["gv_rva"] = hex(target_gv - idaapi.get_imagebase())
        best["gv_inst_offset"] = 0
        best["status"] = "success"
        print(json.dumps(best))
    else:
        print(json.dumps({
            "gv_va": hex(target_gv),
            "candidates_tried": candidates_tried,
            "error": "no unique gv-access signature found",
            "status": "failed"
        }))

main()
"""
```

**Result handling:**
- `status == "success"` → Use `gv_sig` and metadata directly
- `status == "failed"` → See Step 2

### 2. Iterate if Needed

If Step 1 returns `status: "failed"`:
1. Increase `max_sig_bytes` (e.g., to 192) and re-run Step 1
2. Specify a different `target_func` to find more candidates
3. Re-run until unique

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Provide the following information for runtime GV resolution:

### Required Output Fields

1. **gv_sig**: Space-separated hex bytes with `??` for wildcards
1. **gv_sig_va**: The virtual address that the signature matches
2. **gv_inst_offset**: Always `0` (signature starts at the GV-accessing instruction)
3. **gv_inst_length**: Total length of the GV-accessing instruction (from output metadata)
4. **gv_inst_disp**: Position of the 4-byte absolute-address displacement within the instruction (from output metadata)

### Optional Output Fields

1. **gv_pic_addend**: Present for PIC register-relative `disp32` sites. The variable RVA equals the
   embedded disp32 plus this value (mod 2^32). It includes any constant intermediate base and member
   adjustment; it is not necessarily the GOT RVA. Presence, including zero, selects module rebasing.
2. **gv_address_offset**: Optional adjustment after address recovery (mod 2^32). For example,
   `0xfffffffc` recovers a table base from a relocated absolute operand holding `table + 4`.

The shared emitter always preserves these semantic fields, even when a finder's desired-field list
omits them. Direct locators use `gv_resolution_fields_via_mcp` after validating ownership and the target.

### Example Output

```yaml
gv_sig: "A1 ?? ?? ?? ?? 85 C0 74 ?? 8B 0D ?? ?? ?? ??"
gv_sig_va: 0x10244610      # The virtual address that the signature matches
gv_inst_offset: 0          # GV instruction starts at signature start
gv_inst_length: 5          # A1 XX XX XX XX = 5 bytes
gv_inst_disp:   1          # Displacement offset starts at position 1 (after A1)
```

### Runtime Resolution Formula (x86-32 — absolute addressing)

At runtime, after pattern scan finds the signature at address `scan_result`:

```cpp
// C++ example
uint8_t* inst_addr = scan_result + gv_inst_offset;
uint32_t gv_address = *(uint32_t*)(inst_addr + gv_inst_disp) + gv_address_offset; // default offset: 0
```

```python
# Python example
import struct
inst_addr = scan_result + gv_inst_offset
gv_address = (struct.unpack('<I', memory[inst_addr + gv_inst_disp : inst_addr + gv_inst_disp + 4])[0]
              + gv_address_offset) & 0xFFFFFFFF  # default offset: 0
```

The displacement **is** the GV's absolute address. Do **not** add `inst_length` (that is the x86-64 RIP-relative
formula and produces a wrong address on x86-32).

### Runtime Resolution Formula (x86-32 — PIC GOTOFF addressing)

When the artifact carries `gv_pic_addend` (register-relative disp32, SvEngine Linux), add it to the
embedded dword to recover the variable RVA, then rebase onto the loaded module:

```cpp
// C++ example
uint8_t* inst_addr = scan_result + gv_inst_offset;
uint32_t disp = *(uint32_t*)(inst_addr + gv_inst_disp);
uint32_t gv_rva = disp + gv_pic_addend;          // mod 2^32
uint32_t gv_address = module_base + gv_rva + gv_address_offset; // default offset: 0
```

```python
# Python example
import struct
inst_addr = scan_result + gv_inst_offset
disp = struct.unpack('<I', memory[inst_addr + gv_inst_disp : inst_addr + gv_inst_disp + 4])[0]
gv_rva = (disp + gv_pic_addend) & 0xFFFFFFFF
gv_address = (module_base + gv_rva + gv_address_offset) & 0xFFFFFFFF  # default offset: 0
```
