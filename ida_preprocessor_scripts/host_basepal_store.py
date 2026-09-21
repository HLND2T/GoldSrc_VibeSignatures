"""Prove a unique Hunk_AllocName(size, name) return store.

``engine/host.c`` assigns ``host_basepal = Hunk_AllocName(2048, "palette.lmp")``.
The locator requires the call target, both C arguments, and EAX/return-register
dataflow into the store. Nearby 0x800 immediates and unrelated global writes
are not enough. After the call, only proven keep-alive instructions may preserve
the return register; implicit writers such as ``mul`` kill it.
"""

from ida_preprocessor_scripts.x86_call_arguments import recover_call_arguments


def locate_palette_hunk_store(
    code,
    hunk_ea,
    size_imm,
    name_addrs,
    recover_call_arguments=recover_call_arguments,
):
    hunk_ea = int(hunk_ea)
    size_imm = int(size_imm)
    names = {int(addr) for addr in name_addrs}
    candidates = []
    for index, entry in enumerate(code):
        if entry.get("mnem") != "call" or int(entry.get("call_target") or 0) != hunk_ea:
            continue
        args = recover_call_arguments(code, index, 2)
        if args[0] != size_imm or args[1] not in names:
            continue
        live = {"eax"}
        for later in code[index + 1 :]:
            mnem = later["mnem"]
            if mnem == "call" or mnem.startswith("j") or mnem in ("ret", "retn", "loop"):
                break
            ops = later.get("ops") or []
            dest = ops[0] if ops else None
            src = ops[1] if len(ops) > 1 else None
            if mnem == "mov" and dest and dest[0] == "reg":
                dest_reg = dest[1]
                if src and src[0] == "reg" and src[1] in live:
                    live.add(dest_reg)
                elif dest_reg in live:
                    live.discard(dest_reg)
                continue
            if mnem in ("cmp", "test", "push"):
                continue
            if mnem in ("add", "sub") and dest == ("reg", "esp") and src and src[0] == "imm":
                continue
            if mnem != "mov" or not src or src[0] != "reg" or src[1] not in live:
                live.clear()
                continue
            written = later.get("written") or set()
            if len(written) != 1 or not later.get("disp"):
                live.clear()
                continue
            gv = next(iter(written))
            candidates.append(
                (
                    gv,
                    {
                        "gv_ea": hex(int(gv)),
                        "insn_ea": hex(int(later["ea"])),
                        "insn_len": hex(int(later["len"])),
                        "insn_disp": hex(int(later["disp"])),
                        "insn_disasm": later.get("disasm") or "",
                    },
                )
            )
            break
    unique = {}
    for gv, located in candidates:
        unique[gv] = located
    if len(unique) != 1:
        return {
            "error": "Hunk_AllocName(0x800, palette.lmp) return store is not unique: %s" % [hex(gv) for gv in unique]
        }
    return {"pointer_size": 4, "gv": next(iter(unique.values()))}
