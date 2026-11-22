"""Offline PDB (llvm-pdbutil) and ELF/DWARF (llvm-readelf + llvm-dwarfdump) indexers."""

from __future__ import annotations

import collections
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class DebugProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class SymbolEntry:
    name: str
    mangled: str
    rva: int
    size: int
    is_import: bool = False
    prototype: str = ""


@dataclass(frozen=True)
class ArrayLayout:
    element_type: str
    element_size: int
    count: int
    total_size: int


@dataclass(frozen=True)
class FieldResolution:
    offset: int
    size: int | None
    type_name: str
    array: ArrayLayout | None = None


# Built-in CodeView primitive type sizes (32-bit x86).
_CV_PRIMITIVE_SIZES: dict[int, int] = {
    0x0003: 0,  # void
    0x0010: 1,  # signed char
    0x0011: 2,  # short
    0x0012: 4,  # long
    0x0013: 8,  # int64
    0x0020: 1,  # unsigned char
    0x0021: 2,  # unsigned short
    0x0022: 4,  # unsigned long
    0x0023: 8,  # unsigned int64
    0x0030: 1,  # bool
    0x0040: 4,  # float
    0x0041: 8,  # double
    0x0070: 1,  # char
    0x0071: 2,  # wchar_t
    0x0072: 2,  # int16
    0x0073: 2,  # uint16
    0x0074: 4,  # int
    0x0075: 4,  # unsigned int
    0x0076: 8,  # __int64
    0x0077: 8,  # unsigned __int64
}


def _run_tool(args: list[str], *, input_text: str | None = None, check: bool = True) -> str:
    try:
        proc = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
        )
    except FileNotFoundError as exc:
        raise DebugProviderError(f"Required CLI tool not found in PATH: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise DebugProviderError(f"Command failed ({exc.returncode}): {' '.join(args)}\n{exc.stderr.strip()}") from exc
    return proc.stdout


def strip_cpp_params(demangled: str) -> str:
    """Return qualified symbol name without parameter list, return type, or calling convention."""
    s = demangled.strip()
    # Keep special compiler suffixes like " (.part.0)" stripped separately by callers.
    if " [clone " in s:
        s = s.split(" [clone ", 1)[0].strip()
    idx = s.find("(")
    if idx != -1:
        # Preserve function-local static variable scope: Foo(int)::bar -> Foo::bar
        tail = s[idx:]
        close_idx = tail.find(")::")
        if close_idx != -1:
            s = s[:idx].strip() + "::" + tail[close_idx + 3 :].strip()
        else:
            s = s[:idx].strip()
    for token in (
        "__cdecl ",
        "__thiscall ",
        "__stdcall ",
        "__fastcall ",
        "public: ",
        "private: ",
        "protected: ",
        "virtual ",
        "static ",
    ):
        s = s.replace(token, "")
    if (
        not s.startswith(("vtable for ", "typeinfo ", "non-virtual thunk to ", "virtual thunk to "))
        and "operator" not in s
        and " " in s
    ):
        s = s.split()[-1]
    return s.strip()


def _format_rsds_guid(hex_bytes: list[int]) -> str:
    if len(hex_bytes) != 16:
        return ""
    d1 = int.from_bytes(bytes(hex_bytes[0:4]), "little")
    d2 = int.from_bytes(bytes(hex_bytes[4:6]), "little")
    d3 = int.from_bytes(bytes(hex_bytes[6:8]), "little")
    d4 = "".join(f"{b:02X}" for b in hex_bytes[8:10])
    d5 = "".join(f"{b:02X}" for b in hex_bytes[10:16])
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}}}"


def _batch_llvm_undname(mangled_list: list[str]) -> dict[str, str]:
    """Run llvm-undname in batches and pair echoed mangled lines with demangled results."""
    result: dict[str, str] = {}
    if not mangled_list:
        return result
    unique = list(dict.fromkeys(mangled_list))
    for i in range(0, len(unique), 2000):
        chunk = unique[i : i + 2000]
        chunk_set = set(chunk)
        out = _run_tool(["llvm-undname"], input_text="\n".join(chunk) + "\n", check=False)
        lines = out.splitlines()
        cur_src: str | None = None
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped in chunk_set and cur_src is None:
                cur_src = stripped
                continue
            if cur_src is not None:
                if not stripped.startswith("error:"):
                    result[cur_src] = stripped
                cur_src = None
    return result


def verify_pe_pdb_match(dll_path: Path, pdb_path: Path) -> None:
    """Fail closed if PE CodeView RSDS GUID/Age does not match PDB summary."""
    pe_out = _run_tool(["llvm-readobj", "--coff-debug-directory", str(dll_path)])
    pdb_out = _run_tool(["llvm-pdbutil", "dump", "--summary", str(pdb_path)])

    m_pe_guid = re.search(r"PDBGUID:\s*\(([0-9A-Fa-f\s]+)\)", pe_out)
    m_pe_age = re.search(r"PDBAge:\s*(\d+)", pe_out)
    m_pdb_guid = re.search(r"GUID:\s*(\{[0-9A-Fa-f-]+\})", pdb_out)
    m_pdb_age = re.search(r"Age:\s*(\d+)", pdb_out)
    if not (m_pe_guid and m_pe_age and m_pdb_guid and m_pdb_age):
        raise DebugProviderError(f"Unable to verify CodeView GUID/Age between {dll_path} and {pdb_path}")

    pe_bytes = [int(tok, 16) for tok in m_pe_guid.group(1).split()]
    pe_guid = _format_rsds_guid(pe_bytes)
    pe_age = int(m_pe_age.group(1))
    pdb_guid = m_pdb_guid.group(1).upper()
    pdb_age = int(m_pdb_age.group(1))
    if pe_guid != pdb_guid or pe_age != pdb_age:
        raise DebugProviderError(
            f"PE/PDB mismatch: {dll_path.name} expects {pe_guid} age={pe_age}, "
            f"but {pdb_path.name} has {pdb_guid} age={pdb_age}"
        )


class BaseDebugIndex:
    platform: str

    def find_funcs(self, name: str, *, allow_import: bool = False) -> list[SymbolEntry]:
        raise NotImplementedError

    def find_func_parts(self, base_name: str) -> list[SymbolEntry]:
        raise NotImplementedError

    def find_globals(self, name: str) -> list[SymbolEntry]:
        raise NotImplementedError

    def find_vtable(self, class_name: str) -> tuple[str, int] | None:
        raise NotImplementedError

    def find_vfunc_slot(self, class_name: str, method_name: str) -> int | None:
        raise NotImplementedError

    def resolve_struct_size(self, struct_name: str) -> int | None:
        raise NotImplementedError

    def resolve_field_path(
        self, struct_name: str, field_path: list[str], *, global_type_hint: str | None = None
    ) -> FieldResolution | None:
        raise NotImplementedError

    def resolve_global_array(self, global_name: str) -> ArrayLayout | None:
        raise NotImplementedError


class PdbDebugIndex(BaseDebugIndex):
    """Offline indexer backed by llvm-pdbutil and llvm-undname."""

    platform = "windows"

    def __init__(self, dll_path: Path, pdb_path: Path, *, verify_guid: bool = True) -> None:
        self.dll_path = Path(dll_path)
        self.pdb_path = Path(pdb_path)
        if verify_guid:
            verify_pe_pdb_match(self.dll_path, self.pdb_path)

        self.section_rvas: dict[int, int] = {}
        self.funcs_by_name: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.globals_by_name: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.global_type_tids: dict[str, int] = {}
        self.vtables_by_class: dict[str, tuple[str, int]] = {}

        # TPI graph
        self.tid_size: dict[int, int] = dict(_CV_PRIMITIVE_SIZES)
        self.tid_name: dict[int, str] = {}
        self.tid_array: dict[int, tuple[int, int]] = {}  # tid -> (elem_tid, total_bytes)
        self.tid_modifier_underlying: dict[int, int] = {}
        self.struct_name_to_tid: dict[str, int] = {}
        self.struct_members: dict[int, dict[str, tuple[int, int]]] = {}  # struct_tid -> {member: (offset, type_tid)}
        self.struct_methods: dict[int, dict[str, int | None]] = {}  # struct_tid -> {method: vftable_offset}

        self._load_sections()
        self._load_types()
        self._load_symbols_and_publics()

    def _sec_off_to_rva(self, sec: int, off: int) -> int | None:
        base = self.section_rvas.get(sec)
        if base is None:
            return None
        return base + off

    def _load_sections(self) -> None:
        out = _run_tool(["llvm-pdbutil", "dump", "--section-headers", str(self.pdb_path)])
        cur_sec: int | None = None
        re_sec = re.compile(r"^\s*SECTION HEADER #(\d+)")
        re_va = re.compile(r"^\s*([0-9A-Fa-f]+)\s+virtual address")
        for line in out.splitlines():
            ms = re_sec.match(line)
            if ms:
                cur_sec = int(ms.group(1))
                continue
            if cur_sec is not None:
                mv = re_va.match(line)
                if mv:
                    self.section_rvas[cur_sec] = int(mv.group(1), 16)
                    cur_sec = None

    def _type_size(self, tid: int, depth: int = 0) -> int | None:
        if depth > 12:
            return None
        if tid in self.tid_size:
            return self.tid_size[tid]
        # CodeView built-in near32 pointer range (0x0400..0x06FF)
        if 0x0400 <= tid <= 0x06FF:
            return 4
        if tid in self.tid_modifier_underlying:
            return self._type_size(self.tid_modifier_underlying[tid], depth + 1)
        if tid in self.tid_array:
            return self.tid_array[tid][1]
        if tid in self.tid_name:
            full_tid = self.struct_name_to_tid.get(self.tid_name[tid])
            if full_tid is not None and full_tid != tid:
                return self._type_size(full_tid, depth + 1)
        return None

    def _unwrap_modifier(self, tid: int) -> int:
        seen: set[int] = set()
        while tid in self.tid_modifier_underlying and tid not in seen:
            seen.add(tid)
            tid = self.tid_modifier_underlying[tid]
        return tid

    def _load_types(self) -> None:
        out = _run_tool(["llvm-pdbutil", "dump", "--types", str(self.pdb_path)])
        fieldlist_members: dict[int, dict[str, tuple[int, int]]] = {}
        fieldlist_bases: dict[int, list[tuple[int, int]]] = {}
        fieldlist_methods: dict[int, dict[str, int | None]] = {}
        fieldlist_overloads: dict[int, list[tuple[str, int]]] = {}
        methodlists: dict[int, list[int]] = {}
        pending_structs: list[tuple[int, str, int, int]] = []  # (tid, name, fl_tid, size)

        re_tid = re.compile(r"^\s*0x([0-9A-Fa-f]+)\s*\|\s*(LF_\w+)\s+\[size = \d+\](?:\s+`(.*)`)?")
        re_fl = re.compile(r"field list:\s*0x([0-9A-Fa-f]+)")
        re_sz = re.compile(r"sizeof\s+(\d+)")
        re_mem = re.compile(r"-\s+LF_MEMBER\s+\[name = `([^`]+)`,\s*Type = 0x([0-9A-Fa-f]+)[^,]*,\s*offset = (\d+)")
        re_bclass = re.compile(r"-\s+LF_BCLASS\s+\[type = 0x([0-9A-Fa-f]+)[^,]*,\s*offset = (\d+)")
        re_onemethod = re.compile(r"-\s+LF_ONEMETHOD\s+\[name = `([^`]+)`")
        re_method = re.compile(r"-\s+LF_METHOD\s+\[name = `([^`]+)`.*overload list = 0x([0-9A-Fa-f]+)")
        re_voff = re.compile(r"vftable offset = (-?\d+)")
        re_arr = re.compile(r"size:\s*(\d+),\s*index type:\s*0x[0-9A-Fa-f]+.*element type:\s*0x([0-9A-Fa-f]+)")
        re_mod = re.compile(r"referent = 0x([0-9A-Fa-f]+)")
        re_ml_voff = re.compile(r"vftable offset = (-?\d+)")

        cur_tid: int | None = None
        cur_kind: str | None = None
        cur_name: str | None = None
        cur_fwd = False
        cur_fl: int | None = None
        cur_sz = 0
        cur_method_name: str | None = None

        def flush() -> None:
            if cur_tid is None:
                return
            if cur_kind in ("LF_STRUCTURE", "LF_CLASS", "LF_UNION") and cur_name:
                self.tid_name[cur_tid] = cur_name
                if not cur_fwd:
                    self.tid_size[cur_tid] = cur_sz
                    if cur_fl is not None:
                        pending_structs.append((cur_tid, cur_name, cur_fl, cur_sz))
            elif cur_kind in ("LF_POINTER", "LF_ENUM"):
                self.tid_size[cur_tid] = 4

        for line in out.splitlines():
            mt = re_tid.match(line)
            if mt:
                flush()
                cur_tid = int(mt.group(1), 16)
                cur_kind = mt.group(2)
                cur_name = mt.group(3)
                cur_fwd = False
                cur_fl = None
                cur_sz = 0
                cur_method_name = None
                if cur_kind == "LF_FIELDLIST":
                    fieldlist_members[cur_tid] = {}
                    fieldlist_bases[cur_tid] = []
                    fieldlist_methods[cur_tid] = {}
                    fieldlist_overloads[cur_tid] = []
                elif cur_kind == "LF_METHODLIST":
                    methodlists[cur_tid] = []
                continue

            if cur_tid is None:
                continue
            if cur_kind in ("LF_STRUCTURE", "LF_CLASS", "LF_UNION"):
                if "forward ref" in line:
                    cur_fwd = True
                mfl = re_fl.search(line)
                if mfl:
                    cur_fl = int(mfl.group(1), 16)
                msz = re_sz.search(line)
                if msz:
                    cur_sz = int(msz.group(1))
            elif cur_kind == "LF_ARRAY":
                ma = re_arr.search(line)
                if ma:
                    total_bytes = int(ma.group(1))
                    elem_tid = int(ma.group(2), 16)
                    self.tid_array[cur_tid] = (elem_tid, total_bytes)
                    self.tid_size[cur_tid] = total_bytes
            elif cur_kind == "LF_MODIFIER":
                mm = re_mod.search(line)
                if mm:
                    self.tid_modifier_underlying[cur_tid] = int(mm.group(1), 16)
            elif cur_kind == "LF_METHODLIST":
                mv = re_ml_voff.search(line)
                if mv:
                    voff = int(mv.group(1))
                    if voff >= 0:
                        methodlists[cur_tid].append(voff)
            elif cur_kind == "LF_FIELDLIST":
                mm = re_mem.search(line)
                if mm:
                    fieldlist_members[cur_tid][mm.group(1)] = (int(mm.group(3)), int(mm.group(2), 16))
                    cur_method_name = None
                    continue
                mb = re_bclass.search(line)
                if mb:
                    fieldlist_bases[cur_tid].append((int(mb.group(1), 16), int(mb.group(2))))
                    cur_method_name = None
                    continue
                mo = re_onemethod.search(line)
                if mo:
                    cur_method_name = mo.group(1)
                    fieldlist_methods[cur_tid].setdefault(cur_method_name, None)
                    continue
                ml = re_method.search(line)
                if ml:
                    cur_method_name = None
                    fieldlist_overloads[cur_tid].append((ml.group(1), int(ml.group(2), 16)))
                    continue
                if cur_method_name is not None:
                    mv = re_voff.search(line)
                    if mv:
                        voff = int(mv.group(1))
                        if voff >= 0:
                            fieldlist_methods[cur_tid][cur_method_name] = voff
                        cur_method_name = None

        flush()

        # Resolve structs, merge methodlists & base classes
        struct_fl: dict[int, int] = {}
        for tid, sname, fl_tid, ssz in pending_structs:
            mems = dict(fieldlist_members.get(fl_tid, {}))
            meths = dict(fieldlist_methods.get(fl_tid, {}))
            for mname, mlist_tid in fieldlist_overloads.get(fl_tid, []):
                voffs = methodlists.get(mlist_tid, [])
                if voffs:
                    meths.setdefault(mname, voffs[0])
                else:
                    meths.setdefault(mname, None)
            self.struct_members[tid] = mems
            self.struct_methods[tid] = meths
            struct_fl[tid] = fl_tid

            prev_tid = self.struct_name_to_tid.get(sname)
            if prev_tid is None or (len(mems) + len(meths)) > (
                len(self.struct_members.get(prev_tid, {})) + len(self.struct_methods.get(prev_tid, {}))
            ):
                self.struct_name_to_tid[sname] = tid

        # Map forward-ref base TIDs by name if needed, then propagate bases
        for _ in range(4):
            for tid, fl_tid in struct_fl.items():
                for base_tid, boff in fieldlist_bases.get(fl_tid, []):
                    resolved_base = base_tid
                    if resolved_base not in self.struct_members and resolved_base in self.tid_name:
                        resolved_base = self.struct_name_to_tid.get(self.tid_name[resolved_base], resolved_base)
                    for mname, (moff, mtid) in self.struct_members.get(resolved_base, {}).items():
                        self.struct_members[tid].setdefault(mname, (boff + moff, mtid))
                    for fn, voff in self.struct_methods.get(resolved_base, {}).items():
                        if fn not in self.struct_methods[tid] or (
                            self.struct_methods[tid][fn] is None and voff is not None
                        ):
                            self.struct_methods[tid][fn] = voff

        # Register *_s -> *_t aliases and leaf class names (e.g. vgui2::ISurface -> ISurface)
        for sname, tid in list(self.struct_name_to_tid.items()):
            if sname.endswith("_s"):
                self.struct_name_to_tid.setdefault(sname[:-2] + "_t", tid)
            if "::" in sname:
                self.struct_name_to_tid.setdefault(sname.split("::")[-1], tid)

    def _load_symbols_and_publics(self) -> None:
        # 1) Module symbols give exact proc RVA + size + prototype, and module-local static variables (S_LDATA32)
        sym_out = _run_tool(["llvm-pdbutil", "dump", "--symbols", str(self.pdb_path)])
        re_any_rec = re.compile(r"^\s*(?:\d+\s*\|\s*(S_\w+)|Mod\s+\d+\s*\|)")
        re_rec = re.compile(
            r"^\s*\d+\s*\|\s*(S_GPROC32|S_LPROC32|S_GPROC32_ID|S_LPROC32_ID|S_GDATA32|S_LDATA32|S_END)\s+\[size = \d+\](?:\s+`(.*)`)?"
        )
        re_addr = re.compile(r"addr = (\d+):(\d+)")
        re_codesize = re.compile(r"code size = (\d+)")
        re_dtype = re.compile(r"type = `?0x([0-9A-Fa-f]+)(?:\s*\((.*)\))?")

        proc_stack: list[str] = []
        pending_kind: str | None = None
        pending_name: str | None = None
        pending_rva: int | None = None
        pending_size = 0
        pending_dtype: int | None = None
        pending_proto = ""
        seen_funcs: set[tuple[str, int]] = set()
        seen_datas: set[tuple[str, int]] = set()

        def flush_sym() -> None:
            nonlocal pending_kind, pending_name, pending_rva, pending_size, pending_dtype, pending_proto
            if pending_kind and pending_name and pending_rva is not None:
                if pending_kind in ("S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"):
                    key = (pending_name, pending_rva)
                    if key not in seen_funcs:
                        seen_funcs.add(key)
                        self.funcs_by_name[pending_name].append(
                            SymbolEntry(pending_name, pending_name, pending_rva, pending_size, prototype=pending_proto)
                        )
                elif pending_kind in ("S_GDATA32", "S_LDATA32"):
                    names_to_reg = [pending_name]
                    if proc_stack:
                        names_to_reg.append(f"{proc_stack[-1]}::{pending_name}")
                    for reg in names_to_reg:
                        key = (reg, pending_rva)
                        if key not in seen_datas:
                            seen_datas.add(key)
                            self.globals_by_name[reg].append(SymbolEntry(reg, pending_name, pending_rva, 0))
                        if pending_dtype is not None and (
                            reg not in self.global_type_tids
                            or (
                                self._unwrap_modifier(pending_dtype) in self.tid_array
                                and self._unwrap_modifier(self.global_type_tids[reg]) not in self.tid_array
                            )
                        ):
                            self.global_type_tids[reg] = pending_dtype
            pending_kind = None
            pending_name = None
            pending_rva = None
            pending_size = 0
            pending_dtype = None
            pending_proto = ""

        for line in sym_out.splitlines():
            m_any = re_any_rec.match(line)
            if m_any:
                flush_sym()
                if line.lstrip().startswith("Mod "):
                    proc_stack.clear()
                    continue
                mr = re_rec.match(line)
                if not mr:
                    continue
                kind, name = mr.group(1), mr.group(2)
                if kind == "S_END":
                    if proc_stack:
                        proc_stack.pop()
                    continue
                if kind in ("S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"):
                    proc_stack.append(name or "")
                pending_kind = kind
                pending_name = name
                continue
            if pending_kind is None:
                continue
            ma = re_addr.search(line)
            if ma and pending_rva is None:
                pending_rva = self._sec_off_to_rva(int(ma.group(1)), int(ma.group(2)))
            mc = re_codesize.search(line)
            if mc:
                pending_size = int(mc.group(1))
            mt = re_dtype.search(line)
            if mt:
                pending_dtype = int(mt.group(1), 16)
                if mt.group(2):
                    pending_proto = mt.group(2).rstrip("`")
        flush_sym()

        # 2) Public symbols & globals for vtables (??_7...) and fallback C/C++ publics
        pub_out = _run_tool(["llvm-pdbutil", "dump", "--publics", "--globals", str(self.pdb_path)])
        re_pub = re.compile(r"^\s*\d+\s*\|\s*(S_PUB32|S_GDATA32|S_LDATA32)\s+\[size = \d+\]\s+`(.*)`\s*$")
        raw_vtables: list[tuple[str, int]] = []
        raw_cpp_pub_funcs: list[tuple[str, int]] = []
        cur_k: str | None = None
        cur_n: str | None = None
        cur_t: int | None = None

        for line in pub_out.splitlines():
            if re_any_rec.match(line):
                mp = re_pub.match(line)
                if mp:
                    cur_k, cur_n, cur_t = mp.group(1), mp.group(2), None
                else:
                    cur_k, cur_n, cur_t = None, None, None
                continue
            if cur_k is None or cur_n is None:
                continue
            mt = re_dtype.search(line)
            if mt:
                cur_t = int(mt.group(1), 16)
            ma = re_addr.search(line)
            if ma:
                rva = self._sec_off_to_rva(int(ma.group(1)), int(ma.group(2)))
                if rva is not None:
                    if cur_k == "S_PUB32":
                        if cur_n.startswith("??_7"):
                            raw_vtables.append((cur_n, rva))
                        elif (
                            cur_n.startswith("?")
                            and "flags = function" in line
                            and not cur_n.startswith(("??_C@", "??_R"))
                        ):
                            raw_cpp_pub_funcs.append((cur_n, rva))
                        elif cur_n.startswith("_") and not cur_n.startswith("__"):
                            plain = cur_n[1:].split("@")[0]
                            if "flags = function" in line:
                                if (plain, rva) not in seen_funcs:
                                    seen_funcs.add((plain, rva))
                                    self.funcs_by_name[plain].append(SymbolEntry(plain, cur_n, rva, 0))
                            else:
                                if (plain, rva) not in seen_datas:
                                    seen_datas.add((plain, rva))
                                    self.globals_by_name[plain].append(SymbolEntry(plain, cur_n, rva, 0))
                    else:
                        if (cur_n, rva) not in seen_datas:
                            seen_datas.add((cur_n, rva))
                            self.globals_by_name[cur_n].append(SymbolEntry(cur_n, cur_n, rva, 0))
                        if cur_t is not None and (
                            cur_n not in self.global_type_tids
                            or (
                                self._unwrap_modifier(cur_t) in self.tid_array
                                and self._unwrap_modifier(self.global_type_tids[cur_n]) not in self.tid_array
                            )
                        ):
                            self.global_type_tids[cur_n] = cur_t
                cur_k = None
                cur_n = None

        # Enrich truncated PDB procedure prototypes using full undname of S_PUB32 C++ functions
        if raw_cpp_pub_funcs:
            und_map = _batch_llvm_undname([m for m, _ in raw_cpp_pub_funcs])
            rva_to_full_proto: dict[int, str] = {}
            for mangled, rva in raw_cpp_pub_funcs:
                dem = und_map.get(mangled)
                if dem:
                    rva_to_full_proto[rva] = dem
            for fname, entries in list(self.funcs_by_name.items()):
                updated = []
                for ent in entries:
                    full_p = rva_to_full_proto.get(ent.rva)
                    if full_p and ("..." in ent.prototype or not ent.prototype):
                        updated.append(SymbolEntry(ent.name, ent.mangled, ent.rva, ent.size, ent.is_import, full_p))
                    else:
                        updated.append(ent)
                self.funcs_by_name[fname] = updated

        if raw_vtables:
            und_vt = _batch_llvm_undname([m for m, _ in raw_vtables])
            for mangled, rva in raw_vtables:
                demangled = und_vt.get(mangled, "")
                vm = re.search(r"const\s+([A-Za-z0-9_:<>]+)::[`']vftable'(?:\{for\s+[`']([^']+)'\})?", demangled)
                if vm:
                    cls = vm.group(1)
                    if cls not in self.vtables_by_class or vm.group(2) is None:
                        self.vtables_by_class[cls] = (mangled, rva)
                mm_vt = re.match(r"^\?\?_7([A-Za-z0-9_@]+)@@6B@$", mangled)
                if mm_vt:
                    parts = [p for p in mm_vt.group(1).split("@") if p]
                    cls_direct = "::".join(reversed(parts))
                    self.vtables_by_class.setdefault(cls_direct, (mangled, rva))

    def _resolve_struct_tid(self, struct_name: str, *, global_type_hint: str | None = None) -> int | None:
        if global_type_hint and global_type_hint in self.global_type_tids:
            tid = self._unwrap_modifier(self.global_type_tids[global_type_hint])
            if tid in self.struct_members:
                return tid
        for cand in (struct_name, struct_name[:-2] + "_s" if struct_name.endswith("_t") else ""):
            if cand and cand in self.struct_name_to_tid:
                return self.struct_name_to_tid[cand]
        # Normalized template whitespace match (e.g. CUtlVector<gltexture_t>)
        compact = struct_name.replace(" ", "")
        for sname, tid in self.struct_name_to_tid.items():
            if sname.replace(" ", "") == compact or sname.replace(" ", "").startswith(compact[:-1] + ","):
                return tid
        return None

    def find_funcs(self, name: str, *, allow_import: bool = False) -> list[SymbolEntry]:
        del allow_import
        return list(self.funcs_by_name.get(name, ()))

    def find_func_parts(self, base_name: str) -> list[SymbolEntry]:
        return []

    def find_globals(self, name: str) -> list[SymbolEntry]:
        return list(self.globals_by_name.get(name, ()))

    def find_vtable(self, class_name: str) -> tuple[str, int] | None:
        return self.vtables_by_class.get(class_name)

    def find_vfunc_slot(self, class_name: str, method_name: str) -> int | None:
        tid = self._resolve_struct_tid(class_name)
        if tid is None:
            return None
        voff = self.struct_methods.get(tid, {}).get(method_name)
        if voff is None or voff < 0 or voff % 4 != 0:
            return None
        return voff // 4

    def resolve_struct_size(self, struct_name: str) -> int | None:
        tid = self._resolve_struct_tid(struct_name)
        return None if tid is None else self._type_size(tid)

    def resolve_field_path(
        self, struct_name: str, field_path: list[str], *, global_type_hint: str | None = None
    ) -> FieldResolution | None:
        cur_tid = self._resolve_struct_tid(struct_name, global_type_hint=global_type_hint)
        if cur_tid is None or not field_path:
            return None
        total_offset = 0
        last_tid = cur_tid
        for idx, field in enumerate(field_path):
            cur_tid = self._unwrap_modifier(cur_tid)
            if cur_tid in self.tid_array:
                cur_tid = self._unwrap_modifier(self.tid_array[cur_tid][0])
            mems = self.struct_members.get(cur_tid)
            if not mems or field not in mems:
                return None
            moff, mtid = mems[field]
            total_offset += moff
            last_tid = self._unwrap_modifier(mtid)
            if idx < len(field_path) - 1:
                cur_tid = last_tid
                if cur_tid not in self.struct_members and cur_tid in self.tid_name:
                    cur_tid = self.struct_name_to_tid.get(self.tid_name[cur_tid], cur_tid)
                elif cur_tid in self.tid_array:
                    elem_tid = self._unwrap_modifier(self.tid_array[cur_tid][0])
                    if elem_tid not in self.struct_members and elem_tid in self.tid_name:
                        elem_tid = self.struct_name_to_tid.get(self.tid_name[elem_tid], elem_tid)
                    cur_tid = elem_tid

        arr_layout = None
        if last_tid in self.tid_array:
            elem_tid, total_bytes = self.tid_array[last_tid]
            elem_tid = self._unwrap_modifier(elem_tid)
            elem_sz = self._type_size(elem_tid) or 0
            if elem_sz == 0 and elem_tid in self.tid_name:
                full_tid = self.struct_name_to_tid.get(self.tid_name[elem_tid])
                if full_tid is not None:
                    elem_sz = self._type_size(full_tid) or 0
            count = total_bytes // elem_sz if elem_sz > 0 else 0
            arr_layout = ArrayLayout(self.tid_name.get(elem_tid, ""), elem_sz, count, total_bytes)

        return FieldResolution(
            offset=total_offset,
            size=self._type_size(last_tid),
            type_name=self.tid_name.get(last_tid, ""),
            array=arr_layout,
        )

    def resolve_global_array(self, global_name: str) -> ArrayLayout | None:
        tid = self.global_type_tids.get(global_name)
        if tid is None:
            return None
        tid = self._unwrap_modifier(tid)
        if tid not in self.tid_array:
            return None
        elem_tid, total_bytes = self.tid_array[tid]
        elem_tid = self._unwrap_modifier(elem_tid)
        elem_name = self.tid_name.get(elem_tid, "")
        elem_sz = self._type_size(elem_tid) or 0
        if elem_sz == 0 and elem_name:
            elem_sz = self.resolve_struct_size(elem_name) or 0
        if elem_sz <= 0:
            return None
        return ArrayLayout(elem_name, elem_sz, total_bytes // elem_sz, total_bytes)


@dataclass
class _DwarfStruct:
    name: str
    die_offset: int
    size: int
    members: dict[str, tuple[int, int | None, str]]  # name -> (offset, type_die, type_str)
    methods: dict[str, int | None]  # name -> vtable_slot_index
    bases: list[tuple[int | None, str, int]]  # (base_die, base_name, offset)


class ElfDwarfDebugIndex(BaseDebugIndex):
    """Offline indexer backed by llvm-readelf, c++filt, and targeted llvm-dwarfdump."""

    platform = "linux"

    def __init__(self, so_path: Path, dwarf_path: Path | None = None) -> None:
        self.so_path = Path(so_path)
        self.dwarf_path = Path(dwarf_path) if dwarf_path else self.so_path

        self.funcs_by_name: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.func_parts_by_base: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.imports_by_name: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.globals_by_name: dict[str, list[SymbolEntry]] = collections.defaultdict(list)
        self.vtables_by_class: dict[str, tuple[str, int]] = {}

        self._struct_cache: dict[str, _DwarfStruct | None] = {}
        self._die_cache: dict[int, _DwarfStruct | None] = {}
        self._global_var_type_cache: dict[str, tuple[int | None, str] | None] = {}

        self._load_elf_symbols()

    def _load_elf_symbols(self) -> None:
        out = _run_tool(["llvm-readelf", "-s", "--wide", str(self.so_path)])
        re_sym = re.compile(
            r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+|0x[0-9a-fA-F]+)\s+(FUNC|OBJECT|NOTYPE)\s+\w+\s+\w+\s+(\S+)\s+(\S+)"
        )
        parsed: list[tuple[int, int, str, str, str]] = []
        for line in out.splitlines():
            m = re_sym.match(line)
            if not m:
                continue
            rva = int(m.group(1), 16)
            size = int(m.group(2), 0)
            stype = m.group(3)
            ndx = m.group(4)
            mangled = m.group(5).split("@", 1)[0]
            if mangled.endswith(".localalias"):
                continue
            parsed.append((rva, size, stype, ndx, mangled))

        unique_mangled = sorted({row[4] for row in parsed})
        demangled_map: dict[str, str] = {}
        for i in range(0, len(unique_mangled), 4000):
            chunk = unique_mangled[i : i + 4000]
            res = _run_tool(["c++filt"], input_text="\n".join(chunk) + "\n", check=False)
            for src, dst in zip(chunk, res.splitlines()):
                demangled_map[src] = dst.strip()

        seen_funcs: set[tuple[str, int]] = set()
        seen_objs: set[tuple[str, int]] = set()
        for rva, size, stype, ndx, mangled in parsed:
            dem = demangled_map.get(mangled, mangled)
            if ndx == "UND":
                if stype == "FUNC":
                    short = strip_cpp_params(dem)
                    entry = SymbolEntry(short, mangled, 0, 0, is_import=True)
                    self.imports_by_name[short].append(entry)
                    if mangled != short:
                        self.imports_by_name[mangled].append(entry)
                continue

            if stype == "FUNC":
                if re.search(r"\.(?:part|cold|isra|constprop)\.\d+$", mangled) or "[clone " in dem:
                    base = strip_cpp_params(dem)
                    self.func_parts_by_base[base].append(SymbolEntry(dem, mangled, rva, size, prototype=dem))
                    continue
                short = strip_cpp_params(dem)
                for key_name in dict.fromkeys((short, dem, mangled)):
                    if (key_name, rva) not in seen_funcs:
                        seen_funcs.add((key_name, rva))
                        self.funcs_by_name[key_name].append(SymbolEntry(short, mangled, rva, size, prototype=dem))
            elif stype == "OBJECT":
                if dem.startswith("vtable for "):
                    cls = dem[len("vtable for ") :].strip()
                    self.vtables_by_class[cls] = (mangled, rva)
                short = strip_cpp_params(dem)
                for key_name in dict.fromkeys((short, dem, mangled)):
                    if (key_name, rva) not in seen_objs:
                        seen_objs.add((key_name, rva))
                        self.globals_by_name[key_name].append(SymbolEntry(short, mangled, rva, size))

    def _parse_dwarf_structs_from_dump(self, text: str, wanted_name: str | None = None) -> list[_DwarfStruct]:
        results: list[_DwarfStruct] = []
        in_struct = False
        struct_depth = 0
        nested_skip_depth: int | None = None
        struct_die = 0
        struct_name = ""
        struct_size = 0
        struct_decl = False
        cur_tag = ""
        members: dict[str, tuple[int, int | None, str]] = {}
        methods: dict[str, int | None] = {}
        bases: list[tuple[int | None, str, int]] = []

        item_name: str | None = None
        item_off: int | None = None
        item_type_die: int | None = None
        item_type_str = ""
        item_vloc: int | None = None

        def flush_item() -> None:
            nonlocal item_name, item_off, item_type_die, item_type_str, item_vloc
            if cur_tag == "DW_TAG_member" and item_name is not None and item_off is not None:
                members[item_name] = (item_off, item_type_die, item_type_str)
            elif cur_tag == "DW_TAG_subprogram" and item_name is not None:
                if item_name not in methods or (methods[item_name] is None and item_vloc is not None):
                    methods[item_name] = item_vloc
            elif cur_tag == "DW_TAG_inheritance":
                bases.append((item_type_die, item_type_str, item_off or 0))
            item_name = None
            item_off = None
            item_type_die = None
            item_type_str = ""
            item_vloc = None

        def flush_struct() -> None:
            nonlocal in_struct, nested_skip_depth
            flush_item()
            if (
                in_struct
                and not struct_decl
                and (members or methods or bases or struct_size > 0)
                and (wanted_name is None or struct_name == wanted_name or struct_name.endswith("::" + wanted_name))
            ):
                results.append(
                    _DwarfStruct(
                        name=struct_name,
                        die_offset=struct_die,
                        size=struct_size,
                        members=dict(members),
                        methods=dict(methods),
                        bases=list(bases),
                    )
                )
            in_struct = False
            nested_skip_depth = None

        re_tag = re.compile(r"^0x([0-9a-fA-F]+):(\s+)(DW_TAG_\w+)")
        re_name = re.compile(r'DW_AT_name\s+\("([^"]+)"\)')
        re_sz = re.compile(r"DW_AT_byte_size\s+\((0x[0-9a-fA-F]+|\d+)\)")
        re_loc = re.compile(r"DW_AT_data_member_location\s+\((0x[0-9a-fA-F]+|\d+)\)")
        re_type = re.compile(r'DW_AT_type\s+\(0x([0-9a-fA-F]+)\s+"([^"]*)"\)')
        re_vloc = re.compile(r"DW_AT_vtable_elem_location\s+\((?:DW_OP_constu\s+(0x[0-9a-fA-F]+|\d+)|DW_OP_lit(\d+))\)")

        for line in text.splitlines():
            mt = re_tag.match(line)
            if mt:
                die = int(mt.group(1), 16)
                depth = len(mt.group(2))
                tag = mt.group(3)
                if nested_skip_depth is not None and depth <= nested_skip_depth:
                    nested_skip_depth = None
                if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    if in_struct and depth <= struct_depth:
                        flush_struct()
                    if not in_struct:
                        in_struct = True
                        struct_depth = depth
                        struct_die = die
                        struct_name = ""
                        struct_size = 0
                        struct_decl = False
                        cur_tag = tag
                        members = {}
                        methods = {}
                        bases = []
                    else:
                        flush_item()
                        cur_tag = ""
                        nested_skip_depth = depth
                elif in_struct and depth <= struct_depth:
                    flush_struct()
                elif in_struct and nested_skip_depth is None:
                    if tag in ("DW_TAG_member", "DW_TAG_subprogram", "DW_TAG_inheritance"):
                        flush_item()
                        cur_tag = tag
                    elif tag not in ("DW_TAG_formal_parameter", "DW_TAG_template_type_parameter"):
                        flush_item()
                        cur_tag = ""
                continue

            if not in_struct or nested_skip_depth is not None:
                continue
            if cur_tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                if "DW_AT_declaration" in line:
                    struct_decl = True
                mn = re_name.search(line)
                if mn and not struct_name:
                    struct_name = mn.group(1)
                ms = re_sz.search(line)
                if ms:
                    struct_size = int(ms.group(1), 0)
            elif cur_tag in ("DW_TAG_member", "DW_TAG_inheritance"):
                mn = re_name.search(line)
                if mn:
                    item_name = mn.group(1)
                ml = re_loc.search(line)
                if ml:
                    item_off = int(ml.group(1), 0)
                mty = re_type.search(line)
                if mty:
                    item_type_die = int(mty.group(1), 16)
                    item_type_str = mty.group(2)
            elif cur_tag == "DW_TAG_subprogram":
                mn = re_name.search(line)
                if mn:
                    item_name = mn.group(1)
                mv = re_vloc.search(line)
                if mv:
                    item_vloc = int(mv.group(1), 0) if mv.group(1) is not None else int(mv.group(2), 10)

        if in_struct:
            flush_struct()
        return results

    def _merge_bases(self, st: _DwarfStruct, depth: int = 0) -> _DwarfStruct:
        if depth > 4 or not st.bases:
            return st
        merged_mems = dict(st.members)
        merged_meths = dict(st.methods)
        for base_die, base_name, boff in st.bases:
            base_st = self._get_struct_by_die(base_die) if base_die else self._get_struct(base_name)
            if base_st is None and base_name:
                base_st = self._get_struct(base_name)
            if base_st is None:
                continue
            base_st = self._merge_bases(base_st, depth + 1)
            for mn, (moff, mdie, mstr) in base_st.members.items():
                merged_mems.setdefault(mn, (boff + moff, mdie, mstr))
            for fn, vloc in base_st.methods.items():
                if fn not in merged_meths or (merged_meths[fn] is None and vloc is not None):
                    merged_meths[fn] = vloc
        return _DwarfStruct(st.name, st.die_offset, st.size, merged_mems, merged_meths, st.bases)

    def _get_struct_by_die(self, die_offset: int) -> _DwarfStruct | None:
        if die_offset in self._die_cache:
            return self._die_cache[die_offset]
        out = _run_tool(
            ["llvm-dwarfdump", f"--debug-info={hex(die_offset)}", "--show-children", str(self.dwarf_path)],
            check=False,
        )
        # Follow typedef / array / const indirections if die is not directly a struct
        first_tag = re.search(r"^0x[0-9a-fA-F]+:\s+(DW_TAG_\w+)", out, re.MULTILINE)
        if first_tag and first_tag.group(1) in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_array_type"):
            mty = re.search(r'DW_AT_type\s+\(0x([0-9a-fA-F]+)\s+"([^"]*)"\)', out)
            if mty:
                res = self._get_struct_by_die(int(mty.group(1), 16))
                self._die_cache[die_offset] = res
                return res
        parsed = self._parse_dwarf_structs_from_dump(out)
        chosen = self._merge_bases(parsed[0]) if parsed else None
        self._die_cache[die_offset] = chosen
        return chosen

    def _get_global_var_type(self, global_name: str) -> tuple[int | None, str] | None:
        if global_name in self._global_var_type_cache:
            return self._global_var_type_cache[global_name]
        out = _run_tool(["llvm-dwarfdump", f"--name={global_name}", str(self.dwarf_path)], check=False)
        blocks = re.split(r"(?=^0x[0-9a-fA-F]+:\s+DW_TAG_)", out, flags=re.MULTILINE)
        fallback: tuple[int | None, str] | None = None
        for blk in blocks:
            if "DW_TAG_variable" not in blk:
                continue
            mty = re.search(r'DW_AT_type\s+\(0x([0-9a-fA-F]+)\s+"([^"]*)"\)', blk)
            if not mty:
                continue
            cand = (int(mty.group(1), 16), mty.group(2))
            is_decl = "DW_AT_declaration" in blk
            has_array_len = bool(re.search(r"\[\d+\]$", cand[1].strip()))
            if not is_decl and has_array_len:
                self._global_var_type_cache[global_name] = cand
                return cand
            if fallback is None:
                fallback = cand
        self._global_var_type_cache[global_name] = fallback
        return fallback

    def _get_struct(self, struct_name: str, *, global_type_hint: str | None = None) -> _DwarfStruct | None:
        cache_key = f"{struct_name}|{global_type_hint or ''}"
        if cache_key in self._struct_cache:
            return self._struct_cache[cache_key]

        if global_type_hint:
            vt = self._get_global_var_type(global_type_hint)
            if vt and vt[0] is not None:
                st = self._get_struct_by_die(vt[0])
                if st is not None:
                    self._struct_cache[cache_key] = st
                    return st

        candidates: list[str] = [struct_name]
        if struct_name.endswith("_t"):
            candidates.append(struct_name[:-2] + "_s")
        if "::" in struct_name:
            candidates.append(struct_name.split("::")[-1])

        for cand in candidates:
            out = _run_tool(["llvm-dwarfdump", f"--name={cand}", "--show-children", str(self.dwarf_path)], check=False)
            if not out.strip():
                continue
            parsed = self._parse_dwarf_structs_from_dump(out, wanted_name=cand)
            if not parsed:
                # Try resolving typedefs (e.g. client_dll_callbacks_t -> struct ...)
                for blk in re.split(r"(?=^0x[0-9a-fA-F]+:\s+DW_TAG_)", out, flags=re.MULTILINE):
                    if "DW_TAG_typedef" in blk:
                        mty = re.search(r'DW_AT_type\s+\(0x([0-9a-fA-F]+)\s+"([^"]*)"\)', blk)
                        if mty:
                            st = self._get_struct_by_die(int(mty.group(1), 16))
                            if st is not None:
                                self._struct_cache[cache_key] = st
                                return st
                continue
            best = max(parsed, key=lambda s: (len(s.members) + len(s.methods), s.size))
            best = self._merge_bases(best)
            self._struct_cache[cache_key] = best
            return best

        self._struct_cache[cache_key] = None
        return None

    def _size_from_type_str(self, type_die: int | None, type_str: str) -> int | None:
        clean = type_str.replace("const ", "").replace("volatile ", "").strip()
        if clean.endswith("*") or "(*)" in clean:
            return 4
        prim = {
            "bool": 1,
            "char": 1,
            "signed char": 1,
            "unsigned char": 1,
            "byte": 1,
            "short": 2,
            "short int": 2,
            "unsigned short": 2,
            "short unsigned int": 2,
            "int": 4,
            "unsigned int": 4,
            "long int": 4,
            "long unsigned int": 4,
            "float": 4,
            "qboolean": 4,
            "double": 8,
            "long long int": 8,
            "long long unsigned int": 8,
        }
        if clean in prim:
            return prim[clean]
        m_arr = re.match(r"^(.+?)\[(\d+)\]$", clean)
        if m_arr:
            elem_sz = self._size_from_type_str(None, m_arr.group(1).strip())
            if elem_sz is not None:
                return elem_sz * int(m_arr.group(2))
        if type_die is not None:
            st = self._get_struct_by_die(type_die)
            if st is not None and st.size > 0:
                return st.size
        if clean:
            st = self._get_struct(clean)
            if st is not None and st.size > 0:
                return st.size
        return None

    def find_funcs(self, name: str, *, allow_import: bool = False) -> list[SymbolEntry]:
        hits = list(self.funcs_by_name.get(name, ()))
        if not hits and allow_import:
            hits = list(self.imports_by_name.get(name, ()))
        return hits

    def find_func_parts(self, base_name: str) -> list[SymbolEntry]:
        return list(self.func_parts_by_base.get(base_name, ()))

    def find_globals(self, name: str) -> list[SymbolEntry]:
        return list(self.globals_by_name.get(name, ()))

    def find_vtable(self, class_name: str) -> tuple[str, int] | None:
        return self.vtables_by_class.get(class_name)

    def find_vfunc_slot(self, class_name: str, method_name: str) -> int | None:
        st = self._get_struct(class_name)
        if st is None:
            return None
        slot = st.methods.get(method_name)
        if slot is None:
            return None
        return slot

    def resolve_struct_size(self, struct_name: str) -> int | None:
        st = self._get_struct(struct_name)
        return None if st is None else st.size

    def resolve_field_path(
        self, struct_name: str, field_path: list[str], *, global_type_hint: str | None = None
    ) -> FieldResolution | None:
        st = self._get_struct(struct_name, global_type_hint=global_type_hint)
        if st is None or not field_path:
            return None
        total_offset = 0
        leaf_die: int | None = None
        leaf_type_str = ""
        for idx, field in enumerate(field_path):
            if field not in st.members:
                return None
            moff, mdie, mstr = st.members[field]
            total_offset += moff
            leaf_die, leaf_type_str = mdie, mstr
            if idx < len(field_path) - 1:
                next_st = self._get_struct_by_die(mdie) if mdie is not None else self._get_struct(mstr)
                if next_st is None:
                    base_type = re.sub(r"\[\d+\]$", "", mstr).strip()
                    next_st = self._get_struct(base_type)
                if next_st is None:
                    return None
                st = next_st

        arr_layout = None
        m_arr = re.match(r"^(.+?)\[(\d+)\]$", leaf_type_str.strip())
        if m_arr:
            elem_type = m_arr.group(1).strip()
            count = int(m_arr.group(2))
            elem_sz = self._size_from_type_str(leaf_die, elem_type) or 0
            if elem_sz > 0:
                arr_layout = ArrayLayout(elem_type, elem_sz, count, elem_sz * count)

        leaf_size = arr_layout.total_size if arr_layout else self._size_from_type_str(leaf_die, leaf_type_str)
        return FieldResolution(offset=total_offset, size=leaf_size, type_name=leaf_type_str, array=arr_layout)

    def resolve_global_array(self, global_name: str) -> ArrayLayout | None:
        vt = self._get_global_var_type(global_name)
        if not vt:
            return None
        type_die, type_str = vt
        m_arr = re.match(r"^(.+?)\[(\d+)\]$", type_str.strip())
        if not m_arr:
            return None
        elem_type = m_arr.group(1).strip()
        count = int(m_arr.group(2))
        elem_sz = self._size_from_type_str(type_die, elem_type) or 0
        if elem_sz <= 0:
            return None
        return ArrayLayout(elem_type, elem_sz, count, elem_sz * count)
