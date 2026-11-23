#!/usr/bin/env python3
"""Generate GoldSrc VibeSignatures per-symbol YAML using PDB/DWARF + IDA-MCP."""

from __future__ import annotations

import argparse
import asyncio
import collections
import datetime
import importlib.util
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

# Allow importing repository-root modules when invoked directly as `python goldsrc-reverse/generate_gamedata.py`.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from debug_providers import BaseDebugIndex, ElfDwarfDebugIndex, PdbDebugIndex, SymbolEntry

from binary_format import inspect_binary
from binary_hashing import hash_file
from gamesymbols_json import (
    DATASET_SCHEMA_VERSION,
    INDEX_SCHEMA_VERSION,
    REQUIRED_SNAPSHOT_SCHEMA_VERSION,
    _symbol_kind,
    _symbol_name,
)
from ida_analyze_bin import DATABASE_POLICY_REBUILD, IdaMcpLifecycle, _allocate_local_port
from ida_analyze_util import (
    _find_unique_bytes,
    _gv_operand_displacement,
    _gv_resolution_fields,
    _inspect_function_via_mcp,
    _inspect_llm_instruction,
    _resolve_jmp_thunk_target_via_mcp,
    parse_mcp_result,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_gv_yaml,
    write_patch_yaml,
    write_scalar_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_elf import ELF_RESOLVER_PY
from ida_mcp_session import open_ida_mcp_session
from ida_preprocessor_scripts._patch_signature_common import run_signature
from mcp_worker_client import run_mcp_operation
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes, sha256_file, write_canonical_json

# MetaHookSv runtime gamedata pruning rules (mirrors MetaHook/scripts/sync-gamedata.py).
METAHOOK_CONSUMED_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
    "function": (
        "func_rva",
        "func_size",
        "func_sig",
        "func_sig_allow_across_function_boundary",
    ),
    "global": (
        "gv_rva",
        "gv_sig",
        "gv_sig_va",
        "gv_va",
        "gv_inst_offset",
        "gv_inst_disp",
        "gv_inst_length",
        "gv_sig_allow_across_function_boundary",
    ),
    "patch": ("patch_rva",),
    "scalar": ("scalar_name", "scalar_value"),
    "structMember": ("struct_name", "member_name", "offset"),
    "virtualFunction": (
        "vfunc_index",
        "vtable_name",
        "func_rva",
        "func_size",
        "vfunc_sig",
        "func_sig",
        "vfunc_sig_allow_across_function_boundary",
        "func_sig_allow_across_function_boundary",
    ),
    "vtable": ("vtable_rva", "vtable_size", "vtable_symbol", "vtable_numvfunc"),
}
METAHOOK_CONSUMED_TOP_LEVEL_FIELDS: tuple[str, ...] = ("schemaVersion", "source", "binaries", "records")
METAHOOK_CONSUMED_SOURCE_FIELDS: tuple[str, ...] = ("snapshotSchemaVersion", "analysisOutputContractVersion")
METAHOOK_CONSUMED_RECORD_FIELDS: tuple[str, ...] = ("platform", "module", "symbolName", "kind", "payload")

# MetaHook rewrites the disp32 of a Win32 call [global]. References in
# inlined cleanup code can name the same global without invoking the callback.
WIN32_GLOBAL_CALLS_PY = r"""
import ida_bytes, idautils, json
encoding = b'\xff\x15' + TARGET_VA.to_bytes(4, 'little')
matches = []
for ea in idautils.FuncItems(OWNER_VA):
    if ida_bytes.get_item_size(ea) == len(encoding) and ida_bytes.get_bytes(ea, len(encoding)) == encoding:
        matches.append(int(ea))
result = json.dumps({'matches': matches})
"""

BATCH_GV_XREFS_PY = (
    ELF_RESOLVER_PY
    + r"""
import ida_funcs, ida_segment, ida_ua, idaapi, idautils, json
gv_items = GV_ITEMS_PLACEHOLDER
out = {}
base_xref_cache = {}

def exec_refs(target_va, limit=12):
    refs = []
    seen = set()
    for src in elf_data_refs_to(int(target_va)):
        ea = int(src)
        if ea in seen:
            continue
        seen.add(ea)
        seg = ida_segment.getseg(ea)
        if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        fn = ida_funcs.get_func(ea)
        if fn is None:
            continue
        refs.append([ea, int(fn.start_ea)])
        if len(refs) >= limit:
            break
    return refs

for item in gv_items:
    key = str(item['key'])
    gv_va = int(item['gv_va'])
    refs = exec_refs(gv_va, 12)
    # Handle array-of-struct globals accessed at element+4 / element+8 (e.g. cl_parsefuncs[i].pfn)
    if not refs and item.get('member_offset', 0) == 0:
        for delta in (4, 8):
            refs = exec_refs(gv_va + delta, 12)
            if refs:
                break
    # Handle Linux PIC aggregate subfields: base loaded from GOT, then [reg + member_offset]
    if not refs and item.get('base_va') is not None and item.get('member_offset', 0) > 0:
        base_va = int(item['base_va'])
        member_off = int(item['member_offset'])
        if base_va not in base_xref_cache:
            base_xref_cache[base_va] = exec_refs(base_va, 400)
        seen_sub = set()
        for src_ea, owner_va in base_xref_cache[base_va]:
            cursor = src_ea
            fn = ida_funcs.get_func(owner_va)
            if fn is None:
                continue
            fn_end = int(fn.end_ea)
            for _ in range(36):
                insn = idautils.DecodeInstruction(cursor)
                if not insn or insn.size <= 0:
                    break
                matched = False
                for op in insn.ops:
                    if op.type == ida_ua.o_void:
                        break
                    if op.type in (ida_ua.o_displ, ida_ua.o_phrase, ida_ua.o_mem) and int(op.addr) == member_off:
                        matched = True
                        break
                if matched and cursor not in seen_sub:
                    seen_sub.add(cursor)
                    refs.append([cursor, owner_va])
                    break
                cursor += insn.size
                if cursor >= fn_end:
                    break
            if len(refs) >= 12:
                break
    out[key] = refs
result = json.dumps(out)
"""
)

BATCH_CALLSITES_PY = r"""
import ida_funcs, ida_name, ida_segment, ida_ua, idautils, idc, json
pairs = PAIRS_PLACEHOLDER
out = {}
for key, caller_va, target_vas, target_names in pairs:
    target_set = set(int(v) for v in target_vas)
    name_set = set(target_names)
    fn = ida_funcs.get_func(int(caller_va))
    hits = []
    if fn is not None:
        caller_start = int(fn.start_ea)
        for ea in idautils.FuncItems(caller_start):
            if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
                continue
            insn = idautils.DecodeInstruction(int(ea))
            if not insn or insn.ops[0].type != ida_ua.o_near:
                continue
            dest = int(insn.ops[0].addr)
            if dest in target_set:
                hits.append(int(ea))
                continue
            # Match ELF -fPIC .plt stubs (e.g. .Cbuf_Execute, ._Z12Cbuf_Executev, .strncpy)
            dest_name = (ida_name.get_ea_name(dest) or '').lstrip('.')
            if dest_name in name_set:
                hits.append(int(ea))
                continue
            seg = ida_segment.getseg(dest)
            if seg is not None and '.plt' in (ida_segment.get_segm_name(seg) or ''):
                dem = (ida_name.demangle_name(dest_name, 0) or '').split('(', 1)[0].strip()
                if dem in name_set:
                    hits.append(int(ea))
    out[key] = sorted(set(hits))
result = json.dumps(out)
"""

FOLLOW_SINGLE_TAIL_JUMP_PY = r"""
import ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, json
def pc_thunk(callee):
    items = list(idautils.FuncItems(callee))
    if len(items) != 2:
        return False
    first = idautils.DecodeInstruction(items[0])
    return (first is not None and idc.print_insn_mnem(items[0]).lower() == 'mov'
            and first.ops[0].type == ida_ua.o_reg
            and idc.print_operand(items[0], 1).lower().replace(' ', '') in ('[esp]', '[esp+0]')
            and idc.print_insn_mnem(items[1]).lower() in ('ret', 'retn'))

target = TARGET_EA_PLACEHOLDER
seen = set()
while target not in seen:
    seen.add(target)
    fn = ida_funcs.get_func(target)
    seg = ida_segment.getseg(target)
    if not fn or int(fn.start_ea) != target or not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
        break
    calls = False
    jumps = set()
    for ea in idautils.FuncItems(target):
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        if mnem == 'call':
            insn = idautils.DecodeInstruction(int(ea))
            if not insn or insn.ops[0].type != ida_ua.o_near or not pc_thunk(int(insn.ops[0].addr)):
                calls = True
        elif mnem == 'jmp':
            insn = idautils.DecodeInstruction(int(ea))
            if not insn or insn.ops[0].type != ida_ua.o_near:
                calls = True
                continue
            dest = int(insn.ops[0].addr)
            owner = ida_funcs.get_func(dest)
            if owner and int(owner.start_ea) != target and int(owner.start_ea) == dest:
                jumps.add(dest)
    if calls or len(jumps) != 1:
        break
    target = jumps.pop()
result = json.dumps({'target': target})
"""

FIND_IMPORT_PLT_PY = r"""
import ida_bytes, ida_name, ida_segment, idaapi, json
names = NAMES_PLACEHOLDER
out = {}
for target in names:
    candidates = [f'.{target}', f'_{target}', target]
    found = None
    for cand in candidates:
        ea = ida_name.get_name_ea(idaapi.BADADDR, cand)
        if ea != idaapi.BADADDR and ida_bytes.is_loaded(ea):
            seg = ida_segment.getseg(ea)
            if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
                continue
            seg_name = (ida_segment.get_segm_name(seg) or '').lower()
            if seg_name == 'extern':
                continue
            found = int(ea)
            break
    out[target] = found
result = json.dumps(out)
"""


def load_yaml_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise TypeError(f"Expected YAML mapping in {path}")
    return dict(data)


def load_module_symbols(config_path: Path, module_name: str, platform: str) -> list[dict[str, Any]]:
    cfg = load_yaml_file(config_path)
    modules = cfg.get("modules") or []
    mod = next((m for m in modules if m.get("name") == module_name), None)
    if mod is None:
        raise ValueError(f"Module {module_name!r} not found in {config_path}")

    active: set[str] = set()
    for skill in mod.get("skills", []):
        skill_plat = skill.get("platform")
        for out in skill.get("expected_output", []):
            if skill_plat and skill_plat != platform:
                continue
            stem = out.replace(".{platform}.yaml", "")
            if stem.endswith(".windows.yaml"):
                if platform == "windows":
                    active.add(stem[: -len(".windows.yaml")])
            elif stem.endswith(".linux.yaml"):
                if platform == "linux":
                    active.add(stem[: -len(".linux.yaml")])
            else:
                active.add(stem)
        for out in skill.get(f"expected_output_{platform}", []):
            active.add(out.replace(".{platform}.yaml", "").replace(f".{platform}.yaml", ""))

    return [s for s in mod.get("symbols", []) if s.get("category") != "struct" and s.get("name") in active]


def _convention_func_candidates(name: str) -> list[str]:
    cands = [name]
    if "__" in name:
        cands.append(name.replace("__", "::"))
    if name.endswith("_ctor"):
        base = name[: -len("_ctor")]
        for sep_base in (base, base.replace("_", "::", 1)):
            cands.append(f"{sep_base}::{sep_base.split('::')[-1]}")
    if "_" in name:
        parts = name.split("_")
        if len(parts) == 2:
            cands.append(f"{parts[0]}::{parts[1]}")
        elif len(parts) >= 3:
            cands.append(f"{parts[0]}::{'_'.join(parts[1:])}")
            cands.append(f"{parts[0]}::{parts[1]}::{'_'.join(parts[2:])}")
            cands.append(f"{'_'.join(parts[:-1])}::{parts[-1]}")
    return list(dict.fromkeys(cands))


def resolve_func_entry(
    name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]
) -> tuple[SymbolEntry | None, dict[str, Any], str]:
    func_aliases = aliases.get("func_aliases") or {}
    spec = func_aliases.get(name)
    meta: dict[str, Any] = {}

    if isinstance(spec, Mapping):
        meta = dict(spec)
        if "ordered_pair" in spec:
            pair_names = spec["ordered_pair"]
            pair_idx = int(spec["index"])
            resolved: list[SymbolEntry] = []
            for pname in pair_names:
                hits = index.find_funcs(pname)
                if len(hits) == 1:
                    resolved.append(hits[0])
            if len(resolved) == len(pair_names):
                resolved.sort(key=lambda e: e.rva)
                return resolved[pair_idx], meta, "alias_ordered_pair"
            return None, meta, f"ordered_pair_incomplete({len(resolved)}/{len(pair_names)})"

        if spec.get("allow_import_plt"):
            sym = str(spec.get("symbol", name))
            hits = index.find_funcs(sym, allow_import=True)
            if hits:
                return hits[0], meta, "alias_import_plt"
            return None, meta, "import_not_found"

        target_name = str(spec["target"])
        if spec.get("prefer_part") or spec.get("prefer_part_with_string"):
            parts = index.find_func_parts(target_name)
            if len(parts) == 1:
                return parts[0], meta, "alias_part"
        hits = index.find_funcs(target_name, allow_import=bool(spec.get("allow_import_plt")))
        # Disambiguate C++ overloads via param_hint / win_param_hint when provided
        hint = (
            spec.get("win_param_hint")
            if index.platform == "windows" and spec.get("win_param_hint")
            else spec.get("param_hint")
        )
        if hint and len(hits) > 1:
            norm_hint = str(hint).replace(" ", "")
            filtered = [h for h in hits if norm_hint in h.prototype.replace(" ", "")]
            if len(filtered) == 1:
                return filtered[0], meta, "alias_overload"
            if filtered:
                hits = filtered
        if len(hits) == 1 or (len(hits) > 1 and len({h.rva for h in hits}) == 1):
            return hits[0], meta, "alias_rule"
        if len(hits) > 1:
            return None, meta, f"ambiguous({len(hits)}): {[h.prototype or h.mangled for h in hits[:4]]}"
        return None, meta, f"target_not_found({target_name})"

    if isinstance(spec, str):
        hits = index.find_funcs(spec)
        if len(hits) == 1:
            return hits[0], meta, "alias"
        if len(hits) > 1:
            return None, meta, f"ambiguous({len(hits)}): {[h.mangled for h in hits[:4]]}"
        return None, meta, f"alias_not_found({spec})"

    for idx_i, cand in enumerate(_convention_func_candidates(name)):
        hits = index.find_funcs(cand)
        if len(hits) == 1:
            return hits[0], meta, "exact" if idx_i == 0 else "convention"
        if len(hits) > 1:
            # Prefer non-thunk or largest body only if identical name has duplicates? Fail closed for safety.
            uniq_rvas = {h.rva for h in hits}
            if len(uniq_rvas) == 1:
                return hits[0], meta, "exact" if idx_i == 0 else "convention"
            return None, meta, f"ambiguous({len(hits)}): {[h.mangled for h in hits[:4]]}"
    return None, meta, "not_found"


def resolve_gv_rvas(
    name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]
) -> tuple[list[int], dict[str, Any], str]:
    """Return (candidate_rvas, meta, how). Multiple candidates can be disambiguated via prefer_owner_func."""
    gv_aliases = aliases.get("gv_aliases") or {}
    spec = gv_aliases.get(name)
    if isinstance(spec, Mapping):
        if "symbol" in spec:
            ghits = index.find_globals(str(spec["symbol"]))
            rvas = sorted({g.rva for g in ghits})
            if rvas:
                return rvas, dict(spec), "alias_disambiguated"
            return [], dict(spec), f"symbol_not_found({spec['symbol']})"
        gname = str(spec["global"])
        gtype = str(spec["type"])
        fpath = list(spec["field_path"])
        ghits = index.find_globals(gname)
        uniq_g = sorted({g.rva for g in ghits})
        if len(uniq_g) != 1:
            return [], dict(spec), f"base_global_missing({gname}, hits={len(uniq_g)})"
        fres = index.resolve_field_path(gtype, fpath, global_type_hint=gname)
        if fres is None:
            return [], dict(spec), f"field_path_missing({gtype}.{'.'.join(fpath)})"
        meta = dict(spec)
        meta["_base_rva"] = uniq_g[0]
        meta["_member_offset"] = fres.offset
        return [uniq_g[0] + fres.offset], meta, "alias_subfield"

    if isinstance(spec, str):
        ghits = index.find_globals(spec)
        rvas = sorted({g.rva for g in ghits})
        if len(rvas) == 1:
            return rvas, {}, "alias"
        return [], {}, f"alias_not_found({spec}, hits={len(rvas)})"

    for idx_i, cand in enumerate(_convention_func_candidates(name)):
        ghits = index.find_globals(cand)
        rvas = sorted({g.rva for g in ghits})
        if len(rvas) == 1:
            return rvas, {}, "exact" if idx_i == 0 else "convention"

    prefixes = aliases.get("global_struct_prefixes") or {}
    for prefix, stype in prefixes.items():
        if name.startswith(prefix + "_"):
            ghits = index.find_globals(prefix)
            if not ghits:
                continue
            field = name[len(prefix) + 1 :]
            fres = index.resolve_field_path(stype, [field], global_type_hint=prefix)
            if fres is not None:
                return (
                    [ghits[0].rva + fres.offset],
                    {"_base_rva": ghits[0].rva, "_member_offset": fres.offset},
                    "prefix_subfield",
                )
    return [], {}, "not_found"


def resolve_vtable_class(name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]) -> tuple[str, str, int] | None:
    vt_aliases = aliases.get("vtable_aliases") or {}
    if name in vt_aliases:
        cls = str(vt_aliases[name])
        hit = index.find_vtable(cls)
        if hit:
            return cls, hit[0], hit[1]
    stem = name.removesuffix("_vtable")
    cands = [stem]
    if "_" in stem:
        cands.append(stem.replace("_", "::", 1))
    for cls in cands:
        hit = index.find_vtable(cls)
        if hit:
            return cls, hit[0], hit[1]
    return None


def resolve_structmember_layout(
    sym: Mapping[str, Any], index: BaseDebugIndex, aliases: Mapping[str, Any]
) -> tuple[str, str, int, int | None, str] | None:
    name = sym["name"]
    sm_aliases = aliases.get("structmember_aliases") or {}
    spec = sm_aliases.get(name)
    if isinstance(spec, Mapping):
        st = str(spec["struct"])
        member_label = str(spec.get("member", ".".join(spec["field_path"])))
        fres = index.resolve_field_path(st, list(spec["field_path"]), global_type_hint=spec.get("global_type_hint"))
        if fres is not None:
            return str(sym.get("struct") or st), member_label, fres.offset, fres.size, "alias"
        return None

    parent = str(sym.get("struct") or "")
    if not parent:
        return None
    p_flat = parent.replace("::", "_")
    rem = name[len(p_flat) + 1 :] if name.startswith(p_flat + "_") else name
    rem = rem.removesuffix("_offset")
    fres = index.resolve_field_path(parent, [rem])
    if fres is not None:
        return parent, rem, fres.offset, fres.size, "direct"
    return None


def resolve_scalar_value(name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]) -> tuple[int | None, str]:
    sc_aliases = aliases.get("scalar_aliases") or {}
    spec = sc_aliases.get(name)
    if isinstance(spec, Mapping):
        if "global_array" in spec:
            arr = index.resolve_global_array(str(spec["global_array"]))
            if arr is None:
                return None, f"global_array_not_found({spec['global_array']})"
            if "property" in spec:
                prop = spec["property"]
                val = {"element_size": arr.element_size, "count": arr.count, "total_size": arr.total_size}.get(prop)
                return val, "alias_global_array" if val is not None else f"bad_property({prop})"
            if "member" in spec:
                fres = index.resolve_field_path(arr.element_type, [str(spec["member"])])
                if fres is not None:
                    return fres.offset, "alias_global_array_member"
                return None, f"array_elem_member_not_found({arr.element_type}.{spec['member']})"
        if "struct" in spec:
            fres = index.resolve_field_path(str(spec["struct"]), list(spec["field_path"]))
            if fres is None:
                return None, f"struct_field_not_found({spec['struct']})"
            prop = spec.get("property", "offset")
            if prop == "offset":
                return fres.offset, "alias_struct_field"
            if fres.array is not None:
                val = {
                    "element_size": fres.array.element_size,
                    "count": fres.array.count,
                    "total_size": fres.array.total_size,
                }.get(prop)
                if val is not None:
                    return val, "alias_struct_array"
            return None, f"property_unavailable({prop})"

    if name.startswith("size_of_"):
        st = name[len("size_of_") :] + "_t"
        sz = index.resolve_struct_size(st)
        if sz is not None:
            return sz, "sizeof_rule"

    prefixes = aliases.get("global_struct_prefixes") or {}
    for suffix, prop in (
        ("_offset", "offset"),
        ("_count", "count"),
        ("_element_size", "element_size"),
        ("_size", "total_size"),
    ):
        if not name.endswith(suffix):
            continue
        body = name[: -len(suffix)]
        if "_t_" in body:
            st, mem = body.split("_t_", 1)
            fres = index.resolve_field_path(st + "_t", [mem])
            if fres is not None:
                if prop == "offset":
                    return fres.offset, "struct_offset_rule"
                if fres.array is not None:
                    val = getattr(fres.array, prop)
                    return val, "struct_array_rule"
        for prefix, stype in prefixes.items():
            if body.startswith(prefix + "_"):
                mem = body[len(prefix) + 1 :]
                fres = index.resolve_field_path(stype, [mem], global_type_hint=prefix)
                if fres is not None:
                    if prop == "offset":
                        return fres.offset, "prefix_offset_rule"
                    if fres.array is not None:
                        return getattr(fres.array, prop), "prefix_array_rule"
    return None, "not_found"


def resolve_vfunc_info(
    name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]
) -> tuple[str | None, str | None, int | None, SymbolEntry | None, str]:
    """Return (class_name, method_name, slot_index_from_type, concrete_func_entry, how)."""
    # 1) Try concrete implementation method first (e.g. BaseUISurface_PaintTraverse, CEngine_Frame)
    concrete, _, how = resolve_func_entry(name, index, aliases)
    cls_guess: str | None = None
    meth_guess: str | None = None
    if concrete is not None and "::" in concrete.name:
        cls_guess, meth_guess = concrete.name.rsplit("::", 1)
    elif "_" in name:
        parts = name.split("_")
        if parts[0] == "vgui2" and len(parts) >= 3:
            cls_guess, meth_guess = f"vgui2::{parts[1]}", "_".join(parts[2:])
        else:
            cls_guess, meth_guess = parts[0], "_".join(parts[1:])

    if concrete is not None:
        slot = None
        if cls_guess and meth_guess:
            slot = index.find_vfunc_slot(cls_guess, meth_guess)
            if slot is None and not cls_guess.startswith("vgui2::"):
                slot = index.find_vfunc_slot(f"vgui2::{cls_guess}", meth_guess)
        return cls_guess, meth_guess, slot, concrete, f"concrete_{how}"

    # 2) Pure virtual interface slot from PDB TPI / DWARF
    pairs = []
    if cls_guess and meth_guess:
        pairs.append((cls_guess, meth_guess))
        if not cls_guess.startswith("vgui2::"):
            pairs.append((f"vgui2::{cls_guess}", meth_guess))
    for cls, meth in pairs:
        slot = index.find_vfunc_slot(cls, meth)
        if slot is not None:
            return cls, meth, slot, None, "type_vtable_slot"
    return cls_guess, meth_guess, None, None, "not_found"


def _load_preprocessor_module(script_rel_path: str) -> Any:
    script_path = (REPO_ROOT / script_rel_path).resolve()
    if not script_path.is_relative_to(REPO_ROOT.resolve()) or not script_path.is_file():
        raise FileNotFoundError(f"Preprocessor script not found inside repository: {script_rel_path}")
    module_key = "_goldsrc_reverse_preproc_" + re.sub(r"[^0-9A-Za-z_]", "_", script_rel_path)
    spec = importlib.util.spec_from_file_location(module_key, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load preprocessor script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _match_patch_preprocessor(
    name: str, aliases: Mapping[str, Any]
) -> tuple[int, Mapping[str, Any], int | None] | None:
    """Match a patch symbol name against external `patch_preprocessors` rules in aliases YAML.

    Returns `(rule_index, rule_spec, numbered_index_or_none)` or `None`.
    """
    rules = aliases.get("patch_preprocessors") or ()
    for rule_idx, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            continue
        exact = rule.get("match_exact") or ()
        if isinstance(exact, str):
            exact = (exact,)
        if name in exact:
            return rule_idx, rule, None
        prefix = rule.get("match_prefix")
        if isinstance(prefix, str) and prefix and name.startswith(prefix):
            tail = name[len(prefix) :]
            if tail.isdigit():
                return rule_idx, rule, int(tail)
            if not rule.get("numbered_only", False):
                return rule_idx, rule, None
    return None


def resolve_patch_callsite_spec(
    name: str, index: BaseDebugIndex, aliases: Mapping[str, Any]
) -> tuple[SymbolEntry | None, SymbolEntry | None, int, str]:
    patch_map = aliases.get("patch_callsites") or {}
    if name in patch_map:
        spec = patch_map[name]
        c1, _, h1 = resolve_func_entry(str(spec["caller"]), index, aliases)
        callee_name = str(spec["callee"])
        if spec.get("allow_import_plt"):
            chits = index.find_funcs(callee_name, allow_import=True)
            c2, h2 = (chits[0], "import") if chits else (None, "import_not_found")
        else:
            c2, _, h2 = resolve_func_entry(callee_name, index, aliases)
        if c1 and c2:
            return c1, c2, int(spec.get("ordinal", 0)), "alias_callsite"
        return None, None, 0, f"alias_callsite_unresolved(caller={h1}, callee={h2})"

    m = re.match(r"^(.+)_to_(.+)_callsite_(\d+)$", name)
    if not m:
        return None, None, 0, "skipped_special_patch"
    c1, _, h1 = resolve_func_entry(m.group(1), index, aliases)
    c2, _, h2 = resolve_func_entry(m.group(2), index, aliases)
    if c1 and c2:
        return c1, c2, int(m.group(3)), "callsite_pattern"
    return None, None, 0, f"callsite_unresolved(caller={h1}, callee={h2})"


async def _inspect_func_with_fallback(
    session: Any, va: int, image_base: int, func_name: str, *, cache: dict[int, dict[str, Any] | None] | None = None
) -> tuple[dict[str, Any] | None, bool]:
    if cache is not None and va in cache:
        cached = cache[va]
        if cached is None:
            return None, False
        copied = dict(cached)
        copied["func_name"] = func_name
        return copied, bool(copied.get("func_sig_allow_across_function_boundary"))

    res = await _inspect_function_via_mcp(session, va, image_base, func_name, allow_across_function_boundary=False)
    across = False
    if res is None:
        res = await _inspect_function_via_mcp(session, va, image_base, func_name, allow_across_function_boundary=True)
        across = res is not None
    if res is None:
        res = await _inspect_function_via_mcp(
            session,
            va,
            image_base,
            func_name,
            allow_across_function_boundary=True,
            allow_relative_call_discriminator=True,
        )
        across = res is not None
    if res is not None and across:
        res["func_sig_allow_across_function_boundary"] = True
    if cache is not None:
        cache[va] = dict(res) if res is not None else None
    return res, across


async def _emit_with_mcp(
    session: Any,
    *,
    symbols: list[dict[str, Any]],
    index: BaseDebugIndex,
    aliases: Mapping[str, Any],
    platform: str,
    output_dir: Path,
    reference_dir: Path | None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    img_payload = parse_mcp_result(
        await session.call_tool(
            "py_eval", {"code": "import idaapi, json\nresult = json.dumps({'image_base': int(idaapi.get_imagebase())})"}
        )
    )
    image_base = int(img_payload["image_base"])
    print(f"[MCP] Connected; image_base={hex(image_base)}, symbols={len(symbols)}")

    report: dict[str, Any] = {
        "platform": platform,
        "image_base": hex(image_base),
        "counts": collections.defaultdict(lambda: {"ok": 0, "failed": 0, "skipped": 0}),
        "failures": [],
        "skipped": [],
        "reference_comparison": {},
    }
    func_sig_cache: dict[int, dict[str, Any] | None] = {}
    vtable_cache: dict[str, dict[str, Any]] = {}
    resolved_func_vas: dict[str, int] = {}

    def record_ok(cat: str) -> None:
        report["counts"][cat]["ok"] += 1

    def record_fail(cat: str, name: str, reason: str) -> None:
        report["counts"][cat]["failed"] += 1
        report["failures"].append({"category": cat, "name": name, "reason": reason})

    def record_skip(cat: str, name: str, reason: str) -> None:
        report["counts"][cat]["skipped"] += 1
        report["skipped"].append({"category": cat, "name": name, "reason": reason})

    # --- Phase 1: vtables ---
    for sym in [s for s in symbols if s["category"] == "vtable"]:
        name = sym["name"]
        vt = resolve_vtable_class(name, index, aliases)
        if vt is None:
            record_fail("vtable", name, "vtable_not_found_in_debug_index")
            continue
        cls_name, mangled_sym, _ = vt
        data = await preprocess_vtable_via_mcp(session, cls_name, image_base, platform, symbol_aliases=[mangled_sym])
        if data is None:
            record_fail("vtable", name, f"preprocess_vtable_via_mcp_failed({cls_name}, {mangled_sym})")
            continue
        vtable_cache[cls_name] = data
        if "::" in cls_name:
            vtable_cache[cls_name.split("::")[-1]] = data
        payload = {k: v for k, v in data.items() if not k.startswith("_")}
        write_vtable_yaml(output_dir / f"{name}.{platform}.yaml", payload)
        record_ok("vtable")

    # --- Phase 2: functions ---
    import_func_names: list[str] = []
    func_plan: list[tuple[dict[str, Any], SymbolEntry | None, dict[str, Any], str]] = []
    for sym in [s for s in symbols if s["category"] == "func"]:
        entry, meta, how = resolve_func_entry(sym["name"], index, aliases)
        func_plan.append((sym, entry, meta, how))
        if entry is not None and entry.is_import:
            import_func_names.append(entry.name)

    import_eas: dict[str, int | None] = {}
    if import_func_names:
        res_imp = parse_mcp_result(
            await session.call_tool(
                "py_eval",
                {
                    "code": "import idaapi\n"
                    + FIND_IMPORT_PLT_PY.replace("NAMES_PLACEHOLDER", json.dumps(import_func_names))
                },
            )
        )
        import_eas = dict(res_imp or {})

    for sym, entry, meta, how in func_plan:
        name = sym["name"]
        if entry is None:
            record_fail("func", name, how)
            continue
        if entry.is_import:
            va = import_eas.get(entry.name)
            if va is None:
                record_fail("func", name, f"import_plt_not_found_in_idb({entry.name})")
                continue
        else:
            va = image_base + entry.rva

        # Unwrap MSVC incremental-link ILT / JMP thunks
        resolved_va = await _resolve_jmp_thunk_target_via_mcp(session, va, strict=False)
        if resolved_va is not None:
            va = resolved_va

        if meta.get("follow_single_tail_jump"):
            tail = parse_mcp_result(
                await session.call_tool(
                    "py_eval", {"code": FOLLOW_SINGLE_TAIL_JUMP_PY.replace("TARGET_EA_PLACEHOLDER", str(va))}
                )
            )
            if isinstance(tail, Mapping) and tail.get("target"):
                va = int(tail["target"])

        resolved_func_vas[name] = va
        inspected, across = await _inspect_func_with_fallback(session, va, image_base, name, cache=func_sig_cache)
        if inspected is None:
            record_fail("func", name, f"unique_sig_failed_at_{hex(va)}")
            continue
        payload = {k: inspected[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if across:
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(output_dir / f"{name}.{platform}.yaml", payload)
        record_ok("func")

    # --- Phase 3: vfuncs ---
    for sym in [s for s in symbols if s["category"] == "vfunc"]:
        name = sym["name"]
        cls_name, meth_name, type_slot, concrete, how = resolve_vfunc_info(name, index, aliases)
        if concrete is not None:
            va = image_base + concrete.rva
            resolved_va = await _resolve_jmp_thunk_target_via_mcp(session, va, strict=False)
            if resolved_va is not None:
                va = resolved_va
            slot = type_slot
            vt_data = vtable_cache.get(cls_name or "")
            if slot is None and vt_data is not None:
                for idx_k, raw_v in (vt_data.get("vtable_entries") or {}).items():
                    entry_va = int(raw_v, 0)
                    entry_resolved = (
                        await _resolve_jmp_thunk_target_via_mcp(session, entry_va, strict=False) or entry_va
                    )
                    if entry_resolved == va:
                        slot = int(idx_k)
                        break
            if slot is None:
                record_fail("vfunc", name, f"vfunc_slot_not_found({cls_name}::{meth_name})")
                continue
            inspected, across = await _inspect_func_with_fallback(session, va, image_base, name, cache=func_sig_cache)
            if inspected is not None:
                payload = {
                    "func_name": name,
                    "func_va": inspected["func_va"],
                    "func_rva": inspected["func_rva"],
                    "func_size": inspected["func_size"],
                    "func_sig": inspected["func_sig"],
                    "vtable_name": cls_name,
                    "vfunc_offset": hex(slot * 4),
                    "vfunc_index": slot,
                }
                if across:
                    payload["func_sig_allow_across_function_boundary"] = True
            else:
                payload = {
                    "func_name": name,
                    "vtable_name": cls_name,
                    "vfunc_offset": hex(slot * 4),
                    "vfunc_index": slot,
                }
            write_func_yaml(output_dir / f"{name}.{platform}.yaml", payload)
            record_ok("vfunc")
        elif type_slot is not None and cls_name:
            payload = {
                "func_name": name,
                "vtable_name": cls_name,
                "vfunc_offset": hex(type_slot * 4),
                "vfunc_index": type_slot,
            }
            write_func_yaml(output_dir / f"{name}.{platform}.yaml", payload)
            record_ok("vfunc")
        else:
            record_fail("vfunc", name, how)

    # --- Phase 4: globals (batch DataRefsTo via single py_eval) ---
    gv_syms = [s for s in symbols if s["category"] == "gv"]
    gv_candidates: dict[str, tuple[list[int], dict[str, Any]]] = {}
    for sym in gv_syms:
        rvas, meta, how = resolve_gv_rvas(sym["name"], index, aliases)
        if not rvas:
            record_fail("gv", sym["name"], how)
        else:
            gv_candidates[sym["name"]] = ([image_base + r for r in rvas], meta)

    gv_query_items: list[dict[str, Any]] = []
    seen_gv_keys: set[str] = set()
    for cand_vas, meta in gv_candidates.values():
        base_rva = meta.get("_base_rva")
        member_off = int(meta.get("_member_offset", 0) or 0)
        for va in cand_vas:
            key = f"{va}:{base_rva}:{member_off}"
            if key in seen_gv_keys:
                continue
            seen_gv_keys.add(key)
            item: dict[str, Any] = {"key": key, "gv_va": va, "member_offset": member_off}
            if base_rva is not None:
                item["base_va"] = image_base + int(base_rva)
            gv_query_items.append(item)

    gv_xref_map: dict[str, list[list[int]]] = {}
    if gv_query_items:
        for i in range(0, len(gv_query_items), 60):
            chunk = gv_query_items[i : i + 60]
            chunk_res = parse_mcp_result(
                await session.call_tool(
                    "py_eval", {"code": BATCH_GV_XREFS_PY.replace("GV_ITEMS_PLACEHOLDER", json.dumps(chunk))}
                )
            )
            if isinstance(chunk_res, Mapping):
                gv_xref_map.update(chunk_res)

    for name, (cand_vas, meta) in gv_candidates.items():
        preferred_owner_va: int | None = None
        if meta.get("prefer_owner_func"):
            pref_ent, _, _ = resolve_func_entry(str(meta["prefer_owner_func"]), index, aliases)
            if pref_ent is not None and not pref_ent.is_import:
                pva = image_base + pref_ent.rva
                preferred_owner_va = await _resolve_jmp_thunk_target_via_mcp(session, pva, strict=False) or pva

        base_rva = meta.get("_base_rva")
        member_off = int(meta.get("_member_offset", 0) or 0)
        ordered_pairs: list[tuple[int, int, int]] = []  # (gv_va, insn_va, owner_va)
        for gv_va in cand_vas:
            key = f"{gv_va}:{base_rva}:{member_off}"
            for insn_va, owner_va in gv_xref_map.get(key) or []:
                ordered_pairs.append((gv_va, insn_va, owner_va))
        if call_owner := meta.get("indirect_call_in"):
            entry, _, _ = resolve_func_entry(call_owner, index, aliases)
            if platform != "windows" or entry is None or entry.is_import or len(cand_vas) != 1:
                record_fail("gv", name, f"cannot_resolve_indirect_call({call_owner})")
                continue
            owner = image_base + entry.rva
            owner = await _resolve_jmp_thunk_target_via_mcp(session, owner, strict=False) or owner
            code = WIN32_GLOBAL_CALLS_PY.replace("TARGET_VA", f"({cand_vas[0]})").replace("OWNER_VA", str(owner))
            response = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
            matches = response.get("matches", []) if isinstance(response, Mapping) else []
            if len(matches) != 1:
                record_fail("gv", name, f"expected_one_indirect_call({call_owner}, hits={len(matches)})")
                continue
            ordered_pairs = [(cand_vas[0], matches[0], owner)]
        elif preferred_owner_va is not None:
            ordered_pairs.sort(key=lambda item: 0 if item[2] == preferred_owner_va else 1)
        elif len(cand_vas) > 1:
            record_fail("gv", name, f"ambiguous_gv_rvas({[hex(v) for v in cand_vas]})")
            continue

        emitted = False
        for gv_va, insn_va, owner_va in ordered_pairs:
            if preferred_owner_va is not None and len(cand_vas) > 1 and owner_va != preferred_owner_va:
                continue
            detail = await _inspect_llm_instruction(session, insn_va)
            if detail is None:
                continue
            disp = _gv_operand_displacement(detail)
            if disp is None:
                continue
            res_fields = _gv_resolution_fields(detail, gv_va, image_base, disp, platform=platform)
            owner_fn, owner_across = await _inspect_func_with_fallback(
                session, owner_va, image_base, "__gv_anchor", cache=func_sig_cache
            )
            used_across = owner_across
            if owner_fn is not None and insn_va >= int(owner_fn["func_va"], 0):
                sig_va = int(owner_fn["func_va"], 0)
                sig_str = owner_fn["func_sig"]
            else:
                inst_sig = await run_signature(session, insn_va)
                if inst_sig is None:
                    continue
                sig_va = insn_va
                sig_str = inst_sig["patch_sig"]
                used_across = True

            payload = {
                "gv_name": name,
                "gv_va": hex(gv_va),
                "gv_rva": hex(gv_va - image_base),
                "gv_sig": sig_str,
                "gv_sig_va": hex(sig_va),
                "gv_inst_offset": insn_va - sig_va,
                "gv_inst_length": int(detail["size"]),
                "gv_inst_disp": disp,
            }
            payload.update(res_fields)
            if used_across:
                payload["gv_sig_allow_across_function_boundary"] = True
            write_gv_yaml(output_dir / f"{name}.{platform}.yaml", payload)
            record_ok("gv")
            emitted = True
            break
        if not emitted:
            record_fail(
                "gv", name, f"no_usable_code_xref_at_{[hex(v) for v in cand_vas]} (raw_refs={len(ordered_pairs)})"
            )

    # --- Phase 5: structmembers & scalars ---
    for sym in [s for s in symbols if s["category"] == "structmember"]:
        name = sym["name"]
        resolved = resolve_structmember_layout(sym, index, aliases)
        if resolved is None:
            record_fail("structmember", name, "type_or_member_not_found")
            continue
        struct_name, member_name, offset, size, _ = resolved
        payload: dict[str, Any] = {
            "struct_name": struct_name,
            "member_name": member_name,
            "offset": hex(offset),
        }
        if size is not None and size > 0:
            payload["size"] = hex(size)
        write_struct_offset_yaml(output_dir / f"{name}.{platform}.yaml", payload)
        record_ok("structmember")

    for sym in [s for s in symbols if s["category"] == "scalar"]:
        name = sym["name"]
        val, how = resolve_scalar_value(name, index, aliases)
        if val is None:
            record_fail("scalar", name, how)
            continue
        write_scalar_yaml(output_dir / f"{name}.{platform}.yaml", {"scalar_name": name, "scalar_value": int(val)})
        record_ok("scalar")

    # --- Phase 6: patches (external preprocessor rules + callsite patches) ---
    preproc_groups: dict[int, tuple[Mapping[str, Any], list[tuple[int | None, str]]]] = {}
    callsite_specs: list[tuple[str, int, SymbolEntry, int]] = []  # (name, caller_va, callee_entry, ordinal)
    for sym in [s for s in symbols if s["category"] == "patch"]:
        name = sym["name"]
        matched_preproc = _match_patch_preprocessor(name, aliases)
        if matched_preproc is not None:
            rule_idx, rule_spec, num_idx = matched_preproc
            if rule_idx not in preproc_groups:
                preproc_groups[rule_idx] = (rule_spec, [])
            preproc_groups[rule_idx][1].append((num_idx, name))
            continue
        c1, c2, ordinal, how = resolve_patch_callsite_spec(name, index, aliases)
        if how == "skipped_special_patch":
            record_skip("patch", name, "non_callsite_special_patch_use_existing_preprocessor")
            continue
        if c1 is None or c2 is None:
            record_fail("patch", name, how)
            continue
        caller_va = await _resolve_jmp_thunk_target_via_mcp(session, image_base + c1.rva, strict=False) or (
            image_base + c1.rva
        )
        callsite_specs.append((name, caller_va, c2, ordinal))

    for rule_spec, grouped_items in preproc_groups.values():
        script_rel = str(rule_spec.get("script") or "").strip()
        mode = str(rule_spec.get("mode") or "preprocess_skill").strip()
        if not script_rel:
            for _, name in grouped_items:
                record_fail("patch", name, "patch_preprocessor_missing_script")
            continue
        try:
            preproc_mod = _load_preprocessor_module(script_rel)
        except (OSError, ImportError, RuntimeError, SyntaxError) as exc:
            for _, name in grouped_items:
                record_fail("patch", name, f"patch_preprocessor_load_failed({exc})")
            continue

        if mode == "preprocess_skill":
            owner_name = str(rule_spec.get("owner_func") or "").strip()
            if owner_name and not (output_dir / f"{owner_name}.{platform}.yaml").is_file():
                owner_va = resolved_func_vas.get(owner_name)
                if owner_va is None:
                    owner_ent, _, _ = resolve_func_entry(owner_name, index, aliases)
                    if owner_ent is not None and not owner_ent.is_import:
                        raw_owner_va = image_base + owner_ent.rva
                        owner_va = (
                            await _resolve_jmp_thunk_target_via_mcp(session, raw_owner_va, strict=False) or raw_owner_va
                        )
                if owner_va is not None:
                    inspected_owner, owner_across = await _inspect_func_with_fallback(
                        session, owner_va, image_base, owner_name, cache=func_sig_cache
                    )
                    if inspected_owner is not None:
                        owner_payload = {
                            k: inspected_owner[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")
                        }
                        if owner_across:
                            owner_payload["func_sig_allow_across_function_boundary"] = True
                        write_func_yaml(output_dir / f"{owner_name}.{platform}.yaml", owner_payload)
            expected_outputs = [str(output_dir / f"{name}.{platform}.yaml") for _, name in grouped_items]
            skill_name = str(rule_spec.get("skill_name") or Path(script_rel).stem)
            ok = await preproc_mod.preprocess_skill(
                session,
                skill_name,
                expected_outputs,
                {},
                str(output_dir),
                platform,
                image_base,
                debug=False,
            )
            for _, name in grouped_items:
                if ok and (output_dir / f"{name}.{platform}.yaml").is_file():
                    record_ok("patch")
                else:
                    record_fail("patch", name, f"preprocessor_skill_failed({script_rel})")
            continue

        if mode != "site_locator":
            for _, name in grouped_items:
                record_fail("patch", name, f"unsupported_patch_preprocessor_mode({mode})")
            continue

        owner_name = str(rule_spec.get("owner_func") or getattr(preproc_mod, "OWNER_FUNC_NAME", "")).strip()
        if not owner_name:
            for _, name in grouped_items:
                record_fail("patch", name, f"site_locator_missing_owner_func({script_rel})")
            continue
        owner_va = resolved_func_vas.get(owner_name)
        if owner_va is None:
            owner_ent, _, owner_how = resolve_func_entry(owner_name, index, aliases)
            if owner_ent is not None and not owner_ent.is_import:
                raw_owner_va = image_base + owner_ent.rva
                owner_va = await _resolve_jmp_thunk_target_via_mcp(session, raw_owner_va, strict=False) or raw_owner_va
            else:
                for _, name in grouped_items:
                    record_fail("patch", name, f"owner_func_unresolved({owner_name}: {owner_how})")
                continue

        locator_fn_name = str(rule_spec.get("locator_func") or "_locate_patches")
        locator_fn = getattr(preproc_mod, locator_fn_name, None)
        if locator_fn is None:
            for _, name in grouped_items:
                record_fail("patch", name, f"locator_func_missing({script_rel}:{locator_fn_name})")
            continue

        located = await locator_fn(session, owner_va)
        sites = located.get("sites") if isinstance(located, Mapping) else None
        owner_end = (
            next(
                (int(val, 0) for key, val in located.items() if key.endswith("_end") and val is not None),
                None,
            )
            if isinstance(located, Mapping)
            else None
        )
        if (
            not isinstance(located, Mapping)
            or located.get("error")
            or located.get("pointer_size") != 4
            or not isinstance(sites, list)
            or owner_end is None
        ):
            err_detail = located.get("error") if isinstance(located, Mapping) else "locator_returned_none"
            for _, name in grouped_items:
                record_fail("patch", name, f"site_locator_failed({err_detail})")
            continue

        prefix = str(rule_spec.get("match_prefix") or getattr(preproc_mod, "PATCH_NAME_PREFIX", ""))
        allowed_imms = getattr(preproc_mod, "HEAP_LIMIT_IMMEDIATES", None)
        requested_by_idx = {idx: name for idx, name in grouped_items if idx is not None}
        emitted_indices: set[int] = set()
        for idx, site in enumerate(sites):
            patch_name = requested_by_idx.get(idx, f"{prefix}{idx}")
            if not isinstance(site, Mapping):
                record_fail("patch", patch_name, "invalid_site_record")
                continue
            try:
                patch_ea = int(site["ea"], 0)
                patch_sig_disp = int(site["patch_sig_disp"])
                insn_len = int(site["insn_len"])
                imm_val = int(site["imm"], 0) if "imm" in site and site["imm"] is not None else None
            except (TypeError, ValueError, KeyError) as exc:
                record_fail("patch", patch_name, f"invalid_site_fields({exc})")
                continue
            patch_sig = site.get("patch_sig")
            if (
                not isinstance(patch_sig, str)
                or not patch_sig.strip()
                or (allowed_imms is not None and imm_val not in allowed_imms)
                or patch_ea < owner_va
                or patch_ea >= owner_end
                or patch_sig_disp != 0
                or insn_len <= 0
            ):
                record_fail("patch", patch_name, f"site_contract_failed_at_{hex(patch_ea)}")
                continue
            unique_ea = await _find_unique_bytes(session, patch_sig)
            if unique_ea != patch_ea:
                record_fail("patch", patch_name, f"site_sig_not_unique_at_{hex(patch_ea)}")
                continue
            write_patch_yaml(
                output_dir / f"{patch_name}.{platform}.yaml",
                {
                    "patch_name": patch_name,
                    "patch_va": hex(patch_ea),
                    "patch_rva": hex(patch_ea - image_base),
                    "patch_sig": patch_sig,
                    "patch_sig_disp": patch_sig_disp,
                },
            )
            emitted_indices.add(idx)
            record_ok("patch")
        for idx, name in sorted(grouped_items, key=lambda item: (-1 if item[0] is None else item[0], item[1])):
            if idx is not None and idx >= len(sites) and idx not in emitted_indices:
                record_skip("patch", name, f"site_not_present_in_this_build(found={len(sites)})")

    if callsite_specs:
        query_pairs = []
        for name, caller_va, callee_ent, _ in callsite_specs:
            target_vas: list[int] = []
            if not callee_ent.is_import and callee_ent.rva:
                raw_va = image_base + callee_ent.rva
                target_vas.append(raw_va)
                res_va = await _resolve_jmp_thunk_target_via_mcp(session, raw_va, strict=False)
                if res_va is not None and res_va != raw_va:
                    target_vas.append(res_va)
            target_names = sorted({callee_ent.name, callee_ent.mangled, f"_{callee_ent.name}"})
            query_pairs.append([name, caller_va, target_vas, target_names])

        cs_map = parse_mcp_result(
            await session.call_tool(
                "py_eval", {"code": BATCH_CALLSITES_PY.replace("PAIRS_PLACEHOLDER", json.dumps(query_pairs))}
            )
        )
        for name, _, _, ordinal in callsite_specs:
            hits = sorted(set(cs_map.get(name) or []))
            if ordinal >= len(hits):
                record_fail("patch", name, f"callsite_ordinal_{ordinal}_out_of_range(found={len(hits)})")
                continue
            target_ea = hits[ordinal]
            sig = await run_signature(session, target_ea)
            if sig is None:
                record_fail("patch", name, f"unique_patch_sig_failed_at_{hex(target_ea)}")
                continue
            write_patch_yaml(
                output_dir / f"{name}.{platform}.yaml",
                {
                    "patch_name": name,
                    "patch_va": hex(target_ea),
                    "patch_rva": hex(target_ea - image_base),
                    "patch_sig": sig["patch_sig"],
                    "patch_sig_disp": sig["patch_sig_disp"],
                },
            )
            record_ok("patch")

    # Optional schema comparison against reference bin_artifacts directory
    if reference_dir is not None and reference_dir.is_dir():
        schema_diffs = []
        matched_files = 0
        for generated_path in sorted(output_dir.glob(f"*.{platform}.yaml")):
            ref_path = reference_dir / generated_path.name
            if not ref_path.is_file():
                continue
            matched_files += 1
            gen_data = load_yaml_file(generated_path)
            ref_data = load_yaml_file(ref_path)
            gen_keys = {k for k in gen_data if not k.startswith("_")}
            ref_keys = {k for k in ref_data if not k.startswith("_")}
            # Ignore optional *_allow_across_function_boundary / gv_address_offset variance
            missing_req = sorted(
                k
                for k in (ref_keys - gen_keys)
                if not k.endswith("_allow_across_function_boundary")
                and k not in {"gv_address_offset", "func_sig_resolve_jmp_thunk"}
            )
            if missing_req:
                schema_diffs.append({"file": generated_path.name, "missing_vs_ref": missing_req})
        report["reference_comparison"] = {
            "reference_dir": str(reference_dir),
            "compared_files": matched_files,
            "files_with_missing_keys": len(schema_diffs),
            "samples": schema_diffs[:30],
        }

    report["counts"] = dict(report["counts"])
    return report


def _run_dry_probe(
    symbols: list[dict[str, Any]], index: BaseDebugIndex, aliases: Mapping[str, Any], platform: str
) -> dict[str, Any]:
    counts: dict[str, dict[str, int]] = collections.defaultdict(lambda: {"ok": 0, "failed": 0, "skipped": 0})
    failures: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for sym in symbols:
        name = sym["name"]
        cat = sym["category"]
        if cat == "func":
            ent, _, how = resolve_func_entry(name, index, aliases)
            if ent is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": how})
        elif cat == "gv":
            rvas, _, how = resolve_gv_rvas(name, index, aliases)
            if rvas:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": how})
        elif cat == "vtable":
            if resolve_vtable_class(name, index, aliases) is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": "not_found"})
        elif cat == "vfunc":
            _, _, slot, concrete, how = resolve_vfunc_info(name, index, aliases)
            if slot is not None or concrete is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": how})
        elif cat == "structmember":
            if resolve_structmember_layout(sym, index, aliases) is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": "not_found"})
        elif cat == "scalar":
            val, how = resolve_scalar_value(name, index, aliases)
            if val is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": how})
        elif cat == "patch":
            matched_preproc = _match_patch_preprocessor(name, aliases)
            if matched_preproc is not None:
                _, rule_spec, _ = matched_preproc
                script_rel = str(rule_spec.get("script") or "").strip()
                owner_name = str(rule_spec.get("owner_func") or "").strip()
                if not script_rel or not (REPO_ROOT / script_rel).is_file():
                    counts[cat]["failed"] += 1
                    failures.append({"category": cat, "name": name, "reason": f"missing_script({script_rel})"})
                elif owner_name:
                    owner_ent, _, owner_how = resolve_func_entry(owner_name, index, aliases)
                    if owner_ent is not None:
                        counts[cat]["ok"] += 1
                    else:
                        counts[cat]["failed"] += 1
                        failures.append({"category": cat, "name": name, "reason": f"{owner_name}({owner_how})"})
                else:
                    counts[cat]["ok"] += 1
                continue
            c1, c2, _, how = resolve_patch_callsite_spec(name, index, aliases)
            if how == "skipped_special_patch":
                counts[cat]["skipped"] += 1
                skipped.append({"category": cat, "name": name, "reason": how})
            elif c1 is not None and c2 is not None:
                counts[cat]["ok"] += 1
            else:
                counts[cat]["failed"] += 1
                failures.append({"category": cat, "name": name, "reason": how})
    return {"platform": platform, "dry_run": True, "counts": dict(counts), "failures": failures, "skipped": skipped}


def _serialize_metahook_json(document: object) -> bytes:
    """Compact UTF-8 JSON with preserved key order and trailing newline (matches MetaHook sync-gamedata.py)."""
    return (json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=False) + "\n").encode("utf-8")


def _normalize_manifest_symbol_block(value: object) -> dict[str, dict[str, str]]:
    if value is None:
        return {}
    if isinstance(value, list):
        return {"engine": {str(sym): "" for sym in value if isinstance(sym, str) and sym}}
    if not isinstance(value, Mapping):
        raise TypeError("MetaHook manifest symbol block must be a mapping or list")
    module_scoped = len(value) > 0 and all(isinstance(v, (Mapping, list)) for v in value.values())
    result: dict[str, dict[str, str]] = {}
    if module_scoped:
        for mod, mapping in value.items():
            if isinstance(mapping, list):
                result[str(mod)] = {str(sym): "" for sym in mapping if isinstance(sym, str) and sym}
            elif isinstance(mapping, Mapping):
                result[str(mod)] = {str(sym): ("" if kind is None else str(kind)) for sym, kind in mapping.items()}
    else:
        result["engine"] = {str(sym): ("" if kind is None else str(kind)) for sym, kind in value.items()}
    return result


def _parse_manifest_numbered_sets(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, str) and item:
            result.append(("engine", item))
        elif isinstance(item, Mapping) and isinstance(item.get("prefix"), str) and item["prefix"]:
            result.append((str(item.get("module") or "engine"), str(item["prefix"])))
    return result


def _metahook_manifest_keep_set(
    manifest: Mapping[str, Any], records: list[dict[str, Any]], game_version: str
) -> set[tuple[str, str]]:
    present: set[tuple[str, str]] = {(str(r.get("module", "engine")), str(r.get("symbolName", ""))) for r in records}
    present_names = {name for _, name in present}
    keep: set[tuple[str, str]] = set()

    for mod, sym_map in _normalize_manifest_symbol_block(manifest.get("symbols")).items():
        for sym in sym_map:
            keep.add((mod, sym))
    for mod, sym_map in _normalize_manifest_symbol_block(manifest.get("optionalSymbols")).items():
        for sym in sym_map:
            if sym in present_names:
                keep.add((mod, sym))
    for mod, prefix in _parse_manifest_numbered_sets(manifest.get("numberedPatchSets")):
        idx = 0
        while (mod, f"{prefix}_{idx}") in present:
            keep.add((mod, f"{prefix}_{idx}"))
            idx += 1
    for group in manifest.get("conditionalGroups") or []:
        if not isinstance(group, Mapping):
            continue
        exempt = group.get("exempt") or []
        when = group.get("when") or []
        if game_version in exempt or (when and game_version not in when):
            continue
        for mod, sym_map in _normalize_manifest_symbol_block(group.get("symbols")).items():
            for sym in sym_map:
                keep.add((mod, sym))
        for mod, prefix in _parse_manifest_numbered_sets(group.get("numberedPatchSets")):
            idx = 0
            while (mod, f"{prefix}_{idx}") in present:
                keep.add((mod, f"{prefix}_{idx}"))
                idx += 1
    return keep


def _prune_record_for_metahook(
    record: Mapping[str, Any],
    *,
    strip_record_fields: set[str],
    strip_payload_fields: Mapping[str, set[str]],
) -> dict[str, Any]:
    pruned: dict[str, Any] = {}
    for field in METAHOOK_CONSUMED_RECORD_FIELDS:
        if field in record and field not in strip_record_fields:
            pruned[field] = record[field]

    kind = record.get("kind")
    payload = record.get("payload")
    if isinstance(kind, str) and kind in METAHOOK_CONSUMED_PAYLOAD_FIELDS and isinstance(payload, Mapping):
        stripped = strip_payload_fields.get(kind, set())
        keep_keys = [
            field for field in METAHOOK_CONSUMED_PAYLOAD_FIELDS[kind] if field in payload and field not in stripped
        ]
        if keep_keys:
            pruned["payload"] = {field: payload[field] for field in keep_keys}
    return pruned


def prune_dataset_for_metahook(
    dataset: Mapping[str, Any],
    *,
    game_version: str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert an upstream Schema-5 dataset into MetaHookSv's pruned runtime JSON format."""
    raw_records = list(dataset.get("records") or [])
    strip_record_fields = set(manifest.get("stripRecordFields") or ()) if manifest else set()
    strip_top_level_fields = set(manifest.get("stripTopLevelFields") or ()) if manifest else set()
    strip_payload_fields: dict[str, set[str]] = {}
    if manifest and isinstance(manifest.get("stripPayloadFields"), Mapping):
        for kind, fields in manifest["stripPayloadFields"].items():
            strip_payload_fields[str(kind)] = set(fields or ())

    keep_set = _metahook_manifest_keep_set(manifest, raw_records, game_version) if manifest else None

    kept_records: list[dict[str, Any]] = []
    used_modules: list[str] = []
    seen_modules: set[str] = set()
    for record in raw_records:
        if keep_set is not None:
            key = (str(record.get("module", "engine")), str(record.get("symbolName", "")))
            if key not in keep_set:
                continue
        pruned = _prune_record_for_metahook(
            record,
            strip_record_fields=strip_record_fields,
            strip_payload_fields=strip_payload_fields,
        )
        kept_records.append(pruned)
        mod = pruned.get("module")
        if isinstance(mod, str) and mod not in seen_modules:
            seen_modules.add(mod)
            used_modules.append(mod)

    allowed_top = set(METAHOOK_CONSUMED_TOP_LEVEL_FIELDS) - strip_top_level_fields
    pruned_doc: dict[str, Any] = {}
    if "schemaVersion" in allowed_top and "schemaVersion" in dataset:
        pruned_doc["schemaVersion"] = dataset["schemaVersion"]

    source = dataset.get("source")
    if "source" in allowed_top and isinstance(source, Mapping):
        allowed_source = set(METAHOOK_CONSUMED_SOURCE_FIELDS) - strip_top_level_fields
        pruned_source: dict[str, Any] = {
            field: source[field]
            for field in METAHOOK_CONSUMED_SOURCE_FIELDS
            if field in allowed_source and field in source
        }
        if isinstance(source.get("gameVersion"), str):
            pruned_source["gameVersion"] = source["gameVersion"]
        pruned_doc["source"] = pruned_source

    binaries = dataset.get("binaries")
    if "binaries" in allowed_top and isinstance(binaries, Mapping):
        pruned_binaries: dict[str, Any] = {}
        for mod in used_modules:
            mod_entry = binaries.get(mod)
            if not isinstance(mod_entry, Mapping):
                continue
            pruned_plats: dict[str, Any] = {}
            for plat, plat_entry in mod_entry.items():
                if not isinstance(plat_entry, Mapping) or not isinstance(plat_entry.get("crc64"), str):
                    continue
                pruned_plat: dict[str, Any] = {"crc64": plat_entry["crc64"]}
                if "alias" in plat_entry:
                    pruned_plat["alias"] = plat_entry["alias"]
                pruned_plats[str(plat)] = pruned_plat
            if pruned_plats:
                pruned_binaries[mod] = pruned_plats
        pruned_doc["binaries"] = pruned_binaries

    if "records" in allowed_top:
        pruned_doc["records"] = kept_records

    return pruned_doc


def export_gamedata_json(
    *,
    artifacts_dir: Path,
    config_path: Path,
    module_name: str,
    binary_path: Path,
    platform: str,
    game_version: str,
    output_json_path: Path,
    reference_dir: Path | None = None,
    write_index: bool = True,
    gamedata_format: str = "upstream",
    metahook_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Export Schema-5 gamedata dataset JSON (+ Schema-4 index.json) in upstream or MetaHookSv runtime format."""
    if gamedata_format not in ("upstream", "metahook"):
        raise ValueError(f"Unsupported gamedata_format: {gamedata_format!r}")
    if metahook_manifest_path is not None and gamedata_format != "metahook":
        raise ValueError("--metahook-manifest requires --gamedata-format metahook")

    # Allow passing a directory (or extensionless path) in metahook mode -> <dir>/<game_version>.json.
    resolved_output = output_json_path
    if gamedata_format == "metahook" and (resolved_output.is_dir() or resolved_output.suffix.lower() != ".json"):
        resolved_output = resolved_output / f"{game_version}.json"

    bin_hashes = hash_file(binary_path)
    binary_entry = {
        "crc32": bin_hashes["crc32"],
        "crc64": bin_hashes["crc64"],
        "isBlob": False,
        "md5": bin_hashes["md5"],
        "sha256": bin_hashes["sha256"],
        "size": bin_hashes["size"],
    }

    records: list[dict[str, Any]] = []
    suffix = f".{platform}.yaml"
    for yaml_path in sorted(artifacts_dir.glob(f"*{suffix}")):
        artifact = yaml_path.name[: -len(suffix)]
        payload = load_yaml_file(yaml_path)
        payload = {k: v for k, v in payload.items() if not k.startswith("_")}
        # Align canonical symbol identity fields with reference artifacts when provided so
        # consumers looking up by symbolName (e.g. cls.state, BaseUISurface::PaintTraverse(...)) match directly.
        if reference_dir is not None:
            ref_path = reference_dir / yaml_path.name
            if ref_path.is_file():
                ref_data = load_yaml_file(ref_path)
                for id_key in (
                    "func_name",
                    "gv_name",
                    "patch_name",
                    "scalar_name",
                    "vtable_class",
                    "struct_name",
                    "member_name",
                ):
                    if id_key in payload and isinstance(ref_data.get(id_key), str) and ref_data[id_key].strip():
                        payload[id_key] = ref_data[id_key]
        record_id = f"{module_name}/{yaml_path.name}"
        records.append(
            {
                "artifact": artifact,
                "id": record_id,
                "kind": _symbol_kind(payload),
                "module": module_name,
                "payload": payload,
                "platform": platform,
                "symbolName": _symbol_name(payload, artifact),
            }
        )

    records.sort(key=lambda item: item["id"])
    publish_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    config_sha = f"sha256:{sha256_file(config_path)}"
    dataset = {
        "binaries": {module_name: {platform: binary_entry}},
        "modules": [
            {
                "count": len(records),
                "linuxCount": len(records) if platform == "linux" else 0,
                "name": module_name,
                "windowsCount": len(records) if platform == "windows" else 0,
            }
        ],
        "records": records,
        "schemaVersion": DATASET_SCHEMA_VERSION,
        "source": {
            "analysisOutputContractVersion": 3,
            "configDigestVersion": 2,
            "configSha256": config_sha,
            "fileCount": len(records),
            "gameVersion": game_version,
            "lastPublishTime": publish_time,
            "snapshotSchemaVersion": REQUIRED_SNAPSHOT_SCHEMA_VERSION,
        },
    }

    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    if gamedata_format == "metahook":
        manifest_doc: dict[str, Any] | None = None
        if metahook_manifest_path is not None:
            manifest_doc = json.loads(metahook_manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest_doc, dict) or manifest_doc.get("schemaVersion") != 1:
                raise ValueError(f"Unsupported MetaHook manifest (expected schemaVersion 1): {metahook_manifest_path}")
        emitted_doc = prune_dataset_for_metahook(dataset, game_version=game_version, manifest=manifest_doc)
        raw = _serialize_metahook_json(emitted_doc)
        resolved_output.write_bytes(raw)
        emitted_record_count = len(emitted_doc.get("records") or ())
    else:
        raw = canonical_json_bytes(dataset)
        write_canonical_json(resolved_output, dataset)
        emitted_record_count = len(records)

    digest = sha256_bytes(raw)
    result: dict[str, Any] = {
        "format": gamedata_format,
        "gamedata_json": str(resolved_output),
        "sha256": digest,
        "size": len(raw),
        "record_count": emitted_record_count,
        "binary": binary_entry,
    }
    if write_index:
        index_path = resolved_output.parent / "index.json"
        if gamedata_format == "metahook":
            index_doc = {
                "schemaVersion": INDEX_SCHEMA_VERSION,
                "versions": [
                    {
                        "gameVersion": game_version,
                        "url": resolved_output.name,
                        "sha256": digest,
                        "size": len(raw),
                        "snapshotSchemaVersion": REQUIRED_SNAPSHOT_SCHEMA_VERSION,
                        "fileCount": emitted_record_count,
                        "lastPublishTime": publish_time,
                    }
                ],
            }
            index_path.write_bytes(_serialize_metahook_json(index_doc))
        else:
            index_doc = {
                "schemaVersion": INDEX_SCHEMA_VERSION,
                "versions": [
                    {
                        "fileCount": emitted_record_count,
                        "gameVersion": game_version,
                        "lastPublishTime": publish_time,
                        "sha256": digest,
                        "size": len(raw),
                        "snapshotSchemaVersion": REQUIRED_SNAPSHOT_SCHEMA_VERSION,
                        "url": resolved_output.name,
                    }
                ],
            }
            write_canonical_json(index_path, index_doc)
        result["index_json"] = str(index_path)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate per-symbol VibeSignatures YAML from PDB/DWARF + IDA-MCP.")
    parser.add_argument(
        "--config", required=True, type=Path, help="Game version config YAML (e.g. configs/svencoop-10257.yaml)"
    )
    parser.add_argument(
        "--gamever", default=None, help="Game version tag for gamedata.json (defaults to --config stem)"
    )
    parser.add_argument("--module", default="engine", help="Module name in config (default: engine)")
    parser.add_argument(
        "--platform",
        choices=("windows", "linux"),
        default=None,
        help="Target platform (inferred from binary if omitted)",
    )
    parser.add_argument("--binary", required=True, type=Path, help="Path to target DLL or SO")
    parser.add_argument(
        "--pdb", type=Path, default=None, help="Path to matching PDB (Windows; defaults to sibling .pdb)"
    )
    parser.add_argument("--dwarf", type=Path, default=None, help="Path to DWARF file (Linux; defaults to --binary)")
    parser.add_argument(
        "--module-config",
        "--aliases",
        dest="module_config",
        type=Path,
        default=None,
        help="External module extraction config YAML (defaults to goldsrc-reverse/configs/<gamever>.<module>.yaml if present)",
    )
    parser.add_argument("--output-dir", required=True, type=Path, help="Output directory for generated symbol YAMLs")
    parser.add_argument(
        "--emit-gamedata-json",
        type=Path,
        default=None,
        help="Also export Schema-5 gamedata JSON + Schema-4 index.json (in metahook mode, a directory writes <gamever>.json)",
    )
    parser.add_argument(
        "--gamedata-format",
        choices=("upstream", "metahook"),
        default="upstream",
        help="Gamedata JSON schema style: upstream (full dataset) or metahook (pruned runtime format)",
    )
    parser.add_argument(
        "--metahook-manifest",
        type=Path,
        default=None,
        help="Optional MetaHook consumer manifest JSON (schemaVersion 1) to filter symbols when --gamedata-format=metahook",
    )
    parser.add_argument(
        "--export-only",
        action="store_true",
        help="Skip IDA/PDB extraction and only export gamedata.json from --output-dir",
    )
    parser.add_argument("--report", type=Path, default=None, help="Path for JSON diagnostics report")
    parser.add_argument(
        "--reference-dir", type=Path, default=None, help="Optional reference artifact dir for schema comparison"
    )
    parser.add_argument("--symbols", default=None, help="Comma-separated subset of symbol names to process")
    parser.add_argument("--mcp-host", default="127.0.0.1", help="IDA-MCP host (default: 127.0.0.1)")
    parser.add_argument(
        "--mcp-port", type=int, default=None, help="Attach to existing IDA-MCP port; omit to auto-start idalib-mcp"
    )
    parser.add_argument("--no-verify-guid", action="store_true", help="Skip PE/PDB GUID+Age verification")
    parser.add_argument(
        "--dry-run", action="store_true", help="Run offline PDB/DWARF symbol resolution only (no IDA-MCP)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    binary_path = args.binary.resolve()
    bin_info = inspect_binary(binary_path)
    platform = args.platform or bin_info.platform
    if platform != bin_info.platform:
        raise ValueError(f"Platform mismatch: --platform={platform}, binary is {bin_info.platform}")
    game_version = args.gamever or args.config.stem

    if args.export_only:
        if args.emit_gamedata_json is None:
            raise ValueError("--export-only requires --emit-gamedata-json")
        exported = export_gamedata_json(
            artifacts_dir=args.output_dir,
            config_path=args.config,
            module_name=args.module,
            binary_path=binary_path,
            platform=platform,
            game_version=game_version,
            output_json_path=args.emit_gamedata_json,
            reference_dir=args.reference_dir,
            gamedata_format=args.gamedata_format,
            metahook_manifest_path=args.metahook_manifest,
        )
        print(json.dumps(exported, indent=2, ensure_ascii=False))
        return 0

    module_config_path = args.module_config
    if module_config_path is None:
        default_config = SCRIPT_DIR / "configs" / f"{game_version}.{args.module}.yaml"
        if default_config.is_file():
            module_config_path = default_config
    aliases = load_yaml_file(module_config_path)
    if overrides := aliases.get(f"{platform}_gv_aliases"):
        aliases["gv_aliases"] = {**aliases.get("gv_aliases", {}), **overrides}
    symbols = load_module_symbols(args.config, args.module, platform)
    if args.symbols:
        wanted = {s.strip() for s in args.symbols.split(",") if s.strip()}
        symbols = [s for s in symbols if s["name"] in wanted]

    if platform == "windows":
        pdb_path = (args.pdb or binary_path.with_suffix(".pdb")).resolve()
        print(f"[Index] Loading PDB: {pdb_path}")
        index: BaseDebugIndex = PdbDebugIndex(binary_path, pdb_path, verify_guid=not args.no_verify_guid)
    else:
        dwarf_path = (args.dwarf or binary_path).resolve()
        print(f"[Index] Loading ELF+DWARF: {dwarf_path}")
        index = ElfDwarfDebugIndex(binary_path, dwarf_path)

    if args.dry_run:
        report = _run_dry_probe(symbols, index, aliases, platform)
    elif args.mcp_port is not None:

        async def _attach_run():
            async with open_ida_mcp_session(args.mcp_host, args.mcp_port, expected_binary=binary_path) as session:
                return await _emit_with_mcp(
                    session,
                    symbols=symbols,
                    index=index,
                    aliases=aliases,
                    platform=platform,
                    output_dir=args.output_dir,
                    reference_dir=args.reference_dir,
                )

        report = asyncio.run(_attach_run())
    else:
        port = _allocate_local_port(args.mcp_host)
        print(f"[MCP] Starting owned idalib-mcp on {args.mcp_host}:{port} for {binary_path}")
        with IdaMcpLifecycle(
            str(binary_path),
            platform,
            args.mcp_host,
            port,
            ida_args="",
            debug=args.debug,
            database_policy=DATABASE_POLICY_REBUILD,
            save_on_success=True,
        ) as lifecycle:

            async def _owned_run():
                async with open_ida_mcp_session(args.mcp_host, lifecycle.port, expected_binary=binary_path) as session:
                    return await _emit_with_mcp(
                        session,
                        symbols=symbols,
                        index=index,
                        aliases=aliases,
                        platform=platform,
                        output_dir=args.output_dir,
                        reference_dir=args.reference_dir,
                    )

            report = run_mcp_operation(_owned_run())

    if args.emit_gamedata_json is not None and not args.dry_run:
        report["gamedata_export"] = export_gamedata_json(
            artifacts_dir=args.output_dir,
            config_path=args.config,
            module_name=args.module,
            binary_path=binary_path,
            platform=platform,
            game_version=game_version,
            output_json_path=args.emit_gamedata_json,
            reference_dir=args.reference_dir,
            gamedata_format=args.gamedata_format,
            metahook_manifest_path=args.metahook_manifest,
        )

    report_path = args.report or (args.output_dir / f"generation-report.{platform}.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"\n=== Summary ({platform}) ===")
    tot_ok = tot_fail = tot_skip = 0
    for cat in ("func", "gv", "vtable", "vfunc", "structmember", "scalar", "patch"):
        c = report["counts"].get(cat)
        if not c:
            continue
        ok, fail, skip = c["ok"], c["failed"], c["skipped"]
        tot_ok += ok
        tot_fail += fail
        tot_skip += skip
        print(f"  {cat:13s}: ok={ok:3d}  failed={fail:3d}  skipped={skip:3d}")
    print(f"  {'TOTAL':13s}: ok={tot_ok:3d}  failed={tot_fail:3d}  skipped={tot_skip:3d}")
    print(f"  Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
