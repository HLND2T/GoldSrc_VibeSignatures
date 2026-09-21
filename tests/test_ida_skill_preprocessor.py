from __future__ import annotations

import ast
import asyncio
import io
import json
import math
import os
import struct
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, call, patch

import yaml

import ida_analyze_util
import ida_skill_preprocessor
from analysis_config import AnalysisConfigError
from ida_analyze_util import (
    _build_func_xref_py_eval,
    _build_llm_function_export_py_eval,
    _call_llm_for_targets,
    _export_llm_function,
    _inspect_function_via_mcp,
    _llm_entry_instruction_is_valid,
    _normalize_llm_decompile_specs,
    _prepare_llm_context,
    _preprocess_llm_target,
    _resolve_llm_template,
    _resolve_reference_resource,
    canonical_symbol_yaml_bytes,
    _gv_resolution_fields,
    parse_mcp_result,
    preprocess_common_skill,
    preprocess_func_sig_via_mcp,
    preprocess_func_xrefs_via_mcp,
    preprocess_index_based_vfunc_via_mcp,
)
from ida_preprocessor_scripts._indirect_vcall_target_common import preprocess_indirect_vcall_target_skill
from ida_preprocessor_scripts._client_portal_offsets import recover_portal_offsets
from ida_preprocessor_scripts._ordinal_vtable_common import preprocess_ordinal_vtable_via_mcp
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
    _normalize_preprocess_status,
    _parse_image_base,
    preprocess_single_skill_via_mcp,
)


@asynccontextmanager
async def _bound_session(session):
    yield session


def _image_base_result(value="0x400000"):
    return SimpleNamespace(structuredContent={"result": value}, content=[], isError=False)


class UnicodeStringScanTests(unittest.TestCase):
    def _scan_namespace(self, min_length, *, fail_unicode=False):
        options = SimpleNamespace(
            strtypes=[0], minlen=3, only_7bit=False, ignore_heads=True, display_only_existing_strings=True
        )
        cache = [None]

        class StringItem:
            def __init__(self, text, ea):
                self.text, self.ea = text, ea

            def __str__(self):
                return self.text

        class Strings:
            # Model IDA's shared options/list, including setup's default values.
            def __init__(self, default_setup=False):
                if default_setup:
                    self.setup()

            def setup(
                self,
                strtypes=(0,),
                minlen=5,
                only_7bit=True,
                ignore_instructions=False,
                display_only_existing_strings=False,
            ):
                options.strtypes = list(strtypes)
                options.minlen = minlen
                options.only_7bit = only_7bit
                options.ignore_heads = ignore_instructions
                options.display_only_existing_strings = display_only_existing_strings

            def __iter__(self):
                if 1 in options.strtypes:
                    if fail_unicode:
                        raise RuntimeError("string enumeration failed")
                    return iter([StringItem("wide anchor", 0x5000)])
                return iter([StringItem("Cache_Alloc: size %i", 0x6000)])

        tree = ast.parse(_build_func_xref_py_eval({}, 0))
        helpers = {"_string_items", "_string_candidates", "_unicode_string_items", "_unicode_string_candidates"}
        namespace = {
            "spec": {"string_min_length": min_length},
            "json": json,
            "idautils": SimpleNamespace(Strings=Strings),
            "ida_nalt": SimpleNamespace(STRTYPE_C=0, STRTYPE_C_16=1),
            "ida_strlist": SimpleNamespace(get_strlist_options=lambda: options),
            "ida_netnode": SimpleNamespace(
                netnode=lambda *_args: SimpleNamespace(
                    valobj=lambda: cache[0], set=lambda value: cache.__setitem__(0, value)
                )
            ),
            "UNICODE_STRING_TYPES": [1],
            "unicode_strings_without_owner": [],
            "_functions_referencing": lambda ea: {0x401000 if ea == 0x5000 else 0x402000},
        }
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in helpers]
        exec(  # noqa: S102 - execute the production-generated string scan helpers.
            compile(ast.Module(body=nodes, type_ignores=[]), "<string-scans>", "exec"), namespace
        )
        return namespace, options, cache

    def test_unicode_scan_preserves_following_ascii_scans_and_cached_options(self):
        for min_length in (None, 7):
            with self.subTest(min_length=min_length):
                namespace, options, cache = self._scan_namespace(min_length)
                ascii_scan = lambda: namespace["_string_candidates"]("FULLMATCH:Cache_Alloc: size %i")
                self.assertEqual({0x402000}, ascii_scan())
                before_options, before_cache = dict(vars(options)), cache[0]
                for _ in range(2):
                    self.assertEqual({0x401000}, namespace["_unicode_string_candidates"]("FULLMATCH:wide anchor"))
                    self.assertEqual(before_options, vars(options))
                    self.assertEqual(before_cache, cache[0])
                    # Custom finders enumerate the shared list without the ASCII helper.
                    self.assertEqual(["Cache_Alloc: size %i"], [str(item) for item in namespace["idautils"].Strings()])
                    self.assertEqual({0x402000}, ascii_scan())

    def test_unicode_enumeration_failure_restores_shared_options(self):
        namespace, options, cache = self._scan_namespace(None, fail_unicode=True)
        before_options = dict(vars(options))
        with self.assertRaisesRegex(RuntimeError, "string enumeration failed"):
            namespace["_unicode_string_candidates"]("wide anchor")
        self.assertEqual(before_options, vars(options))
        self.assertIsNone(cache[0])
        self.assertEqual({0x402000}, namespace["_string_candidates"]("Cache_Alloc: size %i"))


class GLShutdownAnchorScanTests(unittest.TestCase):
    def _anchor_owners(self, *, fail_readonly=False):
        datarefs_seen = []

        class Segment:
            def __init__(self, start_ea, end_ea, name, perm):
                self.start_ea, self.end_ea, self.name, self.perm = start_ea, end_ea, name, perm

        # .rdata holds one true literal at offset 1 (preceded by NUL) and one
        # embedded in a longer literal (preceded by 'x'); .data holds the same
        # writable copy the old Windows hw.dll family really stores; the
        # exec-only .text copy must never be scanned.
        blob = b"\x00Sys_Shutdown()\x00prefixSys_Shutdown()\x00"
        seg_rdata = Segment(0x1000, 0x1000 + len(blob), ".rdata", 4)
        seg_data = Segment(0x8000, 0x8020, ".data", 6)
        seg_text = Segment(0x400000, 0x400040, ".text", 1)

        def getseg(ea):
            for seg in (seg_rdata, seg_data, seg_text):
                if seg.start_ea <= ea < seg.end_ea:
                    return seg
            return None

        def data_refs_to(ea):
            datarefs_seen.append(ea)
            return [0x5000 + ea]

        def get_bytes(ea, count):
            if ea == seg_rdata.start_ea:
                if fail_readonly:
                    raise RuntimeError("segment read failed")
                return blob
            if ea == seg_data.start_ea:
                return b"Sys_Shutdown()\x00"
            return b"Sys_Shutdown()\x00"

        finder_path = Path(__file__).resolve().parent.parent / "ida_preprocessor_scripts" / "find-GL_Shutdown.py"
        tree = ast.parse(finder_path.read_text(encoding="utf-8"))
        locate_py = next(
            node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "LOCATE_PY" for t in node.targets)
        )
        locate_tree = ast.parse(locate_py)
        anchors = [
            node
            for node in locate_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "anchor_string_owners"
        ]
        self.assertEqual(1, len(anchors))
        # No idautils.Strings is provided on purpose: the anchor scan must not
        # touch the shared string list, whose setup() rebuild is IDB-wide
        # state (a minlen=6 rebuild hid Mod_LoadStudioModel's 5-char "bogus"
        # anchor from later skills in PR CI).
        namespace = {
            "ANCHOR_STRING": "Sys_Shutdown()",
            "idautils": SimpleNamespace(
                Segments=lambda: [seg_text.start_ea, seg_rdata.start_ea, seg_data.start_ea],
                DataRefsTo=data_refs_to,
            ),
            "ida_segment": SimpleNamespace(getseg=getseg, get_segm_name=lambda seg: seg.name),
            "ida_bytes": SimpleNamespace(get_bytes=get_bytes),
            "func_start": lambda ea: 0x1000 + ea,
        }
        exec(  # noqa: S102 - execute the production anchor scan in isolation.
            compile(ast.Module(body=anchors, type_ignores=[]), "<gl-shutdown-anchor>", "exec"), namespace
        )
        return namespace["anchor_string_owners"](), datarefs_seen

    def test_anchor_scan_reads_readable_segments_without_shared_string_list(self):
        owners, datarefs_seen = self._anchor_owners()
        # Standalone literals resolve owners (.rdata offset 1 and the writable
        # .data copy); the embedded occurrence and the exec-only copy do not.
        self.assertEqual([0x1000 + 0x5000 + 0x1001, 0x1000 + 0x5000 + 0x8000], owners)
        self.assertEqual([0x1001, 0x8000], datarefs_seen)

    def test_anchor_scan_survives_segment_read_failure(self):
        owners, datarefs_seen = self._anchor_owners(fail_readonly=True)
        self.assertEqual([0x1000 + 0x5000 + 0x8000], owners)
        self.assertEqual([0x8000], datarefs_seen)


class FloatFilterBehaviorTests(unittest.TestCase):
    FLOAT_FILTER_HELPERS = {
        "_scalar_float_kind",
        "_has_xmm_operand",
        "_is_readonly_float_segment",
        "_is_readonly_float_segment_name",
        "_float_fallback_owners",
        "_float_matches",
        "_float_read_width",
        "_function_matches_float_filters",
    }

    def _matches(self, mnemonic, width, blob, required, excluded=(), *, decoded=True):
        nodes = self._float_filter_nodes(with_constants=True)
        operand = SimpleNamespace(dtype=width)
        namespace = {
            "math": math,
            "struct": struct,
            "idc": SimpleNamespace(
                o_mem=2,
                o_displ=4,
                o_phrase=3,
                print_insn_mnem=lambda ea: mnemonic,
                print_operand=lambda ea, index: "xmm0" if index == 1 else "pool",
                get_operand_type=lambda ea, index: 2 if index == 0 else 0,
                get_operand_value=lambda ea, index: 0x2000,
            ),
            "ida_ua": SimpleNamespace(
                insn_t=lambda: SimpleNamespace(ops=[operand]),
                decode_insn=lambda insn, ea: 6 if decoded else 0,
                get_dtype_size=lambda dtype: dtype,
            ),
            "ida_segment": SimpleNamespace(getseg=lambda ea: object(), get_segm_name=lambda seg: ".rdata"),
            "idautils": SimpleNamespace(
                FuncItems=lambda start: [0x1000], Segments=lambda: (), DataRefsTo=lambda ea: ()
            ),
            "ida_bytes": SimpleNamespace(get_bytes=lambda ea, count: blob[:count]),
        }
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<float-filters>", "exec"), namespace)
        return namespace["_function_matches_float_filters"](0x1000, required, excluded)

    def _float_filter_nodes(self, *, with_constants):
        tree = ast.parse(_build_func_xref_py_eval({}, 0))
        constants = {
            "SINGLE_FLOAT_MNEMS",
            "DOUBLE_FLOAT_MNEMS",
            "X87_FLOAT_MNEMS",
            "MEMORY_OPERAND_TYPES",
            "_FLOAT_FALLBACK_OWNERS_CACHE",
        }
        return [
            node
            for node in tree.body
            if (isinstance(node, ast.FunctionDef) and node.name in self.FLOAT_FILTER_HELPERS)
            or (
                with_constants
                and isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets)
            )
        ]

    def _matches_got(self, required, pool_blob, *, owner_hit=True, excluded=None):
        # GOT fallback exercise: the float instruction's operands decode to
        # no constant address (operand type o_void), so only the stored-
        # constant xref path can match. The fld dtype mirrors the stored
        # instance width, as a real fldl/flds decode would.
        width = len(pool_blob) if len(pool_blob) in (4, 8) else 8
        nodes = self._float_filter_nodes(with_constants=True)
        namespace = {
            "math": math,
            "struct": struct,
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=0x1000)),
            "idc": SimpleNamespace(
                o_mem=2,
                o_displ=4,
                o_phrase=3,
                print_insn_mnem=lambda ea: "fld",
                print_operand=lambda ea, index: "st(0)",
                get_operand_type=lambda ea, index: 0,
            ),
            "ida_ua": SimpleNamespace(
                insn_t=lambda: SimpleNamespace(ops=[SimpleNamespace(type=4, dtype=width)]),
                decode_insn=lambda insn, ea: 6,
                get_dtype_size=lambda dtype: dtype,
            ),
            "ida_segment": SimpleNamespace(
                getseg=lambda ea: SimpleNamespace(start_ea=0x3000, end_ea=0x3100),
                get_segm_name=lambda seg: ".rodata",
            ),
            "idautils": SimpleNamespace(
                FuncItems=lambda start: [0x1000],
                Segments=lambda: [0x3000],
                DataRefsTo=lambda ea: [0x1000] if owner_hit else [],
            ),
            "ida_bytes": SimpleNamespace(get_bytes=lambda ea, count: pool_blob),
        }
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<float-filters>", "exec"), namespace)
        return namespace["_function_matches_float_filters"](0x1000, required, excluded or [])

    def test_got_fallback_matches_stored_constant_reference(self):
        self.assertTrue(self._matches_got([0.004], struct.pack("<f", 0.004)))
        self.assertTrue(self._matches_got([20.0], struct.pack("<d", 20.0)))

    def test_got_fallback_still_requires_the_function_reference(self):
        pool = struct.pack("<f", 0.004)
        self.assertFalse(self._matches_got([0.004], pool, owner_hit=False))
        self.assertFalse(self._matches_got([0.5], pool))

    def test_got_fallback_rejects_double_reader_for_its_low_float_word(self):
        # The only reference is fld qword [double_1023]; the low word of the
        # f64 encoding reinterprets as float 0.0 and must not credit the
        # function with a float 0.0 reference, while the double itself does.
        pool = struct.pack("<d", 1023.0)
        self.assertFalse(self._matches_got([0.0], pool))
        self.assertTrue(self._matches_got([1023.0], pool))

    def test_got_fallback_applies_excluded_constants(self):
        # A forbidden constant reached only through the stored-instance xref
        # must exclude the candidate through the same resolution path.
        pool = struct.pack("<f", 0.004)
        self.assertFalse(self._matches_got([0.004], pool, excluded=[0.004]))

    def test_x87_double_does_not_also_reference_its_low_float_word(self):
        blob = struct.pack("<d", 1023.0)
        self.assertFalse(self._matches("fld", 8, blob, [0.0]))
        self.assertTrue(self._matches("fld", 8, blob, [1023.0], [0.0]))

    def test_x87_float_reads_only_its_four_bytes(self):
        self.assertTrue(self._matches("fmul", 4, struct.pack("<f", 0.875), [0.875]))
        blob = struct.pack("<d", 1023.0)
        self.assertFalse(self._matches("fld", 4, blob, [1023.0]))

    def test_x87_bad_decode_unsupported_width_and_truncation_fail_closed(self):
        blob = struct.pack("<d", 1023.0)
        for width, data, decoded in ((10, blob, True), (8, blob[:4], True), (8, blob, False)):
            with self.subTest(width=width, decoded=decoded):
                self.assertFalse(self._matches("fld", width, data, [1023.0], decoded=decoded))

    def test_sse_and_x87_required_and_excluded_constants(self):
        for mnemonic, width, fmt in (("mulss", 4, "<f"), ("mulsd", 8, "<d"), ("fld", 4, "<f"), ("fdiv", 8, "<d")):
            with self.subTest(mnemonic=mnemonic, width=width):
                blob = struct.pack(fmt, 0.875)
                self.assertTrue(self._matches(mnemonic, width, blob, [0.875]))
                self.assertFalse(self._matches(mnemonic, width, blob, [0.875], [0.875]))
                self.assertFalse(self._matches(mnemonic, width, blob, [0.075]))


class PortalOffsetBehaviorTests(unittest.TestCase):
    @staticmethod
    def reg(name, size=4):
        return {"kind": "reg", "reg": name, "size": size}

    @staticmethod
    def mem(base, disp=0):
        return {"kind": "mem", "base": base, "disp": disp, "size": 4}

    @staticmethod
    def imm(value):
        return {"kind": "imm", "value": value, "size": 4}

    @staticmethod
    def ins(mnemonic, *operands, successors=()):
        writes = []
        if operands and operands[0]["kind"] == "reg" and mnemonic in {"mov", "lea", "xor", "add", "sub", "pop"}:
            writes = [operands[0]["reg"]]
        return {"mnemonic": mnemonic, "operands": list(operands), "writes": writes, "successors": successors}

    def api(self, name):
        return self.ins("call", {"kind": "api", "name": name, "size": 4})

    def vector(self, platform="windows", begin=140):
        r, m, c, i = self.reg, self.mem, self.imm, self.ins
        prefix = [i("mov", r("ebx"), r("ecx"))]
        if platform == "linux":
            prefix = [i("push", r("ebp")), i("sub", r("esp"), c(32)), i("mov", r("ebx"), m("esp", 40))]
        return prefix + [
            i("mov", r("esi"), m("ebx", begin)),
            i("mov", r("eax"), m("ebx", begin + 4)),
            i("cmp", r("esi"), r("eax")),
            i("jz", successors=(len(prefix) + 4,)),
            i("mov", r("edi"), m("esi")),
        ]

    def texture(self, offset=204):
        r, m, c, i = self.reg, self.mem, self.imm, self.ins
        return [
            i("cmp", m("ebx", offset), c(0)),
            i("lea", r("esi"), m("ebx", offset)),
            i("push", r("esi")),
            i("push", c(1)),
            self.api("glGenTextures"),
            i("push", c(0xDE1)),
            self.api("glEnable"),
            i("push", m("esi")),
            i("push", c(0xDE1)),
            self.api("glBindTexture"),
            i("push", c(0)),
            i("push", c(0x1400)),
            i("push", c(0x1908)),
            i("push", c(0)),
            i("push", m("ebx", offset + 8)),
            i("push", m("ebx", offset + 4)),
            i("push", c(0x1908)),
            i("push", c(0)),
            i("push", c(0xDE1)),
            self.api("glTexImage2D"),
        ]

    def test_recovers_platform_specific_vector_from_this_argument(self):
        self.assertEqual(
            {"vector_begin": 132, "vector_end": 136}, recover_portal_offsets(self.vector("linux", 132), "linux")
        )
        # Synthetic offsets deliberately differ from the shipped build.
        self.assertEqual(
            {"vector_begin": 64, "vector_end": 68, "texture_id": 96, "texture_width": 100, "texture_height": 104},
            recover_portal_offsets(self.vector(begin=64) + self.texture(96), "windows"),
        )

    def test_vector_rejects_unrelated_base_clobber_missing_iteration_and_ambiguity(self):
        i, r, m, c = self.ins, self.reg, self.mem, self.imm
        invalid = []
        code = self.vector()
        code[0] = i("mov", r("ebx"), r("edx"))
        invalid.append(code)
        code = self.vector()
        code.insert(3, i("xor", r("esi"), r("esi")))
        invalid.append(code)
        invalid.append(self.vector()[:-1])
        code = self.vector() + self.vector(begin=40)[1:]
        code[-2]["successors"] = (len(code) - 1,)
        invalid.append(code)
        for code in invalid:
            with self.subTest(code=code), self.assertRaises(ValueError):
                recover_portal_offsets(code + self.texture(), "windows")

    def test_texture_rejects_unrelated_pushes_without_gl_calls(self):
        i, r, m, c = self.ins, self.reg, self.mem, self.imm
        code = self.vector() + [
            i("cmp", m("ebx", 204), c(0)),
            i("lea", r("esi"), m("ebx", 204)),
            i("push", m("edi", 212)),
            i("push", m("eax", 208)),
        ]
        with self.assertRaises(ValueError):
            recover_portal_offsets(code, "windows")

    def test_vector_branch_paths_cannot_borrow_this_from_dead_code(self):
        code = self.vector()
        # Skip the only assignment carrying the this argument to ebx.
        code.insert(0, self.ins("jmp", successors=(2,)))
        code[-2]["successors"] = (len(code) - 1,)
        with self.assertRaises(ValueError):
            recover_portal_offsets(code + self.texture(), "windows")

    def test_texture_requires_same_object_argument_order_and_complete_call_chain(self):
        i, r, m, c = self.ins, self.reg, self.mem, self.imm
        for index, replacement in (
            (2, i("push", r("edi"))),
            (3, i("push", c(2))),
            (4, self.api("unrelated")),
            (7, i("push", m("edi"))),
            (9, self.api("unrelated")),
            (14, i("push", m("edi", 212))),
            (15, i("push", m("eax", 208))),
            (19, self.api("unrelated")),
        ):
            code = self.texture()
            code[index] = replacement
            with self.subTest(index=index), self.assertRaises(ValueError):
                recover_portal_offsets(self.vector() + code, "windows")
        code = self.texture()
        code[14], code[15] = code[15], code[14]
        with self.assertRaises(ValueError):
            recover_portal_offsets(self.vector() + code, "windows")

    def test_texture_clobbers_and_conflicting_triples_fail_closed(self):
        for index, register in ((2, "esi"), (7, "esi"), (14, "ebx")):
            code = self.texture()
            code.insert(index, self.ins("xor", self.reg(register), self.reg(register)))
            with self.subTest(index=index), self.assertRaises(ValueError):
                recover_portal_offsets(self.vector() + code, "windows")
        with self.assertRaises(ValueError):
            recover_portal_offsets(self.vector() + self.texture() + self.texture(100), "windows")
        code = self.texture()
        partial_write = self.ins("mov", self.reg("bl", 1), self.imm(0))
        partial_write["writes"] = ["ebx"]
        code.insert(14, partial_write)
        with self.assertRaises(ValueError):
            recover_portal_offsets(self.vector() + code, "windows")
        code = self.texture()
        code.insert(14, self.ins("mul", self.reg("esi")))
        with self.assertRaises(ValueError):
            recover_portal_offsets(self.vector() + code, "windows")

    def test_texture_branch_paths_do_not_share_register_provenance(self):
        code = self.vector()
        start = len(code)
        texture = self.texture()
        # The fallthrough overwrites esi then jumps past the restoring LEA.
        # The taken branch restores esi but exits before the GL sequence.
        branch = [
            self.ins("jz", successors=(start + 3, start + 5)),
            self.ins("xor", self.reg("esi"), self.reg("esi")),
            self.ins("jmp", successors=(start + 7,)),
            self.ins("lea", self.reg("esi"), self.mem("ebx", 204)),
            self.ins("ret"),
        ]
        code += texture[:2] + branch + texture[2:]
        with self.assertRaises(ValueError):
            recover_portal_offsets(code, "windows")
        # Two forward paths retaining the same pointer both prove the triple.
        code = (
            self.vector()
            + texture[:2]
            + [self.ins("jz", successors=(start + 3, start + 4)), self.ins("nop")]
            + texture[2:]
        )
        self.assertEqual(204, recover_portal_offsets(code, "windows")["texture_id"])


class PreprocessStatusTests(unittest.TestCase):
    def test_status_truthiness_and_legacy_normalization(self):
        self.assertTrue(PREPROCESS_STATUS_SUCCESS)
        self.assertTrue(PREPROCESS_STATUS_ABSENT_OK)
        self.assertFalse(PREPROCESS_STATUS_NO_SCRIPT)
        self.assertFalse(PREPROCESS_STATUS_FAILED)
        cases = (
            (True, PREPROCESS_STATUS_SUCCESS),
            ("success", PREPROCESS_STATUS_SUCCESS),
            ("absent_ok", PREPROCESS_STATUS_ABSENT_OK),
            ("no_script", PREPROCESS_STATUS_NO_SCRIPT),
            (False, PREPROCESS_STATUS_FAILED),
            (None, PREPROCESS_STATUS_FAILED),
            ("unexpected", PREPROCESS_STATUS_FAILED),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertIs(expected, _normalize_preprocess_status(raw))

    def test_sdk_snake_case_structured_content_is_unwrapped(self):
        result = SimpleNamespace(
            structuredContent=None,
            structured_content={"result": json.dumps({"pointer_size": 4})},
            content=[],
        )
        self.assertEqual({"pointer_size": 4}, parse_mcp_result(result))

    def test_sdk_snake_case_structured_content_supplies_image_base(self):
        result = SimpleNamespace(
            structuredContent=None,
            structured_content={"result": "0x1d00000"},
            content=[],
        )
        self.assertEqual(0x1D00000, _parse_image_base(result))

    def test_func_xref_py_eval_round_trips_json_only_values(self):
        spec = {"inline_alias": None, "enabled": True, "values": [1, "anchor"]}
        code = _build_func_xref_py_eval(spec, 0x400000)
        spec_line = next(line for line in code.splitlines() if line.startswith("spec = "))
        namespace = {"json": json}
        exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
        self.assertEqual(spec, namespace["spec"])

    def test_func_xref_py_eval_preserves_cs2_semantic_contracts(self):
        code = _build_func_xref_py_eval(
            {
                "func_name": "Target",
                "vtable_entries": [0x401000],
                "allow_across_function_boundary": True,
            },
            0x400000,
        )

        ast.parse(code)
        self.assertIn("FUNCTION_RECOVERY_BACKTRACK_LIMIT", code)
        self.assertIn("return {start for start, count in counts.items() if count == 1}", code)
        self.assertIn("Strings(default_setup=False)", code)
        self.assertIn("strings.setup(strtypes=[ida_nalt.STRTYPE_C]", code)
        self.assertIn("name == '.rdata' or name.startswith('.rodata')", code)
        self.assertIn("required_hits = [False] * len(required_values)", code)
        self.assertIn("required_hits[index] = True", code)
        self.assertIn("return all(required_hits) and not excluded_hit", code)
        self.assertIn("if not callers and dep_start is not None and dep_start in vtable_candidates", code)
        self.assertIn("SIGNATURE_XREF_PROBE_MAX_CANDIDATES = 256", code)
        self.assertIn("def _function_contains_signature(start, signature):", code)
        self.assertIn("range_end=int(func.end_ea)", code)
        self.assertIn("def _signature_candidates(narrowed, signature, match_eas):", code)
        self.assertIn("excluded.update(_named_candidates(value))", code)
        self.assertIn("if spec.get('vtable_entries'):", code)
        self.assertIn("def _try_decode_padding_nop", code)
        self.assertIn("not ida_bytes.is_head(flags)", code)
        self.assertNotIn("if len(tokens) >= max_tokens:\n                break", code)
        self.assertIn("ida_ua.o_displ", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)
        self.assertIn("def _try_decode_padding_nop", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)

    def test_function_owner_recovery_replaces_false_suffix_with_unique_direct_call_entry(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        anchor_ea = 0x401120
        entry_ea = 0x401000
        suffix = SimpleNamespace(start_ea=anchor_ea, end_ea=0x401160)
        recovered = SimpleNamespace(start_ea=entry_ea, end_ea=0x401160)
        calls = []

        def recover(entry, anchor, expected_end, expected_signature):
            calls.append((entry, anchor, expected_end, expected_signature))
            return recovered

        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda ea: suffix if ea == anchor_ea else None),
            "_direct_call_entry_candidates": lambda _anchor, _lower: {entry_ea},
            "_has_data_entry_reference": lambda _entry: False,
            "_recover_function_entry": recover,
            "_function_payload": lambda func, was_recovered, reason: {
                "function_start": int(func.start_ea),
                "function_end": int(func.end_ea),
                "recovered": was_recovered,
                "recovery_reason": reason,
            },
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-owner-recovery>", "exec"),
            namespace,
        )

        result = namespace["_ensure_function_owner"](anchor_ea)

        self.assertEqual(entry_ea, result["function_start"])
        self.assertTrue(result["recovered"])
        self.assertEqual([(entry_ea, anchor_ea, None, None)], calls)

    def test_function_owner_preserves_data_referenced_virtual_entry(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        entry = 0x401100
        existing = SimpleNamespace(start_ea=entry, end_ea=0x401190)
        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda _ea: existing),
            "_has_data_entry_reference": lambda value: value == entry,
            "_direct_call_entry_candidates": lambda *_args: {0x401000, 0x401080},
            "_recover_function_entry": lambda *_args: self.fail("a vtable entry must not be merged with nearby code"),
            "_function_payload": lambda func, recovered, reason: (func.start_ea, recovered),
        }
        exec(
            compile(ast.Module(body=[function_node], type_ignores=[]), "<virtual-entry-recovery>", "exec"),
            namespace,
        )
        self.assertEqual((entry, False), namespace["_ensure_function_owner"](entry))

    def test_exact_function_exclusion_preserves_verified_dependency_entries(self):
        tree = ast.parse(ida_analyze_util._build_func_xref_py_eval({}, 0))
        node = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_exact_function_candidates"
        )
        entry = 0x401100
        namespace = {
            "_named_ea": lambda value: value,
            "_is_executable_address": lambda ea: ea in (entry, entry + 4),
            "ida_funcs": SimpleNamespace(
                get_func=lambda ea: SimpleNamespace(start_ea=entry) if ea in (entry, entry + 4) else None
            ),
            "_function_start": lambda _ea: self.fail("a verified exclusion must not infer a neighboring owner"),
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<exact-function-exclusion>", "exec"), namespace)
        self.assertEqual({entry}, namespace["_exact_function_candidates"]([entry, entry + 4, None, 0x501000]))

    def test_function_owner_recovery_fails_closed_on_ambiguous_entries(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        anchor_ea = 0x401120
        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda _ea: None),
            "_direct_call_entry_candidates": lambda _anchor, _lower: {0x401000, 0x401080},
            "_recover_function_entry": lambda *_args: self.fail("ambiguous recovery must not mutate IDA"),
            "_function_payload": lambda *_args: self.fail("ambiguous recovery must not produce a function"),
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-owner-recovery>", "exec"),
            namespace,
        )

        self.assertIsNone(namespace["_ensure_function_owner"](anchor_ea))

    def test_function_owner_destructive_recovery_requires_external_direct_call(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_recover_function_entry"
        )
        entry_ea = 0x401000
        anchor_ea = 0x401120
        cleanup_end = 0x401160
        add_func_calls = []
        namespace = {
            "FUNCTION_RECOVERY_MAX_SPAN": 0x4000,
            "ida_funcs": SimpleNamespace(
                get_func=lambda _ea: None,
                add_func=lambda *args: add_func_calls.append(args),
            ),
            "_verified_entry_function": lambda *_args: None,
            "_is_executable_address": lambda _ea: True,
            "_signature_matches": lambda _ea, _signature: True,
            "_direct_call_sources": lambda _ea: [anchor_ea],
            "_next_recovery_limit": lambda _entry, _anchor: cleanup_end,
            "_same_executable_segment": lambda *_args: self.fail(
                "internal direct calls must not reach destructive recovery gates"
            ),
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-entry-recovery>", "exec"),
            namespace,
        )

        result = namespace["_recover_function_entry"](entry_ea, anchor_ea, None, None)

        self.assertIsNone(result)
        self.assertEqual([(entry_ea,)], add_func_calls)

    def test_func_xref_float_filters_require_every_xref_and_exclude_any_hit(self):
        code = _build_func_xref_py_eval({"func_name": "Target"}, 0x400000)
        tree = ast.parse(code)
        function_nodes = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in {"_float_matches", "_function_matches_float_filters"}
        ]
        scalar_values = {
            0x5000: 64.0,
            0x5004: 0.5,
            0x5008: 128.0,
        }
        function_items = {
            0x1000: [0x4000],
            0x2000: [0x4000, 0x4004],
            0x3000: [0x4000, 0x4004, 0x4008],
        }
        namespace = {
            "MEMORY_OPERAND_TYPES": {1},
            "ida_bytes": SimpleNamespace(
                get_bytes=lambda target_ea, width: __import__("struct").pack("<f", scalar_values[target_ea])
            ),
            "idautils": SimpleNamespace(FuncItems=lambda start: function_items[start]),
            "idc": SimpleNamespace(
                get_operand_type=lambda _ea, operand_index: 1 if operand_index == 0 else 0,
                get_operand_value=lambda ea, _operand_index: ea + 0x1000,
            ),
            "math": __import__("math"),
            "struct": __import__("struct"),
            "_has_xmm_operand": lambda _ea: True,
            "_is_readonly_float_segment": lambda _ea: True,
            "_scalar_float_kind": lambda _ea: "float",
            "_float_read_width": lambda _ea, _operand_index=None: 4,
            "_float_fallback_owners": lambda _value: set(),
        }
        exec(  # noqa: S102 - executes only selected generated helper definitions.
            compile(ast.Module(body=function_nodes, type_ignores=[]), "<func-xref-floats>", "exec"),
            namespace,
        )
        matches = namespace["_function_matches_float_filters"]

        self.assertFalse(matches(0x1000, [64.0, 0.5], []))
        self.assertTrue(matches(0x2000, [64.0, 0.5], []))
        self.assertFalse(matches(0x3000, [64.0, 0.5], [128.0]))

    def test_func_xref_signature_probes_narrowed_candidates_else_uses_global_matches(self):
        code = _build_func_xref_py_eval({"func_name": "Target"}, 0x400000)
        tree = ast.parse(code)
        wanted = {
            "_address_candidates",
            "_function_contains_signature",
            "_intersected_candidates",
            "_signature_candidates",
        }
        function_nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
        contained = {0x1000: True, 0x2000: False}
        namespace = {
            "SIGNATURE_XREF_PROBE_MAX_CANDIDATES": 256,
            "ida_bytes": SimpleNamespace(
                BIN_SEARCH_FORWARD=1,
                BIN_SEARCH_NOSHOW=2,
                find_bytes=lambda _signature, start, range_end=None, flags=0, radix=16: (
                    start if contained.get(start) else -1
                ),
            ),
            "ida_funcs": SimpleNamespace(
                get_func=lambda start: (
                    SimpleNamespace(start_ea=start, end_ea=start + 0x40) if start in contained else None
                )
            ),
            "idaapi": SimpleNamespace(BADADDR=-1),
            "_function_start": lambda ea: {0x401010: 0x401000, 0x402010: 0x402000}.get(int(ea), int(ea)),
        }
        exec(  # noqa: S102 - executes only selected generated helper definitions.
            compile(ast.Module(body=function_nodes, type_ignores=[]), "<func-xref-signatures>", "exec"),
            namespace,
        )
        select = namespace["_signature_candidates"]
        intersect = namespace["_intersected_candidates"]

        self.assertEqual({0x1000}, select({0x1000, 0x2000}, "AA BB", [0x401010]))
        self.assertEqual({0x401000}, select(set(), "AA BB", [0x401010]))
        self.assertEqual({0x401000}, select(set(range(300)), "AA BB", [0x401010]))
        self.assertEqual({0x1000}, intersect([{0x1000, 0x2000}, {0x1000, 0x3000}]))

    def test_gsvibe_string_min_length_config_matches_cs2_rules(self):
        cases = ((None, None), ("", None), ("0", 4), ("invalid", 4), ("7", 7))
        for raw_value, expected in cases:
            with self.subTest(raw_value=raw_value), patch.dict(os.environ, {}, clear=True):
                if raw_value is not None:
                    os.environ["GSVIBE_STRING_MIN_LENGTH"] = raw_value
                self.assertEqual(expected, ida_analyze_util._resolve_ida_string_min_length_config())


class PreprocessorLoaderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    async def test_missing_script_and_unsafe_name_fail_closed(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(temporary)),
        ):
            missing = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-missing",
                [],
                None,
                temporary,
                "windows",
            )
            unsafe = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "../escape",
                [],
                None,
                temporary,
                "windows",
            )
        self.assertIs(PREPROCESS_STATUS_NO_SCRIPT, missing)
        self.assertIs(PREPROCESS_STATUS_FAILED, unsafe)

    async def test_loader_caches_success_and_rejects_invalid_abi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            counter = root / "imports.txt"
            script = root / "find-cache.py"
            script.write_text(
                "from pathlib import Path\n"
                f"p = Path({str(counter)!r})\n"
                "p.write_text((p.read_text() if p.exists() else '') + 'x')\n"
                "def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, "
                "new_binary_dir, platform, image_base, debug=False):\n"
                "    return True\n",
                encoding="utf-8",
            )
            invalid = root / "find-invalid.py"
            invalid.write_text("def preprocess_skill(session):\n    return True\n", encoding="utf-8")
            session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
            with (
                patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", root),
                patch.object(
                    ida_skill_preprocessor,
                    "open_ida_mcp_session",
                    side_effect=lambda *_args, **_kwargs: _bound_session(session),
                ),
            ):
                first = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-cache", [], None, temporary, "windows"
                )
                second = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-cache", [], None, temporary, "windows"
                )
                invalid_result = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-invalid", [], None, temporary, "windows"
                )
                import_count = counter.read_text(encoding="utf-8")
        self.assertIs(PREPROCESS_STATUS_SUCCESS, first)
        self.assertIs(PREPROCESS_STATUS_SUCCESS, second)
        self.assertEqual("x", import_count)
        self.assertIs(PREPROCESS_STATUS_FAILED, invalid_result)


class PreprocessorDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    async def test_passes_bound_session_image_base_and_opt_in_llm_config(self):
        received = {}

        async def script(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            llm_config,
            debug=False,
        ):
            received.update(locals())
            return "absent_ok"

        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result("0x0")))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ) as open_session,
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [r"D:\out.yaml"],
                {r"D:\out.yaml": r"D:\old.yaml"},
                r"D:\new",
                "windows",
                expected_inputs=[r"D:\input.yaml"],
                optional_inputs=[r"D:\optional.yaml"],
                expected_binary=r"D:\game\hw.dll",
                explicit_database="database-1",
                llm_model="test-model",
                llm_apikey="secret",
                llm_baseurl="https://example.invalid/v1",
                llm_temperature=0.5,
                llm_effort="high",
                llm_fake_as="codex",
                llm_max_retries=4,
                symbol_aliases={"Symbol": ("Alias",)},
                debug=True,
            )
        self.assertIs(PREPROCESS_STATUS_ABSENT_OK, result)
        self.assertIs(session, received["session"])
        self.assertEqual(0, received["image_base"])
        self.assertEqual("secret", received["llm_config"]["api_key"])
        self.assertEqual(4, received["llm_config"]["max_retries"])
        self.assertEqual([r"D:\input.yaml"], received["llm_config"]["_expected_inputs"])
        self.assertEqual({"Symbol": ("Alias",)}, received["llm_config"]["symbol_aliases"])
        open_session.assert_called_once_with(
            "127.0.0.1",
            13337,
            expected_binary=r"D:\game\hw.dll",
            explicit_database="database-1",
        )

    async def test_invalid_image_base_returns_failed_without_running_script(self):
        script = AsyncMock(return_value=True)
        diagnostics = []
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result("not-hex")))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        script.assert_not_awaited()
        self.assertEqual("mcp_failed", diagnostics[-1]["reason"])

    async def test_llm_requires_explicit_parameter_and_unhashable_status_is_rejected(self):
        received = {}

        def script(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            debug=False,
        ):
            received.update(locals())
            return {"unsupported": True}

        diagnostics = []
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                llm_apikey="secret-key",
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        self.assertNotIn("llm_config", received)
        self.assertEqual("invalid_status", diagnostics[-1]["reason"])

    async def test_script_exception_is_diagnosed_without_exposing_api_key(self):
        async def script(**_kwargs):
            raise RuntimeError("request failed for secret-key")

        diagnostics = []
        stderr = io.StringIO()
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
        with (
            redirect_stderr(stderr),
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                llm_apikey="secret-key",
                debug=True,
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        self.assertEqual("script_failed", diagnostics[-1]["reason"])
        self.assertNotIn("secret-key", diagnostics[-1]["message"])
        self.assertNotIn("secret-key", stderr.getvalue())


class CommonPreprocessorContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_engine_callback_resolves_indirect_efx_table_slot(self):
        from ida_preprocessor_scripts import _engine_public_callback_common as callback

        table_ea = 0x500000
        efx_table = 0x600000
        slot = 64
        target = 0x401000
        dwords = {
            table_ea + 0x14C: efx_table,
            efx_table + slot * 4: target,
        }
        instruction = SimpleNamespace(ops=[SimpleNamespace(type=0, addr=0)])

        def get_segment(ea):
            if ea in (efx_table, efx_table + slot * 4):
                return SimpleNamespace(perm=2)
            if ea == target:
                return SimpleNamespace(perm=4)
            return None

        modules = {
            "ida_bytes": SimpleNamespace(get_dword=lambda ea: dwords.get(ea, 0)),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea) if ea == target else None),
            "ida_segment": SimpleNamespace(getseg=get_segment, SEGPERM_EXEC=4),
            "ida_ua": SimpleNamespace(o_near=1, o_reg=2),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False),
            "idautils": SimpleNamespace(
                FuncItems=lambda ea: [ea] if ea == target else [],
                DecodeInstruction=lambda ea: instruction if ea == target else None,
            ),
            "idc": SimpleNamespace(
                print_insn_mnem=lambda _ea: "ret",
                print_operand=lambda _ea, _index: "",
            ),
        }

        async def evaluate(_tool, args):
            namespace = {}
            with patch.dict("sys.modules", modules):
                exec(args["code"], namespace)
            return json.loads(namespace["result"])

        function = {
            "func_name": "CL_AllocDlight",
            "func_va": hex(target),
            "func_rva": "0x1000",
            "func_size": "0x20",
            "func_sig": "55 8B EC",
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "cl_enginefuncs.windows.yaml").write_text(f"gv_va: '{hex(table_ea)}'\n")
            output = directory / "CL_AllocDlight.windows.yaml"
            with patch.object(callback, "_inspect_function_via_mcp", AsyncMock(return_value=function)):
                result = await callback.preprocess_engine_callback(
                    SimpleNamespace(call_tool=evaluate),
                    [str(output)],
                    directory,
                    "windows",
                    0x400000,
                    name="CL_AllocDlight",
                    slot=slot,
                    indirect_table_offset=0x14C,
                )

            self.assertTrue(result)
            self.assertEqual(function, yaml.safe_load(output.read_text()))

    async def test_engine_callback_rejects_forwarding_cycles(self):
        from ida_preprocessor_scripts import _engine_public_callback_common as callback

        instructions = {
            0x401000: SimpleNamespace(ops=[SimpleNamespace(type=1, addr=0x402000)]),
            0x402000: SimpleNamespace(ops=[SimpleNamespace(type=1, addr=0x401000)]),
        }
        modules = {
            "ida_bytes": SimpleNamespace(get_dword=lambda _ea: 0x401000),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea)),
            "ida_segment": SimpleNamespace(getseg=lambda _ea: SimpleNamespace(perm=4), SEGPERM_EXEC=4),
            "ida_ua": SimpleNamespace(o_near=1),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False),
            "idautils": SimpleNamespace(FuncItems=lambda ea: [ea], DecodeInstruction=instructions.get),
            "idc": SimpleNamespace(print_insn_mnem=lambda _ea: "jmp"),
        }

        async def evaluate(_tool, args):
            namespace = {}
            with patch.dict("sys.modules", modules):
                exec(args["code"], namespace)
            return json.loads(namespace["result"])

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "cl_enginefuncs.windows.yaml").write_text("gv_va: '0x500000'\n")
            inspected = AsyncMock(return_value=None)
            with patch.object(callback, "_inspect_function_via_mcp", inspected):
                result = await callback.preprocess_engine_callback(
                    SimpleNamespace(call_tool=evaluate),
                    [str(directory / "Target.windows.yaml")],
                    directory,
                    "windows",
                    0x400000,
                    name="Target",
                    slot=0,
                )
            self.assertFalse(result)
            inspected.assert_not_awaited()

    def test_get_times_globals_keep_adjacent_double_fields_separate(self):
        from ida_preprocessor_scripts._studio_player_model_common import _get_times_gv_items

        located = {
            "raw_read_refs": ["0x700000", "0x700004", "0x700008", "0x70000c", "0x900000"],
            "gv_refs": {
                "0x700000": {"ea": "0x401010", "len": 6, "offb": 2},
                "0x700004": {"ea": "0x401016", "len": 6, "offb": 2},
                "0x700008": {"ea": "0x401020", "len": 6, "offb": 2},
                "0x70000c": {"ea": "0x401026", "len": 6, "offb": 2},
            },
        }

        items = _get_times_gv_items(located)

        self.assertIsNotNone(items)
        self.assertEqual([0x700000, 0x700008], [item["gv_ea"] for item in items])

    def test_get_times_globals_reject_unrelated_adjacent_pair(self):
        from ida_preprocessor_scripts._studio_player_model_common import _get_times_gv_items

        located = {
            "raw_read_refs": ["0x700000", "0x700008", "0x800000", "0x800008"],
            "gv_refs": {},
        }

        self.assertIsNone(_get_times_gv_items(located))

    def test_write_pair_keeps_instruction_order_when_va_reversed(self):
        from ida_preprocessor_scripts._studio_player_model_common import (
            SLOT_SHAPE_WRITE_PAIR,
            _shape_gv_bases,
        )

        located = {
            "read_bases": [],
            "write_bases": ["0x242f94c", "0x248b59c"],
            "insns": [
                {"dir": "write", "targets": ["0x248b59c"]},
                {"dir": "write", "targets": ["0x242f94c"]},
            ],
        }

        self.assertEqual([0x248B59C, 0x242F94C], _shape_gv_bases(located, SLOT_SHAPE_WRITE_PAIR))

    def test_write_pair_keeps_adjacent_int_stores_separate(self):
        from ida_preprocessor_scripts._studio_player_model_common import (
            SLOT_SHAPE_WRITE,
            SLOT_SHAPE_WRITE_PAIR,
            _shape_gv_bases,
        )

        located = {
            "read_bases": [],
            "write_bases": ["0x300d40"],
            "insns": [
                {"dir": "write", "targets": ["0x300d44"]},
                {"dir": "write", "targets": ["0x300d40"]},
            ],
        }

        self.assertEqual([0x300D40], _shape_gv_bases(located, SLOT_SHAPE_WRITE))
        self.assertEqual([0x300D44, 0x300D40], _shape_gv_bases(located, SLOT_SHAPE_WRITE_PAIR))

    def test_write_pair_rejects_reads_or_wrong_store_count(self):
        from ida_preprocessor_scripts._studio_player_model_common import (
            SLOT_SHAPE_WRITE_PAIR,
            _shape_gv_bases,
        )

        with_read = {
            "read_bases": ["0x10"],
            "write_bases": ["0x20", "0x24"],
            "insns": [
                {"dir": "write", "targets": ["0x20"]},
                {"dir": "write", "targets": ["0x24"]},
            ],
        }
        one_store = {
            "read_bases": [],
            "write_bases": ["0x20"],
            "insns": [{"dir": "write", "targets": ["0x20"]}],
        }
        three_stores = {
            "read_bases": [],
            "write_bases": ["0x20", "0x24", "0x28"],
            "insns": [
                {"dir": "write", "targets": ["0x20"]},
                {"dir": "write", "targets": ["0x24"]},
                {"dir": "write", "targets": ["0x28"]},
            ],
        }

        self.assertIsNone(_shape_gv_bases(with_read, SLOT_SHAPE_WRITE_PAIR))
        self.assertIsNone(_shape_gv_bases(one_store, SLOT_SHAPE_WRITE_PAIR))
        self.assertIsNone(_shape_gv_bases(three_stores, SLOT_SHAPE_WRITE_PAIR))

    def test_global_targets_use_decoded_absolute_operand_over_offset_base_xref(self):
        detail = {
            "data_refs": ["0x2000"],
            "operand_targets": ["0x3800"],
            "operand_dwords": [None, "0x3800"],
            "operand_pic": [False, False],
        }
        self.assertEqual(["0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_keep_two_encoded_operands_ambiguous(self):
        detail = {
            "data_refs": ["0x2000", "0x3800"],
            "operand_targets": ["0x2000", "0x3800"],
            "operand_dwords": ["0x2000", "0x3800"],
            "operand_pic": [False, False],
        }
        self.assertEqual(["0x2000", "0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_preserve_pic_relocation_xrefs(self):
        detail = {
            "data_refs": ["0x3800"],
            "operand_targets": [],
            "operand_dwords": [None, "0xffffe010"],
            "operand_pic": [False, True],
        }
        self.assertEqual(["0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_keep_mixed_pic_and_absolute_operands_ambiguous(self):
        detail = {
            "data_refs": ["0x3800", "0x4800"],
            "operand_targets": ["0x4800"],
            "operand_dwords": ["0xffffe010", "0x4800"],
            "operand_pic": [True, False],
        }
        self.assertEqual(["0x3800", "0x4800"], ida_analyze_util._llm_global_targets(detail))

    async def test_xref_string_function_uses_cs2_api_and_writes_canonical_yaml(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "R_RenderView.windows.yaml"

            async def call_tool(name, arguments):
                if name == "find_bytes":
                    self.assertEqual(["55 8B EC ??"], arguments["patterns"])
                    return {"matches": ["0x401000"], "n": 1}
                self.assertEqual("py_eval", name)
                self.assertIn("R_RenderView: NULL worldmodel", arguments["code"])
                candidate = {
                    "func_name": "R_RenderView",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x80",
                    "func_sig": "55 8B EC ??",
                }
                return SimpleNamespace(
                    structuredContent={"result": json.dumps({"candidates": [candidate], "pointer_size": 4})},
                    content=[],
                    isError=False,
                )

            result = await preprocess_common_skill(
                session=SimpleNamespace(call_tool=call_tool),
                expected_outputs=[str(output)],
                old_yaml_map=None,
                new_binary_dir=temporary,
                platform="windows",
                image_base=0x400000,
                func_names=["R_RenderView"],
                func_xrefs=[
                    {
                        "func_name": "R_RenderView",
                        "xref_strings": ["R_RenderView: NULL worldmodel"],
                        "xref_gvs": [],
                        "xref_signatures": [],
                        "xref_funcs": [],
                        "exclude_funcs": [],
                        "exclude_strings": [],
                        "exclude_gvs": [],
                        "exclude_signatures": [],
                    }
                ],
                generate_yaml_desired_fields=[
                    ("R_RenderView", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                ],
            )

            self.assertTrue(result)
            self.assertEqual(
                {
                    "func_name": "R_RenderView",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x80",
                    "func_sig": "55 8B EC ??",
                },
                yaml.safe_load(output.read_text(encoding="utf-8")),
            )

    async def test_func_xref_applies_signature_float_inline_alias_and_sibling_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = Path(temporary)
            client_root = game_root / "client"
            engine_root = game_root / "engine"
            client_root.mkdir()
            engine_root.mkdir()
            (engine_root / "Alias.windows.yaml").write_text("func_name: Alias\nfunc_va: '0x401100'\n", encoding="utf-8")
            calls = []

            async def call_tool(name, arguments):
                calls.append((name, arguments))
                if name == "find_bytes":
                    pattern = arguments["patterns"][0]
                    address = {
                        "DE AD ?? EF": "0x401020",
                        "BA AD F0 0D": "0x401030",
                        "55 8B EC 83 EC ??": "0x401000",
                    }[pattern]
                    return {"matches": [address], "n": 1}
                self.assertIn("3735928559", arguments["code"])
                self.assertIn("3.5", arguments["code"])
                self.assertIn("4198656", arguments["code"])
                candidate = {
                    "func_name": "Target",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x40",
                    "func_sig": "55 8B EC 83 EC ??",
                }
                return {"pointer_size": 4, "candidates": [candidate]}

            result = await preprocess_func_xrefs_via_mcp(
                session=SimpleNamespace(call_tool=call_tool),
                func_name="Target",
                xref_strings=["anchor"],
                xref_gvs=["0xDEADBEEF"],
                xref_signatures=["DE AD ?? EF"],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=["BA AD F0 0D"],
                new_binary_dir=client_root,
                platform="windows",
                image_base=0x400000,
                xref_floats=["3.5"],
                exclude_floats=["4.5"],
                inline_alias="../engine/Alias",
            )
            self.assertEqual("Target", result["func_name"])
            self.assertEqual(["find_bytes", "find_bytes", "py_eval", "find_bytes"], [name for name, _ in calls])

    async def test_func_xref_intersects_each_signature_candidate_set(self):
        signatures = {
            "AA BB": ["0x401010", "0x402010"],
            "CC DD": ["0x401020"],
            "55 8B EC 83 EC ??": ["0x401000"],
        }

        async def call_tool(name, arguments):
            if name == "find_bytes":
                pattern = arguments["patterns"][0]
                matches = signatures[pattern]
                return {"matches": matches, "n": len(matches)}
            self.assertEqual("py_eval", name)
            code = arguments["code"]
            spec_line = next(line for line in code.splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            self.assertEqual(["AA BB", "CC DD"], namespace["spec"]["xref_signatures"])
            self.assertEqual(
                [[0x401010, 0x402010], [0x401020]],
                namespace["spec"]["xref_signature_ea_sets"],
            )
            self.assertIn("def _signature_candidates(narrowed, signature, match_eas):", code)
            self.assertIn("for index, signature in enumerate(signature_texts):", code)
            candidate = {
                "func_name": "Target",
                "func_va": "0x401000",
                "func_rva": "0x1000",
                "func_size": "0x40",
                "func_sig": "55 8B EC 83 EC ??",
            }
            return {"pointer_size": 4, "candidates": [candidate]}

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=[],
            xref_gvs=[],
            xref_signatures=["AA BB", "CC DD"],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_keeps_empty_global_signature_matches_for_narrowed_probe(self):
        captured_spec = {}

        async def call_tool(name, arguments):
            if name == "find_bytes":
                return {"matches": [], "n": 0}
            self.assertEqual("py_eval", name)
            spec_line = next(line for line in arguments["code"].splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            captured_spec.update(namespace["spec"])
            return {
                "pointer_size": 4,
                "candidates": [
                    {
                        "func_name": "Target",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x40",
                    }
                ],
            }

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=["anchor"],
            xref_gvs=[],
            xref_signatures=["AA BB"],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual("Target", result["func_name"])
        self.assertEqual(["AA BB"], captured_spec["xref_signatures"])
        self.assertEqual([[]], captured_spec["xref_signature_ea_sets"])

    async def test_func_xref_forwards_gsvibe_string_min_length(self):
        captured_spec = {}

        async def call_tool(name, arguments):
            self.assertEqual("py_eval", name)
            spec_line = next(line for line in arguments["code"].splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            captured_spec.update(namespace["spec"])
            return {
                "pointer_size": 4,
                "candidates": [
                    {
                        "func_name": "Target",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x40",
                    }
                ],
            }

        with patch.dict(os.environ, {"GSVIBE_STRING_MIN_LENGTH": " 7 "}):
            result = await preprocess_func_xrefs_via_mcp(
                session=SimpleNamespace(call_tool=call_tool),
                func_name="Target",
                xref_strings=["anchor"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir=None,
                platform="windows",
                image_base=0x400000,
            )

        self.assertEqual(7, captured_spec["string_min_length"])
        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_accepts_unicode_string_sources(self):
        captured_spec = {}

        async def call_tool(name, arguments):
            self.assertEqual("py_eval", name)
            spec_line = next(line for line in arguments["code"].splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            captured_spec.update(namespace["spec"])
            self.assertIn("_unicode_string_candidates", arguments["code"])
            self.assertIn("STRTYPE_C_16", arguments["code"])
            return {
                "pointer_size": 4,
                "candidates": [
                    {
                        "func_name": "Target",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x40",
                    }
                ],
            }

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=[],
            xref_unicode_strings=["FULLMATCH:wide anchor"],
            xref_gvs=[],
            xref_signatures=[],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual(["FULLMATCH:wide anchor"], captured_spec["xref_unicode_strings"])
        self.assertEqual([], captured_spec["xref_strings"])
        self.assertEqual("Target", result["func_name"])

        # A unicode literal alone is a positive source: normalize must accept
        # it, while an empty spec still fails.
        normalized = ida_analyze_util._normalize_func_xref_specs(
            [{"func_name": "Target", "xref_strings": [], "xref_unicode_strings": ["FULLMATCH:wide"]}]
        )
        self.assertEqual(["FULLMATCH:wide"], normalized["Target"]["xref_unicode_strings"])
        self.assertIsNone(
            ida_analyze_util._normalize_func_xref_specs(
                [{"func_name": "Target", "xref_strings": [], "xref_unicode_strings": []}]
            )
        )

    async def test_func_xref_rejects_explicit_function_addresses_but_allows_gv_literals(self):
        with tempfile.TemporaryDirectory() as temporary:
            base_kwargs = {
                "session": None,
                "func_name": "Target",
                "xref_strings": ["anchor"],
                "xref_gvs": [],
                "xref_signatures": [],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
                "new_binary_dir": temporary,
                "platform": "windows",
                "image_base": 0x400000,
            }
            cases = (
                {"xref_strings": [], "xref_funcs": ["0x401000"]},
                {"exclude_funcs": ["0x401000"]},
                {"exclude_callees": ["0x401000"]},
                {"xref_strings": [], "inline_alias": "0x401000"},
            )
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    session = SimpleNamespace(call_tool=AsyncMock())
                    result = await preprocess_func_xrefs_via_mcp(**{**base_kwargs, **overrides, "session": session})
                    self.assertIsNone(result)
                    session.call_tool.assert_not_awaited()

            async def call_tool(name, arguments):
                self.assertEqual("py_eval", name)
                self.assertIn("3735928559", arguments["code"])
                return {
                    "pointer_size": 4,
                    "candidates": [
                        {
                            "func_name": "Target",
                            "func_va": "0x401000",
                            "func_rva": "0x1000",
                            "func_size": "0x40",
                        }
                    ],
                }

            result = await preprocess_func_xrefs_via_mcp(
                **{
                    **base_kwargs,
                    "session": SimpleNamespace(call_tool=call_tool),
                    "xref_strings": [],
                    "xref_gvs": ["0xDEADBEEF"],
                }
            )

        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_nonunique_signature_keeps_basic_function_metadata(self):
        async def call_tool(name, _arguments):
            if name == "py_eval":
                return {
                    "pointer_size": 4,
                    "candidates": [
                        {
                            "func_name": "Target",
                            "func_va": "0x401000",
                            "func_rva": "0x1000",
                            "func_size": "0x40",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ],
                }
            return {"matches": ["0x401000", "0x402000"], "n": 2}

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=["anchor"],
            xref_gvs=[],
            xref_signatures=[],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual(
            {
                "func_name": "Target",
                "func_va": "0x401000",
                "func_rva": "0x1000",
                "func_size": "0x40",
                "_pointer_size": 4,
            },
            result,
        )

    async def test_pattern_d_llm_fallback_uses_dependency_contract_and_verified_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt = root / "prompt.md"
            reference = root / "reference.yaml"
            current = root / "Predecessor.windows.yaml"
            output = root / "Target.windows.yaml"
            prompt.write_text("Compare reference and target.", encoding="utf-8")
            reference.write_text(
                "func_name: Predecessor\nfunc_va: '0x401000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            current.write_text("func_name: Predecessor\nfunc_va: '0x401000'\n", encoding="utf-8")

            async def call_tool(name, arguments):
                if name == "find_bytes":
                    return {"matches": ["0x402000"], "n": 1}
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "format_name = 'json'" in code and "output_path = " in code:
                    output_path = None
                    for line in code.splitlines():
                        if line.startswith("output_path = "):
                            output_path = ast.literal_eval(line.split("=", 1)[1].strip())
                            break
                    self.assertIsInstance(output_path, str)
                    payload = {
                        "pointer_size": 4,
                        "func_start": "0x401000",
                        "func_end": "0x401100",
                        "disasm_code": "0x401020: call sub_402000",
                        "procedure": "sub_402000();",
                    }
                    Path(output_path).write_text(json.dumps(payload), encoding="utf-8")
                    return {
                        "ok": True,
                        "output_path": output_path,
                        "bytes_written": Path(output_path).stat().st_size,
                        "format": "json",
                    }
                if "operand_targets" in code:
                    return {
                        "pointer_size": 4,
                        "size": 5,
                        "func_start": "0x401000",
                        "func_end": "0x401100",
                        "line": "call sub_402000",
                        "mnemonic": "call",
                        "code_refs": ["0x402000"],
                        "data_refs": [],
                        "operand_targets": ["0x402000"],
                        "displacements": [],
                        "operand_offsets": [1],
                    }
                return {
                    "pointer_size": 4,
                    "function": {
                        "func_va": "0x402000",
                        "func_rva": "0x2000",
                        "func_size": "0x30",
                        "func_sig": "55 8B EC 83 EC ??",
                    },
                }

            llm_result = """\
found_vcall: []
found_call:
  - func_name: Target
    insn_va: '0x401020'
    insn_disasm: call sub_402000
found_funcptr: []
found_gv: []
found_struct_offset: []
"""
            with patch("ida_llm_decompile.request_text", return_value=llm_result):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=call_tool),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Target",
                            "prompt_path": str(prompt),
                            "reference_yaml_paths": [str(reference)],
                            "expected_result_sections": ["found_call"],
                            "dependency_policy": {"Predecessor.{platform}.yaml": "required"},
                        }
                    ],
                    llm_config={
                        "model": "test-model",
                        "api_key": "test-key",
                        "_expected_inputs": [str(current)],
                        "_optional_inputs": [],
                    },
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )
            self.assertTrue(result)
            self.assertEqual("Target", yaml.safe_load(output.read_text(encoding="utf-8"))["func_name"])

    async def test_struct_member_llm_fallback_preserves_old_yaml_canonical_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbol_name = "CBaseEntity_m_modelState_m_simulationState"
            old_output = root / "old.yaml"
            output = root / f"{symbol_name}.windows.yaml"
            old_output.write_text(
                "struct_name: CBaseEntity\nmember_name: m_modelState.m_simulationState\noffset: '0x0'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_struct_offset": [
                    {
                        "struct_name": "CBaseEntity",
                        "member_name": "m_modelState_m_simulationState",
                        "insn_va": "0x401020",
                        "offset": "0x0",
                    }
                ]
            }
            instruction = {
                "size": 3,
                "func_start": "0x401000",
                "func_end": "0x401100",
                "line": "mov eax, [ecx]",
                "displacements": ["0x0"],
            }

            with (
                patch("ida_analyze_util.preprocess_struct_offset_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch(
                    "ida_analyze_util._prepare_llm_context",
                    return_value={
                        "model": "test-model",
                        "prompt_path": "prompt.md",
                        "reference_yaml_paths": ["reference.yaml"],
                        "temperature": None,
                    },
                ),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch("ida_analyze_util._inspect_llm_instruction", new=AsyncMock(return_value=instruction)),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(return_value={"func_va": "0x401000", "func_sig": "55 8B EC"}),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    old_yaml_map={str(output): str(old_output)},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    struct_member_names=[symbol_name],
                    llm_decompile_specs=[
                        {
                            "symbol_name": symbol_name,
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.yaml"],
                            "expected_result_sections": ["found_struct_offset"],
                            "dependency_policy": {"dependency.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (symbol_name, ["struct_name", "member_name", "offset", "offset_sig", "offset_sig_disp"])
                    ],
                )

            self.assertTrue(result)
            payload = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual("CBaseEntity", payload["struct_name"])
            self.assertEqual("m_modelState.m_simulationState", payload["member_name"])

    async def test_llm_batch_groups_two_unresolved_regular_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = [root / "TargetA.windows.yaml", root / "TargetB.windows.yaml"]
            specs = [
                {
                    "symbol_name": name,
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                }
                for name in ("TargetA", "TargetB")
            ]
            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "TargetA",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_402000",
                    },
                    {
                        "func_name": "TargetB",
                        "insn_va": "0x401030",
                        "insn_disasm": "call sub_403000",
                    },
                ],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            details = {
                0x401020: {
                    "func_start": "0x401000",
                    "line": "call sub_402000",
                    "code_refs": ["0x402000"],
                },
                0x401030: {
                    "func_start": "0x401000",
                    "line": "call sub_403000",
                    "code_refs": ["0x403000"],
                },
            }

            async def inspect_instruction(_session, ea):
                return details[int(ea, 0) if isinstance(ea, str) else ea]

            async def inspect_function(_session, ea, image_base, name):
                return {
                    "func_name": name,
                    "func_va": hex(ea),
                    "func_rva": hex(ea - image_base),
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 83 EC ??",
                }

            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch("ida_analyze_util._inspect_llm_instruction", new=inspect_instruction),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(path) for path in outputs],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["TargetA", "TargetB"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("TargetA", "TargetB")
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["TargetA", "TargetB"], call_llm.await_args.kwargs["symbol_names"])
            self.assertEqual(
                ["TargetA", "TargetB"],
                [yaml.safe_load(path.read_text(encoding="utf-8"))["func_name"] for path in outputs],
            )

    async def test_llm_batch_excludes_function_resolved_by_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = [root / "FastTarget.windows.yaml", root / "LlmTarget.windows.yaml"]
            specs = [
                {
                    "symbol_name": name,
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                }
                for name in ("FastTarget", "LlmTarget")
            ]
            fast_candidate = {
                "func_name": "FastTarget",
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            }

            async def fast_path(*_args, func_name=None, **_kwargs):
                return fast_candidate if func_name == "FastTarget" else None

            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "LlmTarget",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_403000",
                    }
                ],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call sub_403000",
                            "code_refs": ["0x403000"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "LlmTarget",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(path) for path in outputs],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["FastTarget", "LlmTarget"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("FastTarget", "LlmTarget")
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["LlmTarget"], call_llm.await_args.kwargs["symbol_names"])

    async def test_function_fast_path_waits_for_predecessor_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dependency_output = root / "Dependency.windows.yaml"
            target_output = root / "Target.windows.yaml"
            fast_path_calls = []

            async def fast_path(*_args, func_name=None, **_kwargs):
                fast_path_calls.append(func_name)
                if func_name == "Dependency":
                    return {
                        "func_name": "Dependency",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x20",
                        "func_sig": "55 8B EC 90",
                    }
                self.assertTrue(dependency_output.is_file())
                return None

            async def xref_path(**kwargs):
                self.assertEqual("Target", kwargs["func_name"])
                self.assertTrue(dependency_output.is_file())
                return {
                    "func_name": "Target",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 91",
                }

            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
                patch(
                    "ida_analyze_util.preprocess_func_xrefs_via_mcp",
                    new=AsyncMock(side_effect=xref_path),
                ) as xref_fast_path,
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(dependency_output), str(target_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Dependency", "Target"],
                    func_xrefs=[{"func_name": "Target", "xref_funcs": ["Dependency"]}],
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("Dependency", "Target")
                    ],
                )

            self.assertTrue(result)
            self.assertEqual(["Dependency", "Target"], fast_path_calls)
            xref_fast_path.assert_awaited_once()
            self.assertEqual("Dependency", yaml.safe_load(dependency_output.read_text(encoding="utf-8"))["func_name"])
            self.assertEqual("Target", yaml.safe_load(target_output.read_text(encoding="utf-8"))["func_name"])

    async def test_vtable_output_is_emitted_before_related_function_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vtable_output = root / "TargetClass_vtable.windows.yaml"
            function_output = root / "VirtualTarget.windows.yaml"
            call_order = []
            vtable_candidate = {
                "vtable_class": "TargetClass",
                "vtable_symbol": "??_7TargetClass@@6B@",
                "vtable_va": "0x410000",
                "vtable_rva": "0x10000",
                "vtable_size": "0x4",
                "vtable_numvfunc": 1,
                "vtable_entries": {0: "0x402000"},
            }

            async def vtable_path(*_args, **_kwargs):
                call_order.append("vtable")
                return vtable_candidate

            async def function_path(*_args, **_kwargs):
                call_order.append("function")
                self.assertTrue(vtable_output.is_file())
                return {
                    "func_name": "VirtualTarget",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "vtable_name": "TargetClass",
                    "vfunc_offset": "0x0",
                    "vfunc_index": 0,
                }

            with (
                patch("ida_analyze_util.preprocess_vtable_via_mcp", new=vtable_path),
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=function_path),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(vtable_output), str(function_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    vtable_class_names=["TargetClass"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    generate_yaml_desired_fields=[
                        (
                            "TargetClass",
                            [
                                "vtable_class",
                                "vtable_symbol",
                                "vtable_va",
                                "vtable_rva",
                                "vtable_size",
                                "vtable_numvfunc",
                                "vtable_entries",
                            ],
                        ),
                        (
                            "VirtualTarget",
                            [
                                "func_name",
                                "func_va",
                                "func_rva",
                                "func_size",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        ),
                    ],
                )

            self.assertTrue(result)
            self.assertEqual(["vtable", "function"], call_order)
            self.assertEqual("TargetClass", yaml.safe_load(vtable_output.read_text(encoding="utf-8"))["vtable_class"])

    async def test_llm_batch_includes_unresolved_global_variable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            func_output = root / "Target.windows.yaml"
            gv_output = root / "g_Target.windows.yaml"
            specs = [
                {
                    "symbol_name": "Target",
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                },
                {
                    "symbol_name": "g_Target",
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_gv"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                },
            ]
            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "Target",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_402000",
                    }
                ],
                "found_funcptr": [],
                "found_gv": [
                    {
                        "gv_name": "g_Target",
                        "insn_va": "0x401040",
                        "insn_disasm": "mov eax, ds:dword_404000",
                    }
                ],
                "found_struct_offset": [],
            }
            details = {
                0x401020: {
                    "func_start": "0x401000",
                    "line": "call sub_402000",
                    "code_refs": ["0x402000"],
                },
                0x401040: {
                    "func_start": "0x401000",
                    "line": "mov eax, ds:dword_404000",
                    "size": 5,
                    "data_refs": ["0x404000"],
                    "operand_targets": [],
                    "operand_offsets": [1],
                },
            }

            async def inspect_instruction(_session, ea):
                return details[int(ea, 0) if isinstance(ea, str) else ea]

            async def inspect_function(_session, ea, image_base, name):
                if name == "__llm_anchor":
                    return {"func_va": "0x401000", "func_sig": "55 8B EC 83 EC ??"}
                return {
                    "func_name": name,
                    "func_va": hex(ea),
                    "func_rva": hex(ea - image_base),
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 83 EC ??",
                }

            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util.preprocess_gv_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch("ida_analyze_util._inspect_llm_instruction", new=inspect_instruction),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(func_output), str(gv_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    gv_names=["g_Target"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
                        (
                            "g_Target",
                            [
                                "gv_name",
                                "gv_va",
                                "gv_rva",
                                "gv_sig",
                                "gv_sig_va",
                                "gv_inst_offset",
                                "gv_inst_length",
                                "gv_inst_disp",
                            ],
                        ),
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["Target", "g_Target"], call_llm.await_args.kwargs["symbol_names"])
            self.assertEqual("g_Target", yaml.safe_load(gv_output.read_text(encoding="utf-8"))["gv_name"])

    async def test_llm_global_can_retry_with_across_boundary_signature_budget(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [
                {
                    "gv_name": "g_Target",
                    "insn_va": "0x401040",
                    "insn_disasm": "mov eax, ds:dword_404000",
                }
            ],
            "found_struct_offset": [],
        }
        extended_function = {
            "func_va": "0x401000",
            "func_sig": "55 8B EC 83 EC ?? 53 56 57 8B F9",
        }
        inspect_function = AsyncMock(side_effect=[None, extended_function])
        with (
            patch(
                "ida_analyze_util._inspect_llm_instruction",
                new=AsyncMock(
                    return_value={
                        "func_start": "0x401000",
                        "line": "mov eax, ds:dword_404000",
                        "size": 5,
                        "data_refs": ["0x404000"],
                        "operand_targets": [],
                        "operand_offsets": [1],
                    }
                ),
            ),
            patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
        ):
            candidate = await _preprocess_llm_target(
                session=SimpleNamespace(call_tool=AsyncMock()),
                symbol_name="g_Target",
                category="gv",
                spec={"expected_result_sections": ["found_gv"]},
                llm_config={"model": "test-model"},
                new_binary_dir=Path("D:/game/engine"),
                platform="windows",
                image_base=0x400000,
                desired_fields=[
                    "gv_name",
                    "gv_va",
                    "gv_rva",
                    "gv_sig",
                    "gv_sig_va",
                    "gv_inst_offset",
                    "gv_inst_length",
                    "gv_inst_disp",
                    "gv_sig_allow_across_function_boundary",
                ],
                llm_result=llm_result,
                target_ranges=[(0x401000, 0x401100)],
            )

        self.assertEqual(extended_function["func_sig"], candidate["gv_sig"])
        self.assertTrue(candidate["gv_sig_allow_across_function_boundary"])
        self.assertEqual(
            [
                call(ANY, 0x401000, 0x400000, "__llm_anchor"),
                call(
                    ANY,
                    0x401000,
                    0x400000,
                    "__llm_anchor",
                    allow_across_function_boundary=True,
                ),
            ],
            inspect_function.await_args_list,
        )

    def test_optional_global_across_boundary_marker_is_a_desired_output_field(self):
        desired = ida_analyze_util._desired_fields_map(
            [
                (
                    "g_Target",
                    [
                        "gv_name",
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary?",
                    ],
                )
            ]
        )

        self.assertIsNotNone(desired)
        field_spec = desired["g_Target"]
        self.assertIn("gv_sig_allow_across_function_boundary", field_spec["fields"])
        self.assertIn("gv_sig_allow_across_function_boundary", field_spec["optional_fields"])
        self.assertNotIn("gv_sig_allow_across_function_boundary", field_spec["generation_options"])

    async def test_llm_global_emits_pic_addend_for_register_relative_displacement(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [
                {
                    "gv_name": "g_Target",
                    "insn_va": "0x401040",
                    "insn_disasm": "mov [eax+0x4A388D4], edx",
                }
            ],
            "found_struct_offset": [],
        }
        function = {
            "func_va": "0x401000",
            "func_sig": "8B 54 24 ?? 89 90 ?? ?? ?? ?? C3",
        }
        desired_fields = [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_pic_addend?",
        ]

        async def run(operand_pic, operand_dwords):
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "mov [eax+0x4A388D4], edx",
                            "size": 6,
                            "data_refs": ["0x4d268d4"],
                            "operand_targets": [],
                            "operand_offsets": [2],
                            "operand_pic": operand_pic,
                            "operand_dwords": operand_dwords,
                        }
                    ),
                ),
                patch("ida_analyze_util._inspect_function_via_mcp", new=AsyncMock(return_value=function)),
            ):
                return await _preprocess_llm_target(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    symbol_name="g_Target",
                    category="gv",
                    spec={"expected_result_sections": ["found_gv"]},
                    llm_config={"model": "test-model"},
                    new_binary_dir=Path("D:/game/engine"),
                    platform="linux",
                    image_base=0x400000,
                    desired_fields=desired_fields,
                    llm_result=llm_result,
                    target_ranges=[(0x401000, 0x401100)],
                )

        pic_candidate = await run([True], ["0x4a388d4"])
        self.assertIsNotNone(pic_candidate)
        # The addend recovers an RVA even when the IDB image base is nonzero.
        self.assertEqual("0xffeee000", pic_candidate["gv_pic_addend"])

        absolute_candidate = await run([False], ["0x4d268d4"])
        self.assertIsNotNone(absolute_candidate)
        # Absolute form: the embedded dword already is the address.
        self.assertNotIn("gv_pic_addend", absolute_candidate)

    def test_gv_resolution_rebases_pic_and_adjusts_absolute_members(self):
        # MSVC indexed absolute operands may also decode as o_displ.
        self.assertEqual(
            {},
            _gv_resolution_fields(
                {"operand_offsets": [2], "operand_pic": [True], "operand_dwords": ["0x2345678"]},
                0x2345678,
                0x1D00000,
                platform="windows",
            ),
        )
        for embedded, target_rva, pic in (
            (0xA388D4, 0xD268D4, True),
            (0x602A14, 0x1BDA774, True),
            (0xFFFF4044, 0x2E2040, True),
            (0x2579C4, 0x2579C0, False),
        ):
            for image_base in (0, 0x400000):
                with self.subTest(embedded=embedded, image_base=image_base):
                    operand = embedded if pic else embedded + image_base
                    detail = {"operand_offsets": [2], "operand_pic": [pic], "operand_dwords": [hex(operand)]}
                    fields = _gv_resolution_fields(detail, target_rva + image_base, image_base)
                    load_base = 0x50000000
                    if pic:
                        actual = load_base + ((operand + int(fields["gv_pic_addend"], 0)) & 0xFFFFFFFF)
                    else:
                        actual = load_base + embedded + int(fields.get("gv_address_offset", "0"), 0)
                    self.assertEqual(load_base + target_rva, actual & 0xFFFFFFFF)

    def test_unindexed_address_load_decoder_preserves_the_memory_address(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        decode = namespace["decode_address_load"]
        self.assertEqual((6, 0x242324), decode(bytes.fromhex("8B 96 24 23 24 00")))
        self.assertEqual((1, 0x242324), decode(bytes.fromhex("8B 89 24 23 24 00")))
        self.assertEqual((6, 0xFFFFFFFC), decode(bytes.fromhex("8D 86 FC FF FF FF")))
        self.assertEqual((2, 0x6020), decode(bytes.fromhex("89 82 20 60 00 00")))
        for unsupported in (
            "89 04 B5 24 23 24 00",
            "8B 04 B5 24 23 24 00",
            "66 8B 86 24 23 24 00",
            "8B 46 04",
            "8B 05 24 23 24 00",
        ):
            self.assertIsNone(decode(bytes.fromhex(unsupported)))

    def test_relative_store_resolution_overrides_mapped_displacement(self):
        detail = {
            "data_refs": ["0x6020"],
            "operand_targets": [],
            "operand_pic": [True, False],
            "relative_store_address": {"target": "0x806020"},
        }
        self.assertEqual(["0x806020"], ida_analyze_util._llm_global_targets(detail))
        detail["relative_store_address"] = {"target": None, "issue": "Unknown EDX base"}
        self.assertEqual([], ida_analyze_util._llm_global_targets(detail))
        self.assertEqual(["0x6020"], ida_analyze_util._llm_global_targets(detail, platform="windows"))

    def test_relative_store_inspection_checks_effective_address(self):
        for base, mapped, clobbered, width, permission, unknown_lea in (
            (0x8000, True, False, 4, 6, False),
            (0xA000, True, False, 4, 6, False),
            (0x8000, False, False, 4, 6, False),
            (0x8000, True, True, 4, 6, False),
            (0x8000, True, False, 3, 6, False),
            (0x8000, True, False, 4, 7, False),
            (0x8000, True, False, 4, 6, True),
        ):
            with self.subTest(
                base=base,
                mapped=mapped,
                clobbered=clobbered,
                width=width,
                permission=permission,
                unknown_lea=unknown_lea,
            ):
                ea, displacement = 0x1010, 0x2000
                register = SimpleNamespace(type=1, reg=2, dtype=2, offb=0)
                source = SimpleNamespace(type=1, reg=0, dtype=2, offb=0)
                memory = SimpleNamespace(type=4, addr=displacement, offb=2, dtype=2)
                void = SimpleNamespace(type=0)
                store = SimpleNamespace(ops=[memory, source, void])
                definition = SimpleNamespace(
                    ops=[register, memory if unknown_lea else SimpleNamespace(type=5, value=base), void], size=6
                )
                segment = SimpleNamespace(perm=permission, end_ea=base + displacement + width)

                def getseg(address):
                    if address in (base, displacement) or (mapped and address == base + displacement):
                        return segment
                    return None

                block = SimpleNamespace(id=0, start_ea=0x1000, end_ea=0x1016, preds=lambda: [])
                modules = {
                    "ida_bytes": SimpleNamespace(
                        get_dword=lambda address: displacement,
                        get_bytes=lambda address, size: bytes.fromhex(
                            "8D 91 00 20 00 00" if address == 0x1000 else "89 82 00 20 00 00"
                        ),
                    ),
                    "ida_fixup": SimpleNamespace(fixup_data_t=lambda: None, get_fixup=lambda *args: False),
                    "ida_funcs": SimpleNamespace(get_func=lambda address: block),
                    "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
                    "ida_segment": SimpleNamespace(getseg=getseg, SEGPERM_EXEC=1),
                    "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, BADADDR=0xFFFFFFFF),
                    "ida_ua": SimpleNamespace(
                        o_void=0,
                        o_reg=1,
                        o_mem=2,
                        o_phrase=3,
                        o_displ=4,
                        o_imm=5,
                        o_near=6,
                        o_far=7,
                        dt_byte=0,
                        dt_dword=2,
                        insn_t=lambda: store,
                        decode_insn=lambda *args: 6,
                    ),
                    "ida_gdl": SimpleNamespace(FlowChart=lambda func: [block]),
                    "idautils": SimpleNamespace(
                        DataRefsFrom=lambda address: [base] if address == 0x1000 else [displacement],
                        CodeRefsFrom=lambda *args: [],
                        Heads=lambda *args: [0x1000, 0x1006, ea] if clobbered else [0x1000, ea],
                        DecodeInstruction=lambda address: definition if address != ea else store,
                    ),
                    "idc": SimpleNamespace(
                        generate_disasm_line=lambda *args: "mov [edx+2000h], eax",
                        print_insn_mnem=lambda address: (
                            "lea" if unknown_lea and address == 0x1000 else "xor" if address == 0x1006 else "mov"
                        ),
                    ),
                }
                namespace = {}
                with patch.dict("sys.modules", modules):
                    exec(
                        ida_analyze_util._INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(ea)), namespace
                    )
                detail = json.loads(namespace["result"])
                self.assertEqual([hex(displacement)], detail["data_refs"])
                if mapped and not clobbered and width >= 4 and permission == 6 and not unknown_lea:
                    self.assertEqual([hex(base + displacement)], ida_analyze_util._llm_global_targets(detail))
                    self.assertEqual(hex(base), _gv_resolution_fields(detail, base + displacement, 0)["gv_pic_addend"])
                else:
                    self.assertEqual([], ida_analyze_util._llm_global_targets(detail))
                    self.assertTrue(detail["relative_store_address"]["issue"])

    def test_address_flow_requires_agreement_on_every_incoming_path(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        resolve = namespace["resolve_address_flow"]
        graph = {
            0: {"preds": [], "writes": [{6: ("constant", 0x2000)}]},
            1: {"preds": [0], "writes": [{0: None, 1: None, 2: None}]},
            2: {"preds": [0], "writes": []},
            3: {"preds": [1, 2], "writes": []},
        }
        self.assertEqual(0x2000, resolve(graph, 3, 0, 6))
        graph[2]["writes"] = [{6: ("constant", 0x3000)}]
        self.assertIsNone(resolve(graph, 3, 0, 6))
        graph[2]["writes"] = [{6: None}]
        self.assertIsNone(resolve(graph, 3, 0, 6))
        graph[2]["writes"] = []
        graph[3]["writes"] = [{7: ("register", 6)}]
        self.assertEqual(0x2000, resolve(graph, 3, 1, 7))
        graph[4] = {"preds": [], "writes": []}
        graph[3]["preds"].append(4)
        reachable = namespace["reachable_address_graph"](graph, 0)
        self.assertEqual(0x2000, resolve(reachable, 3, 1, 7))
        graph[3]["preds"].remove(4)
        graph[0]["preds"] = [3]
        graph[0]["writes"] = []
        self.assertIsNone(resolve(graph, 3, 1, 7))

    def test_relative_store_ignores_x87_paths_that_cannot_define_the_base(self):
        # SvEngine Linux Mod_LoadModel shape: the GOT base is built in the entry
        # block, an x87 comparison sits between it and the store, and the store
        # block carries a self-loop. The comparison has no general purpose
        # register operand, so it must not invalidate EBX; `fnstsw ax` does.
        ea, displacement, base, thunk = 0x1006, 0x2000, 0x8000, 0x2000
        void = SimpleNamespace(type=0)
        for mnemonic, float_ops, expected in (
            ("fld", [SimpleNamespace(type=4, addr=0, offb=2, dtype=2), void], "0xa000"),
            ("fnstsw", [SimpleNamespace(type=1, reg=0, dtype=2, offb=0), void], None),
        ):
            with self.subTest(mnemonic=mnemonic):
                function = SimpleNamespace(start_ea=0x1000, end_ea=0x100C)
                block0 = SimpleNamespace(id=0, start_ea=0x1000, end_ea=0x1004)
                block1 = SimpleNamespace(id=1, start_ea=0x1004, end_ea=0x1006)
                block2 = SimpleNamespace(id=2, start_ea=0x1006, end_ea=0x100C)
                block0.preds = lambda: []
                block1.preds = lambda: [block0]
                block2.preds = lambda: [block1, block2]
                call = SimpleNamespace(ops=[SimpleNamespace(type=5, value=thunk), void], size=2)
                add = SimpleNamespace(
                    ops=[
                        SimpleNamespace(type=1, reg=3, dtype=2, offb=0),
                        SimpleNamespace(type=5, value=0x6FFE),
                        void,
                    ],
                    size=2,
                )
                float_insn = SimpleNamespace(ops=float_ops, size=2)
                store = SimpleNamespace(
                    ops=[
                        SimpleNamespace(type=4, addr=displacement, offb=2, dtype=2),
                        SimpleNamespace(type=1, reg=6, dtype=2, offb=0),
                        void,
                    ],
                    size=6,
                )
                instructions = {0x1000: call, 0x1002: add, 0x1004: float_insn, ea: store}
                mnemonics = {0x1000: "call", 0x1002: "add", 0x1004: mnemonic, ea: "mov"}
                heads = {0x1000: [0x1000, 0x1002], 0x1004: [0x1004], ea: [ea]}
                segment = SimpleNamespace(perm=6, end_ea=base + displacement + 6)
                modules = {
                    "ida_bytes": SimpleNamespace(
                        get_dword=lambda address: displacement,
                        get_bytes=lambda address, size: (
                            bytes.fromhex("8B 1C 24 C3") if address == thunk else bytes.fromhex("89 B3 00 20 00 00")
                        ),
                    ),
                    "ida_fixup": SimpleNamespace(fixup_data_t=lambda: None, get_fixup=lambda *args: False),
                    "ida_funcs": SimpleNamespace(get_func=lambda address: function),
                    "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
                    "ida_segment": SimpleNamespace(
                        getseg=lambda address: (
                            segment if address in (base, displacement, base + displacement) else None
                        ),
                        SEGPERM_EXEC=1,
                    ),
                    "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, BADADDR=0xFFFFFFFF),
                    "ida_gdl": SimpleNamespace(FlowChart=lambda func: [block0, block1, block2]),
                    "ida_ua": SimpleNamespace(
                        o_void=0,
                        o_reg=1,
                        o_mem=2,
                        o_phrase=3,
                        o_displ=4,
                        o_imm=5,
                        o_near=6,
                        o_far=7,
                        dt_byte=0,
                        dt_dword=2,
                        insn_t=lambda: store,
                        decode_insn=lambda *args: 6,
                    ),
                    "idautils": SimpleNamespace(
                        DataRefsFrom=lambda address: [displacement],
                        CodeRefsFrom=lambda address, flow: [thunk] if address == 0x1000 else [],
                        Heads=lambda start, end: heads[start],
                        DecodeInstruction=lambda address: instructions[address],
                    ),
                    "idc": SimpleNamespace(
                        generate_disasm_line=lambda *args: "mov [ebx+2000h], esi",
                        print_insn_mnem=lambda address: mnemonics[address],
                    ),
                }
                namespace = {}
                with patch.dict("sys.modules", modules):
                    exec(
                        ida_analyze_util._INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(ea)), namespace
                    )
                detail = json.loads(namespace["result"])
                self.assertEqual(expected, detail["relative_store_address"]["target"])
                self.assertEqual([expected] if expected else [], ida_analyze_util._llm_global_targets(detail))

    def test_address_flow_ignores_loop_paths_that_never_define_the_register(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        resolve = namespace["resolve_address_flow"]
        # SvEngine Linux Mod_LoadModel shape: the GOT base loaded in the entry
        # block survives a self-loop and a back edge into the loop header that
        # never write the register.
        graph = {
            0: {"preds": [], "writes": [{3: ("constant", 0x1005)}, {3: ("offset", 0x6FFB)}]},
            1: {"preds": [0], "writes": []},
            2: {"preds": [1, 5], "writes": [{0: None}]},
            3: {"preds": [2], "writes": []},
            4: {"preds": [1], "writes": [{0: None}]},
            5: {"preds": [4, 5], "writes": [{0: None}]},
            6: {"preds": [2, 3], "writes": []},
        }
        self.assertEqual(0x8000, resolve(graph, 6, 0, 3))
        # A loop that does clobber the register still fails closed.
        graph[5]["writes"] = [{0: None}, {3: None}]
        self.assertIsNone(resolve(graph, 6, 0, 3))

    def test_address_flow_rejects_cycles_that_write_the_register(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        resolve = namespace["resolve_address_flow"]
        # The entry block sets the register once and the loop adds 4 per
        # iteration. The value after the loop depends on the iteration count, so
        # the entry constant must not stand in for it even though the loop body
        # contains no `None` clobber.
        graph = {
            0: {"preds": [], "writes": [{3: ("constant", 0x8000)}]},
            1: {"preds": [0, 1], "writes": [{3: ("offset", 4)}]},
            2: {"preds": [1], "writes": []},
        }
        self.assertIsNone(resolve(graph, 2, 0, 3))
        # A self-referential operand in one block is the same hazard.
        self.assertIsNone(resolve(graph, 1, 1, 3))
        # Removing the loop write still resolves the entry constant.
        graph[1]["writes"] = []
        self.assertEqual(0x8000, resolve(graph, 2, 0, 3))

    def test_address_flow_preserves_pic_base_arithmetic_and_rejects_clobbers(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        graph = {
            0: {
                "preds": [],
                "writes": [
                    {3: ("constant", 0x1005)},
                    {3: ("offset", 0x6FFB)},
                    {2: ("register", 3)},
                    {2: ("offset", -4)},
                ],
            }
        }
        resolve = namespace["resolve_address_flow"]
        self.assertEqual(0x7FFC, resolve(graph, 0, 4, 2))
        graph[0]["writes"][0] = {3: None}
        self.assertIsNone(resolve(graph, 0, 4, 2))

    def test_address_flow_high_byte_write_invalidates_its_parent_register(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        register = namespace["address_write_register"]
        self.assertEqual(0, register(4, True))  # AH writes EAX, not ESP.
        self.assertEqual(3, register(7, True))  # BH writes EBX, not EDI.
        self.assertEqual(4, register(4, False))
        graph = {0: {"preds": [], "writes": [{0: ("constant", 0x2000)}, {register(4, True): None}]}}
        self.assertIsNone(namespace["resolve_address_flow"](graph, 0, 2, 0))

    def test_address_flow_got_load_requires_matching_reaching_address(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        graph = {
            0: {
                "preds": [],
                "writes": [
                    {3: ("constant", 0x8000)},
                    {2: ("got_load", (3, -0x20, {0x7FE0: 0x9000}))},
                ],
            }
        }
        resolve = namespace["resolve_address_flow"]
        self.assertEqual(0x9000, resolve(graph, 0, 2, 2))
        graph[0]["writes"][0] = {3: ("constant", 0x7000)}
        self.assertIsNone(resolve(graph, 0, 2, 2))
        graph[0]["writes"][0] = {3: None}
        self.assertIsNone(resolve(graph, 0, 2, 2))

    def test_instruction_inspection_distinguishes_relocated_indexed_operands(self):
        class Fixup:
            pass

        for relocated in (False, True):

            def get_fixup(fixup, address):
                self.assertIsInstance(fixup, Fixup)
                self.assertEqual(0x1002, address)
                return relocated

            modules = {
                "ida_bytes": SimpleNamespace(
                    get_dword=lambda ea: 0x2004, get_bytes=lambda ea, size: bytes.fromhex("8B 83 04 20 00 00")
                ),
                "ida_fixup": SimpleNamespace(fixup_data_t=Fixup, get_fixup=get_fixup),
                "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1010)),
                "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
                "ida_segment": SimpleNamespace(getseg=lambda ea: object() if ea in (0x2004, 0x3004) else None),
                "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, BADADDR=0xFFFFFFFF),
                "ida_ua": SimpleNamespace(
                    o_void=0,
                    o_reg=1,
                    o_mem=2,
                    o_far=7,
                    o_near=6,
                    o_imm=5,
                    o_displ=4,
                    o_phrase=3,
                    insn_t=lambda: SimpleNamespace(
                        ops=[SimpleNamespace(type=4, offb=2, addr=0x2004), SimpleNamespace(type=0)]
                    ),
                    decode_insn=lambda insn, ea: 6,
                ),
                # IDA can return UDT/member IDs as data xrefs. They are not
                # runtime addresses; two genuine mapped refs must still survive.
                "idautils": SimpleNamespace(
                    DataRefsFrom=lambda ea: [0x2004, 0xFF0000000000346B, 0xDEAD0000, 0x3004],
                    CodeRefsFrom=lambda ea, flow: [],
                ),
                "idc": SimpleNamespace(
                    generate_disasm_line=lambda ea, flags: "mov eax, [ebx+2004h]", print_insn_mnem=lambda ea: "mov"
                ),
            }
            namespace = {}
            with patch.dict("sys.modules", modules):
                exec(ida_analyze_util._INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", "4096"), namespace)
            self.assertEqual([not relocated], json.loads(namespace["result"])["operand_pic"])
            self.assertEqual(["0x2004", "0x3004"], json.loads(namespace["result"])["data_refs"])

    async def test_gv_emission_preserves_resolution_metadata_without_desired_fields(self):
        for metadata in ({"gv_pic_addend": "0x2ee000"}, {"gv_address_offset": "0xfffffffc"}):
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "g_Target.linux.yaml"
                candidate = {
                    "gv_name": "g_Target",
                    "gv_va": "0xd268d4",
                    "gv_rva": "0xd268d4",
                    "gv_sig": "89 90 ?? ?? ?? ??",
                    "gv_sig_va": "0x9fe7e",
                    "gv_inst_offset": 0,
                    "gv_inst_length": 6,
                    "gv_inst_disp": 2,
                }
                fields = list(candidate)
                candidate.update(metadata)
                with (
                    patch("ida_analyze_util.preprocess_gv_sig_via_mcp", new=AsyncMock(return_value=candidate)),
                ):
                    ok = await preprocess_common_skill(
                        session=SimpleNamespace(call_tool=AsyncMock()),
                        expected_outputs=[str(output)],
                        new_binary_dir=temporary,
                        platform="linux",
                        image_base=0,
                        gv_names=["g_Target"],
                        generate_yaml_desired_fields=[("g_Target", fields)],
                    )
                self.assertTrue(ok)
                emitted = yaml.safe_load(output.read_text())
                for key, value in metadata.items():
                    self.assertEqual(value, emitted[key])

    def test_canonical_gv_yaml_orders_pic_addend_after_inst_disp(self):
        payload = {
            "gv_sig_allow_across_function_boundary": True,
            "gv_pic_addend": 0x2EE000,
            "gv_inst_disp": 2,
            "gv_inst_length": 6,
            "gv_inst_offset": 0,
            "gv_sig_va": "0x401000",
            "gv_sig": "8b 54 ??",
            "gv_rva": 0x9268D4,
            "gv_va": 0x4D268D4,
            "gv_name": "g_Target",
        }
        raw = canonical_symbol_yaml_bytes(payload, category="gv").decode("utf-8")
        lines = [line.split(":")[0] for line in raw.splitlines() if ":" in line]
        self.assertEqual(
            [
                "gv_name",
                "gv_va",
                "gv_rva",
                "gv_sig",
                "gv_sig_va",
                "gv_inst_offset",
                "gv_inst_length",
                "gv_inst_disp",
                "gv_pic_addend",
                "gv_sig_allow_across_function_boundary",
            ],
            lines,
        )
        self.assertIn("gv_pic_addend: '0x2ee000'", raw)

    async def test_llm_found_funcptr_generates_regular_function(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "Callback.windows.yaml"
            llm_result = {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [
                    {
                        "funcptr_name": "Callback",
                        "insn_va": "0x401030",
                        "insn_disasm": "lea eax, sub_403000",
                    }
                ],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "lea eax, sub_403000",
                            "operand_targets": ["0x403000"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "Callback",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Callback"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Callback",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_funcptr"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Callback", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )

            self.assertTrue(result)
            self.assertEqual("Callback", yaml.safe_load(output.read_text(encoding="utf-8"))["func_name"])

    async def test_llm_found_vcall_uses_four_byte_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "VirtualTarget.windows.yaml"
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  5: '0x402000'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax+14h]",
                        "vfunc_offset": "0x14",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax+14h]",
                            "displacements": ["0x14"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x402000",
                            "func_rva": "0x2000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "VirtualTarget",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_vcall"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (
                            "VirtualTarget",
                            ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                        )
                    ],
                )

            self.assertTrue(result)
            payload = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual("0x14", payload["vfunc_offset"])
            self.assertEqual(5, payload["vfunc_index"])

    async def test_llm_found_vcall_accepts_zero_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  0: '0x402000'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax]",
                        "vfunc_offset": "0x0",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x402000",
                            "func_rva": "0x2000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                candidate = await _preprocess_llm_target(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    symbol_name="VirtualTarget",
                    category="vfunc",
                    spec={"expected_result_sections": ["found_vcall"]},
                    llm_config={"model": "test-model"},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    desired_fields=["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                    vtable_name="TargetClass",
                    llm_result=llm_result,
                    target_ranges=[(0x401000, 0x401100)],
                )

            self.assertEqual("0x0", candidate["vfunc_offset"])
            self.assertEqual(0, candidate["vfunc_index"])

    async def test_llm_vcall_retries_requested_signature_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "TargetClass_vtable.windows.yaml").write_text("vtable_entries:\n  0: '0x402000'\n")
            inspected = AsyncMock(
                side_effect=[
                    None,
                    {
                        "func_name": "VirtualTarget",
                        "func_va": "0x402000",
                        "func_rva": "0x2000",
                        "func_size": "0x200",
                        "func_sig": "55 8B EC",
                    },
                ]
            )
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspected),
            ):
                candidate = await _preprocess_llm_target(
                    session=None,
                    symbol_name="VirtualTarget",
                    category="vfunc",
                    spec={"expected_result_sections": ["found_vcall"]},
                    llm_config={},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    desired_fields=["vfunc_sig", "vfunc_sig_allow_across_function_boundary"],
                    vtable_name="TargetClass",
                    target_ranges=[(0x401000, 0x401100)],
                    llm_result={
                        "found_vcall": [{"func_name": "VirtualTarget", "insn_va": "0x401010", "vfunc_offset": "0x0"}]
                    },
                )
            self.assertIsNotNone(candidate)
            self.assertTrue(candidate["vfunc_sig_allow_across_function_boundary"])
            self.assertEqual(2, inspected.await_count)
            self.assertEqual({"allow_across_function_boundary": True}, inspected.await_args.kwargs)

    async def test_incomplete_vfunc_fast_path_still_enters_llm_batch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "VirtualTarget.windows.yaml"
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  0: '0x403000'\n",
                encoding="utf-8",
            )
            fast_candidate = {
                "func_name": "VirtualTarget",
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            }
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax]",
                        "vfunc_offset": "0x0",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=fast_candidate)),
                patch("ida_analyze_util.preprocess_vtable_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "VirtualTarget",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_vcall"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (
                            "VirtualTarget",
                            ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                        )
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["VirtualTarget"], call_llm.await_args.kwargs["symbol_names"])

    async def test_generated_function_signature_must_be_unique(self):
        function_payload = {
            "pointer_size": 4,
            "function": {
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            },
        }

        async def ambiguous_call_tool(name, _arguments):
            if name == "py_eval":
                return function_payload
            return {"matches": ["0x402000", "0x403000"], "n": 2}

        async def unique_call_tool(name, _arguments):
            if name == "py_eval":
                return function_payload
            return {"matches": ["0x402000"], "n": 1}

        self.assertIsNone(
            await _inspect_function_via_mcp(
                SimpleNamespace(call_tool=ambiguous_call_tool),
                0x402000,
                0x400000,
                "Target",
            )
        )
        self.assertEqual(
            "Target",
            (
                await _inspect_function_via_mcp(
                    SimpleNamespace(call_tool=unique_call_tool),
                    0x402000,
                    0x400000,
                    "Target",
                )
            )["func_name"],
        )

    async def test_llm_direct_call_resolves_requested_jmp_thunk(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [
                {
                    "func_name": "Target",
                    "insn_va": "0x401010",
                    "insn_disasm": "call j_Target",
                }
            ],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }
        inspected_function = {
            "func_name": "Target",
            "func_va": "0x403000",
            "func_rva": "0x3000",
            "func_size": "0x20",
            "func_sig": "55 8B EC 83 EC ??",
        }
        with (
            patch(
                "ida_analyze_util._inspect_llm_instruction",
                new=AsyncMock(
                    return_value={
                        "func_start": "0x401000",
                        "line": "call j_Target",
                        "code_refs": ["0x402000"],
                    }
                ),
            ),
            patch(
                "ida_analyze_util._resolve_jmp_thunk_target_via_mcp",
                new=AsyncMock(return_value=0x403000),
            ) as resolve_thunk,
            patch(
                "ida_analyze_util._inspect_function_via_mcp",
                new=AsyncMock(return_value=inspected_function),
            ) as inspect_function,
        ):
            candidate = await _preprocess_llm_target(
                session=SimpleNamespace(call_tool=AsyncMock()),
                symbol_name="Target",
                category="func",
                spec={"expected_result_sections": ["found_call"]},
                llm_config={"model": "test-model"},
                new_binary_dir=Path("D:/game/engine"),
                platform="windows",
                image_base=0x400000,
                desired_fields=[
                    "func_name",
                    "func_sig",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig_resolve_jmp_thunk",
                ],
                llm_result=llm_result,
                target_ranges=[(0x401000, 0x401100)],
            )

        self.assertEqual(inspected_function, candidate)
        resolve_thunk.assert_awaited_once()
        inspect_function.assert_awaited_once_with(ANY, 0x403000, 0x400000, "Target")

    def test_llm_function_export_builder_writes_json_via_remote_ack(self):
        code = _build_llm_function_export_py_eval(0x1AEBF0, "D:/tmp/export.json")
        compile(code, "<llm-function-export>", "exec")
        self.assertIn("tmp_path = output_path + '.tmp'", code)
        self.assertIn("os.replace(tmp_path, output_path)", code)
        self.assertIn("payload_text = json.dumps(payload)", code)
        self.assertLess(
            code.index("payload_text = json.dumps(payload)"), code.index("os.replace(tmp_path, output_path)")
        )

    async def test_export_llm_function_reads_remote_json_payload(self):
        exported = {
            "pointer_size": 4,
            "func_name": "ClientDLL_Init",
            "func_va": "0x1aebf0",
            "func_start": "0x1aebf0",
            "func_end": "0x1af71d",
            "disasm_code": "call FreeBlob",
            "procedure": "FreeBlob(&g_blobfootprintClient);",
            "chunk_ranges": [["0x1aebf0", "0x1af71d"]],
        }

        async def fake_call_tool(name, arguments=None, **_kwargs):
            self.assertEqual("py_eval", name)
            code = arguments["code"]
            output_path = None
            for line in code.splitlines():
                if line.startswith("output_path = "):
                    output_path = ast.literal_eval(line.split("=", 1)[1].strip())
                    break
            self.assertIsInstance(output_path, str)
            Path(output_path).write_text(json.dumps(exported), encoding="utf-8")
            return {
                "ok": True,
                "output_path": output_path,
                "bytes_written": Path(output_path).stat().st_size,
                "format": "json",
            }

        payload = await _export_llm_function(SimpleNamespace(call_tool=fake_call_tool), 0x1AEBF0)
        self.assertEqual(exported, payload)

    async def test_llm_global_address_feedback_retries_unknown_base(self):
        exported = {
            "func_name": "Owner",
            "func_start": "0x1000",
            "func_end": "0x1020",
            "disasm_code": "0x1000: mov [edx+2000h], eax\n0x1010: mov [ecx+3000h], eax",
            "procedure": "",
            "func_va": "0x1000",
        }
        context = {
            "targets": [({}, 0x1000)],
            "reference_items": [exported],
            "model": "test-model",
            "prompt_template": "{target_blocks}",
            "max_retries": 2,
        }
        for unknown_base, exhausted in ((False, False), (True, False), (True, True)):
            with self.subTest(unknown_base=unknown_base, exhausted=exhausted):
                requests = []

                def transport(**kwargs):
                    requests.append(kwargs["messages"])
                    use_first = len(requests) == 1 or exhausted
                    address, instruction = (
                        ("0x1000", "mov [edx+2000h], eax") if use_first else ("0x1010", "mov [ecx+3000h], eax")
                    )
                    return (
                        f"found_gv:\n  - insn_va: '{address}'\n    insn_disasm: '{instruction}'\n    gv_name: Target\n"
                    )

                async def inspect_instruction(session, address):
                    if unknown_base and address == "0x1000":
                        return {
                            "relative_store_address": {
                                "target": None,
                                "issue": "Cannot determine EDX base. 0x2000 is a displacement, not a complete global address.",
                            }
                        }
                    return {"relative_store_address": {"target": "0x9000"}}

                with (
                    patch("ida_analyze_util._export_llm_function", new=AsyncMock(return_value=exported)),
                    patch("ida_analyze_util._inspect_llm_instruction", side_effect=inspect_instruction),
                    patch("ida_llm_decompile._default_transport", side_effect=transport),
                ):
                    result, _ranges = await _call_llm_for_targets(
                        session=SimpleNamespace(),
                        symbol_names=["Target"],
                        specs={"Target": {"expected_result_sections": ["found_gv"]}},
                        context=context,
                        platform="linux",
                        new_binary_dir=Path("engine"),
                    )
                self.assertEqual(2 if unknown_base else 1, len(requests))
                if unknown_base:
                    feedback = requests[1][-1]["content"]
                    self.assertIn("EDX", feedback)
                    self.assertIn("displacement", feedback)
                    self.assertIn("same global", feedback)
                if exhausted:
                    self.assertEqual([], result["found_gv"])
                else:
                    self.assertEqual("0x1010" if unknown_base else "0x1000", result["found_gv"][0]["insn_va"])

    async def test_call_llm_for_targets_preserves_tail_chunk_ranges(self):
        keepalive_called = asyncio.Event()
        session = SimpleNamespace(call_tool=AsyncMock(side_effect=lambda **kwargs: keepalive_called.set()))

        async def call_llm_with_keepalive(**kwargs):
            await asyncio.wait_for(keepalive_called.wait(), timeout=1)
            return {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }

        exported = {
            "func_name": "Predecessor",
            "func_start": "0x401000",
            "func_end": "0x401050",
            "chunk_ranges": [["0x401000", "0x401050"], ["0x402000", "0x402020"]],
            "disasm_code": "0x402010: call sub_403000",
            "procedure": "sub_403000();",
        }
        context = {
            "targets": [({}, 0x401000)],
            "reference_items": [
                {
                    "func_name": "Predecessor",
                    "func_va": "0x401000",
                    "disasm_code": "call Target",
                    "procedure": "Target();",
                }
            ],
            "model": "test-model",
            "prompt_template": "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
        }
        with (
            patch("ida_analyze_util._export_llm_function", new=AsyncMock(return_value=exported)),
            patch(
                "ida_analyze_util.call_llm_decompile",
                new=AsyncMock(side_effect=call_llm_with_keepalive),
            ),
            patch("ida_mcp_keepalive.WORKER_KEEPALIVE_INTERVAL_SECONDS", 0.001),
        ):
            _result, target_ranges = await _call_llm_for_targets(
                session=session,
                symbol_names=["Target"],
                specs={"Target": {"expected_result_sections": ["found_call"]}},
                context=context,
                platform="windows",
                new_binary_dir=Path("D:/game/engine"),
            )

        session.call_tool.assert_awaited_with(name="py_eval", arguments={"code": "1"})
        self.assertEqual([(0x401000, 0x401050), (0x402000, 0x402020)], target_ranges)
        self.assertTrue(
            _llm_entry_instruction_is_valid(
                {"insn_va": "0x402010"},
                {"func_start": "0x401000", "line": "call sub_403000 ; tail chunk"},
                target_ranges,
                [
                    {"regex": r"jmp .+"},
                    {"regex": r"call sub_403000"},
                ],
            )
        )

    def test_prepare_llm_context_skips_missing_optional_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt = root / "prompt.md"
            required_reference = root / "Required.yaml"
            optional_reference = root / "Optional.yaml"
            required_current = root / "Required.windows.yaml"
            missing_optional = root / "Optional.windows.yaml"
            prompt.write_text("{reference_blocks}\n{target_blocks}\n{symbol_name_list}", encoding="utf-8")
            required_reference.write_text(
                "func_name: Required\nfunc_va: '0x401000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            optional_reference.write_text(
                "func_name: Optional\nfunc_va: '0x402000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            required_current.write_text("func_name: Required\nfunc_va: '0x411000'\n", encoding="utf-8")
            context = _prepare_llm_context(
                {
                    "symbol_name": "Target",
                    "prompt_path": str(prompt),
                    "reference_yaml_paths": [str(required_reference), str(optional_reference)],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {
                        "Required.{platform}.yaml": "required",
                        "Optional.{platform}.yaml": "optional",
                    },
                },
                {
                    "model": "test-model",
                    "_expected_inputs": [str(required_current)],
                    "_optional_inputs": [str(missing_optional)],
                },
                root,
                "windows",
            )

            self.assertEqual(1, len(context["targets"]))
            self.assertEqual(0x411000, context["targets"][0][1])
            self.assertEqual([str(required_reference.resolve())], context["reference_yaml_paths"])

    async def test_dependency_contract_is_validated_before_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "Target.windows.yaml"
            fast_path = AsyncMock(
                return_value={
                    "func_name": "Target",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "func_sig": "55 8B EC",
                }
            )
            with (
                patch("ida_analyze_util._prepare_llm_context", return_value=None) as prepare_context,
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Target",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_call"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )

            self.assertFalse(result)
            prepare_context.assert_called_once()
            fast_path.assert_not_awaited()

    def test_llm_spec_rejects_casefold_duplicate_dependency_policy(self):
        self.assertIsNone(
            _normalize_llm_decompile_specs(
                [
                    {
                        "symbol_name": "Target",
                        "prompt_path": "prompt.md",
                        "reference_yaml_paths": ["reference.windows.yaml"],
                        "expected_result_sections": ["found_call"],
                        "dependency_policy": {
                            "Predecessor.windows.yaml": "required",
                            "predecessor.windows.yaml": "required",
                        },
                    }
                ]
            )
        )

    def test_llm_templates_support_module_and_module_name(self):
        rendered = _resolve_llm_template(
            "references/{module}/{module_name}/Target.{platform}.yaml",
            Path("D:/game/engine"),
            "linux",
        )
        self.assertEqual("references/engine/engine/Target.linux.yaml", rendered)

    def test_llm_template_supports_gamever(self):
        rendered = _resolve_llm_template(
            "references/{gamever}/{module}/Target.{platform}.yaml",
            Path("D:/game/hl-10210/engine"),
            "linux",
        )
        self.assertEqual("references/hl-10210/engine/Target.linux.yaml", rendered)

    def test_resolve_reference_resource_prefers_current_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            current = (
                root
                / "ida_preprocessor_scripts"
                / "references"
                / "svencoop-10257"
                / "engine"
                / "SV_SendServerinfo.windows.yaml"
            )
            current.parent.mkdir(parents=True)
            current.write_text("func_name: SV_SendServerinfo\n", encoding="utf-8")

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
            ):
                resolved = _resolve_reference_resource(
                    "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(current.resolve(), resolved)

    def test_resolve_reference_resource_falls_back_to_canonical_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            canonical = (
                root
                / "ida_preprocessor_scripts"
                / "references"
                / "hl-10210"
                / "engine"
                / "SV_SendServerinfo.windows.yaml"
            )
            canonical.parent.mkdir(parents=True)
            canonical.write_text("func_name: SV_SendServerinfo\n", encoding="utf-8")

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
                patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True),
            ):
                resolved = _resolve_reference_resource(
                    "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(canonical.resolve(), resolved)

    def test_reference_fallback_order_is_current_family_then_global(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference_root = root / "references"
            template = "references/{gamever}/engine/Target.{platform}.yaml"
            paths = [reference_root / tag / "engine/Target.linux.yaml" for tag in ("sample-1", "sample-9", "other-8")]
            for path in paths:
                path.parent.mkdir(parents=True)
                path.touch()

            def resolve(value, binary_dir, platform):
                return root / _resolve_llm_template(value, binary_dir, platform)

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=resolve),
                patch.object(ida_analyze_util, "REFERENCE_RESOURCE_ROOT", reference_root),
                patch.object(ida_analyze_util, "FAMILY_REFERENCE_GAMEVERS", {"sample": "sample-9"}, create=True),
                patch.object(ida_analyze_util, "_reference_gamever", return_value="other-8"),
            ):
                for expected in paths:
                    self.assertEqual(
                        expected.resolve(), _resolve_reference_resource(template, root / "sample-1/engine", "linux")
                    )
                    expected.unlink()

    def test_resolve_reference_resource_without_gamever_placeholder_has_no_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            calls = []

            def _fake_resolve(value, new_binary_dir, platform):
                calls.append(value)
                return (root / "ida_preprocessor_scripts" / str(value).replace("{platform}", platform)).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
                patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True),
            ):
                resolved = _resolve_reference_resource(
                    "references/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(1, len(calls))
        self.assertNotIn("hl-10210", resolved.parts)

    def test_resolve_reference_resource_rejects_invalid_canonical_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            for gamever in ("", "../../..", "HL-10210"):
                with (
                    self.subTest(gamever=gamever),
                    patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                    patch.object(
                        ida_analyze_util,
                        "REFERENCE_RESOURCE_ROOT",
                        root / "ida_preprocessor_scripts" / "references",
                    ),
                    patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": gamever}, clear=True),
                    self.assertRaises(AnalysisConfigError),
                ):
                    _resolve_reference_resource(
                        "references/{gamever}/engine/SV_SendServerinfo.windows.yaml",
                        root / "missing-12345" / "engine",
                        "windows",
                    )

    def test_resolve_reference_resource_rejects_path_outside_reference_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference_root = root / "ida_preprocessor_scripts" / "references"
            outside = root / "outside" / "{gamever}" / "SV_SendServerinfo.windows.yaml"
            with (
                patch.object(ida_analyze_util, "REFERENCE_RESOURCE_ROOT", reference_root),
                self.assertRaisesRegex(ValueError, "outside reference root"),
            ):
                _resolve_reference_resource(outside, root / "hl-10210" / "engine", "windows")

    def test_resolve_reference_resource_uses_repository_svencoop_override(self):
        root = Path(__file__).parents[1]
        expected = (
            root
            / "ida_preprocessor_scripts"
            / "references"
            / "svencoop-10257"
            / "engine"
            / "SV_SendServerinfo.windows.yaml"
        ).resolve()
        with patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True):
            resolved = _resolve_reference_resource(
                "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                root / "bin" / "svencoop-10257" / "engine",
                "windows",
            )
        self.assertEqual(expected, resolved)

    async def test_common_preprocessor_rejects_non_x86_pointer_size(self):
        async def call_tool(_name, _arguments):
            return SimpleNamespace(
                structuredContent={"result": json.dumps({"candidates": [], "pointer_size": 8})},
                content=[],
                isError=False,
            )

        result = await preprocess_common_skill(
            session=SimpleNamespace(call_tool=call_tool),
            expected_outputs=[],
            platform="windows",
            image_base=0x400000,
            func_names=["R_RenderView"],
            func_xrefs=[{"func_name": "R_RenderView", "xref_strings": ["anchor"]}],
            generate_yaml_desired_fields=[("R_RenderView", ["func_name"])],
        )
        self.assertFalse(result)

    async def test_inherited_slot_only_vfunc_uses_four_byte_slots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Base_Run.windows.yaml").write_text(
                "func_name: Base_Run\nvtable_name: Base\nvfunc_offset: '0x14'\nvfunc_index: 5\n",
                encoding="utf-8",
            )
            result = await preprocess_index_based_vfunc_via_mcp(
                session=SimpleNamespace(call_tool=AsyncMock()),
                target_func_name="Derived_Run",
                target_output=root / "Derived_Run.windows.yaml",
                old_yaml_map=None,
                new_binary_dir=root,
                platform="windows",
                image_base=0x400000,
                base_vfunc_name="Base_Run",
                inherit_vtable_class="Derived",
                generate_func_sig=False,
                slot_only=True,
            )
            self.assertEqual(5, result["vfunc_index"])
            self.assertEqual("0x14", result["vfunc_offset"])

    async def test_indirect_vcall_helper_merges_pattern_i_and_l_on_x86(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Thunk.windows.yaml").write_text(
                "func_name: Thunk\nfunc_va: '0x401000'\n",
                encoding="utf-8",
            )

            async def call_tool(_name, _arguments):
                return SimpleNamespace(
                    structuredContent={
                        "result": json.dumps(
                            {
                                "pointer_size": 4,
                                "targets": [
                                    {
                                        "source_ea": "0x401010",
                                        "source_mnemonic": "jmp",
                                        "vfunc_offset": "0x14",
                                        "vfunc_index": 5,
                                    }
                                ],
                            }
                        )
                    },
                    content=[],
                    isError=False,
                )

            output = root / "IThing_Run.windows.yaml"
            result = await preprocess_indirect_vcall_target_skill(
                session=SimpleNamespace(call_tool=call_tool),
                expected_outputs=[str(output)],
                new_binary_dir=root,
                platform="windows",
                source_yaml_stem="Thunk",
                target_name="IThing_Run",
                vtable_name="IThing",
                generate_yaml_desired_fields=[
                    ("IThing_Run", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])
                ],
            )
            self.assertTrue(result)
            self.assertEqual(5, yaml.safe_load(output.read_text(encoding="utf-8"))["vfunc_index"])

    async def test_ordinal_vtable_helper_rejects_x64_and_normalizes_x86(self):
        async def call_tool(_name, _arguments):
            return SimpleNamespace(
                structuredContent={
                    "result": json.dumps(
                        {
                            "pointer_size": 4,
                            "selected": {
                                "vtable_class": "Thing",
                                "vtable_symbol": "??_7Thing@@6B@",
                                "vtable_va": "0x402000",
                                "vtable_size": "0x8",
                                "vtable_numvfunc": 2,
                                "vtable_entries": {"0": "0x401000", "1": "0x401100"},
                            },
                        }
                    )
                },
                content=[],
                isError=False,
            )

        result = await preprocess_ordinal_vtable_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            class_name="Thing",
            ordinal=0,
            image_base=0x400000,
            platform="windows",
        )
        self.assertEqual("0x2000", result["vtable_rva"])
        self.assertEqual({0: "0x401000", 1: "0x401100"}, result["vtable_entries"])


class PreprocessFuncSigViaMcpTests(unittest.IsolatedAsyncioTestCase):
    IMAGE_BASE = 0x400000
    FUNC_VA = 0x402000
    OTHER_VA = 0x403000
    CURRENT_SIG = "55 8B EC 83 EC ??"
    STALE_SIG = "90 90 90 90"
    OLD_SIG_RAW = "55 8b ec 90"
    OLD_SIG_NORMALIZED = "55 8B EC 90"

    def _write_old_yaml(self, root, *, func_sig=None, allow_across=False):
        payload = {"func_name": "Target"}
        if func_sig is not None:
            payload["func_sig"] = func_sig
        if allow_across:
            payload["func_sig_allow_across_function_boundary"] = True
        path = Path(root) / "Target.windows.yaml"
        path.write_text(yaml.safe_dump(payload), encoding="utf-8")
        return path

    def _inspect_payload(self, *, function=True):
        if not function:
            return {"pointer_size": 4, "function": None}
        return {
            "pointer_size": 4,
            "function": {
                "func_va": hex(self.FUNC_VA),
                "func_rva": hex(self.FUNC_VA - self.IMAGE_BASE),
                "func_size": "0x20",
                "func_sig": self.CURRENT_SIG,
            },
        }

    def _session(self, *, extra_matches=None, inspect_function=True, inspect_error=False):
        matches_by_pattern = {self.CURRENT_SIG: [self.FUNC_VA]}
        if extra_matches:
            matches_by_pattern.update(extra_matches)
        lookups = []
        py_eval_codes = []

        async def call_tool(name, arguments):
            if name == "find_bytes":
                pattern = arguments["patterns"][0]
                lookups.append(pattern)
                matches = matches_by_pattern.get(pattern, [])
                return {
                    "matches": [hex(match) if isinstance(match, int) else match for match in matches],
                    "n": len(matches),
                }
            if name == "py_eval":
                py_eval_codes.append(arguments["code"])
                if inspect_error:
                    raise RuntimeError("inspect failed")
                return self._inspect_payload(function=inspect_function)
            raise AssertionError(f"unexpected tool {name}")

        return SimpleNamespace(call_tool=call_tool, lookups=lookups, py_eval_codes=py_eval_codes)

    async def _preprocess(self, session, old_path, **kwargs):
        return await preprocess_func_sig_via_mcp(
            session,
            "Target.windows.yaml",
            old_path,
            self.IMAGE_BASE,
            "unused",
            "windows",
            func_name="Target",
            **kwargs,
        )

    async def test_direct_va_keeps_current_sig_when_old_sig_matches_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            session = self._session(extra_matches={self.STALE_SIG: []})
            result = await self._preprocess(session, old_path, direct_func_va=self.FUNC_VA)

        self.assertEqual(self.CURRENT_SIG, result["func_sig"])
        self.assertEqual(hex(self.FUNC_VA), result["func_va"])
        self.assertNotIn(self.STALE_SIG, session.lookups)
        self.assertEqual([self.CURRENT_SIG], session.lookups)

    async def test_direct_va_never_returns_old_sig_matching_other_or_multiple_locations(self):
        cases = (
            {self.STALE_SIG: [self.OTHER_VA]},
            {self.STALE_SIG: [self.FUNC_VA, self.OTHER_VA]},
        )
        for extra_matches in cases:
            with self.subTest(extra_matches=extra_matches), tempfile.TemporaryDirectory() as temporary:
                old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
                session = self._session(extra_matches=extra_matches)
                result = await self._preprocess(session, old_path, direct_func_va=hex(self.FUNC_VA))

                self.assertEqual(self.CURRENT_SIG, result["func_sig"])
                self.assertNotEqual(self.STALE_SIG, result["func_sig"])
                self.assertNotIn(self.STALE_SIG, session.lookups)

    async def test_direct_va_without_old_sig_keeps_current_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary)
            session = self._session()
            result = await self._preprocess(session, old_path, direct_func_va=self.FUNC_VA)

        self.assertEqual(self.CURRENT_SIG, result["func_sig"])
        self.assertEqual([self.CURRENT_SIG], session.lookups)

    async def test_direct_va_inspection_failure_returns_none_even_with_old_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            missing_function = self._session(extra_matches={self.STALE_SIG: [self.FUNC_VA]}, inspect_function=False)
            self.assertIsNone(await self._preprocess(missing_function, old_path, direct_func_va=self.FUNC_VA))
            self.assertEqual([], missing_function.lookups)

            inspect_error = self._session(extra_matches={self.STALE_SIG: [self.FUNC_VA]}, inspect_error=True)
            self.assertIsNone(await self._preprocess(inspect_error, old_path, direct_func_va=self.FUNC_VA))
            self.assertEqual([], inspect_error.lookups)

    async def test_ordinary_path_reuses_validated_unique_old_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(session, old_path)

        self.assertEqual(self.OLD_SIG_NORMALIZED, result["func_sig"])
        self.assertEqual(hex(self.FUNC_VA), result["func_va"])
        self.assertEqual([self.OLD_SIG_RAW, self.CURRENT_SIG], session.lookups)

    async def test_ordinary_path_missing_or_nonunique_old_sig_returns_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing_sig_path = self._write_old_yaml(temporary)
            session = self._session()
            self.assertIsNone(await self._preprocess(session, missing_sig_path))
            self.assertEqual([], session.lookups)
            self.assertEqual([], session.py_eval_codes)

            self.assertIsNone(await self._preprocess(session, None))
            self.assertEqual([], session.lookups)

            stale_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            for extra_matches in ({self.STALE_SIG: []}, {self.STALE_SIG: [self.FUNC_VA, self.OTHER_VA]}):
                with self.subTest(extra_matches=extra_matches):
                    session = self._session(extra_matches=extra_matches)
                    self.assertIsNone(await self._preprocess(session, stale_path))
                    self.assertEqual([self.STALE_SIG], session.lookups)
                    self.assertEqual([], session.py_eval_codes)

    async def test_across_function_boundary_flag_is_forwarded_and_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(
                session,
                old_path,
                allow_func_sig_across_function_boundary=True,
            )
            self.assertTrue(result["func_sig_allow_across_function_boundary"])
            self.assertIn("allow_across_function_boundary = True", session.py_eval_codes[0])

            old_flag_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW, allow_across=True)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(session, old_flag_path)
            self.assertTrue(result["func_sig_allow_across_function_boundary"])
            self.assertIn("allow_across_function_boundary = True", session.py_eval_codes[0])

            session = self._session()
            result = await self._preprocess(session, None, direct_func_va=self.FUNC_VA)
            self.assertNotIn("func_sig_allow_across_function_boundary", result)
            self.assertIn("allow_across_function_boundary = False", session.py_eval_codes[0])


if __name__ == "__main__":
    unittest.main()
