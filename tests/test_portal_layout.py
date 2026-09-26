import copy
import unittest

from ida_preprocessor_scripts._portal_layout import constructor_offsets, linux_texture_offsets, source_mode_offset
from ida_preprocessor_scripts._portal_render_state import recover_shader_member, clip_setup, clip_call_arguments


def reg(name, size=4):
    return {"kind": "reg", "size": size, "reg": name}


def mem(base, disp=0, size=4):
    return {"kind": "mem", "size": size, "base": base, "disp": disp}


def imm(value):
    return {"kind": "imm", "size": 4, "value": value}


def ins(mnemonic, *ops, writes=()):
    return {"mnemonic": mnemonic, "operands": list(ops), "writes": list(writes)}


def api(name):
    return ins("call", {"kind": "api", "size": 4, "name": name})


def constructor(platform, start=0, wide=False):
    code = [ins("mov", reg("esi"), reg("ecx"))] if platform == "windows" else [ins("mov", reg("esi"), mem("esp", 4))]
    first = 8 if platform == "windows" else 12
    for vector in range(3):
        code.append(ins("mov", reg("edi"), mem("esp", first + 4 * vector)))
        for offset, size in [(0, 8), (8, 4)] if wide else [(0, 4), (4, 4), (8, 4)]:
            r = reg("xmm0", 16) if size == 8 else reg("eax")
            mnemonic = "movq" if size == 8 else "mov"
            code += [
                ins(mnemonic, r, mem("edi", offset, size)),
                ins(mnemonic, mem("esi", start + vector * 12 + offset, size), r),
            ]
    return code + [ins("ret")]


def texture(offset=196):
    return [
        ins("lea", reg("eax"), mem("esi", offset)),
        ins("mov", mem("esp", 4), reg("eax")),
        ins("mov", mem("esp"), imm(1)),
        api("glGenTextures"),
        ins("mov", mem("esp"), imm(0xDE1)),
        api("glEnable"),
        ins("mov", reg("edx"), mem("esi", offset)),
        ins("mov", mem("esp", 4), reg("edx")),
        ins("mov", mem("esp"), imm(0xDE1)),
        api("glBindTexture"),
        ins("mov", reg("ecx"), mem("esi", offset + 8)),
        ins("mov", mem("esp", 16), reg("ecx")),
        ins("mov", reg("esi"), mem("esi", offset + 4)),
        ins("mov", mem("esp", 12), reg("esi")),
        ins("mov", mem("esp"), imm(0xDE1)),
        api("glTexImage2D"),
    ]


class PortalLayoutTests(unittest.TestCase):
    def shader_fixture(self, flag=36, program=40):
        init, draw = 100, 200
        body = [
            ins("mov", reg("esi"), reg("ecx")),
            ins("mov", mem("esi", flag, 1), imm(1)),
            ins("mov", mem("esi", flag, 1), imm(0)),
            ins("mov", mem("esi", program), imm(0)),
            ins("ret"),
        ]
        toggles = []
        for argument in [mem("ebx", program), imm(0)]:
            start = len(toggles)
            toggles += [
                ins("mov", reg("ecx"), reg("ebx")),
                ins("call", {"kind": "func", "size": 4, "value": init}),
                ins("cmp", mem("ebx", flag, 1), imm(0)),
                ins("jz"),
                ins("mov", reg("eax"), {"kind": "global", "size": 4, "value": 900}),
                ins("push", argument),
                ins("call", reg("eax")),
                ins("nop"),
            ]
            toggles[start + 3]["successors"] = [start + 4, start + 7]
        toggles.append(ins("ret"))
        for code in [body, toggles]:
            for i, item in enumerate(code):
                item["ea"] = i
        return init, draw, {init: body, draw: toggles}

    def test_shader_byte_agrees_with_both_live_toggles(self):
        for flag, program in [(36, 40), (80, 100)]:
            init, draw, functions = self.shader_fixture(flag, program)
            result = recover_shader_member(init, draw, functions, "windows")
            self.assertEqual((flag, 1, program), (result["offset"], result["size"], result["program"]))

    def test_linux_shader_wrappers_allow_cdecl_cleanup_and_split_reset(self):
        for split in (False, True):
            init, draw, functions = self.shader_fixture()
            functions[init][0] = ins("mov", reg("esi"), mem("esp", 4))
            functions[draw] = [
                ins("call", {"kind": "func", "size": 4, "value": 300}),
                ins("call", {"kind": "func", "size": 4, "value": 400}),
                ins("ret"),
            ]
            for owner, argument in [(300, mem("ebx", 40)), (400, imm(0))]:
                functions[owner] = [
                    ins("mov", reg("ebx"), mem("esp", 4)),
                    ins("push", reg("ebx")),
                    ins("call", {"kind": "func", "size": 4, "value": init}),
                    ins("add", reg("esp"), imm(4)),
                    ins("cmp", mem("ebx", 36, 1), imm(0)),
                    ins("jz"),
                    ins("mov", reg("eax"), {"kind": "global", "size": 4, "value": 900}),
                    ins("push", argument),
                    ins("call", reg("eax")),
                    ins("ret"),
                ]
                functions[owner][5]["successors"] = [6, 9]
            if split:
                functions[400][6:] = [ins("call", {"kind": "func", "size": 4, "value": 500}), ins("ret")]
                functions[400][5]["successors"] = [6, 7]
                functions[500] = [
                    ins("mov", reg("eax"), {"kind": "global", "size": 4, "value": 900}),
                    ins("push", imm(0)),
                    ins("call", reg("eax")),
                    ins("ret"),
                ]
            for code in functions.values():
                for i, item in enumerate(code):
                    item["ea"] = i
            result = recover_shader_member(init, draw, functions, "linux")
            self.assertEqual((36, 1), (result["offset"], result["size"]))

    def test_shader_rejects_wrong_width_local_flag_and_disagreeing_reads(self):
        for mutation in ["width", "stack", "other_flag", "program", "slot", "missing_enable_write"]:
            init, draw, functions = self.shader_fixture()
            if mutation == "width":
                functions[init][1]["operands"][0]["size"] = 4
            elif mutation == "stack":
                functions[init][1]["operands"][0]["base"] = "esp"
            elif mutation == "other_flag":
                functions[draw][10]["operands"][0]["disp"] = 37
            elif mutation == "program":
                functions[draw][5]["operands"][0]["disp"] = 36
            elif mutation == "slot":
                functions[draw][12]["operands"][1]["value"] = 901
            else:
                functions[init][1]["operands"][1] = imm(0)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recover_shader_member(init, draw, functions, "windows")

    def test_clip_setup_distinguishes_diagnostic_owner_and_wrong_gl_cap(self):
        code = [
            api("glLoadIdentity"),
            ins("lea", reg("esi"), mem("edi", 0x3000)),
            ins("lea", reg("eax"), mem("esp", 32)),
            ins("mov", mem("esp", 4), reg("eax")),
            ins("mov", mem("esp"), reg("esi")),
            api("glClipPlane"),
            ins("mov", mem("esp"), reg("esi")),
            api("glEnable"),
        ]
        for i, item in enumerate(code):
            item["ea"] = i
        self.assertTrue(clip_setup(code, "linux"))
        self.assertFalse(clip_setup([api("printf")], "linux"))
        code[1]["operands"][1]["disp"] = 0xDE1
        self.assertFalse(clip_setup(code, "linux"))

    def test_clip_caller_requires_related_view_vectors(self):
        code = [
            ins("lea", reg("eax"), mem("esi", 12)),
            ins("push", reg("edi")),
            ins("push", reg("esi")),
            ins("push", reg("eax")),
            ins("push", imm(0)),
            ins("mov", reg("ecx"), reg("ebx")),
            ins("call", {"kind": "func", "size": 4, "value": 100}),
        ]
        self.assertTrue(clip_call_arguments(code, 100, "windows"))
        code[0]["operands"][1]["disp"] = 16
        self.assertFalse(clip_call_arguments(code, 100, "windows"))

    def test_getter_tracks_pointer_arithmetic_after_entity_load(self):
        from ida_preprocessor_scripts._portal_layout import getter_return

        code = [
            ins("mov", reg("eax"), mem("esp", 4)),
            ins("mov", reg("eax"), mem("eax", 112)),
            ins("add", reg("eax"), imm(2888)),
            ins("ret"),
        ]
        self.assertEqual(("ptr", ("load", ("ptr", "this", 112), 4), 2888), getter_return(code, "linux"))
        code[1]["operands"][1]["size"] = 1
        self.assertIsNone(getter_return(code, "linux"))

    def test_client_transform_keeps_entity_indirection_separate(self):
        from ida_preprocessor_scripts._portal_layout import client_transform_offsets

        for platform in ("windows", "linux"):
            for entity, origin, mode in ((112, 2888, 40), (64, 120, 24)):
                code = [
                    ins("mov", reg("edi"), mem("esi", entity)),
                    ins("lea", reg("eax"), mem("edi", origin)),
                    ins("lea", reg("edx"), mem("edi", origin + 12)),
                    ins("lea", reg("ecx"), mem("esi", 12)),
                ]
                args = [mem("esi", mode), imm(1), imm(2), reg("eax"), reg("edx"), reg("esi"), reg("ecx")]
                if platform == "linux":
                    args.insert(0, reg("ebx"))
                code += [ins("push", arg) for arg in reversed(args)]
                code.append(ins("call", {"kind": "func", "size": 4, "value": 1234}))
                self.assertEqual(
                    {"mode": mode, "entity": entity, "origin": origin, "angles": origin + 12},
                    client_transform_offsets(code, platform, 1234, {}),
                )
                code[0]["operands"][1]["base"] = "ebx"
                with self.assertRaises(ValueError):
                    client_transform_offsets(code, platform, 1234, {})

    def test_constructor_accepts_bounded_rep_movsd_vec3_copies(self):
        code = [ins("mov", reg("ebx"), mem("esp", 4))]
        for index in range(3):
            code += [
                ins("lea", reg("edi"), mem("ebx", index * 12)),
                ins("mov", reg("esi"), mem("esp", 12 + index * 4)),
                ins("mov", reg("ecx"), imm(3)),
                ins("rep_movsd"),
            ]
        self.assertEqual({"origin": 0, "angles": 12}, constructor_offsets(code, "linux"))
        code[3] = ins("mov", reg("ecx"), imm(2))
        with self.assertRaises(ValueError):
            constructor_offsets(code, "linux")

    def test_texture_accepts_verified_cdecl_this_stack_argument(self):
        load = ins("mov", reg("esi"), mem("esp", 32))
        load["stack_offset"] = -28
        code = [load, ins("nop")] + texture()
        self.assertEqual({"texture_id": 196, "texture_width": 200, "texture_height": 204}, linux_texture_offsets(code))
        load["stack_offset"] = -24
        with self.assertRaises(ValueError):
            linux_texture_offsets(code)

    def test_constructor_reads_zero_displacement_and_alternate_layouts(self):
        for platform in ("windows", "linux"):
            for start in (0, 16):
                for wide in (False, True):
                    with self.subTest(platform=platform, start=start, wide=wide):
                        self.assertEqual(
                            {"origin": start, "angles": start + 12},
                            constructor_offsets(constructor(platform, start, wide), platform),
                        )

    def test_constructor_rejects_incomplete_or_clobbered_copies(self):
        for mutation in ("missing", "source", "destination", "partial", "branch", "implicit"):
            code = constructor("windows")
            if mutation == "missing":
                del code[3]
            elif mutation == "source":
                code[1]["operands"][1] = mem("esp", 100)
            elif mutation == "destination":
                code[3]["operands"][0] = mem("ebx")
            elif mutation == "partial":
                code.insert(-1, ins("mov", mem("esi", 0, 1), imm(0)))
            elif mutation == "branch":
                code.insert(2, ins("jmp"))
            else:
                code.insert(2, ins("mul", reg("ebx")))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                constructor_offsets(code, "windows")

    def test_mode_is_relative_to_source_argument(self):
        for platform in ("windows", "linux"):
            for offset in (64, 92):
                code = []
                args = [mem("esi", offset), imm(1), imm(2), reg("esi")]
                if platform == "linux":
                    args.insert(0, reg("edi"))
                    for i, arg in enumerate(args):
                        code += [ins("mov", reg("eax"), arg), ins("mov", mem("esp", i * 4), reg("eax"))]
                else:
                    code = [ins("push", arg) for arg in reversed(args)]
                code.append(ins("call", {"kind": "func", "size": 4, "value": 1234}))
                self.assertEqual(offset, source_mode_offset(code, platform, 1234))
                wrong = copy.deepcopy(code)
                for item in wrong:
                    for op in item["operands"]:
                        if op.get("base") == "esi":
                            op["base"] = "edi"
                with self.assertRaises(ValueError):
                    source_mode_offset(wrong, platform, 1234)

    def test_linux_texture_follows_gl_arguments(self):
        for offset in (96, 196):
            self.assertEqual(
                {"texture_id": offset, "texture_width": offset + 4, "texture_height": offset + 8},
                linux_texture_offsets([ins("mov", reg("esi"), reg("eax")), ins("nop")] + texture(offset)),
            )
        for mutation in (
            "wrong_object",
            "missing_bind",
            "wrong_target",
            "clobber",
            "branch",
            "partial_stack",
            "ambiguous",
        ):
            code = texture()
            if mutation == "wrong_object":
                code[10]["operands"][1]["base"] = "edi"
            elif mutation == "missing_bind":
                code[9] = api("unrelated")
            elif mutation == "wrong_target":
                code[8]["operands"][1] = imm(0)
            elif mutation == "clobber":
                code.insert(10, ins("mov", reg("esi"), imm(0)))
            elif mutation == "branch":
                code.insert(10, ins("jmp"))
            elif mutation == "partial_stack":
                code.insert(9, ins("mov", mem("esp", 4, 1), imm(0)))
            else:
                branch = ins("jmp")
                branch["successors"] = [3, len(code) + 4]
                code = [branch] + code + [ins("ret")] + texture(96)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                linux_texture_offsets([ins("mov", reg("esi"), reg("eax")), ins("nop")] + code)

    def test_linux_mode_resolves_dominating_stack_spill(self):
        for header in (8, 20):
            code = [
                ins("lea", reg("edi"), mem("ebp", header), writes=("edi",)),
                ins("mov", mem("esp", 56), reg("edi")),
                api("unrelated"),
                ins("mov", reg("eax"), mem("esp", 56), writes=("eax",)),
                ins("mov", mem("esp", 16), reg("eax")),
                ins("mov", reg("edx"), mem("ebp", header + 64), writes=("edx",)),
                ins("mov", mem("esp", 4), reg("edx")),
                ins("call", {"kind": "func", "size": 4, "value": 1234}),
            ]
            self.assertEqual(64, source_mode_offset(code, "linux", 1234))
            for mutation in ("bypass", "base_write", "spill_write"):
                wrong = copy.deepcopy(code)
                if mutation == "bypass":
                    wrong[0]["successors"] = [1, 2]
                elif mutation == "base_write":
                    wrong.insert(3, ins("mov", reg("ebp"), imm(0), writes=("ebp",)))
                else:
                    write = ins("mov", mem("esp", 57, 1), imm(0))
                    write["memory_writes"] = [mem("esp", 57, 1)]
                    wrong.insert(3, write)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    source_mode_offset(wrong, "linux", 1234)
