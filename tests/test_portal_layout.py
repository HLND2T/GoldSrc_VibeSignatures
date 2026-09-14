import copy
import unittest

from ida_preprocessor_scripts._portal_layout import constructor_offsets, linux_texture_offsets, source_mode_offset


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
