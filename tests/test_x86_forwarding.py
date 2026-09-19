"""Observable dataflow checks for straight-line x86 forwarding and GL calls."""

import unittest

from ida_preprocessor_scripts.x86_forwarding import trace_calls


def ins(mnemonic, *operands, target=None):
    return {"mnem": mnemonic, "ops": operands, "target": target}


class ForwardingTests(unittest.TestCase):
    def wrapper(self):
        code = [ins("push", ("reg", "ebx")), ins("sub", ("reg", "esp"), ("imm", 40))]
        # PIC call must preserve EAX loaded before it.
        code += [ins("mov", ("reg", "eax"), ("stack", 76)), ins("call", target=("pic", "ebx"))]
        code += [ins("add", ("reg", "ebx"), ("imm", 100)), ins("mov", ("stack", 28), ("reg", "eax"))]
        for index in reversed(range(7)):
            code += [ins("mov", ("reg", "eax"), ("stack", 48 + index * 4))]
            code += [ins("mov", ("stack", index * 4), ("reg", "eax"))]
        return code + [
            ins("call", target=("body", 0x2000)),
            ins("add", ("reg", "esp"), ("imm", 40)),
            ins("pop", ("reg", "ebx")),
            ins("retn"),
        ]

    def test_forwarded_arguments_survive_pic(self):
        calls = trace_calls(self.wrapper(), "linux", forwarding=True)
        self.assertEqual([("body", 0x2000)], [c[0] for c in calls])
        self.assertEqual([("arg", i) for i in range(8)], calls[0][1])

    def test_reject_swapped_argument(self):
        code = self.wrapper()
        code[5] = ins("mov", ("stack", 24), ("reg", "eax"))
        with self.assertRaises(ValueError):
            trace_calls(code, "linux", forwarding=True)

    def test_reject_multiple_calls_and_control_flow(self):
        for extra in [ins("call", target=("body", 0x3000)), ins("jne", ("imm", 0x1234))]:
            code = self.wrapper()
            code.insert(-4, extra)
            with self.assertRaises(ValueError):
                trace_calls(code, "linux", forwarding=True)

    def test_reject_unknown_instruction_and_unbalanced_stack(self):
        for extra in [ins("xor", ("reg", "eax"), ("reg", "eax")), ins("push", ("imm", 7))]:
            code = self.wrapper()
            code.insert(-1, extra)
            with self.assertRaises(ValueError):
                trace_calls(code, "linux", forwarding=True)

    def test_gl_arguments_follow_values_not_nearby_immediates(self):
        code = [
            ins("sub", ("reg", "esp"), ("imm", 8)),
            ins("mov", ("reg", "edx"), ("imm", 0x303)),
            ins("mov", ("reg", "edx"), ("imm", 1)),
            ins("mov", ("stack", 4), ("reg", "edx")),
            ins("mov", ("stack", 0), ("imm", 0x302)),
            ins("call", target=("gl", "glBlendFunc")),
            ins("add", ("reg", "esp"), ("imm", 8)),
            ins("retn"),
        ]
        self.assertEqual([0x302, 1], trace_calls(code, "linux")[0][1])

    def test_stdcall_cleanup_and_import_register(self):
        code = [
            ins("push", ("reg", "esi")),
            ins("mov", ("reg", "esi"), ("symbol", "glEnable")),
            ins("push", ("imm", 0xDE1)),
            ins("call", ("reg", "esi")),
            ins("push", ("imm", 1)),
            ins("push", ("imm", 0x302)),
            ins("call", target=("gl", "glBlendFunc")),
            ins("pop", ("reg", "esi")),
            ins("retn"),
        ]
        self.assertEqual([0x302, 1], trace_calls(code, "windows")[1][1])

    def test_call_clobbers_caller_saved_values(self):
        code = [
            ins("mov", ("reg", "eax"), ("imm", 0x303)),
            ins("call", target=("gl", "glEnd")),
            ins("push", ("reg", "eax")),
            ins("push", ("imm", 0x302)),
            ins("call", target=("gl", "glBlendFunc")),
            ins("retn"),
        ]
        self.assertEqual([0x302, None], trace_calls(code, "windows")[1][1])
