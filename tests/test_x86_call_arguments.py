import unittest

from ida_preprocessor_scripts.x86_call_arguments import recover_call_arguments


class CallArgumentsTests(unittest.TestCase):
    def test_right_to_left_pushes(self):
        instructions = [
            {"mnem": "push", "sp": 0, "ops": [("imm", 1)]},
            {"mnem": "push", "sp": -4, "ops": [("imm", 770)]},
            {"mnem": "call", "sp": -8, "ops": []},
        ]
        self.assertEqual([770, 1], recover_call_arguments(instructions, 2, 2))

    def test_register_to_reserved_stack_and_zero(self):
        instructions = [
            {"mnem": "mov", "sp": -16, "ops": [("reg", "eax"), ("imm", 24)]},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -16), ("reg", "eax")]},
            {"mnem": "xor", "sp": -16, "ops": [("reg", "edx"), ("reg", "edx")]},
            {"mnem": "mov", "sp": -16, "ops": [("stack", -12), ("reg", "edx")]},
            {"mnem": "call", "sp": -16, "ops": []},
        ]
        self.assertEqual([24, 0], recover_call_arguments(instructions, 4, 2))

    def test_unknown_overwrite_and_call_clobber(self):
        for overwrite in ("add", "call"):
            with self.subTest(overwrite=overwrite):
                instructions = [
                    {"mnem": "mov", "sp": -4, "ops": [("reg", "eax"), ("imm", 1)]},
                    {"mnem": overwrite, "sp": -4, "ops": [("reg", "eax"), ("imm", 2)]},
                    {"mnem": "mov", "sp": -4, "ops": [("stack", -4), ("reg", "eax")]},
                    {"mnem": "call", "sp": -4, "ops": []},
                ]
                self.assertEqual([None], recover_call_arguments(instructions, 3, 1))

    def test_branch_prevents_cross_path_inference(self):
        instructions = [
            {"mnem": "push", "sp": 0, "ops": [("imm", 7)]},
            {"mnem": "jne", "sp": -4, "ops": []},
            {"mnem": "call", "sp": -4, "ops": []},
        ]
        self.assertEqual([None], recover_call_arguments(instructions, 2, 1))

    def test_call_does_not_prove_reused_stack_contents(self):
        instructions = [
            {"mnem": "mov", "sp": -4, "ops": [("stack", -4), ("imm", 7)]},
            {"mnem": "call", "sp": -4, "ops": []},
            {"mnem": "call", "sp": -4, "ops": []},
        ]
        self.assertEqual([None], recover_call_arguments(instructions, 2, 1))
