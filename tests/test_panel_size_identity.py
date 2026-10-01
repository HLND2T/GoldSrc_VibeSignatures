import unittest

from ida_preprocessor_scripts._panel_size_identity import (
    forwarding_calls_only,
    frame_minimum_candidate,
    proportional_helper_dispatches,
    size_constants,
)
from ida_preprocessor_scripts._x86_vcall_flow import trace_function, virtual_targets


class PanelSizeIdentityTests(unittest.TestCase):
    def call(self, ea, target, receiver, *args, platform="windows"):
        return dict(
            ea=ea, direct=target, this=receiver, stack_args=list(args) if platform == "windows" else [receiver, *args]
        )

    def test_plain_constants_on_both_abis(self):
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform):
                call = self.call(30, 900, ("arg", 0), ("const", 0), ("const", 640), platform=platform)
                self.assertEqual((0, 640), size_constants(call, {}, platform, scaled=False))

    def test_two_scaled_constants_on_both_abis(self):
        for platform in ("windows", "linux"):
            recv = ("load", ("arg", 0), 40)
            calls = {
                ea: self.call(ea, 800, recv, ("const", value), platform=platform)
                for ea, value in ((10, 624), (20, 278))
            }
            call = self.call(30, 900, recv, ("result", 10), ("result", 20), platform=platform)
            self.assertEqual((624, 278), size_constants(call, calls, platform, scaled=True, scale_method=800))

    def test_reused_scaled_result(self):
        calls = {10: self.call(10, 800, ("arg", 0), ("const", 18))}
        call = self.call(30, 900, ("arg", 0), ("result", 10), ("result", 10))
        self.assertEqual((18, 18), size_constants(call, calls, "windows", scaled=True, scale_method=800))

    def test_identical_choice_sets_do_not_prove_receiver_correlation(self):
        receiver = ("choice", ("arg", 0), ("arg", 1))
        calls = {10: self.call(10, 800, receiver, ("const", 18))}
        call = self.call(30, 900, receiver, ("result", 10), ("result", 10))
        self.assertIsNone(size_constants(call, calls, "windows", scaled=True, scale_method=800))

    def test_reject_wrong_receiver_target_variable_and_modified_result(self):
        for receiver, target, value, result in (
            (("arg", 1), 800, ("const", 18), ("result", 10)),
            (("arg", 0), 801, ("const", 18), ("result", 10)),
            (("arg", 0), 800, ("arg", 1), ("result", 10)),
            (("arg", 0), 800, ("const", 18), ("address", ("result", 10), 8)),
            (None, 800, ("const", 18), ("result", 10)),
        ):
            calls = {10: self.call(10, target, receiver, value)}
            call = self.call(30, 900, ("arg", 0), result, result)
            self.assertIsNone(size_constants(call, calls, "windows", scaled=True, scale_method=800))

    def test_reject_ambiguous_plain_or_scaled_and_restored_sizes(self):
        for value in (("choice", ("const", 18), ("const", 20)), ("arg", 1), None):
            call = self.call(30, 900, ("arg", 0), value, ("const", 20))
            self.assertIsNone(size_constants(call, {}, "windows", scaled=False))
        call = self.call(30, 900, ("arg", 0), ("const", 18), ("const", 20))
        self.assertIsNone(size_constants(call, {}, "windows", scaled=True, scale_method=800))

    def test_frame_minimum_is_a_candidate_not_a_method_identity(self):
        call = self.call(30, 900, ("arg", 0), ("const", 128), ("const", 66))
        self.assertEqual((900, None), frame_minimum_candidate(call, {}, "windows"))
        call["this"] = ("arg", 1)
        self.assertIsNone(frame_minimum_candidate(call, {}, "windows"))

    def test_plain_constants_do_not_require_recovering_the_receiver(self):
        call = self.call(30, 900, None, ("const", 624), ("const", 278))
        self.assertEqual((624, 278), size_constants(call, {}, "windows", scaled=False))
        self.assertIsNone(size_constants(call, {}, "windows", scaled=True, scale_method=800))

    def test_forwarder_rejects_setbounds_extra_dispatch(self):
        vpanel = ("load", ("load", ("arg", 0), 0), 12)
        setter = ("load", ("load", ("result", 10), 0), 44)
        calls = [
            dict(ea=10, direct=800, target=("const", 800)),
            dict(ea=20, direct=None, target=vpanel),
            dict(ea=30, direct=None, target=setter),
        ]
        self.assertTrue(forwarding_calls_only(calls, 30, 800, 12, virtual_targets))
        calls.append(dict(ea=40, direct=None, target=("load", ("load", ("result", 10), 0), 36)))
        self.assertFalse(forwarding_calls_only(calls, 30, 800, 12, virtual_targets))

    def test_scaler_requires_identity_and_both_dispatch_returns(self):
        calls = []
        for ea, slot in ((10, 44), (20, 60)):
            calls.append(dict(ea=ea, direct=800, target=("const", 800), this=None, stack_args=[]))
            calls.append(
                dict(
                    ea=ea + 1,
                    direct=None,
                    target=("load", ("load", ("result", ea), 0), slot),
                    this=("result", ea),
                    stack_args=[("arg", 1)],
                    tail=True,
                )
            )
        flow = dict(calls=calls, returns=[dict(value=("arg", 1))])
        self.assertEqual(
            [(800, 44, 11), (800, 60, 21)], proportional_helper_dispatches(flow, "windows", virtual_targets)
        )
        flow["returns"] = [dict(value=("const", 1))]
        self.assertIsNone(proportional_helper_dispatches(flow, "windows", virtual_targets))

    def test_linux_register_receiver_and_spilled_scale_results(self):
        def insn(ea, mnemonic, *operands, **extra):
            return dict(ea=ea, mnem=mnemonic, ops=list(operands), sp=-20, after=-20, **extra)

        def reg(name):
            return ("reg", name)

        def imm(value):
            return ("imm", value)

        def mem(offset):
            return ("mem", "esp", offset, None, 1)

        receiver = ("entry_register", 1, "eax")
        code = [
            insn(1, "mov", reg("esi"), reg("eax")),
            insn(2, "mov", mem(0), reg("esi")),
            insn(3, "mov", mem(4), imm(624)),
            insn(4, "call", imm(800), direct=800),
            insn(5, "mov", mem(16), reg("eax")),
            insn(6, "mov", mem(0), reg("esi")),
            insn(7, "mov", mem(4), imm(278)),
            insn(8, "call", imm(800), direct=800),
            insn(9, "mov", mem(8), reg("eax")),
            insn(10, "mov", reg("eax"), mem(16)),
            insn(11, "mov", mem(4), reg("eax")),
            insn(12, "mov", mem(0), reg("esi")),
            insn(13, "call", imm(900), direct=900),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux", entry_state={"eax": receiver})
        calls = {c["ea"]: c for c in flow["calls"]}
        self.assertEqual((624, 278), size_constants(calls[13], calls, "linux", scaled=True, scale_method=800))
        code.insert(-1, insn(125, "add", mem(4), imm(8)))
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux", entry_state={"eax": receiver})
        calls = {c["ea"]: c for c in flow["calls"]}
        self.assertIsNone(size_constants(calls[13], calls, "linux", scaled=True, scale_method=800))


if __name__ == "__main__":
    unittest.main()
