"""Semantic checks for Frame key events, independent of table layout."""

import copy
import unittest

from ida_preprocessor_scripts._frame_key_identity import (
    identify_pressed,
    identify_typed,
    message_posts,
    unique_slot,
)


THIS = ("arg", 0)


def virtual(ea, receiver, slot, args, block):
    return dict(
        ea=ea, block=block, direct=None, target=("load", ("load", receiver, 0), slot * 4), args=[receiver, *args]
    )


def fixture():
    getter = dict(ea=11, block=10, direct=900, target=("const", 900), args=[])
    support = virtual(12, ("result", 11), 42, [("const", 3)], 10)
    ctor = dict(
        ea=21,
        block=20,
        direct=800,
        target=("const", 800),
        args=[("result", 19), ("const", 1000), ("const", 1001), ("const", 1002)],
    )
    post = virtual(22, THIS, 17, [THIS, ("choice", ("const", 0), ("result", 21)), ("const", 0)], 20)
    flow = dict(
        calls=[getter, support, ctor, post],
        blocks={0: [10, 99], 10: [20, 99], 20: [99], 99: []},
        equalities=[dict(values=[("arg", 1), ("const", 70)], equal=10, unequal=99)],
        branches=[dict(condition=("result", 12), nonzero=20, zero=99)],
    )
    literals = {name: {address} for name, address in zip(("Command", "command", "Cancel"), range(1000, 1003))}
    return flow, literals


class FrameKeyIdentityTests(unittest.TestCase):
    def test_typed_identity_does_not_require_an_escape_branch(self):
        literals = {"CloseFrameButtonPressed": {1000}, "Hotkey": {1001}}
        flow = dict(
            calls=[],
            branches=[],
            blocks={0: [10, 20, 99], 10: [99], 20: [99], 99: []},
            equalities=[
                dict(values=[("arg", 1), ("const", 95)], equal=10, unequal=20),
                dict(values=[("arg", 1), ("const", 64)], equal=20, unequal=10),
            ],
        )
        for block, label, recipient in ((10, 1000, THIS), (20, 1001, ("result", 88))):
            flow["calls"].extend(
                [
                    dict(
                        ea=block + 1,
                        block=block,
                        direct=800,
                        target=("const", 800),
                        args=[("result", block), ("const", label)],
                    ),
                    virtual(block + 2, THIS, 17, [recipient, ("result", block + 1), ("const", 0)], block),
                ]
            )
        for i, key in enumerate(range(79, 85)):
            ea = 30 + i * 2
            flow["calls"].extend(
                [
                    dict(ea=ea, block=0, direct=900, target=("const", 900), args=[]),
                    virtual(ea + 1, ("result", ea), 42, [("const", key)], 0),
                ]
            )
        self.assertEqual((900, 42), identify_typed(flow, literals))
        flow["equalities"][0]["values"][1] = ("const", 70)
        with self.assertRaises(ValueError):
            identify_typed(flow, literals)

    def test_cancel_requires_escape_and_positive_capability(self):
        flow, literals = fixture()
        self.assertEqual((900, 42, 17), identify_pressed(flow, literals))
        for field in ("equalities", "branches"):
            bad = copy.deepcopy(flow)
            bad[field] = []
            with self.assertRaises(ValueError):
                identify_pressed(bad, literals)

    def test_other_key_and_wrong_recipient_are_rejected(self):
        flow, literals = fixture()
        flow["equalities"][0]["values"][1] = ("const", 95)
        with self.assertRaises(ValueError):
            identify_pressed(flow, literals)
        flow, literals = fixture()
        flow["calls"][-1]["args"][1] = ("arg", 2)
        with self.assertRaises(ValueError):
            identify_pressed(flow, literals)

    def test_message_must_be_the_constructed_object(self):
        flow, literals = fixture()
        flow["calls"][-1]["args"][2] = ("result", 777)
        self.assertEqual([], message_posts(flow, literals, ("Command", "command", "Cancel")))

    def test_slot_is_recovered_and_ambiguity_rejected(self):
        self.assertEqual(237, unique_slot({4: 99, 237: 123}, 123))
        with self.assertRaises(ValueError):
            unique_slot({4: 123, 237: 123}, 123)


if __name__ == "__main__":
    unittest.main()
