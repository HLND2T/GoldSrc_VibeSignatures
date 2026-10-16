"""Synthetic behavior checks for receiver/argument based menu identities."""

import copy
import unittest

from ida_preprocessor_scripts._combobox_unicode_identity import (
    add_item_evidence,
    recover_menu_getter,
    spectator_update_calls,
    update_item_evidence,
)


THIS = ("arg", 0)
TEXT = ("arg", 1)
USER = ("arg", 2)


def call(ea, receiver, *args, index=None, direct=None, block=1):
    target = ("load", ("load", receiver, 0), index * 4) if index is not None else ("const", direct)
    return dict(ea=ea, args=[receiver, *args], target=target, direct=direct, block=block)


def insertion(offset=0x94, index=17, wide=False):
    message = call(100, ("stack", -40), ("const", 10), ("const", 20), TEXT, direct=900)
    menu = ("load", THIS, offset)
    dispatch = call(200, menu, ("stack", -100) if wide else TEXT, ("result", 100), THIS, USER, index=index)
    return dict(
        flow=dict(calls=[message, dispatch], returns=[dict(value=("result", 200))]),
        converted_menu_calls=[200] if wide else [],
    )


LITERALS = dict(SetText=dict(addresses=[10]), text=dict(addresses=[20]))


class MenuIdentityTests(unittest.TestCase):
    def test_derives_current_member_and_slot_after_reordering(self):
        for offset, index in ((0x94, 17), (0xB4, 41)):
            method = insertion(offset, index)
            method["flow"]["calls"].reverse()
            found = add_item_evidence(method, LITERALS)
            self.assertEqual((offset, index), (found["dropdown"], found["menu_index"]))

    def test_rejects_wrong_target_userdata_text_message_and_return(self):
        for argument, value in ((1, ("const", 99)), (2, USER), (3, USER), (4, THIS)):
            method = insertion()
            method["flow"]["calls"][1]["args"][argument] = value
            self.assertIsNone(add_item_evidence(method, LITERALS))
        method = insertion()
        method["flow"]["returns"][0]["value"] = ("result", 999)
        self.assertIsNone(add_item_evidence(method, LITERALS))

    def test_wide_requires_same_conversion_output_and_original_message_input(self):
        method = insertion(wide=True)
        self.assertIsNotNone(add_item_evidence(method, LITERALS, wide=True))
        self.assertIsNone(add_item_evidence(method, LITERALS))
        method["converted_menu_calls"] = [201]
        self.assertIsNone(add_item_evidence(method, LITERALS, wide=True))
        method = insertion(wide=True)
        method["flow"]["calls"][0]["args"][3] = ("stack", -100)
        self.assertIsNone(add_item_evidence(method, LITERALS, wide=True))

    def test_nullable_message_is_accepted_but_unrelated_choice_is_rejected(self):
        method = insertion()
        method["flow"]["calls"][1]["args"][2] = ("choice", ("const", 0), ("result", 100))
        self.assertIsNotNone(add_item_evidence(method, LITERALS))
        method["flow"]["calls"][1]["args"][2] += (("result", 101),)
        self.assertIsNone(add_item_evidence(method, LITERALS))

    def test_ambiguous_insertion_fails_closed(self):
        method = insertion()
        duplicate = copy.deepcopy(method["flow"]["calls"][1])
        duplicate["ea"] = 201
        method["flow"]["calls"].append(duplicate)
        method["flow"]["returns"].append(dict(value=("result", 201)))
        with self.assertRaises(ValueError):
            add_item_evidence(method, LITERALS)

    def test_getter_requires_unique_pure_member_return(self):
        getter = dict(flow=dict(calls=[], stores=[], returns=[dict(value=("load", THIS, 0x94))]))
        self.assertEqual(getter, recover_menu_getter([getter], 0x94))
        with self.assertRaises(ValueError):
            recover_menu_getter([getter, copy.deepcopy(getter)], 0x94)


def guarded_update():
    combo, item = ("load", THIS, 0x58), ("arg", 3)
    check = call(10, combo, item, index=13, block=1)
    add = call(20, combo, TEXT, USER, index=33, block=2)
    update = call(30, combo, item, TEXT, USER, index=7, block=3)
    return dict(
        flow=dict(
            calls=[update, add, check],
            blocks={1: [2, 3], 2: [4], 3: [4], 4: [1]},
            branches=[dict(condition=("narrow", ("result", 10), 1), zero=2, nonzero=3)],
        )
    )


class GuardedUpdateTests(unittest.TestCase):
    def test_accepts_reordered_calls_and_loop_backedge(self):
        found = spectator_update_calls(guarded_update())
        self.assertEqual((10, 20, 30), tuple(found[k]["ea"] for k in ("check", "add", "update")))

    def test_rejects_wrong_receiver_arguments_and_branch(self):
        for fault in ("receiver", "userdata", "id", "branch"):
            method = guarded_update()
            update = method["flow"]["calls"][0]
            if fault == "receiver":
                update["args"][0] = ("load", THIS, 0x60)
            elif fault == "userdata":
                update["args"][3] = ("const", 0)
            elif fault == "id":
                update["args"][1] = ("arg", 4)
            else:
                update["block"] = 2
            self.assertIsNone(spectator_update_calls(method))


def item_update():
    menu = ("load", THIS, 0x94)
    check = call(10, menu, ("arg", 1), index=13, block=1)
    message = call(20, ("stack", -40), ("const", 10), ("const", 20), ("stack", -80), direct=900, block=3)
    update = call(30, menu, ("arg", 1), ("arg", 2), ("result", 20), ("arg", 3), index=31, block=3)
    invalidate = call(40, THIS, ("const", 0), ("const", 0), index=61, block=3)
    return dict(
        flow=dict(
            calls=[invalidate, update, message, check],
            blocks={1: [2, 3], 2: [], 3: []},
            branches=[dict(condition=("result", 10), zero=2, nonzero=3)],
        )
    )


class UpdateItemTests(unittest.TestCase):
    def test_recovers_menu_update_and_layout_without_fixed_slots(self):
        method = item_update()
        found = update_item_evidence(method, LITERALS, 0x94)
        self.assertEqual((30, 40), (found["update"]["ea"], found["invalidate"]["ea"]))
        method["flow"]["calls"][0]["target"] = ("load", ("load", THIS, 0), 79 * 4)
        self.assertIsNotNone(update_item_evidence(method, LITERALS, 0x94))

    def test_rejects_wrong_id_text_userdata_message_and_branch(self):
        for argument in (1, 2, 3, 4):
            method = item_update()
            method["flow"]["calls"][1]["args"][argument] = ("const", 999)
            self.assertIsNone(update_item_evidence(method, LITERALS, 0x94))
        method = item_update()
        method["flow"]["calls"][1]["block"] = 2
        self.assertIsNone(update_item_evidence(method, LITERALS, 0x94))
        method = item_update()
        method["flow"]["calls"][0]["args"][1] = ("const", 1)
        self.assertIsNone(update_item_evidence(method, LITERALS, 0x94))


if __name__ == "__main__":
    unittest.main()
