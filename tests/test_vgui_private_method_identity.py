"""Behavioral regression checks for VGUI method identity over decoded flow."""

import copy
import unittest

from ida_preprocessor_scripts._vgui_private_method_identity import recover_private_methods


THIS = ("arg", 0)
KEY = ("arg", 1)
SCROLLBAR = ("load", THIS, 0x80)
PAGE = ("load", THIS, 0xA0)
SET_SIZE = 0x9000


def call(ea, receiver, *args, direct=None, slot=None):
    target = ("load", ("load", receiver, 0), slot) if slot is not None else ("const", direct)
    return dict(ea=ea, args=[receiver, *args], direct=direct, target=target)


def method(index, *, inherited=True, **facts):
    address = 0x1000 + index * 0x100
    result = dict(
        index=index,
        address=address,
        base=address if inherited else address + 0x8000,
        warning=False,
        comparisons=[],
        immediates=set(),
        divides=False,
        calls=[],
        stores=[],
    )
    result.update(facts)
    return result


def font_calls(ea):
    return [
        call(ea, THIS, direct=0xA000),
        call(ea + 1, ("result", ea), ("load", THIS, 0x90), slot=24),
    ]


def fixture():
    # Deliberately unrelated to the production ABI's method positions.
    insert = method(3, warning=True, comparisons=[dict(values=[KEY, ("const", ch)]) for ch in (9, 10, 13)])
    layout = method(
        7,
        divides=True,
        calls=[
            *font_calls(100),
            call(102, THIS, *(("stack", offset) for offset in (0, 4, 8, 12)), slot=40),
            call(103, SCROLLBAR, ("load", THIS, 0x84), ("load", THIS, 0x88), direct=SET_SIZE),
            call(104, SCROLLBAR, slot=32),
        ],
    )
    draw = method(
        11,
        divides=True,
        calls=[*font_calls(200), call(202, SCROLLBAR, slot=32)],
        stores=[dict(address=KEY, value=("const", 0))],
    )
    hotkey = method(
        13,
        inherited=False,
        calls=[
            call(300, PAGE, direct=0xB000),
            call(301, PAGE, ("const", 0), direct=0xB100),
            call(302, ("result", 301), KEY, slot=13 * 4),
        ],
    )
    perform = method(17, inherited=False, immediates={2, 4, 25, 27})
    perform["calls"] = [
        call(400, THIS, direct=perform["base"]),
        call(401, THIS, *(("stack", offset) for offset in (0, 4, 8, 12)), direct=0xC000),
        call(402, PAGE, ("const", 0), ("const", 28), ("load", THIS, 0x40), ("load", THIS, 0x44), direct=0xC100),
    ]
    return [insert, layout, draw], [hotkey, perform]


class PrivateMethodIdentityTests(unittest.TestCase):
    def test_recovers_methods_after_table_reordering(self):
        text, sheet = fixture()
        expected = dict(zip(("insert", "layout", "draw", "hotkey", "perform"), text + sheet))
        for item in text + sheet:
            item["index"] += 23
        sheet[0]["calls"][-1]["target"] = ("load", ("load", ("result", 301), 0), sheet[0]["index"] * 4)
        found = recover_private_methods(list(reversed(text)), list(reversed(sheet)), SET_SIZE)
        self.assertEqual(
            {key: value["address"] for key, value in expected.items()},
            {key: value["address"] for key, value in found.items()},
        )
        self.assertEqual(
            {key: value["index"] for key, value in expected.items()},
            {key: value["index"] for key, value in found.items()},
        )

    def test_rejects_inlined_insert_string_even_with_same_warning_and_filters(self):
        text, sheet = fixture()
        impostor = copy.deepcopy(text[0])
        impostor.update(index=4, address=0x7000, base=0x7000)
        for comparison in impostor["comparisons"]:
            comparison["values"][0] = ("load", KEY, 0)
        text.insert(0, impostor)
        self.assertEqual(0x1300, recover_private_methods(text, sheet, SET_SIZE)["insert"]["address"])
        text.pop(1)
        with self.assertRaisesRegex(ValueError, "InsertChar behavior is ambiguous"):
            recover_private_methods(text, sheet, SET_SIZE)

    def test_accepts_word_sized_character_argument(self):
        text, sheet = fixture()
        for comparison in text[0]["comparisons"]:
            comparison["values"][0] = ("narrow", KEY, 2)
        self.assertEqual(text[0], recover_private_methods(text, sheet, SET_SIZE)["insert"])

    def test_rejects_ambiguous_identity(self):
        text, sheet = fixture()
        duplicate = copy.deepcopy(text[0])
        duplicate.update(index=4, address=0x7000, base=0x7000)
        with self.assertRaisesRegex(ValueError, "InsertChar behavior is ambiguous"):
            recover_private_methods([*text, duplicate], sheet, SET_SIZE)

    def test_rejects_missing_character_filter(self):
        text, sheet = fixture()
        text[0]["comparisons"].pop()
        with self.assertRaisesRegex(ValueError, "InsertChar behavior is ambiguous"):
            recover_private_methods(text, sheet, SET_SIZE)

    def test_rejects_aliased_inset_outputs(self):
        text, sheet = fixture()
        text[1]["calls"][2]["args"][-1] = ("stack", 0)
        with self.assertRaisesRegex(ValueError, "LayoutVerticalScrollBarSlider behavior is ambiguous"):
            recover_private_methods(text, sheet, SET_SIZE)

    def test_draw_requires_same_scrollbar_and_font(self):
        for field in ("scrollbar", "font", "output"):
            with self.subTest(field=field):
                text, sheet = fixture()
                if field == "scrollbar":
                    text[2]["calls"][-1] = call(202, ("load", THIS, 0xA4), slot=32)
                elif field == "font":
                    text[2]["calls"][1]["args"][1] = ("load", THIS, 0x94)
                else:
                    text[2]["stores"][0]["address"] = ("address", THIS, 0x20)
                with self.assertRaisesRegex(ValueError, "GetStartDrawIndex behavior is ambiguous"):
                    recover_private_methods(text, sheet, SET_SIZE)

    def test_hotkey_requires_forwarded_key_at_its_own_slot(self):
        for field in ("key", "slot"):
            with self.subTest(field=field):
                text, sheet = fixture()
                forwarded = sheet[0]["calls"][-1]
                if field == "key":
                    forwarded["args"][1] = ("const", 0)
                else:
                    forwarded["target"] = ("load", ("load", ("result", 301), 0), 8)
                with self.assertRaisesRegex(ValueError, "HasHotkey behavior is ambiguous"):
                    recover_private_methods(text, sheet, SET_SIZE)

    def test_layout_requires_matching_active_page_and_base_call(self):
        for field in ("page", "base"):
            with self.subTest(field=field):
                text, sheet = fixture()
                if field == "page":
                    sheet[1]["calls"][-1]["args"][0] = ("load", THIS, 0xA4)
                else:
                    sheet[1]["calls"][0]["direct"] += 1
                with self.assertRaisesRegex(ValueError, "PerformLayout behavior is ambiguous"):
                    recover_private_methods(text, sheet, SET_SIZE)


if __name__ == "__main__":
    unittest.main()
