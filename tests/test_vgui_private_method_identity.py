"""Behavioral regression checks for VGUI method identity over decoded flow."""

import copy
import unittest

from ida_preprocessor_scripts._vgui_private_method_identity import (
    expand_leaf_returns,
    itanium_virtual_member_slot,
    recover_factory_parent,
    recover_frame_focus,
    recover_private_methods,
    recover_property_sheet,
    recover_setfocus_slot,
    stack_check_preserves_registers,
    virtual_dispatch,
)


THIS = ("arg", 0)
KEY = ("arg", 1)
SCROLLBAR = ("load", THIS, 0x80)
PAGE = ("load", THIS, 0xA0)
SET_SIZE = 0x9000


def call(ea, receiver, *args, direct=None, slot=None):
    target = ("load", ("load", receiver, 0), slot) if slot is not None else ("const", direct)
    return dict(ea=ea, args=[receiver, *args], stack_args=list(args), direct=direct, target=target)


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


def chain_method(index, address, *, calls=(), stores=(), returns=(), comparisons=(), loads=(), labels=()):
    return dict(
        index=index,
        ea=address,
        strings=[(address, 0, label) for label in labels],
        flow=dict(
            calls=[dict(c, stack_args=c.get("stack_args", [])) for c in calls],
            stores=list(stores),
            returns=list(returns),
            comparisons=list(comparisons),
            loads=list(loads),
        ),
    )


def factory_fixture():
    pointer = chain_method(8, 0x8000, calls=[call(10, KEY, slot=12), call(11, THIS, ("result", 10), slot=36)])
    parent = chain_method(9, 0x9000, calls=[call(12, THIS, ("result", 13), slot=76)])
    proportional = chain_method(
        19,
        0xA000,
        calls=[call(14, ("load", THIS, 0x180), KEY, slot=76), call(15, THIS, ("const", 0), ("const", 0), slot=28)],
        stores=[dict(address=("address", THIS, 0x48), value=KEY, width=4)],
    )
    getvpanel = chain_method(3, 0xB000, returns=[dict(value=("load", THIS, 0x50))])
    panel = ("result", 21)
    owner = chain_method(
        None,
        0xC000,
        calls=[
            dict(call(21, KEY, direct=0xE000), stack_args=[("const", 0xF000)]),
            call(22, panel, ("arg", 2), ("arg", 3), direct=0xD000),
            call(23, panel, ("load", THIS, 0x80), slot=32),
        ],
    )
    methods = [pointer, parent, proportional, getvpanel]
    data = dict(
        tables={"vgui2::Panel": dict(vtable_entries={str(m["index"]): hex(m["ea"]) for m in methods})},
        functions={str(m["ea"]): m for m in [*methods, owner]},
        roots={"stage1": [owner["ea"]]},
        literals={"PanelPtr": dict(addresses=[0xF000])},
    )
    return data


def sheet_fixture():
    page, tab, count, width = 0xA0, 0xB0, 0xC0, 0xD0

    def load(offset):
        return dict(value=("load", THIS, offset), address=("address", THIS, offset))

    def store(offset, value=None):
        return dict(address=("address", THIS, offset), value=value, width=4)

    methods = {}

    def add(name, index, **facts):
        methods[name] = chain_method(index, 0x10000 + index * 0x100, **facts)

    add("AddPage", 31, labels=("tab", "ResetData"), loads=[load(width), load(count)])
    add("ChangeActiveTab", 7, labels=("PageHide", "PageShow", "PageChanged"), stores=[store(page), store(tab)])
    add("ResetAllData", 25, labels=("ResetData",), loads=[load(count)])
    add("ApplyChanges", 18, labels=("ApplyChanges",), loads=[load(count)])
    for name, index, offset in (("GetActivePage", 22, page), ("GetActiveTab", 16, tab), ("GetNumPages", 29, count)):
        add(name, index, returns=[dict(value=("load", THIS, offset))])
    add("GetActiveTabTitle", 11, calls=[call(100, ("load", THIS, tab), KEY, ("arg", 2), slot=400)])
    add(
        "SetActivePage",
        26,
        calls=[call(101, THIS, ("result", 102), slot=28)],
        comparisons=[dict(values=[KEY, ("load", THIS, count)])],
    )
    add(
        "DeletePage",
        5,
        calls=[call(103, THIS, ("const", 0), slot=28), call(104, THIS, slot=156), call(105, KEY, slot=220)],
        loads=[load(count), dict(value=KEY, address=("stack", 4))],
    )
    add("SetTabWidth", 12, stores=[store(width, KEY)], calls=[call(106, THIS, ("const", 0), ("const", 0), slot=96)])
    add(
        "GetPage",
        13,
        comparisons=[dict(values=[KEY, ("load", THIS, count)])],
        returns=[dict(value=("load", ("indexed", ("load", THIS, 0xE0), KEY, 4), 0)), dict(value=("const", 0))],
    )
    add("GetActivePageNum", 23, loads=[load(page), load(count)], returns=[dict(value=("const", 0xFFFFFFFF))])
    add(
        "GetTabTitle",
        9,
        loads=[dict(value=KEY, address=("stack", 4))],
        calls=[call(107, ("load", ("indexed", ("load", THIS, 0xF0), KEY, 4), 0), ("arg", 2), ("arg", 3), slot=400)],
    )
    for name, index, state in (("EnablePage", 17, 1), ("DisablePage", 24, 0)):
        add(name, index, calls=[call(108, THIS, KEY, ("const", state), slot=240)])
    data = dict(
        tables={
            "vgui2::Panel": dict(vtable_entries={}),
            "vgui2::PropertySheet": dict(vtable_entries={str(m["index"]): hex(m["ea"]) for m in methods.values()}),
        },
        functions={str(m["ea"]): m for m in methods.values()},
    )
    return data, methods, page


def frame_focus_fixture():
    nav_offset, handle_offset = 0x234, 0x90
    frame_calls = [
        call(10, THIS, direct=0x1100),
        call(11, ("result", 10), slot=168),
        call(12, THIS, direct=0x1200),
        call(13, ("result", 12), ("result", 11), slot=116),
        call(14, THIS, direct=0x1300),
        call(15, ("result", 14), slot=76),
        call(16, ("result", 13), ("const", 0), ("const", 1), slot=240),
        call(20, THIS, direct=0x1400),
        call(21, ("result", 20), ("const", 79), slot=100),
        call(22, THIS, slot=16),
        call(23, THIS, direct=0x1100),
        call(24, ("result", 23), ("const", 3), slot=268),
        call(25, THIS, direct=0x1400),
        call(26, ("result", 25), slot=92),
        call(27, THIS, slot=4),
    ]
    getvpanel = chain_method(1, 0x5000, returns=[dict(value=("load", THIS, 0x48))])
    nav = chain_method(4, 0x5100, returns=[dict(value=("address", THIS, nav_offset))])
    panel_focus = chain_method(6, 0x5200, calls=[call(30, THIS, slot=160)])
    editable_focus = chain_method(
        6,
        0x5300,
        calls=[call(31, ("address", THIS, nav_offset), slot=8), call(32, THIS, direct=panel_focus["ea"])],
        comparisons=[dict(values=[("result", 31), THIS])],
    )
    handle = ("address", THIS, handle_offset)
    current = chain_method(2, 0x5400, calls=[call(33, handle, direct=0x1500), call(34, handle, direct=0x1600)])
    setter = chain_method(3, 0x5500, calls=[call(35, handle, KEY, direct=0x1700)])
    frame = chain_method(14, 0x5600, calls=frame_calls, comparisons=[dict(values=[("result", 26), ("result", 27)])])
    owner = chain_method(
        None,
        0x5700,
        stores=[
            dict(block=1, address=("stack", -160), value=("const", 0xA000)),
            dict(block=1, address=("stack", -44), value=("const", 0x5800)),
        ],
    )
    wrapper = chain_method(None, 0x5800, calls=[call(36, THIS, slot=24)])
    groups = {
        "vgui2::Panel": [getvpanel, panel_focus],
        "vgui2::EditablePanel": [getvpanel, nav, editable_focus],
        "vgui2::FocusNavGroup": [current, setter],
        "vgui2::Frame": [frame],
    }
    methods = [getvpanel, nav, panel_focus, editable_focus, current, setter, frame, owner, wrapper]
    data = dict(
        platform="windows",
        tables={cls: dict(vtable_entries={str(m["index"]): hex(m["ea"]) for m in ms}) for cls, ms in groups.items()},
        functions={str(m["ea"]): m for m in methods},
        roots={"stage2": [frame["ea"]], "setfocus_all": [owner["ea"]]},
        literals={"SetFocus": dict(addresses=[0xA000])},
    )
    return data, getvpanel


class StageIdentityTests(unittest.TestCase):
    def test_frame_and_message_chains_agree_on_moved_slots_and_distinct_member_offsets(self):
        data, getvpanel = frame_focus_fixture()
        found = recover_frame_focus(data, getvpanel)
        self.assertEqual(0x234, found["nav_offset"])
        self.assertEqual(0x90, found["current_offset"])
        self.assertEqual(2, found["current"]["index"])
        self.assertEqual(
            {
                "vgui2::ISurface::SupportsFeature(vgui2::ISurface::SurfaceFeature_e)": 67,
                "vgui2::IInput::GetAppModalSurface()": 23,
                "vgui2::ISchemeManager::ReloadSchemes()": 19,
            },
            found["interfaces"],
        )

    def test_frame_rejects_wrong_interface_receiver_and_disagreeing_navigation_member(self):
        for failure in ("input", "member"):
            with self.subTest(failure=failure):
                data, getvpanel = frame_focus_fixture()
                if failure == "input":
                    next(c for c in data["functions"][str(0x5600)]["flow"]["calls"] if c["ea"] == 25)["direct"] = 0x1100
                else:
                    data["functions"][str(0x5100)]["flow"]["returns"][0]["value"] = ("address", THIS, 0x238)
                with self.assertRaises(ValueError):
                    recover_frame_focus(data, getvpanel)

    def test_stack_check_accepts_saved_frame_pointer_and_rejects_unbalanced_or_nontransparent_helper(self):
        registers = ("ebp", "eax", "edx", "ebx", "esi", "edi")
        code = [dict(ea=1, mnemonic="jnz", branch=3), dict(ea=2, mnemonic="retn", purge=0)]
        code += [dict(ea=3 + i, mnemonic="push", register=r) for i, r in enumerate(registers)]
        code += [dict(ea=20, mnemonic="int", trap=3)]
        code += [dict(ea=21 + i, mnemonic="pop", register=r) for i, r in enumerate(reversed(registers))]
        code += [dict(ea=30, mnemonic="retn", purge=0)]
        self.assertTrue(stack_check_preserves_registers(code))
        for failure in ("normal_purge", "trap", "restore", "branch"):
            with self.subTest(failure=failure):
                changed = copy.deepcopy(code)
                if failure == "normal_purge":
                    changed[1]["purge"] = 4
                elif failure == "trap":
                    changed[8]["trap"] = 4
                elif failure == "restore":
                    changed[-2]["register"] = "ecx"
                else:
                    changed[0]["branch"] = 2
                self.assertFalse(stack_check_preserves_registers(changed))

    def test_message_record_recovers_moved_callback_field_and_rejects_wrong_receiver(self):
        wrapper = chain_method(None, 0x8000, calls=[call(10, THIS, slot=148)])
        owner = chain_method(
            None,
            0x9000,
            stores=[
                dict(block=1, address=("stack", -160), value=("const", 0xA000)),
                dict(block=1, address=("stack", -44), value=("const", 0x8000)),
            ],
        )
        data = dict(
            platform="windows",
            functions={str(f["ea"]): f for f in (wrapper, owner)},
            roots={"setfocus_all": [owner["ea"]]},
            literals={"SetFocus": dict(addresses=[0xA000])},
        )
        self.assertEqual(37, recover_setfocus_slot(data))
        wrapper["flow"]["calls"][0] = call(10, KEY, slot=148)
        with self.assertRaisesRegex(ValueError, "callback thunk"):
            recover_setfocus_slot(data)

    def test_itanium_record_requires_zero_adjustment_and_current_table_entry(self):
        owner = chain_method(
            None,
            0x9000,
            stores=[
                dict(block=1, address=("stack", -160), value=("const", 0xA000)),
                dict(block=1, address=("stack", -44), value=("const", 149)),
                dict(block=1, address=("stack", -40), value=("const", 0)),
            ],
        )
        data = dict(
            platform="linux",
            functions={str(owner["ea"]): owner},
            roots={"setfocus_all": [owner["ea"]]},
            literals={"SetFocus": dict(addresses=[0xA000])},
            tables={"vgui2::Panel": dict(vtable_entries={"37": "0xB000"})},
        )
        self.assertEqual(37, recover_setfocus_slot(data))
        owner["flow"]["stores"][-1]["value"] = ("const", 4)
        with self.assertRaisesRegex(ValueError, "record virtual member"):
            recover_setfocus_slot(data)

    def test_factory_tracks_created_receiver_through_parent_overload(self):
        data = factory_fixture()
        result = recover_factory_parent(data)
        self.assertEqual(0xA000, result["proportional"]["ea"])
        self.assertEqual(19, result["proportional"]["index"])
        owner = data["functions"][str(0xC000)]
        impostor = copy.deepcopy(owner)
        impostor["ea"] = 0xC100
        impostor["flow"]["calls"][-1] = call(23, THIS, ("load", THIS, 0x80), slot=32)
        data["functions"][str(impostor["ea"])] = impostor
        data["roots"]["stage1"].insert(0, impostor["ea"])
        self.assertEqual(0xA000, recover_factory_parent(data)["proportional"]["ea"])

    def test_factory_accepts_inline_owner_and_rejects_missing_recursive_state_write(self):
        data = factory_fixture()
        owner = data["functions"][str(0xC000)]
        owner["flow"]["calls"][1]["args"][1:3] = [("const", 0), ("const", 0)]
        self.assertTrue(recover_factory_parent(data)["inline"])
        data["functions"][str(0xA000)]["flow"]["stores"].clear()
        with self.assertRaisesRegex(ValueError, "SetProportional"):
            recover_factory_parent(data)

    def test_member_pointer_abi_checks_alignment_and_adjustment(self):
        self.assertEqual(43, itanium_virtual_member_slot(43 * 4 + 1, 0))
        for encoded, adjustment in ((172, 0), (175, 0), (173, 4), (0, 0)):
            with self.subTest(encoded=encoded, adjustment=adjustment), self.assertRaises(ValueError):
                itanium_virtual_member_slot(encoded, adjustment)
        self.assertEqual(
            (("address", THIS, 0x234), 43), virtual_dispatch(dict(target=("load", ("load", THIS, 0x234), 172)))
        )
        self.assertIsNone(virtual_dispatch(dict(target=("load", ("narrow", ("load", THIS, 0), 2), 172))))

    def test_sheet_methods_follow_messages_and_roles_after_reordering(self):
        data, methods, page = sheet_fixture()
        result = recover_property_sheet(data, page, 39)
        self.assertEqual({name: m["ea"] for name, m in methods.items()}, {name: m["ea"] for name, m in result.items()})
        self.assertEqual(31, result["AddPage"]["index"])
        self.assertEqual(7, result["ChangeActiveTab"]["index"])

    def test_sheet_rejects_wrong_page_and_ambiguous_message_owner(self):
        data, methods, page = sheet_fixture()
        with self.assertRaisesRegex(ValueError, "active page"):
            recover_property_sheet(data, page + 4, 39)
        duplicate = copy.deepcopy(methods["ResetAllData"])
        duplicate.update(ea=0x90000, index=55)
        data["functions"][str(duplicate["ea"])] = duplicate
        data["tables"]["vgui2::PropertySheet"]["vtable_entries"]["55"] = hex(duplicate["ea"])
        with self.assertRaisesRegex(ValueError, "ResetAllData"):
            recover_property_sheet(data, page, 39)

    def test_leaf_helper_rebases_member_and_preserves_unknown_or_side_effecting_results(self):
        helper = chain_method(0, 0x8000, returns=[dict(value=("load", THIS, 12))])
        owner = chain_method(
            1, 0x9000, calls=[call(10, ("address", THIS, 0x200), direct=0x8000)], returns=[dict(value=("result", 10))]
        )
        data = dict(functions={"32768": helper})
        self.assertEqual(("load", THIS, 0x20C), expand_leaf_returns(data, owner)["flow"]["returns"][0]["value"])
        helper["flow"]["stores"].append(dict(address=("address", THIS, 4), value=KEY, width=4))
        self.assertEqual(("result", 10), expand_leaf_returns(data, owner)["flow"]["returns"][0]["value"])


if __name__ == "__main__":
    unittest.main()
