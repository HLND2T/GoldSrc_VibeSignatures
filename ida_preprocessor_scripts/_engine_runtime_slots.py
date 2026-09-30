"""Infer runtime-interface call roles from current x86 reaching values and CFG.

Input is the JSON-shaped result of the existing virtual-call flow decoder.
The selector contains no game-version slot numbers or instruction addresses.
"""

import json


WORD_SIZE = 4


def _control_flow(flow, entry):
    if flow.get("error"):
        raise ValueError("invalid call flow")
    graph = {int(key): successors for key, successors in flow["blocks"].items()}
    if entry not in graph or any(target not in graph for targets in graph.values() for target in targets):
        raise ValueError("incomplete function control-flow graph")

    def reachable(start, stop=None):
        pending, visited = [start], set()
        while pending:
            node = pending.pop()
            if node not in visited and node != stop:
                visited.add(node)
                pending.extend(graph[node])
        return visited

    nodes = reachable(entry)
    dominators = {node: ({node} if node == entry else set(nodes)) for node in nodes}
    predecessors = {node: {parent for parent in nodes if node in graph[parent]} for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in sorted(nodes - {entry}):
            incoming = predecessors[node]
            value = {node} | set.intersection(*(dominators[parent] for parent in incoming))
            if value != dominators[node]:
                dominators[node] = value
                changed = True
    return graph, nodes, reachable, dominators


def _receiver(call):
    return call["virtuals"][0][0]


def _offset(call):
    return call["virtuals"][0][1]


def _global_pointer(value):
    return (
        isinstance(value, list)
        and len(value) == 3
        and value[0] == "load"
        and value[2] == 0
        and isinstance(value[1], list)
        and len(value[1]) == 2
        and value[1][0] == "const"
        and isinstance(value[1][1], int)
        and not isinstance(value[1][1], bool)
        and value[1][1] > 0
    )


def _choose_slot(name, matches):
    if any(len(call["virtuals"]) != 1 for call in matches):
        raise ValueError(f"{name}: ambiguous virtual receiver or slot")
    slots = {_offset(call) for call in matches}
    receivers = {json.dumps(_receiver(call)) for call in matches}
    if len(slots) != 1 or len(receivers) != 1:
        raise ValueError(f"{name}: expected one receiver/slot, got {len(receivers)}/{len(slots)}")
    slot = next(iter(slots))
    if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0 or slot % WORD_SIZE:
        raise ValueError(f"{name}: invalid x86 slot displacement")
    if any(call["args"][:1] != [_receiver(call)] for call in matches):
        raise ValueError(f"{name}: this argument disagrees with vtable receiver")
    return {"offset": slot, "sites": [call["ea"] for call in matches]}


def select_runlistenserver_slots(flow, entry, eng_address, video_address, platform):
    if platform not in {"windows", "linux"}:
        raise ValueError("unsupported platform")
    graph, nodes, reachable, dominators = _control_flow(flow, entry)
    cyclic = {node for node in nodes if any(node in reachable(child) for child in graph[node])}
    branches = {}
    for branch in flow["branches"]:
        condition = branch["condition"]
        if condition[0] != "result":
            continue
        previous = branches.get(condition[1])
        if previous and (previous["zero"], previous["nonzero"]) != (branch["zero"], branch["nonzero"]):
            raise ValueError("one call result controls conflicting branches")
        branches[condition[1]] = branch
    calls = flow["calls"]
    if any(len(call["virtuals"]) != 1 for call in calls):
        raise ValueError("ambiguous virtual receiver or slot")
    eng = ["load", ["const", eng_address], 0]
    video = ["load", ["const", video_address], 0]
    # The shared decoder reserves arg0 for ECX on Windows. RunListenServer is
    # cdecl, so its first stack argument is arg1 there and arg0 on Linux.
    argument_shift = int(platform == "windows")
    instance = ["arg", argument_shift]
    found = {}

    receiver, offset = _receiver, _offset

    def choose(name, matches):
        found[name] = _choose_slot(name, matches)
        return matches[0]

    video_init = choose(
        "IVideoMode_Init",
        [
            call
            for call in calls
            if receiver(call) == video and call["args"][1:2] == [instance] and call["ea"] in branches
        ],
    )
    game_init = choose(
        "IGame_Init",
        [
            call
            for call in calls
            if receiver(call) not in (eng, video) and call["args"][1:2] == [instance] and call["ea"] in branches
        ],
    )
    game = receiver(game_init)
    if not _global_pointer(game):
        raise ValueError("game receiver is not a proven global pointer load")
    load = choose(
        "IEngine_Load",
        [
            call
            for call in calls
            if receiver(call) == eng
            and call["args"][:4] == [eng, ["const", 0], ["arg", argument_shift + 1], ["arg", argument_shift + 2]]
            and call["ea"] in branches
            and call["block"] not in cyclic
        ],
    )
    setter = choose(
        "IEngine_SetQuitting",
        [
            call
            for call in calls
            if receiver(call) == eng
            and call["args"][1:2] == [["const", 0]]
            and call["ea"] not in branches
            and call["block"] in dominators[video_init["block"]]
            and (call["block"] != video_init["block"] or call["ea"] < video_init["ea"])
        ],
    )
    getter = choose(
        "IEngine_GetQuitting",
        [
            call
            for call in calls
            if receiver(call) == eng
            and call["block"] in cyclic
            and call["ea"] in branches
            and offset(call) != offset(setter)
        ],
    )
    choose(
        "IEngine_Frame",
        [
            call
            for call in calls
            if receiver(call) == eng
            and call["block"] in cyclic
            and offset(call) not in (offset(setter), offset(getter))
        ],
    )
    failure = reachable(branches[load["ea"]]["zero"])
    choose(
        "IGame_Shutdown",
        [
            call
            for call in calls
            if receiver(call) == game and call["block"] in failure and offset(call) != offset(game_init)
        ],
    )
    choose(
        "IVideoMode_Shutdown",
        [
            call
            for call in calls
            if receiver(call) == video and call["block"] in failure and offset(call) != offset(video_init)
        ],
    )
    return found


def select_frame_slots(flow, entry):
    """Identify the activity test, inactive wait and dominating audio dispatch."""
    _, _, reachable, dominators = _control_flow(flow, entry)
    virtuals = [call for call in flow["calls"] if call["virtuals"]]
    if any(len(call["virtuals"]) != 1 for call in virtuals):
        raise ValueError("ambiguous virtual receiver or slot")
    calls = [call for call in virtuals if _global_pointer(_receiver(call))]
    pairs = []
    for branch in flow["branches"]:
        if branch["condition"][0] != "result":
            continue
        getters = [call for call in calls if call["ea"] == branch["condition"][1]]
        if len(getters) != 1:
            continue
        getter = getters[0]
        inactive = reachable(branch["zero"]) - reachable(branch["nonzero"])
        waits = [
            call
            for call in calls
            if call["block"] in inactive and _receiver(call) == _receiver(getter) and _offset(call) != _offset(getter)
        ]
        if waits:
            pairs.append((getter, waits))
    if len(pairs) != 1:
        raise ValueError("expected one activity-test/inactive-wait pair")
    getter, waits = pairs[0]
    audio = [
        call
        for call in calls
        if _receiver(call) != _receiver(getter)
        and call["block"] in dominators[getter["block"]]
        and (call["block"] != getter["block"] or call["ea"] < getter["ea"])
    ]
    return {
        name: _choose_slot(name, candidates)
        for name, candidates in (
            ("IGame_IsActiveApp", [getter]),
            ("IGame_SleepUntilInput", waits),
            ("ICDAudio_Frame", audio),
        )
    }


def _one(values, label):
    if len(values) != 1:
        raise ValueError(f"{label}: expected one candidate, got {len(values)}")
    return values[0]


def _this_stores(flow):
    return [store for store in flow["stores"] if store["address"] and store["address"][:2] == ["address", ["arg", 0]]]


def _getter(flow, value):
    return (
        not flow["calls"]
        and all(store["address"] and store["address"][0] == "stack" for store in flow["stores"])
        and bool(flow["returns"])
        and all(ret["value"] == value for ret in flow["returns"])
    )


def select_event_slots(engine, event, frame_index, key_address, eng_address, video_address, update_offset, *, sdl):
    """Recover trapping/state getters and event-window dispatches from current bodies."""
    if any(isinstance(index, bool) for index in engine):
        raise ValueError("boolean table index")
    engine = {int(index): method for index, method in engine.items()}
    if any(isinstance(index, bool) or index < 0 or method["flow"].get("error") for index, method in engine.items()):
        raise ValueError("invalid current engine table flow")
    if frame_index not in engine or event.get("error"):
        raise ValueError("missing frame or event flow")
    key_index = _one(
        [
            index
            for index, method in engine.items()
            if any(call.get("direct") == key_address for call in method["flow"]["calls"])
        ],
        "Key_Event caller",
    )
    key = engine[key_index]["flow"]
    stores = _this_stores(key)
    key_field = _one(
        [store["address"] for store in stores if store["width"] == WORD_SIZE and store["value"] == ["arg", 1]],
        "trap key field",
    )
    buttons_field = _one(
        [store["address"] for store in stores if store["width"] == WORD_SIZE and store["value"] == ["const", 0]],
        "trap buttons field",
    )
    trap = _one(
        [
            branch["condition"]
            for branch in key["branches"]
            if len(branch["condition"]) == 3
            and branch["condition"][0] == "narrow"
            and branch["condition"][2] == 1
            and branch["condition"][1][:2] == ["load", ["arg", 0]]
        ],
        "trap flag",
    )
    mouse_index = _one(
        [
            index
            for index, method in engine.items()
            if any(branch["condition"] == trap for branch in method["flow"]["branches"])
            and any(
                store["address"] == key_field and store["value"] == ["const", 0] and store["width"] == WORD_SIZE
                for store in _this_stores(method["flow"])
            )
            and any(
                store["address"] == buttons_field and store["value"] == ["arg", 1] and store["width"] == WORD_SIZE
                for store in _this_stores(method["flow"])
            )
        ],
        "reciprocal mouse stores",
    )
    trap_index = _one([index for index, method in engine.items() if _getter(method["flow"], trap)], "trap getter")
    frame = engine[frame_index]["flow"]
    state = _one(
        [branch["condition"] for branch in frame["branches"] if branch["condition"][:2] == ["load", ["arg", 0]]],
        "Frame DLL state",
    )
    state_index = _one([index for index, method in engine.items() if _getter(method["flow"], state)], "state getter")
    indices = {
        "IEngine_TrapKey_Event": key_index,
        "IEngine_TrapMouse_Event": mouse_index,
        "IEngine_IsTrapping": trap_index,
        "IEngine_GetState": state_index,
    }
    if len(set(indices.values())) != len(indices):
        raise ValueError("engine method roles overlap")
    found = {name: dict(offset=index * WORD_SIZE, method=engine[index]["address"]) for name, index in indices.items()}

    virtuals = [call for call in event["calls"] if call["virtuals"]]
    if any(len(call["virtuals"]) != 1 for call in virtuals):
        raise ValueError("ambiguous event dispatch")
    eng = ["load", ["const", eng_address], 0]
    video = ["load", ["const", video_address], 0]
    if not any(_receiver(call) == eng and _offset(call) == state_index * WORD_SIZE for call in virtuals):
        raise ValueError("event owner does not dispatch the inferred GetState slot")
    video_calls = [call for call in virtuals if _receiver(call) == video and _offset(call) != update_offset]
    found["IVideoMode_IsWindowedMode"] = _choose_slot("IVideoMode_IsWindowedMode", video_calls)
    activity = select_frame_slots(frame, engine[frame_index]["address"])["IGame_IsActiveApp"]["sites"]
    game = _receiver(_one([call for call in frame["calls"] if call["ea"] == activity[0]], "game receiver"))
    game_calls = [call for call in virtuals if _receiver(call) == game]
    if sdl:
        _, _, reachable, _ = _control_flow(event, event["entry"])
        activity_sites = {call["ea"] for call in video_calls}
        branch = _one(
            [
                branch
                for branch in event["branches"]
                if branch["condition"][0] == "result" and branch["condition"][1] in activity_sites
            ],
            "windowed branch",
        )
        # Cut re-entry to the condition; otherwise the SDL event loop makes
        # both branches reach every later iteration and erases exclusivity.
        windowed_region = reachable(branch["nonzero"], branch["block"]) - reachable(branch["zero"], branch["block"])
        game_calls = [call for call in game_calls if call["block"] in windowed_region]
    found["IGame_SetWindowXY"] = _choose_slot("IGame_SetWindowXY", game_calls)
    return found
