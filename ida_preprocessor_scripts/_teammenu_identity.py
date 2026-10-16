"""Distinguish a map-page helper from an Update body that inlined it."""

LOAD_MAP_NAME = "CTeamMenu::LoadMapPage(char const*)"
UPDATE_NAME = "CTeamMenu::Update(char const*, bool, char const**, int)"


def _reaches(graph, start, end):
    pending, seen = [start], set()
    while pending:
        node = pending.pop()
        if node == end:
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(graph.get(node, ()))
    return False


def guarded_team_update(flow, team_buttons):
    """Require this/teamNames/numTeams and both non-null guards on the call."""
    graph = flow.get("blocks", {})
    matches = []
    for call in flow.get("calls", []):
        if call.get("direct") not in team_buttons:
            continue
        if call.get("args", [])[:3] != [("arg", 0), ("arg", 3), ("arg", 4)]:
            continue
        conditions = set()
        for branch in flow.get("branches", []):
            condition = branch["condition"]
            if isinstance(condition, tuple) and condition[0] == "narrow":
                condition = condition[1]
            if _reaches(graph, branch["nonzero"], call["block"]) and not _reaches(graph, branch["zero"], call["block"]):
                conditions.add(condition)
        if {("arg", 3), ("load", ("arg", 3), 0)} <= conditions:
            matches.append(call)
    return len(matches) == 1


def classify_map_owner(platform, symbol, cleanups, flow, team_buttons):
    """The caller has independently proved the map-file/BOM behavior."""
    update = guarded_team_update(flow, team_buttons)
    has_team_call = any(call.get("direct") in team_buttons for call in flow.get("calls", []))
    if platform == "windows":
        if set(cleanups) == {16} and update:
            return "TeamMenu_Update", UPDATE_NAME
        if set(cleanups) == {4} and not has_team_call:
            return "TeamMenu_LoadMapPage", LOAD_MAP_NAME
    elif platform == "linux":
        if symbol == "_ZN9CTeamMenu11LoadMapPageEPKc" and not has_team_call:
            return "TeamMenu_LoadMapPage", LOAD_MAP_NAME
        if symbol == "_ZN9CTeamMenu6UpdateEPKcbPS1_i" and update:
            return "TeamMenu_Update", UPDATE_NAME
    raise ValueError("map string owner has ambiguous or inconsistent function identity/ABI")
