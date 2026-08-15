def format_snapshot_mismatch(expected: dict, actual: dict) -> str:
    expected_paths = set(expected.get("files", {}))
    actual_paths = set(actual.get("files", {}))
    details = []
    if expected_paths - actual_paths:
        details.append("Missing: " + ", ".join(sorted(expected_paths - actual_paths)))
    if actual_paths - expected_paths:
        details.append("Added: " + ", ".join(sorted(actual_paths - expected_paths)))
    changed = sorted(
        path for path in expected_paths & actual_paths if expected["files"].get(path) != actual["files"].get(path)
    )
    if changed:
        details.append("Changed: " + ", ".join(changed))
    if expected.get("binaries") != actual.get("binaries"):
        details.append("Binary metadata changed")
    return "Snapshot mismatch" + (": " + "; ".join(details) if details else "")
