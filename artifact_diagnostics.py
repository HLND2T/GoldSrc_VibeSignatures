"""Best-effort byte diagnostics shared by PR and release artifact comparisons."""

from __future__ import annotations

import difflib
import hashlib
from collections.abc import Callable
from itertools import islice
from pathlib import Path

from gamesymbol_snapshot_lib.paths import canonical_key, ensure_real_tree, iter_yaml_paths

MAX_DIFF_LINES = 40
MAX_CHANGED_ARTIFACTS = 5


def render_artifact_diff(path: str, expected: bytes, actual: bytes, *, expected_source: str) -> str:
    def facts(raw: bytes) -> str:
        return f"size={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}"

    detail = (
        f"\n  artifact: {path}"
        f"\n  expected ({expected_source}): {facts(expected)}"
        f"\n  actual (isolated rebuild): {facts(actual)}"
    )
    try:
        expected_lines = expected.decode("utf-8").splitlines()
        actual_lines = actual.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return detail + "\n  content diff unavailable: artifact is not UTF-8"
    diff = difflib.unified_diff(expected_lines, actual_lines, fromfile="expected", tofile="actual", lineterm="")
    shown = list(islice(diff, MAX_DIFF_LINES + 1))
    if not shown:
        return detail + "\n  no line diff: byte drift is in line endings or final newline"
    detail += "\n  content diff (expected -> actual):\n" + "\n".join(f"    {line}" for line in shown[:MAX_DIFF_LINES])
    if len(shown) > MAX_DIFF_LINES:
        detail += f"\n    ... diff truncated after {MAX_DIFF_LINES} lines"
    return detail


def append_artifact_diagnostics(
    message: str,
    *,
    tag: str,
    actual_root: Path,
    load_expected: Callable[[], dict[str, bytes]],
    expected_source: str,
) -> str:
    """Preserve the original rejection if safe diagnostic collection fails.

    Inspect raw flat YAML without requiring a valid payload, so an earlier
    contract rejection can still report missing, extra and changed together.
    Complete path/link validation before opening any discovered artifact.
    """
    try:
        game_root = actual_root / tag
        ensure_real_tree(actual_root, game_root)
        paths = tuple(iter_yaml_paths(game_root))
        keyed_paths = [(canonical_key(game_root, path), path) for path in paths]
        keys = [key.casefold() for key, _path in keyed_paths]
        if len(set(keys)) != len(keys):
            raise ValueError("Case-insensitive artifact collision")
        expected = load_expected()
        actual = {key: path.read_bytes() for key, path in keyed_paths}
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        changed = sorted(key for key in expected.keys() & actual.keys() if expected[key] != actual[key])
        detail = f"\n  {tag}: missing={missing!r}; extra={extra!r}; changed={changed!r}"
        for key in changed[:MAX_CHANGED_ARTIFACTS]:
            detail += render_artifact_diff(
                f"bin_artifacts/{tag}/{key}",
                expected[key],
                actual[key],
                expected_source=expected_source,
            )
        if len(changed) > MAX_CHANGED_ARTIFACTS:
            detail += f"\n  ... {len(changed) - MAX_CHANGED_ARTIFACTS} changed artifact details omitted"
        return message + detail
    except Exception as exc:
        # Diagnostics must never replace the authoritative comparison failure.
        return message + f"\n  artifact diagnostics unavailable for {tag}: {exc}"
