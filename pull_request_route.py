from __future__ import annotations

import re
from collections.abc import Iterable

PR_ROUTE_SOURCE = "source"
PR_ROUTE_OUTPUT = "output"
OUTPUT_BRANCH_PREFIX = "gamesymbols/build/"
RELEASE_OWNED_PATH_PREFIXES = ("gamesymbols/", "gamedata/", "release-manifests/")
# One-time trust bridge for the reviewed cutover PR. The cutover removes this
# legacy routing module, so the exception expires when that exact head merges.
BIN_ARTIFACT_CUTOVER_HEAD_SHA = "059957302ea083f371f61a51c9dca014e0e98298"
_OUTPUT_BRANCH_RE = re.compile(
    r"gamesymbols/build/(?P<tag>[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+)/"
    r"(?P<build_id>[a-z0-9]+(?:-[a-z0-9]+)*)\Z"
)


class PullRequestRouteError(ValueError):
    pass


def parse_output_branch(branch: str) -> tuple[str, str] | None:
    if not isinstance(branch, str):
        raise PullRequestRouteError("Pull-request head ref must be a string")
    match = _OUTPUT_BRANCH_RE.fullmatch(branch)
    if match is not None:
        return match.group("tag"), match.group("build_id")
    if branch.startswith(OUTPUT_BRANCH_PREFIX):
        raise PullRequestRouteError(f"Invalid generated-output branch: {branch!r}")
    return None


def classify_pr_route(*, head_ref: str, output_routing_enabled: bool) -> str:
    if output_routing_enabled and head_ref.startswith(OUTPUT_BRANCH_PREFIX):
        return PR_ROUTE_OUTPUT
    return PR_ROUTE_SOURCE


def validate_source_paths(paths: Iterable[str], *, head_sha: str | None = None) -> None:
    rejected = sorted(
        {path for path in paths if any(path.startswith(prefix) for prefix in RELEASE_OWNED_PATH_PREFIXES)}
    )
    if rejected and head_sha != BIN_ARTIFACT_CUTOVER_HEAD_SHA:
        raise PullRequestRouteError("Source PR contains release-owned generated-output paths: " + ", ".join(rejected))
