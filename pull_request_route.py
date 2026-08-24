from __future__ import annotations

import re

PR_ROUTE_SOURCE = "source"
PR_ROUTE_OUTPUT = "output"
OUTPUT_BRANCH_PREFIX = "gamesymbols/build/"
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
