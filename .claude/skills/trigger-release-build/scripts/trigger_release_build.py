#!/usr/bin/env python3
"""Dispatch a new release or resume its matching draft from immutable origin/main."""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ALLOWED_REPOSITORIES = {"HLND2T/GoldSrc_VibeSignatures", "hzqst/GoldSrc_VibeSignatures"}
VERSION_RE = re.compile(r"^v[0-9]{8}[a-z]?\Z")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "release-build.yml"
RUN_LIST_LIMIT = "100"
RUN_DISCOVERY_ATTEMPTS = 10
RUN_DISCOVERY_DELAY_SECONDS = 2


class TriggerError(Exception):
    """Raised when a dispatch safety precondition is not satisfied."""


def run_command(command: list[str], cwd: Path, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise TriggerError(f"{' '.join(command)} failed: {detail}")
    return result


def repository_root() -> Path:
    expected = Path(__file__).resolve().parents[4]
    result = run_command(["git", "rev-parse", "--show-toplevel"], expected)
    actual = Path(result.stdout.strip()).resolve()
    if actual != expected:
        raise TriggerError(f"skill is not running in its owning repository: {actual}")
    return actual


def parse_repository(remote_url: str) -> str:
    patterns = (
        r"^https://github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
        r"^git@github\.com:(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/(?P<repo>[^/]+/[^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote_url.strip())
        if match:
            return match.group("repo")
    raise TriggerError(f"unsupported origin URL: {remote_url}")


def require_repository(root: Path) -> str:
    remote = run_command(["git", "remote", "get-url", "origin"], root).stdout.strip()
    repository = parse_repository(remote)
    if repository not in ALLOWED_REPOSITORIES:
        raise TriggerError(f"origin repository is not allowlisted: {repository}")
    return repository


def require_github_access(root: Path, repository: str) -> None:
    run_command(["gh", "auth", "status", "--hostname", "github.com"], root)
    permission = run_command(["gh", "api", f"repos/{repository}", "--jq", ".permissions.push"], root).stdout.strip()
    if permission != "true":
        raise TriggerError(f"authenticated GitHub account cannot dispatch Actions for {repository}")
    run_command(["gh", "api", f"repos/{repository}/actions/workflows/{WORKFLOW}", "--jq", ".id"], root)


def resolve_source(root: Path) -> tuple[str, str]:
    run_command(["git", "fetch", "--no-tags", "origin", "refs/heads/main"], root)
    source_sha = run_command(["git", "rev-parse", "FETCH_HEAD"], root).stdout.strip().lower()
    if not SHA_RE.fullmatch(source_sha):
        raise TriggerError("origin/main did not resolve to a full commit SHA")
    subject = run_command(["git", "show", "-s", "--format=%s", source_sha], root).stdout.strip()
    return source_sha, subject


def require_version(value: str) -> str:
    if not VERSION_RE.fullmatch(value):
        raise TriggerError(f"invalid release version: {value!r}")
    return value


def remote_tag_target(root: Path, version: str) -> str | None:
    tag = run_command(
        ["git", "ls-remote", "--exit-code", "--tags", "origin", f"refs/tags/{version}"],
        root,
        allowed=(0, 2),
    )
    if tag.returncode == 2 or not tag.stdout.strip():
        return None
    return tag.stdout.split()[0].lower()


def release_state(root: Path, repository: str, version: str, source_sha: str) -> str:
    target = remote_tag_target(root, version)
    result = run_command(
        ["gh", "api", f"repos/{repository}/releases/tags/{version}"],
        root,
        allowed=(0, 1),
    )
    if result.returncode == 1:
        detail = (result.stderr or result.stdout).strip()
        if not re.search(r"\bHTTP 404\b", detail):
            raise TriggerError(f"release lookup failed: {detail or 'exit code 1'}")
        release = None
    else:
        try:
            release = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise TriggerError("release lookup returned invalid JSON") from exc
    if target is None:
        if release is None:
            return "new"
        raise TriggerError(f"release {version} exists without its immutable tag")
    if target != source_sha:
        raise TriggerError(f"existing tag {version} does not point to the selected origin/main SHA")
    if not isinstance(release, dict):
        return "resume"
    if release.get("draft") is True:
        return "resume"
    raise TriggerError(f"release {version} is already published and immutable; use a new version")


def parse_json_list(raw: str, label: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise TriggerError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise TriggerError(f"{label} did not return a JSON list")
    return value


def list_runs(root: Path) -> list[dict]:
    result = run_command(
        [
            "gh",
            "run",
            "list",
            "--workflow",
            WORKFLOW,
            "--limit",
            RUN_LIST_LIMIT,
            "--json",
            "databaseId,displayTitle,status,url,headSha,event",
        ],
        root,
    )
    return parse_json_list(result.stdout, "gh run list")


def require_no_duplicate(root: Path, version: str) -> set[int]:
    pulls = run_command(
        ["gh", "pr", "list", "--state", "open", "--limit", RUN_LIST_LIMIT, "--json", "headRefName,url"], root
    )
    canonical_prefix = f"gamesymbols/build/{version}"
    for pull in parse_json_list(pulls.stdout, "gh pr list"):
        head_ref = str(pull.get("headRefName", ""))
        if head_ref.startswith(canonical_prefix):
            raise TriggerError(f"an output PR is already open for {version}: {pull.get('url')}")
    runs = list_runs(root)
    title = f"Release build {version}"
    for run in runs:
        if run.get("status") in {"queued", "in_progress"} and run.get("displayTitle") == title:
            raise TriggerError(f"a release build is already active for {version}: {run.get('url')}")
    return {int(run["databaseId"]) for run in runs if "databaseId" in run}


def require_main_unchanged(root: Path, source_sha: str) -> None:
    result = run_command(["git", "ls-remote", "--heads", "origin", "refs/heads/main"], root)
    remote_sha = result.stdout.split()[0].lower() if result.stdout.split() else ""
    if remote_sha != source_sha:
        raise TriggerError("origin/main advanced while validating the rebuild request; run the skill again")


def dispatch(root: Path, version: str, source_sha: str) -> None:
    run_command(
        [
            "gh",
            "workflow",
            "run",
            WORKFLOW,
            "--ref",
            "main",
            "-f",
            f"version={version}",
            "-f",
            f"source_sha={source_sha}",
        ],
        root,
    )


def discover_run(root: Path, known_ids: set[int], *, version: str, source_sha: str) -> str:
    for _attempt in range(RUN_DISCOVERY_ATTEMPTS):
        for run in list_runs(root):
            run_id = int(run.get("databaseId", 0))
            if (
                run_id not in known_ids
                and run.get("displayTitle") == f"Release build {version}"
                and run.get("event") == "workflow_dispatch"
                and run.get("headSha") == source_sha
            ):
                return str(run.get("url"))
        time.sleep(RUN_DISCOVERY_DELAY_SECONDS)
    raise TriggerError("workflow was dispatched but its Actions run URL could not be discovered")


def execute(requested: str) -> dict:
    root = repository_root()
    repository = require_repository(root)
    require_github_access(root, repository)
    source_sha, subject = resolve_source(root)
    version = require_version(requested)
    state = release_state(root, repository, version, source_sha)
    known_ids = require_no_duplicate(root, version)
    require_main_unchanged(root, source_sha)
    dispatch(root, version, source_sha)
    run_url = discover_run(root, known_ids, version=version, source_sha=source_sha)
    return {
        "version": version,
        "state": state,
        "source_sha": source_sha,
        "subject": subject,
        "run_url": run_url,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="A release version of the form vYYYYMMDD[a-z]")
    args = parser.parse_args(argv)
    try:
        result = execute(args.version)
    except (TriggerError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Selected VERSION: {result['version']}")
    print(f"Release state: {result['state']}")
    print(f"SOURCE_SHA: {result['source_sha']}")
    print(f"Commit: {result['subject']}")
    print(f"Actions run: {result['run_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
