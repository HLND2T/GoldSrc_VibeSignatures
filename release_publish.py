#!/usr/bin/env python3
"""Preflight and publish immutable release bundle assets with the GitHub CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from release_bundle import ReleaseBundleError, verify_release_bundle
from release_workflow_lib.manifests import require_sha, require_version


class ReleasePublishError(ValueError):
    pass


IDENTITY_PREFIX = "<!-- gsvibe-release-identity:"
IDENTITY_SUFFIX = " -->"


def _run(arguments: list[str], *, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if result.returncode not in allowed:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        raise ReleasePublishError(f"{' '.join(arguments)} failed: {detail}")
    return result


def _gh_json(arguments: list[str], *, allow_not_found: bool = False) -> dict | None:
    result = _run(["gh", *arguments], allowed=(0, 1) if allow_not_found else (0,))
    if result.returncode == 1:
        detail = (result.stderr or result.stdout).strip()
        if allow_not_found and re.search(r"\bHTTP 404\b", detail):
            return None
        raise ReleasePublishError(f"gh {' '.join(arguments)} failed: {detail or 'exit code 1'}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleasePublishError(f"gh {' '.join(arguments)} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ReleasePublishError(f"gh {' '.join(arguments)} did not return an object")
    return value


def remote_state(repository: str, version: str) -> tuple[dict | None, dict | None]:
    version = require_version(version)
    tag = _gh_json(
        ["api", f"repos/{repository}/git/ref/tags/{version}"],
        allow_not_found=True,
    )
    release = _gh_json(
        ["api", f"repos/{repository}/releases/tags/{version}"],
        allow_not_found=True,
    )
    return tag, release


def preflight(repository: str, version: str, source_sha: str) -> str:
    return inspect_preflight(repository, version, source_sha, build_id="unused", workflow_run_url="unused")[0]


def _release_identity_notes(*, version: str, source_sha: str, build_id: str, workflow_run_url: str) -> str:
    identity = {
        "schema_version": 1,
        "release_version": version,
        "source_sha": source_sha,
        "build_id": str(build_id),
        "workflow_run_url": str(workflow_run_url),
    }
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"Immutable release built from {source_sha}.\n\n{IDENTITY_PREFIX}{encoded}{IDENTITY_SUFFIX}"


def _release_identity(release: dict, *, version: str, source_sha: str) -> tuple[str, str]:
    body = release.get("body")
    if not isinstance(body, str):
        raise ReleasePublishError("Existing Release has no immutable build identity")
    start = body.find(IDENTITY_PREFIX)
    end = body.find(IDENTITY_SUFFIX, start + len(IDENTITY_PREFIX))
    if start < 0 or end < 0:
        raise ReleasePublishError("Existing Release has no immutable build identity")
    try:
        identity = json.loads(body[start + len(IDENTITY_PREFIX) : end])
    except json.JSONDecodeError as exc:
        raise ReleasePublishError("Existing Release has an invalid build identity") from exc
    expected = {
        "schema_version": 1,
        "release_version": version,
        "source_sha": source_sha,
    }
    if not isinstance(identity, dict) or any(identity.get(key) != value for key, value in expected.items()):
        raise ReleasePublishError("Existing Release build identity does not match version and SOURCE_SHA")
    build_id = identity.get("build_id")
    workflow_run_url = identity.get("workflow_run_url")
    if not isinstance(build_id, str) or not build_id or not isinstance(workflow_run_url, str) or not workflow_run_url:
        raise ReleasePublishError("Existing Release has an incomplete build identity")
    return build_id, workflow_run_url


def inspect_preflight(
    repository: str,
    version: str,
    source_sha: str,
    *,
    build_id: str,
    workflow_run_url: str,
) -> tuple[str, str, str]:
    version = require_version(version)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    if not build_id or not workflow_run_url:
        raise ReleasePublishError("build_id and workflow_run_url are required")
    tag, release = remote_state(repository, version)
    if tag is None and release is not None:
        raise ReleasePublishError("Release exists without its immutable tag")
    if tag is not None:
        target = tag.get("object", {}).get("sha")
        kind = tag.get("object", {}).get("type")
        if kind != "commit" or target != source_sha:
            raise ReleasePublishError(f"Existing tag {version} does not point directly to SOURCE_SHA")
    if release is None:
        return ("new" if tag is None else "resume"), str(build_id), str(workflow_run_url)
    if release.get("tag_name") != version:
        raise ReleasePublishError("Existing Release tag identity mismatch")
    existing_build_id, existing_run_url = _release_identity(release, version=version, source_sha=source_sha)
    state = "resume" if release.get("draft") is True else "published"
    return state, existing_build_id, existing_run_url


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remote_asset_sha256(repository: str, version: str, asset: dict) -> str:
    digest = asset.get("digest")
    if isinstance(digest, str) and digest.startswith("sha256:"):
        return digest.removeprefix("sha256:")
    asset_id = asset.get("id")
    if not isinstance(asset_id, int):
        raise ReleasePublishError("Remote asset has no usable digest or ID")
    with tempfile.TemporaryDirectory(prefix="release-asset-") as temporary:
        target = Path(temporary) / str(asset.get("name", "asset"))
        _run(
            [
                "gh",
                "release",
                "download",
                version,
                "--repo",
                repository,
                "--pattern",
                target.name,
                "--dir",
                temporary,
            ]
        )
        if not target.is_file():
            raise ReleasePublishError(f"Remote asset download did not produce {target.name}")
        return _sha256_file(target)


def _release_assets(bundle_root: Path, manifest: dict, version: str) -> tuple[Path, ...]:
    relatives = [item["path"] for item in manifest["assets"]]
    relatives.extend((f"release-manifest-{version}.json", f"SHA256SUMS-{version}.txt"))
    paths = tuple(bundle_root / relative for relative in relatives)
    if any(not path.is_file() for path in paths):
        raise ReleasePublishError("Verified release bundle is missing a publishable asset")
    if len({path.name for path in paths}) != len(paths):
        raise ReleasePublishError("Publishable Release asset names must be globally unique")
    return paths


def publish_release(
    *,
    repository: str,
    repo_root: str | Path,
    bundle_root: str | Path,
    version: str,
) -> str:
    repo_root = Path(repo_root).resolve()
    bundle_root = Path(bundle_root).resolve()
    manifest = verify_release_bundle(repo_root=repo_root, bundle_root=bundle_root, version=version)
    source_sha = manifest["source_sha"]
    state, _build_id, _workflow_run_url = inspect_preflight(
        repository,
        version,
        source_sha,
        build_id=manifest["build_id"],
        workflow_run_url=manifest["workflow_run_url"],
    )
    if state == "new":
        _run(
            [
                "gh",
                "api",
                f"repos/{repository}/git/refs",
                "-f",
                f"ref=refs/tags/{version}",
                "-f",
                f"sha={source_sha}",
            ]
        )

    _tag, release = remote_state(repository, version)
    if release is None:
        _run(
            [
                "gh",
                "release",
                "create",
                version,
                "--repo",
                repository,
                "--target",
                source_sha,
                "--draft",
                "--verify-tag",
                "--title",
                version,
                "--notes",
                _release_identity_notes(
                    version=version,
                    source_sha=source_sha,
                    build_id=manifest["build_id"],
                    workflow_run_url=manifest["workflow_run_url"],
                ),
            ]
        )
        _tag, release = remote_state(repository, version)
    if release is None:
        raise ReleasePublishError("Draft Release was not observable after creation")
    if _release_identity(release, version=version, source_sha=source_sha) != (
        manifest["build_id"],
        manifest["workflow_run_url"],
    ):
        raise ReleasePublishError("Draft Release build identity differs from the verified bundle")
    if release.get("draft") is not True and state != "published":
        raise ReleasePublishError("Release became published before asset verification completed")

    remote_assets = {asset.get("name"): asset for asset in release.get("assets", []) if isinstance(asset, dict)}
    for path in _release_assets(bundle_root, manifest, version):
        expected_sha = _sha256_file(path)
        existing = remote_assets.get(path.name)
        if existing is None:
            if state == "published":
                raise ReleasePublishError(f"Published Release is missing asset {path.name}")
            _run(["gh", "release", "upload", version, str(path), "--repo", repository])
        elif (
            int(existing.get("size", -1)) != path.stat().st_size
            or _remote_asset_sha256(repository, version, existing) != expected_sha
        ):
            raise ReleasePublishError(f"Remote Release asset differs and cannot be overwritten: {path.name}")

    _tag, verified_release = remote_state(repository, version)
    if verified_release is None:
        raise ReleasePublishError("Release disappeared during verification")
    verified_assets = {
        asset.get("name"): asset for asset in verified_release.get("assets", []) if isinstance(asset, dict)
    }
    expected_paths = _release_assets(bundle_root, manifest, version)
    if set(verified_assets) != {path.name for path in expected_paths}:
        raise ReleasePublishError("Remote Release asset-name inventory mismatch")
    for path in expected_paths:
        asset = verified_assets[path.name]
        if int(asset.get("size", -1)) != path.stat().st_size or _remote_asset_sha256(
            repository, version, asset
        ) != _sha256_file(path):
            raise ReleasePublishError(f"Remote Release asset verification failed: {path.name}")

    if verified_release.get("draft") is True:
        _run(["gh", "release", "edit", version, "--repo", repository, "--draft=false", "--verify-tag"])
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("preflight")
    inspect.add_argument("--repository", required=True)
    inspect.add_argument("--version", required=True)
    inspect.add_argument("--source-sha", required=True)
    inspect.add_argument("--build-id", required=True)
    inspect.add_argument("--workflow-run-url", required=True)
    inspect.add_argument("--github-output")
    publish = commands.add_parser("publish")
    publish.add_argument("--repository", required=True)
    publish.add_argument("--repo-root", default=".")
    publish.add_argument("--bundle-root", required=True)
    publish.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            state, build_id, workflow_run_url = inspect_preflight(
                args.repository,
                args.version,
                args.source_sha,
                build_id=args.build_id,
                workflow_run_url=args.workflow_run_url,
            )
            if args.github_output:
                with Path(args.github_output).open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(f"release_state={state}\n")
                    handle.write(f"build_id={build_id}\n")
                    handle.write(f"workflow_run_url={workflow_run_url}\n")
            print(state)
        else:
            print(
                publish_release(
                    repository=args.repository,
                    repo_root=args.repo_root,
                    bundle_root=args.bundle_root,
                    version=args.version,
                )
            )
    except (ReleasePublishError, ReleaseBundleError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
