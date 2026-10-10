"""Private S3 endpoint parsing and disposable CI cache staging."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def parse_endpoint(value: str) -> dict[str, str]:
    if not value or any(c.isspace() for c in value):
        raise ValueError("S3_ENDPOINT_URL must be an HTTP(S) origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or "?" in value
        or "#" in value
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("S3_ENDPOINT_URL must contain only an HTTP(S) origin")
    port = parsed.port
    if port == 0:
        raise ValueError("Invalid S3 endpoint port")
    host = parsed.hostname if parsed.netloc.startswith("[") else parsed.netloc.split(":")[0]
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise ValueError("Invalid S3 endpoint hostname")
    return {
        "endpoint": host,
        "port": str(port or (80 if parsed.scheme == "http" else 443)),
        "insecure": str(parsed.scheme == "http").lower(),
    }


def is_link(path: Path) -> bool:
    return path.is_symlink() or (
        path.exists() and bool(getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    )


def prepare(workspace: Path, repository: str, platform: str) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if platform not in ("Windows", "Linux", "macOS"):
        raise ValueError("Invalid runner platform")
    workspace = workspace.absolute()
    # Never follow a runner workspace or staging junction during cleanup.
    for path in (workspace, *workspace.parents):
        if is_link(path):
            raise ValueError("Workspace traverses a link")
    if not workspace.is_dir():
        raise ValueError("Workspace is missing")
    repository_id = hashlib.sha256(repository.lower().encode()).hexdigest()
    name = f".gsvibe-s3-{repository_id}"
    staging = workspace.parent / name
    if is_link(staging):
        raise ValueError("Staging must not be a link")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    # hzqst/actions-cache rejects relative patterns ("." / ".."), so publish the
    # absolute staging path that the disposable layout already guarantees.
    prefix = f"gsvibe-s3-v1-{repository_id}"
    return {
        "cache-path": str(staging),
        "persisted-root": str(staging),
        "prefix": f"{prefix}-shared",
        "restore-prefixes": "\n".join(
            f"{prefix}-{os_name}-idb-" for os_name in ("shared", "windows", "linux", "macos")
        ),
    }


def write_outputs(values: dict[str, str], path: str | Path) -> None:
    """Write scalar and multiline values using the Actions environment-file protocol."""
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                delimiter = f"gsvibe_{uuid.uuid4().hex}"
                handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                handle.write(f"{key}={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("endpoint", "prepare"))
    args = parser.parse_args()
    if args.command == "endpoint":
        if os.environ.get("CACHE_OPERATION") not in ("restore", "save"):
            raise ValueError("Invalid cache operation")
        for name in ("S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"):
            if not os.environ.get(name, "").strip():
                raise ValueError(f"{name} is required")
        outputs = parse_endpoint(os.environ.get("S3_ENDPOINT_URL", ""))
    else:
        outputs = prepare(
            Path(os.environ["GITHUB_WORKSPACE"]), os.environ["GITHUB_REPOSITORY"], os.environ["RUNNER_OS"]
        )
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
            handle.write(f"IDB_CACHE_ROOT={outputs['persisted-root']}\n")
    write_outputs(outputs, os.environ["GITHUB_OUTPUT"])


if __name__ == "__main__":
    main()
