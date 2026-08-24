from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from release_workflow_lib.errors import GitIdentityError
from release_workflow_lib.hashing import canonical_json_bytes, normalized_relative_path, sha256_bytes

GIT_SHA1_LENGTH = 40


@dataclass(frozen=True)
class GitTreeEntry:
    path: str
    mode: str
    object_type: str
    oid: str
    size: int | None


class GitObjectRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def _run(self, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise GitIdentityError(f"git {' '.join(args)} failed: {message}")
        return result.stdout

    def resolve_commit(self, ref: str) -> str:
        oid = self._run("rev-parse", "--verify", f"{ref}^{{commit}}").decode("ascii").strip()
        if len(oid) != GIT_SHA1_LENGTH or any(character not in "0123456789abcdef" for character in oid):
            raise GitIdentityError(f"Resolved commit has unsupported object identity: {oid!r}")
        return oid

    def commit_parents(self, ref: str) -> tuple[str, ...]:
        fields = self._run("rev-list", "--parents", "-n", "1", self.resolve_commit(ref)).decode("ascii").split()
        return tuple(fields[1:])

    def is_ancestor(self, ancestor_ref: str, descendant_ref: str) -> bool:
        ancestor = self.resolve_commit(ancestor_ref)
        descendant = self.resolve_commit(descendant_ref)
        result = subprocess.run(
            ["git", "-C", str(self.path), "merge-base", "--is-ancestor", ancestor, descendant],
            capture_output=True,
            check=False,
        )
        if result.returncode not in {0, 1}:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise GitIdentityError(f"git merge-base --is-ancestor failed: {message}")
        return result.returncode == 0

    def changed_paths(self, base_ref: str, head_ref: str) -> tuple[str, ...]:
        raw = self._run("diff", "--name-only", "-z", self.resolve_commit(base_ref), self.resolve_commit(head_ref))
        try:
            paths = tuple(normalized_relative_path(item.decode("utf-8")) for item in raw.split(b"\0") if item)
        except UnicodeDecodeError as exc:
            raise GitIdentityError("Git diff contains a non-UTF-8 path") from exc
        if len(paths) != len({path.casefold() for path in paths}):
            raise GitIdentityError("Git diff contains duplicate or case-colliding paths")
        return paths

    def create_commit_with_blob(self, *, parent_ref: str, path: str, raw: bytes, message: str) -> str:
        parent = self.resolve_commit(parent_ref)
        normalized = normalized_relative_path(path)
        if not isinstance(message, str) or not message.strip():
            raise GitIdentityError("Commit message must be non-empty")
        environment = os.environ | {
            "GIT_AUTHOR_NAME": os.environ.get("GIT_AUTHOR_NAME", "GoldSrc release bot"),
            "GIT_AUTHOR_EMAIL": os.environ.get("GIT_AUTHOR_EMAIL", "release-bot@users.noreply.github.com"),
            "GIT_COMMITTER_NAME": os.environ.get("GIT_COMMITTER_NAME", "GoldSrc release bot"),
            "GIT_COMMITTER_EMAIL": os.environ.get("GIT_COMMITTER_EMAIL", "release-bot@users.noreply.github.com"),
        }

        def run(*args: str, input_bytes: bytes | None = None) -> bytes:
            result = subprocess.run(
                ["git", "-C", str(self.path), *args],
                input=input_bytes,
                capture_output=True,
                env=environment,
                check=False,
            )
            if result.returncode != 0:
                message_text = result.stderr.decode("utf-8", errors="replace").strip()
                raise GitIdentityError(f"git {' '.join(args)} failed: {message_text}")
            return result.stdout

        with tempfile.TemporaryDirectory(prefix="release-index-") as temporary:
            environment["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
            oid = run("hash-object", "-w", "--stdin", input_bytes=raw).decode("ascii").strip()
            run("read-tree", parent)
            run("update-index", "--add", "--cacheinfo", "100644", oid, normalized)
            tree = run("write-tree").decode("ascii").strip()
            commit = run("commit-tree", tree, "-p", parent, "-m", message.strip()).decode("ascii").strip()
        if self.commit_parents(commit) != (parent,) or self.changed_paths(parent, commit) != (normalized,):
            raise GitIdentityError("Constructed output commit does not have the required direct-parent/one-path shape")
        return self.resolve_commit(commit)

    def _parse_entries(self, raw: bytes) -> tuple[GitTreeEntry, ...]:
        entries = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise GitIdentityError("Malformed git ls-tree output")
            try:
                mode, object_type, oid, raw_size = metadata.decode("ascii").split()
                path = normalized_relative_path(raw_path.decode("utf-8"))
                size = None if raw_size == "-" else int(raw_size)
            except (UnicodeDecodeError, ValueError) as exc:
                raise GitIdentityError("Malformed or non-UTF-8 git tree entry") from exc
            entries.append(GitTreeEntry(path, mode, object_type, oid, size))
        return tuple(entries)

    def entry(self, ref: str, path: str) -> GitTreeEntry | None:
        normalized = normalized_relative_path(path)
        entries = self._parse_entries(self._run("ls-tree", "-z", "--long", ref, "--", normalized))
        if not entries:
            return None
        if len(entries) != 1 or entries[0].path != normalized:
            raise GitIdentityError(f"Git tree lookup was ambiguous for {normalized}")
        return entries[0]

    def list_tree(self, ref: str, prefix: str) -> tuple[GitTreeEntry, ...]:
        normalized = normalized_relative_path(prefix)
        entries = self._parse_entries(self._run("ls-tree", "-r", "-z", "--long", ref, "--", normalized))
        return tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))

    def read_blob_oid(self, oid: str) -> bytes:
        return self._run("cat-file", "blob", oid)

    def read_blob(self, ref: str, path: str, *, required_mode: str | None = None) -> bytes:
        entry = self.entry(ref, path)
        if entry is None:
            raise GitIdentityError(f"Required Git blob is missing at {ref}: {path}")
        if entry.object_type != "blob" or entry.size is None:
            raise GitIdentityError(f"Git tree entry is not a blob at {ref}: {path}")
        if required_mode is not None and entry.mode != required_mode:
            raise GitIdentityError(f"Git blob mode mismatch for {path}: expected {required_mode}, got {entry.mode}")
        raw = self.read_blob_oid(entry.oid)
        if len(raw) != entry.size:
            raise GitIdentityError(f"Git blob size mismatch for {path}")
        return raw

    def gitlink(self, ref: str, path: str) -> str:
        entry = self.entry(ref, path)
        if entry is None or entry.mode != "160000" or entry.object_type != "commit" or entry.size is not None:
            raise GitIdentityError(f"Required Git gitlink is missing at {ref}: {path}")
        return entry.oid


def source_bundle_sha256(
    repo: GitObjectRepository,
    ref: str,
    paths: tuple[str, ...],
    *,
    domain: str,
) -> str:
    files = []
    for path in sorted(paths, key=lambda value: value.encode("utf-8")):
        raw = repo.read_blob(ref, path, required_mode="100644")
        files.append({"path": path, "size": len(raw), "sha256": sha256_bytes(raw)})
    return sha256_bytes(canonical_json_bytes({"domain": domain, "files": files}))
