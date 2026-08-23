from __future__ import annotations

import argparse
from pathlib import Path

from release_workflow_lib.content import build_content_manifest, verify_content_manifest
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes
from release_workflow_lib.shadow import run_shadow_verification


def _identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-default-ref", required=True)
    parser.add_argument("-repository-id", required=True, type=int)
    parser.add_argument("-workflow-repository", required=True)
    parser.add_argument("-workflow-path", required=True)
    parser.add_argument("-workflow-ref", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and verify GoldSrc release content provenance")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("manifest-build")
    _identity_arguments(build)
    build.add_argument("-tag", required=True)
    build.add_argument("-output", required=True)
    verify = commands.add_parser("manifest-verify")
    _identity_arguments(verify)
    verify.add_argument("-manifest", required=True)
    shadow = commands.add_parser("shadow")
    _identity_arguments(shadow)
    shadow.add_argument("-tag", action="append", required=True)
    shadow.add_argument("-output-dir", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo = GitObjectRepository(args.repo_root)
    identity = {
        "repo": repo,
        "repository_id": args.repository_id,
        "workflow_repository": args.workflow_repository,
        "workflow_path": args.workflow_path,
        "workflow_ref": args.workflow_ref,
    }
    try:
        if args.command == "manifest-build":
            document = build_content_manifest(source_ref=args.default_ref, tag=args.tag, **identity)
            Path(args.output).write_bytes(canonical_json_bytes(document))
        elif args.command == "manifest-verify":
            verify_content_manifest(
                default_ref=args.default_ref,
                manifest_raw=Path(args.manifest).read_bytes(),
                **identity,
            )
        else:
            run_shadow_verification(
                default_ref=args.default_ref,
                tags=tuple(args.tag),
                output_dir=args.output_dir,
                **identity,
            )
    except (OSError, ReleaseWorkflowError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
