from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from release_workflow_lib.content import build_content_manifest, verify_content_manifest
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.github_api import GitHubReleaseApi
from release_workflow_lib.hashing import canonical_json_bytes, write_canonical_json
from release_workflow_lib.output import prepare_output_build, validate_output_event, verify_output_pull_request
from release_workflow_lib.promotion import promote_release, republish_release, verify_promotion_merge
from release_workflow_lib.recovery import (
    abandon_build,
    authorize_retry,
    cleanup_completed_stage,
    load_completion_record,
    reconcile_local_stage,
    reconcile_release,
    stage_info,
    verify_retry_authorized,
)
from release_workflow_lib.shadow import run_shadow_verification
from release_workflow_lib.staging import bind_pull_request, repair_pr_index


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
    output_build = commands.add_parser("output-build")
    _identity_arguments(output_build)
    output_build.add_argument("-tag", required=True)
    output_build.add_argument("-build-id", required=True)
    output_build.add_argument("-repository", required=True)
    output_build.add_argument("-base-branch", required=True)
    output_build.add_argument("-persisted-root", required=True)
    output_build.add_argument("-run-id", required=True)
    output_build.add_argument("-run-attempt", required=True, type=int)
    output_build.add_argument("-lease-owner", required=True)
    output_build.add_argument("-output", required=True)
    bind_pr = commands.add_parser("bind-pr")
    bind_pr.add_argument("-persisted-root", required=True)
    bind_pr.add_argument("-tag", required=True)
    bind_pr.add_argument("-build-id", required=True)
    bind_pr.add_argument("-pr-number", required=True, type=int)
    bind_pr.add_argument("-pr-head-sha", required=True)
    bind_pr.add_argument("-pr-base-sha", required=True)
    event_check = commands.add_parser("output-event-check")
    _event_arguments(event_check, include_refs=False)
    output_verify = commands.add_parser("output-verify")
    _event_arguments(output_verify, include_refs=True)
    output_verify.add_argument("-build-workflow-path", required=True)
    output_verify.add_argument("-build-workflow-ref", required=True)
    output_verify.add_argument("-persisted-root", required=True)
    output_verify.add_argument("-output", required=True)
    promotion_verify = commands.add_parser("promotion-verify")
    _promotion_arguments(promotion_verify)
    promotion_verify.add_argument("-output", required=True)
    promote = commands.add_parser("promote")
    _promotion_arguments(promote)
    promote.add_argument("-expected-approval-sha256", required=True)
    promote.add_argument("-workflow-path", required=True)
    promote.add_argument("-workflow-ref-sha", required=True)
    promote.add_argument("-run-id", required=True)
    promote.add_argument("-run-attempt", required=True, type=int)
    promote.add_argument("-output-dir", required=True)
    promote.add_argument("-github-api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    republish = commands.add_parser("republish")
    republish.add_argument("-repo-root", default=".")
    republish.add_argument("-repository", required=True)
    republish.add_argument("-persisted-root", required=True)
    republish.add_argument("-tag", required=True)
    republish.add_argument("-build-id", required=True)
    republish.add_argument("-output-dir", required=True)
    republish.add_argument("-github-api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    info = commands.add_parser("stage-info")
    info.add_argument("-persisted-root", required=True)
    info.add_argument("-tag", required=True)
    info.add_argument("-build-id", required=True)
    info.add_argument("-required-state")
    info.add_argument("-output", required=True)
    retry = commands.add_parser("retry")
    retry.add_argument("-persisted-root", required=True)
    retry.add_argument("-tag", required=True)
    retry.add_argument("-build-id", required=True)
    retry.add_argument("-new-build-id", required=True)
    retry.add_argument("-reason", required=True)
    retry_check = commands.add_parser("retry-check")
    retry_check.add_argument("-persisted-root", required=True)
    retry_check.add_argument("-tag", required=True)
    retry_check.add_argument("-build-id", required=True)
    retry_check.add_argument("-new-build-id", required=True)
    retry_check.add_argument("-reason", required=True)
    abandon = commands.add_parser("abandon")
    abandon.add_argument("-persisted-root", required=True)
    abandon.add_argument("-tag", required=True)
    abandon.add_argument("-build-id", required=True)
    abandon.add_argument("-confirmation", required=True)
    abandon.add_argument("-reason", required=True)
    repair = commands.add_parser("repair-index")
    repair.add_argument("-persisted-root", required=True)
    repair.add_argument("-tag", required=True)
    repair.add_argument("-build-id", required=True)
    repair.add_argument("-pr-number", required=True, type=int)
    repair.add_argument("-repository-id", required=True, type=int)
    repair.add_argument("-repository", required=True)
    repair.add_argument("-base-ref", required=True)
    repair.add_argument("-output-branch", required=True)
    repair.add_argument("-pr-head-sha", required=True)
    repair.add_argument("-pr-base-sha", required=True)
    repair.add_argument("-confirmation", required=True)
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("-persisted-root", required=True)
    cleanup.add_argument("-tag", required=True)
    cleanup.add_argument("-build-id", required=True)
    cleanup.add_argument("-confirmation", required=True)
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("-persisted-root", required=True)
    reconcile.add_argument("-tag", required=True)
    reconcile.add_argument("-build-id", required=True)
    reconcile.add_argument("-repository")
    reconcile.add_argument("-github-api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    return parser


def _event_arguments(parser: argparse.ArgumentParser, *, include_refs: bool) -> None:
    parser.add_argument("-repository-id", required=True, type=int)
    parser.add_argument("-repository", required=True)
    parser.add_argument("-expected-repository-id", required=True, type=int)
    parser.add_argument("-expected-repository", required=True)
    parser.add_argument("-head-repository", required=True)
    parser.add_argument("-head-branch", required=True)
    parser.add_argument("-base-branch", required=True)
    parser.add_argument("-expected-base-branch", required=True)
    parser.add_argument("-author-login", required=True)
    parser.add_argument("-expected-author-login", required=True)
    if include_refs:
        parser.add_argument("-repo-root", default=".")
        parser.add_argument("-base-ref", required=True)
        parser.add_argument("-head-ref", required=True)
        parser.add_argument("-pr-number", required=True, type=int)
        parser.add_argument("-workflow-repository", required=True)


def _promotion_arguments(parser: argparse.ArgumentParser) -> None:
    _event_arguments(parser, include_refs=False)
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-merge-ref", required=True)
    parser.add_argument("-default-ref", required=True)
    parser.add_argument("-head-ref", required=True)
    parser.add_argument("-pr-number", required=True, type=int)
    parser.add_argument("-workflow-repository", required=True)
    parser.add_argument("-build-workflow-path", required=True)
    parser.add_argument("-build-workflow-ref", required=True)
    parser.add_argument("-persisted-root", required=True)


def _event_kwargs(args) -> dict:
    return {
        "repository_id": args.repository_id,
        "repository": args.repository,
        "expected_repository_id": args.expected_repository_id,
        "expected_repository": args.expected_repository,
        "head_repository": args.head_repository,
        "head_branch": args.head_branch,
        "base_branch": args.base_branch,
        "expected_base_branch": args.expected_base_branch,
        "author_login": args.author_login,
        "expected_author_login": args.expected_author_login,
    }


def _promotion_kwargs(args) -> dict:
    return {
        "repo": GitObjectRepository(args.repo_root),
        "merge_ref": args.merge_ref,
        "default_ref": args.default_ref,
        "head_ref": args.head_ref,
        "pr_number": args.pr_number,
        **_event_kwargs(args),
        "workflow_repository": args.workflow_repository,
        "build_workflow_path": args.build_workflow_path,
        "build_workflow_ref": args.build_workflow_ref,
        "persisted_root": args.persisted_root,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {"manifest-build", "manifest-verify", "shadow", "output-build"}:
            repo = GitObjectRepository(args.repo_root)
            identity = {
                "repo": repo,
                "repository_id": args.repository_id,
                "workflow_repository": args.workflow_repository,
                "workflow_path": args.workflow_path,
                "workflow_ref": args.workflow_ref,
            }
        if args.command == "manifest-build":
            document = build_content_manifest(source_ref=args.default_ref, tag=args.tag, **identity)
            Path(args.output).write_bytes(canonical_json_bytes(document))
        elif args.command == "manifest-verify":
            verify_content_manifest(
                default_ref=args.default_ref,
                manifest_raw=Path(args.manifest).read_bytes(),
                **identity,
            )
        elif args.command == "shadow":
            run_shadow_verification(
                default_ref=args.default_ref,
                tags=tuple(args.tag),
                output_dir=args.output_dir,
                **identity,
            )
        elif args.command == "output-build":
            prepare_output_build(
                repo=repo,
                source_ref=args.default_ref,
                tag=args.tag,
                build_id=args.build_id,
                repository_id=args.repository_id,
                repository=args.repository,
                base_ref=args.base_branch,
                workflow_repository=args.workflow_repository,
                workflow_path=args.workflow_path,
                workflow_ref=args.workflow_ref,
                persisted_root=args.persisted_root,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                lease_owner=args.lease_owner,
                output_path=args.output,
            )
        elif args.command == "bind-pr":
            bind_pull_request(
                persisted_root=args.persisted_root,
                tag=args.tag,
                build_id=args.build_id,
                pr_number=args.pr_number,
                pr_head_sha=args.pr_head_sha,
                pr_base_sha=args.pr_base_sha,
            )
        elif args.command == "output-event-check":
            validate_output_event(
                repository_id=args.repository_id,
                repository=args.repository,
                head_repository=args.head_repository,
                head_ref=args.head_branch,
                base_ref=args.base_branch,
                expected_base_ref=args.expected_base_branch,
                author_login=args.author_login,
                expected_repository_id=args.expected_repository_id,
                expected_repository=args.expected_repository,
                expected_author_login=args.expected_author_login,
            )
        elif args.command == "output-verify":
            approval = verify_output_pull_request(
                repo=GitObjectRepository(args.repo_root),
                base_ref=args.base_ref,
                head_ref=args.head_ref,
                pr_number=args.pr_number,
                **_event_kwargs(args),
                workflow_repository=args.workflow_repository,
                workflow_path=args.build_workflow_path,
                workflow_ref=args.build_workflow_ref,
                persisted_root=args.persisted_root,
            )
            write_canonical_json(args.output, approval)
        elif args.command == "promotion-verify":
            write_canonical_json(args.output, verify_promotion_merge(**_promotion_kwargs(args)))
        elif args.command == "promote":
            approval = verify_promotion_merge(**_promotion_kwargs(args))
            token = os.environ.get("GITHUB_APP_TOKEN")
            api = GitHubReleaseApi(repository=args.repository, token=token or "", api_url=args.github_api_url)
            promote_release(
                repo=GitObjectRepository(args.repo_root),
                api=api,
                approval=approval,
                expected_approval_sha256=args.expected_approval_sha256,
                persisted_root=args.persisted_root,
                workflow_repository=args.workflow_repository,
                workflow_path=args.workflow_path,
                workflow_ref_sha=args.workflow_ref_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                output_dir=args.output_dir,
            )
        elif args.command == "republish":
            token = os.environ.get("GITHUB_APP_TOKEN")
            api = GitHubReleaseApi(repository=args.repository, token=token or "", api_url=args.github_api_url)
            republish_release(
                repo=GitObjectRepository(args.repo_root),
                api=api,
                completion_record=load_completion_record(
                    persisted_root=args.persisted_root,
                    tag=args.tag,
                    build_id=args.build_id,
                ),
                persisted_root=args.persisted_root,
                output_dir=args.output_dir,
            )
        elif args.command == "stage-info":
            write_canonical_json(
                args.output,
                stage_info(
                    persisted_root=args.persisted_root,
                    tag=args.tag,
                    build_id=args.build_id,
                    required_state=args.required_state,
                ),
            )
        elif args.command == "retry":
            print(
                json.dumps(
                    authorize_retry(
                        persisted_root=args.persisted_root,
                        tag=args.tag,
                        build_id=args.build_id,
                        new_build_id=args.new_build_id,
                        reason=args.reason,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "retry-check":
            print(
                json.dumps(
                    verify_retry_authorized(
                        persisted_root=args.persisted_root,
                        tag=args.tag,
                        build_id=args.build_id,
                        new_build_id=args.new_build_id,
                        reason=args.reason,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "abandon":
            abandon_build(
                persisted_root=args.persisted_root,
                tag=args.tag,
                build_id=args.build_id,
                confirmation=args.confirmation,
                reason=args.reason,
            )
        elif args.command == "repair-index":
            repair_pr_index(
                persisted_root=args.persisted_root,
                tag=args.tag,
                build_id=args.build_id,
                pr_number=args.pr_number,
                repository_id=args.repository_id,
                repository=args.repository,
                base_ref=args.base_ref,
                output_branch_name=args.output_branch,
                pr_head_sha=args.pr_head_sha,
                pr_base_sha=args.pr_base_sha,
                confirmation=args.confirmation,
            )
        elif args.command == "cleanup":
            print(
                cleanup_completed_stage(
                    persisted_root=args.persisted_root,
                    tag=args.tag,
                    build_id=args.build_id,
                    confirmation=args.confirmation,
                )
            )
        elif args.command == "reconcile":
            token = os.environ.get("GITHUB_API_TOKEN")
            if args.repository and token:
                result = reconcile_release(
                    persisted_root=args.persisted_root,
                    tag=args.tag,
                    build_id=args.build_id,
                    api=GitHubReleaseApi(repository=args.repository, token=token, api_url=args.github_api_url),
                )
            else:
                result = reconcile_local_stage(
                    persisted_root=args.persisted_root,
                    tag=args.tag,
                    build_id=args.build_id,
                )
            print(
                json.dumps(
                    result,
                    sort_keys=True,
                )
            )
    except (OSError, ReleaseWorkflowError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
