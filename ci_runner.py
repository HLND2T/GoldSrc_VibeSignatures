#!/usr/bin/env python3
"""Portable CI orchestration executed from the workflow's trusted tooling checkout."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml

import ci_s3_cache
from release_workflow_lib.hashing import sha256_file, write_canonical_json

MAX_TAIL_CONCURRENCY = 32
DEFAULT_TAIL_CONCURRENCY = 2


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or not str(value).strip():
        raise ValueError(f"{name} is required")
    return str(value)


def workspace():
    return Path(env("GITHUB_WORKSPACE")).absolute()


def temporary(*parts):
    return Path(env("RUNNER_TEMP")).joinpath(*parts)


def emit(values, *, environment=False):
    ci_s3_cache.write_outputs(values, env("GITHUB_ENV" if environment else "GITHUB_OUTPUT"))


def command(args, *, capture=False):
    result = subprocess.run(
        [str(arg) for arg in args],
        check=True,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE if capture else None,
        cwd=workspace(),
    )
    return result.stdout.strip() if capture else None


def tool(script, *args, project=None, capture=False):
    prefix = ["uv", "run"] + (["--project", project] if project else [])
    path = Path(project) / script if project else script
    return command([*prefix, "python", path, *args], capture=capture)


def checked_path(root, target):
    root, target = root.absolute(), target.absolute()
    if target == root or not target.is_relative_to(root):
        raise ValueError(f"Path escaped its allowed root: {target}")
    for path in (target, *target.parents):
        if ci_s3_cache.is_link(path):
            raise ValueError(f"Path traverses a link: {path}")
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escaped its allowed root: {target}")
    return target


def reset_temporary(target):
    target = checked_path(temporary(), target)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    return target


def sync_submodules():
    command(["git", "submodule", "sync", "--recursive"])
    command(["git", "submodule", "update", "--init", "--recursive", "--force", "--depth", "1", "--jobs", "8"])


def clean_bin():
    target = checked_path(workspace(), workspace() / "bin")
    if not target.exists():
        return
    top = Path(command(["git", "-C", target, "rev-parse", "--show-toplevel"], capture=True)).resolve()
    if top != target.resolve():
        raise ValueError(f"Refusing to clean an unexpected bin repository: {top}")
    command(["git", "-C", target, "reset", "--hard"])
    command(["git", "-C", target, "clean", "-ffdx"])


def validate_producer():
    if not re.fullmatch(r"[0-9a-fA-F]{40}", env("SOURCE_SHA")):
        raise ValueError("source_sha must be a full 40-hex commit SHA")
    scope = env("SCOPE")
    if scope not in ("release-all", "bound-plan"):
        raise ValueError("unsupported producer scope")
    env("SELECTION_ARTIFACT_NAME")
    if scope == "bound-plan":
        env("PLAN_ARTIFACT_NAME")
        if not re.fullmatch(r"[0-9a-f]{64}", env("PLAN_SHA256")):
            raise ValueError("bound-plan scope requires a lowercase plan_sha256")
    if command(["git", "rev-parse", "HEAD"], capture=True).lower() != env("SOURCE_SHA").lower():
        raise ValueError("Warmup source checkout drifted")


def host_tool(*names):
    # uv prepends its dependency environment; IDA belongs to the host installation.
    excluded = [Path(sys.prefix).resolve(), workspace() / ".venv", workspace() / ".ci-tools" / ".venv"]
    paths = [
        entry
        for entry in os.get_exec_path()
        if entry and not any(Path(entry).absolute().is_relative_to(p) for p in excluded)
    ]
    for name in names:
        found = shutil.which(name, path=os.pathsep.join(paths))
        if found:
            return str(Path(found).absolute())
    raise ValueError(f"Runner tool {'/'.join(names)} is unavailable on the host PATH")


def resolve_ida(*, consumer=False, release=False):
    python = host_tool("python", "python3")
    mcp = host_tool("idalib-mcp") if consumer else None
    probe = workspace() / ("ida_runtime_probe.py" if consumer else "idb_warm_worker.py")
    args = ["--idalib-mcp", mcp] if consumer else ["--print-ida-version"]
    version = command([python, probe, *args], capture=True)
    if not version:
        raise ValueError("Failed to resolve the IDA kernel version")
    values = {"IDA_PYTHON_EXE": python, "IDA_KERNEL_VERSION": version}
    if release:
        env("IDADIR")
        runtime = temporary("ida-runtime.json")
        write_canonical_json(runtime, {"kernel_version": version, "idalib_mcp_sha256": sha256_file(mcp)})
        values["IDA_RUNTIME_PATH"] = str(runtime)
    if not consumer:
        values["CACHE_BUNDLE"] = str(temporary("idb-cache-selection"))
    emit(values, environment=True)


def cache_prepare():
    values = ci_s3_cache.prepare(workspace(), env("GITHUB_REPOSITORY"), env("RUNNER_OS"))
    emit(values)
    emit({"IDB_CACHE_ROOT": values["persisted-root"]}, environment=True)


def verify_plan():
    plan = temporary("idb-cache-selection", "plan.json")
    document = json.loads(plan.read_text(encoding="utf-8-sig"))
    if document["plan_sha256"] != env("PLAN_SHA256"):
        raise ValueError("bound plan does not carry the caller-declared plan_sha256")
    print(f"Bound plan file SHA-256: {sha256_file(plan)}; plan_sha256: {document['plan_sha256']}")


def warm_selection(operation):
    bundle = temporary("idb-cache-selection")
    bundle.mkdir(parents=True, exist_ok=True)
    common = [
        "-repo-root",
        workspace(),
        "-bindir",
        "bin",
        "-persisted-root",
        env("IDB_CACHE_ROOT"),
        "-kernel-version",
        env("IDA_KERNEL_VERSION"),
    ]
    release = env("SCOPE") == "release-all"
    script = "idb_cache_release.py" if release else "idb_cache_workflow.py"
    binding = ["-source-sha", env("SOURCE_SHA")] if release else ["-plan", bundle / "plan.json", "-merge-ref", "HEAD"]
    if operation == "prepare":
        args = [
            "--ida-python",
            env("IDA_PYTHON_EXE"),
            "--max-concurrency",
            env("IDB_WARMUP_MAX_CONCURRENCY", "2"),
            "--worker-timeout-seconds",
            "1800",
            "--repository",
            env("GITHUB_REPOSITORY"),
            "-run-id",
            env("GITHUB_RUN_ID"),
            "-attempt",
            env("GITHUB_RUN_ATTEMPT"),
            "-output",
            bundle / "cache-selection.json",
            "-output-sha256",
            bundle / "cache-selection.sha256",
        ]
    else:
        args = ["-selection", bundle / "cache-selection.json", "-selection-sha256", bundle / "cache-selection.sha256"]
    tool(script, operation, *common, *binding, *args)


def warm_materialize():
    tool(
        "release_workflow.py",
        "materialize-accepted-bin",
        "--repo-root",
        workspace(),
        "--persisted-root",
        env("IDB_CACHE_ROOT"),
        "--bindir",
        "bin",
        "--all-gamevers",
    )


def warm_outputs():
    bundle = temporary("idb-cache-selection")
    digest = (bundle / "cache-selection.sha256").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("cache selection SHA-256 evidence is malformed")
    document = json.loads((bundle / "cache-selection.json").read_text(encoding="utf-8"))
    emit(
        {
            "selection_artifact_name": env("SELECTION_ARTIFACT_NAME"),
            "selection_sha256": digest,
            "selection_schema_version": str(document["schema_version"]),
            "source_sha": env("SOURCE_SHA").lower(),
        }
    )


def verify_producer_digest(bundle):
    expected = env("PRODUCER_SELECTION_SHA256")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected)
        or (bundle / "cache-selection.sha256").read_text(encoding="utf-8").strip() != expected
    ):
        raise ValueError("cache selection digest mismatch")


def pr_restore():
    bundle = temporary("gamesymbol-validation")
    verify_producer_digest(bundle)
    env("IDADIR")
    tool(
        "idb_cache_workflow.py",
        "restore",
        "-repo-root",
        workspace(),
        "-plan",
        bundle / "plan.json",
        "-merge-ref",
        "HEAD",
        "-bindir",
        "bin",
        "-persisted-root",
        env("IDB_CACHE_ROOT"),
        "-kernel-version",
        env("IDA_KERNEL_VERSION"),
        "-selection",
        bundle / "cache-selection.json",
        "-selection-sha256",
        bundle / "cache-selection.sha256",
    )


def tail_concurrency():
    raw = os.environ.get("GSVIBE_TAIL_MAX_CONCURRENCY", str(DEFAULT_TAIL_CONCURRENCY))
    if not re.fullmatch(r"[0-9]+", raw) or not 1 <= int(raw) <= MAX_TAIL_CONCURRENCY:
        raise ValueError(f"GSVIBE_TAIL_MAX_CONCURRENCY must be a decimal integer in 1..32, got {raw!r}")
    return int(raw)


@contextmanager
def stage(label):
    started = time.monotonic()
    status = "failed"
    print(f"[{datetime.now(timezone.utc).isoformat()}] START {label}", flush=True)
    try:
        yield
        status = "succeeded"
    finally:
        print(
            f"[{datetime.now(timezone.utc).isoformat()}] END {label} status={status} elapsed={time.monotonic() - started:.3f}s",
            flush=True,
        )


def parallel_tags(tags, action, concurrency, label):
    failures = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(action, tag): tag for tag in tags}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001 - all siblings must finish before reporting failure.
                detail = (
                    f"command exited with code {exc.returncode}"
                    if isinstance(exc, subprocess.CalledProcessError)
                    else str(exc)
                )
                failures.append(f"{futures[future]}: {detail}")
    if failures:
        raise ValueError(f"{len(failures)} tag {label}(s) failed: {'; '.join(sorted(failures))}")


def pr_validate():
    concurrency = tail_concurrency()
    plan = temporary("gamesymbol-validation", "plan.json")
    document = json.loads(plan.read_text(encoding="utf-8"))
    analyzed = [item for item in document["tags"] if item["analysis_nodes"]]
    selection = temporary("gamesymbol-validation", "analysis-selection.json")
    write_canonical_json(
        selection,
        {
            "schema_version": 1,
            "selections": [{"tag": item["tag"], "node_ids": item["analysis_nodes"]} for item in analyzed],
        },
    )
    artifact_root = temporary("rebuilt-bin-artifacts")
    diagnostics = temporary(f"gamesymbol-analysis-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT')}")
    trusted = workspace() / ".trusted-validator"
    with stage("batch/validate-selection"):
        tool(
            "ida_analyze_bin.py",
            "-batch_selection",
            selection,
            "-validate_selection_only",
            "-artifactdir",
            artifact_root,
            "-batch_diagnostics",
            diagnostics,
        )

    def materialize(tag):
        with stage(f"{tag}/materialize"):
            tool(
                "gamesymbol_pr_validation.py",
                "materialize",
                "-repo-root",
                workspace(),
                "-plan",
                plan,
                "-tag",
                tag,
                "-merge-ref",
                "HEAD",
                "-bindir",
                "bin",
                "-artifactdir",
                artifact_root,
                project=trusted,
            )

    tags = [item["tag"] for item in analyzed]
    parallel_tags(tags, materialize, concurrency, "materialization")
    with stage("batch/analyze"):
        tool(
            "ida_analyze_bin.py",
            "-batch_selection",
            selection,
            "-bindir",
            "bin",
            "-artifactdir",
            artifact_root,
            "-batch_diagnostics",
            diagnostics,
            "-debug",
            "-process_reporter",
            "console",
        )

    def downstream(tag):
        with tempfile.TemporaryDirectory(prefix=f"gamesymbol-{tag}-", dir=temporary()) as directory:
            root = Path(directory)
            candidate, symbol_session, gamedata_session = (
                root / f"{tag}.yaml",
                root / "symbol-session.json",
                root / "gamedata-session.json",
            )
            commands = [
                (
                    "compare",
                    "gamesymbol_pr_validation.py",
                    [
                        "compare",
                        "-repo-root",
                        workspace(),
                        "-plan",
                        plan,
                        "-tag",
                        tag,
                        "-merge-ref",
                        "HEAD",
                        "-bindir",
                        "bin",
                        "-artifactdir",
                        artifact_root,
                    ],
                    trusted,
                ),
                (
                    "symbol-build",
                    "gamesymbol_candidate.py",
                    [
                        "build",
                        "-gamever",
                        tag,
                        "-bindir",
                        "bin",
                        "-artifactdir",
                        artifact_root,
                        "-configyaml",
                        f"configs/{tag}.yaml",
                        "-output",
                        candidate,
                        "-session",
                        symbol_session,
                        "-snapshot-schema-version",
                        "8",
                    ],
                    trusted,
                ),
                (
                    "symbol-guard",
                    "gamesymbol_candidate.py",
                    ["guard", "-candidate", candidate, "-session", symbol_session],
                    None,
                ),
                (
                    "gamedata-build",
                    "gamedata_candidate.py",
                    [
                        "build",
                        "-gamever",
                        tag,
                        "-build-id",
                        f"pr-{env('GITHUB_RUN_ID')}",
                        "-snapshot",
                        candidate,
                        "-configyaml",
                        f"configs/{tag}.yaml",
                        "-modulesdir",
                        "gamedata-generators",
                        "-candidate-root",
                        root / "gamedata",
                        "-session",
                        gamedata_session,
                    ],
                    None,
                ),
                ("gamedata-guard", "gamedata_candidate.py", ["guard", "-session", gamedata_session], None),
                (
                    "self-consistency",
                    "gamesymbol_candidate.py",
                    [
                        "mark",
                        "-candidate",
                        candidate,
                        "-session",
                        symbol_session,
                        "-step",
                        "gamedata",
                        "-gamedata-session",
                        gamedata_session,
                    ],
                    None,
                ),
            ]
            for label, script, args, project in commands:
                with stage(f"{tag}/{label}"):
                    tool(script, *args, project=project)

    parallel_tags(tags, downstream, concurrency, "validation pipeline")
    with stage("batch/check-tracked-artifacts"):
        command(["git", "diff", "--exit-code", "--", "bin_artifacts"])


def release_restore():
    if env("SOURCE_ARTIFACT_MODE", "rebuild") == "tracked":
        return
    bundle = temporary("idb-cache-selection")
    verify_producer_digest(bundle)
    for operation in ("verify", "restore"):
        tool(
            "idb_cache_release.py",
            operation,
            "-repo-root",
            workspace(),
            "-bindir",
            "bin",
            "-persisted-root",
            env("IDB_CACHE_ROOT"),
            "-kernel-version",
            env("IDA_KERNEL_VERSION"),
            "-source-sha",
            env("SOURCE_SHA"),
            "-selection",
            bundle / "cache-selection.json",
            "-selection-sha256",
            bundle / "cache-selection.sha256",
        )


def release_analyze():
    artifacts = reset_temporary(temporary("rebuilt-bin-artifacts"))
    tool(
        "ida_analyze_bin.py",
        "-allgamever",
        "-force_all",
        "-bindir",
        "bin",
        "-artifactdir",
        artifacts,
        "-debug",
        "-process_reporter",
        "console",
        "-batch_diagnostics",
        temporary(f"analysis-diagnostics-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT')}"),
    )
    tool("bin_artifact_contract.py", "--repo-root", workspace(), "--actual-root", artifacts)
    command(["git", "diff", "--exit-code", "--", "bin_artifacts"])
    emit({"RELEASE_ARTIFACT_ROOT": str(workspace() / "bin_artifacts")}, environment=True)


def release_bind():
    binding = temporary("tracked-artifact-binding.json")
    tool(
        "release_bundle.py",
        "bind-tracked",
        "--repo-root",
        workspace(),
        "--source-sha",
        env("SOURCE_SHA"),
        "--output",
        binding,
    )
    emit(
        {"RELEASE_TRACKED_BINDING": str(binding), "RELEASE_ARTIFACT_ROOT": str(workspace() / "bin_artifacts")},
        environment=True,
    )


def gamevers():
    with (workspace() / "configs" / "config.yaml").open(encoding="utf-8") as handle:
        versions = yaml.safe_load(handle)["gamevers"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(
            not isinstance(tag, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+", tag) for tag in versions
        )
    ):
        raise ValueError("configs/config.yaml contains invalid game versions")
    return versions


def release_datasets():
    generated = reset_temporary(temporary("release-generated"))
    snapshots, datasets = generated / "gamesymbols", generated / "gamesymbols-json"
    snapshots.mkdir()
    datasets.mkdir()
    published = (
        datetime.fromisoformat(command(["git", "show", "-s", "--format=%cI", "HEAD"], capture=True))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    for tag in gamevers():
        root = reset_temporary(temporary(f"release-candidate-{tag}"))
        candidate, session, json_session = (
            root / f"{tag}.yaml",
            root / "symbol-session.json",
            root / "json-session.json",
        )
        tool(
            "gamesymbol_candidate.py",
            "build",
            "-gamever",
            tag,
            "-bindir",
            "bin",
            "-artifactdir",
            env("RELEASE_ARTIFACT_ROOT"),
            "-configyaml",
            f"configs/{tag}.yaml",
            "-output",
            candidate,
            "-session",
            session,
            "-last-publish-time",
            published,
        )
        tool(
            "gamesymbols_json.py",
            "build",
            "-snapshot",
            candidate,
            "-metadata",
            root / f"{tag}.metadata.yaml",
            "-gamever",
            tag,
            "-output-dir",
            datasets,
            "-session",
            json_session,
        )
        tool(
            "gamesymbol_candidate.py",
            "mark",
            "-candidate",
            candidate,
            "-session",
            session,
            "-step",
            "json",
            "-json-session",
            json_session,
        )
        tool(
            "gamesymbol_candidate.py",
            "publish",
            "-candidate",
            candidate,
            "-session",
            session,
            "-destination",
            snapshots / f"{tag}.yaml",
        )
    emit({"GENERATED_ROOT": str(generated)}, environment=True)


def release_bundle():
    root = checked_path(temporary(), temporary("release-bundle"))
    if root.exists():
        shutil.rmtree(root)
    mode = env("SOURCE_ARTIFACT_MODE", "rebuild")
    common = [
        "--repo-root",
        workspace(),
        "--bundle-root",
        root,
        "--source-artifact-mode",
        mode,
        "--version",
        env("VERSION"),
        "--build-id",
        env("BUILD_ID"),
        "--workflow-run-url",
        env("WORKFLOW_RUN_URL"),
        "--source-sha",
        env("SOURCE_SHA"),
    ]
    build = (
        ["--tracked-binding", env("RELEASE_TRACKED_BINDING")]
        if mode == "tracked"
        else ["--cache-selection", temporary("idb-cache-selection", "cache-selection.json")]
    )
    verify = [] if mode == "tracked" else ["--cache-selection-sha256", env("PRODUCER_SELECTION_SHA256")]
    tool(
        "release_bundle.py",
        "build",
        *common,
        *build,
        "--gamesymbols-root",
        Path(env("GENERATED_ROOT")) / "gamesymbols",
        "--gamesymbols-json-root",
        Path(env("GENERATED_ROOT")) / "gamesymbols-json",
        "--ida-runtime",
        env("IDA_RUNTIME_PATH"),
    )
    tool("release_bundle.py", "verify", *common, *verify)


def legacy_cleanup():
    for tag in gamevers():
        tool(
            "release_workflow.py",
            "cleanup-legacy-accepted-yaml",
            "--repo-root",
            workspace(),
            "--persisted-root",
            env("PERSISTED_WORKSPACE"),
            "--gamever",
            tag,
            "--cutover-id",
            "bin-artifacts-v1",
        )


def artifacts():
    kind = env("CI_KIND")
    paths = {
        "warmup": [temporary("idb-cache-selection")],
        "pr": [
            temporary("rebuilt-bin-artifacts"),
            temporary("gamesymbol-validation"),
            temporary(f"gamesymbol-analysis-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT')}"),
        ],
        "release": [
            temporary("release-bundle"),
            temporary("rebuilt-bin-artifacts"),
            temporary(f"analysis-diagnostics-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT')}"),
        ],
    }[kind]
    available = [path for path in paths if path.exists()]
    emit({"available": str(bool(available)).lower(), "paths": "\n".join(str(path) for path in available)})


def cleanup():
    if env("CI_KIND") == "warmup":
        bundle = temporary("idb-cache-selection")
        for identity in bundle.glob(".*-identity.json"):
            checked_path(temporary(), identity).unlink()
    clean_bin()


COMMANDS = {
    "validate-producer": validate_producer,
    "sync-submodules": sync_submodules,
    "clean-bin": clean_bin,
    "cache-prepare": cache_prepare,
    "resolve-warm-ida": resolve_ida,
    "resolve-consumer-ida": lambda: resolve_ida(consumer=True),
    "resolve-release-ida": lambda: resolve_ida(consumer=True, release=True),
    "verify-plan": verify_plan,
    "warm-materialize": warm_materialize,
    "warm-prepare": lambda: warm_selection("prepare"),
    "warm-verify": lambda: warm_selection("verify"),
    "warm-outputs": warm_outputs,
    "pr-restore": pr_restore,
    "pr-validate": pr_validate,
    "release-restore": release_restore,
    "release-analyze": release_analyze,
    "release-bind": release_bind,
    "release-datasets": release_datasets,
    "release-bundle": release_bundle,
    "legacy-cleanup": legacy_cleanup,
    "artifacts": artifacts,
    "cleanup": cleanup,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args(argv)
    try:
        COMMANDS[args.command]()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        # Commands may contain credentials; never print argv on failure.
        detail = (
            f"command exited with code {exc.returncode}" if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        )
        print(f"CI {args.command} failed: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
