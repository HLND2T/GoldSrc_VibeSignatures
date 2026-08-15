"""Command-line entry points for the Redis Analyzer scheduler."""

import argparse
import os
import sys

from dotenv import load_dotenv

from process_reporter_factory import DEFAULT_REDIS_PREFIX, DEFAULT_REDIS_URL
from process_scheduler_redis import RedisProcessScheduler, RedisRunQueue, RunRequest


def _add_redis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("GSVIBE_REDIS_URL", DEFAULT_REDIS_URL),
    )
    parser.add_argument(
        "--redis-prefix",
        default=os.environ.get("GSVIBE_REDIS_PREFIX", DEFAULT_REDIS_PREFIX),
    )
    parser.add_argument("--group", default="scheduler")
    parser.add_argument("--consumer")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Submit and execute queued ida_analyze_bin.py runs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    submit = subparsers.add_parser("submit", help="Append a validated Run request to the Redis Stream")
    _add_redis_options(submit)
    submit.add_argument("--gamever", required=True)
    submit.add_argument("--platforms", default="windows,linux")
    submit.add_argument("--modules", default="*")
    submit.add_argument("--skill")
    submit.add_argument("--agent", default=os.environ.get("GSVIBE_AGENT", "claude"))
    submit.add_argument("--run-id")

    run = subparsers.add_parser("run", help="Run the single-concurrency Scheduler worker")
    _add_redis_options(run)
    run.add_argument("--recovery-idle-ms", type=int, default=30_000)
    run.add_argument("--poll-ms", type=int, default=1_000)
    run.add_argument("--analyzer-script", default="ida_analyze_bin.py")
    run.add_argument("--python-executable", default=sys.executable)
    run.add_argument("--config", help="Explicit analysis-config override for every queued request")
    run.add_argument("--bindir", default="bin")
    run.add_argument("--workdir")
    run.add_argument("--once", action="store_true")
    return parser


def _queue(args) -> RedisRunQueue:
    return RedisRunQueue(
        args.redis_url,
        args.redis_prefix,
        group=args.group,
        consumer=args.consumer,
        recovery_idle_ms=getattr(args, "recovery_idle_ms", 30_000),
    )


def _submit(args) -> int:
    queue = _queue(args)
    try:
        request = RunRequest.create(
            args.gamever,
            run_id=args.run_id,
            platforms=args.platforms,
            modules=args.modules,
            skill_filter=args.skill,
            agent=args.agent,
        )
        queue.submit(request)
        print(request.run_id)
        return 0
    finally:
        queue.close()


def _run(args) -> int:
    queue = _queue(args)
    scheduler = RedisProcessScheduler(
        queue,
        analyzer_script=args.analyzer_script,
        python_executable=args.python_executable,
        config_path=args.config,
        binary_dir=args.bindir,
        workdir=args.workdir,
    )
    try:
        if args.once:
            scheduler.run_once(args.poll_ms)
        else:
            scheduler.serve_forever(args.poll_ms)
    except KeyboardInterrupt:
        return 130
    finally:
        queue.close()
    return 0


def main(argv=None) -> int:
    load_dotenv()
    args = _build_parser().parse_args(argv)
    return _submit(args) if args.command == "submit" else _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
