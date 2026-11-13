---
title: static-symbol-explorer-and-pages
type: architecture
permalink: goldsrc-vibesignatures/static-symbol-explorer-and-pages
tags:
- pages
- symbols
- analysis
---

# Static Symbol Explorer and Pages

## Overview

Issue #414 removes the entire real-time process-reporting system: Reporter backends and event protocol, Redis queue scheduler and status readers, Process API/SSE, and the dashboard run/graph/task pages. There is no compatibility backend or service startup step. Ordinary analyzer logs and preprocessor/LLM diagnostics remain.

## Analysis execution and batch results

The validated analysis DAG remains the planning authority. The process-only graph projection is removed. `analyze()` can fill a caller-provided `node_results` dictionary directly from execution; it no longer accepts a reporter or reporting run identity. Successful, skipped, failed and lifecycle-aborted nodes are recorded as final results; unfinished nodes become `aborted/not_executed` on exit without overwriting completed results.

Batch workers keep the existing request/result JSON schema, work-item run identities, summary counters, memory admission and process ownership. They no longer infer final results from monitoring events. Agent `run_skill()` retains its boolean return and can fill `failure_detail` with final failure diagnostics; it does not publish attempt-progress callbacks.

## Static application

The React application in `pages/` opens the Symbol Explorer directly. It loads the static version index and content-addressed symbol datasets, verifies size and SHA-256, and supports search, details, language selection and persistent color themes. No API connection configuration, health polling or SSE is required. React Query, Ant Design, dayjs, i18n and theme code remain shared application dependencies.

GitHub Pages publishes only `pages/dist`. Production relays immutable Release-derived dataset bytes. `pages-snapshots` remains an append-only presentation mirror, never source or release truth. Existing publication, archive and deployed-byte verification stay in place. See [[Immutable alias metadata companion]] and [[Release bundle publication and recovery]].

## Validation

Analyzer and batch regressions cover final results, failure and abort handling, summaries, exits and MCP lifecycle ownership. The test-group registry contains unit, repository-contract and optional ida-integration groups. Pages retains test/lint/build/asset/E2E checks, including fresh visits without progress-service requests. Commercial IDA integration remains a separate gate; skipped tests do not prove real analysis passed.

## Issue #414 verification (2026-11-13)

- Windows `tests/run_test_suite.py all -b --durations 30`: 1582 tests, OK, 13 skips (POSIX/Linux-only and opt-in CLI/real-IDA gates). Real IDA integration was not enabled.
- Independent unit gate: 1562 tests, OK, 12 skips before the last four regression tests; the final all suite includes those additions. Independent repository-contract gate: 15 tests, OK.
- Pages: 34 tests, lint, production build, static asset verification and 3 Chromium E2E tests passed. E2E covers fresh visits without progress API requests, static symbol search/details, languages and persistent themes.
- Locked environment synchronization, repository formatting, changed-code Pyflakes and diff whitespace checks passed. The npm lockfile removes dependencies without adding packages or changing retained package versions.
