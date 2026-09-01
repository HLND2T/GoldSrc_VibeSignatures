---
title: test 文件必须登记到测试分组
type: note
permalink: goldsrc-vibesignatures/notes/test-文件必须登记到测试分组
tags:
- ci
- testing
- tests
- workflow
---

# test 文件必须登记到测试分组

## Overview

`tests/run_test_suite.py` 用 `GROUP_FILES` 显式白名单把每个测试文件登记到分组（`unit` / `redis-integration` / `repository-contract` / `ida-integration`）。入口 `validate_membership()` 对比 `tests/` 下所有 `test_*.py`（排除 `test_support.py`），任何新文件未登记都会在**跑任何测试之前**抛 `RuntimeError` 并退出，导致所有调用 `run_test_suite.py` 的 CI job 全部失败（包括与该文件无关的 `redis-integration`）。

## Trigger

- 在 `tests/` 新增 `test_*.py` 文件后，未在 `GROUP_FILES` 登记。
- CI 报 `RuntimeError: Invalid test group membership: ... missing={'test_xxx.py'}`。
- 修改 `tests/run_test_suite.py` 的分组定义时。

## 根因 / 约束

- `GROUP_FILES` 是唯一的分组真相：`unittest discover(pattern=filename)` 只运行登记的文件。
- `validate_membership` 对每个 suite 命令无条件执行，无「只跑部分文件」的豁免路径。
- 直接用 `pytest tests/test_xxx.py` 本地跑测试会绕过该校验，导致本地全绿、CI 才暴露。

## 正确做法

1. 新增 `tests/test_*.py` 后，立即在 `tests/run_test_suite.py` 的 `GROUP_FILES["unit"]`（或对应分组）追加文件名。
2. 提交前用 CI 相同命令验证：`uv run python tests/run_test_suite.py unit -b --durations 30`。
3. 本地定向调试用 pytest 可以，但「全量通过」的结论必须以 `run_test_suite.py` 为准。

## Verification

- 无新增/删除测试文件时运行 `validate_membership` 应通过。
- 新增测试文件并登记后，`uv run python tests/run_test_suite.py unit -b` 全部通过且包含新文件用例。
- CI `test (ubuntu-latest)` / `redis-integration` 等所有调用 `run_test_suite.py` 的 job 均应绿。

## 适用范围

GoldSrc VibeSignatures 仓库及任何使用 `tests/run_test_suite.py` 白名单分组模型的仓库。
