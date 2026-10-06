---
title: Read-only Git tests compare repository content, not internal storage
type: note
permalink: goldsrc-vibesignatures/lessons/read-only-git-tests-compare-repository-content
tags:
- testing
- git
- release-notes
---

# Read-only Git tests compare repository content, not internal storage

## 触发信号

PR #339 的 Ubuntu CI 在 `ContextTests.test_symbol_artifacts_are_evidence_and_initial_context_is_read_only`
失败,unit/repository-contract 步骤成功,全量 suite 报一项失败。
[失败 job](https://github.com/HLND2T/GoldSrc_VibeSignatures/actions/runs/37449518842/job/112222395430)
使用 Git 2.55.0;前后文件快照差异包含 `.git/objects/maintenance.lock` 和对象存储。

## 根因 / 约束

测试通过 `root.rglob('*')` 逐字节比较整个临时仓库,把 `.git` 内部元数据也当成内容。
Git 的后台维护可以移除 lock、压缩 loose objects、打包 refs 或刷新 index 元数据,
而工作区字节、HEAD、引用目标和暂存状态均保持一致。这使测试依赖后台进程时序。
在测试拥有的临时仓库显式运行 `git gc --quiet`,可以确定性复现同种错误断言。

## 正确做法

- 文件快照覆盖工作区内的 tracked/untracked 文件,排除 `.git`。
- 用 Git 查询并比较 HEAD、`for-each-ref` 的引用目标和 porcelain status,
  保持对引用/暂存状态意外修改的检查。
- 临时 fixture 的 Git 命令使用 invocation-scoped `gc.auto=0`、`maintenance.auto=false`,
  防止 fixture 的 commit 启动后台维护与显式 GC 竞争。
- 在前后快照之间显式执行同步 GC,让存储格式变化成为回归场景。
  所有 `.git` 修改均交给 Git 命令,不由测试手工编辑内部文件。

## 验证方式与适用范围

修复前,显式 GC 场景触发原断言失败;修复后 release notes 的 19 项定向测试通过。
`uv run python tests/run_test_suite.py all -b --durations 30`:1428 tests / 125.098s,
exit 0,13 skips;`uv run python format_repo_files.py --check`:exit 0。
适用于检验只读 Git 查询及 context 生成的测试;工作区字节、HEAD、refs 和暂存状态仍须一致。
本次修复位于 `tests/test_release_notes.py` 的 fixture 和只读断言。
