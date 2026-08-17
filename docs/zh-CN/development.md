[返回 README](../../README_CN.md) | [English](../en/development.md)

# 开发检查

## 格式化

本仓库使用 `ruff format` 格式化 Git-tracked 的 `*.py` 文件，使用 `yamlfix` 格式化 Git-tracked 的 `*.yaml` 文件。

提交前先在本地格式化：

```bash
uv run python format_repo_files.py
```

运行与 GitHub Actions 相同的格式化门禁：

```bash
uv run python format_repo_files.py --check
```

formatter 只处理 `git ls-files --cached -- '*.py' '*.yaml'` 返回的文件，因此被忽略的文件与未跟踪的临时文件会被跳过。

## 测试

本地编辑-测试循环中使用快速隔离套件：

```bash
uv run python tests/run_test_suite.py unit -b --durations 30
```

其余主套件显式覆盖仓库状态与 Redis：

```bash
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
```

完成前运行全部指定测试：

```bash
uv run python tests/run_test_suite.py all -b --durations 30
```

只有在 `RUN_IDA_INTEGRATION=1` 且 `idalib` 环境已激活时才运行商业 IDA 集成测试；跳过不代表真实 IDA 分析通过。
