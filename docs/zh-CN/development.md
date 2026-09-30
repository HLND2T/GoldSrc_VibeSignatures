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

其余 source 权限套件显式覆盖仓库结构与 Redis：

```bash
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py redis-integration -b --durations 30
```

完成前运行全部 source-compatible 指定测试：

```bash
uv run python tests/run_test_suite.py all -b --durations 30
```

`all` 是 unit、Redis integration、repository contract 与 IDA integration group 的声明式不重复并集。Release bundle
与 publisher contract 属于普通 unit test；真实 GitHub publication 与商业 IDA evidence 仍是独立运维门禁。

只有在 `RUN_IDA_INTEGRATION=1` 且 `idalib` 环境已激活时才运行商业 IDA 集成测试；跳过不代表真实 IDA 分析通过。

## 静态 LLM 声明

拥有 LLM specs 的 preprocessor 必须只有一处无条件模块顶层 `LLM_DECOMPILE = ...`。
普通声明使用字面量 `list[dict]`；不同运行时分支需要不同 reference 或 policy 时，使用字面量
`dict[str, list[dict]]`，每个分支独立按运行时共享的纯规则校验。禁止变量引用、f-string、推导式、
函数调用、字典展开、重复键、覆盖声明及原地修改。路径占位符仅允许 `{gamever}`、`{platform}`、
`{module_name}`、`{module}`。

将声明或选中的分支直接作为 `llm_decompile_specs` 传入。需要筛选目标、补充当前二进制验证得到的标量值
或指令规则时，从 `llm_spec` 导入 `select_llm_specs`：

```python
specs = select_llm_specs(
    LLM_DECOMPILE,
    branch=selected_branch,
    symbols=verified_symbols,
    expected_values=verified_values,
)
```

该函数复制所选 specs，只允许补充 `expected_value`、`instruction_rules`。symbol、prompt、reference 和
policy 始终来自声明。转发 helper 使用仅限关键字的 `llm_decompile_specs` 参数；实际分析时仍可读取上游 artifact。

现有 repository-contract 套件审计全部 preprocessor 源码。AST 校验器支持直接选择、作用域内别名、字面量
kwargs 字典及共享选择函数；任意 specs 工厂、动态 kwargs、修改声明及反射式 Python 数据流不属于支持的编写形式。
扫描不会导入或执行 preprocessor。导入依赖覆盖 Git tree 中存在的包初始化文件与 `from package import helper`
子模块，包括别名、相对导入和 namespace package；普通属性导入不会产生不存在的子模块依赖。

规划器收集所有分支资源的并集，因此 reference 变化可能保守地多触发其他运行时分支。
当前版本 → family → default 的 reference 回退保持不变。历史树中不支持的声明仍可建立源码 ownership，
但任何 reference/prompt 新增、修改、删除或重命名都会保守触发这些声明的消费者，并报告源码和节点数。
当前树必须通过严格声明审计，不能依赖历史兼容回退；orphan reference 仍然只输出 warning。

CI 继续使用 trusted base 工具。依赖新的编写形式前，应先让 scanner 支持进入 base。本次迁移输出的普通字面量
资源路径也能被旧扫描器读取，严格审计通过现有测试入口执行。重跑旧 workflow 不会自动升级其 planner。
