# Release 运维

`release-build.yml` 接受 immutable `version`、可选 `source_sha`、默认开启的 `publish_release`，以及默认关闭的
`cleanup_legacy_yaml`，以及 `source_artifact_mode`（默认 `rebuild`，也可选 `tracked`）。生产 source 必须可从 default branch 到达。`publish_release=false` 只用于不发布的 workflow
verification，并要求 source 等于 dispatch commit。两种模式都会在 bundle 验证后生成 AI notes。
已发布版本跳过 AI，保留原正文并继续资产幂等检查，以便恢复失败的 Pages dispatch。

## 使用已跟踪产物的 build-free 发布

`source_artifact_mode=tracked` 跳过 full analysis 和重建产物比对，直接使用选定 source SHA 已提交的
`bin_artifacts`。它证明产物来自该提交，不证明产物可以重建。Warm-IDB 准备/恢复、runtime 证据、snapshot/JSON
生成、hosted verification、notes 和受保护的发布步骤仍然执行。

Trigger skill 在未指定构建路径时先询问，已经明确选择时直接沿用。脚本调用方式：

```powershell
uv run python .claude/skills/trigger-release-build/scripts/trigger_release_build.py <VERSION> --source-artifact-mode tracked
```

常规完整分析使用 `rebuild`，脚本默认值也为 `rebuild`，兼容已有调用。两种模式共用同一 workflow 和版本互斥。
脚本检查 immutable source、权限、版本及重复运行，完整 artifact 绑定由 CI 检查。本地未提交产物不会用于发布。

`release_bundle.py bind-tracked --repo-root <checkout> --source-sha <SHA> --output <binding.json>` 校验 HEAD、
配置及 artifact 清单、暂存区 identity、Git blob 原始字节，以及 artifact 规范和链接约束。
Bundle `build --source-artifact-mode tracked --tracked-binding <binding.json>` 将 canonical binding 证据写入包内。
Bundle `verify` 和 publisher `publish` 必须传入匹配的 `--source-artifact-mode tracked`，并独立重算绑定。
缺失、修改、额外、暂存或链接形式的 source input 漂移均阻断发布。

新 manifest 使用 schema 3，增加 `source_artifact_mode` 和 `tracked_artifact_binding_sha256`（rebuild 为 null）。
Schema 2 仅按 rebuild 兼容读取，公开压缩包内容格式保持不变。Draft 重试须保持 mode/source；切换模式不能覆盖
已有资产。Runner 验收使用 `publish_release=false`，source 等于 dispatch commit，检查两种模式的 job 结果及
verified bundle；该验收仍依赖已配置的 runner、warm-IDB 基础设施和 notes 端点。

## 信任与权限边界

- `preflight`、`warmup-idb`、`build-release-bundle`、`verify-release-bundle`、`release-notes` 都只有 contents read 权限。
- self-hosted build 没有 PAT、push、tag 或 Release authority；`GSVIBE_BIN_TOKEN` 只读 private submodule。
- GitHub-hosted verifier 对照 exact source Git objects 校验封闭 bundle。
- `publish-release` 位于受保护的 `release` Environment，是 `release-build.yml` 中唯一 `contents: write` job；
  Pages archive writer 是独立的非权威展示镜像。
- Actions Artifact 名称绑定 version/source SHA/run ID/attempt，下载前还会检查 digest。

## 不可变版本状态

- 无 tag/Release：创建直接指向 source SHA 的 tag，再创建 draft Release；
- matching tag + draft：恢复原 build identity，已存在 asset 必须 size/hash 完全一致；
- published Release：全部 exact assets 一致则幂等成功，缺失或不同则失败；
- Publisher 从分页 GraphQL Release inventory 按 exact tag 发现 Draft，再通过 `gh release view` 读取唯一匹配项；不依赖
  Actions `GITHUB_TOKEN` 下会对 Draft 返回 404 或空 inventory 的 REST endpoints；
- 同一 tag 存在多个 Release、tag mismatch、Release without tag、不同 draft identity 或覆盖请求一律 fail closed；
- 内容变化必须使用新版本，禁止 `--clobber`、移动 tag 与内容型 republish。

Draft 是可恢复 staging 层。Publisher 只上传缺失 asset，绝不覆盖；随后重新读取 remote name/size/hash，完整 inventory
一致才转为 published。排障时保留 run URL、source/bin SHA、bundle manifest、checksums、draft URL 与 Release ID。若同一
tag 已有重复 Draft，必须通过显式人工操作减少到唯一 matching Draft 后再重跑，Publisher 不会自行选择或删除。

## AI Release Notes

首次运行前，在现有 `release` GitHub Environment 配置：

| 类型 | 名称 | 值 |
| --- | --- | --- |
| Variable | `RELEASE_NOTES_PROVIDER` | 默认 `claude`，也支持 `codex` |
| Variable | `RELEASE_NOTES_MODEL` | 端点支持的精确模型名称，必填 |
| Secret | `RELEASE_NOTES_BASE_URL` | GitHub-hosted runner 可访问的 HTTPS API base URL，必填 |
| Secret | `RELEASE_NOTES_API_KEY` | API 凭证，必填 |

BASE_URL 不回退读取 Variable。Claude 需要支持 streaming 和 tool use 的 Anthropic-compatible 端点，通常填写服务根地址，
CLI 追加 `/v1/messages`。Codex 需要支持 streaming 和 function calls 的 Responses-compatible 端点，CLI 追加 `/responses`，
服务要求 `/v1` 时须包含在 base URL 中；只有 Chat Completions 的端点不适用。URL 不允许用户名密码、query 或 fragment，
TLS 证书须公开受信任。模型配置独立于二进制分析使用的 `GSVIBE_LLM_*`。

notes job 每次安装 `@anthropic-ai/claude-code@latest` 和 `@openai/codex@latest`，并打印实际版本以便排障。
使用 Node 22，运行于隔离的临时 home/work 目录，
环境变量采用 allowlist。API secrets 只注入生成步骤，AI CLI 不接收 GitHub/artifact 凭证。仅开放本地 `release_git` stdio MCP，
支持经过参数校验的 `log`、`show`、`diff`、`ls-tree`，revision 限于 source SHA 及祖先。不开放 Shell、编辑、任意 Git 参数、
外部 diff/textconv 或 remote transport，Git 子进程不继承 API 凭证。检出完整主仓库历史，不检出私有 `bin` 子模块。
notes 和 publisher 都使用现有 `release` Environment，已有 reviewer/ref 限制适用于两个 job，也适用于不发布验证的 notes job。
生成前的 Environment 审批不等于对生成正文的审核。

基线为最近发布、非 Draft、非 prerelease 且 tag 可解析为 source SHA 祖先的 Release，排除当前版本。没有基线时使用全部可达
历史并注明首次发布。证据包括提交消息、文件统计、过滤后的 diff（保留 `bin_artifacts` 和符号/配置变化），以及最近三个正式版本
的正文风格示例。初始上下文上限 96 KiB，每轮总证据 200 KiB；最多 32 次 Git 查询，每次最多 16 KiB、30 秒。二进制、第三方、
缓存和常见无关生成产物正文被排除。证据会发送到所配置的 API，仓库指令与历史正文视为不可信数据。

输出包含内容对应的 `## English`、`## 中文`，优先总结游戏版本支持、符号和签名新增/修复，再介绍重要分析工具、浏览器和工具链
变化。空白、格式错误、超过 120 KiB、包含凭证或保留 identity 标记的输出被拒绝。每轮最多 10 分钟，总计最多两轮；失败阻断
发布，不自动降级为提交摘要。不打印或上传原始 prompt、CLI 输出或凭证。结构校验不代表内容事实正确。

失败日志只记录固定诊断类别：例如 `cli_timeout`、`cli_exit=<退出码>`、`invalid_json`、`notes_language_sections`、
`missing_model_or_key`。CLI/模型返回错误时，`output_hint` 可包含白名单 HTTP 状态和认证、模型、参数或连接错误标记；
这些只是从不可信输出中识别的线索，不代表已验证的 HTTP 响应或根因。无法识别时显示 `unclassified`，不会回退打印原文。

只将 Markdown 上传至 `release-notes-<version>-<source_sha>-<run_id>-<attempt>` artifact，保留 7 天。publisher 下载前校验
同次 run 的名称和 digest。notes 不进入封闭 bundle 或资产 manifest。`release_publish.py publish --notes-file <path>` 在创建
未发布版本的 tag/Draft 之前要求有效 notes，并在正文末尾追加程序生成的 immutable identity。重试可更新 matching Draft 的 notes，
已有资产仍不可覆盖。公开前重新检查 tag、Release identity/state、正文与资产。workflow 运行时不要手动修改/发布同一个 Draft，
GitHub 不提供原子的 compare-and-publish 操作。

修复 provider 或配置故障后，在 artifact 有效期内 Re-run failed jobs；过期后用相同 version/source Re-run all jobs，matching
Draft 会恢复原 build identity。已发布版本不重新生成或更新正文。真实端点验收使用 `publish_release=false`，source 为 dispatch
commit，下载 notes artifact 检查结果；该运行仍会执行正常构建和校验流程。

确定性验证不需要 API 凭证：

```bash
uv run python -m unittest discover -s tests -p 'test_release*.py'
actionlint .github/workflows/release-build.yml
git diff --check
```

Linux 上将上述最新版 CLI 与 Node 22 放入 `PATH` 后，可运行
`RELEASE_CLI_SMOKE=1 uv run python -B -m unittest discover -s tests -p test_release_cli.py -v`。
该测试用模拟 API 和假 key 验证证据往返及写工具拒绝，不创建 Release、不调用付费 API，也不能替代 hosted-runner/真实端点验收。

## Binary-only accepted cache 维护

`PERSISTED_WORKSPACE/bin/<gamever>` 是可重建 binary/side-file cache，不是 release truth。Materialization 会忽略分析
YAML 和 IDA/BinSync state。一次性 cutover 应在 reviewed non-publishing run 中显式开启 `cleanup_legacy_yaml`。
Build job 仅在 release bundle 通过本地校验并上传 transport artifact 后、GitHub-hosted verifier 运行前执行 cleanup。
该输入默认关闭，并对所有 configured gamevers 使用固定 cutover identity `bin-artifacts-v1`。

如需人工恢复或在授权 runner 上定向重跑，可逐 game version 执行：

```bash
uv run python release_workflow.py cleanup-legacy-accepted-yaml --repo-root <checkout> \
  --persisted-root <root> --gamever <tag> --cutover-id bin-artifacts-v1
```

命令先验证 binary-only materialization，再在 per-gamever lock 内把 exact inventory 备份到
`accepted-bin/legacy-yaml-backups/<cutover-id>/<gamever>`；只有 YAML inventory 未变化时才删除。Rename 或 partial
deletion 中断后，使用同一参数重跑；命令只会从 canonical matching backup 恢复。

## Full analysis 并发 runbook

release build job 从受保护的 `win64` Environment 读取 `GSVIBE_ANALYSIS_MAX_CONCURRENCY` 与
`GSVIBE_ANALYSIS_MAX_MEMORY_MIB`。安全激活顺序：

1. 未配置（即 `1`）时合入：production 经两阶段 coordinator 保持串行。
2. 确保 `GSVIBE_ANALYSIS_MAX_MEMORY_MIB` 的 85% soft limit 能容纳实测 coordinator baseline 加一个 worker reservation（默认 2048 MiB，可通过 `GSVIBE_ANALYSIS_INITIAL_WORKER_RESERVATION_MIB` 调整），
   并在 concurrency `1` 运行中记录真实峰值。
3. 提升到 concurrency `2`，验证两个 verified MCP endpoint、内存低于预算，且产物经 `bin_artifact_contract.py`
   逐字节一致。
4. 回滚只需把 concurrency 改回 `1`；cache generation、selection 与 release schema 不受影响。hard memory limit 触发
   以结构化 reason 失败，不会在同一次 run 内降并发重试。

