# CS2 Workflow PAT 权限模型移植计划

状态：仓库实现与本地验证完成；protected test/production smoke 受外部门禁阻塞

日期：2026-08-28（Asia/Singapore）

优先级：P0

GoldSrc 规划基线：`main@8b69640d55018f0a62cf7f65037c41defa5883a5`

CS2 参考树：`D:/CS2_VibeSignatures@2a5437854f4c6e1ec37b812649ea70de9959fc69`

失败样本：Release Build run `33156203943`、job `98799521184`、版本 `v20260828d`

CS2 参考 workflows：

- `.github/workflows/build-on-self-runner.yml`
- `.github/workflows/promote-release-after-output-merge.yml`
- `.github/workflows/validate-generated-output-pr.yml`

## 实施结果（2026-08-28）

仓库实现已原子迁移到 CS2 PAT 权限模型：

- `release-build.yml` 默认 `${{ github.token }}` 已收窄为 `actions: read`、`contents: read`、
  `pull-requests: read`；exact source checkout、耗时分析前 authentication/repository preflight、output branch push 与
  PR create 使用 `secrets.HLND2T_GH_TOKEN`；所有相关 `git`/`gh`/stage index 写入均逐条 fail-fast；
- output validation 与 merge-time promotion 的 workflow predicate 和 Python verifier 均接受
  `github-actions[bot]` 或 `OWNER`/`MEMBER`/`COLLABORATOR` author association，同时保留 same-repository、default
  base、branch、parent、path 与 hash contract；
- promotion 使用 `${{ github.token }}`，权限为 `contents: write`、`pull-requests: read`，tag 与每条 GitHub Release
  write command 均 fail-fast；
- `architecture-followup-migration.md`、中英文 release operations、CI/CD 与 requirements 文档已同步 PAT/default
  token/private-read-token 职责边界。

本地验证证据：

```text
actionlint <all 24 .github/workflows/*.yml files>                       passed
uv run python format_repo_files.py --check                             passed
uv run python -m unittest -v tests.test_release_workflow_guards        17 passed
uv run python tests/run_test_suite.py unit -b --durations 30           441 passed
uv run python tests/run_test_suite.py repository-contract -b --durations 30
                                                                        15 passed
git diff --check                                                        passed
```

外部只读核对结果：

- GoldSrc `win64` Environment 已列出 `HLND2T_GH_TOKEN`；未读取或输出 secret value；
- default branch 为 `main`，repository Actions default workflow permission 为 write，但本次 workflow 显式权限按上述
  最小边界声明；
- `main` 当前没有 branch protection，repository 也没有 ruleset，故尚不能提供 required `pr-validate`/protected test
  repository 事件矩阵证据；
- `PERSISTED_WORKSPACE` 只存在于 `win64` Environment secret，hosted Ubuntu `verify` job 未声明该 Environment，故
  当前引用会解析为空；即使改为 repository secret，该 job 仍会把 Windows self-hosted runner 产生的
  `PERSISTED_WORKSPACE/release-staging` 当作本地 filesystem 读取，且没有 artifact/shared mount transport。按第 7
  节要求，production promotion 验收保持 blocked，本次不静默扩大为 storage/topology 重构；
- 因上述门禁，未触发 production release build，也未执行 production smoke；不得把本地测试描述为完整 release
  事件链验收。

## 1. 计划决策

本计划以“严格对齐 CS2、最短路径修复”为准，采用同名静态 PAT secret：

```text
HLND2T_GH_TOKEN
```

不引入 GitHub App，不配置以下三项：

```text
HLND2T_RELEASE_APP_ID
HLND2T_RELEASE_APP_PRIVATE_KEY
HLND2T_RELEASE_APP_BOT_LOGIN
```

移植的权限边界为：

1. release build 的默认 `GITHUB_TOKEN` 保持只读；
2. exact source checkout、Git authentication、output branch push 和 PR create 使用 `secrets.HLND2T_GH_TOKEN`；
3. PAT 创建的 PR 作为普通 `pull_request` 事件触发 output `pr-validate`；
4. promotion workflow 单独取得 `contents: write`，使用 `${{ github.token }}` 推 tag 和发布 Release；
5. PAT 不进入普通 PR validation，不进入 fork workflow；
6. 所有 `git`/`gh` 写操作 fail-fast，首个失败后不再写后续状态。

本计划条件性替代 `docs/plans/architecture-followup-migration.md` 第 7.3 节“production output branch/PR 不使用个人 PAT”的凭据决策。实施时必须同步修改该冲突表述，避免两份计划定义相反的 production token 模型。

## 2. 当前故障

### 2.1 直接根因

GoldSrc `release-build.yml` 当前只声明：

```yaml
permissions:
  contents: read
```

失败 job 的实际 token 权限为：

```text
Contents: read
Metadata: read
```

但 `Create generated-output pull request` 使用 `${{ github.token }}` 执行：

```text
git push origin HEAD:refs/heads/gamesymbols/build/v20260828d
gh pr create ...
```

日志中的真实错误是：

```text
remote: Permission to HLND2T/GoldSrc_VibeSignatures.git denied to github-actions[bot].
fatal: unable to access ...: The requested URL returned error: 403
pull request create failed: GraphQL: Resource not accessible by integration (createPullRequest)
```

`write-pr-index --pr-number` 缺参只是 PR 创建失败后 `$prNumber` 为空造成的连带错误。

仓库级 Actions 设置当前为 `default_workflow_permissions=write`、`can_approve_pull_request_reviews=true`。故障来自 workflow 显式收窄 token，不是 repository UI 开关或 self-hosted runner 文件权限。

### 2.2 为什么不能只提升默认 `GITHUB_TOKEN`

把 build workflow 直接改成 `contents: write`、`pull-requests: write` 只能解决写权限，不保证 output PR 的后续事件链。

默认 `GITHUB_TOKEN` 创建的 PR/push 受 GitHub Actions 防递归规则限制，通常不会再次触发 `pull_request.opened` workflow。GoldSrc output validation 正依赖该事件，因此必须像 CS2 一样用 PAT 创建 PR。

### 2.3 Promotion 的后续权限缺口

GoldSrc `promote-release-after-output-merge.yml` 当前同样只有 `contents: read`，但后续会执行：

- `git push origin refs/tags/<version>`；
- `gh release create/upload/edit`。

若只修 build，output PR 合并后 promotion 会在 tag/Release 阶段再次遇到权限失败。

## 3. CS2 对齐目标

| 边界 | Token | Permissions/Scopes | 用途 |
| --- | --- | --- | --- |
| build 默认 token | `${{ github.token }}` | `actions: read`、`contents: read`、`pull-requests: read` | 默认只读能力 |
| exact source checkout | `${{ secrets.HLND2T_GH_TOKEN }}` | PAT repository read/write | 持久化 Git authentication，与 CS2 一致 |
| Bin/Git authentication preflight | `${{ secrets.HLND2T_GH_TOKEN }}` | PAT organization/repository access | `gh auth setup-git`、`gh api /orgs/HLND2T` |
| output branch/PR | `${{ secrets.HLND2T_GH_TOKEN }}` | Contents write、Pull requests write | `git push`、`gh pr create` |
| output PR validation | `${{ github.token }}` | `contents: read` | 只读验证，不接收 PAT |
| merge-time promotion | `${{ github.token }}` | `contents: write`、`pull-requests: read` | tag 和 GitHub Release |

核心不变量：

- workflow 顶层默认 token 不因 build 写入需求而升级；
- PAT 只注入受保护 `win64` Environment 的 release build job；
- output PR 的 author 必须是受信任 PAT account，head repository 必须是当前 repository；
- validation 继续只读并使用 trusted base tooling；
- promotion 是事件链终点，不依赖 `${{ github.token }}` 产生的新事件触发其他 required workflow；
- secret value 不写日志、artifact、manifest、stage、cache 或 Git config dump。

## 4. 范围与非目标

### 4.1 计划内

- `.github/workflows/release-build.yml` 的 PAT checkout、authentication、push/PR create 和 fail-fast；
- `.github/workflows/validate-generated-output-pr.yml` 的 PAT author trust 条件；
- `.github/workflows/promote-release-after-output-merge.yml` 的最小写权限、PAT author trust 条件和 fail-fast；
- GoldSrc `win64` Environment 增加 `HLND2T_GH_TOKEN`；
- 中英文 release operator 文档和冲突架构计划同步；
- protected test repository 与 production 事件链验证。

### 4.2 非目标

- 不引入 GitHub App 或 runtime token mint；
- 不修改 release manifest、staging、completion、provenance 或 archive schema；
- 不改变 output branch/version parser；
- 不改变 warm/cold IDB、IDA、LLM 或 Agent 行为；
- 不复制 CS2 的单 `GAMEVER`、BinSync、repository_dispatch 或 persisted-bin 逻辑；
- 不借本次权限修复重构 promotion job topology；
- 不自动 approve、merge、删除 output PR/branch/tag/Release；
- 不通过单元测试锁定 workflow YAML 文本、secret 内容或 GitHub UI 配置。

## 5. 外部前置配置

### 5.1 `win64` Environment secret

由 operator 在 `HLND2T/GoldSrc_VibeSignatures` 的 `win64` Environment 中增加：

```text
HLND2T_GH_TOKEN
```

当前 CS2 `win64` Environment 已配置该 secret，GoldSrc 尚未配置。优先复用 CS2 的现有 PAT；若该 token 尚未获得 GoldSrc repository access，扩展范围属于外部权限变更，必须由 owner 明确执行。

不得在计划、workflow、日志或交付说明中读取/输出 secret value。

### 5.2 PAT 权限与身份

PAT 至少必须满足：

- 可以访问 `HLND2T/GoldSrc_VibeSignatures`；
- repository contents read/write；
- pull requests read/write；
- organization SSO/authorization 状态有效；
- token owner 对 `HLND2T` 是 `OWNER`、`MEMBER` 或目标 repository `COLLABORATOR`；
- token 未过期、未吊销，并有明确轮换负责人。

若使用 fine-grained PAT，只授予目标 repository 的 `Contents: Read and write`、`Pull requests: Read and write`、`Metadata: Read`。若复用的是 classic PAT，记录其实际 scope 和适用 repository，但本次计划不要求为了改 token 类型而扩大范围。

### 5.3 Repository/ruleset

确认并记录：

- default branch 是受保护 `main`；
- output PR required check 是稳定名称 `pr-validate`；
- Actions 允许当前 workflow 正常读取 contents；
- PAT 创建的 PR 会走普通 branch protection/ruleset，不绕过 required checks；
- merge actor 是人工 reviewer/operator，不由本计划自动化。

## 6. 实施方案

### 6.1 Release build

修改 `.github/workflows/release-build.yml`，对齐 CS2：

1. 默认权限改为：

   ```yaml
   permissions:
     actions: read
     contents: read
     pull-requests: read
   ```

2. `build` job 继续使用受保护 `win64` Environment。
3. `Checkout exact source` 显式使用：

   ```yaml
   token: ${{ secrets.HLND2T_GH_TOKEN }}
   ```

   不再回退到只读 `${{ github.token }}` 执行 release publication。
4. 在耗时分析前增加或复用 PAT authentication preflight：

   ```text
   gh auth setup-git
   gh api /orgs/HLND2T --jq .login
   ```

   API 必须返回 `HLND2T`；否则以明确的 token invalid/expired/org access 错误提前失败。
5. `Create generated-output pull request` 使用：

   ```yaml
   env:
     GH_TOKEN: ${{ secrets.HLND2T_GH_TOKEN }}
   ```

6. push 前再次执行 `gh auth setup-git`，避免 git remote 继续使用默认 Actions credential。
7. 保持现有 output branch、commit、manifest 与 PR title/body contract。
8. 每条 native write command 后检查 `$LASTEXITCODE`：
   - `git commit`；
   - `git push`；
   - `gh pr create`；
   - `gh pr view`/PR number resolve；
   - `write-pr-index`。
9. `git push` 或 `gh pr create` 失败后立即终止，不再以空 `$prNumber` 调用 `write-pr-index`。

### 6.2 Output PR validation

修改 `.github/workflows/validate-generated-output-pr.yml`，对齐 CS2 的 PAT actor 模型：

```yaml
if: >
  (github.event.pull_request.user.login == 'github-actions[bot]' ||
   github.event.pull_request.author_association == 'OWNER' ||
   github.event.pull_request.author_association == 'MEMBER' ||
   github.event.pull_request.author_association == 'COLLABORATOR') &&
  github.event.pull_request.head.repo.full_name == github.repository &&
  startsWith(github.event.pull_request.head.ref, 'gamesymbols/build/')
```

同时保持：

- `pull_request` types 为 opened/synchronize/reopened/ready_for_review；
- `permissions: contents: read`；
- exact output head checkout；
- trusted validation tooling 从 PR base checkout；
- stable required-check job name `pr-validate`；
- path、manifest、source parent、hash 和 repository contracts 不放宽。

### 6.3 Merge-time promotion

修改 `.github/workflows/promote-release-after-output-merge.yml`，对齐 CS2：

1. 继续使用普通 `pull_request: closed`。
2. 权限改为：

   ```yaml
   permissions:
     contents: write
     pull-requests: read
   ```

3. resolve/promote actor 条件与 validation 一致，接受：
   - `github-actions[bot]`；或
   - `OWNER`；或
   - `MEMBER`；或
   - `COLLABORATOR`。
4. 继续要求 merged true、same head repository、default base 和严格 output branch prefix。
5. `GH_TOKEN` 保持 `${{ github.token }}`。
6. tag push 和每条 `gh release create/upload/edit` 后检查 `$LASTEXITCODE`，失败立即停止。
7. promotion 后不要求 tag/release 事件触发新的 required workflow，因此默认 token 的防递归行为不构成缺口。

### 6.4 文档同步

实施 PR 同步更新：

- `docs/plans/architecture-followup-migration.md` 第 7.3 节，将 GitHub App-only 决策改为本计划选定的 CS2 PAT 模型；
- `docs/en/release-operations.md`；
- `docs/zh-CN/release-operations.md`。

文档必须区分：

- 默认 `${{ github.token }}`；
- PAT secret `${{ secrets.HLND2T_GH_TOKEN }}`；
- private submodule/read token 若仍存在时的职责；
- workflow permissions 与 PAT repository scopes。

## 7. 已知的非权限风险

当前 GoldSrc promotion 有 hosted `verify` job，并向它传递 `${{ secrets.PERSISTED_WORKSPACE }}`。该路径是否能从 hosted Ubuntu 访问不属于本次 PAT 权限修复。

实施时必须做一次只读核对：

- `PERSISTED_WORKSPACE` 的有效 secret source；
- hosted runner 是否实际需要访问 Windows persisted stage；
- 现有 `verify-promotion` 是否会读取该路径。

若确认不可访问，停止 production promotion 验收并单独处理 storage/topology 缺口；不得在本次最短路径计划中静默扩大为 release architecture 重构，也不得在没有证据时声称完整 release 链路已修复。

## 8. 测试与验证

本迁移是 workflow authority 和事件链行为变更。验证以真实 GitHub 事件为主，不以测试锁定 YAML 文本。

### 8.1 静态与仓库验证

```text
actionlint .github/workflows/*.yml
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
git diff --check
```

若仓库已有正式 release integration suite，再运行其当前入口；不得虚构 suite 名称或结果。

### 8.2 PAT preflight

在不输出 token 的前提下验证：

1. `secrets.HLND2T_GH_TOKEN` 在 GoldSrc `win64` Environment 中可用；
2. `gh api /orgs/HLND2T --jq .login` 返回 `HLND2T`；
3. token 可以读取目标 repository；
4. token owner association 是 OWNER/MEMBER/COLLABORATOR；
5. 不通过临时 push 或创建测试 PR探测权限，远程写能力在 protected test run 中验证。

### 8.3 Protected test repository 事件矩阵

至少验证：

1. build job 初始化日志中默认 token 保持 read-only；
2. PAT checkout 和 `gh auth setup-git` 成功；
3. PAT 成功 push exact output branch；
4. PAT 成功创建 output PR；
5. PR author/association 命中受信任条件；
6. `pull_request.opened` 自动触发唯一 `Validate Generated Output PR`；
7. `pr-validate` 成功并成为 required check；
8. fork、错误 branch、非可信 author/association 不能通过；
9. PR 未合并关闭时不创建 tag/Release；
10. 合并可信 PR 后 promotion 运行；
11. promotion token 显示 `Contents: write`、`PullRequests: read`；
12. tag、Release create/upload/edit 成功，下载 assets 后 size/SHA-256 一致；
13. PAT invalid/expired/SSO invalid 时在耗时分析前 fail-fast；
14. push/PR create 失败时不再出现空 PR number 的连带状态写入；
15. logs/artifacts 不出现 PAT value。

### 8.4 Production smoke

protected test repository 验证通过后：

1. 合并 workflow 和文档；
2. 从包含修复的新 `origin/main` SHA触发新 release build；
3. 不 rerun `33156203943`，因为 rerun 会继续使用旧 workflow/SHA；
4. 依次保存 build run、output PR、`pr-validate`、merge、promotion、tag、Release 和 asset hash 证据；
5. 使用仓库 `.claude/skills/trigger-release-build` 的受控脚本触发，不临时拼接 `gh workflow run`。

## 9. 实施顺序

1. operator 把 CS2 使用的 `HLND2T_GH_TOKEN` 配置到 GoldSrc `win64` Environment；
2. 确认 PAT repository access、scope、SSO 和 owner association；
3. 原子修改 release build 的 PAT checkout/auth/push/PR 和 fail-fast；
4. 同一提交修改 validation 与 promotion 的 trusted PAT actor 条件；
5. 同一提交补齐 promotion permissions；
6. 同步架构计划和中英文 operator docs；
7. 运行静态、unit、repository-contract 与已有 release integration 验证；
8. 完成 protected test repository 事件矩阵；
9. 从新 main SHA执行 production smoke；
10. 保存 run/PR/check/merge/tag/Release/hash 与 PAT scope/rotation 证据。

token wiring、actor 条件和 promotion permission 必须原子交付。禁止先切 PAT 创建 PR、后补 validation/promotion 条件，否则会产生无法通过 required check 或无法晋级的悬挂 PR。

## 10. 风险与缓解

### 风险：PAT 权限过宽或绑定个人生命周期

缓解：优先复用现有 CS2 token；记录 owner、scope、expiration、SSO、rotation 和 revocation owner。能使用 fine-grained PAT 时限制到目标 repositories；本次不为 token 类型迁移扩大实现范围。

### 风险：checkout 后 Git push 仍使用默认 token

缓解：checkout 显式传 `HLND2T_GH_TOKEN`，push 前再次执行 `gh auth setup-git`，并在日志中只输出 actor/repository、不输出 credential。

### 风险：PAT PR author 被 workflow 跳过

缓解：validation/promotion 原子迁移 CS2 的 OWNER/MEMBER/COLLABORATOR 条件，并保持 same-repository/branch contracts。

### 风险：PAT 失效导致长构建末尾才失败

缓解：在耗时分析前执行 organization/repository read preflight；最终写操作仍逐条检查退出码。

### 风险：默认 token promotion 不触发后续 workflow

缓解：当前 promotion 是 release 事件链终点。未来新增 tag/release 下游 workflow 时必须重新评估 token source。

## 11. 回滚

- token 异常时停止新的 release dispatch，并由 operator从 GoldSrc `win64` Environment 移除/轮换 `HLND2T_GH_TOKEN`；
- 回滚 workflow commit不会自动删除 branch、PR、tag、Release 或 private stage；先按 exact identity 只读盘点；
- 未合并 output PR 关闭后不得 promotion；删除 branch 需另行确认；
- 已写 `PROMOTION_STARTED` 的 build 不得换 build ID绕过恢复规则；
- 不通过删除已创建 tag/Release 来掩盖部分 promotion，先执行 reconcile 和 hash 核对。

## 12. 验收标准

- GoldSrc `win64` Environment 使用与 CS2 同名的 `HLND2T_GH_TOKEN`；
- 不存在 `HLND2T_RELEASE_APP_*` 配置或 runtime App token mint；
- release build 默认 `GITHUB_TOKEN` 保持只读；
- checkout、Git authentication、output branch push 和 PR create 使用 PAT；
- output PR 创建后自动触发唯一 `pr-validate`；
- validation/promotion 接受可信 OWNER/MEMBER/COLLABORATOR，同时拒绝 fork、错误 branch 和非可信 actor；
- promotion 拥有 `contents: write`、`pull-requests: read`，可以完成 tag 和 GitHub Release；
- git/gh 写失败后不产生空 PR number 连带错误或伪完成状态；
- 架构计划和中英文 operator docs 与 PAT 决策一致；
- protected test repository 和 production smoke 均有真实证据；
- 不 rerun旧失败 run，修复验证来自包含新 workflow 的 immutable main SHA。
