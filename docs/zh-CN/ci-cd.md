[返回 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 参考

## 持续集成

`ci.yaml` 运行 formatting、unit、repository-contract、全部 assigned suite、Redis integration，以及 Pages
test/lint/build/asset/E2E 检查。Repository contract 要求完整 formal `bin_artifacts` Git inventory，并禁止 tracked
`bin/**/*.yaml`、`gamesymbols/`、`gamedata/` 与 `release-manifests/` 输出。

## Source PR validation

`gamesymbol-pr-validation.yml` 只有 source route。可信 base tooling 从 base/head/merge Git tree 规划影响，覆盖 artifact
A/M/D/R/C ownership 与 downstream closure。重建只写 checkout 外临时 artifact root，强制 selected node 执行，再把
完整 inventory/bytes 与 merge Git blobs 比较。需要 self-hosted analysis 的 fork 会 fail closed；`pr-validate` 是聚合
required check。

Reusable `warmup-idb` producer 发布 exact selection；consumer 只 verify/restore，不 warm、不 save。IDB key 绑定
binary/runtime identity，并且有意不绑定 `bin_artifacts` 内容。

## Release workflow

Release DAG：

```text
preflight -> warmup-idb -> build-release-bundle -> verify-release-bundle -> publish-release
```

self-hosted read-only build 在 fresh root 强制重建全部分析 artifact、与 Git truth 比较、派生完整 release bundle，再上传
唯一 transport Artifact。GitHub-hosted verifier 校验 source ancestry、bin gitlink、artifact inventory、payload contract、
allowlist、canonical manifest 与 checksums。受保护 publisher 是 release workflow 中唯一 contents writer，并实现 immutable
tag/draft/asset 语义。不再存在 generated-output PR 或独立 promotion workflow。

## Pages deployment

`deploy-pages.yml` 由 published Release 触发，或通过显式 published tag 手动触发。它下载 Release snapshot/metadata
YAML，构建 content-addressed JSON，保留非权威、append-only 的 `pages-snapshots` 展示镜像，部署 Pages 并验证 CDN
bytes。本地/CI build 使用动态生成的最小 schema fixture；production 始终设置显式下载 asset 目录。
