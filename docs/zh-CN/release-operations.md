# Release 运维

`release-build.yml` 接受 immutable `version`、可选 `source_sha` 与默认开启的 `publish_release`。生产 source 必须可从
default branch 到达。`publish_release=false` 只用于不发布的 workflow verification，并要求 source 等于 dispatch commit。

## 信任与权限边界

- `preflight`、`warmup-idb`、`build-release-bundle`、`verify-release-bundle` 都只有 contents read 权限。
- self-hosted build 没有 PAT、push、tag 或 Release authority；`GSVIBE_BIN_TOKEN` 只读 private submodule。
- GitHub-hosted verifier 对照 exact source Git objects 校验封闭 bundle。
- `publish-release` 位于受保护的 `release` Environment，是唯一 `contents: write` job。
- Actions Artifact 名称绑定 version/source SHA/run ID/attempt，下载前还会检查 digest。

## 不可变版本状态

- 无 tag/Release：创建直接指向 source SHA 的 tag，再创建 draft Release；
- matching tag + draft：恢复原 build identity，已存在 asset 必须 size/hash 完全一致；
- published Release：全部 exact assets 一致则幂等成功，缺失或不同则失败；
- tag mismatch、Release without tag、不同 draft identity 或覆盖请求一律 fail closed；
- 内容变化必须使用新版本，禁止 `--clobber`、移动 tag 与内容型 republish。

Draft 是可恢复 staging 层。Publisher 只上传缺失 asset，绝不覆盖；随后重新读取 remote name/size/hash，完整 inventory
一致才转为 published。排障时保留 run URL、source/bin SHA、bundle manifest、checksums 与 draft URL。

## Binary-only accepted cache 维护

`PERSISTED_WORKSPACE/bin/<gamever>` 是可重建 binary/side-file cache，不是 release truth。Materialization 会忽略分析
YAML 和 IDA/BinSync state。在授权 runner 上逐 game version 清理 legacy persisted YAML：

```bash
uv run python release_workflow.py cleanup-legacy-accepted-yaml --repo-root <checkout> \
  --persisted-root <root> --gamever <tag> --cutover-id bin-artifacts-v1
```

命令先验证 binary-only materialization，再在 per-gamever lock 内把 exact inventory 备份到
`accepted-bin/legacy-yaml-backups/<cutover-id>/<gamever>`；只有 YAML inventory 未变化时才删除。Rename 或 partial
deletion 中断后，使用同一参数重跑；命令只会从 canonical matching backup 恢复。
