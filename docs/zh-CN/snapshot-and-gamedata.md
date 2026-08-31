[返回 README](../../README_CN.md) | [English](../en/snapshot-and-gamedata.md)

# Snapshot、gamedata 与发布

单 symbol 分析 YAML 只在 `bin_artifacts/<GAMEVER>/<module>/` 由 Git 托管。`bin/` 仅保存二进制与可重建的 IDA
状态，不是 artifact truth。`gamesymbols/`、`gamedata/` 与 release manifest 都是 release 派生输出，不再版本化入库。

## 不可变 candidate 事务

Candidate 必须写入显式 staging。Snapshot 从 `bin/` 读取二进制 metadata，从 `bin_artifacts/` 读取 symbol YAML；
gamedata 必须由同一 immutable candidate 生成并完成 mark：

```bash
CANDIDATE_DIR="$(mktemp -d)"
uv run python gamesymbol_candidate.py build -gamever cstrike-10210 -bindir bin \
  -artifactdir bin_artifacts -output "$CANDIDATE_DIR/cstrike-10210.yaml" \
  -session "$CANDIDATE_DIR/symbol-session.json"
uv run python gamedata_candidate.py build -gamever cstrike-10210 -build-id local-1 \
  -snapshot "$CANDIDATE_DIR/cstrike-10210.yaml" -configyaml configs/cstrike-10210.yaml \
  -candidate-root "$CANDIDATE_DIR/gamedata" -session "$CANDIDATE_DIR/gamedata-session.json"
uv run python gamesymbol_candidate.py mark -candidate "$CANDIDATE_DIR/cstrike-10210.yaml" \
  -session "$CANDIDATE_DIR/symbol-session.json" -step gamedata \
  -gamedata-session "$CANDIDATE_DIR/gamedata-session.json"
```

Candidate session 绑定 snapshot/metadata 字节、文件系统 identity、config 与 matching gamedata session。即使 generator
inventory 为空，gamedata 也有排除自身的 canonical manifest。本地 `publish` 只把已验证字节复制到调用方显式 staging；
正常开发与 PR validation 不写 repository-root `gamesymbols/` 或 `gamedata/`。

## Release bundle

`release-build.yml` 在 checkout 外的 fresh root 强制重建全部 configured artifact，并与 Git `bin_artifacts` 做 exact
byte comparison。随后派生 snapshot、metadata、gamedata 和 archive，并构造封闭 bundle：

- `gamesymbols/<tag>.yaml` 与 `<tag>.metadata.yaml`；
- `gamedata/<tag>/**`；
- `archives/gamedata-<tag>.7z`，包含 config、`bin_artifacts`、snapshot、gamedata 与兼容二进制；
- binary-only `archives/gamebin-<tag>.7z`；
- `release-manifest-<version>.json` 与 `SHA256SUMS-<version>.txt`。

GitHub-hosted verifier 会检查 exact source SHA/bin gitlink、repository artifact inventory、
snapshot/metadata/gamedata contract、bundle allowlist、canonical manifest 与全部 checksum。只有这份 exact verified
bundle 能进入受保护 publisher。GitHub Release assets 是公开发布层；Actions Artifact 只负责传输。

## Restore 与验证

Snapshot restore 只是显式 compatibility/migration 操作。必须提供从 published Release 下载的 snapshot；verify 只读、
restore 只写显式 artifact root：

```bash
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py restore-legacy -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir <compatibility-artifact-root>
```

Writer 输出 schema 6，reader 接受 schema 1–6。Restore/verify 拒绝 link、path escape、未声明或缺失 YAML、
非 canonical bytes 与 contract drift。
