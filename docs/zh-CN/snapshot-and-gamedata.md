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
byte comparison。随后每个 gamever 派生 snapshot、metadata，用 `gamesymbols_json.py` 从它们确定性派生浏览器 JSON
dataset（schema 3，`<tag>.<sha256>.json`），`mark -step json` 后发布 snapshot/metadata，最后在 `release_bundle.py`
中组装 index（schema 4）、打包唯一 all-in-one 7z，并构造封闭 bundle：

- `gamesymbols/<tag>.yaml` 与 `<tag>.metadata.yaml`（canonical snapshot/metadata，用于再派生校验）；
- `gamesymbols-json/<tag>.<sha256>.json` 与 `gamesymbols-json/index.json`；
- `archives/gamesymbols-<version>.7z` —— **唯一发布载荷**，内含 `gamesymbols/index.json` 与全部 dataset；
- `evidence/ida-runtime.json`、`evidence/cache-selection.json`；
- `release-manifest-<version>.json` 与 `SHA256SUMS-<version>.txt`。

GitHub Release 只发布 3 个资产：`gamesymbols-<version>.7z`、`release-manifest-<version>.json`、
`SHA256SUMS-<version>.txt`。GitHub-hosted verifier 会检查 exact source SHA/bin gitlink、repository artifact
inventory、snapshot/metadata contract、**独立再派生 JSON 并与 bundle 内 `gamesymbols-json/` 逐字节对比**、7z 内容、
bundle allowlist、canonical manifest 与全部 checksum。只有这份 exact verified bundle 能进入受保护 publisher。
GitHub Release assets 是公开发布层；Actions Artifact 只负责传输。

gamedata 生成不再属于 release 流水线；snapshot candidate 的 gamedata 一致性 gate 由
`gamesymbol-pr-validation.yml`（`mark -step gamedata`）与 `update_gamedata.py` 承担。

## Restore 与验证

Snapshot restore 只是显式 compatibility/migration 操作。Release 不再发布 snapshot YAML，必须提供本地 candidate
build 生成的 snapshot（`gamesymbol_candidate.py build` 输出）；verify 只读、restore 只写显式 artifact root：

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
