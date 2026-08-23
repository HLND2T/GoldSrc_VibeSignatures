[返回 README](../../README_CN.md) | [English](../en/snapshot-and-gamedata.md)

# Snapshot、gamedata 与发布

单个 symbol 的 YAML 保持被 `bin/<GAMEVER>/<module>/` 忽略。每个已发布版本都有一对 Git-tracked canonical
文件：`gamesymbols/<GAMEVER>.yaml` 保存分析 lockfile，`gamesymbols/<GAMEVER>.metadata.yaml` 冻结展示 alias
及其解析后的 module/platform/artifact owner。

## 不可变 candidate 事务

顶层分析事务成功后，立即构建一个 candidate。两个下游消费者都读取同一个不可变 candidate；只有 gamedata guard
通过后，发布才会复制其原始字节：

```bash
CANDIDATE_DIR="$(mktemp -d)"
CANDIDATE_SNAPSHOT="$CANDIDATE_DIR/cstrike-10210.yaml"
CANDIDATE_METADATA="$CANDIDATE_DIR/cstrike-10210.metadata.yaml"
CANDIDATE_SESSION="$CANDIDATE_DIR/session.json"
GAMEDATA_ROOT="$CANDIDATE_DIR/gamedata-candidate"
GAMEDATA_SESSION="$CANDIDATE_DIR/gamedata.session.json"

uv run python gamesymbol_candidate.py build -gamever cstrike-10210 -bindir bin -output "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION"
uv run python gamedata_candidate.py build -gamever cstrike-10210 -build-id local-1 -snapshot "$CANDIDATE_SNAPSHOT" -configyaml configs/cstrike-10210.yaml -candidate-root "$GAMEDATA_ROOT" -session "$GAMEDATA_SESSION"
uv run python gamedata_candidate.py guard -session "$GAMEDATA_SESSION"
uv run python gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step gamedata -gamedata-session "$GAMEDATA_SESSION"
uv run python gamesymbol_candidate.py publish -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -destination gamesymbols/cstrike-10210.yaml
uv run python gamedata_candidate.py publish -session "$GAMEDATA_SESSION" -outputdir gamedata/cstrike-10210
uv run python gamedata_candidate.py stage -session "$GAMEDATA_SESSION" -repo-root .
```

注意：

- `gamesymbol_candidate.py mark -step gamedata` 需要 `-gamedata-session`，其 gamever 与 candidate SHA-256 必须
  与该 symbol candidate 匹配。
- `gamedata_candidate.py publish -outputdir` 必须以精确 tag 结尾。发布是原子替换。
- candidate build 同时生成 `$CANDIDATE_METADATA`。session 绑定两份文件的精确路径、hash、文件系统 identity，
  以及 metadata 对 snapshot SHA-256 的绑定。
- 本地 pair 发布使用恢复 journal 与固定替换顺序；任何中间错配都会被 verifier 拒绝。对外原子边界是 Git
  commit/tree。
- 即使没有 generator 产生 payload，每个 gamedata 目录也包含 canonical `gamedata-manifest.json`。它绑定
  snapshot、config、generator contract 与排除 manifest 自身的 payload inventory。
- `stage` 先 guard candidate，再构造并验证临时 Git tree，最后只对 candidate manifest 中的精确路径执行
  `git add -f -- <exact-path>`。仓库继续忽略 `gamedata/*/`，禁止宽泛 glob staging。
- generator 根目录不存在或为空会产生带 hash 的空 inventory，只要 `guard` 成功仍可满足 gamedata 步骤。

可以独立生成或验证 tracked companion：

```bash
uv run python gamesymbol_metadata.py generate -snapshot gamesymbols/hl-10210.yaml -configyaml configs/hl-10210.yaml -gamever hl-10210 -metadata gamesymbols/hl-10210.metadata.yaml
uv run python gamesymbol_metadata.py verify -snapshot gamesymbols/hl-10210.yaml -configyaml configs/hl-10210.yaml -gamever hl-10210 -metadata gamesymbols/hl-10210.metadata.yaml
```

Pages 不再读取 live config alias。companion 缺失、非 canonical、hash 不匹配或 owner 不匹配都会使构建失败。

## 直接生成 gamedata

不使用完整 candidate 事务时，可直接把 canonical symbol snapshot 转换成版本化 gamedata：

```bash
uv run python update_gamedata.py -gamever cstrike-10210 -snapshot gamesymbols/cstrike-10210.yaml -modulesdir gamedata-generators -outputdir gamedata/cstrike-10210
```

## 恢复与验证 snapshot

恢复干净的分析基线，或在不动 tracked snapshot 的前提下验证当前工作区：

```bash
uv run python gamesymbol_snapshot.py restore -gamever cstrike-10210
uv run python gamesymbol_snapshot.py restore -gamever cstrike-10210 -replace
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10210
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10210
```

默认 restore 会创建缺失的 YAML，并拒绝覆盖语义不同的文件。`-replace` 只删除 `bin/<GAMEVER>/` 下的 YAML，
保留二进制与 IDA 数据库，再重建 snapshot 内容。

writer 输出 schema 6（config digest v2）、canonical 文件载荷与不依赖路径的二进制 hash metadata；reader 兼容
schema 1–6，schema 5 仍严格读取其必需的旧 binary `path`。restore / verify 拒绝链接、路径逃逸、未声明
YAML、缺失必需 YAML、非 canonical bytes 与 contract drift。

`check-contract` 是只读信任探针：退出 `0` 表示可信，退出 `3` 上报机器可读的不可信原因，调用、配置或操作错误
仍是硬失败。

## 范围：无 C++ layout 验证

与 CS2 项目不同，GoldSrc VibeSignatures 不会针对源 header 运行 C++ layout 验证——没有 `run_cpp_tests.py`
或 HL2SDK checkout。发布前唯一的 downstream guard 是 gamedata 步骤。
