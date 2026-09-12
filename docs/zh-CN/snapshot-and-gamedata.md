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
dataset（schema 5，`<tag>.<sha256>.json`，含 per-binary `isBlob` 标志），`mark -step json` 后发布 snapshot/metadata，
最后在 `release_bundle.py` 中组装 index（schema 4）、打包唯一 all-in-one 7z，并构造封闭 bundle：

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

Writer 输出 schema 8，legacy reader 接受 schema 1–8。Schema 7 开始为每个 module/platform 记录必填布尔 `is_blob`：仅当原始
Windows 二进制是通过完整校验的 Metahook blob 时为 `true`（普通 PE/ELF 为 `false`；非法二进制直接让 snapshot
失败，而不是发布为 `false`）。JSON 生成器只接受 schema-8 snapshot，前端只接受 schema-5 dataset，没有旧
dataset 兼容模式。Restore/verify 拒绝 link、path escape、未声明或缺失 YAML、
非 canonical bytes 与 contract drift。

## 数值型 scalar

Schema 8 / analysis output contract 3 新增 `category: scalar`。产物仅包含 `scalar_name` 与 uint32
`scalar_value`。消费端按匹配的 binary identity 直接使用该值，不加 image base、不解引用为指针、不做运行时扫描。
Finder 独立核验当前二进制数据流，并要求 LLM 的语义映射结果与之相符。例如编译器可能把 frame stride
乘法优化为 LEA/SHL/SUB 链，而伪代码仍显示常量乘数；数值产物不应依赖是否存在单条 IMUL。
证据不支持或数值冲突时失败，不能回填其他版本值。JSON 输出 `kind: scalar` 并完整保留 payload，index 仍为 schema 4。

旧 snapshot 不得携带 scalar 字段。先显式恢复到独立兼容 artifact 目录，再分析缺少的当前产物，通过当前
candidate 流程重建 snapshot/dataset；直接修改 schema 数字不算迁移。历史归档字节保持不可变。

### Trusted scalar 契约的分阶段升级

PR 的 trusted planner 和 candidate builder 来自 base revision，因此必须先合入契约支持，再启用新符号。
前置兼容 PR 保留 snapshot 7 / analysis-output contract 2 默认值；本功能将默认值切换为 snapshot 8 / contract 3。
显式传入 `gamesymbol_candidate.py build -snapshot-schema-version 8` 同样选择 snapshot 8 / contract 3。
Builder 按选定契约校验 artifact、生成 metadata 并重新打开 candidate，拒绝不支持的版本。
普通 SymbolStore 仍严格要求当前 contract；只有显式指定受支持版本的调用方可以选择另一版本。

`category: scalar` 的 artifact 仅包含 `scalar_name` 和 uint32 `scalar_value`，直接使用数值，不加 image base、
不解引用。Snapshot 1–7 和 analysis-output contract 2 不得携带 scalar。
兼容代码已进入 main，PR workflow 向 trusted builder 显式请求格式 8。Profile 7 仍供不含 scalar 产物的
兼容调用方显式选择；它不迁移旧数据，也不放宽当前 export/UI 的版本要求。
