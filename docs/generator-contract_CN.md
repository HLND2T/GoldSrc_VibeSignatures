# Gamedata generator contract

每个启用的 generator 位于 `gamedata-generators/<directory>/gamedata.py`，并声明：

```python
MODULE_NAME = "example"
GENERATOR_API_VERSION = 2
OUTPUT_PATHS = ("gamedata.txt",)


def update(symbol_store, output_dir, *, context):
    payload = symbol_store.require("engine", "example.windows.yaml")
    (output_dir / "gamedata.txt").write_text(str(payload), encoding="utf-8")
```

API v1 省略 `GENERATOR_API_VERSION` 和 `context` keyword。`GeneratorContext` 提供不可变的游戏 tag 与 snapshot
二进制元数据；`SymbolStore` 为只读接口，并对外返回副本。

所有输出必须是 `OUTPUT_PATHS` 声明的安全相对数据文件。runner 给每个 generator 独立目录，并拒绝缺失、额外、
链接或越界输出。generator 源码、配置、符号 candidate 或任一输出 byte 发生变化后，guard 都会失效。

generator 根目录不存在或为空是合法状态，此时生成带 hash 的空 inventory。只有 `gamedata_candidate.py guard`
成功且 game-symbol candidate 显式验证了匹配 session 后，才算完成 gamedata 步骤。
