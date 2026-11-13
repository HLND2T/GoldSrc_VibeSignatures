[返回 README](../../README_CN.md) | [English](../en/symbol-browser.md)

# 静态符号浏览器与 Pages

`pages/` 中的 React 应用浏览已发布的游戏符号快照，直接加载静态版本索引和 content-addressed 数据集，
无需连接后端或启动服务。可以按模块、平台、符号名和 artifact 搜索并查看详情，通过页头切换语言与颜色主题。

本地构建：

```bash
cd pages
npm ci
npm run build
npm run verify:gamesymbols
npm run preview
```

本地与 CI 构建默认生成最小 fixture；设置 `GSVIBE_GAMESYMBOLS_DIR` 可改用已下载的 Release 数据集目录。
生产部署下载 immutable published Release 的 `gamesymbols-*.7z`，将其中的原始数据字节放入 `pages/dist`。
浏览器在解析前验证数据集大小与 SHA-256。

GitHub Pages 部署静态 `pages/dist`。`pages-snapshots` 分支是已发布 Release 的只追加展示镜像，已有 digest
文件必须保持字节不变。部署与验证细节见 [Pages 开发说明](../../pages/README.md)。
