# 🚀 GhostTrack-CN v1.2.0 — 5 大新功能 / Big Feature Release

性能 + UX 大幅升级。新增 **5 大功能**：扫描进度条、模式筛选、Markdown 报告、查询历史、批量域名查询。

## ✨ 主打新功能

### 1. 🚀 扫描提速 3-15 倍

```bash
gt user akxan --quick                    # ~20 秒（vs 默认 ~45 秒）
gt user akxan --category code            # ~3 秒（仅 54 平台）
gt user akxan --category chinese,spanish # ~6 秒（98 平台）
gt user akxan --workers 200 --timeout 3  # 极速：~10 秒
```

### 2. 🎬 实时进度条
```
[████████████░░░░░░░░░░░░░░░░░░] 1234/2020 (61.0%) 已命中: 42
```

### 3. 📝 Markdown 报告导出
```bash
gt user akxan --quick --save report.md   # 直接生成可分享的 markdown
```

### 4. 📚 查询历史
```bash
gt history                               # 查看最近 20 次
gt history --limit 100 --search akxan    # 搜索过滤
```

### 5. 🌐 批量 MX / WHOIS
```bash
gt mx gmail.com outlook.com yahoo.com    # 一次查 3 个
gt whois example.com github.com gitlab.com
```

## 🔞 新增 `adult` 类别（42 平台）

不再过滤 NSFW —— OnlyFans / Fansly / FetLife / Chaturbate / Stripchat / ManyVids / PornHub Community / Badoo / Tagged / PlentyOfFish 等。

可独立查询：
```bash
gt user akxan --category adult           # 只扫成人/约会平台
```

## 🎯 命中可信度排序

每个类别内按可信度排序（★★★ → ★★ → ★），真实用户更可能落在前列。

## 📊 当前规模

- **2032 平台**（+12，含 42 adult）
- **63 测试** 全过
- **5 路静态审计** 全清

## 升级

```bash
git pull && pip install -r requirements.txt
```

## 完整变更

详见 [CHANGELOG - 1.2.0](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/CHANGELOG.md#120--2026-04-29)

---

**⭐ 如果好用，给个 Star 支持！**
