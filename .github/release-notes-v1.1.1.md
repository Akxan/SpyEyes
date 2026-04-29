# 🔥 GhostTrack-CN v1.1.1 — Patch Release

**经过 5 路独立审计修复 v1.1 中的 3 个 P1 真 bug**。所有 v1.1.0 用户**强烈建议升级**。

> 💡 v1.1.1 = v1.1.0 + 关键 bug 修复。所有 v1.1.0 的新功能（i18n / 2020 平台 / 中英双语 / 中文+西语区域覆盖）原样保留。

## 🐛 修复的 P1 Bug

| # | Bug | 触发条件 | 后果 |
|---|---|---|---|
| **1** | `_check_username` 漏 catch `ValueError` | Maigret 上游加 `{:d}` 格式 URL 模板 | 整个 2020 平台扫描崩 |
| **2** | `track_username` 不防 worker 异常 | 任何 worker 抛非 format 异常 | 单点失败传染全局 |
| **3** | `--workers 0/-5/99999` 无校验 | 用户手滑 / shell 拼写错误 | `ThreadPoolExecutor` 崩 |

## ➕ 顺手清理

- ruff 静态规则全清（F601 重复 dict key、F401 未用 import、F541 空 f-string、E702 单行多语句）
- 空输入处理：`track_ip('')` / `track_username('')` 不再误报
- `.gitignore` 扩展（`.coverage` / `.mypy_cache` / `.ruff_cache`）

## 🧪 验证

5 路独立审计，全部 ✅：
- **ruff** lint + format
- **mypy** 类型检查
- **bandit** 安全扫描
- **pytest**：51 → **63 测试** 全过
- **superpowers:code-reviewer agent**：「modulo two minor optimization notes — substantially correct」

## 📋 完整变更

详见 [CHANGELOG.md - 1.1.1](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/CHANGELOG.md#111--2026-04-29)

## 🚀 升级

```bash
git pull && pip install -r requirements.txt
```

或全新安装：

```bash
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 GhostTR.py
```

---

**如果这个工具对你有帮助，请点个 ⭐ Star 支持开发！**

Featured: 2020 platforms · Bilingual (zh/en) · 46 Chinese-region · 52 Spanish-region
