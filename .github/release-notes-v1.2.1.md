# 🚀 GhostTrack-CN v1.2.1 — 速度翻倍 + 6 个 P1 Bug 修复（覆盖 v1.2.0）

经过 5 路独立审计 + Sherlock 思路借鉴，**用户名扫描 2× 提速**，**6 个 P1 真 bug 全修**。

> 💡 v1.2.1 = v1.2.0 + 性能翻倍 + audit 修复。**强烈建议所有 v1.2.0 用户升级**。

## ⚡ 性能：45s → 21s（2.1×）

借鉴 [Sherlock](https://github.com/sherlock-project/sherlock) 项目的连接复用 + HEAD 优化思路：

| 模式 | v1.2.0 | **v1.2.1** | 加速 |
|---|---|---|---|
| 全 2067 平台扫描 | ~45s | **21s** | **2.1×** |
| `--quick` (727 平台) | ~20s | **9s** | **2.2×** |
| `--category code` (54 平台) | ~3s | **<2s** | **1.5×** |

**4 项底层优化**：
1. **`requests.Session` per-thread + pool_maxsize=64** —— 重复 host 复用 TCP/TLS 连接
2. **HEAD 请求**：856 个仅检测 status_code 的平台（41%）跳过 body 下载
3. **`stream=True` + 只读 64KB**：需要 body 检测的平台不下载完整页面
4. **拆分 timeout `(connect=3s, read=5s)`**：快速踢死 DNS 慢的死站

## 🐛 6 个 P1 Bug 修复（独立 agent 发现）

| # | Bug | 影响 |
|---|---|---|
| 1 | `Cam4` / `CAM4` curated 列表中重复 | 用户看到 2 行同平台，命中数虚高 |
| 2 | `_to_markdown` 不转义 dict key + 接受换行注入 | 报告分享时可被注入伪标题 / 破坏表格 |
| 3 | `_record_history` 在 `data=None` 时崩溃 | 极端场景下 CLI 退出码不对 |
| 4 | `must_contain=(b'',)` 永远 True | 假 ★★★ 命中（每个用户名都报"找到"） |
| 5 | `track_username('')` 返回 all-None 不是 _error | 与 `track_ip('')` 不一致，历史记录假成功 |
| 6 | `--category xyz` 未知类别静默扫 0 个 | 用户以为查了，其实没扫 |

## 🧪 验证

5 路审计全清：
- **ruff** lint + format
- **mypy** type check
- **bandit** security scan
- **pytest**: 63 → **83 测试** 全过（+20 新测试覆盖所有修复）
- **superpowers:code-reviewer agent**: P1 bugs 全修，仅剩 P3 nits 接受不动

## 升级

```bash
git pull && pip install -r requirements.txt
```

## 完整变更

详见 [CHANGELOG - 1.2.1](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/CHANGELOG.md#121--2026-04-29)

---

**⭐ 觉得好用就给个 Star，谢谢！**
