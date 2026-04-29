# 🛡 GhostTrack-CN v1.2.3 — Audit Patch（覆盖 v1.2.2）

第 N 轮 5 路独立审计（ruff + mypy + bandit + pytest + agent）发现 **4 个 P1 真 bug**，全修。同步加 ReDoS 防护。

> 💡 v1.2.3 = v1.2.2 + 安全/正确性补丁。所有 v1.2.2 用户**强烈建议升级**。

## 🐛 4 个 P1 修复

| # | Bug | 影响 |
|---|---|---|
| 1 | `_to_markdown` 通用 dict 分支泄露 `_statuses` 私有 key | Markdown 报告含调试字段 |
| 2 | `re.search` 而非 `re.fullmatch` —— 未锚定 regex 注入 | 含特殊字符 username 可能误判通过 |
| 3 | 无 ReDoS 防护 —— 嵌套量词模式让 worker CPU 卡死 | 数据源若混入 `(a+)+` 可拖垮整个扫描 |
| 4 | `--json` 输出泄露 `_statuses` 私有 key | JSON 不干净；脚本用户看到内部字段 |

## 🛡 同步收紧

- WAF_FINGERPRINTS 改用 **特定 WAF 自有标志**（`cdn-cgi/challenge-platform`、`aws-waf-token`、`/_pxhc/`、`datadome.co` 等），剔除 `b'cloudflare'`/`b'access denied'` 这类太泛模式 → **显著降低误报**
- 新增 `_REDOS_RE` 模块级 regex 检测嵌套量词，命中时跳过 regex check 避免 CPU 灾难

## 🧪 验证

- **99 测试**全过（+6 新：fullmatch 注入测试、ReDoS 检测、ReDoS 0ms 跳过、WAF 误报修复 ×3）
- **5 路审计**全清：ruff / mypy / bandit / pytest / agent
- 实测：恶意 `(a+)+` regex 0 ms 跳过（无防护时数秒 CPU）

## 升级

```bash
git pull && pip install -r requirements.txt
```

## 完整变更

详见 [CHANGELOG - 1.2.3](https://github.com/Akxan/GhostTrack-CN/blob/main/docs/CHANGELOG.md#123--2026-04-29)

---

⭐ 觉得好用就给个 Star，谢谢！
