# 🔒 安全策略 / Security Policy

## 受支持的版本 / Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | ✅                 |
| < 1.0   | ❌                 |

## 报告漏洞 / Reporting a Vulnerability

如果你发现安全漏洞，**请不要**在公开 issue 里讨论。
If you discover a security vulnerability, **do NOT** open a public issue.

请通过以下方式之一私下联系：

- 📧 **邮件 / Email**: 通过 GitHub profile 找联系方式
- 🔐 **GitHub Security Advisory**: [开私密 advisory](https://github.com/Akxan/SpyEyes/security/advisories/new)（推荐）

报告时请尽量包含：

1. 漏洞类型与影响范围
2. 受影响的代码位置（文件 + 行号）
3. 复现步骤
4. 可能的修复建议（如有）

## 响应时效 / Response Time

- **致命漏洞**（RCE / 凭证泄露 / 数据破坏）：48 小时内响应
- **高危**（信息泄露 / DoS）：7 天内响应
- **一般**：14 天内响应

## 安全设计原则 / Security Principles

SpyEyes 在设计上遵循以下原则：

1. **本地优先存储**：查询结果仅在内存中处理；唯一的本地落盘是
   `~/.spyeyes/history.jsonl`（仅记录元数据：时间戳/命令/查询/摘要，**不存全量结果**）。
   要完全禁用历史，设环境变量 `SPYEYES_NO_HISTORY=1`，或定期 `rm ~/.spyeyes/history.jsonl`
2. **不发送未授权请求**：所有 API 调用目标域名公开透明（`ipwho.is` / `ipify.org` 等）
3. **不绕过任何访问控制**：仅查询公开信息
4. **不内嵌追踪代码**：本工具无任何遥测、统计、第三方 SDK

## 用户安全提醒 / User Safety Notice

- 工具查询的电话号码、邮箱、域名等可能涉及隐私，请仅用于**自查或授权场景**
- **历史记录默认开启** —— `~/.spyeyes/history.jsonl` 会累积所有 CLI 查询的元数据。
  敏感场景请：
  - 设 `SPYEYES_NO_HISTORY=1` 完全禁用
  - 或定期 `rm ~/.spyeyes/history.jsonl` 清理
- 使用 `--save` 时输出的 JSON 包含查询输入，请妥善保管
- 在共享/公共终端使用时建议通过 `--no-color` 避免 ANSI 转义符落入截屏

---

感谢你帮助让 SpyEyes 更安全 🙏

Thank you for helping keep SpyEyes secure!
