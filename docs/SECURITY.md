# 🔒 Security Policy / 安全策略

## Supported Versions / 受支持的版本

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

Fixes land on the latest release. Run `spyeyes upgrade` to get them.

## Reporting a Vulnerability / 报告漏洞

**Please do not discuss security vulnerabilities in public issues.**

Report privately through **[GitHub Security Advisories](https://github.com/Akxan/SpyEyes/security/advisories/new)** — this is the only reporting channel, and it keeps the report visible to the maintainer only until a fix is released.

Please include:

1. The type of vulnerability and its impact
2. The affected code (file and line)
3. Steps to reproduce
4. A suggested fix, if you have one

### Response time

- **Critical** (remote code execution, credential leak, data destruction): within 48 hours
- **High** (information disclosure, denial of service): within 7 days
- **Other**: within 14 days

## What SpyEyes Stores and Sends / 本地数据与外发请求

**Stored locally** (all under `~/.spyeyes/`, nothing is uploaded):

| File | Contents |
|---|---|
| `history.jsonl` | Metadata of each query — time, command, query string, summary. Never the full results. Disable with `SPYEYES_NO_HISTORY=1`. |
| `config.json` | Saved interface language |
| `.update_check.json` | Cached result of the release check |
| `env` | Optional API keys **you** put there (`chmod 600` recommended) |

Reports are written only where you ask (`--save`), or to the default report directory in interactive mode.

**Network requests**:

- Queries go to the public sources each command needs (for example `ipwho.is`, `crt.sh`, the sites checked by a username scan). The sources are listed in the [README](https://github.com/Akxan/SpyEyes#readme).
- A release check asks `api.github.com` at most once every 24 hours. Disable it with `SPYEYES_NO_UPDATE_CHECK=1` or `--no-update-check`.
- No telemetry, analytics or third-party SDKs.
- **HTML and graph reports load web fonts from Google Fonts, and graph reports load D3.js from `d3js.org`, when you open them in a browser.** Opening a report offline shows fallback fonts; the graph needs network access to render.

## Security Design / 安全设计

- User input is validated before use: usernames, domains and IP addresses are checked against strict rules, so they cannot inject URLs, paths or report markup.
- Reports escape all untrusted content (HTML, Markdown, CSV formula injection, XMind, PDF).
- The domain email crawler only requests URLs inside the target domain, obeys `robots.txt` by default and rate-limits itself.
- SMTP verification is opt-in (`--verify-smtp`) because it connects to the target's mail servers.
- SpyEyes does not bypass access controls; it only reads publicly available information.

## User Safety Notice / 用户安全提醒

- Phone numbers, emails and domains may be personal data. Use SpyEyes only for self-audits or authorized work.
- History is on by default; set `SPYEYES_NO_HISTORY=1` for sensitive work, or delete `~/.spyeyes/history.jsonl`.
- Saved reports contain your query and its results — store them accordingly.

---

## 中文摘要

- **报告漏洞**:请不要开公开 issue,通过 [GitHub Security Advisory](https://github.com/Akxan/SpyEyes/security/advisories/new) 私下报告(唯一渠道)。请附上漏洞类型与影响、受影响的代码位置、复现步骤和修复建议。
- **响应时效**:致命漏洞 48 小时内,高危 7 天内,其余 14 天内。
- **本地数据**:`~/.spyeyes/` 下有四个文件 —— `history.jsonl`(只记查询元数据,`SPYEYES_NO_HISTORY=1` 可关闭)、`config.json`(界面语言)、`.update_check.json`(版本检查缓存)、`env`(你自己填的可选 API key)。查询结果不会上传。
- **外发请求**:只访问各命令所需的公开数据源;每 24 小时最多向 `api.github.com` 查一次新版本(`SPYEYES_NO_UPDATE_CHECK=1` 可关闭);没有任何遥测。
- **注意**:HTML 和关系图报告在浏览器里打开时会从 Google Fonts 加载字体,关系图还会从 `d3js.org` 加载 D3.js;离线打开时关系图无法显示。
- **使用提醒**:电话、邮箱、域名可能涉及个人信息,请仅用于自查或已获授权的场景;保存的报告包含查询内容,请妥善保管。

Thank you for helping keep SpyEyes secure. 感谢你帮助让 SpyEyes 更安全 🙏
