# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- PyPI 发布 (`pip install spyeyes`)
- Docker 镜像

---

## [1.0.0] — 2026-04-30

🎉 SpyEyes 首个独立版本发布。

### ✨ Features 核心功能

- **🌐 IP 追踪** — IPv4 / IPv6 全支持，国家/城市/ISP/ASN/经纬度，国家中文名映射（180+ 国家）
- **📡 本机 IP 查询** — 一键显示当前公网出口 IP
- **📱 电话号码追踪** — 中文归属地（北京市/上海市...）+ 中文运营商（中国移动/联通/电信）+ 12 种号码类型
- **👤 用户名扫描** — **2067 个平台**（合并 Maigret + Sherlock + WhatsMyName 三大上游）
  - 46 中文圈（陆/台/港/星/马）+ 52 西语圈（西班牙/拉美）+ 84 成人/约会
  - 100 线程并发，21 秒扫完
  - WAF 检测（Cloudflare/AWS WAF/PerimeterX/DataDome 等）
  - regex 预过滤 + ReDoS 防护
  - 命中可信度排序（★★★/★★/★）
- **🔍 域名 WHOIS** — 注册商、日期、DNS 服务器、注册组织
- **📨 域名 MX 记录** — 列出所有 MX 优先级
- **✉️ 邮箱有效性验证** — 正则 + MX 联合检查
- **📚 查询历史** — `~/.spyeyes/history.jsonl`
- **📝 Markdown 报告** — `--save report.md` 生成可分享报告

### 🌍 i18n 国际化

- 完整中英双语 UI（~140 翻译键）
- 首次启动语言选择器
- CLI `--lang zh|en` + 菜单 [8] 切换
- 偏好持久化到 `~/.spyeyes/config.json`

### ⚡ Performance 性能

- 100 线程并发扫描 + per-thread `requests.Session`（连接池复用）
- HEAD 请求（仅检测 status_code 时）
- `stream=True` + 只读前 64KB（避免大页面下载）
- 拆分 timeout `(connect=3s, read=5s)`
- ReDoS 启发式防护（拒绝嵌套量词）
- 实测：全 2067 平台 21s / `--quick` 9s / `--category code` 3s

### 🛠 Developer Experience

- 99 个 pytest 单元测试
- ruff / mypy / bandit / pytest 全部通过
- GitHub Actions CI（macOS+Ubuntu × Python 3.10-3.13）
- Dependabot 自动依赖升级
- Apache License 2.0（含明确专利授权 + 商标保护）

### 🎨 UX

- ANSI Shadow 风格 SPYEYES Banner
- 实时进度条（仅 TTY 模式）
- 4 种扫描模式（菜单内选）：快速 / 完整 / 中文+西语 / 仅代码
- 批量域名 MX/WHOIS（`spy mx domain1 domain2 ...`）

---

[Unreleased]: https://github.com/Akxan/SpyEyes/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Akxan/SpyEyes/releases/tag/v1.0.0
