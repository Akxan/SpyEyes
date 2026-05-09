---
layout: default
title: SpyEyes
---

# 🔍 SpyEyes

**OSINT 信息查询工具中文增强版** · One-shot toolkit · **10 commands** · IP · Phone · Username · WHOIS · MX · Email · Subdomain · Domain Emails · **Diff** · **Batch**

> 一站式 OSINT:IP / 电话 / 用户名(3164 平台)/ WHOIS / MX / 邮箱 / **子域名枚举(7 维度)** / **域名邮箱挖掘(6 源全免费)** / **Diff 监控** / **批量扫描** · 8 种 Editorial 风报告

[**📖 详细教程 / Tutorial**](TUTORIAL.html) · [**📝 更新日志 / Changelog**](CHANGELOG.html) · [**🤝 贡献指南 / Contributing**](CONTRIBUTING.html) · [**🔒 安全策略 / Security**](SECURITY.html)

[**⭐ Star on GitHub**](https://github.com/Akxan/SpyEyes) · [**🐛 Report Bug**](https://github.com/Akxan/SpyEyes/issues) · [**📦 Latest Release**](https://github.com/Akxan/SpyEyes/releases/latest)

---

## ✨ 核心特性 / Key Features

- **🌐 IP 追踪** — IPv4/IPv6 + 180+ 国家中文映射
- **📡 本机 IP 查询**
- **📱 电话号码追踪** — 中文归属地 + 中文运营商
- **👤 用户名扫描** — **3164 个平台**(Maigret + Sherlock + WhatsMyName 合并)
  - 48 中文圈 + 58 西语圈 + 91 成人/约会 + 733 论坛
  - 150 线程并发,~20 秒扫完
  - Maigret-style permute(全排列 × 4 种分隔符 + `--method strict|all`)
  - 递归扫描挖关联账号(深度 ≤ 2,完整进度反馈)
- **🔍 WHOIS / 📨 MX / ✉️ 邮箱验证** — IDN 支持
- **🌐 子域名枚举 (v1.3.0 → v1.6.8)** — 6 被动源(crt.sh + CertSpotter + HackerTarget + OTX + **Wayback Machine**)+ **🚀 可选 subfinder 30+ 源** + **DNS 字典爆破** + **JS/HTML host 提取(支持 4xx/5xx title + CNAME 完整 chain)** + DNS + HTTP probe + Wildcard 检测 + **wildcard 严格模式**(v1.6.5 防 DNS 劫持 fake "活")
- **📧 域名邮箱挖掘 (v1.4.0 → v1.6.6)** — **6 源全并发,完全免费无需注册**:Bing SERP + DuckDuckGo + Wayback + GitHub commits + crt.sh + WHOIS;**HTTP 过滤 + 多 target 并行 BFS 爬虫(3-4× 提速,v1.6.6)**;深度爬虫 + 模式生成 + 可选 SMTP 验证
- **📊 Diff 模式 + 批量(v1.5.0)** — `spyeyes diff old.json new.json` OSINT 持续监控;`--batch domains.txt` 批量扫描每个域独立报告
- **🔑 API key 配置(v1.6.8)** — `~/.spyeyes/env` 跨平台自动加载;OTX / CertSpotter / PDCP / GitHub PAT 等都支持;shell export 优先
- **📊 8 种 Editorial 风报告** — `JSON / Markdown / HTML / PDF / TXT / CSV / XMind / Graph`,Cormorant Garamond + JetBrains Mono 三件套;**报告显示完整 6 源状态 ✅/⊘/❌**(v1.6.8)
- **🌍 完整中英双语** UI **+ 报告内容**
- **📈 100% 进度反馈(v1.6.1)** — 所有 > 2 秒操作均有阶段反馈,告别"看着卡死"
- **📁 跨平台报告目录(v1.6.3+)** — 所有平台都默认 `<cwd>/Downloads/`,`SPYEYES_REPORTS_DIR` 自定义

## 🔒 安全防护

经多轮独立 fresh-eyes 盲审收敛到「无真 bug」状态:

- SSRF / ReDoS / Domain 注入 / Username 注入 / Markdown 注入 / HTML XSS / CSV 公式注入防护
- WAF 高精度指纹检测(Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai)
- 子域名爬虫 robots.txt 默认遵守 + 单域 500ms 速率限制
- SMTP 验证 opt-in + 强 disclaimer
- 隐私选项:`SPYEYES_NO_HISTORY=1` 完全禁用历史
- **488 个 pytest 测试**,0 红 / **ruff 0 / mypy 0 / bandit 0** 全清,CI 跨 macOS/Linux/Windows × Python 3.10–3.14

## 🚀 快速开始

```bash
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m spyeyes --version    # spyeyes 1.6.11
```

立即体验:

```bash
python3 -m spyeyes ip 8.8.8.8                          # IP 追踪
python3 -m spyeyes phone +8613800138000                # 电话解析
python3 -m spyeyes user torvalds                       # 3164 平台扫描
python3 -m spyeyes whois example.com                   # WHOIS
python3 -m spyeyes mx 中国.cn                          # IDN 域名 MX

# 子域名枚举(v1.3.0 → v1.6.1)
python3 -m spyeyes subdomain example.com --alive-only --save report.html
python3 -m spyeyes subdomain example.com --bruteforce  # 加 220 词字典

# 🆕 v1.5.0 批量域名扫描
python3 -m spyeyes subdomain --batch domains.txt --batch-save-dir reports/ --alive-only

# 🆕 v1.5.0 Diff 模式 — OSINT 监控
python3 -m spyeyes subdomain example.com --json > snap1.json
python3 -m spyeyes subdomain example.com --json > snap2.json   # 几天后
python3 -m spyeyes diff snap1.json snap2.json --save diff.html

# 🆕 v1.6.0 域名邮箱(6 源全免费并发)
python3 -m spyeyes domain-emails example.com           # crt.sh + WHOIS + Bing + DDG + Wayback + GitHub
python3 -m spyeyes domain-emails example.com --guess "John Doe"

# 8 种报告格式(全 Editorial 风,中英双语)
python3 -m spyeyes user torvalds --save report.html       # HTML(sticky thead + 颜色编码)
python3 -m spyeyes user torvalds --save report.pdf        # PDF(封面页 + 罗马数字章节)
python3 -m spyeyes user torvalds --save report.xmind      # XMind 思维导图
python3 -m spyeyes user torvalds --save report.graph.html # D3.js 力导向图

SPYEYES_NO_HISTORY=1 python3 -m spyeyes ...   # 禁用历史(隐私模式)
```

完整文档见 [详细教程](TUTORIAL.html)。

---

**License**: Apache 2.0 · **Author**: [Akxan](https://github.com/Akxan)
