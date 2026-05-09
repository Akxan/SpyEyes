---
layout: default
title: SpyEyes
---

# 🔍 SpyEyes

**OSINT 信息查询工具中文增强版** · One-shot toolkit · 9 commands · IP · Phone · Username · WHOIS · MX · Email · Subdomain · Domain Emails

> 一站式 OSINT:IP / 电话 / 用户名(3164 平台)/ WHOIS / MX / 邮箱 / **子域名枚举** / **域名邮箱挖取** · 8 种 Editorial 风报告

[**📖 详细教程 / Tutorial**](TUTORIAL.html) · [**📝 更新日志 / Changelog**](CHANGELOG.html) · [**🤝 贡献指南 / Contributing**](CONTRIBUTING.html) · [**🔒 安全策略 / Security**](SECURITY.html)

[**⭐ Star on GitHub**](https://github.com/Akxan/SpyEyes) · [**🐛 Report Bug**](https://github.com/Akxan/SpyEyes/issues) · [**📦 Latest Release**](https://github.com/Akxan/SpyEyes/releases/latest)

---

## ✨ 核心特性 / Key Features

- **🌐 IP 追踪** — IPv4/IPv6 + 180+ 国家中文映射
- **📡 本机 IP 查询**
- **📱 电话号码追踪** — 中文归属地 + 中文运营商
- **👤 用户名扫描** — **3164 个平台**（Maigret + Sherlock + WhatsMyName 合并）
  - 48 中文圈 + 58 西语圈 + 91 成人/约会 + 733 论坛
  - 150 线程并发，~20 秒扫完
  - Maigret-style permute（全排列 × 4 种分隔符 + `--method strict|all`）
  - 递归扫描挖关联账号
- **🔍 WHOIS / 📨 MX / ✉️ 邮箱验证** — IDN 支持
- **🌐 子域名枚举(v1.3.0 / v1.4.8)** — 被动多源(crt.sh + CertSpotter + HackerTarget + AlienVault OTX) + **🚀 可选 subfinder 接力 30+ 源(v1.4.8)** + DNS + HTTP probe + Wildcard 检测
- **📧 域名邮箱挖取(v1.4.0)** — theHarvester + Hunter.io 混合:CT 日志 + WHOIS + 深度爬虫 + 模式生成 + 可选 SMTP 验证
- **📊 8 种 Editorial 风报告** — `JSON / Markdown / HTML / PDF / TXT / CSV / XMind / Graph`,Cormorant Garamond + JetBrains Mono 字体三件套(v1.4.x)
- **🌍 完整中英双语** UI **+ 报告内容**(v1.2.0+)

## 🔒 安全防护

经多轮独立 fresh-eyes 盲审收敛到「无真 bug」状态:

- SSRF / ReDoS / Domain 注入 / Username 注入 / Markdown 注入 / HTML XSS / CSV 公式注入防护
- WAF 高精度指纹检测(Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai)
- 子域名爬虫 robots.txt 默认遵守 + 单域 500ms 速率限制
- SMTP 验证 opt-in + 强 disclaimer
- 隐私选项:`SPYEYES_NO_HISTORY=1` 完全禁用历史
- **417 个 pytest 测试**,0 红 / ruff / mypy / bandit 全清,CI 跨 macOS/Linux/Windows × Python 3.10–3.14

## 🚀 快速开始

```bash
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m spyeyes --version    # spyeyes 1.2.0
```

立即体验:

```bash
python3 -m spyeyes ip 8.8.8.8                          # IP 追踪
python3 -m spyeyes phone +8613800138000                # 电话解析
python3 -m spyeyes user torvalds                       # 3164 平台扫描(150 线程)
python3 -m spyeyes whois example.com                   # WHOIS
python3 -m spyeyes mx 中国.cn                          # IDN 域名 MX
python3 -m spyeyes email user@中国.cn                  # IDN 邮箱

# 🆕 v1.3.0 子域名枚举
python3 -m spyeyes subdomain example.com               # 被动 + DNS + HTTP probe

# 🆕 v1.4.0 域名邮箱挖取
python3 -m spyeyes domain-emails example.com           # 多源 + 深度爬虫
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
