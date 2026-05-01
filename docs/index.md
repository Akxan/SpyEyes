---
layout: default
title: SpyEyes
---

# 🔍 SpyEyes

**OSINT 信息查询工具中文增强版** · One-shot lookup for IP · Phone · Username · WHOIS · MX · Email

> 一站式查询 IP / 电话 / 用户名 (2067 平台) / 域名 WHOIS / MX 记录 / 邮箱有效性

[**📖 详细教程 / Tutorial**](TUTORIAL.html) · [**📝 更新日志 / Changelog**](CHANGELOG.html) · [**🤝 贡献指南 / Contributing**](CONTRIBUTING.html) · [**🔒 安全策略 / Security**](SECURITY.html)

[**⭐ Star on GitHub**](https://github.com/Akxan/SpyEyes) · [**🐛 Report Bug**](https://github.com/Akxan/SpyEyes/issues) · [**📦 Latest Release**](https://github.com/Akxan/SpyEyes/releases/latest)

---

## ✨ 核心特性 / Key Features

- **🌐 IP 追踪** — IPv4/IPv6 + 180+ 国家中文映射
- **📡 本机 IP 查询**
- **📱 电话号码追踪** — 中文归属地 + 中文运营商
- **👤 用户名扫描** — **2067 个平台**（Maigret + Sherlock + WhatsMyName 合并）
  - 46 中文圈 + 52 西语圈 + 83 成人/约会
  - 100 线程并发，~21 秒扫完
- **🔍 WHOIS / 📨 MX / ✉️ 邮箱验证** — IDN 支持
- **📚 查询历史** + **📝 Markdown 报告**
- **🌍 完整中英双语** UI

## 🔒 安全防护

经 **18 轮独立 fresh-eyes 盲审**收敛到「无真 bug」状态：

- SSRF / ReDoS / Domain 注入 / Username 注入 / Markdown 注入防护
- WAF 高精度指纹检测（Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai）
- 隐私选项：`SPYEYES_NO_HISTORY=1` 完全禁用历史
- 262 个 pytest 测试，0 红 / ruff / mypy / bandit 全清

## 🚀 快速开始

```bash
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m spyeyes --version    # spyeyes 1.0.0
```

立即体验：

```bash
python3 -m spyeyes ip 8.8.8.8                # IP 追踪
python3 -m spyeyes phone +8613800138000      # 电话解析
python3 -m spyeyes user torvalds             # 2067 平台扫描
python3 -m spyeyes whois example.com         # WHOIS
python3 -m spyeyes mx 中国.cn                # IDN 域名 MX
python3 -m spyeyes email user@中国.cn        # IDN email
SPYEYES_NO_HISTORY=1 python3 -m spyeyes ...  # 禁用历史（隐私模式）
```

完整文档见 [详细教程](TUTORIAL.html)。

---

**License**: Apache 2.0 · **Author**: [Akxan](https://github.com/Akxan)
