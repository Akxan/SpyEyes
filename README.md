<div align="center">

# 🔍 SpyEyes

### OSINT 信息查询工具中文增强版

**一站式查询 IP · 电话 · 用户名 · 域名 WHOIS · MX 记录 · 邮箱 · 子域名 · 域名邮箱 · Diff 监控 · 批量扫描**

[![CI](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml/badge.svg)](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akxan/SpyEyes/branch/main/graph/badge.svg)](https://codecov.io/gh/Akxan/SpyEyes)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-468%20passed-success.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-3164-orange.svg)](#-与同类工具对比)
[![Reports](https://img.shields.io/badge/reports-8%20formats-9cf.svg)](#-报告格式8-种)
[![Commands](https://img.shields.io/badge/commands-10-blueviolet.svg)](docs/TUTORIAL.md)
[![Version](https://img.shields.io/badge/version-1.6.6-blueviolet.svg)](docs/CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-online-blue.svg)](https://akxan.github.io/SpyEyes/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20%7C%20Termux-lightgrey)](#-安装)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/maintenance/yes/2026.svg)](https://github.com/Akxan/SpyEyes/commits/main)

[![Stars](https://img.shields.io/github/stars/Akxan/SpyEyes?style=social)](https://github.com/Akxan/SpyEyes/stargazers)
[![Forks](https://img.shields.io/github/forks/Akxan/SpyEyes?style=social)](https://github.com/Akxan/SpyEyes/network/members)
[![Issues](https://img.shields.io/github/issues/Akxan/SpyEyes.svg)](https://github.com/Akxan/SpyEyes/issues)
[![Last Commit](https://img.shields.io/github/last-commit/Akxan/SpyEyes.svg)](https://github.com/Akxan/SpyEyes/commits/main)

**🇨🇳 中文 · [🇬🇧 English](README.en.md)**

[**📖 详细教程**](docs/TUTORIAL.md) · [**🐛 报 Bug**](https://github.com/Akxan/SpyEyes/issues) · [**🤝 贡献代码**](docs/CONTRIBUTING.md) · [**📝 更新日志**](docs/CHANGELOG.md)

</div>

---

## 📖 项目简介

**SpyEyes** 是一款用 Python 编写的命令行 **OSINT(开源情报)信息收集工具**,专为中文用户深度优化。**10 大核心能力**:IP 追踪 / 电话号码解析 / 用户名扫描(**3164 个平台 / 中英双语**)/ 域名 WHOIS / MX 查询 / 邮箱有效性验证 / **子域名枚举**(6 被动源 + 字典爆破 + JS 提取)/ **域名邮箱挖掘**(6 源全免费并发 + 深度爬虫)/ **Diff 监控**(对比两次扫描)/ **批量域名输入**(`--batch`)/ **8 种 Editorial 风报告**。

适合 **网络安全研究人员、渗透测试工程师、SOC 分析师、技术调查员、红队蓝队成员、CTF 玩家** 以及任何对开源情报感兴趣的开发者使用。

### 💎 项目亮点

- **🆕 v1.6.0:域名邮箱 6 源全并发** — Bing SERP + DuckDuckGo + Wayback Machine + GitHub commits + crt.sh + WHOIS,**完全免费 + 无需注册**;并发执行总耗时 ≈ 最慢源(2-3× 提速);对比 theHarvester / Photon / EmailFinder 等同类工具,免费层最强 + 报告格式最丰富
- **🆕 v1.5.0:Diff 模式 + 批量域名** — `spyeyes diff old.json new.json` 对比两次扫描挖出新增 / 消失 / 变更的子域(OSINT 监控刚需);`--batch domains.txt --batch-save-dir reports/` 批量扫描每个域独立报告
- **🆕 v1.4.x:子域名 7 维度收集** — 6 被动源(crt.sh / CertSpotter / HackerTarget / OTX / **Wayback Machine** / 可选 subfinder 30+ 源)+ DNS 字典爆破(220 词内置 / `SPYEYES_DNS_WORDLIST` 自定义)+ JS/HTML body host 提取 + DNS A/AAAA/CNAME 验证 + HTTP probe + Wildcard 检测
- **🆕 Editorial Investigation Brief 报告美化** — 调查档案/报刊调性:Cormorant Garamond + Crimson Pro + JetBrains Mono 三件套 + cream/ink/印章红配色;HTML sticky thead + alive/dead 视觉区分 + HTTP status 颜色编码;PDF 封面页 + 罗马数字章节;XMind 层级展开;Graph D3.js 力导向图
- **3164 个用户名扫描平台**:48 中文圈 + 58 西语圈 + 91 成人/约会 + 733 论坛,Sherlock 级速度 ~20 秒(150 线程并发 + Session 池 + ReDoS 防护)
- **Maigret-style permute** + 递归扫描 `--recursive` + 多扫描模式 `--quick` / `--category`
- **8 种报告格式** —— `JSON / Markdown / HTML / PDF / TXT / CSV / XMind / Graph (D3.js)`,全部跟随 UI 语言(中/英)
- **WAF 检测**:Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai 等高精度指纹
- **完整中英双语**:交互菜单 / CLI 参数 / 错误信息 / **报告内容**全部双语
- **🆕 v1.6.1:进度条 100% 全功能审计** — 12 核心函数 + 12 被动源逐一审计,所有耗时操作均有阶段反馈(用户反馈"看着不卡了")
- **468 个 pytest 测试**:4 工具全清(ruff 0 / mypy 0 / bandit 0 / pytest 全绿),CI 跨 macOS/Linux/Windows × Python 3.10–3.14

---

## ✨ 核心特性

<table>
<tr>
<td width="50%">

### 🌐 IP 地址追踪
- 支持 **IPv4 / IPv6**
- 国家、城市、ISP、ASN、经纬度
- 自动生成谷歌地图链接
- **国家中文名映射**（180+ 国家）

### 📡 本机 IP 查询
- 一键显示当前公网出口 IP
- VPN / 代理切换后实时刷新

### 📱 电话号码追踪
- 中文归属地（北京市 / 上海市 / ...）
- 中文运营商（中国移动 / 联通 / 电信）
- 时区、E.164 / 国际格式 / 移动拨号格式
- 12 种号码类型识别（移动 / 固话 / VoIP / 寻呼机 ...）

### 👤 用户名扫描
- **3164 个平台**（合并 Maigret + Sherlock + WhatsMyName，含 Maigret engine 解析）
- **48 中文圈**（陆/台/港/星/马）+ **58 西语圈**（西班牙/拉美）+ **733 论坛**
- **150 线程并发**，全部扫完 ~20 秒（quick 模式 ~10 秒）
- 内容关键词 + `must_contain` 双重检测 + WAF 识别
- 默认只显示命中，`--all` 看完整结果
- **🆕 v1.1.0**：`--recursive` 递归扫描（深度 0-2）+ `permute` 子命令（用户名变形）

</td>
<td width="50%">

### 🔍 域名 WHOIS 查询
- 注册商、创建/到期/更新日期
- DNS 服务器、注册组织、邮箱
- 支持 200+ TLD

### 📨 域名 MX 记录
- 列出所有 MX 记录及优先级
- 用于邮件域名情报

### ✉️ 邮箱有效性验证
- 正则格式校验
- MX 记录联合检查
- 不发送邮件，不留痕迹

### 🌐 子域名枚举(v1.3.0 → v1.6.1 🆕)
- **被动多源(6 源)**:`crt.sh` + CertSpotter + HackerTarget + AlienVault OTX + **Wayback Machine(v1.4.9)** 并发汇总
- **🚀 可选 subfinder 接力(v1.4.8)**:自动检测 `subfinder` 二进制,接力 30+ 数据源(virustotal / shodan / censys / chaos / fofa / quake / securitytrails 等);未装则零开销跳过
- **🆕 DNS 字典爆破(v1.4.9,opt-in)**:内置 ~220 高命中前缀 + `SPYEYES_DNS_WORDLIST=/path` 自定义大字典,`--bruteforce` 启用
- **🆕 JS / HTML host 提取(v1.4.9,默认开)**:从 probe 已抓的 16KB body 中正则扫硬编码 host 引用(`fetch('https://api.example.com/...')` 等),提取后再跑一轮 DNS 验证;`--no-js-extract` 关闭
- **DNS 主动验证**:A / AAAA / CNAME(默认 30 worker)
- **HTTP probe**:抓 status_code + `<title>`(`--no-probe` 关闭)
- **Wildcard 检测**:32 字符随机前缀探测,标记不可信结果
- 8 种报告全支持(HTML 中 alive 子域可点击跳转)

### 📊 OSINT 监控 / 批量(v1.5.0 🆕)
- **Diff 模式**:`spyeyes diff old.json new.json` — 对比两次扫描挖**新增 / 消失 / 变更**的子域(IP/HTTP状态/title)
- **批量域名输入**:`spyeyes subdomain --batch domains.txt --batch-save-dir reports/` — 每个域独立报告,Ctrl+C 可中断不丢
- **`--alive-only` 全局**:CLI / JSON / 8 种导出报告全过滤,只保留可达子域

### 🚀 通用增强
- **CLI 参数模式**:可脚本化批量调用
- **JSON 输出**:与 jq / 任意工具流水线集成
- **结果保存**:`--save DIR` 自动落盘
- **进度反馈 100% 覆盖**(v1.6.1):所有 > 2 秒操作都有实时进度
- **彩色终端**:自动检测 TTY
- **跨平台**:macOS / Linux / Windows / Termux

</td>
</tr>
</table>

---

## 🆚 与同类工具对比

| 工具 | IP | 电话 | 用户名 | WHOIS | MX | 邮箱 | 子域名 | 域名邮箱 | Diff监控 | 批量 | 报告格式 | 中文 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [Sherlock](https://github.com/sherlock-project/sherlock) | ❌ | ❌ | ✅ (400+) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 1 | ❌ |
| [Maigret](https://github.com/soxoj/maigret) | ❌ | ❌ | ✅ (3000+) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 1-2 | ❌ |
| [holehe](https://github.com/megadose/holehe) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 1 | ❌ |
| [theHarvester](https://github.com/laramies/theHarvester) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅(部分商业) | ❌ | ❌ | 1-2 | ❌ |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | 1 | ❌ |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | 1 | ❌ |
| **SpyEyes** | ✅ | ✅ | ✅ **(3164)** | ✅ | ✅ | ✅ | ✅ **(7 维度)** | ✅ **(6 源全免费)** | ✅ | ✅ | **8** | ✅ |

> 💡 **定位说明**:SpyEyes **不是**为了在用户名扫描深度上跟 Sherlock 卷,而是做**轻量级一站式 + 中文优先 + 报告丰富**的 OSINT 工具。
> - 只查用户名 → Sherlock / Maigret 更专业
> - 邮箱挖掘要 30+ 商业 API → theHarvester 更全
> - 但要**免费层最强 + 8 种报告 + 中文 UI + 一站式 10 个命令** → **SpyEyes 就是为你准备的**

---

## 🛠 技术栈

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/Requests-2C5BB4?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)

</div>

| 类别 | 技术 / 库 | 用途 |
|---|---|---|
| **语言** | Python 3.10+ | 主语言 |
| **HTTP** | `requests` | API 调用 |
| **电话解析** | `phonenumbers` | Google 官方电话号码库 |
| **DNS** | `dnspython` | MX / A / AAAA 记录查询 |
| **WHOIS** | `python-whois` | 域名注册信息 |
| **并发** | `concurrent.futures.ThreadPoolExecutor` | 多平台并发扫描 |
| **CLI** | `argparse` | 命令行参数解析 |
| **终端** | ANSI escape sequences | 彩色输出 + TTY 检测 |
| **测试** | `pytest` + `unittest.mock` | 单元测试 + HTTP mock |
| **CI/CD** | GitHub Actions | 跨平台多版本自动测试 |
| **数据源 API** | `ipwho.is` · `api.ipify.org` | IP 信息查询 |

---

## 🚀 快速开始

### 一行安装运行（macOS / Linux）

```bash
git clone https://github.com/Akxan/SpyEyes.git && \
cd SpyEyes && \
python3 -m venv .venv && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
python3 -m spyeyes
```

### 立即体验

```bash
# 查询 Google DNS 的 IP 信息
python3 -m spyeyes ip 8.8.8.8

# 查询本机出口 IP
python3 -m spyeyes myip

# 查询电话号码
python3 -m spyeyes phone +8613800138000

# 扫描用户名
python3 -m spyeyes user torvalds

# WHOIS 查询
python3 -m spyeyes whois example.com

# MX 记录
python3 -m spyeyes mx gmail.com

# 邮箱验证
python3 -m spyeyes email someone@gmail.com

# 子域名枚举(v1.3.0 → v1.6.1)
python3 -m spyeyes subdomain example.com                                     # 6 源被动 + DNS + HTTP probe + JS 提取(默认全开)
python3 -m spyeyes subdomain example.com --bruteforce                        # 加内置 220 字典爆破(更全)
SPYEYES_DNS_WORDLIST=~/all.txt spyeyes subdomain example.com --bruteforce    # 自定义大字典
python3 -m spyeyes subdomain example.com --alive-only --save report.html     # 只保留活跃子域(报告整洁)
python3 -m spyeyes subdomain example.com --no-js-extract --no-probe          # 仅纯被动,最快
python3 -m spyeyes subdomain example.com --json | jq '.subdomains[] | select(.alive)'

# 🆕 v1.5.0:批量域名扫描
python3 -m spyeyes subdomain --batch domains.txt --batch-save-dir reports/ --alive-only
# domains.txt 每行一个域;# 注释 + 空行自动跳过;每个域独立 HTML 报告

# 🆕 v1.5.0:Diff 模式 — OSINT 持续监控
python3 -m spyeyes subdomain example.com --json > monday.json
python3 -m spyeyes subdomain example.com --json > friday.json   # 几天后再扫
python3 -m spyeyes diff monday.json friday.json --save diff.html   # 新增/消失/变更子域

# 🆕 v1.6.0:域名邮箱挖掘(6 源全并发,免费无注册)
python3 -m spyeyes domain-emails example.com           # crt.sh + WHOIS + Bing + DDG + Wayback + GitHub 全并发
python3 -m spyeyes domain-emails example.com --guess "John Doe,Jane Smith"   # 加模式生成
python3 -m spyeyes domain-emails example.com --no-crawl   # 仅被动 6 源,最快

# 查看历史记录（~/.spyeyes/history.jsonl 自动累积）
python3 -m spyeyes history --limit 20            # 最近 20 条
python3 -m spyeyes history --search torvalds     # 按 query 子串过滤
python3 -m spyeyes history --json | jq           # JSON pipeline

# 输出 JSON + 保存到文件
python3 -m spyeyes ip 8.8.8.8 --json --save results/
```

### 🆕 v1.2.0 新功能演示

```bash
# 1) 8 种报告格式 —— 按 --save 文件后缀分发
python3 -m spyeyes user torvalds --save report.html      # HTML（含 CSS 样式）
python3 -m spyeyes user torvalds --save report.pdf       # PDF（需 spyeyes[pdf]）
python3 -m spyeyes user torvalds --save report.xmind     # XMind 8 思维导图
python3 -m spyeyes user torvalds --save report.graph.html # D3.js 力导向图
python3 -m spyeyes user torvalds --save report.csv       # CSV（含 injection 防护）
python3 -m spyeyes user torvalds --save report.txt       # 纯文本
python3 -m spyeyes user torvalds --save report.md        # Markdown
python3 -m spyeyes user torvalds --save report.json      # JSON

# 2) 报告内容跟随 UI 语言：中文 UI 出中文报告，英文 UI 出英文报告
python3 -m spyeyes --lang zh user torvalds --save zh.html
python3 -m spyeyes --lang en user torvalds --save en.html

# 3) Maigret-style 用户名变形（method=all 包含 _前缀/后缀_）
python3 -m spyeyes permute "John Doe"                    # strict（默认）
python3 -m spyeyes permute "John Doe" --method all       # 含 _johndoe / johndoe_
python3 -m spyeyes permute "Linus Torvalds" --scan --quick  # 变形 + 自动扫描

# 4) 递归扫描：在命中页面提取次级用户名继续扫
python3 -m spyeyes user torvalds --recursive --depth 2

# 5) 默认 150 线程并发（从 100 升级）；可调
python3 -m spyeyes user torvalds --workers 200
```

---

## 📦 安装

### macOS（推荐 venv）

```bash
brew install python3 git
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install git python3 python3-pip python3-venv
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Termux (Android)

```bash
pkg install git python
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
pip install -r requirements.txt
```

### Windows

```powershell
# 在 https://www.python.org 下载 Python 3，安装时勾选 "Add to PATH"
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## 📋 使用方法

### 1️⃣ 交互菜单模式

```bash
python3 -m spyeyes
```

```
███████╗██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
███████╗██████╔╝ ╚████╔╝ █████╗   ╚████╔╝ █████╗  ███████╗
╚════██║██╔═══╝   ╚██╔╝  ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
███████║██║        ██║   ███████╗   ██║   ███████╗███████║
╚══════╝╚═╝        ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚══════╝
       👁  All-in-One OSINT Toolkit  ·  github.com/Akxan/SpyEyes  👁

[ 1 ] IP 追踪
[ 2 ] 查看本机 IP
[ 3 ] 电话号码追踪
[ 4 ] 用户名追踪 / 变形扫描   ← v1.2.0：合并变形子流程
[ 5 ] 域名 WHOIS 查询
[ 6 ] 域名 MX 记录
[ 7 ] 邮箱有效性检查
[ 8 ] 子域名枚举              ← v1.3.0：新增
[ 9 ] 域名邮箱枚举            ← v1.4.0：新增(OSINT 邮箱挖取)
[ 10 ] 切换语言 / Language    ← v1.4.0：让位到 [10]
[ 0 ] 退出

 [ + ] 请选择功能 :

 (在任意子功能中输入 0 或直接回车可返回此菜单)
```

> **菜单流程**:
> - `[4]` 用户名:先选策略(直接扫 / 变形+扫 / 仅变形)→ 扫描模式 → 可选递归
> - `[8]` 子域名:输入域名 → 选是否 HTTP probe → 4 阶段实时反馈(被动源 → wildcard → DNS → probe)
> - `[9]` 域名邮箱:输入域名 → 选是否含 alive 子域 → 可选模式生成姓名 → 可选 SMTP 验证
> - 保存报告时弹 `[1-8]` 数字格式菜单 + 默认 `~/Downloads/`,可连续多格式保存
> - **任何输入步骤**直接回车或 `0` 都返回主菜单(v1.3.2 新增)

### 2️⃣ 命令行模式（脚本友好）

```bash
# 基本用法
python3 -m spyeyes <subcommand> <args...> [--json] [--save DIR] [--no-color]

# 与 jq 联动（管道处理）
python3 -m spyeyes ip 8.8.8.8 --json | jq -r '.country'
python3 -m spyeyes phone +8613800138000 --json | jq -r '.location'

# 批量查 IP
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 -m spyeyes ip "$ip" --json | jq -r '.ip + " -> " + .country'
done

# 自动保存所有查询结果
mkdir -p results
python3 -m spyeyes user torvalds --save results
python3 -m spyeyes mx gmail.com --save results
```

### 3️⃣ 完整教程

更详细的功能讲解、安装排错、参数说明请见：

📖 **[TUTORIAL.md — 详细使用教程](docs/TUTORIAL.md)**

---

## 📊 报告格式（8 种）

按 `--save <文件>` 的后缀自动分发，所有格式都跟随当前 UI 语言（中/英）：

| 格式 | 后缀 | 实现 | 适用场景 |
|---|---|---|---|
| **JSON** | `.json` | stdlib | 管道处理、脚本调用、API 集成 |
| **Markdown** | `.md` | stdlib（含注入转义） | GitHub Issue、笔记、wiki |
| **HTML** | `.html` | stdlib + 内嵌 CSS | 浏览器查看、邮件附件、外发报告 |
| **PDF** | `.pdf` | reportlab（可选 `[pdf]`） | 正式调查报告、归档 |
| **TXT** | `.txt` | stdlib | 复制粘贴到 ticket / IM / 邮件 |
| **CSV** | `.csv` | csv stdlib + Excel 公式注入防护 | Excel / Google Sheets / pandas |
| **XMind** | `.xmind` | zipfile + xml stdlib | 思维导图（XMind 8 兼容） |
| **Graph** | `.graph.html` | D3.js v7 (CDN) | 力导向关系图，可点击跳转 |

```bash
# 自动按后缀分发，全部 8 种格式都 work：
python3 -m spyeyes user torvalds --save report.html
python3 -m spyeyes user torvalds --save report.xmind
python3 -m spyeyes user torvalds --save report.graph.html
```

**交互模式**：选"保存报告 → 是"后会弹出 `[1] JSON ... [8] Graph` 数字菜单，
默认路径 `~/Downloads/`，保存完追问"还要保存其它格式吗？"可连续多种格式输出。

> **安全防护**：HTML / Graph 用 `_html_escape` 防 XSS；CSV 单元格首字符为
> `= + - @ \t \r` 时前置 `'` 防 Excel/Sheets 公式注入；Graph 中嵌入 JSON 的
> `</` 转义为 `<\/` 防 `</script>` 注入。

> **注意**：
> - `--save DIR/`（目录形式，以 `/` 结尾或目录已存在）固定输出 **JSON**，按时间戳命名归档；
>   要选格式请用具体的文件路径如 `--save report.html`
> - **报告内容跟随 `--lang`** —— CSV 列头也会本地化（中文 UI 输出 `分类,平台,主页地址,状态`）。
>   下游用 pandas/jq 等需要稳定列名的脚本，请用 `--lang en` 或直接读 JSON

---

## 🧪 测试

```bash
# 安装测试依赖
pip install pytest pytest-cov

# 跑全部测试
pytest tests/ -v

# 带覆盖率报告
pytest tests/ --cov=. --cov-report=term-missing
```

当前测试覆盖：
- ✅ **306 个测试**，0.6 秒跑完（v1.2.0 完整覆盖）
- ✅ 覆盖纯函数 + HTTP mock + 边界条件 + SSRF/ReDoS 防御 + 8 种报告格式 × 2 种语言
- ✅ GitHub Actions 在 macOS / Ubuntu / **Windows** × Python 3.10-3.13 自动测试
- ✅ 独立 lint job（ruff + mypy + bandit）

```bash
# 安装运行依赖 + 测试依赖
pip install -r requirements-dev.txt
```

---

## 📁 项目结构

```
SpyEyes/
├── spyeyes/                    # 主包（v1.0.0 起）
│   ├── __init__.py             # 主代码（含全部功能 + i18n + __version__）
│   ├── __main__.py             # python -m spyeyes 入口
│   └── data/platforms.json     # 3164 平台数据库（合并 Maigret + Sherlock + WhatsMyName）
├── README.md                   # 你正在看的这个（中文入口）
├── README.en.md                # English entry
├── LICENSE                     # Apache 2.0
├── NOTICE                      # 版权声明
├── requirements.txt            # 运行依赖
├── requirements-dev.txt        # 开发/测试依赖（pytest, ruff, mypy, bandit）
├── docs/                       # 📚 所有文档
│   ├── TUTORIAL.md             # 详细教程
│   ├── CHANGELOG.md            # 版本更新日志
│   ├── CONTRIBUTING.md         # 贡献指南
│   └── SECURITY.md             # 安全策略
├── tools/
│   └── build_platforms.py      # 平台数据库重建脚本（拉取上游最新，原子写 + 重试）
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # autouse fixture（全局状态隔离）
│   ├── test_spyeyes.py         # 主功能测试（220 个）
│   └── test_build_platforms.py # 构建工具测试（40 个）
├── .github/
│   ├── workflows/ci.yml        # GitHub Actions CI（lint job + 多 OS × 多 Python 矩阵）
│   ├── ISSUE_TEMPLATE/         # bug / 功能 issue 模板
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml          # 自动依赖更新
└── asset/                      # README 截图与社交预览图
```

---

## 🎯 适用场景

- 🛡 **企业蓝队 / SOC**：分析可疑 IP 来源、排查钓鱼邮件域名
- 🎯 **红队 / 渗透测试**：信息收集阶段的快速查询
- 🏆 **CTF / OSINT 比赛**：快速做题工具
- 🕵 **安全研究**：批量 IP 归属分析、Domain Reputation
- 📞 **诈骗号码识别**：判断陌生来电的归属与运营商
- 📧 **邮件营销**：邮箱清单的有效性预筛
- 🌍 **个人调研**：查 VPN 出口、检查 DNS 配置

---

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Akxan/SpyEyes&type=Date)](https://star-history.com/#Akxan/SpyEyes&Date)

---

## 🤝 贡献

欢迎 PR、Issue、Star！

请先阅读 [CONTRIBUTING.md](docs/CONTRIBUTING.md) 了解开发流程和代码规范。

<a href="https://github.com/Akxan/SpyEyes/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Akxan/SpyEyes" />
</a>

---

## 📄 许可证

本项目采用 **[Apache License 2.0](LICENSE)** 开源。

Apache 2.0 比 MIT 多了**明确的专利授权**和**商标保护**，对二次开发和商业使用更安全。

任何人可以自由使用、修改、分发，包括商业用途，但需保留版权声明。

---

## 🙏 致谢

- 🌟 **[Google libphonenumber](https://github.com/google/libphonenumber)** —— 业界最权威的电话号码库
- 🌟 **[ipwho.is](https://ipwho.is/)** —— 免费、稳定、信息丰富的 IP 地理位置 API
- 🌟 **[ipify.org](https://www.ipify.org/)** —— 简洁的本机 IP 查询服务
- 🌟 所有为开源安全工具做贡献的开发者们 ❤️

---

## ⚠️ 免责声明

本工具仅用于**合法的安全研究、自查、CTF、教学**等场景。

❌ **禁止**用于：
- 跟踪、骚扰、人肉搜索任何个人
- 未经授权的网络扫描或入侵
- 收集后用于商业牟利或违法犯罪

✅ **允许**：
- 对自己拥有的资产做安全自查
- 在书面授权范围内的渗透测试
- 完全公开信息的合法查询
- 教学、研究、开源贡献

使用者需自行承担一切法律责任。详见 [TUTORIAL.md - 法律与道德提醒](docs/TUTORIAL.md#法律与道德提醒)。

---

## 🔍 关键词 / Keywords

`OSINT` `信息收集` `IP 追踪` `电话号码查询` `用户名搜索` `WHOIS` `MX 记录` `邮箱验证` `子域名枚举` `域名邮箱挖取` `证书透明度` `网络安全` `渗透测试` `CTF 工具` `Python OSINT` `中文 OSINT 工具` `osint-tool` `ip-tracker` `phone-tracker` `username-search` `whois-lookup` `dns-lookup` `email-verification` `subdomain-enumeration` `subdomain-finder` `email-harvester` `crtsh` `certspotter` `certificate-transparency` `cybersecurity` `reconnaissance` `red-team` `blue-team` `pentest` `ctf`

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 鼓励一下！**

[⬆ 回到顶部](#-spyeyes)

</div>
