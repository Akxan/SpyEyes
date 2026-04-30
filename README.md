<div align="center">

# 🔍 SpyEyes

### OSINT 信息查询工具中文增强版

**一站式查询 IP · 电话 · 用户名 · 域名 WHOIS · MX 记录 · 邮箱有效性**

[![CI](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml/badge.svg)](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akxan/SpyEyes/branch/main/graph/badge.svg)](https://codecov.io/gh/Akxan/SpyEyes)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-183%20passed-success.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-2067-orange.svg)](data/platforms.json)
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

**SpyEyes** 是一款用 Python 编写的命令行 **OSINT（开源情报）信息收集工具**，专为中文用户深度优化。集成 IP 追踪、电话号码解析、用户名扫描（2067 个平台 / 中英双语）、域名 WHOIS / MX 查询、邮箱有效性验证等 7 大功能于一体。

适合 **网络安全研究人员、渗透测试工程师、SOC 分析师、技术调查员、红队蓝队成员、CTF 玩家** 以及任何对开源情报感兴趣的开发者使用。

### 💎 项目亮点

- **2067 个用户名扫描平台**：包含 46 中文圈（陆/台/港/星/马）+ 52 西语圈（西班牙/拉美）+ 84 成人/约会平台
- **中英双语 UI**：交互菜单 / CLI 参数 / 错误信息 全部双语
- **Sherlock 级速度**：21 秒扫完 2067 平台（100 线程并发 + Session 池 + HEAD 优化 + ReDoS 防护）
- **WAF 检测**：识别 Cloudflare / AWS WAF / PerimeterX 等反爬墙，避免误报
- **多种查询模式**：`--quick`（~9s）/ `--category`（~3s）/ 默认完整（~21s）
- **结构化输出**：JSON / Markdown 报告 / 历史记录持久化
- **183 个 pytest 测试**：5 路审计全清（ruff / mypy / bandit / pytest / agent）

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
- **2067 个平台**（合并 Maigret + Sherlock + WhatsMyName 三大上游）
- **46 中文圈**（陆/台/港/星/马）+ **52 西语圈**（西班牙/拉美）
- **100 线程并发**，全部扫完 ~21 秒（与 README 顶部一致）
- 内容关键词 + `must_contain` 双重检测
- 默认只显示命中，`--all` 看完整结果

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

### 🚀 通用增强
- **CLI 参数模式**：可脚本化批量调用
- **JSON 输出**：与 jq / 任意工具流水线集成
- **结果保存**：`--save DIR` 自动落盘
- **彩色终端**：自动检测 TTY
- **跨平台**：macOS / Linux / Windows / Termux

</td>
</tr>
</table>

---

## 🆚 与同类工具对比

| 工具 | IP | 电话 | 用户名 | WHOIS | MX | 邮箱 | 中文优先 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [Sherlock](https://github.com/sherlock-project/sherlock) | ❌ | ❌ | ✅ (400+) | ❌ | ❌ | ❌ | ❌ |
| [Maigret](https://github.com/soxoj/maigret) | ❌ | ❌ | ✅ (3000+) | ❌ | ❌ | ❌ | ❌ |
| [holehe](https://github.com/megadose/holehe) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| [theHarvester](https://github.com/laramies/theHarvester) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **SpyEyes** | ✅ | ✅ | ✅ **(2067)** | ✅ | ✅ | ✅ | ✅ |

> 💡 **定位说明**：SpyEyes **不是**为了在用户名扫描深度上跟 Sherlock 卷，而是做**轻量级一站式中文工具**。
> - 只查用户名 → Sherlock / Maigret 更专业
> - 想一个工具搞定 6 类查询且全中文 → **SpyEyes 就是为你准备的**

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
python3 spyeyes.py
```

### 立即体验

```bash
# 查询 Google DNS 的 IP 信息
python3 spyeyes.py ip 8.8.8.8

# 查询本机出口 IP
python3 spyeyes.py myip

# 查询电话号码
python3 spyeyes.py phone +8613800138000

# 扫描用户名
python3 spyeyes.py user torvalds

# WHOIS 查询
python3 spyeyes.py whois example.com

# MX 记录
python3 spyeyes.py mx gmail.com

# 邮箱验证
python3 spyeyes.py email someone@gmail.com

# 输出 JSON + 保存到文件
python3 spyeyes.py ip 8.8.8.8 --json --save results/
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
python3 spyeyes.py
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
[ 4 ] 用户名追踪
[ 5 ] 域名 WHOIS 查询
[ 6 ] 域名 MX 记录
[ 7 ] 邮箱有效性检查
[ 0 ] 退出

 [ + ] 请选择功能 :
```

### 2️⃣ 命令行模式（脚本友好）

```bash
# 基本用法
python3 spyeyes.py <subcommand> <args...> [--json] [--save DIR] [--no-color]

# 与 jq 联动（管道处理）
python3 spyeyes.py ip 8.8.8.8 --json | jq -r '.country'
python3 spyeyes.py phone +8613800138000 --json | jq -r '.location'

# 批量查 IP
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 spyeyes.py ip "$ip" --json | jq -r '.ip + " -> " + .country'
done

# 自动保存所有查询结果
mkdir -p results
python3 spyeyes.py user torvalds --save results
python3 spyeyes.py mx gmail.com --save results
```

### 3️⃣ 完整教程

更详细的功能讲解、安装排错、参数说明请见：

📖 **[TUTORIAL.md — 详细使用教程](docs/TUTORIAL.md)**

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
- ✅ **183 个测试**，0.4 秒跑完（v1.0.0 完整覆盖）
- ✅ 覆盖纯函数 + HTTP mock + 边界条件 + SSRF/ReDoS 防御
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
├── spyeyes.py                  # 主脚本（含全部功能 + i18n + __version__）
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
├── data/
│   └── platforms.json          # 2067 平台数据库（Maigret + Sherlock + WhatsMyName 合并）
├── tools/
│   └── build_platforms.py      # 平台数据库重建脚本（拉取上游最新，原子写 + 重试）
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # autouse fixture（全局状态隔离）
│   ├── test_spyeyes.py         # 主功能测试（145 个）
│   └── test_build_platforms.py # 构建工具测试（38 个）
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

`OSINT` `信息收集` `IP 追踪` `电话号码查询` `用户名搜索` `WHOIS` `MX 记录` `邮箱验证` `网络安全` `渗透测试` `CTF 工具` `Python OSINT` `中文 OSINT 工具` `osint-tool` `ip-tracker` `phone-tracker` `username-search` `whois-lookup` `dns-lookup` `email-verification` `cybersecurity` `reconnaissance` `red-team` `blue-team`

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 鼓励一下！**

[⬆ 回到顶部](#-spyeyes-cn)

</div>
