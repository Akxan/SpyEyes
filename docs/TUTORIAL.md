# SpyEyes 详细使用教程

> 本文档面向中文用户，带你从零开始安装、运行、理解 SpyEyes 的所有功能。

## 目录

1. [工具简介](#工具简介)
2. [系统要求与依赖](#系统要求与依赖)
3. [安装步骤](#安装步骤)
   - [macOS](#macos-安装)
   - [Linux (Debian/Ubuntu)](#linux-debianubuntu-安装)
   - [Termux (Android)](#termux-android-安装)
   - [Windows](#windows-安装)
4. [API key 配置(可选)](#api-key-配置可选免费)
5. [启动与菜单导航](#启动与菜单导航)
6. [功能详解](#功能详解)
   - [① IP 追踪](#-ip-追踪)
   - [② 查看本机 IP](#-查看本机-ip)
   - [③ 电话号码追踪](#-电话号码追踪)
   - [④ 用户名追踪](#-用户名追踪)
   - [⑤ 域名 WHOIS 查询](#-域名-whois-查询)
   - [⑥ 域名 MX 记录](#-域名-mx-记录)
   - [⑦ 邮箱有效性检查](#-邮箱有效性检查)
   - [⑧ 子域名枚举](#-子域名枚举)
   - [⑨ 域名邮箱枚举](#-域名邮箱枚举)
   - [⑩ Diff 模式 + 批量域名](#-diff-模式--批量)
   - [⑪ 综合调查](#-综合调查)
   - [⑫ 一键升级 + 版本检查](#-一键升级--版本检查)
7. [命令行模式（脚本调用）](#命令行模式脚本调用)
8. [常见问题排查](#常见问题排查)
9. [已知限制](#已知限制)
10. [法律与道德提醒](#法律与道德提醒)

---

## 工具简介

SpyEyes 是一个用 Python 编写的命令行 OSINT 工具，作为 Python 包发布（`spyeyes/` 含 `__init__.py` + `__main__.py` + `data/`），通过交互式菜单提供以下信息查询能力：

| 功能 | 数据来源 | 是否需要联网 |
|---|---|---|
| IP 地址归属查询 | 公开 API：`ipwho.is`（HTTPS，含国家中文名） | 是 |
| 查看本机出口 IP | 公开 API：`api.ipify.org` | 是 |
| 电话号码解析 | 本地 `phonenumbers` 库（中文运营商/归属地） | 否 |
| 用户名社交平台扫描 | **3164 个**平台 HTTP 探测（Maigret + Sherlock + WhatsMyName），**150 线程并发 + 内容关键词** | 是 |
| 域名 WHOIS 查询 | `python-whois` 库（直连 RDAP / WHOIS 服务器） | 是 |
| 域名 MX 记录查询 | `dnspython`，使用系统 DNS 解析 | 是 |
| 邮箱有效性验证 | 本地正则 + MX 记录检查 | 是 |
| 子域名枚举（v1.3.0 → v1.6.1） | 6 被动源(crt.sh + CertSpotter + HackerTarget + OTX + Wayback)+ **可选 subfinder 30+ 源** + **DNS 字典爆破** + **JS/HTML body host 提取** + DNS A/AAAA/CNAME + HTTP probe | 是 |
| 域名邮箱枚举（v1.4.0 → v1.6.0） | **6 源全并发**(crt.sh + WHOIS + Bing SERP + DuckDuckGo + Wayback + GitHub commits)**全免费** + 深度爬虫 + 模式生成 + 可选 SMTP 验证 | 是 |
| **Diff 模式（v1.5.0）** | 对比两次子域 JSON 扫描结果,挖出新增/消失/变更 | 否(纯本地计算) |
| **批量域名（v1.5.0）** | `--batch domains.txt` 逐个扫描,可写每域独立报告 | 是 |
| **综合调查（v1.7.0）** | 一个域名 → WHOIS + MX + 子域名 + 域名邮箱并发,再接力 IP 情报 / 用户名扫描,出整合档案 | 是 |
| **一键升级（v1.8.2）** | GitHub Releases 版本检查(24h 缓存)+ `spyeyes upgrade` 按安装方式自动升级 | 是 |
| **查询历史** | `spyeyes history`,读取 `~/.spyeyes/history.jsonl`(只存查询元数据) | 否 |

> 所有数据查询均依赖**公开渠道**，工具本身不存储任何个人信息，也不绕过任何访问控制。

---

## 系统要求与依赖

- **Python**：3.10 或更高（PEP 562 模块级 `__getattr__` + 类型注解）
- **Python 库**（已写入 `requirements.txt`）：
  - `requests` —— HTTP 请求
  - `phonenumbers` —— Google 的电话号码解析库
  - `dnspython` —— DNS 查询（MX 记录、邮箱验证）
  - `python-whois` —— WHOIS 查询
- **系统命令**：`git`（仅用于下载源码）
- **可选**：`reportlab`（PDF 报告，源码目录内 `pip install -e ".[pdf]"` 或直接 `pip install reportlab`）；`subfinder` 二进制（子域名接力 30+ 数据源）
- **可选（开发）**：`pip install -r requirements-dev.txt`（pytest / ruff / mypy / bandit）

---

## 安装步骤

### macOS 安装

macOS 自带的或 Homebrew 安装的 Python 默认启用了 [PEP 668](https://peps.python.org/pep-0668/) 保护，**直接 `pip3 install` 会被拒绝**。推荐使用虚拟环境：

```bash
# 1. 安装 Python 和 git（如果没装）
brew install python3 git

# 2. 克隆项目
cd ~/Documents/Code            # 选择你想放代码的目录
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes

# 3. 创建虚拟环境并激活
python3 -m venv .venv
source .venv/bin/activate

# 4. 安装依赖
pip install -r requirements.txt

# 5. 运行
python3 -m spyeyes
```

每次新开终端要再用，记得先 `cd SpyEyes && source .venv/bin/activate`。
不想激活的话，直接用绝对路径调用 venv 里的 Python：

```bash
~/Documents/Code/SpyEyes/.venv/bin/python -m spyeyes
```

### Linux (Debian/Ubuntu) 安装

```bash
sudo apt-get update
sudo apt-get install git python3 python3-pip
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
pip3 install -r requirements.txt   # 较新发行版可能也需要 venv，参考上面的 macOS 方案
python3 -m spyeyes
```

### Termux (Android) 安装

```bash
pkg update
pkg install git python
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
pip install -r requirements.txt
python -m spyeyes
```

### Windows 安装

```powershell
# 在官网 https://www.python.org 安装 Python 3，安装时勾选 "Add to PATH"
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m spyeyes
```

### 可选：注册 `spyeyes` 命令 / pipx 安装

```bash
# 源码目录内 editable 安装 —— 之后任意目录可直接敲 spyeyes
# (升级:git pull && pip install -e .)
pip install -e .

# 或不 clone,直接从 GitHub 装到独立环境 —— 之后可用 `spyeyes upgrade` 一键升级
pipx install git+https://github.com/Akxan/SpyEyes.git
```

---

## API key 配置(可选,免费)

SpyEyes 默认 6 个免费源**无需任何 key 也能跑**,但配置 keys 后:
- ⬆️ 命中率提升 30-50%
- ⬆️ 速率限制大幅放宽(免费层 50/天 → 500/天)
- ⬆️ subfinder 解锁更多源

### 推荐方式:`~/.spyeyes/env` 文件

模块加载时自动读,跨平台一致(macOS/Linux/Windows),`shell export` 优先,改完即时生效。

```bash
mkdir -p ~/.spyeyes
cat > ~/.spyeyes/env << 'EOF'
# ~~~~~ AlienVault OTX ~~~~~
# 免费注册:https://otx.alienvault.com/settings
# 用途:子域名 + 邮箱被动 DNS 查询,quota 显著放宽
SPYEYES_OTX_API_KEY=your_otx_key_here

# ~~~~~ SSLMate CertSpotter ~~~~~
# 免费注册:https://sslmate.com/account/api_credentials
# 用途:CT 日志(SSL 证书)子域查询,免费层 100/h → 注册后宽很多
SPYEYES_CERTSPOTTER_API_KEY=your_certspotter_key_here

# ~~~~~ ProjectDiscovery PDCP(免费)~~~~~
# 注册:https://cloud.projectdiscovery.io
# 用途:subfinder 自动读,解锁更多源(virustotal/shodan/censys 等)
PDCP_API_KEY=your_pdcp_key_here

# ~~~~~ GitHub PAT(可选,只读)~~~~~
# 创建:https://github.com/settings/tokens
# 用途:GitHub commit search 提速 rate limit(10/min → 30/min)
SPYEYES_GITHUB_TOKEN=ghp_your_pat_here

# ~~~~~ 实时电话运营商(可选,付费 API)~~~~~
# 提供商:numverify(https://numverify.com,免费 100/月)
# SPYEYES_PHONE_API_KEY=numverify:your_numverify_key

# ~~~~~ 自定义 DNS 字典爆破词典 ~~~~~
# 默认 220 内置;massdns/shuffledns 大字典直接复用
# SPYEYES_DNS_WORDLIST=/path/to/all.txt

# ~~~~~ 固定报告目录(可选)~~~~~
# 默认(v1.8.0+):源码运行 → <项目根>/Downloads/;pip/pipx 安装 → ~/Downloads/spyeyes/
# 服务器场景常用 /var/log/spyeyes
# SPYEYES_REPORTS_DIR=/var/log/spyeyes

# ~~~~~ 其它开关(可选)~~~~~
# subdomain 总是启用 DNS 字典爆破(等价 --bruteforce)
# SPYEYES_BRUTEFORCE=1
# 关闭启动时的 GitHub 版本检查(等价 --no-update-check)
# SPYEYES_NO_UPDATE_CHECK=1
# 不写 ~/.spyeyes/history.jsonl(隐私模式)
# SPYEYES_NO_HISTORY=1
# 没有 --lang 也没有 ~/.spyeyes/config.json 时的默认语言(zh 开头 → 中文,其它 → 英文)
# SPYEYES_LANG=zh
EOF

# 锁权限(只本用户可读)
chmod 600 ~/.spyeyes/env
```

> 格式:每行一个 `KEY=VALUE`,值可加引号;`#` 开头的整行是注释。**不要在值后面写行内注释**(会被当成值的一部分)。

### 替代方式:shell 配置文件

如果你已经有 `~/.zshrc` / `~/.bashrc`,也可以直接 `export`:

```bash
# 写到 ~/.zshrc(zsh)或 ~/.bashrc(bash)
export SPYEYES_OTX_API_KEY=your_key
export SPYEYES_CERTSPOTTER_API_KEY=your_key
export PDCP_API_KEY=your_key

# 立即生效
source ~/.zshrc
```

注意:VS Code 终端需要重启才能读到新加的 env vars。

### 验证 key 已加载

```bash
.venv/bin/python -c "
import os, spyeyes
keys = ['SPYEYES_OTX_API_KEY', 'SPYEYES_CERTSPOTTER_API_KEY', 'PDCP_API_KEY']
for k in keys:
    v = os.environ.get(k, '')
    print(f'{k}: {\"✅ 已加载\" if v else \"❌ 未配置\"}')
"
```

---

## 启动与菜单导航

### 首次启动 —— 选择语言

第一次运行 `python3 -m spyeyes` 时会出现语言选择器：

```
 ╔════════════════════════════════════════════╗
 ║  请选择语言 / Please select language:      ║
 ╚════════════════════════════════════════════╝

  [ 1 ] 中文 (Chinese)
  [ 2 ] English (英文)

 >>>
```

选择后会保存到 `~/.spyeyes/config.json`，下次自动用同一语言。后续可以随时通过菜单 `[ 11 ]` 切换。（启动时带了 `--lang zh|en` 则不弹选择器，也不写配置。）

### 主菜单

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
[ 8 ] 子域名枚举                      ← v1.3.0 新增
[ 9 ] 域名邮箱枚举(OSINT 邮箱挖取)    ← v1.4.0 新增
[ 10 ] 综合调查 (多源整合档案)         ← v1.7.0 新增
[ 11 ] 切换语言 / Language
[ 12 ] 检查并升级 SpyEyes              ← v1.8.2 新增
[ 0 ] 退出

  (在任意子功能中输入 0 或直接回车可返回此菜单)

 [ + ] 请选择功能 :
```

**操作要点**：

- 输入对应**数字**后回车
- 每个功能跑完会提示「按回车键继续」—— 按回车回到主菜单
- `[ 11 ]` 随时切换中/英文 UI,立即生效并保存(v1.7.0 加入综合调查后从 [10] 移到 [11])
- `[ 12 ]` 检查并升级:强制查询 GitHub Releases,有新版则问 `[Y/n]` 后升级(详见 [⑫](#-一键升级--版本检查))
- **启动升级提示**(v1.8.2):若后台缓存发现新版且在 TTY 中,进菜单前会问 `现在升级? [Y/n]`;选 N 直接进菜单。源码安装选 Y 只显示 `git pull && pip install -e .` 提示,按回车后照常进入菜单
- **任何子功能输入步骤**输入 `0` 或直接回车都返回主菜单(v1.3.2 新增)
- 任何时候按 `Ctrl + C` 可以强制退出
- 输入非数字（如字母）会提示「请输入数字」并重新让你选

### 命令行强制语言

不进入交互菜单，直接用 CLI 时也可指定语言：

```bash
python3 -m spyeyes --lang en ip 8.8.8.8     # 强制英文输出
python3 -m spyeyes --lang zh user torvalds  # 强制中文输出
```

语言优先级：**`--lang` 标志 > 配置文件 `~/.spyeyes/config.json` > 环境变量 `SPYEYES_LANG` / `LC_ALL` / `LANG`**（值以 `zh` 开头 → 中文，其它或未设置 → 英文）。CLI 模式不会弹语言选择器。

---

## 功能详解

### ① IP 追踪

**作用**：根据输入的 IP 地址查询地理位置、ISP、ASN、时区等信息。

**操作示范**：

```
请选择功能 : 1
请输入目标 IP : 8.8.8.8
```

**输出示例**：

```
============= IP 地址信息 =============

 目标 IP         : 8.8.8.8
 IP 类型         : IPv4
 国家            : United States
 国家代码        : US
 城市            : Mountain View
 大洲            : North America
 地区            : California
 纬度            : 37.3860517
 经度            : -122.0838511
 谷歌地图        : https://www.google.com/maps/@37.3860517,-122.0838511,8z
 邮编            : 94039
 国际区号        : 1
 首都            : Washington D.C.
 国旗            : 🇺🇸
 ASN             : 15169
 组织            : Google LLC
 ISP             : Google LLC
 域名            : google.com
 时区 ID         : America/Los_Angeles
 时区缩写        : PDT
 偏移量          : -25200
 UTC             : -07:00
```

**说明**：
- 谷歌地图链接可以直接复制到浏览器查看大致定位
- IP 归属定位的精度取决于 ISP 上报，**不能精确到具体街道**
- 国家代码（country_code）通过 v1.0.0 起内置的 `COUNTRY_ZH` 映射表（180+ 国家/地区）转中文显示；城市名仍由 `ipwho.is` 返回的英文为准

---

### ② 查看本机 IP

**作用**：显示你当前公网出口 IP（NAT 之后的对外地址）。

**操作示范**：

```
请选择功能 : 2
```

**输出示例**：

```
========== 本机 IP 信息 ==========

[ + ] 你的 IP 地址 : 185.155.61.166
```

**说明**：
- 这是你被外部世界看到的 IP，和电脑「网络设置」里看到的内网 IP（通常是 `192.168.x.x`）不同
- 走 VPN 时会显示 VPN 出口 IP

---

### ③ 电话号码追踪

**作用**：用 Google 的 `phonenumbers` 库本地解析电话号码，得到归属地、运营商、时区、号码类型等。

**操作示范**：

```
请选择功能 : 3
请输入目标电话号码 例如 [+8613800138000] : +8613800138000
```

**输出示例**：

```
========== 电话号码信息 ==========

 归属地             : 北京市
 地区代码           : CN
 时区               : Asia/Shanghai
 运营商             : 中国移动
 是否有效号码       : True
 是否可能号码       : True
 国际格式           : +86 138 0013 8000
 移动拨号格式       : 138 0013 8000
 原始号码           : 13800138000
 E.164 格式         : +8613800138000
 国家代码           : 86
 本地号码           : 13800138000
 号码类型           : 移动电话
```

**输入格式要点**：

| 输入方式 | 是否可行 | 备注 |
|---|---|---|
| `+8613800138000` | ✅ 推荐 | 国际格式，最不易出错 |
| `13800138000` | ✅ 可行 | 默认区域已设为 `CN`（中国），可省略 `+86` |
| `+12025550100` | ✅ 可行 | 美国号码，`+1` 国际区号 |
| `138 0013 8000` | ✅ 可行 | 库会自动忽略空格 |
| `138-0013-8000` | ✅ 可行 | 横线也会被忽略 |
| `2025550100`（无 `+1` 也无国家上下文） | ❌ 不行 | 默认区域 `CN`，会被误判 |

**说明**：
- 该功能完全**离线运行**，不会向任何远程服务器发送号码
- 「归属地」精度只到省/直辖市级别，无法精确到城市
- 查询虚拟号段（170/171）时，运营商可能显示为空

---

### ④ 用户名追踪

**作用**：把你输入的用户名拼到 **3164 个主流社交/技术平台** 的 URL 中并发访问，按区域和主题分组返回命中结果。数据库整合自三大上游：[Maigret](https://github.com/soxoj/maigret) + [Sherlock](https://github.com/sherlock-project/sherlock) + [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)，加上手工 curated 的中文/西语区精选。

**操作示范**：

```
请选择功能 : 4
请输入用户名 : torvalds
```

**输出示例**（默认只显示命中）：

```
========== 用户名扫描结果 ==========

 共扫描 3164 个平台，命中 317 个：
 （仅显示命中；用 --all 查看未命中）

 ┌─ 代码与开发 (26/115) ─
 [ + ] GitHub                         https://github.com/torvalds
 [ + ] GitLab                         https://gitlab.com/torvalds
 [ + ] Bitbucket                      https://bitbucket.org/torvalds
 ...

 ┌─ 中文平台（陆/台/港/星/马） (12/48) ─
 [ + ] CSDN                           https://blog.csdn.net/torvalds
 [ + ] V2EX                           https://v2ex.com/member/torvalds
 [ + ] Dcard 狄卡                     https://www.dcard.tw/@torvalds
 ...

 ┌─ 西语圈（西班牙/拉美） (8/58) ─
 [ + ] MercadoLibre AR                https://perfil.mercadolibre.com.ar/torvalds
 [ + ] Wallapop                       https://es.wallapop.com/user/torvalds
 ...
```

**平台分类（13 大类，3164 总数）**：

| 类别 | 数量 | 典型平台 |
|---|---:|---|
| `code` | 115 | GitHub / GitLab / LeetCode / CodePen ... |
| `social` | 99 | Twitter / Facebook / Mastodon / Bluesky ... |
| `forum` | 733 | Reddit / Quora / Disqus + 各国论坛 |
| `video` | 25 | YouTube / TikTok / Twitch / Vimeo ... |
| `music` | 22 | SoundCloud / Bandcamp / Last.fm ... |
| `writing` | 51 | Medium / Substack / 简书 ... |
| `art` | 59 | DeviantArt / ArtStation / Behance ... |
| `gaming` | 97 | Steam / Itch.io / Lichess ... |
| `funding` | 13 | Patreon / Ko-fi / OpenCollective ... |
| **`chinese`** | **48** | 微博 · 知乎 · CSDN · V2EX · 简书 · Dcard · Mobile01 · 巴哈姆特 · PIXNET · LIHKG · Shopee TW/SG/MY · ... |
| **`spanish`** | **58** | Wallapop · MercadoLibre AR/MX/BR · Menéame · Taringa · Forocoches · Hispachan · Forosperu · Xataka · ... |
| **`adult`** | **91** | OnlyFans · Fansly · Chaturbate · Pornhub · XVideos · 等成人/约会/CAM 平台（OSINT 用途独立分类） |
| `other` | 1753 | Maigret 长尾（小众/地区性）；`--quick` 跳过这一类，只扫其余 ~1411 个 |

**性能 / 调优**：

- 默认 **150 线程并发**（v1.2.0 从 100 升级），~20 秒完成 3164 平台全扫描；可用 `--workers N` 调节（1-200），单平台超时 `--timeout`（默认 5 秒）
- 默认**只显示命中**（不然 3164 行太多）—— CLI 加 `--all` 查看完整报告（含未命中）
- **三重检测逻辑**：HTTP 200 → 不含 `not_found` 模式（如 "page not found"） → 含 `must_contain` 模式（如平台特征 HTML）
- **v1.2.0 菜单流程**：进入 `[4]` 后先选策略：
  - `1` 直接扫描原始用户名
  - `2` 用户名变形（生成 `johndoe`/`j.doe`/`jd` 等变体）+ 批量扫描 —— 找化名 / 小号利器
  - `3` 仅生成变形列表（不扫描）
- 数据库可随时刷新：`python3 tools/build_platforms.py` 自动从三大上游拉最新

**重要说明**：

> ⚠️ **3164 平台中约 1753 个为 `other` 长尾（主要来自 Maigret）**，许多是小众/地区性站点。命中率因平台而异：
> - 主流平台（GitHub / Twitter / Reddit）：精度 95%+
> - 中文/西语精选区域：精度 85%+（手工 curate 过）
> - Maigret 长尾：精度 70-80%（部分有 must_contain 验证）
> - 真正登录墙的平台（LinkedIn / Instagram）依然会误报「未找到」

---

### ⑤ 域名 WHOIS 查询

**作用**：查询域名注册信息（注册商、创建/到期日期、DNS 服务器、注册联系人等）。

**操作示范**：

```
请选择功能 : 5
请输入域名 : example.com
```

**输出示例**：

```
========== WHOIS 查询 ==========

 域名           : EXAMPLE.COM
 注册商         : RESERVED-Internet Assigned Numbers Authority
 创建日期       : 1995-08-14 04:00:00+00:00
 到期日期       : 2026-08-13 04:00:00+00:00
 更新日期       : 2026-01-16 18:26:50+00:00
 DNS 服务器     : ELLIOTT.NS.CLOUDFLARE.COM, HERA.NS.CLOUDFLARE.COM
 状态           : clientDeleteProhibited ...
```

**说明**：
- 部分顶级域（如 `.cn`、`.ai`）WHOIS 信息受限或被屏蔽
- 启用了 WHOIS 隐私保护的域名只能看到代理服务商信息

---

### ⑥ 域名 MX 记录

**作用**：查询域名的邮件交换记录，告诉你这个域名的邮件由哪些服务器接收。

**操作示范**：

```
请选择功能 : 6
请输入域名 : gmail.com
```

**输出示例**：

```
========== MX 记录 ==========

 域名       : gmail.com

  优先级    5  →  gmail-smtp-in.l.google.com
  优先级   10  →  alt1.gmail-smtp-in.l.google.com
  优先级   20  →  alt2.gmail-smtp-in.l.google.com
  优先级   30  →  alt3.gmail-smtp-in.l.google.com
  优先级   40  →  alt4.gmail-smtp-in.l.google.com
```

**说明**：
- 优先级数字**越小越优先**
- 没有 MX 记录时该域名无法接收邮件
- 用了 Cloudflare/阿里云 等代理服务时会显示代理 MX

---

### ⑦ 邮箱有效性检查

**作用**：通过「正则格式校验」+「域名 MX 记录检查」判断邮箱是否可能有效。

**操作示范**：

```
请选择功能 : 7
请输入邮箱 : someone@gmail.com
```

**输出示例**：

```
========== 邮箱有效性 ==========

 邮箱           : someone@gmail.com
 格式合法       : True
 域名           : gmail.com
 MX 有效        : True
   → 优先级    5  gmail-smtp-in.l.google.com
   → ...
```

**说明**：
- **不会真的发邮件验证**，只验证格式 + 邮件服务器可达性
- 「MX 有效」≠「该邮箱地址存在」，比如 `xxxxxxxxxxxxxxxxxxx@gmail.com` 也会显示「MX 有效」
- 想真正验证地址存在性需要 SMTP HELO/RCPT 探测，但很多大厂会拒绝

---

### ⑧ 子域名枚举

**作用**：枚举目标域名下所有公开可见的子域名(`api.example.com`、`mail.example.com` 等),并对每个候选做 DNS 解析与 HTTP 探测,识别哪些子域真实存在、运行什么服务。

**操作示范**：

```
请选择功能 : 8
请输入目标域名（如 example.com）：example.com

是否抓 HTTP <title> 信息？
   [ 1 ] 是（默认）  [ 2 ] 否
  请选择 [1/2，默认 1] : 1

是否启用 DNS 字典爆破？(~220 个前缀，+5-15 秒)
   [ 1 ] 否（默认，仅被动源）  [ 2 ] 是（更全面）
  请选择 [1/2，默认 1] : 1
```

扫描结束后、保存报告前还会问一次「保存报告时是否隐藏不可达子域？」（默认是，效果同 `--alive-only`）。

**输出示例**(中文 UI):

```
========== 子域名枚举 ==========

 子域名枚举：example.com
 共发现 8 个 · 活跃 1 个 · 来自 2 个数据源
 数据源：crtsh=6, hackertarget=2, certspotter=0, otx=0, wayback=0, subfinder=0

 ┌─ 活跃子域 (1) ─
 [ + ] example.com                         104.20.23.154, 172.66.147.243   HTTP 200  Example Domain

 ┌─ 不可达 / 未解析子域 (7) ─
 [ - ] dev.example.com
 [ - ] m.example.com
 [ - ] products.example.com
 ...
```

**工作流程(三阶段)**：

1. **被动汇总(6 个公开数据源 + 1 个可选)**:
   - [crt.sh](https://crt.sh) —— Certificate Transparency 日志(免费、无 API key、覆盖率最高)
   - [CertSpotter](https://sslmate.com/certspotter/api/) —— SSLMate CT 监控(免费匿名 100/h;`SPYEYES_CERTSPOTTER_API_KEY` 解锁高 quota)
   - [HackerTarget hostsearch](https://api.hackertarget.com/hostsearch/) —— 匿名每日 quota ~50,触发限速优雅降级
   - [AlienVault OTX](https://otx.alienvault.com) —— passive_dns 端点(`SPYEYES_OTX_API_KEY` 解锁高 quota)
   - **[Wayback Machine](https://web.archive.org)(v1.4.9 新增)** —— Internet Archive 的 CDX API,挖出**已下线但曾出现过**的子域(被动 DNS / CT 不会留)
   - **[subfinder](https://github.com/projectdiscovery/subfinder)(可选,推荐)** —— v1.4.8 新增,自动检测 `subfinder` 二进制,接力 ProjectDiscovery 的 30+ 数据源(virustotal、shodan、censys、binaryedge、chaos、bevigil、bufferover、dnsdumpster、fofa、fullhunt、leakix、netlas、quake、redhuntlabs、securitytrails、whoisxmlapi、zoomeye 等)
     - 没装则零开销跳过,装了立即接力使用,无需任何配置代码改动
     - 安装:`brew install subfinder`(macOS)/ `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`(Linux)
     - 配置 `~/.config/subfinder/provider-config.yaml` 解锁更多源
   - 任何一源挂掉 / 限速,其它源继续工作;统计落到 `errors` 字段

1.5. **DNS 字典爆破(v1.4.9,opt-in)**:
   - `--bruteforce` 启用 / `SPYEYES_BRUTEFORCE=1` 等价
   - 内置 ~220 个高命中前缀字典(`www / mail / api / admin / dev / staging / test / vpn / git / jenkins / db / redis ...`)
   - 自定义大字典:`SPYEYES_DNS_WORDLIST=/path/to/all.txt`(支持 `#` 注释 + 空行,massdns/shuffledns 字典直接复用)
   - 字典 prefix 拼成 `<prefix>.<domain>` 加入 candidates,通过 stage 3 DNS 验证自动过滤死的

2. **DNS 主动验证(默认 30 worker 并发)**:对每个候选跑 A / AAAA / CNAME 三种查询,确认活性
3. **HTTP probe(默认开,`--no-probe` 关闭)**:对 alive 子域抓 HTTP 状态码 + `<title>`(https 失败回退 http;只读 16KB body 早停)
3.5. **JS/HTML host 提取(v1.4.9,默认开,`--no-js-extract` 关闭)**:在 probe 抓 `<title>` 已读的 16KB body 上,正则扫 `*.<domain>` 引用(内联 script 中的 `fetch('https://api.example.com/...')`、`<script src="//cdn.example.com/...">` 等),提取后跑第二轮 DNS+probe(单轮即止,不递归)

**Wildcard DNS 检测**:用 32 字符密码学随机前缀做 DNS 查询(如 `f3a1b2c..d.example.com`)。命中即标记 `wildcard_suspect=true`,提示用户结果不可信(常见于 `*.blogspot.com`、`*.github.io` 等通配域)。

**JSON 输出结构**:

```json
{
  "domain": "example.com",
  "sources": {"crtsh": 6, "certspotter": 0, "hackertarget": 2, "otx": 0, "wayback": 0, "subfinder": 0},
  "wildcard_suspect": false,
  "subdomains": [
    {"host": "example.com", "alive": true,
     "a": ["104.20.23.154"], "aaaa": ["2606:4700:..."], "cname": null,
     "http_status": 200, "title": "Example Domain", "scheme": "https"}
  ],
  "_stats": {"total": 8, "alive": 1, "probed": 1, "bruteforce_added": 0, "js_extracted": 0, "errors": {}}
}
```

**CLI 选项**:

| 选项 | 作用 |
|---|---|
| `DOMAIN` / `--batch FILE` | 单个目标域名,或每行一个域名的文件(批量模式见 [⑩](#-diff-模式--批量)) |
| `--batch-save-dir DIR` | 批量模式下逐域写报告的目录 |
| `--no-probe` | 仅跑 DNS,不发 HTTP(更快,匿名场景) |
| `--workers N` | DNS 并发数(默认 30,最大 200);HTTP probe 并发取 `max(N, 80)` |
| `--timeout T` | 单 host HTTP probe 超时秒数(默认 4.0) |
| `--alive-only` | 只保留活跃子域 —— **终端、JSON 和所有导出报告**都过滤;检测到通配符 DNS 时自动切严格模式(必须有 HTTP 响应或真实 CNAME 才算活) |
| `--bruteforce` | 启用 DNS 字典爆破(opt-in;内置 ~220 前缀,`SPYEYES_DNS_WORDLIST=/path` 自定义,`SPYEYES_BRUTEFORCE=1` 等价) |
| `--no-js-extract` | 关闭 JS/HTML body host 提取(默认开) |

**示例**:

```bash
python3 -m spyeyes subdomain example.com                  # 默认:被动 + DNS + probe
python3 -m spyeyes subdomain example.com --no-probe       # 仅 DNS,~3s
python3 -m spyeyes subdomain github.io                    # 通配域 → wildcard_suspect=true
python3 -m spyeyes subdomain example.com --workers 50     # 调高并发
python3 -m spyeyes subdomain example.com --alive-only     # 只保留活跃的(终端 / JSON / 报告都过滤)
python3 -m spyeyes subdomain example.com --bruteforce     # 加 ~220 词字典爆破

# JSON 管道:筛 alive
python3 -m spyeyes subdomain example.com --json | jq '.subdomains[] | select(.alive)'

# 8 种报告全支持
python3 -m spyeyes subdomain example.com --save report.html         # HTML(alive 子域可点击)
python3 -m spyeyes subdomain example.com --save report.csv          # 7 列:host,alive,a,aaaa,cname,http_status,title
python3 -m spyeyes subdomain example.com --save report.xmind        # 思维导图(alive/dead 两支)
python3 -m spyeyes subdomain example.com --save report.graph.html   # D3.js 力导向图(域名为中心)
```

**已知限制**:
- 默认只能找到**曾经申请过 TLS 证书**或被三方平台索引过的子域(被动源的本质);`--bruteforce` 可额外猜常见前缀
- 内网 / 测试环境 / 未公开的子域抓不到(这是设计取舍,符合 SpyEyes 公开信息原则)
- HackerTarget 匿名每日 quota 约 50,大量调用会触发限速(其它源仍工作)

**安全声明**:本功能**默认纯被动** —— 只汇总**已经公开**的子域信息(CT 日志 / 被动 DNS / 网页归档),再对候选做常规 DNS 解析与 HTTP 探测,符合 SpyEyes "不绕过任何访问控制" 原则。**DNS 字典爆破是 opt-in**(`--bruteforce` / `SPYEYES_BRUTEFORCE=1`),开启后会额外发出数百次 DNS 查询(自定义大字典时更多)。HTTP probe 与正常浏览器访问无差。但 **仍建议** 仅对**自己拥有的资产** 或 **书面授权范围内** 的目标使用,开启字典爆破时尤其如此。

---

### ⑨ 域名邮箱枚举

**作用**:从一个域名挖出**所有公开可见的邮箱地址**(管理员、support、销售、技术联系人等),类 [theHarvester](https://github.com/laramies/theHarvester) + [Hunter.io](https://hunter.io) 的混合方案。

**操作示范**:

```
请选择功能 : 9
请输入要挖邮箱的目标域名(如 example.com): example.com

是否包含活跃子域名一起爬取?
   [ 1 ] 是(默认,更全面)  [ 2 ] 否(仅主域,更快)
  请选择 [1/2,默认 1] : 1

爬取深度?
   [ 1 ] 标准 200 页(默认,约 1 分钟)  [ 2 ] 深度 500 页(约 3-4 分钟)  [ 3 ] 极速 50 页(约 20 秒)
  请选择 [1/2/3,默认 1] : 1

从姓名生成模式邮箱?用逗号分隔多人(留空跳过): John Doe, Jane Smith

是否做 SMTP 验证(高调 — 仅对自己拥有的域使用)?
   [ 1 ] 是  [ 2 ] 否(默认)
  请选择 [1/2,默认 2] : 2
```

**输出示例**:

```
============= 域名邮箱枚举 =============

 域名邮箱:example.com
 共找到 12 个邮箱(爬取 47 页 · sitemap:✓)
 crawl=8, pattern=2, whois=1, crtsh=1

 ┌─ 来自被动数据源(crt.sh / WHOIS) (2) ─
 [ + ] admin@example.com           (whois)
 [ + ] hostmaster@example.com      (crtsh)

 ┌─ 来自深度爬取 (8) ─
 [ + ] contact@example.com         (crawl)  https://example.com/contact
 [ + ] support@example.com         (crawl)  https://example.com/support
 [ + ] press@example.com           (crawl)  https://example.com/press
 ...

 ┌─ 来自模式生成(未验证的猜测) (2) ─
 [ + ] john.doe@example.com        (pattern)
 [ + ] jane.smith@example.com      (pattern)
```

**4 阶段实时反馈**(沿用 v1.3.3 stage 风格):

```
阶段 1/4:被动数据源(crt.sh / WHOIS / Bing / DDG / Wayback / GitHub)...
   [   crtsh] 1 个邮箱
   [   whois] 1 个邮箱
   [    bing] 0 个邮箱
   [     ddg] 0 个邮箱
   [ wayback] 0 个邮箱
   [  github] 0 个邮箱
阶段 2/4:发现可爬取的活跃子域名 ...
   3 个爬取目标
阶段 3/4:深度爬取 3 个目标(robots.txt + sitemap.xml + BFS)...
   [example.com] pages=47/66 emails=8 queue=14
   [1/3] example.com  pages=47 emails=8
阶段 3.5/4:从提供的姓名生成模式邮箱 ...
   2 个模式邮箱生成
```

> 阶段 1 实际是 **6 个被动源并发**(crt.sh / WHOIS / Bing / DuckDuckGo / Wayback / GitHub),总耗时约等于最慢的那个源。阶段 3 的 `pages=47/66`:`--max-pages` 是**总页数预算**,按爬取目标均分(默认 200 ÷ 3 个目标 ≈ 66 页/目标,每个至少 10 页)。

**数据来源(6 个被动源并发 + 深度爬虫 + 可选项)**:

| 来源 | 提取的内容 | 默认开关 |
|---|---|---|
| **crt.sh CT 日志** | 证书 SAN/email 字段(管理员邮箱常出现) | ✓ |
| **WHOIS 联系人** | 注册联系人邮箱(`registrant.email` / `admin.email`) | ✓ |
| **Bing 搜索** | `"@domain" site:domain` 搜索结果页中的邮箱(免费、无需 key) | ✓ |
| **DuckDuckGo 搜索** | HTML 版搜索结果页中的邮箱(免费、无需 key) | ✓ |
| **Wayback Machine** | 历史归档快照里的邮箱(能挖到已下线页面) | ✓ |
| **GitHub commits** | commit 作者邮箱(`SPYEYES_GITHUB_TOKEN` 可放宽限速) | ✓ |
| **深度爬取主域** | robots.txt + sitemap.xml + BFS 内部链接(默认总预算 200 页 / 深度 5) | ✓ `--no-crawl` 关 |
| **含 alive 子域** | 复用子域名枚举,只爬有 HTTP 响应的活跃子域 | ✓ `--no-include-subdomains` 关 |
| **模式生成** | 用户给姓名 → `firstname.lastname` / `f.lastname` / `fl` 等 ~10 变体 | opt-in `--guess` |
| **SMTP 验证** | HELO+MAIL+RCPT 探测候选邮箱真实性 | opt-in `--verify-smtp` |

**CLI 选项**:

| 选项 | 作用 |
|---|---|
| `--no-crawl` | 跳过深度爬取,仅 6 个被动源(最快) |
| `--no-include-subdomains` | 仅爬主域,不含 alive 子域(更快) |
| `--max-pages N` | 爬取**总**页数预算(默认 200,最大 2000),按爬取目标均分 |
| `--crawl-depth N` | BFS 深度(默认 5) |
| `--ignore-robots` | 忽略 robots.txt(用慎重) |
| `--guess "John Doe,Jane Smith"` | 用姓名生成 ~10 个模式邮箱 |
| `--verify-smtp` | SMTP 验证(**高调** — 仅对自己拥有/授权的域) |

**示例**:

```bash
python3 -m spyeyes domain-emails example.com               # 默认:被动 + 爬虫 + alive 子域
python3 -m spyeyes domain-emails example.com --no-crawl    # 仅 6 个被动源(最快)
python3 -m spyeyes domain-emails example.com --max-pages 500 --no-include-subdomains   # 主域深爬
python3 -m spyeyes domain-emails example.com --guess "John Doe,Jane Smith"
python3 -m spyeyes domain-emails example.com --verify-smtp # 高调,自己的域才用
python3 -m spyeyes domain-emails example.com --json | jq '.emails[]'

# 8 种报告全支持
python3 -m spyeyes domain-emails example.com --save report.html      # mailto: 链接可点
python3 -m spyeyes domain-emails example.com --save report.csv       # 4 列:address,sources,page,verified
python3 -m spyeyes domain-emails example.com --save report.graph.html # 力导向图
```

**已知限制**:

- 只能找到**已经公开出现**在网页/CT 日志/WHOIS 中的邮箱;深藏在登录页、PDF、内网的找不到
- HackerTarget 限速会跨命令影响(子域名也用这个源)
- 模式生成需要姓名输入(无人提供 = 跳过此阶段)
- SMTP 验证经常被大厂(Gmail/Outlook)拒绝 RCPT,准确率不稳定

**安全声明**:

- **默认行为合规**:被动 OSINT 源 + 礼貌爬虫(遵守 robots.txt,500ms 单域速率限制)
- **爬虫不出圈**:只抓目标域及其子域下的 URL(robots.txt 里声明的 sitemap 也一样),不会跟随外链去爬第三方站点
- **`--ignore-robots` / `--verify-smtp` 高风险**:仅对自己拥有或获得授权的域使用
- 爬虫与正常浏览器无异,但**仍建议**有授权
- SMTP 验证连接目标 MX 服务器,**强烈建议**仅自己域使用(否则可能被对方反爬墙记录)

---

### ⑩ Diff 模式 + 批量

#### Diff 模式 — OSINT 持续监控

**作用**:对比两次子域名扫描的 JSON 输出,挖出**新增 / 消失 / 变更**的子域。OSINT 持续监控、红队跟踪目标基础设施变化、SOC 检测异常子域上线 — 都用得上。

**用法**:

```bash
# 第 1 次扫描,保存 JSON 快照
python3 -m spyeyes subdomain example.com --json > ~/snapshots/2026-05-09.json

# 几天后再扫,保存新快照
python3 -m spyeyes subdomain example.com --json > ~/snapshots/2026-05-13.json

# 对比 — 输出 added/removed/changed
python3 -m spyeyes diff ~/snapshots/2026-05-09.json ~/snapshots/2026-05-13.json

# 导出 8 种格式之一
python3 -m spyeyes diff old.json new.json --save diff_report.html
python3 -m spyeyes diff old.json new.json --save diff_report.pdf
python3 -m spyeyes diff old.json new.json --json | jq '.added'
```

**输出结构**:

```json
{
  "domain": "example.com",
  "added": [{...}, ...],          // 新增的 host 列表
  "removed": [{...}, ...],         // 消失的 host 列表
  "changed": [{                     // 同一 host 但属性变了
    "host": "api.example.com",
    "changes": {
      "a": {"before": ["1.2.3.4"], "after": ["5.6.7.8"]},
      "http_status": {"before": 200, "after": 401}
    },
    ...
  }],
  "_stats": {"added": 3, "removed": 1, "changed": 2, "unchanged": 156}
}
```

**对比字段**:`alive / a / aaaa / cname / http_status / title`,**列表顺序无关**(`['1.1.1.1', '2.2.2.2']` 与 `['2.2.2.2', '1.1.1.1']` 视为同一)。

#### 批量域名扫描

**作用**:一次扫描多个域,每个域写独立报告。运维 / 红队批量审计常用。

```bash
# 准备域名列表
cat > targets.txt <<EOF
# 注释行被忽略
example.com
example.org

akxan.com
EOF

# 跑批量
python3 -m spyeyes subdomain --batch targets.txt --batch-save-dir reports/ --alive-only

# 输出
# == 批量扫描 3 个域名 ==
# [1/3] 扫描 example.com  ...
# [2/3] 扫描 example.org  ...
# [3/3] 扫描 akxan.com  ...
# == 批量扫描完成 ==
#   ✓ example.com   total= 2000  alive=    0
#   ✓ example.org      total=   84  alive=   33
#   ✓ akxan.com     total=  XX   alive=    Y

# 每个域单独 HTML 报告
ls reports/
# subdomain_example.com.html  subdomain_example.org.html  subdomain_akxan.com.html
```

**特点**:
- 每行一个域名,`#` 注释 + 空行自动跳过
- `--batch-save-dir` 自动创建目录,每个域写 `subdomain_<domain>.<ext>`;扩展名取 `--save`(默认 `.html`)
- 批量模式下 `--save r.pdf` **只决定报告格式**,必须配合 `--batch-save-dir` 才会写文件(只给 `--save` 会打印警告)
- 任一域扫描失败,整体退出码为 `1`(全部成功才是 `0`)
- `--alive-only` 在 batch 下对每个域独立生效
- Ctrl+C 中断时显示"已完成 N/M",已跑的不丢
- `--workers` / `--timeout` / `--bruteforce` 等所有 flag 都对每个 domain 生效

**典型场景**:

```bash
# 监控公司全部子公司域名
spyeyes subdomain --batch company_domains.txt --batch-save-dir weekly/ \
                   --alive-only --bruteforce

# 红队批量审计客户授权范围
spyeyes subdomain --batch authorized_scope.txt --batch-save-dir audit/ \
                   --alive-only --no-js-extract

# 注:批量 + diff 可组合 — 用 `--save x.json --batch-save-dir snap_0509/` 跑批得到每域 JSON 快照,
#     几天后换个目录再跑一次,然后对每个域执行
#     `spyeyes diff snap_0509/subdomain_a.com.json snap_0513/subdomain_a.com.json`
```

---

### ⑪ 综合调查

**作用**:只输入一个域名,自动把 WHOIS / MX / 子域名 / 域名邮箱 4 个查询**并发**跑完,再沿着结果做**单向接力(pivot)**:活跃子域的 IP → IP 情报;看起来像真人的邮箱 local-part → 用户名扫描。最后汇成一份整合档案(dossier)。目前只支持**域名**作为输入。

**操作示范**(菜单 `[10]`):

```
请选择功能 : 10
请输入目标域名 : example.com

接力深度?
   [ 1 ] 标准 (子域→IP, 邮箱→用户) — 默认
   [ 2 ] 仅原子查询 (不接力,更快)
  请选择 [1/2, 默认 1] : 1
```

**工作流程**:

1. **阶段 1 —— 4 个原子任务并发**:`whois` + `mx` + `subdomain`(含 HTTP probe,`--no-probe` 关闭)+ `domain-emails`(轻量模式:只爬主域,约 80 页)
2. **阶段 2a —— 子域 → IP**:活跃子域解析出的 IP 去重后逐个查 IP 情报(国家 / ASN / 组织),最多 `--max-pivot-ips` 个(默认 20)
3. **阶段 2b —— 邮箱 → 用户名**:邮箱按"像不像真人名"打分排序,取前 `--max-pivot-emails` 个(默认 15),用 local-part 做用户名扫描(默认 quick 模式,跳过 `other` 长尾;`--no-quick` 全扫)。`noreply / info / admin / support / contact / sales ...` 等角色账号**自动跳过**
4. 全程 `[N/M] ✓ task` 实时进度(只在 TTY 显示,`--json` / 管道时静默)

接力是**单向**的:域名是根,IP 和用户名都是叶子,不会再反查域名,所以不会出现循环。任何一个任务失败只记在自己的槽位,其它任务照常进行。

**CLI 选项**:

| 选项 | 作用 |
|---|---|
| `--depth {0,1}` | 接力深度:`1` = 带 pivot(默认),`0` = 只跑阶段 1 的 4 个原子任务 |
| `--budget 秒` | 时间预算(默认 300);超出后**剩余的 pivot 会被跳过** —— 阶段 1 的任务各有自己的超时,总会跑完;`0` = 不限 |
| `--max-pivot-ips N` | 子域 → IP 接力上限(默认 20) |
| `--max-pivot-emails N` | 邮箱 → 用户名接力上限(默认 15) |
| `--no-quick` | 用户名接力也扫 `other` 长尾平台(更全,更慢) |
| `--no-probe` | 子域阶段跳过 HTTP probe(更快) |

**示例**:

```bash
python3 -m spyeyes investigate example.com                            # 默认:4 原子任务 + 接力
python3 -m spyeyes investigate example.com --depth 0                  # 只要 whois / mx / 子域 / 邮箱,不接力
python3 -m spyeyes investigate example.com --budget 120 --max-pivot-emails 5
python3 -m spyeyes investigate example.com --json | jq '._stats'      # tasks / pivots / graph / _stats
python3 -m spyeyes investigate example.com --save dossier.html        # 整合 HTML 档案
python3 -m spyeyes investigate example.com --save dossier.graph.html  # 调查关系图
```

**报告**:Markdown / HTML / TXT / CSV 都有综合调查专属章节;`.graph.html` 画出调查关系图(域名为根 → 子域 / IP / MX / 邮箱 → 平台账号);PDF / XMind 使用通用布局;JSON 始终包含完整数据(`tasks` / `pivots` / `graph` / `_stats`)。

**安全声明**:综合调查只是把上面几个功能串起来,默认不做字典爆破(除非设置了 `SPYEYES_BRUTEFORCE=1`)、不做 SMTP 验证;但它会对目标域发起子域探测和网页爬取,并对邮箱 local-part 做跨平台用户名扫描 —— **请仅对自己拥有或获得书面授权的目标使用**。

---

### ⑫ 一键升级 + 版本检查

#### 启动版本检查

- 每次运行时在**后台线程**查询 GitHub Releases 最新版本,结果缓存 24 小时(`~/.spyeyes/.update_check.json`),不拖慢启动
- 有新版时在 **stderr** 打一行提示(不会污染 `--json` 管道输出);离线 / API 失败完全静默
- 关闭:加 `--no-update-check`,或设置 `SPYEYES_NO_UPDATE_CHECK=1`

#### 三个升级入口

| 入口 | 行为 |
|---|---|
| **菜单启动提示** | 进交互菜单时,若缓存发现新版且在 TTY 中,先问 `🆕 新版本 vX 可用 (当前 vY)。现在升级? [Y/n]`;选 N 直接进菜单(下次启动仍会提示) |
| **菜单 `[12]`** | 强制刷新(绕过 24h 缓存)→ 显示版本对比 + 更新说明链接 → 问 `[Y/n]` → 升级 |
| **CLI `spyeyes upgrade`** | 同上;`--yes` / `-y` 跳过确认,`--check` 只查不升 |

#### 按安装方式自适应

| 安装方式 | 升级动作 |
|---|---|
| `pip install git+https://…` | 自动执行 `python -m pip install --upgrade --no-input git+https://github.com/Akxan/SpyEyes.git@<release-tag>`(钉到提示里宣布的那个 tag) |
| `pipx install …` | 自动执行 `pipx upgrade spyeyes`;PATH 里找不到 `pipx` 时改为显示等价的 pip 命令并以退出码 1 结束 |
| 源码(git clone / `pip install -e .`) | **不自动执行**,只提示 `git pull && pip install -e .`(避免和本地改动冲突) |
| 装在 Homebrew / 系统 Python 里(PEP 668「外部管理环境」) | pip 默认拒绝安装。SpyEyes 会说明情况、推荐改用 pipx,并**单独问一次** `[y/N]`(默认否);同意后才带 `--break-system-packages` 原地升级。脚本里用 `spyeyes upgrade --yes --break-system-packages` |
| `pip install --user` 装在用户目录 | 自动加 `--user`,保证新版不会被用户目录里的旧副本遮住 |

> 💡 **推荐用 pipx 安装**(独立虚拟环境,不碰系统 Python,升级最省心)。从 Homebrew / 系统 Python 迁移:
> ```bash
> python3 -m pip uninstall -y --break-system-packages spyeyes   # 用当初安装 spyeyes 的那个 python
> brew install pipx && pipx ensurepath                           # Debian/Ubuntu: sudo apt install pipx
> pipx install git+https://github.com/Akxan/SpyEyes.git
> ```

- 升级成功后进程以退出码 0 结束,并提示**重新启动 spyeyes**(当前进程里加载的还是旧代码)
- 用户数据 `~/.spyeyes/`(语言、历史、API key)保持不动
- `spyeyes upgrade` 是显式请求,即使设置了 `SPYEYES_NO_UPDATE_CHECK=1` 也会去查

**用法**:

```bash
spyeyes upgrade --check            # 只查版本,不安装
spyeyes upgrade                    # 查 → 问 [Y/n] → 升级
spyeyes upgrade --yes              # 不问,直接升级(脚本 / 无 TTY 场景必须加)
spyeyes upgrade --lang en --no-color   # 通用选项同样可用
spyeyes upgrade --yes --break-system-packages   # Homebrew / 系统 Python 里原地升级(显式同意绕过 PEP 668)
```

**`upgrade` 退出码**:

| 退出码 | 含义 |
|---|---|
| `0` | 升级成功 / 已是最新 / 用户取消 / `--check` / 源码安装(只提示命令) |
| `1` | 网络错误(连不上 GitHub Releases)或 pipx 缺失 |
| `2` | 无 TTY 又没加 `--yes`;或 PEP 668 环境下无 TTY 又没加 `--break-system-packages` |
| `130` | Ctrl-C |
| 其它 | 透传 pip / pipx 的退出码 |

---

## 命令行模式（脚本调用）

除了交互菜单，工具还支持**命令行参数模式**，方便集成到脚本里。

### 基本用法

```bash
# 直接查询（输出彩色文本）
python3 -m spyeyes ip 8.8.8.8
python3 -m spyeyes myip
python3 -m spyeyes phone +8613800138000
python3 -m spyeyes user torvalds
python3 -m spyeyes whois example.com
python3 -m spyeyes mx gmail.com
python3 -m spyeyes email someone@gmail.com
python3 -m spyeyes subdomain example.com
python3 -m spyeyes domain-emails example.com
python3 -m spyeyes investigate example.com
python3 -m spyeyes diff old.json new.json
python3 -m spyeyes history
python3 -m spyeyes upgrade --check
```

全部 14 个子命令：`ip` · `myip` · `phone` · `user` · `permute` · `whois` · `mx` · `email` · `subdomain` · `domain-emails` · `history` · `diff` · `investigate` · `upgrade`。`whois` / `mx` 可一次传多个域名批量查询。

### 通用选项（在 subcommand 前后均可）

| 选项 | 作用 |
|---|---|
| `--json` | 输出 JSON 而非美化文本，方便管道处理 |
| `--save DIR/` | 把结果保存为 `DIR/<功能>_<时间戳>.json`（目录形式固定 JSON） |
| `--save FILE` | 按后缀选报告格式：`.json` `.md` `.html` `.pdf` `.txt` `.csv` `.xmind` `.graph.html`（见下文 8 种报告格式） |
| `--no-color` | 禁用彩色输出（也支持 [`NO_COLOR`](https://no-color.org/) 环境变量；非 TTY 自动关闭颜色） |
| `--lang zh\|en` | 强制语言（覆盖配置文件 + 环境变量，不写入配置）|
| `--no-update-check` | 本次运行跳过 GitHub 版本检查（等价 `SPYEYES_NO_UPDATE_CHECK=1`） |
| `--version` | 显示版本号 |

### user 子命令专属选项

| 选项 | 作用 |
|---|---|
| `--workers N` | 并发线程数，默认 **150**（已优化到 Sherlock 级速度），范围 1-200 |
| `--timeout T` | 单平台 HTTP 超时秒数，默认 5 |
| `--all` | 显示所有平台（含未命中），默认仅显示命中 |
| `--quick` | 跳过 "other" 长尾，仅扫主流 ~1411 个（v1.1.0 重新校准） |
| `--category CAT,CAT,...` | 只扫指定类别：`code` / `social` / `chinese` / `spanish` / `forum` / 等 |
| `--recursive` | **v1.1.0**：递归扫描——抓取命中页面提取次级用户名继续扫 |
| `--depth N` | **v1.1.0**：递归深度（0-2，默认 2，仅与 `--recursive` 配合） |

> 递归扫描时如果初始用户名本身不合法（空、超过 64 字符等），会直接报错并以退出码 `1` 结束。

```bash
python3 -m spyeyes user torvalds --workers 50 --all
python3 -m spyeyes user torvalds --recursive --depth 2     # v1.1.0 递归挖关联账号
python3 -m spyeyes user torvalds --category code,social    # 只扫代码与社交
```

### 用户名变形（permute 子命令 / 菜单 [4]→2/3）

灵感来自 Maigret `--permute`，从一个名字生成多个变形（化名/小号常用模式）：

```bash
# 仅生成变形（不扫描）
python3 -m spyeyes permute "John Doe"
# → johndoe / doe.john / j.doe / jdoe / jd / ... 数十个

# v1.2.0：Maigret 风格 method=all 加 _前缀 / 后缀_
python3 -m spyeyes permute "John Doe" --method all
# → 在 strict 基础上额外加 _johndoe / johndoe_ 等

# 生成 + 自动扫描每个变形（耗时但效果好）
python3 -m spyeyes permute "Linus Torvalds" --scan --quick

# JSON 管道
python3 -m spyeyes permute "John Doe" --json | jq -r '.permutations[]'

# 中文姓名（Unicode 也支持）
python3 -m spyeyes permute "张 三" --lang zh
```

**变形规则（v1.2.0 Maigret-style）**：
- 多片段：所有子集大小 `2..N` 的全排列 × 4 种分隔符 `['', '_', '-', '.']`
- size-2 排列额外生成首字母变形：`jdoe` / `j.doe` / `jd` / `j_d` 等
- `--method all`：在 strict 基础上加 `_前缀` / `后缀_` 变体
- 安全限制：最多 4 个输入片段、200 个输出（防 DoS）；v1.2.0 排序优先非装饰变体（method=all 时不会被 `_xxx` 占满前 200）
- 自动小写、去重

**交互菜单 `[4]` 也内置变形**：进入用户名追踪后选策略 `2`（变形+扫描）或 `3`（仅生成）。

### 8 种报告格式

按 `--save <文件>` 后缀自动分发，所有格式都跟随当前 UI 语言（中/英）：

| 格式 | 后缀 | 实现 / 依赖 | 适用场景 |
|---|---|---|---|
| **JSON** | `.json` | stdlib | 管道处理、脚本 |
| **Markdown** | `.md` | stdlib（含注入转义） | GitHub Issue / 笔记 |
| **HTML** | `.html` | stdlib + 内嵌 CSS | 浏览器查看、邮件附件 |
| **PDF** | `.pdf` | reportlab（可选 `[pdf]`） | 正式调查报告 |
| **TXT** | `.txt` | stdlib | 复制粘贴到 ticket / IM / 邮件 |
| **CSV** | `.csv` | csv stdlib + 公式注入防护（UTF-8 BOM，Excel 直接打开中文不乱码） | Excel / Sheets / pandas |
| **XMind** | `.xmind` | zipfile + xml stdlib | 思维导图（XMind 8 兼容） |
| **Graph** | `.graph.html` | D3.js v7 (CDN) | 力导向图，可点击跳转 |

**安装可选 PDF 依赖**：

```bash
pip install reportlab       # 仅 PDF 需要；其它 7 种零依赖
pip install -e ".[pdf]"     # 源码目录内的等价写法（项目尚未发布到 PyPI，暂不能 pip install "spyeyes[pdf]"）
```

**示例**：

```bash
python3 -m spyeyes user torvalds --save investigation.pdf
python3 -m spyeyes user torvalds --save investigation.html
python3 -m spyeyes user torvalds --save investigation.xmind
python3 -m spyeyes user torvalds --save investigation.graph.html  # D3 力导向图
python3 -m spyeyes ip 8.8.8.8 --save ip_report.html --lang en
python3 -m spyeyes whois example.com --save whois.csv
```

**报告内容会跟随 `--lang`**：中文 UI 输出 "SpyEyes 报告/查询/平台/主页地址" 等，英文 UI 输出 "SpyEyes Report/Query/Platform/Profile URL" 等。CSV 列头也本地化（zh: `分类,平台,主页地址,状态` / en: `Category,Platform,Profile URL,Status`）—— 下游 pandas/jq 等需要稳定列名时请用 `--lang en` 或直接读 JSON。

**所有用户输入字段都做 escape 防注入**：
- HTML/Graph：`& < > " '` HTML escape
- CSV：单元格首字符为 `= + - @ \t \r` 时前置 `'` 防 Excel/Sheets 公式执行
- Graph：JSON 内嵌 `<script>` 时 `</` → `<\/` 防 `</script>` 注入
- Markdown：`| \r \n` 单行化 + `` ` `` 转义防 backtick 跳出 inline code

**`--save DIR/`（目录形式）固定输出 JSON** —— 自动生成 `<prefix>_<时间戳>.json` 文件名。要选具体格式必须给文件名（含后缀）。

### 交互式连续保存

进入"保存报告 → 是"后会弹出 1-8 数字格式选择菜单。默认目录按 v1.8.0 智能路由：**源码运行 → `<项目根>/Downloads/`**，**pip / pipx 安装 → `~/Downloads/spyeyes/`**，设置 `SPYEYES_REPORTS_DIR=path` 则始终用它。保存后追问"继续保存其它格式？"，可在一次会话中同时输出 HTML + PDF + XMind 等多种格式：

```
请选择报告格式 / Choose report format:
  [ 1 ] JSON               (.json)
  [ 2 ] Markdown           (.md)
  [ 3 ] HTML               (.html)
  [ 4 ] PDF                (.pdf, 需 reportlab)
  [ 5 ] 纯文本             (.txt)
  [ 6 ] CSV                (.csv)
  [ 7 ] XMind 8 思维导图   (.xmind)
  [ 8 ] 力导向图           (.graph.html, D3.js — 用户名 / 子域名 / 邮箱 / 综合调查)
请选择 [1-8，默认 1] : 3

文件名 [默认 /path/to/SpyEyes/Downloads/username_torvalds_20260502-061500.html]:

继续保存其它格式？
  [ 1 ] 是   [ 2 ] 否（默认）
请选择 [1/2，默认 2] : 1
（再次弹出 1-8 菜单 ...）
```

### 示例：与 jq 联动

```bash
# 查 IP 国家
python3 -m spyeyes ip 8.8.8.8 --json | jq -r '.country'

# 查电话号码归属
python3 -m spyeyes phone +8613800138000 --json | jq -r '.location'

# 批量查 IP
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 -m spyeyes ip "$ip" --json | jq -r '.ip + " -> " + .country'
done
```

### 示例：批量保存

```bash
mkdir results
python3 -m spyeyes user torvalds --save results
python3 -m spyeyes mx gmail.com --save results
ls results/
# username_torvalds_20260429-123456.json
# mx_gmail.com_20260429-123457.json
```

### 帮助命令

```bash
python3 -m spyeyes -h         # 总览
python3 -m spyeyes ip -h      # 查看 ip 子命令的所有参数
python3 -m spyeyes investigate -h
```

### 退出码（脚本编程友好）

| 退出码 | 含义 |
|---|---|
| `0` | 成功 |
| `1` | 查询失败（如 API 报错、域名不存在）；批量 `whois` / `mx`（多个域名）或 `subdomain --batch` 中**任一项失败**也返回 `1` |
| `2` | 参数 / 用法错误（如 `diff` 读不到 JSON 文件） |

`upgrade` 有自己的退出码约定（无 TTY 未加 `--yes` → `2`，Ctrl-C → `130` 等），见 [⑫ 一键升级](#-一键升级--版本检查)。

### 查询历史（history 子命令）

每次 CLI 查询会把**元数据**（命令、查询对象、命中数等，不含完整结果）追加到 `~/.spyeyes/history.jsonl`：

```bash
python3 -m spyeyes history                     # 最近 20 条
python3 -m spyeyes history --limit 50          # 最多 200
python3 -m spyeyes history --search torvalds   # 按查询内容过滤
SPYEYES_NO_HISTORY=1 python3 -m spyeyes ...    # 本次不记录（也可写进 ~/.spyeyes/env）
```

---

## 常见问题排查

### Q1: macOS 跑 `pip3 install` 提示 `error: externally-managed-environment`

**原因**：Homebrew 的 Python 启用了 PEP 668 保护。
**解决**：用虚拟环境，参考 [macOS 安装](#macos-安装) 第 3-4 步。

---

### Q2: 提示 `command not found: lcd`

**原因**：你不小心把 `cd` 输成了 `lcd`。
**解决**：复制粘贴时检查首字母，正确命令是 `cd 路径`。

---

### Q3: 提示 `No module named spyeyes`

**原因**：当前目录不在 SpyEyes 项目里，或没装好依赖。
**解决**：先 `cd /path/to/SpyEyes` + `source .venv/bin/activate`，再运行 `python3 -m spyeyes`。
或者 `pip install .` 后任意目录直接 `spyeyes ...`。

---

### Q4: 选项 4 用户名查询大量显示「未找到」

**原因**：现代社交平台普遍有反爬机制。本项目已使用 Chrome User-Agent + `must_contain` 双重检测大幅降低误报，但 LinkedIn / Instagram / TikTok 等强登录墙平台仍可能误判。
**解决**：
- 用 `--all` 看完整结果而非默认压缩输出
- 试试更高 `--workers` 加速
- 或者只看主流平台：`python3 -m spyeyes user xxx --json | jq '.[] | select(.) | .' | head`

---

### Q5: 终端中文显示成乱码

**原因**：终端字符编码不是 UTF-8。
**解决**：
- macOS / Linux：`export LANG=zh_CN.UTF-8`
- Windows PowerShell：`chcp 65001`
- 或者直接用英文 UI：`python3 -m spyeyes --lang en`

---

### Q6: 想退出工具但 `0` 之后没反应

**原因**：选项 0 的 `exit` 是 Python 的 `exit` 函数，正常情况下会立即退出。
**解决**：直接按 `Ctrl + C` 强制退出。

---

### Q7: 想换语言怎么办？

**菜单方式**：在主菜单选 `[ 11 ] 切换语言 / Language`，立即生效并保存到 `~/.spyeyes/config.json`。

**CLI 方式**：每次加 `--lang en` 或 `--lang zh`（覆盖一次，不写入配置）。

**重置语言选择**：删除 `~/.spyeyes/config.json`，下次启动会重新弹出语言选择器。

---

### Q8: 平台数据库怎么更新？

```bash
python3 tools/build_platforms.py
```

会从 Maigret + Sherlock + WhatsMyName 三个上游 GitHub 仓库拉取最新 sites 数据，过滤、去重、自动分类后覆盖 `spyeyes/data/platforms.json`。建议每月跑一次。

---

### Q9: 怎么升级 SpyEyes？

- 源码安装（git clone）：`git pull && pip install -r requirements.txt`（装过 `pip install -e .` 的话再跑一次 `pip install -e .`）
- pip / pipx 安装：`spyeyes upgrade`，或在菜单选 `[ 12 ]`

详见 [⑫ 一键升级](#-一键升级--版本检查)。

---

### Q10: 颜色看着累 / 不想要颜色 / 想在脚本里用

- **默认配色**(v1.8.5 起):正文用终端自己的文字颜色,编号和标签加粗,颜色只用在阶段标题(青)、警告(黄)、错误(红)、星标(品红)等少量地方,且都是普通亮度,深色 / 浅色背景都清晰,不刺眼
- **想要旧版亮绿风格**:设 `SPYEYES_THEME=classic`(可写进 `~/.spyeyes/env`)
- **完全不要颜色**:加 `--no-color`,或设置环境变量 `NO_COLOR=1`

输出不是终端(管道 / 重定向)时会自动关闭颜色,进度信息写 stderr 且只在 TTY 时显示,`--json` 输出可以直接接 `jq`。

---

## 已知限制

1. **数据语言**：`ipwho.is` 返回的城市/地区名仍为英文（国家名已通过本地映射表译成中文）
2. **用户名扫描准确率有限**：约 1753 个 `other` 长尾平台（主要来自 Maigret）仅做基本检测，有 20-30% 误报
3. **登录墙平台**：LinkedIn / Instagram / TikTok 强反爬，命中率较低
4. **WHOIS 速度**：跨地区查询某些 TLD 时较慢（10-15 秒）
5. **无代理支持**：默认走系统直连，无内置 HTTP/SOCKS 代理选项
6. **国家中文映射表**：约 180 个，极少数小国家可能落到英文 fallback

---

## 法律与道德提醒

SpyEyes 收集的均为**公开信息**，但请牢记：

- ❌ **不要**用本工具骚扰、跟踪或人肉搜索任何人
- ❌ **不要**把查询到的他人个人信息公开发布或商用
- ❌ **不要**对未授权的网络资产进行扫描
- ✅ 仅对**自己拥有**的资产、**自己授权**的目标，或**完全公开**的信息（如自查）使用
- ✅ 在企业/红队场景使用时，**必须**有书面授权

不同司法管辖区的相关法律：
- 中国：《个人信息保护法》《网络安全法》《数据安全法》
- 欧盟：GDPR
- 美国：CFAA（计算机欺诈与滥用法）

**违规使用工具产生的一切法律后果由使用者自行承担**。

---

## 项目地址

- 仓库：https://github.com/Akxan/SpyEyes
- 作者：[Akxan](https://github.com/Akxan)

如需提交问题或贡献代码，请前往上游 GitHub 仓库。
