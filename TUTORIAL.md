# GhostTrack 详细使用教程

> 本文档面向中文用户，带你从零开始安装、运行、理解 GhostTrack 的所有功能。

## 目录

1. [工具简介](#工具简介)
2. [系统要求与依赖](#系统要求与依赖)
3. [安装步骤](#安装步骤)
   - [macOS](#macos-安装)
   - [Linux (Debian/Ubuntu)](#linux-debianubuntu-安装)
   - [Termux (Android)](#termux-android-安装)
   - [Windows](#windows-安装)
4. [启动与菜单导航](#启动与菜单导航)
5. [功能详解](#功能详解)
   - [① IP 追踪](#-ip-追踪)
   - [② 查看本机 IP](#-查看本机-ip)
   - [③ 电话号码追踪](#-电话号码追踪)
   - [④ 用户名追踪](#-用户名追踪)
   - [⑤ 域名 WHOIS 查询](#-域名-whois-查询)
   - [⑥ 域名 MX 记录](#-域名-mx-记录)
   - [⑦ 邮箱有效性检查](#-邮箱有效性检查)
6. [命令行模式（脚本调用）](#命令行模式脚本调用)
7. [常见问题排查](#常见问题排查)
8. [已知限制](#已知限制)
9. [法律与道德提醒](#法律与道德提醒)

---

## 工具简介

GhostTrack 是一个用 Python 编写的命令行 OSINT 小工具，整个项目核心只有一个脚本 `GhostTR.py`，通过交互式菜单提供四种信息查询能力：

| 功能 | 数据来源 | 是否需要联网 |
|---|---|---|
| IP 地址归属查询 | 公开 API：`ipwho.is`（HTTPS，含国家中文名） | 是 |
| 查看本机出口 IP | 公开 API：`api.ipify.org` | 是 |
| 电话号码解析 | 本地 `phonenumbers` 库（中文运营商/归属地） | 否 |
| 用户名社交平台扫描 | 23 个社交平台 HTTP 探测，**并发 + 内容关键词** | 是 |
| 域名 WHOIS 查询 | `python-whois` 库（直连 RDAP / WHOIS 服务器） | 是 |
| 域名 MX 记录查询 | `dnspython`，使用系统 DNS 解析 | 是 |
| 邮箱有效性验证 | 本地正则 + MX 记录检查 | 是 |

> 所有数据查询均依赖**公开渠道**，工具本身不存储任何个人信息，也不绕过任何访问控制。

---

## 系统要求与依赖

- **Python**：3.8 或更高
- **Python 库**（已写入 `requirements.txt`）：
  - `requests` —— HTTP 请求
  - `phonenumbers` —— Google 的电话号码解析库
  - `dnspython` —— DNS 查询（MX 记录、邮箱验证）
  - `python-whois` —— WHOIS 查询
- **系统命令**：`git`（仅用于下载源码）
- **可选（开发）**：`pytest`（运行测试套件）

---

## 安装步骤

### macOS 安装

macOS 自带的或 Homebrew 安装的 Python 默认启用了 [PEP 668](https://peps.python.org/pep-0668/) 保护，**直接 `pip3 install` 会被拒绝**。推荐使用虚拟环境：

```bash
# 1. 安装 Python 和 git（如果没装）
brew install python3 git

# 2. 克隆项目
cd ~/Documents/Code            # 选择你想放代码的目录
git clone https://github.com/HunxByts/GhostTrack.git
cd GhostTrack

# 3. 创建虚拟环境并激活
python3 -m venv .venv
source .venv/bin/activate

# 4. 安装依赖
pip install -r requirements.txt

# 5. 运行
python3 GhostTR.py
```

每次新开终端要再用，记得先 `cd GhostTrack && source .venv/bin/activate`。
不想激活的话，直接用绝对路径调用 venv 里的 Python：

```bash
~/Documents/Code/GhostTrack/.venv/bin/python ~/Documents/Code/GhostTrack/GhostTR.py
```

### Linux (Debian/Ubuntu) 安装

```bash
sudo apt-get update
sudo apt-get install git python3 python3-pip
git clone https://github.com/HunxByts/GhostTrack.git
cd GhostTrack
pip3 install -r requirements.txt   # 较新发行版可能也需要 venv，参考上面的 macOS 方案
python3 GhostTR.py
```

### Termux (Android) 安装

```bash
pkg update
pkg install git python
git clone https://github.com/HunxByts/GhostTrack.git
cd GhostTrack
pip install -r requirements.txt
python GhostTR.py
```

### Windows 安装

```powershell
# 在官网 https://www.python.org 安装 Python 3，安装时勾选 "Add to PATH"
git clone https://github.com/HunxByts/GhostTrack.git
cd GhostTrack
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python GhostTR.py
```

---

## 启动与菜单导航

运行 `python3 GhostTR.py` 后会看到主菜单：

```
       ________               __      ______                __
      / ____/ /_  ____  _____/ /_    /_  __/________ ______/ /__
     / / __/ __ \/ __ \/ ___/ __/_____/ / / ___/ __ `/ ___/ //_/
    / /_/ / / / / /_/ (__  ) /_/_____/ / / /  / /_/ / /__/ ,<
    \____/_/ /_/\____/____/\__/     /_/ /_/   \__,_/\___/_/|_|

              [ + ]  C O D E   B Y  H U N X  [ + ]

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

**操作要点**：

- 输入对应**数字**后回车
- 每个功能跑完会提示「按回车键继续」—— 按回车回到主菜单
- 任何时候按 `Ctrl + C` 可以强制退出
- 输入非数字（如字母）会提示「请输入数字」并重新让你选

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
- 数据值（国家名、城市名）由 `ipwho.is` 返回，目前仅支持英文。如需中文国家名，需要自己加一层翻译表

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
 号码类型           : 移动电话号码
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

**作用**：把你输入的用户名拼到 23 个主流社交平台的 URL 中，逐一访问看是否返回 HTTP 200。

**操作示范**：

```
请选择功能 : 4
请输入用户名 : torvalds
```

**输出示例**：

```
========== 用户名信息 ==========

 [ + ] Facebook : https://www.facebook.com/torvalds
 [ + ] Twitter : https://www.twitter.com/torvalds
 [ + ] Instagram : https://www.instagram.com/torvalds
 [ + ] LinkedIn : 未找到该用户名 !
 [ + ] GitHub : https://www.github.com/torvalds
 [ + ] Pinterest : https://www.pinterest.com/torvalds
 ...
```

**覆盖的 23 个平台**：

Facebook · Twitter · Instagram · LinkedIn · GitHub · Pinterest · Tumblr · YouTube · SoundCloud · Snapchat · TikTok · Behance · Medium · Quora · Flickr · Periscope · Twitch · Dribbble · StumbleUpon · Ello · Product Hunt · Telegram · We Heart It

**重要说明**：

> 本项目已经做了优化（**并发扫描 + 内容关键词检测**），但准确率仍受平台反爬机制影响：
> - **优势**：使用 Chrome User-Agent + 10 线程并发，比串行版本快 10-20 倍（23 个平台 ~3 秒）
> - **检测逻辑**：HTTP 200 + 不包含 `not found` 等关键词
> - **局限**：登录墙严重的平台（LinkedIn、Instagram）依然会有误报
> - 需要更可靠的用户名搜索建议改用 [Sherlock](https://github.com/sherlock-project/sherlock)

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

## 命令行模式（脚本调用）

除了交互菜单，工具还支持**命令行参数模式**，方便集成到脚本里。

### 基本用法

```bash
# 直接查询（输出彩色文本）
python3 GhostTR.py ip 8.8.8.8
python3 GhostTR.py myip
python3 GhostTR.py phone +8613800138000
python3 GhostTR.py user torvalds
python3 GhostTR.py whois example.com
python3 GhostTR.py mx gmail.com
python3 GhostTR.py email someone@gmail.com
```

### 通用选项（在 subcommand 前后均可）

| 选项 | 作用 |
|---|---|
| `--json` | 输出 JSON 而非美化文本，方便管道处理 |
| `--save DIR` | 同时把结果保存为 `DIR/<功能>_<时间戳>.json` |
| `--no-color` | 禁用彩色输出 |

### 示例：与 jq 联动

```bash
# 查 IP 国家
python3 GhostTR.py ip 8.8.8.8 --json | jq -r '.country'

# 查电话号码归属
python3 GhostTR.py phone +8613800138000 --json | jq -r '.location'

# 批量查 IP
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 GhostTR.py ip "$ip" --json | jq -r '.ip + " -> " + .country'
done
```

### 示例：批量保存

```bash
mkdir results
python3 GhostTR.py user torvalds --save results
python3 GhostTR.py mx gmail.com --save results
ls results/
# username_torvalds_20260429-123456.json
# mx_gmail.com_20260429-123457.json
```

### 帮助命令

```bash
python3 GhostTR.py -h         # 总览
python3 GhostTR.py ip -h      # 查看 ip 子命令的所有参数
```

### 退出码（脚本编程友好）

| 退出码 | 含义 |
|---|---|
| `0` | 成功 |
| `1` | 查询失败（如 API 报错、域名不存在） |
| `2` | 参数错误 |

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

### Q3: 提示 `No such file or directory: GhostTR.py`

**原因**：当前目录不在 GhostTrack 项目里。
**解决**：先 `cd /path/to/GhostTrack`，再运行 `python3 GhostTR.py`。可用 `pwd` 确认当前所在目录。

---

### Q4: 选项 1 IP 查询返回 `KeyError: 'current_time'`

**原因**：`ipwho.is` 在 2024 年后移除了 `timezone.current_time` 字段，旧代码尚未适配。
**解决**：本项目的本地版本已经修复（删除了该行）。如果你拉的是上游原版，需要手动删除 `GhostTR.py` 中的最后一行 `print(f"{Wh} 偏移量 ..." ip_data["timezone"]["current_time"])`。

---

### Q5: 选项 4 用户名查询大量显示「未找到」

**原因**：判断逻辑过于简单（只看 HTTP 200），现代社交平台基本都有反爬机制。
**解决**：改用 [Sherlock](https://github.com/sherlock-project/sherlock) 等更专业的工具。

---

### Q6: 终端中文显示成乱码

**原因**：终端字符编码不是 UTF-8。
**解决**：
- macOS / Linux：在 shell 里执行 `export LANG=zh_CN.UTF-8`
- Windows PowerShell：执行 `chcp 65001`

---

### Q7: 想退出工具但 `0` 之后没反应

**原因**：选项 0 的 `exit` 是 Python 的 `exit` 函数，正常情况下会立即退出。
**解决**：直接按 `Ctrl + C` 强制退出。

---

## 已知限制

1. **数据语言**：`ipwho.is` 返回的城市/地区名仍为英文（国家名已通过本地映射表译成中文）
2. **用户名扫描不完美**：登录墙严重的平台（LinkedIn、Instagram、TikTok）依然有误报
3. **WHOIS 速度**：跨地区查询某些 TLD 时较慢（10-15 秒）
4. **无代理支持**：默认走系统直连，无内置 HTTP/SOCKS 代理选项
5. **国家中文映射表**：约 180 个，极少数小国家可能落到英文 fallback

---

## 法律与道德提醒

GhostTrack 收集的均为**公开信息**，但请牢记：

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

- 上游：https://github.com/HunxByts/GhostTrack
- 作者：[HunxByts](https://github.com/HunxByts)

如需提交问题或贡献代码，请前往上游 GitHub 仓库。
