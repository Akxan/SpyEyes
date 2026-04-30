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
- IDN（中文 / 韩文 / 日文域名）通过 punycode 支持

---

## [1.0.0] — 2026-04-30

🎉 **SpyEyes 首个稳定版本发布** —— 经过完整代码审计 + 多轮回归验证。

### ✨ Features 核心功能

- **🌐 IP 追踪** — IPv4 / IPv6 全支持，国家/城市/ISP/ASN/经纬度，国家中文名映射（180+ 国家）
- **📡 本机 IP 查询** — 一键显示当前公网出口 IP
- **📱 电话号码追踪** — 中文归属地 + 中文运营商 + 12 种号码类型 + 国际/E.164 格式
- **👤 用户名扫描** — **2067 个平台**（合并 Maigret + Sherlock + WhatsMyName 三大上游）
  - 46 中文圈（陆/台/港/星/马）+ 52 西语圈（西班牙/拉美）+ 83 成人/约会
  - **100 线程并发**，21 秒扫完
  - WAF 检测（Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai 等）
  - regex 预过滤 + ReDoS 长度限制防护（`MAX_USERNAME_LENGTH=64`）
  - HEAD 优化 + 405/501 GET 回退
  - 命中可信度排序（★★★/★★/★）
- **🔍 域名 WHOIS** — 注册商、日期、DNS 服务器、注册组织（含基本格式校验防注入）
- **📨 域名 MX 记录** — 列出所有 MX 优先级
- **✉️ 邮箱有效性验证** — 正则 + MX 联合检查（mx_error 收敛为枚举防信息泄漏）
- **📚 查询历史** — `~/.spyeyes/history.jsonl`（损坏行容错）+ `spyeyes history [--limit N] [--search STR] [--json]` 子命令查询
- **📝 Markdown 报告** — `--save report.md`（含 backtick / pipe / newline 注入转义）

### 🌍 i18n 国际化

- 完整中英双语 UI（~140 翻译键）
- 首次启动语言选择器
- CLI `--lang zh|en` + 菜单 `[8]` 切换
- 偏好持久化到 `~/.spyeyes/config.json`（损坏文件容错）

### 🔒 Security 安全

- **SSRF 防护** — `track_ip` 用 `ipaddress.ip_address()` 校验，拒绝路径穿越（`'../admin'`）和 query string 污染（`'8.8.8.8?key=leak'`）
- **ReDoS 防护** — `MAX_USERNAME_LENGTH = 64` 截断恶意输入，防止 `(a+)+` 类指数回溯
- **Domain 校验** — `whois`/`mx` 入口用 `DOMAIN_RE` 拒绝换行注入 / URL 形式 / 路径片段
- **MX 错误信息收敛** — DNS 内部细节（server IP / 解析器栈）不泄漏到 `--json` 输出，收敛为 `nxdomain` / `no_mx` / `invalid_domain` / `dns_failed` 枚举
- **Markdown 注入防护** — 用户输入字段（username / ip / domain）的 `|`、换行、反引号转义，防 GitHub PR / Obsidian / VSCode preview 渲染攻击
- **WAF 高精度指纹** — 使用各 WAF 自有的特定标志（`cdn-cgi/challenge-platform` 等）而非 `cloudflare` 等泛词，假阳性极低

### ⚡ Performance 性能

- **100 线程并发**扫描 + per-thread `requests.Session`（连接池复用）
- **HEAD 请求**（仅检测 status_code 时）+ 405/501 自动回退 GET
- **stream + 64KB 早停**（避免大页面下载）
- **拆分 timeout** `(connect=3s, read=5s)`
- **PLATFORMS 懒加载**（PEP 562 `__getattr__` + `__dir__` 保持 IDE 兼容）
- 实测：全 2067 平台 21s / `--quick` 9s / `--category code` 3s

### 🛠 Reliability 可靠性

- `safe_get` 拓宽异常列表覆盖 `urllib3.LocationParseError` / `UnicodeError` / `OSError`
- `_check_username` body 循环读取保证拿满 64KB（chunked encoding 短读取防护）
- `_batch_lookup` 支持 `Ctrl+C`（`cancel_futures=True`）
- `_maybe_save` `OSError` 友好提示而非抛 traceback
- `whois_lookup` 处理 python-whois 在罕见 TLD 返回 `None`
- `track_phone` 拒绝 `is_possible_number=False` 的号码（之前会被误记为成功）
- `tools/build_platforms.py` 原子写（`tempfile + os.replace`）+ 重试退避

### 🛠 Developer Experience

- **260 个 pytest 测试**，0.4 秒跑完
  - 主功能测试（220 个）+ 构建工具测试（40 个）
  - 覆盖：纯函数 + HTTP mock + 边界条件 + SSRF / ReDoS / Markdown injection / 信息泄漏 / Platform 不可变性 / 损坏文件容错 / 跨线程隔离
- **5 路审计全清** — ruff / mypy / bandit / pytest / fresh-eyes agent reviews
- **GitHub Actions CI** —
  - Lint job: ruff + mypy + bandit
  - Test matrix: macOS / Ubuntu / **Windows** × Python 3.10-3.13（8 jobs）
  - `--cov=spyeyes` / `--timeout=15` / `--timeout-method=thread` (Windows-safe)
  - `concurrency` 取消同分支重复 build
- **autouse fixture** 隔离 `_lang` / `Color` / thread-local Session / `_PLATFORMS_CACHE`
- **Apache License 2.0**（含明确专利授权 + 商标保护）
- **Dependabot** 自动依赖升级
- **`requirements.txt` 加上限**（`requests<3` 等）防上游 major 破坏 API
- **`requirements-dev.txt`** 分离开发依赖
- **`pyproject.toml`** 支持 `pip install` + `python_requires>=3.10`

### 🎨 UX

- ANSI Shadow 风格 SPYEYES Banner
- 实时进度条（仅 TTY 模式）
- 4 种扫描模式（菜单内选）：快速 / 完整 / 中文+西语 / 仅代码
- 批量域名 MX/WHOIS（`spyeyes mx domain1 domain2 ...`）
- `__version__ = '1.0.0'` + `--version` CLI flag

---

[Unreleased]: https://github.com/Akxan/SpyEyes/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Akxan/SpyEyes/releases/tag/v1.0.0
