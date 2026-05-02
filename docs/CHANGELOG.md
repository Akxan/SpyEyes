# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5 / Tor / I2P，借鉴 Maigret)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- 首次 upload 到 PyPI（package 重构已完成，`pip install .` 已 work，剩 `twine upload`）
- Docker 镜像
- 国旗 emoji 在终端的显示宽度修正（当前 `display_width` 8 段 if 链不准确）
- curl_cffi 浏览器指纹伪装可选（`spyeyes[stealth]`，绕过 Cloudflare）
- XMind 思维导图报告输出（中文调查交付场景）

---

## [1.1.0] — 2026-05-02

🚀 **Maigret 融合升级** —— 平台数 +57%，新增三大功能（用户名变形 / 递归扫描 / PDF 报告）。

### ✨ Features 新功能

- **📈 平台库扩容到 3164 个**（从 2067 → 3164，+57%）
  - 关键升级：解析 Maigret 的 **engine 模板系统**（Discourse / XenForo / phpBB / vBulletin），
    1097 个共享配置的论坛站点不再丢失。Maigret 单源贡献从 1422 → 2519。
  - 引入 Maigret 上游 **tags 体系**（cn/jp/ru/photo/dating 等），分类更精确。
  - 论坛类 285 → 733（+157%），代码类 50 → 115（+130%），游戏类 39 → 95。
- **🧬 用户名变形 (`spyeyes permute "John Doe"`)** —— 灵感来自 Maigret `--permute`
  - 自动生成 `johndoe` / `j.doe` / `john.d` / `jdoe` / `jd` 等 22+ 变形
  - 支持空白/逗号/分号/点/下划线/连字符多种分隔符
  - 支持 Unicode（中文姓名 "张 三" 也能生成 10 个变形）
  - 安全限制：最多 4 个输入片段、200 个输出（防 DoS）
  - `--scan` 选项：批量扫描每个变形（找化名常用）
- **🔁 递归扫描 (`spyeyes user X --recursive`)** —— 灵感来自 Maigret recursive search
  - 在命中页面用保守正则提取 `@handle` 与社交平台 URL 中的次级用户名
  - 自动在 visited 集合内去重（防循环），最多 2 层、每层 5 个新候选、每层抓 8 个页面
  - `--depth N` 控制递归深度（0-2）
  - 输出含层级总结：`[depth N] username → M hits`
- **📄 PDF 报告 (`--save report.pdf`)** —— 通过可选 `reportlab` 依赖
  - 安装方式：`pip install "spyeyes[pdf]"`
  - 适用所有子命令（IP/Phone/Username/WHOIS/MX/Email），表格+样式+分类小节
  - 用户输入字段全部 escape，防止 PDF 注入（继承 Markdown 防御）
  - 缺失依赖时友好降级提示，不打印 traceback
- **🌐 双语 i18n 完整支持** —— 9 个新键全部覆盖中英两版

### 🔧 Improvements 改进

- **build_platforms.py 工具升级**
  - `parse_maigret()` 现在解析 `engines` 字段（支持 `{urlMain}{urlSubpath}` 模板替换）
  - 引入 `MAIGRET_TAG_MAP` 把 Maigret tags 映射为 SpyEyes 分类
  - 旧格式回退更稳健：`sites` 顶层键缺失时仍工作
- **CLI epilog 示例更新** —— 新功能均在 `--help` 例子中列出
- **扫描模式标签重新校准** —— Quick 14s/Full 30s（因平台数翻倍）

### 🧪 Tests 测试

- **+42 个新测试**（全套 264 → 306）
- 新增覆盖：permute 边界、Unicode、递归 visited 去重、PDF 安全 escape、CLI 路由
- 多语言一致性：i18n 键完整性自动检查（防止某语言漏键）

### 📦 Packaging 打包

- `pyproject.toml` 新增 optional extras：`spyeyes[pdf]` / `spyeyes[all]`
- 主包仍保持 4 个核心依赖（零膨胀）
- `__version__` 1.0.0 → 1.1.0

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

- **264 个 pytest 测试**，0.4 秒跑完
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
