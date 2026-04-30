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

## [1.1.0] — 2026-04-30

🛠 **质量与稳健性大版本** —— 综合代码审计后的 5 个 P0 + 多项 P1/P2/P3 修复，
99 → 157 测试（+58），CI 增加 lint job + Windows 矩阵。

### 🐛 Fixed —— 真实 Bug

- **CI 红灯**：删除引用已删除 `_REDOS_RE` 的测试（[#test 重写](../tests/test_spyeyes.py)）
- **`_maybe_save` 目录判定 bug**：`--save somefile`（无后缀单文件）会被错判为目录
  并被 `os.makedirs` 创建为空目录。改为：仅当 target 显式以 `/` 结尾或路径已存在
  为目录时才视为目录
- **`_record_history` 'ok' 语义**：`data=None` 或空 `dict` 时 `'_error' not in {}`
  返回 True（误判为成功）→ 改为 `has_data and '_error' not in data`
- **HEAD 405 假阴性**：不支持 HEAD 的平台返回 405/501 时回退 GET
  （之前直接判 STATUS_NOT_FOUND，对 GitHub/Twitter 等平台误报）
- **`whois_lookup` None 返回**：python-whois 在罕见 TLD 返回 None 时
  `w.domain_name` AttributeError → 改为防御性检查
- **`safe_get` 异常拓宽**：覆盖 `urllib3.LocationParseError`（继承 `ValueError`）
  与 `UnicodeError` / `OSError`，避免穿透到顶层崩溃
- **`_check_username` body 短读取**：循环读取保证拿满 64KB
  （chunked encoding 下单次 `read` 可能短读取 → 假阴性）

### 🔒 Security

- **ReDoS 防护**：新增 `MAX_USERNAME_LENGTH = 64` 截断恶意输入。替代误报严重的
  `_REDOS_RE` 启发式（合法 regex 如 `[a-z]+(-[a-z]+)*` 也会命中）
- **SSRF 防护**：`track_ip` 用 `ipaddress.ip_address()` 校验，拒绝路径穿越
  （`'../admin'`）和 query string 污染（`'8.8.8.8?key=leak'`）
- **空输入防御**：`email_validate(None)` / `whois_lookup('')` 等正确返回错误
  而非崩溃
- **WAF 指纹增强**：CF Error Code 1020、CF Ray ID、`cf-mitigated`、AkamaiGHost、
  HTML-encoded "Reference #" 等

### ✨ Added

- `__version__ = '1.1.0'` 模块常量 + `--version` CLI flag
- `_print_section_header()` / `_emit_json()` helpers（去掉 ~30 行重复）
- `_batch_lookup` 支持 `KeyboardInterrupt`（`cancel_futures=True` 立即取消未启动 worker）
- `tests/conftest.py` autouse fixture：每个测试自动重置 `_lang` / `Color` /
  thread-local session
- `tools/build_platforms.py` 新增 `--cache-dir` / `--no-fetch` 选项支持离线开发
- `requirements-dev.txt`：分离运行/开发依赖（pytest, pytest-cov, pytest-timeout,
  ruff, mypy, bandit）

### ⚡ Performance

- **PLATFORMS 懒加载**：PEP 562 模块级 `__getattr__`，首次访问才合并 600KB JSON
  - `myip` / `--help` / `--version` 启动从 ~150ms → ~30ms
  - 测试代码无需改动（`gt.PLATFORMS` 仍可直接访问）

### 🛠 Build & CI

- **CI lint job**：ruff + mypy + bandit 三件套独立 job，test job 依赖之
- **Windows 矩阵**：覆盖 `os.name=='nt'` 分支（之前完全无信号）
- **CI 优化**：
  - `--cov=spyeyes` 替代 `--cov=.`（不再把 .venv/.mypy_cache 纳入覆盖率）
  - `--timeout=15` 防 ReDoS 测试卡死整个 CI
  - `concurrency` 取消同分支重复 build
  - 矩阵优化：Linux 跑全 4 版本，macOS/Windows 仅跑最低+最高（8 jobs 不变）
- **`tools/build_platforms.py` 加固**：
  - `atomic_write_json`：tempfile + `os.replace` 原子写（之前断电留下损坏 JSON）
  - `fetch` 加 `retries=3` + 指数退避（任意上游 5xx 不再让构建挂掉）
  - `merge_dedup` 新增 `SOURCE_PRIORITY`（maigret > whatsmyname > sherlock），
    评分相同时按优先级显式取舍而非依赖字典遍历顺序
  - 新增 `fetch_all()` / `main()` 可独立调用入口

### 🧪 Tests

- **总数 99 → 157**（+58 个测试）
- **新增 `tests/test_build_platforms.py`**（38 测试）：parse_maigret/sherlock/wmn、
  categorize、get_tld、merge_dedup priority、atomic_write 临时文件清理、fetch retry
- **重写假测试**：
  - `TestSession`：新增跨线程隔离反向断言（thread-local 改成全局会失败）
  - `TestRecordHistoryDataNone`：从 3 个空转测试扩为 6 个真实内容断言
  - `TestColor`：依赖 conftest 自动恢复，不再手动 try/finally
  - `TestRegexCheck`：删除引用 `_REDOS_RE` 的旧测试，新增长度限制 + 边界测试
- **新增覆盖**：
  - SSRF / IPv6 / path traversal / query string 拒绝（`TestTrackIp`）
  - `.md` / 单文件 JSON / 无后缀文件 / 显式目录 / 私有 key 过滤（`TestMaybeSave`）
  - None / 空 / 空白输入（`TestEmailValidateInput`）
  - whois None 返回 / 空 domain（`TestWhoisLookup`）

### 🧹 Removed

- `tests/__pycache__/test_ghosttrack.cpython-314-pytest-9.0.3.pyc`（GhostTrack 重命名残留）
- `asset/text`（8 字节 `Image..` 无引用）
- `_REDOS_RE` 启发式（误报严重）—— 改用 `MAX_USERNAME_LENGTH` 长度限制

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

[Unreleased]: https://github.com/Akxan/SpyEyes/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Akxan/SpyEyes/releases/tag/v1.1.0
[1.0.0]: https://github.com/Akxan/SpyEyes/releases/tag/v1.0.0
