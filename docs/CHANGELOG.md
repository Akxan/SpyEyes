# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- PyPI 发布 (`pip install ghosttrack-cn`)
- Docker 镜像

---

## [1.2.3] — 2026-04-29

经过第 N 轮 5 路独立审计（ruff + mypy + bandit + pytest + superpowers:code-reviewer agent），修复 v1.2.2 引入的 4 个 P1 真 bug + 加 ReDoS 防护。**强烈建议升级**。

### 🐛 Fixed — 独立 audit agent 发现的 4 个 P1 + 1 doc bug

- **P1: `_to_markdown` 通用 dict 分支泄露 `_statuses` 私有 key** —— `username` 分支已用 `_platform_only` 过滤，但通用 fallback 直接迭代 `data.items()` 把 `_statuses` 当成普通字段渲染进表格。修复：通用分支也用 `_platform_only`
- **P1: `re.search` 而非 `re.fullmatch` —— 未锚定 regex 匹配子串造成注入风险** —— Sherlock 用 `re.match`/`re.fullmatch`，我们之前用 `re.search`，对未锚定模式（如 Dealabs 的 `[a-z0-9]{4,16}`）会匹配 `'AB; DROP TABLE; abc'` 中的 `'abc'` 子串。修复：改 `re.fullmatch` 强制全匹配
- **P1: ReDoS（regex 灾难性回溯）防护缺失** —— 数据源若混入恶意/手滑的 `(a+)+` 类嵌套量词模式，单个 worker 线程会跑死几秒。Python `re.error` 不捕获 CPU 灾难。修复：新增 `_REDOS_RE` 启发式检测，命中时跳过 regex check 直接发请求
- **P1: `--json` 输出泄露 `_statuses` 私有 key** —— Python `_*` 命名约定意为「私有」，但被直接 `json.dumps` 输出给用户。修复：CLI `--json` 模式自动剥掉 `_*` key（保留正常的 `_error`）
- **doc: README test count stale (93 → 99)** —— 加测试时漏更新徽章

### 🚀 Changed 改进

- WAF_FINGERPRINTS 收紧到只用 WAF 自有的特定 URL/cookie 标志（如 `cdn-cgi/challenge-platform`、`aws-waf-token`、`/_pxhc/`、`datadome.co`、`/_incapsula_resource` 等），**剔除** `b'cloudflare'` / `b'access denied'` 这类宽泛模式 —— 显著降低误报
- 新增 `_REDOS_RE` 模块级正则用于 ReDoS 启发式检测

### 🧪 Tests

- 93 → **99 测试**（+6 新增：fullmatch 注入测试、ReDoS 检测、ReDoS 不卡死、WAF 误报场景 ×3）
- 静态分析全部通过：ruff / mypy / bandit
- 实测验证：恶意 `(a+)+` regex 模式 0 ms 跳过（vs 无防护时几秒 CPU）

---

## [1.2.2] — 2026-04-29 (deprecated, replaced by 1.2.3)

整合剩下的 Sherlock 核心思路：**`regex_check` 预过滤** + **WAF 检测**。结果更准确、对反爬墙透明、对无效 username 不浪费请求。

### ✨ Added — Sherlock 完整体

- **🎯 `regex_check` 预过滤**（Sherlock 风格）—— `Platform` NamedTuple 新增 `regex_check` 字段。88 个主流平台（Twitter/Facebook/YouTube/...）从 Sherlock + Maigret 上游提取了用户名规则正则。当 username 不符合时**直接跳过 HTTP 请求**，不浪费时间不打扰目标服务器
  - 实测：含空格的 username `"joe smith"` 在 `--quick` 模式下跳过 18 个平台
- **🛡 WAF / CDN 拦截识别** —— 新增 `_detect_waf()` 检测 Cloudflare / AWS WAF / PerimeterX / DataDome 等反爬墙。被拦截的平台**不再误报为「找到」**，而是标记 `WAF blocked` 单独显示
  - 实测：扫 torvalds 时检测到 8-9 个 Cloudflare 拦截
- **📊 状态透明化** —— `_check_username` 返回 5 种状态：`found` / `not_found` / `waf` / `invalid` / `network_err`
- **`[ note ]` 摘要行** —— 扫描结果顶部显示「N WAF-blocked · M skipped (regex) · K network errors」让用户知道结果可信度
- **未找到细分显示** —— 之前所有 miss 都写「未找到」，现在区分：
  - 普通未找到：`未找到`
  - 反爬墙拦截：`[ WAF blocked ]`（紫色）
  - regex 不符：`[ skipped ]`（暗色）

### 🚀 Changed 改进

- `tools/build_platforms.py` 现在从 Sherlock + Maigret 数据中提取 `regexCheck`（88 个平台命中）
- `track_username` 返回 dict 中附加 `_statuses` 私有 key（不影响公开 API）
- `_platform_only(d)` 辅助函数过滤私有 key，所有 iteration 自动跳过

### 🧪 Tests

- 83 → **93 测试**（新增 10 个 regex / WAF / status 相关测试）
- 静态分析全部通过：ruff / mypy / bandit

---

## [1.2.1] — 2026-04-29 (deprecated, replaced by 1.2.2)

经过 5 路独立审计（ruff + mypy + bandit + pytest-cov + superpowers:code-reviewer agent）发现并修复 v1.2.0 的 6 个 P1 真 bug + 借鉴 Sherlock 优化思路，**用户名扫描速度翻倍（45s → 21s, 2.1×）**。

### 🚀 Performance — Sherlock-inspired 2× speed-up

经独立 agent 研究 Sherlock 项目得出 4 项可复用优化：

- **Per-thread `requests.Session` + 连接池复用**（pool_maxsize=64）—— 消除重复 host 的 DNS/TCP/TLS 握手（如 `*.tumblr.com`、`*.shopee.*`、`mercadolibre.*` 等多平台同 host 场景）
- **HEAD 请求**：仅需 status_code 检测的 856 个平台（41% of 2067）跳过 body 下载，每平台节省 1-50KB 网络传输
- **`stream=True` + `raw.read(65536)`**：需要 body 检测的平台只读前 64KB，避免下载 1-5MB 的页面
- **拆分 timeout `(connect=3s, read=N)`**：快速踢死 DNS 慢的死站，让长尾延迟显著降低

**实测对比**：
| 场景 | v1.2.0 | **v1.2.1** | 加速 |
|---|---|---|---|
| 全 2067 平台 (workers=100) | ~45s | **21s** | **2.1×** |
| `--quick` (727 平台) | ~20s | **9s** | **2.2×** |

### 🐛 Fixed — 独立 audit agent 发现的 6 个 P1 bug

- **P1: PLATFORMS 列表自含重复**（`Cam4` 与 `CAM4` 大小写不同）—— 删除重复 + 加 `_dedup_platforms` 防御未来笔误
- **P1: `_to_markdown` markdown 注入** —— 之前 `query` 含 `\n## PWNED` 会注入伪标题；dict key 含 `|` 会破坏表格列。新增 `_md_escape()` 统一转义所有 cell（key + value）+ 单行化 query/headers
- **P1: `_record_history` 在 `data=None` 时 `AttributeError`** —— 改为防御性 `if not isinstance(data, dict): data = {}`
- **P1: `must_contain=(b'',)` 空 pattern 永远 True** —— `b'' in any_bytes` 为 True，会让所有用户名误报「★★★ 命中」。新增 `_clean_patterns()` 在加载时过滤空字节串
- **P1: `track_username('')` 返回 all-None 而非 `_error`** —— 与 `track_ip('')` 行为不一致，写历史会记录假成功；统一返回 `{'_error': ...}`
- **P1: `--category xyz`（未知类别）静默扫 0 平台** —— 新增校验：未知类别返回 `_error` 并提示有效类别名

### 🚀 Changed 改进

- 默认 `--workers` 50 → **100**
- 默认 `--timeout` 8s → **5s**
- `track_username` 在 `categories` 中含未知值时立即报错而非静默
- `--quick` + `--category` 同时传 → stderr 警告 `--quick ignored when --category is set`

### 🧪 Tests

- 63 → **83 测试**（新增 20 个：dedup 校验、空模式过滤、markdown 注入防护、Session 复用、空输入对齐、未知类别校验等）
- 静态分析全部通过：ruff（lint）、mypy（type）、bandit（security）

---

## [1.2.0] — 2026-04-29 (deprecated, replaced by 1.2.1)

性能 + 用户体验大幅提升。新增 **5 大功能**：扫描进度条、模式筛选、Markdown 报告、查询历史、批量域名查询。新增 `adult` 类别（含 42 个成人/约会平台）。

### ✨ Added 新增

- **🚀 扫描速度优化（3-15× 提速）**
  - `--quick` 标志：跳过 1375 个 `other` 长尾平台，仅扫主流 645 个 → ~20s（vs 默认 ~45s）
  - `--category code,chinese,spanish,adult,...`：按类别精准过滤，最少 ~3s 完成
  - `--timeout N`：自定义单平台 HTTP 超时秒数
  - 默认 `--workers` 30 → **100**（实测线性扩展，2020 平台 mock 测试 12.5s → 6.4s）
  - 默认 `--timeout` 8s → **5s**

- **🎬 实时进度条**：扫描中底部一行 `[████░░░] 1234/2020 (61%) 已命中: 42` 实时刷新（仅 TTY，不污染管道/JSON）

- **🎯 交互菜单选项 4 新增 4 模式选择**：快速 / 完整 / 仅中文+西语 / 仅代码

- **📝 Markdown 报告导出**：`--save report.md` 直接生成可分享的 Markdown 报告
  - 自动按平台类别分组
  - 命中链接 `<url>` 可点击
  - 通用 dict 自动转表格
  - `--save out/` 仍是 JSON（按扩展名自动判断）

- **📚 查询历史记录** (`~/.ghosttrack/history.jsonl`)
  - 每次查询自动追加（仅元数据：时间/命令/查询/摘要，**不存全量结果**保护隐私）
  - `gt history --limit 50 --search xxx` 列表 / 过滤
  - 双语 UI

- **🌐 批量域名 MX / WHOIS**
  - `gt mx gmail.com outlook.com yahoo.com`
  - `gt whois example.com github.com gitlab.com`
  - 内部 10 线程并发，输出按域名分组

- **🔞 新增 `adult` 类别（42 个平台）**
  - **不再过滤 NSFW** —— 用户合法 OSINT 场景需要查这些
  - 手工 curated 20 个：OnlyFans / Fansly / FetLife / Chaturbate / Stripchat / ManyVids / JustForFans / AdmireMe / MyFreeCams / LiveJasmin / Cam4 / CamSoda / PornHub Community / xHamster / Literotica / F95Zone / Rule34 / PlentyOfFish / Badoo / Tagged
  - Maigret 数据库自动识别 22 个（通过 `ADULT_KEYWORDS` 关键词分类）
  - 总平台数 2020 → **2032**

- **🎯 命中可信度排序（★★★ / ★★ / ★）**
  - 每个类别内按可信度排序：`must_contain` 模式 → `not_found` 模式 → 仅 HTTP 200
  - 结果行可视化：`★★★ GitHub` 表示高可信，`★ Foo` 表示低可信
  - 真实用户更可能落在前列

### 🚀 Changed 改进

- `print_username_results` 按实际扫描数显示分母（避免 `--quick` 时显示「0/1375」误导）
- `_maybe_save` 智能判断：`.md` → Markdown 报告；`.json` 或目录 → JSON
- CLI 子命令 `mx` / `whois` 改为 `nargs='+'`，向后兼容（单域名仍可）

---

## [1.1.1] — 2026-04-29

经过 5 路独立审计（ruff + mypy + bandit + pytest-cov + superpowers:code-reviewer agent）发现并修复 v1.1.0 中潜伏的 3 个 P1 真 bug + 6 个 lint / 边界问题。建议所有 v1.1.0 用户立刻升级。

### 🐛 Fixed 修复

- **P1: `_check_username` 未捕获 `ValueError`** —— `str.format()` 对格式串错误（如 `{:d}`、`{0!q}`）会抛 `ValueError`，原代码只捕获 `IndexError/KeyError`。Maigret 上游某天若引入此类模板会让**整个 2020 平台扫描崩溃**。
- **P1: `track_username` 单 worker 异常会传染整个扫描** —— `fut.result()` 未包 try/except。现在任何 worker 内未捕获异常都被吞掉，对应平台标记 `None`，其它继续扫描。
- **P1: `--workers 0` / 负数 / 超大值直接 crash** —— 新增 `_positive_int` argparse 校验器，强制 `[1, 200]` 范围。
- **`field.region` 翻译键在 EN 字典中重复定义**（ruff F601 检测）—— 删除冗余条目。
- **`tools/build_platforms.py` 含未用 `re` / `sys` import**（ruff F401）—— 删除。
- **`tools/build_platforms.py` 含无占位符 f-string**（ruff F541）—— 改普通字符串。
- **`tools/build_platforms.py` 多语句单行用 `;`**（ruff E702）—— 拆开。
- **`track_ip('')` 会让 ipwho.is 返回调用方自己的 IP**（误导用户以为查的是别人）—— 现在空输入早返回 `err.empty_input`。
- **`track_username('')` 会命中所有平台主页造成误报** —— 现在空输入直接返回所有 `None`，零网络请求。

### 🧪 Tests

- 51 → **63 测试**（新增空输入、`ValueError` 处理、worker 异常隔离、`--workers` 边界值校验等 12 个测试）
- 静态分析全部通过：ruff（lint + format）、mypy（type check）、bandit（security scan）

### 📦 Internal

- `.gitignore` 扩展覆盖 `.coverage` / `.mypy_cache` / `.ruff_cache` 等开发产物

---

## [1.1.0] — 2026-04-29

OSINT 信息检索能力大幅扩展。从 113 个手工 curated 平台跃升至 **2020 个**（合并三大上游数据源），并新增完整的中英双语 i18n 系统。

### ✨ Added 新增

- **🌍 完整中英双语 UI（i18n）**
  - 全新 ~130 key 翻译系统（`TRANSLATIONS` dict）
  - 首次启动弹出语言选择器（中文 / English）
  - 菜单 `[ 8 ]` 切换语言，立即生效
  - CLI `--lang zh|en` 标志（一次性覆盖）
  - 偏好持久化到 `~/.ghosttrack/config.json`
  - 优先级：CLI > 配置文件 > `LANG` 环境变量 > 默认
  - 国家名根据语言显示：zh → "美国 (United States)"；en → "United States"

- **📊 平台数 113 → 2020（18×）**
  - 整合三大 OSINT 上游数据库：
    - [Maigret](https://github.com/soxoj/maigret)：1409 sites
    - [Sherlock](https://github.com/sherlock-project/sherlock)：475 sites
    - [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)：708 sites
  - 加上手工 curated 的中文/西语区域精选
  - 总计 2020 个去重平台

- **🇨🇳 中文圈深度覆盖（46 个）**
  - 简中 PRC：CSDN、V2EX、知乎、微博、豆瓣、贴吧、SegmentFault、掘金、力扣 CN、博客园、IT 之家、雪球、即刻、36 氪、虎扑、牛客、AcWing、阿里云、51CTO、马蜂窝、穷游、果壳、起点、晋江、360doc、大众点评 ...
  - 繁中 / 港台星马：Dcard、Mobile01、巴哈姆特、PIXNET、隨意窩、iCook、LIHKG 連登、HK01、Carousell、Shopee TW/SG/MY ...

- **🌎 西语圈覆盖（52 个）**
  - 西班牙：Wallapop、Menéame、Forocoches、Genbeta、Xataka
  - 拉美：MercadoLibre AR/MX/BR、Taringa、Hispachan、Forosperu
  - 国际：Duolingo

- **🛠 平台数据库构建工具**
  - `tools/build_platforms.py` 一键拉取 3 上游 → 过滤、去重、自动分类 → 输出 `data/platforms.json`
  - 智能分类：CHINESE_KEYWORDS / SPANISH_KEYWORDS / TLD-based / 主题关键词四级 fallback

- **🔍 用户名扫描增强**
  - `Platform` NamedTuple 新增 `must_contain` 字段，HTTP 200 + 不含 not_found + 含 must_contain 三重检测
  - 默认 30 线程并发（原 10），`--workers N` 自定义
  - 默认只显示命中（不然 2020 行太多），`--all` 看完整报告
  - 按 12 大类（含 chinese / spanish / other）分组显示，每组显示「命中/总数」

- **📜 Documentation**
  - TUTORIAL.md 大幅扩充：新增 i18n、`--all`、语言切换、平台数据库刷新章节
  - CHANGELOG.md 加入 v1.1.0 条目

### 🚀 Changed 改进

- 默认用户名扫描线程数 10 → **30**
- 用户名扫描结果按区域 + 主题分组（原来一字排开）
- `print_username_results()` 新增 `show_all` 参数控制详略
- CI Python matrix 3.9-3.12 → **3.10-3.13**（3.9 已 EOL）

### 🐛 Fixed 修复

- 死代码清理：`msg.scanning`、`field.local_num` 翻译键定义但从未使用
- 注释「约 1500 个」→「约 2020 个」对齐实际数据

### 📦 Dependencies 依赖

- `requests` >=2.28 → >=2.33.1
- `phonenumbers` >=8.13 → >=9.0.29
- `dnspython` >=2.4 → >=2.8.0
- `python-whois` >=0.9 → >=0.9.6
- CI Actions：checkout v5 → v6、setup-python v5 → v6、codecov v5 → v6

### 🧪 Tests

- 47 → **51 测试**（新增 4 个 Platform / 类别覆盖测试）
- 测试目标：`assert len(PLATFORMS) >= 2000`、`>= 30 chinese`、`>= 30 spanish`

---

## [1.0.0] — 2026-04-29

首个正式版本。基于原版 [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack) 全面重构与中文增强。

### ✨ Added 新增

- **3 个新功能模块**：
  - 域名 WHOIS 查询（`python-whois`）
  - 域名 MX 记录查询（`dnspython`）
  - 邮箱有效性验证（正则 + MX 联合）
- **CLI 参数模式**：所有功能均可通过 `python3 GhostTR.py <subcmd>` 非交互调用
- **JSON 输出**（`--json`）：方便管道处理与脚本集成
- **结果保存**（`--save DIR`）：自动落盘为 `<功能>_<时间戳>.json`
- **国家中文映射表**：180+ 国家/地区，IP 显示中文国名
- **47 个 pytest 单元测试** + GitHub Actions CI（macOS/Ubuntu × Python 3.10-3.13）
- **MIT License、CONTRIBUTING.md、SECURITY.md、CHANGELOG.md**
- **English README** + 双语切换
- **Issue / PR 模板**、Dependabot 自动更新

### 🚀 Changed 改进

- **全中文 UI**：菜单、字段标签、错误信息、电话归属地、运营商
- **用户名扫描并发化**：`ThreadPoolExecutor` 10 线程，30-60s → 2-3s（10-20× 提速）
- **请求加超时与默认 User-Agent**：避免挂起，减少 403
- **HTTP → HTTPS**：`ipwho.is` 改用安全连接
- **彩色输出自动检测 TTY**：重定向时不输出 ANSI 转义
- **菜单循环改为 `while True`**：解决原版递归调用导致的栈溢出风险
- **依赖管理统一**：`requirements.txt` 锁定最低版本

### 🐛 Fixed 修复

- IP 查询的 `Current Time` 字段崩溃（`ipwho.is` API 已移除该字段）
- 谷歌地图链接经纬度被 `int()` 截断成整数，丢失精度
- 电话号码解析异常未捕获导致整个程序退出
- API 失败 / 网络异常导致的 `KeyError`、`AttributeError`
- 用户名列表中 Snapchat 重复 2 次

### 🔧 Internal 内部

- 全文加 type hints
- 拆分 `print_field()` 辅助函数，消除 30+ 行重复 print
- ANSI 颜色集中在 `Color` 类
- 替换已废弃 actions 版本（checkout v4→v5、setup-python v5→v6、codecov v4→v5）

### 🙏 Credits

基于 [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack) 二次开发，感谢原作者。

---

[Unreleased]: https://github.com/Akxan/GhostTrack-CN/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/Akxan/GhostTrack-CN/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/Akxan/GhostTrack-CN/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/Akxan/GhostTrack-CN/compare/v1.1.1...v1.2.1
[1.2.0]: https://github.com/Akxan/GhostTrack-CN/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/Akxan/GhostTrack-CN/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Akxan/GhostTrack-CN/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Akxan/GhostTrack-CN/releases/tag/v1.0.0
