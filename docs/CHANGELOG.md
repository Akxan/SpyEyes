# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### ✨ Added 新增

- **用户名扫描进度条** —— 实时刷新底部一行 `[████░░░░░░░] 1234/2020 (61.0%) 已命中: 42`，仅 TTY 模式下显示，不污染管道/JSON 输出
- **`--quick` 标志** —— 跳过 1375 个 `other` 长尾平台，仅扫主流 645 个，实测 **45s → 20s**（**3-4× 提速**）
- **`--category code,chinese,...`** —— 按类别精准过滤，`--category chinese,spanish` 实测 **5.7s** 完成 98 平台
- **`--timeout N`** —— 自定义单平台 HTTP 超时秒数

### 🚀 Changed 改进

- 默认 `--workers` 30 → **50**
- 默认 `--timeout` 8s → **5s**（更激进，避免被极慢平台拖累）
- `print_username_results` 现按「实际扫描数」显示分母（避免 `--quick` 时显示「0/1375」误导）

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- PyPI 发布 (`pip install ghosttrack-cn`)
- Docker 镜像

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

[Unreleased]: https://github.com/Akxan/GhostTrack-CN/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/Akxan/GhostTrack-CN/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Akxan/GhostTrack-CN/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Akxan/GhostTrack-CN/releases/tag/v1.0.0
