# 更新日志 / Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- 代理支持 (`--proxy http://...` / SOCKS5)
- 批量输入模式 (`--batch ips.txt`)
- HIBP (Have I Been Pwned) 邮箱泄露集成
- English UI mode (`--lang en`)
- PyPI 发布 (`pip install ghosttrack-cn`)

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

[Unreleased]: https://github.com/Akxan/GhostTrack-CN/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Akxan/GhostTrack-CN/releases/tag/v1.0.0
