# v1.8.2 设计:一键升级 (菜单 Y/N + CLI `upgrade` 子命令)

**日期**:2026-05-13
**版本目标**:v1.8.2
**状态**:Draft (待 user review)

---

## 背景

v1.8.0 已完成"启动版本检查"(后台 daemon + 24h 缓存 + stderr 提示),用户看到提示后**仍需手动复制**升级命令再去执行。本设计补全闭环 —— 让用户**选 Y 就自动升级**,不再需要手动跑命令。

## 决策点回顾

(brainstorming 阶段已对齐)

| 决策 | 选定方案 |
|---|---|
| 触发点 | 进交互菜单时自动弹 Y/N + 菜单 `[U]` 主动入口 + CLI `spyeyes upgrade` |
| 执行 | 打包安装 (pip/pipx) → subprocess 自动跑;源码 (git clone) → 只显示命令让用户复制 |
| 完成后 | subprocess 完成 → `exit 0`,提示用户重启 (避 Windows 文件锁导致旧代码) |
| CLI 子命令 | `spyeyes upgrade [--yes] [--check]` |
| 菜单等价 | `[U] Check & Upgrade` 一项:进入即强制刷新 → 显示对比 → 有新版 prompt Y/N (选 N = `--check` 语义) |

---

## 架构

### 新增函数 (全在 [`spyeyes/__init__.py`](../../spyeyes/__init__.py))

| 函数 | 签名 | 职责 |
|---|---|---|
| `_detect_install_mode` | `() -> str` | 返回 `'source' / 'packaged-pip' / 'packaged-pipx'`。复用 `_is_packaged_install()`,pipx 额外靠 `__file__` 路径含 `pipx/venvs` 或 `pipx\venvs` 判断 |
| `_build_upgrade_command` | `(mode: str) -> list[str] \| None` | 按 mode 返回 subprocess 命令: `pip`→`[sys.executable, '-m', 'pip', 'install', '--upgrade', 'git+...']`;`pipx`→`['pipx', 'upgrade', 'spyeyes']`;`source`→`None` |
| `_prompt_yes_no` | `(question: str, default_yes: bool = True) -> bool` | TTY 安全的 Y/N prompt;非 TTY 直接返回 `default_yes`;Ctrl-C 抛 `KeyboardInterrupt` 由上层处理 |
| `run_upgrade` | `(yes: bool = False, check_only: bool = False) -> int` | 主流程,见下文"数据流" |

### 现有代码修改点

| 位置 | 修改 |
|---|---|
| `menu_loop()` 入口 (~line 9325) | 启动时读 `_get_cached_update_info()`,有新版 + `sys.stdin.isatty()` → prompt Y/N → Y 调 `run_upgrade(yes=True)` → exit 0 / N 跳过本次继续菜单 |
| `handle_choice()` | 加 `[U]` 分支 → 调 `run_upgrade()` (不强制 yes) |
| `MENU_KEYS` | 加 `'U'` 条目 |
| `build_parser()` | 加 `upgrade` 子 parser + `--yes` / `--check` flags |
| `run_cli()` | dispatch `upgrade` 子命令 → `run_upgrade(args.yes, args.check)` |
| `TRANSLATIONS` (zh+en) | 加 ~14 个 i18n key |

### 升级机制(回应用户对"是否留垃圾"的关切)

| 安装方式 | 升级命令 | 旧版本行为 |
|---|---|---|
| `pip install git+URL` | `pip install --upgrade git+URL` | pip 内部先 uninstall (清 `site-packages/spyeyes/` 全部 .py + `__pycache__/`) 再 install 新版 |
| `pipx install git+URL` | `pipx upgrade spyeyes` | pipx 在独立 venv (`~/.local/pipx/venvs/spyeyes/`) 内部跑 pip,完全隔离 |
| `git clone + pip install -e .` | (源码模式不自动跑) | 显示 `git pull && pip install -e .` 给用户 |

**残留分析**:

- pip 全局 cache (`~/.cache/pip/` / Windows `%LOCALAPPDATA%\pip\Cache`) — pip 自己 LRU 管理,**不需要 SpyEyes 清**
- `~/.spyeyes/` (config.json / history.jsonl / .update_check.json) — 用户数据,**绝不能清** (否则升级一次历史就丢)
- `__pycache__/` — pip uninstall 会清

**结论**:pip / pipx 是标准包管理,升级**彻底替换**,不留 SpyEyes 残留。

---

## 数据流

```
后台 daemon (v1.8.0, 不变)
  └─→ 24h 缓存 ~/.spyeyes/.update_check.json

通道 1: 菜单启动自动 prompt (NEW)
  menu_loop() 入口
    → _get_cached_update_info() (读缓存,不强刷)
    → 有新版 + sys.stdin.isatty()
    → "🆕 v{latest} available (current {current}). Upgrade now? [Y/n]:"
      ├─ Y → run_upgrade(yes=True) → exit 0
      └─ N → 跳过本次,继续菜单 (下次启动仍 prompt)

通道 2: 菜单 [U] 主动入口 (NEW)
  handle_choice('U') → run_upgrade(yes=False, check_only=False)
    → "Checking GitHub Releases..."
    → refresh_update_cache_sync(force=True) (强刷,绕 24h)
    → 已是最新 → "✓ Already on latest" → 返回菜单
    → 网络错 → "Could not reach GitHub" → 返回菜单
    → 有新版 →
        显示 "Current: {current} → Latest: {latest}"
                "Release notes: {url}"
        prompt "Upgrade now? [Y/n]:"
          ├─ Y → subprocess + 流式输出 → exit 0
          └─ N → "Cancelled" → 返回菜单 (= --check 语义)

通道 3: CLI `spyeyes upgrade` (NEW)
  run_cli('upgrade', --yes/--check) → run_upgrade(yes, check_only)
    → 同通道 2 流程,但:
       - --check → 显示对比后 return 0,不 prompt 不 subprocess
       - --yes → 跳 prompt 直接 subprocess
       - 非 TTY 且无 --yes → 报错 return 2
```

---

## 错误处理 / 边界

| 情况 | 处理 |
|---|---|
| 网络断 / GitHub 502 / API 限速 | refresh 失败 → "Could not reach GitHub Releases. Try again later." → return 1 |
| 已是最新 | "✓ Already on latest version ({current})" → return 0 |
| 源码模式 (`_detect_install_mode()=='source'`) | "Source install detected. Run: `git pull && pip install -e .`" → return 0 (不 subprocess) |
| 非 TTY + 缺 `--yes` | "Cannot prompt without TTY. Use --yes to skip confirmation." → return 2 |
| subprocess 失败 (非 0 退出) | 显示 subprocess 的 stderr + 兜底手动命令 → return subprocess 的 exit code |
| `pipx` 不在 PATH (虽是 pipx 装的但环境出问题) | `shutil.which('pipx')` 失败 → 降级显示手动 `pip install --upgrade ...` → return 1 |
| 用户在 prompt 处 Ctrl-C | 捕获 `KeyboardInterrupt` → "Cancelled" → return 130 |
| 用户在 prompt 处选 N (CLI 模式) | "Cancelled" → return 0 (主动取消不算错,与 `--check` 行为一致) |
| Windows 文件锁 (`pip` 升级时 spyeyes 进程持有 .py) | pip 自己会用 tempdir + rename,**通常成功**;若失败 → 显示 "Please close all SpyEyes processes and retry." |

---

## 测试覆盖 (~14 个新测试,548 → ~562)

| TestClass | 测试用例 |
|---|---|
| `TestDetectInstallMode` | source / pip / pipx 三种 mode 识别 (`__file__` mock) |
| `TestBuildUpgradeCommand` | 三种 mode → cmd 列表内容正确 (含 `--upgrade` / `git+...` / `pipx upgrade spyeyes`) |
| `TestPromptYesNo` | TTY + 'y' / 'n' / 空 (用 default);非 TTY → 立即返回 default;Ctrl-C 抛 |
| `TestRunUpgrade` | source mode → 只 print 不 subprocess;packaged + yes=True → subprocess 调用一次;packaged + 用户 N → 不调 subprocess;非 TTY + yes=False → return 2;subprocess 非 0 退出 → return 透传 + 显示兜底;已是最新 → return 0 不 subprocess;`--check` → 显示对比 + return 0 不 subprocess;网络错 → return 1 |
| `TestMenuUpgradePrompt` | 缓存有新版 + TTY → prompt 被调一次;缓存无新版 → prompt 不调;非 TTY → prompt 不调;用户 N → 继续菜单不 exit |

---

## YAGNI(明确不做)

| 不做 | 原因 |
|---|---|
| 自动 `git pull` (源码模式) | git 冲突风险高,只显示命令更安全 |
| Dry-run / `pip install --dry-run` 预检 | YAGNI;失败兜底已有 |
| GPG/PGP release 签名验证 | 当前 release 没签名,后续可加 |
| 升级到指定历史版本 (`upgrade --version vX.Y.Z`) | YAGNI;固定升 latest |
| PyPI 路径 | 当前未上 PyPI,等上线后再加 (届时优先 `pip install --upgrade spyeyes`) |
| 显式清 pip cache | pip 自管理,不归 SpyEyes |
| 菜单显式拆 `[U] Upgrade` + `[C] Check` | 一项 `[U]` 内嵌 prompt 已等价覆盖 (选 N = check-only) |
| 自动 exec 重启 | Windows 文件锁问题,提示用户手动重启更可靠 |

---

## i18n key 一览 (zh + en 各一份, 共 ~14 个 key, 28 entries)

| key | en | zh |
|---|---|---|
| `upgrade.prompt_menu_start` | `🆕 New version {latest} available (current {current}). Upgrade now? [Y/n]:` | `🆕 新版本 {latest} 可用 (当前 {current})。现在升级? [Y/n]:` |
| `upgrade.checking` | `Checking GitHub Releases...` | `查询 GitHub Releases...` |
| `upgrade.already_latest` | `✓ Already on latest version ({current})` | `✓ 已是最新版本 ({current})` |
| `upgrade.found_new` | `Current: {current} → Latest: {latest}` | `当前: {current} → 最新: {latest}` |
| `upgrade.release_notes` | `Release notes: {url}` | `更新说明: {url}` |
| `upgrade.confirm` | `Upgrade now? [Y/n]:` | `现在升级? [Y/n]:` |
| `upgrade.cancelled` | `Cancelled` | `已取消` |
| `upgrade.source_install_hint` | `` Source install detected. Run: `git pull && pip install -e .` `` | `` 检测到源码安装。请执行: `git pull && pip install -e .` `` |
| `upgrade.running_cmd` | `Running: {cmd}` | `执行: {cmd}` |
| `upgrade.success` | `✓ Upgraded to {latest}. Please re-run spyeyes.` | `✓ 已升级到 {latest}。请重新启动 spyeyes。` |
| `upgrade.failed` | `Upgrade failed (exit {code}). Manual: {cmd}` | `升级失败 (退出码 {code})。手动: {cmd}` |
| `upgrade.no_tty` | `Cannot prompt without a TTY. Use --yes to skip confirmation.` | `无 TTY 无法交互。请加 --yes 跳过确认。` |
| `upgrade.network_error` | `Could not reach GitHub Releases. Try again later.` | `无法连接 GitHub Releases,请稍后重试。` |
| `upgrade.pipx_missing` | `pipx not found in PATH. Falling back to: {pip_cmd}` | `PATH 里找不到 pipx。降级到: {pip_cmd}` |

`menu.upgrade` (菜单项标签) 复用现有命名风格:

| | en | zh |
|---|---|---|
| `menu.upgrade` | `Check & Upgrade SpyEyes` | `检查并升级 SpyEyes` |

---

## 估算

- 实现 ~200 行 Python (核心 4 函数 + 菜单钩子 + CLI dispatch)
- 测试 ~150 行 (14 个新 case)
- i18n 28 entries
- 总 commit 2-3 个 (核心实现 / 测试 / CHANGELOG+version bump)
- v1.8.2 release

## 不影响的已有行为

- v1.8.0 的后台启动检查 + 24h 缓存 + stderr 提示 — **全部保留**
- v1.8.1 的 `_is_packaged_install()` 区分文案 — **复用,且本 design 把它从纯文案升级为执行入口**
- 所有现有子命令 / 菜单项 / 测试 — **全部不动**
