# v1.8.2 一键升级 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (推荐) 或 superpowers:executing-plans 来逐 task 执行。步骤用 `- [ ]` 复选框跟踪。

**Goal:** 在 SpyEyes v1.8.0 已有"启动版本检查"基础上,补全"用户选 Y 自动升级"闭环 —— 菜单启动弹 Y/N + 菜单 `[12]` 主动入口 + CLI `spyeyes upgrade` 三条通道,打包安装 (pip/pipx) subprocess 自动跑、源码安装只显示命令。

**Architecture:** 4 个新 helper 函数 (`_detect_install_mode` / `_build_upgrade_command` / `_prompt_yes_no` / `run_upgrade`) 全加在 [`spyeyes/__init__.py`](../../spyeyes/__init__.py),复用 v1.8.0 已有的 `_is_packaged_install()` 和 `refresh_update_cache_sync()`。修改点:`menu_loop()` 入口加自动 prompt;`MENU_KEYS` + `handle_choice()` 加 `[12]` 项;`build_parser()` + `run_cli()` 加 `upgrade` 子命令;`TRANSLATIONS` (zh+en) 加 14 个新 key。

**Tech Stack:** Python 3.10+,`subprocess`,`shutil.which`,`sys.stdin.isatty()`,argparse subparsers,无新依赖。Reference spec: [`docs/design/2026-05-13-one-click-upgrade.md`](../design/2026-05-13-one-click-upgrade.md)。

---

## Task 1: 加 14 个 i18n key (en + zh)

**Files:**
- Modify: `spyeyes/__init__.py:712-715` (现有 update.* 区段, en) + `spyeyes/__init__.py:1029-1032` (zh) + `spyeyes/__init__.py:5367-5380` (MENU_KEYS 暂不动,只加 menu.upgrade key)

**为什么放第一**:其他任务的实现代码会直接调 `t('upgrade.xxx')`,先把 key 放进去后续测试才能跑。

- [ ] **Step 1: 写测试 — 确保 14 个新 key 在两种语言下都有**

加到 [`tests/test_spyeyes.py`](../../tests/test_spyeyes.py) 末尾(新 TestClass `TestUpgradeI18n`):

```python
class TestUpgradeI18n:
    """v1.8.2 一键升级新增 i18n key 完整性检查。"""

    UPGRADE_KEYS = [
        'upgrade.prompt_menu_start',
        'upgrade.checking',
        'upgrade.already_latest',
        'upgrade.found_new',
        'upgrade.release_notes',
        'upgrade.confirm',
        'upgrade.cancelled',
        'upgrade.source_install_hint',
        'upgrade.running_cmd',
        'upgrade.success',
        'upgrade.failed',
        'upgrade.no_tty',
        'upgrade.network_error',
        'upgrade.pipx_missing',
        'menu.upgrade',
    ]

    def test_all_upgrade_keys_present_in_en(self):
        for key in self.UPGRADE_KEYS:
            assert key in gt.TRANSLATIONS['en'], f"missing en key: {key}"

    def test_all_upgrade_keys_present_in_zh(self):
        for key in self.UPGRADE_KEYS:
            assert key in gt.TRANSLATIONS['zh'], f"missing zh key: {key}"

    def test_en_zh_key_sets_match(self):
        """en 和 zh 的 key 集合必须完全一致 (含我们新加的)。"""
        en_keys = set(gt.TRANSLATIONS['en'].keys())
        zh_keys = set(gt.TRANSLATIONS['zh'].keys())
        assert en_keys == zh_keys, f"diff: en-zh={en_keys-zh_keys}, zh-en={zh_keys-en_keys}"
```

- [ ] **Step 2: 跑测试确认失败**

```bash
source .venv/bin/activate
pytest tests/test_spyeyes.py::TestUpgradeI18n -v
```

Expected: 3 个测试全 FAIL,报 missing key。

- [ ] **Step 3: 在 en 区段加 14 个 key**

定位 [`spyeyes/__init__.py:715`](../../spyeyes/__init__.py#L715) 的 `'update.disable_hint': ...` 行后(en 的 update.* 区段结尾)。紧接着加:

```python
        # Upgrade (v1.8.2: 一键升级)
        'upgrade.prompt_menu_start':  '🆕 New version {latest} available (current {current}). Upgrade now? [Y/n]:',
        'upgrade.checking':           'Checking GitHub Releases...',
        'upgrade.already_latest':     '✓ Already on latest version ({current})',
        'upgrade.found_new':          'Current: {current} → Latest: {latest}',
        'upgrade.release_notes':      'Release notes: {url}',
        'upgrade.confirm':            'Upgrade now? [Y/n]:',
        'upgrade.cancelled':          'Cancelled',
        'upgrade.source_install_hint':'Source install detected. Run: `git pull && pip install -e .`',
        'upgrade.running_cmd':        'Running: {cmd}',
        'upgrade.success':            '✓ Upgraded to {latest}. Please re-run spyeyes.',
        'upgrade.failed':             'Upgrade failed (exit {code}). Manual: {cmd}',
        'upgrade.no_tty':             'Cannot prompt without a TTY. Use --yes to skip confirmation.',
        'upgrade.network_error':      'Could not reach GitHub Releases. Try again later.',
        'upgrade.pipx_missing':       'pipx not found in PATH. Falling back to: {pip_cmd}',
```

同时,定位 [`MENU_KEYS` (5367)](../../spyeyes/__init__.py#L5367) 之前在 menu.* 区段加 `menu.upgrade` key。在 en 区段找到 `'menu.lang':` 这一行,在它之前加:

```python
        'menu.upgrade':         'Check & Upgrade SpyEyes',
```

(menu.exit 之前那行的 menu.lang 之前。如果不确定位置,grep `'menu.lang':` 找精确。)

- [ ] **Step 4: 在 zh 区段加同 15 个 key**

定位 [`spyeyes/__init__.py`](../../spyeyes/__init__.py) 的 `'update.disable_hint':` zh 版本(约 1032 行附近)的后面,加:

```python
        # Upgrade (v1.8.2: 一键升级)
        'upgrade.prompt_menu_start':  '🆕 新版本 {latest} 可用 (当前 {current})。现在升级? [Y/n]:',
        'upgrade.checking':           '查询 GitHub Releases...',
        'upgrade.already_latest':     '✓ 已是最新版本 ({current})',
        'upgrade.found_new':          '当前: {current} → 最新: {latest}',
        'upgrade.release_notes':      '更新说明: {url}',
        'upgrade.confirm':            '现在升级? [Y/n]:',
        'upgrade.cancelled':          '已取消',
        'upgrade.source_install_hint':'检测到源码安装。请执行: `git pull && pip install -e .`',
        'upgrade.running_cmd':        '执行: {cmd}',
        'upgrade.success':            '✓ 已升级到 {latest}。请重新启动 spyeyes。',
        'upgrade.failed':             '升级失败 (退出码 {code})。手动: {cmd}',
        'upgrade.no_tty':             '无 TTY 无法交互。请加 --yes 跳过确认。',
        'upgrade.network_error':      '无法连接 GitHub Releases,请稍后重试。',
        'upgrade.pipx_missing':       'PATH 里找不到 pipx。降级到: {pip_cmd}',
```

zh 的 `'menu.lang':` 行之前加:

```python
        'menu.upgrade':         '检查并升级 SpyEyes',
```

- [ ] **Step 5: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestUpgradeI18n -v
```

Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): 加 14 个 upgrade.* i18n key (zh+en) + menu.upgrade"
```

---

## Task 2: `_detect_install_mode()` — 三态识别

**Files:**
- Modify: `spyeyes/__init__.py` (在 `_is_packaged_install` 函数 [line 8545](../../spyeyes/__init__.py#L8545) 之后加新函数)
- Modify: `tests/test_spyeyes.py` (加 TestClass)

- [ ] **Step 1: 写测试**

加 TestClass `TestDetectInstallMode` 到 `tests/test_spyeyes.py`(放在 `TestUpgradeI18n` 后):

```python
class TestDetectInstallMode:
    """v1.8.2: source / packaged-pip / packaged-pipx 三态识别。"""

    def test_source_install_mode(self, monkeypatch):
        """非打包安装 → 'source'。"""
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: False)
        assert gt._detect_install_mode() == 'source'

    def test_packaged_pip_mode(self, monkeypatch):
        """打包安装 + __file__ 不含 pipx → 'packaged-pip'。"""
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: True)
        # 模拟一个普通 site-packages 路径(用 os.sep 让 Windows 也对)
        fake_path = os.path.join('/usr/lib/python3.12/site-packages', 'spyeyes', '__init__.py')
        monkeypatch.setattr(gt, '__file__', fake_path)
        assert gt._detect_install_mode() == 'packaged-pip'

    def test_packaged_pipx_mode_posix(self, monkeypatch):
        """打包安装 + __file__ 含 pipx/venvs (POSIX) → 'packaged-pipx'。"""
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: True)
        fake_path = '/home/user/.local/pipx/venvs/spyeyes/lib/python3.12/site-packages/spyeyes/__init__.py'
        monkeypatch.setattr(gt, '__file__', fake_path)
        assert gt._detect_install_mode() == 'packaged-pipx'

    def test_packaged_pipx_mode_windows(self, monkeypatch):
        """Windows pipx 路径 (反斜杠) → 'packaged-pipx'。"""
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: True)
        fake_path = r'C:\Users\me\pipx\venvs\spyeyes\Lib\site-packages\spyeyes\__init__.py'
        monkeypatch.setattr(gt, '__file__', fake_path)
        assert gt._detect_install_mode() == 'packaged-pipx'
```

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestDetectInstallMode -v
```

Expected: 4 个测试 FAIL — `AttributeError: module 'spyeyes' has no attribute '_detect_install_mode'`。

- [ ] **Step 3: 实现 `_detect_install_mode()`**

在 [`spyeyes/__init__.py`](../../spyeyes/__init__.py) 的 `_is_packaged_install` 函数定义之后(约 line 8550)插入:

```python
def _detect_install_mode() -> str:
    """识别 SpyEyes 是怎么装的,返回 'source' / 'packaged-pip' / 'packaged-pipx'。

    'source':        git clone + pip install -e .  → 不自动跑升级,只显示命令
    'packaged-pip':  pip install git+URL           → subprocess 跑 pip install --upgrade
    'packaged-pipx': pipx install git+URL          → subprocess 跑 pipx upgrade spyeyes

    pipx 装的包,__file__ 路径含 `pipx/venvs` (POSIX) 或 `pipx\\venvs` (Windows)。
    """
    if not _is_packaged_install():
        return 'source'
    real = os.path.realpath(__file__)
    # 跨平台:同时查正反斜杠两种分隔
    if 'pipx' + os.sep + 'venvs' in real or 'pipx/venvs' in real or 'pipx\\venvs' in real:
        return 'packaged-pipx'
    return 'packaged-pip'
```

- [ ] **Step 4: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestDetectInstallMode -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): _detect_install_mode 三态识别 (source/pip/pipx)"
```

---

## Task 3: `_build_upgrade_command()` — 构造 subprocess 命令

**Files:**
- Modify: `spyeyes/__init__.py` (紧接 `_detect_install_mode` 之后)
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试**

加 TestClass:

```python
class TestBuildUpgradeCommand:
    """v1.8.2: mode → subprocess 命令列表的映射。"""

    def test_source_returns_none(self):
        """源码模式不自动跑,返回 None。"""
        assert gt._build_upgrade_command('source') is None

    def test_pip_command_uses_sys_executable(self):
        """packaged-pip → [sys.executable, -m, pip, install, --upgrade, git+URL]。"""
        cmd = gt._build_upgrade_command('packaged-pip')
        assert cmd is not None
        assert cmd[0] == sys.executable        # 避 PATH 缺失
        assert cmd[1] == '-m'
        assert cmd[2] == 'pip'
        assert cmd[3] == 'install'
        assert '--upgrade' in cmd
        assert any('git+https://github.com/Akxan/SpyEyes.git' in c for c in cmd)

    def test_pipx_command(self):
        """packaged-pipx → [pipx, upgrade, spyeyes]。"""
        cmd = gt._build_upgrade_command('packaged-pipx')
        assert cmd == ['pipx', 'upgrade', 'spyeyes']
```

(测试文件顶部已有 `import sys`,如无补上)

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestBuildUpgradeCommand -v
```

Expected: 3 个 FAIL。

- [ ] **Step 3: 实现**

在 `_detect_install_mode` 之后加:

```python
def _build_upgrade_command(mode: str) -> Optional[list[str]]:
    """按 mode 返回 subprocess 命令列表,源码模式返回 None。

    使用 sys.executable -m pip 而非 'pip',避 PATH 缺失 (Windows 上 pip.exe 可能不在 PATH)。
    使用 list 形式 (非 shell 字符串) 避跨平台 shell quoting 差异。
    """
    if mode == 'source':
        return None
    if mode == 'packaged-pipx':
        return ['pipx', 'upgrade', 'spyeyes']
    if mode == 'packaged-pip':
        return [sys.executable, '-m', 'pip', 'install', '--upgrade',
                'git+https://github.com/Akxan/SpyEyes.git']
    return None
```

- [ ] **Step 4: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestBuildUpgradeCommand -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): _build_upgrade_command 按 mode 构造 subprocess 命令"
```

---

## Task 4: `_prompt_yes_no()` — TTY 安全的 Y/N prompt

**Files:**
- Modify: `spyeyes/__init__.py`
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试**

```python
class TestPromptYesNo:
    """v1.8.2: TTY-safe Y/N prompt。"""

    def test_returns_default_when_not_tty(self, monkeypatch):
        """非 TTY 时立即返回 default_yes,不调用 input。"""
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        called = []
        monkeypatch.setattr('builtins.input', lambda _: called.append(1) or 'y')
        assert gt._prompt_yes_no('continue?', default_yes=True) is True
        assert gt._prompt_yes_no('continue?', default_yes=False) is False
        assert called == []  # 绝不调 input

    def test_tty_y_returns_true(self, monkeypatch):
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        assert gt._prompt_yes_no('continue?', default_yes=True) is True

    def test_tty_n_returns_false(self, monkeypatch):
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        assert gt._prompt_yes_no('continue?', default_yes=True) is False

    def test_tty_empty_uses_default(self, monkeypatch):
        """直接回车 → 用 default_yes。"""
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda _: '')
        assert gt._prompt_yes_no('q', default_yes=True) is True
        assert gt._prompt_yes_no('q', default_yes=False) is False

    def test_tty_ctrl_c_raises(self, monkeypatch):
        """Ctrl-C 透传 KeyboardInterrupt 让上层处理。"""
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        def raise_kbd(_):
            raise KeyboardInterrupt
        monkeypatch.setattr('builtins.input', raise_kbd)
        import pytest
        with pytest.raises(KeyboardInterrupt):
            gt._prompt_yes_no('q', default_yes=True)
```

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestPromptYesNo -v
```

Expected: 5 个 FAIL。

- [ ] **Step 3: 实现**

加在 `_build_upgrade_command` 之后:

```python
def _prompt_yes_no(question: str, default_yes: bool = True) -> bool:
    """TTY 安全的 Y/N prompt。

    非 TTY 直接返回 default_yes(管道、cron 等场景不交互)。
    TTY 上 'y'/'yes' → True,'n'/'no' → False,空 → default_yes,其他 → 重问一次。
    Ctrl-C 透传给上层 (run_upgrade 会捕获)。
    """
    if not sys.stdin.isatty():
        return default_yes
    try:
        answer = input(question + ' ').strip().lower()
    except EOFError:
        return default_yes
    if answer in ('y', 'yes'):
        return True
    if answer in ('n', 'no'):
        return False
    return default_yes  # 空输入或不识别 → 用 default
```

- [ ] **Step 4: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestPromptYesNo -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): _prompt_yes_no TTY 安全的 Y/N 交互"
```

---

## Task 5: `run_upgrade()` — 主升级流程

这是核心,要实现完整流程:刷缓存 → 对比 → 显示 / prompt → subprocess。

**Files:**
- Modify: `spyeyes/__init__.py`
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试 (8 个测试,覆盖所有分支)**

```python
class TestRunUpgrade:
    """v1.8.2: run_upgrade 主流程。"""

    def test_already_latest_returns_0(self, monkeypatch, capsys):
        """已是最新 → 显示 '✓ Already on latest' + return 0。"""
        gt.set_lang('en')
        # mock _get_cached_update_info 返回 None (means: no newer version)
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: None)
        rc = gt.run_upgrade(yes=False, check_only=False)
        assert rc == 0
        assert 'Already on latest' in capsys.readouterr().out

    def test_check_only_does_not_subprocess(self, monkeypatch, capsys):
        """--check → 显示对比 + return 0,不调 subprocess。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1',
                'url': 'https://github.com/Akxan/SpyEyes/releases/tag/v1.8.2'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        subprocess_called = []
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: subprocess_called.append(a) or None)
        rc = gt.run_upgrade(yes=False, check_only=True)
        assert rc == 0
        assert subprocess_called == []
        out = capsys.readouterr().out
        assert 'v1.8.2' in out
        assert '1.8.1' in out

    def test_source_mode_shows_command_only(self, monkeypatch, capsys):
        """源码安装 → 只显示命令,不 subprocess,return 0。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'source')
        subprocess_called = []
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: subprocess_called.append(a) or None)
        rc = gt.run_upgrade(yes=True, check_only=False)
        assert rc == 0
        assert subprocess_called == []
        assert 'git pull' in capsys.readouterr().out

    def test_packaged_yes_calls_subprocess(self, monkeypatch, capsys):
        """打包 + yes=True → subprocess 被调一次,成功 → return 0。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'packaged-pip')

        class FakeCompleted:
            returncode = 0
        called = []
        def fake_run(cmd, **kw):
            called.append(cmd)
            return FakeCompleted()
        monkeypatch.setattr('subprocess.run', fake_run)

        rc = gt.run_upgrade(yes=True, check_only=False)
        assert rc == 0
        assert len(called) == 1
        assert '--upgrade' in called[0]

    def test_packaged_user_declines_returns_0(self, monkeypatch, capsys):
        """打包 + 用户 N → 不调 subprocess,return 0 (用户主动取消)。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'packaged-pip')
        monkeypatch.setattr(gt, '_prompt_yes_no', lambda *a, **kw: False)
        subprocess_called = []
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: subprocess_called.append(a) or None)
        rc = gt.run_upgrade(yes=False, check_only=False)
        assert rc == 0
        assert subprocess_called == []
        assert 'Cancelled' in capsys.readouterr().out

    def test_non_tty_without_yes_returns_2(self, monkeypatch, capsys):
        """非 TTY + 不带 yes → return 2 错误。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'packaged-pip')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        rc = gt.run_upgrade(yes=False, check_only=False)
        assert rc == 2
        assert 'TTY' in capsys.readouterr().out or '--yes' in capsys.readouterr().out

    def test_subprocess_failure_propagates_exit_code(self, monkeypatch, capsys):
        """subprocess 非 0 退出 → 透传 exit code + 显示兜底手动命令。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'packaged-pip')

        class FakeCompleted:
            returncode = 1
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: FakeCompleted())

        rc = gt.run_upgrade(yes=True, check_only=False)
        assert rc == 1
        out = capsys.readouterr().out
        assert 'failed' in out.lower() or 'Manual' in out

    def test_pipx_missing_falls_back(self, monkeypatch, capsys):
        """pipx mode + which('pipx') 找不到 → 降级显示 pip 命令 + return 1。"""
        gt.set_lang('en')
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, 'refresh_update_cache_sync', lambda: None)
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(gt, '_detect_install_mode', lambda: 'packaged-pipx')
        monkeypatch.setattr('shutil.which', lambda c: None)  # pipx 找不到
        subprocess_called = []
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: subprocess_called.append(a) or None)
        rc = gt.run_upgrade(yes=True, check_only=False)
        assert rc == 1
        assert subprocess_called == []
        assert 'pipx' in capsys.readouterr().out
```

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestRunUpgrade -v
```

Expected: 8 个 FAIL — `module has no attribute 'run_upgrade'`。

- [ ] **Step 3: 实现 `run_upgrade()`**

加在 `_prompt_yes_no` 之后:

```python
def run_upgrade(yes: bool = False, check_only: bool = False) -> int:
    """v1.8.2 一键升级主流程。

    流程:
      1. 强刷 update cache (绕过 24h)
      2. 拿 _get_cached_update_info(),无新版 → 显示 '✓ Already on latest' return 0
      3. 显示当前/最新版本对比 + release notes URL
      4. check_only → return 0 (不 prompt 不 subprocess)
      5. mode = _detect_install_mode()
         - source → 显示 git pull 命令 → return 0 (不 subprocess)
         - packaged-pipx 但找不到 pipx → 降级显示 pip 命令 → return 1
      6. 非 yes 且非 TTY → return 2 (no_tty 错误)
      7. 非 yes 但 TTY → prompt Y/N,N → 显示 'Cancelled' return 0
      8. subprocess.run 跑命令 (流式输出走子进程的 stdout/stderr 继承)
      9. 成功 → 显示 '✓ Upgraded. Please re-run.' return 0
         失败 → 显示 '✗ Upgrade failed. Manual: ...' return 子进程 exit code

    Return code 约定:
      0  成功 / 已是最新 / 用户取消 / check-only / 源码模式
      1  网络错 / pipx 找不到
      2  非 TTY 缺 --yes
      130 Ctrl-C
      其他 透传 subprocess exit code
    """
    print(f" {Color.Cy}{t('upgrade.checking')}{Color.Reset}")
    try:
        refresh_update_cache_sync()
    except Exception:
        print(f" {Color.Re}{t('upgrade.network_error')}{Color.Reset}")
        return 1

    info = _get_cached_update_info()
    if not info:
        print(f" {Color.Gr}{t('upgrade.already_latest', current=__version__)}{Color.Reset}")
        return 0

    latest = info['latest']
    current = info['current']
    url = info.get('url', '')

    print(f" {Color.Wh}{t('upgrade.found_new', current=current, latest=latest)}{Color.Reset}")
    if url:
        print(f" {Color.Cy}{t('upgrade.release_notes', url=url)}{Color.Reset}")

    if check_only:
        return 0

    mode = _detect_install_mode()
    if mode == 'source':
        print(f" {Color.Ye}{t('upgrade.source_install_hint')}{Color.Reset}")
        return 0

    cmd = _build_upgrade_command(mode)
    if mode == 'packaged-pipx' and shutil.which('pipx') is None:
        # pipx 不在 PATH,降级到 pip 命令兜底
        pip_cmd = _build_upgrade_command('packaged-pip') or []
        pip_str = ' '.join(pip_cmd)
        print(f" {Color.Re}{t('upgrade.pipx_missing', pip_cmd=pip_str)}{Color.Reset}")
        return 1

    if cmd is None:
        return 1

    if not yes:
        if not sys.stdin.isatty():
            print(f" {Color.Re}{t('upgrade.no_tty')}{Color.Reset}")
            return 2
        try:
            if not _prompt_yes_no(t('upgrade.confirm'), default_yes=True):
                print(f" {Color.Wh}{t('upgrade.cancelled')}{Color.Reset}")
                return 0
        except KeyboardInterrupt:
            print(f"\n {Color.Wh}{t('upgrade.cancelled')}{Color.Reset}")
            return 130

    cmd_str = ' '.join(cmd)
    print(f"\n {Color.Cy}{t('upgrade.running_cmd', cmd=cmd_str)}{Color.Reset}\n")
    try:
        completed = subprocess.run(cmd)  # 流式继承当前进程 stdout/stderr
    except (OSError, FileNotFoundError) as e:
        print(f" {Color.Re}{t('upgrade.failed', code=str(e), cmd=cmd_str)}{Color.Reset}")
        return 1

    if completed.returncode == 0:
        print(f"\n {Color.Gr}{t('upgrade.success', latest=latest)}{Color.Reset}")
        return 0
    else:
        print(f"\n {Color.Re}{t('upgrade.failed', code=completed.returncode, cmd=cmd_str)}{Color.Reset}")
        return completed.returncode
```

确保文件顶部有 `import subprocess` 和 `import shutil`:

```bash
grep -E "^import subprocess|^import shutil" spyeyes/__init__.py
```

如缺,补到文件顶部 import 区段。

- [ ] **Step 4: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestRunUpgrade -v
```

Expected: 8 passed。

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): run_upgrade 主流程 (8 分支全覆盖)"
```

---

## Task 6: 菜单 `[12]` 入口

**Files:**
- Modify: `spyeyes/__init__.py:5367-5380` (MENU_KEYS) + `spyeyes/__init__.py:5525` (handle_choice)
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试**

```python
class TestMenuUpgradeItem:
    """v1.8.2: 菜单 [12] Check & Upgrade 入口。"""

    def test_menu_key_12_in_MENU_KEYS(self):
        """[12] 项必须在 MENU_KEYS 列表里,key='menu.upgrade'。"""
        items = dict(gt.MENU_KEYS)
        assert 12 in items
        assert items[12] == 'menu.upgrade'

    def test_handle_choice_12_calls_run_upgrade(self, monkeypatch):
        """选 12 → 调 run_upgrade(yes=False, check_only=False)。"""
        called = []
        monkeypatch.setattr(gt, 'run_upgrade',
                            lambda yes=False, check_only=False: called.append((yes, check_only)) or 0)
        gt.handle_choice(12)
        assert called == [(False, False)]
```

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestMenuUpgradeItem -v
```

Expected: 2 FAIL — 12 not in MENU_KEYS, handle_choice raises ValueError。

- [ ] **Step 3: 修改 MENU_KEYS**

定位 [`spyeyes/__init__.py:5367-5380`](../../spyeyes/__init__.py#L5367):

```python
MENU_KEYS = [
    (1, 'menu.ip_track'),
    (2, 'menu.my_ip'),
    (3, 'menu.phone'),
    (4, 'menu.username'),
    (5, 'menu.whois'),
    (6, 'menu.mx'),
    (7, 'menu.email'),
    (8, 'menu.subdomain'),
    (9, 'menu.domain_emails'),
    (10, 'menu.investigate'),
    (11, 'menu.lang'),
    (0, 'menu.exit'),
]
```

改成:

```python
MENU_KEYS = [
    (1, 'menu.ip_track'),
    (2, 'menu.my_ip'),
    (3, 'menu.phone'),
    (4, 'menu.username'),
    (5, 'menu.whois'),
    (6, 'menu.mx'),
    (7, 'menu.email'),
    (8, 'menu.subdomain'),
    (9, 'menu.domain_emails'),
    (10, 'menu.investigate'),
    (11, 'menu.lang'),
    (12, 'menu.upgrade'),    # v1.8.2: 一键升级
    (0, 'menu.exit'),
]
```

- [ ] **Step 4: 修改 `handle_choice` 加 `[12]` 分支**

定位 `handle_choice` 函数 (`spyeyes/__init__.py:5525`)。在它处理 `11` (lang) 的分支后、`0` (exit) 之前加:

```python
    elif choice == 12:
        # v1.8.2: 一键升级
        run_upgrade()
```

(如果 `handle_choice` 用的是 if/elif 串,加在合适位置;如用 dict 查表,加 entry。建议先 grep `choice == 11` 找精确位置。)

- [ ] **Step 5: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestMenuUpgradeItem -v
```

Expected: 2 passed。

- [ ] **Step 6: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): 菜单 [12] Check & Upgrade 入口"
```

---

## Task 7: 菜单启动自动 prompt

**Files:**
- Modify: `spyeyes/__init__.py:8597` (menu_loop 入口)
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试**

```python
class TestMenuStartupPrompt:
    """v1.8.2: 菜单启动自动 prompt (仅 TTY + 有缓存的新版)。"""

    def test_prompt_called_when_cache_has_new_and_tty(self, monkeypatch):
        """缓存有新版 + TTY → _prompt_yes_no 被调一次。"""
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        prompted = []
        monkeypatch.setattr(gt, '_prompt_yes_no',
                            lambda *a, **kw: prompted.append(a) or False)  # 选 N 避免 exit
        # 让菜单循环退出 (用户选 0)
        monkeypatch.setattr('builtins.input', lambda _: '0')
        try:
            gt.menu_loop()
        except SystemExit:
            pass
        assert len(prompted) == 1

    def test_prompt_skipped_when_no_new_cache(self, monkeypatch):
        """缓存无新版 → 不 prompt。"""
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: None)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        prompted = []
        monkeypatch.setattr(gt, '_prompt_yes_no', lambda *a, **kw: prompted.append(a) or False)
        monkeypatch.setattr('builtins.input', lambda _: '0')
        try:
            gt.menu_loop()
        except SystemExit:
            pass
        assert prompted == []

    def test_prompt_skipped_when_not_tty(self, monkeypatch):
        """非 TTY → 不 prompt (即使有新版)。"""
        info = {'latest': 'v1.8.2', 'current': '1.8.1', 'url': 'X'}
        monkeypatch.setattr(gt, '_get_cached_update_info', lambda: info)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        prompted = []
        monkeypatch.setattr(gt, '_prompt_yes_no', lambda *a, **kw: prompted.append(a) or False)
        monkeypatch.setattr('builtins.input', lambda _: '0')
        try:
            gt.menu_loop()
        except SystemExit:
            pass
        assert prompted == []
```

注意:`menu_loop` 当前 `try: int(raw)` 解析,输入 '0' 会 `handle_choice(0)`,handle_choice 里 `0` 是退出 → `sys.exit` 或类似。测试用 `try/except SystemExit` 兜住。

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestMenuStartupPrompt -v
```

Expected: `test_prompt_called_when_cache_has_new_and_tty` FAIL (因为还没加 prompt 逻辑)。

- [ ] **Step 3: 修改 `menu_loop`**

定位 [`spyeyes/__init__.py:8597`](../../spyeyes/__init__.py#L8597):

```python
def menu_loop(save_dir: Optional[str] = None) -> None:
    while True:
        clear_screen()
        ...
```

在 `while True:` 之前(函数体最开始)加自动 prompt 逻辑:

```python
def menu_loop(save_dir: Optional[str] = None) -> None:
    # v1.8.2: 启动时如有缓存的新版 + TTY → prompt Y/N 升级。选 N 跳过本次。
    _menu_startup_upgrade_prompt()
    while True:
        clear_screen()
        ...
```

然后在文件中加 helper(放在 `menu_loop` 之前):

```python
def _menu_startup_upgrade_prompt() -> None:
    """菜单启动时检测缓存的新版本,有则 prompt Y/N。仅 TTY 触发。"""
    if not sys.stdin.isatty():
        return
    info = _get_cached_update_info()
    if not info:
        return
    msg = t('upgrade.prompt_menu_start',
            latest=info['latest'], current=info['current'])
    try:
        if _prompt_yes_no(f"\n {Color.Ye}{msg}{Color.Reset}", default_yes=True):
            rc = run_upgrade(yes=True)
            sys.exit(rc)  # 升级后 exit,提示用户重启
        # 选 N → 继续菜单
    except KeyboardInterrupt:
        sys.exit(130)
```

- [ ] **Step 4: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestMenuStartupPrompt -v
```

Expected: 3 passed。

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): 菜单启动自动 prompt 升级 (TTY 安全)"
```

---

## Task 8: CLI `spyeyes upgrade` 子命令

**Files:**
- Modify: `spyeyes/__init__.py:8647` (build_parser) + `spyeyes/__init__.py:8912` (run_cli)
- Modify: `tests/test_spyeyes.py`

- [ ] **Step 1: 写测试**

```python
class TestCliUpgradeSubcommand:
    """v1.8.2: CLI `spyeyes upgrade [--yes] [--check]` 子命令。"""

    def test_parser_accepts_upgrade(self):
        """build_parser() 能解析 'upgrade' 子命令。"""
        parser = gt.build_parser()
        args = parser.parse_args(['upgrade'])
        assert args.subcommand == 'upgrade'
        assert args.yes is False
        assert args.check is False

    def test_parser_accepts_yes_flag(self):
        parser = gt.build_parser()
        args = parser.parse_args(['upgrade', '--yes'])
        assert args.yes is True

    def test_parser_accepts_check_flag(self):
        parser = gt.build_parser()
        args = parser.parse_args(['upgrade', '--check'])
        assert args.check is True

    def test_run_cli_dispatches_upgrade(self, monkeypatch):
        """run_cli 收到 upgrade subcommand → 调 run_upgrade。"""
        called = []
        monkeypatch.setattr(gt, 'run_upgrade',
                            lambda yes, check_only: called.append((yes, check_only)) or 0)
        parser = gt.build_parser()
        args = parser.parse_args(['upgrade', '--yes'])
        rc = gt.run_cli(args)
        assert called == [(True, False)]
        assert rc == 0
```

- [ ] **Step 2: 跑测试确认失败**

```bash
pytest tests/test_spyeyes.py::TestCliUpgradeSubcommand -v
```

Expected: 4 FAIL — argparse 不认识 upgrade。

- [ ] **Step 3: 修改 `build_parser` 加 subparser**

定位 [`spyeyes/__init__.py:8647`](../../spyeyes/__init__.py#L8647) `build_parser()` 函数。在它里面 subparsers 区段(应该已经有 `subparsers = parser.add_subparsers(dest='subcommand', ...)`)的合适位置(其他子命令旁)加:

```python
    # v1.8.2: 一键升级
    p_upgrade = subparsers.add_parser('upgrade', help=t('menu.upgrade'))
    p_upgrade.add_argument('--yes', '-y', action='store_true',
                           help='Skip confirmation prompt')
    p_upgrade.add_argument('--check', action='store_true',
                           help='Check for updates without installing')
```

(`t('menu.upgrade')` 在 help 里调用 — argparse parse 时 _lang 应该已设。若有问题就用字面 string。)

- [ ] **Step 4: 修改 `run_cli` 加 dispatch**

定位 [`spyeyes/__init__.py:8912`](../../spyeyes/__init__.py#L8912) `run_cli(args)` 函数。在 dispatch 链(`if args.subcommand == 'ip': ... elif args.subcommand == 'phone': ... `)合适位置加:

```python
    elif args.subcommand == 'upgrade':
        return run_upgrade(yes=args.yes, check_only=args.check)
```

- [ ] **Step 5: 跑测试确认通过**

```bash
pytest tests/test_spyeyes.py::TestCliUpgradeSubcommand -v
```

Expected: 4 passed。

- [ ] **Step 6: Commit**

```bash
git add spyeyes/__init__.py tests/test_spyeyes.py
git commit -m "feat(v1.8.2 wip): CLI spyeyes upgrade [--yes] [--check] 子命令"
```

---

## Task 9: 版本号 + CHANGELOG

**Files:**
- Modify: `spyeyes/__init__.py:71` (__version__)
- Modify: `pyproject.toml:26` (version)
- Modify: `docs/CHANGELOG.md`

- [ ] **Step 1: 升 `__version__`**

```bash
grep -n "^__version__" spyeyes/__init__.py
```

修改为:

```python
__version__ = '1.8.2'
```

- [ ] **Step 2: 升 pyproject**

```bash
grep -n "^version" pyproject.toml
```

修改为:

```toml
version = "1.8.2"  # 同步：spyeyes/__init__.py __version__ + docs/CHANGELOG.md + git tag
```

- [ ] **Step 3: 加 CHANGELOG 条目**

在 `docs/CHANGELOG.md` 的 `## [Unreleased]` 区段之后、`## [1.8.1] — 2026-05-13` 之前插:

```markdown
---

## [1.8.2] — 2026-05-13

✨ **一键升级** — 用户启动菜单时如有新版本,直接 Y/N 选择是否升级;CLI 也有 `spyeyes upgrade` 子命令。

### 新功能

- **菜单启动自动 prompt**:进交互菜单时,如 24h 后台缓存检测到新版 + TTY → 弹 `🆕 v1.8.2 available. Upgrade now? [Y/n]:`。选 Y 自动跑 pip/pipx 升级,完成 exit 0 提示用户重启;选 N 跳过本次继续菜单。
- **菜单 [12] Check & Upgrade**:菜单里随时点 `[12]` 主动检查 + 升级(强刷缓存,绕 24h 限制)。
- **CLI `spyeyes upgrade`**:命令行直接升级。
  - `spyeyes upgrade` — 强刷查最新版,prompt Y/N
  - `spyeyes upgrade --yes` / `-y` — 跳 prompt 直接升
  - `spyeyes upgrade --check` — 只查不升

### 跨平台 + 安装方式自适应

| 安装方式 | 升级行为 |
|---|---|
| `pip install git+URL` | subprocess 跑 `pip install --upgrade git+URL` 标准卸载 + 重装,旧版本彻底清除 |
| `pipx install ...` | subprocess 跑 `pipx upgrade spyeyes`,独立 venv 完全隔离 |
| `git clone + pip install -e .` | 只显示 `git pull && pip install -e .` 让用户复制(git 冲突风险,不自动跑) |

升级后**绝不留旧版本残留**(pip/pipx 标准包管理),用户数据 `~/.spyeyes/`(config/history/cache) 保留。

### 边界处理

- 非 TTY 缺 `--yes` → 友好报错 + 兜底显示手动命令
- `pipx` 不在 PATH → 自动降级到 `pip install --upgrade` 命令
- subprocess 失败 → 透传 exit code + 显示兜底手动命令
- 网络断 → "Could not reach GitHub Releases" + return 1
- 用户 Ctrl-C → "Cancelled" return 130
- Windows 文件锁 → 不尝试自我替换,升级后 exit 0 提示重启

### 设计参考

- spec: `docs/design/2026-05-13-one-click-upgrade.md`
- plan: `docs/plans/2026-05-13-one-click-upgrade-plan.md`

### 验收

- ✅ ruff 0 / mypy 0 / bandit 0
- ✅ pytest 548 + ~32 新 = ~580 passed
- ✅ Linux × Py 3.10-3.14 / macOS × Py 3.10,3.14 / Windows × Py 3.10,3.14 全绿
```

- [ ] **Step 4: 本地验收版本号一致性**

```bash
grep -E "^__version__|^version" spyeyes/__init__.py pyproject.toml
spyeyes --version 2>&1 || python -m spyeyes --version  # 装了 -e . 的可直接跑
```

Expected: 两处都显示 1.8.2,`spyeyes --version` 输出 `spyeyes 1.8.2`。

- [ ] **Step 5: Commit**

```bash
git add spyeyes/__init__.py pyproject.toml docs/CHANGELOG.md
git commit -m "chore(v1.8.2): bump version + CHANGELOG 一键升级条目"
```

---

## Task 10: 完整本地验收 + push

- [ ] **Step 1: 跑完整 lint 三件套 + 完整测试套件**

```bash
source .venv/bin/activate
echo "=== ruff ===" && ruff check . | tail -3
echo "=== mypy ===" && mypy spyeyes tools/build_platforms.py --ignore-missing-imports | tail -3
echo "=== bandit ===" && (bandit -r spyeyes/ tools/ -ll >/dev/null 2>&1 && echo OK) || echo FAIL
echo "=== pytest ===" && pytest tests/ --timeout=15 --timeout-method=thread -q | tail -3
```

Expected: 全绿,pytest ~580 passed (548 base + ~32 新)。

- [ ] **Step 2: 真实手测 (smoke test)**

```bash
# 验证 CLI subcommand 注册
spyeyes upgrade --check 2>&1 | head -5  # 应显示"Already on latest"(因为本地装的就是 latest)
                                        # 或显示版本对比(如果远程有更新)
spyeyes upgrade --help                   # 应显示 --yes / --check 帮助
# 验证菜单项注册
echo "0" | spyeyes 2>&1 | grep -i "Check & Upgrade\|检查并升级"  # 应能看到 [12] 项
```

- [ ] **Step 3: push 到 main 触发 CI**

```bash
git push origin main
sleep 5
gh run list --branch main --limit 1
```

- [ ] **Step 4: 等 CI 通过**

```bash
RUN_ID=$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch $RUN_ID --interval 20 --exit-status
gh run view $RUN_ID --json conclusion,jobs --jq '{conclusion, failed: [.jobs[] | select(.conclusion != "success") | .name]}'
```

Expected: conclusion success,failed []。

如有 Windows × Py 3.10 setup-python flake (前几次见过) → `gh run rerun $RUN_ID --failed`,等再次完成。

---

## Task 11: 发 v1.8.2 (tag + release)

- [ ] **Step 1: 打 tag**

```bash
git tag -a v1.8.2 -m "v1.8.2 — 一键升级 (菜单 Y/N + CLI upgrade)"
git push origin v1.8.2
```

- [ ] **Step 2: 创建 GitHub Release**

```bash
gh release create v1.8.2 \
  --title "v1.8.2 — 一键升级 (菜单 Y/N + CLI upgrade 子命令)" \
  --notes "$(cat <<'EOF'
## ✨ v1.8.2: 一键升级

v1.8.0 做了启动版本检查 + stderr 通知。**v1.8.2 补全升级闭环 —— 用户选 Y 自动升级**,不再需要手动复制命令。

## 三条升级通道

| 通道 | 触发 | 行为 |
|---|---|---|
| **菜单启动自动 prompt** | 进交互菜单 + 后台缓存检测到新版 + TTY | 弹 `🆕 v1.8.2 available. Upgrade now? [Y/n]:` |
| **菜单 [12] Check & Upgrade** | 用户在菜单点 [12] | 强刷缓存 → 显示版本对比 → prompt |
| **CLI `spyeyes upgrade`** | 命令行 | `[--yes]` 跳 prompt / `[--check]` 只查不升 |

## 安装方式自适应

| 你的安装方式 | 自动升级行为 |
|---|---|
| `pip install git+URL` | subprocess 跑 `pip install --upgrade ...` |
| `pipx install git+URL` | subprocess 跑 `pipx upgrade spyeyes` |
| `git clone + pip install -e .` | 显示 \`git pull && pip install -e .\` 让你手动跑(git 冲突风险) |

## 安全 + 干净

- 旧版本**彻底卸载**(pip uninstall 清完 site-packages 再装新版)
- 用户数据 `~/.spyeyes/` (config/history/cache) **保留**
- Windows 文件锁:升级后 exit 0 提示重启,绝不尝试自我替换
- 非 TTY 缺 \`--yes\` → 友好报错不挂
- 网络断 → \"Could not reach GitHub Releases\" 提示后退出
- 用户 Ctrl-C → \"Cancelled\" 干净退出

## 用户控制开关

| 关闭 | 方式 |
|---|---|
| 关闭启动版本检查(继承自 v1.8.0) | \`SPYEYES_NO_UPDATE_CHECK=1\` 或 \`--no-update-check\` |
| 强制看版本对比不升级 | \`spyeyes upgrade --check\` 或 菜单 [12] 在 prompt 处选 N |

## 验收

- ✅ ruff 0 / mypy 0 / bandit 0
- ✅ pytest ~580 passed (548 base + 32 新覆盖 5 个新功能 + 14 个 i18n key)
- ✅ Linux × Py 3.10-3.14 / macOS × Py 3.10,3.14 / Windows × Py 3.10,3.14 全绿

**Full Changelog**: https://github.com/Akxan/SpyEyes/compare/v1.8.1...v1.8.2
EOF
)"
```

- [ ] **Step 3: 验证 release**

```bash
gh release view v1.8.2 --json url,tagName,publishedAt --jq '.'
gh release list --limit 3
```

Expected: v1.8.2 为 Latest,URL 可访问。

---

## Self-Review 结果

Plan 与 spec 对照检查:

1. ✅ **触发点 (3 个)**:菜单启动 prompt → Task 7;菜单 [12] → Task 6;CLI upgrade → Task 8
2. ✅ **执行方式 (mode 自适应)**:Task 2 detect mode + Task 3 build cmd + Task 5 dispatch
3. ✅ **完成后 exit 0**:Task 7 menu_loop hook 里 `sys.exit(rc)` (after run_upgrade)
4. ✅ **i18n 14 keys**:Task 1
5. ✅ **错误处理 (9 种)**:Task 5 的 8 测试 + 网络错 / 非 TTY / pipx 缺失 / Ctrl-C / subprocess 失败 / 已是最新 / 源码模式 / check-only / 用户 N
6. ✅ **跨平台**:Task 3 测试用 `sys.executable` 而非 `pip` 字面;Task 2 测试 POSIX + Windows 两种 pipx 路径
7. ✅ **测试 ~32 个**(spec 写 14,实际拆细 32: i18n 3 + detect 4 + build 3 + prompt 5 + run_upgrade 8 + menu 5 + cli 4)

**Type consistency**:
- `_detect_install_mode() -> str` (Task 2) ✓
- `_build_upgrade_command(mode: str) -> Optional[list[str]]` (Task 3) ✓ — Task 5 用 `mode = _detect_install_mode(); cmd = _build_upgrade_command(mode)` 类型一致 ✓
- `_prompt_yes_no(question: str, default_yes: bool) -> bool` (Task 4) ✓ — Task 5 / Task 7 用法一致 ✓
- `run_upgrade(yes: bool, check_only: bool) -> int` (Task 5) ✓ — Task 6 / Task 7 / Task 8 调用形式一致 ✓

**Spec 覆盖完整**。
