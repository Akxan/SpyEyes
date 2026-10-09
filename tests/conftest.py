"""pytest 全局 fixtures。

每个测试自动重置全局状态（语言、Color、thread-local Session），避免测试间污染。
"""
import os
import sys

import pytest

# 让 tests/ 能 import 上层 spyeyes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402

# 预热延迟导入的重型模块。spyeyes 把 phonenumbers 数据表(track_phone 内)和 reportlab
# (_import_reportlab)推迟到用到时才导入;但冷缓存的 CI runner 上首次导入 geodata 可能超过
# 15 s,会被 --timeout=15 算进"第一个查电话的测试"而误杀。在收集阶段导入一次,
# 让 per-test timeout 只衡量测试本身。(TestLazyHeavyImports 用子进程验证延迟导入,不受影响)
from phonenumbers import carrier, geocoder, timezone  # noqa: E402,F401

gt._import_reportlab()


_COLOR_ATTRS = gt._COLOR_ATTRS

# 会改变被测行为的用户环境变量。spyeyes 在 import 时 _load_env_file() 会把开发者
# ~/.spyeyes/env 里的值注入 os.environ —— 例如本机设了 SPYEYES_NO_HISTORY=1 时,
# 所有写历史的测试都会失败;SPYEYES_BRUTEFORCE=1 会往子域测试里塞 220 个字典候选。
# 每个测试前统一清掉,需要的测试再显式 setenv。
_BEHAVIOR_ENV_VARS = (
    'SPYEYES_NO_HISTORY', 'SPYEYES_BRUTEFORCE', 'SPYEYES_DNS_WORDLIST',
    'SPYEYES_REPORTS_DIR', 'SPYEYES_PHONE_API_KEY', 'SPYEYES_GITHUB_TOKEN',
    'SPYEYES_OTX_API_KEY', 'SPYEYES_CERTSPOTTER_API_KEY', 'NO_COLOR', 'SPYEYES_THEME',
)


@pytest.fixture(autouse=True)
def reset_global_state(tmp_path, monkeypatch):
    """每个测试前后恢复 _lang、Color、thread-local session、PLATFORMS 缓存。

    并全局隔离 CONFIG_DIR / CONFIG_FILE / HISTORY_FILE / ENV_FILE 到 tmp_path —— 防止
    任何测试静默写入用户真实 ~/.spyeyes/（之前 TestRunCli 等多处遗漏 patch
    CONFIG_DIR 导致每次 pytest 都在用户家目录建空 .spyeyes/ 目录）。

    用 try/finally 保证即使测试体抛异常也能恢复。"""
    saved_lang = gt._lang
    saved_color = {a: getattr(gt.Color, a) for a in _COLOR_ATTRS}
    saved_color['enabled'] = gt.Color.enabled

    # 把所有用户数据路径重定向到 tmp（每个测试一个独立目录）
    fake_config_dir = str(tmp_path / '.spyeyes')
    monkeypatch.setattr(gt, 'CONFIG_DIR', fake_config_dir)
    monkeypatch.setattr(gt, 'CONFIG_FILE', f'{fake_config_dir}/config.json')
    monkeypatch.setattr(gt, 'HISTORY_FILE', f'{fake_config_dir}/history.jsonl')
    monkeypatch.setattr(gt, 'UPDATE_CACHE_FILE', f'{fake_config_dir}/.update_check.json')
    monkeypatch.setattr(gt, 'ENV_FILE', f'{fake_config_dir}/env')

    for var in _BEHAVIOR_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # 升级逻辑会按宿主 Python 是否 PEP 668「外部管理环境」走不同分支 —— 默认视为普通环境,
    # 让结果不取决于跑测试的是 venv 还是 Homebrew Python;需要时测试里再显式 patch 成 True
    monkeypatch.setattr(gt, '_is_externally_managed', lambda: False)
    # subfinder 探测结果是模块级缓存:强制"未安装",防止装了 subfinder 的开发机跑真实子进程
    monkeypatch.setattr(gt, '_SUBFINDER_BIN', None)
    monkeypatch.setattr(gt, '_SUBFINDER_CHECKED', True)

    # 默认禁用更新检查 — 避免测试套件击打 GitHub API。
    # 单个测试需要测 update logic 时,显式 monkeypatch.delenv 'SPYEYES_NO_UPDATE_CHECK'。
    monkeypatch.setenv('SPYEYES_NO_UPDATE_CHECK', '1')

    try:
        yield
    finally:
        gt._lang = saved_lang
        for k, v in saved_color.items():
            setattr(gt.Color, k, v)
        # 强制 reset 为 None 让下个测试触发干净懒加载（避免依赖测试执行顺序）
        # 性能影响可忽略：_load_platforms_json ~50ms × 260+ 测试 = ~13s 可接受
        # 实际不会每次都触发 —— 大多测试不访问 PLATFORMS
        gt._PLATFORMS_CACHE = None
        if hasattr(gt._thread_local, 'session'):
            try:
                gt._thread_local.session.close()
            except Exception:
                pass
            del gt._thread_local.session
