"""pytest 全局 fixtures。

每个测试自动重置全局状态（语言、Color、thread-local Session），避免测试间污染。
"""
import os
import sys

import pytest

# 让 tests/ 能 import 上层 spyeyes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402


_COLOR_ATTRS = ('Bl', 'Re', 'Gr', 'Ye', 'Blu', 'Mage', 'Cy', 'Wh', 'Reset')


@pytest.fixture(autouse=True)
def reset_global_state(tmp_path, monkeypatch):
    """每个测试前后恢复 _lang、Color、thread-local session、PLATFORMS 缓存。

    并全局隔离 CONFIG_DIR / CONFIG_FILE / HISTORY_FILE 到 tmp_path —— 防止
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

    try:
        yield
    finally:
        gt._lang = saved_lang
        for k, v in saved_color.items():
            setattr(gt.Color, k, v)
        # 强制 reset 为 None 让下个测试触发干净懒加载（避免依赖测试执行顺序）
        # 性能影响可忽略：_load_platforms_json ~50ms × 248 测试 = ~12s 可接受
        # 实际不会每次都触发 —— 大多测试不访问 PLATFORMS
        gt._PLATFORMS_CACHE = None
        if hasattr(gt._thread_local, 'session'):
            try:
                gt._thread_local.session.close()
            except Exception:
                pass
            del gt._thread_local.session
