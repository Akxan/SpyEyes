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
def reset_global_state():
    """每个测试前后恢复 _lang、Color、thread-local session、PLATFORMS 缓存。
    用 try/finally 保证即使测试体抛异常也能恢复，避免污染下个测试。"""
    saved_lang = gt._lang
    saved_color = {a: getattr(gt.Color, a) for a in _COLOR_ATTRS}
    saved_color['enabled'] = gt.Color.enabled
    saved_platforms_cache = gt._PLATFORMS_CACHE
    try:
        yield
    finally:
        gt._lang = saved_lang
        for k, v in saved_color.items():
            setattr(gt.Color, k, v)
        gt._PLATFORMS_CACHE = saved_platforms_cache
        if hasattr(gt._thread_local, 'session'):
            try:
                gt._thread_local.session.close()
            except Exception:
                pass
            del gt._thread_local.session
