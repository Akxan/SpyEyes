"""tools/build_platforms.py 单元测试。

覆盖纯函数（parse_maigret/sherlock/wmn、categorize、get_tld、merge_dedup、
atomic_write_json）以及关键的优先级语义。
"""
import json
import os
import sys
from unittest.mock import patch

import pytest

# 让 import 找到 tools/
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, 'tools'))

import build_platforms as bp  # noqa: E402


class TestGetTld:
    def test_basic(self):
        assert bp.get_tld('https://example.com/{}') == 'com'

    def test_two_level_known(self):
        assert bp.get_tld('https://example.com.cn/{}') == 'com.cn'

    def test_two_level_unknown_falls_back(self):
        # com.au 不在 TLD_CATEGORY 里 → 回退顶级 tld
        assert bp.get_tld('https://example.com.au/{}') == 'au'

    def test_invalid_url(self):
        assert bp.get_tld('not a url') == ''

    def test_empty(self):
        assert bp.get_tld('') == ''

    def test_single_part(self):
        assert bp.get_tld('http://localhost/{}') == ''


class TestCategorize:
    def test_adult_keyword_wins_over_social(self):
        # 'tinder' 是约会站，不应该被 'social' 类目误归
        assert bp.categorize('Tinder', 'https://tinder.com/{}') == 'adult'

    def test_chinese_keyword(self):
        assert bp.categorize('Weibo', 'https://weibo.com/{}') == 'chinese'

    def test_spanish_keyword(self):
        assert bp.categorize('Wallapop', 'https://wallapop.com/{}') == 'spanish'

    def test_tld_chinese(self):
        # 不在 keywords 里但 TLD 是 .com.cn
        assert bp.categorize('Random', 'https://example.com.cn/{}') == 'chinese'

    def test_tld_spanish(self):
        assert bp.categorize('Random', 'https://example.com.mx/{}') == 'spanish'

    def test_theme_code(self):
        assert bp.categorize('GitHub', 'https://github.com/{}') == 'code'

    def test_theme_social(self):
        assert bp.categorize('Facebook', 'https://facebook.com/{}') == 'social'

    def test_other_fallback(self):
        assert bp.categorize('Obscure', 'https://obscure-site-xyz.io/{}') == 'other'

    def test_adult_priority_over_chinese(self):
        # 即便 URL 含 .cn，pornhub 关键词也优先
        assert bp.categorize('PH-CN', 'https://pornhub.com.cn/{}') == 'adult'


class TestParseMaigret:
    def test_basic(self):
        raw = {'sites': {
            'GitHub': {
                'url': 'https://github.com/{username}',
                'absenceStrs': ['Not Found'],
                'presenseStrs': ['contributions'],
                'regexCheck': '^[a-z0-9-]+$',
            },
        }}
        result = bp.parse_maigret(raw)
        assert len(result) == 1
        item = result[0]
        assert item['name'] == 'GitHub'
        assert item['url'] == 'https://github.com/{}'
        assert item['not_found'] == ['Not Found']
        assert item['must_contain'] == ['contributions']
        assert item['regex_check'] == '^[a-z0-9-]+$'

    def test_disabled_skipped(self):
        raw = {'sites': {
            'Dead': {'url': 'https://dead.com/{username}', 'disabled': True},
        }}
        assert bp.parse_maigret(raw) == []

    def test_url_without_template_skipped(self):
        raw = {'sites': {
            'NoTemplate': {'url': 'https://example.com/profile'},
        }}
        assert bp.parse_maigret(raw) == []

    def test_max_patterns_truncated(self):
        raw = {'sites': {
            'Many': {
                'url': 'https://x.com/{username}',
                'absenceStrs': ['a', 'b', 'c', 'd', 'e', 'f'],
            },
        }}
        result = bp.parse_maigret(raw)
        assert len(result[0]['not_found']) == bp.MAX_PATTERNS_PER_PLATFORM

    def test_non_string_patterns_filtered(self):
        raw = {'sites': {
            'Mixed': {
                'url': 'https://x.com/{username}',
                'absenceStrs': ['valid', None, 123, ''],
            },
        }}
        result = bp.parse_maigret(raw)
        # None / 123 被过滤；空字符串保留（视为有效 str）
        assert all(isinstance(s, str) for s in result[0]['not_found'])

    def test_handles_no_sites_key(self):
        # 某些版本数据直接在顶层
        raw = {'X': {'url': 'https://x.com/{username}', 'absenceStrs': ['n']}}
        result = bp.parse_maigret(raw)
        assert len(result) == 1


class TestParseSherlock:
    def test_basic_string_errormsg(self):
        raw = {'GitHub': {
            'url': 'https://github.com/{}',
            'errorMsg': 'Not Found',
        }}
        result = bp.parse_sherlock(raw)
        assert result[0]['not_found'] == ['Not Found']

    def test_list_errormsg(self):
        raw = {'X': {'url': 'https://x.com/{}', 'errorMsg': ['a', 'b']}}
        result = bp.parse_sherlock(raw)
        assert result[0]['not_found'] == ['a', 'b']

    def test_skips_non_dict(self):
        raw = {'$schema': 'http://json-schema.org/...', 'X': {'url': 'https://x.com/{}'}}
        result = bp.parse_sherlock(raw)
        assert len(result) == 1
        assert result[0]['name'] == 'X'

    def test_skips_url_without_template(self):
        raw = {'NoTpl': {'url': 'https://x.com/profile'}}
        assert bp.parse_sherlock(raw) == []


class TestParseWmn:
    def test_basic(self):
        raw = {'sites': [
            {'name': 'GitHub', 'uri_check': 'https://github.com/{account}',
             'e_string': '404', 'm_string': 'contributions'},
        ]}
        result = bp.parse_wmn(raw)
        assert result[0]['url'] == 'https://github.com/{}'
        assert result[0]['not_found'] == ['404']
        assert result[0]['must_contain'] == ['contributions']

    def test_username_template(self):
        raw = {'sites': [{'name': 'X', 'uri_check': 'https://x.com/{username}'}]}
        result = bp.parse_wmn(raw)
        assert result[0]['url'] == 'https://x.com/{}'

    def test_no_template_skipped(self):
        raw = {'sites': [{'name': 'X', 'uri_check': 'https://x.com/'}]}
        assert bp.parse_wmn(raw) == []


class TestMergeDedup:
    def test_higher_pattern_count_wins(self):
        m = [{'name': 'GitHub', 'not_found': ['x', 'y'], 'must_contain': []}]
        s = [{'name': 'GitHub', 'not_found': [], 'must_contain': []}]
        merged = bp.merge_dedup(('maigret', m), ('sherlock', s))
        assert len(merged) == 1
        assert len(merged[0]['not_found']) == 2

    def test_priority_breaks_tie_sherlock_first(self):
        """同评分时 maigret 胜出（pri=3 > sherlock pri=1），sherlock 先到也一样。"""
        m = [{'name': 'GitHub', 'not_found': ['m'], 'must_contain': []}]
        s = [{'name': 'GitHub', 'not_found': ['s'], 'must_contain': []}]
        merged = bp.merge_dedup(('sherlock', s), ('maigret', m))
        assert merged[0]['not_found'] == ['m']

    def test_priority_breaks_tie_maigret_first(self):
        """反向顺序：maigret 先到，sherlock 后到也应保留 maigret。
        语义验证：'顺序无关' 说法必须真无关。"""
        m = [{'name': 'GitHub', 'not_found': ['m'], 'must_contain': []}]
        s = [{'name': 'GitHub', 'not_found': ['s'], 'must_contain': []}]
        merged = bp.merge_dedup(('maigret', m), ('sherlock', s))
        assert merged[0]['not_found'] == ['m'], \
            "maigret 先到时也应保留 maigret（pri 3 > sherlock pri 1）"

    def test_priority_whatsmyname_beats_sherlock(self):
        """whatsmyname (pri=2) 同分时应胜过 sherlock (pri=1)。"""
        s = [{'name': 'X', 'not_found': ['s'], 'must_contain': []}]
        w = [{'name': 'X', 'not_found': ['w'], 'must_contain': []}]
        merged = bp.merge_dedup(('sherlock', s), ('whatsmyname', w))
        assert merged[0]['not_found'] == ['w']

    def test_empty_name_skipped(self):
        m = [{'name': '', 'not_found': []}, {'name': 'X', 'not_found': []}]
        merged = bp.merge_dedup(('maigret', m))
        assert len(merged) == 1
        assert merged[0]['name'] == 'X'

    def test_case_insensitive_dedup(self):
        m = [{'name': 'GitHub', 'not_found': []}]
        s = [{'name': 'github', 'not_found': []}]
        merged = bp.merge_dedup(('maigret', m), ('sherlock', s))
        assert len(merged) == 1


class TestAtomicWrite:
    def test_writes_correctly(self, tmp_path):
        path = str(tmp_path / 'out.json')
        bp.atomic_write_json(path, {'k': 'v', 'n': [1, 2]})
        assert json.loads(open(path, encoding='utf-8').read()) == {'k': 'v', 'n': [1, 2]}

    def test_creates_parent_dir(self, tmp_path):
        path = str(tmp_path / 'sub' / 'out.json')
        bp.atomic_write_json(path, {'k': 'v'})
        assert os.path.exists(path)

    def test_temp_file_cleaned_on_failure(self, tmp_path):
        # 模拟 json.dump 失败，临时文件应被清理
        path = str(tmp_path / 'out.json')

        class Unserializable:
            pass

        with pytest.raises(TypeError):
            bp.atomic_write_json(path, {'k': Unserializable()})
        # 不应留下 .platforms.* 临时文件
        leftover = [f for f in os.listdir(tmp_path) if f.startswith('.platforms.')]
        assert leftover == [], f"临时文件未清理：{leftover}"


class TestFetchRetry:
    def test_succeeds_after_retry(self):
        attempts = {'count': 0}

        def flaky_get(url, timeout):
            attempts['count'] += 1
            if attempts['count'] < 2:
                import requests
                raise requests.RequestException('flaky')
            class R:
                def raise_for_status(self): pass
                def json(self): return {'ok': True}
            return R()

        with patch.object(bp.requests, 'get', side_effect=flaky_get):
            with patch.object(bp.time, 'sleep'):  # 跳过 backoff
                result = bp.fetch('https://x.com/d.json', retries=3)
        assert result == {'ok': True}
        assert attempts['count'] == 2

    def test_raises_after_max_retries(self):
        import requests as r

        def always_fail(url, timeout):
            raise r.RequestException('always')

        with patch.object(bp.requests, 'get', side_effect=always_fail):
            with patch.object(bp.time, 'sleep'):
                with pytest.raises(RuntimeError, match='fetch failed'):
                    bp.fetch('https://x.com/d.json', retries=2)


class TestNoFetchRequiresCacheDir:
    def test_main_rejects_no_fetch_without_cache(self):
        rc = bp.main(['--no-fetch'])
        assert rc == 2
