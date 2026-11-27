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
                'absenceStrs': [f'p{i}' for i in range(bp.MAX_PATTERNS_PER_PLATFORM + 4)],
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
        """回归：e_string 是「存在标志」、m_string 是「不存在标志」。
        v1.1.0 ~ v1.8.6 接反了（m 被读成 must contain），这条测试当时也按接反的写。
        夹具取自 WhatsMyName 上游的 Chess.com 条目原文。"""
        raw = {'sites': [
            {'name': 'Chess.com', 'uri_check': 'https://api.chess.com/pub/player/{account}',
             'e_code': 200, 'e_string': '"player_id":',
             'm_code': 404, 'm_string': '"code":0'},
        ]}
        result = bp.parse_wmn(raw)
        assert result[0]['url'] == 'https://api.chess.com/pub/player/{}'
        assert result[0]['must_contain'] == ['"player_id":']
        assert result[0]['not_found'] == ['"code":0']

    def test_missing_strings_give_empty_rules(self):
        raw = {'sites': [{'name': 'X', 'uri_check': 'https://x.com/{account}', 'e_code': 200}]}
        result = bp.parse_wmn(raw)
        assert result[0]['must_contain'] == []
        assert result[0]['not_found'] == []

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


class TestMaigretEngineRules:
    """回归:引擎站点的检测规则在 `engine.site` 里。engine 顶层的 presenseStrs 是「识别论坛软件」的指纹,
    该论坛每个页面都有。v1.1.0 ~ v1.8.7 把指纹当成 must_contain、又漏掉 engine.site 的规则,
    1110 个论坛条目因此要么只看状态码,要么带着一条永远成立的「必须包含」。"""

    ENGINES = {'XenForo': {
        'presenseStrs': ['XenForo'],
        'site': {'checkType': 'message',
                 'absenceStrs': ['The requested page could not be found.',
                                 'The specified member cannot be found'],
                 'presenseStrs': ['memberHeader'],
                 'url': '{urlMain}{urlSubpath}/members/?username={username}'}}}

    def _parse(self, site):
        return bp.parse_maigret({'engines': self.ENGINES, 'sites': {'SomeForum': site}})[0]

    def test_engine_site_rules_are_used(self):
        item = self._parse({'engine': 'XenForo', 'urlMain': 'https://forum.example.com/',
                            'urlSubpath': '/community'})
        assert item['url'] == 'https://forum.example.com/community/members/?username={}'
        assert item['not_found'] == ['The requested page could not be found.',
                                     'The specified member cannot be found']
        assert item['must_contain'] == ['memberHeader']

    def test_engine_fingerprint_is_not_a_detection_rule(self):
        item = self._parse({'engine': 'XenForo', 'urlMain': 'https://forum.example.com'})
        assert 'XenForo' not in item['must_contain']

    def test_site_rules_come_first_and_duplicates_collapse(self):
        item = self._parse({'engine': 'XenForo', 'urlMain': 'https://forum.example.com',
                            'absenceStrs': ['Usuario no encontrado', 'The requested page could not be found.'],
                            'presenseStrs': ['perfil']})
        assert item['not_found'] == ['Usuario no encontrado', 'The requested page could not be found.',
                                     'The specified member cannot be found']
        assert item['must_contain'] == ['perfil', 'memberHeader']

    def test_site_without_engine_is_unaffected(self):
        item = self._parse({'url': 'https://x.example.com/{username}', 'absenceStrs': ['nope']})
        assert (item['not_found'], item['must_contain']) == (['nope'], [])


class TestUnusableUrlTemplates:
    """回归:写出过 `{}.com`(Maigret 的 DNS 查询条目)和 `{urlMain}forum/...`(占位符没展开)
    这样的地址,运行时永远请求失败。"""

    @pytest.mark.parametrize('protocol', ['dns', 'tor', 'i2p'])
    def test_non_http_protocols_are_skipped(self, protocol):
        raw = {'sites': {'X': {'protocol': protocol, 'url': 'http://example.onion/u/{username}'}}}
        assert bp.parse_maigret(raw) == []

    def test_url_main_placeholder_expanded_for_plain_sites(self):
        raw = {'sites': {'Rutracker': {
            'urlMain': 'https://rutracker.org/',
            'url': '{urlMain}forum/profile.php?mode=viewprofile&u={username}'}}}
        assert bp.parse_maigret(raw)[0]['url'] == 'https://rutracker.org/forum/profile.php?mode=viewprofile&u={}'

    def test_template_without_scheme_is_dropped(self):
        assert bp.parse_maigret({'sites': {'{username}.com': {'url': '{username}.com'}}}) == []

    @pytest.mark.parametrize('url, ok', [
        ('https://x.com/{}', True),
        ('http://x.com/u?name={}', True),
        ('{}.com', False),
        ('https://x.com/profile', False),
        ('{urlMain}forum/{}', False),
        ('https://x.com/{}/{urlSubpath}', False),
        ('ftp://x.com/{}', False),
    ])
    def test_is_probeable_url(self, url, ok):
        assert bp.is_probeable_url(url) is ok


class TestBareCoIsNotSpanish:
    """回归:`.co` 被当成西语圈域名,HuggingFace、VSCO 等 27 个平台被归进「西语圈」。"""

    def test_bare_co_domains(self):
        assert bp.categorize('SomeSite', 'https://somesite.co/{}') != 'spanish'
        assert bp.get_tld('https://somesite.co/{}') not in bp.TLD_CATEGORY

    def test_com_co_is_still_spanish(self):
        assert bp.categorize('Tienda', 'https://tienda.com.co/{}') == 'spanish'


class TestBuildSanityChecks:
    """回归:上游改了数据格式时,解析结果会骤减甚至为空 —— 以前会照样写出一份残缺的 platforms.json。"""

    def _sites(self, n, prefix):
        return {f'{prefix}{i}': {'url': f'https://{prefix}{i}.example.com/{{username}}'} for i in range(n)}

    def _run(self, monkeypatch, tmp_path, raw, mins=None, total=None):
        out = tmp_path / 'platforms.json'
        out.write_text('"existing"')
        monkeypatch.setattr(bp, 'OUT_PATH', str(out))
        monkeypatch.setattr(bp, 'fetch_all', lambda **kw: raw)
        if mins is not None:
            monkeypatch.setattr(bp, 'MIN_PLATFORMS_PER_SOURCE', mins)
        if total is not None:
            monkeypatch.setattr(bp, 'MIN_PLATFORMS_TOTAL', total)
        return out

    def test_collapsed_source_aborts_and_keeps_existing_file(self, monkeypatch, tmp_path):
        raw = {'maigret': {'sites': self._sites(5, 'm')}, 'sherlock': {}, 'whatsmyname': {'sites': []}}
        out = self._run(monkeypatch, tmp_path, raw)
        with pytest.raises(RuntimeError, match='maigret'):
            bp.build()
        assert out.read_text() == '"existing"'
        assert bp.main([]) == 1

    def test_healthy_build_writes_file_without_unusable_urls(self, monkeypatch, tmp_path):
        sherlock = {f's{i}': {'url': f'https://s{i}.example.com/{{}}'} for i in range(3)}
        sherlock['Broken'] = {'url': '{urlMain}x/{}'}
        raw = {'maigret': {'sites': self._sites(4, 'm')}, 'sherlock': sherlock,
               'whatsmyname': {'sites': [{'name': 'W', 'uri_check': 'https://w.example.com/{account}'}]}}
        out = self._run(monkeypatch, tmp_path, raw,
                        mins={'maigret': 1, 'sherlock': 1, 'whatsmyname': 1}, total=5)
        assert bp.build() == 8
        import json
        names = {item['name'] for item in json.loads(out.read_text())}
        assert 'Broken' not in names and len(names) == 8

    def test_too_few_after_merge_aborts(self, monkeypatch, tmp_path):
        raw = {'maigret': {'sites': self._sites(2, 'm')}, 'sherlock': {'s': {'url': 'https://s.example.com/{}'}},
               'whatsmyname': {'sites': [{'name': 'W', 'uri_check': 'https://w.example.com/{account}'}]}}
        out = self._run(monkeypatch, tmp_path, raw,
                        mins={'maigret': 1, 'sherlock': 1, 'whatsmyname': 1}, total=50)
        with pytest.raises(RuntimeError):
            bp.build()
        assert out.read_text() == '"existing"'


class TestDedupByUrl:
    """回归:上游三个库给同一个网址起不同的名字,按名字去重拦不住。"""

    def _item(self, name, url, nf=0, mc=0, category='other'):
        return {'name': name, 'url': url, 'not_found': ['x'] * nf, 'must_contain': ['y'] * mc, 'category': category}

    def test_entry_with_more_rules_wins(self):
        items = [self._item('Calendy', 'https://calendly.com/{}', nf=1),
                 self._item('Calendly', 'https://www.calendly.com/{}/', nf=1, mc=2)]
        assert [i['name'] for i in bp.dedup_by_url(items)] == ['Calendly']

    def test_tie_goes_to_the_one_with_a_real_category(self):
        items = [self._item('Giphy (Channel)', 'https://giphy.com/channel/{}', nf=1),
                 self._item('Giphy', 'https://giphy.com/channel/{}', nf=1, category='video')]
        assert [i['name'] for i in bp.dedup_by_url(items)] == ['Giphy']

    def test_full_tie_keeps_the_first_and_order_is_preserved(self):
        items = [self._item('B', 'https://b.com/{}'), self._item('A1', 'https://a.com/{}'),
                 self._item('A2', 'http://a.com/{}'), self._item('C', 'https://c.com/{}')]
        assert [i['name'] for i in bp.dedup_by_url(items)] == ['B', 'A1', 'C']

    def test_different_paths_are_not_merged(self):
        items = [self._item('Steam', 'https://steamcommunity.com/id/{}'),
                 self._item('Steam (Group)', 'https://steamcommunity.com/groups/{}')]
        assert len(bp.dedup_by_url(items)) == 2

    @pytest.mark.parametrize('url', ['https://Example.com/U/{}', 'http://www.example.com/u/{}/',
                                     'https://{}.example.com', 'https://example.com/a?b={}'])
    def test_url_key_matches_the_runtime_one(self, url):
        import spyeyes
        assert bp.url_key(url) == spyeyes._platform_url_key(url)

    @pytest.mark.parametrize('url', ['http://abcdefghijklmnop.onion/u/{}', 'http://forum.i2p/search.php?author={}'])
    def test_darknet_addresses_are_not_probeable(self, url):
        assert bp.is_probeable_url(url) is False
