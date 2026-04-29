"""GhostTrack 单元测试。

运行：
    pytest -q
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# 让 tests/ 能 import 上层 GhostTR
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import GhostTR as gt  # noqa: E402


# ------------------------------------------------------------------
# 纯函数：display_width
# ------------------------------------------------------------------
class TestDisplayWidth:
    def test_ascii(self):
        assert gt.display_width('hello') == 5

    def test_chinese(self):
        assert gt.display_width('中文') == 4

    def test_mixed(self):
        assert gt.display_width('IP 地址') == 2 + 1 + 4

    def test_empty(self):
        assert gt.display_width('') == 0

    def test_full_width_punctuation(self):
        assert gt.display_width('！？') == 4


# ------------------------------------------------------------------
# 纯函数：country_zh
# ------------------------------------------------------------------
class TestCountryZh:
    def test_known(self):
        assert gt.country_zh('US') == '美国'
        assert gt.country_zh('CN') == '中国'
        assert gt.country_zh('JP') == '日本'

    def test_lowercase_input(self):
        assert gt.country_zh('us') == '美国'

    def test_unknown(self):
        assert gt.country_zh('XX', 'fallback') == 'fallback'

    def test_none(self):
        assert gt.country_zh(None, 'unk') == 'unk'

    def test_empty(self):
        assert gt.country_zh('', 'fb') == 'fb'


# ------------------------------------------------------------------
# 纯函数：EMAIL_RE
# ------------------------------------------------------------------
class TestEmailRegex:
    @pytest.mark.parametrize('email', [
        'a@b.com', 'foo.bar@example.co.uk', 'user+tag@gmail.com',
        'a_b-c.d@sub.domain.org',
    ])
    def test_valid(self, email):
        assert gt.EMAIL_RE.match(email) is not None

    @pytest.mark.parametrize('email', [
        'no-at-sign', '@nouser.com', 'spaces in@email.com',
        'no-domain@', 'a@b', '中文@example.com',
    ])
    def test_invalid(self, email):
        assert gt.EMAIL_RE.match(email) is None


# ------------------------------------------------------------------
# track_phone：纯本地解析，无需 mock
# ------------------------------------------------------------------
class TestTrackPhone:
    def test_cn_number_with_plus(self):
        data = gt.track_phone('+8613800138000')
        assert '_error' not in data
        assert data['country_code'] == 86
        assert data['region_code'] == 'CN'
        assert data['is_valid'] is True
        assert data['number_type'] in ('移动电话', '固定/移动电话')

    def test_cn_number_without_prefix(self):
        data = gt.track_phone('13800138000', default_region='CN')
        assert data['country_code'] == 86
        assert data['e164'] == '+8613800138000'

    def test_us_number(self):
        data = gt.track_phone('+12025550100')
        assert '_error' not in data
        assert data['country_code'] == 1
        assert data['region_code'] == 'US'

    def test_invalid_input(self):
        data = gt.track_phone('not-a-number')
        assert '_error' in data

    def test_empty_input(self):
        data = gt.track_phone('')
        assert '_error' in data


# ------------------------------------------------------------------
# track_ip：mock requests
# ------------------------------------------------------------------
class TestTrackIp:
    def test_success(self):
        fake_response = MagicMock()
        fake_response.json.return_value = {
            'success': True, 'type': 'IPv4', 'country': 'United States',
            'country_code': 'US', 'city': 'Mountain View',
        }
        with patch.object(gt, 'safe_get', return_value=fake_response):
            data = gt.track_ip('8.8.8.8')
        assert '_error' not in data
        assert data['country_code'] == 'US'

    def test_network_failure(self):
        with patch.object(gt, 'safe_get', return_value=None):
            data = gt.track_ip('8.8.8.8')
        assert '_error' in data

    def test_api_error(self):
        fake_response = MagicMock()
        fake_response.json.return_value = {'success': False, 'message': '无效 IP'}
        with patch.object(gt, 'safe_get', return_value=fake_response):
            data = gt.track_ip('garbage')
        assert data['_error'] == '无效 IP'

    def test_non_json_response(self):
        fake_response = MagicMock()
        fake_response.json.side_effect = ValueError('not JSON')
        with patch.object(gt, 'safe_get', return_value=fake_response):
            data = gt.track_ip('8.8.8.8')
        assert '_error' in data

    def test_empty_ip_returns_error_without_api_call(self):
        """空 IP 输入会让 ipwho.is 返回调用方 IP，必须早返回错误。"""
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('')
            assert mock_get.call_count == 0
        assert '_error' in data

    def test_whitespace_ip_returns_error(self):
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('   ')
            assert mock_get.call_count == 0
        assert '_error' in data


# ------------------------------------------------------------------
# show_my_ip
# ------------------------------------------------------------------
class TestShowMyIp:
    def test_success(self):
        fake = MagicMock(status_code=200, text='1.2.3.4\n')
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt.show_my_ip() == '1.2.3.4'

    def test_failure(self):
        with patch.object(gt, 'safe_get', return_value=None):
            assert gt.show_my_ip() is None


# ------------------------------------------------------------------
# username 检查（单平台）
# ------------------------------------------------------------------
class TestCheckUsername:
    def _make_platform(self, not_found=()):
        return gt.Platform('GitHub', 'https://github.com/{}', 'code', not_found)

    def test_found(self):
        fake = MagicMock(status_code=200, content=b'<html>real profile</html>')
        with patch.object(gt, 'safe_get', return_value=fake):
            p, url = gt._check_username(self._make_platform(), 'user', 5)
        assert p.name == 'GitHub'
        assert url == 'https://github.com/user'

    def test_404(self):
        fake = MagicMock(status_code=404)
        with patch.object(gt, 'safe_get', return_value=fake):
            p, url = gt._check_username(self._make_platform(), 'x', 5)
        assert url is None

    def test_content_pattern_says_not_found(self):
        # 新版 _check_username 用 stream=True + resp.raw.read()
        fake = MagicMock(status_code=200)
        fake.raw.read.return_value = b'<title>Page not found</title>'
        with patch.object(gt, 'safe_get', return_value=fake):
            p, url = gt._check_username(self._make_platform((b'page not found',)), 'x', 5)
        assert url is None

    def test_network_error(self):
        with patch.object(gt, 'safe_get', return_value=None):
            p, url = gt._check_username(self._make_platform(), 'u', 5)
        assert url is None

    def test_empty_username_no_network_call(self):
        """空 username 早返回 _error，不应触发任何 HTTP 请求。"""
        with patch.object(gt, 'safe_get') as mock_get:
            results = gt.track_username('')
            assert mock_get.call_count == 0
        assert '_error' in results

    def test_whitespace_username_no_network_call(self):
        with patch.object(gt, 'safe_get') as mock_get:
            results = gt.track_username('   ')
            assert mock_get.call_count == 0
        assert '_error' in results

    def test_check_username_handles_format_value_error(self):
        """str.format 的格式串错误（'{:d}' 等）必须被吞掉，不能崩溃。"""
        bad_platform = gt.Platform('BadFmt', 'https://x.com/{:d}', 'code')
        # 不需要 mock safe_get — 应在 .format() 处早返回
        p, url = gt._check_username(bad_platform, 'alice', 5)
        assert url is None
        assert p.name == 'BadFmt'

    def test_track_username_survives_worker_exception(self):
        """单个 worker 抛任何异常不应让整个扫描崩溃。"""
        # 让 safe_get 总是抛 RuntimeError，模拟 worker 灾难
        with patch.object(gt, 'safe_get', side_effect=RuntimeError('simulated')):
            results = gt.track_username('alice', max_workers=5)
        # 必须返回正常的 dict，所有平台都是 None（因为全部失败）
        assert isinstance(results, dict)
        assert len(results) == len(gt.PLATFORMS)
        assert all(v is None for v in results.values())

    def test_track_username_clamps_zero_workers(self):
        """传入 max_workers=0 不应崩溃。"""
        # 不实际跑（避免真的 query 网络），只验证不抛异常
        with patch.object(gt, 'safe_get', return_value=None):
            results = gt.track_username('x', max_workers=0)
        assert isinstance(results, dict)

    def test_empty_username_returns_error_dict(self):
        """audit P1#5: 空 username 返回 {'_error': ...}（与 track_ip 一致）。"""
        results = gt.track_username('')
        assert isinstance(results, dict)
        assert '_error' in results

    def test_unknown_category_returns_error(self):
        """audit P1#6: 未知 category 不应静默返回 0 结果，而是 _error。"""
        results = gt.track_username('alice', categories=['nonexistent_xyz'])
        assert '_error' in results
        # error message 应包含未知类别名 + 提示有效类别
        assert 'nonexistent_xyz' in results['_error']

    def test_known_categories_pass_validation(self):
        """有效 categories 不触发错误。"""
        with patch.object(gt, 'safe_get', return_value=None):
            results = gt.track_username('x', categories=['code'])
        assert '_error' not in results
        # 应只扫 code 类别的平台
        code_count = sum(1 for p in gt.PLATFORMS if p.category == 'code')
        assert len(results) == code_count


class TestPlatformDedup:
    """audit P1#1: PLATFORMS 列表内不应有名字重复（即使大小写不同）。"""

    def test_no_duplicate_names_case_insensitive(self):
        names = [p.name.lower().strip() for p in gt.PLATFORMS]
        dups = [n for n in set(names) if names.count(n) > 1]
        assert not dups, f"Duplicate platform names: {dups}"

    def test_dedup_helper_works(self):
        plats = [
            gt.Platform('Foo', 'https://a/{}', 'code'),
            gt.Platform('FOO', 'https://b/{}', 'code'),  # 同名不同 URL
            gt.Platform('Bar', 'https://c/{}', 'code'),
        ]
        result = gt._dedup_platforms(plats)
        assert len(result) == 2
        assert result[0].url == 'https://a/{}'  # 保留先出现的


class TestPatternCleaning:
    """audit P1#4: 空 pattern (b'') 在 'in' 测试中永远 True，必须被过滤。"""

    def test_clean_filters_empty_strings(self):
        assert gt._clean_patterns(['valid', '', '  ', 'also valid']) == (
            b'valid', b'also valid')

    def test_clean_filters_empty_bytes(self):
        assert gt._clean_patterns([b'valid', b'', b'  ', b'also']) == (
            b'valid', b'also')

    def test_clean_handles_none(self):
        assert gt._clean_patterns(None) == ()

    def test_clean_handles_empty_list(self):
        assert gt._clean_patterns([]) == ()

    def test_empty_pattern_does_not_falsely_match(self):
        """实际行为测试：含空 pattern 的 Platform 不应误报命中。"""
        # 用 _clean_patterns 处理，空字符串应被滤掉
        cleaned = gt._clean_patterns(['', 'real pattern'])
        assert b'' not in cleaned


class TestMarkdownSafety:
    """audit P1#2: markdown 注入防护。"""

    def test_pipe_in_query_does_not_break_table(self):
        md = gt._to_markdown('ip_8.8.8.8|injected', {'country': 'US'})
        # query 应被转义
        assert '8.8.8.8\\|injected' in md

    def test_newline_in_query_does_not_inject_heading(self):
        md = gt._to_markdown('ip_evil\n## PWNED', {'country': 'US'})
        # 换行符必须被替换为空格，不能让任何行以 '## PWNED' 开头
        for line in md.split('\n'):
            assert not line.startswith('## PWNED'), f"Heading injection: {line}"

    def test_pipe_in_dict_key_escaped(self):
        md = gt._to_markdown('whois_x', {'reg|istrar': 'someone'})
        for line in md.split('\n'):
            if 'reg' in line and 'someone' in line:
                # 计算未转义的 | 数量（前面没有 \）
                import re
                unescaped = len(re.findall(r'(?<!\\)\|', line))
                assert unescaped == 3, f"Got {unescaped} unescaped | in: {line}"

    def test_md_escape_handles_none(self):
        assert gt._md_escape(None) == ''


class TestRecordHistoryDataNone:
    """audit P1#3: _record_history 在 data=None 时不应崩溃。"""

    def test_ip_data_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        import argparse
        gt._record_history('ip', argparse.Namespace(target='1.2.3.4'), None)

    def test_myip_data_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        import argparse
        gt._record_history('myip', argparse.Namespace(), None)

    def test_email_data_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        import argparse
        gt._record_history('email', argparse.Namespace(address='a@b.com'), None)


class TestSession:
    """Sherlock-inspired: thread-local Session reuse."""

    def test_session_returns_session(self):
        s = gt._get_session()
        import requests
        assert isinstance(s, requests.Session)

    def test_session_reused_within_same_thread(self):
        s1 = gt._get_session()
        s2 = gt._get_session()
        assert s1 is s2  # 同线程必须复用

    def test_session_has_default_headers(self):
        s = gt._get_session()
        assert 'User-Agent' in s.headers
        assert 'Mozilla' in s.headers['User-Agent']

    def test_platforms_count_meets_target(self):
        """对标 Maigret + Sherlock + WhatsMyName 合并，至少 2000 个平台。"""
        assert len(gt.PLATFORMS) >= 2000, f"got {len(gt.PLATFORMS)}"

    def test_chinese_region_coverage(self):
        chinese = [p for p in gt.PLATFORMS if p.category == 'chinese']
        assert len(chinese) >= 30, f"got {len(chinese)}"

    def test_spanish_region_coverage(self):
        spanish = [p for p in gt.PLATFORMS if p.category == 'spanish']
        assert len(spanish) >= 30, f"got {len(spanish)}"

    def test_all_categories_covered(self):
        cats = {p.category for p in gt.PLATFORMS}
        assert cats.issubset(set(gt.CATEGORY_ORDER))
        for cat in cats:
            assert cat in gt.CATEGORY_ORDER


# ------------------------------------------------------------------
# email_validate
# ------------------------------------------------------------------
class TestEmailValidate:
    def test_invalid_format(self):
        result = gt.email_validate('not-an-email')
        assert result['syntax_valid'] is False
        assert '_error' in result

    def test_valid_format_with_mock_mx(self):
        with patch.object(gt, 'mx_lookup', return_value={
            'domain': 'gmail.com',
            'records': [{'preference': 5, 'exchange': 'gmail-smtp.l.google.com'}],
        }):
            result = gt.email_validate('user@gmail.com')
        assert result['syntax_valid'] is True
        assert result['mx_valid'] is True
        assert len(result['mx_records']) == 1

    def test_valid_format_no_mx(self):
        with patch.object(gt, 'mx_lookup', return_value={'_error': '没有 MX'}):
            result = gt.email_validate('user@nowhere.invalid')
        assert result['syntax_valid'] is True
        assert result['mx_valid'] is False
        assert 'mx_error' in result


# ------------------------------------------------------------------
# Color disable
# ------------------------------------------------------------------
class TestColor:
    def test_disable_blanks_all(self):
        original = gt.Color.Re
        try:
            gt.Color.disable()
            assert gt.Color.Re == ''
            assert gt.Color.Wh == ''
        finally:
            # 恢复（避免影响其它测试）
            gt.Color.Re = original


# ------------------------------------------------------------------
# CLI parser smoke tests
# ------------------------------------------------------------------
class TestCliParser:
    def test_no_args(self):
        parser = gt.build_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_ip_subcommand(self):
        args = gt.build_parser().parse_args(['ip', '8.8.8.8'])
        assert args.command == 'ip'
        assert args.target == '8.8.8.8'

    def test_phone_with_region(self):
        args = gt.build_parser().parse_args(['phone', '13800138000', '--region', 'US'])
        assert args.region == 'US'

    def test_json_flag_before_subcommand(self):
        args = gt.build_parser().parse_args(['--json', 'myip'])
        assert getattr(args, 'json', False) is True

    def test_json_flag_after_subcommand(self):
        args = gt.build_parser().parse_args(['myip', '--json'])
        assert getattr(args, 'json', False) is True

    def test_json_flag_absent(self):
        args = gt.build_parser().parse_args(['myip'])
        assert getattr(args, 'json', False) is False

    def test_workers_rejects_zero(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['user', 'alice', '--workers', '0'])

    def test_workers_rejects_negative(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['user', 'alice', '--workers', '-5'])

    def test_workers_rejects_too_large(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['user', 'alice', '--workers', '500'])

    def test_workers_rejects_non_integer(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['user', 'alice', '--workers', 'abc'])

    def test_workers_accepts_valid(self):
        args = gt.build_parser().parse_args(['user', 'alice', '--workers', '50'])
        assert args.workers == 50


# ------------------------------------------------------------------
# _maybe_save 真写文件
# ------------------------------------------------------------------
class TestMaybeSave:
    def test_writes_json(self, tmp_path):
        gt._maybe_save(str(tmp_path), 'ip_8.8.8.8', {'a': 1, 'b': '中'})
        files = list(tmp_path.glob('*.json'))
        assert len(files) == 1
        loaded = json.loads(files[0].read_text(encoding='utf-8'))
        assert loaded == {'a': 1, 'b': '中'}

    def test_skip_when_no_dir(self, tmp_path):
        # save_dir=None 时不应该创建任何东西
        gt._maybe_save(None, 'foo', {'x': 1})
        assert list(tmp_path.iterdir()) == []
