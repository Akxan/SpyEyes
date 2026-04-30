"""SpyEyes 单元测试。

运行：
    pytest -q
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# 让 tests/ 能 import 上层 spyeyes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402


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
        """合法 IP 但 API 返回错误（用 reserved/loopback 模拟）。"""
        fake_response = MagicMock()
        fake_response.json.return_value = {'success': False, 'message': '无效 IP'}
        with patch.object(gt, 'safe_get', return_value=fake_response):
            data = gt.track_ip('127.0.0.1')
        assert data['_error'] == '无效 IP'

    def test_invalid_ip_rejected_without_api_call(self):
        """SSRF 防护：非合法 IP 在送进 URL 前被 ipaddress 校验拦截。"""
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('garbage')
        assert mock_get.call_count == 0
        assert '_error' in data
        assert 'garbage' in data['_error']

    def test_path_traversal_in_ip_rejected(self):
        """SSRF：'../admin' 等路径穿越尝试必须被拒绝。"""
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('../admin')
        assert mock_get.call_count == 0
        assert '_error' in data

    def test_query_string_in_ip_rejected(self):
        """SSRF：尝试附加 query string 污染必须被拒绝。"""
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('8.8.8.8?key=leak')
        assert mock_get.call_count == 0
        assert '_error' in data

    def test_ipv6_accepted(self):
        """合法 IPv6 必须通过校验。"""
        fake = MagicMock()
        fake.json.return_value = {'success': True, 'type': 'IPv6', 'country_code': 'US'}
        with patch.object(gt, 'safe_get', return_value=fake):
            data = gt.track_ip('2001:4860:4860::8888')
        assert '_error' not in data

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
            p, url, _ = gt._check_username(self._make_platform(), 'user', 5)
        assert p.name == 'GitHub'
        assert url == 'https://github.com/user'

    def test_404(self):
        fake = MagicMock(status_code=404)
        with patch.object(gt, 'safe_get', return_value=fake):
            p, url, _ = gt._check_username(self._make_platform(), 'x', 5)
        assert url is None

    def test_content_pattern_says_not_found(self):
        # 新版 _check_username 用 stream=True + resp.raw.read()
        fake = MagicMock(status_code=200)
        fake.raw.read.return_value = b'<title>Page not found</title>'
        with patch.object(gt, 'safe_get', return_value=fake):
            p, url, _ = gt._check_username(self._make_platform((b'page not found',)), 'x', 5)
        assert url is None

    def test_network_error(self):
        with patch.object(gt, 'safe_get', return_value=None):
            p, url, _ = gt._check_username(self._make_platform(), 'u', 5)
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
        p, url, _ = gt._check_username(bad_platform, 'alice', 5)
        assert url is None
        assert p.name == 'BadFmt'

    def test_track_username_survives_worker_exception(self):
        """单个 worker 抛任何异常不应让整个扫描崩溃。"""
        # 让 safe_get 总是抛 RuntimeError，模拟 worker 灾难
        with patch.object(gt, 'safe_get', side_effect=RuntimeError('simulated')):
            results = gt.track_username('alice', max_workers=5)
        # 必须返回正常的 dict，所有平台都是 None（因为全部失败）
        assert isinstance(results, dict)
        plat = gt._platform_only(results)
        assert len(plat) == len(gt.PLATFORMS)
        assert all(v is None for v in plat.values())

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
        # 应只扫 code 类别的平台（filter out _statuses 等私有 key）
        code_count = sum(1 for p in gt.PLATFORMS if p.category == 'code')
        plat = gt._platform_only(results)
        assert len(plat) == code_count


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
    """_record_history 在 data=None 时不应崩溃，且必须正确写入摘要内容。"""

    def _read_record(self, path):
        with open(path, encoding='utf-8') as f:
            line = f.readline().strip()
        return json.loads(line)

    def test_ip_data_none_records_failure(self, tmp_path, monkeypatch):
        """data=None → ok=False（之前 '_error' not in {} 误返回 True 等同成功）"""
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('ip', argparse.Namespace(target='1.2.3.4'), None)
        rec = self._read_record(history_file)
        assert rec['cmd'] == 'ip'
        assert rec['query'] == '1.2.3.4'
        assert rec['ok'] is False, "data=None 必须记为失败"

    def test_ip_data_with_error_records_failure(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('ip', argparse.Namespace(target='1.2.3.4'),
                            {'_error': 'network'})
        rec = self._read_record(history_file)
        assert rec['ok'] is False

    def test_ip_data_success_records_ok(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('ip', argparse.Namespace(target='8.8.8.8'),
                            {'country': 'US'})
        rec = self._read_record(history_file)
        assert rec['ok'] is True

    def test_myip_data_none(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('myip', argparse.Namespace(), None)
        rec = self._read_record(history_file)
        assert rec['cmd'] == 'myip'
        assert rec['ok'] is False

    def test_email_data_none(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('email', argparse.Namespace(address='a@b.com'), None)
        rec = self._read_record(history_file)
        assert rec['cmd'] == 'email'
        assert rec['query'] == 'a@b.com'

    def test_user_records_found_count(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        gt._record_history('user', argparse.Namespace(username='alice'),
                            {'GitHub': 'https://github.com/alice', 'Twitter': None})
        rec = self._read_record(history_file)
        assert rec['cmd'] == 'user'
        assert rec['query'] == 'alice'
        assert rec['found'] == 1
        assert rec['scanned'] == 2


class TestSession:
    """Sherlock-inspired: thread-local Session reuse + 跨线程隔离。"""

    def test_session_returns_session(self):
        s = gt._get_session()
        import requests
        assert isinstance(s, requests.Session)

    def test_session_reused_within_same_thread(self):
        s1 = gt._get_session()
        s2 = gt._get_session()
        assert s1 is s2  # 同线程必须复用

    def test_session_isolated_across_threads(self):
        """跨线程必须拿到不同 Session（thread-local 语义）。
        反向断言：如果 _thread_local 被改成全局变量，本测试会失败。"""
        import threading
        sessions = []

        def grab():
            sessions.append(gt._get_session())

        main_session = gt._get_session()
        t = threading.Thread(target=grab)
        t.start()
        t.join()
        assert sessions[0] is not main_session, "跨线程 Session 必须独立"

    def test_session_has_default_headers(self):
        s = gt._get_session()
        assert 'User-Agent' in s.headers
        assert 'Mozilla' in s.headers['User-Agent']


class TestRegexCheck:
    """Sherlock-inspired: regex pre-filter 跳过不可能的平台。"""

    def test_regex_mismatch_skips_network(self):
        """username 不匹配 regex → 不发请求，返回 invalid 状态。"""
        p = gt.Platform('Strict', 'https://x.com/{}', 'code',
                         regex_check=r'^[a-z]{1,5}$')  # 只允许 1-5 个小写字母
        with patch.object(gt, 'safe_get') as mock_get:
            plat, url, status = gt._check_username(p, 'TOO_LONG_USERNAME', 5)
        assert mock_get.call_count == 0  # 完全跳过网络
        assert url is None
        assert status == gt.STATUS_INVALID_USERNAME

    def test_regex_match_proceeds(self):
        """username 匹配 regex → 正常发请求。"""
        p = gt.Platform('Strict', 'https://x.com/{}', 'code',
                         regex_check=r'^[a-z]+$')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            plat, url, status = gt._check_username(p, 'alice', 5)
        assert status == gt.STATUS_FOUND

    def test_malformed_regex_does_not_crash(self):
        """坏的 regex 模式应被忽略，正常发请求。"""
        p = gt.Platform('Bad', 'https://x.com/{}', 'code',
                         regex_check=r'[invalid(regex')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            plat, url, status = gt._check_username(p, 'anyone', 5)
        # 应不崩，照常出结果
        assert status == gt.STATUS_FOUND

    def test_fullmatch_rejects_substring_injection(self):
        """audit P1#4: re.fullmatch 拒绝 username 含合法子串但带垃圾的注入。"""
        # Dealabs 风格未锚定的 regex：原本 re.search 会匹配子串
        p = gt.Platform('Loose', 'https://x.com/{}', 'code', regex_check=r'[a-z]{4,16}')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            plat, url, status = gt._check_username(p, 'AB; DROP TABLE; abc', 5)
        # re.search 会过（找到 "abc" 等子串），re.fullmatch 必须拒绝（含大写+空格+符号）
        assert status == gt.STATUS_INVALID_USERNAME

    def test_redos_heuristic_intentionally_removed(self):
        """_REDOS_RE 启发式（嵌套量词检测）已删除 —— 误报严重（合法 regex
        如 [a-z]+(-[a-z]+)* 也命中）。改用 MAX_USERNAME_LENGTH 限制输入长度
        作为 ReDoS 实际防护。"""
        assert not hasattr(gt, '_REDOS_RE')
        assert hasattr(gt, 'MAX_USERNAME_LENGTH')
        assert gt.MAX_USERNAME_LENGTH > 0

    def test_username_length_limit_blocks_redos(self):
        """超长 username 被拒，避免 (a+)+ 类 regex 触发指数回溯。"""
        long_name = 'a' * (gt.MAX_USERNAME_LENGTH + 1)
        result = gt.track_username(long_name, max_workers=1, show_progress=False)
        assert '_error' in result
        assert 'too long' in result['_error'].lower() or '过长' in result['_error']

    def test_username_at_length_limit_accepted(self, monkeypatch):
        """正好 MAX_USERNAME_LENGTH 长度应通过（边界 OK）。
        注意：PLATFORMS 通过 PEP 562 __getattr__ 懒加载，patch.object(gt, 'PLATFORMS', ...)
        无效；要 patch _PLATFORMS_CACHE 才能真正绕过 lazy load。"""
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [
            gt.Platform('T', 'https://x.com/{}', 'code')
        ])
        with patch.object(gt, 'safe_get', return_value=None):
            result = gt.track_username('a' * gt.MAX_USERNAME_LENGTH,
                                        max_workers=1, show_progress=False)
        assert '_error' not in result

    def test_redos_short_input_completes_fast(self):
        """ReDoS 防护策略说明：
        - track_username 入口拦截 > MAX_USERNAME_LENGTH 的输入（已测）
        - _check_username 接收的 username 必经长度限制，所以恶意 (a+)+$ 类 regex
          在 ≤64 字符输入上 worst case 仍可能数十毫秒，但不会卡死线程池

        本测试用一个能触发回溯但很短（22 字符）的输入验证 re 在合理时间内返回。
        不用更长输入是因为 Python re 模块在 (a+)+$ 上仍会指数爆炸 —— 真正的
        长输入防护是 MAX_USERNAME_LENGTH 而非 _check_username 内部超时。"""
        import time
        p = gt.Platform('Evil', 'https://x.com/{}', 'code', regex_check=r'(a+)+$')
        fake = MagicMock(status_code=200)
        evil_input = 'a' * 22 + 'b'  # 2^22 ≈ 4M，秒级以内
        with patch.object(gt, 'safe_get', return_value=fake):
            t0 = time.time()
            gt._check_username(p, evil_input, 5)
            dt = time.time() - t0
        assert dt < 5.0, f"ReDoS 短输入超时：{dt*1000:.0f}ms"

    def test_no_regex_means_no_filter(self):
        """regex_check 为空字符串时不做过滤。"""
        p = gt.Platform('NoRegex', 'https://x.com/{}', 'code', regex_check='')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            plat, url, status = gt._check_username(p, 'whatever_user_name', 5)
        assert status == gt.STATUS_FOUND


class TestWAFDetection:
    """Sherlock-inspired: WAF 拦截识别。"""

    def test_cloudflare_block_detected(self):
        body = b'<html><title>just a moment...</title>cdn-cgi/challenge-platform</html>'
        assert gt._detect_waf(body) is True

    def test_aws_waf_detected(self):
        body = b'<html>aws-waf-token: xxx</html>'
        assert gt._detect_waf(body) is True

    def test_perimeterx_detected(self):
        # 用真实 PerimeterX/HUMAN 的特定标志（cookie 名 / URL 路径）
        body = b'<html>document.cookie = "_px3=abc";</html>'
        assert gt._detect_waf(body) is True

    def test_perimeterx_brand_alone_no_false_positive(self):
        """正常内容提到 perimeterx 一词不应误报。"""
        body = b'<html>I read a security blog about perimeterx today</html>'
        assert gt._detect_waf(body) is False

    def test_normal_content_with_access_denied_no_false_positive(self):
        """audit fix: 正常论坛贴含 'access denied' 字面量不应误报。"""
        body = b'<html>Forum thread: how to fix access denied error in Linux</html>'
        assert gt._detect_waf(body) is False

    def test_cloudflare_brand_alone_no_false_positive(self):
        """提到 cloudflare 一词的正常文章不应误报。"""
        body = b'<html>Hosted on Cloudflare since 2020.</html>'
        assert gt._detect_waf(body) is False

    def test_normal_content_not_flagged(self):
        body = b'<html><title>Real Profile</title>Welcome user!</html>'
        assert gt._detect_waf(body) is False

    def test_only_first_8kb_checked(self):
        # WAF 标志藏在 9000 字节后 → 不应被检测
        body = b'X' * 9000 + b'cdn-cgi/challenge-platform'
        assert gt._detect_waf(body) is False

    def test_waf_in_check_username_returns_waf_status(self):
        p = gt.Platform('Test', 'https://x.com/{}', 'code',
                         not_found=(b'no such user',))
        fake = MagicMock(status_code=200)
        # 用真实 Cloudflare challenge 标志
        fake.raw.read.return_value = b'<title>just a moment...</title>cdn-cgi/challenge-platform/h/g'
        with patch.object(gt, 'safe_get', return_value=fake):
            plat, url, status = gt._check_username(p, 'alice', 5)
        assert status == gt.STATUS_WAF
        assert url is None  # WAF 拦截 = 不报「找到」

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
    """Color.disable 必须清空所有颜色属性，conftest 的 autouse fixture 负责恢复。"""

    def test_disable_blanks_all(self):
        gt.Color.disable()
        assert gt.Color.Re == ''
        assert gt.Color.Wh == ''
        assert gt.Color.Gr == ''
        assert gt.Color.Bl == ''
        assert gt.Color.Reset == ''
        assert gt.Color.enabled is False


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

    def test_writes_md_file(self, tmp_path):
        out = tmp_path / 'r.md'
        gt._maybe_save(str(out), 'ip_8.8.8.8', {'country': 'US', 'city': 'MV'})
        assert out.exists()
        content = out.read_text(encoding='utf-8')
        assert content.startswith('# ')
        assert '8.8.8.8' in content
        assert 'US' in content

    def test_writes_single_json_file(self, tmp_path):
        out = tmp_path / 'r.json'
        gt._maybe_save(str(out), 'ip_x', {'a': 1, 'b': '中'})
        loaded = json.loads(out.read_text(encoding='utf-8'))
        assert loaded == {'a': 1, 'b': '中'}

    def test_no_extension_treated_as_json_file(self, tmp_path):
        """关键 bug 回归：--save somefile（无后缀）必须当文件而非目录。
        之前会 os.makedirs 把文件名建成空目录。"""
        out = tmp_path / 'somefile'
        gt._maybe_save(str(out), 'ip_x', {'k': 'v'})
        assert out.is_file(), "无后缀路径必须创建为文件而非目录"
        loaded = json.loads(out.read_text(encoding='utf-8'))
        assert loaded == {'k': 'v'}

    def test_explicit_dir_with_trailing_slash(self, tmp_path):
        """显式以 / 结尾才创建目录。"""
        target = str(tmp_path) + os.sep
        gt._maybe_save(target, 'ip_x', {'k': 'v'})
        files = list(tmp_path.glob('*.json'))
        assert len(files) == 1

    def test_filters_private_keys_from_username_json(self, tmp_path):
        """username 扫描 JSON 输出过滤 _* 私有 key（保留 _error）。
        注意：仅 prefix='username_' 时过滤；mx/whois 不过滤（合法 _dmarc 子域）。"""
        out = tmp_path / 'r.json'
        gt._maybe_save(str(out), 'username_x', {
            'GitHub': 'https://github.com/x',
            '_statuses': {'GitHub': 'found'},  # 必须过滤
        })
        loaded = json.loads(out.read_text(encoding='utf-8'))
        assert '_statuses' not in loaded
        assert 'GitHub' in loaded


class TestEmailValidateInput:
    """email_validate 输入校验：None / 空字符串 / 空白。"""

    def test_none_input(self):
        result = gt.email_validate(None)
        assert result['syntax_valid'] is False
        assert '_error' in result

    def test_empty_string(self):
        result = gt.email_validate('')
        assert result['syntax_valid'] is False

    def test_whitespace_only(self):
        result = gt.email_validate('   ')
        assert result['syntax_valid'] is False


class TestWhoisLookup:
    """whois_lookup 防御性输入处理。"""

    def test_none_return_handled(self):
        """python-whois 在罕见 TLD 上可能返回 None 而非抛异常。"""
        if not gt.HAS_WHOIS:
            pytest.skip('whois 依赖未安装')
        with patch.object(gt.whois, 'whois', return_value=None):
            result = gt.whois_lookup('weird.tld')
        assert '_error' in result

    def test_empty_domain(self):
        if not gt.HAS_WHOIS:
            pytest.skip('whois 依赖未安装')
        result = gt.whois_lookup('')
        assert '_error' in result

    def test_invalid_format_rejected_before_lookup(self):
        """非法 domain 不会进入 whois.whois，避免 internal traceback 泄漏。"""
        if not gt.HAS_WHOIS:
            pytest.skip('whois 依赖未安装')
        with patch.object(gt.whois, 'whois') as mock_whois:
            for bad in ('../etc/passwd', 'http://evil.com/', 'a\nb.com', 'no_dot'):
                result = gt.whois_lookup(bad)
                assert '_error' in result
        assert mock_whois.call_count == 0


class TestMxLookup:
    """mx_lookup 输入校验。"""

    def test_invalid_domain_rejected(self):
        """非法 domain 不会进入 dns.resolver.resolve。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        with patch.object(gt.dns.resolver, 'resolve') as mock_resolve:
            for bad in ('', '../admin', 'http://x', 'no_dot', 'a\nb'):
                result = gt.mx_lookup(bad)
                assert '_error' in result
        assert mock_resolve.call_count == 0


class TestNormalizeDomain:
    """_normalize_domain 单元测试（含 IDN 支持）。"""

    def test_valid_domains(self):
        for d in ('example.com', 'sub.example.com', 'EXAMPLE.COM', '  gmail.com  '):
            assert gt._normalize_domain(d) is not None

    def test_invalid_domains(self):
        for d in ('', '   ', 'no_dot', '../admin', 'http://x.com',
                  'a..b.com', '-bad.com', 'bad-.com', 'a\nb.com', None):
            assert gt._normalize_domain(d) is None, f"应拒绝 {d!r}"

    def test_normalizes_to_lowercase(self):
        assert gt._normalize_domain('GMAIL.COM') == 'gmail.com'

    def test_strips_whitespace(self):
        assert gt._normalize_domain('  gmail.com  ') == 'gmail.com'

    def test_idn_chinese_domain_to_punycode(self):
        """中文域名应转为 punycode（xn--）形式。"""
        result = gt._normalize_domain('中国.cn')
        assert result is not None
        assert result.startswith('xn--')

    def test_idn_japanese_domain(self):
        """日文域名同样支持。"""
        result = gt._normalize_domain('日本.jp')
        assert result is not None
        assert result.startswith('xn--')

    def test_idn_mixed_label(self):
        """混合 ASCII + Unicode label 也支持。"""
        result = gt._normalize_domain('mail.中国.cn')
        assert result is not None
        assert 'xn--' in result

    def test_already_punycode_passes_through(self):
        """已经是 punycode 形式的输入直接通过。"""
        result = gt._normalize_domain('xn--fiqs8s.cn')
        assert result == 'xn--fiqs8s.cn'


class TestEmailIDN:
    """email_validate 支持 IDN 域名（local 部分仍 ASCII）。"""

    def test_chinese_domain_email(self):
        with patch.object(gt, 'mx_lookup', return_value={
            'domain': 'xn--fiqs8s.cn',
            'records': [{'preference': 10, 'exchange': 'mx.example.com'}],
        }):
            r = gt.email_validate('user@中国.cn')
        assert r['syntax_valid'] is True

    def test_quote_in_local_part(self):
        """RFC 5321 允许 local 含 ' （之前 EMAIL_RE 拒绝了 o'malley@example.com）"""
        with patch.object(gt, 'mx_lookup', return_value={'_error': 'x', '_error_kind': gt.MX_ERR_NXDOMAIN}):
            r = gt.email_validate("o'malley@example.com")
        assert r['syntax_valid'] is True


class TestMxLookupErrorKind:
    """mx_lookup 返回稳定 _error_kind 枚举（替代 substring 嗅探）。"""

    def test_invalid_domain_kind(self):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        result = gt.mx_lookup('not_a_domain')
        assert result['_error_kind'] == gt.MX_ERR_INVALID_DOMAIN

    def test_nxdomain_kind(self):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        with patch.object(gt.dns.resolver, 'resolve',
                            side_effect=gt.dns.resolver.NXDOMAIN()):
            result = gt.mx_lookup('nonexistent.example')
        assert result['_error_kind'] == gt.MX_ERR_NXDOMAIN

    def test_no_mx_kind(self):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        with patch.object(gt.dns.resolver, 'resolve',
                            side_effect=gt.dns.resolver.NoAnswer()):
            result = gt.mx_lookup('example.com')
        assert result['_error_kind'] == gt.MX_ERR_NO_MX

    def test_dns_failed_kind_no_substring_misclassification(self):
        """关键：'NoNameservers' 含 'no' 之前会被错归为 no_mx，
        现在用稳定枚举不会再误判。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')

        class FakeNoNameservers(Exception):
            def __str__(self):
                return 'NoNameservers: All nameservers failed; no MX record cached'

        with patch.object(gt.dns.resolver, 'resolve',
                            side_effect=FakeNoNameservers()):
            result = gt.mx_lookup('example.com')
        assert result['_error_kind'] == gt.MX_ERR_DNS_FAILED, \
            "通用异常应归到 dns_failed，不能被 substring 'no' 误归 no_mx"


class TestPhoneIsValidSemantics:
    """track_phone 与 _record_history 的 is_valid 语义一致性。

    is_possible=True / is_valid=False 的号码现在不应被记为 ok=True
    （之前会，因为 _record_history 只查 _error）。"""

    def test_record_history_uses_is_valid(self, tmp_path, monkeypatch):
        """长度 OK 但号码段未分配 → is_valid=False → history 应记 ok=False。"""
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        # 模拟 track_phone 返回 is_possible=True 但 is_valid=False 的数据
        # （现实中，'+18005550199' 等保留号段可能触发）
        fake_data = {
            'is_valid': False,
            'is_possible': True,
            'country_code': 1,
            'national': 5550199,
        }
        gt._record_history('phone', argparse.Namespace(number='+15550199'), fake_data)
        with open(history_file, encoding='utf-8') as f:
            rec = json.loads(f.readline())
        assert rec['ok'] is False, "is_valid=False 应记为 ok=False"

    def test_record_history_valid_phone_records_ok(self, tmp_path, monkeypatch):
        history_file = str(tmp_path / 'h.jsonl')
        monkeypatch.setattr(gt, 'HISTORY_FILE', history_file)
        import argparse
        fake_data = {'is_valid': True, 'is_possible': True, 'country_code': 86}
        gt._record_history('phone', argparse.Namespace(number='+8613800138000'), fake_data)
        with open(history_file, encoding='utf-8') as f:
            rec = json.loads(f.readline())
        assert rec['ok'] is True


class TestNoHistoryEnvVar:
    """v1.0.x 加固：SPYEYES_NO_HISTORY=1 禁用历史记录（隐私选项）。
    SECURITY.md 承诺的「敏感场景禁用」必须真生效。"""

    def test_env_var_disables_history_write(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        monkeypatch.setenv('SPYEYES_NO_HISTORY', '1')
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        # 文件不应被创建
        assert not h.exists()

    def test_env_var_disable_with_yes(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        monkeypatch.setenv('SPYEYES_NO_HISTORY', 'yes')
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        assert not h.exists()

    def test_no_env_var_writes_normally(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        monkeypatch.delenv('SPYEYES_NO_HISTORY', raising=False)
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        assert h.exists()
        assert '8.8.8.8' in h.read_text(encoding='utf-8')


class TestUsernameC1ControlChars:
    """Round 9 加固：C1 控制字符 (0x80-0x9F) 也必须拒绝。
    含 NEL=0x85 / CSI=0x9B —— xterm 系终端解释为 ANSI escape 起始字节，
    可用于终端 escape injection。"""

    def test_c1_nel_rejected(self):
        """U+0085 (NEL) 被某些终端解释为换行。"""
        assert gt._is_invalid_username('foo\x85bar') is True

    def test_c1_csi_rejected(self):
        """U+009B (CSI) 是 ANSI escape 起始字节。"""
        assert gt._is_invalid_username('admin\x9b[31m') is True

    def test_c1_range_rejected(self):
        for c in ('\x80', '\x88', '\x90', '\x9f'):
            assert gt._is_invalid_username(f'a{c}b') is True

    def test_unicode_line_separator_rejected(self):
        """U+2028 / U+2029 / U+0085 在 markdown 中被视为换行 → 注入伪标题。"""
        assert gt._is_invalid_username('foo bar') is True
        assert gt._is_invalid_username('foo bar') is True


class TestMdEscapeUnicodeLineSeparators:
    """Round 9 加固：_md_escape 需替换 U+2028/U+2029/U+0085 为空格
    （str.splitlines() 视其为换行 → markdown 渲染注入伪标题）。"""

    def test_u2028_replaced(self):
        result = gt._md_escape('foo # fake header')
        assert ' ' not in result

    def test_u2029_replaced(self):
        assert ' ' not in gt._md_escape('a b')

    def test_nel_replaced(self):
        assert '\x85' not in gt._md_escape('a\x85b')


class TestSaveWhitespaceTarget:
    """Round 9 加固：_maybe_save 拒绝纯空白 target（' ' 是 truthy，会真创建文件）。"""

    def test_single_space_rejected(self, tmp_path, monkeypatch):
        # 切到 tmp 避免污染 cwd
        monkeypatch.chdir(tmp_path)
        gt._maybe_save(' ', 'ip_x', {'k': 'v'})
        # 空白 target 不应创建文件
        files = list(tmp_path.iterdir())
        assert ' ' not in [f.name for f in files], "纯空格 target 不应创建文件"

    def test_tab_only_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        gt._maybe_save('\t', 'ip_x', {'k': 'v'})
        files = list(tmp_path.iterdir())
        assert '\t' not in [f.name for f in files]


class TestUsernameControlChars:
    """Round 8 加固：控制字符（NUL / SOH / DEL 等）也应被拒绝。
    攻击场景：'admin\\x00garbage' 在某些日志聚合器中被截断为 'admin'，
    导致审计日志显示与实际查询不一致（防御性日志注入）。"""

    def test_nul_byte_rejected(self):
        assert gt._is_invalid_username('admin\x00') is True
        assert gt._is_invalid_username('a\x00b') is True

    def test_low_control_chars_rejected(self):
        for c in ('\x01', '\x02', '\x08', '\x0e', '\x1b', '\x1f'):
            assert gt._is_invalid_username(f'foo{c}bar') is True

    def test_del_char_rejected(self):
        assert gt._is_invalid_username('foo\x7fbar') is True

    def test_normal_unicode_still_accepted(self):
        """普通 Unicode（中文/日文）不应被控制字符检测误伤。"""
        assert gt._is_invalid_username('张三') is False
        assert gt._is_invalid_username('alice') is False


class TestLoadPlatformsJsonRobust:
    """Round 8 加固：_load_platforms_json 对损坏 / 恶意 JSON 必须不崩溃。"""

    def test_non_list_top_level_returns_empty(self, tmp_path):
        """JSON 顶层是 null / int / dict 时不应崩 TypeError。"""
        for content in ('null', '42', '"x"', 'true', '{"k": "v"}'):
            p = tmp_path / 'platforms.json'
            p.write_text(content, encoding='utf-8')
            assert gt._load_platforms_json(str(p)) == []

    def test_item_with_null_name_skipped(self, tmp_path):
        """单条 item name=null 不应让 _dedup_platforms 抛 AttributeError。"""
        p = tmp_path / 'platforms.json'
        p.write_text(json.dumps([
            {'name': None, 'url': 'https://x.com/{}'},
            {'name': 'GoodSite', 'url': 'https://good.com/{}'},
        ]), encoding='utf-8')
        result = gt._load_platforms_json(str(p))
        # 坏条被跳过，好条保留
        assert len(result) == 1
        assert result[0].name == 'GoodSite'

    def test_item_missing_name_skipped(self, tmp_path):
        p = tmp_path / 'platforms.json'
        p.write_text(json.dumps([
            {'url': 'https://x.com/{}'},  # 无 name
            {'name': 'OK', 'url': 'https://ok.com/{}'},
        ]), encoding='utf-8')
        result = gt._load_platforms_json(str(p))
        assert len(result) == 1

    def test_item_url_no_template_skipped(self, tmp_path):
        """url 不含 {} 占位符的条目跳过（无法 format username）。"""
        p = tmp_path / 'platforms.json'
        p.write_text(json.dumps([
            {'name': 'Bad', 'url': 'https://x.com/profile'},  # 无 {}
            {'name': 'OK', 'url': 'https://ok.com/{}'},
        ]), encoding='utf-8')
        result = gt._load_platforms_json(str(p))
        assert len(result) == 1
        assert result[0].name == 'OK'

    def test_non_dict_item_skipped(self, tmp_path):
        p = tmp_path / 'platforms.json'
        p.write_text(json.dumps([
            'string-not-dict',
            42,
            None,
            {'name': 'OK', 'url': 'https://ok.com/{}'},
        ]), encoding='utf-8')
        result = gt._load_platforms_json(str(p))
        assert len(result) == 1


class TestUsernameDotInjection:
    """Round 7 加固：username='.' / '..' / '.foo' / 'foo.' 拼到任意 URL 模板会
    触发假命中（github.com/. 返回首页 200 → 不含 not_found 模式 → 假报「找到」）。
    211 个 curated 平台无 regex_check，对此类输入完全没保护层。"""

    def test_single_dot_rejected(self):
        result = gt.track_username('.', max_workers=1, show_progress=False)
        assert '_error' in result, "'.' 拼到 URL 触发路径穿越，必须早返"

    def test_double_dot_rejected(self):
        result = gt.track_username('..', max_workers=1, show_progress=False)
        assert '_error' in result

    def test_dotdot_in_middle_rejected(self):
        result = gt.track_username('foo..bar', max_workers=1, show_progress=False)
        assert '_error' in result

    def test_leading_dot_rejected(self):
        result = gt.track_username('.foo', max_workers=1, show_progress=False)
        assert '_error' in result

    def test_trailing_dot_rejected(self):
        result = gt.track_username('foo.', max_workers=1, show_progress=False)
        assert '_error' in result

    def test_check_username_directly_also_rejects(self):
        """_check_username 也独立校验（深度防御）。"""
        p = gt.Platform('GitHub', 'https://github.com/{}', 'code')
        with patch.object(gt, 'safe_get') as mock_get:
            _, url, status = gt._check_username(p, '..', 5)
        assert mock_get.call_count == 0
        assert status == gt.STATUS_INVALID_USERNAME

    def test_normal_username_with_dot_in_middle_still_works(self):
        """合法 username 含点（非首尾、非连续）仍接受：bob.smith / a.b.c."""
        p = gt.Platform('X', 'https://x.com/{}', 'social')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            _, _, status = gt._check_username(p, 'bob.smith', 5)
        assert status == gt.STATUS_FOUND


class TestNormalizeDomainExtras:
    """Round 7 加固：trailing-dot FQDN + underscore-label OSINT 子域。"""

    def test_trailing_dot_fqdn_accepted(self):
        """'example.com.' 是合法 DNS FQDN，应被规范化为 'example.com'。"""
        assert gt._normalize_domain('example.com.') == 'example.com'

    def test_underscore_label_dmarc_accepted(self):
        """_dmarc.example.com 是合法 DKIM/DMARC 子域（OSINT 常用）。"""
        result = gt._normalize_domain('_dmarc.example.com')
        assert result == '_dmarc.example.com'

    def test_underscore_label_acme_accepted(self):
        """_acme-challenge.example.com 是合法 ACME 验证子域。"""
        result = gt._normalize_domain('_acme-challenge.example.com')
        assert result is not None
        assert '_acme-challenge' in result

    def test_dual_underscore_labels(self):
        """多个 _ label 都接受。"""
        assert gt._normalize_domain('_dmarc._domainkey.example.com') is not None


class TestWhoisDateFiltersNone:
    """Round 7 加固：_whois_date 过滤 list 内的 None / 异常元素。"""

    def test_list_with_none_filtered(self):
        import datetime as dt
        result = gt._whois_date([dt.datetime(2020, 1, 1), None, dt.datetime(2020, 6, 1)])
        assert result is not None
        assert len(result) == 2
        assert 'None' not in str(result), "不应有 'None' 字面字符串污染输出"

    def test_all_none_returns_none(self):
        result = gt._whois_date([None, None])
        assert result is None


class TestRecordHistoryUnknownCmd:
    """Round 7 加固：未知 cmd 不写空 entry 污染历史。"""

    def test_unknown_cmd_no_history_entry(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        import argparse
        gt._record_history('not_a_real_cmd', argparse.Namespace(), {})
        # 文件可能不存在或为空（早 return 不写）
        assert not h.exists() or h.read_text() == ''


class TestUsernameUrlInjection:
    """v1.0.x 加固：username 含 URL 元字符 / 空白时拒绝（防假阳性 + 主机劫持）。

    场景:
    - 'foo?x=1' 拼到 github.com/{} → 实际访问 /foo?x=1 → 假命中
    - 'a@b' 拼到 'https://{}.tumblr.com' → 主机变 b.tumblr.com
    - '../etc' 拼到任意模板 → 路径穿越
    """

    def test_question_mark_rejected(self):
        p = gt.Platform('GitHub', 'https://github.com/{}', 'code')
        with patch.object(gt, 'safe_get') as mock_get:
            _, url, status = gt._check_username(p, 'foo?bar=1', 5)
        assert mock_get.call_count == 0, "URL 元字符应在送进 platform.url.format 前被拦"
        assert status == gt.STATUS_INVALID_USERNAME

    def test_at_sign_rejected(self):
        p = gt.Platform('Tumblr', 'https://{}.tumblr.com', 'social')
        with patch.object(gt, 'safe_get') as mock_get:
            _, url, status = gt._check_username(p, 'a@evil.com', 5)
        assert mock_get.call_count == 0
        assert status == gt.STATUS_INVALID_USERNAME

    def test_path_traversal_rejected(self):
        p = gt.Platform('X', 'https://x.com/{}', 'social')
        with patch.object(gt, 'safe_get') as mock_get:
            _, url, status = gt._check_username(p, '../etc', 5)
        assert mock_get.call_count == 0
        assert status == gt.STATUS_INVALID_USERNAME

    def test_whitespace_rejected(self):
        p = gt.Platform('X', 'https://x.com/{}', 'social')
        with patch.object(gt, 'safe_get') as mock_get:
            _, url, status = gt._check_username(p, 'a b', 5)
        assert mock_get.call_count == 0
        assert status == gt.STATUS_INVALID_USERNAME

    def test_normal_username_still_accepted(self):
        """合法 username（字母数字 . - _ +）应正常通过。"""
        p = gt.Platform('X', 'https://x.com/{}', 'social')
        fake = MagicMock(status_code=200)
        with patch.object(gt, 'safe_get', return_value=fake):
            for name in ('alice', 'bob.smith', 'user-1', 'a_b', 'name+1'):
                _, _, status = gt._check_username(p, name, 5)
                assert status == gt.STATUS_FOUND, f"应接受合法 username {name!r}"


class TestSymlinkInstall:
    """_PLATFORMS_JSON 用 realpath 而非 abspath：通过 symlink 部署时仍能找到 data。"""

    def test_uses_realpath(self):
        # realpath 解析符号链接，abspath 不解析
        # 验证当前 _PLATFORMS_JSON 是 realpath 形式（不含 symlink）
        path = gt._PLATFORMS_JSON
        # _PLATFORMS_JSON 的目录应等于 spyeyes.py 真实目录的 realpath
        spyeyes_real_dir = os.path.dirname(os.path.realpath(gt.__file__))
        expected = os.path.join(spyeyes_real_dir, 'data', 'platforms.json')
        assert path == expected


class TestReadHistoryEdgeCases:
    """v1.0.x 加固：limit≤0 返回空（与 argparse 校验一致）；UnicodeDecodeError 容错。"""

    def test_limit_zero_returns_empty(self, tmp_path, monkeypatch):
        """limit=0 应返回空（之前 entries[-0:] 退化为 entries[0:] 全返回反直觉）。
        argparse 用 _positive_int 已拒绝 0；这里是函数级深度防御。"""
        h = tmp_path / 'h.jsonl'
        h.write_text('\n'.join([
            json.dumps({'cmd': 'ip', 'query': '1.1.1.1', 'ok': True}),
            json.dumps({'cmd': 'ip', 'query': '8.8.8.8', 'ok': True}),
        ]) + '\n', encoding='utf-8')
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        assert gt.read_history(limit=0) == []

    def test_limit_negative_returns_empty(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        h.write_text(json.dumps({'cmd': 'ip', 'query': 'x'}) + '\n', encoding='utf-8')
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        assert gt.read_history(limit=-5) == []

    def test_argparse_rejects_zero_limit(self):
        """CLI 层 --limit 0 被 _positive_int 拒绝。"""
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['history', '--limit', '0'])

    def test_argparse_rejects_negative_limit(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['history', '--limit', '-1'])

    def test_non_utf8_bytes_handled(self, tmp_path, monkeypatch):
        """外部进程写入 GBK 字节让整个 read_history 不应挂。"""
        h = tmp_path / 'h.jsonl'
        h.write_bytes(b'{"cmd":"ip","query":"x","ok":true}\n\xff\xfe garbage\n')
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        # 不应抛 UnicodeDecodeError
        result = gt.read_history(limit=10)
        # 至少能拿到合法的第一条
        assert len(result) >= 1
        assert result[0]['query'] == 'x'


class TestLoadConfigUnicodeDecode:
    """config.json 含非 UTF-8 字节也不应让 load_config 挂。"""

    def test_non_utf8_returns_empty(self, tmp_path, monkeypatch):
        c = tmp_path / 'config.json'
        c.write_bytes(b'\xff\xfe garbage')
        monkeypatch.setattr(gt, 'CONFIG_FILE', str(c))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        # 不应抛 UnicodeDecodeError
        assert gt.load_config() == {}


class TestHistoryTimestampHasTimezone:
    """append_history 写入的 ts 应含时区（OSINT 跨时区分析需要 TZ 信息）。"""

    def test_ts_has_timezone_offset(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        line = h.read_text(encoding='utf-8').strip()
        rec = json.loads(line)
        ts = rec['ts']
        # 应该是 ISO 格式 + 时区（+HHMM 或 -HHMM）或 UTC Z
        # 至少不是裸的 'YYYY-MM-DDTHH:MM:SS'
        # 具体检查：长度应大于 19（裸格式只有 19 字符）
        assert len(ts) > 19 or ts.endswith('Z'), \
            f"ts '{ts}' 应包含时区偏移，否则无法跨时区追溯"


class TestMarkdownSubdomainNotStripped:
    """Round 15 加固：_to_markdown 通用 dict 分支也不应过滤 _dmarc 等合法子域。
    （之前 _maybe_save Round 7 修了，但 _to_markdown 内部仍用 _platform_only）"""

    def test_underscore_subdomain_kept_in_md(self):
        """模拟批量 mx 结果含 _dmarc 子域，写入 markdown 表格应保留。"""
        data = {
            '_dmarc.example.com': {'records': '1 mx1'},
            'normal.com': {'records': '5 mx2'},
        }
        # prefix 'mx_xxx' 不是 username_，应保留所有 key
        md = gt._to_markdown('mx_x', data)
        assert '_dmarc.example.com' in md, \
            "批量 mx/whois 写 markdown 时合法 _dmarc 子域不应被过滤"
        assert 'normal.com' in md

    def test_username_md_still_filters_private(self):
        """username 扫描结果仍过滤 _statuses 等私有 key。"""
        data = {
            'GitHub': 'https://github.com/x',
            '_statuses': {'GitHub': 'found'},
        }
        md = gt._to_markdown('username_x', data)
        # username 路径走专用分支（不是通用 dict），_statuses 仍不出现
        assert '_statuses' not in md or '\\_statuses' in md


class TestPrivateSubdomainSavedNotStripped:
    """v1.0.x 加固：批量 mx/whois 保存时不应过滤 _dmarc.x.com 等合法子域。
    （之前 _maybe_save 无条件套用 _platform_only → 数据丢失）"""

    def test_underscore_subdomain_kept_in_mx_save(self, tmp_path):
        """模拟批量 mx 结果：含 _dmarc 子域的合法 result。"""
        save_file = tmp_path / 'r.json'
        data = {
            '_dmarc.example.com': {'records': [{'preference': 1, 'exchange': 'mx1'}]},
            'normal.com': {'records': [{'preference': 5, 'exchange': 'mx2'}]},
        }
        # prefix 'mx_xxx' 不是 username_，所以应保留所有 key
        gt._maybe_save(str(save_file), 'mx_x', data)
        loaded = json.loads(save_file.read_text(encoding='utf-8'))
        assert '_dmarc.example.com' in loaded, \
            "批量 mx/whois 保存时合法 _dmarc 子域不应被过滤"
        assert 'normal.com' in loaded

    def test_username_save_still_filters_private_keys(self, tmp_path):
        """验证 username 路径仍过滤 _statuses 等私有 key。"""
        save_file = tmp_path / 'r.json'
        data = {
            'GitHub': 'https://github.com/x',
            '_statuses': {'GitHub': 'found'},
        }
        gt._maybe_save(str(save_file), 'username_x', data)
        loaded = json.loads(save_file.read_text(encoding='utf-8'))
        assert 'GitHub' in loaded
        assert '_statuses' not in loaded


class TestWhoisDateList:
    """python-whois 对某些 TLD 返回 list[datetime]，str() 会得到 repr 字符串。"""

    def test_list_datetime_serialized_as_list_of_strings(self):
        if not gt.HAS_WHOIS:
            pytest.skip('whois 依赖未安装')
        import datetime as dt
        fake_w = type('FakeWhois', (), {
            'domain_name': 'test.com',
            'registrar': 'Test',
            'creation_date': dt.datetime(2020, 1, 1),
            'expiration_date': dt.datetime(2030, 1, 1),
            'updated_date': [dt.datetime(2025, 1, 1), dt.datetime(2025, 6, 1)],
            'name_servers': ['ns1.test.com'],
            'status': 'ok',
            'emails': ['admin@test.com'],
            'org': 'Test Org',
            'country': 'US',
        })()
        with patch.object(gt.whois, 'whois', return_value=fake_w):
            result = gt.whois_lookup('test.com')
        assert isinstance(result['updated_date'], list), \
            "list[datetime] 应序列化为 list of str，不是 repr 字符串"
        assert len(result['updated_date']) == 2
        assert all(isinstance(d, str) for d in result['updated_date'])
        # 单个 datetime 仍是字符串
        assert isinstance(result['creation_date'], str)
        assert isinstance(result['expiration_date'], str)


class TestIPv6ScopeIdRejected:
    """v1.0.x 加固：fe80::1%eth0 等带 scope_id 的 IPv6 会让 URL 包含 % 触发
    urllib3 解析错误，最终用户只看到「网络错误」误导。直接拒绝。"""

    def test_ipv6_with_scope_id_rejected_without_api_call(self):
        with patch.object(gt, 'safe_get') as mock_get:
            data = gt.track_ip('fe80::1%eth0')
        assert mock_get.call_count == 0, "scope_id 应在送进 URL 前被拦"
        assert '_error' in data
        assert 'fe80' in data['_error']

    def test_normal_ipv6_still_accepted(self):
        fake = MagicMock()
        fake.json.return_value = {'success': True, 'type': 'IPv6'}
        with patch.object(gt, 'safe_get', return_value=fake):
            data = gt.track_ip('2001:4860:4860::8888')
        assert '_error' not in data


class TestRunCli:
    """run_cli 端到端覆盖。
    autouse fixture 隔离 HISTORY_FILE / CONFIG_DIR，防止测试污染用户家目录
    （v1.0.x 加固：之前每次 pytest 都会在 ~/.spyeyes/history.jsonl 增条目）"""

    @pytest.fixture(autouse=True)
    def _isolate_history(self, tmp_path, monkeypatch):
        """每个 TestRunCli 测试都自动重定向 HISTORY_FILE/CONFIG_DIR 到 tmp。"""
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))

    def _make_args(self, **kwargs):
        import argparse
        return argparse.Namespace(**kwargs)

    def test_ip_success_returns_0(self, capsys, monkeypatch):
        monkeypatch.setattr(gt, 'track_ip', lambda x: {'country': 'US'})
        args = self._make_args(command='ip', target='8.8.8.8', json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert 'US' in out

    def test_ip_error_returns_1(self, capsys, monkeypatch):
        monkeypatch.setattr(gt, 'track_ip', lambda x: {'_error': 'invalid'})
        args = self._make_args(command='ip', target='garbage', json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 1

    def test_unknown_cmd_returns_2(self):
        args = self._make_args(command='not_a_real_cmd', json=False, save=None)
        rc = gt.run_cli(args)
        assert rc == 2

    def test_history_subcommand_returns_0(self, tmp_path, capsys):
        # HISTORY_FILE 已被 fixture 隔离
        args = self._make_args(command='history', limit=10, search=None,
                                json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 0
        # 空文件 → []
        assert '[]' in capsys.readouterr().out

    def test_myip_network_failure_returns_1(self, capsys, monkeypatch):
        """v1.0.x 加固：myip 网络失败时 exit 1（之前 ip=None 仍 exit 0
        让 shell `spyeyes myip || handle` 误判成功）。"""
        monkeypatch.setattr(gt, 'show_my_ip', lambda: None)
        args = self._make_args(command='myip', json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 1

    def test_myip_success_returns_0(self, capsys, monkeypatch):
        monkeypatch.setattr(gt, 'show_my_ip', lambda: '1.2.3.4')
        args = self._make_args(command='myip', json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 0

    def test_batch_whois_dispatched_to_batch_lookup(self, monkeypatch):
        """多个 domain 时 run_cli 走 _batch_lookup 而非单次 whois_lookup。"""
        called = {'batch': 0, 'single': 0}

        def fake_batch(fn, items, max_workers=10):
            called['batch'] += 1
            return {item: {'domain': item} for item in items}

        def fake_single(d):
            called['single'] += 1
            return {'domain': d}

        monkeypatch.setattr(gt, '_batch_lookup', fake_batch)
        monkeypatch.setattr(gt, 'whois_lookup', fake_single)

        gt.run_cli(self._make_args(command='whois', domains=['example.com'],
                                    json=True, save=None))
        gt.run_cli(self._make_args(command='whois',
                                    domains=['example.com', 'test.com'],
                                    json=True, save=None))
        assert called['batch'] == 1
        assert called['single'] == 1

    def test_save_called_on_success(self, tmp_path, monkeypatch, capsys):
        save_path = str(tmp_path / 'r.json')
        monkeypatch.setattr(gt, 'track_ip', lambda x: {'country': 'US'})
        args = self._make_args(command='ip', target='8.8.8.8',
                                json=True, save=save_path)
        rc = gt.run_cli(args)
        assert rc == 0
        assert os.path.exists(save_path)


class TestPhoneInvalid:
    """track_phone 拒绝可解析但 not_possible 的号码。"""

    def test_parse_failure_rejected(self):
        """'+1' / '+86' 等极短输入直接 NumberParseException 路径被拒。"""
        for n in ('+1', '+86', '+861'):
            result = gt.track_phone(n)
            assert '_error' in result, f"应拒绝 {n}"

    def test_possible_but_invalid_rejected(self):
        """'+123' / '+1234' parse 成功但 is_possible_number=False —— 走新加的防御。
        没有这层防御 _record_history 会把它误记为成功（'_error' not in data）。"""
        for n in ('+123', '+1234', '+12345', '+8612', '+86123'):
            result = gt.track_phone(n)
            assert '_error' in result, f"应拒绝 is_possible=False 的 {n}"
            # 必须走新加的防御消息，不是 NumberParseException 消息
            assert ('不可解析' in result['_error']
                    or 'not a possible' in result['_error'].lower()), \
                f"{n} 应走 is_possible 防御，实际：{result['_error']}"

    def test_normal_number_still_works(self):
        result = gt.track_phone('+8613800138000')
        assert '_error' not in result
        assert result['is_valid'] is True


class TestMarkdownBacktickInjection:
    """v1.0.x 加固：防 backtick 跳出 inline code 注入 markdown。
    （之前测试用 'A or B' 短路逻辑形同虚设，已重写为独立断言）"""

    def test_user_input_backtick_is_escaped(self):
        """username 含 backtick 必须被 \\` 转义，不能原样进 markdown。"""
        md = gt._to_markdown('username_foo`bar`baz',
                              {'GitHub': 'https://github.com/foo'})
        # 关键断言：原始未转义的 backtick 不应在 query 字段出现（除了 ``` 三反引号代码块）
        # 用户输入区是 query (foo`bar`baz)，应已被 _md_escape 转义为 foo\`bar\`baz
        assert 'foo\\`bar\\`baz' in md, \
            f"username 中的 backtick 必须被 \\\\` 转义，实际 md:\n{md}"

    def test_dict_value_backtick_escaped(self):
        """dict value 含 backtick 也必须转义（不能跳出 inline code 注入 HTML）。"""
        md = gt._to_markdown('ip_8.8.8.8',
                              {'note': 'normal `dangerous` more'})
        # 真正的安全检查：原始 `dangerous` 必须被转义（出现 \\`dangerous\\`）
        assert '\\`dangerous\\`' in md, \
            f"dict value 中的 backtick 必须转义，实际 md:\n{md}"

    def test_md_escape_function_directly(self):
        """直接测 _md_escape 函数：所有 backtick 必须前置 \\\\."""
        result = gt._md_escape('a`b`c')
        assert result == 'a\\`b\\`c'
        # pipe / newline 也必须转义
        assert gt._md_escape('a|b') == 'a\\|b'
        assert gt._md_escape('a\nb') == 'a b'


class TestDirHasLazyPlatforms:
    """PEP 562 __getattr__ 不应破坏 introspection（IDE 自动补全等）。"""

    def test_platforms_visible_via_dir(self):
        assert 'PLATFORMS' in dir(gt)

    def test_other_attrs_still_visible(self):
        d = dir(gt)
        for attr in ('track_ip', 'track_username', 'whois_lookup',
                     '__version__', 'MAX_USERNAME_LENGTH'):
            assert attr in d, f"{attr} 应在 dir() 里"


class TestPlatformImmutable:
    """Platform NamedTuple 不可变性回归测试。"""

    def test_cannot_set_attribute(self):
        p = gt.Platform('X', 'https://x.com/{}', 'code')
        with pytest.raises(AttributeError):
            p.name = 'Y'  # type: ignore[misc]

    def test_default_fields_are_tuples(self):
        p = gt.Platform('X', 'https://x.com/{}', 'code')
        assert isinstance(p.not_found, tuple)
        assert isinstance(p.must_contain, tuple)


class TestDetectWafStringInput:
    """_detect_waf 防御性接受 str 输入（contract 是 bytes）。"""

    def test_str_input_handled(self):
        # 不应抛 TypeError
        assert gt._detect_waf('cdn-cgi/challenge-platform') is True

    def test_non_bytes_non_str_returns_false(self):
        assert gt._detect_waf(None) is False
        assert gt._detect_waf(123) is False


class TestHistoryCorruption:
    """守护：history.jsonl 单行损坏不应让整个 read_history 挂掉。"""

    def test_corrupted_line_skipped(self, tmp_path, monkeypatch):
        history_file = tmp_path / 'h.jsonl'
        history_file.write_text(
            '{"valid": 1}\n'
            '{garbage not json\n'
            '{"valid": 2}\n',
            encoding='utf-8',
        )
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(history_file))
        result = gt.read_history()
        # 应跳过损坏行，返回 2 条合法记录
        assert len(result) == 2
        assert all('valid' in r for r in result)

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'nonexistent.jsonl'))
        assert gt.read_history() == []


class TestConfigCorruption:
    """守护：config.json 损坏不应让 load_config 挂掉。"""

    def test_corrupted_json_returns_empty_dict(self, tmp_path, monkeypatch):
        config_file = tmp_path / 'config.json'
        config_file.write_text('{not valid json', encoding='utf-8')
        monkeypatch.setattr(gt, 'CONFIG_FILE', str(config_file))
        # 也要重定向 CONFIG_DIR 避免触发 _migrate_legacy_config
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        assert gt.load_config() == {}


class TestSavePermissionError:
    """v1.1.x 加固：_maybe_save 遇到 OSError 友好提示而非抛 traceback。
    用 mock 模拟而非真实 chmod —— Windows chmod(0o555) 是 no-op，跨平台不稳。"""

    def test_permission_denied_handled(self, tmp_path, capsys, monkeypatch):
        """open() 抛 PermissionError 时应打印错误而非崩溃。"""
        target = str(tmp_path / 'r.json')

        real_open = open

        def fake_open(path, *args, **kwargs):
            # 仅对目标文件抛错，其它（i18n 加载等）正常
            if str(path) == target:
                raise PermissionError(13, 'Permission denied')
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', fake_open)
        # 不应抛 PermissionError
        gt._maybe_save(target, 'ip_x', {'k': 'v'})
        captured = capsys.readouterr()
        # 必须有错误提示（中英任意）
        combined = (captured.err + captured.out).lower()
        assert 'error' in combined or '错' in (captured.err + captured.out) or \
               'permission' in combined or '失败' in (captured.err + captured.out) or \
               '无法' in (captured.err + captured.out)

    def test_makedirs_failure_handled(self, tmp_path, capsys, monkeypatch):
        """os.makedirs 抛 OSError（如 NotADirectoryError）时应友好处理 + 必须有错误提示。"""
        def boom(*args, **kwargs):
            raise OSError(20, 'Not a directory')

        monkeypatch.setattr(gt.os, 'makedirs', boom)
        target = str(tmp_path / 'sub' / 'r.json')
        # 不应抛
        gt._maybe_save(target, 'ip_x', {'k': 'v'})
        # 必须有错误提示（不能静默吞）
        captured = capsys.readouterr()
        combined = captured.err + captured.out
        assert 'error' in combined.lower() or '错' in combined or '失败' in combined or '无法' in combined, \
            f"_maybe_save 静默吞错没提示，拿到：err={captured.err!r} out={captured.out!r}"


class TestEmailMxErrorEnum:
    """email_validate 的 mx_error 直接读 mx_lookup 返回的 _error_kind 枚举
    （v1.0.x 前用 substring 匹配 i18n msg 容易误判，已改为枚举）。"""

    def test_nxdomain_kind_propagated(self):
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': 'NXDOMAIN: example.invalid',
            '_error_kind': gt.MX_ERR_NXDOMAIN,
        }):
            r = gt.email_validate('user@example.invalid')
        assert r['mx_error'] == 'nxdomain'

    def test_no_mx_kind_propagated(self):
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': 'x.com has no MX records',
            '_error_kind': gt.MX_ERR_NO_MX,
        }):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'no_mx'

    def test_invalid_domain_kind_propagated(self):
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': '域名格式不合法：x',
            '_error_kind': gt.MX_ERR_INVALID_DOMAIN,
        }):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'invalid_domain'

    def test_dns_failed_kind_propagated_no_ip_leak(self):
        """dns_failed 错误的 server IP 不应泄漏到结果（信息隐藏）。"""
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': 'TimeoutError on 10.0.0.1:53',
            '_error_kind': gt.MX_ERR_DNS_FAILED,
        }):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'dns_failed'
        # _error_kind 是 enum 字符串，不含 IP；mx_error 字段也不含
        assert '10.0.0.1' not in r['mx_error']

    def test_missing_kind_falls_back_to_dns_failed(self):
        """旧式 mx_lookup 没返回 _error_kind 时，安全 fallback 为 dns_failed。"""
        with patch.object(gt, 'mx_lookup', return_value={'_error': 'something'}):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'dns_failed'
