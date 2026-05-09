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
        # v1.4.1: Markdown 以 YAML frontmatter 开头
        assert content.startswith('---\n'), 'Markdown should start with YAML frontmatter'
        assert '\n# ' in content, 'Markdown should contain a top-level heading'
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


class TestEmailMxErrorMsgFriendly:
    """Round 29 加固：print_email 显示 i18n 友好消息而非英文枚举字符串。
    （之前用户看到 'nxdomain' 而不是「域名不存在：x.com」）"""

    def test_email_validate_includes_friendly_msg(self):
        """email_validate 返回 mx_error_msg（i18n 友好消息）+ mx_error（枚举）。"""
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': '域名不存在：example.com',
            '_error_kind': gt.MX_ERR_NXDOMAIN,
        }):
            r = gt.email_validate('user@example.com')
        # 程序判定面：稳定枚举
        assert r['mx_error'] == 'nxdomain'
        # UI 显示面：i18n 友好消息
        assert r['mx_error_msg'] == '域名不存在：example.com'


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

    def test_history_save_actually_writes(self, tmp_path, capsys):
        """Round 24 加固: history --save 之前早 return 0 静默丢失。
        现在必须真写文件。"""
        save_path = str(tmp_path / 'h.json')
        # 先写一条历史
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        args = self._make_args(command='history', limit=10, search=None,
                                json=True, save=save_path)
        rc = gt.run_cli(args)
        assert rc == 0
        assert os.path.exists(save_path), "history --save 必须真写文件，不能静默丢失"
        # 内容应是 list 含 1 条
        loaded = json.loads(open(save_path).read())
        assert isinstance(loaded, list) and len(loaded) >= 1

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
        """dns_failed 错误的 server IP 不应泄漏到 mx_error 枚举字段。
        但 mx_error_msg 保留原始 i18n msg 供 UI 显示（含 IP 是 dns lib 行为，
        不在我们 OSINT 工具的隐私防护范围内）。"""
        with patch.object(gt, 'mx_lookup', return_value={
            '_error': 'TimeoutError on 10.0.0.1:53',
            '_error_kind': gt.MX_ERR_DNS_FAILED,
        }):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'dns_failed'
        # 关键：mx_error 枚举字段不含 IP（程序判定面）
        assert '10.0.0.1' not in r['mx_error']

    def test_missing_kind_falls_back_to_dns_failed(self):
        """旧式 mx_lookup 没返回 _error_kind 时，安全 fallback 为 dns_failed。"""
        with patch.object(gt, 'mx_lookup', return_value={'_error': 'something'}):
            r = gt.email_validate('user@x.com')
        assert r['mx_error'] == 'dns_failed'


# ====================================================================
# v1.1.0: permute_username 用户名变形生成器
# ====================================================================
class TestPermuteUsername:
    def test_empty_returns_empty(self):
        assert gt.permute_username('') == []
        assert gt.permute_username('   ') == []
        assert gt.permute_username(None) == []

    def test_single_word(self):
        out = gt.permute_username('torvalds')
        assert out == ['torvalds']

    def test_two_words_basic(self):
        out = gt.permute_username('John Doe')
        # 必含的关键变形
        assert 'johndoe' in out
        assert 'doejohn' in out
        assert 'john.doe' in out
        assert 'doe.john' in out
        assert 'jdoe' in out
        assert 'johnd' in out
        assert 'jd' in out

    def test_lowercase_normalized(self):
        out = gt.permute_username('JOHN DOE')
        assert all(s == s.lower() for s in out)

    def test_dot_separated_input(self):
        out = gt.permute_username('john.doe')
        assert 'johndoe' in out

    def test_underscore_separated_input(self):
        out = gt.permute_username('john_doe')
        assert 'johndoe' in out

    def test_comma_separated(self):
        out = gt.permute_username('John,Doe')
        assert 'johndoe' in out

    def test_strips_punctuation(self):
        # "John!" → 单片段 → ["john"]
        out = gt.permute_username('John!')
        assert 'john' in out

    def test_max_input_parts_truncated(self):
        # 5 个片段超过 PERMUTE_MAX_INPUT_PARTS=4，应截断而非崩溃
        out = gt.permute_username('a b c d e')
        assert out  # 不为空
        # 截断到 4 部分；不应包含第 5 个 'e' 单独
        assert isinstance(out, list)

    def test_output_capped(self):
        # 4 部分组合可能很多，但 PERMUTE_MAX_OUTPUT 限制
        out = gt.permute_username('alice bob carol dan')
        assert len(out) <= gt.PERMUTE_MAX_OUTPUT

    def test_unicode_chinese_falls_through(self):
        # 中文字符不被 \w 匹配为非字母数字 → 被剥离 → 空
        # 实际上 Python re \w 在 unicode 模式下匹配中文 → 应能保留
        out = gt.permute_username('张 三')
        # 非空结果是好的；主要是不能崩
        assert isinstance(out, list)

    def test_dedupe(self):
        # "ab ab" → 两个相同片段 → 不应有重复
        out = gt.permute_username('foo foo')
        assert len(out) == len(set(out))

    def test_sorted_output(self):
        out = gt.permute_username('Charlie Alpha')
        assert out == sorted(out)


# ====================================================================
# v1.1.0: recursive_track_username 与 _extract_usernames_from_text
# ====================================================================
class TestExtractUsernames:
    def test_at_handle(self):
        text = "Find me at @torvalds and @ kernel."
        out = gt._extract_usernames_from_text(text, set())
        assert 'torvalds' in out

    def test_twitter_url(self):
        text = "Check https://twitter.com/elonmusk for updates"
        out = gt._extract_usernames_from_text(text, set())
        assert 'elonmusk' in out

    def test_github_url(self):
        text = "https://github.com/torvalds/linux"
        out = gt._extract_usernames_from_text(text, set())
        assert 'torvalds' in out

    def test_excludes_known(self):
        text = "@alice @bob @alice"
        out = gt._extract_usernames_from_text(text, {'bob'})
        assert 'alice' in out
        assert 'bob' not in out

    def test_dedupe(self):
        text = "@alice @alice @ALICE"
        out = gt._extract_usernames_from_text(text, set())
        # 都小写化后 dedupe
        assert out.count('alice') == 1

    def test_skips_short(self):
        text = "@a @ab @abc"  # <3 chars filtered
        out = gt._extract_usernames_from_text(text, set())
        assert 'a' not in out
        assert 'ab' not in out
        assert 'abc' in out

    def test_skips_too_long(self):
        long_name = '@' + 'a' * 50
        out = gt._extract_usernames_from_text(long_name, set())
        assert not out

    def test_skips_invalid(self):
        # 含 URL 元字符的不应通过 _is_invalid_username
        # @ 后必须是字母开头（regex 限制）—— 这里测的是 _is_invalid_username 兜底
        text = "@valid_user"
        out = gt._extract_usernames_from_text(text, set())
        # valid_user 通过验证
        assert 'valid_user' in out

    def test_empty_input(self):
        assert gt._extract_usernames_from_text('', set()) == []
        assert gt._extract_usernames_from_text(None, set()) == []


class TestRecursiveTrackUsername:
    def test_depth_zero_acts_like_track_username(self):
        # depth=0 → 仅扫初始 username，不递归
        with patch.object(gt, 'track_username',
                          return_value={'GitHub': 'https://github.com/x', '_statuses': {}}) as mock_track:
            result = gt.recursive_track_username('alice', max_depth=0,
                                                 show_progress=False)
        assert mock_track.call_count == 1
        assert '_recursive' in result
        assert result['_recursive']['levels'][0]['username'] == 'alice'
        assert result['_recursive']['depth_reached'] == 0

    def test_depth_clamped_to_max(self):
        with patch.object(gt, 'track_username',
                          return_value={'_statuses': {}}):
            r = gt.recursive_track_username('x', max_depth=99, show_progress=False)
        # max 被钳到 RECURSIVE_MAX_DEPTH
        assert r['_recursive']['depth_reached'] <= gt.RECURSIVE_MAX_DEPTH

    def test_error_in_initial_scan(self):
        with patch.object(gt, 'track_username',
                          return_value={'_error': 'bad input'}):
            r = gt.recursive_track_username('!!!', max_depth=2, show_progress=False)
        levels = r['_recursive']['levels']
        assert levels[0].get('error') == 'bad input'

    def test_visited_dedup(self):
        """同一个用户名不应在多层中被重复扫描。"""
        call_log: list = []

        def fake_track(name, **kw):
            call_log.append(name)
            return {'GitHub': f'https://github.com/{name}', '_statuses': {}}

        # mock safe_get to return body that mentions same user
        fake_resp = MagicMock()
        fake_resp.text = '@alice @alice @alice'
        with patch.object(gt, 'track_username', side_effect=fake_track), \
             patch.object(gt, 'safe_get', return_value=fake_resp):
            gt.recursive_track_username('alice', max_depth=2,
                                        show_progress=False)
        # 'alice' 只该被扫一次（visited 去重）
        assert call_log.count('alice') == 1


# ====================================================================
# v1.1.0: PDF 报告输出
# ====================================================================
@pytest.mark.skipif(not gt.HAS_REPORTLAB, reason="reportlab not installed")
class TestPdfReport:
    def test_basic_ip_pdf(self, tmp_path):
        out = tmp_path / "report.pdf"
        err = gt._to_pdf('ip_8.8.8.8', {'country': 'US', 'city': 'X'}, str(out))
        assert err is None
        assert out.exists()
        # PDF magic header
        assert out.read_bytes().startswith(b'%PDF')

    def test_username_scan_pdf(self, tmp_path):
        out = tmp_path / "user.pdf"
        data = {
            'GitHub': 'https://github.com/x',
            'Twitter': None,
            '_statuses': {},
        }
        err = gt._to_pdf('username_torvalds', data, str(out))
        assert err is None
        assert out.exists()

    def test_error_in_data(self, tmp_path):
        out = tmp_path / "err.pdf"
        err = gt._to_pdf('ip_x', {'_error': 'bad'}, str(out))
        assert err is None
        assert out.exists()

    def test_pipe_in_value_escaped(self, tmp_path):
        """用户输入含 | 不应破坏 PDF 表格。"""
        out = tmp_path / "esc.pdf"
        err = gt._to_pdf('ip_x', {'org': 'a|b|c'}, str(out))
        assert err is None
        assert out.exists()


class TestPdfWithoutReportlab:
    def test_returns_error_when_no_reportlab(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HAS_REPORTLAB', False)
        err = gt._to_pdf('ip_x', {'a': 1}, str(tmp_path / 'r.pdf'))
        assert err is not None
        assert 'reportlab' in err.lower() or 'pdf' in err.lower()


# ====================================================================
# v1.1.0: _maybe_save 识别 .pdf 扩展名
# ====================================================================
class TestMaybeSavePdf:
    @pytest.mark.skipif(not gt.HAS_REPORTLAB, reason="reportlab not installed")
    def test_pdf_extension_creates_pdf(self, tmp_path, capsys):
        out = tmp_path / "report.pdf"
        gt._maybe_save(str(out), 'ip_8.8.8.8', {'country': 'US'})
        assert out.exists()
        assert out.read_bytes().startswith(b'%PDF')

    def test_pdf_without_reportlab_friendly_error(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(gt, 'HAS_REPORTLAB', False)
        out = tmp_path / "report.pdf"
        gt._maybe_save(str(out), 'ip_x', {'a': 1})
        # 没生成 PDF
        assert not out.exists()
        # 应有错误提示输出到 stderr
        captured = capsys.readouterr()
        assert 'reportlab' in captured.err.lower() or 'pdf' in captured.err.lower()


# ====================================================================
# v1.1.0: CLI 解析 —— permute / user --recursive
# ====================================================================
class TestCliPermute:
    def test_permute_subcommand_exists(self):
        parser = gt.build_parser()
        args = parser.parse_args(['permute', 'John Doe'])
        assert args.command == 'permute'
        assert args.name == 'John Doe'

    def test_permute_scan_flag(self):
        parser = gt.build_parser()
        args = parser.parse_args(['permute', 'X', '--scan', '--workers', '50'])
        assert args.scan is True
        assert args.workers == 50

    def test_user_recursive_flag(self):
        parser = gt.build_parser()
        args = parser.parse_args(['user', 'torvalds', '--recursive', '--depth', '1'])
        assert args.recursive is True
        assert args.depth == 1

    def test_user_recursive_default_depth(self):
        parser = gt.build_parser()
        args = parser.parse_args(['user', 'torvalds', '--recursive'])
        assert args.depth == 2  # default


class TestRunCliPermute:
    def test_run_permute_no_scan(self, capsys):
        parser = gt.build_parser()
        args = parser.parse_args(['permute', 'foo bar', '--lang', 'en'])
        # set required defaults that run_cli expects
        gt.set_lang('en')
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert 'foo' in out.lower() or 'bar' in out.lower()

    def test_run_permute_json(self, capsys):
        parser = gt.build_parser()
        args = parser.parse_args(['permute', 'foo bar', '--json'])
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data['name'] == 'foo bar'
        assert isinstance(data['permutations'], list)
        assert 'foobar' in data['permutations']

    def test_run_permute_empty_input(self, capsys):
        parser = gt.build_parser()
        args = parser.parse_args(['permute', '   ', '--json'])
        rc = gt.run_cli(args)
        # 空输入返回 _error → 非零退出
        assert rc == 1
        out = capsys.readouterr().out
        data = json.loads(out)
        assert '_error' in data


# ====================================================================
# v1.1.0: 翻译键完整性（防止某语言漏键导致 UI 退化为 key 字符串）
# ====================================================================
class TestNewTranslationKeys:
    def test_v110_keys_exist_in_both_langs(self):
        new_keys = [
            'permute.title', 'permute.generated',
            'err.permute_empty',
            'recursive.depth', 'recursive.title', 'msg.recursive_done',
            'err.no_pdf', 'err.pdf_failed',
        ]
        for key in new_keys:
            assert key in gt.TRANSLATIONS['en'], f"Missing en: {key}"
            assert key in gt.TRANSLATIONS['zh'], f"Missing zh: {key}"

    def test_t_returns_localized(self):
        gt.set_lang('en')
        en_msg = gt.t('recursive.title')
        gt.set_lang('zh')
        zh_msg = gt.t('recursive.title')
        # 不同语言应返回不同字符串
        assert en_msg != zh_msg
        # 都不应是 key 本身（fallback 失败）
        assert en_msg != 'recursive.title'
        assert zh_msg != 'recursive.title'


# ====================================================================
# v1.3.0: 子域名枚举(被动多源 + DNS + HTTP probe)
# ====================================================================
class TestSubdomainCleanCandidates:
    """归一化逻辑:小写、过滤 wildcard、过滤跨域、字符白名单。"""

    def test_basic_filter(self):
        out = gt._clean_subdomain_candidates(['API.example.com', 'mail.example.com'],
                                              'example.com')
        assert 'api.example.com' in out
        assert 'mail.example.com' in out

    def test_wildcard_prefix_stripped(self):
        out = gt._clean_subdomain_candidates(['*.example.com'], 'example.com')
        assert out == {'example.com'}

    def test_cross_domain_filtered(self):
        """被动源串域(返回 evil.com)必须丢弃 — 防数据污染。"""
        out = gt._clean_subdomain_candidates(
            ['api.example.com', 'evil.com', 'sub.evil.com'], 'example.com')
        assert out == {'api.example.com'}

    def test_invalid_chars_rejected(self):
        out = gt._clean_subdomain_candidates(
            ['api.example.com', 'a b.example.com', 'a/b.example.com'], 'example.com')
        assert out == {'api.example.com'}

    def test_overly_long_rejected(self):
        long_host = 'a' * 254 + '.example.com'
        out = gt._clean_subdomain_candidates([long_host], 'example.com')
        assert out == set()

    def test_trailing_dot_normalized(self):
        out = gt._clean_subdomain_candidates(['api.example.com.'], 'example.com')
        assert 'api.example.com' in out

    def test_non_string_filtered(self):
        out = gt._clean_subdomain_candidates(['api.example.com', None, 42, ''], 'example.com')
        assert out == {'api.example.com'}

    def test_non_iterable_returns_empty(self):
        assert gt._clean_subdomain_candidates(None, 'example.com') == set()
        assert gt._clean_subdomain_candidates('string', 'example.com') == set()

    def test_newlines_in_host_skipped(self):
        """crt.sh name_value 含 \\n 是上层负责按行 split,这里防御性拒收剩余的换行。"""
        out = gt._clean_subdomain_candidates(['a.example.com\nb.example.com'], 'example.com')
        assert out == set()


class TestSubdomainParsers:
    """4 个被动数据源的 mock 测试。"""

    def test_crtsh_parses_name_value(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = [
            {'name_value': 'api.example.com\nmail.example.com'},
            {'common_name': 'blog.example.com'},
        ]
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._src_crtsh('example.com')
        assert {'api.example.com', 'mail.example.com', 'blog.example.com'} <= out

    def test_crtsh_handles_non_json(self):
        fake = MagicMock(status_code=200)
        fake.json.side_effect = ValueError('not JSON')
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._src_crtsh('example.com') == set()

    def test_crtsh_network_failure(self):
        with patch.object(gt, 'safe_get', return_value=None):
            assert gt._src_crtsh('example.com') == set()

    def test_hackertarget_csv_format(self):
        fake = MagicMock(status_code=200,
                         text='api.example.com,1.2.3.4\nmail.example.com,5.6.7.8\n')
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._src_hackertarget('example.com')
        assert 'api.example.com' in out
        assert 'mail.example.com' in out

    def test_hackertarget_rate_limit_returns_empty(self):
        fake = MagicMock(status_code=200, text='API count exceeded - rate limit reached')
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._src_hackertarget('example.com') == set()

    def test_otx_parses_passive_dns(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {
            'passive_dns': [
                {'hostname': 'api.example.com'},
                {'hostname': 'mail.example.com'},
                {'no_hostname': 'irrelevant'},
            ]
        }
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._src_otx('example.com')
        assert {'api.example.com', 'mail.example.com'} <= out

    def test_otx_handles_non_dict(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = ['unexpected', 'list', 'format']
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._src_otx('example.com') == set()

    def test_subfinder_no_binary_returns_empty(self, monkeypatch):
        """v1.4.8:没装 subfinder 时 silent 返 empty set(不破坏主流程)。"""
        monkeypatch.setattr(gt, '_SUBFINDER_BIN', None)
        monkeypatch.setattr(gt, '_SUBFINDER_CHECKED', True)
        result = gt._src_subfinder('example.com')
        assert result == set()

    def test_subfinder_parses_json_output(self, monkeypatch):
        """v1.4.8:有 subfinder 时解析 JSON Lines 输出 + 跨域过滤。"""
        monkeypatch.setattr(gt, '_SUBFINDER_BIN', '/usr/local/bin/subfinder')
        monkeypatch.setattr(gt, '_SUBFINDER_CHECKED', True)
        # subfinder -json 输出 JSONL 格式:每行一个 {"host": "..."} 对象
        fake_output = (
            '{"host":"api.example.com","input":"example.com","source":"crtsh"}\n'
            '{"host":"mail.example.com","input":"example.com","source":"chaos"}\n'
            '{"host":"evil.com","input":"example.com","source":"chaos"}\n'  # 跨域,应过滤
            '\n'  # 空行
            'invalid-not-json\n'  # 老版本可能直接 plain text
        )

        class FakeProc:
            returncode = 0
            stdout = fake_output
            stderr = ''
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: FakeProc())
        result = gt._src_subfinder('example.com')
        # api / mail 通过,evil.com 跨域被过滤,invalid-not-json 通过 _clean(非合法 hostname 被拒)
        assert 'api.example.com' in result
        assert 'mail.example.com' in result
        assert 'evil.com' not in result

    def test_subfinder_timeout_returns_empty(self, monkeypatch):
        """subfinder 超时时返空,不让单源拖垮整体。"""
        import subprocess
        monkeypatch.setattr(gt, '_SUBFINDER_BIN', '/usr/local/bin/subfinder')
        monkeypatch.setattr(gt, '_SUBFINDER_CHECKED', True)

        def fake_run(*a, **kw):
            raise subprocess.TimeoutExpired(cmd='subfinder', timeout=90)
        monkeypatch.setattr('subprocess.run', fake_run)
        result = gt._src_subfinder('example.com')
        assert result == set()

    def test_subfinder_nonzero_exit_returns_empty(self, monkeypatch):
        """subfinder 异常退出时返空。"""
        monkeypatch.setattr(gt, '_SUBFINDER_BIN', '/usr/local/bin/subfinder')
        monkeypatch.setattr(gt, '_SUBFINDER_CHECKED', True)

        class FakeProc:
            returncode = 1
            stdout = ''
            stderr = 'error: invalid domain'
        monkeypatch.setattr('subprocess.run', lambda *a, **kw: FakeProc())
        assert gt._src_subfinder('example.com') == set()

    def test_subfinder_in_sources_dict(self):
        """SUBDOMAIN_SOURCES 含 'subfinder' key(v1.4.8 加的第 5 源)。"""
        assert 'subfinder' in gt.SUBDOMAIN_SOURCES

    def test_wayback_parses_cdx_response(self):
        """v1.4.9:Wayback CDX JSON 响应抽 hostname。"""
        fake = MagicMock(status_code=200)
        # CDX 格式:第一行 header,后续每行 [original_url]
        fake.json.return_value = [
            ['original'],
            ['https://api.example.com/v1/users'],
            ['http://blog.example.com/post/1'],
            ['https://www.example.com/'],
            ['https://attacker.com/evil'],  # 跨域应过滤
            ['malformed-no-scheme.example.com/x'],  # 无 scheme,_src_wayback 自动加 http://
        ]
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._src_wayback('example.com')
        assert 'api.example.com' in out
        assert 'blog.example.com' in out
        assert 'www.example.com' in out
        assert 'attacker.com' not in out

    def test_wayback_handles_empty_response(self):
        """空 CDX(只有 header 或 None)返空 set。"""
        fake = MagicMock(status_code=200)
        fake.json.return_value = [['original']]  # 仅 header,无数据
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._src_wayback('example.com') == set()

    def test_wayback_handles_rate_limit(self):
        """Wayback 限速返非 200,silent 返空(不破坏其他源)。"""
        fake = MagicMock(status_code=429)
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._src_wayback('example.com') == set()

    def test_wayback_in_sources_dict(self):
        """SUBDOMAIN_SOURCES 含 'wayback'(v1.4.9 加的第 6 源)。"""
        assert 'wayback' in gt.SUBDOMAIN_SOURCES


class TestBruteforce:
    """v1.4.9:DNS 字典爆破生成器。"""

    def test_generates_candidates_from_builtin(self):
        """内置词典(~220 词)生成 prefix.domain 候选。"""
        out = gt._generate_bruteforce_candidates('example.com')
        # 内置词典必然包含这几个高命中率前缀
        assert 'www.example.com' in out
        assert 'mail.example.com' in out
        assert 'api.example.com' in out
        assert 'admin.example.com' in out
        # 全是合法子域,且至少有 200 个(内置词典规模)
        assert len(out) >= 200
        for h in out:
            assert h.endswith('.example.com')

    def test_empty_domain_returns_empty(self):
        """空 domain 返空 set,不抛。"""
        assert gt._generate_bruteforce_candidates('') == set()
        assert gt._generate_bruteforce_candidates('   ') == set()

    def test_custom_wordlist_overrides_builtin(self, monkeypatch, tmp_path):
        """SPYEYES_DNS_WORDLIST=path 覆盖内置词典。"""
        wl = tmp_path / 'mywords.txt'
        wl.write_text('alpha\nbeta\n# this is comment\n\ngamma\n', encoding='utf-8')
        monkeypatch.setenv('SPYEYES_DNS_WORDLIST', str(wl))
        out = gt._generate_bruteforce_candidates('example.com')
        assert out == {'alpha.example.com', 'beta.example.com', 'gamma.example.com'}

    def test_custom_wordlist_missing_falls_back(self, monkeypatch):
        """指定的字典文件不存在时 silent fall back 到内置词典。"""
        monkeypatch.setenv('SPYEYES_DNS_WORDLIST', '/nonexistent/path/foo.txt')
        out = gt._generate_bruteforce_candidates('example.com')
        # 内置词典生效
        assert 'www.example.com' in out
        assert len(out) >= 200


class TestJsExtract:
    """v1.4.9:从 HTML/JS body 提取硬编码的子域名引用。"""

    def test_extracts_inline_script_references(self):
        body = (b'<html><body><script>'
                b"fetch('https://api.example.com/v1/users');"
                b"const cdn='https://cdn.example.com/lib.js';"
                b'</script></body></html>')
        out = gt._extract_hosts_from_body(body, 'example.com')
        assert 'api.example.com' in out
        assert 'cdn.example.com' in out

    def test_extracts_attribute_references(self):
        body = (b'<a href="//cdn.example.com/x">y</a>'
                b'<img src="https://images.example.com/p.png">'
                b'<link href="https://static.example.com/style.css">')
        out = gt._extract_hosts_from_body(body, 'example.com')
        assert {'cdn.example.com', 'images.example.com', 'static.example.com'} <= out

    def test_filters_cross_domain_references(self):
        body = (b'<a href="https://attacker.com/x">x</a>'
                b'<script>fetch("https://gtag.googletagmanager.com/")</script>'
                b'<img src="https://api.example.com/p.png">')
        out = gt._extract_hosts_from_body(body, 'example.com')
        assert out == {'api.example.com'}
        assert 'attacker.com' not in out
        assert 'gtag.googletagmanager.com' not in out

    def test_empty_or_missing_inputs(self):
        assert gt._extract_hosts_from_body(b'', 'example.com') == set()
        assert gt._extract_hosts_from_body(b'<html></html>', '') == set()

    def test_caps_at_5000_to_prevent_oom(self):
        """大量重复 host 引用不会爆内存。"""
        # 模拟一个有大量 hostname 的 body
        body = (b'api.example.com ' * 6000)
        out = gt._extract_hosts_from_body(body, 'example.com')
        # 去重后只应有一个
        assert out == {'api.example.com'}

    def test_certspotter_parses_dns_names(self):
        """v1.4.4: CertSpotter 替代 ThreatCrowd 死站。"""
        fake = MagicMock(status_code=200)
        fake.json.return_value = [
            {'dns_names': ['api.example.com', 'mail.example.com']},
            {'dns_names': ['admin.example.com', 'evil.com']},  # evil.com 跨域应过滤
        ]
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._src_certspotter('example.com')
        assert {'api.example.com', 'mail.example.com', 'admin.example.com'} <= out
        assert 'evil.com' not in out


class TestPassiveCollectSubdomains:
    """多源并发汇总:任何单源失败不影响整体。"""

    def test_all_sources_succeed(self, monkeypatch):
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'crtsh',
                            lambda d: {'api.example.com', 'mail.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'hackertarget',
                            lambda d: {'api.example.com', 'blog.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'otx', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'certspotter',
                            lambda d: {'cdn.example.com'})
        # v1.4.8:subfinder 也要 mock,否则装了 subfinder 的环境会跑真实查询
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'subfinder', lambda d: set())
        # v1.4.9:wayback 也要 mock,否则会真实查 web.archive.org
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'wayback', lambda d: set())
        result = gt.passive_collect_subdomains('example.com')
        assert result['candidates'] == {'api.example.com', 'mail.example.com',
                                         'blog.example.com', 'cdn.example.com'}
        assert result['sources']['crtsh'] == 2
        assert result['errors'] == {}

    def test_one_source_throws_does_not_break_others(self, monkeypatch):
        def boom(d):
            raise RuntimeError('source down')
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'crtsh', boom)
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'hackertarget',
                            lambda d: {'good.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'otx', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'certspotter', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'subfinder', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'wayback', lambda d: set())
        result = gt.passive_collect_subdomains('example.com')
        assert 'good.example.com' in result['candidates']
        assert result['errors'].get('crtsh') is True


class TestEnumerateSubdomains:
    """主流程 mock 测试 — 跳过真实网络。"""

    def test_invalid_domain_rejected(self):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        result = gt.enumerate_subdomains('http://bad/x')
        assert '_error' in result

    def test_full_flow(self, monkeypatch):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {'api.example.com', 'mail.example.com'},
            'sources': {'crtsh': 2, 'hackertarget': 0, 'otx': 0, 'certspotter': 0},
            'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)

        def fake_resolve(host, dns_timeout=3.0):
            return {'host': host, 'alive': True, 'a': ['1.2.3.4'],
                    'aaaa': [], 'cname': None}
        monkeypatch.setattr(gt, '_resolve_one_subdomain', fake_resolve)

        # v1.4.9:_probe_one_subdomain 加了 parent_domain 第 3 参数
        def fake_probe(host, timeout=5.0, parent_domain=None):
            return {'http_status': 200, 'title': 'Example', 'scheme': 'https',
                    'extracted_hosts': set()}
        monkeypatch.setattr(gt, '_probe_one_subdomain', fake_probe)

        result = gt.enumerate_subdomains('example.com', show_progress=False)
        assert result['domain'] == 'example.com'
        assert result['_stats']['total'] == 2
        assert result['_stats']['alive'] == 2
        assert result['_stats']['probed'] == 2
        assert all(s.get('http_status') == 200 for s in result['subdomains'])
        # 输出按字母序排序
        hosts = [s['host'] for s in result['subdomains']]
        assert hosts == sorted(hosts)

    def test_no_probe_skips_http(self, monkeypatch):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {'api.example.com'},
            'sources': {'crtsh': 1}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': True, 'a': ['1.2.3.4'], 'aaaa': [], 'cname': None
        })
        called = {'probe': 0}

        def fake_probe(host, timeout=5.0):
            called['probe'] += 1
            return {}
        monkeypatch.setattr(gt, '_probe_one_subdomain', fake_probe)

        result = gt.enumerate_subdomains('example.com', probe=False, show_progress=False)
        assert called['probe'] == 0, '--no-probe 时不应调 _probe_one_subdomain'
        assert result['_stats']['probed'] == 0

    def test_wildcard_flag_propagated(self, monkeypatch):
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': set(), 'sources': {'crtsh': 0}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: True)
        result = gt.enumerate_subdomains('example.com', show_progress=False)
        assert result['wildcard_suspect'] is True

    def test_max_results_truncation(self, monkeypatch):
        """超过 SUBDOMAIN_MAX_RESULTS 时只解析前 N 条,防 wildcard 域刷爆资源。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        # 临时调小 MAX 加快测试
        monkeypatch.setattr(gt, 'SUBDOMAIN_MAX_RESULTS', 3)
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {f'h{i}.example.com' for i in range(10)},
            'sources': {'crtsh': 10}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': False, 'a': [], 'aaaa': [], 'cname': None
        })
        result = gt.enumerate_subdomains('example.com', probe=False, show_progress=False)
        assert result['_stats']['total'] == 3

    def test_bruteforce_flag_injects_wordlist(self, monkeypatch):
        """v1.4.9:--bruteforce 时把字典 prefix 加入 candidates。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        # 被动源返空,bruteforce 必须独立贡献候选
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': set(), 'sources': {}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        # 用小 wordlist 替代内置 220 词,加速测试
        monkeypatch.setattr(gt, '_load_bruteforce_wordlist', lambda: ('foo', 'bar'))
        resolved_hosts = []
        def fake_resolve(host, dns_timeout=3.0):
            resolved_hosts.append(host)
            return {'host': host, 'alive': False, 'a': [], 'aaaa': [], 'cname': None}
        monkeypatch.setattr(gt, '_resolve_one_subdomain', fake_resolve)
        result = gt.enumerate_subdomains('example.com', probe=False,
                                          bruteforce=True, show_progress=False)
        # bruteforce 把 foo.example.com / bar.example.com 加进 candidates
        assert {'foo.example.com', 'bar.example.com'} <= set(resolved_hosts)
        assert result['_stats']['bruteforce_added'] == 2

    def test_bruteforce_off_by_default(self, monkeypatch):
        """默认 bruteforce=False,不引入字典候选。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {'api.example.com'}, 'sources': {'crtsh': 1}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        # 防止误调用 bruteforce 字典
        monkeypatch.setattr(gt, '_load_bruteforce_wordlist',
                            lambda: pytest.fail('bruteforce wordlist 不应被加载'))
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': False, 'a': [], 'aaaa': [], 'cname': None
        })
        result = gt.enumerate_subdomains('example.com', probe=False, show_progress=False)
        assert result['_stats']['bruteforce_added'] == 0

    def test_bruteforce_env_var_enables(self, monkeypatch):
        """SPYEYES_BRUTEFORCE=1 等价于 --bruteforce flag。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setenv('SPYEYES_BRUTEFORCE', '1')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': set(), 'sources': {}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_load_bruteforce_wordlist', lambda: ('test',))
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': False, 'a': [], 'aaaa': [], 'cname': None
        })
        result = gt.enumerate_subdomains('example.com', probe=False, show_progress=False)
        assert result['_stats']['bruteforce_added'] == 1

    def test_js_extract_finds_new_hosts(self, monkeypatch):
        """v1.4.9:js_extract=True 时从 probe body 抽 host,二轮 DNS 验证。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {'www.example.com'}, 'sources': {'crtsh': 1}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': True, 'a': ['1.2.3.4'], 'aaaa': [], 'cname': None
        })
        # probe www → 返发现 api.example.com / cdn.example.com
        # probe api / cdn → 返空(防递归)
        def fake_probe(host, timeout=5.0, parent_domain=None):
            extracted = set()
            if host == 'www.example.com' and parent_domain == 'example.com':
                extracted = {'api.example.com', 'cdn.example.com'}
            return {'http_status': 200, 'title': host, 'scheme': 'https',
                    'extracted_hosts': extracted}
        monkeypatch.setattr(gt, '_probe_one_subdomain', fake_probe)
        result = gt.enumerate_subdomains('example.com', show_progress=False)
        hosts = {s['host'] for s in result['subdomains']}
        # api / cdn 通过 JS 提取被发现并验证
        assert {'www.example.com', 'api.example.com', 'cdn.example.com'} <= hosts
        assert result['_stats']['js_extracted'] == 2

    def test_js_extract_disabled_with_flag(self, monkeypatch):
        """js_extract=False 时不传 parent_domain 给 probe,不做二轮。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr(gt, 'passive_collect_subdomains', lambda d, **kw: {
            'candidates': {'www.example.com'}, 'sources': {'crtsh': 1}, 'errors': {},
        })
        monkeypatch.setattr(gt, '_detect_wildcard_dns', lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_resolve_one_subdomain', lambda host, dns_timeout=3.0: {
            'host': host, 'alive': True, 'a': ['1.2.3.4'], 'aaaa': [], 'cname': None
        })
        captured = {'parent': 'unset'}
        def fake_probe(host, timeout=5.0, parent_domain=None):
            captured['parent'] = parent_domain
            return {'http_status': 200, 'title': host, 'scheme': 'https',
                    'extracted_hosts': set()}
        monkeypatch.setattr(gt, '_probe_one_subdomain', fake_probe)
        result = gt.enumerate_subdomains('example.com', js_extract=False,
                                          show_progress=False)
        # js_extract=False 时,parent_domain 显式传 None → probe 不触发提取
        assert captured['parent'] is None
        assert result['_stats']['js_extracted'] == 0


class TestSubdomainProbe:
    def test_probe_extracts_title(self):
        fake = MagicMock(status_code=200)
        fake.raw.read.return_value = b'<html><head><title>Example Site</title></head>'
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._probe_one_subdomain('api.example.com')
        assert out['http_status'] == 200
        assert out['title'] == 'Example Site'
        assert out['scheme'] == 'https'

    def test_probe_handles_unicode_title(self):
        fake = MagicMock(status_code=200)
        fake.raw.read.return_value = '<title>中文标题</title>'.encode('utf-8')
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._probe_one_subdomain('api.example.com')
        assert out['title'] == '中文标题'

    def test_probe_skips_title_for_4xx(self):
        fake = MagicMock(status_code=404)
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._probe_one_subdomain('api.example.com')
        assert out['http_status'] == 404
        assert out['title'] is None

    def test_probe_https_fail_falls_back_to_http(self):
        responses = [None]  # https 失败
        fake_http = MagicMock(status_code=200)
        fake_http.raw.read.return_value = b''
        responses.append(fake_http)

        def fake_get(url, **kwargs):
            return responses.pop(0)
        with patch.object(gt, 'safe_get', side_effect=fake_get):
            out = gt._probe_one_subdomain('api.example.com')
        assert out['scheme'] == 'http'
        assert out['http_status'] == 200

    def test_probe_total_failure_returns_empty_status(self):
        with patch.object(gt, 'safe_get', return_value=None):
            out = gt._probe_one_subdomain('api.example.com')
        assert out['http_status'] is None


class TestSubdomainCli:
    """CLI argparse + run_cli 路由。"""

    def test_subdomain_subcommand_parses(self):
        args = gt.build_parser().parse_args(['subdomain', 'example.com'])
        assert args.command == 'subdomain'
        assert args.domain == 'example.com'
        assert args.no_probe is False

    def test_no_probe_flag(self):
        args = gt.build_parser().parse_args(['subdomain', 'example.com', '--no-probe'])
        assert args.no_probe is True

    def test_alive_only_flag(self):
        args = gt.build_parser().parse_args(['subdomain', 'example.com', '--alive-only'])
        assert args.alive_only is True

    def test_workers_validation(self):
        with pytest.raises(SystemExit):
            gt.build_parser().parse_args(['subdomain', 'example.com', '--workers', '0'])

    def test_run_cli_subdomain_json(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        fake_result = {
            'domain': 'example.com',
            'sources': {'crtsh': 1},
            'wildcard_suspect': False,
            'subdomains': [{'host': 'api.example.com', 'alive': True,
                            'a': ['1.2.3.4'], 'aaaa': [], 'cname': None,
                            'http_status': 200, 'title': 'API', 'scheme': 'https'}],
            '_stats': {'total': 1, 'alive': 1, 'probed': 1, 'errors': {}},
        }
        monkeypatch.setattr(gt, 'enumerate_subdomains',
                            lambda *a, **kw: fake_result)
        import argparse
        args = argparse.Namespace(command='subdomain', domain='example.com',
                                   no_probe=False, workers=30, timeout=5.0,
                                   alive_only=False, json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data['domain'] == 'example.com'
        assert len(data['subdomains']) == 1


class TestSubdomainReports:
    """8 种报告生成器在 subdomain 数据上不崩 + 关键内容存在。"""

    @pytest.fixture
    def sample_data(self):
        return {
            'domain': 'example.com',
            'sources': {'crtsh': 2, 'otx': 1},
            'wildcard_suspect': False,
            'subdomains': [
                {'host': 'api.example.com', 'alive': True,
                 'a': ['1.2.3.4'], 'aaaa': [], 'cname': None,
                 'http_status': 200, 'title': 'API', 'scheme': 'https'},
                {'host': 'old.example.com', 'alive': False,
                 'a': [], 'aaaa': [], 'cname': None,
                 'http_status': None, 'title': None, 'scheme': None},
            ],
            '_stats': {'total': 2, 'alive': 1, 'probed': 1, 'errors': {}},
        }

    def test_markdown_renders_subdomain_table(self, sample_data):
        md = gt._to_markdown('subdomain_example.com', sample_data)
        assert 'api.example.com' in md
        assert 'old.example.com' in md
        # 命中行含 IP
        assert '1.2.3.4' in md
        # 含 markdown 表头
        assert '|' in md and '---' in md

    def test_html_renders_anchor_for_all_hosts(self, sample_data):
        """v1.4.6:所有 host(alive/dead)都可点击(用户期望直接尝试访问 dead 子域)。"""
        html = gt._to_html('subdomain_example.com', sample_data)
        assert 'api.example.com' in html
        # alive 子域 anchor
        assert 'href="https://api.example.com/"' in html
        # dead 子域也加 anchor(默认 https,用户可直接尝试)
        assert 'href="https://old.example.com/"' in html
        # alive/dead 用 data-alive 属性区分(CSS 左边框色调)
        assert 'data-alive="true"' in html
        assert 'data-alive="false"' in html

    def test_txt_renders(self, sample_data):
        txt = gt._to_txt('subdomain_example.com', sample_data)
        assert 'api.example.com' in txt
        assert 'old.example.com' in txt

    def test_csv_columns(self, sample_data):
        csv = gt._to_csv('subdomain_example.com', sample_data)
        # CSV 有 7 列
        first = csv.split('\n')[0]
        assert first.count(',') == 6
        assert 'api.example.com' in csv
        assert 'old.example.com' in csv

    def test_xmind_creates_file(self, sample_data, tmp_path):
        out = tmp_path / 'r.xmind'
        err = gt._to_xmind('subdomain_example.com', sample_data, str(out))
        assert err is None
        assert out.exists()
        # 验证是合法 zip
        import zipfile
        with zipfile.ZipFile(str(out)) as zf:
            assert 'content.xml' in zf.namelist()
            content = zf.read('content.xml').decode('utf-8')
            assert 'api.example.com' in content

    def test_graph_html_has_root_and_subs(self, sample_data):
        html = gt._to_graph_html('subdomain_example.com', sample_data)
        assert 'api.example.com' in html
        assert 'old.example.com' in html
        # alive 子域 url 字段存在(JSON 里)
        assert '"https://api.example.com/"' in html

    def test_wildcard_warning_in_reports(self, sample_data):
        sample_data['wildcard_suspect'] = True
        for fn in (gt._to_markdown, gt._to_html, gt._to_txt):
            out = fn('subdomain_example.com', sample_data)
            # 应含警告(中或英版本)
            assert 'wildcard' in out.lower() or '通配符' in out

    @pytest.mark.skipif(not gt.HAS_REPORTLAB, reason="reportlab not installed")
    def test_pdf_renders(self, sample_data, tmp_path):
        out = tmp_path / 'r.pdf'
        err = gt._to_pdf('subdomain_example.com', sample_data, str(out))
        assert err is None
        assert out.exists()
        assert out.read_bytes().startswith(b'%PDF')


class TestSubdomainHistoryRecord:
    def test_record_history_subdomain(self, tmp_path, monkeypatch):
        h = tmp_path / 'h.jsonl'
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(h))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        import argparse
        gt._record_history('subdomain',
                           argparse.Namespace(domain='example.com'),
                           {'_stats': {'total': 5, 'alive': 3},
                            'wildcard_suspect': False,
                            'subdomains': []})
        line = h.read_text(encoding='utf-8').strip()
        rec = json.loads(line)
        assert rec['cmd'] == 'subdomain'
        assert rec['query'] == 'example.com'
        assert rec['total'] == 5
        assert rec['alive'] == 3


class TestSubdomainI18nKeys:
    """i18n 完整性:新增 13 个 subdomain.* 与 menu.subdomain 键中英都齐。"""

    def test_subdomain_keys_exist_both_langs(self):
        new_keys = [
            'menu.subdomain', 'section.subdomain',
            'subdomain.title', 'subdomain.summary',
            'subdomain.wildcard_warn', 'subdomain.no_results',
            'subdomain.source_breakdown',
            'subdomain.alive_section', 'subdomain.dead_section',
            'subdomain.col_host', 'subdomain.col_ip', 'subdomain.col_cname',
            'subdomain.col_status', 'subdomain.col_title',
            'prompt.input_subdomain', 'prompt.subdomain_probe',
        ]
        for key in new_keys:
            assert key in gt.TRANSLATIONS['en'], f"Missing en: {key}"
            assert key in gt.TRANSLATIONS['zh'], f"Missing zh: {key}"


# ====================================================================
# v1.3.2: 电话运营商 MNP-aware (block-allocated disclaimer + 实时 HLR API)
# ====================================================================
class TestPhoneCarrierMNP:
    """v1.3.2: track_phone 输出 carrier_note 提示号段所属(MNP 不感知),
    可选实时 HLR API 查询补充准确数据。"""

    def test_carrier_note_present_by_default(self):
        """每次 track_phone 都应返回 carrier_note disclaimer 让用户理解局限。"""
        data = gt.track_phone('+8613800138000')
        assert '_error' not in data
        assert 'carrier_note' in data
        assert data['carrier_note']  # 非空
        # disclaimer 必含 MNP 概念(中或英)
        note = data['carrier_note'].lower()
        assert 'mnp' in note or '携号' in data['carrier_note'] or 'port' in note

    def test_carrier_note_localized(self):
        """carrier_note 跟随 UI 语言。"""
        gt.set_lang('en')
        en_data = gt.track_phone('+8613800138000')
        gt.set_lang('zh')
        zh_data = gt.track_phone('+8613800138000')
        assert en_data['carrier_note'] != zh_data['carrier_note']
        assert 'port' in en_data['carrier_note'].lower()
        assert '携号' in zh_data['carrier_note'] or '号段' in zh_data['carrier_note']

    def test_carrier_field_remains_block_carrier(self):
        """carrier 字段保留号段所属(向后兼容,只是标签变更)。"""
        data = gt.track_phone('+8613800138000')
        # 中国移动号段 13800 应仍报 China Mobile
        assert ('Mobile' in data['carrier'] or '移动' in data['carrier']
                or 'China' in data['carrier'])

    def test_realtime_hint_when_no_api_key(self, monkeypatch):
        """没设 SPYEYES_PHONE_API_KEY 时,carrier_realtime=None + 给出 hint。"""
        monkeypatch.delenv('SPYEYES_PHONE_API_KEY', raising=False)
        data = gt.track_phone('+8613800138000')
        assert data.get('carrier_realtime') is None
        assert data.get('carrier_realtime_hint')
        # hint 应提到 SPYEYES_PHONE_API_KEY env var
        assert 'SPYEYES_PHONE_API_KEY' in data['carrier_realtime_hint']

    def test_realtime_disabled_explicitly(self, monkeypatch):
        """lookup_realtime=False 时,即使 env 设了也不调用,且不出 hint。"""
        monkeypatch.setenv('SPYEYES_PHONE_API_KEY', 'numverify:fakekey')
        with patch.object(gt, '_resolve_phone_realtime') as mock_lookup:
            data = gt.track_phone('+8613800138000', lookup_realtime=False)
        assert mock_lookup.call_count == 0
        # 不该出现 carrier_realtime_* 字段
        assert 'carrier_realtime' not in data
        assert 'carrier_realtime_hint' not in data

    def test_realtime_success_via_env(self, monkeypatch):
        """env var 设了 numverify:key,假装 API 返回 'Jazztel',应进 carrier_realtime。
        注意:_resolve_phone_realtime 通过 _PHONE_PROVIDERS dict 查 fn,
        必须 monkeypatch.setitem(dict) 而非 patch.object(module, fn_name)。"""
        monkeypatch.setenv('SPYEYES_PHONE_API_KEY', 'numverify:fakekey')
        monkeypatch.setitem(gt._PHONE_PROVIDERS, 'numverify',
                            lambda e164, key: {'carrier': 'Jazztel'})
        data = gt.track_phone('+34600320351', default_region='ES')
        assert data.get('carrier_realtime') == 'Jazztel'
        assert 'carrier_realtime_error' not in data
        # 号段层仍是 Vodafone(phonenumbers 数据);realtime 给出真实运营商
        assert 'Vodafone' in data['carrier']

    def test_realtime_provider_failure_graceful(self, monkeypatch):
        """API 调用抛异常 → carrier_realtime=None + carrier_realtime_error 字段,主流程不受影响。"""
        monkeypatch.setenv('SPYEYES_PHONE_API_KEY', 'numverify:fakekey')

        def boom(e164, key):
            raise RuntimeError('rate limit exceeded')
        monkeypatch.setitem(gt._PHONE_PROVIDERS, 'numverify', boom)
        data = gt.track_phone('+8613800138000')
        assert '_error' not in data  # 主流程仍成功
        assert data.get('carrier_realtime') is None
        assert 'rate limit' in data.get('carrier_realtime_error', '')

    def test_realtime_unknown_provider(self, monkeypatch):
        """env 写错 provider → 优雅报错,不影响主流程。"""
        monkeypatch.setenv('SPYEYES_PHONE_API_KEY', 'unknownprovider:key')
        data = gt.track_phone('+8613800138000')
        assert '_error' not in data
        err = data.get('carrier_realtime_error', '')
        assert 'unsupported provider' in err or 'unknownprovider' in err

    def test_realtime_malformed_env(self, monkeypatch):
        """env 没冒号或缺 key/provider → 视为未配置(走 hint 分支)。"""
        for malformed in ('numverify', ':keyonly', 'numverify:', ''):
            monkeypatch.setenv('SPYEYES_PHONE_API_KEY', malformed)
            data = gt.track_phone('+8613800138000')
            assert data.get('carrier_realtime') is None
            assert data.get('carrier_realtime_hint'), \
                f'malformed {malformed!r} 应出 hint'


class TestNumverifyProvider:
    """numverify provider HTTP 行为单测(纯 mock)。"""

    def test_success_extracts_carrier(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {
            'success': True, 'valid': True,
            'carrier': 'Jazztel S.A.U.', 'country_code': 'ES',
        }
        with patch.object(gt, 'safe_get', return_value=fake):
            r = gt._phone_provider_numverify('+34600320351', 'fakekey')
        assert r['carrier'] == 'Jazztel S.A.U.'

    def test_strips_plus_in_url(self):
        captured = {}

        def fake_get(url, **kw):
            captured['url'] = url
            fake = MagicMock(status_code=200)
            fake.json.return_value = {'success': True, 'carrier': 'X'}
            return fake
        with patch.object(gt, 'safe_get', side_effect=fake_get):
            gt._phone_provider_numverify('+34600320351', 'KEY')
        # E.164 number 必须不带 + 进 numverify
        assert 'number=34600320351' in captured['url']
        assert 'access_key=KEY' in captured['url']

    def test_api_error_response(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {
            'success': False, 'error': {'type': 'invalid_access_key',
                                         'info': 'Bad key'}
        }
        with patch.object(gt, 'safe_get', return_value=fake):
            with pytest.raises(RuntimeError, match='Bad key|invalid'):
                gt._phone_provider_numverify('+34600320351', 'badkey')

    def test_http_failure(self):
        with patch.object(gt, 'safe_get', return_value=None):
            with pytest.raises(RuntimeError):
                gt._phone_provider_numverify('+34600320351', 'k')

    def test_http_500(self):
        fake = MagicMock(status_code=500)
        with patch.object(gt, 'safe_get', return_value=fake):
            with pytest.raises(RuntimeError, match='500'):
                gt._phone_provider_numverify('+34600320351', 'k')

    def test_non_json(self):
        fake = MagicMock(status_code=200)
        fake.json.side_effect = ValueError('not JSON')
        with patch.object(gt, 'safe_get', return_value=fake):
            with pytest.raises(RuntimeError, match='non-JSON'):
                gt._phone_provider_numverify('+34600320351', 'k')

    def test_empty_carrier_returns_none(self):
        """API 响应中 carrier 字段为空字符串 → 返回 None(不报错)。"""
        fake = MagicMock(status_code=200)
        fake.json.return_value = {'success': True, 'carrier': ''}
        with patch.object(gt, 'safe_get', return_value=fake):
            r = gt._phone_provider_numverify('+34600320351', 'k')
        assert r['carrier'] is None


class TestSubdomainStageProgress:
    """v1.3.3:子域名枚举各阶段反馈(消除"卡顿期"困惑)。
    由于 _stage_log 仅在 stderr.isatty() 时输出,这里 patch isatty=True 验证。"""

    def test_passive_collect_emits_per_source_lines(self, monkeypatch, capsys):
        """每个源完成后立即输出一行到 stderr。"""
        monkeypatch.setattr('sys.stderr.isatty', lambda: True)
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'crtsh',
                            lambda d: {'a.example.com', 'b.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'hackertarget', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'otx', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'certspotter', lambda d: set())
        gt.passive_collect_subdomains('example.com', show_progress=True)
        err = capsys.readouterr().err
        # 每个源都应该有一行(成功的显示候选数,空的显示 0)
        assert 'crtsh' in err
        assert 'hackertarget' in err
        assert 'otx' in err
        assert 'certspotter' in err  # v1.4.4: 替代 threatcrowd 死站
        # crtsh 应显示 2 个候选(数字)
        assert '2' in err

    def test_passive_collect_silent_when_progress_off(self, monkeypatch, capsys):
        """show_progress=False 时不写 stderr(测试场景需要)。"""
        monkeypatch.setattr('sys.stderr.isatty', lambda: True)
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'crtsh', lambda d: {'a.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'hackertarget', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'otx', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'certspotter', lambda d: set())
        gt.passive_collect_subdomains('example.com', show_progress=False)
        err = capsys.readouterr().err
        assert 'crtsh' not in err

    def test_passive_collect_errors_show_up(self, monkeypatch, capsys):
        """单源抛异常 → 在 stderr 显示 error 行 + 继续其它源。"""
        monkeypatch.setattr('sys.stderr.isatty', lambda: True)

        def boom(d):
            raise RuntimeError('rate limit')
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'crtsh', boom)
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'hackertarget',
                            lambda d: {'good.example.com'})
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'otx', lambda d: set())
        monkeypatch.setitem(gt.SUBDOMAIN_SOURCES, 'certspotter', lambda d: set())
        result = gt.passive_collect_subdomains('example.com', show_progress=True)
        err = capsys.readouterr().err
        assert 'crtsh' in err
        assert 'rate limit' in err
        # 主流程不受影响
        assert 'good.example.com' in result['candidates']

    def test_stage_log_silent_when_not_tty(self, monkeypatch, capsys):
        """stderr 不是 TTY(管道场景)时 _stage_log 静默 — 防污染 jq pipeline。"""
        monkeypatch.setattr('sys.stderr.isatty', lambda: False)
        gt._stage_log('this should not appear')
        err = capsys.readouterr().err
        assert 'this should not appear' not in err

    def test_enumerate_emits_all_4_stage_headers(self, monkeypatch, capsys):
        """enumerate_subdomains 跑完应输出 4 个 stage header。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr('sys.stderr.isatty', lambda: True)
        monkeypatch.setattr(gt, 'passive_collect_subdomains',
                            lambda d, show_progress=True: {
                                'candidates': {'api.example.com'},
                                'sources': {'crtsh': 1}, 'errors': {}})
        monkeypatch.setattr(gt, '_detect_wildcard_dns',
                            lambda d, dns_timeout=3.0: False)
        monkeypatch.setattr(gt, '_resolve_one_subdomain',
                            lambda h, dns_timeout=3.0: {
                                'host': h, 'alive': True, 'a': ['1.2.3.4'],
                                'aaaa': [], 'cname': None})
        monkeypatch.setattr(gt, '_probe_one_subdomain',
                            lambda h, timeout=5.0: {'http_status': 200,
                                                     'title': 't', 'scheme': 'https'})
        gt.enumerate_subdomains('example.com', show_progress=True)
        err = capsys.readouterr().err
        # 4 个 stage header 关键词:'1/4'..'4/4'
        for stage in ('1/4', '2/4', '3/4', '4/4'):
            assert stage in err, f'missing stage {stage} in: {err}'

    def test_enumerate_silent_when_progress_off(self, monkeypatch, capsys):
        """show_progress=False 时,enumerate_subdomains 不写任何 stage 反馈。"""
        if not gt.HAS_DNS:
            pytest.skip('dns 依赖未安装')
        monkeypatch.setattr('sys.stderr.isatty', lambda: True)
        monkeypatch.setattr(gt, 'passive_collect_subdomains',
                            lambda d, show_progress=True: {
                                'candidates': set(),
                                'sources': {'crtsh': 0}, 'errors': {}})
        monkeypatch.setattr(gt, '_detect_wildcard_dns',
                            lambda d, dns_timeout=3.0: False)
        gt.enumerate_subdomains('example.com', show_progress=False)
        err = capsys.readouterr().err
        for stage in ('1/4', '2/4', '3/4', '4/4'):
            assert stage not in err


class TestSubdomainStageI18n:
    """v1.3.3 stage 反馈 i18n 键完整性。"""

    def test_stage_keys_in_both_langs(self):
        keys = ['subdomain.stage_passive', 'subdomain.stage_wildcard',
                'subdomain.stage_dns', 'subdomain.stage_probe',
                'subdomain.source_done', 'subdomain.source_err',
                'subdomain.wildcard_yes', 'subdomain.wildcard_no']
        for k in keys:
            assert k in gt.TRANSLATIONS['en'], f"Missing en: {k}"
            assert k in gt.TRANSLATIONS['zh'], f"Missing zh: {k}"

    def test_stage_localized(self):
        gt.set_lang('en')
        en = gt.t('subdomain.stage_passive')
        gt.set_lang('zh')
        zh = gt.t('subdomain.stage_passive')
        assert en != zh
        assert 'Stage 1/4' in en
        assert '阶段 1/4' in zh


    pass  # marker


# ====================================================================
# v1.4.0: 域名邮箱枚举(多源 OSINT + 深度爬取 + 可选模式 + 可选 SMTP)
# ====================================================================
class TestEmailRelevance:
    """_is_email_relevant: 仅接受 target domain 或子域,排除 fake/示例域。"""

    def test_main_domain(self):
        assert gt._is_email_relevant('a@example.com', 'example.com') is True

    def test_subdomain(self):
        assert gt._is_email_relevant('admin@mail.example.com', 'example.com') is True

    def test_other_domain_rejected(self):
        assert gt._is_email_relevant('a@evil.com', 'example.com') is False

    def test_partial_match_rejected(self):
        """notexample.com 不应匹配 example.com。"""
        assert gt._is_email_relevant('a@notexample.com', 'example.com') is False

    def test_fake_example_filtered(self):
        """example.com 的 example.com 邮箱仍属合法,但 example.org 之类应被
        视为示例。这里我们直接限定排除常见示例 — 输入 example.com 时其它
        example.* 域的邮箱本来也不属于 example.com。"""
        assert gt._is_email_relevant('foo@yourdomain.com', 'example.com') is False

    def test_no_at_rejected(self):
        assert gt._is_email_relevant('not-an-email', 'example.com') is False

    def test_empty(self):
        assert gt._is_email_relevant('', 'example.com') is False


class TestEmailExtractFromText:
    def test_mailto_link(self):
        text = '<a href="mailto:contact@example.com">Email us</a>'
        out = gt._extract_emails_from_text(text, 'example.com')
        assert 'contact@example.com' in out

    def test_plain_text(self):
        text = 'Reach out to support@example.com or admin@example.com'
        out = gt._extract_emails_from_text(text, 'example.com')
        assert out == {'support@example.com', 'admin@example.com'}

    def test_filters_other_domains(self):
        text = 'Internal: x@example.com / External: x@gmail.com'
        out = gt._extract_emails_from_text(text, 'example.com')
        assert out == {'x@example.com'}

    def test_subdomain_emails_kept(self):
        text = 'Mail: ops@mail.example.com / Web: web@example.com'
        out = gt._extract_emails_from_text(text, 'example.com')
        assert 'ops@mail.example.com' in out
        assert 'web@example.com' in out

    def test_lookbehind_prevents_truncation(self):
        """正则 lookbehind 防 'abc@example.com' 被切成 'bc@example.com'。"""
        text = 'visit prefixabc@example.com today'  # 没有空格前缀
        out = gt._extract_emails_from_text(text, 'example.com')
        # 完整 'prefixabc@example.com' 而非裸 'abc@example.com'
        assert 'prefixabc@example.com' in out
        assert 'abc@example.com' not in out

    def test_empty_input(self):
        assert gt._extract_emails_from_text('', 'example.com') == set()
        assert gt._extract_emails_from_text(None, 'example.com') == set()


class TestEmailPatternGeneration:
    def test_single_name(self):
        out = gt._generate_email_patterns('John Doe', 'example.com')
        assert 'john.doe@example.com' in out
        assert 'jdoe@example.com' in out
        assert 'john@example.com' in out
        assert 'doe@example.com' in out
        assert 'jd@example.com' in out

    def test_multiple_names(self):
        out = gt._generate_email_patterns('John Doe, Jane Smith', 'example.com')
        assert any('john' in e for e in out)
        assert any('jane' in e for e in out)

    def test_empty_input(self):
        assert gt._generate_email_patterns('', 'example.com') == []
        assert gt._generate_email_patterns(None, 'example.com') == []

    def test_dedup(self):
        out = gt._generate_email_patterns('John Doe, John Doe', 'example.com')
        assert len(out) == len(set(out))

    def test_unicode(self):
        """中文姓名会被剥离非 word 字符,得到拼音前的字母名(可能空)。"""
        out = gt._generate_email_patterns('张 三', 'example.com')
        # 至少不抛异常
        assert isinstance(out, list)


class TestRobotsTxt:
    def test_extract_sitemap_and_disallow(self):
        fake = MagicMock(status_code=200, text=(
            "User-agent: *\n"
            "Disallow: /private/\n"
            "Disallow: /admin\n"
            "Sitemap: https://example.com/sitemap.xml\n"
        ))
        with patch.object(gt, 'safe_get', return_value=fake):
            sm, dis = gt._fetch_robots_txt('https', 'example.com')
        assert sm == {'https://example.com/sitemap.xml'}
        assert '/private/' in dis
        assert '/admin' in dis

    def test_404_returns_empty(self):
        fake = MagicMock(status_code=404)
        with patch.object(gt, 'safe_get', return_value=fake):
            sm, dis = gt._fetch_robots_txt('https', 'example.com')
        assert sm == set() and dis == []

    def test_disallow_match(self):
        assert gt._is_path_disallowed('https://example.com/admin/x',
                                       ['/admin']) is True
        assert gt._is_path_disallowed('https://example.com/public',
                                       ['/admin']) is False
        # '/' 全站禁
        assert gt._is_path_disallowed('https://example.com/anything',
                                       ['/']) is True


class TestSitemapParsing:
    def test_extract_locs(self):
        fake = MagicMock(status_code=200, text=(
            '<?xml version="1.0"?><urlset>'
            '<url><loc>https://example.com/page1</loc></url>'
            '<url><loc>https://example.com/page2</loc></url>'
            '<url><loc>https://evil.com/notmine</loc></url>'  # 跨域应被过滤
            '</urlset>'
        ))
        with patch.object(gt, 'safe_get', return_value=fake):
            urls = gt._fetch_sitemap_urls('https://example.com/sitemap.xml',
                                           'example.com')
        assert 'https://example.com/page1' in urls
        assert 'https://example.com/page2' in urls
        assert 'https://evil.com/notmine' not in urls


class TestEmailsFromCrtsh:
    def test_extracts_from_name_value(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = [
            {'name_value': 'admin@example.com\nfoo@example.com',
             'common_name': 'support@example.com'},
        ]
        with patch.object(gt, 'safe_get', return_value=fake):
            out = gt._emails_from_crtsh('example.com')
        assert {'admin@example.com', 'foo@example.com',
                'support@example.com'} <= out

    def test_handles_non_list(self):
        fake = MagicMock(status_code=200)
        fake.json.return_value = {}
        with patch.object(gt, 'safe_get', return_value=fake):
            assert gt._emails_from_crtsh('example.com') == set()


class TestEnumerateDomainEmails:
    """主入口集成测试 — mock 各组件验证流程编排正确。"""

    def test_invalid_domain_rejected(self):
        result = gt.enumerate_domain_emails('http://bad/x')
        assert '_error' in result

    def test_passive_only_no_crawl(self, monkeypatch):
        """crawl=False 时不调爬虫,只用 crtsh + WHOIS。"""
        monkeypatch.setattr(gt, '_emails_from_crtsh',
                            lambda d: {'a@example.com'})
        monkeypatch.setattr(gt, '_emails_from_whois',
                            lambda d: {'admin@example.com'})
        called = {'crawl': 0}

        def fake_crawl(*a, **kw):
            called['crawl'] += 1
            return {'emails': set(), 'page_map': {}, 'pages_crawled': 0,
                    'sitemap_found': False, 'robots_disallows': 0}
        monkeypatch.setattr(gt, '_crawl_domain_for_emails', fake_crawl)
        r = gt.enumerate_domain_emails('example.com', crawl=False,
                                        show_progress=False)
        assert called['crawl'] == 0
        addrs = {e['address'] for e in r['emails']}
        assert addrs == {'a@example.com', 'admin@example.com'}

    def test_full_flow_with_crawl(self, monkeypatch):
        monkeypatch.setattr(gt, '_emails_from_crtsh',
                            lambda d: {'a@example.com'})
        monkeypatch.setattr(gt, '_emails_from_whois',
                            lambda d: {'admin@example.com'})

        def fake_crawl(target, **kw):
            return {'emails': {'web@example.com'},
                    'page_map': {'web@example.com': 'https://example.com/'},
                    'pages_crawled': 5, 'sitemap_found': True,
                    'robots_disallows': 0}
        monkeypatch.setattr(gt, '_crawl_domain_for_emails', fake_crawl)
        # include_subdomains=False → 不调 enumerate_subdomains
        r = gt.enumerate_domain_emails('example.com', include_subdomains=False,
                                        show_progress=False)
        addrs = {e['address'] for e in r['emails']}
        assert {'a@example.com', 'admin@example.com', 'web@example.com'} <= addrs
        assert r['_stats']['pages_crawled'] == 5
        assert r['_stats']['sitemap_found'] is True

    def test_pattern_generation(self, monkeypatch):
        monkeypatch.setattr(gt, '_emails_from_crtsh', lambda d: set())
        monkeypatch.setattr(gt, '_emails_from_whois', lambda d: set())
        r = gt.enumerate_domain_emails('example.com', crawl=False,
                                        guess_names='John Doe',
                                        show_progress=False)
        addrs = {e['address'] for e in r['emails']}
        assert 'john.doe@example.com' in addrs
        # source 标记是 pattern
        for e in r['emails']:
            if e['address'] == 'john.doe@example.com':
                assert 'pattern' in e['sources']

    def test_smtp_verify_off_by_default(self, monkeypatch):
        monkeypatch.setattr(gt, '_emails_from_crtsh',
                            lambda d: {'a@example.com'})
        monkeypatch.setattr(gt, '_emails_from_whois', lambda d: set())
        with patch.object(gt, '_verify_smtp') as mock_verify:
            r = gt.enumerate_domain_emails('example.com', crawl=False,
                                            show_progress=False)
        assert mock_verify.call_count == 0
        # verified 字段都是 None
        assert all(e['verified'] is None for e in r['emails'])

    def test_smtp_verify_when_opted_in(self, monkeypatch):
        monkeypatch.setattr(gt, '_emails_from_crtsh',
                            lambda d: {'a@example.com', 'b@example.com'})
        monkeypatch.setattr(gt, '_emails_from_whois', lambda d: set())

        def fake_verify(em, **kw):
            return (em == 'a@example.com', 'mocked')
        monkeypatch.setattr(gt, '_verify_smtp', fake_verify)
        r = gt.enumerate_domain_emails('example.com', crawl=False,
                                        verify_smtp=True, show_progress=False)
        verified = [e for e in r['emails'] if e['verified'] is True]
        not_verified = [e for e in r['emails'] if e['verified'] is False]
        assert len(verified) == 1
        assert verified[0]['address'] == 'a@example.com'
        assert len(not_verified) == 1


class TestDomainEmailsCli:
    def test_subcommand_parses(self):
        args = gt.build_parser().parse_args(['domain-emails', 'example.com'])
        assert args.command == 'domain-emails'
        assert args.domain == 'example.com'
        assert args.no_crawl is False

    def test_all_flags(self):
        args = gt.build_parser().parse_args([
            'domain-emails', 'example.com',
            '--no-crawl', '--no-include-subdomains',
            '--max-pages', '100', '--crawl-depth', '3',
            '--ignore-robots', '--guess', 'John Doe',
            '--verify-smtp',
        ])
        assert args.no_crawl is True
        assert args.no_include_subdomains is True
        assert args.max_pages == 100
        assert args.crawl_depth == 3
        assert args.ignore_robots is True
        assert args.guess_names == 'John Doe'
        assert args.verify_smtp is True

    def test_run_cli(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))
        monkeypatch.setattr(gt, 'enumerate_domain_emails', lambda d, **kw: {
            'domain': 'example.com',
            'emails': [{'address': 'a@example.com', 'sources': ['crtsh'],
                        'page': None, 'verified': None, 'verify_reason': None}],
            '_stats': {'total': 1, 'by_source': {'crtsh': 1},
                       'pages_crawled': 0, 'sitemap_found': False, 'verified': 0},
        })
        import argparse
        args = argparse.Namespace(command='domain-emails', domain='example.com',
                                   no_crawl=True, no_include_subdomains=True,
                                   max_pages=100, crawl_depth=3,
                                   ignore_robots=False, guess_names=None,
                                   verify_smtp=False, json=True, save=None)
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data['domain'] == 'example.com'
        assert len(data['emails']) == 1


class TestDomainEmailsReports:
    """8 种报告生成器在 domain-emails 数据上不崩 + 关键内容存在。"""

    @pytest.fixture
    def sample(self):
        return {
            'domain': 'example.com',
            'emails': [
                {'address': 'admin@example.com', 'sources': ['whois'],
                 'page': None, 'verified': None, 'verify_reason': None},
                {'address': 'support@example.com', 'sources': ['crawl'],
                 'page': 'https://example.com/contact',
                 'verified': True, 'verify_reason': 'rcpt accepted'},
                {'address': 'john.doe@example.com', 'sources': ['pattern'],
                 'page': None, 'verified': False, 'verify_reason': 'rejected'},
            ],
            '_stats': {'total': 3, 'by_source': {'whois': 1, 'crawl': 1, 'pattern': 1},
                       'pages_crawled': 12, 'sitemap_found': True, 'verified': 1},
        }

    def test_markdown(self, sample):
        md = gt._to_markdown('domain-emails_example.com', sample)
        assert 'admin@example.com' in md
        assert 'support@example.com' in md
        assert 'john.doe@example.com' in md
        assert '|' in md  # table

    def test_html(self, sample):
        html = gt._to_html('domain-emails_example.com', sample)
        assert 'mailto:admin@example.com' in html
        assert 'support@example.com' in html

    def test_txt(self, sample):
        txt = gt._to_txt('domain-emails_example.com', sample)
        assert 'admin@example.com' in txt
        assert '[verified]' in txt or '[unverified]' in txt

    def test_csv(self, sample):
        csv = gt._to_csv('domain-emails_example.com', sample)
        first = csv.split('\n')[0]
        # 4 列
        assert first.count(',') == 3
        assert 'admin@example.com' in csv

    def test_xmind(self, sample, tmp_path):
        out = tmp_path / 'r.xmind'
        err = gt._to_xmind('domain-emails_example.com', sample, str(out))
        assert err is None
        assert out.exists()

    def test_graph(self, sample):
        html = gt._to_graph_html('domain-emails_example.com', sample)
        assert 'admin@example.com' in html
        assert 'mailto:' in html

    @pytest.mark.skipif(not gt.HAS_REPORTLAB, reason="reportlab not installed")
    def test_pdf(self, sample, tmp_path):
        out = tmp_path / 'r.pdf'
        err = gt._to_pdf('domain-emails_example.com', sample, str(out))
        assert err is None
        assert out.read_bytes().startswith(b'%PDF')


class TestDomainEmailsI18n:
    def test_keys_in_both_langs(self):
        keys = ['menu.domain_emails', 'section.demails',
                'demails.title', 'demails.summary', 'demails.no_results',
                'demails.col_address', 'demails.col_sources',
                'demails.col_page', 'demails.col_verified',
                'demails.stage_passive', 'demails.stage_subdomain',
                'demails.stage_crawl', 'demails.stage_guess',
                'demails.stage_smtp', 'demails.smtp_warn',
                'prompt.input_demails', 'prompt.demails_subdomains',
                'prompt.demails_guess', 'prompt.demails_verify']
        for k in keys:
            assert k in gt.TRANSLATIONS['en'], f'Missing en: {k}'
            assert k in gt.TRANSLATIONS['zh'], f'Missing zh: {k}'


class TestPhoneI18nKeys:
    """v1.3.2 新 i18n 键完整性。"""

    def test_keys_in_both_langs(self):
        keys = ['phone.mnp_note', 'phone.realtime_hint', 'phone.realtime_failed',
                'field.carrier_realtime']
        for k in keys:
            assert k in gt.TRANSLATIONS['en'], f"Missing en: {k}"
            assert k in gt.TRANSLATIONS['zh'], f"Missing zh: {k}"

    def test_carrier_label_now_block_aware(self):
        """field.carrier 标签现在含'block'/'号段'词,不再是裸'Carrier'。"""
        en = gt.TRANSLATIONS['en']['field.carrier']
        zh = gt.TRANSLATIONS['zh']['field.carrier']
        assert 'block' in en.lower(), f"en label not block-aware: {en}"
        assert '号段' in zh, f"zh label not block-aware: {zh}"
