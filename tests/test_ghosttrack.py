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
    def test_found(self):
        fake = MagicMock(status_code=200, content=b'<html>real profile</html>')
        with patch.object(gt, 'safe_get', return_value=fake):
            name, url = gt._check_username('GitHub', 'https://github.com/{}', 'user', 5)
        assert name == 'GitHub'
        assert url == 'https://github.com/user'

    def test_404(self):
        fake = MagicMock(status_code=404)
        with patch.object(gt, 'safe_get', return_value=fake):
            name, url = gt._check_username('GitHub', 'https://github.com/{}', 'x', 5)
        assert url is None

    def test_content_pattern_says_not_found(self):
        fake = MagicMock(status_code=200, content=b'<title>Page not found</title>')
        with patch.object(gt, 'safe_get', return_value=fake):
            name, url = gt._check_username('GitHub', 'https://github.com/{}', 'x', 5)
        assert url is None

    def test_network_error(self):
        with patch.object(gt, 'safe_get', return_value=None):
            name, url = gt._check_username('Foo', 'https://x.com/{}', 'u', 5)
        assert url is None


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
