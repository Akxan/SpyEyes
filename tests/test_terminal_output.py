"""SpyEyes 终端输出 / 交互菜单 / 语言解析 / run_cli 非 JSON 路径的测试。

约定:
- 颜色统一关掉,断言直接比对纯文本;
- 所有核心查询函数默认换成「一调用就失败」的替身,用例再按需换成会记录参数的假函数;
- input() 由 feed 喂答案:多问一次当场失败,少问一次在用例结束时失败。

运行：
    pytest tests/test_terminal_output.py -q
"""

import json
import os
import re
import sys
import time

import pytest

# 让 tests/ 能 import 上层 spyeyes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402


# ------------------------------------------------------------------
# 公共替身与工具
# ------------------------------------------------------------------
CORE_QUERIES = (
    'track_ip', 'show_my_ip', 'track_phone', 'track_username', 'recursive_track_username',
    'whois_lookup', 'mx_lookup', 'email_validate', 'enumerate_subdomains',
    'enumerate_domain_emails', 'do_investigate', 'run_upgrade',
)

# 「快速」模式 = 全部类别去掉 other(写死,不从 CATEGORY_ORDER 推导,否则断言等于照抄实现)
QUICK_CATEGORIES = ['code', 'social', 'forum', 'video', 'music', 'writing', 'art',
                    'gaming', 'funding', 'chinese', 'spanish', 'adult']


class Recorder:
    """记录调用参数的假函数。result 是固定返回值,或按参数算返回值的 callable。"""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.result(*args, **kwargs) if callable(self.result) else self.result


def _bomb(name):
    def _fail(*args, **kwargs):
        raise AssertionError(f'{name} 不应被调用(用例没有替换它)')
    return _fail


@pytest.fixture(autouse=True)
def _isolated_terminal(monkeypatch, tmp_path):
    gt.Color.disable()
    monkeypatch.setattr(time, 'sleep', lambda *_a, **_k: None)
    # 真实实现会在仓库根目录 / 家目录下建 Downloads 目录
    monkeypatch.setattr(gt, '_default_report_dir', lambda: str(tmp_path / 'reports'))
    for name in CORE_QUERIES:
        monkeypatch.setattr(gt, name, _bomb(name))


@pytest.fixture
def fake(monkeypatch):
    """fake('track_ip', 返回值) → 把 gt.track_ip 换成 Recorder 并返回它。"""
    def _install(name, result):
        rec = Recorder(result)
        monkeypatch.setattr(gt, name, rec)
        return rec
    return _install


@pytest.fixture
def feed(monkeypatch):
    """feed('a', '', EOFError) → 依次喂给 input();返回的列表记下每次的提示语。"""
    pending: list = []
    prompts: list = []

    def fake_input(prompt=''):
        prompts.append(prompt)
        if not pending:
            raise AssertionError(f'多调用了一次 input(): {prompt!r}')
        answer = pending.pop(0)
        if isinstance(answer, type) and issubclass(answer, BaseException):
            raise answer()
        return answer

    def _feed(*answers):
        pending[:] = answers
        del prompts[:]
        return prompts

    monkeypatch.setattr('builtins.input', fake_input)
    yield _feed
    assert not pending, f'还有 {len(pending)} 个答案没被 input() 用掉(少问了问题): {pending}'


def fields(out):
    """把 print_field 打出的 `标签 : 值` 行解析成 {标签: 值}。"""
    parsed = {}
    for line in out.splitlines():
        label, sep, value = line.partition(' :')
        if sep:
            parsed[label.strip()] = value.strip()
    return parsed


def line_with(out, needle):
    hits = [line for line in out.splitlines() if needle in line]
    assert len(hits) == 1, f'期望恰好一行包含 {needle!r},实际 {len(hits)} 行:\n{out}'
    return hits[0]


def block(out, header):
    """取出含 header 的那一行到下一个空行之间的输出(一个分节)。"""
    lines = out.splitlines()
    starts = [i for i, line in enumerate(lines) if header in line]
    assert len(starts) == 1, f'期望恰好一个分节标题包含 {header!r},实际 {len(starts)} 个:\n{out}'
    seg = []
    for line in lines[starts[0]:]:
        if not line.strip():
            break
        seg.append(line)
    return seg


def cli(*argv):
    return gt.build_parser().parse_args(list(argv))


def saved_json(directory):
    """目录里应该恰好有一份报告;返回 (文件名, 解析后的 JSON)。"""
    names = sorted(os.listdir(directory))
    assert len(names) == 1, names
    with open(os.path.join(directory, names[0]), encoding='utf-8') as f:
        return names[0], json.load(f)


# ------------------------------------------------------------------
# 样例数据
# ------------------------------------------------------------------
def ip_data(**over):
    data = {
        'ip': '8.8.8.8', 'success': True, 'type': 'IPv4',
        'continent': 'North America', 'country': 'United States', 'country_code': 'US',
        'region': 'California', 'city': 'Mountain View',
        'latitude': 37.386, 'longitude': -122.0838,
        'is_eu': False, 'postal': '94039', 'calling_code': '1', 'capital': 'Washington D.C.',
        'flag': {'emoji': '🇺🇸'},
        'connection': {'asn': 15169, 'org': 'Google LLC', 'isp': 'Google Fiber', 'domain': 'google.com'},
        'timezone': {'id': 'America/Los_Angeles', 'abbr': 'PDT', 'utc': '-07:00'},
    }
    data.update(over)
    return data


def phone_data(**over):
    data = {
        'location': '北京市', 'region_code': 'CN', 'timezones': 'Asia/Shanghai',
        'carrier': '中国移动',
        'is_valid': False, 'is_possible': True,
        'international': '+86 138 0013 8000', 'mobile_dial': '138 0013 8000',
        'national': 13800138000, 'e164': '+8613800138000', 'country_code': 86,
        'number_type': '手机',
    }
    data.update(over)
    return data


def whois_data(**over):
    data = {
        'domain': 'EXAMPLE.COM', 'registrar': 'Example Registrar, Inc.',
        'creation_date': '1995-08-14 04:00:00', 'expiration_date': '2027-08-13 04:00:00',
        'updated_date': '2026-08-14 07:01:34',
        'name_servers': ['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET'],
        'status': 'clientTransferProhibited',
        'emails': ['abuse@example.com', 'admin@example.com'],
        'org': 'Internet Assigned Numbers Authority', 'country': 'US',
    }
    data.update(over)
    return data


def mx_data():
    return {'domain': 'example.com',
            'records': [{'preference': 10, 'exchange': 'mx1.example.com'},
                        {'preference': 5, 'exchange': 'mx2.example.com'}]}


def email_data(**over):
    data = {'email': 'a@example.com', 'syntax_valid': True, 'domain': 'example.com',
            'mx_valid': True, 'mx_records': [{'preference': 10, 'exchange': 'mx1.example.com'}]}
    data.update(over)
    return data


def demails_data():
    return {
        'domain': 'example.com',
        'emails': [
            {'address': 'ceo@example.com', 'sources': ['crtsh', 'whois'], 'page': None, 'verified': True},
            {'address': 'sales@example.com', 'sources': ['crawl'],
             'page': 'https://example.com/contact', 'verified': False,
             'verify_reason': '550-5.1.1-user-unknown-in-virtual-mailbox-table'},
            {'address': 'john.doe@example.com', 'sources': ['pattern'], 'page': None, 'verified': None},
            {'address': 'jane@example.com', 'sources': ['bing', 'pattern'], 'page': None, 'verified': None},
        ],
        '_stats': {'total': 4, 'pages_crawled': 12, 'sitemap_found': True, 'verified': 1,
                   'by_source': {'crtsh': 1, 'whois': 1, 'crawl': 1, 'pattern': 2, 'bing': 1}},
    }


def subdomain_data(**over):
    data = {
        'domain': 'example.com',
        'sources': {'crtsh': 3, 'otx': 0, 'wayback': 0, 'hackertarget': 2},
        'wildcard_suspect': False,
        'subdomains': [
            {'host': 'www.example.com', 'alive': True, 'a': ['93.184.216.34'], 'aaaa': ['2606:2800::1'],
             'cname': None, 'http_status': 200, 'title': 'Example Domain'},
            {'host': 'api.example.com', 'alive': True, 'a': [], 'aaaa': [],
             'cname': 'edge.cdn.net', 'http_status': 403, 'title': None},
            {'host': 'vpn.example.com', 'alive': True, 'a': ['10.0.0.1'], 'aaaa': [],
             'cname': None, 'http_status': None, 'title': None},
            {'host': 'old.example.com', 'alive': False, 'a': [], 'aaaa': [],
             'cname': None, 'http_status': None, 'title': None},
        ],
        '_stats': {'total': 4, 'alive': 3, 'probed': 3, 'errors': {'wayback': 'timeout'}},
    }
    data.update(over)
    return data


def diff_data():
    return {
        'domain': 'example.com',
        'added': [{'host': 'new.example.com', 'a': ['1.1.1.1'], 'aaaa': [], 'http_status': 200},
                  {'host': 'v6.example.com', 'a': [], 'aaaa': ['2001:db8::1'], 'http_status': None}],
        'removed': [{'host': 'gone.example.com', 'a': ['2.2.2.2'], 'aaaa': []}],
        'changed': [{'host': 'api.example.com',
                     'changes': {'http_status': {'before': 200, 'after': 503},
                                 'title': {'before': 'API', 'after': None}}}],
        '_stats': {'added': 2, 'removed': 1, 'changed': 1, 'unchanged': 7},
    }


def investigate_data():
    return {
        'entity_type': 'domain', 'target': 'example.com', 'depth': 1, 'elapsed': 12.34,
        'tasks': {
            'whois': {'registrar': 'Example Registrar', 'creation_date': '1995-08-14',
                      'name_servers': ['a.ns.example', 'b.ns.example'], 'emails': 'abuse@example.com'},
            'mx': {'domain': 'example.com', 'records': [{'preference': 10, 'exchange': 'mx1.example.com'}]},
            'subdomain': {
                'subdomains': [
                    {'host': 'www.example.com', 'alive': True, 'a': ['93.184.216.34'], 'aaaa': []},
                    {'host': 'cdn.example.com', 'alive': True, 'a': [], 'aaaa': [], 'cname': 'edge.cdn.net'},
                    {'host': 'old.example.com', 'alive': False, 'a': [], 'aaaa': []},
                ],
                '_stats': {'total': 3, 'alive': 2},
            },
            'emails': {'emails': [{'address': 'john.doe@example.com', 'sources': ['crawl', 'github']}],
                       '_stats': {'total': 1, 'pages_crawled': 8}},
        },
        'pivots': {
            'ips': {'93.184.216.34': {'country': 'United States', 'connection': {'org': 'Edgecast Inc.'}},
                    '10.0.0.1': {'_error': 'reserved range'}},
            'users': {
                'john.doe@example.com': {'local_part': 'john.doe',
                                         'result': {'GitHub': 'https://github.com/john.doe',
                                                    'GitLab': None, '_statuses': {'GitHub': 'found'}}},
                'bob@example.com': {'local_part': 'bob', '_error': 'scan blew up'},
            },
        },
        '_stats': {'tasks_done': 4, 'tasks_failed': 0, 'pivots_done': 2, 'pivots_skipped': 2,
                   'truncated': {'ips': 0, 'emails': 0}, 'budget_exceeded': False},
    }


# 用户名扫描:自定义一份小平台表,覆盖三档置信度 + 各种未命中状态
PLATFORMS = [
    gt.Platform('StrictSite', 'https://strict.test/{}', 'code', (), (b'profile',)),      # must_contain → ★★★
    gt.Platform('NfSite', 'https://nf.test/{}', 'code', (b'not found',)),                # not_found → ★★
    gt.Platform('PlainSite', 'https://plain.test/{}', 'code'),                           # 仅 HTTP 200 → ★
    gt.Platform('MissCode', 'https://misscode.test/{}', 'code', (b'nope',), (b'profile',)),
    gt.Platform('WafSite', 'https://waf.test/{}', 'social'),
    gt.Platform('UnvSite', 'https://unv.test/{}', 'social'),
    gt.Platform('SkipSite', 'https://skip.test/{}', 'social'),
    gt.Platform('NetSite', 'https://net.test/{}', 'social'),
    gt.Platform('MissSite', 'https://miss.test/{}', 'forum'),
]


@pytest.fixture
def platforms(monkeypatch):
    monkeypatch.setattr(gt, '_PLATFORMS_CACHE', list(PLATFORMS))


def username_results():
    return {
        'StrictSite': 'https://strict.test/alice',
        'NfSite': 'https://nf.test/alice',
        'PlainSite': 'https://plain.test/alice',
        'MissCode': None, 'WafSite': None, 'UnvSite': None,
        'SkipSite': None, 'NetSite': None, 'MissSite': None,
        '_statuses': {
            'StrictSite': gt.STATUS_FOUND, 'NfSite': gt.STATUS_FOUND, 'PlainSite': gt.STATUS_FOUND,
            'MissCode': gt.STATUS_NOT_FOUND, 'WafSite': gt.STATUS_WAF,
            'UnvSite': gt.STATUS_UNVERIFIABLE, 'SkipSite': gt.STATUS_INVALID_USERNAME,
            'NetSite': gt.STATUS_NETWORK_ERROR, 'MissSite': gt.STATUS_NOT_FOUND,
        },
    }


def col(text, width):
    """左对齐补空格到 width 列(等价于源码里的 f'{text:{width}}')。"""
    return text.ljust(width)


def hit_line(badge, name, url):
    return f' [ + ] {badge} {col(name, 28)} {url}'


def miss_line(badge, name, note):
    return f' [ - ] {badge} {col(name, 28)} {note}'


# ==================================================================
# 一、终端打印函数
# ==================================================================
class TestPrintIpInfo:
    def test_all_fields_zh(self, capsys):
        gt.print_ip_info('8.8.8.8', ip_data())
        out = capsys.readouterr().out
        assert ' ============= IP 地址信息 =============' in out.splitlines()
        assert fields(out) == {
            '目标 IP': '8.8.8.8', 'IP 类型': 'IPv4', '国家': '美国 (United States)', '国家代码': 'US',
            '城市': 'Mountain View', '大洲': 'North America', '地区': 'California',
            '纬度': '37.386', '经度': '-122.0838',
            '谷歌地图': 'https://www.google.com/maps/@37.386,-122.0838,8z',
            '是否欧盟': 'False', '邮编': '94039', '国际区号': '1', '首都': 'Washington D.C.',
            '国旗': '🇺🇸', 'ASN': '15169', '组织': 'Google LLC', 'ISP': 'Google Fiber',
            '域名': 'google.com', '时区 ID': 'America/Los_Angeles', '时区缩写': 'PDT', 'UTC 偏移': '-07:00',
        }

    def test_all_fields_en(self, capsys):
        gt.set_lang('en')
        gt.print_ip_info('8.8.8.8', ip_data())
        out = capsys.readouterr().out
        assert ' ============= IP Address Info =============' in out.splitlines()
        assert fields(out) == {
            'Target IP': '8.8.8.8', 'IP Type': 'IPv4', 'Country': 'United States', 'Country Code': 'US',
            'City': 'Mountain View', 'Continent': 'North America', 'Region': 'California',
            'Latitude': '37.386', 'Longitude': '-122.0838',
            'Google Maps': 'https://www.google.com/maps/@37.386,-122.0838,8z',
            'Is EU': 'False', 'Postal': '94039', 'Calling Code': '1', 'Capital': 'Washington D.C.',
            'Flag': '🇺🇸', 'ASN': '15169', 'Organization': 'Google LLC', 'ISP': 'Google Fiber',
            'Domain': 'google.com', 'Timezone ID': 'America/Los_Angeles', 'Timezone Abbr': 'PDT',
            'UTC Offset': '-07:00',
        }

    @pytest.mark.parametrize('lang, expected', [('zh', '查询失败：Invalid IP address'),
                                                ('en', 'Query failed: Invalid IP address')])
    def test_error_prints_only_the_message(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_ip_info('999.1.1.1', {'_error': 'Invalid IP address'})
        out = capsys.readouterr().out
        assert line_with(out, 'Invalid IP address') == f' {expected}'
        assert fields(out) == {}          # 出错时一个字段都不该打
        assert '999.1.1.1' not in out

    def test_empty_response_prints_blank_values_and_no_map(self, capsys):
        gt.print_ip_info('1.1.1.1', {})
        parsed = fields(capsys.readouterr().out)
        assert parsed['目标 IP'] == '1.1.1.1'
        assert '谷歌地图' not in parsed
        assert len(parsed) == 21
        assert {v for k, v in parsed.items() if k != '目标 IP'} == {''}

    def test_none_sub_objects_do_not_crash(self, capsys):
        gt.print_ip_info('1.1.1.1', ip_data(flag=None, connection=None, timezone=None))
        parsed = fields(capsys.readouterr().out)
        assert parsed['国旗'] == '' and parsed['ASN'] == '' and parsed['时区 ID'] == ''
        assert parsed['城市'] == 'Mountain View'   # 其余字段照常

    @pytest.mark.parametrize('lat, lon', [(None, 1.0), (1.0, None), ('abc', 1.0), (1.0, 'n/a')])
    def test_unusable_coordinates_skip_map_link(self, capsys, lat, lon):
        gt.print_ip_info('1.1.1.1', ip_data(latitude=lat, longitude=lon))
        out = capsys.readouterr().out
        assert 'google.com/maps' not in out
        assert fields(out)['是否欧盟'] == 'False'   # 地图行之后的字段没被跳过

    def test_numeric_string_coordinates_still_get_a_map_link(self, capsys):
        gt.print_ip_info('1.1.1.1', ip_data(latitude='-33.5', longitude='151'))
        assert fields(capsys.readouterr().out)['谷歌地图'] == 'https://www.google.com/maps/@-33.5,151.0,8z'

    def test_country_without_chinese_name_falls_back_to_english(self, capsys):
        gt.print_ip_info('1.1.1.1', ip_data(country='Atlantis', country_code='ZZ'))
        assert fields(capsys.readouterr().out)['国家'] == 'Atlantis'

    def test_missing_country_shows_unknown_in_english(self, capsys):
        gt.set_lang('en')
        data = ip_data()
        del data['country']
        gt.print_ip_info('1.1.1.1', data)
        assert fields(capsys.readouterr().out)['Country'] == '(unknown)'


class TestPrintMyIp:
    @pytest.mark.parametrize('lang, header, line', [
        ('zh', ' ========== 本机 IP 信息 ==========', ' [ + ] 你的 IP 地址 : 203.0.113.7'),
        ('en', ' ========== My IP Info ==========', ' [ + ] Your IP address : 203.0.113.7'),
    ])
    def test_shows_ip(self, capsys, lang, header, line):
        gt.set_lang(lang)
        gt.print_my_ip('203.0.113.7')
        lines = capsys.readouterr().out.splitlines()
        assert header in lines and line in lines
        assert lines[-1] == ' =========================================='

    @pytest.mark.parametrize('lang, message, ok_label', [
        ('zh', ' 查询失败，请检查网络', '你的 IP 地址'),
        ('en', ' Query failed, please check network', 'Your IP address'),
    ])
    def test_none_reports_network_failure(self, capsys, lang, message, ok_label):
        gt.set_lang(lang)
        gt.print_my_ip(None)
        out = capsys.readouterr().out
        assert message in out.splitlines()
        assert ok_label not in out and 'None' not in out


class TestPrintPhoneInfo:
    def test_all_fields_zh(self, capsys):
        gt.print_phone_info(phone_data())
        out = capsys.readouterr().out
        assert ' ========== 电话号码信息 ==========' in out.splitlines()
        assert fields(out) == {
            '归属地': '北京市', '地区代码': 'CN', '时区': 'Asia/Shanghai', '运营商(号段所属)': '中国移动',
            '是否有效号码': 'False', '是否可能号码': 'True',
            '国际格式': '+86 138 0013 8000', '移动拨号格式': '138 0013 8000',
            '原始号码': '13800138000', 'E.164 格式': '+8613800138000', '国家代码': '86', '号码类型': '手机',
        }
        assert '↳' not in out             # 没有备注 / 实时信息时不打子条

    def test_all_fields_en(self, capsys):
        gt.set_lang('en')
        gt.print_phone_info(phone_data(location='Beijing', carrier='China Mobile', number_type='Mobile'))
        out = capsys.readouterr().out
        assert ' ========== Phone Number Info ==========' in out.splitlines()
        assert fields(out) == {
            'Location': 'Beijing', 'Region Code': 'CN', 'Timezone': 'Asia/Shanghai',
            'Carrier (block-allocated)': 'China Mobile',
            'Valid Number': 'False', 'Possible Number': 'True',
            'International Format': '+86 138 0013 8000', 'Mobile Dial Format': '138 0013 8000',
            'Original Number': '13800138000', 'E.164 Format': '+8613800138000',
            'Country Code': '86', 'Number Type': 'Mobile',
        }

    def test_error_prints_message_without_fields(self, capsys):
        gt.print_phone_info({'_error': '无法解析号码'})
        out = capsys.readouterr().out
        assert ' 无法解析号码' in out.splitlines()
        assert fields(out) == {}

    def test_carrier_note_follows_the_carrier_line(self, capsys):
        gt.print_phone_info(phone_data(carrier_note='携号转网后可能不准'))
        lines = capsys.readouterr().out.splitlines()
        carrier_at = next(i for i, line in enumerate(lines) if '运营商(号段所属)' in line)
        assert lines[carrier_at + 1] == '     ↳ 携号转网后可能不准'

    def test_realtime_carrier_gets_its_own_field(self, capsys):
        gt.print_phone_info(phone_data(carrier_realtime='中国联通',
                                       carrier_realtime_error='不该出现的错误',
                                       carrier_realtime_hint='不该出现的提示'))
        out = capsys.readouterr().out
        assert fields(out)['运营商(实时 HLR)'] == '中国联通'
        assert fields(out)['运营商(号段所属)'] == '中国移动'
        assert '不该出现' not in out

    def test_realtime_error_wins_over_hint(self, capsys):
        gt.print_phone_info(phone_data(carrier_realtime=None,
                                       carrier_realtime_error='实时查询失败',
                                       carrier_realtime_hint='可配置 API key'))
        out = capsys.readouterr().out
        assert '     ↳ 实时查询失败' in out.splitlines()
        assert '可配置 API key' not in out
        assert '运营商(实时 HLR)' not in out

    def test_realtime_hint_shown_when_not_configured(self, capsys):
        gt.print_phone_info(phone_data(carrier_realtime=None, carrier_realtime_hint='可配置 API key'))
        out = capsys.readouterr().out
        assert '     ↳ 可配置 API key' in out.splitlines()
        assert '运营商(实时 HLR)' not in out


class TestPrintUsernameResults:
    NOTE_ZH = (' [ 提示 ] 1 个被拦截(WAF / 限流)  ·  1 个无法确认(该站对任何用户名都显示存在)'
               '  ·  1 个跳过(格式不符)  ·  1 个网络错误')
    NOTE_EN = (' [ note ] 1 blocked (WAF / rate limit)  ·  1 unverifiable (site says "exists" for any name)'
               '  ·  1 skipped (regex)  ·  1 network errors')

    def test_default_view_lists_only_hits_zh(self, capsys, platforms):
        gt.print_username_results(username_results())
        lines = capsys.readouterr().out.splitlines()
        assert ' ========== 用户名扫描结果 ==========' in lines
        assert ' 共扫描 9 个平台，命中 3 个：' in lines
        assert self.NOTE_ZH in lines
        assert ' （仅显示命中；用 --all 查看未命中）' in lines
        # 只有「代码与开发」有命中;类别内按可信度从高到低
        assert [line for line in lines if '┌─' in line] == [' ┌─ 代码与开发 (3/4) ─']
        assert [line for line in lines if line.startswith((' [ + ]', ' [ - ]'))] == [
            hit_line('★★★', 'StrictSite', 'https://strict.test/alice'),
            hit_line('★★', 'NfSite', 'https://nf.test/alice'),
            hit_line('★  ', 'PlainSite', 'https://plain.test/alice'),
        ]

    def test_default_view_en(self, capsys, platforms):
        gt.set_lang('en')
        gt.print_username_results(username_results())
        lines = capsys.readouterr().out.splitlines()
        assert ' ========== Username Scan Results ==========' in lines
        assert ' Scanned 9 platforms, found 3:' in lines
        assert self.NOTE_EN in lines
        assert ' (showing only matches; use --all to see misses)' in lines
        assert [line for line in lines if '┌─' in line] == [' ┌─ Code & Dev (3/4) ─']

    def test_show_all_lists_every_category_in_order(self, capsys, platforms):
        gt.print_username_results(username_results(), show_all=True)
        out = capsys.readouterr().out
        assert '--all' not in out                      # 已经是 --all 了,不再提示
        assert [line for line in out.splitlines() if '┌─' in line] == [
            ' ┌─ 代码与开发 (3/4) ─', ' ┌─ 社交网络 (0/4) ─', ' ┌─ 论坛社区 (0/1) ─']
        # 命中在前(可信度降序),未命中在后
        assert block(out, '代码与开发')[1:] == [
            hit_line('★★★', 'StrictSite', 'https://strict.test/alice'),
            hit_line('★★', 'NfSite', 'https://nf.test/alice'),
            hit_line('★  ', 'PlainSite', 'https://plain.test/alice'),
            miss_line('★★★', 'MissCode', '未找到'),
        ]
        assert block(out, '论坛社区')[1:] == [miss_line('★  ', 'MissSite', '未找到')]

    @pytest.mark.parametrize('lang, tags', [
        ('zh', {'WafSite': '[ 被拦截 ]', 'UnvSite': '[ 无法确认 ]', 'SkipSite': '[ 已跳过 ]'}),
        ('en', {'WafSite': '[ blocked ]', 'UnvSite': '[ unverifiable ]', 'SkipSite': '[ skipped ]'}),
    ])
    def test_show_all_tags_inconclusive_platforms(self, capsys, platforms, lang, tags):
        gt.set_lang(lang)
        gt.print_username_results(username_results(), show_all=True)
        out = capsys.readouterr().out
        for name, tag in tags.items():
            assert line_with(out, name) == miss_line('★  ', name, tag)

    def test_show_all_does_not_report_network_errors_as_not_found(self, capsys, platforms):
        gt.print_username_results(username_results(), show_all=True)
        assert '未找到' not in line_with(capsys.readouterr().out, 'NetSite')

    @pytest.mark.parametrize('status, note', [
        (gt.STATUS_WAF, '2 个被拦截(WAF / 限流)'),
        (gt.STATUS_UNVERIFIABLE, '2 个无法确认(该站对任何用户名都显示存在)'),
        (gt.STATUS_INVALID_USERNAME, '2 个跳过(格式不符)'),
        (gt.STATUS_NETWORK_ERROR, '2 个网络错误'),
    ])
    def test_summary_note_counts_each_status(self, capsys, platforms, status, note):
        results = {'WafSite': None, 'UnvSite': None, 'MissSite': None,
                   '_statuses': {'WafSite': status, 'UnvSite': status, 'MissSite': gt.STATUS_NOT_FOUND}}
        gt.print_username_results(results)
        assert f' [ 提示 ] {note}' in capsys.readouterr().out.splitlines()

    def test_no_note_line_when_everything_is_conclusive(self, capsys, platforms):
        results = {'StrictSite': 'https://strict.test/alice', 'MissSite': None,
                   '_statuses': {'StrictSite': gt.STATUS_FOUND, 'MissSite': gt.STATUS_NOT_FOUND}}
        gt.print_username_results(results)
        out = capsys.readouterr().out
        assert '提示' not in out
        assert ' 共扫描 2 个平台，命中 1 个：' in out.splitlines()

    def test_results_without_statuses_show_misses_as_not_found(self, capsys, platforms):
        gt.print_username_results({'WafSite': None, 'StrictSite': None}, show_all=True)
        out = capsys.readouterr().out
        assert '提示' not in out
        assert line_with(out, 'WafSite') == miss_line('★  ', 'WafSite', '未找到')
        assert block(out, '代码与开发')[0] == ' ┌─ 代码与开发 (0/1) ─'

    def test_no_hits_prints_summary_but_no_category(self, capsys, platforms):
        gt.print_username_results({'StrictSite': None, 'MissSite': None})
        out = capsys.readouterr().out
        assert ' 共扫描 2 个平台，命中 0 个：' in out.splitlines()
        assert '┌─' not in out and 'StrictSite' not in out

    def test_empty_results(self, capsys, platforms):
        gt.print_username_results({})
        out = capsys.readouterr().out
        assert ' 共扫描 0 个平台，命中 0 个：' in out.splitlines()
        assert '┌─' not in out

    @pytest.mark.parametrize('lang, expected', [('zh', ' 查询失败：用户名过长'), ('en', ' Query failed: 用户名过长')])
    def test_error(self, capsys, platforms, lang, expected):
        gt.set_lang(lang)
        gt.print_username_results({'_error': '用户名过长'}, show_all=True)
        out = capsys.readouterr().out
        assert expected in out.splitlines()
        assert '┌─' not in out and '共扫描' not in out and 'Scanned' not in out

    def test_recursive_metadata_is_not_counted_as_a_platform(self, capsys, platforms):
        results = {'StrictSite': 'https://strict.test/alice',
                   '_recursive': {'levels': [], 'total_found': 1}}
        gt.print_username_results(results)
        assert ' 共扫描 1 个平台，命中 1 个：' in capsys.readouterr().out.splitlines()


class TestPrintRecursiveSummary:
    REC = {'levels': [{'depth': 0, 'username': 'alice', 'found': 3},
                      {'depth': 1, 'username': 'alice_dev', 'found': 1},
                      {'depth': 2, 'username': 'bad name', 'found': 0, 'error': '输入非法'}],
           'total_found': 4}

    def test_levels_and_total_zh(self, capsys):
        gt._print_recursive_summary(self.REC)
        lines = [line for line in capsys.readouterr().out.splitlines() if line]
        assert lines == [
            ' ━━━ 递归扫描总结 ━━━',
            '  [depth 0] alice  →  命中 3 个',
            '  [depth 1] alice_dev  →  命中 1 个',
            '  [depth 2] bad name: 输入非法',
            ' 递归扫描结束。共 4 个平台，3 层。',
        ]

    def test_levels_and_total_en(self, capsys):
        gt.set_lang('en')
        gt._print_recursive_summary(self.REC)
        lines = [line for line in capsys.readouterr().out.splitlines() if line]
        assert lines[0] == ' ━━━ Recursive scan summary ━━━'
        assert lines[1] == '  [depth 0] alice  →  3 hits'
        assert lines[-1] == ' Recursive scan finished. Total: 4 platforms across 3 levels.'

    @pytest.mark.parametrize('rec', [{}, {'levels': []}, {'levels': None, 'total_found': 9}])
    def test_no_levels_prints_nothing(self, capsys, rec):
        gt._print_recursive_summary(rec)
        assert capsys.readouterr().out == ''

    def test_missing_fields_default_to_zero(self, capsys):
        gt._print_recursive_summary({'levels': [{}]})
        lines = [line for line in capsys.readouterr().out.splitlines() if line]
        assert lines[1] == '  [depth 0]   →  命中 0 个'
        assert lines[2] == ' 递归扫描结束。共 0 个平台，1 层。'


class TestPrintWhois:
    def test_all_fields_zh(self, capsys):
        gt.print_whois(whois_data())
        out = capsys.readouterr().out
        assert ' ========== WHOIS 查询 ==========' in out.splitlines()
        assert fields(out) == {
            '域名': 'EXAMPLE.COM', '注册商': 'Example Registrar, Inc.',
            '创建日期': '1995-08-14 04:00:00', '到期日期': '2027-08-13 04:00:00',
            '更新日期': '2026-08-14 07:01:34',
            'DNS 服务器': 'A.IANA-SERVERS.NET, B.IANA-SERVERS.NET',
            '状态': 'clientTransferProhibited', '邮箱': 'abuse@example.com, admin@example.com',
            '注册组织': 'Internet Assigned Numbers Authority', '国家': 'US',
        }

    def test_all_fields_en(self, capsys):
        gt.set_lang('en')
        gt.print_whois(whois_data())
        out = capsys.readouterr().out
        assert ' ========== WHOIS Lookup ==========' in out.splitlines()
        assert fields(out) == {
            'Domain': 'EXAMPLE.COM', 'Registrar': 'Example Registrar, Inc.',
            'Created': '1995-08-14 04:00:00', 'Expires': '2027-08-13 04:00:00',
            'Updated': '2026-08-14 07:01:34',
            'Name Servers': 'A.IANA-SERVERS.NET, B.IANA-SERVERS.NET',
            'Status': 'clientTransferProhibited', 'Emails': 'abuse@example.com, admin@example.com',
            'Organization': 'Internet Assigned Numbers Authority', 'Country': 'US',
        }

    @pytest.mark.parametrize('lang, placeholder', [('zh', '(无)'), ('en', '(none)')])
    def test_missing_and_none_values_use_placeholder(self, capsys, lang, placeholder):
        gt.set_lang(lang)
        gt.print_whois({'domain': 'example.com', 'registrar': None})
        parsed = fields(capsys.readouterr().out)
        assert len(parsed) == 10
        assert [v for v in parsed.values() if v != placeholder] == ['example.com']
        assert 'None' not in parsed.values()

    def test_tuple_values_are_joined(self, capsys):
        gt.print_whois(whois_data(domain=('EXAMPLE.COM', 'example.com'), status=('ok', 'locked')))
        parsed = fields(capsys.readouterr().out)
        assert parsed['域名'] == 'EXAMPLE.COM, example.com'
        assert parsed['状态'] == 'ok, locked'

    def test_error(self, capsys):
        gt.print_whois({'_error': 'WHOIS 查询失败：timed out'})
        out = capsys.readouterr().out
        assert ' WHOIS 查询失败：timed out' in out.splitlines()
        assert '注册商' not in out


class TestPrintMx:
    @pytest.mark.parametrize('lang, header, domain_label, priority', [
        ('zh', ' ========== MX 记录 ==========', '域名', '优先级'),
        ('en', ' ========== MX Records ==========', 'Domain', 'Priority'),
    ])
    def test_records_in_given_order(self, capsys, lang, header, domain_label, priority):
        gt.set_lang(lang)
        gt.print_mx(mx_data())
        out = capsys.readouterr().out
        assert header in out.splitlines()
        assert fields(out) == {domain_label: 'example.com'}
        assert [line for line in out.splitlines() if '→' in line] == [
            f'  {priority}   10  →  mx1.example.com',
            f'  {priority}    5  →  mx2.example.com',
        ]

    def test_no_records(self, capsys):
        gt.print_mx({'domain': 'example.com', 'records': []})
        out = capsys.readouterr().out
        assert fields(out) == {'域名': 'example.com'}
        assert '→' not in out

    def test_error(self, capsys):
        gt.print_mx({'_error': '域名不存在', '_error_kind': 'nxdomain'})
        out = capsys.readouterr().out
        assert ' 域名不存在' in out.splitlines()
        assert 'nxdomain' not in out and '→' not in out


class TestPrintEmail:
    def test_valid_with_mx_zh(self, capsys):
        gt.print_email(email_data())
        out = capsys.readouterr().out
        assert ' ========== 邮箱有效性 ==========' in out.splitlines()
        assert fields(out) == {'邮箱': 'a@example.com', '格式合法': 'True',
                               '域名': 'example.com', 'MX 有效': 'True'}
        assert '   → 优先级   10  mx1.example.com' in out.splitlines()

    def test_valid_with_mx_en(self, capsys):
        gt.set_lang('en')
        gt.print_email(email_data())
        out = capsys.readouterr().out
        assert ' ========== Email Validity ==========' in out.splitlines()
        assert fields(out) == {'Email': 'a@example.com', 'Format valid': 'True',
                               'Domain': 'example.com', 'MX valid': 'True'}
        assert '   → Priority   10  mx1.example.com' in out.splitlines()

    def test_bad_syntax_stops_after_the_error(self, capsys):
        gt.print_email({'email': 'not-an-email', 'syntax_valid': False, '_error': '邮箱格式不合法'})
        out = capsys.readouterr().out
        assert fields(out) == {'邮箱': 'not-an-email', '格式合法': 'False'}
        assert ' 邮箱格式不合法' in out.splitlines()

    def test_mx_failure_shows_friendly_message_not_the_enum(self, capsys):
        gt.print_email(email_data(mx_valid=False, mx_records=None, mx_error='nxdomain',
                                  mx_error_msg='域名不存在'))
        out = capsys.readouterr().out
        assert fields(out)['MX 有效'] == 'False'
        assert ' 域名不存在' in out.splitlines()
        assert 'nxdomain' not in out and '→' not in out

    def test_mx_failure_falls_back_to_enum_when_no_message(self, capsys):
        gt.print_email({'email': 'a@example.com', 'syntax_valid': True, 'domain': 'example.com',
                        'mx_valid': False, 'mx_error': 'no_mx'})
        assert ' no_mx' in capsys.readouterr().out.splitlines()


class TestPrintDomainEmails:
    def test_groups_and_summary_zh(self, capsys):
        gt.print_domain_emails(demails_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== 域名邮箱枚举 ==========' in lines
        assert ' 域名邮箱:example.com' in lines
        assert ' 共找到 4 个邮箱(爬取 12 页 · sitemap:✓)' in lines
        assert ' bing=1, crawl=1, crtsh=1, pattern=2, whois=1' in lines
        passive = block(out, '来自被动数据源')
        crawl = block(out, '来自深度爬取')
        pattern = block(out, '来自模式生成')
        assert passive[0] == ' ┌─ 来自被动数据源(crt.sh / WHOIS / 搜索引擎 / Wayback / GitHub) (2) ─'
        assert crawl[0] == ' ┌─ 来自深度爬取 (1) ─'
        assert pattern[0] == ' ┌─ 来自模式生成(未验证的猜测) (1) ─'
        # 被搜索引擎佐证过的模式邮箱(jane)归到被动源,而不是「未验证的猜测」
        assert [line.split()[3] for line in passive[1:]] == ['ceo@example.com', 'jane@example.com']
        assert [line.split()[3] for line in pattern[1:]] == ['john.doe@example.com']
        assert passive[1] == f" [ + ] {col('ceo@example.com', 45)} (crtsh,whois) [✓ 已验证]"
        assert passive[2] == f" [ + ] {col('jane@example.com', 45)} (bing,pattern)"
        # 验证失败:原因截断到 30 个字符;后面跟首次出现的页面
        assert crawl[1] == (f" [ + ] {col('sales@example.com', 45)} (crawl)"
                            ' [✗ 550-5.1.1-user-unknown-in-virt]  https://example.com/contact')

    def test_groups_and_summary_en(self, capsys):
        gt.set_lang('en')
        gt.print_domain_emails(demails_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== Domain Email Enumeration ==========' in lines
        assert ' Domain emails: example.com' in lines
        assert ' 4 emails found (12 pages crawled · sitemap: ✓)' in lines
        assert block(out, 'From passive sources')[0] == (
            ' ┌─ From passive sources (crt.sh / WHOIS / search engines / Wayback / GitHub) (2) ─')
        assert block(out, 'From deep crawl')[0] == ' ┌─ From deep crawl (1) ─'
        assert block(out, 'From pattern generation')[0] == ' ┌─ From pattern generation (UNVERIFIED guesses) (1) ─'
        assert line_with(out, 'ceo@example.com').endswith('[✓ verified]')

    @pytest.mark.parametrize('lang, expected', [('zh', ' 未发现邮箱'), ('en', ' No emails found')])
    def test_no_emails(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_domain_emails({'domain': 'example.com', 'emails': [],
                                '_stats': {'total': 0, 'pages_crawled': 3, 'sitemap_found': False}})
        out = capsys.readouterr().out
        assert expected in out.splitlines()
        assert '┌─' not in out
        assert 'sitemap:✗' in out or 'sitemap: ✗' in out

    def test_missing_stats_and_emails_default_to_zero(self, capsys):
        gt.print_domain_emails({'domain': 'example.com', 'emails': None, '_stats': None})
        lines = capsys.readouterr().out.splitlines()
        assert ' 共找到 0 个邮箱(爬取 0 页 · sitemap:✗)' in lines
        assert ' 未发现邮箱' in lines

    def test_only_non_empty_groups_are_printed(self, capsys):
        data = demails_data()
        data['emails'] = [e for e in data['emails'] if e['sources'] == ['crawl']]
        gt.print_domain_emails(data)
        out = capsys.readouterr().out
        assert [line for line in out.splitlines() if '┌─' in line] == [' ┌─ 来自深度爬取 (1) ─']

    def test_long_page_url_is_truncated_to_60_chars(self, capsys):
        url = 'https://example.com/' + 'a' * 100
        gt.print_domain_emails({'domain': 'example.com', '_stats': {'total': 1},
                                'emails': [{'address': 'x@example.com', 'sources': ['crawl'], 'page': url}]})
        line = line_with(capsys.readouterr().out, 'x@example.com')
        assert line.endswith('  ' + url[:60])

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' 页数预算已用完:另有 3 个子域未爬(调大 --max-pages 可纳入)'),
        ('en', ' Page budget reached: 3 more subdomain(s) not crawled (raise --max-pages to include them)'),
    ])
    def test_reports_targets_skipped_by_page_budget(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_domain_emails({'domain': 'example.com', 'emails': [],
                                '_stats': {'total': 0, 'pages_crawled': 200, 'targets_skipped': 3}})
        assert expected in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('pages, robots_skipped, shown', [(0, 5, True), (0, 0, False), (7, 5, False)])
    def test_robots_notice_only_when_nothing_was_crawled(self, capsys, pages, robots_skipped, shown):
        gt.print_domain_emails({'domain': 'example.com', 'emails': [],
                                '_stats': {'total': 0, 'pages_crawled': pages,
                                           'robots_skipped': robots_skipped}})
        out = capsys.readouterr().out
        assert ('robots.txt 禁止爬取' in out) is shown

    def test_error(self, capsys):
        gt.print_domain_emails({'_error': '域名非法', 'emails': [{'address': 'x@example.com'}]})
        out = capsys.readouterr().out
        assert ' 查询失败：域名非法' in out.splitlines()
        assert 'x@example.com' not in out and '共找到' not in out


class TestPrintSubdomainDiff:
    def test_three_groups_zh(self, capsys):
        gt.print_subdomain_diff(diff_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== 子域名 Diff ==========' in lines
        assert ' 子域名 diff:example.com' in lines
        assert ' 新增 2 个 · 消失 1 个 · 变更 1 个 · 不变 7 个' in lines
        assert block(out, '新增子域') == [
            ' + 新增子域 (2 个)',
            f"   + {col('new.example.com', 45)} {col('1.1.1.1', 20)} HTTP 200",
            f"   + {col('v6.example.com', 45)} {col('2001:db8::1', 20)} ",
        ]
        assert block(out, '消失子域') == [
            ' - 消失子域 (1 个)',
            f"   - {col('gone.example.com', 45)} {col('2.2.2.2', 20)}",
        ]
        assert block(out, '变更子域') == [
            ' ~ 变更子域 (1 个)',
            f"   ~ {col('api.example.com', 45)} 变更字段: http_status, title",
            '     http_status: 200 → 503',
            '     title: API → None',
        ]
        assert '无变化' not in out

    def test_three_groups_en(self, capsys):
        gt.set_lang('en')
        gt.print_subdomain_diff(diff_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== Subdomain Diff ==========' in lines
        assert ' Subdomain diff: example.com' in lines
        assert ' Added 2 · Removed 1 · Changed 1 · Unchanged 7' in lines
        assert ' + Added subdomains (2)' in lines
        assert ' - Removed subdomains (1)' in lines
        assert ' ~ Changed subdomains (1)' in lines
        assert line_with(out, 'api.example.com').endswith('changed fields: http_status, title')

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' 无变化 — 两次扫描完全一致'),
        ('en', ' No changes detected — both scans are identical'),
    ])
    def test_no_changes(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_subdomain_diff({'domain': 'example.com', 'added': [], 'removed': None, 'changed': [],
                                 '_stats': {'added': 0, 'removed': 0, 'changed': 0, 'unchanged': 5}})
        out = capsys.readouterr().out
        assert expected in out.splitlines()
        assert '+ ' not in out and '~ ' not in out

    def test_host_without_ip_shows_dash(self, capsys):
        gt.print_subdomain_diff({'domain': 'example.com', 'added': [{'host': 'x.example.com'}],
                                 'removed': [{'host': 'y.example.com', 'a': None, 'aaaa': None}],
                                 '_stats': {'added': 1, 'removed': 1}})
        out = capsys.readouterr().out
        assert line_with(out, 'x.example.com') == f"   + {col('x.example.com', 45)} {col('-', 20)} "
        assert line_with(out, 'y.example.com') == f"   - {col('y.example.com', 45)} {col('-', 20)}"

    def test_error_prints_only_the_message(self, capsys):
        gt.print_subdomain_diff({'_error': '输入无效', 'added': [{'host': 'x.example.com'}]})
        out = capsys.readouterr().out
        assert [line for line in out.splitlines() if line] == [' 输入无效']


class TestPrintSubdomains:
    def test_alive_and_dead_sections_zh(self, capsys):
        gt.print_subdomains(subdomain_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== 子域名枚举 ==========' in lines
        assert ' 子域名枚举：example.com' in lines
        # 「来自 N 个数据源」只数有产出的源(crtsh、hackertarget)
        assert ' 共发现 4 个 · 活跃 3 个 · 来自 2 个数据源' in lines
        assert ' 数据源：✓ crtsh: 3  ✓ hackertarget: 2  ○ otx: 0  ✗ wayback (错误)' in lines
        assert '通配符' not in out
        assert block(out, '活跃子域') == [
            ' ┌─ 活跃子域 (3) ─',
            f" [ + ] {col('www.example.com', 40)} {col('93.184.216.34, 2606:2800::1', 30)}  HTTP 200  Example Domain",
            f" [ + ] {col('api.example.com', 40)} {col('edge.cdn.net', 30)}  HTTP 403",
            f" [ + ] {col('vpn.example.com', 40)} {col('10.0.0.1', 30)}  HTTP -",
        ]
        assert block(out, '不可达') == [' ┌─ 不可达 / 未解析子域 (1) ─', ' [ - ] old.example.com']

    def test_alive_and_dead_sections_en(self, capsys):
        gt.set_lang('en')
        gt.print_subdomains(subdomain_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== Subdomain Enumeration ==========' in lines
        assert ' Subdomain enumeration: example.com' in lines
        assert ' 4 discovered · 3 alive · 2 sources' in lines
        assert ' Sources: ✓ crtsh: 3  ✓ hackertarget: 2  ○ otx: 0  ✗ wayback (error)' in lines
        assert ' ┌─ Alive subdomains (3) ─' in lines
        assert ' ┌─ Dead / unresolved subdomains (1) ─' in lines

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' ⚠ 检测到通配符 DNS — 结果可信度降低'),
        ('en', ' ⚠ Wildcard DNS detected — results may be unreliable'),
    ])
    def test_wildcard_warning(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_subdomains(subdomain_data(wildcard_suspect=True))
        assert expected in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' 未发现子域名（所有数据源为空或触发限速）'),
        ('en', ' No subdomains discovered (all sources empty or rate-limited)'),
    ])
    def test_no_results(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_subdomains({'domain': 'example.com', 'subdomains': [], 'sources': {'crtsh': 0},
                             '_stats': {'total': 0, 'alive': 0}})
        out = capsys.readouterr().out
        assert expected in out.splitlines()
        assert '┌─' not in out
        assert '○ crtsh: 0' in out            # 源都返回 0 时也要让用户看到查过哪些源

    def test_missing_keys_default_to_zero_and_hide_breakdown(self, capsys):
        gt.print_subdomains({'domain': 'example.com', 'subdomains': None, 'sources': None, '_stats': None})
        out = capsys.readouterr().out
        assert ' 共发现 0 个 · 活跃 0 个 · 来自 0 个数据源' in out.splitlines()
        assert '数据源：' not in out

    def test_only_dead_hosts_skip_the_alive_section(self, capsys):
        gt.print_subdomains({'domain': 'example.com', '_stats': {'total': 1, 'alive': 0},
                             'subdomains': [{'host': 'old.example.com', 'alive': False}]})
        out = capsys.readouterr().out
        assert [line for line in out.splitlines() if '┌─' in line] == [' ┌─ 不可达 / 未解析子域 (1) ─']

    def test_alive_host_with_no_address_shows_question_mark(self, capsys):
        gt.print_subdomains({'domain': 'example.com', '_stats': {'total': 1, 'alive': 1},
                             'subdomains': [{'host': 'odd.example.com', 'alive': True}]})
        assert line_with(capsys.readouterr().out, 'odd.example.com') == (
            f" [ + ] {col('odd.example.com', 40)} {col('?', 30)}  HTTP -")

    def test_long_title_is_truncated_to_60_chars(self, capsys):
        title = 'T' * 80
        gt.print_subdomains({'domain': 'example.com', '_stats': {'total': 1, 'alive': 1},
                             'subdomains': [{'host': 'www.example.com', 'alive': True, 'a': ['1.1.1.1'],
                                             'http_status': 200, 'title': title}]})
        assert line_with(capsys.readouterr().out, 'www.example.com').endswith('HTTP 200  ' + 'T' * 60)

    def test_error(self, capsys):
        gt.print_subdomains({'_error': '域名非法', 'subdomains': [{'host': 'x.example.com', 'alive': True}]})
        out = capsys.readouterr().out
        assert ' 查询失败：域名非法' in out.splitlines()
        assert 'x.example.com' not in out and '共发现' not in out


class TestPrintInvestigate:
    SECTIONS_ZH = ['I. WHOIS 注册信息', 'II. MX 邮件服务器', 'III. 子域名枚举',
                   'IV. IP 富化 (子域 → IP)', 'V. 域名邮箱', 'VI. 用户名足迹 (邮箱 → 平台)']
    SECTIONS_EN = ['I. WHOIS Registration', 'II. MX (Mail Servers)', 'III. Subdomain Enumeration',
                   'IV. IP Enrichment (subdomain → IP)', 'V. Domain Emails',
                   'VI. Username Footprint (email → platforms)']

    def test_full_report_zh(self, capsys):
        gt.print_investigate(investigate_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== 综合调查 ==========' in lines
        assert ' 综合调查报告: example.com' in lines
        assert ' 任务: 4 成功 · 0 失败 · 接力: 2 完成 · 耗时: 12.34s' in lines
        assert '预算' not in out and '截断' not in out
        assert [line for line in lines if '┌─' in line] == [f' ┌─ {s} ─' for s in self.SECTIONS_ZH]
        assert block(out, 'I. WHOIS')[1:] == [
            '   注册商: Example Registrar', '   创建日期: 1995-08-14',
            '   DNS 服务器: a.ns.example, b.ns.example', '   邮箱: abuse@example.com']
        assert block(out, 'II. MX')[1:] == ['   [ + ]   10  mx1.example.com']
        assert block(out, 'III. ')[1:] == [
            '   2 个活子域 / 3 个候选',
            f"   [ + ] {col('www.example.com', 35)} 93.184.216.34",
            f"   [ + ] {col('cdn.example.com', 35)} edge.cdn.net",
        ]
        assert block(out, 'IV. ')[1:] == [
            f"   [ + ] {col('93.184.216.34', 18)} {col('United States', 15)} Edgecast Inc.",
            '   ✗ 10.0.0.1: reserved range',
        ]
        assert block(out, '─ V. ')[1:] == [
            '   抓取到 1 个邮箱 (共爬取 8 页)',
            f"   [ + ] {col('john.doe@example.com', 45)} (crawl,github)",
        ]
        # 只列命中的平台:GitLab=None 与内部的 _statuses 都不该出现
        assert block(out, 'VI. ')[1:] == [
            f"   [ + ] {col('john.doe@example.com', 35)} (john.doe) → 命中 1 个",
            '     GitHub: https://github.com/john.doe',
            '   ✗ bob@example.com (bob): scan blew up',
        ]

    def test_full_report_en(self, capsys):
        gt.set_lang('en')
        gt.print_investigate(investigate_data())
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' ========== Comprehensive Investigation ==========' in lines
        assert ' Investigation Report for example.com' in lines
        assert ' Tasks: 4 done · 0 failed · Pivots: 2 done · Elapsed: 12.34s' in lines
        assert [line for line in lines if '┌─' in line] == [f' ┌─ {s} ─' for s in self.SECTIONS_EN]
        assert '   2 alive / 3 total' in lines
        assert '   1 emails harvested across 8 pages' in lines
        assert line_with(out, '(john.doe)').endswith('→ 1 hits')
        assert '   Registrar: Example Registrar' in lines

    def test_each_failed_task_is_marked_in_its_own_section(self, capsys):
        data = investigate_data()
        data['tasks'] = {'whois': {'_error': 'whois-down'}, 'mx': {'_error': 'mx-down'},
                         'subdomain': {'_error': 'sub-down'}, 'emails': {'_error': 'mail-down'}}
        data['pivots'] = {'ips': {}, 'users': {}}
        gt.print_investigate(data)
        out = capsys.readouterr().out
        assert block(out, 'I. WHOIS')[1:] == ['   ✗ whois-down']
        assert block(out, 'II. MX')[1:] == ['   ✗ mx-down']
        assert block(out, 'III. ')[1:] == ['   ✗ sub-down']
        assert block(out, 'IV. ')[1:] == ['   (无数据)']
        assert block(out, '─ V. ')[1:] == ['   ✗ mail-down']
        assert block(out, 'VI. ')[1:] == ['   (无数据)']

    def test_empty_report_still_prints_all_six_sections(self, capsys):
        gt.set_lang('en')
        gt.print_investigate({'target': 'example.com', 'tasks': None, 'pivots': None, '_stats': None})
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' Tasks: 0 done · 0 failed · Pivots: 0 done · Elapsed: 0s' in lines
        assert [line for line in lines if '┌─' in line] == [f' ┌─ {s} ─' for s in self.SECTIONS_EN]
        assert block(out, 'I. WHOIS')[1:] == ['   Registrar: -', '   Created: -',
                                              '   Name Servers: -', '   Emails: -']
        assert lines.count('   (no data)') == 2
        assert '   0 alive / 0 total' in lines
        assert '   0 emails harvested across 0 pages' in lines

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' ⚠ 已超出时间预算 — 部分接力被跳过'),
        ('en', ' ⚠ Budget exceeded — some pivots were skipped'),
    ])
    def test_budget_warning(self, capsys, lang, expected):
        gt.set_lang(lang)
        data = investigate_data()
        data['_stats']['budget_exceeded'] = True
        gt.print_investigate(data)
        assert expected in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' 触发上限截断: 跳过了 7 个 IP 和 2 个邮箱 (用 --max-pivot-* 提升)'),
        ('en', ' Truncated by cap: 7 IPs and 2 emails skipped (use --max-pivot-* to raise)'),
    ])
    def test_truncation_notice(self, capsys, lang, expected):
        gt.set_lang(lang)
        data = investigate_data()
        data['_stats']['truncated'] = {'ips': 7, 'emails': 2}
        gt.print_investigate(data)
        assert expected in capsys.readouterr().out.splitlines()

    def test_long_lists_are_capped_with_a_more_line(self, capsys):
        data = investigate_data()
        data['tasks']['subdomain']['subdomains'] = [
            {'host': f'h{i:02}.example.com', 'alive': True, 'a': [f'10.0.0.{i}']} for i in range(23)]
        data['tasks']['emails']['emails'] = [
            {'address': f'user{i:02}@example.com', 'sources': ['crawl']} for i in range(17)]
        data['pivots']['users'] = {'max@example.com': {
            'local_part': 'max', 'result': {f'Site{i}': f'https://s{i}.test/max' for i in range(7)}}}
        gt.print_investigate(data)
        out = capsys.readouterr().out
        subs, emails, users = block(out, 'III. '), block(out, '─ V. '), block(out, 'VI. ')
        assert len([line for line in subs if '[ + ]' in line]) == 20
        assert 'h19.example.com' in subs[-2] and subs[-1] == '   ... 另有 3 个'
        assert len([line for line in emails if '[ + ]' in line]) == 15
        assert emails[-1] == '   ... 另有 2 个'
        assert users[1].endswith('→ 命中 7 个')
        assert users[2:] == [f'     Site{i}: https://s{i}.test/max' for i in range(5)] + ['     ... 另有 2 个']

    def test_whois_values_of_other_shapes(self, capsys):
        data = investigate_data()
        data['tasks']['whois'] = {'registrar': None, 'creation_date': None,
                                  'name_servers': 'ns.single.example',
                                  'emails': ['a@example.com', 'b@example.com']}
        gt.print_investigate(data)
        assert block(capsys.readouterr().out, 'I. WHOIS')[1:] == [
            '   注册商: -', '   创建日期: -',
            '   DNS 服务器: ns.single.example', '   邮箱: a@example.com, b@example.com']

    def test_malformed_user_pivot_entries_are_skipped(self, capsys):
        data = investigate_data()
        data['pivots']['users'] = {'ghost@example.com': None,
                                   'max@example.com': {'local_part': 'max', 'result': None}}
        gt.print_investigate(data)
        assert block(capsys.readouterr().out, 'VI. ')[1:] == [
            f"   [ + ] {col('max@example.com', 35)} (max) → 命中 0 个"]

    def test_ip_pivot_falls_back_to_top_level_org(self, capsys):
        data = investigate_data()
        data['pivots']['ips'] = {'192.0.2.1': {'country': None, 'org': 'Flat Org'},
                                 '192.0.2.2': {'country': 'Japan', 'connection': {'org': None}}}
        gt.print_investigate(data)
        assert block(capsys.readouterr().out, 'IV. ')[1:] == [
            f"   [ + ] {col('192.0.2.1', 18)} {col('-', 15)} Flat Org",
            f"   [ + ] {col('192.0.2.2', 18)} {col('Japan', 15)} -",
        ]

    @pytest.mark.parametrize('lang, expected', [('zh', ' 查询失败：仅支持域名'), ('en', ' Query failed: 仅支持域名')])
    def test_error(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_investigate({'_error': '仅支持域名', 'target': '8.8.8.8', 'entity_type': 'ip'})
        out = capsys.readouterr().out
        assert expected in out.splitlines()
        assert '┌─' not in out

    @pytest.mark.parametrize('bad', [None, [], 'oops'])
    def test_non_dict_input_does_not_crash(self, capsys, bad):
        gt.print_investigate(bad)
        lines = [line for line in capsys.readouterr().out.splitlines() if line]
        assert lines[0] == ' ========== 综合调查 =========='
        assert len(lines) == 2                 # 标题 + 一行说明,不展开任何分节


class TestPrintHistory:
    ENTRIES = [
        {'ts': '2026-11-27T10:00:00+0800', 'cmd': 'user', 'query': 'alice', 'scanned': 100, 'found': 3},
        {'ts': '2026-11-27T10:00:01+0800', 'cmd': 'ip', 'query': '8.8.8.8', 'ok': True},
        {'ts': '2026-11-27T10:00:02+0800', 'cmd': 'phone', 'query': '+1', 'ok': False},
        {'ts': '2026-11-27T10:00:03+0800', 'cmd': 'email', 'query': 'a@example.com', 'mx_valid': True},
        {'ts': '2026-11-27T10:00:04+0800', 'cmd': 'email', 'query': 'b@example.com', 'mx_valid': False},
        {'ts': '2026-11-27T10:00:05+0800', 'cmd': 'subdomain', 'query': 'example.com',
         'total': 9, 'alive': 4, 'wildcard': True},
        {'ts': '2026-11-27T10:00:06+0800', 'cmd': 'subdomain', 'query': 'example.org',
         'total': 2, 'alive': 0, 'wildcard': False},
        {'ts': '2026-11-27T10:00:07+0800', 'cmd': 'domain-emails', 'query': 'example.com',
         'total': 5, 'pages_crawled': 12, 'verified': 0},
        {'ts': '2026-11-27T10:00:08+0800', 'cmd': 'whois', 'query': 'a.com,b.com', 'domains': ['a.com', 'b.com']},
    ]

    def test_one_line_per_entry_with_extras(self, capsys):
        gt.print_history(self.ENTRIES)
        lines = capsys.readouterr().out.splitlines()
        assert ' ========== 最近查询 ==========' in lines
        # 命令列按最长的命令名(domain-emails,13 个字符)对齐
        assert [line for line in lines if line.startswith('  2026')] == [
            '  2026-11-27T10:00:00+0800  user           alice  [3/100]',
            '  2026-11-27T10:00:01+0800  ip             8.8.8.8  [✓]',
            '  2026-11-27T10:00:02+0800  phone          +1  [✗]',
            '  2026-11-27T10:00:03+0800  email          a@example.com  [mx✓]',
            '  2026-11-27T10:00:04+0800  email          b@example.com  [mx✗]',
            '  2026-11-27T10:00:05+0800  subdomain      example.com  [4/9, ⚠wildcard]',
            '  2026-11-27T10:00:06+0800  subdomain      example.org  [0/2]',
            '  2026-11-27T10:00:07+0800  domain-emails  example.com',
            '  2026-11-27T10:00:08+0800  whois          a.com,b.com',
        ]

    def test_header_follows_language(self, capsys):
        gt.set_lang('en')
        gt.print_history(self.ENTRIES[:1])
        assert ' ========== Recent Queries ==========' in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('lang, expected', [
        ('zh', ' （暂无历史 —— 先跑一次查询试试）'),
        ('en', ' (no history yet — run a query first)'),
    ])
    def test_empty(self, capsys, lang, expected):
        gt.set_lang(lang)
        gt.print_history([])
        assert expected in capsys.readouterr().out.splitlines()

    def test_missing_fields_use_placeholders(self, capsys):
        gt.print_history([{'query': 'orphan'}, {'cmd': 'user', 'query': 'bob', 'found': 2}])
        lines = capsys.readouterr().out.splitlines()
        assert '  ?  ?     orphan' in lines
        assert '  ?  user  bob  [2/?]' in lines

    @pytest.mark.parametrize('bad_line', ['{"ts": "t", "cmd": null, "query": "q"}', '123'])
    def test_history_command_survives_a_malformed_line(self, capsys, bad_line):
        os.makedirs(gt.CONFIG_DIR, exist_ok=True)
        with open(gt.HISTORY_FILE, 'w', encoding='utf-8') as f:
            f.write('{"ts": "t0", "cmd": "ip", "query": "8.8.8.8", "ok": true}\n' + bad_line + '\n')
        assert gt.run_cli(cli('history')) == 0
        assert '8.8.8.8' in capsys.readouterr().out


class TestPrintUpdateNotice:
    INFO = {'latest': 'v9.9.9', 'current': '1.8.7', 'url': 'https://example.test/releases/v9.9.9'}

    def test_four_lines_on_stderr_zh(self, monkeypatch, capsys):
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: False)
        gt.print_update_notice(self.INFO)
        captured = capsys.readouterr()
        assert captured.out == ''
        assert [line for line in captured.err.splitlines() if line] == [
            '🆕 SpyEyes v9.9.9 可用(当前 1.8.7)',
            '   更新: 进入仓库目录,执行 `git pull && pip install -e .`',
            '   更新内容: https://example.test/releases/v9.9.9',
            '   (关闭提示: SPYEYES_NO_UPDATE_CHECK=1 或 --no-update-check)',
        ]

    def test_four_lines_on_stderr_en_packaged(self, monkeypatch, capsys):
        monkeypatch.setattr(gt, '_is_packaged_install', lambda: True)
        gt.set_lang('en')
        gt.print_update_notice(self.INFO)
        assert [line for line in capsys.readouterr().err.splitlines() if line] == [
            '🆕 SpyEyes v9.9.9 available (current 1.8.7)',
            '   Update: run `spyeyes upgrade` or menu [12] (handles pip / pipx / Homebrew installs)',
            '   Release notes: https://example.test/releases/v9.9.9',
            '   (disable: SPYEYES_NO_UPDATE_CHECK=1 or --no-update-check)',
        ]

    @pytest.mark.parametrize('info', [{'latest': 'v9.9.9', 'current': '1.8.7'},
                                      {'latest': 'v9.9.9', 'current': '1.8.7', 'url': None}])
    def test_missing_url_prints_empty_link_not_none(self, capsys, info):
        gt.print_update_notice(info)
        err = capsys.readouterr().err
        assert '   更新内容: ' in err.splitlines()
        assert 'None' not in err

    def test_broken_stderr_is_swallowed(self, monkeypatch):
        attempts = []

        class Broken:
            def write(self, text):
                attempts.append(text)
                raise OSError('stderr closed')

        monkeypatch.setattr(sys, 'stderr', Broken())
        gt.print_update_notice(self.INFO)     # 提示打不出来不该拖垮主流程
        assert len(attempts) == 1 and 'v9.9.9' in attempts[0]


# ==================================================================
# 二、交互提问小函数
# ==================================================================
class TestIsAffirmative:
    @pytest.mark.parametrize('answer', ['1', 'y', 'Y', 'yes', 'YES', ' yes ', '是', '保存', 'true', 'True', '1\n'])
    def test_yes(self, answer):
        assert gt._is_affirmative(answer) is True

    @pytest.mark.parametrize('answer', ['', ' ', None, '2', '0', 'n', 'no', '否', '11', 'ok', 'yep', '不保存'])
    def test_everything_else_is_no(self, answer):
        assert gt._is_affirmative(answer) is False


class TestAskScanMode:
    @pytest.mark.parametrize('answer, expected', [
        ('', QUICK_CATEGORIES), ('1', QUICK_CATEGORIES), ('  1 ', QUICK_CATEGORIES),
        ('2', None), ('3', ['chinese', 'spanish']), ('4', ['code']),
        ('9', QUICK_CATEGORIES), ('full', QUICK_CATEGORIES),
        (EOFError, QUICK_CATEGORIES), (KeyboardInterrupt, QUICK_CATEGORIES),
    ])
    def test_answer_to_categories(self, feed, answer, expected):
        feed(answer)
        assert gt._ask_scan_mode() == expected

    @pytest.mark.parametrize('lang, title, first, prompt', [
        ('zh', ' 扫描模式:', '  [ 1 ] 快速', '请选择 [1/2/3/4, 默认 1]: '),
        ('en', ' Scan mode:', '  [ 1 ] Quick', 'Choose [1/2/3/4, default 1]: '),
    ])
    def test_lists_four_numbered_modes(self, feed, capsys, lang, title, first, prompt):
        gt.set_lang(lang)
        prompts = feed('')
        gt._ask_scan_mode()
        lines = capsys.readouterr().out.splitlines()
        assert title in lines
        options = [line for line in lines if line.startswith('  [ ')]
        assert [line[:7] for line in options] == ['  [ 1 ]', '  [ 2 ]', '  [ 3 ]', '  [ 4 ]']
        assert options[0].startswith(first)
        assert prompts == [f' {prompt}']


class TestAskUsernameStrategy:
    @pytest.mark.parametrize('answer, expected', [
        ('', 'direct'), ('1', 'direct'), ('2', 'permute_scan'), (' 3 ', 'permute_only'),
        ('4', 'direct'), ('x', 'direct'), (EOFError, 'direct'), (KeyboardInterrupt, 'direct'),
    ])
    def test_answer_to_strategy(self, feed, answer, expected):
        feed(answer)
        assert gt._ask_username_strategy() == expected

    def test_lists_three_strategies(self, feed, capsys):
        prompts = feed('')
        gt._ask_username_strategy()
        lines = capsys.readouterr().out.splitlines()
        assert ' 扫描方式：' in lines
        assert [line for line in lines if line.startswith('  [ ')] == [
            '  [ 1 ] 直接扫描该用户名',
            '  [ 2 ] 先生成变形再批量扫描（适合 "John Doe" / "张 三" 找化名）',
            '  [ 3 ] 仅生成变形列表（不扫描）',
        ]
        assert prompts == [' 请选择 [1/2/3，默认 1] : ']


class TestAskPermuteMethod:
    @pytest.mark.parametrize('answer, expected', [
        ('', 'strict'), ('1', 'strict'), ('2', 'all'), (' 2 ', 'all'), ('all', 'strict'),
        (EOFError, 'strict'), (KeyboardInterrupt, 'strict'),
    ])
    def test_answer_to_method(self, feed, answer, expected):
        feed(answer)
        assert gt._ask_permute_method() == expected

    def test_lists_two_methods(self, feed, capsys):
        gt.set_lang('en')
        prompts = feed('')
        gt._ask_permute_method()
        lines = capsys.readouterr().out.splitlines()
        assert ' Permutation method:' in lines
        options = [line for line in lines if line.startswith('  [ ')]
        assert len(options) == 2
        assert options[0].startswith('  [ 1 ] strict') and options[1].startswith('  [ 2 ] all')
        assert prompts == [' Choose [1/2, default 1] : ']


class TestPromptLanguageSelect:
    @pytest.mark.parametrize('answers, expected', [
        (['1'], 'zh'), (['2'], 'en'), ([' 2 '], 'en'),
        (['', 'x', '3', '2'], 'en'),          # 无效输入一直重问,直到给出 1 / 2
    ])
    def test_returns_chosen_language(self, feed, answers, expected):
        prompts = feed(*answers)
        assert gt.prompt_language_select() == expected
        assert len(prompts) == len(answers)

    @pytest.mark.parametrize('interrupt', [EOFError, KeyboardInterrupt])
    @pytest.mark.parametrize('current', ['zh', 'en'])
    def test_interrupt_keeps_current_language(self, feed, interrupt, current):
        gt.set_lang(current)
        feed(interrupt)
        assert gt.prompt_language_select() == current

    def test_does_not_switch_language_by_itself(self, feed):
        feed('2')
        gt.prompt_language_select()
        assert gt.get_lang() == 'zh'          # 只返回选择,由调用方 set_lang

    def test_shows_both_options(self, feed, capsys):
        feed('1')
        gt.prompt_language_select()
        lines = capsys.readouterr().out.splitlines()
        assert '  [ 1 ] 中文 (Chinese)' in lines
        assert '  [ 2 ] English (英文)' in lines
        assert any('请选择语言 / Please select language:' in line for line in lines)


class TestSwitchLanguageMenu:
    def test_switch_to_english_persists_config(self, feed, capsys):
        gt.save_config({'lang': 'zh', 'theme': 'classic'})
        feed('2')
        gt.switch_language_menu()
        assert gt.get_lang() == 'en'
        assert gt.load_config() == {'lang': 'en', 'theme': 'classic'}   # 其它配置项保留
        assert ' Language switched to English' in capsys.readouterr().out.splitlines()

    def test_switch_to_chinese_persists_config(self, feed, capsys):
        gt.set_lang('en')
        feed('1')
        gt.switch_language_menu()
        assert gt.get_lang() == 'zh'
        assert gt.load_config() == {'lang': 'zh'}
        assert ' 已切换为中文' in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('answer', ['0', '', '3', 'en', EOFError, KeyboardInterrupt])
    def test_anything_else_changes_nothing(self, feed, capsys, answer):
        feed(answer)
        gt.switch_language_menu()
        assert gt.get_lang() == 'zh'
        assert not os.path.exists(gt.CONFIG_FILE)
        out = capsys.readouterr().out
        assert '已切换' not in out and 'switched' not in out

    def test_menu_lists_cancel_option(self, feed, capsys):
        feed('0')
        gt.switch_language_menu()
        assert [line for line in capsys.readouterr().out.splitlines() if line.startswith('  [ ')] == [
            '  [ 1 ] 中文 (Chinese)', '  [ 2 ] English (英文)', '  [ 0 ] 返回 / Back']


class TestShowMenu:
    def test_menu_zh(self, capsys):
        gt.show_menu()
        captured = capsys.readouterr()
        assert [line for line in captured.out.splitlines() if line.startswith('[ ')] == [
            '[ 1 ] IP 追踪', '[ 2 ] 查看本机 IP', '[ 3 ] 电话号码追踪', '[ 4 ] 用户名追踪',
            '[ 5 ] 域名 WHOIS 查询', '[ 6 ] 域名 MX 记录', '[ 7 ] 邮箱有效性检查', '[ 8 ] 子域名枚举',
            '[ 9 ] 域名邮箱枚举(OSINT 邮箱挖取)', '[ 10 ] 综合调查 (多源整合档案)',
            '[ 11 ] 切换语言 / Language', '[ 12 ] 检查并升级 SpyEyes', '[ 0 ] 退出',
        ]
        assert '  (在任意子功能中输入 0 或直接回车可返回此菜单)' in captured.out.splitlines()
        # Logo 走 stderr,不混进 stdout
        assert 'All-in-One OSINT Toolkit' in captured.err
        assert 'OSINT Toolkit' not in captured.out

    def test_menu_en(self, capsys):
        gt.set_lang('en')
        gt.show_menu()
        lines = capsys.readouterr().out.splitlines()
        assert [line for line in lines if line.startswith('[ ')] == [
            '[ 1 ] IP Tracker', '[ 2 ] My Public IP', '[ 3 ] Phone Number Tracker', '[ 4 ] Username Scanner',
            '[ 5 ] Domain WHOIS Lookup', '[ 6 ] Domain MX Records', '[ 7 ] Email Validator',
            '[ 8 ] Subdomain Enumeration', '[ 9 ] Domain Emails (OSINT email harvest)',
            '[ 10 ] Investigate (multi-source dossier)', '[ 11 ] Language / 语言',
            '[ 12 ] Check & Upgrade SpyEyes', '[ 0 ] Exit',
        ]
        assert '  (In any sub-menu, enter 0 or press Enter to return here)' in lines


# ==================================================================
# 三、保存报告的交互流程
# ==================================================================
class TestInteractiveSavePrompt:
    DATA = {'ip': '8.8.8.8', 'country': 'United States'}

    @staticmethod
    def default_path(prompt):
        """从「文件名 [默认 xxx]: 」提示里取出默认路径。"""
        m = re.search(r'\[(?:默认 |default: )(.+)\]: $', prompt)
        assert m, prompt
        return m.group(1)

    def test_save_dir_saves_without_asking(self, feed, tmp_path, capsys):
        out_dir = str(tmp_path / 'out') + '/'
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, out_dir)   # 没喂答案:一问就失败
        name, saved = saved_json(out_dir)
        assert re.fullmatch(r'ip_8\.8\.8\.8_\d{8}-\d{6}\.json', name)
        assert saved == self.DATA
        assert '已保存到' in capsys.readouterr().out

    @pytest.mark.parametrize('answer', ['2', '', 'n', 'no', '0', EOFError, KeyboardInterrupt])
    def test_declining_saves_nothing(self, feed, tmp_path, capsys, answer):
        prompts = feed(answer)
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        assert len(prompts) == 1 and '是否保存报告？' in prompts[0]
        assert not os.path.exists(tmp_path / 'reports')
        assert capsys.readouterr().out == ''

    def test_yes_then_defaults_saves_json_in_report_dir(self, feed, tmp_path, capsys):
        prompts = feed('1', '', '', '2')
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        name, saved = saved_json(tmp_path / 'reports')
        assert re.fullmatch(r'ip_8\.8\.8\.8_\d{8}-\d{6}\.json', name)
        assert saved == self.DATA
        path = str(tmp_path / 'reports' / name)
        assert self.default_path(prompts[2]) == path        # 提示里给的默认路径就是实际保存的路径
        assert '请选择 [1-8，默认 1]' in prompts[1] and '继续保存其它格式？' in prompts[3]
        out = capsys.readouterr().out
        assert f' [ 已保存到 {path} ]' in out.splitlines()

    def test_format_menu_lists_eight_formats(self, feed, capsys):
        feed('1', EOFError)
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        lines = capsys.readouterr().out.splitlines()
        assert ' 请选择报告格式 / Choose report format:' in lines
        options = [line for line in lines if line.startswith('  [ ')]
        assert [line[:7] for line in options] == [f'  [ {i} ]' for i in range(1, 9)]
        assert [re.search(r'\((\.[a-z.]+)', line).group(1) for line in options] == [
            '.json', '.md', '.html', '.pdf', '.txt', '.csv', '.xmind', '.graph.html']

    @pytest.mark.parametrize('choice, ext', [
        ('1', 'json'), ('2', 'md'), ('3', 'html'), ('4', 'pdf'), ('5', 'txt'), ('6', 'csv'),
        ('7', 'xmind'), ('8', 'graph.html'),
        ('', 'json'), ('0', 'json'), ('9', 'json'), ('-1', 'json'), ('pdf', 'json'), (' 3 ', 'html'),
    ])
    def test_format_choice_decides_default_extension(self, feed, tmp_path, choice, ext):
        prompts = feed('1', choice, EOFError)             # 在文件名那一步中断,不真的写文件
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        default = self.default_path(prompts[2])
        assert os.path.dirname(default) == str(tmp_path / 'reports')
        assert re.fullmatch(r'ip_8\.8\.8\.8_\d{8}-\d{6}\.' + re.escape(ext), os.path.basename(default))
        assert not os.path.exists(tmp_path / 'reports')

    def test_custom_filename_is_used_and_parent_created(self, feed, tmp_path, capsys):
        target = tmp_path / 'deep' / 'dir' / 'mine.txt'
        feed('1', '5', f'  {target}  ', '2')
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        text = target.read_text(encoding='utf-8')
        assert 'United States' in text and not text.lstrip().startswith('{')   # 是 TXT 报告,不是 JSON
        assert not os.path.exists(tmp_path / 'reports')
        assert f' [ 已保存到 {target} ]' in capsys.readouterr().out.splitlines()

    def test_save_another_format_loops(self, feed, tmp_path, capsys):
        prompts = feed('1', '1', '', '1', '6', '', '2')
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        by_ext = {name.rsplit('.', 1)[1]: name for name in os.listdir(tmp_path / 'reports')}
        assert sorted(by_ext) == ['csv', 'json']
        assert len(prompts) == 7
        out = capsys.readouterr().out
        assert out.count('请选择报告格式') == 2 and out.count('已保存到') == 2
        with open(tmp_path / 'reports' / by_ext['csv'], 'rb') as f:
            assert f.read(3) == b'\xef\xbb\xbf'           # CSV 带 BOM

    @pytest.mark.parametrize('again', ['2', '', EOFError, KeyboardInterrupt])
    def test_stops_after_one_save_unless_confirmed(self, feed, tmp_path, again):
        feed('1', '2', '', again)
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        names = os.listdir(tmp_path / 'reports')
        assert len(names) == 1 and names[0].endswith('.md')

    @pytest.mark.parametrize('prefix, expected', [
        ('email_a@b.com', r'email_a_b\.com_\d{8}-\d{6}\.json'),
        ('username_../../etc/passwd', r'username_\.\._\.\._etc_passwd_\d{8}-\d{6}\.json'),
        ('phone_+8613800138000', r'phone_\+8613800138000_\d{8}-\d{6}\.json'),
        ('permute_John Doe', r'permute_John_Doe_\d{8}-\d{6}\.json'),
        ('', r'report_\d{8}-\d{6}\.json'),
        ('x' * 100, 'x' * 60 + r'_\d{8}-\d{6}\.json'),
    ])
    def test_default_filename_is_sanitised(self, feed, tmp_path, prefix, expected):
        prompts = feed('1', '1', EOFError)
        gt._interactive_save_prompt(prefix, self.DATA, None)
        default = self.default_path(prompts[2])
        assert os.path.dirname(default) == str(tmp_path / 'reports')     # 路径分隔符没有逃出报告目录
        assert re.fullmatch(expected, os.path.basename(default))

    def test_prompts_follow_language(self, feed):
        gt.set_lang('en')
        prompts = feed('1', '1', EOFError)
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        assert 'Save report?' in prompts[0]
        assert prompts[1] == ' Choose [1-8, default 1]: '
        assert prompts[2].startswith(' Filename [default: ')

    def test_username_json_strips_private_keys(self, feed, tmp_path):
        feed('1', '1', '', '2')
        gt._interactive_save_prompt('username_alice', username_results(), None)
        _, saved = saved_json(tmp_path / 'reports')
        assert '_statuses' not in saved
        assert saved['StrictSite'] == 'https://strict.test/alice' and saved['MissSite'] is None

    def test_chosen_format_applies_to_custom_name_without_extension(self, feed, tmp_path):
        target = tmp_path / 'myreport'
        feed('1', '2', str(target), '2')
        gt._interactive_save_prompt('ip_8.8.8.8', self.DATA, None)
        written = [p for p in tmp_path.iterdir() if p.name.startswith('myreport')]
        assert len(written) == 1
        assert not written[0].read_text(encoding='utf-8').lstrip().startswith('{')


# ==================================================================
# 四、交互菜单 handle_choice
# ==================================================================
class TestHandleChoiceBackToMenu:
    FIRST_PROMPT = {
        1: '请输入目标 IP : ', 3: '请输入电话号码 例如 [+8613800138000] : ', 4: '请输入用户名 : ',
        5: '请输入域名 : ', 6: '请输入域名 : ', 7: '请输入邮箱 : ',
        8: '请输入目标域名（如 example.com）：', 9: '请输入要挖邮箱的目标域名(如 example.com):',
        10: '请输入目标域名 : ',
    }

    @pytest.mark.parametrize('choice', sorted(FIRST_PROMPT))
    @pytest.mark.parametrize('answer', ['', '0', '   ', EOFError, KeyboardInterrupt])
    def test_empty_or_zero_returns_without_querying(self, feed, capsys, choice, answer):
        prompts = feed(answer)                 # 核心函数都还是「一调用就失败」的替身
        assert gt.handle_choice(choice) is None
        assert prompts == [f'\n {self.FIRST_PROMPT[choice]}']
        assert capsys.readouterr().out == ''

    @pytest.mark.parametrize('choice', [13, 99, -1])
    def test_unknown_option_raises_value_error(self, choice):
        with pytest.raises(ValueError, match=f'^未知选项：{choice}$'):
            gt.handle_choice(choice)

    def test_unknown_option_message_follows_language(self):
        gt.set_lang('en')
        with pytest.raises(ValueError, match='^Unknown option: 42$'):
            gt.handle_choice(42)


class TestHandleChoiceSimpleQueries:
    def test_1_ip(self, feed, fake, capsys):
        track = fake('track_ip', ip_data())
        prompts = feed('  8.8.8.8 ', '2')
        gt.handle_choice(1)
        assert track.calls == [(('8.8.8.8',), {})]              # 输入去掉了首尾空白
        assert fields(capsys.readouterr().out)['组织'] == 'Google LLC'
        assert '是否保存报告？' in prompts[1]

    def test_1_ip_error_is_printed(self, feed, fake, capsys):
        fake('track_ip', {'_error': '非法 IP'})
        feed('nope', '2')
        gt.handle_choice(1)
        assert ' 查询失败：非法 IP' in capsys.readouterr().out.splitlines()

    def test_2_my_ip(self, feed, fake, capsys):
        mine = fake('show_my_ip', '203.0.113.7')
        feed('2')
        gt.handle_choice(2)
        assert mine.calls == [((), {})]
        assert ' [ + ] 你的 IP 地址 : 203.0.113.7' in capsys.readouterr().out.splitlines()

    def test_2_my_ip_failure(self, feed, fake, capsys, tmp_path):
        fake('show_my_ip', None)
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(2, save_dir=out_dir)
        assert ' 查询失败，请检查网络' in capsys.readouterr().out.splitlines()
        assert saved_json(out_dir)[1] == {'ip': None}

    def test_3_phone(self, feed, fake, capsys):
        track = fake('track_phone', phone_data())
        feed('+8613800138000', '2')
        gt.handle_choice(3)
        assert track.calls == [(('+8613800138000',), {})]
        assert fields(capsys.readouterr().out)['E.164 格式'] == '+8613800138000'

    def test_5_whois(self, feed, fake, capsys):
        lookup = fake('whois_lookup', whois_data())
        feed('example.com', '2')
        gt.handle_choice(5)
        assert lookup.calls == [(('example.com',), {})]
        assert fields(capsys.readouterr().out)['注册商'] == 'Example Registrar, Inc.'

    def test_6_mx(self, feed, fake, capsys):
        lookup = fake('mx_lookup', mx_data())
        feed('example.com', '2')
        gt.handle_choice(6)
        assert lookup.calls == [(('example.com',), {})]
        assert '  优先级   10  →  mx1.example.com' in capsys.readouterr().out.splitlines()

    def test_7_email(self, feed, fake, capsys):
        validate = fake('email_validate', email_data())
        feed('a@example.com', '2')
        gt.handle_choice(7)
        assert validate.calls == [(('a@example.com',), {})]
        assert fields(capsys.readouterr().out)['MX 有效'] == 'True'

    @pytest.mark.parametrize('choice, core, result, answer, filename, saved', [
        (1, 'track_ip', {'country': 'US'}, '8.8.8.8', r'ip_8\.8\.8\.8_', {'country': 'US'}),
        (3, 'track_phone', {'_error': '解析失败'}, '+8613800138000', r'phone_\+8613800138000_',
         {'_error': '解析失败'}),
        (5, 'whois_lookup', {'_error': 'whois 挂了'}, 'example.com', r'whois_example\.com_',
         {'_error': 'whois 挂了'}),
        (6, 'mx_lookup', mx_data(), 'example.com', r'mx_example\.com_', mx_data()),
        (7, 'email_validate', email_data(), 'a@example.com', r'email_a_example\.com_', email_data()),
    ])
    def test_save_dir_gets_the_result_under_the_right_name(self, feed, fake, tmp_path, capsys,
                                                           choice, core, result, answer, filename, saved):
        fake(core, result)
        feed(answer)                           # 指定了 save_dir:只问查询目标,不再问是否保存
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(choice, save_dir=out_dir)
        name, content = saved_json(out_dir)
        assert re.fullmatch(filename + r'\d{8}-\d{6}\.json', name)
        assert content == saved

    def test_query_then_interactive_save_end_to_end(self, feed, fake, tmp_path, capsys):
        fake('track_ip', ip_data())
        feed('8.8.8.8', '1', '2', '', '2')       # 查 → 保存 → Markdown → 默认文件名 → 不再存
        gt.handle_choice(1)
        names = os.listdir(tmp_path / 'reports')
        assert len(names) == 1 and re.fullmatch(r'ip_8\.8\.8\.8_\d{8}-\d{6}\.md', names[0])
        report = (tmp_path / 'reports' / names[0]).read_text(encoding='utf-8')
        assert 'Google LLC' in report and 'Mountain View' in report
        assert f" [ 已保存到 {tmp_path / 'reports' / names[0]} ]" in capsys.readouterr().out.splitlines()

    def test_11_switches_language(self, feed, capsys):
        feed('2')
        gt.handle_choice(11)
        assert gt.get_lang() == 'en'
        assert gt.load_config() == {'lang': 'en'}
        assert ' Language switched to English' in capsys.readouterr().out.splitlines()


class TestHandleChoiceUsername:
    """选项 4:直接扫描 / 变形后批量扫描 / 仅生成变形。"""

    def test_direct_scan_with_defaults(self, feed, fake, capsys, platforms):
        scan = fake('track_username', username_results())
        prompts = feed('alice', '', '', '', '2')          # 策略、模式、递归都用默认
        gt.handle_choice(4)
        assert scan.calls == [(('alice',), {'categories': QUICK_CATEGORIES})]
        out = capsys.readouterr().out
        assert ' 共扫描 9 个平台，命中 3 个：' in out.splitlines()
        assert 'https://strict.test/alice' in out and '递归扫描总结' not in out
        assert '是否递归扫描' in prompts[3] and '是否保存报告？' in prompts[4]

    @pytest.mark.parametrize('mode, categories', [('2', None), ('3', ['chinese', 'spanish']), ('4', ['code'])])
    def test_direct_scan_passes_chosen_scan_mode(self, feed, fake, platforms, mode, categories):
        scan = fake('track_username', username_results())
        feed('alice', '1', mode, '2', '2')
        gt.handle_choice(4)
        assert scan.calls == [(('alice',), {'categories': categories})]

    @pytest.mark.parametrize('depth_answer, depth', [
        ('', 2), ('1', 1), ('2', 2), ('0', 0), ('9', 2), ('-3', 0), ('deep', 2), (EOFError, 2)])
    def test_recursive_scan_clamps_depth(self, feed, fake, capsys, platforms, depth_answer, depth):
        result = username_results()
        result['_recursive'] = {'levels': [{'depth': 0, 'username': 'alice', 'found': 3},
                                           {'depth': 1, 'username': 'alice_dev', 'found': 2}],
                                'total_found': 5}
        recurse = fake('recursive_track_username', result)
        prompts = feed('alice', '1', '4', '1', depth_answer, '2')
        gt.handle_choice(4)
        assert recurse.calls == [(('alice',), {'max_depth': depth, 'categories': ['code']})]
        assert '递归深度' in prompts[4]
        out = capsys.readouterr().out
        # 先打层级总结,再打第 0 层的平台明细
        assert out.index('递归扫描结束。共 5 个平台，2 层。') < out.index('共扫描 9 个平台，命中 3 个：')

    def test_eof_at_recursive_question_means_no(self, feed, fake, platforms):
        scan = fake('track_username', username_results())
        feed('alice', '1', '1', EOFError, '2')
        gt.handle_choice(4)
        assert len(scan.calls) == 1            # recursive_track_username 仍是「一调用就失败」的替身

    def test_direct_scan_error_is_printed(self, feed, fake, capsys):
        fake('track_username', {'_error': '用户名含非法字符'})
        feed('a/b', '', '', '', '2')
        gt.handle_choice(4)
        assert ' 查询失败：用户名含非法字符' in capsys.readouterr().out.splitlines()

    def test_direct_scan_saved_json_has_no_private_keys(self, feed, fake, tmp_path, platforms):
        fake('track_username', username_results())
        feed('alice', '', '', '')
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(4, save_dir=out_dir)
        name, saved = saved_json(out_dir)
        assert name.startswith('username_alice_')
        assert '_statuses' not in saved and saved['NfSite'] == 'https://nf.test/alice'

    @pytest.mark.parametrize('method_answer, method', [('', 'strict'), ('2', 'all')])
    def test_permute_only_lists_variations_without_scanning(self, feed, monkeypatch, capsys, tmp_path,
                                                            method_answer, method):
        permute = Recorder(['johndoe', 'doe.john'])
        monkeypatch.setattr(gt, 'permute_username', permute)
        feed('John Doe', '3', method_answer)
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(4, save_dir=out_dir)   # track_username 没被替换:扫了就失败
        assert permute.calls == [(('John Doe',), {'method': method})]
        lines = capsys.readouterr().out.splitlines()
        assert ' 从 "John Doe" 生成 2 个变形：' in lines
        assert [line for line in lines if '•' in line] == ['  • johndoe', '  • doe.john']
        name, saved = saved_json(out_dir)
        assert name.startswith('permute_John_Doe_')
        assert saved == {'name': 'John Doe', 'permutations': ['johndoe', 'doe.john']}

    @pytest.mark.parametrize('strategy, lang, expected', [
        ('3', 'zh', ' 无法生成变形：输入为空'), ('2', 'zh', ' 无法生成变形：输入为空'),
        ('3', 'en', ' Cannot generate permutations: input is empty'),
    ])
    def test_name_with_no_usable_parts_stops_early(self, feed, capsys, strategy, lang, expected):
        gt.set_lang(lang)
        feed('!!!', strategy, '')               # 真实的 permute_username;之后不该再问扫描模式 / 保存
        gt.handle_choice(4)
        assert expected in capsys.readouterr().out.splitlines()

    def test_permute_scan_scans_every_variation(self, feed, fake, monkeypatch, capsys, tmp_path, platforms):
        permute = Recorder(['johndoe', 'doejohn'])
        monkeypatch.setattr(gt, 'permute_username', permute)

        def scan_one(name, categories=None):
            return {'StrictSite': f'https://strict.test/{name}' if name == 'johndoe' else None,
                    'MissSite': None}

        scan = fake('track_username', scan_one)
        feed('John Doe', '2', '1', '3')         # 变形扫描 → strict → 仅中文 + 西语
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(4, save_dir=out_dir)
        assert permute.calls == [(('John Doe',), {'method': 'strict'})]
        assert scan.calls == [(('johndoe',), {'categories': ['chinese', 'spanish']}),
                              (('doejohn',), {'categories': ['chinese', 'spanish']})]
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' 从 "John Doe" 生成 2 个变形：' in lines
        first, second = lines.index(' ━━━ johndoe ━━━'), lines.index(' ━━━ doejohn ━━━')
        assert first < second
        assert ' 共扫描 2 个平台，命中 1 个：' in lines[first:second]
        assert ' 共扫描 2 个平台，命中 0 个：' in lines[second:]
        assert out.count('https://strict.test/johndoe') == 1
        name, saved = saved_json(out_dir)
        assert name.startswith('permute_John_Doe_')
        assert saved == {'johndoe': {'StrictSite': 'https://strict.test/johndoe', 'MissSite': None},
                         'doejohn': {'StrictSite': None, 'MissSite': None}}


class TestHandleChoiceSubdomain:
    """选项 8:probe / bruteforce / alive-only 三个追问。"""

    @pytest.mark.parametrize('probe_answer, bf_answer, probe, bruteforce', [
        ('', '', True, False),                  # 都回车:抓 title、不爆破
        ('1', '1', True, False),
        ('2', '2', False, True),
        ('2', '', False, False),
        ('', '2', True, True),
        ('n', 'y', True, False),                # 只认 '2'
        (EOFError, KeyboardInterrupt, True, False),
    ])
    def test_probe_and_bruteforce_answers(self, feed, fake, probe_answer, bf_answer, probe, bruteforce):
        enum = fake('enumerate_subdomains', subdomain_data())
        prompts = feed('example.com', probe_answer, bf_answer, '', '2')
        gt.handle_choice(8)
        assert enum.calls == [(('example.com',), {'probe': probe, 'bruteforce': bruteforce})]
        assert '是否抓 HTTP <title> 信息？' in prompts[1]
        assert '是否启用 DNS 字典爆破？' in prompts[2]
        assert '保存报告时是否隐藏不可达子域？' in prompts[3]

    def test_terminal_always_shows_dead_hosts(self, feed, fake, capsys):
        fake('enumerate_subdomains', subdomain_data())
        feed('example.com', '', '', '', '2')
        gt.handle_choice(8)
        out = capsys.readouterr().out
        assert ' [ - ] old.example.com' in out.splitlines()
        assert ' 共发现 4 个 · 活跃 3 个 · 来自 2 个数据源' in out.splitlines()

    @pytest.mark.parametrize('answer', ['', '1', 'x', EOFError])
    def test_saved_report_hides_dead_hosts_by_default(self, feed, fake, tmp_path, answer):
        fake('enumerate_subdomains', subdomain_data())
        feed('example.com', '', '', answer)
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(8, save_dir=out_dir)
        name, saved = saved_json(out_dir)
        assert name.startswith('subdomain_example.com_')
        assert [s['host'] for s in saved['subdomains']] == [
            'www.example.com', 'api.example.com', 'vpn.example.com']
        assert saved['_filtered'] == {'mode': 'alive_only', 'hidden': 1, 'wildcard_suspect': False}

    def test_answer_2_keeps_dead_hosts_in_saved_report(self, feed, fake, tmp_path):
        fake('enumerate_subdomains', subdomain_data())
        feed('example.com', '', '', '2')
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(8, save_dir=out_dir)
        _, saved = saved_json(out_dir)
        assert [s['host'] for s in saved['subdomains']][-1] == 'old.example.com'
        assert len(saved['subdomains']) == 4 and '_filtered' not in saved

    def test_error_result(self, feed, fake, capsys, tmp_path):
        fake('enumerate_subdomains', {'_error': '域名非法'})
        feed('bad domain', '', '', '')
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(8, save_dir=out_dir)
        assert ' 查询失败：域名非法' in capsys.readouterr().out.splitlines()
        assert saved_json(out_dir)[1] == {'_error': '域名非法'}


class TestHandleChoiceDomainEmails:
    """选项 9:含子域 / 爬取深度 / 模式生成 / SMTP 验证四个追问。"""

    def run(self, feed, fake, *answers):
        enum = fake('enumerate_domain_emails', demails_data())
        prompts = feed('example.com', *answers, '2')
        gt.handle_choice(9)
        assert len(enum.calls) == 1
        args, kwargs = enum.calls[0]
        assert args == ('example.com',)
        return kwargs, prompts

    def test_all_defaults(self, feed, fake, capsys):
        kwargs, prompts = self.run(feed, fake, '', '', '', '')
        assert kwargs == {'include_subdomains': True, 'max_pages': 200,
                          'guess_names': None, 'verify_smtp': False}
        assert '是否包含活跃子域名一起爬取?' in prompts[1]
        assert '爬取深度?' in prompts[2]
        assert '从姓名生成模式邮箱?' in prompts[3]
        assert '是否做 SMTP 验证' in prompts[4]
        assert ' 共找到 4 个邮箱(爬取 12 页 · sitemap:✓)' in capsys.readouterr().out.splitlines()

    def test_everything_switched(self, feed, fake):
        kwargs, _ = self.run(feed, fake, '2', '2', ' John Doe,Jane Roe ', '1')
        assert kwargs == {'include_subdomains': False, 'max_pages': 500,
                          'guess_names': 'John Doe,Jane Roe', 'verify_smtp': True}

    @pytest.mark.parametrize('answer, pages', [('', 200), ('1', 200), ('2', 500), ('3', 50), ('4', 200), ('500', 200)])
    def test_crawl_depth_choices(self, feed, fake, answer, pages):
        kwargs, _ = self.run(feed, fake, '', answer, '', '')
        assert kwargs['max_pages'] == pages

    @pytest.mark.parametrize('answer, verify', [('1', True), ('', False), ('2', False), ('y', False), ('yes', False)])
    def test_smtp_verification_needs_an_explicit_1(self, feed, fake, answer, verify):
        """SMTP 验证会连目标 MX,是高调动作:只有明确输入 1 才开。"""
        kwargs, _ = self.run(feed, fake, '', '', '', answer)
        assert kwargs['verify_smtp'] is verify

    def test_interrupts_fall_back_to_defaults(self, feed, fake):
        kwargs, _ = self.run(feed, fake, EOFError, KeyboardInterrupt, EOFError, KeyboardInterrupt)
        assert kwargs == {'include_subdomains': True, 'max_pages': 200,
                          'guess_names': None, 'verify_smtp': False}

    def test_save_dir_file_name(self, feed, fake, tmp_path):
        fake('enumerate_domain_emails', {'_error': '域名非法'})
        feed('example.com', '', '', '', '')
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(9, save_dir=out_dir)
        name, saved = saved_json(out_dir)
        assert name.startswith('domain-emails_example.com_') and saved == {'_error': '域名非法'}


class TestHandleChoiceInvestigate:
    @pytest.mark.parametrize('answer, depth', [('', 1), ('1', 1), ('2', 0), ('3', 1), (EOFError, 1)])
    def test_depth_answer(self, feed, fake, capsys, answer, depth):
        investigate = fake('do_investigate', investigate_data())
        prompts = feed('example.com', answer, '2')
        gt.handle_choice(10)
        assert investigate.calls == [(('example.com',), {'depth': depth})]
        assert '接力深度?' in prompts[1]
        assert ' 综合调查报告: example.com' in capsys.readouterr().out.splitlines()

    def test_save_dir_file_name(self, feed, fake, tmp_path):
        fake('do_investigate', {'_error': '仅支持域名', 'target': '8.8.8.8'})
        feed('8.8.8.8', '')
        out_dir = str(tmp_path / 'out') + '/'
        gt.handle_choice(10, save_dir=out_dir)
        name, saved = saved_json(out_dir)
        assert name.startswith('investigate_8.8.8.8_') and saved['_error'] == '仅支持域名'


# ==================================================================
# 五、语言解析链
# ==================================================================
LANG_ENV_VARS = ('SPYEYES_LANG', 'LC_ALL', 'LANG')


@pytest.fixture
def lang_env(monkeypatch):
    """先清空四个语言环境变量,再按需设置。"""
    for var in LANG_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    def _set(**env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
    return _set


class TestDetectLang:
    @pytest.mark.parametrize('env, expected', [
        ({}, 'en'),
        ({'LANG': 'zh_CN.UTF-8'}, 'zh'),
        ({'LANG': 'ZH_TW.UTF-8'}, 'zh'),                              # 不区分大小写
        ({'LANG': 'en_US.UTF-8'}, 'en'),
        ({'LANG': 'C'}, 'en'),
        ({'LANG': 'fr_FR.UTF-8'}, 'en'),
        ({'LANG': 'en_ZH'}, 'en'),                                    # 只看前缀
        ({'LC_ALL': 'zh_CN.UTF-8', 'LANG': 'en_US.UTF-8'}, 'zh'),     # LC_ALL > LANG
        ({'LC_ALL': 'en_US.UTF-8', 'LANG': 'zh_CN.UTF-8'}, 'en'),
        ({'SPYEYES_LANG': 'en', 'LC_ALL': 'zh_CN.UTF-8', 'LANG': 'zh_CN.UTF-8'}, 'en'),
        ({'SPYEYES_LANG': 'zh', 'LC_ALL': 'en_US.UTF-8', 'LANG': 'en_US.UTF-8'}, 'zh'),
        ({'SPYEYES_LANG': '', 'LANG': 'zh_CN.UTF-8'}, 'zh'),          # 空值当作没设
    ])
    def test_environment_precedence(self, lang_env, env, expected):
        lang_env(**env)
        assert gt.detect_lang() == expected


class TestResolveLanguage:
    def test_cli_flag_beats_config_and_environment(self, lang_env):
        lang_env(SPYEYES_LANG='zh', LANG='zh_CN.UTF-8')
        gt.save_config({'lang': 'zh'})
        assert gt.resolve_language(cli('--lang', 'en', 'myip')) == 'en'
        assert gt.resolve_language(cli('myip', '--lang', 'en')) == 'en'    # 写在子命令后面也一样

    def test_cli_flag_can_force_chinese(self, lang_env):
        lang_env(SPYEYES_LANG='en')
        gt.save_config({'lang': 'en'})
        assert gt.resolve_language(cli('ip', '8.8.8.8', '--lang', 'zh')) == 'zh'

    @pytest.mark.parametrize('saved, env_lang', [('en', 'zh'), ('zh', 'en')])
    def test_config_beats_environment(self, lang_env, saved, env_lang):
        lang_env(SPYEYES_LANG=env_lang, LANG=f'{env_lang}_XX.UTF-8')
        gt.save_config({'lang': saved})
        args = cli('myip')
        assert not hasattr(args, 'lang')       # 没传 --lang 时属性根本不存在(SUPPRESS)
        assert gt.resolve_language(args) == saved

    @pytest.mark.parametrize('env, expected', [({'SPYEYES_LANG': 'zh'}, 'zh'), ({'LANG': 'zh_CN.UTF-8'}, 'zh'),
                                               ({'LANG': 'en_US.UTF-8'}, 'en'), ({}, 'en')])
    def test_environment_used_when_no_flag_and_no_config(self, lang_env, env, expected):
        lang_env(**env)
        assert not os.path.exists(gt.CONFIG_FILE)
        assert gt.resolve_language(cli('myip')) == expected

    @pytest.mark.parametrize('config', [{'lang': 'fr'}, {'lang': None}, {'lang': ''}, {'theme': 'classic'}])
    def test_unusable_config_language_falls_through_to_environment(self, lang_env, config):
        lang_env(SPYEYES_LANG='zh')
        gt.save_config(config)
        assert gt.resolve_language(cli('myip')) == 'zh'

    def test_corrupt_config_file_falls_through_to_environment(self, lang_env):
        lang_env(LANG='zh_CN.UTF-8')
        os.makedirs(gt.CONFIG_DIR, exist_ok=True)
        with open(gt.CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write('{not json')
        assert gt.resolve_language(cli('myip')) == 'zh'

    @pytest.mark.parametrize('content', ['[]', 'null', '"en"', '{"lang": ["zh"]}'])
    def test_wrong_shaped_config_file_falls_through_to_environment(self, lang_env, content):
        lang_env(LANG='zh_CN.UTF-8')
        os.makedirs(gt.CONFIG_DIR, exist_ok=True)
        with open(gt.CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        assert gt.resolve_language(cli('myip')) == 'zh'

    def test_resolving_does_not_change_the_active_language(self, lang_env):
        gt.resolve_language(cli('--lang', 'en', 'myip'))
        assert gt.get_lang() == 'zh'


# ==================================================================
# 六、run_cli 的人类可读(非 JSON)路径
# ==================================================================
class TestRunCliHumanOutput:
    def last_history(self):
        entry = gt.read_history()[-1]
        entry.pop('ts')
        return entry

    # ---- ip / myip / phone ----
    def test_ip(self, fake, capsys):
        track = fake('track_ip', ip_data())
        assert gt.run_cli(cli('ip', '8.8.8.8')) == 0
        assert track.calls == [(('8.8.8.8',), {})]
        out = capsys.readouterr().out
        assert fields(out)['目标 IP'] == '8.8.8.8' and fields(out)['国家'] == '美国 (United States)'
        assert '"country"' not in out          # 不是 JSON
        assert self.last_history() == {'cmd': 'ip', 'query': '8.8.8.8', 'target': '8.8.8.8', 'ok': True}

    def test_ip_error_exits_1(self, fake, capsys):
        fake('track_ip', {'_error': '非法 IP'})
        assert gt.run_cli(cli('ip', 'nope')) == 1
        assert ' 查询失败：非法 IP' in capsys.readouterr().out.splitlines()
        assert self.last_history()['ok'] is False

    def test_myip(self, fake, capsys):
        gt.set_lang('en')
        fake('show_my_ip', '203.0.113.7')
        assert gt.run_cli(cli('myip')) == 0
        assert ' [ + ] Your IP address : 203.0.113.7' in capsys.readouterr().out.splitlines()

    def test_myip_failure_exits_1(self, fake, capsys):
        fake('show_my_ip', None)
        assert gt.run_cli(cli('myip')) == 1
        assert ' 查询失败，请检查网络' in capsys.readouterr().out.splitlines()

    def test_phone_passes_region(self, fake, capsys):
        track = fake('track_phone', phone_data())
        assert gt.run_cli(cli('phone', '2025550100', '--region', 'US')) == 0
        assert track.calls == [(('2025550100',), {'default_region': 'US'})]
        assert fields(capsys.readouterr().out)['国际格式'] == '+86 138 0013 8000'

    def test_phone_default_region_is_cn(self, fake):
        track = fake('track_phone', phone_data())
        gt.run_cli(cli('phone', '13800138000'))
        assert track.calls == [(('13800138000',), {'default_region': 'CN'})]

    def test_phone_error_exits_1(self, fake, capsys):
        fake('track_phone', {'_error': '号码无效'})
        assert gt.run_cli(cli('phone', '+1')) == 1
        assert ' 号码无效' in capsys.readouterr().out.splitlines()

    # ---- user ----
    def test_user_default(self, fake, capsys, platforms):
        scan = fake('track_username', username_results())
        assert gt.run_cli(cli('user', 'alice')) == 0
        assert scan.calls == [(('alice',), {'max_workers': 150, 'timeout': 5.0, 'categories': None})]
        out = capsys.readouterr().out
        assert ' 共扫描 9 个平台，命中 3 个：' in out.splitlines()
        assert 'https://nf.test/alice' in out and 'MissSite' not in out
        assert self.last_history() == {'cmd': 'user', 'query': 'alice', 'username': 'alice',
                                       'scanned': 9, 'found': 3}

    def test_user_all_shows_misses(self, fake, capsys, platforms):
        fake('track_username', username_results())
        assert gt.run_cli(cli('user', 'alice', '--all')) == 0
        out = capsys.readouterr().out
        assert line_with(out, 'MissSite') == miss_line('★  ', 'MissSite', '未找到')
        assert line_with(out, 'WafSite') == miss_line('★  ', 'WafSite', '[ 被拦截 ]')

    def test_user_quick_skips_other(self, fake, platforms):
        scan = fake('track_username', username_results())
        gt.run_cli(cli('user', 'alice', '--quick', '--workers', '7', '--timeout', '1.5'))
        assert scan.calls == [(('alice',), {'max_workers': 7, 'timeout': 1.5, 'categories': QUICK_CATEGORIES})]

    def test_user_category_overrides_quick_with_warning(self, fake, capsys, platforms):
        scan = fake('track_username', username_results())
        assert gt.run_cli(cli('user', 'alice', '--category', ' code, social ,', '--quick')) == 0
        assert scan.calls[0][1]['categories'] == ['code', 'social']
        assert '[warn] 已指定 --category,--quick 被忽略' in capsys.readouterr().err

    def test_user_category_alone_prints_no_warning(self, fake, capsys, platforms):
        fake('track_username', username_results())
        gt.run_cli(cli('user', 'alice', '--category', 'code'))
        assert capsys.readouterr().err == ''

    @pytest.mark.parametrize('depth_args, depth', [([], 2), (['--depth', '1'], 1), (['--depth', '9'], 2),
                                                   (['--depth', '-1'], 0)])
    def test_user_recursive(self, fake, capsys, platforms, depth_args, depth):
        result = username_results()
        result['_recursive'] = {'levels': [{'depth': 0, 'username': 'alice', 'found': 3},
                                           {'depth': 1, 'username': 'alice_dev', 'found': 4}],
                                'total_found': 7, 'depth_reached': 1}
        recurse = fake('recursive_track_username', result)
        assert gt.run_cli(cli('user', 'alice', '--recursive', *depth_args)) == 0
        assert recurse.calls == [(('alice',), {'max_depth': depth, 'max_workers': 150,
                                               'timeout': 5.0, 'categories': None})]
        out = capsys.readouterr().out
        assert '  [depth 1] alice_dev  →  命中 4 个' in out.splitlines()
        assert out.index('递归扫描结束。共 7 个平台，2 层。') < out.index('共扫描 9 个平台，命中 3 个：')
        assert self.last_history() == {'cmd': 'user', 'query': 'alice', 'username': 'alice',
                                       'scanned': 9, 'found': 7, 'recursive': 2}

    def test_user_error_exits_1(self, fake, capsys):
        fake('track_username', {'_error': '用户名过长'})
        assert gt.run_cli(cli('user', 'x' * 80)) == 1
        assert ' 查询失败：用户名过长' in capsys.readouterr().out.splitlines()

    # ---- permute ----
    def test_permute_lists_variations(self, capsys):
        gt.set_lang('en')
        assert gt.run_cli(cli('permute', 'alice', '--method', 'all')) == 0     # 真实的 permute_username(纯函数)
        lines = capsys.readouterr().out.splitlines()
        assert ' Generated 3 variations from "alice":' in lines
        assert [line for line in lines if '•' in line] == ['  • alice', '  • _alice', '  • alice_']
        assert self.last_history() == {'cmd': 'permute', 'query': 'alice', 'name': 'alice', 'variations': 3}

    def test_permute_strict_is_the_default_method(self, capsys):
        gt.run_cli(cli('permute', 'alice'))
        assert [line for line in capsys.readouterr().out.splitlines() if '•' in line] == ['  • alice']

    @pytest.mark.parametrize('lang, expected', [('zh', ' 无法生成变形：输入为空'),
                                                ('en', ' Cannot generate permutations: input is empty')])
    def test_permute_nothing_to_generate_exits_1(self, capsys, lang, expected):
        gt.set_lang(lang)
        assert gt.run_cli(cli('permute', '!!!')) == 1
        assert capsys.readouterr().out.splitlines() == [expected]

    def test_permute_scan(self, fake, monkeypatch, capsys, platforms):
        monkeypatch.setattr(gt, 'permute_username', Recorder(['johndoe', 'doejohn']))
        scan = fake('track_username', lambda name, **kw: {
            'StrictSite': f'https://strict.test/{name}' if name == 'doejohn' else None, 'MissSite': None})
        assert gt.run_cli(cli('permute', 'John Doe', '--scan', '--quick', '--workers', '9')) == 0
        assert scan.calls == [
            (('johndoe',), {'max_workers': 9, 'categories': QUICK_CATEGORIES, 'show_progress': True}),
            (('doejohn',), {'max_workers': 9, 'categories': QUICK_CATEGORIES, 'show_progress': True})]
        lines = capsys.readouterr().out.splitlines()
        assert ' 从 "John Doe" 生成 2 个变形：' in lines
        first, second = lines.index(' ━━━ johndoe ━━━'), lines.index(' ━━━ doejohn ━━━')
        assert ' 共扫描 2 个平台，命中 0 个：' in lines[first:second]
        assert hit_line('★★★', 'StrictSite', 'https://strict.test/doejohn') in lines[second:]
        assert self.last_history() == {'cmd': 'permute', 'query': 'John Doe', 'name': 'John Doe',
                                       'variations': 2, 'found': 1}

    def test_permute_scan_without_quick_scans_everything(self, fake, monkeypatch, platforms):
        monkeypatch.setattr(gt, 'permute_username', Recorder(['johndoe']))
        scan = fake('track_username', {'MissSite': None})
        gt.run_cli(cli('permute', 'John Doe', '--scan'))
        assert scan.calls == [(('johndoe',), {'max_workers': 150, 'categories': None, 'show_progress': True})]

    # ---- whois / mx ----
    def test_whois_single(self, fake, capsys):
        lookup = fake('whois_lookup', whois_data())
        assert gt.run_cli(cli('whois', 'example.com')) == 0
        assert lookup.calls == [(('example.com',), {})]
        out = capsys.readouterr().out
        assert fields(out)['注册组织'] == 'Internet Assigned Numbers Authority'
        assert '━━━' not in out                # 单域名不打批量分隔条
        assert self.last_history() == {'cmd': 'whois', 'query': 'example.com', 'domains': ['example.com']}

    def test_whois_single_error_exits_1(self, fake, capsys):
        fake('whois_lookup', {'_error': 'WHOIS 查询失败'})
        assert gt.run_cli(cli('whois', 'example.com')) == 1
        assert ' WHOIS 查询失败' in capsys.readouterr().out.splitlines()

    def test_whois_batch_prints_each_domain_in_input_order(self, fake, capsys):
        fake('whois_lookup', lambda d: whois_data(domain=d.upper(), registrar=f'Registrar of {d}'))
        assert gt.run_cli(cli('whois', 'b.example', 'a.example')) == 0
        lines = capsys.readouterr().out.splitlines()
        first, second = lines.index(' ━━━ b.example ━━━'), lines.index(' ━━━ a.example ━━━')
        assert first < second
        assert fields('\n'.join(lines[first:second]))['注册商'] == 'Registrar of b.example'
        assert fields('\n'.join(lines[second:]))['注册商'] == 'Registrar of a.example'

    def test_whois_batch_with_one_failure_exits_1(self, fake, capsys):
        fake('whois_lookup', lambda d: {'_error': f'{d} 查不到'} if d == 'bad.example' else whois_data())
        assert gt.run_cli(cli('whois', 'example.com', 'bad.example')) == 1
        out = capsys.readouterr().out
        assert ' bad.example 查不到' in out.splitlines()
        assert fields(out)['注册商'] == 'Example Registrar, Inc.'      # 成功的那个照常打印

    def test_mx_single(self, fake, capsys):
        gt.set_lang('en')
        lookup = fake('mx_lookup', mx_data())
        assert gt.run_cli(cli('mx', 'example.com')) == 0
        assert lookup.calls == [(('example.com',), {})]
        out = capsys.readouterr().out
        assert '  Priority    5  →  mx2.example.com' in out.splitlines()
        assert '━━━' not in out

    def test_mx_single_error_exits_1(self, fake, capsys):
        fake('mx_lookup', {'_error': '域名不存在', '_error_kind': 'nxdomain'})
        assert gt.run_cli(cli('mx', 'nope.example')) == 1
        assert ' 域名不存在' in capsys.readouterr().out.splitlines()

    def test_mx_batch_keeps_underscore_domains(self, fake, capsys):
        fake('mx_lookup', lambda d: {'domain': d, 'records': [{'preference': 1, 'exchange': f'mx.{d}'}]})
        assert gt.run_cli(cli('mx', '_dmarc.example.com', 'example.org')) == 0
        lines = capsys.readouterr().out.splitlines()
        assert ' ━━━ _dmarc.example.com ━━━' in lines and ' ━━━ example.org ━━━' in lines
        assert '  优先级    1  →  mx._dmarc.example.com' in lines
        assert self.last_history() == {'cmd': 'mx', 'query': '_dmarc.example.com,example.org',
                                       'domains': ['_dmarc.example.com', 'example.org']}

    def test_mx_batch_all_failed_exits_1(self, fake, capsys):
        fake('mx_lookup', lambda d: {'_error': f'{d}: 无 MX'})
        assert gt.run_cli(cli('mx', 'a.example', 'b.example')) == 1
        lines = capsys.readouterr().out.splitlines()
        assert ' a.example: 无 MX' in lines and ' b.example: 无 MX' in lines

    # ---- email ----
    def test_email(self, fake, capsys):
        validate = fake('email_validate', email_data())
        assert gt.run_cli(cli('email', 'a@example.com')) == 0
        assert validate.calls == [(('a@example.com',), {})]
        assert '   → 优先级   10  mx1.example.com' in capsys.readouterr().out.splitlines()
        assert self.last_history() == {'cmd': 'email', 'query': 'a@example.com',
                                       'address': 'a@example.com', 'mx_valid': True}

    def test_email_bad_syntax_exits_1(self, fake, capsys):
        fake('email_validate', {'email': 'bad', 'syntax_valid': False, '_error': '邮箱格式不合法'})
        assert gt.run_cli(cli('email', 'bad')) == 1
        assert ' 邮箱格式不合法' in capsys.readouterr().out.splitlines()

    # ---- subdomain ----
    def test_subdomain_defaults(self, fake, capsys):
        enum = fake('enumerate_subdomains', subdomain_data())
        assert gt.run_cli(cli('subdomain', 'example.com')) == 0
        assert enum.calls == [(('example.com',), {'probe': True, 'max_workers': 30, 'probe_timeout': 4.0,
                                                  'bruteforce': False, 'js_extract': True,
                                                  'show_progress': True})]
        lines = capsys.readouterr().out.splitlines()
        assert ' 共发现 4 个 · 活跃 3 个 · 来自 2 个数据源' in lines
        assert ' [ - ] old.example.com' in lines
        assert self.last_history() == {'cmd': 'subdomain', 'query': 'example.com', 'domain': 'example.com',
                                       'total': 4, 'alive': 3, 'wildcard': False}

    def test_subdomain_flags_are_passed_through(self, fake):
        enum = fake('enumerate_subdomains', subdomain_data())
        gt.run_cli(cli('subdomain', 'example.com', '--no-probe', '--workers', '5', '--timeout', '1.5',
                       '--bruteforce', '--no-js-extract'))
        assert enum.calls[0][1] == {'probe': False, 'max_workers': 5, 'probe_timeout': 1.5,
                                    'bruteforce': True, 'js_extract': False, 'show_progress': True}

    def test_subdomain_alive_only_hides_dead_hosts(self, fake, capsys):
        fake('enumerate_subdomains', subdomain_data())
        assert gt.run_cli(cli('subdomain', 'example.com', '--alive-only')) == 0
        out = capsys.readouterr().out
        assert 'old.example.com' not in out and '不可达' not in out
        assert ' ┌─ 活跃子域 (3) ─' in out.splitlines()

    def test_subdomain_error_exits_1(self, fake, capsys):
        fake('enumerate_subdomains', {'_error': '域名非法'})
        assert gt.run_cli(cli('subdomain', 'bad domain')) == 1
        assert ' 查询失败：域名非法' in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('lang, expected', [
        ('zh', 'subdomain:需要提供域名或 --batch 文件\n'),
        ('en', 'subdomain: a domain or --batch FILE is required\n'),
    ])
    def test_subdomain_without_domain_exits_2(self, capsys, lang, expected):
        gt.set_lang(lang)
        assert gt.run_cli(cli('subdomain')) == 2      # enumerate_subdomains 没被替换:调了就失败
        captured = capsys.readouterr()
        assert captured.err == expected and captured.out == ''
        assert gt.read_history() == []

    # ---- domain-emails ----
    def test_domain_emails_defaults(self, fake, capsys):
        enum = fake('enumerate_domain_emails', demails_data())
        assert gt.run_cli(cli('domain-emails', 'example.com')) == 0
        assert enum.calls == [(('example.com',), {
            'crawl': True, 'include_subdomains': True, 'max_pages': 200, 'max_depth': 5,
            'obey_robots': True, 'guess_names': None, 'verify_smtp': False, 'show_progress': True})]
        out = capsys.readouterr().out
        assert ' 共找到 4 个邮箱(爬取 12 页 · sitemap:✓)' in out.splitlines()
        assert line_with(out, 'ceo@example.com').endswith('[✓ 已验证]')
        assert self.last_history() == {'cmd': 'domain-emails', 'query': 'example.com', 'domain': 'example.com',
                                       'total': 4, 'pages_crawled': 12, 'verified': 1}

    def test_domain_emails_flags_are_passed_through(self, fake):
        enum = fake('enumerate_domain_emails', demails_data())
        gt.run_cli(cli('domain-emails', 'example.com', '--no-crawl', '--no-include-subdomains',
                       '--max-pages', '500', '--crawl-depth', '2', '--ignore-robots',
                       '--guess', 'John Doe,Jane Roe', '--verify-smtp'))
        assert enum.calls[0][1] == {
            'crawl': False, 'include_subdomains': False, 'max_pages': 500, 'max_depth': 2,
            'obey_robots': False, 'guess_names': 'John Doe,Jane Roe', 'verify_smtp': True,
            'show_progress': True}

    def test_domain_emails_error_exits_1(self, fake, capsys):
        fake('enumerate_domain_emails', {'_error': '域名非法'})
        assert gt.run_cli(cli('domain-emails', 'bad domain')) == 1
        assert ' 查询失败：域名非法' in capsys.readouterr().out.splitlines()

    # ---- history ----
    def test_history_empty(self, capsys):
        assert gt.run_cli(cli('history')) == 0
        assert ' （暂无历史 —— 先跑一次查询试试）' in capsys.readouterr().out.splitlines()

    def test_history_lists_search_and_limit(self, capsys):
        gt.append_history('ip', '8.8.8.8', {'ok': True})
        gt.append_history('user', 'alice', {'scanned': 10, 'found': 2})
        gt.append_history('ip', '1.1.1.1', {'ok': False})

        def rows():
            return [line.split()[1:] for line in capsys.readouterr().out.splitlines() if line.startswith('  20')]

        assert gt.run_cli(cli('history')) == 0
        assert rows() == [['ip', '8.8.8.8', '[✓]'], ['user', 'alice', '[2/10]'], ['ip', '1.1.1.1', '[✗]']]
        assert gt.run_cli(cli('history', '--search', 'ALICE')) == 0
        assert rows() == [['user', 'alice', '[2/10]']]
        assert gt.run_cli(cli('history', '--limit', '1')) == 0
        assert rows() == [['ip', '1.1.1.1', '[✗]']]
        assert len(gt.read_history()) == 3      # 看历史本身不写历史

    def test_query_then_history_round_trip(self, fake, capsys, platforms):
        fake('track_username', username_results())
        gt.run_cli(cli('user', 'alice'))
        capsys.readouterr()
        gt.run_cli(cli('history'))
        assert line_with(capsys.readouterr().out, 'alice').endswith('user  alice  [3/9]')

    # ---- diff ----
    def write_scan(self, path, hosts):
        path.write_text(json.dumps({'domain': 'example.com', 'subdomains': hosts}), encoding='utf-8')
        return str(path)

    def test_diff(self, tmp_path, capsys):
        old = self.write_scan(tmp_path / 'old.json', [
            {'host': 'api.example.com', 'alive': True, 'a': ['1.1.1.1'], 'http_status': 200},
            {'host': 'gone.example.com', 'alive': True, 'a': ['2.2.2.2']},
            {'host': 'same.example.com', 'alive': True, 'a': ['4.4.4.4']}])
        new = self.write_scan(tmp_path / 'new.json', [
            {'host': 'api.example.com', 'alive': True, 'a': ['1.1.1.1'], 'http_status': 503},
            {'host': 'new.example.com', 'alive': True, 'a': ['3.3.3.3'], 'http_status': 200},
            {'host': 'same.example.com', 'alive': True, 'a': ['4.4.4.4']}])
        assert gt.run_cli(cli('diff', old, new)) == 0
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert ' 新增 1 个 · 消失 1 个 · 变更 1 个 · 不变 1 个' in lines
        assert f"   + {col('new.example.com', 45)} {col('3.3.3.3', 20)} HTTP 200" in lines
        assert f"   - {col('gone.example.com', 45)} {col('2.2.2.2', 20)}" in lines
        assert '     http_status: 200 → 503' in lines
        assert 'same.example.com' not in out
        assert gt.read_history() == []          # diff 不写历史

    def test_diff_save_writes_the_diff(self, tmp_path, capsys):
        old = self.write_scan(tmp_path / 'old.json', [{'host': 'gone.example.com', 'alive': True}])
        new = self.write_scan(tmp_path / 'new.json', [{'host': 'new.example.com', 'alive': True}])
        target = tmp_path / 'd.json'
        assert gt.run_cli(cli('diff', old, new, '--save', str(target))) == 0
        saved = json.loads(target.read_text(encoding='utf-8'))
        assert [s['host'] for s in saved['added']] == ['new.example.com']
        assert [s['host'] for s in saved['removed']] == ['gone.example.com']
        assert f' [ 已保存到 {target} ]' in capsys.readouterr().out.splitlines()

    def test_diff_identical_scans(self, tmp_path, capsys):
        scan = self.write_scan(tmp_path / 'scan.json', [{'host': 'a.example.com', 'alive': True}])
        assert gt.run_cli(cli('diff', scan, scan)) == 0
        assert ' 无变化 — 两次扫描完全一致' in capsys.readouterr().out.splitlines()

    @pytest.mark.parametrize('missing', ['old', 'new'])
    def test_diff_unreadable_file_exits_2(self, tmp_path, capsys, missing):
        good = self.write_scan(tmp_path / 'good.json', [])
        bad = str(tmp_path / 'missing.json')
        argv = ('diff', bad, good) if missing == 'old' else ('diff', good, bad)
        assert gt.run_cli(cli(*argv)) == 2
        captured = capsys.readouterr()
        assert captured.err.startswith(f'加载 JSON 失败:{bad}: ')
        assert captured.out == ''

    def test_diff_broken_json_exits_2(self, tmp_path, capsys):
        good = self.write_scan(tmp_path / 'good.json', [])
        broken = tmp_path / 'broken.json'
        broken.write_text('{not json', encoding='utf-8')
        gt.set_lang('en')
        assert gt.run_cli(cli('diff', good, str(broken))) == 2
        assert capsys.readouterr().err.startswith(f'Failed to load JSON: {broken}: ')

    def test_diff_wrong_shape_exits_2(self, tmp_path, capsys):
        good = self.write_scan(tmp_path / 'good.json', [])
        a_list = tmp_path / 'list.json'
        a_list.write_text('[1, 2, 3]', encoding='utf-8')
        assert gt.run_cli(cli('diff', str(a_list), good)) == 2
        captured = capsys.readouterr()
        assert captured.err == '输入无效 — 两份文件必须是 enumerate_subdomains() 的 JSON 输出\n'
        assert captured.out == ''

    # ---- investigate ----
    def test_investigate_defaults(self, fake, capsys):
        investigate = fake('do_investigate', investigate_data())
        assert gt.run_cli(cli('investigate', 'example.com')) == 0
        assert investigate.calls == [(('example.com',), {
            'depth': 1, 'budget': 300.0, 'max_pivot_ips': 20, 'max_pivot_emails': 15,
            'quick': True, 'probe': True, 'show_progress': True})]
        lines = capsys.readouterr().out.splitlines()
        assert ' 综合调查报告: example.com' in lines
        assert '     GitHub: https://github.com/john.doe' in lines
        assert self.last_history() == {'cmd': 'investigate', 'query': 'example.com', 'target': 'example.com',
                                       'tasks_done': 4, 'tasks_failed': 0, 'pivots_done': 2, 'elapsed': 12.34}

    def test_investigate_flags_are_passed_through(self, fake):
        investigate = fake('do_investigate', investigate_data())
        gt.run_cli(cli('investigate', 'example.com', '--depth', '0', '--budget', '45',
                       '--max-pivot-ips', '3', '--max-pivot-emails', '4', '--no-quick', '--no-probe'))
        assert investigate.calls[0][1] == {
            'depth': 0, 'budget': 45.0, 'max_pivot_ips': 3, 'max_pivot_emails': 4,
            'quick': False, 'probe': False, 'show_progress': True}

    def test_investigate_error_exits_1(self, fake, capsys):
        fake('do_investigate', {'_error': '仅支持域名', 'target': '8.8.8.8', 'entity_type': 'ip'})
        assert gt.run_cli(cli('investigate', '8.8.8.8')) == 1
        assert ' 查询失败：仅支持域名' in capsys.readouterr().out.splitlines()

    # ---- --save 与人类可读输出并存 ----
    def test_save_writes_report_and_still_prints(self, fake, tmp_path, capsys):
        fake('track_ip', ip_data())
        target = tmp_path / 'r.md'
        assert gt.run_cli(cli('ip', '8.8.8.8', '--save', str(target))) == 0
        out = capsys.readouterr().out
        assert fields(out)['城市'] == 'Mountain View'
        assert f' [ 已保存到 {target} ]' in out.splitlines()
        assert 'Mountain View' in target.read_text(encoding='utf-8')

    def test_save_still_happens_when_the_query_failed(self, fake, tmp_path):
        fake('track_ip', {'_error': '非法 IP'})
        target = tmp_path / 'r.json'
        assert gt.run_cli(cli('ip', 'nope', '--save', str(target))) == 1
        assert json.loads(target.read_text(encoding='utf-8')) == {'_error': '非法 IP'}
