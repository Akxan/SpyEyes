"""SpyEyes 底层函数与报告分支的补充测试。

体检发现下面这些代码要么从没被测试执行过，要么一直被 mock 掉、本体没测：
safe_get / _get_session、DNS 解析（_resolve_one_subdomain / _detect_wildcard_dns）、
_verify_smtp、_fetch_latest_version_from_github、_batch_lookup、mx_lookup / email_validate
的成功路径、_check_username 的 must_contain、recursive_track_username 的真实展开、
用户名 / 变形结果在各报告格式里的分支、_maybe_save 的后缀分发、do_investigate 的预算截停。

全部走替身：没有真实网络、DNS、SMTP、子进程，也不真的睡眠。

运行：
    pytest tests/test_low_level.py -q
"""

import csv
import io
import json
import os
import re
import smtplib
import sys
import threading
import time
import zipfile
from html.parser import HTMLParser
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest
import requests

# 让 tests/ 能 import 上层 spyeyes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402

needs_dns = pytest.mark.skipif(not gt.HAS_DNS, reason='dnspython not installed')


# ====================================================================
# 共用替身
# ====================================================================
class _FakeRaw:
    """最小的 urllib3 响应体替身：支持 read(n, decode_content=...) 和 close()，
    并记下一共被读走多少字节、有没有被关闭。"""

    def __init__(self, body: bytes):
        self._buf = io.BytesIO(body)
        self.bytes_read = 0
        self.closed = False

    def read(self, amt=-1, decode_content=False):
        chunk = self._buf.read(amt)
        self.bytes_read += len(chunk)
        return chunk

    def close(self):
        self.closed = True


def _real_response(status: int, body: bytes = b'', headers=None) -> requests.Response:
    """真实的 requests.Response（MagicMock 响应恒为真值、属性任取，测不出状态码语义）。"""
    resp = requests.Response()
    resp.status_code = status
    resp.raw = _FakeRaw(body)
    resp.encoding = 'utf-8'
    resp.headers.update(headers or {})
    return resp


class _FakeTime:
    """顶替 spyeyes 模块里的 `time`：time() 走可控时钟，sleep() 只拨表不真睡，
    strftime() 默认格式化这个假时刻（报告里的时间戳因此固定），其余属性原样转发。
    只换掉 gt.time 这个名字，不碰全局 time 模块 —— pytest / 线程池自己的计时不受影响。"""

    def __init__(self, start: float = 1_800_000_000.0):
        self._now = start
        self._lock = threading.Lock()

    def time(self) -> float:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += seconds

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def strftime(self, fmt, when=None):
        return time.strftime(fmt, time.localtime(self.time()) if when is None else when)

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def clock(monkeypatch):
    fake = _FakeTime()
    monkeypatch.setattr(gt, 'time', fake)
    return fake


# ====================================================================
# 1. safe_get / _get_session
# ====================================================================
class _RecordingSession:
    """假 session：记录 get / head 调用，返回预置对象或抛预置异常。"""

    def __init__(self):
        self.result = None
        self.exc = None
        self.calls = []

    def _call(self, verb, url, kwargs):
        self.calls.append((verb, url, kwargs))
        if self.exc is not None:
            raise self.exc
        return self.result

    def get(self, url, **kwargs):
        return self._call('GET', url, kwargs)

    def head(self, url, **kwargs):
        return self._call('HEAD', url, kwargs)


@pytest.fixture
def fake_session(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(gt, '_get_session', lambda: session)
    return session


class TestSafeGet:
    URL = 'https://api.example.test/v1/thing'

    def test_default_is_one_get_and_its_result_is_returned(self, fake_session):
        fake_session.result = sentinel = object()
        assert gt.safe_get(self.URL) is sentinel
        assert fake_session.calls == [
            ('GET', self.URL, {'timeout': (3.0, gt.DEFAULT_TIMEOUT), 'headers': {}, 'stream': False}),
        ]

    @pytest.mark.parametrize('method', ['HEAD', 'head', 'Head'])
    def test_head_method_goes_to_session_head(self, fake_session, method):
        fake_session.result = sentinel = object()
        assert gt.safe_get(self.URL, method=method, timeout=5) is sentinel
        # HEAD 没有响应体：不带 stream 参数，也绝不能顺手再发一个 GET
        assert fake_session.calls == [('HEAD', self.URL, {'timeout': (3.0, 5), 'headers': {}})]

    @pytest.mark.parametrize('method', ['GET', 'HEAD'])
    @pytest.mark.parametrize('timeout,expected', [
        (10, (3.0, 10)),       # 读超时长 → 连接超时封顶 3 秒
        (45.0, (3.0, 45.0)),
        (3, (3.0, 3)),
        (1.5, (1.5, 1.5)),     # 读超时不足 3 秒 → 连接超时跟着缩短，不能比总超时还长
        (0.2, (0.2, 0.2)),
    ])
    def test_connect_timeout_defaults_to_min_of_3s_and_timeout(self, fake_session, method, timeout, expected):
        gt.safe_get(self.URL, timeout=timeout, method=method)
        (_, _, kwargs), = fake_session.calls
        assert kwargs['timeout'] == expected

    @pytest.mark.parametrize('method', ['GET', 'HEAD'])
    @pytest.mark.parametrize('connect,timeout', [(10.0, 45.0), (0.5, 10), (8.0, 2.0)])
    def test_explicit_connect_timeout_wins(self, fake_session, method, connect, timeout):
        gt.safe_get(self.URL, timeout=timeout, connect_timeout=connect, method=method)
        (_, _, kwargs), = fake_session.calls
        assert kwargs['timeout'] == (connect, timeout)

    @pytest.mark.parametrize('method', ['GET', 'HEAD'])
    def test_headers_are_forwarded(self, fake_session, method):
        headers = {'Authorization': 'Bearer tok', 'Accept': 'application/json'}
        gt.safe_get(self.URL, headers=headers, method=method)
        (verb, _, kwargs), = fake_session.calls
        assert verb == method
        assert kwargs['headers'] == {'Authorization': 'Bearer tok', 'Accept': 'application/json'}

    def test_headers_none_becomes_empty_dict(self, fake_session):
        gt.safe_get(self.URL, headers=None)
        (_, _, kwargs), = fake_session.calls
        assert kwargs['headers'] == {}

    @pytest.mark.parametrize('stream', [True, False])
    def test_stream_flag_is_forwarded_to_get(self, fake_session, stream):
        gt.safe_get(self.URL, stream=stream)
        (_, _, kwargs), = fake_session.calls
        assert kwargs['stream'] is stream

    @pytest.mark.parametrize('method', ['GET', 'HEAD'])
    def test_other_keyword_arguments_pass_through(self, fake_session, method):
        gt.safe_get(self.URL, method=method, allow_redirects=False, params={'q': 'x'})
        (_, url, kwargs), = fake_session.calls
        assert url == self.URL
        assert kwargs['allow_redirects'] is False
        assert kwargs['params'] == {'q': 'x'}

    @pytest.mark.parametrize('method', ['GET', 'HEAD'])
    @pytest.mark.parametrize('exc', [
        requests.exceptions.RequestException('generic'),
        requests.exceptions.ConnectionError('refused'),
        requests.exceptions.Timeout('slow'),
        requests.exceptions.TooManyRedirects('loop'),
        ValueError('unparseable url'),
        UnicodeError('idna label too long'),
        OSError('network unreachable'),
    ], ids=lambda e: type(e).__name__)
    def test_request_errors_return_none(self, fake_session, method, exc):
        fake_session.exc = exc
        assert gt.safe_get(self.URL, method=method) is None
        assert len(fake_session.calls) == 1   # 确实发起过请求，而不是什么都没做就返回 None

    def test_failure_to_build_the_session_returns_none(self, monkeypatch):
        def broken():
            raise OSError('too many open files')
        monkeypatch.setattr(gt, '_get_session', broken)
        assert gt.safe_get(self.URL) is None

    @pytest.mark.parametrize('status', [404, 429, 503])
    def test_error_status_is_still_a_response_not_none(self, fake_session, status):
        """4xx / 5xx 的 Response 是 falsy（bool(resp) == resp.ok）。safe_get 必须把它原样交回，
        由调用方用 `is None` 区分「没连上」和「连上了但被拒」。"""
        resp = _real_response(status)
        fake_session.result = resp
        got = gt.safe_get(self.URL)
        assert got is resp
        assert got is not None and not got


class TestGetSession:
    def test_same_thread_reuses_one_session(self):
        first = gt._get_session()
        assert isinstance(first, requests.Session)
        assert gt._get_session() is first

    def test_each_thread_gets_its_own_session(self):
        main = gt._get_session()
        seen = {}

        def worker(key):
            first, second = gt._get_session(), gt._get_session()
            seen[key] = (first, second)
            first.close()

        threads = [threading.Thread(target=worker, args=(key,)) for key in ('t1', 't2')]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=5)
        assert set(seen) == {'t1', 't2'}
        (a1, a2), (b1, b2) = seen['t1'], seen['t2']
        assert a1 is a2 and b1 is b2          # 线程内复用
        assert a1 is not b1                   # 线程间隔离
        assert a1 is not main and b1 is not main
        assert gt._get_session() is main      # 别的线程建 session 不影响本线程

    def test_session_has_browser_ua_and_big_no_retry_pool(self):
        session = gt._get_session()
        assert session.headers['User-Agent'] == gt.DEFAULT_HEADERS['User-Agent']
        https = session.get_adapter('https://example.test/')
        assert session.get_adapter('http://example.test/') is https
        assert (https._pool_connections, https._pool_maxsize) == (200, 200)
        assert https.max_retries.total == 0   # 重试会让 150 线程扫描的长尾延迟翻倍


# ====================================================================
# 2. _resolve_one_subdomain / _detect_wildcard_dns
# ====================================================================
class _FakeResolver:
    """dns.resolver.Resolver 替身：按 (host, qtype) 查 answers；查不到用 default（默认 NXDOMAIN）。
    答案可以是记录列表、要抛的异常，或 (host, qtype) -> 前两者 的函数。"""

    def __init__(self):
        self.answers = {}
        self.default = gt.dns.resolver.NXDOMAIN()
        self.queries = []
        self.timeout = None
        self.lifetime = None

    def resolve(self, host, qtype):
        self.queries.append((host, qtype))
        answer = self.answers.get((host, qtype), self.default)
        if callable(answer):
            answer = answer(host, qtype)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def asked(self, qtype):
        return [host for host, kind in self.queries if kind == qtype]


def _cname(target: str) -> list:
    """一条 CNAME 应答（dnspython 的 target 是带结尾点的 Name）。"""
    return [SimpleNamespace(target=gt.dns.name.from_text(target))]


@pytest.fixture
def resolver(monkeypatch):
    """装一个假 Resolver；测试往 resolver.answers 里填应答。"""
    if not gt.HAS_DNS:
        pytest.skip('dnspython not installed')
    fake = _FakeResolver()
    monkeypatch.setattr(gt.dns.resolver, 'Resolver', lambda: fake)
    return fake


@needs_dns
class TestResolveOneSubdomain:
    HOST = 'www.example.com'

    def test_a_records_only(self, resolver):
        resolver.answers = {(self.HOST, 'A'): ['93.184.216.34', '10.0.0.7']}
        assert gt._resolve_one_subdomain(self.HOST) == {
            'host': self.HOST, 'alive': True,
            'a': ['10.0.0.7', '93.184.216.34'], 'aaaa': [], 'cname': None,
        }
        # 三种记录都问过，且只问了这个 host
        assert resolver.queries == [(self.HOST, 'A'), (self.HOST, 'AAAA'), (self.HOST, 'CNAME')]

    def test_aaaa_records_only(self, resolver):
        resolver.answers = {(self.HOST, 'AAAA'): ['2606:2800:220:1::1']}
        assert gt._resolve_one_subdomain(self.HOST) == {
            'host': self.HOST, 'alive': True,
            'a': [], 'aaaa': ['2606:2800:220:1::1'], 'cname': None,
        }

    def test_a_and_aaaa_are_kept_apart(self, resolver):
        resolver.answers = {(self.HOST, 'A'): ['1.2.3.4'], (self.HOST, 'AAAA'): ['2001:db8::1']}
        rec = gt._resolve_one_subdomain(self.HOST)
        assert (rec['a'], rec['aaaa'], rec['alive']) == (['1.2.3.4'], ['2001:db8::1'], True)

    def test_one_failing_record_type_does_not_hide_the_other(self, resolver):
        resolver.answers = {
            (self.HOST, 'A'): gt.dns.resolver.NoAnswer(),
            (self.HOST, 'AAAA'): ['2001:db8::1'],
            (self.HOST, 'CNAME'): gt.dns.exception.Timeout(),
        }
        rec = gt._resolve_one_subdomain(self.HOST)
        assert rec == {'host': self.HOST, 'alive': True, 'a': [], 'aaaa': ['2001:db8::1'], 'cname': None}

    def test_everything_failing_means_not_alive(self, resolver):
        assert gt._resolve_one_subdomain(self.HOST) == {
            'host': self.HOST, 'alive': False, 'a': [], 'aaaa': [], 'cname': None,
        }
        assert resolver.queries == [(self.HOST, 'A'), (self.HOST, 'AAAA'), (self.HOST, 'CNAME')]

    def test_timeout_and_lifetime_are_set_on_the_resolver(self, resolver):
        gt._resolve_one_subdomain(self.HOST, dns_timeout=1.25)
        assert (resolver.timeout, resolver.lifetime) == (1.25, 1.25)

    def test_default_timeout_is_the_module_constant(self, resolver):
        gt._resolve_one_subdomain(self.HOST)
        assert (resolver.timeout, resolver.lifetime) == (gt.SUBDOMAIN_DNS_TIMEOUT, gt.SUBDOMAIN_DNS_TIMEOUT)

    def test_trailing_dots_are_stripped_from_answers(self, resolver):
        resolver.answers = {
            (self.HOST, 'A'): ['1.2.3.4.'],
            (self.HOST, 'CNAME'): _cname('edge.cdn.example.net.'),
        }
        rec = gt._resolve_one_subdomain(self.HOST)
        assert rec['a'] == ['1.2.3.4']
        assert rec['cname'] == 'edge.cdn.example.net'

    def test_single_cname_alone_makes_the_host_alive(self, resolver):
        resolver.answers = {(self.HOST, 'CNAME'): _cname('ghs.googlehosted.com.')}
        assert gt._resolve_one_subdomain(self.HOST) == {
            'host': self.HOST, 'alive': True, 'a': [], 'aaaa': [], 'cname': 'ghs.googlehosted.com',
        }

    def test_multi_hop_cname_chain_is_followed_to_the_end(self, resolver):
        resolver.answers = {
            (self.HOST, 'CNAME'): _cname('cdn1.example.com.'),
            ('cdn1.example.com', 'CNAME'): _cname('lb.cdn.example.net.'),
            ('lb.cdn.example.net', 'CNAME'): _cname('edge-7.cloudflare.net.'),
        }
        rec = gt._resolve_one_subdomain(self.HOST)
        assert rec['cname'] == 'cdn1.example.com → lb.cdn.example.net → edge-7.cloudflare.net'
        assert rec['alive'] is True
        # 每一跳查的是上一跳的目标；链尾没有 CNAME 时停下
        assert resolver.asked('CNAME') == [
            self.HOST, 'cdn1.example.com', 'lb.cdn.example.net', 'edge-7.cloudflare.net',
        ]

    def test_cname_loop_terminates(self, resolver):
        resolver.answers = {
            ('a.example.com', 'CNAME'): _cname('b.example.com.'),
            ('b.example.com', 'CNAME'): _cname('a.example.com.'),
        }
        rec = gt._resolve_one_subdomain('a.example.com')
        assert resolver.asked('CNAME') == ['a.example.com', 'b.example.com']   # 绕回起点就不再查
        assert rec['cname'].split(' → ')[0] == 'b.example.com'
        assert rec['alive'] is True

    def test_cname_loop_detection_ignores_case(self, resolver):
        resolver.answers = {
            ('a.example.com', 'CNAME'): _cname('B.Example.COM.'),
            ('B.Example.COM', 'CNAME'): _cname('A.EXAMPLE.com.'),
        }
        gt._resolve_one_subdomain('a.example.com')
        assert resolver.asked('CNAME') == ['a.example.com', 'B.Example.COM']

    def test_cname_pointing_at_itself_is_not_a_chain(self, resolver):
        resolver.answers = {(self.HOST, 'CNAME'): _cname('WWW.example.com.')}
        rec = gt._resolve_one_subdomain(self.HOST)
        assert rec['cname'] is None
        assert rec['alive'] is False
        assert resolver.asked('CNAME') == [self.HOST]

    def test_empty_cname_answer_stops_the_chain(self, resolver):
        resolver.answers = {
            (self.HOST, 'CNAME'): _cname('cdn1.example.com.'),
            ('cdn1.example.com', 'CNAME'): [],
        }
        assert gt._resolve_one_subdomain(self.HOST)['cname'] == 'cdn1.example.com'

    def test_cname_chain_is_capped_at_five_hops(self, resolver):
        def next_hop(host, qtype):
            """hopN 永远指向 hopN+1 —— 没有上限就查不完。"""
            if qtype != 'CNAME':
                return gt.dns.resolver.NoAnswer()
            number = int(host.split('.')[0].removeprefix('hop'))
            return _cname(f'hop{number + 1}.example.com.')

        resolver.default = next_hop
        rec = gt._resolve_one_subdomain('hop0.example.com')
        assert rec['cname'] == ' → '.join(f'hop{i}.example.com' for i in range(1, 6))
        assert resolver.asked('CNAME') == [f'hop{i}.example.com' for i in range(5)]

    def test_without_dnspython_nothing_is_resolved(self, resolver, monkeypatch):
        resolver.default = ['203.0.113.9']        # 真去查的话，什么都能查到
        monkeypatch.setattr(gt, 'HAS_DNS', False)
        assert gt._resolve_one_subdomain(self.HOST) == {
            'host': self.HOST, 'alive': False, 'a': [], 'aaaa': [], 'cname': None,
        }
        assert resolver.queries == []


@needs_dns
class TestDetectWildcardDns:
    def test_random_label_resolving_means_wildcard(self, resolver):
        resolver.default = ['203.0.113.9']   # 泛解析：随便什么名字都有 A 记录
        assert gt._detect_wildcard_dns('example.com', dns_timeout=0.75) is True
        (host, qtype), = resolver.queries
        assert qtype == 'A'
        # 探测的是「32 位十六进制随机前缀 + 目标域」，不是目标域本身
        assert re.fullmatch(r'[0-9a-f]{32}\.example\.com', host)
        assert (resolver.timeout, resolver.lifetime) == (0.75, 0.75)

    def test_each_probe_uses_a_fresh_random_label(self, resolver):
        resolver.default = ['203.0.113.9']
        gt._detect_wildcard_dns('example.com')
        gt._detect_wildcard_dns('example.com')
        first, second = resolver.asked('A')
        assert first != second

    @pytest.mark.parametrize('error', ['nxdomain', 'no_answer', 'timeout', 'os_error'])
    def test_any_resolution_failure_means_no_wildcard(self, resolver, error):
        resolver.default = {
            'nxdomain': gt.dns.resolver.NXDOMAIN(),
            'no_answer': gt.dns.resolver.NoAnswer(),
            'timeout': gt.dns.exception.Timeout(),
            'os_error': OSError('no route to resolver'),
        }[error]
        assert gt._detect_wildcard_dns('example.com') is False
        assert len(resolver.queries) == 1

    def test_without_dnspython_reports_no_wildcard(self, resolver, monkeypatch):
        resolver.default = ['203.0.113.9']        # 真去查的话会被判成泛解析
        monkeypatch.setattr(gt, 'HAS_DNS', False)
        assert gt._detect_wildcard_dns('example.com') is False
        assert resolver.queries == []


# ====================================================================
# 3. _verify_smtp
# ====================================================================
def _mx(preference: int, exchange: str) -> SimpleNamespace:
    """一条 MX 应答（exchange 用真的 dns Name，str() 带结尾的点）。"""
    return SimpleNamespace(preference=preference, exchange=gt.dns.name.from_text(exchange))


@pytest.fixture
def mx_answers(monkeypatch):
    """顶替 dns.resolver.resolve。box.answer 是要返回的记录列表，或要抛的异常。"""
    if not gt.HAS_DNS:
        pytest.skip('dnspython not installed')
    box = SimpleNamespace(answer=[], queries=[])

    def fake_resolve(name, rdtype, *args, **kwargs):
        box.queries.append((name, rdtype))
        if isinstance(box.answer, BaseException):
            raise box.answer
        return box.answer

    monkeypatch.setattr(gt.dns.resolver, 'resolve', fake_resolve)
    return box


@pytest.fixture
def smtp(monkeypatch):
    """顶替 smtplib.SMTP。smtp.code 是 RCPT 的应答码；connect_exc / rcpt_exc 用来模拟故障。"""
    box = SimpleNamespace(code=250, connect_exc=None, rcpt_exc=None, connects=[], commands=[], exits=0)

    class FakeSMTP:
        def __init__(self, host='', port=0, *args, **kwargs):
            box.connects.append((host, port, kwargs.get('timeout')))
            if box.connect_exc is not None:
                raise box.connect_exc

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            box.exits += 1
            return False

        def helo(self, name=''):
            box.commands.append(('helo', name))
            return 250, b'hello'

        def mail(self, sender):
            box.commands.append(('mail', sender))
            return 250, b'ok'

        def rcpt(self, recipient):
            box.commands.append(('rcpt', recipient))
            if box.rcpt_exc is not None:
                raise box.rcpt_exc
            return box.code, b'reply text'

    monkeypatch.setattr(smtplib, 'SMTP', FakeSMTP)
    return box


@needs_dns
class TestVerifySmtp:
    EMAIL = 'alice@example.com'

    @pytest.mark.parametrize('code', [250, 251])
    def test_accepted_recipient_is_verified(self, mx_answers, smtp, code):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        smtp.code = code
        assert gt._verify_smtp(self.EMAIL) == (True, f'rcpt accepted ({code})')

    @pytest.mark.parametrize('code', [550, 551, 553])
    def test_rejected_recipient_is_not_verified(self, mx_answers, smtp, code):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        smtp.code = code
        assert gt._verify_smtp(self.EMAIL) == (False, f'rcpt rejected ({code})')

    @pytest.mark.parametrize('code', [252, 421, 450, 451, 452, 552, 554])
    def test_any_other_code_is_ambiguous_not_a_rejection(self, mx_answers, smtp, code):
        """灰名单 / 限流 / 「不验证但会投递」都说明不了邮箱存不存在。"""
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        smtp.code = code
        assert gt._verify_smtp(self.EMAIL) == (False, f'rcpt ambiguous ({code})')

    def test_connects_to_the_lowest_preference_mx_on_port_25(self, mx_answers, smtp):
        mx_answers.answer = [
            _mx(20, 'backup.example.com.'),
            _mx(5, 'primary.example.com.'),
            _mx(10, 'secondary.example.com.'),
        ]
        gt._verify_smtp(self.EMAIL)
        assert mx_answers.queries == [('example.com', 'MX')]
        assert smtp.connects == [('primary.example.com', 25, 8.0)]   # 结尾的点已去掉，默认超时 8 秒

    def test_timeout_is_passed_to_the_smtp_connection(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        gt._verify_smtp(self.EMAIL, timeout=2.5)
        assert smtp.connects == [('mx.example.com', 25, 2.5)]

    def test_smtp_dialogue_is_helo_mail_rcpt(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        gt._verify_smtp(self.EMAIL)
        assert smtp.commands == [
            ('helo', 'spyeyes.osint'), ('mail', 'verify@spyeyes.osint'), ('rcpt', self.EMAIL),
        ]
        assert smtp.exits == 1   # 连接用完即关

    def test_custom_helo_and_sender_are_used(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        gt._verify_smtp(self.EMAIL, helo_domain='probe.test', from_addr='check@probe.test')
        assert smtp.commands[:2] == [('helo', 'probe.test'), ('mail', 'check@probe.test')]

    def test_domain_is_whatever_follows_the_last_at_sign(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.org.')]
        gt._verify_smtp('"odd@local"@example.org')
        assert mx_answers.queries == [('example.org', 'MX')]

    def test_domain_without_mx_never_opens_a_connection(self, mx_answers, smtp):
        mx_answers.answer = []
        assert gt._verify_smtp(self.EMAIL) == (False, 'no MX records')
        assert smtp.connects == []

    @pytest.mark.parametrize('error', ['nxdomain', 'timeout', 'os_error'])
    def test_mx_lookup_failure_never_opens_a_connection(self, mx_answers, smtp, error):
        mx_answers.answer = {
            'nxdomain': gt.dns.resolver.NXDOMAIN(),
            'timeout': gt.dns.exception.Timeout(),
            'os_error': OSError('resolver unreachable'),
        }[error]
        ok, reason = gt._verify_smtp(self.EMAIL)
        assert ok is False
        assert reason == f'mx lookup failed: {mx_answers.answer}'
        assert smtp.connects == []

    def test_connection_failure_is_reported_not_raised(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        smtp.connect_exc = ConnectionRefusedError('port 25 blocked')
        assert gt._verify_smtp(self.EMAIL) == (False, 'smtp connect failed: port 25 blocked')
        assert smtp.commands == []

    def test_server_hanging_up_mid_dialogue_is_reported_not_raised(self, mx_answers, smtp):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        smtp.rcpt_exc = smtplib.SMTPServerDisconnected('Connection unexpectedly closed')
        assert gt._verify_smtp(self.EMAIL) == (False, 'smtp connect failed: Connection unexpectedly closed')
        assert smtp.exits == 1

    def test_address_ending_in_at_sign_has_no_domain(self, mx_answers, smtp):
        assert gt._verify_smtp('alice@') == (False, 'no domain part')
        assert mx_answers.queries == [] and smtp.connects == []

    def test_without_dnspython_nothing_is_contacted(self, mx_answers, smtp, monkeypatch):
        monkeypatch.setattr(gt, 'HAS_DNS', False)
        assert gt._verify_smtp(self.EMAIL) == (False, 'dns dependency missing')
        assert mx_answers.queries == [] and smtp.connects == []


# ====================================================================
# 4. _fetch_latest_version_from_github
# ====================================================================
@pytest.fixture
def github(monkeypatch):
    """顶替 requests.get。github.response 是要返回的 Response，github.exc 是要抛的异常。"""
    box = SimpleNamespace(response=None, exc=None, calls=[])

    def fake_get(url, **kwargs):
        box.calls.append((url, kwargs))
        if box.exc is not None:
            raise box.exc
        return box.response

    monkeypatch.setattr(gt.requests, 'get', fake_get)
    return box


def _json_response(status: int, payload) -> requests.Response:
    return _real_response(status, json.dumps(payload).encode('utf-8'))


class TestFetchLatestVersionFromGithub:
    def test_returns_tag_name_of_the_latest_release(self, github):
        github.response = _json_response(200, {'tag_name': 'v9.9.9', 'name': 'Release 9.9.9'})
        assert gt._fetch_latest_version_from_github() == 'v9.9.9'

    def test_request_goes_to_the_releases_api_with_ua_and_short_timeout(self, github):
        github.response = _json_response(200, {'tag_name': 'v9.9.9'})
        gt._fetch_latest_version_from_github()
        (url, kwargs), = github.calls
        assert url == gt.UPDATE_CHECK_URL == 'https://api.github.com/repos/Akxan/SpyEyes/releases/latest'
        assert kwargs['headers'] == {
            'User-Agent': f'spyeyes/{gt.__version__}', 'Accept': 'application/vnd.github+json',
        }
        assert kwargs['timeout'] == gt.UPDATE_CHECK_TIMEOUT == 3.0   # 启动路径上的同步请求，必须短

    @pytest.mark.parametrize('status', [301, 403, 404, 429, 500])
    def test_non_200_is_ignored_even_if_the_body_has_a_tag(self, github, status):
        github.response = _json_response(status, {'tag_name': 'v9.9.9'})
        assert gt._fetch_latest_version_from_github() is None

    @pytest.mark.parametrize('body', [b'<html>rate limited</html>', b'', b'{"tag_name": "v9.9', b'\xff\xfe\x00'])
    def test_body_that_is_not_json_returns_none(self, github, body):
        github.response = _real_response(200, body)
        assert gt._fetch_latest_version_from_github() is None

    @pytest.mark.parametrize('payload', [
        {},                               # 没有 tag_name
        {'name': 'v9.9.9'},               # 只有 release 标题
        {'tag_name': None},
        {'tag_name': 123},
        {'tag_name': ['v9.9.9']},
        {'tag_name': {'ref': 'v9.9.9'}},
        {'tag_name': ''},
        {'tag_name': '   '},
        ['v9.9.9'],                       # 顶层不是对象
        'v9.9.9',
        None,
    ], ids=repr)
    def test_missing_or_non_string_tag_returns_none(self, github, payload):
        github.response = _json_response(200, payload)
        assert gt._fetch_latest_version_from_github() is None

    @pytest.mark.parametrize('exc', [
        requests.exceptions.ConnectionError('dns failure'),
        requests.exceptions.Timeout('3s elapsed'),
        requests.exceptions.SSLError('bad cert'),
        OSError('network down'),
        ValueError('bad proxy url'),
    ], ids=lambda e: type(e).__name__)
    def test_network_errors_return_none(self, github, exc):
        github.exc = exc
        assert gt._fetch_latest_version_from_github() is None
        assert len(github.calls) == 1


# ====================================================================
# 5. _batch_lookup
# ====================================================================
class TestBatchLookup:
    def test_results_keep_input_order_even_when_finished_in_reverse(self):
        """每一项都等「后一项」放行才返回 → 完成顺序是输入顺序的反序。
        结果 dict 仍必须按输入顺序排（批量 whois/mx 的输出顺序 = 用户敲的顺序）。"""
        items = [f'd{i}.example.com' for i in range(8)]
        released = {item: threading.Event() for item in items}

        def lookup(item):
            idx = items.index(item)
            if idx + 1 < len(items):
                released[items[idx + 1]].wait(timeout=5)
            released[item].set()
            return {'domain': item}

        result = gt._batch_lookup(lookup, items)
        assert list(result) == items
        assert result == {item: {'domain': item} for item in items}

    def test_one_failing_item_only_spoils_itself(self):
        def lookup(item):
            if item == 'bad.example.com':
                raise RuntimeError('whois server said no')
            return {'domain': item, 'registrar': 'Example Registrar'}

        items = ['a.example.com', 'bad.example.com', 'z.example.com']
        assert gt._batch_lookup(lookup, items) == {
            'a.example.com': {'domain': 'a.example.com', 'registrar': 'Example Registrar'},
            'bad.example.com': {'_error': 'whois server said no'},
            'z.example.com': {'domain': 'z.example.com', 'registrar': 'Example Registrar'},
        }

    def test_every_item_is_looked_up_exactly_once(self):
        seen = []
        lock = threading.Lock()

        def lookup(item):
            with lock:
                seen.append(item)
            return item.upper()

        items = ['a.com', 'b.com', 'c.com', 'd.com']
        assert gt._batch_lookup(lookup, items, max_workers=2) == {
            'a.com': 'A.COM', 'b.com': 'B.COM', 'c.com': 'C.COM', 'd.com': 'D.COM',
        }
        assert sorted(seen) == items

    def test_all_items_failing_still_returns_every_key(self):
        def lookup(item):
            raise ValueError(f'cannot look up {item}')

        assert gt._batch_lookup(lookup, ['x.com', 'y.com']) == {
            'x.com': {'_error': 'cannot look up x.com'},
            'y.com': {'_error': 'cannot look up y.com'},
        }

    def test_empty_input_gives_empty_dict(self):
        assert gt._batch_lookup(lambda item: item, []) == {}


# ====================================================================
# 6. mx_lookup / email_validate 成功路径
# ====================================================================
@needs_dns
class TestMxLookupSuccess:
    def test_records_are_sorted_by_preference_without_trailing_dots(self, mx_answers):
        mx_answers.answer = [
            _mx(30, 'alt2.aspmx.l.google.com.'),
            _mx(1, 'aspmx.l.google.com.'),
            _mx(10, 'alt1.aspmx.l.google.com.'),
        ]
        assert gt.mx_lookup('example.com') == {
            'domain': 'example.com',
            'records': [
                {'preference': 1, 'exchange': 'aspmx.l.google.com'},
                {'preference': 10, 'exchange': 'alt1.aspmx.l.google.com'},
                {'preference': 30, 'exchange': 'alt2.aspmx.l.google.com'},
            ],
        }

    def test_equal_preferences_keep_the_order_dns_returned(self, mx_answers):
        mx_answers.answer = [_mx(10, 'mx-b.example.com.'), _mx(10, 'mx-a.example.com.'), _mx(5, 'mx-c.example.com.')]
        exchanges = [r['exchange'] for r in gt.mx_lookup('example.com')['records']]
        assert exchanges == ['mx-c.example.com', 'mx-b.example.com', 'mx-a.example.com']

    def test_query_uses_the_normalised_domain(self, mx_answers):
        mx_answers.answer = [_mx(10, 'mx.example.com.')]
        result = gt.mx_lookup('  Example.COM.  ')
        assert mx_answers.queries == [('example.com', 'MX')]
        assert result['domain'] == 'example.com'
        assert '_error' not in result and '_error_kind' not in result

    def test_single_record(self, mx_answers):
        mx_answers.answer = [_mx(0, 'mail.example.com.')]
        assert gt.mx_lookup('example.com')['records'] == [{'preference': 0, 'exchange': 'mail.example.com'}]


@needs_dns
class TestEmailValidateSuccess:
    def test_valid_address_with_mx_reports_sorted_records(self, mx_answers):
        mx_answers.answer = [_mx(20, 'mx2.example.com.'), _mx(10, 'mx1.example.com.')]
        assert gt.email_validate('alice@example.com') == {
            'email': 'alice@example.com',
            'syntax_valid': True,
            'domain': 'example.com',
            'mx_valid': True,
            'mx_records': [
                {'preference': 10, 'exchange': 'mx1.example.com'},
                {'preference': 20, 'exchange': 'mx2.example.com'},
            ],
        }
        assert mx_answers.queries == [('example.com', 'MX')]

    def test_surrounding_whitespace_is_trimmed_before_validation(self, mx_answers):
        mx_answers.answer = [_mx(10, 'mx1.example.com.')]
        result = gt.email_validate('  first.last+tag@mail.example.com \n')
        assert result['email'] == 'first.last+tag@mail.example.com'
        assert result['domain'] == 'mail.example.com'
        assert result['mx_valid'] is True
        assert mx_answers.queries == [('mail.example.com', 'MX')]
        assert 'mx_error' not in result and '_error' not in result

    def test_same_address_without_mx_gets_error_fields_instead_of_records(self, mx_answers):
        """对照：域名不存在时给的是 mx_error（稳定枚举）+ 提示文字，而不是 mx_records。"""
        mx_answers.answer = gt.dns.resolver.NXDOMAIN()
        failed = gt.email_validate('alice@example.com')
        assert failed['mx_valid'] is False
        assert failed['mx_error'] == gt.MX_ERR_NXDOMAIN
        assert failed['mx_error_msg'] == gt.t('err.nxdomain', domain='example.com')
        assert 'mx_records' not in failed


# ====================================================================
# 7. _check_username 的 must_contain
# ====================================================================
_MUST = gt.Platform('Must', 'https://must.test/u/{}', 'code',
                    must_contain=(b'"player_id":', b'profile-card'))
_BOTH = gt.Platform('Both', 'https://both.test/u/{}', 'code',
                    not_found=(b'no such user',), must_contain=(b'profile-card',))
_BODY_LIMIT = 65536   # _check_username 只读响应体的前 64 KB


@pytest.fixture
def served(monkeypatch):
    """顶替 safe_get：served.respond(status, body) 预置一个真实 Response，served.calls 记录请求。"""
    box = SimpleNamespace(response=None, calls=[])

    def respond(status, body=b'', headers=None):
        box.response = _real_response(status, body, headers)
        return box.response

    def fake_safe_get(url, **kwargs):
        box.calls.append((url, kwargs))
        return box.response

    box.respond = respond
    monkeypatch.setattr(gt, 'safe_get', fake_safe_get)
    return box


class TestCheckUsernameMustContain:
    def test_marker_present_means_found(self, served):
        served.respond(200, b'<html><div class="profile-card">alice</div></html>')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, 'https://must.test/u/alice', gt.STATUS_FOUND)

    def test_any_one_of_the_markers_is_enough(self, served):
        served.respond(200, b'{"player_id": 42, "username": "alice"}')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, 'https://must.test/u/alice', gt.STATUS_FOUND)

    def test_marker_absent_means_not_found_even_with_http_200(self, served):
        served.respond(200, b'<html><h1>Welcome! Sign up today</h1></html>')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_NOT_FOUND)

    def test_empty_200_body_is_not_found(self, served):
        served.respond(200, b'')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_NOT_FOUND)

    def test_page_text_is_matched_case_insensitively(self, served):
        served.respond(200, b'<DIV CLASS="Profile-Card">ALICE</DIV>')
        assert gt._check_username(_MUST, 'alice', 5)[2] == gt.STATUS_FOUND

    @pytest.mark.parametrize('status', [404, 410, 500])
    def test_non_200_is_not_found_whatever_the_body_says(self, served, status):
        served.respond(status, b'<div class="profile-card">alice</div>')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_NOT_FOUND)

    def test_body_platform_is_fetched_with_one_streamed_get(self, served):
        served.respond(200, b'profile-card')
        gt._check_username(_MUST, 'alice', 7)
        (url, kwargs), = served.calls
        assert url == 'https://must.test/u/alice'
        assert kwargs.get('method', 'GET').upper() == 'GET'    # 要看正文 → 不能用 HEAD
        assert kwargs['stream'] is True                        # 流式读取才能只读前 64 KB
        assert kwargs['timeout'] == 7

    @pytest.mark.parametrize('body', [b'profile-card', b'nothing to see'])
    def test_response_is_closed_after_reading(self, served, body):
        resp = served.respond(200, body)
        gt._check_username(_MUST, 'alice', 5)
        assert resp.raw.closed is True   # 不关的话 150 线程扫描会把连接池耗尽

    @pytest.mark.parametrize('body,expected', [
        (b'<div class="profile-card">alice</div>', gt.STATUS_FOUND),
        (b'<div class="profile-card"></div><p>No such user</p>', gt.STATUS_NOT_FOUND),   # 两种标志都在 → 「未找到」优先
        (b'<p>no such user</p>', gt.STATUS_NOT_FOUND),
        (b'<p>hello world</p>', gt.STATUS_NOT_FOUND),                                    # 两种标志都不在
    ], ids=['must_only', 'both', 'not_found_only', 'neither'])
    def test_not_found_marker_beats_must_contain(self, served, body, expected):
        served.respond(200, body)
        _, url, status = gt._check_username(_BOTH, 'alice', 5)
        assert status == expected
        assert url == ('https://both.test/u/alice' if expected == gt.STATUS_FOUND else None)

    def test_waf_page_is_reported_as_blocked_not_as_found(self, served):
        served.respond(200, b'<title>Just a moment...</title><div class="profile-card">alice</div>')
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_WAF)

    def test_marker_after_the_first_64kb_is_never_read(self, served):
        resp = served.respond(200, b'x' * _BODY_LIMIT + b'profile-card' + b'y' * 4096)
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_NOT_FOUND)
        assert resp.raw.bytes_read == _BODY_LIMIT

    def test_marker_ending_exactly_at_64kb_still_counts(self, served):
        marker = b'profile-card'
        served.respond(200, b'x' * (_BODY_LIMIT - len(marker)) + marker + b'y' * 4096)
        assert gt._check_username(_MUST, 'alice', 5)[2] == gt.STATUS_FOUND

    def test_not_found_marker_after_the_first_64kb_is_not_seen_either(self, served):
        served.respond(200, b'<div class="profile-card">' + b'x' * _BODY_LIMIT + b'no such user')
        assert gt._check_username(_BOTH, 'alice', 5)[2] == gt.STATUS_FOUND

    def test_connection_failure_is_a_network_error(self, served):
        served.response = None
        assert gt._check_username(_MUST, 'alice', 5) == (_MUST, None, gt.STATUS_NETWORK_ERROR)

    def test_through_track_username_soft_404_site_is_unverifiable(self, monkeypatch):
        """走完整入口：命中后会用乱码用户名复查。乱码名查无此人 → 命中成立；
        对谁都回同一张带标志的页面 → 分辨不了，命中不作数。"""
        strict = gt.Platform('Strict', 'https://strict.test/u/{}', 'code', must_contain=(b'profile-card',))
        soft = gt.Platform('Soft404', 'https://soft.test/u/{}', 'code', must_contain=(b'profile-card',))
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [strict, soft])
        monkeypatch.setattr(gt, '_make_control_username', lambda: 'zqcontrol00')
        pages = {
            'https://strict.test/u/alice': (200, b'<div class="profile-card">alice</div>'),
            'https://strict.test/u/zqcontrol00': (404, b'<h1>not here</h1>'),
            'https://soft.test/u/alice': (200, b'<div class="profile-card"></div>'),
            'https://soft.test/u/zqcontrol00': (200, b'<div class="profile-card"></div>'),
        }
        monkeypatch.setattr(gt, 'safe_get', lambda url, **kwargs: _real_response(*pages[url]))
        assert gt.track_username('alice', show_progress=False) == {
            'Strict': 'https://strict.test/u/alice',
            'Soft404': None,
            '_statuses': {'Strict': gt.STATUS_FOUND, 'Soft404': gt.STATUS_UNVERIFIABLE},
        }


# ====================================================================
# 8. recursive_track_username 真正展开到下一层
# ====================================================================
@pytest.fixture
def web(monkeypatch):
    """顶替 track_username + safe_get，搭一个「主页互相提到别的账号」的小网络。
    web.hits[name]   该用户名命中的页面 URL 列表（默认只有 https://site.test/<name>）
    web.pages[url]   页面正文（默认空）；None 表示这一页抓不下来
    web.errors[name] track_username 对该用户名返回的 _error"""
    box = SimpleNamespace(hits={}, pages={}, errors={}, scanned=[], scan_kwargs=[], fetched=[], fetch_kwargs=[])

    def fake_track(name, **kwargs):
        box.scanned.append(name)
        box.scan_kwargs.append(kwargs)
        if name in box.errors:
            return {'_error': box.errors[name]}
        urls = box.hits.get(name, [f'https://site.test/{name}'])
        result = {f'Site{i}': url for i, url in enumerate(urls)}
        result['Nowhere'] = None
        result['_statuses'] = {key: ('found' if url else 'not_found') for key, url in result.items()}
        return result

    def fake_safe_get(url, **kwargs):
        box.fetched.append(url)
        box.fetch_kwargs.append(kwargs)
        text = box.pages.get(url, '')
        return None if text is None else _real_response(200, text.encode('utf-8'))

    monkeypatch.setattr(gt, 'track_username', fake_track)
    monkeypatch.setattr(gt, 'safe_get', fake_safe_get)
    return box


def _page(name: str) -> str:
    return f'https://site.test/{name}'


class TestRecursiveExpansion:
    def test_handle_on_a_hit_page_is_scanned_at_depth_1(self, web):
        web.pages[_page('alice')] = '<p>Also find me as @seconduser elsewhere</p>'
        result = gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.scanned == ['alice', 'seconduser']
        rec = result['_recursive']
        assert [(lv['depth'], lv['username'], lv['found']) for lv in rec['levels']] == [
            (0, 'alice', 1), (1, 'seconduser', 1),
        ]
        assert rec['levels'][1]['platforms']['Site0'] == _page('seconduser')
        assert (rec['total_found'], rec['depth_reached']) == (2, 1)
        # 到了最大深度就不再抓页面：只抓过第 0 层命中的那一页
        assert web.fetched == [_page('alice')]

    def test_top_level_still_carries_the_depth_0_scan(self, web):
        web.pages[_page('alice')] = '@seconduser'
        result = gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert {k: v for k, v in result.items() if k != '_recursive'} == {
            'Site0': _page('alice'), 'Nowhere': None,
            '_statuses': {'Site0': 'found', 'Nowhere': 'not_found'},
        }

    def test_scan_options_reach_every_level_and_the_page_fetch(self, web):
        web.pages[_page('alice')] = '@seconduser'
        gt.recursive_track_username('alice', max_depth=1, max_workers=7, timeout=2.5,
                                    show_progress=False, categories=['code'])
        options = {'max_workers': 7, 'timeout': 2.5, 'show_progress': False, 'categories': ['code']}
        assert [{key: kwargs[key] for key in options} for kwargs in web.scan_kwargs] == [options, options]
        assert [kwargs['timeout'] for kwargs in web.fetch_kwargs] == [2.5]

    def test_max_depth_zero_scans_once_and_fetches_nothing(self, web):
        web.pages[_page('alice')] = '@seconduser'
        result = gt.recursive_track_username('alice', max_depth=0, show_progress=False)
        assert web.scanned == ['alice']
        assert web.fetched == []
        rec = result['_recursive']
        assert [(lv['depth'], lv['username']) for lv in rec['levels']] == [(0, 'alice')]
        assert (rec['total_found'], rec['depth_reached']) == (1, 0)

    def test_depth_2_follows_the_chain_one_more_step(self, web):
        web.pages[_page('alice')] = '@bobby'
        web.pages[_page('bobby')] = '@carol'
        web.pages[_page('carol')] = '@david'
        result = gt.recursive_track_username('alice', max_depth=2, show_progress=False)
        assert web.scanned == ['alice', 'bobby', 'carol']          # david 在第 3 层，不扫
        assert web.fetched == [_page('alice'), _page('bobby')]     # 最后一层的页面不抓
        assert result['_recursive']['depth_reached'] == 2
        assert result['_recursive']['total_found'] == 3

    def test_requested_depth_is_clamped_to_the_hard_limit(self, web):
        chain = ['alice', 'bobby', 'carol', 'david', 'erin', 'frank']
        for name, mentioned in zip(chain, chain[1:]):
            web.pages[_page(name)] = f'@{mentioned}'
        gt.recursive_track_username('alice', max_depth=99, show_progress=False)
        assert web.scanned == chain[:gt.RECURSIVE_MAX_DEPTH + 1]

    def test_a_username_is_never_scanned_twice(self, web):
        web.pages[_page('alice')] = '@Alice @bobby @BOBBY @bobby'
        web.pages[_page('bobby')] = '@alice @bobby @carol'
        gt.recursive_track_username('alice', max_depth=2, show_progress=False)
        assert web.scanned == ['alice', 'bobby', 'carol']

    def test_same_child_reached_from_two_parents_is_scanned_once(self, web):
        web.pages[_page('alice')] = '@bobby @carol'
        web.pages[_page('bobby')] = '@david'
        web.pages[_page('carol')] = '@david @erin'
        gt.recursive_track_username('alice', max_depth=2, show_progress=False)
        assert web.scanned == ['alice', 'bobby', 'carol', 'david', 'erin']

    def test_one_page_yields_at_most_five_new_usernames(self, web):
        handles = [f'user{i}' for i in range(9)]
        web.pages[_page('alice')] = ' '.join(f'@{h}' for h in handles)
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.scanned == ['alice'] + handles[:5]      # 按页面里出现的顺序取前 5 个

    def test_new_username_cap_follows_the_module_constant(self, web, monkeypatch):
        monkeypatch.setattr(gt, 'RECURSIVE_MAX_NEW_PER_DEPTH', 2)
        web.pages[_page('alice')] = '@user0 @user1 @user2 @user3'
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.scanned == ['alice', 'user0', 'user1']

    def test_already_scanned_names_do_not_use_up_the_cap(self, web):
        """页面里提到自己（已扫过）不占 5 个名额，否则后面真正的新账号会被挤掉。"""
        web.pages[_page('alice')] = '@alice @Alice @user0 @user1 @user2 @user3 @user4'
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.scanned == ['alice', 'user0', 'user1', 'user2', 'user3', 'user4']

    def test_cap_counts_across_pages_and_stops_fetching_once_full(self, web):
        web.hits['alice'] = [_page(f'p{i}') for i in range(5)]
        web.pages[_page('p0')] = '@aaa1 @aaa2'
        web.pages[_page('p1')] = '@bbb1 @bbb2 @aaa1'
        web.pages[_page('p2')] = '@ccc1 @ccc2'
        web.pages[_page('p3')] = '@ddd1'
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.scanned == ['alice', 'aaa1', 'aaa2', 'bbb1', 'bbb2', 'ccc1']
        assert web.fetched == [_page('p0'), _page('p1'), _page('p2')]   # 凑满 5 个就不再抓 p3 / p4

    def test_at_most_eight_hit_pages_are_fetched(self, web):
        web.hits['alice'] = [_page(f'p{i}') for i in range(12)]
        web.pages[_page('p9')] = '@toolate'           # 第 10 个命中页里的账号永远看不到
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.fetched == [_page(f'p{i}') for i in range(8)]
        assert web.scanned == ['alice']

    def test_page_fetch_cap_follows_the_module_constant(self, web, monkeypatch):
        monkeypatch.setattr(gt, 'RECURSIVE_FETCH_LIMIT', 3)
        web.hits['alice'] = [_page(f'p{i}') for i in range(6)]
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.fetched == [_page('p0'), _page('p1'), _page('p2')]

    def test_fan_out_at_depth_2_stays_bounded(self, web, monkeypatch):
        """每一页都列出 9 个全新的账号 —— 上限失效的话扫描次数会爆炸。"""
        def endless_mentions(url, **kwargs):
            owner = url.rsplit('/', 1)[1]
            return _real_response(200, ' '.join(f'@{owner}x{i}' for i in range(9)).encode())
        monkeypatch.setattr(gt, 'safe_get', endless_mentions)
        result = gt.recursive_track_username('root', max_depth=2, show_progress=False)
        by_depth = {}
        for level in result['_recursive']['levels']:
            by_depth.setdefault(level['depth'], []).append(level['username'])
        assert by_depth[0] == ['root']
        assert by_depth[1] == [f'rootx{i}' for i in range(5)]
        for parent in by_depth[1]:
            children = [name for name in by_depth[2] if name.startswith(parent + 'x')]
            assert 1 <= len(children) <= gt.RECURSIVE_MAX_NEW_PER_DEPTH
        assert len(web.scanned) <= 1 + 5 + 25

    def test_page_that_cannot_be_fetched_is_skipped(self, web):
        web.hits['alice'] = [_page('p0'), _page('p1')]
        web.pages[_page('p0')] = None
        web.pages[_page('p1')] = '@bobby'
        gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        assert web.fetched == [_page('p0'), _page('p1')]
        assert web.scanned == ['alice', 'bobby']

    def test_failed_child_scan_is_recorded_without_failing_the_run(self, web):
        web.pages[_page('alice')] = '@bobby @carol'
        web.errors['bobby'] = 'scan rejected'
        result = gt.recursive_track_username('alice', max_depth=1, show_progress=False)
        rec = result['_recursive']
        assert rec['levels'][1] == {'depth': 1, 'username': 'bobby', 'error': 'scan rejected', 'platforms': {}}
        assert [(lv['depth'], lv['username']) for lv in rec['levels']] == [(0, 'alice'), (1, 'bobby'), (1, 'carol')]
        assert rec['total_found'] == 2            # alice + carol，各命中 1 个
        assert '_error' not in result             # 只有第 0 层失败才算整次扫描失败

    def test_no_hits_means_nothing_to_expand(self, web):
        web.hits['alice'] = []
        result = gt.recursive_track_username('alice', max_depth=2, show_progress=False)
        assert web.scanned == ['alice']
        assert web.fetched == []
        assert result['_recursive']['total_found'] == 0


# ====================================================================
# 9. 用户名 / 变形结果的报告分支
# ====================================================================
class _HtmlProbe(HTMLParser):
    """按浏览器的方式把 HTML 解析一遍：有哪些标签、带什么属性、各元素里的文本是什么。
    转义正确 ⇔ 解析出来的文本与原始值一字不差，且恶意内容没有变成标签或属性。"""

    _TRACKED = frozenset({'title', 'h2', 'h3', 'p', 'th', 'td', 'a', 'li', 'em', 'div', 'script'})

    def __init__(self, markup: str):
        super().__init__(convert_charrefs=True)
        self.tags = []      # 所有开始标签名，按出现顺序
        self.attrs = {}     # 标签名 -> [属性 dict, ...]
        self.texts = {}     # 标签名 -> [元素内的完整文本（含子元素文本）, ...]
        self._open = []     # 尚未闭合的 (标签名, [文本片段])
        self.feed(markup)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.setdefault(tag, []).append(dict(attrs))
        if tag in self._TRACKED:
            self._open.append((tag, []))

    def handle_endtag(self, tag):
        for i in range(len(self._open) - 1, -1, -1):
            if self._open[i][0] == tag:
                _, pieces = self._open.pop(i)
                self.texts.setdefault(tag, []).append(''.join(pieces))
                break

    def handle_data(self, data):
        for _, pieces in self._open:
            pieces.append(data)


def _graph_payload(html: str):
    """取出关系图页面内嵌的 nodes / links（就是浏览器里 D3 拿到的数据）。"""
    nodes = json.loads(re.search(r'^const nodes = (.*);$', html, re.M).group(1))
    links = json.loads(re.search(r'^const links = (.*);$', html, re.M).group(1))
    return nodes, links


_XMIND_NS = {'x': 'urn:xmind:xmap:xmlns:content:2.0'}
_XLINK_HREF = '{http://www.w3.org/1999/xlink}href'


def _xmind_outline(path):
    """解开 .xmind，把 content.xml 解析成 (sheet 标题, 根 topic)。
    topic 有 title / href / markers / children。content.xml 不是合法 XML 时直接抛错。"""
    with zipfile.ZipFile(str(path)) as zf:
        tree = ElementTree.fromstring(zf.read('content.xml'))

    def walk(topic):
        return SimpleNamespace(
            title=topic.findtext('x:title', namespaces=_XMIND_NS),
            href=topic.get(_XLINK_HREF),
            markers=[m.get('marker-id') for m in topic.findall('x:marker-refs/x:marker-ref', _XMIND_NS)],
            children=[walk(child) for child in topic.findall('x:children/x:topics/x:topic', _XMIND_NS)],
        )

    sheet = tree.find('x:sheet', _XMIND_NS)
    return sheet.findtext('x:title', namespaces=_XMIND_NS), walk(sheet.find('x:topic', _XMIND_NS))


def _write_xmind(tmp_path, prefix, data):
    out = tmp_path / 'report.xmind'
    assert gt._to_xmind(prefix, data, str(out)) is None
    return _xmind_outline(out)


def _md_body(md: str) -> list:
    """Markdown 报告正文（二级标题起）的非空行 —— 不关心空行怎么排。"""
    return [line for line in md[md.index('\n## ') + 1:].splitlines() if line]


def _md_cells(row: str) -> list:
    """Markdown 表格的一行按「未转义的 |」拆成单元格。"""
    return [cell.strip() for cell in re.split(r'(?<!\\)\|', row)[1:-1]]


# 没被转义（前面没有反斜杠）的 <script / </script —— 渲染 Markdown 时会变成真标签
_RAW_SCRIPT_TAG = re.compile(r'(?<!\\)</?script', re.IGNORECASE)


def _txt_body(txt: str, first_line_prefix: str) -> list:
    """TXT 报告正文（抬头方框之后）的非空行。"""
    lines = txt.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(first_line_prefix))
    return [line for line in lines[start:] if line]


def _csv_rows(text: str) -> list:
    return list(csv.reader(io.StringIO(text)))


_SPYEYES_LINK = 'https://github.com/Akxan/SpyEyes'   # 页脚的项目链接，不属于查询结果

_CODE_ZH = '代码与开发'
_CHINESE_ZH = '中文平台（陆/台/港/星/马）'
_GITHUB_URL = 'https://github.com/alice'
_WEIBO_URL = 'https://weibo.com/n/alice'
_ZHIHU_URL = 'https://www.zhihu.com/people/alice'


def _scan_platforms() -> list:
    return [
        gt.Platform('GitHub', 'https://github.com/{}', 'code'),
        gt.Platform('GitLab', 'https://gitlab.com/{}', 'code'),
        gt.Platform('Twitter', 'https://twitter.com/{}', 'social'),
        gt.Platform('Weibo', 'https://weibo.com/n/{}', 'chinese'),
        gt.Platform('Zhihu', 'https://www.zhihu.com/people/{}', 'chinese'),
        gt.Platform('Unscanned', 'https://unscanned.test/{}', 'other'),   # 平台库里有，但这次没扫
    ]


def _scan_result() -> dict:
    """一次 track_username 的结果：5 个平台扫了、3 个命中。
    故意不按分类排 —— 分组报告必须按 CATEGORY_ORDER + 平台库顺序输出，而不是照抄 dict 顺序。"""
    return {
        'Zhihu': _ZHIHU_URL,
        'Twitter': None,
        'GitHub': _GITHUB_URL,
        'Weibo': _WEIBO_URL,
        'GitLab': None,
        '_statuses': {'Zhihu': 'found', 'Twitter': 'waf', 'GitHub': 'found',
                      'Weibo': 'found', 'GitLab': 'not_found'},
    }


class TestUsernameReportContent:
    PREFIX = 'username_alice'

    @pytest.fixture(autouse=True)
    def _platforms(self, monkeypatch):
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', _scan_platforms())

    def test_markdown_groups_hits_by_category(self):
        assert _md_body(gt._to_markdown(self.PREFIX, _scan_result())) == [
            '## 用户名扫描: `alice`',
            '**共扫描 5 个平台 · 命中 3 个账号**',
            f'### {_CODE_ZH} (1/2)',
            '| 平台 | 主页地址 |',
            '|---|---|',
            f'| GitHub | <{_GITHUB_URL}> |',
            f'### {_CHINESE_ZH} (2/2)',
            '| 平台 | 主页地址 |',
            '|---|---|',
            f'| Weibo | <{_WEIBO_URL}> |',
            f'| Zhihu | <{_ZHIHU_URL}> |',
        ]

    def test_html_groups_hits_by_category_with_safe_links(self):
        probe = _HtmlProbe(gt._to_html(self.PREFIX, _scan_result()))
        assert probe.texts['title'] == ['SpyEyes 报告 — alice']
        assert probe.texts['h2'] == ['用户名扫描: alice']
        assert probe.texts['p'] == ['共扫描 5 个平台 · 命中 3 个账号']
        assert probe.texts['h3'] == [f'{_CODE_ZH} (1/2)', f'{_CHINESE_ZH} (2/2)']
        assert probe.texts['th'] == ['平台', '主页地址', '平台', '主页地址']
        assert probe.texts['td'] == ['GitHub', _GITHUB_URL, 'Weibo', _WEIBO_URL, 'Zhihu', _ZHIHU_URL]
        assert [a['href'] for a in probe.attrs['a']] == [_GITHUB_URL, _WEIBO_URL, _ZHIHU_URL, _SPYEYES_LINK]
        # 结果链接在新标签页打开，且不把 window.opener / Referer 交给被查的站点
        assert all(a['target'] == '_blank' and a['rel'] == 'noopener noreferrer' for a in probe.attrs['a'])
        assert 'script' not in probe.tags

    def test_txt_lists_hits_under_category_rules(self):
        txt = gt._to_txt(self.PREFIX, _scan_result())
        assert _txt_body(txt, '用户名扫描') == [
            '用户名扫描: alice',
            '共扫描 5 个平台 · 命中 3 个账号',
            f'── {_CODE_ZH} (1/2) ──',
            f'  {"GitHub":30} {_GITHUB_URL}',
            f'── {_CHINESE_ZH} (2/2) ──',
            f'  {"Weibo":30} {_WEIBO_URL}',
            f'  {"Zhihu":30} {_ZHIHU_URL}',
        ]
        header = txt[:txt.index('用户名扫描')]
        assert '│  username' in header and '│  alice' in header

    def test_csv_has_one_row_per_hit_with_category_and_status(self):
        assert _csv_rows(gt._to_csv(self.PREFIX, _scan_result())) == [
            ['分类', '平台', '主页地址', '状态'],
            ['code', 'GitHub', _GITHUB_URL, 'found'],
            ['chinese', 'Weibo', _WEIBO_URL, 'found'],
            ['chinese', 'Zhihu', _ZHIHU_URL, 'found'],
        ]

    def test_csv_status_defaults_to_found_for_the_public_json_view(self):
        public = gt._username_json_view(_scan_result())     # 没有 _statuses
        assert '_statuses' not in public
        assert _csv_rows(gt._to_csv(self.PREFIX, public))[1:] == [
            ['code', 'GitHub', _GITHUB_URL, 'found'],
            ['chinese', 'Weibo', _WEIBO_URL, 'found'],
            ['chinese', 'Zhihu', _ZHIHU_URL, 'found'],
        ]

    def test_xmind_outline_mirrors_the_categories(self, tmp_path):
        sheet_title, root = _write_xmind(tmp_path, self.PREFIX, _scan_result())
        assert sheet_title == 'SpyEyes 报告 — alice'
        assert root.title == '👤 SpyEyes 报告 · username · alice'
        meta, code, chinese = root.children
        assert meta.title.startswith('⏱') and meta.children == []
        assert (code.title, code.markers, code.href) == (f'{_CODE_ZH} (1/2)', ['flag-blue'], None)
        assert [(leaf.title, leaf.href, leaf.markers) for leaf in code.children] == [
            ('GitHub', _GITHUB_URL, ['task-done']),
        ]
        assert chinese.title == f'{_CHINESE_ZH} (2/2)'
        assert [(leaf.title, leaf.href) for leaf in chinese.children] == [
            ('Weibo', _WEIBO_URL), ('Zhihu', _ZHIHU_URL),
        ]

    def test_xmind_file_is_a_zip_with_uncompressed_mimetype_first(self, tmp_path):
        out = tmp_path / 'report.xmind'
        assert gt._to_xmind(self.PREFIX, _scan_result(), str(out)) is None
        with zipfile.ZipFile(str(out)) as zf:
            assert zf.namelist() == ['mimetype', 'content.xml', 'meta.xml', 'META-INF/manifest.xml']
            assert zf.read('mimetype') == b'application/vnd.xmind.workbook'
            assert zf.getinfo('mimetype').compress_type == zipfile.ZIP_STORED

    def test_graph_links_the_query_node_to_every_hit(self):
        html = gt._to_graph_html(self.PREFIX, _scan_result())
        nodes, links = _graph_payload(html)
        assert nodes == [
            {'id': 'alice', 'group': 1, 'name': 'alice', 'url': ''},
            {'id': 'p_Zhihu', 'group': 2, 'name': 'Zhihu', 'url': _ZHIHU_URL, 'category': 'chinese'},
            {'id': 'p_GitHub', 'group': 2, 'name': 'GitHub', 'url': _GITHUB_URL, 'category': 'code'},
            {'id': 'p_Weibo', 'group': 2, 'name': 'Weibo', 'url': _WEIBO_URL, 'category': 'chinese'},
        ]
        assert links == [
            {'source': 'alice', 'target': 'p_Zhihu', 'value': 1},
            {'source': 'alice', 'target': 'p_GitHub', 'value': 1},
            {'source': 'alice', 'target': 'p_Weibo', 'value': 1},
        ]
        probe = _HtmlProbe(html)
        assert probe.texts['title'] == ['SpyEyes 关系图 — alice']
        assert probe.texts['em'] == ['alice']
        assert '命中 3 个平台' in html

    def test_every_format_follows_the_ui_language(self, tmp_path):
        gt.set_lang('en')
        data = _scan_result()
        md = _md_body(gt._to_markdown(self.PREFIX, data))
        assert md[:5] == [
            '## Username scan: `alice`',
            '**Scanned 5 platforms · Found 3 accounts**',
            '### Code & Dev (1/2)',
            '| Platform | Profile URL |',
            '|---|---|',
        ]
        assert '### Chinese Platforms (CN/TW/HK/SG/MY) (2/2)' in md
        html = gt._to_html(self.PREFIX, data)
        assert '<h3 class="cat">Code &amp; Dev (1/2)</h3>' in html     # 分类标题里的 & 恰好转义一次
        assert _HtmlProbe(html).texts['th'][:2] == ['Platform', 'Profile URL']
        assert '── Code & Dev (1/2) ──' in gt._to_txt(self.PREFIX, data).splitlines()
        assert _csv_rows(gt._to_csv(self.PREFIX, data))[0] == ['Category', 'Platform', 'Profile URL', 'Status']
        _, root = _write_xmind(tmp_path, self.PREFIX, data)
        assert [topic.title for topic in root.children[1:]] == [
            'Code & Dev (1/2)', 'Chinese Platforms (CN/TW/HK/SG/MY) (2/2)',
        ]
        assert 'Found 3 platforms' in gt._to_graph_html(self.PREFIX, data)

    def test_failed_scan_is_reported_as_an_error_in_every_format(self, tmp_path):
        data = {'_error': '=cmd <b>bad</b> | input'}
        quote, = [line for line in gt._to_markdown('username_x', data).splitlines() if 'input' in line]
        assert quote.startswith('> =cmd ') and quote.endswith(' \\| input')
        probe = _HtmlProbe(gt._to_html('username_x', data))
        assert '❌ 错误: =cmd <b>bad</b> | input' in probe.texts['div']
        assert probe.tags.count('b') == 1                    # 只有「错误:」这个标签自带的 <b>
        assert '  ✗ 错误: =cmd <b>bad</b> | input' in gt._to_txt('username_x', data).splitlines()
        assert _csv_rows(gt._to_csv('username_x', data)) == [['错误'], ["'=cmd <b>bad</b> | input"]]
        _, root = _write_xmind(tmp_path, 'username_x', data)
        assert [(topic.title, topic.markers) for topic in root.children[1:]] == [
            ('错误: =cmd <b>bad</b> | input', ['flag-red', 'symbol-warning']),
        ]


class TestUsernameReportEscaping:
    """平台名 / URL 来自平台库（贡献者可改）和目标站点，报告必须把它们当纯数据。"""

    PREFIX = 'username_alice'
    EVIL = 'Evil<script>alert(1)</script>'
    EVIL_URL = 'https://evil.test/alice?next=</script><script>alert(2)</script>'
    # (分类, 平台名, 命中 URL) —— 也是分组报告里应有的顺序
    ROWS = [
        ('code', 'GitHub', 'https://github.com/alice'),
        ('code', EVIL, EVIL_URL),
        ('social', 'Pipe|Name', 'https://pipe.test/a|b'),
        ('social', 'A&B <Official>', 'https://amp.test/alice?a=1&b=2'),
        ('chinese', 'Quote"Name\'s', 'https://quote.test/alice" onmouseover="alert(3)'),
        ('other', '=cmd|calc', '=HYPERLINK("http://evil.test","x")'),
        ('other', '+SUM(1,2)', 'https://plus.test/alice'),
        ('other', '-2+3', 'https://minus.test/alice'),
        ('other', '@at', 'https://at.test/alice'),
    ]

    @pytest.fixture(autouse=True)
    def _platforms(self, monkeypatch):
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [
            gt.Platform(name, 'https://unused.test/{}', category) for category, name, _ in self.ROWS
        ])

    def _data(self) -> dict:
        return {name: url for _, name, url in self.ROWS}

    def test_html_renders_hostile_values_as_inert_text(self):
        html = gt._to_html(self.PREFIX, self._data())
        probe = _HtmlProbe(html)
        # 浏览器解析后看到的文本 / 链接与原始值一字不差 → 转义了，而且只转义了一次
        assert probe.texts['td'] == [cell for _, name, url in self.ROWS for cell in (name, url)]
        assert [a['href'] for a in probe.attrs['a']] == [url for _, _, url in self.ROWS] + [_SPYEYES_LINK]
        # 没有任何内容被解析成标签或事件属性
        assert 'script' not in probe.tags and 'official' not in probe.tags
        assert not [attr for a in probe.attrs['a'] for attr in a if attr.startswith('on')]
        assert '<td>Evil&lt;script&gt;alert(1)&lt;/script&gt;</td>' in html
        assert '&amp;amp;' not in html and '&amp;lt;' not in html and '&amp;quot;' not in html

    def test_markdown_escapes_pipes_so_every_row_keeps_two_cells(self):
        body = _md_body(gt._to_markdown(self.PREFIX, self._data()))
        rows = [line for line in body if line.startswith('| ')]
        pipe_row, = [row for row in rows if 'pipe.test' in row]
        formula_row, = [row for row in rows if 'HYPERLINK' in row]
        assert _md_cells(pipe_row) == ['Pipe\\|Name', '<https://pipe.test/a\\|b>']
        assert _md_cells(formula_row)[0] == '=cmd\\|calc'
        assert len(rows) == 4 + len(self.ROWS)                       # 4 个分类各一行表头 + 9 行数据
        assert all(len(_md_cells(row)) == 2 for row in rows)         # 名字 / URL 里的 | 没有多切出一列

    def test_markdown_keeps_multiline_and_backtick_names_on_one_row(self, monkeypatch):
        name = 'Line1\n## PWNED `code`'
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [gt.Platform(name, 'https://x.test/{}', 'code')])
        lines = gt._to_markdown(self.PREFIX, {name: 'https://x.test/alice'}).splitlines()
        assert '| Line1 ## PWNED \\`code\\` | <https://x.test/alice> |' in lines
        assert not any(line.startswith('## PWNED') for line in lines)

    def test_markdown_does_not_pass_raw_html_in_platform_name_through(self):
        row, = [line for line in gt._to_markdown(self.PREFIX, self._data()).splitlines()
                if 'evil.test/alice' in line]
        assert not _RAW_SCRIPT_TAG.search(_md_cells(row)[0])

    def test_markdown_does_not_pass_raw_html_in_url_through(self):
        row, = [line for line in gt._to_markdown(self.PREFIX, self._data()).splitlines()
                if 'evil.test/alice' in line]
        assert not _RAW_SCRIPT_TAG.search(_md_cells(row)[1])

    def test_txt_keeps_values_verbatim(self):
        lines = gt._to_txt(self.PREFIX, self._data()).splitlines()
        for _, name, url in self.ROWS:
            assert f'  {name:30} {url}' in lines

    def test_csv_defuses_formulas_and_round_trips_everything_else(self):
        text = gt._to_csv(self.PREFIX, self._data())
        rows = _csv_rows(text)
        assert rows[1:] == [
            ['code', 'GitHub', 'https://github.com/alice', 'found'],
            ['code', self.EVIL, self.EVIL_URL, 'found'],
            ['social', 'Pipe|Name', 'https://pipe.test/a|b', 'found'],
            ['social', 'A&B <Official>', 'https://amp.test/alice?a=1&b=2', 'found'],
            ['chinese', 'Quote"Name\'s', 'https://quote.test/alice" onmouseover="alert(3)', 'found'],
            ['other', "'=cmd|calc", '\'=HYPERLINK("http://evil.test","x")', 'found'],
            ['other', "'+SUM(1,2)", 'https://plus.test/alice', 'found'],
            ['other', "'-2+3", 'https://minus.test/alice', 'found'],
            ['other', "'@at", 'https://at.test/alice', 'found'],
        ]
        # 表格软件看到的任何单元格都不以公式字符开头
        assert not [cell for row in rows for cell in row if cell[:1] in ('=', '+', '-', '@')]

    def test_xmind_stays_well_formed_and_round_trips_values(self, tmp_path):
        _, root = _write_xmind(tmp_path, self.PREFIX, self._data())
        leaves = [(leaf.title, leaf.href) for category in root.children[1:] for leaf in category.children]
        assert leaves == [(name, url) for _, name, url in self.ROWS]

    def test_graph_data_cannot_break_out_of_the_script_block(self):
        html = gt._to_graph_html(self.PREFIX, self._data())
        nodes, links = _graph_payload(html)
        assert [(node['name'], node['url']) for node in nodes[1:]] == [(name, url) for _, name, url in self.ROWS]
        assert [link['target'] for link in links] == [f'p_{name}' for _, name, _ in self.ROWS]
        probe = _HtmlProbe(html)
        assert probe.tags.count('script') == 2           # D3 库 + 内联脚本；注入的 <script> 没有变成标签
        assert 'd3.forceSimulation(nodes)' in probe.texts['script'][1]   # 内联脚本没被 </script> 提前截断
        assert html.count('</script>') == 2

    def test_hostile_query_is_escaped_wherever_it_is_shown(self, tmp_path):
        query = '<img src=x onerror=alert(1)>&"q"'
        prefix = f'username_{query}'
        data = {'GitHub': 'https://github.com/alice'}

        page = _HtmlProbe(gt._to_html(prefix, data))
        assert page.texts['title'] == [f'SpyEyes 报告 — {query}']
        assert page.texts['h2'] == [f'用户名扫描: {query}']
        assert 'img' not in page.tags

        graph_html = gt._to_graph_html(prefix, data)
        graph = _HtmlProbe(graph_html)
        assert graph.texts['title'] == [f'SpyEyes 关系图 — {query}']
        assert graph.texts['em'] == [query]
        assert 'img' not in graph.tags
        assert _graph_payload(graph_html)[0][0] == {'id': query, 'group': 1, 'name': query, 'url': ''}

        sheet_title, root = _write_xmind(tmp_path, prefix, data)
        assert sheet_title == f'SpyEyes 报告 — {query}'
        assert root.title == f'👤 SpyEyes 报告 · username · {query}'

    def test_graph_of_a_failed_scan_claims_no_hits(self):
        assert '命中 0 个平台' in gt._to_graph_html('username_x', {'_error': 'scan rejected'})


class TestPermuteListReports:
    """permute 只生成变形、不扫描时的数据形态：{'name': ..., 'permutations': [...]}。"""

    PREFIX = 'permute_John Doe'
    VARIATIONS = ['johndoe', 'john.doe', 'j_doe', 'doe-john']

    def _data(self) -> dict:
        return {'name': 'John Doe', 'permutations': list(self.VARIATIONS)}

    def test_shape_is_recognised_as_a_list_not_a_scan(self):
        assert gt._is_permute_only(self._data()) is True
        assert gt._is_permute_scan(self._data()) is False

    def test_markdown_is_a_bullet_list(self):
        assert _md_body(gt._to_markdown(self.PREFIX, self._data())) == [
            '## 用户名变形： `John Doe`',
            '- `johndoe`', '- `john.doe`', '- `j_doe`', '- `doe-john`',
        ]

    def test_html_is_a_list_without_tables(self):
        probe = _HtmlProbe(gt._to_html(self.PREFIX, self._data()))
        assert probe.texts['h2'] == ['用户名变形： John Doe']
        assert probe.texts['li'] == self.VARIATIONS
        assert 'table' not in probe.tags

    def test_txt_is_a_bullet_list(self):
        assert _txt_body(gt._to_txt(self.PREFIX, self._data()), '用户名变形') == [
            '用户名变形： John Doe',
            '  • johndoe', '  • john.doe', '  • j_doe', '  • doe-john',
        ]

    def test_csv_is_a_single_column(self):
        assert _csv_rows(gt._to_csv(self.PREFIX, self._data())) == [
            ['用户名变形：'], ['johndoe'], ['john.doe'], ['j_doe'], ['doe-john'],
        ]

    def test_xmind_has_one_topic_per_variation(self, tmp_path):
        sheet_title, root = _write_xmind(tmp_path, self.PREFIX, self._data())
        assert sheet_title == 'SpyEyes 报告 — John Doe'
        assert root.title == '🧬 SpyEyes 报告 · permute · John Doe'
        assert [(topic.title, topic.href, topic.markers, topic.children) for topic in root.children[1:]] == [
            (variation, None, ['priority-1'], []) for variation in self.VARIATIONS
        ]

    def test_graph_has_nothing_to_link_so_only_the_query_node(self):
        nodes, links = _graph_payload(gt._to_graph_html(self.PREFIX, self._data()))
        assert nodes == [{'id': 'John Doe', 'group': 1, 'name': 'John Doe', 'url': ''}]
        assert links == []

    def test_heading_uses_the_name_stored_in_the_data(self):
        data = {'name': 'Jane Roe', 'permutations': ['janeroe']}
        assert '## 用户名变形： `Jane Roe`' in gt._to_markdown('permute_x', data).splitlines()
        assert _HtmlProbe(gt._to_html('permute_x', data)).texts['h2'] == ['用户名变形： Jane Roe']
        assert '用户名变形： Jane Roe' in gt._to_txt('permute_x', data).splitlines()

    def test_hostile_name_and_variations_are_escaped_per_format(self, tmp_path):
        variations = ['<script>alert(1)</script>', 'a|b', '=1+1', '@SUM(A1)', '+1', '-1', 'A&B']
        data = {'name': 'J<i>D</i>|x', 'permutations': variations}

        probe = _HtmlProbe(gt._to_html(self.PREFIX, data))
        assert probe.texts['h2'] == ['用户名变形： J<i>D</i>|x']
        assert probe.texts['li'] == variations
        assert 'script' not in probe.tags and 'i' not in probe.tags

        md = _md_body(gt._to_markdown(self.PREFIX, data))
        assert md[0].startswith('## 用户名变形： `J') and md[0].endswith('\\|x`')
        assert '- `a\\|b`' in md

        assert _csv_rows(gt._to_csv(self.PREFIX, data))[1:] == [
            ['<script>alert(1)</script>'], ['a|b'], ["'=1+1"], ["'@SUM(A1)"], ["'+1"], ["'-1"], ['A&B'],
        ]

        _, root = _write_xmind(tmp_path, self.PREFIX, data)
        assert [topic.title for topic in root.children[1:]] == variations


class TestPermuteScanReports:
    """permute + 扫描时的数据形态：{变形: track_username 的结果, ...}。"""

    PREFIX = 'permute_John Doe'
    GITHUB = 'https://github.com/johndoe'
    RETIRED = 'https://retired.test/johndoe'
    WEIBO = 'https://weibo.com/n/doejohn'

    @pytest.fixture(autouse=True)
    def _platforms(self, monkeypatch):
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [
            gt.Platform('GitHub', 'https://github.com/{}', 'code'),
            gt.Platform('Weibo', 'https://weibo.com/n/{}', 'chinese'),
        ])

    def _data(self) -> dict:
        return {
            'johndoe': {
                'GitHub': self.GITHUB, 'Weibo': None,
                'Retired': self.RETIRED,       # 平台库里已经没有这个名字 → 分类按 other 算
                '_statuses': {'GitHub': 'found', 'Weibo': 'not_found', 'Retired': 'found'},
            },
            'john.doe': {'GitHub': None, 'Weibo': None, '_statuses': {'GitHub': 'not_found', 'Weibo': 'waf'}},
            'j_doe': {'_error': 'scan rejected'},
            'doejohn': {'GitHub': None, 'Weibo': self.WEIBO, '_statuses': {'GitHub': 'not_found', 'Weibo': 'found'}},
        }

    def test_shape_is_recognised_as_a_scan_not_a_list(self):
        assert gt._is_permute_scan(self._data()) is True
        assert gt._is_permute_only(self._data()) is False

    def test_markdown_has_one_section_per_variation(self):
        assert _md_body(gt._to_markdown(self.PREFIX, self._data())) == [
            '## 用户名变形： `John Doe`',
            '**共扫描 4 个变形**',
            '### `johndoe`',
            '**共扫描 3 个平台 · 命中 2 个账号**',
            '| 平台 | 主页地址 |',
            '|---|---|',
            f'| GitHub | <{self.GITHUB}> |',
            f'| Retired | <{self.RETIRED}> |',
            '### `john.doe`',
            '**共扫描 2 个平台 · 命中 0 个账号**',       # 没命中 → 只有小结，没有空表
            '### `j_doe`',
            '> ❌ scan rejected',
            '### `doejohn`',
            '**共扫描 2 个平台 · 命中 1 个账号**',
            '| 平台 | 主页地址 |',
            '|---|---|',
            f'| Weibo | <{self.WEIBO}> |',
        ]

    def test_html_has_one_section_per_variation(self):
        html = gt._to_html(self.PREFIX, self._data())
        probe = _HtmlProbe(html)
        assert probe.texts['h2'] == ['用户名变形： John Doe']
        assert probe.texts['h3'] == ['johndoe', 'john.doe', 'j_doe', 'doejohn']
        assert probe.texts['p'] == [
            '共扫描 4 个变形',
            '共扫描 3 个平台 · 命中 2 个账号',
            '共扫描 2 个平台 · 命中 0 个账号',
            '共扫描 2 个平台 · 命中 1 个账号',
        ]
        assert probe.texts['td'] == ['GitHub', self.GITHUB, 'Retired', self.RETIRED, 'Weibo', self.WEIBO]
        assert [a['href'] for a in probe.attrs['a']] == [self.GITHUB, self.RETIRED, self.WEIBO, _SPYEYES_LINK]
        assert '❌ scan rejected' in probe.texts['div']
        assert probe.tags.count('table') == 2            # 没命中的变形不出空表
        assert '_statuses' not in html

    def test_txt_has_one_block_per_variation(self):
        assert _txt_body(gt._to_txt(self.PREFIX, self._data()), '用户名变形') == [
            '用户名变形： John Doe',
            '共扫描 4 个变形',
            '━━━ johndoe ━━━',
            '  共扫描 3 个平台 · 命中 2 个账号',
            f'    {"GitHub":28} {self.GITHUB}',
            f'    {"Retired":28} {self.RETIRED}',
            '━━━ john.doe ━━━',
            '  共扫描 2 个平台 · 命中 0 个账号',
            '━━━ j_doe ━━━',
            '  错误: scan rejected',
            '━━━ doejohn ━━━',
            '  共扫描 2 个平台 · 命中 1 个账号',
            f'    {"Weibo":28} {self.WEIBO}',
        ]

    def test_csv_has_one_row_per_hit_tagged_with_its_variation(self):
        assert _csv_rows(gt._to_csv(self.PREFIX, self._data())) == [
            ['用户名扫描', '分类', '平台', '主页地址'],
            ['johndoe', 'code', 'GitHub', self.GITHUB],
            ['johndoe', 'other', 'Retired', self.RETIRED],
            ['doejohn', 'chinese', 'Weibo', self.WEIBO],
        ]

    def test_xmind_has_one_topic_per_variation(self, tmp_path):
        _, root = _write_xmind(tmp_path, self.PREFIX, self._data())
        assert root.title == '🧬 SpyEyes 报告 · permute · John Doe'
        outline = [(topic.title, topic.markers, [(leaf.title, leaf.href) for leaf in topic.children])
                   for topic in root.children[1:]]
        assert outline == [
            ('johndoe (命中 2 个)', ['flag-purple'], [('GitHub', self.GITHUB), ('Retired', self.RETIRED)]),
            ('john.doe (命中 0 个)', ['flag-orange'], []),
            ('j_doe: 错误 scan rejected', ['flag-red'], []),
            ('doejohn (命中 1 个)', ['flag-purple'], [('Weibo', self.WEIBO)]),
        ]

    def test_graph_has_one_centre_per_variation(self):
        nodes, links = _graph_payload(gt._to_graph_html(self.PREFIX, self._data()))
        assert nodes == [
            {'id': 'johndoe', 'group': 1, 'name': 'johndoe', 'url': ''},
            {'id': 'johndoe__p_GitHub', 'group': 2, 'name': 'GitHub', 'url': self.GITHUB, 'category': 'code'},
            {'id': 'johndoe__p_Retired', 'group': 2, 'name': 'Retired', 'url': self.RETIRED, 'category': 'other'},
            {'id': 'john.doe', 'group': 1, 'name': 'john.doe', 'url': ''},
            {'id': 'doejohn', 'group': 1, 'name': 'doejohn', 'url': ''},       # 出错的 j_doe 不进图
            {'id': 'doejohn__p_Weibo', 'group': 2, 'name': 'Weibo', 'url': self.WEIBO, 'category': 'chinese'},
        ]
        assert links == [
            {'source': 'johndoe', 'target': 'johndoe__p_GitHub', 'value': 1},
            {'source': 'johndoe', 'target': 'johndoe__p_Retired', 'value': 1},
            {'source': 'doejohn', 'target': 'doejohn__p_Weibo', 'value': 1},
        ]

    def test_graph_keeps_the_same_platform_apart_for_each_variation(self):
        data = {
            'johndoe': {'GitHub': 'https://github.com/johndoe', '_statuses': {}},
            'doejohn': {'GitHub': 'https://github.com/doejohn', '_statuses': {}},
        }
        nodes, links = _graph_payload(gt._to_graph_html(self.PREFIX, data))
        ids = [node['id'] for node in nodes]
        assert ids == ['johndoe', 'johndoe__p_GitHub', 'doejohn', 'doejohn__p_GitHub']
        assert len(set(ids)) == len(ids)
        # 每条边的两端都是存在的节点（否则 D3 forceLink 直接抛错，整张图不显示）
        assert all(link['source'] in ids and link['target'] in ids for link in links)

    def test_graph_header_counts_hits_not_nodes(self):
        assert '命中 3 个平台' in gt._to_graph_html(self.PREFIX, self._data())

    def test_hostile_variation_and_platform_are_escaped_per_format(self, tmp_path, monkeypatch):
        evil, evil_url = TestUsernameReportEscaping.EVIL, TestUsernameReportEscaping.EVIL_URL
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', [gt.Platform(evil, 'https://evil.test/{}', 'social')])
        data = {
            '=bad|var': {evil: evil_url, '_statuses': {evil: 'found'}},
            'x<i>y': {'_error': 'boom <b>bang</b>'},
        }

        html = gt._to_html(self.PREFIX, data)
        probe = _HtmlProbe(html)
        assert probe.texts['h3'] == ['=bad|var', 'x<i>y']
        assert probe.texts['td'] == [evil, evil_url]
        assert '❌ boom <b>bang</b>' in probe.texts['div']
        assert 'script' not in probe.tags and 'i' not in probe.tags
        assert probe.tags.count('b') == 1            # 只有「共扫描 N 个变形」小结自带的 <b>

        assert '### `=bad\\|var`' in _md_body(gt._to_markdown(self.PREFIX, data))
        assert _csv_rows(gt._to_csv(self.PREFIX, data))[1:] == [["'=bad|var", 'social', evil, evil_url]]

        _, root = _write_xmind(tmp_path, self.PREFIX, data)
        assert [(topic.title, [(leaf.title, leaf.href) for leaf in topic.children])
                for topic in root.children[1:]] == [
            ('=bad|var (命中 1 个)', [(evil, evil_url)]),
            ('x<i>y: 错误 boom <b>bang</b>', []),
        ]

        graph_html = gt._to_graph_html(self.PREFIX, data)
        nodes, _ = _graph_payload(graph_html)
        assert [(node['name'], node['url']) for node in nodes] == [('=bad|var', ''), (evil, evil_url)]
        assert _HtmlProbe(graph_html).tags.count('script') == 2

    def test_real_input_can_produce_a_variation_called_name(self):
        """下面那条 xfail 的前提：真实输入就会产生名为 name 的变形。"""
        assert 'name' in gt.permute_username('Name Smith')

    def test_variation_called_name_is_still_reported_as_a_scan(self):
        data = {
            'name': {'GitHub': 'https://github.com/name', '_statuses': {'GitHub': 'found'}},
            'smith': {'GitHub': None, '_statuses': {'GitHub': 'not_found'}},
        }
        assert _csv_rows(gt._to_csv('permute_Name Smith', data)) == [
            ['用户名扫描', '分类', '平台', '主页地址'],
            ['name', 'code', 'GitHub', 'https://github.com/name'],
        ]


# ====================================================================
# 10. _maybe_save 的后缀分发
# ====================================================================
_BOM = b'\xef\xbb\xbf'


class TestMaybeSaveDispatch:
    PREFIX = 'username_alice'
    PUBLIC_VIEW = {'Zhihu': _ZHIHU_URL, 'Twitter': None, 'GitHub': _GITHUB_URL, 'Weibo': _WEIBO_URL, 'GitLab': None}

    @pytest.fixture(autouse=True)
    def _platforms(self, monkeypatch):
        monkeypatch.setattr(gt, '_PLATFORMS_CACHE', _scan_platforms())

    @pytest.fixture
    def generators(self, monkeypatch):
        """把所有报告生成器换成打标记的替身，记录谁被调用了。"""
        calls = []

        def text_stub(name):
            def stub(prefix, data):
                calls.append((name, prefix, data))
                return f'<<{name}>>'
            return stub

        def file_stub(name):
            def stub(prefix, data, out_path):
                calls.append((name, prefix, data))
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(f'<<{name}>>')
                return None
            return stub

        for name in ('_to_markdown', '_to_html', '_to_graph_html', '_to_txt', '_to_csv'):
            monkeypatch.setattr(gt, name, text_stub(name))
        for name in ('_to_xmind', '_to_pdf'):
            monkeypatch.setattr(gt, name, file_stub(name))
        return calls

    def test_graph_html_and_html_are_two_different_reports(self, tmp_path, clock):
        data = _scan_result()
        graph_file, html_file = tmp_path / 'r.graph.html', tmp_path / 'r.html'
        gt._maybe_save(str(graph_file), self.PREFIX, data)
        gt._maybe_save(str(html_file), self.PREFIX, data)
        graph, html = graph_file.read_text(encoding='utf-8'), html_file.read_text(encoding='utf-8')
        assert graph == gt._to_graph_html(self.PREFIX, data)
        assert html == gt._to_html(self.PREFIX, data)
        assert 'd3.forceSimulation(nodes)' in graph and '<table>' not in graph
        assert '<table>' in html and 'd3.forceSimulation' not in html

    @pytest.mark.parametrize('filename,generator', [
        ('r.md', '_to_markdown'),
        ('r.html', '_to_html'),
        ('r.graph.html', '_to_graph_html'),
        ('r.txt', '_to_txt'),
        ('r.csv', '_to_csv'),
        ('r.xmind', '_to_xmind'),
        ('R.MD', '_to_markdown'),                  # 后缀不分大小写
        ('R.HTML', '_to_html'),
        ('R.Graph.HTML', '_to_graph_html'),
        ('R.TXT', '_to_txt'),
        ('R.CSV', '_to_csv'),
        ('R.XMind', '_to_xmind'),
        ('graph.html', '_to_html'),                # 只是文件名叫 graph，后缀是 .html
        ('my.graph.v2.html', '_to_html'),
        ('alice.html.graph.html', '_to_graph_html'),
        ('notes.md.txt', '_to_txt'),               # 只看最后的后缀
        ('table.csv.md', '_to_markdown'),
    ])
    def test_suffix_selects_exactly_one_generator(self, tmp_path, generators, filename, generator):
        data = _scan_result()
        out = tmp_path / filename
        gt._maybe_save(str(out), self.PREFIX, data)
        assert [(name, prefix) for name, prefix, _ in generators] == [(generator, self.PREFIX)]
        assert generators[0][2] is data            # 生成器拿到的是原始结果（含 _statuses），不是 JSON 视图
        assert out.read_text(encoding='utf-8-sig') == f'<<{generator}>>'

    @pytest.mark.parametrize('filename', ['r.json', 'R.JSON', 'report', 'r.dat', 'r.htm', 'r.markdown'])
    def test_any_other_name_is_written_as_json(self, tmp_path, generators, filename):
        data = {**_scan_result(), '_recursive': {'levels': [], 'total_found': 3, 'depth_reached': 0}}
        out = tmp_path / filename
        gt._maybe_save(str(out), self.PREFIX, data)
        assert generators == []
        # 用户名结果的公开视图：_statuses 剥掉，_recursive 保留
        assert json.loads(out.read_text(encoding='utf-8')) == {
            **self.PUBLIC_VIEW, '_recursive': {'levels': [], 'total_found': 3, 'depth_reached': 0},
        }

    def test_real_xmind_file_is_written(self, tmp_path):
        out = tmp_path / 'r.xmind'
        gt._maybe_save(str(out), self.PREFIX, _scan_result())
        sheet_title, root = _xmind_outline(out)
        assert sheet_title == 'SpyEyes 报告 — alice'
        assert [topic.title for topic in root.children[1:]] == [f'{_CODE_ZH} (1/2)', f'{_CHINESE_ZH} (2/2)']

    def test_xmind_failure_goes_to_stderr_and_is_not_announced_as_saved(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(gt, '_to_xmind', lambda prefix, data, out_path: 'XMind generation failed: disk full')
        gt._maybe_save(str(tmp_path / 'r.xmind'), self.PREFIX, _scan_result())
        captured = capsys.readouterr()
        assert 'XMind generation failed: disk full' in captured.err
        assert captured.out == ''

    def test_directory_target_gets_a_timestamped_json(self, tmp_path, clock, generators):
        target = str(tmp_path / 'out') + '/'          # 目录还不存在，以 / 结尾 → 当目录建出来
        gt._maybe_save(target, self.PREFIX, _scan_result())
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(clock.time()))
        assert os.listdir(tmp_path / 'out') == [f'username_alice_{stamp}.json']
        saved = (tmp_path / 'out' / f'username_alice_{stamp}.json').read_text(encoding='utf-8')
        assert json.loads(saved) == self.PUBLIC_VIEW
        assert generators == []

    @pytest.mark.parametrize('dirname', ['reports', 'reports.md', 'reports.graph.html', 'reports.csv'])
    def test_existing_directory_always_gets_json_whatever_its_name(self, tmp_path, clock, generators, dirname):
        target = tmp_path / dirname
        target.mkdir()
        gt._maybe_save(str(target), 'mx_example.com', {'domain': 'example.com', 'records': []})
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(clock.time()))
        assert os.listdir(target) == [f'mx_example.com_{stamp}.json']
        assert json.loads((target / f'mx_example.com_{stamp}.json').read_text(encoding='utf-8')) == {
            'domain': 'example.com', 'records': [],
        }
        assert generators == []

    @pytest.mark.parametrize('prefix,stem', [
        ('whois_a/b c:d*e', 'whois_a_b_c_d_e'),            # 路径分隔符 / 空格 / 通配符都换成下划线
        ('username_../../etc/passwd', 'username_.._.._etc_passwd'),
        ('username_张三', 'username_张三'),                  # 中文保留
        ('ip_8.8.8.8', 'ip_8.8.8.8'),
    ])
    def test_directory_filename_is_built_from_a_sanitised_prefix(self, tmp_path, clock, prefix, stem):
        out_dir = tmp_path / 'out'
        gt._maybe_save(str(out_dir) + '/', prefix, {'k': 'v'})
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(clock.time()))
        assert os.listdir(out_dir) == [f'{stem}_{stamp}.json']       # 没有逃出目标目录

    def test_csv_starts_with_exactly_one_utf8_bom(self, tmp_path):
        data = _scan_result()
        out = tmp_path / 'r.csv'
        gt._maybe_save(str(out), self.PREFIX, data)
        raw = out.read_bytes()
        assert raw.startswith(_BOM)                  # 没有 BOM，Excel 会把中文表头显示成乱码
        assert raw.count(_BOM) == 1
        assert raw[len(_BOM):].decode('utf-8') == gt._to_csv(self.PREFIX, data)
        assert raw[len(_BOM):].startswith('分类,平台,主页地址,状态\n'.encode('utf-8'))
        assert b'\r' not in raw                      # newline='' → 行尾不被平台二次翻译

    @pytest.mark.parametrize('filename', ['r.md', 'r.html', 'r.graph.html', 'r.txt', 'r.json'])
    def test_other_formats_have_no_bom(self, tmp_path, filename):
        out = tmp_path / filename
        gt._maybe_save(str(out), self.PREFIX, _scan_result())
        raw = out.read_bytes()
        assert raw and not raw.startswith(_BOM)

    def test_missing_parent_directories_are_created(self, tmp_path, clock):
        out = tmp_path / 'deep' / 'er' / 'r.txt'
        gt._maybe_save(str(out), self.PREFIX, _scan_result())
        assert out.read_text(encoding='utf-8') == gt._to_txt(self.PREFIX, _scan_result())

    def test_absolute_path_of_the_written_file_is_announced(self, tmp_path, capsys):
        out = tmp_path / 'r.txt'
        gt._maybe_save(str(out), self.PREFIX, _scan_result())
        assert gt.t('msg.saved_to', path=os.path.abspath(str(out))) in capsys.readouterr().out


# ====================================================================
# 11. do_investigate 的预算截停与 pivot 截断
# ====================================================================
@pytest.fixture
def world(monkeypatch, clock):
    """顶替 do_investigate 的全部外部依赖（阶段 1 的四个任务 + 两种 pivot）。
    world.cost[步骤] = 该步骤每调用一次，假时钟前进多少秒。"""
    box = SimpleNamespace(
        cost=dict.fromkeys(('whois', 'mx', 'subdomain', 'emails', 'ip', 'user'), 0.0),
        subdomains=[
            {'host': 'www.example.com', 'alive': True, 'a': ['192.0.2.10']},
            {'host': 'api.example.com', 'alive': True, 'a': ['192.0.2.20']},
        ],
        emails=['john.doe@example.com', 'alice@example.com'],
        ips_tracked=[],
        users_tracked=[],
    )
    lock = threading.Lock()

    def whois_lookup(domain):
        clock.advance(box.cost['whois'])
        return {'domain': domain, 'registrar': 'Example Registrar', 'emails': None}

    def mx_lookup(domain):
        clock.advance(box.cost['mx'])
        return {'domain': domain, 'records': [{'preference': 10, 'exchange': f'mx.{domain}'}]}

    def enumerate_subdomains(domain, **kwargs):
        clock.advance(box.cost['subdomain'])
        return {'domain': domain, 'subdomains': box.subdomains}

    def enumerate_domain_emails(domain, **kwargs):
        clock.advance(box.cost['emails'])
        return {'domain': domain, 'emails': [{'address': addr, 'sources': ['crawl']} for addr in box.emails]}

    def track_ip(ip):
        with lock:
            box.ips_tracked.append(ip)
        clock.advance(box.cost['ip'])
        return {'ip': ip, 'country_code': 'US'}

    def track_username(name, **kwargs):
        with lock:
            box.users_tracked.append(name)
        clock.advance(box.cost['user'])
        return {'GitHub': f'https://github.com/{name}', '_statuses': {'GitHub': 'found'}}

    for fake in (whois_lookup, mx_lookup, enumerate_subdomains, enumerate_domain_emails, track_ip, track_username):
        monkeypatch.setattr(gt, fake.__name__, fake)
    return box


def _user_hit(name: str) -> dict:
    return {'local_part': name, 'result': {'GitHub': f'https://github.com/{name}', '_statuses': {'GitHub': 'found'}}}


class TestInvestigateBudget:
    def test_budget_used_up_by_phase_1_skips_every_pivot(self, world):
        world.cost['subdomain'] = 60          # 阶段 1 的线程取消不了，照样跑完，只是把预算耗光了
        data = gt.do_investigate('example.com', budget=10, show_progress=False)
        assert world.ips_tracked == [] and world.users_tracked == []
        assert data['pivots'] == {'ips': {}, 'users': {}}
        assert data['_stats'] == {
            'tasks_done': 4, 'tasks_failed': 0, 'pivots_done': 0, 'pivots_skipped': 0,
            'truncated': {'ips': 0, 'emails': 0}, 'budget_exceeded': True,
        }
        # 阶段 1 的结果完整保留
        assert [s['host'] for s in data['tasks']['subdomain']['subdomains']] == ['www.example.com', 'api.example.com']
        assert data['tasks']['whois']['registrar'] == 'Example Registrar'
        assert data['elapsed'] == 60.0
        assert {node['type'] for node in data['graph']['nodes']} == {'domain', 'mx', 'subdomain', 'email'}

    def test_same_run_within_budget_does_pivot(self, world):
        """对照组：同样慢的阶段 1，预算够就照常 pivot。"""
        world.cost['subdomain'] = 60
        data = gt.do_investigate('example.com', budget=300, show_progress=False)
        assert sorted(world.ips_tracked) == ['192.0.2.10', '192.0.2.20']
        assert sorted(world.users_tracked) == ['alice', 'john.doe']
        assert data['pivots'] == {
            'ips': {'192.0.2.10': {'ip': '192.0.2.10', 'country_code': 'US'},
                    '192.0.2.20': {'ip': '192.0.2.20', 'country_code': 'US'}},
            'users': {'john.doe@example.com': _user_hit('john.doe'), 'alice@example.com': _user_hit('alice')},
        }
        assert data['_stats']['pivots_done'] == 4
        assert data['_stats']['budget_exceeded'] is False

    @pytest.mark.parametrize('budget', [0, -5])
    def test_non_positive_budget_means_no_deadline(self, world, budget):
        world.cost['subdomain'] = 100_000
        data = gt.do_investigate('example.com', budget=budget, show_progress=False)
        assert sorted(world.ips_tracked) == ['192.0.2.10', '192.0.2.20']
        assert sorted(world.users_tracked) == ['alice', 'john.doe']
        assert data['_stats']['budget_exceeded'] is False

    def test_budget_running_out_during_ip_pivot_stops_there(self, world):
        world.subdomains = [{'host': f'h{i}.example.com', 'alive': True, 'a': [f'192.0.2.{i}']} for i in range(1, 7)]
        world.cost['ip'] = 1000               # 查完第一个 IP 就已经超时
        data = gt.do_investigate('example.com', budget=300, show_progress=False)
        assert len(data['pivots']['ips']) == 1
        assert set(data['pivots']['ips']) <= {f'192.0.2.{i}' for i in range(1, 7)}
        # 邮箱 pivot 整个跳过
        assert world.users_tracked == []
        assert data['pivots']['users'] == {}
        assert data['_stats']['pivots_done'] == 1
        assert data['_stats']['budget_exceeded'] is True

    def test_budget_running_out_during_user_pivot_skips_remaining_emails(self, world, monkeypatch):
        monkeypatch.setattr(gt, 'INVESTIGATE_USER_PIVOT_OUTER_WORKERS', 1)    # 串行，结果才确定
        world.subdomains = []
        world.emails = ['alice@example.com', 'john.doe@example.com', 'a.b@example.com', 'carol@example.com']
        world.cost['user'] = 1000             # 扫完第一个邮箱就已经超时
        data = gt.do_investigate('example.com', budget=300, show_progress=False)
        assert world.users_tracked == ['a.b']             # 最像真人的先扫；其余 3 个不再启动
        assert len(data['pivots']['users']) == 1
        assert data['_stats']['budget_exceeded'] is True

    def test_max_pivot_ips_keeps_the_first_n_and_counts_the_rest(self, world):
        world.subdomains = [
            {'host': 'www.example.com', 'alive': True, 'a': ['192.0.2.30', '192.0.2.10']},
            {'host': 'api.example.com', 'alive': True, 'a': ['192.0.2.10', '192.0.2.20']},    # .10 重复
            {'host': 'cdn.example.com', 'alive': True, 'a': ['192.0.2.40', '192.0.2.50']},
            {'host': 'old.example.com', 'alive': False, 'a': ['198.51.100.1']},                # 不活跃 → 不查
            {'host': 'v6.example.com', 'alive': True, 'a': []},
        ]
        world.emails = []
        data = gt.do_investigate('example.com', max_pivot_ips=2, show_progress=False)
        assert sorted(world.ips_tracked) == ['192.0.2.10', '192.0.2.20']
        assert set(data['pivots']['ips']) == {'192.0.2.10', '192.0.2.20'}
        assert data['_stats']['truncated'] == {'ips': 3, 'emails': 0}      # 5 个去重后的活跃 IP，砍掉 3 个
        assert data['_stats']['pivots_done'] == 2
        assert data['_stats']['budget_exceeded'] is False

    def test_ips_under_the_cap_are_each_tracked_once(self, world):
        world.subdomains = [
            {'host': 'www.example.com', 'alive': True, 'a': ['192.0.2.30', '192.0.2.10']},
            {'host': 'api.example.com', 'alive': True, 'a': ['192.0.2.10', '192.0.2.20']},
        ]
        world.emails = []
        data = gt.do_investigate('example.com', max_pivot_ips=3, show_progress=False)
        assert sorted(world.ips_tracked) == ['192.0.2.10', '192.0.2.20', '192.0.2.30']
        assert data['_stats']['truncated'] == {'ips': 0, 'emails': 0}

    def test_max_pivot_emails_keeps_the_most_personal_and_counts_the_rest(self, world):
        world.subdomains = []
        world.emails = [
            'alice@example.com',         # 像用户名：2 分
            'noreply@example.com',       # role 账号 → 不参与
            'john.doe@example.com',      # 多段人名：3 分
            'bob@example.com',           # 太短：1 分
            'ab@example.com',            # 本地部分不足 3 个字符 → 不参与
            'a.b@example.com',           # 3 分，且更短 → 排最前
            'we ird@example.com',        # 不是合法用户名 → 不参与
            'not-an-address',            # 没有 @ → 不参与
        ]
        data = gt.do_investigate('example.com', max_pivot_emails=2, show_progress=False)
        assert sorted(world.users_tracked) == ['a.b', 'john.doe']
        assert data['pivots']['users'] == {
            'a.b@example.com': _user_hit('a.b'),
            'john.doe@example.com': _user_hit('john.doe'),
        }
        assert data['_stats']['truncated'] == {'ips': 0, 'emails': 2}      # 4 个合格的砍掉 2 个；不合格的不计
        assert data['_stats']['pivots_done'] == 2

    def test_emails_under_the_cap_are_all_scanned(self, world):
        world.subdomains = []
        world.emails = ['alice@example.com', 'noreply@example.com', 'john.doe@example.com']
        data = gt.do_investigate('example.com', max_pivot_emails=2, show_progress=False)
        assert sorted(world.users_tracked) == ['alice', 'john.doe']
        assert data['_stats']['truncated'] == {'ips': 0, 'emails': 0}
