"""v1.7.0 综合调查 (investigate) 单元测试。

覆盖:
- 实体侦测 _detect_entity_type
- 邮箱真人评分 _personal_email_score
- do_investigate happy path (mocked deps)
- depth=0 跳过 pivot
- 非 domain 输入返回 _error
- pivot 截断到 max_pivot_*
- role-account 邮箱在 pivot 中被跳过
- 报告生成器 (md/html/txt/csv) 不抛
- CLI run_cli 'investigate' 端到端 + history record
"""
import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spyeyes as gt  # noqa: E402


class TestDetectEntityType:
    def test_domain(self):
        assert gt._detect_entity_type('example.com') == 'domain'

    def test_ipv4(self):
        assert gt._detect_entity_type('8.8.8.8') == 'ip'

    def test_ipv6(self):
        assert gt._detect_entity_type('2001:db8::1') == 'ip'

    def test_email(self):
        assert gt._detect_entity_type('a@b.com') == 'email'

    def test_username(self):
        assert gt._detect_entity_type('torvalds') == 'username'

    def test_empty(self):
        assert gt._detect_entity_type('') == 'unknown'

    def test_idn_domain(self):
        # IDN domain (Chinese) — should normalize and detect as domain
        assert gt._detect_entity_type('中国.cn') == 'domain'


class TestPersonalEmailScore:
    def test_role_account_zero(self):
        assert gt._personal_email_score('noreply') == 0
        assert gt._personal_email_score('info') == 0
        assert gt._personal_email_score('admin') == 0

    def test_role_variant_one(self):
        assert gt._personal_email_score('noreply-john') == 1
        assert gt._personal_email_score('info.dept') == 1

    def test_dotted_personal_three(self):
        assert gt._personal_email_score('john.doe') == 3
        assert gt._personal_email_score('first_last') == 3

    def test_plain_username_two(self):
        assert gt._personal_email_score('torvalds') == 2
        # zhangsan is 8 chars, no dot → score 2 (looks like a username)
        assert gt._personal_email_score('zhangsan') == 2

    def test_short_one(self):
        assert gt._personal_email_score('xx') == 1

    def test_pure_digits_zero(self):
        assert gt._personal_email_score('12345') == 0


class TestDoInvestigate:
    """Happy path / failure / cap behaviours, with all network deps mocked."""

    @pytest.fixture(autouse=True)
    def _mock_deps(self, monkeypatch):
        monkeypatch.setattr(gt, 'whois_lookup',
                            lambda d: {'domain': d, 'registrar': 'Test Reg',
                                       'emails': ['admin@' + d]})
        monkeypatch.setattr(gt, 'mx_lookup',
                            lambda d: {'domain': d, 'records': [
                                {'preference': 10, 'exchange': 'mx1.' + d}]})
        monkeypatch.setattr(gt, 'enumerate_subdomains',
                            lambda d, **kw: {'domain': d, 'subdomains': [
                                {'host': 'www.' + d, 'alive': True, 'a': ['1.2.3.4'],
                                 'http_status': 200},
                                {'host': 'api.' + d, 'alive': True, 'a': ['1.2.3.5'],
                                 'http_status': 200},
                                {'host': 'dead.' + d, 'alive': False, 'a': []},
                            ], '_stats': {'total': 3, 'alive': 2}})
        monkeypatch.setattr(gt, 'enumerate_domain_emails',
                            lambda d, **kw: {'domain': d, 'emails': [
                                {'address': 'john.doe@' + d, 'sources': ['crawl']},
                                {'address': 'noreply@' + d, 'sources': ['whois']},
                                {'address': 'alice@' + d, 'sources': ['crtsh']},
                            ], '_stats': {'total': 3, 'pages_crawled': 5}})
        monkeypatch.setattr(gt, 'track_ip',
                            lambda ip: {'country': 'United States', 'org': 'TestNet'})
        # track_username returns mostly empty so test is fast
        monkeypatch.setattr(gt, 'track_username',
                            lambda u, **kw: {'github': f'https://github.com/{u}',
                                             '_statuses': {}})

    def test_domain_happy_path(self):
        data = gt.do_investigate('example.com', depth=1, show_progress=False)
        assert data['entity_type'] == 'domain'
        assert data['target'] == 'example.com'
        assert data['_stats']['tasks_done'] == 4
        assert data['_stats']['tasks_failed'] == 0
        assert 'tasks' in data and 'pivots' in data
        assert data['tasks']['whois']['registrar'] == 'Test Reg'
        # pivots: 2 IPs from alive subdomains
        assert len(data['pivots']['ips']) == 2
        # pivots: 2 users (john.doe + alice) — noreply skipped as role-account
        assert len(data['pivots']['users']) == 2
        assert 'noreply@example.com' not in data['pivots']['users']

    def test_depth_zero_no_pivots(self):
        data = gt.do_investigate('example.com', depth=0, show_progress=False)
        assert data['pivots']['ips'] == {}
        assert data['pivots']['users'] == {}
        assert data['_stats']['tasks_done'] == 4  # all 4 atomic tasks still ran

    def test_max_pivot_ips_caps(self):
        data = gt.do_investigate('example.com', depth=1, max_pivot_ips=1,
                                 show_progress=False)
        assert len(data['pivots']['ips']) == 1
        assert data['_stats']['truncated']['ips'] == 1

    def test_max_pivot_emails_caps(self):
        # alice+john are personal → both eligible; cap to 1 keeps the higher-scored
        data = gt.do_investigate('example.com', depth=1, max_pivot_emails=1,
                                 show_progress=False)
        assert len(data['pivots']['users']) == 1
        # john.doe has score 3 (dotted), alice has score 2 → john.doe wins
        assert 'john.doe@example.com' in data['pivots']['users']

    def test_non_domain_target_errors(self):
        d = gt.do_investigate('8.8.8.8', show_progress=False)
        assert '_error' in d
        assert d['entity_type'] == 'ip'

    def test_empty_target_errors(self):
        d = gt.do_investigate('', show_progress=False)
        assert '_error' in d

    def test_invalid_domain_errors(self):
        d = gt.do_investigate('not a domain!!', show_progress=False)
        assert '_error' in d

    def test_failed_task_does_not_abort_others(self, monkeypatch):
        # WHOIS fails but the other 3 should still complete successfully
        monkeypatch.setattr(gt, 'whois_lookup',
                            lambda d: {'_error': 'whois server down'})
        data = gt.do_investigate('example.com', depth=0, show_progress=False)
        assert data['_stats']['tasks_failed'] == 1
        assert data['_stats']['tasks_done'] == 3
        assert '_error' in data['tasks']['whois']
        assert '_error' not in data['tasks']['mx']

    def test_graph_built(self):
        data = gt.do_investigate('example.com', depth=1, show_progress=False)
        g = data['graph']
        node_ids = {n['id'] for n in g['nodes']}
        # root + 2 alive subdomains + 1 mx + multiple emails + 2 IPs
        assert 'example.com' in node_ids
        assert 'www.example.com' in node_ids
        assert 'mx1.example.com' in node_ids
        assert '1.2.3.4' in node_ids
        # edges are list of dicts with src/dst/kind
        kinds = {e['kind'] for e in g['edges']}
        assert 'subdomain' in kinds
        assert 'mx_record' in kinds
        assert 'resolves_to' in kinds

    # v1.8.0:Phase 2b 并行化测试

    def test_pivot2_passes_inner_workers_to_track_username(self, monkeypatch):
        """验证并行 pivot 把 INNER_WORKERS 而非旧的 120 传给 track_username。"""
        captured: list = []
        def spy_track_username(u, **kw):
            captured.append({'user': u, 'max_workers': kw.get('max_workers')})
            return {}
        monkeypatch.setattr(gt, 'track_username', spy_track_username)
        gt.do_investigate('example.com', depth=1, show_progress=False)
        # 至少应该有 2 次调用(john.doe + alice)
        assert len(captured) >= 2
        # 全部用新的 INNER_WORKERS = 50,而非旧的 120
        for call in captured:
            assert call['max_workers'] == gt.INVESTIGATE_USER_PIVOT_INNER_WORKERS

    def test_pivot2_silent_when_show_progress_false(self, monkeypatch, capsys):
        """show_progress=False 时,新增的 [N/M] 进度行不应写 stderr。"""
        gt.do_investigate('example.com', depth=1, show_progress=False)
        captured = capsys.readouterr()
        # stderr 应完全干净(尤其不能有 [N/M] 或 ✓/✗ 进度行)
        assert '[1/' not in captured.err
        assert '[2/' not in captured.err

    def test_pivot2_outer_workers_capped_at_pick_count(self, monkeypatch):
        """outer worker 数应该是 min(配置值, 实际邮箱数) — 防止开过多空线程。"""
        # 只给 1 个真人邮箱(把其他 mock 成 role-account)
        monkeypatch.setattr(gt, 'enumerate_domain_emails',
                            lambda d, **kw: {'domain': d, 'emails': [
                                {'address': 'john.doe@' + d, 'sources': ['crawl']},
                            ], '_stats': {'total': 1, 'pages_crawled': 1}})
        # 不应该崩(min(4, 1) = 1 worker pool 仍 work)
        data = gt.do_investigate('example.com', depth=1, show_progress=False)
        assert len(data['pivots']['users']) == 1


class TestInvestigateReports:
    """报告生成器对 investigate_* prefix 不抛 + 含关键字段。"""

    @pytest.fixture
    def sample_data(self):
        return {
            'entity_type': 'domain',
            'target': 'example.com',
            'depth': 1,
            'elapsed': 12.5,
            'tasks': {
                'whois': {'domain': 'example.com', 'registrar': 'X',
                          'emails': ['a@example.com']},
                'mx': {'domain': 'example.com', 'records': [
                    {'preference': 10, 'exchange': 'mx.example.com'}]},
                'subdomain': {'domain': 'example.com', 'subdomains': [
                    {'host': 'www.example.com', 'alive': True, 'a': ['1.1.1.1'],
                     'http_status': 200}],
                              '_stats': {'total': 1, 'alive': 1}},
                'emails': {'domain': 'example.com', 'emails': [
                    {'address': 'admin@example.com', 'sources': ['whois']}],
                           '_stats': {'total': 1, 'pages_crawled': 1}},
            },
            'pivots': {
                'ips': {'1.1.1.1': {'country': 'US', 'org': 'CF'}},
                'users': {'admin@example.com': {'local_part': 'admin',
                                                 'result': {'github': 'https://gh.example/admin'}}},
            },
            'graph': {'nodes': [], 'edges': []},
            '_stats': {'tasks_done': 4, 'tasks_failed': 0, 'pivots_done': 2,
                       'pivots_skipped': 0, 'truncated': {'ips': 0, 'emails': 0},
                       'budget_exceeded': False},
        }

    def test_markdown_renders(self, sample_data):
        md = gt._to_markdown('investigate_example.com', sample_data)
        assert 'example.com' in md
        assert 'mx.example.com' in md
        assert 'www.example.com' in md
        assert 'admin@example.com' in md
        # role-section headings
        assert 'WHOIS' in md or 'whois' in md.lower()

    def test_html_renders_and_escapes(self, sample_data):
        html = gt._to_html('investigate_example.com', sample_data)
        assert '<html' in html
        assert '</html>' in html
        # 应该有表格
        assert '<table' in html
        # mailto: 链接应该生成
        assert 'mailto:admin@example.com' in html

    def test_html_escapes_user_data(self, sample_data):
        # Inject XSS attempt in registrar — should be escaped
        sample_data['tasks']['whois']['registrar'] = '<script>alert(1)</script>'
        html = gt._to_html('investigate_example.com', sample_data)
        assert '<script>alert(1)</script>' not in html
        assert '&lt;script&gt;' in html

    def test_txt_renders(self, sample_data):
        txt = gt._to_txt('investigate_example.com', sample_data)
        assert 'example.com' in txt
        assert 'admin@example.com' in txt

    def test_csv_renders_wide_format(self, sample_data):
        csv = gt._to_csv('investigate_example.com', sample_data)
        assert 'section,kind,key,value' in csv
        assert 'whois,field,registrar,X' in csv
        assert 'mx,record,10,mx.example.com' in csv
        assert 'ip_pivot,enriched,1.1.1.1' in csv

    def test_csv_injection_safe(self, sample_data):
        # CSV injection — formula-prefixed registrar should be defanged with leading '
        sample_data['tasks']['whois']['registrar'] = '=cmd|"calc"'
        csv = gt._to_csv('investigate_example.com', sample_data)
        # _csv_safe prefixes a single quote to defang
        assert "'=cmd" in csv or '"=cmd' in csv  # quoted by csv module is ok too

    def test_error_data_renders(self):
        err = {'_error': 'something failed', 'target': 'example.com',
               'entity_type': 'domain'}
        # _to_markdown / _to_html / _to_txt / _to_csv must all handle _error gracefully
        assert 'something failed' in gt._to_markdown('investigate_example.com', err)
        assert 'something failed' in gt._to_html('investigate_example.com', err)
        assert 'something failed' in gt._to_txt('investigate_example.com', err)
        assert 'something failed' in gt._to_csv('investigate_example.com', err)


class TestInvestigateCli:
    """End-to-end: build_parser accepts the subcommand + run_cli dispatches."""

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gt, 'HISTORY_FILE', str(tmp_path / 'h.jsonl'))
        monkeypatch.setattr(gt, 'CONFIG_DIR', str(tmp_path))

    def test_parser_accepts_investigate(self):
        parser = gt.build_parser()
        args = parser.parse_args(['investigate', 'example.com'])
        assert args.command == 'investigate'
        assert args.target == 'example.com'
        assert args.depth == 1
        assert args.max_pivot_ips == gt.INVESTIGATE_MAX_PIVOT_IPS

    def test_parser_accepts_flags(self):
        parser = gt.build_parser()
        args = parser.parse_args(['investigate', 'example.com',
                                  '--depth', '0', '--budget', '60',
                                  '--max-pivot-ips', '5',
                                  '--max-pivot-emails', '3',
                                  '--no-quick', '--no-probe'])
        assert args.depth == 0
        assert args.budget == 60
        assert args.max_pivot_ips == 5
        assert args.max_pivot_emails == 3
        assert args.no_quick is True
        assert args.no_probe is True

    def test_run_cli_dispatches(self, monkeypatch, capsys):
        """run_cli calls do_investigate and emits JSON when --json is set."""
        def fake_invest(target, **kw):
            return {'entity_type': 'domain', 'target': target,
                    'tasks': {}, 'pivots': {'ips': {}, 'users': {}},
                    'graph': {'nodes': [], 'edges': []},
                    '_stats': {'tasks_done': 4, 'tasks_failed': 0,
                               'pivots_done': 0, 'pivots_skipped': 0,
                               'truncated': {'ips': 0, 'emails': 0},
                               'budget_exceeded': False}}
        monkeypatch.setattr(gt, 'do_investigate', fake_invest)
        args = argparse.Namespace(
            command='investigate', target='example.com', depth=1,
            budget=300.0, max_pivot_ips=20, max_pivot_emails=15,
            no_quick=False, no_probe=False, json=True, save=None,
        )
        rc = gt.run_cli(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert 'example.com' in out

    def test_run_cli_error_returns_1(self, monkeypatch, capsys):
        monkeypatch.setattr(gt, 'do_investigate',
                            lambda t, **kw: {'_error': 'bad', 'target': t})
        args = argparse.Namespace(
            command='investigate', target='bad!!', depth=1,
            budget=300.0, max_pivot_ips=20, max_pivot_emails=15,
            no_quick=False, no_probe=False, json=True, save=None,
        )
        rc = gt.run_cli(args)
        assert rc == 1

    def test_history_recorded(self, monkeypatch, tmp_path):
        """investigate 写 history.jsonl,记 target + stats summary."""
        monkeypatch.setattr(gt, 'do_investigate',
                            lambda t, **kw: {'entity_type': 'domain', 'target': t,
                                              'tasks': {}, 'pivots': {'ips': {}, 'users': {}},
                                              'graph': {'nodes': [], 'edges': []},
                                              'elapsed': 1.5,
                                              '_stats': {'tasks_done': 4, 'tasks_failed': 0,
                                                         'pivots_done': 2, 'pivots_skipped': 0,
                                                         'truncated': {'ips': 0, 'emails': 0},
                                                         'budget_exceeded': False}})
        args = argparse.Namespace(
            command='investigate', target='example.com', depth=1,
            budget=300.0, max_pivot_ips=20, max_pivot_emails=15,
            no_quick=False, no_probe=False, json=True, save=None,
        )
        gt.run_cli(args)
        entries = gt.read_history(limit=10)
        assert any(e.get('cmd') == 'investigate' for e in entries)
