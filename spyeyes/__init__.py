#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
SpyEyes —— All-in-One OSINT Toolkit (Bilingual: zh / en)

  支持: IP / 本机 IP / 电话 / 用户名 (3164 平台) / WHOIS / MX / 邮箱
        + 用户名变形 / 递归扫描 / 8 种报告格式（v1.2.0：HTML / PDF / XMind / Graph 等，全部 i18n）
  Features: IP / MyIP / Phone / Username (3164 platforms) / WHOIS / MX / Email
        + Permutations / Recursive scan / 8 report formats (v1.2.0: HTML / PDF / XMind / Graph, all i18n)

  https://github.com/Akxan/SpyEyes

Copyright 2026 Akxan
Licensed under the Apache License, Version 2.0
"""

import argparse
import csv as _csv
import io as _io
import ipaddress
import itertools
import json
import os
import re
import sys
import threading
import time
import uuid as _uuid
import zipfile as _zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple, Optional

import phonenumbers
import requests
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import NumberParseException

try:
    import dns.resolver  # type: ignore
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois  # type: ignore
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

# v1.1.0: PDF 输出（可选 extras 依赖 spyeyes[pdf] = reportlab）
try:
    from reportlab.lib import colors as _rl_colors  # type: ignore
    from reportlab.lib.pagesizes import A4 as _rl_a4  # type: ignore
    from reportlab.lib.styles import getSampleStyleSheet as _rl_styles  # type: ignore
    from reportlab.platypus import (  # type: ignore
        HRFlowable as _rl_hr,
        PageBreak as _rl_pagebreak,
        Paragraph as _rl_paragraph,
        SimpleDocTemplate as _rl_doc,
        Spacer as _rl_spacer,
        Table as _rl_table,
        TableStyle as _rl_table_style,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


# 语义化版本号 —— 同步更新 docs/CHANGELOG.md 与 git tag
__version__ = '1.8.1'


# ====================================================================
# CONFIG —— 用户偏好持久化（语言等）
# ====================================================================
CONFIG_DIR = os.path.expanduser('~/.spyeyes')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
HISTORY_FILE = os.path.join(CONFIG_DIR, 'history.jsonl')
ENV_FILE = os.path.join(CONFIG_DIR, 'env')   # v1.6.8:KEY=VALUE 格式 API key 配置

# 历史遗留路径（早期版本配置目录），首次启动时自动迁移
_LEGACY_CONFIG_DIR = os.path.expanduser('~/.ghosttrack')


def _load_env_file() -> int:
    """v1.6.8:从 ~/.spyeyes/env 读 KEY=VALUE 格式 API key 配置。

    设计原因(替代 LaunchAgent 方案):
    - LaunchAgent 在 macOS Sequoia 显示"未签名开发者"警告 + 污染登录项
    - 跨平台不一致(Windows / Linux 没有 LaunchAgent)
    - 改 key 要重启
    - 现在改成读项目控制的简单文件,跨平台一致 + 不污染系统

    格式:
      KEY=VALUE          # 简单赋值
      KEY="VALUE"        # 带引号(支持空格 / 特殊字符)
      KEY='VALUE'        # 单引号
      # 注释行,空行                  也支持

    优先级:已存在的 os.environ 优先(用户显式 export 的不被覆盖),
    文件里的值仅填补缺失的。

    返回:成功读取的 KEY 数(供测试 / 启动 log)。"""
    if not os.path.isfile(ENV_FILE):
        return 0
    loaded = 0
    try:
        with open(ENV_FILE, encoding='utf-8') as f:
            for line_no, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                # 剥可选引号
                if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
                    value = value[1:-1]
                if not key:
                    continue
                # 已存在的不覆盖(用户 shell export 优先)
                if key in os.environ:
                    continue
                os.environ[key] = value
                loaded += 1
    except OSError:
        pass
    return loaded


# 模块加载时自动读 env 文件(早于任何 _src_* 调用 os.environ.get)
_load_env_file()


def _migrate_legacy_config() -> None:
    """如有旧配置/历史文件且新位置不存在，自动迁移（一次性、无感）。"""
    try:
        legacy_pairs = [
            (os.path.join(_LEGACY_CONFIG_DIR, 'config.json'), CONFIG_FILE),
            (os.path.join(_LEGACY_CONFIG_DIR, 'history.jsonl'), HISTORY_FILE),
        ]
        if not any(os.path.exists(legacy) for legacy, _ in legacy_pairs):
            return
        os.makedirs(CONFIG_DIR, exist_ok=True)
        for legacy, new in legacy_pairs:
            if os.path.exists(legacy) and not os.path.exists(new):
                # errors='replace' 防 GBK / 半行损坏的旧文件让迁移整个失败
                with open(legacy, encoding='utf-8', errors='replace') as src, \
                     open(new, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
    except (OSError, UnicodeDecodeError):
        pass


def append_history(command: str, query: str, summary: dict) -> None:
    """追加查询记录到 history.jsonl。仅记录元数据（时间/命令/查询/摘要），
    不存完整结果，保护隐私 + 控制文件大小。
    时间戳含时区（OSINT 跨时区分析需要 TZ 信息才能复现）。

    隐私选项：设 SPYEYES_NO_HISTORY=1 完全禁用历史记录（敏感场景如取证调查）。
    """
    if os.environ.get('SPYEYES_NO_HISTORY', '').strip() in ('1', 'true', 'yes'):
        return
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        entry = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z') or time.strftime('%Y-%m-%dT%H:%M:%S'),
            'cmd': command,
            'query': query,
            **summary,
        }
        with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        pass


def read_history(limit: int = 50, search: Optional[str] = None) -> list:
    """读取最近的查询历史。
    - limit: 最近 N 条（必须 >= 1，否则返回空列表 —— 与 CLI argparse 校验一致）
    - search: 按 query 子串过滤
    """
    if not os.path.exists(HISTORY_FILE):
        return []
    entries: list = []
    try:
        # errors='replace' 防外部进程写入了非 UTF-8 字节让整个 read 挂掉
        with open(HISTORY_FILE, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except (OSError, UnicodeDecodeError):
        return []
    if search:
        s = search.lower()
        # `or ''` 防 entry 字段值为 None（手工编辑 / 第三方写入 / 老版本数据）
        entries = [e for e in entries if s in (e.get('query') or '').lower()
                   or s in (e.get('cmd') or '').lower()]
    # limit <= 0 返回空（与 argparse 校验一致；之前 entries[-0:] 全返回反直觉）
    if limit <= 0:
        return []
    return entries[-limit:]


def load_config() -> dict:
    # 一次性迁移老路径配置（升级用户无感）
    _migrate_legacy_config()
    try:
        with open(CONFIG_FILE, encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}


def save_config(cfg: dict) -> None:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


# ====================================================================
# UPDATE CHECK —— 启动时静默检查 GitHub Release 新版本
# ====================================================================
# 设计要点(参考 yt-dlp / gh CLI 等成熟实践):
# - 完全异步,不阻塞主流程(后台 daemon 线程)
# - 24h 缓存,避免每次启动都打 GitHub API
# - 完整离线降级(无网/超时/解析错误一律静默)
# - 可禁用:SPYEYES_NO_UPDATE_CHECK=1 / --no-update-check
# - 通知输出到 stderr,不污染 --json 管道(jq 等下游工具不受影响)

UPDATE_CACHE_FILE = os.path.join(CONFIG_DIR, '.update_check.json')
UPDATE_CHECK_URL = 'https://api.github.com/repos/Akxan/SpyEyes/releases/latest'
UPDATE_RELEASES_URL_TEMPLATE = 'https://github.com/Akxan/SpyEyes/releases/tag/{tag}'
UPDATE_CACHE_TTL = 24 * 3600   # 24h
UPDATE_CHECK_TIMEOUT = 3.0     # 3s 网络超时


def _normalize_version(s: str) -> tuple:
    """'v1.7.0' / '1.7.0' / 'v1.7.0-rc1' → (1, 7, 0)。无法解析返回 ()。"""
    raw = (s or '').strip().lstrip('vV').split('-')[0].split('+')[0]
    if not raw:
        return ()
    parts = raw.split('.')
    out: list = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            return ()
    return tuple(out)


def _is_newer(remote: str, local: str) -> bool:
    """语义化比较:remote > local → True。任一无法解析 → False(保守不打扰)。"""
    r = _normalize_version(remote)
    lo = _normalize_version(local)
    if not r or not lo:
        return False
    return r > lo


def _read_update_cache() -> Optional[dict]:
    """读 ~/.spyeyes/.update_check.json。任何失败返回 None。"""
    try:
        with open(UPDATE_CACHE_FILE, encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _write_update_cache(data: dict) -> None:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(UPDATE_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def _fetch_latest_version_from_github() -> Optional[str]:
    """同步 HTTP 调用,3s 超时,完全静默(任何错误返回 None)。

    用 requests.get 而不是 safe_get:此函数在模块早期路径(main 启动时)运行,
    不希望依赖 _get_session() 的 thread-local 初始化。"""
    try:
        resp = requests.get(
            UPDATE_CHECK_URL,
            headers={
                'User-Agent': f'spyeyes/{__version__}',
                'Accept': 'application/vnd.github+json',
            },
            timeout=UPDATE_CHECK_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        tag = data.get('tag_name') if isinstance(data, dict) else None
        return tag if isinstance(tag, str) and tag.strip() else None
    except (requests.RequestException, ValueError, OSError):
        return None


def _is_update_check_disabled() -> bool:
    return os.environ.get('SPYEYES_NO_UPDATE_CHECK', '').strip().lower() in ('1', 'true', 'yes')


def get_cached_update_info() -> Optional[dict]:
    """同步读缓存,立即返回。
    返回 {latest, current, url} 表示有新版本; None 表示无更新 / 无缓存 / 已禁用。
    """
    if _is_update_check_disabled():
        return None
    cache = _read_update_cache()
    if not cache:
        return None
    latest = cache.get('latest')
    if not isinstance(latest, str) or not _is_newer(latest, __version__):
        return None
    return {
        'latest': latest,
        'current': __version__,
        'url': cache.get('url') or UPDATE_RELEASES_URL_TEMPLATE.format(tag=latest),
    }


def refresh_update_cache_sync() -> None:
    """同步刷新缓存(实查 GitHub)。供后台线程或测试调用。"""
    if _is_update_check_disabled():
        return
    tag = _fetch_latest_version_from_github()
    payload = {
        'checked_at': time.time(),
        'latest': tag,
        'url': UPDATE_RELEASES_URL_TEMPLATE.format(tag=tag) if tag else None,
    }
    _write_update_cache(payload)


def _start_background_update_check() -> None:
    """启动后台 daemon 线程刷新缓存。
    24h 内已查过则跳过(避免每次启动都打 GitHub API)。"""
    if _is_update_check_disabled():
        return
    cache = _read_update_cache()
    if cache:
        ts = cache.get('checked_at', 0)
        if isinstance(ts, (int, float)) and (time.time() - ts) < UPDATE_CACHE_TTL:
            return   # 缓存还新,不查
    th = threading.Thread(target=refresh_update_cache_sync,
                          daemon=True, name='spyeyes-update-check')
    th.start()


def print_update_notice(info: dict) -> None:
    """启动时打印一行升级提示到 stderr(不污染 --json 管道)。
    所有 i18n 调用前 _lang 必须已设定。"""
    try:
        msg_avail = t('update.available', latest=info['latest'], current=info['current'])
        # 打包安装(pip/pipx)用户没有 repo 目录,给 pip --upgrade 指令;源码用户走 git pull。
        msg_howto = t('update.howto_packaged' if _is_packaged_install() else 'update.howto')
        msg_notes = t('update.release_notes', url=info.get('url') or '')
        msg_hint = t('update.disable_hint')
        sys.stderr.write(
            f"\n{Color.Ye}🆕 {msg_avail}{Color.Reset}\n"
            f"   {Color.Cy}{msg_howto}{Color.Reset}\n"
            f"   {Color.Gr}{msg_notes}{Color.Reset}\n"
            f"   {Color.Bl}{msg_hint}{Color.Reset}\n\n"
        )
    except (OSError, UnicodeEncodeError):
        pass


# ====================================================================
# I18N —— 中英文双语翻译系统
# ====================================================================
TRANSLATIONS: dict = {
    'en': {
        # Menu
        'menu.ip_track':        'IP Tracker',
        'menu.my_ip':           'My Public IP',
        'menu.phone':           'Phone Number Tracker',
        'menu.username':        'Username Scanner',
        'menu.whois':           'Domain WHOIS Lookup',
        'menu.mx':              'Domain MX Records',
        'menu.email':           'Email Validator',
        'menu.subdomain':       'Subdomain Enumeration',
        'menu.domain_emails':   'Domain Emails (OSINT email harvest)',
        'menu.upgrade':         'Check & Upgrade SpyEyes',
        'menu.lang':            'Language / 语言',
        'menu.exit':            'Exit',
        'menu.back_hint':       '(In any sub-menu, enter 0 or press Enter to return here)',
        # Prompts
        'prompt.select_option': 'Select option : ',
        'prompt.input_ip':      'Enter target IP : ',
        'prompt.input_phone':   'Enter phone number e.g. [+12025550100] : ',
        'prompt.input_username':'Enter username : ',
        'prompt.input_domain':  'Enter domain : ',
        'prompt.input_email':   'Enter email : ',
        'prompt.press_enter':   'Press Enter to continue',
        'prompt.input_number':  'Please enter a number',
        'prompt.unknown_option':'Unknown option: {n}',
        'prompt.bye':           'Goodbye!',
        'prompt.interrupted':   'Interrupted',
        'prompt.exited':        'Exited',
        # Language picker
        'lang.title':           'Please select language / 请选择语言:',
        'lang.zh':              '中文 (Chinese)',
        'lang.en':              'English (英文)',
        'lang.cancel':          'Back / 返回',
        'lang.changed':         'Language switched to English',
        # Section headers
        'section.ip':           'IP Address Info',
        'section.my_ip':        'My IP Info',
        'section.phone':        'Phone Number Info',
        'section.username':     'Username Scan Results',
        'section.whois':        'WHOIS Lookup',
        'section.mx':           'MX Records',
        'section.email':        'Email Validity',
        'section.subdomain':    'Subdomain Enumeration',
        'section.history':      'Recent Queries',
        # IP fields
        'field.target_ip':      'Target IP',
        'field.ip_type':        'IP Type',
        'field.country':        'Country',
        'field.country_code':   'Country Code',
        'field.city':           'City',
        'field.continent':      'Continent',
        'field.region':         'Region',
        'field.latitude':       'Latitude',
        'field.longitude':      'Longitude',
        'field.maps':           'Google Maps',
        'field.is_eu':          'Is EU',
        'field.postal':         'Postal',
        'field.calling_code':   'Calling Code',
        'field.capital':        'Capital',
        'field.flag':           'Flag',
        'field.asn':            'ASN',
        'field.org':            'Organization',
        'field.isp':            'ISP',
        'field.domain':         'Domain',
        'field.timezone_id':    'Timezone ID',
        'field.timezone_abbr':  'Timezone Abbr',
        'field.utc_offset':     'UTC Offset',
        # Phone fields
        'field.location':       'Location',
        'field.region_code':    'Region Code',
        'field.timezone':       'Timezone',
        'field.carrier':        'Carrier (block-allocated)',
        'field.carrier_realtime': 'Carrier (realtime HLR)',
        'phone.mnp_note':       'Block-allocated carrier — actual carrier may differ if number was ported (MNP)',
        'phone.realtime_hint':  'Set SPYEYES_PHONE_API_KEY=numverify:YOUR_KEY for realtime carrier lookup',
        'phone.realtime_failed': 'Realtime carrier lookup failed: {err}',
        'field.is_valid':       'Valid Number',
        'field.is_possible':    'Possible Number',
        'field.intl_format':    'International Format',
        'field.mobile_dial':    'Mobile Dial Format',
        'field.original_num':   'Original Number',
        'field.e164_format':    'E.164 Format',
        'field.number_type':    'Number Type',
        # Phone types
        'phone.mobile':         'Mobile phone',
        'phone.fixed':          'Fixed-line phone',
        'phone.fixed_or_mobile':'Fixed or mobile',
        'phone.toll_free':      'Toll-free',
        'phone.premium':        'Premium-rate',
        'phone.shared_cost':    'Shared-cost',
        'phone.voip':           'VoIP',
        'phone.personal':       'Personal number',
        'phone.pager':          'Pager',
        'phone.uan':            'Universal Access Number',
        'phone.voicemail':      'Voicemail',
        'phone.unknown':        'Unknown',
        'phone.other':          'Other type',
        # WHOIS fields
        'field.whois_domain':   'Domain',
        'field.registrar':      'Registrar',
        'field.creation_date':  'Created',
        'field.expiration_date':'Expires',
        'field.updated_date':   'Updated',
        'field.name_servers':   'Name Servers',
        'field.status':         'Status',
        'field.emails':         'Emails',
        'field.whois_org':      'Organization',
        'field.whois_country':  'Country',
        # MX / Email
        'field.mx_domain':      'Domain',
        'field.priority':       'Priority',
        'field.email':          'Email',
        'field.syntax_valid':   'Format valid',
        'field.mx_valid':       'MX valid',
        # Misc messages
        'msg.your_ip':          'Your IP address',
        'msg.scan_summary':     'Scanned {total} platforms, found {found}:',
        'msg.not_found':        'Not found',
        'msg.unknown':          '(unknown)',
        'msg.none':             '(none)',
        'msg.saved_to':         '[ Saved to {path} ]',
        'msg.network_failed':   'Query failed, please check network',
        # Categories
        'cat.code':             'Code & Dev',
        'cat.social':           'Social',
        'cat.forum':            'Forums',
        'cat.video':            'Video',
        'cat.music':            'Music',
        'cat.writing':          'Writing',
        'cat.art':              'Art & Design',
        'cat.gaming':           'Gaming',
        'cat.funding':          'Creator Economy',
        'cat.chinese':          'Chinese Platforms (CN/TW/HK/SG/MY)',
        'cat.spanish':          'Spanish & Latin America (ES/AR/MX/BR/PE...)',
        'cat.adult':            'Adult / Dating (18+)',
        'cat.other':            'Other',
        'msg.show_all_hint':    '(showing only matches; use --all to see misses)',
        # v1.3.0 — Subdomain enumeration
        'subdomain.title':            'Subdomain enumeration: {domain}',
        'subdomain.summary':          '{total} discovered · {alive} alive · {sources} sources',
        'subdomain.wildcard_warn':    'Wildcard DNS detected — results may be unreliable',
        'subdomain.no_results':       'No subdomains discovered (all sources empty or rate-limited)',
        'subdomain.source_breakdown': 'Sources: {breakdown}',
        'subdomain.alive_section':    'Alive subdomains',
        'subdomain.dead_section':     'Dead / unresolved subdomains',
        'subdomain.col_host':         'Hostname',
        'subdomain.col_ip':           'IP address',
        'subdomain.col_cname':        'CNAME',
        'subdomain.col_status':       'HTTP',
        'subdomain.col_title':        'Title',
        # v1.3.3:阶段进度反馈,告诉用户每一步在做什么(消除"卡顿期")
        # v1.6.1 — Recursive scan progress
        'recursive.stage_scan':       'Depth {depth}/{max}: scanning username \'{name}\' ...',
        'recursive.stage_fetch':      'Fetching {n} profile pages to extract related usernames ...',
        'recursive.found_new':        'found {n} new candidates so far',
        'recursive.candidates_found': 'Extracted {n} new usernames: {names}',
        # v1.5.0 — Subdomain diff
        'diff.title':                 'Subdomain diff: {domain}',
        'diff.summary':               'Added {added} · Removed {removed} · Changed {changed} · Unchanged {unchanged}',
        'diff.section_added':         '+ Added subdomains ({n})',
        'diff.section_removed':       '- Removed subdomains ({n})',
        'diff.section_changed':       '~ Changed subdomains ({n})',
        'diff.no_changes':            'No changes detected — both scans are identical',
        'diff.err_load':              'Failed to load JSON: {path}',
        'diff.err_invalid':           'Invalid input — both files must be enumerate_subdomains() JSON output',
        'subdomain.stage_passive':    'Stage 1/4: Fetching passive sources (crt.sh / CertSpotter / HackerTarget / OTX / Wayback / subfinder) ...',
        'subdomain.stage_wildcard':   'Stage 2/4: Detecting wildcard DNS ...',
        'subdomain.stage_dns':        'Stage 3/4: Resolving {n} candidates via DNS ...',
        'subdomain.stage_probe':      'Stage 4/4: HTTP-probing {n} alive subdomains ...',
        'subdomain.stage_js_extract': 'Stage 4b: JS-extract pass — verifying {n} new hosts found in HTML bodies ...',
        'subdomain.source_done':      '[{name:>13}] {n:>4} candidates',
        'subdomain.source_err':       '[{name:>13}] error: {err}',
        'subdomain.wildcard_yes':     'wildcard detected — results may be unreliable',
        'subdomain.wildcard_no':      'no wildcard',
        'prompt.input_subdomain':     'Enter target domain (e.g. example.com): ',
        'prompt.subdomain_probe':     'Run HTTP probe to fetch <title>?\n   [ 1 ] Yes (default)  [ 2 ] No\n  Choose [1/2, default 1] : ',
        'prompt.subdomain_bruteforce': 'Enable DNS dictionary bruteforce? (~220 prefixes, +5-15s)\n   [ 1 ] No (default, passive only)  [ 2 ] Yes (more thorough)\n  Choose [1/2, default 1] : ',
        'prompt.subdomain_alive_only': 'Hide dead subdomains in the saved report?\n   [ 1 ] Yes (default, cleaner)  [ 2 ] No (include all, full data)\n  Choose [1/2, default 1] : ',
        # v1.4.0 — Domain emails enumeration
        'section.demails':            'Domain Email Enumeration',
        'demails.title':              'Domain emails: {domain}',
        'demails.summary':            '{total} emails found ({pages} pages crawled · sitemap: {sitemap})',
        'demails.no_results':         'No emails found',
        'demails.col_address':        'Email Address',
        'demails.col_sources':        'Sources',
        'demails.col_page':           'First seen at',
        'demails.col_verified':       'Verified',
        'demails.stage_passive':      'Stage 1/4: Passive sources (crt.sh CT logs + WHOIS contacts) ...',
        'demails.stage_subdomain':    'Stage 2/4: Discovering alive subdomains to crawl ...',
        'demails.stage_crawl':        'Stage 3/4: Deep-crawling {n} target(s) (robots.txt + sitemap.xml + BFS) ...',
        'demails.target_progress':    '[{idx}/{total}] Crawling target: {target}',
        'demails.stage_guess':        'Stage 3.5/4: Generating pattern emails from provided names ...',
        'demails.stage_smtp':         'Stage 4/4: SMTP verification of {n} candidates (HIGH-PROFILE) ...',
        'demails.smtp_warn':          'SMTP verification connects to target MX servers — only run on domains you own or have authorization to test',
        'demails.found_emails':       'emails',
        'demails.target_count':       'crawl targets',
        'demails.pattern_emails':     'pattern emails generated',
        'demails.section_passive':    'From passive sources (crt.sh / WHOIS)',
        'demails.section_crawl':      'From deep crawl',
        'demails.section_pattern':    'From pattern generation (UNVERIFIED guesses)',
        'prompt.input_demails':       'Enter target domain for email harvest (e.g. example.com): ',
        'prompt.demails_subdomains':  'Include alive subdomains in crawl?\n   [ 1 ] Yes (default, more thorough)  [ 2 ] No (main domain only, faster)\n  Choose [1/2, default 1] : ',
        'prompt.demails_max_pages':   'Crawl depth?\n   [ 1 ] Standard 200 pages (default, ~1 min)  [ 2 ] Deep 500 pages (~3-4 min)  [ 3 ] Quick 50 pages (~20s)\n  Choose [1/2/3, default 1] : ',
        'prompt.demails_guess':       'Generate pattern emails from names? Enter comma-separated names (or empty to skip): ',
        'prompt.demails_verify':      'Run SMTP verification (HIGH-PROFILE — only for domains you own)?\n   [ 1 ] Yes  [ 2 ] No (default)\n  Choose [1/2, default 2] : ',
        # Errors
        'err.network':          'Network request failed (timeout or connection error)',
        'err.non_json':         'API returned non-JSON response',
        'err.unknown_api':      'Unknown API error',
        'err.parse_phone':      'Phone parse failed: {e}',
        'err.no_dns':           'Requires dnspython: pip install dnspython',
        'err.no_whois':         'Requires python-whois: pip install python-whois',
        'err.whois_failed':     'WHOIS lookup failed: {e}',
        'err.dns_failed':       'DNS lookup failed: {e}',
        'err.nxdomain':         'Domain does not exist: {domain}',
        'err.no_mx':            '{domain} has no MX records',
        'err.email_format':     'Invalid email format',
        'err.query_failed':     'Query failed: {msg}',
        'err.empty_input':      'Input is empty',
        'err.unknown_category': 'Unknown category: {unknown}. Valid: {valid}',
        'err.username_too_long': 'Username too long (max {max} chars) — ReDoS protection',
        'err.username_invalid_chars': 'Username contains invalid characters (URL metachars / dots)',
        'err.invalid_ip':       'Invalid IP address: {ip}',
        'err.invalid_domain':   'Invalid domain: {domain}',
        'err.phone_invalid':    'Phone number is not a possible number',
        'err.save_failed':      'Failed to save to {target}: {err}',
        'msg.progress':         'Scanning',
        'msg.found':            'found',
        'msg.no_history':       '(no history yet — run a query first)',
        'mode.title':           'Scan mode:',
        'mode.quick':           'Quick   (~1411 platforms, ~14s)  [recommended]',
        'mode.full':            'Full    (~3164 platforms, ~30s)',
        'mode.cn_es':           'Chinese + Spanish only (~106 platforms, ~6s)',
        'mode.code':            'Code platforms only (~115 platforms, ~3s)',
        'mode.prompt':          'Choose [1/2/3/4, default 1]: ',
        # v1.1.0 — Permutation / Recursive / PDF
        'permute.title':        'Username permutations:',
        'permute.generated':    'Generated {n} variations from "{name}":',
        'err.permute_empty':    'Cannot generate permutations: input is empty',
        'recursive.depth':      'Recursive depth {depth}: {n} new candidates discovered',
        'recursive.title':      'Recursive scan summary',
        'msg.recursive_done':   'Recursive scan finished. Total: {total} platforms across {depths} levels.',
        'err.no_pdf':           'PDF requires reportlab: pip install "spyeyes[pdf]"',
        'err.pdf_failed':       'PDF generation failed: {e}',
        # Interactive menu prompts (v1.1.0+; numeric 1/2 style for menu consistency)
        'prompt.recursive':     'Recursive scan (extract sub-usernames from hits)?\n   [ 1 ] Yes  [ 2 ] No (default)\n  Choose [1/2, default 2] : ',
        'prompt.recursive_depth':'Recursive depth [1-2, default 2] : ',
        'prompt.save_confirm':  'Save report?\n   [ 1 ] Yes  [ 2 ] No (default)\n  Choose [1/2, default 2] : ',
        'prompt.save_filename': 'Filename [default: {default}]: ',
        # v1.2.0 — 8 种报告格式 + ~/Downloads 默认目录
        'prompt.format_title':  'Choose report format / 选择报告格式:',
        'prompt.format_select': 'Choose [1-8, default 1]: ',
        'fmt.json':             'JSON               (.json)',
        'fmt.md':               'Markdown           (.md)',
        'fmt.html':             'HTML               (.html)',
        'fmt.pdf':              'PDF                (.pdf, needs spyeyes[pdf])',
        'fmt.txt':              'Plain text         (.txt)',
        'fmt.csv':              'CSV                (.csv)',
        'fmt.xmind':            'XMind 8 mind-map   (.xmind)',
        'fmt.graph':            'Force-directed graph (.graph.html, D3.js — username scan only)',
        'prompt.save_another':  'Save another format?\n   [ 1 ] Yes  [ 2 ] No (default)\n  Choose [1/2, default 2] : ',
        # v1.2.0 — 用户名菜单合并 permute（菜单从 9 项缩到 8 项）
        'prompt.scan_strategy':       'Scan strategy:',
        'strategy.direct':            'Scan the username as-is',
        'strategy.permute_scan':      'Generate permutations and scan each (good for real names)',
        'strategy.permute_only':      'Generate permutations only (no scan)',
        'prompt.scan_strategy_select':'Choose [1/2/3, default 1] : ',
        'prompt.permute_method':      'Permutation method:',
        'method.strict':              "strict (multi-part perms × ['', '_', '-', '.'], default)",
        'method.all':                 'all    (strict + _prefix / suffix_ variants)',
        'prompt.permute_method_select':'Choose [1/2, default 1] : ',
        # v1.2.1 — Report localization (HTML / PDF / MD / TXT / CSV / XMind / Graph)
        'report.title':           'SpyEyes Report',
        'report.command':         'Command',
        'report.query':           'Query',
        'report.generated':       'Generated',
        'report.error':           'Error',
        'report.tool':            'Tool',
        'report.username_scan':   'Username scan',
        'report.scan_summary':    'Scanned {total} platforms · Found {found} accounts',
        'report.field':           'Field',
        'report.value':           'Value',
        'report.platform':        'Platform',
        'report.url':             'Profile URL',
        'report.info_for':        'info',
        'report.mx_records':      'MX Records for',
        'report.priority':        'Priority',
        'report.mail_server':     'Mail Server',
        'report.status':          'Status',
        'report.category':        'Category',
        'report.graph_title':     'SpyEyes Graph',
        'report.graph_help':      'Scroll to zoom · drag to pan · click hit to open · F to fit',
        'report.graph_found':     'Found {n} platforms',
        'report.legend_query':    'Query username',
        'report.legend_hit':      'Hit platform',
        'report.legend_other':    'Error / Other',
        # v1.7.0 — Investigate (one-shot multi-source dossier)
        'menu.investigate':           'Investigate (multi-source dossier)',
        'section.investigate':        'Comprehensive Investigation',
        'prompt.input_investigate':   'Enter target domain : ',
        'prompt.investigate_depth':   'Pivot depth?\n   [ 1 ] Standard (subdomain→IP, email→user) — default\n   [ 2 ] Atomic only (no pivots, faster)\n  Choose [1/2, default 1] : ',
        'investigate.stage_start':    'Starting comprehensive investigation: {target}',
        'investigate.stage_atomic':   'Stage 1: 4 atomic tasks (whois / mx / subdomain / domain-emails)…',
        'investigate.stage_ip_pivot': 'Stage 2a: enriching {n} IPs (subdomain → ip)…',
        'investigate.stage_user_pivot':'Stage 2b: scanning {n} email local-parts (email → user, {workers} parallel)…',
        'investigate.task_done':      '[{elapsed}s] {sym} {name}',
        'investigate.ip_pivot_done':  '[{n}/{total}] {sym} {ip}{summary}',
        'investigate.user_pivot_done':'[{n}/{total}] {sym} {local}{summary}',
        'investigate.budget_warn':    '⚠  budget exhausted, skipping remaining work',
        'investigate.elapsed_total':  'Total elapsed: {elapsed}s',
        'investigate.title':          'Investigation Report for {target}',
        'investigate.summary':        'Tasks: {tasks_done} done · {tasks_failed} failed · Pivots: {pivots_done} done · Elapsed: {elapsed}s',
        'investigate.budget_exceeded':'Budget exceeded — some pivots were skipped',
        'investigate.truncated':      'Truncated by cap: {ips} IPs and {emails} emails skipped (use --max-pivot-* to raise)',
        'investigate.subdomain_summary':'{alive} alive / {total} total',
        'investigate.email_summary':  '{total} emails harvested across {pages} pages',
        'investigate.section_whois':  'I. WHOIS Registration',
        'investigate.section_mx':     'II. MX (Mail Servers)',
        'investigate.section_subdomain':'III. Subdomain Enumeration',
        'investigate.section_ip_pivot':'IV. IP Enrichment (subdomain → IP)',
        'investigate.section_emails': 'V. Domain Emails',
        'investigate.section_user_pivot':'VI. Username Footprint (email → platforms)',
        'investigate.no_data':        'no data',
        'err.investigate_only_domain':'investigate currently supports domain input only (email/ip/username planned for v2)',
        # Update check
        'update.available':           'SpyEyes {latest} available (current {current})',
        'update.howto':               'Update: cd to repo, then `git pull && pip install -e .`',
        'update.howto_packaged':      'Update: `pip install --upgrade git+https://github.com/Akxan/SpyEyes.git` (or `pipx upgrade spyeyes`)',
        'update.release_notes':       'Release notes: {url}',
        'update.disable_hint':        '(disable: SPYEYES_NO_UPDATE_CHECK=1 or --no-update-check)',
        # Upgrade (v1.8.2: 一键升级)
        'upgrade.prompt_menu_start':  '🆕 New version {latest} available (current {current}). Upgrade now? [Y/n]:',
        'upgrade.checking':           'Checking GitHub Releases...',
        'upgrade.already_latest':     '✓ Already on latest version ({current})',
        'upgrade.found_new':          'Current: {current} → Latest: {latest}',
        'upgrade.release_notes':      'Release notes: {url}',
        'upgrade.confirm':            'Upgrade now? [Y/n]:',
        'upgrade.cancelled':          'Cancelled',
        'upgrade.source_install_hint':'Source install detected. Run: `git pull && pip install -e .`',
        'upgrade.running_cmd':        'Running: {cmd}',
        'upgrade.success':            '✓ Upgraded to {latest}. Please re-run spyeyes.',
        'upgrade.failed':             'Upgrade failed (exit {code}). Manual: {cmd}',
        'upgrade.no_tty':             'Cannot prompt without a TTY. Use --yes to skip confirmation.',
        'upgrade.network_error':      'Could not reach GitHub Releases. Try again later.',
        'upgrade.pipx_missing':       'pipx not found in PATH. Falling back to: {pip_cmd}',
    },
    'zh': {
        'menu.ip_track':        'IP 追踪',
        'menu.my_ip':           '查看本机 IP',
        'menu.phone':           '电话号码追踪',
        'menu.username':        '用户名追踪',
        'menu.whois':           '域名 WHOIS 查询',
        'menu.mx':              '域名 MX 记录',
        'menu.email':           '邮箱有效性检查',
        'menu.subdomain':       '子域名枚举',
        'menu.domain_emails':   '域名邮箱枚举(OSINT 邮箱挖取)',
        'menu.upgrade':         '检查并升级 SpyEyes',
        'menu.lang':            '切换语言 / Language',
        'menu.exit':            '退出',
        'menu.back_hint':       '(在任意子功能中输入 0 或直接回车可返回此菜单)',
        'prompt.select_option': '请选择功能 : ',
        'prompt.input_ip':      '请输入目标 IP : ',
        'prompt.input_phone':   '请输入电话号码 例如 [+8613800138000] : ',
        'prompt.input_username':'请输入用户名 : ',
        'prompt.input_domain':  '请输入域名 : ',
        'prompt.input_email':   '请输入邮箱 : ',
        'prompt.press_enter':   '按回车键继续',
        'prompt.input_number':  '请输入数字',
        'prompt.unknown_option':'未知选项：{n}',
        'prompt.bye':           '再见！',
        'prompt.interrupted':   '已中断',
        'prompt.exited':        '已退出',
        'lang.title':           '请选择语言 / Please select language:',
        'lang.zh':              '中文 (Chinese)',
        'lang.en':              'English (英文)',
        'lang.cancel':          '返回 / Back',
        'lang.changed':         '已切换为中文',
        'section.ip':           'IP 地址信息',
        'section.my_ip':        '本机 IP 信息',
        'section.phone':        '电话号码信息',
        'section.username':     '用户名扫描结果',
        'section.whois':        'WHOIS 查询',
        'section.mx':           'MX 记录',
        'section.email':        '邮箱有效性',
        'section.subdomain':    '子域名枚举',
        'section.history':      '最近查询',
        'field.target_ip':      '目标 IP',
        'field.ip_type':        'IP 类型',
        'field.country':        '国家',
        'field.country_code':   '国家代码',
        'field.city':           '城市',
        'field.continent':      '大洲',
        'field.region':         '地区',
        'field.latitude':       '纬度',
        'field.longitude':      '经度',
        'field.maps':           '谷歌地图',
        'field.is_eu':          '是否欧盟',
        'field.postal':         '邮编',
        'field.calling_code':   '国际区号',
        'field.capital':        '首都',
        'field.flag':           '国旗',
        'field.asn':            'ASN',
        'field.org':            '组织',
        'field.isp':            'ISP',
        'field.domain':         '域名',
        'field.timezone_id':    '时区 ID',
        'field.timezone_abbr':  '时区缩写',
        'field.utc_offset':     'UTC 偏移',
        'field.location':       '归属地',
        'field.region_code':    '地区代码',
        'field.timezone':       '时区',
        'field.carrier':        '运营商(号段所属)',
        'field.carrier_realtime': '运营商(实时 HLR)',
        'phone.mnp_note':       '号段原始分配方;实际运营商可能因携号转网(MNP)与此不同',
        'phone.realtime_hint':  '设置 SPYEYES_PHONE_API_KEY=numverify:YOUR_KEY 启用实时运营商查询',
        'phone.realtime_failed': '实时运营商查询失败:{err}',
        'field.is_valid':       '是否有效号码',
        'field.is_possible':    '是否可能号码',
        'field.intl_format':    '国际格式',
        'field.mobile_dial':    '移动拨号格式',
        'field.original_num':   '原始号码',
        'field.e164_format':    'E.164 格式',
        'field.number_type':    '号码类型',
        'phone.mobile':         '移动电话',
        'phone.fixed':          '固定电话',
        'phone.fixed_or_mobile':'固定/移动电话',
        'phone.toll_free':      '免费电话',
        'phone.premium':        '付费电话',
        'phone.shared_cost':    '共享费用电话',
        'phone.voip':           'VoIP',
        'phone.personal':       '个人号码',
        'phone.pager':          '寻呼机',
        'phone.uan':            '通用接入号',
        'phone.voicemail':      '语音信箱',
        'phone.unknown':        '未知',
        'phone.other':          '其他类型',
        'field.whois_domain':   '域名',
        'field.registrar':      '注册商',
        'field.creation_date':  '创建日期',
        'field.expiration_date':'到期日期',
        'field.updated_date':   '更新日期',
        'field.name_servers':   'DNS 服务器',
        'field.status':         '状态',
        'field.emails':         '邮箱',
        'field.whois_org':      '注册组织',
        'field.whois_country':  '国家',
        'field.mx_domain':      '域名',
        'field.priority':       '优先级',
        'field.email':          '邮箱',
        'field.syntax_valid':   '格式合法',
        'field.mx_valid':       'MX 有效',
        'msg.your_ip':          '你的 IP 地址',
        'msg.scan_summary':     '共扫描 {total} 个平台，命中 {found} 个：',
        'msg.not_found':        '未找到',
        'msg.unknown':          '(未知)',
        'msg.none':             '(无)',
        'msg.saved_to':         '[ 已保存到 {path} ]',
        'msg.network_failed':   '查询失败，请检查网络',
        'cat.code':             '代码与开发',
        'cat.social':           '社交网络',
        'cat.forum':            '论坛社区',
        'cat.video':            '视频平台',
        'cat.music':            '音乐平台',
        'cat.writing':          '写作平台',
        'cat.art':              '艺术与设计',
        'cat.gaming':           '游戏平台',
        'cat.funding':          '创作者经济',
        'cat.chinese':          '中文平台（陆/台/港/星/马）',
        'cat.spanish':          '西语圈（西班牙/拉美）',
        'cat.adult':            '成人 / 约会（18+）',
        'cat.other':            '其他平台',
        'msg.show_all_hint':    '（仅显示命中；用 --all 查看未命中）',
        # v1.3.0 —— 子域名枚举
        'subdomain.title':            '子域名枚举：{domain}',
        'subdomain.summary':          '共发现 {total} 个 · 活跃 {alive} 个 · 来自 {sources} 个数据源',
        'subdomain.wildcard_warn':    '检测到通配符 DNS — 结果可信度降低',
        'subdomain.no_results':       '未发现子域名（所有数据源为空或触发限速）',
        'subdomain.source_breakdown': '数据源：{breakdown}',
        'subdomain.alive_section':    '活跃子域',
        'subdomain.dead_section':     '不可达 / 未解析子域',
        'subdomain.col_host':         '主机名',
        'subdomain.col_ip':           'IP 地址',
        'subdomain.col_cname':        'CNAME',
        'subdomain.col_status':       'HTTP',
        'subdomain.col_title':        '标题',
        # v1.3.3:阶段进度反馈,告诉用户每一步在做什么(消除"卡顿期")
        # v1.6.1 — 递归扫描进度
        'recursive.stage_scan':       '深度 {depth}/{max}：扫描用户名 \'{name}\' ...',
        'recursive.stage_fetch':      '抓取 {n} 个 profile 页面以提取关联用户名 ...',
        'recursive.found_new':        '当前已发现 {n} 个新候选',
        'recursive.candidates_found': '抽出 {n} 个新用户名：{names}',
        # v1.5.0 — 子域名 diff
        'diff.title':                 '子域名 diff:{domain}',
        'diff.summary':               '新增 {added} 个 · 消失 {removed} 个 · 变更 {changed} 个 · 不变 {unchanged} 个',
        'diff.section_added':         '+ 新增子域 ({n} 个)',
        'diff.section_removed':       '- 消失子域 ({n} 个)',
        'diff.section_changed':       '~ 变更子域 ({n} 个)',
        'diff.no_changes':            '无变化 — 两次扫描完全一致',
        'diff.err_load':              '加载 JSON 失败:{path}',
        'diff.err_invalid':           '输入无效 — 两份文件必须是 enumerate_subdomains() 的 JSON 输出',
        'subdomain.stage_passive':    '阶段 1/4:拉取被动数据源(crt.sh / CertSpotter / HackerTarget / OTX / Wayback / subfinder)...',
        'subdomain.stage_wildcard':   '阶段 2/4:通配符 DNS 检测 ...',
        'subdomain.stage_dns':        '阶段 3/4:DNS 解析 {n} 个候选 ...',
        'subdomain.stage_probe':      '阶段 4/4:HTTP probe {n} 个活跃子域 ...',
        'subdomain.stage_js_extract': '阶段 4b:JS 解析 — 验证从页面 body 抽出的 {n} 个新 host ...',
        'subdomain.source_done':      '[{name:>13}] {n:>4} 个候选',
        'subdomain.source_err':       '[{name:>13}] 错误:{err}',
        'subdomain.wildcard_yes':     '检测到通配符 — 结果可信度降低',
        'subdomain.wildcard_no':      '无通配符',
        'prompt.input_subdomain':     '请输入目标域名（如 example.com）：',
        'prompt.subdomain_probe':     '是否抓 HTTP <title> 信息？\n   [ 1 ] 是（默认）  [ 2 ] 否\n  请选择 [1/2，默认 1] : ',
        'prompt.subdomain_bruteforce': '是否启用 DNS 字典爆破？(~220 个前缀，+5-15 秒)\n   [ 1 ] 否（默认，仅被动源）  [ 2 ] 是（更全面）\n  请选择 [1/2，默认 1] : ',
        'prompt.subdomain_alive_only': '保存报告时是否隐藏不可达子域？\n   [ 1 ] 是（默认，报告更简洁）  [ 2 ] 否（保留全部，含未解析）\n  请选择 [1/2，默认 1] : ',
        # v1.4.0 —— 域名邮箱枚举
        'section.demails':            '域名邮箱枚举',
        'demails.title':              '域名邮箱:{domain}',
        'demails.summary':            '共找到 {total} 个邮箱(爬取 {pages} 页 · sitemap:{sitemap})',
        'demails.no_results':         '未发现邮箱',
        'demails.col_address':        '邮箱地址',
        'demails.col_sources':        '来源',
        'demails.col_page':           '首次出现页面',
        'demails.col_verified':       '已验证',
        'demails.stage_passive':      '阶段 1/4:被动数据源(crt.sh CT 日志 + WHOIS 联系人)...',
        'demails.stage_subdomain':    '阶段 2/4:发现可爬取的活跃子域名 ...',
        'demails.stage_crawl':        '阶段 3/4:深度爬取 {n} 个目标(robots.txt + sitemap.xml + BFS)...',
        'demails.target_progress':    '[{idx}/{total}] 爬取目标:{target}',
        'demails.stage_guess':        '阶段 3.5/4:从提供的姓名生成模式邮箱 ...',
        'demails.stage_smtp':         '阶段 4/4:SMTP 验证 {n} 个候选(高调动作)...',
        'demails.smtp_warn':          'SMTP 验证会连接目标 MX 服务器 — 仅对自己拥有或获得授权的域使用',
        'demails.found_emails':       '个邮箱',
        'demails.target_count':       '个爬取目标',
        'demails.pattern_emails':     '个模式邮箱生成',
        'demails.section_passive':    '来自被动数据源(crt.sh / WHOIS)',
        'demails.section_crawl':      '来自深度爬取',
        'demails.section_pattern':    '来自模式生成(未验证的猜测)',
        'prompt.input_demails':       '请输入要挖邮箱的目标域名(如 example.com):',
        'prompt.demails_subdomains':  '是否包含活跃子域名一起爬取?\n   [ 1 ] 是(默认,更全面)  [ 2 ] 否(仅主域,更快)\n  请选择 [1/2,默认 1] : ',
        'prompt.demails_max_pages':   '爬取深度?\n   [ 1 ] 标准 200 页(默认,约 1 分钟)  [ 2 ] 深度 500 页(约 3-4 分钟)  [ 3 ] 极速 50 页(约 20 秒)\n  请选择 [1/2/3,默认 1] : ',
        'prompt.demails_guess':       '从姓名生成模式邮箱?用逗号分隔多人(留空跳过):',
        'prompt.demails_verify':      '是否做 SMTP 验证(高调 — 仅对自己拥有的域使用)?\n   [ 1 ] 是  [ 2 ] 否(默认)\n  请选择 [1/2,默认 2] : ',
        'err.network':          '网络请求失败（超时或连接错误）',
        'err.non_json':         'API 返回了非 JSON 响应',
        'err.unknown_api':      '未知 API 错误',
        'err.parse_phone':      '号码解析失败：{e}',
        'err.no_dns':           '需要安装 dnspython：pip install dnspython',
        'err.no_whois':         '需要安装 python-whois：pip install python-whois',
        'err.whois_failed':     'WHOIS 查询失败：{e}',
        'err.dns_failed':       'DNS 查询失败：{e}',
        'err.nxdomain':         '域名不存在：{domain}',
        'err.no_mx':            '{domain} 没有 MX 记录',
        'err.email_format':     '邮箱格式不合法',
        'err.query_failed':     '查询失败：{msg}',
        'err.empty_input':      '输入为空',
        'err.unknown_category': '未知类别：{unknown}。有效类别：{valid}',
        'err.username_too_long': '用户名过长（最多 {max} 字符）— ReDoS 防护',
        'err.username_invalid_chars': '用户名含非法字符（URL 元字符 / 点号）',
        'err.invalid_ip':       'IP 地址不合法：{ip}',
        'err.invalid_domain':   '域名格式不合法：{domain}',
        'err.phone_invalid':    '号码格式不可解析',
        'err.save_failed':      '无法保存到 {target}：{err}',
        'msg.progress':         '扫描中',
        'msg.found':            '已命中',
        'msg.no_history':       '（暂无历史 —— 先跑一次查询试试）',
        'mode.title':           '扫描模式:',
        'mode.quick':           '快速   (约 1411 平台, ~14 秒)  [推荐]',
        'mode.full':            '完整   (全部 3164 平台, ~30 秒)',
        'mode.cn_es':           '仅中文 + 西语圈 (约 106 平台, ~6 秒)',
        'mode.code':            '仅代码平台 (约 115 平台, ~3 秒)',
        'mode.prompt':          '请选择 [1/2/3/4, 默认 1]: ',
        # v1.1.0 —— 用户名变形 / 递归扫描 / PDF
        'permute.title':        '用户名变形：',
        'permute.generated':    '从 "{name}" 生成 {n} 个变形：',
        'err.permute_empty':    '无法生成变形：输入为空',
        'recursive.depth':      '第 {depth} 层递归：发现 {n} 个新候选',
        'recursive.title':      '递归扫描总结',
        'msg.recursive_done':   '递归扫描结束。共 {total} 个平台，{depths} 层。',
        'err.no_pdf':           'PDF 输出需要 reportlab：pip install "spyeyes[pdf]"',
        'err.pdf_failed':       'PDF 生成失败：{e}',
        # 交互菜单提示 (v1.1.0+；统一用 1/2 数字选项，与主菜单风格一致)
        'prompt.recursive':     '是否递归扫描（从命中页面提取次级用户名）？\n   [ 1 ] 是   [ 2 ] 否（默认）\n  请选择 [1/2，默认 2] : ',
        'prompt.recursive_depth':'递归深度 [1-2，默认 2] : ',
        'prompt.save_confirm':  '是否保存报告？\n   [ 1 ] 是   [ 2 ] 否（默认）\n  请选择 [1/2，默认 2] : ',
        'prompt.save_filename': '文件名 [默认 {default}]: ',
        # v1.2.0 —— 8 种报告格式 + ~/下载 默认目录
        'prompt.format_title':  '请选择报告格式 / Choose report format:',
        'prompt.format_select': '请选择 [1-8，默认 1]: ',
        'fmt.json':             'JSON               (.json)',
        'fmt.md':               'Markdown           (.md)',
        'fmt.html':             'HTML               (.html)',
        'fmt.pdf':              'PDF                (.pdf, 需 spyeyes[pdf])',
        'fmt.txt':              '纯文本             (.txt)',
        'fmt.csv':              'CSV                (.csv)',
        'fmt.xmind':            'XMind 8 思维导图   (.xmind)',
        'fmt.graph':            '力导向图           (.graph.html, D3.js — 仅用户名扫描)',
        'prompt.save_another':  '继续保存其它格式？\n   [ 1 ] 是   [ 2 ] 否（默认）\n  请选择 [1/2，默认 2] : ',
        # v1.2.0 —— 用户名菜单合并 permute（菜单从 9 项缩到 8 项）
        'prompt.scan_strategy':       '扫描方式：',
        'strategy.direct':            '直接扫描该用户名',
        'strategy.permute_scan':      '先生成变形再批量扫描（适合 "John Doe" / "张 三" 找化名）',
        'strategy.permute_only':      '仅生成变形列表（不扫描）',
        'prompt.scan_strategy_select':'请选择 [1/2/3，默认 1] : ',
        'prompt.permute_method':      '变形方式：',
        'method.strict':              "strict（多片段全排列 × ['', '_', '-', '.']，默认）",
        'method.all':                 'all   （strict 基础上加 _前缀 / 后缀_）',
        'prompt.permute_method_select':'请选择 [1/2，默认 1] : ',
        # v1.2.1 —— 报告本地化（HTML / PDF / MD / TXT / CSV / XMind / Graph）
        'report.title':           'SpyEyes 报告',
        'report.command':         '命令',
        'report.query':           '查询',
        'report.generated':       '生成时间',
        'report.error':           '错误',
        'report.tool':            '工具',
        'report.username_scan':   '用户名扫描',
        'report.scan_summary':    '共扫描 {total} 个平台 · 命中 {found} 个账号',
        'report.field':           '字段',
        'report.value':           '值',
        'report.platform':        '平台',
        'report.url':             '主页地址',
        'report.info_for':        '信息',
        'report.mx_records':      'MX 记录',
        'report.priority':        '优先级',
        'report.mail_server':     '邮件服务器',
        'report.status':          '状态',
        'report.category':        '分类',
        'report.graph_title':     'SpyEyes 关系图',
        'report.graph_help':      '滚轮缩放 · 拖拽平移 · 点击命中节点跳转 · F 自适应',
        'report.graph_found':     '命中 {n} 个平台',
        'report.legend_query':    '查询用户名',
        'report.legend_hit':      '命中平台',
        'report.legend_other':    '错误 / 其它',
        # v1.7.0 — 综合调查(一次输入域名,自动 fan-out + 单向接力,出整合档案)
        'menu.investigate':           '综合调查 (多源整合档案)',
        'section.investigate':        '综合调查',
        'prompt.input_investigate':   '请输入目标域名 : ',
        'prompt.investigate_depth':   '接力深度?\n   [ 1 ] 标准 (子域→IP, 邮箱→用户) — 默认\n   [ 2 ] 仅原子查询 (不接力,更快)\n  请选择 [1/2, 默认 1] : ',
        'investigate.stage_start':    '开始综合调查: {target}',
        'investigate.stage_atomic':   '阶段 1: 4 个原子任务并发 (whois / mx / subdomain / domain-emails)…',
        'investigate.stage_ip_pivot': '阶段 2a: 接力查询 {n} 个 IP (子域 → IP)…',
        'investigate.stage_user_pivot':'阶段 2b: 接力扫描 {n} 个邮箱本地部分 (邮箱 → 用户名, {workers} 并发)…',
        'investigate.task_done':      '[{elapsed}s] {sym} {name}',
        'investigate.ip_pivot_done':  '[{n}/{total}] {sym} {ip}{summary}',
        'investigate.user_pivot_done':'[{n}/{total}] {sym} {local}{summary}',
        'investigate.budget_warn':    '⚠  预算耗尽,跳过剩余工作',
        'investigate.elapsed_total':  '总耗时: {elapsed}s',
        'investigate.title':          '综合调查报告: {target}',
        'investigate.summary':        '任务: {tasks_done} 成功 · {tasks_failed} 失败 · 接力: {pivots_done} 完成 · 耗时: {elapsed}s',
        'investigate.budget_exceeded':'已超出时间预算 — 部分接力被跳过',
        'investigate.truncated':      '触发上限截断: 跳过了 {ips} 个 IP 和 {emails} 个邮箱 (用 --max-pivot-* 提升)',
        'investigate.subdomain_summary':'{alive} 个活子域 / {total} 个候选',
        'investigate.email_summary':  '抓取到 {total} 个邮箱 (共爬取 {pages} 页)',
        'investigate.section_whois':  'I. WHOIS 注册信息',
        'investigate.section_mx':     'II. MX 邮件服务器',
        'investigate.section_subdomain':'III. 子域名枚举',
        'investigate.section_ip_pivot':'IV. IP 富化 (子域 → IP)',
        'investigate.section_emails': 'V. 域名邮箱',
        'investigate.section_user_pivot':'VI. 用户名足迹 (邮箱 → 平台)',
        'investigate.no_data':        '无数据',
        'err.investigate_only_domain':'综合调查当前仅支持 domain 输入 (email/ip/username 计划 v2 支持)',
        # 版本更新检查
        'update.available':           'SpyEyes {latest} 可用(当前 {current})',
        'update.howto':               '更新: 进入仓库目录,执行 `git pull && pip install -e .`',
        'update.howto_packaged':      '更新: `pip install --upgrade git+https://github.com/Akxan/SpyEyes.git` (或 `pipx upgrade spyeyes`)',
        'update.release_notes':       '更新内容: {url}',
        'update.disable_hint':        '(关闭提示: SPYEYES_NO_UPDATE_CHECK=1 或 --no-update-check)',
        # Upgrade (v1.8.2: 一键升级)
        'upgrade.prompt_menu_start':  '🆕 新版本 {latest} 可用 (当前 {current})。现在升级? [Y/n]:',
        'upgrade.checking':           '查询 GitHub Releases...',
        'upgrade.already_latest':     '✓ 已是最新版本 ({current})',
        'upgrade.found_new':          '当前: {current} → 最新: {latest}',
        'upgrade.release_notes':      '更新说明: {url}',
        'upgrade.confirm':            '现在升级? [Y/n]:',
        'upgrade.cancelled':          '已取消',
        'upgrade.source_install_hint':'检测到源码安装。请执行: `git pull && pip install -e .`',
        'upgrade.running_cmd':        '执行: {cmd}',
        'upgrade.success':            '✓ 已升级到 {latest}。请重新启动 spyeyes。',
        'upgrade.failed':             '升级失败 (退出码 {code})。手动: {cmd}',
        'upgrade.no_tty':             '无 TTY 无法交互。请加 --yes 跳过确认。',
        'upgrade.network_error':      '无法连接 GitHub Releases,请稍后重试。',
        'upgrade.pipx_missing':       'PATH 里找不到 pipx。降级到: {pip_cmd}',
    },
}

_lang = 'zh'  # 当前语言，由 set_lang() 修改


def detect_lang() -> str:
    """根据系统环境自动判定默认语言。"""
    val = (os.environ.get('SPYEYES_LANG')
           or os.environ.get('GHOSTTRACK_LANG')  # 旧版兼容
           or os.environ.get('LC_ALL')
           or os.environ.get('LANG')
           or '').lower()
    if val.startswith('zh'):
        return 'zh'
    return 'en'


def set_lang(lang: str) -> None:
    """切换当前语言。"""
    global _lang
    if lang in TRANSLATIONS:
        _lang = lang


def get_lang() -> str:
    return _lang


def t(key: str, **kwargs: Any) -> str:
    """翻译查找。找不到 key 时回退英文，再回退原 key。"""
    table = TRANSLATIONS.get(_lang, TRANSLATIONS['en'])
    s = table.get(key)
    if s is None:
        s = TRANSLATIONS['en'].get(key, key)
    if kwargs:
        try:
            s = s.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            pass
    return s


# ====================================================================
# 颜色配置：自动检测 TTY
# ====================================================================
def _supports_color() -> bool:
    if not sys.stdout.isatty():
        return False
    term = os.environ.get('TERM', '')
    if term in ('', 'dumb'):
        return False
    if os.name == 'nt' and 'WT_SESSION' not in os.environ:
        return False
    return True


class Color:
    enabled = _supports_color()
    Bl    = '\033[30m'   if enabled else ''
    Re    = '\033[1;31m' if enabled else ''
    Gr    = '\033[1;32m' if enabled else ''
    Ye    = '\033[1;33m' if enabled else ''
    Blu   = '\033[1;34m' if enabled else ''
    Mage  = '\033[1;35m' if enabled else ''
    Cy    = '\033[1;36m' if enabled else ''
    Wh    = '\033[1;37m' if enabled else ''
    Reset = '\033[0m'    if enabled else ''

    @classmethod
    def disable(cls) -> None:
        for attr in ('Bl', 'Re', 'Gr', 'Ye', 'Blu', 'Mage', 'Cy', 'Wh', 'Reset'):
            setattr(cls, attr, '')
        cls.enabled = False


# ====================================================================
# HTTP
# ====================================================================
DEFAULT_TIMEOUT = 10
# Sherlock 风格的连接超时拆分：(connect=3s, read=超时秒数)
# 快速踢死 DNS/TCP 慢的 host，让长尾尾延迟显著降低
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}

# 每线程一个 requests.Session，连接池复用 → 大幅减少重复 host
# 的 DNS/TCP/TLS 握手（如 *.tumblr.com / *.shopee.* / mercadolibre.*）
_thread_local = threading.local()


def _get_session() -> requests.Session:
    s = getattr(_thread_local, 'session', None)
    if s is None:
        s = requests.Session()
        s.headers.update(DEFAULT_HEADERS)
        # pool_maxsize=200：v1.2.0 默认 worker 升到 150，pool 也跟着升到 200
        # 留 buffer 让 _check_username GET 回退路径（HEAD→405→GET）不出现 pool 满。
        # 之前 64 在 150 workers 下会让 urllib3 频繁重建连接，部分抵消并发提升。
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=200, pool_maxsize=200, max_retries=0
        )
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        _thread_local.session = s
    return s


def safe_get(url: str, *, timeout: float = DEFAULT_TIMEOUT, method: str = 'GET',
             stream: bool = False,
             connect_timeout: Optional[float] = None,
             **kwargs) -> Optional[requests.Response]:
    """带连接池复用 + 拆分超时的 HTTP 请求。
    method='HEAD' 时跳过 body 下载 —— 仅看 status_code 的平台用得上。
    stream=True 时调用方负责读取/关闭（用于早停 body 读）。

    connect_timeout: 建立 TCP/TLS 连接的上限。
      None(默认)= min(3s, timeout) — username 扫描场景需要快速踢死慢 host
      显式传值 — 给慢 OSINT 源(如 crt.sh 首次握手 5+s)足够时间(v1.4.3)"""
    extra_headers = kwargs.pop('headers', None) or {}
    try:
        session = _get_session()
        # 拆分 timeout:connect 上限可被显式覆盖
        if connect_timeout is None:
            connect_timeout = min(3.0, timeout)
        req_timeout = (connect_timeout, timeout)
        if method.upper() == 'HEAD':
            return session.head(url, timeout=req_timeout, headers=extra_headers, **kwargs)
        return session.get(url, timeout=req_timeout, headers=extra_headers, stream=stream, **kwargs)
    except (requests.exceptions.RequestException, ValueError, UnicodeError, OSError):
        # ValueError: urllib3.LocationParseError 等；UnicodeError: URL 编码失败；
        # OSError: 罕见网络层错误。统一返回 None 让调用方走 STATUS_NETWORK_ERROR
        return None


# ====================================================================
# 国家代码 → 中文名（仅 zh 模式下使用，180+ 国家/地区）
# ====================================================================
COUNTRY_ZH = {
    'AD': '安道尔', 'AE': '阿联酋', 'AF': '阿富汗', 'AG': '安提瓜和巴布达', 'AI': '安圭拉',
    'AL': '阿尔巴尼亚', 'AM': '亚美尼亚', 'AO': '安哥拉', 'AR': '阿根廷', 'AT': '奥地利',
    'AU': '澳大利亚', 'AZ': '阿塞拜疆', 'BA': '波黑', 'BB': '巴巴多斯', 'BD': '孟加拉',
    'BE': '比利时', 'BF': '布基纳法索', 'BG': '保加利亚', 'BH': '巴林', 'BI': '布隆迪',
    'BJ': '贝宁', 'BN': '文莱', 'BO': '玻利维亚', 'BR': '巴西', 'BS': '巴哈马',
    'BT': '不丹', 'BW': '博茨瓦纳', 'BY': '白俄罗斯', 'BZ': '伯利兹', 'CA': '加拿大',
    'CD': '刚果(金)', 'CF': '中非', 'CG': '刚果(布)', 'CH': '瑞士', 'CI': '科特迪瓦',
    'CL': '智利', 'CM': '喀麦隆', 'CN': '中国', 'CO': '哥伦比亚', 'CR': '哥斯达黎加',
    'CU': '古巴', 'CV': '佛得角', 'CY': '塞浦路斯', 'CZ': '捷克', 'DE': '德国',
    'DJ': '吉布提', 'DK': '丹麦', 'DM': '多米尼克', 'DO': '多米尼加', 'DZ': '阿尔及利亚',
    'EC': '厄瓜多尔', 'EE': '爱沙尼亚', 'EG': '埃及', 'ER': '厄立特里亚', 'ES': '西班牙',
    'ET': '埃塞俄比亚', 'FI': '芬兰', 'FJ': '斐济', 'FM': '密克罗尼西亚', 'FR': '法国',
    'GA': '加蓬', 'GB': '英国', 'GD': '格林纳达', 'GE': '格鲁吉亚', 'GH': '加纳',
    'GM': '冈比亚', 'GN': '几内亚', 'GQ': '赤道几内亚', 'GR': '希腊', 'GT': '危地马拉',
    'GW': '几内亚比绍', 'GY': '圭亚那', 'HK': '香港', 'HN': '洪都拉斯', 'HR': '克罗地亚',
    'HT': '海地', 'HU': '匈牙利', 'ID': '印度尼西亚', 'IE': '爱尔兰', 'IL': '以色列',
    'IN': '印度', 'IQ': '伊拉克', 'IR': '伊朗', 'IS': '冰岛', 'IT': '意大利',
    'JM': '牙买加', 'JO': '约旦', 'JP': '日本', 'KE': '肯尼亚', 'KG': '吉尔吉斯斯坦',
    'KH': '柬埔寨', 'KI': '基里巴斯', 'KM': '科摩罗', 'KN': '圣基茨和尼维斯', 'KP': '朝鲜',
    'KR': '韩国', 'KW': '科威特', 'KZ': '哈萨克斯坦', 'LA': '老挝', 'LB': '黎巴嫩',
    'LC': '圣卢西亚', 'LI': '列支敦士登', 'LK': '斯里兰卡', 'LR': '利比里亚', 'LS': '莱索托',
    'LT': '立陶宛', 'LU': '卢森堡', 'LV': '拉脱维亚', 'LY': '利比亚', 'MA': '摩洛哥',
    'MC': '摩纳哥', 'MD': '摩尔多瓦', 'ME': '黑山', 'MG': '马达加斯加', 'MH': '马绍尔群岛',
    'MK': '北马其顿', 'ML': '马里', 'MM': '缅甸', 'MN': '蒙古', 'MO': '澳门',
    'MR': '毛里塔尼亚', 'MT': '马耳他', 'MU': '毛里求斯', 'MV': '马尔代夫', 'MW': '马拉维',
    'MX': '墨西哥', 'MY': '马来西亚', 'MZ': '莫桑比克', 'NA': '纳米比亚', 'NE': '尼日尔',
    'NG': '尼日利亚', 'NI': '尼加拉瓜', 'NL': '荷兰', 'NO': '挪威', 'NP': '尼泊尔',
    'NR': '瑙鲁', 'NZ': '新西兰', 'OM': '阿曼', 'PA': '巴拿马', 'PE': '秘鲁',
    'PG': '巴布亚新几内亚', 'PH': '菲律宾', 'PK': '巴基斯坦', 'PL': '波兰', 'PT': '葡萄牙',
    'PW': '帕劳', 'PY': '巴拉圭', 'QA': '卡塔尔', 'RO': '罗马尼亚', 'RS': '塞尔维亚',
    'RU': '俄罗斯', 'RW': '卢旺达', 'SA': '沙特', 'SB': '所罗门群岛', 'SC': '塞舌尔',
    'SD': '苏丹', 'SE': '瑞典', 'SG': '新加坡', 'SI': '斯洛文尼亚', 'SK': '斯洛伐克',
    'SL': '塞拉利昂', 'SM': '圣马力诺', 'SN': '塞内加尔', 'SO': '索马里', 'SR': '苏里南',
    'SS': '南苏丹', 'ST': '圣多美和普林西比', 'SV': '萨尔瓦多', 'SY': '叙利亚', 'SZ': '斯威士兰',
    'TD': '乍得', 'TG': '多哥', 'TH': '泰国', 'TJ': '塔吉克斯坦', 'TL': '东帝汶',
    'TM': '土库曼斯坦', 'TN': '突尼斯', 'TO': '汤加', 'TR': '土耳其', 'TT': '特立尼达和多巴哥',
    'TV': '图瓦卢', 'TW': '台湾', 'TZ': '坦桑尼亚', 'UA': '乌克兰', 'UG': '乌干达',
    'US': '美国', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦', 'VC': '圣文森特和格林纳丁斯',
    'VE': '委内瑞拉', 'VN': '越南', 'VU': '瓦努阿图', 'WS': '萨摩亚', 'YE': '也门',
    'ZA': '南非', 'ZM': '赞比亚', 'ZW': '津巴布韦',
}


def country_zh(code: Optional[str], fallback: str = '') -> str:
    """中文国家名查表。en 模式下应直接用 API 的英文。"""
    if not code:
        return fallback
    return COUNTRY_ZH.get(code.upper(), fallback)


def localized_country(code: Optional[str], en_name: str) -> str:
    """根据当前语言返回本地化的国家名。"""
    if _lang == 'zh':
        zh = country_zh(code, '')
        return f"{zh} ({en_name})" if zh else en_name
    return en_name or t('msg.unknown')


# ====================================================================
# 通用打印工具
# ====================================================================
def display_width(s: str) -> int:
    """估算字符串在等宽终端中的显示宽度。
    覆盖：CJK / 全宽符号 / emoji（含 Astral Plane U+1F000+）/ 国旗 RIS 序列。
    国旗 emoji（U+1F1E6-U+1F1FF Regional Indicator Symbol）由两个 RIS 组成，
    多数终端渲染为宽度 2 —— 此实现按每对 RIS 算 width=2。"""
    width = 0
    skip_next = False
    for i, ch in enumerate(s):
        if skip_next:
            skip_next = False
            continue
        cp = ord(ch)
        # 国旗 emoji: 两个连续 RIS (U+1F1E6-U+1F1FF) 算宽 2（占下个字符）
        if 0x1F1E6 <= cp <= 0x1F1FF and i + 1 < len(s):
            next_cp = ord(s[i + 1])
            if 0x1F1E6 <= next_cp <= 0x1F1FF:
                width += 2
                skip_next = True
                continue
        # 标准 emoji 范围（Misc Symbols / Pictographs / Transport / Symbols）
        if (0x1F000 <= cp <= 0x1FFFF or 0x2600 <= cp <= 0x27BF):
            width += 2
            continue
        # CJK / Hangul / 全宽 ASCII / 全宽符号
        if (0x1100 <= cp <= 0x115F or 0x2E80 <= cp <= 0x9FFF or
                0xA000 <= cp <= 0xA4CF or 0xAC00 <= cp <= 0xD7A3 or
                0xF900 <= cp <= 0xFAFF or 0xFE30 <= cp <= 0xFE4F or
                0xFF00 <= cp <= 0xFF60 or 0xFFE0 <= cp <= 0xFFE6):
            width += 2
        else:
            width += 1
    return width


def print_field(label: str, value: Any, *, width: int = 20, indent: str = ' ') -> None:
    pad = max(0, width - display_width(label))
    display_value = '' if value is None else value
    print(f"{indent}{Color.Wh}{label}{' ' * pad} :{Color.Gr} {display_value}{Color.Reset}")


def clear_screen() -> None:
    """v1.5.0:用 ANSI 转义替代 os.system('cls'/'clear') —
    跨平台 + 无子进程开销(Windows 10+ 默认支持 ANSI)。"""
    if sys.stdout.isatty():
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()


# ====================================================================
# 核心查询：IP
# ====================================================================
def track_ip(ip: str) -> dict:
    # 空输入会让 ipwho.is 返回调用方自己的 IP，这是误导性行为，必须早返回
    ip = (ip or '').strip()
    if not ip:
        return {'_error': t('err.empty_input')}
    # SSRF 防护：拒绝非合法 IPv4/IPv6（防止 "8.8.8.8?key=leak" 污染 query
    # 或 "../admin" 路径穿越，即便 ipwho.is 自身能拒绝，也避免暴露异常信息）
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return {'_error': t('err.invalid_ip', ip=ip)}
    # IPv6 scope_id（如 'fe80::1%eth0'）会让 URL 含 % 触发 urllib3 解析错误
    # → safe_get 返回 None → 用户得到「网络错误」误导。直接拒绝。
    if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.scope_id:
        return {'_error': t('err.invalid_ip', ip=ip)}
    resp = safe_get(f"https://ipwho.is/{ip}")
    if resp is None:
        return {'_error': t('err.network')}
    try:
        data = resp.json()
    except ValueError:
        return {'_error': t('err.non_json')}
    if data.get('success') is False:
        return {'_error': data.get('message', t('err.unknown_api'))}
    return data


def show_my_ip() -> Optional[str]:
    resp = safe_get('https://api.ipify.org/')
    if resp is None or resp.status_code != 200:
        return None
    return resp.text.strip()


# ====================================================================
# 核心查询：电话号码
# ====================================================================
_PHONE_TYPE_KEY = {
    phonenumbers.PhoneNumberType.MOBILE:               'phone.mobile',
    phonenumbers.PhoneNumberType.FIXED_LINE:           'phone.fixed',
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'phone.fixed_or_mobile',
    phonenumbers.PhoneNumberType.TOLL_FREE:            'phone.toll_free',
    phonenumbers.PhoneNumberType.PREMIUM_RATE:         'phone.premium',
    phonenumbers.PhoneNumberType.SHARED_COST:          'phone.shared_cost',
    phonenumbers.PhoneNumberType.VOIP:                 'phone.voip',
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER:      'phone.personal',
    phonenumbers.PhoneNumberType.PAGER:                'phone.pager',
    phonenumbers.PhoneNumberType.UAN:                  'phone.uan',
    phonenumbers.PhoneNumberType.VOICEMAIL:            'phone.voicemail',
    phonenumbers.PhoneNumberType.UNKNOWN:              'phone.unknown',
}


# v1.3.2:实时运营商查询(HLR-aware)
# 解决 phonenumbers 不感知 MNP(号码携带)的根本局限。
# Provider 接口设计:每个 provider 接 (e164_number, api_key) 返回 {'carrier': str, 'mcc_mnc': str|None} 或抛异常。


def _phone_provider_numverify(e164: str, api_key: str) -> dict:
    """numverify.com 实时运营商查询 (free tier 100/月)。返回 {'carrier': str, ...}。
    Numverify 的 carrier 字段对 MNP 携号转网比 phonenumbers 准很多。"""
    # numverify 接受不带 + 的 E.164
    num = e164.lstrip('+')
    url = f'https://apilayer.net/api/validate?access_key={api_key}&number={num}'
    resp = safe_get(url, timeout=10)
    if resp is None or resp.status_code != 200:
        raise RuntimeError(f'HTTP {resp.status_code if resp else "no response"}')
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException) as e:
        raise RuntimeError(f'non-JSON response: {e}') from e
    if not isinstance(data, dict):
        raise RuntimeError('unexpected response shape')
    if data.get('success') is False:
        err = data.get('error', {})
        raise RuntimeError(f'API error: {err.get("info", err.get("type", "unknown"))}')
    return {'carrier': (data.get('carrier') or '').strip() or None}


# 可扩展:以后加 numlookupapi / abstractapi 等 provider
_PHONE_PROVIDERS = {
    'numverify': _phone_provider_numverify,
}


def _resolve_phone_realtime(e164: str) -> Optional[dict]:
    """读 SPYEYES_PHONE_API_KEY=provider:key 环境变量并调用对应 provider。
    返回 dict(成功)、None(未配置)、{'_error': str}(失败)。"""
    env = (os.environ.get('SPYEYES_PHONE_API_KEY') or '').strip()
    if not env or ':' not in env:
        return None
    provider, _, key = env.partition(':')
    provider = provider.strip().lower()
    key = key.strip()
    if not provider or not key:
        return None
    fn = _PHONE_PROVIDERS.get(provider)
    if fn is None:
        return {'_error': f'unsupported provider: {provider!r}, valid: {list(_PHONE_PROVIDERS)}'}
    try:
        return fn(e164, key)
    except Exception as e:
        return {'_error': str(e)}


def track_phone(number: str, default_region: str = 'CN', *,
                lookup_realtime: Optional[bool] = None) -> dict:
    """解析电话号码。
    - 默认基于 phonenumbers 静态号段映射(carrier 字段是号段原始分配方,不感知 MNP)
    - 设 SPYEYES_PHONE_API_KEY=provider:key 自动启用实时 HLR 查询
      (carrier_realtime 字段补充准确数据;失败优雅降级,不影响主流程)
    - lookup_realtime=True/False 显式覆盖 env var 决策
    """
    try:
        parsed = phonenumbers.parse(number, default_region)
    except NumberParseException as e:
        return {'_error': t('err.parse_phone', e=e)}

    # `parse('+1')` 等形似号码会成功但 is_possible_number=False；返回 _error
    # 避免 _record_history 把它记为成功
    if not phonenumbers.is_possible_number(parsed):
        return {'_error': t('err.phone_invalid')}

    lib_lang = 'zh' if _lang == 'zh' else 'en'
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    block_carrier = (carrier.name_for_number(parsed, lib_lang)
                     or carrier.name_for_number(parsed, 'en')
                     or t('msg.unknown'))

    result: dict = {
        'location':      geocoder.description_for_number(parsed, lib_lang) or t('msg.unknown'),
        'region_code':   phonenumbers.region_code_for_number(parsed) or t('msg.unknown'),
        'timezones':     ', '.join(timezone.time_zones_for_number(parsed)) or t('msg.unknown'),
        # carrier 现在明确是「号段所属」(block-allocated),carrier_note 提示用户
        'carrier':       block_carrier,
        'carrier_note':  t('phone.mnp_note'),
        'is_valid':      phonenumbers.is_valid_number(parsed),
        'is_possible':   phonenumbers.is_possible_number(parsed),
        'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        'mobile_dial':   phonenumbers.format_number_for_mobile_dialing(parsed, default_region, with_formatting=True),
        'national':      parsed.national_number,
        'e164':          e164,
        'country_code':  parsed.country_code,
        'number_type':   t(_PHONE_TYPE_KEY.get(phonenumbers.number_type(parsed), 'phone.other')),
    }

    # 实时 HLR 查询(可选;失败优雅降级)
    # lookup_realtime=False 显式禁用;True 强制启用(无 key 也尝试 = 报 None)
    # None(默认)= 看 env var 决定
    if lookup_realtime is False:
        return result
    rt = _resolve_phone_realtime(e164)
    if rt is None:
        # 未配置 API key,不影响主流程;hint 让用户知道可启用
        result['carrier_realtime'] = None
        result['carrier_realtime_hint'] = t('phone.realtime_hint')
    elif '_error' in rt:
        result['carrier_realtime'] = None
        result['carrier_realtime_error'] = t('phone.realtime_failed', err=rt['_error'])
    else:
        result['carrier_realtime'] = rt.get('carrier') or t('msg.unknown')
    return result


# ====================================================================
# 核心查询：用户名扫描
# ====================================================================
class Platform(NamedTuple):
    """单个社交/网站平台定义。"""
    name: str
    url: str
    category: str             # 用于分组显示，见 CATEGORY_ORDER
    not_found: tuple = ()     # 字节模式列表，命中其中之一即视为「未找到」
    must_contain: tuple = ()  # 字节模式列表，至少命中一个才视为「找到」（更严格的检测）
    regex_check: str = ''     # Sherlock 风格：username 必须匹配此正则才发请求；不匹配 = invalid


PLATFORMS = [
    # ---- 代码与开发 / Code & Dev ----
    Platform('GitHub',           'https://github.com/{}',                      'code', (b'not found', b'page-404')),
    Platform('GitLab',           'https://gitlab.com/{}',                      'code', (b'page not found',)),
    Platform('Bitbucket',        'https://bitbucket.org/{}',                   'code'),
    Platform('Codeberg',         'https://codeberg.org/{}',                    'code'),
    Platform('Sourcehut',        'https://sr.ht/~{}',                          'code'),
    Platform('DEV.to',           'https://dev.to/{}',                          'code'),
    Platform('Hashnode',         'https://hashnode.com/@{}',                   'code'),
    Platform('HackerNews',       'https://news.ycombinator.com/user?id={}',    'code', (b'no such user',)),
    Platform('Lobsters',         'https://lobste.rs/u/{}',                     'code'),
    Platform('LeetCode',         'https://leetcode.com/{}/',                   'code'),
    Platform('Codeforces',       'https://codeforces.com/profile/{}',          'code'),
    Platform('AtCoder',          'https://atcoder.jp/users/{}',                'code'),
    Platform('HackerRank',       'https://www.hackerrank.com/{}',              'code'),
    Platform('CodePen',          'https://codepen.io/{}',                      'code'),
    Platform('Replit',           'https://replit.com/@{}',                     'code'),
    Platform('Glitch',           'https://glitch.com/@{}',                     'code'),
    Platform('CodeSandbox',      'https://codesandbox.io/u/{}',                'code'),
    Platform('Codewars',         'https://www.codewars.com/users/{}',          'code'),
    Platform('NPM',              'https://www.npmjs.com/~{}',                  'code'),
    Platform('PyPI',             'https://pypi.org/user/{}/',                  'code'),
    Platform('RubyGems',         'https://rubygems.org/profiles/{}',           'code'),
    Platform('Crates.io',        'https://crates.io/users/{}',                 'code'),
    Platform('Docker Hub',       'https://hub.docker.com/u/{}',                'code'),
    Platform('HuggingFace',      'https://huggingface.co/{}',                  'code'),
    Platform('Kaggle',           'https://www.kaggle.com/{}',                  'code'),

    # ---- 社交网络 / Social ----
    Platform('Facebook',         'https://www.facebook.com/{}',                'social'),
    Platform('Twitter',          'https://twitter.com/{}',                     'social'),
    Platform('Instagram',        'https://www.instagram.com/{}',               'social'),
    Platform('LinkedIn',         'https://www.linkedin.com/in/{}',             'social'),
    Platform('Threads',          'https://www.threads.net/@{}',                'social'),
    Platform('Bluesky',          'https://bsky.app/profile/{}.bsky.social',    'social'),
    Platform('Mastodon',         'https://mastodon.social/@{}',                'social'),
    Platform('Pinterest',        'https://www.pinterest.com/{}/',              'social', (b"sorry, we couldn't find",)),
    Platform('Tumblr',           'https://{}.tumblr.com',                      'social', (b"there's nothing here",)),
    Platform('Snapchat',         'https://www.snapchat.com/add/{}',            'social'),
    Platform('Telegram',         'https://t.me/{}',                            'social'),
    Platform('VK',               'https://vk.com/{}',                          'social'),
    Platform('OK.ru',            'https://ok.ru/{}',                           'social'),
    Platform('Mixi',             'https://mixi.jp/show_friend.pl?nickname={}', 'social'),
    Platform('Plurk',            'https://www.plurk.com/{}',                   'social'),
    Platform('Ello',             'https://ello.co/{}',                         'social'),
    Platform('Keybase',          'https://keybase.io/{}',                      'social'),
    Platform('Gravatar',         'https://en.gravatar.com/{}',                 'social'),

    # ---- 论坛 / Forums ----
    Platform('Reddit',           'https://www.reddit.com/user/{}',             'forum', (b'page not found', b'sorry, nobody on reddit')),
    Platform('Quora',            'https://www.quora.com/profile/{}',           'forum', (b'page not found',)),
    Platform('Disqus',           'https://disqus.com/by/{}/',                  'forum'),
    Platform('Habr',             'https://habr.com/ru/users/{}/',              'forum'),
    Platform('Medium',           'https://medium.com/@{}',                     'writing', (b'page not found',)),

    # ---- 视频 / Video ----
    Platform('YouTube',          'https://www.youtube.com/@{}',                'video'),
    Platform('TikTok',           'https://www.tiktok.com/@{}',                 'video'),
    Platform('Twitch',           'https://www.twitch.tv/{}',                   'video'),
    Platform('Vimeo',            'https://vimeo.com/{}',                       'video'),
    Platform('DailyMotion',      'https://www.dailymotion.com/{}',             'video'),
    Platform('Rumble',           'https://rumble.com/c/{}',                    'video'),
    Platform('Odysee',           'https://odysee.com/@{}',                     'video'),

    # ---- 音乐 / Music ----
    Platform('SoundCloud',       'https://soundcloud.com/{}',                  'music'),
    Platform('Last.fm',          'https://www.last.fm/user/{}',                'music'),
    Platform('Bandcamp',         'https://bandcamp.com/{}',                    'music'),
    Platform('Mixcloud',         'https://www.mixcloud.com/{}/',               'music'),
    Platform('ReverbNation',     'https://www.reverbnation.com/{}',            'music'),
    Platform('AudioMack',        'https://audiomack.com/{}',                   'music'),
    Platform('BandLab',          'https://www.bandlab.com/{}',                 'music'),

    # ---- 写作 / Writing ----
    Platform('Substack',         'https://{}.substack.com',                    'writing'),
    Platform('Wattpad',          'https://www.wattpad.com/user/{}',            'writing'),
    Platform('AO3',              'https://archiveofourown.org/users/{}',       'writing'),
    Platform('FanFiction.net',   'https://www.fanfiction.net/u/{}',            'writing'),

    # ---- 艺术与设计 / Art & Design ----
    Platform('DeviantArt',       'https://www.deviantart.com/{}',              'art'),
    Platform('ArtStation',       'https://www.artstation.com/{}',              'art'),
    Platform('Behance',          'https://www.behance.net/{}',                 'art'),
    Platform('Dribbble',         'https://dribbble.com/{}',                    'art'),
    Platform('500px',            'https://500px.com/p/{}',                     'art'),
    Platform('Unsplash',         'https://unsplash.com/@{}',                   'art'),
    Platform('Flickr',           'https://www.flickr.com/people/{}',           'art'),
    Platform('Newgrounds',       'https://{}.newgrounds.com',                  'art'),
    Platform('Etsy',             'https://www.etsy.com/people/{}',             'art'),

    # ---- 游戏 / Gaming ----
    Platform('Steam',            'https://steamcommunity.com/id/{}',           'gaming'),
    Platform('Itch.io',          'https://{}.itch.io',                         'gaming'),
    Platform('Roblox',           'https://www.roblox.com/user.aspx?username={}', 'gaming'),
    Platform('Speedrun.com',     'https://www.speedrun.com/user/{}',           'gaming'),
    Platform('Chess.com',        'https://www.chess.com/member/{}',            'gaming'),
    Platform('Lichess',          'https://lichess.org/@/{}',                   'gaming'),
    Platform('MyAnimeList',      'https://myanimelist.net/profile/{}',         'gaming'),
    Platform('AniList',          'https://anilist.co/user/{}',                 'gaming'),
    Platform('BoardGameGeek',    'https://boardgamegeek.com/user/{}',          'gaming'),

    # ---- 创作者经济 / Creator ----
    Platform('Patreon',          'https://www.patreon.com/{}',                 'funding'),
    Platform('Buy Me A Coffee',  'https://www.buymeacoffee.com/{}',            'funding'),
    Platform('Ko-fi',            'https://ko-fi.com/{}',                       'funding'),
    Platform('OpenCollective',   'https://opencollective.com/{}',              'funding'),
    Platform('Liberapay',        'https://liberapay.com/{}/',                  'funding'),
    Platform('Wellfound',        'https://wellfound.com/u/{}',                 'funding'),
    Platform('Indie Hackers',    'https://www.indiehackers.com/{}',            'funding'),
    Platform('Product Hunt',     'https://www.producthunt.com/@{}',            'funding'),

    # ---- 阅读/书影 / Books & Films ----
    Platform('Goodreads',        'https://www.goodreads.com/{}',               'art'),
    Platform('Letterboxd',       'https://letterboxd.com/{}',                  'art'),

    # ---- 中文平台 / Chinese ----
    Platform('微博 Weibo',        'https://weibo.com/n/{}',                     'chinese'),
    Platform('知乎 Zhihu',        'https://www.zhihu.com/people/{}',            'chinese'),
    Platform('豆瓣 Douban',       'https://www.douban.com/people/{}/',          'chinese'),
    Platform('百度贴吧 Tieba',    'https://tieba.baidu.com/home/main?un={}',    'chinese'),
    Platform('CSDN',              'https://blog.csdn.net/{}',                   'chinese'),
    Platform('V2EX',              'https://v2ex.com/member/{}',                 'chinese'),
    Platform('简书 Jianshu',      'https://www.jianshu.com/u/{}',               'chinese'),
    Platform('SegmentFault 思否', 'https://segmentfault.com/u/{}',              'chinese'),
    Platform('OSCHINA 开源中国',  'https://my.oschina.net/{}',                  'chinese'),
    Platform('掘金 Juejin',       'https://juejin.cn/user/{}',                  'chinese'),
    Platform('力扣 LeetCode-CN',  'https://leetcode.cn/u/{}/',                  'chinese'),
    Platform('LOFTER',            'https://{}.lofter.com',                      'chinese'),
    Platform('雪球 Xueqiu',       'https://xueqiu.com/n/{}',                    'chinese'),
    Platform('即刻 Jike',         'https://web.okjike.com/u/{}',                'chinese'),
    Platform('36氪 36Kr',         'https://www.36kr.com/user/{}',               'chinese'),
    Platform('虎扑 Hupu',         'https://my.hupu.com/{}',                     'chinese'),
    Platform('牛客 Nowcoder',     'https://www.nowcoder.com/users/{}',          'chinese'),
    Platform('博客园 Cnblogs',    'https://www.cnblogs.com/{}/',                'chinese'),
    Platform('IT之家 ITHome',     'https://my.ithome.com/{}',                   'chinese'),

    # ---- 简中（更多 PRC 平台）/ More Simplified Chinese ----
    Platform('51CTO 博客',         'https://blog.51cto.com/{}',                  'chinese'),
    Platform('马蜂窝 Mafengwo',    'https://www.mafengwo.cn/u/{}',               'chinese'),
    Platform('穷游网 Qyer',        'https://www.qyer.com/u/{}',                  'chinese'),
    Platform('大众点评 Dianping',  'https://www.dianping.com/member/{}',         'chinese'),
    Platform('果壳 Guokr',         'https://www.guokr.com/i/{}',                 'chinese'),
    Platform('360doc 图书馆',      'https://www.360doc.com/userhome/{}',         'chinese'),
    Platform('起点中文网 Qidian',  'https://my.qidian.com/{}',                   'chinese'),
    Platform('晋江文学城 JJWXC',   'https://my.jjwxc.net/onename.php?keyword={}','chinese'),
    Platform('AcWing',             'https://www.acwing.com/user/myspace/index/{}/','chinese'),
    Platform('阿里云开发者社区',   'https://developer.aliyun.com/profile/{}',    'chinese'),

    # ---- 繁中 / Traditional Chinese (Taiwan) ----
    Platform('Dcard 狄卡',         'https://www.dcard.tw/@{}',                   'chinese'),
    Platform('Mobile01',           'https://www.mobile01.com/userinfo.php?account={}', 'chinese'),
    Platform('巴哈姆特 Bahamut',   'https://home.gamer.com.tw/homeindex.php?owner={}', 'chinese'),
    Platform('PIXNET 痞客邦',      'https://{}.pixnet.net',                      'chinese'),
    Platform('iCook 愛料理',       'https://icook.tw/users/{}',                  'chinese'),
    Platform('隨意窩 Xuite',       'https://blog.xuite.net/{}',                  'chinese'),

    # ---- 港澳 / Hong Kong & Macau ----
    Platform('LIHKG 連登',         'https://lihkg.com/profile/{}',               'chinese'),
    Platform('HK01',               'https://www.hk01.com/author/{}',             'chinese'),

    # ---- 新加坡 / 马来西亚 / Singapore & Malaysia ----
    Platform('Carousell',          'https://www.carousell.com/u/{}/',            'chinese'),
    Platform('蝦皮 Shopee TW',     'https://shopee.tw/{}',                       'chinese'),
    Platform('蝦皮 Shopee SG',     'https://shopee.sg/{}',                       'chinese'),
    Platform('蝦皮 Shopee MY',     'https://shopee.com.my/{}',                   'chinese'),

    # ---- 西班牙 + 拉美 / Spanish (Spain + Latin America) ----
    Platform('Wallapop',           'https://es.wallapop.com/user/{}',            'spanish'),
    Platform('MercadoLibre AR',    'https://perfil.mercadolibre.com.ar/{}',      'spanish'),
    Platform('MercadoLibre MX',    'https://perfil.mercadolibre.com.mx/{}',      'spanish'),
    Platform('MercadoLibre BR',    'https://perfil.mercadolivre.com.br/{}',      'spanish'),
    Platform('Menéame',            'https://www.meneame.net/user/{}',            'spanish'),
    Platform('Duolingo',           'https://www.duolingo.com/profile/{}',        'spanish'),
    Platform('Taringa',            'https://www.taringa.net/{}',                 'spanish'),
    Platform('Forocoches',         'https://forocoches.com/foro/member.php?username={}', 'spanish'),
    Platform('Hispachan',          'https://www.hispachan.org/u/{}',             'spanish'),
    Platform('Forosperu',          'https://www.forosperu.net/members/{}.html',  'spanish'),
    Platform('Genbeta',            'https://www.genbeta.com/comments-by/{}',     'spanish'),
    Platform('Xataka',             'https://www.xataka.com/comments-by/{}',      'spanish'),

    # ---- 成人 / 约会 / 性内容（18+）/ Adult & Dating ----
    Platform('OnlyFans',           'https://onlyfans.com/{}',                    'adult'),
    Platform('Fansly',             'https://fansly.com/{}',                      'adult'),
    Platform('FetLife',            'https://fetlife.com/users/{}',               'adult'),
    Platform('Chaturbate',         'https://chaturbate.com/{}/',                 'adult'),
    Platform('Stripchat',          'https://stripchat.com/{}',                   'adult'),
    Platform('ManyVids',           'https://www.manyvids.com/Profile/{}',        'adult'),
    Platform('JustForFans',        'https://justfor.fans/{}',                    'adult'),
    Platform('AdmireMe',           'https://admireme.vip/{}',                    'adult'),
    Platform('MyFreeCams',         'https://profiles.myfreecams.com/{}',         'adult'),
    Platform('LiveJasmin',         'https://www.livejasmin.com/en/chat/{}',      'adult'),
    Platform('Cam4',               'https://www.cam4.com/{}',                    'adult'),
    Platform('CamSoda',            'https://www.camsoda.com/{}',                 'adult'),
    Platform('PornHub Community',  'https://www.pornhub.com/users/{}',           'adult'),
    Platform('xHamster',           'https://xhamster.com/users/{}',              'adult'),
    Platform('Literotica',         'https://www.literotica.com/stories/memberpage.php?uid={}', 'adult'),
    Platform('F95Zone',            'https://f95zone.to/members/{}',              'adult'),
    Platform('Rule34',             'https://rule34.xxx/index.php?page=account&s=profile&uname={}', 'adult'),
    Platform('PlentyOfFish',       'https://www.pof.com/viewprofile.aspx?profile_id={}', 'adult'),
    Platform('Badoo',              'https://badoo.com/profile/{}',               'adult'),
    Platform('Tagged',             'https://www.tagged.com/{}',                  'adult'),

    # ---- 成人创作者平台（OnlyFans 替代品）/ Adult creator platforms ----
    Platform('LoyalFans',          'https://www.loyalfans.com/{}',               'adult'),
    Platform('FanCentro',          'https://fancentro.com/{}',                   'adult'),
    Platform('AVN Stars',          'https://avnstars.com/{}',                    'adult'),
    Platform('IsMyGirl',           'https://ismygirl.com/{}',                    'adult'),
    Platform('Pocket Stars',       'https://www.pocketstars.com/{}',             'adult'),
    Platform('AdultNode',          'https://www.adultnode.com/{}',               'adult'),
    Platform('Fanvue',             'https://www.fanvue.com/{}',                  'adult'),
    Platform('FANBOX',             'https://www.fanbox.cc/@{}',                  'adult'),
    Platform('Modelhub',           'https://www.modelhub.com/{}',                'adult'),
    Platform('MV Live',            'https://www.manyvids.com/MV-Live/{}',        'adult'),

    # ---- 直播 cam（更多）/ Live cam ----
    Platform('BongaCams',          'https://bongacams.com/profile/{}',           'adult'),
    Platform('Cherry.tv',          'https://cherry.tv/{}',                       'adult'),
    Platform('SkyPrivate',         'https://skyprivate.com/{}',                  'adult'),
    Platform('Streamate',          'https://streamate.com/cam/{}/',              'adult'),
    # CAM4 with /profile/ path removed — duplicates 'Cam4' above (case-insensitive)
    Platform('CamSoda Models',     'https://www.camsoda.com/p/{}',               'adult'),
    Platform('Flirt4Free',         'https://www.flirt4free.com/{}/',             'adult'),
    Platform('xLoveCam',           'https://www.xlovecam.com/en/cam/{}',         'adult'),
    Platform('Naked.com',          'https://naked.com/{}',                       'adult'),

    # ---- 约会 / 交友（含同志）/ Dating & hookup ----
    Platform('AdultFriendFinder',  'https://adultfriendfinder.com/profile/{}',   'adult'),
    Platform('MeetMe',             'https://www.meetme.com/{}',                  'adult'),
    Platform('Skout',              'https://www.skout.com/profile/{}',           'adult'),
    Platform('Mocospace',          'https://www.mocospace.com/u/{}',             'adult'),
    Platform('Kasidie (swinger)',  'https://www.kasidie.com/profile/{}',         'adult'),
    Platform('SwingLifestyle',     'https://www.swinglifestyle.com/profile/{}',  'adult'),
    Platform('Adam4Adam',          'https://www.adam4adam.com/{}',               'adult'),
    Platform('DaddyHunt',          'https://www.daddyhunt.com/{}',               'adult'),
    Platform('Recon',              'https://www.recon.com/{}',                   'adult'),
    Platform('Squirt.org',         'https://www.squirt.org/users/{}',            'adult'),
    Platform('BarebackRT',         'https://www.barebackrt.com/profile/{}',      'adult'),
    Platform('Grommr',             'https://www.grommr.com/{}',                  'adult'),

    # ---- 成人论坛 / 社区 / Adult forums & community ----
    Platform('LPSG',               'https://www.lpsg.com/members/{}',            'adult'),
    Platform('Eros',               'https://www.eros.com/{}',                    'adult'),
    Platform('AVN Forum',          'https://forum.adultdvdtalk.com/users/{}',    'adult'),
    Platform('Reddit r/gonewild',  'https://www.reddit.com/user/{}/submitted/?type=link&sort=new', 'adult'),
    Platform('SLS Forum',          'https://www.swinglifestyle.com/forum/profile/{}/', 'adult'),

    # ---- 视频 / 内容（更多）/ More video & content ----
    Platform('SpankBang',          'https://spankbang.com/profile/{}',           'adult'),
    Platform('Beeg Profiles',      'https://www.beeg.com/-/{}',                  'adult'),
    Platform('YouPorn',            'https://www.youporn.com/uservids/{}/',       'adult'),
    Platform('RedTube',            'https://www.redtube.com/users/{}',           'adult'),
    Platform('Tube8',              'https://www.tube8.com/users/{}',             'adult'),
    Platform('XVideos',            'https://www.xvideos.com/profiles/{}',        'adult'),
    Platform('XNXX',               'https://www.xnxx.com/profiles/{}',           'adult'),
]

# 类别在输出中的显示顺序
CATEGORY_ORDER = ['code', 'social', 'forum', 'video', 'music', 'writing', 'art', 'gaming', 'funding', 'chinese', 'spanish', 'adult', 'other']

# 加载从 Maigret 拉取的扩展平台库
# 用 realpath 而非 abspath：通过符号链接安装（brew/pipx）时 abspath 不解析 symlink，
# 会指向链接目录而非真实目录 → 找不到 data/ → 静默丢失 ~2000 个平台只剩 curated
_PLATFORMS_JSON = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'platforms.json')


def _clean_patterns(items) -> tuple:
    """过滤空 / 全空白 字符串模式。空 bytes pattern (`b''`) 在 `if pat in body`
    永远为 True，会导致每次都报「找到」（伪 ★★★ 命中）—— 必须剔除。"""
    if not items:
        return ()
    cleaned = []
    for s in items:
        if not isinstance(s, (str, bytes)):
            continue
        if isinstance(s, bytes):
            if s.strip():
                cleaned.append(s.lower())
        else:
            ss = s.strip()
            if ss:
                cleaned.append(ss.lower().encode())
    return tuple(cleaned)


def _load_platforms_json(path: str) -> list:
    """从 JSON 文件加载平台定义，转换为 Platform NamedTuple。
    过滤掉空 not_found / must_contain 模式，避免假阳性。
    防御性输入处理（文件被损坏 / 恶意改写时不让整个 _get_platforms 永久失败）：
    - 文件不存在 / 解析错 / 编码错 → 返回 []
    - 顶层不是 list（如 null / int / dict）→ 返回 []
    - 单条 item 不是 dict / 缺 name / 缺 url / name 为 None → 跳过该条
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get('name')
        url = item.get('url')
        # 严格校验：name 必须非空 str，url 必须含 {} 占位符
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(url, str) or '{' not in url:
            continue
        try:
            out.append(Platform(
                name=name,
                url=url,
                category=item.get('category', 'other') if isinstance(item.get('category'), str) else 'other',
                not_found=_clean_patterns(item.get('not_found')),
                must_contain=_clean_patterns(item.get('must_contain')),
                regex_check=item.get('regex_check') or '' if isinstance(item.get('regex_check'), str) else '',
            ))
        except (KeyError, TypeError, ValueError):
            continue
    # JSON 内部去重（_merge_platforms 只去掉与 curated 重复的，不去 JSON 自身重复）
    return _dedup_platforms(out)


def _dedup_platforms(platforms: list) -> list:
    """去掉名字（不区分大小写）重复的项，保留先出现的。
    防御 curated 列表中的笔误（例如 Cam4 / CAM4 同时出现）。"""
    seen = set()
    out = []
    for p in platforms:
        key = p.name.lower().strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _merge_platforms(curated: list, extended: list) -> list:
    """以 curated 为优先（保留我们的中文/分类），追加 extended 中名字不重复的项。"""
    seen = {p.name.lower().strip() for p in curated}
    merged = list(curated)
    for p in extended:
        key = p.name.lower().strip()
        if key in seen:
            continue
        seen.add(key)
        merged.append(p)
    return merged


# 懒加载：保留 curated 列表名，但 PLATFORMS 通过 __getattr__ 按需合并 JSON
# 收益：myip/--help/history 等不扫平台的子命令不再吃 600KB JSON 加载（~100ms）
_CURATED_PLATFORMS = _dedup_platforms(PLATFORMS)
del PLATFORMS  # 强制走 __getattr__ —— 防止意外捕获 curated-only 的旧引用
_PLATFORMS_CACHE: Optional[list] = None


def _get_platforms() -> list:
    """合并 curated + data/platforms.json，结果缓存到模块级。"""
    global _PLATFORMS_CACHE
    if _PLATFORMS_CACHE is None:
        _PLATFORMS_CACHE = _merge_platforms(_CURATED_PLATFORMS, _load_platforms_json(_PLATFORMS_JSON))
    return _PLATFORMS_CACHE


def __getattr__(name: str):
    """PEP 562 模块级 __getattr__：让 spyeyes.PLATFORMS 触发懒加载。
    保持向后兼容（测试和外部代码继续 import spyeyes; spyeyes.PLATFORMS）。"""
    if name == 'PLATFORMS':
        return _get_platforms()
    raise AttributeError(f"module 'spyeyes' has no attribute {name!r}")


def __dir__() -> list:
    """让 dir(spyeyes) / inspect.getmembers() 仍能看到懒加载的 PLATFORMS。
    没这个会导致 IDE 自动补全、PyInstaller hook、IDE introspection 看不到 PLATFORMS。"""
    return sorted(set(globals().keys()) | {'PLATFORMS'})


# WAF / CDN 拦截指纹（Sherlock-inspired，高精度优先）
# 命中 = 该平台被反爬墙拦了，结果不可信；标记 'waf' 而非「找到/未找到」
# 仅使用各 WAF 自有的特定标志（URL/cookie/品牌名），避免 'access denied' / 'cloudflare'
# 这种太泛的模式触发误报（普通页面提到 cloudflare/access denied 时会被误判）
WAF_FINGERPRINTS = (
    # Cloudflare —— 唯一标志（challenge / error pages）
    b'cdn-cgi/challenge-platform',
    b'cf-browser-verification',
    b'cf-challenge',
    b'<title>just a moment...</title>',
    b'<title>attention required! | cloudflare</title>',
    b'enable javascript and cookies to continue',
    b'error code: 1020',           # CF 1020 (Access denied)
    b'cloudflare ray id',           # CF error page footer
    b'cf-mitigated',                # CF 标头泄露到 body
    # AWS WAF
    b'aws-waf-token',
    b'awswafcaptcha',
    b'aws_waf',
    # PerimeterX (HUMAN)
    b'/_pxhc/',
    b'_px3',
    b'px-captcha',
    # DataDome
    b'dd-jwt',
    b'datadome.co',
    # Imperva / Incapsula
    b'/_incapsula_resource',
    b'visid_incap_',
    # Sucuri
    b'sucuri/cloudproxy',
    b'sucuri website firewall',
    # Akamai Bot Manager / Reference IDs
    b'akam/13/pixel',
    b'akamaighost',
    b'reference&#32;&#35;',         # "Reference #" HTML-encoded (Akamai/F5)
)


def _detect_waf(body) -> bool:
    """检查响应体前 8KB 是否含已知 WAF 指纹。
    contract: body 应是 bytes（_check_username 总是传 bytes），但防御性接受 str。"""
    if isinstance(body, str):
        body = body.encode('utf-8', errors='replace')
    if not isinstance(body, (bytes, bytearray)):
        return False
    sample = body[:8192].lower()
    return any(fp in sample for fp in WAF_FINGERPRINTS)


# _check_username 返回 status 取值
STATUS_FOUND = 'found'
STATUS_NOT_FOUND = 'not_found'
STATUS_WAF = 'waf'                    # 被 CDN/反爬墙拦了，结果不可信
STATUS_INVALID_USERNAME = 'invalid'   # 用户名不符合该平台 regex 规则
STATUS_NETWORK_ERROR = 'network_err'  # 超时/连接失败

# username 长度上限（ReDoS 实际防护）：
# data/platforms.json 是 contributor-controlled，无法静态识别所有恶意 regex
# (a+)+ 类灾难性回溯在长输入上指数爆炸 → 把输入限制在 64 字符内可保证
# worst case 落在毫秒级，足以保护 150 线程池（v1.2.0 默认）不被消耗。
# 之前用 _REDOS_RE 启发式检测嵌套量词，在合法 regex（如 [a-z]+(-[a-z]+)*）上
# 误报严重；改用长度限制后既简单又有效。
MAX_USERNAME_LENGTH = 64

# username 字符白名单 —— 拒绝 URL 元字符（/?#@:）、空白、% (URL encoding)，
# 防止 platform.url.format() 拼出非预期 URL：
# - 'foo?x=1' 拼到 github.com/{} → 实际访问 /foo?x=1 → 假命中
# - 'a@b' 拼到 'https://{}.tumblr.com' → 主机变 b.tumblr.com
# - '%2e%2e' URL-encoded 路径穿越
_USERNAME_INVALID_CHARS = frozenset('/?#@:&= \t\n\r\\%')


def _is_invalid_username(username: str) -> bool:
    """检查 username 是否有非法字符或形态。
    拒绝条件：
    - 含 _USERNAME_INVALID_CHARS 中任一字符
    - 含 C0/C1/DEL 控制字符（U+0000-001F / U+007F-009F）—— 防日志注入 /
      终端 escape 注入（C1 含 NEL=0x85 / CSI=0x9B 等）
    - 含 Unicode line/paragraph separator（U+2028/U+2029）—— Markdown 报告
      str.splitlines() 视其为换行 → 注入伪标题
    - 是 '.' / '..'（拼到任意 URL 模板都触发路径穿越式假命中：
      `https://github.com/.` 返回 GitHub 首页 → 不含 not_found 模式 → 假报「找到」）
    - 包含 '..' 子串（同上）
    - 以 '.' 开头或结尾（隐式路径片段）
    """
    if not username or any(c in _USERNAME_INVALID_CHARS for c in username):
        return True
    # 控制字符检测：覆盖 C0 (0x00-0x1F)、DEL (0x7F)、C1 (0x80-0x9F)
    # 攻击场景：
    #   - 'admin\x00garbage' 在日志聚合器中被截断显示为 'admin'
    #   - C1 CSI (0x9B) 是 ANSI escape 起始字节，xterm 系终端会解释为 escape
    if any(ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f for c in username):
        return True
    # Unicode line/paragraph separator —— markdown 渲染按换行处理 → 注入伪标题
    if any(c in '  ' for c in username):
        return True
    if username in ('.', '..') or '..' in username:
        return True
    if username.startswith('.') or username.endswith('.'):
        return True
    return False


def _check_username(platform: 'Platform', username: str, timeout: float):
    """检查单个平台是否存在该用户名。返回 (Platform, URL or None, status)。

    Sherlock-inspired 优化:
    1. **regex_check 预过滤**：username 不符合平台规则 → 跳过 HTTP，节省时间
    2. **HEAD 请求**：仅检测 status_code 的平台跳过 body 下载
    3. **stream + 64KB 读取**：需 body 检测的只读前 64 KB
    4. **WAF 检测**：识别 Cloudflare/AWS WAF 等拦截，避免误报
    """
    # 深度防御：track_username 入口已限制长度 + 已 strip，但 _check_username
    # 是公开的私有 API（_前缀），测试或未来扩展可能直接调用 → 这里再做一次防护
    # 包括 strip 让两个入口语义一致（agent feedback）
    username = (username or '').strip()
    if len(username) > MAX_USERNAME_LENGTH or _is_invalid_username(username):
        return platform, None, STATUS_INVALID_USERNAME

    # ---- 1. URL 模板与 regex 预过滤（不发请求）----
    try:
        full_url = platform.url.format(username)
    except (IndexError, KeyError, ValueError):
        return platform, None, STATUS_INVALID_USERNAME

    if platform.regex_check:
        try:
            # 用 re.fullmatch 而非 re.search 与 Sherlock 保持一致
            # （re.search 对未锚定的 regex 会匹配子串，导致注入风险）
            if not re.fullmatch(platform.regex_check, username):
                return platform, None, STATUS_INVALID_USERNAME
        except re.error:
            pass  # 模式本身坏了，忽略 regex 检查继续

    needs_body = bool(platform.not_found) or bool(platform.must_contain)

    # ---- 2a. 不需要 body → HEAD ----
    if not needs_body:
        resp = safe_get(full_url, timeout=timeout, method='HEAD', allow_redirects=True)
        if resp is None:
            return platform, None, STATUS_NETWORK_ERROR
        # 405/501：平台不支持 HEAD（如 GitHub、Twitter），回退 GET 避免假阴性
        if resp.status_code in (405, 501):
            resp.close()  # 关闭原 HEAD response 释放连接到 pool
            resp = safe_get(full_url, timeout=timeout, stream=True, allow_redirects=True)
            if resp is None:
                return platform, None, STATUS_NETWORK_ERROR
            try:
                if resp.status_code != 200:
                    return platform, None, STATUS_NOT_FOUND
                return platform, full_url, STATUS_FOUND
            finally:
                resp.close()
        # HEAD 成功路径也必须 close，否则 150 线程 × 千平台下连接池被 GC 才回收
        try:
            if resp.status_code != 200:
                return platform, None, STATUS_NOT_FOUND
            return platform, full_url, STATUS_FOUND
        finally:
            resp.close()

    # ---- 2b. 需要 body → stream + 只读前 64KB ----
    resp = safe_get(full_url, timeout=timeout, stream=True, allow_redirects=True)
    if resp is None:
        return platform, None, STATUS_NETWORK_ERROR
    if resp.status_code != 200:
        resp.close()
        return platform, None, STATUS_NOT_FOUND
    try:
        # 循环读取保证拿满 64KB（chunked encoding 下单次 read 可能短读取）
        chunks = []
        remaining = 65536
        while remaining > 0:
            chunk = resp.raw.read(remaining, decode_content=True)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b''.join(chunks).lower()
    except (OSError, ValueError, requests.exceptions.RequestException):
        return platform, None, STATUS_NETWORK_ERROR
    finally:
        resp.close()

    # ---- 3. WAF 检测（在 not_found / must_contain 之前）----
    if _detect_waf(body):
        return platform, None, STATUS_WAF

    # ---- 4. 平台特定检测 ----
    for pattern in platform.not_found:
        if pattern in body:
            return platform, None, STATUS_NOT_FOUND
    if platform.must_contain:
        if not any(pat in body for pat in platform.must_contain):
            return platform, None, STATUS_NOT_FOUND
    return platform, full_url, STATUS_FOUND


def _print_scan_progress(done: int, total: int, found_count: int) -> None:
    """在 stderr 上原地刷新扫描进度条。仅当 stderr 是 TTY 时输出，避免污染日志/管道。"""
    if not sys.stderr.isatty():
        return
    bar_width = 30
    pct = done / total if total else 1.0
    filled = int(bar_width * pct)
    bar = '█' * filled + '░' * (bar_width - filled)
    msg = f"\r {Color.Wh}[{Color.Gr}{bar}{Color.Wh}] {done}/{total} ({pct*100:5.1f}%) {t('msg.found')}: {Color.Gr}{found_count}{Color.Reset}  "
    sys.stderr.write(msg)
    sys.stderr.flush()


def _clear_progress_line() -> None:
    """清掉进度条所在那行（仅 TTY）。"""
    if sys.stderr.isatty():
        sys.stderr.write('\r' + ' ' * 80 + '\r')
        sys.stderr.flush()


def _ask_scan_mode() -> Optional[list]:
    """交互式选择扫描模式。返回 categories 列表（None 表示全部）。"""
    print()
    print(f" {Color.Wh}{t('mode.title')}{Color.Reset}")
    print(f"  {Color.Wh}[ 1 ] {Color.Gr}{t('mode.quick')}{Color.Reset}")
    print(f"  {Color.Wh}[ 2 ] {Color.Gr}{t('mode.full')}{Color.Reset}")
    print(f"  {Color.Wh}[ 3 ] {Color.Gr}{t('mode.cn_es')}{Color.Reset}")
    print(f"  {Color.Wh}[ 4 ] {Color.Gr}{t('mode.code')}{Color.Reset}")
    print()
    try:
        choice = input(f" {Color.Wh}{t('mode.prompt')}{Color.Gr}").strip() or '1'
    except (EOFError, KeyboardInterrupt):
        choice = '1'
    if choice == '2':
        return None  # 完整：全扫
    if choice == '3':
        return ['chinese', 'spanish']
    if choice == '4':
        return ['code']
    # 默认 1：快速 = 全部 cat 减去 'other'
    return [c for c in CATEGORY_ORDER if c != 'other']


def track_username(username: str, *, max_workers: int = 150, timeout: float = 5,
                   show_progress: bool = True, categories: Optional[list] = None) -> dict:
    """并发扫描平台，返回 {platform_name: url_or_None}（按 PLATFORMS 顺序）。
    - 空 username 返回 {'_error': ...}（与 track_ip 行为一致）。
    - 单 worker 抛任何异常不影响其它平台 —— 该平台标记 None 跳过。
    - show_progress=True 且 stderr 是 TTY 时显示进度条。
    - categories=['code', 'chinese', ...] 只扫指定类别；未知类别会触发 _error。"""
    username = (username or '').strip()
    if not username:
        return {'_error': t('err.empty_input')}
    # ReDoS 防护：长输入触发 (a+)+ 类指数回溯 → 截断保证 worst case 毫秒级
    if len(username) > MAX_USERNAME_LENGTH:
        return {'_error': t('err.username_too_long', max=MAX_USERNAME_LENGTH)}
    # URL 注入 / 路径穿越早返：之前会扫 2067 平台都返 STATUS_INVALID_USERNAME
    # 输出 2067 个 null 看起来像「全没命中」而不是「输入被拒」（误导）
    if _is_invalid_username(username):
        return {'_error': t('err.username_invalid_chars')}
    if max_workers < 1:
        max_workers = 1
    # 校验 categories：未知类别返回 error 而非静默扫 0 个
    if categories:
        unknown = [c for c in categories if c not in CATEGORY_ORDER]
        if unknown:
            return {'_error': t('err.unknown_category', unknown=', '.join(unknown),
                                valid=', '.join(CATEGORY_ORDER))}
        platforms_to_scan = [p for p in _get_platforms() if p.category in categories]
    else:
        platforms_to_scan = _get_platforms()
    found: dict = {}
    statuses: dict = {}  # name → STATUS_*
    total = len(platforms_to_scan)
    found_count = 0
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check_username, p, username, timeout): p for p in platforms_to_scan}
        try:
            for fut in as_completed(futures):
                try:
                    platform, url, status = fut.result()
                except Exception:
                    platform = futures[fut]
                    url = None
                    status = STATUS_NETWORK_ERROR
                found[platform.name] = url
                statuses[platform.name] = status
                done += 1
                if url:
                    found_count += 1
                if show_progress:
                    _print_scan_progress(done, total, found_count)
        except KeyboardInterrupt:
            # Ctrl+C: 立即取消未启动 worker，已运行的最多等 timeout 秒
            ex.shutdown(wait=False, cancel_futures=True)
            if show_progress:
                _clear_progress_line()
            raise
    if show_progress:
        _clear_progress_line()
    # 保持 PLATFORMS 内部顺序；未扫描的平台不出现在结果里
    results = {p.name: found[p.name] for p in platforms_to_scan if p.name in found}
    # 统计信息存到私有 key（_ 开头），打印/保存函数会跳过
    results['_statuses'] = {p.name: statuses[p.name] for p in platforms_to_scan if p.name in statuses}
    return results


# ====================================================================
# v1.1.0: 用户名变形生成器 —— 灵感来自 Maigret --permute
# ====================================================================
# 防 DoS：限制输入片段数和最终变形数（笛卡尔积可能爆炸）
PERMUTE_MAX_INPUT_PARTS = 4   # 最多接受 4 个片段（"first middle last extra"）
PERMUTE_MAX_OUTPUT = 200      # 单次最多生成 200 个变形（避免组合爆炸打爆扫描）


PERMUTE_SEPARATORS = ('', '_', '-', '.')  # Maigret 风格四种分隔符


def _permute_sort_key(s: str) -> tuple:
    """排序键：method='all' 模式下，把"装饰过的"变体（_前缀 / 后缀_）排到后面。
    避免 200 输出上限被 `_a-...`, `_b-...` 这类填满，让用户看不到 johndoe 等核心变体。
    （v1.2.1 P1-1 修复 —— `_` ASCII 95 < 字母 97，纯字母序排序会让 `_xxx` 在前。）"""
    decorated = s.startswith('_') or s.endswith('_')
    return (1 if decorated else 0, s)


def permute_username(name: str, method: str = 'strict') -> list[str]:
    """从 "John Doe" / "first.last" / "John;Doe;42" 生成用户名变形（Maigret 风格）。

    method:
      - 'strict' (默认): 多片段全排列 + 4 种分隔符 + 首字母变形
      - 'all':           在 strict 基础上额外加入 `_前缀` / `后缀_` 变种

    生成规则：
      - 单片段：直接返回小写形式（'all' 模式额外加 `_x` / `x_`）
      - 多片段（按空白/逗号/分号/点号/下划线/连字符切分）：
        * `itertools.permutations(parts, r)` 对 r ∈ [2..N] 全排列
        * 每个排列与 4 种分隔符 ['', '_', '-', '.'] 拼接
        * size-2 排列额外生成首字母变形：jdoe / johnd / j.doe / john.d / jd / j_d / ...
      - 全部小写、去重、按字母序、截断到 PERMUTE_MAX_OUTPUT

    安全：限制输入片段数 ≤ PERMUTE_MAX_INPUT_PARTS，避免 4! * variants 爆炸；
    set + 早停 + sorted 保证确定性输出。
    """
    name = (name or '').strip()
    if not name:
        return []
    # 同时支持空白 / 标点 作为分隔符（"john doe" / "John,Doe" / "first.last"）
    parts = re.split(r"[\s,;._\-]+", name)
    parts = [re.sub(r"[^\w]", "", p).lower() for p in parts if p.strip()]
    parts = [p for p in parts if p]  # 过滤被清空的片段
    if not parts:
        return []
    if len(parts) > PERMUTE_MAX_INPUT_PARTS:
        # 截断而非报错：用户友好（"a b c d e f" → 取前 4 个）
        parts = parts[:PERMUTE_MAX_INPUT_PARTS]

    out: set[str] = set()

    def _add(s: str) -> bool:
        """加入候选；method='all' 时额外加 _前缀 / 后缀_。返回是否已达上限。"""
        out.add(s)
        if method == 'all':
            out.add(f'_{s}')
            out.add(f'{s}_')
        return len(out) >= PERMUTE_MAX_OUTPUT

    # 单片段：直接返回（method='all' 通过 _add 加 _x / x_）
    if len(parts) == 1:
        _add(parts[0])
        return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]

    # 多片段：所有子集大小 2..N 的全排列 × 4 种分隔符
    for r in range(2, len(parts) + 1):
        for perm in itertools.permutations(parts, r):
            for sep in PERMUTE_SEPARATORS:
                if _add(sep.join(perm)):
                    return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]
            # 首字母变形仅对 size-2 排列生成（防 r=4 时组合爆炸）
            if r == 2:
                a, b = perm
                for sep in PERMUTE_SEPARATORS:
                    if _add(f'{a[0]}{sep}{b}'):       # jdoe / j.doe / j_doe / j-doe
                        return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]
                    if _add(f'{a}{sep}{b[0]}'):       # johnd / john.d / john_d / john-d
                        return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]
                    if _add(f'{a[0]}{sep}{b[0]}'):    # jd / j.d / j_d / j-d
                        return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]

    # 单片段也作为候选（"John Doe" → ["john", "doe"] 单字也试）
    for p in parts:
        if _add(p):
            break
    # 截断到上限（防御 unicode 多字节带来的意外膨胀）
    return sorted(out, key=_permute_sort_key)[:PERMUTE_MAX_OUTPUT]


# ====================================================================
# v1.1.0: 递归扫描 —— 灵感来自 Maigret 的 recursive search
# ====================================================================
# 从命中页面提取的"次级用户名"模式（保守、低误报）
# 只匹配明显的 @handle 与已知社交平台 URL 中的用户名
_USERNAME_EXTRACT_RE = re.compile(
    r"(?:"
    # @handle 形式（前后必须是非字母数字边界）
    r"(?<![\w])@([a-zA-Z][\w]{2,30})(?![\w])"
    r"|"
    # twitter/instagram/github/youtube 等 URL 中的用户名
    r"(?:https?://)?(?:www\.)?"
    r"(?:twitter|x|instagram|facebook|github|gitlab|youtube|t\.me|telegram|"
    r"linkedin|reddit|tiktok|twitch|medium|patreon|behance|dribbble|"
    r"deviantart|soundcloud|bandcamp|mastodon\.social|threads\.net)"
    r"\.com/(?:@)?([\w][\w.\-]{2,30})"
    r")",
    re.IGNORECASE,
)
RECURSIVE_MAX_DEPTH = 2          # 防止指数爆炸
RECURSIVE_MAX_NEW_PER_DEPTH = 5  # 每层最多扩展 5 个新用户名（避免被海量误识别坑死）
RECURSIVE_FETCH_LIMIT = 8        # 每层最多抓取 8 个命中页面提取用户名（速度 + 礼貌）


def _extract_usernames_from_text(text: str, exclude: set[str]) -> list[str]:
    """从一段文本（profile 页面）提取潜在的次级用户名。
    - exclude: 已知扫过的，避免循环
    - 长度过滤：3 ≤ len ≤ 30
    - 全部小写比较，避免 "Foo" 与 "foo" 重复
    """
    found: list[str] = []
    seen: set[str] = set()
    for m in _USERNAME_EXTRACT_RE.finditer(text or ''):
        # 两个捕获组择一非空
        candidate = (m.group(1) or m.group(2) or '').strip().lower()
        if not candidate or len(candidate) < 3 or len(candidate) > 30:
            continue
        if candidate in seen or candidate in exclude:
            continue
        # 拒绝纯数字（avoid "support" → "1234567890" 之类）
        if candidate.isdigit():
            continue
        # ReDoS / URL 注入防护
        if _is_invalid_username(candidate):
            continue
        seen.add(candidate)
        found.append(candidate)
    return found


def recursive_track_username(username: str, *, max_depth: int = 2,
                             max_workers: int = 150, timeout: float = 5,
                             show_progress: bool = True,
                             categories: Optional[list] = None) -> dict:
    """递归扫描：先扫初始 username → 抓取部分命中页面 → 提取次级用户名 → 再扫。

    返回结构：
      {
        '_recursive': {
          'levels': [
            {'depth': 0, 'username': 'torvalds', 'found': N, 'platforms': {...}},
            {'depth': 1, 'username': 'linus', 'found': M, 'platforms': {...}},
            ...
          ],
          'total_found': 总命中数,
        },
        // 顶层 platforms 仍是 depth=0 的结果（向后兼容）
        ...depth0_results...
      }
    """
    max_depth = max(0, min(max_depth, RECURSIVE_MAX_DEPTH))
    visited: set[str] = set()
    levels: list[dict] = []
    queue: list[tuple[int, str]] = [(0, username)]

    while queue:
        depth, name = queue.pop(0)
        if depth > max_depth:
            break
        key = name.lower().strip()
        if not key or key in visited:
            continue
        visited.add(key)
        # v1.6.1:递归层级反馈(用户开多深度时知道现在在哪一层)
        if show_progress:
            _stage_log(f"\n {Color.Cy}{t('recursive.stage_scan', depth=depth, max=max_depth, name=name)}{Color.Reset}")
        result = track_username(name, max_workers=max_workers, timeout=timeout,
                                show_progress=show_progress, categories=categories)
        if '_error' in result:
            levels.append({'depth': depth, 'username': name, 'error': result['_error'], 'platforms': {}})
            continue
        plat = _platform_only(result)
        found_urls = [u for u in plat.values() if u]
        levels.append({
            'depth': depth, 'username': name, 'found': len(found_urls),
            'platforms': result,
        })
        # 仅在还没到最大深度时抓取页面继续展开
        if depth >= max_depth:
            continue
        # v1.6.1:profile 抓取阶段加进度反馈(之前 silent 40s,用户以为卡了)
        fetch_count = min(len(found_urls), RECURSIVE_FETCH_LIMIT)
        if fetch_count > 0 and show_progress:
            _stage_log(f"   {Color.Bl}{t('recursive.stage_fetch', n=fetch_count)}{Color.Reset}")
        new_candidates: list[str] = []
        fetched_done = 0
        for url in found_urls[:RECURSIVE_FETCH_LIMIT]:
            try:
                resp = safe_get(url, timeout=timeout, method='GET')
                # 仅抓 first 64KB 防大页面拖慢
                body = (resp.text or '')[:65536] if resp is not None else ''
            except Exception:
                body = ''
            extracted = _extract_usernames_from_text(body, visited)
            for u in extracted:
                if u not in new_candidates:
                    new_candidates.append(u)
                if len(new_candidates) >= RECURSIVE_MAX_NEW_PER_DEPTH:
                    break
            fetched_done += 1
            # v1.6.1:每抓一页打一行,用户知道在第几页
            if show_progress and sys.stderr.isatty():
                sys.stderr.write(
                    f"\r   [fetch] {fetched_done}/{fetch_count} "
                    f"({t('recursive.found_new', n=len(new_candidates))})       "
                )
                sys.stderr.flush()
            if len(new_candidates) >= RECURSIVE_MAX_NEW_PER_DEPTH:
                break
        if show_progress and sys.stderr.isatty():
            sys.stderr.write('\r' + ' ' * 80 + '\r')
            sys.stderr.flush()
        if show_progress and new_candidates:
            _stage_log(f"   {Color.Gr}{t('recursive.candidates_found', n=len(new_candidates), names=', '.join(new_candidates))}{Color.Reset}")
        for u in new_candidates:
            queue.append((depth + 1, u))

    total_found = sum(level.get('found', 0) for level in levels)
    summary = {
        '_recursive': {
            'levels': levels,
            'total_found': total_found,
            'depth_reached': max((level['depth'] for level in levels), default=0),
        }
    }
    # 向后兼容：把 depth=0 的扁平结果也合并到顶层（让 _platform_only/print_username 直接可用）
    if levels and levels[0].get('platforms'):
        summary.update(levels[0]['platforms'])
    return summary


# ====================================================================
# 核心查询：WHOIS / MX / 邮箱
# ====================================================================
def whois_lookup(domain: str) -> dict:
    if not HAS_WHOIS:
        return {'_error': t('err.no_whois')}
    normalized = _normalize_domain(domain)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=(domain or '').strip()[:80])}
    domain = normalized
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {'_error': t('err.whois_failed', e=e)}
    # python-whois 在某些 TLD（如未支持的 TLD）会返回 None 而非抛异常
    if w is None:
        return {'_error': t('err.whois_failed', e='no data')}
    return {
        'domain':          w.domain_name,
        'registrar':       w.registrar,
        'creation_date':   _whois_date(w.creation_date),
        'expiration_date': _whois_date(w.expiration_date),
        'updated_date':    _whois_date(w.updated_date),
        'name_servers':    w.name_servers,
        'status':          w.status,
        'emails':          w.emails,
        'org':             w.org,
        'country':         w.country,
    }


def _whois_date(value):
    """python-whois 对某些 TLD 返回 list[datetime]（多次记录），不能直接 str()
    会得到 repr 字符串 "[datetime.datetime(...)]"，必须逐项转换为列表。
    list 内 None / 异常元素被过滤（避免 'None' 字面字符串污染输出）。"""
    if value is None:
        return None
    if isinstance(value, list):
        cleaned = [str(d) for d in value if d is not None]
        return cleaned or None
    return str(value)


def mx_lookup(domain: str) -> dict:
    """查询 MX 记录。
    成功: {'domain': str, 'records': [{'preference': int, 'exchange': str}, ...]}
    失败: {'_error': i18n_msg, '_error_kind': MX_ERR_*}
        _error_kind 是稳定枚举供调用方判断（避免 substring 误匹配 i18n msg）
    """
    if not HAS_DNS:
        return {'_error': t('err.no_dns'), '_error_kind': MX_ERR_NO_DNS_DEP}
    normalized = _normalize_domain(domain)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=(domain or '').strip()[:80]),
                '_error_kind': MX_ERR_INVALID_DOMAIN}
    domain = normalized
    try:
        answers = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        return {'_error': t('err.nxdomain', domain=domain), '_error_kind': MX_ERR_NXDOMAIN}
    except dns.resolver.NoAnswer:
        return {'_error': t('err.no_mx', domain=domain), '_error_kind': MX_ERR_NO_MX}
    except Exception as e:
        # NoNameservers / Timeout / 等都归到 dns_failed —— 不要让 message
        # 内部细节（server IP / 解析栈）泄漏到 _error_kind 决策
        return {'_error': t('err.dns_failed', e=e), '_error_kind': MX_ERR_DNS_FAILED}
    records = sorted(
        [{'preference': r.preference, 'exchange': str(r.exchange).rstrip('.')} for r in answers],
        key=lambda r: r['preference'],
    )
    return {'domain': domain, 'records': records}


# Email 本地部分：ASCII；domain 部分允许 IDN（先转 punycode 再校验）
EMAIL_RE = re.compile(r"^([A-Za-z0-9._%+\-']+)@([\w.\-¡-￿]+\.[\w\-¡-￿]{2,})$")

# 域名 punycode 形式（IDN 转换后）的格式校验
# Label 首字符允许下划线：DKIM/DMARC/ACME 用的 _dmarc.example.com / _acme-challenge.x
# 是 RFC-compliant DNS label（OSINT 工具的合法查询场景）
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)'
    r'[_A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(?:\.[_A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'
)


def _normalize_domain(domain: str) -> Optional[str]:
    """规范化并校验 domain。非法返回 None；合法返回 lower-case ASCII 形式。

    支持:
    - IDN（中文/韩文/日文等）: 先 encode('idna') 转 punycode (xn--...)
    - DKIM/DMARC/ACME 子域: 允许下划线开头的 label（_dmarc / _acme-challenge）
    - Trailing dot FQDN: 'example.com.' 是合法 DNS FQDN，自动 rstrip

    防御目标：拒绝换行注入 / URL 形式 / 路径片段。
    """
    domain = (domain or '').strip().lower().rstrip('.')
    if not domain:
        return None
    # IDN 转 punycode（如 '中国' → 'xn--fiqs8s'）
    # 失败的非法 Unicode 域名（控制字符、不规范 label 等）走 except → None
    try:
        # encode('idna') 对纯 ASCII 域名也能 work，对带 _ 的 label 不行
        # → 先按 . 分 label 逐个 encode（避免 idna 拒绝 _dmarc 这类合法 OSINT 域名）
        labels = []
        for label in domain.split('.'):
            if label.startswith('_'):
                # _ 开头的 label 不参与 IDN 转换，保持原样
                if not label.replace('_', '').replace('-', '').isalnum():
                    return None
                labels.append(label)
            else:
                labels.append(label.encode('idna').decode('ascii'))
        ascii_form = '.'.join(labels)
    except (UnicodeError, UnicodeDecodeError):
        return None
    if not DOMAIN_RE.match(ascii_form):
        return None
    return ascii_form


# mx_lookup 错误类型枚举（agent feedback：之前用 substring 匹配 dns 错误 message
# 容易误判，比如 'NoNameservers' 含 'no' 会被错归为 no_mx；改用显式枚举）
MX_ERR_NXDOMAIN = 'nxdomain'
MX_ERR_NO_MX = 'no_mx'
MX_ERR_INVALID_DOMAIN = 'invalid_domain'
MX_ERR_NO_DNS_DEP = 'no_dns_dep'
MX_ERR_DNS_FAILED = 'dns_failed'


def email_validate(email: str) -> dict:
    email = (email or '').strip()
    if not email:
        return {'email': '', 'syntax_valid': False, '_error': t('err.empty_input')}
    m = EMAIL_RE.match(email)
    if not m:
        return {'email': email, 'syntax_valid': False, '_error': t('err.email_format')}
    domain = m.group(2)  # group(1)=local part, group(2)=domain
    result: dict = {'email': email, 'syntax_valid': True, 'domain': domain}
    mx = mx_lookup(domain)
    if '_error' in mx:
        result['mx_valid'] = False
        # mx_error: 稳定枚举供程序判定（'nxdomain' / 'no_mx' / ...）
        # mx_error_msg: i18n 友好消息供 UI 显示（避免用户看到英文枚举字符串）
        result['mx_error'] = mx.get('_error_kind', MX_ERR_DNS_FAILED)
        result['mx_error_msg'] = mx.get('_error', '')
    else:
        result['mx_valid'] = True
        result['mx_records'] = mx['records']
    return result


# ====================================================================
# v1.3.0: 子域名枚举(被动多源 + DNS 验证 + 可选 HTTP probe)
# ====================================================================
# 设计:
#   - 被动多源(crt.sh / HackerTarget / AlienVault OTX / ThreatCrowd)并发拉取
#   - 单源失败/超时不影响其它源(每源独立 try/except,返回空 set)
#   - Wildcard 检测:解析 32 字符随机前缀,命中则给所有结果加 wildcard_suspect 标记
#   - DNS A/AAAA/CNAME 解析每个候选,确认活性
#   - HTTP probe(默认开启,--no-probe 关闭)对 alive 子域抓 status + <title>
#   - 所有用户输入字段经 _normalize_domain 校验(沿用 whois/mx 同套防御)
SUBDOMAIN_MAX_RESULTS = 2000           # 输出上限,防被动源刷出几万条压垮内存/网络
SUBDOMAIN_DEFAULT_WORKERS = 30         # DNS 并发线程数(系统 resolver 不喜欢过高并发)
SUBDOMAIN_HTTP_WORKERS = 80            # v1.4.11:HTTP probe 用更高并发(I/O bound,~3 倍速)
SUBDOMAIN_DNS_TIMEOUT = 3.0            # 单条 DNS 查询超时
SUBDOMAIN_HTTP_PROBE_TIMEOUT = 4.0     # v1.4.11:5s → 4s(连不上的快点失败)
SUBDOMAIN_PROBE_MAX_BODY = 16384       # probe 抓取 body 上限(只为提取 <title>)
SUBDOMAIN_SOURCE_TIMEOUT = 45.0        # v1.4.4:单源被动 API 拉取超时(crt.sh 对 .do 等 TLD 慢,15s 不够)

# hostname 字符白名单:字母数字 + . - + 下划线(_dmarc 等合法 OSINT 子域)
_SUBDOMAIN_HOSTNAME_RE = re.compile(r'^[a-z0-9._\-]+$')

# 提取 <title> 用的正则;case-insensitive + dotall 不必要(title 一般在头部 16KB 内)
_HTML_TITLE_RE = re.compile(rb'<title[^>]*>([^<]{0,200})</title>', re.IGNORECASE)


def _clean_subdomain_candidates(raw_hosts, parent_domain: str) -> set[str]:
    """归一化被动源返回的 hostname:小写、strip、过滤 wildcard `*.`、去 trailing dot,
    丢弃不属于 parent_domain 的项(防被动源串域)。"""
    parent = parent_domain.lower().strip().rstrip('.')
    out: set[str] = set()
    if not isinstance(raw_hosts, (list, tuple, set)):
        return out
    for h in raw_hosts:
        if not isinstance(h, str):
            continue
        host = h.strip().lower().rstrip('.')
        # 去掉 wildcard 前缀 `*.example.com` → `example.com`
        if host.startswith('*.'):
            host = host[2:]
        # 部分源会返回多行(crt.sh `name_value` 含换行),逐行处理交给上层
        if '\n' in host or '\r' in host:
            continue
        # 必须是 parent_domain 的子域(包括 parent 本身)
        if not (host == parent or host.endswith('.' + parent)):
            continue
        if not _SUBDOMAIN_HOSTNAME_RE.match(host):
            continue
        if len(host) > 253:  # DNS 上限
            continue
        out.add(host)
    return out


def _src_crtsh(domain: str) -> set[str]:
    """https://crt.sh/?q=%25.{domain}&output=json — Certificate Transparency 日志。
    返回 [{name_value: "a.example.com\\nb.example.com", ...}, ...]"""
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    # v1.4.3:OSINT 源首次连接握手可能很慢(crt.sh ~5s),不能让 connect 卡 3s
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT, connect_timeout=10.0)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, list):
        return set()
    hosts: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        # name_value 可能含 \n 分隔的多个 SAN
        nv = entry.get('name_value') or ''
        if isinstance(nv, str):
            for line in nv.split('\n'):
                hosts.append(line)
        cn = entry.get('common_name')
        if isinstance(cn, str):
            hosts.append(cn)
    return _clean_subdomain_candidates(hosts, domain)


def _src_hackertarget(domain: str) -> set[str]:
    """https://api.hackertarget.com/hostsearch/?q={domain} — text/CSV `host,ip`(每日 ~50 quota)。"""
    url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
    # v1.4.3:OSINT 源首次连接握手可能很慢(crt.sh ~5s),不能让 connect 卡 3s
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT, connect_timeout=10.0)
    if resp is None or resp.status_code != 200:
        return set()
    text = (resp.text or '').strip()
    # quota 用尽时返回 "API count exceeded - rate limit reached" 而非 CSV
    if 'error' in text.lower() or 'rate limit' in text.lower() or 'exceeded' in text.lower():
        return set()
    hosts = [line.split(',', 1)[0] for line in text.splitlines() if ',' in line]
    return _clean_subdomain_candidates(hosts, domain)


def _src_otx(domain: str) -> set[str]:
    """https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
    AlienVault OTX:passive DNS 数据库。
    v1.4.4:2024 年起匿名访问被限速(429 anonymous limited),需要 API key。
    设 SPYEYES_OTX_API_KEY=YOUR_KEY 启用(免费注册 https://otx.alienvault.com)。
    无 key 时仍试匿名(可能 work 也可能 429)。"""
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
    api_key = (os.environ.get('SPYEYES_OTX_API_KEY') or '').strip()
    headers = {'X-OTX-API-KEY': api_key} if api_key else None
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT,
                    connect_timeout=10.0, headers=headers)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, dict):
        return set()
    records = data.get('passive_dns') or []
    if not isinstance(records, list):
        return set()
    hosts = [r.get('hostname') for r in records if isinstance(r, dict)]
    return _clean_subdomain_candidates(hosts, domain)


def _src_certspotter(domain: str) -> set[str]:
    """https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names
    SSLMate CertSpotter:免费 CT 日志查询 API,替补 crt.sh(后者经常超时)。
    返回 [{dns_names: [host1, host2], ...}, ...]
    v1.4.7:加 SPYEYES_CERTSPOTTER_API_KEY 支持(免费层 100 req/h → 注册后宽很多;
    https://sslmate.com/account/api_credentials)"""
    url = (f'https://api.certspotter.com/v1/issuances?domain={domain}'
           f'&include_subdomains=true&expand=dns_names')
    api_key = (os.environ.get('SPYEYES_CERTSPOTTER_API_KEY') or '').strip()
    headers = {'Authorization': f'Bearer {api_key}'} if api_key else None
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT,
                    connect_timeout=10.0, headers=headers)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, list):
        return set()
    hosts: list = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        names = entry.get('dns_names') or []
        if isinstance(names, list):
            hosts.extend(n for n in names if isinstance(n, str))
    return _clean_subdomain_candidates(hosts, domain)


def _src_wayback(domain: str) -> set[str]:
    """v1.4.9:Web Archive(Wayback Machine) CDX API。
    https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey
    返回 [["original"], [url1], [url2], ...] — 历史归档过的所有 URL,从中抽 hostname。
    特点:覆盖时间长(Internet Archive 自 1996),能挖出已下线但曾出现过的子域。"""
    url = (f'https://web.archive.org/cdx/search/cdx?url=*.{domain}'
           f'&output=json&fl=original&collapse=urlkey&limit=10000')
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT, connect_timeout=10.0)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, list) or len(data) < 2:
        return set()
    import urllib.parse
    hosts: list[str] = []
    for row in data[1:]:  # 第一行是 header ["original"]
        if not isinstance(row, list) or not row:
            continue
        u = row[0]
        if not isinstance(u, str) or not u:
            continue
        if '://' not in u:
            u = 'http://' + u
        try:
            host = urllib.parse.urlsplit(u).hostname
        except (ValueError, AttributeError):
            continue
        if host:
            hosts.append(host)
    return _clean_subdomain_candidates(hosts, domain)


# v1.4.8:可选集成 ProjectDiscovery 的 subfinder(30+ 数据源,行业最强被动子域工具)
# 设计:用户机器装了 subfinder 二进制 → SpyEyes 自动调用作为第 5 个源;
#        没装 → silent skip,4 源照常工作。零强制依赖。
# subfinder 自己管 chaos / SecurityTrails / Censys / Shodan 等付费 API key
# (~/.config/subfinder/provider-config.yaml 或读 PDCP_API_KEY env var)
SUBFINDER_TIMEOUT = 90  # 单次 subfinder 跑总超时(s),subfinder 自己也有 -timeout

# 模块级缓存:每次 enumerate 不重复跑 which (~ms 但累积)
_SUBFINDER_BIN: Optional[str] = None
_SUBFINDER_CHECKED = False


def _has_subfinder() -> Optional[str]:
    """检测 subfinder 二进制路径,返 path 或 None。结果缓存到模块级。"""
    global _SUBFINDER_BIN, _SUBFINDER_CHECKED
    if not _SUBFINDER_CHECKED:
        import shutil
        _SUBFINDER_BIN = shutil.which('subfinder')
        _SUBFINDER_CHECKED = True
    return _SUBFINDER_BIN


def _src_subfinder(domain: str) -> set[str]:
    """v1.4.8:调用 ProjectDiscovery subfinder 二进制,聚合 30+ 数据源结果。
    没装 subfinder 时返空 set(silent skip,不破坏 SpyEyes 4 源主流程)。

    安装:
      brew install subfinder
      或 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    subfinder 自动读 ~/.config/subfinder/provider-config.yaml 与 env vars
    (PDCP_API_KEY / VIRUSTOTAL_API_KEY 等)— SpyEyes 不参与认证。"""
    bin_path = _has_subfinder()
    if not bin_path:
        return set()
    # subfinder 是用户主动安装的可信工具,bin_path 来自 shutil.which
    # (仅返 PATH 内可执行文件),domain 已 _normalize_domain 校验,
    # 参数全是字面量,shell=False(默认)。安全。
    import subprocess  # nosec B404
    try:
        proc = subprocess.run(  # nosec B603
            [bin_path, '-d', domain, '-silent', '-json',
             '-timeout', '30', '-max-time', '2'],  # max-time 单位:分钟
            capture_output=True, text=True,
            timeout=SUBFINDER_TIMEOUT, shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return set()
    if proc.returncode != 0:
        return set()
    out: list = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            # subfinder 老版本可能直接打 plain hostname,不是 JSON
            out.append(line)
            continue
        if isinstance(rec, dict):
            host = rec.get('host', '')
            if isinstance(host, str) and host:
                out.append(host)
    # _clean_subdomain_candidates:跨域过滤 + 字符白名单 + 长度上限
    return _clean_subdomain_candidates(out, domain)


# v1.4.4:源映射表(测试可 monkeypatch 单个源;调整顺序不影响合并结果)
# v1.4.8:加 subfinder 第 5 源(可选 — 检测到二进制才用)
SUBDOMAIN_SOURCES = {
    'crtsh':         _src_crtsh,
    'certspotter':   _src_certspotter,
    'hackertarget':  _src_hackertarget,
    'otx':           _src_otx,
    'wayback':       _src_wayback,    # v1.4.9:Web Archive 历史归档(可挖已下线子域)
    'subfinder':     _src_subfinder,  # 30+ 源聚合,装了 subfinder 自动启用
}


# v1.4.9:DNS 字典爆破(opt-in via --bruteforce 或 SPYEYES_BRUTEFORCE=1)
# ~220 个高命中率前缀(jhaddix top 1k 的精选子集)。用户可设
# SPYEYES_DNS_WORDLIST=/path/to/big.txt 覆盖(massdns / shuffledns 用的大字典)。
_SUBDOMAIN_BUILTIN_WORDLIST: tuple = (
    'www', 'www1', 'www2', 'www3', 'mail', 'mail2', 'webmail', 'webmail2',
    'smtp', 'pop', 'pop3', 'imap', 'autodiscover', 'email', 'mx', 'mx1', 'mx2',
    'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
    'admin', 'administrator', 'dashboard', 'cpanel', 'whm', 'webdisk',
    'api', 'api1', 'api2', 'api-dev', 'api-staging', 'api-prod', 'api-test',
    'app', 'apps', 'application', 'mobile', 'm', 'wap', 'mobi',
    'static', 'cdn', 'cdn1', 'cdn2', 'assets', 'media', 'images', 'img',
    'video', 'videos', 'stream', 'streaming', 'live',
    'dev', 'development', 'dev1', 'dev2', 'staging', 'stage',
    'test', 'testing', 'test1', 'test2', 'qa', 'sandbox', 'demo', 'beta',
    'alpha', 'preview', 'preprod', 'pre-prod', 'prod', 'production',
    'rc', 'uat', 'sit',
    'blog', 'news', 'forum', 'forums', 'community',
    'help', 'support', 'kb', 'docs', 'doc', 'documentation', 'wiki', 'faq',
    'shop', 'store', 'cart', 'checkout', 'pay', 'payment', 'payments',
    'billing', 'invoice', 'orders',
    'login', 'signin', 'signup', 'register', 'auth', 'sso', 'oauth',
    'account', 'accounts', 'profile', 'user', 'users', 'my', 'me',
    'portal', 'gateway', 'proxy', 'router', 'edge', 'gw',
    'vpn', 'vpn1', 'vpn2', 'remote', 'rdp', 'ssh',
    'git', 'gitlab', 'svn', 'jenkins', 'ci', 'build', 'deploy',
    'jira', 'confluence', 'bamboo', 'bitbucket',
    'monitor', 'monitoring', 'metrics', 'grafana', 'kibana', 'prometheus',
    'log', 'logs', 'logging', 'syslog',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'mongodb',
    'es', 'elastic', 'elasticsearch', 'solr', 'search',
    'crm', 'erp', 'hr', 'finance', 'sales', 'marketing',
    'public', 'private', 'internal', 'intranet', 'extranet',
    'old', 'new', 'temp', 'tmp', 'backup', 'bak',
    'office', 'office365', 'lync', 'sip', 'voip', 'pbx',
    'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'files', 'file',
    'download', 'upload', 'uploads', 'fileserver',
    'ws', 'websocket', 'rtc', 'meet', 'chat', 'im',
    'analytics', 'tracking', 'pixel', 'tag', 'tags', 'tagmanager',
    'ads', 'ad', 'campaign', 'promo',
    'partner', 'partners', 'vendor', 'reseller',
    'event', 'events', 'webinar',
    'job', 'jobs', 'careers',
    'about', 'contact', 'press', 'investor', 'investors',
    'home', 'root', 'main',
    'secure', 'security', 'cert', 'ssl',
    'web', 'web1', 'web2',
    'ftp', 'ftps', 'sftp',
)


def _load_bruteforce_wordlist() -> tuple:
    """加载用户字典(`SPYEYES_DNS_WORDLIST=/path`)或内置 ~220 词字典。
    用户字典每行一个前缀,空行 / `#` 注释行忽略;若加载失败 silent fall back 到内置字典。"""
    custom_path = (os.environ.get('SPYEYES_DNS_WORDLIST') or '').strip()
    if custom_path:
        try:
            with open(custom_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = []
                for line in f:
                    w = line.strip()
                    if not w or w.startswith('#'):
                        continue
                    words.append(w)
                if words:
                    return tuple(words)
        except OSError:
            pass
    return _SUBDOMAIN_BUILTIN_WORDLIST


def _generate_bruteforce_candidates(domain: str) -> set[str]:
    """v1.4.9:从内置 / 用户字典生成 `<prefix>.<domain>` 候选列表。
    返回的是候选 hostname set(尚未做 DNS 验证),后续主流程的 stage 3 DNS resolve 自动验证。"""
    domain = (domain or '').lower().strip().rstrip('.')
    if not domain:
        return set()
    words = _load_bruteforce_wordlist()
    raw = [f'{w}.{domain}' for w in words]
    return _clean_subdomain_candidates(raw, domain)


# v1.4.9:JS / HTML 提取 — 在 alive 子域 HTTP probe 时,扫 body 中的 hostname 引用
# 例:`fetch('https://api.example.com/...')` / `<script src="//cdn.example.com/...">`
# 提取后再走一轮 DNS 验证,挖出页面上硬编码但被动源没收录的子域。
_HTML_HOSTNAME_RE = re.compile(rb'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                                rb'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',
                                re.IGNORECASE)


def _extract_hosts_from_body(body: bytes, parent_domain: str) -> set[str]:
    """v1.4.9:从 HTML/JS body 中正则提取 `*.parent_domain` 的 hostname。
    body 已经是 16KB 截断的(SUBDOMAIN_PROBE_MAX_BODY),正则扫描成本极低。
    跨域 hostname 自动过滤(parent_domain 校验在 _clean_subdomain_candidates 中做)。"""
    if not body or not parent_domain:
        return set()
    hosts: list[str] = []
    for m in _HTML_HOSTNAME_RE.finditer(body):
        try:
            h = m.group(0).decode('ascii', errors='replace').lower()
        except (UnicodeDecodeError, AttributeError):
            continue
        hosts.append(h)
        if len(hosts) > 5000:  # 防恶意页面把内存压垮
            break
    return _clean_subdomain_candidates(hosts, parent_domain)


def _stage_log(msg: str) -> None:
    """子域名枚举阶段反馈(写 stderr,仅 TTY 时输出避免污染管道)。"""
    if sys.stderr.isatty():
        sys.stderr.write(msg + '\n')
        sys.stderr.flush()


def passive_collect_subdomains(domain: str, *, show_progress: bool = True) -> dict:
    """并发拉取所有被动源,返回 {sources: {name: count}, candidates: set, errors: {name: True}}.
    任何单源失败都被吞,只在 errors 中记录;调用方据此判断结果可信度。
    show_progress=True 时每个源完成后输出一行到 stderr(消除"卡顿期"困惑)。"""
    candidates: set[str] = set()
    sources_count: dict = {}
    errors: dict = {}
    with ThreadPoolExecutor(max_workers=len(SUBDOMAIN_SOURCES)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in SUBDOMAIN_SOURCES.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                hosts = fut.result()
            except Exception as e:
                errors[name] = True
                sources_count[name] = 0
                if show_progress:
                    _stage_log(f"   {Color.Re}{t('subdomain.source_err', name=name, err=str(e)[:60])}{Color.Reset}")
                continue
            sources_count[name] = len(hosts)
            candidates |= hosts
            if show_progress:
                color = Color.Gr if hosts else Color.Bl  # 命中 = 绿,空 = 蓝
                _stage_log(f"   {color}{t('subdomain.source_done', name=name, n=len(hosts))}{Color.Reset}")
    return {'sources': sources_count, 'candidates': candidates, 'errors': errors}


def _detect_wildcard_dns(domain: str, dns_timeout: float = SUBDOMAIN_DNS_TIMEOUT) -> bool:
    """检测 `*.example.com` 是否解析到 IP。命中 = wildcard DNS,所有结果可信度降低。
    随机 32 字符前缀 + 不在被动结果里 → 几乎不可能真有此子域,若解析成功必是 wildcard。"""
    if not HAS_DNS:
        return False
    import secrets
    probe_label = secrets.token_hex(16)  # 32 hex chars
    probe_host = f'{probe_label}.{domain}'
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = dns_timeout
        resolver.lifetime = dns_timeout
        resolver.resolve(probe_host, 'A')
        return True
    except Exception:
        return False


def _resolve_one_subdomain(host: str, dns_timeout: float = SUBDOMAIN_DNS_TIMEOUT) -> dict:
    """对单个 hostname 跑 A/AAAA/CNAME 三种查询,返回 dict.
    alive=True 当且仅当至少有一种记录命中。任何 DNS 异常归到 alive=False。
    v1.6.7:CNAME 跟踪完整 chain(防 CNAME → CNAME → A 多级链路只显示头一级)。
    """
    rec: dict = {'host': host, 'alive': False, 'a': [], 'aaaa': [], 'cname': None}
    if not HAS_DNS:
        return rec
    resolver = dns.resolver.Resolver()
    resolver.timeout = dns_timeout
    resolver.lifetime = dns_timeout
    for qtype, key in (('A', 'a'), ('AAAA', 'aaaa')):
        try:
            ans = resolver.resolve(host, qtype)
            rec[key] = sorted(str(r).rstrip('.') for r in ans)
            rec['alive'] = True
        except Exception:
            pass
    # v1.6.7:递归跟 CNAME chain(最多 5 级,防循环)
    # 例:www.x.com → cdn1.x.com → cdn-real.cloudflare.net
    # 输出格式:'cdn1.x.com → cdn-real.cloudflare.net'(箭头连接完整链路)
    try:
        chain: list[str] = []
        current = host
        seen: set[str] = set()  # 防 CNAME 循环
        for _ in range(5):  # 最多 5 跳
            if current.lower() in seen:
                break
            seen.add(current.lower())
            try:
                ans = resolver.resolve(current, 'CNAME')
            except Exception:
                break
            if not ans:
                break
            target = str(ans[0].target).rstrip('.')
            if not target or target.lower() == current.lower():
                break
            chain.append(target)
            current = target
        if chain:
            # 用 ' → ' 连接,首跳是从 host 出发,所以不要 host 自己
            rec['cname'] = ' → '.join(chain)
            rec['alive'] = True
    except Exception:
        pass
    return rec


def _probe_one_subdomain(host: str, timeout: float = SUBDOMAIN_HTTP_PROBE_TIMEOUT,
                         parent_domain: Optional[str] = None) -> dict:
    """对 alive 子域抓 HTTP status + <title>。先试 https,失败回退 http。
    复用 _get_session 连接池;stream 早停只读 16KB 提取 title。
    v1.4.9:若传 parent_domain,顺带从 body 提取 `*.parent_domain` 的 hostname 引用,
    返回 'extracted_hosts' 字段(主流程会再 DNS 验证找出新子域)。
    v1.4.11:connect_timeout 拆出 (默认 2s) — 死站快速失败,大幅提升整体速度。"""
    out: dict = {'http_status': None, 'title': None, 'scheme': None,
                 'extracted_hosts': set()}
    # v1.4.11:连接超时单独控制(2s),读取超时仍是 timeout(4s)
    # 死站:TCP RST 立刻或 2s 内超时 → 早失败 + 切 http 重试,总 ≤ 4s 而非 ≤ 8s
    connect_to = min(2.0, timeout)
    for scheme in ('https', 'http'):
        url = f'{scheme}://{host}/'
        resp = safe_get(url, timeout=timeout, connect_timeout=connect_to,
                        stream=True, allow_redirects=True)
        if resp is None:
            continue
        try:
            out['scheme'] = scheme
            out['http_status'] = resp.status_code
            # v1.6.7:所有状态码都提取 title — 用户反馈 Cloudflare 403 challenge
            # 页面 title="Just a moment..." 是有用情报(知道被 WAF 挡了),不是噪声。
            # 401/403/404/500 等的 title 同样有信息价值:
            #   "Just a moment..."        ← Cloudflare WAF
            #   "Attention Required!"     ← Cloudflare WAF
            #   "Welcome to nginx!"       ← 默认页(未配置)
            #   "Sign in"                 ← 401 但有登录页
            #   "Page not found"          ← 真 404
            try:
                chunks = []
                remaining = SUBDOMAIN_PROBE_MAX_BODY
                while remaining > 0:
                    chunk = resp.raw.read(remaining, decode_content=True)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                body = b''.join(chunks)
                m = _HTML_TITLE_RE.search(body)
                if m:
                    title_bytes = m.group(1).strip()
                    try:
                        out['title'] = title_bytes.decode('utf-8', errors='replace').strip()[:120]
                    except Exception:
                        pass
                # v1.4.9:从 body 抽 hostname 引用(几乎免费 — body 已经在内存里)
                # 仅对 2xx/3xx 抽,4xx/5xx 的 body 通常是 CF 错误页,无业务 host 引用
                if parent_domain and 200 <= resp.status_code < 400:
                    out['extracted_hosts'] = _extract_hosts_from_body(body, parent_domain)
            except (OSError, ValueError, requests.exceptions.RequestException):
                pass
            return out
        finally:
            resp.close()
    return out


def enumerate_subdomains(domain: str, *, probe: bool = True,
                        max_workers: int = SUBDOMAIN_DEFAULT_WORKERS,
                        dns_timeout: float = SUBDOMAIN_DNS_TIMEOUT,
                        probe_timeout: float = SUBDOMAIN_HTTP_PROBE_TIMEOUT,
                        bruteforce: bool = False,
                        js_extract: bool = True,
                        show_progress: bool = True) -> dict:
    """子域名枚举主入口。

    流程:
    1. _normalize_domain 校验输入(沿用 whois/mx 同套防御:拒 URL/路径穿越/控制字符)
    2. passive_collect_subdomains 并发跑 4 个被动源
    3. _detect_wildcard_dns 探测 wildcard
    4. ThreadPoolExecutor 并发 DNS 解析每个候选
    5. 若 probe=True,对 alive 子域并发跑 HTTP probe
    6. 截断到 SUBDOMAIN_MAX_RESULTS,按 host 字母序输出

    返回结构:
      {'domain': str,                   # 规范化后的 punycode/lowercase
       'sources': {name: int},          # 每源贡献候选数
       'wildcard_suspect': bool,        # wildcard DNS 检测结果
       'subdomains': [                  # 按 host 字母序
         {'host': str, 'alive': bool, 'a': [...], 'aaaa': [...], 'cname': str|None,
          'http_status': int|None, 'title': str|None, 'scheme': str|None},
         ...
       ],
       '_stats': {'total': int, 'alive': int, 'probed': int, 'errors': dict}
      }
      失败:{'_error': i18n_msg}
    """
    if not HAS_DNS:
        return {'_error': t('err.no_dns')}
    normalized = _normalize_domain(domain)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=(domain or '').strip()[:80])}
    domain = normalized

    # 1) 被动多源
    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('subdomain.stage_passive')}{Color.Reset}")
    passive = passive_collect_subdomains(domain, show_progress=show_progress)
    candidates = passive['candidates']

    # v1.4.9:DNS 字典爆破(opt-in)— 把字典 prefix 直接拼成 candidates,
    # 让 stage 3 的 DNS 解析自动验证,死的自然过滤掉。
    bruteforce_count = 0
    if bruteforce or os.environ.get('SPYEYES_BRUTEFORCE') == '1':
        bf_cands = _generate_bruteforce_candidates(domain)
        # 仅统计"新引入"的(已经在 passive 里的不算 bruteforce 贡献)
        new_bf = bf_cands - candidates
        bruteforce_count = len(new_bf)
        candidates = candidates | bf_cands
        if show_progress:
            _stage_log(f"   {Color.Bl}[{'bruteforce':>13}] {len(bf_cands):>4} candidates"
                       f" ({bruteforce_count} new){Color.Reset}")

    # 2) wildcard 探测(独立,失败不阻塞主流程)
    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('subdomain.stage_wildcard')}{Color.Reset}")
    wildcard = _detect_wildcard_dns(domain)
    if show_progress:
        if wildcard:
            _stage_log(f"   {Color.Re}{t('subdomain.wildcard_yes')}{Color.Reset}")
        else:
            _stage_log(f"   {Color.Gr}{t('subdomain.wildcard_no')}{Color.Reset}")

    # 3) DNS 解析 — 截断到 MAX 防巨型 wildcard 域(blogspot 等)拖垮
    if len(candidates) > SUBDOMAIN_MAX_RESULTS:
        candidates = set(sorted(candidates)[:SUBDOMAIN_MAX_RESULTS])

    if max_workers < 1:
        max_workers = 1
    resolved: list = []
    total = len(candidates)
    done = 0
    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('subdomain.stage_dns', n=total)}{Color.Reset}")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve_one_subdomain, h, dns_timeout): h for h in candidates}
        try:
            for fut in as_completed(futures):
                try:
                    rec = fut.result()
                except Exception:
                    rec = {'host': futures[fut], 'alive': False,
                           'a': [], 'aaaa': [], 'cname': None}
                resolved.append(rec)
                done += 1
                if show_progress:
                    _print_scan_progress(done, total,
                                         sum(1 for r in resolved if r.get('alive')))
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            if show_progress:
                _clear_progress_line()
            raise
    if show_progress:
        _clear_progress_line()

    # 4) HTTP probe(仅 alive,除非 wildcard 全标记不可信)
    probed = 0
    responsive = 0  # v1.4.11:HTTP 真返了状态码的(不是 None)— 用作进度条 found_count
    extracted_total: set[str] = set()
    # v1.4.11:HTTP probe 是 I/O bound,可用更高并发(80 vs DNS 的 30)
    http_workers = max(max_workers, SUBDOMAIN_HTTP_WORKERS)
    if probe:
        alive_recs = [r for r in resolved if r.get('alive')]
        if show_progress and alive_recs:
            _stage_log(f"\n {Color.Cy}{t('subdomain.stage_probe', n=len(alive_recs))}{Color.Reset}")
        # v1.4.9:js_extract=True 时把 parent_domain 传给 probe,从 body 抽硬编码 host
        probe_parent = domain if js_extract else None
        with ThreadPoolExecutor(max_workers=http_workers) as ex:
            futures = {ex.submit(_probe_one_subdomain, r['host'], probe_timeout,
                                 probe_parent): r
                       for r in alive_recs}
            try:
                for fut in as_completed(futures):
                    rec = futures[fut]
                    try:
                        result = fut.result()
                    except Exception:
                        rec['http_status'] = None
                        probed += 1
                        if show_progress:
                            _print_scan_progress(probed, len(alive_recs), responsive)
                        continue
                    extracted = result.pop('extracted_hosts', set()) or set()
                    rec.update(result)
                    if extracted:
                        extracted_total |= extracted
                    probed += 1
                    if rec.get('http_status') is not None:
                        responsive += 1
                    # v1.4.11:HTTP probe 实时进度(之前没有,baidu 1203 个时看着像卡了)
                    if show_progress:
                        _print_scan_progress(probed, len(alive_recs), responsive)
            except KeyboardInterrupt:
                ex.shutdown(wait=False, cancel_futures=True)
                if show_progress:
                    _clear_progress_line()
                raise
        if show_progress and alive_recs:
            _clear_progress_line()

    # v1.4.9:JS 提取的第二轮 — 对 body 中发现的"已知列表外"新 host 做 DNS+probe
    # 单轮即止(不递归),避免对话窗口里跑出爆炸式扩张。
    js_extracted_count = 0
    if probe and js_extract and extracted_total:
        known_hosts = {r['host'] for r in resolved}
        new_hosts = extracted_total - known_hosts
        # 截断到 MAX,避免恶意 / SPA 大页面引入几千个无关 host
        if len(new_hosts) > SUBDOMAIN_MAX_RESULTS:
            new_hosts = set(sorted(new_hosts)[:SUBDOMAIN_MAX_RESULTS])
        if new_hosts:
            if show_progress:
                _stage_log(f"\n {Color.Cy}{t('subdomain.stage_js_extract', n=len(new_hosts))}{Color.Reset}")
            extra_resolved: list = []
            extra_done = 0
            extra_alive_count = 0
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_resolve_one_subdomain, h, dns_timeout): h
                           for h in new_hosts}
                try:
                    for fut in as_completed(futures):
                        try:
                            rec = fut.result()
                        except Exception:
                            rec = {'host': futures[fut], 'alive': False,
                                   'a': [], 'aaaa': [], 'cname': None}
                        rec['source_hint'] = 'js_extract'
                        extra_resolved.append(rec)
                        extra_done += 1
                        if rec.get('alive'):
                            extra_alive_count += 1
                        # v1.4.11:JS 提取阶段 DNS 解析进度
                        if show_progress:
                            _print_scan_progress(extra_done, len(new_hosts), extra_alive_count)
                except KeyboardInterrupt:
                    ex.shutdown(wait=False, cancel_futures=True)
                    if show_progress:
                        _clear_progress_line()
                    raise
            if show_progress:
                _clear_progress_line()
            # 对 alive 的 extracted host 跑 probe(不再递归提取 — 单轮即止)
            extra_alive = [r for r in extra_resolved if r.get('alive')]
            if extra_alive:
                extra_probe_done = 0
                extra_responsive = 0
                with ThreadPoolExecutor(max_workers=http_workers) as ex:
                    futures = {ex.submit(_probe_one_subdomain, r['host'],
                                         probe_timeout, None): r
                               for r in extra_alive}
                    try:
                        for fut in as_completed(futures):
                            rec = futures[fut]
                            try:
                                result = fut.result()
                            except Exception:
                                rec['http_status'] = None
                                probed += 1
                                extra_probe_done += 1
                                if show_progress:
                                    _print_scan_progress(extra_probe_done, len(extra_alive), extra_responsive)
                                continue
                            result.pop('extracted_hosts', None)
                            rec.update(result)
                            probed += 1
                            extra_probe_done += 1
                            if rec.get('http_status') is not None:
                                extra_responsive += 1
                            if show_progress:
                                _print_scan_progress(extra_probe_done, len(extra_alive), extra_responsive)
                    except KeyboardInterrupt:
                        ex.shutdown(wait=False, cancel_futures=True)
                        if show_progress:
                            _clear_progress_line()
                        raise
                if show_progress:
                    _clear_progress_line()
            resolved.extend(extra_resolved)
            js_extracted_count = len(extra_resolved)

    # 默认填空(报告生成器不要做存在性检查)
    for r in resolved:
        r.setdefault('http_status', None)
        r.setdefault('title', None)
        r.setdefault('scheme', None)

    resolved.sort(key=lambda r: r.get('host', ''))
    alive_count = sum(1 for r in resolved if r.get('alive'))
    return {
        'domain': domain,
        'sources': passive['sources'],
        'wildcard_suspect': wildcard,
        'subdomains': resolved,
        '_stats': {
            'total': len(resolved),
            'alive': alive_count,
            'probed': probed,
            'bruteforce_added': bruteforce_count,
            'js_extracted': js_extracted_count,
            'errors': passive.get('errors', {}),
        },
    }


# ====================================================================
# v1.5.0: 子域名 Diff 模式 — 对比两次扫描,挖出新增/消失/状态变更
# ====================================================================
# 用例:OSINT 持续监控 — 周一跑一次保存 JSON,周五再跑一次,diff 出新冒出来的子域
# 输入:两份 enumerate_subdomains 的 JSON 输出
# 输出:{added: [...], removed: [...], changed: [{host, before, after, changes}], unchanged_count}

def _format_source_breakdown(data: dict) -> str:
    """v1.6.8:格式化所有源的状态字符串(报告 / 终端共用)。
    v1.6.9:emoji ✅⊘❌ → ✓○✗(PDF 中文字体不支持 emoji,会乱码;✓○✗ 在 STSong-Light
    及大多数 CJK 字体里都有,跨终端/HTML/PDF/Markdown 一致渲染)。

    用户反馈"为什么数据源数字一会 2 一会 3,看不到内部"。
    展示 ALL configured sources(包括返 0 的)+ 状态符号:
      ✓ N      源成功返 N 个 hosts
      ○ 0      源成功但返 0(API 限速 / 域无数据 / 没 key 等)
      ✗ 错误    源抛异常(连接失败 / 超时 / etc)

    输入:enumerate_subdomains() 输出 dict
    输出:`✓ certspotter: 21  ○ crtsh: 0  ○ otx: 0  ✗ wayback (错误)  ✓ subfinder: 20`
         (单行紧凑,保留空格分隔以便长行 wrap 不切坏)
    """
    sources = data.get('sources') or {}
    errors = (data.get('_stats') or {}).get('errors') or {}
    if not sources and not errors:
        return ''
    # 同时展示成功 + 错误的源(都按字母序)
    all_names = sorted(set(list(sources.keys()) + list(errors.keys())))
    parts = []
    for name in all_names:
        if errors.get(name):
            parts.append(f'✗ {name} (错误)')
        else:
            n = sources.get(name, 0)
            if n > 0:
                parts.append(f'✓ {name}: {n}')
            else:
                parts.append(f'○ {name}: 0')
    return '  '.join(parts)


def _filter_alive_only(data: dict) -> dict:
    """v1.6.5:智能 --alive-only 过滤,自动应对 wildcard DNS / DNS 劫持场景。

    背景:
    用户反馈在 wildcard DNS / 公司 WARP / VPN 劫持环境下,即使开了 --alive-only
    报告里仍然全是 fake host(都"解析"到劫持 IP 198.18.x.x)。

    根因:
    `alive` 字段只看 DNS 是否返 A/AAAA,不看 IP 真不真。劫持环境下任何字符串都"alive"。

    设计:
    - 正常情况(wildcard_suspect=False):alive = DNS 有 A/AAAA 记录
    - wildcard 命中:升级严格模式 — DNS + (HTTP 探测响应 OR 真实 CNAME)
      理由:劫持的 fake IP 不会响应 HTTP;真实 CNAME 是 wildcard 不会伪造的强证据

    返回原 dict 的浅拷贝(subdomains 替换 + 加 _filtered 元数据)。
    """
    if not isinstance(data, dict) or 'subdomains' not in data:
        return data
    subs = data.get('subdomains') or []
    if not isinstance(subs, list):
        return data
    wildcard = bool(data.get('wildcard_suspect'))
    if wildcard:
        # 严格:DNS 解析 + (HTTP 响应 OR 真实 CNAME)
        # http_status is not None 表示 probe 阶段拿到了响应(不一定 2xx,
        # 401/403 也算"真实站点"); CNAME 非空字符串表示 DNS 链路真实
        def _passes(s: dict) -> bool:
            if not isinstance(s, dict) or not s.get('alive'):
                return False
            has_http = s.get('http_status') is not None
            has_cname = bool(s.get('cname'))
            return has_http or has_cname
        filtered = [s for s in subs if _passes(s)]
        mode = 'alive_only_strict'
    else:
        filtered = [s for s in subs if isinstance(s, dict) and s.get('alive')]
        mode = 'alive_only'
    return {**data, 'subdomains': filtered,
            '_filtered': {'mode': mode,
                          'hidden': len(subs) - len(filtered),
                          'wildcard_suspect': wildcard}}


def diff_subdomain_results(old: dict, new: dict) -> dict:
    """对比两次子域扫描结果。返回 added/removed/changed 三组 + 元数据。

    added:   new 里有但 old 里没有的 host
    removed: old 里有但 new 里没有的 host
    changed: 两边都有,但 alive / a / aaaa / cname / http_status / title 有变化
    unchanged_count:  两边完全一致的 host 数

    每个 changed 条目含具体变化字段,便于报告生成器突出显示。
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return {'_error': 'invalid input — both must be enumerate_subdomains() output'}
    old_subs = old.get('subdomains') or []
    new_subs = new.get('subdomains') or []
    # 显式类型收窄(满足 mypy):host 必须是非空 str 才入 map
    old_map: dict[str, dict] = {}
    for s in old_subs:
        if isinstance(s, dict):
            h = s.get('host')
            if isinstance(h, str) and h:
                old_map[h] = s
    new_map: dict[str, dict] = {}
    for s in new_subs:
        if isinstance(s, dict):
            h = s.get('host')
            if isinstance(h, str) and h:
                new_map[h] = s

    added = sorted([new_map[h] for h in new_map if h not in old_map],
                   key=lambda r: r.get('host', ''))
    removed = sorted([old_map[h] for h in old_map if h not in new_map],
                     key=lambda r: r.get('host', ''))

    changed: list = []
    unchanged_count = 0
    # 对两边都有的 host,逐字段比较
    common_hosts = sorted(set(old_map) & set(new_map))
    tracked_fields = ('alive', 'a', 'aaaa', 'cname', 'http_status', 'title')
    for host in common_hosts:
        before = old_map[host]
        after = new_map[host]
        diffs: dict = {}
        for f in tracked_fields:
            b_val = before.get(f)
            a_val = after.get(f)
            # 列表比较前先归一化(顺序无关)
            if isinstance(b_val, list) and isinstance(a_val, list):
                if sorted(b_val) != sorted(a_val):
                    diffs[f] = {'before': b_val, 'after': a_val}
            elif b_val != a_val:
                diffs[f] = {'before': b_val, 'after': a_val}
        if diffs:
            changed.append({'host': host, 'changes': diffs,
                            'before': {f: before.get(f) for f in tracked_fields},
                            'after': {f: after.get(f) for f in tracked_fields}})
        else:
            unchanged_count += 1

    return {
        'domain': new.get('domain') or old.get('domain') or '',
        'added': added,
        'removed': removed,
        'changed': changed,
        '_stats': {
            'added': len(added),
            'removed': len(removed),
            'changed': len(changed),
            'unchanged': unchanged_count,
            'total_old': len(old_subs),
            'total_new': len(new_subs),
        },
    }


# ====================================================================
# v1.4.0: 域名邮箱枚举(多源 OSINT + 深度爬取 + 可选模式生成 + 可选 SMTP 验证)
# ====================================================================
# 设计哲学:"全 + 准" — 默认开所有被动源 + 深度爬取 + 含 alive 子域;高调动作 opt-in
# 数据源(默认全开):
#   1. crt.sh CT 日志的 SAN/email 字段
#   2. WHOIS 注册联系人 emails
#   3. 深度爬取主域(或主域 + alive 子域)
# 高级(opt-in):
#   4. 模式生成 `--guess "John Doe,Jane Smith"`(姓名 → firstname.lastname@domain 等)
#   5. SMTP HELO/RCPT 验证(`--verify-smtp`,带强 disclaimer)

DOMAIN_EMAIL_DEFAULT_MAX_PAGES = 200      # v1.6.11:500→200(用户反馈"卡 5 分钟")
                                          # 实践:典型企业域 contact/about/team 等高邮箱密度页 < 100 页
                                          # 更大 budget 长尾 page 邮箱密度急剧降到几乎 0,纯花时间
DOMAIN_EMAIL_PER_TARGET_CAP = 100         # v1.6.11:单个 target 最多 100 页(防 2 target 时各拿 100 共 200)
DOMAIN_EMAIL_DEFAULT_DEPTH = 5
DOMAIN_EMAIL_DEFAULT_WORKERS = 5
DOMAIN_EMAIL_RATE_LIMIT_MS = 500          # 单域请求间最少 500ms 防被反爬墙拉黑
DOMAIN_EMAIL_PAGE_TIMEOUT = 10.0
DOMAIN_EMAIL_MAX_BODY = 256 * 1024        # 单页只读前 256KB(防大页面拖慢)
DOMAIN_EMAIL_TOTAL_TIMEOUT = 300.0        # 总超时 5 分钟,防跑飞
DOMAIN_EMAIL_PROGRESS_EVERY = 20          # v1.6.11:每 20 页打一行进度(平衡信噪比)

# v1.6.11:并行多 target 爬虫时,各 target 写 stderr 进度需要互斥避免行交织
_DEMAIL_PROGRESS_LOCK = threading.Lock()
DOMAIN_EMAIL_PRIORITY_PATHS = (
    '/', '/contact', '/contact-us', '/about', '/about-us', '/team',
    '/imprint', '/legal', '/privacy', '/support', '/help', '/jobs',
    '/careers', '/press',
)

# 邮箱提取正则(比 EMAIL_RE 宽松,因为爬取场景可能含混杂上下文)
# (?<![a-zA-Z0-9._%+-]) lookbehind 防 "abc@gmail.com" 被截成 "bc@gmail.com"
_DOMAIN_EMAIL_EXTRACT_RE = re.compile(
    r'(?<![a-zA-Z0-9._%+-])'
    r'([a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63})'      # local part(首字符必须字母数字)
    r'@'
    r'([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)'       # domain
    r'(?![a-zA-Z0-9.-])',
)

# mailto: 链接专用正则
_MAILTO_RE = re.compile(r'mailto:\s*([^?\s"\'<>]+)', re.IGNORECASE)

# 内部链接提取(href / src)— 仅 http/https/相对路径
_HREF_RE = re.compile(r'''<a\s[^>]*href\s*=\s*["']([^"'#]+)["']''', re.IGNORECASE)

# 占位域名黑名单:仅用于过滤"用户没在查这些域,但爬出来碰巧含这些域邮箱"的场景
# 注意:仅当 target_domain 与黑名单**不重叠**时才生效 — 用户主动查 example.com 是合法的
_FAKE_DOMAINS = ('yourdomain.com', 'yoursite.com', 'domain.example')


def _is_email_relevant(email: str, target_domain: str) -> bool:
    """判断邮箱是否属于 target_domain 或其子域。
    target = example.com → 接受 *@example.com / *@*.example.com,拒绝 *@gmail.com。
    target = example.com → 接受 *@example.com / *@www.example.com / *@mail.example.com。"""
    email_l = email.lower().strip()
    if '@' not in email_l:
        return False
    local, _, edomain = email_l.rpartition('@')
    if not local or not edomain:
        return False
    target = target_domain.lower().strip().rstrip('.')
    # 必须等于 target 或其子域(endswith '.' + target);跨域自动拒
    if edomain == target or edomain.endswith('.' + target):
        # 仅当 target 不是占位符域时才过滤(用户主动查 yourdomain.com 是允许的)
        if target not in _FAKE_DOMAINS:
            for fake in _FAKE_DOMAINS:
                if edomain == fake or edomain.endswith('.' + fake):
                    return False
        return True
    return False


def _extract_emails_from_text(text: str, target_domain: str) -> set[str]:
    """从一段文本(HTML / 纯文本)提取 target_domain 的邮箱。
    优先匹配 mailto: + 通用 email regex,合并去重。"""
    if not text:
        return set()
    found: set[str] = set()
    # mailto: 链接(优先 + 高可信)
    for m in _MAILTO_RE.finditer(text):
        addr = m.group(1).strip().lower()
        if _is_email_relevant(addr, target_domain):
            found.add(addr)
    # 通用 email regex(扫描所有匹配)
    for m in _DOMAIN_EMAIL_EXTRACT_RE.finditer(text):
        local = m.group(1).strip().lower()
        edom = m.group(2).strip().lower()
        addr = f'{local}@{edom}'
        if _is_email_relevant(addr, target_domain):
            found.add(addr)
    return found


def _emails_from_crtsh(domain: str) -> set[str]:
    """crt.sh CT 日志的 entries 含 'name_value'(SAN)和 'common_name';有些证书把
    管理员邮箱放到 SAN 里(`email:admin@example.com`)。同时挖 'name_value' 字段
    所有 substring 匹配的邮箱(部分 CA 在 OU 字段写 contact email)。"""
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    # v1.4.3:OSINT 源首次连接握手可能很慢(crt.sh ~5s),不能让 connect 卡 3s
    resp = safe_get(url, timeout=SUBDOMAIN_SOURCE_TIMEOUT, connect_timeout=10.0)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, list):
        return set()
    found: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for key in ('name_value', 'common_name', 'issuer_name'):
            v = entry.get(key) or ''
            if isinstance(v, str):
                found |= _extract_emails_from_text(v, domain)
    return found


def _emails_from_whois(domain: str) -> set[str]:
    """从 WHOIS 注册联系人 emails 字段提取。复用现有 whois_lookup,容错 None 值。"""
    if not HAS_WHOIS:
        return set()
    result = whois_lookup(domain)
    if not isinstance(result, dict) or '_error' in result:
        return set()
    found: set[str] = set()
    val = result.get('emails')
    if isinstance(val, str):
        if _is_email_relevant(val, domain):
            found.add(val.lower().strip())
    elif isinstance(val, list):
        for e in val:
            if isinstance(e, str) and _is_email_relevant(e, domain):
                found.add(e.lower().strip())
    return found


def _emails_from_bing(domain: str) -> set[str]:
    """v1.6.0:Bing SERP dorking — 完全免费、无需 token。
    用 `\"@domain\" site:domain` 在搜索引擎结果页(SERP)抽邮箱。
    Bing 对自动化检测较 Google 宽松,User-Agent 伪装即可。

    限制:
    - Bing 偶发返 captcha → 静默返空(不阻塞主流程)
    - 单次最多 50 结果(2 页 × 25)
    - 加 ~500ms 延迟降低被 ban 概率
    """
    found: set[str] = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    # 两个查询模式分别拿不同邮箱(尽量不重复)
    import urllib.parse as _urlparse
    queries = [
        f'"@{domain}" site:{domain}',
        f'"@{domain}" -site:{domain}',  # 域外页面(博客/论坛)提到的
    ]
    for q in queries:
        for offset in (1, 11):  # 第 1-10 + 11-20 条结果
            url = (f'https://www.bing.com/search?q={_urlparse.quote(q)}'
                   f'&first={offset}&count=10&FORM=PERE')
            resp = safe_get(url, timeout=15.0, connect_timeout=5.0,
                            headers=headers)
            if resp is None or resp.status_code != 200:
                break  # captcha / rate limit → 跳过本 query 剩余页
            text = (resp.text or '')[:DOMAIN_EMAIL_MAX_BODY]
            new_found = _extract_emails_from_text(text, domain)
            if not new_found:
                break  # 结果页没新邮箱,后续页也大概率没,提早退出
            found |= new_found
            time.sleep(0.5)  # 礼貌延迟
    return found


def _emails_from_ddg(domain: str) -> set[str]:
    """v1.6.0:DuckDuckGo HTML SERP dorking — 完全免费、无 token、对自动化最友好。
    `html.duckduckgo.com/html/?q=...` 返回纯 HTML 无 JS,直接 regex 解析。"""
    found: set[str] = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    import urllib.parse as _urlparse
    queries = [
        f'"@{domain}"',
        f'"@{domain}" contact',
        f'"@{domain}" email',
    ]
    for q in queries:
        url = f'https://html.duckduckgo.com/html/?q={_urlparse.quote(q)}'
        resp = safe_get(url, timeout=15.0, connect_timeout=5.0,
                        headers=headers)
        if resp is None or resp.status_code != 200:
            continue
        text = (resp.text or '')[:DOMAIN_EMAIL_MAX_BODY]
        found |= _extract_emails_from_text(text, domain)
        time.sleep(0.4)
    return found


def _emails_from_wayback(domain: str) -> set[str]:
    """v1.6.0:Wayback Machine 历史归档 — 挖出已下线但归档的页面里的邮箱。
    流程:
    1. CDX API 拿历史归档过的 URL 列表(限 200 条)
    2. 对部分 URL 拉 Wayback 快照(`/web/<timestamp>id_/<url>`)
    3. 从快照 HTML 抽邮箱

    限制:
    - 只抓 50 个 URL(避免触发 wayback 限速)
    - 每页 8s 超时
    """
    cdx_url = (f'https://web.archive.org/cdx/search/cdx?url={domain}'
               f'&output=json&fl=timestamp,original&filter=mimetype:text/html'
               f'&filter=statuscode:200&collapse=urlkey&limit=200')
    resp = safe_get(cdx_url, timeout=30.0, connect_timeout=10.0)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, list) or len(data) < 2:
        return set()
    # 优先抓"看起来是 contact / about / team 页"的(高邮箱密度)
    candidates: list = []
    priority_kws = ('contact', 'about', 'team', 'imprint', 'support',
                     'help', 'press', 'people', 'staff')
    for row in data[1:]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        ts, orig = row[0], row[1]
        if not isinstance(orig, str):
            continue
        url_lower = orig.lower()
        priority = any(kw in url_lower for kw in priority_kws)
        candidates.append((priority, ts, orig))
    # 优先页放前面
    candidates.sort(key=lambda x: not x[0])
    candidates = candidates[:50]
    found: set[str] = set()
    for _, ts, orig in candidates:
        snap_url = f'https://web.archive.org/web/{ts}id_/{orig}'
        snap_resp = safe_get(snap_url, timeout=8.0, connect_timeout=4.0)
        if snap_resp is None or snap_resp.status_code != 200:
            continue
        body = (snap_resp.text or '')[:DOMAIN_EMAIL_MAX_BODY]
        found |= _extract_emails_from_text(body, domain)
        if len(found) >= 50:  # 邮箱够多就停
            break
    return found


def _emails_from_github(domain: str) -> set[str]:
    """v1.6.0:GitHub commit emails 挖掘 — 完全免费、无需 token(走未认证 API)。
    流程:
    1. 调 GitHub Search API 查 author-email 含 domain 的 commits
    2. 拿到 commit URL → 转 .patch 端点拿 author email
    3. regex 提邮箱

    限制:
    - 未认证 rate limit:10 req/min(GitHub Search API)
    - SpyEyes 未存 token → 严格按 rate limit 仅拿前 30 条结果
    - 用户可设 SPYEYES_GITHUB_TOKEN 环境变量提升到 30 req/min(可选)
    """
    found: set[str] = set()
    api_url = (f'https://api.github.com/search/commits?q=author-email:{domain}'
               f'&per_page=30&sort=committer-date&order=desc')
    headers = {
        # commits 搜索曾需 cloak-preview header,现已 stable 但兼容旧版仍接受
        'Accept': 'application/vnd.github.cloak-preview+json',
        'User-Agent': 'SpyEyes-OSINT/1.6.0',
    }
    # 可选:用户配置了 GITHUB token 时附上(rate limit 大幅提升)
    gh_token = (os.environ.get('SPYEYES_GITHUB_TOKEN') or '').strip()
    if gh_token:
        headers['Authorization'] = f'Bearer {gh_token}'
    resp = safe_get(api_url, timeout=20.0, connect_timeout=5.0, headers=headers)
    if resp is None or resp.status_code != 200:
        return set()
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return set()
    if not isinstance(data, dict):
        return set()
    items = data.get('items') or []
    if not isinstance(items, list):
        return set()
    for item in items[:30]:
        if not isinstance(item, dict):
            continue
        # commit author 的 email 直接在 commit.author.email 字段
        commit = item.get('commit') or {}
        if isinstance(commit, dict):
            author = commit.get('author') or {}
            if isinstance(author, dict):
                email = author.get('email')
                if isinstance(email, str) and _is_email_relevant(email, domain):
                    found.add(email.lower().strip())
            committer = commit.get('committer') or {}
            if isinstance(committer, dict):
                email = committer.get('email')
                if isinstance(email, str) and _is_email_relevant(email, domain):
                    found.add(email.lower().strip())
    return found


# v1.6.0:邮箱被动数据源映射表 — 与 SUBDOMAIN_SOURCES 同一设计哲学
# 全并发拉取,任何一源失败 silent 降级,不影响其他源
DOMAIN_EMAIL_SOURCES: dict = {
    'crtsh':   _emails_from_crtsh,
    'whois':   _emails_from_whois,
    'bing':    _emails_from_bing,
    'ddg':     _emails_from_ddg,
    'wayback': _emails_from_wayback,
    'github':  _emails_from_github,
}


def _fetch_robots_txt(scheme: str, host: str) -> tuple[set[str], list[str]]:
    """拉取 robots.txt,返回 (sitemap urls, disallow paths)。
    失败时返回空,不影响主流程。"""
    url = f'{scheme}://{host}/robots.txt'
    resp = safe_get(url, timeout=DOMAIN_EMAIL_PAGE_TIMEOUT)
    if resp is None or resp.status_code != 200:
        return set(), []
    text = (resp.text or '')[:DOMAIN_EMAIL_MAX_BODY]
    sitemaps: set[str] = set()
    disallows: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith('sitemap:'):
            sm = line[8:].strip()
            if sm:
                sitemaps.add(sm)
        elif line.lower().startswith('disallow:'):
            path = line[9:].strip()
            if path:
                disallows.append(path)
    return sitemaps, disallows


def _fetch_sitemap_urls(sitemap_url: str, target_domain: str,
                       max_urls: int = 2000) -> set[str]:
    """拉取 sitemap.xml 提取 <loc> 标签 URL。支持 sitemap index 嵌套(一层)。"""
    resp = safe_get(sitemap_url, timeout=DOMAIN_EMAIL_PAGE_TIMEOUT)
    if resp is None or resp.status_code != 200:
        return set()
    text = (resp.text or '')[:DOMAIN_EMAIL_MAX_BODY * 4]  # sitemap 通常较大
    urls: set[str] = set()
    nested: set[str] = set()
    # 简单 regex 提 <loc>(避免 xml 解析复杂度)
    loc_re = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.IGNORECASE)
    for m in loc_re.finditer(text):
        u = m.group(1).strip()
        if not u:
            continue
        if u.endswith('.xml'):
            nested.add(u)
        else:
            urls.add(u)
        if len(urls) >= max_urls:
            break
    # 处理一层嵌套 sitemap index
    for nu in list(nested)[:10]:  # 最多展开 10 个嵌套
        sub_resp = safe_get(nu, timeout=DOMAIN_EMAIL_PAGE_TIMEOUT)
        if sub_resp is None or sub_resp.status_code != 200:
            continue
        sub_text = (sub_resp.text or '')[:DOMAIN_EMAIL_MAX_BODY * 4]
        for m in loc_re.finditer(sub_text):
            u = m.group(1).strip()
            if u and not u.endswith('.xml'):
                urls.add(u)
                if len(urls) >= max_urls:
                    break
        if len(urls) >= max_urls:
            break
    # 仅保留属于 target_domain 的 URL
    target = target_domain.lower().rstrip('.')
    out = set()
    for u in urls:
        try:
            from urllib.parse import urlparse as _up
            host = _up(u).netloc.lower()
            if host == target or host.endswith('.' + target):
                out.add(u)
        except Exception:
            continue
    return out


def _is_path_disallowed(url: str, disallows: list[str]) -> bool:
    """判断 URL 是否被 robots.txt Disallow 命中(简单前缀匹配)。"""
    if not disallows:
        return False
    try:
        from urllib.parse import urlparse as _up
        path = _up(url).path or '/'
    except Exception:
        return False
    for d in disallows:
        if d == '/' or path.startswith(d):
            return True
    return False


def _crawl_domain_for_emails(domain: str, *,
                             max_pages: int = DOMAIN_EMAIL_DEFAULT_MAX_PAGES,
                             max_depth: int = DOMAIN_EMAIL_DEFAULT_DEPTH,
                             workers: int = DOMAIN_EMAIL_DEFAULT_WORKERS,
                             obey_robots: bool = True,
                             show_progress: bool = True) -> dict:
    """深度爬取 domain,返回 {emails: set, pages_crawled: int, sitemap_found: bool, ...}.

    起点:robots.txt + sitemap.xml + 主页 + DOMAIN_EMAIL_PRIORITY_PATHS。
    BFS 跟内部链接,深度限制,礼貌速率限制(单域 500ms 间隔)。"""
    target = domain.lower().rstrip('.')
    found_emails: set[str] = set()
    page_emails: dict = {}  # email → first 出现的 page url(用于 source 元数据)
    visited: set[str] = set()
    pages_crawled = 0

    # 1) robots.txt
    sitemaps, disallows = _fetch_robots_txt('https', target)
    if not sitemaps and not disallows:
        # 试 http(有些 site 没 https)
        sitemaps, disallows = _fetch_robots_txt('http', target)
    if not obey_robots:
        disallows = []

    # 2) sitemap.xml(显式来自 robots 的 + 默认路径)
    sitemap_urls: set[str] = set(sitemaps)
    sitemap_urls.add(f'https://{target}/sitemap.xml')
    sitemap_urls.add(f'https://{target}/sitemap_index.xml')
    seed_urls: set[str] = set()
    sitemap_found = False
    for sm in sitemap_urls:
        urls = _fetch_sitemap_urls(sm, target, max_urls=max_pages * 2)
        if urls:
            sitemap_found = True
            seed_urls |= urls
        if len(seed_urls) >= max_pages * 2:
            break

    # 3) 加优先路径作为补充种子
    for p in DOMAIN_EMAIL_PRIORITY_PATHS:
        seed_urls.add(f'https://{target}{p}')

    # 4) BFS 队列:(url, depth)
    queue: list[tuple[str, int]] = [(u, 0) for u in seed_urls]
    last_request_ts = 0.0

    def _fetch_page(url: str) -> Optional[str]:
        """拉取一页 HTML,返 text 或 None。每域 500ms 速率限制(简单 sleep,
        多 worker 共享同一速率窗口防被封)。"""
        nonlocal last_request_ts
        # 速率限制
        elapsed_ms = (time.time() - last_request_ts) * 1000
        if elapsed_ms < DOMAIN_EMAIL_RATE_LIMIT_MS:
            time.sleep((DOMAIN_EMAIL_RATE_LIMIT_MS - elapsed_ms) / 1000.0)
        last_request_ts = time.time()
        resp = safe_get(url, timeout=DOMAIN_EMAIL_PAGE_TIMEOUT, stream=True)
        if resp is None or resp.status_code != 200:
            return None
        try:
            ctype = (resp.headers.get('Content-Type') or '').lower()
            if 'html' not in ctype and 'text/' not in ctype and 'xml' not in ctype:
                return None
            chunks = []
            remaining = DOMAIN_EMAIL_MAX_BODY
            while remaining > 0:
                chunk = resp.raw.read(remaining, decode_content=True)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b''.join(chunks).decode('utf-8', errors='replace')
        except (OSError, ValueError, requests.exceptions.RequestException):
            return None
        finally:
            resp.close()

    started = time.time()
    # 简单串行 BFS(多 worker 互相速率限制反而难协调,单域抓取 500 ms*200 页=100s 可接受)
    while queue and pages_crawled < max_pages:
        if (time.time() - started) > DOMAIN_EMAIL_TOTAL_TIMEOUT:
            break
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        # robots.txt 拒绝
        if _is_path_disallowed(url, disallows):
            continue
        # 仅同主域(含子域)
        try:
            from urllib.parse import urlparse as _up, urljoin as _uj
            parsed = _up(url)
            if parsed.scheme not in ('http', 'https'):
                continue
            host = parsed.netloc.lower()
            if host != target and not host.endswith('.' + target):
                continue
        except Exception:
            continue
        body = _fetch_page(url)
        if body is None:
            continue
        pages_crawled += 1
        # 提取邮箱
        for email in _extract_emails_from_text(body, target):
            if email not in found_emails:
                found_emails.add(email)
                page_emails[email] = url
        # v1.6.11:进度反馈改用 \n + target 前缀(支持并行多 target 不交织)
        # 频率从每 10 → 20 页(降噪声),且不再用 \r(并行时 \r 会被其它 target 覆盖)
        if (show_progress and pages_crawled % DOMAIN_EMAIL_PROGRESS_EVERY == 0
                and sys.stderr.isatty()):
            with _DEMAIL_PROGRESS_LOCK:
                sys.stderr.write(
                    f"   [{target}] pages={pages_crawled}/{max_pages} "
                    f"emails={len(found_emails)} queue={len(queue)}\n"
                )
                sys.stderr.flush()
        # 深度未到则提取内部链接入队
        if depth < max_depth:
            for m in _HREF_RE.finditer(body):
                href = m.group(1).strip()
                if not href:
                    continue
                try:
                    abs_url = _uj(url, href)
                    abs_url = abs_url.split('#', 1)[0]
                    if abs_url and abs_url not in visited:
                        queue.append((abs_url, depth + 1))
                except Exception:
                    continue
    if show_progress and sys.stderr.isatty():
        sys.stderr.write('\r' + ' ' * 70 + '\r')
        sys.stderr.flush()
    return {
        'emails': found_emails,
        'page_map': page_emails,  # email → first page url
        'pages_crawled': pages_crawled,
        'sitemap_found': sitemap_found,
        'robots_disallows': len(disallows),
    }


# 模式生成:用户给的姓名 → 常见邮箱组合
_EMAIL_PATTERNS = (
    '{first}.{last}',
    '{f}.{last}',
    '{first}.{l}',
    '{first}{last}',
    '{f}{last}',
    '{first}_{last}',
    '{last}.{first}',
    '{first}',
    '{last}',
    '{f}{l}',
)


def _generate_email_patterns(names_csv: str, domain: str) -> list[str]:
    """从 'John Doe, Jane Smith' 生成模式邮箱。每个姓名生成 ~10 变体。
    输入用 [,;] 分隔多人,空白分隔 first/last。"""
    domain = domain.lower().strip()
    out: list[str] = []
    seen: set[str] = set()
    for entry in re.split(r'[,;]+', names_csv or ''):
        entry = entry.strip()
        if not entry:
            continue
        parts = re.split(r'\s+', entry)
        if not parts:
            continue
        first = re.sub(r'[^\w]', '', parts[0]).lower()
        last = re.sub(r'[^\w]', '', parts[-1]).lower() if len(parts) > 1 else ''
        if not first:
            continue
        f = first[0]
        last_initial = last[0] if last else ''
        for tpl in _EMAIL_PATTERNS:
            try:
                local = tpl.format(first=first, last=last, f=f, l=last_initial)
            except (KeyError, IndexError):
                continue
            local = local.strip('.').replace('..', '.')  # 干净化
            if not local:
                continue
            email = f'{local}@{domain}'
            if email not in seen:
                seen.add(email)
                out.append(email)
    return out


def _verify_smtp(email: str, *, helo_domain: str = 'spyeyes.osint',
                from_addr: str = 'verify@spyeyes.osint',
                timeout: float = 8.0) -> tuple[bool, str]:
    """SMTP HELO/MAIL/RCPT 验证邮箱是否存在。
    返回 (verified_bool, reason)。
    高调动作:走目标域 MX → SMTP 25 端口连接 → 提示用户负责合法性。"""
    if not HAS_DNS:
        return False, 'dns dependency missing'
    _, _, edom = email.rpartition('@')
    if not edom:
        return False, 'no domain part'
    try:
        # 拿 MX
        mx_ans = dns.resolver.resolve(edom, 'MX')
        mx_records = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in mx_ans])
        if not mx_records:
            return False, 'no MX records'
        # 试最高优先级 MX(preference 数字最小)
        target = mx_records[0][1]
    except Exception as e:
        return False, f'mx lookup failed: {e}'
    try:
        import smtplib
        with smtplib.SMTP(target, 25, timeout=timeout) as srv:
            srv.helo(helo_domain)
            srv.mail(from_addr)
            code, _ = srv.rcpt(email)
            # 250 = exists,550/551/553 = not exists,其它 = ambiguous
            if code in (250, 251):
                return True, f'rcpt accepted ({code})'
            if code in (550, 551, 553):
                return False, f'rcpt rejected ({code})'
            return False, f'rcpt ambiguous ({code})'
    except Exception as e:
        return False, f'smtp connect failed: {e}'


def enumerate_domain_emails(domain: str, *,
                           crawl: bool = True,
                           include_subdomains: bool = True,
                           max_pages: int = DOMAIN_EMAIL_DEFAULT_MAX_PAGES,
                           max_depth: int = DOMAIN_EMAIL_DEFAULT_DEPTH,
                           workers: int = DOMAIN_EMAIL_DEFAULT_WORKERS,
                           obey_robots: bool = True,
                           guess_names: Optional[str] = None,
                           verify_smtp: bool = False,
                           show_progress: bool = True) -> dict:
    """域名邮箱枚举主入口。
    - 阶段 1:crt.sh + WHOIS 拉被动数据
    - 阶段 2:深度爬取主域(可选 include_subdomains 复用 enumerate_subdomains 拿 alive 子域)
    - 阶段 3:[可选] 模式生成 — 需 guess_names 输入
    - 阶段 4:[可选] SMTP 验证 — verify_smtp=True

    返回结构:
      {'domain': str,
       'emails': [{'address': str, 'sources': [str], 'page': str|None,
                   'verified': None | True | False, 'verify_reason': str|None}, ...],
       '_stats': {'total': int, 'by_source': {...}, 'pages_crawled': int,
                  'sitemap_found': bool, 'verified': int, 'errors': dict}}
    """
    normalized = _normalize_domain(domain)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=(domain or '').strip()[:80])}
    domain = normalized

    # email → {sources: set, page: str|None}
    by_email: dict = {}

    def _add(email: str, source: str, page: Optional[str] = None) -> None:
        rec = by_email.setdefault(email.lower().strip(),
                                   {'sources': set(), 'page': None})
        rec['sources'].add(source)
        if page and not rec['page']:
            rec['page'] = page

    # 阶段 1:被动数据源 — v1.6.0:全 6 源并发(crt.sh/whois/bing/ddg/wayback/github)
    # 总耗时 ≈ 最慢源(通常 wayback 30s),而非顺序累加(老版 ~120s)
    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('demails.stage_passive')}{Color.Reset}")
    source_errors: dict = {}
    with ThreadPoolExecutor(max_workers=len(DOMAIN_EMAIL_SOURCES)) as ex:
        future_to_name = {ex.submit(fn, domain): name
                          for name, fn in DOMAIN_EMAIL_SOURCES.items()}
        for fut in as_completed(future_to_name):
            name = future_to_name[fut]
            try:
                emails = fut.result()
            except Exception as e:
                source_errors[name] = type(e).__name__
                if show_progress:
                    _stage_log(f"   {Color.Re}[{name:>8}] error: "
                               f"{type(e).__name__}{Color.Reset}")
                continue
            for em in emails:
                _add(em, name)
            if show_progress:
                color = Color.Gr if emails else Color.Bl
                _stage_log(f"   {color}[{name:>8}] {len(emails)} "
                           f"{t('demails.found_emails')}{Color.Reset}")

    # 阶段 2:深度爬取
    pages_crawled_total = 0
    sitemap_found_any = False
    if crawl:
        targets_to_crawl = [domain]
        if include_subdomains and HAS_DNS:
            if show_progress:
                _stage_log(f"\n {Color.Cy}{t('demails.stage_subdomain')}{Color.Reset}")
            # v1.6.6:probe=True 拿 HTTP 状态,后续过滤掉非 web 子域
            # (mail/pop/smtp/dns 这种 DNS 解析但没 HTTP 服务的,爬了也是空)
            # 之前 probe=False 时,linux.do 33 个子域全爬,大部分死站等超时,5+ 分钟
            sub_result = enumerate_subdomains(domain, probe=True,
                                              show_progress=show_progress)
            if isinstance(sub_result, dict) and 'subdomains' in sub_result:
                # v1.6.6:只取 HTTP 响应的(http_status not None = 真有 web 服务)
                # 4xx/5xx 也算(服务器在,只是要认证) — 过滤掉的是连不上的纯 DNS 主机
                http_alive = [s['host'] for s in sub_result['subdomains']
                              if s.get('alive') and s.get('http_status') is not None]
                # 排除主域自己,加 web-responsive 子域
                for h in http_alive:
                    if h != domain and h not in targets_to_crawl:
                        targets_to_crawl.append(h)
            if show_progress:
                _stage_log(f"   {Color.Gr}{len(targets_to_crawl)} "
                           f"{t('demails.target_count')}{Color.Reset}")

        if show_progress:
            _stage_log(f"\n {Color.Cy}{t('demails.stage_crawl', n=len(targets_to_crawl))}{Color.Reset}")
        # v1.6.11:per_target 加 PER_TARGET_CAP 上限(防 2 target 时各拿 250 共 500)
        # 之前 500 / 2 = 250 × 2 = 500 页 × 500ms 速率 = 4 分钟最低
        # 现在 min(100, 200/2) = 100 × 2 = 200 页 × 500ms = 100 秒,体感快很多
        per_target = max(10, min(DOMAIN_EMAIL_PER_TARGET_CAP,
                                  max_pages // max(1, len(targets_to_crawl))))
        total_targets = len(targets_to_crawl)

        # v1.6.6:多 target 并行爬(workers=3,平衡速度 vs 礼貌)
        # v1.6.11:并行时仍保留进度反馈(用 [target] 前缀防交织,不再 silent)
        TARGET_PARALLEL_WORKERS = 3
        crawl_results: dict = {}

        def _crawl_one(target):
            # v1.6.11:show_progress 透传 — 内部用 [target] 前缀的非 \r 行,
            # 多线程交织也不会乱(加上 _stderr_lock 保护原子写)
            return target, _crawl_domain_for_emails(
                target, max_pages=per_target, max_depth=max_depth,
                workers=workers, obey_robots=obey_robots,
                show_progress=show_progress)

        with ThreadPoolExecutor(max_workers=min(TARGET_PARALLEL_WORKERS, total_targets)) as ex:
            futures = {ex.submit(_crawl_one, tgt): (idx + 1, tgt)
                       for idx, tgt in enumerate(targets_to_crawl)}
            done_count = 0
            try:
                for fut in as_completed(futures):
                    idx, tgt = futures[fut]
                    done_count += 1
                    try:
                        _, crawl_result = fut.result()
                    except Exception as e:
                        if show_progress:
                            _stage_log(f"   {Color.Re}[{tgt}] error: {type(e).__name__}{Color.Reset}")
                        continue
                    crawl_results[tgt] = crawl_result
                    for em in crawl_result.get('emails', set()):
                        _add(em, 'crawl', crawl_result.get('page_map', {}).get(em))
                    pages_crawled_total += crawl_result.get('pages_crawled', 0)
                    sitemap_found_any = sitemap_found_any or crawl_result.get('sitemap_found', False)
                    if show_progress:
                        n_pages = crawl_result.get('pages_crawled', 0)
                        n_emails = len(crawl_result.get('emails', set()))
                        # 颜色:有结果 = 绿,空目标 = 蓝(信息性,不是错误)
                        color = Color.Gr if n_emails else Color.Bl
                        _stage_log(f"   {color}[{done_count}/{total_targets}] "
                                   f"{tgt}  pages={n_pages} emails={n_emails}{Color.Reset}")
            except KeyboardInterrupt:
                ex.shutdown(wait=False, cancel_futures=True)
                raise

    # 阶段 3:模式生成(opt-in)
    if guess_names:
        if show_progress:
            _stage_log(f"\n {Color.Cy}{t('demails.stage_guess')}{Color.Reset}")
        for em in _generate_email_patterns(guess_names, domain):
            _add(em, 'pattern')
        n_pat = sum(1 for v in by_email.values() if 'pattern' in v['sources'])
        if show_progress:
            _stage_log(f"   {Color.Gr}{n_pat} {t('demails.pattern_emails')}{Color.Reset}")

    # 阶段 4:SMTP 验证(opt-in)
    verified_count = 0
    if verify_smtp and by_email:
        if show_progress:
            _stage_log(f"\n {Color.Cy}{t('demails.stage_smtp', n=len(by_email))}{Color.Reset}")
            _stage_log(f"   {Color.Re}⚠ {t('demails.smtp_warn')}{Color.Reset}")
        for em, rec in list(by_email.items()):
            ok, reason = _verify_smtp(em)
            rec['verified'] = ok
            rec['verify_reason'] = reason
            if ok:
                verified_count += 1
            if show_progress and sys.stderr.isatty():
                sys.stderr.write(
                    f"\r   [smtp] {em[:40]:40} → "
                    f"{'✓' if ok else '✗'} {reason[:40]}     "
                )
                sys.stderr.flush()
        if show_progress and sys.stderr.isatty():
            sys.stderr.write('\r' + ' ' * 100 + '\r')
            sys.stderr.flush()

    # 整理输出:list of dict 按字母序
    emails_list = []
    for em in sorted(by_email.keys()):
        rec = by_email[em]
        emails_list.append({
            'address': em,
            'sources': sorted(rec['sources']),
            'page': rec.get('page'),
            'verified': rec.get('verified'),       # None / True / False
            'verify_reason': rec.get('verify_reason'),
        })

    # 按 source 统计
    by_source: dict = {}
    for em in emails_list:
        for s in em['sources']:
            by_source[s] = by_source.get(s, 0) + 1

    return {
        'domain': domain,
        'emails': emails_list,
        '_stats': {
            'total': len(emails_list),
            'by_source': by_source,
            'pages_crawled': pages_crawled_total,
            'sitemap_found': sitemap_found_any,
            'verified': verified_count,
        },
    }


# ====================================================================
# v1.7.0: INVESTIGATE — 综合调查（一次输入域名,自动 fan-out + 单向接力,出综合报告）
# ====================================================================
# 设计:
#   1. 入口:do_investigate(target, ...) -> dict.MVP 仅支持 domain 实体
#   2. 阶段 1 并发:whois + mx + subdomain + domain-emails(4 个原子任务)
#   3. 阶段 2 单向 pivot(depth>=1):
#        subdomain.alive[*].a → track_ip(每 IP)         # 单向叶子,不回根
#        emails[*].address → track_username(local-part) # 单向叶子,不回根
#      物理上无环:user/ip 都不再反查域名 — 不可能出现"死循环"
#   4. 硬上限:
#        - budget (总时间硬超时;default 300s,深度 0 时只跑阶段 1)
#        - max_pivot_ips (默认 20 个 IP)
#        - max_pivot_emails (默认 15 个邮箱,且按"看着像真人名"评分排序优先)
#        - role-account 邮箱(noreply/info/...)自动跳过
#   5. 错误隔离:任何单任务失败只在自己槽位记 _error,其它任务照常进行

INVESTIGATE_DEFAULT_BUDGET = 300.0          # 5 分钟硬超时(深度 1 时)
INVESTIGATE_MAX_PIVOT_IPS = 20              # 子域接 IP 最多查 20 个 unique IP
INVESTIGATE_MAX_PIVOT_EMAILS = 15           # 邮箱接 user 最多 15 个邮箱
INVESTIGATE_MIN_PIVOT_EMAIL_LEN = 3         # local-part 长度门槛(防 a@x.com)
INVESTIGATE_EMAILS_MAX_PAGES = 80           # 综合调查默认轻量爬取(对比 domain-emails 默认 200)
INVESTIGATE_IP_PIVOT_WORKERS = 20           # v1.8.0:10 → 20,track_ip 单 HTTP 调用,可激进
INVESTIGATE_USER_PIVOT_OUTER_WORKERS = 4    # v1.8.0:Phase 2b 并行邮箱数(配合 INNER_WORKERS 控制总线程)
INVESTIGATE_USER_PIVOT_INNER_WORKERS = 50   # v1.8.0:每邮箱内部 worker 数(50×4=200 持平单 user 150)

# 邮箱本地部分 role-account 黑名单 → 自动跳过 user pivot
_EMAIL_NONPERSONAL_PREFIXES = frozenset({
    'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'info',
    'admin', 'administrator', 'support', 'help', 'contact', 'hello',
    'sales', 'marketing', 'press', 'jobs', 'careers', 'team',
    'webmaster', 'postmaster', 'hostmaster', 'mailer-daemon', 'mailer',
    'abuse', 'security', 'privacy', 'legal', 'compliance', 'office',
    'billing', 'accounts', 'service', 'feedback', 'news', 'newsletter',
    'updates', 'notifications', 'notify', 'noticias', 'root',
})


def _personal_email_score(local: str) -> int:
    """评 email local-part 像真人名的程度(0..3,越高越像).
       0 = 明确 role-account(noreply/info/...) → user pivot 跳过
       1 = role-account 变体(noreply-john / info_xx) → 不推荐 pivot
       2 = 看起来像 username(纯字母 / 字母+数字)
       3 = 多段名字风格(john.doe / first_last)→ 真人概率高
    """
    lp = (local or '').lower().split('+')[0]  # 去掉 +tag
    if not lp:
        return 0
    if lp in _EMAIL_NONPERSONAL_PREFIXES:
        return 0
    # role-account 前缀变体: noreply-x / noreply.x / noreply_x
    for role in _EMAIL_NONPERSONAL_PREFIXES:
        if lp.startswith(role + '-') or lp.startswith(role + '.') or lp.startswith(role + '_'):
            return 1
    # 多段分隔(john.doe / first_last)→ 真名概率
    if any(sep in lp for sep in '._-'):
        parts = re.split(r'[._-]+', lp)
        if all(p and p not in _EMAIL_NONPERSONAL_PREFIXES for p in parts):
            return 3
    if lp.isdigit():
        return 0
    if len(lp) >= 4:
        return 2
    return 1


def _detect_entity_type(target: str) -> str:
    """v1.7.0:实体侦测,返回 'domain' / 'email' / 'ip' / 'username' / 'unknown'.
    MVP 只 'domain' 走完整 investigate 流程,其余 v2 实现。"""
    s = (target or '').strip()
    if not s:
        return 'unknown'
    try:
        ipaddress.ip_address(s)
        return 'ip'
    except ValueError:
        pass
    if '@' in s and EMAIL_RE.match(s):
        return 'email'
    if '.' in s and _normalize_domain(s) is not None:
        return 'domain'
    if not _is_invalid_username(s):
        return 'username'
    return 'unknown'


def _build_investigate_graph(target: str, tasks: dict, pivots: dict) -> dict:
    """v1.7.0:把任务/接力结果折成图(nodes + edges),给 HTML 报告用.
    单向 DAG — domain 是根,其它节点都是叶子(无回边)。"""
    nodes: list = [{'id': target, 'type': 'domain', 'label': target}]
    edges: list = []
    seen_ids: set = {target}

    def _add_node(nid: str, ntype: str, label: Optional[str] = None) -> None:
        if nid in seen_ids:
            return
        seen_ids.add(nid)
        nodes.append({'id': nid, 'type': ntype, 'label': label or nid})

    def _add_edge(src: str, dst: str, kind: str) -> None:
        edges.append({'src': src, 'dst': dst, 'kind': kind})

    # WHOIS 注册邮箱
    w = tasks.get('whois') or {}
    if isinstance(w, dict) and '_error' not in w:
        wem = w.get('emails')
        if isinstance(wem, str):
            wem = [wem]
        for em in (wem or []):
            if isinstance(em, str) and em:
                _add_node(em, 'email')
                _add_edge(target, em, 'whois_email')

    # MX 服务器
    mx_d = tasks.get('mx') or {}
    if isinstance(mx_d, dict) and '_error' not in mx_d:
        for r in (mx_d.get('records') or []):
            ex = r.get('exchange') if isinstance(r, dict) else None
            if ex:
                _add_node(ex, 'mx', label=ex)
                _add_edge(target, ex, 'mx_record')

    # 子域名(只画 alive)
    sub_d = tasks.get('subdomain') or {}
    sub_list = sub_d.get('subdomains') if isinstance(sub_d, dict) else None
    for s in (sub_list or []):
        if isinstance(s, dict) and s.get('alive'):
            host = s.get('host', '')
            if host and host != target:
                _add_node(host, 'subdomain', label=host)
                _add_edge(target, host, 'subdomain')

    # 域名邮箱
    em_d = tasks.get('emails') or {}
    if isinstance(em_d, dict) and '_error' not in em_d:
        for e in (em_d.get('emails') or []):
            addr = e.get('address') if isinstance(e, dict) else None
            if addr:
                _add_node(addr, 'email', label=addr)
                _add_edge(target, addr, 'email')

    # Pivot IP — 用 subdomain.a 反查 host
    for ip in (pivots.get('ips') or {}).keys():
        _add_node(ip, 'ip', label=ip)
        for s in (sub_list or []):
            if isinstance(s, dict) and ip in (s.get('a') or []):
                _add_edge(s.get('host', ''), ip, 'resolves_to')

    # Pivot user 命中
    for addr, ud in (pivots.get('users') or {}).items():
        if not isinstance(ud, dict):
            continue
        result = ud.get('result')
        local = ud.get('local_part', '')
        if not isinstance(result, dict):
            continue
        for plat_name, url in result.items():
            if plat_name.startswith('_') or not url:
                continue
            plat_id = f'platform:{plat_name}:{addr}'
            _add_node(plat_id, 'platform', label=f'{plat_name} / {local}')
            _add_edge(addr, plat_id, 'username_hit')

    return {'nodes': nodes, 'edges': edges}


def do_investigate(target: str, *,
                   depth: int = 1,
                   budget: float = INVESTIGATE_DEFAULT_BUDGET,
                   max_pivot_ips: int = INVESTIGATE_MAX_PIVOT_IPS,
                   max_pivot_emails: int = INVESTIGATE_MAX_PIVOT_EMAILS,
                   quick: bool = True,
                   probe: bool = True,
                   show_progress: bool = True) -> dict:
    """v1.7.0:综合调查 — domain 输入,自动 fan-out + 单向 pivot,出整合 dict.

    MVP 仅支持 domain 实体;其余实体类型返回 _error('only_domain').

    pivot 设计是单向 DAG(domain 是根,user/ip/mx/email 都是叶子),物理上不可能死循环。
    explosion 防御靠 cap:子域 → 最多 max_pivot_ips 个 IP;邮箱 → 按真人评分排前
    max_pivot_emails 个,role-account(noreply/info/...)自动跳过。
    """
    raw = (target or '').strip()
    if not raw:
        return {'_error': t('err.empty_input'), 'target': raw, 'entity_type': 'unknown'}

    entity = _detect_entity_type(raw)
    if entity != 'domain':
        return {'_error': t('err.investigate_only_domain'),
                'target': raw, 'entity_type': entity}

    normalized = _normalize_domain(raw)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=raw[:80]),
                'target': raw, 'entity_type': entity}
    domain = normalized

    started_at = time.time()
    deadline = (started_at + budget) if budget and budget > 0 else float('inf')

    def _remaining() -> float:
        return max(0.0, deadline - time.time())

    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('investigate.stage_start', target=domain)}{Color.Reset}")
        _stage_log(f" {Color.Wh}{t('investigate.stage_atomic')}{Color.Reset}")

    # 阶段 1:4 个原子任务并发(每个 task 内部已有自己的超时/异常处理)
    # 注意:emails 任务用 include_subdomains=False — 否则会再跑一遍 subdomain
    # 枚举(重复 + 慢 2x).综合调查里 subdomain 独立任务已经覆盖子域视图.
    def _task_whois() -> dict:
        return whois_lookup(domain)

    def _task_mx() -> dict:
        return mx_lookup(domain)

    def _task_subdomain() -> dict:
        return enumerate_subdomains(domain, probe=probe, show_progress=False)

    def _task_emails() -> dict:
        return enumerate_domain_emails(
            domain,
            crawl=True,
            include_subdomains=False,
            max_pages=INVESTIGATE_EMAILS_MAX_PAGES,
            show_progress=False,
        )

    tasks_result: dict = {'whois': None, 'mx': None, 'subdomain': None, 'emails': None}
    fn_map = {
        'whois': _task_whois, 'mx': _task_mx,
        'subdomain': _task_subdomain, 'emails': _task_emails,
    }
    tasks_failed = 0
    phase1_start = time.time()
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in fn_map.items()}
        try:
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    tasks_result[name] = fut.result()
                except Exception as e:
                    tasks_result[name] = {'_error': str(e)}
                if isinstance(tasks_result[name], dict) and '_error' in tasks_result[name]:
                    tasks_failed += 1
                if show_progress:
                    ok = isinstance(tasks_result[name], dict) and '_error' not in tasks_result[name]
                    sym = '✓' if ok else '✗'
                    color = Color.Gr if ok else Color.Re
                    phase1_elapsed = int(time.time() - phase1_start)
                    _stage_log(f"   {color}{t('investigate.task_done', elapsed=phase1_elapsed, sym=sym, name=name)}{Color.Reset}")
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            raise

    # 阶段 2:单向 pivot(depth>=1 且仍有 budget)
    pivots: dict = {'ips': {}, 'users': {}}
    truncated = {'ips': 0, 'emails': 0}
    pivots_done = 0
    pivots_skipped = 0

    if depth >= 1 and _remaining() > 0:
        # Pivot 1:alive subdomain → IP enrichment(country/ASN/org)
        sub_data = tasks_result.get('subdomain') or {}
        if isinstance(sub_data, dict) and 'subdomains' in sub_data:
            all_alive_ips: set = set()
            for s in sub_data.get('subdomains', []) or []:
                if isinstance(s, dict) and s.get('alive'):
                    for ip in (s.get('a') or []):
                        if ip:
                            all_alive_ips.add(ip)
            unique_ips = sorted(all_alive_ips)[:max_pivot_ips]
            truncated['ips'] = max(0, len(all_alive_ips) - len(unique_ips))

            if unique_ips:
                if show_progress:
                    _stage_log(f"\n {Color.Wh}{t('investigate.stage_ip_pivot', n=len(unique_ips))}{Color.Reset}")
                ip_total = len(unique_ips)
                ip_completed = 0
                with ThreadPoolExecutor(
                    max_workers=min(INVESTIGATE_IP_PIVOT_WORKERS, ip_total),
                ) as ex:
                    fut_to_ip = {ex.submit(track_ip, ip): ip for ip in unique_ips}
                    try:
                        for fut in as_completed(fut_to_ip):
                            ip = fut_to_ip[fut]
                            try:
                                pivots['ips'][ip] = fut.result()
                            except Exception as e:
                                pivots['ips'][ip] = {'_error': str(e)}
                                pivots_skipped += 1
                                ip_completed += 1
                                if show_progress:
                                    _stage_log(f"   {Color.Re}{t('investigate.ip_pivot_done', n=ip_completed, total=ip_total, sym='✗', ip=ip, summary='')}{Color.Reset}")
                                continue
                            ip_completed += 1
                            if isinstance(pivots['ips'][ip], dict) and '_error' in pivots['ips'][ip]:
                                pivots_skipped += 1
                                if show_progress:
                                    _stage_log(f"   {Color.Re}{t('investigate.ip_pivot_done', n=ip_completed, total=ip_total, sym='✗', ip=ip, summary='')}{Color.Reset}")
                            else:
                                pivots_done += 1
                                if show_progress:
                                    geo = pivots['ips'][ip] or {}
                                    cc = geo.get('country_code') or geo.get('country') or ''
                                    asn = (geo.get('connection') or {}).get('org', '') if isinstance(geo.get('connection'), dict) else ''
                                    summary = f' → {cc} {asn}'.rstrip() if (cc or asn) else ''
                                    _stage_log(f"   {Color.Gr}{t('investigate.ip_pivot_done', n=ip_completed, total=ip_total, sym='✓', ip=ip, summary=summary)}{Color.Reset}")
                            if _remaining() <= 0:
                                ex.shutdown(wait=False, cancel_futures=True)
                                if show_progress:
                                    _stage_log(f"   {Color.Ye}{t('investigate.budget_warn')}{Color.Reset}")
                                break
                    except KeyboardInterrupt:
                        ex.shutdown(wait=False, cancel_futures=True)
                        raise

        # Pivot 2:emails → username 扫描(local-part)
        email_data = tasks_result.get('emails') or {}
        if isinstance(email_data, dict) and '_error' not in email_data and _remaining() > 0:
            scored: list = []
            for em_rec in (email_data.get('emails') or []):
                addr = (em_rec.get('address') if isinstance(em_rec, dict) else '') or ''
                if '@' not in addr:
                    continue
                local = addr.split('@', 1)[0]
                if len(local) < INVESTIGATE_MIN_PIVOT_EMAIL_LEN:
                    continue
                if _is_invalid_username(local):
                    continue
                score = _personal_email_score(local)
                if score == 0:  # role-account → 跳过
                    continue
                scored.append((score, len(local), addr, local))
            # 高分先,短的先(更可能匹配平台 username 约束)
            scored.sort(key=lambda r: (-r[0], r[1]))
            picks = scored[:max_pivot_emails]
            truncated['emails'] = max(0, len(scored) - len(picks))

            if picks:
                outer = min(INVESTIGATE_USER_PIVOT_OUTER_WORKERS, len(picks))
                if show_progress:
                    _stage_log(f"\n {Color.Wh}{t('investigate.stage_user_pivot', n=len(picks), workers=outer)}{Color.Reset}")
                # v1.8.0:从串行改并行 — outer 4 邮箱 × inner 50 worker = 200 总线程
                # (持平单 user 默认 150,单平台 burst 风险≈不变 因为 4 outer 同时打同一平台
                # 概率极低:每个 outer 同一时刻只有 1/1700 概率打 GitHub)
                # quick 模式跳过 other 长尾(3164 → ~1750 平台)
                cats = [c for c in CATEGORY_ORDER if c != 'other'] if quick else None

                def _scan_one_email(payload: tuple) -> tuple:
                    """子线程:跑 track_username,返回 (addr, local, result_or_error_dict)。"""
                    addr_, local_ = payload
                    if _remaining() <= 0:
                        return addr_, local_, {'_error': 'budget_exceeded'}
                    try:
                        r = track_username(local_,
                                           max_workers=INVESTIGATE_USER_PIVOT_INNER_WORKERS,
                                           timeout=3.0, categories=cats,
                                           show_progress=False)
                        return addr_, local_, {'result': r}
                    except Exception as exc:
                        return addr_, local_, {'_error': str(exc)}

                user_completed = 0
                user_total = len(picks)
                with ThreadPoolExecutor(max_workers=outer) as ex_users:
                    fut_to_pick = {
                        ex_users.submit(_scan_one_email, (addr, local)): (addr, local)
                        for _, _, addr, local in picks
                    }
                    try:
                        for efut in as_completed(fut_to_pick):
                            addr, local = fut_to_pick[efut]
                            try:
                                _addr, _local, payload = efut.result()
                            except Exception as exc:  # 应该不会到这里(_scan_one_email 已捕获)
                                payload = {'_error': str(exc)}
                            user_completed += 1
                            if '_error' in payload:
                                pivots['users'][addr] = {'local_part': local, '_error': payload['_error']}
                                pivots_skipped += 1
                                if show_progress:
                                    _stage_log(f"   {Color.Re}{t('investigate.user_pivot_done', n=user_completed, total=user_total, sym='✗', local=local, summary='')}{Color.Reset}")
                            else:
                                r = payload['result']
                                pivots['users'][addr] = {'local_part': local, 'result': r}
                                pivots_done += 1
                                if show_progress:
                                    # 计 hit 数:dict 里非 None 且非以 _ 开头的 key 个数
                                    hits = sum(1 for k, v in (r or {}).items()
                                               if v is not None and not k.startswith('_'))
                                    summary = f' → {hits} hit{"s" if hits != 1 else ""}' if hits else ''
                                    _stage_log(f"   {Color.Gr}{t('investigate.user_pivot_done', n=user_completed, total=user_total, sym='✓', local=local, summary=summary)}{Color.Reset}")
                            if _remaining() <= 0:
                                ex_users.shutdown(wait=False, cancel_futures=True)
                                if show_progress:
                                    _stage_log(f"   {Color.Ye}{t('investigate.budget_warn')}{Color.Reset}")
                                break
                    except KeyboardInterrupt:
                        ex_users.shutdown(wait=False, cancel_futures=True)
                        raise

    elapsed = time.time() - started_at
    budget_exceeded = bool(budget) and budget > 0 and _remaining() <= 0
    graph = _build_investigate_graph(domain, tasks_result, pivots)

    if show_progress:
        _stage_log(f"\n {Color.Cy}{t('investigate.elapsed_total', elapsed=int(elapsed))}{Color.Reset}")

    return {
        'entity_type': 'domain',
        'target': domain,
        'depth': depth,
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(started_at)),
        'finished_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed': round(elapsed, 2),
        'tasks': tasks_result,
        'pivots': pivots,
        'graph': graph,
        '_stats': {
            'tasks_done': sum(1 for v in tasks_result.values()
                              if isinstance(v, dict) and '_error' not in v),
            'tasks_failed': tasks_failed,
            'pivots_done': pivots_done,
            'pivots_skipped': pivots_skipped,
            'truncated': truncated,
            'budget_exceeded': budget_exceeded,
        },
    }


# ====================================================================
# 输出格式化
# ====================================================================
def _print_section_header(section_key: str, *, equals: int = 10) -> None:
    """打印 `========== Section ==========` 标题。多处 print_* 函数共用。"""
    bar = '=' * equals
    print(f"\n {Color.Wh}{bar} {Color.Gr}{t(section_key)} {Color.Wh}{bar}")


def _emit_json(data: Any) -> None:
    """统一 JSON 输出（中文不转义、缩进 2、datetime 等回退 str）。
    所有 CLI 子命令 --json 走这里。"""
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def print_banner() -> None:
    sys.stderr.write(f"""{Color.Gr}
███████╗██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
███████╗██████╔╝ ╚████╔╝ █████╗   ╚████╔╝ █████╗  ███████╗
╚════██║██╔═══╝   ╚██╔╝  ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
███████║██║        ██║   ███████╗   ██║   ███████╗███████║
╚══════╝╚═╝        ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚══════╝
       {Color.Wh}👁  All-in-One OSINT Toolkit  ·  github.com/Akxan/SpyEyes  👁{Color.Reset}
""")


def print_ip_info(ip: str, data: dict) -> None:
    _print_section_header('section.ip', equals=13)
    print()
    if '_error' in data:
        print(f" {Color.Re}{t('err.query_failed', msg=data['_error'])}{Color.Reset}")
        return
    print_field(t('field.target_ip'),    ip)
    print_field(t('field.ip_type'),      data.get('type'))
    print_field(t('field.country'),      localized_country(data.get('country_code'), data.get('country', '')))
    print_field(t('field.country_code'), data.get('country_code'))
    print_field(t('field.city'),         data.get('city'))
    print_field(t('field.continent'),    data.get('continent'))
    print_field(t('field.region'),       data.get('region'))
    print_field(t('field.latitude'),     data.get('latitude'))
    print_field(t('field.longitude'),    data.get('longitude'))
    try:
        lat = float(data['latitude'])
        lon = float(data['longitude'])
        print_field(t('field.maps'), f"https://www.google.com/maps/@{lat},{lon},8z")
    except (KeyError, TypeError, ValueError):
        pass
    print_field(t('field.is_eu'),         data.get('is_eu'))
    print_field(t('field.postal'),        data.get('postal'))
    print_field(t('field.calling_code'),  data.get('calling_code'))
    print_field(t('field.capital'),       data.get('capital'))
    flag = data.get('flag') or {}
    print_field(t('field.flag'),          flag.get('emoji', ''))
    conn = data.get('connection') or {}
    print_field(t('field.asn'),           conn.get('asn'))
    print_field(t('field.org'),           conn.get('org'))
    print_field(t('field.isp'),           conn.get('isp'))
    print_field(t('field.domain'),        conn.get('domain'))
    tz = data.get('timezone') or {}
    print_field(t('field.timezone_id'),   tz.get('id'))
    print_field(t('field.timezone_abbr'), tz.get('abbr'))
    print_field(t('field.utc_offset'),    tz.get('utc'))


def print_my_ip(ip: Optional[str]) -> None:
    _print_section_header('section.my_ip')
    if ip is None:
        print(f"\n {Color.Re}{t('msg.network_failed')}{Color.Reset}")
    else:
        print(f"\n {Color.Wh}[{Color.Gr} + {Color.Wh}] {t('msg.your_ip')} : {Color.Gr}{ip}{Color.Reset}")
    print(f"\n {Color.Wh}=========================================={Color.Reset}")


def print_phone_info(data: dict) -> None:
    _print_section_header('section.phone')
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    print_field(t('field.location'),       data['location'],      width=22)
    print_field(t('field.region_code'),    data['region_code'],   width=22)
    print_field(t('field.timezone'),       data['timezones'],     width=22)
    # carrier(号段所属)+ disclaimer 子条
    print_field(t('field.carrier'),        data['carrier'],       width=22)
    note = data.get('carrier_note')
    if note:
        print(f"     {Color.Bl}↳ {note}{Color.Reset}")
    # 实时 HLR 运营商(若有)
    rt = data.get('carrier_realtime')
    if rt:
        print_field(t('field.carrier_realtime'), rt, width=22)
    elif data.get('carrier_realtime_error'):
        print(f"     {Color.Re}↳ {data['carrier_realtime_error']}{Color.Reset}")
    elif data.get('carrier_realtime_hint'):
        print(f"     {Color.Bl}↳ {data['carrier_realtime_hint']}{Color.Reset}")
    print_field(t('field.is_valid'),       data['is_valid'],      width=22)
    print_field(t('field.is_possible'),    data['is_possible'],   width=22)
    print_field(t('field.intl_format'),    data['international'], width=22)
    print_field(t('field.mobile_dial'),    data['mobile_dial'],   width=22)
    print_field(t('field.original_num'),   data['national'],      width=22)
    print_field(t('field.e164_format'),    data['e164'],          width=22)
    print_field(t('field.country_code'),   data['country_code'],  width=22)
    print_field(t('field.number_type'),    data['number_type'],   width=22)


def _platform_only(d: dict) -> dict:
    """从 track_username 返回的 dict 中只取出平台名→URL 项（跳过 _statuses 等私有 key）。
    注意：仅供 username 扫描结果使用 —— 批量 mx/whois 的 key 是用户传入的域名
    （包括合法的 _dmarc.example.com 等以 _ 开头的子域），不能套用此过滤。"""
    return {k: v for k, v in d.items() if not k.startswith('_')}


def _print_recursive_summary(rec: dict) -> None:
    """打印递归扫描的层级总结（v1.1.0）。"""
    levels = rec.get('levels') or []
    if not levels:
        return
    print()
    print(f" {Color.Cy}━━━ {t('recursive.title')} ━━━{Color.Reset}")
    for level in levels:
        depth = level.get('depth', 0)
        name = level.get('username', '')
        n_found = level.get('found', 0)
        if 'error' in level:
            print(f"  {Color.Re}[depth {depth}]{Color.Reset} {name}: {level['error']}")
        else:
            print(f"  {Color.Bl}[depth {depth}]{Color.Reset} {Color.Wh}{name}{Color.Reset}  →  "
                  f"{Color.Gr}{n_found}{Color.Reset} hits")
    total = rec.get('total_found', 0)
    depths = max((lvl.get('depth', 0) for lvl in levels), default=0) + 1
    print(f"\n {Color.Cy}{t('msg.recursive_done', total=total, depths=depths)}{Color.Reset}")


def print_username_results(results: dict, show_all: bool = False) -> None:
    _print_section_header('section.username')
    print()
    if isinstance(results, dict) and '_error' in results:
        print(f" {Color.Re}{t('err.query_failed', msg=results['_error'])}{Color.Reset}")
        return
    statuses = results.get('_statuses', {}) if isinstance(results, dict) else {}
    plat_results = _platform_only(results)
    found = sum(1 for v in plat_results.values() if v)
    print(f" {Color.Wh}{t('msg.scan_summary', total=len(plat_results), found=found)}{Color.Reset}")
    # 打印 status 摘要（WAF / invalid / 网络错误）—— 让用户知道结果可信度
    if statuses:
        status_counts = Counter(statuses.values())
        notes = []
        if status_counts.get(STATUS_WAF, 0):
            notes.append(f"{Color.Mage}{status_counts[STATUS_WAF]} WAF-blocked{Color.Reset}")
        if status_counts.get(STATUS_INVALID_USERNAME, 0):
            notes.append(f"{Color.Bl}{status_counts[STATUS_INVALID_USERNAME]} skipped (regex){Color.Reset}")
        if status_counts.get(STATUS_NETWORK_ERROR, 0):
            notes.append(f"{Color.Re}{status_counts[STATUS_NETWORK_ERROR]} network errors{Color.Reset}")
        if notes:
            print(f" {Color.Ye}[ note ] {Color.Reset}" + "  ·  ".join(notes))
    if not show_all:
        print(f" {Color.Bl}{Color.Ye}{t('msg.show_all_hint')}{Color.Reset}")
    print()
    # 按类别分组打印；类别内部按命中可信度排序：
    #   must_contain（最严格 → 高可信）→ not_found → 仅 HTTP 200（低可信）
    def _confidence(p):
        return (2 if p.must_contain else 0) + (1 if p.not_found else 0)
    for cat in CATEGORY_ORDER:
        cat_platforms = [p for p in _get_platforms() if p.category == cat and p.name in plat_results]
        if not cat_platforms:
            continue
        cat_found_list = [p for p in cat_platforms if plat_results.get(p.name)]
        # 命中的按可信度降序排（高可信优先 → 真实用户更可能在这）
        cat_found_list.sort(key=lambda p: (-_confidence(p), p.name))
        cat_found = len(cat_found_list)
        # 默认只显示有命中的类别；--all 时显示所有
        if not show_all and cat_found == 0:
            continue
        cat_label = t(f'cat.{cat}')
        print(f" {Color.Cy}┌─ {cat_label} ({cat_found}/{len(cat_platforms)}) ─{Color.Reset}")
        if show_all:
            platforms_to_show = sorted(cat_platforms,
                                       key=lambda p: (0 if results.get(p.name) else 1,
                                                      -_confidence(p), p.name))
        else:
            platforms_to_show = cat_found_list
        for p in platforms_to_show:
            url = plat_results.get(p.name)
            # 置信度标记：★★★ = must_contain, ★★ = not_found, ★ = 仅 HTTP 200
            conf = _confidence(p)
            badge = '★★★' if conf >= 2 else ('★★' if conf == 1 else '★  ')
            if url:
                print(f" {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {Color.Mage}{badge}{Color.Wh} {p.name:28} {Color.Gr}{url}{Color.Reset}")
            else:
                # 区分「未找到」「WAF 拦截」「无效用户名」
                p_status = statuses.get(p.name, STATUS_NOT_FOUND)
                if p_status == STATUS_WAF:
                    note = f"{Color.Mage}[ WAF blocked ]{Color.Reset}"
                elif p_status == STATUS_INVALID_USERNAME:
                    note = f"{Color.Bl}[ skipped ]{Color.Reset}"
                else:
                    note = f"{Color.Ye}{t('msg.not_found')}"
                print(f" {Color.Wh}[ {Color.Re}- {Color.Wh}] {Color.Bl}{badge}{Color.Wh} {p.name:28} {note}{Color.Reset}")
        print()


def print_whois(data: dict) -> None:
    _print_section_header('section.whois')
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    field_keys = [
        ('domain',          'field.whois_domain'),
        ('registrar',       'field.registrar'),
        ('creation_date',   'field.creation_date'),
        ('expiration_date', 'field.expiration_date'),
        ('updated_date',    'field.updated_date'),
        ('name_servers',    'field.name_servers'),
        ('status',          'field.status'),
        ('emails',          'field.emails'),
        ('org',             'field.whois_org'),
        ('country',         'field.whois_country'),
    ]
    for key, label_key in field_keys:
        value = data.get(key)
        if isinstance(value, (list, tuple, set)):
            value = ', '.join(str(v) for v in value)
        print_field(t(label_key), value if value is not None else t('msg.none'), width=18)


def print_mx(data: dict) -> None:
    _print_section_header('section.mx')
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    print_field(t('field.mx_domain'), data['domain'], width=12)
    print()
    for r in data['records']:
        print(f"  {Color.Wh}{t('field.priority')} {r['preference']:>4}  →  {Color.Gr}{r['exchange']}{Color.Reset}")


def print_email(result: dict) -> None:
    _print_section_header('section.email')
    print()
    print_field(t('field.email'),         result['email'],            width=16)
    print_field(t('field.syntax_valid'),  result.get('syntax_valid'), width=16)
    if not result.get('syntax_valid'):
        print(f" {Color.Re}{result.get('_error', '')}{Color.Reset}")
        return
    print_field(t('field.domain'),    result['domain'],            width=16)
    print_field(t('field.mx_valid'),  result.get('mx_valid'),      width=16)
    if result.get('mx_valid'):
        for r in result['mx_records']:
            print(f"   {Color.Wh}→ {t('field.priority')} {r['preference']:>4}  {Color.Gr}{r['exchange']}{Color.Reset}")
    else:
        # 优先用友好 i18n 消息；fallback 到 enum（向后兼容老 result 结构）
        msg = result.get('mx_error_msg') or result.get('mx_error', '')
        print(f" {Color.Re}{msg}{Color.Reset}")


def print_domain_emails(data: dict) -> None:
    """v1.4.0:打印域名邮箱枚举结果。按 source 分组(passive / crawl / pattern)。"""
    _print_section_header('section.demails')
    print()
    if '_error' in data:
        print(f" {Color.Re}{t('err.query_failed', msg=data['_error'])}{Color.Reset}")
        return
    domain = data.get('domain', '')
    emails = data.get('emails', []) or []
    stats = data.get('_stats', {}) or {}
    print(f" {Color.Wh}{t('demails.title', domain=domain)}{Color.Reset}")
    sm_label = ('✓' if stats.get('sitemap_found') else '✗')
    print(f" {Color.Wh}{t('demails.summary', total=stats.get('total', 0), pages=stats.get('pages_crawled', 0), sitemap=sm_label)}{Color.Reset}")
    by_src = stats.get('by_source', {})
    if by_src:
        breakdown = ', '.join(f"{k}={v}" for k, v in sorted(by_src.items()))
        print(f" {Color.Bl}{breakdown}{Color.Reset}")
    print()
    if not emails:
        print(f" {Color.Ye}{t('demails.no_results')}{Color.Reset}")
        return

    # 分组:passive(crtsh+whois) / crawl / pattern
    groups: dict = {'passive': [], 'crawl': [], 'pattern': []}
    for e in emails:
        srcs = set(e.get('sources', []))
        if 'pattern' in srcs and not (srcs & {'crtsh', 'whois', 'crawl'}):
            groups['pattern'].append(e)
        elif 'crawl' in srcs:
            groups['crawl'].append(e)
        else:
            groups['passive'].append(e)

    section_keys = [('passive', 'demails.section_passive'),
                    ('crawl', 'demails.section_crawl'),
                    ('pattern', 'demails.section_pattern')]
    for key, label_key in section_keys:
        items = groups[key]
        if not items:
            continue
        print(f" {Color.Cy}┌─ {t(label_key)} ({len(items)}) ─{Color.Reset}")
        for e in items:
            addr = e.get('address', '')
            srcs_str = ','.join(e.get('sources', []))
            verified = e.get('verified')
            v_str = ''
            if verified is True:
                v_str = f" {Color.Gr}[✓ verified]{Color.Reset}"
            elif verified is False:
                reason = (e.get('verify_reason') or '')[:30]
                v_str = f" {Color.Re}[✗ {reason}]{Color.Reset}"
            page_str = ''
            if e.get('page'):
                page_str = f"  {Color.Bl}{e['page'][:60]}{Color.Reset}"
            print(f" {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {addr:45} {Color.Mage}({srcs_str}){Color.Reset}{v_str}{page_str}")
        print()


def print_subdomain_diff(data: dict) -> None:
    """v1.5.0:终端打印 Diff 结果。三组分块 + 颜色编码:绿=新增,红=消失,黄=变更。"""
    if isinstance(data, dict) and data.get('_error'):
        print(f"\n {Color.Re}{data['_error']}{Color.Reset}\n")
        return
    _print_section_header('section.subdomain')
    print()
    domain = data.get('domain', '')
    stats = data.get('_stats', {}) or {}
    print(f" {Color.Wh}{t('diff.title', domain=domain)}{Color.Reset}")
    print(f" {Color.Wh}{t('diff.summary', added=stats.get('added', 0), removed=stats.get('removed', 0), changed=stats.get('changed', 0), unchanged=stats.get('unchanged', 0))}{Color.Reset}")
    print()
    added = data.get('added') or []
    removed = data.get('removed') or []
    changed = data.get('changed') or []
    if added:
        print(f" {Color.Gr}{t('diff.section_added', n=len(added))}{Color.Reset}")
        for s in added:
            ip = (s.get('a') or s.get('aaaa') or [None])[0]
            status = s.get('http_status')
            status_str = f"HTTP {status}" if status else ''
            print(f"   {Color.Gr}+ {s.get('host', ''):45} {Color.Wh}{(ip or '-'):20} {Color.Cy}{status_str}{Color.Reset}")
        print()
    if removed:
        print(f" {Color.Re}{t('diff.section_removed', n=len(removed))}{Color.Reset}")
        for s in removed:
            ip = (s.get('a') or s.get('aaaa') or [None])[0]
            print(f"   {Color.Re}- {s.get('host', ''):45} {Color.Wh}{(ip or '-'):20}{Color.Reset}")
        print()
    if changed:
        print(f" {Color.Ye}{t('diff.section_changed', n=len(changed))}{Color.Reset}")
        for c in changed:
            host = c.get('host', '')
            chg = c.get('changes', {})
            fields = ', '.join(chg.keys())
            print(f"   {Color.Ye}~ {host:45} {Color.Wh}变更字段: {Color.Mage}{fields}{Color.Reset}")
            for field, vals in chg.items():
                b = vals.get('before')
                a = vals.get('after')
                print(f"     {Color.Bl}{field}{Color.Reset}: {Color.Re}{b}{Color.Reset} → {Color.Gr}{a}{Color.Reset}")
        print()
    if not added and not removed and not changed:
        print(f" {Color.Gr}{t('diff.no_changes')}{Color.Reset}\n")


def print_subdomains(data: dict) -> None:
    """v1.3.0：打印子域名枚举结果。按 alive/dead 分组,WAF wildcard 警告优先。"""
    _print_section_header('section.subdomain')
    print()
    if '_error' in data:
        print(f" {Color.Re}{t('err.query_failed', msg=data['_error'])}{Color.Reset}")
        return
    domain = data.get('domain', '')
    subs = data.get('subdomains', []) or []
    stats = data.get('_stats', {}) or {}
    sources = data.get('sources', {}) or {}
    sources_active = sum(1 for v in sources.values() if v > 0)

    # 标题 + 概要
    print(f" {Color.Wh}{t('subdomain.title', domain=domain)}{Color.Reset}")
    print(f" {Color.Wh}{t('subdomain.summary', total=stats.get('total', 0), alive=stats.get('alive', 0), sources=sources_active)}{Color.Reset}")
    if data.get('wildcard_suspect'):
        print(f" {Color.Re}⚠ {t('subdomain.wildcard_warn')}{Color.Reset}")
    # v1.6.8:用新 _format_source_breakdown 显示完整 6 源状态(✅/⊘/❌)
    breakdown = _format_source_breakdown(data)
    if breakdown:
        print(f" {Color.Bl}{t('subdomain.source_breakdown', breakdown=breakdown)}{Color.Reset}")
    print()

    if not subs:
        print(f" {Color.Ye}{t('subdomain.no_results')}{Color.Reset}")
        return

    alive = [s for s in subs if s.get('alive')]
    dead = [s for s in subs if not s.get('alive')]

    if alive:
        print(f" {Color.Cy}┌─ {t('subdomain.alive_section')} ({len(alive)}) ─{Color.Reset}")
        for s in alive:
            host = s.get('host', '')
            ips = (s.get('a') or []) + (s.get('aaaa') or [])
            ip_str = ', '.join(ips) if ips else (s.get('cname') or '?')
            status = s.get('http_status')
            status_str = f"{Color.Gr}{status}{Color.Reset}" if status and status < 400 else \
                         (f"{Color.Ye}{status}{Color.Reset}" if status else f"{Color.Bl}-{Color.Reset}")
            title = s.get('title') or ''
            title_str = f"  {Color.Bl}{title[:60]}{Color.Reset}" if title else ''
            print(f" {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {host:40} {Color.Gr}{ip_str:30}{Color.Reset}  HTTP {status_str}{title_str}")
        print()

    if dead:
        print(f" {Color.Cy}┌─ {t('subdomain.dead_section')} ({len(dead)}) ─{Color.Reset}")
        for s in dead:
            print(f" {Color.Wh}[ {Color.Re}- {Color.Wh}] {s.get('host', '')}{Color.Reset}")
        print()


def print_investigate(data: dict) -> None:
    """v1.7.0:综合调查终端输出 — 6 个 section,扁平易读.每个 section 失败独立标记."""
    _print_section_header('section.investigate')
    print()
    if not isinstance(data, dict):
        print(f" {Color.Re}invalid data{Color.Reset}")
        return
    if '_error' in data:
        print(f" {Color.Re}{t('err.query_failed', msg=data['_error'])}{Color.Reset}")
        return
    target = data.get('target', '')
    stats = data.get('_stats') or {}
    elapsed = data.get('elapsed', 0)
    print(f" {Color.Wh}{t('investigate.title', target=target)}{Color.Reset}")
    print(f" {Color.Wh}{t('investigate.summary', tasks_done=stats.get('tasks_done', 0), tasks_failed=stats.get('tasks_failed', 0), pivots_done=stats.get('pivots_done', 0), elapsed=elapsed)}{Color.Reset}")
    if stats.get('budget_exceeded'):
        print(f" {Color.Ye}⚠ {t('investigate.budget_exceeded')}{Color.Reset}")
    trunc = stats.get('truncated') or {}
    if trunc.get('ips') or trunc.get('emails'):
        print(f" {Color.Bl}{t('investigate.truncated', ips=trunc.get('ips', 0), emails=trunc.get('emails', 0))}{Color.Reset}")
    print()

    tasks = data.get('tasks') or {}
    pivots = data.get('pivots') or {}

    # WHOIS
    print(f" {Color.Cy}┌─ {t('investigate.section_whois')} ─{Color.Reset}")
    w = tasks.get('whois') or {}
    if isinstance(w, dict) and '_error' in w:
        print(f"   {Color.Re}✗ {w['_error']}{Color.Reset}")
    elif isinstance(w, dict):
        registrar = w.get('registrar') or '-'
        created = w.get('creation_date') or '-'
        ns = w.get('name_servers')
        ns_str = ', '.join(ns) if isinstance(ns, list) else (str(ns) if ns else '-')
        emails = w.get('emails')
        if isinstance(emails, list):
            em_str = ', '.join(emails)
        else:
            em_str = str(emails) if emails else '-'
        print(f"   {Color.Wh}{t('field.registrar')}:{Color.Reset} {registrar}")
        print(f"   {Color.Wh}{t('field.creation_date')}:{Color.Reset} {created}")
        print(f"   {Color.Wh}{t('field.name_servers')}:{Color.Reset} {ns_str[:120]}")
        print(f"   {Color.Wh}{t('field.emails')}:{Color.Reset} {em_str[:120]}")
    print()

    # MX
    print(f" {Color.Cy}┌─ {t('investigate.section_mx')} ─{Color.Reset}")
    mx = tasks.get('mx') or {}
    if isinstance(mx, dict) and '_error' in mx:
        print(f"   {Color.Re}✗ {mx['_error']}{Color.Reset}")
    else:
        for r in (mx.get('records') or []):
            if isinstance(r, dict):
                print(f"   {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {r.get('preference', '-'):>4}  {r.get('exchange', '')}{Color.Reset}")
    print()

    # Subdomains
    print(f" {Color.Cy}┌─ {t('investigate.section_subdomain')} ─{Color.Reset}")
    sub = tasks.get('subdomain') or {}
    if isinstance(sub, dict) and '_error' in sub:
        print(f"   {Color.Re}✗ {sub['_error']}{Color.Reset}")
    elif isinstance(sub, dict):
        subs = sub.get('subdomains') or []
        alive = [s for s in subs if isinstance(s, dict) and s.get('alive')]
        sub_stats = sub.get('_stats') or {}
        print(f"   {Color.Wh}{t('investigate.subdomain_summary', alive=len(alive), total=sub_stats.get('total', 0))}{Color.Reset}")
        for s in alive[:20]:
            host = s.get('host', '')
            ips = (s.get('a') or []) + (s.get('aaaa') or [])
            ip_str = ', '.join(ips[:3]) if ips else (s.get('cname') or '?')
            print(f"   {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {host:35} {Color.Gr}{ip_str[:40]}{Color.Reset}")
        if len(alive) > 20:
            print(f"   {Color.Bl}... +{len(alive) - 20} more{Color.Reset}")
    print()

    # Pivot IP
    print(f" {Color.Cy}┌─ {t('investigate.section_ip_pivot')} ─{Color.Reset}")
    ips = pivots.get('ips') or {}
    if not ips:
        print(f"   {Color.Bl}({t('investigate.no_data')}){Color.Reset}")
    else:
        for ip, ipdata in ips.items():
            if isinstance(ipdata, dict) and '_error' in ipdata:
                print(f"   {Color.Re}✗ {ip}: {ipdata['_error']}{Color.Reset}")
            elif isinstance(ipdata, dict):
                country = ipdata.get('country') or '-'
                org = (ipdata.get('connection') or {}).get('org') if isinstance(ipdata.get('connection'), dict) else None
                org = org or ipdata.get('org') or '-'
                print(f"   {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {ip:18} {Color.Gr}{country:15}{Color.Reset} {Color.Bl}{str(org)[:40]}{Color.Reset}")
    print()

    # Emails
    print(f" {Color.Cy}┌─ {t('investigate.section_emails')} ─{Color.Reset}")
    em = tasks.get('emails') or {}
    if isinstance(em, dict) and '_error' in em:
        print(f"   {Color.Re}✗ {em['_error']}{Color.Reset}")
    elif isinstance(em, dict):
        em_list = em.get('emails') or []
        em_stats = em.get('_stats') or {}
        print(f"   {Color.Wh}{t('investigate.email_summary', total=em_stats.get('total', 0), pages=em_stats.get('pages_crawled', 0))}{Color.Reset}")
        for e in em_list[:15]:
            if isinstance(e, dict):
                addr = e.get('address', '')
                srcs = ','.join(e.get('sources') or [])
                print(f"   {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {addr:45} {Color.Mage}({srcs}){Color.Reset}")
        if len(em_list) > 15:
            print(f"   {Color.Bl}... +{len(em_list) - 15} more{Color.Reset}")
    print()

    # Pivot user
    print(f" {Color.Cy}┌─ {t('investigate.section_user_pivot')} ─{Color.Reset}")
    users = pivots.get('users') or {}
    if not users:
        print(f"   {Color.Bl}({t('investigate.no_data')}){Color.Reset}")
    else:
        for addr, ud in users.items():
            if not isinstance(ud, dict):
                continue
            local = ud.get('local_part', '')
            if '_error' in ud:
                print(f"   {Color.Re}✗ {addr} ({local}): {ud['_error']}{Color.Reset}")
                continue
            result = ud.get('result') or {}
            hits = [(k, v) for k, v in result.items() if not k.startswith('_') and v]
            print(f"   {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {addr:35} ({local}) {Color.Gr}→ {len(hits)} hits{Color.Reset}")
            for plat, url in hits[:5]:
                print(f"     {Color.Bl}{plat}{Color.Reset}: {url}")
            if len(hits) > 5:
                print(f"     {Color.Bl}... +{len(hits) - 5} more{Color.Reset}")
    print()


# ====================================================================
# 语言选择器（首次启动 + 菜单切换）
# ====================================================================
def prompt_language_select() -> str:
    """交互式选择语言，返回 'zh' 或 'en'。"""
    clear_screen()
    print()
    print(f" {Color.Wh}╔════════════════════════════════════════════╗")
    print(f" {Color.Wh}║  {Color.Gr}{t('lang.title'):42s}{Color.Wh}║")
    print(f" {Color.Wh}╚════════════════════════════════════════════╝")
    print()
    print(f"  {Color.Wh}[ 1 ] {Color.Gr}{t('lang.zh')}{Color.Reset}")
    print(f"  {Color.Wh}[ 2 ] {Color.Gr}{t('lang.en')}{Color.Reset}")
    print()
    while True:
        try:
            choice = input(f" {Color.Wh}>>> {Color.Reset}").strip()
            if choice == '1':
                return 'zh'
            if choice == '2':
                return 'en'
        except (EOFError, KeyboardInterrupt):
            return _lang


def switch_language_menu() -> None:
    """从菜单切换语言。"""
    print()
    print(f" {Color.Wh}{t('lang.title')}{Color.Reset}")
    print(f"  {Color.Wh}[ 1 ] {Color.Gr}{t('lang.zh')}{Color.Reset}")
    print(f"  {Color.Wh}[ 2 ] {Color.Gr}{t('lang.en')}{Color.Reset}")
    print(f"  {Color.Wh}[ 0 ] {Color.Ye}{t('lang.cancel')}{Color.Reset}")
    print()
    try:
        choice = input(f" {Color.Wh}>>> {Color.Reset}").strip()
    except (EOFError, KeyboardInterrupt):
        return
    if choice == '1':
        set_lang('zh')
        save_config({**load_config(), 'lang': 'zh'})
        print(f"\n {Color.Gr}{t('lang.changed')}{Color.Reset}")
    elif choice == '2':
        set_lang('en')
        save_config({**load_config(), 'lang': 'en'})
        print(f"\n {Color.Gr}{t('lang.changed')}{Color.Reset}")


# ====================================================================
# 菜单
# ====================================================================
MENU_KEYS = [
    (1, 'menu.ip_track'),
    (2, 'menu.my_ip'),
    (3, 'menu.phone'),
    (4, 'menu.username'),  # v1.2.0: 含变形子流程（permute 不再独立菜单项）
    (5, 'menu.whois'),
    (6, 'menu.mx'),
    (7, 'menu.email'),
    (8, 'menu.subdomain'),       # v1.3.0: 子域名枚举
    (9, 'menu.domain_emails'),   # v1.4.0: 域名邮箱枚举
    (10, 'menu.investigate'),    # v1.7.0: 综合调查 (lang 让位到 [11])
    (11, 'menu.lang'),
    (0, 'menu.exit'),
]


def show_menu() -> None:
    print_banner()
    print()
    for num, key in MENU_KEYS:
        print(f"{Color.Wh}[ {num} ] {Color.Gr}{t(key)}{Color.Reset}")
    # v1.3.2:全局提示子功能内可用 0 / 回车返回主菜单
    print(f"\n  {Color.Bl}{t('menu.back_hint')}{Color.Reset}")


def _ask_input(prompt_key: str, **kwargs) -> Optional[str]:
    """子功能输入 helper(v1.3.2):统一"返回主菜单"语义。
    返回 None 表示用户想返回主菜单 — 触发条件:
      - 空输入(直接回车)
      - 输入 '0'
      - EOFError / KeyboardInterrupt(管道末尾 / Ctrl+C)
    返回非空字符串则是用户实际查询输入。"""
    try:
        v = input(f"\n {Color.Wh}{t(prompt_key, **kwargs)}{Color.Gr}").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not v or v == '0':
        return None
    return v


def _is_affirmative(answer: str) -> bool:
    """统一判定肯定答复（v1.1.0 UX 统一）。
    主推 1/2 数字风格（与主菜单一致），同时兼容老用户习惯：y/yes/是/保存。
    任何其它输入（包括空字符串、'2'、'n'、'no'）一律视为否定。
    """
    return (answer or '').strip().lower() in (
        '1',           # 主推
        'y', 'yes',    # 英文短答（向后兼容）
        '是', '保存',   # 中文（向后兼容老用户）
        'true',        # 极端兼容
    )


def _interactive_save_prompt(prefix: str, data: Any, save_dir: Optional[str]) -> None:
    """交互模式下"保存报告"询问，v1.2.0 改为多格式循环：
      1. 是否保存？(1=是 / 2=否)
      2. 进入循环：选格式（1-8）→ 选文件名 → 保存 → 是否保存其他格式？
         任意时刻 EOF / Ctrl+C / 否 都安全退出。
      3. 默认路径 ~/Downloads/<prefix>_<ts>.<ext>，回车即用。

    若用户启动时传了 --save DIR/path，沿用旧逻辑（保存一次到该路径）。
    """
    if save_dir:
        # CLI 已指定 --save DIR：沿用原有目录归档逻辑，不再问
        _maybe_save(save_dir, prefix, data)
        return
    try:
        ans = input(f"\n {Color.Wh}{t('prompt.save_confirm')}{Color.Gr}")
    except (EOFError, KeyboardInterrupt):
        return
    if not _is_affirmative(ans):
        return

    formats = [
        ('json',       'fmt.json'),
        ('md',         'fmt.md'),
        ('html',       'fmt.html'),
        ('pdf',        'fmt.pdf'),
        ('txt',        'fmt.txt'),
        ('csv',        'fmt.csv'),
        ('xmind',      'fmt.xmind'),
        ('graph.html', 'fmt.graph'),
    ]
    safe_prefix = re.sub(r'[^\w.+-]', '_', prefix)[:60] or 'report'

    # 循环：选格式 → 保存 → 是否再保存一种
    while True:
        print()
        print(f" {Color.Wh}{t('prompt.format_title')}{Color.Reset}")
        for i, (_, key) in enumerate(formats, 1):
            print(f"  {Color.Wh}[ {i} ] {Color.Gr}{t(key)}{Color.Reset}")
        print()
        try:
            choice = input(f" {Color.Wh}{t('prompt.format_select')}{Color.Gr}").strip() or '1'
        except (EOFError, KeyboardInterrupt):
            return
        try:
            idx = int(choice) - 1
        except ValueError:
            idx = 0
        if not (0 <= idx < len(formats)):
            idx = 0
        ext = formats[idx][0]

        # 智能默认文件名 → ~/Downloads/<prefix>_<ts>.<ext>
        # 在循环内重新计算 ts 让多次保存得到不同文件名
        ts_str = time.strftime('%Y%m%d-%H%M%S')
        default_name = os.path.join(_default_report_dir(), f'{safe_prefix}_{ts_str}.{ext}')
        try:
            target = input(
                f" {Color.Wh}{t('prompt.save_filename', default=default_name)}{Color.Gr}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not target:
            target = default_name
        _maybe_save(target, prefix, data)

        # 是否继续保存其他格式
        try:
            again = input(f"\n {Color.Wh}{t('prompt.save_another')}{Color.Gr}")
        except (EOFError, KeyboardInterrupt):
            return
        if not _is_affirmative(again):
            return


def _ask_permute_method() -> str:
    """v1.2.0：交互式选择 permute 方式（与主菜单 1/2 风格一致）。"""
    print()
    print(f" {Color.Wh}{t('prompt.permute_method')}{Color.Reset}")
    print(f"  {Color.Wh}[ 1 ] {Color.Gr}{t('method.strict')}{Color.Reset}")
    print(f"  {Color.Wh}[ 2 ] {Color.Gr}{t('method.all')}{Color.Reset}")
    print()
    try:
        choice = input(f" {Color.Wh}{t('prompt.permute_method_select')}{Color.Gr}").strip() or '1'
    except (EOFError, KeyboardInterrupt):
        choice = '1'
    return 'all' if choice == '2' else 'strict'


def _ask_username_strategy() -> str:
    """v1.2.0：选择用户名扫描策略（直接 / 变形扫 / 仅变形）。
    返回 'direct' | 'permute_scan' | 'permute_only'。"""
    print()
    print(f" {Color.Wh}{t('prompt.scan_strategy')}{Color.Reset}")
    print(f"  {Color.Wh}[ 1 ] {Color.Gr}{t('strategy.direct')}{Color.Reset}")
    print(f"  {Color.Wh}[ 2 ] {Color.Gr}{t('strategy.permute_scan')}{Color.Reset}")
    print(f"  {Color.Wh}[ 3 ] {Color.Gr}{t('strategy.permute_only')}{Color.Reset}")
    print()
    try:
        choice = input(f" {Color.Wh}{t('prompt.scan_strategy_select')}{Color.Gr}").strip() or '1'
    except (EOFError, KeyboardInterrupt):
        choice = '1'
    return {'2': 'permute_scan', '3': 'permute_only'}.get(choice, 'direct')


def handle_choice(choice: int, save_dir: Optional[str] = None) -> None:
    # v1.3.2:所有顶层输入用 _ask_input,空 / '0' / EOF / Ctrl+C 都返回主菜单
    if choice == 1:
        ip = _ask_input('prompt.input_ip')
        if ip is None:
            return
        data = track_ip(ip)
        print_ip_info(ip, data)
        _interactive_save_prompt(f'ip_{ip}', data, save_dir)
    elif choice == 2:
        my = show_my_ip()
        print_my_ip(my)
        _interactive_save_prompt('myip', {'ip': my}, save_dir)
    elif choice == 3:
        num = _ask_input('prompt.input_phone')
        if num is None:
            return
        data = track_phone(num)
        print_phone_info(data)
        _interactive_save_prompt(f'phone_{num}', data, save_dir)
    elif choice == 4:
        name = _ask_input('prompt.input_username')
        if name is None:
            return
        # v1.2.0：先选策略 — 直接 / 变形扫描 / 仅变形（替代旧 [8] permute 菜单项）
        strategy = _ask_username_strategy()

        # 分支 1：仅生成变形（不扫描）
        if strategy == 'permute_only':
            method = _ask_permute_method()
            variations = permute_username(name, method=method)
            if not variations:
                print(f" {Color.Re}{t('err.permute_empty')}{Color.Reset}")
                return
            print(f"\n {Color.Cy}{t('permute.generated', name=name, n=len(variations))}{Color.Reset}\n")
            for v in variations:
                print(f"  {Color.Gr}•{Color.Reset} {v}")
            _interactive_save_prompt(f'permute_{name}',
                                     {'name': name, 'permutations': variations},
                                     save_dir)
            return

        # 分支 2：生成变形 + 批量扫描
        if strategy == 'permute_scan':
            method = _ask_permute_method()
            variations = permute_username(name, method=method)
            if not variations:
                print(f" {Color.Re}{t('err.permute_empty')}{Color.Reset}")
                return
            cats = _ask_scan_mode()
            print(f"\n {Color.Cy}{t('permute.generated', name=name, n=len(variations))}{Color.Reset}")
            scan_results: dict = {}
            for v in variations:
                print(f"\n {Color.Bl}━━━ {v} ━━━{Color.Reset}")
                r = track_username(v, categories=cats)
                scan_results[v] = r
                print_username_results(r, show_all=False)
            _interactive_save_prompt(f'permute_{name}', scan_results, save_dir)
            return

        # 分支 3（默认）：直接扫描原始用户名
        cats = _ask_scan_mode()
        try:
            recurse_ans = input(f"\n {Color.Wh}{t('prompt.recursive')}{Color.Gr}")
        except EOFError:
            recurse_ans = ''
        if _is_affirmative(recurse_ans):
            try:
                depth_str = input(f" {Color.Wh}{t('prompt.recursive_depth')}{Color.Gr}").strip()
            except EOFError:
                depth_str = ''
            try:
                depth = int(depth_str) if depth_str else 2
            except ValueError:
                depth = 2
            depth = max(0, min(depth, RECURSIVE_MAX_DEPTH))
            results = recursive_track_username(name, max_depth=depth, categories=cats)
            if isinstance(results, dict) and '_recursive' in results:
                _print_recursive_summary(results['_recursive'])
            print_username_results(results)
        else:
            results = track_username(name, categories=cats)
            print_username_results(results)
        _interactive_save_prompt(f'username_{name}', results, save_dir)
    elif choice == 5:
        domain = _ask_input('prompt.input_domain')
        if domain is None:
            return
        data = whois_lookup(domain)
        print_whois(data)
        _interactive_save_prompt(f'whois_{domain}', data, save_dir)
    elif choice == 6:
        domain = _ask_input('prompt.input_domain')
        if domain is None:
            return
        data = mx_lookup(domain)
        print_mx(data)
        _interactive_save_prompt(f'mx_{domain}', data, save_dir)
    elif choice == 7:
        addr = _ask_input('prompt.input_email')
        if addr is None:
            return
        result = email_validate(addr)
        print_email(result)
        _interactive_save_prompt(f'email_{addr}', result, save_dir)
    elif choice == 8:
        # v1.3.0: 子域名枚举
        domain = _ask_input('prompt.input_subdomain')
        if domain is None:
            return
        # 询问 probe 偏好(默认开);'2'=否,其它=是(包括空回车)
        try:
            probe_ans = input(f"\n {Color.Wh}{t('prompt.subdomain_probe')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            probe_ans = ''
        probe = probe_ans != '2'
        # v1.4.9:询问 bruteforce(默认关 — 多数用户只想要被动结果)
        try:
            bf_ans = input(f"\n {Color.Wh}{t('prompt.subdomain_bruteforce')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            bf_ans = ''
        bruteforce = bf_ans == '2'
        result = enumerate_subdomains(domain, probe=probe, bruteforce=bruteforce)
        print_subdomains(result)
        # v1.4.10:保存前询问是否过滤 dead 子域(默认是 — 用户反馈报告太挤)
        # v1.6.5:用 _filter_alive_only,wildcard 时自动严格(防 DNS 劫持)
        try:
            ao_ans = input(f"\n {Color.Wh}{t('prompt.subdomain_alive_only')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            ao_ans = ''
        save_data = result
        if ao_ans != '2':
            save_data = _filter_alive_only(result)
        _interactive_save_prompt(f'subdomain_{domain}', save_data, save_dir)
    elif choice == 9:
        # v1.4.0: 域名邮箱枚举
        domain = _ask_input('prompt.input_demails')
        if domain is None:
            return
        # 子问题:是否含 alive 子域(默认是)
        try:
            inc_ans = input(f"\n {Color.Wh}{t('prompt.demails_subdomains')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            inc_ans = ''
        include_subdomains = inc_ans != '2'
        # v1.6.12:子问题 — 爬取深度(默认标准 200 页)
        try:
            depth_ans = input(f"\n {Color.Wh}{t('prompt.demails_max_pages')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            depth_ans = ''
        # '1' 或空 → 200(默认),'2' → 500(深度),'3' → 50(极速)
        if depth_ans == '2':
            max_pages = 500
        elif depth_ans == '3':
            max_pages = 50
        else:
            max_pages = DOMAIN_EMAIL_DEFAULT_MAX_PAGES  # 200
        # 子问题:是否要模式生成
        try:
            guess_ans = input(f"\n {Color.Wh}{t('prompt.demails_guess')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            guess_ans = ''
        guess_names = guess_ans if guess_ans else None
        # 子问题:是否 SMTP 验证(默认否)
        try:
            verify_ans = input(f"\n {Color.Wh}{t('prompt.demails_verify')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            verify_ans = ''
        verify_smtp = verify_ans == '1'
        result = enumerate_domain_emails(
            domain,
            include_subdomains=include_subdomains,
            max_pages=max_pages,
            guess_names=guess_names,
            verify_smtp=verify_smtp,
        )
        print_domain_emails(result)
        _interactive_save_prompt(f'domain-emails_{domain}', result, save_dir)
    elif choice == 10:
        # v1.7.0:综合调查 (一个域名 → 4 原子 + 2 单向 pivot,出整合报告)
        domain = _ask_input('prompt.input_investigate')
        if domain is None:
            return
        # 询问接力深度(默认 1=带 pivot;2=仅原子)
        try:
            d_ans = input(f"\n {Color.Wh}{t('prompt.investigate_depth')}{Color.Gr}").strip()
        except (EOFError, KeyboardInterrupt):
            d_ans = ''
        depth = 0 if d_ans == '2' else 1
        data = do_investigate(domain, depth=depth)
        print_investigate(data)
        _interactive_save_prompt(f'investigate_{domain}', data, save_dir)
    elif choice == 11:
        # v1.4.0: 切换语言(v1.3.0 是 [9],加 domain-emails 后让位到 [10],加 investigate 后到 [11])
        switch_language_menu()
    elif choice == 0:
        print(f"\n {Color.Gr}{t('prompt.bye')}{Color.Reset}")
        sys.exit(0)
    else:
        raise ValueError(t('prompt.unknown_option', n=choice))


def _maybe_save(target: Optional[str], prefix: str, data: Any) -> None:
    """保存查询结果。target 可以是：
       - 目录（如 'out/'）：自动生成 <prefix>_<ts>.json
       - 单文件按后缀分发（v1.2.0 起 8 种格式）：
         .json / .md / .html / .pdf / .txt / .csv / .xmind / .graph.html
       - 单文件无扩展 → JSON
    JSON 输出会自动过滤 _* 私有 key（如 _statuses）保持公开 API 干净。
    所有 IO 错误（PermissionError / OSError）友好提示而非抛 traceback 给用户。
    """
    # 拒绝纯空白 target —— ' '/'\t' 是 truthy，会真创建命名为 ' ' 的文件污染 cwd
    target = (target or '').strip()
    if not target:
        return
    target_lower = target.lower()
    is_md_file = target_lower.endswith('.md')
    is_pdf_file = target_lower.endswith('.pdf')  # v1.1.0
    # v1.2.0：注意 .graph.html 必须先于 .html 判定（else 被泛 .html 抢走）
    is_graph_file = target_lower.endswith('.graph.html')
    is_html_file = target_lower.endswith('.html') and not is_graph_file
    is_txt_file = target_lower.endswith('.txt')
    is_csv_file = target_lower.endswith('.csv')
    is_xmind_file = target_lower.endswith('.xmind')
    is_dir = target.endswith(os.sep) or (os.path.exists(target) and os.path.isdir(target))
    # 仅 username 扫描结果需要剥 _statuses 等私有 key；
    # 批量 mx/whois 的 key 是用户传入的域名（含合法 _dmarc.example.com 等
    # 以 _ 开头的子域），不能无脑过滤 —— 之前会导致这些子域结果被静默删掉。
    json_data = data
    if isinstance(data, dict) and '_error' not in data and prefix.startswith('username_'):
        json_data = _platform_only(data)
    try:
        if is_dir:
            os.makedirs(target, exist_ok=True)
            safe_prefix = re.sub(r'[^\w.+-]', '_', prefix)
            ts = time.strftime('%Y%m%d-%H%M%S')
            path = os.path.join(target, f'{safe_prefix}_{ts}.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2, default=str)
        else:
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if is_md_file:
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(_to_markdown(prefix, data))
            elif is_pdf_file:
                err = _to_pdf(prefix, data, target)
                if err:
                    sys.stderr.write(f"\n {Color.Re}[error] {err}{Color.Reset}\n")
                    return
            elif is_graph_file:
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(_to_graph_html(prefix, data))
            elif is_html_file:
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(_to_html(prefix, data))
            elif is_txt_file:
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(_to_txt(prefix, data))
            elif is_csv_file:
                # newline='' 让 csv 模块自己控行尾，避免 Windows 多余 \r
                with open(target, 'w', encoding='utf-8', newline='') as f:
                    f.write(_to_csv(prefix, data))
            elif is_xmind_file:
                err = _to_xmind(prefix, data, target)
                if err:
                    sys.stderr.write(f"\n {Color.Re}[error] {err}{Color.Reset}\n")
                    return
            else:
                with open(target, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, ensure_ascii=False, indent=2, default=str)
            path = target
    except OSError as e:
        # 包含 PermissionError / FileNotFoundError / NotADirectoryError 等
        sys.stderr.write(f"\n {Color.Re}[error] {t('err.save_failed', target=target, err=e)}{Color.Reset}\n")
        return
    # 显示绝对路径，方便用户立刻找到文件（解决"我的文件存哪去了"困惑）
    abs_path = os.path.abspath(path)
    print(f"\n {Color.Cy}{t('msg.saved_to', path=abs_path)}{Color.Reset}")


def _md_escape(s: Any) -> str:
    """转义 markdown 表格 cell：
    - `|`：表格列分隔符
    - `\\r` `\\n`：避免注入伪标题
    - U+0085 NEL / U+2028 LINE SEP / U+2029 PARAGRAPH SEP：
      str.splitlines() 视其为换行 → markdown 渲染按换行处理 → 注入伪标题
    - `` ` ``：避免破坏 inline code 围栏，让用户输入跳出 code span 注入任意 markdown
      （security: 用户可控字段如 username/ip/domain 会进 markdown 报告）
    """
    if s is None:
        return ''
    return (str(s)
            .replace('|', '\\|')
            .replace('\r', ' ')
            .replace('\n', ' ')
            .replace('\x85', ' ')
            .replace(' ', ' ')
            .replace(' ', ' ')
            .replace('`', '\\`')
            .strip())


def _to_markdown(prefix: str, data: Any) -> str:
    """根据 prefix（如 'ip_8.8.8.8' / 'username_torvalds'）生成 Markdown 报告。
    所有用户输入字段（cmd / query / dict keys / values）都做 escape，
    防止换行注入伪标题或 `|` 破坏表格列数。
    v1.2.1: 标题/标签跟随当前 UI 语言（_lang）。"""
    lines = []
    cmd, _, query = prefix.partition('_')
    # query/cmd 可能含恶意换行符 → 单行化
    cmd = _md_escape(cmd) or '?'
    query = _md_escape(query)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    classification = '机密 · OSINT 简报' if get_lang() == 'zh' else 'Confidential · OSINT Brief'
    # v1.4.1:YAML frontmatter(支持 Jekyll/Hugo/Obsidian 元数据)+ 引文式 quote 头
    lines.append('---')
    lines.append(f'title: "{t("report.title")} — {query}"')
    lines.append(f'command: {cmd}')
    lines.append(f'query: "{query}"')
    lines.append(f'generated: {ts}')
    lines.append('tool: SpyEyes')
    lines.append('classification: confidential')
    lines.append('---')
    lines.append('')
    lines.append(f"# {t('report.title')}")
    lines.append('')
    lines.append(f"> _{classification}_")
    lines.append('')
    lines.append(f"| {t('report.command')} | {t('report.query')} | {t('report.generated')} |")
    lines.append("|---|---|---|")
    lines.append(f"| `{cmd}` | `{query}` | {ts} |")
    lines.append('')

    if isinstance(data, dict) and '_error' in data:
        # _error 也要 escape：whois/dns 后端返回的异常 message 可能含换行注入伪标题
        lines.append(f"## ❌ {t('report.error')}\n\n> {_md_escape(data['_error'])}\n")
        return '\n'.join(lines)

    if cmd == 'username' and isinstance(data, dict):
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        lines.append(f"## {t('report.username_scan')}: `{query}`")
        lines.append("")
        lines.append(f"**{t('report.scan_summary', total=len(plat), found=found)}**")
        lines.append("")
        for cat in CATEGORY_ORDER:
            cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
            cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
            if not cat_found:
                continue
            cat_label = _md_escape(t(f'cat.{cat}'))
            lines.append(f"### {cat_label} ({len(cat_found)}/{len(cat_pl)})")
            lines.append("")
            lines.append(f"| {t('report.platform')} | {t('report.url')} |")
            lines.append("|---|---|")
            for p, url in cat_found:
                lines.append(f"| {_md_escape(p.name)} | <{_md_escape(url)}> |")
            lines.append("")
        return '\n'.join(lines)

    if cmd == 'mx' and isinstance(data, dict) and 'records' in data:
        lines.append(f"## {t('report.mx_records')} `{data.get('domain', query)}`")
        lines.append("")
        lines.append(f"| {t('report.priority')} | {t('report.mail_server')} |")
        lines.append("|---:|---|")
        for r in data['records']:
            lines.append(f"| {r['preference']} | `{r['exchange']}` |")
        lines.append("")
        return '\n'.join(lines)

    # v1.4.0: domain-emails 枚举 — 表格列 邮箱 / 来源 / 出处页面 / 已验证
    if cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
        domain_lbl = _md_escape(data.get('domain', query))
        stats = data.get('_stats', {}) or {}
        sm_label = '✓' if stats.get('sitemap_found') else '✗'
        lines.append(f"## {_md_escape(t('demails.title', domain=domain_lbl))}")
        lines.append("")
        lines.append(f"**{_md_escape(t('demails.summary', total=stats.get('total', 0), pages=stats.get('pages_crawled', 0), sitemap=sm_label))}**")
        lines.append("")
        if not data.get('emails'):
            lines.append(f"_{_md_escape(t('demails.no_results'))}_")
            return '\n'.join(lines)
        lines.append(
            f"| {t('demails.col_address')} | {t('demails.col_sources')} | "
            f"{t('demails.col_page')} | {t('demails.col_verified')} |"
        )
        lines.append("|---|---|---|---:|")
        for e in data['emails']:
            ver = ''
            if e.get('verified') is True:
                ver = '✓'
            elif e.get('verified') is False:
                ver = '✗'
            page = e.get('page') or ''
            lines.append(
                f"| `{_md_escape(e.get('address', ''))}` | "
                f"{_md_escape(','.join(e.get('sources', [])))} | "
                f"{_md_escape(page)} | {ver} |"
            )
        lines.append("")
        return '\n'.join(lines)

    # v1.3.0: subdomain 枚举 — 表格列出 host / IP / CNAME / status / title
    if cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
        domain_lbl = _md_escape(data.get('domain', query))
        stats = data.get('_stats', {}) or {}
        lines.append(f"## {_md_escape(t('subdomain.title', domain=domain_lbl))}")
        lines.append("")
        lines.append(f"**{_md_escape(t('subdomain.summary', total=stats.get('total', 0), alive=stats.get('alive', 0), sources=sum(1 for v in (data.get('sources') or {}).values() if v > 0)))}**")
        # v1.6.8:加完整 6 源状态行
        bd = _format_source_breakdown(data)
        if bd:
            lines.append("")
            lines.append(f"_{_md_escape(t('subdomain.source_breakdown', breakdown=bd))}_")
        if data.get('wildcard_suspect'):
            lines.append(f"\n> ⚠ {_md_escape(t('subdomain.wildcard_warn'))}")
        lines.append("")
        if not data.get('subdomains'):
            lines.append(f"_{_md_escape(t('subdomain.no_results'))}_")
            return '\n'.join(lines)
        lines.append(
            f"| {t('subdomain.col_host')} | {t('subdomain.col_ip')} | "
            f"{t('subdomain.col_cname')} | {t('subdomain.col_status')} | {t('subdomain.col_title')} |"
        )
        lines.append("|---|---|---|---:|---|")
        for s in data['subdomains']:
            ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
            cname = s.get('cname') or ''
            status = s.get('http_status')
            status_str = str(status) if status is not None else ''
            title = s.get('title') or ''
            host = s.get('host') or ''
            lines.append(
                f"| `{_md_escape(host)}` | {_md_escape(ips)} | "
                f"{_md_escape(cname)} | {status_str} | {_md_escape(title)} |"
            )
        lines.append("")
        return '\n'.join(lines)

    # v1.2.1 P1-2: permute 仅生成变形（不扫描）—— 列出变形清单
    if cmd == 'permute' and _is_permute_only(data):
        lines.append(f"## {t('permute.title')} `{_md_escape(data.get('name', query))}`")
        lines.append("")
        for v in data.get('permutations', []):
            lines.append(f"- `{_md_escape(v)}`")
        lines.append("")
        return '\n'.join(lines)

    # v1.2.1 P1-2: permute + 批量扫描 —— 每个变形一个子节
    if cmd == 'permute' and _is_permute_scan(data):
        lines.append(f"## {t('permute.title')} `{query}`")
        lines.append("")
        lines.append(f"**{len(data)} variations scanned**")
        lines.append("")
        for var, scan in data.items():
            if not isinstance(scan, dict):
                continue
            lines.append(f"### `{_md_escape(var)}`")
            if '_error' in scan:
                lines.append(f"> ❌ {_md_escape(scan['_error'])}")
                lines.append("")
                continue
            plat = _platform_only(scan)
            found = sum(1 for v in plat.values() if v)
            lines.append(f"**{t('report.scan_summary', total=len(plat), found=found)}**")
            lines.append("")
            if found == 0:
                continue
            lines.append(f"| {t('report.platform')} | {t('report.url')} |")
            lines.append("|---|---|")
            for p_name, url in plat.items():
                if url:
                    lines.append(f"| {_md_escape(p_name)} | <{_md_escape(url)}> |")
            lines.append("")
        return '\n'.join(lines)

    # v1.7.0: investigate 综合调查 — 6 sections,带 stats summary 在前
    if cmd == 'investigate' and isinstance(data, dict) and 'tasks' in data:
        target_lbl = _md_escape(data.get('target', query))
        stats = data.get('_stats', {}) or {}
        lines.append(f"## {_md_escape(t('investigate.title', target=target_lbl))}")
        lines.append("")
        lines.append(f"**{_md_escape(t('investigate.summary', tasks_done=stats.get('tasks_done', 0), tasks_failed=stats.get('tasks_failed', 0), pivots_done=stats.get('pivots_done', 0), elapsed=data.get('elapsed', 0)))}**")
        lines.append("")
        if stats.get('budget_exceeded'):
            lines.append(f"> ⚠ {_md_escape(t('investigate.budget_exceeded'))}")
            lines.append("")
        trunc = stats.get('truncated') or {}
        if trunc.get('ips') or trunc.get('emails'):
            lines.append(f"_{_md_escape(t('investigate.truncated', ips=trunc.get('ips', 0), emails=trunc.get('emails', 0)))}_")
            lines.append("")
        tasks = data.get('tasks') or {}
        pivots = data.get('pivots') or {}

        # WHOIS
        lines.append(f"### {_md_escape(t('investigate.section_whois'))}")
        lines.append("")
        w = tasks.get('whois') or {}
        if isinstance(w, dict) and '_error' in w:
            lines.append(f"> ❌ {_md_escape(w['_error'])}")
        elif isinstance(w, dict):
            lines.append(f"| {t('report.field')} | {t('report.value')} |")
            lines.append("|---|---|")
            for k in ('registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails', 'org', 'country'):
                v = w.get(k)
                if v is None or v == '':
                    continue
                if isinstance(v, list):
                    v_str = ', '.join(str(x) for x in v)
                else:
                    v_str = str(v)
                lines.append(f"| `{_md_escape(k)}` | {_md_escape(v_str)} |")
        lines.append("")

        # MX
        lines.append(f"### {_md_escape(t('investigate.section_mx'))}")
        lines.append("")
        mx = tasks.get('mx') or {}
        if isinstance(mx, dict) and '_error' in mx:
            lines.append(f"> ❌ {_md_escape(mx['_error'])}")
        elif isinstance(mx, dict) and mx.get('records'):
            lines.append(f"| {t('report.priority')} | {t('report.mail_server')} |")
            lines.append("|---:|---|")
            for r in mx['records']:
                lines.append(f"| {r.get('preference', '-')} | `{_md_escape(r.get('exchange', ''))}` |")
        lines.append("")

        # Subdomain
        lines.append(f"### {_md_escape(t('investigate.section_subdomain'))}")
        lines.append("")
        sub = tasks.get('subdomain') or {}
        if isinstance(sub, dict) and '_error' in sub:
            lines.append(f"> ❌ {_md_escape(sub['_error'])}")
        elif isinstance(sub, dict):
            subs = sub.get('subdomains') or []
            alive = [s for s in subs if isinstance(s, dict) and s.get('alive')]
            sub_stats = sub.get('_stats') or {}
            lines.append(f"**{_md_escape(t('investigate.subdomain_summary', alive=len(alive), total=sub_stats.get('total', 0)))}**")
            lines.append("")
            if alive:
                lines.append(f"| {t('subdomain.col_host')} | {t('subdomain.col_ip')} | {t('subdomain.col_status')} |")
                lines.append("|---|---|---:|")
                for s in alive:
                    ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
                    status = s.get('http_status')
                    status_str = str(status) if status is not None else ''
                    lines.append(f"| `{_md_escape(s.get('host', ''))}` | {_md_escape(ips)} | {status_str} |")
        lines.append("")

        # IP pivot
        lines.append(f"### {_md_escape(t('investigate.section_ip_pivot'))}")
        lines.append("")
        ip_pivot = pivots.get('ips') or {}
        if not ip_pivot:
            lines.append(f"_{_md_escape(t('investigate.no_data'))}_")
        else:
            lines.append(f"| IP | {t('field.country')} | {t('field.org')} |")
            lines.append("|---|---|---|")
            for ip, ipd in ip_pivot.items():
                if isinstance(ipd, dict) and '_error' in ipd:
                    lines.append(f"| `{_md_escape(ip)}` | — | ❌ {_md_escape(ipd['_error'])} |")
                elif isinstance(ipd, dict):
                    country = ipd.get('country') or '-'
                    conn = ipd.get('connection') if isinstance(ipd.get('connection'), dict) else None
                    org = (conn.get('org') if conn else None) or ipd.get('org') or '-'
                    lines.append(f"| `{_md_escape(ip)}` | {_md_escape(country)} | {_md_escape(str(org))} |")
        lines.append("")

        # Emails
        lines.append(f"### {_md_escape(t('investigate.section_emails'))}")
        lines.append("")
        em = tasks.get('emails') or {}
        if isinstance(em, dict) and '_error' in em:
            lines.append(f"> ❌ {_md_escape(em['_error'])}")
        elif isinstance(em, dict):
            em_list = em.get('emails') or []
            em_stats = em.get('_stats') or {}
            lines.append(f"**{_md_escape(t('investigate.email_summary', total=em_stats.get('total', 0), pages=em_stats.get('pages_crawled', 0)))}**")
            lines.append("")
            if em_list:
                lines.append(f"| {t('demails.col_address')} | {t('demails.col_sources')} |")
                lines.append("|---|---|")
                for e in em_list:
                    if isinstance(e, dict):
                        addr = e.get('address', '')
                        srcs = ', '.join(e.get('sources') or [])
                        lines.append(f"| `{_md_escape(addr)}` | {_md_escape(srcs)} |")
        lines.append("")

        # User pivot
        lines.append(f"### {_md_escape(t('investigate.section_user_pivot'))}")
        lines.append("")
        users = pivots.get('users') or {}
        if not users:
            lines.append(f"_{_md_escape(t('investigate.no_data'))}_")
        else:
            for addr, ud in users.items():
                if not isinstance(ud, dict):
                    continue
                local = ud.get('local_part', '')
                lines.append(f"#### `{_md_escape(addr)}` (`{_md_escape(local)}`)")
                lines.append("")
                if '_error' in ud:
                    lines.append(f"> ❌ {_md_escape(ud['_error'])}")
                    continue
                result = ud.get('result') or {}
                hits = [(k, v) for k, v in result.items() if not k.startswith('_') and v]
                if not hits:
                    lines.append(f"_{_md_escape(t('investigate.no_data'))}_")
                    continue
                lines.append(f"| {t('report.platform')} | {t('report.url')} |")
                lines.append("|---|---|")
                for plat, url in hits:
                    lines.append(f"| {_md_escape(plat)} | <{_md_escape(url)}> |")
                lines.append("")
        return '\n'.join(lines)

    # 通用：扁平化 dict 为表格（key 与 value 都转义）
    # 注意：仅对 username 扫描结果调 _platform_only 过滤 _* 私有 key；
    # 批量 mx/whois 的 key 是用户传入的域名（含 _dmarc.example.com 等合法子域），
    # 一律过滤 _ 开头的 key 会让这些条目从 MD 报告里被静默删除（数据丢失）
    if isinstance(data, dict):
        lines.append(f"## {cmd.upper()} {t('report.info_for')}: `{query}`")
        lines.append("")
        lines.append(f"| {t('report.field')} | {t('report.value')} |")
        lines.append("|---|---|")
        items = _platform_only(data).items() if cmd == 'username' else data.items()
        for k, v in items:
            if v is None or v == '':
                continue
            if isinstance(v, dict):
                v_str = ', '.join(f"{kk}={vv}" for kk, vv in v.items() if not isinstance(vv, (dict, list)))
            elif isinstance(v, (list, tuple)):
                v_str = ', '.join(str(x) for x in v)
            else:
                v_str = str(v)
            lines.append(f"| {_md_escape(k)} | {_md_escape(v_str)} |")
        lines.append("")
        return '\n'.join(lines)

    # 兜底
    lines.append("```json")
    lines.append(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    lines.append("```")
    return '\n'.join(lines)


# PDF CJK 字体缓存:reportlab 默认 Helvetica/Times 不含 CJK glyph,中文显示成 □
# 注册一次内置 CID 字体 STSong-Light(简中,reportlab 自带,无需外部 TTF,跨平台 work)
_PDF_FONT: Optional[str] = None


def _register_pdf_cjk_font() -> str:
    """注册 reportlab 内置 STSong-Light(简中 CID 字体)用于 PDF 中文渲染。
    一次注册全局生效,失败回退 Helvetica(英文场景仍可用)。"""
    global _PDF_FONT
    if _PDF_FONT is not None:
        return _PDF_FONT
    if not HAS_REPORTLAB:
        _PDF_FONT = 'Helvetica'
        return _PDF_FONT
    try:
        from reportlab.pdfbase import pdfmetrics  # type: ignore
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont  # type: ignore
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
        _PDF_FONT = 'STSong-Light'
    except Exception:
        _PDF_FONT = 'Helvetica'
    return _PDF_FONT


# A4 宽 595pt,默认 margin 72×2 = 451pt 可用;新边距 36×2 = 523pt 给 buffer
_PDF_MARGIN = 36
_PDF_USABLE_WIDTH = 523  # 595 - 36*2
# 表格内文本格式化(IP 列截断、title 截断)
_PDF_MAX_IPS_SHOWN = 4
_PDF_MAX_TITLE_LEN = 50

# v1.3.1:连续 ASCII 可打印字符段切换到 Helvetica 字体,避免 STSong-Light
# 把英文/数字字符宽度压得太紧贴(中文字体下 Latin advance 偏窄)
# v1.6.10:扩展到 Latin-1 Supplement (U+00A0-U+00FF),覆盖西/法/德/葡/意全部带变音符
# Latin 字母(í/ñ/é/ü/ç/á/à/è/ò/ó/ú/â/î/ô/ê/û 等)。之前 í 等会 fall through 到
# STSong-Light(中文字体不含这些字形)→ 字体回退插诡异空格,如
# "Comparador de Envíos" 渲染成 "Comparador de Enví os"。
# Helvetica 的 WinAnsi 编码完整覆盖 0xA0-0xFF Latin-1 Supplement 区。
# 加 ‐-―(各种 dash)+ ‘-”(smart quotes)+ …(…)
# 提升西文标点支持,这些在 Helvetica 也可用。
_PDF_LATIN_RUN_RE = re.compile(r'[\x20-\x7E -ÿ‐-―‘-”…]+')


def _pdf_para_text(raw: Any) -> str:
    """Paragraph 输入文本预处理:
    1) XML escape(防 reportlab 解析器把 `<` `>` `&` 当标签/实体起点)
    2) 连续 ASCII 段包 `<font name="Helvetica">...</font>`,中文部分保持 STSong-Light
    返回的是已含合法 reportlab inline 标签的字符串,可直接喂给 Paragraph。"""
    s = '' if raw is None else str(raw)
    # XML escape;CR/LF 单行化(避免在表格单元格内强换行)
    s = (s.replace('&', '&amp;')
          .replace('<', '&lt;')
          .replace('>', '&gt;')
          .replace('\r', ' ')
          .replace('\n', ' '))
    return _PDF_LATIN_RUN_RE.sub(
        lambda m: f'<font name="Helvetica">{m.group(0)}</font>', s
    )


def _pdf_para(raw: Any, style, bold: bool = False) -> Any:
    """生成自动换行的表格单元格 Paragraph。raw 是任意用户文本,函数内 XML escape +
    中英字体回退。bold=True 时加 <b> 让 reportlab 合成粗体效果(STSong-Light 无 Bold variant)。"""
    if raw is None or raw == '':
        return ''
    txt = _pdf_para_text(raw)
    if bold:
        txt = f'<b>{txt}</b>'
    return _rl_paragraph(txt, style)


def _pdf_table_style(font_name: str, font_size: int = 9, *,
                     extra: Optional[list] = None) -> Any:
    """v1.4.4:Editorial 调性表格 — 报刊版式风格。
    - 表头:soft cream 底色(非纯白)+ 顶/底双线分隔
    - 数据行:无垂直线(只留水平细线),斑马 cream/white
    - padding 加大让数据呼吸"""
    ink = _rl_colors.HexColor('#0a0a0c')
    soft = _rl_colors.HexColor('#e8e3d6')
    cream = _rl_colors.HexColor('#fafaf5')
    base = [
        ('FONTNAME', (0, 0), (-1, -1), font_name),
        ('FONTSIZE', (0, 0), (-1, -1), font_size),
        # 表头:cream 浅底色,头部衬线感
        ('BACKGROUND', (0, 0), (-1, 0), soft),
        ('FONTSIZE', (0, 0), (-1, 0), font_size + 0.5),
        # 顶/底主线(报刊双线感)
        ('LINEABOVE', (0, 0), (-1, 0), 1.2, ink),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, ink),
        ('LINEBELOW', (0, -1), (-1, -1), 1.2, ink),
        # 数据行间细分隔(无垂直线)
        ('LINEBELOW', (0, 1), (-1, -2), 0.25, _rl_colors.HexColor('#c8c1ad')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        # padding 加大,让数据呼吸
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        # 斑马纹:cream/white 交替
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [cream, _rl_colors.HexColor('#ffffff')]),
    ]
    if extra:
        base.extend(extra)
    return _rl_table_style(base)


def _pdf_format_ips(a_records: list, aaaa_records: list) -> str:
    """格式化 IP 列:每个 IP 一行,> _PDF_MAX_IPS_SHOWN 截断显示 +N more。
    返回值已 XML escape + 中英字体回退 + 含 `<br/>` 标签,需直接 _rl_paragraph 渲染
    (不要再走 _pdf_para,会把 <br/> 转义掉)。"""
    ips = (a_records or []) + (aaaa_records or [])
    if not ips:
        return ''
    parts = [_pdf_para_text(ip) for ip in ips[:_PDF_MAX_IPS_SHOWN]]
    if len(ips) > _PDF_MAX_IPS_SHOWN:
        parts.append(_pdf_para_text(f'+{len(ips) - _PDF_MAX_IPS_SHOWN} more'))
    return '<br/>'.join(parts)


# 匹配 reportlab inline 标签(<b>、</b>、<font ...>、<br/> 等)
_PDF_INLINE_TAG_RE = re.compile(r'<[^>]+>')


def _pdf_inline_html(prepared: str) -> str:
    """开发者书写的含 inline 标签的字符串(如 `<b>命令</b>: ip`),把标签**之间**的纯文本
    段做 XML escape + 中英字体回退,标签本身原样保留。
    Caller 写 inline 标签时不需要在内容里手动 escape `& < >`,本函数会处理。"""
    if not prepared:
        return ''
    out: list = []
    last = 0
    for m in _PDF_INLINE_TAG_RE.finditer(prepared):
        out.append(_pdf_para_text(prepared[last:m.start()]))
        out.append(m.group(0))  # 标签原样
        last = m.end()
    out.append(_pdf_para_text(prepared[last:]))
    return ''.join(out)


def _pdf_story(prepared: str, style) -> Any:
    """story 段 Paragraph 工厂(支持 <b>/<i>/<br/> 等内联标签 + 自动中英字体回退)。
    用于标题、heading、元数据等"非表格单元格"位置。"""
    return _rl_paragraph(_pdf_inline_html(prepared), style)


def _to_pdf(prefix: str, data: Any, out_path: str) -> Optional[str]:
    """生成 PDF 报告（v1.1.0 新增）。需要 reportlab：pip install spyeyes[pdf]
    返回错误字符串（成功时返回 None）。
    设计取舍：直接复用 _to_markdown 生成的内容结构 → 转 reportlab Paragraph/Table，
    避免维护两套报告模板（markdown 已经过充分 escape，PDF 也安全）。
    """
    if not HAS_REPORTLAB:
        return t('err.no_pdf')
    try:
        cmd, _, query = prefix.partition('_')
        cmd = _md_escape(cmd) or '?'
        query = _md_escape(query)
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        # v1.3.1 修复:注册 CJK 字体让中文不显示成 □,并把所有 styles 字体改成它
        # (Helvetica/Times 不含 CJK glyph,reportlab 静默用 □ 替代)
        font_name = _register_pdf_cjk_font()
        styles = _rl_styles()
        for s_name in ('Normal', 'Title', 'Heading1', 'Heading2',
                       'Heading3', 'Code', 'BodyText'):
            if s_name in styles.byName:
                styles[s_name].fontName = font_name
        # 行高放宽 — STSong-Light 中文字符高,默认 leading 偏挤
        styles['Normal'].leading = 13
        styles['Normal'].fontSize = 9.5
        styles['Title'].leading = 38
        styles['Title'].fontSize = 32
        styles['Title'].spaceAfter = 0
        # v1.4.4:Heading2/3 美化 — 编辑信式衬线感 + accent 红 + 留白
        styles['Heading2'].leading = 22
        styles['Heading2'].fontSize = 17
        styles['Heading2'].spaceBefore = 22
        styles['Heading2'].spaceAfter = 10
        styles['Heading2'].textColor = _rl_colors.HexColor('#0a0a0c')
        styles['Heading3'].leading = 16
        styles['Heading3'].fontSize = 12
        styles['Heading3'].spaceBefore = 12
        styles['Heading3'].spaceAfter = 6
        styles['Heading3'].textColor = _rl_colors.HexColor('#c8102e')

        # v1.4.2:封面页 — Editorial Investigation Brief 调性
        # 类似 HTML masthead:CONFIDENTIAL stamp + 大标题 + classification + 元数据 + 双线分隔
        cover_classification = ('机密 · OSINT 简报' if get_lang() == 'zh'
                                 else 'CONFIDENTIAL · OSINT BRIEF')
        cover_subtitle = ('开源情报调查档案' if get_lang() == 'zh'
                          else 'Open-Source Intelligence Dossier')
        # CONFIDENTIAL 印章风(用 Table 给出红色边框 + center align)
        stamp_table = _rl_table(
            [[_pdf_story(f'<font color="#c8102e"><b>{_md_escape(cover_classification)}</b></font>',
                          styles['Normal'])]],
            colWidths=[260],
        )
        stamp_table.setStyle(_rl_table_style([
            ('BOX', (0, 0), (-1, -1), 1.5, _rl_colors.HexColor('#c8102e')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        story: list = []
        story.append(_rl_spacer(1, 80))
        # CONFIDENTIAL stamp
        story.append(stamp_table)
        story.append(_rl_spacer(1, 36))
        # 大标题 — 用 Title style(leading=38)避免高字号溢出 box 与 subtitle 重叠
        # 通过 ParagraphStyle alignment 而非 inline <para> 让 leading 生效
        from reportlab.lib.styles import ParagraphStyle as _RlPS  # type: ignore
        title_style = _RlPS(
            'CoverTitle', parent=styles['Title'],
            fontName=font_name, fontSize=32, leading=42,
            alignment=1,  # 1 = TA_CENTER
            spaceAfter=18,
        )
        subtitle_style = _RlPS(
            'CoverSubtitle', parent=styles['Normal'],
            fontName=font_name, fontSize=9, leading=14,
            alignment=1, textColor=_rl_colors.HexColor('#6b6657'),
            spaceBefore=0, spaceAfter=24,
        )
        story.append(_pdf_story(
            f'<b>{_md_escape(t("report.title"))}</b>', title_style))
        story.append(_pdf_story(
            _md_escape(cover_subtitle).upper(), subtitle_style))
        # 双线分隔
        story.append(_rl_hr(width='80%', thickness=2, color=_rl_colors.HexColor('#0a0a0c'),
                            hAlign='CENTER', spaceBefore=0, spaceAfter=4))
        story.append(_rl_hr(width='80%', thickness=0.5, color=_rl_colors.HexColor('#0a0a0c'),
                            hAlign='CENTER', spaceBefore=0, spaceAfter=14))
        # 元数据表(三列):命令 / 查询 / 生成时间
        meta_table = _rl_table([
            [_pdf_story(f'<para alignment="center"><font size="7" color="#6b6657">'
                        f'{_md_escape(t("report.command")).upper()}</font></para>', styles['Normal']),
             _pdf_story(f'<para alignment="center"><font size="7" color="#6b6657">'
                        f'{_md_escape(t("report.query")).upper()}</font></para>', styles['Normal']),
             _pdf_story(f'<para alignment="center"><font size="7" color="#6b6657">'
                        f'{_md_escape(t("report.generated")).upper()}</font></para>', styles['Normal'])],
            [_pdf_story(f'<para alignment="center"><b>{_md_escape(cmd)}</b></para>', styles['Normal']),
             _pdf_story(f'<para alignment="center"><b>{_md_escape(query)}</b></para>', styles['Normal']),
             _pdf_story(f'<para alignment="center"><b>{_md_escape(ts)}</b></para>', styles['Normal'])],
        ], colWidths=[140, 200, 140])
        meta_table.setStyle(_rl_table_style([
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)
        story.append(_rl_pagebreak())
        if isinstance(data, dict) and '_error' in data:
            story.append(_pdf_story(
                f"<b>{_md_escape(t('report.error'))}:</b> {_md_escape(data['_error'])}", styles['Normal']))
        elif cmd == 'username' and isinstance(data, dict):
            plat = _platform_only(data)
            found = sum(1 for v in plat.values() if v)
            story.append(_pdf_story(
                f"<b>{_md_escape(t('report.username_scan'))}:</b> {query}", styles['Heading2']))
            story.append(_pdf_story(
                _md_escape(t('report.scan_summary', total=len(plat), found=found)),
                styles['Normal']))
            story.append(_rl_spacer(1, 12))
            for cat in CATEGORY_ORDER:
                cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
                cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
                if not cat_found:
                    continue
                cat_label = _md_escape(t(f'cat.{cat}'))
                story.append(_pdf_story(
                    f"<b>{cat_label}</b> ({len(cat_found)}/{len(cat_pl)})",
                    styles['Heading3']))
                # v1.3.1:Paragraph 自动 XML escape + 中英字体回退 + bold 表头
                table_data = [[
                    _pdf_para(t('report.platform'), styles['Normal'], bold=True),
                    _pdf_para(t('report.url'), styles['Normal'], bold=True),
                ]]
                for p, url in cat_found:
                    table_data.append([
                        _pdf_para(p.name, styles['Normal']),
                        _pdf_para(url, styles['Normal']),
                    ])
                tbl = _rl_table(table_data, colWidths=[140, 380], repeatRows=1)
                tbl.setStyle(_pdf_table_style(font_name, 9))
                story.append(tbl)
                story.append(_rl_spacer(1, 12))
        elif cmd == 'permute' and _is_permute_only(data):
            # v1.2.1 P1-2：仅生成变形（不扫描）
            story.append(_pdf_story(
                f"<b>{_md_escape(t('permute.title'))}:</b> {_md_escape(data.get('name', query))}",
                styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            for v in data.get('permutations', []):
                story.append(_pdf_story(f"• {_md_escape(v)}", styles['Normal']))
        elif cmd == 'permute' and _is_permute_scan(data):
            # v1.2.1 P1-2：变形 + 批量扫描，每个变形一节
            story.append(_pdf_story(
                f"<b>{_md_escape(t('permute.title'))}:</b> {query}", styles['Heading2']))
            story.append(_pdf_story(
                f"{len(data)} variations scanned", styles['Normal']))
            story.append(_rl_spacer(1, 12))
            for var, scan in data.items():
                if not isinstance(scan, dict):
                    continue
                story.append(_pdf_story(f"<b>{_md_escape(var)}</b>", styles['Heading3']))
                if '_error' in scan:
                    story.append(_pdf_story(
                        f"{_md_escape(t('report.error'))}: {_md_escape(scan['_error'])}",
                        styles['Normal']))
                    story.append(_rl_spacer(1, 6))
                    continue
                plat = _platform_only(scan)
                found = sum(1 for v in plat.values() if v)
                story.append(_pdf_story(
                    _md_escape(t('report.scan_summary', total=len(plat), found=found)),
                    styles['Normal']))
                if found > 0:
                    p_table = [[
                        _pdf_para(t('report.platform'), styles['Normal'], bold=True),
                        _pdf_para(t('report.url'), styles['Normal'], bold=True),
                    ]]
                    for p_name, url in plat.items():
                        if url:
                            p_table.append([
                                _pdf_para(p_name, styles['Normal']),
                                _pdf_para(url, styles['Normal']),
                            ])
                    tbl = _rl_table(p_table, colWidths=[140, 380], repeatRows=1)
                    tbl.setStyle(_pdf_table_style(font_name, 9))
                    story.append(tbl)
                story.append(_rl_spacer(1, 10))
        elif cmd == 'mx' and isinstance(data, dict) and 'records' in data:
            # MX 专用（v1.2.1 P0-3 修复，之前落到通用 dict 把 records list 压成 repr）
            domain_lbl = _md_escape(data.get('domain', query))
            story.append(_pdf_story(
                f"<b>{_md_escape(t('report.mx_records'))}:</b> {domain_lbl}",
                styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            mx_table = [[
                _pdf_para(t('report.priority'), styles['Normal'], bold=True),
                _pdf_para(t('report.mail_server'), styles['Normal'], bold=True),
            ]]
            for r in data['records']:
                mx_table.append([
                    _pdf_para(r.get('preference', ''), styles['Normal']),
                    _pdf_para(r.get('exchange', ''), styles['Normal']),
                ])
            tbl = _rl_table(mx_table, colWidths=[60, 460], repeatRows=1)
            tbl.setStyle(_pdf_table_style(font_name, 10, extra=[
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # priority 列居中
            ]))
            story.append(tbl)
        elif cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
            # v1.4.0:域名邮箱 PDF 表格
            domain_lbl = _md_escape(data.get('domain', query))
            stats = data.get('_stats', {}) or {}
            sm_label = '✓' if stats.get('sitemap_found') else '✗'
            story.append(_pdf_story(
                f"<b>{_md_escape(t('demails.title', domain=domain_lbl))}</b>",
                styles['Heading2']))
            story.append(_pdf_story(
                _md_escape(t('demails.summary', total=stats.get('total', 0),
                             pages=stats.get('pages_crawled', 0), sitemap=sm_label)),
                styles['Normal']))
            story.append(_rl_spacer(1, 8))
            tbl_data = [[
                _pdf_para(t('demails.col_address'), styles['Normal'], bold=True),
                _pdf_para(t('demails.col_sources'), styles['Normal'], bold=True),
                _pdf_para(t('demails.col_page'), styles['Normal'], bold=True),
                _pdf_para(t('demails.col_verified'), styles['Normal'], bold=True),
            ]]
            for e in data.get('emails', []):
                ver = ''
                if e.get('verified') is True:
                    ver = '✓'
                elif e.get('verified') is False:
                    ver = '✗'
                tbl_data.append([
                    _pdf_para(e.get('address', ''), styles['Normal']),
                    _pdf_para(','.join(e.get('sources', [])), styles['Normal']),
                    _pdf_para((e.get('page') or '')[:80], styles['Normal']),
                    _pdf_para(ver, styles['Normal']),
                ])
            tbl = _rl_table(tbl_data, colWidths=[180, 110, 200, 30], repeatRows=1)
            tbl.setStyle(_pdf_table_style(font_name, 8))
            story.append(tbl)
        elif cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
            # v1.3.0:子域名枚举 PDF 表格
            domain_lbl = _md_escape(data.get('domain', query))
            stats = data.get('_stats', {}) or {}
            sources_active = sum(1 for v in (data.get('sources') or {}).values() if v > 0)
            story.append(_pdf_story(
                f"<b>{_md_escape(t('subdomain.title', domain=domain_lbl))}</b>",
                styles['Heading2']))
            story.append(_pdf_story(
                _md_escape(t('subdomain.summary',
                             total=stats.get('total', 0), alive=stats.get('alive', 0),
                             sources=sources_active)),
                styles['Normal']))
            # v1.6.8:PDF 加完整 6 源状态(用户反馈"X 个"太笼统)
            bd_pdf = _format_source_breakdown(data)
            if bd_pdf:
                story.append(_pdf_story(
                    f"<i>{_md_escape(t('subdomain.source_breakdown', breakdown=bd_pdf))}</i>",
                    styles['Normal']))
            if data.get('wildcard_suspect'):
                story.append(_pdf_story(
                    f"<b>⚠ {_md_escape(t('subdomain.wildcard_warn'))}</b>", styles['Normal']))
            story.append(_rl_spacer(1, 8))
            # v1.3.1:Paragraph 自动 XML escape + 中英字体回退;表头 bold;IP 列保留 <br/>
            header = [
                _pdf_para(t('subdomain.col_host'), styles['Normal'], bold=True),
                _pdf_para(t('subdomain.col_ip'), styles['Normal'], bold=True),
                _pdf_para(t('subdomain.col_cname'), styles['Normal'], bold=True),
                _pdf_para(t('subdomain.col_status'), styles['Normal'], bold=True),
                _pdf_para(t('subdomain.col_title'), styles['Normal'], bold=True),
            ]
            sub_table = [header]
            for s in data.get('subdomains', []):
                ips_html = _pdf_format_ips(s.get('a') or [], s.get('aaaa') or [])
                # ips_html 已 escape + 字体 mix,且含 <br/>,直接给 Paragraph(不要再走 _pdf_para)
                ips_cell = _rl_paragraph(ips_html, styles['Normal']) if ips_html else ''
                title = (s.get('title') or '')[:_PDF_MAX_TITLE_LEN]
                sub_table.append([
                    _pdf_para(s.get('host', ''), styles['Normal']),
                    ips_cell,
                    _pdf_para(s.get('cname') or '', styles['Normal']),
                    _pdf_para(s.get('http_status', '') or '', styles['Normal']),
                    _pdf_para(title, styles['Normal']),
                ])
            # 列宽合计 520pt(host 145 + ip 130 + cname 110 + status 45 + title 90),在 523 内
            tbl = _rl_table(sub_table, colWidths=[145, 130, 110, 45, 90], repeatRows=1)
            tbl.setStyle(_pdf_table_style(font_name, 8, extra=[
                ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # status 列居中
            ]))
            story.append(tbl)
        elif isinstance(data, dict):
            story.append(_pdf_story(
                f"<b>{cmd.upper()} {_md_escape(t('report.info_for'))}:</b> {query}", styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            items = data.items() if cmd != 'username' else _platform_only(data).items()
            table_data = [[
                _pdf_para(t('report.field'), styles['Normal'], bold=True),
                _pdf_para(t('report.value'), styles['Normal'], bold=True),
            ]]
            for k, v in items:
                if v is None or v == '':
                    continue
                if isinstance(v, dict):
                    v_str = ', '.join(f"{kk}={vv}" for kk, vv in v.items()
                                       if not isinstance(vv, (dict, list)))
                elif isinstance(v, (list, tuple)):
                    v_str = ', '.join(str(x) for x in v)
                else:
                    v_str = str(v)
                table_data.append([
                    _pdf_para(k, styles['Normal']),
                    _pdf_para(v_str, styles['Normal']),
                ])
            tbl = _rl_table(table_data, colWidths=[140, 380], repeatRows=1)
            tbl.setStyle(_pdf_table_style(font_name, 10))
            story.append(tbl)
        else:
            story.append(_pdf_story(
                _md_escape(json.dumps(data, ensure_ascii=False, default=str)),
                styles['Code']))
        # v1.3.1:用更小边距(36pt vs 默认 72pt)+ 字号统一,给宽表格更多空间
        # v1.4.2:topMargin 加大让封面页大标题有足够上空白
        doc = _rl_doc(out_path, pagesize=_rl_a4,
                      leftMargin=_PDF_MARGIN, rightMargin=_PDF_MARGIN,
                      topMargin=_PDF_MARGIN, bottomMargin=_PDF_MARGIN + 12)

        # v1.4.4:页脚用 Helvetica 字体 — 纯英文 brand 避免 STSong 的 Latin advance 偏窄
        # 字符串保持英文,中英两版统一(brand 名字"SpyEyes"是品牌不翻译)
        # 加 query 作为页脚右侧"running header"风格,提升页面信息密度
        page_footer_text = 'SpyEyes  ·  OSINT Toolkit'
        page_footer_query = f'{cmd}: {query}'[:60]

        def _draw_footer(canvas, _doc):
            canvas.saveState()
            # 一律用 Helvetica(英文字体),英文字符间距才舒服
            canvas.setFont('Helvetica', 7.5)
            canvas.setFillColor(_rl_colors.HexColor('#6b6657'))
            # 底部分隔线
            canvas.setStrokeColor(_rl_colors.HexColor('#0a0a0c'))
            canvas.setLineWidth(0.3)
            canvas.line(_PDF_MARGIN, 30, _rl_a4[0] - _PDF_MARGIN, 30)
            # 左侧 brand(英文,Helvetica 已经字符间距正常)
            canvas.drawString(_PDF_MARGIN, 18, page_footer_text)
            # 中间 query(用 mono 风格)— 但 canvas 没 mono 内置,继续 Helvetica 也 OK
            canvas.drawCentredString(_rl_a4[0] / 2, 18, page_footer_query)
            # 右侧页码
            canvas.drawRightString(_rl_a4[0] - _PDF_MARGIN, 18,
                                    f'p. {_doc.page}')
            canvas.restoreState()

        doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
        return None
    except Exception as e:
        return t('err.pdf_failed', e=e)


# ====================================================================
# v1.2.0: 报告格式扩充 —— HTML / TXT / CSV / XMind / Graph (D3.js)
# ====================================================================
def _html_escape(s: Any) -> str:
    """HTML/XML escape：防 `<script>` 注入、`"` 跳出属性值。
    用于 _to_html / _to_graph_html / _to_xmind。"""
    if s is None:
        return ''
    return (str(s)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def _is_permute_scan(data: Any) -> bool:
    """v1.2.1 P1-2：检测 permute_scan 数据形态 `{variation: track_result_dict, ...}`。
    permute_scan 来自 handle_choice(4) 的"变形+批量扫描"分支。
    与 permute_only 区分（后者是 `{'name': ..., 'permutations': [...]}`）。"""
    if not isinstance(data, dict) or '_error' in data or not data:
        return False
    # permute_only 标志键（明确排除）
    if 'permutations' in data or 'name' in data:
        return False
    # 所有 value 必须是 dict（track_username 结果），且至少一个含真实数据
    return (all(isinstance(v, dict) for v in data.values())
            and any(_platform_only(v) for v in data.values() if isinstance(v, dict)))


def _is_permute_only(data: Any) -> bool:
    """检测 permute_only 形态 `{'name': ..., 'permutations': [...]}`。"""
    return (isinstance(data, dict) and 'permutations' in data
            and isinstance(data.get('permutations'), list))


def _csv_safe(v: Any) -> str:
    """CSV injection 防护：单元格首字符为 = + - @ \\t \\r 时前置 ' 防 Excel/Sheets 执行公式。
    `csv` 模块已处理 | / , / \\n 转义，但对公式注入不防御。"""
    s = '' if v is None else str(v)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


def _to_html(prefix: str, data: Any) -> str:
    """生成 HTML 报告（独立文件，含基本 CSS 样式）。
    所有用户输入字段 _html_escape 防 XSS。
    v1.2.1：标题/标签跟随当前 UI 语言。"""
    cmd, _, query = prefix.partition('_')
    cmd_safe = _html_escape(cmd) or '?'
    query_safe = _html_escape(query)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    html_lang = 'zh' if get_lang() == 'zh' else 'en'
    title_safe = _html_escape(t('report.title'))

    # v1.4.1:Editorial Investigation Brief 风格 — 调查档案/报刊调性
    # 字体三件套:Cormorant Garamond (display) + Crimson Pro (body) + JetBrains Mono (data)
    # CJK fallback:Noto Serif SC + Sarasa Mono SC
    # 配色:cream + ink + 印章红 + 古典蓝 — 不用 purple gradient / 卡片阴影 / 圆角
    parts = [
        '<!DOCTYPE html>',
        f'<html lang="{html_lang}">',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<title>{title_safe} — {query_safe}</title>',
        '<link rel="preconnect" href="https://fonts.googleapis.com">',
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
        '<link href="https://fonts.googleapis.com/css2?'
        'family=Cormorant+Garamond:wght@400;500;600;700&'
        'family=Crimson+Pro:ital,wght@0,400;0,500;0,600;1,400&'
        'family=JetBrains+Mono:wght@400;500;700&'
        'family=Noto+Serif+SC:wght@400;500;700&display=swap" rel="stylesheet">',
        '<style>',
        ':root{',
        '--bg:#fafaf5;--surface:#fff;--ink:#0a0a0c;--rule:#0a0a0c;',
        '--muted:#6b6657;--soft:#e8e3d6;--row-alt:#f4f0e6;',
        '--accent:#c8102e;--link:#1d4ed8;--success:#1f5837;--warn:#a06800;',
        '--serif:"Cormorant Garamond","Noto Serif SC",Georgia,"Songti SC",serif;',
        '--body:"Crimson Pro","Noto Serif SC",Georgia,"Songti SC",serif;',
        '--mono:"JetBrains Mono","Sarasa Mono SC",ui-monospace,Menlo,monospace;',
        '}',
        '*{box-sizing:border-box}',
        'html,body{margin:0;padding:0}',
        'body{background:var(--bg);color:var(--ink);font-family:var(--body);'
        'font-size:17px;line-height:1.7;max-width:1280px;margin:3em auto;'
        'padding:0 3em 4em;letter-spacing:0.005em;'
        '-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}',
        '@media(max-width:1340px){body{max-width:none;margin:2em 4em 3em}}',
        '@media(max-width:720px){body{margin:1em;padding:0 1em 2em;font-size:15px}}',
        # Masthead 报刊头
        '.masthead{border-top:5px double var(--ink);border-bottom:5px double var(--ink);'
        'padding:1.6em 0 1.4em;margin-bottom:2.5em;text-align:center;position:relative}',
        '.stamp{display:inline-block;border:1.5px solid var(--accent);color:var(--accent);'
        'font-family:var(--mono);font-size:0.65em;letter-spacing:0.28em;'
        'text-transform:uppercase;padding:0.3em 0.9em;margin-bottom:0.8em;'
        'font-weight:700;transform:rotate(-1.5deg)}',
        '.masthead h1{font-family:var(--serif);font-weight:500;font-size:3.2em;'
        'line-height:1.05;letter-spacing:-0.03em;margin:0.1em 0;color:var(--ink)}',
        '.masthead .subtitle{font-family:var(--mono);font-size:0.7em;letter-spacing:0.35em;'
        'text-transform:uppercase;color:var(--muted);margin-top:0.4em}',
        # Meta strip
        '.meta{font-family:var(--mono);font-size:0.78em;display:grid;'
        'grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1.5em;'
        'padding:1em 0;border-bottom:1px solid var(--rule);margin-bottom:2em}',
        '.meta-item{display:flex;flex-direction:column;gap:0.3em}',
        '.meta-label{text-transform:uppercase;letter-spacing:0.18em;font-size:0.85em;'
        'color:var(--muted);font-weight:500}',
        '.meta-value{color:var(--ink);font-weight:700;word-break:break-all}',
        # Section headings
        'body{counter-reset:section}',
        'h2{font-family:var(--serif);font-weight:500;font-size:2em;line-height:1.2;'
        'margin:2.5em 0 0.8em;padding-bottom:0.4em;border-bottom:1px solid var(--rule);'
        'display:flex;align-items:baseline;gap:0.6em;letter-spacing:-0.01em}',
        'h2::before{content:counter(section,upper-roman);counter-increment:section;'
        'font-family:var(--mono);font-size:0.45em;color:var(--muted);'
        'letter-spacing:0.15em;font-weight:500;flex-shrink:0}',
        'h2 code{background:transparent;padding:0;font-size:0.8em;color:var(--accent)}',
        'h3,h3.cat{font-family:var(--serif);font-weight:600;font-size:1.3em;'
        'margin:1.8em 0 0.7em;padding-left:0.7em;border-left:3px solid var(--accent);'
        'color:var(--ink);letter-spacing:-0.005em}',
        # Tables — Editorial 报刊风:1.5px 双线 frame + zebra + hover
        # v1.4.5 修复:max-width 920→1280 + td:first-child nowrap 让长 hostname 完整一行,
        # 不再变 3 行阶梯。窄屏时(max-width:900px)允许 wrap 避免横向溢出
        'table{border-collapse:collapse;width:100%;margin:1em 0 1.5em;'
        'font-family:var(--mono);font-size:0.85em;background:var(--surface);'
        'border-top:1.5px solid var(--ink);border-bottom:1.5px solid var(--ink)}',
        'thead tr{border-bottom:1px solid var(--ink)}',
        # v1.4.6:sticky thead — 长列表滚动时表头始终可见
        'th{text-align:left;padding:0.85em 1em;font-family:var(--serif);'
        'font-weight:700;font-size:0.95em;letter-spacing:0.02em;color:var(--ink);'
        'background:var(--soft);border-bottom:1.5px solid var(--ink);'
        'white-space:nowrap;'
        'position:sticky;top:0;z-index:5;'
        # 阴影模拟"压在内容之上"的层次感
        'box-shadow:0 2px 0 0 var(--ink),0 4px 6px -2px rgba(10,10,12,0.1)}',
        'td{padding:0.7em 1em;border-bottom:1px solid #e8e3d6;vertical-align:top;'
        'word-break:normal;overflow-wrap:anywhere}',
        # 第一列(host/field)不断行,完整可读
        'td:first-child{white-space:nowrap;font-weight:500}',
        '@media(max-width:900px){td:first-child{white-space:normal}}',
        'tr:nth-child(even) td{background:var(--row-alt)}',
        # v1.4.6:alive/dead 视觉区分 — 左边框 3px 绿/灰
        'tr[data-alive="true"] td:first-child{border-left:3px solid #1f5837;'
        'padding-left:calc(1em - 3px)}',
        'tr[data-alive="false"] td:first-child{border-left:3px solid #c8c1ad;'
        'padding-left:calc(1em - 3px);color:var(--muted)}',
        'tr[data-alive="false"] td{color:var(--muted)}',
        # hover 加深 + 横向阴影
        'tbody tr:hover td{background:var(--soft);transition:background 0.15s ease}',
        'tbody tr:hover{box-shadow:inset 0 0 0 0.5px var(--ink)}',
        # v1.4.6:HTTP status code 颜色编码 — 一眼识别 2xx/3xx/4xx/5xx
        'td.status-ok{color:var(--success);font-weight:700}',
        'td.status-redir{color:var(--link);font-weight:600}',
        'td.status-warn{color:var(--warn);font-weight:600}',
        'td.status-err{color:var(--accent);font-weight:700}',
        # Links + code
        'a{color:var(--link);text-decoration:underline;'
        'text-decoration-thickness:0.5px;text-underline-offset:0.22em;'
        'transition:text-decoration-thickness 0.15s ease}',
        'a:hover{text-decoration-thickness:1.5px}',
        'code{font-family:var(--mono);background:var(--soft);'
        'padding:0.05em 0.45em;border-radius:1px;font-size:0.95em;'
        'color:var(--ink)}',
        # Status indicators
        '.error{color:#7a0a0a;background:#fdf3f3;border-left:4px solid var(--accent);'
        'padding:1em 1.4em;margin:1em 0;font-family:var(--body);font-style:italic}',
        '.error b{font-style:normal;text-transform:uppercase;'
        'letter-spacing:0.1em;font-size:0.85em;font-family:var(--mono)}',
        '.summary{font-family:var(--serif);font-size:1.15em;font-style:italic;'
        'color:var(--muted);margin:0.5em 0 1.5em;padding-left:1em;'
        'border-left:2px solid var(--soft)}',
        # Colophon footer
        '.colophon{margin-top:5em;padding-top:1.5em;border-top:1px solid var(--rule);'
        'font-family:var(--mono);font-size:0.7em;color:var(--muted);'
        'letter-spacing:0.18em;text-transform:uppercase;text-align:center}',
        '.colophon a{color:var(--muted);text-decoration:none}',
        '.colophon a:hover{color:var(--ink)}',
        # Print refinement
        '@media print{body{max-width:none;margin:0;padding:1em;font-size:11pt}'
        '.masthead,h2,h3{break-after:avoid}table{break-inside:avoid}}',
        '</style>',
        '</head><body>',
        '<header class="masthead">',
        f'<div class="stamp">{("机密 · OSINT 简报" if get_lang() == "zh" else "Confidential · OSINT Brief")}</div>',
        f'<h1>{title_safe}</h1>',
        f'<div class="subtitle">{("开源情报调查档案" if get_lang() == "zh" else "Open-Source Intelligence Dossier")}</div>',
        '</header>',
        '<div class="meta">',
        f'<div class="meta-item"><span class="meta-label">{_html_escape(t("report.command"))}</span>'
        f'<span class="meta-value">{cmd_safe}</span></div>',
        f'<div class="meta-item"><span class="meta-label">{_html_escape(t("report.query"))}</span>'
        f'<span class="meta-value">{query_safe}</span></div>',
        f'<div class="meta-item"><span class="meta-label">{_html_escape(t("report.generated"))}</span>'
        f'<span class="meta-value">{ts}</span></div>',
        '</div>',
    ]

    if isinstance(data, dict) and '_error' in data:
        parts.append(
            f'<div class="error">❌ <b>{_html_escape(t("report.error"))}:</b> '
            f'{_html_escape(data["_error"])}</div>'
        )
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    if cmd == 'username' and isinstance(data, dict):
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        parts.append(
            f'<h2>{_html_escape(t("report.username_scan"))}: '
            f'<code>{query_safe}</code></h2>'
        )
        parts.append(
            f'<p><b>{_html_escape(t("report.scan_summary", total=len(plat), found=found))}</b></p>'
        )
        for cat in CATEGORY_ORDER:
            cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
            cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
            if not cat_found:
                continue
            cat_label = _html_escape(t(f'cat.{cat}'))
            parts.append(
                f'<h3 class="cat">{cat_label} ({len(cat_found)}/{len(cat_pl)})</h3>'
            )
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("report.platform"))}</th>'
                f'<th>{_html_escape(t("report.url"))}</th>'
                '</tr></thead><tbody>'
            )
            for p, url in cat_found:
                url_safe = _html_escape(url)
                parts.append(
                    f'<tr><td>{_html_escape(p.name)}</td>'
                    f'<td><a href="{url_safe}" target="_blank" rel="noopener noreferrer">{url_safe}</a></td></tr>'
                )
            parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # v1.2.1 P1-2: permute 仅生成变形 —— 列表
    if cmd == 'permute' and _is_permute_only(data):
        name_safe = _html_escape(data.get('name', query))
        parts.append(f'<h2>{_html_escape(t("permute.title"))} <code>{name_safe}</code></h2>')
        parts.append('<ul>')
        for v in data.get('permutations', []):
            parts.append(f'<li><code>{_html_escape(v)}</code></li>')
        parts.append('</ul>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # v1.2.1 P1-2: permute + 批量扫描 —— 每个变形一个子节
    if cmd == 'permute' and _is_permute_scan(data):
        parts.append(f'<h2>{_html_escape(t("permute.title"))} <code>{query_safe}</code></h2>')
        parts.append(f'<p><b>{len(data)} variations scanned</b></p>')
        for var, scan in data.items():
            if not isinstance(scan, dict):
                continue
            parts.append(f'<h3 class="cat"><code>{_html_escape(var)}</code></h3>')
            if '_error' in scan:
                parts.append(f'<div class="error">❌ {_html_escape(scan["_error"])}</div>')
                continue
            plat = _platform_only(scan)
            found = sum(1 for v in plat.values() if v)
            parts.append(
                f'<p>{_html_escape(t("report.scan_summary", total=len(plat), found=found))}</p>'
            )
            if found == 0:
                continue
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("report.platform"))}</th>'
                f'<th>{_html_escape(t("report.url"))}</th>'
                '</tr></thead><tbody>'
            )
            for p_name, url in plat.items():
                if url:
                    url_safe = _html_escape(url)
                    parts.append(
                        f'<tr><td>{_html_escape(p_name)}</td>'
                        f'<td><a href="{url_safe}" target="_blank" rel="noopener noreferrer">{url_safe}</a></td></tr>'
                    )
            parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # v1.4.0: domain-emails HTML 报告
    if cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
        domain_safe = _html_escape(data.get('domain', query))
        stats = data.get('_stats', {}) or {}
        sm_label = '✓' if stats.get('sitemap_found') else '✗'
        parts.append(f'<h2>{_html_escape(t("demails.title", domain=domain_safe))}</h2>')
        parts.append(
            f'<p><b>{_html_escape(t("demails.summary", total=stats.get("total", 0), pages=stats.get("pages_crawled", 0), sitemap=sm_label))}</b></p>'
        )
        if not data.get('emails'):
            parts.append(f'<p><i>{_html_escape(t("demails.no_results"))}</i></p>')
        else:
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("demails.col_address"))}</th>'
                f'<th>{_html_escape(t("demails.col_sources"))}</th>'
                f'<th>{_html_escape(t("demails.col_page"))}</th>'
                f'<th>{_html_escape(t("demails.col_verified"))}</th>'
                '</tr></thead><tbody>'
            )
            for e in data['emails']:
                addr_safe = _html_escape(e.get('address', ''))
                page = e.get('page') or ''
                page_html = (f'<a href="{_html_escape(page)}" target="_blank" rel="noopener noreferrer">{_html_escape(page)[:60]}</a>'
                             if page else '')
                ver = ''
                if e.get('verified') is True:
                    ver = '✓'
                elif e.get('verified') is False:
                    ver = '✗'
                parts.append(
                    f'<tr><td><a href="mailto:{addr_safe}">{addr_safe}</a></td>'
                    f'<td>{_html_escape(",".join(e.get("sources", [])))}</td>'
                    f'<td>{page_html}</td>'
                    f'<td>{_html_escape(ver)}</td></tr>'
                )
            parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # v1.3.0: subdomain 枚举 — 表格 host / IP / CNAME / status / title
    if cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
        domain_safe = _html_escape(data.get('domain', query))
        stats = data.get('_stats', {}) or {}
        sources_active = sum(1 for v in (data.get('sources') or {}).values() if v > 0)
        parts.append(
            f'<h2>{_html_escape(t("subdomain.title", domain=domain_safe))}</h2>'
        )
        parts.append(
            f'<p><b>{_html_escape(t("subdomain.summary", total=stats.get("total", 0), alive=stats.get("alive", 0), sources=sources_active))}</b></p>'
        )
        # v1.6.8:HTML 加完整 6 源状态行(用户反馈"X 个数据源"太笼统)
        bd_html = _format_source_breakdown(data)
        if bd_html:
            parts.append(
                f'<p style="font-size: 0.92em; color: #5a5550; margin-top: -0.5em;">'
                f'<i>{_html_escape(t("subdomain.source_breakdown", breakdown=bd_html))}</i></p>'
            )
        if data.get('wildcard_suspect'):
            parts.append(
                f'<div class="error">⚠ {_html_escape(t("subdomain.wildcard_warn"))}</div>'
            )
        if not data.get('subdomains'):
            parts.append(f'<p><i>{_html_escape(t("subdomain.no_results"))}</i></p>')
        else:
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("subdomain.col_host"))}</th>'
                f'<th>{_html_escape(t("subdomain.col_ip"))}</th>'
                f'<th>{_html_escape(t("subdomain.col_cname"))}</th>'
                f'<th>{_html_escape(t("subdomain.col_status"))}</th>'
                f'<th>{_html_escape(t("subdomain.col_title"))}</th>'
                '</tr></thead><tbody>'
            )
            for s in data['subdomains']:
                ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
                status = s.get('http_status')
                status_str = str(status) if status is not None else ''
                title = s.get('title') or ''
                host = s.get('host') or ''
                alive = bool(s.get('alive'))
                # v1.4.6:所有 host 都可点击 — alive 用真实 scheme(已 probe);
                # dead 默认 https(用户能直接尝试访问)
                scheme = s.get('scheme') or 'https'
                href = f'{scheme}://{_html_escape(host)}/'
                host_html = (f'<a href="{href}" target="_blank" rel="noopener noreferrer">'
                             f'{_html_escape(host)}</a>')
                # status 单元格:有数字时按 2xx/3xx/4xx/5xx 加颜色 class
                status_class = ''
                if status is not None:
                    if 200 <= status < 300:
                        status_class = ' class="status-ok"'
                    elif 300 <= status < 400:
                        status_class = ' class="status-redir"'
                    elif 400 <= status < 500:
                        status_class = ' class="status-warn"'
                    else:
                        status_class = ' class="status-err"'
                parts.append(
                    f'<tr data-alive="{"true" if alive else "false"}">'
                    f'<td>{host_html}</td>'
                    f'<td>{_html_escape(ips)}</td>'
                    f'<td>{_html_escape(s.get("cname") or "")}</td>'
                    f'<td{status_class}>{_html_escape(status_str)}</td>'
                    f'<td>{_html_escape(title)}</td></tr>'
                )
            parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # MX 专用：渲染优先级表（v1.2.1 P0-3 修复，之前会落到通用 dict 把 records list 压成 repr）
    if cmd == 'mx' and isinstance(data, dict) and 'records' in data:
        domain_safe = _html_escape(data.get('domain', query))
        parts.append(
            f'<h2>{_html_escape(t("report.mx_records"))} '
            f'<code>{domain_safe}</code></h2>'
        )
        parts.append(
            '<table><thead><tr>'
            f'<th>{_html_escape(t("report.priority"))}</th>'
            f'<th>{_html_escape(t("report.mail_server"))}</th>'
            '</tr></thead><tbody>'
        )
        for r in data['records']:
            parts.append(
                f'<tr><td>{_html_escape(r.get("preference", ""))}</td>'
                f'<td><code>{_html_escape(r.get("exchange", ""))}</code></td></tr>'
            )
        parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    # v1.7.0: investigate 综合调查 — 6 sections,Editorial 调性沿用主 CSS
    if cmd == 'investigate' and isinstance(data, dict) and 'tasks' in data:
        target_safe = _html_escape(data.get('target', query))
        stats = data.get('_stats', {}) or {}
        parts.append(
            f'<h2>{_html_escape(t("investigate.title", target=target_safe))}</h2>'
        )
        parts.append(
            f'<p class="summary"><b>{_html_escape(t("investigate.summary", tasks_done=stats.get("tasks_done", 0), tasks_failed=stats.get("tasks_failed", 0), pivots_done=stats.get("pivots_done", 0), elapsed=data.get("elapsed", 0)))}</b></p>'
        )
        if stats.get('budget_exceeded'):
            parts.append(
                f'<div class="error"><b>⚠</b> {_html_escape(t("investigate.budget_exceeded"))}</div>'
            )
        trunc = stats.get('truncated') or {}
        if trunc.get('ips') or trunc.get('emails'):
            parts.append(
                f'<p class="summary"><i>{_html_escape(t("investigate.truncated", ips=trunc.get("ips", 0), emails=trunc.get("emails", 0)))}</i></p>'
            )
        tasks = data.get('tasks') or {}
        pivots = data.get('pivots') or {}

        # I. WHOIS
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_whois"))}</h3>')
        w = tasks.get('whois') or {}
        if isinstance(w, dict) and '_error' in w:
            parts.append(f'<div class="error">❌ {_html_escape(w["_error"])}</div>')
        elif isinstance(w, dict):
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("report.field"))}</th>'
                f'<th>{_html_escape(t("report.value"))}</th>'
                '</tr></thead><tbody>'
            )
            for k in ('registrar', 'creation_date', 'expiration_date', 'name_servers',
                      'emails', 'org', 'country'):
                v = w.get(k)
                if v is None or v == '':
                    continue
                if isinstance(v, list):
                    v_str = ', '.join(str(x) for x in v)
                else:
                    v_str = str(v)
                parts.append(
                    f'<tr><td><code>{_html_escape(k)}</code></td>'
                    f'<td>{_html_escape(v_str)}</td></tr>'
                )
            parts.append('</tbody></table>')

        # II. MX
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_mx"))}</h3>')
        mx = tasks.get('mx') or {}
        if isinstance(mx, dict) and '_error' in mx:
            parts.append(f'<div class="error">❌ {_html_escape(mx["_error"])}</div>')
        elif isinstance(mx, dict) and mx.get('records'):
            parts.append(
                '<table><thead><tr>'
                f'<th>{_html_escape(t("report.priority"))}</th>'
                f'<th>{_html_escape(t("report.mail_server"))}</th>'
                '</tr></thead><tbody>'
            )
            for r in mx['records']:
                parts.append(
                    f'<tr><td>{_html_escape(r.get("preference", ""))}</td>'
                    f'<td><code>{_html_escape(r.get("exchange", ""))}</code></td></tr>'
                )
            parts.append('</tbody></table>')

        # III. Subdomain
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_subdomain"))}</h3>')
        sub = tasks.get('subdomain') or {}
        if isinstance(sub, dict) and '_error' in sub:
            parts.append(f'<div class="error">❌ {_html_escape(sub["_error"])}</div>')
        elif isinstance(sub, dict):
            subs = sub.get('subdomains') or []
            alive_subs = [s for s in subs if isinstance(s, dict) and s.get('alive')]
            sub_stats = sub.get('_stats') or {}
            parts.append(
                f'<p><b>{_html_escape(t("investigate.subdomain_summary", alive=len(alive_subs), total=sub_stats.get("total", 0)))}</b></p>'
            )
            if alive_subs:
                parts.append(
                    '<table><thead><tr>'
                    f'<th>{_html_escape(t("subdomain.col_host"))}</th>'
                    f'<th>{_html_escape(t("subdomain.col_ip"))}</th>'
                    f'<th>{_html_escape(t("subdomain.col_status"))}</th>'
                    '</tr></thead><tbody>'
                )
                for s in alive_subs:
                    host = s.get('host', '')
                    ip_list_str = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
                    status = s.get('http_status')
                    scheme = s.get('scheme') or 'https'
                    href = f'{scheme}://{_html_escape(host)}/'
                    host_html = (f'<a href="{href}" target="_blank" rel="noopener noreferrer">'
                                 f'{_html_escape(host)}</a>')
                    parts.append(
                        f'<tr data-alive="true">'
                        f'<td>{host_html}</td>'
                        f'<td>{_html_escape(ip_list_str)}</td>'
                        f'<td>{_html_escape(str(status) if status is not None else "")}</td></tr>'
                    )
                parts.append('</tbody></table>')

        # IV. IP pivot
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_ip_pivot"))}</h3>')
        ip_pivot = pivots.get('ips') or {}
        if not ip_pivot:
            parts.append(f'<p><i>{_html_escape(t("investigate.no_data"))}</i></p>')
        else:
            parts.append(
                '<table><thead><tr>'
                '<th>IP</th>'
                f'<th>{_html_escape(t("field.country"))}</th>'
                f'<th>{_html_escape(t("field.org"))}</th>'
                '</tr></thead><tbody>'
            )
            for ip, ipd in ip_pivot.items():
                if isinstance(ipd, dict) and '_error' in ipd:
                    parts.append(
                        f'<tr><td><code>{_html_escape(ip)}</code></td>'
                        f'<td colspan="2">❌ {_html_escape(ipd["_error"])}</td></tr>'
                    )
                elif isinstance(ipd, dict):
                    country = ipd.get('country') or '-'
                    conn = ipd.get('connection') if isinstance(ipd.get('connection'), dict) else None
                    org = (conn.get('org') if conn else None) or ipd.get('org') or '-'
                    parts.append(
                        f'<tr><td><code>{_html_escape(ip)}</code></td>'
                        f'<td>{_html_escape(country)}</td>'
                        f'<td>{_html_escape(str(org))}</td></tr>'
                    )
            parts.append('</tbody></table>')

        # V. Emails
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_emails"))}</h3>')
        em = tasks.get('emails') or {}
        if isinstance(em, dict) and '_error' in em:
            parts.append(f'<div class="error">❌ {_html_escape(em["_error"])}</div>')
        elif isinstance(em, dict):
            em_list = em.get('emails') or []
            em_stats = em.get('_stats') or {}
            parts.append(
                f'<p><b>{_html_escape(t("investigate.email_summary", total=em_stats.get("total", 0), pages=em_stats.get("pages_crawled", 0)))}</b></p>'
            )
            if em_list:
                parts.append(
                    '<table><thead><tr>'
                    f'<th>{_html_escape(t("demails.col_address"))}</th>'
                    f'<th>{_html_escape(t("demails.col_sources"))}</th>'
                    '</tr></thead><tbody>'
                )
                for e in em_list:
                    if isinstance(e, dict):
                        addr_safe = _html_escape(e.get('address', ''))
                        srcs = ','.join(e.get('sources') or [])
                        parts.append(
                            f'<tr><td><a href="mailto:{addr_safe}">{addr_safe}</a></td>'
                            f'<td>{_html_escape(srcs)}</td></tr>'
                        )
                parts.append('</tbody></table>')

        # VI. User pivot
        parts.append(f'<h3 class="cat">{_html_escape(t("investigate.section_user_pivot"))}</h3>')
        users = pivots.get('users') or {}
        if not users:
            parts.append(f'<p><i>{_html_escape(t("investigate.no_data"))}</i></p>')
        else:
            for addr, ud in users.items():
                if not isinstance(ud, dict):
                    continue
                local = ud.get('local_part', '')
                parts.append(
                    f'<h4><code>{_html_escape(addr)}</code> '
                    f'(<code>{_html_escape(local)}</code>)</h4>'
                )
                if '_error' in ud:
                    parts.append(f'<div class="error">❌ {_html_escape(ud["_error"])}</div>')
                    continue
                result = ud.get('result') or {}
                hits = [(k, v) for k, v in result.items() if not k.startswith('_') and v]
                if not hits:
                    parts.append(f'<p><i>{_html_escape(t("investigate.no_data"))}</i></p>')
                    continue
                parts.append(
                    '<table><thead><tr>'
                    f'<th>{_html_escape(t("report.platform"))}</th>'
                    f'<th>{_html_escape(t("report.url"))}</th>'
                    '</tr></thead><tbody>'
                )
                for plat, url in hits:
                    url_safe = _html_escape(url)
                    parts.append(
                        f'<tr><td>{_html_escape(plat)}</td>'
                        f'<td><a href="{url_safe}" target="_blank" rel="noopener noreferrer">{url_safe}</a></td></tr>'
                    )
                parts.append('</tbody></table>')

        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    if isinstance(data, dict):
        parts.append(
            f'<h2>{cmd_safe.upper()} {_html_escape(t("report.info_for"))}: '
            f'<code>{query_safe}</code></h2>'
        )
        parts.append(
            '<table><thead><tr>'
            f'<th>{_html_escape(t("report.field"))}</th>'
            f'<th>{_html_escape(t("report.value"))}</th>'
            '</tr></thead><tbody>'
        )
        items = data.items() if cmd != 'username' else _platform_only(data).items()
        for k, v in items:
            if v is None or v == '':
                continue
            if isinstance(v, dict):
                v_str = ', '.join(f'{kk}={vv}' for kk, vv in v.items()
                                  if not isinstance(vv, (dict, list)))
            elif isinstance(v, (list, tuple)):
                v_str = ', '.join(str(x) for x in v)
            else:
                v_str = str(v)
            parts.append(
                f'<tr><td>{_html_escape(k)}</td><td>{_html_escape(v_str)}</td></tr>'
            )
        parts.append('</tbody></table>')
        parts.extend([
            '<footer class="colophon">',
            'Generated by <a href="https://github.com/Akxan/SpyEyes" target="_blank" rel="noopener noreferrer">SpyEyes</a>',
            ' · OSINT Toolkit',
            '</footer>',
            '</body>', '</html>'
        ])
        return '\n'.join(parts)

    parts.append(
        f'<pre>{_html_escape(json.dumps(data, ensure_ascii=False, indent=2, default=str))}</pre>'
    )
    parts.extend(['</body>', '</html>'])
    return '\n'.join(parts)


def _to_txt(prefix: str, data: Any) -> str:
    """纯文本报告（无 ANSI 颜色 / 无 markdown / 无表格）。
    适合复制粘贴到 ticket / issue / 邮件。
    v1.2.1：标题/标签跟随当前 UI 语言。"""
    cmd, _, query = prefix.partition('_')
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    # v1.4.1:像调查档案打字机/电传报告 — 双线 + 装饰角 + 整齐 ALIGN COLUMN
    title = t('report.title').upper()
    classification = '机密 · OSINT 简报' if get_lang() == 'zh' else 'CONFIDENTIAL · OSINT BRIEF'
    width = 70
    title_padded = title.center(width - 4)
    classification_padded = classification.center(width - 4)
    lines = [
        '╔' + '═' * (width - 2) + '╗',
        '║ ' + title_padded + ' ║',
        '║ ' + classification_padded + ' ║',
        '╚' + '═' * (width - 2) + '╝',
        '',
        f'  {t("report.command").upper():>10}  │  {cmd}',
        f'  {t("report.query").upper():>10}  │  {query}',
        f'  {t("report.generated").upper():>10}  │  {ts}',
        '',
        '  ' + '─' * (width - 4),
        '',
    ]
    if isinstance(data, dict) and '_error' in data:
        lines.append(f'  ✗ {t("report.error").upper()}: {data["_error"]}')
        lines.append('')
        return '\n'.join(lines) + '\n'

    if cmd == 'username' and isinstance(data, dict):
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        lines.append(f'{t("report.username_scan")}: {query}')
        lines.append(t('report.scan_summary', total=len(plat), found=found))
        lines.append('')
        for cat in CATEGORY_ORDER:
            cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
            cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
            if not cat_found:
                continue
            lines.append(f'── {t(f"cat.{cat}")} ({len(cat_found)}/{len(cat_pl)}) ──')
            for p, url in cat_found:
                lines.append(f'  {p.name:30} {url}')
            lines.append('')
        return '\n'.join(lines) + '\n'

    # v1.2.1 P1-2: permute 仅生成变形 —— 列表
    if cmd == 'permute' and _is_permute_only(data):
        lines.append(f'{t("permute.title")} {data.get("name", query)}')
        lines.append('')
        for v in data.get('permutations', []):
            lines.append(f'  • {v}')
        return '\n'.join(lines) + '\n'

    # v1.2.1 P1-2: permute + 批量扫描 —— 每个变形一个段
    if cmd == 'permute' and _is_permute_scan(data):
        lines.append(f'{t("permute.title")} {query}')
        lines.append(f'{len(data)} variations scanned')
        lines.append('')
        for var, scan in data.items():
            if not isinstance(scan, dict):
                continue
            lines.append(f'━━━ {var} ━━━')
            if '_error' in scan:
                lines.append(f'  {t("report.error")}: {scan["_error"]}')
                lines.append('')
                continue
            plat = _platform_only(scan)
            found = sum(1 for v in plat.values() if v)
            lines.append(f'  {t("report.scan_summary", total=len(plat), found=found)}')
            for p_name, url in plat.items():
                if url:
                    lines.append(f'    {p_name:28} {url}')
            lines.append('')
        return '\n'.join(lines) + '\n'

    # MX 专用（v1.2.1 P0-3 修复）
    if cmd == 'mx' and isinstance(data, dict) and 'records' in data:
        lines.append(f'{t("report.mx_records")} {data.get("domain", query)}')
        lines.append('')
        for r in data['records']:
            lines.append(f'  {t("report.priority")} {r.get("preference", ""):>4}  →  '
                         f'{r.get("exchange", "")}')
        return '\n'.join(lines) + '\n'

    # v1.4.0: domain-emails TXT 报告
    if cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
        domain_lbl = data.get('domain', query)
        stats = data.get('_stats', {}) or {}
        sm_label = '✓' if stats.get('sitemap_found') else '✗'
        lines.append(t('demails.title', domain=domain_lbl))
        lines.append(t('demails.summary', total=stats.get('total', 0),
                       pages=stats.get('pages_crawled', 0), sitemap=sm_label))
        lines.append('')
        if not data.get('emails'):
            lines.append(t('demails.no_results'))
            return '\n'.join(lines) + '\n'
        for e in data['emails']:
            srcs = ','.join(e.get('sources', []))
            ver = ''
            if e.get('verified') is True:
                ver = '  [verified]'
            elif e.get('verified') is False:
                ver = '  [unverified]'
            page = f'  ← {e.get("page")}' if e.get('page') else ''
            lines.append(f'  {e.get("address", "")} ({srcs}){ver}{page}')
        return '\n'.join(lines) + '\n'

    # v1.3.0: subdomain 枚举 TXT
    if cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
        domain_lbl = data.get('domain', query)
        stats = data.get('_stats', {}) or {}
        sources_active = sum(1 for v in (data.get('sources') or {}).values() if v > 0)
        lines.append(t('subdomain.title', domain=domain_lbl))
        lines.append(t('subdomain.summary', total=stats.get('total', 0),
                       alive=stats.get('alive', 0), sources=sources_active))
        # v1.6.8:加完整 6 源状态
        bd = _format_source_breakdown(data)
        if bd:
            lines.append(t('subdomain.source_breakdown', breakdown=bd))
        if data.get('wildcard_suspect'):
            lines.append(f'⚠ {t("subdomain.wildcard_warn")}')
        lines.append('')
        if not data.get('subdomains'):
            lines.append(t('subdomain.no_results'))
            return '\n'.join(lines) + '\n'
        for s in data['subdomains']:
            host = s.get('host', '')
            ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
            cname = s.get('cname') or ''
            status = s.get('http_status')
            status_str = f'HTTP {status}' if status else ''
            title = s.get('title') or ''
            mark = '+' if s.get('alive') else '-'
            extra = []
            if ips:
                extra.append(ips)
            if cname:
                extra.append(f'CNAME→{cname}')
            if status_str:
                extra.append(status_str)
            if title:
                extra.append(title[:60])
            lines.append(f'  [{mark}] {host:40}  {"  |  ".join(extra)}')
        return '\n'.join(lines) + '\n'

    # v1.7.0: investigate 综合调查 — 纯文本 6 sections,平铺易复制
    if cmd == 'investigate' and isinstance(data, dict) and 'tasks' in data:
        target_lbl = data.get('target', query)
        stats = data.get('_stats', {}) or {}
        lines.append(t('investigate.title', target=target_lbl))
        lines.append(t('investigate.summary',
                       tasks_done=stats.get('tasks_done', 0),
                       tasks_failed=stats.get('tasks_failed', 0),
                       pivots_done=stats.get('pivots_done', 0),
                       elapsed=data.get('elapsed', 0)))
        if stats.get('budget_exceeded'):
            lines.append(f'⚠ {t("investigate.budget_exceeded")}')
        trunc = stats.get('truncated') or {}
        if trunc.get('ips') or trunc.get('emails'):
            lines.append(t('investigate.truncated',
                           ips=trunc.get('ips', 0), emails=trunc.get('emails', 0)))
        lines.append('')

        tasks = data.get('tasks') or {}
        pivots = data.get('pivots') or {}

        def _section(title: str) -> None:
            lines.append('── ' + title + ' ──')

        # WHOIS
        _section(t('investigate.section_whois'))
        w = tasks.get('whois') or {}
        if isinstance(w, dict) and '_error' in w:
            lines.append(f'  ✗ {w["_error"]}')
        elif isinstance(w, dict):
            for k in ('registrar', 'creation_date', 'expiration_date',
                      'name_servers', 'emails', 'org', 'country'):
                v = w.get(k)
                if v is None or v == '':
                    continue
                if isinstance(v, list):
                    v = ', '.join(str(x) for x in v)
                lines.append(f'  {k:20}: {v}')
        lines.append('')

        # MX
        _section(t('investigate.section_mx'))
        mx = tasks.get('mx') or {}
        if isinstance(mx, dict) and '_error' in mx:
            lines.append(f'  ✗ {mx["_error"]}')
        elif isinstance(mx, dict):
            for r in (mx.get('records') or []):
                lines.append(f'  [{r.get("preference", "-"):>3}]  {r.get("exchange", "")}')
        lines.append('')

        # Subdomain
        _section(t('investigate.section_subdomain'))
        sub = tasks.get('subdomain') or {}
        if isinstance(sub, dict) and '_error' in sub:
            lines.append(f'  ✗ {sub["_error"]}')
        elif isinstance(sub, dict):
            subs = sub.get('subdomains') or []
            alive = [s for s in subs if isinstance(s, dict) and s.get('alive')]
            sub_stats = sub.get('_stats') or {}
            lines.append(t('investigate.subdomain_summary',
                           alive=len(alive), total=sub_stats.get('total', 0)))
            for s in alive:
                ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
                lines.append(f'  [+] {s.get("host", ""):40} {ips}')
        lines.append('')

        # IP pivot
        _section(t('investigate.section_ip_pivot'))
        ips_p = pivots.get('ips') or {}
        if not ips_p:
            lines.append(f'  ({t("investigate.no_data")})')
        else:
            for ip, ipd in ips_p.items():
                if isinstance(ipd, dict) and '_error' in ipd:
                    lines.append(f'  ✗ {ip}: {ipd["_error"]}')
                elif isinstance(ipd, dict):
                    country = ipd.get('country') or '-'
                    conn = ipd.get('connection') if isinstance(ipd.get('connection'), dict) else None
                    org = (conn.get('org') if conn else None) or ipd.get('org') or '-'
                    lines.append(f'  [+] {ip:18} {country:15}  {str(org)[:40]}')
        lines.append('')

        # Emails
        _section(t('investigate.section_emails'))
        em = tasks.get('emails') or {}
        if isinstance(em, dict) and '_error' in em:
            lines.append(f'  ✗ {em["_error"]}')
        elif isinstance(em, dict):
            em_list = em.get('emails') or []
            em_stats = em.get('_stats') or {}
            lines.append(t('investigate.email_summary',
                           total=em_stats.get('total', 0),
                           pages=em_stats.get('pages_crawled', 0)))
            for e in em_list:
                if isinstance(e, dict):
                    addr = e.get('address', '')
                    srcs = ','.join(e.get('sources') or [])
                    lines.append(f'  [+] {addr:45}  ({srcs})')
        lines.append('')

        # User pivot
        _section(t('investigate.section_user_pivot'))
        users = pivots.get('users') or {}
        if not users:
            lines.append(f'  ({t("investigate.no_data")})')
        else:
            for addr, ud in users.items():
                if not isinstance(ud, dict):
                    continue
                local = ud.get('local_part', '')
                if '_error' in ud:
                    lines.append(f'  ✗ {addr} ({local}): {ud["_error"]}')
                    continue
                result = ud.get('result') or {}
                hits = [(k, v) for k, v in result.items() if not k.startswith('_') and v]
                lines.append(f'  [+] {addr} ({local}) → {len(hits)} hits')
                for plat, url in hits:
                    lines.append(f'        {plat:25} {url}')
        lines.append('')
        return '\n'.join(lines) + '\n'

    if isinstance(data, dict):
        lines.append(f'{cmd.upper()} {t("report.info_for")}: {query}')
        lines.append('')
        items = data.items() if cmd != 'username' else _platform_only(data).items()
        for k, v in items:
            if v is None or v == '':
                continue
            if isinstance(v, dict):
                v_str = ', '.join(f'{kk}={vv}' for kk, vv in v.items()
                                  if not isinstance(vv, (dict, list)))
            elif isinstance(v, (list, tuple)):
                v_str = ', '.join(str(x) for x in v)
            else:
                v_str = str(v)
            lines.append(f'  {k:22}: {v_str}')
        return '\n'.join(lines) + '\n'

    lines.append(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    return '\n'.join(lines) + '\n'


def _to_csv(prefix: str, data: Any) -> str:
    """CSV 报告。
    - username 扫描：rows = (category, platform, url, status) 仅命中
    - 其它：rows = (field, value)
    含 CSV injection 防护（_csv_safe 给 = + - @ 前缀加 '）。
    v1.2.1：列头跟随当前 UI 语言（zh: 分类/平台/主页地址/状态）。
    注意：CSV 列头的本地化在脚本消费时可能影响 `df['platform']` 类访问，
    需要稳定列名的用户请用 `--lang en` 或直接读 JSON。"""
    cmd, _, query = prefix.partition('_')
    buf = _io.StringIO()
    writer = _csv.writer(buf, lineterminator='\n', quoting=_csv.QUOTE_MINIMAL)

    if isinstance(data, dict) and '_error' in data:
        writer.writerow([t('report.error').lower()])
        writer.writerow([_csv_safe(data['_error'])])
        return buf.getvalue()

    if cmd == 'username' and isinstance(data, dict):
        writer.writerow([
            t('report.category'), t('report.platform'),
            t('report.url'), t('report.status'),
        ])
        plat = _platform_only(data)
        statuses = data.get('_statuses', {}) if isinstance(data, dict) else {}
        for cat in CATEGORY_ORDER:
            cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
            for p in cat_pl:
                url = plat.get(p.name) or ''
                if not url:
                    continue
                status = statuses.get(p.name, 'found')
                # cat 仍用英文 enum 值（机器可读），p.name 保留原名
                writer.writerow([_csv_safe(cat), _csv_safe(p.name),
                                 _csv_safe(url), _csv_safe(status)])
        return buf.getvalue()

    # v1.2.1 P1-2: permute 仅生成变形 —— 单列变形清单
    if cmd == 'permute' and _is_permute_only(data):
        writer.writerow([t('permute.title')])
        for v in data.get('permutations', []):
            writer.writerow([_csv_safe(v)])
        return buf.getvalue()

    # v1.2.1 P1-2: permute + 批量扫描 —— 每行 (variation, category, platform, url)
    if cmd == 'permute' and _is_permute_scan(data):
        writer.writerow([
            t('report.username_scan'), t('report.category'),
            t('report.platform'), t('report.url'),
        ])
        for var, scan in data.items():
            if not isinstance(scan, dict) or '_error' in scan:
                continue
            plat = _platform_only(scan)
            cat_lookup = {p.name: p.category for p in _get_platforms()}
            for p_name, url in plat.items():
                if url:
                    writer.writerow([_csv_safe(var),
                                     _csv_safe(cat_lookup.get(p_name, 'other')),
                                     _csv_safe(p_name), _csv_safe(url)])
        return buf.getvalue()

    # MX 专用（v1.2.1 P0-3 修复）
    if cmd == 'mx' and isinstance(data, dict) and 'records' in data:
        writer.writerow([t('report.priority'), t('report.mail_server')])
        for r in data['records']:
            writer.writerow([_csv_safe(r.get('preference', '')),
                             _csv_safe(r.get('exchange', ''))])
        return buf.getvalue()

    # v1.4.0: domain-emails CSV — address, sources, page, verified
    if cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
        writer.writerow([
            t('demails.col_address'), t('demails.col_sources'),
            t('demails.col_page'), t('demails.col_verified'),
        ])
        for e in data.get('emails', []):
            ver = ''
            if e.get('verified') is True:
                ver = '1'
            elif e.get('verified') is False:
                ver = '0'
            writer.writerow([
                _csv_safe(e.get('address', '')),
                _csv_safe(','.join(e.get('sources', []))),
                _csv_safe(e.get('page') or ''),
                _csv_safe(ver),
            ])
        return buf.getvalue()

    # v1.3.0: subdomain 枚举 CSV — host, alive, a, aaaa, cname, http_status, title
    if cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
        writer.writerow([
            t('subdomain.col_host'), 'alive',
            'a', 'aaaa', t('subdomain.col_cname'),
            t('subdomain.col_status'), t('subdomain.col_title'),
        ])
        for s in data.get('subdomains', []):
            writer.writerow([
                _csv_safe(s.get('host', '')),
                _csv_safe('1' if s.get('alive') else '0'),
                _csv_safe(','.join(s.get('a') or [])),
                _csv_safe(','.join(s.get('aaaa') or [])),
                _csv_safe(s.get('cname') or ''),
                _csv_safe(s.get('http_status') if s.get('http_status') is not None else ''),
                _csv_safe(s.get('title') or ''),
            ])
        return buf.getvalue()

    # v1.7.0: investigate 综合调查 — section, kind, value 三列宽表(扁平)
    # 让 BI / spreadsheet pivot 时按 section / kind 切片直接可用
    if cmd == 'investigate' and isinstance(data, dict) and 'tasks' in data:
        writer.writerow(['section', 'kind', 'key', 'value'])
        target_lbl = data.get('target', query)
        writer.writerow(['meta', 'target', '', _csv_safe(target_lbl)])
        writer.writerow(['meta', 'elapsed', '', _csv_safe(data.get('elapsed', 0))])
        tasks = data.get('tasks') or {}
        pivots = data.get('pivots') or {}

        w = tasks.get('whois') or {}
        if isinstance(w, dict):
            if '_error' in w:
                writer.writerow(['whois', 'error', '', _csv_safe(w['_error'])])
            else:
                for k, v in w.items():
                    if v is None or v == '':
                        continue
                    if isinstance(v, list):
                        v = ', '.join(str(x) for x in v)
                    writer.writerow(['whois', 'field', _csv_safe(k), _csv_safe(str(v))])

        mx = tasks.get('mx') or {}
        if isinstance(mx, dict):
            if '_error' in mx:
                writer.writerow(['mx', 'error', '', _csv_safe(mx['_error'])])
            else:
                for r in (mx.get('records') or []):
                    writer.writerow(['mx', 'record',
                                     _csv_safe(str(r.get('preference', ''))),
                                     _csv_safe(r.get('exchange', ''))])

        sub = tasks.get('subdomain') or {}
        if isinstance(sub, dict):
            if '_error' in sub:
                writer.writerow(['subdomain', 'error', '', _csv_safe(sub['_error'])])
            else:
                for s in (sub.get('subdomains') or []):
                    if isinstance(s, dict) and s.get('alive'):
                        ips = ', '.join((s.get('a') or []) + (s.get('aaaa') or []))
                        writer.writerow(['subdomain', 'alive',
                                         _csv_safe(s.get('host', '')), _csv_safe(ips)])

        for ip, ipd in (pivots.get('ips') or {}).items():
            if isinstance(ipd, dict) and '_error' in ipd:
                writer.writerow(['ip_pivot', 'error', _csv_safe(ip), _csv_safe(ipd['_error'])])
            elif isinstance(ipd, dict):
                country = ipd.get('country') or ''
                conn = ipd.get('connection') if isinstance(ipd.get('connection'), dict) else None
                org = (conn.get('org') if conn else None) or ipd.get('org') or ''
                writer.writerow(['ip_pivot', 'enriched',
                                 _csv_safe(ip), _csv_safe(f'{country} | {org}')])

        em = tasks.get('emails') or {}
        if isinstance(em, dict):
            if '_error' in em:
                writer.writerow(['email', 'error', '', _csv_safe(em['_error'])])
            else:
                for e in (em.get('emails') or []):
                    if isinstance(e, dict):
                        writer.writerow(['email', 'address',
                                         _csv_safe(e.get('address', '')),
                                         _csv_safe(','.join(e.get('sources') or []))])

        for addr, ud in (pivots.get('users') or {}).items():
            if not isinstance(ud, dict):
                continue
            local = ud.get('local_part', '')
            if '_error' in ud:
                writer.writerow(['user_pivot', 'error',
                                 _csv_safe(f'{addr} ({local})'), _csv_safe(ud['_error'])])
                continue
            result = ud.get('result') or {}
            for plat, url in result.items():
                if plat.startswith('_') or not url:
                    continue
                writer.writerow(['user_pivot', 'hit',
                                 _csv_safe(f'{addr}|{plat}'), _csv_safe(url)])
        return buf.getvalue()

    if isinstance(data, dict):
        writer.writerow([t('report.field'), t('report.value')])
        items = data.items() if cmd != 'username' else _platform_only(data).items()
        for k, v in items:
            if v is None or v == '':
                continue
            if isinstance(v, dict):
                v_str = ', '.join(f'{kk}={vv}' for kk, vv in v.items()
                                  if not isinstance(vv, (dict, list)))
            elif isinstance(v, (list, tuple)):
                v_str = ', '.join(str(x) for x in v)
            else:
                v_str = str(v)
            writer.writerow([_csv_safe(k), _csv_safe(v_str)])
        return buf.getvalue()

    writer.writerow(['data'])
    writer.writerow([_csv_safe(json.dumps(data, ensure_ascii=False, default=str))])
    return buf.getvalue()


def _to_xmind(prefix: str, data: Any, out_path: str) -> Optional[str]:
    """XMind 8 文件(zip 含 content.xml + meta.xml + manifest.xml),纯标准库实现。
    无新依赖;XMind 8 可直接打开。返回错误字符串(成功时返回 None)。
    v1.4.2:加 marker-refs(XMind 内置图标)让节点视觉分级清晰 + emoji prefix。"""
    try:
        cmd, _, query = prefix.partition('_')
        ts = time.strftime('%Y-%m-%d %H:%M:%S')

        def _topic(title: str, children: Optional[list] = None,
                   href: Optional[str] = None,
                   markers: Optional[list] = None) -> str:
            """生成 XMind topic XML。markers 是 XMind 内置 marker ID 列表
            (如 'task-done' / 'flag-red' / 'symbol-warning' 等),
            会渲染为节点旁的彩色图标。"""
            tid = _uuid.uuid4().hex
            href_attr = f' xlink:href="{_html_escape(href)}"' if href else ''
            inner = f'<title>{_html_escape(title)}</title>'
            if markers:
                refs = ''.join(f'<marker-ref marker-id="{_html_escape(m)}"/>'
                               for m in markers)
                inner += f'<marker-refs>{refs}</marker-refs>'
            if children:
                kids = ''.join(children)
                inner += f'<children><topics type="attached">{kids}</topics></children>'
            return f'<topic id="{tid}"{href_attr}>{inner}</topic>'

        # 元数据节点(每个报告都有,显示生成时间 + 命令)
        meta_topic = _topic(
            f'⏱  {t("report.generated")}: {ts}',
            markers=['symbol-info'],
        )

        if isinstance(data, dict) and '_error' in data:
            sub_topics = [meta_topic, _topic(
                f'{t("report.error")}: {data["_error"]}',
                markers=['flag-red', 'symbol-warning'],
            )]
        elif cmd == 'username' and isinstance(data, dict):
            sub_topics = [meta_topic]
            plat = _platform_only(data)
            for cat in CATEGORY_ORDER:
                cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
                cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
                if not cat_found:
                    continue
                cat_kids = [_topic(p.name, href=url, markers=['task-done'])
                            for p, url in cat_found]
                sub_topics.append(_topic(
                    f'{t(f"cat.{cat}")} ({len(cat_found)}/{len(cat_pl)})',
                    cat_kids,
                    markers=['flag-blue'],
                ))
        elif cmd == 'permute' and _is_permute_only(data):
            sub_topics = [meta_topic]
            for v in data.get('permutations', []):
                sub_topics.append(_topic(v, markers=['priority-1']))
        elif cmd == 'permute' and _is_permute_scan(data):
            sub_topics = [meta_topic]
            for var, scan in data.items():
                if not isinstance(scan, dict):
                    continue
                if '_error' in scan:
                    sub_topics.append(_topic(
                        f'{var}: {t("report.error")} {scan["_error"]}',
                        markers=['flag-red'],
                    ))
                    continue
                plat = _platform_only(scan)
                p_kids = [_topic(p_name, href=url, markers=['task-done'])
                          for p_name, url in plat.items() if url]
                found = len(p_kids)
                sub_topics.append(_topic(
                    f'{var} ({found} hits)', p_kids,
                    markers=['flag-purple'] if found else ['flag-orange'],
                ))
        elif cmd == 'mx' and isinstance(data, dict) and 'records' in data:
            domain_lbl = data.get('domain', query)
            mx_kids = []
            for r in data['records']:
                pref = r.get('preference', '')
                exch = r.get('exchange', '')
                # priority-1..9 标记数字 1-9 越小优先级越高(MX 同义)
                prio_marker = (f'priority-{min(int(pref), 9)}'
                               if isinstance(pref, int) and pref >= 1 else 'priority-1')
                mx_kids.append(_topic(
                    f'{t("report.priority")} {pref} → {exch}',
                    markers=[prio_marker],
                ))
            sub_topics = [meta_topic, _topic(
                f'📧 {t("report.mx_records")} {domain_lbl}', mx_kids,
                markers=['symbol-tip'],
            )]
        elif cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
            sub_topics = [meta_topic]
            stats = data.get('_stats', {}) or {}
            sub_topics.append(_topic(
                f'📊 共 {stats.get("total", 0)} 个邮箱 · 爬取 {stats.get("pages_crawled", 0)} 页',
                markers=['symbol-info'],
            ))
            groups: dict = {'passive': [], 'crawl': [], 'pattern': []}
            for e in data.get('emails', []):
                srcs = set(e.get('sources', []))
                if 'pattern' in srcs and not (srcs & {'crtsh', 'whois', 'crawl'}):
                    groups['pattern'].append(e)
                elif 'crawl' in srcs:
                    groups['crawl'].append(e)
                else:
                    groups['passive'].append(e)
            # 每分组用不同 flag 颜色 + 不同 marker
            section_meta = {
                'passive': ('demails.section_passive', 'flag-blue', 'symbol-info'),
                'crawl': ('demails.section_crawl', 'flag-green', 'symbol-attention'),
                'pattern': ('demails.section_pattern', 'flag-purple', 'symbol-question'),
            }
            for key in ('passive', 'crawl', 'pattern'):
                items = groups[key]
                if not items:
                    continue
                label_key, group_marker, item_marker = section_meta[key]
                kids = []
                for e in items:
                    addr = e.get('address', '')
                    href = f'mailto:{addr}'
                    # verified ✓ → task-done;unverified ✗ → flag-red;未验证 → 默认
                    if e.get('verified') is True:
                        kids.append(_topic(addr, href=href,
                                           markers=['task-done', item_marker]))
                    elif e.get('verified') is False:
                        kids.append(_topic(addr, href=href,
                                           markers=['flag-red', item_marker]))
                    else:
                        kids.append(_topic(addr, href=href,
                                           markers=[item_marker]))
                sub_topics.append(_topic(
                    f'{t(label_key)} ({len(items)})', kids,
                    markers=[group_marker],
                ))
        elif cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
            # v1.4.4 重做:充分利用 XMind 层级 — host 节点只显 host,IP/CNAME/Title 各占一层子节点
            # 这样收起时简洁(扫一眼 host),展开时详细
            alive_kids = []
            dead_kids = []
            for s in data.get('subdomains', []):
                host = s.get('host', '')
                status = s.get('http_status')
                # host 标题:简洁显示 host + 可选 status code(只一个数字)
                if s.get('alive') and status:
                    host_label = f'{host}  ·  HTTP {status}'
                else:
                    host_label = host
                # alive 子域 host 可点击跳转
                href = None
                if s.get('alive') and s.get('scheme'):
                    href = f'{s["scheme"]}://{host}/'
                # 子节点:IPv4 / IPv6 / CNAME / Title 各一层
                kids = []
                a_records = s.get('a') or []
                aaaa_records = s.get('aaaa') or []
                if a_records:
                    ipv4_kids = [_topic(ip) for ip in a_records]
                    kids.append(_topic(
                        f'📡 IPv4 ({len(a_records)})', ipv4_kids,
                        markers=['symbol-tip'],
                    ))
                if aaaa_records:
                    ipv6_kids = [_topic(ip) for ip in aaaa_records]
                    kids.append(_topic(
                        f'📡 IPv6 ({len(aaaa_records)})', ipv6_kids,
                        markers=['symbol-tip'],
                    ))
                if s.get('cname'):
                    kids.append(_topic(
                        f'🔗 CNAME → {s["cname"]}',
                        markers=['symbol-info'],
                    ))
                title_text = s.get('title')
                if title_text:
                    # v1.4.4:不再用 `<title>:` 看起来像 HTML 残留,改成 "📄 Title:"
                    title_label = ('📄 标题' if get_lang() == 'zh' else '📄 Title')
                    kids.append(_topic(
                        f'{title_label}: {title_text}',
                        markers=['symbol-info'],
                    ))
                # 状态码 → marker
                status_marker = 'task-done'
                if status:
                    if 200 <= status < 300:
                        status_marker = 'task-done'
                    elif 300 <= status < 400:
                        status_marker = 'task-3quar'
                    elif 400 <= status < 500:
                        status_marker = 'flag-orange'
                    elif status >= 500:
                        status_marker = 'flag-red'
                topic = _topic(host_label, kids if kids else None, href=href,
                               markers=[status_marker if s.get('alive') else 'task-start'])
                if s.get('alive'):
                    alive_kids.append(topic)
                else:
                    dead_kids.append(topic)
            sub_topics = [meta_topic]
            # 概要节点 — 给用户先看到统计
            stats = data.get('_stats', {}) or {}
            sources = data.get('sources', {}) or {}
            sources_active = sum(1 for v in sources.values() if v > 0)
            sub_topics.append(_topic(
                f'📊 {t("subdomain.summary", total=stats.get("total", 0), alive=stats.get("alive", 0), sources=sources_active)}',
                markers=['symbol-info'],
            ))
            if data.get('wildcard_suspect'):
                sub_topics.append(_topic(
                    f'⚠ {t("subdomain.wildcard_warn")}',
                    markers=['symbol-warning', 'flag-red'],
                ))
            if alive_kids:
                sub_topics.append(_topic(
                    f'✓ {t("subdomain.alive_section")} ({len(alive_kids)})',
                    alive_kids, markers=['flag-green'],
                ))
            if dead_kids:
                sub_topics.append(_topic(
                    f'✗ {t("subdomain.dead_section")} ({len(dead_kids)})',
                    dead_kids, markers=['task-start'],
                ))
        elif isinstance(data, dict):
            sub_topics = [meta_topic]
            items = data.items() if cmd != 'username' else _platform_only(data).items()
            for k, v in items:
                if v is None or v == '':
                    continue
                if isinstance(v, dict):
                    v_str = ', '.join(f'{kk}={vv}' for kk, vv in v.items()
                                      if not isinstance(vv, (dict, list)))
                elif isinstance(v, (list, tuple)):
                    v_str = ', '.join(str(x) for x in v)
                else:
                    v_str = str(v)
                sub_topics.append(_topic(f'{k}: {v_str}'))
        else:
            sub_topics = [meta_topic, _topic(
                json.dumps(data, ensure_ascii=False, default=str)
            )]

        root_id = _uuid.uuid4().hex
        kids_xml = ''.join(sub_topics)
        children_xml = (f'<children><topics type="attached">{kids_xml}</topics></children>'
                       if sub_topics else '')

        # v1.4.2:每个 cmd 类型有独立 emoji,让 root 节点视觉识别度高
        _XMIND_CMD_EMOJI = {
            'ip': '🌐', 'myip': '📡', 'phone': '📱', 'username': '👤',
            'permute': '🧬', 'whois': '🔍', 'mx': '📧', 'email': '✉️',
            'subdomain': '🌐', 'domain-emails': '📧', 'history': '🕐',
        }
        emoji = _XMIND_CMD_EMOJI.get(cmd, '🔎')
        # root title:emoji + 报告名 + cmd · query(支持中英)
        root_title = f'{emoji} {t("report.title")} · {cmd} · {query}'
        # 根节点也加 marker(star-red 强调)
        root_markers_xml = '<marker-refs><marker-ref marker-id="star-red"/></marker-refs>'
        # sheet title 双语
        sheet_title = f'{t("report.title")} — {query}'

        content_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
            '<xmap-content xmlns="urn:xmind:xmap:xmlns:content:2.0" '
            'xmlns:xlink="http://www.w3.org/1999/xlink" '
            f'version="2.0" timestamp="{int(time.time() * 1000)}">'
            '<sheet id="sheet1">'
            f'<title>{_html_escape(sheet_title)}</title>'
            f'<topic id="{root_id}">'
            f'<title>{_html_escape(root_title)}</title>'
            f'{root_markers_xml}'
            f'{children_xml}'
            '</topic>'
            '</sheet>'
            '</xmap-content>'
        )
        manifest_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
            '<manifest xmlns="urn:xmind:xmap:xmlns:manifest:1.0">'
            '<file-entry full-path="content.xml" media-type="text/xml"/>'
            '<file-entry full-path="META-INF/manifest.xml" media-type="text/xml"/>'
            '</manifest>'
        )
        meta_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
            '<meta xmlns="urn:xmind:xmap:xmlns:meta:2.0">'
            '<Creator><Name>SpyEyes</Name></Creator>'
            '</meta>'
        )

        with _zipfile.ZipFile(out_path, 'w', _zipfile.ZIP_DEFLATED) as zf:
            # v1.2.1 P2-11：XMind 8 spec 推荐 mimetype 作为第一个 zip 条目（uncompressed），
            # 类似 EPUB；提升与不同 XMind 版本的兼容性
            mimetype_info = _zipfile.ZipInfo('mimetype')
            mimetype_info.compress_type = _zipfile.ZIP_STORED
            zf.writestr(mimetype_info, 'application/vnd.xmind.workbook')
            zf.writestr('content.xml', content_xml)
            zf.writestr('meta.xml', meta_xml)
            zf.writestr('META-INF/manifest.xml', manifest_xml)
        return None
    except Exception as e:
        return f'XMind generation failed: {e}'


def _to_graph_html(prefix: str, data: Any) -> str:
    """D3.js force-directed 图（独立 HTML，D3 from CDN）。
    仅用户名扫描有意义；其它命令 fallback 为简单 HTML。

    安全：
    - 用户输入字段 _html_escape 防 XSS
    - JSON 嵌入 <script> 时把 `</` 转义为 `<\\/` 防 </script> 注入
    """
    cmd, _, query = prefix.partition('_')
    query_safe = _html_escape(query)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')

    # username 扫描：构建节点 / 链接
    nodes: list = [{'id': query, 'group': 1, 'name': query, 'url': ''}]
    links: list = []
    cat_lookup = {p.name: p.category for p in _get_platforms()}
    if cmd == 'username' and isinstance(data, dict) and '_error' not in data:
        plat = _platform_only(data)
        for p_name, url in plat.items():
            if not url:
                continue
            nodes.append({
                'id': f'p_{p_name}',
                'group': 2,
                'name': p_name,
                'url': url,
                'category': cat_lookup.get(p_name, 'other'),
            })
            links.append({'source': query, 'target': f'p_{p_name}', 'value': 1})
    elif cmd == 'permute' and _is_permute_scan(data):
        # v1.2.1 P1-2: 多中心图 —— 每个变形一个 group=1 节点，命中平台为 group=2 子节点
        # 重置 nodes：原始 query 不参与（用户通常想看每个 variation 的命中分布）
        nodes = []
        for var, scan in data.items():
            if not isinstance(scan, dict) or '_error' in scan:
                continue
            nodes.append({'id': var, 'group': 1, 'name': var, 'url': ''})
            plat = _platform_only(scan)
            for p_name, url in plat.items():
                if not url:
                    continue
                node_id = f'{var}__p_{p_name}'  # 防 var 之间平台重名冲突
                nodes.append({
                    'id': node_id, 'group': 2, 'name': p_name, 'url': url,
                    'category': cat_lookup.get(p_name, 'other'),
                })
                links.append({'source': var, 'target': node_id, 'value': 1})
    elif cmd == 'domain-emails' and isinstance(data, dict) and 'emails' in data:
        # v1.4.0: 域名邮箱力导向图 —— domain 中心 + email 节点(按 source 颜色分组)
        nodes = [{'id': data.get('domain', query), 'group': 1,
                  'name': data.get('domain', query), 'url': ''}]
        root_id = data.get('domain', query)
        # group:passive=2 / crawl=3 / pattern=4
        src_to_group = {'crtsh': 2, 'whois': 2, 'crawl': 3, 'pattern': 4}
        for e in data.get('emails', []):
            addr = e.get('address', '')
            if not addr:
                continue
            srcs = e.get('sources', [])
            grp = max((src_to_group.get(s, 2) for s in srcs), default=2)
            nodes.append({
                'id': f'em_{addr}',
                'group': grp,
                'name': addr,
                'url': f'mailto:{addr}',
            })
            links.append({'source': root_id, 'target': f'em_{addr}', 'value': 1})
    elif cmd == 'subdomain' and isinstance(data, dict) and 'subdomains' in data:
        # v1.3.0: 子域名力导向图 —— root domain (group=1) + alive 子域 (group=2) + dead (group=3)
        nodes = [{'id': data.get('domain', query), 'group': 1,
                  'name': data.get('domain', query), 'url': ''}]
        root_id = data.get('domain', query)
        for s in data.get('subdomains', []):
            host = s.get('host', '')
            if not host or host == root_id:
                continue
            alive = s.get('alive')
            url = ''
            if alive and s.get('scheme'):
                url = f'{s["scheme"]}://{host}/'
            nodes.append({
                'id': f'sd_{host}',
                'group': 2 if alive else 3,
                'name': host,
                'url': url,
            })
            links.append({'source': root_id, 'target': f'sd_{host}', 'value': 1})
    elif isinstance(data, dict) and '_error' in data:
        # 非 username 命令也允许导出 graph，仅展示 query 单节点 + 错误提示
        nodes.append({'id': 'err', 'group': 3, 'name': data['_error'], 'url': ''})
        links.append({'source': query, 'target': 'err', 'value': 1})

    # </script> 注入防护：把 </ 转义
    nodes_json = json.dumps(nodes, ensure_ascii=False).replace('</', '<\\/')
    links_json = json.dumps(links, ensure_ascii=False).replace('</', '<\\/')

    # 节点数越多需要越大的力 + 越大的画布；自适应避免被 viewport 裁剪
    node_count = len(nodes)
    initial_radius = max(400, int(20 * (node_count ** 0.5)))
    html_lang = 'zh' if get_lang() == 'zh' else 'en'
    graph_title = _html_escape(t('report.graph_title'))
    graph_help_safe = _html_escape(t('report.graph_help'))
    found_n_safe = _html_escape(t('report.graph_found', n=len(nodes) - 1))
    legend_q = _html_escape(t('report.legend_query'))
    legend_h = _html_escape(t('report.legend_hit'))
    legend_o = _html_escape(t('report.legend_other'))
    gen_label = _html_escape(t('report.generated'))
    return f'''<!DOCTYPE html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{graph_title} — {query_safe}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600&family=JetBrains+Mono:wght@400;500;700&family=Noto+Serif+SC:wght@500;700&display=swap" rel="stylesheet">
<style>
:root {{
  /* v1.4.4:浅色 Editorial 主题(用户反馈不要深色)*/
  --bg: #fafaf5;
  --surface: #ffffff;
  --ink: #0a0a0c;
  --muted: #6b6657;
  --rule: #0a0a0c;
  --soft: #e8e3d6;
  --accent: #c8102e;        /* 印章红 — 主节点 query */
  --hit: #1d4ed8;           /* 古典蓝 — 命中 */
  --other: #6b6657;         /* 暗灰 — 错误/其它 */
  --link-color: rgba(10,10,12,0.18);
  --link-hover: rgba(200,16,46,0.5);
  --serif: "Cormorant Garamond","Noto Serif SC",Georgia,serif;
  --mono: "JetBrains Mono",ui-monospace,Menlo,monospace;
}}
* {{ box-sizing: border-box; }}
html, body {{ height: 100%; margin: 0; overflow: hidden; }}
body {{
  background: var(--bg);
  color: var(--ink);
  font-family: var(--mono);
  display: flex;
  flex-direction: column;
}}
.header {{
  padding: 1.2em 2em 1em;
  background: rgba(250,250,245,0.96);
  border-bottom: 5px double var(--ink);
  flex-shrink: 0;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 10;
}}
.eyebrow {{
  font-family: var(--mono); font-size: 0.65em; letter-spacing: 0.4em;
  text-transform: uppercase; color: var(--accent); margin-bottom: 0.35em;
  font-weight: 700;
}}
.header h2 {{
  font-family: var(--serif); font-weight: 500; font-size: 1.85em;
  margin: 0; color: var(--ink); letter-spacing: -0.02em; line-height: 1.1;
}}
.header h2 em {{
  font-style: italic; color: var(--accent); font-weight: 600;
  text-decoration: underline; text-decoration-color: rgba(200,16,46,0.35);
  text-underline-offset: 0.18em; text-decoration-thickness: 1px;
}}
.meta-row {{
  font-family: var(--mono); color: var(--muted); margin: 0.6em 0 0;
  font-size: 0.78em; letter-spacing: 0.04em;
}}
.meta-row span {{ color: var(--ink); font-weight: 500; }}
.legend {{
  display: flex; gap: 1.5em; margin-top: 0.7em;
  font-family: var(--mono); font-size: 0.72em; color: var(--muted);
  flex-wrap: wrap; letter-spacing: 0.05em;
}}
.legend span {{ display: flex; align-items: center; gap: 0.4em; }}
.legend i {{
  display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  box-shadow: 0 0 0 1px rgba(0,0,0,0.08);
}}
.legend kbd {{
  background: var(--soft); border: 1px solid var(--rule);
  padding: 1px 6px; font-size: 0.95em; border-radius: 2px;
  color: var(--ink); font-family: var(--mono); font-weight: 700;
}}
.node circle {{
  stroke: var(--surface); stroke-width: 1.5px;
  filter: drop-shadow(0 1px 2px rgba(0,0,0,0.15));
  transition: filter 0.2s ease, stroke-width 0.2s ease;
}}
.node:hover circle {{
  filter: drop-shadow(0 2px 6px rgba(0,0,0,0.25));
  stroke-width: 2.5px;
}}
.node text {{
  font-family: var(--mono); font-size: 11px; font-weight: 500;
  pointer-events: none; fill: var(--ink);
  paint-order: stroke; stroke: rgba(250,250,245,0.95); stroke-width: 3px;
  letter-spacing: 0.02em;
}}
.node[data-group="1"] text {{
  font-family: var(--serif); font-size: 14px; font-weight: 600;
  fill: var(--accent); letter-spacing: 0.01em;
}}
.link {{ stroke: var(--link-color); stroke-width: 1px; }}
svg {{
  flex: 1 1 auto; width: 100%; cursor: grab; display: block;
  background: var(--bg);
}}
svg:active {{ cursor: grabbing; }}
.colophon {{
  position: fixed; bottom: 0.6em; right: 1em;
  font-family: var(--mono); font-size: 0.65em;
  color: var(--muted); letter-spacing: 0.15em;
  text-transform: uppercase; pointer-events: none;
  background: rgba(250,250,245,0.7);
  padding: 2px 6px; border-radius: 2px;
}}
</style>
</head>
<body>
<div class="header">
  <div class="eyebrow">{("情报关系图谱" if html_lang == "zh" else "Intelligence Graph")}</div>
  <h2>{graph_title}: <em>{query_safe}</em></h2>
  <div class="meta-row">
    <span>{gen_label}</span> {ts} &nbsp;&nbsp;·&nbsp;&nbsp; {found_n_safe} &nbsp;&nbsp;·&nbsp;&nbsp; {graph_help_safe}
  </div>
  <div class="legend">
    <span style="color:var(--accent)"><i></i> {legend_q}</span>
    <span style="color:var(--hit)"><i></i> {legend_h}</span>
    <span style="color:var(--other)"><i></i> {legend_o}</span>
  </div>
</div>
<svg></svg>
<div class="colophon">SpyEyes</div>
<script>
const nodes = {nodes_json};
const links = {links_json};
const colors = {{1:'#c8102e', 2:'#1d4ed8', 3:'#6b6657'}};  /* 印章红/古典蓝/暗灰 — 浅色 theme 适配 */
const initialRadius = {initial_radius};

const svg = d3.select('svg');
const container = svg.node();

// 把 viewBox 设为以 (0,0) 为中心,这样 forceCenter(0,0) 拉拢的节点显示在视窗正中
// (修复 v1.3.0:之前默认 viewBox 从 (0,0) 起,导致节点全堆在左上角被裁掉)
function applyCenterViewBox() {{
  const w = container.clientWidth || window.innerWidth;
  const h = container.clientHeight || (window.innerHeight - 140);
  svg.attr('viewBox', `${{-w/2}} ${{-h/2}} ${{w}} ${{h}}`)
     .attr('preserveAspectRatio', 'xMidYMid meet');
}}
applyCenterViewBox();

// Pan/zoom 容器
const root = svg.append('g').attr('class', 'root');

// 力模拟：节点越多 charge 越强，避免堆在中心被边缘节点遮挡
const simulation = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).id(d => d.id).distance(d => d.target.group === 1 ? 100 : 90))
  .force('charge', d3.forceManyBody().strength(-300 - Math.min(nodes.length, 800)))
  .force('center', d3.forceCenter(0, 0))
  .force('collide', d3.forceCollide().radius(d => d.group === 1 ? 30 : 18))
  .force('radial', d3.forceRadial(d => d.group === 1 ? 0 : initialRadius, 0, 0).strength(0.05));

const link = root.append('g').attr('class', 'links').selectAll('line').data(links).join('line').attr('class', 'link');
const node = root.append('g').attr('class', 'nodes').selectAll('g').data(nodes).join('g').attr('class', 'node').attr('data-group', d => d.group)
  .call(d3.drag()
    .on('start', e => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; }})
    .on('drag', e => {{ e.subject.fx = e.x; e.subject.fy = e.y; }})
    .on('end', e => {{ if (!e.active) simulation.alphaTarget(0); e.subject.fx = null; e.subject.fy = null; }}));
node.append('circle').attr('r', d => d.group === 1 ? 13 : 7).attr('fill', d => colors[d.group] || '#bbb');
node.append('text').attr('dx', 11).attr('dy', 4).text(d => d.name);
node.filter(d => d.url).append('title').text(d => d.url);
node.filter(d => d.url).style('cursor', 'pointer').on('click', (e, d) => {{
  if (e.defaultPrevented) return;  // 拖拽时不触发点击
  window.open(d.url, '_blank', 'noopener');
}});

simulation.on('tick', () => {{
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

// d3.zoom:滚轮缩放 + 拖拽空白处平移;scale 0.05-8 防过度缩放
// userZoomed:用户主动操作过(拖/缩)→ 停止自动 fit,不打断用户
let userZoomed = false;
const zoom = d3.zoom()
  .scaleExtent([0.05, 8])
  .on('zoom', e => {{
    root.attr('transform', e.transform);
    if (e.sourceEvent) userZoomed = true;  // sourceEvent 只在真实用户事件时存在(programmatic transition 没有)
  }});
svg.call(zoom);

// 自适应:模拟稳定后或按 F 键,把整个图缩放/平移到完全可见
// viewBox 已居中 (0,0),所以这里只需把 bbox 中心拉到 (0,0)
function fitToView() {{
  const bbox = root.node().getBBox();
  // bbox 不可用(初始化所有节点都在 0,0 / simulation 没跑开)→ 重置 zoom,viewBox 居中能保证看到节点
  if (!isFinite(bbox.width) || !isFinite(bbox.height) || bbox.width < 1 || bbox.height < 1) {{
    svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity);
    return;
  }}
  const padding = 60;
  const w = container.clientWidth || window.innerWidth;
  const h = container.clientHeight || (window.innerHeight - 140);
  const scale = Math.min(
    (w - padding * 2) / bbox.width,
    (h - padding * 2) / bbox.height,
    1.5
  );
  const tx = -(bbox.x + bbox.width / 2) * scale;
  const ty = -(bbox.y + bbox.height / 2) * scale;
  svg.transition().duration(700).call(
    zoom.transform,
    d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}}

// 自动 fit:用户没主动操作过时多次重试,确保图最终居中
// 多个时间点覆盖:小图很快稳定 / 中图 1-2s / 大图 simulation.end / 兜底 3.5s
function autoFit() {{ if (!userZoomed) fitToView(); }}
setTimeout(autoFit, 600);
setTimeout(autoFit, 1500);
simulation.on('end', autoFit);
setTimeout(autoFit, 3500);

// F 键随时重新 fit(强制,忽略 userZoomed);R 键重置缩放
window.addEventListener('keydown', e => {{
  if (e.key === 'f' || e.key === 'F') {{ userZoomed = false; fitToView(); }}
  if (e.key === 'r' || e.key === 'R') {{
    userZoomed = false;
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
  }}
}});

// 窗口 resize:viewBox 跟着重算 + 重新 fit
window.addEventListener('resize', () => {{ applyCenterViewBox(); fitToView(); }});
</script>
</body>
</html>
'''


# pip / pipx / brew / uv / conda 等安装方式都会把包放在含 site-packages/dist-packages 的路径下;
# editable install (pip install -e .) 不会(__file__ 直接指向源码),所以源码运行能正确识别
_PACKAGED_INSTALL_MARKERS = ('site-packages', 'dist-packages')


def _is_packaged_install() -> bool:
    """判断当前是否为打包安装(pip/pipx/brew/conda 等),还是从源码直接运行。"""
    pkg_dir = os.path.dirname(os.path.realpath(__file__))
    return any(marker in pkg_dir for marker in _PACKAGED_INSTALL_MARKERS)


def _detect_install_mode() -> str:
    """识别 SpyEyes 是怎么装的,返回 'source' / 'packaged-pip' / 'packaged-pipx'。

    'source':        git clone + pip install -e .  → 不自动跑升级,只显示命令
    'packaged-pip':  pip install git+URL           → subprocess 跑 pip install --upgrade
    'packaged-pipx': pipx install git+URL          → subprocess 跑 pipx upgrade spyeyes

    pipx 装的包,__file__ 路径含 `pipx/venvs` (POSIX) 或 `pipx\\venvs` (Windows)。
    """
    if not _is_packaged_install():
        return 'source'
    real = os.path.realpath(__file__)
    # 跨平台:同时查正反斜杠两种分隔
    if 'pipx' + os.sep + 'venvs' in real or 'pipx/venvs' in real or 'pipx\\venvs' in real:
        return 'packaged-pipx'
    return 'packaged-pip'


def _build_upgrade_command(mode: str) -> Optional[list[str]]:
    """按 mode 返回 subprocess 命令列表,源码模式返回 None。

    使用 sys.executable -m pip 而非 'pip',避 PATH 缺失 (Windows 上 pip.exe 可能不在 PATH)。
    使用 list 形式 (非 shell 字符串) 避跨平台 shell quoting 差异。
    """
    if mode == 'source':
        return None
    if mode == 'packaged-pipx':
        return ['pipx', 'upgrade', 'spyeyes']
    if mode == 'packaged-pip':
        return [sys.executable, '-m', 'pip', 'install', '--upgrade',
                'git+https://github.com/Akxan/SpyEyes.git']
    return None


def _prompt_yes_no(question: str, default_yes: bool = True) -> bool:
    """TTY 安全的 Y/N prompt。

    非 TTY 直接返回 default_yes(管道、cron 等场景不交互)。
    TTY 上 'y'/'yes' → True,'n'/'no' → False,空 → default_yes,其他 → 重问一次。
    Ctrl-C 透传给上层 (run_upgrade 会捕获)。
    """
    if not sys.stdin.isatty():
        return default_yes
    try:
        answer = input(question + ' ').strip().lower()
    except EOFError:
        return default_yes
    if answer in ('y', 'yes'):
        return True
    if answer in ('n', 'no'):
        return False
    return default_yes  # 空输入或不识别 → 用 default


def _default_report_dir() -> str:
    """智能默认报告目录,按安装方式自适应。

    优先级:
    1. SPYEYES_REPORTS_DIR — 用户显式覆盖(服务器场景常用 /var/log/spyeyes 等)
    2. 源码运行(git clone / pip install -e .) → <项目根>/Downloads/
       用户能在仓库根目录直接看到报告,所见即所得
    3. 打包安装(pip/pipx/brew/conda) → ~/Downloads/spyeyes/
       绝不写入 site-packages(权限/污染问题),用户惯用的 Downloads 下建子文件夹
    4. 兜底: <cwd>/Downloads/, 最后 cwd

    历史:
    - v1.2.0: ~/Downloads(Linux 服务器无桌面常无此目录)
    - v1.6.4: <cwd>/Downloads/(所见即所得,但 spyeyes 被加到 PATH 后用户在 / 下跑会污染根目录)
    - v1.8.0: 智能路由 — 源码用户回归项目目录,打包用户回归 ~/Downloads/spyeyes/

    不缓存:每次重新计算,支持交互菜单内 cd 切换的场景。"""
    custom = (os.environ.get('SPYEYES_REPORTS_DIR') or '').strip()
    if custom:
        try:
            os.makedirs(custom, exist_ok=True)
            return custom
        except OSError:
            pass

    if _is_packaged_install():
        # 打包安装:绝不写 site-packages,落到用户 home 的 Downloads/spyeyes/
        target = os.path.join(os.path.expanduser('~'), 'Downloads', 'spyeyes')
    else:
        # 源码运行:落到项目根 (spyeyes/__init__.py 上一层) 的 Downloads/
        project_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        target = os.path.join(project_root, 'Downloads')

    try:
        os.makedirs(target, exist_ok=True)
        return target
    except OSError:
        # 目标不可写(权限/只读 FS),退到 cwd/Downloads/
        fallback = os.path.join(os.getcwd(), 'Downloads')
        try:
            os.makedirs(fallback, exist_ok=True)
            return fallback
        except OSError:
            return os.getcwd()


def menu_loop(save_dir: Optional[str] = None) -> None:
    while True:
        clear_screen()
        show_menu()
        try:
            raw = input(f"\n {Color.Wh}[ + ] {Color.Gr}{t('prompt.select_option')}{Color.Wh}").strip()
            choice = int(raw)
        except ValueError:
            print(f"\n {Color.Re}{t('prompt.input_number')}{Color.Reset}")
            time.sleep(1)
            continue
        except (EOFError, KeyboardInterrupt):
            # stdin 关闭（管道末尾、Ctrl+D）→ 正常退出而非 traceback
            print()
            return
        try:
            handle_choice(choice, save_dir=save_dir)
        except ValueError as e:
            print(f"\n {Color.Re}{e}{Color.Reset}")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n {Color.Re}{t('prompt.interrupted')}{Color.Reset}")
            continue
        except EOFError:
            print()
            return
        if choice != 0:
            try:
                input(f"\n{Color.Wh}[ {Color.Gr}+ {Color.Wh}] {Color.Gr}{t('prompt.press_enter')}{Color.Reset}")
            except (EOFError, KeyboardInterrupt):
                return


# ====================================================================
# CLI
# ====================================================================
def _positive_int(value: str) -> int:
    """argparse 校验器：仅接受 1..200 的正整数。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"expected integer, got {value!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {n}")
    if n > 200:
        raise argparse.ArgumentTypeError(f"must be <= 200 (avoid system overload), got {n}")
    return n


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--json', action='store_const', const=True,
                        default=argparse.SUPPRESS, help='JSON output / 输出原始 JSON')
    common.add_argument('--save', metavar='DIR',
                        default=argparse.SUPPRESS, help='Save results to DIR / 保存到指定目录')
    common.add_argument('--no-color', action='store_const', const=True,
                        default=argparse.SUPPRESS, help='Disable color / 禁用颜色')
    common.add_argument('--lang', choices=['zh', 'en'],
                        default=argparse.SUPPRESS, help='UI language: zh or en / 界面语言')
    common.add_argument('--no-update-check', action='store_const', const=True,
                        default=argparse.SUPPRESS,
                        help='Skip GitHub update check / 跳过 GitHub 版本检查')
    common.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')

    parser = argparse.ArgumentParser(
        prog='spyeyes',
        parents=[common],
        description=f'SpyEyes {__version__} —— OSINT toolkit (bilingual: zh/en)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples / 示例 (after `pip install .` use `spyeyes ...` directly):
  python3 -m spyeyes                              # Interactive menu / 交互菜单
  python3 -m spyeyes --lang en                    # Force English UI / 强制英文界面
  python3 -m spyeyes ip 8.8.8.8                   # IP lookup
  python3 -m spyeyes myip --lang en               # English JSON
  python3 -m spyeyes phone +12025550100           # Phone parse
  python3 -m spyeyes user torvalds                # Username scan (3164 platforms, 150 workers)
  python3 -m spyeyes user torvalds --recursive    # v1.1.0: recursive scan
  python3 -m spyeyes permute "John Doe"           # v1.1.0: generate variations (strict)
  python3 -m spyeyes permute "John Doe" --method all  # v1.2.0: Maigret-style with _prefix/suffix_
  python3 -m spyeyes permute "John Doe" --scan    # v1.1.0: gen + scan all
  python3 -m spyeyes whois example.com            # WHOIS
  python3 -m spyeyes mx gmail.com                 # MX records
  python3 -m spyeyes email a@b.com                # Email validate
  python3 -m spyeyes subdomain example.com        # v1.3.0: subdomain enum (CT logs + DNS + HTTP probe)
  python3 -m spyeyes subdomain example.com --no-probe  # skip HTTP probe (faster)
  python3 -m spyeyes ip 8.8.8.8 --json            # JSON output
  python3 -m spyeyes ip 8.8.8.8 --save out/       # Save to dir (auto JSON)
  python3 -m spyeyes user torvalds --save r.pdf   # v1.1.0: PDF report (needs spyeyes[pdf])
  python3 -m spyeyes user torvalds --save r.md    # Markdown report
  python3 -m spyeyes user torvalds --save r.html  # v1.2.0: HTML report (styled tables)
  python3 -m spyeyes user torvalds --save r.txt   # v1.2.0: plain text report
  python3 -m spyeyes user torvalds --save r.csv   # v1.2.0: CSV (excel-safe, injection-protected)
  python3 -m spyeyes user torvalds --save r.xmind # v1.2.0: XMind 8 mind-map (no extra deps)
  python3 -m spyeyes user torvalds --save r.graph.html  # v1.2.0: D3.js force-directed graph
""",
    )

    sub = parser.add_subparsers(dest='command')

    sp = sub.add_parser('ip', parents=[common], help='IP lookup / IP 查询')
    sp.add_argument('target', help='IPv4 / IPv6 address')

    sub.add_parser('myip', parents=[common], help='Show public IP / 本机出口 IP')

    sp = sub.add_parser('phone', parents=[common], help='Parse phone number / 电话号码解析')
    sp.add_argument('number')
    sp.add_argument('--region', default='CN', help='Default region (default: CN)')

    sp = sub.add_parser('user', parents=[common], help='Scan username / 用户名扫描')
    sp.add_argument('username')
    sp.add_argument('--workers', type=_positive_int, default=150,
                    help='Concurrent threads / 并发线程数 (default: 150, max 200)')
    sp.add_argument('--timeout', type=float, default=5.0,
                    help='HTTP timeout per platform in seconds / 单平台超时秒数 (default: 5)')
    sp.add_argument('--all', action='store_true', dest='show_all',
                    help='Show all platforms incl. misses / 显示所有平台（含未命中）')
    sp.add_argument('--quick', action='store_true',
                    help='Skip "other" long-tail (~1411 vs 3164 platforms, ~2x faster) / 跳过 other 长尾')
    sp.add_argument('--category', dest='category_filter',
                    help='Comma-separated categories: code,social,chinese,spanish,... / 用逗号分隔的类别')
    # v1.1.0
    sp.add_argument('--recursive', action='store_true',
                    help='Recursively scan usernames discovered in profile pages (v1.1.0)')
    sp.add_argument('--depth', type=int, default=2,
                    help=f'Max recursive depth, 0-{RECURSIVE_MAX_DEPTH} (default: 2; only with --recursive)')

    sp = sub.add_parser('permute', parents=[common],
                        help='Generate username permutations / 生成用户名变形 (v1.1.0)')
    sp.add_argument('name', help='Name or text to permute (e.g. "John Doe")')
    sp.add_argument('--method', choices=['strict', 'all'], default='strict',
                    help='Permutation method: strict (default, multi-part perms) '
                         "or 'all' (also adds _prefix / suffix_ variants) — Maigret-style")
    sp.add_argument('--scan', action='store_true',
                    help='Also scan each permutation across platforms (slow!)')
    sp.add_argument('--workers', type=_positive_int, default=150,
                    help='Concurrent threads if --scan (default: 150)')
    sp.add_argument('--quick', action='store_true',
                    help='If --scan: quick mode (skip "other" long-tail)')

    sp = sub.add_parser('whois', parents=[common], help='WHOIS lookup')
    sp.add_argument('domains', nargs='+', help='One or more domains for batch query')

    sp = sub.add_parser('mx', parents=[common], help='MX records')
    sp.add_argument('domains', nargs='+', help='One or more domains for batch query')

    sp = sub.add_parser('email', parents=[common], help='Email validation / 邮箱验证')
    sp.add_argument('address')

    # v1.3.0: 子域名枚举
    sp = sub.add_parser('subdomain', parents=[common],
                        help='Enumerate subdomains / 子域名枚举 (v1.3.0)')
    # v1.5.0:domain 改 nargs='?',允许只用 --batch 而不传 domain
    sp.add_argument('domain', nargs='?', help='Target domain (e.g. example.com)')
    # v1.5.0:批量域名输入 — 每行一个域名,逐个跑独立报告
    sp.add_argument('--batch', dest='batch_file',
                    help='File with one domain per line (# comments + blank lines ignored).'
                         ' Each domain runs independently; combine with --batch-save-dir'
                         ' to write per-domain reports.')
    sp.add_argument('--batch-save-dir', dest='batch_save_dir',
                    help='Directory to write per-domain reports when --batch is used'
                         ' (extension from --save, e.g. .html). Default: print to stdout only.')
    sp.add_argument('--no-probe', action='store_true', dest='no_probe',
                    help='Skip HTTP probe (faster, only DNS resolution)')
    sp.add_argument('--workers', type=_positive_int, default=SUBDOMAIN_DEFAULT_WORKERS,
                    help=f'DNS / probe concurrency (default: {SUBDOMAIN_DEFAULT_WORKERS}, max 200)')
    sp.add_argument('--timeout', type=float, default=SUBDOMAIN_HTTP_PROBE_TIMEOUT,
                    help=f'HTTP probe timeout per host (default: {SUBDOMAIN_HTTP_PROBE_TIMEOUT}s)')
    sp.add_argument('--alive-only', action='store_true', dest='alive_only',
                    help='Hide dead subdomains in CLI output AND saved reports'
                         ' (HTML/PDF/JSON/CSV/etc.). Useful when bruteforce produces'
                         ' many dead candidates and the report becomes cluttered.')
    # v1.4.9:DNS 字典爆破(opt-in,~220 内置词典 / 用户 SPYEYES_DNS_WORDLIST 覆盖)
    sp.add_argument('--bruteforce', action='store_true', dest='bruteforce',
                    help='Enable DNS dictionary bruteforce (~220 built-in prefixes;'
                         ' set SPYEYES_DNS_WORDLIST=/path to use custom wordlist)')
    # v1.4.9:JS / HTML body host 提取(默认开,几乎免费 — body 已在内存里)
    sp.add_argument('--no-js-extract', action='store_true', dest='no_js_extract',
                    help='Skip JS/HTML body extraction of additional hostnames'
                         ' (default: enabled, scans probe response bodies for *.<domain>)')

    # v1.4.0: 域名邮箱枚举(OSINT email harvest)
    sp = sub.add_parser('domain-emails', parents=[common],
                        help='Enumerate emails for a domain / 域名邮箱枚举 (v1.4.0)')
    sp.add_argument('domain', help='Target domain (e.g. example.com)')
    sp.add_argument('--no-crawl', action='store_true', dest='no_crawl',
                    help='Skip deep crawl, only use crt.sh + WHOIS')
    sp.add_argument('--no-include-subdomains', action='store_true',
                    dest='no_include_subdomains',
                    help='Skip alive subdomains in crawl (main domain only, faster)')
    sp.add_argument('--max-pages', type=_positive_int,
                    default=DOMAIN_EMAIL_DEFAULT_MAX_PAGES,
                    help=f'Max pages to crawl (default: {DOMAIN_EMAIL_DEFAULT_MAX_PAGES})')
    sp.add_argument('--crawl-depth', type=int, default=DOMAIN_EMAIL_DEFAULT_DEPTH,
                    help=f'BFS depth limit (default: {DOMAIN_EMAIL_DEFAULT_DEPTH})')
    sp.add_argument('--ignore-robots', action='store_true', dest='ignore_robots',
                    help='Ignore robots.txt Disallow (use carefully)')
    sp.add_argument('--guess', dest='guess_names',
                    help='Generate pattern emails from comma-separated names'
                         ' (e.g. "John Doe,Jane Smith")')
    sp.add_argument('--verify-smtp', action='store_true', dest='verify_smtp',
                    help='SMTP HELO/RCPT verification (HIGH-PROFILE — only for'
                         ' domains you own)')

    sp = sub.add_parser('history', parents=[common], help='Show recent queries / 显示历史查询')
    sp.add_argument('--limit', type=_positive_int, default=20,
                    help='Max entries to show, must be >= 1 (default: 20, max 200)')
    sp.add_argument('--search', help='Filter by query substring')

    # v1.5.0:Diff 模式 — 对比两次子域扫描 JSON
    sp = sub.add_parser('diff', parents=[common],
                        help='Compare two subdomain scan JSON files / 对比两次子域扫描 (v1.5.0)')
    sp.add_argument('old', help='Old scan JSON file (e.g. monday.json)')
    sp.add_argument('new', help='New scan JSON file (e.g. friday.json)')

    # v1.7.0:综合调查 — 一次输入 domain,自动 fan-out + 单向 pivot,出整合报告
    sp = sub.add_parser('investigate', parents=[common],
                        help='Comprehensive multi-source investigation / 综合调查 (v1.7.0)')
    sp.add_argument('target', help='Target domain (v2 will add email/ip/username)')
    sp.add_argument('--depth', type=int, default=1,
                    help='Pivot depth: 0=atomic-only, 1=with pivots (default: 1)')
    sp.add_argument('--budget', type=float, default=INVESTIGATE_DEFAULT_BUDGET,
                    help=f'Total time budget in seconds, 0=unlimited (default: {INVESTIGATE_DEFAULT_BUDGET})')
    sp.add_argument('--max-pivot-ips', type=_positive_int,
                    default=INVESTIGATE_MAX_PIVOT_IPS, dest='max_pivot_ips',
                    help=f'Cap on subdomain→IP enrichment (default: {INVESTIGATE_MAX_PIVOT_IPS})')
    sp.add_argument('--max-pivot-emails', type=_positive_int,
                    default=INVESTIGATE_MAX_PIVOT_EMAILS, dest='max_pivot_emails',
                    help=f'Cap on email→username pivot (default: {INVESTIGATE_MAX_PIVOT_EMAILS})')
    sp.add_argument('--no-quick', action='store_true', dest='no_quick',
                    help='Disable quick mode (also scan "other" long-tail platforms)')
    sp.add_argument('--no-probe', action='store_true', dest='no_probe',
                    help='Skip HTTP probe in subdomain stage (faster)')
    return parser


def _run_subdomain_batch(args: argparse.Namespace) -> int:
    """v1.5.0:批量子域扫描。从 --batch FILE 读 domain 列表,逐个跑独立报告。
    输出:每个 domain 的 _stats 摘要打到 stderr;若 --batch-save-dir 指定,
    每个 domain 单独写报告(扩展名取 --save 的);否则只打印进度。"""
    path = args.batch_file
    save_dir = getattr(args, 'batch_save_dir', None)
    save_ext = None
    if args.save:
        # 从 --save 推断扩展名
        m = re.search(r'\.([a-z]+(?:\.[a-z]+)?)$', args.save.lower())
        save_ext = m.group(1) if m else 'html'
    elif save_dir:
        save_ext = 'html'  # 默认 HTML 报告
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
    except OSError as e:
        sys.stderr.write(f"--batch: 无法读取文件 {path}: {e}\n")
        return 2
    domains: list[str] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)
    if not domains:
        sys.stderr.write(f"--batch: 文件 {path} 中没有有效域名\n")
        return 2
    if save_dir:
        try:
            os.makedirs(save_dir, exist_ok=True)
        except OSError as e:
            sys.stderr.write(f"--batch: 无法创建保存目录 {save_dir}: {e}\n")
            return 2
    sys.stderr.write(f"\n {Color.Cy}== 批量扫描 {len(domains)} 个域名 ==\n{Color.Reset}")
    summary: list = []
    probe = not getattr(args, 'no_probe', False)
    for idx, domain in enumerate(domains, 1):
        sys.stderr.write(f"\n {Color.Wh}[{idx}/{len(domains)}] 扫描 {Color.Gr}{domain}{Color.Reset}\n")
        try:
            data = enumerate_subdomains(
                domain, probe=probe,
                max_workers=args.workers,
                probe_timeout=args.timeout,
                bruteforce=getattr(args, 'bruteforce', False),
                js_extract=not getattr(args, 'no_js_extract', False),
                show_progress=not args.json,
            )
        except KeyboardInterrupt:
            sys.stderr.write(f" {Color.Re}用户中断,已完成 {idx-1}/{len(domains)}\n{Color.Reset}")
            break
        if getattr(args, 'alive_only', False):
            # v1.6.5:同样用智能过滤(wildcard 时自动严格)
            data = _filter_alive_only(data)
        stats = (data.get('_stats') or {}) if isinstance(data, dict) else {}
        summary.append({
            'domain': domain,
            'total': stats.get('total', 0),
            'alive': stats.get('alive', 0),
            'error': data.get('_error') if isinstance(data, dict) else None,
        })
        # 写文件(若 save_dir 给定)
        if save_dir and isinstance(data, dict) and not data.get('_error'):
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
            out_path = os.path.join(save_dir, f'subdomain_{safe_name}.{save_ext}')
            _maybe_save(out_path, 'subdomain', data)
        # 写历史(批量也记录)
        _record_history('subdomain', argparse.Namespace(domain=domain), data)
    # 总结
    sys.stderr.write(f"\n {Color.Cy}== 批量扫描完成 ==\n{Color.Reset}")
    for r in summary:
        marker = f"{Color.Re}✗{Color.Reset}" if r['error'] else f"{Color.Gr}✓{Color.Reset}"
        sys.stderr.write(f"  {marker} {r['domain']:30}  total={r['total']:5}  alive={r['alive']:5}\n")
    if args.json:
        _emit_json({'batch_summary': summary, 'count': len(summary)})
    return 0


def run_cli(args: argparse.Namespace) -> int:
    cmd = args.command
    args.json = getattr(args, 'json', False)
    args.save = getattr(args, 'save', None)
    data: Any = None
    save_prefix = cmd  # 默认；下面各 cmd 会带上 query
    if cmd == 'ip':
        data = track_ip(args.target)
        save_prefix = f'ip_{args.target}'
        if args.json:
            _emit_json(data)
        else:
            print_ip_info(args.target, data)
    elif cmd == 'myip':
        ip = show_my_ip()
        # 失败时显式 _error 让 run_cli 末尾返回 exit 1（之前 data={'ip': None}
        # 让 '_error' not in data 为 True → exit 0 → shell 脚本误判成功）
        data = {'ip': ip} if ip else {'ip': None, '_error': t('err.network')}
        # 'myip' (无下划线) 而非 'my_ip' —— 避免报告生成器 partition('_') 误切成
        # cmd='my', query='ip' 输出 "MY 信息: ip"（v1.2.1 P0-4 修复）
        save_prefix = 'myip'
        if args.json:
            _emit_json(data)
        else:
            print_my_ip(ip)
    elif cmd == 'phone':
        data = track_phone(args.number, default_region=args.region)
        save_prefix = f'phone_{args.number}'
        if args.json:
            _emit_json(data)
        else:
            print_phone_info(data)
    elif cmd == 'user':
        cats = None
        if getattr(args, 'category_filter', None):
            cats = [c.strip() for c in args.category_filter.split(',') if c.strip()]
            # 同时传 --quick + --category 时警告：--category 优先
            if getattr(args, 'quick', False):
                sys.stderr.write(f"{Color.Ye}[warn] --quick ignored when --category is set{Color.Reset}\n")
        elif getattr(args, 'quick', False):
            cats = [c for c in CATEGORY_ORDER if c != 'other']
        if getattr(args, 'recursive', False):
            depth = max(0, min(getattr(args, 'depth', 2), RECURSIVE_MAX_DEPTH))
            data = recursive_track_username(args.username, max_depth=depth,
                                            max_workers=args.workers,
                                            timeout=args.timeout, categories=cats)
        else:
            data = track_username(args.username, max_workers=args.workers,
                                  timeout=args.timeout, categories=cats)
        save_prefix = f'username_{args.username}'
        if args.json:
            # 剥掉私有 _* key（如 _statuses）—— 这些是 print_* 的内部使用
            # 递归结果保留 _recursive，让 JSON 消费者拿到完整层级数据
            if isinstance(data, dict) and '_error' not in data:
                json_data = {k: v for k, v in data.items() if k == '_recursive' or not k.startswith('_')}
                if '_recursive' not in json_data:
                    json_data = _platform_only(data)
            else:
                json_data = data
            _emit_json(json_data)
        else:
            if isinstance(data, dict) and '_recursive' in data:
                _print_recursive_summary(data['_recursive'])
            print_username_results(data, show_all=getattr(args, 'show_all', False))
    elif cmd == 'permute':
        method = getattr(args, 'method', 'strict')
        names = permute_username(args.name, method=method)
        if not names:
            data = {'_error': t('err.permute_empty')}
            save_prefix = f'permute_{args.name}'
            if args.json:
                _emit_json(data)
            else:
                print(f" {Color.Re}{data['_error']}{Color.Reset}")
        elif getattr(args, 'scan', False):
            # 扫描每个变形（耗时！但用户明确请求）
            cats = None
            if getattr(args, 'quick', False):
                cats = [c for c in CATEGORY_ORDER if c != 'other']
            scan_results: dict = {}
            print(f" {Color.Cy}{t('permute.generated', name=args.name, n=len(names))}{Color.Reset}")
            for n in names:
                print(f"\n {Color.Bl}━━━ {n} ━━━{Color.Reset}")
                r = track_username(n, max_workers=args.workers, categories=cats,
                                   show_progress=True)
                scan_results[n] = r
                if not args.json:
                    print_username_results(r, show_all=False)
            data = scan_results
            save_prefix = f'permute_{args.name}'
            if args.json:
                # 剥每个子结果的 _statuses
                json_data = {n: _platform_only(r) if isinstance(r, dict) and '_error' not in r else r
                             for n, r in scan_results.items()}
                _emit_json(json_data)
        else:
            data = {'name': args.name, 'permutations': names}
            save_prefix = f'permute_{args.name}'
            if args.json:
                _emit_json(data)
            else:
                print(f"\n {Color.Cy}{t('permute.generated', name=args.name, n=len(names))}{Color.Reset}\n")
                for n in names:
                    print(f"  {Color.Gr}•{Color.Reset} {n}")
                print()
    elif cmd == 'whois':
        data = _batch_lookup(whois_lookup, args.domains) if len(args.domains) > 1 else whois_lookup(args.domains[0])
        save_prefix = f'whois_{"_".join(args.domains)[:60]}'
        if args.json:
            _emit_json(data)
        else:
            if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
                # batch
                for domain, d in data.items():
                    print(f"\n {Color.Cy}━━━ {domain} ━━━{Color.Reset}")
                    print_whois(d)
            else:
                print_whois(data)
    elif cmd == 'mx':
        data = _batch_lookup(mx_lookup, args.domains) if len(args.domains) > 1 else mx_lookup(args.domains[0])
        save_prefix = f'mx_{"_".join(args.domains)[:60]}'
        if args.json:
            _emit_json(data)
        else:
            if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
                for domain, d in data.items():
                    print(f"\n {Color.Cy}━━━ {domain} ━━━{Color.Reset}")
                    print_mx(d)
            else:
                print_mx(data)
    elif cmd == 'email':
        data = email_validate(args.address)
        save_prefix = f'email_{args.address}'
        if args.json:
            _emit_json(data)
        else:
            print_email(data)
    elif cmd == 'domain-emails':
        # v1.4.0: 域名邮箱枚举
        data = enumerate_domain_emails(
            args.domain,
            crawl=not getattr(args, 'no_crawl', False),
            include_subdomains=not getattr(args, 'no_include_subdomains', False),
            max_pages=args.max_pages,
            max_depth=args.crawl_depth,
            obey_robots=not getattr(args, 'ignore_robots', False),
            guess_names=getattr(args, 'guess_names', None),
            verify_smtp=getattr(args, 'verify_smtp', False),
            show_progress=not args.json,
        )
        save_prefix = f'domain-emails_{args.domain}'
        if args.json:
            _emit_json(data)
        else:
            print_domain_emails(data)
    elif cmd == 'subdomain':
        # v1.3.0: 子域名枚举
        # v1.5.0:支持 --batch domains.txt 批量
        batch_file = getattr(args, 'batch_file', None)
        if batch_file:
            return _run_subdomain_batch(args)
        if not args.domain:
            sys.stderr.write("subdomain: domain or --batch is required\n")
            return 2
        probe = not getattr(args, 'no_probe', False)
        data = enumerate_subdomains(
            args.domain,
            probe=probe,
            max_workers=args.workers,
            probe_timeout=args.timeout,
            bruteforce=getattr(args, 'bruteforce', False),
            js_extract=not getattr(args, 'no_js_extract', False),
            show_progress=not args.json,
        )
        save_prefix = f'subdomain_{args.domain}'
        # v1.4.10:--alive-only 现在影响 CLI / JSON / 导出报告全部
        # v1.6.5:wildcard 检测时自动用严格过滤(防 DNS 劫持 fake "alive")
        if getattr(args, 'alive_only', False):
            data = _filter_alive_only(data)
        if args.json:
            _emit_json(data)
        else:
            print_subdomains(data)
    elif cmd == 'history':
        entries = read_history(limit=args.limit, search=getattr(args, 'search', None))
        if args.json:
            _emit_json(entries)
        else:
            print_history(entries)
        # `--save` 在 history 子命令也生效（之前早 return 0 静默丢失）
        if args.save:
            _maybe_save(args.save, 'history', entries)
        return 0
    elif cmd == 'diff':
        # v1.5.0:对比两次子域扫描 JSON
        try:
            with open(args.old, 'r', encoding='utf-8') as f:
                old = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"{t('diff.err_load', path=args.old)}: {e}\n")
            return 2
        try:
            with open(args.new, 'r', encoding='utf-8') as f:
                new = json.load(f)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"{t('diff.err_load', path=args.new)}: {e}\n")
            return 2
        data = diff_subdomain_results(old, new)
        if isinstance(data, dict) and data.get('_error'):
            sys.stderr.write(f"{t('diff.err_invalid')}\n")
            return 2
        save_prefix = f"diff_{(data.get('domain') or 'subdomain')}"
        if args.json:
            _emit_json(data)
        else:
            print_subdomain_diff(data)
        if args.save:
            _maybe_save(args.save, 'diff', data)
        return 0
    elif cmd == 'investigate':
        # v1.7.0:综合调查
        data = do_investigate(
            args.target,
            depth=getattr(args, 'depth', 1),
            budget=getattr(args, 'budget', INVESTIGATE_DEFAULT_BUDGET),
            max_pivot_ips=getattr(args, 'max_pivot_ips', INVESTIGATE_MAX_PIVOT_IPS),
            max_pivot_emails=getattr(args, 'max_pivot_emails', INVESTIGATE_MAX_PIVOT_EMAILS),
            quick=not getattr(args, 'no_quick', False),
            probe=not getattr(args, 'no_probe', False),
            show_progress=not args.json,
        )
        save_prefix = f'investigate_{args.target}'
        if args.json:
            _emit_json(data)
        else:
            print_investigate(data)
    else:
        return 2
    # 写历史（仅对实际查询的子命令）
    _record_history(cmd, args, data)
    if args.save:
        _maybe_save(args.save, save_prefix, data)
    return 1 if isinstance(data, dict) and '_error' in data else 0


def _batch_lookup(fn, items: list, max_workers: int = 10) -> dict:
    """对一组输入并发调用 fn，返回 {item: result}。
    支持 Ctrl+C 中断：cancel_futures=True 立即取消未启动的 worker。"""
    results: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fn, item): item for item in items}
        try:
            for fut in as_completed(futures):
                item = futures[fut]
                try:
                    results[item] = fut.result()
                except Exception as e:
                    results[item] = {'_error': str(e)}
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            raise
    return {item: results[item] for item in items if item in results}  # 保持输入顺序


def _record_history(cmd: str, args: argparse.Namespace, data: Any) -> None:
    """记录单次查询到 history.jsonl。仅记摘要不存全量，保护隐私。
    所有 data 访问都防御性地处理 None / 非 dict 情况。"""
    # data=None 或非 dict 视为失败（之前 `'_error' not in {}` 会返回 True 等同成功）
    has_data = isinstance(data, dict) and bool(data)
    if not isinstance(data, dict):
        data = {}
    ok = has_data and '_error' not in data
    summary: dict = {}
    if cmd == 'ip':
        summary = {'target': args.target, 'ok': ok}
    elif cmd == 'myip':
        summary = {'ok': data.get('ip') is not None}
    elif cmd == 'phone':
        # phone 用 is_valid 判定 ok（is_possible=True 但 is_valid=False 的号码
        # 不应记为成功 —— 它解析通过但实际不是真分配的号码段）
        phone_ok = ok and bool(data.get('is_valid', False))
        summary = {'number': args.number, 'ok': phone_ok}
    elif cmd == 'user':
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        summary = {'username': args.username, 'scanned': len(plat), 'found': found}
        # 递归扫描时记录层数（让 history 能区分单次 vs 递归）
        if isinstance(data.get('_recursive'), dict):
            summary['recursive'] = data['_recursive'].get('depth_reached', 0) + 1
            summary['found'] = data['_recursive'].get('total_found', found)
    elif cmd == 'permute':
        # data 可能是 {'_error': ...}, {'name': ..., 'permutations': [...]}, 或 {var: results, ...}
        if 'permutations' in data:
            summary = {'name': args.name, 'variations': len(data.get('permutations', []))}
        elif data and '_error' not in data:
            # --scan 模式：data 是每个变形的结果
            total_found = sum(
                sum(1 for v in _platform_only(r).values() if v)
                for r in data.values() if isinstance(r, dict) and '_error' not in r
            )
            summary = {'name': args.name, 'variations': len(data), 'found': total_found}
        else:
            summary = {'name': args.name, 'ok': False}
    elif cmd in ('whois', 'mx'):
        summary = {'domains': args.domains}
    elif cmd == 'email':
        summary = {'address': args.address, 'mx_valid': data.get('mx_valid')}
    elif cmd == 'subdomain':
        # v1.3.0: 记录 domain + 总数 + alive 数(配合 history --search 排查)
        stats = data.get('_stats', {}) or {}
        summary = {'domain': args.domain,
                   'total': stats.get('total', 0),
                   'alive': stats.get('alive', 0),
                   'wildcard': bool(data.get('wildcard_suspect'))}
    elif cmd == 'domain-emails':
        # v1.4.0: 记录 domain + 邮箱总数 + 爬取页数
        stats = data.get('_stats', {}) or {}
        summary = {'domain': args.domain,
                   'total': stats.get('total', 0),
                   'pages_crawled': stats.get('pages_crawled', 0),
                   'verified': stats.get('verified', 0)}
    elif cmd == 'investigate':
        # v1.7.0: 记录 target + 任务/接力计数(不存 emails / users 细节防泄露)
        stats = data.get('_stats', {}) or {}
        summary = {'target': args.target,
                   'tasks_done': stats.get('tasks_done', 0),
                   'tasks_failed': stats.get('tasks_failed', 0),
                   'pivots_done': stats.get('pivots_done', 0),
                   'elapsed': data.get('elapsed', 0)}
    else:
        # 未知 cmd（未来加新子命令但忘了更新这里）→ 不写空 entry 污染历史
        return
    # investigate uses 'target' key — domain is normalized at do_investigate entry; we keep
    # the raw arg for history readability (history is a UI surface, not a re-query key)
    query = summary.get('target') or summary.get('username') or summary.get('address') \
            or (summary.get('domains') and ','.join(summary['domains'])) or summary.get('number') \
            or summary.get('name') or summary.get('domain') or ''
    append_history(cmd, str(query), summary)


def print_history(entries: list) -> None:
    _print_section_header('section.history')
    print()
    if not entries:
        print(f" {Color.Ye}{t('msg.no_history')}{Color.Reset}")
        return
    for e in entries:
        ts = e.get('ts', '?')
        cmd = e.get('cmd', '?')
        query = e.get('query', '')
        extras = []
        if 'found' in e:
            extras.append(f"{e['found']}/{e.get('scanned', '?')}")
        if 'ok' in e:
            extras.append('✓' if e['ok'] else '✗')
        if 'mx_valid' in e:
            extras.append('mx✓' if e['mx_valid'] else 'mx✗')
        # v1.3.0: subdomain 命令的 alive/total 显示 + wildcard 警告
        if 'alive' in e and 'total' in e:
            extras.append(f"{e['alive']}/{e['total']}")
            if e.get('wildcard'):
                extras.append('⚠wildcard')
        extra_str = f"  [{Color.Cy}{', '.join(str(x) for x in extras)}{Color.Reset}]" if extras else ''
        print(f"  {Color.Bl}{ts}{Color.Reset}  {Color.Wh}{cmd:7}{Color.Reset}  {Color.Gr}{query}{Color.Reset}{extra_str}")


def resolve_language(args: argparse.Namespace) -> str:
    """优先级：CLI --lang > 配置文件 > 环境变量 > 默认。"""
    cli_lang = getattr(args, 'lang', None)
    if cli_lang:
        return cli_lang
    cfg = load_config()
    if cfg.get('lang') in TRANSLATIONS:
        return cfg['lang']
    return detect_lang()


def main() -> int:
    # Windows cp936 console 默认编码无法显示 emoji（👁国旗）和部分非 CJK Unicode
    # → print() 抛 UnicodeEncodeError 让进程崩。Python 3.7+ 用 reconfigure 强制 utf-8。
    # errors='replace' 保证即使 console 真不支持也不抛异常（用 ? 替代）
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    parser = build_parser()
    args = parser.parse_args()

    if getattr(args, 'no_color', False):
        Color.disable()

    # CLI 命令显式 --no-update-check 也通过 env var 传给后台线程
    # (后台线程通过 _is_update_check_disabled() 统一判定,避免参数透传)
    if getattr(args, 'no_update_check', False):
        os.environ['SPYEYES_NO_UPDATE_CHECK'] = '1'

    # CLI 模式：直接根据语言优先级选定，不弹首次提示
    if args.command:
        set_lang(resolve_language(args))
        _maybe_show_update_notice()
        return run_cli(args)

    # 交互模式：如果配置中没有 lang 且 CLI 没指定，弹出语言选择并保存
    cfg = load_config()
    cli_lang = getattr(args, 'lang', None)
    if cli_lang:
        set_lang(cli_lang)
    elif cfg.get('lang') in TRANSLATIONS:
        set_lang(cfg['lang'])
    else:
        chosen = prompt_language_select()
        set_lang(chosen)
        save_config({**cfg, 'lang': chosen})

    _maybe_show_update_notice()

    try:
        menu_loop(save_dir=getattr(args, 'save', None))
    except KeyboardInterrupt:
        print(f"\n{Color.Re}{t('prompt.exited')}{Color.Reset}")
    return 0


def _maybe_show_update_notice() -> None:
    """语言已设定后立刻打提示(若缓存有新版本),并在后台刷新缓存。
    分开成函数 — 避免 main() 被 update 逻辑拆得太碎。"""
    info = get_cached_update_info()
    if info:
        print_update_notice(info)
    _start_background_update_check()


if __name__ == '__main__':
    sys.exit(main())
