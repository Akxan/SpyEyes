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
__version__ = '1.2.0'


# ====================================================================
# CONFIG —— 用户偏好持久化（语言等）
# ====================================================================
CONFIG_DIR = os.path.expanduser('~/.spyeyes')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
HISTORY_FILE = os.path.join(CONFIG_DIR, 'history.jsonl')

# 历史遗留路径（早期版本配置目录），首次启动时自动迁移
_LEGACY_CONFIG_DIR = os.path.expanduser('~/.ghosttrack')


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
        'menu.lang':            'Language / 语言',
        'menu.exit':            'Exit',
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
        'field.carrier':        'Carrier',
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
    },
    'zh': {
        'menu.ip_track':        'IP 追踪',
        'menu.my_ip':           '查看本机 IP',
        'menu.phone':           '电话号码追踪',
        'menu.username':        '用户名追踪',
        'menu.whois':           '域名 WHOIS 查询',
        'menu.mx':              '域名 MX 记录',
        'menu.email':           '邮箱有效性检查',
        'menu.lang':            '切换语言 / Language',
        'menu.exit':            '退出',
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
        'field.carrier':        '运营商',
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
             stream: bool = False, **kwargs) -> Optional[requests.Response]:
    """带连接池复用 + 拆分超时的 HTTP 请求。
    method='HEAD' 时跳过 body 下载 —— 仅看 status_code 的平台用得上。
    stream=True 时调用方负责读取/关闭（用于早停 body 读）。"""
    extra_headers = kwargs.pop('headers', None) or {}
    try:
        session = _get_session()
        # 拆分 timeout：连接 3s 上限 + 读取 timeout 秒
        req_timeout = (min(3.0, timeout), timeout)
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
    if os.name == 'nt':
        os.system('cls')
    elif os.environ.get('TERM'):
        os.system('clear')


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


def track_phone(number: str, default_region: str = 'CN') -> dict:
    try:
        parsed = phonenumbers.parse(number, default_region)
    except NumberParseException as e:
        return {'_error': t('err.parse_phone', e=e)}

    # `parse('+1')` 等形似号码会成功但 is_possible_number=False；返回 _error
    # 避免 _record_history 把它记为成功
    if not phonenumbers.is_possible_number(parsed):
        return {'_error': t('err.phone_invalid')}

    lib_lang = 'zh' if _lang == 'zh' else 'en'
    return {
        'location':      geocoder.description_for_number(parsed, lib_lang) or t('msg.unknown'),
        'region_code':   phonenumbers.region_code_for_number(parsed) or t('msg.unknown'),
        'timezones':     ', '.join(timezone.time_zones_for_number(parsed)) or t('msg.unknown'),
        # phonenumbers 库的 carrier 中文翻译只覆盖中国 —— 国外号码 zh 模式拿不到，
        # 必须回退英文（如 'KDDI' / 'T-Mobile' / 'Airtel'）；都拿不到才显示「未知」
        'carrier':       (carrier.name_for_number(parsed, lib_lang)
                          or carrier.name_for_number(parsed, 'en')
                          or t('msg.unknown')),
        'is_valid':      phonenumbers.is_valid_number(parsed),
        'is_possible':   phonenumbers.is_possible_number(parsed),
        'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        'mobile_dial':   phonenumbers.format_number_for_mobile_dialing(parsed, default_region, with_formatting=True),
        'national':      parsed.national_number,
        'e164':          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        'country_code':  parsed.country_code,
        'number_type':   t(_PHONE_TYPE_KEY.get(phonenumbers.number_type(parsed), 'phone.other')),
    }


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
        new_candidates: list[str] = []
        for url in found_urls[:RECURSIVE_FETCH_LIMIT]:
            try:
                resp = safe_get(url, timeout=timeout, method='GET')
                # 仅抓 first 64KB 防大页面拖慢
                body = (resp.text or '')[:65536] if resp is not None else ''
            except Exception:
                continue
            extracted = _extract_usernames_from_text(body, visited)
            for u in extracted:
                if u not in new_candidates:
                    new_candidates.append(u)
                if len(new_candidates) >= RECURSIVE_MAX_NEW_PER_DEPTH:
                    break
            if len(new_candidates) >= RECURSIVE_MAX_NEW_PER_DEPTH:
                break
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
    print_field(t('field.carrier'),        data['carrier'],       width=22)
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
    (8, 'menu.lang'),
    (0, 'menu.exit'),
]


def show_menu() -> None:
    print_banner()
    print()
    for num, key in MENU_KEYS:
        print(f"{Color.Wh}[ {num} ] {Color.Gr}{t(key)}{Color.Reset}")


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
    if choice == 1:
        ip = input(f"{Color.Wh}\n {t('prompt.input_ip')}{Color.Gr}").strip()
        data = track_ip(ip)
        print_ip_info(ip, data)
        _interactive_save_prompt(f'ip_{ip}', data, save_dir)
    elif choice == 2:
        my = show_my_ip()
        print_my_ip(my)
        _interactive_save_prompt('myip', {'ip': my}, save_dir)
    elif choice == 3:
        num = input(f"\n {Color.Wh}{t('prompt.input_phone')}{Color.Gr}").strip()
        data = track_phone(num)
        print_phone_info(data)
        _interactive_save_prompt(f'phone_{num}', data, save_dir)
    elif choice == 4:
        name = input(f"\n {Color.Wh}{t('prompt.input_username')}{Color.Gr}").strip()
        if not name:
            print_username_results({})
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
        domain = input(f"\n {Color.Wh}{t('prompt.input_domain')}{Color.Gr}").strip()
        data = whois_lookup(domain)
        print_whois(data)
        _interactive_save_prompt(f'whois_{domain}', data, save_dir)
    elif choice == 6:
        domain = input(f"\n {Color.Wh}{t('prompt.input_domain')}{Color.Gr}").strip()
        data = mx_lookup(domain)
        print_mx(data)
        _interactive_save_prompt(f'mx_{domain}', data, save_dir)
    elif choice == 7:
        addr = input(f"\n {Color.Wh}{t('prompt.input_email')}{Color.Gr}").strip()
        result = email_validate(addr)
        print_email(result)
        _interactive_save_prompt(f'email_{addr}', result, save_dir)
    elif choice == 8:
        # v1.2.0: 切换语言（之前是 [9]，permute 子菜单合并到 [4] 后腾出位置）
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
    lines.append(f"# 🔍 {t('report.title')}")
    lines.append("")
    lines.append(f"- **{t('report.command')}**: `{cmd}`")
    lines.append(f"- **{t('report.query')}**: `{query}`")
    lines.append(f"- **{t('report.generated')}**: {ts}")
    lines.append(f"- **{t('report.tool')}**: [SpyEyes](https://github.com/Akxan/SpyEyes)")
    lines.append("")
    lines.append("---")
    lines.append("")

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
        styles = _rl_styles()
        story: list = []
        story.append(_rl_paragraph(f"<b>{_md_escape(t('report.title'))}</b>", styles['Title']))
        story.append(_rl_spacer(1, 12))
        story.append(_rl_paragraph(f"<b>{_md_escape(t('report.command'))}:</b> {cmd}", styles['Normal']))
        story.append(_rl_paragraph(f"<b>{_md_escape(t('report.query'))}:</b> {query}", styles['Normal']))
        story.append(_rl_paragraph(f"<b>{_md_escape(t('report.generated'))}:</b> {ts}", styles['Normal']))
        story.append(_rl_spacer(1, 18))
        if isinstance(data, dict) and '_error' in data:
            story.append(_rl_paragraph(
                f"<b>{_md_escape(t('report.error'))}:</b> {_md_escape(data['_error'])}", styles['Normal']))
        elif cmd == 'username' and isinstance(data, dict):
            plat = _platform_only(data)
            found = sum(1 for v in plat.values() if v)
            story.append(_rl_paragraph(
                f"<b>{_md_escape(t('report.username_scan'))}:</b> {query}", styles['Heading2']))
            story.append(_rl_paragraph(
                _md_escape(t('report.scan_summary', total=len(plat), found=found)),
                styles['Normal']))
            story.append(_rl_spacer(1, 12))
            for cat in CATEGORY_ORDER:
                cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
                cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
                if not cat_found:
                    continue
                cat_label = _md_escape(t(f'cat.{cat}'))
                story.append(_rl_paragraph(
                    f"<b>{cat_label}</b> ({len(cat_found)}/{len(cat_pl)})",
                    styles['Heading3']))
                table_data = [[_md_escape(t('report.platform')), _md_escape(t('report.url'))]]
                for p, url in cat_found:
                    # reportlab 支持 inline 标签，但用户输入须 escape 防伪标签注入
                    safe_name = _md_escape(p.name)
                    safe_url = _md_escape(url)
                    table_data.append([safe_name, safe_url])
                tbl = _rl_table(table_data, colWidths=[150, 350])
                tbl.setStyle(_rl_table_style([
                    ('BACKGROUND', (0, 0), (-1, 0), _rl_colors.lightgrey),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.25, _rl_colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(tbl)
                story.append(_rl_spacer(1, 12))
        elif cmd == 'permute' and _is_permute_only(data):
            # v1.2.1 P1-2：仅生成变形（不扫描）
            story.append(_rl_paragraph(
                f"<b>{_md_escape(t('permute.title'))}:</b> {_md_escape(data.get('name', query))}",
                styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            for v in data.get('permutations', []):
                story.append(_rl_paragraph(f"• {_md_escape(v)}", styles['Normal']))
        elif cmd == 'permute' and _is_permute_scan(data):
            # v1.2.1 P1-2：变形 + 批量扫描，每个变形一节
            story.append(_rl_paragraph(
                f"<b>{_md_escape(t('permute.title'))}:</b> {query}", styles['Heading2']))
            story.append(_rl_paragraph(
                f"{len(data)} variations scanned", styles['Normal']))
            story.append(_rl_spacer(1, 12))
            for var, scan in data.items():
                if not isinstance(scan, dict):
                    continue
                story.append(_rl_paragraph(f"<b>{_md_escape(var)}</b>", styles['Heading3']))
                if '_error' in scan:
                    story.append(_rl_paragraph(
                        f"{_md_escape(t('report.error'))}: {_md_escape(scan['_error'])}",
                        styles['Normal']))
                    story.append(_rl_spacer(1, 6))
                    continue
                plat = _platform_only(scan)
                found = sum(1 for v in plat.values() if v)
                story.append(_rl_paragraph(
                    _md_escape(t('report.scan_summary', total=len(plat), found=found)),
                    styles['Normal']))
                if found > 0:
                    p_table = [[_md_escape(t('report.platform')),
                                _md_escape(t('report.url'))]]
                    for p_name, url in plat.items():
                        if url:
                            p_table.append([_md_escape(p_name), _md_escape(url)])
                    tbl = _rl_table(p_table, colWidths=[150, 350])
                    tbl.setStyle(_rl_table_style([
                        ('BACKGROUND', (0, 0), (-1, 0), _rl_colors.lightgrey),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.25, _rl_colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(tbl)
                story.append(_rl_spacer(1, 10))
        elif cmd == 'mx' and isinstance(data, dict) and 'records' in data:
            # MX 专用（v1.2.1 P0-3 修复，之前落到通用 dict 把 records list 压成 repr）
            domain_lbl = _md_escape(data.get('domain', query))
            story.append(_rl_paragraph(
                f"<b>{_md_escape(t('report.mx_records'))}:</b> {domain_lbl}",
                styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            mx_table = [[_md_escape(t('report.priority')), _md_escape(t('report.mail_server'))]]
            for r in data['records']:
                mx_table.append([str(r.get('preference', '')),
                                 _md_escape(r.get('exchange', ''))])
            tbl = _rl_table(mx_table, colWidths=[80, 420])
            tbl.setStyle(_rl_table_style([
                ('BACKGROUND', (0, 0), (-1, 0), _rl_colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.25, _rl_colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ]))
            story.append(tbl)
        elif isinstance(data, dict):
            story.append(_rl_paragraph(
                f"<b>{cmd.upper()} {_md_escape(t('report.info_for'))}:</b> {query}", styles['Heading2']))
            story.append(_rl_spacer(1, 8))
            items = data.items() if cmd != 'username' else _platform_only(data).items()
            table_data = [[_md_escape(t('report.field')), _md_escape(t('report.value'))]]
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
                table_data.append([_md_escape(k), _md_escape(v_str)])
            tbl = _rl_table(table_data, colWidths=[150, 350])
            tbl.setStyle(_rl_table_style([
                ('BACKGROUND', (0, 0), (-1, 0), _rl_colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.25, _rl_colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(tbl)
        else:
            story.append(_rl_paragraph(
                _md_escape(json.dumps(data, ensure_ascii=False, default=str)),
                styles['Code']))
        doc = _rl_doc(out_path, pagesize=_rl_a4)
        doc.build(story)
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

    parts = [
        '<!DOCTYPE html>',
        f'<html lang="{html_lang}">',
        '<head>',
        '<meta charset="utf-8">',
        f'<title>{title_safe} — {query_safe}</title>',
        '<style>',
        'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;'
        'max-width:960px;margin:2em auto;padding:1em;color:#222;background:#fafafa}',
        'h1{border-bottom:3px solid #0066cc;padding-bottom:.3em}',
        'h2{color:#0066cc;margin-top:1.5em}',
        'h3.cat{color:#0a8c4a;margin-top:1.2em;padding-left:.5em;border-left:4px solid #0a8c4a}',
        'table{border-collapse:collapse;width:100%;margin:.7em 0;background:#fff}',
        'th,td{border:1px solid #ddd;padding:8px 12px;text-align:left;vertical-align:top}',
        'th{background:#f4f4f4;font-weight:600}',
        'tr:nth-child(even){background:#fafafa}',
        '.error{color:#c00;background:#fee;padding:1em;border-radius:4px;border:1px solid #fcc}',
        'a{color:#0066cc;text-decoration:none}',
        'a:hover{text-decoration:underline}',
        'code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-family:SFMono-Regular,Menlo,monospace}',
        '.meta{color:#666;font-size:0.9em}',
        '</style>',
        '</head><body>',
        f'<h1>🔍 {title_safe}</h1>',
        f'<p class="meta"><b>{_html_escape(t("report.command"))}:</b> <code>{cmd_safe}</code> · '
        f'<b>{_html_escape(t("report.query"))}:</b> <code>{query_safe}</code> · '
        f'<b>{_html_escape(t("report.generated"))}:</b> {ts}</p>',
        '<hr>',
    ]

    if isinstance(data, dict) and '_error' in data:
        parts.append(
            f'<div class="error">❌ <b>{_html_escape(t("report.error"))}:</b> '
            f'{_html_escape(data["_error"])}</div>'
        )
        parts.extend(['</body>', '</html>'])
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
        parts.extend(['</body>', '</html>'])
        return '\n'.join(parts)

    # v1.2.1 P1-2: permute 仅生成变形 —— 列表
    if cmd == 'permute' and _is_permute_only(data):
        name_safe = _html_escape(data.get('name', query))
        parts.append(f'<h2>{_html_escape(t("permute.title"))} <code>{name_safe}</code></h2>')
        parts.append('<ul>')
        for v in data.get('permutations', []):
            parts.append(f'<li><code>{_html_escape(v)}</code></li>')
        parts.append('</ul>')
        parts.extend(['</body>', '</html>'])
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
        parts.extend(['</body>', '</html>'])
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
        parts.extend(['</body>', '</html>'])
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
        parts.extend(['</body>', '</html>'])
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
    lines = [
        '═══════════════════════════════════════════════',
        f'  🔍 {t("report.title")}',
        '═══════════════════════════════════════════════',
        f'{t("report.command"):11} {cmd}',
        f'{t("report.query"):11} {query}',
        f'{t("report.generated"):11} {ts}',
        '',
    ]
    if isinstance(data, dict) and '_error' in data:
        lines.append(f'{t("report.error").upper()}: {data["_error"]}')
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
    """XMind 8 文件（zip 含 content.xml + meta.xml + manifest.xml），纯标准库实现。
    无新依赖；XMind 8 可直接打开。返回错误字符串（成功时返回 None）。"""
    try:
        cmd, _, query = prefix.partition('_')
        ts = time.strftime('%Y-%m-%d %H:%M:%S')

        def _topic(title: str, children: Optional[list] = None,
                   href: Optional[str] = None) -> str:
            tid = _uuid.uuid4().hex
            href_attr = f' xlink:href="{_html_escape(href)}"' if href else ''
            inner = f'<title>{_html_escape(title)}</title>'
            if children:
                kids = ''.join(children)
                inner += f'<children><topics type="attached">{kids}</topics></children>'
            return f'<topic id="{tid}"{href_attr}>{inner}</topic>'

        if isinstance(data, dict) and '_error' in data:
            sub_topics = [_topic(f'{t("report.error")}: {data["_error"]}')]
        elif cmd == 'username' and isinstance(data, dict):
            sub_topics = []
            plat = _platform_only(data)
            for cat in CATEGORY_ORDER:
                cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
                cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
                if not cat_found:
                    continue
                cat_kids = [_topic(p.name, href=url) for p, url in cat_found]
                sub_topics.append(_topic(
                    f'{t(f"cat.{cat}")} ({len(cat_found)}/{len(cat_pl)})', cat_kids
                ))
        elif cmd == 'permute' and _is_permute_only(data):
            # v1.2.1 P1-2：仅变形列表
            sub_topics = [
                _topic(v) for v in data.get('permutations', [])
            ]
        elif cmd == 'permute' and _is_permute_scan(data):
            # v1.2.1 P1-2：每个变形一棵子树
            sub_topics = []
            for var, scan in data.items():
                if not isinstance(scan, dict):
                    continue
                if '_error' in scan:
                    sub_topics.append(_topic(f'{var}: {t("report.error")} {scan["_error"]}'))
                    continue
                plat = _platform_only(scan)
                p_kids = [_topic(p_name, href=url) for p_name, url in plat.items() if url]
                found = len(p_kids)
                sub_topics.append(_topic(f'{var} ({found} hits)', p_kids))
        elif cmd == 'mx' and isinstance(data, dict) and 'records' in data:
            # MX 专用（v1.2.1 P0-3 修复）
            domain_lbl = data.get('domain', query)
            mx_kids = [
                _topic(f'{t("report.priority")} {r.get("preference", "")} → {r.get("exchange", "")}')
                for r in data['records']
            ]
            sub_topics = [_topic(f'{t("report.mx_records")} {domain_lbl}', mx_kids)]
        elif isinstance(data, dict):
            sub_topics = []
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
            sub_topics = [_topic(json.dumps(data, ensure_ascii=False, default=str))]

        root_id = _uuid.uuid4().hex
        kids_xml = ''.join(sub_topics)
        children_xml = (f'<children><topics type="attached">{kids_xml}</topics></children>'
                       if sub_topics else '')

        content_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
            '<xmap-content xmlns="urn:xmind:xmap:xmlns:content:2.0" '
            'xmlns:xlink="http://www.w3.org/1999/xlink" '
            f'version="2.0" timestamp="{int(time.time() * 1000)}">'
            '<sheet id="sheet1">'
            f'<title>{_html_escape(t("report.title"))}</title>'
            f'<topic id="{root_id}">'
            f'<title>{_html_escape(cmd)}: {_html_escape(query)} ({_html_escape(ts)})</title>'
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
<title>{graph_title} — {query_safe}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
html, body {{ height: 100%; margin: 0; }}
body {{ background: #fafafa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  display: flex; flex-direction: column; overflow: hidden; }}
.header {{ padding: 1em 2em; background: #fff; border-bottom: 1px solid #ddd; flex-shrink: 0; }}
.header h2 {{ margin: 0; color: #0066cc; }}
.header p {{ color: #666; margin: .3em 0 0; }}
.legend {{ display: flex; gap: 1em; margin-top: .5em; font-size: .85em; color: #666; flex-wrap: wrap; }}
.legend span {{ display: flex; align-items: center; gap: .3em; }}
.legend i {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; }}
.legend kbd {{ background: #f0f0f0; border: 1px solid #ccc; border-radius: 3px; padding: 1px 5px; font-size: .85em; }}
.node circle {{ stroke: #fff; stroke-width: 1.5px; }}
.node text {{ font-size: 11px; pointer-events: none; fill: #333;
  paint-order: stroke; stroke: rgba(255,255,255,0.85); stroke-width: 3px; }}
.link {{ stroke: #999; stroke-opacity: 0.35; }}
svg {{ flex: 1 1 auto; width: 100%; cursor: grab; display: block; background: #fafafa; }}
svg:active {{ cursor: grabbing; }}
</style>
</head>
<body>
<div class="header">
  <h2>🔍 {graph_title}: {query_safe}</h2>
  <p>{gen_label}: {ts} · {found_n_safe} · {graph_help_safe}</p>
  <div class="legend">
    <span><i style="background:#e74c3c"></i> {legend_q}</span>
    <span><i style="background:#3498db"></i> {legend_h}</span>
    <span><i style="background:#95a5a6"></i> {legend_o}</span>
  </div>
</div>
<svg></svg>
<script>
const nodes = {nodes_json};
const links = {links_json};
const colors = {{1:'#e74c3c', 2:'#3498db', 3:'#95a5a6'}};
const initialRadius = {initial_radius};

const svg = d3.select('svg');
const container = svg.node();

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
const node = root.append('g').attr('class', 'nodes').selectAll('g').data(nodes).join('g').attr('class', 'node')
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

// d3.zoom：滚轮缩放 + 拖拽空白处平移；scale 0.1-8 防过度缩放
const zoom = d3.zoom()
  .scaleExtent([0.05, 8])
  .on('zoom', e => root.attr('transform', e.transform));
svg.call(zoom);

// 自适应：模拟稳定后或按 F 键，把整个图缩放/平移到完全可见
function fitToView() {{
  const bbox = root.node().getBBox();
  if (!bbox.width || !bbox.height) return;
  const padding = 60;
  const w = container.clientWidth || window.innerWidth;
  const h = container.clientHeight || (window.innerHeight - 140);
  const scale = Math.min(
    (w - padding * 2) / bbox.width,
    (h - padding * 2) / bbox.height,
    1.5
  );
  const tx = w / 2 - (bbox.x + bbox.width / 2) * scale;
  const ty = h / 2 - (bbox.y + bbox.height / 2) * scale;
  svg.transition().duration(700).call(
    zoom.transform,
    d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}}

// 第一次稳定后自动 fit
let fitted = false;
simulation.on('end', () => {{ if (!fitted) {{ fitted = true; fitToView(); }} }});
// 兜底：3 秒后无论稳定与否都 fit 一次（节点多时模拟可能跑很久）
setTimeout(() => {{ if (!fitted) {{ fitted = true; fitToView(); }} }}, 3000);

// F 键随时重新 fit；R 键重置缩放
window.addEventListener('keydown', e => {{
  if (e.key === 'f' || e.key === 'F') fitToView();
  if (e.key === 'r' || e.key === 'R') svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
}});

// 窗口 resize 自适应
window.addEventListener('resize', () => fitToView());
</script>
</body>
</html>
'''


_DEFAULT_REPORT_DIR_CACHE: Optional[str] = None


def _default_report_dir() -> str:
    """v1.2.0：默认报告保存目录（~/Downloads，跨平台）。
    fallback 顺序：~/Downloads → ~/Download → ~/spyeyes-reports（自动创建） → cwd
    v1.2.1 P2-3：模块级缓存，多格式连续保存循环里不重复 stat。"""
    global _DEFAULT_REPORT_DIR_CACHE
    if _DEFAULT_REPORT_DIR_CACHE is not None:
        return _DEFAULT_REPORT_DIR_CACHE
    candidates = [
        os.path.expanduser('~/Downloads'),  # macOS / Linux / Windows 标准
        os.path.expanduser('~/Download'),   # 部分 Linux 发行版
    ]
    for d in candidates:
        if os.path.isdir(d):
            _DEFAULT_REPORT_DIR_CACHE = d
            return d
    fallback = os.path.expanduser('~/spyeyes-reports')
    try:
        os.makedirs(fallback, exist_ok=True)
        _DEFAULT_REPORT_DIR_CACHE = fallback
        return fallback
    except OSError:
        cwd = os.getcwd()
        _DEFAULT_REPORT_DIR_CACHE = cwd
        return cwd


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

    sp = sub.add_parser('history', parents=[common], help='Show recent queries / 显示历史查询')
    sp.add_argument('--limit', type=_positive_int, default=20,
                    help='Max entries to show, must be >= 1 (default: 20, max 200)')
    sp.add_argument('--search', help='Filter by query substring')
    return parser


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
    else:
        # 未知 cmd（未来加新子命令但忘了更新这里）→ 不写空 entry 污染历史
        return
    query = summary.get('target') or summary.get('username') or summary.get('address') \
            or (summary.get('domains') and ','.join(summary['domains'])) or summary.get('number') \
            or summary.get('name') or ''
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

    # CLI 模式：直接根据语言优先级选定，不弹首次提示
    if args.command:
        set_lang(resolve_language(args))
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

    try:
        menu_loop(save_dir=getattr(args, 'save', None))
    except KeyboardInterrupt:
        print(f"\n{Color.Re}{t('prompt.exited')}{Color.Reset}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
