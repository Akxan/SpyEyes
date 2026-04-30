#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
SpyEyes —— All-in-One OSINT Toolkit (Bilingual: zh / en)

  支持: IP / 本机 IP / 电话 / 用户名 (2067 平台) / WHOIS / MX / 邮箱
  Features: IP / MyIP / Phone / Username (2067 platforms) / WHOIS / MX / Email

  https://github.com/Akxan/SpyEyes

Copyright 2026 Akxan
Licensed under the Apache License, Version 2.0
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import threading
import time
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


# 语义化版本号 —— 同步更新 docs/CHANGELOG.md 与 git tag
__version__ = '1.0.0'


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
                with open(legacy, 'r', encoding='utf-8') as src, \
                     open(new, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
    except OSError:
        pass


def append_history(command: str, query: str, summary: dict) -> None:
    """追加查询记录到 history.jsonl。仅记录元数据（时间/命令/查询/摘要），
    不存完整结果，保护隐私 + 控制文件大小。"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        entry = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'cmd': command,
            'query': query,
            **summary,
        }
        with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        pass


def read_history(limit: int = 50, search: Optional[str] = None) -> list:
    """读取最近的查询历史。limit=最近 N 条，search=按 query 子串过滤。"""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            entries = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    if search:
        s = search.lower()
        entries = [e for e in entries if s in e.get('query', '').lower()
                   or s in e.get('cmd', '').lower()]
    return entries[-limit:]


def load_config() -> dict:
    # 一次性迁移老路径配置（升级用户无感）
    _migrate_legacy_config()
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
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
        'err.invalid_ip':       'Invalid IP address: {ip}',
        'err.invalid_domain':   'Invalid domain: {domain}',
        'err.phone_invalid':    'Phone number is not a possible number',
        'err.save_failed':      'Failed to save to {target}: {err}',
        'msg.progress':         'Scanning',
        'msg.found':            'found',
        'msg.no_history':       '(no history yet — run a query first)',
        'mode.title':           'Scan mode:',
        'mode.quick':           'Quick   (~720 platforms, ~20s)  [recommended]',
        'mode.full':            'Full    (~2067 platforms, ~50s)',
        'mode.cn_es':           'Chinese + Spanish only (~98 platforms, ~6s)',
        'mode.code':            'Code platforms only (~54 platforms, ~3s)',
        'mode.prompt':          'Choose [1/2/3/4, default 1]: ',
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
        'err.invalid_ip':       'IP 地址不合法：{ip}',
        'err.invalid_domain':   '域名格式不合法：{domain}',
        'err.phone_invalid':    '号码格式不可解析',
        'err.save_failed':      '无法保存到 {target}：{err}',
        'msg.progress':         '扫描中',
        'msg.found':            '已命中',
        'msg.no_history':       '（暂无历史 —— 先跑一次查询试试）',
        'mode.title':           '扫描模式:',
        'mode.quick':           '快速   (约 720 平台, ~20 秒)  [推荐]',
        'mode.full':            '完整   (全部 2067 平台, ~50 秒)',
        'mode.cn_es':           '仅中文 + 西语圈 (约 98 平台, ~6 秒)',
        'mode.code':            '仅代码平台 (约 54 平台, ~3 秒)',
        'mode.prompt':          '请选择 [1/2/3/4, 默认 1]: ',
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
        # pool_maxsize=64：100 workers 下不至于 pool 不够触发重建
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=64, pool_maxsize=64, max_retries=0
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
    width = 0
    for ch in s:
        cp = ord(ch)
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
        ipaddress.ip_address(ip)
    except ValueError:
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
_PLATFORMS_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'platforms.json')


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
    过滤掉空 not_found / must_contain 模式，避免假阳性。"""
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for item in data:
        try:
            out.append(Platform(
                name=item['name'],
                url=item['url'],
                category=item.get('category', 'other'),
                not_found=_clean_patterns(item.get('not_found')),
                must_contain=_clean_patterns(item.get('must_contain')),
                regex_check=item.get('regex_check') or '',
            ))
        except (KeyError, TypeError):
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
# worst case 落在毫秒级，足以保护 100 线程池不被消耗。
# 之前用 _REDOS_RE 启发式检测嵌套量词，在合法 regex（如 [a-z]+(-[a-z]+)*）上
# 误报严重；改用长度限制后既简单又有效。
MAX_USERNAME_LENGTH = 64


def _check_username(platform: 'Platform', username: str, timeout: float):
    """检查单个平台是否存在该用户名。返回 (Platform, URL or None, status)。

    Sherlock-inspired 优化:
    1. **regex_check 预过滤**：username 不符合平台规则 → 跳过 HTTP，节省时间
    2. **HEAD 请求**：仅检测 status_code 的平台跳过 body 下载
    3. **stream + 64KB 读取**：需 body 检测的只读前 64 KB
    4. **WAF 检测**：识别 Cloudflare/AWS WAF 等拦截，避免误报
    """
    # 深度防御：track_username 入口已限制长度，但 _check_username 是公开的私有
    # API（_前缀），测试或未来扩展可能直接调用 → 在这里再做一次防护
    if len(username) > MAX_USERNAME_LENGTH:
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
            resp = safe_get(full_url, timeout=timeout, stream=True, allow_redirects=True)
            if resp is None:
                return platform, None, STATUS_NETWORK_ERROR
            try:
                if resp.status_code != 200:
                    return platform, None, STATUS_NOT_FOUND
                return platform, full_url, STATUS_FOUND
            finally:
                resp.close()
        if resp.status_code != 200:
            return platform, None, STATUS_NOT_FOUND
        return platform, full_url, STATUS_FOUND

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


def track_username(username: str, *, max_workers: int = 100, timeout: float = 5,
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
    if show_progress:
        _clear_progress_line()
    # 保持 PLATFORMS 内部顺序；未扫描的平台不出现在结果里
    results = {p.name: found[p.name] for p in platforms_to_scan if p.name in found}
    # 统计信息存到私有 key（_ 开头），打印/保存函数会跳过
    results['_statuses'] = {p.name: statuses[p.name] for p in platforms_to_scan if p.name in statuses}
    return results


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
        'creation_date':   str(w.creation_date) if w.creation_date else None,
        'expiration_date': str(w.expiration_date) if w.expiration_date else None,
        'updated_date':    str(w.updated_date) if w.updated_date else None,
        'name_servers':    w.name_servers,
        'status':          w.status,
        'emails':          w.emails,
        'org':             w.org,
        'country':         w.country,
    }


def mx_lookup(domain: str) -> dict:
    if not HAS_DNS:
        return {'_error': t('err.no_dns')}
    normalized = _normalize_domain(domain)
    if normalized is None:
        return {'_error': t('err.invalid_domain', domain=(domain or '').strip()[:80])}
    domain = normalized
    try:
        answers = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        return {'_error': t('err.nxdomain', domain=domain)}
    except dns.resolver.NoAnswer:
        return {'_error': t('err.no_mx', domain=domain)}
    except Exception as e:
        return {'_error': t('err.dns_failed', e=e)}
    records = sorted(
        [{'preference': r.preference, 'exchange': str(r.exchange).rstrip('.')} for r in answers],
        key=lambda r: r['preference'],
    )
    return {'domain': domain, 'records': records}


EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$')

# 域名基本格式校验（whois/mx 入口防 traceback 泄漏）
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$')


def _normalize_domain(domain: str) -> Optional[str]:
    """规范化并校验 domain。非法返回 None；合法返回 lower-case 形式。
    防御目标：拒绝换行注入 / URL 形式 / 路径片段，避免直接进 dns.resolver / whois.whois。"""
    domain = (domain or '').strip().lower()
    if not domain or not DOMAIN_RE.match(domain):
        return None
    return domain


def email_validate(email: str) -> dict:
    email = (email or '').strip()
    if not email:
        return {'email': '', 'syntax_valid': False, '_error': t('err.empty_input')}
    m = EMAIL_RE.match(email)
    if not m:
        return {'email': email, 'syntax_valid': False, '_error': t('err.email_format')}
    domain = m.group(1)
    result: dict = {'email': email, 'syntax_valid': True, 'domain': domain}
    mx = mx_lookup(domain)
    if '_error' in mx:
        result['mx_valid'] = False
        # 收敛 mx_error 为已知枚举（避免 dns_failed 嵌入 server IP / 内部 socket
        # 错误细节泄漏到 --json 输出）；原始错误进 'mx_error_detail' 仅供调试
        err_msg = mx['_error']
        if 'NXDOMAIN' in err_msg or 'nxdomain' in err_msg or '不存在' in err_msg or 'does not exist' in err_msg.lower():
            result['mx_error'] = 'nxdomain'
        elif 'no_mx' in err_msg or 'no MX' in err_msg or '没有 MX' in err_msg:
            result['mx_error'] = 'no_mx'
        elif 'invalid' in err_msg.lower() or '不合法' in err_msg:
            result['mx_error'] = 'invalid_domain'
        else:
            result['mx_error'] = 'dns_failed'
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
    """从 track_username 返回的 dict 中只取出平台名→URL 项（跳过 _statuses 等私有 key）。"""
    return {k: v for k, v in d.items() if not k.startswith('_')}


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
        print(f" {Color.Re}{result.get('mx_error', '')}{Color.Reset}")


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
    (4, 'menu.username'),
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


def handle_choice(choice: int, save_dir: Optional[str] = None) -> None:
    if choice == 1:
        ip = input(f"{Color.Wh}\n {t('prompt.input_ip')}{Color.Gr}").strip()
        data = track_ip(ip)
        print_ip_info(ip, data)
        _maybe_save(save_dir, f'ip_{ip}', data)
    elif choice == 2:
        my = show_my_ip()
        print_my_ip(my)
        _maybe_save(save_dir, 'my_ip', {'ip': my})
    elif choice == 3:
        num = input(f"\n {Color.Wh}{t('prompt.input_phone')}{Color.Gr}").strip()
        data = track_phone(num)
        print_phone_info(data)
        _maybe_save(save_dir, f'phone_{num}', data)
    elif choice == 4:
        name = input(f"\n {Color.Wh}{t('prompt.input_username')}{Color.Gr}").strip()
        if not name:
            print_username_results({})
            return
        # 选扫描模式
        cats = _ask_scan_mode()
        results = track_username(name, categories=cats)
        print_username_results(results)
        _maybe_save(save_dir, f'username_{name}', results)
    elif choice == 5:
        domain = input(f"\n {Color.Wh}{t('prompt.input_domain')}{Color.Gr}").strip()
        data = whois_lookup(domain)
        print_whois(data)
        _maybe_save(save_dir, f'whois_{domain}', data)
    elif choice == 6:
        domain = input(f"\n {Color.Wh}{t('prompt.input_domain')}{Color.Gr}").strip()
        data = mx_lookup(domain)
        print_mx(data)
        _maybe_save(save_dir, f'mx_{domain}', data)
    elif choice == 7:
        addr = input(f"\n {Color.Wh}{t('prompt.input_email')}{Color.Gr}").strip()
        result = email_validate(addr)
        print_email(result)
        _maybe_save(save_dir, f'email_{addr}', result)
    elif choice == 8:
        switch_language_menu()
    elif choice == 0:
        print(f"\n {Color.Gr}{t('prompt.bye')}{Color.Reset}")
        sys.exit(0)
    else:
        raise ValueError(t('prompt.unknown_option', n=choice))


def _maybe_save(target: Optional[str], prefix: str, data: Any) -> None:
    """保存查询结果。target 可以是：
       - 目录（如 'out/'）：自动生成 <prefix>_<ts>.json
       - 单文件 .md  →  Markdown 报告
       - 单文件 .json → JSON
       - 单文件无扩展 → JSON
    JSON 输出会自动过滤 _* 私有 key（如 _statuses）保持公开 API 干净。
    所有 IO 错误（PermissionError / OSError）友好提示而非抛 traceback 给用户。
    """
    if not target:
        return
    target_lower = target.lower()
    is_md_file = target_lower.endswith('.md')
    is_dir = target.endswith(os.sep) or (os.path.exists(target) and os.path.isdir(target))
    json_data = data
    if isinstance(data, dict) and '_error' not in data:
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
                md = _to_markdown(prefix, data)
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(md)
            else:
                with open(target, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, ensure_ascii=False, indent=2, default=str)
            path = target
    except OSError as e:
        # 包含 PermissionError / FileNotFoundError / NotADirectoryError 等
        sys.stderr.write(f"\n {Color.Re}[error] {t('err.save_failed', target=target, err=e)}{Color.Reset}\n")
        return
    print(f"\n {Color.Cy}{t('msg.saved_to', path=path)}{Color.Reset}")


def _md_escape(s: Any) -> str:
    """转义 markdown 表格 cell：
    - `|`：表格列分隔符
    - `\\r` `\\n`：避免注入伪标题
    - `` ` ``：避免破坏 inline code 围栏，让用户输入跳出 code span 注入任意 markdown
      （security: 用户可控字段如 username/ip/domain 会进 markdown 报告）
    """
    if s is None:
        return ''
    return (str(s)
            .replace('|', '\\|')
            .replace('\r', ' ')
            .replace('\n', ' ')
            .replace('`', '\\`')
            .strip())


def _to_markdown(prefix: str, data: Any) -> str:
    """根据 prefix（如 'ip_8.8.8.8' / 'username_torvalds'）生成 Markdown 报告。
    所有用户输入字段（cmd / query / dict keys / values）都做 escape，
    防止换行注入伪标题或 `|` 破坏表格列数。"""
    lines = []
    cmd, _, query = prefix.partition('_')
    # query/cmd 可能含恶意换行符 → 单行化
    cmd = _md_escape(cmd) or '?'
    query = _md_escape(query)
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    lines.append("# 🔍 SpyEyes Report")
    lines.append("")
    lines.append(f"- **Command**: `{cmd}`")
    lines.append(f"- **Query**: `{query}`")
    lines.append(f"- **Generated**: {ts}")
    lines.append("- **Tool**: [SpyEyes](https://github.com/Akxan/SpyEyes)")
    lines.append("")
    lines.append("---")
    lines.append("")

    if isinstance(data, dict) and '_error' in data:
        lines.append(f"## ❌ Error\n\n> {data['_error']}\n")
        return '\n'.join(lines)

    if cmd == 'username' and isinstance(data, dict):
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        lines.append(f"## Username scan: `{query}`")
        lines.append("")
        lines.append(f"**Scanned {len(plat)} platforms · Found {found} accounts**")
        lines.append("")
        for cat in CATEGORY_ORDER:
            cat_pl = [p for p in _get_platforms() if p.category == cat and p.name in plat]
            cat_found = [(p, plat[p.name]) for p in cat_pl if plat[p.name]]
            if not cat_found:
                continue
            lines.append(f"### {_md_escape(cat.title())} ({len(cat_found)}/{len(cat_pl)})")
            lines.append("")
            lines.append("| Platform | Profile URL |")
            lines.append("|---|---|")
            for p, url in cat_found:
                lines.append(f"| {_md_escape(p.name)} | <{_md_escape(url)}> |")
            lines.append("")
        return '\n'.join(lines)

    if cmd == 'mx' and isinstance(data, dict) and 'records' in data:
        lines.append(f"## MX Records for `{data.get('domain', query)}`")
        lines.append("")
        lines.append("| Priority | Mail Server |")
        lines.append("|---:|---|")
        for r in data['records']:
            lines.append(f"| {r['preference']} | `{r['exchange']}` |")
        lines.append("")
        return '\n'.join(lines)

    # 通用：扁平化 dict 为表格（key 与 value 都转义；跳过 _* 私有 key）
    if isinstance(data, dict):
        lines.append(f"## {cmd.upper()} info: `{query}`")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        for k, v in _platform_only(data).items():
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
        try:
            handle_choice(choice, save_dir=save_dir)
        except ValueError as e:
            print(f"\n {Color.Re}{e}{Color.Reset}")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n {Color.Re}{t('prompt.interrupted')}{Color.Reset}")
            continue
        if choice != 0:
            input(f"\n{Color.Wh}[ {Color.Gr}+ {Color.Wh}] {Color.Gr}{t('prompt.press_enter')}{Color.Reset}")


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
        epilog="""Examples / 示例:
  python3 spyeyes.py                          # Interactive menu / 交互菜单
  python3 spyeyes.py --lang en                # Force English UI / 强制英文界面
  python3 spyeyes.py ip 8.8.8.8               # IP lookup
  python3 spyeyes.py myip --lang en           # English JSON
  python3 spyeyes.py phone +12025550100       # Phone parse
  python3 spyeyes.py user torvalds            # Username scan
  python3 spyeyes.py whois example.com        # WHOIS
  python3 spyeyes.py mx gmail.com             # MX records
  python3 spyeyes.py email a@b.com            # Email validate
  python3 spyeyes.py ip 8.8.8.8 --json        # JSON output
  python3 spyeyes.py ip 8.8.8.8 --save out/   # Save to file
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
    sp.add_argument('--workers', type=_positive_int, default=100,
                    help='Concurrent threads / 并发线程数 (default: 100, max 200)')
    sp.add_argument('--timeout', type=float, default=5.0,
                    help='HTTP timeout per platform in seconds / 单平台超时秒数 (default: 5)')
    sp.add_argument('--all', action='store_true', dest='show_all',
                    help='Show all platforms incl. misses / 显示所有平台（含未命中）')
    sp.add_argument('--quick', action='store_true',
                    help='Skip "other" long-tail (~720 platforms vs 2068, ~3-4x faster) / 跳过 other 长尾，仅扫主流 ~720 个')
    sp.add_argument('--category', dest='category_filter',
                    help='Comma-separated categories: code,social,chinese,spanish,... / 用逗号分隔的类别')

    sp = sub.add_parser('whois', parents=[common], help='WHOIS lookup')
    sp.add_argument('domains', nargs='+', help='One or more domains for batch query')

    sp = sub.add_parser('mx', parents=[common], help='MX records')
    sp.add_argument('domains', nargs='+', help='One or more domains for batch query')

    sp = sub.add_parser('email', parents=[common], help='Email validation / 邮箱验证')
    sp.add_argument('address')

    sp = sub.add_parser('history', parents=[common], help='Show recent queries / 显示历史查询')
    sp.add_argument('--limit', type=int, default=20, help='Max entries to show (default: 20)')
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
        data = {'ip': ip}
        save_prefix = 'my_ip'
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
        data = track_username(args.username, max_workers=args.workers,
                              timeout=args.timeout, categories=cats)
        save_prefix = f'username_{args.username}'
        if args.json:
            # 剥掉私有 _* key（如 _statuses）—— 这些是 print_* 的内部使用
            json_data = _platform_only(data) if isinstance(data, dict) and '_error' not in data else data
            _emit_json(json_data)
        else:
            print_username_results(data, show_all=getattr(args, 'show_all', False))
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
        summary = {'number': args.number, 'ok': ok}
    elif cmd == 'user':
        plat = _platform_only(data)
        found = sum(1 for v in plat.values() if v)
        summary = {'username': args.username, 'scanned': len(plat), 'found': found}
    elif cmd in ('whois', 'mx'):
        summary = {'domains': args.domains}
    elif cmd == 'email':
        summary = {'address': args.address, 'mx_valid': data.get('mx_valid')}
    query = summary.get('target') or summary.get('username') or summary.get('address') \
            or (summary.get('domains') and ','.join(summary['domains'])) or summary.get('number') or ''
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
