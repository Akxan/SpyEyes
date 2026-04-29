#!/usr/bin/env python3
# << CODE BY HUNX04 (中文重构版)
# << 原作者 https://github.com/HunxByts/GhostTrack

"""
GhostTrack —— OSINT 信息查询工具（中文版）

功能：
  * IP 地址归属查询（IPv4 / IPv6，含国家中文名）
  * 本机出口 IP 查询
  * 电话号码解析（归属地 / 运营商 / 时区，全中文）
  * 用户名社交平台扫描（并发，含内容关键词检测）
  * 域名 WHOIS 查询
  * 域名 MX 记录查询
  * 邮箱有效性验证（格式 + MX 检查）

支持交互式菜单 与 命令行参数 两种使用方式，可选 JSON 输出与结果保存。
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

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


# ====================================================================
# 颜色配置：自动检测终端，是否为 TTY 决定是否输出 ANSI 转义
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
# HTTP 配置
# ====================================================================
DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


def safe_get(url: str, *, timeout: float = DEFAULT_TIMEOUT, **kwargs) -> Optional[requests.Response]:
    """带超时和默认 User-Agent 的 GET，网络异常时返回 None。"""
    headers = {**DEFAULT_HEADERS, **kwargs.pop('headers', {})}
    try:
        return requests.get(url, timeout=timeout, headers=headers, **kwargs)
    except requests.exceptions.RequestException:
        return None


# ====================================================================
# 国家代码 → 中文名（覆盖 ~180 个常用国家/地区）
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
    if not code:
        return fallback
    return COUNTRY_ZH.get(code.upper(), fallback)


# ====================================================================
# 通用打印工具
# ====================================================================
def display_width(s: str) -> int:
    """估算字符串在等宽终端中的视觉宽度，CJK / 全角字符按 2 计。"""
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


def print_field(label: str, value: Any, *, width: int = 16, indent: str = ' ') -> None:
    """对齐打印「字段名 : 值」，根据中文显示宽度自动补齐空格。"""
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
    resp = safe_get(f"https://ipwho.is/{ip}")
    if resp is None:
        return {'_error': '网络请求失败（超时或连接错误）'}
    try:
        data = resp.json()
    except ValueError:
        return {'_error': 'API 返回了非 JSON 响应'}
    if data.get('success') is False:
        return {'_error': data.get('message', '未知 API 错误')}
    return data


def show_my_ip() -> Optional[str]:
    resp = safe_get('https://api.ipify.org/')
    if resp is None or resp.status_code != 200:
        return None
    return resp.text.strip()


# ====================================================================
# 核心查询：电话号码
# ====================================================================
_PHONE_TYPE_ZH = {
    phonenumbers.PhoneNumberType.MOBILE:               '移动电话',
    phonenumbers.PhoneNumberType.FIXED_LINE:           '固定电话',
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: '固定/移动电话',
    phonenumbers.PhoneNumberType.TOLL_FREE:            '免费电话',
    phonenumbers.PhoneNumberType.PREMIUM_RATE:         '付费电话',
    phonenumbers.PhoneNumberType.SHARED_COST:          '共享费用电话',
    phonenumbers.PhoneNumberType.VOIP:                 'VoIP',
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER:      '个人号码',
    phonenumbers.PhoneNumberType.PAGER:                '寻呼机',
    phonenumbers.PhoneNumberType.UAN:                  '通用接入号',
    phonenumbers.PhoneNumberType.VOICEMAIL:            '语音信箱',
    phonenumbers.PhoneNumberType.UNKNOWN:              '未知',
}


def track_phone(number: str, default_region: str = 'CN') -> dict:
    try:
        parsed = phonenumbers.parse(number, default_region)
    except NumberParseException as e:
        return {'_error': f'号码解析失败：{e}'}

    return {
        'location':      geocoder.description_for_number(parsed, 'zh') or '(未知)',
        'region_code':   phonenumbers.region_code_for_number(parsed) or '(未知)',
        'timezones':     ', '.join(timezone.time_zones_for_number(parsed)) or '(未知)',
        'carrier':       carrier.name_for_number(parsed, 'zh') or '(未知)',
        'is_valid':      phonenumbers.is_valid_number(parsed),
        'is_possible':   phonenumbers.is_possible_number(parsed),
        'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        'mobile_dial':   phonenumbers.format_number_for_mobile_dialing(parsed, default_region, with_formatting=True),
        'national':      parsed.national_number,
        'e164':          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        'country_code':  parsed.country_code,
        'number_type':   _PHONE_TYPE_ZH.get(phonenumbers.number_type(parsed), '其他类型'),
    }


# ====================================================================
# 核心查询：用户名扫描（并发 + 内容关键词检测）
# ====================================================================
SOCIAL_PLATFORMS = [
    ('Facebook',     'https://www.facebook.com/{}'),
    ('Twitter',      'https://twitter.com/{}'),
    ('Instagram',    'https://www.instagram.com/{}'),
    ('LinkedIn',     'https://www.linkedin.com/in/{}'),
    ('GitHub',       'https://github.com/{}'),
    ('Pinterest',    'https://www.pinterest.com/{}'),
    ('Tumblr',       'https://{}.tumblr.com'),
    ('YouTube',      'https://www.youtube.com/@{}'),
    ('SoundCloud',   'https://soundcloud.com/{}'),
    ('Snapchat',     'https://www.snapchat.com/add/{}'),
    ('TikTok',       'https://www.tiktok.com/@{}'),
    ('Behance',      'https://www.behance.net/{}'),
    ('Medium',       'https://medium.com/@{}'),
    ('Quora',        'https://www.quora.com/profile/{}'),
    ('Flickr',       'https://www.flickr.com/people/{}'),
    ('Twitch',       'https://www.twitch.tv/{}'),
    ('Dribbble',     'https://dribbble.com/{}'),
    ('Ello',         'https://ello.co/{}'),
    ('Product Hunt', 'https://www.producthunt.com/@{}'),
    ('Telegram',     'https://t.me/{}'),
    ('Reddit',       'https://www.reddit.com/user/{}'),
    ('GitLab',       'https://gitlab.com/{}'),
    ('Keybase',      'https://keybase.io/{}'),
]

NOT_FOUND_PATTERNS = {
    'GitHub':    [b'not found', b'page-404'],
    'Pinterest': [b"sorry, we couldn't find"],
    'Reddit':    [b'page not found', b'sorry, nobody on reddit'],
    'Tumblr':    [b"there's nothing here"],
    'Quora':     [b'page not found'],
    'GitLab':    [b'page not found'],
    'Medium':    [b'page not found'],
}


def _check_username(name: str, url_template: str, username: str, timeout: float) -> tuple:
    full_url = url_template.format(username)
    resp = safe_get(full_url, timeout=timeout, allow_redirects=True)
    if resp is None or resp.status_code != 200:
        return name, None
    body = resp.content.lower()
    for pattern in NOT_FOUND_PATTERNS.get(name, []):
        if pattern in body:
            return name, None
    return name, full_url


def track_username(username: str, *, max_workers: int = 10, timeout: float = 8) -> dict:
    results: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_check_username, name, url, username, timeout): name
            for name, url in SOCIAL_PLATFORMS
        }
        for fut in as_completed(futures):
            name, found = fut.result()
            results[name] = found
    return {name: results[name] for name, _ in SOCIAL_PLATFORMS}


# ====================================================================
# 核心查询：WHOIS / MX / 邮箱
# ====================================================================
def whois_lookup(domain: str) -> dict:
    if not HAS_WHOIS:
        return {'_error': '需要安装 python-whois：pip install python-whois'}
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {'_error': f'WHOIS 查询失败：{e}'}
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
        return {'_error': '需要安装 dnspython：pip install dnspython'}
    try:
        answers = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        return {'_error': f'域名不存在：{domain}'}
    except dns.resolver.NoAnswer:
        return {'_error': f'{domain} 没有 MX 记录'}
    except Exception as e:
        return {'_error': f'DNS 查询失败：{e}'}
    records = sorted(
        [{'preference': r.preference, 'exchange': str(r.exchange).rstrip('.')} for r in answers],
        key=lambda r: r['preference'],
    )
    return {'domain': domain, 'records': records}


EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$')


def email_validate(email: str) -> dict:
    m = EMAIL_RE.match(email)
    if not m:
        return {'email': email, 'syntax_valid': False, '_error': '邮箱格式不合法'}
    domain = m.group(1)
    result: dict = {'email': email, 'syntax_valid': True, 'domain': domain}
    mx = mx_lookup(domain)
    if '_error' in mx:
        result['mx_valid'] = False
        result['mx_error'] = mx['_error']
    else:
        result['mx_valid'] = True
        result['mx_records'] = mx['records']
    return result


# ====================================================================
# 输出格式化
# ====================================================================
def print_banner() -> None:
    sys.stderr.write(f"""{Color.Gr}
       ________               __      ______                __
      / ____/ /_  ____  _____/ /_    /_  __/________ ______/ /__
     / / __/ __ \\/ __ \\/ ___/ __/_____/ / / ___/ __ `/ ___/ //_/
    / /_/ / / / / /_/ (__  ) /_/_____/ / / /  / /_/ / /__/ ,<
    \\____/_/ /_/\\____/____/\\__/     /_/ /_/   \\__,_/\\___/_/|_|

              {Color.Wh}[ + ]  C O D E   B Y  H U N X  [ + ]{Color.Reset}
""")


def print_ip_info(ip: str, data: dict) -> None:
    print(f"\n {Color.Wh}============= {Color.Gr}IP 地址信息 {Color.Wh}=============")
    print()
    if '_error' in data:
        print(f" {Color.Re}查询失败：{data['_error']}{Color.Reset}")
        return
    cn_name = country_zh(data.get('country_code'), '')
    country_display = f"{cn_name} ({data.get('country', '')})" if cn_name else data.get('country', '')
    print_field('目标 IP',  ip)
    print_field('IP 类型',  data.get('type'))
    print_field('国家',     country_display)
    print_field('国家代码', data.get('country_code'))
    print_field('城市',     data.get('city'))
    print_field('大洲',     data.get('continent'))
    print_field('地区',     data.get('region'))
    print_field('纬度',     data.get('latitude'))
    print_field('经度',     data.get('longitude'))
    try:
        lat = float(data['latitude'])
        lon = float(data['longitude'])
        print_field('谷歌地图', f"https://www.google.com/maps/@{lat},{lon},8z")
    except (KeyError, TypeError, ValueError):
        pass
    print_field('是否欧盟', data.get('is_eu'))
    print_field('邮编',     data.get('postal'))
    print_field('国际区号', data.get('calling_code'))
    print_field('首都',     data.get('capital'))
    flag = data.get('flag') or {}
    print_field('国旗',     flag.get('emoji', ''))
    conn = data.get('connection') or {}
    print_field('ASN',      conn.get('asn'))
    print_field('组织',     conn.get('org'))
    print_field('ISP',      conn.get('isp'))
    print_field('域名',     conn.get('domain'))
    tz = data.get('timezone') or {}
    print_field('时区 ID',  tz.get('id'))
    print_field('时区缩写', tz.get('abbr'))
    print_field('UTC 偏移', tz.get('utc'))


def print_my_ip(ip: Optional[str]) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}本机 IP 信息 {Color.Wh}==========")
    if ip is None:
        print(f"\n {Color.Re}查询失败，请检查网络{Color.Reset}")
    else:
        print(f"\n {Color.Wh}[{Color.Gr} + {Color.Wh}] 你的 IP 地址 : {Color.Gr}{ip}{Color.Reset}")
    print(f"\n {Color.Wh}=========================================={Color.Reset}")


def print_phone_info(data: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}电话号码信息 {Color.Wh}==========")
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    print_field('归属地',         data['location'],      width=18)
    print_field('地区代码',       data['region_code'],   width=18)
    print_field('时区',           data['timezones'],     width=18)
    print_field('运营商',         data['carrier'],       width=18)
    print_field('是否有效号码',   data['is_valid'],      width=18)
    print_field('是否可能号码',   data['is_possible'],   width=18)
    print_field('国际格式',       data['international'], width=18)
    print_field('移动拨号格式',   data['mobile_dial'],   width=18)
    print_field('原始号码',       data['national'],      width=18)
    print_field('E.164 格式',     data['e164'],          width=18)
    print_field('国家代码',       data['country_code'],  width=18)
    print_field('号码类型',       data['number_type'],   width=18)


def print_username_results(results: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}用户名扫描结果 {Color.Wh}==========")
    print()
    found = sum(1 for v in results.values() if v)
    print(f" {Color.Wh}共扫描 {len(results)} 个平台，命中 {Color.Gr}{found}{Color.Wh} 个：{Color.Reset}\n")
    for site, url in results.items():
        if url:
            print(f" {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {site:14}: {Color.Gr}{url}{Color.Reset}")
        else:
            print(f" {Color.Wh}[ {Color.Re}- {Color.Wh}] {site:14}: {Color.Ye}未找到{Color.Reset}")


def print_whois(data: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}WHOIS 查询 {Color.Wh}==========")
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    label_zh = {
        'domain': '域名', 'registrar': '注册商', 'creation_date': '创建日期',
        'expiration_date': '到期日期', 'updated_date': '更新日期',
        'name_servers': 'DNS 服务器', 'status': '状态', 'emails': '邮箱',
        'org': '注册组织', 'country': '国家',
    }
    for key, label in label_zh.items():
        value = data.get(key)
        if isinstance(value, (list, tuple, set)):
            value = ', '.join(str(v) for v in value)
        print_field(label, value if value is not None else '(无)', width=14)


def print_mx(data: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}MX 记录 {Color.Wh}==========")
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    print_field('域名', data['domain'], width=10)
    print()
    for r in data['records']:
        print(f"  {Color.Wh}优先级 {r['preference']:>4}  →  {Color.Gr}{r['exchange']}{Color.Reset}")


def print_email(result: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}邮箱有效性 {Color.Wh}==========")
    print()
    print_field('邮箱',     result['email'],            width=14)
    print_field('格式合法', result.get('syntax_valid'), width=14)
    if not result.get('syntax_valid'):
        print(f" {Color.Re}{result.get('_error', '')}{Color.Reset}")
        return
    print_field('域名',    result['domain'],            width=14)
    print_field('MX 有效', result.get('mx_valid'),      width=14)
    if result.get('mx_valid'):
        for r in result['mx_records']:
            print(f"   {Color.Wh}→ 优先级 {r['preference']:>4}  {Color.Gr}{r['exchange']}{Color.Reset}")
    else:
        print(f" {Color.Re}{result.get('mx_error', '')}{Color.Reset}")


# ====================================================================
# 交互式菜单
# ====================================================================
MENU_OPTIONS = [
    (1, 'IP 追踪'),
    (2, '查看本机 IP'),
    (3, '电话号码追踪'),
    (4, '用户名追踪'),
    (5, '域名 WHOIS 查询'),
    (6, '域名 MX 记录'),
    (7, '邮箱有效性检查'),
    (0, '退出'),
]


def show_menu() -> None:
    print_banner()
    print()
    for num, text in MENU_OPTIONS:
        print(f"{Color.Wh}[ {num} ] {Color.Gr}{text}{Color.Reset}")


def handle_choice(choice: int, save_dir: Optional[str] = None) -> None:
    if choice == 1:
        ip = input(f"{Color.Wh}\n 请输入目标 IP : {Color.Gr}").strip()
        data = track_ip(ip)
        print_ip_info(ip, data)
        _maybe_save(save_dir, f'ip_{ip}', data)
    elif choice == 2:
        my = show_my_ip()
        print_my_ip(my)
        _maybe_save(save_dir, 'my_ip', {'ip': my})
    elif choice == 3:
        num = input(f"\n {Color.Wh}请输入电话号码 {Color.Gr}例如 [+8613800138000]{Color.Wh} : {Color.Gr}").strip()
        data = track_phone(num)
        print_phone_info(data)
        _maybe_save(save_dir, f'phone_{num}', data)
    elif choice == 4:
        name = input(f"\n {Color.Wh}请输入用户名 : {Color.Gr}").strip()
        results = track_username(name)
        print_username_results(results)
        _maybe_save(save_dir, f'username_{name}', results)
    elif choice == 5:
        domain = input(f"\n {Color.Wh}请输入域名 : {Color.Gr}").strip()
        data = whois_lookup(domain)
        print_whois(data)
        _maybe_save(save_dir, f'whois_{domain}', data)
    elif choice == 6:
        domain = input(f"\n {Color.Wh}请输入域名 : {Color.Gr}").strip()
        data = mx_lookup(domain)
        print_mx(data)
        _maybe_save(save_dir, f'mx_{domain}', data)
    elif choice == 7:
        addr = input(f"\n {Color.Wh}请输入邮箱 : {Color.Gr}").strip()
        result = email_validate(addr)
        print_email(result)
        _maybe_save(save_dir, f'email_{addr}', result)
    elif choice == 0:
        print(f"\n {Color.Gr}再见！{Color.Reset}")
        sys.exit(0)
    else:
        raise ValueError(f"未知选项：{choice}")


def _maybe_save(directory: Optional[str], prefix: str, data: Any) -> None:
    if not directory:
        return
    os.makedirs(directory, exist_ok=True)
    safe_prefix = re.sub(r'[^\w.+-]', '_', prefix)
    ts = time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(directory, f'{safe_prefix}_{ts}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n {Color.Cy}[ 已保存到 {path} ]{Color.Reset}")


def menu_loop(save_dir: Optional[str] = None) -> None:
    while True:
        clear_screen()
        show_menu()
        try:
            raw = input(f"\n {Color.Wh}[ + ] {Color.Gr}请选择功能 : {Color.Wh}").strip()
            choice = int(raw)
        except ValueError:
            print(f"\n {Color.Re}请输入数字{Color.Reset}")
            time.sleep(1)
            continue
        try:
            handle_choice(choice, save_dir=save_dir)
        except ValueError as e:
            print(f"\n {Color.Re}{e}{Color.Reset}")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n {Color.Re}已中断{Color.Reset}")
            continue
        if choice != 0:
            input(f"\n{Color.Wh}[ {Color.Gr}+ {Color.Wh}] {Color.Gr}按回车键继续{Color.Reset}")


# ====================================================================
# CLI 参数模式
# ====================================================================
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    # default=SUPPRESS：未指定时不在 namespace 里产生属性，避免子命令覆盖父级值
    common.add_argument('--json', action='store_const', const=True,
                        default=argparse.SUPPRESS, help='输出原始 JSON 而非美化文本')
    common.add_argument('--save', metavar='DIR',
                        default=argparse.SUPPRESS, help='把结果以 JSON 保存到指定目录')
    common.add_argument('--no-color', action='store_const', const=True,
                        default=argparse.SUPPRESS, help='禁用 ANSI 颜色')

    parser = argparse.ArgumentParser(
        prog='GhostTR',
        parents=[common],
        description='GhostTrack —— OSINT 信息查询工具（中文版）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例：
  python3 GhostTR.py                         # 进入交互菜单
  python3 GhostTR.py ip 8.8.8.8              # 查询 IP
  python3 GhostTR.py myip                    # 查看本机 IP
  python3 GhostTR.py phone +8613800138000    # 查询电话号码
  python3 GhostTR.py user torvalds           # 扫描用户名
  python3 GhostTR.py whois example.com       # WHOIS 查询
  python3 GhostTR.py mx gmail.com            # 查询 MX 记录
  python3 GhostTR.py email a@b.com           # 邮箱验证
  python3 GhostTR.py ip 8.8.8.8 --json       # JSON 输出
  python3 GhostTR.py ip 8.8.8.8 --save out/  # 保存到文件
""",
    )

    sub = parser.add_subparsers(dest='command')

    sp = sub.add_parser('ip', parents=[common], help='查询 IP 地址信息')
    sp.add_argument('target', help='IPv4 或 IPv6 地址')

    sub.add_parser('myip', parents=[common], help='显示本机出口 IP')

    sp = sub.add_parser('phone', parents=[common], help='解析电话号码')
    sp.add_argument('number', help='电话号码（含国际区号最稳）')
    sp.add_argument('--region', default='CN', help='默认国家代码，默认 CN')

    sp = sub.add_parser('user', parents=[common], help='扫描用户名在社交平台的存在')
    sp.add_argument('username')
    sp.add_argument('--workers', type=int, default=10, help='并发线程数，默认 10')

    sp = sub.add_parser('whois', parents=[common], help='WHOIS 查询')
    sp.add_argument('domain')

    sp = sub.add_parser('mx', parents=[common], help='MX 记录查询')
    sp.add_argument('domain')

    sp = sub.add_parser('email', parents=[common], help='邮箱有效性验证')
    sp.add_argument('address')
    return parser


def run_cli(args: argparse.Namespace) -> int:
    cmd = args.command
    args.json = getattr(args, 'json', False)
    args.save = getattr(args, 'save', None)
    data: Any = None
    if cmd == 'ip':
        data = track_ip(args.target)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        else:
            print_ip_info(args.target, data)
    elif cmd == 'myip':
        ip = show_my_ip()
        data = {'ip': ip}
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_my_ip(ip)
    elif cmd == 'phone':
        data = track_phone(args.number, default_region=args.region)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        else:
            print_phone_info(data)
    elif cmd == 'user':
        data = track_username(args.username, max_workers=args.workers)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_username_results(data)
    elif cmd == 'whois':
        data = whois_lookup(args.domain)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        else:
            print_whois(data)
    elif cmd == 'mx':
        data = mx_lookup(args.domain)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_mx(data)
    elif cmd == 'email':
        data = email_validate(args.address)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_email(data)
    else:
        return 2
    if args.save:
        _maybe_save(args.save, cmd, data)
    return 1 if isinstance(data, dict) and '_error' in data else 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, 'no_color', False):
        Color.disable()
    if args.command:
        return run_cli(args)
    try:
        menu_loop(save_dir=getattr(args, 'save', None))
    except KeyboardInterrupt:
        print(f"\n{Color.Re}已退出{Color.Reset}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
