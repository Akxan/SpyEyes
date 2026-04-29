#!/usr/bin/env python3
# << CODE BY HUNX04 (中文/英文双语版 · Bilingual Edition)
# << 原作者 https://github.com/HunxByts/GhostTrack

"""
GhostTrack-CN —— OSINT 信息查询工具（中英双语）
GhostTrack-CN —— OSINT Toolkit (Bilingual: Chinese / English)
"""

import argparse
import json
import os
import re
import sys
import time
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


# ====================================================================
# CONFIG —— 用户偏好持久化（语言等）
# ====================================================================
CONFIG_DIR = os.path.expanduser('~/.ghosttrack')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')


def load_config() -> dict:
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
        'msg.progress':         'Scanning',
        'msg.found':            'found',
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
        'msg.progress':         '扫描中',
        'msg.found':            '已命中',
    },
}

_lang = 'zh'  # 当前语言，由 set_lang() 修改


def detect_lang() -> str:
    """根据系统环境自动判定默认语言。"""
    val = (os.environ.get('GHOSTTRACK_LANG')
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
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


def safe_get(url: str, *, timeout: float = DEFAULT_TIMEOUT, **kwargs) -> Optional[requests.Response]:
    headers = {**DEFAULT_HEADERS, **kwargs.pop('headers', {})}
    try:
        return requests.get(url, timeout=timeout, headers=headers, **kwargs)
    except requests.exceptions.RequestException:
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

    lib_lang = 'zh' if _lang == 'zh' else 'en'
    return {
        'location':      geocoder.description_for_number(parsed, lib_lang) or t('msg.unknown'),
        'region_code':   phonenumbers.region_code_for_number(parsed) or t('msg.unknown'),
        'timezones':     ', '.join(timezone.time_zones_for_number(parsed)) or t('msg.unknown'),
        'carrier':       carrier.name_for_number(parsed, lib_lang) or t('msg.unknown'),
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
]

# 类别在输出中的显示顺序
CATEGORY_ORDER = ['code', 'social', 'forum', 'video', 'music', 'writing', 'art', 'gaming', 'funding', 'chinese', 'spanish', 'other']

# 加载从 Maigret 拉取的扩展平台库
_PLATFORMS_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'platforms.json')


def _load_platforms_json(path: str) -> list:
    """从 JSON 文件加载平台定义，转换为 Platform NamedTuple。"""
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
                not_found=tuple(s.lower().encode() for s in item.get('not_found', [])),
                must_contain=tuple(s.lower().encode() for s in item.get('must_contain', [])),
            ))
        except (KeyError, TypeError):
            continue
    return out


def _merge_platforms(curated: list, extended: list) -> list:
    """以 curated 为优先（保留我们的中文/分类），追加 extended 中名字不重复的项。"""
    seen = {p.name.lower() for p in curated}
    merged = list(curated)
    for p in extended:
        key = p.name.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(p)
    return merged


# 合并：手工 curated（含中文/西语精选）+ data/platforms.json（Maigret + Sherlock + WhatsMyName）
# 当前实测合并后总数 ~2020 个平台
PLATFORMS = _merge_platforms(PLATFORMS, _load_platforms_json(_PLATFORMS_JSON))


def _check_username(platform: 'Platform', username: str, timeout: float):
    """检查单个平台是否存在该用户名。返回 (Platform, URL or None)。
    任何 URL 模板异常（IndexError/KeyError/ValueError）都视为该平台不可用。"""
    try:
        full_url = platform.url.format(username)
    except (IndexError, KeyError, ValueError):
        # ValueError 覆盖 str.format 的格式串错误（如 '{:d}'、'{0!q}' 等）
        return platform, None
    resp = safe_get(full_url, timeout=timeout, allow_redirects=True)
    if resp is None or resp.status_code != 200:
        return platform, None
    body = resp.content.lower()
    # 检查「未找到」模式
    for pattern in platform.not_found:
        if pattern in body:
            return platform, None
    # 如果定义了「必须包含」模式，至少命中一个才算找到
    if platform.must_contain:
        if not any(pat in body for pat in platform.must_contain):
            return platform, None
    return platform, full_url


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


def track_username(username: str, *, max_workers: int = 50, timeout: float = 5,
                   show_progress: bool = True, categories: Optional[list] = None) -> dict:
    """并发扫描平台，返回 {platform_name: url_or_None}（按 PLATFORMS 顺序）。
    - 空 username 会被拒绝以避免命中各平台主页造成误报。
    - 单 worker 抛任何异常不影响其它平台 —— 该平台标记 None 跳过。
    - show_progress=True 且 stderr 是 TTY 时显示进度条。
    - categories=['code', 'chinese', ...] 只扫指定类别。None 时扫全部。"""
    username = (username or '').strip()
    if not username:
        return {p.name: None for p in PLATFORMS}
    if max_workers < 1:
        max_workers = 1
    # 按 category 过滤
    if categories:
        platforms_to_scan = [p for p in PLATFORMS if p.category in categories]
    else:
        platforms_to_scan = PLATFORMS
    found: dict = {}
    total = len(platforms_to_scan)
    found_count = 0
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check_username, p, username, timeout): p for p in platforms_to_scan}
        for fut in as_completed(futures):
            try:
                platform, url = fut.result()
            except Exception:
                platform = futures[fut]
                url = None
            found[platform.name] = url
            done += 1
            if url:
                found_count += 1
            if show_progress:
                _print_scan_progress(done, total, found_count)
    if show_progress:
        _clear_progress_line()
    # 保持 PLATFORMS 内部顺序；未扫描的平台不出现在结果里
    return {p.name: found[p.name] for p in platforms_to_scan if p.name in found}


# ====================================================================
# 核心查询：WHOIS / MX / 邮箱
# ====================================================================
def whois_lookup(domain: str) -> dict:
    if not HAS_WHOIS:
        return {'_error': t('err.no_whois')}
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {'_error': t('err.whois_failed', e=e)}
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


def email_validate(email: str) -> dict:
    m = EMAIL_RE.match(email)
    if not m:
        return {'email': email, 'syntax_valid': False, '_error': t('err.email_format')}
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
    print(f"\n {Color.Wh}============= {Color.Gr}{t('section.ip')} {Color.Wh}=============")
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
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.my_ip')} {Color.Wh}==========")
    if ip is None:
        print(f"\n {Color.Re}{t('msg.network_failed')}{Color.Reset}")
    else:
        print(f"\n {Color.Wh}[{Color.Gr} + {Color.Wh}] {t('msg.your_ip')} : {Color.Gr}{ip}{Color.Reset}")
    print(f"\n {Color.Wh}=========================================={Color.Reset}")


def print_phone_info(data: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.phone')} {Color.Wh}==========")
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


def print_username_results(results: dict, show_all: bool = False) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.username')} {Color.Wh}==========")
    print()
    found = sum(1 for v in results.values() if v)
    print(f" {Color.Wh}{t('msg.scan_summary', total=len(results), found=found)}{Color.Reset}")
    if not show_all:
        print(f" {Color.Bl}{Color.Ye}{t('msg.show_all_hint')}{Color.Reset}")
    print()
    # 按类别分组打印；只统计实际被扫描的平台（results 中存在的）
    for cat in CATEGORY_ORDER:
        cat_platforms = [p for p in PLATFORMS if p.category == cat and p.name in results]
        if not cat_platforms:
            continue
        cat_found_list = [p for p in cat_platforms if results.get(p.name)]
        cat_found = len(cat_found_list)
        # 默认只显示有命中的类别；--all 时显示所有
        if not show_all and cat_found == 0:
            continue
        cat_label = t(f'cat.{cat}')
        print(f" {Color.Cy}┌─ {cat_label} ({cat_found}/{len(cat_platforms)}) ─{Color.Reset}")
        platforms_to_show = cat_platforms if show_all else cat_found_list
        for p in platforms_to_show:
            url = results.get(p.name)
            if url:
                print(f" {Color.Wh}[ {Color.Gr}+ {Color.Wh}] {p.name:30} {Color.Gr}{url}{Color.Reset}")
            else:
                print(f" {Color.Wh}[ {Color.Re}- {Color.Wh}] {p.name:30} {Color.Ye}{t('msg.not_found')}{Color.Reset}")
        print()


def print_whois(data: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.whois')} {Color.Wh}==========")
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
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.mx')} {Color.Wh}==========")
    print()
    if '_error' in data:
        print(f" {Color.Re}{data['_error']}{Color.Reset}")
        return
    print_field(t('field.mx_domain'), data['domain'], width=12)
    print()
    for r in data['records']:
        print(f"  {Color.Wh}{t('field.priority')} {r['preference']:>4}  →  {Color.Gr}{r['exchange']}{Color.Reset}")


def print_email(result: dict) -> None:
    print(f"\n {Color.Wh}========== {Color.Gr}{t('section.email')} {Color.Wh}==========")
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
        results = track_username(name)
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


def _maybe_save(directory: Optional[str], prefix: str, data: Any) -> None:
    if not directory:
        return
    os.makedirs(directory, exist_ok=True)
    safe_prefix = re.sub(r'[^\w.+-]', '_', prefix)
    ts = time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(directory, f'{safe_prefix}_{ts}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n {Color.Cy}{t('msg.saved_to', path=path)}{Color.Reset}")


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

    parser = argparse.ArgumentParser(
        prog='GhostTR',
        parents=[common],
        description='GhostTrack-CN —— OSINT toolkit (bilingual: zh/en)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples / 示例:
  python3 GhostTR.py                          # Interactive menu / 交互菜单
  python3 GhostTR.py --lang en                # Force English UI / 强制英文界面
  python3 GhostTR.py ip 8.8.8.8               # IP lookup
  python3 GhostTR.py myip --lang en           # English JSON
  python3 GhostTR.py phone +12025550100       # Phone parse
  python3 GhostTR.py user torvalds            # Username scan
  python3 GhostTR.py whois example.com        # WHOIS
  python3 GhostTR.py mx gmail.com             # MX records
  python3 GhostTR.py email a@b.com            # Email validate
  python3 GhostTR.py ip 8.8.8.8 --json        # JSON output
  python3 GhostTR.py ip 8.8.8.8 --save out/   # Save to file
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
    sp.add_argument('--workers', type=_positive_int, default=50,
                    help='Concurrent threads / 并发线程数 (default: 50, max 200)')
    sp.add_argument('--timeout', type=float, default=5.0,
                    help='HTTP timeout per platform in seconds / 单平台超时秒数 (default: 5)')
    sp.add_argument('--all', action='store_true', dest='show_all',
                    help='Show all platforms incl. misses / 显示所有平台（含未命中）')
    sp.add_argument('--quick', action='store_true',
                    help='Skip "other" long-tail (645 platforms vs 2020, ~3-4x faster) / 跳过 other 长尾，仅扫主流 645 个')
    sp.add_argument('--category', dest='category_filter',
                    help='Comma-separated categories: code,social,chinese,spanish,... / 用逗号分隔的类别')

    sp = sub.add_parser('whois', parents=[common], help='WHOIS lookup')
    sp.add_argument('domain')

    sp = sub.add_parser('mx', parents=[common], help='MX records')
    sp.add_argument('domain')

    sp = sub.add_parser('email', parents=[common], help='Email validation / 邮箱验证')
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
        # 解析 category 过滤：--quick 等同于「除 other 外全部」
        cats = None
        if getattr(args, 'category_filter', None):
            cats = [c.strip() for c in args.category_filter.split(',') if c.strip()]
        elif getattr(args, 'quick', False):
            cats = [c for c in CATEGORY_ORDER if c != 'other']
        data = track_username(args.username, max_workers=args.workers,
                              timeout=args.timeout, categories=cats)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print_username_results(data, show_all=getattr(args, 'show_all', False))
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
