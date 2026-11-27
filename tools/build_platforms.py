#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
构建平台数据库 / Build platforms database.

合并 3 个 OSINT 上游数据源：
  - Maigret (~3000 entries)
  - Sherlock (~400 entries)
  - WhatsMyName (~700+ entries)

过滤、去重、按 TLD/关键词分类后保存为 spyeyes/data/platforms.json。

Usage:
    python3 tools/build_platforms.py
    python3 tools/build_platforms.py --cache-dir .cache  # 缓存上游 JSON
    python3 tools/build_platforms.py --no-fetch          # 离线（要求已缓存）
"""

import argparse
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from urllib.parse import urlparse

import requests

SOURCES = {
    "maigret":      "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
    "sherlock":     "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    "whatsmyname":  "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
}

# 名字相同时的优先级（评分相同时取此顺序）：
# Maigret > WhatsMyName > Sherlock —— Maigret 维护最积极、规则最完整
SOURCE_PRIORITY = {"maigret": 3, "whatsmyname": 2, "sherlock": 1}

# 每平台每类检测模式最多保留几条。
# 曾经是 3:论坛引擎的「用户不存在」提示是按语言列的(XenForo 5 条、vBulletin 6 条),
# 截到 3 条会把非英语论坛的提示截掉。
MAX_PATTERNS_PER_PLATFORM = 8

# Maigret 里 protocol 不是 http(s) 的站点:dns = 查「<用户名>.com」这类域名是否存在,
# tor / i2p = 暗网地址。SpyEyes 只发普通 HTTP 请求,这些条目永远请求不成功。
UNREACHABLE_PROTOCOLS = frozenset({"dns", "tor", "i2p"})

# 产物校验的下限:上游改了数据格式时,解析结果会骤减甚至为空 ——
# 宁可构建失败,也不要悄悄写出一份残缺的 platforms.json 把现有数据覆盖掉。
MIN_PLATFORMS_PER_SOURCE = {"maigret": 1500, "sherlock": 250, "whatsmyname": 400}
MIN_PLATFORMS_TOTAL = 2500

# fetch 重试参数
FETCH_RETRIES = 3
FETCH_BACKOFF_BASE = 2.0  # 秒，指数退避

OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "spyeyes",
    "data",
    "platforms.json",
)

# TLD → 地区类别映射（覆盖率最高的判定）
TLD_CATEGORY = {
    # 中文圈 (PRC + 台/港/星/马)
    "cn": "chinese", "com.cn": "chinese", "net.cn": "chinese", "org.cn": "chinese", "gov.cn": "chinese",
    "tw": "chinese", "com.tw": "chinese", "net.tw": "chinese", "org.tw": "chinese",
    "hk": "chinese", "com.hk": "chinese", "net.hk": "chinese", "org.hk": "chinese",
    "mo": "chinese", "com.mo": "chinese",
    "sg": "chinese", "com.sg": "chinese", "edu.sg": "chinese",
    "my": "chinese", "com.my": "chinese", "net.my": "chinese", "org.my": "chinese",
    # 西班牙语圈
    "es": "spanish", "com.es": "spanish",
    "ar": "spanish", "com.ar": "spanish", "net.ar": "spanish", "org.ar": "spanish",
    "mx": "spanish", "com.mx": "spanish", "org.mx": "spanish",
    "cl": "spanish", "com.cl": "spanish",
    "com.co": "spanish",  # 不含裸 .co:它基本被当通用域名用(huggingface.co / vsco.co),不代表西语站
    "pe": "spanish", "com.pe": "spanish",
    "ve": "spanish", "com.ve": "spanish",
    "uy": "spanish", "com.uy": "spanish",
    "ec": "spanish", "com.ec": "spanish",
    "py": "spanish", "com.py": "spanish",
    "bo": "spanish", "com.bo": "spanish",
    "do": "spanish", "com.do": "spanish",
    "gt": "spanish", "com.gt": "spanish",
    "hn": "spanish", "com.hn": "spanish",
    "ni": "spanish", "com.ni": "spanish",
    "pa": "spanish", "com.pa": "spanish",
    "sv": "spanish", "com.sv": "spanish",
    "cu": "spanish", "com.cu": "spanish",
    "cr": "spanish", "com.cr": "spanish",
    "br": "spanish", "com.br": "spanish",  # 葡萄牙语，归到 spanish/latam
}

# 中文圈关键词（优先于主题分类）
CHINESE_KEYWORDS = [
    "weibo", "zhihu", "douban", "tieba", "csdn", "v2ex", "jianshu",
    "segmentfault", "oschina", "juejin", "nowcoder", "acwing", "51cto",
    "lofter", "lihkg", "mobile01", "dcard", "ptt.cc", "bahamut",
    "pixnet", "mafengwo", "qyer", "dianping", "guokr", "360doc",
    "qidian", "jjwxc", "aliyun", "huaweicloud", "bilibili",
    "douyin", "iqiyi", "youku", "baidu", "sina.com", "sohu",
    "hk01", "shopee", "carousell", "xueqiu", "okjike", "36kr",
    "hupu", "cnblogs", "ithome", "miui", "weixin", "qq.com",
    "163.com", "126.com", "yeah.net", "tencent",
]

# 西语圈关键词（优先于主题分类）
SPANISH_KEYWORDS = [
    "wallapop", "mercadolibre", "mercadolivre", "meneame", "taringa",
    "forocoches", "hispachan", "forosperu", "genbeta", "xataka",
    "duolingo", "globo.com", "uol.com", "g1.globo",
]

# 成人 / 约会 / 性内容平台关键词（优先于其它分类）
ADULT_KEYWORDS = [
    # 通用
    "porn", "xxx", "nsfw", "adult", "erotic", "fetish", "kink",
    # 视频站
    "xvideos", "xnxx", "redtube", "youporn", "tube8", "spankbang",
    "pornhub", "xhamster", "beeg", "txxx", "drtuber", "eporner",
    "xtube", "thumbzilla", "porntrex", "pornone", "anyporn",
    # 创作者
    "onlyfans", "fansly", "manyvids", "justforfans", "admireme",
    "loyalfans", "fancentro", "avnstars", "ismygirl", "pocketstars",
    "adultnode", "fanvue", "modelhub", "scrileconnect",
    # cam
    "chaturbate", "stripchat", "myfreecams", "bongacams", "livejasmin",
    "cam4", "camsoda", "flirt4free", "skyprivate", "streamate",
    "imlive", "ifriends", "xlovecam", "cherry.tv", "cammodels",
    # 社区/论坛
    "fetlife", "kinkly", "alt.com", "fetster", "lpsg",
    "literotica", "asstr", "f95zone", "rule34", "e621", "e926",
    "rule34.xxx", "gelbooru", "danbooru",
    # 约会
    "ashleymadison", "adultfriendfinder", "ohlala", "iamnaughty",
    "hookup", "fling", "naughty",
    "tinder", "bumble", "hinge", "okcupid", "match.com", "pof.com",
    "plentyoffish", "tagged.com", "badoo", "meetme", "skout",
    "mocospace", "kasidie", "swinglifestyle",
    # 同志
    "grindr", "scruff", "adam4adam", "daddyhunt", "recon",
    "squirt.org", "barebackrt", "manhunt", "grommr",
    "her.app", "feeld", "happn", "coffeemeetsbagel",
    # 异国成人
    "fanbox", "dlsite", "fantia",
    # 同性恋约会
    "gaydar", "gay.com", "lpsg.com",
    # 妓女/陪伴
    "eros.com", "tryst", "switter", "switter.at",
    # 中文/日韩
    "91porn", "1024",
]

# 主题分类（仅在区域判定后兜底使用）
CATEGORY_RULES = [
    ("code", [
        "github", "gitlab", "bitbucket", "codeberg", "sr.ht", "sourcehut",
        "leetcode", "codeforces", "hackerrank", "atcoder", "codepen", "replit",
        "glitch", "codesandbox", "codewars", "npm", "pypi", "rubygems",
        "crates.io", "docker", "hashnode", "dev.to", "hackernews",
        "lobste.rs", "stackover", "kaggle", "huggingface", "topcoder",
        "exercism", "kattis", "stackblitz", "jsfiddle",
        "hackerearth", "spoj", "codechef", "geeksforgeeks", "rosalind",
        "gist", "gitee", "packagist",
    ]),
    ("social", [
        "facebook", "twitter", "instagram", "linkedin", "mastodon",
        "bluesky", "bsky", "threads", "snapchat", "telegram", "vk.com",
        "ok.ru", "mixi", "plurk", "ello", "keybase", "gravatar",
        "diaspora", "minds", "spoutible", "post.news", "gettr", "parler",
        "truth", "gab.com", "mewe", "myspace",
    ]),
    ("forum", [
        "reddit", "quora", "disqus", "habr", "lobsters", "4chan",
        "forum", "discuss", "community",
    ]),
    ("video", [
        "youtube", "tiktok", "twitch", "vimeo", "dailymotion", "rumble",
        "odysee", "bitchute", "niconico", "peertube", "metacafe",
    ]),
    ("music", [
        "soundcloud", "spotify", "lastfm", "last.fm", "bandcamp",
        "mixcloud", "reverbnation", "audiomack", "bandlab", "anchor",
        "audius", "tidal", "deezer",
    ]),
    ("writing", [
        "medium", "substack", "wattpad", "ao3", "archiveofourown",
        "fanfiction", "fictionpress", "ghost.org", "blog", "wordpress",
        "blogger", "tumblr", "ghost.io",
    ]),
    ("art", [
        "deviantart", "artstation", "behance", "dribbble", "500px",
        "unsplash", "flickr", "newgrounds", "etsy", "redbubble",
        "society6", "pixiv", "fotolog", "imgur",
    ]),
    ("gaming", [
        "steam", "itch.io", "roblox", "speedrun", "chess.com", "lichess",
        "myanimelist", "anilist", "boardgamegeek", "playstation", "xbox",
        "nintendo", "epic", "riot", "blizzard", "origin", "uplay",
        "minecraft", "wikia", "fandom",
    ]),
    ("funding", [
        "patreon", "buymeacoffee", "ko-fi", "kofi", "opencollective",
        "liberapay", "wellfound", "indiehackers", "producthunt",
        "kickstarter", "indiegogo", "gofundme",
    ]),
]


def get_tld(url: str) -> str:
    """从 URL 提取 TLD。支持 com.cn / com.tw 等二级域名。"""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return ""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    # 尝试匹配二级 TLD（com.cn, com.tw 等）
    if len(parts) >= 3:
        two_level = ".".join(parts[-2:])
        if two_level in TLD_CATEGORY:
            return two_level
    return parts[-1]


def categorize(name: str, url: str) -> str:
    """分类优先级：
       1. 成人/约会站点（避免被 'social' 等误归）
       2. 中文/西语关键词（CSDN/V2EX/Wallapop 等知名站点）
       3. TLD 地区（.cn/.tw/.es/.mx 等）
       4. 主题关键词（github→code, twitter→social...）
       5. 'other' 兜底
    """
    haystack = (name + " " + url).lower()
    if any(kw in haystack for kw in ADULT_KEYWORDS):
        return "adult"
    if any(kw in haystack for kw in CHINESE_KEYWORDS):
        return "chinese"
    if any(kw in haystack for kw in SPANISH_KEYWORDS):
        return "spanish"
    tld = get_tld(url)
    if tld in TLD_CATEGORY:
        return TLD_CATEGORY[tld]
    for cat, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in haystack:
                return cat
    return "other"


def normalize_url(url: str) -> str:
    return url.replace("{username}", "{}").replace("{account}", "{}")


def is_probeable_url(url: str) -> bool:
    """这个地址模板能不能直接发 HTTP 请求:http(s) 开头、含 {} 占位符、没有其它未展开的占位符。
    (曾经写出过 `{}.com` 和 `{urlMain}forum/profile.php?...` 这样的条目,运行时永远请求失败。)"""
    if not re.match(r"^https?://", url) or "{}" not in url:
        return False
    return re.search(r"\{[^}]+\}", url) is None


def expand_site_placeholders(url: str, info: dict) -> str:
    """展开 Maigret 地址模板里的 {urlMain} / {urlSubpath}(引擎模板和少数普通站点都会用)。"""
    if "{urlMain}" not in url and "{urlSubpath}" not in url:
        return url
    url_main = info.get("urlMain", "") or ""
    if "{urlMain}/" in url or "{urlMain}{urlSubpath}" in url:
        url_main = url_main.rstrip("/")
    elif url_main and not url_main.endswith("/"):
        url_main += "/"
    return url.replace("{urlMain}", url_main).replace("{urlSubpath}", info.get("urlSubpath", "") or "")


def _str_list(value) -> list:
    return [s for s in (value or []) if isinstance(s, str) and s]


def _merge_patterns(*lists) -> list:
    """按顺序合并、去重、截到上限。"""
    return list(dict.fromkeys(s for lst in lists for s in lst))[:MAX_PATTERNS_PER_PLATFORM]


def fetch(url: str, retries: int = FETCH_RETRIES) -> dict:
    """带重试 + 指数退避的 GET。任意上游 5xx/超时不再让整个构建挂掉。"""
    print(f"  fetching {url} ...")
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            last_err = e
            if attempt < retries:
                backoff = FETCH_BACKOFF_BASE ** (attempt - 1)
                print(f"    attempt {attempt}/{retries} failed: {e} — retry in {backoff:.0f}s")
                time.sleep(backoff)
    raise RuntimeError(f"fetch failed after {retries} attempts: {url}") from last_err


# Maigret tag → SpyEyes category 映射
# tags 来自 Maigret data.json 的 'tags' 字段（最权威的 OSINT 分类源）
MAIGRET_TAG_MAP = {
    # 中文圈
    "cn": "chinese", "tw": "chinese", "hk": "chinese", "sg": "chinese",
    # 西语圈
    "es": "spanish", "ar": "spanish", "mx": "spanish", "br": "spanish",
    # 主题
    "coding": "code", "tech": "code",
    "social": "social", "messaging": "social",
    "forum": "forum", "discussion": "forum",
    "video": "video", "streaming": "video",
    "music": "music", "audio": "music",
    "blog": "writing", "writing": "writing", "literature": "writing",
    "photo": "art", "art": "art", "design": "art",
    "gaming": "gaming", "games": "gaming",
    "crowdfunding": "funding", "donation": "funding",
    "dating": "adult", "porn": "adult", "nsfw": "adult", "adult": "adult",
    "lgbt": "adult",
}


def parse_maigret(raw: dict) -> list:
    """Maigret 格式：{sites: {name: {url, urlMain, urlSubpath, engine, absenceStrs, presenseStrs, ...}},
                     engines: {name: {site: {url, ...}, presenseStrs}}}

    关键升级 (v1.1.0): 解析 engine 模板。Maigret 用 Discourse/XenForo/phpBB 等 engine 把
    1097 个论坛站点折叠成共享配置 —— 站点本身的 url 字段为空但 engine 给出 {urlMain}{urlSubpath}/...
    模板。展开后 Maigret 站点数从 1422 → ~2500+。

    引擎的检测规则在 `engine.site` 里(absenceStrs / presenseStrs),与站点自己的规则合并使用。
    `engine.presenseStrs`(顶层)是另一回事:它是「识别某个网站是不是这种论坛软件」的指纹
    (如 `XenForo`、`content="Discourse"`),该论坛的每个页面都有,**不能**当成 must_contain。
    v1.1.0 ~ v1.8.7 正是把指纹当成了 must_contain、又漏掉了 engine.site 的规则:
    1110 个论坛条目要么只看状态码,要么带着一条永远成立的「必须包含」。
    """
    sites = raw.get("sites")
    engines = raw.get("engines", {})
    # 旧格式回退：raw 没有 'sites' 顶层键 → raw 本身就是 sites dict
    if not isinstance(sites, dict) or not sites:
        sites = raw if isinstance(raw, dict) else {}
    out = []
    for name, info in sites.items():
        if not isinstance(info, dict):
            continue
        # 不再过滤 NSFW —— 这些会被 categorize() 归到 'adult' 类别
        if info.get("disabled"):
            continue
        if info.get("protocol") in UNREACHABLE_PROTOCOLS:
            continue
        url = info.get("url", "") or ""
        engine_name = info.get("engine")
        engine = engines.get(engine_name) if engine_name and isinstance(engines, dict) else None
        eng_site = engine.get("site") if isinstance(engine, dict) and isinstance(engine.get("site"), dict) else {}
        # 站点自身没 url 模板 → 用 engine 的
        if "{username}" not in url and "{}" not in url and "{username}" in (eng_site.get("url") or ""):
            url = eng_site["url"]
        if "{username}" not in url and "{}" not in url:
            continue
        url = normalize_url(expand_site_placeholders(url, info))
        if not is_probeable_url(url):
            continue
        regex = info.get("regexCheck") or ""
        # 检测规则 = 站点自己的 + 引擎模板的(engine.site.*)。不要用 engine 顶层的 presenseStrs(那是指纹)
        merged_must = _merge_patterns(_str_list(info.get("presenseStrs")), _str_list(eng_site.get("presenseStrs")))
        merged_absent = _merge_patterns(_str_list(info.get("absenceStrs")), _str_list(eng_site.get("absenceStrs")))
        # 收集 Maigret 自带 tags（用于更精确分类）
        tags = info.get("tags") or []
        tags = [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
        out.append({
            "name": name,
            "url": url,
            "not_found": merged_absent,
            "must_contain": merged_must,
            "regex_check": regex if isinstance(regex, str) else "",
            "_tags": tags,  # 临时字段，categorize 用完后剥离
        })
    return out


def categorize_with_tags(name: str, url: str, tags: list) -> str:
    """优先用 Maigret tags 分类，回退到关键词/TLD 启发式。"""
    # tags 优先（Maigret 维护者人工标注，最权威）
    for tag in tags or []:
        cat = MAIGRET_TAG_MAP.get(tag.lower() if isinstance(tag, str) else "")
        if cat:
            return cat
    return categorize(name, url)


def parse_sherlock(raw: dict) -> list:
    """Sherlock 格式：{name: {url, urlMain, errorMsg, errorType, regexCheck, ...}}"""
    out = []
    for name, info in raw.items():
        if not isinstance(info, dict):
            continue
        url = info.get("url", "")
        if "{}" not in url and "{username}" not in url:
            continue
        not_found = []
        em = info.get("errorMsg")
        if isinstance(em, str):
            not_found = [em]
        elif isinstance(em, list):
            not_found = [s for s in em if isinstance(s, str)][:MAX_PATTERNS_PER_PLATFORM]
        regex = info.get("regexCheck") or ""
        out.append({
            "name": name,
            "url": normalize_url(url),
            "not_found": not_found,
            "must_contain": [],
            "regex_check": regex if isinstance(regex, str) else "",
        })
    return out


def parse_wmn(raw: dict) -> list:
    """WhatsMyName 格式：{sites: [{name, uri_check, e_code, e_string, m_code, m_string, ...}]}

    字段含义（上游 schema，别按首字母猜）：
      e_string / e_code = 账号**存在**（exists）时响应里出现的字符串 / 状态码
      m_string / m_code = 账号**不存在**（missing）时响应里出现的字符串 / 状态码
    所以 e_string → must_contain，m_string → not_found。
    v1.1.0 ~ v1.8.6 把两者接反了（把 m 读成 "must contain"）：587 个平台对真实账号
    恒报「未找到」，对「不存在也返回 200」的站点反而报「找到」。"""
    out = []
    for site in raw.get("sites", []):
        if site.get("known_accounts") and not site.get("uri_check"):
            continue
        url = site.get("uri_check", "")
        if "{account}" in url:
            url = url.replace("{account}", "{}")
        elif "{username}" in url:
            url = normalize_url(url)
        if "{}" not in url:
            continue
        # e_string = exists（存在标志）→ must_contain；m_string = missing（不存在标志）→ not_found
        must_contain = []
        if site.get("e_string") and isinstance(site["e_string"], str):
            must_contain = [site["e_string"]]
        not_found = []
        if site.get("m_string") and isinstance(site["m_string"], str):
            not_found = [site["m_string"]]
        out.append({
            "name": site.get("name", "Unknown"),
            "url": url,
            "not_found": not_found,
            "must_contain": must_contain,
        })
    return out


def merge_dedup(*sources_lists) -> list:
    """名字去重：(检测模式数量, 上游优先级) 高者胜出。
    上游优先级: maigret > whatsmyname > sherlock（见 SOURCE_PRIORITY）"""
    by_name: dict = {}
    for src_name, lst in sources_lists:
        new_pri = SOURCE_PRIORITY.get(src_name, 0)
        for item in lst:
            key = item["name"].lower().strip()
            if not key:
                continue
            existing = by_name.get(key)
            if existing is None:
                item["_source"] = src_name
                by_name[key] = item
                continue
            cur_score = len(existing.get("not_found", [])) + len(existing.get("must_contain", []))
            cur_pri = SOURCE_PRIORITY.get(existing.get("_source"), 0)
            new_score = len(item.get("not_found", [])) + len(item.get("must_contain", []))
            if (new_score, new_pri) > (cur_score, cur_pri):
                item["_source"] = src_name
                by_name[key] = item
    return list(by_name.values())


def atomic_write_json(path: str, data) -> None:
    """原子写入 JSON：先写临时文件，再 os.replace（POSIX 原子）。
    避免写入中途断电/Ctrl+C 留下损坏的 platforms.json。"""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".platforms.", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _cache_path(cache_dir: str, source_name: str) -> str:
    return os.path.join(cache_dir, f"{source_name}.json")


def fetch_all(cache_dir: str | None = None, no_fetch: bool = False) -> dict:
    """拉取或从缓存加载所有上游。可独立测试。"""
    raw = {}
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    for name, url in SOURCES.items():
        cache_file = _cache_path(cache_dir, name) if cache_dir else None
        if no_fetch:
            if not cache_file or not os.path.exists(cache_file):
                raise RuntimeError(f"--no-fetch but no cache for {name}: {cache_file}")
            with open(cache_file, encoding="utf-8") as f:
                raw[name] = json.load(f)
        else:
            data = fetch(url)
            raw[name] = data
            if cache_file:
                atomic_write_json(cache_file, data)
    return raw


def build(cache_dir: str | None = None, no_fetch: bool = False) -> int:
    print("\n=== Fetching upstream sources ===")
    raw = fetch_all(cache_dir=cache_dir, no_fetch=no_fetch)

    print("\n=== Parsing ===")
    maigret = parse_maigret(raw["maigret"])
    print(f"  maigret:      {len(maigret)}")
    sherlock = parse_sherlock(raw["sherlock"])
    print(f"  sherlock:     {len(sherlock)}")
    wmn = parse_wmn(raw["whatsmyname"])
    print(f"  whatsmyname:  {len(wmn)}")

    for src_name, parsed in (("maigret", maigret), ("sherlock", sherlock), ("whatsmyname", wmn)):
        if len(parsed) < MIN_PLATFORMS_PER_SOURCE[src_name]:
            raise RuntimeError(
                f"{src_name} 只解析出 {len(parsed)} 个平台(下限 {MIN_PLATFORMS_PER_SOURCE[src_name]})"
                " —— 上游数据格式可能变了,已中止,platforms.json 未改动")

    print("\n=== Merging + dedup ===")
    merged = merge_dedup(
        ("maigret",     maigret),
        ("sherlock",    sherlock),
        ("whatsmyname", wmn),
    )
    print(f"  total unique: {len(merged)}")
    unprobeable = [item["name"] for item in merged if not is_probeable_url(item["url"])]
    if unprobeable:
        print(f"  dropped {len(unprobeable)} entries with unusable URL templates: {unprobeable[:10]}")
        merged = [item for item in merged if is_probeable_url(item["url"])]
    if len(merged) < MIN_PLATFORMS_TOTAL:
        raise RuntimeError(
            f"合并后只有 {len(merged)} 个平台(下限 {MIN_PLATFORMS_TOTAL}) —— 已中止,platforms.json 未改动")

    print("\n=== Categorizing ===")
    for item in merged:
        # _tags 来自 Maigret 上游（如 ['cn', 'social']）；其它源没有此字段
        item["category"] = categorize_with_tags(item["name"], item["url"], item.get("_tags") or [])
        item.pop("_source", None)
        item.pop("_tags", None)
        item.setdefault("regex_check", "")

    by_cat = Counter(p["category"] for p in merged)
    print("  by category:")
    for cat, n in by_cat.most_common():
        print(f"    {cat:10} {n}")

    atomic_write_json(OUT_PATH, merged)
    print(f"\nWrote {len(merged)} platforms to {OUT_PATH} ({os.path.getsize(OUT_PATH)/1024:.1f} KB)")
    return len(merged)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build SpyEyes platforms.json from upstream OSINT sources")
    p.add_argument("--cache-dir", help="Cache upstream JSON to this directory (for re-runs)")
    p.add_argument("--no-fetch", action="store_true", help="Skip network; require cached files (--cache-dir required)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.no_fetch and not args.cache_dir:
        print("ERROR: --no-fetch requires --cache-dir", file=sys.stderr)
        return 2
    try:
        build(cache_dir=args.cache_dir, no_fetch=args.no_fetch)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
