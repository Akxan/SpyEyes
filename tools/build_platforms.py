#!/usr/bin/env python3
"""
构建平台数据库 / Build platforms database.

合并 3 个 OSINT 上游数据源：
  - Maigret (~3000 entries)
  - Sherlock (~400 entries)
  - WhatsMyName (~700+ entries)

过滤、去重、按 TLD/关键词分类后保存为 data/platforms.json。

Usage:
    python3 tools/build_platforms.py
"""

import json
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse

import requests

SOURCES = {
    "maigret":      "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
    "sherlock":     "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    "whatsmyname":  "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
}

OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
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
    "co": "spanish", "com.co": "spanish",
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
       1. 中文/西语关键词（CSDN/V2EX/Wallapop 等知名站点）
       2. TLD 地区（.cn/.tw/.es/.mx 等）
       3. 主题关键词（github→code, twitter→social...）
       4. 'other' 兜底
    """
    haystack = (name + " " + url).lower()
    # 1. 区域关键词优先
    if any(kw in haystack for kw in CHINESE_KEYWORDS):
        return "chinese"
    if any(kw in haystack for kw in SPANISH_KEYWORDS):
        return "spanish"
    # 2. TLD 地区判定
    tld = get_tld(url)
    if tld in TLD_CATEGORY:
        return TLD_CATEGORY[tld]
    # 3. 主题分类兜底
    for cat, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in haystack:
                return cat
    return "other"


def normalize_url(url: str) -> str:
    return url.replace("{username}", "{}").replace("{account}", "{}")


def fetch(url: str) -> dict:
    print(f"  fetching {url} ...")
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.json()


def parse_maigret(raw: dict) -> list:
    """Maigret 格式：{name: {url, urlMain, absenceStrs, presenseStrs, disabled, isNSFW, ...}}"""
    sites = raw.get("sites", raw)
    out = []
    for name, info in sites.items():
        if info.get("disabled") or info.get("isNSFW"):
            continue
        url = info.get("url", "")
        if "{username}" not in url and "{}" not in url:
            continue
        out.append({
            "name": name,
            "url": normalize_url(url),
            "not_found": [s for s in (info.get("absenceStrs") or []) if isinstance(s, str)][:3],
            "must_contain": [s for s in (info.get("presenseStrs") or []) if isinstance(s, str)][:3],
        })
    return out


def parse_sherlock(raw: dict) -> list:
    """Sherlock 格式：{name: {url, urlMain, errorMsg, errorType, ...}}"""
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
            not_found = [s for s in em if isinstance(s, str)][:3]
        out.append({
            "name": name,
            "url": normalize_url(url),
            "not_found": not_found,
            "must_contain": [],
        })
    return out


def parse_wmn(raw: dict) -> list:
    """WhatsMyName 格式：{sites: [{name, uri_check, m_string?, e_string?, ...}]}"""
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
        # m_string = "must contain"; e_string = error/not found
        not_found = []
        if site.get("e_string") and isinstance(site["e_string"], str):
            not_found = [site["e_string"]]
        must_contain = []
        if site.get("m_string") and isinstance(site["m_string"], str):
            must_contain = [site["m_string"]]
        out.append({
            "name": site.get("name", "Unknown"),
            "url": url,
            "not_found": not_found,
            "must_contain": must_contain,
        })
    return out


def merge_dedup(*sources_lists) -> list:
    """名字去重，名字相同时优先保留有更多检测模式的版本。"""
    by_name = {}
    for src_name, lst in sources_lists:
        for item in lst:
            key = item["name"].lower().strip()
            if not key:
                continue
            existing = by_name.get(key)
            if existing is None:
                item["_source"] = src_name
                by_name[key] = item
            else:
                # 保留模式多的版本
                cur_score = len(existing.get("not_found", [])) + len(existing.get("must_contain", []))
                new_score = len(item.get("not_found", [])) + len(item.get("must_contain", []))
                if new_score > cur_score:
                    item["_source"] = src_name
                    by_name[key] = item
    return list(by_name.values())


def build():
    print("\n=== Fetching upstream sources ===")
    raw = {k: fetch(u) for k, u in SOURCES.items()}

    print("\n=== Parsing ===")
    maigret = parse_maigret(raw["maigret"]);     print(f"  maigret:      {len(maigret)}")
    sherlock = parse_sherlock(raw["sherlock"]);  print(f"  sherlock:     {len(sherlock)}")
    wmn = parse_wmn(raw["whatsmyname"]);         print(f"  whatsmyname:  {len(wmn)}")

    print("\n=== Merging + dedup ===")
    merged = merge_dedup(
        ("maigret",     maigret),
        ("sherlock",    sherlock),
        ("whatsmyname", wmn),
    )
    print(f"  total unique: {len(merged)}")

    print("\n=== Categorizing ===")
    for item in merged:
        item["category"] = categorize(item["name"], item["url"])
        item.pop("_source", None)

    by_cat = Counter(p["category"] for p in merged)
    print(f"  by category:")
    for cat, n in by_cat.most_common():
        print(f"    {cat:10} {n}")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=1)
    print(f"\nWrote {len(merged)} platforms to {OUT_PATH} ({os.path.getsize(OUT_PATH)/1024:.1f} KB)")


if __name__ == "__main__":
    build()
