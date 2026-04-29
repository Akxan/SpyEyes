#!/usr/bin/env python3
"""
构建平台数据库 / Build platforms database.

从 Maigret 上游拉取最新的 sites 数据，过滤、去重、分类后保存为
data/platforms.json，运行时由 GhostTR.py 加载。

用法 / Usage:
    python3 tools/build_platforms.py

会覆盖 data/platforms.json。
"""

import json
import os
import re
import sys

import requests

MAIGRET_URL = (
    "https://raw.githubusercontent.com/soxoj/maigret/main/"
    "maigret/resources/data.json"
)

# 输出文件
OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "platforms.json",
)

# 分类启发式：按关键词匹配 URL 或站点名
CATEGORY_RULES = [
    ("code", [
        "github", "gitlab", "bitbucket", "codeberg", "sr.ht", "sourcehut",
        "leetcode", "codeforces", "hackerrank", "atcoder", "codepen", "replit",
        "glitch", "codesandbox", "codewars", "npm", "pypi", "rubygems",
        "crates.io", "docker", "hashnode", "dev.to", "hackernews",
        "lobste.rs", "stackover", "kaggle", "huggingface", "topcoder",
        "exercism", "kattis", "earthly", "stackblitz", "jsfiddle",
        "hackerearth", "spoj", "codechef", "geeksforgeeks", "rustprogramming",
        "rosalind", "gist", "git",
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


def categorize(name: str, url: str) -> str:
    """根据站点名/URL 启发式判定类别。"""
    haystack = (name + " " + url).lower()
    for cat, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in haystack:
                return cat
    return "other"


def normalize_url(url: str) -> str:
    """把 Maigret 的 {username} 占位符规范成 Python {}。"""
    return url.replace("{username}", "{}")


def fetch_maigret() -> dict:
    print(f"Fetching {MAIGRET_URL} ...")
    r = requests.get(MAIGRET_URL, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data.get("sites", data)


def build():
    sites = fetch_maigret()
    out = []
    skipped = {"disabled": 0, "nsfw": 0, "no_url": 0, "duplicate": 0}
    seen_names = set()

    for name, info in sites.items():
        if info.get("disabled"):
            skipped["disabled"] += 1
            continue
        if info.get("isNSFW"):
            skipped["nsfw"] += 1
            continue
        url = info.get("url", "")
        if "{username}" not in url and "{}" not in url:
            skipped["no_url"] += 1
            continue
        norm_name = name.lower()
        if norm_name in seen_names:
            skipped["duplicate"] += 1
            continue
        seen_names.add(norm_name)

        url = normalize_url(url)
        not_found = info.get("absenceStrs") or []
        must_contain = info.get("presenseStrs") or []
        # 限制每条最多 3 个模式，避免膨胀
        not_found = [s for s in not_found if isinstance(s, str)][:3]
        must_contain = [s for s in must_contain if isinstance(s, str)][:3]
        category = categorize(name, url)

        out.append({
            "name": name,
            "url": url,
            "category": category,
            "not_found": not_found,
            "must_contain": must_contain,
        })

    print(f"Total fetched: {len(sites)}")
    print(f"Skipped: {skipped}")
    print(f"Final usable: {len(out)}")

    # 按类别打印分布
    from collections import Counter
    by_cat = Counter(p["category"] for p in out)
    print(f"\nBy category:")
    for cat, n in by_cat.most_common():
        print(f"  {cat:10} {n}")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"\nWrote {len(out)} platforms to {OUT_PATH}")
    print(f"File size: {os.path.getsize(OUT_PATH) / 1024:.1f} KB")


if __name__ == "__main__":
    build()
