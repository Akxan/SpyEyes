---
layout: default
home: true
title: "SpyEyes — All-in-One OSINT Toolkit"
description: "SpyEyes is a free, open-source OSINT command-line toolkit in Python: username search across 2,963 sites, subdomain enumeration, domain email harvesting, IP geolocation, phone lookup, WHOIS and MX — no API keys required."
lang: en
---

<section class="hero">
  <p class="eyebrow">Free &amp; open source · Python CLI · English / 简体中文</p>
  <h1>SpyEyes — the all-in-one <span>OSINT toolkit</span></h1>
  <p class="lead"><strong>SpyEyes is a free, open-source OSINT (open-source intelligence) toolkit for the command line, written in Python.</strong> Username search across 2,963 websites, subdomain enumeration, domain email harvesting, IP, phone, WHOIS and MX lookups — one install, no API keys.</p>
  <div class="install"><span class="prompt">$ </span>pipx install git+https://github.com/Akxan/SpyEyes.git</div>
  <div class="actions">
    <a class="btn primary" href="https://github.com/Akxan/SpyEyes">View on GitHub</a>
    <a class="btn" href="TUTORIAL.html">Tutorial (中文)</a>
    <a class="btn" href="https://github.com/Akxan/SpyEyes/releases/latest">Latest release</a>
  </div>
  <ul class="facts">
    <li><b>2,963</b><span>sites per username scan</span></li>
    <li><b>14</b><span>commands</span></li>
    <li><b>8</b><span>report formats</span></li>
    <li><b>0</b><span>API keys required</span></li>
  </ul>
</section>

## What you can do with it

One tool for the everyday reconnaissance pass — each command works on its own and supports `--json` and `--save`.

<ul class="cards">
  <li>
    <h3>👤 Username search</h3>
    <p>Check one username across 2,963 websites — social networks, forums, code hosts, Chinese- and Spanish-language platforms — with 150 threads. <code>spyeyes user torvalds</code></p>
  </li>
  <li>
    <h3>🌐 Subdomain enumeration</h3>
    <p>Six passive sources (crt.sh, CertSpotter, HackerTarget, AlienVault OTX, Wayback Machine, optional subfinder), DNS bruteforce, DNS validation and an HTTP probe. <code>spyeyes subdomain example.com</code></p>
  </li>
  <li>
    <h3>📧 Domain email harvesting</h3>
    <p>Six free sources plus an in-domain crawler, no sign-up. Optional name-pattern guesses and SMTP verification. <code>spyeyes domain-emails example.com</code></p>
  </li>
  <li>
    <h3>🕵 Investigate</h3>
    <p>One domain in: WHOIS, MX, subdomains and emails run concurrently, then pivot automatically to IP enrichment and username scans. One dossier and a relationship graph out.</p>
  </li>
  <li>
    <h3>📍 IP, phone, WHOIS, MX, email</h3>
    <p>IP geolocation with ASN and ISP, phone number region and carrier, domain registration, mail servers, email syntax and MX validation.</p>
  </li>
  <li>
    <h3>📊 Eight report formats</h3>
    <p>JSON, Markdown, HTML, PDF, TXT, CSV, XMind and an interactive graph — picked by file extension. <code>--save report.html</code></p>
  </li>
</ul>

## Results you can trust

Username scanners are only useful if a "found" means found. SpyEyes checks its own answers.

<div class="callout">
  <p><strong>Hit verification.</strong> Every hit is re-checked with a random gibberish username. If the site also says the gibberish name "exists" — login walls, soft-404 pages, DNS hijacking — the hit is marked <em>unverifiable</em> and not counted.</p>
  <p><strong>Blocked is not "not found".</strong> WAF challenges and rate limits are reported as <em>blocked</em>, so you can tell "no such account" from "the site would not answer".</p>
</div>

## Quick start

```bash
pipx install git+https://github.com/Akxan/SpyEyes.git

spyeyes user torvalds                         # username search across 2,963 sites
spyeyes user torvalds --quick                 # skip the long tail (~1,300 sites)
spyeyes subdomain example.com --alive-only    # subdomain enumeration
spyeyes domain-emails example.com             # harvest a domain's email addresses
spyeyes investigate example.com --save dossier.html
spyeyes                                       # interactive menu
```

Requires Python 3.10+. Runs on macOS, Linux, Windows and Termux. Prefer a source checkout or plain `pip`? See [Installation](https://github.com/Akxan/SpyEyes#-installation).

## Commands

| Command | What it does |
|---|---|
| `user` | Check one username across 2,963 websites (merged from Maigret, Sherlock and WhatsMyName) |
| `permute` | Generate username variations from a real name, optionally scan each one |
| `subdomain` | Enumerate subdomains: 6 passive sources + DNS bruteforce + HTTP probe; `--batch` for many domains |
| `diff` | Compare two subdomain scans — added, removed and changed hosts |
| `domain-emails` | Harvest a domain's email addresses from 6 free sources plus a crawler |
| `investigate` | One domain → WHOIS + MX + subdomains + emails, automatic pivots, one consolidated dossier |
| `ip` · `myip` | IP geolocation, ASN and ISP (IPv4 / IPv6); show your public IP |
| `phone` | Parse a phone number: region, carrier, timezone, number type |
| `whois` · `mx` · `email` | Domain WHOIS, MX records, email syntax + MX validation |
| `history` · `upgrade` | Local query history; one-command self-upgrade |

## FAQ

<details>
  <summary>Is SpyEyes free? Do I need API keys?</summary>
  <p>Yes. SpyEyes is open source under the Apache-2.0 license and every command works without any API key. Optional free keys (AlienVault OTX, CertSpotter, GitHub, ProjectDiscovery) only raise rate limits.</p>
</details>
<details>
  <summary>How is SpyEyes different from Sherlock or Maigret?</summary>
  <p>Sherlock and Maigret are username-search tools. SpyEyes reuses their site lists (merged with WhatsMyName) and adds subdomain enumeration, domain email harvesting, IP, phone, WHOIS and MX lookups, an investigate workflow and 8 report formats in the same command-line tool.</p>
</details>
<details>
  <summary>How accurate is the username search?</summary>
  <p>Every hit is re-checked with a random gibberish username. Sites that say the gibberish name exists are reported as unverifiable and not counted. WAF challenges and rate limits are reported as blocked rather than "not found". Login-walled sites such as Instagram, LinkedIn and TikTok cannot be checked reliably without an account, by this or any similar tool.</p>
</details>
<details>
  <summary>Which platforms does it run on?</summary>
  <p>macOS, Linux, Windows and Termux (Android), with Python 3.10 or newer.</p>
</details>
<details>
  <summary>Is it legal to use?</summary>
  <p>SpyEyes only queries publicly available sources. Use it on your own assets, in authorized security tests, and for research or education. You are responsible for complying with local law.</p>
</details>

<div class="zh" lang="zh-CN" translate="no" markdown="1">

## 中文简介

**SpyEyes 是一款免费开源的 OSINT(开源情报)命令行工具,用 Python 编写。** 一次安装包含 14 个命令:用户名扫描(2963 个平台)、子域名枚举、域名邮箱挖掘、IP 归属地、电话号码解析、WHOIS、MX、邮箱验证,以及一条命令出整合档案的 `investigate`。支持 8 种报告格式,无需任何 API key,界面与报告内容中英双语。

用户名扫描会对每个命中做复查:用随机乱码用户名再查一次,乱码也"存在"的平台标为"无法确认",不计入命中;被拦截的平台标为"被拦截",而不是"未找到"。

[中文说明(README)](https://github.com/Akxan/SpyEyes/blob/main/README.zh-CN.md) · [详细教程](TUTORIAL.html) · [更新日志](CHANGELOG.html) · [贡献指南](CONTRIBUTING.html) · [安全策略](SECURITY.html)

</div>

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "name": "SpyEyes",
      "description": "Free, open-source OSINT command-line toolkit written in Python: username search across 2,963 websites, subdomain enumeration, domain email harvesting, IP geolocation, phone number lookup, WHOIS, MX and email validation, with 8 report formats.",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "macOS, Linux, Windows, Android (Termux)",
      "programmingLanguage": "Python",
      "license": "https://www.apache.org/licenses/LICENSE-2.0",
      "isAccessibleForFree": true,
      "inLanguage": ["en", "zh-CN"],
      "url": "https://akxan.github.io/SpyEyes/",
      "codeRepository": "https://github.com/Akxan/SpyEyes",
      "downloadUrl": "https://github.com/Akxan/SpyEyes/releases/latest",
      "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
      "keywords": "OSINT, username search, subdomain enumeration, email harvesting, IP geolocation, phone lookup, WHOIS, reconnaissance, information gathering"
    },
    {
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "Is SpyEyes free? Do I need API keys?",
          "acceptedAnswer": {"@type": "Answer", "text": "Yes. SpyEyes is open source under the Apache-2.0 license and every command works without any API key. Optional free keys (AlienVault OTX, CertSpotter, GitHub, ProjectDiscovery) only raise rate limits."}
        },
        {
          "@type": "Question",
          "name": "How is SpyEyes different from Sherlock or Maigret?",
          "acceptedAnswer": {"@type": "Answer", "text": "Sherlock and Maigret are username-search tools. SpyEyes reuses their site lists (merged with WhatsMyName) and adds subdomain enumeration, domain email harvesting, IP, phone, WHOIS and MX lookups, an investigate workflow and 8 report formats in the same command-line tool."}
        },
        {
          "@type": "Question",
          "name": "How accurate is the SpyEyes username search?",
          "acceptedAnswer": {"@type": "Answer", "text": "Every hit is re-checked with a random gibberish username. Sites that say the gibberish name exists are reported as unverifiable and not counted. WAF challenges and rate limits are reported as blocked rather than not found. Login-walled sites such as Instagram, LinkedIn and TikTok cannot be checked reliably without an account, by this or any similar tool."}
        },
        {
          "@type": "Question",
          "name": "Which platforms does SpyEyes run on?",
          "acceptedAnswer": {"@type": "Answer", "text": "macOS, Linux, Windows and Termux (Android), with Python 3.10 or newer."}
        },
        {
          "@type": "Question",
          "name": "Is it legal to use SpyEyes?",
          "acceptedAnswer": {"@type": "Answer", "text": "SpyEyes only queries publicly available sources. Use it on your own assets, in authorized security tests, and for research or education. You are responsible for complying with local law."}
        }
      ]
    }
  ]
}
</script>
