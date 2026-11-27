---
layout: default
title: "SpyEyes — All-in-One OSINT Toolkit"
description: "SpyEyes is a free, open-source OSINT command-line toolkit in Python: username search across 3,164 sites, subdomain enumeration, domain email harvesting, IP geolocation, phone lookup, WHOIS and MX — no API keys required."
lang: en
---

**SpyEyes is a free, open-source OSINT (open-source intelligence) toolkit for the command line, written in Python.** One install gives you 14 commands: username search across 3,164 websites, subdomain enumeration, domain email harvesting, IP geolocation, phone number lookup, WHOIS, MX and email validation — with 8 report formats, no API keys required, and a fully bilingual interface (English / 简体中文).

[**⭐ GitHub**](https://github.com/Akxan/SpyEyes) · [**📖 Tutorial (中文)**](TUTORIAL.html) · [**📝 Changelog**](CHANGELOG.html) · [**🤝 Contributing**](CONTRIBUTING.html) · [**🔒 Security**](SECURITY.html) · [**🇨🇳 中文说明**](https://github.com/Akxan/SpyEyes/blob/main/README.zh-CN.md)

---

## Quick start

```bash
pipx install git+https://github.com/Akxan/SpyEyes.git

spyeyes user torvalds                  # username search across 3,164 sites
spyeyes subdomain example.com          # subdomain enumeration
spyeyes domain-emails example.com      # harvest a domain's email addresses
spyeyes investigate example.com --save dossier.html
spyeyes                                # interactive menu
```

Requires Python 3.10+. Runs on macOS, Linux, Windows and Termux. Prefer a source checkout? See the [README](https://github.com/Akxan/SpyEyes#-installation).

## What SpyEyes does

| Command | What it does |
|---|---|
| `user` | Check one username across **3,164 websites** (merged from Maigret, Sherlock and WhatsMyName), 150 threads, with hit verification against false positives |
| `permute` | Generate username variations from a real name, optionally scan each one |
| `subdomain` | Enumerate subdomains from 6 passive sources (crt.sh, CertSpotter, HackerTarget, AlienVault OTX, Wayback Machine, optional subfinder) + DNS bruteforce + HTTP probe |
| `diff` | Compare two subdomain scans — added, removed and changed hosts |
| `domain-emails` | Harvest a domain's email addresses from 6 free sources plus an in-domain crawler |
| `investigate` | One domain in → WHOIS + MX + subdomains + emails, automatic pivots, one consolidated dossier and relationship graph |
| `ip` / `myip` | IP geolocation, ASN and ISP lookup (IPv4 / IPv6); show your public IP |
| `phone` | Parse a phone number: region, carrier, timezone, number type |
| `whois` / `mx` / `email` | Domain WHOIS, MX records, email syntax + MX validation |
| `history` / `upgrade` | Local query history; one-command self-upgrade |

Every command supports `--json` for scripting and `--save` with 8 report formats: **JSON, Markdown, HTML, PDF, TXT, CSV, XMind** and an **interactive D3 graph**.

## FAQ

### Is SpyEyes free? Do I need API keys?

Yes. It is open source under the Apache-2.0 license and every command works without any API key. Optional free keys only raise rate limits.

### How is SpyEyes different from Sherlock or Maigret?

Sherlock and Maigret are username-search tools. SpyEyes reuses their site lists and adds subdomain enumeration, domain email harvesting, IP / phone / WHOIS / MX lookups, an `investigate` workflow and 8 report formats in the same CLI.

### How accurate is the username search?

Every hit is re-checked with a random gibberish username; sites that say "exists" for anything are reported as *unverifiable* and not counted. WAF challenges and rate limits are reported as *blocked*, not as "not found".

### Is it legal?

SpyEyes only queries publicly available sources. Use it on your own assets, in authorized security tests, and for research or education.

---

## 中文简介

**SpyEyes 是一款免费开源的 OSINT(开源情报)命令行工具,用 Python 编写。** 一次安装包含 14 个命令:用户名扫描(3164 个平台)、子域名枚举、域名邮箱挖掘、IP 归属地、电话号码解析、WHOIS、MX、邮箱验证,以及一条命令出整合档案的 `investigate`。支持 8 种报告格式,无需任何 API key,界面与报告内容中英双语。

- 中文说明:[README.zh-CN.md](https://github.com/Akxan/SpyEyes/blob/main/README.zh-CN.md)
- 详细教程:[TUTORIAL](TUTORIAL.html)
- 更新日志:[CHANGELOG](CHANGELOG.html)

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "name": "SpyEyes",
      "description": "Free, open-source OSINT command-line toolkit written in Python: username search across 3,164 websites, subdomain enumeration, domain email harvesting, IP geolocation, phone number lookup, WHOIS, MX and email validation, with 8 report formats.",
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
          "acceptedAnswer": {"@type": "Answer", "text": "Yes. SpyEyes is open source under the Apache-2.0 license and every command works without any API key. Optional free keys only raise rate limits."}
        },
        {
          "@type": "Question",
          "name": "How is SpyEyes different from Sherlock or Maigret?",
          "acceptedAnswer": {"@type": "Answer", "text": "Sherlock and Maigret are username-search tools. SpyEyes reuses their site lists and adds subdomain enumeration, domain email harvesting, IP, phone, WHOIS and MX lookups, an investigate workflow and 8 report formats in the same command-line tool."}
        },
        {
          "@type": "Question",
          "name": "How accurate is the SpyEyes username search?",
          "acceptedAnswer": {"@type": "Answer", "text": "Every hit is re-checked with a random gibberish username. Sites that say the gibberish name exists are reported as unverifiable and not counted. WAF challenges and rate limits are reported as blocked rather than not found."}
        }
      ]
    }
  ]
}
</script>
