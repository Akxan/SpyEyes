<div align="center">

# 🔍 SpyEyes

### All-in-One OSINT Toolkit (Chinese-Enhanced Edition)

**One-shot lookup for IP · Phone · Username · WHOIS · MX · Email · Subdomain · Domain Emails**

[![CI](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml/badge.svg)](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akxan/SpyEyes/branch/main/graph/badge.svg)](https://codecov.io/gh/Akxan/SpyEyes)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-468%20passed-success.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-3164-orange.svg)](#-comparison-with-similar-tools)
[![Reports](https://img.shields.io/badge/reports-8%20formats-9cf.svg)](#-report-formats-8-types)
[![Commands](https://img.shields.io/badge/commands-10-blueviolet.svg)](docs/TUTORIAL.md)
[![Version](https://img.shields.io/badge/version-1.6.6-blueviolet.svg)](docs/CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-online-blue.svg)](https://akxan.github.io/SpyEyes/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20%7C%20Termux-lightgrey)](#-installation)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/maintenance/yes/2026.svg)](https://github.com/Akxan/SpyEyes/commits/main)

[![Stars](https://img.shields.io/github/stars/Akxan/SpyEyes?style=social)](https://github.com/Akxan/SpyEyes/stargazers)
[![Forks](https://img.shields.io/github/forks/Akxan/SpyEyes?style=social)](https://github.com/Akxan/SpyEyes/network/members)
[![Issues](https://img.shields.io/github/issues/Akxan/SpyEyes.svg)](https://github.com/Akxan/SpyEyes/issues)
[![Last Commit](https://img.shields.io/github/last-commit/Akxan/SpyEyes.svg)](https://github.com/Akxan/SpyEyes/commits/main)

**[🇨🇳 中文](README.md) · 🇬🇧 English**

[**📖 Tutorial**](docs/TUTORIAL.md) · [**🐛 Report Bug**](https://github.com/Akxan/SpyEyes/issues) · [**🤝 Contribute**](docs/CONTRIBUTING.md)

</div>

---

## 📖 About

**SpyEyes** is a Python-based command-line **OSINT (Open-Source Intelligence) toolkit**, deeply optimized for Chinese-speaking users. **10 core capabilities**: IP / Phone / Username (3164 platforms) / WHOIS / MX / Email / **Subdomain enum** (6 sources + bruteforce + JS extract) / **Domain email harvest** (6 sources concurrent, all free) / **Diff monitoring** / **Batch input** / **8 Editorial-style report formats**.

Designed for **security researchers, penetration testers, SOC analysts, threat hunters, red/blue teamers, CTF players** and anyone curious about open-source intelligence.

### 💎 Highlights

- **🆕 v1.6.0: Domain email — 6 sources concurrent, all free** — Bing SERP + DuckDuckGo + Wayback Machine + GitHub commits + crt.sh + WHOIS, **completely free + no registration**; concurrent execution (~2-3× faster than sequential); compared to theHarvester/Photon/EmailFinder, free-tier strongest + most report formats
- **🆕 v1.5.0: Diff mode + batch input** — `spyeyes diff old.json new.json` to find added/removed/changed subdomains (essential for OSINT monitoring); `--batch domains.txt --batch-save-dir reports/` for batch scan with per-domain reports
- **🆕 v1.4.x: Subdomain — 7 collection dimensions** — 6 passive sources (crt.sh / CertSpotter / HackerTarget / OTX / **Wayback Machine** / optional subfinder w/ 30+) + DNS dictionary bruteforce (built-in 220 words / `SPYEYES_DNS_WORDLIST` for custom) + JS/HTML body host extraction + DNS A/AAAA/CNAME validation + HTTP probe + wildcard detection
- **🆕 Editorial Investigation Brief styling** — Cormorant Garamond + Crimson Pro + JetBrains Mono triplet + cream/ink/seal-red palette; HTML sticky thead + alive/dead visual differentiation + HTTP status color-coding; PDF cover page + roman numeral chapters
- **3164 username-scan platforms**: 48 Chinese-region + 58 Spanish-region + 91 adult/dating + 733 forums; Sherlock-class speed ~20s
- **Maigret-style permute** + recursive scan `--recursive` + multi mode `--quick` / `--category`
- **8 report formats** — `JSON / Markdown / HTML / PDF / TXT / CSV / XMind / Graph (D3.js)`, all bilingual (zh/en)
- **WAF detection**: Cloudflare / AWS WAF / PerimeterX / DataDome / Akamai
- **Full bilingual**: interactive menu / CLI / errors / **report content** all in zh+en
- **🆕 v1.6.1: 100% progress feedback audit** — every operation > 2s has stage feedback (no more "looks frozen")
- **468 pytest tests**: 4-tool audit clean (ruff 0 / mypy 0 / bandit 0 / pytest), CI on macOS/Linux/Windows × Python 3.10–3.14

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🌐 IP Tracking
- **IPv4 & IPv6** support
- Country, city, ISP, ASN, geo-coords
- Auto-generated Google Maps link
- **Chinese country names** (180+ regions)

### 📡 My IP
- Show current public egress IP
- Real-time refresh after VPN/proxy switch

### 📱 Phone Tracking
- Chinese region info (北京市 / 上海市 ...)
- Chinese carriers (中国移动 / 联通 / 电信)
- Timezone, E.164 / international / mobile-dial format
- 12 number type categories (mobile / landline / VoIP / pager ...)

### 👤 Username Scan
- **3164 platforms** (Maigret + Sherlock + WhatsMyName, with Maigret engine resolution)
- **48 Chinese-region** + **58 Spanish-region** + **733 forums**
- **150-thread concurrent**, full ~20s, quick mode ~10s
- Dual detection: not-found patterns + must-contain + WAF detection
- Shows hits only by default, use `--all` for full report
- **🆕 v1.1.0**: `--recursive` for follow-up scans (depth 0-2), `permute` subcommand for username variations

</td>
<td width="50%">

### 🔍 Domain WHOIS
- Registrar, creation/expiration/update dates
- Name servers, registrant org, contact emails
- Supports 200+ TLDs

### 📨 Domain MX Records
- All MX records sorted by preference
- Useful for email infrastructure intel

### ✉️ Email Validation
- Regex format check
- MX record validation (no test emails sent)
- Privacy-respecting: zero traces

### 🌐 Subdomain Enumeration (v1.3.0 → v1.6.1 🆕)
- **Passive multi-source (6 sources)**: `crt.sh` + CertSpotter + HackerTarget + AlienVault OTX + **Wayback Machine (v1.4.9)** in concurrent fan-out
- **🚀 Optional subfinder relay (v1.4.8)**: auto-detects `subfinder` binary and relays to 30+ sources (virustotal / shodan / censys / chaos / fofa / quake / securitytrails ...); zero overhead if not installed
- **🆕 DNS dictionary bruteforce (v1.4.9, opt-in)**: built-in ~220 high-hit prefixes + `SPYEYES_DNS_WORDLIST=/path` for custom big wordlists; `--bruteforce` to enable
- **🆕 JS / HTML host extraction (v1.4.9, default on)**: regex-scans the already-fetched 16KB probe body for hardcoded host references (e.g. `fetch('https://api.example.com/...')`), then re-resolves found hosts; `--no-js-extract` to disable
- **DNS validation**: A / AAAA / CNAME (default 30 workers)
- **HTTP probe**: status_code + `<title>` (`--no-probe` to skip)
- **Wildcard detection**: 32-char random prefix probe; flags unreliable results
- All 8 report formats supported (HTML clickable links for alive subs)

### 📊 OSINT Monitoring / Batch (v1.5.0 🆕)
- **Diff mode**: `spyeyes diff old.json new.json` — find **added / removed / changed** subdomains across two scans (essential for continuous monitoring)
- **Batch domain input**: `spyeyes subdomain --batch domains.txt --batch-save-dir reports/` — per-domain reports, Ctrl+C interruptible
- **`--alive-only` everywhere**: filters CLI / JSON / all 8 export formats

### 🚀 General Enhancements
- **CLI args mode**: scriptable
- **JSON output**: pipe-friendly with jq
- **Result saving**: `--save DIR` auto-persistence
- **100% progress feedback** (v1.6.1): every >2s operation has live progress
- **Color terminal**: auto TTY detection
- **Cross-platform**: macOS / Linux / Windows / Termux

</td>
</tr>
</table>

---

## 🆚 Comparison with similar tools

| Tool | IP | Phone | Username | WHOIS | MX | Email | Subdomain | Domain Emails | Diff | Batch | Reports | Chinese |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [Sherlock](https://github.com/sherlock-project/sherlock) | ❌ | ❌ | ✅ (400+) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 1 | ❌ |
| [Maigret](https://github.com/soxoj/maigret) | ❌ | ❌ | ✅ (3000+) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 1-2 | ❌ |
| [holehe](https://github.com/megadose/holehe) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 1 | ❌ |
| [theHarvester](https://github.com/laramies/theHarvester) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (some paid) | ❌ | ❌ | 1-2 | ❌ |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | 1 | ❌ |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | 1 | ❌ |
| **SpyEyes** | ✅ | ✅ | ✅ **(3164)** | ✅ | ✅ | ✅ | ✅ **(7 dim)** | ✅ **(6 free)** | ✅ | ✅ | **8** | ✅ |

> 💡 **Positioning**: SpyEyes is **not** trying to outdo Sherlock in username-scan depth. It's a **lightweight all-in-one + Chinese-first + report-rich** OSINT toolkit. For pure username OSINT, Sherlock/Maigret are deeper. For one tool covering 10 commands with 8 export formats and full bilingual UI, SpyEyes is unmatched in the free tier.

---

## 🛠 Tech Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/Requests-2C5BB4?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)

</div>

| Layer | Tech / Library | Purpose |
|---|---|---|
| **Language** | Python 3.10+ | Core |
| **HTTP** | `requests` | API calls |
| **Phone parser** | `phonenumbers` | Google's official phone number library |
| **DNS** | `dnspython` | MX / A / AAAA queries |
| **WHOIS** | `python-whois` | Domain registration |
| **Concurrency** | `concurrent.futures.ThreadPoolExecutor` | Multi-platform parallel scan |
| **CLI** | `argparse` | Command-line parsing |
| **Terminal** | ANSI escape sequences | Colored output + TTY detection |
| **Testing** | `pytest` + `unittest.mock` | Unit tests + HTTP mocking |
| **CI/CD** | GitHub Actions | Cross-platform multi-version auto-testing |
| **Data sources** | `ipwho.is` · `api.ipify.org` | IP information APIs |

---

## 🚀 Quick Start

### One-liner install & run (macOS / Linux)

```bash
git clone https://github.com/Akxan/SpyEyes.git && \
cd SpyEyes && \
python3 -m venv .venv && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
python3 -m spyeyes
```

### Try it instantly

```bash
# Look up Google DNS
python3 -m spyeyes ip 8.8.8.8

# Show your public IP
python3 -m spyeyes myip

# Parse a phone number
python3 -m spyeyes phone +12025550100

# Scan a username
python3 -m spyeyes user torvalds

# WHOIS
python3 -m spyeyes whois example.com

# MX records
python3 -m spyeyes mx gmail.com

# Email validation
python3 -m spyeyes email someone@gmail.com

# Subdomain enumeration (v1.3.0 → v1.6.1)
python3 -m spyeyes subdomain example.com                                     # 6 sources passive + DNS + HTTP probe + JS extract (default all on)
python3 -m spyeyes subdomain example.com --bruteforce                        # add built-in 220-word dict bruteforce
SPYEYES_DNS_WORDLIST=~/all.txt spyeyes subdomain example.com --bruteforce    # custom big wordlist
python3 -m spyeyes subdomain example.com --alive-only --save report.html     # only alive subs (cleaner report)
python3 -m spyeyes subdomain example.com --no-js-extract --no-probe          # passive only, fastest
python3 -m spyeyes subdomain example.com --json | jq '.subdomains[] | select(.alive)'

# 🆕 v1.5.0: Batch domain scan
python3 -m spyeyes subdomain --batch domains.txt --batch-save-dir reports/ --alive-only
# domains.txt: one domain per line; # comments + blank lines skipped; per-domain HTML report

# 🆕 v1.5.0: Diff mode — OSINT continuous monitoring
python3 -m spyeyes subdomain example.com --json > monday.json
python3 -m spyeyes subdomain example.com --json > friday.json   # rescan days later
python3 -m spyeyes diff monday.json friday.json --save diff.html   # added / removed / changed subdomains

# 🆕 v1.6.0: Domain email harvest (6 sources concurrent, all free)
python3 -m spyeyes domain-emails example.com           # crt.sh + WHOIS + Bing + DDG + Wayback + GitHub all concurrent
python3 -m spyeyes domain-emails example.com --guess "John Doe,Jane Smith"   # + pattern generation
python3 -m spyeyes domain-emails example.com --no-crawl   # 6 passive sources only, fastest

# JSON + save
python3 -m spyeyes ip 8.8.8.8 --json --save results/
```

### 🆕 v1.2.0 New features

```bash
# 1) 8 report formats — auto-dispatched by --save file extension
python3 -m spyeyes user torvalds --save report.html       # HTML (styled)
python3 -m spyeyes user torvalds --save report.pdf        # PDF (needs spyeyes[pdf])
python3 -m spyeyes user torvalds --save report.xmind      # XMind 8 mind-map
python3 -m spyeyes user torvalds --save report.graph.html # D3.js force-directed graph
python3 -m spyeyes user torvalds --save report.csv        # CSV (injection-protected)
python3 -m spyeyes user torvalds --save report.txt        # Plain text
python3 -m spyeyes user torvalds --save report.md         # Markdown
python3 -m spyeyes user torvalds --save report.json       # JSON

# 2) Reports follow UI language
python3 -m spyeyes --lang zh user torvalds --save zh.html
python3 -m spyeyes --lang en user torvalds --save en.html

# 3) Maigret-style permute (method=all adds _prefix/suffix_)
python3 -m spyeyes permute "John Doe"                     # strict (default)
python3 -m spyeyes permute "John Doe" --method all
python3 -m spyeyes permute "Linus Torvalds" --scan --quick  # permute + auto-scan

# 4) Recursive scan
python3 -m spyeyes user torvalds --recursive --depth 2

# 5) Default 150-thread concurrency (up from 100)
python3 -m spyeyes user torvalds --workers 200
```

---

## 📦 Installation

### macOS (venv recommended)

```bash
brew install python3 git
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install git python3 python3-pip python3-venv
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Termux (Android)

```bash
pkg install git python
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
pip install -r requirements.txt
```

### Windows

```powershell
# Install Python 3 from python.org, check "Add to PATH"
git clone https://github.com/Akxan/SpyEyes.git
cd SpyEyes
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## 📋 Usage

### 1️⃣ Interactive menu mode

```bash
python3 -m spyeyes
```

### 2️⃣ CLI mode (script-friendly)

```bash
# Basic
python3 -m spyeyes <subcommand> <args> [--json] [--save DIR] [--no-color]

# Pipe with jq
python3 -m spyeyes ip 8.8.8.8 --json | jq -r '.country'

# Bulk
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 -m spyeyes ip "$ip" --json | jq -r '.ip + " -> " + .country'
done
```

### 3️⃣ Full tutorial (Chinese)

📖 **[TUTORIAL.md](docs/TUTORIAL.md)** — covers every feature in depth (currently Chinese only; English version planned).

---

## 📊 Report formats (8 types)

Auto-dispatched by `--save <file>` extension. All formats follow the current UI language (zh/en):

| Format | Suffix | Implementation | Use case |
|---|---|---|---|
| **JSON** | `.json` | stdlib | Pipelines, scripts, API integration |
| **Markdown** | `.md` | stdlib (with injection escaping) | GitHub Issues, notes, wiki |
| **HTML** | `.html` | stdlib + inline CSS | Browser viewing, email attachments |
| **PDF** | `.pdf` | reportlab (optional `[pdf]`) | Formal investigation reports, archive |
| **TXT** | `.txt` | stdlib | Paste into tickets / IM / email |
| **CSV** | `.csv` | csv stdlib + Excel-formula injection guard | Excel / Google Sheets / pandas |
| **XMind** | `.xmind` | zipfile + xml stdlib | Mind-map (XMind 8 compatible) |
| **Graph** | `.graph.html` | D3.js v7 (CDN) | Interactive force-directed graph |

```bash
python3 -m spyeyes user torvalds --save report.html
python3 -m spyeyes user torvalds --save report.xmind
python3 -m spyeyes user torvalds --save report.graph.html
```

**Interactive mode**: after picking "Save report", you'll see a `[1] JSON ... [8] Graph` numeric chooser, default path `~/Downloads/`. After saving, you'll be asked "Save another format?" — chain multiple format outputs in one session.

> **Security**: HTML / Graph use `_html_escape` against XSS; CSV cells starting with `= + - @ \t \r` are prefixed with `'` to neutralize Excel/Sheets formula injection; the Graph escapes `</` to `<\/` inside embedded JSON to prevent `</script>` injection.

> **Notes**:
> - `--save DIR/` (trailing slash or existing directory) always writes **JSON** with timestamped names — to pick a format, give a concrete file path like `--save report.html`
> - **Report content follows `--lang`** — including CSV column headers (zh outputs `分类,平台,主页地址,状态`). Downstream scripts (pandas/jq) needing stable column names should pin `--lang en` or read JSON instead.

---

## 🧪 Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=. --cov-report=term-missing
```

- ✅ **306 tests**, ~0.6 seconds (v1.2.0 comprehensive coverage)
- ✅ Pure functions + HTTP mocking + edge cases + SSRF/ReDoS defenses
- ✅ GitHub Actions runs on macOS / Ubuntu / **Windows** × Python 3.10-3.13
- ✅ Dedicated lint job (ruff + mypy + bandit)

```bash
pip install -r requirements-dev.txt
```

---

## 📁 Project Structure

```
SpyEyes/
├── spyeyes/                    # Main package (v1.0.0+)
│   ├── __init__.py             # Main code (all features + i18n + __version__)
│   ├── __main__.py             # python -m spyeyes entry point
│   └── data/platforms.json     # 3164-platform database (Maigret + Sherlock + WhatsMyName merged)
├── README.md                   # 中文 README
├── README.en.md                # English README (you are here)
├── LICENSE                     # Apache 2.0
├── NOTICE                      # 版权声明
├── requirements.txt            # Runtime deps
├── requirements-dev.txt        # Dev/test deps (pytest, ruff, mypy, bandit)
├── docs/                       # 📚 All documentation
│   ├── TUTORIAL.md             # Detailed tutorial (Chinese)
│   ├── CHANGELOG.md            # Version history
│   ├── CONTRIBUTING.md         # Contribution guide
│   └── SECURITY.md             # Security policy
├── tools/
│   └── build_platforms.py      # Refresh platform DB (atomic write + retries)
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # autouse fixture (global state isolation)
│   ├── test_spyeyes.py         # Core tests (222)
│   └── test_build_platforms.py # Build tool tests (40)
├── .github/
│   ├── workflows/ci.yml        # CI (lint job + multi-OS × multi-Python matrix)
│   ├── ISSUE_TEMPLATE/         # Issue templates
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml          # Auto dependency updates
└── asset/                      # README screenshots & social preview
```

---

## 🎯 Use Cases

- 🛡 **Enterprise Blue Team / SOC**: analyze suspicious IPs, investigate phishing domains
- 🎯 **Red Team / Pentest**: rapid info-gathering during recon
- 🏆 **CTF / OSINT competitions**: quick lookup tool
- 🕵 **Security research**: bulk IP attribution, domain reputation
- 📞 **Phone scam identification**: check unknown caller origin and carrier
- 📧 **Email marketing**: pre-filter mailing lists for valid addresses
- 🌍 **Personal use**: check VPN exit, audit DNS configs

---

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Akxan/SpyEyes&type=Date)](https://star-history.com/#Akxan/SpyEyes&Date)

---

## 🤝 Contributing

PRs, Issues, and Stars all welcome!

Read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for development workflow and code conventions.

<a href="https://github.com/Akxan/SpyEyes/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Akxan/SpyEyes" />
</a>

---

## 🔒 Security

Found a security issue? Please report responsibly via [SECURITY.md](docs/SECURITY.md) — do not open public issues for security bugs.

---

## 📄 License

[**Apache License 2.0**](LICENSE) — free for personal and commercial use, with explicit patent grant and trademark protection. See [NOTICE](NOTICE) for required attribution.

---

## 🙏 Acknowledgments

- 🌟 **[Google libphonenumber](https://github.com/google/libphonenumber)** — industry-standard phone number library
- 🌟 **[ipwho.is](https://ipwho.is/)** — free, stable, info-rich IP geolocation API
- 🌟 **[ipify.org](https://www.ipify.org/)** — clean public IP lookup service
- 🌟 All open-source security tool contributors ❤️

---

## ⚠️ Disclaimer

This tool is for **legitimate security research, self-audit, CTF, and educational purposes only**.

❌ **Prohibited uses**:
- Tracking, harassing, or doxing individuals
- Unauthorized network scanning or intrusion
- Commercial use of harvested personal data

✅ **Permitted uses**:
- Self-audit of your own assets
- Authorized penetration testing
- Lookup of fully public information
- Education, research, open-source contribution

Users assume all legal responsibility. See [TUTORIAL.md - Legal Notice](docs/TUTORIAL.md#法律与道德提醒) for details.

---

## 🔍 Keywords

`OSINT` `information-gathering` `IP-tracker` `phone-tracker` `username-search` `WHOIS` `MX-records` `email-verification` `subdomain-enumeration` `subdomain-finder` `email-harvester` `domain-emails` `crtsh` `certspotter` `certificate-transparency` `cybersecurity` `pentest` `CTF` `red-team` `blue-team` `Python OSINT` `Chinese OSINT toolkit` `osint-tool` `ip-tracker` `phone-tracker` `username-search` `whois-lookup` `dns-lookup` `email-verification` `reconnaissance` `editorial-reports`

---

<div align="center">

**If this project helps you, please ⭐ star it to support development!**

[⬆ Back to top](#-spyeyes)

</div>
