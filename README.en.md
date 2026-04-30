<div align="center">

# 🔍 SpyEyes

### All-in-One OSINT Toolkit (Chinese-Enhanced Edition)

**One-shot lookup for IP · Phone · Username · WHOIS · MX · Email**

[![CI](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml/badge.svg)](https://github.com/Akxan/SpyEyes/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akxan/SpyEyes/branch/main/graph/badge.svg)](https://codecov.io/gh/Akxan/SpyEyes)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-157%20passed-success.svg)](tests/)
[![Platforms](https://img.shields.io/badge/platforms-2067-orange.svg)](data/platforms.json)
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

**SpyEyes** is a Python-based command-line **OSINT (Open-Source Intelligence) toolkit**, deeply optimized for Chinese-speaking users. Integrates IP tracking, phone parsing, username scanning across 2067 platforms, domain WHOIS / MX lookups, and email validation — all in one tool.

Designed for **security researchers, penetration testers, SOC analysts, threat hunters, red/blue teamers, CTF players** and anyone curious about open-source intelligence.

### 💎 Highlights

- **2067 username-scan platforms**: 46 Chinese-region (CN/TW/HK/SG/MY) + 52 Spanish-region (ES/AR/MX/BR/...) + 84 adult/dating platforms
- **Bilingual UI**: interactive menu / CLI / errors all in zh+en
- **Sherlock-class speed**: 21s for full 2067-platform scan (100-thread concurrent + Session pool + HEAD optimization + ReDoS guard)
- **WAF detection**: identifies Cloudflare / AWS WAF / PerimeterX blocks to avoid false positives
- **Multiple modes**: `--quick` (~9s) / `--category` (~3s) / default full (~21s)
- **Structured output**: JSON / Markdown reports / persistent history
- **157 pytest tests**: 5-pronged audit clean (ruff / mypy / bandit / pytest / agent)

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
- **2067 platforms** (Maigret + Sherlock + WhatsMyName combined)
- **46 Chinese-region** (CN/TW/HK/SG/MY) + **52 Spanish-region** (ES/AR/MX/BR/...)
- **30-50 thread concurrent** scan, ~20-25 sec
- Dual detection: not-found patterns + must-contain
- Shows hits only by default, use `--all` for full report

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

### 🚀 General Enhancements
- **CLI args mode**: scriptable, batchable
- **JSON output**: pipe-friendly with jq
- **Result saving**: `--save DIR` auto-persistence
- **Color terminal**: auto TTY detection
- **Cross-platform**: macOS / Linux / Windows / Termux

</td>
</tr>
</table>

---

## 🆚 Comparison with similar tools

| Tool | IP | Phone | Username | WHOIS | MX | Email | Chinese-first |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [Sherlock](https://github.com/sherlock-project/sherlock) | ❌ | ❌ | ✅ (400+) | ❌ | ❌ | ❌ | ❌ |
| [Maigret](https://github.com/soxoj/maigret) | ❌ | ❌ | ✅ (3000+) | ❌ | ❌ | ❌ | ❌ |
| [holehe](https://github.com/megadose/holehe) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| [theHarvester](https://github.com/laramies/theHarvester) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **SpyEyes** | ✅ | ✅ | ✅ **(2067)** | ✅ | ✅ | ✅ | ✅ |

> 💡 **Positioning**: SpyEyes is **not** trying to outdo Sherlock in username-scan depth. It's a **lightweight all-in-one Chinese-first toolkit**. For pure username OSINT, Sherlock/Maigret are deeper. For one tool covering 6 lookup types with full Chinese localization, SpyEyes is unmatched.

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
python3 spyeyes.py
```

### Try it instantly

```bash
# Look up Google DNS
python3 spyeyes.py ip 8.8.8.8

# Show your public IP
python3 spyeyes.py myip

# Parse a phone number
python3 spyeyes.py phone +12025550100

# Scan a username
python3 spyeyes.py user torvalds

# WHOIS
python3 spyeyes.py whois example.com

# MX records
python3 spyeyes.py mx gmail.com

# Email validation
python3 spyeyes.py email someone@gmail.com

# JSON + save
python3 spyeyes.py ip 8.8.8.8 --json --save results/
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
python3 spyeyes.py
```

### 2️⃣ CLI mode (script-friendly)

```bash
# Basic
python3 spyeyes.py <subcommand> <args> [--json] [--save DIR] [--no-color]

# Pipe with jq
python3 spyeyes.py ip 8.8.8.8 --json | jq -r '.country'

# Bulk
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 spyeyes.py ip "$ip" --json | jq -r '.ip + " -> " + .country'
done
```

### 3️⃣ Full tutorial (Chinese)

📖 **[TUTORIAL.md](docs/TUTORIAL.md)** — covers every feature in depth (currently Chinese only; English version planned).

---

## 🧪 Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=. --cov-report=term-missing
```

- ✅ **157 tests**, ~0.3 seconds (v1.1.0 added 58)
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
├── spyeyes.py                  # Main script (full features + i18n + __version__)
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
├── data/
│   └── platforms.json          # 2067-platform database (Maigret + Sherlock + WhatsMyName)
├── tools/
│   └── build_platforms.py      # Refresh platform DB (atomic write + retries)
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # autouse fixture (global state isolation)
│   ├── test_spyeyes.py         # Core tests (119)
│   └── test_build_platforms.py # Build tool tests (38)
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

`OSINT` `information-gathering` `IP-tracker` `phone-tracker` `username-search` `WHOIS` `MX-records` `email-verification` `cybersecurity` `pentest` `CTF` `red-team` `blue-team` `Python OSINT` `Chinese OSINT toolkit` `osint-tool` `ip-tracker` `phone-tracker` `username-search` `whois-lookup` `dns-lookup` `email-verification` `reconnaissance`

---

<div align="center">

**If this project helps you, please ⭐ star it to support development!**

[⬆ Back to top](#-spyeyes-cn)

</div>
