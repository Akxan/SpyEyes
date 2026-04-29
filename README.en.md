<div align="center">

# 🔍 GhostTrack-CN

### All-in-One OSINT Toolkit (Chinese-Enhanced Edition)

**One-shot lookup for IP · Phone · Username · WHOIS · MX · Email**

[![CI](https://github.com/Akxan/GhostTrack-CN/actions/workflows/ci.yml/badge.svg)](https://github.com/Akxan/GhostTrack-CN/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Akxan/GhostTrack-CN/branch/main/graph/badge.svg)](https://codecov.io/gh/Akxan/GhostTrack-CN)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-47%20passed-success.svg)](tests/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20%7C%20Termux-lightgrey)](#-installation)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/maintenance/yes/2026.svg)](https://github.com/Akxan/GhostTrack-CN/commits/main)

[![Stars](https://img.shields.io/github/stars/Akxan/GhostTrack-CN?style=social)](https://github.com/Akxan/GhostTrack-CN/stargazers)
[![Forks](https://img.shields.io/github/forks/Akxan/GhostTrack-CN?style=social)](https://github.com/Akxan/GhostTrack-CN/network/members)
[![Issues](https://img.shields.io/github/issues/Akxan/GhostTrack-CN.svg)](https://github.com/Akxan/GhostTrack-CN/issues)
[![Last Commit](https://img.shields.io/github/last-commit/Akxan/GhostTrack-CN.svg)](https://github.com/Akxan/GhostTrack-CN/commits/main)

**[🇨🇳 中文](README.md) · 🇬🇧 English**

[**📖 Tutorial**](TUTORIAL.md) · [**🐛 Report Bug**](https://github.com/Akxan/GhostTrack-CN/issues) · [**🤝 Contribute**](CONTRIBUTING.md)

</div>

---

## 📖 About

**GhostTrack-CN** is a Python-based command-line **OSINT (Open-Source Intelligence) toolkit**, deeply optimized for Chinese-speaking users. It is a heavily refactored derivative of [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack), with major additions in functionality, performance, and localization.

Designed for **security researchers, penetration testers, SOC analysts, threat hunters, red/blue teamers, CTF players** and anyone curious about open-source intelligence.

### 🆚 What's improved over the original

| Aspect | Original GhostTrack | GhostTrack-CN |
|---|---|---|
| **Language** | English + Indonesian | Full Chinese UI (menus / labels / errors) |
| **Features** | 4 | **7** (+WHOIS / MX / Email validation) |
| **Performance** | Sequential username scan (30-60s) | **2-3 seconds** (10-thread concurrent, 10-20× speedup) |
| **Reliability** | No timeouts, API errors crash, recursive stack overflow | All fixed, unified error handling |
| **Usage modes** | Interactive menu only | Interactive menu + **CLI args mode** + JSON output |
| **Code quality** | No type hints, no tests | Type-annotated + **47 pytest tests** + CI |
| **Country display** | English only | Chinese mapping (180+ countries) |
| **Code size** | 316 lines, single file | 749 lines (full refactor + new features) |

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
- **2020 platforms** (Maigret + Sherlock + WhatsMyName combined)
- **46 Chinese-region** (CN/TW/HK/SG/MY) + **52 Spanish-region** (ES/AR/MX/BR/...)
- **30-50 thread concurrent** scan, ~45-60 sec
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
| **GhostTrack-CN** | ✅ | ✅ | ✅ **(2020)** | ✅ | ✅ | ✅ | ✅ |

> 💡 **Positioning**: GhostTrack-CN is **not** trying to outdo Sherlock in username-scan depth. It's a **lightweight all-in-one Chinese-first toolkit**. For pure username OSINT, Sherlock/Maigret are deeper. For one tool covering 6 lookup types with full Chinese localization, GhostTrack-CN is unmatched.

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
git clone https://github.com/Akxan/GhostTrack-CN.git && \
cd GhostTrack-CN && \
python3 -m venv .venv && \
source .venv/bin/activate && \
pip install -r requirements.txt && \
python3 GhostTR.py
```

### Try it instantly

```bash
# Look up Google DNS
python3 GhostTR.py ip 8.8.8.8

# Show your public IP
python3 GhostTR.py myip

# Parse a phone number
python3 GhostTR.py phone +12025550100

# Scan a username
python3 GhostTR.py user torvalds

# WHOIS
python3 GhostTR.py whois example.com

# MX records
python3 GhostTR.py mx gmail.com

# Email validation
python3 GhostTR.py email someone@gmail.com

# JSON + save
python3 GhostTR.py ip 8.8.8.8 --json --save results/
```

---

## 📦 Installation

### macOS (venv recommended)

```bash
brew install python3 git
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install git python3 python3-pip python3-venv
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Termux (Android)

```bash
pkg install git python
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
pip install -r requirements.txt
```

### Windows

```powershell
# Install Python 3 from python.org, check "Add to PATH"
git clone https://github.com/Akxan/GhostTrack-CN.git
cd GhostTrack-CN
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

---

## 📋 Usage

### 1️⃣ Interactive menu mode

```bash
python3 GhostTR.py
```

### 2️⃣ CLI mode (script-friendly)

```bash
# Basic
python3 GhostTR.py <subcommand> <args> [--json] [--save DIR] [--no-color]

# Pipe with jq
python3 GhostTR.py ip 8.8.8.8 --json | jq -r '.country'

# Bulk
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
  python3 GhostTR.py ip "$ip" --json | jq -r '.ip + " -> " + .country'
done
```

### 3️⃣ Full tutorial (Chinese)

📖 **[TUTORIAL.md](TUTORIAL.md)** — covers every feature in depth (currently Chinese only; English version planned).

---

## 🧪 Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=. --cov-report=term-missing
```

- ✅ 47 tests, ~0.3 seconds
- ✅ Pure functions + HTTP mocking + edge cases
- ✅ GitHub Actions runs on macOS/Ubuntu × Python 3.10-3.13 = 8 combinations

---

## 📁 Project Structure

```
GhostTrack-CN/
├── GhostTR.py                  # Main script (749 lines)
├── requirements.txt            # Runtime deps
├── tests/
│   ├── __init__.py
│   └── test_ghosttrack.py      # 47 pytest tests
├── .github/
│   ├── workflows/ci.yml        # GitHub Actions CI
│   ├── ISSUE_TEMPLATE/         # Issue templates
│   └── dependabot.yml          # Auto dependency updates
├── README.md                   # 中文 README
├── README.en.md                # English README (you are here)
├── TUTORIAL.md                 # Detailed tutorial (Chinese)
├── CONTRIBUTING.md             # Contribution guide
├── SECURITY.md                 # Security policy
├── CHANGELOG.md                # Version history
├── LICENSE                     # MIT
└── asset/                      # Demo images
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

[![Star History Chart](https://api.star-history.com/svg?repos=Akxan/GhostTrack-CN&type=Date)](https://star-history.com/#Akxan/GhostTrack-CN&Date)

---

## 🤝 Contributing

PRs, Issues, and Stars all welcome!

Read [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and code conventions.

<a href="https://github.com/Akxan/GhostTrack-CN/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Akxan/GhostTrack-CN" />
</a>

---

## 🔒 Security

Found a security issue? Please report responsibly via [SECURITY.md](SECURITY.md) — do not open public issues for security bugs.

---

## 📄 License

[**MIT License**](LICENSE) — free for personal and commercial use, just keep the copyright notice.

---

## 🙏 Acknowledgments

- 🌟 **[HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack)** — original author, foundation of this project
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

Users assume all legal responsibility. See [TUTORIAL.md - Legal Notice](TUTORIAL.md#法律与道德提醒) for details.

---

## 🔍 Keywords

`OSINT` `information-gathering` `IP-tracker` `phone-tracker` `username-search` `WHOIS` `MX-records` `email-verification` `cybersecurity` `pentest` `CTF` `red-team` `blue-team` `Python OSINT` `Chinese OSINT toolkit` `osint-tool` `ip-tracker` `phone-tracker` `username-search` `whois-lookup` `dns-lookup` `email-verification` `reconnaissance`

---

<div align="center">

**If this project helps you, please ⭐ star it to support development!**

[⬆ Back to top](#-ghosttrack-cn)

</div>
