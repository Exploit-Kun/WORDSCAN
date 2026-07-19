# WordScan v8.2 — WordPress Vulnerability Scanner + Auto Exploit

**Enterprise-grade WordPress vulnerability scanner with auto exploit and Telegram notification.**

## 📋 Supported Plugins & CVEs

| No | Plugin | CVE | CVSS | Status |
|----|--------|-----|------|--------|
| 1 | Podlove Podcast Publisher | CVE-2026-13001 | 9.8 | 🔴 RCE |
| 2 | WPvivid Backup | CVE-2026-1357 | 9.8 | 🔴 RCE |
| 3 | Everest Forms Pro | CVE-2026-3300 | 9.8 | 🔴 RCE |
| 4 | Ninja Forms Uploads | CVE-2026-0740 | 9.8 | 🔴 RCE |
| 5 | Sneeit Framework | CVE-2025-6389 | 9.8 | 🔴 RCE |
| 6 | Copypress Rest API | CVE-2025-8625 | 9.8 | 🔴 RCE |
| 7 | GutenKit | CVE-2024-9234 | 9.8 | 🔴 RCE |
| 8 | Hunk Companion | CVE-2024-9707 | 9.8 | 🔴 RCE |
| 9 | Really Simple Security | CVE-2024-10924 | 9.8 | 🔴 RCE |

## ⚡ Features

- ✅ Auto Detect CMS (WordPress/Joomla/Drupal)
- ✅ Auto Detect Plugin & Version (50+ fingerprint methods)
- ✅ Auto Match CVE (9+ CVEs)
- ✅ Auto Exploit (9+ exploits)
- ✅ Auto Upload Shell
- ✅ Auto Telegram Notification
- ✅ Auto Generate Report (JSON, CSV, SQLite, HTML)
- ✅ Resume Scan
- ✅ Configuration Profiles (Fast/Balanced/Deep)

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/Exploit-Kun/wordscan.git
cd wordscan

# Install dependencies
pip install -r requirements.txt