<div align="center">

# ZAL

### Hotmail / Outlook Inbox Checker

**Custom-keyword inbox search via Microsoft Graph API.**

<br>

[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20termux-6b7280?style=for-the-badge&logo=linux&logoColor=white)]()

<br>

[![Telegram](https://img.shields.io/badge/Channel-professor__zal__projects-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/professor_zal_projects)
[![Contact](https://img.shields.io/badge/Contact-%40mr__crkz-C084FC?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/mr_crkz)

</div>

---

## Overview

**ZAL** logs into Hotmail/Outlook accounts, pulls a Graph API token, and searches the inbox for keywords you choose. Valid accounts, mail hits, and 2FA-protected accounts all get sorted automatically into timestamped folders.

No defaults. No forced keyword sets. **You define what to hunt for.**

---

## Features

| | |
|---|---|
| 🎯 **Custom keywords** | No defaults — you enter the search set each run |
| 📊 **Live dashboard** | ANSI box UI · progress bar · CPM · real-time hit feed |
| 🌍 **Country sorting** | Hits auto-split into `Countries/` by account region |
| 🗂️ **Per-keyword files** | Every keyword gets its own file in `Keywords/` |
| 🔌 **Proxy support** | Bulk load · live-tested · rotated per request |
| ⚡ **Threaded** | Bounded semaphore — no thread explosion |
| 🔍 **Graph search** | subject / from / body, fallback to full-text |
| 🔐 **2FA detection** | Flagged separately from dead accounts |

---

## Install

```bash
git clone https://github.com/professorzal/Hotmail-Outlook-Inboxer-.git
cd Hotmail-Outlook-Inboxer-
pip install -r requirements.txt
