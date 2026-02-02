# 🛡️ S.C.A.R. - System for Countering Automated Reconnaissance

<div align="center">

```
███████╗ ██████╗ █████╗ ██████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗
███████╗██║     ███████║██████╔╝
╚════██║██║     ██╔══██║██╔══██╗
███████║╚██████╗██║  ██║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**Next-Gen Active Defense Honeypot**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AI](https://img.shields.io/badge/AI_Models-4_Layers-purple.svg)](models/)
[![Telegram](https://img.shields.io/badge/Alert-Telegram_Bot-26A5E4.svg)](https://core.telegram.org/bots)

</div>

---

## 📋 Overview

**S.C.A.R.** adalah sistem honeypot canggih yang dirancang untuk mendeteksi, menganalisis, dan **menjebak** serangan siber secara otomatis. Berbeda dengan honeypot pasif biasa, S.C.A.R. menggunakan **Threat Fusion Engine** yang menggabungkan kekuatan 4 model AI dan Reconnaissance Blacklist untuk akurasi deteksi maksimal.

Jika serangan terdeteksi, S.C.A.R. tidak hanya memblokir IP — S.C.A.R. melakukan **Tarpit (Resource Exhaustion)** untuk membuang waktu dan sumber daya penyerang, sambil mengirim **notifikasi real-time** ke Telegram.

---

## ✨ Key Features

### 🧠 Multi-Layer AI Fusion Engine
S.C.A.R. memiliki **4 Lapisan AI** yang bekerja bersama:
| Layer | Model | Fungsi | Algoritma |
|-------|-------|--------|-----------|
| 1 | URL Threat | Deteksi URL Phishing & Malware | TF-IDF + Logistic Regression |
| 2 | SQL Injection | Analisis payload injeksi SQL | TF-IDF + Logistic Regression |
| 3 | HTTP Behavior | Deteksi anomali struktur request | Random Forest |
| 4 | Zero-Day Anomaly | Deteksi serangan tak dikenal | Isolation Forest |

**Fusion Logic:**
- **Hard Layers** (URL, SQLi): Bisa memblokir sendiri jika confidence tinggi.
- **Soft Layers** (Behavior, Anomaly): Butuh 2+ layer setuju untuk memblokir — mengurangi false positive.

### 🕵️ Reconnaissance Blacklist
Menangkap probing terhadap file/path sensitif yang sering digunakan penyerang:
- `.git/config`, `.env`, `.htaccess`, `.htpasswd`
- `wp-admin`, `wp-login`, `phpMyAdmin`, `/admin`
- `etc/passwd`, `../` (directory traversal)
- `.bak`, `.sql`, `.dump` (backup files)

### 🌐 Real-Time Threat Intelligence
- Integrasi **AbuseIPDB API** untuk cek reputasi IP.
- **Smart Caching**: Hasil disimpan di memori (TTL: 1 jam).
- **Private IP Bypass**: IP lokal otomatis dilewati.

### ⚔️ Active Defense: Tarpit
Ketika serangan terdeteksi, S.C.A.R. **tidak memutus koneksi** — justru sebaliknya:
1. Server merespons `HTTP 200 OK` (penyerang pikir berhasil).
2. Mengirim **garbage headers tanpa henti** (`X-Trap-XXXXXX: [random hex]`).
3. Penyerang **terjebak menunggu** response yang tidak pernah selesai.
4. Tool penyerang (SQLMap, DirBuster, dll) **hang** sampai timeout.

### 🔔 Telegram Alert
Notifikasi instan ke grup/channel Telegram setiap kali serangan terdeteksi:
- IP penyerang, jenis ancaman, risk score.
- Dikirim secara **non-blocking** (background thread).
- Format pesan dengan emoji dan detail lengkap.

---

## 🏗️ Defense Flow

```
                        INCOMING REQUEST
                              │
                              ▼
                ┌──────────────────────────┐
                │  Layer 0: IP Reputation  │
                │  (AbuseIPDB API + Cache) │
                └──────────────────────────┘
                              │
                              ▼
                ┌──────────────────────────┐
                │  Layer 1: Recon Blacklist│
                │  (.git, .env, wp-admin)  │
                └──────────────────────────┘
                              │
                              ▼
          ┌───────────────────────────────────────┐
          │      THREAT FUSION ENGINE (AI)        │
          │                                       │
          │  [URL Model] [SQLi Model]  ← Hard     │
          │  [Behavior]  [Anomaly]     ← Soft     │
          │                                       │
          │  Fusion Logic → Risk Score            │
          └───────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            ┌─────────────┐    ┌──────────────────┐
            │  ✅ CLEAN    │    │  🔴 TARPIT       │
            │  Serve Page  │    │  Drain Resources │
            └─────────────┘    │  + Telegram Alert │
                               └──────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/FalitoNGL/Project_SCAR.git
cd Project_SCAR
pip install -r requirements.txt
```

### 2. Konfigurasi

Edit `server.py` untuk mengatur:

```python
# Threat Intelligence API
ABUSEIPDB_API_KEY = "YOUR_API_KEY"

# Telegram Alert (Opsional)
TELEGRAM_BOT_TOKEN = "your_bot_token"
TELEGRAM_CHAT_ID = "your_chat_id"

# Tarpit Settings
TARPIT_DELAY_SECONDS = 5
TARPIT_HEADER_COUNT = 1000000
```

### 3. Jalankan Server

```bash
python server.py
# atau dengan port custom:
python server.py --port 8080
```

### 4. Simulasi Serangan (Terminal Baru)

```bash
python attacker_simulation.py
```

---

## 📁 Project Structure

```
Project_SCAR/
├── server.py                # 🖥️ Main Server + Fusion Engine + Tarpit
├── attacker_simulation.py   # 🧪 Tool Simulasi Serangan
├── default.html             # 🎭 Halaman Palsu (Honeypot Lure)
├── requirements.txt         # 📦 Dependencies
├── .gitignore               # 🚫 Git Ignore Rules
├── models/                  # 🧠 AI Models
│   ├── url_model.pkl        #    Layer 1: URL Threat
│   ├── url_vectorizer.pkl   #    Layer 1: TF-IDF Vectorizer
│   ├── sqli_model.pkl       #    Layer 2: SQLi Detection
│   ├── sqli_vectorizer.pkl  #    Layer 2: TF-IDF Vectorizer
│   ├── behavior_model.pkl   #    Layer 3: HTTP Behavior
│   └── anomaly_model.pkl    #    Layer 4: Anomaly Detection
└── README.md                # 📖 Dokumentasi
```

---

## 📝 License

MIT License — Feel free to use and modify.

---

## 👥 Author

**PROJECT S.C.A.R.**
*System for Countering Automated Reconnaissance*

_Membangun pertahanan siber yang tidak hanya diam, tapi melawan balik._ 🛡️👊
