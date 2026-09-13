# 🛡️ SudoDeck — Cyber Operations & Threat Intelligence Suite

<div align="center">

![SudoDeck Banner](https://raw.githubusercontent.com/Yushif-cpu/SudoDeck/main/public/favicon.ico)

[![Node.js Version](https://img.shields.io/badge/Node.js-v18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-v5.2-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-ISC-blue?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Platform-Active-emerald?style=for-the-badge)]()

**All-in-one OSINT, Threat Hunting, Indicator Analysis & Security Operations Platform.**

[Key Features](#-key-features) •
[Architecture](#-tech-stack--architecture) •
[Installation](#-installation--quickstart) •
[Configuration](#-environment-variables) •
[API Documentation](#-api-endpoints) •
[Deployment](#-deployment-guide)

</div>

---

## 📌 Overview

**SudoDeck** is a modern, high-performance security workbench designed for SOC Analysts, Threat Hunters, Incident Responders, and Penetration Testers. It consolidates disparate threat intelligence lookups, Unix privilege escalation matrices, SIEM log parsing, cryptographic decoding, and hardware reconnaissance into a single, unified, dark-mode cockpit.

---

## 🚀 Key Features

### 🔍 1. OSINT & Threat Intel Analysis
* **IP Reputation & Geo-Lookup:** Live scoring via AbuseIPDB and ThreatFox (abuse.ch) with ASN, ISP, country metadata, and malicious confidence ratings.
* **Domain & URL Intel:** Comprehensive domain reputation, resolution history, and categorization via VirusTotal.
* **File & Hash Lookup:** Instant identification and verdict retrieval for MD5, SHA-1, and SHA-256 hashes against global threat telemetry.
* **Email Header Security Inspector:** Deep-dive RFC parser detecting spoofing, SPF/DKIM/DMARC alignment, and parsing raw hop delivery chains.

### ⚡ 2. GTFOBins Privilege Escalation Explorer
* Offline-first Unix binary exploitation catalog.
* Categorized bypasses: `Sudo`, `SUID`, `Capabilities`, `File Read/Write`, `Command Injection`, and `Reverse Shell`.
* Instant one-click command generators tailored for pentesting and CTF challenges.

### 📜 3. SIEM Log Analysis & Workbench
* Live multi-format parsing for Syslog, Apache/Nginx access logs, and Windows Security Event logs.
* Automated IOC extraction engine (detects IPs, domains, hashes, and URLs from raw unformatted dumps).
* Sigma & YARA rule templates for fast detection engineering.

### 🔐 4. Cryptographic & Cipher Suite
* Multi-algorithm hashing: MD5, SHA-1, SHA-256, SHA-512, Keccak-256.
* Encodings & Transforms: Base64, Hexadecimal, URL encode/decode, Rot13, Binary.
* JWT Inspector: Decodes headers, payloads, and checks token expiration timestamps client-side.

### 🌐 5. Hardware & OUI Reconnaissance
* IEEE MAC address vendor lookup with hardware manufacturer resolution.
* Address classification: Unicast vs. Multicast, Globally Unique (OUI) vs. Locally Administered (LAA).

### 🛡️ 6. NVD Vulnerability Database (CVE)
* Real-time search of the National Vulnerability Database (NVD v2.0 API).
* CVSS v3.1 vector breakdown, severity scoring, and EPSS exploit probability.

---

## 🛠️ Tech Stack & Architecture

* **Runtime:** Node.js (ES Modules, Express 5.x)
* **Frontend:** Modern Vanilla JavaScript, HTML5, Tailwind CSS, Lucide Icons
* **Security & Hardening:**
  * `helmet` for secure HTTP headers (CSP, HSTS, XSS Protection)
  * `express-rate-limit` for DDoS & API abuse mitigation
  * `cors` for granular cross-origin resource policy
* **HTTP Client:** `axios` with configured timeouts and custom user-agent headers
* **Design Aesthetic:** High-density Glassmorphism, tailored cyberpunk HSL palette, dark theme, and keyboard command palette (`Ctrl + K`).

---

## 💻 Installation & Quickstart

### Prerequisites
* [Node.js](https://nodejs.org/) (v18.0.0 or higher recommended)
* [npm](https://www.npmjs.com/) (v9.0.0 or higher)

### 1. Clone the repository
```bash
git clone https://github.com/Yushif-cpu/SudoDeck.git
cd SudoDeck
```

### 2. Install dependencies
```bash
npm install
```

### 3. Setup Environment Variables
Create a `.env` file in the root directory:
```bash
cp .env.example .env   # Or create .env manually
```
Add your third-party API credentials (all keys are optional; platform operates in graceful degradation mode if keys are absent):
```env
PORT=3000
NODE_ENV=development

# Threat Intelligence APIs (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
NVD_API_KEY=your_nvd_api_key_here
```

### 4. Run the Development Server
```bash
npm run dev
```

### 5. Access the Platform
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/recent-malicious-ips` | Fetches live ThreatFox malicious IP telemetry |
| `POST` | `/api/check-ip` | Inspects IP address reputation & geolocation |
| `POST` | `/api/check-domain` | Evaluates domain safety score via VirusTotal |
| `POST` | `/api/check-hash` | Queries VirusTotal for known file hash verdicts |
| `POST` | `/api/check-file` | Computes client file hash & retrieves threat intel |
| `POST` | `/api/analyze-email` | Parses raw RFC 822 email headers for spoofing/SPF/DKIM |
| `GET` | `/api/gtfobins` | Retrieves GTFOBins catalog data |
| `GET` | `/api/gtfobins/:binary` | Retrieves specific Unix binary privilege escalation methods |
| `POST` | `/api/crypto/analyze` | Detects encoding/hash type automatically |
| `POST` | `/api/crypto/process` | Executes cryptographic operations (hash/encode/decode) |
| `GET` | `/api/mac/:mac` | Resolves MAC address to hardware manufacturer |
| `GET` | `/api/cve/search` | Queries NVD for CVE identifiers and keywords |
| `POST` | `/api/contact` | Submits CIRT / dispatch feedback message |
| `GET` | `/api/health` | System health check and uptime probe |

---

## 🌐 Deployment Guide

### Deploying to Render.com (Recommended)

1. Create a free account at [render.com](https://render.com).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub account and select `Yushif-cpu/SudoDeck`.
4. Configure service settings:
   - **Environment:** `Node`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance Type:** `Free`
5. Under **Environment Variables**, optionally paste your `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, etc.
6. Click **Deploy Web Service**.

---

## 🔒 Security & Privacy

* **Zero Data Retention:** SudoDeck does not store or log uploaded file contents, sensitive query artifacts, or email bodies.
* **Safe Secrets Handling:** Secret keys are loaded strictly from server-side environment variables and are never exposed to clients.
* **Rate Limited:** Built-in safeguards protect all computational endpoints from automated brute-force attempts.

---

## 📄 License

This project is licensed under the [ISC License](LICENSE).

---

<div align="center">
  <sub>Built with ❤️ for the Cybersecurity and Open-Source Intelligence Community.</sub>
</div>
