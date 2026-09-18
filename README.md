# 🛡️ SudoDeck — Cyber Operations & Threat Intelligence Suite

<div align="center">

![SudoDeck Banner](https://raw.githubusercontent.com/Yushif-cpu/SudoDeck/main/public/favicon.ico)

[![Node.js Version](https://img.shields.io/badge/Node.js-v18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-v5.2-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-ISC-blue?style=for-the-badge)](LICENSE)
[![Platform Status](https://img.shields.io/badge/Platform-Active_&_Secured-emerald?style=for-the-badge)]()

**Enterprise-grade OSINT, Threat Hunting, Attack Simulation, Indicator Analysis & Security Operations Cockpit.**

[Key Modules](#-key-modules--capabilities) •
[Architecture](#-tech-stack--architecture) •
[Installation](#-installation--quickstart) •
[Configuration](#-environment-variables) •
[API Documentation](#-complete-api-reference) •
[Deployment](#-deployment-guide)

</div>

---

## 📌 Overview

**SudoDeck** is a high-performance, dark-theme security workbench designed for **SOC Incident Responders, Threat Hunters, Red Teamers, and OSINT Investigators**. It unifies disparate threat intelligence sources, web traffic telemetry, social footprint reconnaissance, Unix privilege escalation matrices, defensive payload vectors, SIEM log parsing, and cryptographic decoding into a single, cohesive terminal interface.

---

## 🚀 Key Modules & Capabilities

### 🌐 1. Web Traffic & Audience Intelligence (`/traffic`)
* **Traffic & Engagement Telemetry:** Domain visit metrics, global and country rankings, bounce rates, visit duration, and page depth powered by Similarweb.
* **Device & Geography Breakdown:** Desktop vs. mobile visitor splits and top demographic source countries.
* **Traffic Acquisition Channels:** Detailed breakdown of Direct, Organic Search, Referral, Social, and Paid traffic flows.
* **Supabase Edge Caching:** Database-backed persistent caching to prevent upstream rate-limiting and ensure sub-second response times.

### 🕵️ 4. Social Media Footprint Hunter (`/social-footprint`)
* **Cross-Platform Reconnaissance:** OSINT username scanning across **35+ global platforms** (GitHub, Twitter/X, Instagram, Telegram, HackerOne, Keybase, Reddit, TikTok, LinkedIn, etc.) utilizing the Sherlock/Maigret methodology.
* **Official SVG Brand Assets:** High-fidelity platform brand iconography, direct clickable profile links, and live availability verification.

### 📷 5. Visual Recon & Image Geolocation (`/visual-recon`)
* **Client-Side EXIF Forensic Analysis:** Reads camera make, lens model, shutter speed, and embedded GPS coordinates without uploading image binaries to external servers.
* **Interactive Map Pinpoint:** Plots extracted GPS coordinates directly onto OpenStreetMap with latitude, longitude, and elevation.
* **Tesseract OCR Landmark Detection:** Extracts embedded textual indicators, road signs, and watermarks from imagery.
* **Multi-Engine Reverse Visual Search:** Generates one-click reverse search queries for Google Lens, Yandex Visual, and Bing Images.

### 💣 6. Defensive Payload Testing Suite (`/payloads`)
* **Curated Exploit Vectors:** Comprehensive library of defensive test vectors for `Cross-Site Scripting (XSS)`, `SQL Injection (SQLi)`, `Path Traversal / LFI`, and `CSRF`.
* **Downloadable Wordlists:** Instant access to pre-built `.txt` payload lists served statically from `/downloads/payloads/` with in-browser preview modals.
* **Developer Customization Guide:** Accompanied by [PAYLOAD_CUSTOMIZATION_GUIDE.md](PAYLOAD_CUSTOMIZATION_GUIDE.md) for adding custom test wordlists.

### 🔍 7. Core OSINT & Indicator Reputation (`/` & `/#ip` / `/#domain`)
* **IP Reputation & Geo-Lookup:** Multi-source scoring via AbuseIPDB and live ThreatFox (abuse.ch) with ASN, ISP, country metadata, and malicious confidence ratings.
* **Domain & WHOIS Engine:** VirusTotal threat engine aggregation, DNS records (A, AAAA, MX, TXT, NS), and registration timeline analysis.
* **File & Hash Verdict:** Instant lookup for MD5, SHA-1, and SHA-256 digests against global antivirus engines.
* **Subdomain Discovery (`/subdomain`):** Passive infrastructure asset discovery powered by Certificate Transparency logs (crt.sh) and HackerTarget.

### ⚡ 8. GTFOBins Privilege Escalation Explorer (`/gtfobins`)
* **Offline-First Unix Exploitation Catalog:** Searchable database of Unix binaries exploitable for privilege escalation.
* **Filter by Function:** `Sudo`, `SUID`, `Capabilities`, `File Read/Write`, `Command Injection`, and `Reverse Shell`.
* **One-Click Command Generator:** Generates tailored bash one-liners ready for CTF competitions and authorized pentests.

### 📜 9. SIEM Log Analysis & Email Forensics (`/siem`)
* **Log Formatter & IOC Extractor:** Formats Syslog, Windows Event XML, Apache, and Nginx logs into structured JSON, auto-extracting IPs, domains, and hashes.
* **RFC 822 Email Header Inspector:** Parses message hops, calculates transit latency, and verifies SPF, DKIM, and DMARC alignment.
* **Detection Regex Sandbox:** Tests and validates detection engineering regular expressions against sample adversary logs.

### 🔐 10. Cryptographic & Cipher Suite (`/crypto`)
* **Smart Hash & Encoding Analyzer:** Automatically identifies cipher types, character sets, and probable hashing algorithms.
* **Multi-Algorithm Operations:** MD5, SHA-1, SHA-256, SHA-512, Keccak-256, Base64, Hexadecimal, Rot13, and URL encoding.
* **JWT Token Forensics:** Inspects and validates JSON Web Token headers, claims, issued-at, and expiration timestamps.

### 🏷️ 11. Hardware OUI & CVE Vulnerability Search (`/mac` & `/cve`)
* **IEEE MAC Vendor Resolver:** Resolves OUI prefixes to hardware manufacturers (Cisco, Apple, Intel, Raspberry Pi, etc.).
* **NVD CVE Explorer:** Live search of the NIST National Vulnerability Database (NVD v2.0) with CVSS v3.1 vector breakdowns and EPSS exploit probability scores.

---

## 🛠️ Tech Stack & Architecture

| Layer | Technologies |
| :--- | :--- |
| **Backend Runtime** | Node.js (ES Modules), Express 5.x |
| **Frontend UI** | Modern Vanilla JavaScript, HTML5, Tailwind CSS, Lucide Icons, Glassmorphism CSS |
| **Database & Cache** | Supabase (PostgreSQL) edge caching + Browser LocalStorage persistence |
| **Security & Hardening** | `helmet` (strict CSP, HSTS), `express-rate-limit` (DDoS mitigation), `cors` |
| **Navigation & Palette** | Global keyboard command palette (`Ctrl + K`), dynamic auth status pills |

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

### 2. Navigate to the application directory and install dependencies
```bash
cd threat-intel-node
npm install
```

### 3. Setup Environment Variables
Create your `.env` file based on the template:
```bash
cp .env.example .env
```

Configure your optional third-party API credentials:
```env
PORT=3000
NODE_ENV=development

# Threat Intelligence APIs (Optional — features operate with fallback demo data if absent)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
NVD_API_KEY=your_nvd_api_key_here
MACVENDORS_API_TOKEN=your_macvendors_token_here
APIFY_API_TOKEN=your_apify_token_here
ALLOWED_ORIGINS=https://your-frontend.example

# Supabase (Optional — for cloud traffic cache & persistence)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=your_supabase_publishable_key
```

Public traffic lookups use the Supabase cache when available. New paid Apify calls
are limited to 20 per hour per server process, with a 10-minute cooldown per
domain and request type. The original Bypass Cache control remains available.
Multi-instance deployments need a shared rate-limit store and an upstream spend cap.
The Next traffic route uses the publishable Supabase key. Enable RLS and grant
only the `domain_traffic` operations it needs, or leave caching disabled.
Rotate any vendor token that was shared outside the private server environment.
The original frontend markup and event handlers are preserved. Untrusted traffic
data is escaped before HTML rendering, and news links use validated HTTP URLs.

### 4. Start the Application
```bash
# Development mode with hot-reloading:
npm run dev

# Production mode:
npm start
```

### 5. Access the Platform
Open your browser and navigate to:
```text
http://localhost:3000
```

---

## 📡 Complete API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/recent-malicious-ips` | Live ThreatFox malicious IP feed (Keyless) |
| `POST` | `/api/check-ip` | IP reputation, geolocation, ISP, and abuse scores |
| `POST` | `/api/check-domain` | Evaluates domain safety score via VirusTotal |
| `POST` | `/api/check-hash` | Queries VirusTotal for known file hash verdicts |
| `POST` | `/api/check-file` | Computes file hash & retrieves threat intel |
| `POST` | `/api/check-traffic` | Domain traffic volume, global rank & audience telemetry |
| `POST` | `/api/sherlock/search` | Cross-network OSINT username hunting (35+ platforms) |
| `POST` | `/api/subdomain/discover` | Discovers passive subdomains via CT logs |
| `GET` | `/api/payloads` | Curated defensive injection vectors & wordlist metadata |
| `GET` | `/api/gtfobins` | GTFOBins catalog data |
| `GET` | `/api/gtfobins/:binary` | Specific Unix binary privilege escalation methods |
| `POST` | `/api/analyze-email` | Parses RFC 822 email headers for spoofing & SPF/DKIM |
| `POST` | `/api/crypto/analyze` | Detects encoding and hash algorithms |
| `POST` | `/api/crypto/process` | Executes cryptographic hash/encode/decode operations |
| `GET` | `/api/mac/:mac` | Resolves MAC address to hardware manufacturer |
| `GET` | `/api/cve/search` | Queries NVD for CVE identifiers and keywords |
| `POST` | `/api/contact` | Submits CIRT / dispatch feedback message |
| `GET` | `/api/health` | System health check and uptime probe |

---

## 🌐 Deployment Guide

### Deploying to Render.com / Railway / Cloud Run

1. Connect your GitHub repository: `Yushif-cpu/SudoDeck`.
2. Set root directory to `threat-intel-node` (or repository root if deploying top-level).
3. Configure build and start commands:
   * **Build Command:** `npm install`
   * **Start Command:** `npm start`
   * **Port:** `3000` (or leave default `$PORT`)
4. Add environment variables under **Environment** tab in your cloud dashboard.
5. Deploy service.

---

## 🔒 Security & Privacy

* **Zero Sensitive Data Retention:** SudoDeck does not store or leak uploaded file binaries, private email bodies, or internal credentials.
* **Safe Secrets Handling:** API keys are processed strictly on the server-side environment and are never transmitted to client browsers.
* **Multi-Tier Rate Limiting:** Granular rate limiters protect compute-heavy scans (subdomain discovery, Sherlock search) from automated denial of service.
* **Strict CSP & Headers:** Enforced via `helmet` with custom Content Security Policy and HTTP Strict Transport Security (HSTS).

---

## 📄 License

This project is open source and licensed under the [ISC License](LICENSE).

---

<div align="center">
  <sub>Designed & engineered for the global Cybersecurity, Threat Intelligence, and OSINT community.</sub>
</div>
