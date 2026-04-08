# 🎣 PhishingDetector — Email Threat Analysis Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-black?style=flat-square&logo=flask)
![Security](https://img.shields.io/badge/Security-SOC%20Tool-red?style=flat-square)
![Blue Team](https://img.shields.io/badge/Blue_Team-Defensive-blue?style=flat-square)

> Python-based phishing email analysis tool with a web dashboard — built for SOC Tier 1 analysts to triage suspicious emails, extract IOCs, and score phishing risk from 0–100.

---

## 🎯 Purpose

Phishing triage is one of the most frequent Tier 1 SOC analyst tasks. PhishingDetector supports that workflow by enabling rapid, structured analysis of user-reported suspicious emails — without requiring manual header inspection, URL lookups, or DNS querying. Built to mirror the analytical process a trained analyst follows, and to produce documented IOCs suitable for ticket evidence.

---

## 🔍 Detection Modules

| Module | What It Checks | SOC Relevance |
|---|---|---|
| **Header Spoofing** | Mismatched From / Reply-To / Return-Path domains | Classic BEC indicator |
| **SPF / DKIM Failures** | DNS-based authentication header parsing | Failed auth = sender not authorized |
| **Suspicious URLs** | Malicious TLDs, IP-based URLs, URL shorteners | Legitimate services don't use raw IPs |
| **URL Obfuscation** | @ symbol abuse, href vs display text mismatch | Active deception — masks true destination |
| **Brand Impersonation** | PayPal, Amazon, Microsoft, IRS, banks | Sender domain doesn't match claimed org |
| **Urgency Language** | 25+ urgency trigger patterns | Psychological manipulation |
| **Sensitive Data Requests** | SSN, credit card, password, bank account keywords | Credential harvesting attempt |
| **Suspicious Attachments** | .exe, .zip, .ps1, .vbs, macro-enabled Office files | Malware delivery vectors |
| **Grammar Analysis** | Generic greetings, phishing language patterns | Supporting signal |

---

## 📊 Risk Scoring

9 detection modules calculate a weighted composite risk score from 0–100.

| Score | Verdict |
|---|---|
| 70–100 | 🔴 PHISHING |
| 40–69 | 🟡 SUSPICIOUS |
| 0–39 | 🟢 LIKELY SAFE |

**Higher-weight signals:**
- SPF/DKIM authentication failure (+30)
- Sensitive data requests (+35)
- IP-based URLs (+25)
- Reply-To / From domain mismatch (+25)

---

## 🧪 Test Case — Verified Results

A sample phishing email is included at `samples/fake_phishing.eml`.

**Result: 100/100 — PHISHING** with 12 threat indicators detected:

| Indicator | Finding |
|---|---|
| Header spoofing | Reply-To domain mismatch |
| SPF/DKIM | Authentication failure |
| IP-based URL | Raw IP address in link |
| Suspicious domain | .xyz TLD detected |
| Sensitive data request | SSN, credit card, bank account keywords |
| Brand impersonation | PayPal domain spoofing |
| Suspicious attachment | .exe file detected |
| Urgency language | Multiple high-confidence triggers |

---

## 🔵 SOC Analyst Workflow

1. User reports suspicious email → ticket created
2. Analyst pulls raw email headers and body
3. Pastes content into PhishingDetector dashboard
4. SPF/DKIM authentication results parsed automatically
5. URLs extracted → checked against TLD blocklist and IP pattern detection
6. Brand impersonation and Reply-To mismatch evaluated
7. Risk score and verdict returned → PHISHING / SUSPICIOUS / LIKELY SAFE
8. IOCs extracted and documented for ticket evidence
9. Analyst escalates confirmed phishing or closes false positive

---

## 🚀 Quick Start

```bash
git clone https://github.com/Lovedipsingh/Phishing-Detector
cd Phishing-Detector
pip install flask requests dnspython
python app.py
```

Open **http://localhost:5001** in your browser. Paste raw email content or upload a `.eml` file.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Detection Module |
|---|---|---|
| Phishing | T1566 | Full detection suite |
| Spearphishing Attachment | T1566.001 | Attachment detection |
| Spearphishing Link | T1566.002 | URL and obfuscation detection |
| Obtain Capabilities: Domains | T1583.001 | Suspicious TLD and domain spoofing |
| Impersonation | T1656 | Brand impersonation detection |

---

## 🏅 Skills Demonstrated

- Python email header parsing and regex-based detection
- Weighted risk scoring engine design
- Flask web application development
- IOC extraction and SOC triage workflow
- MITRE ATT&CK mapping

---

## 📁 Project Structure

```
Phishing-Detector/
├── app.py                    # Flask web server
├── analyzer.py               # Core phishing analysis engine
├── templates/
│   └── index.html            # SOC dashboard UI
├── docs/
│   └── triage-playbook.md    # SOC analyst triage playbook
├── samples/
│   └── fake_phishing.eml     # Test phishing email (100/100 score)
└── README.md
```

---

## 🛠️ Tech Stack

- **Backend** — Python 3, Flask
- **Analysis** — Custom regex engine, email header parsing, DNS-based SPF/DKIM inspection
- **Frontend** — HTML dashboard with live risk score and IOC display
- **Libraries** — `dnspython`, `requests`

---

*Built by [Lovedip Singh](https://github.com/Lovedipsingh) — SOC analyst portfolio project.*
*[LinkedIn](https://linkedin.com/in/lovedip-singh-76802a1a3) | [GitHub](https://github.com/Lovedipsingh)*
