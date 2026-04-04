# 🎣 PhishingDetector — Email Threat Analysis Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-black?style=flat-square&logo=flask)
![Security](https://img.shields.io/badge/Security-SOC%20Tool-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A Python-based phishing email analysis tool with a web dashboard — built for SOC Tier 1 analysts to triage suspicious emails, extract IOCs, and score phishing risk from 0–100. Includes a structured SOC triage playbook for analyst workflow documentation.

---

## 🎯 Purpose

Phishing triage is one of the most frequent Tier 1 SOC analyst tasks. PhishingDetector supports that workflow by enabling rapid, structured analysis of user-reported suspicious emails — without requiring manual header inspection, URL lookups, or DNS querying. Built to mirror the analytical process a trained analyst follows, and to produce documented IOCs suitable for ticket evidence.

---

## 🔍 What It Detects

| Detection Module | What It Checks | SOC Relevance |
|---|---|---|
| **Header Spoofing** | Mismatched From / Reply-To / Return-Path domains | Classic BEC indicator — sender identity is not what it claims |
| **SPF / DKIM Failures** | DNS-based authentication header parsing | Failed auth = sender not authorized by domain owner |
| **Suspicious URLs** | Malicious TLDs, IP-based URLs, URL shorteners | Legitimate services don't use raw IPs or .tk/.xyz domains |
| **URL Obfuscation** | @ symbol abuse, href vs display text mismatch | Active deception — display text masks actual destination |
| **Brand Impersonation** | PayPal, Amazon, Microsoft, IRS, banks | Sender domain doesn't match claimed organization |
| **Urgency Language** | 25+ urgency trigger patterns | Psychological manipulation — pressure to act without thinking |
| **Sensitive Data Requests** | SSN, credit card, password, bank account keywords | Immediate escalation trigger — credential harvesting attempt |
| **Suspicious Attachments** | .exe, .zip, .ps1, .vbs, macro-enabled Office files | Malware delivery vectors — should never arrive via unsolicited email |
| **Grammar and Salutation Analysis** | Generic greetings, phishing language patterns | Supporting signal — low confidence alone, high confidence combined |

---

## 🔬 How SPF / DKIM Detection Works

The tool extracts `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` headers from the raw email. It parses the SPF result field for `pass`, `fail`, `softfail`, or `neutral` outcomes and checks whether a valid DKIM signature is present and covers the `From` domain. A missing or failed SPF record combined with no valid DKIM signature is treated as a strong authentication failure — one of the highest-weighted signals in the risk score.

---

## 📊 Risk Scoring

The tool runs 9 detection modules and calculates a weighted composite risk score from 0–100.

**Higher-weight signals** (strong phishing indicators on their own):
- SPF/DKIM authentication failure
- Credential harvesting language (SSN, password, bank account requests)
- IP-based URLs in body
- Reply-To / From domain mismatch

**Supporting signals** (contribute to score in combination):
- Urgency language
- Suspicious TLDs
- Generic greetings
- Brand impersonation keywords

| Score | Verdict |
|---|---|
| 70–100 | 🔴 PHISHING |
| 40–69 | 🟡 SUSPICIOUS |
| 0–39 | 🟢 LIKELY SAFE |

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Detection Module |
|---|---|---|
| Phishing | T1566 | Full detection suite |
| Spearphishing Attachment | T1566.001 | Suspicious attachment detection |
| Spearphishing Link | T1566.002 | URL and obfuscation detection |
| Obtain Capabilities: Domains | T1583.001 | Suspicious TLD and domain spoofing detection |
| Impersonation | T1656 | Brand impersonation detection |

---

## 🔵 SOC Analyst Workflow

**Typical Tier 1 phishing triage scenario:**

1. User reports suspicious email → ticket created
2. Analyst pulls raw email headers and body
3. Pastes content into PhishingDetector dashboard
4. SPF/DKIM authentication results parsed automatically
5. URLs extracted → checked against TLD blocklist and IP pattern detection
6. Brand impersonation and Reply-To mismatch evaluated
7. Risk score and verdict returned → PHISHING / SUSPICIOUS / LIKELY SAFE
8. IOCs (IPs, domains, URLs) extracted and documented
9. Analyst escalates confirmed phishing or closes false positive with documented evidence

**Accompanying triage playbook** — a structured SOC analyst playbook documenting the step-by-step investigation process, escalation criteria, and evidence collection standards is included in `docs/triage-playbook.md`.

---

## 🧪 Test Case — Verified Results

A sample phishing email is included at `samples/fake_phishing.eml`.

**Expected result: 100/100 — PHISHING** with 12 threat indicators:

| Indicator | Finding |
|---|---|
| Header spoofing | Reply-To domain mismatch detected |
| SPF/DKIM | Authentication failure |
| IP-based URL | Raw IP address embedded in link |
| Suspicious domain | .xyz TLD detected |
| Sensitive data request | SSN, credit card, bank account keywords |
| Brand impersonation | PayPal domain spoofing |
| Suspicious attachment | .exe file detected |
| Urgency language | Multiple high-confidence triggers |

---

## 🚀 Quick Start

```bash
git clone https://github.com/Lovedipsingh/PhishingDetector
cd PhishingDetector
pip install flask requests dnspython
python app.py
```

Open **http://localhost:5001** in your browser. Paste raw email content or upload a `.eml` / `.txt` file.

---

## 🏗️ Project Structure

```
PhishingDetector/
├── app.py                    # Flask web server
├── analyzer.py               # Core phishing analysis engine
├── templates/
│   └── index.html            # SOC dashboard UI
├── docs/
│   └── triage-playbook.md    # SOC analyst triage playbook
├── uploads/                  # Temporary email storage
├── samples/
│   └── fake_phishing.eml     # Test phishing email (100/100 score)
└── README.md
```

---

## 🛠️ Tech Stack

- **Backend** — Python 3, Flask
- **Analysis** — Custom regex engine, email header parsing, DNS-based SPF/DKIM inspection
- **Reporting** — Live dashboard with risk score, verdict, and IOC extraction
- **Libraries** — `dnspython` for DNS lookups, `requests` for URL reputation checks

---

## 📄 License

MIT License — free to use and modify.

---

*Built by [Lovedip Singh](https://github.com/Lovedipsingh) — SOC analyst portfolio project.*  
*[LinkedIn](https://linkedin.com/in/lovedip-singh-76802a1a3) | [GitHub](https://github.com/Lovedipsingh)*
