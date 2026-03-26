# 🎣 PhishingDetector — Email Threat Analysis Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-black?style=flat-square&logo=flask)
![Security](https://img.shields.io/badge/Security-SOC%20Tool-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A Python-based phishing email analysis tool with a dark web dashboard — built for SOC analysts to triage suspicious emails, extract IOCs, and score phishing risk from 0–100.

---

## 🖥️ Dashboard Preview

> Drag and drop an email → instant threat analysis with risk scoring and IOC extraction

---

## 🔍 What It Detects

| Check | Description |
|---|---|
| **Header Spoofing** | Mismatched From/Reply-To/Return-Path domains |
| **SPF/DKIM Failures** | Authentication header analysis |
| **Suspicious URLs** | Malicious TLDs, IP-based URLs, URL shorteners |
| **URL Obfuscation** | @ symbol abuse, mismatched href vs display text |
| **Brand Impersonation** | PayPal, Amazon, Microsoft, IRS, banks and more |
| **Urgency Language** | 25+ urgency trigger patterns |
| **Sensitive Data Requests** | SSN, credit card, password, bank account requests |
| **Suspicious Attachments** | .exe, .zip, .ps1, .vbs and macro-enabled files |
| **Poor Grammar** | Generic greetings and phishing language patterns |

---

## 🔵 SOC Analyst Use Case

Phishing triage is one of the most common Tier 1 SOC analyst tasks. PhishingDetector supports analyst workflows by enabling rapid analysis of suspicious emails reported by users — without requiring manual header inspection or URL lookup.

**Typical SOC phishing workflow:**

1. User reports suspicious email → ticket created in ticketing system
2. Analyst pulls raw email content → pastes into PhishingDetector
3. Tool extracts headers and checks SPF/DKIM authentication results
4. URLs extracted → checked against suspicious TLD and IP pattern database
5. Brand impersonation checked → flags if sender domain doesn't match claimed brand
6. Risk score reviewed → PHISHING / SUSPICIOUS / LIKELY SAFE verdict returned
7. IOCs documented → IPs, URLs, domains added to ticket as evidence
8. Analyst escalates confirmed phishing or closes false positive

**What PhishingDetector detects that matters in a SOC:**

| Indicator | Why It Matters |
|---|---|
| SPF/DKIM failures | Confirms sender authentication failed — strong phishing signal |
| Reply-To mismatch | Classic Business Email Compromise (BEC) indicator |
| IP-based URLs | Legitimate services never use raw IPs — strong IOC |
| Suspicious TLDs (.xyz, .tk, .pw) | Associated with malicious infrastructure |
| Brand impersonation | Sender domain doesn't match claimed organization |
| Credential harvesting language | SSN, password, credit card requests — immediate escalation trigger |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
git clone https://github.com/Lovedipsingh/PhishingDetector
cd PhishingDetector
pip install flask requests dnspython
python app.py
```

Open your browser at `http://localhost:5001`

---

## 🧪 Testing

A sample phishing email is included:

```
samples/fake_phishing.eml
```

Upload it or paste the contents to see the analyzer in action. Expected result: **100/100 PHISHING** score with 12 threat indicators detected including:
- Header spoofing (Reply-To domain mismatch)
- IP-based URL (raw IP address in link)
- Suspicious domain (.xyz TLD)
- Sensitive information request (SSN, credit card, bank account)
- Brand impersonation (PayPal)
- Suspicious attachment (.exe)
- High urgency language (multiple triggers)

---

## 🏗️ Project Structure

```
PhishingDetector/
├── app.py              # Flask web server
├── analyzer.py         # Core phishing analysis engine
├── templates/
│   └── index.html      # Dark SOC dashboard UI
├── uploads/            # Temporary email storage
├── samples/
│   └── fake_phishing.eml  # Test phishing email
└── README.md
```

---

## 🎯 How It Works

1. **Input** — Paste raw email content or upload .eml/.txt file
2. **Parse** — Extracts headers, URLs, and body content
3. **Analyze** — Runs 9 detection modules in parallel
4. **Score** — Calculates weighted risk score 0–100
5. **Report** — Displays verdict, flags, and extracted IOCs

### Risk Scoring

| Score | Verdict |
|---|---|
| 70–100 | 🔴 PHISHING |
| 40–69 | 🟡 SUSPICIOUS |
| 0–39 | 🟢 LIKELY SAFE |

---

## 🛠️ Tech Stack

- **Backend** — Python 3, Flask
- **Analysis** — Custom regex engine, header parsing, URL analysis
- **Frontend** — HTML5, CSS3, Vanilla JS
- **Fonts** — Share Tech Mono, Syne (Google Fonts)

---

## 👨‍💻 Author

**Lovedip Singh** — U.S. Army Veteran | Cybersecurity Analyst | Security+ | Network+

- GitHub: [github.com/Lovedipsingh](https://github.com/Lovedipsingh)
- LinkedIn: [linkedin.com/in/lovedip-singh-76802a1a3](https://linkedin.com/in/lovedip-singh-76802a1a3)
- Email: lovedip590@outlook.com

---

## 📄 License

MIT License — free to use and modify.
