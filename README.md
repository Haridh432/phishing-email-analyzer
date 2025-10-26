# 🕵️‍♂️ Phishing Email Analyzer

A simple Python-based tool to analyze suspicious `.eml` email files for phishing indicators.  
It extracts URLs, domains, checks SPF/DKIM/DMARC presence, and produces readable and JSON reports.

---

## 🚀 Features
- Parse and extract URLs/domains from emails  
- Identify missing SPF, DKIM, or DMARC configurations  
- Detect IP-based URLs (common phishing sign)  
- Generate readable (`.txt`) and structured (`.json`) reports  

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/Phishing-Email-Analyzer.git
cd Phishing-Email-Analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
