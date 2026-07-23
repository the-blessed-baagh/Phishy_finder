🛡️ Phishy_finder
A Python-based security tool designed to detect, analyze, and flag suspicious or phishing URLs before they reach users.

📌 Overview
Phishy_finder helps threat hunters, security analysts, and users identify phishing links and malicious domains. By evaluating URL structures, domain age, SSL details, and querying reputation databases, it provides real-time risk scores for suspected links.

✨ Features
URL & Domain Parsing: Detects IP-based URLs, excessive subdomains, brand-impersonation keywords, and shortened links.

Reputation & Threat Scoring: Integrates with threat intelligence feeds (e.g., VirusTotal, AbuseIPDB, Safe Browsing).

SSL/TLS & WHOIS Inspection: Evaluates certificate validity, issuer, and domain registration age.

Batch Analysis: Scan single URLs via CLI or process bulk lists from CSV/TXT files.

Exportable Reports: Output scan findings in JSON or CSV format.

🚀 Quick Start
Prerequisites
Python 3.8+

pip package manager

Installation
Bash
# Clone the repository
git clone https://github.com/the-blessed-baagh/Phishy_finder.git

# Navigate into the project directory
cd Phishy_finder

# Install dependencies
pip install -r requirements.txt