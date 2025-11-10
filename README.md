# CAMERAVISION PRO - Advanced Network Camera Security Assessment Platform

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![AI](https://img.shields.io/badge/AI-Powered-purple.svg)

**Premium Camera Vulnerability Scanner & Security Testing Suite**

---

## 🚀 Overview

CAMERAVISION PRO is a next-generation security assessment platform combining AI/ML algorithms with comprehensive vulnerability scanning for network cameras and surveillance systems.

### Key Features

- 🤖 **AI-Powered Detection**: Machine learning anomaly detection using Isolation Forest
- 🔐 **Enterprise Security**: PBKDF2 encryption, GeoIP integration, secure credential storage
- 📊 **Professional Reports**: PDF, JSON, CSV, HTML with executive summaries
- 🌐 **Multi-Protocol**: HTTP/HTTPS, RTSP, RTMP, ONVIF support
- 🛡️ **CVE Database**: Automated vulnerability mapping (CVE-2021-36260, CVE-2018-9995)
- ⚡ **Async Scanning**: High-performance concurrent network scanning
- 🎯 **Risk Scoring**: AI-powered vulnerability risk assessment (0-10 scale)

---

## 📦 Installation

### Prerequisites
- Python 3.9+
- wkhtmltopdf (for PDF generation)
- GeoLite2 Database

### Quick Install

```bash
# Clone repository
git clone https://github.com/joyelkhan/CAMERAVISION-PRO.git
cd CAMERAVISION-PRO

# Install dependencies
pip install -r requirements.txt

# Download GeoLite2 database
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

# Run scanner
python cameravision-pro.py --help
```

---

## 🚀 Usage

```bash
# Basic scan
python cameravision-pro.py --target 192.168.1.100 --output pdf

# Network range scan
python cameravision-pro.py --target 192.168.1.0/24 --output json

# Stealth mode
python cameravision-pro.py --target 10.0.0.0/16 --stealth --threads 50

# All output formats
python cameravision-pro.py --target 192.168.1.1-192.168.1.254 --output all
```

### Command Line Arguments

```
--target TARGET       Target IP, range, or CIDR (required)
--output FORMAT       pdf, json, csv, html, all (default: pdf)
--config FILE         Custom configuration file
--stealth             Enable stealth mode
--threads N           Concurrent threads (default: 100)
--timeout N           Request timeout in seconds (default: 10)
```

---

## 🎯 Core Modules

### 1. AI & Machine Learning
```python
class AIMLDetector:
    - Isolation Forest anomaly detection
    - Vulnerability pattern recognition
    - Risk score prediction (0-10)
    - Configuration behavioral analysis
```

### 2. Security Manager
```python
class SecurityManager:
    - PBKDF2 key derivation (100k iterations)
    - Fernet symmetric encryption
    - GeoIP database integration
    - Secure credential storage
```

### 3. Network Scanner
```python
class AdvancedNetworkScanner:
    - Async port scanning (asyncio)
    - Multi-protocol detection
    - Service fingerprinting
    - CIDR range support
```

### 4. Vulnerability Assessor
```python
class VulnerabilityAssessor:
    - CVE database integration
    - Exploit database mapping
    - Authentication bypass testing
    - Protocol-specific vulnerabilities
```

### 5. Professional Reporter
```python
class ProfessionalReporter:
    - PDF generation (pdfkit)
    - Multi-format export
    - Custom templates
    - Executive summaries
```

---

## 📊 Report Examples

### PDF Report
- Executive summary with risk scores
- Detailed vulnerability findings
- CVE mappings with CVSS scores
- Remediation recommendations
- Color-coded severity levels

### JSON Report
```json
{
  "discovered_cameras": 15,
  "total_vulnerabilities": 47,
  "average_risk_score": 7.8,
  "assessment_results": [...]
}
```

---

## 🔧 Configuration

Create `cameravision.conf`:

```ini
[SCANNER]
max_threads = 100
request_timeout = 10
stealth_mode = true

[SECURITY]
enable_tor = false
verify_ssl = false
credential_storage = encrypted

[AI]
enable_ml_detection = true
anomaly_threshold = 0.75

[REPORTING]
report_format = pdf,json,csv
include_screenshots = true
```

---

## 🛡️ Security Features

- **Encryption**: PBKDF2 + Fernet for sensitive data
- **Stealth Mode**: Advanced evasion techniques
- **Proxy Support**: TOR and custom proxy integration
- **Rate Limiting**: Configurable request delays
- **Audit Logging**: Comprehensive activity tracking

---

## ⚠️ Legal Disclaimer

**CRITICAL**: This tool is for **authorized security testing only**.

✅ **Authorized Use:**
- Penetration testing with written permission
- Security research on owned systems
- Educational purposes in controlled environments

❌ **Prohibited:**
- Unauthorized network scanning
- Accessing systems without permission
- Any activity violating laws

**Unauthorized use may violate Computer Fraud and Abuse Act (CFAA) and similar laws worldwide, resulting in criminal prosecution.**

---

## 📁 Project Structure

```
CAMERAVISION-PRO/
├── cameravision-pro.py      # Main application
├── requirements.txt          # Dependencies
├── cameravision.conf         # Configuration
├── GeoLite2-City.mmdb       # GeoIP database
├── report_templates/         # Report templates
└── reports/                  # Generated reports
```

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Follow PEP 8 style guide
4. Add unit tests
5. Submit pull request

---

## 📞 Contact & Support

- **GitHub**: [joyelkhan](https://github.com/joyelkhan)
- **Repository**: [CAMERAVISION-PRO](https://github.com/joyelkhan/CAMERAVISION-PRO)
- **Issues**: [Report bugs](https://github.com/joyelkhan/CAMERAVISION-PRO/issues)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- Built with Python and modern security tools
- AI/ML powered by scikit-learn
- Encryption by cryptography library
- GeoIP data by MaxMind

---

**Made with ❤️ for Security Research & Education**

*CAMERAVISION PRO v2.0 - Production Ready Build*
