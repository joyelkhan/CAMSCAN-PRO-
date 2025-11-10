# CAMXPLOIT ELITE - Advanced CCTV Security Assessment Suite

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Enterprise-Grade Camera Reconnaissance & Vulnerability Scanner**

</div>

---

## 🚀 Overview

CAMXPLOIT ELITE is a comprehensive security reconnaissance tool designed for researchers and security enthusiasts to identify exposed CCTV cameras and surveillance systems. This tool provides advanced scanning capabilities with a focus on security research and vulnerability assessment.

⚠️ **Disclaimer**: This tool is intended for educational and security research purposes only. Unauthorized scanning of systems you do not own is illegal. Use responsibly.

## 🆕 What's New in v3.0.0

- ✅ **Multi-Threaded Scanning**: 150+ threads for rapid port scanning
- ✅ **Enhanced Brand Detection**: Hikvision, Dahua, Axis, CP Plus, Sony, Bosch
- ✅ **CVE Database Integration**: Automated vulnerability checking
- ✅ **Live Stream Detection**: RTSP, HTTP, MJPEG stream discovery
- ✅ **IP Intelligence**: Geolocation with Google Maps/Earth integration
- ✅ **Credential Testing**: Smart rate-limited authentication testing
- ✅ **Endpoint Discovery**: Comprehensive API and path enumeration
- ✅ **Modern UI**: Colorful emoji-enhanced console output
- ✅ **Multiple Reports**: JSON export with detailed findings
- ✅ **Colorful Logging**: Professional console output with progress tracking
- ✅ **Statistics Dashboard**: Real-time scan metrics and performance data

## 🎯 Key Features

### 🔍 Advanced Detection
- **Multi-Brand Support**: Hikvision, Dahua, Axis, CP Plus, Sony, Bosch, and generic cameras
- **Smart Fingerprinting**: HTML/header/content analysis for accurate identification
- **Firmware Detection**: Extract version information for CVE mapping
- **Model Identification**: Precise camera model detection

### 🔐 Security Assessment
- **Default Credentials**: Comprehensive password database per brand
- **Authentication Analysis**: Basic Auth and Form-based login testing
- **CVE Database**: Automated vulnerability checking with NVD links
- **Smart Rate Limiting**: Responsible credential testing (0.05s delay)

### 📹 Stream Detection
- **RTSP Streams**: Automatic RTSP endpoint discovery on ports 554, 8554, 10554
- **HTTP Streams**: MJPEG, MPEG, H.264 stream detection
- **Multiple Protocols**: Support for RTSP, HTTP, RTMP
- **Content-Type Validation**: Smart stream verification

### 🌍 Intelligence Gathering
- **IP Geolocation**: City, region, country, timezone identification
- **ISP Information**: Organization and provider details
- **Google Maps/Earth**: Direct coordinate links for physical location
- **OSINT Links**: Shodan, Censys, Zoomeye integration
- **Google Dorking**: Automated dork suggestions

### ⚡ Performance
- **150 Concurrent Threads**: Fast multi-threaded scanning
- **100+ Ports**: Comprehensive CCTV port coverage
- **Smart Rate Limiting**: Configurable delays (default: 0.05s)
- **Optimized Timeouts**: Balanced speed vs accuracy (6s default)

### 📊 Reporting
- **JSON Export**: Structured data with scan metadata
- **Statistics Dashboard**: Real-time scan metrics
- **Detailed Findings**: Comprehensive security assessment
- **Interactive Prompts**: User-friendly scanning workflow

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/joyelkhan/CAMXPLOIT-ELITE.git
cd CAMXPLOIT-ELITE

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python camxploit-elite.py
```

### Dependencies
- `requests` - HTTP library
- `aiohttp` - Async HTTP client
- `urllib3` - HTTP client utility

## 🚀 Usage

### Interactive Mode
```bash
# Run the scanner
python camxploit-elite.py

# Enter target IP when prompted
[+] Enter IP address: 192.168.1.100
```

### Scanning Workflow

1. **IP Validation**: Validates target IP and checks if private
2. **OSINT Links**: Provides Shodan, Censys, Zoomeye search links
3. **Google Dorking**: Suggests relevant Google dorks
4. **IP Intelligence**: Gathers geolocation and ISP information
5. **Port Scanning**: Scans 100+ CCTV-specific ports
6. **Camera Detection**: Analyzes responses for camera indicators
7. **Authentication Check**: Identifies login pages
8. **Fingerprinting**: Detects brand, model, firmware
9. **Credential Testing**: Tests default credentials with rate limiting
10. **Stream Detection**: Discovers live video streams
11. **Report Generation**: Creates JSON report with findings
12. **Statistics**: Displays comprehensive scan statistics

### Configuration

You can modify scanner settings in the code:

```python
scanner = CamXploitElite(
    max_threads=150,  # Number of concurrent threads
    timeout=6,        # Connection timeout in seconds
    rate_limit=0.05   # Delay between requests in seconds
)
```

## 📊 Output Formats

### Markdown Report
Enterprise-grade report with:
- Camera details, model, and firmware
- Risk assessment scores with visual indicators
- Working credentials with security warnings
- Location information with ISP details
- Comprehensive vulnerability analysis
- Discovered endpoints and APIs
- Investigation links (Shodan, Google Dorking)
- Scan statistics dashboard

### JSON Report
Structured data format for:
- Automation and scripting
- Integration with other tools
- Data analysis and processing

## 📁 Project Structure

```
CAMXPLOIT-ELITE/
├── camxploit-elite.py          # Main scanner application
├── requirements.txt         # Python dependencies
├── README.md               # Documentation
├── LICENSE                 # MIT License
├── .gitignore             # Git ignore rules
└── camxploit_report_*.json # Generated scan reports
```

## 🔒 Security Features

- ⏱️ **Advanced Rate Limiting**: Configurable delays (0.01-1.0s) to avoid detection
- 🔄 **Smart Retry Logic**: 5-attempt retry with exponential backoff
- 🛡️ **SSL/TLS Support**: Full certificate handling and validation
- 🔐 **Safe Credential Testing**: Rate-limited with 50+ passwords per brand
- ✅ **Input Validation**: IP, CIDR, and network range validation
- 📝 **Colorful Logging**: Professional console output with progress bars
- 🎯 **Risk Scoring**: Automated 0-100 security risk assessment
- 🔧 **Exploit Framework**: Educational CVE validation (opt-in)

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is intended for:
- ✅ Security research
- ✅ Educational purposes
- ✅ Authorized penetration testing
- ✅ Vulnerability assessment on systems you own or have permission to test

**Usage Restrictions**:
- ❌ Only use on networks you own or have explicit written permission to test
- ❌ Comply with all applicable laws and regulations in your jurisdiction
- ❌ Do not use for unauthorized access or malicious activities
- ❌ Respect privacy and ethical boundaries

**The developers are not responsible for misuse of this tool. Users are solely responsible for their actions.**

## 🐛 Bug Reports & Features

Found a bug or have a feature request? Please open an issue on GitHub Issues.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add docstrings to all functions
- Test with multiple camera brands
- Update documentation as needed
- Respect rate limiting in tests

## 📞 Support

For questions, issues, or discussions:
- Open an issue on GitHub
- Check existing issues for solutions
- Read the documentation carefully

---

<div align="center">

**Built for security researchers by security researchers. Use responsibly.**

⭐ If you find this tool useful, please consider giving it a star!

</div>