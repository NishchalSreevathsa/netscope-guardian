# 🛡️ NetScope Guardian - AI-Powered Browser Threat Contextualizer

[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?style=flat-square&logo=google-chrome)](https://chrome.google.com)
[![Gemini AI](https://img.shields.io/badge/Powered%20by-Gemini%202.0-4285F4?style=flat-square)](https://ai.google.dev/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

> **AI-powered cybersecurity threat analysis directly in your browser. Real-time threat intelligence with natural language explanations using Google Gemini Flash 2.0.**

---

## 🎯 **Project Overview**

**NetScope Guardian** is a cutting-edge Chrome extension that revolutionizes browser security analysis by combining real-time threat intelligence with advanced AI capabilities. Built with **Google Gemini Flash (Latest)**, it provides instant, contextual security assessments for any web resource—transforming complex threat data into actionable insights that anyone can understand.

### **The Problem We Solve**

In today's digital landscape:
- 🔴 **Security analysts** are overwhelmed by raw threat data without context
- 🔴 **Junior analysts** struggle to understand what makes indicators dangerous
- 🔴 **Average users** have no way to assess website security before interacting
- 🔴 **Organizations** lack real-time, browser-based security awareness tools

### **Our Solution**

NetScope Guardian bridges the gap between raw security data and actionable intelligence by:
- ✅ Providing **AI-powered explanations** in plain English
- ✅ Offering **instant threat analysis** for any IP, domain, URL, or hash
- ✅ Evaluating **website security posture** with one click
- ✅ Monitoring **real-time network activity** for suspicious patterns
- ✅ Integrating data from **VirusTotal** and **AbuseIPDB** for comprehensive analysis

---

## 🚀 **Key Features**

### 🤖 **AI-Powered Analysis**
- **Google Gemini Flash (Latest) Integration** - Latest AI model for fast, accurate threat analysis
- **Natural Language Explanations** - Complex security data explained in simple terms
- **Contextual Intelligence** - Understanding of current threat landscape and attack patterns
- **Educational Insights** - Learn *why* something is dangerous, not just *that* it is

### 🎯 **Real-Time Threat Intelligence**
- **Right-Click Analysis** - Instantly analyze any IP, domain, URL, email, or file hash
- **Multi-Source Reputation** - Aggregates data from VirusTotal, AbuseIPDB, and threat feeds
- **Smart Risk Scoring** - AI-powered classification: CLEAN, LOW, MEDIUM, HIGH, CRITICAL
- **Historical Context** - See how indicators have been used in past attacks

### 🔒 **Security Headers Assessment**
- **Comprehensive Evaluation** - Analyzes 6 critical HTTP security headers
- **Security Score** - 0-100 rating of website security posture
- **Missing Header Detection** - Identifies security gaps with recommendations
- **AI Explanations** - Understand what each header does and why it matters

### 🌐 **Network Monitoring**
- **Real-Time Traffic Analysis** - Monitor all network requests from current page
- **Behavioral Detection** - Identify C2 beacons, data exfiltration, malicious scripts
- **Suspicious Pattern Recognition** - Flag credential harvesting, keyloggers, and more
- **Privacy-First Design** - All monitoring happens locally, no data collection

### 📊 **Professional Interface**
- **Dark Theme UI** - Modern cybersecurity aesthetic
- **Expandable Details** - Drill down into technical threat data
- **Mitigation Recommendations** - Actionable steps for each threat
- **External Integration** - Quick links to VirusTotal and AbuseIPDB

---

## 🔐 **Security & Privacy**

### **Privacy-First Design**
- ✅ **Local Processing** - All analysis happens locally or via your private backend
- ✅ **No Data Collection** - Extension doesn't collect or store browsing history
- ✅ **Minimal Permissions** - Only requests necessary Chrome API access
- ✅ **No Telemetry** - Zero tracking or analytics
- ✅ **Open Source** - Full transparency of code and operations

### **Security Best Practices**
- ✅ **Input Validation** - All user inputs sanitized and validated
- ✅ **CSP Compliant** - Content Security Policy enforced
- ✅ **Rate Limiting** - Backend API protected from abuse
- ✅ **HTTPS Only** - Secure communication for production deployment
- ✅ **API Key Protection** - Keys stored in environment variables only

---

## 🎓 **Use Cases**

### **For Security Analysts**
- **Rapid Triage** - Quickly assess indicators during incident response
- **Context Generation** - Get AI explanations to include in reports
- **Training Tool** - Learn about threats through natural language descriptions
- **Time Savings** - Reduce manual lookups across multiple tools

### **For Organizations**
- **Security Awareness** - Educate employees about web threats in real-time
- **Phishing Prevention** - Analyze suspicious emails and links before clicking
- **Supply Chain Security** - Verify external scripts and resources
- **Compliance** - Assess vendor websites for security compliance

### **For Developers**
- **Security Testing** - Evaluate security headers during development
- **Code Review** - Check external dependencies and APIs
- **Learning Resource** - Understand security best practices
- **Bug Bounty Hunting** - Identify security misconfigurations

### **For Everyone**
- **Safe Browsing** - Check website security before entering credentials
- **Phishing Detection** - Verify suspicious links and emails
- **Education** - Learn about cybersecurity threats
- **Peace of Mind** - Browse with confidence

---

## 🌟 **Real-World Impact**

### **Industry Benefits**

**For SOC Teams:**
- Reduces alert fatigue by providing context
- Speeds up incident response
- Improves analyst training and knowledge retention
- Facilitates better communication with non-technical stakeholders

**For Enterprises:**
- Reduces successful phishing attacks 
- Increases security awareness across all departments
- Provides measurable security posture improvements
- Enables proactive threat hunting

**For Individuals:**
- Protects against credential theft and malware
- Prevents financial fraud and identity theft
- Empowers users to make informed security decisions
- Builds cybersecurity awareness

---

## 📈 **Threat Score Meanings**

| Score | Indicator | Meaning | Action |
|-------|-----------|---------|--------|
| **CLEAN** | 🟢 | No threats detected | Safe to interact |
| **LOW** | 🟡 | Minor concerns | Proceed with caution |
| **MEDIUM** | 🟠 | Suspicious patterns | Investigate further |
| **HIGH** | 🔴 | Known malicious | Avoid/block |
| **CRITICAL** | 🚨 | Actively dangerous | Block immediately |

---

## 🏗️ **Technical Architecture**

### **Frontend (Chrome Extension)**
```
Manifest V3 Standard
├── Background Service Worker (background.js)
│   ├── Context menu handlers
│   ├── Network request monitoring
│   └── Message passing coordination
├── Content Scripts (content.js)
│   └── Page interaction and indicator detection
├── Popup Interface (popup/)
│   └── Quick access controls
└── Sidebar Dashboard (sidebar/)
    └── Full analysis interface
```

### **Backend (Python API)**
```
FastAPI Framework
├── main.py - API server
├── Google Gemini Integration
│   ├── Threat indicator analysis
│   ├── Security headers evaluation
│   └── Natural language generation
├── Threat Intelligence
│   ├── Pattern detection
│   ├── Reputation scoring
│   └── IOC classification
└── RESTful Endpoints
    ├── /threat-summary
    ├── /headers
    └── /network-audit
```

---

## 🛠️ **Technology Stack**

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Frontend** | JavaScript ES6+ | - | Extension logic and UI |
| **Extension API** | Chrome Manifest V3 | 3.0 | Browser integration |
| **Backend** | Python | 3.9+ | API server |
| **Web Framework** | FastAPI | 0.104+ | RESTful API |
| **AI Engine** | Google Gemini | Flash 2.0 | Natural language analysis |
| **HTTP Client** | httpx | 0.25+ | Async requests |
| **Data Validation** | Pydantic | 2.5+ | Request/response models |
| **ASGI Server** | uvicorn | 0.24+ | Production server |

---

## 📦 **Installation**

### **Prerequisites**
- Chrome Browser (v88+)
- Python 3.9 or higher
- Google Gemini API Key ([Get one here](https://aistudio.google.com/app/apikey))

### **Step 1: Clone Repository**
```bash
git clone https://github.com/yourusername/netscope-guardian.git
cd netscope-guardian
```

### **Step 2: Backend Setup**
```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Add your Gemini API key to .env
# GEMINI_API_KEY=your-actual-api-key-here
```

### **Step 3: Install Chrome Extension**
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **"Developer mode"** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `netscope-guardian` folder
5. Extension should appear in your toolbar

### **Step 4: Start the Backend**
```bash
cd backend
python main.py
```

You should see:
```
🛡️  NetScope Guardian Backend Starting

🚀 Server: http://127.0.0.1:8000
🤖 Gemini AI: ✅ Connected
🔧 Debug Mode: ❌ Disabled
```

---

## 🎮 **Usage Guide**

### **Right-Click Analysis** (Primary Feature)
1. Visit any webpage
2. Highlight an IP address, domain, email, or URL
3. Right-click → **"🛡️ Analyze with NetScope Guardian"**
4. Dashboard opens with complete AI analysis

### **Security Headers Analysis**
1. Visit any website (e.g., google.com)
2. Click extension icon
3. Click **"Analyze Page"**
4. View security score and header analysis

### **Quick Scan**
1. Click extension icon
2. Click **"Quick Scan"**
3. Extension finds all indicators on current page
4. Shows count of IPs, domains, emails, and hashes found

### **Manual Search**
1. Click **"Open Dashboard"**
2. Enter any indicator in search box
3. View comprehensive AI-powered analysis

### **Network Monitoring**
1. Open dashboard
2. Click **"Network"** tab
3. View real-time requests and suspicious activity

---

## 📊 **Python Packages Required**

### **Core Dependencies**
```
fastapi==0.104.1          # Web framework
uvicorn[standard]==0.24.0 # ASGI server
google-generativeai==0.3.2 # Gemini AI SDK
httpx==0.25.2             # Async HTTP client
pydantic==2.5.0           # Data validation
python-multipart==0.0.6   # Form data support
python-dotenv==1.0.0      # Environment variables
```

### **Optional Dependencies**
```
ipaddress==1.0.23         # IP address validation
dnspython==2.4.2          # DNS resolution
validators==0.22.0        # Input validation
aiofiles==23.2.1          # Async file operations
```

### **Installation**
```bash
pip install -r requirements.txt
```

---

## 🚀 **Future Enhancements**

- [ ] Integration with enterprise SIEM platforms
- [ ] Machine learning-based anomaly detection
- [ ] Multi-language support
- [ ] Custom threat intelligence feed integration
- [ ] Advanced network flow analysis
- [ ] Mobile browser support
- [ ] Team collaboration features
- [ ] Threat hunting workspace

---

## 🤝 **Contributing**

We welcome contributions!

### **Development Setup**
```bash
# Fork and clone
git clone https://github.com/yourusername/netscope-guardian.git

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
# Commit and push
git push origin feature/amazing-feature

# Open Pull Request
```

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE] file for details.

---

## 🙏 **Acknowledgments**

- **Google Gemini Team** - For providing the incredible AI capabilities
- **FastAPI Community** - For the excellent web framework
- **Chrome Extensions Team** - For the robust extension platform
- **Cybersecurity Community** - For threat intelligence and feedback

---

## ⭐ **Star History**

If you find this project useful, please consider giving it a star on GitHub!

---

**Built with ❤️ for the cybersecurity community**

*Making the web safer, one analysis at a time.* 🛡️

---

## 📊 **Project Stats**

- **Lines of Code**: ~3,500+
- **Languages**: JavaScript, Python, HTML, CSS
- **API Endpoints**: 3
- **Chrome Permissions**: 6 (minimal)
- **Dependencies**: 10 (carefully selected)
- **Development Time**: Academic project
- **License**: MIT (Open Source)

---

**NetScope Guardian** - Empowering users with AI-driven security insights. 🚀🛡️
