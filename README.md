# 🔒 Dr-Sayer Security Testing Tool

**Author:** SayerLinux  
**Email:** SayerLinux@outlook.sa  
**Version:** 1.0.0  
**License:** Educational/Authorized Testing Only

> ⚠️ **CRITICAL LEGAL NOTICE:** This tool is for **authorized security testing only**. Misuse is **illegal** and may violate computer crime laws. You must have explicit written permission to test any target system.

## 🎯 Overview

**Dr-Sayer** is a comprehensive security testing tool designed for **authorized penetration testing** and security assessments. It provides advanced testing capabilities for common web application vulnerabilities with professional reporting features.

### 🌟 Key Features

#### 🔍 **Advanced Security Testing Modules**
- **SQL Injection Testing** - Database-specific payloads and detection methods
- **Cross-Site Scripting (XSS)** - Multiple context testing with payload variations  
- **Log4j Vulnerability (CVE-2021-44228)** - Specialized JNDI injection testing
- **WAF Bypass Techniques** - Advanced evasion and bypass methods
- **HTTP Inspector** - Non-destructive checks (CSP, HSTS, CORS, COOP, CORP, Permissions-Policy, cookies)
- **Out-of-Band (OOB) Attacks** - SSTI, XXE, and SSRF testing.

#### 📊 **Professional Reporting System**
- **HTML Reports** - Interactive dashboards with charts and statistics
- **JSON Reports** - Machine-readable format for tool integration
- **Text Reports** - Simple format for documentation and quick review

#### 🖥️ **User Interfaces**
- **Command-Line Interface (CLI):** For automation and advanced users.
- **Web-Based Graphical User Interface (GUI):** A modern, user-friendly interface for easy testing and report management.

---

## 🚀 Installation and Usage

### 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd Dr-Sayer
    ```

2.  **Install dependencies:**
    It is highly recommended to use a virtual environment.
    ```bash
    # Create and activate a virtual environment (optional but recommended)
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

    # Install the required packages
    pip install -r requirements.txt
    ```

### 🎯 Usage

Dr-Sayer can be run via its command-line interface or a modern web-based GUI.

#### 1. Web-Based GUI (Recommended)

The easiest way to use Dr-Sayer is through the web interface.

1.  **Start the web server:**
    ```bash
    python dr-sayer-web-gui.py
    ```

2.  **Open your browser:**
    Navigate to **[http://localhost:5000](http://localhost:5000)**.

3.  **Using the Interface:**
    -   Enter the target URL.
    -   Select the tests you want to run.
    -   Configure report options.
    -   Accept the legal disclaimer and start the test.
    -   View real-time progress and manage reports directly from the browser.

#### 2. Command-Line Interface (CLI)

For advanced users and automation, the CLI provides full control.

**⚠️ IMPORTANT:** You must have explicit authorization to test any target system. The `--accept-risk` flag is always required for CLI usage.

**Basic Examples:**
```bash
# Run all tests with an HTML report
python dr-sayer.py -u http://target.com --all --report html --accept-risk

# Test for specific vulnerabilities
python dr-sayer.py -u http://target.com --sql --xss --accept-risk

# Run an OOB attack test
python dr-sayer-oob-fixed.py -u http://target.com --oob-attacks --oob-callback your-callback.com --accept-risk
```

**Adding Arabic Context to Reports:**
```bash
python dr-sayer.py -u http://target.com --accept-risk \
  --attack-surface-ar "سطح الاستغلال: لوحة إدارة ويب" \
  --attack-vector-ar "متجه الهجوم: إرسال طلبات عبر الشبكة بقيم طويلة" \
  --report html -o report_ar.html
```

---
## 📋 Command Reference

### Required Parameters
- `-u, --url URL` - **Target URL for testing** (required)
- `--accept-risk` - **Accept legal responsibility** (required for ethical usage)

### Testing Modules
- `--sql` - **SQL injection testing** with database detection
- `--xss` - **Cross-site scripting testing** with multiple contexts
- `--log4j` - **Log4j vulnerability testing** (CVE-2021-44228)
- `--waf-bypass` - **WAF bypass technique testing**
- `--oob-attacks` - Run Out-of-Band attacks (SSTI, XXE, SSRF)
- `--all` - **Run all available tests**

### Output Options
- `--report {html,json,txt}` - **Report format** (default: html)
- `-o, --output FILENAME` - **Custom output filename**
- `-v, --verbose` - **Verbose output** for detailed logging

### Advanced Options
- `--params PARAM [PARAM...]` - **Specific parameters to test** (for SQL injection)
- `--attack-surface-ar TEXT` - **Arabic text for Attack Surface section**
- `--attack-vector-ar TEXT` - **Arabic text for Attack Vector section**
- `--sql-oob` - **Enable out-of-band SQLi probes** (non-destructive, requires callback)
- `--oob-callback HOST` - **Callback host** for OOB probes (e.g., collaborator.example.com)

---

## 🛡️ Legal and Ethical Usage

### ⚠️ **CRITICAL REQUIREMENTS**

1. **AUTHORIZATION REQUIRED** - You must have explicit written permission
2. **LEGAL RESPONSIBILITY** - Users accept all legal consequences
3. **ETHICAL USAGE ONLY** - No malicious or unauthorized testing
4. **RESPONSIBLE DISCLOSURE** - Report findings appropriately
5. **COMPLIANCE** - Follow all applicable laws and regulations

**By using this tool, you confirm that you:**
- Have explicit permission to test the target system
- Accept full legal responsibility for your actions
- Will follow responsible disclosure practices
- Understand the legal consequences of misuse

**Remember: With great power comes great responsibility. Use ethically and legally.**

---

**🔒 Dr-Sayer - Professional Security Testing for Authorized Users Only**
