#!/usr/bin/env python3
"""
Dr-Sayer with OOB Attack Support
Author: SayerLinux (SayerLinux@outlook.sa)
Extended version with Out-of-Band attack modules
"""

import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Any

# Import modules
from modules.sql_injection import SQLInjectionTester
from modules.xss_tester import XSSTester
from modules.log4j_tester import Log4jTester
from modules.waf_bypass import WAFSBypass
from modules.reporter import SecurityReporter
from modules.http_inspector import HttpInspector
from modules.oob_attacks_fixed import OOBAttackTester

class DrSayer:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "SayerLinux"
        self.email = "SayerLinux@outlook.sa"
        self.start_time = datetime.now()
        self.attack_surface_ar = None
        self.attack_vector_ar = None
        
        # Initialize modules
        self.sql_tester = SQLInjectionTester()
        self.xss_tester = XSSTester()
        self.log4j_tester = Log4jTester()
        self.waf_bypass = WAFSBypass()
        self.http_inspector = HttpInspector()
        self.oob_tester = OOBAttackTester()
        self.reporter = SecurityReporter()
        
        # Results storage
        self.findings = []
        
    def banner(self):
        """Display tool banner"""
        banner_text = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                            Dr-Sayer Security Tool                           ║
║                          Version {self.version} - By {self.author}                    ║
║                        Email: {self.email}                    ║
║                                                                              ║
║  ⚠️  WARNING: For authorized security testing only! Misuse is illegal! ⚠️  ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner_text)
    
    def run_sql_injection_tests(self, target_url: str, parameters: List[str] = None, oob_callback: str = None) -> Dict[str, Any]:
        """Run SQL injection tests with optional OOB support"""
        print(f"[*] Starting SQL Injection tests on {target_url}")
        
        # Configure OOB if callback provided
        if oob_callback:
            self.sql_tester.enable_oob = True
            self.sql_tester.oob_callback = oob_callback
            print(f"[*] OOB SQL injection testing enabled with callback: {oob_callback}")
        
        results = self.sql_tester.test_target(target_url, parameters)
        self.findings.extend(results.get('vulnerabilities', []))
        return results
    
    def run_xss_tests(self, target_url: str, forms: List[Dict] = None) -> Dict[str, Any]:
        """Run XSS tests"""
        print(f"[*] Starting XSS tests on {target_url}")
        results = self.xss_tester.test_target(target_url, forms)
        self.findings.extend(results.get('vulnerabilities', []))
        return results
    
    def run_log4j_tests(self, target_url: str, headers: List[str] = None) -> Dict[str, Any]:
        """Run Log4j vulnerability tests"""
        print(f"[*] Starting Log4j (CVE-2021-44228) tests on {target_url}")
        results = self.log4j_tester.test_target(target_url, headers)
        self.findings.extend(results.get('vulnerabilities', []))
        return results
    
    def run_waf_bypass_tests(self, target_url: str, payload: str) -> Dict[str, Any]:
        """Run WAF bypass tests"""
        print(f"[*] Starting WAF bypass tests on {target_url}")
        results = self.waf_bypass.test_bypass_techniques(target_url, payload)
        self.findings.extend(results.get('techniques', []))
        return results
    
    def run_http_inspector(self, target_url: str) -> Dict[str, Any]:
        """Run non-destructive HTTP headers and cookies inspection"""
        print(f"[*] Inspecting HTTP headers and cookies on {target_url}")
        results = self.http_inspector.test_target(target_url)
        self.findings.extend(results.get('vulnerabilities', []))
        return results
    
    def run_oob_attacks(self, target_url: str, callback_host: str) -> Dict[str, Any]:
        """Run Out-of-Band attacks (SSTI, XXE, SSRF)"""
        print(f"[*] Running Out-of-Band attacks on {target_url}")
        self.oob_tester.callback_host = callback_host
        results = self.oob_tester.test_target(target_url)
        self.findings.extend(results.get('vulnerabilities', []))
        return results
    
    def generate_report(self, output_format: str = "html", output_file: str = None) -> str:
        """Generate security testing report"""
        print(f"[*] Generating {output_format.upper()} report")
        report_path = self.reporter.generate_report(
            findings=self.findings,
            start_time=self.start_time,
            output_format=output_format,
            output_file=output_file,
            attack_meta={
                'attack_surface_ar': self.attack_surface_ar,
                'attack_vector_ar': self.attack_vector_ar
            }
        )
        return report_path
    
    def print_summary(self):
        """Print testing summary"""
        print("\n" + "="*60)
        print("SECURITY TESTING SUMMARY")
        print("="*60)
        print(f"Total vulnerabilities found: {len(self.findings)}")
        
        vuln_types = {}
        for finding in self.findings:
            vuln_type = finding.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        for vuln_type, count in vuln_types.items():
            print(f"  {vuln_type}: {count}")
        
        print(f"Testing duration: {datetime.now() - self.start_time}")
        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Dr-Sayer Security Testing Tool - For authorized testing only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dr-sayer-oob.py -u http://example.com --sql
  python dr-sayer-oob.py -u http://example.com --xss --log4j
  python dr-sayer-oob.py -u http://example.com --all --report html
  python dr-sayer-oob.py -u http://example.com --oob-attacks --oob-callback oob.example.com
        """
    )
    
    # Target options
    parser.add_argument('-u', '--url', required=True, help='Target URL for testing')
    parser.add_argument('--params', nargs='*', help='Parameters to test (for SQL injection)')
    
    # Test modules
    parser.add_argument('--sql', action='store_true', help='Run SQL injection tests')
    parser.add_argument('--xss', action='store_true', help='Run XSS tests')
    parser.add_argument('--log4j', action='store_true', help='Run Log4j vulnerability tests')
    parser.add_argument('--waf-bypass', action='store_true', help='Test WAF bypass techniques')
    parser.add_argument('--http-inspector', action='store_true', help='Inspect HTTP headers and cookies (non-destructive)')
    parser.add_argument('--oob-attacks', action='store_true', help='Run Out-of-Band attacks (SSTI, XXE, SSRF)')
    parser.add_argument('--all', action='store_true', help='Run all available tests')
    
    # OOB specific options
    parser.add_argument('--sql-oob', action='store_true', help='Enable out-of-band SQLi probes (requires --oob-callback)')
    parser.add_argument('--oob-callback', help='Callback host for OOB attacks (required for --oob-attacks and --sql-oob)')
    
    # Output options
    parser.add_argument('--report', choices=['html', 'json', 'txt'], default='html',
                       help='Report output format (default: html)')
    parser.add_argument('-o', '--output', help='Output file name for report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--attack-surface-ar', help='Arabic text for attack surface section')
    parser.add_argument('--attack-vector-ar', help='Arabic text for attack vector section')
    
    # Safety and legal notice
    parser.add_argument('--accept-risk', action='store_true', required=True,
                       help='Accept legal responsibility for using this tool')
    
    args = parser.parse_args()
    
    # Initialize tool
    tool = DrSayer()
    tool.banner()
    
    # Legal disclaimer
    print("\n⚠️  LEGAL DISCLAIMER ⚠️")
    print("This tool is for authorized security testing only.")
    print("You are responsible for ensuring you have proper authorization.")
    print("Misuse of this tool may violate applicable laws.")
    
    if not args.accept_risk:
        print("\n❌ You must accept the risk with --accept-risk flag")
        sys.exit(1)
    
    print(f"\n[*] Starting security testing on: {args.url}")
    
    tool.attack_surface_ar = args.attack_surface_ar
    tool.attack_vector_ar = args.attack_vector_ar
    
    # Configure OOB if needed
    oob_callback = None
    if args.sql_oob or args.oob_attacks:
        if not args.oob_callback:
            print("\n❌ --oob-callback is required when using --sql-oob or --oob-attacks")
            sys.exit(1)
        oob_callback = args.oob_callback
    
    try:
        # Run selected tests
        if args.all or args.sql:
            tool.run_sql_injection_tests(args.url, args.params, oob_callback if args.sql_oob else None)
        
        if args.all or args.xss:
            tool.run_xss_tests(args.url)
        
        if args.all or args.log4j:
            tool.run_log4j_tests(args.url)
        
        if args.all or args.waf_bypass:
            tool.run_waf_bypass_tests(args.url, "test")
        
        if args.all or args.http_inspector:
            tool.run_http_inspector(args.url)
        
        if args.all or args.oob_attacks:
            tool.run_oob_attacks(args.url, oob_callback)
        
        # Generate report
        report_path = tool.generate_report(args.report, args.output)
        tool.print_summary()
        
        print(f"\n✅ Report generated: {report_path}")
        print("✅ Security testing completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
        tool.print_summary()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()