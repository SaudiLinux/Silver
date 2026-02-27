"""
Parameter Fuzzer Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
Performs real fuzzing of application parameters for hidden vulnerabilities
"""

import requests
import random
import string
import time
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode
import warnings

warnings.filterwarnings('ignore')

class ParameterFuzzer:
    """Real parameter fuzzing and discovery"""
    
    def __init__(self, timeout: int = 15):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = timeout
        
        # Common parameter names to test
        self.common_params = [
            'id', 'user', 'username', 'login', 'email', 'pass', 'password',
            'search', 'query', 'q', 'keyword', 'tag', 'sort', 'order',
            'page', 'limit', 'offset', 'skip', 'count', 'per_page',
            'admin', 'config', 'debug', 'mode', 'test', 'preview',
            'action', 'cmd', 'command', 'execute', 'eval', 'file',
            'path', 'url', 'redirect', 'return', 'callback', 'next',
            'token', 'key', 'api_key', 'secret', 'csrf', 'session',
            'hash', 'checksum', 'version', 'type', 'format', 'lang',
            'v', 'access', 'level', 'role', 'permission', 'status'
        ]
        
    def discover_parameters(self, url: str) -> Dict[str, Any]:
        """Discover hidden parameters"""
        findings = []
        parsed_url = urlparse(url)
        discovered_params = set()
        
        try:
            # Make request
            response = self.session.get(url, timeout=self.timeout, verify=False)
            original_length = len(response.text)
            
            # Test each common parameter
            for param in self.common_params:
                # Test with unique value
                test_value = f'dr-sayer-{random.randint(100000, 999999)}'
                test_params = parse_qs(parsed_url.query) if parsed_url.query else {}
                test_params[param] = [test_value]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += f"?{urlencode(test_params, doseq=True)}"
                
                try:
                    test_response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check if parameter is reflected
                    if test_value in test_response.text:
                        discovered_params.add(param)
                        findings.append({
                            'type': 'Parameter Discovery',
                            'parameter': param,
                            'status': 'Reflected',
                            'severity': 'Info',
                            'description': f'Parameter "{param}" is reflected in response',
                            'method': 'Direct Reflection'
                        })
                    
                    # Check for response differences
                    if abs(len(test_response.text) - original_length) > 100:
                        findings.append({
                            'type': 'Parameter Discovery',
                            'parameter': param,
                            'status': 'Processed',
                            'severity': 'Info',
                            'description': f'Parameter "{param}" affects response size',
                            'method': 'Response Differential'
                        })
                        
                except:
                    pass
        
        except:
            pass
        
        return {
            'discovered_parameters': list(discovered_params),
            'total_findings': len(findings),
            'findings': findings,
            'target': url
        }
    
    def test_parameter_pollution(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test for HTTP parameter pollution vulnerabilities"""
        findings = []
        parsed_url = urlparse(url)
        
        try:
            # Test with duplicate parameters
            test_params = parse_qs(parsed_url.query) if parsed_url.query else {}
            test_params[param] = ['value1', 'value2', 'value3']
            
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if test_params:
                test_url += f"?{urlencode(test_params, doseq=True)}"
            
            response = self.session.get(test_url, timeout=self.timeout, verify=False)
            
            # Check if multiple values are processed
            if 'value1' in response.text or 'value2' in response.text or 'value3' in response.text:
                findings.append({
                    'type': 'HTTP Parameter Pollution',
                    'parameter': param,
                    'severity': 'Medium',
                    'description': 'Application processes multiple parameter values',
                    'evidence': 'Multiple parameter values are reflected/processed',
                    'url': url
                })
        
        except:
            pass
        
        return findings
    
    def test_type_juggling(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test for type juggling/coercion vulnerabilities"""
        findings = []
        parsed_url = urlparse(url)
        
        # Test different types
        type_test_values = [
            ('0', 'Zero as string'),
            ('true', 'Boolean true'),
            ('false', 'Boolean false'),
            ('null', 'Null value'),
            ('[]', 'Empty array'),
            ('{}', 'Empty object'),
            ('1e999', 'Scientific notation overflow'),
            ('-1', 'Negative number'),
            ('0x0', 'Hex value'),
        ]
        
        for test_value, description in type_test_values:
            try:
                test_params = parse_qs(parsed_url.query) if parsed_url.query else {}
                test_params[param] = [test_value]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += f"?{urlencode(test_params, doseq=True)}"
                
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Look for unexpected behaviors
                if test_value in response.text or 'error' not in response.text.lower():
                    findings.append({
                        'type': 'Type Juggling',
                        'parameter': param,
                        'test_value': test_value,
                        'description': description,
                        'severity': 'Low',
                        'evidence': 'Unexpected type handling detected'
                    })
            except:
                pass
        
        return findings
