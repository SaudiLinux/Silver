"""
HTTP Inspector Module for Dr-Sayer
Author: SayerLinux (SayerLinux@outlook.sa)
Enhanced for Real Penetration Testing - Non-Destructive
"""

import re
import requests
import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')

class HttpInspector:
    """Non-destructive HTTP headers, SSL/TLS, and security configuration inspector"""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        self.security_findings = []

    def _add_finding(self, findings: List[Dict[str, Any]], severity: str, description: str,
                     evidence: str, location: str = 'Response Headers'):
        finding = {
            'type': 'HTTP Configuration Issue',
            'module': 'HTTP Inspector',
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'location': location
        }
        findings.append(finding)

    def analyze_security_headers(self, url: str, headers: Dict[str, str], is_https: bool,
                                 findings: List[Dict[str, Any]]):
        h = {k.lower(): v for k, v in headers.items()}

        if is_https and 'strict-transport-security' not in h:
            self._add_finding(findings, 'Medium',
                              'Missing Strict-Transport-Security (HSTS) header on HTTPS endpoint',
                              'Strict-Transport-Security: <missing>')

        csp = h.get('content-security-policy')
        if not csp:
            self._add_finding(findings, 'Medium',
                              'Missing Content-Security-Policy (CSP) header',
                              'Content-Security-Policy: <missing>')

        xfo = h.get('x-frame-options')
        if not xfo:
            self._add_finding(findings, 'Low',
                              'Missing X-Frame-Options header (clickjacking protection)',
                              'X-Frame-Options: <missing>')

        xcto = h.get('x-content-type-options')
        if xcto is None or xcto.lower() != 'nosniff':
            self._add_finding(findings, 'Low',
                              'Missing or weak X-Content-Type-Options header',
                              f"X-Content-Type-Options: {xcto or '<missing>'}")

        refpol = h.get('referrer-policy')
        if not refpol:
            self._add_finding(findings, 'Low',
                              'Missing Referrer-Policy header',
                              'Referrer-Policy: <missing>')

        coop = h.get('cross-origin-opener-policy')
        if not coop:
            self._add_finding(findings, 'Low',
                              'Missing Cross-Origin-Opener-Policy (COOP) header',
                              'Cross-Origin-Opener-Policy: <missing>')
        elif coop.lower() not in ['same-origin', 'same-origin-allow-popups']:
            self._add_finding(findings, 'Low',
                              'COOP value is not strict (prefer same-origin)',
                              f"Cross-Origin-Opener-Policy: {coop}")

        corp = h.get('cross-origin-resource-policy')
        if not corp:
            self._add_finding(findings, 'Low',
                              'Missing Cross-Origin-Resource-Policy (CORP) header',
                              'Cross-Origin-Resource-Policy: <missing>')
        elif corp.lower() not in ['same-origin', 'same-site']:
            self._add_finding(findings, 'Low',
                              'CORP value is permissive',
                              f"Cross-Origin-Resource-Policy: {corp}")

        permpol = h.get('permissions-policy') or h.get('feature-policy')
        if not permpol:
            self._add_finding(findings, 'Low',
                              'Missing Permissions-Policy header',
                              'Permissions-Policy: <missing>')

        aco = h.get('access-control-allow-origin')
        acc = h.get('access-control-allow-credentials')
        if aco:
            if aco == '*':
                if acc and acc.lower() == 'true':
                    self._add_finding(findings, 'High',
                                      'CORS allows any origin with credentials enabled',
                                      f"Access-Control-Allow-Origin: {aco}\nAccess-Control-Allow-Credentials: {acc}")
                else:
                    self._add_finding(findings, 'Medium',
                                      'CORS allows any origin (*)',
                                      f"Access-Control-Allow-Origin: {aco}")
            if aco == 'null' and acc and acc.lower() == 'true':
                self._add_finding(findings, 'Medium',
                                  'CORS allows null origin with credentials',
                                  f"Access-Control-Allow-Origin: {aco}\nAccess-Control-Allow-Credentials: {acc}")

        server = h.get('server')
        if server and re.search(r'\d', server):
            self._add_finding(findings, 'Low',
                              'Server header discloses version information',
                              f"Server: {server}")
        xpb = h.get('x-powered-by')
        if xpb and re.search(r'\d', xpb):
            self._add_finding(findings, 'Low',
                              'X-Powered-By header discloses technology/version',
                              f"X-Powered-By: {xpb}")

        cache = h.get('cache-control') or ''
        if 'set-cookie' in {k.lower() for k in headers.keys()}:
            if 'no-store' not in cache.lower():
                self._add_finding(findings, 'Info',
                                  'Cache-Control missing no-store while cookies are set (review context)',
                                  f"Cache-Control: {cache or '<missing>'}")

    def analyze_cookies(self, url: str, response: requests.Response, is_https: bool,
                        findings: List[Dict[str, Any]]):
        # Use Set-Cookie headers if available, else requests cookies
        set_cookie = response.headers.get('Set-Cookie', '')
        cookies = []
        if set_cookie:
            cookies = [c.strip() for c in set_cookie.split(',') if '=' in c]
        else:
            for c in response.cookies:
                parts = [f"{c.name}={c.value}"]
                if c.secure:
                    parts.append('Secure')
                if getattr(c, 'has_nonstandard_attr', None) and c.has_nonstandard_attr('HttpOnly'):
                    parts.append('HttpOnly')
                cookies.append('; '.join(parts))

        for raw in cookies:
            name_match = re.match(r'([^=]+)=', raw)
            name = name_match.group(1) if name_match else 'cookie'
            lower = raw.lower()

            if is_https and 'secure' not in lower:
                self._add_finding(findings, 'Medium',
                                  f'Cookie "{name}" missing Secure attribute over HTTPS',
                                  raw, location='Set-Cookie')
            if 'httponly' not in lower:
                self._add_finding(findings, 'Medium',
                                  f'Cookie "{name}" missing HttpOnly attribute',
                                  raw, location='Set-Cookie')
            samesite_match = re.search(r'samesite=([a-z]+)', lower)
            if not samesite_match:
                self._add_finding(findings, 'Low',
                                  f'Cookie "{name}" missing SameSite attribute',
                                  raw, location='Set-Cookie')
            else:
                if samesite_match.group(1) == 'none' and 'secure' not in lower:
                    self._add_finding(findings, 'High',
                                      f'Cookie "{name}" uses SameSite=None without Secure',
                                      raw, location='Set-Cookie')

    def test_target(self, target_url: str) -> Dict[str, Any]:
        """Comprehensive HTTP security inspection without destructive testing"""
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(target_url)
        is_https = parsed.scheme.lower() == 'https'
        
        try:
            # Make request with SSL verification disabled
            resp = self.session.get(target_url, allow_redirects=True, timeout=self.timeout, verify=False)
            
            # Check if redirected to HTTPS
            final_https = resp.url.lower().startswith('https')
            if not is_https and final_https:
                self._add_finding(findings, 'Info',
                                'HTTP endpoint redirects to HTTPS',
                                f'Redirect from {target_url} to {resp.url}')
            
            # Analyze security headers
            self.analyze_security_headers(target_url, resp.headers, is_https or final_https, findings)
            
            # Analyze cookies
            self.analyze_cookies(target_url, resp, is_https or final_https, findings)
            
            # Check SSL/TLS configuration if HTTPS
            if is_https or final_https:
                host = parsed.hostname or urlparse(resp.url).hostname
                self.analyze_ssl_tls(host, findings)
            
            # Check for information disclosure
            self.check_information_disclosure(resp, findings)
            
            # Check for deprecated protocols/features
            self.check_deprecated_features(resp.headers, findings)
            
            return {
                'target': target_url,
                'final_url': resp.url,
                'status_code': resp.status_code,
                'headers_count': len(resp.headers),
                'vulnerabilities': findings,
                'response_time': resp.elapsed.total_seconds(),
                'is_https': is_https or final_https,
                'detection_method': 'HTTP Analysis'
            }
            
        except requests.exceptions.Timeout:
            self._add_finding(findings, 'Info', 'Request timeout during HTTP inspection',
                            f'Timeout after {self.timeout}s')
        except requests.exceptions.ConnectionError:
            self._add_finding(findings, 'Info', 'Connection failed',
                            'Could not reach target')
        except requests.exceptions.RequestException as e:
            self._add_finding(findings, 'Info', 'Request failed during HTTP inspection', str(e))
        
        return {
            'target': target_url,
            'vulnerabilities': findings,
            'error': 'Connection failed',
            'detection_method': 'HTTP Analysis'
        }
    
    def analyze_ssl_tls(self, hostname: str, findings: List[Dict[str, Any]]):
        """Analyze SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check SSL/TLS version
                    if protocol_version in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._add_finding(findings, 'High',
                                        f'{protocol_version} is deprecated and vulnerable',
                                        f'Protocol: {protocol_version}',
                                        'SSL/TLS Configuration')
                    elif protocol_version == 'TLSv1.2':
                        self._add_finding(findings, 'Info',
                                        'Uses TLSv1.2 (should upgrade to TLSv1.3)',
                                        f'Protocol: {protocol_version}',
                                        'SSL/TLS Configuration')
                    
                    # Check cipher strength
                    if cipher and 'EXPORT' in cipher[0]:
                        self._add_finding(findings, 'Critical',
                                        'Weak export cipher suite detected',
                                        f'Cipher: {cipher[0]}',
                                        'SSL/TLS Configuration')
                    elif cipher and 'RC4' in cipher[0]:
                        self._add_finding(findings, 'High',
                                        'RC4 cipher detected (weak)',
                                        f'Cipher: {cipher[0]}',
                                        'SSL/TLS Configuration')
                    
        except Exception as e:
            self._add_finding(findings, 'Info',
                            'Could not analyze SSL/TLS configuration',
                            str(e),
                            'SSL/TLS Configuration')
    
    def check_information_disclosure(self, response: requests.Response, findings: List[Dict[str, Any]]):
        """Check for information disclosure vulnerabilities"""
        headers = response.headers
        
        # Directory listing
        if '<!DOCTYPE' in response.text and 'Index of' in response.text:
            self._add_finding(findings, 'High',
                            'Directory listing enabled',
                            'Application exposes directory contents',
                            'Content Analysis')
        
        # Check for sensitive comments
        if '<!--' in response.text:
            comments = re.findall(r'<!--(.+?)-->', response.text, re.DOTALL)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ['password', 'api', 'key', 'secret', 'token']):
                    self._add_finding(findings, 'Medium',
                                    'Sensitive information in HTML comments',
                                    f'Comment: {comment[:100].strip()}...',
                                    'Source Code Analysis')
                    break
    
    def check_deprecated_features(self, headers: Dict, findings: List[Dict[str, Any]]):
        """Check for deprecated or insecure features"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for X-XSS-Protection (deprecated but still useful)
        if 'x-xss-protection' not in headers_lower:
            self._add_finding(findings, 'Low',
                            'X-XSS-Protection header missing (legacy protection)',
                            'X-XSS-Protection: <missing>',
                            'Deprecated Features')
        
        # Check for X-UA-Compatible
        if 'x-ua-compatible' in headers_lower:
            self._add_finding(findings, 'Info',
                            'X-UA-Compatible header present',
                            f'Value: {headers_lower["x-ua-compatible"]}',
                            'Deprecated Features')
    
