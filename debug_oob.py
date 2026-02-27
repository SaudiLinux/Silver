#!/usr/bin/env python3
"""Debug script for OOB attacks"""

import sys
import traceback
from modules.oob_attacks_fixed import OOBAttackTester

def debug_oob():
    """Debug the OOB attacks"""
    try:
        print("[*] Creating OOBAttackTester...")
        tester = OOBAttackTester('oob.example.com')
        
        print("[*] Starting SSTI test...")
        
        # Test individual components
        print("[*] Testing SSTI payloads...")
        
        # Test freemarker payload specifically
        freemarker_payloads = tester.oob_payloads['ssti']['freemarker']
        print(f"[*] Found {len(freemarker_payloads)} freemarker payloads")
        
        for i, payload in enumerate(freemarker_payloads):
            try:
                print(f"[*] Testing freemarker payload {i+1}: {payload}")
                formatted_payload = payload.format(host='oob.example.com')
                print(f"[*] Formatted payload: {formatted_payload}")
            except Exception as e:
                print(f"[!] Error formatting payload {i+1}: {e}")
                traceback.print_exc()
        
        print("[*] Running full SSTI test...")
        result = tester.test_ssti('https://httpbin.org')
        print(f"[*] SSTI test completed. Found {len(result['vulnerabilities'])} findings")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    debug_oob()