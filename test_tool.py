#!/usr/bin/env python3
"""
Test script for Dr-Sayer Security Tool
Author: SayerLinux (SayerLinux@outlook.sa)
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from modules.sql_injection import SQLInjectionTester
        print("✅ SQL Injection module imported successfully")
    except ImportError as e:
        print(f"❌ SQL Injection module import failed: {e}")
        return False
    
    try:
        from modules.xss_tester import XSSTester
        print("✅ XSS Tester module imported successfully")
    except ImportError as e:
        print(f"❌ XSS Tester module import failed: {e}")
        return False
    
    try:
        from modules.log4j_tester import Log4jTester
        print("✅ Log4j Tester module imported successfully")
    except ImportError as e:
        print(f"❌ Log4j Tester module import failed: {e}")
        return False
    
    try:
        from modules.waf_bypass import WAFSBypass
        print("✅ WAF Bypass module imported successfully")
    except ImportError as e:
        print(f"❌ WAF Bypass module import failed: {e}")
        return False
    
    try:
        from modules.reporter import SecurityReporter
        print("✅ Reporter module imported successfully")
    except ImportError as e:
        print(f"❌ Reporter module import failed: {e}")
        return False
    
    try:
        # Import from the main script file
        import importlib.util
        spec = importlib.util.spec_from_file_location("dr_sayer", "dr-sayer.py")
        dr_sayer_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dr_sayer_module)
        DrSayer = dr_sayer_module.DrSayer
        print("✅ Main Dr-Sayer class imported successfully")
    except Exception as e:
        print(f"❌ Main Dr-Sayer class import failed: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality"""
    print("\\nTesting basic functionality...")
    
    try:
        # Test reporter
        from modules.reporter import SecurityReporter
        reporter = SecurityReporter()
        print("✅ Reporter initialized successfully")
        
        # Test main tool
        import importlib.util
        spec = importlib.util.spec_from_file_location("dr_sayer", "dr-sayer.py")
        dr_sayer_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dr_sayer_module)
        DrSayer = dr_sayer_module.DrSayer
        
        tool = DrSayer()
        print("✅ Dr-Sayer tool initialized successfully")
        
        # Test banner
        tool.banner()
        print("✅ Banner displayed successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Dr-Sayer Security Tool - Test Suite")
    print("=" * 50)
    
    # Test imports
    if not test_imports():
        print("\\n❌ Import tests failed. Please check dependencies.")
        return False
    
    # Test basic functionality
    if not test_basic_functionality():
        print("\\n❌ Basic functionality tests failed.")
        return False
    
    print("\\n✅ All tests passed! Dr-Sayer is ready to use.")
    print("\\nTo run the tool, use:")
    print("python dr-sayer.py -u <target_url> --accept-risk")
    print("\\nFor help:")
    print("python dr-sayer.py --help")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)