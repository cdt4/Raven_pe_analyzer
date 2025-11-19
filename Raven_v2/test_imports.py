#!/usr/bin/env python3
"""
Quick test to verify all modules import correctly
"""
import sys

def test_imports():
    """Test that all core modules can be imported"""
    tests = []
    
    # Test main package
    try:
        from raven import PEAnalyzer
        tests.append(("raven package", True, None))
    except Exception as e:
        tests.append(("raven package", False, str(e)))
    
    # Test core modules
    try:
        from raven.core import (calculate_entropy, classify_string, 
                                calculate_risk_level, find_packer_signatures)
        tests.append(("raven.core", True, None))
    except Exception as e:
        tests.append(("raven.core", False, str(e)))
    
    # Test parsing modules
    try:
        from raven.parsing import (load_pe_file, parse_sections, 
                                   parse_imports, parse_exports)
        tests.append(("raven.parsing", True, None))
    except Exception as e:
        tests.append(("raven.parsing", False, str(e)))
    
    # Test disasm module
    try:
        from raven.disasm import CodeDisassembler
        tests.append(("raven.disasm", True, None))
    except Exception as e:
        tests.append(("raven.disasm", False, str(e)))
    
    # Test reporting module
    try:
        from raven.reporting import (generate_text_report, generate_json_report, 
                                     generate_html_report)
        tests.append(("raven.reporting", True, None))
    except Exception as e:
        tests.append(("raven.reporting", False, str(e)))
    
    # Print results
    print("=" * 60)
    print("RAVEN MODULE IMPORT TEST")
    print("=" * 60)
    
    all_passed = True
    for name, passed, error in tests:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:8} - {name}")
        if error:
            print(f"         Error: {error}")
            all_passed = False
    
    print("=" * 60)
    
    if all_passed:
        print("✓ All imports successful!")
        return 0
    else:
        print("✗ Some imports failed - check dependencies")
        return 1

if __name__ == "__main__":
    sys.exit(test_imports())
