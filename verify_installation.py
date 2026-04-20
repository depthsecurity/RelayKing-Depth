#!/usr/bin/env python3
"""
RelayKing Installation Verification Script
Checks that all dependencies are installed and modules can be imported
"""

import sys
import importlib

def check_python_version():
    """Check Python version is 3.8+"""
    print("[*] Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"[!] ERROR: Python 3.8+ required, found {version.major}.{version.minor}")
        return False
    print(f"[+] Python {version.major}.{version.minor}.{version.micro} OK")
    return True

def check_dependencies():
    """Check required Python packages"""
    print("\n[*] Checking dependencies...")

    dependencies = {
        'impacket': 'Impacket (SMB, LDAP, MSSQL protocols)',
        'requests': 'Requests (HTTP/HTTPS)',
        'requests_ntlm': 'Requests-NTLM (NTLM auth for HTTP)',
        'ldap3': 'LDAP3 (LDAP operations)',
        'dns.resolver': 'dnspython (DNS resolution)',
        'pyasn1': 'PyASN1 (ASN.1 encoding)',
        'urllib3': 'urllib3 (HTTP client)',
    }

    all_ok = True
    for module, description in dependencies.items():
        try:
            importlib.import_module(module)
            print(f"[+] {description}: OK")
        except ImportError:
            print(f"[!] {description}: MISSING")
            all_ok = False

    return all_ok

def check_modules():
    """Check RelayKing modules can be imported"""
    print("\n[*] Checking RelayKing modules...")

    modules = [
        'core.banner',
        'core.config',
        'core.target_parser',
        'core.scanner',
        'core.relay_analyzer',
        'protocols.base_detector',
        'protocols.smb_detector',
        'protocols.http_detector',
        'protocols.ldap_detector',
        'protocols.mssql_detector',
        'protocols.additional_detectors',
        'detectors.webdav_detector',
        'detectors.ntlm_reflection',
        'detectors.coercion',
        'output.formatters',
    ]

    all_ok = True
    for module in modules:
        try:
            importlib.import_module(module)
            print(f"[+] {module}: OK")
        except ImportError as e:
            print(f"[!] {module}: FAILED - {e}")
            all_ok = False

    return all_ok

def check_syntax():
    """Check syntax of all Python files"""
    print("\n[*] Checking Python syntax...")

    import ast
    import os

    all_ok = True
    for root, dirs, files in os.walk('.'):
        # Skip __pycache__ and venv directories
        dirs[:] = [d for d in dirs if d not in ['__pycache__', 'venv', 'env', '.git']]

        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        ast.parse(f.read())
                except SyntaxError as e:
                    print(f"[!] Syntax error in {filepath}: {e}")
                    all_ok = False

    if all_ok:
        print("[+] All Python files have valid syntax")

    return all_ok

def main():
    """Run all verification checks"""
    print("=" * 80)
    print("RelayKing Installation Verification")
    print("=" * 80)

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Modules", check_modules),
        ("Syntax", check_syntax),
    ]

    results = {}
    for name, check_func in checks:
        results[name] = check_func()

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    all_passed = all(results.values())

    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        symbol = "[+]" if passed else "[!]"
        print(f"{symbol} {name}: {status}")

    print("=" * 80)

    if all_passed:
        print("\n[+] All checks passed! RelayKing is ready to use.")
        print("\nQuick start:")
        print("  python3 relayking.py --help")
        print("  python3 relayking.py -u user -p password -d domain.local --audit")
        return 0
    else:
        print("\n[!] Some checks failed. Please install missing dependencies:")
        print("  pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
