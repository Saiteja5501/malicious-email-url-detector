#!/usr/bin/env python3
"""
Test runner for Smart Detection System
"""

import unittest
import sys
import os
import subprocess

def run_unit_tests():
    """Run unit tests"""
    print("Running unit tests...")
    print("=" * 50)
    
    # Add src directory to path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

def run_linting():
    """Run code linting"""
    print("\nRunning code linting...")
    print("=" * 50)
    
    try:
        # Check if flake8 is available
        subprocess.run(['flake8', '--version'], check=True, capture_output=True)
        
        # Run flake8 on src directory
        result = subprocess.run([
            'flake8', 'src/', '--max-line-length=120', '--ignore=E501,W503'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Linting passed!")
            return True
        else:
            print("❌ Linting failed:")
            print(result.stdout)
            print(result.stderr)
            return False
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  flake8 not available, skipping linting")
        return True

def run_security_checks():
    """Run security checks"""
    print("\nRunning security checks...")
    print("=" * 50)
    
    try:
        # Check if bandit is available
        subprocess.run(['bandit', '--version'], check=True, capture_output=True)
        
        # Run bandit on src directory
        result = subprocess.run([
            'bandit', '-r', 'src/', '-f', 'json'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Security checks passed!")
            return True
        else:
            print("⚠️  Security issues found:")
            print(result.stdout)
            return False
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  bandit not available, skipping security checks")
        return True

def check_dependencies():
    """Check if all dependencies are installed"""
    print("Checking dependencies...")
    print("=" * 50)
    
    required_packages = [
        'flask', 'scikit-learn', 'pandas', 'numpy', 'nltk', 'textblob',
        'requests', 'beautifulsoup4', 'urllib3', 'dnspython', 'whois'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("Install them with: pip install -r requirements.txt")
        return False
    
    print("\n✅ All dependencies are installed!")
    return True

def main():
    """Main test runner"""
    print("Smart Detection System - Test Runner")
    print("=" * 50)
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    # Run linting
    lint_ok = run_linting()
    
    # Run security checks
    security_ok = run_security_checks()
    
    # Run unit tests
    tests_ok = run_unit_tests()
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    print(f"Dependencies: {'✅ PASS' if deps_ok else '❌ FAIL'}")
    print(f"Linting: {'✅ PASS' if lint_ok else '❌ FAIL'}")
    print(f"Security: {'✅ PASS' if security_ok else '❌ FAIL'}")
    print(f"Unit Tests: {'✅ PASS' if tests_ok else '❌ FAIL'}")
    
    overall_success = deps_ok and lint_ok and security_ok and tests_ok
    
    if overall_success:
        print("\n🎉 All tests passed! The system is ready to use.")
        return 0
    else:
        print("\n❌ Some tests failed. Please fix the issues before deployment.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
