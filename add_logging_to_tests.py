#!/usr/bin/env python3
"""
Add comprehensive logging to all test files in Utils/Tests directory.
This script implements the exact logging pattern required by the ShadowStrike project.
"""

import re
import os
from pathlib import Path

# Test files that need logging enhancement
TEST_FILES = [
    "CompressionUtils_Tests.cpp",
    "CryptoUtils_Tests.cpp",
    "FileUtilsTests.cpp",
    "HashUtils_Tests.cpp",
    "JSONUtils_Tests.cpp",
    "MemoryUtils_Tests.cpp",
    "NetworkUtils_Tests.cpp",
    "ProcessUtils_Tests.cpp",
    "RegistryUtilsTests.cpp",
    "SystemUtils_Tests.cpp",
    "ThreadPool_Tests.cpp",
    "XMLUtils_Tests.cpp",
]

TEST_DIR = Path("c:\\Users\\RTX40\\source\\repos\\vscode\\ShadowStrike\\ShadowStrike\\tests\\unit\\Utils")

def extract_test_class_name(content):
    """Extract the test fixture class name."""
    match = re.search(r'class\s+(\w+)\s*:\s*public\s*::testing::Test', content)
    if match:
        return match.group(1)
    return None

def extract_filename_prefix(filename):
    """Extract the logging category from filename (e.g., 'CryptoUtils_Tests' from 'CryptoUtils_Tests.cpp')."""
    return filename.replace('.cpp', '')

def add_logging_to_test_function(test_func, test_name, filename_prefix):
    """Add logging to a single test function."""
    # Extract function body
    lines = test_func.split('\n')
    
    # Find the opening brace of the test
    brace_idx = -1
    for i, line in enumerate(lines):
        if '{' in line:
            brace_idx = i
            break
    
    if brace_idx == -1:
        return test_func
    
    # Check if logging is already present
    func_body = '\n'.join(lines[brace_idx+1:])
    if 'SS_LOG_INFO' in func_body and f'[{test_name}]' in func_body:
        return test_func  # Already has logging
    
    # Insert SS_LOG_INFO after opening brace
    indent = "    "
    log_line = f'{indent}SS_LOG_INFO(L"{filename_prefix}", L"[{test_name}] Testing...");'
    
    lines.insert(brace_idx + 1, log_line)
    
    return '\n'.join(lines)

def process_file(filepath):
    """Process a single test file and add logging."""
    if not filepath.exists():
        print(f"  WARNING: File not found: {filepath}")
        return False
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    filename_prefix = extract_filename_prefix(filepath.name)
    
    # Find all TEST_F and TEST( functions
    # Pattern: TEST_F(ClassName, TestName) or TEST(ClassName, TestName)
    pattern = r'TEST(?:_F)?\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{'
    
    matches = list(re.finditer(pattern, content))
    
    if not matches:
        print(f"  No tests found in {filepath.name}")
        return True
    
    # Track changes
    modifications = 0
    offset = 0
    
    for match in matches:
        test_name = match.group(2)
        start_pos = match.start()
        
        # Find the opening brace
        brace_pos = content.find('{', start_pos)
        if brace_pos == -1:
            continue
        
        # Check if logging already exists near this test
        next_section = content[brace_pos:brace_pos+300]
        if f'SS_LOG_INFO(L"{filename_prefix}", L"[{test_name}]' in next_section:
            continue
        
        # Insert logging after opening brace
        indent = "    "
        log_line = f"\n{indent}SS_LOG_INFO(L\"{filename_prefix}\", L\"[{test_name}] Testing...\");"
        
        insert_pos = brace_pos + 1
        content = content[:insert_pos] + log_line + content[insert_pos:]
        modifications += 1
    
    if modifications > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  ✓ Added logging to {filepath.name} ({modifications} tests)")
        return True
    else:
        print(f"  ✓ {filepath.name} already has logging or no tests found")
        return True

def main():
    print("=" * 80)
    print("ShadowStrike Test File Logging Enhancement")
    print("=" * 80)
    
    success_count = 0
    
    for test_file in TEST_FILES:
        filepath = TEST_DIR / test_file
        print(f"\nProcessing: {test_file}")
        
        if process_file(filepath):
            success_count += 1
        else:
            print(f"  ERROR: Failed to process {test_file}")
    
    print(f"\n{'=' * 80}")
    print(f"Completed: {success_count}/{len(TEST_FILES)} files processed successfully")
    print("=" * 80)

if __name__ == "__main__":
    main()
