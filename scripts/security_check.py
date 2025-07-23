#!/usr/bin/env python3
"""
Security Check Script

This script validates that no company-specific information, URLs, or secrets
are hardcoded in the codebase.
"""

import os
import re
import sys
from pathlib import Path

def check_for_hardcoded_secrets():
    """Check for hardcoded secrets, URLs, or company information"""
    
    # Patterns to check for
    patterns = {
        'company_urls': [
            r'https?://[a-zA-Z0-9.-]+\.atlassian\.net',
            r'https?://[a-zA-Z0-9.-]+\.company\.com',
            r'https?://[a-zA-Z0-9.-]+\.org',
            r'https?://[a-zA-Z0-9.-]+\.net',
        ],
        'company_names': [
            r'company\.com',
            r'your-company',
            r'your-domain',
        ],
        'api_tokens': [
            r'Bearer [a-zA-Z0-9]{20,}',
        ],
        'email_addresses': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'folder_ids': [
            r'[0-9]{9,}',  # Long numbers that might be IDs (but not in template strings)
        ]
    }
    
    issues_found = []
    
    # Check Python files
    for py_file in Path('.').rglob('*.py'):
        if 'venv' in str(py_file) or '__pycache__' in str(py_file):
            continue
            
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                line_num = 0
                
                for line in content.split('\n'):
                    line_num += 1
                    
                    for pattern_name, pattern_list in patterns.items():
                        for pattern in pattern_list:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Skip if it's a template or example
                                if 'template' in line.lower() or 'example' in line.lower():
                                    continue
                                if 'your-' in line.lower() or 'placeholder' in line.lower():
                                    continue
                                # Skip folder IDs in template strings
                                if pattern_name == 'folder_ids' and ('YOUR_FOLDER_ID' in line or 'template' in line.lower()):
                                    continue
                                # Skip legitimate URLs in templates
                                if pattern_name == 'company_urls' and any(legit_url in line for legit_url in ['mitre.org', 'sans.org', 'cisecurity.org']):
                                    continue
                                    
                                issues_found.append({
                                    'file': str(py_file),
                                    'line': line_num,
                                    'pattern': pattern_name,
                                    'content': line.strip()
                                })
        except Exception as e:
            print(f"Error reading {py_file}: {e}")
    
    return issues_found

def check_environment_files():
    """Check if environment files exist and contain sensitive data"""
    env_files = [
        '.env',
        '.env.confluence',
        'confluence_config.env',
        '.env.local',
        '.env.production'
    ]
    
    issues = []
    
    for env_file in env_files:
        if os.path.exists(env_file):
            try:
                with open(env_file, 'r') as f:
                    content = f.read()
                    
                    # Check for real values instead of placeholders
                    if 'your-' not in content and 'placeholder' not in content:
                        if any(real_value in content for real_value in ['@', '.com', '.net', 'http']):
                            issues.append({
                                'file': env_file,
                                'type': 'environment_file_with_real_data',
                                'message': f'Environment file {env_file} contains real data'
                            })
            except Exception as e:
                print(f"Error reading {env_file}: {e}")
    
    return issues

def check_git_status():
    """Check if any sensitive files are staged for commit"""
    import subprocess
    
    try:
        # Check for staged files that might contain sensitive data
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True)
        
        staged_files = []
        for line in result.stdout.split('\n'):
            if line.strip():
                status = line[:2]
                filename = line[3:]
                
                # Check for sensitive files
                if any(sensitive in filename.lower() for sensitive in [
                    '.env', 'config', 'credential', 'secret', 'token', 'backup'
                ]):
                    staged_files.append({
                        'status': status,
                        'file': filename
                    })
        
        return staged_files
    except Exception as e:
        print(f"Error checking git status: {e}")
        return []

def main():
    """Run security checks"""
    print("Running Security Validation...")
    print("=" * 50)
    
    # Check for hardcoded secrets
    print("\n1. Checking for hardcoded secrets and company information...")
    hardcoded_issues = check_for_hardcoded_secrets()
    
    if hardcoded_issues:
        print("ISSUES FOUND:")
        for issue in hardcoded_issues:
            print(f"   File: {issue['file']}:{issue['line']}")
            print(f"   Pattern: {issue['pattern']}")
            print(f"   Content: {issue['content']}")
            print()
    else:
        print("No hardcoded secrets found")
    
    # Check environment files
    print("\n2. Checking environment files...")
    env_issues = check_environment_files()
    
    if env_issues:
        print("ISSUES FOUND:")
        for issue in env_issues:
            print(f"   {issue['message']}")
            print()
    else:
        print("Environment files look safe")
    
    # Check git status
    print("\n3. Checking git status...")
    git_issues = check_git_status()
    
    if git_issues:
        print("SENSITIVE FILES STAGED:")
        for issue in git_issues:
            print(f"   {issue['status']} {issue['file']}")
        print()
    else:
        print("No sensitive files staged for commit")
    
    # Summary
    total_issues = len(hardcoded_issues) + len(env_issues) + len(git_issues)
    
    print("=" * 50)
    if total_issues == 0:
        print("SECURITY VALIDATION PASSED")
        print("No security issues found. Safe to commit to version control.")
    else:
        print(f"SECURITY VALIDATION FAILED")
        print(f"Found {total_issues} security issues that must be resolved.")
        print("\nRECOMMENDATIONS:")
        print("1. Remove any hardcoded company URLs or information")
        print("2. Use environment variables for all configuration")
        print("3. Ensure .env files are not committed")
        print("4. Review staged files before committing")
    
    return total_issues == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 