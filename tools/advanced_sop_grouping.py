#!/usr/bin/env python3
"""
Advanced SOP Grouping and Organization Script

This script provides advanced categorization and sub-grouping of SOPs
using generic patterns that don't reveal business-specific information.

DISCLAIMER: This software is provided "AS IS" without any warranties.
Use at your own risk. The author is not liable for any damages or
consequences from the use of this software. Always review and validate
generated content before implementation in production environments.
"""

import os
import re
import shutil
from pathlib import Path
from collections import defaultdict
import json

class AdvancedSOPGrouper:
    def __init__(self, sop_directory="output/generated_sops"):
        self.sop_directory = Path(sop_directory)
        self.categories = defaultdict(list)
        self.category_stats = defaultdict(int)
        self.account_details = defaultdict(dict)
        
    def analyze_account_details(self, filename):
        """Analyze account filename for environment and function details using generic patterns"""
        filename_lower = filename.lower()
        
        # Generic environment detection
        environment = "unknown"
        if any(env in filename_lower for env in ['prod', 'production']):
            environment = "production"
        elif any(env in filename_lower for env in ['dev', 'development']):
            environment = "development"
        elif any(env in filename_lower for env in ['stg', 'stage', 'staging']):
            environment = "staging"
        elif any(env in filename_lower for env in ['test']):
            environment = "testing"
        
        # Generic function detection
        function = "general"
        if any(func in filename_lower for func in ['sql', 'database', 'db']):
            function = "database"
        elif any(func in filename_lower for func in ['app', 'application']):
            function = "application"
        elif any(func in filename_lower for func in ['admin', 'adm']):
            function = "administration"
        elif any(func in filename_lower for func in ['backup']):
            function = "backup"
        elif any(func in filename_lower for func in ['automation', 'bot']):
            function = "automation"
        elif any(func in filename_lower for func in ['ldap', 'ad']):
            function = "directory_services"
        elif any(func in filename_lower for func in ['network']):
            function = "network_management"
        elif any(func in filename_lower for func in ['batch']):
            function = "batch_processing"
        elif any(func in filename_lower for func in ['payment']):
            function = "payment_processing"
        elif any(func in filename_lower for func in ['financial']):
            function = "financial_systems"
        elif any(func in filename_lower for func in ['integration']):
            function = "data_integration"
        elif any(func in filename_lower for func in ['security']):
            function = "security_services"
        
        return {
            'environment': environment,
            'function': function,
            'full_name': filename.replace('_Misuse_Detected_SOP.md', '')
        }
    
    def create_advanced_account_structure(self, output_dir="output/advanced_organized_sops"):
        """Create advanced organized structure with sub-groupings"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Process accounts with advanced grouping
        account_groups = defaultdict(lambda: defaultdict(list))
        
        for sop_file in self.sop_directory.glob("*.md"):
            if any(pattern in sop_file.name.lower() for pattern in ['account', 'user', 'service']):
                details = self.analyze_account_details(sop_file.name)
                env = details['environment']
                func = details['function']
                
                account_groups[env][func].append({
                    'filename': sop_file.name,
                    'details': details,
                    'filepath': sop_file
                })
        
        # Create environment-based structure
        for environment, functions in account_groups.items():
            env_dir = output_path / "Account_Security" / environment
            env_dir.mkdir(parents=True, exist_ok=True)
            
            # Create environment summary
            env_summary = env_dir / "README.md"
            with open(env_summary, 'w', encoding='utf-8') as f:
                f.write(f"# Account Security - {environment.title()} Environment\n\n")
                
                total_sops = sum(len(sops) for sops in functions.values())
                f.write(f"**Total SOPs:** {total_sops}\n\n")
                
                f.write("## By Function\n\n")
                for function, sops in functions.items():
                    f.write(f"### {function.replace('_', ' ').title()} ({len(sops)})\n\n")
                    for sop in sorted(sops, key=lambda x: x['filename']):
                        f.write(f"- [{sop['filename']}]({function}/{sop['filename']})\n")
                    f.write("\n")
                
                # Copy files to function subdirectories
                for function, sops in functions.items():
                    func_dir = env_dir / function
                    func_dir.mkdir(exist_ok=True)
                    
                    for sop in sops:
                        dest_file = func_dir / sop['filename']
                        shutil.copy2(sop['filepath'], dest_file)
        
        # Create overall account summary
        overall_account_summary = output_path / "Account_Security" / "OVERALL_ACCOUNT_SUMMARY.md"
        with open(overall_account_summary, 'w', encoding='utf-8') as f:
            f.write("# Account Security - Overall Summary\n\n")
            
            total_account_sops = sum(sum(len(sops) for sops in functions.values()) 
                                   for functions in account_groups.values())
            f.write(f"**Total Account Security SOPs:** {total_account_sops}\n\n")
            
            f.write("## By Environment\n\n")
            for environment, functions in account_groups.items():
                env_total = sum(len(sops) for sops in functions.values())
                f.write(f"### {environment.title()} ({env_total})\n\n")
                
                for function, sops in functions.items():
                    f.write(f"- **{function.replace('_', ' ').title()}**: {len(sops)} SOPs\n")
                f.write("\n")
            
            f.write("## Quick Links\n\n")
            for environment in account_groups.keys():
                f.write(f"- [{environment.title()}]({environment}/README.md)\n")
        
        print(f"Advanced Account Security structure created in: {output_path}")
        return account_groups
    
    def create_function_based_structure(self, output_dir="output/function_organized_sops"):
        """Create function-based organization across all environments"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Group all SOPs by function
        function_groups = defaultdict(list)
        
        for sop_file in self.sop_directory.glob("*.md"):
            if any(pattern in sop_file.name.lower() for pattern in ['account', 'user', 'service']):
                details = self.analyze_account_details(sop_file.name)
                function = details['function']
                
                function_groups[function].append({
                    'filename': sop_file.name,
                    'details': details,
                    'filepath': sop_file
                })
        
        # Create function-based directories
        for function, sops in function_groups.items():
            func_dir = output_path / function
            func_dir.mkdir(exist_ok=True)
            
            # Create function summary
            func_summary = func_dir / "README.md"
            with open(func_summary, 'w', encoding='utf-8') as f:
                f.write(f"# {function.replace('_', ' ').title()} Account Security\n\n")
                f.write(f"**Total SOPs:** {len(sops)}\n\n")
                
                # Group by environment
                env_groups = defaultdict(list)
                for sop in sops:
                    env_groups[sop['details']['environment']].append(sop)
                
                f.write("## By Environment\n\n")
                for env, env_sops in env_groups.items():
                    f.write(f"### {env.title()} ({len(env_sops)})\n\n")
                    for sop in sorted(env_sops, key=lambda x: x['filename']):
                        f.write(f"- [{sop['filename']}]({sop['filename']})\n")
                    f.write("\n")
                
                # Copy files
                for sop in sops:
                    dest_file = func_dir / sop['filename']
                    shutil.copy2(sop['filepath'], dest_file)
        
        print(f"Function-based structure created in: {output_path}")
        return function_groups
    
    def generate_account_statistics(self):
        """Generate detailed account statistics"""
        account_stats = {
            'total_account_sops': 0,
            'environments': defaultdict(int),
            'functions': defaultdict(int),
            'environment_function_matrix': defaultdict(lambda: defaultdict(int))
        }
        
        for sop_file in self.sop_directory.glob("*.md"):
            if any(pattern in sop_file.name.lower() for pattern in ['account', 'user', 'service']):
                details = self.analyze_account_details(sop_file.name)
                account_stats['total_account_sops'] += 1
                account_stats['environments'][details['environment']] += 1
                account_stats['functions'][details['function']] += 1
                account_stats['environment_function_matrix'][details['environment']][details['function']] += 1
        
        return account_stats

def main():
    grouper = AdvancedSOPGrouper()
    
    print("="*60)
    print("ADVANCED SOP GROUPING")
    print("="*60)
    
    # Generate account statistics
    account_stats = grouper.generate_account_statistics()
    
    print(f"\nAccount Security Statistics:")
    print(f"Total Account Security SOPs: {account_stats['total_account_sops']}")
    
    print(f"\nBy Environment:")
    for env, count in sorted(account_stats['environments'].items()):
        print(f"  {env.title()}: {count}")
    
    print(f"\nBy Function:")
    for func, count in sorted(account_stats['functions'].items()):
        print(f"  {func.replace('_', ' ').title()}: {count}")
    
    print(f"\nEnvironment-Function Matrix:")
    for env in sorted(account_stats['environment_function_matrix'].keys()):
        print(f"  {env.title()}:")
        for func, count in sorted(account_stats['environment_function_matrix'][env].items()):
            print(f"    {func.replace('_', ' ').title()}: {count}")
    
    # Create advanced structures
    print(f"\n" + "="*60)
    print("CREATING ADVANCED STRUCTURES")
    print("="*60)
    
    # Environment-based structure
    print("\nCreating environment-based structure...")
    grouper.create_advanced_account_structure()
    
    # Function-based structure
    print("\nCreating function-based structure...")
    grouper.create_function_based_structure()
    
    print(f"\n" + "="*60)
    print("COMPLETED")
    print("="*60)
    print("Check the following directories:")
    print("- output/advanced_organized_sops/Account_Security/ (by environment)")
    print("- output/function_organized_sops/ (by function)")

if __name__ == "__main__":
    main() 