#!/usr/bin/env python3
"""
Unified SOP Grouping and Organization Script

This script provides comprehensive categorization and organization of SOPs
with multiple grouping strategies and privacy compliance.

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
from typing import Dict, List, Any, Optional
from enum import Enum


class GroupingStrategy(Enum):
    """Available grouping strategies"""
    BASIC = "basic"
    ADVANCED = "advanced"
    GENERIC = "generic"


class UnifiedSOPGrouper:
    """Unified SOP grouping and organization with multiple strategies"""
    
    def __init__(self, sop_directory="output/generated_sops"):
        self.sop_directory = Path(sop_directory)
        self.categories = defaultdict(list)
        self.category_stats = defaultdict(int)
        self.account_details = defaultdict(dict)
        
    def analyze_sop_filename(self, filename: str) -> str:
        """Analyze SOP filename to determine category using generic patterns"""
        filename_lower = filename.lower()
        
        # Generic patterns that don't reveal business information
        if any(pattern in filename_lower for pattern in ['account', 'user', 'service']):
            return "Account_Security"
        
        if any(pattern in filename_lower for pattern in ['database', 'sql', 'db']):
            return "Database_Security"
        
        if any(pattern in filename_lower for pattern in ['script', 'command', 'execution']):
            return "Command_Execution"
        
        if any(pattern in filename_lower for pattern in ['registry', 'config', 'setting']):
            return "System_Configuration"
        
        if any(pattern in filename_lower for pattern in ['network', 'share', 'access']):
            return "Network_Access"
        
        if any(pattern in filename_lower for pattern in ['auth', 'login', 'authentication']):
            return "Authentication"
        
        if any(pattern in filename_lower for pattern in ['cloud', 'azure', 'aws']):
            return "Cloud_Services"
        
        if any(pattern in filename_lower for pattern in ['admin', 'privilege', 'escalation']):
            return "Privileged_Access"
        
        if any(pattern in filename_lower for pattern in ['process', 'system', 'hardware']):
            return "System_Processes"
        
        if any(pattern in filename_lower for pattern in ['file', 'document', 'data']):
            return "Data_Operations"
        
        if any(pattern in filename_lower for pattern in ['credential', 'password', 'secret']):
            return "Credential_Security"
        
        if any(pattern in filename_lower for pattern in ['scheduled', 'task', 'job']):
            return "Scheduled_Operations"
        
        if any(pattern in filename_lower for pattern in ['test', 'development', 'dev']):
            return "Testing_Development"
        
        if any(pattern in filename_lower for pattern in ['geo', 'location', 'region']):
            return "Geographic_Security"
        
        if any(pattern in filename_lower for pattern in ['sanction', 'compliance', 'policy']):
            return "Compliance_Security"
        
        return "General_Security"
    
    def analyze_account_details(self, filename: str) -> Dict[str, str]:
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
    
    def analyze_sop_content(self, filepath: Path) -> Dict[str, Any]:
        """Analyze SOP content to extract metadata"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            metadata = {
                'filename': filepath.name,
                'size': filepath.stat().st_size,
                'lines': len(content.split('\n')),
                'category': self.analyze_sop_filename(filepath.name),
                'has_mitre': 'MITRE ATT&CK' in content,
                'priority': 'medium'
            }
            
            # Extract priority from content
            priority_match = re.search(r'\*\*Priority:\*\*\s*(\w+)', content)
            if priority_match:
                metadata['priority'] = priority_match.group(1)
            
            # Extract rule ID (generic identifier)
            rule_id_match = re.search(r'\*\*Rule ID:\*\*\s*([a-f0-9]+)', content)
            if rule_id_match:
                metadata['rule_id'] = rule_id_match.group(1)
            
            return metadata
        except Exception as e:
            print(f"Warning: Could not analyze {filepath}: {e}")
            return {
                'filename': filepath.name,
                'size': 0,
                'lines': 0,
                'category': self.analyze_sop_filename(filepath.name),
                'has_mitre': False,
                'priority': 'unknown'
            }
    
    def group_sops(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group SOPs by category"""
        if not self.sop_directory.exists():
            print(f"Warning: SOP directory {self.sop_directory} does not exist")
            return {}
        
        for sop_file in self.sop_directory.glob("*.md"):
            if sop_file.is_file():
                metadata = self.analyze_sop_content(sop_file)
                category = metadata['category']
                self.categories[category].append(metadata)
                self.category_stats[category] += 1
        
        return dict(self.categories)
    
    def create_basic_structure(self, output_dir: str = "output/organized_sops") -> None:
        """Create basic organized structure"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Group SOPs
        grouped_sops = self.group_sops()
        
        # Create category directories and copy files
        for category, sops in grouped_sops.items():
            category_dir = output_path / category
            category_dir.mkdir(exist_ok=True)
            
            for sop in sops:
                source_file = self.sop_directory / sop['filename']
                dest_file = category_dir / sop['filename']
                
                if source_file.exists():
                    shutil.copy2(source_file, dest_file)
        
        # Create summary files
        self.create_summary_files(output_path)
    
    def create_advanced_structure(self, output_dir: str = "output/advanced_organized_sops") -> None:
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
            
            # Create function-based subdirectories
            for function, sops in functions.items():
                func_dir = env_dir / function
                func_dir.mkdir(exist_ok=True)
                
                # Copy SOP files
                for sop in sops:
                    dest_file = func_dir / sop['filename']
                    shutil.copy2(sop['filepath'], dest_file)
        
        # Create summary files
        self.create_advanced_summary_files(output_path, account_groups)
    
    def create_generic_structure(self, output_dir: str = "output/generic_organized_sops") -> None:
        """Create generic organized structure with privacy compliance"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Group SOPs
        grouped_sops = self.group_sops()
        
        # Create category directories and copy files
        for category, sops in grouped_sops.items():
            category_dir = output_path / category
            category_dir.mkdir(exist_ok=True)
            
            for sop in sops:
                source_file = self.sop_directory / sop['filename']
                dest_file = category_dir / sop['filename']
                
                if source_file.exists():
                    shutil.copy2(source_file, dest_file)
        
        # Create summary files
        self.create_summary_files(output_path)
        
        # Create advanced generic structure
        self.create_advanced_generic_structure(output_dir.replace("generic_organized_sops", "advanced_generic_sops"))
    
    def create_advanced_generic_structure(self, output_dir: str = "output/advanced_generic_sops") -> None:
        """Create advanced generic structure with enhanced organization"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Group by priority and category
        priority_groups = defaultdict(lambda: defaultdict(list))
        
        for sop_file in self.sop_directory.glob("*.md"):
            metadata = self.analyze_sop_content(sop_file)
            priority = metadata.get('priority', 'medium')
            category = metadata['category']
            
            priority_groups[priority][category].append({
                'filename': sop_file.name,
                'metadata': metadata,
                'filepath': sop_file
            })
        
        # Create priority-based structure
        for priority, categories in priority_groups.items():
            priority_dir = output_path / f"Priority_{priority.title()}"
            priority_dir.mkdir(exist_ok=True)
            
            for category, sops in categories.items():
                category_dir = priority_dir / category
                category_dir.mkdir(exist_ok=True)
                
                # Copy SOP files
                for sop in sops:
                    dest_file = category_dir / sop['filename']
                    shutil.copy2(sop['filepath'], dest_file)
        
        # Create advanced summary
        self.create_advanced_generic_summary(output_path, priority_groups)
    
    def create_summary_files(self, output_path: Path) -> None:
        """Create summary files for basic organization"""
        # Create category summary
        summary_data = {
            'total_sops': sum(self.category_stats.values()),
            'categories': dict(self.category_stats),
            'organization_date': str(Path().cwd()),
            'organization_type': 'basic'
        }
        
        with open(output_path / 'organization_summary.json', 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        # Create README
        readme_content = f"""# SOP Organization Summary

Total SOPs: {summary_data['total_sops']}
Categories: {len(self.category_stats)}

## Category Breakdown:
"""
        for category, count in self.category_stats.items():
            readme_content += f"- {category}: {count} SOPs\n"
        
        with open(output_path / 'README.md', 'w') as f:
            f.write(readme_content)
    
    def create_advanced_summary_files(self, output_path: Path, account_groups: Dict) -> None:
        """Create summary files for advanced organization"""
        summary_data = {
            'total_account_sops': sum(len(sops) for env in account_groups.values() for sops in env.values()),
            'environments': {env: len(functions) for env, functions in account_groups.items()},
            'organization_date': str(Path().cwd()),
            'organization_type': 'advanced_account'
        }
        
        with open(output_path / 'advanced_organization_summary.json', 'w') as f:
            json.dump(summary_data, f, indent=2)
    
    def create_advanced_generic_summary(self, output_path: Path, priority_groups: Dict) -> None:
        """Create summary files for advanced generic organization"""
        summary_data = {
            'total_sops': sum(len(sops) for priority in priority_groups.values() for sops in priority.values()),
            'priorities': {priority: len(categories) for priority, categories in priority_groups.items()},
            'organization_date': str(Path().cwd()),
            'organization_type': 'advanced_generic'
        }
        
        with open(output_path / 'advanced_generic_summary.json', 'w') as f:
            json.dump(summary_data, f, indent=2)
    
    def generate_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        grouped_sops = self.group_sops()
        
        stats = {
            'total_sops': sum(self.category_stats.values()),
            'categories': dict(self.category_stats),
            'category_breakdown': {},
            'mitre_coverage': 0,
            'priority_breakdown': defaultdict(int)
        }
        
        for category, sops in grouped_sops.items():
            stats['category_breakdown'][category] = {
                'count': len(sops),
                'mitre_count': sum(1 for sop in sops if sop.get('has_mitre', False)),
                'priorities': defaultdict(int)
            }
            
            for sop in sops:
                priority = sop.get('priority', 'unknown')
                stats['category_breakdown'][category]['priorities'][priority] += 1
                stats['priority_breakdown'][priority] += 1
                
                if sop.get('has_mitre', False):
                    stats['mitre_coverage'] += 1
        
        return stats


def main():
    """Main function for unified SOP grouping"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified SOP Grouping and Organization")
    parser.add_argument('--strategy', choices=['basic', 'advanced', 'generic', 'all'], 
                       default='basic', help='Grouping strategy to use')
    parser.add_argument('--input-dir', default='output/generated_sops',
                       help='Input directory containing SOP files')
    parser.add_argument('--output-dir', help='Output directory (auto-determined based on strategy)')
    
    args = parser.parse_args()
    
    grouper = UnifiedSOPGrouper(args.input_dir)
    
    if args.strategy == 'basic' or args.strategy == 'all':
        output_dir = args.output_dir or "output/organized_sops"
        print(f"Creating basic organization in {output_dir}")
        grouper.create_basic_structure(output_dir)
    
    if args.strategy == 'advanced' or args.strategy == 'all':
        output_dir = args.output_dir or "output/advanced_organized_sops"
        print(f"Creating advanced organization in {output_dir}")
        grouper.create_advanced_structure(output_dir)
    
    if args.strategy == 'generic' or args.strategy == 'all':
        output_dir = args.output_dir or "output/generic_organized_sops"
        print(f"Creating generic organization in {output_dir}")
        grouper.create_generic_structure(output_dir)
    
    # Generate statistics
    stats = grouper.generate_statistics()
    print(f"\nOrganization complete!")
    print(f"Total SOPs processed: {stats['total_sops']}")
    print(f"Categories created: {len(stats['categories'])}")
    print(f"SOPs with MITRE coverage: {stats['mitre_coverage']}")


if __name__ == "__main__":
    main() 