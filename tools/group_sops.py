#!/usr/bin/env python3
"""
SOP Grouping and Organization Script

This script analyzes generated SOPs and groups them by category for better organization.

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

class SOPGrouper:
    def __init__(self, sop_directory="output/generated_sops"):
        self.sop_directory = Path(sop_directory)
        self.categories = defaultdict(list)
        self.category_stats = defaultdict(int)
        
    def analyze_sop_filename(self, filename):
        """Analyze SOP filename to determine category"""
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
    
    def analyze_sop_content(self, filepath):
        """Analyze SOP content to extract additional metadata"""
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
            
            # Extract rule ID
            rule_id_match = re.search(r'\*\*Rule ID:\*\*\s*([a-f0-9]+)', content)
            if rule_id_match:
                metadata['rule_id'] = rule_id_match.group(1)
            
            return metadata
            
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}")
            return None
    
    def group_sops(self):
        """Group SOPs by category"""
        if not self.sop_directory.exists():
            print(f"SOP directory not found: {self.sop_directory}")
            return
        
        print(f"Analyzing SOPs in: {self.sop_directory}")
        
        for sop_file in self.sop_directory.glob("*.md"):
            metadata = self.analyze_sop_content(sop_file)
            if metadata:
                category = metadata['category']
                self.categories[category].append(metadata)
                self.category_stats[category] += 1
        
        print(f"\nFound {sum(self.category_stats.values())} SOPs in {len(self.categories)} categories:")
        for category, count in sorted(self.category_stats.items()):
            print(f"  {category}: {count} SOPs")
    
    def create_organized_structure(self, output_dir="output/organized_sops"):
        """Create organized directory structure with grouped SOPs"""
        output_path = Path(output_dir)
        
        # Create main output directory
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create category directories and copy files
        for category, sops in self.categories.items():
            category_dir = output_path / category
            category_dir.mkdir(exist_ok=True)
            
            print(f"\nCreating {category} directory with {len(sops)} SOPs...")
            
            for sop in sops:
                source_file = self.sop_directory / sop['filename']
                dest_file = category_dir / sop['filename']
                
                if source_file.exists():
                    shutil.copy2(source_file, dest_file)
                    print(f"  Copied: {sop['filename']}")
        
        # Create summary files
        self.create_summary_files(output_path)
        
        print(f"\nOrganized SOPs created in: {output_path}")
    
    def create_summary_files(self, output_path):
        """Create summary files for each category"""
        for category, sops in self.categories.items():
            category_dir = output_path / category
            summary_file = category_dir / "README.md"
            
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(f"# {category.replace('_', ' ')} SOPs\n\n")
                f.write(f"Total SOPs: {len(sops)}\n\n")
                
                # Group by priority
                priority_groups = defaultdict(list)
                for sop in sops:
                    priority_groups[sop['priority']].append(sop)
                
                f.write("## By Priority\n\n")
                for priority in ['high', 'medium', 'low']:
                    if priority in priority_groups:
                        f.write(f"### {priority.title()} Priority ({len(priority_groups[priority])})\n\n")
                        for sop in sorted(priority_groups[priority], key=lambda x: x['filename']):
                            f.write(f"- [{sop['filename']}]({sop['filename']})\n")
                        f.write("\n")
        
        # Create overall summary
        overall_summary = output_path / "OVERALL_SUMMARY.md"
        with open(overall_summary, 'w', encoding='utf-8') as f:
            f.write("# SOP Organization Summary\n\n")
            f.write(f"Total SOPs: {sum(self.category_stats.values())}\n")
            f.write(f"Categories: {len(self.categories)}\n\n")
            
            f.write("## Category Breakdown\n\n")
            for category, count in sorted(self.category_stats.items()):
                f.write(f"- **{category.replace('_', ' ')}**: {count} SOPs\n")
            
            f.write("\n## Quick Links\n\n")
            for category in sorted(self.categories.keys()):
                f.write(f"- [{category.replace('_', ' ')}]({category}/README.md)\n")
    
    def generate_statistics(self):
        """Generate detailed statistics"""
        stats = {
            'total_sops': sum(self.category_stats.values()),
            'categories': dict(self.category_stats),
            'mitre_mapped': sum(1 for sops in self.categories.values() 
                               for sop in sops if sop.get('has_mitre')),
            'priority_breakdown': defaultdict(int)
        }
        
        for sops in self.categories.values():
            for sop in sops:
                stats['priority_breakdown'][sop['priority']] += 1
        
        return stats

def main():
    grouper = SOPGrouper()
    grouper.group_sops()
    
    # Generate statistics
    stats = grouper.generate_statistics()
    
    print("\n" + "="*50)
    print("DETAILED STATISTICS")
    print("="*50)
    print(f"Total SOPs: {stats['total_sops']}")
    print(f"Categories: {len(stats['categories'])}")
    print(f"MITRE ATT&CK Mapped: {stats['mitre_mapped']}")
    
    print("\nPriority Breakdown:")
    for priority, count in sorted(stats['priority_breakdown'].items()):
        print(f"  {priority.title()}: {count}")
    
    # Create organized structure
    print("\n" + "="*50)
    print("CREATING ORGANIZED STRUCTURE")
    print("="*50)
    grouper.create_organized_structure()
    
    print("\n" + "="*50)
    print("COMPLETED")
    print("="*50)
    print("Check the 'output/organized_sops' directory for the organized structure.")

if __name__ == "__main__":
    main() 