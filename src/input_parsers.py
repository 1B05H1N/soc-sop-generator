"""
Input Parsers Module

This module provides parsers for different input formats to support
SOP generation from various data sources.
"""

import json
import csv
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass

from src.rule_analyzer import RuleInfo


@dataclass
class ParsedRule:
    """Standardized rule data structure"""
    rule_id: str
    rule_name: str
    description: str
    search_filter: str
    search_outcome: str
    status: str
    created_on: str
    last_updated_on: str


class InputValidator:
    """Validates parsed rules for completeness"""
    
    @staticmethod
    def validate_rule(rule: ParsedRule) -> List[str]:
        """Validate a single rule and return list of issues"""
        issues = []
        
        if not rule.rule_id:
            issues.append("Missing rule ID")
        
        if not rule.rule_name:
            issues.append("Missing rule name")
        
        if not rule.description:
            issues.append("Missing description")
        
        if not rule.search_filter:
            issues.append("Missing search filter")
        
        if not rule.search_outcome:
            issues.append("Missing search outcome")
        
        if not rule.status:
            issues.append("Missing status")
        
        return issues
    
    @staticmethod
    def validate_rules(rules: List[ParsedRule]) -> Dict[str, Any]:
        """Validate a list of rules and return validation summary"""
        total_rules = len(rules)
        valid_rules = []
        invalid_rules = []
        
        for rule in rules:
            issues = InputValidator.validate_rule(rule)
            if issues:
                invalid_rules.append({
                    'rule': rule,
                    'issues': issues
                })
            else:
                valid_rules.append(rule)
        
        return {
            'total_rules': total_rules,
            'valid_rules': len(valid_rules),
            'invalid_rules': len(invalid_rules),
            'validation_issues': invalid_rules
        }


class BackupSummaryParser:
    """Parser for security platform backup summary JSON format"""
    
    @staticmethod
    def parse(file_path: str) -> List[ParsedRule]:
        """Parse security platform backup summary JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        rules = []
        
        # Handle different backup summary structures
        if 'saved_rules' in data:
            rules_data = data['saved_rules']
        elif 'correlation_rules' in data:
            rules_data = data['correlation_rules']
        elif 'rules' in data:
            rules_data = data['rules']
        else:
            # If no known structure, assume the data itself is the rules array
            rules_data = data if isinstance(data, list) else []
        
        for rule_data in rules_data:
            # Ensure rule_data is a dictionary
            if isinstance(rule_data, dict):
                rule = ParsedRule(
                rule_id=rule_data.get('rule_id', ''),
                rule_name=rule_data.get('rule_name', ''),
                description=rule_data.get('description', ''),
                search_filter=rule_data.get('search_filter', ''),
                search_outcome=rule_data.get('search_outcome', ''),
                status=rule_data.get('status', 'inactive'),
                created_on=rule_data.get('created_on', ''),
                last_updated_on=rule_data.get('last_updated_on', '')
            )
            rules.append(rule)
        
        return rules


class CustomJSONParser:
    """Parser for custom JSON format"""
    
    @staticmethod
    def parse(file_path: str) -> List[ParsedRule]:
        """Parse custom JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        rules = []
        
        # Handle array of rules
        if isinstance(data, list):
            rules_data = data
        else:
            # Handle object with rules array
            rules_data = data.get('rules', [])
        
        for rule_data in rules_data:
            rule = ParsedRule(
                rule_id=rule_data.get('rule_id', ''),
                rule_name=rule_data.get('rule_name', ''),
                description=rule_data.get('description', ''),
                search_filter=rule_data.get('search_filter', ''),
                search_outcome=rule_data.get('search_outcome', ''),
                status=rule_data.get('status', 'inactive'),
                created_on=rule_data.get('created_on', ''),
                last_updated_on=rule_data.get('last_updated_on', '')
            )
            rules.append(rule)
        
        return rules


class CSVParser:
    """Parser for CSV format"""
    
    @staticmethod
    def parse(file_path: str) -> List[ParsedRule]:
        """Parse CSV file"""
        rules = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                rule = ParsedRule(
                    rule_id=row.get('rule_id', ''),
                    rule_name=row.get('rule_name', ''),
                    description=row.get('description', ''),
                    search_filter=row.get('search_filter', ''),
                    search_outcome=row.get('search_outcome', ''),
                    status=row.get('status', 'inactive'),
                    created_on=row.get('created_on', ''),
                    last_updated_on=row.get('last_updated_on', '')
                )
                rules.append(rule)
        
        return rules


class TextFileParser:
    """Parser for simple text file format"""
    
    @staticmethod
    def parse(file_path: str) -> List[ParsedRule]:
        """Parse simple text file format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        rules = []
        rule_blocks = content.split('---')
        
        for block in rule_blocks:
            block = block.strip()
            if not block:
                continue
            
            rule_data = {}
            for line in block.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    rule_data[key.strip()] = value.strip()
            
            if rule_data:
                rule = ParsedRule(
                    rule_id=rule_data.get('rule_id', ''),
                    rule_name=rule_data.get('rule_name', ''),
                    description=rule_data.get('description', ''),
                    search_filter=rule_data.get('search_filter', ''),
                    search_outcome=rule_data.get('search_outcome', ''),
                    status=rule_data.get('status', 'active'),
                    created_on=rule_data.get('created_on', ''),
                    last_updated_on=rule_data.get('last_updated_on', '')
                )
                rules.append(rule)
        
        return rules


class InputParserFactory:
    """Factory for selecting appropriate parser based on file format"""
    
    @staticmethod
    def detect_format(file_path: str) -> str:
        """Auto-detect input file format based on content and extension"""
        file_path = Path(file_path)
        
        # Check file extension first
        if file_path.suffix.lower() == '.csv':
            return 'csv'
        elif file_path.suffix.lower() == '.txt':
            return 'text'
        elif file_path.suffix.lower() == '.json':
            # Try to determine JSON format by reading content
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Check for security platform backup summary format
                if 'saved_rules' in data:
                    return 'backup_summary'
                elif 'rules' in data:
                    return 'custom_json'
                else:
                    return 'custom_json'  # Default for JSON files
            except (json.JSONDecodeError, UnicodeDecodeError):
                return 'text'  # Fallback to text if JSON parsing fails
        
        # Try to detect by content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
            
            if ',' in first_line and any(keyword in first_line.lower() for keyword in ['rule_id', 'rule_name']):
                return 'csv'
            elif 'rule_id:' in first_line or 'rule_name:' in first_line:
                return 'text'
            else:
                return 'text'  # Default to text format
        except UnicodeDecodeError:
            return 'text'  # Default to text format
    
    @staticmethod
    def get_parser(format_type: str):
        """Get the appropriate parser for the format type"""
        parsers = {
            'backup_summary': BackupSummaryParser,
            'custom_json': CustomJSONParser,
            'csv': CSVParser,
            'text': TextFileParser
        }
        
        if format_type not in parsers:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return parsers[format_type]
    
    @staticmethod
    def parse_file(file_path: str, format_type: Optional[str] = None) -> List[ParsedRule]:
        """Parse file using auto-detection or specified format"""
        if format_type is None:
            format_type = InputParserFactory.detect_format(file_path)
        
        parser_class = InputParserFactory.get_parser(format_type)
        return parser_class.parse(file_path)


class InputTemplateGenerator:
    """Generates input file templates for different formats"""
    
    @staticmethod
    def generate_backup_summary_template() -> str:
        """Generate backup summary template"""
        return """{
  "saved_rules": [
                    {
                        "rule_id": "example_rule_001",
                        "rule_name": "Example Rule Name",
                        "description": "Description of what this rule detects",
                        "search_filter": "event_simpleName=ProcessRollup2 AND CommandLine=*example*",
                        "search_outcome": "Detects suspicious command line activity",
                        "status": "active",
      "created_on": "2025-07-20T00:00:00Z",
      "last_updated_on": "2025-07-20T00:00:00Z"
                    }
                ]
}"""
    
    @staticmethod
    def generate_custom_json_template() -> str:
        """Generate custom JSON template"""
        return """{
            "rules": [
                {
                    "rule_id": "custom_rule_001",
                    "rule_name": "Custom Rule Name",
                    "description": "Description of what this rule detects",
                    "search_filter": "event_simpleName=ProcessRollup2 AND CommandLine=*suspicious*",
                    "search_outcome": "Detects suspicious process activity",
                    "status": "active",
      "created_on": "2025-07-20T00:00:00Z",
      "last_updated_on": "2025-07-20T00:00:00Z"
                }
            ]
}"""
    
    @staticmethod
    def generate_csv_template() -> str:
        """Generate CSV template"""
        return """rule_id,rule_name,description,search_filter,search_outcome,status,created_on,last_updated_on
csv_rule_001,CSV Rule Name,Description of what this rule detects,event_simpleName=ProcessRollup2 AND CommandLine=*csv*,Detects suspicious CSV activity,active,2025-07-20T00:00:00Z,2025-07-20T00:00:00Z"""
    
    @staticmethod
    def generate_text_template() -> str:
        """Generate text file template"""
        return """rule_id: example_rule_001
rule_name: Example Rule Name
description: Description of what this rule detects
search_filter: event_simpleName=ProcessRollup2 AND CommandLine=*example*
search_outcome: Detects suspicious command line activity
status: active
created_on: 2025-07-20T00:00:00Z
last_updated_on: 2025-07-20T00:00:00Z
---
rule_id: example_rule_002
rule_name: Another Rule Name
description: Another rule description
search_filter: event_simpleName=UserLogon AND UserName=*admin*
search_outcome: Detects admin login events
status: active
created_on: 2025-07-20T00:00:00Z
last_updated_on: 2025-07-20T00:00:00Z"""

    @staticmethod
    def generate_all_templates(output_dir: str = "templates"):
        """Generate all input file templates"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Generate backup summary template
        with open(output_path / "backup_summary_template.json", 'w') as f:
            f.write(InputTemplateGenerator.generate_backup_summary_template())
        
        # Generate custom JSON template
        with open(output_path / "custom_json_template.json", 'w') as f:
            f.write(InputTemplateGenerator.generate_custom_json_template())
        
        # Generate CSV template
        with open(output_path / "csv_template.csv", 'w') as f:
            f.write(InputTemplateGenerator.generate_csv_template())
        
        # Generate text template
        with open(output_path / "text_template.txt", 'w') as f:
            f.write(InputTemplateGenerator.generate_text_template())
        
        return [
            str(output_path / "backup_summary_template.json"),
            str(output_path / "custom_json_template.json"),
            str(output_path / "csv_template.csv")
        ] 