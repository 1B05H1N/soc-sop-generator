"""
SOP Generator Module

This module orchestrates the generation of Standard Operating Procedures
from security correlation rules and other input formats.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Iterator
from pathlib import Path

from src.rule_analyzer import RuleAnalyzer, RuleInfo
from src.templates import SOPTemplates
from src.confluence_formatter import ConfluenceFormatter
from src.input_parsers import InputParserFactory, ParsedRule, InputValidator
from src.input_validator import EnhancedInputValidator
from src.unified_config import config

logger = logging.getLogger(__name__)


class SOPGenerator:
    """Main SOP generator class"""
    
    def __init__(self, output_dir: str = "output/generated_sops"):
        self.rule_analyzer = RuleAnalyzer()
        self.confluence_formatter = ConfluenceFormatter()
        self.input_validator = EnhancedInputValidator()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_sop_from_rule(self, rule: RuleInfo, output_format: str = "markdown") -> Dict[str, Any]:
        """Generate SOP from a single rule"""
        # Extract key indicators
        key_indicators = self.rule_analyzer.extract_key_indicators(rule)
        false_positive_indicators = self.rule_analyzer.get_false_positive_indicators(rule)
        
        # Get MITRE ATT&CK information
        attack_summary = self.rule_analyzer.get_attack_summary(rule)
        confidence_level = attack_summary.get('confidence', 'none').title()
        
        # Get appropriate template based on output format and category
        if output_format == "html":
            template = SOPTemplates.get_html_template()
        elif output_format == "json":
            template = SOPTemplates.get_json_template()
        elif output_format == "pdf":
            # PDF format now generates markdown (PDF-ready markdown)
            template = SOPTemplates.get_pdf_template()
        else:
            # Use category-specific template for markdown
            category = self.rule_analyzer.categorize_rule(rule)
            template = SOPTemplates.get_template_by_category(category)
        
        # Prepare template data
        template_data = {
            'rule_name': rule.rule_name,
            'rule_id': rule.rule_id,
            'status': rule.status,
            'priority': self.rule_analyzer.get_priority(rule),
            'category': self.rule_analyzer.categorize_rule(rule),
            'created_on': rule.created_on,
            'last_updated_on': rule.last_updated_on,
            'description': rule.description,
            'search_outcome': rule.search_outcome,
            'search_filter': rule.search_filter,
            'complexity': self.rule_analyzer.get_complexity(rule),
            'data_sources': self.rule_analyzer.get_data_sources(rule),
            'event_types': self.rule_analyzer.get_event_types(rule),
            'attack_mapping': self._format_attack_mapping(attack_summary),
            'attack_mapping_html': self._format_attack_mapping_html(attack_summary),
            'attack_mapping_json': json.dumps(attack_summary, indent=2),
            'confidence_level': confidence_level,
            'key_indicators_html': self._format_list_html(key_indicators),
            'false_positive_indicators_html': self._format_list_html(false_positive_indicators),
            'key_indicators_json': json.dumps(key_indicators),
            'false_positive_indicators_json': json.dumps(false_positive_indicators),
            'key_indicators': self._format_list_markdown(key_indicators),
            'false_positive_indicators': self._format_list_markdown(false_positive_indicators),
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'version': '1.0',
            'last_reviewed': datetime.now().strftime('%Y-%m-%d'),
            'next_review_date': (datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d'),
            'author': config.get_author(),
            'contact_email': config.get_contact_email(),
            'response_time': '5-30 minutes',
            'escalation_threshold': 'Multiple systems affected',
            'primary_indicator': 'Rule trigger condition',
            'secondary_indicators': 'Related security events',
            'contextual_info': 'System and user context',
            'data_impact': 'Potential data exposure',
            'system_impact': 'System compromise risk',
            'business_impact': 'Operational disruption',
            'tactic_mapping': 'TBD',
            'technique_mapping': 'TBD',
            'sub_technique_mapping': 'TBD',
            'soc_manager': 'SOC Manager',
            'soc_manager_phone': '+1-555-0123',
            'soc_manager_email': 'soc.manager@your-company.com',
            'senior_analyst': 'Senior Analyst',
            'senior_analyst_phone': '+1-555-0124',
            'senior_analyst_email': 'senior.analyst@your-company.com',
            'ir_lead': 'IR Lead',
            'ir_lead_phone': '+1-555-0125',
            'ir_lead_email': 'ir.lead@your-company.com',
            'it_security': 'IT Security',
            'it_security_phone': '+1-555-0126',
            'it_security_email': 'it.security@your-company.com',
            'future_date': (datetime.now() + timedelta(days=180)).strftime('%Y-%m-%d'),
            # Category-specific fields
            'service_account_name': self._extract_service_account_name(rule),
            'intended_purpose': self._extract_intended_purpose(rule),
            'authorized_systems': self._extract_authorized_systems(rule),
            'access_level': self._extract_access_level(rule),
            'account_status': self._extract_account_status(rule),
            'last_password_change': self._extract_last_password_change(rule),
            'group_memberships': self._extract_group_memberships(rule),
            'scheduled_tasks': self._extract_scheduled_tasks(rule),
            'normal_usage_patterns': self._extract_normal_usage_patterns(rule),
            'original_privileges': self._extract_original_privileges(rule),
            'escalated_privileges': self._extract_escalated_privileges(rule),
            'escalation_method': self._extract_escalation_method(rule),
            'target_systems': self._extract_target_systems(rule),
            'change_type': self._extract_change_type(rule),
            'changed_component': self._extract_changed_component(rule),
            'change_method': self._extract_change_method(rule),
            'affected_systems': self._extract_affected_systems(rule),
            'data_type': self._extract_data_type(rule),
            'exfiltration_method': self._extract_exfiltration_method(rule),
            'destination': self._extract_destination(rule),
            'data_volume': self._extract_data_volume(rule),
            'anomaly_type': self._extract_anomaly_type(rule),
            'source_ip': self._extract_source_ip(rule),
            'destination_ip': self._extract_destination_ip(rule),
            'protocol': self._extract_protocol(rule),
            'port': self._extract_port(rule),
        }
        
        # Generate content
        content = template.format(**template_data)
        
        return {
            'rule_name': rule.rule_name,
            'rule_id': rule.rule_id,
            'category': self.rule_analyzer.categorize_rule(rule),
            'priority': self.rule_analyzer.get_priority(rule),
            'status': rule.status,
            'content': content,
            'template_data': template_data
        }

    def _extract_service_account_name(self, rule: RuleInfo) -> str:
        """Extract service account name from rule"""
        if 'sa-' in rule.rule_name.lower():
            # Extract service account name from rule name
            parts = rule.rule_name.split()
            for part in parts:
                if part.lower().startswith('sa-'):
                    return part
        return "Unknown"

    def _extract_intended_purpose(self, rule: RuleInfo) -> str:
        """Extract intended purpose from rule description"""
        if 'misuse' in rule.rule_name.lower():
            return "Database/Application Service Account"
        return "Service Account"

    def _extract_authorized_systems(self, rule: RuleInfo) -> str:
        """Extract authorized systems from rule"""
        if 'sql' in rule.rule_name.lower():
            return "SQL Servers"
        elif 'jenkins' in rule.rule_name.lower():
            return "Jenkins Build Servers"
        elif 'firemon' in rule.rule_name.lower():
            return "Network Monitoring Systems"
        return "Authorized Systems"

    def _extract_access_level(self, rule: RuleInfo) -> str:
        """Extract access level from rule"""
        if 'admin' in rule.rule_name.lower():
            return "Administrative"
        elif 'sql' in rule.rule_name.lower():
            return "Database Access"
        return "Standard Access"

    def _extract_account_status(self, rule: RuleInfo) -> str:
        """Extract account status from rule"""
        return "Active" if rule.status == 'active' else "Inactive"

    def _extract_last_password_change(self, rule: RuleInfo) -> str:
        """Extract last password change from rule"""
        return "Within 30 days"  # Placeholder

    def _extract_group_memberships(self, rule: RuleInfo) -> str:
        """Extract group memberships from rule"""
        return "Service Accounts Group"

    def _extract_scheduled_tasks(self, rule: RuleInfo) -> str:
        """Extract scheduled tasks from rule"""
        return "Database maintenance, backups"

    def _extract_normal_usage_patterns(self, rule: RuleInfo) -> str:
        """Extract normal usage patterns from rule"""
        return "Regular database connections, scheduled jobs"

    def _extract_original_privileges(self, rule: RuleInfo) -> str:
        """Extract original privileges from rule"""
        if 'domain' in rule.rule_name.lower():
            return "Standard User"
        return "Standard Access"

    def _extract_escalated_privileges(self, rule: RuleInfo) -> str:
        """Extract escalated privileges from rule"""
        if 'admin' in rule.rule_name.lower():
            return "Administrative"
        return "Elevated Access"

    def _extract_escalation_method(self, rule: RuleInfo) -> str:
        """Extract escalation method from rule"""
        if 'group' in rule.rule_name.lower():
            return "Group Membership Change"
        return "Privilege Escalation"

    def _extract_target_systems(self, rule: RuleInfo) -> str:
        """Extract target systems from rule"""
        return "Domain Controllers, Critical Systems"

    def _extract_change_type(self, rule: RuleInfo) -> str:
        """Extract change type from rule"""
        if 'policy' in rule.rule_name.lower():
            return "Policy Change"
        return "Configuration Change"

    def _extract_changed_component(self, rule: RuleInfo) -> str:
        """Extract changed component from rule"""
        if 'delinea' in rule.rule_name.lower():
            return "Delinea Policy"
        return "System Configuration"

    def _extract_change_method(self, rule: RuleInfo) -> str:
        """Extract change method from rule"""
        return "Administrative Interface"

    def _extract_affected_systems(self, rule: RuleInfo) -> str:
        """Extract affected systems from rule"""
        return "Network Devices, Security Systems"

    def _extract_data_type(self, rule: RuleInfo) -> str:
        """Extract data type from rule"""
        if 'docx' in rule.rule_name.lower():
            return "Document Files"
        return "Sensitive Data"

    def _extract_exfiltration_method(self, rule: RuleInfo) -> str:
        """Extract exfiltration method from rule"""
        if 'powershell' in rule.rule_name.lower():
            return "PowerShell Script"
        return "Data Transfer"

    def _extract_destination(self, rule: RuleInfo) -> str:
        """Extract destination from rule"""
        return "External Destination"

    def _extract_data_volume(self, rule: RuleInfo) -> str:
        """Extract data volume from rule"""
        return "Multiple Files"

    def _extract_anomaly_type(self, rule: RuleInfo) -> str:
        """Extract anomaly type from rule"""
        if 'ssh' in rule.rule_name.lower():
            return "SSH Access Anomaly"
        return "Network Anomaly"

    def _extract_source_ip(self, rule: RuleInfo) -> str:
        """Extract source IP from rule"""
        return "External IP Address"

    def _extract_destination_ip(self, rule: RuleInfo) -> str:
        """Extract destination IP from rule"""
        return "Internal Network Device"

    def _extract_protocol(self, rule: RuleInfo) -> str:
        """Extract protocol from rule"""
        if 'ssh' in rule.rule_name.lower():
            return "SSH"
        return "Network Protocol"

    def _extract_port(self, rule: RuleInfo) -> str:
        """Extract port from rule"""
        if 'ssh' in rule.rule_name.lower():
            return "22"
        return "Standard Port"
    
    def generate_multi_rule_sop(self, rules: List[RuleInfo], category: str = None, output_format: str = "markdown") -> Dict[str, Any]:
        """Generate a single SOP document containing multiple rules"""
        if not rules:
            raise ValueError("No rules provided for multi-rule SOP generation")
        
        # Use the first rule's category if not specified
        if not category:
            category = self.rule_analyzer.categorize_rule(rules[0])
        
        # Generate individual SOPs for each rule
        individual_sops = []
        rule_summary_data = []
        
        for rule in rules:
            sop = self.generate_sop_from_rule(rule, output_format)
            individual_sops.append(sop)
            
            # Prepare summary data
            rule_summary_data.append({
                'rule_id': rule.rule_id,
                'rule_name': rule.rule_name,
                'priority': self.rule_analyzer.get_rule_priority(rule),
                'status': rule.status,
                'description': rule.description[:100] + "..." if len(rule.description) > 100 else rule.description
            })
        
        # Analyze common patterns and shared indicators
        common_patterns = self._analyze_common_patterns(rules)
        shared_indicators = self._analyze_shared_indicators(rules)
        escalation_matrix = self._create_escalation_matrix(rules)
        
        # Get multi-rule template
        template = SOPTemplates.get_multi_rule_template()
        
        # Prepare template data
        template_data = {
            'category_title': category.replace('_', ' ').title(),
            'rule_count': len(rules),
            'category': category,
            'rule_summary_table': self._format_rule_summary_table(rule_summary_data),
            'rules_content': self._format_individual_rules_content(individual_sops),
            'common_patterns': common_patterns,
            'shared_indicators': shared_indicators,
            'escalation_matrix': escalation_matrix,
            'generated_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'version': '1.0',
            'author': config.get_author(),
            'contact_email': config.get_contact_email()
        }
        
        # Generate multi-rule SOP content
        sop_content = template.format(**template_data)
        
        return {
            'category': category,
            'rule_count': len(rules),
            'content': sop_content,
            'template_data': template_data,
            'individual_sops': individual_sops,
            'generated_date': datetime.now().isoformat(),
            'version': '1.0',
            'output_format': output_format
        }
    
    def generate_sops_from_backup_summary(self, backup_summary_path: str, 
                                        output_format: str = "markdown",
                                        rule_filter: Optional[str] = None,
                                        status_filter: Optional[str] = None,
                                        multi_rule: bool = False,
                                        category_grouping: bool = False) -> List[Dict[str, Any]]:
        """Generate SOPs from backup summary file"""
        # Load backup summary
        backup_summary = self.rule_analyzer.load_backup_summary(backup_summary_path)
        
        # Extract rules
        rules = self.rule_analyzer.extract_rules(backup_summary)
        
        # Apply filters
        if rule_filter:
            rules = [r for r in rules if rule_filter.lower() in r.rule_name.lower()]
        
        if status_filter:
            rules = [r for r in rules if r.status.lower() == status_filter.lower()]
        
        if not rules:
            return []
        
        # Generate SOPs based on mode
        if multi_rule:
            # Generate single multi-rule SOP
            return [self.generate_multi_rule_sop(rules, output_format=output_format)]
        elif category_grouping:
            # Group by category and generate multi-rule SOPs
            categories = {}
            for rule in rules:
                category = self.rule_analyzer.categorize_rule(rule)
                if category not in categories:
                    categories[category] = []
                categories[category].append(rule)
            
            multi_rule_sops = []
            for category, category_rules in categories.items():
                if len(category_rules) > 1:
                    multi_rule_sops.append(self.generate_multi_rule_sop(category_rules, category, output_format))
                else:
                    # Single rule in category, generate individual SOP
                    multi_rule_sops.append(self.generate_sop_from_rule(category_rules[0], output_format))
            
            return multi_rule_sops
        else:
            # Generate individual SOPs
            return [self.generate_sop_from_rule(rule, output_format) for rule in rules]
    
    def generate_sops_from_input_file(self, input_file: str, 
                                    input_format: Optional[str] = None,
                                    output_format: str = "markdown",
                                    rule_filter: Optional[str] = None,
                                    status_filter: Optional[str] = None,
                                    multi_rule: bool = False,
                                    category_grouping: bool = False) -> List[Dict[str, Any]]:
        """Generate SOPs from various input file formats"""
        # Determine input format if auto
        if input_format == 'auto':
            input_format = InputParserFactory.detect_format(input_file)
        
        # Parse input file
        parsed_rules = InputParserFactory.parse_file(input_file, input_format)
        
        # Convert ParsedRule to RuleInfo
        rules = []
        for parsed_rule in parsed_rules:
            rule_info = RuleInfo(
                rule_id=parsed_rule.rule_id,
                rule_name=parsed_rule.rule_name,
                description=parsed_rule.description,
                search_filter=parsed_rule.search_filter,
                search_outcome=parsed_rule.search_outcome,
                status=parsed_rule.status,
                created_on=parsed_rule.created_on,
                last_updated_on=parsed_rule.last_updated_on,
                filename=f"{parsed_rule.rule_id}.json",
                file_size=len(str(parsed_rule)),
                timestamp=parsed_rule.created_on
            )
            rules.append(rule_info)
        
        # Apply filters
        if rule_filter:
            rules = [r for r in rules if rule_filter.lower() in r.rule_name.lower()]
        
        if status_filter:
            rules = [r for r in rules if r.status.lower() == status_filter.lower()]
        
        if not rules:
            return []
        
        # Generate SOPs based on mode
        if multi_rule:
            # Generate single multi-rule SOP
            return [self.generate_multi_rule_sop(rules, output_format=output_format)]
        elif category_grouping:
            # Group by category and generate multi-rule SOPs
            categories = {}
            for rule in rules:
                category = self.rule_analyzer.categorize_rule(rule)
                if category not in categories:
                    categories[category] = []
                categories[category].append(rule)
            
            multi_rule_sops = []
            for category, category_rules in categories.items():
                if len(category_rules) > 1:
                    multi_rule_sops.append(self.generate_multi_rule_sop(category_rules, category, output_format))
                else:
                    # Single rule in category, generate individual SOP
                    multi_rule_sops.append(self.generate_sop_from_rule(category_rules[0], output_format))
            
            return multi_rule_sops
        else:
            # Generate individual SOPs
            return [self.generate_sop_from_rule(rule, output_format) for rule in rules]
    
    def generate_sops(self, input_file: str, 
                     input_format: Optional[str] = None,
                     output_format: str = "markdown",
                     rule_filter: Optional[str] = None,
                     status_filter: Optional[str] = None,
                     category_filter: Optional[str] = None,
                     priority_filter: Optional[str] = None,
                     dry_run: bool = False,
                     streaming: bool = False,
                     paginated: bool = False,
                     with_fallback: bool = False) -> List[Dict[str, Any]]:
        """Generate SOPs from input file - main entry point for CLI"""
        return self.generate_sops_from_input_file(
            input_file, input_format, output_format,
            rule_filter, status_filter, False, False
        )
    
    def upload_to_confluence(self, input_file: str, 
                           input_format: Optional[str] = None,
                           confluence_url: str = None,
                           confluence_username: str = None,
                           confluence_token: str = None,
                           confluence_space: str = None,
                           confluence_parent: str = None,
                           confluence_folder: str = None,
                           rule_filter: Optional[str] = None,
                           status_filter: Optional[str] = None,
                           category_filter: Optional[str] = None,
                           priority_filter: Optional[str] = None,
                           update_existing: bool = False,
                           as_draft: bool = False,
                           save_locally: bool = False,
                           dry_run: bool = False,
                           sort_alphabetically: bool = True) -> bool:
        """Upload SOPs to Confluence - main entry point for CLI"""
        try:
            # Import here to avoid circular imports
            from src.confluence_api import ConfluenceAPI
            
            # Initialize Confluence API
            confluence_api = ConfluenceAPI(
                base_url=confluence_url,
                username=confluence_username,
                api_token=confluence_token,
                space_key=confluence_space
            )
            
            # Generate SOPs
            sops = self.generate_sops_from_input_file(
                input_file, input_format, "confluence",
                rule_filter, status_filter, False, False
            )
            
            if not sops:
                return False
            
            # Sort SOPs alphabetically if requested
            if sort_alphabetically:
                sops = sorted(sops, key=lambda x: x.get('rule_name', '').lower())
                logger.info(f"Sorted {len(sops)} SOPs alphabetically")
            
            # Upload each SOP
            for sop in sops:
                if dry_run:
                    print(f"Would upload: {sop.get('rule_name', 'Unknown')}")
                else:
                    # For now, let's upload directly without drafts to avoid the folder creation issue
                    confluence_api.upload_sop(
                        sop, 
                        update_existing=update_existing,
                        as_draft=False,  # Don't use drafts for now
                        target_folder=confluence_folder,
                        parent_page_id=confluence_parent
                    )
            
            return True
            
        except Exception as e:
            logger.error(f"Error uploading to Confluence: {e}")
            return False
    
    def save_sop_to_file(self, sop: Dict[str, Any], output_format: str = "markdown") -> str:
        """Save SOP to file"""
        # Handle multi-rule SOPs vs individual SOPs
        if 'rule_name' in sop:
            # Individual SOP
            safe_rule_name = self._sanitize_filename(sop['rule_name'])
        else:
            # Multi-rule SOP
            category = sop.get('category', 'multi_rule')
            rule_count = sop.get('rule_count', 0)
            safe_rule_name = self._sanitize_filename(f"{category}_{rule_count}_rules")
        
        # Determine file extension based on output format
        if output_format == "confluence":
            file_extension = ".confluence"
        elif output_format == "html":
            file_extension = ".html"
        elif output_format == "json":
            file_extension = ".json"
        elif output_format == "pdf":
            file_extension = ".md"  # PDF format now generates markdown
        else:
            file_extension = ".md"
        
        filename = f"{safe_rule_name}_SOP{file_extension}"
        filepath = self.output_dir / filename
        
        # Save content based on format
        with open(filepath, 'w', encoding='utf-8') as f:
            if output_format == "json":
                # For JSON format, save the structured data
                json.dump(sop, f, indent=2, ensure_ascii=False)
            elif output_format == "confluence":
                content = self.confluence_formatter.format_sop_for_confluence(sop)
                f.write(content)
            else:
                # For other formats (markdown, html, pdf), save the content directly
                f.write(sop['content'])
        
        return str(filepath)
    
    def generate_pdf_sop(self, sop_data: Dict[str, Any]) -> str:
        """Generate actual PDF file using WeasyPrint"""
        try:
            from weasyprint import HTML, CSS
            
            # Convert markdown to HTML
            html_content = self.convert_markdown_to_html(sop_data['content'])
            
            # Add CSS styling
            css = CSS(string='''
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 2cm; 
                    line-height: 1.6;
                    color: #333;
                }
                h1 { 
                    color: #2c3e50; 
                    border-bottom: 2px solid #3498db; 
                    padding-bottom: 10px;
                    font-size: 24px;
                }
                h2 { 
                    color: #34495e; 
                    margin-top: 1.5em; 
                    font-size: 20px;
                    border-left: 4px solid #3498db;
                    padding-left: 10px;
                }
                h3 { 
                    color: #2c3e50; 
                    margin-top: 1.2em;
                    font-size: 16px;
                }
                .mitre-section { 
                    background: #f8f9fa; 
                    padding: 1em; 
                    border-left: 4px solid #e74c3c; 
                    margin: 1em 0;
                    border-radius: 4px;
                }
                .technical-details { 
                    background: #ecf0f1; 
                    padding: 1em; 
                    margin: 1em 0; 
                    border-radius: 4px;
                    border-left: 4px solid #e74c3c;
                }
                .escalation-criteria {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }
                .response-actions {
                    background: #d1ecf1;
                    border: 1px solid #bee5eb;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 15px 0;
                }
                table { 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 15px 0;
                }
                th, td { 
                    border: 1px solid #bdc3c7; 
                    padding: 8px; 
                    text-align: left; 
                }
                th { 
                    background-color: #3498db; 
                    color: white; 
                    font-weight: bold;
                }
                tr:nth-child(even) { 
                    background-color: #f8f9fa; 
                }
                .confidence-high { 
                    color: #27ae60; 
                    font-weight: bold; 
                }
                .confidence-medium { 
                    color: #f39c12; 
                    font-weight: bold; 
                }
                .confidence-low { 
                    color: #e74c3c; 
                    font-weight: bold; 
                }
                .code-block { 
                    background: #2c3e50; 
                    color: #ecf0f1; 
                    padding: 15px; 
                    border-radius: 5px; 
                    font-family: 'Courier New', monospace; 
                    overflow-x: auto; 
                    margin: 10px 0;
                }
                .alert { 
                    background: #f8d7da; 
                    border: 1px solid #f5c6cb; 
                    color: #721c24; 
                    padding: 15px; 
                    border-radius: 5px; 
                    margin: 15px 0; 
                }
                .info { 
                    background: #d1ecf1; 
                    border: 1px solid #bee5eb; 
                    color: #0c5460; 
                    padding: 15px; 
                    border-radius: 5px; 
                    margin: 15px 0; 
                }
                .success { 
                    background: #d4edda; 
                    border: 1px solid #c3e6cb; 
                    color: #155724; 
                    padding: 15px; 
                    border-radius: 5px; 
                    margin: 15px 0; 
                }
                .page-break {
                    page-break-before: always;
                }
                @media print {
                    body { margin: 1cm; }
                    .page-break { page-break-before: always; }
                }
            ''')
            
            # Generate PDF
            html = HTML(string=html_content)
            pdf_bytes = html.write_pdf(stylesheets=[css])
            
            # Save to file
            filename = f"{sop_data['rule_name']}_SOP.pdf"
            filepath = self.output_dir / filename
            with open(filepath, 'wb') as f:
                f.write(pdf_bytes)
            
            logger.info(f"Generated PDF: {filepath}")
            return str(filepath)
            
        except ImportError:
            logger.error("WeasyPrint not available. Install with: pip install weasyprint")
            raise ValueError("PDF generation requires WeasyPrint. Install with: pip install weasyprint")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise
    
    def convert_markdown_to_html(self, markdown_content: str) -> str:
        """Convert markdown content to HTML"""
        import markdown
        
        # Configure markdown extensions
        extensions = [
            'markdown.extensions.tables',
            'markdown.extensions.fenced_code',
            'markdown.extensions.codehilite',
            'markdown.extensions.toc'
        ]
        
        # Convert markdown to HTML
        html_content = markdown.markdown(markdown_content, extensions=extensions)
        
        # Wrap in HTML document structure
        html_doc = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC SOP Document</title>
</head>
<body>
    {html_content}
</body>
</html>
        """
        
        return html_doc
    
    def generate_sop_with_fallback(self, rule: RuleInfo) -> Dict[str, Any]:
        """Generate SOP with fallback options if primary method fails"""
        try:
            # Validate rule first
            validation_issues = self.input_validator.validate_rule_completeness(rule)
            error_issues = [i for i in validation_issues if i.severity == 'error']
            
            if error_issues:
                logger.warning(f"Rule {rule.rule_name} has validation errors: {error_issues}")
            
            # Try primary generation method
            return self.generate_sop_from_rule(rule)
        except Exception as e:
            # Log the error
            logger.error(f"Primary SOP generation failed for {rule.rule_name}: {e}")
            
            # Try fallback method with minimal template
            try:
                return self.generate_minimal_sop(rule)
            except Exception as e2:
                logger.error(f"Fallback SOP generation also failed for {rule.rule_name}: {e2}")
                
                # Return error SOP
                return {
                    'rule_name': rule.rule_name,
                    'error': True,
                    'error_message': str(e),
                    'content': f"""# {rule.rule_name} - GENERATION ERROR

This SOP could not be generated due to an error: {e}

## Error Details
- **Primary Error:** {e}
- **Fallback Error:** {e2}
- **Rule ID:** {rule.rule_id}
- **Status:** {rule.status}

## Contact Information
Please contact the development team for assistance.

## Manual Steps Required
1. Review the rule configuration
2. Check for syntax errors in search filter
3. Verify all required fields are present
4. Regenerate the SOP manually if needed
                    """
                }
    
    def generate_minimal_sop(self, rule: RuleInfo) -> Dict[str, Any]:
        """Generate minimal SOP when primary method fails"""
        return {
            'rule_name': rule.rule_name,
            'rule_id': rule.rule_id,
            'status': rule.status,
            'priority': 'unknown',
            'category': 'unknown',
            'created_on': rule.created_on,
            'last_updated_on': rule.last_updated_on,
            'description': rule.description,
            'search_outcome': rule.search_outcome,
            'search_filter': rule.search_filter,
            'complexity': 'unknown',
            'data_sources': 'unknown',
            'event_types': 'unknown',
            'attack_mapping': 'Unable to generate MITRE ATT&CK mapping',
            'confidence_level': 'unknown',
            'key_indicators': ['Unable to extract key indicators'],
            'false_positive_indicators': ['Unable to extract false positive indicators'],
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'version': '1.0',
            'last_reviewed': datetime.now().strftime('%Y-%m-%d'),
            'author': config.get_author(),
            'contact_email': config.get_contact_email(),
            'content': f"""# {rule.rule_name} Operating Procedure

## Rule Information

**Rule ID:** {rule.rule_id}  
**Status:** {rule.status}  
**Created:** {rule.created_on}  
**Last Updated:** {rule.last_updated_on}  

## Description

{rule.description}

## Search Filter

```
{rule.search_filter}
```

## Search Outcome

{rule.search_outcome}

## Note

This SOP was generated with minimal information due to processing errors. Please review and enhance manually.

## Contact Information

**Author:** {config.get_author()}  
**Contact:** {config.get_contact_email()}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
        }
    
    def generate_sops_streaming(self, backup_summary_path: str, **kwargs) -> Iterator[Dict[str, Any]]:
        """Generate SOPs using streaming to reduce memory usage"""
        backup_summary = self.rule_analyzer.load_backup_summary(backup_summary_path)
        
        for rule_data in backup_summary['saved_rules']:
            # Process one rule at a time
            rule = self.rule_analyzer.create_rule_info(rule_data)
            
            # Apply filters
            if self._should_include_rule(rule, kwargs):
                sop = self.generate_sop_with_fallback(rule)
                yield sop
    
    def _should_include_rule(self, rule: RuleInfo, filters: Dict[str, Any]) -> bool:
        """Check if rule should be included based on filters"""
        # Rule filter
        if 'rule_filter' in filters and filters['rule_filter']:
            if filters['rule_filter'].lower() not in rule.rule_name.lower():
                return False
        
        # Status filter
        if 'status_filter' in filters and filters['status_filter']:
            if filters['status_filter'].lower() != rule.status.lower():
                return False
        
        return True
    
    def generate_paginated_sop(self, rules: List[RuleInfo], category: str) -> List[Dict[str, Any]]:
        """Generate paginated SOPs for large categories"""
        MAX_RULES_PER_PAGE = 20
        pages = []
        
        for i in range(0, len(rules), MAX_RULES_PER_PAGE):
            page_rules = rules[i:i + MAX_RULES_PER_PAGE]
            page_number = (i // MAX_RULES_PER_PAGE) + 1
            
            sop_data = {
                'category': category,
                'rule_count': len(page_rules),
                'page_number': page_number,
                'total_pages': (len(rules) + MAX_RULES_PER_PAGE - 1) // MAX_RULES_PER_PAGE,
                'rules': page_rules,
                'content': self._generate_paginated_content(page_rules, page_number)
            }
            pages.append(sop_data)
        
        return pages
    
    def _generate_paginated_content(self, rules: List[RuleInfo], page_number: int) -> str:
        """Generate content for a paginated SOP"""
        content = f"""# {rules[0].rule_name.split('_')[0]} Rules - Page {page_number}

## Rules in this page:

"""
        
        for i, rule in enumerate(rules, 1):
            content += f"""
### {i}. {rule.rule_name}

**Rule ID:** {rule.rule_id}  
**Status:** {rule.status}  
**Description:** {rule.description}

**Search Filter:**
```
{rule.search_filter}
```

---
"""
        
        return content
    
    def save_sops_batch(self, sops: List[Dict[str, Any]], 
                       output_format: str = "markdown") -> List[str]:
        """Save multiple SOPs to files"""
        saved_files = []
        
        for sop in sops:
            try:
                filepath = self.save_sop_to_file(sop, output_format)
                saved_files.append(filepath)
            except Exception as e:
                # Handle both individual and multi-rule SOPs in error message
                if 'rule_name' in sop:
                    logger.error(f"Error saving SOP for {sop['rule_name']}: {e}")
                else:
                    category = sop.get('category', 'Unknown')
                    rule_count = sop.get('rule_count', 0)
                    logger.error(f"Error saving multi-rule SOP for {category} ({rule_count} rules): {e}")
        
        return saved_files
    
    def create_confluence_export(self, sops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create Confluence export structure"""
        confluence_pages = []
        
        for sop in sops:
            # Format content for Confluence
            confluence_content = self.confluence_formatter.format_sop_for_confluence(sop)
            
            # Create page structure
            page_structure = self.confluence_formatter.create_confluence_page_structure(
                confluence_content, 
                sop['rule_name']
            )
            
            # Add metadata
            metadata = self.confluence_formatter.create_confluence_metadata({
                'rule_id': sop['rule_id'],
                'rule_name': sop['rule_name'],
                'status': sop.get('template_data', {}).get('status', ''),
                'priority': sop['priority'],
                'category': sop['category']
            })
            
            page_structure.update(metadata)
            confluence_pages.append(page_structure)
        
        return {
            'export_date': datetime.now().isoformat(),
            'total_pages': len(confluence_pages),
            'pages': confluence_pages
        }
    
    def save_confluence_export(self, confluence_export: Dict[str, Any], 
                             filename: str = "confluence_export.json") -> str:
        """Save Confluence export to JSON file"""
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(confluence_export, f, indent=2)
        
        return str(filepath)
    
    def generate_sop_summary(self, sops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of generated SOPs"""
        categories = {}
        priorities = {}
        total_rules = len(sops)
        
        for sop in sops:
            if 'rule_name' in sop:
                # Individual SOP
                category = sop['category']
                priority = sop['priority']
                
                categories[category] = categories.get(category, 0) + 1
                priorities[priority] = priorities.get(priority, 0) + 1
            else:
                # Multi-rule SOP
                category = sop.get('category', 'Unknown')
                rule_count = sop.get('rule_count', 0)
                categories[category] = categories.get(category, 0) + 1
                priorities['multi_rule'] = priorities.get('multi_rule', 0) + 1
        
        sop_list = []
        for sop in sops:
            if 'rule_name' in sop:
                # Individual SOP
                sop_list.append({
                    'rule_name': sop['rule_name'],
                    'rule_id': sop['rule_id'],
                    'category': sop['category'],
                    'priority': sop['priority'],
                    'status': sop.get('template_data', {}).get('status', 'Unknown')
                })
            else:
                # Multi-rule SOP
                sop_list.append({
                    'rule_name': f"Multi-rule SOP: {sop.get('category', 'Unknown')}",
                    'rule_id': f"multi_rule_{sop.get('category', 'unknown')}",
                    'category': sop.get('category', 'Unknown'),
                    'priority': 'multi_rule',
                    'status': 'Active'
                })
        
        return {
            'total_sops': total_rules,
            'categories': categories,
            'priorities': priorities,
            'generated_date': datetime.now().isoformat(),
            'sop_list': sop_list
        }
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe file system use"""
        # Remove or replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Replace spaces with underscores
        filename = filename.replace(' ', '_')
        
        # Limit length
        if len(filename) > 100:
            filename = filename[:100]
        
        return filename
    
    def _format_list(self, items: List[str]) -> str:
        """Format list items for template insertion"""
        if not items:
            return "None identified"
        
        formatted_items = []
        for item in items:
            if item.strip():
                formatted_items.append(f"- {item.strip()}")
        
        return '\n'.join(formatted_items) if formatted_items else "None identified"
    
    def _format_list_markdown(self, items: List[str]) -> str:
        """Format list as markdown"""
        if not items:
            return "None identified"
        return '\n'.join([f"- {item}" for item in items])

    def _format_list_html(self, items: List[str]) -> str:
        """Format list as HTML"""
        if not items:
            return "<p>None identified</p>"
        html_items = [f"<li>{item}</li>" for item in items]
        return f"<ul>{''.join(html_items)}</ul>"
    
    def _format_attack_mapping(self, attack_summary: Dict[str, Any]) -> str:
        """Format MITRE ATT&CK mapping for template insertion"""
        if not attack_summary or not attack_summary.get('mapped', False):
            return "No MITRE ATT&CK mapping found for this rule."
        
        formatted_mapping = []
        
        # Add primary tactic information
        if attack_summary.get('primary_tactic'):
            tactic = attack_summary['primary_tactic'].replace('_', ' ').title()
            description = attack_summary.get('tactic_description', '')
            formatted_mapping.append(f"**Primary Tactic:** {tactic}")
            if description:
                formatted_mapping.append(f"**Tactic Description:** {description}")
            formatted_mapping.append("")
        
        # Add mapped techniques
        if attack_summary.get('techniques'):
            formatted_mapping.append("**Mapped Techniques:**")
            for technique in attack_summary['techniques']:
                formatted_mapping.append(f"- **{technique['id']}** - {technique['name']}")
                formatted_mapping.append(f"  - Tactic: {technique['tactic'].replace('_', ' ').title()}")
                formatted_mapping.append(f"  - Description: {technique['description']}")
                formatted_mapping.append(f"  - [View on MITRE ATT&CK]({technique['url']})")
                formatted_mapping.append("")
        
        return '\n'.join(formatted_mapping) if formatted_mapping else "No MITRE ATT&CK mapping found for this rule."
    
    def _format_attack_mapping_html(self, attack_summary: Dict[str, Any]) -> str:
        """Format MITRE ATT&CK mapping for HTML template insertion"""
        if not attack_summary or not attack_summary.get('mapped', False):
            return "No MITRE ATT&CK mapping found for this rule."
        
        formatted_mapping = []
        
        # Add primary tactic information
        if attack_summary.get('primary_tactic'):
            tactic = attack_summary['primary_tactic'].replace('_', ' ').title()
            description = attack_summary.get('tactic_description', '')
            formatted_mapping.append(f"<strong>Primary Tactic:</strong> {tactic}")
            if description:
                formatted_mapping.append(f"<strong>Tactic Description:</strong> {description}")
            formatted_mapping.append("")
        
        # Add mapped techniques
        if attack_summary.get('techniques'):
            formatted_mapping.append("<strong>Mapped Techniques:</strong>")
            for technique in attack_summary['techniques']:
                formatted_mapping.append(f"<li><strong>{technique['id']}</strong> - {technique['name']}</li>")
                formatted_mapping.append(f"  - Tactic: {technique['tactic'].replace('_', ' ').title()}")
                formatted_mapping.append(f"  - Description: {technique['description']}")
                formatted_mapping.append(f"  - <a href=\"{technique['url']}\" target=\"_blank\">View on MITRE ATT&CK</a>")
                formatted_mapping.append("")
        
        return '\n'.join(formatted_mapping) if formatted_mapping else "No MITRE ATT&CK mapping found for this rule."
    
    def _format_rule_summary_table(self, rule_summary_data: List[Dict[str, Any]]) -> str:
        """Format rule summary data for multi-rule SOP template"""
        if not rule_summary_data:
            return "No rules to summarize."
        
        headers = ["Rule ID", "Rule Name", "Priority", "Status", "Description"]
        rows = []
        for rule in rule_summary_data:
            rows.append([
                f"<strong>{rule['rule_id']}</strong>",
                f"<strong>{rule['rule_name']}</strong>",
                f"<strong>{rule['priority']}</strong>",
                f"<strong>{rule['status']}</strong>",
                f"<em>{rule['description']}</em>"
            ])
        
        return self.confluence_formatter.format_table(headers, rows)
    
    def _format_individual_rules_content(self, individual_sops: List[Dict[str, Any]]) -> str:
        """Format individual SOP content for multi-rule SOP template"""
        if not individual_sops:
            return "No individual SOPs to include."
        
        content_blocks = []
        for sop in individual_sops:
            content_blocks.append(f"== {sop['rule_name']} ==")
            content_blocks.append(sop['content'])
            content_blocks.append("") # Add an empty line for separation
        
        return "\n\n".join(content_blocks)
    
    def _analyze_common_patterns(self, rules: List[RuleInfo]) -> str:
        """Analyze common patterns across multiple rules"""
        if len(rules) < 2:
            return "Not enough rules to analyze common patterns."
        
        common_patterns = []
        for i in range(len(rules)):
            for j in range(i + 1, len(rules)):
                common_search_filters = self._find_common_search_filters(rules[i].search_filter, rules[j].search_filter)
                if common_search_filters:
                    common_patterns.append(f"Rule {rules[i].rule_id} and Rule {rules[j].rule_id} share common search filters: {', '.join(common_search_filters)}")
        
        return "\n".join(common_patterns) if common_patterns else "No common search filters found across rules."
    
    def _analyze_shared_indicators(self, rules: List[RuleInfo]) -> str:
        """Analyze shared indicators across multiple rules"""
        if len(rules) < 2:
            return "Not enough rules to analyze shared indicators."
        
        shared_indicators = []
        for i in range(len(rules)):
            for j in range(i + 1, len(rules)):
                # Extract key indicators for each rule
                key_indicators_i = self.rule_analyzer.extract_key_indicators(rules[i])
                key_indicators_j = self.rule_analyzer.extract_key_indicators(rules[j])
                shared_key_indicators = self._find_shared_key_indicators(key_indicators_i, key_indicators_j)
                if shared_key_indicators:
                    shared_indicators.append(f"Rule {rules[i].rule_id} and Rule {rules[j].rule_id} share common key indicators: {', '.join(shared_key_indicators)}")
        
        return "\n".join(shared_indicators) if shared_indicators else "No shared key indicators found across rules."
    
    def _create_escalation_matrix(self, rules: List[RuleInfo]) -> str:
        """Create an escalation matrix for multiple rules"""
        if len(rules) < 2:
            return "Not enough rules to create an escalation matrix."
        
        escalation_matrix = []
        for i in range(len(rules)):
            escalation_row = [f"<strong>Rule {rules[i].rule_id}</strong>"]
            for j in range(len(rules)):
                if i == j:
                    escalation_row.append("Self")
                else:
                    # Simple check: if one rule's search filter contains the other's search filter
                    # This is a very basic escalation logic and might need refinement
                    if rules[i].search_filter in rules[j].search_filter:
                        escalation_row.append("Escalates")
                    elif rules[j].search_filter in rules[i].search_filter:
                        escalation_row.append("Escalated By")
                    else:
                        escalation_row.append("No Escalation")
            escalation_matrix.append(" | ".join(escalation_row))
        
        return "\n".join(escalation_matrix)
    
    def _find_common_search_filters(self, filter1: str, filter2: str) -> List[str]:
        """Find common search filters between two filters"""
        filter1_parts = self._parse_search_filter(filter1)
        filter2_parts = self._parse_search_filter(filter2)
        
        common_parts = []
        for part in filter1_parts:
            if part in filter2_parts:
                common_parts.append(part)
        
        return common_parts
    
    def _find_shared_key_indicators(self, indicators1: List[str], indicators2: List[str]) -> List[str]:
        """Find shared key indicators between two lists"""
        shared_indicators = []
        for indicator in indicators1:
            if indicator in indicators2:
                shared_indicators.append(indicator)
        return shared_indicators
    
    def _parse_search_filter(self, filter_string: str) -> List[str]:
        """Parse a search filter string into individual components"""
        # This is a simplified parser. A more robust one would handle operators, ranges, etc.
        return [part.strip() for part in filter_string.split(',') if part.strip()]
    
    def get_rule_statistics(self, backup_summary_path: str) -> Dict[str, Any]:
        """Get statistics about rules in backup summary"""
        backup_summary = self.rule_analyzer.load_backup_summary(backup_summary_path)
        rules = self.rule_analyzer.extract_rules(backup_summary)
        
        return self._calculate_statistics(rules)

    def get_input_file_statistics(self, input_file: str, input_format: Optional[str] = None) -> Dict[str, Any]:
        """Get statistics about rules in any input file format"""
        parsed_rules = InputParserFactory.parse_file(input_file, input_format)
        
        # Convert ParsedRule to RuleInfo for analysis
        rules = []
        for parsed_rule in parsed_rules:
            rule_info = RuleInfo(
                rule_id=parsed_rule.rule_id,
                rule_name=parsed_rule.rule_name,
                description=parsed_rule.description,
                search_filter=parsed_rule.search_filter,
                search_outcome=parsed_rule.search_outcome,
                status=parsed_rule.status,
                created_on=parsed_rule.created_on,
                last_updated_on=parsed_rule.last_updated_on,
                filename=f"{parsed_rule.rule_id}.json",
                file_size=len(str(parsed_rule)),
                timestamp=parsed_rule.created_on
            )
            rules.append(rule_info)
        
        return self._calculate_statistics(rules)

    def _calculate_statistics(self, rules: List[RuleInfo]) -> Dict[str, Any]:
        """Calculate statistics for a list of rules"""
        stats = {
            'total_rules': len(rules),
            'active_rules': len([r for r in rules if r.status.lower() == 'active']),
            'inactive_rules': len([r for r in rules if r.status.lower() == 'inactive']),
            'categories': {},
            'priorities': {},
            'complexity_levels': {}
        }
        
        for rule in rules:
            category = self.rule_analyzer.categorize_rule(rule)
            priority = self.rule_analyzer.get_rule_priority(rule)
            filter_analysis = self.rule_analyzer.analyze_search_filter(rule.search_filter)
            
            stats['categories'][category] = stats['categories'].get(category, 0) + 1
            stats['priorities'][priority] = stats['priorities'].get(priority, 0) + 1
            stats['complexity_levels'][filter_analysis['complexity']] = stats['complexity_levels'].get(filter_analysis['complexity'], 0) + 1
        
        return stats 