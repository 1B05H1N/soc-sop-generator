"""
Rule Analyzer Module

This module handles the analysis and extraction of information from security correlation rules.
Includes MITRE ATT&CK mapping for threat intelligence.
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass

from src.mitre_attack_mapper import MitreAttackMapper, AttackTechnique


@dataclass
class RuleInfo:
    """Data class for storing rule information"""
    rule_id: str
    rule_name: str
    description: str
    search_outcome: str
    search_filter: str
    created_on: str
    last_updated_on: str
    status: str
    filename: str
    file_size: int
    timestamp: str
    attack_techniques: Optional[List] = None


class RuleAnalyzer:
    """Analyzes correlation rules and extracts key information with MITRE ATT&CK mapping"""
    
    def __init__(self):
        # Initialize MITRE ATT&CK mapper
        self.mitre_mapper = MitreAttackMapper()
        
        self.rule_categories = {
            'service_account_misuse': [
                r'sa-.*misuse',
                r'service.*account.*misuse',
                r'sa_.*misuse'
            ],
            'authentication_anomaly': [
                r'authentication.*anomaly',
                r'auth.*anomaly',
                r'login.*anomaly',
                r'sign.*in.*anomaly'
            ],
            'configuration_change': [
                r'configuration.*change',
                r'config.*change',
                r'policy.*change',
                r'setting.*change'
            ],
            'privilege_escalation': [
                r'privilege.*escalation',
                r'elevation.*privilege',
                r'admin.*privilege',
                r'domain.*admin'
            ],
            'data_exfiltration': [
                r'data.*exfiltration',
                r'data.*leak',
                r'file.*copy',
                r'document.*access'
            ],
            'network_anomaly': [
                r'network.*anomaly',
                r'connection.*anomaly',
                r'port.*scan',
                r'network.*scan'
            ]
        }
    
    def load_backup_summary(self, file_path: str) -> Dict[str, Any]:
        """Load backup summary from JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load backup summary: {e}")
    
    def extract_rules(self, backup_summary: Dict[str, Any]) -> List[RuleInfo]:
        """Extract rule information from backup summary with MITRE ATT&CK mapping"""
        rules = []
        
        if 'saved_rules' not in backup_summary:
            raise ValueError("No saved_rules found in backup summary")
        
        for rule_data in backup_summary['saved_rules']:
            # Map rule to MITRE ATT&CK
            attack_mapping = self.mitre_mapper.map_rule_to_attack(
                rule_data.get('rule_name', ''),
                rule_data.get('description', ''),
                rule_data.get('search_filter', '')
            )
            
            rule = RuleInfo(
                rule_id=rule_data.get('rule_id', ''),
                rule_name=rule_data.get('rule_name', ''),
                description=rule_data.get('description', ''),
                search_outcome=rule_data.get('search_outcome', ''),
                search_filter=rule_data.get('search_filter', ''),
                created_on=rule_data.get('created_on', ''),
                last_updated_on=rule_data.get('last_updated_on', ''),
                status=rule_data.get('status', ''),
                filename=rule_data.get('filename', ''),
                file_size=rule_data.get('file_size', 0),
                timestamp=rule_data.get('timestamp', ''),
                attack_techniques=attack_mapping.get('techniques', [])
            )
            rules.append(rule)
        
        return rules
    
    def categorize_rule(self, rule: RuleInfo) -> str:
        """Categorize a rule based on its name and description"""
        text_to_check = f"{rule.rule_name} {rule.description}".lower()
        
        for category, patterns in self.rule_categories.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    return category
        
        return 'general'
    
    def analyze_search_filter(self, search_filter: str) -> Dict[str, Any]:
        """Analyze the search filter to extract key information"""
        analysis = {
            'event_types': [],
            'data_sources': [],
            'exclusions': [],
            'grouping': [],
            'complexity': 'low'
        }
        
        # Extract event types
        event_patterns = [
            r'#type\s*=\s*["\']([^"\']+)["\']',
            r'#type\s*=\s*([^\s|]+)',
            r'Vendor\.Event\.System\.EventID',
            r'event\.category'
        ]
        
        for pattern in event_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            analysis['event_types'].extend(matches)
        
        # Extract data sources
        data_source_patterns = [
            r'microsoft-windows',
            r'azure',
            r'entraid',
            r'cisco',
            r'sql',
            r'delinea'
        ]
        
        for pattern in data_source_patterns:
            if re.search(pattern, search_filter, re.IGNORECASE):
                analysis['data_sources'].append(pattern)
        
        # Extract exclusions
        exclusion_patterns = [
            r'!in\([^)]+\)',
            r'!match\([^)]+\)',
            r'!in\([^)]+\)',
            r'exclude',
            r'not.*in'
        ]
        
        for pattern in exclusion_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            analysis['exclusions'].extend(matches)
        
        # Extract grouping
        grouping_patterns = [
            r'groupBy\([^)]+\)',
            r'collect\([^)]+\)',
            r'table\([^)]+\)'
        ]
        
        for pattern in grouping_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            analysis['grouping'].extend(matches)
        
        # Determine complexity
        if len(search_filter.split('\n')) > 10 or len(analysis['exclusions']) > 3:
            analysis['complexity'] = 'high'
        elif len(search_filter.split('\n')) > 5 or len(analysis['exclusions']) > 1:
            analysis['complexity'] = 'medium'
        
        return analysis
    
    def extract_key_indicators(self, rule: RuleInfo) -> List[str]:
        """Extract key indicators from the rule"""
        indicators = []
        
        # Extract user accounts from search filter
        user_patterns = [
            r'user\.name\s*=\s*["\']([^"\']+)["\']',
            r'user\.target\.name\s*=\s*["\']([^"\']+)["\']',
            r'user\.name\s*=\s*/([^/]+)/',
            r'user\.target\.name\s*=\s*/([^/]+)/'
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, rule.search_filter, re.IGNORECASE)
            indicators.extend(matches)
        
        # Extract host names
        host_patterns = [
            r'host\.name\s*=\s*["\']([^"\']+)["\']',
            r'host\.name\s*=\s*/([^/]+)/',
            r'!in\(host\.name,\s*values=\[([^\]]+)\]'
        ]
        
        for pattern in host_patterns:
            matches = re.findall(pattern, rule.search_filter, re.IGNORECASE)
            indicators.extend(matches)
        
        # Extract IP addresses
        ip_patterns = [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            r'source\.ip\s*!=\s*([^\s]+)',
            r'!in\(source\.ip,\s*values=\[([^\]]+)\]'
        ]
        
        for pattern in ip_patterns:
            matches = re.findall(pattern, rule.search_filter, re.IGNORECASE)
            indicators.extend(matches)
        
        return list(set(indicators))  # Remove duplicates
    
    def get_rule_priority(self, rule: RuleInfo) -> str:
        """Determine rule priority based on various factors"""
        priority_score = 0
        
        # Check if rule is active
        if rule.status.lower() == 'active':
            priority_score += 3
        
        # Check search outcome
        if rule.search_outcome.lower() == 'incident':
            priority_score += 2
        
        # Check rule category
        category = self.categorize_rule(rule)
        if category in ['service_account_misuse', 'privilege_escalation']:
            priority_score += 2
        elif category in ['authentication_anomaly', 'data_exfiltration']:
            priority_score += 1
        
        # Check complexity
        filter_analysis = self.analyze_search_filter(rule.search_filter)
        if filter_analysis['complexity'] == 'high':
            priority_score += 1
        
        # Determine priority level
        if priority_score >= 6:
            return 'high'
        elif priority_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def get_false_positive_indicators(self, rule: RuleInfo) -> List[str]:
        """Identify potential false positive indicators"""
        indicators = []
        
        # Check for test rules
        if 'test' in rule.rule_name.lower():
            indicators.append("Test rule - may generate false positives")
        
        # Check for exclusions in search filter
        if '!in(' in rule.search_filter or '!match(' in rule.search_filter:
            indicators.append("Rule has exclusions - verify they are up to date")
        
        # Check for complex filters
        filter_analysis = self.analyze_search_filter(rule.search_filter)
        if filter_analysis['complexity'] == 'high':
            indicators.append("Complex search filter - may need tuning")
        
        # Check for specific patterns that might cause false positives
        if 'sa-' in rule.rule_name.lower() and 'misuse' in rule.rule_name.lower():
            indicators.append("Service account misuse rule - verify legitimate service account usage")
        
        return indicators 
    
    def get_attack_techniques(self, rule: RuleInfo) -> List:
        """Get attack techniques for a rule"""
        if rule.attack_techniques:
            return rule.attack_techniques
        return []
    
    def get_primary_tactic(self, rule: RuleInfo) -> Optional[str]:
        """Get the primary tactic for a rule"""
        attack_mapping = self.mitre_mapper.map_rule_to_attack(
            rule.rule_name, rule.description, rule.search_filter
        )
        return attack_mapping.get('primary_tactic')
    
    def get_attack_summary(self, rule: RuleInfo) -> Dict[str, Any]:
        """Get attack summary for a rule"""
        return self.mitre_mapper.map_rule_to_attack(
            rule.rule_name, rule.description, rule.search_filter
        )
    
    def extract_rule_specific_details(self, rule: RuleInfo) -> Dict[str, Any]:
        """Extract rule-specific technical details"""
        details = {
            'search_filter_analysis': self.analyze_search_filter(rule.search_filter),
            'exclusions': self.extract_exclusions(rule.search_filter),
            'inclusions': self.extract_inclusions(rule.search_filter),
            'data_sources': self.extract_data_sources(rule.search_filter),
            'event_types': self.extract_event_types(rule.search_filter),
            'complexity_score': self.calculate_complexity(rule.search_filter),
            'false_positive_risk': self.assess_false_positive_risk(rule)
        }
        
        # Add category-specific details
        if 'service_account' in rule.rule_name.lower():
            details.update(self.extract_service_account_details(rule))
        elif 'privilege' in rule.rule_name.lower():
            details.update(self.extract_privilege_details(rule))
        elif 'configuration' in rule.rule_name.lower():
            details.update(self.extract_configuration_details(rule))
        elif 'data' in rule.rule_name.lower() and 'exfiltration' in rule.rule_name.lower():
            details.update(self.extract_data_exfiltration_details(rule))
        
        return details
    
    def extract_exclusions(self, search_filter: str) -> List[str]:
        """Extract exclusion patterns from search filter"""
        exclusions = []
        
        # Look for exclusion patterns
        exclusion_patterns = [
            r'!in\(([^)]+)\)',
            r'!match\(([^)]+)\)',
            r'NOT\s+([^)]+)',
            r'!=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in exclusion_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            exclusions.extend(matches)
        
        return list(set(exclusions))
    
    def extract_inclusions(self, search_filter: str) -> List[str]:
        """Extract inclusion patterns from search filter"""
        inclusions = []
        
        # Look for inclusion patterns
        inclusion_patterns = [
            r'in\(([^)]+)\)',
            r'match\(([^)]+)\)',
            r'=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in inclusion_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            inclusions.extend(matches)
        
        return list(set(inclusions))
    
    def extract_data_sources(self, search_filter: str) -> List[str]:
        """Extract data sources from search filter"""
        data_sources = []
        
        # Common data source patterns
        source_patterns = [
            r'index\s*=\s*["\']([^"\']+)["\']',
            r'sourcetype\s*=\s*["\']([^"\']+)["\']',
            r'source\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in source_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            data_sources.extend(matches)
        
        return list(set(data_sources))
    
    def extract_event_types(self, search_filter: str) -> List[str]:
        """Extract event types from search filter"""
        event_types = []
        
        # Common event type patterns
        event_patterns = [
            r'event\.type\s*=\s*["\']([^"\']+)["\']',
            r'event_type\s*=\s*["\']([^"\']+)["\']',
            r'type\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in event_patterns:
            matches = re.findall(pattern, search_filter, re.IGNORECASE)
            event_types.extend(matches)
        
        return list(set(event_types))
    
    def calculate_complexity(self, search_filter: str) -> int:
        """Calculate complexity score for search filter"""
        complexity_score = 0
        
        # Count logical operators
        complexity_score += search_filter.count('AND') * 2
        complexity_score += search_filter.count('OR') * 2
        complexity_score += search_filter.count('NOT') * 1
        
        # Count functions
        complexity_score += search_filter.count('(') * 1
        
        # Count wildcards
        complexity_score += search_filter.count('*') * 1
        complexity_score += search_filter.count('?') * 1
        
        # Count regex patterns
        complexity_score += search_filter.count('/') * 2
        
        return complexity_score
    
    def assess_false_positive_risk(self, rule: RuleInfo) -> str:
        """Assess false positive risk for a rule"""
        risk_score = 0
        
        # Check rule name for test indicators
        if any(term in rule.rule_name.lower() for term in ['test', 'demo', 'example']):
            risk_score += 3
        
        # Check for complex filters
        complexity = self.calculate_complexity(rule.search_filter)
        if complexity > 10:
            risk_score += 2
        
        # Check for exclusions
        exclusions = self.extract_exclusions(rule.search_filter)
        if len(exclusions) > 5:
            risk_score += 1
        
        # Check for wildcards
        if rule.search_filter.count('*') > 5:
            risk_score += 1
        
        if risk_score >= 5:
            return 'high'
        elif risk_score >= 3:
            return 'medium'
        else:
            return 'low'
    
    def extract_service_account_details(self, rule: RuleInfo) -> Dict[str, Any]:
        """Extract service account specific details"""
        details = {}
        
        # Extract service account name patterns
        sa_patterns = [
            r'sa-([a-zA-Z0-9_-]+)',
            r'service_account\s*=\s*["\']([^"\']+)["\']',
            r'account\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in sa_patterns:
            matches = re.findall(pattern, rule.search_filter, re.IGNORECASE)
            if matches:
                details['service_account_names'] = matches
                break
        
        # Extract system patterns
        system_patterns = [
            r'host\.name\s*=\s*["\']([^"\']+)["\']',
            r'system\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in system_patterns:
            matches = re.findall(pattern, rule.search_filter, re.IGNORECASE)
            if matches:
                details['target_systems'] = matches
                break
        
        return details
    
    def extract_privilege_details(self, rule: RuleInfo) -> Dict[str, Any]:
        """Extract privilege escalation specific details"""
        details = {}
        
        # Extract privilege patterns
        privilege_patterns = [
            r'admin',
            r'root',
            r'privilege',
            r'elevation',
            r'sudo'
        ]
        
        privileges = []
        for pattern in privilege_patterns:
            if re.search(pattern, rule.search_filter, re.IGNORECASE):
                privileges.append(pattern)
        
        if privileges:
            details['privilege_types'] = privileges
        
        # Extract escalation method patterns
        escalation_patterns = [
            r'UAC',
            r'bypass',
            r'exploit',
            r'vulnerability'
        ]
        
        methods = []
        for pattern in escalation_patterns:
            if re.search(pattern, rule.search_filter, re.IGNORECASE):
                methods.append(pattern)
        
        if methods:
            details['escalation_methods'] = methods
        
        return details
    
    def extract_configuration_details(self, rule: RuleInfo) -> Dict[str, Any]:
        """Extract configuration change specific details"""
        details = {}
        
        # Extract configuration component patterns
        config_patterns = [
            r'policy',
            r'setting',
            r'configuration',
            r'registry',
            r'config'
        ]
        
        components = []
        for pattern in config_patterns:
            if re.search(pattern, rule.search_filter, re.IGNORECASE):
                components.append(pattern)
        
        if components:
            details['config_components'] = components
        
        return details
    
    def extract_data_exfiltration_details(self, rule: RuleInfo) -> Dict[str, Any]:
        """Extract data exfiltration specific details"""
        details = {}
        
        # Extract data type patterns
        data_patterns = [
            r'file',
            r'document',
            r'data',
            r'information',
            r'record'
        ]
        
        data_types = []
        for pattern in data_patterns:
            if re.search(pattern, rule.search_filter, re.IGNORECASE):
                data_types.append(pattern)
        
        if data_types:
            details['data_types'] = data_types
        
        # Extract destination patterns
        dest_patterns = [
            r'external',
            r'upload',
            r'download',
            r'copy',
            r'move'
        ]
        
        destinations = []
        for pattern in dest_patterns:
            if re.search(pattern, rule.search_filter, re.IGNORECASE):
                destinations.append(pattern)
        
        if destinations:
            details['exfiltration_methods'] = destinations
        
        return details
    
    def get_priority(self, rule: RuleInfo) -> str:
        """Get rule priority (alias for get_rule_priority)"""
        return self.get_rule_priority(rule)
    
    def get_complexity(self, rule: RuleInfo) -> str:
        """Get complexity level for a rule"""
        complexity_score = self.calculate_complexity(rule.search_filter)
        
        if complexity_score >= 15:
            return 'high'
        elif complexity_score >= 8:
            return 'medium'
        else:
            return 'low'
    
    def get_data_sources(self, rule: RuleInfo) -> str:
        """Get data sources for a rule"""
        sources = self.extract_data_sources(rule.search_filter)
        return ', '.join(sources) if sources else 'Not specified'
    
    def get_event_types(self, rule: RuleInfo) -> str:
        """Get event types for a rule"""
        types = self.extract_event_types(rule.search_filter)
        return ', '.join(types) if types else 'Not specified'
    
    def create_rule_info(self, rule_data: Dict[str, Any]) -> RuleInfo:
        """Create RuleInfo from rule data dictionary"""
        # Map rule to MITRE ATT&CK
        attack_mapping = self.mitre_mapper.map_rule_to_attack(
            rule_data.get('rule_name', ''),
            rule_data.get('description', ''),
            rule_data.get('search_filter', '')
        )
        
        return RuleInfo(
            rule_id=rule_data.get('rule_id', ''),
            rule_name=rule_data.get('rule_name', ''),
            description=rule_data.get('description', ''),
            search_outcome=rule_data.get('search_outcome', ''),
            search_filter=rule_data.get('search_filter', ''),
            created_on=rule_data.get('created_on', ''),
            last_updated_on=rule_data.get('last_updated_on', ''),
            status=rule_data.get('status', ''),
            filename=rule_data.get('filename', ''),
            file_size=rule_data.get('file_size', 0),
            timestamp=rule_data.get('timestamp', ''),
            attack_techniques=attack_mapping.get('techniques', [])
        ) 