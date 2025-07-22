"""
Enhanced Input Validator Module

This module provides comprehensive validation for security correlation rules
and other input data with detailed error reporting and recovery options.
"""

import re
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from src.rule_analyzer import RuleInfo

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """Data class for validation issues"""
    field: str
    issue_type: str
    message: str
    severity: str  # 'error', 'warning', 'info'
    suggestion: Optional[str] = None


class EnhancedInputValidator:
    """Enhanced input validator with comprehensive validation capabilities"""
    
    def __init__(self):
        self.min_rule_id_length = 10
        self.min_rule_name_length = 5
        self.min_description_length = 20
        self.min_search_filter_length = 10
        
        # Common security-sensitive patterns
        self.security_patterns = {
            'password_in_filter': r'password\s*[=:]\s*["\']?\w+["\']?',
            'api_key_in_filter': r'api[_-]?key\s*[=:]\s*["\']?\w+["\']?',
            'secret_in_filter': r'secret\s*[=:]\s*["\']?\w+["\']?',
            'token_in_filter': r'token\s*[=:]\s*["\']?\w+["\']?',
        }
        
        # Common syntax issues
        self.syntax_patterns = {
            'mixed_case_operators': r'(AND|OR|NOT).*(and|or|not)|(and|or|not).*(AND|OR|NOT)',
            'unmatched_parentheses': r'\([^)]*$|^[^(]*\)',
            'unmatched_brackets': r'\[[^\]]*$|^[^[]*\]',
            'unmatched_braces': r'\{[^}]*$|^[^{]*\}',
        }
    
    def validate_rule_completeness(self, rule: RuleInfo) -> List[ValidationIssue]:
        """Enhanced validation with specific error messages"""
        issues = []
        
        # Check required fields
        if not rule.rule_id:
            issues.append(ValidationIssue(
                field='rule_id',
                issue_type='missing_field',
                message='Missing rule ID',
                severity='error'
            ))
        elif len(rule.rule_id) < self.min_rule_id_length:
            issues.append(ValidationIssue(
                field='rule_id',
                issue_type='too_short',
                message=f'Rule ID too short (minimum {self.min_rule_id_length} characters)',
                severity='warning',
                suggestion='Consider adding more descriptive identifier'
            ))
            
        if not rule.rule_name:
            issues.append(ValidationIssue(
                field='rule_name',
                issue_type='missing_field',
                message='Missing rule name',
                severity='error'
            ))
        elif len(rule.rule_name) < self.min_rule_name_length:
            issues.append(ValidationIssue(
                field='rule_name',
                issue_type='too_short',
                message=f'Rule name too short (minimum {self.min_rule_name_length} characters)',
                severity='warning',
                suggestion='Add more descriptive name'
            ))
            
        if not rule.description:
            issues.append(ValidationIssue(
                field='description',
                issue_type='missing_field',
                message='Missing description',
                severity='error'
            ))
        elif len(rule.description) < self.min_description_length:
            issues.append(ValidationIssue(
                field='description',
                issue_type='too_short',
                message=f'Description too short (minimum {self.min_description_length} characters)',
                severity='warning',
                suggestion='Add more detailed description'
            ))
            
        if not rule.search_filter:
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='missing_field',
                message='Missing search filter',
                severity='error'
            ))
        elif len(rule.search_filter) < self.min_search_filter_length:
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='too_short',
                message=f'Search filter too short (minimum {self.min_search_filter_length} characters)',
                severity='warning',
                suggestion='Add more specific search criteria'
            ))
            
        # Check for common issues
        if 'test' in rule.rule_name.lower() and rule.status == 'active':
            issues.append(ValidationIssue(
                field='status',
                issue_type='test_rule_active',
                message='Test rule marked as active',
                severity='warning',
                suggestion='Consider setting status to "test" or "draft"'
            ))
            
        if rule.search_filter and self._contains_sensitive_data(rule.search_filter):
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='security_risk',
                message='Search filter contains sensitive data - security risk',
                severity='error',
                suggestion='Remove or obfuscate sensitive information'
            ))
            
        return issues
    
    def validate_search_filter_syntax(self, filter_string: str) -> List[ValidationIssue]:
        """Validate search filter syntax for common platforms"""
        issues = []
        
        if not filter_string:
            return issues
        
        # Check for basic syntax issues
        if filter_string.count('(') != filter_string.count(')'):
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='unmatched_parentheses',
                message='Unmatched parentheses in search filter',
                severity='error',
                suggestion='Check and balance all parentheses'
            ))
            
        if filter_string.count('[') != filter_string.count(']'):
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='unmatched_brackets',
                message='Unmatched brackets in search filter',
                severity='error',
                suggestion='Check and balance all brackets'
            ))
            
        if filter_string.count('{') != filter_string.count('}'):
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='unmatched_braces',
                message='Unmatched braces in search filter',
                severity='error',
                suggestion='Check and balance all braces'
            ))
            
        # Check for common mistakes
        if re.search(self.syntax_patterns['mixed_case_operators'], filter_string):
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='mixed_case_operators',
                message='Mixed case in logical operators',
                severity='warning',
                suggestion='Use consistent case for logical operators (AND, OR, NOT)'
            ))
            
        # Check for potential performance issues
        if filter_string.count('*') > 10:
            issues.append(ValidationIssue(
                field='search_filter',
                issue_type='performance_risk',
                message='Too many wildcards may impact performance',
                severity='warning',
                suggestion='Consider more specific search criteria'
            ))
            
        return issues
    
    def _contains_sensitive_data(self, filter_string: str) -> bool:
        """Check if search filter contains sensitive data patterns"""
        for pattern_name, pattern in self.security_patterns.items():
            if re.search(pattern, filter_string, re.IGNORECASE):
                return True
        return False
    
    def validate_rule_consistency(self, rule: RuleInfo) -> List[ValidationIssue]:
        """Validate rule consistency and logic"""
        issues = []
        
        # Check for logical inconsistencies
        if rule.rule_name and rule.description:
            if rule.rule_name.lower() in rule.description.lower():
                issues.append(ValidationIssue(
                    field='description',
                    issue_type='redundant_content',
                    message='Description contains rule name - may be redundant',
                    severity='info',
                    suggestion='Consider making description more specific'
                ))
        
        # Check for potential false positive indicators
        false_positive_terms = ['test', 'demo', 'example', 'sample', 'temporary']
        if any(term in rule.rule_name.lower() for term in false_positive_terms):
            issues.append(ValidationIssue(
                field='rule_name',
                issue_type='potential_false_positive',
                message='Rule name suggests test/demo content',
                severity='warning',
                suggestion='Review if this rule should be active in production'
            ))
        
        return issues
    
    def get_validation_summary(self, issues: List[ValidationIssue]) -> Dict[str, Any]:
        """Generate validation summary"""
        error_count = len([i for i in issues if i.severity == 'error'])
        warning_count = len([i for i in issues if i.severity == 'warning'])
        info_count = len([i for i in issues if i.severity == 'info'])
        
        return {
            'total_issues': len(issues),
            'error_count': error_count,
            'warning_count': warning_count,
            'info_count': info_count,
            'is_valid': error_count == 0,
            'issues': issues
        }
    
    def validate_batch(self, rules: List[RuleInfo]) -> Dict[str, Any]:
        """Validate a batch of rules"""
        all_issues = []
        valid_rules = 0
        invalid_rules = 0
        
        for rule in rules:
            rule_issues = []
            rule_issues.extend(self.validate_rule_completeness(rule))
            rule_issues.extend(self.validate_search_filter_syntax(rule.search_filter))
            rule_issues.extend(self.validate_rule_consistency(rule))
            
            all_issues.extend(rule_issues)
            
            # Count valid/invalid rules
            error_count = len([i for i in rule_issues if i.severity == 'error'])
            if error_count == 0:
                valid_rules += 1
            else:
                invalid_rules += 1
        
        return {
            'total_rules': len(rules),
            'valid_rules': valid_rules,
            'invalid_rules': invalid_rules,
            'validation_rate': valid_rules / len(rules) if rules else 0,
            'issues': all_issues,
            'summary': self.get_validation_summary(all_issues)
        } 