"""
Advanced Rule Optimization System

This module provides intelligent rule optimization capabilities for
security correlation rules, including complexity analysis, performance
optimization, and quality improvements.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
from datetime import datetime

from src.rule_analyzer import RuleInfo

logger = logging.getLogger(__name__)


@dataclass
class OptimizationSuggestion:
    """A suggestion for rule optimization"""
    rule_id: str
    rule_name: str
    suggestion_type: str  # 'performance', 'complexity', 'quality', 'security'
    priority: str  # 'high', 'medium', 'low'
    description: str
    current_value: Any
    suggested_value: Any
    impact_score: float  # 0.0 to 1.0
    implementation_effort: str  # 'low', 'medium', 'high'
    reasoning: str


@dataclass
class RuleComplexityMetrics:
    """Metrics for rule complexity analysis"""
    rule_id: str
    rule_name: str
    complexity_score: int
    filter_length: int
    operator_count: int
    nested_levels: int
    unique_fields: int
    performance_impact: str  # 'low', 'medium', 'high'
    maintainability_score: float  # 0.0 to 1.0
    optimization_potential: float  # 0.0 to 1.0


class RuleOptimizer:
    """Advanced rule optimization engine"""
    
    def __init__(self):
        self.performance_patterns = {
            'expensive_operators': [
                r'\bLIKE\b.*%',  # Wildcard searches
                r'\bREGEX\b',     # Regular expressions
                r'\bCONTAINS\b',  # String contains
                r'\bSEARCH\b'     # Full-text search
            ],
            'inefficient_patterns': [
                r'OR\s+.*OR\s+.*OR',  # Multiple OR conditions
                r'AND\s+.*AND\s+.*AND',  # Multiple AND conditions
                r'\(.*\)\s*OR\s*\(.*\)',  # Complex OR groups
                r'NOT\s+.*AND\s+.*NOT'   # Multiple NOT conditions
            ],
            'optimization_opportunities': [
                r'(\w+)\s*=\s*(\w+)\s+AND\s+\1\s*=\s*(\w+)',  # Redundant conditions
                r'(\w+)\s*IN\s*\([^)]*\)\s+AND\s+\1\s*=\s*\w+',  # IN + equality
                r'(\w+)\s*LIKE\s*[\'"]%[^%]*%[\'"]',  # Leading/trailing wildcards
            ]
        }
        
        self.complexity_indicators = {
            'high_complexity': [
                r'\([^)]*\([^)]*\)[^)]*\)',  # Nested parentheses
                r'AND.*AND.*AND.*AND',        # 4+ AND conditions
                r'OR.*OR.*OR.*OR',            # 4+ OR conditions
                r'NOT.*AND.*NOT.*AND',        # Multiple NOT with AND
                r'LIKE.*%.*%.*%',             # Multiple wildcards
                r'REGEX.*\{.*\}',             # Complex regex patterns
            ],
            'medium_complexity': [
                r'AND.*AND.*AND',             # 3 AND conditions
                r'OR.*OR.*OR',                # 3 OR conditions
                r'\([^)]*OR[^)]*\)',          # OR groups
                r'LIKE.*%.*%',                # Multiple wildcards
                r'IN\s*\([^)]{50,}\)',       # Large IN clauses
            ],
            'low_complexity': [
                r'^\w+\s*=\s*\w+$',          # Simple equality
                r'^\w+\s+IN\s*\([^)]{1,20}\)$',  # Small IN clause
                r'^\w+\s+LIKE\s+[\'"]%[^%]*[\'"]$',  # Simple LIKE
            ]
        }
        
        self.quality_indicators = {
            'security_issues': [
                r'password\s*[=:]\s*[\"\']?\w+[\"\']?',  # Hardcoded passwords
                r'api[_-]?key\s*[=:]\s*[\"\']?\w+[\"\']?',  # API keys in filters
                r'secret\s*[=:]\s*[\"\']?\w+[\"\']?',  # Secrets in filters
                r'token\s*[=:]\s*[\"\']?\w+[\"\']?',  # Tokens in filters
            ],
            'syntax_issues': [
                r'\([^)]*$',                  # Unmatched parentheses
                r'^[^(]*\)',                   # Unmatched closing parentheses
                r'\[[^\]]*$',                  # Unmatched brackets
                r'^[^[]*\]',                   # Unmatched closing brackets
                r'AND\s+and',                  # Mixed case operators
                r'OR\s+or',                    # Mixed case operators
            ],
            'best_practices': [
                r'^\s*$',                      # Empty filters
                r'^\s*OR\s',                   # Leading OR
                r'^\s*AND\s',                  # Leading AND
                r'\s+OR\s*$',                  # Trailing OR
                r'\s+AND\s*$',                 # Trailing AND
            ]
        }
    
    def analyze_rule_complexity(self, rule: RuleInfo) -> RuleComplexityMetrics:
        """Analyze the complexity of a rule"""
        filter_text = rule.search_filter or ""
        
        # Calculate complexity metrics
        complexity_score = self._calculate_complexity_score(filter_text)
        filter_length = len(filter_text)
        operator_count = self._count_operators(filter_text)
        nested_levels = self._count_nested_levels(filter_text)
        unique_fields = self._count_unique_fields(filter_text)
        
        # Determine performance impact
        performance_impact = self._assess_performance_impact(filter_text)
        
        # Calculate maintainability score
        maintainability_score = self._calculate_maintainability_score(filter_text)
        
        # Calculate optimization potential
        optimization_potential = self._calculate_optimization_potential(filter_text)
        
        return RuleComplexityMetrics(
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            complexity_score=complexity_score,
            filter_length=filter_length,
            operator_count=operator_count,
            nested_levels=nested_levels,
            unique_fields=unique_fields,
            performance_impact=performance_impact,
            maintainability_score=maintainability_score,
            optimization_potential=optimization_potential
        )
    
    def generate_optimization_suggestions(self, rule: RuleInfo) -> List[OptimizationSuggestion]:
        """Generate optimization suggestions for a rule"""
        suggestions = []
        filter_text = rule.search_filter or ""
        
        # Performance optimizations
        suggestions.extend(self._suggest_performance_optimizations(rule, filter_text))
        
        # Complexity optimizations
        suggestions.extend(self._suggest_complexity_optimizations(rule, filter_text))
        
        # Quality improvements
        suggestions.extend(self._suggest_quality_improvements(rule, filter_text))
        
        # Security improvements
        suggestions.extend(self._suggest_security_improvements(rule, filter_text))
        
        return suggestions
    
    def optimize_rule_filter(self, filter_text: str) -> Tuple[str, List[str]]:
        """Optimize a rule filter and return the optimized version with changes"""
        original_filter = filter_text
        optimized_filter = filter_text
        changes = []
        
        # Remove redundant conditions
        optimized_filter, redundant_changes = self._remove_redundant_conditions(optimized_filter)
        changes.extend(redundant_changes)
        
        # Simplify complex expressions
        optimized_filter, simplification_changes = self._simplify_expressions(optimized_filter)
        changes.extend(simplification_changes)
        
        # Optimize operator usage
        optimized_filter, operator_changes = self._optimize_operators(optimized_filter)
        changes.extend(operator_changes)
        
        # Clean up syntax
        optimized_filter, syntax_changes = self._clean_syntax(optimized_filter)
        changes.extend(syntax_changes)
        
        return optimized_filter, changes
    
    def _calculate_complexity_score(self, filter_text: str) -> int:
        """Calculate complexity score for a filter"""
        score = 0
        
        # Base score from length
        score += len(filter_text) // 50
        
        # Add points for complex patterns
        for pattern in self.complexity_indicators['high_complexity']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                score += 10
        
        for pattern in self.complexity_indicators['medium_complexity']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                score += 5
        
        # Subtract points for simple patterns
        for pattern in self.complexity_indicators['low_complexity']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                score -= 2
        
        return max(0, score)
    
    def _count_operators(self, filter_text: str) -> int:
        """Count logical operators in the filter"""
        operators = ['AND', 'OR', 'NOT', 'AND NOT', 'OR NOT']
        count = 0
        for operator in operators:
            count += len(re.findall(rf'\b{operator}\b', filter_text, re.IGNORECASE))
        return count
    
    def _count_nested_levels(self, filter_text: str) -> int:
        """Count maximum nesting levels in parentheses"""
        max_depth = 0
        current_depth = 0
        
        for char in filter_text:
            if char == '(':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == ')':
                current_depth = max(0, current_depth - 1)
        
        return max_depth
    
    def _count_unique_fields(self, filter_text: str) -> int:
        """Count unique field names in the filter"""
        # Extract field names (simplified pattern)
        field_pattern = r'\b(\w+)\s*[=<>!]'
        fields = re.findall(field_pattern, filter_text)
        return len(set(fields))
    
    def _assess_performance_impact(self, filter_text: str) -> str:
        """Assess the performance impact of a filter"""
        expensive_count = 0
        
        for pattern in self.performance_patterns['expensive_operators']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                expensive_count += 1
        
        if expensive_count >= 3:
            return 'high'
        elif expensive_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_maintainability_score(self, filter_text: str) -> float:
        """Calculate maintainability score (0.0 to 1.0)"""
        score = 1.0
        
        # Penalize for complexity
        complexity_score = self._calculate_complexity_score(filter_text)
        score -= min(0.5, complexity_score * 0.05)
        
        # Penalize for syntax issues
        for pattern in self.quality_indicators['syntax_issues']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                score -= 0.1
        
        # Penalize for best practice violations
        for pattern in self.quality_indicators['best_practices']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                score -= 0.05
        
        return max(0.0, score)
    
    def _calculate_optimization_potential(self, filter_text: str) -> float:
        """Calculate optimization potential (0.0 to 1.0)"""
        potential = 0.0
        
        # Check for optimization opportunities
        for pattern in self.performance_patterns['optimization_opportunities']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                potential += 0.3
        
        # Check for complexity issues
        complexity_score = self._calculate_complexity_score(filter_text)
        if complexity_score > 10:
            potential += 0.4
        elif complexity_score > 5:
            potential += 0.2
        
        # Check for quality issues
        for pattern in self.quality_indicators['syntax_issues']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                potential += 0.2
        
        return min(1.0, potential)
    
    def _suggest_performance_optimizations(self, rule: RuleInfo, filter_text: str) -> List[OptimizationSuggestion]:
        """Generate performance optimization suggestions"""
        suggestions = []
        
        # Check for expensive operators
        for pattern in self.performance_patterns['expensive_operators']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                suggestions.append(OptimizationSuggestion(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    suggestion_type='performance',
                    priority='high',
                    description='Replace expensive operator with more efficient alternative',
                    current_value=f'Uses {pattern}',
                    suggested_value='Use indexed field comparison',
                    impact_score=0.8,
                    implementation_effort='medium',
                    reasoning='Expensive operators can significantly impact query performance'
                ))
        
        # Check for inefficient patterns
        for pattern in self.performance_patterns['inefficient_patterns']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                suggestions.append(OptimizationSuggestion(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    suggestion_type='performance',
                    priority='medium',
                    description='Simplify complex logical expressions',
                    current_value=f'Complex pattern: {pattern}',
                    suggested_value='Break into simpler conditions',
                    impact_score=0.6,
                    implementation_effort='high',
                    reasoning='Complex logical expressions can be optimized for better performance'
                ))
        
        return suggestions
    
    def _suggest_complexity_optimizations(self, rule: RuleInfo, filter_text: str) -> List[OptimizationSuggestion]:
        """Generate complexity optimization suggestions"""
        suggestions = []
        
        complexity_score = self._calculate_complexity_score(filter_text)
        
        if complexity_score > 15:
            suggestions.append(OptimizationSuggestion(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                suggestion_type='complexity',
                priority='high',
                description='Reduce rule complexity',
                current_value=f'Complexity score: {complexity_score}',
                suggested_value='Break into multiple simpler rules',
                impact_score=0.9,
                implementation_effort='high',
                reasoning='High complexity makes rules difficult to maintain and debug'
            ))
        
        nested_levels = self._count_nested_levels(filter_text)
        if nested_levels > 3:
            suggestions.append(OptimizationSuggestion(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                suggestion_type='complexity',
                priority='medium',
                description='Reduce nesting levels',
                current_value=f'{nested_levels} nested levels',
                suggested_value='Flatten nested expressions',
                impact_score=0.7,
                implementation_effort='medium',
                reasoning='Deep nesting makes rules harder to understand and maintain'
            ))
        
        return suggestions
    
    def _suggest_quality_improvements(self, rule: RuleInfo, filter_text: str) -> List[OptimizationSuggestion]:
        """Generate quality improvement suggestions"""
        suggestions = []
        
        # Check for syntax issues
        for pattern in self.quality_indicators['syntax_issues']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                suggestions.append(OptimizationSuggestion(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    suggestion_type='quality',
                    priority='high',
                    description='Fix syntax issue',
                    current_value=f'Syntax issue: {pattern}',
                    suggested_value='Correct syntax',
                    impact_score=0.8,
                    implementation_effort='low',
                    reasoning='Syntax issues can cause rule failures'
                ))
        
        # Check for best practice violations
        for pattern in self.quality_indicators['best_practices']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                suggestions.append(OptimizationSuggestion(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    suggestion_type='quality',
                    priority='medium',
                    description='Follow best practices',
                    current_value=f'Best practice violation: {pattern}',
                    suggested_value='Apply best practices',
                    impact_score=0.5,
                    implementation_effort='low',
                    reasoning='Following best practices improves rule reliability'
                ))
        
        return suggestions
    
    def _suggest_security_improvements(self, rule: RuleInfo, filter_text: str) -> List[OptimizationSuggestion]:
        """Generate security improvement suggestions"""
        suggestions = []
        
        # Check for security issues
        for pattern in self.quality_indicators['security_issues']:
            if re.search(pattern, filter_text, re.IGNORECASE):
                suggestions.append(OptimizationSuggestion(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    suggestion_type='security',
                    priority='high',
                    description='Remove sensitive data from filter',
                    current_value=f'Sensitive data detected: {pattern}',
                    suggested_value='Use parameterized values',
                    impact_score=1.0,
                    implementation_effort='medium',
                    reasoning='Sensitive data in filters poses security risks'
                ))
        
        return suggestions
    
    def _remove_redundant_conditions(self, filter_text: str) -> Tuple[str, List[str]]:
        """Remove redundant conditions from filter"""
        changes = []
        optimized = filter_text
        
        # Remove duplicate conditions
        conditions = re.split(r'\s+(?:AND|OR)\s+', optimized)
        unique_conditions = []
        for condition in conditions:
            if condition.strip() and condition.strip() not in unique_conditions:
                unique_conditions.append(condition.strip())
        
        if len(unique_conditions) < len(conditions):
            optimized = ' AND '.join(unique_conditions)
            changes.append('Removed duplicate conditions')
        
        return optimized, changes
    
    def _simplify_expressions(self, filter_text: str) -> Tuple[str, List[str]]:
        """Simplify complex expressions"""
        changes = []
        optimized = filter_text
        
        # Simplify double negatives
        optimized = re.sub(r'NOT\s+NOT\s+', '', optimized)
        if optimized != filter_text:
            changes.append('Simplified double negatives')
        
        # Remove unnecessary parentheses around single conditions
        optimized = re.sub(r'\((\w+\s*[=<>!]\s*\w+)\)', r'\1', optimized)
        if optimized != filter_text:
            changes.append('Removed unnecessary parentheses')
        
        return optimized, changes
    
    def _optimize_operators(self, filter_text: str) -> Tuple[str, List[str]]:
        """Optimize operator usage"""
        changes = []
        optimized = filter_text
        
        # Replace multiple AND with single condition where possible
        optimized = re.sub(r'(\w+)\s*=\s*(\w+)\s+AND\s+\1\s*=\s*(\w+)', r'\1 IN (\2, \3)', optimized)
        if optimized != filter_text:
            changes.append('Optimized multiple equality conditions')
        
        return optimized, changes
    
    def _clean_syntax(self, filter_text: str) -> Tuple[str, List[str]]:
        """Clean up syntax issues"""
        changes = []
        optimized = filter_text
        
        # Remove leading/trailing operators
        optimized = re.sub(r'^\s*(AND|OR)\s+', '', optimized)
        optimized = re.sub(r'\s+(AND|OR)\s*$', '', optimized)
        if optimized != filter_text:
            changes.append('Removed leading/trailing operators')
        
        # Normalize whitespace
        optimized = re.sub(r'\s+', ' ', optimized).strip()
        if optimized != filter_text:
            changes.append('Normalized whitespace')
        
        return optimized, changes
    
    def _generate_optimization_report(self, optimization_results: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive optimization report"""
        report = f"""# Rule Optimization Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Rules Analyzed:** {len(optimization_results)}

## Executive Summary

"""
        
        # Calculate summary statistics
        total_suggestions = sum(len(result['suggestions']) for result in optimization_results)
        high_priority_suggestions = sum(
            len([s for s in result['suggestions'] if s.priority == 'high'])
            for result in optimization_results
        )
        medium_priority_suggestions = sum(
            len([s for s in result['suggestions'] if s.priority == 'medium'])
            for result in optimization_results
        )
        low_priority_suggestions = sum(
            len([s for s in result['suggestions'] if s.priority == 'low'])
            for result in optimization_results
        )
        
        complexity_scores = [result['complexity'].complexity_score for result in optimization_results]
        avg_complexity = sum(complexity_scores) / len(complexity_scores) if complexity_scores else 0
        high_complexity_rules = sum(1 for score in complexity_scores if score > 10)
        
        report += f"""
- **Total Optimization Suggestions:** {total_suggestions}
- **High Priority Suggestions:** {high_priority_suggestions}
- **Medium Priority Suggestions:** {medium_priority_suggestions}
- **Low Priority Suggestions:** {low_priority_suggestions}
- **Average Complexity Score:** {avg_complexity:.1f}
- **High Complexity Rules:** {high_complexity_rules}

## Priority Breakdown

### High Priority Optimizations
"""
        
        high_priority_suggestions = []
        for result in optimization_results:
            for suggestion in result['suggestions']:
                if suggestion.priority == 'high':
                    high_priority_suggestions.append((result['rule'], suggestion))
        
        for i, (rule, suggestion) in enumerate(high_priority_suggestions[:10], 1):
            report += f"""
{i}. **{rule.rule_name}** ({rule.rule_id})
    - **Type:** {suggestion.suggestion_type.title()}
    - **Description:** {suggestion.description}
    - **Impact Score:** {suggestion.impact_score:.1f}
    - **Effort:** {suggestion.implementation_effort.title()}
    - **Reasoning:** {suggestion.reasoning}
    - **Current Value:** {suggestion.current_value}
    - **Suggested Value:** {suggestion.suggested_value}
"""
        
        if len(high_priority_suggestions) > 10:
            report += f"\n... and {len(high_priority_suggestions) - 10} more high priority suggestions\n"
        
        report += "\n## Complexity Analysis\n"
        
        # Group rules by complexity
        simple_rules = [r for r in optimization_results if r['complexity'].complexity_score <= 5]
        medium_rules = [r for r in optimization_results if 5 < r['complexity'].complexity_score <= 15]
        complex_rules = [r for r in optimization_results if r['complexity'].complexity_score > 15]
        
        report += f"""
- **Simple Rules (Score ≤ 5):** {len(simple_rules)} rules
- **Medium Complexity (Score 6-15):** {len(medium_rules)} rules
- **Complex Rules (Score > 15):** {len(complex_rules)} rules

### Most Complex Rules
"""
        
        # Sort by complexity score
        sorted_results = sorted(optimization_results, key=lambda x: x['complexity'].complexity_score, reverse=True)
        
        for i, result in enumerate(sorted_results[:5], 1):
            rule = result['rule']
            complexity = result['complexity']
            report += f"""
{i}. **{rule.rule_name}** (Score: {complexity.complexity_score})
    - **Filter Length:** {complexity.filter_length} characters
    - **Operators:** {complexity.operator_count}
    - **Nested Levels:** {complexity.nested_levels}
    - **Unique Fields:** {complexity.unique_fields}
    - **Performance Impact:** {complexity.performance_impact}
    - **Maintainability Score:** {complexity.maintainability_score:.2f}
    - **Optimization Potential:** {complexity.optimization_potential:.2f}
"""
        
        report += "\n## Performance Impact Analysis\n"
        
        # Analyze performance impact
        high_impact_rules = [r for r in optimization_results if r['complexity'].performance_impact == 'high']
        medium_impact_rules = [r for r in optimization_results if r['complexity'].performance_impact == 'medium']
        low_impact_rules = [r for r in optimization_results if r['complexity'].performance_impact == 'low']
        
        report += f"""
- **High Performance Impact:** {len(high_impact_rules)} rules
- **Medium Performance Impact:** {len(medium_impact_rules)} rules
- **Low Performance Impact:** {len(low_impact_rules)} rules

### High Performance Impact Rules
"""
        
        for i, result in enumerate(high_impact_rules[:5], 1):
            rule = result['rule']
            complexity = result['complexity']
            report += f"""
{i}. **{rule.rule_name}**
    - **Complexity Score:** {complexity.complexity_score}
    - **Filter Length:** {complexity.filter_length} characters
    - **Optimization Potential:** {complexity.optimization_potential:.2f}
"""
        
        report += "\n## Recommendations\n"
        
        if high_priority_suggestions:
            report += "1. **Immediate Action Required:** Address all high priority suggestions first\n"
        
        if high_complexity_rules > len(optimization_results) * 0.2:
            report += "2. **Complexity Reduction:** Consider breaking down complex rules into simpler components\n"
        
        if len(high_impact_rules) > len(optimization_results) * 0.1:
            report += "3. **Performance Optimization:** Focus on optimizing high performance impact rules\n"
        
        report += "4. **Regular Review:** Implement regular rule optimization reviews\n"
        report += "5. **Best Practices:** Follow established best practices for rule development\n"
        
        return report 