"""
MITRE ATT&CK Mapper

This module provides mapping between security correlation rules
and MITRE ATT&CK techniques using the expanded technique library.
"""

import re
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from src.mitre_attack_expanded import ExpandedMitreAttackMapper, AttackTechnique

logger = logging.getLogger(__name__)


@dataclass
class MitreMapping:
    """MITRE ATT&CK mapping result"""
    rule_name: str
    rule_id: str
    techniques: List[Dict[str, Any]]
    primary_tactic: str
    confidence_score: float
    coverage_score: float


class MitreAttackMapper:
    """Enhanced MITRE ATT&CK mapper using expanded technique library"""
    
    def __init__(self):
        self.expanded_mapper = ExpandedMitreAttackMapper()
        self.mapping_cache = {}
    
    def map_rule_to_attack(self, rule_name: str, description: str, search_filter: str) -> Dict[str, Any]:
        """Map a security rule to MITRE ATT&CK techniques using expanded library"""
        
        # Create cache key
        cache_key = f"{rule_name}:{description}:{search_filter}"
        
        # Check cache first
        if cache_key in self.mapping_cache:
            return self.mapping_cache[cache_key]
        
        # Use expanded mapper
        result = self.expanded_mapper.map_rule_to_attack(rule_name, description, search_filter)
        
        # Cache the result
        self.mapping_cache[cache_key] = result
        
        return result
    
    def get_technique_details(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get detailed information about a technique"""
        return self.expanded_mapper.get_technique_details(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[AttackTechnique]:
        """Get all techniques for a specific tactic"""
        from src.mitre_attack_expanded import AttackTactic
        try:
            tactic_enum = AttackTactic(tactic)
            return self.expanded_mapper.get_techniques_by_tactic(tactic_enum)
        except ValueError:
            logger.warning(f"Unknown tactic: {tactic}")
            return []
    
    def get_techniques_by_pattern(self, pattern: str) -> List[AttackTechnique]:
        """Get techniques that match a pattern"""
        return self.expanded_mapper.get_techniques_by_pattern(pattern)
    
    def generate_mapping_report(self, rule_mappings: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive MITRE ATT&CK mapping report"""
        return self.expanded_mapper.generate_attack_report(rule_mappings)
    
    def validate_mapping(self, rule_name: str, description: str, search_filter: str, expected_techniques: List[str]) -> Dict[str, Any]:
        """Validate a mapping against expected techniques"""
        mapping = self.map_rule_to_attack(rule_name, description, search_filter)
        
        mapped_techniques = [t['technique_id'] for t in mapping['techniques']]
        expected_found = [t for t in expected_techniques if t in mapped_techniques]
        unexpected_found = [t for t in mapped_techniques if t not in expected_techniques]
        
        accuracy = len(expected_found) / len(expected_techniques) if expected_techniques else 0
        precision = len(expected_found) / len(mapped_techniques) if mapped_techniques else 0
        
        return {
            'rule_name': rule_name,
            'expected_techniques': expected_techniques,
            'mapped_techniques': mapped_techniques,
            'expected_found': expected_found,
            'unexpected_found': unexpected_found,
            'accuracy': accuracy,
            'precision': precision,
            'confidence_score': mapping['confidence_score']
        }
    
    def get_mapping_statistics(self, rule_mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about MITRE ATT&CK mappings"""
        if not rule_mappings:
            return {}
        
        total_rules = len(rule_mappings)
        rules_with_mappings = len([m for m in rule_mappings if m['techniques']])
        
        all_techniques = []
        tactic_counts = {}
        confidence_scores = []
        
        for mapping in rule_mappings:
            all_techniques.extend(mapping['techniques'])
            confidence_scores.append(mapping['confidence_score'])
            
            for technique in mapping['techniques']:
                tactic = technique['tactic']
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        unique_techniques = len(set(t['technique_id'] for t in all_techniques))
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            'total_rules': total_rules,
            'rules_with_mappings': rules_with_mappings,
            'mapping_coverage': rules_with_mappings / total_rules if total_rules > 0 else 0,
            'total_techniques_mapped': len(all_techniques),
            'unique_techniques': unique_techniques,
            'average_confidence': avg_confidence,
            'tactic_distribution': tactic_counts,
            'top_techniques': self._get_top_techniques(all_techniques),
            'top_tactics': self._get_top_tactics(tactic_counts)
        }
    
    def _get_top_techniques(self, techniques: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top techniques by frequency"""
        technique_counts = {}
        for technique in techniques:
            technique_id = technique['technique_id']
            technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
        
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        
        top_techniques = []
        for technique_id, count in sorted_techniques[:limit]:
            technique_details = self.get_technique_details(technique_id)
            if technique_details:
                top_techniques.append({
                    'technique_id': technique_id,
                    'name': technique_details.name,
                    'tactic': technique_details.tactic.value,
                    'count': count
                })
        
        return top_techniques
    
    def _get_top_tactics(self, tactic_counts: Dict[str, int], limit: int = 5) -> List[Dict[str, Any]]:
        """Get top tactics by frequency"""
        sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'tactic': tactic, 'count': count}
            for tactic, count in sorted_tactics[:limit]
        ]
    
    def export_mappings(self, rule_mappings: List[Dict[str, Any]], output_format: str = 'json') -> str:
        """Export mappings in various formats"""
        if output_format == 'json':
            import json
            return json.dumps(rule_mappings, indent=2)
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Rule Name', 'Technique ID', 'Technique Name', 'Tactic', 'Confidence'])
            
            # Write data
            for mapping in rule_mappings:
                rule_name = mapping.get('rule_name', 'Unknown')
                for technique in mapping['techniques']:
                    writer.writerow([
                        rule_name,
                        technique['technique_id'],
                        technique['name'],
                        technique['tactic'],
                        technique['confidence']
                    ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def clear_cache(self) -> None:
        """Clear the mapping cache"""
        self.mapping_cache.clear()
        logger.info("MITRE ATT&CK mapping cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'cache_size': len(self.mapping_cache),
            'cache_hits': 0,  # Would need to implement hit tracking
            'cache_misses': 0  # Would need to implement miss tracking
        } 