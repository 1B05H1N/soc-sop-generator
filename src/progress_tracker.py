"""
Progress Tracking and Analytics System

This module provides comprehensive progress tracking and analytics
for the SOC SOP Generator, including performance metrics and reporting.
"""

import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


@dataclass
class GenerationMetrics:
    """Metrics for SOP generation performance"""
    total_rules: int = 0
    processed_rules: int = 0
    successful_generations: int = 0
    failed_generations: int = 0
    validation_errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_duration: float = 0.0
    average_generation_time: float = 0.0
    memory_usage_mb: float = 0.0
    output_file_count: int = 0
    total_output_size_mb: float = 0.0


@dataclass
class RuleMetrics:
    """Metrics for individual rule processing"""
    rule_id: str
    rule_name: str
    category: str
    priority: str
    status: str
    generation_time: float
    file_size_kb: float
    validation_issues: List[str]
    mitre_techniques_count: int
    complexity_score: int
    success: bool
    error_message: Optional[str] = None


class ProgressTracker:
    """Tracks progress and performance metrics during SOP generation"""
    
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or f"session_{int(time.time())}"
        self.metrics = GenerationMetrics()
        self.rule_metrics: List[RuleMetrics] = []
        self.start_time = None
        self.current_rule_start = None
        self.progress_callbacks: List[callable] = []
        
        # Performance tracking
        self.generation_times: List[float] = []
        self.memory_snapshots: List[float] = []
        self.category_stats = defaultdict(int)
        self.priority_stats = defaultdict(int)
        self.status_stats = defaultdict(int)
        
        # Error tracking
        self.error_counts = Counter()
        self.validation_issues = Counter()
        
    def start_session(self) -> None:
        """Start a new generation session"""
        self.start_time = datetime.now()
        self.metrics.start_time = self.start_time
        logger.info(f"Starting SOP generation session: {self.session_id}")
    
    def end_session(self) -> None:
        """End the current generation session"""
        if self.start_time:
            self.metrics.end_time = datetime.now()
            self.metrics.total_duration = (self.metrics.end_time - self.start_time).total_seconds()
            
            if self.generation_times:
                self.metrics.average_generation_time = sum(self.generation_times) / len(self.generation_times)
            
            logger.info(f"Session {self.session_id} completed in {self.metrics.total_duration:.2f} seconds")
    
    def start_rule_processing(self, rule_id: str, rule_name: str) -> None:
        """Start processing a specific rule"""
        self.current_rule_start = time.time()
        self.metrics.processed_rules += 1
        
        # Notify progress callbacks
        for callback in self.progress_callbacks:
            try:
                callback(self.metrics.processed_rules, self.metrics.total_rules, rule_name)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")
    
    def end_rule_processing(self, rule_metrics: RuleMetrics) -> None:
        """End processing a specific rule"""
        if self.current_rule_start:
            generation_time = time.time() - self.current_rule_start
            rule_metrics.generation_time = generation_time
            self.generation_times.append(generation_time)
            
            # Update statistics
            self.category_stats[rule_metrics.category] += 1
            self.priority_stats[rule_metrics.priority] += 1
            self.status_stats[rule_metrics.status] += 1
            
            # Track errors
            if not rule_metrics.success:
                self.error_counts[rule_metrics.error_message or "Unknown error"] += 1
                self.metrics.failed_generations += 1
            else:
                self.metrics.successful_generations += 1
            
            # Track validation issues
            for issue in rule_metrics.validation_issues:
                self.validation_issues[issue] += 1
            
            self.rule_metrics.append(rule_metrics)
            self.current_rule_start = None
    
    def add_progress_callback(self, callback: callable) -> None:
        """Add a progress callback function"""
        self.progress_callbacks.append(callback)
    
    def get_progress_percentage(self) -> float:
        """Get current progress percentage"""
        if self.metrics.total_rules == 0:
            return 0.0
        return (self.metrics.processed_rules / self.metrics.total_rules) * 100
    
    def get_estimated_time_remaining(self) -> Optional[timedelta]:
        """Get estimated time remaining based on current progress"""
        if not self.generation_times or self.metrics.processed_rules == 0:
            return None
        
        avg_time = sum(self.generation_times) / len(self.generation_times)
        remaining_rules = self.metrics.total_rules - self.metrics.processed_rules
        estimated_seconds = remaining_rules * avg_time
        
        return timedelta(seconds=estimated_seconds)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get a comprehensive performance summary"""
        return {
            'session_id': self.session_id,
            'metrics': asdict(self.metrics),
            'category_distribution': dict(self.category_stats),
            'priority_distribution': dict(self.priority_stats),
            'status_distribution': dict(self.status_stats),
            'error_summary': dict(self.error_counts),
            'validation_issues': dict(self.validation_issues),
            'performance_stats': {
                'min_generation_time': min(self.generation_times) if self.generation_times else 0,
                'max_generation_time': max(self.generation_times) if self.generation_times else 0,
                'avg_generation_time': self.metrics.average_generation_time,
                'total_generation_time': sum(self.generation_times),
                'rules_per_second': self.metrics.processed_rules / self.metrics.total_duration if self.metrics.total_duration > 0 else 0
            }
        }
    
    def export_metrics(self, output_file: str) -> None:
        """Export metrics to a JSON file"""
        summary = self.get_performance_summary()
        summary['export_date'] = datetime.now().isoformat()
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Metrics exported to: {output_file}")
    
    def generate_report(self) -> str:
        """Generate a human-readable performance report"""
        summary = self.get_performance_summary()
        
        report = f"""
# SOC SOP Generator Performance Report

**Session ID:** {summary['session_id']}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Generation Summary
- **Total Rules:** {summary['metrics']['total_rules']}
- **Processed Rules:** {summary['metrics']['processed_rules']}
- **Successful Generations:** {summary['metrics']['successful_generations']}
- **Failed Generations:** {summary['metrics']['failed_generations']}
- **Success Rate:** {(summary['metrics']['successful_generations'] / summary['metrics']['processed_rules'] * 100):.1f}%

## Performance Metrics
- **Total Duration:** {summary['metrics']['total_duration']:.2f} seconds
- **Average Generation Time:** {summary['metrics']['average_generation_time']:.2f} seconds
- **Rules per Second:** {summary['performance_stats']['rules_per_second']:.2f}
- **Output Files:** {summary['metrics']['output_file_count']}
- **Total Output Size:** {summary['metrics']['total_output_size_mb']:.2f} MB

## Category Distribution
"""
        
        for category, count in summary['category_distribution'].items():
            percentage = (count / summary['metrics']['processed_rules'] * 100) if summary['metrics']['processed_rules'] > 0 else 0
            report += f"- **{category.title()}:** {count} ({percentage:.1f}%)\n"
        
        report += "\n## Priority Distribution\n"
        for priority, count in summary['priority_distribution'].items():
            percentage = (count / summary['metrics']['processed_rules'] * 100) if summary['metrics']['processed_rules'] > 0 else 0
            report += f"- **{priority.title()}:** {count} ({percentage:.1f}%)\n"
        
        if summary['error_summary']:
            report += "\n## Error Summary\n"
            for error, count in summary['error_summary'].items():
                report += f"- **{error}:** {count} occurrences\n"
        
        if summary['validation_issues']:
            report += "\n## Validation Issues\n"
            for issue, count in summary['validation_issues'].items():
                report += f"- **{issue}:** {count} occurrences\n"
        
        return report


class AnalyticsEngine:
    """Advanced analytics for SOP generation patterns and trends"""
    
    def __init__(self):
        self.historical_data: List[Dict[str, Any]] = []
        self.trend_analysis = {}
    
    def add_session_data(self, session_data: Dict[str, Any]) -> None:
        """Add session data for trend analysis"""
        self.historical_data.append(session_data)
    
    def analyze_trends(self) -> Dict[str, Any]:
        """Analyze trends across multiple sessions"""
        if len(self.historical_data) < 2:
            return {"message": "Insufficient data for trend analysis"}
        
        trends = {
            'performance_trends': self._analyze_performance_trends(),
            'error_patterns': self._analyze_error_patterns(),
            'category_trends': self._analyze_category_trends(),
            'quality_metrics': self._analyze_quality_metrics()
        }
        
        return trends
    
    def _analyze_performance_trends(self) -> Dict[str, Any]:
        """Analyze performance trends over time"""
        durations = [session['metrics']['total_duration'] for session in self.historical_data]
        success_rates = [
            (session['metrics']['successful_generations'] / session['metrics']['processed_rules'] * 100)
            for session in self.historical_data if session['metrics']['processed_rules'] > 0
        ]
        
        return {
            'avg_duration': sum(durations) / len(durations),
            'duration_trend': 'improving' if durations[-1] < durations[0] else 'degrading',
            'avg_success_rate': sum(success_rates) / len(success_rates),
            'success_rate_trend': 'improving' if success_rates[-1] > success_rates[0] else 'degrading'
        }
    
    def _analyze_error_patterns(self) -> Dict[str, Any]:
        """Analyze error patterns across sessions"""
        all_errors = []
        for session in self.historical_data:
            all_errors.extend(session.get('error_summary', {}).keys())
        
        error_frequency = Counter(all_errors)
        return {
            'most_common_errors': error_frequency.most_common(5),
            'total_error_types': len(error_frequency),
            'error_reduction_trend': self._calculate_error_reduction_trend()
        }
    
    def _analyze_category_trends(self) -> Dict[str, Any]:
        """Analyze category distribution trends"""
        category_trends = defaultdict(list)
        
        for session in self.historical_data:
            for category, count in session.get('category_distribution', {}).items():
                category_trends[category].append(count)
        
        return {
            'category_growth': {
                cat: trends[-1] - trends[0] if len(trends) > 1 else 0
                for cat, trends in category_trends.items()
            },
            'most_processed_category': max(category_trends.items(), key=lambda x: sum(x[1]))[0] if category_trends else None
        }
    
    def _analyze_quality_metrics(self) -> Dict[str, Any]:
        """Analyze quality metrics over time"""
        validation_issues = []
        for session in self.historical_data:
            validation_issues.extend(session.get('validation_issues', {}).keys())
        
        return {
            'total_validation_issues': len(set(validation_issues)),
            'most_common_validation_issues': Counter(validation_issues).most_common(5),
            'quality_improvement': self._calculate_quality_improvement()
        }
    
    def _calculate_error_reduction_trend(self) -> str:
        """Calculate if errors are being reduced over time"""
        if len(self.historical_data) < 2:
            return "insufficient_data"
        
        recent_errors = sum(self.historical_data[-1].get('error_summary', {}).values())
        early_errors = sum(self.historical_data[0].get('error_summary', {}).values())
        
        if recent_errors < early_errors:
            return "improving"
        elif recent_errors > early_errors:
            return "degrading"
        else:
            return "stable"
    
    def _calculate_quality_improvement(self) -> str:
        """Calculate quality improvement trend"""
        if len(self.historical_data) < 2:
            return "insufficient_data"
        
        recent_issues = len(self.historical_data[-1].get('validation_issues', {}))
        early_issues = len(self.historical_data[0].get('validation_issues', {}))
        
        if recent_issues < early_issues:
            return "improving"
        elif recent_issues > early_issues:
            return "degrading"
        else:
            return "stable"
    
    def generate_analytics_report(self) -> str:
        """Generate a comprehensive analytics report"""
        trends = self.analyze_trends()
        
        report = f"""
# SOC SOP Generator Analytics Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Sessions Analyzed:** {len(self.historical_data)}

## Performance Trends
- **Average Duration:** {trends['performance_trends']['avg_duration']:.2f} seconds
- **Duration Trend:** {trends['performance_trends']['duration_trend']}
- **Average Success Rate:** {trends['performance_trends']['avg_success_rate']:.1f}%
- **Success Rate Trend:** {trends['performance_trends']['success_rate_trend']}

## Error Analysis
- **Total Error Types:** {trends['error_patterns']['total_error_types']}
- **Error Trend:** {trends['error_patterns']['error_reduction_trend']}
- **Most Common Errors:**
"""
        
        for error, count in trends['error_patterns']['most_common_errors']:
            report += f"  - {error}: {count} occurrences\n"
        
        report += "\n## Category Trends\n"
        for category, growth in trends['category_trends']['category_growth'].items():
            trend_indicator = "UP" if growth > 0 else "DOWN" if growth < 0 else "STABLE"
            report += f"- **{category.title()}:** {trend_indicator} {growth:+d} rules\n"
        
        report += "\n## Quality Metrics\n"
        report += f"- **Total Validation Issues:** {trends['quality_metrics']['total_validation_issues']}\n"
        report += f"- **Quality Trend:** {trends['quality_metrics']['quality_improvement']}\n"
        
        return report 