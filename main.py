#!/usr/bin/env python3
"""
SOC Standard Operating Procedure (SOP) Generator

Command-line interface for generating Standard Operating Procedures
from security correlation rules.

This software is provided "AS IS" without any warranties.
Use at your own risk. Always review and validate generated content
before implementation in production environments.
"""

import click
from src.cli_commands import (
    generate_command, interactive_command, generate_multi_rule_sops_command,
    generate_templates_command, upload_to_confluence_command, validate_rules_command,
    security_audit_command, optimize_rules_command, config_command,
    analytics_command, performance_command, mitre_mapping_command, version_command,
    test_confluence_command
)


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    SOC Standard Operating Procedure Generator
    
    Generate Standard Operating Procedures for SOC analysts based on 
    security correlation rules.
    """


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file (JSON, CSV, or security platform backup)')
@click.option('--input-format', type=click.Choice(['auto', 'backup_summary', 'custom_json', 'csv', 'text']), 
              default='auto', help='Input file format (auto-detect if not specified)')
@click.option('--output', '-o', 'output_dir', default='output/generated_sops',
              help='Output directory for generated SOPs')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['markdown', 'html', 'json', 'pdf']), default='markdown',
              help='Output format for SOPs')
@click.option('--rule-filter', help='Filter rules by name (case-insensitive)')
@click.option('--status', type=click.Choice(['active', 'inactive']),
              help='Filter rules by status')
@click.option('--category', help='Filter rules by category')
@click.option('--priority', type=click.Choice(['high', 'medium', 'low']),
              help='Filter rules by priority')
@click.option('--dry-run', is_flag=True, help='Show what would be generated without creating files')
@click.option('--multi-rule', is_flag=True, help='Generate a single document with multiple rules')
@click.option('--category-grouping', is_flag=True, help='Group rules by category and generate multi-rule SOPs')
@click.option('--validate', is_flag=True, help='Validate rules before generating SOPs')
@click.option('--streaming', is_flag=True, help='Use streaming mode for large datasets')
@click.option('--paginated', is_flag=True, help='Generate paginated SOPs for large categories')
@click.option('--with-fallback', is_flag=True, help='Use fallback generation for failed rules')
def generate(input_file, input_format, output_dir, output_format, rule_filter, status, category, priority, 
            dry_run, multi_rule, category_grouping, validate, streaming, paginated, with_fallback):
    """Generate SOPs from input file"""
    generate_command(input_file, input_format, output_dir, output_format, rule_filter, status, category, priority, 
                    dry_run, multi_rule, category_grouping, validate, streaming, paginated, with_fallback)


@cli.command()
@click.option('--input', '-i', 'input_file', help='Path to input file (will prompt if not provided)')
@click.option('--output', '-o', 'output_dir', help='Output directory (will prompt if not provided)')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['markdown', 'html', 'json', 'pdf']), 
              help='Output format (will prompt if not provided)')
def interactive(input_file, output_dir, output_format):
    """Interactive mode for guided SOP generation"""
    interactive_command(input_file, output_dir, output_format)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file (JSON, CSV, or security platform backup)')
@click.option('--input-format', type=click.Choice(['auto', 'backup_summary', 'custom_json', 'csv', 'text']), 
              default='auto', help='Input file format (auto-detect if not specified)')
@click.option('--output', '-o', 'output_dir', default='output/multi_rule_sops',
              help='Output directory for generated multi-rule SOPs')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['markdown', 'html', 'json', 'pdf']), default='markdown',
              help='Output format for SOPs')
@click.option('--category', help='Generate multi-rule SOP for specific category only')
@click.option('--rule-filter', help='Filter rules by name (case-insensitive)')
@click.option('--status', type=click.Choice(['active', 'inactive']),
              help='Filter rules by status')
@click.option('--dry-run', is_flag=True, help='Show what would be generated without creating files')
def generate_multi_rule_sops(input_file, input_format, output_dir, output_format, category, rule_filter, status, dry_run):
    """Generate multi-rule SOPs from input file"""
    generate_multi_rule_sops_command(input_file, input_format, output_dir, output_format, category, rule_filter, status, dry_run)


@cli.command()
@click.option('--output', '-o', 'output_dir', default='templates',
              help='Output directory for input templates')
def generate_templates(output_dir):
    """Generate input file templates for different formats"""
    generate_templates_command(output_dir)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file (JSON, CSV, or security platform backup)')
@click.option('--input-format', type=click.Choice(['auto', 'backup_summary', 'custom_json', 'csv', 'text']), 
              default='auto', help='Input file format (auto-detect if not specified)')
@click.option('--confluence-url', help='Confluence instance URL (or use CONFLUENCE_URL env var)')
@click.option('--confluence-username', help='Confluence username or email (or use CONFLUENCE_USERNAME env var)')
@click.option('--confluence-token', help='Confluence API token (or use CONFLUENCE_API_TOKEN env var)')
@click.option('--confluence-space', help='Confluence space key (or use CONFLUENCE_SPACE_KEY env var)')
@click.option('--confluence-parent', help='Confluence parent page ID (optional)')
@click.option('--confluence-folder', help='Confluence folder name to create/use (optional)')
@click.option('--rule-filter', help='Filter rules by name (case-insensitive)')
@click.option('--status', type=click.Choice(['active', 'inactive']), help='Filter rules by status')
@click.option('--category', help='Filter rules by category')
@click.option('--priority', type=click.Choice(['high', 'medium', 'low']), help='Filter rules by priority')
@click.option('--update-existing', is_flag=True, help='Update existing pages in Confluence')
@click.option('--as-draft', is_flag=True, help='Create pages as drafts for review')
@click.option('--save-locally', is_flag=True, help='Save SOPs locally as Markdown files')
@click.option('--dry-run', is_flag=True, help='Show what would be uploaded without creating pages')
def upload_to_confluence(input_file, input_format, confluence_url, confluence_username, 
                        confluence_token, confluence_space, confluence_parent, confluence_folder, rule_filter,
                        status, category, priority, update_existing, as_draft, save_locally, dry_run):
    """Upload SOPs directly to Confluence"""
    upload_to_confluence_command(input_file, input_format, confluence_url, confluence_username, 
                               confluence_token, confluence_space, confluence_parent, confluence_folder, rule_filter,
                               status, category, priority, update_existing, as_draft, save_locally, dry_run)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file (JSON, CSV, or security platform backup)')
@click.option('--input-format', type=click.Choice(['auto', 'backup_summary', 'custom_json', 'csv', 'text']), 
              default='auto', help='Input file format (auto-detect if not specified)')
@click.option('--output', '-o', 'output_file', help='Output file for validation report (JSON format)')
@click.option('--detailed', is_flag=True, help='Show detailed validation issues')
def validate_rules(input_file, input_format, output_file, detailed):
    """Validate rules without generating SOPs"""
    validate_rules_command(input_file, input_format, output_file, detailed)


@cli.command()
@click.option('--check-data', is_flag=True, help='Also check for sensitive data files')
def security_audit(check_data):
    """Perform security audit of the tool and configuration"""
    security_audit_command(check_data)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file containing rules to optimize')
@click.option('--output', '-o', 'output_file', help='Output file for optimization report')
@click.option('--apply', is_flag=True, help='Apply optimizations automatically')
@click.option('--detailed', is_flag=True, help='Show detailed optimization suggestions')
def optimize_rules(input_file, output_file, apply, detailed):
    """Analyze and optimize security correlation rules"""
    optimize_rules_command(input_file, output_file, apply, detailed)


@cli.command()
@click.option('--category', type=click.Choice(['user_preferences', 'template_settings', 'advanced_settings', 'all']),
              default='all', help='Configuration category to show')
@click.option('--set', nargs=3, help='Set a configuration value (category key value)')
@click.option('--export', help='Export configuration to file')
@click.option('--import', 'import_file', help='Import configuration from file')
@click.option('--reset', is_flag=True, help='Reset to default configuration')
def config(category, set, export, import_file, reset):
    """Manage configuration settings"""
    config_command(category, set, export, import_file, reset)


@cli.command()
@click.option('--input', '-i', 'input_file', help='Path to metrics file to analyze')
@click.option('--output', '-o', 'output_file', help='Output file for analytics report')
@click.option('--trends', is_flag=True, help='Show trend analysis')
def analytics(input_file, output_file, trends):
    """Generate analytics and performance reports"""
    analytics_command(input_file, output_file, trends)


@cli.command()
@click.option('--session-id', help='Specific session ID to analyze')
@click.option('--output', '-o', 'output_file', help='Output file for performance report')
@click.option('--export-metrics', help='Export metrics to JSON file')
def performance(session_id, output_file, export_metrics):
    """Analyze performance metrics and generate reports"""
    performance_command(session_id, output_file, export_metrics)


@cli.command()
@click.option('--input', '-i', 'input_file', required=True,
              help='Path to input file containing rules to map')
@click.option('--output', '-o', 'output_file', help='Output file for mapping report')
@click.option('--format', type=click.Choice(['json', 'csv', 'markdown']), default='markdown',
              help='Output format for mapping report')
@click.option('--detailed', is_flag=True, help='Show detailed mapping information')
@click.option('--validate', is_flag=True, help='Validate mappings against known patterns')
def mitre_mapping(input_file, output_file, format, detailed, validate):
    """Analyze and map security rules to MITRE ATT&CK techniques"""
    mitre_mapping_command(input_file, output_file, format, detailed, validate)


@cli.command()
def test_confluence():
    """Test Confluence connection and configuration"""
    test_confluence_command()


@cli.command()
def version():
    """Show version information"""
    version_command()


if __name__ == '__main__':
    cli() 