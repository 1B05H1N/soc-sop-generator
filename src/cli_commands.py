"""
CLI Commands Module

This module contains all the CLI command functions extracted from main.py
to improve maintainability and organization.
"""

import click
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from src.sop_generator import SOPGenerator
from src.unified_config import config

console = Console()


def display_disclaimer():
    """Display the disclaimer panel"""
    console.print(Panel.fit(
        "[bold red]DISCLAIMER:[/bold red] This software is provided 'AS IS' without warranties. "
        "Use at your own risk. Always review and validate generated content before implementation "
        "in any production environment. The author is not liable for any damages or consequences.",
        title="[bold red]IMPORTANT NOTICE[/bold red]",
        border_style="red"
    ))


def generate_command(input_file, input_format, output_dir, output_format, rule_filter, status, category, priority, 
                    dry_run, multi_rule, category_grouping, validate, streaming, paginated, with_fallback):
    """Generate SOPs from input file"""
    
    display_disclaimer()
    
    if not Path(input_file).exists():
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    console.print(Panel.fit(
        f"Generating SOPs from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator(output_dir)
    
    # Determine input format
    if input_format == 'auto':
        input_format = None  # Let the parser auto-detect
    
    # Validate rules if requested
    if validate:
        with console.status("[bold green]Validating rules..."):
            if input_format == 'backup_summary' or (input_format is None and 'backup_summary' in input_file):
                backup_summary = generator.rule_analyzer.load_backup_summary(input_file)
                rules = generator.rule_analyzer.extract_rules(backup_summary)
            else:
                # For other formats, we'll validate during generation
                pass
    
    # Generate SOPs
    with console.status("[bold green]Generating SOPs..."):
        try:
            if multi_rule:
                result = generator.generate_multi_rule_sops(
                    input_file, input_format, output_format, 
                    rule_filter, status, category, priority, dry_run
                )
            elif category_grouping:
                result = generator.generate_category_grouped_sops(
                    input_file, input_format, output_format,
                    rule_filter, status, category, priority, dry_run
                )
            else:
                result = generator.generate_sops(
                    input_file, input_format, output_format,
                    rule_filter, status, category, priority, dry_run,
                    streaming, paginated, with_fallback
                )
            
            if result:
                # Save SOPs to files
                saved_files = generator.save_sops_batch(result, output_format)
                console.print(f"[green]Successfully generated {len(saved_files)} SOPs in {output_dir}[/green]")
                for file_path in saved_files:
                    console.print(f"  [blue]Saved: {file_path}[/blue]")
            else:
                console.print("[yellow]No SOPs were generated[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error generating SOPs: {e}[/red]")


def interactive_command(input_file, output_dir, output_format):
    """Interactive mode for guided SOP generation"""
    
    display_disclaimer()
    
    console.print(Panel.fit(
        "Interactive SOP Generation Mode",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Get input file
    if not input_file:
        input_file = click.prompt("Enter path to input file", type=str)
    
    if not Path(input_file).exists():
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    # Get output directory
    if not output_dir:
        output_dir = click.prompt("Enter output directory", default="output/generated_sops", type=str)
    
    # Get output format
    if not output_format:
        output_format = click.prompt(
            "Select output format",
            type=click.Choice(['markdown', 'html', 'json', 'pdf']),
            default='markdown'
        )
    
    # Get input format
    input_format = click.prompt(
        "Select input format (or 'auto' for auto-detection)",
        type=click.Choice(['auto', 'backup_summary', 'custom_json', 'csv', 'text']),
        default='auto'
    )
    
    if input_format == 'auto':
        input_format = None
    
    # Get filters
    rule_filter = click.prompt("Filter rules by name (optional)", default="", type=str)
    if not rule_filter:
        rule_filter = None
    
    status = click.prompt(
        "Filter by status (optional)",
        type=click.Choice(['', 'active', 'inactive']),
        default=''
    )
    if not status:
        status = None
    
    category = click.prompt("Filter by category (optional)", default="", type=str)
    if not category:
        category = None
    
    priority = click.prompt(
        "Filter by priority (optional)",
        type=click.Choice(['', 'high', 'medium', 'low']),
        default=''
    )
    if not priority:
        priority = None
    
    # Confirm generation
    if click.confirm("Proceed with SOP generation?"):
        generate_command(
            input_file, input_format, output_dir, output_format,
            rule_filter, status, category, priority,
            False, False, False, False, False, False, False
        )


def generate_multi_rule_sops_command(input_file, input_format, output_dir, output_format, category, rule_filter, status, dry_run):
    """Generate multi-rule SOPs from input file"""
    
    display_disclaimer()
    
    if not Path(input_file).exists():
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    console.print(Panel.fit(
        f"Generating multi-rule SOPs from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator(output_dir)
    
    # Determine input format
    if input_format == 'auto':
        input_format = None  # Let the parser auto-detect
    
    # Generate multi-rule SOPs
    with console.status("[bold green]Generating multi-rule SOPs..."):
        try:
            result = generator.generate_multi_rule_sops(
                input_file, input_format, output_format,
                category, rule_filter, status, dry_run
            )
            
            if result:
                console.print(f"[green]Successfully generated multi-rule SOPs in {output_dir}[/green]")
            else:
                console.print("[yellow]No multi-rule SOPs were generated[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error generating multi-rule SOPs: {e}[/red]")


def generate_templates_command(output_dir):
    """Generate input file templates for different formats"""
    
    console.print(Panel.fit(
        "Generating input file templates",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate templates
    with console.status("[bold green]Generating templates..."):
        try:
            generator = SOPGenerator()
            templates = generator.generate_input_templates(output_path)
            
            console.print(f"[green]Successfully generated {len(templates)} templates in {output_dir}[/green]")
            
            # Display template information
            table = Table(title="Generated Templates")
            table.add_column("Template", style="cyan")
            table.add_column("Description", style="green")
            table.add_column("File", style="yellow")
            
            for template_name, template_info in templates.items():
                table.add_row(
                    template_name,
                    template_info.get('description', ''),
                    template_info.get('file', '')
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error generating templates: {e}[/red]")


def upload_to_confluence_command(input_file, input_format, confluence_url, confluence_username, 
                               confluence_token, confluence_space, confluence_parent, confluence_folder, rule_filter,
                               status, category, priority, update_existing, as_draft, save_locally, dry_run):
    """Upload SOPs directly to Confluence"""
    
    display_disclaimer()
    
    if not Path(input_file).exists():
        console.print(f"[red]Error: Input file '{input_file}' not found[/red]")
        return
    
    # Read environment variables if not provided
    import os
    from dotenv import load_dotenv
    
    # Load .env.confluence file if it exists
    env_file = Path('.env.confluence')
    if env_file.exists():
        load_dotenv(env_file)
    
    if not confluence_url:
        confluence_url = os.getenv('CONFLUENCE_URL')
    if not confluence_username:
        confluence_username = os.getenv('CONFLUENCE_USERNAME')
    if not confluence_token:
        confluence_token = os.getenv('CONFLUENCE_API_TOKEN')
    if not confluence_space:
        confluence_space = os.getenv('CONFLUENCE_SPACE_KEY')
    if not confluence_parent:
        confluence_parent = os.getenv('CONFLUENCE_PARENT_PAGE_ID')
    
    # Validate required parameters
    if not confluence_url:
        console.print("[red]Error: Confluence URL is required (--confluence-url or CONFLUENCE_URL env var)[/red]")
        return
    if not confluence_username:
        console.print("[red]Error: Confluence username is required (--confluence-username or CONFLUENCE_USERNAME env var)[/red]")
        return
    if not confluence_token:
        console.print("[red]Error: Confluence API token is required (--confluence-token or CONFLUENCE_API_TOKEN env var)[/red]")
        return
    if not confluence_space:
        console.print("[red]Error: Confluence space key is required (--confluence-space or CONFLUENCE_SPACE_KEY env var)[/red]")
        return
    
    console.print(Panel.fit(
        f"Uploading SOPs to Confluence from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Determine input format
    if input_format == 'auto':
        input_format = None  # Let the parser auto-detect
    
    # Upload to Confluence
    with console.status("[bold green]Uploading to Confluence..."):
        try:
            result = generator.upload_to_confluence(
                input_file, input_format, confluence_url, confluence_username,
                confluence_token, confluence_space, confluence_parent, confluence_folder,
                rule_filter, status, category, priority, update_existing, as_draft, save_locally, dry_run
            )
            
            if result:
                console.print("[green]Successfully uploaded SOPs to Confluence[/green]")
            else:
                console.print("[yellow]No SOPs were uploaded[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error uploading to Confluence: {e}[/red]")


def validate_rules_command(input_file, input_format, output_file, detailed):
    """Validate rules without generating SOPs"""
    
    console.print(Panel.fit(
        f"Validating rules from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Determine input format
    if input_format == 'auto':
        input_format = None  # Let the parser auto-detect
    
    # Validate rules
    with console.status("[bold green]Validating rules..."):
        try:
            validation_result = generator.validate_rules(input_file, input_format, detailed)
            
            if validation_result['valid']:
                console.print(f"[green]Validation passed: {validation_result['total_rules']} rules validated successfully[/green]")
            else:
                console.print(f"[yellow]Validation completed with {len(validation_result['issues'])} issues[/yellow]")
            
            # Display issues if any
            if validation_result['issues'] and detailed:
                console.print("\n[bold]Validation Issues:[/bold]")
                for issue in validation_result['issues']:
                    console.print(f"  [red]• {issue}[/red]")
            
            # Save validation report if requested
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(validation_result, f, indent=2)
                console.print(f"[green]Validation report saved to: {output_file}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error validating rules: {e}[/red]")


def security_audit_command(check_data):
    """Perform security audit of the tool and configuration"""
    
    console.print(Panel.fit(
        "Performing Security Audit",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Perform security audit
    with console.status("[bold green]Performing security audit..."):
        try:
            audit_result = generator.security_audit(check_data)
            
            # Display audit results
            if audit_result['overall_status'] == 'PASS':
                console.print("[green]Security audit passed[/green]")
            else:
                console.print(f"[yellow]Security audit completed with {len(audit_result['issues'])} issues[/yellow]")
            
            # Display detailed results
            if audit_result['issues']:
                console.print("\n[bold]Security Issues:[/bold]")
                for issue in audit_result['issues']:
                    console.print(f"  [red]• {issue}[/red]")
            
            # Display recommendations
            if audit_result['recommendations']:
                console.print("\n[bold]Recommendations:[/bold]")
                for rec in audit_result['recommendations']:
                    console.print(f"  [blue]• {rec}[/blue]")
                    
        except Exception as e:
            console.print(f"[red]Error performing security audit: {e}[/red]")


def optimize_rules_command(input_file, output_file, apply, detailed):
    """Analyze and optimize security correlation rules"""
    
    console.print(Panel.fit(
        f"Optimizing rules from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Optimize rules
    with console.status("[bold green]Analyzing and optimizing rules..."):
        try:
            optimization_result = generator.optimize_rules(input_file, apply, detailed)
            
            console.print(f"[green]Optimization analysis completed[/green]")
            console.print(f"Rules analyzed: {optimization_result['total_rules']}")
            console.print(f"Optimization opportunities: {len(optimization_result['opportunities'])}")
            
            if optimization_result['opportunities'] and detailed:
                console.print("\n[bold]Optimization Opportunities:[/bold]")
                for opp in optimization_result['opportunities']:
                    console.print(f"  [yellow]• {opp}[/yellow]")
            
            # Save optimization report if requested
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(optimization_result, f, indent=2)
                console.print(f"[green]Optimization report saved to: {output_file}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error optimizing rules: {e}[/red]")


def config_command(category, set, export, import_file, reset):
    """Manage configuration settings"""
    
    if reset:
        config.reset_to_defaults()
        console.print("[green]Configuration reset to defaults[/green]")
        return
    
    if import_file:
        try:
            config.import_configuration(import_file)
            console.print(f"[green]Configuration imported from: {import_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error importing configuration: {e}[/red]")
        return
    
    if export:
        try:
            config.export_configuration(export)
            console.print(f"[green]Configuration exported to: {export}[/green]")
        except Exception as e:
            console.print(f"[red]Error exporting configuration: {e}[/red]")
        return
    
    if set and len(set) == 3:
        category_name, key, value = set
        try:
            config.set(f"{category_name}.{key}", value)
            config.save_configuration()
            console.print(f"[green]Configuration updated: {category_name}.{key} = {value}[/green]")
        except Exception as e:
            console.print(f"[red]Error setting configuration: {e}[/red]")
        return
    
    # Display configuration
    config.print_config()
    
    # Display validation issues
    issues = config.validate_configuration()
    if issues:
        console.print("\n[bold yellow]Configuration Issues:[/bold yellow]")
        for issue in issues:
            console.print(f"  [red]• {issue}[/red]")


def analytics_command(input_file, output_file, trends):
    """Generate analytics and performance reports"""
    
    console.print(Panel.fit(
        "Generating Analytics Report",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Generate analytics
    with console.status("[bold green]Generating analytics..."):
        try:
            analytics_result = generator.generate_analytics(input_file, trends)
            
            console.print(f"[green]Analytics report generated[/green]")
            console.print(f"Metrics analyzed: {len(analytics_result['metrics'])}")
            
            # Display key metrics
            if analytics_result['metrics']:
                table = Table(title="Key Metrics")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                
                for metric, value in analytics_result['metrics'].items():
                    table.add_row(metric, str(value))
                
                console.print(table)
            
            # Save analytics report if requested
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(analytics_result, f, indent=2)
                console.print(f"[green]Analytics report saved to: {output_file}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error generating analytics: {e}[/red]")


def performance_command(session_id, output_file, export_metrics):
    """Analyze performance metrics and generate reports"""
    
    console.print(Panel.fit(
        "Analyzing Performance Metrics",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Analyze performance
    with console.status("[bold green]Analyzing performance..."):
        try:
            performance_result = generator.analyze_performance(session_id)
            
            console.print(f"[green]Performance analysis completed[/green]")
            console.print(f"Sessions analyzed: {performance_result['total_sessions']}")
            
            # Display performance metrics
            if performance_result['metrics']:
                table = Table(title="Performance Metrics")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                
                for metric, value in performance_result['metrics'].items():
                    table.add_row(metric, str(value))
                
                console.print(table)
            
            # Save performance report if requested
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(performance_result, f, indent=2)
                console.print(f"[green]Performance report saved to: {output_file}[/green]")
            
            # Export metrics if requested
            if export_metrics:
                with open(export_metrics, 'w') as f:
                    json.dump(performance_result['metrics'], f, indent=2)
                console.print(f"[green]Metrics exported to: {export_metrics}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error analyzing performance: {e}[/red]")


def mitre_mapping_command(input_file, output_file, format, detailed, validate):
    """Analyze and map security rules to MITRE ATT&CK techniques"""
    
    console.print(Panel.fit(
        f"Mapping rules to MITRE ATT&CK from: {input_file}",
        title="[bold blue]SOC SOP Generator[/bold blue]"
    ))
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Determine input format
    input_format = None  # Let the parser auto-detect
    
    # Perform MITRE mapping
    with console.status("[bold green]Mapping to MITRE ATT&CK..."):
        try:
            mapping_result = generator.map_to_mitre(input_file, input_format, detailed, validate)
            
            console.print(f"[green]MITRE mapping completed[/green]")
            console.print(f"Rules mapped: {mapping_result['total_rules']}")
            console.print(f"Techniques identified: {len(mapping_result['techniques'])}")
            
            # Display mapping summary
            if mapping_result['techniques'] and detailed:
                table = Table(title="MITRE ATT&CK Techniques")
                table.add_column("Technique", style="cyan")
                table.add_column("Tactic", style="green")
                table.add_column("Rules", style="yellow")
                
                for technique, info in mapping_result['techniques'].items():
                    table.add_row(
                        technique,
                        info.get('tactic', ''),
                        str(len(info.get('rules', [])))
                    )
                
                console.print(table)
            
            # Save mapping report if requested
            if output_file:
                with open(output_file, 'w') as f:
                    if format == 'json':
                        json.dump(mapping_result, f, indent=2)
                    else:
                        # Generate markdown or CSV format
                        pass
                console.print(f"[green]Mapping report saved to: {output_file}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error mapping to MITRE ATT&CK: {e}[/red]")


def version_command():
    """Show version information"""
    
    console.print(Panel.fit(
        f"SOC SOP Generator v{config.get_version()}",
        title="[bold blue]Version Information[/bold blue]"
    ))
    
    console.print(f"Version: {config.get_version()}")
    console.print(f"Last Updated: {config.get_last_updated()}")
    console.print(f"Author: {config.get_author()}")
    console.print(f"Organization: {config.get_organization()}") 