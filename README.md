# SOC Standard Operating Procedure (SOP) Generator

Enterprise-grade tool for generating professional Standard Operating Procedures from security correlation rules for Security Operations Center teams.

**Version**: 1.0.0  
**Last Updated**: 2025-07-22  
**License**: MIT License

## Overview

The SOC SOP Generator is a comprehensive solution for creating professional Standard Operating Procedures for SOC teams. It supports multiple input formats, provides intelligent rule analysis with MITRE ATT&CK mapping, and offers flexible output options including direct Confluence integration for enterprise environments.

## Key Features

- **Professional SOP Templates**: Enterprise-grade templates following SOC best practices
- **Multiple Input Formats**: Security platform backup summaries, custom JSON, CSV, and text files
- **Intelligent Auto-detection**: Automatically detects input file format
- **Flexible Output**: Generate SOPs in Markdown, HTML, JSON, and PDF formats
- **MITRE ATT&CK Mapping**: Automatic mapping to MITRE ATT&CK tactics and techniques
- **Confluence Integration**: Direct upload to Confluence with professional formatting
- **Rule Optimization**: Analyze and optimize security correlation rules
- **Configuration Management**: Comprehensive settings and preferences system
- **Input Validation**: Robust validation for rule completeness and data integrity
- **Performance Metrics**: Built-in KPIs and response time tracking

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd soc_sop_generator_standalone
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Usage

Generate SOPs from a security platform backup summary:
```bash
python main.py generate --input backup_summary.json
```

Generate SOPs from a custom JSON file:
```bash
python main.py generate --input custom_rules.json --input-format custom_json
```

Generate SOPs from a CSV file:
```bash
python main.py generate --input rules.csv --input-format csv
```

### Interactive Mode

For guided SOP generation:
```bash
python main.py interactive
```

### Upload to Confluence

Upload SOPs directly to Confluence:
```bash
python main.py upload-to-confluence \
  --input rules.json \
  --confluence-url "https://your-domain.atlassian.net" \
  --confluence-username "your-email@your-company.com" \
  --confluence-token "your-api-token" \
  --confluence-space "YOUR_SPACE_KEY" \
  --dry-run
```

## Supported Input Formats

### 1. Security Platform Backup Summary JSON

Standard format from security platform backup tools:

```json
{
  "saved_rules": [
    {
      "rule_id": "example_rule_001",
      "rule_name": "Example Rule Name",
      "description": "Description of what this rule detects",
      "search_filter": "event_simpleName=ProcessRollup2 AND CommandLine=*example*",
      "search_outcome": "Detects suspicious command line activity",
      "status": "active",
      "created_on": "2025-01-21T00:00:00Z",
      "last_updated_on": "2025-01-21T00:00:00Z"
    }
  ]
}
```

### 2. Custom JSON Format

Simplified JSON format for custom rule data:

```json
{
  "rules": [
    {
      "rule_id": "custom_rule_001",
      "rule_name": "Custom Rule Name",
      "description": "Description of what this rule detects",
      "search_filter": "event_simpleName=ProcessRollup2 AND CommandLine=*suspicious*",
      "search_outcome": "Detects suspicious process activity",
      "status": "active",
      "created_on": "2025-01-21T00:00:00Z",
      "last_updated_on": "2025-01-21T00:00:00Z"
    }
  ]
}
```

### 3. CSV Format

Simple CSV format for rule data:

```csv
rule_id,rule_name,description,search_filter,search_outcome,status,created_on,last_updated_on
csv_rule_001,CSV Rule Name,Description of what this rule detects,event_simpleName=ProcessRollup2 AND CommandLine=*csv*,Detects suspicious CSV activity,active,2025-01-21T00:00:00Z,2025-01-21T00:00:00Z
```

### 4. Text File Format

Simple text format for basic rule data:

```text
rule_id: example_rule_001
rule_name: Example Rule Name
description: Description of what this rule detects
search_filter: event_simpleName=ProcessRollup2 AND CommandLine=*example*
search_outcome: Detects suspicious command line activity
status: active
created_on: 2025-01-21T00:00:00Z
last_updated_on: 2025-01-21T00:00:00Z
---
rule_id: example_rule_002
rule_name: Another Rule Name
description: Another rule description
search_filter: event_simpleName=UserLogon AND UserName=*admin*
search_outcome: Detects admin login events
status: active
created_on: 2025-01-21T00:00:00Z
last_updated_on: 2025-01-21T00:00:00Z
```

## Output Formats

- **Markdown**: `{rule_name}_SOP.md`
- **HTML**: `{rule_name}_SOP.html` with embedded CSS styling
- **JSON**: `{rule_name}_SOP.json` with structured metadata
- **PDF**: `{rule_name}_SOP.md` (PDF-ready Markdown)
- **Confluence**: `{rule_name}_SOP.confluence` with proper formatting

## Available Commands

### Core Commands
- `generate`: Generate SOPs from input file
- `generate-multi-rule-sops`: Generate multi-rule SOPs from input file
- `generate-templates`: Generate input file templates for different formats
- `interactive`: Interactive mode for guided SOP generation

### Analysis Commands
- `mitre-mapping`: Analyze and map security rules to MITRE ATT&CK techniques
- `optimize-rules`: Analyze and optimize security correlation rules
- `validate-rules`: Validate rules without generating SOPs
- `analytics`: Generate analytics and performance reports

### Configuration Commands
- `config`: Manage configuration settings
- `performance`: Analyze performance metrics and generate reports
- `security-audit`: Perform security audit of the tool and environment
- `version`: Show version information

### Confluence Commands
- `upload-to-confluence`: Upload SOPs directly to Confluence

## Command Examples

### Generate Individual SOPs
```bash
# Basic generation
python main.py generate -i test_data.json -o output --format markdown

# With filtering
python main.py generate -i rules.json --rule-filter "malware" --status active

# Multiple formats
python main.py generate -i rules.json --format html
python main.py generate -i rules.json --format json
python main.py generate -i rules.json --format pdf
```

### Generate Multi-Rule SOPs
```bash
# Generate single document with all rules
python main.py generate --input rules.json --multi-rule

# Generate category-grouped SOPs
python main.py generate --input rules.json --category-grouping

# Generate for specific category
python main.py generate --input rules.json --category-grouping --category service_account_misuse
```

### MITRE ATT&CK Mapping
```bash
# Map rules to MITRE ATT&CK
python main.py mitre-mapping -i test_data.json --detailed

# Export mapping report
python main.py mitre-mapping -i rules.json -o mapping_report.md --format markdown
```

### Rule Optimization
```bash
# Analyze rule optimization opportunities
python main.py optimize-rules -i test_data.json --detailed

# Apply optimizations automatically
python main.py optimize-rules -i rules.json --apply
```

### Configuration Management
```bash
# View current configuration
python main.py config

# Set configuration values
python main.py config --set user_preferences default_output_format html

# Export configuration
python main.py config --export my_config.json
```

### Upload to Confluence
```bash
# Create drafts for review
python main.py upload-to-confluence \
  --input rules.json \
  --confluence-url "https://your-domain.atlassian.net" \
  --confluence-username "your-email@your-company.com" \
  --confluence-token "your-api-token" \
  --confluence-space "YOUR_SPACE_KEY" \
  --as-draft \
  --save-locally

# Upload as published pages
python main.py upload-to-confluence \
  --input rules.json \
  --confluence-url "https://your-domain.atlassian.net" \
  --confluence-username "your-email@your-company.com" \
  --confluence-token "your-api-token" \
  --confluence-space "YOUR_SPACE_KEY" \
  --save-locally
```

## Advanced Organization Tools

For enhanced SOP organization and categorization, use the unified grouping tool:

```bash
# Basic category grouping
python tools/unified_sop_grouper.py --strategy basic

# Advanced account security grouping
python tools/unified_sop_grouper.py --strategy advanced

# Comprehensive generic grouping
python tools/unified_sop_grouper.py --strategy generic

# All strategies at once
python tools/unified_sop_grouper.py --strategy all
```

## Confluence Integration

### Setup
1. Generate API Token: Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Find Space Key: Look at your Confluence URL: `https://your-domain.atlassian.net/wiki/spaces/YOUR_SPACE_KEY/`
3. Test Connection: Use `--dry-run` flag to test without creating pages

### Environment Variables
Create a `.env.confluence` file:
```bash
CONFLUENCE_URL=https://your-domain.atlassian.net
CONFLUENCE_USERNAME=your-email@your-company.com
CONFLUENCE_API_TOKEN=your-api-token
CONFLUENCE_SPACE_KEY=YOUR_SPACE_KEY
```

### Features
- Direct upload to Confluence via API
- Draft creation for review before publishing
- Page management (create new or update existing)
- Proper Confluence formatting with macros and tables
- Metadata inclusion (rule information, timestamps, version tracking)
- Comprehensive error reporting and validation
- Batch operations for multiple SOPs
- Local saving for offline review

## MITRE ATT&CK Integration

The tool automatically maps security rules to MITRE ATT&CK tactics and techniques based on rule names, descriptions, and search filters.

### Supported ATT&CK Mappings
- **Reconnaissance** (TA0043): Information gathering activities
- **Resource Development** (TA0042): Infrastructure and capability development
- **Initial Access** (TA0001): Gaining initial foothold
- **Execution** (TA0002): Running malicious code
- **Persistence** (TA0003): Maintaining foothold
- **Privilege Escalation** (TA0004): Gaining higher-level permissions
- **Defense Evasion** (TA0005): Avoiding detection
- **Credential Access** (TA0006): Stealing account credentials
- **Discovery** (TA0007): Understanding the environment
- **Lateral Movement** (TA0008): Moving through the network
- **Collection** (TA0009): Gathering data of interest
- **Command and Control** (TA0011): Communicating with compromised systems
- **Exfiltration** (TA0010): Stealing data
- **Impact** (TA0040): Manipulating, disrupting, or destroying systems

### Example Mappings
- Privilege Escalation Detection → T1068 (Exploitation for Privilege Escalation)
- Credential Dumping Detection → T1003 (OS Credential Dumping)
- Lateral Movement Detection → T1021 (Remote Services)
- Service Account Misuse → T1078 (Valid Accounts)

## Professional SOP Templates

The generator includes comprehensive, enterprise-grade SOP templates that follow SOC best practices:

### Template Features
- **Document Control**: Version tracking, review dates, and approval workflows
- **Executive Summary**: Quick reference tables with key metrics
- **Response Procedures**: Step-by-step triage with checkboxes and timeframes
- **Escalation Matrix**: Clear criteria for different escalation levels
- **Performance Metrics**: Built-in KPIs and response time tracking
- **Containment Procedures**: Network, system, and data protection steps
- **Recovery Procedures**: System restoration and business continuity
- **Lessons Learned**: Process improvement tracking
- **Contact Information**: Role-based contact matrices

### Template Categories
1. **Default Template**: Professional template for general correlation rules
2. **Service Account Misuse**: Specialized template for service account monitoring
3. **Privilege Escalation**: Template for privilege escalation detection
4. **Configuration Change**: Template for system configuration monitoring
5. **Data Exfiltration**: Template for data loss prevention
6. **Network Anomaly**: Template for network security monitoring

### Professional Formatting
- **Confluence Integration**: Professional macros and formatting
- **Table Structures**: Organized information presentation
- **Status Indicators**: Visual progress tracking
- **Color-coded Sections**: Info, Warning, Tip, and Note macros

## Examples and Testing

The `examples/` directory contains safe example files for testing:

### Available Example Files
1. **`sample_backup_summary.json`**: Sample security platform backup summary
2. **`sample_custom_json.json`**: Sample custom JSON format file
3. **`sample_rules.csv`**: Sample CSV format file
4. **`sample_config.json`**: Basic configuration file
5. **`sample_confluence_config.env`**: Environment variables for Confluence setup
6. **`sample_user_config.json`**: Comprehensive configuration
7. **`setup_instructions.md`**: Detailed setup instructions

### Template Generation
The tool can generate input file templates dynamically:
```bash
python main.py generate-templates
```
This creates template files in the `templates/` directory for all supported input formats.

### Testing Commands
```bash
# Generate SOPs from backup summary
python main.py generate -i examples/sample_backup_summary.json -o output/test_sops

# Test MITRE mapping
python main.py mitre-mapping -i examples/sample_backup_summary.json --detailed

# Test rule optimization
python main.py optimize-rules -i examples/sample_backup_summary.json --detailed

# Test validation
python main.py validate-rules -i examples/sample_backup_summary.json --detailed
```

## Project Structure

```
soc_sop_generator_standalone/
├── main.py                    # Main CLI interface
├── requirements.txt           # Python dependencies
├── .gitignore                # Git ignore rules for sensitive data
├── README.md                 # Project documentation
├── SECURITY_SETUP.md         # Security setup guide
├── env.template              # Environment variables template
├── security_check.py         # Security validation script
├── push_to_github.sh         # GitHub push helper script
├── src/                      # Source code modules
│   ├── __init__.py
│   ├── sop_generator.py      # Main SOP generation logic
│   ├── rule_analyzer.py      # Rule analysis and categorization
│   ├── rule_optimizer.py     # Rule optimization and analysis
│   ├── templates.py          # SOP templates and formatting
│   ├── input_parsers.py      # Input format parsers
│   ├── input_validator.py    # Input validation and verification
│   ├── mitre_attack_mapper.py # MITRE ATT&CK mapping
│   ├── mitre_attack_expanded.py # Expanded MITRE ATT&CK library
│   ├── confluence_api.py     # Confluence API integration
│   ├── confluence_formatter.py # Confluence formatting
│   ├── unified_config.py     # Unified configuration management
│   ├── cli_commands.py       # CLI command functions
│   └── progress_tracker.py   # Progress tracking and analytics
├── tools/                    # Advanced organization tools
│   ├── unified_sop_grouper.py # Unified SOP grouping and organization
│   ├── advanced_sop_grouping.py # Advanced SOP grouping strategies
│   ├── generic_sop_grouping.py # Generic SOP grouping strategies
│   └── group_sops.py         # Basic SOP grouping functionality
├── templates/                # Input file templates
│   ├── custom_json_template.json
│   ├── csv_template.csv
│   └── text_template.txt
├── examples/                 # Example files for testing
│   ├── sample_config.json
│   ├── sample_custom_json.json
│   ├── sample_user_config.json
│   ├── sample_backup_summary.json
│   ├── sample_rules.csv
│   ├── sample_confluence_config.env
│   └── setup_instructions.md
├── input/                    # Input files (gitignored)
├── output/                   # Generated SOPs (gitignored)
└── venv/                    # Virtual environment (gitignored)
```

## Enterprise Features

### Professional Output
- **Enterprise-grade SOPs**: Following industry best practices and standards
- **Compliance Ready**: Templates designed for audit and compliance requirements
- **Scalable**: Handles large rule sets efficiently
- **Integration Ready**: Works with existing SOC tools and processes

### Quality Assurance
- **Input Validation**: Comprehensive validation of rule data
- **Template Consistency**: Standardized formatting across all SOPs
- **Version Control**: Built-in version tracking and change management
- **Review Workflows**: Support for draft creation and review processes

## Security Considerations

### Data Protection
- No credential storage in plain text
- Environment variable-based configuration
- Input validation to prevent injection attacks
- User input sanitization

### Best Practices
- Use environment variables for sensitive configuration
- Store API tokens securely and rotate regularly
- Use HTTPS for all API communications
- Implement proper access controls for generated SOPs

### Git Security
- Comprehensive `.gitignore` rules prevent accidental commits of sensitive data
- Input files in `input/` directory are automatically ignored
- Output files in `output/` directory are automatically ignored
- Configuration files are ignored

## Testing and Validation

### Basic Testing
```bash
# Generate SOPs from your input file
python main.py generate --input your_input_file.json

# Verify output in output/generated_sops/ directory
ls output/generated_sops/
```

### Advanced Testing
```bash
# Test input validation
python main.py validate-rules --input your_input_file.json

# Test rule optimization
python main.py optimize-rules --input your_input_file.json

# Test performance analytics
python main.py performance

# Test configuration management
python main.py config
```

### Validation
The tool validates input files to ensure:
- All required fields are present
- Rule IDs are unique
- Search filters are properly formatted
- Status values are valid

## Configuration

### Environment Variables
```bash
export SOP_AUTHOR="Your Name"
export SOP_CONTACT_EMAIL="your-email@your-company.com"
export SOP_GITHUB_URL="https://github.com/your-username"
export SOP_ORGANIZATION="Your Organization"
```

### Configuration File
Create `.soc_sop_config.json`:
```json
{
  "user_preferences": {
    "default_output_format": "markdown",
    "default_output_directory": "output/generated_sops"
  },
  "template_settings": {
    "author": "Your Name",
    "contact_email": "your-email@your-company.com",
    "organization": "Your Organization"
  },
  "advanced_settings": {
    "mitre_attack_version": "14.1",
    "confidence_threshold": 0.7
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided "AS IS" without any warranties. Use at your own risk. Always review and validate generated content before implementation in any production environment. The author is not liable for any damages or consequences from the use of this software.
