# SOC Standard Operating Procedure (SOP) Generator

Enterprise-grade tool for generating professional Standard Operating Procedures from security correlation rules for Security Operations Center teams.

**Version**: 1.0.1
**Last Updated**: 2025-07-23  
**License**: MIT License

## Quick Start

### Prerequisites
- **Python 3.8+** - Download from [python.org](https://www.python.org/downloads/)
- **Git** - Download from [git-scm.com](https://git-scm.com/download/win) (Windows) or install via package manager
- **Internet connection** for package downloads

### Installation

#### Option 1: Automated Setup (Recommended)
```bash
# Clone repository
git clone <repository-url>
cd soc_sop_generator_standalone

# Run automated setup
# Windows:
scripts/setup_windows.bat

# macOS/Linux:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### Option 2: Manual Setup
```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create directories
mkdir input output
```

### First Time Setup

#### 1. Test Basic Functionality
```bash
python main.py --help
```

#### 2. Configure Confluence (Optional)
Create `.env` file:
```env
CONFLUENCE_URL=https://your-domain.atlassian.net
CONFLUENCE_USERNAME=your-email@domain.com
CONFLUENCE_API_TOKEN=your-api-token
CONFLUENCE_SPACE_KEY=YOUR_SPACE_KEY
```

#### 3. Test Confluence Connection
```bash
python main.py test-confluence
```

#### 4. Add Your Data
Place your rule data files in the `input/` directory.

#### 5. Generate Your First SOPs
```bash
python main.py generate --input input/your_rules.json --output output/
```

---

## Available Commands

### Core Commands
```bash
# Generate SOPs
python main.py generate --input input/your_rules.json --output output/

# Upload to Confluence
python main.py upload-to-confluence --input input/your_rules.json --confluence-parent "PARENT_ID"

# Test Confluence connection
python main.py test-confluence

# Validate rules
python main.py validate-rules --input input/your_rules.json
```

### Advanced Commands
```bash
# Multi-rule SOPs
python main.py generate --input input/your_rules.json --multi-rule

# Category grouping
python main.py generate --input input/your_rules.json --category-grouping

# MITRE ATT&CK mapping
python main.py mitre-mapping --input input/your_rules.json --detailed

# Rule optimization
python main.py optimize-rules --input input/your_rules.json --detailed

# Configuration management
python main.py config --category all

# Security audit
python main.py security-audit --check-data

# Performance analysis
python main.py performance

# Analytics
python main.py analytics --input metrics.json

# Interactive mode
python main.py interactive
```

---

## Configuration

### Environment Variables
```bash
# Confluence Configuration
export CONFLUENCE_URL="https://your-domain.atlassian.net"
export CONFLUENCE_USERNAME="your-email@domain.com"
export CONFLUENCE_API_TOKEN="your-api-token"
export CONFLUENCE_SPACE_KEY="YOUR_SPACE_KEY"

# SOP Configuration
export SOP_AUTHOR="Your Name"
export SOP_CONTACT_EMAIL="your-email@your-company.com"
export SOP_ORGANIZATION="Your Organization"
```

### Configuration File
Create `.soc_sop_config.json`:
```json
{
  "user_preferences": {
    "default_output_format": "markdown",
    "default_output_directory": "output/generated_sops",
    "enable_validation": true,
    "enable_fallback": true
  },
  "template_settings": {
    "company_name": "Security Operations Center",
    "department_name": "SOC",
    "contact_email": "your-email@your-company.com",
    "emergency_contact": "emergency@your-company.com"
  },
  "advanced_settings": {
    "mitre_attack_version": "14.1",
    "confidence_threshold": 0.7,
    "enable_ai_enhancement": false
  }
}
```

---

## Confluence Integration

### Setup Confluence

#### 1. Get API Token
1. Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Click "Create API token"
3. Give it a name like "SOC SOP Generator"
4. Copy the token

#### 2. Find Space Key
1. Go to your Confluence space
2. Look at the URL: `https://your-domain.atlassian.net/wiki/spaces/SPACE_KEY/`
3. Copy the `SPACE_KEY` part

#### 3. Test Connection
```bash
python main.py test-confluence
```

**Expected Success Output:**
```
Confluence connection successful!

┌─────────────────────────────────────┐
│        Confluence Configuration     │
├─────────────────────────────────────┤
│ URL        │ https://your-domain.atlassian.net │
│ Username   │ your-email@domain.com             │
│ Space Key  │ YOUR_SPACE_KEY                    │
│ API Token  │ ••••••••                          │
└─────────────────────────────────────┘

Your Confluence configuration is working correctly!
```

### Upload to Confluence

#### Basic Upload
```bash
python main.py upload-to-confluence \
  --input input/your_rules.json \
  --confluence-parent "PARENT_PAGE_ID"
```

#### Update Existing SOPs
```bash
python main.py upload-to-confluence \
  --input input/your_rules.json \
  --confluence-parent "PARENT_PAGE_ID" \
  --update-existing
```

#### Upload as Drafts
```bash
python main.py upload-to-confluence \
  --input input/your_rules.json \
  --confluence-parent "PARENT_PAGE_ID" \
  --as-draft
```

#### Save Locally and Upload
```bash
python main.py upload-to-confluence \
  --input input/your_rules.json \
  --confluence-parent "PARENT_PAGE_ID" \
  --save-locally
```

---

## Supported Input Formats

### 1. Security Platform Backup Summary JSON
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
      "created_on": "2025-07-22T00:00:00Z",
      "last_updated_on": "2025-07-22T00:00:00Z"
    }
  ]
}
```

### 2. Custom JSON Format
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
      "created_on": "2025-07-22T00:00:00Z",
      "last_updated_on": "2025-07-22T00:00:00Z"
    }
  ]
}
```

### 3. CSV Format
```csv
rule_id,rule_name,description,search_filter,search_outcome,status,created_on,last_updated_on
csv_rule_001,CSV Rule Name,Description of what this rule detects,event_simpleName=ProcessRollup2 AND CommandLine=*csv*,Detects suspicious CSV activity,active,2025-07-22T00:00:00Z,2025-07-22T00:00:00Z
```

### 4. Text File Format
```text
rule_id: example_rule_001
rule_name: Example Rule Name
description: Description of what this rule detects
search_filter: event_simpleName=ProcessRollup2 AND CommandLine=*example*
search_outcome: Detects suspicious command line activity
status: active
created_on: 2025-07-22T00:00:00Z
last_updated_on: 2025-07-22T00:00:00Z
---
rule_id: example_rule_002
rule_name: Another Rule Name
description: Another rule description
search_filter: event_simpleName=UserLogon AND UserName=*admin*
search_outcome: Detects admin login events
status: active
created_on: 2025-07-22T00:00:00Z
last_updated_on: 2025-07-22T00:00:00Z
```

---

## Usage Examples

### Basic Workflow
```bash
# 1. Test Confluence connection
python main.py test-confluence

# 2. Generate SOPs
python main.py generate --input input/your_rules.json --output output/

# 3. Upload to Confluence
python main.py upload-to-confluence --input input/your_rules.json --confluence-parent "PARENT_ID"
```

### Filter Specific Rules
```bash
# Generate only specific rules
python main.py generate \
  --input input/your_rules.json \
  --output output/ \
  --rule-filter "sa-qrm"

# Upload only specific rules
python main.py upload-to-confluence \
  --input input/your_rules.json \
  --confluence-parent "PARENT_ID" \
  --rule-filter "sa-qrm"
```

### Multi-Rule SOPs
```bash
# Generate multi-rule SOPs
python main.py generate \
  --input input/your_rules.json \
  --output output/ \
  --multi-rule

# Generate category-grouped SOPs
python main.py generate \
  --input input/your_rules.json \
  --output output/ \
  --category-grouping
```

### Advanced Analysis
```bash
# MITRE ATT&CK mapping
python main.py mitre-mapping --input input/your_rules.json --detailed

# Rule optimization
python main.py optimize-rules --input input/your_rules.json --detailed

# Performance analysis
python main.py performance

# Security audit
python main.py security-audit --check-data
```

---

## Troubleshooting

### Common Issues

#### Python Not Found
```bash
# Windows: Add Python to PATH
set PATH=%PATH%;C:\Python39;C:\Python39\Scripts

# macOS/Linux: Install Python
brew install python  # macOS
sudo apt install python3  # Ubuntu
```

#### pip Not Found
```bash
python -m ensurepip --upgrade
```

#### Virtual Environment Issues
```bash
# Deactivate and reactivate
deactivate
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Or recreate environment
rmdir /s venv  # Windows
rm -rf venv  # macOS/Linux
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

#### Package Installation Errors
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install packages individually if needed
pip install click requests pandas
```

#### Confluence Connection Failed
```bash
# Test with curl
curl -u "your-email@domain.com:your-api-token" \
  "https://your-domain.atlassian.net/rest/api/space/YOUR_SPACE_KEY"

# Check environment variables
echo $CONFLUENCE_URL
echo $CONFLUENCE_USERNAME
echo $CONFLUENCE_API_TOKEN
echo $CONFLUENCE_SPACE_KEY
```

### Verification Commands
```bash
# Check Python
python --version

# Check pip
pip --version

# Check virtual environment
echo $VIRTUAL_ENV  # macOS/Linux
echo %VIRTUAL_ENV%  # Windows

# Check installed packages
pip list

# Test main script
python main.py --help

# Test Confluence connection
python main.py test-confluence
```

---

## Testing

### Basic Testing
```bash
# Test basic functionality
python main.py --help

# Test SOP generation
python main.py generate --input input/your_rules.json --dry-run

# Test Confluence connection
python main.py test-confluence

# Test rule validation
python main.py validate-rules --input input/your_rules.json --detailed
```

### Advanced Testing
```bash
# Test MITRE mapping
python main.py mitre-mapping --input input/your_rules.json --detailed

# Test rule optimization
python main.py optimize-rules --input input/your_rules.json --detailed

# Test performance analytics
python main.py performance

# Test configuration
python main.py config --category all
```

---

## Output Formats

- **Markdown**: `{rule_name}_SOP.md`
- **HTML**: `{rule_name}_SOP.html` with embedded CSS styling
- **JSON**: `{rule_name}_SOP.json` with structured metadata
- **PDF**: `{rule_name}_SOP.md` (PDF-ready Markdown)
- **Confluence**: Direct upload with professional formatting

---

## Project Structure

```
soc_sop_generator_standalone/
├── main.py                    # Main CLI interface
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── .gitignore               # Git ignore rules
├── docs/                    # Documentation
│   └── SECURITY_SETUP.md    # Security setup guide
├── scripts/                 # Utility scripts
│   ├── setup_windows.bat    # Windows automated setup
│   ├── setup_windows.ps1    # PowerShell setup script
│   ├── push_to_github.sh    # GitHub repository setup
│   └── security_check.py    # Security validation script
├── config/                  # Configuration templates
│   └── env.template         # Environment variables template
├── src/                     # Source code modules
│   ├── __init__.py
│   ├── sop_generator.py     # Main SOP generation logic
│   ├── rule_analyzer.py     # Rule analysis and categorization
│   ├── rule_optimizer.py    # Rule optimization and analysis
│   ├── templates.py         # SOP templates and formatting
│   ├── input_parsers.py     # Input format parsers
│   ├── input_validator.py   # Input validation and verification
│   ├── mitre_attack_mapper.py # MITRE ATT&CK mapping
│   ├── mitre_attack_expanded.py # Expanded MITRE ATT&CK library
│   ├── confluence_api.py    # Confluence API integration
│   ├── confluence_formatter.py # Confluence formatting
│   ├── config_manager.py    # Configuration management
│   ├── cli_commands.py      # CLI command functions
│   └── progress_tracker.py  # Progress tracking and analytics
├── tools/                   # Advanced organization tools
│   ├── unified_sop_grouper.py # Unified SOP grouping and organization
│   ├── advanced_sop_grouping.py # Advanced SOP grouping strategies
│   ├── generic_sop_grouping.py # Generic SOP grouping strategies
│   └── group_sops.py        # Basic SOP grouping functionality
├── templates/               # Input file templates
│   ├── custom_json_template.json
│   ├── csv_template.csv
│   └── text_template.txt
├── examples/                # Example files for testing
│   ├── sample_config.json
│   ├── sample_custom_json.json
│   ├── sample_user_config.json
│   ├── sample_backup_summary.json
│   ├── sample_rules.csv
│   ├── sample_confluence_config.env
│   └── setup_instructions.md
├── input/                   # Input files (gitignored)
├── output/                  # Generated SOPs (gitignored)
└── venv/                    # Virtual environment (gitignored)
```

---

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

### Security Validation
```bash
# Run security check before committing
python scripts/security_check.py
```

**Expected output:**
```
SECURITY VALIDATION PASSED
No security issues found. Safe to commit to version control.
```

---

## Getting Help

### Documentation
- **`README.md`** - This comprehensive guide (everything you need!)
- **`config/env.template`** - Environment variables template
- **`scripts/security_check.py`** - Security validation script
- **`docs/SECURITY_SETUP.md`** - Detailed security guide

### Help Commands
```bash
# General help
python main.py --help

# Command-specific help
python main.py generate --help
python main.py upload-to-confluence --help
python main.py test-confluence --help
```

### Debug Information
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python main.py test-confluence
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided "AS IS" without any warranties. Use at your own risk. Always review and validate generated content before implementation in any production environment. The author is not liable for any damages or consequences from the use of this software.

---

## Quick Reference

### Daily Usage
```bash
# Activate environment
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Generate SOPs
python main.py generate --input input/your_rules.json --output output/

# Upload to Confluence
python main.py upload-to-confluence --input input/your_rules.json --confluence-parent "PARENT_ID" --update-existing

# Deactivate environment
deactivate
```

### Troubleshooting
```bash
# Test connection
python main.py test-confluence

# Validate input
python main.py validate-rules --input input/your_rules.json --detailed

# Security audit
python main.py security-audit --check-data
```

**You're ready to generate professional SOPs for your SOC team!**
