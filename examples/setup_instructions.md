# Configuration Setup Instructions

This directory contains sample configuration files that you can use to customize the SOC SOP Generator for your environment.

## Available Configuration Files

### 1. `sample_config.json`
Basic configuration file with essential settings.

**Usage:**
```bash
# Copy to your project root
cp examples/sample_config.json .soc_sop_config.json

# Edit with your information
nano .soc_sop_config.json
```

### 2. `sample_confluence_config.env`
Environment variables for Confluence integration.

**Usage:**
```bash
# Copy to your project root
cp examples/sample_confluence_config.env .env.confluence

# Edit with your Confluence details
nano .env.confluence

# Source the environment variables
source .env.confluence
```

### 3. `sample_user_config.json`
Comprehensive configuration with all available options.

**Usage:**
```bash
# Copy to your project root
cp examples/sample_user_config.json .soc_sop_config.json

# Customize for your environment
nano .soc_sop_config.json
```

## Configuration Categories

### User Preferences
- `default_output_format`: markdown, html, json, pdf
- `default_output_directory`: Where to save generated SOPs
- `enable_progress_tracking`: Show progress during generation
- `enable_analytics`: Generate performance reports
- `auto_validate_rules`: Validate rules before processing

### Template Settings
- `company_name`: Your organization name
- `contact_email`: Primary contact email
- `emergency_contact`: Emergency contact email
- `document_classification`: Document classification level
- `include_mitre_mapping`: Include MITRE ATT&CK mappings

### Advanced Settings
- `confidence_threshold`: MITRE mapping confidence (0.0-1.0)
- `max_rules_per_sop`: Maximum rules per multi-rule SOP
- `enable_fallback_generation`: Use fallback for failed rules
- `enable_error_recovery`: Recover from generation errors

### Confluence Settings
- `default_space`: Your Confluence space key
- `default_folder`: Default folder for SOPs
- `create_drafts_by_default`: Create drafts for review
- `update_existing_pages`: Update existing pages

### Security Settings
- `enable_sensitive_data_detection`: Scan for sensitive data
- `enable_credential_scanning`: Check for hardcoded credentials
- `block_private_ips`: Prevent private IP addresses
- `block_internal_domains`: Prevent internal domain names

## Environment Variables

You can also set configuration via environment variables:

```bash
# Basic settings
export SOP_AUTHOR="Your Name"
export SOP_CONTACT_EMAIL="your-email@your-domain.com"
export SOP_GITHUB_URL="https://github.com/your-username"

# Confluence settings
export CONFLUENCE_URL="https://your-domain.atlassian.net"
export CONFLUENCE_USERNAME="your-email@your-domain.com"
export CONFLUENCE_API_TOKEN="your-api-token"
export CONFLUENCE_SPACE_KEY="YOUR_SPACE_KEY"
```

## Testing Your Configuration

After setting up your configuration:

```bash
# Test basic configuration
python main.py config

# Test with example files
python main.py generate -i examples/sample_backup_summary.json --dry-run

# Test Confluence connection (if configured)
python main.py upload-to-confluence -i examples/sample_backup_summary.json --dry-run
```

## Security Notes

- All sample files use generic placeholders
- No sensitive information included
- Safe for public distribution
- Customize with your actual information

## File Locations

- **User Config**: `.soc_sop_config.json` (in project root)
- **Confluence Config**: `.env.confluence` (in project root)
- **Example Files**: `examples/` directory
- **Generated Output**: `output/` directory (gitignored)

Remember to never commit your actual configuration files with sensitive information! 