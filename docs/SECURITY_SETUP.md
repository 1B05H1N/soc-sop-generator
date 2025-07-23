# Security Setup Guide

This guide ensures your company information, URLs, and secrets are never exposed to version control.

## CRITICAL SECURITY REQUIREMENTS

### 1. Environment Configuration

**NEVER commit real credentials or company information to version control.**

1. **Copy the template file:**
   ```bash
   cp env.template .env.confluence
   ```

2. **Edit `.env.confluence` with your actual values:**
   ```bash
   # Confluence Configuration
   CONFLUENCE_URL=https://your-company.atlassian.net
   CONFLUENCE_USERNAME=your-email@your-company.com
   CONFLUENCE_API_TOKEN=your-api-token-here
   CONFLUENCE_SPACE_KEY=YOUR_SPACE_KEY
   CONFLUENCE_FOLDER_ID=your-folder-id-here
   
   # SOP Author Information
   SOP_AUTHOR=Your Name
   SOP_CONTACT_EMAIL=your-email@your-company.com
   SOP_ORGANIZATION=Your Organization
   ```

3. **Verify `.env.confluence` is in `.gitignore`:**
   ```bash
   grep .env.confluence .gitignore
   ```

### 2. Security Validation

**Always run the security check before committing:**

```bash
python security_check.py
```

**Expected output:**
```
SECURITY VALIDATION PASSED
No security issues found. Safe to commit to version control.
```

### 3. Git Safety Checks

**Before committing, verify no sensitive files are staged:**

```bash
git status
```

**Ensure these files are NEVER committed:**
- `.env.confluence`
- `confluence_config.env`
- Any files in `input/` directory
- Any files in `output/` directory
- Any files with real company data

### 4. Configuration Best Practices

#### Environment Variables
- Use environment variables for all configuration
- Never hardcode URLs or credentials
- Use placeholder values in templates

#### File Organization
- Put real data files in `input/` directory (automatically ignored)
- Put generated files in `output/` directory (automatically ignored)
- Use example files in `examples/` directory for testing

#### Code Safety
- Use `os.getenv()` for all configuration values
- Use placeholder values like `'YOUR_FOLDER_ID'` as defaults
- Never commit real company URLs or information

### 5. Testing Without Real Data

**Use example files for testing:**

```bash
# Test with example data
python main.py generate -i examples/sample_backup_summary.json

# Test upload with dry-run
python main.py upload-to-confluence -i examples/sample_backup_summary.json --dry-run
```

### 6. Pre-commit Checklist

Before committing to version control:

- [ ] Run `python security_check.py` - should pass
- [ ] Check `git status` - no sensitive files staged
- [ ] Verify `.env.confluence` is not tracked
- [ ] Ensure no real company URLs in code
- [ ] Test with example data only

### 7. Troubleshooting

#### Security Check Fails
If `security_check.py` finds issues:

1. **Hardcoded URLs:** Replace with environment variables
2. **Real credentials:** Move to `.env.confluence` file
3. **Company information:** Use placeholder values

#### Environment File Issues
If `.env.confluence` is being tracked:

```bash
# Remove from git tracking
git rm --cached .env.confluence

# Add to .gitignore if not already there
echo ".env.confluence" >> .gitignore
```

### 8. Emergency Response

If sensitive data was accidentally committed:

1. **Immediately:** Remove the commit
   ```bash
   git reset --hard HEAD~1
   ```

2. **Rotate credentials:** Change all API tokens and passwords

3. **Audit:** Check what was exposed and take appropriate action

4. **Prevent recurrence:** Review and improve security practices

## Security Features

### Automatic Protection
- **Comprehensive .gitignore:** Prevents accidental commits of sensitive data
- **Security validation:** Automated checks before commits
- **Environment isolation:** All configuration externalized
- **Template safety:** Placeholder values prevent real data exposure

### Manual Safeguards
- **Pre-commit hooks:** Run security checks automatically
- **Code review:** Always review changes before merging
- **Testing isolation:** Use example data for all testing
- **Documentation:** Clear setup and security guides

## Support

If you encounter security issues:

1. **Don't panic:** Follow the emergency response steps
2. **Document:** Record what happened and when
3. **Improve:** Update processes to prevent recurrence
4. **Train:** Ensure team understands security requirements

---

**Remember: Security is everyone's responsibility. When in doubt, ask before committing.** 