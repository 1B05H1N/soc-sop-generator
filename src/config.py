"""
Configuration Module

This module handles user-configurable settings including author and contact information.
Users can customize these settings via environment variables or config files.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration management for the SOC SOP Generator"""
    
    def __init__(self):
        self.config_file = Path(".soc_sop_config.json")
        self.default_config = {
            "author": "[Configure in settings]",
            "contact_email": "[Configure in settings]",
            "github_url": "[Configure in settings]",
            "organization": "Security Operations Center",
            "version": "1.0.0",
            "last_updated": "2025-07-20"
        }
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or environment variables"""
        config = self.default_config.copy()
        
        # Load from environment variables first (highest priority)
        env_config = {
            "author": os.getenv("SOP_AUTHOR"),
            "contact_email": os.getenv("SOP_CONTACT_EMAIL"),
            "github_url": os.getenv("SOP_GITHUB_URL"),
            "organization": os.getenv("SOP_ORGANIZATION")
        }
        
        # Update config with environment variables (only if they exist)
        for key, value in env_config.items():
            if value:
                config[key] = value
        
        # Load from config file (if exists)
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load config file: {e}")
        
        return config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self._config.get(key, default)
    
    def get_author(self) -> str:
        """Get the configured author name"""
        return self.get("author", "[Configure in settings]")
    
    def get_contact_email(self) -> str:
        """Get the configured contact email"""
        return self.get("contact_email", "[Configure in settings]")
    
    def get_github_url(self) -> str:
        """Get the configured GitHub URL"""
        return self.get("github_url", "[Configure in settings]")
    
    def get_organization(self) -> str:
        """Get the configured organization name"""
        return self.get("organization", "Security Operations Center")
    
    def get_version(self) -> str:
        """Get the current version"""
        return self.get("version", "1.0.0")
    
    def get_last_updated(self) -> str:
        """Get the last updated date"""
        return self.get("last_updated", "2025-07-20")
    
    def create_config_template(self, output_file: str = ".soc_sop_config.json") -> str:
        """Create a template configuration file"""
        template = {
            "author": "[Configure in settings]",
            "contact_email": "[Configure in settings]",
            "github_url": "[Configure in settings]",
            "organization": "Security Operations Center",
            "version": "1.0.0",
            "last_updated": "2025-07-20",
            "_comment": "This file allows you to customize the Author and contact information used in generated SOPs"
        }
        
        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)
        
        return output_file
    
    def update_config(self, key: str, value: Any) -> bool:
        """Update a configuration value"""
        try:
            self._config[key] = value
            
            # Save to config file
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error updating config: {e}")
            return False
    
    def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration values"""
        return self._config.copy()
    
    def print_config(self):
        """Print current configuration"""
        print("Current Configuration:")
        print("=" * 50)
        for key, value in self._config.items():
            if not key.startswith('_'):
                print(f"{key}: {value}")
        print("=" * 50)
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate the current configuration"""
        errors = []
        warnings = []
        
        # Check required fields
        if not self.get_author() or self.get_author() == "Your Name":
            warnings.append("Author not configured - using default")
        
        if not self.get_contact_email() or self.get_contact_email() == "[Configure in settings]":
            warnings.append("Contact email not configured - using default")
        
        # Validate email format
        email = self.get_contact_email()
        if email and '@' not in email:
            errors.append("Invalid email format")
        
        # Validate GitHub URL
        github_url = self.get_github_url()
        if github_url and not github_url.startswith('http'):
            errors.append("GitHub URL should start with http:// or https://")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }


# Global configuration instance
config = Config() 