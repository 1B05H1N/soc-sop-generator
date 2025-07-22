"""
Confluence API Integration Module

This module handles direct uploads to Confluence with proper formatting,
metadata, and page management. Supports draft creation and local file saving.
"""

import requests
import json
import base64
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ConfluenceAPI:
    """Handles Confluence API operations for SOP uploads with draft support"""
    
    def __init__(self, base_url: str, username: str, api_token: str, space_key: str):
        """
        Initialize Confluence API client
        
        Args:
            base_url: Confluence instance URL (e.g., https://your-domain.atlassian.net)
            username: Confluence username or email
            api_token: Confluence API token
            space_key: Space key where pages will be created
        """
        # Handle base URL - ensure it ends with /wiki for Confluence Cloud API
        if not base_url.endswith('/wiki'):
            self.base_url = base_url.rstrip('/') + '/wiki'
        else:
            self.base_url = base_url.rstrip('/')
        
        self.username = username
        self.api_token = api_token
        self.space_key = space_key
        self.session = requests.Session()
        self.session.auth = (username, api_token)
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'SOC-SOP-Generator/1.0'
        })
    
    def test_connection(self) -> bool:
        """Test the connection to Confluence"""
        try:
            # Test with the correct API endpoint
            response = self.session.get(f"{self.base_url}/rest/api/space/{self.space_key}")
            if response.status_code == 200:
                logger.info(f"Successfully connected to Confluence space: {self.space_key}")
                return True
            else:
                logger.error(f"Failed to connect to Confluence: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to Confluence: {e}")
            return False
    
    def get_or_create_folder(self, folder_name: str, folder_description: str = None) -> Optional[str]:
        """Get or create a folder page in Confluence"""
        try:
            # First, try to find existing folder
            response = self.session.get(
                f"{self.base_url}/rest/api/content",
                params={
                    'title': folder_name,
                    'spaceKey': self.space_key,
                    'type': 'page'
                }
            )
            
            if response.status_code == 200:
                results = response.json().get('results', [])
                if results:
                    return results[0]['id']
            
            # Create folder if it doesn't exist
            if folder_description is None:
                folder_description = f"<p>This folder contains {folder_name}.</p>"
            
            folder_content = f"""
<h1>{folder_name}</h1>
{folder_description}
"""
            
            folder_id = self.create_page(folder_name, folder_content)
            return folder_id
            
        except Exception as e:
            logger.error(f"Failed to get/create folder '{folder_name}': {e}")
            return None
    
    def get_draft_folder_id(self) -> Optional[str]:
        """Get or create a draft folder for SOP review"""
        return self.get_or_create_folder(
            "SOP Drafts", 
            "<p>This folder contains draft Standard Operating Procedures for review before publication.</p><p><strong>Note:</strong> These are draft versions and should not be used for production until approved.</p>"
        )
    
    def create_draft_page(self, title: str, content: str) -> Optional[str]:
        """Create a draft page in the draft folder"""
        try:
            draft_folder_id = self.get_draft_folder_id()
            if not draft_folder_id:
                logger.error("Failed to get draft folder ID")
                return None
            
            # Add draft indicator to title
            draft_title = f"[DRAFT] {title}"
            
            page_data = {
                'type': 'page',
                'title': draft_title,
                'space': {'key': self.space_key},
                'body': {
                    'storage': {
                        'value': content,
                        'representation': 'storage'
                    }
                },
                'ancestors': [{'id': draft_folder_id}]
            }
            
            response = self.session.post(
                f"{self.base_url}/rest/api/content",
                json=page_data
            )
            
            if response.status_code == 200:
                page_id = response.json()['id']
                logger.info(f"Created draft page: {draft_title} (ID: {page_id})")
                return page_id
            else:
                logger.error(f"Failed to create draft page: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create draft page: {e}")
            return None
    
    def publish_draft(self, draft_page_id: str, target_title: str, target_parent_id: Optional[str] = None) -> Optional[str]:
        """Publish a draft page to the main space"""
        try:
            # Get draft page content
            response = self.session.get(
                f"{self.base_url}/rest/api/content/{draft_page_id}",
                params={'expand': 'body.storage'}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get draft page content: {response.status_code}")
                return None
            
            draft_data = response.json()
            content = draft_data['body']['storage']['value']
            
            # Remove draft indicator from title
            clean_title = target_title.replace('[DRAFT] ', '')
            
            # Create the published page
            page_data = {
                'type': 'page',
                'title': clean_title,
                'space': {'key': self.space_key},
                'body': {
                    'storage': {
                        'value': content,
                        'representation': 'storage'
                    }
                }
            }
            
            if target_parent_id:
                page_data['ancestors'] = [{'id': target_parent_id}]
            
            response = self.session.post(
                f"{self.base_url}/rest/api/content",
                json=page_data
            )
            
            if response.status_code == 200:
                published_page_id = response.json()['id']
                logger.info(f"Published draft to: {clean_title} (ID: {published_page_id})")
                
                # Optionally delete the draft
                self.delete_page(draft_page_id)
                
                return published_page_id
            else:
                logger.error(f"Failed to publish draft: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to publish draft: {e}")
            return None
    
    def delete_page(self, page_id: str) -> bool:
        """Delete a page from Confluence"""
        try:
            response = self.session.delete(f"{self.base_url}/rest/api/content/{page_id}")
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to delete page {page_id}: {e}")
            return False
    
    def save_sop_locally(self, sop_data: Dict[str, Any], output_dir: str = "output/local_sops") -> str:
        """Save SOP content locally as Markdown file"""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            rule_name = sop_data['rule_name']
            safe_filename = "".join(c for c in rule_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
            filename = f"{safe_filename}_SOP.md"
            filepath = output_path / filename
            
            # Convert Confluence content to Markdown
            markdown_content = self._convert_confluence_to_markdown(sop_data)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            logger.info(f"Saved SOP locally: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Failed to save SOP locally: {e}")
            return ""
    
    def _convert_confluence_to_markdown(self, sop_data: Dict[str, Any]) -> str:
        """Convert SOP data to Markdown format"""
        template_data = sop_data.get('template_data', {})
        
        # Use the proper template with Author and Contact information
        from src.templates import SOPTemplates
        from src.unified_config import config
        
        # Get the appropriate template based on category
        category = sop_data.get('category', 'general')
        template = SOPTemplates.get_template_by_category(category)
        
        # Prepare template data with Author and Contact information
        template_data.update({
            'author': config.get_author(),
            'contact_email': config.get_contact_email()
        })
        
        # Format the template
        markdown_content = template.format(**template_data)
        
        return markdown_content

    def get_page_id(self, page_title: str) -> Optional[str]:
        """Get page ID by title"""
        try:
            response = self.session.get(
                f"{self.base_url}/rest/api/content",
                params={
                    'title': page_title,
                    'spaceKey': self.space_key,
                    'expand': 'version'
                }
            )
            
            if response.status_code == 200:
                results = response.json().get('results', [])
                if results:
                    return results[0]['id']
            return None
        except Exception as e:
            logger.error(f"Failed to get page ID for '{page_title}': {e}")
            return None
    
    def create_page(self, title: str, content: str, parent_id: Optional[str] = None) -> Optional[str]:
        """Create a new page in Confluence"""
        try:
            page_data = {
                'type': 'page',
                'title': title,
                'space': {'key': self.space_key},
                'body': {
                    'storage': {
                        'value': content,
                        'representation': 'storage'
                    }
                }
            }
            
            if parent_id:
                page_data['ancestors'] = [{'id': parent_id}]
            
            logger.info(f"Creating page '{title}' in space '{self.space_key}'")
            logger.info(f"API URL: {self.base_url}/rest/api/content")
            logger.debug(f"Page data: {json.dumps(page_data, indent=2)}")
            
            response = self.session.post(
                f"{self.base_url}/rest/api/content",
                json=page_data
            )
            
            logger.info(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code == 200:
                page_id = response.json()['id']
                logger.info(f"Created page '{title}' with ID: {page_id}")
                return page_id
            else:
                logger.error(f"Failed to create page '{title}': {response.status_code}")
                logger.error(f"Response text: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create page '{title}': {e}")
            return None
    
    def update_page(self, page_id: str, title: str, content: str, version: int) -> bool:
        """Update an existing page in Confluence"""
        try:
            page_data = {
                'version': {'number': version + 1},
                'title': title,
                'type': 'page',
                'body': {
                    'storage': {
                        'value': content,
                        'representation': 'storage'
                    }
                }
            }
            
            response = self.session.put(
                f"{self.base_url}/rest/api/content/{page_id}",
                json=page_data
            )
            
            if response.status_code == 200:
                logger.info(f"Updated page '{title}' successfully")
                return True
            else:
                logger.error(f"Failed to update page '{title}': {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update page '{title}': {e}")
            return False
    
    def upload_sop(self, sop_data: Dict[str, Any], update_existing: bool = True, as_draft: bool = False, 
                   target_folder: str = None, parent_page_id: str = None) -> Optional[str]:
        """
        Upload an SOP to Confluence
        
        Args:
            sop_data: SOP data dictionary
            update_existing: Whether to update existing pages
            as_draft: Whether to create as draft
            target_folder: Name of folder to create/use as parent
            parent_page_id: Specific parent page ID to use
            
        Returns:
            Page ID if successful, None otherwise
        """
        rule_name = sop_data['rule_name']
        page_title = f"{rule_name} Operating Procedure"
        
        # Format content for Confluence
        confluence_content = self._format_sop_for_confluence(sop_data)
        
        # Determine parent folder
        parent_id = None
        if parent_page_id:
            parent_id = parent_page_id
        elif target_folder:
            parent_id = self.get_or_create_folder(target_folder)
            if not parent_id:
                logger.error(f"Failed to get/create target folder: {target_folder}")
                return None
        
        if as_draft:
            return self.create_draft_page(page_title, confluence_content)
        
        # Check if page exists
        existing_page_id = self.get_page_id(page_title)
        
        if existing_page_id and update_existing:
            # Get current version
            response = self.session.get(f"{self.base_url}/rest/api/content/{existing_page_id}")
            if response.status_code == 200:
                current_version = response.json()['version']['number']
                success = self.update_page(existing_page_id, page_title, confluence_content, current_version)
                return existing_page_id if success else None
        
        # Create new page
        return self.create_page(page_title, confluence_content, parent_id)
    
    def _format_sop_for_confluence(self, sop_data: Dict[str, Any]) -> str:
        """Format SOP content for Confluence storage format"""
        template_data = sop_data.get('template_data', {})
        
        # Build Confluence content
        content = f"""
<ac:structured-macro ac:name="info" ac:schema-version="1">
<ac:rich-text-body>
<p><strong>Generated SOP for {sop_data['rule_name']}</strong></p>
<p>This Standard Operating Procedure was automatically generated on {template_data.get('generated_date', 'Unknown')}</p>
</ac:rich-text-body>
</ac:structured-macro>

<h1>{sop_data['rule_name']} Operating Procedure</h1>

<h2>Rule Information</h2>
<table>
<tbody>
<tr><td><strong>Rule ID:</strong></td><td>{sop_data['rule_id']}</td></tr>
<tr><td><strong>Status:</strong></td><td>{template_data.get('status', 'Unknown')}</td></tr>
<tr><td><strong>Priority:</strong></td><td>{sop_data['priority']}</td></tr>
<tr><td><strong>Category:</strong></td><td>{sop_data['category']}</td></tr>
<tr><td><strong>Created:</strong></td><td>{template_data.get('created_on', 'Unknown')}</td></tr>
<tr><td><strong>Last Updated:</strong></td><td>{template_data.get('last_updated_on', 'Unknown')}</td></tr>
</tbody>
</table>

<h2>Description</h2>
<p>{template_data.get('description', 'No description available')}</p>

<h2>Technical Details</h2>
<table>
<tbody>
<tr><td><strong>Search Outcome:</strong></td><td>{template_data.get('search_outcome', 'Unknown')}</td></tr>
<tr><td><strong>Filter Complexity:</strong></td><td>{template_data.get('complexity', 'Unknown')}</td></tr>
<tr><td><strong>Data Sources:</strong></td><td>{template_data.get('data_sources', 'None specified')}</td></tr>
<tr><td><strong>Event Types:</strong></td><td>{template_data.get('event_types', 'None specified')}</td></tr>
</tbody>
</table>

<h3>Search Filter</h3>
<ac:structured-macro ac:name="code" ac:schema-version="1">
<ac:parameter ac:name="language">sql</ac:parameter>
<ac:plain-text-body><![CDATA[{template_data.get('search_filter', 'No filter specified')}]]></ac:plain-text-body>
</ac:structured-macro>

<h2>Triage Procedure</h2>

<h3>Initial Assessment (5 minutes)</h3>
<ol>
<li><strong>Verify Alert Context</strong>
<ul>
<li>Check the alert timestamp and frequency</li>
<li>Review the affected systems/users</li>
<li>Identify the scope of the incident</li>
</ul>
</li>
<li><strong>Check for False Positives</strong>
<ul>
<li>Verify if this is a known legitimate activity</li>
<li>Check if affected systems/users are authorized</li>
<li>Review recent changes or maintenance activities</li>
</ul>
</li>
<li><strong>Assess Impact</strong>
<ul>
<li>Determine the number of affected systems</li>
<li>Identify critical systems or data at risk</li>
<li>Evaluate potential business impact</li>
</ul>
</li>
</ol>

<h3>Investigation Steps (15-30 minutes)</h3>
<ol>
<li><strong>Gather Additional Context</strong>
<ul>
<li>Review system logs for related events</li>
<li>Check for similar patterns in recent history</li>
<li>Identify any related security events</li>
</ul>
</li>
<li><strong>Analyze Technical Details</strong>
<ul>
<li>Review the search filter logic</li>
<li>Check for any exclusions or exceptions</li>
<li>Verify the data sources and event types</li>
</ul>
</li>
<li><strong>Identify Root Cause</strong>
<ul>
<li>Determine what triggered the alert</li>
<li>Identify any underlying vulnerabilities</li>
<li>Check for any configuration issues</li>
</ul>
</li>
</ol>

<h3>Escalation Criteria</h3>

<p><strong>Immediate Escalation (within 5 minutes) if:</strong></p>
<ul>
<li>Multiple systems affected</li>
<li>Critical systems involved</li>
<li>Evidence of data exfiltration</li>
<li>Suspicious user activity patterns</li>
<li>Known attack patterns detected</li>
</ul>

<p><strong>Escalate to Senior Analyst if:</strong></p>
<ul>
<li>Complex investigation required</li>
<li>Multiple data sources involved</li>
<li>Need for additional tools or access</li>
<li>Potential false positive but uncertain</li>
</ul>

<h2>Response Actions</h2>

<h3>Immediate Actions (0-15 minutes)</h3>
<ol>
<li><strong>Containment</strong>
<ul>
<li>Isolate affected systems if necessary</li>
<li>Block suspicious network connections</li>
<li>Disable compromised accounts if confirmed</li>
</ul>
</li>
<li><strong>Documentation</strong>
<ul>
<li>Document all findings</li>
<li>Take screenshots of relevant evidence</li>
<li>Update incident tracking system</li>
</ul>
</li>
<li><strong>Communication</strong>
<ul>
<li>Notify relevant stakeholders</li>
<li>Update status in incident management system</li>
<li>Prepare initial incident report</li>
</ul>
</li>
</ol>

<h3>Containment Steps (15-60 minutes)</h3>
<ol>
<li><strong>System Isolation</strong>
<ul>
<li>Disconnect affected systems from network</li>
<li>Implement network segmentation</li>
<li>Restrict access to critical systems</li>
</ul>
</li>
<li><strong>Account Management</strong>
<ul>
<li>Disable suspicious user accounts</li>
<li>Reset passwords for affected accounts</li>
<li>Review and update access controls</li>
</ul>
</li>
<li><strong>Evidence Preservation</strong>
<ul>
<li>Collect and preserve all relevant logs</li>
<li>Create forensic images if necessary</li>
<li>Document all actions taken</li>
</ul>
</li>
</ol>

<h3>Recovery Procedures (1-4 hours)</h3>
<ol>
<li><strong>System Restoration</strong>
<ul>
<li>Restore systems from clean backups</li>
<li>Apply security patches and updates</li>
<li>Verify system integrity</li>
</ul>
</li>
<li><strong>Access Management</strong>
<ul>
<li>Re-enable legitimate user accounts</li>
<li>Implement additional monitoring</li>
<li>Review and update security policies</li>
</ul>
</li>
<li><strong>Validation</strong>
<ul>
<li>Test system functionality</li>
<li>Verify security controls</li>
<li>Monitor for recurrence</li>
</ul>
</li>
</ol>

<h2>False Positive Indicators</h2>
<p>{template_data.get('false_positive_indicators', 'None identified')}</p>

<h2>Key Indicators to Monitor</h2>
<p>{template_data.get('key_indicators', 'None identified')}</p>

<h2>Lessons Learned</h2>
<ul>
<li>Document any process improvements</li>
<li>Update procedures based on findings</li>
<li>Share lessons with the team</li>
<li>Update training materials if needed</li>
</ul>

<h2>References</h2>
<ul>
<li><a href="#">Security Platform Documentation</a></li>
<li><a href="#">Security Incident Response Guide</a></li>
<li><a href="#">Escalation Procedures</a></li>
</ul>

<hr/>
<p><em>Generated on: {template_data.get('generated_date', 'Unknown')}<br/>
SOP Version: {sop_data.get('version', '1.0')}<br/>
Last Reviewed: {template_data.get('generated_date', 'Unknown')}</em></p>
"""
        
        return content.strip()
    
    def batch_upload_sops(self, sops: List[Dict[str, Any]], update_existing: bool = True, as_draft: bool = False, 
                          save_locally: bool = False, target_folder: str = None) -> Dict[str, Any]:
        """
        Upload multiple SOPs to Confluence with optional draft creation and local saving
        
        Args:
            sops: List of SOP data dictionaries
            update_existing: Whether to update existing pages
            as_draft: Whether to create as drafts
            save_locally: Whether to save SOPs locally as well
            target_folder: Name of folder to create/use as parent for all SOPs
            
        Returns:
            Dictionary with upload results
        """
        results = {
            'total_sops': len(sops),
            'successful_uploads': 0,
            'failed_uploads': 0,
            'uploaded_pages': [],
            'local_files': [],
            'errors': []
        }
        
        for sop in sops:
            try:
                # Upload to Confluence
                page_id = self.upload_sop(sop, update_existing, as_draft, target_folder)
                if page_id:
                    results['successful_uploads'] += 1
                    results['uploaded_pages'].append({
                        'rule_name': sop['rule_name'],
                        'page_id': page_id,
                        'page_title': f"{sop['rule_name']} Operating Procedure",
                        'is_draft': as_draft
                    })
                else:
                    results['failed_uploads'] += 1
                    results['errors'].append(f"Failed to upload SOP for {sop['rule_name']}")
                
                # Save locally if requested
                if save_locally:
                    local_file = self.save_sop_locally(sop)
                    if local_file:
                        results['local_files'].append(local_file)
                
            except Exception as e:
                results['failed_uploads'] += 1
                results['errors'].append(f"Error uploading SOP for {sop['rule_name']}: {str(e)}")
        
        return results 