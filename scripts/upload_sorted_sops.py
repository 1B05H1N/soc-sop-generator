#!/usr/bin/env python3
"""
Sorted SOP Upload Script

This script uploads SOPs to Confluence in alphabetical order by rule name.
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from sop_generator import SOPGenerator
from confluence_api import ConfluenceAPI
from rich.console import Console

console = Console()

def upload_sops_sorted(input_file: str, 
                      confluence_url: str,
                      confluence_username: str,
                      confluence_token: str,
                      confluence_space: str,
                      confluence_parent: str = None,
                      confluence_folder: str = None,
                      update_existing: bool = True,
                      as_draft: bool = False,
                      save_locally: bool = False,
                      dry_run: bool = False):
    """
    Upload SOPs to Confluence in alphabetical order
    """
    
    console.print("Generating SOPs from input file...")
    
    # Initialize generator
    generator = SOPGenerator()
    
    # Generate SOPs
    sops = generator.generate_sops_from_input_file(
        input_file, 
        input_format='backup_summary',
        output_format='confluence'
    )
    
    if not sops:
        console.print("No SOPs generated from input file")
        return False
    
    # Sort SOPs alphabetically by rule name
    console.print("Sorting SOPs alphabetically...")
    sorted_sops = sorted(sops, key=lambda x: x.get('rule_name', '').lower())
    
    console.print(f"Generated {len(sorted_sops)} SOPs, sorted alphabetically")
    
    # Initialize Confluence API
    confluence_api = ConfluenceAPI(
        base_url=confluence_url,
        username=confluence_username,
        api_token=confluence_token,
        space_key=confluence_space
    )
    
    # Test connection
    if not confluence_api.test_connection():
        console.print("Failed to connect to Confluence")
        return False
    
    console.print("Connected to Confluence successfully")
    
    # Upload SOPs in alphabetical order
    console.print("Uploading SOPs to Confluence in alphabetical order...")
    
    successful_uploads = 0
    failed_uploads = 0
    
    for i, sop in enumerate(sorted_sops, 1):
        rule_name = sop.get('rule_name', 'Unknown')
        
        console.print(f"[{i}/{len(sorted_sops)}] Uploading: {rule_name}")
        
        if dry_run:
            console.print(f"   Would upload: {rule_name}")
            successful_uploads += 1
        else:
            try:
                page_id = confluence_api.upload_sop(
                    sop,
                    update_existing=update_existing,
                    as_draft=as_draft,
                    target_folder=confluence_folder,
                    parent_page_id=confluence_parent
                )
                
                if page_id:
                    console.print(f"    Successfully uploaded: {rule_name}")
                    successful_uploads += 1
                else:
                    console.print(f"    Failed to upload: {rule_name}")
                    failed_uploads += 1
                    
            except Exception as e:
                console.print(f"    Error uploading {rule_name}: {str(e)}")
                failed_uploads += 1
    
    # Summary
    console.print("\n" + "="*50)
    console.print("📊 Upload Summary:")
    console.print(f"   Total SOPs: {len(sorted_sops)}")
    console.print(f"   Successful: {successful_uploads}")
    console.print(f"   Failed: {failed_uploads}")
    console.print(f"   Success Rate: {(successful_uploads/len(sorted_sops)*100):.1f}%")
    
    if successful_uploads > 0:
        console.print(" Upload completed successfully!")
        return True
    else:
        console.print(" No SOPs were uploaded successfully")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Upload SOPs to Confluence in alphabetical order")
    parser.add_argument("--input", "-i", required=True, help="Input file path")
    parser.add_argument("--confluence-url", required=True, help="Confluence URL")
    parser.add_argument("--confluence-username", required=True, help="Confluence username")
    parser.add_argument("--confluence-token", required=True, help="Confluence API token")
    parser.add_argument("--confluence-space", required=True, help="Confluence space key")
    parser.add_argument("--confluence-parent", help="Confluence parent page ID")
    parser.add_argument("--confluence-folder", help="Confluence folder name")
    parser.add_argument("--update-existing", action="store_true", help="Update existing pages")
    parser.add_argument("--as-draft", action="store_true", help="Create as drafts")
    parser.add_argument("--save-locally", action="store_true", help="Save locally as well")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")
    
    args = parser.parse_args()
    
    success = upload_sops_sorted(
        input_file=args.input,
        confluence_url=args.confluence_url,
        confluence_username=args.confluence_username,
        confluence_token=args.confluence_token,
        confluence_space=args.confluence_space,
        confluence_parent=args.confluence_parent,
        confluence_folder=args.confluence_folder,
        update_existing=args.update_existing,
        as_draft=args.as_draft,
        save_locally=args.save_locally,
        dry_run=args.dry_run
    )
    
    sys.exit(0 if success else 1) 