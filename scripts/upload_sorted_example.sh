#!/bin/bash

# Example script for uploading SOPs to Confluence in alphabetical order
# This ensures your SOPs appear in alphabetical order in Confluence

echo "Uploading SOPs to Confluence in alphabetical order..."

# Method 1: Using the main CLI with sorting enabled (default)
python main.py upload-to-confluence \
    --input input/backup.json \
    --input-format backup_summary \
    --confluence-url "https://your-domain.atlassian.net" \
    --confluence-username "your-email@domain.com" \
    --confluence-token "your-api-token" \
    --confluence-space "YOUR_SPACE_KEY" \
    --confluence-parent "PARENT_PAGE_ID" \
    --update-existing \
    --sort-alphabetically

# Method 2: Using the dedicated sorted upload script
# python scripts/upload_sorted_sops.py \
#     --input input/backup.json \
#     --confluence-url "https://your-domain.atlassian.net" \
#     --confluence-username "your-email@domain.com" \
#     --confluence-token "your-api-token" \
#     --confluence-space "YOUR_SPACE_KEY" \
#     --confluence-parent "PARENT_PAGE_ID" \
#     --update-existing

echo "Upload completed!" 