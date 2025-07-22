"""
Confluence Formatter Module

This module handles formatting SOPs for Confluence integration.
"""

import re
from typing import Dict, Any, List
from datetime import datetime


class ConfluenceFormatter:
    """Formats SOP content for Confluence"""
    
    def __init__(self):
        self.confluence_macros = {
            'info': 'ac:structured-macro ac:name="info"',
            'warning': 'ac:structured-macro ac:name="warning"',
            'note': 'ac:structured-macro ac:name="note"',
            'tip': 'ac:structured-macro ac:name="tip"',
            'code': 'ac:structured-macro ac:name="code"',
            'panel': 'ac:structured-macro ac:name="panel"'
        }
    
    def format_markdown_to_confluence(self, markdown_content: str) -> str:
        """Convert markdown content to Confluence format"""
        confluence_content = markdown_content
        
        # Convert headers
        confluence_content = self._convert_headers(confluence_content)
        
        # Convert bold text
        confluence_content = self._convert_bold(confluence_content)
        
        # Convert italic text
        confluence_content = self._convert_italic(confluence_content)
        
        # Convert code blocks
        confluence_content = self._convert_code_blocks(confluence_content)
        
        # Convert inline code
        confluence_content = self._convert_inline_code(confluence_content)
        
        # Convert lists
        confluence_content = self._convert_lists(confluence_content)
        
        # Convert links
        confluence_content = self._convert_links(confluence_content)
        
        # Convert tables
        confluence_content = self._convert_tables(confluence_content)
        
        # Add Confluence-specific formatting
        confluence_content = self._add_confluence_formatting(confluence_content)
        
        return confluence_content
    
    def _convert_headers(self, content: str) -> str:
        """Convert markdown headers to Confluence format"""
        # Convert H1 (# Header)
        content = re.sub(r'^# (.+)$', r'<h1>\1</h1>', content, flags=re.MULTILINE)
        
        # Convert H2 (## Header)
        content = re.sub(r'^## (.+)$', r'<h2>\1</h2>', content, flags=re.MULTILINE)
        
        # Convert H3 (### Header)
        content = re.sub(r'^### (.+)$', r'<h3>\1</h3>', content, flags=re.MULTILINE)
        
        # Convert H4 (#### Header)
        content = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', content, flags=re.MULTILINE)
        
        return content
    
    def _convert_bold(self, content: str) -> str:
        """Convert bold text to Confluence format"""
        return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', content)
    
    def _convert_italic(self, content: str) -> str:
        """Convert italic text to Confluence format"""
        return re.sub(r'\*(.+?)\*', r'<em>\1</em>', content)
    
    def _convert_code_blocks(self, content: str) -> str:
        """Convert code blocks to Confluence format"""
        def replace_code_block(match):
            code = match.group(1)
            return f'<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">text</ac:parameter><ac:plain-text-body><![CDATA[{code}]]></ac:plain-text-body></ac:structured-macro>'
        
        return re.sub(r'```\n?(.*?)\n?```', replace_code_block, content, flags=re.DOTALL)
    
    def _convert_inline_code(self, content: str) -> str:
        """Convert inline code to Confluence format"""
        return re.sub(r'`(.+?)`', r'<code>\1</code>', content)
    
    def _convert_lists(self, content: str) -> str:
        """Convert lists to Confluence format"""
        lines = content.split('\n')
        formatted_lines = []
        in_list = False
        
        for line in lines:
            # Check for unordered list items
            if re.match(r'^\s*[-*+]\s+', line):
                if not in_list:
                    formatted_lines.append('<ul>')
                    in_list = True
                item_text = re.sub(r'^\s*[-*+]\s+', '', line)
                formatted_lines.append(f'<li>{item_text}</li>')
            # Check for ordered list items
            elif re.match(r'^\s*\d+\.\s+', line):
                if not in_list:
                    formatted_lines.append('<ol>')
                    in_list = True
                item_text = re.sub(r'^\s*\d+\.\s+', '', line)
                formatted_lines.append(f'<li>{item_text}</li>')
            else:
                if in_list:
                    formatted_lines.append('</ul>' if in_list else '</ol>')
                    in_list = False
                formatted_lines.append(line)
        
        if in_list:
            formatted_lines.append('</ul>' if in_list else '</ol>')
        
        return '\n'.join(formatted_lines)
    
    def _convert_links(self, content: str) -> str:
        """Convert links to Confluence format"""
        return re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', content)
    
    def _convert_tables(self, content: str) -> str:
        """Convert tables to Confluence format"""
        # Convert markdown tables to Confluence table format
        lines = content.split('\n')
        formatted_lines = []
        in_table = False
        table_content = []
        
        for line in lines:
            if line.strip().startswith('|') and '|' in line[1:]:
                if not in_table:
                    in_table = True
                    table_content = []
                table_content.append(line)
            else:
                if in_table:
                    # Process the table
                    formatted_lines.append(self._format_table_content(table_content))
                    in_table = False
                formatted_lines.append(line)
        
        if in_table:
            formatted_lines.append(self._format_table_content(table_content))
        
        return '\n'.join(formatted_lines)
    
    def _format_table_content(self, table_lines: List[str]) -> str:
        """Format table content for Confluence"""
        if not table_lines:
            return ""
        
        # Parse table headers and rows
        headers = []
        rows = []
        
        for i, line in enumerate(table_lines):
            cells = [cell.strip() for cell in line.split('|')[1:-1]]  # Remove empty cells at start/end
            if i == 0:
                headers = cells
            elif i == 1 and all(cell.replace('-', '').replace('|', '').strip() == '' for cell in cells):
                # Skip separator line
                continue
            else:
                rows.append(cells)
        
        # Create Confluence table
        table_html = '<table><tbody>'
        
        # Add header row
        if headers:
            table_html += '<tr>'
            for header in headers:
                table_html += f'<th><strong>{header}</strong></th>'
            table_html += '</tr>'
        
        # Add data rows
        for row in rows:
            table_html += '<tr>'
            for cell in row:
                table_html += f'<td>{cell}</td>'
            table_html += '</tr>'
        
        table_html += '</tbody></table>'
        return table_html
    
    def _add_confluence_formatting(self, content: str) -> str:
        """Add Confluence-specific formatting"""
        # Add info macro for document control section
        content = re.sub(
            r'(<h2>Document Control</h2>.*?<h2>Executive Summary</h2>)',
            r'<ac:structured-macro ac:name="info"><ac:rich-text-body>\1</ac:rich-text-body></ac:structured-macro>',
            content,
            flags=re.DOTALL
        )
        
        # Add warning macro for escalation matrix
        content = re.sub(
            r'(<h2>Escalation Matrix</h2>.*?<h2>Containment Procedures</h2>)',
            r'<ac:structured-macro ac:name="warning"><ac:rich-text-body>\1</ac:rich-text-body></ac:structured-macro>',
            content,
            flags=re.DOTALL
        )
        
        # Add tip macro for best practices and lessons learned
        content = re.sub(
            r'(<h2>Lessons Learned</h2>.*?<h2>References and Resources</h2>)',
            r'<ac:structured-macro ac:name="tip"><ac:rich-text-body>\1</ac:rich-text-body></ac:structured-macro>',
            content,
            flags=re.DOTALL
        )
        
        # Add note macro for key performance indicators
        content = re.sub(
            r'(<h2>Key Performance Indicators</h2>.*?<h2>Lessons Learned</h2>)',
            r'<ac:structured-macro ac:name="note"><ac:rich-text-body>\1</ac:rich-text-body></ac:structured-macro>',
            content,
            flags=re.DOTALL
        )
        
        # Add professional styling to checkboxes
        content = re.sub(
            r'- \[ \]',
            r'<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">Grey</ac:parameter><ac:parameter ac:name="title">To Do</ac:parameter></ac:structured-macro>',
            content
        )
        
        content = re.sub(
            r'- \[x\]',
            r'<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">Green</ac:parameter><ac:parameter ac:name="title">Done</ac:parameter></ac:structured-macro>',
            content
        )
        
        return content
    
    def create_confluence_page_structure(self, sop_content: str, rule_name: str) -> Dict[str, Any]:
        """Create Confluence page structure"""
        return {
            "type": "page",
            "title": f"{rule_name} Operating Procedure",
            "space": {
                "key": "SOC"
            },
            "body": {
                "storage": {
                    "value": sop_content,
                    "representation": "storage"
                }
            },
            "metadata": {
                "properties": {
                    "sop-version": {
                        "value": "1.0"
                    },
                    "rule-id": {
                        "value": "placeholder"
                    },
                    "category": {
                        "value": "Security Operations"
                    },
                    "priority": {
                        "value": "Medium"
                    }
                }
            }
        }
    
    def format_sop_for_confluence(self, sop_data: Dict[str, Any]) -> str:
        """Format SOP data for Confluence"""
        # Convert the SOP content to Confluence format
        confluence_content = self.format_markdown_to_confluence(sop_data['content'])
        
        # Add Confluence-specific metadata
        confluence_content = f"""
<ac:structured-macro ac:name="info">
<ac:rich-text-body>
<p><strong>Generated on:</strong> {sop_data.get('generated_date', 'Unknown')}</p>
<p><strong>SOP Version:</strong> {sop_data.get('version', '1.0')}</p>
<p><strong>Rule ID:</strong> {sop_data.get('rule_id', 'Unknown')}</p>
</ac:rich-text-body>
</ac:structured-macro>

{confluence_content}
"""
        
        return confluence_content
    
    def create_confluence_metadata(self, rule_info: Dict[str, Any]) -> Dict[str, Any]:
        """Create Confluence metadata for the SOP"""
        return {
            "page_title": f"{rule_info['rule_name']} Operating Procedure",
            "space_key": "SOC",
            "parent_page_id": "12345",  # Replace with actual parent page ID
            "labels": [
                "sop",
                "security-operations",
                "alert-triage",
                rule_info.get('category', 'general').lower()
            ],
            "properties": {
                "rule-id": rule_info.get('rule_id', ''),
                "rule-status": rule_info.get('status', ''),
                "rule-priority": rule_info.get('priority', ''),
                "rule-category": rule_info.get('category', ''),
                "sop-version": "1.0",
                "last-updated": datetime.now().isoformat()
            }
        }
    
    def format_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Format a table for Confluence"""
        if not headers or not rows:
            return ""
        
        # Create table header
        table_html = "<table><tbody><tr>"
        for header in headers:
            table_html += f"<th>{header}</th>"
        table_html += "</tr>"
        
        # Create table rows
        for row in rows:
            table_html += "<tr>"
            for cell in row:
                table_html += f"<td>{cell}</td>"
            table_html += "</tr>"
        
        table_html += "</tbody></table>"
        return table_html 