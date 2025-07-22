"""
Expanded MITRE ATT&CK Technique Library

This module provides a comprehensive library of MITRE ATT&CK techniques
with detailed mappings for security correlation rules.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class AttackTactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackTechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: AttackTactic
    description: str
    examples: List[str]
    detection_methods: List[str]
    mitigation: List[str]
    sub_techniques: List[str] = None


class ExpandedMitreAttackMapper:
    """Expanded MITRE ATT&CK technique mapper with comprehensive library"""
    
    def __init__(self):
        self.techniques = self._initialize_technique_library()
        self.rule_patterns = self._initialize_rule_patterns()
        self.advanced_patterns = self._initialize_advanced_patterns()
    
    def _initialize_technique_library(self) -> Dict[str, AttackTechnique]:
        """Initialize comprehensive technique library"""
        return {
            # Initial Access Techniques
    'T1078.001': AttackTechnique(
                'T1078.001', 'Default Accounts', AttackTactic.INITIAL_ACCESS,
                'Use of default accounts for initial access',
                ['Default admin accounts', 'Service accounts with default passwords'],
                ['Monitor default account usage', 'Alert on default account login'],
                ['Change default passwords', 'Disable default accounts'],
                ['T1078.001', 'T1078.002', 'T1078.003']
    ),
    'T1078.002': AttackTechnique(
                'T1078.002', 'Domain Accounts', AttackTactic.INITIAL_ACCESS,
                'Use of domain accounts for initial access',
                ['Domain user accounts', 'Service accounts in domain'],
                ['Monitor domain account creation', 'Alert on suspicious domain logins'],
                ['Implement strong password policies', 'Regular account reviews'],
                ['T1078.001', 'T1078.002', 'T1078.003']
    ),
    'T1078.003': AttackTechnique(
                'T1078.003', 'Local Accounts', AttackTactic.INITIAL_ACCESS,
                'Use of local accounts for initial access',
                ['Local admin accounts', 'Local user accounts'],
                ['Monitor local account creation', 'Alert on local admin usage'],
                ['Limit local admin accounts', 'Regular local account audits'],
                ['T1078.001', 'T1078.002', 'T1078.003']
            ),
            'T1133': AttackTechnique(
                'T1133', 'External Remote Services', AttackTactic.INITIAL_ACCESS,
                'Use of external remote services for initial access',
                ['VPN connections', 'RDP connections', 'SSH connections'],
                ['Monitor external connections', 'Alert on suspicious remote access'],
                ['Implement MFA', 'Restrict external access'],
                ['T1133.001', 'T1133.002', 'T1133.003']
            ),
            'T1190': AttackTechnique(
                'T1190', 'Exploit Public-Facing Application', AttackTactic.INITIAL_ACCESS,
                'Exploit vulnerabilities in public-facing applications',
                ['Web application exploits', 'API vulnerabilities', 'Service exploits'],
                ['Monitor application access', 'Alert on exploit attempts'],
                ['Regular vulnerability scanning', 'Web application firewalls'],
                ['T1190.001', 'T1190.002', 'T1190.003']
            ),
            
            # Execution Techniques
            'T1059.001': AttackTechnique(
                'T1059.001', 'PowerShell', AttackTactic.EXECUTION,
                'Use PowerShell for execution',
                ['PowerShell scripts', 'PowerShell commands', 'PS execution'],
                ['Monitor PowerShell execution', 'Alert on suspicious PS commands'],
                ['PowerShell logging', 'Execution policy restrictions'],
                ['T1059.001', 'T1059.002', 'T1059.003']
            ),
            'T1059.002': AttackTechnique(
                'T1059.002', 'AppleScript', AttackTactic.EXECUTION,
                'Use AppleScript for execution',
                ['AppleScript execution', 'macOS scripting', 'OSA execution'],
                ['Monitor AppleScript execution', 'Alert on suspicious scripts'],
                ['Script execution policies', 'Monitor OSA usage'],
                ['T1059.001', 'T1059.002', 'T1059.003']
            ),
            'T1059.003': AttackTechnique(
                'T1059.003', 'Windows Command Shell', AttackTactic.EXECUTION,
                'Use Windows command shell for execution',
                ['CMD execution', 'Command line execution', 'Batch files'],
                ['Monitor command execution', 'Alert on suspicious commands'],
                ['Command logging', 'Execution restrictions'],
                ['T1059.001', 'T1059.002', 'T1059.003']
            ),
            'T1053.001': AttackTechnique(
                'T1053.001', 'At (Linux)', AttackTactic.EXECUTION,
                'Use at command for scheduled execution',
                ['At command execution', 'Scheduled tasks', 'Cron jobs'],
                ['Monitor scheduled tasks', 'Alert on suspicious scheduling'],
                ['Restrict at command', 'Monitor cron jobs'],
                ['T1053.001', 'T1053.002', 'T1053.003']
            ),
            'T1053.002': AttackTechnique(
                'T1053.002', 'At (Windows)', AttackTactic.EXECUTION,
                'Use Windows Task Scheduler for execution',
                ['Scheduled tasks', 'Task scheduler', 'Windows tasks'],
                ['Monitor task creation', 'Alert on suspicious tasks'],
                ['Task scheduler restrictions', 'Monitor task execution'],
                ['T1053.001', 'T1053.002', 'T1053.003']
            ),
            
            # Persistence Techniques
            'T1547.001': AttackTechnique(
                'T1547.001', 'Registry Run Keys / Startup Folder', AttackTactic.PERSISTENCE,
                'Use registry run keys for persistence',
                ['Registry run keys', 'Startup folder', 'Auto-start locations'],
                ['Monitor registry changes', 'Alert on startup modifications'],
                ['Registry monitoring', 'Startup folder restrictions'],
                ['T1547.001', 'T1547.002', 'T1547.003']
            ),
            'T1547.002': AttackTechnique(
                'T1547.002', 'Authentication Package', AttackTactic.PERSISTENCE,
                'Use authentication packages for persistence',
                ['Auth packages', 'GINA DLL', 'Credential providers'],
                ['Monitor auth package loading', 'Alert on package modifications'],
                ['Auth package restrictions', 'Monitor package loading'],
                ['T1547.001', 'T1547.002', 'T1547.003']
            ),
            'T1547.003': AttackTechnique(
                'T1547.003', 'Time Providers', AttackTactic.PERSISTENCE,
                'Use time providers for persistence',
                ['Time provider DLLs', 'W32Time providers', 'Time synchronization'],
                ['Monitor time providers', 'Alert on provider modifications'],
                ['Time provider restrictions', 'Monitor time services'],
                ['T1547.001', 'T1547.002', 'T1547.003']
            ),
            
            # Defense Evasion Techniques
            'T1070.001': AttackTechnique(
                'T1070.001', 'Clear Windows Event Logs', AttackTactic.DEFENSE_EVASION,
                'Clear Windows event logs to evade detection',
                ['Event log clearing', 'Log deletion', 'Audit log removal'],
                ['Monitor log clearing', 'Alert on log deletions'],
                ['Log protection', 'Centralized logging'],
                ['T1070.001', 'T1070.002', 'T1070.003']
            ),
            'T1070.002': AttackTechnique(
                'T1070.002', 'Clear Linux or Mac System Logs', AttackTactic.DEFENSE_EVASION,
                'Clear system logs to evade detection',
                ['System log clearing', 'Log file deletion', 'Audit log removal'],
                ['Monitor log clearing', 'Alert on log deletions'],
                ['Log protection', 'Centralized logging'],
                ['T1070.001', 'T1070.002', 'T1070.003']
            ),
            'T1562.001': AttackTechnique(
                'T1562.001', 'Disable or Modify Tools', AttackTactic.DEFENSE_EVASION,
                'Disable or modify security tools',
                ['Antivirus disabling', 'EDR disabling', 'Security tool modification'],
                ['Monitor tool status', 'Alert on tool modifications'],
                ['Tool protection', 'Centralized monitoring'],
                ['T1562.001', 'T1562.002', 'T1562.003']
            ),
            'T1562.002': AttackTechnique(
                'T1562.002', 'Disable Windows Event Logging', AttackTactic.DEFENSE_EVASION,
                'Disable Windows event logging',
                ['Event log disabling', 'Audit policy modification', 'Log service stopping'],
                ['Monitor logging status', 'Alert on logging changes'],
                ['Logging protection', 'Centralized monitoring'],
                ['T1562.001', 'T1562.002', 'T1562.003']
            ),
            
            # Privilege Escalation Techniques
            'T1548.001': AttackTechnique(
                'T1548.001', 'Setuid and Setgid', AttackTactic.PRIVILEGE_ESCALATION,
                'Use of setuid/setgid binaries for privilege escalation',
                ['SUID binaries', 'SGID binaries', 'Privileged file execution'],
                ['Monitor SUID/SGID file changes', 'Alert on privileged execution'],
                ['Remove unnecessary SUID/SGID', 'Regular file permission audits'],
                ['T1548.001', 'T1548.002', 'T1548.003']
            ),
            'T1548.002': AttackTechnique(
                'T1548.002', 'Bypass User Account Control', AttackTactic.PRIVILEGE_ESCALATION,
                'Bypass User Account Control for privilege escalation',
                ['UAC bypass techniques', 'Elevated process execution'],
                ['Monitor UAC bypass attempts', 'Alert on suspicious elevation'],
                ['Configure UAC settings', 'Monitor elevation events'],
                ['T1548.001', 'T1548.002', 'T1548.003']
            ),
            'T1548.003': AttackTechnique(
                'T1548.003', 'Sudo and Sudo Caching', AttackTactic.PRIVILEGE_ESCALATION,
                'Use of sudo for privilege escalation',
                ['Sudo command execution', 'Sudo caching abuse'],
                ['Monitor sudo usage', 'Alert on suspicious sudo commands'],
                ['Configure sudo timeouts', 'Limit sudo privileges'],
                ['T1548.001', 'T1548.002', 'T1548.003']
            ),
            'T1068': AttackTechnique(
                'T1068', 'Exploitation for Privilege Escalation', AttackTactic.PRIVILEGE_ESCALATION,
                'Exploit vulnerabilities for privilege escalation',
                ['Kernel exploits', 'Application exploits', 'Service exploits'],
                ['Monitor exploit attempts', 'Alert on vulnerability exploitation'],
                ['Regular patching', 'Vulnerability scanning'],
                ['T1068.001', 'T1068.002', 'T1068.003']
            ),
            
            # Credential Access Techniques
            'T1003.001': AttackTechnique(
                'T1003.001', 'LSASS Memory', AttackTactic.CREDENTIAL_ACCESS,
                'Extract credentials from LSASS memory',
                ['LSASS dumping', 'Mimikatz usage', 'Memory extraction'],
                ['Monitor LSASS access', 'Alert on credential dumping'],
                ['Enable LSASS protection', 'Monitor credential access'],
                ['T1003.001', 'T1003.002', 'T1003.003']
            ),
            'T1003.002': AttackTechnique(
                'T1003.002', 'Security Account Manager', AttackTactic.CREDENTIAL_ACCESS,
                'Extract credentials from SAM database',
                ['SAM database access', 'Registry credential extraction'],
                ['Monitor SAM access', 'Alert on SAM database access'],
                ['Restrict SAM access', 'Monitor registry access'],
                ['T1003.001', 'T1003.002', 'T1003.003']
            ),
            'T1003.003': AttackTechnique(
                'T1003.003', 'NTDS', AttackTactic.CREDENTIAL_ACCESS,
                'Extract credentials from NTDS.dit',
                ['NTDS.dit extraction', 'Domain controller access'],
                ['Monitor NTDS access', 'Alert on domain controller access'],
                ['Restrict NTDS access', 'Monitor domain controller activity'],
                ['T1003.001', 'T1003.002', 'T1003.003']
            ),
            'T1110.001': AttackTechnique(
                'T1110.001', 'Brute Force: Password Guessing', AttackTactic.CREDENTIAL_ACCESS,
                'Brute force password guessing',
                ['Password spraying', 'Dictionary attacks', 'Credential stuffing'],
                ['Monitor failed logins', 'Alert on brute force attempts'],
                ['Implement account lockout', 'Strong password policies'],
                ['T1110.001', 'T1110.002', 'T1110.003']
            ),
            'T1110.002': AttackTechnique(
                'T1110.002', 'Brute Force: Password Cracking', AttackTactic.CREDENTIAL_ACCESS,
                'Crack password hashes',
                ['Hash cracking', 'Password recovery', 'Hash extraction'],
                ['Monitor hash access', 'Alert on cracking attempts'],
                ['Strong password policies', 'Hash protection'],
                ['T1110.001', 'T1110.002', 'T1110.003']
            ),
            
            # Discovery Techniques
            'T1082': AttackTechnique(
                'T1082', 'System Information Discovery', AttackTactic.DISCOVERY,
                'Gather system information',
                ['System info commands', 'OS version detection', 'Hardware enumeration'],
                ['Monitor system info commands', 'Alert on enumeration'],
                ['Limit system information', 'Monitor discovery commands'],
                ['T1082.001', 'T1082.002', 'T1082.003']
            ),
            'T1083': AttackTechnique(
                'T1083', 'File and Directory Discovery', AttackTactic.DISCOVERY,
                'Discover files and directories',
                ['Directory listing', 'File enumeration', 'Path discovery'],
                ['Monitor file discovery', 'Alert on enumeration'],
                ['Limit file access', 'Monitor file operations'],
                ['T1083.001', 'T1083.002', 'T1083.003']
            ),
            'T1087.001': AttackTechnique(
                'T1087.001', 'Account Discovery: Local Account', AttackTactic.DISCOVERY,
                'Discover local accounts',
                ['Local user enumeration', 'Account listing', 'User discovery'],
                ['Monitor account enumeration', 'Alert on user discovery'],
                ['Limit account information', 'Monitor account queries'],
                ['T1087.001', 'T1087.002', 'T1087.003']
            ),
            'T1087.002': AttackTechnique(
                'T1087.002', 'Account Discovery: Domain Account', AttackTactic.DISCOVERY,
                'Discover domain accounts',
                ['Domain user enumeration', 'AD account discovery', 'Group membership'],
                ['Monitor domain enumeration', 'Alert on AD queries'],
                ['Limit AD access', 'Monitor domain queries'],
                ['T1087.001', 'T1087.002', 'T1087.003']
            ),
            'T1018': AttackTechnique(
                'T1018', 'Remote System Discovery', AttackTactic.DISCOVERY,
                'Discover remote systems',
                ['Network scanning', 'Host discovery', 'System enumeration'],
                ['Monitor network scanning', 'Alert on discovery attempts'],
                ['Network monitoring', 'Host-based detection'],
                ['T1018.001', 'T1018.002', 'T1018.003']
            ),
            
            # Lateral Movement Techniques
            'T1021.001': AttackTechnique(
                'T1021.001', 'Remote Desktop Protocol', AttackTactic.LATERAL_MOVEMENT,
                'Use RDP for lateral movement',
                ['RDP connections', 'Remote desktop access', 'Terminal services'],
                ['Monitor RDP connections', 'Alert on suspicious RDP'],
                ['Restrict RDP access', 'Implement RDP security'],
                ['T1021.001', 'T1021.002', 'T1021.003']
            ),
            'T1021.002': AttackTechnique(
                'T1021.002', 'SMB/Windows Admin Shares', AttackTactic.LATERAL_MOVEMENT,
                'Use SMB for lateral movement',
                ['SMB connections', 'Admin share access', 'File sharing'],
                ['Monitor SMB connections', 'Alert on admin share access'],
                ['Restrict SMB access', 'Disable unnecessary shares'],
                ['T1021.001', 'T1021.002', 'T1021.003']
            ),
            'T1021.003': AttackTechnique(
                'T1021.003', 'Distributed Component Object Model', AttackTactic.LATERAL_MOVEMENT,
                'Use DCOM for lateral movement',
                ['DCOM connections', 'Remote object activation', 'COM+ access'],
                ['Monitor DCOM connections', 'Alert on remote activation'],
                ['Restrict DCOM access', 'Monitor COM+ activity'],
                ['T1021.001', 'T1021.002', 'T1021.003']
            ),
            'T1021.004': AttackTechnique(
                'T1021.004', 'SSH', AttackTactic.LATERAL_MOVEMENT,
                'Use SSH for lateral movement',
                ['SSH connections', 'Secure shell access', 'Remote command execution'],
                ['Monitor SSH connections', 'Alert on suspicious SSH'],
                ['SSH key management', 'Restrict SSH access'],
                ['T1021.001', 'T1021.002', 'T1021.003', 'T1021.004']
            ),
            
            # Collection Techniques
            'T1005': AttackTechnique(
                'T1005', 'Data from Local System', AttackTactic.COLLECTION,
                'Collect data from local system',
                ['File collection', 'Data extraction', 'Local data gathering'],
                ['Monitor file access', 'Alert on data collection'],
                ['Restrict file access', 'Monitor data operations'],
                ['T1005.001', 'T1005.002', 'T1005.003']
            ),
            'T1074.001': AttackTechnique(
                'T1074.001', 'Local Data Staging', AttackTactic.COLLECTION,
                'Stage collected data locally',
                ['Data staging', 'Temporary storage', 'Data aggregation'],
                ['Monitor data staging', 'Alert on large data operations'],
                ['Monitor storage usage', 'Limit data operations'],
                ['T1074.001', 'T1074.002', 'T1074.003']
            ),
            'T1113': AttackTechnique(
                'T1113', 'Screen Capture', AttackTactic.COLLECTION,
                'Capture screen content',
                ['Screenshot tools', 'Screen recording', 'Visual data collection'],
                ['Monitor screen capture', 'Alert on capture tools'],
                ['Screen capture restrictions', 'Monitor visual data'],
                ['T1113.001', 'T1113.002', 'T1113.003']
            ),
            'T1114.001': AttackTechnique(
                'T1114.001', 'Email Collection: Local Email Archive', AttackTactic.COLLECTION,
                'Collect email from local archives',
                ['Email extraction', 'PST file access', 'Email archive access'],
                ['Monitor email access', 'Alert on email collection'],
                ['Email protection', 'Monitor email operations'],
                ['T1114.001', 'T1114.002', 'T1114.003']
            ),
            
            # Command and Control Techniques
            'T1071.001': AttackTechnique(
                'T1071.001', 'Web Protocols', AttackTactic.COMMAND_AND_CONTROL,
                'Use web protocols for C2 communication',
                ['HTTP C2', 'HTTPS C2', 'Web-based communication'],
                ['Monitor web traffic', 'Alert on suspicious web patterns'],
                ['Web traffic monitoring', 'URL filtering'],
                ['T1071.001', 'T1071.002', 'T1071.003']
            ),
            'T1071.002': AttackTechnique(
                'T1071.002', 'File Transfer Protocols', AttackTactic.COMMAND_AND_CONTROL,
                'Use file transfer protocols for C2',
                ['FTP C2', 'SFTP C2', 'File transfer communication'],
                ['Monitor file transfers', 'Alert on suspicious transfers'],
                ['File transfer monitoring', 'Protocol restrictions'],
                ['T1071.001', 'T1071.002', 'T1071.003']
            ),
            'T1071.003': AttackTechnique(
                'T1071.003', 'Mail Protocols', AttackTactic.COMMAND_AND_CONTROL,
                'Use mail protocols for C2',
                ['SMTP C2', 'IMAP C2', 'Mail-based communication'],
                ['Monitor mail traffic', 'Alert on suspicious mail patterns'],
                ['Mail traffic monitoring', 'Mail filtering'],
                ['T1071.001', 'T1071.002', 'T1071.003']
            ),
            'T1090.001': AttackTechnique(
                'T1090.001', 'Internal Proxy', AttackTactic.COMMAND_AND_CONTROL,
                'Use internal proxy for C2',
                ['Internal proxy', 'Network proxy', 'Traffic redirection'],
                ['Monitor proxy usage', 'Alert on suspicious proxy'],
                ['Proxy monitoring', 'Traffic analysis'],
                ['T1090.001', 'T1090.002', 'T1090.003']
            ),
            
            # Exfiltration Techniques
            'T1041': AttackTechnique(
                'T1041', 'Exfiltration Over C2 Channel', AttackTactic.EXFILTRATION,
                'Exfiltrate data over C2 channel',
                ['Data exfiltration', 'C2 communication', 'Data transfer'],
                ['Monitor data transfers', 'Alert on large data transfers'],
                ['Monitor network traffic', 'Implement data loss prevention'],
                ['T1041.001', 'T1041.002', 'T1041.003']
            ),
            'T1048.003': AttackTechnique(
                'T1048.003', 'Exfiltration Over Alternative Protocol', AttackTactic.EXFILTRATION,
                'Exfiltrate data over alternative protocols',
                ['DNS exfiltration', 'HTTP exfiltration', 'ICMP exfiltration'],
                ['Monitor protocol usage', 'Alert on unusual protocols'],
                ['Monitor network protocols', 'Implement protocol filtering'],
                ['T1048.001', 'T1048.002', 'T1048.003']
            ),
            'T1011.001': AttackTechnique(
                'T1011.001', 'Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth', AttackTactic.EXFILTRATION,
                'Exfiltrate data over Bluetooth',
                ['Bluetooth exfiltration', 'Wireless data transfer', 'Bluetooth communication'],
                ['Monitor Bluetooth usage', 'Alert on Bluetooth transfers'],
                ['Bluetooth monitoring', 'Wireless security'],
                ['T1011.001', 'T1011.002', 'T1011.003']
            ),
            
            # Impact Techniques
            'T1486': AttackTechnique(
                'T1486', 'Data Encrypted for Impact', AttackTactic.IMPACT,
                'Encrypt data for impact',
                ['Ransomware', 'Data encryption', 'Crypto malware'],
                ['Monitor encryption activity', 'Alert on ransomware'],
                ['Regular backups', 'Implement encryption protection'],
                ['T1486.001', 'T1486.002', 'T1486.003']
            ),
            'T1490': AttackTechnique(
                'T1490', 'Inhibit System Recovery', AttackTactic.IMPACT,
                'Inhibit system recovery',
                ['Backup deletion', 'Recovery prevention', 'System damage'],
                ['Monitor backup access', 'Alert on recovery inhibition'],
                ['Protect backups', 'Monitor recovery systems'],
                ['T1490.001', 'T1490.002', 'T1490.003']
            ),
            'T1491.001': AttackTechnique(
                'T1491.001', 'Defacement: Internal Defacement', AttackTactic.IMPACT,
                'Deface internal systems',
                ['Internal defacement', 'System modification', 'Visual impact'],
                ['Monitor system changes', 'Alert on defacement'],
                ['System protection', 'Change monitoring'],
                ['T1491.001', 'T1491.002', 'T1491.003']
            ),
            'T1499.001': AttackTechnique(
                'T1499.001', 'Endpoint Denial of Service: OS Exhaustion Flood', AttackTactic.IMPACT,
                'Deny service through OS exhaustion',
                ['OS exhaustion', 'Resource flooding', 'System overload'],
                ['Monitor system resources', 'Alert on exhaustion'],
                ['Resource monitoring', 'System protection'],
                ['T1499.001', 'T1499.002', 'T1499.003']
            )
        }
    
    def _initialize_rule_patterns(self) -> Dict[str, List[str]]:
        """Initialize rule patterns for technique mapping"""
        return {
            # Service Account Patterns
            r'service.*account.*misuse': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'service.*account.*detection': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'sa-.*misuse': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'service.*account.*login': ['T1078.001', 'T1078.002', 'T1078.003'],
            
            # Initial Access Patterns
            r'external.*access': ['T1133'],
            r'vpn.*connection': ['T1133'],
            r'remote.*access': ['T1133'],
            r'default.*account': ['T1078.001'],
            r'domain.*account': ['T1078.002'],
            r'local.*account': ['T1078.003'],
            r'web.*application.*exploit': ['T1190'],
            r'api.*vulnerability': ['T1190'],
            r'public.*facing.*exploit': ['T1190'],
            
            # Execution Patterns
            r'powershell.*execution': ['T1059.001'],
            r'ps.*command': ['T1059.001'],
            r'applescript.*execution': ['T1059.002'],
            r'osa.*execution': ['T1059.002'],
            r'cmd.*execution': ['T1059.003'],
            r'command.*shell': ['T1059.003'],
            r'scheduled.*task': ['T1053.001', 'T1053.002'],
            r'at.*command': ['T1053.001'],
            r'cron.*job': ['T1053.001'],
            r'task.*scheduler': ['T1053.002'],
            
            # Persistence Patterns
            r'registry.*run.*key': ['T1547.001'],
            r'startup.*folder': ['T1547.001'],
            r'authentication.*package': ['T1547.002'],
            r'gina.*dll': ['T1547.002'],
            r'time.*provider': ['T1547.003'],
            r'w32time.*provider': ['T1547.003'],
            
            # Defense Evasion Patterns
            r'event.*log.*clear': ['T1070.001'],
            r'log.*deletion': ['T1070.001', 'T1070.002'],
            r'system.*log.*clear': ['T1070.002'],
            r'disable.*antivirus': ['T1562.001'],
            r'disable.*edr': ['T1562.001'],
            r'disable.*event.*logging': ['T1562.002'],
            r'audit.*policy.*modification': ['T1562.002'],
            
            # Privilege Escalation Patterns
            r'privilege.*escalation': ['T1548.001', 'T1548.002', 'T1548.003', 'T1068'],
            r'admin.*group.*modification': ['T1548.002', 'T1068'],
            r'domain.*admin.*group': ['T1548.002', 'T1068'],
            r'sudo.*usage': ['T1548.003', 'T1068'],
            r'uac.*bypass': ['T1548.002', 'T1068'],
            r'setuid.*execution': ['T1548.001', 'T1068'],
            r'exploit.*vulnerability': ['T1068'],
            
            # Credential Access Patterns
            r'credential.*dump': ['T1003.001', 'T1003.002', 'T1003.003'],
            r'lsass.*memory': ['T1003.001'],
            r'sam.*database': ['T1003.002'],
            r'ntds.*extraction': ['T1003.003'],
            r'password.*spraying': ['T1110.001'],
            r'brute.*force': ['T1110.001'],
            r'failed.*login': ['T1110.001'],
            r'password.*crack': ['T1110.002'],
            r'hash.*crack': ['T1110.002'],
            
            # Discovery Patterns
            r'system.*information': ['T1082'],
            r'file.*discovery': ['T1083'],
            r'directory.*listing': ['T1083'],
            r'account.*enumeration': ['T1087.001', 'T1087.002'],
            r'user.*enumeration': ['T1087.001', 'T1087.002'],
            r'domain.*enumeration': ['T1087.002'],
            r'remote.*system.*discovery': ['T1018'],
            r'network.*scan': ['T1018'],
            r'host.*discovery': ['T1018'],
            
            # Lateral Movement Patterns
            r'rdp.*connection': ['T1021.001'],
            r'remote.*desktop': ['T1021.001'],
            r'smb.*connection': ['T1021.002'],
            r'admin.*share': ['T1021.002'],
            r'dcom.*connection': ['T1021.003'],
            r'ssh.*connection': ['T1021.004'],
            r'secure.*shell': ['T1021.004'],
            r'lateral.*movement': ['T1021.001', 'T1021.002', 'T1021.003', 'T1021.004'],
            
            # Collection Patterns
            r'data.*collection': ['T1005'],
            r'file.*collection': ['T1005'],
            r'data.*staging': ['T1074.001'],
            r'local.*data': ['T1005', 'T1074.001'],
            r'screen.*capture': ['T1113'],
            r'screenshot': ['T1113'],
            r'email.*collection': ['T1114.001'],
            r'pst.*file': ['T1114.001'],
            r'email.*archive': ['T1114.001'],
            
            # Command and Control Patterns
            r'web.*protocol.*c2': ['T1071.001'],
            r'http.*c2': ['T1071.001'],
            r'https.*c2': ['T1071.001'],
            r'file.*transfer.*c2': ['T1071.002'],
            r'ftp.*c2': ['T1071.002'],
            r'sftp.*c2': ['T1071.002'],
            r'mail.*protocol.*c2': ['T1071.003'],
            r'smtp.*c2': ['T1071.003'],
            r'imap.*c2': ['T1071.003'],
            r'internal.*proxy': ['T1090.001'],
            r'network.*proxy': ['T1090.001'],
            
            # Exfiltration Patterns
            r'data.*exfiltration': ['T1041', 'T1048.003'],
            r'data.*transfer': ['T1041', 'T1048.003'],
            r'dns.*exfiltration': ['T1048.003'],
            r'http.*exfiltration': ['T1048.003'],
            r'bluetooth.*exfiltration': ['T1011.001'],
            r'wireless.*data.*transfer': ['T1011.001'],
            
            # Impact Patterns
            r'ransomware': ['T1486'],
            r'data.*encryption': ['T1486'],
            r'backup.*deletion': ['T1490'],
            r'recovery.*inhibition': ['T1490'],
            r'defacement': ['T1491.001'],
            r'system.*modification': ['T1491.001'],
            r'denial.*of.*service': ['T1499.001'],
            r'os.*exhaustion': ['T1499.001'],
            r'resource.*flood': ['T1499.001']
        }
    
    def _initialize_advanced_patterns(self) -> Dict[str, List[str]]:
        """Initialize advanced pattern matching"""
        return {
            # Advanced Service Account Patterns
            r'service.*account.*(?:login|access|usage).*(?:outside|unauthorized|unusual)': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'(?:sa-|service_).*misuse.*detected': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'service.*account.*(?:privilege|elevation)': ['T1078.001', 'T1078.002', 'T1078.003', 'T1548.001'],
            
            # Advanced Initial Access Patterns
            r'(?:external|remote).*(?:access|connection)': ['T1133'],
            r'(?:vpn|rdp|ssh).*(?:connection|access)': ['T1133'],
            r'(?:default|service).*(?:account|password)': ['T1078.001', 'T1078.002', 'T1078.003'],
            r'(?:web|api).*(?:application|service).*(?:exploit|vulnerability)': ['T1190'],
            r'(?:public|internet).*(?:facing|accessible).*(?:exploit|vulnerability)': ['T1190'],
            
            # Advanced Execution Patterns
            r'(?:powershell|ps).*(?:execution|command|script)': ['T1059.001'],
            r'(?:applescript|osa).*(?:execution|script)': ['T1059.002'],
            r'(?:cmd|command).*(?:shell|execution)': ['T1059.003'],
            r'(?:scheduled|automated).*(?:task|job|execution)': ['T1053.001', 'T1053.002'],
            r'(?:at|cron).*(?:command|job|scheduling)': ['T1053.001'],
            r'(?:task|windows).*(?:scheduler|scheduling)': ['T1053.002'],
            
            # Advanced Persistence Patterns
            r'(?:registry|startup).*(?:run|key|folder)': ['T1547.001'],
            r'(?:authentication|credential).*(?:package|provider)': ['T1547.002'],
            r'(?:gina|time).*(?:dll|provider)': ['T1547.002', 'T1547.003'],
            r'(?:w32time|time).*(?:provider|synchronization)': ['T1547.003'],
            
            # Advanced Defense Evasion Patterns
            r'(?:event|system|audit).*(?:log|logging).*(?:clear|delete|disable)': ['T1070.001', 'T1070.002', 'T1562.002'],
            r'(?:antivirus|edr|security).*(?:disable|modify|modification)': ['T1562.001'],
            r'(?:audit|logging).*(?:policy|service).*(?:modification|disable)': ['T1562.002'],
            
            # Advanced Privilege Escalation Patterns
            r'(?:privilege|admin).*escalation.*(?:detected|attempt)': ['T1548.001', 'T1548.002', 'T1548.003', 'T1068'],
            r'(?:domain|enterprise).*admin.*(?:group|member)': ['T1548.002', 'T1068'],
            r'(?:sudo|uac).*(?:bypass|elevation)': ['T1548.002', 'T1548.003', 'T1068'],
            r'(?:setuid|setgid).*(?:execution|modification)': ['T1548.001', 'T1068'],
            r'(?:exploit|vulnerability).*(?:privilege|escalation)': ['T1068'],
            
            # Advanced Credential Access Patterns
            r'(?:credential|password).*(?:dump|extraction|harvesting)': ['T1003.001', 'T1003.002', 'T1003.003'],
            r'(?:lsass|sam|ntds).*(?:memory|database|extraction)': ['T1003.001', 'T1003.002', 'T1003.003'],
            r'(?:password|credential).*(?:spraying|brute|force)': ['T1110.001'],
            r'(?:failed|multiple).*(?:login|authentication)': ['T1110.001'],
            r'(?:password|hash).*(?:crack|cracking|recovery)': ['T1110.002'],
            
            # Advanced Discovery Patterns
            r'(?:system|host).*(?:information|enumeration)': ['T1082'],
            r'(?:file|directory).*(?:discovery|enumeration|listing)': ['T1083'],
            r'(?:account|user).*(?:enumeration|discovery|listing)': ['T1087.001', 'T1087.002'],
            r'(?:domain|ad).*(?:enumeration|discovery)': ['T1087.002'],
            r'(?:remote|network).*(?:system|host).*(?:discovery|scan)': ['T1018'],
            
            # Advanced Lateral Movement Patterns
            r'(?:rdp|remote.*desktop).*(?:connection|access)': ['T1021.001'],
            r'(?:smb|admin.*share).*(?:connection|access)': ['T1021.002'],
            r'(?:dcom|com\+).*(?:connection|activation)': ['T1021.003'],
            r'(?:ssh|secure.*shell).*(?:connection|access)': ['T1021.004'],
            r'(?:lateral|horizontal).*(?:movement|spread)': ['T1021.001', 'T1021.002', 'T1021.003', 'T1021.004'],
            
            # Advanced Collection Patterns
            r'(?:data|file).*(?:collection|gathering|extraction)': ['T1005', 'T1074.001'],
            r'(?:local|system).*(?:data|file).*(?:staging|collection)': ['T1005', 'T1074.001'],
            r'(?:screen|visual).*(?:capture|recording|screenshot)': ['T1113'],
            r'(?:email|mail).*(?:collection|archive|extraction)': ['T1114.001'],
            r'(?:pst|outlook).*(?:file|archive|access)': ['T1114.001'],
            
            # Advanced Command and Control Patterns
            r'(?:web|http|https).*(?:protocol|traffic).*(?:c2|command)': ['T1071.001'],
            r'(?:file|ftp|sftp).*(?:transfer|protocol).*(?:c2|command)': ['T1071.002'],
            r'(?:mail|smtp|imap).*(?:protocol|traffic).*(?:c2|command)': ['T1071.003'],
            r'(?:internal|network).*(?:proxy|redirection)': ['T1090.001'],
            
            # Advanced Exfiltration Patterns
            r'(?:data|file).*(?:exfiltration|transfer|upload)': ['T1041', 'T1048.003'],
            r'(?:dns|http|icmp).*(?:exfiltration|tunnel)': ['T1048.003'],
            r'(?:large|bulk).*(?:data|file).*(?:transfer|upload)': ['T1041', 'T1048.003'],
            r'(?:bluetooth|wireless).*(?:exfiltration|transfer|communication)': ['T1011.001'],
            
            # Advanced Impact Patterns
            r'(?:ransomware|crypto).*(?:encryption|infection)': ['T1486'],
            r'(?:data|file).*(?:encryption|lock)': ['T1486'],
            r'(?:backup|recovery).*(?:deletion|inhibition)': ['T1490'],
            r'(?:system|service).*(?:recovery|restore).*(?:inhibition|prevention)': ['T1490'],
            r'(?:defacement|visual).*(?:modification|impact)': ['T1491.001'],
            r'(?:denial|dos).*(?:service|exhaustion|flood)': ['T1499.001'],
            r'(?:os|system).*(?:exhaustion|overload|resource)': ['T1499.001']
        }
    
    def map_rule_to_attack(self, rule_name: str, description: str, search_filter: str) -> Dict[str, Any]:
        """Map a security rule to MITRE ATT&CK techniques"""
        text_to_analyze = f"{rule_name} {description} {search_filter}".lower()
        
        matched_techniques = []
        confidence_scores = {}
        
        # Check basic patterns
        for pattern, techniques in self.rule_patterns.items():
            if self._pattern_matches(pattern, text_to_analyze):
                for technique_id in techniques:
                    if technique_id in self.techniques:
                        technique = self.techniques[technique_id]
                        matched_techniques.append({
                            'technique_id': technique_id,
                            'name': technique.name,
                            'tactic': technique.tactic.value,
                            'description': technique.description,
                            'confidence': 0.7
                        })
                        confidence_scores[technique_id] = 0.7
        
        # Check advanced patterns
        for pattern, techniques in self.advanced_patterns.items():
            if self._pattern_matches(pattern, text_to_analyze):
                for technique_id in techniques:
                    if technique_id in self.techniques:
                        technique = self.techniques[technique_id]
                        # Higher confidence for advanced patterns
                        confidence = 0.9
                        
                        # Check if already matched
                        existing = next((t for t in matched_techniques if t['technique_id'] == technique_id), None)
                        if existing:
                            existing['confidence'] = max(existing['confidence'], confidence)
                        else:
                            matched_techniques.append({
                                'technique_id': technique_id,
                                'name': technique.name,
                                'tactic': technique.tactic.value,
                                'description': technique.description,
                                'confidence': confidence
                            })
                        confidence_scores[technique_id] = confidence
        
        # Sort by confidence
        matched_techniques.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {
            'techniques': matched_techniques,
            'primary_tactic': self._determine_primary_tactic(matched_techniques),
            'confidence_score': self._calculate_overall_confidence(matched_techniques),
            'coverage_score': len(matched_techniques) / 10.0  # Normalize to 0-1
        }
    
    def _pattern_matches(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text"""
        import re
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error:
            return False
    
    def _determine_primary_tactic(self, techniques: List[Dict[str, Any]]) -> str:
        """Determine the primary tactic based on matched techniques"""
        if not techniques:
            return "unknown"
        
        # Count techniques by tactic
        tactic_counts = {}
        for technique in techniques:
            tactic = technique['tactic']
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        # Return the most common tactic
        return max(tactic_counts.items(), key=lambda x: x[1])[0]
    
    def _calculate_overall_confidence(self, techniques: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score"""
        if not techniques:
            return 0.0
        
        # Weight by confidence and number of matches
        total_confidence = sum(t['confidence'] for t in techniques)
        return min(1.0, total_confidence / len(techniques))
    
    def get_technique_details(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get detailed information about a technique"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: AttackTactic) -> List[AttackTechnique]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def get_techniques_by_pattern(self, pattern: str) -> List[AttackTechnique]:
        """Get techniques that match a pattern"""
        matched_techniques = []
        for technique_id, technique in self.techniques.items():
            if self._pattern_matches(pattern, technique.name.lower()) or \
               self._pattern_matches(pattern, technique.description.lower()):
                matched_techniques.append(technique)
        return matched_techniques
    
    def generate_attack_report(self, rule_mappings: List[Dict[str, Any]]) -> str:
        """Generate a comprehensive MITRE ATT&CK mapping report"""
        report = f"""# MITRE ATT&CK Mapping Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Rules Analyzed:** {len(rule_mappings)}

## Executive Summary

"""
        
        # Calculate statistics
        total_techniques = sum(len(mapping['techniques']) for mapping in rule_mappings)
        avg_confidence = sum(mapping['confidence_score'] for mapping in rule_mappings) / len(rule_mappings) if rule_mappings else 0
        tactic_distribution = {}
        
        for mapping in rule_mappings:
            for technique in mapping['techniques']:
                tactic = technique['tactic']
                tactic_distribution[tactic] = tactic_distribution.get(tactic, 0) + 1
        
        report += f"""
- **Total Techniques Mapped:** {total_techniques}
- **Average Confidence Score:** {avg_confidence:.2f}
- **Rules with Mappings:** {len([m for m in rule_mappings if m['techniques']])}
- **Coverage Rate:** {len([m for m in rule_mappings if m['techniques']]) / len(rule_mappings) * 100:.1f}%

## Tactic Distribution

"""
        
        for tactic, count in sorted(tactic_distribution.items(), key=lambda x: x[1], reverse=True):
            percentage = count / total_techniques * 100 if total_techniques > 0 else 0
            report += f"- **{tactic.title()}:** {count} techniques ({percentage:.1f}%)\n"
        
        report += "\n## High Confidence Mappings\n"
        
        # Show high confidence mappings
        high_confidence_mappings = []
        for mapping in rule_mappings:
            if mapping['confidence_score'] >= 0.8:
                high_confidence_mappings.append(mapping)
        
        for i, mapping in enumerate(high_confidence_mappings[:10], 1):
            report += f"""
{i}. **{mapping.get('rule_name', 'Unknown Rule')}**
    - **Confidence:** {mapping['confidence_score']:.2f}
    - **Primary Tactic:** {mapping['primary_tactic']}
    - **Techniques:** {', '.join(t['technique_id'] for t in mapping['techniques'][:3])}
"""
        
        if len(high_confidence_mappings) > 10:
            report += f"\n... and {len(high_confidence_mappings) - 10} more high confidence mappings\n"
        
        report += "\n## Recommendations\n"
        
        if avg_confidence < 0.7:
            report += "1. **Improve Pattern Matching:** Add more specific patterns for better technique mapping\n"
        
        if len(tactic_distribution) < 5:
            report += "2. **Expand Coverage:** Add patterns for additional MITRE ATT&CK tactics\n"
        
        report += "3. **Regular Updates:** Keep technique library updated with latest MITRE ATT&CK framework\n"
        report += "4. **Validation:** Regularly validate mappings against known attack scenarios\n"
        
        return report 