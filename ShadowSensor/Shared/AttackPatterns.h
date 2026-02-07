/**
 * ============================================================================
 * ShadowStrike NGAV - MITRE ATT&CK MAPPING AND ATTACK PATTERNS
 * ============================================================================
 *
 * @file AttackPatterns.h
 * @brief MITRE ATT&CK technique definitions and attack pattern structures.
 *
 * This file provides comprehensive MITRE ATT&CK framework integration,
 * defining technique IDs, tactics, and detection patterns for behavioral
 * analysis in the ShadowSensor kernel driver.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

// ============================================================================
// MITRE ATT&CK TACTICS (High-level categories)
// ============================================================================

/**
 * @brief MITRE ATT&CK Tactics.
 * See: https://attack.mitre.org/tactics/enterprise/
 */
typedef enum _MITRE_TACTIC {
    Tactic_None = 0,
    Tactic_Reconnaissance         = 0x0001,   // TA0043
    Tactic_ResourceDevelopment    = 0x0002,   // TA0042
    Tactic_InitialAccess          = 0x0003,   // TA0001
    Tactic_Execution              = 0x0004,   // TA0002
    Tactic_Persistence            = 0x0005,   // TA0003
    Tactic_PrivilegeEscalation    = 0x0006,   // TA0004
    Tactic_DefenseEvasion         = 0x0007,   // TA0005
    Tactic_CredentialAccess       = 0x0008,   // TA0006
    Tactic_Discovery              = 0x0009,   // TA0007
    Tactic_LateralMovement        = 0x000A,   // TA0008
    Tactic_Collection             = 0x000B,   // TA0009
    Tactic_CommandAndControl      = 0x000C,   // TA0011
    Tactic_Exfiltration           = 0x000D,   // TA0010
    Tactic_Impact                 = 0x000E,   // TA0040
    Tactic_Max
} MITRE_TACTIC;

// ============================================================================
// MITRE ATT&CK TECHNIQUE IDs
// Format: T[4-digit ID] encoded as 0xTTTT where TTTT = technique number
// Sub-techniques encoded as: 0xTTTTSS where SS = sub-technique number
// ============================================================================

/**
 * @brief MITRE ATT&CK Technique IDs (Windows-focused).
 * Format: MITRE_T followed by technique number.
 */

// ---------------------------------------------------------------------
// Initial Access (TA0001)
// ---------------------------------------------------------------------
#define MITRE_T1566              0x061E      // Phishing
#define MITRE_T1566_001          0x061E01    // Phishing: Spearphishing Attachment
#define MITRE_T1566_002          0x061E02    // Phishing: Spearphishing Link
#define MITRE_T1566_003          0x061E03    // Phishing: Spearphishing via Service
#define MITRE_T1189              0x0745      // Drive-by Compromise
#define MITRE_T1190              0x0746      // Exploit Public-Facing Application
#define MITRE_T1133              0x0535      // External Remote Services
#define MITRE_T1200              0x04B0      // Hardware Additions
#define MITRE_T1091              0x035B      // Replication Through Removable Media
#define MITRE_T1195              0x04AB      // Supply Chain Compromise
#define MITRE_T1195_001          0x04AB01    // Compromise Software Dependencies
#define MITRE_T1195_002          0x04AB02    // Compromise Software Supply Chain
#define MITRE_T1199              0x04AF      // Trusted Relationship
#define MITRE_T1078              0x030E      // Valid Accounts
#define MITRE_T1078_001          0x030E01    // Default Accounts
#define MITRE_T1078_002          0x030E02    // Domain Accounts
#define MITRE_T1078_003          0x030E03    // Local Accounts

// ---------------------------------------------------------------------
// Execution (TA0002)
// ---------------------------------------------------------------------
#define MITRE_T1059              0x0413      // Command and Scripting Interpreter
#define MITRE_T1059_001          0x041301    // PowerShell
#define MITRE_T1059_003          0x041303    // Windows Command Shell
#define MITRE_T1059_005          0x041305    // Visual Basic
#define MITRE_T1059_006          0x041306    // Python
#define MITRE_T1059_007          0x041307    // JavaScript
#define MITRE_T1059_008          0x041308    // Network Device CLI
#define MITRE_T1203              0x04B3      // Exploitation for Client Execution
#define MITRE_T1559              0x0617      // Inter-Process Communication
#define MITRE_T1559_001          0x061701    // Component Object Model
#define MITRE_T1559_002          0x061702    // Dynamic Data Exchange
#define MITRE_T1106              0x044A      // Native API
#define MITRE_T1053              0x040D      // Scheduled Task/Job
#define MITRE_T1053_002          0x040D02    // At
#define MITRE_T1053_005          0x040D05    // Scheduled Task
#define MITRE_T1129              0x0481      // Shared Modules
#define MITRE_T1072              0x0308      // Software Deployment Tools
#define MITRE_T1569              0x0621      // System Services
#define MITRE_T1569_001          0x062101    // Launchctl
#define MITRE_T1569_002          0x062102    // Service Execution
#define MITRE_T1204              0x04B4      // User Execution
#define MITRE_T1204_001          0x04B401    // Malicious Link
#define MITRE_T1204_002          0x04B402    // Malicious File
#define MITRE_T1047              0x0407      // Windows Management Instrumentation

// ---------------------------------------------------------------------
// Persistence (TA0003)
// ---------------------------------------------------------------------
#define MITRE_T1098              0x035A      // Account Manipulation
#define MITRE_T1197              0x04AD      // BITS Jobs
#define MITRE_T1547              0x0603      // Boot or Logon Autostart Execution
#define MITRE_T1547_001          0x060301    // Registry Run Keys / Startup Folder
#define MITRE_T1547_002          0x060302    // Authentication Package
#define MITRE_T1547_004          0x060304    // Winlogon Helper DLL
#define MITRE_T1547_005          0x060305    // Security Support Provider
#define MITRE_T1547_006          0x060306    // Kernel Modules and Extensions
#define MITRE_T1547_009          0x060309    // Shortcut Modification
#define MITRE_T1547_010          0x06030A    // Port Monitors
#define MITRE_T1547_012          0x06030C    // Print Processors
#define MITRE_T1547_014          0x06030E    // Active Setup
#define MITRE_T1037              0x03FD      // Boot or Logon Initialization Scripts
#define MITRE_T1037_001          0x03FD01    // Logon Script (Windows)
#define MITRE_T1543              0x05FF      // Create or Modify System Process
#define MITRE_T1543_002          0x05FF02    // Systemd Service
#define MITRE_T1543_003          0x05FF03    // Windows Service
#define MITRE_T1546              0x0602      // Event Triggered Execution
#define MITRE_T1546_001          0x060201    // Change Default File Association
#define MITRE_T1546_002          0x060202    // Screensaver
#define MITRE_T1546_003          0x060203    // Windows Management Instrumentation Event
#define MITRE_T1546_007          0x060207    // Netsh Helper DLL
#define MITRE_T1546_008          0x060208    // Accessibility Features
#define MITRE_T1546_009          0x060209    // AppCert DLLs
#define MITRE_T1546_010          0x06020A    // AppInit DLLs
#define MITRE_T1546_011          0x06020B    // Application Shimming
#define MITRE_T1546_012          0x06020C    // Image File Execution Options Injection
#define MITRE_T1546_013          0x06020D    // PowerShell Profile
#define MITRE_T1546_015          0x06020F    // Component Object Model Hijacking
#define MITRE_T1574              0x0626      // Hijack Execution Flow
#define MITRE_T1574_001          0x062601    // DLL Search Order Hijacking
#define MITRE_T1574_002          0x062602    // DLL Side-Loading
#define MITRE_T1574_007          0x062607    // Path Interception by PATH Environment Variable
#define MITRE_T1574_008          0x062608    // Path Interception by Search Order Hijacking
#define MITRE_T1574_009          0x062609    // Path Interception by Unquoted Path
#define MITRE_T1574_010          0x06260A    // Services File Permissions Weakness
#define MITRE_T1574_011          0x06260B    // Services Registry Permissions Weakness
#define MITRE_T1574_012          0x06260C    // COR_PROFILER
#define MITRE_T1556              0x0614      // Modify Authentication Process
#define MITRE_T1137              0x0539      // Office Application Startup
#define MITRE_T1542              0x05FE      // Pre-OS Boot
#define MITRE_T1542_001          0x05FE01    // System Firmware
#define MITRE_T1542_003          0x05FE03    // Bootkit
#define MITRE_T1505              0x05E1      // Server Software Component
#define MITRE_T1505_001          0x05E101    // SQL Stored Procedures
#define MITRE_T1505_003          0x05E103    // Web Shell

// ---------------------------------------------------------------------
// Privilege Escalation (TA0004)
// ---------------------------------------------------------------------
#define MITRE_T1548              0x0604      // Abuse Elevation Control Mechanism
#define MITRE_T1548_002          0x060402    // Bypass User Account Control
#define MITRE_T1134              0x0536      // Access Token Manipulation
#define MITRE_T1134_001          0x053601    // Token Impersonation/Theft
#define MITRE_T1134_002          0x053602    // Create Process with Token
#define MITRE_T1134_003          0x053603    // Make and Impersonate Token
#define MITRE_T1134_004          0x053604    // Parent PID Spoofing
#define MITRE_T1134_005          0x053605    // SID-History Injection
#define MITRE_T1068              0x0424      // Exploitation for Privilege Escalation
#define MITRE_T1055              0x040F      // Process Injection
#define MITRE_T1055_001          0x040F01    // Dynamic-link Library Injection
#define MITRE_T1055_002          0x040F02    // Portable Executable Injection
#define MITRE_T1055_003          0x040F03    // Thread Execution Hijacking
#define MITRE_T1055_004          0x040F04    // Asynchronous Procedure Call
#define MITRE_T1055_005          0x040F05    // Thread Local Storage
#define MITRE_T1055_008          0x040F08    // Ptrace System Calls
#define MITRE_T1055_009          0x040F09    // Proc Memory
#define MITRE_T1055_011          0x040F0B    // Extra Window Memory Injection
#define MITRE_T1055_012          0x040F0C    // Process Hollowing
#define MITRE_T1055_013          0x040F0D    // Process Doppelganging
#define MITRE_T1055_014          0x040F0E    // VDSO Hijacking
#define MITRE_T1055_015          0x040F0F    // ListPlanting

// ---------------------------------------------------------------------
// Defense Evasion (TA0005)
// ---------------------------------------------------------------------
#define MITRE_T1548_003          0x060403    // Sudo and Sudo Caching
#define MITRE_T1140              0x058C      // Deobfuscate/Decode Files or Information
#define MITRE_T1610              0x064A      // Deploy Container
#define MITRE_T1006              0x03E6      // Direct Volume Access
#define MITRE_T1484              0x05C4      // Domain Policy Modification
#define MITRE_T1480              0x05C0      // Execution Guardrails
#define MITRE_T1211              0x04C3      // Exploitation for Defense Evasion
#define MITRE_T1222              0x04CE      // File and Directory Permissions Modification
#define MITRE_T1564              0x061C      // Hide Artifacts
#define MITRE_T1564_001          0x061C01    // Hidden Files and Directories
#define MITRE_T1564_002          0x061C02    // Hidden Users
#define MITRE_T1564_003          0x061C03    // Hidden Window
#define MITRE_T1564_004          0x061C04    // NTFS File Attributes
#define MITRE_T1564_005          0x061C05    // Hidden File System
#define MITRE_T1564_006          0x061C06    // Run Virtual Instance
#define MITRE_T1564_007          0x061C07    // VBA Stomping
#define MITRE_T1562              0x061A      // Impair Defenses
#define MITRE_T1562_001          0x061A01    // Disable or Modify Tools
#define MITRE_T1562_002          0x061A02    // Disable Windows Event Logging
#define MITRE_T1562_003          0x061A03    // Impair Command History Logging
#define MITRE_T1562_004          0x061A04    // Disable or Modify System Firewall
#define MITRE_T1562_006          0x061A06    // Indicator Blocking
#define MITRE_T1562_009          0x061A09    // Safe Mode Boot
#define MITRE_T1562_010          0x061A0A    // Downgrade Attack
#define MITRE_T1070              0x0306      // Indicator Removal
#define MITRE_T1070_001          0x030601    // Clear Windows Event Logs
#define MITRE_T1070_003          0x030603    // Clear Command History
#define MITRE_T1070_004          0x030604    // File Deletion
#define MITRE_T1070_005          0x030605    // Network Share Connection Removal
#define MITRE_T1070_006          0x030606    // Timestomp
#define MITRE_T1202              0x04B2      // Indirect Command Execution
#define MITRE_T1036              0x03FC      // Masquerading
#define MITRE_T1036_001          0x03FC01    // Invalid Code Signature
#define MITRE_T1036_003          0x03FC03    // Rename System Utilities
#define MITRE_T1036_004          0x03FC04    // Masquerade Task or Service
#define MITRE_T1036_005          0x03FC05    // Match Legitimate Name or Location
#define MITRE_T1036_006          0x03FC06    // Space after Filename
#define MITRE_T1036_007          0x03FC07    // Double File Extension
#define MITRE_T1112              0x0450      // Modify Registry
#define MITRE_T1601              0x0641      // Modify System Image
#define MITRE_T1027              0x03F3      // Obfuscated Files or Information
#define MITRE_T1027_001          0x03F301    // Binary Padding
#define MITRE_T1027_002          0x03F302    // Software Packing
#define MITRE_T1027_003          0x03F303    // Steganography
#define MITRE_T1027_004          0x03F304    // Compile After Delivery
#define MITRE_T1027_005          0x03F305    // Indicator Removal from Tools
#define MITRE_T1027_006          0x03F306    // HTML Smuggling
#define MITRE_T1027_007          0x03F307    // Dynamic API Resolution
#define MITRE_T1027_009          0x03F309    // Embedded Payloads
#define MITRE_T1027_010          0x03F30A    // Command Obfuscation
#define MITRE_T1647              0x066F      // Plist File Modification
#define MITRE_T1620              0x0654      // Reflective Code Loading
#define MITRE_T1207              0x04BF      // Rogue Domain Controller
#define MITRE_T1014              0x03EE      // Rootkit
#define MITRE_T1218              0x04CA      // System Binary Proxy Execution
#define MITRE_T1218_001          0x04CA01    // Compiled HTML File
#define MITRE_T1218_002          0x04CA02    // Control Panel
#define MITRE_T1218_003          0x04CA03    // CMSTP
#define MITRE_T1218_004          0x04CA04    // InstallUtil
#define MITRE_T1218_005          0x04CA05    // Mshta
#define MITRE_T1218_007          0x04CA07    // Msiexec
#define MITRE_T1218_008          0x04CA08    // Odbcconf
#define MITRE_T1218_009          0x04CA09    // Regsvcs/Regasm
#define MITRE_T1218_010          0x04CA0A    // Regsvr32
#define MITRE_T1218_011          0x04CA0B    // Rundll32
#define MITRE_T1218_012          0x04CA0C    // Verclsid
#define MITRE_T1218_013          0x04CA0D    // Mavinject
#define MITRE_T1218_014          0x04CA0E    // MMC
#define MITRE_T1216              0x04C8      // System Script Proxy Execution
#define MITRE_T1216_001          0x04C801    // PubPrn
#define MITRE_T1221              0x04CD      // Template Injection
#define MITRE_T1205              0x04B5      // Traffic Signaling
#define MITRE_T1127              0x047F      // Trusted Developer Utilities Proxy Execution
#define MITRE_T1127_001          0x047F01    // MSBuild
#define MITRE_T1535              0x05EF      // Unused/Unsupported Cloud Regions
#define MITRE_T1550              0x060E      // Use Alternate Authentication Material
#define MITRE_T1550_001          0x060E01    // Application Access Token
#define MITRE_T1550_002          0x060E02    // Pass the Hash
#define MITRE_T1550_003          0x060E03    // Pass the Ticket
#define MITRE_T1550_004          0x060E04    // Web Session Cookie
#define MITRE_T1497              0x05D9      // Virtualization/Sandbox Evasion
#define MITRE_T1497_001          0x05D901    // System Checks
#define MITRE_T1497_002          0x05D902    // User Activity Based Checks
#define MITRE_T1497_003          0x05D903    // Time Based Evasion
#define MITRE_T1600              0x0640      // Weaken Encryption
#define MITRE_T1220              0x04CC      // XSL Script Processing

// ---------------------------------------------------------------------
// Credential Access (TA0006)
// ---------------------------------------------------------------------
#define MITRE_T1557              0x0615      // Adversary-in-the-Middle
#define MITRE_T1557_001          0x061501    // LLMNR/NBT-NS Poisoning and SMB Relay
#define MITRE_T1557_002          0x061502    // ARP Cache Poisoning
#define MITRE_T1110              0x044E      // Brute Force
#define MITRE_T1110_001          0x044E01    // Password Guessing
#define MITRE_T1110_002          0x044E02    // Password Cracking
#define MITRE_T1110_003          0x044E03    // Password Spraying
#define MITRE_T1110_004          0x044E04    // Credential Stuffing
#define MITRE_T1555              0x0613      // Credentials from Password Stores
#define MITRE_T1555_001          0x061301    // Keychain
#define MITRE_T1555_003          0x061303    // Credentials from Web Browsers
#define MITRE_T1555_004          0x061304    // Windows Credential Manager
#define MITRE_T1555_005          0x061305    // Password Managers
#define MITRE_T1212              0x04C4      // Exploitation for Credential Access
#define MITRE_T1187              0x04A3      // Forced Authentication
#define MITRE_T1606              0x0646      // Forge Web Credentials
#define MITRE_T1606_001          0x064601    // Web Cookies
#define MITRE_T1606_002          0x064602    // SAML Tokens
#define MITRE_T1056              0x0410      // Input Capture
#define MITRE_T1056_001          0x041001    // Keylogging
#define MITRE_T1056_002          0x041002    // GUI Input Capture
#define MITRE_T1056_003          0x041003    // Web Portal Capture
#define MITRE_T1056_004          0x041004    // Credential API Hooking
#define MITRE_T1556_001          0x061401    // Domain Controller Authentication
#define MITRE_T1556_002          0x061402    // Password Filter DLL
#define MITRE_T1556_003          0x061403    // Pluggable Authentication Modules
#define MITRE_T1556_004          0x061404    // Network Device Authentication
#define MITRE_T1621              0x0655      // Multi-Factor Authentication Request Generation
#define MITRE_T1040              0x0400      // Network Sniffing
#define MITRE_T1003              0x03EB      // OS Credential Dumping
#define MITRE_T1003_001          0x03EB01    // LSASS Memory
#define MITRE_T1003_002          0x03EB02    // Security Account Manager
#define MITRE_T1003_003          0x03EB03    // NTDS
#define MITRE_T1003_004          0x03EB04    // LSA Secrets
#define MITRE_T1003_005          0x03EB05    // Cached Domain Credentials
#define MITRE_T1003_006          0x03EB06    // DCSync
#define MITRE_T1003_007          0x03EB07    // Proc Filesystem
#define MITRE_T1003_008          0x03EB08    // /etc/passwd and /etc/shadow
#define MITRE_T1528              0x05F8      // Steal Application Access Token
#define MITRE_T1558              0x0616      // Steal or Forge Kerberos Tickets
#define MITRE_T1558_001          0x061601    // Golden Ticket
#define MITRE_T1558_002          0x061602    // Silver Ticket
#define MITRE_T1558_003          0x061603    // Kerberoasting
#define MITRE_T1558_004          0x061604    // AS-REP Roasting
#define MITRE_T1539              0x05F3      // Steal Web Session Cookie
#define MITRE_T1111              0x044F      // Two-Factor Authentication Interception
#define MITRE_T1552              0x0610      // Unsecured Credentials
#define MITRE_T1552_001          0x061001    // Credentials In Files
#define MITRE_T1552_002          0x061002    // Credentials in Registry
#define MITRE_T1552_003          0x061003    // Bash History
#define MITRE_T1552_004          0x061004    // Private Keys
#define MITRE_T1552_006          0x061006    // Group Policy Preferences

// ---------------------------------------------------------------------
// Discovery (TA0007)
// ---------------------------------------------------------------------
#define MITRE_T1087              0x033F      // Account Discovery
#define MITRE_T1087_001          0x033F01    // Local Account
#define MITRE_T1087_002          0x033F02    // Domain Account
#define MITRE_T1087_003          0x033F03    // Email Account
#define MITRE_T1087_004          0x033F04    // Cloud Account
#define MITRE_T1010              0x03EA      // Application Window Discovery
#define MITRE_T1217              0x04C9      // Browser Information Discovery
#define MITRE_T1580              0x062C      // Cloud Infrastructure Discovery
#define MITRE_T1538              0x05F2      // Cloud Service Dashboard
#define MITRE_T1526              0x05F6      // Cloud Service Discovery
#define MITRE_T1613              0x064D      // Container and Resource Discovery
#define MITRE_T1482              0x05C2      // Domain Trust Discovery
#define MITRE_T1083              0x033B      // File and Directory Discovery
#define MITRE_T1615              0x064F      // Group Policy Discovery
#define MITRE_T1046              0x0406      // Network Service Discovery
#define MITRE_T1135              0x053F      // Network Share Discovery
#define MITRE_T1040_             0x0400      // Network Sniffing (also Credential Access)
#define MITRE_T1201              0x04B1      // Password Policy Discovery
#define MITRE_T1120              0x0478      // Peripheral Device Discovery
#define MITRE_T1069              0x0305      // Permission Groups Discovery
#define MITRE_T1069_001          0x030501    // Local Groups
#define MITRE_T1069_002          0x030502    // Domain Groups
#define MITRE_T1069_003          0x030503    // Cloud Groups
#define MITRE_T1057              0x0411      // Process Discovery
#define MITRE_T1012              0x03EC      // Query Registry
#define MITRE_T1018              0x03F2      // Remote System Discovery
#define MITRE_T1518              0x05EE      // Software Discovery
#define MITRE_T1518_001          0x05EE01    // Security Software Discovery
#define MITRE_T1082              0x033A      // System Information Discovery
#define MITRE_T1614              0x064E      // System Location Discovery
#define MITRE_T1016              0x03F0      // System Network Configuration Discovery
#define MITRE_T1049              0x0409      // System Network Connections Discovery
#define MITRE_T1033              0x03F9      // System Owner/User Discovery
#define MITRE_T1007              0x03E7      // System Service Discovery
#define MITRE_T1124              0x047C      // System Time Discovery
#define MITRE_T1497_             0x05D9      // Virtualization/Sandbox Evasion (also Defense Evasion)

// ---------------------------------------------------------------------
// Lateral Movement (TA0008)
// ---------------------------------------------------------------------
#define MITRE_T1210              0x04C2      // Exploitation of Remote Services
#define MITRE_T1534              0x05EE      // Internal Spearphishing
#define MITRE_T1570              0x0622      // Lateral Tool Transfer
#define MITRE_T1021              0x03F5      // Remote Services
#define MITRE_T1021_001          0x03F501    // Remote Desktop Protocol
#define MITRE_T1021_002          0x03F502    // SMB/Windows Admin Shares
#define MITRE_T1021_003          0x03F503    // Distributed Component Object Model
#define MITRE_T1021_004          0x03F504    // SSH
#define MITRE_T1021_005          0x03F505    // VNC
#define MITRE_T1021_006          0x03F506    // Windows Remote Management
#define MITRE_T1080              0x0310      // Taint Shared Content
#define MITRE_T1550_             0x060E      // Use Alternate Authentication Material (also Defense Evasion)

// ---------------------------------------------------------------------
// Collection (TA0009)
// ---------------------------------------------------------------------
#define MITRE_T1557_             0x0615      // Adversary-in-the-Middle (also Credential Access)
#define MITRE_T1560              0x0618      // Archive Collected Data
#define MITRE_T1560_001          0x061801    // Archive via Utility
#define MITRE_T1560_002          0x061802    // Archive via Library
#define MITRE_T1560_003          0x061803    // Archive via Custom Method
#define MITRE_T1123              0x047B      // Audio Capture
#define MITRE_T1119              0x0477      // Automated Collection
#define MITRE_T1185              0x04A1      // Browser Session Hijacking
#define MITRE_T1115              0x0453      // Clipboard Data
#define MITRE_T1530              0x05FA      // Data from Cloud Storage
#define MITRE_T1602              0x0642      // Data from Configuration Repository
#define MITRE_T1213              0x04C5      // Data from Information Repositories
#define MITRE_T1213_001          0x04C501    // Confluence
#define MITRE_T1213_002          0x04C502    // Sharepoint
#define MITRE_T1213_003          0x04C503    // Code Repositories
#define MITRE_T1005              0x03E5      // Data from Local System
#define MITRE_T1039              0x03FF      // Data from Network Shared Drive
#define MITRE_T1025              0x03F9      // Data from Removable Media
#define MITRE_T1074              0x030A      // Data Staged
#define MITRE_T1074_001          0x030A01    // Local Data Staging
#define MITRE_T1074_002          0x030A02    // Remote Data Staging
#define MITRE_T1114              0x0452      // Email Collection
#define MITRE_T1114_001          0x045201    // Local Email Collection
#define MITRE_T1114_002          0x045202    // Remote Email Collection
#define MITRE_T1114_003          0x045203    // Email Forwarding Rule
#define MITRE_T1056_             0x0410      // Input Capture (also Credential Access)
#define MITRE_T1113              0x0451      // Screen Capture
#define MITRE_T1125              0x047D      // Video Capture

// ---------------------------------------------------------------------
// Command and Control (TA0011)
// ---------------------------------------------------------------------
#define MITRE_T1071              0x0307      // Application Layer Protocol
#define MITRE_T1071_001          0x030701    // Web Protocols
#define MITRE_T1071_002          0x030702    // File Transfer Protocols
#define MITRE_T1071_003          0x030703    // Mail Protocols
#define MITRE_T1071_004          0x030704    // DNS
#define MITRE_T1092              0x035C      // Communication Through Removable Media
#define MITRE_T1132              0x0534      // Data Encoding
#define MITRE_T1132_001          0x053401    // Standard Encoding
#define MITRE_T1132_002          0x053402    // Non-Standard Encoding
#define MITRE_T1001              0x03E9      // Data Obfuscation
#define MITRE_T1001_001          0x03E901    // Junk Data
#define MITRE_T1001_002          0x03E902    // Steganography
#define MITRE_T1001_003          0x03E903    // Protocol Impersonation
#define MITRE_T1568              0x0620      // Dynamic Resolution
#define MITRE_T1568_001          0x062001    // Fast Flux DNS
#define MITRE_T1568_002          0x062002    // Domain Generation Algorithms
#define MITRE_T1568_003          0x062003    // DNS Calculation
#define MITRE_T1573              0x0625      // Encrypted Channel
#define MITRE_T1573_001          0x062501    // Symmetric Cryptography
#define MITRE_T1573_002          0x062502    // Asymmetric Cryptography
#define MITRE_T1008              0x03E8      // Fallback Channels
#define MITRE_T1105              0x0449      // Ingress Tool Transfer
#define MITRE_T1104              0x0448      // Multi-Stage Channels
#define MITRE_T1095              0x0357      // Non-Application Layer Protocol
#define MITRE_T1571              0x0623      // Non-Standard Port
#define MITRE_T1572              0x0624      // Protocol Tunneling
#define MITRE_T1090              0x035A      // Proxy
#define MITRE_T1090_001          0x035A01    // Internal Proxy
#define MITRE_T1090_002          0x035A02    // External Proxy
#define MITRE_T1090_003          0x035A03    // Multi-hop Proxy
#define MITRE_T1090_004          0x035A04    // Domain Fronting
#define MITRE_T1219              0x04CB      // Remote Access Software
#define MITRE_T1205_             0x04B5      // Traffic Signaling (also Defense Evasion)
#define MITRE_T1102              0x03FE      // Web Service
#define MITRE_T1102_001          0x03FE01    // Dead Drop Resolver
#define MITRE_T1102_002          0x03FE02    // Bidirectional Communication
#define MITRE_T1102_003          0x03FE03    // One-Way Communication

// ---------------------------------------------------------------------
// Exfiltration (TA0010)
// ---------------------------------------------------------------------
#define MITRE_T1020              0x03F4      // Automated Exfiltration
#define MITRE_T1020_001          0x03F401    // Traffic Duplication
#define MITRE_T1030              0x03F6      // Data Transfer Size Limits
#define MITRE_T1048              0x0408      // Exfiltration Over Alternative Protocol
#define MITRE_T1048_001          0x040801    // Exfiltration Over Symmetric Encrypted Non-C2 Protocol
#define MITRE_T1048_002          0x040802    // Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
#define MITRE_T1048_003          0x040803    // Exfiltration Over Unencrypted Non-C2 Protocol
#define MITRE_T1041              0x0401      // Exfiltration Over C2 Channel
#define MITRE_T1011              0x03EB      // Exfiltration Over Other Network Medium
#define MITRE_T1011_001          0x03EB01    // Exfiltration Over Bluetooth
#define MITRE_T1052              0x040C      // Exfiltration Over Physical Medium
#define MITRE_T1052_001          0x040C01    // Exfiltration over USB
#define MITRE_T1567              0x061F      // Exfiltration Over Web Service
#define MITRE_T1567_001          0x061F01    // Exfiltration to Code Repository
#define MITRE_T1567_002          0x061F02    // Exfiltration to Cloud Storage
#define MITRE_T1029              0x03F5      // Scheduled Transfer
#define MITRE_T1537              0x05F1      // Transfer Data to Cloud Account

// ---------------------------------------------------------------------
// Impact (TA0040)
// ---------------------------------------------------------------------
#define MITRE_T1531              0x05FB      // Account Access Removal
#define MITRE_T1485              0x05C5      // Data Destruction
#define MITRE_T1486              0x05C6      // Data Encrypted for Impact (Ransomware)
#define MITRE_T1565              0x061D      // Data Manipulation
#define MITRE_T1565_001          0x061D01    // Stored Data Manipulation
#define MITRE_T1565_002          0x061D02    // Transmitted Data Manipulation
#define MITRE_T1565_003          0x061D03    // Runtime Data Manipulation
#define MITRE_T1491              0x05CB      // Defacement
#define MITRE_T1491_001          0x05CB01    // Internal Defacement
#define MITRE_T1491_002          0x05CB02    // External Defacement
#define MITRE_T1561              0x0619      // Disk Wipe
#define MITRE_T1561_001          0x061901    // Disk Content Wipe
#define MITRE_T1561_002          0x061902    // Disk Structure Wipe
#define MITRE_T1499              0x05DB      // Endpoint Denial of Service
#define MITRE_T1499_001          0x05DB01    // OS Exhaustion Flood
#define MITRE_T1499_002          0x05DB02    // Service Exhaustion Flood
#define MITRE_T1499_003          0x05DB03    // Application Exhaustion Flood
#define MITRE_T1499_004          0x05DB04    // Application or System Exploitation
#define MITRE_T1495              0x05D7      // Firmware Corruption
#define MITRE_T1490              0x05CA      // Inhibit System Recovery
#define MITRE_T1498              0x05DA      // Network Denial of Service
#define MITRE_T1498_001          0x05DA01    // Direct Network Flood
#define MITRE_T1498_002          0x05DA02    // Reflection Amplification
#define MITRE_T1496              0x05D8      // Resource Hijacking (Cryptomining)
#define MITRE_T1489              0x05C9      // Service Stop
#define MITRE_T1529              0x05F9      // System Shutdown/Reboot

// ============================================================================
// ATTACK PATTERN STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief MITRE ATT&CK technique reference.
 */
typedef struct _MITRE_TECHNIQUE_REF {
    UINT32 TechniqueId;                   // MITRE_T* constant
    UINT32 SubTechniqueId;                // Sub-technique (0 if none)
    MITRE_TACTIC PrimaryTactic;
    UINT16 Reserved;
    WCHAR TechniqueName[64];              // Human-readable name
} MITRE_TECHNIQUE_REF, *PMITRE_TECHNIQUE_REF;

/**
 * @brief Detection rule with MITRE mapping.
 */
typedef struct _ATTACK_DETECTION_RULE {
    UINT32 RuleId;
    UINT32 Version;
    UINT32 Priority;                      // 0-100, higher = more important
    UINT32 Flags;
    
    // MITRE mapping
    MITRE_TECHNIQUE_REF Technique;
    MITRE_TACTIC Tactics[4];              // Can map to multiple tactics
    UINT32 TacticCount;
    
    // Detection criteria
    UINT32 ConditionCount;
    UINT32 RequiredConfidence;            // 0-100
    UINT32 ThreatScore;                   // Score when matched
    
    // Metadata
    WCHAR RuleName[64];
    WCHAR Description[256];
    WCHAR Author[64];
    UINT64 CreateTime;
    UINT64 ModifyTime;
    
    // Response
    UINT32 ResponseAction;                // ATTACK_RESPONSE_ACTION
    UINT32 Reserved;
} ATTACK_DETECTION_RULE, *PATTACK_DETECTION_RULE;

// Rule flags
#define RULE_FLAG_ENABLED                 0x00000001
#define RULE_FLAG_BLOCKING                0x00000002
#define RULE_FLAG_ALERTING                0x00000004
#define RULE_FLAG_TELEMETRY_ONLY          0x00000008
#define RULE_FLAG_HIGH_CONFIDENCE         0x00000010
#define RULE_FLAG_EXPERIMENTAL            0x00000020
#define RULE_FLAG_REQUIRES_CORRELATION    0x00000040
#define RULE_FLAG_KERNEL_ONLY             0x00000080
#define RULE_FLAG_USER_MODE_ONLY          0x00000100

// Response actions
typedef enum _ATTACK_RESPONSE_ACTION {
    AttackResponse_None = 0,
    AttackResponse_Allow,
    AttackResponse_Alert,
    AttackResponse_Block,
    AttackResponse_Terminate,
    AttackResponse_Quarantine,
    AttackResponse_Remediate,
    AttackResponse_Investigate,
    AttackResponse_Max
} ATTACK_RESPONSE_ACTION;

/**
 * @brief Attack pattern match result.
 */
typedef struct _ATTACK_MATCH_RESULT {
    UINT32 RuleId;
    UINT32 Confidence;                    // 0-100
    UINT32 ThreatScore;                   // 0-1000
    MITRE_TECHNIQUE_REF Technique;
    UINT64 MatchTime;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 MatchedConditions;
    UINT32 TotalConditions;
    ATTACK_RESPONSE_ACTION RecommendedAction;
    UINT32 Reserved;
    WCHAR MatchDetails[512];
} ATTACK_MATCH_RESULT, *PATTACK_MATCH_RESULT;

/**
 * @brief Known LOLBin (Living Off the Land Binary) entry.
 */
typedef struct _LOLBIN_ENTRY {
    WCHAR BinaryName[64];                 // e.g., "rundll32.exe"
    WCHAR BinaryPath[MAX_FILE_PATH_LENGTH];
    UINT32 MitreTechniques[8];            // Associated techniques
    UINT32 TechniqueCount;
    UINT32 Flags;
    UINT32 RiskScore;                     // Base risk score
    UINT32 Reserved;
    WCHAR Description[256];
} LOLBIN_ENTRY, *PLOLBIN_ENTRY;

// LOLBin flags
#define LOLBIN_FLAG_NETWORK_CAPABLE       0x00000001
#define LOLBIN_FLAG_EXECUTE_CODE          0x00000002
#define LOLBIN_FLAG_DOWNLOAD              0x00000004
#define LOLBIN_FLAG_SCRIPT_HOST           0x00000008
#define LOLBIN_FLAG_UAC_BYPASS            0x00000010
#define LOLBIN_FLAG_PROXY_EXECUTION       0x00000020
#define LOLBIN_FLAG_PERSISTENCE           0x00000040
#define LOLBIN_FLAG_CREDENTIAL_ACCESS     0x00000080

/**
 * @brief Attack chain (kill chain) tracking.
 */
typedef struct _ATTACK_CHAIN {
    UINT64 ChainId;                       // Unique chain identifier
    UINT64 StartTime;
    UINT64 LastUpdateTime;
    
    // Stage tracking
    UINT32 CurrentStage;                  // Current kill chain stage
    UINT32 StageFlags;                    // Bitmask of observed stages
    
    // Techniques observed
    UINT32 TechniqueIds[32];              // Observed techniques
    UINT32 TechniqueCount;
    
    // Tactics observed
    UINT32 TacticFlags;                   // Bitmask of observed tactics
    
    // Scoring
    UINT32 CumulativeThreatScore;         // 0-10000
    UINT32 Confidence;                    // 0-100
    UINT32 EventCount;
    
    // Primary actor
    UINT32 PrimaryProcessId;
    WCHAR PrimaryImagePath[MAX_FILE_PATH_LENGTH];
    
    UINT32 Flags;
    UINT32 Reserved;
} ATTACK_CHAIN, *PATTACK_CHAIN;

// Attack chain flags
#define CHAIN_FLAG_ACTIVE                 0x00000001
#define CHAIN_FLAG_BLOCKED                0x00000002
#define CHAIN_FLAG_REMEDIATED             0x00000004
#define CHAIN_FLAG_FALSE_POSITIVE         0x00000008
#define CHAIN_FLAG_CRITICAL               0x00000010
#define CHAIN_FLAG_APT_LIKELY             0x00000020
#define CHAIN_FLAG_RANSOMWARE_LIKELY      0x00000040
#define CHAIN_FLAG_COINMINER_LIKELY       0x00000080

#pragma pack(pop)

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Extract base technique ID from sub-technique.
 */
#define MITRE_BASE_TECHNIQUE(id) ((id) & 0xFFFF)

/**
 * @brief Extract sub-technique number.
 */
#define MITRE_SUB_TECHNIQUE(id) (((id) >> 16) & 0xFF)

/**
 * @brief Check if technique has sub-technique.
 */
#define MITRE_HAS_SUB_TECHNIQUE(id) (MITRE_SUB_TECHNIQUE(id) != 0)

/**
 * @brief Create technique ID from base and sub.
 */
#define MITRE_MAKE_TECHNIQUE(base, sub) (((sub) << 16) | (base))

/**
 * @brief Check if tactic is in tactic bitmask.
 */
#define TACTIC_IN_MASK(mask, tactic) (((mask) & (1 << (tactic))) != 0)

/**
 * @brief Set tactic in bitmask.
 */
#define TACTIC_SET(mask, tactic) ((mask) |= (1 << (tactic)))

#endif // SHADOWSTRIKE_ATTACK_PATTERNS_H
