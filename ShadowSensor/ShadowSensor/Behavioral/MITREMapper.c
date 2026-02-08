/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE MITRE ATT&CK MAPPER
 * ============================================================================
 *
 * @file MITREMapper.c
 * @brief Enterprise-grade MITRE ATT&CK framework mapping and detection tracking.
 *
 * Implements CrowdStrike Falcon-class MITRE ATT&CK integration with:
 * - Complete technique and tactic database
 * - O(1) technique lookup via hash table
 * - Reference-counted objects for safe lifetime management
 * - Detection recording with temporal tracking
 * - Tactic-based technique queries
 * - Thread-safe operations with proper IRQL handling
 *
 * CRITICAL FIXES APPLIED:
 * - IRQL annotations corrected (push locks require <= APC_LEVEL)
 * - Reference counting on techniques/detections prevents use-after-free
 * - Race condition in eviction loop fixed (collect-then-free pattern)
 * - Integer overflow protection in process name copy
 * - NULL buffer validation for UNICODE_STRING
 * - Proper rollback on partial load failure
 * - O(1) hash table lookup implemented
 * - Kernel-safe string comparison
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "MITREMapper.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MmInitialize)
#pragma alloc_text(PAGE, MmShutdown)
#pragma alloc_text(PAGE, MmLoadTechniques)
#pragma alloc_text(PAGE, MmLookupTechnique)
#pragma alloc_text(PAGE, MmLookupByName)
#pragma alloc_text(PAGE, MmGetTechniquesByTactic)
#endif

// ============================================================================
// TACTIC DEFINITIONS
// ============================================================================

typedef struct _MM_TACTIC_DEF {
    PCSTR Id;
    PCSTR Name;
    PCSTR Description;
    MITRE_TACTIC TacticEnum;
} MM_TACTIC_DEF;

static const MM_TACTIC_DEF g_TacticDefinitions[] = {
    { "TA0043", "Reconnaissance", "Gather information to plan future operations", Tactic_Reconnaissance },
    { "TA0042", "Resource Development", "Establish resources to support operations", Tactic_ResourceDevelopment },
    { "TA0001", "Initial Access", "Gain initial foothold within a network", Tactic_InitialAccess },
    { "TA0002", "Execution", "Run malicious code", Tactic_Execution },
    { "TA0003", "Persistence", "Maintain presence in the environment", Tactic_Persistence },
    { "TA0004", "Privilege Escalation", "Gain higher-level permissions", Tactic_PrivilegeEscalation },
    { "TA0005", "Defense Evasion", "Avoid detection", Tactic_DefenseEvasion },
    { "TA0006", "Credential Access", "Steal account credentials", Tactic_CredentialAccess },
    { "TA0007", "Discovery", "Explore the environment", Tactic_Discovery },
    { "TA0008", "Lateral Movement", "Move through the environment", Tactic_LateralMovement },
    { "TA0009", "Collection", "Gather data of interest", Tactic_Collection },
    { "TA0011", "Command and Control", "Communicate with compromised systems", Tactic_CommandAndControl },
    { "TA0010", "Exfiltration", "Steal data", Tactic_Exfiltration },
    { "TA0040", "Impact", "Manipulate, interrupt, or destroy systems", Tactic_Impact },
    { NULL, NULL, NULL, Tactic_None }
};

// ============================================================================
// TECHNIQUE DEFINITIONS
// ============================================================================

typedef struct _MM_TECHNIQUE_DEF {
    ULONG TechniqueId;
    PCSTR StringId;
    PCSTR Name;
    PCSTR Description;
    MITRE_TACTIC Tactic;
    ULONG DetectionScore;
    BOOLEAN CanBeDetected;
    ULONG ParentTechnique;
} MM_TECHNIQUE_DEF;

/**
 * @brief Core technique database - Windows-focused techniques
 */
static const MM_TECHNIQUE_DEF g_TechniqueDefinitions[] = {
    //
    // Initial Access (TA0001)
    //
    { MITRE_T1566, "T1566", "Phishing", "Adversaries send phishing messages to gain access", Tactic_InitialAccess, 70, TRUE, 0 },
    { MITRE_T1566_001, "T1566.001", "Spearphishing Attachment", "Phishing with malicious attachment", Tactic_InitialAccess, 80, TRUE, MITRE_T1566 },
    { MITRE_T1566_002, "T1566.002", "Spearphishing Link", "Phishing with malicious link", Tactic_InitialAccess, 75, TRUE, MITRE_T1566 },
    { MITRE_T1189, "T1189", "Drive-by Compromise", "Adversary gains access via web exploit", Tactic_InitialAccess, 65, TRUE, 0 },
    { MITRE_T1190, "T1190", "Exploit Public-Facing Application", "Exploit vulnerability in public app", Tactic_InitialAccess, 70, TRUE, 0 },
    { MITRE_T1133, "T1133", "External Remote Services", "Use legitimate remote services", Tactic_InitialAccess, 50, TRUE, 0 },
    { MITRE_T1091, "T1091", "Replication Through Removable Media", "Spread via USB drives", Tactic_InitialAccess, 60, TRUE, 0 },
    { MITRE_T1078, "T1078", "Valid Accounts", "Use legitimate credentials", Tactic_InitialAccess, 40, TRUE, 0 },
    { MITRE_T1078_001, "T1078.001", "Default Accounts", "Use default credentials", Tactic_InitialAccess, 55, TRUE, MITRE_T1078 },
    { MITRE_T1078_002, "T1078.002", "Domain Accounts", "Use domain credentials", Tactic_InitialAccess, 45, TRUE, MITRE_T1078 },
    { MITRE_T1078_003, "T1078.003", "Local Accounts", "Use local credentials", Tactic_InitialAccess, 45, TRUE, MITRE_T1078 },

    //
    // Execution (TA0002)
    //
    { MITRE_T1059, "T1059", "Command and Scripting Interpreter", "Execute commands/scripts", Tactic_Execution, 75, TRUE, 0 },
    { MITRE_T1059_001, "T1059.001", "PowerShell", "Execute PowerShell commands", Tactic_Execution, 85, TRUE, MITRE_T1059 },
    { MITRE_T1059_003, "T1059.003", "Windows Command Shell", "Execute cmd.exe commands", Tactic_Execution, 80, TRUE, MITRE_T1059 },
    { MITRE_T1059_005, "T1059.005", "Visual Basic", "Execute VBScript", Tactic_Execution, 75, TRUE, MITRE_T1059 },
    { MITRE_T1059_007, "T1059.007", "JavaScript", "Execute JavaScript", Tactic_Execution, 70, TRUE, MITRE_T1059 },
    { MITRE_T1106, "T1106", "Native API", "Use Windows API directly", Tactic_Execution, 60, TRUE, 0 },
    { MITRE_T1053, "T1053", "Scheduled Task/Job", "Execute via scheduled task", Tactic_Execution, 70, TRUE, 0 },
    { MITRE_T1053_005, "T1053.005", "Scheduled Task", "Windows Task Scheduler", Tactic_Execution, 75, TRUE, MITRE_T1053 },
    { MITRE_T1047, "T1047", "Windows Management Instrumentation", "Execute via WMI", Tactic_Execution, 80, TRUE, 0 },
    { MITRE_T1204, "T1204", "User Execution", "Rely on user to execute", Tactic_Execution, 55, TRUE, 0 },
    { MITRE_T1204_002, "T1204.002", "Malicious File", "User executes malicious file", Tactic_Execution, 65, TRUE, MITRE_T1204 },
    { MITRE_T1569, "T1569", "System Services", "Execute via system services", Tactic_Execution, 70, TRUE, 0 },
    { MITRE_T1569_002, "T1569.002", "Service Execution", "Execute via Windows service", Tactic_Execution, 75, TRUE, MITRE_T1569 },

    //
    // Persistence (TA0003)
    //
    { MITRE_T1547, "T1547", "Boot or Logon Autostart Execution", "Persist via autostart", Tactic_Persistence, 85, TRUE, 0 },
    { MITRE_T1547_001, "T1547.001", "Registry Run Keys / Startup Folder", "Registry run keys", Tactic_Persistence, 90, TRUE, MITRE_T1547 },
    { MITRE_T1547_004, "T1547.004", "Winlogon Helper DLL", "Winlogon persistence", Tactic_Persistence, 85, TRUE, MITRE_T1547 },
    { MITRE_T1547_005, "T1547.005", "Security Support Provider", "SSP persistence", Tactic_Persistence, 80, TRUE, MITRE_T1547 },
    { MITRE_T1547_009, "T1547.009", "Shortcut Modification", "Modify shortcuts", Tactic_Persistence, 70, TRUE, MITRE_T1547 },
    { MITRE_T1543, "T1543", "Create or Modify System Process", "Service persistence", Tactic_Persistence, 80, TRUE, 0 },
    { MITRE_T1543_003, "T1543.003", "Windows Service", "Create malicious service", Tactic_Persistence, 85, TRUE, MITRE_T1543 },
    { MITRE_T1546, "T1546", "Event Triggered Execution", "Event-based persistence", Tactic_Persistence, 75, TRUE, 0 },
    { MITRE_T1546_001, "T1546.001", "Change Default File Association", "File association hijack", Tactic_Persistence, 70, TRUE, MITRE_T1546 },
    { MITRE_T1546_008, "T1546.008", "Accessibility Features", "Accessibility binary replacement", Tactic_Persistence, 80, TRUE, MITRE_T1546 },
    { MITRE_T1546_010, "T1546.010", "AppInit DLLs", "AppInit_DLLs persistence", Tactic_Persistence, 85, TRUE, MITRE_T1546 },
    { MITRE_T1546_011, "T1546.011", "Application Shimming", "Shim database persistence", Tactic_Persistence, 75, TRUE, MITRE_T1546 },
    { MITRE_T1546_012, "T1546.012", "Image File Execution Options Injection", "IFEO debugger", Tactic_Persistence, 85, TRUE, MITRE_T1546 },
    { MITRE_T1546_015, "T1546.015", "Component Object Model Hijacking", "COM hijacking", Tactic_Persistence, 80, TRUE, MITRE_T1546 },
    { MITRE_T1574, "T1574", "Hijack Execution Flow", "DLL hijacking", Tactic_Persistence, 80, TRUE, 0 },
    { MITRE_T1574_001, "T1574.001", "DLL Search Order Hijacking", "DLL search order abuse", Tactic_Persistence, 85, TRUE, MITRE_T1574 },
    { MITRE_T1574_002, "T1574.002", "DLL Side-Loading", "DLL side-loading", Tactic_Persistence, 80, TRUE, MITRE_T1574 },
    { MITRE_T1197, "T1197", "BITS Jobs", "BITS for persistence", Tactic_Persistence, 70, TRUE, 0 },
    { MITRE_T1505, "T1505", "Server Software Component", "Web shell persistence", Tactic_Persistence, 85, TRUE, 0 },
    { MITRE_T1505_003, "T1505.003", "Web Shell", "Install web shell", Tactic_Persistence, 90, TRUE, MITRE_T1505 },
    { MITRE_T1542, "T1542", "Pre-OS Boot", "Boot-level persistence", Tactic_Persistence, 90, TRUE, 0 },
    { MITRE_T1542_003, "T1542.003", "Bootkit", "Bootkit installation", Tactic_Persistence, 95, TRUE, MITRE_T1542 },

    //
    // Privilege Escalation (TA0004)
    //
    { MITRE_T1548, "T1548", "Abuse Elevation Control Mechanism", "Bypass elevation controls", Tactic_PrivilegeEscalation, 85, TRUE, 0 },
    { MITRE_T1548_002, "T1548.002", "Bypass User Account Control", "UAC bypass", Tactic_PrivilegeEscalation, 90, TRUE, MITRE_T1548 },
    { MITRE_T1134, "T1134", "Access Token Manipulation", "Token manipulation", Tactic_PrivilegeEscalation, 85, TRUE, 0 },
    { MITRE_T1134_001, "T1134.001", "Token Impersonation/Theft", "Steal/impersonate token", Tactic_PrivilegeEscalation, 90, TRUE, MITRE_T1134 },
    { MITRE_T1134_002, "T1134.002", "Create Process with Token", "Process with stolen token", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1134 },
    { MITRE_T1134_004, "T1134.004", "Parent PID Spoofing", "Spoof parent process", Tactic_PrivilegeEscalation, 80, TRUE, MITRE_T1134 },
    { MITRE_T1068, "T1068", "Exploitation for Privilege Escalation", "Kernel exploit", Tactic_PrivilegeEscalation, 95, TRUE, 0 },
    { MITRE_T1055, "T1055", "Process Injection", "Inject into process", Tactic_PrivilegeEscalation, 90, TRUE, 0 },
    { MITRE_T1055_001, "T1055.001", "Dynamic-link Library Injection", "DLL injection", Tactic_PrivilegeEscalation, 90, TRUE, MITRE_T1055 },
    { MITRE_T1055_002, "T1055.002", "Portable Executable Injection", "PE injection", Tactic_PrivilegeEscalation, 90, TRUE, MITRE_T1055 },
    { MITRE_T1055_003, "T1055.003", "Thread Execution Hijacking", "Thread hijacking", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1055 },
    { MITRE_T1055_004, "T1055.004", "Asynchronous Procedure Call", "APC injection", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1055 },
    { MITRE_T1055_012, "T1055.012", "Process Hollowing", "Process hollowing", Tactic_PrivilegeEscalation, 95, TRUE, MITRE_T1055 },
    { MITRE_T1055_013, "T1055.013", "Process Doppelganging", "Process doppelganging", Tactic_PrivilegeEscalation, 95, TRUE, MITRE_T1055 },

    //
    // Defense Evasion (TA0005)
    //
    { MITRE_T1140, "T1140", "Deobfuscate/Decode Files or Information", "Decode obfuscated content", Tactic_DefenseEvasion, 60, TRUE, 0 },
    { MITRE_T1562, "T1562", "Impair Defenses", "Disable security tools", Tactic_DefenseEvasion, 95, TRUE, 0 },
    { MITRE_T1562_001, "T1562.001", "Disable or Modify Tools", "Disable AV/EDR", Tactic_DefenseEvasion, 95, TRUE, MITRE_T1562 },
    { MITRE_T1562_002, "T1562.002", "Disable Windows Event Logging", "Disable logging", Tactic_DefenseEvasion, 90, TRUE, MITRE_T1562 },
    { MITRE_T1562_004, "T1562.004", "Disable or Modify System Firewall", "Disable firewall", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1562 },
    { MITRE_T1070, "T1070", "Indicator Removal", "Remove evidence", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1070_001, "T1070.001", "Clear Windows Event Logs", "Clear event logs", Tactic_DefenseEvasion, 90, TRUE, MITRE_T1070 },
    { MITRE_T1070_004, "T1070.004", "File Deletion", "Delete malicious files", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1070 },
    { MITRE_T1070_006, "T1070.006", "Timestomp", "Modify timestamps", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1070 },
    { MITRE_T1036, "T1036", "Masquerading", "Disguise malware", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1036_003, "T1036.003", "Rename System Utilities", "Rename system tools", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1036 },
    { MITRE_T1036_005, "T1036.005", "Match Legitimate Name or Location", "Legitimate name/path", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1036 },
    { MITRE_T1036_007, "T1036.007", "Double File Extension", "Double extension", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1036 },
    { MITRE_T1027, "T1027", "Obfuscated Files or Information", "Obfuscate payloads", Tactic_DefenseEvasion, 75, TRUE, 0 },
    { MITRE_T1027_002, "T1027.002", "Software Packing", "Packed malware", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1027 },
    { MITRE_T1027_005, "T1027.005", "Indicator Removal from Tools", "Strip IOCs", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1027 },
    { MITRE_T1112, "T1112", "Modify Registry", "Registry modification", Tactic_DefenseEvasion, 65, TRUE, 0 },
    { MITRE_T1218, "T1218", "System Binary Proxy Execution", "LOLBin execution", Tactic_DefenseEvasion, 85, TRUE, 0 },
    { MITRE_T1218_001, "T1218.001", "Compiled HTML File", "CHM execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1218 },
    { MITRE_T1218_005, "T1218.005", "Mshta", "Mshta.exe execution", Tactic_DefenseEvasion, 90, TRUE, MITRE_T1218 },
    { MITRE_T1218_010, "T1218.010", "Regsvr32", "Regsvr32 execution", Tactic_DefenseEvasion, 90, TRUE, MITRE_T1218 },
    { MITRE_T1218_011, "T1218.011", "Rundll32", "Rundll32 execution", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1218 },
    { MITRE_T1497, "T1497", "Virtualization/Sandbox Evasion", "VM/sandbox detection", Tactic_DefenseEvasion, 70, TRUE, 0 },
    { MITRE_T1497_001, "T1497.001", "System Checks", "VM artifact checks", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1497 },
    { MITRE_T1497_003, "T1497.003", "Time Based Evasion", "Sleep/timing evasion", Tactic_DefenseEvasion, 65, TRUE, MITRE_T1497 },
    { MITRE_T1014, "T1014", "Rootkit", "Kernel rootkit", Tactic_DefenseEvasion, 95, TRUE, 0 },
    { MITRE_T1620, "T1620", "Reflective Code Loading", "Reflective loading", Tactic_DefenseEvasion, 90, TRUE, 0 },

    //
    // Credential Access (TA0006)
    //
    { MITRE_T1003, "T1003", "OS Credential Dumping", "Dump credentials", Tactic_CredentialAccess, 95, TRUE, 0 },
    { MITRE_T1003_001, "T1003.001", "LSASS Memory", "Dump LSASS", Tactic_CredentialAccess, 98, TRUE, MITRE_T1003 },
    { MITRE_T1003_002, "T1003.002", "Security Account Manager", "SAM dump", Tactic_CredentialAccess, 95, TRUE, MITRE_T1003 },
    { MITRE_T1003_003, "T1003.003", "NTDS", "NTDS.dit extraction", Tactic_CredentialAccess, 95, TRUE, MITRE_T1003 },
    { MITRE_T1003_004, "T1003.004", "LSA Secrets", "LSA secrets dump", Tactic_CredentialAccess, 90, TRUE, MITRE_T1003 },
    { MITRE_T1003_006, "T1003.006", "DCSync", "DCSync attack", Tactic_CredentialAccess, 95, TRUE, MITRE_T1003 },
    { MITRE_T1555, "T1555", "Credentials from Password Stores", "Password store access", Tactic_CredentialAccess, 85, TRUE, 0 },
    { MITRE_T1555_003, "T1555.003", "Credentials from Web Browsers", "Browser credentials", Tactic_CredentialAccess, 85, TRUE, MITRE_T1555 },
    { MITRE_T1555_004, "T1555.004", "Windows Credential Manager", "Credential Manager", Tactic_CredentialAccess, 80, TRUE, MITRE_T1555 },
    { MITRE_T1056, "T1056", "Input Capture", "Keylogging/input capture", Tactic_CredentialAccess, 85, TRUE, 0 },
    { MITRE_T1056_001, "T1056.001", "Keylogging", "Keyboard logging", Tactic_CredentialAccess, 90, TRUE, MITRE_T1056 },
    { MITRE_T1558, "T1558", "Steal or Forge Kerberos Tickets", "Kerberos attacks", Tactic_CredentialAccess, 90, TRUE, 0 },
    { MITRE_T1558_001, "T1558.001", "Golden Ticket", "Golden ticket attack", Tactic_CredentialAccess, 95, TRUE, MITRE_T1558 },
    { MITRE_T1558_002, "T1558.002", "Silver Ticket", "Silver ticket attack", Tactic_CredentialAccess, 90, TRUE, MITRE_T1558 },
    { MITRE_T1558_003, "T1558.003", "Kerberoasting", "Kerberoasting", Tactic_CredentialAccess, 90, TRUE, MITRE_T1558 },
    { MITRE_T1110, "T1110", "Brute Force", "Password brute force", Tactic_CredentialAccess, 75, TRUE, 0 },
    { MITRE_T1110_003, "T1110.003", "Password Spraying", "Password spray attack", Tactic_CredentialAccess, 80, TRUE, MITRE_T1110 },
    { MITRE_T1557, "T1557", "Adversary-in-the-Middle", "MITM attacks", Tactic_CredentialAccess, 80, TRUE, 0 },

    //
    // Discovery (TA0007)
    //
    { MITRE_T1087, "T1087", "Account Discovery", "Enumerate accounts", Tactic_Discovery, 60, TRUE, 0 },
    { MITRE_T1087_001, "T1087.001", "Local Account", "Local account enum", Tactic_Discovery, 65, TRUE, MITRE_T1087 },
    { MITRE_T1087_002, "T1087.002", "Domain Account", "Domain account enum", Tactic_Discovery, 70, TRUE, MITRE_T1087 },
    { MITRE_T1083, "T1083", "File and Directory Discovery", "File enumeration", Tactic_Discovery, 50, TRUE, 0 },
    { MITRE_T1057, "T1057", "Process Discovery", "Process enumeration", Tactic_Discovery, 50, TRUE, 0 },
    { MITRE_T1082, "T1082", "System Information Discovery", "System info gathering", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1016, "T1016", "System Network Configuration Discovery", "Network config enum", Tactic_Discovery, 60, TRUE, 0 },
    { MITRE_T1018, "T1018", "Remote System Discovery", "Remote system enum", Tactic_Discovery, 70, TRUE, 0 },
    { MITRE_T1135, "T1135", "Network Share Discovery", "Share enumeration", Tactic_Discovery, 65, TRUE, 0 },
    { MITRE_T1069, "T1069", "Permission Groups Discovery", "Group enumeration", Tactic_Discovery, 60, TRUE, 0 },
    { MITRE_T1069_001, "T1069.001", "Local Groups", "Local group enum", Tactic_Discovery, 55, TRUE, MITRE_T1069 },
    { MITRE_T1069_002, "T1069.002", "Domain Groups", "Domain group enum", Tactic_Discovery, 65, TRUE, MITRE_T1069 },
    { MITRE_T1012, "T1012", "Query Registry", "Registry query", Tactic_Discovery, 45, TRUE, 0 },
    { MITRE_T1518, "T1518", "Software Discovery", "Software enumeration", Tactic_Discovery, 50, TRUE, 0 },
    { MITRE_T1518_001, "T1518.001", "Security Software Discovery", "AV/EDR detection", Tactic_Discovery, 75, TRUE, MITRE_T1518 },
    { MITRE_T1033, "T1033", "System Owner/User Discovery", "User enumeration", Tactic_Discovery, 50, TRUE, 0 },
    { MITRE_T1049, "T1049", "System Network Connections Discovery", "Connection enum", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1482, "T1482", "Domain Trust Discovery", "Trust enumeration", Tactic_Discovery, 70, TRUE, 0 },

    //
    // Lateral Movement (TA0008)
    //
    { MITRE_T1021, "T1021", "Remote Services", "Remote service abuse", Tactic_LateralMovement, 80, TRUE, 0 },
    { MITRE_T1021_001, "T1021.001", "Remote Desktop Protocol", "RDP lateral movement", Tactic_LateralMovement, 75, TRUE, MITRE_T1021 },
    { MITRE_T1021_002, "T1021.002", "SMB/Windows Admin Shares", "SMB lateral movement", Tactic_LateralMovement, 85, TRUE, MITRE_T1021 },
    { MITRE_T1021_003, "T1021.003", "Distributed Component Object Model", "DCOM lateral movement", Tactic_LateralMovement, 80, TRUE, MITRE_T1021 },
    { MITRE_T1021_006, "T1021.006", "Windows Remote Management", "WinRM lateral movement", Tactic_LateralMovement, 80, TRUE, MITRE_T1021 },
    { MITRE_T1210, "T1210", "Exploitation of Remote Services", "Remote exploit", Tactic_LateralMovement, 90, TRUE, 0 },
    { MITRE_T1570, "T1570", "Lateral Tool Transfer", "Tool copying", Tactic_LateralMovement, 70, TRUE, 0 },
    { MITRE_T1080, "T1080", "Taint Shared Content", "Poisoned share", Tactic_LateralMovement, 65, TRUE, 0 },
    { MITRE_T1550, "T1550", "Use Alternate Authentication Material", "PTH/PTT", Tactic_LateralMovement, 90, TRUE, 0 },
    { MITRE_T1550_002, "T1550.002", "Pass the Hash", "Pass the Hash attack", Tactic_LateralMovement, 95, TRUE, MITRE_T1550 },
    { MITRE_T1550_003, "T1550.003", "Pass the Ticket", "Pass the Ticket attack", Tactic_LateralMovement, 95, TRUE, MITRE_T1550 },

    //
    // Collection (TA0009)
    //
    { MITRE_T1560, "T1560", "Archive Collected Data", "Data archiving", Tactic_Collection, 70, TRUE, 0 },
    { MITRE_T1560_001, "T1560.001", "Archive via Utility", "Archive with 7z/rar", Tactic_Collection, 75, TRUE, MITRE_T1560 },
    { MITRE_T1005, "T1005", "Data from Local System", "Local data collection", Tactic_Collection, 60, TRUE, 0 },
    { MITRE_T1039, "T1039", "Data from Network Shared Drive", "Share data collection", Tactic_Collection, 65, TRUE, 0 },
    { MITRE_T1113, "T1113", "Screen Capture", "Screenshot capture", Tactic_Collection, 75, TRUE, 0 },
    { MITRE_T1115, "T1115", "Clipboard Data", "Clipboard monitoring", Tactic_Collection, 70, TRUE, 0 },
    { MITRE_T1114, "T1114", "Email Collection", "Email harvesting", Tactic_Collection, 80, TRUE, 0 },
    { MITRE_T1074, "T1074", "Data Staged", "Stage for exfil", Tactic_Collection, 70, TRUE, 0 },
    { MITRE_T1074_001, "T1074.001", "Local Data Staging", "Local staging", Tactic_Collection, 65, TRUE, MITRE_T1074 },
    { MITRE_T1119, "T1119", "Automated Collection", "Automated data collection", Tactic_Collection, 75, TRUE, 0 },
    { MITRE_T1125, "T1125", "Video Capture", "Webcam capture", Tactic_Collection, 80, TRUE, 0 },
    { MITRE_T1123, "T1123", "Audio Capture", "Microphone capture", Tactic_Collection, 80, TRUE, 0 },

    //
    // Command and Control (TA0011)
    //
    { MITRE_T1071, "T1071", "Application Layer Protocol", "C2 protocol", Tactic_CommandAndControl, 70, TRUE, 0 },
    { MITRE_T1071_001, "T1071.001", "Web Protocols", "HTTP/HTTPS C2", Tactic_CommandAndControl, 75, TRUE, MITRE_T1071 },
    { MITRE_T1071_004, "T1071.004", "DNS", "DNS C2", Tactic_CommandAndControl, 85, TRUE, MITRE_T1071 },
    { MITRE_T1573, "T1573", "Encrypted Channel", "Encrypted C2", Tactic_CommandAndControl, 65, TRUE, 0 },
    { MITRE_T1573_001, "T1573.001", "Symmetric Cryptography", "Symmetric encryption", Tactic_CommandAndControl, 60, TRUE, MITRE_T1573 },
    { MITRE_T1573_002, "T1573.002", "Asymmetric Cryptography", "Asymmetric encryption", Tactic_CommandAndControl, 65, TRUE, MITRE_T1573 },
    { MITRE_T1105, "T1105", "Ingress Tool Transfer", "Tool download", Tactic_CommandAndControl, 75, TRUE, 0 },
    { MITRE_T1571, "T1571", "Non-Standard Port", "Unusual port C2", Tactic_CommandAndControl, 70, TRUE, 0 },
    { MITRE_T1572, "T1572", "Protocol Tunneling", "C2 tunneling", Tactic_CommandAndControl, 80, TRUE, 0 },
    { MITRE_T1090, "T1090", "Proxy", "C2 proxy", Tactic_CommandAndControl, 70, TRUE, 0 },
    { MITRE_T1090_003, "T1090.003", "Multi-hop Proxy", "Multi-hop C2", Tactic_CommandAndControl, 80, TRUE, MITRE_T1090 },
    { MITRE_T1568, "T1568", "Dynamic Resolution", "Dynamic C2", Tactic_CommandAndControl, 85, TRUE, 0 },
    { MITRE_T1568_002, "T1568.002", "Domain Generation Algorithms", "DGA domains", Tactic_CommandAndControl, 90, TRUE, MITRE_T1568 },
    { MITRE_T1102, "T1102", "Web Service", "Legitimate web service C2", Tactic_CommandAndControl, 75, TRUE, 0 },
    { MITRE_T1219, "T1219", "Remote Access Software", "RAT tools", Tactic_CommandAndControl, 70, TRUE, 0 },

    //
    // Exfiltration (TA0010)
    //
    { MITRE_T1041, "T1041", "Exfiltration Over C2 Channel", "Exfil via C2", Tactic_Exfiltration, 75, TRUE, 0 },
    { MITRE_T1048, "T1048", "Exfiltration Over Alternative Protocol", "Alt protocol exfil", Tactic_Exfiltration, 80, TRUE, 0 },
    { MITRE_T1567, "T1567", "Exfiltration Over Web Service", "Cloud storage exfil", Tactic_Exfiltration, 75, TRUE, 0 },
    { MITRE_T1567_002, "T1567.002", "Exfiltration to Cloud Storage", "Cloud upload exfil", Tactic_Exfiltration, 80, TRUE, MITRE_T1567 },
    { MITRE_T1020, "T1020", "Automated Exfiltration", "Automated exfil", Tactic_Exfiltration, 80, TRUE, 0 },
    { MITRE_T1030, "T1030", "Data Transfer Size Limits", "Chunked exfil", Tactic_Exfiltration, 65, TRUE, 0 },
    { MITRE_T1052, "T1052", "Exfiltration Over Physical Medium", "Physical exfil", Tactic_Exfiltration, 60, TRUE, 0 },

    //
    // Impact (TA0040)
    //
    { MITRE_T1486, "T1486", "Data Encrypted for Impact", "Ransomware encryption", Tactic_Impact, 100, TRUE, 0 },
    { MITRE_T1485, "T1485", "Data Destruction", "Data wiping", Tactic_Impact, 100, TRUE, 0 },
    { MITRE_T1490, "T1490", "Inhibit System Recovery", "Disable recovery", Tactic_Impact, 95, TRUE, 0 },
    { MITRE_T1489, "T1489", "Service Stop", "Stop services", Tactic_Impact, 80, TRUE, 0 },
    { MITRE_T1561, "T1561", "Disk Wipe", "Disk destruction", Tactic_Impact, 100, TRUE, 0 },
    { MITRE_T1561_001, "T1561.001", "Disk Content Wipe", "Wipe disk content", Tactic_Impact, 100, TRUE, MITRE_T1561 },
    { MITRE_T1561_002, "T1561.002", "Disk Structure Wipe", "Wipe MBR/GPT", Tactic_Impact, 100, TRUE, MITRE_T1561 },
    { MITRE_T1496, "T1496", "Resource Hijacking", "Cryptomining", Tactic_Impact, 70, TRUE, 0 },
    { MITRE_T1531, "T1531", "Account Access Removal", "Account lockout", Tactic_Impact, 85, TRUE, 0 },
    { MITRE_T1529, "T1529", "System Shutdown/Reboot", "Force shutdown", Tactic_Impact, 75, TRUE, 0 },
    { MITRE_T1565, "T1565", "Data Manipulation", "Data tampering", Tactic_Impact, 85, TRUE, 0 },
    { MITRE_T1499, "T1499", "Endpoint Denial of Service", "Endpoint DoS", Tactic_Impact, 80, TRUE, 0 },

    //
    // End marker
    //
    { 0, NULL, NULL, NULL, Tactic_None, 0, FALSE, 0 }
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static PMM_TACTIC
MmpCreateTactic(
    _In_ PCSTR Id,
    _In_ PCSTR Name,
    _In_ PCSTR Description
    );

static VOID
MmpFreeTactic(
    _In_ PMM_TACTIC Tactic
    );

static PMM_TECHNIQUE
MmpCreateTechnique(
    _In_ const MM_TECHNIQUE_DEF* Def,
    _In_opt_ PMM_TACTIC Tactic
    );

static VOID
MmpFreeTechnique(
    _In_ PMM_TECHNIQUE Technique
    );

static PMM_DETECTION
MmpCreateDetection(
    _In_opt_ PMM_TECHNIQUE Technique,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG ConfidenceScore
    );

static VOID
MmpFreeDetection(
    _In_ PMM_DETECTION Detection
    );

static PMM_TACTIC
MmpFindTacticById(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR TacticId
    );

static PMM_TACTIC
MmpFindTacticByEnum(
    _In_ PMM_MAPPER Mapper,
    _In_ MITRE_TACTIC TacticEnum
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
MmpHashTechniqueId(
    _In_ ULONG TechniqueId
    );

static NTSTATUS
MmpAllocateHashTable(
    _In_ PMM_MAPPER Mapper
    );

static VOID
MmpFreeHashTable(
    _In_ PMM_MAPPER Mapper
    );

static VOID
MmpInsertTechniqueIntoHash(
    _In_ PMM_MAPPER Mapper,
    _In_ PMM_TECHNIQUE Technique
    );

_IRQL_requires_max_(APC_LEVEL)
static PMM_TECHNIQUE
MmpLookupTechniqueInHash(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId
    );

static BOOLEAN
MmpCompareStringsInsensitive(
    _In_ PCSTR String1,
    _In_ PCSTR String2
    );

static VOID
MmpCleanupPartialLoad(
    _In_ PMM_MAPPER Mapper
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the MITRE ATT&CK mapper.
 *
 * Allocates and initializes the mapper structure, hash table, and
 * synchronization primitives.
 *
 * @param Mapper   Receives initialized mapper handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MmInitialize(
    _Out_ PMM_MAPPER* Mapper
    )
{
    NTSTATUS status;
    PMM_MAPPER mapper = NULL;

    PAGED_CODE();

    if (Mapper == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Mapper = NULL;

    //
    // Allocate mapper structure from NonPagedPool (contains spin lock)
    //
    mapper = (PMM_MAPPER)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(MM_MAPPER),
        MM_POOL_TAG_MAPPER
    );

    if (mapper == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize lists
    //
    InitializeListHead(&mapper->TacticList);
    InitializeListHead(&mapper->TechniqueList);
    InitializeListHead(&mapper->DetectionList);

    //
    // Initialize locks
    //
    ExInitializePushLock(&mapper->TechniqueLock);
    KeInitializeSpinLock(&mapper->DetectionLock);

    //
    // Allocate hash table
    //
    status = MmpAllocateHashTable(mapper);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(mapper, MM_POOL_TAG_MAPPER);
        return status;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&mapper->Stats.StartTime);

    mapper->Initialized = TRUE;
    mapper->TechniquesLoaded = FALSE;
    *Mapper = mapper;

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the MITRE ATT&CK mapper.
 *
 * Safely frees all resources. Uses collect-then-free pattern to avoid
 * holding locks during deallocation.
 *
 * @param Mapper   Mapper to shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MmShutdown(
    _Inout_ PMM_MAPPER Mapper
    )
{
    LIST_ENTRY tempTactics;
    LIST_ENTRY tempTechniques;
    LIST_ENTRY tempDetections;
    PLIST_ENTRY listEntry;
    PMM_TACTIC tactic;
    PMM_TECHNIQUE technique;
    PMM_DETECTION detection;
    KIRQL oldIrql;

    PAGED_CODE();

    if (Mapper == NULL) {
        return;
    }

    if (!Mapper->Initialized) {
        return;
    }

    //
    // Mark as not initialized to prevent new operations
    //
    Mapper->Initialized = FALSE;
    Mapper->TechniquesLoaded = FALSE;

    //
    // Initialize temporary collection lists
    //
    InitializeListHead(&tempTactics);
    InitializeListHead(&tempTechniques);
    InitializeListHead(&tempDetections);

    //
    // Collect tactics and techniques under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Mapper->TechniqueLock);

    while (!IsListEmpty(&Mapper->TechniqueList)) {
        listEntry = RemoveHeadList(&Mapper->TechniqueList);
        InsertTailList(&tempTechniques, listEntry);
    }

    while (!IsListEmpty(&Mapper->TacticList)) {
        listEntry = RemoveHeadList(&Mapper->TacticList);
        InsertTailList(&tempTactics, listEntry);
    }

    Mapper->TacticCount = 0;
    Mapper->TechniqueCount = 0;

    ExReleasePushLockExclusive(&Mapper->TechniqueLock);
    KeLeaveCriticalRegion();

    //
    // Collect detections under spin lock
    //
    KeAcquireSpinLock(&Mapper->DetectionLock, &oldIrql);

    while (!IsListEmpty(&Mapper->DetectionList)) {
        listEntry = RemoveHeadList(&Mapper->DetectionList);
        InsertTailList(&tempDetections, listEntry);
    }

    Mapper->DetectionCount = 0;

    KeReleaseSpinLock(&Mapper->DetectionLock, oldIrql);

    //
    // Now free everything outside of locks
    // Free techniques first (they may hold tactic references conceptually,
    // though we use weak refs so order doesn't matter for correctness)
    //
    while (!IsListEmpty(&tempTechniques)) {
        listEntry = RemoveHeadList(&tempTechniques);
        technique = CONTAINING_RECORD(listEntry, MM_TECHNIQUE, ListEntry);
        //
        // Force release - we're shutting down
        //
        technique->RefCount = 0;
        MmpFreeTechnique(technique);
    }

    //
    // Free tactics
    //
    while (!IsListEmpty(&tempTactics)) {
        listEntry = RemoveHeadList(&tempTactics);
        tactic = CONTAINING_RECORD(listEntry, MM_TACTIC, ListEntry);
        tactic->RefCount = 0;
        MmpFreeTactic(tactic);
    }

    //
    // Free detections
    //
    while (!IsListEmpty(&tempDetections)) {
        listEntry = RemoveHeadList(&tempDetections);
        detection = CONTAINING_RECORD(listEntry, MM_DETECTION, ListEntry);
        detection->RefCount = 0;
        MmpFreeDetection(detection);
    }

    //
    // Free hash table
    //
    MmpFreeHashTable(Mapper);

    //
    // Free mapper structure
    //
    ExFreePoolWithTag(Mapper, MM_POOL_TAG_MAPPER);
}

// ============================================================================
// PUBLIC API - TECHNIQUE LOADING
// ============================================================================

/**
 * @brief Load MITRE ATT&CK technique database.
 *
 * Loads all tactics and techniques from the static database into the
 * mapper's data structures. Implements proper rollback on failure.
 *
 * @param Mapper   Mapper handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MmLoadTechniques(
    _In_ PMM_MAPPER Mapper
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG tacticIndex = 0;
    ULONG techniqueIndex = 0;
    PMM_TACTIC tactic;
    PMM_TECHNIQUE technique;

    PAGED_CODE();

    if (Mapper == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Mapper->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Mapper->TechniquesLoaded) {
        return STATUS_ALREADY_COMPLETE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Mapper->TechniqueLock);

    //
    // Load tactics first
    //
    for (tacticIndex = 0; g_TacticDefinitions[tacticIndex].Id != NULL; tacticIndex++) {
        tactic = MmpCreateTactic(
            g_TacticDefinitions[tacticIndex].Id,
            g_TacticDefinitions[tacticIndex].Name,
            g_TacticDefinitions[tacticIndex].Description
        );

        if (tactic == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        InsertTailList(&Mapper->TacticList, &tactic->ListEntry);
        Mapper->TacticCount++;
    }

    //
    // Load techniques
    //
    for (techniqueIndex = 0; g_TechniqueDefinitions[techniqueIndex].TechniqueId != 0; techniqueIndex++) {
        const MM_TECHNIQUE_DEF* def = &g_TechniqueDefinitions[techniqueIndex];

        //
        // Find parent tactic
        //
        tactic = MmpFindTacticByEnum(Mapper, def->Tactic);

        technique = MmpCreateTechnique(def, tactic);

        if (technique == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        //
        // Add to mapper's technique list
        //
        InsertTailList(&Mapper->TechniqueList, &technique->ListEntry);
        Mapper->TechniqueCount++;

        //
        // Add to hash table for O(1) lookup
        //
        MmpInsertTechniqueIntoHash(Mapper, technique);

        //
        // Add to tactic's technique list
        //
        if (tactic != NULL) {
            InsertTailList(&tactic->TechniqueList, &technique->TacticListEntry);
            tactic->TechniqueCount++;
        }

        InterlockedIncrement64(&Mapper->Stats.TechniquesLoaded);
    }

    Mapper->TechniquesLoaded = TRUE;

Cleanup:
    if (!NT_SUCCESS(status)) {
        //
        // Rollback: clean up any partially loaded data
        //
        MmpCleanupPartialLoad(Mapper);
    }

    ExReleasePushLockExclusive(&Mapper->TechniqueLock);
    KeLeaveCriticalRegion();

    return status;
}

// ============================================================================
// PUBLIC API - TECHNIQUE LOOKUP
// ============================================================================

/**
 * @brief Lookup technique by MITRE ID.
 *
 * Performs O(1) lookup via hash table. Returns a referenced pointer
 * that the caller MUST release via MmReleaseTechnique.
 *
 * @param Mapper      Mapper handle.
 * @param TechniqueId Technique ID (MITRE_T* constant).
 * @param Technique   Receives technique pointer (referenced).
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL (push lock requirement)
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmLookupTechnique(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId,
    _Out_ PMM_TECHNIQUE* Technique
    )
{
    PMM_TECHNIQUE found = NULL;

    PAGED_CODE();

    if (Mapper == NULL || Technique == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Technique = NULL;

    if (!Mapper->Initialized || !Mapper->TechniquesLoaded) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&Mapper->Stats.TechniqueLookups);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Mapper->TechniqueLock);

    //
    // O(1) hash lookup
    //
    found = MmpLookupTechniqueInHash(Mapper, TechniqueId);

    if (found != NULL) {
        //
        // Add reference for caller
        //
        InterlockedIncrement(&found->RefCount);
        InterlockedIncrement64(&Mapper->Stats.TechniqueHits);
    }

    ExReleasePushLockShared(&Mapper->TechniqueLock);
    KeLeaveCriticalRegion();

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Technique = found;
    return STATUS_SUCCESS;
}

/**
 * @brief Lookup technique by name.
 *
 * Searches by string ID (e.g., "T1059.001") or human-readable name
 * (e.g., "PowerShell"). Returns a referenced pointer.
 *
 * @param Mapper      Mapper handle.
 * @param Name        Technique name or string ID.
 * @param Technique   Receives technique pointer (referenced).
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL (push lock requirement)
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmLookupByName(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR Name,
    _Out_ PMM_TECHNIQUE* Technique
    )
{
    PLIST_ENTRY listEntry;
    PMM_TECHNIQUE technique;
    PMM_TECHNIQUE found = NULL;

    PAGED_CODE();

    if (Mapper == NULL || Name == NULL || Technique == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Technique = NULL;

    if (!Mapper->Initialized || !Mapper->TechniquesLoaded) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate name is not empty
    //
    if (Name[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&Mapper->Stats.TechniqueLookups);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Mapper->TechniqueLock);

    //
    // Linear search by name (no hash for name lookup)
    //
    for (listEntry = Mapper->TechniqueList.Flink;
         listEntry != &Mapper->TechniqueList;
         listEntry = listEntry->Flink) {

        technique = CONTAINING_RECORD(listEntry, MM_TECHNIQUE, ListEntry);

        //
        // Match by string ID (T1059.001) or by name (PowerShell)
        // Using kernel-safe case-insensitive comparison
        //
        if (MmpCompareStringsInsensitive(technique->StringId, Name) ||
            MmpCompareStringsInsensitive(technique->Name, Name)) {
            found = technique;
            break;
        }
    }

    if (found != NULL) {
        //
        // Add reference for caller
        //
        InterlockedIncrement(&found->RefCount);
        InterlockedIncrement64(&Mapper->Stats.TechniqueHits);
    }

    ExReleasePushLockShared(&Mapper->TechniqueLock);
    KeLeaveCriticalRegion();

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Technique = found;
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - REFERENCE MANAGEMENT
// ============================================================================

/**
 * @brief Add reference to a technique.
 *
 * @param Technique   Technique to reference.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReferenceTechnique(
    _In_ PMM_TECHNIQUE Technique
    )
{
    if (Technique != NULL) {
        InterlockedIncrement(&Technique->RefCount);
    }
}

/**
 * @brief Release reference to a technique.
 *
 * When reference count reaches zero, the technique is NOT freed
 * (it's owned by the mapper). This just tracks external references.
 *
 * @param Technique   Technique to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReleaseTechnique(
    _In_ PMM_TECHNIQUE Technique
    )
{
    if (Technique != NULL) {
        LONG newCount = InterlockedDecrement(&Technique->RefCount);
        //
        // Techniques are owned by the mapper and freed during shutdown.
        // RefCount going to 0 just means no external holders.
        // Assert that we don't go negative.
        //
        NT_ASSERT(newCount >= 0);
        UNREFERENCED_PARAMETER(newCount);
    }
}

/**
 * @brief Add reference to a detection.
 *
 * @param Detection   Detection to reference.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReferenceDetection(
    _In_ PMM_DETECTION Detection
    )
{
    if (Detection != NULL) {
        InterlockedIncrement(&Detection->RefCount);
    }
}

/**
 * @brief Release reference to a detection.
 *
 * @param Detection   Detection to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
MmReleaseDetection(
    _In_ PMM_DETECTION Detection
    )
{
    if (Detection != NULL) {
        LONG newCount = InterlockedDecrement(&Detection->RefCount);
        NT_ASSERT(newCount >= 0);
        UNREFERENCED_PARAMETER(newCount);
    }
}

// ============================================================================
// PUBLIC API - DETECTION RECORDING
// ============================================================================

/**
 * @brief Record a technique detection.
 *
 * Creates a detection record and adds it to the detection list.
 * Implements collect-then-free pattern for eviction to avoid race conditions.
 *
 * @param Mapper          Mapper handle.
 * @param TechniqueId     Technique ID detected.
 * @param ProcessId       Process that triggered detection.
 * @param ProcessName     Process name (optional).
 * @param ConfidenceScore Detection confidence (0-100).
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MmRecordDetection(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG ConfidenceScore
    )
{
    PMM_TECHNIQUE technique = NULL;
    PMM_DETECTION detection = NULL;
    LIST_ENTRY evictList;
    PLIST_ENTRY listEntry;
    PMM_DETECTION evictDetection;
    KIRQL oldIrql;
    ULONG evictCount = 0;

    if (Mapper == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Mapper->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Clamp confidence score
    //
    if (ConfidenceScore > 100) {
        ConfidenceScore = 100;
    }

    //
    // Initialize eviction list
    //
    InitializeListHead(&evictList);

    //
    // Try to lookup technique (at PASSIVE/APC level only)
    // If we're at DISPATCH, skip the lookup and record with NULL technique
    //
    if (KeGetCurrentIrql() <= APC_LEVEL && Mapper->TechniquesLoaded) {
        //
        // Ignore failure - we can still record detection with unknown technique
        //
        (VOID)MmLookupTechnique(Mapper, TechniqueId, &technique);
    }

    //
    // Create detection record (technique reference is transferred if non-NULL)
    //
    detection = MmpCreateDetection(technique, ProcessId, ProcessName, ConfidenceScore);
    if (detection == NULL) {
        if (technique != NULL) {
            MmReleaseTechnique(technique);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // If we got a technique reference, mark it as held by detection
    //
    if (technique != NULL) {
        detection->TechniqueRefHeld = TRUE;
    }

    //
    // Add to detection list with eviction
    // CRITICAL: Collect items to evict while holding lock, free after release
    //
    KeAcquireSpinLock(&Mapper->DetectionLock, &oldIrql);

    //
    // Collect items to evict (keep one slot for new detection)
    //
    while (Mapper->DetectionCount >= MM_MAX_DETECTIONS &&
           !IsListEmpty(&Mapper->DetectionList)) {
        listEntry = RemoveHeadList(&Mapper->DetectionList);
        InsertTailList(&evictList, listEntry);
        Mapper->DetectionCount--;
        evictCount++;
    }

    //
    // Add new detection
    //
    InsertTailList(&Mapper->DetectionList, &detection->ListEntry);
    InterlockedIncrement(&Mapper->DetectionCount);
    InterlockedIncrement64(&Mapper->Stats.DetectionsMade);

    KeReleaseSpinLock(&Mapper->DetectionLock, oldIrql);

    //
    // Now free evicted detections outside of lock
    //
    while (!IsListEmpty(&evictList)) {
        listEntry = RemoveHeadList(&evictList);
        evictDetection = CONTAINING_RECORD(listEntry, MM_DETECTION, ListEntry);
        InterlockedIncrement64(&Mapper->Stats.DetectionsEvicted);
        MmpFreeDetection(evictDetection);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API - QUERIES
// ============================================================================

/**
 * @brief Get all techniques for a specific tactic.
 *
 * Returns referenced technique pointers. Caller must release each
 * technique via MmReleaseTechnique.
 *
 * @param Mapper      Mapper handle.
 * @param TacticId    Tactic ID (e.g., "TA0002").
 * @param Techniques  Array to receive technique pointers.
 * @param Max         Maximum techniques to return.
 * @param Count       Receives actual count returned.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= APC_LEVEL (push lock requirement)
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
MmGetTechniquesByTactic(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR TacticId,
    _Out_writes_to_(Max, *Count) PMM_TECHNIQUE* Techniques,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PMM_TACTIC tactic;
    PLIST_ENTRY listEntry;
    PMM_TECHNIQUE technique;
    ULONG count = 0;

    PAGED_CODE();

    if (Mapper == NULL || TacticId == NULL || Techniques == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (Max == 0) {
        return STATUS_SUCCESS;
    }

    if (!Mapper->Initialized || !Mapper->TechniquesLoaded) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Mapper->TechniqueLock);

    //
    // Find tactic
    //
    tactic = MmpFindTacticById(Mapper, TacticId);
    if (tactic == NULL) {
        ExReleasePushLockShared(&Mapper->TechniqueLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Enumerate techniques in this tactic
    //
    for (listEntry = tactic->TechniqueList.Flink;
         listEntry != &tactic->TechniqueList && count < Max;
         listEntry = listEntry->Flink) {

        technique = CONTAINING_RECORD(listEntry, MM_TECHNIQUE, TacticListEntry);

        //
        // Add reference for caller
        //
        InterlockedIncrement(&technique->RefCount);
        Techniques[count++] = technique;
    }

    ExReleasePushLockShared(&Mapper->TechniqueLock);
    KeLeaveCriticalRegion();

    *Count = count;
    return STATUS_SUCCESS;
}

/**
 * @brief Get recent detections within a time window.
 *
 * Returns referenced detection pointers. Caller must release each
 * detection via MmReleaseDetection.
 *
 * @param Mapper        Mapper handle.
 * @param MaxAgeSeconds Maximum age in seconds (0 = all).
 * @param Detections    Array to receive detection pointers.
 * @param Max           Maximum detections to return.
 * @param Count         Receives actual count returned.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
MmGetRecentDetections(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG MaxAgeSeconds,
    _Out_writes_to_(Max, *Count) PMM_DETECTION* Detections,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
{
    PLIST_ENTRY listEntry;
    PMM_DETECTION detection;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER cutoffTime;
    ULONG count = 0;
    KIRQL oldIrql;

    if (Mapper == NULL || Detections == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    if (Max == 0) {
        return STATUS_SUCCESS;
    }

    if (!Mapper->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Calculate cutoff time (overflow-safe)
    //
    if (MaxAgeSeconds > 0) {
        LONGLONG ageIn100ns = (LONGLONG)MaxAgeSeconds * 10000000LL;
        if (currentTime.QuadPart > ageIn100ns) {
            cutoffTime.QuadPart = currentTime.QuadPart - ageIn100ns;
        } else {
            cutoffTime.QuadPart = 0;
        }
    } else {
        cutoffTime.QuadPart = 0;
    }

    KeAcquireSpinLock(&Mapper->DetectionLock, &oldIrql);

    //
    // Walk detection list from newest to oldest (tail to head)
    //
    for (listEntry = Mapper->DetectionList.Blink;
         listEntry != &Mapper->DetectionList && count < Max;
         listEntry = listEntry->Blink) {

        detection = CONTAINING_RECORD(listEntry, MM_DETECTION, ListEntry);

        //
        // Check if within time window
        //
        if (MaxAgeSeconds > 0 && detection->DetectionTime.QuadPart < cutoffTime.QuadPart) {
            //
            // Past cutoff - stop iterating (list is ordered by time)
            //
            break;
        }

        //
        // Add reference for caller
        //
        InterlockedIncrement(&detection->RefCount);
        Detections[count++] = detection;
    }

    KeReleaseSpinLock(&Mapper->DetectionLock, oldIrql);

    *Count = count;
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASH TABLE
// ============================================================================

/**
 * @brief Allocate hash table buckets.
 */
static NTSTATUS
MmpAllocateHashTable(
    _In_ PMM_MAPPER Mapper
    )
{
    ULONG i;
    SIZE_T size;

    size = MM_TECHNIQUE_HASH_BUCKETS * sizeof(MM_HASH_BUCKET);

    Mapper->HashTable = (PMM_HASH_BUCKET)ExAllocatePoolZero(
        NonPagedPoolNx,
        size,
        MM_POOL_TAG_HASH
    );

    if (Mapper->HashTable == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize all bucket list heads
    //
    for (i = 0; i < MM_TECHNIQUE_HASH_BUCKETS; i++) {
        InitializeListHead(&Mapper->HashTable[i].Head);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free hash table.
 */
static VOID
MmpFreeHashTable(
    _In_ PMM_MAPPER Mapper
    )
{
    if (Mapper->HashTable != NULL) {
        ExFreePoolWithTag(Mapper->HashTable, MM_POOL_TAG_HASH);
        Mapper->HashTable = NULL;
    }
}

/**
 * @brief Compute hash bucket index for technique ID.
 *
 * Uses a simple but effective mixing function.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static ULONG
MmpHashTechniqueId(
    _In_ ULONG TechniqueId
    )
{
    ULONG hash = TechniqueId;

    //
    // Simple multiplicative hash with mixing
    //
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;

    return hash % MM_TECHNIQUE_HASH_BUCKETS;
}

/**
 * @brief Insert technique into hash table.
 *
 * Must be called under TechniqueLock exclusive.
 */
static VOID
MmpInsertTechniqueIntoHash(
    _In_ PMM_MAPPER Mapper,
    _In_ PMM_TECHNIQUE Technique
    )
{
    ULONG bucket;

    if (Mapper->HashTable == NULL) {
        return;
    }

    bucket = MmpHashTechniqueId(Technique->Id);
    InsertTailList(&Mapper->HashTable[bucket].Head, &Technique->HashEntry);
}

/**
 * @brief Lookup technique in hash table by ID.
 *
 * Must be called under TechniqueLock shared or exclusive.
 */
_IRQL_requires_max_(APC_LEVEL)
static PMM_TECHNIQUE
MmpLookupTechniqueInHash(
    _In_ PMM_MAPPER Mapper,
    _In_ ULONG TechniqueId
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PMM_TECHNIQUE technique;

    if (Mapper->HashTable == NULL) {
        return NULL;
    }

    bucket = MmpHashTechniqueId(TechniqueId);

    for (listEntry = Mapper->HashTable[bucket].Head.Flink;
         listEntry != &Mapper->HashTable[bucket].Head;
         listEntry = listEntry->Flink) {

        technique = CONTAINING_RECORD(listEntry, MM_TECHNIQUE, HashEntry);

        if (technique->Id == TechniqueId) {
            return technique;
        }
    }

    return NULL;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - STRING COMPARISON
// ============================================================================

/**
 * @brief Case-insensitive ANSI string comparison.
 *
 * Kernel-safe implementation without CRT dependency.
 */
static BOOLEAN
MmpCompareStringsInsensitive(
    _In_ PCSTR String1,
    _In_ PCSTR String2
    )
{
    ANSI_STRING ansi1;
    ANSI_STRING ansi2;

    RtlInitAnsiString(&ansi1, String1);
    RtlInitAnsiString(&ansi2, String2);

    return RtlEqualString(&ansi1, &ansi2, TRUE);  // TRUE = case insensitive
}

// ============================================================================
// PRIVATE IMPLEMENTATION - ALLOCATION HELPERS
// ============================================================================

static PMM_TACTIC
MmpCreateTactic(
    _In_ PCSTR Id,
    _In_ PCSTR Name,
    _In_ PCSTR Description
    )
{
    PMM_TACTIC tactic;

    tactic = (PMM_TACTIC)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(MM_TACTIC),
        MM_POOL_TAG_TACTIC
    );

    if (tactic == NULL) {
        return NULL;
    }

    //
    // Initialize reference count (mapper holds initial reference)
    //
    tactic->RefCount = 1;

    //
    // Copy strings with bounds checking
    //
    if (Id != NULL) {
        RtlStringCchCopyA(tactic->Id, sizeof(tactic->Id), Id);
    }

    if (Name != NULL) {
        RtlStringCchCopyA(tactic->Name, sizeof(tactic->Name), Name);
    }

    if (Description != NULL) {
        RtlStringCchCopyA(tactic->Description, sizeof(tactic->Description), Description);
    }

    InitializeListHead(&tactic->TechniqueList);
    tactic->TechniqueCount = 0;

    return tactic;
}

static VOID
MmpFreeTactic(
    _In_ PMM_TACTIC Tactic
    )
{
    if (Tactic != NULL) {
        ExFreePoolWithTag(Tactic, MM_POOL_TAG_TACTIC);
    }
}

static PMM_TECHNIQUE
MmpCreateTechnique(
    _In_ const MM_TECHNIQUE_DEF* Def,
    _In_opt_ PMM_TACTIC Tactic
    )
{
    PMM_TECHNIQUE technique;

    if (Def == NULL) {
        return NULL;
    }

    technique = (PMM_TECHNIQUE)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(MM_TECHNIQUE),
        MM_POOL_TAG_TECHNIQUE
    );

    if (technique == NULL) {
        return NULL;
    }

    //
    // Initialize reference count (mapper holds initial reference)
    //
    technique->RefCount = 1;

    technique->Id = Def->TechniqueId;
    technique->Tactic = Tactic;  // Weak reference
    technique->DetectionScore = Def->DetectionScore;
    technique->CanBeDetected = Def->CanBeDetected;

    //
    // Check if sub-technique
    //
    if (Def->ParentTechnique != 0) {
        technique->IsSubTechnique = TRUE;
        technique->ParentTechniqueId = Def->ParentTechnique;
    } else {
        technique->IsSubTechnique = FALSE;
        technique->ParentTechniqueId = 0;
    }

    //
    // Copy strings with bounds checking
    //
    if (Def->StringId != NULL) {
        RtlStringCchCopyA(technique->StringId, sizeof(technique->StringId), Def->StringId);
    }

    if (Def->Name != NULL) {
        RtlStringCchCopyA(technique->Name, sizeof(technique->Name), Def->Name);
    }

    if (Def->Description != NULL) {
        RtlStringCchCopyA(technique->Description, sizeof(technique->Description), Def->Description);
    }

    InitializeListHead(&technique->SubTechniqueList);
    InitializeListHead(&technique->IndicatorList);

    return technique;
}

static VOID
MmpFreeTechnique(
    _In_ PMM_TECHNIQUE Technique
    )
{
    PLIST_ENTRY listEntry;
    PMM_BEHAVIORAL_INDICATOR indicator;

    if (Technique == NULL) {
        return;
    }

    //
    // Free indicators
    //
    while (!IsListEmpty(&Technique->IndicatorList)) {
        listEntry = RemoveHeadList(&Technique->IndicatorList);
        indicator = CONTAINING_RECORD(listEntry, MM_BEHAVIORAL_INDICATOR, ListEntry);
        ExFreePoolWithTag(indicator, MM_POOL_TAG_INDICATOR);
    }

    ExFreePoolWithTag(Technique, MM_POOL_TAG_TECHNIQUE);
}

static PMM_DETECTION
MmpCreateDetection(
    _In_opt_ PMM_TECHNIQUE Technique,
    _In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING ProcessName,
    _In_ ULONG ConfidenceScore
    )
{
    PMM_DETECTION detection;

    detection = (PMM_DETECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(MM_DETECTION),
        MM_POOL_TAG_DETECTION
    );

    if (detection == NULL) {
        return NULL;
    }

    //
    // Initialize reference count
    //
    detection->RefCount = 1;

    detection->Technique = Technique;
    detection->TechniqueRefHeld = FALSE;  // Caller sets this if ref transferred
    detection->ProcessId = ProcessId;
    detection->ConfidenceScore = ConfidenceScore;

    KeQuerySystemTime(&detection->DetectionTime);

    //
    // Copy process name if provided - with full validation
    //
    if (ProcessName != NULL &&
        ProcessName->Length > 0 &&
        ProcessName->Buffer != NULL) {

        USHORT nameLen = ProcessName->Length;
        USHORT maxLen;

        //
        // CRITICAL: Check for integer overflow before adding sizeof(WCHAR)
        //
        if (nameLen > (MAXUSHORT - sizeof(WCHAR))) {
            //
            // Truncate to prevent overflow
            //
            nameLen = MAXUSHORT - sizeof(WCHAR);
        }

        //
        // Also cap to reasonable maximum
        //
        if (nameLen > MM_MAX_PROCESS_NAME_LENGTH - sizeof(WCHAR)) {
            nameLen = MM_MAX_PROCESS_NAME_LENGTH - sizeof(WCHAR);
        }

        maxLen = nameLen + sizeof(WCHAR);

        detection->ProcessName.Buffer = (PWCH)ExAllocatePoolZero(
            NonPagedPoolNx,
            maxLen,
            MM_POOL_TAG_NAME
        );

        if (detection->ProcessName.Buffer != NULL) {
            //
            // Safe copy with validated length
            //
            RtlCopyMemory(detection->ProcessName.Buffer, ProcessName->Buffer, nameLen);
            detection->ProcessName.Length = nameLen;
            detection->ProcessName.MaximumLength = maxLen;
        }
        //
        // Allocation failure for name is non-fatal - detection still valid
        //
    }

    //
    // Set indicator counts from technique
    //
    if (Technique != NULL) {
        detection->IndicatorsRequired = 1;
        detection->IndicatorsMatched = 1;
    }

    return detection;
}

static VOID
MmpFreeDetection(
    _In_ PMM_DETECTION Detection
    )
{
    if (Detection == NULL) {
        return;
    }

    //
    // Release technique reference if we hold one
    //
    if (Detection->TechniqueRefHeld && Detection->Technique != NULL) {
        MmReleaseTechnique(Detection->Technique);
        Detection->Technique = NULL;
        Detection->TechniqueRefHeld = FALSE;
    }

    //
    // Free process name buffer
    //
    if (Detection->ProcessName.Buffer != NULL) {
        ExFreePoolWithTag(Detection->ProcessName.Buffer, MM_POOL_TAG_NAME);
        Detection->ProcessName.Buffer = NULL;
    }

    ExFreePoolWithTag(Detection, MM_POOL_TAG_DETECTION);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - LOOKUP HELPERS
// ============================================================================

static PMM_TACTIC
MmpFindTacticById(
    _In_ PMM_MAPPER Mapper,
    _In_ PCSTR TacticId
    )
{
    PLIST_ENTRY listEntry;
    PMM_TACTIC tactic;

    for (listEntry = Mapper->TacticList.Flink;
         listEntry != &Mapper->TacticList;
         listEntry = listEntry->Flink) {

        tactic = CONTAINING_RECORD(listEntry, MM_TACTIC, ListEntry);

        if (MmpCompareStringsInsensitive(tactic->Id, TacticId)) {
            return tactic;
        }
    }

    return NULL;
}

static PMM_TACTIC
MmpFindTacticByEnum(
    _In_ PMM_MAPPER Mapper,
    _In_ MITRE_TACTIC TacticEnum
    )
{
    ULONG i;

    //
    // Find the tactic definition that matches this enum
    //
    for (i = 0; g_TacticDefinitions[i].Id != NULL; i++) {
        if (g_TacticDefinitions[i].TacticEnum == TacticEnum) {
            return MmpFindTacticById(Mapper, g_TacticDefinitions[i].Id);
        }
    }

    return NULL;
}

/**
 * @brief Clean up partially loaded data on failure.
 *
 * Called under TechniqueLock exclusive.
 */
static VOID
MmpCleanupPartialLoad(
    _In_ PMM_MAPPER Mapper
    )
{
    PLIST_ENTRY listEntry;
    PMM_TECHNIQUE technique;
    PMM_TACTIC tactic;

    //
    // Free all techniques
    //
    while (!IsListEmpty(&Mapper->TechniqueList)) {
        listEntry = RemoveHeadList(&Mapper->TechniqueList);
        technique = CONTAINING_RECORD(listEntry, MM_TECHNIQUE, ListEntry);
        MmpFreeTechnique(technique);
    }
    Mapper->TechniqueCount = 0;

    //
    // Free all tactics
    //
    while (!IsListEmpty(&Mapper->TacticList)) {
        listEntry = RemoveHeadList(&Mapper->TacticList);
        tactic = CONTAINING_RECORD(listEntry, MM_TACTIC, ListEntry);
        MmpFreeTactic(tactic);
    }
    Mapper->TacticCount = 0;

    //
    // Re-initialize hash table buckets (buckets still allocated)
    //
    if (Mapper->HashTable != NULL) {
        ULONG i;
        for (i = 0; i < MM_TECHNIQUE_HASH_BUCKETS; i++) {
            InitializeListHead(&Mapper->HashTable[i].Head);
        }
    }

    //
    // Reset stats
    //
    Mapper->Stats.TechniquesLoaded = 0;
}
