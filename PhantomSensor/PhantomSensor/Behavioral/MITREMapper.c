/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE MITRE ATT&CK MAPPER
 * ============================================================================
 *
 * @file MITREMapper.c
 * @brief Enterprise-grade MITRE ATT&CK framework mapping and detection tracking.
 *
 * Implements Enterprise-grade MITRE ATT&CK integration with:
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

#pragma warning(push)
#pragma warning(disable: 4324) // structure was padded due to alignment specifier
#include "MITREMapper.h"
#pragma warning(pop)
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
    // Reconnaissance (TA0043)
    //
    { MITRE_T1595, "T1595", "Active Scanning", "Scan victim infrastructure to gather info", Tactic_Reconnaissance, 30, TRUE, 0 },
    { MITRE_T1595_001, "T1595.001", "Scanning IP Blocks", "Scan IP address blocks for hosts", Tactic_Reconnaissance, 25, TRUE, MITRE_T1595 },
    { MITRE_T1595_002, "T1595.002", "Vulnerability Scanning", "Scan for vulnerabilities", Tactic_Reconnaissance, 35, TRUE, MITRE_T1595 },
    { MITRE_T1595_003, "T1595.003", "Wordlist Scanning", "Brute-force discovery via wordlists", Tactic_Reconnaissance, 30, TRUE, MITRE_T1595 },
    { MITRE_T1592, "T1592", "Gather Victim Host Information", "Gather info about victim hosts", Tactic_Reconnaissance, 25, FALSE, 0 },
    { MITRE_T1592_001, "T1592.001", "Hardware", "Gather hardware info", Tactic_Reconnaissance, 20, FALSE, MITRE_T1592 },
    { MITRE_T1592_002, "T1592.002", "Software", "Gather software info", Tactic_Reconnaissance, 25, FALSE, MITRE_T1592 },
    { MITRE_T1592_003, "T1592.003", "Firmware", "Gather firmware versions", Tactic_Reconnaissance, 20, FALSE, MITRE_T1592 },
    { MITRE_T1592_004, "T1592.004", "Client Configurations", "Gather client configs", Tactic_Reconnaissance, 25, FALSE, MITRE_T1592 },
    { MITRE_T1589, "T1589", "Gather Victim Identity Information", "Gather identity info", Tactic_Reconnaissance, 20, FALSE, 0 },
    { MITRE_T1589_001, "T1589.001", "Credentials", "Gather credentials", Tactic_Reconnaissance, 30, FALSE, MITRE_T1589 },
    { MITRE_T1589_002, "T1589.002", "Email Addresses", "Gather email addresses", Tactic_Reconnaissance, 20, FALSE, MITRE_T1589 },
    { MITRE_T1589_003, "T1589.003", "Employee Names", "Gather employee names", Tactic_Reconnaissance, 15, FALSE, MITRE_T1589 },
    { MITRE_T1590, "T1590", "Gather Victim Network Information", "Gather network info", Tactic_Reconnaissance, 25, FALSE, 0 },
    { MITRE_T1590_001, "T1590.001", "Domain Properties", "Gather domain properties", Tactic_Reconnaissance, 20, FALSE, MITRE_T1590 },
    { MITRE_T1590_002, "T1590.002", "DNS", "Gather DNS records", Tactic_Reconnaissance, 30, TRUE, MITRE_T1590 },
    { MITRE_T1590_003, "T1590.003", "Network Trust Dependencies", "Map trust relationships", Tactic_Reconnaissance, 25, FALSE, MITRE_T1590 },
    { MITRE_T1590_004, "T1590.004", "Network Topology", "Map network topology", Tactic_Reconnaissance, 20, FALSE, MITRE_T1590 },
    { MITRE_T1590_005, "T1590.005", "IP Addresses", "Gather IP addresses", Tactic_Reconnaissance, 25, TRUE, MITRE_T1590 },
    { MITRE_T1590_006, "T1590.006", "Network Security Appliances", "Identify security appliances", Tactic_Reconnaissance, 30, FALSE, MITRE_T1590 },
    { MITRE_T1591, "T1591", "Gather Victim Org Information", "Gather organization info", Tactic_Reconnaissance, 15, FALSE, 0 },
    { MITRE_T1591_001, "T1591.001", "Determine Physical Locations", "Locate physical sites", Tactic_Reconnaissance, 10, FALSE, MITRE_T1591 },
    { MITRE_T1591_002, "T1591.002", "Business Relationships", "Map business relationships", Tactic_Reconnaissance, 15, FALSE, MITRE_T1591 },
    { MITRE_T1591_003, "T1591.003", "Identify Business Tempo", "Identify operational timing", Tactic_Reconnaissance, 10, FALSE, MITRE_T1591 },
    { MITRE_T1591_004, "T1591.004", "Identify Roles", "Identify key personnel roles", Tactic_Reconnaissance, 15, FALSE, MITRE_T1591 },
    { MITRE_T1593, "T1593", "Search Open Websites/Domains", "Search open web sources", Tactic_Reconnaissance, 20, FALSE, 0 },
    { MITRE_T1593_001, "T1593.001", "Social Media", "Search social media", Tactic_Reconnaissance, 15, FALSE, MITRE_T1593 },
    { MITRE_T1593_002, "T1593.002", "Search Engines", "Use search engines for recon", Tactic_Reconnaissance, 15, FALSE, MITRE_T1593 },
    { MITRE_T1593_003, "T1593.003", "Code Repositories", "Search code repositories", Tactic_Reconnaissance, 25, FALSE, MITRE_T1593 },
    { MITRE_T1594, "T1594", "Search Victim-Owned Websites", "Search victim websites", Tactic_Reconnaissance, 20, FALSE, 0 },
    { MITRE_T1596, "T1596", "Search Open Technical Databases", "Search technical databases", Tactic_Reconnaissance, 25, FALSE, 0 },
    { MITRE_T1596_001, "T1596.001", "DNS/Passive DNS", "Query DNS databases", Tactic_Reconnaissance, 30, TRUE, MITRE_T1596 },
    { MITRE_T1596_002, "T1596.002", "WHOIS", "Query WHOIS records", Tactic_Reconnaissance, 20, FALSE, MITRE_T1596 },
    { MITRE_T1596_003, "T1596.003", "Digital Certificates", "Search certificate databases", Tactic_Reconnaissance, 25, FALSE, MITRE_T1596 },
    { MITRE_T1596_004, "T1596.004", "CDNs", "Enumerate CDN infrastructure", Tactic_Reconnaissance, 20, FALSE, MITRE_T1596 },
    { MITRE_T1596_005, "T1596.005", "Scan Databases", "Search scan databases", Tactic_Reconnaissance, 25, FALSE, MITRE_T1596 },
    { MITRE_T1597, "T1597", "Search Closed Sources", "Search paid intelligence sources", Tactic_Reconnaissance, 20, FALSE, 0 },
    { MITRE_T1597_001, "T1597.001", "Threat Intel Vendors", "Purchase threat intel", Tactic_Reconnaissance, 25, FALSE, MITRE_T1597 },
    { MITRE_T1597_002, "T1597.002", "Purchase Technical Data", "Buy technical data", Tactic_Reconnaissance, 20, FALSE, MITRE_T1597 },
    { MITRE_T1598, "T1598", "Phishing for Information", "Phish to gather info", Tactic_Reconnaissance, 50, TRUE, 0 },
    { MITRE_T1598_001, "T1598.001", "Spearphishing Service", "Phish via third-party service", Tactic_Reconnaissance, 45, TRUE, MITRE_T1598 },
    { MITRE_T1598_002, "T1598.002", "Spearphishing Attachment", "Phish with info-gathering attachment", Tactic_Reconnaissance, 55, TRUE, MITRE_T1598 },
    { MITRE_T1598_003, "T1598.003", "Spearphishing Link", "Phish with info-gathering link", Tactic_Reconnaissance, 50, TRUE, MITRE_T1598 },
    { MITRE_T1681, "T1681", "Search Threat Vendor Data", "Search vendor threat data", Tactic_Reconnaissance, 20, FALSE, 0 },

    //
    // Resource Development (TA0042)
    //
    { MITRE_T1583, "T1583", "Acquire Infrastructure", "Acquire C2 infrastructure", Tactic_ResourceDevelopment, 30, FALSE, 0 },
    { MITRE_T1583_001, "T1583.001", "Domains", "Register domains", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1583 },
    { MITRE_T1583_002, "T1583.002", "DNS Server", "Set up DNS servers", Tactic_ResourceDevelopment, 30, TRUE, MITRE_T1583 },
    { MITRE_T1583_003, "T1583.003", "Virtual Private Server", "Rent VPS", Tactic_ResourceDevelopment, 25, FALSE, MITRE_T1583 },
    { MITRE_T1583_004, "T1583.004", "Server", "Purchase dedicated server", Tactic_ResourceDevelopment, 20, FALSE, MITRE_T1583 },
    { MITRE_T1583_005, "T1583.005", "Botnet", "Acquire botnet access", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1583 },
    { MITRE_T1583_006, "T1583.006", "Web Services", "Use legitimate web services", Tactic_ResourceDevelopment, 30, TRUE, MITRE_T1583 },
    { MITRE_T1584, "T1584", "Compromise Infrastructure", "Compromise third-party infra", Tactic_ResourceDevelopment, 35, FALSE, 0 },
    { MITRE_T1584_001, "T1584.001", "Domains", "Compromise domains", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1584 },
    { MITRE_T1584_002, "T1584.002", "DNS Server", "Compromise DNS servers", Tactic_ResourceDevelopment, 30, TRUE, MITRE_T1584 },
    { MITRE_T1584_003, "T1584.003", "Virtual Private Server", "Compromise VPS", Tactic_ResourceDevelopment, 25, FALSE, MITRE_T1584 },
    { MITRE_T1584_004, "T1584.004", "Server", "Compromise servers", Tactic_ResourceDevelopment, 30, FALSE, MITRE_T1584 },
    { MITRE_T1584_005, "T1584.005", "Botnet", "Compromise botnet", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1584 },
    { MITRE_T1584_006, "T1584.006", "Web Services", "Compromise web services", Tactic_ResourceDevelopment, 30, TRUE, MITRE_T1584 },
    { MITRE_T1584_008, "T1584.008", "Network Devices", "Compromise network devices", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1584 },
    { MITRE_T1585, "T1585", "Establish Accounts", "Create fake accounts", Tactic_ResourceDevelopment, 25, FALSE, 0 },
    { MITRE_T1585_001, "T1585.001", "Social Media Accounts", "Create social media accounts", Tactic_ResourceDevelopment, 20, FALSE, MITRE_T1585 },
    { MITRE_T1585_002, "T1585.002", "Email Accounts", "Create email accounts", Tactic_ResourceDevelopment, 25, FALSE, MITRE_T1585 },
    { MITRE_T1585_003, "T1585.003", "Cloud Accounts", "Create cloud accounts", Tactic_ResourceDevelopment, 30, FALSE, MITRE_T1585 },
    { MITRE_T1586, "T1586", "Compromise Accounts", "Compromise existing accounts", Tactic_ResourceDevelopment, 35, FALSE, 0 },
    { MITRE_T1586_001, "T1586.001", "Social Media Accounts", "Compromise social media", Tactic_ResourceDevelopment, 25, FALSE, MITRE_T1586 },
    { MITRE_T1586_002, "T1586.002", "Email Accounts", "Compromise email accounts", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1586 },
    { MITRE_T1586_003, "T1586.003", "Cloud Accounts", "Compromise cloud accounts", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1586 },
    { MITRE_T1587, "T1587", "Develop Capabilities", "Develop attack tools", Tactic_ResourceDevelopment, 30, FALSE, 0 },
    { MITRE_T1587_001, "T1587.001", "Malware", "Develop malware", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1587 },
    { MITRE_T1587_002, "T1587.002", "Code Signing Certificates", "Create code signing certs", Tactic_ResourceDevelopment, 45, TRUE, MITRE_T1587 },
    { MITRE_T1587_003, "T1587.003", "Digital Certificates", "Create digital certs", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1587 },
    { MITRE_T1587_004, "T1587.004", "Exploits", "Develop exploits", Tactic_ResourceDevelopment, 50, TRUE, MITRE_T1587 },
    { MITRE_T1588, "T1588", "Obtain Capabilities", "Acquire tools and malware", Tactic_ResourceDevelopment, 35, FALSE, 0 },
    { MITRE_T1588_001, "T1588.001", "Malware", "Obtain malware", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1588 },
    { MITRE_T1588_002, "T1588.002", "Tool", "Obtain hacking tools", Tactic_ResourceDevelopment, 45, TRUE, MITRE_T1588 },
    { MITRE_T1588_003, "T1588.003", "Code Signing Certificates", "Obtain code signing certs", Tactic_ResourceDevelopment, 50, TRUE, MITRE_T1588 },
    { MITRE_T1588_004, "T1588.004", "Digital Certificates", "Obtain digital certs", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1588 },
    { MITRE_T1588_005, "T1588.005", "Exploits", "Obtain exploits", Tactic_ResourceDevelopment, 50, TRUE, MITRE_T1588 },
    { MITRE_T1588_006, "T1588.006", "Vulnerabilities", "Obtain vulnerability info", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1588 },
    { MITRE_T1608, "T1608", "Stage Capabilities", "Stage tools for operations", Tactic_ResourceDevelopment, 35, FALSE, 0 },
    { MITRE_T1608_001, "T1608.001", "Upload Malware", "Upload malware to staging", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1608 },
    { MITRE_T1608_002, "T1608.002", "Upload Tool", "Upload tools to staging", Tactic_ResourceDevelopment, 35, TRUE, MITRE_T1608 },
    { MITRE_T1608_003, "T1608.003", "Install Digital Certificate", "Install certs on infra", Tactic_ResourceDevelopment, 30, FALSE, MITRE_T1608 },
    { MITRE_T1608_004, "T1608.004", "Drive-by Target", "Prepare drive-by staging", Tactic_ResourceDevelopment, 45, TRUE, MITRE_T1608 },
    { MITRE_T1608_005, "T1608.005", "Link Target", "Prepare phishing link targets", Tactic_ResourceDevelopment, 40, TRUE, MITRE_T1608 },
    { MITRE_T1608_006, "T1608.006", "SEO Poisoning", "SEO poisoning for delivery", Tactic_ResourceDevelopment, 45, TRUE, MITRE_T1608 },
    { MITRE_T1650, "T1650", "Acquire Access", "Purchase access from brokers", Tactic_ResourceDevelopment, 40, FALSE, 0 },
    { MITRE_T1672, "T1672", "Email Spoofing", "Spoof email for delivery", Tactic_ResourceDevelopment, 50, TRUE, 0 },

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
    { MITRE_T1566_003, "T1566.003", "Spearphishing via Service", "Phishing via third-party service", Tactic_InitialAccess, 70, TRUE, MITRE_T1566 },
    { MITRE_T1195, "T1195", "Supply Chain Compromise", "Compromise via supply chain", Tactic_InitialAccess, 80, TRUE, 0 },
    { MITRE_T1195_001, "T1195.001", "Compromise Software Dependencies", "Compromise software deps and tools", Tactic_InitialAccess, 85, TRUE, MITRE_T1195 },
    { MITRE_T1195_002, "T1195.002", "Compromise Software Supply Chain", "Compromise software supply chain", Tactic_InitialAccess, 90, TRUE, MITRE_T1195 },
    { MITRE_T1199, "T1199", "Trusted Relationship", "Abuse trusted third-party relationship", Tactic_InitialAccess, 60, TRUE, 0 },
    { MITRE_T1200, "T1200", "Hardware Additions", "Introduce rogue hardware", Tactic_InitialAccess, 55, TRUE, 0 },

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
    { MITRE_T1204_001, "T1204.001", "Malicious Link", "User clicks malicious link", Tactic_Execution, 60, TRUE, MITRE_T1204 },
    { MITRE_T1059_006, "T1059.006", "Python", "Execute Python scripts", Tactic_Execution, 70, TRUE, MITRE_T1059 },
    { MITRE_T1059_008, "T1059.008", "Network Device CLI", "Execute via network device CLI", Tactic_Execution, 65, TRUE, MITRE_T1059 },
    { MITRE_T1059_013, "T1059.013", "Container CLI/API", "Execute via container CLI/API", Tactic_Execution, 60, TRUE, MITRE_T1059 },
    { MITRE_T1203, "T1203", "Exploitation for Client Execution", "Exploit client application", Tactic_Execution, 80, TRUE, 0 },
    { MITRE_T1559, "T1559", "Inter-Process Communication", "Execute via IPC", Tactic_Execution, 70, TRUE, 0 },
    { MITRE_T1559_001, "T1559.001", "Component Object Model", "Execute via COM", Tactic_Execution, 75, TRUE, MITRE_T1559 },
    { MITRE_T1559_002, "T1559.002", "Dynamic Data Exchange", "Execute via DDE", Tactic_Execution, 80, TRUE, MITRE_T1559 },
    { MITRE_T1129, "T1129", "Shared Modules", "Execute via shared modules", Tactic_Execution, 55, TRUE, 0 },
    { MITRE_T1072, "T1072", "Software Deployment Tools", "Execute via deployment tools", Tactic_Execution, 65, TRUE, 0 },
    { MITRE_T1053_002, "T1053.002", "At", "Execute via at command", Tactic_Execution, 70, TRUE, MITRE_T1053 },
    { MITRE_T1204_005, "T1204.005", "Malicious Library", "User loads malicious library", Tactic_Execution, 75, TRUE, MITRE_T1204 },
    { MITRE_T1204_004, "T1204.004", "Malicious Copy and Paste", "User pastes malicious content", Tactic_Execution, 60, TRUE, MITRE_T1204 },

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
    { MITRE_T1098, "T1098", "Account Manipulation", "Manipulate accounts for persistence", Tactic_Persistence, 75, TRUE, 0 },
    { MITRE_T1037, "T1037", "Boot or Logon Initialization Scripts", "Logon script persistence", Tactic_Persistence, 75, TRUE, 0 },
    { MITRE_T1037_001, "T1037.001", "Logon Script (Windows)", "Windows logon script", Tactic_Persistence, 80, TRUE, MITRE_T1037 },
    { MITRE_T1547_002, "T1547.002", "Authentication Package", "Auth package persistence", Tactic_Persistence, 85, TRUE, MITRE_T1547 },
    { MITRE_T1547_003, "T1547.003", "Time Providers", "Time provider persistence", Tactic_Persistence, 80, TRUE, MITRE_T1547 },
    { MITRE_T1547_006, "T1547.006", "Kernel Modules and Extensions", "Kernel module persistence", Tactic_Persistence, 95, TRUE, MITRE_T1547 },
    { MITRE_T1547_008, "T1547.008", "LSASS Driver", "LSASS driver persistence", Tactic_Persistence, 90, TRUE, MITRE_T1547 },
    { MITRE_T1547_010, "T1547.010", "Port Monitors", "Port monitor persistence", Tactic_Persistence, 80, TRUE, MITRE_T1547 },
    { MITRE_T1547_012, "T1547.012", "Print Processors", "Print processor persistence", Tactic_Persistence, 80, TRUE, MITRE_T1547 },
    { MITRE_T1547_014, "T1547.014", "Active Setup", "Active Setup persistence", Tactic_Persistence, 75, TRUE, MITRE_T1547 },
    { MITRE_T1543_002, "T1543.002", "Systemd Service", "Systemd service persistence", Tactic_Persistence, 80, FALSE, MITRE_T1543 },
    { MITRE_T1546_002, "T1546.002", "Screensaver", "Screensaver persistence", Tactic_Persistence, 70, TRUE, MITRE_T1546 },
    { MITRE_T1546_003, "T1546.003", "WMI Event Subscription", "WMI event persistence", Tactic_Persistence, 85, TRUE, MITRE_T1546 },
    { MITRE_T1546_007, "T1546.007", "Netsh Helper DLL", "Netsh helper persistence", Tactic_Persistence, 80, TRUE, MITRE_T1546 },
    { MITRE_T1546_009, "T1546.009", "AppCert DLLs", "AppCert DLL persistence", Tactic_Persistence, 85, TRUE, MITRE_T1546 },
    { MITRE_T1546_013, "T1546.013", "PowerShell Profile", "PowerShell profile persistence", Tactic_Persistence, 75, TRUE, MITRE_T1546 },
    { MITRE_T1546_018, "T1546.018", "Python Startup Hooks", "Python startup persistence", Tactic_Persistence, 70, TRUE, MITRE_T1546 },
    { MITRE_T1574_007, "T1574.007", "Path Interception by PATH Environment Variable", "PATH env var hijack", Tactic_Persistence, 75, TRUE, MITRE_T1574 },
    { MITRE_T1574_008, "T1574.008", "Path Interception by Search Order Hijacking", "Search order path hijack", Tactic_Persistence, 80, TRUE, MITRE_T1574 },
    { MITRE_T1574_009, "T1574.009", "Path Interception by Unquoted Path", "Unquoted path hijack", Tactic_Persistence, 80, TRUE, MITRE_T1574 },
    { MITRE_T1574_010, "T1574.010", "Services File Permissions Weakness", "Weak service file perms", Tactic_Persistence, 85, TRUE, MITRE_T1574 },
    { MITRE_T1574_011, "T1574.011", "Services Registry Permissions Weakness", "Weak service reg perms", Tactic_Persistence, 85, TRUE, MITRE_T1574 },
    { MITRE_T1574_012, "T1574.012", "COR_PROFILER", "COR_PROFILER hijacking", Tactic_Persistence, 80, TRUE, MITRE_T1574 },
    { MITRE_T1556, "T1556", "Modify Authentication Process", "Modify auth process", Tactic_Persistence, 90, TRUE, 0 },
    { MITRE_T1556_001, "T1556.001", "Domain Controller Authentication", "Modify DC auth", Tactic_Persistence, 95, TRUE, MITRE_T1556 },
    { MITRE_T1556_002, "T1556.002", "Password Filter DLL", "Password filter DLL", Tactic_Persistence, 90, TRUE, MITRE_T1556 },
    { MITRE_T1556_003, "T1556.003", "Pluggable Authentication Modules", "PAM modification", Tactic_Persistence, 85, FALSE, MITRE_T1556 },
    { MITRE_T1556_004, "T1556.004", "Network Device Authentication", "Network device auth mod", Tactic_Persistence, 85, TRUE, MITRE_T1556 },
    { MITRE_T1137, "T1137", "Office Application Startup", "Office startup persistence", Tactic_Persistence, 75, TRUE, 0 },
    { MITRE_T1505_001, "T1505.001", "SQL Stored Procedures", "SQL stored proc persistence", Tactic_Persistence, 80, TRUE, MITRE_T1505 },
    { MITRE_T1542_001, "T1542.001", "System Firmware", "System firmware persistence", Tactic_Persistence, 95, TRUE, MITRE_T1542 },
    { MITRE_T1136, "T1136", "Create Account", "Create new account", Tactic_Persistence, 70, TRUE, 0 },
    { MITRE_T1136_001, "T1136.001", "Local Account", "Create local account", Tactic_Persistence, 75, TRUE, MITRE_T1136 },
    { MITRE_T1136_002, "T1136.002", "Domain Account", "Create domain account", Tactic_Persistence, 80, TRUE, MITRE_T1136 },
    { MITRE_T1136_003, "T1136.003", "Cloud Account", "Create cloud account", Tactic_Persistence, 75, TRUE, MITRE_T1136 },
    { MITRE_T1554, "T1554", "Compromise Host Software Binary", "Modify host software", Tactic_Persistence, 85, TRUE, 0 },
    { MITRE_T1176, "T1176", "Software Extensions", "Browser/software extensions", Tactic_Persistence, 70, TRUE, 0 },
    { MITRE_T1176_001, "T1176.001", "Browser Extensions", "Malicious browser extension", Tactic_Persistence, 75, TRUE, MITRE_T1176 },

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
    { MITRE_T1134_003, "T1134.003", "Make and Impersonate Token", "Create and impersonate token", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1134 },
    { MITRE_T1134_005, "T1134.005", "SID-History Injection", "Inject SID history", Tactic_PrivilegeEscalation, 90, TRUE, MITRE_T1134 },
    { MITRE_T1055_005, "T1055.005", "Thread Local Storage", "TLS callback injection", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1055 },
    { MITRE_T1055_008, "T1055.008", "Ptrace", "Ptrace system call injection", Tactic_PrivilegeEscalation, 80, FALSE, MITRE_T1055 },
    { MITRE_T1055_009, "T1055.009", "Proc Memory", "Proc filesystem injection", Tactic_PrivilegeEscalation, 85, FALSE, MITRE_T1055 },
    { MITRE_T1055_011, "T1055.011", "EWM Injection", "Extra window memory injection", Tactic_PrivilegeEscalation, 85, TRUE, MITRE_T1055 },
    { MITRE_T1055_014, "T1055.014", "VDSO Hijacking", "Virtual dynamic shared object", Tactic_PrivilegeEscalation, 80, FALSE, MITRE_T1055 },
    { MITRE_T1055_015, "T1055.015", "ListPlanting", "List-view message injection", Tactic_PrivilegeEscalation, 80, TRUE, MITRE_T1055 },
    { MITRE_T1548_003, "T1548.003", "Sudo", "Sudo and sudo caching abuse", Tactic_PrivilegeEscalation, 75, FALSE, MITRE_T1548 },

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
    { MITRE_T1006, "T1006", "Direct Volume Access", "Bypass file system via volume access", Tactic_DefenseEvasion, 85, TRUE, 0 },
    { MITRE_T1484, "T1484", "Domain Policy Modification", "Modify domain policies", Tactic_DefenseEvasion, 85, TRUE, 0 },
    { MITRE_T1480, "T1480", "Execution Guardrails", "Environmentally keyed payloads", Tactic_DefenseEvasion, 65, TRUE, 0 },
    { MITRE_T1211, "T1211", "Exploitation for Defense Evasion", "Exploit to evade defenses", Tactic_DefenseEvasion, 85, TRUE, 0 },
    { MITRE_T1222, "T1222", "File and Directory Permissions Modification", "Modify file/dir permissions", Tactic_DefenseEvasion, 60, TRUE, 0 },
    { MITRE_T1564, "T1564", "Hide Artifacts", "Hide files and artifacts", Tactic_DefenseEvasion, 75, TRUE, 0 },
    { MITRE_T1564_001, "T1564.001", "Hidden Files and Directories", "Hide files/dirs", Tactic_DefenseEvasion, 65, TRUE, MITRE_T1564 },
    { MITRE_T1564_002, "T1564.002", "Hidden Users", "Hide user accounts", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1564 },
    { MITRE_T1564_003, "T1564.003", "Hidden Window", "Hide execution windows", Tactic_DefenseEvasion, 65, TRUE, MITRE_T1564 },
    { MITRE_T1564_004, "T1564.004", "NTFS File Attributes", "ADS hiding", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1564 },
    { MITRE_T1564_005, "T1564.005", "Hidden File System", "Hidden filesystem", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1564 },
    { MITRE_T1564_006, "T1564.006", "Run Virtual Instance", "Run in VM to hide", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1564 },
    { MITRE_T1564_007, "T1564.007", "VBA Stomping", "VBA macro stomping", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1564 },
    { MITRE_T1562_003, "T1562.003", "Impair Command History Logging", "Disable cmd history", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1562 },
    { MITRE_T1562_006, "T1562.006", "Indicator Blocking", "Block security indicators", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1562 },
    { MITRE_T1562_009, "T1562.009", "Safe Mode Boot", "Boot to safe mode", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1562 },
    { MITRE_T1562_010, "T1562.010", "Downgrade Attack", "Downgrade security features", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1562 },
    { MITRE_T1562_013, "T1562.013", "Disable or Modify Network Device Firewall", "Disable network device FW", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1562 },
    { MITRE_T1070_003, "T1070.003", "Clear Command History", "Clear command history", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1070 },
    { MITRE_T1070_005, "T1070.005", "Network Share Connection Removal", "Remove share connections", Tactic_DefenseEvasion, 65, TRUE, MITRE_T1070 },
    { MITRE_T1070_010, "T1070.010", "Relocate Malware", "Move malware to evade", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1070 },
    { MITRE_T1202, "T1202", "Indirect Command Execution", "Indirect cmd execution", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1036_001, "T1036.001", "Invalid Code Signature", "Invalid code signature", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1036 },
    { MITRE_T1036_004, "T1036.004", "Masquerade Task or Service", "Masquerade task/service", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1036 },
    { MITRE_T1036_006, "T1036.006", "Space after Filename", "Trailing space in name", Tactic_DefenseEvasion, 65, TRUE, MITRE_T1036 },
    { MITRE_T1036_012, "T1036.012", "Browser Fingerprint", "Spoof browser fingerprint", Tactic_DefenseEvasion, 60, TRUE, MITRE_T1036 },
    { MITRE_T1027_001, "T1027.001", "Binary Padding", "Pad binary to evade", Tactic_DefenseEvasion, 60, TRUE, MITRE_T1027 },
    { MITRE_T1027_003, "T1027.003", "Steganography", "Hide data in images", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1027 },
    { MITRE_T1027_004, "T1027.004", "Compile After Delivery", "Compile on target", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1027 },
    { MITRE_T1027_006, "T1027.006", "HTML Smuggling", "HTML smuggling", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1027 },
    { MITRE_T1027_007, "T1027.007", "Dynamic API Resolution", "Runtime API resolution", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1027 },
    { MITRE_T1027_009, "T1027.009", "Embedded Payloads", "Embedded payload hiding", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1027 },
    { MITRE_T1027_010, "T1027.010", "Command Obfuscation", "Obfuscate commands", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1027 },
    { MITRE_T1027_011, "T1027.011", "Fileless Storage", "Store payload without files", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1027 },
    { MITRE_T1497_002, "T1497.002", "User Activity Based Checks", "Check user activity", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1497 },
    { MITRE_T1218_002, "T1218.002", "Control Panel", "Control panel item execution", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1218 },
    { MITRE_T1218_003, "T1218.003", "CMSTP", "CMSTP execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1218 },
    { MITRE_T1218_004, "T1218.004", "InstallUtil", "InstallUtil execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1218 },
    { MITRE_T1218_007, "T1218.007", "Msiexec", "Msiexec execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1218 },
    { MITRE_T1218_008, "T1218.008", "Odbcconf", "Odbcconf execution", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1218 },
    { MITRE_T1218_009, "T1218.009", "Regsvcs/Regasm", "Regsvcs/Regasm execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1218 },
    { MITRE_T1218_012, "T1218.012", "Verclsid", "Verclsid execution", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1218 },
    { MITRE_T1218_013, "T1218.013", "Mavinject", "Mavinject execution", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1218 },
    { MITRE_T1218_014, "T1218.014", "MMC", "MMC execution", Tactic_DefenseEvasion, 75, TRUE, MITRE_T1218 },
    { MITRE_T1216, "T1216", "System Script Proxy Execution", "Script proxy execution", Tactic_DefenseEvasion, 75, TRUE, 0 },
    { MITRE_T1216_001, "T1216.001", "PubPrn", "PubPrn script execution", Tactic_DefenseEvasion, 80, TRUE, MITRE_T1216 },
    { MITRE_T1221, "T1221", "Template Injection", "Office template injection", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1205, "T1205", "Traffic Signaling", "Port knocking / wake-on-LAN", Tactic_DefenseEvasion, 70, TRUE, 0 },
    { MITRE_T1127, "T1127", "Trusted Developer Utilities Proxy Execution", "Dev tool proxy exec", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1127_001, "T1127.001", "MSBuild", "MSBuild execution", Tactic_DefenseEvasion, 85, TRUE, MITRE_T1127 },
    { MITRE_T1220, "T1220", "XSL Script Processing", "XSL script execution", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1207, "T1207", "Rogue Domain Controller", "DCShadow rogue DC", Tactic_DefenseEvasion, 95, TRUE, 0 },
    { MITRE_T1550_001, "T1550.001", "Application Access Token", "Use app access token", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1550 },
    { MITRE_T1550_004, "T1550.004", "Web Session Cookie", "Use web session cookie", Tactic_DefenseEvasion, 70, TRUE, MITRE_T1550 },
    { MITRE_T1610, "T1610", "Deploy Container", "Deploy malicious container", Tactic_DefenseEvasion, 75, TRUE, 0 },
    { MITRE_T1601, "T1601", "Modify System Image", "Modify network device image", Tactic_DefenseEvasion, 90, TRUE, 0 },
    { MITRE_T1600, "T1600", "Weaken Encryption", "Weaken encryption settings", Tactic_DefenseEvasion, 80, TRUE, 0 },
    { MITRE_T1647, "T1647", "Plist File Modification", "Modify plist files", Tactic_DefenseEvasion, 65, FALSE, 0 },
    { MITRE_T1665, "T1665", "Hide Infrastructure", "Hide attack infrastructure", Tactic_DefenseEvasion, 70, TRUE, 0 },
    { MITRE_T1678, "T1678", "Delay Execution", "Delay malicious execution", Tactic_DefenseEvasion, 60, TRUE, 0 },
    { MITRE_T1679, "T1679", "Selective Exclusion", "Selectively exclude targets", Tactic_DefenseEvasion, 55, TRUE, 0 },

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
    { MITRE_T1003_005, "T1003.005", "Cached Domain Credentials", "Cached credential dump", Tactic_CredentialAccess, 85, TRUE, MITRE_T1003 },
    { MITRE_T1003_007, "T1003.007", "Proc Filesystem", "Proc filesystem cred dump", Tactic_CredentialAccess, 80, FALSE, MITRE_T1003 },
    { MITRE_T1003_008, "T1003.008", "/etc/passwd and /etc/shadow", "Unix password file dump", Tactic_CredentialAccess, 85, FALSE, MITRE_T1003 },
    { MITRE_T1110_001, "T1110.001", "Password Guessing", "Password guessing", Tactic_CredentialAccess, 70, TRUE, MITRE_T1110 },
    { MITRE_T1110_002, "T1110.002", "Password Cracking", "Offline password cracking", Tactic_CredentialAccess, 75, TRUE, MITRE_T1110 },
    { MITRE_T1110_004, "T1110.004", "Credential Stuffing", "Credential stuffing", Tactic_CredentialAccess, 75, TRUE, MITRE_T1110 },
    { MITRE_T1555_001, "T1555.001", "Keychain", "macOS Keychain access", Tactic_CredentialAccess, 80, FALSE, MITRE_T1555 },
    { MITRE_T1555_005, "T1555.005", "Password Managers", "Password manager access", Tactic_CredentialAccess, 85, TRUE, MITRE_T1555 },
    { MITRE_T1056_002, "T1056.002", "GUI Input Capture", "GUI input capture", Tactic_CredentialAccess, 80, TRUE, MITRE_T1056 },
    { MITRE_T1056_003, "T1056.003", "Web Portal Capture", "Web portal credential capture", Tactic_CredentialAccess, 80, TRUE, MITRE_T1056 },
    { MITRE_T1056_004, "T1056.004", "Credential API Hooking", "API hooking for creds", Tactic_CredentialAccess, 85, TRUE, MITRE_T1056 },
    { MITRE_T1558_004, "T1558.004", "AS-REP Roasting", "AS-REP Roasting attack", Tactic_CredentialAccess, 85, TRUE, MITRE_T1558 },
    { MITRE_T1557_001, "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", "LLMNR/NBNS poisoning", Tactic_CredentialAccess, 85, TRUE, MITRE_T1557 },
    { MITRE_T1557_002, "T1557.002", "ARP Cache Poisoning", "ARP cache poisoning", Tactic_CredentialAccess, 80, TRUE, MITRE_T1557 },
    { MITRE_T1557_003, "T1557.003", "DHCP Spoofing", "DHCP spoofing", Tactic_CredentialAccess, 75, TRUE, MITRE_T1557 },
    { MITRE_T1557_004, "T1557.004", "Evil Twin", "Evil twin access point", Tactic_CredentialAccess, 80, TRUE, MITRE_T1557 },
    { MITRE_T1212, "T1212", "Exploitation for Credential Access", "Exploit for credential access", Tactic_CredentialAccess, 85, TRUE, 0 },
    { MITRE_T1187, "T1187", "Forced Authentication", "Force auth for cred capture", Tactic_CredentialAccess, 80, TRUE, 0 },
    { MITRE_T1606, "T1606", "Forge Web Credentials", "Forge web credentials", Tactic_CredentialAccess, 85, TRUE, 0 },
    { MITRE_T1606_001, "T1606.001", "Web Cookies", "Forge web cookies", Tactic_CredentialAccess, 80, TRUE, MITRE_T1606 },
    { MITRE_T1606_002, "T1606.002", "SAML Tokens", "Forge SAML tokens", Tactic_CredentialAccess, 90, TRUE, MITRE_T1606 },
    { MITRE_T1111, "T1111", "Two-Factor Authentication Interception", "Intercept 2FA", Tactic_CredentialAccess, 80, TRUE, 0 },
    { MITRE_T1528, "T1528", "Steal Application Access Token", "Steal app token", Tactic_CredentialAccess, 80, TRUE, 0 },
    { MITRE_T1539, "T1539", "Steal Web Session Cookie", "Steal session cookie", Tactic_CredentialAccess, 80, TRUE, 0 },
    { MITRE_T1552, "T1552", "Unsecured Credentials", "Find unsecured credentials", Tactic_CredentialAccess, 75, TRUE, 0 },
    { MITRE_T1552_001, "T1552.001", "Credentials In Files", "Credentials in files", Tactic_CredentialAccess, 80, TRUE, MITRE_T1552 },
    { MITRE_T1552_002, "T1552.002", "Credentials in Registry", "Credentials in registry", Tactic_CredentialAccess, 80, TRUE, MITRE_T1552 },
    { MITRE_T1552_003, "T1552.003", "Bash History", "Creds in bash history", Tactic_CredentialAccess, 70, FALSE, MITRE_T1552 },
    { MITRE_T1552_004, "T1552.004", "Private Keys", "Steal private keys", Tactic_CredentialAccess, 85, TRUE, MITRE_T1552 },
    { MITRE_T1552_005, "T1552.005", "Cloud Instance Metadata API", "Cloud metadata API creds", Tactic_CredentialAccess, 80, FALSE, MITRE_T1552 },
    { MITRE_T1552_006, "T1552.006", "Group Policy Preferences", "GPP stored credentials", Tactic_CredentialAccess, 85, TRUE, MITRE_T1552 },
    { MITRE_T1621, "T1621", "Multi-Factor Authentication Request Generation", "MFA fatigue attack", Tactic_CredentialAccess, 75, TRUE, 0 },
    { MITRE_T1040, "T1040", "Network Sniffing", "Sniff network traffic", Tactic_CredentialAccess, 70, TRUE, 0 },

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
    { MITRE_T1010, "T1010", "Application Window Discovery", "Enumerate app windows", Tactic_Discovery, 45, TRUE, 0 },
    { MITRE_T1087_003, "T1087.003", "Email Account", "Email account discovery", Tactic_Discovery, 60, TRUE, MITRE_T1087 },
    { MITRE_T1087_004, "T1087.004", "Cloud Account", "Cloud account discovery", Tactic_Discovery, 65, TRUE, MITRE_T1087 },
    { MITRE_T1069_003, "T1069.003", "Cloud Groups", "Cloud group discovery", Tactic_Discovery, 60, TRUE, MITRE_T1069 },
    { MITRE_T1217, "T1217", "Browser Information Discovery", "Browser data discovery", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1046, "T1046", "Network Service Discovery", "Network service scan", Tactic_Discovery, 70, TRUE, 0 },
    { MITRE_T1007, "T1007", "System Service Discovery", "Service enumeration", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1124, "T1124", "System Time Discovery", "Query system time", Tactic_Discovery, 40, TRUE, 0 },
    { MITRE_T1120, "T1120", "Peripheral Device Discovery", "Enumerate peripherals", Tactic_Discovery, 45, TRUE, 0 },
    { MITRE_T1201, "T1201", "Password Policy Discovery", "Discover password policy", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1614, "T1614", "System Location Discovery", "Discover system location", Tactic_Discovery, 45, TRUE, 0 },
    { MITRE_T1615, "T1615", "Group Policy Discovery", "Discover group policies", Tactic_Discovery, 55, TRUE, 0 },
    { MITRE_T1580, "T1580", "Cloud Infrastructure Discovery", "Discover cloud infra", Tactic_Discovery, 60, FALSE, 0 },
    { MITRE_T1526, "T1526", "Cloud Service Discovery", "Discover cloud services", Tactic_Discovery, 55, FALSE, 0 },
    { MITRE_T1538, "T1538", "Cloud Service Dashboard", "Access cloud dashboard", Tactic_Discovery, 50, FALSE, 0 },
    { MITRE_T1613, "T1613", "Container and Resource Discovery", "Discover containers", Tactic_Discovery, 55, FALSE, 0 },
    { MITRE_T1680, "T1680", "Local Storage Discovery", "Discover local storage", Tactic_Discovery, 40, TRUE, 0 },
    { MITRE_T1518_002, "T1518.002", "Backup Software Discovery", "Discover backup software", Tactic_Discovery, 60, TRUE, MITRE_T1518 },
    { MITRE_T1016_001, "T1016.001", "Internet Connection Discovery", "Check internet connectivity", Tactic_Discovery, 45, TRUE, MITRE_T1016 },
    { MITRE_T1016_002, "T1016.002", "Wi-Fi Discovery", "Discover Wi-Fi networks", Tactic_Discovery, 50, TRUE, MITRE_T1016 },

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
    { MITRE_T1021_004, "T1021.004", "SSH", "SSH lateral movement", Tactic_LateralMovement, 70, TRUE, MITRE_T1021 },
    { MITRE_T1021_005, "T1021.005", "VNC", "VNC lateral movement", Tactic_LateralMovement, 70, TRUE, MITRE_T1021 },
    { MITRE_T1534, "T1534", "Internal Spearphishing", "Internal phishing", Tactic_LateralMovement, 75, TRUE, 0 },
    { MITRE_T1092, "T1092", "Communication Through Removable Media", "Removable media lateral", Tactic_LateralMovement, 55, TRUE, 0 },
    { MITRE_T1677, "T1677", "Poisoned Pipeline Execution", "CI/CD pipeline abuse", Tactic_LateralMovement, 80, TRUE, 0 },

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
    { MITRE_T1560_002, "T1560.002", "Archive via Library", "Archive via code library", Tactic_Collection, 70, TRUE, MITRE_T1560 },
    { MITRE_T1560_003, "T1560.003", "Archive via Custom Method", "Custom archive method", Tactic_Collection, 75, TRUE, MITRE_T1560 },
    { MITRE_T1074_002, "T1074.002", "Remote Data Staging", "Remote staging area", Tactic_Collection, 70, TRUE, MITRE_T1074 },
    { MITRE_T1114_001, "T1114.001", "Local Email Collection", "Collect local email", Tactic_Collection, 75, TRUE, MITRE_T1114 },
    { MITRE_T1114_002, "T1114.002", "Remote Email Collection", "Collect remote email", Tactic_Collection, 80, TRUE, MITRE_T1114 },
    { MITRE_T1114_003, "T1114.003", "Email Forwarding Rule", "Email forwarding rule", Tactic_Collection, 80, TRUE, MITRE_T1114 },
    { MITRE_T1185, "T1185", "Browser Session Hijacking", "Hijack browser session", Tactic_Collection, 80, TRUE, 0 },
    { MITRE_T1025, "T1025", "Data from Removable Media", "Collect from removable media", Tactic_Collection, 60, TRUE, 0 },
    { MITRE_T1530, "T1530", "Data from Cloud Storage", "Collect from cloud storage", Tactic_Collection, 75, FALSE, 0 },
    { MITRE_T1602, "T1602", "Data from Configuration Repository", "Collect device configs", Tactic_Collection, 70, TRUE, 0 },
    { MITRE_T1213, "T1213", "Data from Information Repositories", "Collect from info repos", Tactic_Collection, 65, TRUE, 0 },
    { MITRE_T1213_001, "T1213.001", "Confluence", "Collect from Confluence", Tactic_Collection, 65, TRUE, MITRE_T1213 },
    { MITRE_T1213_002, "T1213.002", "Sharepoint", "Collect from Sharepoint", Tactic_Collection, 65, TRUE, MITRE_T1213 },
    { MITRE_T1213_003, "T1213.003", "Code Repositories", "Collect from code repos", Tactic_Collection, 70, TRUE, MITRE_T1213 },
    { MITRE_T1213_006, "T1213.006", "Databases", "Collect from databases", Tactic_Collection, 70, TRUE, MITRE_T1213 },

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
    { MITRE_T1071_002, "T1071.002", "File Transfer Protocols", "FTP C2", Tactic_CommandAndControl, 70, TRUE, MITRE_T1071 },
    { MITRE_T1071_003, "T1071.003", "Mail Protocols", "SMTP/IMAP C2", Tactic_CommandAndControl, 70, TRUE, MITRE_T1071 },
    { MITRE_T1071_005, "T1071.005", "Publish/Subscribe Protocols", "Pub/Sub C2", Tactic_CommandAndControl, 65, TRUE, MITRE_T1071 },
    { MITRE_T1001, "T1001", "Data Obfuscation", "Obfuscate C2 data", Tactic_CommandAndControl, 70, TRUE, 0 },
    { MITRE_T1001_001, "T1001.001", "Junk Data", "Add junk data to C2", Tactic_CommandAndControl, 60, TRUE, MITRE_T1001 },
    { MITRE_T1001_002, "T1001.002", "Steganography", "Hide C2 in images", Tactic_CommandAndControl, 75, TRUE, MITRE_T1001 },
    { MITRE_T1001_003, "T1001.003", "Protocol Impersonation", "Impersonate protocol", Tactic_CommandAndControl, 70, TRUE, MITRE_T1001 },
    { MITRE_T1132, "T1132", "Data Encoding", "Encode C2 data", Tactic_CommandAndControl, 60, TRUE, 0 },
    { MITRE_T1132_001, "T1132.001", "Standard Encoding", "Base64/URL encoding", Tactic_CommandAndControl, 55, TRUE, MITRE_T1132 },
    { MITRE_T1132_002, "T1132.002", "Non-Standard Encoding", "Custom encoding scheme", Tactic_CommandAndControl, 65, TRUE, MITRE_T1132 },
    { MITRE_T1008, "T1008", "Fallback Channels", "Backup C2 channels", Tactic_CommandAndControl, 70, TRUE, 0 },
    { MITRE_T1104, "T1104", "Multi-Stage Channels", "Multi-stage C2", Tactic_CommandAndControl, 75, TRUE, 0 },
    { MITRE_T1095, "T1095", "Non-Application Layer Protocol", "Raw TCP/UDP/ICMP C2", Tactic_CommandAndControl, 75, TRUE, 0 },
    { MITRE_T1090_001, "T1090.001", "Internal Proxy", "Internal C2 proxy", Tactic_CommandAndControl, 70, TRUE, MITRE_T1090 },
    { MITRE_T1090_002, "T1090.002", "External Proxy", "External C2 proxy", Tactic_CommandAndControl, 70, TRUE, MITRE_T1090 },
    { MITRE_T1090_004, "T1090.004", "Domain Fronting", "Domain fronting C2", Tactic_CommandAndControl, 85, TRUE, MITRE_T1090 },
    { MITRE_T1568_001, "T1568.001", "Fast Flux DNS", "Fast flux DNS resolution", Tactic_CommandAndControl, 85, TRUE, MITRE_T1568 },
    { MITRE_T1568_003, "T1568.003", "DNS Calculation", "DNS-based C2 calculation", Tactic_CommandAndControl, 80, TRUE, MITRE_T1568 },
    { MITRE_T1102_001, "T1102.001", "Dead Drop Resolver", "Dead drop resolver C2", Tactic_CommandAndControl, 80, TRUE, MITRE_T1102 },
    { MITRE_T1102_002, "T1102.002", "Bidirectional Communication", "Bidirectional web service C2", Tactic_CommandAndControl, 75, TRUE, MITRE_T1102 },
    { MITRE_T1102_003, "T1102.003", "One-Way Communication", "One-way web service C2", Tactic_CommandAndControl, 70, TRUE, MITRE_T1102 },

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
    { MITRE_T1020_001, "T1020.001", "Traffic Duplication", "Duplicate traffic for exfil", Tactic_Exfiltration, 75, TRUE, MITRE_T1020 },
    { MITRE_T1048_001, "T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Symmetric encrypted exfil", Tactic_Exfiltration, 80, TRUE, MITRE_T1048 },
    { MITRE_T1048_002, "T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Asymmetric encrypted exfil", Tactic_Exfiltration, 80, TRUE, MITRE_T1048 },
    { MITRE_T1048_003, "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Unencrypted alt protocol exfil", Tactic_Exfiltration, 75, TRUE, MITRE_T1048 },
    { MITRE_T1567_001, "T1567.001", "Exfiltration to Code Repository", "Exfil to code repo", Tactic_Exfiltration, 75, TRUE, MITRE_T1567 },
    { MITRE_T1011, "T1011", "Exfiltration Over Other Network Medium", "Exfil via other network", Tactic_Exfiltration, 65, TRUE, 0 },
    { MITRE_T1011_001, "T1011.001", "Exfiltration Over Bluetooth", "Exfil via Bluetooth", Tactic_Exfiltration, 60, TRUE, MITRE_T1011 },
    { MITRE_T1052_001, "T1052.001", "Exfiltration over USB", "Exfil via USB device", Tactic_Exfiltration, 65, TRUE, MITRE_T1052 },
    { MITRE_T1029, "T1029", "Scheduled Transfer", "Scheduled data transfer", Tactic_Exfiltration, 70, TRUE, 0 },
    { MITRE_T1537, "T1537", "Transfer Data to Cloud Account", "Exfil to cloud account", Tactic_Exfiltration, 75, TRUE, 0 },

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
    { MITRE_T1491, "T1491", "Defacement", "Website/system defacement", Tactic_Impact, 75, TRUE, 0 },
    { MITRE_T1491_001, "T1491.001", "Internal Defacement", "Internal defacement", Tactic_Impact, 70, TRUE, MITRE_T1491 },
    { MITRE_T1491_002, "T1491.002", "External Defacement", "External defacement", Tactic_Impact, 80, TRUE, MITRE_T1491 },
    { MITRE_T1495, "T1495", "Firmware Corruption", "Corrupt device firmware", Tactic_Impact, 95, TRUE, 0 },
    { MITRE_T1498, "T1498", "Network Denial of Service", "Network DoS attack", Tactic_Impact, 80, TRUE, 0 },
    { MITRE_T1498_001, "T1498.001", "Direct Network Flood", "Direct network flood", Tactic_Impact, 75, TRUE, MITRE_T1498 },
    { MITRE_T1498_002, "T1498.002", "Reflection Amplification", "Reflection amplification DoS", Tactic_Impact, 80, TRUE, MITRE_T1498 },
    { MITRE_T1499_001, "T1499.001", "OS Exhaustion Flood", "OS resource exhaustion", Tactic_Impact, 75, TRUE, MITRE_T1499 },
    { MITRE_T1499_002, "T1499.002", "Service Exhaustion Flood", "Service resource exhaustion", Tactic_Impact, 75, TRUE, MITRE_T1499 },
    { MITRE_T1499_003, "T1499.003", "Application Exhaustion Flood", "App resource exhaustion", Tactic_Impact, 80, TRUE, MITRE_T1499 },
    { MITRE_T1499_004, "T1499.004", "Application or System Exploitation", "Exploit for DoS", Tactic_Impact, 85, TRUE, MITRE_T1499 },
    { MITRE_T1565_001, "T1565.001", "Stored Data Manipulation", "Modify stored data", Tactic_Impact, 85, TRUE, MITRE_T1565 },
    { MITRE_T1565_002, "T1565.002", "Transmitted Data Manipulation", "Modify data in transit", Tactic_Impact, 85, TRUE, MITRE_T1565 },
    { MITRE_T1565_003, "T1565.003", "Runtime Data Manipulation", "Modify runtime data", Tactic_Impact, 90, TRUE, MITRE_T1565 },

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
    // Mark as not initialized atomically to prevent new operations
    //
    InterlockedExchange8((volatile CHAR*)&Mapper->Initialized, FALSE);
    InterlockedExchange8((volatile CHAR*)&Mapper->TechniquesLoaded, FALSE);

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
        if (newCount == 0) {
            //
            // Last reference dropped — free the detection and its resources
            //
            MmpFreeDetection(Detection);
        }
        NT_ASSERT(newCount >= 0);
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
    // Now release evicted detections outside of lock.
    // Uses MmReleaseDetection to respect external references — if a caller
    // holds a reference from MmGetRecentDetections, the detection stays alive
    // until that caller releases it.
    //
    while (!IsListEmpty(&evictList)) {
        listEntry = RemoveHeadList(&evictList);
        evictDetection = CONTAINING_RECORD(listEntry, MM_DETECTION, ListEntry);
        InterlockedIncrement64(&Mapper->Stats.DetectionsEvicted);
        MmReleaseDetection(evictDetection);
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
