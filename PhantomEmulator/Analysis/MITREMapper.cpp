/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MITREMapper.cpp — MITRE ATT&CK Enterprise technique mapping
 *
 * Maps detected behavioral signals to MITRE ATT&CK techniques. Covers
 * ~91 techniques across all 11 tactics (Execution through Impact).
 * Each mapping records evidence — the specific behavioral indicator that
 * triggered the technique — for forensic reporting.
 *
 * Technique deduplication: if the same technique ID is mapped multiple
 * times, only the highest-confidence instance is kept, but all evidence
 * strings are accumulated.
 *
 * Kill-chain coverage is computed as the number of distinct tactics observed,
 * which correlates with attack sophistication.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MITREMapper.hpp"
#include "AnalysisTypes.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Limits
// ============================================================================

static constexpr uint32_t kMaxMappedTechniques = 512;
static constexpr uint32_t kMaxEvidencePerTechnique = 32;

// ============================================================================
// Static Technique Database
// ============================================================================

struct TechniqueDefinition {
    const char* id;
    const char* name;
    const char* tactic;
    const char* description;
};

// All 11 MITRE ATT&CK tactics
static constexpr const char* kTacticExecution          = "Execution";
static constexpr const char* kTacticPersistence        = "Persistence";
static constexpr const char* kTacticPrivilegeEscalation = "Privilege Escalation";
static constexpr const char* kTacticDefenseEvasion     = "Defense Evasion";
static constexpr const char* kTacticCredentialAccess   = "Credential Access";
static constexpr const char* kTacticDiscovery          = "Discovery";
static constexpr const char* kTacticLateralMovement    = "Lateral Movement";
static constexpr const char* kTacticCollection         = "Collection";
static constexpr const char* kTacticCommandAndControl  = "Command and Control";
static constexpr const char* kTacticExfiltration       = "Exfiltration";
static constexpr const char* kTacticImpact             = "Impact";

static constexpr TechniqueDefinition kTechniqueDB[] = {
    // ========================================================================
    // Execution (TA0002)
    // ========================================================================
    { "T1059.001", "Command and Scripting Interpreter: PowerShell",
      kTacticExecution,
      "Adversaries may abuse PowerShell commands and scripts for execution" },
    { "T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
      kTacticExecution,
      "Adversaries may abuse the Windows command shell (cmd.exe) for execution" },
    { "T1059.005", "Command and Scripting Interpreter: Visual Basic",
      kTacticExecution,
      "Adversaries may abuse VBScript for execution" },
    { "T1059.007", "Command and Scripting Interpreter: JavaScript",
      kTacticExecution,
      "Adversaries may abuse JavaScript for execution via JScript/wscript" },
    { "T1106", "Native API",
      kTacticExecution,
      "Adversaries may interact with the native OS API to execute behaviors" },
    { "T1129", "Shared Modules",
      kTacticExecution,
      "Adversaries may execute malicious payloads via loading shared modules" },
    { "T1204.002", "User Execution: Malicious File",
      kTacticExecution,
      "Adversaries may rely upon a user opening a malicious file for execution" },
    { "T1047", "Windows Management Instrumentation",
      kTacticExecution,
      "Adversaries may abuse WMI to execute malicious commands and payloads" },

    // ========================================================================
    // Persistence (TA0003)
    // ========================================================================
    { "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
      kTacticPersistence,
      "Adversaries may achieve persistence by adding a program to a startup folder or "
      "referencing it with a Registry run key" },
    { "T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL",
      kTacticPersistence,
      "Adversaries may abuse Winlogon helper features to achieve persistence" },
    { "T1547.010", "Boot or Logon Autostart Execution: Port Monitors",
      kTacticPersistence,
      "Adversaries may use port monitors to run an attacker-supplied DLL during system boot" },
    { "T1543.003", "Create or Modify System Process: Windows Service",
      kTacticPersistence,
      "Adversaries may create or modify Windows services to repeatedly execute malicious payloads" },
    { "T1053.005", "Scheduled Task/Job: Scheduled Task",
      kTacticPersistence,
      "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for "
      "initial or recurring execution" },
    { "T1546.003", "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
      kTacticPersistence,
      "Adversaries may establish persistence via WMI event subscriptions" },
    { "T1546.015", "Event Triggered Execution: Component Object Model Hijacking",
      kTacticPersistence,
      "Adversaries may establish persistence by executing malicious content triggered "
      "by hijacked COM object references" },
    { "T1197", "BITS Jobs",
      kTacticPersistence,
      "Adversaries may abuse BITS jobs to persistently execute or download code" },
    { "T1505.003", "Server Software Component: Web Shell",
      kTacticPersistence,
      "Adversaries may backdoor web servers with web shells to establish persistent access" },

    // ========================================================================
    // Privilege Escalation (TA0004)
    // ========================================================================
    { "T1134.001", "Access Token Manipulation: Token Impersonation/Theft",
      kTacticPrivilegeEscalation,
      "Adversaries may duplicate then impersonate another user's token to escalate privileges" },
    { "T1134.002", "Access Token Manipulation: Create Process with Token",
      kTacticPrivilegeEscalation,
      "Adversaries may create a new process with a different token to escalate privileges" },
    { "T1055", "Process Injection",
      kTacticPrivilegeEscalation,
      "Adversaries may inject code into processes to evade defenses and elevate privileges" },
    { "T1068", "Exploitation for Privilege Escalation",
      kTacticPrivilegeEscalation,
      "Adversaries may exploit software vulnerabilities to elevate privileges" },
    { "T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control",
      kTacticPrivilegeEscalation,
      "Adversaries may bypass UAC mechanisms to elevate process privileges" },

    // ========================================================================
    // Defense Evasion (TA0005)
    // ========================================================================
    { "T1055.001", "Process Injection: Dynamic-link Library Injection",
      kTacticDefenseEvasion,
      "Adversaries may inject DLLs into processes to evade defenses and elevate privileges" },
    { "T1055.002", "Process Injection: Portable Executable Injection",
      kTacticDefenseEvasion,
      "Adversaries may inject portable executables into processes" },
    { "T1055.003", "Process Injection: Thread Execution Hijacking",
      kTacticDefenseEvasion,
      "Adversaries may inject code into hijacked processes via thread execution hijacking" },
    { "T1055.004", "Process Injection: Asynchronous Procedure Call",
      kTacticDefenseEvasion,
      "Adversaries may inject code into processes via APC queue abuse" },
    { "T1055.005", "Process Injection: Thread Local Storage",
      kTacticDefenseEvasion,
      "Adversaries may inject code into processes via TLS callback injection" },
    { "T1055.008", "Process Injection: Ptrace System Calls",
      kTacticDefenseEvasion,
      "Adversaries may inject code into processes via ptrace system calls" },
    { "T1055.012", "Process Injection: Process Hollowing",
      kTacticDefenseEvasion,
      "Adversaries may inject code into suspended processes via process hollowing" },
    { "T1055.013", "Process Injection: Process Doppelganging",
      kTacticDefenseEvasion,
      "Adversaries may inject code via process doppelganging using TxF transactions" },
    { "T1055.014", "Process Injection: VDSO Hijacking",
      kTacticDefenseEvasion,
      "Adversaries may inject code into processes via VDSO hijacking" },
    { "T1027", "Obfuscated Files or Information",
      kTacticDefenseEvasion,
      "Adversaries may attempt to make a file or data difficult to discover or analyze" },
    { "T1027.002", "Obfuscated Files or Information: Software Packing",
      kTacticDefenseEvasion,
      "Adversaries may perform software packing to conceal their code" },
    { "T1027.010", "Obfuscated Files or Information: Command Obfuscation",
      kTacticDefenseEvasion,
      "Adversaries may obfuscate commands to make detection more difficult" },
    { "T1140", "Deobfuscate/Decode Files or Information",
      kTacticDefenseEvasion,
      "Adversaries may deobfuscate/decode files or information to reveal malicious content" },
    { "T1070.001", "Indicator Removal: Clear Windows Event Logs",
      kTacticDefenseEvasion,
      "Adversaries may clear Windows Event Logs to hide evidence of intrusion" },
    { "T1070.004", "Indicator Removal: File Deletion",
      kTacticDefenseEvasion,
      "Adversaries may delete files left behind by their intrusion activity" },
    { "T1070.006", "Indicator Removal: Timestomp",
      kTacticDefenseEvasion,
      "Adversaries may modify file time attributes to blend malicious files with normal ones" },
    { "T1562.001", "Impair Defenses: Disable or Modify Tools",
      kTacticDefenseEvasion,
      "Adversaries may modify or disable security tools to avoid detection" },
    { "T1562.004", "Impair Defenses: Disable or Modify System Firewall",
      kTacticDefenseEvasion,
      "Adversaries may disable or modify system firewalls to enable C2 traffic" },
    { "T1497.001", "Virtualization/Sandbox Evasion: System Checks",
      kTacticDefenseEvasion,
      "Adversaries may employ system checks to detect and avoid virtualization or sandboxing" },
    { "T1497.003", "Virtualization/Sandbox Evasion: Time Based Evasion",
      kTacticDefenseEvasion,
      "Adversaries may employ time-based methods to detect and avoid sandboxing" },
    { "T1036.005", "Masquerading: Match Legitimate Name or Location",
      kTacticDefenseEvasion,
      "Adversaries may match or approximate the name or location of legitimate files" },
    { "T1218.011", "System Binary Proxy Execution: Rundll32",
      kTacticDefenseEvasion,
      "Adversaries may abuse rundll32.exe to proxy execution of malicious code" },
    { "T1220", "XSL Script Processing",
      kTacticDefenseEvasion,
      "Adversaries may bypass application controls via XSL script processing" },

    // ========================================================================
    // Credential Access (TA0006)
    // ========================================================================
    { "T1003.001", "OS Credential Dumping: LSASS Memory",
      kTacticCredentialAccess,
      "Adversaries may attempt to access credential material stored in LSASS process memory" },
    { "T1003.002", "OS Credential Dumping: Security Account Manager",
      kTacticCredentialAccess,
      "Adversaries may attempt to extract credential material from the SAM database" },
    { "T1003.004", "OS Credential Dumping: LSA Secrets",
      kTacticCredentialAccess,
      "Adversaries may access LSA Secrets stored in the registry" },
    { "T1552.001", "Unsecured Credentials: Credentials In Files",
      kTacticCredentialAccess,
      "Adversaries may search local file systems for credential material" },
    { "T1555.003", "Credentials from Password Stores: Credentials from Web Browsers",
      kTacticCredentialAccess,
      "Adversaries may acquire credentials from web browsers by reading files" },
    { "T1056.001", "Input Capture: Keylogging",
      kTacticCredentialAccess,
      "Adversaries may log user keystrokes to intercept credentials" },

    // ========================================================================
    // Discovery (TA0007)
    // ========================================================================
    { "T1082", "System Information Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to get detailed information about the OS and hardware" },
    { "T1083", "File and Directory Discovery",
      kTacticDiscovery,
      "Adversaries may enumerate files and directories to identify targets for collection" },
    { "T1057", "Process Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to get information about running processes" },
    { "T1012", "Query Registry",
      kTacticDiscovery,
      "Adversaries may interact with the Windows Registry to gather information" },
    { "T1018", "Remote System Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to get a listing of other systems on the network" },
    { "T1016", "System Network Configuration Discovery",
      kTacticDiscovery,
      "Adversaries may look for details about the network configuration of systems" },
    { "T1049", "System Network Connections Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to get a listing of current network connections" },
    { "T1033", "System Owner/User Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to identify the primary user or current user of a system" },
    { "T1007", "System Service Discovery",
      kTacticDiscovery,
      "Adversaries may try to get information about registered services" },
    { "T1135", "Network Share Discovery",
      kTacticDiscovery,
      "Adversaries may look for shared folders and drives on remote systems" },
    { "T1518.001", "Software Discovery: Security Software Discovery",
      kTacticDiscovery,
      "Adversaries may attempt to enumerate security software installed on a system" },

    // ========================================================================
    // Lateral Movement (TA0008)
    // ========================================================================
    { "T1021.002", "Remote Services: SMB/Windows Admin Shares",
      kTacticLateralMovement,
      "Adversaries may use SMB and Windows Admin Shares for remote execution" },
    { "T1021.003", "Remote Services: Distributed Component Object Model",
      kTacticLateralMovement,
      "Adversaries may use DCOM to move laterally on a network" },
    { "T1021.006", "Remote Services: Windows Remote Management",
      kTacticLateralMovement,
      "Adversaries may use WinRM for remote execution" },
    { "T1570", "Lateral Tool Transfer",
      kTacticLateralMovement,
      "Adversaries may transfer tools or files between systems within the network" },

    // ========================================================================
    // Collection (TA0009)
    // ========================================================================
    { "T1056.001C", "Input Capture: Keylogging",
      kTacticCollection,
      "Adversaries may log user keystrokes to collect sensitive data" },
    { "T1113", "Screen Capture",
      kTacticCollection,
      "Adversaries may attempt to take screen captures to collect information" },
    { "T1115", "Clipboard Data",
      kTacticCollection,
      "Adversaries may collect data stored in the clipboard" },
    { "T1005", "Data from Local System",
      kTacticCollection,
      "Adversaries may search local system sources to find files of interest" },
    { "T1039", "Data from Network Shared Drive",
      kTacticCollection,
      "Adversaries may search network shares to find files of interest" },
    { "T1119", "Automated Collection",
      kTacticCollection,
      "Adversaries may use automated techniques for collecting internal data" },

    // ========================================================================
    // Command and Control (TA0011)
    // ========================================================================
    { "T1071.001", "Application Layer Protocol: Web Protocols",
      kTacticCommandAndControl,
      "Adversaries may communicate using HTTP/HTTPS to avoid detection" },
    { "T1071.004", "Application Layer Protocol: DNS",
      kTacticCommandAndControl,
      "Adversaries may communicate using the DNS protocol for C2" },
    { "T1095", "Non-Application Layer Protocol",
      kTacticCommandAndControl,
      "Adversaries may use a non-application layer protocol for C2 communication" },
    { "T1573.001", "Encrypted Channel: Symmetric Cryptography",
      kTacticCommandAndControl,
      "Adversaries may employ symmetric encryption for C2 communications" },
    { "T1573.002", "Encrypted Channel: Asymmetric Cryptography",
      kTacticCommandAndControl,
      "Adversaries may employ asymmetric encryption for C2 communications" },
    { "T1105", "Ingress Tool Transfer",
      kTacticCommandAndControl,
      "Adversaries may transfer tools from an external system into the environment" },
    { "T1132.001", "Data Encoding: Standard Encoding",
      kTacticCommandAndControl,
      "Adversaries may encode C2 data with standard encoding (Base64)" },
    { "T1572", "Protocol Tunneling",
      kTacticCommandAndControl,
      "Adversaries may tunnel network communications to avoid detection" },
    { "T1090", "Proxy",
      kTacticCommandAndControl,
      "Adversaries may use a connection proxy to direct network traffic" },

    // ========================================================================
    // Exfiltration (TA0010)
    // ========================================================================
    { "T1041", "Exfiltration Over C2 Channel",
      kTacticExfiltration,
      "Adversaries may steal data by exfiltrating it over an existing C2 channel" },
    { "T1048.002", "Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2",
      kTacticExfiltration,
      "Adversaries may steal data by exfiltrating it over an asymmetric encrypted non-C2 protocol" },
    { "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
      kTacticExfiltration,
      "Adversaries may exfiltrate data to a cloud storage service" },

    // ========================================================================
    // Impact (TA0040)
    // ========================================================================
    { "T1486", "Data Encrypted for Impact",
      kTacticImpact,
      "Adversaries may encrypt data on target systems to interrupt availability (ransomware)" },
    { "T1485", "Data Destruction",
      kTacticImpact,
      "Adversaries may destroy data on specific systems to interrupt availability" },
    { "T1490", "Inhibit System Recovery",
      kTacticImpact,
      "Adversaries may delete or disable system recovery features" },
    { "T1489", "Service Stop",
      kTacticImpact,
      "Adversaries may stop or disable services on a system" },
    { "T1529", "System Shutdown/Reboot",
      kTacticImpact,
      "Adversaries may shutdown or reboot systems to interrupt access" },
    { "T1561.001", "Disk Wipe: Disk Content Wipe",
      kTacticImpact,
      "Adversaries may erase the contents of storage devices" },
    { "T1561.002", "Disk Wipe: Disk Structure Wipe",
      kTacticImpact,
      "Adversaries may corrupt or wipe the disk data structures (MBR/GPT)" },
};

static constexpr size_t kTechniqueDBSize = sizeof(kTechniqueDB) / sizeof(kTechniqueDB[0]);

// ============================================================================
// Lookup helper: find a TechniqueDefinition by ID
// ============================================================================

static const TechniqueDefinition* FindTechDef(const char* id) noexcept {
    if (!id) return nullptr;
    for (size_t i = 0; i < kTechniqueDBSize; ++i) {
        if (std::strcmp(kTechniqueDB[i].id, id) == 0) {
            return &kTechniqueDB[i];
        }
    }
    return nullptr;
}

// ============================================================================
// Tactic list for kill-chain coverage
// ============================================================================

static constexpr const char* kAllTactics[] = {
    kTacticExecution,
    kTacticPersistence,
    kTacticPrivilegeEscalation,
    kTacticDefenseEvasion,
    kTacticCredentialAccess,
    kTacticDiscovery,
    kTacticLateralMovement,
    kTacticCollection,
    kTacticCommandAndControl,
    kTacticExfiltration,
    kTacticImpact,
};
static constexpr size_t kTacticCount = sizeof(kAllTactics) / sizeof(kAllTactics[0]);

// ============================================================================
// MITREMapper::Impl
// ============================================================================

struct MITREMapper::Impl {
    mutable std::shared_mutex mutex;

    std::vector<MITRETechnique> mapped;
    std::unordered_map<std::string, size_t> idToIndex;

    explicit Impl() noexcept {
        mapped.reserve(128);
        idToIndex.reserve(128);
    }

    // Add or update a technique with deduplication
    void AddTechnique(const char* id, float confidence,
                      const std::string& evidence) noexcept {
        if (!id) return;
        if (mapped.size() >= kMaxMappedTechniques && idToIndex.find(id) == idToIndex.end()) {
            return;
        }

        confidence = std::clamp(confidence, 0.0f, 1.0f);

        auto it = idToIndex.find(id);
        if (it != idToIndex.end()) {
            // Existing technique — update confidence and add evidence
            auto& tech = mapped[it->second];
            if (confidence > tech.confidence) {
                tech.confidence = confidence;
            }
            if (tech.evidence.size() < kMaxEvidencePerTechnique &&
                !evidence.empty()) {
                // Avoid duplicate evidence strings
                bool duplicate = false;
                for (const auto& ev : tech.evidence) {
                    if (ev == evidence) { duplicate = true; break; }
                }
                if (!duplicate) {
                    tech.evidence.push_back(evidence);
                }
            }
            return;
        }

        // New technique — look up definition
        const auto* def = FindTechDef(id);

        MITRETechnique tech;
        if (def) {
            tech.id          = def->id;
            tech.name        = def->name;
            tech.tactic      = def->tactic;
            tech.description = def->description;
        } else {
            // Technique not in our static DB — use provided ID
            tech.id          = id;
            tech.name        = "Unknown Technique";
            tech.tactic      = "Unknown";
            tech.description = "";
        }
        tech.confidence = confidence;
        if (!evidence.empty()) {
            tech.evidence.push_back(evidence);
        }

        size_t idx = mapped.size();
        mapped.push_back(std::move(tech));
        idToIndex[id] = idx;
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

MITREMapper::MITREMapper() noexcept
    : m_impl(std::make_unique<Impl>())
{
}

MITREMapper::~MITREMapper() noexcept = default;

// ============================================================================
// OnBehaviorAlert — map behavior alerts to MITRE techniques
// ============================================================================

void MITREMapper::OnBehaviorAlert(const BehaviorAlert& alert) noexcept {
    std::unique_lock lock(m_impl->mutex);

    float conf = std::clamp(alert.confidence, 0.0f, 1.0f);
    const std::string& desc = alert.description;

    switch (alert.category) {
        case BehaviorCategory::ProcessInjection:
            m_impl->AddTechnique("T1055", conf, desc);
            m_impl->AddTechnique("T1106", conf * 0.7f,
                "Code injection implies native API usage: " + desc);
            break;

        case BehaviorCategory::ProcessHollowing:
            m_impl->AddTechnique("T1055.012", conf, desc);
            m_impl->AddTechnique("T1055", conf * 0.8f,
                "Process hollowing is a sub-technique of process injection");
            break;

        case BehaviorCategory::DLLInjection:
            m_impl->AddTechnique("T1055.001", conf, desc);
            m_impl->AddTechnique("T1055", conf * 0.8f,
                "DLL injection is a sub-technique of process injection");
            m_impl->AddTechnique("T1129", conf * 0.6f,
                "DLL injection involves loading shared modules");
            break;

        case BehaviorCategory::ReflectiveDLLLoad:
            m_impl->AddTechnique("T1620", conf,
                "Reflective DLL loading detected: " + desc);
            m_impl->AddTechnique("T1055.001", conf * 0.8f,
                "Reflective DLL load is a DLL injection variant: " + desc);
            m_impl->AddTechnique("T1129", conf * 0.6f,
                "Reflective DLL load involves shared modules");
            break;

        case BehaviorCategory::ShellcodeExecution:
            m_impl->AddTechnique("T1106", conf * 0.7f,
                "In-memory execution via native API: " + desc);
            m_impl->AddTechnique("T1055.002", conf * 0.6f,
                "In-memory execution may use PE injection: " + desc);
            break;

        case BehaviorCategory::Persistence:
            m_impl->AddTechnique("T1547.001", conf, desc);
            m_impl->AddTechnique("T1012", conf * 0.5f,
                "Registry persistence implies registry access: " + desc);
            break;

        case BehaviorCategory::PrivilegeEscalation:
            m_impl->AddTechnique("T1068", conf * 0.6f,
                "Privilege escalation behavior: " + desc);
            m_impl->AddTechnique("T1134.001", conf * 0.5f,
                "Privilege escalation may involve token manipulation: " + desc);
            break;

        case BehaviorCategory::CredentialAccess:
            m_impl->AddTechnique("T1003.001", conf * 0.6f,
                "Credential access behavior: " + desc);
            m_impl->AddTechnique("T1552.001", conf * 0.5f,
                "Credential access may target files: " + desc);
            break;

        case BehaviorCategory::DefenseEvasion:
            m_impl->AddTechnique("T1027", conf * 0.5f,
                "Defense evasion behavior: " + desc);
            m_impl->AddTechnique("T1140", conf * 0.4f,
                "Defense evasion may involve deobfuscation: " + desc);
            break;

        case BehaviorCategory::LateralMovement:
            m_impl->AddTechnique("T1021.002", conf * 0.6f,
                "Lateral movement via SMB: " + desc);
            m_impl->AddTechnique("T1570", conf * 0.5f,
                "Lateral movement tool transfer: " + desc);
            break;

        case BehaviorCategory::DataExfiltration:
            m_impl->AddTechnique("T1041", conf * 0.7f,
                "Exfiltration detected: " + desc);
            m_impl->AddTechnique("T1005", conf * 0.7f,
                "Data collection from local system: " + desc);
            m_impl->AddTechnique("T1119", conf * 0.5f,
                "Automated data collection: " + desc);
            break;

        case BehaviorCategory::Ransomware:
            m_impl->AddTechnique("T1486", conf, desc);
            m_impl->AddTechnique("T1490", conf * 0.7f,
                "Ransomware typically inhibits system recovery: " + desc);
            m_impl->AddTechnique("T1489", conf * 0.5f,
                "Ransomware may stop services: " + desc);
            break;

        case BehaviorCategory::Downloader:
            m_impl->AddTechnique("T1204.002", conf * 0.7f,
                "File dropper implies malicious file delivery: " + desc);
            m_impl->AddTechnique("T1105", conf * 0.6f,
                "File drop may indicate ingress tool transfer");
            break;

        case BehaviorCategory::Keylogger:
            m_impl->AddTechnique("T1056.001", conf, desc);
            m_impl->AddTechnique("T1056.001C", conf * 0.9f,
                "Keylogging for data collection: " + desc);
            break;

        case BehaviorCategory::ScreenCapture:
            m_impl->AddTechnique("T1113", conf, desc);
            break;

        case BehaviorCategory::Discovery:
            m_impl->AddTechnique("T1082", conf * 0.5f,
                "Discovery behavior: " + desc);
            m_impl->AddTechnique("T1057", conf * 0.4f,
                "Discovery may include process enumeration: " + desc);
            break;

        case BehaviorCategory::CommandAndControl:
            m_impl->AddTechnique("T1071.001", conf * 0.7f,
                "Network C2 communication detected: " + desc);
            m_impl->AddTechnique("T1095", conf * 0.5f,
                "C2 may use non-application layer protocols");
            break;

        case BehaviorCategory::Execution:
            m_impl->AddTechnique("T1543.003", conf * 0.8f,
                "Service manipulation: " + desc);
            m_impl->AddTechnique("T1489", conf * 0.5f,
                "Service manipulation may include service stop: " + desc);
            m_impl->AddTechnique("T1047", conf * 0.7f,
                "Execution may involve WMI: " + desc);
            m_impl->AddTechnique("T1546.003", conf * 0.6f,
                "WMI execution may indicate event subscription: " + desc);
            m_impl->AddTechnique("T1059.001", conf * 0.6f,
                "Execution may involve PowerShell: " + desc);
            break;

        case BehaviorCategory::FileManipulation:
            m_impl->AddTechnique("T1485", conf, desc);
            m_impl->AddTechnique("T1561.001", conf * 0.6f,
                "Data destruction may target disk content: " + desc);
            break;

        case BehaviorCategory::AntiForensics:
            m_impl->AddTechnique("T1497.001", conf * 0.7f,
                "Anti-analysis behavior: " + desc);
            m_impl->AddTechnique("T1497.003", conf * 0.5f,
                "Anti-analysis may use timing checks: " + desc);
            break;

        default:
            break;
    }
}

// ============================================================================
// OnBehaviorFlags — map individual behavior flags to techniques
// ============================================================================

void MITREMapper::OnBehaviorFlags(BehaviorFlag flags) noexcept {
    std::unique_lock lock(m_impl->mutex);

    if (HasFlag(flags, BehaviorFlag::FileDropped)) {
        m_impl->AddTechnique("T1204.002", 0.6f,
            "File was dropped to disk (BehaviorFlag::FileDropped)");
        m_impl->AddTechnique("T1105", 0.5f,
            "File drop may indicate ingress tool transfer");
    }

    if (HasFlag(flags, BehaviorFlag::RegistryPersistence)) {
        m_impl->AddTechnique("T1547.001", 0.8f,
            "Registry persistence mechanism detected (BehaviorFlag::RegistryPersistence)");
        m_impl->AddTechnique("T1012", 0.6f,
            "Registry persistence implies registry query capability");
    }

    if (HasFlag(flags, BehaviorFlag::ProcessInjection)) {
        m_impl->AddTechnique("T1055", 0.85f,
            "Process injection detected (BehaviorFlag::ProcessInjection)");
        m_impl->AddTechnique("T1106", 0.6f,
            "Process injection uses native API calls");
    }

    if (HasFlag(flags, BehaviorFlag::RemoteThreadCreation)) {
        m_impl->AddTechnique("T1055.003", 0.75f,
            "Remote thread creation detected (BehaviorFlag::RemoteThreadCreation)");
        m_impl->AddTechnique("T1055", 0.7f,
            "Remote thread creation is a process injection sub-technique");
    }

    if (HasFlag(flags, BehaviorFlag::MemoryManipulation)) {
        m_impl->AddTechnique("T1055", 0.5f,
            "Memory manipulation detected (BehaviorFlag::MemoryManipulation)");
        m_impl->AddTechnique("T1106", 0.5f,
            "Memory manipulation uses native API");
    }

    if (HasFlag(flags, BehaviorFlag::NetworkC2)) {
        m_impl->AddTechnique("T1071.001", 0.7f,
            "Network C2 activity detected (BehaviorFlag::NetworkC2)");
        m_impl->AddTechnique("T1095", 0.5f,
            "C2 may use non-application layer protocols");
        m_impl->AddTechnique("T1573.001", 0.4f,
            "C2 traffic may be encrypted");
    }

    if (HasFlag(flags, BehaviorFlag::AntiAnalysis)) {
        m_impl->AddTechnique("T1497.001", 0.7f,
            "Anti-analysis detected (BehaviorFlag::AntiAnalysis)");
        m_impl->AddTechnique("T1497.003", 0.5f,
            "Anti-analysis may include timing evasion");
        m_impl->AddTechnique("T1027", 0.4f,
            "Anti-analysis implies obfuscation");
    }

    if (HasFlag(flags, BehaviorFlag::PrivilegeEscalation)) {
        m_impl->AddTechnique("T1134.001", 0.6f,
            "Privilege escalation detected (BehaviorFlag::PrivilegeEscalation)");
        m_impl->AddTechnique("T1068", 0.5f,
            "Privilege escalation may exploit vulnerabilities");
        m_impl->AddTechnique("T1548.002", 0.5f,
            "Privilege escalation may bypass UAC");
    }

    if (HasFlag(flags, BehaviorFlag::CredentialAccess)) {
        m_impl->AddTechnique("T1003.001", 0.6f,
            "Credential access detected (BehaviorFlag::CredentialAccess)");
        m_impl->AddTechnique("T1552.001", 0.5f,
            "Credential access may target credential files");
        m_impl->AddTechnique("T1555.003", 0.4f,
            "Credential access may target browser credentials");
    }

    if (HasFlag(flags, BehaviorFlag::DefenseEvasion)) {
        m_impl->AddTechnique("T1027", 0.6f,
            "Defense evasion detected (BehaviorFlag::DefenseEvasion)");
        m_impl->AddTechnique("T1140", 0.5f,
            "Defense evasion may involve deobfuscation");
        m_impl->AddTechnique("T1562.001", 0.5f,
            "Defense evasion may disable security tools");
    }

    if (HasFlag(flags, BehaviorFlag::CodeInjection)) {
        m_impl->AddTechnique("T1055", 0.8f,
            "Code injection detected (BehaviorFlag::CodeInjection)");
        m_impl->AddTechnique("T1055.002", 0.6f,
            "Code injection may use PE injection");
        m_impl->AddTechnique("T1106", 0.5f,
            "Code injection uses native API");
    }

    if (HasFlag(flags, BehaviorFlag::ProcessHollowing)) {
        m_impl->AddTechnique("T1055.012", 0.9f,
            "Process hollowing detected (BehaviorFlag::ProcessHollowing)");
        m_impl->AddTechnique("T1055", 0.8f,
            "Process hollowing is a process injection technique");
    }

    if (HasFlag(flags, BehaviorFlag::DLLInjection)) {
        m_impl->AddTechnique("T1055.001", 0.85f,
            "DLL injection detected (BehaviorFlag::DLLInjection)");
        m_impl->AddTechnique("T1055", 0.75f,
            "DLL injection is a process injection technique");
        m_impl->AddTechnique("T1129", 0.6f,
            "DLL injection involves loading shared modules");
    }

    if (HasFlag(flags, BehaviorFlag::Keylogging)) {
        m_impl->AddTechnique("T1056.001", 0.85f,
            "Keylogging detected (BehaviorFlag::Keylogging)");
        m_impl->AddTechnique("T1056.001C", 0.8f,
            "Keylogging for data collection");
    }

    if (HasFlag(flags, BehaviorFlag::ScreenCapture)) {
        m_impl->AddTechnique("T1113", 0.8f,
            "Screen capture detected (BehaviorFlag::ScreenCapture)");
    }

    if (HasFlag(flags, BehaviorFlag::ServiceManipulation)) {
        m_impl->AddTechnique("T1543.003", 0.7f,
            "Service manipulation detected (BehaviorFlag::ServiceManipulation)");
        m_impl->AddTechnique("T1007", 0.5f,
            "Service manipulation implies service discovery");
        m_impl->AddTechnique("T1489", 0.4f,
            "Service manipulation may stop services");
    }

    if (HasFlag(flags, BehaviorFlag::WMIExecution)) {
        m_impl->AddTechnique("T1047", 0.8f,
            "WMI execution detected (BehaviorFlag::WMIExecution)");
        m_impl->AddTechnique("T1546.003", 0.5f,
            "WMI may be used for event subscription persistence");
    }

    if (HasFlag(flags, BehaviorFlag::PowershellExecution)) {
        m_impl->AddTechnique("T1059.001", 0.8f,
            "PowerShell execution detected (BehaviorFlag::PowershellExecution)");
        m_impl->AddTechnique("T1027.010", 0.5f,
            "PowerShell may use command obfuscation");
    }

    if (HasFlag(flags, BehaviorFlag::SuspiciousAPI)) {
        m_impl->AddTechnique("T1106", 0.5f,
            "Suspicious API usage pattern (BehaviorFlag::SuspiciousAPI)");
    }
}

// ============================================================================
// OnAPICall — map specific API calls to techniques
// ============================================================================

void MITREMapper::OnAPICall(const APICallDetail& call) noexcept {
    if (!call.funcName) return;

    std::unique_lock lock(m_impl->mutex);

    std::string_view func(call.funcName);
    std::string evidence = std::string("API call: ") + call.funcName;
    if (call.dllName) {
        evidence += " from ";
        evidence += call.dllName;
    }

    // === Execution APIs ===
    if (func == "CreateProcessA" || func == "CreateProcessW" ||
        func == "CreateProcessInternalW") {
        m_impl->AddTechnique("T1106", 0.6f, evidence);
    }
    if (func == "WinExec" || func == "ShellExecuteA" || func == "ShellExecuteW" ||
        func == "ShellExecuteExA" || func == "ShellExecuteExW") {
        m_impl->AddTechnique("T1106", 0.6f, evidence);
        m_impl->AddTechnique("T1204.002", 0.4f, evidence);
    }
    if (func == "LoadLibraryA" || func == "LoadLibraryW" ||
        func == "LoadLibraryExA" || func == "LoadLibraryExW" ||
        func == "LdrLoadDll") {
        m_impl->AddTechnique("T1129", 0.5f, evidence);
    }

    // === Process Injection APIs ===
    if (func == "VirtualAllocEx" || func == "NtAllocateVirtualMemory") {
        m_impl->AddTechnique("T1055", 0.5f, evidence);
    }
    if (func == "WriteProcessMemory" || func == "NtWriteVirtualMemory") {
        m_impl->AddTechnique("T1055", 0.7f, evidence);
        m_impl->AddTechnique("T1055.002", 0.6f, evidence);
    }
    if (func == "CreateRemoteThread" || func == "CreateRemoteThreadEx" ||
        func == "NtCreateThreadEx") {
        m_impl->AddTechnique("T1055", 0.8f, evidence);
        m_impl->AddTechnique("T1055.003", 0.6f, evidence);
    }
    if (func == "QueueUserAPC" || func == "NtQueueApcThread") {
        m_impl->AddTechnique("T1055.004", 0.7f, evidence);
        m_impl->AddTechnique("T1055", 0.6f, evidence);
    }
    if (func == "NtUnmapViewOfSection" || func == "NtMapViewOfSection") {
        m_impl->AddTechnique("T1055.012", 0.6f, evidence);
    }
    if (func == "SetThreadContext" || func == "NtSetContextThread") {
        m_impl->AddTechnique("T1055.003", 0.7f, evidence);
    }
    if (func == "ResumeThread" || func == "NtResumeThread") {
        m_impl->AddTechnique("T1055.012", 0.4f, evidence);
    }

    // === Registry Persistence APIs ===
    if (func == "RegSetValueExA" || func == "RegSetValueExW" ||
        func == "NtSetValueKey") {
        m_impl->AddTechnique("T1547.001", 0.5f, evidence);
        m_impl->AddTechnique("T1012", 0.4f, evidence);
    }
    if (func == "RegCreateKeyExA" || func == "RegCreateKeyExW" ||
        func == "NtCreateKey") {
        m_impl->AddTechnique("T1547.001", 0.4f, evidence);
    }
    if (func == "RegDeleteKeyA" || func == "RegDeleteKeyW" ||
        func == "RegDeleteValueA" || func == "RegDeleteValueW") {
        m_impl->AddTechnique("T1070.004", 0.3f, evidence);
        m_impl->AddTechnique("T1012", 0.3f, evidence);
    }
    if (func == "RegOpenKeyExA" || func == "RegOpenKeyExW" ||
        func == "NtOpenKey") {
        m_impl->AddTechnique("T1012", 0.4f, evidence);
    }
    if (func == "RegQueryValueExA" || func == "RegQueryValueExW" ||
        func == "NtQueryValueKey") {
        m_impl->AddTechnique("T1012", 0.4f, evidence);
    }

    // === Service APIs ===
    if (func == "CreateServiceA" || func == "CreateServiceW") {
        m_impl->AddTechnique("T1543.003", 0.7f, evidence);
    }
    if (func == "StartServiceA" || func == "StartServiceW" ||
        func == "ControlService") {
        m_impl->AddTechnique("T1543.003", 0.5f, evidence);
        m_impl->AddTechnique("T1489", 0.4f, evidence);
    }
    if (func == "OpenServiceA" || func == "OpenServiceW" ||
        func == "EnumServicesStatusA" || func == "EnumServicesStatusW") {
        m_impl->AddTechnique("T1007", 0.5f, evidence);
    }

    // === Scheduled Task APIs ===
    if (func == "ITaskService_Connect" || func == "ITaskFolder_RegisterTask") {
        m_impl->AddTechnique("T1053.005", 0.7f, evidence);
    }

    // === Token Manipulation APIs ===
    if (func == "OpenProcessToken" || func == "NtOpenProcessToken") {
        m_impl->AddTechnique("T1134.001", 0.5f, evidence);
    }
    if (func == "DuplicateTokenEx" || func == "NtDuplicateToken") {
        m_impl->AddTechnique("T1134.001", 0.7f, evidence);
    }
    if (func == "ImpersonateLoggedOnUser" || func == "SetThreadToken") {
        m_impl->AddTechnique("T1134.001", 0.7f, evidence);
    }
    if (func == "CreateProcessAsUserA" || func == "CreateProcessAsUserW" ||
        func == "CreateProcessWithTokenW") {
        m_impl->AddTechnique("T1134.002", 0.7f, evidence);
    }
    if (func == "AdjustTokenPrivileges") {
        m_impl->AddTechnique("T1134.001", 0.5f, evidence);
    }

    // === Credential Access APIs ===
    if (func == "CredEnumerateA" || func == "CredEnumerateW" ||
        func == "CredReadA" || func == "CredReadW") {
        m_impl->AddTechnique("T1552.001", 0.6f, evidence);
    }
    if (func == "CryptUnprotectData") {
        m_impl->AddTechnique("T1555.003", 0.7f, evidence);
        m_impl->AddTechnique("T1140", 0.4f, evidence);
    }
    if (func == "LsaRetrievePrivateData") {
        m_impl->AddTechnique("T1003.004", 0.7f, evidence);
    }

    // === Keylogging APIs ===
    if (func == "SetWindowsHookExA" || func == "SetWindowsHookExW") {
        m_impl->AddTechnique("T1056.001", 0.7f, evidence);
        m_impl->AddTechnique("T1056.001C", 0.6f, evidence);
    }
    if (func == "GetAsyncKeyState" || func == "GetKeyState" ||
        func == "GetKeyboardState") {
        m_impl->AddTechnique("T1056.001", 0.6f, evidence);
    }

    // === Screen Capture APIs ===
    if (func == "BitBlt" || func == "GetDC" || func == "CreateCompatibleDC") {
        m_impl->AddTechnique("T1113", 0.5f, evidence);
    }

    // === Clipboard APIs ===
    if (func == "GetClipboardData" || func == "OpenClipboard") {
        m_impl->AddTechnique("T1115", 0.6f, evidence);
    }

    // === Network / C2 APIs ===
    if (func == "InternetOpenA" || func == "InternetOpenW" ||
        func == "WinHttpOpen") {
        m_impl->AddTechnique("T1071.001", 0.4f, evidence);
    }
    if (func == "InternetConnectA" || func == "InternetConnectW" ||
        func == "WinHttpConnect") {
        m_impl->AddTechnique("T1071.001", 0.5f, evidence);
    }
    if (func == "HttpOpenRequestA" || func == "HttpOpenRequestW" ||
        func == "WinHttpOpenRequest") {
        m_impl->AddTechnique("T1071.001", 0.6f, evidence);
    }
    if (func == "InternetOpenUrlA" || func == "InternetOpenUrlW") {
        m_impl->AddTechnique("T1071.001", 0.6f, evidence);
        m_impl->AddTechnique("T1105", 0.5f, evidence);
    }
    if (func == "URLDownloadToFileA" || func == "URLDownloadToFileW" ||
        func == "URLDownloadToCacheFileA" || func == "URLDownloadToCacheFileW") {
        m_impl->AddTechnique("T1105", 0.7f, evidence);
        m_impl->AddTechnique("T1071.001", 0.5f, evidence);
    }
    if (func == "DnsQuery_A" || func == "DnsQuery_W" ||
        func == "getaddrinfo" || func == "GetAddrInfoW") {
        m_impl->AddTechnique("T1071.004", 0.4f, evidence);
    }
    if (func == "connect") {
        m_impl->AddTechnique("T1095", 0.4f, evidence);
    }
    if (func == "send" || func == "WSASend") {
        m_impl->AddTechnique("T1095", 0.4f, evidence);
        m_impl->AddTechnique("T1041", 0.3f, evidence);
    }
    if (func == "recv" || func == "WSARecv") {
        m_impl->AddTechnique("T1095", 0.3f, evidence);
    }

    // === File APIs ===
    if (func == "DeleteFileA" || func == "DeleteFileW" ||
        func == "NtDeleteFile") {
        m_impl->AddTechnique("T1070.004", 0.5f, evidence);
    }
    if (func == "MoveFileA" || func == "MoveFileW" ||
        func == "MoveFileExA" || func == "MoveFileExW") {
        m_impl->AddTechnique("T1036.005", 0.3f, evidence);
    }
    if (func == "SetFileTime" || func == "NtSetInformationFile") {
        m_impl->AddTechnique("T1070.006", 0.5f, evidence);
    }
    if (func == "FindFirstFileA" || func == "FindFirstFileW" ||
        func == "FindNextFileA" || func == "FindNextFileW") {
        m_impl->AddTechnique("T1083", 0.4f, evidence);
    }

    // === Discovery APIs ===
    if (func == "GetComputerNameA" || func == "GetComputerNameW" ||
        func == "GetComputerNameExA" || func == "GetComputerNameExW") {
        m_impl->AddTechnique("T1082", 0.4f, evidence);
    }
    if (func == "GetVersionExA" || func == "GetVersionExW" ||
        func == "RtlGetVersion" || func == "GetSystemInfo" ||
        func == "GetNativeSystemInfo") {
        m_impl->AddTechnique("T1082", 0.4f, evidence);
    }
    if (func == "GetUserNameA" || func == "GetUserNameW") {
        m_impl->AddTechnique("T1033", 0.5f, evidence);
    }
    if (func == "GetAdaptersInfo" || func == "GetAdaptersAddresses" ||
        func == "GetNetworkParams") {
        m_impl->AddTechnique("T1016", 0.5f, evidence);
    }
    if (func == "GetTcpTable" || func == "GetUdpTable" ||
        func == "GetExtendedTcpTable") {
        m_impl->AddTechnique("T1049", 0.5f, evidence);
    }
    if (func == "EnumProcesses" || func == "CreateToolhelp32Snapshot" ||
        func == "Process32First" || func == "Process32FirstW" ||
        func == "Process32Next" || func == "Process32NextW" ||
        func == "NtQuerySystemInformation") {
        m_impl->AddTechnique("T1057", 0.5f, evidence);
    }
    if (func == "NetShareEnum" || func == "WNetEnumResourceA" ||
        func == "WNetEnumResourceW") {
        m_impl->AddTechnique("T1135", 0.6f, evidence);
    }
    if (func == "NetServerEnum" || func == "NetGetDCName") {
        m_impl->AddTechnique("T1018", 0.5f, evidence);
    }

    // === Crypto APIs ===
    if (func == "CryptEncrypt" || func == "BCryptEncrypt") {
        m_impl->AddTechnique("T1486", 0.4f, evidence);
        m_impl->AddTechnique("T1573.001", 0.3f, evidence);
    }
    if (func == "CryptDecrypt" || func == "BCryptDecrypt") {
        m_impl->AddTechnique("T1140", 0.4f, evidence);
        m_impl->AddTechnique("T1573.001", 0.3f, evidence);
    }
    if (func == "CryptGenKey" || func == "BCryptGenerateSymmetricKey") {
        m_impl->AddTechnique("T1573.001", 0.3f, evidence);
    }
    if (func == "CryptImportKey" || func == "BCryptImportKeyPair") {
        m_impl->AddTechnique("T1573.002", 0.3f, evidence);
    }

    // === Anti-Debug / Anti-VM APIs ===
    if (func == "IsDebuggerPresent" || func == "CheckRemoteDebuggerPresent" ||
        func == "NtQueryInformationProcess") {
        m_impl->AddTechnique("T1497.001", 0.6f, evidence);
    }
    if (func == "GetTickCount" || func == "GetTickCount64" ||
        func == "QueryPerformanceCounter") {
        m_impl->AddTechnique("T1497.003", 0.3f, evidence);
    }

    // === Defense Evasion APIs ===
    if (func == "VirtualProtect" || func == "VirtualProtectEx" ||
        func == "NtProtectVirtualMemory") {
        m_impl->AddTechnique("T1055", 0.4f, evidence);
    }
    if (func == "OpenEventLogA" || func == "OpenEventLogW" ||
        func == "ClearEventLogA" || func == "ClearEventLogW") {
        m_impl->AddTechnique("T1070.001", 0.7f, evidence);
    }
    if (func == "TerminateProcess") {
        m_impl->AddTechnique("T1562.001", 0.4f, evidence);
    }

    // === Security Software Discovery ===
    // Often done via process enumeration or service enumeration
    if (func == "EnumServicesStatusA" || func == "EnumServicesStatusW" ||
        func == "EnumServicesStatusExA" || func == "EnumServicesStatusExW") {
        m_impl->AddTechnique("T1518.001", 0.4f, evidence);
        m_impl->AddTechnique("T1007", 0.5f, evidence);
    }

    // === BITS Jobs ===
    if (func == "IBackgroundCopyManager_CreateJob") {
        m_impl->AddTechnique("T1197", 0.7f, evidence);
    }

    // === Rundll32 proxy execution ===
    // Detected when command line contains "rundll32"
    // (handled via OnProcessCreate in IOCExtractor but also flagged here)

    // === Firewall manipulation ===
    if (func == "INetFwPolicy2_put_FirewallEnabled") {
        m_impl->AddTechnique("T1562.004", 0.8f, evidence);
    }

    // === Lateral Movement APIs ===
    if (func == "WNetAddConnection2A" || func == "WNetAddConnection2W") {
        m_impl->AddTechnique("T1021.002", 0.6f, evidence);
    }

    // === Data Collection APIs ===
    if (func == "ReadFile" || func == "NtReadFile") {
        m_impl->AddTechnique("T1005", 0.2f, evidence);
    }

    // === General native API usage marker ===
    if (call.dllName) {
        std::string_view dll(call.dllName);
        if (dll == "ntdll.dll" && func.starts_with("Nt")) {
            m_impl->AddTechnique("T1106", 0.3f, evidence);
        }
    }
}

// ============================================================================
// OnMemoryFinding
// ============================================================================

void MITREMapper::OnMemoryFinding(const MemoryFindingDetail& finding) noexcept {
    std::unique_lock lock(m_impl->mutex);

    float conf = std::clamp(finding.confidence, 0.0f, 1.0f);
    const std::string& desc = finding.description;

    switch (finding.type) {
        case MemoryFinding::PEHeaderInMemory:
        case MemoryFinding::PEDOSStub:
        case MemoryFinding::PEImportTable:
        case MemoryFinding::PEExportTable:
        case MemoryFinding::ReflectiveDLLStub:
            m_impl->AddTechnique("T1055.002", conf,
                "PE injection detected in memory: " + desc);
            m_impl->AddTechnique("T1055", conf * 0.8f,
                "PE injection is a process injection sub-technique");
            break;

        case MemoryFinding::ShellcodeNopSled:
        case MemoryFinding::ShellcodeDecoderStub:
        case MemoryFinding::ShellcodeEggHunter:
        case MemoryFinding::ShellcodeEncodedPayload:
        case MemoryFinding::StackShellcode:
            m_impl->AddTechnique("T1055", conf * 0.7f,
                "Shellcode detected: " + desc);
            m_impl->AddTechnique("T1106", conf * 0.6f,
                "Shellcode typically calls native API directly");
            break;

        case MemoryFinding::ROPGadgetChain:
            m_impl->AddTechnique("T1068", conf,
                "ROP chain detected — exploitation technique: " + desc);
            break;

        case MemoryFinding::WriteExecuteTransition:
        case MemoryFinding::SelfModifyingCode:
            m_impl->AddTechnique("T1055", conf * 0.6f,
                "Write-then-execute transition: " + desc);
            m_impl->AddTechnique("T1027", conf * 0.4f,
                "W→X transition may indicate runtime deobfuscation");
            m_impl->AddTechnique("T1140", conf * 0.5f,
                "W→X transition may indicate payload decoding");
            break;

        case MemoryFinding::HollowedProcess:
            m_impl->AddTechnique("T1055.012", conf,
                "Process hollowing confirmed via memory analysis: " + desc);
            m_impl->AddTechnique("T1055", conf * 0.8f,
                "Process hollowing is a process injection technique");
            break;

        case MemoryFinding::HighEntropyRegion:
            m_impl->AddTechnique("T1027.002", conf * 0.8f,
                "High-entropy region detected — possible packed/encrypted payload: " + desc);
            m_impl->AddTechnique("T1140", conf * 0.6f,
                "High entropy implies obfuscated or encoded content");
            break;

        case MemoryFinding::HeapSprayPattern:
        case MemoryFinding::HeapSprayNopRun:
            m_impl->AddTechnique("T1068", conf * 0.8f,
                "Heap spray detected — exploit preparation: " + desc);
            break;

        case MemoryFinding::StackPivotDetected:
            m_impl->AddTechnique("T1068", conf,
                "Stack pivot detected — exploitation technique: " + desc);
            break;

        case MemoryFinding::CodeCaveUsed:
            m_impl->AddTechnique("T1055", conf * 0.7f,
                "Code cave usage: " + desc);
            m_impl->AddTechnique("T1027", conf * 0.5f,
                "Code cave usage may conceal injected code");
            break;

        case MemoryFinding::TrampolineCode:
        case MemoryFinding::IATPatchDetected:
            m_impl->AddTechnique("T1055", conf * 0.6f,
                "Function trampoline detected: " + desc);
            m_impl->AddTechnique("T1562.001", conf * 0.5f,
                "Trampoline may be used to hook/modify security tools");
            break;

        case MemoryFinding::XOREncodedBlock:
        case MemoryFinding::Base64EncodedBlock:
            m_impl->AddTechnique("T1140", conf * 0.7f,
                "Encoded block detected in memory: " + desc);
            m_impl->AddTechnique("T1027", conf * 0.6f,
                "Encoded memory block indicates obfuscation: " + desc);
            break;

        case MemoryFinding::SuspiciousStringTable:
            m_impl->AddTechnique("T1005", conf * 0.5f,
                "Suspicious string table in memory: " + desc);
            m_impl->AddTechnique("T1027", conf * 0.4f,
                "Suspicious strings may indicate obfuscated data");
            break;

        default:
            break;
    }
}

// ============================================================================
// OnPackerDetected
// ============================================================================

void MITREMapper::OnPackerDetected(PackerType packer) noexcept {
    std::unique_lock lock(m_impl->mutex);

    std::string evidence = "Packer detected: ";
    switch (packer) {
        case PackerType::UPX:              evidence += "UPX"; break;
        case PackerType::ASPack:           evidence += "ASPack"; break;
        case PackerType::PECompact:        evidence += "PECompact"; break;
        case PackerType::Themida:          evidence += "Themida"; break;
        case PackerType::VMProtect:        evidence += "VMProtect"; break;
        case PackerType::Enigma:           evidence += "Enigma Protector"; break;
        case PackerType::MPRESS:           evidence += "MPRESS"; break;
        case PackerType::Petite:           evidence += "Petite"; break;
        case PackerType::NsPack:           evidence += "NSPack"; break;
        case PackerType::FSG:              evidence += "FSG"; break;
        case PackerType::MEW:              evidence += "MEW"; break;
        case PackerType::Armadillo:        evidence += "Armadillo"; break;
        case PackerType::ExeCryptor:       evidence += "ExeCryptor"; break;
        case PackerType::PackerCustom:     evidence += "Custom packer"; break;
        case PackerType::PEtite:           evidence += "PEtite"; break;
        case PackerType::Obsidium:         evidence += "Obsidium"; break;
        case PackerType::ASProtect:        evidence += "ASProtect"; break;
        case PackerType::tElock:           evidence += "tElock"; break;
        case PackerType::PESpin:           evidence += "PESpin"; break;
        case PackerType::MoleBox:          evidence += "MoleBox"; break;
        case PackerType::BoxedApp:         evidence += "BoxedApp"; break;
        case PackerType::StarForce:        evidence += "StarForce"; break;
        case PackerType::SafeDisc:         evidence += "SafeDisc"; break;
        case PackerType::SecuROM:          evidence += "SecuROM"; break;
        case PackerType::CodeVirtualizer:  evidence += "CodeVirtualizer"; break;
        case PackerType::DotNetObfuscator: evidence += "DotNetObfuscator"; break;
        case PackerType::AutoIt:           evidence += "AutoIt"; break;
        case PackerType::NSIS:             evidence += "NSIS"; break;
        case PackerType::InnoSetup:        evidence += "InnoSetup"; break;
        case PackerType::PyInstaller:      evidence += "PyInstaller"; break;
        case PackerType::Unknown:          evidence += "Unknown packer"; break;
        default:                           evidence += "Unidentified packer"; break;
    }

    float conf = 0.8f;
    // Advanced protectors get higher confidence for evasion mapping
    switch (packer) {
        case PackerType::Themida:
        case PackerType::VMProtect:
        case PackerType::Enigma:
        case PackerType::Armadillo:
        case PackerType::ExeCryptor:
        case PackerType::Obsidium:
        case PackerType::ASProtect:
        case PackerType::StarForce:
        case PackerType::SafeDisc:
        case PackerType::SecuROM:
        case PackerType::CodeVirtualizer:
            conf = 0.9f;
            m_impl->AddTechnique("T1027.002", conf, evidence);
            m_impl->AddTechnique("T1027", conf * 0.7f,
                "Advanced packer implies heavy obfuscation: " + evidence);
            m_impl->AddTechnique("T1497.001", 0.5f,
                "Advanced packers often include anti-VM checks");
            m_impl->AddTechnique("T1497.003", 0.4f,
                "Advanced packers may use timing-based evasion");
            break;

        case PackerType::Unknown:
            break;

        default:
            m_impl->AddTechnique("T1027.002", conf, evidence);
            m_impl->AddTechnique("T1027", conf * 0.5f,
                "Software packing implies obfuscation");
            break;
    }
}

// ============================================================================
// OnEvasionAttempt
// ============================================================================

void MITREMapper::OnEvasionAttempt(const std::string& technique) noexcept {
    std::unique_lock lock(m_impl->mutex);

    std::string evidence = "Evasion technique: " + technique;

    // Map specific evasion technique names to MITRE techniques
    if (technique.find("timing") != std::string::npos ||
        technique.find("sleep") != std::string::npos ||
        technique.find("delay") != std::string::npos) {
        m_impl->AddTechnique("T1497.003", 0.7f, evidence);
    }

    if (technique.find("VM") != std::string::npos ||
        technique.find("virtual") != std::string::npos ||
        technique.find("sandbox") != std::string::npos ||
        technique.find("hypervisor") != std::string::npos) {
        m_impl->AddTechnique("T1497.001", 0.7f, evidence);
    }

    if (technique.find("debug") != std::string::npos ||
        technique.find("breakpoint") != std::string::npos) {
        m_impl->AddTechnique("T1497.001", 0.6f, evidence);
    }

    if (technique.find("obfuscat") != std::string::npos ||
        technique.find("encrypt") != std::string::npos) {
        m_impl->AddTechnique("T1027", 0.6f, evidence);
        m_impl->AddTechnique("T1027.010", 0.5f, evidence);
    }

    if (technique.find("event log") != std::string::npos) {
        m_impl->AddTechnique("T1070.001", 0.7f, evidence);
    }

    if (technique.find("timestomp") != std::string::npos) {
        m_impl->AddTechnique("T1070.006", 0.8f, evidence);
    }

    if (technique.find("firewall") != std::string::npos) {
        m_impl->AddTechnique("T1562.004", 0.7f, evidence);
    }

    if (technique.find("disable") != std::string::npos &&
        (technique.find("AV") != std::string::npos ||
         technique.find("antivirus") != std::string::npos ||
         technique.find("defender") != std::string::npos ||
         technique.find("security") != std::string::npos)) {
        m_impl->AddTechnique("T1562.001", 0.8f, evidence);
    }

    if (technique.find("UAC") != std::string::npos ||
        technique.find("elevation") != std::string::npos) {
        m_impl->AddTechnique("T1548.002", 0.7f, evidence);
    }

    if (technique.find("masquerade") != std::string::npos ||
        technique.find("rename") != std::string::npos) {
        m_impl->AddTechnique("T1036.005", 0.6f, evidence);
    }

    if (technique.find("rundll32") != std::string::npos) {
        m_impl->AddTechnique("T1218.011", 0.7f, evidence);
    }

    if (technique.find("XSL") != std::string::npos ||
        technique.find("xsl") != std::string::npos) {
        m_impl->AddTechnique("T1220", 0.7f, evidence);
    }

    if (technique.find("BITS") != std::string::npos) {
        m_impl->AddTechnique("T1197", 0.6f, evidence);
    }

    if (technique.find("tunnel") != std::string::npos ||
        technique.find("proxy") != std::string::npos) {
        m_impl->AddTechnique("T1572", 0.6f, evidence);
        m_impl->AddTechnique("T1090", 0.5f, evidence);
    }

    if (technique.find("doppelgang") != std::string::npos) {
        m_impl->AddTechnique("T1055.013", 0.8f, evidence);
    }

    if (technique.find("TLS callback") != std::string::npos) {
        m_impl->AddTechnique("T1055.005", 0.7f, evidence);
    }

    if (technique.find("delete") != std::string::npos &&
        technique.find("file") != std::string::npos) {
        m_impl->AddTechnique("T1070.004", 0.6f, evidence);
    }

    if (technique.find("COM hijack") != std::string::npos) {
        m_impl->AddTechnique("T1546.015", 0.7f, evidence);
    }

    if (technique.find("web shell") != std::string::npos) {
        m_impl->AddTechnique("T1505.003", 0.7f, evidence);
    }

    if (technique.find("WinRM") != std::string::npos ||
        technique.find("winrm") != std::string::npos) {
        m_impl->AddTechnique("T1021.006", 0.6f, evidence);
    }

    if (technique.find("DCOM") != std::string::npos) {
        m_impl->AddTechnique("T1021.003", 0.6f, evidence);
    }

    if (technique.find("port monitor") != std::string::npos) {
        m_impl->AddTechnique("T1547.010", 0.7f, evidence);
    }

    if (technique.find("Winlogon") != std::string::npos) {
        m_impl->AddTechnique("T1547.004", 0.7f, evidence);
    }

    if (technique.find("SAM") != std::string::npos &&
        technique.find("dump") != std::string::npos) {
        m_impl->AddTechnique("T1003.002", 0.7f, evidence);
    }

    if (technique.find("LSASS") != std::string::npos ||
        technique.find("lsass") != std::string::npos) {
        m_impl->AddTechnique("T1003.001", 0.7f, evidence);
    }

    if (technique.find("LSA") != std::string::npos &&
        technique.find("secret") != std::string::npos) {
        m_impl->AddTechnique("T1003.004", 0.7f, evidence);
    }

    if (technique.find("browser") != std::string::npos &&
        (technique.find("credential") != std::string::npos ||
         technique.find("password") != std::string::npos)) {
        m_impl->AddTechnique("T1555.003", 0.7f, evidence);
    }

    if (technique.find("Base64") != std::string::npos ||
        technique.find("base64") != std::string::npos) {
        m_impl->AddTechnique("T1132.001", 0.5f, evidence);
    }

    if (technique.find("cloud") != std::string::npos &&
        technique.find("exfil") != std::string::npos) {
        m_impl->AddTechnique("T1567.002", 0.6f, evidence);
    }

    if (technique.find("shutdown") != std::string::npos ||
        technique.find("reboot") != std::string::npos) {
        m_impl->AddTechnique("T1529", 0.6f, evidence);
    }

    if (technique.find("disk wipe") != std::string::npos ||
        technique.find("MBR") != std::string::npos) {
        m_impl->AddTechnique("T1561.002", 0.8f, evidence);
        m_impl->AddTechnique("T1561.001", 0.6f, evidence);
    }

    if (technique.find("recovery") != std::string::npos &&
        technique.find("inhibit") != std::string::npos) {
        m_impl->AddTechnique("T1490", 0.7f, evidence);
    }

    if (technique.find("shadow") != std::string::npos &&
        technique.find("copy") != std::string::npos) {
        m_impl->AddTechnique("T1490", 0.8f, evidence);
    }

    if (technique.find("VB") != std::string::npos ||
        technique.find("VBScript") != std::string::npos) {
        m_impl->AddTechnique("T1059.005", 0.6f, evidence);
    }

    if (technique.find("JavaScript") != std::string::npos ||
        technique.find("JScript") != std::string::npos) {
        m_impl->AddTechnique("T1059.007", 0.6f, evidence);
    }

    if (technique.find("cmd") != std::string::npos ||
        technique.find("command shell") != std::string::npos) {
        m_impl->AddTechnique("T1059.003", 0.5f, evidence);
    }

    if (technique.find("VDSO") != std::string::npos) {
        m_impl->AddTechnique("T1055.014", 0.7f, evidence);
    }

    if (technique.find("ptrace") != std::string::npos) {
        m_impl->AddTechnique("T1055.008", 0.7f, evidence);
    }
}

// ============================================================================
// GetMappedTechniques
// ============================================================================

const std::vector<MITRETechnique>& MITREMapper::GetMappedTechniques() const noexcept {
    return m_impl->mapped;
}

// ============================================================================
// GetTechniqueCount
// ============================================================================

uint32_t MITREMapper::GetTechniqueCount() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->mapped.size());
}

// ============================================================================
// GetTacticSummary
// ============================================================================

std::vector<MITRETacticSummary> MITREMapper::GetTacticSummary() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    std::unordered_map<std::string_view, MITRETacticSummary> tacticMap;

    for (const auto& tech : m_impl->mapped) {
        if (!tech.tactic) continue;
        std::string_view tactic(tech.tactic);
        auto& summary = tacticMap[tactic];
        summary.tactic = tech.tactic;
        summary.techniqueCount++;
        if (tech.confidence > summary.maxConfidence) {
            summary.maxConfidence = tech.confidence;
        }
    }

    std::vector<MITRETacticSummary> result;
    result.reserve(tacticMap.size());
    for (const auto& [_, summary] : tacticMap) {
        result.push_back(summary);
    }

    // Sort by technique count descending
    std::sort(result.begin(), result.end(),
              [](const MITRETacticSummary& a, const MITRETacticSummary& b) {
                  return a.techniqueCount > b.techniqueCount;
              });

    return result;
}

// ============================================================================
// GetByTactic
// ============================================================================

std::vector<const MITRETechnique*> MITREMapper::GetByTactic(const char* tactic) const noexcept {
    std::shared_lock lock(m_impl->mutex);

    std::vector<const MITRETechnique*> result;
    if (!tactic) return result;

    for (const auto& tech : m_impl->mapped) {
        if (tech.tactic && std::strcmp(tech.tactic, tactic) == 0) {
            result.push_back(&tech);
        }
    }

    return result;
}

// ============================================================================
// GetById
// ============================================================================

const MITRETechnique* MITREMapper::GetById(const char* id) const noexcept {
    std::shared_lock lock(m_impl->mutex);

    if (!id) return nullptr;
    auto it = m_impl->idToIndex.find(id);
    if (it == m_impl->idToIndex.end()) return nullptr;
    return &m_impl->mapped[it->second];
}

// ============================================================================
// GetKillChainCoverage — count distinct tactics observed
// ============================================================================

uint32_t MITREMapper::GetKillChainCoverage() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    std::unordered_set<std::string_view> observedTactics;
    for (const auto& tech : m_impl->mapped) {
        if (tech.tactic) {
            observedTactics.insert(tech.tactic);
        }
    }

    return static_cast<uint32_t>(observedTactics.size());
}

// ============================================================================
// Reset
// ============================================================================

void MITREMapper::Reset() noexcept {
    std::unique_lock lock(m_impl->mutex);

    m_impl->mapped.clear();
    m_impl->idToIndex.clear();
}

} // namespace Phantom
