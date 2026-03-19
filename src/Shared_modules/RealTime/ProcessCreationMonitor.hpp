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
 * ShadowStrike Real-Time - PROCESS CREATION MONITOR (The Overseer)
 * ============================================================================
 *
 * @file ProcessCreationMonitor.hpp
 * @brief Enterprise-grade process execution monitoring and prevention.
 *
 * This module monitors all process creation events system-wide, enabling:
 * - Pre-execution scanning to block malware before first instruction
 * - Parent-child relationship tracking for attack chain detection
 * - Command line analysis for living-off-the-land attack detection
 * - Process genealogy tracking for forensics
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Pre-Execution Scanning**
 *    - Scan executable before process starts
 *    - Block known malware
 *    - Detect packed/encrypted executables
 *    - Check against threat intelligence
 *
 * 2. **Parent-Child Tracking**
 *    - Build process tree
 *    - Detect suspicious spawn patterns
 *    - Track document→script→powershell chains
 *    - Identify process injection indicators
 *
 * 3. **Command Line Analysis**
 *    - Detect obfuscated commands
 *    - Identify LOLBAS attacks
 *    - Extract IOCs from arguments
 *    - Check for encoding/download patterns
 *
 * 4. **Process Genealogy**
 *    - Complete process history
 *    - Session tracking
 *    - User attribution
 *    - Timeline reconstruction
 *
 * 5. **Execution Prevention**
 *    - Block by hash
 *    - Block by path pattern
 *    - Block by parent chain
 *    - Block by command line
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          KERNEL MODE                                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │              PsSetCreateProcessNotifyRoutineEx2                      │   │
 * │  │                                                                       │   │
 * │  │  - Called BEFORE process main thread starts                          │   │
 * │  │  - Can block process creation (return STATUS_ACCESS_DENIED)          │   │
 * │  │  - Provides: ImageFileName, CommandLine, ParentPID                   │   │
 * │  │                                                                       │   │
 * │  └────────────────────────────────────┬──────────────────────────────────┘   │
 * │                                       │                                      │
 * │                                       │ FilterSendMessage                    │
 * │                                       │                                      │
 * └───────────────────────────────────────┼──────────────────────────────────────┘
 *                                         │
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │ Kernel Boundary
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │
 * ┌───────────────────────────────────────┼──────────────────────────────────────┐
 * │                                       ▼                                      │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    ProcessCreationMonitor                            │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐   │   │
 * │  │  │  Pre-Scan   │  │ Parent-Child│  │  CmdLine    │  │  Policy   │   │   │
 * │  │  │  Decision   │  │  Tracking   │  │  Analysis   │  │  Engine   │   │   │
 * │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘   │   │
 * │  │         │                │                │               │         │   │
 * │  │         └────────────────┴────────────────┴───────────────┘         │   │
 * │  │                                   │                                  │   │
 * │  │                                   ▼                                  │   │
 * │  │  ┌──────────────────────────────────────────────────────────────┐   │   │
 * │  │  │                    Integration Layer                          │   │   │
 * │  │  │  - ScanEngine (file scan)                                     │   │   │
 * │  │  │  - ThreatDetector (behavioral correlation)                    │   │   │
 * │  │  │  - HashStore (allow/block lists)                              │   │   │
 * │  │  │  - Whitelist (trusted applications)                           │   │   │
 * │  │  │  - ThreatIntel (reputation lookup)                            │   │   │
 * │  │  └──────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │                           USER MODE                                          │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * SUSPICIOUS PARENT-CHILD PATTERNS
 * =============================================================================
 *
 * | Parent          | Child              | Risk  | Description                 |
 * |-----------------|--------------------|----- -|----------------------------|
 * | winword.exe     | cmd.exe/powershell | High  | Macro execution             |
 * | excel.exe       | mshta.exe          | High  | DCOM/HTA abuse             |
 * | outlook.exe     | any executable     | High  | Attachment execution        |
 * | explorer.exe    | wscript.exe        | Med   | User script execution       |
 * | services.exe    | cmd.exe            | High  | Service abuse               |
 * | svchost.exe     | non-svchost child  | High  | Process injection           |
 * | wmiprvse.exe    | powershell.exe     | High  | WMI abuse                   |
 * | mshta.exe       | any                | High  | HTA dropper                 |
 * | regsvr32.exe    | any                | High  | Squiblydoo attack           |
 *
 * =============================================================================
 * LOLBAS (Living-Off-The-Land Binaries) DETECTION
 * =============================================================================
 *
 * Monitored binaries:
 * - certutil.exe (download/encode/decode)
 * - mshta.exe (script execution)
 * - regsvr32.exe (COM/script execution)
 * - rundll32.exe (DLL execution)
 * - wmic.exe (WMI execution)
 * - msiexec.exe (MSI execution)
 * - cscript/wscript.exe (script execution)
 * - powershell/pwsh.exe (script execution)
 * - cmd.exe (command execution)
 * - bitsadmin.exe (download)
 * - expand.exe (extraction)
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Description                          | Detection Method         |
 * |-----------|--------------------------------------|--------------------------|
 * | T1059     | Command and Scripting Interpreter    | Parent-child + cmdline   |
 * | T1204     | User Execution                       | Document→process chain   |
 * | T1218     | Signed Binary Proxy Execution        | LOLBAS detection         |
 * | T1055     | Process Injection                    | Hollowed process detect  |
 * | T1106     | Native API                           | Direct syscall detection |
 * | T1569     | System Services                      | Service creation         |
 *
 * @note Thread-safe for all public methods
 * @note Requires kernel driver for true pre-execution blocking
 *
 * @see FileSystemFilter for file scanning
 * @see BehaviorAnalyzer for behavioral correlation
 * @see ThreatDetector for event aggregation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process information
#include "../Utils/StringUtils.hpp"           // Command line parsing
#include "../Utils/FileUtils.hpp"             // Executable analysis
#include "../HashStore/HashStore.hpp"         // Hash-based blocking
#include "../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../PatternStore/PatternStore.hpp"   // LOLBAS patterns
#include "../Whitelist/WhiteListStore.hpp"    // Trusted processes

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace Core {
        namespace Engine {
            class ScanEngine;
            class ThreatDetector;
            class BehaviorAnalyzer;
        }
    }
    namespace HashStore {
        class HashStore;
    }
    namespace Whitelist {
        class WhitelistStore;
    }
    namespace ThreatIntel {
        class ThreatIntelIndex;
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessCreationMonitor;
struct ProcessCreateEvent;
struct ProcessInfo;
struct ProcessTreeNode;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace ProcessMonitorConstants {
    // -------------------------------------------------------------------------
    // Process Tracking
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked processes
    constexpr size_t MAX_TRACKED_PROCESSES = 100000;
    
    /// @brief Process tree depth limit
    constexpr size_t MAX_TREE_DEPTH = 64;
    
    /// @brief Maximum command line length to store
    constexpr size_t MAX_CMDLINE_LENGTH = 32767;
    
    /// @brief Maximum child processes to track per parent
    constexpr size_t MAX_CHILDREN_PER_PROCESS = 1000;
    
    /// @brief Process history retention (terminated processes)
    constexpr std::chrono::hours HISTORY_RETENTION{ 24 };
    
    // -------------------------------------------------------------------------
    // Scanning
    // -------------------------------------------------------------------------
    
    /// @brief Scan timeout for process image
    constexpr uint32_t SCAN_TIMEOUT_MS = 10000;
    
    /// @brief Maximum concurrent scans
    constexpr size_t MAX_CONCURRENT_SCANS = 16;
    
    // -------------------------------------------------------------------------
    // LOLBAS Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief PowerShell encoded command length threshold
    constexpr size_t ENCODED_CMDLINE_THRESHOLD = 100;
    
    /// @brief Base64 blob size threshold
    constexpr size_t BASE64_THRESHOLD = 200;
    
    /// @brief URL count threshold in command line
    constexpr size_t URL_COUNT_THRESHOLD = 1;
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief Suspicious parent-child score
    constexpr double SUSPICIOUS_PARENT_CHILD_SCORE = 40.0;
    
    /// @brief LOLBAS abuse score
    constexpr double LOLBAS_ABUSE_SCORE = 35.0;
    
    /// @brief Encoded command score
    constexpr double ENCODED_COMMAND_SCORE = 30.0;
    
    /// @brief Download command score
    constexpr double DOWNLOAD_COMMAND_SCORE = 25.0;
    
    /// @brief Process from temp folder score
    constexpr double TEMP_FOLDER_EXECUTION_SCORE = 20.0;
    
    /// @brief Unsigned executable score
    constexpr double UNSIGNED_EXECUTABLE_SCORE = 15.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Process creation verdict.
 */
enum class ProcessVerdict : uint8_t {
    /// @brief Allow process creation
    Allow = 0,
    
    /// @brief Block process creation
    Block = 1,
    
    /// @brief Allow but monitor closely
    AllowMonitored = 2,
    
    /// @brief Allow but flag suspicious
    AllowSuspicious = 3,
    
    /// @brief Timeout - use default policy
    Timeout = 4,
    
    /// @brief Error - use default policy
    Error = 5
};

/**
 * @brief Process state.
 */
enum class ProcessState : uint8_t {
    /// @brief Unknown state
    Unknown = 0,
    
    /// @brief Process creating (pre-start)
    Creating = 1,
    
    /// @brief Process running
    Running = 2,
    
    /// @brief Process suspended
    Suspended = 3,
    
    /// @brief Process terminating
    Terminating = 4,
    
    /// @brief Process terminated
    Terminated = 5,
    
    /// @brief Process blocked (never started)
    Blocked = 6
};

/**
 * @brief Process type classification.
 */
enum class ProcessType : uint8_t {
    /// @brief Unknown type
    Unknown = 0,
    
    /// @brief System process
    System = 1,
    
    /// @brief Service
    Service = 2,
    
    /// @brief Console application
    Console = 3,
    
    /// @brief GUI application
    GUI = 4,
    
    /// @brief Background process
    Background = 5,
    
    /// @brief Script interpreter
    ScriptInterpreter = 6,
    
    /// @brief Browser
    Browser = 7,
    
    /// @brief Office application
    Office = 8,
    
    /// @brief Development tool
    DevTool = 9,
    
    /// @brief Security software
    Security = 10,
    
    /// @brief Installer
    Installer = 11,
    
    /// @brief Driver/kernel component
    Driver = 12
};

/**
 * @brief LOLBAS (Living-Off-The-Land Binary) type.
 */
enum class LOLBASType : uint8_t {
    /// @brief Not a LOLBAS
    None = 0,
    
    /// @brief cmd.exe
    Cmd = 1,
    
    /// @brief powershell.exe / pwsh.exe
    PowerShell = 2,
    
    /// @brief wscript.exe / cscript.exe
    WSH = 3,
    
    /// @brief mshta.exe
    Mshta = 4,
    
    /// @brief regsvr32.exe
    Regsvr32 = 5,
    
    /// @brief rundll32.exe
    Rundll32 = 6,
    
    /// @brief certutil.exe
    Certutil = 7,
    
    /// @brief bitsadmin.exe
    Bitsadmin = 8,
    
    /// @brief wmic.exe
    Wmic = 9,
    
    /// @brief msiexec.exe
    Msiexec = 10,
    
    /// @brief expand.exe
    Expand = 11,
    
    /// @brief esentutl.exe
    Esentutl = 12,
    
    /// @brief installutil.exe
    InstallUtil = 13,
    
    /// @brief msbuild.exe
    MSBuild = 14,
    
    /// @brief odbcconf.exe
    ODBCConf = 15,
    
    /// @brief regasm.exe
    RegAsm = 16,
    
    /// @brief regsvcs.exe
    RegSvcs = 17,
    
    /// @brief xwizard.exe
    XWizard = 18,
    
    /// @brief forfiles.exe
    ForFiles = 19,
    
    /// @brief pcalua.exe
    PcaLua = 20,
    
    /// @brief syncappvpublishingserver.exe
    SyncAppv = 21,
    
    /// @brief control.exe
    Control = 22,
    
    /// @brief cmstp.exe
    Cmstp = 23,
    
    /// @brief presentationhost.exe
    PresentationHost = 24,
    
    /// @brief bash.exe / wsl.exe
    WSL = 25
};

/**
 * @brief Suspicious pattern type.
 */
enum class SuspiciousPattern : uint16_t {
    /// @brief No suspicious pattern
    None = 0,
    
    // -------------------------------------------------------------------------
    // Parent-Child Patterns
    // -------------------------------------------------------------------------
    
    /// @brief Office spawning script interpreter
    OfficeSpawnsScript = 1,
    
    /// @brief Office spawning command shell
    OfficeSpawnsShell = 2,
    
    /// @brief Browser spawning executable
    BrowserSpawnsExe = 3,
    
    /// @brief Services.exe spawning shell
    ServicesSpawnsShell = 4,
    
    /// @brief Svchost spawning non-service
    SvchostSpawnsUnexpected = 5,
    
    /// @brief WMI spawning process
    WmiSpawnsProcess = 6,
    
    /// @brief Script interpreter spawning executable
    ScriptSpawnsExe = 7,
    
    /// @brief Mshta spawning anything
    MshtaSpawnsProcess = 8,
    
    // -------------------------------------------------------------------------
    // Command Line Patterns
    // -------------------------------------------------------------------------
    
    /// @brief Encoded PowerShell command
    EncodedPowerShell = 100,
    
    /// @brief Obfuscated command line
    ObfuscatedCmdLine = 101,
    
    /// @brief Download command detected
    DownloadCommand = 102,
    
    /// @brief Bypass execution policy
    BypassExecutionPolicy = 103,
    
    /// @brief Hidden window execution
    HiddenWindowExecution = 104,
    
    /// @brief Reflection/Load assembly
    ReflectionLoad = 105,
    
    /// @brief COM object scripting
    COMScripting = 106,
    
    /// @brief Scheduled task creation
    ScheduledTaskCreation = 107,
    
    /// @brief Service creation
    ServiceCreation = 108,
    
    /// @brief Registry modification
    RegistryModification = 109,
    
    // -------------------------------------------------------------------------
    // Execution Patterns
    // -------------------------------------------------------------------------
    
    /// @brief Execution from temp folder
    TempFolderExecution = 200,
    
    /// @brief Execution from downloads
    DownloadsFolderExecution = 201,
    
    /// @brief Execution from user profile
    UserProfileExecution = 202,
    
    /// @brief Execution from recycle bin
    RecycleBinExecution = 203,
    
    /// @brief Execution from network share
    NetworkShareExecution = 204,
    
    /// @brief Execution from archive
    ArchiveExecution = 205,
    
    /// @brief Double extension (doc.exe)
    DoubleExtension = 206,
    
    /// @brief Masquerading (svchost.exe in wrong path)
    ProcessMasquerading = 207,
    
    // -------------------------------------------------------------------------
    // Injection Indicators
    // -------------------------------------------------------------------------
    
    /// @brief Hollowed process indicator
    ProcessHollowing = 300,
    
    /// @brief Doppelganging indicator
    ProcessDoppelgang = 301,
    
    /// @brief Herpaderping indicator
    ProcessHerpadering = 302,
    
    /// @brief Ghost process indicator
    ProcessGhosting = 303
};

/**
 * @brief Get string for ProcessVerdict.
 */
[[nodiscard]] constexpr const char* ProcessVerdictToString(ProcessVerdict verdict) noexcept;

/**
 * @brief Get string for LOLBASType.
 */
[[nodiscard]] constexpr const char* LOLBASTypeToString(LOLBASType type) noexcept;

/**
 * @brief Get MITRE ATT&CK technique for pattern.
 */
[[nodiscard]] constexpr const char* SuspiciousPatternToMitre(SuspiciousPattern pattern) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Process creation event from kernel.
 */
struct ProcessCreateEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief New process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Creating thread ID
    uint32_t creatingThreadId = 0;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /// @brief Image file path
    std::wstring imagePath;
    
    /// @brief Image file name only
    std::wstring imageFileName;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Current directory
    std::wstring currentDirectory;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Token elevation type
    uint32_t elevationType = 0;
    
    /// @brief Is elevated
    bool isElevated = false;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    /// @brief Image is signed
    bool isImageSigned = false;
    
    /// @brief Image signer
    std::wstring imageSigner;
    
    /// @brief Image hash (SHA256)
    std::string imageHash;
    
    /// @brief Image size
    uint64_t imageSize = 0;
    
    /// @brief Is WoW64 process
    bool isWoW64 = false;
    
    /// @brief Is protected process
    bool isProtectedProcess = false;
    
    /// @brief Subsystem
    uint16_t subsystem = 0;
    
    /// @brief Image characteristics
    uint16_t characteristics = 0;
    
    /// @brief Is from network location
    bool isNetworkImage = false;
    
    /// @brief Is from removable media
    bool isRemovableMedia = false;
    
    /// @brief Requires verdict reply
    bool requiresVerdict = true;
};

/**
 * @brief Extended process information.
 */
struct ProcessInfo {
    // -------------------------------------------------------------------------
    // Identification
    // -------------------------------------------------------------------------
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /// @brief Image path
    std::wstring imagePath;
    
    /// @brief Image name
    std::wstring imageName;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Current directory
    std::wstring currentDirectory;
    
    // -------------------------------------------------------------------------
    // User Context
    // -------------------------------------------------------------------------
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Domain name
    std::wstring domainName;
    
    /// @brief Is elevated
    bool isElevated = false;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    
    /// @brief Current state
    ProcessState state = ProcessState::Unknown;
    
    /// @brief Process type
    ProcessType processType = ProcessType::Unknown;
    
    /// @brief Creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Termination time
    std::chrono::system_clock::time_point terminationTime{};
    
    /// @brief Exit code
    uint32_t exitCode = 0;
    
    // -------------------------------------------------------------------------
    // Security
    // -------------------------------------------------------------------------
    
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /// @brief Is Microsoft signed
    bool isMicrosoftSigned = false;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Image hash
    std::string imageHash;
    
    // -------------------------------------------------------------------------
    // Classification
    // -------------------------------------------------------------------------
    
    /// @brief LOLBAS type
    LOLBASType lolbasType = LOLBASType::None;
    
    /// @brief Is script interpreter
    bool isScriptInterpreter = false;
    
    /// @brief Is browser
    bool isBrowser = false;
    
    /// @brief Is office application
    bool isOfficeApp = false;
    
    // -------------------------------------------------------------------------
    // Risk Assessment
    // -------------------------------------------------------------------------
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Detected patterns
    std::vector<SuspiciousPattern> suspiciousPatterns;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Verdict
    ProcessVerdict verdict = ProcessVerdict::Allow;
    
    /// @brief Verdict reason
    std::wstring verdictReason;
    
    // -------------------------------------------------------------------------
    // Relationships
    // -------------------------------------------------------------------------
    
    /// @brief Child process IDs
    std::vector<uint32_t> childProcessIds;
    
    /// @brief Thread count (snapshot)
    uint32_t threadCount = 0;
    
    /// @brief Handle count (snapshot)
    uint32_t handleCount = 0;
    
    // -------------------------------------------------------------------------
    // Network
    // -------------------------------------------------------------------------
    
    /// @brief Has network connections
    bool hasNetworkConnections = false;
    
    /// @brief Outbound connection count
    uint32_t outboundConnections = 0;
    
    /// @brief Contacted domains
    std::vector<std::string> contactedDomains;
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Get process lifetime.
     */
    [[nodiscard]] std::chrono::milliseconds GetLifetime() const noexcept {
        auto end = (state == ProcessState::Terminated) ? terminationTime : std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - creationTime);
    }
    
    /**
     * @brief Check if process is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept {
        return state == ProcessState::Running || state == ProcessState::Creating;
    }
};

/**
 * @brief Process tree node.
 */
struct ProcessTreeNode {
    /// @brief Process info
    ProcessInfo process;
    
    /// @brief Parent node (weak reference via PID)
    uint32_t parentPid = 0;
    
    /// @brief Children nodes (PIDs)
    std::vector<uint32_t> childPids;
    
    /// @brief Tree depth
    uint32_t depth = 0;
    
    /// @brief Tree path (PIDs from root)
    std::vector<uint32_t> ancestorPath;
    
    /**
     * @brief Get process chain as string.
     */
    [[nodiscard]] std::wstring GetProcessChainString() const;
};

/**
 * @brief Command line analysis result.
 */
struct CommandLineAnalysis {
    /// @brief Original command line
    std::wstring originalCommandLine;
    
    /// @brief Executable path extracted
    std::wstring executablePath;
    
    /// @brief Arguments extracted
    std::vector<std::wstring> arguments;
    
    /// @brief Contains encoded content
    bool hasEncodedContent = false;
    
    /// @brief Encoded content type
    std::string encodingType;  // "Base64", "Hex", "Compressed"
    
    /// @brief Decoded content (if applicable)
    std::wstring decodedContent;
    
    /// @brief Contains URLs
    bool hasURLs = false;
    
    /// @brief Extracted URLs
    std::vector<std::string> extractedURLs;
    
    /// @brief Contains IPs
    bool hasIPs = false;
    
    /// @brief Extracted IPs
    std::vector<std::string> extractedIPs;
    
    /// @brief Contains file paths
    bool hasFilePaths = false;
    
    /// @brief Extracted file paths
    std::vector<std::wstring> extractedPaths;
    
    /// @brief Contains registry paths
    bool hasRegistryPaths = false;
    
    /// @brief Extracted registry paths
    std::vector<std::wstring> extractedRegistryPaths;
    
    /// @brief Suspicious keywords found
    std::vector<std::string> suspiciousKeywords;
    
    /// @brief LOLBAS indicators
    std::vector<std::string> lolbasIndicators;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Detected patterns
    std::vector<SuspiciousPattern> patterns;
};

/**
 * @brief Process creation policy rule.
 */
struct ProcessPolicyRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::wstring name;
    
    /// @brief Rule description
    std::wstring description;
    
    /// @brief Is rule enabled
    bool enabled = true;
    
    /// @brief Action (block/allow/monitor)
    ProcessVerdict action = ProcessVerdict::Block;
    
    /// @brief Rule priority (higher = checked first)
    uint32_t priority = 0;
    
    /// @brief Match by image path pattern
    std::optional<std::wstring> imagePathPattern;
    
    /// @brief Match by image hash
    std::optional<std::string> imageHash;
    
    /// @brief Match by image name
    std::optional<std::wstring> imageNamePattern;
    
    /// @brief Match by command line pattern
    std::optional<std::wstring> commandLinePattern;
    
    /// @brief Match by parent image name
    std::optional<std::wstring> parentImagePattern;
    
    /// @brief Match by user
    std::optional<std::wstring> userPattern;
    
    /// @brief Match by signer
    std::optional<std::wstring> signerPattern;
    
    /// @brief Must be signed
    std::optional<bool> requireSigned;
    
    /// @brief Must be from specific path
    std::optional<std::wstring> requiredPath;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Rule source
    std::wstring source;
    
    /// @brief Created time
    std::chrono::system_clock::time_point created{};
};

/**
 * @brief Configuration for process creation monitor.
 */
struct ProcessMonitorConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable monitoring
    bool enabled = true;
    
    /// @brief Enable pre-execution scanning
    bool preExecutionScan = true;
    
    /// @brief Enable command line analysis
    bool analyzeCommandLine = true;
    
    /// @brief Enable parent-child tracking
    bool trackParentChild = true;
    
    /// @brief Enable process tree building
    bool buildProcessTree = true;
    
    // -------------------------------------------------------------------------
    // Blocking Settings
    // -------------------------------------------------------------------------
    
    /// @brief Block unsigned executables
    bool blockUnsigned = false;
    
    /// @brief Block executables from temp folders
    bool blockFromTemp = false;
    
    /// @brief Block executables from network shares
    bool blockFromNetwork = false;
    
    /// @brief Block known malicious hashes
    bool blockKnownMalicious = true;
    
    /// @brief Block on scan timeout
    bool blockOnTimeout = false;
    
    // -------------------------------------------------------------------------
    // Detection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Detect LOLBAS abuse
    bool detectLOLBAS = true;
    
    /// @brief Detect suspicious parent-child
    bool detectSuspiciousParentChild = true;
    
    /// @brief Detect encoded commands
    bool detectEncodedCommands = true;
    
    /// @brief Detect process masquerading
    bool detectMasquerading = true;
    
    /// @brief Minimum risk score to alert
    double alertThreshold = 50.0;
    
    /// @brief Minimum risk score to block
    double blockThreshold = 80.0;
    
    // -------------------------------------------------------------------------
    // Trust Settings
    // -------------------------------------------------------------------------
    
    /// @brief Trust Microsoft signed
    bool trustMicrosoftSigned = true;
    
    /// @brief Trust whitelisted processes
    bool trustWhitelisted = true;
    
    /// @brief Trusted signers
    std::vector<std::wstring> trustedSigners;
    
    // -------------------------------------------------------------------------
    // Performance Settings
    // -------------------------------------------------------------------------
    
    /// @brief Scan timeout (ms)
    uint32_t scanTimeoutMs = ProcessMonitorConstants::SCAN_TIMEOUT_MS;
    
    /// @brief Maximum tracked processes
    size_t maxTrackedProcesses = ProcessMonitorConstants::MAX_TRACKED_PROCESSES;
    
    /// @brief History retention period
    std::chrono::hours historyRetention = ProcessMonitorConstants::HISTORY_RETENTION;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static ProcessMonitorConfig CreateDefault() noexcept {
        return ProcessMonitorConfig{};
    }
    
    /**
     * @brief Create strict configuration.
     */
    [[nodiscard]] static ProcessMonitorConfig CreateStrict() noexcept {
        ProcessMonitorConfig config;
        config.blockUnsigned = true;
        config.blockFromTemp = true;
        config.blockFromNetwork = true;
        config.blockOnTimeout = true;
        config.alertThreshold = 30.0;
        config.blockThreshold = 60.0;
        return config;
    }
    
    /**
     * @brief Create monitor-only configuration.
     */
    [[nodiscard]] static ProcessMonitorConfig CreateMonitorOnly() noexcept {
        ProcessMonitorConfig config;
        config.preExecutionScan = false;
        config.blockUnsigned = false;
        config.blockKnownMalicious = false;
        config.blockThreshold = 100.0;  // Never block
        return config;
    }
};

/**
 * @brief Statistics for process creation monitor.
 */
struct ProcessMonitorStats {
    /// @brief Total process creations observed
    std::atomic<uint64_t> totalProcessCreations{ 0 };
    
    /// @brief Processes allowed
    std::atomic<uint64_t> processesAllowed{ 0 };
    
    /// @brief Processes blocked
    std::atomic<uint64_t> processesBlocked{ 0 };
    
    /// @brief Processes flagged suspicious
    std::atomic<uint64_t> processesSuspicious{ 0 };
    
    /// @brief Pre-execution scans performed
    std::atomic<uint64_t> scansPerformed{ 0 };
    
    /// @brief Scan timeouts
    std::atomic<uint64_t> scanTimeouts{ 0 };
    
    /// @brief LOLBAS abuse detected
    std::atomic<uint64_t> lolbasDetections{ 0 };
    
    /// @brief Suspicious parent-child detected
    std::atomic<uint64_t> parentChildDetections{ 0 };
    
    /// @brief Encoded commands detected
    std::atomic<uint64_t> encodedCommandDetections{ 0 };
    
    /// @brief Process masquerading detected
    std::atomic<uint64_t> masqueradingDetections{ 0 };
    
    /// @brief Currently tracked processes
    std::atomic<size_t> trackedProcesses{ 0 };
    
    /// @brief Process terminations observed
    std::atomic<uint64_t> processTerminations{ 0 };
    
    /// @brief Average decision time (microseconds)
    std::atomic<uint64_t> avgDecisionTimeUs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalProcessCreations.store(0, std::memory_order_relaxed);
        processesAllowed.store(0, std::memory_order_relaxed);
        processesBlocked.store(0, std::memory_order_relaxed);
        processesSuspicious.store(0, std::memory_order_relaxed);
        scansPerformed.store(0, std::memory_order_relaxed);
        scanTimeouts.store(0, std::memory_order_relaxed);
        lolbasDetections.store(0, std::memory_order_relaxed);
        parentChildDetections.store(0, std::memory_order_relaxed);
        encodedCommandDetections.store(0, std::memory_order_relaxed);
        masqueradingDetections.store(0, std::memory_order_relaxed);
        trackedProcesses.store(0, std::memory_order_relaxed);
        processTerminations.store(0, std::memory_order_relaxed);
        avgDecisionTimeUs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using ProcessCreateCallback = std::function<ProcessVerdict(const ProcessCreateEvent&)>;
using ProcessTerminateCallback = std::function<void(uint32_t pid, uint32_t exitCode)>;
using SuspiciousProcessCallback = std::function<void(const ProcessInfo&, const std::vector<SuspiciousPattern>&)>;
using ProcessTreeCallback = std::function<void(const ProcessTreeNode&)>;

// ============================================================================
// MAIN PROCESS CREATION MONITOR CLASS
// ============================================================================

/**
 * @brief Enterprise-grade process execution monitoring and prevention.
 *
 * Monitors all process creation events, analyzes them for suspicious patterns,
 * and can block malicious processes before their first instruction executes.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& monitor = ProcessCreationMonitor::Instance();
 * 
 * // Initialize
 * ProcessMonitorConfig config = ProcessMonitorConfig::CreateDefault();
 * monitor.Initialize(threadPool, config);
 * 
 * // Set integrations
 * monitor.SetScanEngine(&ScanEngine::Instance());
 * monitor.SetWhitelistStore(&WhitelistStore::Instance());
 * monitor.SetHashStore(&HashStore::Instance());
 * 
 * // Register callbacks
 * monitor.RegisterSuspiciousCallback([](const ProcessInfo& proc, const auto& patterns) {
 *     LOG_WARN(L"Suspicious process: {} (PID: {})", proc.imageName, proc.processId);
 *     for (const auto& pattern : patterns) {
 *         LOG_WARN("  Pattern: {}", SuspiciousPatternToString(pattern));
 *     }
 * });
 * 
 * // Add blocking rule
 * ProcessPolicyRule rule;
 * rule.ruleId = "block-mimikatz";
 * rule.imageHash = "abc123...";  // Known mimikatz hash
 * rule.action = ProcessVerdict::Block;
 * monitor.AddRule(rule);
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // Query process info
 * auto info = monitor.GetProcessInfo(1234);
 * if (info) {
 *     LOG_INFO(L"Process: {} started by {}", info->imageName, info->userName);
 * }
 * 
 * // Get process tree
 * auto tree = monitor.GetProcessTree(1234);
 * 
 * monitor.Stop();
 * monitor.Shutdown();
 * @endcode
 */
class ProcessCreationMonitor {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static ProcessCreationMonitor& Instance();

    // Non-copyable, non-movable
    ProcessCreationMonitor(const ProcessCreationMonitor&) = delete;
    ProcessCreationMonitor& operator=(const ProcessCreationMonitor&) = delete;
    ProcessCreationMonitor(ProcessCreationMonitor&&) = delete;
    ProcessCreationMonitor& operator=(ProcessCreationMonitor&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the monitor.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const ProcessMonitorConfig& config
    );

    /**
     * @brief Shutdown the monitor.
     */
    void Shutdown();

    /**
     * @brief Start monitoring.
     */
    void Start();

    /**
     * @brief Stop monitoring.
     */
    void Stop();

    /**
     * @brief Check if monitor is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const ProcessMonitorConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] ProcessMonitorConfig GetConfig() const;

    // =========================================================================
    // Event Handlers
    // =========================================================================

    /**
     * @brief Handle process creation event.
     * @param event Process creation event from kernel.
     * @return Verdict (allow/block).
     */
    [[nodiscard]] ProcessVerdict OnProcessCreate(const ProcessCreateEvent& event);

    /**
     * @brief Handle process creation (simplified).
     * @param pid New process ID.
     * @param imagePath Image file path.
     * @param parentPid Parent process ID.
     * @return Verdict.
     */
    [[nodiscard]] ProcessVerdict OnProcessCreate(
        uint32_t pid,
        const std::wstring& imagePath,
        uint32_t parentPid
    );

    /**
     * @brief Handle process termination.
     * @param pid Terminated process ID.
     * @param exitCode Exit code.
     */
    void OnProcessTerminate(uint32_t pid, uint32_t exitCode = 0);

    // =========================================================================
    // Process Query
    // =========================================================================

    /**
     * @brief Get process information.
     * @param pid Process ID.
     * @return Process info or nullopt if not tracked.
     */
    [[nodiscard]] std::optional<ProcessInfo> GetProcessInfo(uint32_t pid) const;

    /**
     * @brief Get process tree for a process.
     * @param pid Process ID.
     * @return Process tree node or nullopt.
     */
    [[nodiscard]] std::optional<ProcessTreeNode> GetProcessTree(uint32_t pid) const;

    /**
     * @brief Get parent process info.
     */
    [[nodiscard]] std::optional<ProcessInfo> GetParentProcess(uint32_t pid) const;

    /**
     * @brief Get child processes.
     */
    [[nodiscard]] std::vector<ProcessInfo> GetChildProcesses(uint32_t pid) const;

    /**
     * @brief Get process ancestor chain.
     */
    [[nodiscard]] std::vector<ProcessInfo> GetAncestorChain(uint32_t pid) const;

    /**
     * @brief Check if process is running.
     */
    [[nodiscard]] bool IsProcessRunning(uint32_t pid) const;

    /**
     * @brief Get all tracked processes.
     */
    [[nodiscard]] std::vector<ProcessInfo> GetAllProcesses() const;

    /**
     * @brief Get processes by user.
     */
    [[nodiscard]] std::vector<ProcessInfo> GetProcessesByUser(const std::wstring& userName) const;

    /**
     * @brief Get processes by image name.
     */
    [[nodiscard]] std::vector<ProcessInfo> GetProcessesByImage(const std::wstring& imageName) const;

    // =========================================================================
    // Command Line Analysis
    // =========================================================================

    /**
     * @brief Analyze command line.
     * @param commandLine Command line to analyze.
     * @return Analysis result.
     */
    [[nodiscard]] CommandLineAnalysis AnalyzeCommandLine(const std::wstring& commandLine) const;

    /**
     * @brief Check if command line is suspicious.
     */
    [[nodiscard]] bool IsCommandLineSuspicious(const std::wstring& commandLine) const;

    /**
     * @brief Decode encoded command line content.
     */
    [[nodiscard]] std::wstring DecodeEncodedContent(const std::wstring& content) const;

    // =========================================================================
    // Classification
    // =========================================================================

    /**
     * @brief Classify LOLBAS type from image name.
     */
    [[nodiscard]] LOLBASType ClassifyLOLBAS(const std::wstring& imageName) const;

    /**
     * @brief Classify process type.
     */
    [[nodiscard]] ProcessType ClassifyProcessType(const ProcessInfo& info) const;

    /**
     * @brief Check for suspicious parent-child relationship.
     */
    [[nodiscard]] std::vector<SuspiciousPattern> CheckParentChild(
        const ProcessInfo& parent,
        const ProcessInfo& child
    ) const;

    // =========================================================================
    // Rule Management
    // =========================================================================

    /**
     * @brief Add policy rule.
     */
    bool AddRule(const ProcessPolicyRule& rule);

    /**
     * @brief Remove policy rule.
     */
    bool RemoveRule(const std::string& ruleId);

    /**
     * @brief Enable/disable rule.
     */
    void SetRuleEnabled(const std::string& ruleId, bool enabled);

    /**
     * @brief Get all rules.
     */
    [[nodiscard]] std::vector<ProcessPolicyRule> GetRules() const;

    /**
     * @brief Load rules from file.
     */
    bool LoadRulesFromFile(const std::wstring& filePath);

    /**
     * @brief Save rules to file.
     */
    bool SaveRulesToFile(const std::wstring& filePath) const;

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] ProcessMonitorStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register process create callback.
     */
    [[nodiscard]] uint64_t RegisterCreateCallback(ProcessCreateCallback callback);

    /**
     * @brief Unregister create callback.
     */
    bool UnregisterCreateCallback(uint64_t callbackId);

    /**
     * @brief Register process terminate callback.
     */
    [[nodiscard]] uint64_t RegisterTerminateCallback(ProcessTerminateCallback callback);

    /**
     * @brief Unregister terminate callback.
     */
    bool UnregisterTerminateCallback(uint64_t callbackId);

    /**
     * @brief Register suspicious process callback.
     */
    [[nodiscard]] uint64_t RegisterSuspiciousCallback(SuspiciousProcessCallback callback);

    /**
     * @brief Unregister suspicious callback.
     */
    bool UnregisterSuspiciousCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set scan engine.
     */
    void SetScanEngine(Core::Engine::ScanEngine* engine);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer);

    /**
     * @brief Set whitelist store.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set hash store.
     */
    void SetHashStore(HashStore::HashStore* store);

    /**
     * @brief Set threat intel index.
     */
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    ProcessCreationMonitor();
    ~ProcessCreationMonitor();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Evaluate process against rules.
     */
    std::optional<ProcessVerdict> EvaluateRules(const ProcessCreateEvent& event);

    /**
     * @brief Perform pre-execution scan.
     */
    ProcessVerdict PerformScan(const ProcessCreateEvent& event);

    /**
     * @brief Calculate risk score.
     */
    double CalculateRiskScore(const ProcessCreateEvent& event, const CommandLineAnalysis& analysis);

    /**
     * @brief Detect suspicious patterns.
     */
    std::vector<SuspiciousPattern> DetectPatterns(
        const ProcessCreateEvent& event,
        const CommandLineAnalysis& analysis
    );

    /**
     * @brief Update process tree.
     */
    void UpdateProcessTree(const ProcessInfo& process);

    /**
     * @brief Cleanup terminated processes.
     */
    void CleanupTerminatedProcesses();

    /**
     * @brief Invoke create callbacks.
     */
    void InvokeCreateCallbacks(const ProcessCreateEvent& event, ProcessVerdict verdict);

    /**
     * @brief Invoke terminate callbacks.
     */
    void InvokeTerminateCallbacks(uint32_t pid, uint32_t exitCode);

    /**
     * @brief Invoke suspicious callbacks.
     */
    void InvokeSuspiciousCallbacks(const ProcessInfo& info, const std::vector<SuspiciousPattern>& patterns);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get process image name from path.
 */
[[nodiscard]] std::wstring GetProcessImageName(const std::wstring& imagePath) noexcept;

/**
 * @brief Check if process name is a script interpreter.
 */
[[nodiscard]] bool IsScriptInterpreter(const std::wstring& imageName) noexcept;

/**
 * @brief Check if process name is a browser.
 */
[[nodiscard]] bool IsBrowser(const std::wstring& imageName) noexcept;

/**
 * @brief Check if process name is an Office application.
 */
[[nodiscard]] bool IsOfficeApplication(const std::wstring& imageName) noexcept;

/**
 * @brief Check if path is in temp folder.
 */
[[nodiscard]] bool IsInTempFolder(const std::wstring& path) noexcept;

/**
 * @brief Check if path is in downloads folder.
 */
[[nodiscard]] bool IsInDownloadsFolder(const std::wstring& path) noexcept;

/**
 * @brief Check if path is on network share.
 */
[[nodiscard]] bool IsNetworkPath(const std::wstring& path) noexcept;

/**
 * @brief Detect Base64 encoded content in string.
 */
[[nodiscard]] bool ContainsBase64(const std::wstring& str) noexcept;

/**
 * @brief Extract URLs from command line.
 */
[[nodiscard]] std::vector<std::string> ExtractURLsFromCommandLine(const std::wstring& cmdLine) noexcept;

} // namespace RealTime
} // namespace ShadowStrike
