/**
 * ============================================================================
 * ShadowStrike Core Engine - BEHAVIOR ANALYZER (The Dynamic Analyst)
 * ============================================================================
 *
 * @file BehaviorAnalyzer.hpp
 * @brief Enterprise-grade behavioral analysis engine for detecting malicious activity patterns.
 *
 * This module implements a sophisticated behavioral analysis system that maintains
 * per-process state machines to detect complex attack chains and malicious behavior
 * patterns that signature-based detection cannot catch.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Attack Chain Detection**
 *    - Tracks process genealogy and event sequences
 *    - Detects multi-stage attacks (dropper -> payload -> persistence)
 *    - Correlates events across process boundaries
 *    - Maps to MITRE ATT&CK framework
 *
 * 2. **Ransomware Detection**
 *    - Rapid file modification patterns
 *    - High-entropy file write detection
 *    - Shadow copy deletion monitoring
 *    - Canary file system monitoring
 *    - Encryption behavior fingerprinting
 *
 * 3. **Process Injection Detection**
 *    - Remote thread creation monitoring
 *    - VirtualAllocEx in foreign processes
 *    - Process hollowing detection
 *    - DLL injection patterns
 *    - APC queue injection
 *    - Atom bombing detection
 *
 * 4. **Persistence Detection**
 *    - Registry run key modifications
 *    - Scheduled task creation
 *    - Service installation
 *    - WMI event subscriptions
 *    - Startup folder modifications
 *    - Boot configuration changes
 *
 * 5. **Credential Theft Detection**
 *    - LSASS memory access
 *    - SAM database access
 *    - Credential store access
 *    - Mimikatz-like patterns
 *    - Keylogger behavior
 *
 * 6. **Data Exfiltration Detection**
 *    - Large outbound data transfers
 *    - Suspicious archive creation
 *    - Cloud storage API usage
 *    - DNS tunneling patterns
 *    - Clipboard monitoring
 *
 * 7. **Evasion Technique Detection**
 *    - Anti-debugging attempts
 *    - VM/Sandbox detection
 *    - Timestomping
 *    - Log tampering
 *    - Security tool interference
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                        BehaviorAnalyzer                                  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Event Ingestion Layer                         │   │
 * │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │   │
 * │  │  │  Process  │  │   File    │  │  Registry │  │  Network  │    │   │
 * │  │  │  Events   │  │  Events   │  │  Events   │  │  Events   │    │   │
 * │  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘    │   │
 * │  │        └──────────────┴──────────────┴──────────────┘          │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Event Normalization                           │   │
 * │  │  - Timestamp alignment                                           │   │
 * │  │  - Process context enrichment                                    │   │
 * │  │  - Path canonicalization                                         │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Process State Machine                         │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │  Per-Process Behavioral State                           │    │   │
 * │  │  │  - Malice score accumulator                             │    │   │
 * │  │  │  - Event history ring buffer                            │    │   │
 * │  │  │  - Triggered rules tracking                             │    │   │
 * │  │  │  - Category-specific counters                           │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Detection Engines                             │   │
 * │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
 * │  │  │Ransomware│ │Injection│ │Persist. │ │Credential│ │Exfil.  │   │   │
 * │  │  │ Engine  │ │ Engine  │ │ Engine  │ │ Engine  │ │ Engine │   │   │
 * │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Correlation Engine                            │   │
 * │  │  - Cross-process correlation                                     │   │
 * │  │  - Attack chain assembly                                         │   │
 * │  │  - MITRE ATT&CK mapping                                          │   │
 * │  │  - Confidence calculation                                        │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Response Interface                            │   │
 * │  │  - Verdict generation                                            │   │
 * │  │  - Alert triggering                                              │   │
 * │  │  - Remediation recommendations                                   │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * =============================================================================
 * INTEGRATION POINTS
 * =============================================================================
 *
 * - **ProcessMonitor**: Parent-child relationships, process metadata
 * - **RegistryMonitor**: Registry event stream
 * - **NetworkMonitor**: Network connection events
 * - **FileWatcher**: File system events
 * - **ThreatIntel**: IOC correlation for network destinations
 * - **SignatureStore**: YARA/pattern matching for memory regions
 * - **Whitelist**: Legitimate software exclusions
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Tactic             | Techniques Detected                              |
 * |--------------------|--------------------------------------------------|
 * | Execution          | T1059, T1106, T1129, T1203, T1204                |
 * | Persistence        | T1037, T1053, T1078, T1098, T1136, T1197, T1547  |
 * | Privilege Esc.     | T1055, T1068, T1134, T1548                       |
 * | Defense Evasion    | T1027, T1055, T1070, T1112, T1140, T1218, T1562  |
 * | Credential Access  | T1003, T1056, T1110, T1552, T1555                |
 * | Discovery          | T1007, T1012, T1016, T1018, T1033, T1057, T1082  |
 * | Lateral Movement   | T1021, T1091, T1570                              |
 * | Collection         | T1005, T1039, T1074, T1113, T1115, T1119         |
 * | Exfiltration       | T1020, T1030, T1041, T1048, T1567                |
 * | Impact             | T1485, T1486, T1489, T1490, T1491, T1529         |
 *
 * @note Thread-safe for all public methods
 * @note Lock-free fast path for common operations
 *
 * @see ProcessMonitor for process tracking
 * @see ThreatDetector for event stream source
 * @see SignatureStore for pattern matching
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/ProcessUtils.hpp"       // Process context
#include "../../Utils/FileUtils.hpp"          // File operations
#include "../../Utils/RegistryUtils.hpp"      // Registry operations
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../../PatternStore/PatternStore.hpp" // Attack patterns
#include "../../SignatureStore/SignatureStore.hpp" // Behavioral signatures
#include "../../Whitelist/WhiteListStore.hpp" // Trusted behaviors

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
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
        namespace ProcessUtils {
            struct ProcessInfo;
            struct ProcessBasicInfo;
        }
    }
    namespace ThreatIntel {
        class ThreatIntelIndex;
    }
    namespace SignatureStore {
        class SignatureStore;
    }
    namespace Whitelist {
        class WhitelistStore;
    }
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class BehaviorAnalyzer;
struct BehaviorEvent;
struct ProcessBehaviorState;
struct BehaviorVerdict;
struct AttackChain;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace BehaviorConstants {
    // -------------------------------------------------------------------------
    // Scoring Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Minimum score to trigger warning
    constexpr double WARNING_THRESHOLD = 30.0;
    
    /// @brief Minimum score to trigger alert
    constexpr double ALERT_THRESHOLD = 50.0;
    
    /// @brief Minimum score to trigger block
    constexpr double BLOCK_THRESHOLD = 70.0;
    
    /// @brief Minimum score for critical threat
    constexpr double CRITICAL_THRESHOLD = 90.0;
    
    /// @brief Maximum malice score
    constexpr double MAX_MALICE_SCORE = 100.0;
    
    /// @brief Score decay rate per minute (for aging old events)
    constexpr double SCORE_DECAY_PER_MINUTE = 2.0;
    
    /// @brief Maximum score contribution per event
    constexpr double MAX_SCORE_PER_EVENT = 25.0;
    
    // -------------------------------------------------------------------------
    // Ransomware Detection
    // -------------------------------------------------------------------------
    
    /// @brief Files modified threshold for ransomware alert
    constexpr uint32_t RANSOMWARE_FILE_THRESHOLD = 50;
    
    /// @brief Files modified per second threshold
    constexpr double RANSOMWARE_RATE_THRESHOLD = 10.0;
    
    /// @brief Entropy threshold for encrypted files
    constexpr double ENCRYPTION_ENTROPY_THRESHOLD = 7.5;
    
    /// @brief Shadow copy deletion score
    constexpr double SHADOW_COPY_DELETE_SCORE = 40.0;
    
    /// @brief Canary file touch score
    constexpr double CANARY_FILE_SCORE = 50.0;
    
    /// @brief Ransom note creation score
    constexpr double RANSOM_NOTE_SCORE = 60.0;
    
    // -------------------------------------------------------------------------
    // Process Injection Detection
    // -------------------------------------------------------------------------
    
    /// @brief Remote thread creation score
    constexpr double REMOTE_THREAD_SCORE = 35.0;
    
    /// @brief VirtualAllocEx in foreign process score
    constexpr double REMOTE_ALLOC_SCORE = 25.0;
    
    /// @brief WriteProcessMemory score
    constexpr double WRITE_PROCESS_MEMORY_SCORE = 30.0;
    
    /// @brief Process hollowing score
    constexpr double PROCESS_HOLLOWING_SCORE = 60.0;
    
    /// @brief DLL injection score
    constexpr double DLL_INJECTION_SCORE = 45.0;
    
    /// @brief APC injection score
    constexpr double APC_INJECTION_SCORE = 50.0;
    
    // -------------------------------------------------------------------------
    // Persistence Detection
    // -------------------------------------------------------------------------
    
    /// @brief Registry run key modification score
    constexpr double REG_RUN_KEY_SCORE = 30.0;
    
    /// @brief Scheduled task creation score
    constexpr double SCHEDULED_TASK_SCORE = 35.0;
    
    /// @brief Service installation score
    constexpr double SERVICE_INSTALL_SCORE = 40.0;
    
    /// @brief WMI subscription score
    constexpr double WMI_PERSISTENCE_SCORE = 45.0;
    
    /// @brief Boot configuration modification score
    constexpr double BOOT_CONFIG_SCORE = 50.0;
    
    // -------------------------------------------------------------------------
    // Credential Theft Detection
    // -------------------------------------------------------------------------
    
    /// @brief LSASS memory access score
    constexpr double LSASS_ACCESS_SCORE = 70.0;
    
    /// @brief SAM database access score
    constexpr double SAM_ACCESS_SCORE = 65.0;
    
    /// @brief Credential store access score
    constexpr double CREDENTIAL_STORE_SCORE = 40.0;
    
    /// @brief Security database access score
    constexpr double SECURITY_DB_SCORE = 55.0;
    
    // -------------------------------------------------------------------------
    // Evasion Detection
    // -------------------------------------------------------------------------
    
    /// @brief Log tampering score
    constexpr double LOG_TAMPERING_SCORE = 35.0;
    
    /// @brief Security tool interference score
    constexpr double SECURITY_INTERFERENCE_SCORE = 60.0;
    
    /// @brief Timestomping score
    constexpr double TIMESTOMPING_SCORE = 25.0;
    
    /// @brief Anti-debugging score
    constexpr double ANTI_DEBUG_SCORE = 20.0;
    
    // -------------------------------------------------------------------------
    // Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked processes
    constexpr size_t MAX_TRACKED_PROCESSES = 50000;
    
    /// @brief Maximum event history per process
    constexpr size_t MAX_EVENTS_PER_PROCESS = 10000;
    
    /// @brief Maximum attack chains tracked
    constexpr size_t MAX_ATTACK_CHAINS = 1000;
    
    /// @brief Event history retention period
    constexpr std::chrono::hours EVENT_RETENTION_PERIOD{ 24 };
    
    /// @brief State cleanup interval
    constexpr std::chrono::minutes CLEANUP_INTERVAL{ 5 };
    
    /// @brief Maximum rules per process
    constexpr size_t MAX_RULES_PER_PROCESS = 100;
    
    /// @brief Correlation window for related events
    constexpr std::chrono::seconds CORRELATION_WINDOW{ 60 };
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Category of behavioral event.
 */
enum class BehaviorEventCategory : uint8_t {
    /// @brief Unknown/unclassified
    Unknown = 0,
    
    /// @brief Process lifecycle events
    Process = 1,
    
    /// @brief File system operations
    FileSystem = 2,
    
    /// @brief Registry operations
    Registry = 3,
    
    /// @brief Network operations
    Network = 4,
    
    /// @brief Memory operations
    Memory = 5,
    
    /// @brief Handle operations
    Handle = 6,
    
    /// @brief Thread operations
    Thread = 7,
    
    /// @brief System operations
    System = 8,
    
    /// @brief Service operations
    Service = 9,
    
    /// @brief WMI operations
    WMI = 10,
    
    /// @brief PowerShell/script operations
    Script = 11,
    
    /// @brief COM operations
    COM = 12,
    
    /// @brief Driver operations
    Driver = 13,
    
    /// @brief Crypto operations
    Crypto = 14
};

/**
 * @brief Specific behavior event types.
 */
enum class BehaviorEventType : uint16_t {
    /// @brief Unknown event type
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // Process Events (1-99)
    // -------------------------------------------------------------------------
    
    ProcessCreate = 1,
    ProcessTerminate = 2,
    ProcessOpen = 3,
    ProcessDuplicate = 4,
    ProcessSuspend = 5,
    ProcessResume = 6,
    ProcessInject = 7,
    ProcessHollow = 8,
    
    // -------------------------------------------------------------------------
    // Thread Events (100-149)
    // -------------------------------------------------------------------------
    
    ThreadCreate = 100,
    ThreadTerminate = 101,
    ThreadRemoteCreate = 102,
    ThreadSetContext = 103,
    ThreadSuspend = 104,
    ThreadResume = 105,
    ThreadQueueAPC = 106,
    ThreadHijack = 107,
    
    // -------------------------------------------------------------------------
    // Memory Events (150-199)
    // -------------------------------------------------------------------------
    
    MemoryAllocate = 150,
    MemoryFree = 151,
    MemoryProtect = 152,
    MemoryWrite = 153,
    MemoryRead = 154,
    MemoryRemoteAllocate = 155,
    MemoryRemoteWrite = 156,
    MemoryRemoteProtect = 157,
    MemoryMap = 158,
    MemoryUnmap = 159,
    
    // -------------------------------------------------------------------------
    // File Events (200-299)
    // -------------------------------------------------------------------------
    
    FileCreate = 200,
    FileOpen = 201,
    FileRead = 202,
    FileWrite = 203,
    FileDelete = 204,
    FileRename = 205,
    FileSetAttributes = 206,
    FileSetSecurity = 207,
    FileLock = 208,
    FileUnlock = 209,
    FileEncrypt = 210,
    FileDecrypt = 211,
    DirectoryCreate = 220,
    DirectoryDelete = 221,
    DirectoryEnumerate = 222,
    
    // -------------------------------------------------------------------------
    // Registry Events (300-399)
    // -------------------------------------------------------------------------
    
    RegistryCreateKey = 300,
    RegistryDeleteKey = 301,
    RegistrySetValue = 302,
    RegistryDeleteValue = 303,
    RegistryQueryValue = 304,
    RegistryEnumKey = 305,
    RegistryEnumValue = 306,
    RegistryLoadHive = 307,
    RegistryUnloadHive = 308,
    RegistryRenameKey = 309,
    
    // -------------------------------------------------------------------------
    // Network Events (400-499)
    // -------------------------------------------------------------------------
    
    NetworkConnect = 400,
    NetworkListen = 401,
    NetworkAccept = 402,
    NetworkSend = 403,
    NetworkReceive = 404,
    NetworkDNSQuery = 405,
    NetworkHTTPRequest = 406,
    NetworkHTTPSRequest = 407,
    NetworkDownload = 408,
    NetworkUpload = 409,
    
    // -------------------------------------------------------------------------
    // Service Events (500-549)
    // -------------------------------------------------------------------------
    
    ServiceInstall = 500,
    ServiceStart = 501,
    ServiceStop = 502,
    ServiceDelete = 503,
    ServiceModify = 504,
    
    // -------------------------------------------------------------------------
    // Scheduled Task Events (550-599)
    // -------------------------------------------------------------------------
    
    TaskCreate = 550,
    TaskDelete = 551,
    TaskModify = 552,
    TaskRun = 553,
    
    // -------------------------------------------------------------------------
    // WMI Events (600-649)
    // -------------------------------------------------------------------------
    
    WMIQuery = 600,
    WMISubscription = 601,
    WMIExec = 602,
    WMIConsumer = 603,
    
    // -------------------------------------------------------------------------
    // Script Events (650-699)
    // -------------------------------------------------------------------------
    
    ScriptExecute = 650,
    PowerShellCommand = 651,
    PowerShellScript = 652,
    VBScriptExecute = 653,
    JScriptExecute = 654,
    BatchExecute = 655,
    
    // -------------------------------------------------------------------------
    // Credential Events (700-749)
    // -------------------------------------------------------------------------
    
    CredentialAccess = 700,
    LSASSAccess = 701,
    SAMAccess = 702,
    CredentialDump = 703,
    TokenSteal = 704,
    TokenDuplicate = 705,
    
    // -------------------------------------------------------------------------
    // Evasion Events (750-799)
    // -------------------------------------------------------------------------
    
    AntiDebugAttempt = 750,
    VMDetectionAttempt = 751,
    SandboxDetectionAttempt = 752,
    LogClear = 753,
    Timestomp = 754,
    SecurityDisable = 755,
    
    // -------------------------------------------------------------------------
    // System Events (800-849)
    // -------------------------------------------------------------------------
    
    SystemShutdown = 800,
    SystemReboot = 801,
    DriverLoad = 802,
    DriverUnload = 803,
    ShadowCopyDelete = 804,
    BootConfigModify = 805,
    
    // -------------------------------------------------------------------------
    // Crypto Events (850-899)
    // -------------------------------------------------------------------------
    
    CryptoKeyGenerate = 850,
    CryptoKeyImport = 851,
    CryptoEncrypt = 852,
    CryptoDecrypt = 853,
    CryptoSign = 854,
    CryptoHash = 855
};

/**
 * @brief Severity level of detected behavior.
 */
enum class BehaviorSeverity : uint8_t {
    /// @brief Informational (no action needed)
    Info = 0,
    
    /// @brief Low severity (log only)
    Low = 25,
    
    /// @brief Medium severity (alert)
    Medium = 50,
    
    /// @brief High severity (alert + investigate)
    High = 75,
    
    /// @brief Critical severity (immediate action required)
    Critical = 100
};

/**
 * @brief Type of malicious behavior pattern.
 */
enum class BehaviorPatternType : uint16_t {
    /// @brief Unknown/unclassified pattern
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // Ransomware Patterns (1-49)
    // -------------------------------------------------------------------------
    
    /// @brief Rapid file encryption
    RansomwareEncryption = 1,
    
    /// @brief Shadow copy deletion
    RansomwareShadowDelete = 2,
    
    /// @brief Ransom note creation
    RansomwareNote = 3,
    
    /// @brief File extension modification
    RansomwareExtensionChange = 4,
    
    /// @brief Canary file modification
    RansomwareCanaryTouch = 5,
    
    /// @brief Mass file deletion
    RansomwareMassDelete = 6,
    
    /// @brief Backup destruction
    RansomwareBackupDestroy = 7,
    
    // -------------------------------------------------------------------------
    // Process Injection Patterns (50-99)
    // -------------------------------------------------------------------------
    
    /// @brief Classic DLL injection
    InjectionDLL = 50,
    
    /// @brief Process hollowing
    InjectionHollowing = 51,
    
    /// @brief Remote thread creation
    InjectionRemoteThread = 52,
    
    /// @brief APC queue injection
    InjectionAPC = 53,
    
    /// @brief Atom bombing
    InjectionAtomBomb = 54,
    
    /// @brief Thread execution hijacking
    InjectionThreadHijack = 55,
    
    /// @brief Reflective DLL loading
    InjectionReflective = 56,
    
    /// @brief Process doppelganging
    InjectionDoppelgang = 57,
    
    // -------------------------------------------------------------------------
    // Persistence Patterns (100-149)
    // -------------------------------------------------------------------------
    
    /// @brief Registry run key
    PersistenceRunKey = 100,
    
    /// @brief Scheduled task
    PersistenceScheduledTask = 101,
    
    /// @brief Windows service
    PersistenceService = 102,
    
    /// @brief WMI event subscription
    PersistenceWMI = 103,
    
    /// @brief Startup folder
    PersistenceStartupFolder = 104,
    
    /// @brief Boot configuration
    PersistenceBootConfig = 105,
    
    /// @brief DLL search order hijacking
    PersistenceDLLHijack = 106,
    
    /// @brief COM object hijacking
    PersistenceCOMHijack = 107,
    
    /// @brief AppInit DLLs
    PersistenceAppInit = 108,
    
    /// @brief Image file execution options
    PersistenceIFEO = 109,
    
    // -------------------------------------------------------------------------
    // Credential Access Patterns (150-199)
    // -------------------------------------------------------------------------
    
    /// @brief LSASS memory dump
    CredentialLSASSDump = 150,
    
    /// @brief SAM database access
    CredentialSAMAccess = 151,
    
    /// @brief Mimikatz-like behavior
    CredentialMimikatz = 152,
    
    /// @brief Credential store access
    CredentialStoreAccess = 153,
    
    /// @brief Keylogging
    CredentialKeylogger = 154,
    
    /// @brief Browser credential theft
    CredentialBrowserTheft = 155,
    
    /// @brief Token manipulation
    CredentialTokenManip = 156,
    
    // -------------------------------------------------------------------------
    // Defense Evasion Patterns (200-249)
    // -------------------------------------------------------------------------
    
    /// @brief Log clearing
    EvasionLogClear = 200,
    
    /// @brief Security tool disabling
    EvasionSecurityDisable = 201,
    
    /// @brief Timestomping
    EvasionTimestomp = 202,
    
    /// @brief File attribute hiding
    EvasionFileHide = 203,
    
    /// @brief Process masquerading
    EvasionMasquerade = 204,
    
    /// @brief Rootkit behavior
    EvasionRootkit = 205,
    
    /// @brief AMSI bypass
    EvasionAMSIBypass = 206,
    
    /// @brief ETW tampering
    EvasionETWTamper = 207,
    
    // -------------------------------------------------------------------------
    // Exfiltration Patterns (250-299)
    // -------------------------------------------------------------------------
    
    /// @brief Large data transfer
    ExfilLargeTransfer = 250,
    
    /// @brief Archive creation before transfer
    ExfilArchiveCreate = 251,
    
    /// @brief DNS tunneling
    ExfilDNSTunnel = 252,
    
    /// @brief Cloud storage upload
    ExfilCloudUpload = 253,
    
    /// @brief Email exfiltration
    ExfilEmail = 254,
    
    /// @brief Clipboard data theft
    ExfilClipboard = 255,
    
    /// @brief Screenshot capture
    ExfilScreenshot = 256,
    
    // -------------------------------------------------------------------------
    // Lateral Movement Patterns (300-349)
    // -------------------------------------------------------------------------
    
    /// @brief Remote service execution
    LateralService = 300,
    
    /// @brief WMI remote execution
    LateralWMI = 301,
    
    /// @brief PSExec-like behavior
    LateralPSExec = 302,
    
    /// @brief Remote registry
    LateralRemoteRegistry = 303,
    
    /// @brief RDP movement
    LateralRDP = 304,
    
    /// @brief SMB lateral movement
    LateralSMB = 305,
    
    // -------------------------------------------------------------------------
    // Command & Control Patterns (350-399)
    // -------------------------------------------------------------------------
    
    /// @brief Beacon-like behavior
    C2Beacon = 350,
    
    /// @brief Known C2 protocol
    C2KnownProtocol = 351,
    
    /// @brief Encrypted C2 channel
    C2Encrypted = 352,
    
    /// @brief Domain generation algorithm
    C2DGA = 353,
    
    /// @brief Fast flux DNS
    C2FastFlux = 354
};

/**
 * @brief Verdict type from behavior analysis.
 */
enum class BehaviorVerdictType : uint8_t {
    /// @brief No threat detected
    Clean = 0,
    
    /// @brief Suspicious but not conclusive
    Suspicious = 1,
    
    /// @brief Likely malicious
    Malicious = 2,
    
    /// @brief Confirmed threat
    ConfirmedThreat = 3,
    
    /// @brief Ransomware detected
    Ransomware = 4,
    
    /// @brief Active attack detected
    ActiveAttack = 5
};

/**
 * @brief Recommended action based on verdict.
 */
enum class RecommendedAction : uint8_t {
    /// @brief No action needed
    None = 0,
    
    /// @brief Log for review
    Log = 1,
    
    /// @brief Alert security team
    Alert = 2,
    
    /// @brief Suspend process
    Suspend = 3,
    
    /// @brief Terminate process
    Terminate = 4,
    
    /// @brief Block and quarantine
    BlockAndQuarantine = 5,
    
    /// @brief Isolate endpoint
    IsolateEndpoint = 6
};

/**
 * @brief Get string representation of event type.
 */
[[nodiscard]] constexpr const char* BehaviorEventTypeToString(BehaviorEventType type) noexcept;

/**
 * @brief Get MITRE ATT&CK technique ID for behavior pattern.
 */
[[nodiscard]] constexpr const char* BehaviorPatternToMitre(BehaviorPatternType pattern) noexcept;

/**
 * @brief Get string representation of behavior pattern.
 */
[[nodiscard]] constexpr const char* BehaviorPatternTypeToString(BehaviorPatternType pattern) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Normalized behavior event for analysis.
 */
struct alignas(64) BehaviorEvent {
    // -------------------------------------------------------------------------
    // Event Identification
    // -------------------------------------------------------------------------
    
    /// @brief Unique event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp (high precision)
    std::chrono::steady_clock::time_point timestamp{};
    
    /// @brief System time for correlation
    std::chrono::system_clock::time_point systemTime{};
    
    /// @brief Event category
    BehaviorEventCategory category = BehaviorEventCategory::Unknown;
    
    /// @brief Specific event type
    BehaviorEventType eventType = BehaviorEventType::Unknown;
    
    // -------------------------------------------------------------------------
    // Process Context
    // -------------------------------------------------------------------------
    
    /// @brief Source process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Process command line
    std::wstring commandLine;
    
    /// @brief User SID
    std::wstring userSid;
    
    // -------------------------------------------------------------------------
    // Target Information
    // -------------------------------------------------------------------------
    
    /// @brief Target process ID (for cross-process operations)
    uint32_t targetProcessId = 0;
    
    /// @brief Target thread ID
    uint32_t targetThreadId = 0;
    
    /// @brief Target path (file, registry, etc.)
    std::wstring targetPath;
    
    /// @brief Target address (for memory operations)
    uint64_t targetAddress = 0;
    
    /// @brief Target size
    size_t targetSize = 0;
    
    // -------------------------------------------------------------------------
    // Operation Details
    // -------------------------------------------------------------------------
    
    /// @brief Operation-specific action string
    std::string action;
    
    /// @brief Additional details
    std::wstring details;
    
    /// @brief Operation result (success/failure)
    bool success = false;
    
    /// @brief Error code (if failed)
    uint32_t errorCode = 0;
    
    /// @brief Access mask/flags
    uint32_t accessMask = 0;
    
    // -------------------------------------------------------------------------
    // Network Details (for network events)
    // -------------------------------------------------------------------------
    
    /// @brief Remote hostname
    std::string remoteHostname;
    
    /// @brief Remote IP address
    std::string remoteIP;
    
    /// @brief Remote port
    uint16_t remotePort = 0;
    
    /// @brief Local port
    uint16_t localPort = 0;
    
    /// @brief Protocol
    std::string protocol;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    // -------------------------------------------------------------------------
    // File Details (for file events)
    // -------------------------------------------------------------------------
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief File entropy (for encryption detection)
    double fileEntropy = 0.0;
    
    /// @brief File extension
    std::wstring fileExtension;
    
    /// @brief Previous file name (for rename)
    std::wstring previousPath;
    
    // -------------------------------------------------------------------------
    // Registry Details (for registry events)
    // -------------------------------------------------------------------------
    
    /// @brief Registry value name
    std::wstring valueName;
    
    /// @brief Registry value type
    uint32_t valueType = 0;
    
    /// @brief Registry value data
    std::vector<uint8_t> valueData;
    
    // -------------------------------------------------------------------------
    // Analysis Metadata
    // -------------------------------------------------------------------------
    
    /// @brief Pre-calculated score contribution
    double scoreContribution = 0.0;
    
    /// @brief Matched pattern (if any)
    BehaviorPatternType matchedPattern = BehaviorPatternType::Unknown;
    
    /// @brief MITRE ATT&CK technique
    std::string mitreId;
    
    /// @brief Is event from trusted/signed process
    bool fromTrustedProcess = false;
    
    /// @brief Is event whitelisted
    bool isWhitelisted = false;
    
    /**
     * @brief Get event age.
     */
    [[nodiscard]] std::chrono::milliseconds GetAge() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - timestamp
        );
    }
};

/**
 * @brief Accumulated behavioral state for a process.
 */
struct ProcessBehaviorState {
    // -------------------------------------------------------------------------
    // Process Identification
    // -------------------------------------------------------------------------
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Process command line
    std::wstring commandLine;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief Process creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief State creation time
    std::chrono::steady_clock::time_point stateCreatedAt{};
    
    /// @brief Last update time
    std::chrono::steady_clock::time_point lastUpdateTime{};
    
    // -------------------------------------------------------------------------
    // Malice Scoring
    // -------------------------------------------------------------------------
    
    /// @brief Current malice score (0.0 - 100.0)
    double maliceScore = 0.0;
    
    /// @brief Peak malice score reached
    double peakMaliceScore = 0.0;
    
    /// @brief Confidence in malice score
    double confidence = 0.0;
    
    /// @brief Base score modifier (for reputation)
    double baseScoreModifier = 0.0;
    
    // -------------------------------------------------------------------------
    // Rule/Pattern Tracking
    // -------------------------------------------------------------------------
    
    /// @brief MITRE technique IDs triggered
    std::vector<std::string> triggeredMitreTechniques;
    
    /// @brief Behavior patterns detected
    std::vector<BehaviorPatternType> detectedPatterns;
    
    /// @brief Pattern occurrence counts
    std::unordered_map<BehaviorPatternType, uint32_t> patternCounts;
    
    // -------------------------------------------------------------------------
    // Category Counters
    // -------------------------------------------------------------------------
    
    /// @brief File operations count
    uint32_t fileOperationCount = 0;
    
    /// @brief Files modified count
    uint32_t filesModified = 0;
    
    /// @brief Files created count
    uint32_t filesCreated = 0;
    
    /// @brief Files deleted count
    uint32_t filesDeleted = 0;
    
    /// @brief Files encrypted count
    uint32_t filesEncrypted = 0;
    
    /// @brief Canary files touched
    uint32_t canaryFilesTouched = 0;
    
    /// @brief Registry modifications count
    uint32_t registryModifications = 0;
    
    /// @brief Network connections count
    uint32_t networkConnections = 0;
    
    /// @brief Outbound bytes transferred
    uint64_t outboundBytes = 0;
    
    /// @brief Process creation count (children)
    uint32_t childProcessCount = 0;
    
    /// @brief Remote thread creation count
    uint32_t remoteThreadCount = 0;
    
    /// @brief Cross-process write count
    uint32_t crossProcessWrites = 0;
    
    /// @brief Credential access attempts
    uint32_t credentialAccessAttempts = 0;
    
    /// @brief Evasion attempts
    uint32_t evasionAttempts = 0;
    
    // -------------------------------------------------------------------------
    // Ransomware-Specific
    // -------------------------------------------------------------------------
    
    /// @brief High entropy writes count
    uint32_t highEntropyWrites = 0;
    
    /// @brief File rename operations
    uint32_t fileRenames = 0;
    
    /// @brief Extension changes count
    uint32_t extensionChanges = 0;
    
    /// @brief Shadow copy operations
    uint32_t shadowCopyOperations = 0;
    
    /// @brief Ransom note indicators
    uint32_t ransomNoteIndicators = 0;
    
    /// @brief File modification rate (per second)
    double fileModificationRate = 0.0;
    
    /// @brief Last file modification timestamp
    std::chrono::steady_clock::time_point lastFileModTime{};
    
    // -------------------------------------------------------------------------
    // Injection-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Target PIDs for cross-process operations
    std::unordered_set<uint32_t> targetedProcessIds;
    
    /// @brief Injected DLLs
    std::vector<std::wstring> injectedDLLs;
    
    /// @brief Remote memory allocations
    std::vector<std::pair<uint32_t, uint64_t>> remoteAllocations;
    
    // -------------------------------------------------------------------------
    // Persistence-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Registry persistence locations
    std::vector<std::wstring> persistenceLocations;
    
    /// @brief Created services
    std::vector<std::wstring> createdServices;
    
    /// @brief Created scheduled tasks
    std::vector<std::wstring> createdTasks;
    
    // -------------------------------------------------------------------------
    // Network-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Contacted domains
    std::unordered_set<std::string> contactedDomains;
    
    /// @brief Contacted IPs
    std::unordered_set<std::string> contactedIPs;
    
    /// @brief C2 indicators
    uint32_t c2Indicators = 0;
    
    /// @brief DNS queries count
    uint32_t dnsQueryCount = 0;
    
    // -------------------------------------------------------------------------
    // Trust/Reputation Flags
    // -------------------------------------------------------------------------
    
    /// @brief Is signed by Microsoft
    bool isSignedByMicrosoft = false;
    
    /// @brief Is signed by trusted vendor
    bool isSignedByTrustedVendor = false;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Is system process
    bool isSystemProcess = false;
    
    /// @brief Has document parent (Office, PDF reader)
    bool hasDocumentParent = false;
    
    /// @brief Has script interpreter parent
    bool hasScriptParent = false;
    
    /// @brief Is network-downloaded
    bool isNetworkDownloaded = false;
    
    // -------------------------------------------------------------------------
    // Event History
    // -------------------------------------------------------------------------
    
    /// @brief Recent events (ring buffer)
    std::deque<BehaviorEvent> recentEvents;
    
    /// @brief Total events processed
    uint64_t totalEventsProcessed = 0;
    
    // -------------------------------------------------------------------------
    // Verdict
    // -------------------------------------------------------------------------
    
    /// @brief Current verdict
    BehaviorVerdictType currentVerdict = BehaviorVerdictType::Clean;
    
    /// @brief Recommended action
    RecommendedAction recommendedAction = RecommendedAction::None;
    
    /// @brief Whether process has been reported
    bool hasBeenReported = false;
    
    /// @brief Whether process has been terminated
    bool hasBeenTerminated = false;
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Get severity level based on score.
     */
    [[nodiscard]] BehaviorSeverity GetSeverity() const noexcept {
        if (maliceScore >= BehaviorConstants::CRITICAL_THRESHOLD) return BehaviorSeverity::Critical;
        if (maliceScore >= BehaviorConstants::BLOCK_THRESHOLD) return BehaviorSeverity::High;
        if (maliceScore >= BehaviorConstants::ALERT_THRESHOLD) return BehaviorSeverity::Medium;
        if (maliceScore >= BehaviorConstants::WARNING_THRESHOLD) return BehaviorSeverity::Low;
        return BehaviorSeverity::Info;
    }
    
    /**
     * @brief Check if process exhibits ransomware behavior.
     */
    [[nodiscard]] bool HasRansomwareBehavior() const noexcept {
        return filesEncrypted >= BehaviorConstants::RANSOMWARE_FILE_THRESHOLD ||
               shadowCopyOperations > 0 ||
               canaryFilesTouched > 0 ||
               ransomNoteIndicators > 0;
    }
    
    /**
     * @brief Check if process exhibits injection behavior.
     */
    [[nodiscard]] bool HasInjectionBehavior() const noexcept {
        return remoteThreadCount > 0 || crossProcessWrites > 0 || !targetedProcessIds.empty();
    }
    
    /**
     * @brief Get state age.
     */
    [[nodiscard]] std::chrono::milliseconds GetAge() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stateCreatedAt
        );
    }
    
    /**
     * @brief Clear all state data.
     */
    void Clear() noexcept;
};

/**
 * @brief Verdict from behavior analysis.
 */
struct BehaviorVerdict {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Verdict type
    BehaviorVerdictType verdictType = BehaviorVerdictType::Clean;
    
    /// @brief Severity level
    BehaviorSeverity severity = BehaviorSeverity::Info;
    
    /// @brief Malice score
    double maliceScore = 0.0;
    
    /// @brief Confidence (0.0 - 1.0)
    double confidence = 0.0;
    
    /// @brief Recommended action
    RecommendedAction action = RecommendedAction::None;
    
    /// @brief Primary threat name
    std::wstring threatName;
    
    /// @brief Threat family
    std::wstring threatFamily;
    
    /// @brief Primary pattern detected
    BehaviorPatternType primaryPattern = BehaviorPatternType::Unknown;
    
    /// @brief All detected patterns
    std::vector<BehaviorPatternType> detectedPatterns;
    
    /// @brief MITRE ATT&CK techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Summary description
    std::wstring description;
    
    /// @brief Detailed findings
    std::vector<std::wstring> findings;
    
    /// @brief Triggering event ID
    uint64_t triggeringEventId = 0;
    
    /// @brief Related event IDs
    std::vector<uint64_t> relatedEventIds;
    
    /// @brief Verdict timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /**
     * @brief Check if verdict requires immediate action.
     */
    [[nodiscard]] bool RequiresImmediateAction() const noexcept {
        return action >= RecommendedAction::Terminate;
    }
};

/**
 * @brief Attack chain representing multi-step attack.
 */
struct AttackChain {
    /// @brief Unique chain ID
    uint64_t chainId = 0;
    
    /// @brief Chain creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Last update time
    std::chrono::system_clock::time_point lastUpdateTime{};
    
    /// @brief Primary attack type
    BehaviorPatternType primaryPattern = BehaviorPatternType::Unknown;
    
    /// @brief Chain confidence (0.0 - 1.0)
    double confidence = 0.0;
    
    /// @brief Involved process IDs
    std::vector<uint32_t> involvedProcessIds;
    
    /// @brief Chain of events
    std::vector<BehaviorEvent> events;
    
    /// @brief MITRE ATT&CK techniques in chain
    std::vector<std::string> mitreTechniques;
    
    /// @brief MITRE ATT&CK tactics represented
    std::vector<std::string> mitreTactics;
    
    /// @brief Initial access method
    std::wstring initialAccess;
    
    /// @brief Attack description
    std::wstring description;
    
    /// @brief Whether chain is still active
    bool isActive = true;
    
    /// @brief Whether chain has been reported
    bool hasBeenReported = false;
    
    /**
     * @brief Get chain duration.
     */
    [[nodiscard]] std::chrono::seconds GetDuration() const noexcept {
        if (events.empty()) return std::chrono::seconds(0);
        return std::chrono::duration_cast<std::chrono::seconds>(
            events.back().systemTime - events.front().systemTime
        );
    }
};

/**
 * @brief Configuration for behavior analyzer.
 */
struct BehaviorAnalyzerConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable behavior analysis
    bool enabled = true;
    
    /// @brief Warning threshold
    double warningThreshold = BehaviorConstants::WARNING_THRESHOLD;
    
    /// @brief Alert threshold
    double alertThreshold = BehaviorConstants::ALERT_THRESHOLD;
    
    /// @brief Block threshold
    double blockThreshold = BehaviorConstants::BLOCK_THRESHOLD;
    
    /// @brief Critical threshold
    double criticalThreshold = BehaviorConstants::CRITICAL_THRESHOLD;
    
    /// @brief Enable score decay over time
    bool enableScoreDecay = true;
    
    /// @brief Score decay rate per minute
    double scoreDecayRate = BehaviorConstants::SCORE_DECAY_PER_MINUTE;
    
    // -------------------------------------------------------------------------
    // Detection Categories
    // -------------------------------------------------------------------------
    
    /// @brief Enable ransomware detection
    bool detectRansomware = true;
    
    /// @brief Enable process injection detection
    bool detectProcessInjection = true;
    
    /// @brief Enable persistence detection
    bool detectPersistence = true;
    
    /// @brief Enable credential theft detection
    bool detectCredentialTheft = true;
    
    /// @brief Enable evasion detection
    bool detectEvasion = true;
    
    /// @brief Enable exfiltration detection
    bool detectExfiltration = true;
    
    /// @brief Enable lateral movement detection
    bool detectLateralMovement = true;
    
    /// @brief Enable C2 detection
    bool detectC2 = true;
    
    /// @brief Enable attack chain correlation
    bool enableAttackChains = true;
    
    // -------------------------------------------------------------------------
    // Ransomware Settings
    // -------------------------------------------------------------------------
    
    /// @brief File modification threshold for ransomware
    uint32_t ransomwareFileThreshold = BehaviorConstants::RANSOMWARE_FILE_THRESHOLD;
    
    /// @brief File modification rate threshold
    double ransomwareRateThreshold = BehaviorConstants::RANSOMWARE_RATE_THRESHOLD;
    
    /// @brief Enable canary file monitoring
    bool enableCanaryFiles = true;
    
    /// @brief Canary file paths
    std::vector<std::wstring> canaryFilePaths;
    
    // -------------------------------------------------------------------------
    // Response Settings
    // -------------------------------------------------------------------------
    
    /// @brief Auto-terminate on critical
    bool autoTerminateOnCritical = false;
    
    /// @brief Auto-suspend on block threshold
    bool autoSuspendOnBlock = false;
    
    /// @brief Response delay (ms) - grace period before action
    uint32_t responseDelayMs = 0;
    
    // -------------------------------------------------------------------------
    // Integration Settings
    // -------------------------------------------------------------------------
    
    /// @brief Trust signed Microsoft processes
    bool trustMicrosoftSigned = true;
    
    /// @brief Trust signed vendor processes
    bool trustVendorSigned = true;
    
    /// @brief Apply whitelist
    bool applyWhitelist = true;
    
    /// @brief Check ThreatIntel for network destinations
    bool checkThreatIntel = true;
    
    // -------------------------------------------------------------------------
    // Resource Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked processes
    size_t maxTrackedProcesses = BehaviorConstants::MAX_TRACKED_PROCESSES;
    
    /// @brief Maximum events per process
    size_t maxEventsPerProcess = BehaviorConstants::MAX_EVENTS_PER_PROCESS;
    
    /// @brief Event retention period
    std::chrono::hours eventRetentionPeriod = BehaviorConstants::EVENT_RETENTION_PERIOD;
    
    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------
    
    /// @brief Enable verbose logging
    bool verboseLogging = false;
    
    /// @brief Log all events
    bool logAllEvents = false;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static BehaviorAnalyzerConfig CreateDefault() noexcept {
        return BehaviorAnalyzerConfig{};
    }
    
    /**
     * @brief Create high-sensitivity configuration.
     */
    [[nodiscard]] static BehaviorAnalyzerConfig CreateHighSensitivity() noexcept {
        BehaviorAnalyzerConfig config;
        config.warningThreshold = 20.0;
        config.alertThreshold = 40.0;
        config.blockThreshold = 60.0;
        config.ransomwareFileThreshold = 20;
        config.ransomwareRateThreshold = 5.0;
        return config;
    }
    
    /**
     * @brief Create low-sensitivity configuration.
     */
    [[nodiscard]] static BehaviorAnalyzerConfig CreateLowSensitivity() noexcept {
        BehaviorAnalyzerConfig config;
        config.warningThreshold = 50.0;
        config.alertThreshold = 70.0;
        config.blockThreshold = 85.0;
        config.ransomwareFileThreshold = 100;
        return config;
    }
};

/**
 * @brief Statistics for behavior analyzer.
 */
struct BehaviorAnalyzerStats {
    /// @brief Total events processed
    std::atomic<uint64_t> totalEventsProcessed{ 0 };
    
    /// @brief Events per category
    std::array<std::atomic<uint64_t>, 16> eventsByCategory{};
    
    /// @brief Total verdicts generated
    std::atomic<uint64_t> totalVerdicts{ 0 };
    
    /// @brief Verdicts by type
    std::array<std::atomic<uint64_t>, 8> verdictsByType{};
    
    /// @brief Currently tracked processes
    std::atomic<size_t> trackedProcesses{ 0 };
    
    /// @brief Peak tracked processes
    std::atomic<size_t> peakTrackedProcesses{ 0 };
    
    /// @brief Active attack chains
    std::atomic<size_t> activeAttackChains{ 0 };
    
    /// @brief Ransomware detections
    std::atomic<uint64_t> ransomwareDetections{ 0 };
    
    /// @brief Injection detections
    std::atomic<uint64_t> injectionDetections{ 0 };
    
    /// @brief Persistence detections
    std::atomic<uint64_t> persistenceDetections{ 0 };
    
    /// @brief Credential theft detections
    std::atomic<uint64_t> credentialTheftDetections{ 0 };
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{ 0 };
    
    /// @brief Average processing time (microseconds)
    std::atomic<uint64_t> avgProcessingTimeUs{ 0 };
    
    /// @brief Events dropped (queue overflow)
    std::atomic<uint64_t> eventsDropped{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalEventsProcessed.store(0, std::memory_order_relaxed);
        for (auto& c : eventsByCategory) c.store(0, std::memory_order_relaxed);
        totalVerdicts.store(0, std::memory_order_relaxed);
        for (auto& v : verdictsByType) v.store(0, std::memory_order_relaxed);
        trackedProcesses.store(0, std::memory_order_relaxed);
        peakTrackedProcesses.store(0, std::memory_order_relaxed);
        activeAttackChains.store(0, std::memory_order_relaxed);
        ransomwareDetections.store(0, std::memory_order_relaxed);
        injectionDetections.store(0, std::memory_order_relaxed);
        persistenceDetections.store(0, std::memory_order_relaxed);
        credentialTheftDetections.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        avgProcessingTimeUs.store(0, std::memory_order_relaxed);
        eventsDropped.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types for behavior analysis.
 */
using BehaviorVerdictCallback = std::function<void(const BehaviorVerdict&)>;
using AttackChainCallback = std::function<void(const AttackChain&)>;
using ProcessTerminateCallback = std::function<bool(uint32_t pid, const std::wstring& reason)>;

// ============================================================================
// MAIN BEHAVIOR ANALYZER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade behavioral analysis engine.
 *
 * Maintains per-process state machines to detect complex attack patterns
 * including ransomware, process injection, credential theft, and multi-stage
 * attacks. Correlates events across processes to identify attack chains.
 *
 * Thread Safety: All public methods are thread-safe with lock-free fast paths
 * for common operations.
 *
 * Usage Example:
 * @code
 * auto& analyzer = BehaviorAnalyzer::Instance();
 * 
 * // Initialize
 * BehaviorAnalyzerConfig config = BehaviorAnalyzerConfig::CreateDefault();
 * config.autoTerminateOnCritical = true;
 * analyzer.Initialize(threadPool, config);
 * 
 * // Register callback for verdicts
 * analyzer.RegisterVerdictCallback([](const BehaviorVerdict& verdict) {
 *     if (verdict.severity >= BehaviorSeverity::High) {
 *         LOG_ALERT(L"Threat detected: {} (PID: {})", 
 *                   verdict.threatName, verdict.processId);
 *     }
 * });
 * 
 * // Process events (typically from ThreatDetector)
 * BehaviorEvent event;
 * event.processId = targetPid;
 * event.eventType = BehaviorEventType::FileWrite;
 * event.targetPath = L"C:\\Users\\...";
 * 
 * auto verdict = analyzer.ProcessEvent(event);
 * if (verdict && verdict->severity >= BehaviorSeverity::Critical) {
 *     // Immediate action required
 * }
 * 
 * // Query process state
 * auto state = analyzer.GetProcessState(targetPid);
 * LOG_INFO(L"Process malice score: {}", state.maliceScore);
 * 
 * analyzer.Shutdown();
 * @endcode
 */
class BehaviorAnalyzer {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global BehaviorAnalyzer instance.
     * @note Thread-safe (Meyers' singleton).
     */
    [[nodiscard]] static BehaviorAnalyzer& Instance();

    // Non-copyable, non-movable
    BehaviorAnalyzer(const BehaviorAnalyzer&) = delete;
    BehaviorAnalyzer& operator=(const BehaviorAnalyzer&) = delete;
    BehaviorAnalyzer(BehaviorAnalyzer&&) = delete;
    BehaviorAnalyzer& operator=(BehaviorAnalyzer&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the analyzer.
     * @param threadPool Thread pool for async operations.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     * @param threadPool Thread pool.
     * @param config Analyzer configuration.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const BehaviorAnalyzerConfig& config
    );

    /**
     * @brief Initialize with external dependencies.
     * @param threadPool Thread pool.
     * @param config Configuration.
     * @param threatIntel ThreatIntel index for IOC correlation.
     * @param whitelist Whitelist store for exclusions.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const BehaviorAnalyzerConfig& config,
        ThreatIntel::ThreatIntelIndex* threatIntel,
        Whitelist::WhitelistStore* whitelist
    );

    /**
     * @brief Shutdown the analyzer.
     */
    void Shutdown();

    /**
     * @brief Check if analyzer is initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration at runtime.
     */
    void UpdateConfig(const BehaviorAnalyzerConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] BehaviorAnalyzerConfig GetConfig() const;

    // =========================================================================
    // Event Processing
    // =========================================================================

    /**
     * @brief Process a behavior event.
     * @param event Normalized behavior event.
     * @return Optional verdict if event triggered detection threshold.
     */
    [[nodiscard]] std::optional<BehaviorVerdict> ProcessEvent(const BehaviorEvent& event);

    /**
     * @brief Process multiple events in batch.
     * @param events Vector of events.
     * @return Vector of verdicts generated (may be fewer than events).
     */
    [[nodiscard]] std::vector<BehaviorVerdict> ProcessEventBatch(
        const std::vector<BehaviorEvent>& events
    );

    /**
     * @brief Process event asynchronously.
     * @param event Event to process.
     * @return true if event was queued successfully.
     */
    bool ProcessEventAsync(BehaviorEvent event);

    /**
     * @brief Force evaluation of a process.
     * @param processId Process to evaluate.
     * @return Current verdict for the process.
     */
    [[nodiscard]] BehaviorVerdict EvaluateProcess(uint32_t processId);

    // =========================================================================
    // State Management
    // =========================================================================

    /**
     * @brief Get behavioral state for a process.
     * @param processId Target process ID.
     * @return Process state or default state if not tracked.
     */
    [[nodiscard]] ProcessBehaviorState GetProcessState(uint32_t processId) const;

    /**
     * @brief Check if process is being tracked.
     * @param processId Process ID.
     * @return true if process has behavioral state.
     */
    [[nodiscard]] bool IsProcessTracked(uint32_t processId) const noexcept;

    /**
     * @brief Get malice score for process.
     * @param processId Process ID.
     * @return Current malice score (0.0 if not tracked).
     */
    [[nodiscard]] double GetMaliceScore(uint32_t processId) const noexcept;

    /**
     * @brief Reset state for a process (typically on termination).
     * @param processId Process ID.
     */
    void ResetProcessState(uint32_t processId);

    /**
     * @brief Clear all process states.
     */
    void ClearAllStates();

    /**
     * @brief Get all tracked process IDs.
     * @return Vector of process IDs.
     */
    [[nodiscard]] std::vector<uint32_t> GetTrackedProcessIds() const;

    /**
     * @brief Get processes above threshold.
     * @param threshold Minimum malice score.
     * @return Vector of (process ID, malice score) pairs.
     */
    [[nodiscard]] std::vector<std::pair<uint32_t, double>> GetProcessesAboveThreshold(
        double threshold
    ) const;

    // =========================================================================
    // Attack Chain Management
    // =========================================================================

    /**
     * @brief Get active attack chains.
     * @return Vector of active attack chains.
     */
    [[nodiscard]] std::vector<AttackChain> GetActiveAttackChains() const;

    /**
     * @brief Get attack chain by ID.
     * @param chainId Chain identifier.
     * @return Attack chain or nullopt if not found.
     */
    [[nodiscard]] std::optional<AttackChain> GetAttackChain(uint64_t chainId) const;

    /**
     * @brief Get attack chains involving a process.
     * @param processId Process ID.
     * @return Vector of attack chains.
     */
    [[nodiscard]] std::vector<AttackChain> GetAttackChainsForProcess(uint32_t processId) const;

    // =========================================================================
    // Process Operations
    // =========================================================================

    /**
     * @brief Mark process as whitelisted.
     * @param processId Process ID.
     */
    void WhitelistProcess(uint32_t processId);

    /**
     * @brief Remove process from whitelist.
     * @param processId Process ID.
     */
    void UnwhitelistProcess(uint32_t processId);

    /**
     * @brief Adjust base score modifier for process.
     * @param processId Process ID.
     * @param modifier Score modifier (-100.0 to +100.0).
     */
    void SetProcessScoreModifier(uint32_t processId, double modifier);

    // =========================================================================
    // Canary File Management
    // =========================================================================

    /**
     * @brief Add canary file path.
     * @param path Path to canary file.
     */
    void AddCanaryFile(const std::wstring& path);

    /**
     * @brief Remove canary file path.
     * @param path Path to remove.
     */
    void RemoveCanaryFile(const std::wstring& path);

    /**
     * @brief Get all canary file paths.
     * @return Vector of canary file paths.
     */
    [[nodiscard]] std::vector<std::wstring> GetCanaryFiles() const;

    /**
     * @brief Check if path is a canary file.
     * @param path Path to check.
     * @return true if path is a canary file.
     */
    [[nodiscard]] bool IsCanaryFile(const std::wstring& path) const;

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register callback for verdicts.
     * @param callback Callback function.
     * @return Registration ID.
     */
    [[nodiscard]] uint64_t RegisterVerdictCallback(BehaviorVerdictCallback callback);

    /**
     * @brief Unregister verdict callback.
     * @param callbackId Registration ID.
     * @return true if callback was found and removed.
     */
    bool UnregisterVerdictCallback(uint64_t callbackId);

    /**
     * @brief Register callback for attack chains.
     * @param callback Callback function.
     * @return Registration ID.
     */
    [[nodiscard]] uint64_t RegisterAttackChainCallback(AttackChainCallback callback);

    /**
     * @brief Unregister attack chain callback.
     */
    bool UnregisterAttackChainCallback(uint64_t callbackId);

    /**
     * @brief Set process termination callback.
     * @param callback Callback that performs process termination.
     * @note Callback should return true if termination was successful.
     */
    void SetTerminationCallback(ProcessTerminateCallback callback);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get analyzer statistics.
     */
    [[nodiscard]] BehaviorAnalyzerStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // External Store Integration
    // =========================================================================

    /**
     * @brief Set ThreatIntel index for IOC correlation.
     */
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

    /**
     * @brief Set Whitelist store for exclusions.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set SignatureStore for pattern matching.
     */
    void SetSignatureStore(SignatureStore::SignatureStore* store);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    BehaviorAnalyzer();
    ~BehaviorAnalyzer();

    // =========================================================================
    // Internal Detection Engines
    // =========================================================================

    /**
     * @brief Update ransomware detection score.
     */
    void UpdateRansomwareScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update process injection detection score.
     */
    void UpdateInjectionScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update persistence detection score.
     */
    void UpdatePersistenceScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update credential theft detection score.
     */
    void UpdateCredentialScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update evasion detection score.
     */
    void UpdateEvasionScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update exfiltration detection score.
     */
    void UpdateExfiltrationScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update lateral movement detection score.
     */
    void UpdateLateralMovementScore(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Update C2 detection score.
     */
    void UpdateC2Score(ProcessBehaviorState& state, const BehaviorEvent& event);

    // =========================================================================
    // Internal Analysis Methods
    // =========================================================================

    /**
     * @brief Get or create process state.
     */
    ProcessBehaviorState& GetOrCreateState(uint32_t processId, const BehaviorEvent& event);

    /**
     * @brief Apply score decay to process state.
     */
    void ApplyScoreDecay(ProcessBehaviorState& state);

    /**
     * @brief Check if event triggers detection threshold.
     */
    std::optional<BehaviorVerdict> CheckThresholds(ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Correlate event with attack chains.
     */
    void CorrelateWithAttackChains(const BehaviorEvent& event, ProcessBehaviorState& state);

    /**
     * @brief Generate verdict from state.
     */
    BehaviorVerdict GenerateVerdict(const ProcessBehaviorState& state, const BehaviorEvent& event);

    /**
     * @brief Perform recommended action.
     */
    void PerformAction(const BehaviorVerdict& verdict);

    /**
     * @brief Add MITRE ATT&CK mapping for pattern.
     */
    void AddMitreMapping(ProcessBehaviorState& state, BehaviorPatternType pattern);

    /**
     * @brief Check if event target is sensitive.
     */
    bool IsSensitiveTarget(const BehaviorEvent& event) const;

    /**
     * @brief Check if process is trusted.
     */
    bool IsProcessTrusted(const ProcessBehaviorState& state) const;

    /**
     * @brief Invoke verdict callbacks.
     */
    void InvokeVerdictCallbacks(const BehaviorVerdict& verdict);

    /**
     * @brief Invoke attack chain callbacks.
     */
    void InvokeAttackChainCallbacks(const AttackChain& chain);

    /**
     * @brief Cleanup old states and chains.
     */
    void PerformCleanup();

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
 * @brief Create behavior event from file operation.
 */
[[nodiscard]] BehaviorEvent CreateFileEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::wstring& path,
    bool success = true
) noexcept;

/**
 * @brief Create behavior event from registry operation.
 */
[[nodiscard]] BehaviorEvent CreateRegistryEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::wstring& keyPath,
    const std::wstring& valueName = L"",
    bool success = true
) noexcept;

/**
 * @brief Create behavior event from network operation.
 */
[[nodiscard]] BehaviorEvent CreateNetworkEvent(
    BehaviorEventType type,
    uint32_t processId,
    const std::string& remoteHost,
    uint16_t remotePort,
    const std::string& protocol = "TCP"
) noexcept;

/**
 * @brief Create behavior event from process operation.
 */
[[nodiscard]] BehaviorEvent CreateProcessEvent(
    BehaviorEventType type,
    uint32_t sourceProcessId,
    uint32_t targetProcessId = 0
) noexcept;

/**
 * @brief Calculate file entropy.
 */
[[nodiscard]] double CalculateFileEntropy(const std::wstring& filePath) noexcept;

/**
 * @brief Check if path matches ransomware note pattern.
 */
[[nodiscard]] bool IsRansomNotePattern(const std::wstring& path) noexcept;

/**
 * @brief Check if registry path is persistence location.
 */
[[nodiscard]] bool IsPersistenceRegistryPath(const std::wstring& path) noexcept;

/**
 * @brief Check if process name is LSASS.
 */
[[nodiscard]] bool IsLSASSProcess(const std::wstring& processName) noexcept;

/**
 * @brief Check if process is document application.
 */
[[nodiscard]] bool IsDocumentApplication(const std::wstring& processName) noexcept;

/**
 * @brief Check if process is script interpreter.
 */
[[nodiscard]] bool IsScriptInterpreter(const std::wstring& processName) noexcept;

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
