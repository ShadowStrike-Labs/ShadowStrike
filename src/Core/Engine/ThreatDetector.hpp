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
 * ShadowStrike Core Engine - THREAT DETECTOR (The Central Analyst)
 * ============================================================================
 *
 * @file ThreatDetector.hpp
 * @brief Enterprise-grade central threat detection and event correlation engine.
 *
 * ThreatDetector is the central nervous system of the ShadowStrike NGAV engine.
 * It ingests real-time event streams from all sensors, correlates them, and
 * produces actionable threat verdicts. While individual modules detect specific
 * patterns, ThreatDetector orchestrates the overall threat assessment.
 *
 * =============================================================================
 * CORE RESPONSIBILITIES
 * =============================================================================
 *
 * 1. **Event Ingestion & Normalization**
 *    - Receives events from ProcessMonitor, FileWatcher, RegistryMonitor, NetworkMonitor
 *    - Normalizes events into canonical format
 *    - Enriches events with process context and threat intelligence
 *
 * 2. **Threat Correlation**
 *    - Correlates events across processes, time, and resources
 *    - Identifies attack chains and campaigns
 *    - Tracks threat actors across sessions
 *
 * 3. **Multi-Engine Orchestration**
 *    - Routes events to appropriate detection engines
 *    - Aggregates verdicts from BehaviorAnalyzer, HeuristicAnalyzer, EmulationEngine
 *    - Manages confidence levels and false positive reduction
 *
 * 4. **Response Coordination**
 *    - Generates unified threat verdicts
 *    - Triggers appropriate responses (block, quarantine, alert)
 *    - Coordinates with RealTimeProtection for enforcement
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 *                              ┌─────────────────────────────────────────────────────────────┐
 *                              │                      SENSORS                                  │
 *                              │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
 *                              │  │ Process │ │  File   │ │Registry │ │ Network │           │
 *                              │  │ Monitor │ │ Watcher │ │ Monitor │ │ Monitor │           │
 *                              │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
 *                              │       │           │           │           │                 │
 *                              └───────┴───────────┴───────────┴───────────┴─────────────────┘
 *                                      │           │           │           │
 *                                      ▼           ▼           ▼           ▼
 *                              ┌─────────────────────────────────────────────────────────────┐
 *                              │                    EVENT BUS                                 │
 *                              │  - Lock-free SPMC queue                                      │
 *                              │  - Event batching                                            │
 *                              │  - Back-pressure handling                                    │
 *                              └────────────────────────────┬────────────────────────────────┘
 *                                                           │
 *                                                           ▼
 * ┌───────────────────────────────────────────────────────────────────────────────────────────────┐
 * │                                     THREAT DETECTOR                                            │
 * ├───────────────────────────────────────────────────────────────────────────────────────────────┤
 * │                                                                                                │
 * │  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
 * │  │                           Event Normalization & Enrichment                               │ │
 * │  │  - Canonical event format                                                                │ │
 * │  │  - Process context injection                                                             │ │
 * │  │  - ThreatIntel enrichment                                                                │ │
 * │  │  - Whitelist filtering                                                                   │ │
 * │  └─────────────────────────────────────────────────────────────────┬─────────────────────────┘ │
 * │                                                                    │                          │
 * │                                                                    ▼                          │
 * │  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
 * │  │                              Detection Engine Router                                     │ │
 * │  │                                                                                          │ │
 * │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │ │
 * │  │  │   Behavior    │  │   Heuristic   │  │  Emulation    │  │  Signature    │            │ │
 * │  │  │   Analyzer    │  │   Analyzer    │  │   Engine      │  │   Engine      │            │ │
 * │  │  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘            │ │
 * │  │          │                  │                  │                  │                     │ │
 * │  │          └──────────────────┴──────────────────┴──────────────────┘                     │ │
 * │  │                                        │                                                │ │
 * │  └────────────────────────────────────────┼────────────────────────────────────────────────┘ │
 * │                                           ▼                                                   │
 * │  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
 * │  │                              Verdict Aggregator                                          │ │
 * │  │  - Multi-engine verdict fusion                                                           │ │
 * │  │  - Confidence calculation                                                                │ │
 * │  │  - False positive suppression                                                            │ │
 * │  │  - Attack chain assembly                                                                 │ │
 * │  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
 * │                                           │                                                   │
 * │                                           ▼                                                   │
 * │  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
 * │  │                              Response Coordinator                                        │ │
 * │  │  - Action determination                                                                  │ │
 * │  │  - Alert generation                                                                      │ │
 * │  │  - Remediation triggering                                                                │ │
 * │  │  - Telemetry reporting                                                                   │ │
 * │  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                                │
 * └───────────────────────────────────────────────────────────────────────────────────────────────┘
 *                                           │
 *                                           ▼
 *                              ┌─────────────────────────────────────────────────────────────┐
 *                              │                   RESPONSE LAYER                             │
 *                              │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
 *                              │  │  Block  │ │Quarantine│ │  Alert  │ │ Isolate │           │
 *                              │  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
 *                              └─────────────────────────────────────────────────────────────┘
 *
 * =============================================================================
 * EVENT CATEGORIES
 * =============================================================================
 *
 * | Category      | Events                                                      |
 * |---------------|-------------------------------------------------------------|
 * | Process       | Create, Terminate, Suspend, Resume, Inject                  |
 * | Thread        | Create, Terminate, RemoteCreate, SetContext                 |
 * | Memory        | Allocate, Free, Protect, Write, Map                         |
 * | File          | Create, Open, Write, Delete, Rename, SetAttributes          |
 * | Registry      | CreateKey, SetValue, DeleteKey, DeleteValue                 |
 * | Network       | Connect, Listen, Send, Receive, DNS                         |
 * | Service       | Install, Start, Stop, Delete                                |
 * | WMI           | Query, Subscription, Exec                                   |
 * | Script        | PowerShell, VBScript, JavaScript, CMD                       |
 *
 * =============================================================================
 * THREAT CATEGORIES
 * =============================================================================
 *
 * | Threat Type        | Detection Strategy                                    |
 * |--------------------|-------------------------------------------------------|
 * | Malware            | Signature + Heuristic + Fuzzy + Emulation             |
 * | Ransomware         | Behavior (rapid encryption, shadow copy deletion)     |
 * | Process Injection  | Behavior (remote allocation, thread creation)         |
 * | Credential Theft   | Behavior (LSASS access) + Signature (mimikatz)        |
 * | Persistence        | Behavior (run keys, services, tasks)                  |
 * | Lateral Movement   | Behavior (remote execution) + Network                 |
 * | C2 Communication   | Behavior (beaconing) + ThreatIntel (IOC)              |
 * | Data Exfiltration  | Behavior (large transfers) + Network                  |
 * | Rootkit            | Integrity checks + Kernel callbacks                   |
 * | Exploit            | Emulation + Behavior (unusual parent-child)           |
 *
 * =============================================================================
 * MITRE ATT&CK MAPPING
 * =============================================================================
 *
 * Full coverage of MITRE ATT&CK Enterprise matrix:
 * - Initial Access (TA0001)
 * - Execution (TA0002)
 * - Persistence (TA0003)
 * - Privilege Escalation (TA0004)
 * - Defense Evasion (TA0005)
 * - Credential Access (TA0006)
 * - Discovery (TA0007)
 * - Lateral Movement (TA0008)
 * - Collection (TA0009)
 * - Command and Control (TA0011)
 * - Exfiltration (TA0010)
 * - Impact (TA0040)
 *
 * @note Thread-safe for all public methods
 * @note Lock-free event ingestion
 *
 * @see BehaviorAnalyzer for behavioral detection
 * @see HeuristicAnalyzer for static analysis
 * @see EmulationEngine for dynamic analysis
 * @see ScanEngine for signature scanning
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
#include "../../Utils/FileUtils.hpp"          // File analysis
#include "../../Utils/RegistryUtils.hpp"      // Registry events
#include "../../Utils/NetworkUtils.hpp"       // Network events
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IOC correlation
#include "../../PatternStore/PatternStore.hpp" // Behavioral patterns
#include "../../Whitelist/WhiteListStore.hpp" // Trusted processes

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
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
        class Logger;
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
    namespace Core {
        namespace Engine {
            class BehaviorAnalyzer;
            class HeuristicAnalyzer;
            class EmulationEngine;
            class ScanEngine;
            class QuarantineManager;
            class PackerUnpacker;
            class PolymorphicDetector;
            class ZeroDayDetector;
            class SandboxAnalyzer;
            class MachineLearningDetector;
        }
    }
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ThreatDetector;
struct SystemEvent;
struct ThreatVerdict;
struct ThreatContext;
struct DetectionRule;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace ThreatDetectorConstants {
    // -------------------------------------------------------------------------
    // Event Processing
    // -------------------------------------------------------------------------
    
    /// @brief Maximum events per second
    constexpr uint64_t MAX_EVENTS_PER_SECOND = 100000;
    
    /// @brief Event queue capacity
    constexpr size_t EVENT_QUEUE_CAPACITY = 1000000;
    
    /// @brief Event batch size
    constexpr size_t EVENT_BATCH_SIZE = 1000;
    
    /// @brief Event processing threads
    constexpr size_t EVENT_PROCESSING_THREADS = 4;
    
    /// @brief Event retention period
    constexpr std::chrono::hours EVENT_RETENTION{ 24 };
    
    // -------------------------------------------------------------------------
    // Threat Scoring
    // -------------------------------------------------------------------------
    
    /// @brief Minimum score for detection
    constexpr double DETECTION_THRESHOLD = 50.0;
    
    /// @brief Critical threat threshold
    constexpr double CRITICAL_THRESHOLD = 90.0;
    
    /// @brief High threat threshold
    constexpr double HIGH_THRESHOLD = 70.0;
    
    /// @brief Medium threat threshold
    constexpr double MEDIUM_THRESHOLD = 50.0;
    
    /// @brief Low threat threshold
    constexpr double LOW_THRESHOLD = 30.0;
    
    /// @brief Maximum threat score
    constexpr double MAX_THREAT_SCORE = 100.0;
    
    // -------------------------------------------------------------------------
    // Correlation
    // -------------------------------------------------------------------------
    
    /// @brief Correlation window (seconds)
    constexpr std::chrono::seconds CORRELATION_WINDOW{ 300 };
    
    /// @brief Maximum correlated events
    constexpr size_t MAX_CORRELATED_EVENTS = 1000;
    
    /// @brief Attack chain timeout
    constexpr std::chrono::minutes ATTACK_CHAIN_TIMEOUT{ 60 };
    
    // -------------------------------------------------------------------------
    // Engine Weights
    // -------------------------------------------------------------------------
    
    /// @brief Signature engine weight
    constexpr double SIGNATURE_WEIGHT = 1.0;
    
    /// @brief Behavior engine weight
    constexpr double BEHAVIOR_WEIGHT = 0.9;
    
    /// @brief Heuristic engine weight
    constexpr double HEURISTIC_WEIGHT = 0.7;
    
    /// @brief Emulation engine weight
    constexpr double EMULATION_WEIGHT = 0.95;
    
    /// @brief ThreatIntel weight
    constexpr double THREATINTEL_WEIGHT = 0.85;

    /// @brief Machine Learning weight
    constexpr double ML_WEIGHT = 0.80;

    /// @brief Packer/Unpacker weight
    constexpr double PACKER_WEIGHT = 0.75;

    /// @brief Polymorphic detector weight
    constexpr double POLYMORPHIC_WEIGHT = 0.85;

    /// @brief Zero-day detector weight
    constexpr double ZERODAY_WEIGHT = 0.95;

    /// @brief Sandbox analyzer weight
    constexpr double SANDBOX_WEIGHT = 0.90;
    
    // -------------------------------------------------------------------------
    // Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked processes
    constexpr size_t MAX_TRACKED_PROCESSES = 100000;
    
    /// @brief Maximum active threats
    constexpr size_t MAX_ACTIVE_THREATS = 10000;
    
    /// @brief Maximum rules
    constexpr size_t MAX_RULES = 50000;
    
    /// @brief Maximum IOC cache size
    constexpr size_t MAX_IOC_CACHE = 1000000;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Category of system event.
 */
enum class EventCategory : uint8_t {
    Unknown = 0,
    Process = 1,
    Thread = 2,
    Memory = 3,
    File = 4,
    Registry = 5,
    Network = 6,
    Service = 7,
    WMI = 8,
    Script = 9,
    Driver = 10,
    Handle = 11,
    Token = 12,
    COM = 13,
    Crypto = 14,
    System = 15
};

/**
 * @brief Specific event type.
 */
enum class EventType : uint16_t {
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // Process Events (1-49)
    // -------------------------------------------------------------------------
    ProcessCreate = 1,
    ProcessTerminate = 2,
    ProcessOpen = 3,
    ProcessDuplicate = 4,
    ProcessSuspend = 5,
    ProcessResume = 6,
    ProcessInject = 7,
    ProcessHollow = 8,
    ProcessImageLoad = 9,
    
    // -------------------------------------------------------------------------
    // Thread Events (50-99)
    // -------------------------------------------------------------------------
    ThreadCreate = 50,
    ThreadTerminate = 51,
    ThreadRemoteCreate = 52,
    ThreadSetContext = 53,
    ThreadSuspend = 54,
    ThreadResume = 55,
    ThreadQueueAPC = 56,
    
    // -------------------------------------------------------------------------
    // Memory Events (100-149)
    // -------------------------------------------------------------------------
    MemoryAllocate = 100,
    MemoryFree = 101,
    MemoryProtect = 102,
    MemoryWrite = 103,
    MemoryRead = 104,
    MemoryRemoteAllocate = 105,
    MemoryRemoteWrite = 106,
    MemoryMap = 107,
    MemoryUnmap = 108,
    
    // -------------------------------------------------------------------------
    // File Events (150-199)
    // -------------------------------------------------------------------------
    FileCreate = 150,
    FileOpen = 151,
    FileRead = 152,
    FileWrite = 153,
    FileDelete = 154,
    FileRename = 155,
    FileSetAttributes = 156,
    FileSetSecurity = 157,
    FileLock = 158,
    FileUnlock = 159,
    FileEncrypt = 160,
    DirectoryCreate = 170,
    DirectoryDelete = 171,
    DirectoryEnumerate = 172,
    
    // -------------------------------------------------------------------------
    // Registry Events (200-249)
    // -------------------------------------------------------------------------
    RegistryCreateKey = 200,
    RegistryDeleteKey = 201,
    RegistrySetValue = 202,
    RegistryDeleteValue = 203,
    RegistryQueryValue = 204,
    RegistryEnumKey = 205,
    RegistryEnumValue = 206,
    RegistryLoadHive = 207,
    RegistryRenameKey = 208,
    
    // -------------------------------------------------------------------------
    // Network Events (250-299)
    // -------------------------------------------------------------------------
    NetworkConnect = 250,
    NetworkListen = 251,
    NetworkAccept = 252,
    NetworkSend = 253,
    NetworkReceive = 254,
    NetworkDNSQuery = 255,
    NetworkHTTPRequest = 256,
    NetworkHTTPSRequest = 257,
    NetworkDownload = 258,
    NetworkUpload = 259,
    
    // -------------------------------------------------------------------------
    // Service Events (300-349)
    // -------------------------------------------------------------------------
    ServiceInstall = 300,
    ServiceStart = 301,
    ServiceStop = 302,
    ServiceDelete = 303,
    ServiceModify = 304,
    
    // -------------------------------------------------------------------------
    // WMI Events (350-399)
    // -------------------------------------------------------------------------
    WMIQuery = 350,
    WMISubscription = 351,
    WMIExec = 352,
    WMIConsumer = 353,
    
    // -------------------------------------------------------------------------
    // Script Events (400-449)
    // -------------------------------------------------------------------------
    ScriptExecute = 400,
    PowerShellCommand = 401,
    PowerShellScript = 402,
    VBScriptExecute = 403,
    JScriptExecute = 404,
    BatchExecute = 405,
    
    // -------------------------------------------------------------------------
    // Driver Events (450-499)
    // -------------------------------------------------------------------------
    DriverLoad = 450,
    DriverUnload = 451,
    DriverCommunication = 452,
    
    // -------------------------------------------------------------------------
    // Token/Credential Events (500-549)
    // -------------------------------------------------------------------------
    TokenSteal = 500,
    TokenDuplicate = 501,
    TokenImpersonate = 502,
    CredentialAccess = 503,
    LSASSAccess = 504,
    SAMAccess = 505,
    
    // -------------------------------------------------------------------------
    // System Events (550-599)
    // -------------------------------------------------------------------------
    SystemShutdown = 550,
    SystemReboot = 551,
    ShadowCopyDelete = 552,
    BootConfigModify = 553,
    LogClear = 554,
    SecurityDisable = 555,
    Timestomp = 556
};

/**
 * @brief Threat severity level.
 */
enum class ThreatSeverity : uint8_t {
    None = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Critical = 100
};

/**
 * @brief Threat category.
 */
enum class ThreatCategory : uint8_t {
    Unknown = 0,
    
    /// @brief Generic malware
    Malware = 1,
    
    /// @brief Ransomware
    Ransomware = 2,
    
    /// @brief Trojan
    Trojan = 3,
    
    /// @brief Worm
    Worm = 4,
    
    /// @brief Virus
    Virus = 5,
    
    /// @brief Spyware
    Spyware = 6,
    
    /// @brief Adware
    Adware = 7,
    
    /// @brief PUP (Potentially Unwanted Program)
    PUP = 8,
    
    /// @brief Rootkit
    Rootkit = 9,
    
    /// @brief Bootkit
    Bootkit = 10,
    
    /// @brief Backdoor
    Backdoor = 11,
    
    /// @brief Dropper
    Dropper = 12,
    
    /// @brief Downloader
    Downloader = 13,
    
    /// @brief Miner
    CryptoMiner = 14,
    
    /// @brief RAT (Remote Access Trojan)
    RAT = 15,
    
    /// @brief Keylogger
    Keylogger = 16,
    
    /// @brief Stealer
    InfoStealer = 17,
    
    /// @brief Exploit
    Exploit = 18,
    
    /// @brief Fileless attack
    Fileless = 19,
    
    /// @brief APT (Advanced Persistent Threat)
    APT = 20,
    
    /// @brief Hack tool
    HackTool = 21,
    
    /// @brief Suspicious behavior
    SuspiciousBehavior = 22
};

/**
 * @brief Detection source/engine.
 */
enum class DetectionSource : uint8_t {
    None = 0,
    SignatureEngine = 1,
    BehaviorAnalyzer = 2,
    HeuristicAnalyzer = 3,
    EmulationEngine = 4,
    ThreatIntel = 5,
    MachineLearning = 6,
    YARARule = 7,
    ManualRule = 8,
    Correlation = 9,
    UserReport = 10
};

/**
 * @brief Response action type.
 */
enum class ResponseAction : uint8_t {
    None = 0,
    Log = 1,
    Alert = 2,
    Block = 3,
    Quarantine = 4,
    Terminate = 5,
    Remediate = 6,
    Isolate = 7,
    Rollback = 8
};

/**
 * @brief Verdict confidence level.
 */
enum class ConfidenceLevel : uint8_t {
    Unknown = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Confirmed = 100
};

/**
 * @brief Get string representation of EventType.
 */
[[nodiscard]] constexpr const char* EventTypeToString(EventType type) noexcept;

/**
 * @brief Get string representation of ThreatCategory.
 */
[[nodiscard]] constexpr const char* ThreatCategoryToString(ThreatCategory category) noexcept;

/**
 * @brief Get MITRE ATT&CK tactic for threat category.
 */
[[nodiscard]] constexpr const char* ThreatCategoryToMitreTactic(ThreatCategory category) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Normalized system event.
 */
struct alignas(64) SystemEvent {
    // -------------------------------------------------------------------------
    // Event Identification
    // -------------------------------------------------------------------------
    
    /// @brief Unique event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp (steady clock)
    std::chrono::steady_clock::time_point timestamp{};
    
    /// @brief System time
    std::chrono::system_clock::time_point systemTime{};
    
    /// @brief Event category
    EventCategory category = EventCategory::Unknown;
    
    /// @brief Event type
    EventType eventType = EventType::Unknown;
    
    // -------------------------------------------------------------------------
    // Source Process
    // -------------------------------------------------------------------------
    
    /// @brief Source process ID
    uint32_t processId = 0;
    
    /// @brief Source thread ID
    uint32_t threadId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
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
    
    /// @brief User name
    std::wstring userName;
    
    // -------------------------------------------------------------------------
    // Target Information
    // -------------------------------------------------------------------------
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target thread ID
    uint32_t targetThreadId = 0;
    
    /// @brief Target path (file, registry, etc.)
    std::wstring targetPath;
    
    /// @brief Previous target path (for rename operations)
    std::wstring previousPath;
    
    /// @brief Target address (for memory operations)
    uint64_t targetAddress = 0;
    
    /// @brief Target size
    uint64_t targetSize = 0;
    
    // -------------------------------------------------------------------------
    // Operation Details
    // -------------------------------------------------------------------------
    
    /// @brief Operation name
    std::wstring operation;
    
    /// @brief Operation details
    std::wstring details;
    
    /// @brief Access mask
    uint32_t accessMask = 0;
    
    /// @brief Desired access
    uint32_t desiredAccess = 0;
    
    /// @brief Operation result
    bool success = false;
    
    /// @brief NT status code
    int32_t statusCode = 0;
    
    // -------------------------------------------------------------------------
    // File-Specific
    // -------------------------------------------------------------------------
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief File entropy
    double fileEntropy = 0.0;
    
    /// @brief File hash (SHA256)
    std::string fileHash;
    
    /// @brief Is file signed
    bool isFileSigned = false;
    
    /// @brief File signer
    std::wstring fileSigner;
    
    // -------------------------------------------------------------------------
    // Registry-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Registry value name
    std::wstring valueName;
    
    /// @brief Registry value type
    uint32_t valueType = 0;
    
    /// @brief Registry value data
    std::vector<uint8_t> valueData;
    
    // -------------------------------------------------------------------------
    // Network-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Remote hostname
    std::string remoteHost;
    
    /// @brief Remote IP
    std::string remoteIP;
    
    /// @brief Remote port
    uint16_t remotePort = 0;
    
    /// @brief Local IP
    std::string localIP;
    
    /// @brief Local port
    uint16_t localPort = 0;
    
    /// @brief Protocol
    std::string protocol;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief DNS query
    std::string dnsQuery;
    
    /// @brief DNS response
    std::vector<std::string> dnsResponse;
    
    // -------------------------------------------------------------------------
    // Script-Specific
    // -------------------------------------------------------------------------
    
    /// @brief Script content (truncated)
    std::wstring scriptContent;
    
    /// @brief Script hash
    std::string scriptHash;
    
    // -------------------------------------------------------------------------
    // Enrichment Data
    // -------------------------------------------------------------------------
    
    /// @brief Is process signed
    bool isProcessSigned = false;
    
    /// @brief Process signer
    std::wstring processSigner;
    
    /// @brief Is target known malicious (from ThreatIntel)
    bool isTargetMalicious = false;
    
    /// @brief ThreatIntel match info
    std::wstring threatIntelMatch;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Event priority (for processing order)
    uint8_t priority = 0;
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Get event age.
     */
    [[nodiscard]] std::chrono::milliseconds GetAge() const noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - timestamp
        );
    }
    
    /**
     * @brief Check if event is cross-process operation.
     */
    [[nodiscard]] bool IsCrossProcess() const noexcept {
        return targetProcessId != 0 && targetProcessId != processId;
    }
};

/**
 * @brief Threat context for enrichment.
 */
struct ThreatContext {
    /// @brief Process chain (from root to current)
    std::vector<uint32_t> processChain;
    
    /// @brief Process names in chain
    std::vector<std::wstring> processNames;
    
    /// @brief Related file hashes
    std::vector<std::string> relatedHashes;
    
    /// @brief Related network IOCs
    std::vector<std::string> relatedNetworkIOCs;
    
    /// @brief Related registry paths
    std::vector<std::wstring> relatedRegistryPaths;
    
    /// @brief MITRE techniques observed
    std::vector<std::string> mitreTechniques;
    
    /// @brief MITRE tactics observed
    std::vector<std::string> mitreTactics;
    
    /// @brief Timeline of events
    std::vector<uint64_t> eventTimeline;
    
    /// @brief Attack chain ID (if part of chain)
    uint64_t attackChainId = 0;
    
    /// @brief Campaign ID (if identified)
    std::string campaignId;
    
    /// @brief Threat actor (if identified)
    std::wstring threatActor;
};

/**
 * @brief Detection from a specific engine.
 */
struct EngineDetection {
    /// @brief Detection source
    DetectionSource source = DetectionSource::None;
    
    /// @brief Detection score (0-100)
    double score = 0.0;
    
    /// @brief Confidence (0-1)
    double confidence = 0.0;
    
    /// @brief Detection name
    std::wstring detectionName;
    
    /// @brief Detection family
    std::wstring family;
    
    /// @brief Rule/signature ID
    std::string ruleId;
    
    /// @brief Detection details
    std::wstring details;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Timestamp
    std::chrono::system_clock::time_point timestamp{};
};

/**
 * @brief Unified threat verdict.
 */
struct ThreatVerdict {
    // -------------------------------------------------------------------------
    // Verdict Identification
    // -------------------------------------------------------------------------
    
    /// @brief Unique verdict ID
    uint64_t verdictId = 0;
    
    /// @brief Timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    // -------------------------------------------------------------------------
    // Threat Classification
    // -------------------------------------------------------------------------
    
    /// @brief Is threat detected
    bool isThreat = false;
    
    /// @brief Threat severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Threat category
    ThreatCategory category = ThreatCategory::Unknown;
    
    /// @brief Overall threat score (0-100)
    double threatScore = 0.0;
    
    /// @brief Confidence level
    ConfidenceLevel confidence = ConfidenceLevel::Unknown;
    
    // -------------------------------------------------------------------------
    // Threat Information
    // -------------------------------------------------------------------------
    
    /// @brief Primary threat name
    std::wstring threatName;
    
    /// @brief Threat family
    std::wstring threatFamily;
    
    /// @brief Threat variant
    std::wstring threatVariant;
    
    /// @brief Threat description
    std::wstring description;
    
    /// @brief Threat hash (if file-based)
    std::string threatHash;
    
    // -------------------------------------------------------------------------
    // Target Information
    // -------------------------------------------------------------------------
    
    /// @brief Target process ID
    uint32_t processId = 0;
    
    /// @brief Target process name
    std::wstring processName;
    
    /// @brief Target process path
    std::wstring processPath;
    
    /// @brief Target file path (if applicable)
    std::wstring filePath;
    
    /// @brief User name
    std::wstring userName;
    
    // -------------------------------------------------------------------------
    // Detection Details
    // -------------------------------------------------------------------------
    
    /// @brief Primary detection source
    DetectionSource primarySource = DetectionSource::None;
    
    /// @brief All engine detections
    std::vector<EngineDetection> engineDetections;
    
    /// @brief Triggering event ID
    uint64_t triggeringEventId = 0;
    
    /// @brief Related event IDs
    std::vector<uint64_t> relatedEventIds;
    
    // -------------------------------------------------------------------------
    // MITRE ATT&CK
    // -------------------------------------------------------------------------
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief MITRE tactics
    std::vector<std::string> mitreTactics;
    
    // -------------------------------------------------------------------------
    // Response
    // -------------------------------------------------------------------------
    
    /// @brief Recommended action
    ResponseAction recommendedAction = ResponseAction::None;
    
    /// @brief Action taken
    ResponseAction actionTaken = ResponseAction::None;
    
    /// @brief Was action successful
    bool actionSuccessful = false;
    
    /// @brief Action details
    std::wstring actionDetails;
    
    // -------------------------------------------------------------------------
    // Context
    // -------------------------------------------------------------------------
    
    /// @brief Threat context
    ThreatContext context;
    
    /// @brief Is part of attack chain
    bool isAttackChain = false;
    
    /// @brief Attack chain ID
    uint64_t attackChainId = 0;
    
    // -------------------------------------------------------------------------
    // Reporting
    // -------------------------------------------------------------------------
    
    /// @brief Has been reported
    bool hasBeenReported = false;
    
    /// @brief Report timestamp
    std::chrono::system_clock::time_point reportTimestamp{};
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Check if immediate action required.
     */
    [[nodiscard]] bool RequiresImmediateAction() const noexcept {
        return severity >= ThreatSeverity::High;
    }
    
    /**
     * @brief Get severity string.
     */
    [[nodiscard]] std::string GetSeverityString() const noexcept {
        switch (severity) {
            case ThreatSeverity::Critical: return "Critical";
            case ThreatSeverity::High: return "High";
            case ThreatSeverity::Medium: return "Medium";
            case ThreatSeverity::Low: return "Low";
            default: return "None";
        }
    }
};

/**
 * @brief Custom detection rule.
 */
struct DetectionRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::wstring name;
    
    /// @brief Rule description
    std::wstring description;
    
    /// @brief Author
    std::string author;
    
    /// @brief Created date
    std::chrono::system_clock::time_point created{};
    
    /// @brief Modified date
    std::chrono::system_clock::time_point modified{};
    
    /// @brief Is rule enabled
    bool enabled = true;
    
    /// @brief Severity
    ThreatSeverity severity = ThreatSeverity::Medium;
    
    /// @brief Category
    ThreatCategory category = ThreatCategory::Unknown;
    
    /// @brief Event types to match
    std::vector<EventType> eventTypes;
    
    /// @brief Process name patterns
    std::vector<std::wstring> processPatterns;
    
    /// @brief Target path patterns
    std::vector<std::wstring> targetPatterns;
    
    /// @brief Command line patterns
    std::vector<std::wstring> commandLinePatterns;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Score contribution
    double scoreContribution = 0.0;
    
    /// @brief Is atomic (single event) or composite (sequence)
    bool isAtomic = true;
    
    /// @brief Sequence timeout (for composite rules)
    std::chrono::seconds sequenceTimeout{ 60 };
};

/**
 * @brief Attack chain (correlated threat events).
 */
struct AttackChain {
    /// @brief Chain ID
    uint64_t chainId = 0;
    
    /// @brief Creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Last update time
    std::chrono::system_clock::time_point lastUpdateTime{};
    
    /// @brief Overall severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Overall confidence
    double confidence = 0.0;
    
    /// @brief Primary threat category
    ThreatCategory category = ThreatCategory::Unknown;
    
    /// @brief Attack name
    std::wstring attackName;
    
    /// @brief Attack description
    std::wstring description;
    
    /// @brief Involved process IDs
    std::vector<uint32_t> involvedProcessIds;
    
    /// @brief Involved file paths
    std::vector<std::wstring> involvedFiles;
    
    /// @brief Involved network IOCs
    std::vector<std::string> involvedNetworkIOCs;
    
    /// @brief Event sequence
    std::vector<uint64_t> eventIds;
    
    /// @brief Verdicts in chain
    std::vector<uint64_t> verdictIds;
    
    /// @brief MITRE techniques in chain
    std::vector<std::string> mitreTechniques;
    
    /// @brief MITRE tactics covered
    std::vector<std::string> mitreTactics;
    
    /// @brief Initial access vector
    std::wstring initialAccess;
    
    /// @brief Campaign (if identified)
    std::string campaignId;
    
    /// @brief Threat actor (if identified)
    std::wstring threatActor;
    
    /// @brief Is chain active
    bool isActive = true;
    
    /// @brief Is chain complete
    bool isComplete = false;
    
    /**
     * @brief Get chain duration.
     */
    [[nodiscard]] std::chrono::seconds GetDuration() const noexcept {
        return std::chrono::duration_cast<std::chrono::seconds>(
            lastUpdateTime - creationTime
        );
    }
};

/**
 * @brief Configuration for threat detector.
 */
struct ThreatDetectorConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable threat detection
    bool enabled = true;
    
    /// @brief Number of processing threads
    size_t processingThreads = ThreatDetectorConstants::EVENT_PROCESSING_THREADS;
    
    /// @brief Event queue capacity
    size_t eventQueueCapacity = ThreatDetectorConstants::EVENT_QUEUE_CAPACITY;
    
    // -------------------------------------------------------------------------
    // Detection Engines
    // -------------------------------------------------------------------------
    
    /// @brief Enable signature engine
    bool enableSignatureEngine = true;
    
    /// @brief Enable behavior analyzer
    bool enableBehaviorAnalyzer = true;
    
    /// @brief Enable heuristic analyzer
    bool enableHeuristicAnalyzer = true;
    
    /// @brief Enable emulation engine
    bool enableEmulationEngine = true;
    
    /// @brief Enable ThreatIntel correlation
    bool enableThreatIntel = true;
    
    // -------------------------------------------------------------------------
    // Threshold Settings
    // -------------------------------------------------------------------------
    
    /// @brief Detection threshold
    double detectionThreshold = ThreatDetectorConstants::DETECTION_THRESHOLD;
    
    /// @brief Critical threshold
    double criticalThreshold = ThreatDetectorConstants::CRITICAL_THRESHOLD;
    
    /// @brief High threshold
    double highThreshold = ThreatDetectorConstants::HIGH_THRESHOLD;
    
    /// @brief Medium threshold
    double mediumThreshold = ThreatDetectorConstants::MEDIUM_THRESHOLD;
    
    // -------------------------------------------------------------------------
    // Engine Weights
    // -------------------------------------------------------------------------
    
    /// @brief Signature weight
    double signatureWeight = ThreatDetectorConstants::SIGNATURE_WEIGHT;
    
    /// @brief Behavior weight
    double behaviorWeight = ThreatDetectorConstants::BEHAVIOR_WEIGHT;
    
    /// @brief Heuristic weight
    double heuristicWeight = ThreatDetectorConstants::HEURISTIC_WEIGHT;
    
    /// @brief Emulation weight
    double emulationWeight = ThreatDetectorConstants::EMULATION_WEIGHT;
    
    /// @brief ThreatIntel weight
    double threatIntelWeight = ThreatDetectorConstants::THREATINTEL_WEIGHT;
    
    // -------------------------------------------------------------------------
    // Correlation Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable attack chain correlation
    bool enableAttackChainCorrelation = true;
    
    /// @brief Correlation window
    std::chrono::seconds correlationWindow = ThreatDetectorConstants::CORRELATION_WINDOW;
    
    /// @brief Attack chain timeout
    std::chrono::minutes attackChainTimeout = ThreatDetectorConstants::ATTACK_CHAIN_TIMEOUT;
    
    // -------------------------------------------------------------------------
    // Response Settings
    // -------------------------------------------------------------------------
    
    /// @brief Auto-block on critical
    bool autoBlockOnCritical = true;
    
    /// @brief Auto-quarantine on high
    bool autoQuarantineOnHigh = false;
    
    /// @brief Auto-terminate on ransomware
    bool autoTerminateRansomware = true;
    
    /// @brief Response delay (grace period)
    std::chrono::milliseconds responseDelay{ 0 };
    
    // -------------------------------------------------------------------------
    // Trust Settings
    // -------------------------------------------------------------------------
    
    /// @brief Trust Microsoft signed
    bool trustMicrosoftSigned = true;
    
    /// @brief Trust vendor signed
    bool trustVendorSigned = true;
    
    /// @brief Apply whitelist
    bool applyWhitelist = true;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static ThreatDetectorConfig CreateDefault() noexcept {
        return ThreatDetectorConfig{};
    }
    
    /**
     * @brief Create aggressive configuration.
     */
    [[nodiscard]] static ThreatDetectorConfig CreateAggressive() noexcept {
        ThreatDetectorConfig config;
        config.detectionThreshold = 30.0;
        config.autoBlockOnCritical = true;
        config.autoQuarantineOnHigh = true;
        config.autoTerminateRansomware = true;
        return config;
    }
    
    /**
     * @brief Create monitor-only configuration.
     */
    [[nodiscard]] static ThreatDetectorConfig CreateMonitorOnly() noexcept {
        ThreatDetectorConfig config;
        config.autoBlockOnCritical = false;
        config.autoQuarantineOnHigh = false;
        config.autoTerminateRansomware = false;
        return config;
    }
};

/**
 * @brief Statistics for threat detector.
 */
struct ThreatDetectorStats {
    /// @brief Total events processed
    std::atomic<uint64_t> totalEventsProcessed{ 0 };
    
    /// @brief Events by category
    std::array<std::atomic<uint64_t>, 16> eventsByCategory{};
    
    /// @brief Total threats detected
    std::atomic<uint64_t> totalThreatsDetected{ 0 };
    
    /// @brief Threats by severity
    std::array<std::atomic<uint64_t>, 8> threatsBySeverity{};
    
    /// @brief Threats by category
    std::array<std::atomic<uint64_t>, 32> threatsByCategory{};
    
    /// @brief Detections by source
    std::array<std::atomic<uint64_t>, 16> detectionsBySource{};
    
    /// @brief Actions taken
    std::array<std::atomic<uint64_t>, 16> actionsTaken{};
    
    /// @brief Active attack chains
    std::atomic<size_t> activeAttackChains{ 0 };
    
    /// @brief Events per second (current)
    std::atomic<uint64_t> eventsPerSecond{ 0 };
    
    /// @brief Peak events per second
    std::atomic<uint64_t> peakEventsPerSecond{ 0 };
    
    /// @brief Events dropped
    std::atomic<uint64_t> eventsDropped{ 0 };
    
    /// @brief False positives (user reported)
    std::atomic<uint64_t> falsePositives{ 0 };
    
    /// @brief Average processing time (microseconds)
    std::atomic<uint64_t> avgProcessingTimeUs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalEventsProcessed.store(0, std::memory_order_relaxed);
        for (auto& c : eventsByCategory) c.store(0, std::memory_order_relaxed);
        totalThreatsDetected.store(0, std::memory_order_relaxed);
        for (auto& s : threatsBySeverity) s.store(0, std::memory_order_relaxed);
        for (auto& c : threatsByCategory) c.store(0, std::memory_order_relaxed);
        for (auto& d : detectionsBySource) d.store(0, std::memory_order_relaxed);
        for (auto& a : actionsTaken) a.store(0, std::memory_order_relaxed);
        activeAttackChains.store(0, std::memory_order_relaxed);
        eventsPerSecond.store(0, std::memory_order_relaxed);
        peakEventsPerSecond.store(0, std::memory_order_relaxed);
        eventsDropped.store(0, std::memory_order_relaxed);
        falsePositives.store(0, std::memory_order_relaxed);
        avgProcessingTimeUs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using ThreatVerdictCallback = std::function<void(const ThreatVerdict&)>;
using AttackChainCallback = std::function<void(const AttackChain&)>;
using EventCallback = std::function<void(const SystemEvent&)>;
using ResponseCallback = std::function<bool(const ThreatVerdict&, ResponseAction)>;

// ============================================================================
// MAIN THREAT DETECTOR CLASS
// ============================================================================

/**
 * @brief Central threat detection and correlation engine.
 *
 * Orchestrates all detection engines, correlates events, and produces
 * unified threat verdicts. This is the primary interface for real-time
 * threat detection.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& detector = ThreatDetector::Instance();
 * 
 * // Initialize
 * ThreatDetectorConfig config = ThreatDetectorConfig::CreateDefault();
 * detector.Initialize(threadPool, config);
 * 
 * // Connect detection engines
 * detector.SetBehaviorAnalyzer(&BehaviorAnalyzer::Instance());
 * detector.SetHeuristicAnalyzer(&HeuristicAnalyzer::Instance());
 * detector.SetSignatureStore(&SignatureStore::SignatureStore::Instance());
 * detector.SetThreatIntelIndex(&ThreatIntel::ThreatIntelIndex::Instance());
 * 
 * // Register verdict callback
 * detector.RegisterVerdictCallback([](const ThreatVerdict& verdict) {
 *     if (verdict.isThreat) {
 *         LOG_THREAT(L"{} detected in process {} (Score: {})",
 *                    verdict.threatName, verdict.processId, verdict.threatScore);
 *     }
 * });
 * 
 * // Start processing
 * detector.Start();
 * 
 * // Submit events (typically from sensors)
 * SystemEvent event;
 * event.processId = 1234;
 * event.eventType = EventType::FileWrite;
 * event.targetPath = L"C:\\Users\\...";
 * detector.SubmitEvent(event);
 * 
 * // Query active threats
 * auto threats = detector.GetActiveThreats();
 * 
 * detector.Stop();
 * detector.Shutdown();
 * @endcode
 */
class ThreatDetector {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global ThreatDetector instance.
     */
    [[nodiscard]] static ThreatDetector& Instance();

    // Non-copyable, non-movable
    ThreatDetector(const ThreatDetector&) = delete;
    ThreatDetector& operator=(const ThreatDetector&) = delete;
    ThreatDetector(ThreatDetector&&) = delete;
    ThreatDetector& operator=(ThreatDetector&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the detector.
     * @return true on success.
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
        const ThreatDetectorConfig& config
    );

    /**
     * @brief Shutdown the detector.
     */
    void Shutdown();

    /**
     * @brief Start event processing.
     */
    bool Start();

    /**
     * @brief Stop event processing.
     */
    void Stop();

    /**
     * @brief Check if detector is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Check if detector is initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const ThreatDetectorConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] ThreatDetectorConfig GetConfig() const;

    // =========================================================================
    // Event Submission
    // =========================================================================

    /**
     * @brief Submit event for analysis.
     * @param event System event.
     * @return true if event was queued.
     */
    bool SubmitEvent(SystemEvent event);

    /**
     * @brief Submit batch of events.
     * @param events Vector of events.
     * @return Number of events queued.
     */
    size_t SubmitEventBatch(std::vector<SystemEvent> events);

    /**
     * @brief Analyze event synchronously.
     * @param event System event.
     * @return Optional verdict if threat detected.
     */
    [[nodiscard]] std::optional<ThreatVerdict> AnalyzeEvent(const SystemEvent& event);

    // =========================================================================
    // Threat Query
    // =========================================================================

    /**
     * @brief Get all active threats.
     * @return Vector of active threat verdicts.
     */
    [[nodiscard]] std::vector<ThreatVerdict> GetActiveThreats() const;

    /**
     * @brief Get threats for a process.
     * @param processId Process ID.
     * @return Vector of verdicts.
     */
    [[nodiscard]] std::vector<ThreatVerdict> GetThreatsByProcess(uint32_t processId) const;

    /**
     * @brief Get threats by severity.
     * @param minSeverity Minimum severity.
     * @return Vector of verdicts.
     */
    [[nodiscard]] std::vector<ThreatVerdict> GetThreatsBySeverity(
        ThreatSeverity minSeverity
    ) const;

    /**
     * @brief Get threats by category.
     * @param category Threat category.
     * @return Vector of verdicts.
     */
    [[nodiscard]] std::vector<ThreatVerdict> GetThreatsByCategory(
        ThreatCategory category
    ) const;

    /**
     * @brief Get verdict by ID.
     * @param verdictId Verdict ID.
     * @return Verdict or nullopt if not found.
     */
    [[nodiscard]] std::optional<ThreatVerdict> GetVerdict(uint64_t verdictId) const;

    /**
     * @brief Check if process has active threat.
     */
    [[nodiscard]] bool HasActiveThreat(uint32_t processId) const;

    /**
     * @brief Get threat score for process.
     */
    [[nodiscard]] double GetProcessThreatScore(uint32_t processId) const;

    // =========================================================================
    // Attack Chain Management
    // =========================================================================

    /**
     * @brief Get active attack chains.
     */
    [[nodiscard]] std::vector<AttackChain> GetActiveAttackChains() const;

    /**
     * @brief Get attack chain by ID.
     */
    [[nodiscard]] std::optional<AttackChain> GetAttackChain(uint64_t chainId) const;

    /**
     * @brief Get attack chains for process.
     */
    [[nodiscard]] std::vector<AttackChain> GetAttackChainsForProcess(
        uint32_t processId
    ) const;

    // =========================================================================
    // Rule Management
    // =========================================================================

    /**
     * @brief Add detection rule.
     * @param rule Detection rule.
     * @return true if added successfully.
     */
    bool AddRule(const DetectionRule& rule);

    /**
     * @brief Remove detection rule.
     * @param ruleId Rule ID.
     * @return true if removed.
     */
    bool RemoveRule(const std::string& ruleId);

    /**
     * @brief Enable/disable rule.
     * @param ruleId Rule ID.
     * @param enabled Enable state.
     */
    void SetRuleEnabled(const std::string& ruleId, bool enabled);

    /**
     * @brief Get all rules.
     */
    [[nodiscard]] std::vector<DetectionRule> GetRules() const;

    /**
     * @brief Load rules from file.
     */
    bool LoadRulesFromFile(const std::wstring& filePath);

    /**
     * @brief Save rules to file.
     */
    bool SaveRulesToFile(const std::wstring& filePath) const;

    // =========================================================================
    // Response Actions
    // =========================================================================

    /**
     * @brief Execute response action.
     * @param verdictId Verdict ID.
     * @param action Action to take.
     * @return true if action succeeded.
     */
    bool ExecuteAction(uint64_t verdictId, ResponseAction action);

    /**
     * @brief Report false positive.
     * @param verdictId Verdict ID.
     * @param reason Reason for false positive.
     */
    void ReportFalsePositive(uint64_t verdictId, const std::wstring& reason);

    /**
     * @brief Whitelist process.
     */
    void WhitelistProcess(uint32_t processId);

    /**
     * @brief Whitelist file hash.
     */
    void WhitelistHash(const std::string& hash);

    // =========================================================================
    // Process Management
    // =========================================================================

    /**
     * @brief Notify process creation.
     */
    void OnProcessCreate(uint32_t processId, uint32_t parentProcessId,
                         const std::wstring& imagePath);

    /**
     * @brief Notify process termination.
     */
    void OnProcessTerminate(uint32_t processId);

    /**
     * @brief Reset state for process.
     */
    void ResetProcessState(uint32_t processId);

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register verdict callback.
     */
    [[nodiscard]] uint64_t RegisterVerdictCallback(ThreatVerdictCallback callback);

    /**
     * @brief Unregister verdict callback.
     */
    bool UnregisterVerdictCallback(uint64_t callbackId);

    /**
     * @brief Register attack chain callback.
     */
    [[nodiscard]] uint64_t RegisterAttackChainCallback(AttackChainCallback callback);

    /**
     * @brief Unregister attack chain callback.
     */
    bool UnregisterAttackChainCallback(uint64_t callbackId);

    /**
     * @brief Set response callback.
     */
    void SetResponseCallback(ResponseCallback callback);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] ThreatDetectorStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    /**
     * @brief Get queue depth.
     */
    [[nodiscard]] size_t GetQueueDepth() const noexcept;

    // =========================================================================
    // External Engine Integration
    // =========================================================================

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(BehaviorAnalyzer* analyzer);

    /**
     * @brief Set heuristic analyzer.
     */
    void SetHeuristicAnalyzer(HeuristicAnalyzer* analyzer);

    /**
     * @brief Set emulation engine.
     */
    void SetEmulationEngine(EmulationEngine* engine);

    /**
     * @brief Set scan engine.
     */
    void SetScanEngine(ScanEngine* engine);

    /**
     * @brief Set signature store.
     */
    void SetSignatureStore(SignatureStore::SignatureStore* store);

    /**
     * @brief Set threat intel index.
     */
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

    /**
     * @brief Set whitelist store.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set quarantine manager.
     */
    void SetQuarantineManager(QuarantineManager* manager);

    /**
     * @brief Set packer/unpacker engine for packed executable analysis.
     */
    void SetPackerUnpacker(PackerUnpacker* unpacker);

    /**
     * @brief Set polymorphic detector for polymorphic/metamorphic malware detection.
     */
    void SetPolymorphicDetector(PolymorphicDetector* detector);

    /**
     * @brief Set zero-day detector for exploit and shellcode detection.
     */
    void SetZeroDayDetector(ZeroDayDetector* detector);

    /**
     * @brief Set sandbox analyzer for dynamic analysis in isolated VMs.
     */
    void SetSandboxAnalyzer(SandboxAnalyzer* analyzer);

    /**
     * @brief Set machine learning detector for AI-based classification.
     */
    void SetMachineLearningDetector(MachineLearningDetector* detector);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    ThreatDetector();
    ~ThreatDetector();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Event processing loop.
     */
    void ProcessingLoop();

    /**
     * @brief Process single event.
     */
    std::optional<ThreatVerdict> ProcessEventInternal(const SystemEvent& event);

    /**
     * @brief Enrich event with context.
     */
    void EnrichEvent(SystemEvent& event);

    /**
     * @brief Route event to detection engines.
     */
    std::vector<EngineDetection> RouteToEngines(const SystemEvent& event);

    /**
     * @brief Aggregate engine detections.
     */
    ThreatVerdict AggregateDetections(
        const SystemEvent& event,
        const std::vector<EngineDetection>& detections
    );

    /**
     * @brief Correlate with attack chains.
     */
    void CorrelateWithAttackChains(const SystemEvent& event, ThreatVerdict& verdict);

    /**
     * @brief Determine response action.
     */
    ResponseAction DetermineAction(const ThreatVerdict& verdict);

    /**
     * @brief Execute response.
     */
    bool ExecuteResponse(ThreatVerdict& verdict);

    /**
     * @brief Apply custom rules.
     */
    void ApplyRules(const SystemEvent& event, std::vector<EngineDetection>& detections);

    /**
     * @brief Check whitelist.
     */
    bool IsWhitelisted(const SystemEvent& event);

    /**
     * @brief Invoke verdict callbacks.
     */
    void InvokeVerdictCallbacks(const ThreatVerdict& verdict);

    /**
     * @brief Cleanup old data.
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
 * @brief Create system event from file operation.
 */
[[nodiscard]] SystemEvent CreateFileEvent(
    EventType type,
    uint32_t processId,
    const std::wstring& path,
    bool success = true
) noexcept;

/**
 * @brief Create system event from registry operation.
 */
[[nodiscard]] SystemEvent CreateRegistryEvent(
    EventType type,
    uint32_t processId,
    const std::wstring& keyPath,
    const std::wstring& valueName = L"",
    bool success = true
) noexcept;

/**
 * @brief Create system event from network operation.
 */
[[nodiscard]] SystemEvent CreateNetworkEvent(
    EventType type,
    uint32_t processId,
    const std::string& remoteHost,
    uint16_t remotePort,
    const std::string& protocol = "TCP"
) noexcept;

/**
 * @brief Create system event from process operation.
 */
[[nodiscard]] SystemEvent CreateProcessEvent(
    EventType type,
    uint32_t sourceProcessId,
    uint32_t targetProcessId = 0,
    const std::wstring& imagePath = L""
) noexcept;

/**
 * @brief Get MITRE ATT&CK technique for event type.
 */
[[nodiscard]] const char* EventTypeToMitreTechnique(EventType type) noexcept;

/**
 * @brief Check if event type is high-risk.
 */
[[nodiscard]] bool IsHighRiskEventType(EventType type) noexcept;

/**
 * @brief Normalize path for comparison.
 */
[[nodiscard]] std::wstring NormalizePath(const std::wstring& path) noexcept;

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
