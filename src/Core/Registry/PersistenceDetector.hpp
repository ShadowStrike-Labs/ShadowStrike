/**
 * ============================================================================
 * ShadowStrike Core Registry - PERSISTENCE DETECTOR (The Watchman)
 * ============================================================================
 *
 * @file PersistenceDetector.hpp
 * @brief Enterprise-grade Auto-Start Extensibility Point (ASEP) detection engine.
 *
 * Malware uses hundreds of "Auto-Start Extensibility Points" (ASEPs) to survive
 * reboots and maintain persistence. This module provides comprehensive scanning,
 * real-time monitoring, and analysis of all persistence mechanisms in Windows.
 *
 * Key Capabilities:
 * =================
 * 1. ASEP SCANNING
 *    - 100+ persistence locations
 *    - Registry-based persistence
 *    - File system persistence
 *    - Service-based persistence
 *    - Scheduled task persistence
 *    - WMI event subscriptions
 *
 * 2. TARGET RESOLUTION
 *    - Complex command line parsing
 *    - Environment variable expansion
 *    - Indirect execution resolution
 *    - DLL export resolution
 *    - Script host resolution
 *
 * 3. INTEGRITY VERIFICATION
 *    - Digital signature validation
 *    - Hash reputation lookup
 *    - Certificate chain validation
 *    - Publisher verification
 *    - Timestamping validation
 *
 * 4. ANOMALY DETECTION
 *    - Unsigned binary detection
 *    - Suspicious path analysis
 *    - Hidden entry detection
 *    - Timestamp anomalies
 *    - Entropy analysis
 *
 * 5. REAL-TIME ANALYSIS
 *    - Live modification analysis
 *    - Risk scoring
 *    - Immediate threat assessment
 *    - Behavioral correlation
 *
 * Persistence Categories:
 * =======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                      PersistenceDetector                            │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │RegistryASEPs │  │FileSystemASEP│  │    ServiceASEPs          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Run/RunOnce│  │ - Startup    │  │ - Win32 Services         │  │
 *   │  │ - Winlogon   │  │ - Shell Ext  │  │ - Kernel Drivers         │  │
 *   │  │ - IFEO       │  │ - Logon Scrpt│  │ - File System Drivers    │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │TaskScheduler │  │ WMI Subscript│  │    COMHijacking          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Tasks      │  │ - Event Filt │  │ - CLSID Hijack           │  │
 *   │  │ - Triggers   │  │ - Consumers  │  │ - TypeLib Hijack         │  │
 *   │  │ - Actions    │  │ - Bindings   │  │ - Interface Hijack       │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Registry Persistence Locations (50+):
 * =====================================
 * - HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run[Once]
 * - HKLM\SYSTEM\CurrentControlSet\Services
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
 * - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects
 * - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 * - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
 * - HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
 * - HKCU\Software\Classes\CLSID\*\InprocServer32
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1547: Boot or Logon Autostart Execution (all sub-techniques)
 * - T1546: Event Triggered Execution (all sub-techniques)
 * - T1543: Create or Modify System Process
 * - T1053: Scheduled Task/Job
 * - T1574: Hijack Execution Flow
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Scanning is parallelized
 * - Real-time analysis is lock-free
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see RegistryMonitor.hpp for real-time interception
 * @see StartupAnalyzer.hpp for startup management
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/RegistryUtils.hpp"      // Registry enumeration
#include "../../Utils/FileUtils.hpp"          // Startup folder scanning
#include "../../Utils/ProcessUtils.hpp"       // Task scheduler access
#include "../../Utils/CertUtils.hpp"          // Binary verification
#include "../../HashStore/HashStore.hpp"      // Known persistence hashes
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Threat patterns
#include "../../Whitelist/WhiteListStore.hpp" // Trusted persistence

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Registry {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class PersistenceDetectorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace PersistenceDetectorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Scanning
    constexpr size_t TOTAL_ASEP_LOCATIONS = 120;
    constexpr size_t CRITICAL_ASEP_LOCATIONS = 25;
    constexpr uint32_t MAX_SCAN_THREADS = 8;
    constexpr uint32_t SCAN_TIMEOUT_MS = 300000;                  // 5 minutes

    // Analysis
    constexpr size_t MAX_COMMAND_LINE_LENGTH = 32767;
    constexpr size_t MAX_RECURSION_DEPTH = 10;
    constexpr double SUSPICIOUS_ENTROPY_THRESHOLD = 6.5;

    // Cache
    constexpr size_t SIGNATURE_CACHE_SIZE = 10000;
    constexpr size_t HASH_CACHE_SIZE = 50000;
    constexpr uint32_t CACHE_TTL_SECONDS = 3600;

}  // namespace PersistenceDetectorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum PersistenceType
 * @brief Type of persistence mechanism.
 */
enum class PersistenceType : uint16_t {
    Unknown = 0,

    // Registry Run Keys
    RunKey = 100,                  // Run/RunOnce
    RunKeyOnce = 101,
    RunServices = 102,
    RunServicesOnce = 103,
    Policies_Run = 104,            // Group Policy Run
    Explorer_Run = 105,

    // Services
    Service = 200,
    KernelDriver = 201,
    FileSystemDriver = 202,
    ServiceDLL = 203,
    ServiceFailure = 204,

    // Scheduled Tasks
    ScheduledTask = 300,
    ScheduledTaskXML = 301,
    AtJob = 302,

    // Startup Folders
    StartupFolder_User = 400,
    StartupFolder_AllUsers = 401,
    StartupFolder_Common = 402,

    // Winlogon
    Winlogon_Shell = 500,
    Winlogon_Userinit = 501,
    Winlogon_Notify = 502,
    Winlogon_Taskman = 503,
    Winlogon_System = 504,
    Winlogon_VMApplet = 505,

    // Image File Execution Options
    IFEO_Debugger = 600,
    IFEO_GlobalFlag = 601,
    SilentProcessExit = 602,

    // DLL Injection
    AppInit_DLLs = 700,
    AppCertDLLs = 701,
    LoadAppInit = 702,
    Print_Monitors = 703,
    LSA_Authentication = 704,
    LSA_Notification = 705,
    LSA_Security = 706,

    // Boot/Session
    BootExecute = 800,
    SetupExecute = 801,
    KnownDLLs = 802,
    SessionManager = 803,

    // Explorer/Shell
    ShellServiceObjects = 900,
    ShellServiceObjectDelayLoad = 901,
    ShellIconOverlay = 902,
    ShellExtensions = 903,
    ContextMenuHandlers = 904,
    PropertySheetHandlers = 905,
    ColumnHandlers = 906,
    CopyHookHandlers = 907,
    DragDropHandlers = 908,

    // COM Hijacking
    CLSID_InprocServer = 1000,
    CLSID_LocalServer = 1001,
    CLSID_TreatAs = 1002,
    TypeLib_Hijack = 1003,
    ProgID_Hijack = 1004,

    // Browser
    BrowserHelper_Object = 1100,
    Browser_Extensions = 1101,
    URLSearchHook = 1102,

    // Office
    Office_Addins = 1200,
    Office_Startup = 1201,
    Office_VBA = 1202,

    // WMI
    WMI_EventFilter = 1300,
    WMI_EventConsumer = 1301,
    WMI_FilterToConsumer = 1302,

    // Active Setup
    ActiveSetup = 1400,

    // Other
    Logon_Script = 1500,
    Logoff_Script = 1501,
    Startup_Script = 1502,
    Shutdown_Script = 1503,
    Terminal_Services = 1504,
    Netsh_Helper = 1505,
    Protocol_Handler = 1506,
    Font_Driver = 1507,
    Screensaver = 1508,
    Security_Providers = 1509,
    Winsock_Providers = 1510,
    SID_HijacK = 1511,
    PowerShell_Profile = 1512,
    AMSI_Provider = 1513,
    Time_Provider = 1514
};

/**
 * @enum RiskLevel
 * @brief Risk assessment level.
 */
enum class RiskLevel : uint8_t {
    Safe = 0,                      // Signed Microsoft/Known vendor
    Low = 1,                       // Signed third-party
    Unknown = 2,                   // Unsigned but normal location
    Suspicious = 3,                // Unsigned, unusual location/behavior
    Malicious = 4                  // Known bad hash or behavior
};

/**
 * @enum EntryStatus
 * @brief Status of persistence entry.
 */
enum class EntryStatus : uint8_t {
    Active = 0,
    Disabled = 1,
    Orphaned = 2,                  // Target missing
    Corrupted = 3,                 // Invalid data
    Hidden = 4                     // Uses hiding techniques
};

/**
 * @enum SignatureStatus
 * @brief Digital signature status.
 */
enum class SignatureStatus : uint8_t {
    Unknown = 0,
    NotSigned = 1,
    SignedValid = 2,
    SignedExpired = 3,
    SignedRevoked = 4,
    SignedUntrusted = 5,
    SignedInvalid = 6,
    SignedCatalog = 7              // Signed via catalog
};

/**
 * @enum ScanScope
 * @brief Scope of persistence scan.
 */
enum class ScanScope : uint8_t {
    Critical = 0,                  // Critical locations only (~25)
    Standard = 1,                  // Common locations (~50)
    Extended = 2,                  // All known locations (~100)
    Full = 3,                      // Including unusual/rare locations
    Custom = 4                     // User-defined
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct TargetBinary
 * @brief Resolved target binary information.
 */
struct alignas(64) TargetBinary {
    std::wstring path;
    std::wstring originalPath;             // Before resolution
    std::wstring arguments;
    std::wstring workingDirectory;

    // File info
    bool exists{ false };
    uint64_t fileSize{ 0 };
    std::chrono::system_clock::time_point createdTime;
    std::chrono::system_clock::time_point modifiedTime;

    // Hash
    std::array<uint8_t, 32> sha256{ 0 };
    std::string sha256Hex;

    // Signature
    SignatureStatus signatureStatus{ SignatureStatus::Unknown };
    std::wstring signerName;
    std::wstring issuerName;
    std::chrono::system_clock::time_point signatureTime;
    bool isMicrosoftSigned{ false };
    bool isTrusted{ false };

    // Type
    bool isExecutable{ false };
    bool isDLL{ false };
    bool isScript{ false };
    std::string fileType;

    // Analysis
    bool isHidden{ false };
    bool hasADS{ false };                  // Alternate Data Stream
    bool inSystemPath{ false };
    bool inTempPath{ false };
    bool isPacked{ false };
    double entropy{ 0.0 };
};

/**
 * @struct PersistenceEntry
 * @brief Complete persistence entry information.
 */
struct alignas(256) PersistenceEntry {
    // Identity
    uint64_t entryId{ 0 };
    PersistenceType type{ PersistenceType::Unknown };
    EntryStatus status{ EntryStatus::Active };

    // Location
    std::wstring location;                 // Registry key or folder path
    std::wstring entryName;                // Value name or filename
    std::wstring rawCommand;               // Original data

    // Resolved target
    TargetBinary target;
    std::vector<TargetBinary> additionalTargets;  // For multi-part commands

    // Context
    std::wstring description;
    std::wstring publisher;
    bool isUserEntry{ false };             // HKCU vs HKLM
    std::wstring userSid;
    std::wstring userName;

    // Risk assessment
    RiskLevel risk{ RiskLevel::Unknown };
    uint8_t riskScore{ 0 };                // 0-100
    std::vector<std::string> riskFactors;

    // Metadata
    std::chrono::system_clock::time_point createdTime;
    std::chrono::system_clock::time_point modifiedTime;
    std::chrono::system_clock::time_point lastScanned;

    // Reputation
    bool isKnownGood{ false };
    bool isKnownBad{ false };
    std::string malwareFamily;
    std::vector<std::string> detectionNames;

    // MITRE mapping
    std::string mitreTechnique;
    std::string mitreSubTechnique;
};

/**
 * @struct ServiceEntry
 * @brief Windows service persistence entry.
 */
struct alignas(128) ServiceEntry {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring description;
    std::wstring imagePath;
    std::wstring objectName;               // Account running as

    // Service config
    uint32_t startType{ 0 };               // Boot, System, Automatic, Manual, Disabled
    uint32_t serviceType{ 0 };             // Kernel, File System, Win32
    uint32_t errorControl{ 0 };

    // Dependencies
    std::vector<std::wstring> dependencies;
    std::vector<std::wstring> dependents;

    // State
    uint32_t currentState{ 0 };
    uint32_t processId{ 0 };

    // Security
    std::wstring securityDescriptor;

    // Converted to PersistenceEntry
    PersistenceEntry asPersistenceEntry() const;
};

/**
 * @struct ScheduledTaskEntry
 * @brief Scheduled task persistence entry.
 */
struct alignas(128) ScheduledTaskEntry {
    std::wstring taskName;
    std::wstring taskPath;
    std::wstring description;

    // Actions
    struct TaskAction {
        std::wstring type;                 // Exec, ComHandler, SendEmail, ShowMessage
        std::wstring path;
        std::wstring arguments;
        std::wstring workingDirectory;
    };
    std::vector<TaskAction> actions;

    // Triggers
    struct TaskTrigger {
        std::wstring type;                 // Boot, Logon, Time, Event, etc.
        std::wstring details;
        bool enabled{ true };
    };
    std::vector<TaskTrigger> triggers;

    // Security
    std::wstring userId;
    std::wstring securityDescriptor;
    bool runAsHighest{ false };
    bool runOnlyIfLoggedOn{ false };

    // State
    bool enabled{ true };
    std::chrono::system_clock::time_point lastRunTime;
    std::chrono::system_clock::time_point nextRunTime;
    uint32_t lastResult{ 0 };

    // Converted
    PersistenceEntry asPersistenceEntry() const;
};

/**
 * @struct WMISubscription
 * @brief WMI event subscription entry.
 */
struct alignas(64) WMISubscription {
    std::wstring filterName;
    std::wstring filterQuery;
    std::wstring filterLanguage;

    std::wstring consumerName;
    std::wstring consumerType;             // CommandLine, Script, ActiveScript
    std::wstring consumerCommand;

    std::wstring bindingName;

    PersistenceEntry asPersistenceEntry() const;
};

/**
 * @struct ScanResult
 * @brief Result of persistence scan.
 */
struct alignas(128) ScanResult {
    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    std::chrono::milliseconds duration{ 0 };

    // Scope
    ScanScope scope{ ScanScope::Standard };
    uint32_t locationsScanned{ 0 };
    uint32_t errorsEncountered{ 0 };

    // Results
    std::vector<PersistenceEntry> entries;

    // Summary
    uint32_t totalEntries{ 0 };
    uint32_t safeEntries{ 0 };
    uint32_t suspiciousEntries{ 0 };
    uint32_t maliciousEntries{ 0 };
    uint32_t unknownEntries{ 0 };
    uint32_t orphanedEntries{ 0 };

    // By type
    std::unordered_map<PersistenceType, uint32_t> entriesByType;
};

/**
 * @struct RealTimeAnalysis
 * @brief Real-time persistence analysis result.
 */
struct alignas(64) RealTimeAnalysis {
    RiskLevel risk{ RiskLevel::Unknown };
    uint8_t riskScore{ 0 };

    PersistenceType detectedType{ PersistenceType::Unknown };
    std::wstring resolvedTarget;

    // Flags
    bool isPersistenceAttempt{ false };
    bool isKnownBad{ false };
    bool isSuspiciousLocation{ false };
    bool isSuspiciousTarget{ false };
    bool isUnsigned{ false };

    // Evidence
    std::vector<std::string> indicators;
    std::string recommendation;
};

/**
 * @struct PersistenceAlert
 * @brief Alert for persistence detection.
 */
struct alignas(256) PersistenceAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Detection
    PersistenceType type{ PersistenceType::Unknown };
    RiskLevel risk{ RiskLevel::Unknown };
    std::string description;

    // Entry
    std::wstring location;
    std::wstring entryName;
    std::wstring command;
    std::wstring targetPath;

    // Process (if real-time)
    uint32_t processId{ 0 };
    std::wstring processPath;
    std::string userName;

    // Analysis
    PersistenceEntry entry;
    RealTimeAnalysis analysis;

    // MITRE
    std::string mitreTechnique;

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct PersistenceDetectorConfig
 * @brief Configuration for persistence detector.
 */
struct alignas(64) PersistenceDetectorConfig {
    // Scanning
    ScanScope defaultScope{ ScanScope::Standard };
    uint32_t maxScanThreads{ PersistenceDetectorConstants::MAX_SCAN_THREADS };
    uint32_t scanTimeoutMs{ PersistenceDetectorConstants::SCAN_TIMEOUT_MS };

    // Analysis
    bool resolveTargets{ true };
    bool verifySignatures{ true };
    bool checkHashes{ true };
    bool checkReputation{ true };
    bool detectHidden{ true };

    // Real-time
    bool enableRealTimeAnalysis{ true };
    bool alertOnSuspicious{ true };
    bool alertOnUnknown{ false };

    // Whitelist
    std::vector<std::wstring> whitelistedPaths;
    std::vector<std::string> whitelistedHashes;
    std::vector<std::wstring> whitelistedSigners;

    // Performance
    bool useCache{ true };
    uint32_t cacheTTLSeconds{ PersistenceDetectorConstants::CACHE_TTL_SECONDS };

    // Logging
    bool logAllEntries{ false };
    bool logSuspiciousOnly{ true };

    // Factory methods
    static PersistenceDetectorConfig CreateDefault() noexcept;
    static PersistenceDetectorConfig CreateQuick() noexcept;
    static PersistenceDetectorConfig CreateThorough() noexcept;
    static PersistenceDetectorConfig CreateForensic() noexcept;
};

/**
 * @struct PersistenceDetectorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) PersistenceDetectorStatistics {
    // Scan statistics
    std::atomic<uint64_t> totalScans{ 0 };
    std::atomic<uint64_t> entriesScanned{ 0 };
    std::atomic<uint64_t> locationsScanned{ 0 };

    // Detection statistics
    std::atomic<uint64_t> safeEntriesFound{ 0 };
    std::atomic<uint64_t> suspiciousEntriesFound{ 0 };
    std::atomic<uint64_t> maliciousEntriesFound{ 0 };

    // Real-time statistics
    std::atomic<uint64_t> realTimeAnalyses{ 0 };
    std::atomic<uint64_t> persistenceAttempts{ 0 };
    std::atomic<uint64_t> blockedAttempts{ 0 };

    // Verification statistics
    std::atomic<uint64_t> signaturesVerified{ 0 };
    std::atomic<uint64_t> hashesChecked{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };

    // Alert statistics
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Performance
    std::atomic<uint64_t> avgScanTimeMs{ 0 };
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for scan progress.
 */
using ScanProgressCallback = std::function<void(
    uint32_t currentLocation,
    uint32_t totalLocations,
    const std::wstring& currentPath
)>;

/**
 * @brief Callback for entry found.
 */
using EntryFoundCallback = std::function<void(const PersistenceEntry& entry)>;

/**
 * @brief Callback for persistence alerts.
 */
using PersistenceAlertCallback = std::function<void(const PersistenceAlert& alert)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class PersistenceDetector
 * @brief Enterprise-grade ASEP detection and analysis.
 *
 * Thread Safety:
 * All public methods are thread-safe. Scanning is parallelized.
 *
 * Usage Example:
 * @code
 * auto& detector = PersistenceDetector::Instance();
 * 
 * // Full scan
 * auto results = detector.ScanAll();
 * for (const auto& entry : results.entries) {
 *     if (entry.risk >= RiskLevel::Suspicious) {
 *         InvestigateEntry(entry);
 *     }
 * }
 * 
 * // Real-time analysis
 * auto risk = detector.AnalyzeRealTime(keyPath, valueName, data);
 * if (risk.risk >= RiskLevel::Suspicious) {
 *     BlockOperation();
 * }
 * @endcode
 */
class PersistenceDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static PersistenceDetector& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the persistence detector.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const PersistenceDetectorConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // SCANNING
    // ========================================================================

    /**
     * @brief Performs full scan of all persistence locations.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanAll();

    /**
     * @brief Scans critical locations only (fast).
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanCritical();

    /**
     * @brief Scans with specified scope.
     * @param scope Scan scope.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult Scan(ScanScope scope);

    /**
     * @brief Scans specific persistence type.
     * @param type Persistence type.
     * @return Vector of entries.
     */
    [[nodiscard]] std::vector<PersistenceEntry> ScanType(PersistenceType type);

    /**
     * @brief Scans specific key/path.
     * @param path Registry key or folder path.
     * @return Vector of entries.
     */
    [[nodiscard]] std::vector<PersistenceEntry> ScanPath(const std::wstring& path);

    /**
     * @brief Cancels ongoing scan.
     */
    void CancelScan();

    // ========================================================================
    // REAL-TIME ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes registry modification for persistence risk.
     * @param keyPath Registry key path.
     * @param valueName Value name.
     * @param data Value data.
     * @return Risk level.
     */
    [[nodiscard]] RiskLevel AnalyzeRealTime(
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::wstring& data
    );

    /**
     * @brief Full real-time analysis.
     * @param keyPath Registry key path.
     * @param valueName Value name.
     * @param data Value data.
     * @return Complete analysis.
     */
    [[nodiscard]] RealTimeAnalysis AnalyzeRealTimeFull(
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::wstring& data
    );

    /**
     * @brief Checks if path is a persistence location.
     * @param keyPath Registry key path.
     * @return Persistence type, or Unknown.
     */
    [[nodiscard]] PersistenceType IsPersistenceLocation(const std::wstring& keyPath) const;

    // ========================================================================
    // TARGET RESOLUTION
    // ========================================================================

    /**
     * @brief Resolves command to target binary.
     * @param command Command line.
     * @return Resolved target.
     */
    [[nodiscard]] TargetBinary ResolveTarget(const std::wstring& command);

    /**
     * @brief Resolves complex command (rundll32, cmd, etc.).
     * @param command Command line.
     * @return Vector of resolved targets.
     */
    [[nodiscard]] std::vector<TargetBinary> ResolveComplexCommand(const std::wstring& command);

    // ========================================================================
    // SERVICE SCANNING
    // ========================================================================

    /**
     * @brief Scans all Windows services.
     * @return Vector of service entries.
     */
    [[nodiscard]] std::vector<ServiceEntry> ScanServices();

    /**
     * @brief Gets service entry.
     * @param serviceName Service name.
     * @return Service entry, or nullopt.
     */
    [[nodiscard]] std::optional<ServiceEntry> GetService(const std::wstring& serviceName);

    // ========================================================================
    // SCHEDULED TASK SCANNING
    // ========================================================================

    /**
     * @brief Scans all scheduled tasks.
     * @return Vector of task entries.
     */
    [[nodiscard]] std::vector<ScheduledTaskEntry> ScanScheduledTasks();

    // ========================================================================
    // WMI SCANNING
    // ========================================================================

    /**
     * @brief Scans WMI event subscriptions.
     * @return Vector of subscriptions.
     */
    [[nodiscard]] std::vector<WMISubscription> ScanWMISubscriptions();

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterProgressCallback(ScanProgressCallback callback);
    [[nodiscard]] uint64_t RegisterEntryCallback(EntryFoundCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(PersistenceAlertCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const PersistenceDetectorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;
    bool ExportScanReport(const ScanResult& result, const std::wstring& outputPath) const;

private:
    PersistenceDetector();
    ~PersistenceDetector();

    PersistenceDetector(const PersistenceDetector&) = delete;
    PersistenceDetector& operator=(const PersistenceDetector&) = delete;

    std::unique_ptr<PersistenceDetectorImpl> m_impl;
};

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike