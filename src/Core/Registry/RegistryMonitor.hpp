/**
 * ============================================================================
 * ShadowStrike Core Registry - REGISTRY MONITOR (The Gatekeeper)
 * ============================================================================
 *
 * @file RegistryMonitor.hpp
 * @brief Enterprise-grade real-time Windows Registry monitoring and protection.
 *
 * The Windows Registry is the most common persistence mechanism for malware.
 * This module provides comprehensive real-time interception, analysis, and
 * policy enforcement for all registry operations through kernel-level
 * callbacks and user-mode policy engines.
 *
 * Key Capabilities:
 * =================
 * 1. REAL-TIME INTERCEPTION
 *    - Kernel callback integration (CmRegisterCallback)
 *    - Pre-operation interception
 *    - Post-operation notification
 *    - Transactional registry support
 *    - Virtualized registry detection
 *
 * 2. SELF-DEFENSE
 *    - Protected key enforcement
 *    - Anti-tampering mechanisms
 *    - Configuration protection
 *    - Driver parameter protection
 *    - Service key protection
 *
 * 3. PERSISTENCE PREVENTION
 *    - Run/RunOnce key monitoring
 *    - Service registration blocking
 *    - Winlogon modification prevention
 *    - Shell extension blocking
 *    - COM hijack prevention
 *
 * 4. FILELESS MALWARE DETECTION
 *    - Large binary blob detection
 *    - Encoded payload identification
 *    - Script storage detection
 *    - PowerShell command storage
 *
 * 5. POLICY ENFORCEMENT
 *    - Configurable allow/block rules
 *    - Process-based policies
 *    - User-based policies
 *    - Key path-based policies
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        RegistryMonitor                              │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │KernelCallback│  │EventDispatch │  │    PolicyEngine          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - PreCreate  │  │ - Filter     │  │ - Allow/Block Rules      │  │
 *   │  │ - PreSetValue│  │ - Queue      │  │ - Process Context        │  │
 *   │  │ - PreDelete  │  │ - Dispatch   │  │ - Self-Defense           │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ValueAnalyzer │  │DeceptionMode │  │    StatisticsCollector   │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Blob Detect│  │ - Honeypot   │  │ - Operation Counts       │  │
 *   │  │ - Encoded    │  │ - Silent Drop│  │ - Block Counts           │  │
 *   │  │ - Suspicious │  │ - Fake Write │  │ - Performance            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Kernel Communication:
 * =====================
 *   Kernel Driver (CmRegisterCallback)
 *          │
 *          ▼ IPC (FilterConnectCommunicationPort)
 *   User-Mode RegistryMonitor
 *          │
 *          ▼ Policy Decision
 *   Verdict returned to Kernel
 *
 * Critical Registry Paths Monitored:
 * ==================================
 * - HKLM\Software\Microsoft\Windows\CurrentVersion\Run[Once]
 * - HKLM\SYSTEM\CurrentControlSet\Services
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
 * - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell[...]
 * - HKCU\Software\Classes\CLSID (COM Hijacking)
 * - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
 * - T1547.004: Winlogon Helper DLL
 * - T1546.015: Component Object Model Hijacking
 * - T1546.012: Image File Execution Options Injection
 * - T1112: Modify Registry
 * - T1562.001: Disable or Modify Tools
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Kernel communication is serialized
 * - Callback invocation is protected
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see PersistenceDetector.hpp for ASEP analysis
 * @see RegistryUtils.hpp for registry utilities
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/RegistryUtils.hpp"      // Registry operations
#include "../../Utils/ProcessUtils.hpp"       // Process context
#include "../../Utils/StringUtils.hpp"        // Path handling
#include "../../Whitelist/WhiteListStore.hpp" // Trusted processes/keys
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Known malware patterns

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
#include <variant>
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
class RegistryMonitorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace RegistryMonitorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Registry limits
    constexpr size_t MAX_KEY_PATH_LENGTH = 16384;
    constexpr size_t MAX_VALUE_NAME_LENGTH = 16383;
    constexpr size_t MAX_VALUE_DATA_SIZE = 1024 * 1024;           // 1 MB
    constexpr size_t LARGE_VALUE_THRESHOLD = 64 * 1024;           // 64 KB

    // Detection thresholds
    constexpr double ENTROPY_THRESHOLD = 7.0;                     // High entropy
    constexpr size_t MIN_BLOB_SIZE_FOR_ANALYSIS = 256;
    constexpr size_t MAX_SCRIPT_LENGTH = 32768;

    // Performance
    constexpr uint32_t EVENT_QUEUE_SIZE = 10000;
    constexpr uint32_t CALLBACK_TIMEOUT_MS = 5000;
    constexpr size_t MAX_PROTECTED_KEYS = 1000;
    constexpr size_t MAX_RULES = 10000;

    // Kernel communication
    constexpr wchar_t COMMUNICATION_PORT[] = L"\\ShadowStrikeRegPort";

}  // namespace RegistryMonitorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum RegistryOp
 * @brief Registry operation types.
 */
enum class RegistryOp : uint8_t {
    Unknown = 0,

    // Key operations
    CreateKey = 1,
    OpenKey = 2,
    DeleteKey = 3,
    RenameKey = 4,
    CloseKey = 5,

    // Value operations
    SetValue = 10,
    DeleteValue = 11,
    QueryValue = 12,
    EnumerateValue = 13,

    // Hive operations
    LoadKey = 20,
    UnloadKey = 21,
    SaveKey = 22,
    RestoreKey = 23,
    ReplaceKey = 24,

    // Security operations
    SetKeySecurity = 30,
    QueryKeySecurity = 31,

    // Transaction operations
    CreateTransaction = 40,
    CommitTransaction = 41,
    RollbackTransaction = 42
};

/**
 * @enum RegistryValueType
 * @brief Registry value types.
 */
enum class RegistryValueType : uint32_t {
    NONE = 0,
    SZ = 1,                        // REG_SZ
    EXPAND_SZ = 2,                 // REG_EXPAND_SZ
    BINARY = 3,                    // REG_BINARY
    DWORD = 4,                     // REG_DWORD
    DWORD_BIG_ENDIAN = 5,
    LINK = 6,                      // REG_LINK
    MULTI_SZ = 7,                  // REG_MULTI_SZ
    RESOURCE_LIST = 8,
    FULL_RESOURCE_DESCRIPTOR = 9,
    RESOURCE_REQUIREMENTS_LIST = 10,
    QWORD = 11                     // REG_QWORD
};

/**
 * @enum RegistryVerdict
 * @brief Verdict for registry operation.
 */
enum class RegistryVerdict : uint8_t {
    Allow = 0,
    Block = 1,
    SilentDrop = 2,                // Fake success, no write
    Redirect = 3,                  // Redirect to different location
    Delay = 4,                     // Delay operation
    Alert = 5                      // Allow but generate alert
};

/**
 * @enum KeyCategory
 * @brief Category of registry key.
 */
enum class KeyCategory : uint8_t {
    Unknown = 0,
    Persistence = 1,               // Run keys, services, etc.
    Security = 2,                  // UAC, firewall, etc.
    Network = 3,                   // Proxy, DNS, etc.
    Shell = 4,                     // Shell extensions, associations
    COM = 5,                       // COM objects, CLSID
    System = 6,                    // System configuration
    Driver = 7,                    // Driver parameters
    Application = 8,               // Application settings
    UserPreference = 9             // User preferences
};

/**
 * @enum ThreatType
 * @brief Type of registry threat.
 */
enum class RegistryThreatType : uint16_t {
    NONE = 0,

    // Persistence
    PERSISTENCE_RUN_KEY = 100,
    PERSISTENCE_SERVICE = 101,
    PERSISTENCE_WINLOGON = 102,
    PERSISTENCE_SCHEDULED_TASK = 103,
    PERSISTENCE_IFEO = 104,
    PERSISTENCE_APPINIT = 105,
    PERSISTENCE_BOOT_EXECUTE = 106,

    // Hijacking
    COM_HIJACK = 200,
    DLL_SEARCH_ORDER = 201,
    SHELL_EXTENSION = 202,
    FILE_ASSOCIATION = 203,
    CONTEXT_MENU = 204,

    // Security bypass
    UAC_BYPASS = 300,
    FIREWALL_DISABLE = 301,
    DEFENDER_DISABLE = 302,
    AMSI_BYPASS = 303,
    ETW_BYPASS = 304,

    // Fileless
    FILELESS_PAYLOAD = 400,
    ENCODED_SCRIPT = 401,
    POWERSHELL_COMMAND = 402,

    // Tampering
    SELF_DEFENSE_TAMPER = 500,
    LOG_TAMPERING = 501,
    AUDIT_DISABLE = 502,

    // Network
    PROXY_MODIFICATION = 600,
    DNS_MODIFICATION = 601,
    HOSTS_REDIRECT = 602
};

/**
 * @enum RiskLevel
 * @brief Risk level of operation.
 */
enum class RiskLevel : uint8_t {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @enum RuleAction
 * @brief Action for registry rule.
 */
enum class RuleAction : uint8_t {
    Allow = 0,
    Block = 1,
    Alert = 2,
    Log = 3,
    Redirect = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct RegistryEvent
 * @brief Detailed registry operation event.
 */
struct alignas(256) RegistryEvent {
    // Event identity
    uint64_t eventId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Operation
    RegistryOp operation{ RegistryOp::Unknown };
    bool isPreOperation{ true };

    // Process context
    uint32_t processId{ 0 };
    uint32_t threadId{ 0 };
    std::wstring processPath;
    std::string processName;
    std::wstring userSid;
    std::string userName;
    uint32_t sessionId{ 0 };
    bool isElevated{ false };

    // Registry details
    std::wstring keyPath;
    std::wstring valueName;
    RegistryValueType valueType{ RegistryValueType::NONE };
    std::vector<uint8_t> data;
    std::vector<uint8_t> previousData;

    // Expanded paths (for REG_EXPAND_SZ)
    std::wstring expandedValue;

    // Handle info
    uint64_t keyHandle{ 0 };
    uint32_t desiredAccess{ 0 };
    uint32_t createOptions{ 0 };

    // Transaction context
    bool isTransacted{ false };
    uint64_t transactionId{ 0 };

    // Analysis helpers
    [[nodiscard]] bool IsPersistenceKey() const;
    [[nodiscard]] bool IsServiceKey() const;
    [[nodiscard]] bool IsSecurityKey() const;
    [[nodiscard]] bool IsCOMKey() const;
    [[nodiscard]] bool IsNetworkKey() const;
    [[nodiscard]] KeyCategory GetCategory() const;
    [[nodiscard]] std::wstring GetHive() const;
};

/**
 * @struct ValueAnalysis
 * @brief Analysis of registry value.
 */
struct alignas(64) ValueAnalysis {
    // Basic info
    size_t dataSize{ 0 };
    RegistryValueType type{ RegistryValueType::NONE };

    // Content analysis
    double entropy{ 0.0 };
    bool isHighEntropy{ false };
    bool isBinaryBlob{ false };
    bool isLargeValue{ false };

    // Detection
    bool containsExecutable{ false };
    bool containsScript{ false };
    bool containsEncodedData{ false };
    bool containsPath{ false };
    bool containsUrl{ false };

    // Extracted data
    std::vector<std::wstring> extractedPaths;
    std::vector<std::string> extractedUrls;
    std::string detectedEncoding;

    // Risk assessment
    RiskLevel risk{ RiskLevel::Safe };
    std::vector<std::string> riskFactors;
};

/**
 * @struct RegistryRule
 * @brief Registry policy rule.
 */
struct alignas(128) RegistryRule {
    uint64_t ruleId{ 0 };
    std::string name;
    std::string description;

    // Matching criteria
    std::wstring keyPathPattern;           // Regex or wildcard
    std::wstring valueNamePattern;
    std::optional<RegistryOp> operation;
    std::optional<RegistryValueType> valueType;

    // Process criteria
    std::wstring processPathPattern;
    std::vector<uint32_t> processIds;
    std::wstring userSidPattern;

    // Action
    RuleAction action{ RuleAction::Alert };
    RegistryVerdict verdict{ RegistryVerdict::Allow };

    // Priority (higher = evaluated first)
    uint32_t priority{ 100 };

    // Status
    bool enabled{ true };
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
    bool isPermanent{ true };

    // Statistics
    std::atomic<uint64_t> matchCount{ 0 };
};

/**
 * @struct ProtectedKey
 * @brief Protected registry key configuration.
 */
struct alignas(64) ProtectedKey {
    std::wstring keyPath;
    bool includeSubkeys{ true };
    bool protectValues{ true };
    bool protectDelete{ true };
    bool protectRename{ true };
    bool protectSecurity{ true };

    // Exceptions
    std::vector<std::wstring> allowedProcesses;
    std::vector<std::wstring> allowedUsers;

    // Self-defense
    bool isSelfDefense{ false };
};

/**
 * @struct RegistryAlert
 * @brief Alert for registry threat.
 */
struct alignas(256) RegistryAlert {
    // Identity
    uint64_t alertId{ 0 };
    uint64_t eventId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Threat
    RegistryThreatType threatType{ RegistryThreatType::NONE };
    RiskLevel risk{ RiskLevel::Medium };
    std::string description;

    // Context
    RegistryOp operation{ RegistryOp::Unknown };
    std::wstring keyPath;
    std::wstring valueName;

    // Process
    uint32_t processId{ 0 };
    std::wstring processPath;
    std::string userName;

    // Action taken
    RegistryVerdict verdict{ RegistryVerdict::Allow };
    bool wasBlocked{ false };

    // Evidence
    std::vector<uint8_t> dataSnapshot;
    ValueAnalysis analysis;
    std::vector<std::string> indicators;

    // MITRE mapping
    std::string mitreTechnique;
    std::string mitreSubTechnique;

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct DeceptionConfig
 * @brief Deception mode configuration.
 */
struct alignas(32) DeceptionConfig {
    bool enabled{ false };
    bool silentDropEnabled{ true };
    bool honeypotEnabled{ false };
    std::vector<std::wstring> honeypotKeys;
    bool fakeSuccessEnabled{ false };
};

/**
 * @struct RegistryMonitorConfig
 * @brief Configuration for registry monitor.
 */
struct alignas(64) RegistryMonitorConfig {
    // Main settings
    bool enabled{ true };
    bool useKernelCallback{ true };
    bool useUserModeHooks{ false };

    // Monitoring scope
    bool monitorCreateKey{ true };
    bool monitorSetValue{ true };
    bool monitorDeleteKey{ true };
    bool monitorDeleteValue{ true };
    bool monitorRename{ true };
    bool monitorLoadHive{ true };
    bool monitorSecurity{ true };
    bool monitorTransactions{ true };

    // Analysis
    bool analyzeValues{ true };
    bool detectFileless{ true };
    bool detectPersistence{ true };
    bool detectSecurityChanges{ true };
    size_t largeValueThreshold{ RegistryMonitorConstants::LARGE_VALUE_THRESHOLD };

    // Self-defense
    bool selfDefenseEnabled{ true };
    bool protectShadowStrikeKeys{ true };

    // Deception
    DeceptionConfig deception;

    // Performance
    uint32_t eventQueueSize{ RegistryMonitorConstants::EVENT_QUEUE_SIZE };
    uint32_t workerThreads{ 2 };
    uint32_t callbackTimeoutMs{ RegistryMonitorConstants::CALLBACK_TIMEOUT_MS };

    // Logging
    bool logAllOperations{ false };
    bool logBlockedOnly{ false };
    bool logPersistenceKeys{ true };

    // Factory methods
    static RegistryMonitorConfig CreateDefault() noexcept;
    static RegistryMonitorConfig CreateHighSecurity() noexcept;
    static RegistryMonitorConfig CreatePerformance() noexcept;
    static RegistryMonitorConfig CreateForensic() noexcept;
};

/**
 * @struct RegistryMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) RegistryMonitorStatistics {
    // Operation statistics
    std::atomic<uint64_t> totalEvents{ 0 };
    std::atomic<uint64_t> createKeyEvents{ 0 };
    std::atomic<uint64_t> setValueEvents{ 0 };
    std::atomic<uint64_t> deleteKeyEvents{ 0 };
    std::atomic<uint64_t> deleteValueEvents{ 0 };
    std::atomic<uint64_t> renameEvents{ 0 };

    // Verdict statistics
    std::atomic<uint64_t> allowedOperations{ 0 };
    std::atomic<uint64_t> blockedOperations{ 0 };
    std::atomic<uint64_t> silentDropped{ 0 };

    // Detection statistics
    std::atomic<uint64_t> persistenceAttempts{ 0 };
    std::atomic<uint64_t> filelessPayloads{ 0 };
    std::atomic<uint64_t> securityChanges{ 0 };
    std::atomic<uint64_t> selfDefenseBlocks{ 0 };

    // Alert statistics
    std::atomic<uint64_t> alertsGenerated{ 0 };
    std::atomic<uint64_t> criticalAlerts{ 0 };

    // Performance
    std::atomic<uint64_t> avgCallbackTimeUs{ 0 };
    std::atomic<uint64_t> maxCallbackTimeUs{ 0 };
    std::atomic<uint64_t> droppedEvents{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Policy callback for registry operations.
 */
using RegistryPolicyCallback = std::function<RegistryVerdict(const RegistryEvent&)>;

/**
 * @brief Alert callback for registry threats.
 */
using RegistryAlertCallback = std::function<void(const RegistryAlert&)>;

/**
 * @brief Event notification callback.
 */
using RegistryEventCallback = std::function<void(const RegistryEvent&, RegistryVerdict)>;

/**
 * @brief Value analysis callback.
 */
using ValueAnalysisCallback = std::function<void(
    const RegistryEvent&,
    const ValueAnalysis&
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class RegistryMonitor
 * @brief Enterprise-grade real-time registry monitoring.
 *
 * Thread Safety:
 * All public methods are thread-safe. Kernel communication is serialized.
 *
 * Usage Example:
 * @code
 * auto& monitor = RegistryMonitor::Instance();
 * 
 * // Initialize
 * auto config = RegistryMonitorConfig::CreateHighSecurity();
 * monitor.Initialize(config);
 * 
 * // Set policy callback
 * monitor.SetPolicyCallback([](const RegistryEvent& event) -> RegistryVerdict {
 *     if (IsMalicious(event)) return RegistryVerdict::Block;
 *     return RegistryVerdict::Allow;
 * });
 * 
 * // Protect critical keys
 * monitor.AddProtectedKey(L"HKLM\\SOFTWARE\\ShadowStrike");
 * 
 * // Start monitoring
 * monitor.Start();
 * @endcode
 */
class RegistryMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static RegistryMonitor& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the registry monitor.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const RegistryMonitorConfig& config);

    /**
     * @brief Starts monitoring (connects to kernel).
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops monitoring.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if running.
     * @return True if active.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Checks if kernel connection is active.
     * @return True if connected to kernel driver.
     */
    [[nodiscard]] bool IsKernelConnected() const noexcept;

    // ========================================================================
    // POLICY MANAGEMENT
    // ========================================================================

    /**
     * @brief Sets the primary policy callback.
     * @param callback Policy decision callback.
     */
    void SetPolicyCallback(RegistryPolicyCallback callback);

    /**
     * @brief Adds a registry rule.
     * @param rule Rule to add.
     * @return Rule ID.
     */
    [[nodiscard]] uint64_t AddRule(const RegistryRule& rule);

    /**
     * @brief Removes a rule.
     * @param ruleId Rule ID.
     * @return True if removed.
     */
    bool RemoveRule(uint64_t ruleId);

    /**
     * @brief Gets all rules.
     * @return Vector of rules.
     */
    [[nodiscard]] std::vector<RegistryRule> GetRules() const;

    /**
     * @brief Enables or disables a rule.
     * @param ruleId Rule ID.
     * @param enabled Enable state.
     * @return True if updated.
     */
    bool SetRuleEnabled(uint64_t ruleId, bool enabled);

    // ========================================================================
    // KEY PROTECTION
    // ========================================================================

    /**
     * @brief Adds a protected key.
     * @param keyPath Key path to protect.
     */
    void AddProtectedKey(const std::wstring& keyPath);

    /**
     * @brief Adds protected key with config.
     * @param config Protected key configuration.
     */
    void AddProtectedKey(const ProtectedKey& config);

    /**
     * @brief Removes protected key.
     * @param keyPath Key path.
     */
    void RemoveProtectedKey(const std::wstring& keyPath);

    /**
     * @brief Checks if key is protected.
     * @param keyPath Key path.
     * @return True if protected.
     */
    [[nodiscard]] bool IsProtectedKey(const std::wstring& keyPath) const;

    /**
     * @brief Gets all protected keys.
     * @return Vector of protected key configs.
     */
    [[nodiscard]] std::vector<ProtectedKey> GetProtectedKeys() const;

    // ========================================================================
    // KEY ANALYSIS
    // ========================================================================

    /**
     * @brief Check if key is critical to system.
     * @param keyPath Key path.
     * @return True if critical.
     */
    [[nodiscard]] static bool IsCriticalKey(const std::wstring& keyPath);

    /**
     * @brief Gets key category.
     * @param keyPath Key path.
     * @return Key category.
     */
    [[nodiscard]] static KeyCategory GetKeyCategory(const std::wstring& keyPath);

    /**
     * @brief Analyzes registry value.
     * @param data Value data.
     * @param type Value type.
     * @return Value analysis.
     */
    [[nodiscard]] ValueAnalysis AnalyzeValue(
        std::span<const uint8_t> data,
        RegistryValueType type
    ) const;

    // ========================================================================
    // EVENT HANDLING
    // ========================================================================

    /**
     * @brief Manually process a registry event.
     * @param event Registry event.
     * @return Verdict.
     */
    [[nodiscard]] RegistryVerdict ProcessEvent(const RegistryEvent& event);

    /**
     * @brief Gets recent events.
     * @param maxCount Maximum count.
     * @return Vector of recent events.
     */
    [[nodiscard]] std::vector<RegistryEvent> GetRecentEvents(size_t maxCount = 100) const;

    // ========================================================================
    // DECEPTION
    // ========================================================================

    /**
     * @brief Configures deception mode.
     * @param config Deception configuration.
     */
    void ConfigureDeception(const DeceptionConfig& config);

    /**
     * @brief Adds honeypot key.
     * @param keyPath Key path.
     */
    void AddHoneypotKey(const std::wstring& keyPath);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAlertCallback(RegistryAlertCallback callback);
    [[nodiscard]] uint64_t RegisterEventCallback(RegistryEventCallback callback);
    [[nodiscard]] uint64_t RegisterValueCallback(ValueAnalysisCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const RegistryMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    RegistryMonitor();
    ~RegistryMonitor();

    RegistryMonitor(const RegistryMonitor&) = delete;
    RegistryMonitor& operator=(const RegistryMonitor&) = delete;

    std::unique_ptr<RegistryMonitorImpl> m_impl;
};

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike