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
 * ShadowStrike Core Registry - STARTUP ANALYZER (The Boot Guard)
 * ============================================================================
 *
 * @file StartupAnalyzer.hpp
 * @brief Enterprise-grade startup program analysis and optimization engine.
 *
 * This module provides comprehensive analysis, management, and optimization
 * of Windows startup programs, enabling security assessment, boot performance
 * analysis, and safe cleanup of malicious or unnecessary startup entries.
 *
 * Key Capabilities:
 * =================
 * 1. STARTUP ENUMERATION
 *    - Registry Run keys
 *    - Startup folders
 *    - Scheduled tasks (logon trigger)
 *    - Services (auto-start)
 *    - Shell extensions
 *
 * 2. BOOT ANALYSIS
 *    - Boot time measurement
 *    - Per-entry impact analysis
 *    - Resource consumption tracking
 *    - Dependency analysis
 *    - Parallel startup detection
 *
 * 3. SECURITY ASSESSMENT
 *    - Digital signature validation
 *    - Hash reputation lookup
 *    - Behavioral analysis
 *    - Threat intelligence integration
 *    - Risk scoring
 *
 * 4. MANAGEMENT
 *    - Safe disable/enable
 *    - Delay startup
 *    - Remove malicious entries
 *    - Backup/restore
 *    - Quarantine support
 *
 * 5. OPTIMIZATION
 *    - Identify unnecessary items
 *    - Recommend optimizations
 *    - Auto-optimization mode
 *    - Performance baseline
 *
 * Startup Analysis Architecture:
 * ==============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       StartupAnalyzer                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ItemEnumerator│  │BootAnalyzer  │  │    SecurityAssessor      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Registry   │  │ - Boot Time  │  │ - Signatures             │  │
 *   │  │ - Folders    │  │ - Impact     │  │ - Hashes                 │  │
 *   │  │ - Tasks      │  │ - Resources  │  │ - Reputation             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ItemManager   │  │ Optimizer    │  │    HistoryTracker        │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Enable     │  │ - Recommend  │  │ - Changes                │  │
 *   │  │ - Disable    │  │ - Auto-opt   │  │ - Rollback               │  │
 *   │  │ - Remove     │  │ - Baseline   │  │ - Backup                 │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - PersistenceDetector: Entry identification
 * - ScanEngine: Binary scanning
 * - HashStore: Known good/bad hashes
 * - ThreatIntel: Reputation data
 * - Whitelist: Trusted entries
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1547: Boot or Logon Autostart Execution
 * - T1053: Scheduled Task/Job (logon triggers)
 * - T1543: Create or Modify System Process (services)
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - State modifications are serialized
 * - Concurrent scanning supported
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see PersistenceDetector.hpp for ASEP detection
 * @see RegistryMonitor.hpp for real-time monitoring
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/RegistryUtils.hpp"      // Registry operations
#include "../../Utils/FileUtils.hpp"          // Startup folders
#include "../../Utils/CertUtils.hpp"          // Binary verification
#include "../../Utils/ProcessUtils.hpp"       // Process enumeration
#include "../../Whitelist/WhiteListStore.hpp" // Trusted startup items

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

namespace ShadowStrike {
namespace Core {
namespace Registry {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class StartupAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace StartupAnalyzerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr size_t MAX_STARTUP_ITEMS = 10000;
    constexpr size_t MAX_HISTORY_ENTRIES = 1000;
    constexpr uint32_t BOOT_ANALYSIS_TIMEOUT_MS = 60000;

    // Performance thresholds
    constexpr uint32_t SLOW_STARTUP_THRESHOLD_MS = 5000;
    constexpr uint32_t HIGH_CPU_THRESHOLD_PERCENT = 25;
    constexpr uint64_t HIGH_MEMORY_THRESHOLD_MB = 100;

    // Delay constants
    constexpr uint32_t DEFAULT_DELAY_SECONDS = 30;
    constexpr uint32_t MAX_DELAY_SECONDS = 300;

}  // namespace StartupAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum StartupSource
 * @brief Source of startup entry.
 */
enum class StartupSource : uint8_t {
    Unknown = 0,
    RegistryRun_HKLM = 1,
    RegistryRun_HKCU = 2,
    RegistryRunOnce_HKLM = 3,
    RegistryRunOnce_HKCU = 4,
    StartupFolder_User = 5,
    StartupFolder_AllUsers = 6,
    ScheduledTask = 7,
    Service = 8,
    ShellExtension = 9,
    GroupPolicy = 10,
    AppXPackage = 11
};

/**
 * @enum StartupStatus
 * @brief Status of startup item.
 */
enum class StartupStatus : uint8_t {
    Enabled = 0,
    Disabled = 1,
    Delayed = 2,
    Quarantined = 3,
    Removed = 4,
    Orphaned = 5,                  // Target doesn't exist
    Error = 6
};

/**
 * @enum ItemCategory
 * @brief Category of startup item.
 */
enum class ItemCategory : uint8_t {
    Unknown = 0,
    System = 1,                    // OS components
    Security = 2,                  // AV, firewall
    Hardware = 3,                  // Drivers, utilities
    Application = 4,              // User applications
    Utility = 5,                   // System utilities
    Bloatware = 6,                 // Unnecessary software
    Malicious = 7                  // Detected malware
};

/**
 * @enum ImpactLevel
 * @brief Boot time impact level.
 */
enum class ImpactLevel : uint8_t {
    None = 0,
    Low = 1,                       // < 1 second
    Medium = 2,                    // 1-3 seconds
    High = 3,                      // 3-5 seconds
    Critical = 4                   // > 5 seconds
};

/**
 * @enum ActionResult
 * @brief Result of management action.
 */
enum class ActionResult : uint8_t {
    Success = 0,
    Failed = 1,
    AccessDenied = 2,
    NotFound = 3,
    AlreadyInState = 4,
    RequiresReboot = 5,
    PartialSuccess = 6
};

/**
 * @enum OptimizationRecommendation
 * @brief Recommendation for startup item.
 */
enum class OptimizationRecommendation : uint8_t {
    Keep = 0,
    Delay = 1,
    Disable = 2,
    Remove = 3,
    Investigate = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct BootImpact
 * @brief Boot time impact analysis.
 */
struct alignas(32) BootImpact {
    ImpactLevel level{ ImpactLevel::None };
    uint32_t estimatedMs{ 0 };
    double cpuUsagePercent{ 0.0 };
    uint64_t memoryUsageMB{ 0 };
    uint32_t diskReadsMB{ 0 };
    bool blocksOthers{ false };
};

/**
 * @struct SignatureInfo
 * @brief Digital signature information.
 */
struct alignas(64) SignatureInfo {
    bool isSigned{ false };
    bool isValid{ false };
    bool isTrusted{ false };
    bool isMicrosoftSigned{ false };

    std::wstring signerName;
    std::wstring issuerName;
    std::chrono::system_clock::time_point signatureTime;

    std::wstring certificateThumbprint;
    bool isExpired{ false };
    bool isRevoked{ false };
};

/**
 * @struct ReputationInfo
 * @brief Reputation/threat intelligence.
 */
struct alignas(32) ReputationInfo {
    bool isKnownGood{ false };
    bool isKnownBad{ false };
    uint8_t trustScore{ 0 };               // 0-100
    std::string reputation;                // Good, Suspicious, Malicious
    std::string malwareFamily;
    std::vector<std::string> detectionNames;
};

/**
 * @struct StartupItem
 * @brief Complete startup item information.
 */
struct alignas(256) StartupItem {
    // Identity
    uint64_t itemId{ 0 };
    std::wstring name;
    std::wstring displayName;
    std::wstring description;
    std::wstring publisher;

    // Source
    StartupSource source{ StartupSource::Unknown };
    std::wstring location;                 // Registry key or folder
    std::wstring entryName;                // Value name or filename

    // Target
    std::wstring command;                  // Full command line
    std::wstring targetPath;               // Resolved executable path
    std::wstring arguments;
    std::wstring workingDirectory;
    bool targetExists{ false };

    // Status
    StartupStatus status{ StartupStatus::Enabled };
    bool isEnabled{ true };
    bool isDelayed{ false };
    uint32_t delaySeconds{ 0 };

    // Classification
    ItemCategory category{ ItemCategory::Unknown };
    bool isCritical{ false };              // Required for system
    bool isUserCreated{ false };
    bool isHidden{ false };

    // Security
    SignatureInfo signature;
    ReputationInfo reputation;
    bool isMalicious{ false };
    uint8_t riskScore{ 0 };                // 0-100
    std::vector<std::string> riskFactors;

    // Impact
    BootImpact bootImpact;

    // Hash
    std::array<uint8_t, 32> sha256{ 0 };
    std::string sha256Hex;

    // Timestamps
    std::chrono::system_clock::time_point createdTime;
    std::chrono::system_clock::time_point modifiedTime;
    std::chrono::system_clock::time_point lastRun;

    // Optimization
    OptimizationRecommendation recommendation{ OptimizationRecommendation::Keep };
    std::string recommendationReason;

    // User notes
    std::wstring userNotes;
};

/**
 * @struct BootAnalysis
 * @brief System boot analysis.
 */
struct alignas(64) BootAnalysis {
    // Timing
    std::chrono::system_clock::time_point bootTime;
    uint32_t totalBootTimeMs{ 0 };
    uint32_t preLogonTimeMs{ 0 };
    uint32_t postLogonTimeMs{ 0 };
    uint32_t desktopReadyTimeMs{ 0 };

    // Startup items
    uint32_t totalStartupItems{ 0 };
    uint32_t enabledItems{ 0 };
    uint32_t delayedItems{ 0 };
    uint32_t criticalItems{ 0 };

    // Impact breakdown
    uint32_t highImpactItems{ 0 };
    uint32_t totalStartupImpactMs{ 0 };

    // Resources
    double peakCPUPercent{ 0.0 };
    uint64_t peakMemoryMB{ 0 };
    uint64_t diskReadMB{ 0 };

    // Comparison to baseline
    int32_t changeFromBaselineMs{ 0 };
    double changePercent{ 0.0 };
};

/**
 * @struct StartupChange
 * @brief Record of startup change.
 */
struct alignas(128) StartupChange {
    uint64_t changeId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // What changed
    uint64_t itemId{ 0 };
    std::wstring itemName;
    StartupSource source{ StartupSource::Unknown };

    // Change details
    std::string changeType;                // Enable, Disable, Remove, Add, Modify
    StartupStatus previousStatus{ StartupStatus::Enabled };
    StartupStatus newStatus{ StartupStatus::Enabled };

    // Who made change
    std::string changedBy;                 // User, System, ShadowStrike
    uint32_t processId{ 0 };
    std::wstring processPath;

    // Backup
    bool hasBackup{ false };
    std::wstring backupData;

    // Rollback info
    bool canRollback{ true };
};

/**
 * @struct OptimizationPlan
 * @brief Plan for startup optimization.
 */
struct alignas(64) OptimizationPlan {
    // Summary
    uint32_t itemsToDelay{ 0 };
    uint32_t itemsToDisable{ 0 };
    uint32_t itemsToRemove{ 0 };
    uint32_t estimatedTimeSavedMs{ 0 };

    // Items
    std::vector<uint64_t> delayItems;
    std::vector<uint64_t> disableItems;
    std::vector<uint64_t> removeItems;

    // Safety
    bool isSafe{ true };
    std::vector<std::string> warnings;
};

/**
 * @struct StartupAlert
 * @brief Alert for startup changes.
 */
struct alignas(128) StartupAlert {
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Type
    std::string alertType;                 // NewItem, Malicious, Suspicious, Removed
    uint8_t severity{ 0 };                 // 0-4

    // Item
    uint64_t itemId{ 0 };
    std::wstring itemName;
    std::wstring targetPath;

    // Risk
    uint8_t riskScore{ 0 };
    std::vector<std::string> riskFactors;

    // Recommendation
    OptimizationRecommendation recommendation{ OptimizationRecommendation::Investigate };
    std::string description;
};

/**
 * @struct StartupAnalyzerConfig
 * @brief Configuration for startup analyzer.
 */
struct alignas(64) StartupAnalyzerConfig {
    // Analysis options
    bool analyzeSignatures{ true };
    bool checkReputation{ true };
    bool measureBootImpact{ true };
    bool detectHidden{ true };

    // Auto actions
    bool autoDisableMalicious{ false };
    bool autoQuarantineMalicious{ true };
    bool alertOnNewItems{ true };
    bool alertOnSuspicious{ true };

    // Optimization
    bool enableOptimization{ false };
    bool autoDelayNonCritical{ false };
    uint32_t defaultDelaySeconds{ StartupAnalyzerConstants::DEFAULT_DELAY_SECONDS };

    // History
    bool trackHistory{ true };
    size_t maxHistoryEntries{ StartupAnalyzerConstants::MAX_HISTORY_ENTRIES };

    // Backup
    bool createBackups{ true };
    std::wstring backupPath;

    // Factory methods
    static StartupAnalyzerConfig CreateDefault() noexcept;
    static StartupAnalyzerConfig CreateSecurity() noexcept;
    static StartupAnalyzerConfig CreatePerformance() noexcept;
};

/**
 * @struct StartupAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) StartupAnalyzerStatistics {
    // Item statistics
    std::atomic<uint64_t> totalItemsAnalyzed{ 0 };
    std::atomic<uint32_t> enabledItems{ 0 };
    std::atomic<uint32_t> disabledItems{ 0 };
    std::atomic<uint32_t> maliciousItems{ 0 };

    // Action statistics
    std::atomic<uint64_t> itemsEnabled{ 0 };
    std::atomic<uint64_t> itemsDisabled{ 0 };
    std::atomic<uint64_t> itemsRemoved{ 0 };
    std::atomic<uint64_t> itemsQuarantined{ 0 };

    // Alert statistics
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Boot analysis
    std::atomic<uint32_t> lastBootTimeMs{ 0 };
    std::atomic<uint32_t> baselineBootTimeMs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for new startup item.
 */
using NewItemCallback = std::function<void(const StartupItem& item)>;

/**
 * @brief Callback for startup alert.
 */
using StartupAlertCallback = std::function<void(const StartupAlert& alert)>;

/**
 * @brief Callback for item change.
 */
using ItemChangeCallback = std::function<void(const StartupChange& change)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class StartupAnalyzer
 * @brief Enterprise-grade startup program analysis and management.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = StartupAnalyzer::Instance();
 *
 * // Get all startup items
 * auto items = analyzer.GetStartupItems();
 *
 * // Check for malicious items
 * for (const auto& item : items) {
 *     if (item.isMalicious) {
 *         analyzer.DisableItem(item.name);
 *     }
 * }
 *
 * // Get optimization recommendations
 * auto plan = analyzer.GetOptimizationPlan();
 * if (plan.isSafe) {
 *     analyzer.ApplyOptimizationPlan(plan);
 * }
 * @endcode
 */
class StartupAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to singleton instance.
     */
    [[nodiscard]] static StartupAnalyzer& Instance() noexcept;

    /**
     * @brief Check if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // Delete copy/move
    StartupAnalyzer(const StartupAnalyzer&) = delete;
    StartupAnalyzer& operator=(const StartupAnalyzer&) = delete;
    StartupAnalyzer(StartupAnalyzer&&) = delete;
    StartupAnalyzer& operator=(StartupAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the startup analyzer.
     * @param config Configuration settings.
     * @return True if successful.
     */
    [[nodiscard]] bool Initialize(const StartupAnalyzerConfig& config = StartupAnalyzerConfig::CreateDefault());

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Check if analyzer is initialized.
     * @return True if initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     * @param config New configuration.
     * @return True if successful.
     */
    [[nodiscard]] bool UpdateConfig(const StartupAnalyzerConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] StartupAnalyzerConfig GetConfig() const;

    // ========================================================================
    // ITEM ENUMERATION
    // ========================================================================

    /**
     * @brief Gets all startup items.
     * @return Vector of startup items.
     */
    [[nodiscard]] std::vector<StartupItem> GetStartupItems();

    /**
     * @brief Gets startup item by name.
     * @param name Item name.
     * @return Item, or nullopt.
     */
    [[nodiscard]] std::optional<StartupItem> GetItem(const std::wstring& name) const;

    /**
     * @brief Gets startup item by ID.
     * @param itemId Item ID.
     * @return Item, or nullopt.
     */
    [[nodiscard]] std::optional<StartupItem> GetItemById(uint64_t itemId) const;

    /**
     * @brief Gets items by source.
     * @param source Startup source.
     * @return Vector of items.
     */
    [[nodiscard]] std::vector<StartupItem> GetItemsBySource(StartupSource source) const;

    /**
     * @brief Gets items by category.
     * @param category Item category.
     * @return Vector of items.
     */
    [[nodiscard]] std::vector<StartupItem> GetItemsByCategory(ItemCategory category) const;

    /**
     * @brief Refreshes startup items.
     */
    void RefreshItems();

    // ========================================================================
    // ITEM MANAGEMENT
    // ========================================================================

    /**
     * @brief Disables a startup item.
     * @param name Item name.
     * @return Action result.
     */
    [[nodiscard]] ActionResult DisableItem(const std::wstring& name);

    /**
     * @brief Enables a startup item.
     * @param name Item name.
     * @return Action result.
     */
    [[nodiscard]] ActionResult EnableItem(const std::wstring& name);

    /**
     * @brief Removes a startup item.
     * @param name Item name.
     * @param quarantine Move to quarantine instead of delete.
     * @return Action result.
     */
    [[nodiscard]] ActionResult RemoveItem(const std::wstring& name, bool quarantine = true);

    /**
     * @brief Delays a startup item.
     * @param name Item name.
     * @param delaySeconds Delay in seconds.
     * @return Action result.
     */
    [[nodiscard]] ActionResult DelayItem(const std::wstring& name, uint32_t delaySeconds);

    /**
     * @brief Restores a quarantined item.
     * @param name Item name.
     * @return Action result.
     */
    [[nodiscard]] ActionResult RestoreItem(const std::wstring& name);

    // ========================================================================
    // BOOT ANALYSIS
    // ========================================================================

    /**
     * @brief Gets boot analysis.
     * @return Boot analysis.
     */
    [[nodiscard]] BootAnalysis GetBootAnalysis() const;

    /**
     * @brief Sets boot baseline.
     */
    void SetBootBaseline();

    /**
     * @brief Gets boot baseline.
     * @return Baseline boot time in ms.
     */
    [[nodiscard]] uint32_t GetBootBaseline() const noexcept;

    // ========================================================================
    // OPTIMIZATION
    // ========================================================================

    /**
     * @brief Gets optimization plan.
     * @return Optimization plan.
     */
    [[nodiscard]] OptimizationPlan GetOptimizationPlan() const;

    /**
     * @brief Applies optimization plan.
     * @param plan Plan to apply.
     * @return True if successful.
     */
    [[nodiscard]] bool ApplyOptimizationPlan(const OptimizationPlan& plan);

    /**
     * @brief Gets items recommended for delay.
     * @return Vector of item IDs.
     */
    [[nodiscard]] std::vector<uint64_t> GetDelayRecommendations() const;

    /**
     * @brief Gets items recommended for disable.
     * @return Vector of item IDs.
     */
    [[nodiscard]] std::vector<uint64_t> GetDisableRecommendations() const;

    // ========================================================================
    // SECURITY
    // ========================================================================

    /**
     * @brief Gets malicious items.
     * @return Vector of malicious items.
     */
    [[nodiscard]] std::vector<StartupItem> GetMaliciousItems() const;

    /**
     * @brief Gets suspicious items.
     * @param minRiskScore Minimum risk score.
     * @return Vector of suspicious items.
     */
    [[nodiscard]] std::vector<StartupItem> GetSuspiciousItems(uint8_t minRiskScore = 50) const;

    /**
     * @brief Scans item for threats.
     * @param name Item name.
     * @return Updated item with scan results.
     */
    [[nodiscard]] StartupItem ScanItem(const std::wstring& name);

    // ========================================================================
    // HISTORY
    // ========================================================================

    /**
     * @brief Gets change history.
     * @param maxCount Maximum entries.
     * @return Vector of changes.
     */
    [[nodiscard]] std::vector<StartupChange> GetHistory(size_t maxCount = 100) const;

    /**
     * @brief Rollbacks a change.
     * @param changeId Change ID.
     * @return True if successful.
     */
    [[nodiscard]] bool RollbackChange(uint64_t changeId);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterNewItemCallback(NewItemCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(StartupAlertCallback callback);
    [[nodiscard]] uint64_t RegisterChangeCallback(ItemChangeCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get analyzer statistics.
     * @return Current statistics.
     */
    [[nodiscard]] const StartupAnalyzerStatistics& GetStatistics() const noexcept;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Get analyzer version.
     * @return Version string.
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

    /**
     * @brief Run self-test.
     * @return True if all tests pass.
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Run diagnostics.
     * @return Diagnostic messages.
     */
    [[nodiscard]] std::vector<std::wstring> RunDiagnostics() const;

    // ========================================================================
    // EXPORT
    // ========================================================================

    bool ExportReport(const std::wstring& outputPath) const;
    bool ExportItems(const std::wstring& outputPath) const;

private:
    StartupAnalyzer();
    ~StartupAnalyzer();

    std::unique_ptr<StartupAnalyzerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetStartupSourceName(StartupSource source) noexcept;
[[nodiscard]] std::string_view GetStartupStatusName(StartupStatus status) noexcept;
[[nodiscard]] std::string_view GetItemCategoryName(ItemCategory category) noexcept;
[[nodiscard]] std::string_view GetImpactLevelName(ImpactLevel level) noexcept;
[[nodiscard]] std::string_view GetActionResultName(ActionResult result) noexcept;
[[nodiscard]] std::string_view GetOptimizationRecommendationName(OptimizationRecommendation rec) noexcept;

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
