/**
 * ============================================================================
 * ShadowStrike Core System - BOOT TIME ANALYZER (The Startup Inspector)
 * ============================================================================
 *
 * @file BootTimeAnalyzer.hpp
 * @brief Enterprise-grade boot performance analysis and startup security.
 *
 * This module provides comprehensive boot time analysis including performance
 * measurement, startup item evaluation, boot security assessment, and
 * early-launch anti-malware (ELAM) integration.
 *
 * Key Capabilities:
 * =================
 * 1. BOOT PERFORMANCE ANALYSIS
 *    - Boot phase timing
 *    - Driver load times
 *    - Service start times
 *    - Application launch impact
 *
 * 2. STARTUP SECURITY
 *    - Startup item enumeration
 *    - Malicious startup detection
 *    - Persistence mechanism analysis
 *    - Boot chain integrity
 *
 * 3. ELAM INTEGRATION
 *    - Early launch status
 *    - Boot driver classification
 *    - Secure boot verification
 *    - Measured boot analysis
 *
 * 4. OPTIMIZATION RECOMMENDATIONS
 *    - Boot time reduction suggestions
 *    - Unnecessary startup items
 *    - Driver load order optimization
 *    - ShadowStrike impact measurement
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1547: Boot or Logon Autostart Execution
 * - T1542: Pre-OS Boot
 * - T1553.006: Code Signing Policy Modification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see DriverAnalyzer.hpp for driver security analysis
 * @see ServiceManager.hpp for service management
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/SystemUtils.hpp"        // Boot info, OS version
#include "../../Utils/RegistryUtils.hpp"      // Startup registry entries
#include "../../Utils/FileUtils.hpp"          // Startup folder enumeration
#include "../../Utils/CertUtils.hpp"          // Startup item verification
#include "../../Whitelist/WhiteListStore.hpp" // Trusted startup items

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace System {

// Forward declaration is inside the class definition for PIMPL pattern

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum BootPhase
 * @brief Boot process phase.
 */
enum class BootPhase : uint8_t {
    Unknown = 0,
    UEFI = 1,                      // UEFI/BIOS
    BootLoader = 2,                // Windows Boot Manager
    KernelInit = 3,                // Kernel initialization
    DriverInit = 4,                // Driver initialization
    SessionInit = 5,               // Session manager
    ServiceStart = 6,              // Service startup
    ShellStart = 7,                // Shell (Explorer) start
    UserLogon = 8,                 // User logon process
    PostLogon = 9                  // Post-logon apps
};

/**
 * @enum StartupItemType
 * @brief Type of startup item.
 */
enum class StartupItemType : uint8_t {
    Unknown = 0,
    Service = 1,
    Driver = 2,
    RunKey = 3,                    // HKLM/HKCU\...\Run
    RunOnceKey = 4,
    StartupFolder = 5,
    ScheduledTask = 6,
    ShellExtension = 7,
    BrowserExtension = 8,
    ActiveXControl = 9,
    WMISubscription = 10
};

/**
 * @enum StartupItemRisk
 * @brief Risk level of startup item.
 */
enum class StartupItemRisk : uint8_t {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @enum SecureBootStatus
 * @brief Secure Boot status.
 */
enum class SecureBootStatus : uint8_t {
    Unknown = 0,
    Enabled = 1,
    Disabled = 2,
    NotSupported = 3
};

/**
 * @enum ELAMDriverStatus
 * @brief ELAM driver classification.
 */
enum class ELAMDriverStatus : uint8_t {
    Unknown = 0,
    Good = 1,                      // Known good
    Bad = 2,                       // Known bad
    Unknown_ = 3,                  // Unknown to ELAM
    BadButCritical = 4             // Bad but required for boot
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct BootPhaseMetric
 * @brief Timing for a boot phase.
 */
struct alignas(32) BootPhaseMetric {
    BootPhase phase{ BootPhase::Unknown };
    std::wstring phaseName;
    std::chrono::milliseconds duration{ 0 };
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
};

/**
 * @struct DriverBootMetric
 * @brief Boot timing for a driver.
 */
struct alignas(64) DriverBootMetric {
    std::wstring driverName;
    std::wstring driverPath;
    std::chrono::microseconds initDuration{ 0 };
    uint32_t loadOrder{ 0 };
    bool isCritical{ false };
    bool delayedBoot{ false };
    ELAMDriverStatus elamStatus{ ELAMDriverStatus::Unknown };
};

/**
 * @struct ServiceBootMetric
 * @brief Boot timing for a service.
 */
struct alignas(64) ServiceBootMetric {
    std::wstring serviceName;
    std::wstring displayName;
    std::chrono::milliseconds startDuration{ 0 };
    std::chrono::milliseconds delayFromBoot{ 0 };
    bool isDelayedStart{ false };
    bool startedSuccessfully{ true };
    uint32_t startOrder{ 0 };
};

/**
 * @struct ApplicationBootMetric
 * @brief Boot timing for an application.
 */
struct alignas(64) ApplicationBootMetric {
    std::wstring appName;
    std::wstring appPath;
    StartupItemType launchType{ StartupItemType::Unknown };
    std::chrono::milliseconds delayFromLogon{ 0 };
    std::chrono::milliseconds loadDuration{ 0 };
    bool isEssential{ false };
    uint8_t impactScore{ 0 };         // 0-100, 0 = no impact
};

/**
 * @struct StartupItem
 * @brief Comprehensive startup item information.
 */
struct alignas(128) StartupItem {
    // Identity
    std::wstring name;
    std::wstring path;
    std::wstring commandLine;
    std::wstring publisher;
    StartupItemType type{ StartupItemType::Unknown };
    
    // Location
    std::wstring registryLocation;
    std::wstring folderLocation;
    
    // Status
    bool isEnabled{ true };
    bool isRunning{ false };
    bool isVerified{ false };         // Signature verified
    
    // Security
    StartupItemRisk riskLevel{ StartupItemRisk::Safe };
    bool isSuspicious{ false };
    std::wstring suspicionReason;
    std::string sha256Hash;
    
    // Performance
    uint8_t impactScore{ 0 };
    std::chrono::milliseconds avgLoadTime{ 0 };
    
    // Timestamps
    std::chrono::system_clock::time_point addedDate;
    std::chrono::system_clock::time_point lastModified;
};

/**
 * @struct BootSecurityStatus
 * @brief Boot chain security status.
 */
struct alignas(64) BootSecurityStatus {
    SecureBootStatus secureBoot{ SecureBootStatus::Unknown };
    bool measuredBootEnabled{ false };
    bool vbsEnabled{ false };           // Virtualization-based security
    bool hvciEnabled{ false };          // Hypervisor-enforced CI
    bool credentialGuardEnabled{ false };
    bool kernelDMAProtection{ false };
    bool bitLockerEnabled{ false };
    bool tpmPresent{ false };
    uint8_t tpmVersion{ 0 };           // 12 = 1.2, 20 = 2.0
};

/**
 * @struct BootAnalysisResult
 * @brief Complete boot analysis result.
 */
struct alignas(256) BootAnalysisResult {
    // Timing summary
    std::chrono::milliseconds totalBootTime{ 0 };
    std::chrono::milliseconds preBootTime{ 0 };     // UEFI + bootloader
    std::chrono::milliseconds kernelTime{ 0 };
    std::chrono::milliseconds logonTime{ 0 };
    std::chrono::milliseconds postLogonTime{ 0 };
    
    // Phase breakdown
    std::vector<BootPhaseMetric> phases;
    
    // Detailed metrics
    std::vector<DriverBootMetric> drivers;
    std::vector<ServiceBootMetric> services;
    std::vector<ApplicationBootMetric> applications;
    
    // Security
    BootSecurityStatus security;
    
    // ShadowStrike impact
    std::chrono::milliseconds shadowStrikeImpact{ 0 };
    std::wstring shadowStrikeDriverTime;
    std::wstring shadowStrikeServiceTime;
    
    // Issues found
    uint32_t slowDrivers{ 0 };
    uint32_t slowServices{ 0 };
    uint32_t suspiciousStartupItems{ 0 };
    
    // Timestamp
    std::chrono::system_clock::time_point analysisTime;
    std::chrono::system_clock::time_point lastBootTime;
};

/**
 * @struct BootOptimizationSuggestion
 * @brief Boot optimization recommendation.
 */
struct BootOptimizationSuggestion {
    std::wstring category;
    std::wstring suggestion;
    std::wstring targetItem;
    std::chrono::milliseconds potentialSaving{ 0 };
    uint8_t priority{ 0 };            // 1-5, 5 = highest
    bool requiresAdminAction{ false };
};

/**
 * @struct BootTimeAnalyzerConfig
 * @brief Configuration for boot time analyzer.
 */
struct alignas(32) BootTimeAnalyzerConfig {
    bool analyzeDrivers{ true };
    bool analyzeServices{ true };
    bool analyzeApplications{ true };
    bool evaluateSecurity{ true };
    bool generateRecommendations{ true };
    
    static BootTimeAnalyzerConfig CreateDefault() noexcept;
};

/**
 * @struct BootTimeAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) BootTimeAnalyzerStatistics {
    std::atomic<uint64_t> analysesPerformed{ 0 };
    std::atomic<uint64_t> startupItemsScanned{ 0 };
    std::atomic<uint64_t> suspiciousItemsFound{ 0 };
    std::atomic<uint64_t> optimizationsSuggested{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class BootTimeAnalyzer
 * @brief Enterprise-grade boot performance and security analyzer.
 *
 * Thread-safe singleton providing comprehensive boot analysis
 * with security assessment and optimization recommendations.
 */
class BootTimeAnalyzer {
    // Forward declaration of PIMPL implementation struct
    struct BootTimeAnalyzerImpl;
    
public:
    /**
     * @brief Gets singleton instance.
     */
    [[nodiscard]] static BootTimeAnalyzer& Instance() noexcept;

    /**
     * @brief Check if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    /**
     * @brief Initializes boot time analyzer.
     */
    [[nodiscard]] bool Initialize(const BootTimeAnalyzerConfig& config = BootTimeAnalyzerConfig::CreateDefault());
    
    /**
     * @brief Shuts down boot time analyzer.
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
    [[nodiscard]] bool UpdateConfig(const BootTimeAnalyzerConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] BootTimeAnalyzerConfig GetConfig() const;

    // ========================================================================
    // BOOT ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyzes last boot performance.
     */
    [[nodiscard]] BootAnalysisResult AnalyzeLastBoot() const;
    
    /**
     * @brief Gets boot phase metrics.
     */
    [[nodiscard]] std::vector<BootPhaseMetric> GetBootPhaseMetrics() const;
    
    /**
     * @brief Gets total boot time.
     */
    [[nodiscard]] std::chrono::milliseconds GetTotalBootTime() const;
    
    /**
     * @brief Gets ShadowStrike's boot impact.
     */
    [[nodiscard]] std::chrono::milliseconds GetShadowStrikeBootImpact() const;
    
    // ========================================================================
    // DRIVER ANALYSIS
    // ========================================================================
    
    /**
     * @brief Gets driver boot metrics.
     */
    [[nodiscard]] std::vector<DriverBootMetric> GetDriverBootMetrics() const;
    
    /**
     * @brief Gets slowest loading drivers.
     */
    [[nodiscard]] std::vector<DriverBootMetric> GetSlowestDrivers(
        uint32_t count = 10) const;
    
    /**
     * @brief Gets ELAM driver classifications.
     */
    [[nodiscard]] std::unordered_map<std::wstring, ELAMDriverStatus> 
        GetELAMClassifications() const;
    
    // ========================================================================
    // SERVICE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Gets service boot metrics.
     */
    [[nodiscard]] std::vector<ServiceBootMetric> GetServiceBootMetrics() const;
    
    /**
     * @brief Gets slowest starting services.
     */
    [[nodiscard]] std::vector<ServiceBootMetric> GetSlowestServices(
        uint32_t count = 10) const;
    
    // ========================================================================
    // STARTUP ITEMS
    // ========================================================================
    
    /**
     * @brief Enumerates all startup items.
     */
    [[nodiscard]] std::vector<StartupItem> EnumerateStartupItems() const;
    
    /**
     * @brief Gets suspicious startup items.
     */
    [[nodiscard]] std::vector<StartupItem> GetSuspiciousStartupItems() const;
    
    /**
     * @brief Analyzes a specific startup item.
     */
    [[nodiscard]] StartupItem AnalyzeStartupItem(const std::wstring& path) const;
    
    /**
     * @brief Disables a startup item.
     */
    [[nodiscard]] bool DisableStartupItem(const StartupItem& item);
    
    /**
     * @brief Enables a startup item.
     */
    [[nodiscard]] bool EnableStartupItem(const StartupItem& item);
    
    // ========================================================================
    // SECURITY
    // ========================================================================
    
    /**
     * @brief Gets boot security status.
     */
    [[nodiscard]] BootSecurityStatus GetBootSecurityStatus() const;
    
    /**
     * @brief Checks if Secure Boot is enabled.
     */
    [[nodiscard]] bool IsSecureBootEnabled() const;
    
    /**
     * @brief Verifies boot chain integrity.
     */
    [[nodiscard]] bool VerifyBootChainIntegrity() const;
    
    // ========================================================================
    // OPTIMIZATION
    // ========================================================================
    
    /**
     * @brief Gets optimization suggestions.
     */
    [[nodiscard]] std::vector<BootOptimizationSuggestion> 
        GetOptimizationSuggestions() const;
    
    /**
     * @brief Estimates potential boot time savings.
     */
    [[nodiscard]] std::chrono::milliseconds EstimateOptimizationSavings() const;
    
    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] const BootTimeAnalyzerStatistics& GetStatistics() const noexcept;
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

    /**
     * @brief Export boot analysis report.
     * @param outputPath Output file path.
     * @return True if successful.
     */
    [[nodiscard]] bool ExportReport(const std::wstring& outputPath) const;

    /**
     * @brief Export optimization suggestions.
     * @param outputPath Output file path.
     * @return True if successful.
     */
    [[nodiscard]] bool ExportOptimizations(const std::wstring& outputPath) const;

private:
    BootTimeAnalyzer();
    ~BootTimeAnalyzer();

    // Delete copy/move
    BootTimeAnalyzer(const BootTimeAnalyzer&) = delete;
    BootTimeAnalyzer& operator=(const BootTimeAnalyzer&) = delete;
    BootTimeAnalyzer(BootTimeAnalyzer&&) = delete;
    BootTimeAnalyzer& operator=(BootTimeAnalyzer&&) = delete;

    std::unique_ptr<BootTimeAnalyzerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetBootPhaseName(BootPhase phase) noexcept;
[[nodiscard]] std::string_view GetStartupItemTypeName(StartupItemType type) noexcept;
[[nodiscard]] std::string_view GetStartupItemRiskName(StartupItemRisk risk) noexcept;
[[nodiscard]] std::string_view GetSecureBootStatusName(SecureBootStatus status) noexcept;
[[nodiscard]] std::string_view GetELAMDriverStatusName(ELAMDriverStatus status) noexcept;

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
