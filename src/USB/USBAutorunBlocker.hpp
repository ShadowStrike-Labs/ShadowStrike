/**
 * ============================================================================
 * ShadowStrike NGAV - USB AUTORUN BLOCKER MODULE
 * ============================================================================
 *
 * @file USBAutorunBlocker.hpp
 * @brief Enterprise-grade USB autorun protection engine for preventing
 *        automatic malware execution from removable media.
 *
 * Provides comprehensive autorun.inf protection including parsing, blocking,
 * sanitization, and vaccination of removable drives.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. AUTORUN.INF ANALYSIS
 *    - Full INI parsing
 *    - Open command detection
 *    - ShellExecute detection
 *    - Icon redirection detection
 *    - Action command extraction
 *    - Label manipulation detection
 *
 * 2. BLOCKING MODES
 *    - Block execution only
 *    - Delete autorun.inf
 *    - Quarantine autorun.inf
 *    - Sanitize (remove dangerous lines)
 *    - Rename/disable
 *
 * 3. VACCINATION
 *    - Create protected autorun.inf folder
 *    - NTFS alternate data streams
 *    - Prevent future autorun creation
 *    - Self-healing vaccination
 *
 * 4. MALWARE DETECTION
 *    - Known malware patterns
 *    - Obfuscation detection
 *    - Hidden file references
 *    - Suspicious icon paths
 *    - Conficker detection
 *    - AutoRun worms
 *
 * 5. ENTERPRISE FEATURES
 *    - Policy-based enforcement
 *    - Audit logging
 *    - Centralized management
 *    - Compliance reporting
 *
 * INTEGRATION:
 * ============
 * - PatternStore for autorun patterns
 * - SignatureStore for malware signatures
 * - USBDeviceMonitor for mount events
 * - Whitelist for trusted autorun
 *
 * @note Windows Vista+ disables autorun by default for most drives.
 * @note Still relevant for backward compatibility and edge cases.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::USB {
    class USBAutorunBlockerImpl;
}

namespace ShadowStrike {
namespace USB {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AutorunConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum autorun.inf size (1 MB)
    inline constexpr size_t MAX_AUTORUN_SIZE = 1 * 1024 * 1024;
    
    /// @brief Autorun file names
    inline constexpr const char* AUTORUN_FILENAMES[] = {
        "autorun.inf",
        "AUTORUN.INF",
        "AutoRun.inf",
        "Autorun.inf"
    };
    
    /// @brief Dangerous autorun keys
    inline constexpr const char* DANGEROUS_KEYS[] = {
        "open",
        "shellexecute",
        "shell\\open\\command",
        "shell\\explore\\command",
        "shell\\autoplay\\command",
        "shell\\find\\command",
        "shell\\print\\command"
    };
    
    /// @brief Vaccination folder name
    inline constexpr const char* VACCINE_FOLDER_NAME = "autorun.inf";

}  // namespace AutorunConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Autorun action taken
 */
enum class AutorunAction : uint8_t {
    Allowed         = 0,    ///< Autorun allowed (whitelisted)
    Blocked         = 1,    ///< Execution blocked
    Sanitized       = 2,    ///< Dangerous lines removed
    Deleted         = 3,    ///< File deleted
    Quarantined     = 4,    ///< File quarantined
    Renamed         = 5,    ///< File renamed
    Vaccinated      = 6,    ///< Drive vaccinated
    ErrorOccurred   = 255   ///< Error during processing
};

/**
 * @brief Autorun threat type
 */
enum class AutorunThreatType : uint8_t {
    None            = 0,
    OpenCommand     = 1,    ///< open= directive
    ShellExecute    = 2,    ///< shellexecute= directive
    ShellCommand    = 3,    ///< shell\*\command directive
    SuspiciousIcon  = 4,    ///< Suspicious icon path
    HiddenFile      = 5,    ///< References hidden file
    ObfuscatedPath  = 6,    ///< Obfuscated file path
    KnownMalware    = 7,    ///< Known malware pattern
    MultipleCommands = 8,   ///< Multiple execution commands
    NonStandardEntry = 9    ///< Non-standard entry
};

/**
 * @brief Vaccination status
 */
enum class VaccinationStatus : uint8_t {
    NotVaccinated   = 0,
    Vaccinated      = 1,
    PartiallyVaccinated = 2,
    VaccinationFailed = 3,
    VaccinationRemoved = 4
};

/**
 * @brief Policy mode
 */
enum class AutorunPolicyMode : uint8_t {
    Block           = 0,    ///< Block all autorun
    Sanitize        = 1,    ///< Remove dangerous entries
    Delete          = 2,    ///< Delete autorun.inf
    Quarantine      = 3,    ///< Quarantine autorun.inf
    Monitor         = 4,    ///< Monitor only (log)
    AllowTrusted    = 5     ///< Allow if signed/trusted
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Autorun.inf parsed entry
 */
struct AutorunEntry {
    /// @brief Section name
    std::string section;
    
    /// @brief Key name
    std::string key;
    
    /// @brief Value
    std::string value;
    
    /// @brief Line number
    size_t lineNumber = 0;
    
    /// @brief Is dangerous
    bool isDangerous = false;
    
    /// @brief Threat type
    AutorunThreatType threatType = AutorunThreatType::None;
    
    /// @brief Resolved path (if file reference)
    std::filesystem::path resolvedPath;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Autorun analysis result
 */
struct AutorunAnalysisResult {
    /// @brief File exists
    bool fileExists = false;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Threat type
    AutorunThreatType primaryThreat = AutorunThreatType::None;
    
    /// @brief All entries
    std::vector<AutorunEntry> entries;
    
    /// @brief Dangerous entries
    std::vector<AutorunEntry> dangerousEntries;
    
    /// @brief Referenced files
    std::vector<std::filesystem::path> referencedFiles;
    
    /// @brief Open command (if present)
    std::string openCommand;
    
    /// @brief Icon path
    std::string iconPath;
    
    /// @brief Label
    std::string label;
    
    /// @brief Action command
    std::string actionCommand;
    
    /// @brief Detected malware family
    std::string detectedFamily;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief File hash (SHA-256)
    std::string sha256;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Analysis time
    SystemTimePoint analysisTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Enforcement result
 */
struct EnforcementResult {
    /// @brief Action taken
    AutorunAction action = AutorunAction::ErrorOccurred;
    
    /// @brief Was successful
    bool success = false;
    
    /// @brief Analysis result
    AutorunAnalysisResult analysis;
    
    /// @brief Lines removed (if sanitized)
    std::vector<size_t> linesRemoved;
    
    /// @brief Quarantine path (if quarantined)
    std::filesystem::path quarantinePath;
    
    /// @brief New filename (if renamed)
    std::string newFilename;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Enforcement time
    SystemTimePoint enforcementTime;
    
    /// @brief Duration
    std::chrono::microseconds duration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Vaccination result
 */
struct VaccinationResult {
    /// @brief Status
    VaccinationStatus status = VaccinationStatus::VaccinationFailed;
    
    /// @brief Was successful
    bool success = false;
    
    /// @brief Drive path
    std::string drivePath;
    
    /// @brief Vaccine path
    std::filesystem::path vaccinePath;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Vaccination time
    SystemTimePoint vaccinationTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct AutorunStatistics {
    std::atomic<uint64_t> drivesScanned{0};
    std::atomic<uint64_t> autorunFilesFound{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> filesBlocked{0};
    std::atomic<uint64_t> filesSanitized{0};
    std::atomic<uint64_t> filesDeleted{0};
    std::atomic<uint64_t> filesQuarantined{0};
    std::atomic<uint64_t> drivesVaccinated{0};
    std::atomic<uint64_t> vaccinationFailures{0};
    std::array<std::atomic<uint64_t>, 16> byThreatType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct AutorunBlockerConfiguration {
    /// @brief Enable blocking
    bool enabled = true;
    
    /// @brief Policy mode
    AutorunPolicyMode policyMode = AutorunPolicyMode::Block;
    
    /// @brief Vaccinate drives automatically
    bool autoVaccinate = true;
    
    /// @brief Delete autorun on mount
    bool deleteOnMount = false;
    
    /// @brief Quarantine before delete
    bool quarantineBeforeDelete = true;
    
    /// @brief Block hidden file references
    bool blockHiddenReferences = true;
    
    /// @brief Scan referenced files
    bool scanReferencedFiles = true;
    
    /// @brief Notify user on action
    bool notifyUser = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using EnforcementCallback = std::function<void(const EnforcementResult&)>;
using VaccinationCallback = std::function<void(const VaccinationResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// USB AUTORUN BLOCKER CLASS
// ============================================================================

/**
 * @class USBAutorunBlocker
 * @brief Enterprise USB autorun protection engine
 */
class USBAutorunBlocker final {
public:
    [[nodiscard]] static USBAutorunBlocker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    USBAutorunBlocker(const USBAutorunBlocker&) = delete;
    USBAutorunBlocker& operator=(const USBAutorunBlocker&) = delete;
    USBAutorunBlocker(USBAutorunBlocker&&) = delete;
    USBAutorunBlocker& operator=(USBAutorunBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const AutorunBlockerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const AutorunBlockerConfiguration& config);
    [[nodiscard]] AutorunBlockerConfiguration GetConfiguration() const;

    // ========================================================================
    // ENFORCEMENT
    // ========================================================================
    
    /// @brief Enforce policy on drive
    [[nodiscard]] EnforcementResult EnforcePolicy(const std::string& driveRoot);
    
    /// @brief Enforce policy on specific autorun file
    [[nodiscard]] EnforcementResult EnforcePolicyOnFile(
        const std::filesystem::path& autorunPath);
    
    /// @brief Check drive for autorun threats
    [[nodiscard]] AutorunAnalysisResult AnalyzeDrive(const std::string& driveRoot);
    
    /// @brief Analyze specific autorun.inf file
    [[nodiscard]] AutorunAnalysisResult AnalyzeAutorunFile(
        const std::filesystem::path& autorunPath);

    // ========================================================================
    // VACCINATION
    // ========================================================================
    
    /// @brief Vaccinate drive
    [[nodiscard]] VaccinationResult VaccinateDrive(const std::string& driveRoot);
    
    /// @brief Check vaccination status
    [[nodiscard]] VaccinationStatus GetVaccinationStatus(const std::string& driveRoot);
    
    /// @brief Remove vaccination
    [[nodiscard]] bool RemoveVaccination(const std::string& driveRoot);
    
    /// @brief Repair vaccination if corrupted
    [[nodiscard]] bool RepairVaccination(const std::string& driveRoot);

    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /// @brief Find autorun.inf on drive
    [[nodiscard]] std::optional<std::filesystem::path> FindAutorunFile(
        const std::string& driveRoot);
    
    /// @brief Check if path is dangerous
    [[nodiscard]] bool IsDangerousPath(const std::string& path) const;
    
    /// @brief Parse autorun.inf content
    [[nodiscard]] std::vector<AutorunEntry> ParseAutorunContent(
        std::string_view content);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterEnforcementCallback(EnforcementCallback callback);
    void RegisterVaccinationCallback(VaccinationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] AutorunStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    USBAutorunBlocker();
    ~USBAutorunBlocker();
    
    std::unique_ptr<USBAutorunBlockerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAutorunActionName(AutorunAction action) noexcept;
[[nodiscard]] std::string_view GetAutorunThreatTypeName(AutorunThreatType type) noexcept;
[[nodiscard]] std::string_view GetVaccinationStatusName(VaccinationStatus status) noexcept;
[[nodiscard]] std::string_view GetAutorunPolicyModeName(AutorunPolicyMode mode) noexcept;
[[nodiscard]] bool IsAutorunKey(std::string_view key) noexcept;
[[nodiscard]] bool IsDangerousAutorunKey(std::string_view key) noexcept;

}  // namespace USB
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_AUTORUN_ENFORCE(driveRoot) \
    ::ShadowStrike::USB::USBAutorunBlocker::Instance().EnforcePolicy(driveRoot)

#define SS_AUTORUN_VACCINATE(driveRoot) \
    ::ShadowStrike::USB::USBAutorunBlocker::Instance().VaccinateDrive(driveRoot)