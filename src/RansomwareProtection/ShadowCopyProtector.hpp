/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - SHADOW COPY PROTECTOR
 * ============================================================================
 *
 * @file ShadowCopyProtector.hpp
 * @brief Enterprise-grade VSS shadow copy protection preventing unauthorized
 *        deletion or modification of Windows Volume Shadow Copies.
 *
 * This module provides comprehensive protection for VSS shadow copies against
 * ransomware attempting to destroy backup recovery options through various
 * attack vectors.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. COMMAND LINE DETECTION
 *    - vssadmin delete shadows
 *    - vssadmin resize shadowstorage
 *    - wmic shadowcopy delete
 *    - PowerShell shadow deletion
 *    - diskshadow commands
 *
 * 2. API-LEVEL PROTECTION
 *    - VSS API interception
 *    - COM interface monitoring
 *    - WMI query blocking
 *    - Direct VSS service access
 *
 * 3. SERVICE PROTECTION
 *    - VSS service lock
 *    - Service stop prevention
 *    - Configuration protection
 *    - Startup type protection
 *
 * 4. REGISTRY PROTECTION
 *    - VSS registry keys
 *    - Shadow storage settings
 *    - Provider configurations
 *
 * 5. PROACTIVE DEFENSE
 *    - Pre-attack snapshot creation
 *    - Scheduled snapshot protection
 *    - Storage monitoring
 *    - Health verification
 *
 * @note Requires administrative privileges for service lock.
 * @note Works in conjunction with BackupProtector.
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>

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
#include "../Utils/ProcessUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class ShadowCopyProtectorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ShadowCopyConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;
    
    /// @brief Dangerous command patterns
    inline constexpr const wchar_t* DELETE_PATTERNS[] = {
        L"delete shadows",
        L"shadowcopy delete",
        L"remove-wmiobject",
        L"resize shadowstorage"
    };
}

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief VSS attack type
 */
enum class VSSAttackType : uint8_t {
    Unknown             = 0,
    CommandLineDelete   = 1,
    WMIDelete           = 2,
    APIDelete           = 3,
    ServiceStop         = 4,
    StorageResize       = 5,
    RegistryModify      = 6,
    ProviderDisable     = 7
};

/**
 * @brief Shadow copy state
 */
enum class ShadowCopyState : uint8_t {
    Unknown     = 0,
    Active      = 1,
    Protected   = 2,
    Deleted     = 3,
    Corrupted   = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Shadow copy information
 */
struct ShadowCopyInfo {
    /// @brief Shadow copy ID (GUID)
    std::wstring shadowId;
    
    /// @brief Volume name
    std::wstring volume;
    
    /// @brief Shadow copy device path
    std::wstring devicePath;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief State
    ShadowCopyState state = ShadowCopyState::Unknown;
    
    /// @brief Size in bytes
    uint64_t sizeBytes = 0;
    
    /// @brief Is protected by ShadowStrike
    bool isProtected = false;
    
    /// @brief Provider ID
    std::wstring providerId;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief VSS attack event
 */
struct VSSAttackEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Attack type
    VSSAttackType attackType = VSSAttackType::Unknown;
    
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Was blocked
    bool wasBlocked = true;
    
    /// @brief Details
    std::wstring details;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Shadow copy protector configuration
 */
struct ShadowCopyProtectorConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    /// @brief Block command line deletion
    bool blockCommandLine = true;
    
    /// @brief Block WMI deletion
    bool blockWMI = true;
    
    /// @brief Block API deletion
    bool blockAPI = true;
    
    /// @brief Lock VSS service
    bool lockService = true;
    
    /// @brief Protect storage settings
    bool protectStorage = true;
    
    /// @brief Kill attacking process
    bool killAttacker = true;
    
    /// @brief Whitelisted processes
    std::vector<std::wstring> whitelist;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Shadow copy statistics
 */
struct ShadowCopyStatistics {
    /// @brief Attacks blocked
    std::atomic<uint64_t> attacksBlocked{0};
    
    /// @brief Processes killed
    std::atomic<uint64_t> processesKilled{0};
    
    /// @brief By attack type
    std::array<std::atomic<uint64_t>, 8> byAttackType{};
    
    /// @brief Current shadow copies
    std::atomic<uint64_t> currentShadowCopies{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using VSSAttackCallback = std::function<void(const VSSAttackEvent&)>;
using DecisionCallback = std::function<bool(uint32_t pid, VSSAttackType type)>;

// ============================================================================
// SHADOW COPY PROTECTOR CLASS
// ============================================================================

/**
 * @class ShadowCopyProtector
 * @brief Enterprise-grade VSS shadow copy protection
 *
 * Protects Windows Volume Shadow Copies from unauthorized deletion.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 */
class ShadowCopyProtector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static ShadowCopyProtector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ShadowCopyProtector(const ShadowCopyProtector&) = delete;
    ShadowCopyProtector& operator=(const ShadowCopyProtector&) = delete;
    ShadowCopyProtector(ShadowCopyProtector&&) = delete;
    ShadowCopyProtector& operator=(ShadowCopyProtector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ShadowCopyProtectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DETECTION
    // ========================================================================
    
    /**
     * @brief Check if command line is VSS destruction attempt
     */
    [[nodiscard]] bool IsVssDestructionAttempt(const std::wstring& cmdLine);
    
    /**
     * @brief Check command line with detailed result
     */
    [[nodiscard]] std::optional<VSSAttackType> AnalyzeCommand(std::wstring_view cmdLine);
    
    /**
     * @brief Check if process should be blocked
     */
    [[nodiscard]] bool ShouldBlock(uint32_t pid, std::wstring_view cmdLine);
    
    // ========================================================================
    // SERVICE PROTECTION
    // ========================================================================
    
    /**
     * @brief Lock VSS service from being stopped
     */
    void LockVssService();
    
    /**
     * @brief Unlock VSS service
     */
    void UnlockVssService();
    
    /**
     * @brief Check if VSS service is locked
     */
    [[nodiscard]] bool IsVssServiceLocked() const noexcept;
    
    /**
     * @brief Check VSS service status
     */
    [[nodiscard]] bool IsVssServiceRunning() const;
    
    /**
     * @brief Start VSS service if stopped
     */
    [[nodiscard]] bool EnsureVssServiceRunning();
    
    // ========================================================================
    // SHADOW COPY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Enumerate all shadow copies
     */
    [[nodiscard]] std::vector<ShadowCopyInfo> EnumerateShadowCopies();
    
    /**
     * @brief Get shadow copy count
     */
    [[nodiscard]] size_t GetShadowCopyCount() const;
    
    /**
     * @brief Create protective snapshot
     */
    [[nodiscard]] std::optional<std::wstring> CreateProtectiveSnapshot(
        std::wstring_view volume);
    
    /**
     * @brief Verify shadow copy integrity
     */
    [[nodiscard]] bool VerifyShadowCopy(std::wstring_view shadowId);
    
    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    void AddToWhitelist(std::wstring_view processPath);
    void RemoveFromWhitelist(std::wstring_view processPath);
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processPath) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetAttackCallback(VSSAttackCallback callback);
    void SetDecisionCallback(DecisionCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ShadowCopyStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<VSSAttackEvent> GetRecentAttacks(size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ShadowCopyProtector();
    ~ShadowCopyProtector();
    
    std::unique_ptr<ShadowCopyProtectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVSSAttackTypeName(VSSAttackType type) noexcept;
[[nodiscard]] std::string_view GetShadowCopyStateName(ShadowCopyState state) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IS_VSS_ATTACK(cmd) \
    ::ShadowStrike::Ransomware::ShadowCopyProtector::Instance().IsVssDestructionAttempt(cmd)

#define SS_LOCK_VSS() \
    ::ShadowStrike::Ransomware::ShadowCopyProtector::Instance().LockVssService()
