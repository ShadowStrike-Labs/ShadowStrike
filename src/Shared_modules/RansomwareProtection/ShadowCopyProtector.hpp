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
 * ShadowStrike Ransomware Protection - SHADOW COPY PROTECTOR
 * ============================================================================
 *
 * @file ShadowCopyProtector.hpp
 * @brief Enterprise-grade VSS shadow copy protection preventing unauthorized
 *        deletion or modification of Windows Volume Shadow Copies.
 *
 * This module provides comprehensive protection for VSS shadow copies against
 * ransomware attempting to destroy backup recovery options through various
 * attack vectors including living-off-the-land binaries, direct COM calls,
 * obfuscated PowerShell, and WMI-based deletion.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. COMMAND LINE DETECTION (with obfuscation bypass)
 *    - vssadmin delete shadows (caret/env-var/quoting bypass resistant)
 *    - vssadmin resize shadowstorage
 *    - wmic shadowcopy delete
 *    - PowerShell shadow deletion (base64 -EncodedCommand detection)
 *    - diskshadow script commands
 *    - bcdedit recovery disable
 *    - wbadmin catalog/backup deletion
 *
 * 2. KERNEL PROCESS CREATION BLOCKING
 *    - PhantomSensor PsSetCreateProcessNotifyRoutineEx integration
 *    - Pre-execution blocking via process creation verdict
 *    - Command line analysis before process starts
 *
 * 3. SERVICE PROTECTION
 *    - VSS service startup type enforcement (auto-start)
 *    - Service status monitoring with auto-restart
 *    - Configuration change detection
 *
 * 4. SNAPSHOT INVENTORY MONITORING
 *    - Continuous shadow copy count tracking
 *    - Decrease detection triggers immediate alert
 *    - Proactive snapshot creation on attack detection
 *
 * 5. PROACTIVE DEFENSE
 *    - Pre-attack snapshot creation
 *    - Scheduled snapshot health verification
 *    - Storage monitoring
 *
 * @note Requires administrative privileges for service management.
 * @note Works in conjunction with BackupProtector and VolumeSnapshotService.
 * @note Kernel process blocking requires PhantomSensor driver loaded.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
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
#include <shared_mutex>

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
    inline constexpr uint32_t VERSION_MINOR = 1;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Monitoring interval (ms) for shadow copy inventory checks
    inline constexpr uint32_t MONITORING_INTERVAL_MS = 2000;

    /// @brief Maximum recent attacks to retain in memory
    inline constexpr size_t MAX_RECENT_ATTACKS = 500;

    /// @brief Maximum whitelist entries (prevent unbounded growth)
    inline constexpr size_t MAX_WHITELIST_ENTRIES = 256;
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
 * @brief VSS attack vector classification
 */
enum class VSSAttackType : uint8_t {
    Unknown             = 0,
    CommandLineDelete   = 1,  ///< vssadmin/diskshadow/wbadmin delete
    WMIDelete           = 2,  ///< wmic/PowerShell WMI shadow deletion
    APIDelete           = 3,  ///< Direct IVssBackupComponents::DeleteSnapshots COM call
    ServiceStop         = 4,  ///< VSS service stop/disable attempt
    StorageResize       = 5,  ///< vssadmin resize shadowstorage (shrink attack)
    RegistryModify      = 6,  ///< bcdedit recovery disable / VSS registry tampering
    ProviderDisable     = 7   ///< VSS provider disable/unregister
};

/**
 * @brief Process creation verdict for kernel callback integration
 *
 * Returned by OnProcessCreation() to tell the kernel driver whether
 * to allow or deny the process from starting.
 */
enum class ProcessCreationVerdict : uint8_t {
    Allow   = 0,  ///< Process is safe, allow execution
    Block   = 1,  ///< VSS attack detected, deny execution at kernel level
    Monitor = 2   ///< Suspicious but not conclusive, allow with enhanced monitoring
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
    
    /// @brief Whitelisted processes (full paths, case-insensitive match)
    std::vector<std::wstring> whitelist;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Shadow copy statistics (thread-safe, copyable)
 *
 * Contains atomic counters for lock-free updates from multiple threads.
 * Custom copy operations load atomics safely.
 */
struct ShadowCopyStatistics {
    /// @brief Attacks blocked
    std::atomic<uint64_t> attacksBlocked{0};
    
    /// @brief Processes killed
    std::atomic<uint64_t> processesKilled{0};
    
    /// @brief Processes blocked at kernel level (pre-execution)
    std::atomic<uint64_t> processesBlockedKernel{0};
    
    /// @brief Snapshot count decreases detected
    std::atomic<uint64_t> snapshotDecreaseAlerts{0};
    
    /// @brief By attack type
    std::array<std::atomic<uint64_t>, 8> byAttackType{};
    
    /// @brief Current shadow copies
    std::atomic<uint64_t> currentShadowCopies{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();

    ShadowCopyStatistics() noexcept = default;

    ShadowCopyStatistics(const ShadowCopyStatistics& other) noexcept
        : attacksBlocked(other.attacksBlocked.load(std::memory_order_relaxed))
        , processesKilled(other.processesKilled.load(std::memory_order_relaxed))
        , processesBlockedKernel(other.processesBlockedKernel.load(std::memory_order_relaxed))
        , snapshotDecreaseAlerts(other.snapshotDecreaseAlerts.load(std::memory_order_relaxed))
        , currentShadowCopies(other.currentShadowCopies.load(std::memory_order_relaxed))
        , startTime(other.startTime) {
        for (size_t i = 0; i < byAttackType.size(); ++i) {
            byAttackType[i].store(other.byAttackType[i].load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
        }
    }

    ShadowCopyStatistics& operator=(const ShadowCopyStatistics& other) noexcept {
        if (this != &other) {
            attacksBlocked.store(other.attacksBlocked.load(std::memory_order_relaxed),
                                std::memory_order_relaxed);
            processesKilled.store(other.processesKilled.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
            processesBlockedKernel.store(other.processesBlockedKernel.load(std::memory_order_relaxed),
                                         std::memory_order_relaxed);
            snapshotDecreaseAlerts.store(other.snapshotDecreaseAlerts.load(std::memory_order_relaxed),
                                         std::memory_order_relaxed);
            currentShadowCopies.store(other.currentShadowCopies.load(std::memory_order_relaxed),
                                      std::memory_order_relaxed);
            startTime = other.startTime;
            for (size_t i = 0; i < byAttackType.size(); ++i) {
                byAttackType[i].store(other.byAttackType[i].load(std::memory_order_relaxed),
                                      std::memory_order_relaxed);
            }
        }
        return *this;
    }
    
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
 * Protects Windows Volume Shadow Copies from unauthorized deletion
 * through command-line monitoring, obfuscation detection, kernel
 * process creation blocking, service protection, and snapshot
 * inventory monitoring.
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
     * @brief Check if process should be blocked (user-mode, post-creation)
     */
    [[nodiscard]] bool ShouldBlock(uint32_t pid, std::wstring_view cmdLine);

    // ========================================================================
    // KERNEL PROCESS CREATION INTEGRATION
    // ========================================================================

    /**
     * @brief Kernel process creation callback handler
     *
     * Called by the user-mode message dispatcher when PhantomSensor's
     * PsSetCreateProcessNotifyRoutineEx callback fires. This enables
     * PRE-EXECUTION blocking of vssadmin.exe, wmic.exe, PowerShell,
     * bcdedit.exe, and diskshadow.exe before they can delete shadow copies.
     *
     * @param pid          Process ID of the new process
     * @param parentPid    Parent process ID
     * @param imagePath    Full NT image path of the executable
     * @param commandLine  Full command line of the process
     * @return Verdict: Allow, Block, or Monitor
     *
     * @note This runs in the hot path of process creation — must be fast (<1ms).
     */
    [[nodiscard]] ProcessCreationVerdict OnProcessCreation(
        uint32_t pid,
        uint32_t parentPid,
        std::wstring_view imagePath,
        std::wstring_view commandLine);
    
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
