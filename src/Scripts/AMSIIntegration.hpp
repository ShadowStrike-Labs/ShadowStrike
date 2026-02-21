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
 * ShadowStrike NGAV - AMSI INTEGRATION MODULE
 * ============================================================================
 *
 * @file AMSIIntegration.hpp
 * @brief Enterprise-grade Windows Antimalware Scan Interface (AMSI) integration
 *        providing bidirectional malware scanning and bypass detection.
 *
 * Provides comprehensive AMSI capabilities including provider registration,
 * content scanning, bypass detection, and integrity validation.
 *
 * CAPABILITIES:
 * =============
 *
 * 1. AMSI PROVIDER REGISTRATION
 *    - Custom provider registration
 *    - Provider priority management
 *    - Session handling
 *    - Multi-instance support
 *
 * 2. CONTENT SCANNING
 *    - Script content scanning
 *    - Binary content scanning
 *    - URL/network content scanning
 *    - Memory buffer scanning
 *    - Session-aware scanning
 *
 * 3. BYPASS DETECTION
 *    - AmsiScanBuffer patching
 *    - AmsiInitialize tampering
 *    - CLR hooking detection
 *    - Reflection-based bypass
 *    - Memory patching detection
 *    - ETW bypass correlation
 *
 * 4. INTEGRITY VALIDATION
 *    - amsi.dll integrity check
 *    - Function prologue validation
 *    - IAT hook detection
 *    - In-memory modification tracking
 *    - Real-time integrity monitoring
 *
 * 5. BYPASS REPAIR
 *    - Automatic function restoration
 *    - Memory protection reset
 *    - Module reloading
 *    - Process remediation
 *
 * 6. INTEGRATION POINTS
 *    - PowerShell integration
 *    - Windows Script Host (WSH)
 *    - Office VBA
 *    - .NET CLR
 *    - Third-party applications
 *
 * INTEGRATION:
 * ============
 * - Utils::MemoryUtils for memory operations
 * - Utils::ProcessUtils for process monitoring
 * - ThreatIntel for bypass signature correlation
 *
 * @note Requires Windows 10+ for full AMSI support.
 * @note Provider registration requires elevation.
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
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
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Scripts {
    class AMSIIntegrationImpl;
}

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AMSIConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum content size for scanning
    inline constexpr size_t MAX_SCAN_CONTENT_SIZE = 64 * 1024 * 1024;  // 64MB
    
    /// @brief Maximum sessions to track
    inline constexpr size_t MAX_SESSIONS = 4096;
    
    /// @brief Integrity check interval (ms)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 5000;
    
    /// @brief AMSI function bytes to verify (AmsiScanBuffer prologue)
    inline constexpr size_t AMSI_PROLOGUE_SIZE = 16;
    
    /// @brief Provider name
    inline constexpr const wchar_t* PROVIDER_NAME = L"ShadowStrike AMSI Provider";
    
    /// @brief Provider GUID (example)
    inline constexpr const wchar_t* PROVIDER_GUID = L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";

}  // namespace AMSIConstants

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
 * @brief AMSI scan result
 */
enum class AmsiResult : uint32_t {
    Clean               = 0,        ///< Content is clean
    NotDetected         = 1,        ///< Not detected as malware
    BlockedByAdminStart = 0x4000,   ///< Blocked by admin (range start)
    BlockedByAdminEnd   = 0x4FFF,   ///< Blocked by admin (range end)
    Detected            = 0x8000,   ///< Malware detected
    Unknown             = 0xFFFF    ///< Unknown/error
};

/**
 * @brief Content type being scanned
 */
enum class AmsiContentType : uint8_t {
    Unknown         = 0,
    PowerShell      = 1,    ///< PowerShell script
    VBScript        = 2,    ///< VBScript
    JScript         = 3,    ///< JScript/JavaScript
    Macro           = 4,    ///< Office macro
    DotNetCLR       = 5,    ///< .NET assembly
    Binary          = 6,    ///< Binary content
    URL             = 7,    ///< URL content
    Custom          = 8     ///< Custom application
};

/**
 * @brief AMSI bypass technique
 */
enum class AmsiBypassTechnique : uint32_t {
    Unknown                     = 0,
    AmsiScanBufferPatch         = 1 << 0,   ///< Patching AmsiScanBuffer
    AmsiInitializePatch         = 1 << 1,   ///< Patching AmsiInitialize
    AmsiOpenSessionPatch        = 1 << 2,   ///< Patching AmsiOpenSession
    AmsiContextCorruption       = 1 << 3,   ///< Context structure corruption
    ReflectionBypass            = 1 << 4,   ///< .NET reflection bypass
    CLRHooking                  = 1 << 5,   ///< CLR method hooking
    DLLUnload                   = 1 << 6,   ///< amsi.dll unload attempt
    DLLHijacking                = 1 << 7,   ///< amsi.dll hijacking
    MemoryProtectionChange      = 1 << 8,   ///< VirtualProtect on AMSI
    IATHooking                  = 1 << 9,   ///< Import address table hook
    InlineHooking               = 1 << 10,  ///< Inline function hooking
    TramplineBypass             = 1 << 11,  ///< Trampoline bypass
    ETWBlinding                 = 1 << 12,  ///< ETW disable for AMSI evasion
    AmsiProviderBypass          = 1 << 13,  ///< Provider registry manipulation
    ForceError                  = 1 << 14   ///< Force AMSI initialization error
};

/**
 * @brief Integrity status
 */
enum class AmsiIntegrityStatus : uint8_t {
    Unknown         = 0,
    Intact          = 1,    ///< AMSI is intact
    Tampered        = 2,    ///< AMSI has been tampered
    Missing         = 3,    ///< amsi.dll not loaded
    Corrupted       = 4,    ///< AMSI context corrupted
    Repaired        = 5     ///< AMSI was repaired
};

/**
 * @brief Provider registration status
 */
enum class ProviderStatus : uint8_t {
    Unregistered    = 0,
    Registered      = 1,
    Active          = 2,
    Failed          = 3,
    Disabled        = 4
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
 * @brief AMSI session information
 */
struct AmsiSessionInfo {
    /// @brief Session ID
    uint64_t sessionId = 0;
    
    /// @brief Session handle (HAMSISSESSION)
    uint64_t sessionHandle = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Application name
    std::wstring applicationName;
    
    /// @brief Content type
    AmsiContentType contentType = AmsiContentType::Unknown;
    
    /// @brief Scan count in session
    uint32_t scanCount = 0;
    
    /// @brief Detection count in session
    uint32_t detectionCount = 0;
    
    /// @brief Session start time
    SystemTimePoint startTime;
    
    /// @brief Last activity time
    SystemTimePoint lastActivityTime;
    
    /// @brief Is session active
    bool isActive = true;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief AMSI scan request
 */
struct AmsiScanRequest {
    /// @brief Content buffer
    std::span<const uint8_t> content;
    
    /// @brief Content name/description
    std::wstring contentName;
    
    /// @brief Content type
    AmsiContentType contentType = AmsiContentType::Unknown;
    
    /// @brief Session ID (0 for no session)
    uint64_t sessionId = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Scan timeout (ms)
    uint32_t timeoutMs = 5000;
    
    /// @brief Return deobfuscated content
    bool returnDeobfuscated = false;
};

/**
 * @brief AMSI scan response
 */
struct AmsiScanResponse {
    /// @brief Scan result
    AmsiResult result = AmsiResult::Unknown;
    
    /// @brief Is content malicious
    bool isMalicious = false;
    
    /// @brief Threat name (if detected)
    std::string threatName;
    
    /// @brief Risk score (0-100)
    double riskScore = 0.0;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Deobfuscated content (if requested)
    std::vector<uint8_t> deobfuscatedContent;
    
    /// @brief Content hash
    std::string contentHash;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /// @brief Scan timestamp
    SystemTimePoint timestamp;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief AMSI bypass event
 */
struct AmsiBypassEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Bypass techniques detected
    AmsiBypassTechnique techniques = AmsiBypassTechnique::Unknown;
    
    /// @brief Target function
    std::string targetFunction;
    
    /// @brief Target address
    uint64_t targetAddress = 0;
    
    /// @brief Original bytes
    std::vector<uint8_t> originalBytes;
    
    /// @brief Patched bytes
    std::vector<uint8_t> patchedBytes;
    
    /// @brief Was repaired
    bool wasRepaired = false;
    
    /// @brief Repair successful
    bool repairSuccessful = false;
    
    /// @brief Additional details
    std::string details;
    
    /// @brief Detection timestamp
    SystemTimePoint timestamp;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief AMSI integrity report
 */
struct AmsiIntegrityReport {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Integrity status
    AmsiIntegrityStatus status = AmsiIntegrityStatus::Unknown;
    
    /// @brief amsi.dll base address
    uint64_t amsiDllBase = 0;
    
    /// @brief amsi.dll size
    size_t amsiDllSize = 0;
    
    /// @brief amsi.dll hash
    std::string amsiDllHash;
    
    /// @brief Expected hash
    std::string expectedHash;
    
    /// @brief Function states
    struct FunctionState {
        std::string functionName;
        uint64_t address = 0;
        bool isIntact = true;
        std::vector<uint8_t> currentPrologue;
        std::vector<uint8_t> expectedPrologue;
    };
    std::vector<FunctionState> functionStates;
    
    /// @brief Bypass techniques detected
    AmsiBypassTechnique detectedBypasses = AmsiBypassTechnique::Unknown;
    
    /// @brief Report timestamp
    SystemTimePoint timestamp;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct AMSIStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> cleanResults{0};
    std::atomic<uint64_t> sessionsCreated{0};
    std::atomic<uint64_t> bypassAttemptsDetected{0};
    std::atomic<uint64_t> bypassesRepaired{0};
    std::atomic<uint64_t> integrityChecks{0};
    std::atomic<uint64_t> integrityFailures{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byContentType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct AMSIConfiguration {
    /// @brief Enable AMSI provider
    bool enableProvider = true;
    
    /// @brief Enable bypass detection
    bool enableBypassDetection = true;
    
    /// @brief Enable automatic repair
    bool enableAutoRepair = true;
    
    /// @brief Enable integrity monitoring
    bool enableIntegrityMonitoring = true;
    
    /// @brief Integrity check interval (ms)
    uint32_t integrityCheckIntervalMs = AMSIConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Block on bypass detection
    bool blockOnBypassDetection = true;
    
    /// @brief Terminate process on repeated bypass
    bool terminateOnRepeatedBypass = false;
    
    /// @brief Maximum content size (bytes)
    size_t maxContentSize = AMSIConstants::MAX_SCAN_CONTENT_SIZE;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanCallback = std::function<void(const AmsiScanResponse&)>;
using BypassCallback = std::function<void(const AmsiBypassEvent&)>;
using IntegrityCallback = std::function<void(uint32_t processId, AmsiIntegrityStatus)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// AMSI INTEGRATION CLASS
// ============================================================================

/**
 * @class AMSIIntegration
 * @brief Enterprise-grade AMSI integration and bypass protection
 */
class AMSIIntegration final {
public:
    [[nodiscard]] static AMSIIntegration& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    AMSIIntegration(const AMSIIntegration&) = delete;
    AMSIIntegration& operator=(const AMSIIntegration&) = delete;
    AMSIIntegration(AMSIIntegration&&) = delete;
    AMSIIntegration& operator=(AMSIIntegration&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const AMSIConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const AMSIConfiguration& config);
    [[nodiscard]] AMSIConfiguration GetConfiguration() const;

    // ========================================================================
    // PROVIDER MANAGEMENT
    // ========================================================================
    
    /// @brief Register ShadowStrike as AMSI provider
    [[nodiscard]] bool RegisterProvider();
    
    /// @brief Unregister AMSI provider
    [[nodiscard]] bool UnregisterProvider();
    
    /// @brief Get provider status
    [[nodiscard]] ProviderStatus GetProviderStatus() const noexcept;
    
    /// @brief Check if provider is registered
    [[nodiscard]] bool IsProviderRegistered() const noexcept;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan content buffer
    [[nodiscard]] AmsiScanResponse ScanBuffer(const AmsiScanRequest& request);
    
    /// @brief Scan content buffer (simplified)
    [[nodiscard]] AmsiResult ScanBuffer(
        std::span<const uint8_t> buffer,
        std::wstring_view contentName,
        uint64_t sessionId = 0);
    
    /// @brief Scan string content
    [[nodiscard]] AmsiResult ScanString(
        std::wstring_view content,
        std::wstring_view contentName,
        AmsiContentType type = AmsiContentType::Unknown);
    
    /// @brief Scan using system AMSI chain
    [[nodiscard]] AmsiResult ScanWithSystemAMSI(
        std::span<const uint8_t> buffer,
        std::wstring_view contentName);

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================
    
    /// @brief Open AMSI session
    [[nodiscard]] uint64_t OpenSession(
        std::wstring_view applicationName,
        uint32_t processId = 0);
    
    /// @brief Close AMSI session
    void CloseSession(uint64_t sessionId);
    
    /// @brief Get session info
    [[nodiscard]] std::optional<AmsiSessionInfo> GetSessionInfo(uint64_t sessionId) const;
    
    /// @brief Get active sessions
    [[nodiscard]] std::vector<AmsiSessionInfo> GetActiveSessions() const;

    // ========================================================================
    // INTEGRITY & BYPASS DETECTION
    // ========================================================================
    
    /// @brief Check AMSI integrity in process
    [[nodiscard]] AmsiIntegrityReport CheckIntegrity(uint32_t processId);
    
    /// @brief Check AMSI integrity in current process
    [[nodiscard]] AmsiIntegrityReport CheckIntegrity();
    
    /// @brief Repair tampered AMSI in process
    [[nodiscard]] bool RepairIntegrity(uint32_t processId);
    
    /// @brief Repair tampered AMSI in current process
    [[nodiscard]] bool RepairIntegrity();
    
    /// @brief Start integrity monitoring for process
    [[nodiscard]] bool StartIntegrityMonitoring(uint32_t processId);
    
    /// @brief Stop integrity monitoring for process
    void StopIntegrityMonitoring(uint32_t processId);
    
    /// @brief Check if bypass is detected
    [[nodiscard]] bool IsAmsiBypassDetected(uint32_t processId) const;
    
    /// @brief Get detected bypass techniques
    [[nodiscard]] AmsiBypassTechnique GetDetectedBypasses(uint32_t processId) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(ScanCallback callback);
    void RegisterBypassCallback(BypassCallback callback);
    void RegisterIntegrityCallback(IntegrityCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] AMSIStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<AmsiBypassEvent> GetRecentBypassEvents(size_t maxCount = 100) const;
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    AMSIIntegration();
    ~AMSIIntegration();
    
    std::unique_ptr<AMSIIntegrationImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAmsiResultName(AmsiResult result) noexcept;
[[nodiscard]] std::string_view GetAmsiContentTypeName(AmsiContentType type) noexcept;
[[nodiscard]] std::string_view GetAmsiBypassTechniqueName(AmsiBypassTechnique tech) noexcept;
[[nodiscard]] std::string_view GetAmsiIntegrityStatusName(AmsiIntegrityStatus status) noexcept;
[[nodiscard]] bool IsAmsiResultMalicious(AmsiResult result) noexcept;

}  // namespace Scripts
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_AMSI_SCAN(buffer, name) \
    ::ShadowStrike::Scripts::AMSIIntegration::Instance().ScanBuffer(buffer, name)

#define SS_AMSI_CHECK_INTEGRITY(pid) \
    ::ShadowStrike::Scripts::AMSIIntegration::Instance().CheckIntegrity(pid)

#define SS_AMSI_REPAIR(pid) \
    ::ShadowStrike::Scripts::AMSIIntegration::Instance().RepairIntegrity(pid)