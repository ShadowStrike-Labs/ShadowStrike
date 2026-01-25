/**
 * ============================================================================
 * ShadowStrike Ransomware Detection - WANNACRY FAMILY DETECTOR
 * ============================================================================
 *
 * @file WannaCryDetector.hpp
 * @brief Enterprise-grade specific detection module for WannaCry ransomware
 *        and its worm-like propagation mechanisms.
 *
 * WannaCry (WannaCrypt, WCry) is a notorious ransomware with worm capabilities:
 * - Exploits EternalBlue (MS17-010) for SMB propagation
 * - Kill-switch domain checking behavior
 * - Specific file drops and artifacts
 * - Unique encryption patterns (RSA-2048 + AES-128-CBC)
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. SMB EXPLOITATION
 *    - EternalBlue attack patterns
 *    - Anomalous SMB traffic
 *    - MS17-010 exploitation artifacts
 *    - DoublePulsar backdoor detection
 *
 * 2. KILL-SWITCH BEHAVIOR
 *    - Known kill-switch domain queries
 *    - DNS sinkhole patterns
 *    - Connection attempt monitoring
 *
 * 3. FILE ARTIFACTS
 *    - tasksche.exe dropper
 *    - @WanaDecryptor@.exe
 *    - @Please_Read_Me@.txt
 *    - .WNCRY file extension
 *    - c.wnry, r.wnry, s.wnry, t.wnry, u.wnry files
 *
 * 4. BEHAVIORAL PATTERNS
 *    - Service creation (mssecsvc2.0)
 *    - Scheduled task creation
 *    - Wallpaper modification
 *    - Tor client installation
 *
 * 5. NETWORK PROPAGATION
 *    - Internal network scanning
 *    - SMB port probing (445)
 *    - Rapid lateral movement
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
#include <unordered_set>

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
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class WannaCryDetectorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace WannaCryConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;
    
    /// @brief WannaCry file extension
    inline constexpr const wchar_t* WNCRY_EXTENSION = L".WNCRY";
    
    /// @brief WannaCry support files
    inline constexpr const wchar_t* SUPPORT_FILES[] = {
        L"c.wnry", L"r.wnry", L"s.wnry", L"t.wnry", L"u.wnry",
        L"msg\\", L"TaskData\\", L"@WanaDecryptor@.exe"
    };
    
    /// @brief Known kill-switch domains (historical)
    inline constexpr const char* KNOWN_KILL_SWITCHES[] = {
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    };
    
    /// @brief SMB port
    inline constexpr uint16_t SMB_PORT = 445;
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
 * @brief WannaCry variant
 */
enum class WannaCryVariant : uint8_t {
    Unknown         = 0,
    WannaCry1       = 1,    ///< Original version
    WannaCry2       = 2,    ///< Updated version
    WannaCryNoKill  = 3,    ///< Kill-switch removed variant
    WannaCryMod     = 4     ///< Modified variant
};

/**
 * @brief Attack phase
 */
enum class WannaCryPhase : uint8_t {
    Unknown         = 0,
    InitialDrop     = 1,    ///< Initial dropper execution
    KillSwitchCheck = 2,    ///< Kill-switch domain check
    ServiceCreation = 3,    ///< mssecsvc2.0 service
    Propagation     = 4,    ///< SMB worm activity
    Encryption      = 5,    ///< File encryption
    RansomDisplay   = 6     ///< Ransom note display
};

/**
 * @brief Detection confidence
 */
enum class DetectionConfidence : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Confirmed   = 4
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
 * @brief WannaCry detection result
 */
struct WannaCryDetectionResult {
    /// @brief Is WannaCry detected
    bool detected = false;
    
    /// @brief Variant identified
    WannaCryVariant variant = WannaCryVariant::Unknown;
    
    /// @brief Current phase
    WannaCryPhase phase = WannaCryPhase::Unknown;
    
    /// @brief Confidence level
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Indicators found
    std::vector<std::string> indicators;
    
    /// @brief Artifacts found
    std::vector<std::wstring> artifactsFound;
    
    /// @brief Kill-switch domain queried
    bool killSwitchQueried = false;
    
    /// @brief Kill-switch domain
    std::string killSwitchDomain;
    
    /// @brief SMB exploitation detected
    bool smbExploitDetected = false;
    
    /// @brief Hosts scanned
    uint32_t hostsScanned = 0;
    
    /// @brief Hosts infected
    uint32_t hostsInfected = 0;
    
    /// @brief Files encrypted
    uint32_t filesEncrypted = 0;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief EternalBlue indicator
 */
struct EternalBlueIndicator {
    /// @brief Source IP
    std::string sourceIP;
    
    /// @brief Destination IP
    std::string destIP;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Packet signature matched
    bool signatureMatched = false;
    
    /// @brief Exploit stage
    uint8_t exploitStage = 0;
    
    /// @brief Was blocked
    bool wasBlocked = false;
};

/**
 * @brief WannaCry detector configuration
 */
struct WannaCryDetectorConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Monitor SMB traffic
    bool monitorSMB = true;
    
    /// @brief Monitor kill-switch DNS
    bool monitorKillSwitch = true;
    
    /// @brief Monitor file artifacts
    bool monitorArtifacts = true;
    
    /// @brief Monitor network propagation
    bool monitorPropagation = true;
    
    /// @brief Minimum confidence for alert
    DetectionConfidence minAlertConfidence = DetectionConfidence::Medium;
    
    /// @brief Auto-terminate on detection
    bool autoTerminate = true;
    
    /// @brief Block SMB exploitation attempts
    bool blockSMBExploit = true;
    
    /// @brief Network isolation on detection
    bool networkIsolation = false;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief WannaCry detection statistics
 */
struct WannaCryStatistics {
    /// @brief Total detections
    std::atomic<uint64_t> totalDetections{0};
    
    /// @brief By variant
    std::array<std::atomic<uint64_t>, 8> byVariant{};
    
    /// @brief SMB exploits blocked
    std::atomic<uint64_t> smbExploitsBlocked{0};
    
    /// @brief Kill-switch queries detected
    std::atomic<uint64_t> killSwitchQueries{0};
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{0};
    
    /// @brief Hosts protected
    std::atomic<uint64_t> hostsProtected{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using WannaCryDetectionCallback = std::function<void(const WannaCryDetectionResult&)>;
using EternalBlueCallback = std::function<void(const EternalBlueIndicator&)>;

// ============================================================================
// WANNACRY DETECTOR CLASS
// ============================================================================

/**
 * @class WannaCryDetector
 * @brief Specialized detector for WannaCry ransomware worm
 *
 * Provides targeted detection for WannaCry and its propagation.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 */
class WannaCryDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static WannaCryDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    WannaCryDetector(const WannaCryDetector&) = delete;
    WannaCryDetector& operator=(const WannaCryDetector&) = delete;
    WannaCryDetector(WannaCryDetector&&) = delete;
    WannaCryDetector& operator=(WannaCryDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const WannaCryDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DETECTION
    // ========================================================================
    
    /**
     * @brief Check for WannaCry artifacts in process
     */
    [[nodiscard]] bool Detect(uint32_t pid);
    
    /**
     * @brief Full detection with result
     */
    [[nodiscard]] WannaCryDetectionResult DetectEx(uint32_t pid);
    
    /**
     * @brief Check if file is WannaCry artifact
     */
    [[nodiscard]] bool IsWannaCryArtifact(std::wstring_view filePath) const;
    
    /**
     * @brief Check if domain is WannaCry kill-switch
     */
    [[nodiscard]] bool IsKillSwitchDomain(std::string_view domain) const;
    
    /**
     * @brief Analyze SMB traffic for EternalBlue
     */
    [[nodiscard]] bool AnalyzeSMBTraffic(std::span<const uint8_t> packet,
                                         std::string_view sourceIP,
                                         std::string_view destIP);
    
    /**
     * @brief Check file hash against known WannaCry samples
     */
    [[nodiscard]] bool CheckKnownHash(const Hash256& hash) const;
    
    /**
     * @brief Scan directory for WannaCry artifacts
     */
    [[nodiscard]] std::vector<std::wstring> ScanForArtifacts(std::wstring_view directory);
    
    // ========================================================================
    // VULNERABILITY CHECK
    // ========================================================================
    
    /**
     * @brief Check if system is vulnerable to EternalBlue
     */
    [[nodiscard]] bool IsSystemVulnerable() const;
    
    /**
     * @brief Check if MS17-010 patch is installed
     */
    [[nodiscard]] bool IsPatchInstalled() const;
    
    /**
     * @brief Get SMB version info
     */
    [[nodiscard]] std::string GetSMBVersionInfo() const;
    
    // ========================================================================
    // PATTERN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add known kill-switch domain
     */
    void AddKillSwitchDomain(std::string_view domain);
    
    /**
     * @brief Add known WannaCry hash
     */
    void AddKnownHash(const Hash256& hash);
    
    /**
     * @brief Update patterns from threat intel
     */
    void UpdatePatternsFromThreatIntel();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetDetectionCallback(WannaCryDetectionCallback callback);
    void SetEternalBlueCallback(EternalBlueCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] WannaCryStatistics GetStatistics() const;
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    WannaCryDetector();
    ~WannaCryDetector();
    
    std::unique_ptr<WannaCryDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetWannaCryVariantName(WannaCryVariant variant) noexcept;
[[nodiscard]] std::string_view GetWannaCryPhaseName(WannaCryPhase phase) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DETECT_WANNACRY(pid) \
    ::ShadowStrike::Ransomware::WannaCryDetector::Instance().Detect(pid)

#define SS_IS_VULNERABLE_TO_ETERNALBLUE() \
    ::ShadowStrike::Ransomware::WannaCryDetector::Instance().IsSystemVulnerable()
