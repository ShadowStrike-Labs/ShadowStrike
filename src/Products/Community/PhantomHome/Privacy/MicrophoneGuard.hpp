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
 * ShadowStrike NGAV - MICROPHONE GUARD MODULE
 * ============================================================================
 *
 * @file MicrophoneGuard.hpp
 * @brief Enterprise-grade microphone access control and audio eavesdropping
 *        prevention with application whitelisting and hardware control.
 *
 * Provides comprehensive microphone privacy protection including unauthorized
 * access detection, audio stream monitoring, and process-level control.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. AUDIO STREAM MONITORING
 *    - WASAPI stream detection
 *    - WaveIn monitoring
 *    - DirectSound capture
 *    - OpenAL capture
 *    - Real-time notifications
 *
 * 2. ACCESS CONTROL
 *    - Process whitelist
 *    - Per-app permissions
 *    - Time-based access
 *    - User-based access
 *    - Signature verification
 *
 * 3. ENFORCEMENT
 *    - Stream interception
 *    - Forced muting
 *    - Process termination
 *    - Hardware disable
 *    - Volume override
 *
 * 4. PROTECTION MODES
 *    - Full block (all mics)
 *    - Whitelist only
 *    - Prompt mode
 *    - Silent logging
 *    - Schedule-based
 *
 * 5. SPYWARE DETECTION
 *    - RAT audio capture
 *    - Hidden recording detection
 *    - Suspicious patterns
 *    - Background recording alerts
 *
 * AUDIO APIS MONITORED:
 * =====================
 * - Windows Audio Session API (WASAPI)
 * - WaveIn/WaveOut legacy API
 * - DirectSound
 * - OpenAL
 * - Media Foundation
 * - Core Audio endpoints
 *
 * @note Requires audio driver integration for hardware control.
 * @note Thread-safe singleton design.
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
#include <unordered_set>
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
#include "../Utils/SystemUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class MicrophoneGuardImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MicrophoneConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum devices to monitor
    inline constexpr size_t MAX_DEVICES = 32;
    
    /// @brief Maximum whitelist entries
    inline constexpr size_t MAX_WHITELIST = 256;
    
    /// @brief Polling interval for stream monitoring
    inline constexpr uint32_t POLLING_INTERVAL_MS = 500;
    
    /// @brief Default trusted applications
    inline constexpr const char* DEFAULT_TRUSTED_APPS[] = {
        "Zoom.exe",
        "Teams.exe",
        "Skype.exe",
        "Discord.exe",
        "Slack.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe"
    };

}  // namespace MicrophoneConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Protection mode
 */
enum class MicrophoneProtectionMode : uint8_t {
    Disabled        = 0,    ///< No protection
    Monitor         = 1,    ///< Log only
    Prompt          = 2,    ///< Ask user on access
    WhitelistOnly   = 3,    ///< Only whitelist apps
    BlockAll        = 4     ///< Block all access
};

/**
 * @brief Audio access decision
 */
enum class AudioAccessDecision : uint8_t {
    Allow           = 0,    ///< Allow access
    Block           = 1,    ///< Block access
    Mute            = 2,    ///< Allow but inject silence
    Prompt          = 3,    ///< Prompt user
    AllowOnce       = 4,    ///< Allow this time only
    AllowTimed      = 5     ///< Allow for limited time
};

/**
 * @brief Audio device type
 */
enum class AudioDeviceType : uint8_t {
    Unknown         = 0,
    IntegratedMic   = 1,    ///< Built-in microphone
    ExternalUSB     = 2,    ///< USB microphone
    Headset         = 3,    ///< Headset microphone
    WebcamMic       = 4,    ///< Webcam integrated mic
    Virtual         = 5,    ///< Virtual audio device
    Bluetooth       = 6,    ///< Bluetooth mic
    ArrayMic        = 7     ///< Microphone array
};

/**
 * @brief Audio capture API
 */
enum class AudioCaptureAPI : uint8_t {
    Unknown         = 0,
    WASAPI          = 1,    ///< Windows Audio Session API
    WaveIn          = 2,    ///< Legacy waveIn
    DirectSound     = 3,    ///< DirectSound capture
    OpenAL          = 4,    ///< OpenAL
    MediaFoundation = 5,    ///< Media Foundation
    CoreAudio       = 6     ///< Core Audio
};

/**
 * @brief Access reason
 */
enum class AudioAccessReason : uint8_t {
    Unknown         = 0,
    VoiceCall       = 1,
    VoiceRecording  = 2,
    VoiceAssistant  = 3,
    Dictation       = 4,
    Streaming       = 5,
    Gaming          = 6,
    Malware         = 7,
    SuspiciousRAT   = 8
};

/**
 * @brief Risk level
 */
enum class AudioRiskLevel : uint8_t {
    Safe            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Audio device info
 */
struct AudioDevice {
    /// @brief Device ID
    std::string deviceId;
    
    /// @brief Endpoint ID
    std::string endpointId;
    
    /// @brief Friendly name
    std::string friendlyName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Device type
    AudioDeviceType type = AudioDeviceType::Unknown;
    
    /// @brief Is default device
    bool isDefault = false;
    
    /// @brief Is currently active
    bool isActive = false;
    
    /// @brief Is muted
    bool isMuted = false;
    
    /// @brief Is blocked
    bool isBlocked = false;
    
    /// @brief Current volume (0-100)
    int currentVolume = 100;
    
    /// @brief Sample rate
    uint32_t sampleRate = 0;
    
    /// @brief Channel count
    uint32_t channels = 0;
    
    /// @brief Bits per sample
    uint32_t bitsPerSample = 0;
    
    /// @brief Last access time
    SystemTimePoint lastAccess;
    
    /// @brief Total access count
    uint64_t accessCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Audio stream info
 */
struct AudioStreamInfo {
    /// @brief Stream ID
    uint64_t streamId = 0;
    
    /// @brief Device being used
    std::string deviceId;
    
    /// @brief API being used
    AudioCaptureAPI api = AudioCaptureAPI::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Process path
    fs::path processPath;
    
    /// @brief Stream state
    bool isCapturing = false;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief Duration
    std::chrono::seconds duration{0};
    
    /// @brief Bytes captured
    uint64_t bytesCaptured = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Audio access event
 */
struct AudioAccessEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Device being accessed
    std::string deviceId;
    
    /// @brief Capture API
    AudioCaptureAPI api = AudioCaptureAPI::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Process path
    fs::path processPath;
    
    /// @brief Is process signed
    bool isSigned = false;
    
    /// @brief Publisher
    std::string publisher;
    
    /// @brief User name
    std::string userName;
    
    /// @brief Access reason
    AudioAccessReason reason = AudioAccessReason::Unknown;
    
    /// @brief Risk level
    AudioRiskLevel riskLevel = AudioRiskLevel::Safe;
    
    /// @brief Decision made
    AudioAccessDecision decision = AudioAccessDecision::Allow;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Duration (if ended)
    std::chrono::seconds duration{0};
    
    /// @brief Is ongoing
    bool isOngoing = false;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Whitelist entry
 */
struct AudioWhitelistEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Process name or path pattern
    std::string processPattern;
    
    /// @brief Publisher (optional)
    std::string publisher;
    
    /// @brief SHA256 hash (optional)
    std::string sha256Hash;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Require signed
    bool requireSigned = false;
    
    /// @brief Allowed APIs (bitmask)
    uint32_t allowedAPIs = 0xFFFFFFFF;  // All APIs
    
    /// @brief Time restrictions
    std::optional<int> allowFromHour;
    std::optional<int> allowToHour;
    
    /// @brief Days of week (bitmask)
    uint8_t allowedDays = 0x7F;  // All days
    
    /// @brief User restrictions
    std::vector<std::string> allowedUsers;
    
    /// @brief Added by
    std::string addedBy;
    
    /// @brief When added
    SystemTimePoint addedTime;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] bool IsCurrentlyAllowed() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct MicrophoneStatistics {
    std::atomic<uint64_t> totalAccessAttempts{0};
    std::atomic<uint64_t> accessAllowed{0};
    std::atomic<uint64_t> accessBlocked{0};
    std::atomic<uint64_t> accessMuted{0};
    std::atomic<uint64_t> accessPrompted{0};
    std::atomic<uint64_t> suspiciousAccess{0};
    std::atomic<uint64_t> malwareBlocked{0};
    std::atomic<uint64_t> ratDetected{0};
    std::atomic<uint64_t> whitelistHits{0};
    std::atomic<uint64_t> devicesMonitored{0};
    std::atomic<uint64_t> activeStreams{0};
    std::atomic<uint64_t> totalCaptureTime{0};  // seconds
    std::array<std::atomic<uint64_t>, 8> byAPI{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct MicrophoneConfiguration {
    /// @brief Protection mode
    MicrophoneProtectionMode mode = MicrophoneProtectionMode::WhitelistOnly;
    
    /// @brief Show notification on access
    bool showNotification = true;
    
    /// @brief Notification duration (ms)
    uint32_t notificationDurationMs = 5000;
    
    /// @brief Play visual indicator
    bool showIndicator = true;
    
    /// @brief Log all access
    bool logAllAccess = true;
    
    /// @brief Block unsigned processes
    bool blockUnsigned = false;
    
    /// @brief Block on screensaver
    bool blockOnScreensaver = true;
    
    /// @brief Block on lock screen
    bool blockOnLockScreen = true;
    
    /// @brief Check ThreatIntel
    bool checkThreatIntel = true;
    
    /// @brief Auto-block spyware
    bool autoBlockSpyware = true;
    
    /// @brief Maximum capture duration (0 = unlimited)
    std::chrono::seconds maxCaptureDuration{0};
    
    /// @brief Inject silence instead of blocking
    bool preferMuteOverBlock = false;
    
    /// @brief Hardware control enabled
    bool hardwareControlEnabled = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AudioAccessCallback = std::function<void(const AudioAccessEvent&)>;
using StreamCallback = std::function<void(const AudioStreamInfo&)>;
using DeviceChangeCallback = std::function<void(const AudioDevice&, bool added)>;
using DecisionCallback = std::function<AudioAccessDecision(const AudioAccessEvent&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// MICROPHONE GUARD CLASS
// ============================================================================

/**
 * @class MicrophoneGuard
 * @brief Enterprise microphone privacy protection
 */
class MicrophoneGuard final {
public:
    [[nodiscard]] static MicrophoneGuard& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    MicrophoneGuard(const MicrophoneGuard&) = delete;
    MicrophoneGuard& operator=(const MicrophoneGuard&) = delete;
    MicrophoneGuard(MicrophoneGuard&&) = delete;
    MicrophoneGuard& operator=(MicrophoneGuard&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const MicrophoneConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const MicrophoneConfiguration& config);
    [[nodiscard]] MicrophoneConfiguration GetConfiguration() const;

    // ========================================================================
    // PROTECTION CONTROL
    // ========================================================================
    
    /// @brief Set protection mode
    void SetProtectionMode(MicrophoneProtectionMode mode);
    
    /// @brief Get protection mode
    [[nodiscard]] MicrophoneProtectionMode GetProtectionMode() const noexcept;
    
    /// @brief Set global mute
    [[nodiscard]] bool SetGlobalMute(bool muted);
    
    /// @brief Is globally muted
    [[nodiscard]] bool IsGloballyMuted() const noexcept;
    
    /// @brief Block specific device
    [[nodiscard]] bool BlockDevice(const std::string& deviceId);
    
    /// @brief Unblock specific device
    [[nodiscard]] bool UnblockDevice(const std::string& deviceId);

    // ========================================================================
    // DEVICE MANAGEMENT
    // ========================================================================
    
    /// @brief Get all audio input devices
    [[nodiscard]] std::vector<AudioDevice> GetAudioDevices();
    
    /// @brief Get device by ID
    [[nodiscard]] std::optional<AudioDevice> GetDevice(const std::string& deviceId);
    
    /// @brief Get default input device
    [[nodiscard]] std::optional<AudioDevice> GetDefaultDevice();
    
    /// @brief Refresh device list
    [[nodiscard]] bool RefreshDevices();
    
    /// @brief Is any device active
    [[nodiscard]] bool IsAnyDeviceActive() const noexcept;
    
    /// @brief Get active devices
    [[nodiscard]] std::vector<AudioDevice> GetActiveDevices();

    // ========================================================================
    // STREAM MONITORING
    // ========================================================================
    
    /// @brief Start monitoring audio streams
    [[nodiscard]] bool MonitorAudioStreams();
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoringActive() const noexcept;
    
    /// @brief Get active streams
    [[nodiscard]] std::vector<AudioStreamInfo> GetActiveStreams();

    // ========================================================================
    // ACCESS CONTROL
    // ========================================================================
    
    /// @brief Block audio for process
    [[nodiscard]] bool BlockAudioForProcess(uint32_t pid);
    
    /// @brief Unblock audio for process
    [[nodiscard]] bool UnblockAudioForProcess(uint32_t pid);
    
    /// @brief Mute audio for process (inject silence)
    [[nodiscard]] bool MuteAudioForProcess(uint32_t pid);
    
    /// @brief Evaluate access request
    [[nodiscard]] AudioAccessDecision EvaluateAccess(
        uint32_t processId,
        AudioCaptureAPI api = AudioCaptureAPI::Unknown);
    
    /// @brief Allow process temporarily
    [[nodiscard]] bool AllowProcessTemporarily(
        uint32_t processId,
        std::chrono::seconds duration);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const AudioWhitelistEntry& entry);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& entryId);
    
    /// @brief Is process whitelisted
    [[nodiscard]] bool IsProcessWhitelisted(
        const std::string& processName,
        const fs::path& processPath = {});
    
    /// @brief Get whitelist
    [[nodiscard]] std::vector<AudioWhitelistEntry> GetWhitelist() const;
    
    /// @brief Import default trusted apps
    [[nodiscard]] bool ImportDefaultTrustedApps();

    // ========================================================================
    // EVENT HISTORY
    // ========================================================================
    
    /// @brief Get recent events
    [[nodiscard]] std::vector<AudioAccessEvent> GetRecentEvents(
        size_t limit = 100,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Get events for process
    [[nodiscard]] std::vector<AudioAccessEvent> GetEventsForProcess(
        const std::string& processName);
    
    /// @brief Clear history
    void ClearEventHistory();

    // ========================================================================
    // SPYWARE DETECTION
    // ========================================================================
    
    /// @brief Check if process is known spyware
    [[nodiscard]] bool IsKnownSpyware(uint32_t processId);
    
    /// @brief Analyze process for RAT behavior
    [[nodiscard]] AudioRiskLevel AnalyzeProcess(uint32_t processId);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAccessCallback(AudioAccessCallback callback);
    void RegisterStreamCallback(StreamCallback callback);
    void RegisterDeviceCallback(DeviceChangeCallback callback);
    void RegisterDecisionCallback(DecisionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] MicrophoneStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MicrophoneGuard();
    ~MicrophoneGuard();
    
    std::unique_ptr<MicrophoneGuardImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetProtectionModeName(MicrophoneProtectionMode mode) noexcept;
[[nodiscard]] std::string_view GetDeviceTypeName(AudioDeviceType type) noexcept;
[[nodiscard]] std::string_view GetCaptureAPIName(AudioCaptureAPI api) noexcept;
[[nodiscard]] std::string_view GetAccessReasonName(AudioAccessReason reason) noexcept;
[[nodiscard]] std::string_view GetRiskLevelName(AudioRiskLevel level) noexcept;
[[nodiscard]] std::string_view GetDecisionName(AudioAccessDecision decision) noexcept;

/// @brief Enumerate audio input devices
[[nodiscard]] std::vector<AudioDevice> EnumerateAudioDevices();

/// @brief Get processes using audio capture
[[nodiscard]] std::vector<uint32_t> GetProcessesCapturingAudio();

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_MIC_MUTE_ALL() \
    ::ShadowStrike::Privacy::MicrophoneGuard::Instance().SetGlobalMute(true)

#define SS_MIC_UNMUTE() \
    ::ShadowStrike::Privacy::MicrophoneGuard::Instance().SetGlobalMute(false)

#define SS_MIC_IS_MUTED() \
    ::ShadowStrike::Privacy::MicrophoneGuard::Instance().IsGloballyMuted()

#define SS_MIC_BLOCK_PROCESS(pid) \
    ::ShadowStrike::Privacy::MicrophoneGuard::Instance().BlockAudioForProcess(pid)
