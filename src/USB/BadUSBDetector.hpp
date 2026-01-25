/**
 * ============================================================================
 * ShadowStrike NGAV - BAD USB DETECTOR MODULE
 * ============================================================================
 *
 * @file BadUSBDetector.hpp
 * @brief Enterprise-grade HID-based attack detection engine for identifying
 *        malicious USB devices (Rubber Ducky, Bash Bunny, O.MG Cable, etc.)
 *
 * Provides comprehensive detection of BadUSB attacks using behavioral analysis,
 * device fingerprinting, and input pattern recognition.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. DEVICE ANALYSIS
 *    - VID/PID blacklist matching
 *    - Known attack device fingerprints
 *    - Device descriptor anomaly detection
 *    - Interface class enumeration
 *    - Multiple interface detection (HID+Storage combo)
 *
 * 2. BEHAVIORAL ANALYSIS
 *    - Typing speed analysis (superhuman detection)
 *    - Keystroke timing variance
 *    - Input burst detection
 *    - Key combination tracking
 *    - Inter-keystroke interval analysis
 *
 * 3. COMMAND PATTERN DETECTION
 *    - PowerShell download cradles
 *    - cmd.exe invocation
 *    - Privilege escalation sequences
 *    - Persistence mechanisms
 *    - Script execution patterns
 *
 * 4. ATTACK DEVICE DETECTION
 *    - USB Rubber Ducky
 *    - Hak5 Bash Bunny
 *    - O.MG Cable
 *    - Digispark clones
 *    - Teensy-based attacks
 *    - Arduino HID attacks
 *    - MalDuino
 *    - P4wnP1
 *
 * 5. COUNTERMEASURES
 *    - Input blocking
 *    - Device ejection
 *    - Alert generation
 *    - Forensic logging
 *    - Process termination
 *
 * INTEGRATION:
 * ============
 * - HashStore for device fingerprints
 * - ThreatIntel for malicious VID/PIDs
 * - Whitelist for trusted devices
 * - Process monitoring for injected commands
 *
 * @note Requires raw input hook installation.
 * @note Works in conjunction with USBDeviceMonitor.
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
#include <deque>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>

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
#include "../Utils/ProcessUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::USB {
    class BadUSBDetectorImpl;
}

namespace ShadowStrike {
namespace USB {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BadUSBConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum keystrokes per second (human limit ~15)
    inline constexpr uint32_t MAX_HUMAN_CPS = 20;
    
    /// @brief Superhuman keystroke threshold
    inline constexpr uint32_t BADUSB_CPS_THRESHOLD = 50;
    
    /// @brief Minimum inter-keystroke interval (ms)
    inline constexpr uint32_t MIN_HUMAN_INTERVAL_MS = 30;
    
    /// @brief Analysis window size (keystrokes)
    inline constexpr size_t ANALYSIS_WINDOW_SIZE = 100;
    
    /// @brief Burst detection threshold
    inline constexpr uint32_t BURST_THRESHOLD = 20;
    
    /// @brief Known malicious VID/PID pairs
    struct KnownBadDevice {
        uint16_t vendorId;
        uint16_t productId;
        const char* deviceName;
    };
    
    /// @brief Known BadUSB devices
    inline constexpr KnownBadDevice KNOWN_BAD_DEVICES[] = {
        {0x1FC9, 0x000C, "USB Rubber Ducky"},
        {0x2E8A, 0x000A, "Bash Bunny MK2"},
        {0x16D0, 0x0753, "Digispark"},
        {0x2341, 0x0001, "Arduino HID"},
        {0x16C0, 0x0483, "Teensy HID"},
        {0x1B4F, 0x9203, "SparkFun Pro Micro"},
        {0x239A, 0x000E, "Adafruit HID"},
        {0x0403, 0x6001, "FTDI-based (potential)"},
    };

}  // namespace BadUSBConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Duration = std::chrono::microseconds;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Device analysis result
 */
enum class DeviceAnalysisResult : uint8_t {
    Safe            = 0,
    Suspicious      = 1,
    KnownBadDevice  = 2,
    AnomalousDescriptor = 3,
    MultipleInterfaces = 4,
    SpoofedVIDPID   = 5,
    BlacklistedDevice = 6,
    Unknown         = 255
};

/**
 * @brief Input pattern type
 */
enum class InputPatternType : uint8_t {
    Normal          = 0,
    SuperhumanSpeed = 1,
    PerfectTiming   = 2,
    BurstInput      = 3,
    ScriptedSequence = 4,
    CommandInjection = 5,
    PrivilegeEscalation = 6,
    DownloadCradle  = 7,
    PersistenceMechanism = 8,
    ShellExecution  = 9
};

/**
 * @brief Attack device type
 */
enum class AttackDeviceType : uint8_t {
    Unknown         = 0,
    RubberDucky     = 1,
    BashBunny       = 2,
    OMGCable        = 3,
    Digispark       = 4,
    Teensy          = 5,
    Arduino         = 6,
    MalDuino        = 7,
    P4wnP1          = 8,
    USBNinja        = 9,
    HakCat          = 10,
    Custom          = 255
};

/**
 * @brief Response action
 */
enum class BadUSBResponse : uint8_t {
    Allow           = 0,
    Monitor         = 1,
    Block           = 2,
    BlockAndEject   = 3,
    BlockAndAlert   = 4,
    Quarantine      = 5
};

/**
 * @brief Detection confidence
 */
enum class DetectionConfidence : uint8_t {
    None            = 0,
    Low             = 25,
    Medium          = 50,
    High            = 75,
    Certain         = 100
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
 * @brief HID input statistics
 */
struct HIDInputStatistics {
    /// @brief Characters per second (current)
    double currentCPS = 0.0;
    
    /// @brief Peak characters per second
    double peakCPS = 0.0;
    
    /// @brief Average characters per second
    double averageCPS = 0.0;
    
    /// @brief Maximum burst length
    uint32_t maxBurstLength = 0;
    
    /// @brief Timing consistency score (0.0 = robot, 1.0 = human)
    double consistencyScore = 1.0;
    
    /// @brief Timing variance (ms)
    double timingVarianceMs = 0.0;
    
    /// @brief Minimum inter-keystroke interval
    Duration minInterval{0};
    
    /// @brief Maximum inter-keystroke interval
    Duration maxInterval{0};
    
    /// @brief Average inter-keystroke interval
    Duration avgInterval{0};
    
    /// @brief Total keystrokes analyzed
    uint64_t totalKeystrokes = 0;
    
    /// @brief Special key combinations used
    bool usesSpecialCombos = false;
    
    /// @brief Win+R detected
    bool winRDetected = false;
    
    /// @brief Ctrl+Esc detected
    bool ctrlEscDetected = false;
    
    /// @brief Analysis window start time
    TimePoint windowStart;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Device descriptor info
 */
struct HIDDeviceDescriptor {
    /// @brief Vendor ID
    uint16_t vendorId = 0;
    
    /// @brief Product ID
    uint16_t productId = 0;
    
    /// @brief Device path
    std::string devicePath;
    
    /// @brief Device instance ID
    std::string instanceId;
    
    /// @brief Manufacturer string
    std::string manufacturer;
    
    /// @brief Product string
    std::string product;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief USB class code
    uint8_t classCode = 0;
    
    /// @brief USB subclass code
    uint8_t subclassCode = 0;
    
    /// @brief Protocol code
    uint8_t protocolCode = 0;
    
    /// @brief Interface count
    uint8_t interfaceCount = 0;
    
    /// @brief Interface types (class codes)
    std::vector<uint8_t> interfaceClasses;
    
    /// @brief Is composite device
    bool isComposite = false;
    
    /// @brief Has HID interface
    bool hasHIDInterface = false;
    
    /// @brief Has mass storage interface
    bool hasMassStorage = false;
    
    /// @brief First seen time
    SystemTimePoint firstSeen;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detected command pattern
 */
struct DetectedCommandPattern {
    /// @brief Pattern type
    InputPatternType patternType = InputPatternType::Normal;
    
    /// @brief Command string (reconstructed)
    std::string commandString;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief MITRE ATT&CK technique
    std::string mitreAttackId;
    
    /// @brief Detection time
    TimePoint detectionTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Attack detection event
 */
struct BadUSBAttackEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Device descriptor
    HIDDeviceDescriptor device;
    
    /// @brief Analysis result
    DeviceAnalysisResult analysisResult = DeviceAnalysisResult::Unknown;
    
    /// @brief Attack device type
    AttackDeviceType attackType = AttackDeviceType::Unknown;
    
    /// @brief Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Input statistics
    HIDInputStatistics inputStats;
    
    /// @brief Detected patterns
    std::vector<DetectedCommandPattern> detectedPatterns;
    
    /// @brief Response taken
    BadUSBResponse responseTaken = BadUSBResponse::Allow;
    
    /// @brief Reconstructed command buffer
    std::string reconstructedBuffer;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detection reason
    std::string detectionReason;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Attack duration
    std::chrono::milliseconds attackDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct BadUSBStatistics {
    std::atomic<uint64_t> totalDevicesAnalyzed{0};
    std::atomic<uint64_t> knownBadDevicesDetected{0};
    std::atomic<uint64_t> suspiciousDevicesDetected{0};
    std::atomic<uint64_t> attacksDetected{0};
    std::atomic<uint64_t> attacksBlocked{0};
    std::atomic<uint64_t> superhumanInputDetected{0};
    std::atomic<uint64_t> commandInjectionDetected{0};
    std::atomic<uint64_t> totalKeystrokesAnalyzed{0};
    std::atomic<uint64_t> totalBurstEventsDetected{0};
    std::array<std::atomic<uint64_t>, 16> byDeviceType{};
    std::array<std::atomic<uint64_t>, 16> byPatternType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct BadUSBConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Enable behavioral analysis
    bool enableBehavioralAnalysis = true;
    
    /// @brief Enable command pattern detection
    bool enableCommandPatternDetection = true;
    
    /// @brief Block known bad devices
    bool blockKnownBadDevices = true;
    
    /// @brief Block superhuman input
    bool blockSuperhumanInput = true;
    
    /// @brief Max CPS before block
    uint32_t maxAllowedCPS = BadUSBConstants::BADUSB_CPS_THRESHOLD;
    
    /// @brief Minimum timing variance (robot detection)
    double minTimingVarianceMs = 5.0;
    
    /// @brief Analysis window size
    size_t analysisWindowSize = BadUSBConstants::ANALYSIS_WINDOW_SIZE;
    
    /// @brief Default response action
    BadUSBResponse defaultResponse = BadUSBResponse::BlockAndAlert;
    
    /// @brief Eject on detection
    bool ejectOnDetection = true;
    
    /// @brief Terminate launched processes
    bool terminateLaunchedProcesses = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AttackEventCallback = std::function<void(const BadUSBAttackEvent&)>;
using DeviceAnalysisCallback = std::function<void(const HIDDeviceDescriptor&, DeviceAnalysisResult)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// BAD USB DETECTOR CLASS
// ============================================================================

/**
 * @class BadUSBDetector
 * @brief Enterprise-grade HID attack detection engine
 */
class BadUSBDetector final {
public:
    [[nodiscard]] static BadUSBDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    BadUSBDetector(const BadUSBDetector&) = delete;
    BadUSBDetector& operator=(const BadUSBDetector&) = delete;
    BadUSBDetector(BadUSBDetector&&) = delete;
    BadUSBDetector& operator=(BadUSBDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const BadUSBConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const BadUSBConfiguration& config);
    [[nodiscard]] BadUSBConfiguration GetConfiguration() const;

    // ========================================================================
    // DEVICE ANALYSIS
    // ========================================================================
    
    /// @brief Analyze device descriptor
    [[nodiscard]] DeviceAnalysisResult AnalyzeDeviceDescriptor(
        const std::string& devicePath);
    
    /// @brief Analyze device by VID/PID
    [[nodiscard]] DeviceAnalysisResult AnalyzeDevice(
        uint16_t vendorId,
        uint16_t productId);
    
    /// @brief Get device descriptor info
    [[nodiscard]] std::optional<HIDDeviceDescriptor> GetDeviceDescriptor(
        const std::string& devicePath);
    
    /// @brief Check if device is known bad
    [[nodiscard]] bool IsKnownBadDevice(uint16_t vendorId, uint16_t productId) const noexcept;
    
    /// @brief Get attack device type
    [[nodiscard]] AttackDeviceType IdentifyAttackDeviceType(
        uint16_t vendorId,
        uint16_t productId) const noexcept;

    // ========================================================================
    // INPUT ANALYSIS
    // ========================================================================
    
    /// @brief Process keyboard event
    void ProcessKeyboardEvent(
        uint16_t virtualKey,
        bool isKeyDown,
        TimePoint timestamp,
        const std::string& deviceId = "");
    
    /// @brief Check if attack is in progress
    [[nodiscard]] bool IsAttackInProgress() const noexcept;
    
    /// @brief Get current input statistics
    [[nodiscard]] HIDInputStatistics GetCurrentInputStatistics() const;
    
    /// @brief Get reconstructed command buffer
    [[nodiscard]] std::string GetReconstructedBuffer() const;
    
    /// @brief Reset analysis state
    void ResetAnalysis();

    // ========================================================================
    // RESPONSE ACTIONS
    // ========================================================================
    
    /// @brief Block device
    [[nodiscard]] bool BlockDevice(const std::string& devicePath);
    
    /// @brief Eject device
    [[nodiscard]] bool EjectDevice(const std::string& devicePath);
    
    /// @brief Terminate processes launched by attack
    void TerminateLaunchedProcesses();
    
    /// @brief Clear input buffer (neutralize pending keystrokes)
    void ClearInputBuffer();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAttackCallback(AttackEventCallback callback);
    void RegisterDeviceCallback(DeviceAnalysisCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] BadUSBStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    BadUSBDetector();
    ~BadUSBDetector();
    
    std::unique_ptr<BadUSBDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDeviceAnalysisResultName(DeviceAnalysisResult result) noexcept;
[[nodiscard]] std::string_view GetInputPatternTypeName(InputPatternType type) noexcept;
[[nodiscard]] std::string_view GetAttackDeviceTypeName(AttackDeviceType type) noexcept;
[[nodiscard]] std::string_view GetBadUSBResponseName(BadUSBResponse response) noexcept;
[[nodiscard]] bool IsVIDPIDKnownMalicious(uint16_t vid, uint16_t pid) noexcept;
[[nodiscard]] std::string FormatVIDPID(uint16_t vid, uint16_t pid);

}  // namespace USB
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_BADUSB_ANALYZE(devicePath) \
    ::ShadowStrike::USB::BadUSBDetector::Instance().AnalyzeDeviceDescriptor(devicePath)

#define SS_BADUSB_CHECK_ATTACK() \
    ::ShadowStrike::USB::BadUSBDetector::Instance().IsAttackInProgress()