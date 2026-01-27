/**
 * ============================================================================
 * ShadowStrike NGAV - BAD USB DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file BadUSBDetector.cpp
 * @brief Enterprise-grade HID attack detection engine implementation
 *
 * Implements comprehensive BadUSB attack detection including:
 * - Known attack device fingerprinting (Rubber Ducky, Bash Bunny, etc.)
 * - Behavioral analysis (superhuman typing speed, perfect timing)
 * - Command pattern detection (PowerShell cradles, privilege escalation)
 * - Input buffer reconstruction and analysis
 * - Real-time response and countermeasures
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "BadUSBDetector.hpp"
#include "USBDeviceMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/HashUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <numeric>
#include <cmath>

// Windows-specific includes for device operations
#ifdef _WIN32
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <hidsdi.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#endif

namespace ShadowStrike {
namespace USB {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"BadUSBDetector";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> BadUSBDetector::s_instanceCreated{false};

// ============================================================================
// COMMAND PATTERN DEFINITIONS
// ============================================================================

namespace CommandPatterns {

    // PowerShell download cradle patterns
    static const std::vector<std::regex> POWERSHELL_CRADLES = {
        std::regex(R"(powershell.*-e[ncodema]*\s+[A-Za-z0-9+/=]+)", std::regex::icase),
        std::regex(R"(powershell.*IEX.*\(.*New-Object.*Net\.WebClient)", std::regex::icase),
        std::regex(R"(powershell.*Invoke-Expression.*downloadstring)", std::regex::icase),
        std::regex(R"(powershell.*\[System\.Net\.WebClient\])", std::regex::icase),
        std::regex(R"(powershell.*Start-BitsTransfer)", std::regex::icase),
        std::regex(R"(powershell.*Invoke-WebRequest)", std::regex::icase),
        std::regex(R"(powershell.*wget\s+http)", std::regex::icase),
        std::regex(R"(powershell.*curl\s+http)", std::regex::icase),
    };

    // CMD execution patterns
    static const std::vector<std::regex> CMD_PATTERNS = {
        std::regex(R"(cmd\s*/c)", std::regex::icase),
        std::regex(R"(cmd\.exe\s*/k)", std::regex::icase),
        std::regex(R"(command\.com)", std::regex::icase),
    };

    // Privilege escalation patterns
    static const std::vector<std::regex> PRIVESC_PATTERNS = {
        std::regex(R"(runas\s+/user:)", std::regex::icase),
        std::regex(R"(net\s+user\s+\w+\s+/add)", std::regex::icase),
        std::regex(R"(net\s+localgroup\s+administrators)", std::regex::icase),
        std::regex(R"(reg\s+add.*\\CurrentVersion\\Run)", std::regex::icase),
        std::regex(R"(schtasks\s+/create)", std::regex::icase),
        std::regex(R"(wmic\s+process\s+call\s+create)", std::regex::icase),
    };

    // Persistence mechanism patterns
    static const std::vector<std::regex> PERSISTENCE_PATTERNS = {
        std::regex(R"(\\Startup\\)", std::regex::icase),
        std::regex(R"(\\Run\\)", std::regex::icase),
        std::regex(R"(\\RunOnce\\)", std::regex::icase),
        std::regex(R"(schtasks.*\/create)", std::regex::icase),
        std::regex(R"(sc\s+create)", std::regex::icase),
        std::regex(R"(reg\s+add.*\\services\\)", std::regex::icase),
    };

    // Shell execution patterns
    static const std::vector<std::regex> SHELL_PATTERNS = {
        std::regex(R"(bash\s+-c)", std::regex::icase),
        std::regex(R"(wscript)", std::regex::icase),
        std::regex(R"(cscript)", std::regex::icase),
        std::regex(R"(mshta)", std::regex::icase),
        std::regex(R"(certutil.*-urlcache)", std::regex::icase),
        std::regex(R"(bitsadmin.*\/transfer)", std::regex::icase),
    };

    // MITRE ATT&CK technique mappings
    struct PatternTechniqueMap {
        InputPatternType type;
        const char* mitreId;
        const char* name;
        int baseRiskScore;
    };

    static const PatternTechniqueMap TECHNIQUE_MAP[] = {
        {InputPatternType::DownloadCradle, "T1059.001", "PowerShell Download Cradle", 90},
        {InputPatternType::CommandInjection, "T1059.003", "Windows Command Shell", 75},
        {InputPatternType::PrivilegeEscalation, "T1548", "Abuse Elevation Control", 95},
        {InputPatternType::PersistenceMechanism, "T1547", "Boot/Logon Autostart", 85},
        {InputPatternType::ShellExecution, "T1059", "Command and Scripting Interpreter", 70},
        {InputPatternType::SuperhumanSpeed, "T1059", "Automated Input Injection", 80},
    };

}  // namespace CommandPatterns

// ============================================================================
// KEYSTROKE EVENT STRUCTURE
// ============================================================================

struct KeystrokeEvent {
    uint16_t virtualKey;
    bool isKeyDown;
    TimePoint timestamp;
    std::string deviceId;
    char character;  // Resolved character (0 if non-printable)
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BadUSBDetectorImpl {
public:
    BadUSBDetectorImpl() = default;
    ~BadUSBDetectorImpl() = default;

    // Non-copyable, non-movable
    BadUSBDetectorImpl(const BadUSBDetectorImpl&) = delete;
    BadUSBDetectorImpl& operator=(const BadUSBDetectorImpl&) = delete;
    BadUSBDetectorImpl(BadUSBDetectorImpl&&) = delete;
    BadUSBDetectorImpl& operator=(BadUSBDetectorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const BadUSBConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized &&
            m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized or running");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration provided");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        // Initialize keystroke buffer
        m_keystrokeBuffer.clear();
        m_keystrokeBuffer.reserve(config.analysisWindowSize);
        m_commandBuffer.clear();
        m_commandBuffer.reserve(4096);

        // Reset state
        m_attackInProgress = false;
        m_currentAttackEvent = std::nullopt;
        m_nextEventId = 1;

        // Initialize modifier key state
        m_modifierState = {false, false, false, false};

        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"BadUSBDetector initialized successfully");
        SS_LOG_INFO(LOG_CATEGORY, L"  Behavioral analysis: %ls",
            m_config.enableBehavioralAnalysis ? L"enabled" : L"disabled");
        SS_LOG_INFO(LOG_CATEGORY, L"  Command detection: %ls",
            m_config.enableCommandPatternDetection ? L"enabled" : L"disabled");
        SS_LOG_INFO(LOG_CATEGORY, L"  Max allowed CPS: %u", m_config.maxAllowedCPS);

        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Uninitialized ||
            m_status == ModuleStatus::Stopped) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Clear callbacks
        m_attackCallbacks.clear();
        m_deviceCallbacks.clear();
        m_errorCallbacks.clear();

        // Clear buffers
        m_keystrokeBuffer.clear();
        m_commandBuffer.clear();
        m_trackedDevices.clear();

        m_status = ModuleStatus::Stopped;

        SS_LOG_INFO(LOG_CATEGORY, L"BadUSBDetector shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status == ModuleStatus::Running || m_status == ModuleStatus::Monitoring;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    [[nodiscard]] bool UpdateConfiguration(const BadUSBConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] BadUSBConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // DEVICE ANALYSIS
    // ========================================================================

    [[nodiscard]] DeviceAnalysisResult AnalyzeDeviceDescriptor(const std::string& devicePath) {
        std::unique_lock lock(m_mutex);

        m_stats.totalDevicesAnalyzed++;

        // Get device descriptor
        auto descriptor = GetDeviceDescriptorInternal(devicePath);
        if (!descriptor) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to get device descriptor: %hs",
                devicePath.c_str());
            return DeviceAnalysisResult::Unknown;
        }

        DeviceAnalysisResult result = AnalyzeDescriptor(*descriptor);

        // Track device
        m_trackedDevices[devicePath] = *descriptor;

        // Notify callbacks
        for (const auto& callback : m_deviceCallbacks) {
            try {
                callback(*descriptor, result);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Device callback threw exception");
            }
        }

        LogDeviceAnalysis(*descriptor, result);

        return result;
    }

    [[nodiscard]] DeviceAnalysisResult AnalyzeDevice(uint16_t vendorId, uint16_t productId) {
        std::unique_lock lock(m_mutex);

        m_stats.totalDevicesAnalyzed++;

        // Check known bad devices first
        if (IsKnownBadDeviceInternal(vendorId, productId)) {
            m_stats.knownBadDevicesDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"Known bad device detected: VID=%04X PID=%04X",
                vendorId, productId);
            return DeviceAnalysisResult::KnownBadDevice;
        }

        // Check for suspicious VIDs (known attack hardware vendors)
        if (IsSuspiciousVendor(vendorId)) {
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::Suspicious;
        }

        return DeviceAnalysisResult::Safe;
    }

    [[nodiscard]] std::optional<HIDDeviceDescriptor> GetDeviceDescriptor(
        const std::string& devicePath) {
        std::shared_lock lock(m_mutex);
        return GetDeviceDescriptorInternal(devicePath);
    }

    [[nodiscard]] bool IsKnownBadDevice(uint16_t vendorId, uint16_t productId) const noexcept {
        std::shared_lock lock(m_mutex);
        return IsKnownBadDeviceInternal(vendorId, productId);
    }

    [[nodiscard]] AttackDeviceType IdentifyAttackDeviceType(
        uint16_t vendorId, uint16_t productId) const noexcept {
        std::shared_lock lock(m_mutex);

        // USB Rubber Ducky
        if (vendorId == 0x1FC9 && productId == 0x000C) {
            return AttackDeviceType::RubberDucky;
        }

        // Bash Bunny
        if (vendorId == 0x2E8A && productId == 0x000A) {
            return AttackDeviceType::BashBunny;
        }

        // Digispark
        if (vendorId == 0x16D0 && productId == 0x0753) {
            return AttackDeviceType::Digispark;
        }

        // Teensy
        if (vendorId == 0x16C0 && (productId == 0x0483 || productId == 0x0486)) {
            return AttackDeviceType::Teensy;
        }

        // Arduino
        if (vendorId == 0x2341) {
            return AttackDeviceType::Arduino;
        }

        // O.MG Cable (uses various VID/PID combinations)
        if (vendorId == 0x0483 && productId == 0x5740) {
            return AttackDeviceType::OMGCable;
        }

        // P4wnP1 (Raspberry Pi Zero based)
        if (vendorId == 0x1D6B && productId == 0x0104) {
            return AttackDeviceType::P4wnP1;
        }

        return AttackDeviceType::Unknown;
    }

    // ========================================================================
    // INPUT ANALYSIS
    // ========================================================================

    void ProcessKeyboardEvent(uint16_t virtualKey, bool isKeyDown,
                              TimePoint timestamp, const std::string& deviceId) {
        std::unique_lock lock(m_mutex);

        if (!m_config.enabled) return;

        // Update modifier state
        UpdateModifierState(virtualKey, isKeyDown);

        // Only process key down events for typing analysis
        if (!isKeyDown) return;

        m_stats.totalKeystrokesAnalyzed++;

        // Create keystroke event
        KeystrokeEvent event;
        event.virtualKey = virtualKey;
        event.isKeyDown = isKeyDown;
        event.timestamp = timestamp;
        event.deviceId = deviceId;
        event.character = VirtualKeyToChar(virtualKey);

        // Add to buffer
        m_keystrokeBuffer.push_back(event);

        // Trim buffer to window size
        while (m_keystrokeBuffer.size() > m_config.analysisWindowSize) {
            m_keystrokeBuffer.pop_front();
        }

        // Update command buffer
        if (event.character != 0) {
            m_commandBuffer.push_back(event.character);
            // Limit command buffer size
            if (m_commandBuffer.size() > 8192) {
                m_commandBuffer.erase(0, 4096);
            }
        }

        // Check for special key combinations
        DetectSpecialCombinations(virtualKey);

        // Perform analysis if we have enough data
        if (m_keystrokeBuffer.size() >= 10) {
            PerformBehavioralAnalysis();
        }

        // Check for command patterns
        if (m_config.enableCommandPatternDetection && m_commandBuffer.size() >= 10) {
            PerformCommandPatternAnalysis();
        }
    }

    [[nodiscard]] bool IsAttackInProgress() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_attackInProgress;
    }

    [[nodiscard]] HIDInputStatistics GetCurrentInputStatistics() const {
        std::shared_lock lock(m_mutex);
        return CalculateInputStatistics();
    }

    [[nodiscard]] std::string GetReconstructedBuffer() const {
        std::shared_lock lock(m_mutex);
        return m_commandBuffer;
    }

    void ResetAnalysis() {
        std::unique_lock lock(m_mutex);
        m_keystrokeBuffer.clear();
        m_commandBuffer.clear();
        m_attackInProgress = false;
        m_currentAttackEvent = std::nullopt;
        m_modifierState = {false, false, false, false};
        SS_LOG_INFO(LOG_CATEGORY, L"Analysis state reset");
    }

    // ========================================================================
    // RESPONSE ACTIONS
    // ========================================================================

    [[nodiscard]] bool BlockDevice(const std::string& devicePath) {
        std::unique_lock lock(m_mutex);

        SS_LOG_WARN(LOG_CATEGORY, L"Blocking device: %hs", devicePath.c_str());

#ifdef _WIN32
        // Disable the device using SetupAPI
        HDEVINFO devInfo = SetupDiGetClassDevsA(
            nullptr, devicePath.c_str(), nullptr,
            DIGCF_ALLCLASSES | DIGCF_DEVICEINTERFACE);

        if (devInfo == INVALID_HANDLE_VALUE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to get device info for blocking");
            return false;
        }

        SP_DEVINFO_DATA devInfoData{};
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        bool success = false;
        if (SetupDiEnumDeviceInfo(devInfo, 0, &devInfoData)) {
            SP_PROPCHANGE_PARAMS propChange{};
            propChange.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            propChange.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            propChange.StateChange = DICS_DISABLE;
            propChange.Scope = DICS_FLAG_GLOBAL;
            propChange.HwProfile = 0;

            if (SetupDiSetClassInstallParamsA(devInfo, &devInfoData,
                    &propChange.ClassInstallHeader, sizeof(propChange))) {
                success = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, devInfo, &devInfoData);
            }
        }

        SetupDiDestroyDeviceInfoList(devInfo);

        if (success) {
            m_stats.attacksBlocked++;
            SS_LOG_INFO(LOG_CATEGORY, L"Device blocked successfully");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to block device: %lu", GetLastError());
        }

        return success;
#else
        return false;
#endif
    }

    [[nodiscard]] bool EjectDevice(const std::string& devicePath) {
        std::unique_lock lock(m_mutex);

        SS_LOG_WARN(LOG_CATEGORY, L"Ejecting device: %hs", devicePath.c_str());

#ifdef _WIN32
        // Use CM_Request_Device_Eject
        DEVINST devInst = 0;
        CONFIGRET cr = CM_Locate_DevNodeA(&devInst, const_cast<char*>(devicePath.c_str()),
            CM_LOCATE_DEVNODE_NORMAL);

        if (cr != CR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to locate device node: %lu", cr);
            return false;
        }

        // Get parent (USB hub) for ejection
        DEVINST parentInst = 0;
        cr = CM_Get_Parent(&parentInst, devInst, 0);
        if (cr != CR_SUCCESS) {
            parentInst = devInst;
        }

        PNP_VETO_TYPE vetoType;
        wchar_t vetoName[MAX_PATH] = {0};
        cr = CM_Request_Device_EjectW(parentInst, &vetoType, vetoName, MAX_PATH, 0);

        if (cr == CR_SUCCESS) {
            SS_LOG_INFO(LOG_CATEGORY, L"Device ejected successfully");
            return true;
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to eject device: %lu, Veto: %ls",
                cr, vetoName);
            return false;
        }
#else
        return false;
#endif
    }

    void TerminateLaunchedProcesses() {
        std::unique_lock lock(m_mutex);

        if (!m_config.terminateLaunchedProcesses) return;

        SS_LOG_WARN(LOG_CATEGORY, L"Terminating processes launched by attack");

        // Get list of recently spawned processes
        // This would integrate with ProcessUtils to find and terminate
        // processes that were likely launched by the attack

        // For now, we target common attack targets
        const wchar_t* targetProcesses[] = {
            L"powershell.exe",
            L"cmd.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe",
        };

        for (const auto& processName : targetProcesses) {
            // TODO: Integrate with ProcessUtils to terminate specific instances
            // that were launched during the attack window
            SS_LOG_INFO(LOG_CATEGORY, L"Would terminate: %ls", processName);
        }
    }

    void ClearInputBuffer() {
        std::unique_lock lock(m_mutex);

        SS_LOG_INFO(LOG_CATEGORY, L"Clearing input buffer");

#ifdef _WIN32
        // Flush the keyboard buffer
        while (true) {
            MSG msg;
            if (!PeekMessageW(&msg, nullptr, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE)) {
                break;
            }
        }

        // Also clear any pending input
        INPUT input{};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = 0;
        input.ki.dwFlags = KEYEVENTF_KEYUP;

        // Send key up for all modifier keys to reset state
        uint16_t modifiers[] = {VK_CONTROL, VK_SHIFT, VK_MENU, VK_LWIN, VK_RWIN};
        for (auto vk : modifiers) {
            input.ki.wVk = vk;
            SendInput(1, &input, sizeof(INPUT));
        }
#endif
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterAttackCallback(AttackEventCallback callback) {
        std::unique_lock lock(m_mutex);
        m_attackCallbacks.push_back(std::move(callback));
    }

    void RegisterDeviceCallback(DeviceAnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        m_deviceCallbacks.push_back(std::move(callback));
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallbacks.push_back(std::move(callback));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_attackCallbacks.clear();
        m_deviceCallbacks.clear();
        m_errorCallbacks.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] BadUSBStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

    void ResetStatistics() {
        std::unique_lock lock(m_mutex);
        m_stats.Reset();
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Starting self-test...");

        try {
            // Test 1: Known bad device detection
            if (!IsKnownBadDeviceInternal(0x1FC9, 0x000C)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Rubber Ducky not detected");
                return false;
            }

            // Test 2: Attack device type identification
            auto deviceType = IdentifyAttackDeviceType(0x16D0, 0x0753);
            if (deviceType != AttackDeviceType::Digispark) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Device type mismatch");
                return false;
            }

            // Test 3: Safe device check
            auto result = AnalyzeDevice(0x046D, 0xC52B);  // Logitech receiver
            if (result == DeviceAnalysisResult::KnownBadDevice) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: False positive on safe device");
                return false;
            }

            // Test 4: Keystroke processing
            TimePoint now = Clock::now();
            for (int i = 0; i < 20; i++) {
                ProcessKeyboardEvent('A' + i, true,
                    now + std::chrono::milliseconds(i * 5), "TEST");
            }

            auto stats = CalculateInputStatistics();
            if (stats.totalKeystrokes != 20) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Keystroke count mismatch");
                ResetAnalysis();
                return false;
            }

            // Cleanup
            ResetAnalysis();

            SS_LOG_INFO(LOG_CATEGORY, L"Self-test completed successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    [[nodiscard]] std::optional<HIDDeviceDescriptor> GetDeviceDescriptorInternal(
        const std::string& devicePath) const {

#ifdef _WIN32
        HIDDeviceDescriptor descriptor;
        descriptor.devicePath = devicePath;
        descriptor.firstSeen = std::chrono::system_clock::now();

        // Open HID device
        HANDLE hDevice = CreateFileA(
            devicePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        if (hDevice == INVALID_HANDLE_VALUE) {
            return std::nullopt;
        }

        // Get HID attributes
        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(HIDD_ATTRIBUTES);
        if (HidD_GetAttributes(hDevice, &attributes)) {
            descriptor.vendorId = attributes.VendorID;
            descriptor.productId = attributes.ProductID;
        }

        // Get manufacturer string
        wchar_t buffer[256] = {0};
        if (HidD_GetManufacturerString(hDevice, buffer, sizeof(buffer))) {
            descriptor.manufacturer = Utils::StringUtils::ToNarrow(buffer);
        }

        // Get product string
        if (HidD_GetProductString(hDevice, buffer, sizeof(buffer))) {
            descriptor.product = Utils::StringUtils::ToNarrow(buffer);
        }

        // Get serial number
        if (HidD_GetSerialNumberString(hDevice, buffer, sizeof(buffer))) {
            descriptor.serialNumber = Utils::StringUtils::ToNarrow(buffer);
        }

        // Get preparsed data for interface info
        PHIDP_PREPARSED_DATA preparsedData = nullptr;
        if (HidD_GetPreparsedData(hDevice, &preparsedData)) {
            HIDP_CAPS caps{};
            if (HidP_GetCaps(preparsedData, &caps) == HIDP_STATUS_SUCCESS) {
                descriptor.hasHIDInterface = true;
                // Check usage page for keyboard/mouse
                if (caps.UsagePage == HID_USAGE_PAGE_GENERIC) {
                    if (caps.Usage == HID_USAGE_GENERIC_KEYBOARD) {
                        descriptor.classCode = 0x03;  // HID
                        descriptor.subclassCode = 0x01;  // Boot interface
                        descriptor.protocolCode = 0x01;  // Keyboard
                    } else if (caps.Usage == HID_USAGE_GENERIC_MOUSE) {
                        descriptor.classCode = 0x03;
                        descriptor.subclassCode = 0x01;
                        descriptor.protocolCode = 0x02;  // Mouse
                    }
                }
            }
            HidD_FreePreparsedData(preparsedData);
        }

        CloseHandle(hDevice);

        return descriptor;
#else
        return std::nullopt;
#endif
    }

    [[nodiscard]] bool IsKnownBadDeviceInternal(uint16_t vendorId, uint16_t productId) const {
        for (const auto& device : BadUSBConstants::KNOWN_BAD_DEVICES) {
            if (device.vendorId == vendorId && device.productId == productId) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool IsSuspiciousVendor(uint16_t vendorId) const {
        // Check for known attack hardware vendors
        switch (vendorId) {
            case 0x16C0:  // Teensy
            case 0x16D0:  // Digispark/MCS
            case 0x1FC9:  // NXP (Rubber Ducky)
            case 0x2E8A:  // Raspberry Pi (Bash Bunny MK2)
            case 0x1D6B:  // Linux Foundation (P4wnP1)
            case 0x0483:  // STMicroelectronics (O.MG)
                return true;
            default:
                return false;
        }
    }

    [[nodiscard]] DeviceAnalysisResult AnalyzeDescriptor(const HIDDeviceDescriptor& desc) {
        // Check known bad devices
        if (IsKnownBadDeviceInternal(desc.vendorId, desc.productId)) {
            m_stats.knownBadDevicesDetected++;
            return DeviceAnalysisResult::KnownBadDevice;
        }

        // Check for composite device (HID + Storage)
        if (desc.hasHIDInterface && desc.hasMassStorage) {
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::MultipleInterfaces;
        }

        // Check for descriptor anomalies
        if (desc.manufacturer.empty() && desc.product.empty()) {
            // Missing strings can indicate attack device
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::AnomalousDescriptor;
        }

        // Check suspicious vendor
        if (IsSuspiciousVendor(desc.vendorId)) {
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::Suspicious;
        }

        return DeviceAnalysisResult::Safe;
    }

    void LogDeviceAnalysis(const HIDDeviceDescriptor& desc, DeviceAnalysisResult result) {
        SS_LOG_INFO(LOG_CATEGORY,
            L"Device analyzed: VID=%04X PID=%04X Mfg='%hs' Product='%hs' -> %hs",
            desc.vendorId, desc.productId,
            desc.manufacturer.c_str(), desc.product.c_str(),
            std::string(GetDeviceAnalysisResultName(result)).c_str());
    }

    // ========================================================================
    // KEYSTROKE ANALYSIS
    // ========================================================================

    void UpdateModifierState(uint16_t virtualKey, bool isKeyDown) {
        switch (virtualKey) {
            case VK_CONTROL:
            case VK_LCONTROL:
            case VK_RCONTROL:
                m_modifierState.ctrl = isKeyDown;
                break;
            case VK_SHIFT:
            case VK_LSHIFT:
            case VK_RSHIFT:
                m_modifierState.shift = isKeyDown;
                break;
            case VK_MENU:
            case VK_LMENU:
            case VK_RMENU:
                m_modifierState.alt = isKeyDown;
                break;
            case VK_LWIN:
            case VK_RWIN:
                m_modifierState.win = isKeyDown;
                break;
        }
    }

    [[nodiscard]] char VirtualKeyToChar(uint16_t vk) const {
        // Convert virtual key to ASCII character
        if (vk >= 'A' && vk <= 'Z') {
            return m_modifierState.shift ? static_cast<char>(vk) : static_cast<char>(vk + 32);
        }
        if (vk >= '0' && vk <= '9') {
            return static_cast<char>(vk);
        }
        if (vk == VK_SPACE) return ' ';
        if (vk == VK_RETURN) return '\n';
        if (vk == VK_TAB) return '\t';

        // Handle punctuation with shift
        if (m_modifierState.shift) {
            switch (vk) {
                case VK_OEM_1: return ':';  // ;:
                case VK_OEM_PLUS: return '+';
                case VK_OEM_COMMA: return '<';
                case VK_OEM_MINUS: return '_';
                case VK_OEM_PERIOD: return '>';
                case VK_OEM_2: return '?';  // /?
                case VK_OEM_3: return '~';  // `~
                case VK_OEM_4: return '{';  // [{
                case VK_OEM_5: return '|';  // \|
                case VK_OEM_6: return '}';  // ]}
                case VK_OEM_7: return '"';  // '"
            }
        } else {
            switch (vk) {
                case VK_OEM_1: return ';';
                case VK_OEM_PLUS: return '=';
                case VK_OEM_COMMA: return ',';
                case VK_OEM_MINUS: return '-';
                case VK_OEM_PERIOD: return '.';
                case VK_OEM_2: return '/';
                case VK_OEM_3: return '`';
                case VK_OEM_4: return '[';
                case VK_OEM_5: return '\\';
                case VK_OEM_6: return ']';
                case VK_OEM_7: return '\'';
            }
        }

        return 0;  // Non-printable
    }

    void DetectSpecialCombinations(uint16_t virtualKey) {
        // Win+R detection (Run dialog)
        if (m_modifierState.win && virtualKey == 'R') {
            m_inputStats.winRDetected = true;
            SS_LOG_WARN(LOG_CATEGORY, L"Win+R combination detected");
        }

        // Ctrl+Esc (Start menu)
        if (m_modifierState.ctrl && virtualKey == VK_ESCAPE) {
            m_inputStats.ctrlEscDetected = true;
        }

        // Alt+Tab (could be used for evasion)
        if (m_modifierState.alt && virtualKey == VK_TAB) {
            SS_LOG_INFO(LOG_CATEGORY, L"Alt+Tab detected during analysis");
        }

        // Ctrl+Shift+Esc (Task Manager)
        if (m_modifierState.ctrl && m_modifierState.shift && virtualKey == VK_ESCAPE) {
            SS_LOG_WARN(LOG_CATEGORY, L"Ctrl+Shift+Esc (Task Manager) detected");
        }

        if (m_inputStats.winRDetected || m_inputStats.ctrlEscDetected) {
            m_inputStats.usesSpecialCombos = true;
        }
    }

    [[nodiscard]] HIDInputStatistics CalculateInputStatistics() const {
        HIDInputStatistics stats;

        if (m_keystrokeBuffer.size() < 2) {
            return stats;
        }

        stats.totalKeystrokes = m_keystrokeBuffer.size();
        stats.windowStart = m_keystrokeBuffer.front().timestamp;

        // Calculate intervals
        std::vector<Duration> intervals;
        intervals.reserve(m_keystrokeBuffer.size() - 1);

        for (size_t i = 1; i < m_keystrokeBuffer.size(); i++) {
            auto interval = std::chrono::duration_cast<Duration>(
                m_keystrokeBuffer[i].timestamp - m_keystrokeBuffer[i-1].timestamp);
            intervals.push_back(interval);
        }

        if (intervals.empty()) {
            return stats;
        }

        // Min/Max interval
        auto [minIt, maxIt] = std::minmax_element(intervals.begin(), intervals.end());
        stats.minInterval = *minIt;
        stats.maxInterval = *maxIt;

        // Average interval
        Duration total{0};
        for (const auto& interval : intervals) {
            total += interval;
        }
        stats.avgInterval = Duration(total.count() / intervals.size());

        // Calculate CPS
        auto windowDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            m_keystrokeBuffer.back().timestamp - m_keystrokeBuffer.front().timestamp);

        if (windowDuration.count() > 0) {
            stats.currentCPS = (static_cast<double>(m_keystrokeBuffer.size()) * 1000.0) /
                               static_cast<double>(windowDuration.count());
        }

        stats.peakCPS = std::max(stats.peakCPS, stats.currentCPS);
        stats.averageCPS = stats.currentCPS;  // Simplified

        // Calculate timing variance (standard deviation)
        if (intervals.size() >= 2) {
            double mean = static_cast<double>(stats.avgInterval.count());
            double sumSquares = 0.0;

            for (const auto& interval : intervals) {
                double diff = static_cast<double>(interval.count()) - mean;
                sumSquares += diff * diff;
            }

            double variance = sumSquares / static_cast<double>(intervals.size());
            stats.timingVarianceMs = std::sqrt(variance) / 1000.0;  // Convert to ms

            // Consistency score: higher variance = more human-like
            // Very low variance indicates scripted/automated input
            stats.consistencyScore = std::min(1.0, stats.timingVarianceMs / 20.0);
        }

        // Detect bursts (consecutive keystrokes under threshold)
        uint32_t currentBurst = 0;
        for (const auto& interval : intervals) {
            if (interval.count() < BadUSBConstants::MIN_HUMAN_INTERVAL_MS * 1000) {
                currentBurst++;
                stats.maxBurstLength = std::max(stats.maxBurstLength, currentBurst);
            } else {
                currentBurst = 0;
            }
        }

        // Copy special combo flags
        stats.winRDetected = m_inputStats.winRDetected;
        stats.ctrlEscDetected = m_inputStats.ctrlEscDetected;
        stats.usesSpecialCombos = m_inputStats.usesSpecialCombos;

        return stats;
    }

    void PerformBehavioralAnalysis() {
        if (!m_config.enableBehavioralAnalysis) return;

        auto stats = CalculateInputStatistics();

        bool isSuspicious = false;
        std::string reason;

        // Check 1: Superhuman typing speed
        if (stats.currentCPS > static_cast<double>(m_config.maxAllowedCPS)) {
            isSuspicious = true;
            reason = "Superhuman typing speed detected: " +
                     std::to_string(static_cast<int>(stats.currentCPS)) + " CPS";
            m_stats.superhumanInputDetected++;
        }

        // Check 2: Perfect timing (too consistent = robot)
        if (stats.timingVarianceMs < m_config.minTimingVarianceMs &&
            stats.totalKeystrokes > 20) {
            isSuspicious = true;
            reason = "Robotic timing pattern detected (variance: " +
                     std::to_string(stats.timingVarianceMs) + "ms)";
        }

        // Check 3: Burst input
        if (stats.maxBurstLength > BadUSBConstants::BURST_THRESHOLD) {
            isSuspicious = true;
            reason = "Input burst detected (" +
                     std::to_string(stats.maxBurstLength) + " rapid keystrokes)";
            m_stats.totalBurstEventsDetected++;
        }

        // Check 4: Special combinations with high speed
        if (stats.usesSpecialCombos &&
            stats.currentCPS > static_cast<double>(BadUSBConstants::MAX_HUMAN_CPS)) {
            isSuspicious = true;
            reason = "Automated hotkey sequence detected";
        }

        if (isSuspicious) {
            TriggerAttackDetection(InputPatternType::SuperhumanSpeed, reason, stats);
        }
    }

    void PerformCommandPatternAnalysis() {
        // Convert command buffer to lowercase for matching
        std::string lowerBuffer = m_commandBuffer;
        std::transform(lowerBuffer.begin(), lowerBuffer.end(),
                       lowerBuffer.begin(), ::tolower);

        // Check PowerShell cradles
        for (const auto& pattern : CommandPatterns::POWERSHELL_CRADLES) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::DownloadCradle;
                detected.commandString = m_commandBuffer;
                detected.riskScore = 90;
                detected.mitreAttackId = "T1059.001";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection(detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check privilege escalation
        for (const auto& pattern : CommandPatterns::PRIVESC_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::PrivilegeEscalation;
                detected.commandString = m_commandBuffer;
                detected.riskScore = 95;
                detected.mitreAttackId = "T1548";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection(detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check persistence mechanisms
        for (const auto& pattern : CommandPatterns::PERSISTENCE_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::PersistenceMechanism;
                detected.commandString = m_commandBuffer;
                detected.riskScore = 85;
                detected.mitreAttackId = "T1547";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection(detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check CMD patterns
        for (const auto& pattern : CommandPatterns::CMD_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::CommandInjection;
                detected.commandString = m_commandBuffer;
                detected.riskScore = 75;
                detected.mitreAttackId = "T1059.003";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection(detected);
                return;
            }
        }

        // Check shell execution
        for (const auto& pattern : CommandPatterns::SHELL_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::ShellExecution;
                detected.commandString = m_commandBuffer;
                detected.riskScore = 70;
                detected.mitreAttackId = "T1059";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection(detected);
                return;
            }
        }
    }

    void TriggerAttackDetection(InputPatternType patternType,
                                 const std::string& reason,
                                 const HIDInputStatistics& stats) {

        SS_LOG_WARN(LOG_CATEGORY, L"BadUSB ATTACK DETECTED: %hs", reason.c_str());

        m_attackInProgress = true;
        m_stats.attacksDetected++;

        // Create attack event
        BadUSBAttackEvent event;
        event.eventId = m_nextEventId++;
        event.analysisResult = DeviceAnalysisResult::Suspicious;
        event.attackType = AttackDeviceType::Unknown;
        event.confidence = DetectionConfidence::High;
        event.inputStats = stats;
        event.reconstructedBuffer = m_commandBuffer;
        event.detectionReason = reason;
        event.detectionTime = std::chrono::system_clock::now();

        // Add pattern
        DetectedCommandPattern pattern;
        pattern.patternType = patternType;
        pattern.commandString = m_commandBuffer;
        pattern.riskScore = 80;
        pattern.detectionTime = Clock::now();
        event.detectedPatterns.push_back(pattern);

        event.riskScore = CalculateRiskScore(event);
        event.responseTaken = DetermineResponse(event);

        m_currentAttackEvent = event;

        // Execute response
        ExecuteResponse(event);

        // Notify callbacks
        NotifyAttackCallbacks(event);
    }

    void TriggerPatternDetection(const DetectedCommandPattern& pattern) {
        SS_LOG_WARN(LOG_CATEGORY, L"Command pattern detected: %hs (MITRE: %hs)",
            std::string(GetInputPatternTypeName(pattern.patternType)).c_str(),
            pattern.mitreAttackId.c_str());

        m_attackInProgress = true;
        m_stats.attacksDetected++;

        // Create or update attack event
        if (!m_currentAttackEvent) {
            BadUSBAttackEvent event;
            event.eventId = m_nextEventId++;
            event.analysisResult = DeviceAnalysisResult::Suspicious;
            event.confidence = DetectionConfidence::High;
            event.inputStats = CalculateInputStatistics();
            event.reconstructedBuffer = m_commandBuffer;
            event.detectionTime = std::chrono::system_clock::now();
            m_currentAttackEvent = event;
        }

        m_currentAttackEvent->detectedPatterns.push_back(pattern);
        m_currentAttackEvent->riskScore = CalculateRiskScore(*m_currentAttackEvent);
        m_currentAttackEvent->responseTaken = DetermineResponse(*m_currentAttackEvent);
        m_currentAttackEvent->detectionReason = "Command pattern: " +
            std::string(GetInputPatternTypeName(pattern.patternType));

        // Execute response
        ExecuteResponse(*m_currentAttackEvent);

        // Notify callbacks
        NotifyAttackCallbacks(*m_currentAttackEvent);
    }

    [[nodiscard]] int CalculateRiskScore(const BadUSBAttackEvent& event) {
        int score = 0;

        // Base score from analysis result
        switch (event.analysisResult) {
            case DeviceAnalysisResult::KnownBadDevice: score += 40; break;
            case DeviceAnalysisResult::MultipleInterfaces: score += 30; break;
            case DeviceAnalysisResult::Suspicious: score += 20; break;
            default: break;
        }

        // Add pattern scores
        for (const auto& pattern : event.detectedPatterns) {
            score += pattern.riskScore / 2;  // Partial contribution
        }

        // Adjust for input statistics
        if (event.inputStats.currentCPS > BadUSBConstants::BADUSB_CPS_THRESHOLD) {
            score += 20;
        }

        if (event.inputStats.usesSpecialCombos) {
            score += 15;
        }

        return std::min(100, score);
    }

    [[nodiscard]] BadUSBResponse DetermineResponse(const BadUSBAttackEvent& event) {
        if (event.riskScore >= 80) {
            return m_config.ejectOnDetection ?
                BadUSBResponse::BlockAndEject : BadUSBResponse::BlockAndAlert;
        }

        if (event.riskScore >= 50) {
            return BadUSBResponse::Block;
        }

        if (event.riskScore >= 25) {
            return BadUSBResponse::Monitor;
        }

        return BadUSBResponse::Allow;
    }

    void ExecuteResponse(const BadUSBAttackEvent& event) {
        SS_LOG_WARN(LOG_CATEGORY, L"Executing response: %hs (Risk: %d)",
            std::string(GetBadUSBResponseName(event.responseTaken)).c_str(),
            event.riskScore);

        switch (event.responseTaken) {
            case BadUSBResponse::BlockAndEject:
                ClearInputBuffer();
                if (!event.device.devicePath.empty()) {
                    EjectDevice(event.device.devicePath);
                }
                if (m_config.terminateLaunchedProcesses) {
                    TerminateLaunchedProcesses();
                }
                m_stats.attacksBlocked++;
                break;

            case BadUSBResponse::BlockAndAlert:
            case BadUSBResponse::Block:
                ClearInputBuffer();
                if (!event.device.devicePath.empty()) {
                    BlockDevice(event.device.devicePath);
                }
                m_stats.attacksBlocked++;
                break;

            case BadUSBResponse::Monitor:
                // Continue monitoring, log only
                break;

            case BadUSBResponse::Quarantine:
                ClearInputBuffer();
                // TODO: Implement quarantine
                break;

            case BadUSBResponse::Allow:
            default:
                break;
        }
    }

    void NotifyAttackCallbacks(const BadUSBAttackEvent& event) {
        for (const auto& callback : m_attackCallbacks) {
            try {
                callback(event);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Attack callback threw exception");
            }
        }
    }

    void NotifyError(const std::string& message, int code) {
        for (const auto& callback : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    BadUSBConfiguration m_config;

    // Keystroke analysis
    std::deque<KeystrokeEvent> m_keystrokeBuffer;
    std::string m_commandBuffer;
    HIDInputStatistics m_inputStats;

    // Modifier key state
    struct ModifierState {
        bool ctrl = false;
        bool shift = false;
        bool alt = false;
        bool win = false;
    } m_modifierState;

    // Attack state
    bool m_attackInProgress{false};
    std::optional<BadUSBAttackEvent> m_currentAttackEvent;
    uint64_t m_nextEventId{1};

    // Tracked devices
    std::unordered_map<std::string, HIDDeviceDescriptor> m_trackedDevices;

    // Statistics
    BadUSBStatistics m_stats;

    // Callbacks
    std::vector<AttackEventCallback> m_attackCallbacks;
    std::vector<DeviceAnalysisCallback> m_deviceCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
};

// ============================================================================
// BAD USB DETECTOR - SINGLETON IMPLEMENTATION
// ============================================================================

BadUSBDetector& BadUSBDetector::Instance() noexcept {
    static BadUSBDetector instance;
    return instance;
}

bool BadUSBDetector::HasInstance() noexcept {
    return s_instanceCreated.load();
}

BadUSBDetector::BadUSBDetector()
    : m_impl(std::make_unique<BadUSBDetectorImpl>()) {
    s_instanceCreated.store(true);
}

BadUSBDetector::~BadUSBDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false);
}

// ============================================================================
// LIFECYCLE DELEGATIONS
// ============================================================================

bool BadUSBDetector::Initialize(const BadUSBConfiguration& config) {
    return m_impl->Initialize(config);
}

void BadUSBDetector::Shutdown() {
    m_impl->Shutdown();
}

bool BadUSBDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus BadUSBDetector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool BadUSBDetector::UpdateConfiguration(const BadUSBConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

BadUSBConfiguration BadUSBDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// DEVICE ANALYSIS DELEGATIONS
// ============================================================================

DeviceAnalysisResult BadUSBDetector::AnalyzeDeviceDescriptor(const std::string& devicePath) {
    return m_impl->AnalyzeDeviceDescriptor(devicePath);
}

DeviceAnalysisResult BadUSBDetector::AnalyzeDevice(uint16_t vendorId, uint16_t productId) {
    return m_impl->AnalyzeDevice(vendorId, productId);
}

std::optional<HIDDeviceDescriptor> BadUSBDetector::GetDeviceDescriptor(
    const std::string& devicePath) {
    return m_impl->GetDeviceDescriptor(devicePath);
}

bool BadUSBDetector::IsKnownBadDevice(uint16_t vendorId, uint16_t productId) const noexcept {
    return m_impl->IsKnownBadDevice(vendorId, productId);
}

AttackDeviceType BadUSBDetector::IdentifyAttackDeviceType(
    uint16_t vendorId, uint16_t productId) const noexcept {
    return m_impl->IdentifyAttackDeviceType(vendorId, productId);
}

// ============================================================================
// INPUT ANALYSIS DELEGATIONS
// ============================================================================

void BadUSBDetector::ProcessKeyboardEvent(uint16_t virtualKey, bool isKeyDown,
                                           TimePoint timestamp, const std::string& deviceId) {
    m_impl->ProcessKeyboardEvent(virtualKey, isKeyDown, timestamp, deviceId);
}

bool BadUSBDetector::IsAttackInProgress() const noexcept {
    return m_impl->IsAttackInProgress();
}

HIDInputStatistics BadUSBDetector::GetCurrentInputStatistics() const {
    return m_impl->GetCurrentInputStatistics();
}

std::string BadUSBDetector::GetReconstructedBuffer() const {
    return m_impl->GetReconstructedBuffer();
}

void BadUSBDetector::ResetAnalysis() {
    m_impl->ResetAnalysis();
}

// ============================================================================
// RESPONSE ACTION DELEGATIONS
// ============================================================================

bool BadUSBDetector::BlockDevice(const std::string& devicePath) {
    return m_impl->BlockDevice(devicePath);
}

bool BadUSBDetector::EjectDevice(const std::string& devicePath) {
    return m_impl->EjectDevice(devicePath);
}

void BadUSBDetector::TerminateLaunchedProcesses() {
    m_impl->TerminateLaunchedProcesses();
}

void BadUSBDetector::ClearInputBuffer() {
    m_impl->ClearInputBuffer();
}

// ============================================================================
// CALLBACK DELEGATIONS
// ============================================================================

void BadUSBDetector::RegisterAttackCallback(AttackEventCallback callback) {
    m_impl->RegisterAttackCallback(std::move(callback));
}

void BadUSBDetector::RegisterDeviceCallback(DeviceAnalysisCallback callback) {
    m_impl->RegisterDeviceCallback(std::move(callback));
}

void BadUSBDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void BadUSBDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ============================================================================
// STATISTICS DELEGATIONS
// ============================================================================

BadUSBStatistics BadUSBDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void BadUSBDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool BadUSBDetector::SelfTest() {
    return m_impl->SelfTest();
}

std::string BadUSBDetector::GetVersionString() noexcept {
    return std::to_string(BadUSBConstants::VERSION_MAJOR) + "." +
           std::to_string(BadUSBConstants::VERSION_MINOR) + "." +
           std::to_string(BadUSBConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string HIDInputStatistics::ToJson() const {
    Utils::JSON::Json json;
    json["currentCPS"] = currentCPS;
    json["peakCPS"] = peakCPS;
    json["averageCPS"] = averageCPS;
    json["maxBurstLength"] = maxBurstLength;
    json["consistencyScore"] = consistencyScore;
    json["timingVarianceMs"] = timingVarianceMs;
    json["minIntervalUs"] = minInterval.count();
    json["maxIntervalUs"] = maxInterval.count();
    json["avgIntervalUs"] = avgInterval.count();
    json["totalKeystrokes"] = totalKeystrokes;
    json["usesSpecialCombos"] = usesSpecialCombos;
    json["winRDetected"] = winRDetected;
    json["ctrlEscDetected"] = ctrlEscDetected;
    return json.dump();
}

std::string HIDDeviceDescriptor::ToJson() const {
    Utils::JSON::Json json;
    json["vendorId"] = vendorId;
    json["productId"] = productId;
    json["devicePath"] = devicePath;
    json["instanceId"] = instanceId;
    json["manufacturer"] = manufacturer;
    json["product"] = product;
    json["serialNumber"] = serialNumber;
    json["classCode"] = classCode;
    json["subclassCode"] = subclassCode;
    json["protocolCode"] = protocolCode;
    json["interfaceCount"] = interfaceCount;
    json["isComposite"] = isComposite;
    json["hasHIDInterface"] = hasHIDInterface;
    json["hasMassStorage"] = hasMassStorage;
    return json.dump();
}

std::string DetectedCommandPattern::ToJson() const {
    Utils::JSON::Json json;
    json["patternType"] = static_cast<uint8_t>(patternType);
    json["patternTypeName"] = std::string(GetInputPatternTypeName(patternType));
    json["commandString"] = commandString;
    json["riskScore"] = riskScore;
    json["mitreAttackId"] = mitreAttackId;
    return json.dump();
}

std::string BadUSBAttackEvent::ToJson() const {
    Utils::JSON::Json json;
    json["eventId"] = eventId;

    Utils::JSON::Json deviceJson;
    Utils::JSON::Parse(device.ToJson(), deviceJson);
    json["device"] = deviceJson;

    json["analysisResult"] = static_cast<uint8_t>(analysisResult);
    json["analysisResultName"] = std::string(GetDeviceAnalysisResultName(analysisResult));
    json["attackType"] = static_cast<uint8_t>(attackType);
    json["attackTypeName"] = std::string(GetAttackDeviceTypeName(attackType));
    json["confidence"] = static_cast<uint8_t>(confidence);

    Utils::JSON::Json statsJson;
    Utils::JSON::Parse(inputStats.ToJson(), statsJson);
    json["inputStats"] = statsJson;

    json["detectedPatterns"] = Utils::JSON::Json::array();
    for (const auto& pattern : detectedPatterns) {
        Utils::JSON::Json patternJson;
        Utils::JSON::Parse(pattern.ToJson(), patternJson);
        json["detectedPatterns"].push_back(patternJson);
    }

    json["responseTaken"] = static_cast<uint8_t>(responseTaken);
    json["responseName"] = std::string(GetBadUSBResponseName(responseTaken));
    json["reconstructedBuffer"] = reconstructedBuffer;
    json["riskScore"] = riskScore;
    json["detectionReason"] = detectionReason;
    json["attackDurationMs"] = attackDuration.count();

    return json.dump();
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void BadUSBStatistics::Reset() noexcept {
    totalDevicesAnalyzed.store(0);
    knownBadDevicesDetected.store(0);
    suspiciousDevicesDetected.store(0);
    attacksDetected.store(0);
    attacksBlocked.store(0);
    superhumanInputDetected.store(0);
    commandInjectionDetected.store(0);
    totalKeystrokesAnalyzed.store(0);
    totalBurstEventsDetected.store(0);

    for (auto& counter : byDeviceType) {
        counter.store(0);
    }
    for (auto& counter : byPatternType) {
        counter.store(0);
    }

    startTime = Clock::now();
}

std::string BadUSBStatistics::ToJson() const {
    Utils::JSON::Json json;
    json["totalDevicesAnalyzed"] = totalDevicesAnalyzed.load();
    json["knownBadDevicesDetected"] = knownBadDevicesDetected.load();
    json["suspiciousDevicesDetected"] = suspiciousDevicesDetected.load();
    json["attacksDetected"] = attacksDetected.load();
    json["attacksBlocked"] = attacksBlocked.load();
    json["superhumanInputDetected"] = superhumanInputDetected.load();
    json["commandInjectionDetected"] = commandInjectionDetected.load();
    json["totalKeystrokesAnalyzed"] = totalKeystrokesAnalyzed.load();
    json["totalBurstEventsDetected"] = totalBurstEventsDetected.load();

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    json["uptimeSeconds"] = uptime;

    return json.dump();
}

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

bool BadUSBConfiguration::IsValid() const noexcept {
    if (maxAllowedCPS == 0 || maxAllowedCPS > 1000) {
        return false;
    }
    if (analysisWindowSize < 10 || analysisWindowSize > 10000) {
        return false;
    }
    if (minTimingVarianceMs < 0.0 || minTimingVarianceMs > 100.0) {
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetDeviceAnalysisResultName(DeviceAnalysisResult result) noexcept {
    switch (result) {
        case DeviceAnalysisResult::Safe:              return "Safe";
        case DeviceAnalysisResult::Suspicious:        return "Suspicious";
        case DeviceAnalysisResult::KnownBadDevice:    return "KnownBadDevice";
        case DeviceAnalysisResult::AnomalousDescriptor: return "AnomalousDescriptor";
        case DeviceAnalysisResult::MultipleInterfaces: return "MultipleInterfaces";
        case DeviceAnalysisResult::SpoofedVIDPID:     return "SpoofedVIDPID";
        case DeviceAnalysisResult::BlacklistedDevice: return "BlacklistedDevice";
        case DeviceAnalysisResult::Unknown:
        default:                                      return "Unknown";
    }
}

std::string_view GetInputPatternTypeName(InputPatternType type) noexcept {
    switch (type) {
        case InputPatternType::Normal:              return "Normal";
        case InputPatternType::SuperhumanSpeed:     return "SuperhumanSpeed";
        case InputPatternType::PerfectTiming:       return "PerfectTiming";
        case InputPatternType::BurstInput:          return "BurstInput";
        case InputPatternType::ScriptedSequence:    return "ScriptedSequence";
        case InputPatternType::CommandInjection:    return "CommandInjection";
        case InputPatternType::PrivilegeEscalation: return "PrivilegeEscalation";
        case InputPatternType::DownloadCradle:      return "DownloadCradle";
        case InputPatternType::PersistenceMechanism: return "PersistenceMechanism";
        case InputPatternType::ShellExecution:      return "ShellExecution";
        default:                                    return "Unknown";
    }
}

std::string_view GetAttackDeviceTypeName(AttackDeviceType type) noexcept {
    switch (type) {
        case AttackDeviceType::Unknown:     return "Unknown";
        case AttackDeviceType::RubberDucky: return "RubberDucky";
        case AttackDeviceType::BashBunny:   return "BashBunny";
        case AttackDeviceType::OMGCable:    return "OMGCable";
        case AttackDeviceType::Digispark:   return "Digispark";
        case AttackDeviceType::Teensy:      return "Teensy";
        case AttackDeviceType::Arduino:     return "Arduino";
        case AttackDeviceType::MalDuino:    return "MalDuino";
        case AttackDeviceType::P4wnP1:      return "P4wnP1";
        case AttackDeviceType::USBNinja:    return "USBNinja";
        case AttackDeviceType::HakCat:      return "HakCat";
        case AttackDeviceType::Custom:      return "Custom";
        default:                            return "Unknown";
    }
}

std::string_view GetBadUSBResponseName(BadUSBResponse response) noexcept {
    switch (response) {
        case BadUSBResponse::Allow:         return "Allow";
        case BadUSBResponse::Monitor:       return "Monitor";
        case BadUSBResponse::Block:         return "Block";
        case BadUSBResponse::BlockAndEject: return "BlockAndEject";
        case BadUSBResponse::BlockAndAlert: return "BlockAndAlert";
        case BadUSBResponse::Quarantine:    return "Quarantine";
        default:                            return "Unknown";
    }
}

bool IsVIDPIDKnownMalicious(uint16_t vid, uint16_t pid) noexcept {
    for (const auto& device : BadUSBConstants::KNOWN_BAD_DEVICES) {
        if (device.vendorId == vid && device.productId == pid) {
            return true;
        }
    }
    return false;
}

std::string FormatVIDPID(uint16_t vid, uint16_t pid) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0')
        << "VID_" << std::setw(4) << vid
        << "&PID_" << std::setw(4) << pid;
    return oss.str();
}

}  // namespace USB
}  // namespace ShadowStrike
