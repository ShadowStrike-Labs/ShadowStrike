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
 * - Per-device input buffer reconstruction and analysis
 * - Multi-window sliding CPS for slow-type evasion resistance
 * - Real-time response and countermeasures with process termination
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
#include "../Utils/ProcessUtils.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <numeric>
#include <cmath>

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
        std::regex(R"(pwsh.*-e[ncodema]*\s+[A-Za-z0-9+/=]+)", std::regex::icase),
        std::regex(R"(powershell.*DownloadFile)", std::regex::icase),
        std::regex(R"(pwsh.*IEX)", std::regex::icase),
    };

    // CMD execution patterns
    static const std::vector<std::regex> CMD_PATTERNS = {
        std::regex(R"(cmd\s*/c)", std::regex::icase),
        std::regex(R"(cmd\s*/k)", std::regex::icase),
        std::regex(R"(cmd\.exe)", std::regex::icase),
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

    // UAC bypass patterns
    static const std::vector<std::regex> UAC_BYPASS_PATTERNS = {
        std::regex(R"(fodhelper)", std::regex::icase),
        std::regex(R"(eventvwr)", std::regex::icase),
        std::regex(R"(computerdefaults)", std::regex::icase),
    };

    // Persistence mechanism patterns
    static const std::vector<std::regex> PERSISTENCE_PATTERNS = {
        std::regex(R"(\\Startup\\)", std::regex::icase),
        std::regex(R"(\\Run\\)", std::regex::icase),
        std::regex(R"(\\RunOnce\\)", std::regex::icase),
        std::regex(R"(schtasks.*\/create)", std::regex::icase),
        std::regex(R"(sc\s+create)", std::regex::icase),
        std::regex(R"(reg\s+add.*\\services\\)", std::regex::icase),
        std::regex(R"(reg\s+add.*\\Run)", std::regex::icase),
    };

    // Shell execution patterns
    static const std::vector<std::regex> SHELL_PATTERNS = {
        std::regex(R"(bash\s+-c)", std::regex::icase),
        std::regex(R"(wscript)", std::regex::icase),
        std::regex(R"(cscript)", std::regex::icase),
        std::regex(R"(mshta)", std::regex::icase),
        std::regex(R"(certutil.*-urlcache)", std::regex::icase),
        std::regex(R"(bitsadmin.*\/transfer)", std::regex::icase),
        std::regex(R"(\bcurl\s+.*http)", std::regex::icase),
        std::regex(R"(\bwget\s+.*http)", std::regex::icase),
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
    char character;
};

// ============================================================================
// PER-DEVICE ANALYSIS STATE
// ============================================================================

struct DeviceAnalysisState {
    std::deque<TimePoint> keystrokeTimes;
    std::string reconstructedBuffer;
    HIDInputStatistics stats;
    std::vector<DetectedCommandPattern> detectedPatterns;
    int cumulativeRiskScore = 0;
    TimePoint firstKeystroke;
    TimePoint lastKeystroke;
    bool attackDetected = false;
    TimePoint attackStartTime;

    struct ModifierState {
        bool ctrl = false;
        bool shift = false;
        bool alt = false;
        bool win = false;
    } modifierState;

    std::deque<KeystrokeEvent> keystrokeBuffer;
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BadUSBDetectorImpl {
public:
    BadUSBDetectorImpl() = default;
    ~BadUSBDetectorImpl() = default;

    BadUSBDetectorImpl(const BadUSBDetectorImpl&) = delete;
    BadUSBDetectorImpl& operator=(const BadUSBDetectorImpl&) = delete;
    BadUSBDetectorImpl(BadUSBDetectorImpl&&) = delete;
    BadUSBDetectorImpl& operator=(BadUSBDetectorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const BadUSBConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != BadUSBModuleStatus::Uninitialized &&
            m_status != BadUSBModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized or running");
            return false;
        }

        m_status = BadUSBModuleStatus::Initializing;

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration provided");
            m_status = BadUSBModuleStatus::Error;
            return false;
        }

        m_config = config;
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        m_deviceStates.clear();

        m_attackInProgress = false;
        m_currentAttackEvent = std::nullopt;
        m_nextEventId = 1;

        m_status = BadUSBModuleStatus::Running;

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

        if (m_status == BadUSBModuleStatus::Uninitialized ||
            m_status == BadUSBModuleStatus::Stopped) {
            return;
        }

        m_status = BadUSBModuleStatus::Stopping;

        m_attackCallbacks.clear();
        m_deviceCallbacks.clear();
        m_errorCallbacks.clear();

        m_deviceStates.clear();
        m_trackedDevices.clear();

        m_status = BadUSBModuleStatus::Stopped;

        SS_LOG_INFO(LOG_CATEGORY, L"BadUSBDetector shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status == BadUSBModuleStatus::Running ||
               m_status == BadUSBModuleStatus::Monitoring;
    }

    [[nodiscard]] BadUSBModuleStatus GetStatus() const noexcept {
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

        auto descriptor = GetDeviceDescriptorInternal(devicePath);
        if (!descriptor) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to get device descriptor: %hs",
                devicePath.c_str());
            return DeviceAnalysisResult::Unknown;
        }

        DeviceAnalysisResult result = AnalyzeDescriptor(*descriptor);

        m_trackedDevices[devicePath] = *descriptor;

        // Copy callbacks under lock, invoke outside
        auto callbacksCopy = m_deviceCallbacks;
        lock.unlock();

        for (const auto& callback : callbacksCopy) {
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

        if (IsKnownBadDeviceInternal(vendorId, productId)) {
            m_stats.knownBadDevicesDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"Known bad device detected: VID=%04X PID=%04X",
                vendorId, productId);
            return DeviceAnalysisResult::KnownBadDevice;
        }

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

        if (vendorId == 0x1FC9 && productId == 0x000C) {
            return AttackDeviceType::RubberDucky;
        }
        if (vendorId == 0x2E8A && productId == 0x000A) {
            return AttackDeviceType::BashBunny;
        }
        if (vendorId == 0x16D0 && productId == 0x0753) {
            return AttackDeviceType::Digispark;
        }
        if (vendorId == 0x16C0 && (productId == 0x0483 || productId == 0x0486)) {
            return AttackDeviceType::Teensy;
        }
        if (vendorId == 0x2341) {
            return AttackDeviceType::Arduino;
        }
        if (vendorId == 0x0483 && productId == 0x5740) {
            return AttackDeviceType::OMGCable;
        }
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

        auto& devState = GetOrCreateDeviceState_Locked(deviceId);

        UpdateModifierState(devState, virtualKey, isKeyDown);

        if (!isKeyDown) return;

        m_stats.totalKeystrokesAnalyzed++;

        KeystrokeEvent event;
        event.virtualKey = virtualKey;
        event.isKeyDown = isKeyDown;
        event.timestamp = timestamp;
        event.deviceId = deviceId;
        event.character = VirtualKeyToChar(devState, virtualKey);

        devState.keystrokeBuffer.push_back(event);
        devState.keystrokeTimes.push_back(timestamp);

        while (devState.keystrokeBuffer.size() > m_config.analysisWindowSize) {
            devState.keystrokeBuffer.pop_front();
        }
        while (devState.keystrokeTimes.size() > m_config.analysisWindowSize) {
            devState.keystrokeTimes.pop_front();
        }

        if (devState.firstKeystroke == TimePoint{}) {
            devState.firstKeystroke = timestamp;
        }
        devState.lastKeystroke = timestamp;

        if (event.character != 0) {
            devState.reconstructedBuffer.push_back(event.character);
            if (devState.reconstructedBuffer.size() > 8192) {
                devState.reconstructedBuffer.erase(0, 4096);
            }
        }

        DetectSpecialCombinations(devState, virtualKey);

        if (devState.keystrokeBuffer.size() >= 10) {
            PerformBehavioralAnalysis_Locked(devState, deviceId);
        }

        if (m_config.enableCommandPatternDetection &&
            devState.reconstructedBuffer.size() >= 10) {
            PerformCommandPatternAnalysis_Locked(devState, deviceId);
        }
    }

    [[nodiscard]] bool IsAttackInProgress() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_attackInProgress;
    }

    [[nodiscard]] HIDInputStatistics GetCurrentInputStatistics() const {
        std::shared_lock lock(m_mutex);
        // Aggregate across all devices
        HIDInputStatistics agg;
        for (const auto& [id, devState] : m_deviceStates) {
            auto stats = CalculateInputStatistics(devState);
            agg.totalKeystrokes += stats.totalKeystrokes;
            agg.peakCPS = std::max(agg.peakCPS, stats.peakCPS);
            if (stats.currentCPS > agg.currentCPS) {
                agg.currentCPS = stats.currentCPS;
                agg.timingVarianceMs = stats.timingVarianceMs;
                agg.consistencyScore = stats.consistencyScore;
                agg.minInterval = stats.minInterval;
                agg.maxInterval = stats.maxInterval;
                agg.avgInterval = stats.avgInterval;
                agg.maxBurstLength = stats.maxBurstLength;
            }
            agg.winRDetected |= stats.winRDetected;
            agg.ctrlEscDetected |= stats.ctrlEscDetected;
            agg.usesSpecialCombos |= stats.usesSpecialCombos;
        }
        return agg;
    }

    [[nodiscard]] std::string GetReconstructedBuffer() const {
        std::shared_lock lock(m_mutex);
        std::string combined;
        for (const auto& [id, devState] : m_deviceStates) {
            if (!devState.reconstructedBuffer.empty()) {
                if (!combined.empty()) combined += '\n';
                combined += devState.reconstructedBuffer;
            }
        }
        return combined;
    }

    // Public ResetAnalysis acquires lock, calls _Locked
    void ResetAnalysis() {
        std::unique_lock lock(m_mutex);
        ResetAnalysis_Locked();
    }

    // ========================================================================
    // RESPONSE ACTIONS — PUBLIC (acquire lock, delegate to _Locked)
    // ========================================================================

    [[nodiscard]] bool BlockDevice(const std::string& devicePath) {
        std::unique_lock lock(m_mutex);
        return BlockDevice_Locked(devicePath);
    }

    [[nodiscard]] bool EjectDevice(const std::string& devicePath) {
        std::unique_lock lock(m_mutex);
        return EjectDevice_Locked(devicePath);
    }

    void TerminateLaunchedProcesses() {
        std::unique_lock lock(m_mutex);
        TerminateLaunchedProcesses_Locked();
    }

    void ClearInputBuffer() {
        std::unique_lock lock(m_mutex);
        ClearInputBuffer_Locked();
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

    [[nodiscard]] BadUSBStatisticsSnapshot GetStatistics() const {
        std::shared_lock lock(m_mutex);
        BadUSBStatisticsSnapshot snap;
        snap.totalDevicesAnalyzed     = m_stats.totalDevicesAnalyzed.load(std::memory_order_relaxed);
        snap.knownBadDevicesDetected  = m_stats.knownBadDevicesDetected.load(std::memory_order_relaxed);
        snap.suspiciousDevicesDetected= m_stats.suspiciousDevicesDetected.load(std::memory_order_relaxed);
        snap.attacksDetected          = m_stats.attacksDetected.load(std::memory_order_relaxed);
        snap.attacksBlocked           = m_stats.attacksBlocked.load(std::memory_order_relaxed);
        snap.superhumanInputDetected  = m_stats.superhumanInputDetected.load(std::memory_order_relaxed);
        snap.commandInjectionDetected = m_stats.commandInjectionDetected.load(std::memory_order_relaxed);
        snap.totalKeystrokesAnalyzed  = m_stats.totalKeystrokesAnalyzed.load(std::memory_order_relaxed);
        snap.totalBurstEventsDetected = m_stats.totalBurstEventsDetected.load(std::memory_order_relaxed);
        for (size_t i = 0; i < snap.byDeviceType.size(); ++i) {
            snap.byDeviceType[i] = m_stats.byDeviceType[i].load(std::memory_order_relaxed);
        }
        for (size_t i = 0; i < snap.byPatternType.size(); ++i) {
            snap.byPatternType[i] = m_stats.byPatternType[i].load(std::memory_order_relaxed);
        }
        snap.startTime = m_stats.startTime;
        return snap;
    }

    void ResetStatistics() {
        std::unique_lock lock(m_mutex);
        m_stats.Reset();
    }

    // ========================================================================
    // SELF-TEST — No main-mutex hold; calls public methods sequentially
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Starting self-test...");

        try {
            // Test 1: Known bad device detection (public API, manages own lock)
            if (!IsKnownBadDevice(0x1FC9, 0x000C)) {
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
            auto result = AnalyzeDevice(0x046D, 0xC52B);
            if (result == DeviceAnalysisResult::KnownBadDevice) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: False positive on safe device");
                return false;
            }

            // Test 4: Keystroke processing
            {
                TimePoint now = Clock::now();
                for (int i = 0; i < 20; i++) {
                    ProcessKeyboardEvent(
                        static_cast<uint16_t>('A' + i), true,
                        now + std::chrono::milliseconds(i * 5), "SELFTEST");
                }

                auto stats = GetCurrentInputStatistics();
                if (stats.totalKeystrokes < 20) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Self-test failed: Keystroke count mismatch (got %llu)",
                        static_cast<unsigned long long>(stats.totalKeystrokes));
                    ResetAnalysis();
                    return false;
                }

                ResetAnalysis();
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Self-test completed successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // _LOCKED METHODS (caller already holds m_mutex)
    // ========================================================================

    void ResetAnalysis_Locked() {
        m_deviceStates.clear();
        m_attackInProgress = false;
        m_currentAttackEvent = std::nullopt;
        SS_LOG_INFO(LOG_CATEGORY, L"Analysis state reset");
    }

    [[nodiscard]] bool BlockDevice_Locked(const std::string& devicePath) {
        SS_LOG_WARN(LOG_CATEGORY, L"Blocking device: %hs", devicePath.c_str());

#ifdef _WIN32
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

    [[nodiscard]] bool EjectDevice_Locked(const std::string& devicePath) {
        SS_LOG_WARN(LOG_CATEGORY, L"Ejecting device: %hs", devicePath.c_str());

#ifdef _WIN32
        DEVINST devInst = 0;
        CONFIGRET cr = CM_Locate_DevNodeA(&devInst, const_cast<char*>(devicePath.c_str()),
            CM_LOCATE_DEVNODE_NORMAL);

        if (cr != CR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to locate device node: %lu",
                static_cast<unsigned long>(cr));
            return false;
        }

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
                static_cast<unsigned long>(cr), vetoName);
            return false;
        }
#else
        return false;
#endif
    }

    void TerminateLaunchedProcesses_Locked() {
        if (!m_config.terminateLaunchedProcesses) return;

        SS_LOG_WARN(LOG_CATEGORY, L"Terminating processes launched by BadUSB attack");

        static constexpr const wchar_t* kTargetProcesses[] = {
            L"powershell.exe",
            L"pwsh.exe",
            L"cmd.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"mshta.exe",
        };

        // Determine the attack start time. If unknown, use a 30-second window.
        TimePoint attackStart = Clock::now() - std::chrono::seconds(30);
        for (const auto& [id, state] : m_deviceStates) {
            if (state.attackDetected && state.attackStartTime != TimePoint{}) {
                if (state.attackStartTime < attackStart) {
                    attackStart = state.attackStartTime;
                }
            }
        }

        // Convert steady_clock attack start to system FILETIME for comparison
        auto sysNow = std::chrono::system_clock::now();
        auto steadyNow = Clock::now();
        auto attackAge = std::chrono::duration_cast<std::chrono::milliseconds>(
            steadyNow - attackStart);
        auto sysAttackStart = sysNow - attackAge;

        // Convert to FILETIME for process creation comparison
        auto sysEpoch = sysAttackStart.time_since_epoch();
        auto ftCount = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(
            sysEpoch).count();
        // Windows FILETIME epoch is Jan 1, 1601. system_clock is Jan 1, 1970.
        constexpr int64_t kEpochDiff = 116444736000000000LL;
        int64_t attackFt = ftCount + kEpochDiff;

        Utils::ProcessUtils::Error procErr;

        for (const auto& processName : kTargetProcesses) {
            procErr.Clear();
            auto pids = Utils::ProcessUtils::GetProcessIdsByName(processName, &procErr);
            if (procErr.HasError() || pids.empty()) {
                continue;
            }

            for (auto pid : pids) {
                // Check if process was created after attack start
                Utils::ProcessUtils::ProcessBasicInfo pInfo;
                procErr.Clear();
                if (!Utils::ProcessUtils::GetProcessBasicInfo(pid, pInfo, &procErr)) {
                    continue;
                }

                int64_t creationFt = (static_cast<int64_t>(pInfo.creationTime.dwHighDateTime) << 32) |
                                     static_cast<int64_t>(pInfo.creationTime.dwLowDateTime);

                if (creationFt < attackFt) {
                    // Process predates the attack — skip
                    continue;
                }

                SS_LOG_WARN(LOG_CATEGORY,
                    L"Terminating attack-spawned process: %ls (PID %lu)",
                    processName, static_cast<unsigned long>(pid));

                procErr.Clear();
                if (Utils::ProcessUtils::TerminateProcessTree(pid, 1, &procErr)) {
                    SS_LOG_INFO(LOG_CATEGORY,
                        L"Successfully terminated process tree for PID %lu",
                        static_cast<unsigned long>(pid));
                } else {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Failed to terminate PID %lu: %ls",
                        static_cast<unsigned long>(pid),
                        procErr.message.c_str());
                }
            }
        }
    }

    void ClearInputBuffer_Locked() {
        SS_LOG_INFO(LOG_CATEGORY, L"Clearing input buffer");

#ifdef _WIN32
        while (true) {
            MSG msg;
            if (!PeekMessageW(&msg, nullptr, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE)) {
                break;
            }
        }

        INPUT input{};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = 0;
        input.ki.dwFlags = KEYEVENTF_KEYUP;

        uint16_t modifiers[] = {VK_CONTROL, VK_SHIFT, VK_MENU, VK_LWIN, VK_RWIN};
        for (auto vk : modifiers) {
            input.ki.wVk = vk;
            SendInput(1, &input, sizeof(INPUT));
        }
#endif
    }

    // ========================================================================
    // PER-DEVICE STATE
    // ========================================================================

    [[nodiscard]] DeviceAnalysisState& GetOrCreateDeviceState_Locked(
        const std::string& deviceId) {

        auto it = m_deviceStates.find(deviceId);
        if (it != m_deviceStates.end()) {
            return it->second;
        }

        auto [newIt, _] = m_deviceStates.emplace(deviceId, DeviceAnalysisState{});
        return newIt->second;
    }

    // ========================================================================
    // PRIVATE HELPERS — Device descriptor & classification
    // ========================================================================

    [[nodiscard]] std::optional<HIDDeviceDescriptor> GetDeviceDescriptorInternal(
        const std::string& devicePath) const {

#ifdef _WIN32
        HIDDeviceDescriptor descriptor;
        descriptor.devicePath = devicePath;
        descriptor.firstSeen = std::chrono::system_clock::now();

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

        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(HIDD_ATTRIBUTES);
        if (HidD_GetAttributes(hDevice, &attributes)) {
            descriptor.vendorId = attributes.VendorID;
            descriptor.productId = attributes.ProductID;
        }

        wchar_t buffer[256] = {0};
        if (HidD_GetManufacturerString(hDevice, buffer, sizeof(buffer))) {
            descriptor.manufacturer = Utils::StringUtils::ToNarrow(buffer);
        }

        if (HidD_GetProductString(hDevice, buffer, sizeof(buffer))) {
            descriptor.product = Utils::StringUtils::ToNarrow(buffer);
        }

        if (HidD_GetSerialNumberString(hDevice, buffer, sizeof(buffer))) {
            descriptor.serialNumber = Utils::StringUtils::ToNarrow(buffer);
        }

        PHIDP_PREPARSED_DATA preparsedData = nullptr;
        if (HidD_GetPreparsedData(hDevice, &preparsedData)) {
            HIDP_CAPS caps{};
            if (HidP_GetCaps(preparsedData, &caps) == HIDP_STATUS_SUCCESS) {
                descriptor.hasHIDInterface = true;
                if (caps.UsagePage == HID_USAGE_PAGE_GENERIC) {
                    if (caps.Usage == HID_USAGE_GENERIC_KEYBOARD) {
                        descriptor.classCode = 0x03;
                        descriptor.subclassCode = 0x01;
                        descriptor.protocolCode = 0x01;
                    } else if (caps.Usage == HID_USAGE_GENERIC_MOUSE) {
                        descriptor.classCode = 0x03;
                        descriptor.subclassCode = 0x01;
                        descriptor.protocolCode = 0x02;
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
        if (IsKnownBadDeviceInternal(desc.vendorId, desc.productId)) {
            m_stats.knownBadDevicesDetected++;
            return DeviceAnalysisResult::KnownBadDevice;
        }

        if (desc.hasHIDInterface && desc.hasMassStorage) {
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::MultipleInterfaces;
        }

        if (desc.manufacturer.empty() && desc.product.empty()) {
            m_stats.suspiciousDevicesDetected++;
            return DeviceAnalysisResult::AnomalousDescriptor;
        }

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
    // KEYSTROKE ANALYSIS — per-device
    // ========================================================================

    static void UpdateModifierState(DeviceAnalysisState& devState,
                                    uint16_t virtualKey, bool isKeyDown) {
        switch (virtualKey) {
            case VK_CONTROL:
            case VK_LCONTROL:
            case VK_RCONTROL:
                devState.modifierState.ctrl = isKeyDown;
                break;
            case VK_SHIFT:
            case VK_LSHIFT:
            case VK_RSHIFT:
                devState.modifierState.shift = isKeyDown;
                break;
            case VK_MENU:
            case VK_LMENU:
            case VK_RMENU:
                devState.modifierState.alt = isKeyDown;
                break;
            case VK_LWIN:
            case VK_RWIN:
                devState.modifierState.win = isKeyDown;
                break;
        }
    }

    [[nodiscard]] static char VirtualKeyToChar(const DeviceAnalysisState& devState,
                                               uint16_t vk) {
        if (vk >= 'A' && vk <= 'Z') {
            return devState.modifierState.shift ?
                static_cast<char>(vk) : static_cast<char>(vk + 32);
        }
        if (vk >= '0' && vk <= '9') {
            return static_cast<char>(vk);
        }
        if (vk == VK_SPACE) return ' ';
        if (vk == VK_RETURN) return '\n';
        if (vk == VK_TAB) return '\t';

        if (devState.modifierState.shift) {
            switch (vk) {
                case VK_OEM_1: return ':';
                case VK_OEM_PLUS: return '+';
                case VK_OEM_COMMA: return '<';
                case VK_OEM_MINUS: return '_';
                case VK_OEM_PERIOD: return '>';
                case VK_OEM_2: return '?';
                case VK_OEM_3: return '~';
                case VK_OEM_4: return '{';
                case VK_OEM_5: return '|';
                case VK_OEM_6: return '}';
                case VK_OEM_7: return '"';
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

        return 0;
    }

    void DetectSpecialCombinations(DeviceAnalysisState& devState, uint16_t virtualKey) {
        if (devState.modifierState.win && virtualKey == 'R') {
            devState.stats.winRDetected = true;
            SS_LOG_WARN(LOG_CATEGORY, L"Win+R combination detected");
        }

        if (devState.modifierState.ctrl && virtualKey == VK_ESCAPE) {
            devState.stats.ctrlEscDetected = true;
        }

        if (devState.modifierState.alt && virtualKey == VK_TAB) {
            SS_LOG_INFO(LOG_CATEGORY, L"Alt+Tab detected during analysis");
        }

        if (devState.modifierState.ctrl && devState.modifierState.shift &&
            virtualKey == VK_ESCAPE) {
            SS_LOG_WARN(LOG_CATEGORY, L"Ctrl+Shift+Esc (Task Manager) detected");
        }

        if (devState.stats.winRDetected || devState.stats.ctrlEscDetected) {
            devState.stats.usesSpecialCombos = true;
        }
    }

    // ========================================================================
    // SLIDING WINDOW CPS CALCULATION
    // ========================================================================

    struct SlidingWindowCPS {
        double cps100ms  = 0.0;
        double cps1s     = 0.0;
        double cps5s     = 0.0;
        double cps30s    = 0.0;
    };

    [[nodiscard]] SlidingWindowCPS CalculateSlidingWindowCPS(
        const DeviceAnalysisState& devState, TimePoint now) const {

        SlidingWindowCPS result;
        const auto& times = devState.keystrokeTimes;
        if (times.empty()) return result;

        auto countInWindow = [&](std::chrono::milliseconds window) -> double {
            TimePoint cutoff = now - window;
            auto it = std::lower_bound(times.begin(), times.end(), cutoff);
            auto count = static_cast<double>(std::distance(it, times.end()));
            double windowSec = static_cast<double>(window.count()) / 1000.0;
            return (windowSec > 0.0) ? (count / windowSec) : 0.0;
        };

        result.cps100ms = countInWindow(std::chrono::milliseconds(100));
        result.cps1s    = countInWindow(std::chrono::milliseconds(1000));
        result.cps5s    = countInWindow(std::chrono::milliseconds(5000));
        result.cps30s   = countInWindow(std::chrono::milliseconds(30000));

        return result;
    }

    [[nodiscard]] HIDInputStatistics CalculateInputStatistics(
        const DeviceAnalysisState& devState) const {

        HIDInputStatistics stats;
        const auto& buf = devState.keystrokeBuffer;

        if (buf.size() < 2) {
            stats.totalKeystrokes = buf.size();
            return stats;
        }

        stats.totalKeystrokes = buf.size();
        stats.windowStart = buf.front().timestamp;

        std::vector<Duration> intervals;
        intervals.reserve(buf.size() - 1);

        for (size_t i = 1; i < buf.size(); i++) {
            auto interval = std::chrono::duration_cast<Duration>(
                buf[i].timestamp - buf[i-1].timestamp);
            intervals.push_back(interval);
        }

        if (intervals.empty()) {
            return stats;
        }

        auto [minIt, maxIt] = std::minmax_element(intervals.begin(), intervals.end());
        stats.minInterval = *minIt;
        stats.maxInterval = *maxIt;

        Duration total{0};
        for (const auto& interval : intervals) {
            total += interval;
        }
        stats.avgInterval = Duration(total.count() /
            static_cast<int64_t>(intervals.size()));

        auto windowDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            buf.back().timestamp - buf.front().timestamp);

        if (windowDuration.count() > 0) {
            stats.currentCPS = (static_cast<double>(buf.size()) * 1000.0) /
                               static_cast<double>(windowDuration.count());
        }

        stats.peakCPS = std::max(stats.peakCPS, stats.currentCPS);
        stats.averageCPS = stats.currentCPS;

        if (intervals.size() >= 2) {
            double mean = static_cast<double>(stats.avgInterval.count());
            double sumSquares = 0.0;

            for (const auto& interval : intervals) {
                double diff = static_cast<double>(interval.count()) - mean;
                sumSquares += diff * diff;
            }

            double variance = sumSquares / static_cast<double>(intervals.size());
            stats.timingVarianceMs = std::sqrt(variance) / 1000.0;

            stats.consistencyScore = std::min(1.0, stats.timingVarianceMs / 20.0);
        }

        uint32_t currentBurst = 0;
        for (const auto& interval : intervals) {
            if (interval.count() < BadUSBConstants::MIN_HUMAN_INTERVAL_MS * 1000) {
                currentBurst++;
                stats.maxBurstLength = std::max(stats.maxBurstLength, currentBurst);
            } else {
                currentBurst = 0;
            }
        }

        stats.winRDetected = devState.stats.winRDetected;
        stats.ctrlEscDetected = devState.stats.ctrlEscDetected;
        stats.usesSpecialCombos = devState.stats.usesSpecialCombos;

        return stats;
    }

    // ========================================================================
    // BEHAVIORAL ANALYSIS — multi-layer, per-device, _Locked
    // ========================================================================

    void PerformBehavioralAnalysis_Locked(DeviceAnalysisState& devState,
                                          const std::string& deviceId) {
        if (!m_config.enableBehavioralAnalysis) return;

        auto stats = CalculateInputStatistics(devState);
        auto now = devState.keystrokeBuffer.back().timestamp;
        auto windowCPS = CalculateSlidingWindowCPS(devState, now);

        bool isSuspicious = false;
        std::string reason;
        int riskIncrement = 0;

        // Layer 1: Superhuman typing speed (any window)
        double maxCPS = std::max({windowCPS.cps100ms, windowCPS.cps1s,
                                  windowCPS.cps5s, windowCPS.cps30s});
        if (maxCPS > static_cast<double>(m_config.maxAllowedCPS)) {
            isSuspicious = true;
            reason = "Superhuman typing speed detected: " +
                     std::to_string(static_cast<int>(maxCPS)) + " CPS";
            riskIncrement += 30;
            m_stats.superhumanInputDetected++;
        }

        // Layer 2: Short-window burst that exceeds human max even if long-window
        //          average is below threshold (catches slow-type with micro-bursts)
        if (windowCPS.cps100ms > static_cast<double>(BadUSBConstants::BADUSB_CPS_THRESHOLD) &&
            stats.totalKeystrokes > 5) {
            isSuspicious = true;
            reason = "Short-window burst detected: " +
                     std::to_string(static_cast<int>(windowCPS.cps100ms)) + " CPS (100ms)";
            riskIncrement += 25;
        }

        // Layer 3: Robotic timing variance
        if (stats.timingVarianceMs < m_config.minTimingVarianceMs &&
            stats.totalKeystrokes > 20) {
            isSuspicious = true;
            reason = "Robotic timing pattern detected (variance: " +
                     std::to_string(stats.timingVarianceMs) + "ms)";
            riskIncrement += 25;
        }

        // Layer 4: Burst input
        if (stats.maxBurstLength > BadUSBConstants::BURST_THRESHOLD) {
            isSuspicious = true;
            reason = "Input burst detected (" +
                     std::to_string(stats.maxBurstLength) + " rapid keystrokes)";
            riskIncrement += 20;
            m_stats.totalBurstEventsDetected++;
        }

        // Layer 5: Special combinations with elevated speed
        if (stats.usesSpecialCombos &&
            stats.currentCPS > static_cast<double>(BadUSBConstants::MAX_HUMAN_CPS)) {
            isSuspicious = true;
            reason = "Automated hotkey sequence detected";
            riskIncrement += 15;
        }

        // Accumulate cumulative risk score per device
        devState.cumulativeRiskScore += riskIncrement;

        // Clamp cumulative to 100
        if (devState.cumulativeRiskScore > 100) {
            devState.cumulativeRiskScore = 100;
        }

        if (isSuspicious || devState.cumulativeRiskScore >= 50) {
            TriggerAttackDetection_Locked(devState, deviceId,
                InputPatternType::SuperhumanSpeed, reason, stats);
        }
    }

    // ========================================================================
    // COMMAND PATTERN ANALYSIS — enhanced, _Locked
    // ========================================================================

    void PerformCommandPatternAnalysis_Locked(DeviceAnalysisState& devState,
                                              const std::string& deviceId) {
        std::string lowerBuffer = devState.reconstructedBuffer;
        std::transform(lowerBuffer.begin(), lowerBuffer.end(),
                       lowerBuffer.begin(), ::tolower);

        // Check PowerShell cradles
        for (const auto& pattern : CommandPatterns::POWERSHELL_CRADLES) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::DownloadCradle;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 90;
                detected.mitreAttackId = "T1059.001";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check UAC bypass patterns
        for (const auto& pattern : CommandPatterns::UAC_BYPASS_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::PrivilegeEscalation;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 95;
                detected.mitreAttackId = "T1548.002";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check privilege escalation
        for (const auto& pattern : CommandPatterns::PRIVESC_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::PrivilegeEscalation;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 95;
                detected.mitreAttackId = "T1548";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check persistence mechanisms
        for (const auto& pattern : CommandPatterns::PERSISTENCE_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::PersistenceMechanism;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 85;
                detected.mitreAttackId = "T1547";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                m_stats.commandInjectionDetected++;
                return;
            }
        }

        // Check CMD patterns
        for (const auto& pattern : CommandPatterns::CMD_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::CommandInjection;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 75;
                detected.mitreAttackId = "T1059.003";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                return;
            }
        }

        // Check shell execution
        for (const auto& pattern : CommandPatterns::SHELL_PATTERNS) {
            if (std::regex_search(lowerBuffer, pattern)) {
                DetectedCommandPattern detected;
                detected.patternType = InputPatternType::ShellExecution;
                detected.commandString = devState.reconstructedBuffer;
                detected.riskScore = 70;
                detected.mitreAttackId = "T1059";
                detected.detectionTime = Clock::now();

                TriggerPatternDetection_Locked(devState, deviceId, detected);
                return;
            }
        }
    }

    // ========================================================================
    // ATTACK TRIGGERING — _Locked versions
    // ========================================================================

    void TriggerAttackDetection_Locked(DeviceAnalysisState& devState,
                                        const std::string& deviceId,
                                        InputPatternType patternType,
                                        const std::string& reason,
                                        const HIDInputStatistics& stats) {

        SS_LOG_WARN(LOG_CATEGORY, L"BadUSB ATTACK DETECTED on device '%hs': %hs",
            deviceId.c_str(), reason.c_str());

        m_attackInProgress = true;
        devState.attackDetected = true;
        if (devState.attackStartTime == TimePoint{}) {
            devState.attackStartTime = Clock::now();
        }
        m_stats.attacksDetected++;

        BadUSBAttackEvent event;
        event.eventId = m_nextEventId++;
        event.analysisResult = DeviceAnalysisResult::Suspicious;
        event.attackType = AttackDeviceType::Unknown;
        event.confidence = DetectionConfidence::High;
        event.inputStats = stats;
        event.reconstructedBuffer = devState.reconstructedBuffer;
        event.detectionReason = reason;
        event.detectionTime = std::chrono::system_clock::now();

        DetectedCommandPattern pattern;
        pattern.patternType = patternType;
        pattern.commandString = devState.reconstructedBuffer;
        pattern.riskScore = 80;
        pattern.detectionTime = Clock::now();
        event.detectedPatterns.push_back(pattern);

        event.riskScore = CalculateRiskScore(event, devState);
        event.responseTaken = DetermineResponse(event);

        m_currentAttackEvent = event;

        // Execute response — calls _Locked versions (no re-lock)
        ExecuteResponse_Locked(event);

        // Copy callbacks under lock, invoke outside
        auto callbacksCopy = m_attackCallbacks;
        // We need to release the lock before invoking callbacks, but we are
        // called from within ProcessKeyboardEvent which holds the lock.
        // Store the callbacks for deferred invocation after we finish processing.
        m_pendingAttackEvents.push_back(event);
        m_pendingAttackCallbacks = callbacksCopy;
    }

    void TriggerPatternDetection_Locked(DeviceAnalysisState& devState,
                                         const std::string& deviceId,
                                         const DetectedCommandPattern& pattern) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"Command pattern detected on device '%hs': %hs (MITRE: %hs)",
            deviceId.c_str(),
            std::string(GetInputPatternTypeName(pattern.patternType)).c_str(),
            pattern.mitreAttackId.c_str());

        m_attackInProgress = true;
        devState.attackDetected = true;
        if (devState.attackStartTime == TimePoint{}) {
            devState.attackStartTime = Clock::now();
        }
        m_stats.attacksDetected++;
        devState.cumulativeRiskScore += pattern.riskScore / 2;
        if (devState.cumulativeRiskScore > 100) {
            devState.cumulativeRiskScore = 100;
        }

        if (!m_currentAttackEvent) {
            BadUSBAttackEvent event;
            event.eventId = m_nextEventId++;
            event.analysisResult = DeviceAnalysisResult::Suspicious;
            event.confidence = DetectionConfidence::High;
            event.inputStats = CalculateInputStatistics(devState);
            event.reconstructedBuffer = devState.reconstructedBuffer;
            event.detectionTime = std::chrono::system_clock::now();
            m_currentAttackEvent = event;
        }

        m_currentAttackEvent->detectedPatterns.push_back(pattern);
        devState.detectedPatterns.push_back(pattern);
        m_currentAttackEvent->riskScore = CalculateRiskScore(
            *m_currentAttackEvent, devState);
        m_currentAttackEvent->responseTaken = DetermineResponse(*m_currentAttackEvent);
        m_currentAttackEvent->detectionReason = "Command pattern: " +
            std::string(GetInputPatternTypeName(pattern.patternType));

        ExecuteResponse_Locked(*m_currentAttackEvent);

        auto callbacksCopy = m_attackCallbacks;
        m_pendingAttackEvents.push_back(*m_currentAttackEvent);
        m_pendingAttackCallbacks = callbacksCopy;
    }

    [[nodiscard]] int CalculateRiskScore(const BadUSBAttackEvent& event,
                                          const DeviceAnalysisState& devState) {
        int score = devState.cumulativeRiskScore;

        switch (event.analysisResult) {
            case DeviceAnalysisResult::KnownBadDevice: score += 40; break;
            case DeviceAnalysisResult::MultipleInterfaces: score += 30; break;
            case DeviceAnalysisResult::Suspicious: score += 20; break;
            default: break;
        }

        for (const auto& pattern : event.detectedPatterns) {
            score += pattern.riskScore / 2;
        }

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

    void ExecuteResponse_Locked(const BadUSBAttackEvent& event) {
        SS_LOG_WARN(LOG_CATEGORY, L"Executing response: %hs (Risk: %d)",
            std::string(GetBadUSBResponseName(event.responseTaken)).c_str(),
            event.riskScore);

        switch (event.responseTaken) {
            case BadUSBResponse::BlockAndEject:
                ClearInputBuffer_Locked();
                if (!event.device.devicePath.empty()) {
                    EjectDevice_Locked(event.device.devicePath);
                }
                if (m_config.terminateLaunchedProcesses) {
                    TerminateLaunchedProcesses_Locked();
                }
                m_stats.attacksBlocked++;
                break;

            case BadUSBResponse::BlockAndAlert:
            case BadUSBResponse::Block:
                ClearInputBuffer_Locked();
                if (!event.device.devicePath.empty()) {
                    BlockDevice_Locked(event.device.devicePath);
                }
                if (m_config.terminateLaunchedProcesses) {
                    TerminateLaunchedProcesses_Locked();
                }
                m_stats.attacksBlocked++;
                break;

            case BadUSBResponse::Monitor:
                break;

            case BadUSBResponse::Quarantine:
                // HID-based attacks have no file to quarantine directly.
                // Clear input buffer and escalate to USBDeviceMonitor for
                // device-level quarantine.
                ClearInputBuffer_Locked();
                if (!event.device.devicePath.empty()) {
                    BlockDevice_Locked(event.device.devicePath);
                }
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Quarantine requested for HID device — "
                    L"escalating to USBDeviceMonitor for device-level quarantine");
                m_stats.attacksBlocked++;
                break;

            case BadUSBResponse::Allow:
            default:
                break;
        }
    }

    void NotifyError(const std::string& message, int code) {
        // Copy callbacks under lock, invoke outside
        auto callbacksCopy = m_errorCallbacks;
        // Release lock not possible here as callers may/may not hold it.
        // Since error callbacks are rare, invoke inline with exception guard.
        for (const auto& callback : callbacksCopy) {
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
    BadUSBModuleStatus m_status{BadUSBModuleStatus::Uninitialized};
    BadUSBConfiguration m_config;

    // Per-device analysis state (keyed by deviceId)
    std::unordered_map<std::string, DeviceAnalysisState> m_deviceStates;

    // Attack state
    bool m_attackInProgress{false};
    std::optional<BadUSBAttackEvent> m_currentAttackEvent;
    uint64_t m_nextEventId{1};

    // Tracked device descriptors
    std::unordered_map<std::string, HIDDeviceDescriptor> m_trackedDevices;

    // Statistics
    BadUSBStatistics m_stats;

    // Callbacks
    std::vector<AttackEventCallback> m_attackCallbacks;
    std::vector<DeviceAnalysisCallback> m_deviceCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Deferred callback invocation storage
    std::vector<BadUSBAttackEvent> m_pendingAttackEvents;
    std::vector<AttackEventCallback> m_pendingAttackCallbacks;

    // Grant outer ProcessKeyboardEvent access to flush pending callbacks
    friend class BadUSBDetector;
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

BadUSBModuleStatus BadUSBDetector::GetStatus() const noexcept {
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

    // Flush any pending attack callbacks OUTSIDE the lock
    std::vector<BadUSBAttackEvent> pendingEvents;
    std::vector<AttackEventCallback> pendingCallbacks;
    {
        std::unique_lock lock(m_impl->m_mutex);
        pendingEvents.swap(m_impl->m_pendingAttackEvents);
        pendingCallbacks.swap(m_impl->m_pendingAttackCallbacks);
    }
    for (const auto& event : pendingEvents) {
        for (const auto& cb : pendingCallbacks) {
            try {
                cb(event);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Attack callback threw exception");
            }
        }
    }
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

BadUSBStatisticsSnapshot BadUSBDetector::GetStatistics() const {
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

std::string BadUSBStatisticsSnapshot::ToJson() const {
    Utils::JSON::Json json;
    json["totalDevicesAnalyzed"] = totalDevicesAnalyzed;
    json["knownBadDevicesDetected"] = knownBadDevicesDetected;
    json["suspiciousDevicesDetected"] = suspiciousDevicesDetected;
    json["attacksDetected"] = attacksDetected;
    json["attacksBlocked"] = attacksBlocked;
    json["superhumanInputDetected"] = superhumanInputDetected;
    json["commandInjectionDetected"] = commandInjectionDetected;
    json["totalKeystrokesAnalyzed"] = totalKeystrokesAnalyzed;
    json["totalBurstEventsDetected"] = totalBurstEventsDetected;

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
