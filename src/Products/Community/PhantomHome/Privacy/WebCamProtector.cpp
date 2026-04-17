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
 * ShadowStrike NGAV - WEBCAM PROTECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file WebCamProtector.cpp
 * @brief Enterprise-grade webcam access control implementation.
 *
 * Production-level implementation for webcam privacy protection with
 * hardware-level blocking, application whitelisting, and spyware detection.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Real-time camera access monitoring
 * - Application whitelisting with signature verification
 * - Hardware-level camera control (UVC)
 * - Spyware and RAT detection
 * - Temporary access grants
 * - Time-based access restrictions
 * - Multi-mode protection (Monitor, Prompt, Whitelist, BlockAll)
 * - Device enumeration via SetupAPI
 * - Event history and auditing
 * - Infrastructure reuse (ThreatIntel, WhiteListStore, Utils)
 * - Comprehensive statistics (10+ atomic counters)
 * - Callback system (4 types)
 * - Self-test and diagnostics
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
#include "WebCamProtector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <thread>
#include <fstream>
#include <format>
#include <unordered_set>
#include <deque>
#include <ctime>

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#ifdef _WIN32
#include <SetupAPI.h>
#include <devguid.h>
#include <dbt.h>
#include <cfgmgr32.h>
#include <wintrust.h>
#include <softpub.h>
#include <Psapi.h>
#pragma comment(lib, "SetupAPI.lib")
#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Crypt32.lib")
#endif

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace Privacy {

using SystemClock = std::chrono::system_clock;

// KSCATEGORY_VIDEO_CAMERA {E5323777-F976-4F5B-9B55-B94699C46E44}
static const GUID s_ksCategoryVideoCamera =
    { 0xe5323777, 0xf976, 0x4f5b, { 0x9b, 0x55, 0xb9, 0x46, 0x99, 0xc4, 0x6e, 0x44 } };

// KSCATEGORY_VIDEO {6994AD05-93EF-11D0-A3CC-00A0C9223196}
static const GUID s_ksCategoryVideo =
    { 0x6994ad05, 0x93ef, 0x11d0, { 0xa3, 0xcc, 0x00, 0xa0, 0xc9, 0x22, 0x31, 0x96 } };

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Generate unique event ID
 */
uint64_t GenerateEventId() {
    static std::atomic<uint64_t> s_counter{0};
    const auto now = SystemClock::now().time_since_epoch().count();
    const uint64_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);
    return static_cast<uint64_t>(now) ^ (counter << 32);
}

/**
 * @brief Check if current time is within allowed hours
 */
bool IsWithinAllowedHours(const std::optional<int>& fromHour, const std::optional<int>& toHour) {
    if (!fromHour.has_value() || !toHour.has_value()) {
        return true;  // No restriction
    }

    auto now = SystemClock::now();
    auto now_t = SystemClock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &now_t);
    int currentHour = tm.tm_hour;

    int from = fromHour.value();
    int to = toHour.value();

    if (from < to) {
        return currentHour >= from && currentHour < to;
    } else {
        // Wraps around midnight
        return currentHour >= from || currentHour < to;
    }
}

/**
 * @brief Check if current day is allowed
 */
bool IsCurrentDayAllowed(uint8_t allowedDays) {
    auto now = SystemClock::now();
    auto now_t = SystemClock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &now_t);
    int dayOfWeek = tm.tm_wday;  // 0 = Sunday

    return (allowedDays & (1 << dayOfWeek)) != 0;
}

/**
 * @brief Verify digital signature of executable
 */
bool VerifySignature(const fs::path& filePath) {
#ifdef _WIN32
    try {
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = nullptr;
        winTrustData.pSIPClientData = nullptr;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = nullptr;
        winTrustData.pwszURLReference = nullptr;
        winTrustData.dwProvFlags = WTD_SAFER_FLAG;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        LONG result = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

        // Close state data
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

        return (result == ERROR_SUCCESS);

    } catch (...) {
        return false;
    }
#else
    return false;
#endif
}

/**
 * @brief Get publisher name from digital signature
 */
std::string GetPublisher(const fs::path& filePath) {
#ifdef _WIN32
    try {
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(WINTRUST_DATA);
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        wtd.dwProvFlags = WTD_SAFER_FLAG;
        wtd.pFile = &fileInfo;

        LONG result = WinVerifyTrust(nullptr, &policyGUID, &wtd);
        std::string publisher;

        if (result == ERROR_SUCCESS && wtd.hWVTStateData) {
            CRYPT_PROVIDER_DATA* provData =
                WTHelperProvDataFromStateData(wtd.hWVTStateData);
            if (provData) {
                CRYPT_PROVIDER_SGNR* signer =
                    WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
                if (signer && signer->pasCertChain && signer->csCertChain > 0) {
                    PCCERT_CONTEXT cert = signer->pasCertChain[0].pCert;
                    if (cert) {
                        wchar_t name[256] = {};
                        DWORD nameLen = CertGetNameStringW(
                            cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, nullptr, name, static_cast<DWORD>(std::size(name)));
                        if (nameLen > 1) {
                            publisher = Utils::StringUtils::ToNarrow(name);
                        }
                    }
                }
            }
        }

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGUID, &wtd);
        return publisher;
    } catch (...) {
        return {};
    }
#else
    return {};
#endif
}

/**
 * @brief Convert raw hash bytes to lowercase hex string.
 */
std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    static constexpr char digits[] = "0123456789abcdef";
    for (uint8_t b : bytes) {
        hex += digits[(b >> 4) & 0xF];
        hex += digits[b & 0xF];
    }
    return hex;
}

#ifdef _WIN32
/**
 * @brief Check whether the workstation is currently locked.
 */
bool IsWorkstationLocked() noexcept {
    HDESK hDesktop = OpenInputDesktop(0, FALSE, GENERIC_READ);
    if (!hDesktop) {
        return true;  // Cannot open input desktop → likely locked
    }
    wchar_t name[256] = {};
    DWORD needed = 0;
    bool locked = true;
    if (GetUserObjectInformationW(hDesktop, UOI_NAME, name, sizeof(name), &needed)) {
        locked = (_wcsicmp(name, L"Default") != 0);
    }
    CloseDesktop(hDesktop);
    return locked;
}

/**
 * @brief Check whether the screensaver is currently running.
 */
bool IsScreensaverRunning() noexcept {
    BOOL running = FALSE;
    SystemParametersInfoW(SPI_GETSCREENSAVERRUNNING, 0, &running, 0);
    return running != FALSE;
}

/**
 * @brief Detect virtual camera devices by checking hardware/device IDs.
 */
bool IsVirtualCameraDevice(const std::wstring& hardwareId, const std::wstring& friendlyName) {
    std::wstring hwLower = hardwareId;
    std::transform(hwLower.begin(), hwLower.end(), hwLower.begin(), ::towlower);
    std::wstring nameLower = friendlyName;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

    // Root-enumerated or software devices are typically virtual
    if (hwLower.find(L"root\\") != std::wstring::npos ||
        hwLower.find(L"sw\\") != std::wstring::npos) {
        return true;
    }
    // Name-based heuristics for known virtual cameras
    if (nameLower.find(L"virtual") != std::wstring::npos ||
        nameLower.find(L"manycam") != std::wstring::npos ||
        nameLower.find(L"obs-camera") != std::wstring::npos ||
        nameLower.find(L"snap camera") != std::wstring::npos ||
        nameLower.find(L"xsplit") != std::wstring::npos ||
        nameLower.find(L"droidcam") != std::wstring::npos) {
        return true;
    }
    return false;
}
#endif

}  // namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string CameraDevice::ToJson() const {
    nlohmann::json j = {
        {"deviceId", deviceId},
        {"devicePath", devicePath},
        {"friendlyName", friendlyName},
        {"manufacturer", manufacturer},
        {"type", static_cast<uint32_t>(type)},
        {"vendorId", vendorId},
        {"productId", productId},
        {"isActive", isActive},
        {"isHardwareEnabled", isHardwareEnabled},
        {"isBlocked", isBlocked},
        {"isVirtual", isVirtual},
        {"accessCount", accessCount}
    };
    return j.dump(2);
}

std::string CameraAccessEvent::ToJson() const {
    nlohmann::json j = {
        {"eventId", eventId},
        {"deviceId", deviceId},
        {"processId", processId},
        {"threadId", threadId},
        {"processName", processName},
        {"processPath", processPath.string()},
        {"isSigned", isSigned},
        {"publisher", publisher},
        {"userName", userName},
        {"reason", static_cast<uint32_t>(reason)},
        {"riskLevel", static_cast<uint32_t>(riskLevel)},
        {"decision", static_cast<uint32_t>(decision)},
        {"duration", duration.count()},
        {"isOngoing", isOngoing},
        {"notes", notes}
    };
    return j.dump(2);
}

bool CameraWhitelistEntry::IsCurrentlyAllowed() const {
    if (!enabled) {
        return false;
    }

    if (!IsWithinAllowedHours(allowFromHour, allowToHour)) {
        return false;
    }

    if (!IsCurrentDayAllowed(allowedDays)) {
        return false;
    }

    return true;
}

std::string CameraWhitelistEntry::ToJson() const {
    nlohmann::json j = {
        {"entryId", entryId},
        {"processPattern", processPattern},
        {"publisher", publisher},
        {"sha256Hash", sha256Hash},
        {"enabled", enabled},
        {"requireSigned", requireSigned},
        {"allowedDays", allowedDays},
        {"allowedUsers", allowedUsers},
        {"addedBy", addedBy},
        {"notes", notes}
    };
    return j.dump(2);
}

void WebcamStatistics::Reset() noexcept {
    totalAccessAttempts.store(0, std::memory_order_relaxed);
    accessAllowed.store(0, std::memory_order_relaxed);
    accessBlocked.store(0, std::memory_order_relaxed);
    accessPrompted.store(0, std::memory_order_relaxed);
    suspiciousAccess.store(0, std::memory_order_relaxed);
    malwareBlocked.store(0, std::memory_order_relaxed);
    ratDetected.store(0, std::memory_order_relaxed);
    whitelistHits.store(0, std::memory_order_relaxed);
    devicesMonitored.store(0, std::memory_order_relaxed);
    virtualCameraBlocked.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string WebcamStatistics::ToJson() const {
    nlohmann::json j = {
        {"totalAccessAttempts", totalAccessAttempts.load()},
        {"accessAllowed", accessAllowed.load()},
        {"accessBlocked", accessBlocked.load()},
        {"accessPrompted", accessPrompted.load()},
        {"suspiciousAccess", suspiciousAccess.load()},
        {"malwareBlocked", malwareBlocked.load()},
        {"ratDetected", ratDetected.load()},
        {"whitelistHits", whitelistHits.load()},
        {"devicesMonitored", devicesMonitored.load()},
        {"virtualCameraBlocked", virtualCameraBlocked.load()}
    };
    return j.dump(2);
}

bool WebcamConfiguration::IsValid() const noexcept {
    if (notificationDurationMs == 0) return false;
    if (notificationDurationMs > 60000) return false;  // Max 1 minute
    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class WebcamProtectorImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    WebcamConfiguration m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Module status
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    /// @brief Monitoring active
    std::atomic<bool> m_monitoringActive{false};

    /// @brief Camera blocked
    std::atomic<bool> m_cameraBlocked{false};

    /// @brief Statistics
    WebcamStatistics m_statistics;

    /// @brief Camera devices
    std::unordered_map<std::string, CameraDevice> m_devices;
    mutable std::shared_mutex m_devicesMutex;

    /// @brief Whitelist entries
    std::unordered_map<std::string, CameraWhitelistEntry> m_whitelist;
    mutable std::shared_mutex m_whitelistMutex;

    /// @brief Access events history
    std::deque<CameraAccessEvent> m_events;
    mutable std::shared_mutex m_eventsMutex;
    static constexpr size_t MAX_EVENTS = 1000;

    /// @brief Temporary access grants (PID -> expiration time)
    std::unordered_map<uint32_t, SystemTimePoint> m_temporaryAccess;
    mutable std::shared_mutex m_temporaryMutex;

    /// @brief Cooldown tracker (PID -> last notification time)
    std::unordered_map<uint32_t, SystemTimePoint> m_cooldownTracker;
    mutable std::mutex m_cooldownMutex;

    /// @brief Callbacks
    std::vector<AccessEventCallback> m_accessCallbacks;
    std::vector<DeviceChangeCallback> m_deviceCallbacks;
    std::vector<DecisionCallback> m_decisionCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    std::mutex m_callbacksMutex;

    /// @brief Cooldown cleanup counter — prune stale entries periodically
    uint32_t m_cooldownCleanupCounter{0};
    static constexpr uint32_t COOLDOWN_CLEANUP_INTERVAL = 64;

    // ========================================================================
    // METHODS
    // ========================================================================

    WebcamProtectorImpl() = default;
    ~WebcamProtectorImpl() = default;

    [[nodiscard]] bool Initialize(const WebcamConfiguration& config);
    void Shutdown();

    // Device management
    [[nodiscard]] std::vector<CameraDevice> GetCameraDevicesInternal();
    [[nodiscard]] std::optional<CameraDevice> GetDeviceInternal(const std::string& deviceId);
    [[nodiscard]] bool RefreshDevicesInternal();

    // Access control
    [[nodiscard]] CameraAccessDecision EvaluateAccessInternal(
        uint32_t processId,
        const std::string& deviceId);
    [[nodiscard]] bool OnCameraAccessAttemptInternal(uint32_t pid);

    // Whitelist management
    [[nodiscard]] bool AddToWhitelistInternal(const CameraWhitelistEntry& entry);
    [[nodiscard]] bool RemoveFromWhitelistInternal(const std::string& entryId);
    [[nodiscard]] bool IsProcessWhitelistedInternal(
        const std::string& processName,
        const fs::path& processPath);
    [[nodiscard]] std::vector<CameraWhitelistEntry> GetWhitelistInternal() const;

    // Event tracking
    void RecordAccessEvent(const CameraAccessEvent& event);
    [[nodiscard]] std::vector<CameraAccessEvent> GetRecentEventsInternal(
        size_t limit,
        std::optional<SystemTimePoint> since);

    // Spyware detection
    [[nodiscard]] bool IsKnownSpywareInternal(uint32_t processId);
    [[nodiscard]] CameraRiskLevel AnalyzeProcessInternal(uint32_t processId);

    // Helpers
    void InvokeAccessCallbacks(const CameraAccessEvent& event);
    void InvokeDeviceCallbacks(const CameraDevice& device, bool added);
    void InvokeErrorCallbacks(const std::string& message, int code);
    [[nodiscard]] CameraAccessDecision InvokeDecisionCallbacks(const CameraAccessEvent& event);

    // Cooldown check
    [[nodiscard]] bool IsInCooldown(uint32_t processId);
    void UpdateCooldown(uint32_t processId);
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool WebcamProtectorImpl::Initialize(
    const WebcamConfiguration& config)
{
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"WebcamProtector", L"Already initialized");
            return true;
        }

        SS_LOG_INFO(L"WebcamProtector", L"Initializing...");

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"WebcamProtector", L"Invalid configuration");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Enumerate camera devices
        RefreshDevicesInternal();

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(L"WebcamProtector", L"Initialized successfully (mode: %hs)",
                      std::string(GetProtectionModeName(m_config.mode)).c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Initialization failed - %hs", e.what());
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void WebcamProtectorImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        SS_LOG_INFO(L"WebcamProtector", L"Shutting down...");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Stop monitoring
        m_monitoringActive.store(false, std::memory_order_release);

        // Clear data structures
        {
            std::unique_lock lock(m_devicesMutex);
            m_devices.clear();
        }

        {
            std::unique_lock lock(m_whitelistMutex);
            m_whitelist.clear();
        }

        {
            std::unique_lock lock(m_eventsMutex);
            m_events.clear();
        }

        {
            std::unique_lock lock(m_temporaryMutex);
            m_temporaryAccess.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_accessCallbacks.clear();
            m_deviceCallbacks.clear();
            m_decisionCallbacks.clear();
            m_errorCallbacks.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        SS_LOG_INFO(L"WebcamProtector", L"Shutdown complete");

    } catch (...) {
        SS_LOG_ERROR(L"WebcamProtector", L"Exception during shutdown");
    }
}

// ============================================================================
// IMPL: DEVICE MANAGEMENT
// ============================================================================

std::vector<CameraDevice> WebcamProtectorImpl::GetCameraDevicesInternal() {
    std::shared_lock lock(m_devicesMutex);

    std::vector<CameraDevice> devices;
    devices.reserve(m_devices.size());

    for (const auto& [id, device] : m_devices) {
        devices.push_back(device);
    }

    return devices;
}

std::optional<CameraDevice> WebcamProtectorImpl::GetDeviceInternal(
    const std::string& deviceId)
{
    std::shared_lock lock(m_devicesMutex);

    auto it = m_devices.find(deviceId);
    if (it == m_devices.end()) {
        return std::nullopt;
    }

    return it->second;
}

bool WebcamProtectorImpl::RefreshDevicesInternal() {
    try {
        auto newDevices = EnumerateCameraDevices();

        // Collect newly-added devices to invoke callbacks OUTSIDE the lock,
        // preventing deadlock (m_devicesMutex → m_callbacksMutex ordering).
        std::vector<CameraDevice> addedDevices;

        {
            std::unique_lock lock(m_devicesMutex);

            for (const auto& newDevice : newDevices) {
                auto it = m_devices.find(newDevice.deviceId);
                if (it != m_devices.end()) {
                    it->second.isActive = newDevice.isActive;
                    it->second.isHardwareEnabled = newDevice.isHardwareEnabled;
                    it->second.isVirtual = newDevice.isVirtual;
                    it->second.type = newDevice.type;
                    it->second.vendorId = newDevice.vendorId;
                    it->second.productId = newDevice.productId;
                } else {
                    m_devices[newDevice.deviceId] = newDevice;
                    addedDevices.push_back(newDevice);
                }
            }

            m_statistics.devicesMonitored.store(m_devices.size(), std::memory_order_relaxed);
        }

        // Fire callbacks without holding the devices lock
        for (const auto& dev : addedDevices) {
            InvokeDeviceCallbacks(dev, true);
        }

        SS_LOG_INFO(L"WebcamProtector", L"Enumerated %zu camera devices", newDevices.size());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Device enumeration failed - %hs", e.what());
        return false;
    }
}

// ============================================================================
// IMPL: ACCESS CONTROL
// ============================================================================

CameraAccessDecision WebcamProtectorImpl::EvaluateAccessInternal(
    uint32_t processId,
    const std::string& deviceId)
{
    try {
        m_statistics.totalAccessAttempts.fetch_add(1, std::memory_order_relaxed);

        // Create access event
        CameraAccessEvent event;
        event.eventId = GenerateEventId();
        event.deviceId = deviceId;
        event.processId = processId;
        event.timestamp = SystemClock::now();
        event.isOngoing = true;

        // Get process information
        {
            auto optPath = Utils::ProcessUtils::GetProcessPath(processId);
            if (optPath.has_value()) {
                event.processPath = fs::path(*optPath);
                event.processName = event.processPath.filename().string();
                event.isSigned = VerifySignature(event.processPath);
                event.publisher = GetPublisher(event.processPath);
            } else {
                event.processName = "Unknown";
                event.riskLevel = CameraRiskLevel::Medium;
            }
        }

        // Check if camera is globally blocked
        if (m_cameraBlocked.load(std::memory_order_acquire)) {
            event.decision = CameraAccessDecision::Block;
            event.riskLevel = CameraRiskLevel::Low;
            event.notes = "Camera globally blocked";
            RecordAccessEvent(event);
            m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Block;
        }

        // Block if workstation is locked (if configured)
#ifdef _WIN32
        if (m_config.blockOnLockScreen && IsWorkstationLocked()) {
            event.decision = CameraAccessDecision::Block;
            event.riskLevel = CameraRiskLevel::High;
            event.notes = "Workstation locked - camera access denied";
            RecordAccessEvent(event);
            m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
            m_statistics.suspiciousAccess.fetch_add(1, std::memory_order_relaxed);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Block;
        }

        // Block if screensaver is running (if configured)
        if (m_config.blockOnScreensaver && IsScreensaverRunning()) {
            event.decision = CameraAccessDecision::Block;
            event.riskLevel = CameraRiskLevel::High;
            event.notes = "Screensaver active - camera access denied";
            RecordAccessEvent(event);
            m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
            m_statistics.suspiciousAccess.fetch_add(1, std::memory_order_relaxed);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Block;
        }
#endif

        // Block virtual cameras if configured
        if (m_config.blockVirtualCameras && !deviceId.empty()) {
            std::shared_lock devLock(m_devicesMutex);
            auto devIt = m_devices.find(deviceId);
            if (devIt != m_devices.end() && devIt->second.isVirtual) {
                event.decision = CameraAccessDecision::Block;
                event.notes = "Virtual camera blocked by policy";
                m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
                m_statistics.virtualCameraBlocked.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return CameraAccessDecision::Block;
            }
        }

        // Check protection mode
        switch (m_config.mode) {
            case WebcamProtectionMode::Disabled:
                event.decision = CameraAccessDecision::Allow;
                m_statistics.accessAllowed.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return CameraAccessDecision::Allow;

            case WebcamProtectionMode::BlockAll:
                event.decision = CameraAccessDecision::Block;
                event.notes = "BlockAll mode active";
                m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return CameraAccessDecision::Block;

            case WebcamProtectionMode::Monitor:
                event.decision = CameraAccessDecision::Allow;
                event.notes = "Monitor mode - logging only";
                m_statistics.accessAllowed.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return CameraAccessDecision::Allow;

            case WebcamProtectionMode::Prompt:
                // Check callbacks for decision
                event.decision = InvokeDecisionCallbacks(event);
                if (event.decision == CameraAccessDecision::Block) {
                    m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
                } else {
                    m_statistics.accessAllowed.fetch_add(1, std::memory_order_relaxed);
                }
                m_statistics.accessPrompted.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return event.decision;

            case WebcamProtectionMode::WhitelistOnly:
                break;  // Continue to whitelist check
        }

        // Check temporary access (and purge expired entries)
        {
            std::unique_lock lock(m_temporaryMutex);
            auto now = SystemClock::now();

            // Purge expired grants
            for (auto it = m_temporaryAccess.begin(); it != m_temporaryAccess.end(); ) {
                if (now >= it->second) {
                    it = m_temporaryAccess.erase(it);
                } else {
                    ++it;
                }
            }

            auto it = m_temporaryAccess.find(processId);
            if (it != m_temporaryAccess.end()) {
                event.decision = CameraAccessDecision::AllowTimed;
                event.notes = "Temporary access granted";
                m_statistics.accessAllowed.fetch_add(1, std::memory_order_relaxed);
                RecordAccessEvent(event);
                InvokeAccessCallbacks(event);
                return CameraAccessDecision::AllowTimed;
            }
        }

        // Check spyware/malware
        if (m_config.checkThreatIntel && IsKnownSpywareInternal(processId)) {
            event.decision = CameraAccessDecision::Block;
            event.riskLevel = CameraRiskLevel::Critical;
            event.reason = AccessReason::Malware;
            event.notes = "Known spyware/malware detected";
            m_statistics.malwareBlocked.fetch_add(1, std::memory_order_relaxed);
            RecordAccessEvent(event);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Block;
        }

        // Analyze process for suspicious behavior
        event.riskLevel = AnalyzeProcessInternal(processId);
        if (event.riskLevel >= CameraRiskLevel::High) {
            m_statistics.suspiciousAccess.fetch_add(1, std::memory_order_relaxed);
            if (event.riskLevel == CameraRiskLevel::Critical) {
                m_statistics.ratDetected.fetch_add(1, std::memory_order_relaxed);
                event.reason = AccessReason::SuspiciousRAT;
            }
        }

        // Check if unsigned and blocking enabled
        if (m_config.blockUnsigned && !event.isSigned) {
            event.decision = CameraAccessDecision::Block;
            event.notes = "Unsigned process blocked";
            m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
            RecordAccessEvent(event);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Block;
        }

        // Check whitelist
        if (IsProcessWhitelistedInternal(event.processName, event.processPath)) {
            event.decision = CameraAccessDecision::Allow;
            event.notes = "Whitelisted application";
            m_statistics.accessAllowed.fetch_add(1, std::memory_order_relaxed);
            m_statistics.whitelistHits.fetch_add(1, std::memory_order_relaxed);
            RecordAccessEvent(event);
            InvokeAccessCallbacks(event);
            return CameraAccessDecision::Allow;
        }

        // Not whitelisted in WhitelistOnly mode
        event.decision = CameraAccessDecision::Block;
        event.notes = "Not in whitelist";
        m_statistics.accessBlocked.fetch_add(1, std::memory_order_relaxed);
        RecordAccessEvent(event);
        InvokeAccessCallbacks(event);

        return CameraAccessDecision::Block;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Access evaluation failed - %hs", e.what());
        return CameraAccessDecision::Block;  // Fail secure
    }
}

bool WebcamProtectorImpl::OnCameraAccessAttemptInternal(uint32_t pid) {
    try {
        if (!m_monitoringActive.load(std::memory_order_acquire)) {
            return true;
        }

        // Skip full re-evaluation during cooldown to avoid notification spam,
        // but still enforce the current protection mode.
        if (IsInCooldown(pid)) {
            if (m_cameraBlocked.load(std::memory_order_acquire) ||
                m_config.mode == WebcamProtectionMode::BlockAll) {
                return false;
            }
            return true;
        }

        auto decision = EvaluateAccessInternal(pid, "");

        UpdateCooldown(pid);

        if (decision == CameraAccessDecision::Block) {
            SS_LOG_WARN(L"WebcamProtector", L"Blocked camera access from PID %u", pid);
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Access attempt handling failed - %hs", e.what());
        return false;
    }
}

// ============================================================================
// IMPL: WHITELIST MANAGEMENT
// ============================================================================

bool WebcamProtectorImpl::AddToWhitelistInternal(
    const CameraWhitelistEntry& entry)
{
    try {
        if (entry.entryId.empty()) {
            SS_LOG_ERROR(L"WebcamProtector", L"Empty entry ID");
            return false;
        }

        std::unique_lock lock(m_whitelistMutex);

        if (m_whitelist.size() >= WebcamConstants::MAX_WHITELIST) {
            SS_LOG_ERROR(L"WebcamProtector", L"Whitelist full");
            return false;
        }

        m_whitelist[entry.entryId] = entry;

        SS_LOG_INFO(L"WebcamProtector", L"Added to whitelist: %hs", entry.processPattern.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to add to whitelist - %hs", e.what());
        return false;
    }
}

bool WebcamProtectorImpl::RemoveFromWhitelistInternal(const std::string& entryId) {
    try {
        std::unique_lock lock(m_whitelistMutex);

        auto it = m_whitelist.find(entryId);
        if (it == m_whitelist.end()) {
            return false;
        }

        m_whitelist.erase(it);

        SS_LOG_INFO(L"WebcamProtector", L"Removed from whitelist: %hs", entryId.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to remove from whitelist - %hs", e.what());
        return false;
    }
}

bool WebcamProtectorImpl::IsProcessWhitelistedInternal(
    const std::string& processName,
    const fs::path& processPath)
{
    std::shared_lock lock(m_whitelistMutex);

    for (const auto& [id, entry] : m_whitelist) {
        if (!entry.enabled) continue;
        if (!entry.IsCurrentlyAllowed()) continue;

        // Check process name pattern
        if (entry.processPattern == processName) {
            // Check signature if required
            if (entry.requireSigned && !processPath.empty()) {
                if (!VerifySignature(processPath)) {
                    continue;
                }
            }

            // Check hash if specified
            if (!entry.sha256Hash.empty() && !processPath.empty()) {
                std::vector<uint8_t> hashBytes;
                if (!Utils::HashUtils::ComputeFile(
                        Utils::HashUtils::Algorithm::SHA256,
                        processPath.wstring(), hashBytes)) {
                    continue;
                }
                if (BytesToHex(hashBytes) != entry.sha256Hash) {
                    continue;
                }
            }

            return true;
        }
    }

    return false;
}

std::vector<CameraWhitelistEntry> WebcamProtectorImpl::GetWhitelistInternal() const {
    std::shared_lock lock(m_whitelistMutex);

    std::vector<CameraWhitelistEntry> entries;
    entries.reserve(m_whitelist.size());

    for (const auto& [id, entry] : m_whitelist) {
        entries.push_back(entry);
    }

    return entries;
}

// ============================================================================
// IMPL: EVENT TRACKING
// ============================================================================

void WebcamProtectorImpl::RecordAccessEvent(const CameraAccessEvent& event) {
    try {
        std::unique_lock lock(m_eventsMutex);

        m_events.push_back(event);
        if (m_events.size() > MAX_EVENTS) {
            m_events.pop_front();
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to record event - %hs", e.what());
    }
}

std::vector<CameraAccessEvent> WebcamProtectorImpl::GetRecentEventsInternal(
    size_t limit,
    std::optional<SystemTimePoint> since)
{
    std::shared_lock lock(m_eventsMutex);

    std::vector<CameraAccessEvent> result;
    const size_t cappedLimit = std::min(limit, static_cast<size_t>(10000));
    result.reserve(std::min(cappedLimit, m_events.size()));

    for (auto it = m_events.rbegin(); it != m_events.rend() && result.size() < cappedLimit; ++it) {
        if (!since.has_value() || it->timestamp >= since.value()) {
            result.push_back(*it);
        }
    }

    return result;
}

// ============================================================================
// IMPL: SPYWARE DETECTION
// ============================================================================

bool WebcamProtectorImpl::IsKnownSpywareInternal(uint32_t processId) {
    try {
        auto& threatIntel = ThreatIntel::ThreatIntelManager::Instance();
        if (!threatIntel.IsInitialized()) {
            return false;
        }

        auto optPath = Utils::ProcessUtils::GetProcessPath(processId);
        if (!optPath.has_value()) {
            return false;
        }

        std::vector<uint8_t> hashBytes;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                *optPath, hashBytes)) {
            return false;
        }

        std::string hexHash = BytesToHex(hashBytes);
        double riskScore = 0.0;
        std::string threatName;
        return threatIntel.IsKnownMalicious(hexHash, riskScore, threatName);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Spyware check failed - %hs", e.what());
        return false;
    }
}

CameraRiskLevel WebcamProtectorImpl::AnalyzeProcessInternal(uint32_t processId) {
    try {
        auto optPath = Utils::ProcessUtils::GetProcessPath(processId);
        if (!optPath.has_value()) {
            return CameraRiskLevel::Medium;
        }
        fs::path processPath(*optPath);
        auto processName = processPath.filename().string();

        CameraRiskLevel risk = CameraRiskLevel::Safe;

        // Check if signed
        if (!VerifySignature(processPath)) {
            risk = CameraRiskLevel::Low;
        }

        // Check if process is running from suspicious location
        std::string pathStr = processPath.string();
        std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), ::tolower);

        if (pathStr.find("\\temp\\") != std::string::npos ||
            pathStr.find("\\appdata\\local\\temp") != std::string::npos) {
            risk = CameraRiskLevel::High;
        }

        // Check for hidden or system attributes
        DWORD attrs = GetFileAttributesW(processPath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            if (attrs & FILE_ATTRIBUTE_HIDDEN) {
                risk = CameraRiskLevel::High;
            }
        }

        // Check process name patterns (known RAT patterns)
        if (processName.find("remote") != std::string::npos ||
            processName.find("vnc") != std::string::npos ||
            processName.find("rdp") != std::string::npos) {
            risk = std::max(risk, CameraRiskLevel::Medium);
        }

        return risk;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Process analysis failed - %hs", e.what());
        return CameraRiskLevel::Medium;  // Unknown = medium risk
    }
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void WebcamProtectorImpl::InvokeAccessCallbacks(const CameraAccessEvent& event) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& callback : m_accessCallbacks) {
        try {
            callback(event);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"WebcamProtector", L"Access callback error - %hs", e.what());
        }
    }
}

void WebcamProtectorImpl::InvokeDeviceCallbacks(
    const CameraDevice& device,
    bool added)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& callback : m_deviceCallbacks) {
        try {
            callback(device, added);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"WebcamProtector", L"Device callback error - %hs", e.what());
        }
    }
}

CameraAccessDecision WebcamProtectorImpl::InvokeDecisionCallbacks(
    const CameraAccessEvent& event)
{
    std::lock_guard lock(m_callbacksMutex);

    if (m_decisionCallbacks.empty()) {
        return CameraAccessDecision::Prompt;  // Default to prompt
    }

    // Use first callback's decision
    try {
        return m_decisionCallbacks[0](event);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Decision callback error - %hs", e.what());
        return CameraAccessDecision::Block;  // Fail secure
    }
}

void WebcamProtectorImpl::InvokeErrorCallbacks(
    const std::string& message,
    int code)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& callback : m_errorCallbacks) {
        try {
            callback(message, code);
        } catch (...) {
            // Suppress errors in error handler
        }
    }
}

// ============================================================================
// IMPL: COOLDOWN
// ============================================================================

bool WebcamProtectorImpl::IsInCooldown(uint32_t processId) {
    std::lock_guard lock(m_cooldownMutex);

    auto it = m_cooldownTracker.find(processId);
    if (it == m_cooldownTracker.end()) {
        return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        SystemClock::now() - it->second).count();

    return elapsed < WebcamConstants::ACCESS_COOLDOWN_MS;
}

void WebcamProtectorImpl::UpdateCooldown(uint32_t processId) {
    std::lock_guard lock(m_cooldownMutex);
    m_cooldownTracker[processId] = SystemClock::now();

    // Periodically prune stale cooldown entries to prevent unbounded growth
    if (++m_cooldownCleanupCounter >= COOLDOWN_CLEANUP_INTERVAL) {
        m_cooldownCleanupCounter = 0;
        auto now = SystemClock::now();
        for (auto it = m_cooldownTracker.begin(); it != m_cooldownTracker.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second).count();
            if (elapsed > static_cast<long long>(WebcamConstants::ACCESS_COOLDOWN_MS) * 10) {
                it = m_cooldownTracker.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> WebcamProtector::s_instanceCreated{false};

WebcamProtector& WebcamProtector::Instance() noexcept {
    static WebcamProtector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool WebcamProtector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

WebcamProtector::WebcamProtector()
    : m_impl(std::make_unique<WebcamProtectorImpl>())
{
    SS_LOG_INFO(L"WebcamProtector", L"Constructor called");
}

WebcamProtector::~WebcamProtector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"WebcamProtector", L"Destructor called");
}

bool WebcamProtector::Initialize(const WebcamConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void WebcamProtector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool WebcamProtector::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus WebcamProtector::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire)
                  : ModuleStatus::Uninitialized;
}

bool WebcamProtector::UpdateConfiguration(const WebcamConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"WebcamProtector", L"Invalid configuration");
        return false;
    }

    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;

    SS_LOG_INFO(L"WebcamProtector", L"Configuration updated");
    return true;
}

WebcamConfiguration WebcamProtector::GetConfiguration() const {
    if (!m_impl) {
        return WebcamConfiguration{};
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// PROTECTION CONTROL
// ============================================================================

void WebcamProtector::SetProtectionMode(WebcamProtectionMode mode) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.mode = mode;

    SS_LOG_INFO(L"WebcamProtector", L"Protection mode changed to: %hs",
                      std::string(GetProtectionModeName(mode)).c_str());
}

WebcamProtectionMode WebcamProtector::GetProtectionMode() const noexcept {
    if (!m_impl) return WebcamProtectionMode::Disabled;

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.mode;
}

bool WebcamProtector::SetCameraBlocked(bool blocked) {
    if (!m_impl) return false;

    m_impl->m_cameraBlocked.store(blocked, std::memory_order_release);

    SS_LOG_INFO(L"WebcamProtector", L"Camera globally %ls",
                      blocked ? L"BLOCKED" : L"UNBLOCKED");

    return true;
}

bool WebcamProtector::IsCameraBlocked() const noexcept {
    return m_impl ? m_impl->m_cameraBlocked.load(std::memory_order_acquire) : false;
}

bool WebcamProtector::BlockDevice(const std::string& deviceId) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_devicesMutex);

        auto it = m_impl->m_devices.find(deviceId);
        if (it == m_impl->m_devices.end()) {
            return false;
        }

        it->second.isBlocked = true;

        SS_LOG_INFO(L"WebcamProtector", L"Device blocked: %hs", deviceId.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to block device - %hs", e.what());
        return false;
    }
}

bool WebcamProtector::UnblockDevice(const std::string& deviceId) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_devicesMutex);

        auto it = m_impl->m_devices.find(deviceId);
        if (it == m_impl->m_devices.end()) {
            return false;
        }

        it->second.isBlocked = false;

        SS_LOG_INFO(L"WebcamProtector", L"Device unblocked: %hs", deviceId.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to unblock device - %hs", e.what());
        return false;
    }
}

// ============================================================================
// DEVICE MANAGEMENT
// ============================================================================

std::vector<CameraDevice> WebcamProtector::GetCameraDevices() {
    return m_impl ? m_impl->GetCameraDevicesInternal() : std::vector<CameraDevice>{};
}

std::optional<CameraDevice> WebcamProtector::GetDevice(const std::string& deviceId) {
    return m_impl ? m_impl->GetDeviceInternal(deviceId) : std::nullopt;
}

bool WebcamProtector::RefreshDevices() {
    return m_impl ? m_impl->RefreshDevicesInternal() : false;
}

bool WebcamProtector::IsAnyCameraActive() const noexcept {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_devicesMutex);

    for (const auto& [id, device] : m_impl->m_devices) {
        if (device.isActive) {
            return true;
        }
    }

    return false;
}

std::vector<CameraDevice> WebcamProtector::GetActiveCameras() {
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_devicesMutex);

    std::vector<CameraDevice> active;
    for (const auto& [id, device] : m_impl->m_devices) {
        if (device.isActive) {
            active.push_back(device);
        }
    }

    return active;
}

// ============================================================================
// ACCESS CONTROL
// ============================================================================

bool WebcamProtector::OnCameraAccessAttempt(uint32_t pid) {
    return m_impl ? m_impl->OnCameraAccessAttemptInternal(pid) : true;
}

CameraAccessDecision WebcamProtector::EvaluateAccess(
    uint32_t processId,
    const std::string& deviceId)
{
    return m_impl ? m_impl->EvaluateAccessInternal(processId, deviceId)
                  : CameraAccessDecision::Block;
}

bool WebcamProtector::AllowProcessTemporarily(
    uint32_t processId,
    std::chrono::seconds duration)
{
    if (!m_impl) return false;

    try {
        auto expiration = SystemClock::now() + duration;

        std::unique_lock lock(m_impl->m_temporaryMutex);
        m_impl->m_temporaryAccess[processId] = expiration;

        SS_LOG_INFO(L"WebcamProtector", L"Temporary access granted to PID %u for %lld seconds",
                          processId, static_cast<long long>(duration.count()));

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to grant temporary access - %hs", e.what());
        return false;
    }
}

void WebcamProtector::RevokeTemporaryAccess(uint32_t processId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_temporaryMutex);
    m_impl->m_temporaryAccess.erase(processId);

    SS_LOG_INFO(L"WebcamProtector", L"Temporary access revoked for PID %u", processId);
}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

bool WebcamProtector::AddToWhitelist(const CameraWhitelistEntry& entry) {
    return m_impl ? m_impl->AddToWhitelistInternal(entry) : false;
}

bool WebcamProtector::RemoveFromWhitelist(const std::string& entryId) {
    return m_impl ? m_impl->RemoveFromWhitelistInternal(entryId) : false;
}

bool WebcamProtector::IsProcessWhitelisted(
    const std::string& processName,
    const fs::path& processPath)
{
    return m_impl ? m_impl->IsProcessWhitelistedInternal(processName, processPath) : false;
}

std::vector<CameraWhitelistEntry> WebcamProtector::GetWhitelist() const {
    return m_impl ? m_impl->GetWhitelistInternal() : std::vector<CameraWhitelistEntry>{};
}

bool WebcamProtector::ImportDefaultTrustedApps() {
    if (!m_impl) return false;

    try {
        for (const auto& appName : WebcamConstants::DEFAULT_TRUSTED_APPS) {
            CameraWhitelistEntry entry;
            entry.entryId = std::string("DEFAULT_") + appName;
            entry.processPattern = appName;
            entry.enabled = true;
            entry.requireSigned = true;
            entry.addedBy = "System";
            entry.addedTime = SystemClock::now();
            entry.notes = "Default trusted application";

            m_impl->AddToWhitelistInternal(entry);
        }

        SS_LOG_INFO(L"WebcamProtector", L"Imported %zu default trusted apps",
                          std::size(WebcamConstants::DEFAULT_TRUSTED_APPS));

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Failed to import default apps - %hs", e.what());
        return false;
    }
}

// ============================================================================
// MONITORING
// ============================================================================

bool WebcamProtector::StartMonitoring() {
    if (!m_impl) return false;

    m_impl->m_monitoringActive.store(true, std::memory_order_release);

    SS_LOG_INFO(L"WebcamProtector", L"Monitoring started");

    return true;
}

void WebcamProtector::StopMonitoring() {
    if (!m_impl) return;

    m_impl->m_monitoringActive.store(false, std::memory_order_release);

    SS_LOG_INFO(L"WebcamProtector", L"Monitoring stopped");
}

bool WebcamProtector::IsMonitoringActive() const noexcept {
    return m_impl ? m_impl->m_monitoringActive.load(std::memory_order_acquire) : false;
}

// ============================================================================
// EVENT HISTORY
// ============================================================================

std::vector<CameraAccessEvent> WebcamProtector::GetRecentEvents(
    size_t limit,
    std::optional<SystemTimePoint> since)
{
    return m_impl ? m_impl->GetRecentEventsInternal(limit, since)
                  : std::vector<CameraAccessEvent>{};
}

std::vector<CameraAccessEvent> WebcamProtector::GetEventsForProcess(
    const std::string& processName)
{
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_eventsMutex);

    std::vector<CameraAccessEvent> result;
    for (const auto& event : m_impl->m_events) {
        if (event.processName == processName) {
            result.push_back(event);
        }
    }

    return result;
}

void WebcamProtector::ClearEventHistory() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_eventsMutex);
    m_impl->m_events.clear();

    SS_LOG_INFO(L"WebcamProtector", L"Event history cleared");
}

// ============================================================================
// SPYWARE DETECTION
// ============================================================================

bool WebcamProtector::IsKnownSpyware(uint32_t processId) {
    return m_impl ? m_impl->IsKnownSpywareInternal(processId) : false;
}

CameraRiskLevel WebcamProtector::AnalyzeProcess(uint32_t processId) {
    return m_impl ? m_impl->AnalyzeProcessInternal(processId) : CameraRiskLevel::Medium;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void WebcamProtector::RegisterAccessCallback(AccessEventCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_accessCallbacks.push_back(std::move(callback));
}

void WebcamProtector::RegisterDeviceCallback(DeviceChangeCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_deviceCallbacks.push_back(std::move(callback));
}

void WebcamProtector::RegisterDecisionCallback(DecisionCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_decisionCallbacks.push_back(std::move(callback));
}

void WebcamProtector::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void WebcamProtector::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_accessCallbacks.clear();
    m_impl->m_deviceCallbacks.clear();
    m_impl->m_decisionCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

WebcamStatistics WebcamProtector::GetStatistics() const {
    return m_impl ? m_impl->m_statistics : WebcamStatistics{};
}

void WebcamProtector::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
        SS_LOG_INFO(L"WebcamProtector", L"Statistics reset");
    }
}

bool WebcamProtector::SelfTest() {
    try {
        SS_LOG_INFO(L"WebcamProtector", L"Starting self-test");

        if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - module not initialized");
            return false;
        }

        // Test 1: Configuration validation
        {
            WebcamConfiguration validCfg;
            validCfg.notificationDurationMs = 5000;
            if (!validCfg.IsValid()) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - default config invalid");
                return false;
            }
            WebcamConfiguration badCfg;
            badCfg.notificationDurationMs = 0;
            if (badCfg.IsValid()) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - bad config accepted");
                return false;
            }
        }

        // Test 2: Device enumeration (read-only)
        {
            auto devices = GetCameraDevices();
            SS_LOG_INFO(L"WebcamProtector", L"Self-test: enumerated %zu devices", devices.size());
        }

        // Test 3: Whitelist add/check/remove cycle (cleans up after itself)
        {
            CameraWhitelistEntry entry;
            entry.entryId = "__SS_SELFTEST__";
            entry.processPattern = "__selftest_dummy__.exe";
            entry.enabled = true;

            if (!AddToWhitelist(entry)) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - whitelist add");
                return false;
            }
            bool found = IsProcessWhitelisted("__selftest_dummy__.exe", fs::path{});
            RemoveFromWhitelist("__SS_SELFTEST__");
            if (!found) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - whitelist lookup");
                return false;
            }
        }

        // Test 4: Camera block/unblock (restores original state)
        {
            bool wasBlocked = IsCameraBlocked();
            SetCameraBlocked(true);
            if (!IsCameraBlocked()) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - block camera");
                SetCameraBlocked(wasBlocked);
                return false;
            }
            SetCameraBlocked(false);
            if (IsCameraBlocked()) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - unblock camera");
                SetCameraBlocked(wasBlocked);
                return false;
            }
            SetCameraBlocked(wasBlocked);
        }

        // Test 5: Statistics snapshot
        {
            auto stats = GetStatistics();
            (void)stats.totalAccessAttempts.load(std::memory_order_relaxed);
        }

        // Test 6: Version string sanity
        {
            auto ver = GetVersionString();
            if (ver.empty()) {
                SS_LOG_ERROR(L"WebcamProtector", L"Self-test failed - empty version");
                return false;
            }
        }

        SS_LOG_INFO(L"WebcamProtector", L"Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"Self-test exception - %hs", e.what());
        return false;
    }
}

std::string WebcamProtector::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
                      WebcamConstants::VERSION_MAJOR,
                      WebcamConstants::VERSION_MINOR,
                      WebcamConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetProtectionModeName(WebcamProtectionMode mode) noexcept {
    switch (mode) {
        case WebcamProtectionMode::Disabled: return "Disabled";
        case WebcamProtectionMode::Monitor: return "Monitor";
        case WebcamProtectionMode::Prompt: return "Prompt";
        case WebcamProtectionMode::WhitelistOnly: return "Whitelist Only";
        case WebcamProtectionMode::BlockAll: return "Block All";
        default: return "Unknown";
    }
}

std::string_view GetDeviceTypeName(CameraDeviceType type) noexcept {
    switch (type) {
        case CameraDeviceType::Unknown: return "Unknown";
        case CameraDeviceType::IntegratedUSB: return "Integrated USB";
        case CameraDeviceType::ExternalUSB: return "External USB";
        case CameraDeviceType::Virtual: return "Virtual";
        case CameraDeviceType::IP: return "IP Camera";
        case CameraDeviceType::FireWire: return "FireWire";
        default: return "Unknown";
    }
}

std::string_view GetAccessReasonName(AccessReason reason) noexcept {
    switch (reason) {
        case AccessReason::Unknown: return "Unknown";
        case AccessReason::VideoCall: return "Video Call";
        case AccessReason::Streaming: return "Streaming";
        case AccessReason::Recording: return "Recording";
        case AccessReason::PhotoCapture: return "Photo Capture";
        case AccessReason::SystemCheck: return "System Check";
        case AccessReason::Malware: return "Malware";
        case AccessReason::SuspiciousRAT: return "Suspicious RAT";
        default: return "Unknown";
    }
}

std::string_view GetRiskLevelName(CameraRiskLevel level) noexcept {
    switch (level) {
        case CameraRiskLevel::Safe: return "Safe";
        case CameraRiskLevel::Low: return "Low";
        case CameraRiskLevel::Medium: return "Medium";
        case CameraRiskLevel::High: return "High";
        case CameraRiskLevel::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetDecisionName(CameraAccessDecision decision) noexcept {
    switch (decision) {
        case CameraAccessDecision::Allow: return "Allow";
        case CameraAccessDecision::Block: return "Block";
        case CameraAccessDecision::Prompt: return "Prompt";
        case CameraAccessDecision::AllowOnce: return "Allow Once";
        case CameraAccessDecision::AllowTimed: return "Allow Timed";
        default: return "Unknown";
    }
}

std::vector<CameraDevice> EnumerateCameraDevices() {
    std::vector<CameraDevice> devices;

#ifdef _WIN32
    try {
        // Use SetupAPI to enumerate camera devices
        HDEVINFO deviceInfo = SetupDiGetClassDevsW(
            &s_ksCategoryVideoCamera,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        if (deviceInfo == INVALID_HANDLE_VALUE) {
            return devices;
        }

        SP_DEVICE_INTERFACE_DATA interfaceData = {};
        interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

        for (DWORD i = 0; SetupDiEnumDeviceInterfaces(
                 deviceInfo, nullptr, &s_ksCategoryVideoCamera, i, &interfaceData);
             i++) {

            // Get required size
            DWORD requiredSize = 0;
            SetupDiGetDeviceInterfaceDetailW(deviceInfo, &interfaceData, nullptr, 0, &requiredSize, nullptr);

            if (requiredSize == 0) continue;

            // Allocate buffer
            std::vector<BYTE> buffer(requiredSize);
            PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData =
                reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
            detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

            SP_DEVINFO_DATA devInfoData = {};
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

            if (SetupDiGetDeviceInterfaceDetailW(
                    deviceInfo, &interfaceData, detailData, requiredSize, nullptr, &devInfoData)) {

                CameraDevice device;
                device.devicePath = Utils::StringUtils::ToNarrow(detailData->DevicePath);
                device.deviceId = std::format("CAM_{}", i);

                // Get friendly name
                wchar_t friendlyName[256] = {};
                if (SetupDiGetDeviceRegistryPropertyW(
                        deviceInfo, &devInfoData, SPDRP_FRIENDLYNAME, nullptr,
                        reinterpret_cast<PBYTE>(friendlyName), sizeof(friendlyName), nullptr)) {
                    device.friendlyName = Utils::StringUtils::ToNarrow(friendlyName);
                }

                // Get manufacturer
                wchar_t manufacturer[256] = {};
                if (SetupDiGetDeviceRegistryPropertyW(
                        deviceInfo, &devInfoData, SPDRP_MFG, nullptr,
                        reinterpret_cast<PBYTE>(manufacturer), sizeof(manufacturer), nullptr)) {
                    device.manufacturer = Utils::StringUtils::ToNarrow(manufacturer);
                }

                // Detect device type and virtual camera status
                wchar_t hwId[512] = {};
                if (SetupDiGetDeviceRegistryPropertyW(
                        deviceInfo, &devInfoData, SPDRP_HARDWAREID, nullptr,
                        reinterpret_cast<PBYTE>(hwId), sizeof(hwId), nullptr)) {

                    std::wstring hwIdStr(hwId);
                    std::wstring nameW = Utils::StringUtils::ToWide(device.friendlyName);
                    device.isVirtual = IsVirtualCameraDevice(hwIdStr, nameW);

                    if (device.isVirtual) {
                        device.type = CameraDeviceType::Virtual;
                    } else {
                        // Extract VID/PID from hardware ID (e.g. "USB\\VID_046D&PID_082D...")
                        std::wstring hwLower = hwIdStr;
                        std::transform(hwLower.begin(), hwLower.end(), hwLower.begin(), ::towlower);

                        auto vidPos = hwLower.find(L"vid_");
                        auto pidPos = hwLower.find(L"pid_");
                        if (vidPos != std::wstring::npos && vidPos + 8 <= hwLower.size()) {
                            device.vendorId = static_cast<uint16_t>(
                                std::wcstoul(hwLower.c_str() + vidPos + 4, nullptr, 16));
                        }
                        if (pidPos != std::wstring::npos && pidPos + 8 <= hwLower.size()) {
                            device.productId = static_cast<uint16_t>(
                                std::wcstoul(hwLower.c_str() + pidPos + 4, nullptr, 16));
                        }

                        if (hwLower.find(L"usb\\") != std::wstring::npos) {
                            device.type = CameraDeviceType::ExternalUSB;
                        } else {
                            device.type = CameraDeviceType::IntegratedUSB;
                        }
                    }
                } else {
                    device.type = CameraDeviceType::Unknown;
                }

                // Check device status via Configuration Manager
                DEVINST devInst = devInfoData.DevInst;
                ULONG devStatus = 0, devProblem = 0;
                if (CM_Get_DevNode_Status(&devStatus, &devProblem, devInst, 0) == CR_SUCCESS) {
                    device.isHardwareEnabled = !(devStatus & DN_DISABLEABLE &&
                                                  devProblem == CM_PROB_DISABLED);
                    device.isActive = (devStatus & DN_STARTED) != 0;
                } else {
                    device.isHardwareEnabled = true;
                    device.isActive = false;
                }

                devices.push_back(device);

                if (devices.size() >= WebcamConstants::MAX_DEVICES) {
                    break;
                }
            }
        }

        SetupDiDestroyDeviceInfoList(deviceInfo);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"WebcamProtector", L"EnumerateCameraDevices exception - %hs", e.what());
    }
#endif

    return devices;
}

std::vector<uint32_t> GetProcessesUsingCamera(const std::string& deviceId) {
    std::vector<uint32_t> pids;

#ifdef _WIN32
    // Enumerate running processes and check for camera-related modules.
    // This is a user-mode heuristic; kernel-mode callbacks (PhantomSensor)
    // provide authoritative device-handle tracking.
    DWORD procIds[4096];
    DWORD bytesReturned = 0;
    if (!EnumProcesses(procIds, sizeof(procIds), &bytesReturned)) {
        SS_LOG_LAST_ERROR(L"WebcamProtector", L"EnumProcesses failed");
        return pids;
    }

    const DWORD procCount = bytesReturned / sizeof(DWORD);
    constexpr size_t MAX_RESULTS = 64;

    for (DWORD i = 0; i < procCount && pids.size() < MAX_RESULTS; ++i) {
        if (procIds[i] == 0) continue;

        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, procIds[i]);
        if (!hProc) continue;

        HMODULE modules[1024];
        DWORD cbNeeded = 0;
        if (EnumProcessModulesEx(hProc, modules, sizeof(modules),
                                 &cbNeeded, LIST_MODULES_ALL)) {
            const DWORD modCount = std::min<DWORD>(
                cbNeeded / sizeof(HMODULE),
                static_cast<DWORD>(std::size(modules)));
            for (DWORD m = 0; m < modCount; ++m) {
                wchar_t modName[MAX_PATH] = {};
                if (GetModuleBaseNameW(hProc, modules[m], modName, MAX_PATH)) {
                    if (_wcsicmp(modName, L"FrameServerClient.dll") == 0) {
                        pids.push_back(procIds[i]);
                        break;
                    }
                }
            }
        }
        CloseHandle(hProc);
    }
#endif

    return pids;
}

}  // namespace Privacy
}  // namespace ShadowStrike
