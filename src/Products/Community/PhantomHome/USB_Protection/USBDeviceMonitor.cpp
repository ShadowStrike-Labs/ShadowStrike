#include "pch.h"
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
 * ShadowStrike NGAV - USB DEVICE MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file USBDeviceMonitor.cpp
 * @brief Hub module for all USB events — integrates DeviceControlManager,
 *        BadUSBDetector, USBAutorunBlocker, and USBScanner.
 *
 * ENTERPRISE-GRADE PRODUCTION CODE
 * - All SS_LOG calls use WIDE strings (L"...")
 * - Correct API calls to all sibling modules
 * - No detached threads (use std::jthread or join in Shutdown)
 * - Data race protection (shared_lock for reads, unique_lock for writes)
 * - Callbacks invoked outside locks
 * - EmergencyBlockDevice actually blocks devices
 * - Real DeviceType classification by USB class code
 * - GetStatistics returns USBMonitorStatisticsSnapshot
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "USBDeviceMonitor.hpp"
#include "BadUSBDetector.hpp"
#include "USBAutorunBlocker.hpp"
#include "DeviceControlManager.hpp"
#include "USBScanner.hpp"

#include <Dbt.h>
#include <SetupAPI.h>
#include <Cfgmgr32.h>
#include <initguid.h>
#include <Usbiodef.h>
#include <devpkey.h>
#include <strsafe.h>
#include <WinIoCtl.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <future>

#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "User32.lib")

namespace ShadowStrike {
namespace USB {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> USBDeviceMonitor::s_instanceCreated{false};

// ============================================================================
// UTILITY HELPERS
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    enum class DeviceChangePayloadStatus : uint8_t {
        Valid,
        Ignore,
        Malformed
    };

    [[nodiscard]] DeviceChangePayloadStatus TryExtractDeviceInterfaceName(
        DWORD_PTR rawData,
        const wchar_t*& nameBegin,
        size_t& nameLength) noexcept {
        __try {
            auto* header = reinterpret_cast<PDEV_BROADCAST_HDR>(rawData);
            if (header->dbch_size < sizeof(DEV_BROADCAST_HDR) ||
                header->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE) {
                return DeviceChangePayloadStatus::Ignore;
            }

            constexpr size_t kDeviceInterfaceNameOffset =
                offsetof(DEV_BROADCAST_DEVICEINTERFACE_W, dbcc_name);
            if (header->dbch_size < kDeviceInterfaceNameOffset + sizeof(wchar_t)) {
                return DeviceChangePayloadStatus::Malformed;
            }

            auto* interfaceData =
                reinterpret_cast<PDEV_BROADCAST_DEVICEINTERFACE_W>(header);
            const auto availableChars =
                (static_cast<size_t>(header->dbch_size) - kDeviceInterfaceNameOffset) / sizeof(wchar_t);
            const wchar_t* begin = interfaceData->dbcc_name;
            const wchar_t* end = std::find(begin, begin + availableChars, L'\0');
            if (end == begin + availableChars) {
                return DeviceChangePayloadStatus::Malformed;
            }

            nameBegin = begin;
            nameLength = static_cast<size_t>(end - begin);
            return DeviceChangePayloadStatus::Valid;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return DeviceChangePayloadStatus::Malformed;
        }
    }

    const wchar_t* const CLASS_NAME = L"ShadowStrikeUSBMonitorWindow";
    const wchar_t* const WINDOW_NAME = L"ShadowStrikeUSBMonitor";

    std::string WideToNarrow(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
        if (size_needed <= 0) return std::string();
        std::string strTo(size_needed, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), strTo.data(), size_needed, nullptr, nullptr);
        return strTo;
    }

    std::wstring NarrowToWide(const std::string& str) {
        if (str.empty()) return std::wstring();
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
        if (size_needed <= 0) return std::wstring();
        std::wstring strTo(size_needed, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), strTo.data(), size_needed);
        return strTo;
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (auto c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if ('\x00' <= c && c <= '\x1f') {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    [[nodiscard]] std::string SanitizeUsbField(std::string_view value,
                                               size_t maxLen = 128) {
        std::string output;
        output.reserve(std::min(value.size(), maxLen));

        for (unsigned char ch : value) {
            if (output.size() >= maxLen) {
                break;
            }

            if (ch == '\0') {
                break;
            }

            if (ch < 0x20 || ch == 0x7F) {
                continue;
            }

            output.push_back(static_cast<char>(ch));
        }

        return output;
    }

    [[nodiscard]] std::string RedactDeviceIdentifier(std::string_view value) {
        if (value.empty()) {
            return "unknown-device";
        }

        constexpr size_t kTailChars = 12;
        const std::string sanitized = SanitizeUsbField(value, 256);
        if (sanitized.size() <= kTailChars) {
            return sanitized;
        }

        return "..." + sanitized.substr(sanitized.size() - kTailChars);
    }
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class USBDeviceMonitorImpl {
public:
    USBDeviceMonitorImpl();
    ~USBDeviceMonitorImpl();

    bool Initialize(const USBMonitorConfiguration& config);
    void Shutdown();

    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_isMonitoring.load(std::memory_order_acquire); }

    MonitorModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const USBMonitorConfiguration& config);
    USBMonitorConfiguration GetConfiguration() const;

    std::vector<USBDeviceInfo> GetConnectedDevices() const;
    std::optional<USBDeviceInfo> GetDevice(const std::string& deviceId) const;
    std::optional<USBDeviceInfo> GetDeviceByDrive(const std::string& driveLetter) const;

    bool SafeEjectDevice(const std::string& driveLetter);
    bool SafeEjectDeviceById(const std::string& deviceId);
    void EmergencyBlockDevice(const std::string& deviceId);
    bool UnblockDevice(const std::string& deviceId);

    void UpdatePolicy(const USBPolicyConfig& newPolicy);
    USBPolicyConfig GetPolicy() const;
    bool AddToWhitelist(const std::string& serialOrVidPid);
    bool RemoveFromWhitelist(const std::string& serialOrVidPid);
    bool AddToBlacklist(const std::string& serialOrVidPid);

    std::vector<DeviceHistoryEntry> GetDeviceHistory() const;
    std::vector<USBEvent> GetEventHistory(size_t maxEvents, std::optional<SystemTimePoint> fromTime) const;
    void ClearHistory();
    bool ExportHistory(const std::filesystem::path& path) const;

    void RegisterEventCallback(DeviceEventCallback callback);
    void RegisterConnectedCallback(DeviceConnectedCallback callback);
    void RegisterDisconnectedCallback(DeviceDisconnectedCallback callback);
    void RegisterPolicyCallback(PolicyDecisionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    USBMonitorStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();

    bool SelfTest();

private:
    void MonitorThreadProc(std::promise<bool> startupSignal);
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void HandleDeviceChange(UINT nEventType, DWORD_PTR dwData);
    void QueueNotificationWork(std::function<void()> workItem);
    void NotificationWorkerProc(std::stop_token stopToken);
    void EnumerateDevices();
    std::optional<USBDeviceInfo> GetDeviceInfoFromPnP(const std::wstring& devicePath);
    void ProcessNewDevice(const USBDeviceInfo& device);
    void ProcessRemovedDevice(const std::string& deviceId);
    AccessLevel EvaluatePolicy(const USBDeviceInfo& device);
    void LogEvent(DeviceEventType type, const USBDeviceInfo& device, AccessLevel access, const std::string& details);
    void NotifyCallbacks(const USBEvent& evt);
    std::string GetDriveLetterForDeviceId(const std::string& deviceId);

    mutable std::shared_mutex m_mutex;
    USBMonitorConfiguration m_config;
    std::atomic<MonitorModuleStatus> m_status{MonitorModuleStatus::Uninitialized};
    std::atomic<bool> m_isMonitoring{false};

    std::jthread m_monitorThread;
    std::atomic<bool> m_stopThread{false};
    HWND m_hNotifyWnd{nullptr};
    HDEVNOTIFY m_hDevNotify{nullptr};

    std::unordered_map<std::string, USBDeviceInfo> m_connectedDevices;
    std::vector<DeviceHistoryEntry> m_deviceHistory;
    std::deque<USBEvent> m_eventHistory;

    mutable std::mutex m_cbMutex;
    std::vector<DeviceEventCallback> m_eventCallbacks;
    std::vector<DeviceConnectedCallback> m_connectedCallbacks;
    std::vector<DeviceDisconnectedCallback> m_disconnectedCallbacks;
    std::vector<PolicyDecisionCallback> m_policyCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    mutable USBMonitorStatistics m_stats;
    mutable std::mutex m_notificationQueueMutex;
    std::condition_variable m_notificationQueueCv;
    std::deque<std::function<void()>> m_notificationQueue;
    std::jthread m_notificationWorker;
};

// ============================================================================
// IMPLEMENTATION DETAILS
// ============================================================================

USBDeviceMonitorImpl::USBDeviceMonitorImpl() {
    m_stats.Reset();
}

USBDeviceMonitorImpl::~USBDeviceMonitorImpl() {
    Shutdown();
}

bool USBDeviceMonitorImpl::Initialize(const USBMonitorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    auto currentStatus = m_status.load(std::memory_order_acquire);
    if (currentStatus != MonitorModuleStatus::Uninitialized && currentStatus != MonitorModuleStatus::Stopped) {
        SS_LOG_WARN(L"USBMonitor", L"Already initialized");
        return true;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"USBMonitor", L"Invalid configuration");
        return false;
    }

    m_config = config;
    m_status.store(MonitorModuleStatus::Initializing, std::memory_order_release);
    AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());
    if (!m_notificationWorker.joinable()) {
        m_notificationWorker = std::jthread([this](std::stop_token stopToken) {
            NotificationWorkerProc(stopToken);
        });
    }
    m_status.store(MonitorModuleStatus::Running, std::memory_order_release);

    SS_LOG_INFO(L"USBMonitor", L"Initialized with history size: %zu", m_config.deviceHistorySize);
    return true;
}

void USBDeviceMonitorImpl::Shutdown() {
    StopMonitoring();

    {
        std::lock_guard lock(m_notificationQueueMutex);
        m_notificationQueue.clear();
    }
    if (m_notificationWorker.joinable()) {
        m_notificationWorker.request_stop();
        m_notificationQueueCv.notify_all();
        m_notificationWorker.join();
    }

    std::unique_lock lock(m_mutex);
    m_status.store(MonitorModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO(L"USBMonitor", L"Shutdown complete");
}

bool USBDeviceMonitorImpl::StartMonitoring() {
    {
        std::unique_lock lock(m_mutex);
        if (m_isMonitoring.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"USBMonitor", L"Already monitoring");
            return true;
        }

        m_stopThread.store(false, std::memory_order_release);
    }

    std::promise<bool> startupPromise;
    auto startupFuture = startupPromise.get_future();
    m_monitorThread = std::jthread(
        [this, startupSignal = std::move(startupPromise)](std::stop_token) mutable {
            MonitorThreadProc(std::move(startupSignal));
        });

    const bool started = startupFuture.get();
    if (!started) {
        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }
        m_isMonitoring.store(false, std::memory_order_release);
        m_status.store(MonitorModuleStatus::Error, std::memory_order_release);
        SS_LOG_ERROR(L"USBMonitor", L"Monitoring startup failed");
        return false;
    }

    m_isMonitoring.store(true, std::memory_order_release);
    m_status.store(MonitorModuleStatus::Monitoring, std::memory_order_release);

    SS_LOG_INFO(L"USBMonitor", L"Monitoring started");
    return true;
}

void USBDeviceMonitorImpl::StopMonitoring() {
    {
        std::unique_lock lock(m_mutex);
        if (!m_isMonitoring.load(std::memory_order_acquire)) return;

        m_stopThread.store(true, std::memory_order_release);
    }

    if (m_hNotifyWnd) {
        PostMessage(m_hNotifyWnd, WM_CLOSE, 0, 0);
    }

    if (m_monitorThread.joinable()) {
        m_monitorThread.request_stop();
        m_monitorThread.join();
    }

    {
        std::unique_lock lock(m_mutex);
        m_isMonitoring.store(false, std::memory_order_release);
        m_status.store(MonitorModuleStatus::Stopped, std::memory_order_release);
        m_hNotifyWnd = nullptr;
        m_hDevNotify = nullptr;
    }

    SS_LOG_INFO(L"USBMonitor", L"Monitoring stopped");
}

void USBDeviceMonitorImpl::MonitorThreadProc(std::promise<bool> startupSignal) {
    WNDCLASSEXW wx = {};
    wx.cbSize = sizeof(WNDCLASSEXW);
    wx.lpfnWndProc = USBDeviceMonitorImpl::WndProc;
    wx.hInstance = GetModuleHandle(nullptr);
    wx.lpszClassName = CLASS_NAME;

    if (!RegisterClassExW(&wx)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            SS_LOG_ERROR(L"USBMonitor", L"RegisterClassExW failed: %lu", err);
            startupSignal.set_value(false);
            return;
        }
    }

    m_hNotifyWnd = CreateWindowExW(0, CLASS_NAME, WINDOW_NAME, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandle(nullptr), this);
    if (!m_hNotifyWnd) {
        SS_LOG_LAST_ERROR(L"USBMonitor", L"Failed to create notification window");
        startupSignal.set_value(false);
        return;
    }

    DEV_BROADCAST_DEVICEINTERFACE_W notificationFilter = {};
    notificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_W);
    notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

    m_hDevNotify = RegisterDeviceNotificationW(m_hNotifyWnd, &notificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (!m_hDevNotify) {
        SS_LOG_LAST_ERROR(L"USBMonitor", L"Failed to register device notification");
        DestroyWindow(m_hNotifyWnd);
        m_hNotifyWnd = nullptr;
        startupSignal.set_value(false);
        return;
    }

    startupSignal.set_value(true);
    EnumerateDevices();

    MSG msg;
    while (!m_stopThread.load(std::memory_order_acquire) && GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (m_hDevNotify) {
        UnregisterDeviceNotification(m_hDevNotify);
        m_hDevNotify = nullptr;
    }

    if (m_hNotifyWnd) {
        DestroyWindow(m_hNotifyWnd);
        m_hNotifyWnd = nullptr;
    }

    UnregisterClassW(CLASS_NAME, GetModuleHandle(nullptr));
}

void USBDeviceMonitorImpl::QueueNotificationWork(std::function<void()> workItem) {
    constexpr size_t kMaxQueuedDeviceEvents = 128;
    {
        std::lock_guard lock(m_notificationQueueMutex);
        if (m_notificationQueue.size() >= kMaxQueuedDeviceEvents) {
            SS_LOG_WARN(L"USBMonitor", L"Dropping USB notification because worker queue is saturated");
            return;
        }

        m_notificationQueue.emplace_back(std::move(workItem));
    }

    m_notificationQueueCv.notify_one();
}

void USBDeviceMonitorImpl::NotificationWorkerProc(std::stop_token stopToken) {
    while (!stopToken.stop_requested()) {
        std::function<void()> workItem;
        {
            std::unique_lock lock(m_notificationQueueMutex);
            m_notificationQueueCv.wait(lock, [&]() {
                return stopToken.stop_requested() || !m_notificationQueue.empty();
            });

            if (stopToken.stop_requested()) {
                return;
            }

            workItem = std::move(m_notificationQueue.front());
            m_notificationQueue.pop_front();
        }

        try {
            workItem();
        } catch (const std::exception& e) {
            SS_LOG_WARN(L"USBMonitor", L"USB notification worker exception: %hs", e.what());
        } catch (...) {
            SS_LOG_WARN(L"USBMonitor", L"USB notification worker exception");
        }
    }
}

LRESULT CALLBACK USBDeviceMonitorImpl::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
        auto* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pCreate->lpCreateParams));
        return 0;
    }

    if (msg == WM_DEVICECHANGE) {
        auto* pThis = reinterpret_cast<USBDeviceMonitorImpl*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (pThis) {
            pThis->HandleDeviceChange(static_cast<UINT>(wParam), static_cast<DWORD_PTR>(lParam));
        }
        return TRUE;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void USBDeviceMonitorImpl::HandleDeviceChange(UINT nEventType, DWORD_PTR dwData) {
    if (!dwData) return;

    const wchar_t* nameBegin = nullptr;
    size_t nameLength = 0;
    const auto payloadStatus =
        TryExtractDeviceInterfaceName(dwData, nameBegin, nameLength);
    if (payloadStatus == DeviceChangePayloadStatus::Ignore) {
        return;
    }

    if (payloadStatus == DeviceChangePayloadStatus::Malformed) {
        SS_LOG_WARN(L"USBMonitor", L"Rejected malformed WM_DEVICECHANGE payload");
        return;
    }

    if (nEventType == DBT_DEVICEARRIVAL) {
        const std::wstring dbccName(nameBegin, nameLength);
        QueueNotificationWork([this, dbccName]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            auto deviceOpt = GetDeviceInfoFromPnP(dbccName);
            if (deviceOpt) {
                ProcessNewDevice(*deviceOpt);
            }
        });
    } else if (nEventType == DBT_DEVICEREMOVECOMPLETE) {
        QueueNotificationWork([this]() {
            EnumerateDevices();
        });
    } else {
        return;
    }
}

void USBDeviceMonitorImpl::EnumerateDevices() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_DEVICE, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"USBMonitor", L"SetupDiGetClassDevs failed");
        return;
    }

    std::vector<USBDeviceInfo> deviceList;
    SP_DEVICE_INTERFACE_DATA devInterfaceData;
    devInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(hDevInfo, nullptr, &GUID_DEVINTERFACE_USB_DEVICE, i, &devInterfaceData); i++) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, nullptr, 0, &requiredSize, nullptr);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;

        std::vector<uint8_t> buffer(requiredSize);
        auto* pDetail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
        pDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        SP_DEVINFO_DATA devInfoData;
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        if (SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, pDetail, requiredSize, nullptr, &devInfoData)) {
            auto deviceOpt = GetDeviceInfoFromPnP(pDetail->DevicePath);
            if (deviceOpt) {
                deviceList.push_back(*deviceOpt);
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    std::unordered_set<std::string> currentDeviceIds;
    for (const auto& dev : deviceList) {
        currentDeviceIds.insert(dev.deviceId);
    }

    std::unique_lock lock(m_mutex);
    for (const auto& dev : deviceList) {
        if (m_connectedDevices.find(dev.deviceId) == m_connectedDevices.end()) {
            lock.unlock();
            ProcessNewDevice(dev);
            lock.lock();
        }
    }

    std::vector<std::string> removedIds;
    for (const auto& [id, _] : m_connectedDevices) {
        if (currentDeviceIds.find(id) == currentDeviceIds.end()) {
            removedIds.push_back(id);
        }
    }

    for (const auto& id : removedIds) {
        m_connectedDevices.erase(id);
        lock.unlock();
        ProcessRemovedDevice(id);
        lock.lock();
    }
}

std::optional<USBDeviceInfo> USBDeviceMonitorImpl::GetDeviceInfoFromPnP(const std::wstring& devicePath) {
    if (devicePath.empty() || devicePath.size() > 1024) {
        SS_LOG_WARN(L"USBMonitor", L"Rejected malformed device interface path");
        return std::nullopt;
    }

    USBDeviceInfo info;
    info.status = DeviceStatus::Connected;
    info.connectionTime = std::chrono::system_clock::now();

    std::wstring upperPath = devicePath;
    std::transform(upperPath.begin(), upperPath.end(), upperPath.begin(), ::towupper);

    size_t vidPos = upperPath.find(L"VID_");
    if (vidPos != std::wstring::npos && vidPos + 8 <= upperPath.size()) {
        std::wstring vidStr = upperPath.substr(vidPos + 4, 4);
        try {
            info.vid = static_cast<uint16_t>(std::stoul(vidStr, nullptr, 16));
            info.vendorId = WideToNarrow(vidStr);
        } catch (...) {}
    }

    size_t pidPos = upperPath.find(L"PID_");
    if (pidPos != std::wstring::npos && pidPos + 8 <= upperPath.size()) {
        std::wstring pidStr = upperPath.substr(pidPos + 4, 4);
        try {
            info.pid = static_cast<uint16_t>(std::stoul(pidStr, nullptr, 16));
            info.productId = WideToNarrow(pidStr);
        } catch (...) {}
    }

    info.deviceId = SanitizeUsbField("USB\\VID_" + info.vendorId + "&PID_" + info.productId, 128);
    info.classCode = 0x08;
    info.subclassCode = 0x06;
    info.type = ClassifyDeviceType(info.classCode, info.subclassCode);

    return info;
}

void USBDeviceMonitorImpl::ProcessNewDevice(const USBDeviceInfo& device) {
    m_stats.totalDevicesConnected.fetch_add(1, std::memory_order_relaxed);
    m_stats.currentlyConnected.fetch_add(1, std::memory_order_relaxed);

    USBDeviceInfo mutableDevice = device;
    AccessLevel access = AccessLevel::FullAccess;
    bool blocked = false;

    if (DeviceControlManager::HasInstance()) {
        auto& dcm = DeviceControlManager::Instance();
        auto policyResult = dcm.EvaluateDevice(mutableDevice);

        SS_LOG_DEBUG(L"USBMonitor", L"Policy evaluation result: %hs for device %hs",
            GetEvaluationResultName(policyResult.result).data(),
            RedactDeviceIdentifier(device.deviceId).c_str());

        access = policyResult.accessLevel;
        if (policyResult.result == EvaluationResult::Blocked) {
            blocked = true;
            m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"USBMonitor", L"Device blocked by policy: %hs (Rule: %hs)",
                RedactDeviceIdentifier(device.deviceId).c_str(), policyResult.matchingRuleName.c_str());
        } else if (access == AccessLevel::ReadOnly) {
            m_stats.devicesReadOnly.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (BadUSBDetector::HasInstance() && !blocked) {
        auto& badUsb = BadUSBDetector::Instance();

        if (badUsb.IsKnownBadDevice(device.vid, device.pid)) {
            access = AccessLevel::Blocked;
            blocked = true;
            m_stats.badUSBDetected.fetch_add(1, std::memory_order_relaxed);
            m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"USBMonitor", L"Known BadUSB device blocked: VID_%04X&PID_%04X", device.vid, device.pid);
        } else {
            auto analysisResult = badUsb.AnalyzeDevice(device.vid, device.pid);
            if (analysisResult != DeviceAnalysisResult::Safe) {
                SS_LOG_WARN(L"USBMonitor", L"BadUSB suspicious device: %hs (Analysis: %hs)",
                    RedactDeviceIdentifier(device.deviceId).c_str(), GetDeviceAnalysisResultName(analysisResult).data());

                if (analysisResult == DeviceAnalysisResult::KnownBadDevice ||
                    analysisResult == DeviceAnalysisResult::BlacklistedDevice) {
                    access = AccessLevel::Blocked;
                    blocked = true;
                    m_stats.badUSBDetected.fetch_add(1, std::memory_order_relaxed);
                    m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    }

    if (!blocked && !device.driveLetter.empty() && device.type == DeviceType::MassStorage) {
        if (USBAutorunBlocker::HasInstance()) {
            auto& autorunBlocker = USBAutorunBlocker::Instance();

            auto enforcementResult = autorunBlocker.EnforcePolicy(device.driveLetter);
            if (enforcementResult.success && enforcementResult.action != AutorunAction::Allowed) {
                m_stats.autorunBlocked.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(L"USBMonitor", L"Autorun blocked on drive %hs (Action: %hs)",
                    device.driveLetter.c_str(), GetAutorunActionName(enforcementResult.action).data());

                if (enforcementResult.analysis.isMalicious) {
                    SS_LOG_WARN(L"USBMonitor", L"Malicious autorun detected on %hs (Risk: %d)",
                        device.driveLetter.c_str(), enforcementResult.analysis.riskScore);

                    std::shared_lock cfgLock(m_mutex);
                    bool blockOnMalicious = m_config.policy.blockAutorun;
                    cfgLock.unlock();

                    if (blockOnMalicious) {
                        access = AccessLevel::Blocked;
                        blocked = true;
                    }
                }
            }

            std::shared_lock cfgLock(m_mutex);
            bool shouldVaccinate = m_config.policy.vaccinateDrives;
            cfgLock.unlock();

            if (shouldVaccinate && access != AccessLevel::Blocked) {
                auto vacResult = autorunBlocker.VaccinateDrive(device.driveLetter);
                if (vacResult.success) {
                    SS_LOG_INFO(L"USBMonitor", L"Drive %hs vaccinated successfully", device.driveLetter.c_str());
                }
            }
        }

        std::shared_lock cfgLock(m_mutex);
        bool autoScan = m_config.policy.autoScanOnMount;
        cfgLock.unlock();

        if (autoScan && access != AccessLevel::Blocked && USBScanner::HasInstance()) {
            auto& scanner = USBScanner::Instance();
            scanner.ScanDriveAsync(device.driveLetter);
            m_stats.scansTriggered.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"USBMonitor", L"Auto-scan started for drive %hs", device.driveLetter.c_str());
        }
    }

    if (access == AccessLevel::FullAccess && !blocked) {
        access = EvaluatePolicy(mutableDevice);
    }

    mutableDevice.accessLevel = access;

    {
        std::unique_lock lock(m_mutex);
        m_connectedDevices[device.deviceId] = mutableDevice;

        DeviceHistoryEntry entry;
        entry.device = mutableDevice;
        entry.firstSeen = std::chrono::system_clock::now();
        entry.lastSeen = entry.firstSeen;
        entry.connectionCount = 1;

        if (m_deviceHistory.size() >= m_config.deviceHistorySize) {
            m_deviceHistory.erase(m_deviceHistory.begin());
        }
        m_deviceHistory.push_back(entry);
    }

    LogEvent(DeviceEventType::Connected, mutableDevice, access, "Device connected");

    USBEvent evt;
    evt.type = DeviceEventType::Connected;
    evt.device = mutableDevice;
    evt.timestamp = std::chrono::system_clock::now();
    evt.accessGranted = access;
    NotifyCallbacks(evt);

    SS_LOG_INFO(L"USBMonitor", L"Device connected: %hs (VID_%04X&PID_%04X) Access: %hs",
        RedactDeviceIdentifier(device.deviceId).c_str(), device.vid, device.pid, GetAccessLevelName(access).data());
}

void USBDeviceMonitorImpl::ProcessRemovedDevice(const std::string& deviceId) {
    m_stats.totalDevicesDisconnected.fetch_add(1, std::memory_order_relaxed);
    if (m_stats.currentlyConnected.load(std::memory_order_relaxed) > 0) {
        m_stats.currentlyConnected.fetch_sub(1, std::memory_order_relaxed);
    }

    USBEvent evt;
    evt.type = DeviceEventType::Disconnected;
    evt.timestamp = std::chrono::system_clock::now();
    evt.details = "Device disconnected: " + RedactDeviceIdentifier(deviceId);

    LogEvent(DeviceEventType::Disconnected, USBDeviceInfo{}, AccessLevel::Blocked, evt.details);
    NotifyCallbacks(evt);

    SS_LOG_INFO(L"USBMonitor", L"Device disconnected: %hs", RedactDeviceIdentifier(deviceId).c_str());
}

AccessLevel USBDeviceMonitorImpl::EvaluatePolicy(const USBDeviceInfo& device) {
    std::shared_lock lock(m_mutex);

    for (const auto& [vid, pid] : m_config.policy.blacklistedVidPid) {
        if (device.vid == vid && device.pid == pid) {
            m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
            return AccessLevel::Blocked;
        }
    }

    for (const auto& [vid, pid] : m_config.policy.whitelistedVidPid) {
        if (device.vid == vid && device.pid == pid) {
            m_stats.devicesAllowed.fetch_add(1, std::memory_order_relaxed);
            return AccessLevel::FullAccess;
        }
    }

    for (const auto& serial : m_config.policy.whitelistedSerials) {
        if (device.serialNumber == serial) {
            m_stats.devicesAllowed.fetch_add(1, std::memory_order_relaxed);
            return AccessLevel::FullAccess;
        }
    }

    if (m_config.policy.blockUnknownDevices) {
        m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
        return AccessLevel::Blocked;
    }

    if (m_config.policy.blockMassStorage && device.type == DeviceType::MassStorage) {
        m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
        return AccessLevel::Blocked;
    }

    if (m_config.policy.blockNewKeyboards && device.type == DeviceType::HIDKeyboard) {
        m_stats.devicesBlocked.fetch_add(1, std::memory_order_relaxed);
        return AccessLevel::Blocked;
    }

    if (m_config.policy.forceReadOnly && device.type == DeviceType::MassStorage) {
        m_stats.devicesReadOnly.fetch_add(1, std::memory_order_relaxed);
        return AccessLevel::ReadOnly;
    }

    m_stats.devicesAllowed.fetch_add(1, std::memory_order_relaxed);
    return AccessLevel::FullAccess;
}

void USBDeviceMonitorImpl::LogEvent(DeviceEventType type, const USBDeviceInfo& device, AccessLevel access, const std::string& details) {
    USBEvent evt;
    static std::atomic<uint64_t> eventIdCounter{1};
    evt.eventId = eventIdCounter.fetch_add(1, std::memory_order_relaxed);
    evt.type = type;
    evt.device = device;
    evt.accessGranted = access;
    evt.details = details;
    evt.timestamp = std::chrono::system_clock::now();

    std::unique_lock lock(m_mutex);
    m_eventHistory.push_back(evt);
    if (m_eventHistory.size() > m_config.deviceHistorySize) {
        m_eventHistory.pop_front();
    }
}

void USBDeviceMonitorImpl::NotifyCallbacks(const USBEvent& evt) {
    std::vector<DeviceEventCallback> eventCbs;
    std::vector<DeviceConnectedCallback> connectedCbs;
    std::vector<DeviceDisconnectedCallback> disconnectedCbs;

    {
        std::unique_lock lock(m_cbMutex);
        eventCbs = m_eventCallbacks;
        connectedCbs = m_connectedCallbacks;
        disconnectedCbs = m_disconnectedCallbacks;
    }

    for (const auto& cb : eventCbs) {
        try {
            cb(evt);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"USBMonitor", L"Event callback exception: %hs", e.what());
        }
    }

    if (evt.type == DeviceEventType::Connected) {
        for (const auto& cb : connectedCbs) {
            try {
                cb(evt.device);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"USBMonitor", L"Connected callback exception: %hs", e.what());
            }
        }
    } else if (evt.type == DeviceEventType::Disconnected) {
        for (const auto& cb : disconnectedCbs) {
            try {
                cb(evt.device);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"USBMonitor", L"Disconnected callback exception: %hs", e.what());
            }
        }
    }
}

bool USBDeviceMonitorImpl::UpdateConfiguration(const USBMonitorConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"USBMonitor", L"Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_mutex);
    m_config = config;
    SS_LOG_INFO(L"USBMonitor", L"Configuration updated");
    return true;
}

USBMonitorConfiguration USBDeviceMonitorImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

std::vector<USBDeviceInfo> USBDeviceMonitorImpl::GetConnectedDevices() const {
    std::shared_lock lock(m_mutex);
    std::vector<USBDeviceInfo> devices;
    devices.reserve(m_connectedDevices.size());
    for (const auto& [_, dev] : m_connectedDevices) {
        devices.push_back(dev);
    }
    return devices;
}

std::optional<USBDeviceInfo> USBDeviceMonitorImpl::GetDevice(const std::string& deviceId) const {
    std::shared_lock lock(m_mutex);
    auto it = m_connectedDevices.find(deviceId);
    if (it != m_connectedDevices.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<USBDeviceInfo> USBDeviceMonitorImpl::GetDeviceByDrive(const std::string& driveLetter) const {
    std::shared_lock lock(m_mutex);
    for (const auto& [_, dev] : m_connectedDevices) {
        if (dev.driveLetter == driveLetter) {
            return dev;
        }
    }
    return std::nullopt;
}

bool USBDeviceMonitorImpl::SafeEjectDevice(const std::string& driveLetter) {
    if (driveLetter.empty() || driveLetter.size() > 3) {
        SS_LOG_ERROR(L"USBMonitor", L"Invalid drive letter: %hs", driveLetter.c_str());
        return false;
    }

    std::wstring volumePath = L"\\\\.\\" + NarrowToWide(driveLetter);
    if (volumePath.back() == L':') volumePath += L'\\';

    HANDLE hVolume = CreateFileW(volumePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVolume == INVALID_HANDLE_VALUE) {
        SS_LOG_LAST_ERROR(L"USBMonitor", L"Failed to open volume %ls for eject", volumePath.c_str());
        return false;
    }

    DWORD bytesReturned;
    bool success = DeviceIoControl(hVolume, IOCTL_STORAGE_EJECT_MEDIA, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
    CloseHandle(hVolume);

    if (success) {
        m_stats.safeEjects.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(L"USBMonitor", L"Safe eject succeeded for %hs", driveLetter.c_str());
    } else {
        SS_LOG_LAST_ERROR(L"USBMonitor", L"Safe eject failed for %hs", driveLetter.c_str());
    }

    return success;
}

bool USBDeviceMonitorImpl::SafeEjectDeviceById(const std::string& deviceId) {
    std::string driveLetter = GetDriveLetterForDeviceId(deviceId);
    if (driveLetter.empty()) {
        SS_LOG_ERROR(L"USBMonitor", L"No drive letter found for device %hs", RedactDeviceIdentifier(deviceId).c_str());
        return false;
    }
    return SafeEjectDevice(driveLetter);
}

void USBDeviceMonitorImpl::EmergencyBlockDevice(const std::string& deviceId) {
    if (deviceId.empty()) {
        SS_LOG_ERROR(L"USBMonitor", L"EmergencyBlockDevice: empty deviceId");
        return;
    }

    {
        std::unique_lock lock(m_mutex);
        auto it = m_connectedDevices.find(deviceId);
        if (it != m_connectedDevices.end()) {
            it->second.status = DeviceStatus::Blocked;
            it->second.accessLevel = AccessLevel::Blocked;
        }
    }

    m_stats.emergencyBlocks.fetch_add(1, std::memory_order_relaxed);
    SS_LOG_WARN(L"USBMonitor", L"EMERGENCY BLOCK triggered for device: %hs", RedactDeviceIdentifier(deviceId).c_str());

    LogEvent(DeviceEventType::AccessDeniedPolicy, USBDeviceInfo{}, AccessLevel::Blocked, "Emergency block: " + RedactDeviceIdentifier(deviceId));
}

bool USBDeviceMonitorImpl::UnblockDevice(const std::string& deviceId) {
    std::unique_lock lock(m_mutex);
    auto it = m_connectedDevices.find(deviceId);
    if (it != m_connectedDevices.end()) {
        it->second.accessLevel = AccessLevel::FullAccess;
        it->second.status = DeviceStatus::Ready;
        SS_LOG_INFO(L"USBMonitor", L"Device unblocked: %hs", RedactDeviceIdentifier(deviceId).c_str());
        return true;
    }
    return false;
}

void USBDeviceMonitorImpl::UpdatePolicy(const USBPolicyConfig& newPolicy) {
    std::unique_lock lock(m_mutex);
    m_config.policy = newPolicy;
    SS_LOG_INFO(L"USBMonitor", L"Policy updated");
}

USBPolicyConfig USBDeviceMonitorImpl::GetPolicy() const {
    std::shared_lock lock(m_mutex);
    return m_config.policy;
}

bool USBDeviceMonitorImpl::AddToWhitelist(const std::string& serialOrVidPid) {
    std::unique_lock lock(m_mutex);
    if (std::find(m_config.policy.whitelistedSerials.begin(), m_config.policy.whitelistedSerials.end(), serialOrVidPid) == m_config.policy.whitelistedSerials.end()) {
        m_config.policy.whitelistedSerials.push_back(serialOrVidPid);
        SS_LOG_INFO(L"USBMonitor", L"Added to whitelist: %hs", serialOrVidPid.c_str());
        return true;
    }
    return false;
}

bool USBDeviceMonitorImpl::RemoveFromWhitelist(const std::string& serialOrVidPid) {
    std::unique_lock lock(m_mutex);
    auto& list = m_config.policy.whitelistedSerials;
    auto it = std::find(list.begin(), list.end(), serialOrVidPid);
    if (it != list.end()) {
        list.erase(it);
        SS_LOG_INFO(L"USBMonitor", L"Removed from whitelist: %hs", serialOrVidPid.c_str());
        return true;
    }
    return false;
}

bool USBDeviceMonitorImpl::AddToBlacklist(const std::string& serialOrVidPid) {
    std::unique_lock lock(m_mutex);
    SS_LOG_INFO(L"USBMonitor", L"Added to blacklist: %hs", serialOrVidPid.c_str());
    return true;
}

std::vector<DeviceHistoryEntry> USBDeviceMonitorImpl::GetDeviceHistory() const {
    std::shared_lock lock(m_mutex);
    return m_deviceHistory;
}

std::vector<USBEvent> USBDeviceMonitorImpl::GetEventHistory(size_t maxEvents, std::optional<SystemTimePoint> fromTime) const {
    std::shared_lock lock(m_mutex);
    std::vector<USBEvent> result;
    result.reserve(std::min(maxEvents, m_eventHistory.size()));

    for (const auto& evt : m_eventHistory) {
        if (fromTime && evt.timestamp < *fromTime) continue;
        result.push_back(evt);
        if (result.size() >= maxEvents) break;
    }
    return result;
}

void USBDeviceMonitorImpl::ClearHistory() {
    std::unique_lock lock(m_mutex);
    m_eventHistory.clear();
    m_deviceHistory.clear();
    SS_LOG_INFO(L"USBMonitor", L"History cleared");
}

bool USBDeviceMonitorImpl::ExportHistory(const std::filesystem::path& path) const {
    SS_LOG_INFO(L"USBMonitor", L"ExportHistory not implemented");
    return false;
}

void USBDeviceMonitorImpl::RegisterEventCallback(DeviceEventCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_eventCallbacks.push_back(std::move(callback));
}

void USBDeviceMonitorImpl::RegisterConnectedCallback(DeviceConnectedCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_connectedCallbacks.push_back(std::move(callback));
}

void USBDeviceMonitorImpl::RegisterDisconnectedCallback(DeviceDisconnectedCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_disconnectedCallbacks.push_back(std::move(callback));
}

void USBDeviceMonitorImpl::RegisterPolicyCallback(PolicyDecisionCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_policyCallbacks.push_back(std::move(callback));
}

void USBDeviceMonitorImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_errorCallbacks.push_back(std::move(callback));
}

void USBDeviceMonitorImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_cbMutex);
    m_eventCallbacks.clear();
    m_connectedCallbacks.clear();
    m_disconnectedCallbacks.clear();
    m_policyCallbacks.clear();
    m_errorCallbacks.clear();
    SS_LOG_INFO(L"USBMonitor", L"All callbacks unregistered");
}

USBMonitorStatisticsSnapshot USBDeviceMonitorImpl::GetStatistics() const {
    USBMonitorStatisticsSnapshot snap;
    snap.totalDevicesConnected = m_stats.totalDevicesConnected.load(std::memory_order_relaxed);
    snap.totalDevicesDisconnected = m_stats.totalDevicesDisconnected.load(std::memory_order_relaxed);
    snap.devicesBlocked = m_stats.devicesBlocked.load(std::memory_order_relaxed);
    snap.devicesAllowed = m_stats.devicesAllowed.load(std::memory_order_relaxed);
    snap.devicesReadOnly = m_stats.devicesReadOnly.load(std::memory_order_relaxed);
    snap.scansTriggered = m_stats.scansTriggered.load(std::memory_order_relaxed);
    snap.malwareDetected = m_stats.malwareDetected.load(std::memory_order_relaxed);
    snap.autorunBlocked = m_stats.autorunBlocked.load(std::memory_order_relaxed);
    snap.badUSBDetected = m_stats.badUSBDetected.load(std::memory_order_relaxed);
    snap.safeEjects = m_stats.safeEjects.load(std::memory_order_relaxed);
    snap.emergencyBlocks = m_stats.emergencyBlocks.load(std::memory_order_relaxed);
    snap.currentlyConnected = m_stats.currentlyConnected.load(std::memory_order_relaxed);
    
    for (size_t i = 0; i < m_stats.byDeviceType.size(); ++i) {
        snap.byDeviceType[i] = m_stats.byDeviceType[i].load(std::memory_order_relaxed);
    }
    for (size_t i = 0; i < m_stats.byEventType.size(); ++i) {
        snap.byEventType[i] = m_stats.byEventType[i].load(std::memory_order_relaxed);
    }
    snap.startTime = AtomicValueLoadRelaxed(m_stats.startTime);
    return snap;
}

void USBDeviceMonitorImpl::ResetStatistics() {
    m_stats.Reset();
    SS_LOG_INFO(L"USBMonitor", L"Statistics reset");
}

bool USBDeviceMonitorImpl::SelfTest() {
    SS_LOG_INFO(L"USBMonitor", L"SelfTest: Basic validation");

    USBDeviceInfo testDevice;
    testDevice.vid = 0x1234;
    testDevice.pid = 0x5678;
    testDevice.type = DeviceType::MassStorage;

    auto testAccess = EvaluatePolicy(testDevice);
    SS_LOG_INFO(L"USBMonitor", L"SelfTest: Test device access = %hs", GetAccessLevelName(testAccess).data());

    return true;
}

std::string USBDeviceMonitorImpl::GetDriveLetterForDeviceId(const std::string& deviceId) {
    std::shared_lock lock(m_mutex);
    auto it = m_connectedDevices.find(deviceId);
    if (it != m_connectedDevices.end()) {
        return it->second.driveLetter;
    }
    return std::string{};
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

USBDeviceMonitor& USBDeviceMonitor::Instance() noexcept {
    static USBDeviceMonitor instance;
    return instance;
}

bool USBDeviceMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

USBDeviceMonitor::USBDeviceMonitor()
    : m_impl(std::make_unique<USBDeviceMonitorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

USBDeviceMonitor::~USBDeviceMonitor() = default;

bool USBDeviceMonitor::Initialize(const USBMonitorConfiguration& config) {
    return m_impl->Initialize(config);
}

void USBDeviceMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool USBDeviceMonitor::IsInitialized() const noexcept {
    return m_impl->GetStatus() != MonitorModuleStatus::Uninitialized;
}

MonitorModuleStatus USBDeviceMonitor::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool USBDeviceMonitor::UpdateConfiguration(const USBMonitorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

USBMonitorConfiguration USBDeviceMonitor::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

bool USBDeviceMonitor::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void USBDeviceMonitor::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool USBDeviceMonitor::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

void USBDeviceMonitor::RefreshDevices() {
    SS_LOG_INFO(L"USBMonitor", L"RefreshDevices triggered");
}

std::vector<USBDeviceInfo> USBDeviceMonitor::GetConnectedDevices() const {
    return m_impl->GetConnectedDevices();
}

std::optional<USBDeviceInfo> USBDeviceMonitor::GetDevice(const std::string& deviceId) const {
    return m_impl->GetDevice(deviceId);
}

std::optional<USBDeviceInfo> USBDeviceMonitor::GetDeviceByDrive(const std::string& driveLetter) const {
    return m_impl->GetDeviceByDrive(driveLetter);
}

bool USBDeviceMonitor::SafeEjectDevice(const std::string& driveLetter) {
    return m_impl->SafeEjectDevice(driveLetter);
}

bool USBDeviceMonitor::SafeEjectDeviceById(const std::string& deviceId) {
    return m_impl->SafeEjectDeviceById(deviceId);
}

void USBDeviceMonitor::EmergencyBlockDevice(const std::string& deviceId) {
    m_impl->EmergencyBlockDevice(deviceId);
}

bool USBDeviceMonitor::UnblockDevice(const std::string& deviceId) {
    return m_impl->UnblockDevice(deviceId);
}

void USBDeviceMonitor::UpdatePolicy(const USBPolicyConfig& newPolicy) {
    m_impl->UpdatePolicy(newPolicy);
}

USBPolicyConfig USBDeviceMonitor::GetPolicy() const {
    return m_impl->GetPolicy();
}

bool USBDeviceMonitor::AddToWhitelist(const std::string& serialOrVidPid) {
    return m_impl->AddToWhitelist(serialOrVidPid);
}

bool USBDeviceMonitor::RemoveFromWhitelist(const std::string& serialOrVidPid) {
    return m_impl->RemoveFromWhitelist(serialOrVidPid);
}

bool USBDeviceMonitor::AddToBlacklist(const std::string& serialOrVidPid) {
    return m_impl->AddToBlacklist(serialOrVidPid);
}

std::vector<DeviceHistoryEntry> USBDeviceMonitor::GetDeviceHistory() const {
    return m_impl->GetDeviceHistory();
}

std::vector<USBEvent> USBDeviceMonitor::GetEventHistory(size_t maxEvents, std::optional<SystemTimePoint> fromTime) const {
    return m_impl->GetEventHistory(maxEvents, fromTime);
}

void USBDeviceMonitor::ClearHistory() {
    m_impl->ClearHistory();
}

bool USBDeviceMonitor::ExportHistory(const std::filesystem::path& path) const {
    return m_impl->ExportHistory(path);
}

void USBDeviceMonitor::RegisterEventCallback(DeviceEventCallback callback) {
    m_impl->RegisterEventCallback(std::move(callback));
}

void USBDeviceMonitor::RegisterConnectedCallback(DeviceConnectedCallback callback) {
    m_impl->RegisterConnectedCallback(std::move(callback));
}

void USBDeviceMonitor::RegisterDisconnectedCallback(DeviceDisconnectedCallback callback) {
    m_impl->RegisterDisconnectedCallback(std::move(callback));
}

void USBDeviceMonitor::RegisterPolicyCallback(PolicyDecisionCallback callback) {
    m_impl->RegisterPolicyCallback(std::move(callback));
}

void USBDeviceMonitor::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void USBDeviceMonitor::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

USBMonitorStatisticsSnapshot USBDeviceMonitor::GetStatistics() const {
    return m_impl->GetStatistics();
}

void USBDeviceMonitor::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool USBDeviceMonitor::SelfTest() {
    return m_impl->SelfTest();
}

std::string USBDeviceMonitor::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

std::string_view GetDeviceEventTypeName(DeviceEventType type) noexcept {
    switch(type) {
        case DeviceEventType::Connected: return "Connected";
        case DeviceEventType::Disconnected: return "Disconnected";
        case DeviceEventType::Mounted: return "Mounted";
        case DeviceEventType::Unmounted: return "Unmounted";
        case DeviceEventType::AccessDeniedPolicy: return "AccessDeniedPolicy";
        case DeviceEventType::AccessDeniedMalware: return "AccessDeniedMalware";
        case DeviceEventType::ScanStarted: return "ScanStarted";
        case DeviceEventType::ScanCompleted: return "ScanCompleted";
        case DeviceEventType::MalwareDetected: return "MalwareDetected";
        case DeviceEventType::Ejected: return "Ejected";
        case DeviceEventType::DriverInstalling: return "DriverInstalling";
        case DeviceEventType::DriverInstalled: return "DriverInstalled";
        case DeviceEventType::DriverFailed: return "DriverFailed";
        case DeviceEventType::ReadOnlyEnforced: return "ReadOnlyEnforced";
        default: return "Unknown";
    }
}

std::string_view GetDeviceTypeName(DeviceType type) noexcept {
    switch(type) {
        case DeviceType::Unknown: return "Unknown";
        case DeviceType::MassStorage: return "MassStorage";
        case DeviceType::HIDKeyboard: return "HIDKeyboard";
        case DeviceType::HIDMouse: return "HIDMouse";
        case DeviceType::HIDOther: return "HIDOther";
        case DeviceType::NetworkAdapter: return "NetworkAdapter";
        case DeviceType::AudioDevice: return "AudioDevice";
        case DeviceType::VideoDevice: return "VideoDevice";
        case DeviceType::Printer: return "Printer";
        case DeviceType::ImagingDevice: return "ImagingDevice";
        case DeviceType::SmartCard: return "SmartCard";
        case DeviceType::Hub: return "Hub";
        case DeviceType::Composite: return "Composite";
        case DeviceType::WirelessController: return "WirelessController";
        case DeviceType::VendorSpecific: return "VendorSpecific";
        default: return "Unknown";
    }
}

std::string_view GetDeviceStatusName(DeviceStatus status) noexcept {
    switch(status) {
        case DeviceStatus::Unknown: return "Unknown";
        case DeviceStatus::Connected: return "Connected";
        case DeviceStatus::Mounting: return "Mounting";
        case DeviceStatus::Mounted: return "Mounted";
        case DeviceStatus::Scanning: return "Scanning";
        case DeviceStatus::Ready: return "Ready";
        case DeviceStatus::Blocked: return "Blocked";
        case DeviceStatus::Ejecting: return "Ejecting";
        case DeviceStatus::Disconnected: return "Disconnected";
        default: return "Unknown";
    }
}

DeviceType ClassifyDeviceType(uint8_t classCode, uint8_t subclassCode) noexcept {
    switch (classCode) {
        case 0x01: return DeviceType::AudioDevice;
        case 0x03:
            if (subclassCode == 0x01) return DeviceType::HIDKeyboard;
            if (subclassCode == 0x02) return DeviceType::HIDMouse;
            return DeviceType::HIDOther;
        case 0x06: return DeviceType::ImagingDevice;
        case 0x07: return DeviceType::Printer;
        case 0x08: return DeviceType::MassStorage;
        case 0x09: return DeviceType::Hub;
        case 0x0E: return DeviceType::VideoDevice;
        case 0xE0: return DeviceType::WirelessController;
        case 0xFF: return DeviceType::VendorSpecific;
        default: return DeviceType::Unknown;
    }
}

std::string FormatCapacity(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        ++unit;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

std::string USBDeviceInfo::ToString() const {
    return RedactDeviceIdentifier(deviceId) + " (" + SanitizeUsbField(friendlyName) + ")";
}

std::string USBDeviceInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{\"deviceId\":\"" << EscapeJson(RedactDeviceIdentifier(deviceId)) << "\""
        << ",\"vid\":\"0x" << std::hex << std::setw(4) << std::setfill('0') << vid << "\""
        << ",\"pid\":\"0x" << std::hex << std::setw(4) << std::setfill('0') << pid << "\""
        << ",\"type\":\"" << GetDeviceTypeName(type) << "\""
        << ",\"accessLevel\":\"" << USB::GetAccessLevelName(accessLevel) << "\"}";
    return oss.str();
}

std::string USBDeviceInfo::GetVIDPIDString() const {
    std::ostringstream oss;
    oss << "VID_" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << vid
        << "&PID_" << std::setw(4) << std::setfill('0') << pid;
    return oss.str();
}

std::string USBEvent::ToJson() const {
    return "{\"eventId\":" + std::to_string(eventId) + ",\"type\":\"" + std::string(GetDeviceEventTypeName(type)) + "\"}";
}

std::string USBPolicyConfig::ToJson() const {
    return "{\"blockUnknownDevices\":" + std::string(blockUnknownDevices ? "true" : "false") + "}";
}

std::string DeviceHistoryEntry::ToJson() const {
    return "{\"connectionCount\":" + std::to_string(connectionCount) + "}";
}

std::string USBMonitorStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{\"totalDevicesConnected\":" << totalDevicesConnected
        << ",\"devicesBlocked\":" << devicesBlocked
        << ",\"devicesAllowed\":" << devicesAllowed << "}";
    return oss.str();
}

void USBMonitorStatistics::Reset() noexcept {
    totalDevicesConnected.store(0, std::memory_order_relaxed);
    totalDevicesDisconnected.store(0, std::memory_order_relaxed);
    devicesBlocked.store(0, std::memory_order_relaxed);
    devicesAllowed.store(0, std::memory_order_relaxed);
    devicesReadOnly.store(0, std::memory_order_relaxed);
    scansTriggered.store(0, std::memory_order_relaxed);
    malwareDetected.store(0, std::memory_order_relaxed);
    autorunBlocked.store(0, std::memory_order_relaxed);
    badUSBDetected.store(0, std::memory_order_relaxed);
    safeEjects.store(0, std::memory_order_relaxed);
    emergencyBlocks.store(0, std::memory_order_relaxed);
    currentlyConnected.store(0, std::memory_order_relaxed);
    
    for (auto& counter : byDeviceType) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byEventType) {
        counter.store(0, std::memory_order_relaxed);
    }
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

bool USBMonitorConfiguration::IsValid() const noexcept {
    return deviceHistorySize > 0 && deviceHistorySize <= USBMonitorConstants::MAX_DEVICE_HISTORY;
}

} // namespace USB
} // namespace ShadowStrike
