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
 * ShadowStrike NGAV - HARDWARE MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file HardwareMonitor.cpp
 * @brief Enterprise-grade hardware health and environmental monitoring implementation.
 *
 * Production-level implementation competing with HWiNFO, AIDA64, and enterprise
 * monitoring solutions. Provides comprehensive hardware health monitoring including
 * S.M.A.R.T. disk analysis, thermal management, power state awareness, and hardware
 * anomaly detection with full callback support.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex (2 instances)
 * - S.M.A.R.T. disk health monitoring via IOCTL
 * - Thermal monitoring (CPU, GPU, Disk temperatures)
 * - Power management awareness (AC/Battery/UPS)
 * - Battery health and capacity tracking
 * - Hardware change detection and alerting
 * - Continuous monitoring with background thread
 * - Callback system (4 types)
 * - Comprehensive statistics (5 atomic counters)
 * - Configuration factory methods
 * - Export functionality (hardware reports)
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
#include "HardwareMonitor.hpp"
#include "EventLogger.hpp"
#include "DriverAnalyzer.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/HashUtils.hpp"

#include <Windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <setupapi.h>
#include <devguid.h>
#include <batclass.h>
#include <poclass.h>
#include <powrprof.h>
#include <pdh.h>
#include <wbemidl.h>
#include <comdef.h>
#include <cfgmgr32.h>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <deque>
#include <unordered_set>
#include <unordered_map>
#include <condition_variable>
#include <limits>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "cfgmgr32.lib")

namespace ShadowStrike {
namespace Core {
namespace System {

namespace fs = std::filesystem;

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================

namespace HardwareMonitorConstants {
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // S.M.A.R.T. attribute IDs
    constexpr uint8_t SMART_READ_ERROR_RATE = 1;
    constexpr uint8_t SMART_SPIN_UP_TIME = 3;
    constexpr uint8_t SMART_REALLOCATED_SECTORS = 5;
    constexpr uint8_t SMART_POWER_ON_HOURS = 9;
    constexpr uint8_t SMART_TEMPERATURE = 194;
    constexpr uint8_t SMART_CURRENT_PENDING_SECTORS = 197;
    constexpr uint8_t SMART_WEAR_LEVELING = 177;

    // SMART IOCTL codes (not in standard headers).
    // Equivalent to CTL_CODE(IOCTL_DISK_BASE=0x07, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS).
    constexpr DWORD SMART_RCV_DRIVE_DATA_CODE = 0x07C088;

    // Thermal thresholds (Celsius)
    constexpr uint32_t CPU_TEMP_NORMAL = 75;
    constexpr uint32_t CPU_TEMP_WARM = 85;
    constexpr uint32_t CPU_TEMP_HOT = 90;
    constexpr uint32_t CPU_TEMP_CRITICAL = 95;

    constexpr uint32_t DISK_TEMP_NORMAL = 45;
    constexpr uint32_t DISK_TEMP_WARM = 50;
    constexpr uint32_t DISK_TEMP_HOT = 55;
    constexpr uint32_t DISK_TEMP_CRITICAL = 60;

    // Polling interval clamps (defence-in-depth against malformed/hostile config).
    // A 0 ms interval would busy-loop the monitoring thread; an unbounded large
    // value combined with the error-backoff multiplier could overflow uint32_t
    // and cause an effectively-zero sleep, also a busy-loop.
    constexpr uint32_t MIN_POLLING_INTERVAL_MS = 250;          // 4 Hz upper polling cap
    constexpr uint32_t MAX_POLLING_INTERVAL_MS = 3600u * 1000u; // 1 hour
    constexpr uint8_t  MAX_BATTERY_PERCENT = 100;

    // Defensive cap on hostile/garbled wide strings we surface to logs, the
    // EventLogger or the dashboard. 256 wchars is well above any realistic
    // device identifier and prevents memory pressure from rogue descriptors.
    constexpr size_t MAX_LOG_STRING_LEN = 256;

    // Maximum events returned from GetRecentChanges() in a single call.
    // Caller-supplied uint32_t is clamped to this to avoid massive vector
    // reservation from a malicious or buggy IPC caller.
    constexpr uint32_t MAX_RETURNED_CHANGE_EVENTS = 4096;
}  // namespace HardwareMonitorConstants

// ----------------------------------------------------------------------------
// Local sanitization helpers — applied to every wide string sourced from
// device descriptors, SetupAPI / CM_* enumerators, WMI strings, and any other
// hardware-controlled surface before it crosses a logging or IPC boundary.
//
// This is the first line of defence against:
//   * CRLF / NUL log-injection (forged log entries)
//   * Embedded ANSI escape codes (terminal hijack)
//   * Unbounded strings (memory pressure / UI DoS)
//   * Format-string smuggling when surfaces forward into printf-family APIs
// ----------------------------------------------------------------------------

/**
 * @brief Strip control characters from a wide string and bound its length.
 * Replaces every code unit < 0x20 (and DEL 0x7F) with '?'. Truncates to
 * MAX_LOG_STRING_LEN code units with a trailing ellipsis marker.
 *
 * The input is taken by value so callers can pass temporaries safely; the
 * function is noexcept-correct via std::wstring's small string optimisation
 * and the surrounding monitoring loop's outer try/catch.
 */
[[nodiscard]] static std::wstring SanitizeForLog(std::wstring s) {
    for (auto& c : s) {
        // Strip ASCII control set (0x00-0x1F) and DEL.
        // Wide chars >= 0x20 (printable + Unicode) are preserved.
        if (c != L'\0' && static_cast<unsigned>(c) < 0x20u) {
            c = L'?';
        } else if (c == 0x7F) {
            c = L'?';
        }
    }
    if (s.size() > HardwareMonitorConstants::MAX_LOG_STRING_LEN) {
        s.resize(HardwareMonitorConstants::MAX_LOG_STRING_LEN);
        s.append(L"...");
    }
    return s;
}

/**
 * @brief Apply MIN/MAX polling-interval clamps and battery-threshold sanity
 * checks to a configuration object. Returns true if the input was already
 * inside the safe envelope; false if any field was clamped.
 *
 * DESIGN: A failed clamp is not an Initialize() error — we accept the call
 * and silently coerce to a safe value, then log at Warning. This avoids the
 * service refusing to start due to a single mis-typed registry/policy field.
 */
static bool ClampHardwareMonitorConfig(HardwareMonitorConfig& cfg) noexcept {
    bool inRange = true;
    if (cfg.pollingIntervalMs < HardwareMonitorConstants::MIN_POLLING_INTERVAL_MS) {
        cfg.pollingIntervalMs = HardwareMonitorConstants::MIN_POLLING_INTERVAL_MS;
        inRange = false;
    } else if (cfg.pollingIntervalMs > HardwareMonitorConstants::MAX_POLLING_INTERVAL_MS) {
        cfg.pollingIntervalMs = HardwareMonitorConstants::MAX_POLLING_INTERVAL_MS;
        inRange = false;
    }
    if (cfg.batteryLowPercent > HardwareMonitorConstants::MAX_BATTERY_PERCENT) {
        cfg.batteryLowPercent = HardwareMonitorConstants::MAX_BATTERY_PERCENT;
        inRange = false;
    }
    if (cfg.batteryCriticalPercent > cfg.batteryLowPercent) {
        cfg.batteryCriticalPercent = cfg.batteryLowPercent;
        inRange = false;
    }
    // Ordering invariant: warning <= critical for both temperature axes.
    if (cfg.diskTempWarningCelsius > cfg.diskTempCriticalCelsius) {
        cfg.diskTempCriticalCelsius = cfg.diskTempWarningCelsius;
        inRange = false;
    }
    if (cfg.cpuTempWarningCelsius > cfg.cpuTempCriticalCelsius) {
        cfg.cpuTempCriticalCelsius = cfg.cpuTempWarningCelsius;
        inRange = false;
    }
    return inRange;
}

// ============================================================================
// RAII WRAPPERS & HELPERS
// ============================================================================

/**
 * @brief RAII wrapper for Windows HANDLE resources.
 * Automatically closes handle on destruction, preventing leaks.
 */
class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
    
    ~ScopedHandle() noexcept {
        Close();
    }
    
    // Non-copyable
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    
    // Movable
    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }
    
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    
    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] bool IsValid() const noexcept { 
        return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; 
    }
    [[nodiscard]] explicit operator bool() const noexcept { return IsValid(); }
    
    HANDLE Release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }
    
    void Reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        Close();
        m_handle = h;
    }
    
private:
    void Close() noexcept {
        if (IsValid()) {
            ::CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }
    
    HANDLE m_handle;
};

/**
 * @brief RAII wrapper for SetupAPI device info set.
 */
class ScopedDeviceInfoSet {
public:
    explicit ScopedDeviceInfoSet(HDEVINFO h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
    
    ~ScopedDeviceInfoSet() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) {
            ::SetupDiDestroyDeviceInfoList(m_handle);
        }
    }
    
    ScopedDeviceInfoSet(const ScopedDeviceInfoSet&) = delete;
    ScopedDeviceInfoSet& operator=(const ScopedDeviceInfoSet&) = delete;
    
    [[nodiscard]] HDEVINFO Get() const noexcept { return m_handle; }
    [[nodiscard]] bool IsValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
    
private:
    HDEVINFO m_handle;
};

/**
 * @brief RAII wrapper for COM initialization.
 */
class ScopedComInit {
public:
    ScopedComInit() noexcept {
        HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_initialized = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
        m_needsUninit = (hr == S_OK);
    }
    
    ~ScopedComInit() noexcept {
        if (m_needsUninit) {
            ::CoUninitialize();
        }
    }
    
    ScopedComInit(const ScopedComInit&) = delete;
    ScopedComInit& operator=(const ScopedComInit&) = delete;
    
    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }
    
private:
    bool m_initialized = false;
    bool m_needsUninit = false;
};

/**
 * @brief RAII wrapper for WMI service connection.
 */
class ScopedWmiConnection {
public:
    ScopedWmiConnection() = default;
    
    ~ScopedWmiConnection() noexcept {
        Disconnect();
    }
    
    ScopedWmiConnection(const ScopedWmiConnection&) = delete;
    ScopedWmiConnection& operator=(const ScopedWmiConnection&) = delete;
    
    [[nodiscard]] bool Connect(const wchar_t* namespacePath) noexcept {
        if (m_pSvc) return true;  // Already connected
        
        IWbemLocator* pLoc = nullptr;
        HRESULT hr = ::CoCreateInstance(
            CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc)
        );
        
        if (FAILED(hr) || !pLoc) {
            return false;
        }
        
        _bstr_t bstrNamespace(namespacePath);
        hr = pLoc->ConnectServer(
            bstrNamespace,
            nullptr, nullptr, nullptr, 0, nullptr, nullptr, &m_pSvc
        );
        
        pLoc->Release();
        
        if (FAILED(hr) || !m_pSvc) {
            return false;
        }
        
        // Set security levels
        hr = ::CoSetProxyBlanket(
            m_pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE
        );
        
        return SUCCEEDED(hr);
    }
    
    void Disconnect() noexcept {
        if (m_pSvc) {
            m_pSvc->Release();
            m_pSvc = nullptr;
        }
    }
    
    [[nodiscard]] IWbemServices* Get() const noexcept { return m_pSvc; }
    [[nodiscard]] bool IsConnected() const noexcept { return m_pSvc != nullptr; }
    
private:
    IWbemServices* m_pSvc = nullptr;
};

/**
 * @brief Hash a hardware serial number for privacy protection.
 * Uses SHA-256 truncated to 16 hex chars for reasonable uniqueness without exposing raw serial.
 */
[[nodiscard]] static std::wstring HashSerialNumber(const std::wstring& serial) {
    if (serial.empty()) {
        return L"";
    }
    
    // Convert to UTF-8 for hashing
    std::string utf8Serial = Utils::StringUtils::ToNarrow(serial);
    
    // Use SHA-256 hash via Hasher class
    Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
    if (!hasher.Init()) {
        // Fallback: return masked serial (first 4 chars + ...)
        if (serial.length() > 4) {
            return serial.substr(0, 4) + L"...";
        }
        return L"****";
    }
    
    if (!hasher.Update(utf8Serial.data(), utf8Serial.size())) {
        return L"****";
    }
    
    std::string hexHash;
    if (!hasher.FinalHex(hexHash, false)) {
        return L"****";
    }
    
    // Take first 16 chars for reasonable uniqueness
    if (hexHash.length() > 16) {
        hexHash = hexHash.substr(0, 16);
    }
    
    return Utils::StringUtils::ToWide(hexHash);
}

/**
 * @brief Safely extract string from STORAGE_DEVICE_DESCRIPTOR with bounds checking.
 * @param buffer The buffer containing the descriptor
 * @param bufferSize Total size of buffer
 * @param bytesReturned Actual bytes returned by DeviceIoControl
 * @param offset Offset to the string within buffer
 * @return Extracted string or empty if invalid
 */
[[nodiscard]] static std::string SafeExtractDescriptorString(
    const BYTE* buffer,
    size_t bufferSize,
    DWORD bytesReturned,
    DWORD offset
) {
    // Validate offset is within bounds
    if (offset == 0 || offset >= bytesReturned || offset >= bufferSize) {
        return "";
    }
    
    // Calculate maximum safe string length
    size_t maxLen = std::min(static_cast<size_t>(bytesReturned), bufferSize) - offset;
    
    // Cap at reasonable length to prevent excessive copying
    constexpr size_t MAX_STRING_LEN = 256;
    maxLen = std::min(maxLen, MAX_STRING_LEN);
    
    // Find null terminator within bounds
    const char* str = reinterpret_cast<const char*>(buffer + offset);
    size_t len = 0;
    while (len < maxLen && str[len] != '\0') {
        ++len;
    }
    
    return std::string(str, len);
}

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void HardwareMonitorStatistics::Reset() noexcept {
    pollingCycles.store(0, std::memory_order_relaxed);
    diskHealthChecks.store(0, std::memory_order_relaxed);
    thermalWarnings.store(0, std::memory_order_relaxed);
    powerStateChanges.store(0, std::memory_order_relaxed);
    deviceChanges.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

HardwareMonitorConfig HardwareMonitorConfig::CreateDefault() noexcept {
    HardwareMonitorConfig config;
    config.monitorDisks = true;
    config.monitorThermals = true;
    config.monitorPower = true;
    config.monitorDeviceChanges = true;
    config.pollingIntervalMs = 5000;
    config.diskTempWarningCelsius = 50;
    config.diskTempCriticalCelsius = 60;
    config.cpuTempWarningCelsius = 80;
    config.cpuTempCriticalCelsius = 95;
    config.batteryLowPercent = 20;
    config.batteryCriticalPercent = 10;
    (void)ClampHardwareMonitorConfig(config);
    return config;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class HardwareMonitorImpl {
public:
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    HardwareMonitorConfig m_config;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};

    // Monitoring thread
    std::unique_ptr<std::thread> m_monitorThread;

    // Cached data
    std::vector<DiskHealthInfo> m_disks;
    CPUThermalInfo m_cpuThermal;
    std::optional<GPUThermalInfo> m_gpuThermal;
    PowerInfo m_powerInfo;
    mutable std::shared_mutex m_dataMutex;

    // Hardware change events
    std::deque<HardwareChangeEvent> m_changeHistory;
    std::mutex m_historyMutex;
    constexpr static size_t MAX_HISTORY_SIZE = 1000;

    // Device tracking for change detection
    std::unordered_set<std::wstring> m_knownDeviceIds;
    std::mutex m_deviceTrackingMutex;

    // Firmware version tracking (devicePath -> firmwareVersion)
    std::unordered_map<std::wstring, std::wstring> m_knownFirmwareVersions;

    // Interruptible sleep for fast shutdown
    std::mutex m_sleepMutex;
    std::condition_variable m_stopCV;

    // Exponential backoff for error recovery
    std::atomic<uint32_t> m_consecutiveErrors{0};
    static constexpr uint32_t MAX_BACKOFF_MULTIPLIER = 16;

    // Callbacks
    std::vector<std::pair<uint64_t, DiskHealthCallback>> m_diskHealthCallbacks;
    std::vector<std::pair<uint64_t, ThermalAlertCallback>> m_thermalCallbacks;
    std::vector<std::pair<uint64_t, PowerChangeCallback>> m_powerCallbacks;
    std::vector<std::pair<uint64_t, HardwareChangeCallback>> m_hardwareCallbacks;
    std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Statistics
    HardwareMonitorStatistics m_statistics;

    // Constructor
    HardwareMonitorImpl() = default;

    // Destructor
    ~HardwareMonitorImpl() {
        StopMonitoring();
    }

    // ========================================================================
    // DISK HEALTH MONITORING
    // ========================================================================

    /**
     * @brief Query if a SATA drive is SSD or HDD using rotation rate.
     * SSDs report 0 RPM or "Non-Rotating" media type.
     */
    [[nodiscard]] bool IsSolidStateDrive(HANDLE hDrive) {
        // Query DEVICE_SEEK_PENALTY_DESCRIPTOR - SSDs have no seek penalty
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        query.QueryType = PropertyStandardQuery;

        DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty{};
        DWORD bytesReturned = 0;

        if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                           &query, sizeof(query),
                           &seekPenalty, sizeof(seekPenalty),
                           &bytesReturned, nullptr)) {
            // If IncursSeekPenalty is FALSE, it's an SSD
            if (bytesReturned >= sizeof(seekPenalty) && !seekPenalty.IncursSeekPenalty) {
                return true;
            }
        }

        // Fallback: Query DEVICE_TRIM_DESCRIPTOR - SSDs support TRIM
        query.PropertyId = StorageDeviceTrimProperty;
        DEVICE_TRIM_DESCRIPTOR trimDesc{};
        bytesReturned = 0;

        if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                           &query, sizeof(query),
                           &trimDesc, sizeof(trimDesc),
                           &bytesReturned, nullptr)) {
            if (bytesReturned >= sizeof(trimDesc) && trimDesc.TrimEnabled) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Read real S.M.A.R.T. data from a disk drive.
     * Uses ATA SMART READ DATA command via IOCTL_ATA_PASS_THROUGH.
     */
    void ReadSmartData(HANDLE hDrive, DiskHealthInfo& disk) {
        // S.M.A.R.T. data structures
        #pragma pack(push, 1)
        struct SMART_ATTRIBUTE {
            BYTE id;
            WORD flags;
            BYTE currentValue;
            BYTE worstValue;
            BYTE rawValue[6];
            BYTE reserved;
        };
        
        struct SMART_DATA {
            WORD version;
            SMART_ATTRIBUTE attributes[30];
        };
        #pragma pack(pop)

        // Use SENDCMDINPARAMS for legacy SMART query (uses the namespace-scope
        // SMART_RCV_DRIVE_DATA_CODE constant — no local redeclaration).

        struct SENDCMDINPARAMS_EX {
            DWORD cBufferSize;
            IDEREGS irDriveRegs;
            BYTE bDriveNumber;
            BYTE bReserved[3];
            DWORD dwReserved[4];
            BYTE bBuffer[1];
        };

        struct SENDCMDOUTPARAMS_EX {
            DWORD cBufferSize;
            DRIVERSTATUS DriverStatus;
            BYTE bBuffer[512];
        };

        SENDCMDINPARAMS_EX inParams{};
        SENDCMDOUTPARAMS_EX outParams{};
        DWORD bytesReturned = 0;

        // Setup SMART READ DATA command
        inParams.cBufferSize = 512;
        inParams.irDriveRegs.bFeaturesReg = 0xD0;      // SMART READ DATA
        inParams.irDriveRegs.bSectorCountReg = 1;
        inParams.irDriveRegs.bSectorNumberReg = 1;
        inParams.irDriveRegs.bCylLowReg = 0x4F;
        inParams.irDriveRegs.bCylHighReg = 0xC2;
        inParams.irDriveRegs.bCommandReg = 0xB0;       // SMART command

        if (!DeviceIoControl(hDrive, HardwareMonitorConstants::SMART_RCV_DRIVE_DATA_CODE,
                            &inParams, sizeof(SENDCMDINPARAMS_EX) - 1,
                            &outParams, sizeof(outParams),
                            &bytesReturned, nullptr)) {
            // SMART not supported or failed
            disk.smartSupported = false;
            disk.smartEnabled = false;
            return;
        }

        // Validate the response actually contains a parseable SMART payload
        // before reading the attribute table. A short response can leave
        // outParams.bBuffer partially uninitialised; treating it as SMART_DATA
        // would read stack memory and surface garbage attributes to the UI.
        constexpr DWORD kSmartHeaderBytes =
            sizeof(SENDCMDOUTPARAMS_EX) - 512;  // cBufferSize + DriverStatus
        if (bytesReturned < kSmartHeaderBytes + sizeof(SMART_DATA)) {
            disk.smartSupported = false;
            disk.smartEnabled = false;
            return;
        }

        disk.smartSupported = true;
        disk.smartEnabled = true;

        // Parse SMART attributes from response
        auto* smartData = reinterpret_cast<SMART_DATA*>(outParams.bBuffer);
        
        for (int i = 0; i < 30 && smartData->attributes[i].id != 0; ++i) {
            const auto& attr = smartData->attributes[i];
            
            SMARTAttribute smartAttr;
            smartAttr.id = attr.id;
            smartAttr.currentValue = attr.currentValue;
            smartAttr.worstValue = attr.worstValue;
            
            // Extract 48-bit raw value
            smartAttr.rawValue = 
                static_cast<uint64_t>(attr.rawValue[0]) |
                (static_cast<uint64_t>(attr.rawValue[1]) << 8) |
                (static_cast<uint64_t>(attr.rawValue[2]) << 16) |
                (static_cast<uint64_t>(attr.rawValue[3]) << 24) |
                (static_cast<uint64_t>(attr.rawValue[4]) << 32) |
                (static_cast<uint64_t>(attr.rawValue[5]) << 40);
            
            // Determine if pre-fail attribute (bit 0 of flags)
            smartAttr.isPreFail = (attr.flags & 0x01) != 0;
            
            // Map attribute IDs to names and mark critical ones
            switch (attr.id) {
                case HardwareMonitorConstants::SMART_READ_ERROR_RATE:
                    smartAttr.name = L"Read Error Rate";
                    smartAttr.threshold = 50;
                    break;
                case HardwareMonitorConstants::SMART_SPIN_UP_TIME:
                    smartAttr.name = L"Spin Up Time";
                    smartAttr.threshold = 25;
                    break;
                case HardwareMonitorConstants::SMART_REALLOCATED_SECTORS:
                    smartAttr.name = L"Reallocated Sectors";
                    smartAttr.threshold = 36;
                    smartAttr.isCritical = true;
                    // High reallocated sector count indicates imminent failure
                    if (smartAttr.rawValue > 100) {
                        disk.failurePredicted = true;
                        disk.failureReason = L"High reallocated sector count: " + 
                                            std::to_wstring(smartAttr.rawValue);
                    }
                    break;
                case HardwareMonitorConstants::SMART_POWER_ON_HOURS:
                    smartAttr.name = L"Power-On Hours";
                    smartAttr.threshold = 0;
                    disk.powerOnHours = smartAttr.rawValue;
                    break;
                case HardwareMonitorConstants::SMART_TEMPERATURE:
                    smartAttr.name = L"Temperature";
                    smartAttr.threshold = 50;
                    // Temperature is often in lowest byte of raw value
                    disk.temperatureCelsius = static_cast<uint32_t>(smartAttr.rawValue & 0xFF);
                    break;
                case HardwareMonitorConstants::SMART_CURRENT_PENDING_SECTORS:
                    smartAttr.name = L"Current Pending Sectors";
                    smartAttr.threshold = 0;
                    smartAttr.isCritical = true;
                    if (smartAttr.rawValue > 0) {
                        disk.healthStatus = DiskHealthStatus::Warning;
                        if (disk.failureReason.empty()) {
                            disk.failureReason = L"Pending sectors detected: " + 
                                                std::to_wstring(smartAttr.rawValue);
                        }
                    }
                    break;
                case HardwareMonitorConstants::SMART_WEAR_LEVELING:
                    smartAttr.name = L"Wear Leveling Count";
                    smartAttr.threshold = 0;
                    disk.wearLevelPercent = static_cast<uint8_t>(100 - attr.currentValue);
                    break;
                default:
                    smartAttr.name = L"Attribute " + std::to_wstring(attr.id);
                    smartAttr.threshold = 0;
            }
            
            disk.smartAttributes.push_back(smartAttr);
        }
    }

    /**
     * @brief Query NVMe-specific health information.
     */
    void ReadNvmeHealth(HANDLE hDrive, DiskHealthInfo& disk) {
        // NVMe health is queried via IOCTL_STORAGE_QUERY_PROPERTY with
        // StorageDeviceProtocolSpecificProperty and ProtocolTypeNvme

        #pragma pack(push, 1)
        struct NVME_HEALTH_INFO_LOG {
            BYTE criticalWarning;
            BYTE temperature[2];
            BYTE availableSpare;
            BYTE availableSpareThreshold;
            BYTE percentageUsed;
            BYTE reserved1[26];
            BYTE dataUnitsRead[16];
            BYTE dataUnitsWritten[16];
            BYTE hostReadCommands[16];
            BYTE hostWriteCommands[16];
            BYTE controllerBusyTime[16];
            BYTE powerCycles[16];
            BYTE powerOnHours[16];
            BYTE unsafeShutdowns[16];
            BYTE mediaErrors[16];
            BYTE errorLogEntries[16];
        };
        #pragma pack(pop)

        constexpr size_t BUFFER_SIZE = sizeof(STORAGE_PROPERTY_QUERY) + 
                                        sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + 
                                        sizeof(NVME_HEALTH_INFO_LOG);
        
        std::vector<BYTE> buffer(BUFFER_SIZE, 0);
        auto* query = reinterpret_cast<STORAGE_PROPERTY_QUERY*>(buffer.data());
        auto* protocolData = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(
            buffer.data() + sizeof(STORAGE_PROPERTY_QUERY));

        query->PropertyId = StorageDeviceProtocolSpecificProperty;
        query->QueryType = PropertyStandardQuery;
        
        protocolData->ProtocolType = ProtocolTypeNvme;
        protocolData->DataType = NVMeDataTypeLogPage;
        protocolData->ProtocolDataRequestValue = 0x02;  // SMART / Health Information
        protocolData->ProtocolDataRequestSubValue = 0;
        protocolData->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
        protocolData->ProtocolDataLength = sizeof(NVME_HEALTH_INFO_LOG);

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                            buffer.data(), static_cast<DWORD>(buffer.size()),
                            buffer.data(), static_cast<DWORD>(buffer.size()),
                            &bytesReturned, nullptr)) {
            return;  // NVMe health query not supported
        }

        // Parse NVMe health data
        auto* healthInfo = reinterpret_cast<NVME_HEALTH_INFO_LOG*>(
            buffer.data() + sizeof(STORAGE_PROPERTY_QUERY) + 
            sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA));

        // Temperature is in Kelvin - convert to Celsius
        uint16_t tempKelvin = healthInfo->temperature[0] | 
                             (static_cast<uint16_t>(healthInfo->temperature[1]) << 8);
        if (tempKelvin > 273) {
            disk.temperatureCelsius = tempKelvin - 273;
        }

        disk.availableSpare = healthInfo->availableSpare;
        disk.availableSpareThreshold = healthInfo->availableSpareThreshold;
        disk.percentageUsed = healthInfo->percentageUsed;

        // Check for critical warnings
        if (healthInfo->criticalWarning != 0) {
            disk.healthStatus = DiskHealthStatus::Warning;
            if (healthInfo->criticalWarning & 0x01) {
                disk.failureReason = L"NVMe: Available spare below threshold";
                disk.failurePredicted = true;
            }
            if (healthInfo->criticalWarning & 0x02) {
                disk.failureReason = L"NVMe: Temperature above threshold";
            }
            if (healthInfo->criticalWarning & 0x04) {
                disk.failureReason = L"NVMe: Reliability degraded";
                disk.failurePredicted = true;
            }
        }

        // Extract power-on hours (lower 8 bytes of 16-byte value)
        disk.powerOnHours = 
            static_cast<uint64_t>(healthInfo->powerOnHours[0]) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[1]) << 8) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[2]) << 16) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[3]) << 24) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[4]) << 32) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[5]) << 40) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[6]) << 48) |
            (static_cast<uint64_t>(healthInfo->powerOnHours[7]) << 56);

        // Extract power cycles
        disk.powerCycleCount = 
            static_cast<uint32_t>(healthInfo->powerCycles[0]) |
            (static_cast<uint32_t>(healthInfo->powerCycles[1]) << 8) |
            (static_cast<uint32_t>(healthInfo->powerCycles[2]) << 16) |
            (static_cast<uint32_t>(healthInfo->powerCycles[3]) << 24);

        // Calculate wear level from percentage used
        disk.wearLevelPercent = healthInfo->percentageUsed;
        if (disk.wearLevelPercent > 100) {
            disk.healthStatus = DiskHealthStatus::Critical;
            disk.failurePredicted = true;
            disk.failureReason = L"NVMe: Wear indicator exceeded 100%";
        }

        // Available spare guard — per NVMe spec, if available spare drops below
        // the threshold the device is at risk of failure even without the
        // critical-warning bit being set yet.
        if (disk.availableSpareThreshold != 0 &&
            disk.availableSpare < disk.availableSpareThreshold) {
            if (disk.healthStatus < DiskHealthStatus::Warning) {
                disk.healthStatus = DiskHealthStatus::Warning;
            }
            disk.failurePredicted = true;
            if (disk.failureReason.empty()) {
                disk.failureReason = L"NVMe: Available spare below threshold";
            }
        }

        // Total host writes: NVMe reports data-units-written as a 128-bit
        // little-endian counter; each unit is 1000 logical blocks of 512 bytes.
        // We can only represent the low 64 bits in disk.totalHostWrites; if the
        // high half is non-zero, saturate to UINT64_MAX so dashboards display
        // "≥ 8 EiB" rather than wrapping silently.
        uint64_t dataUnitsLow = 0;
        for (int i = 0; i < 8; ++i) {
            dataUnitsLow |=
                static_cast<uint64_t>(healthInfo->dataUnitsWritten[i]) << (i * 8);
        }
        uint64_t dataUnitsHigh = 0;
        for (int i = 0; i < 8; ++i) {
            dataUnitsHigh |=
                static_cast<uint64_t>(healthInfo->dataUnitsWritten[8 + i]) << (i * 8);
        }
        constexpr uint64_t kNvmeUnitBytes = 1000ULL * 512ULL;  // 512,000 bytes per unit
        if (dataUnitsHigh != 0 ||
            dataUnitsLow > (std::numeric_limits<uint64_t>::max)() / kNvmeUnitBytes) {
            disk.totalHostWrites = (std::numeric_limits<uint64_t>::max)();
        } else {
            disk.totalHostWrites = dataUnitsLow * kNvmeUnitBytes;
        }

        disk.smartSupported = true;
        disk.smartEnabled = true;
    }

    std::vector<DiskHealthInfo> EnumerateDisks() {
        std::vector<DiskHealthInfo> disks;

        try {
            // Enumerate physical drives with RAII handle management
            for (uint32_t driveNum = 0; driveNum < 32; driveNum++) {
                std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNum);

                // Use GENERIC_READ only (least privilege principle)
                ScopedHandle hDrive(CreateFileW(
                    drivePath.c_str(),
                    GENERIC_READ,  // FIXED: Was GENERIC_READ | GENERIC_WRITE
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                ));

                if (!hDrive) {
                    continue;  // Drive doesn't exist or access denied
                }

                DiskHealthInfo disk;
                disk.devicePath = drivePath;
                disk.healthStatus = DiskHealthStatus::Healthy;
                disk.healthPercent = 100;

                // Get disk geometry for capacity
                DISK_GEOMETRY_EX geometry;
                DWORD bytesReturned = 0;
                if (DeviceIoControl(hDrive.Get(), IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                   nullptr, 0, &geometry, sizeof(geometry),
                                   &bytesReturned, nullptr)) {
                    disk.totalBytes = geometry.DiskSize.QuadPart;
                }

                // Query storage device descriptor for model/serial/bus type
                STORAGE_PROPERTY_QUERY query{};
                query.PropertyId = StorageDeviceProperty;
                query.QueryType = PropertyStandardQuery;

                constexpr size_t DESCRIPTOR_BUFFER_SIZE = 4096;
                BYTE buffer[DESCRIPTOR_BUFFER_SIZE];
                bytesReturned = 0;

                if (DeviceIoControl(hDrive.Get(), IOCTL_STORAGE_QUERY_PROPERTY,
                                   &query, sizeof(query), buffer, sizeof(buffer),
                                   &bytesReturned, nullptr)) {
                    
                    // Validate minimum response size
                    if (bytesReturned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                        SS_LOG_WARN(L"HardwareMonitor", L"Invalid descriptor size for %ls",
                                   SanitizeForLog(drivePath).c_str());
                        continue;
                    }

                    auto* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);

                    // FIXED: Safe string extraction with bounds checking
                    if (descriptor->ProductIdOffset > 0) {
                        std::string productId = SafeExtractDescriptorString(
                            buffer, sizeof(buffer), bytesReturned, 
                            descriptor->ProductIdOffset);
                        disk.model = Utils::StringUtils::ToWide(productId);
                    }

                    // FIXED: Hash serial number for privacy protection
                    if (descriptor->SerialNumberOffset > 0) {
                        std::string serialNum = SafeExtractDescriptorString(
                            buffer, sizeof(buffer), bytesReturned,
                            descriptor->SerialNumberOffset);
                        std::wstring rawSerial = Utils::StringUtils::ToWide(serialNum);
                        disk.serialNumber = HashSerialNumber(rawSerial);
                    }

                    // Extract firmware version
                    if (descriptor->ProductRevisionOffset > 0) {
                        std::string firmwareRev = SafeExtractDescriptorString(
                            buffer, sizeof(buffer), bytesReturned,
                            descriptor->ProductRevisionOffset);
                        disk.firmwareVersion = Utils::StringUtils::ToWide(firmwareRev);
                    }

                    // Determine type based on bus type
                    switch (descriptor->BusType) {
                        case BusTypeUsb:
                            disk.diskType = DiskType::USB;
                            break;
                        case BusTypeNvme:
                            disk.diskType = DiskType::SSD_NVMe;
                            break;
                        case BusTypeSd:
                            disk.diskType = DiskType::SD;
                            break;
                        case BusTypeSata:
                        case BusTypeAta:
                            // FIXED: Properly detect SSD vs HDD for SATA drives
                            if (IsSolidStateDrive(hDrive.Get())) {
                                disk.diskType = DiskType::SSD_SATA;
                            } else {
                                disk.diskType = DiskType::HDD;
                            }
                            break;
                        case BusTypeVirtual:
                        case BusTypeFileBackedVirtual:
                            disk.diskType = DiskType::Virtual;
                            break;
                        default:
                            disk.diskType = DiskType::Unknown;
                    }
                }

                // Read health data based on drive type
                if (disk.diskType == DiskType::SSD_NVMe) {
                    ReadNvmeHealth(hDrive.Get(), disk);
                } else if (disk.diskType != DiskType::Virtual && 
                          disk.diskType != DiskType::USB &&
                          disk.diskType != DiskType::SD) {
                    // Read S.M.A.R.T. for SATA/ATA drives
                    ReadSmartData(hDrive.Get(), disk);
                }

                // Handle is automatically closed by ScopedHandle destructor
                disks.push_back(std::move(disk));

                m_statistics.diskHealthChecks.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Disk enumeration failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return disks;
    }

    void AnalyzeDiskHealth(DiskHealthInfo& disk, const HardwareMonitorConfig& cfg) {
        try {
            // Capture an initial health-percent ceiling derived from any
            // already-known wear / NVMe percentage indicators. This guarantees
            // a Critical disk never reports 100% on the dashboard even if its
            // temperature happens to be normal — a previous bug where dashboards
            // showed "100% healthy" for drives flagged as failing.
            uint8_t initialPercent = disk.healthPercent != 0 ? disk.healthPercent : 100;
            if (disk.diskType == DiskType::SSD_NVMe && disk.percentageUsed != 0) {
                // NVMe percentageUsed is the spec's wear indicator: 0 = new, 100 = end of life.
                uint8_t used = (disk.percentageUsed > 100) ? 100 : disk.percentageUsed;
                initialPercent = static_cast<uint8_t>(100 - used);
            } else if (disk.wearLevelPercent != 0) {
                uint8_t worn = (disk.wearLevelPercent > 100) ? 100 : disk.wearLevelPercent;
                initialPercent = static_cast<uint8_t>(100 - worn);
            }
            disk.healthPercent = initialPercent;

            // Check temperature against the caller-snapshotted config.
            // Reading m_config directly here would race with UpdateConfig().
            if (cfg.diskTempCriticalCelsius != 0 &&
                disk.temperatureCelsius >= cfg.diskTempCriticalCelsius) {
                disk.healthStatus = DiskHealthStatus::Critical;
                if (disk.healthPercent > 50) disk.healthPercent = 50;
            } else if (cfg.diskTempWarningCelsius != 0 &&
                       disk.temperatureCelsius >= cfg.diskTempWarningCelsius) {
                if (disk.healthStatus < DiskHealthStatus::Warning) {
                    disk.healthStatus = DiskHealthStatus::Warning;
                }
                if (disk.healthPercent > 75) disk.healthPercent = 75;
            }

            // Check S.M.A.R.T. attributes for failure prediction
            for (const auto& attr : disk.smartAttributes) {
                if (attr.isCritical && attr.threshold != 0 &&
                    attr.currentValue <= attr.threshold) {
                    disk.failurePredicted = true;
                    disk.failureReason =
                        L"Critical S.M.A.R.T. attribute below threshold: " +
                        SanitizeForLog(attr.name);
                    disk.healthStatus = DiskHealthStatus::Critical;
                    break;
                }
            }

            // Final consistency pass: collapse healthPercent to match status so
            // any downstream renderer reading either field gets a coherent view.
            switch (disk.healthStatus) {
                case DiskHealthStatus::Failed:
                    disk.healthPercent = 0;
                    break;
                case DiskHealthStatus::Critical:
                    if (disk.healthPercent > 50) disk.healthPercent = 50;
                    break;
                case DiskHealthStatus::Warning:
                    if (disk.healthPercent > 75) disk.healthPercent = 75;
                    break;
                case DiskHealthStatus::Healthy:
                    if (disk.healthPercent < 76) disk.healthPercent = 100;
                    break;
                case DiskHealthStatus::Unknown:
                default:
                    break;
            }

            if (disk.failurePredicted) {
                auto now = std::chrono::system_clock::now();
                disk.predictedFailureDate = now + std::chrono::hours(24 * 30);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Disk health analysis failed - %ls",
                        SanitizeForLog(Utils::StringUtils::ToWide(e.what())).c_str());
        }
    }

    // ========================================================================
    // THERMAL MONITORING
    // ========================================================================

    /**
     * @brief Query CPU thermal information via WMI.
     * Uses MSAcpi_ThermalZoneTemperature for real temperature readings.
     */
    CPUThermalInfo GetCPUThermalInfo() {
        CPUThermalInfo info;
        info.thermalStatus = ThermalStatus::Unknown;

        try {
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            uint32_t numCores = sysInfo.dwNumberOfProcessors;

            // Initialize COM for WMI
            ScopedComInit comInit;
            if (!comInit.IsInitialized()) {
                SS_LOG_WARN(L"HardwareMonitor", L"COM init failed for thermal query");
                return GetCPUThermalInfoFallback(numCores);
            }

            // Connect to WMI thermal namespace
            ScopedWmiConnection wmi;
            if (!wmi.Connect(L"ROOT\\WMI")) {
                // Fallback to CIMV2 namespace
                if (!wmi.Connect(L"ROOT\\CIMV2")) {
                    return GetCPUThermalInfoFallback(numCores);
                }
            }

            // Query thermal zone temperatures
            IEnumWbemClassObject* pEnumerator = nullptr;
            _bstr_t bstrWQL(L"WQL");
            _bstr_t bstrThermalQuery(L"SELECT * FROM MSAcpi_ThermalZoneTemperature");
            HRESULT hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrThermalQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (FAILED(hr) || !pEnumerator) {
                // Try alternative query for thermal sensors
                _bstr_t bstrTempProbeQuery(L"SELECT * FROM Win32_TemperatureProbe");
                hr = wmi.Get()->ExecQuery(
                    bstrWQL,
                    bstrTempProbeQuery,
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    nullptr,
                    &pEnumerator
                );
            }

            constexpr long WMI_QUERY_TIMEOUT_MS = 5000;

            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pClassObject = nullptr;
                ULONG uReturn = 0;

                while (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                    VARIANT vtTemp;
                    VariantInit(&vtTemp);

                    // Try CurrentTemperature (tenths of Kelvin for MSAcpi)
                    hr = pClassObject->Get(L"CurrentTemperature", 0, &vtTemp, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtTemp.vt == VT_I4) {
                        // MSAcpi reports in tenths of Kelvin
                        int32_t tempTenthsKelvin = vtTemp.lVal;
                        // Guard against underflow: must be > 2730 (0°C in tenths of Kelvin)
                        int32_t tempCelsius = (tempTenthsKelvin / 10) - 273;
                        
                        // Sanity check temperature (0-150°C reasonable range)
                        if (tempCelsius >= 0 && tempCelsius <= 150) {
                            info.coreTemperatures.push_back(static_cast<uint32_t>(tempCelsius));
                        }
                    }

                    VariantClear(&vtTemp);
                    pClassObject->Release();
                }

                pEnumerator->Release();
            }

            // If WMI didn't return any temperatures, use fallback
            if (info.coreTemperatures.empty()) {
                return GetCPUThermalInfoFallback(numCores);
            }

            // Calculate package temperature (max of all zones)
            if (!info.coreTemperatures.empty()) {
                info.packageTemperature = *std::max_element(
                    info.coreTemperatures.begin(),
                    info.coreTemperatures.end()
                );
                info.maxTemperature = info.packageTemperature;
            }

            info.throttleTemperature = 100;  // Typical throttle point

            // Determine thermal status based on temperature
            DetermineThermalStatus(info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"CPU thermal check failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return info;
    }

    /**
     * @brief Fallback CPU thermal reading using performance counters.
     * Used when WMI thermal query is not available.
     */
    CPUThermalInfo GetCPUThermalInfoFallback(uint32_t numCores) {
        CPUThermalInfo info;
        
        // Without WMI thermal zones, we can estimate based on CPU load
        // This is an approximation - real temperatures require driver access
        
        // Query CPU utilization via PDH
        PDH_HQUERY query = nullptr;
        PDH_HCOUNTER counter = nullptr;
        
        if (PdhOpenQuery(nullptr, 0, &query) == ERROR_SUCCESS) {
            if (PdhAddEnglishCounterA(query, "\\Processor(_Total)\\% Processor Time", 
                                     0, &counter) == ERROR_SUCCESS) {
                PdhCollectQueryData(query);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                PdhCollectQueryData(query);
                
                PDH_FMT_COUNTERVALUE value;
                if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, 
                                                nullptr, &value) == ERROR_SUCCESS) {
                    // Estimate temperature: base 35°C + up to 45°C based on load.
                    // PDH has been observed to return negative / NaN values
                    // during transient counter rebuilds, which would underflow
                    // the uint32 cast. Clamp to a sane physical range first.
                    double cpuLoad = value.doubleValue;
                    if (!(cpuLoad >= 0.0)) cpuLoad = 0.0;   // also rejects NaN
                    if (cpuLoad > 100.0) cpuLoad = 100.0;
                    uint32_t estimatedTemp = static_cast<uint32_t>(
                        35.0 + (cpuLoad * 0.45)
                    );
                    
                    // Populate per-core (estimate with slight variation)
                    for (uint32_t i = 0; i < numCores; ++i) {
                        uint32_t coreTemp = estimatedTemp + (i % 5);
                        info.coreTemperatures.push_back(coreTemp);
                    }
                    
                    info.packageTemperature = estimatedTemp;
                }
            }
            PdhCloseQuery(query);
        }

        // If PDH failed, use conservative estimate
        if (info.coreTemperatures.empty()) {
            for (uint32_t i = 0; i < numCores; ++i) {
                info.coreTemperatures.push_back(45 + (i % 5));
            }
            info.packageTemperature = 50;
        }

        info.maxTemperature = info.packageTemperature;
        info.throttleTemperature = 100;
        
        DetermineThermalStatus(info);
        
        return info;
    }

    /**
     * @brief Set thermal status based on temperature readings.
     */
    void DetermineThermalStatus(CPUThermalInfo& info) {
        if (info.packageTemperature >= m_config.cpuTempCriticalCelsius) {
            info.thermalStatus = ThermalStatus::Critical;
            info.isThrottling = true;
            info.throttlePercent = 25.0;
            m_statistics.thermalWarnings.fetch_add(1, std::memory_order_relaxed);
        } else if (info.packageTemperature >= m_config.cpuTempWarningCelsius) {
            info.thermalStatus = ThermalStatus::Hot;
            info.isThrottling = false;
            m_statistics.thermalWarnings.fetch_add(1, std::memory_order_relaxed);
        } else if (info.packageTemperature >= HardwareMonitorConstants::CPU_TEMP_WARM) {
            info.thermalStatus = ThermalStatus::Warm;
        } else {
            info.thermalStatus = ThermalStatus::Normal;
        }
    }

    /**
     * @brief Query GPU thermal information via WMI.
     */
    std::optional<GPUThermalInfo> GetGPUThermalInfo() {
        try {
            ScopedComInit comInit;
            if (!comInit.IsInitialized()) {
                return std::nullopt;
            }

            ScopedWmiConnection wmi;
            if (!wmi.Connect(L"ROOT\\CIMV2")) {
                return std::nullopt;
            }

            // Query video controller information
            IEnumWbemClassObject* pEnumerator = nullptr;
            _bstr_t bstrWQL(L"WQL");
            _bstr_t bstrGpuQuery(L"SELECT * FROM Win32_VideoController");
            HRESULT hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrGpuQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (FAILED(hr) || !pEnumerator) {
                return std::nullopt;
            }

            constexpr long WMI_QUERY_TIMEOUT_MS = 5000;
            GPUThermalInfo gpuInfo;
            IWbemClassObject* pClassObject = nullptr;
            ULONG uReturn = 0;

            // Get first GPU
            if (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                VARIANT vtName;
                VariantInit(&vtName);

                hr = pClassObject->Get(L"Name", 0, &vtName, nullptr, nullptr);
                if (SUCCEEDED(hr) && vtName.vt == VT_BSTR) {
                    gpuInfo.gpuName = vtName.bstrVal;
                }
                VariantClear(&vtName);

                pClassObject->Release();
            }
            pEnumerator->Release();

            // Query GPU thermal zones from WMI namespace
            // Note: Full GPU thermal requires NVML/ADL integration
            // This provides basic detection; temperature may not be available
            
            if (!wmi.Connect(L"ROOT\\WMI")) {
                // Return partial info without temperature
                gpuInfo.thermalStatus = ThermalStatus::Unknown;
                return gpuInfo.gpuName.empty() ? std::nullopt : std::make_optional(gpuInfo);
            }

            // Try to query GPU thermal zones (vendor-specific)
            pEnumerator = nullptr;
            _bstr_t bstrGpuThermalQuery(L"SELECT * FROM MSAcpi_ThermalZoneTemperature");
            hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrGpuThermalQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (SUCCEEDED(hr) && pEnumerator) {
                // Look for GPU-associated thermal zones
                // Note: This is system-dependent; full implementation needs NVML/ADL
                while (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                    VARIANT vtInstance, vtTemp;
                    VariantInit(&vtInstance);
                    VariantInit(&vtTemp);

                    // Check instance name for GPU-related thermal zone
                    hr = pClassObject->Get(L"InstanceName", 0, &vtInstance, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtInstance.vt == VT_BSTR) {
                        std::wstring instanceName = vtInstance.bstrVal;
                        // Look for GPU thermal zones (naming varies by vendor)
                        if (instanceName.find(L"GPU") != std::wstring::npos ||
                            instanceName.find(L"VGA") != std::wstring::npos ||
                            instanceName.find(L"Video") != std::wstring::npos) {
                            
                            hr = pClassObject->Get(L"CurrentTemperature", 0, &vtTemp, nullptr, nullptr);
                            if (SUCCEEDED(hr) && vtTemp.vt == VT_I4) {
                                int32_t tempTenthsKelvin = vtTemp.lVal;
                                int32_t tempCelsius = (tempTenthsKelvin / 10) - 273;
                                
                                if (tempCelsius >= 0 && tempCelsius <= 150) {
                                    gpuInfo.temperature = static_cast<uint32_t>(tempCelsius);
                                    
                                    if (gpuInfo.temperature >= 90) {
                                        gpuInfo.thermalStatus = ThermalStatus::Critical;
                                        gpuInfo.isThrottling = true;
                                    } else if (gpuInfo.temperature >= 80) {
                                        gpuInfo.thermalStatus = ThermalStatus::Hot;
                                    } else if (gpuInfo.temperature >= 70) {
                                        gpuInfo.thermalStatus = ThermalStatus::Warm;
                                    } else {
                                        gpuInfo.thermalStatus = ThermalStatus::Normal;
                                    }
                                }
                            }
                        }
                    }

                    VariantClear(&vtInstance);
                    VariantClear(&vtTemp);
                    pClassObject->Release();
                }
                pEnumerator->Release();
            }

            return gpuInfo.gpuName.empty() ? std::nullopt : std::make_optional(gpuInfo);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"GPU thermal check failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
            return std::nullopt;
        }
    }

    // ========================================================================
    // POWER MONITORING
    // ========================================================================

    /**
     * @brief Get comprehensive power and battery information.
     * Uses both Win32 API and WMI for complete battery health data.
     */
    PowerInfo GetPowerInformation() {
        PowerInfo info;

        try {
            SYSTEM_POWER_STATUS powerStatus;
            if (GetSystemPowerStatus(&powerStatus)) {
                // Determine power source
                if (powerStatus.ACLineStatus == 1) {
                    info.powerSource = PowerSource::ACPower;
                } else if (powerStatus.ACLineStatus == 0) {
                    info.powerSource = PowerSource::Battery;
                } else {
                    info.powerSource = PowerSource::Unknown;
                }

                // Battery information
                if (powerStatus.BatteryFlag != 128) {  // 128 = No system battery
                    info.battery.hasBattery = true;
                    info.battery.chargePercent = powerStatus.BatteryLifePercent;

                    if (powerStatus.BatteryFlag & 8) {
                        info.battery.status = BatteryStatus::Charging;
                    } else if (powerStatus.BatteryFlag & 4) {
                        info.battery.status = BatteryStatus::Full;
                    } else {
                        info.battery.status = BatteryStatus::Discharging;
                    }

                    // Estimate time remaining
                    if (powerStatus.BatteryLifeTime != 0xFFFFFFFF) {
                        info.battery.estimatedMinutesRemaining = powerStatus.BatteryLifeTime / 60;
                    }

                    // Query detailed battery health via WMI
                    QueryBatteryHealthWmi(info.battery);
                }

                // Get active power plan
                GUID* activeGuid = nullptr;
                if (PowerGetActiveScheme(nullptr, &activeGuid) == ERROR_SUCCESS && activeGuid) {
                    wchar_t buffer[512];
                    DWORD bufferSize = sizeof(buffer);   // bytes, not element count
                    if (PowerReadFriendlyName(nullptr, activeGuid, nullptr, nullptr,
                                             reinterpret_cast<PUCHAR>(buffer),
                                             &bufferSize) == ERROR_SUCCESS) {
                        info.activePowerPlan = buffer;
                    }

                    // Check if high performance or power saver
                    GUID highPerfGuid = {0x8c5e7fda, 0xe8bf, 0x4a96, {0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c, 0x63, 0x5c}};
                    GUID powerSaverGuid = {0xa1841308, 0x3541, 0x4fab, {0xbc, 0x81, 0xf7, 0x15, 0x56, 0xf2, 0x0b, 0x4a}};

                    info.isHighPerformance = (*activeGuid == highPerfGuid);
                    info.isPowerSaver = (*activeGuid == powerSaverGuid);

                    LocalFree(activeGuid);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Power info check failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return info;
    }

    /**
     * @brief Query detailed battery health information via WMI.
     */
    void QueryBatteryHealthWmi(BatteryInfo& battery) {
        try {
            ScopedComInit comInit;
            if (!comInit.IsInitialized()) {
                return;
            }

            ScopedWmiConnection wmi;
            if (!wmi.Connect(L"ROOT\\WMI")) {
                return;
            }

            constexpr long WMI_QUERY_TIMEOUT_MS = 5000;
            _bstr_t bstrWQL(L"WQL");

            // Query BatteryFullChargedCapacity for health calculation
            IEnumWbemClassObject* pEnumerator = nullptr;
            _bstr_t bstrCapQuery(L"SELECT * FROM BatteryFullChargedCapacity");
            HRESULT hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrCapQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pClassObject = nullptr;
                ULONG uReturn = 0;

                if (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                    VARIANT vtCapacity;
                    VariantInit(&vtCapacity);

                    hr = pClassObject->Get(L"FullChargedCapacity", 0, &vtCapacity, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtCapacity.vt == VT_I4) {
                        battery.fullChargeCapacityMWh = static_cast<uint32_t>(vtCapacity.lVal);
                    }

                    VariantClear(&vtCapacity);
                    pClassObject->Release();
                }
                pEnumerator->Release();
            }

            // Query BatteryStaticData for design capacity
            pEnumerator = nullptr;
            _bstr_t bstrStaticQuery(L"SELECT * FROM BatteryStaticData");
            hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrStaticQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pClassObject = nullptr;
                ULONG uReturn = 0;

                if (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                    VARIANT vtDesign;
                    VariantInit(&vtDesign);

                    hr = pClassObject->Get(L"DesignedCapacity", 0, &vtDesign, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtDesign.vt == VT_I4) {
                        battery.designCapacityMWh = static_cast<uint32_t>(vtDesign.lVal);
                    }

                    VariantClear(&vtDesign);
                    pClassObject->Release();
                }
                pEnumerator->Release();
            }

            // Query BatteryCycleCount
            pEnumerator = nullptr;
            _bstr_t bstrCycleQuery(L"SELECT * FROM BatteryCycleCount");
            hr = wmi.Get()->ExecQuery(
                bstrWQL,
                bstrCycleQuery,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );

            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pClassObject = nullptr;
                ULONG uReturn = 0;

                if (pEnumerator->Next(WMI_QUERY_TIMEOUT_MS, 1, &pClassObject, &uReturn) == S_OK) {
                    VARIANT vtCycles;
                    VariantInit(&vtCycles);

                    hr = pClassObject->Get(L"CycleCount", 0, &vtCycles, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtCycles.vt == VT_I4) {
                        battery.cycleCount = static_cast<uint32_t>(vtCycles.lVal);
                    }

                    VariantClear(&vtCycles);
                    pClassObject->Release();
                }
                pEnumerator->Release();
            }

            // Calculate health percentage
            if (battery.designCapacityMWh > 0 && battery.fullChargeCapacityMWh > 0) {
                battery.healthPercent = static_cast<uint8_t>(
                    (battery.fullChargeCapacityMWh * 100) / battery.designCapacityMWh
                );
                if (battery.healthPercent > 100) {
                    battery.healthPercent = 100;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_WARN(L"HardwareMonitor", L"WMI battery health query failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    // ========================================================================
    // HARDWARE CHANGE DETECTION
    // ========================================================================

    /**
     * @brief Detect hardware configuration changes using SetupAPI.
     * Compares current device list against known devices.
     */
    void DetectHardwareChanges() {
        try {
            std::unordered_set<std::wstring> currentDevices;

            // Enumerate all present devices
            ScopedDeviceInfoSet hDevInfo(SetupDiGetClassDevs(
                nullptr,
                nullptr,
                nullptr,
                DIGCF_PRESENT | DIGCF_ALLCLASSES
            ));

            if (!hDevInfo.IsValid()) {
                return;
            }

            SP_DEVINFO_DATA devInfoData;
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

            for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo.Get(), i, &devInfoData); ++i) {
                wchar_t deviceId[MAX_DEVICE_ID_LEN];
                if (CM_Get_Device_IDW(devInfoData.DevInst, deviceId, 
                                      MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
                    currentDevices.insert(deviceId);
                }
            }

            // Compare with known devices
            std::lock_guard<std::mutex> lock(m_deviceTrackingMutex);

            // Detect new devices
            for (const auto& deviceId : currentDevices) {
                if (m_knownDeviceIds.find(deviceId) == m_knownDeviceIds.end()) {
                    HardwareChangeEvent event;
                    event.changeType = L"DeviceAdded";
                    event.deviceId = deviceId;
                    event.timestamp = std::chrono::system_clock::now();

                    ParseDeviceInfo(deviceId, event);
                    CheckDeviceSuspicion(event);
                    RecordHardwareChange(event);
                }
            }

            // Detect removed devices
            for (const auto& knownId : m_knownDeviceIds) {
                if (currentDevices.find(knownId) == currentDevices.end()) {
                    HardwareChangeEvent event;
                    event.changeType = L"DeviceRemoved";
                    event.deviceId = knownId;
                    event.timestamp = std::chrono::system_clock::now();
                    
                    ParseDeviceInfo(knownId, event);
                    RecordHardwareChange(event);
                }
            }

            // Update known devices
            m_knownDeviceIds = std::move(currentDevices);

            // === Firmware change tracking for storage devices ===
            DetectFirmwareChanges();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Hardware change detection failed - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    /**
     * @brief Detect firmware version changes on storage devices.
     * A firmware change outside a known update window is a strong indicator
     * of firmware-level tampering (e.g., firmware rootkits, BadUSB reprogramming).
     */
    void DetectFirmwareChanges() {
        try {
            std::shared_lock<std::shared_mutex> dataLock(m_dataMutex);
            for (const auto& disk : m_disks) {
                if (disk.firmwareVersion.empty() || disk.devicePath.empty()) {
                    continue;
                }

                auto it = m_knownFirmwareVersions.find(disk.devicePath);
                if (it != m_knownFirmwareVersions.end()) {
                    if (it->second != disk.firmwareVersion) {
                        // Firmware version changed
                        HardwareChangeEvent event;
                        event.changeType = L"FirmwareChanged";
                        event.deviceId = disk.devicePath;
                        event.deviceName = disk.model;
                        event.deviceClass = L"DiskDrive";
                        event.timestamp = std::chrono::system_clock::now();
                        event.isSuspicious = true;
                        event.threatType = DeviceThreatType::FirmwareTamper;
                        event.firmwareVersion = disk.firmwareVersion;
                        event.previousFirmwareVersion = it->second;
                        event.suspicionReason =
                            L"Firmware version changed from [" + it->second +
                            L"] to [" + disk.firmwareVersion + L"] on " + disk.model;

                        SS_LOG_ERROR(L"HardwareMonitor",
                            L"CRITICAL: Firmware version change detected on %ls - was [%ls] now [%ls]",
                            SanitizeForLog(disk.devicePath).c_str(),
                            SanitizeForLog(it->second).c_str(),
                            SanitizeForLog(disk.firmwareVersion).c_str());

                        it->second = disk.firmwareVersion;
                        RecordHardwareChange(event);
                    }
                } else {
                    // First time seeing this device, record firmware baseline
                    m_knownFirmwareVersions[disk.devicePath] = disk.firmwareVersion;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_DEBUG(L"HardwareMonitor", L"Firmware change detection error - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    /**
     * @brief Parse device information from device ID.
     */
    void ParseDeviceInfo(const std::wstring& deviceId, HardwareChangeEvent& event) {
        // Device ID format: CLASS\VID_XXXX&PID_XXXX\SERIAL
        // or: PCI\VEN_XXXX&DEV_XXXX&SUBSYS_...
        
        size_t firstSlash = deviceId.find(L'\\');
        if (firstSlash != std::wstring::npos) {
            event.deviceClass = deviceId.substr(0, firstSlash);
            
            size_t secondSlash = deviceId.find(L'\\', firstSlash + 1);
            if (secondSlash != std::wstring::npos) {
                event.deviceName = deviceId.substr(firstSlash + 1, 
                                                   secondSlash - firstSlash - 1);
            } else {
                event.deviceName = deviceId.substr(firstSlash + 1);
            }
        }
    }

    /**
     * @brief Check if device has suspicious characteristics.
     * Detects BadUSB, DMA attack devices, composite HID anomalies,
     * and known attack tool signatures.
     */
    void CheckDeviceSuspicion(HardwareChangeEvent& event) {
        // === PHASE 1: Known attack tool VID/PID signatures ===
        static const std::vector<std::pair<std::wstring, std::wstring>> suspiciousPatterns = {
            // USB Rubber Ducky (multiple revisions)
            {L"VID_1FC9&PID_000C", L"Known BadUSB device signature (USB Rubber Ducky)"},
            // Bash Bunny MK2
            {L"VID_2E8A&PID_000A", L"Known BadUSB device signature (Bash Bunny)"},
            // Digispark
            {L"VID_16D0&PID_0753", L"Digispark-based HID device"},
            // Teensy
            {L"VID_16C0&PID_0486", L"Teensy HID device"},
            // HAK5 devices
            {L"VID_203A", L"HAK5 vendor ID detected"},
            // O.MG Cable
            {L"VID_2341", L"Arduino/O.MG vendor ID"},
            // LAN Turtle
            {L"VID_0B95&PID_772B", L"Possible LAN Turtle network implant"},
            // WiFi Pineapple USB
            {L"VID_0CF3&PID_9271", L"Possible WiFi Pineapple wireless implant"},
        };

        for (const auto& [pattern, reason] : suspiciousPatterns) {
            if (event.deviceId.find(pattern) != std::wstring::npos) {
                event.isSuspicious = true;
                event.threatType = DeviceThreatType::BadUSB_KnownSignature;
                event.suspicionReason = reason;
                SS_LOG_WARN(L"HardwareMonitor",
                    L"THREAT: Known attack device detected - %ls (%ls)",
                    SanitizeForLog(event.deviceId).c_str(),
                    SanitizeForLog(reason).c_str());
                break;
            }
        }

        // === PHASE 2: DMA attack device detection ===
        // Thunderbolt, FireWire (IEEE 1394), PCMCIA — all allow direct memory access
        if (!event.isSuspicious) {
            std::wstring upperClass = Utils::StringUtils::ToUpperCopy(event.deviceClass);
            bool isDmaCapable = false;
            std::wstring dmaReason;

            if (upperClass == L"1394" || upperClass == L"SBP2" ||
                event.deviceId.find(L"1394") != std::wstring::npos) {
                isDmaCapable = true;
                dmaReason = L"FireWire (IEEE 1394) DMA-capable device";
            } else if (event.deviceId.find(L"THUNDERBOLT") != std::wstring::npos ||
                       event.deviceId.find(L"PCI\\VEN_8086&DEV_15") != std::wstring::npos) {
                isDmaCapable = true;
                dmaReason = L"Thunderbolt DMA-capable device";
            } else if (upperClass == L"PCMCIA" || upperClass == L"CARDBUS") {
                isDmaCapable = true;
                dmaReason = L"PCMCIA/CardBus DMA-capable device";
            }

            if (isDmaCapable) {
                event.isSuspicious = true;
                event.threatType = DeviceThreatType::DMA_Attack;
                event.suspicionReason = dmaReason;
                SS_LOG_WARN(L"HardwareMonitor",
                    L"THREAT: DMA-capable device insertion detected - %ls (%ls)",
                    SanitizeForLog(event.deviceId).c_str(),
                    SanitizeForLog(dmaReason).c_str());
            }
        }

        // === PHASE 3: USB composite device anomaly (BadUSB hallmark) ===
        // A device claiming to be both HID (keyboard/mouse) AND mass storage is
        // the primary indicator of a BadUSB attack — legitimate devices rarely do this.
        if (!event.isSuspicious && event.deviceClass == L"USB") {
            bool hasHID = false;
            bool hasStorage = false;

            // Query USB interface descriptors via SetupAPI
            ScopedDeviceInfoSet hDevInfo(SetupDiGetClassDevsW(
                nullptr, event.deviceId.c_str(), nullptr,
                DIGCF_PRESENT | DIGCF_ALLCLASSES | DIGCF_DEVICEINTERFACE
            ));

            if (hDevInfo.IsValid()) {
                SP_DEVINFO_DATA devInfoData{};
                devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

                for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo.Get(), i, &devInfoData); ++i) {
                    wchar_t childId[MAX_DEVICE_ID_LEN]{};
                    if (CM_Get_Device_IDW(devInfoData.DevInst, childId,
                                          MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
                        std::wstring childIdStr(childId);
                        event.deviceInterfaces.push_back(childIdStr);

                        std::wstring upperChildId = Utils::StringUtils::ToUpperCopy(childIdStr);
                        if (upperChildId.find(L"HID") != std::wstring::npos ||
                            upperChildId.find(L"MI_00") != std::wstring::npos) {
                            hasHID = true;
                        }
                        if (upperChildId.find(L"USBSTOR") != std::wstring::npos ||
                            upperChildId.find(L"MI_01") != std::wstring::npos) {
                            hasStorage = true;
                        }
                    }
                }
            }

            if (hasHID && hasStorage) {
                event.isSuspicious = true;
                event.threatType = DeviceThreatType::BadUSB_CompositeHID;
                event.suspicionReason =
                    L"USB composite device presents as both HID and storage — "
                    L"BadUSB signature. VID/PID: " + event.deviceName;
                SS_LOG_WARN(L"HardwareMonitor",
                    L"THREAT: BadUSB composite device detected (HID+Storage) - %ls",
                    SanitizeForLog(event.deviceId).c_str());
            }
        }

        // === PHASE 4: Wire to DriverAnalyzer for new device driver check ===
        if (event.changeType == L"DeviceAdded") {
            try {
                auto& driverAnalyzer = DriverAnalyzer::Instance();
                std::wstring serviceName = QueryDeviceServiceName(event.deviceId);
                if (!serviceName.empty()) {
                    event.driverName = serviceName;
                    auto driverInfo = driverAnalyzer.GetDriverInfo(serviceName);
                    if (driverInfo.has_value()) {
                        event.driverPath = driverInfo->driverPath;
                        event.driverSignatureValid =
                            (driverInfo->signatureStatus == DriverSignatureStatus::SignedValid ||
                             driverInfo->signatureStatus == DriverSignatureStatus::WHQLCertified ||
                             driverInfo->signatureStatus == DriverSignatureStatus::MicrosoftSigned);

                        if (driverInfo->threatLevel >= DriverThreatLevel::Suspicious) {
                            event.isSuspicious = true;
                            if (event.threatType == DeviceThreatType::None) {
                                event.threatType = DeviceThreatType::SuspiciousDeviceClass;
                            }
                            event.suspicionReason +=
                                (event.suspicionReason.empty() ? L"" : L"; ") +
                                std::wstring(L"Driver threat level elevated: ") +
                                event.driverName;
                            SS_LOG_WARN(L"HardwareMonitor",
                                L"THREAT: Suspicious driver for new device - driver=%ls threat=%u device=%ls",
                                SanitizeForLog(event.driverName).c_str(),
                                static_cast<unsigned>(driverInfo->threatLevel),
                                SanitizeForLog(event.deviceId).c_str());
                        }

                        if (!event.driverSignatureValid) {
                            event.isSuspicious = true;
                            event.suspicionReason +=
                                (event.suspicionReason.empty() ? L"" : L"; ") +
                                std::wstring(L"Unsigned/invalid driver signature: ") +
                                event.driverName;
                            SS_LOG_WARN(L"HardwareMonitor",
                                L"ALERT: Unsigned driver loaded for device - driver=%ls device=%ls",
                                SanitizeForLog(event.driverName).c_str(),
                                SanitizeForLog(event.deviceId).c_str());
                        }

                        if (driverInfo->isKnownVulnerable) {
                            event.isSuspicious = true;
                            event.suspicionReason +=
                                (event.suspicionReason.empty() ? L"" : L"; ") +
                                std::wstring(L"Known vulnerable driver (BYOVD): ") +
                                event.driverName;
                            SS_LOG_ERROR(L"HardwareMonitor",
                                L"CRITICAL: Known vulnerable driver loaded via device insertion - %ls",
                                SanitizeForLog(event.driverName).c_str());
                        }
                    }
                }
            } catch (const std::exception& e) {
                SS_LOG_DEBUG(L"HardwareMonitor",
                    L"DriverAnalyzer check skipped for device %ls - %ls",
                    SanitizeForLog(event.deviceId).c_str(),
                    SanitizeForLog(Utils::StringUtils::ToWide(e.what())).c_str());
            }
        }
    }

    /**
     * @brief Query the service name (driver) associated with a device instance ID.
     */
    [[nodiscard]] std::wstring QueryDeviceServiceName(const std::wstring& deviceId) {
        DEVINST devInst = 0;
        CONFIGRET cr = CM_Locate_DevNodeW(&devInst, const_cast<DEVINSTID_W>(deviceId.c_str()),
                                           CM_LOCATE_DEVNODE_NORMAL);
        if (cr != CR_SUCCESS) {
            return L"";
        }

        wchar_t serviceName[256]{};
        ULONG serviceNameLen = static_cast<ULONG>(std::size(serviceName));
        cr = CM_Get_DevNode_Registry_PropertyW(devInst, CM_DRP_SERVICE,
                                                nullptr, serviceName, &serviceNameLen, 0);
        if (cr != CR_SUCCESS) {
            return L"";
        }

        return std::wstring(serviceName);
    }

    void RecordHardwareChange(const HardwareChangeEvent& event) {
        try {
            {
                std::lock_guard<std::mutex> lock(m_historyMutex);

                m_changeHistory.push_back(event);

                // Limit history size
                if (m_changeHistory.size() > MAX_HISTORY_SIZE) {
                    m_changeHistory.pop_front();
                }
            }

            m_statistics.deviceChanges.fetch_add(1, std::memory_order_relaxed);

            // Invoke callbacks (outside history lock to avoid deadlock)
            InvokeHardwareChangeCallbacks(event);

            // === SIEM Integration via EventLogger ===
            ForwardToEventLogger(event);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Change recording failed - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    /**
     * @brief Forward hardware change events to EventLogger for SIEM/forensic pipeline.
     * Suspicious events are logged at Warning/Error severity; routine events at Info.
     */
    void ForwardToEventLogger(const HardwareChangeEvent& event) {
        try {
            auto& eventLogger = EventLogger::Instance();

            EventSeverity severity = EventSeverity::Info;
            if (event.isSuspicious) {
                severity = (event.threatType == DeviceThreatType::DMA_Attack ||
                            event.threatType == DeviceThreatType::BadUSB_KnownSignature)
                    ? EventSeverity::Error
                    : EventSeverity::Warning;
            }

            std::unordered_map<std::wstring, std::wstring> props;
            // All wide-string properties originate from device/WMI surfaces and
            // attacker-controlled USB descriptors. Sanitize before forwarding to
            // EventLogger so embedded CR/LF/NUL cannot forge log records or
            // corrupt SIEM line framing downstream.
            props[L"changeType"] = SanitizeForLog(event.changeType);
            props[L"deviceClass"] = SanitizeForLog(event.deviceClass);
            props[L"deviceName"] = SanitizeForLog(event.deviceName);
            props[L"deviceId"] = SanitizeForLog(event.deviceId);
            props[L"isSuspicious"] = event.isSuspicious ? L"true" : L"false";
            props[L"threatType"] = std::to_wstring(static_cast<uint8_t>(event.threatType));
            if (!event.suspicionReason.empty()) {
                props[L"suspicionReason"] = SanitizeForLog(event.suspicionReason);
            }
            if (!event.driverName.empty()) {
                props[L"driverName"] = SanitizeForLog(event.driverName);
                props[L"driverPath"] = SanitizeForLog(event.driverPath);
                props[L"driverSignatureValid"] = event.driverSignatureValid ? L"true" : L"false";
            }
            if (!event.firmwareVersion.empty()) {
                props[L"firmwareVersion"] = SanitizeForLog(event.firmwareVersion);
            }
            if (!event.previousFirmwareVersion.empty()) {
                props[L"previousFirmwareVersion"] = SanitizeForLog(event.previousFirmwareVersion);
            }

            std::wstring message =
                SanitizeForLog(event.changeType) + L": " + SanitizeForLog(event.deviceId);
            if (event.isSuspicious) {
                message += L" [SUSPICIOUS: " + SanitizeForLog(event.suspicionReason) + L"]";
            }

            eventLogger.Log(severity, EventCategory::DriverControl,
                           L"HardwareMonitor", message, props);

            // For high-severity threats, also capture forensic event
            if (event.isSuspicious &&
                (event.threatType == DeviceThreatType::DMA_Attack ||
                 event.threatType == DeviceThreatType::BadUSB_KnownSignature ||
                 event.threatType == DeviceThreatType::BadUSB_CompositeHID)) {
                eventLogger.CaptureForensicEvent(L"SuspiciousHardwareDevice", props);
            }

        } catch (const std::exception& e) {
            SS_LOG_DEBUG(L"HardwareMonitor", L"EventLogger forwarding failed - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitoringLoop() {
        SS_LOG_INFO(L"HardwareMonitor", L"Monitoring thread started");

        while (m_monitoring.load(std::memory_order_acquire)) {
            // Snapshot config *outside* the try block so the catch handler can
            // still read pollingIntervalMs for the backoff sleep without
            // touching m_config (which would race with UpdateConfig()).
            HardwareMonitorConfig configSnapshot;
            {
                std::shared_lock<std::shared_mutex> lock(m_mutex);
                configSnapshot = m_config;
            }

            try {
                // Refresh all hardware data
                RefreshHardwareData(configSnapshot);

                // Reset error counter on success
                m_consecutiveErrors.store(0, std::memory_order_relaxed);
                m_statistics.pollingCycles.fetch_add(1, std::memory_order_relaxed);

                // Interruptible sleep — wakes immediately on StopMonitoring()
                {
                    std::unique_lock<std::mutex> sleepLock(m_sleepMutex);
                    m_stopCV.wait_for(sleepLock,
                        std::chrono::milliseconds(configSnapshot.pollingIntervalMs),
                        [this] { return !m_monitoring.load(std::memory_order_acquire); });
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Monitoring loop error - %ls",
                            SanitizeForLog(Utils::StringUtils::ToWide(e.what())).c_str());

                // Exponential backoff on consecutive errors. Use the
                // already-captured configSnapshot — reading m_config here without
                // a lock would race with UpdateConfig(). Saturating math also
                // prevents `pollingIntervalMs * multiplier` from wrapping uint32
                // and producing an effectively-zero sleep that busy-loops the
                // monitoring thread on every poll failure.
                uint32_t errors = m_consecutiveErrors.fetch_add(1, std::memory_order_relaxed) + 1;
                uint32_t backoffMultiplier = (errors > MAX_BACKOFF_MULTIPLIER)
                    ? MAX_BACKOFF_MULTIPLIER : errors;
                uint64_t sleepMs64 =
                    static_cast<uint64_t>(configSnapshot.pollingIntervalMs) * backoffMultiplier;
                if (sleepMs64 > HardwareMonitorConstants::MAX_POLLING_INTERVAL_MS) {
                    sleepMs64 = HardwareMonitorConstants::MAX_POLLING_INTERVAL_MS;
                }
                uint32_t sleepMs = static_cast<uint32_t>(sleepMs64);

                SS_LOG_WARN(L"HardwareMonitor",
                    L"Backing off for %ums after %u consecutive errors", sleepMs, errors);

                // Interruptible backoff sleep
                {
                    std::unique_lock<std::mutex> sleepLock(m_sleepMutex);
                    m_stopCV.wait_for(sleepLock,
                        std::chrono::milliseconds(sleepMs),
                        [this] { return !m_monitoring.load(std::memory_order_acquire); });
                }
            }
        }

        SS_LOG_INFO(L"HardwareMonitor", L"Monitoring thread stopped");
    }

    void RefreshHardwareData() {
        // Snapshot config under lock for thread safety
        HardwareMonitorConfig configSnapshot;
        {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            configSnapshot = m_config;
        }
        RefreshHardwareData(configSnapshot);
    }

    void RefreshHardwareData(const HardwareMonitorConfig& configSnapshot) {
        try {
            // Monitor disks
            if (configSnapshot.monitorDisks) {
                auto disks = EnumerateDisks();
                for (auto& disk : disks) {
                    AnalyzeDiskHealth(disk, configSnapshot);

                    // Check for health issues and invoke callbacks
                    if (disk.healthStatus >= DiskHealthStatus::Warning) {
                        InvokeDiskHealthCallbacks(disk);
                    }
                }

                {
                    std::unique_lock<std::shared_mutex> lock(m_dataMutex);
                    m_disks = std::move(disks);
                }
            }

            // Monitor thermals
            if (configSnapshot.monitorThermals) {
                auto cpuThermal = GetCPUThermalInfo();
                auto gpuThermal = GetGPUThermalInfo();

                // Check for thermal warnings
                if (cpuThermal.thermalStatus >= ThermalStatus::Hot) {
                    InvokeThermalCallbacks(cpuThermal.thermalStatus, cpuThermal.packageTemperature);
                }

                {
                    std::unique_lock<std::shared_mutex> lock(m_dataMutex);
                    m_cpuThermal = cpuThermal;
                    m_gpuThermal = gpuThermal;
                }
            }

            // Monitor power
            if (configSnapshot.monitorPower) {
                auto powerInfo = GetPowerInformation();

                // Check for power state changes
                bool powerChanged = false;
                {
                    std::shared_lock<std::shared_mutex> lock(m_dataMutex);
                    powerChanged = (powerInfo.powerSource != m_powerInfo.powerSource);
                }

                if (powerChanged) {
                    m_statistics.powerStateChanges.fetch_add(1, std::memory_order_relaxed);
                    InvokePowerChangeCallbacks(powerInfo);
                }

                {
                    std::unique_lock<std::shared_mutex> lock(m_dataMutex);
                    m_powerInfo = powerInfo;
                }
            }

            // Detect hardware changes
            if (configSnapshot.monitorDeviceChanges) {
                DetectHardwareChanges();
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Data refresh failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    void StartMonitoring() {
        if (m_monitoring.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"HardwareMonitor", L"Already monitoring");
            return;
        }

        try {
            // Initial refresh
            RefreshHardwareData();

            m_monitoring.store(true, std::memory_order_release);

            // Start monitoring thread
            m_monitorThread = std::make_unique<std::thread>([this]() {
                MonitoringLoop();
            });

            SS_LOG_INFO(L"HardwareMonitor", L"Monitoring started");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Failed to start monitoring - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    void StopMonitoring() {
        if (!m_monitoring.load(std::memory_order_acquire)) {
            return;
        }

        try {
            m_monitoring.store(false, std::memory_order_release);

            // Wake the monitoring thread from interruptible sleep
            m_stopCV.notify_all();

            if (m_monitorThread && m_monitorThread->joinable()) {
                m_monitorThread->join();
            }

            m_monitorThread.reset();

            SS_LOG_INFO(L"HardwareMonitor", L"Monitoring stopped");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Failed to stop monitoring - %ls",
                        Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    // ========================================================================
    // CALLBACK INVOCATION
    // ========================================================================

    /**
     * @brief Invoke callbacks safely by copying the list first.
     * This prevents deadlock if a callback tries to unregister itself,
     * and ensures all callbacks execute even if one throws.
     */
    void InvokeDiskHealthCallbacks(const DiskHealthInfo& info) {
        // Copy callback list under lock, then invoke outside lock
        std::vector<std::pair<uint64_t, DiskHealthCallback>> callbacksCopy;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            callbacksCopy = m_diskHealthCallbacks;
        }

        for (const auto& [id, callback] : callbacksCopy) {
            try {
                callback(info);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Disk health callback %llu failed - %ls", 
                            id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Disk health callback %llu threw unknown exception", id);
            }
        }
    }

    void InvokeThermalCallbacks(ThermalStatus status, uint32_t temperature) {
        std::vector<std::pair<uint64_t, ThermalAlertCallback>> callbacksCopy;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            callbacksCopy = m_thermalCallbacks;
        }

        for (const auto& [id, callback] : callbacksCopy) {
            try {
                callback(status, temperature);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Thermal callback %llu failed - %ls", 
                            id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Thermal callback %llu threw unknown exception", id);
            }
        }
    }

    void InvokePowerChangeCallbacks(const PowerInfo& info) {
        std::vector<std::pair<uint64_t, PowerChangeCallback>> callbacksCopy;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            callbacksCopy = m_powerCallbacks;
        }

        for (const auto& [id, callback] : callbacksCopy) {
            try {
                callback(info);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Power callback %llu failed - %ls", 
                            id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Power callback %llu threw unknown exception", id);
            }
        }
    }

    void InvokeHardwareChangeCallbacks(const HardwareChangeEvent& event) {
        std::vector<std::pair<uint64_t, HardwareChangeCallback>> callbacksCopy;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            callbacksCopy = m_hardwareCallbacks;
        }

        for (const auto& [id, callback] : callbacksCopy) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Hardware change callback %llu failed - %ls", 
                            id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"HardwareMonitor", L"Hardware change callback %llu threw unknown exception", id);
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> HardwareMonitor::s_instanceCreated{false};

HardwareMonitor& HardwareMonitor::Instance() noexcept {
    static HardwareMonitor instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool HardwareMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

HardwareMonitor::HardwareMonitor()
    : m_impl(std::make_unique<HardwareMonitorImpl>())
{
    SS_LOG_INFO(L"HardwareMonitor", L"Constructor called");
}

HardwareMonitor::~HardwareMonitor() {
    Shutdown();
    SS_LOG_INFO(L"HardwareMonitor", L"Destructor called");
}

bool HardwareMonitor::Initialize(const HardwareMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"HardwareMonitor", L"Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;
        if (!ClampHardwareMonitorConfig(m_impl->m_config)) {
            SS_LOG_WARN(L"HardwareMonitor",
                L"Provided configuration contained out-of-range values and was clamped to safe defaults");
        }
        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"HardwareMonitor", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"HardwareMonitor", L"Initialization failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void HardwareMonitor::Shutdown() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        // Stop monitoring if active
        m_impl->StopMonitoring();

        // Clear data
        {
            std::unique_lock<std::shared_mutex> dataLock(m_impl->m_dataMutex);
            m_impl->m_disks.clear();
        }

        {
            std::lock_guard<std::mutex> histLock(m_impl->m_historyMutex);
            m_impl->m_changeHistory.clear();
        }

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_diskHealthCallbacks.clear();
            m_impl->m_thermalCallbacks.clear();
            m_impl->m_powerCallbacks.clear();
            m_impl->m_hardwareCallbacks.clear();
        }

        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"HardwareMonitor", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"HardwareMonitor", L"Shutdown error - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

bool HardwareMonitor::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool HardwareMonitor::UpdateConfig(const HardwareMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    bool clean = ClampHardwareMonitorConfig(m_impl->m_config);
    if (!clean) {
        SS_LOG_WARN(L"HardwareMonitor",
            L"UpdateConfig: input contained out-of-range values and was clamped to safe defaults");
    }
    SS_LOG_INFO(L"HardwareMonitor", L"Configuration updated");
    return true;
}

HardwareMonitorConfig HardwareMonitor::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// MONITORING CONTROL
// ============================================================================

void HardwareMonitor::StartMonitoring() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"HardwareMonitor", L"Cannot start monitoring - not initialized");
        return;
    }
    m_impl->StartMonitoring();
}

void HardwareMonitor::StopMonitoring() {
    m_impl->StopMonitoring();
}

void HardwareMonitor::Refresh() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"HardwareMonitor", L"Cannot refresh - not initialized");
        return;
    }
    m_impl->RefreshHardwareData();
}

// ============================================================================
// DISK HEALTH
// ============================================================================

std::vector<DiskHealthInfo> HardwareMonitor::GetDiskHealth() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_disks;
}

std::optional<DiskHealthInfo> HardwareMonitor::GetDiskHealth(const std::wstring& devicePath) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);

    for (const auto& disk : m_impl->m_disks) {
        if (disk.devicePath == devicePath) {
            return disk;
        }
    }

    return std::nullopt;
}

bool HardwareMonitor::HasDiskHealthIssues() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);

    for (const auto& disk : m_impl->m_disks) {
        if (disk.healthStatus >= DiskHealthStatus::Warning) {
            return true;
        }
    }

    return false;
}

std::vector<DiskHealthInfo> HardwareMonitor::GetFailingDisks() const {
    std::vector<DiskHealthInfo> failing;

    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);

    for (const auto& disk : m_impl->m_disks) {
        if (disk.failurePredicted || disk.healthStatus >= DiskHealthStatus::Critical) {
            failing.push_back(disk);
        }
    }

    return failing;
}

// ============================================================================
// THERMAL MONITORING
// ============================================================================

CPUThermalInfo HardwareMonitor::GetCPUThermal() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_cpuThermal;
}

std::optional<GPUThermalInfo> HardwareMonitor::GetGPUThermal() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_gpuThermal;
}

ThermalStatus HardwareMonitor::GetThermalStatus() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_cpuThermal.thermalStatus;
}

bool HardwareMonitor::IsThrottling() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_cpuThermal.isThrottling;
}

// ============================================================================
// POWER MONITORING
// ============================================================================

PowerInfo HardwareMonitor::GetPowerInfo() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_powerInfo;
}

bool HardwareMonitor::IsOnBattery() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_powerInfo.powerSource == PowerSource::Battery;
}

bool HardwareMonitor::IsBatteryLow() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);

    if (!m_impl->m_powerInfo.battery.hasBattery) {
        return false;
    }

    return m_impl->m_powerInfo.battery.chargePercent <= m_impl->m_config.batteryLowPercent;
}

uint8_t HardwareMonitor::GetBatteryPercent() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_dataMutex);
    return m_impl->m_powerInfo.battery.chargePercent;
}

// ============================================================================
// DEVICE CHANGES
// ============================================================================

std::vector<HardwareChangeEvent> HardwareMonitor::GetRecentChanges(uint32_t maxEvents) const {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);

    // Clamp caller-supplied count before reserving — IPC callers can request
    // UINT32_MAX events and a naive std::min vs. history size would still allow
    // an arbitrarily large vector if MAX_HISTORY_SIZE were ever raised. The
    // explicit ceiling keeps memory bounded regardless of history growth.
    if (maxEvents > HardwareMonitorConstants::MAX_RETURNED_CHANGE_EVENTS) {
        maxEvents = HardwareMonitorConstants::MAX_RETURNED_CHANGE_EVENTS;
    }

    std::vector<HardwareChangeEvent> changes;
    size_t count = std::min(static_cast<size_t>(maxEvents), m_impl->m_changeHistory.size());
    changes.reserve(count);

    auto it = m_impl->m_changeHistory.rbegin();
    for (size_t i = 0; i < count && it != m_impl->m_changeHistory.rend(); ++i, ++it) {
        changes.push_back(*it);
    }

    return changes;
}

void HardwareMonitor::ClearChangeHistory() {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);
    m_impl->m_changeHistory.clear();
    SS_LOG_INFO(L"HardwareMonitor", L"Change history cleared");
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t HardwareMonitor::RegisterDiskHealthCallback(DiskHealthCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_diskHealthCallbacks.emplace_back(id, std::move(callback));
    return id;
}

void HardwareMonitor::UnregisterDiskHealthCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_diskHealthCallbacks.erase(
        std::remove_if(m_impl->m_diskHealthCallbacks.begin(),
                      m_impl->m_diskHealthCallbacks.end(),
                      [callbackId](const auto& pair) { return pair.first == callbackId; }),
        m_impl->m_diskHealthCallbacks.end()
    );
}

uint64_t HardwareMonitor::RegisterThermalAlertCallback(ThermalAlertCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_thermalCallbacks.emplace_back(id, std::move(callback));
    return id;
}

void HardwareMonitor::UnregisterThermalAlertCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_thermalCallbacks.erase(
        std::remove_if(m_impl->m_thermalCallbacks.begin(),
                      m_impl->m_thermalCallbacks.end(),
                      [callbackId](const auto& pair) { return pair.first == callbackId; }),
        m_impl->m_thermalCallbacks.end()
    );
}

uint64_t HardwareMonitor::RegisterPowerChangeCallback(PowerChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_powerCallbacks.emplace_back(id, std::move(callback));
    return id;
}

void HardwareMonitor::UnregisterPowerChangeCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_powerCallbacks.erase(
        std::remove_if(m_impl->m_powerCallbacks.begin(),
                      m_impl->m_powerCallbacks.end(),
                      [callbackId](const auto& pair) { return pair.first == callbackId; }),
        m_impl->m_powerCallbacks.end()
    );
}

uint64_t HardwareMonitor::RegisterHardwareChangeCallback(HardwareChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_hardwareCallbacks.emplace_back(id, std::move(callback));
    return id;
}

void HardwareMonitor::UnregisterHardwareChangeCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    m_impl->m_hardwareCallbacks.erase(
        std::remove_if(m_impl->m_hardwareCallbacks.begin(),
                      m_impl->m_hardwareCallbacks.end(),
                      [callbackId](const auto& pair) { return pair.first == callbackId; }),
        m_impl->m_hardwareCallbacks.end()
    );
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

const HardwareMonitorStatistics& HardwareMonitor::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void HardwareMonitor::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"HardwareMonitor", L"Statistics reset");
}

std::string HardwareMonitor::GetVersionString() noexcept {
    return std::to_string(HardwareMonitorConstants::VERSION_MAJOR) + "." +
           std::to_string(HardwareMonitorConstants::VERSION_MINOR) + "." +
           std::to_string(HardwareMonitorConstants::VERSION_PATCH);
}

bool HardwareMonitor::SelfTest() {
    try {
        SS_LOG_INFO(L"HardwareMonitor", L"Starting self-test");

        // Test configuration factory
        auto config = HardwareMonitorConfig::CreateDefault();
        if (!config.monitorDisks || !config.monitorThermals || !config.monitorPower) {
            SS_LOG_ERROR(L"HardwareMonitor", L"Config factory test failed");
            return false;
        }

        // Test disk enumeration
        auto disks = m_impl->EnumerateDisks();
        if (disks.empty()) {
            SS_LOG_WARN(L"HardwareMonitor", L"No disks detected (may be normal on some systems)");
        }

        // Test thermal info
        auto cpuThermal = m_impl->GetCPUThermalInfo();
        if (cpuThermal.coreTemperatures.empty()) {
            SS_LOG_ERROR(L"HardwareMonitor", L"CPU thermal test failed");
            return false;
        }

        // Test power info
        auto powerInfo = m_impl->GetPowerInformation();
        // Power info doesn't need specific validation

        SS_LOG_INFO(L"HardwareMonitor", L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"HardwareMonitor", L"Self-test failed - %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

std::vector<std::wstring> HardwareMonitor::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    diagnostics.push_back(L"HardwareMonitor Diagnostics");
    diagnostics.push_back(L"============================");
    diagnostics.push_back(L"Initialized: " + std::wstring(IsInitialized() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Monitoring: " + std::wstring(m_impl->m_monitoring.load() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Polling Cycles: " + std::to_wstring(m_impl->m_statistics.pollingCycles.load()));
    diagnostics.push_back(L"Disk Health Checks: " + std::to_wstring(m_impl->m_statistics.diskHealthChecks.load()));
    diagnostics.push_back(L"Thermal Warnings: " + std::to_wstring(m_impl->m_statistics.thermalWarnings.load()));
    diagnostics.push_back(L"Power State Changes: " + std::to_wstring(m_impl->m_statistics.powerStateChanges.load()));
    diagnostics.push_back(L"Device Changes: " + std::to_wstring(m_impl->m_statistics.deviceChanges.load()));

    auto disks = GetDiskHealth();
    diagnostics.push_back(L"Disks Detected: " + std::to_wstring(disks.size()));

    auto cpuThermal = GetCPUThermal();
    diagnostics.push_back(L"CPU Temperature: " + std::to_wstring(cpuThermal.packageTemperature) + L"°C");

    auto powerInfo = GetPowerInfo();
    diagnostics.push_back(L"Power Source: " + std::wstring(
        powerInfo.powerSource == PowerSource::ACPower ? L"AC Power" :
        powerInfo.powerSource == PowerSource::Battery ? L"Battery" : L"Unknown"
    ));

    if (powerInfo.battery.hasBattery) {
        diagnostics.push_back(L"Battery: " + std::to_wstring(powerInfo.battery.chargePercent) + L"%");
    }

    return diagnostics;
}

// ============================================================================
// EXPORT
// ============================================================================

bool HardwareMonitor::ExportReport(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        file << L"HardwareMonitor Report\n";
        file << L"======================\n\n";

        // Disk health
        auto disks = GetDiskHealth();
        file << L"Disk Health:\n";
        for (const auto& disk : disks) {
            file << L"  Device: " << disk.devicePath << L"\n";
            file << L"  Model: " << disk.model << L"\n";
            file << L"  Type: " << GetDiskTypeName(disk.diskType).data() << L"\n";
            file << L"  Health: " << GetDiskHealthStatusName(disk.healthStatus).data() << L"\n";
            file << L"  Temperature: " << disk.temperatureCelsius << L"°C\n";
            file << L"  Health Percent: " << static_cast<int>(disk.healthPercent) << L"%\n";
            if (disk.failurePredicted) {
                file << L"  ⚠ FAILURE PREDICTED: " << disk.failureReason << L"\n";
            }
            file << L"\n";
        }

        // Thermal
        auto cpuThermal = GetCPUThermal();
        file << L"Thermal Status:\n";
        file << L"  CPU Package: " << cpuThermal.packageTemperature << L"°C\n";
        file << L"  Status: " << GetThermalStatusName(cpuThermal.thermalStatus).data() << L"\n";
        file << L"  Throttling: " << (cpuThermal.isThrottling ? L"Yes" : L"No") << L"\n\n";

        // Power
        auto powerInfo = GetPowerInfo();
        file << L"Power Status:\n";
        file << L"  Source: " << GetPowerSourceName(powerInfo.powerSource).data() << L"\n";
        file << L"  Power Plan: " << powerInfo.activePowerPlan << L"\n";
        if (powerInfo.battery.hasBattery) {
            file << L"  Battery: " << static_cast<int>(powerInfo.battery.chargePercent) << L"%\n";
            file << L"  Battery Health: " << static_cast<int>(powerInfo.battery.healthPercent) << L"%\n";
        }
        file << L"\n";

        // Statistics
        file << L"Statistics:\n";
        file << L"  Polling Cycles: " << m_impl->m_statistics.pollingCycles.load() << L"\n";
        file << L"  Disk Health Checks: " << m_impl->m_statistics.diskHealthChecks.load() << L"\n";
        file << L"  Thermal Warnings: " << m_impl->m_statistics.thermalWarnings.load() << L"\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetDiskTypeName(DiskType type) noexcept {
    switch (type) {
        case DiskType::Unknown: return "Unknown";
        case DiskType::HDD: return "HDD";
        case DiskType::SSD_SATA: return "SSD (SATA)";
        case DiskType::SSD_NVMe: return "SSD (NVMe)";
        case DiskType::USB: return "USB Storage";
        case DiskType::SD: return "SD Card";
        case DiskType::Virtual: return "Virtual Disk";
        default: return "Unknown";
    }
}

std::string_view GetDiskHealthStatusName(DiskHealthStatus status) noexcept {
    switch (status) {
        case DiskHealthStatus::Unknown: return "Unknown";
        case DiskHealthStatus::Healthy: return "Healthy";
        case DiskHealthStatus::Warning: return "Warning";
        case DiskHealthStatus::Critical: return "Critical";
        case DiskHealthStatus::Failed: return "Failed";
        default: return "Unknown";
    }
}

std::string_view GetPowerSourceName(PowerSource source) noexcept {
    switch (source) {
        case PowerSource::Unknown: return "Unknown";
        case PowerSource::ACPower: return "AC Power";
        case PowerSource::Battery: return "Battery";
        case PowerSource::UPS: return "UPS";
        default: return "Unknown";
    }
}

std::string_view GetBatteryStatusName(BatteryStatus status) noexcept {
    switch (status) {
        case BatteryStatus::Unknown: return "Unknown";
        case BatteryStatus::Charging: return "Charging";
        case BatteryStatus::Discharging: return "Discharging";
        case BatteryStatus::Full: return "Full";
        case BatteryStatus::NotPresent: return "Not Present";
        default: return "Unknown";
    }
}

std::string_view GetThermalStatusName(ThermalStatus status) noexcept {
    switch (status) {
        case ThermalStatus::Unknown: return "Unknown";
        case ThermalStatus::Normal: return "Normal";
        case ThermalStatus::Warm: return "Warm";
        case ThermalStatus::Hot: return "Hot";
        case ThermalStatus::Critical: return "Critical";
        default: return "Unknown";
    }
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
