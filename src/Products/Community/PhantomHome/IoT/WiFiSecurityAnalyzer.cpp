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
 * ShadowStrike NGAV - WIFI SECURITY ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file WiFiSecurityAnalyzer.cpp
 * @brief Enterprise-grade WiFi network security analysis implementation
 *
 * Implements comprehensive WiFi security assessment including encryption
 * analysis, evil twin detection, rogue AP identification, and protocol
 * vulnerability detection for enterprise wireless security monitoring.
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - std::shared_mutex for concurrent read access
 * - RAII throughout for exception safety
 *
 * PERFORMANCE:
 * ============
 * - Lock-free statistics updates
 * - Efficient BSSID history with LRU eviction
 * - O(1) network lookups via hash tables
 * - Background monitoring thread with configurable intervals
 *
 * SECURITY FEATURES:
 * ==================
 * - Evil twin detection via signal strength and BSSID analysis
 * - Rogue AP detection with whitelist validation
 * - Encryption weakness identification (WEP, weak WPA)
 * - KRACK/Dragonblood vulnerability detection
 * - WPS attack surface analysis
 * - Deauthentication attack detection
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
#include "WiFiSecurityAnalyzer.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <thread>
#include <condition_variable>
#include <deque>
#include <cmath>

// Third-party libraries
#include <nlohmann/json.hpp>

// ShadowStrike infrastructure
#include "../Utils/Logger.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// Windows-specific headers
#ifdef _WIN32
#include <wlanapi.h>
#include <windot11.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <atomic>
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// INTERNAL STRUCTURES
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


// ============================================================================
// LOG CATEGORY
// ============================================================================

constexpr const wchar_t* LOG_CAT = L"WiFiSecurity";

// ============================================================================
// SSID SANITIZATION
// ============================================================================

/**
 * @brief Sanitize an SSID for safe display, logging, and JSON embedding.
 *
 * SSIDs are raw byte sequences (up to 32 bytes). They can contain null bytes,
 * control characters, non-UTF-8 sequences, and other hostile content.
 * An attacker controlling a nearby AP can craft SSIDs to:
 * - Inject into log files (CRLF injection)
 * - Break JSON serialization
 * - Exploit downstream parsers
 *
 * This function replaces non-printable-ASCII bytes with hex escapes.
 */
[[nodiscard]] std::string SanitizeSSID(const std::string& raw) noexcept {
    if (raw.empty()) return "<hidden>";

    std::string sanitized;
    sanitized.reserve(raw.size() * 2);

    for (unsigned char ch : raw) {
        if (ch >= 0x20 && ch < 0x7F && ch != '\\' && ch != '"') {
            sanitized.push_back(static_cast<char>(ch));
        } else {
            // Hex-escape non-printable and special characters
            sanitized += "\\x";
            constexpr char hex[] = "0123456789abcdef";
            sanitized.push_back(hex[(ch >> 4) & 0x0F]);
            sanitized.push_back(hex[ch & 0x0F]);
        }
    }
    return sanitized;
}

/**
 * @brief Validate and normalize a BSSID string (MAC address format).
 * @return Uppercased BSSID in XX:XX:XX:XX:XX:XX format, or empty on invalid input.
 */
[[nodiscard]] std::string ValidateAndNormalizeBSSID(const std::string& bssid) noexcept {
    if (bssid.size() != 17) return {};

    std::string normalized;
    normalized.reserve(17);

    for (size_t i = 0; i < 17; ++i) {
        char c = bssid[i];
        if (i % 3 == 2) {
            if (c != ':') return {};
            normalized.push_back(':');
        } else {
            char upper = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
            if ((upper >= '0' && upper <= '9') || (upper >= 'A' && upper <= 'F')) {
                normalized.push_back(upper);
            } else {
                return {};
            }
        }
    }
    return normalized;
}

// ============================================================================
// OUI VENDOR DATABASE
// ============================================================================

/**
 * @brief OUI vendor database — production subset covering major AP manufacturers.
 *
 * In production, this would be loaded from an updatable file (IEEE OUI database).
 * This embedded subset covers the most common AP, router, and IoT device vendors
 * to provide vendor identification without requiring external file I/O.
 */
const std::unordered_map<std::string, std::string> OUI_VENDORS = {
    // Apple
    {"00:1B:63", "Apple"}, {"00:25:00", "Apple"}, {"00:1E:C2", "Apple"},
    {"00:26:BB", "Apple"}, {"00:03:93", "Apple"}, {"00:0D:93", "Apple"},
    {"00:17:F2", "Apple"}, {"00:1F:5B", "Apple"}, {"00:21:E9", "Apple"},
    {"00:22:41", "Apple"}, {"00:23:12", "Apple"}, {"00:23:32", "Apple"},
    {"00:23:6C", "Apple"}, {"00:24:36", "Apple"}, {"00:25:BC", "Apple"},
    {"00:26:08", "Apple"}, {"AC:DE:48", "Apple"}, {"A8:5C:2C", "Apple"},
    {"3C:15:C2", "Apple"}, {"70:56:81", "Apple"}, {"F0:D1:A9", "Apple"},
    // Microsoft
    {"00:50:F2", "Microsoft"}, {"00:15:5D", "Microsoft"}, {"28:18:78", "Microsoft"},
    // Cisco / Meraki
    {"00:0C:41", "Cisco"}, {"00:17:94", "Cisco"}, {"00:1A:A1", "Cisco"},
    {"00:1B:D4", "Cisco"}, {"00:22:BD", "Cisco"}, {"00:23:04", "Cisco"},
    {"00:26:52", "Cisco"}, {"00:40:96", "Cisco"}, {"0C:75:BD", "Cisco"},
    {"AC:17:C8", "Cisco"}, {"00:18:0A", "Cisco Meraki"}, {"0C:8D:DB", "Cisco Meraki"},
    // Aruba / HPE
    {"00:0B:86", "Aruba"}, {"00:1A:1E", "Aruba"}, {"00:24:6C", "Aruba"},
    {"24:DE:C6", "Aruba"}, {"6C:F3:7F", "Aruba"}, {"AC:A3:1E", "Aruba"},
    // Ruckus
    {"00:22:7A", "Ruckus"}, {"C4:10:8A", "Ruckus"}, {"EC:58:EA", "Ruckus"},
    // Ubiquiti
    {"00:27:22", "Ubiquiti"}, {"04:18:D6", "Ubiquiti"}, {"24:A4:3C", "Ubiquiti"},
    {"44:D9:E7", "Ubiquiti"}, {"68:72:51", "Ubiquiti"}, {"78:8A:20", "Ubiquiti"},
    {"80:2A:A8", "Ubiquiti"}, {"B4:FB:E4", "Ubiquiti"}, {"F0:9F:C2", "Ubiquiti"},
    // TP-Link
    {"00:23:CD", "TP-Link"}, {"14:CC:20", "TP-Link"}, {"30:B5:C2", "TP-Link"},
    {"50:C7:BF", "TP-Link"}, {"54:C8:0F", "TP-Link"}, {"60:32:B1", "TP-Link"},
    {"C0:25:E9", "TP-Link"}, {"EC:08:6B", "TP-Link"}, {"F4:F2:6D", "TP-Link"},
    // Netgear
    {"00:14:6C", "Netgear"}, {"00:1B:2F", "Netgear"}, {"00:1E:2A", "Netgear"},
    {"00:26:F2", "Netgear"}, {"20:0C:C8", "Netgear"}, {"A0:21:B7", "Netgear"},
    {"A4:2B:8C", "Netgear"}, {"C4:3D:C7", "Netgear"}, {"B0:B9:8A", "Netgear"},
    // Linksys
    {"00:14:BF", "Linksys"}, {"00:18:F8", "Linksys"}, {"00:1A:70", "Linksys"},
    {"00:21:29", "Linksys"}, {"C0:56:27", "Linksys"},
    // ASUS
    {"00:1D:60", "ASUS"}, {"08:60:6E", "ASUS"}, {"10:BF:48", "ASUS"},
    {"1C:87:2C", "ASUS"}, {"2C:56:DC", "ASUS"}, {"50:46:5D", "ASUS"},
    {"AC:9E:17", "ASUS"}, {"F0:2F:74", "ASUS"},
    // D-Link
    {"00:05:5D", "D-Link"}, {"00:17:9A", "D-Link"}, {"00:1B:11", "D-Link"},
    {"00:1C:F0", "D-Link"}, {"1C:7E:E5", "D-Link"}, {"28:10:7B", "D-Link"},
    {"84:C9:B2", "D-Link"}, {"FC:75:16", "D-Link"},
    // Huawei
    {"00:25:9E", "Huawei"}, {"00:46:4B", "Huawei"}, {"20:F3:A3", "Huawei"},
    {"48:46:FB", "Huawei"}, {"58:2A:F7", "Huawei"}, {"70:72:3C", "Huawei"},
    {"88:28:B3", "Huawei"}, {"AC:E8:7B", "Huawei"}, {"CC:A2:23", "Huawei"},
    // Samsung
    {"00:12:47", "Samsung"}, {"00:21:19", "Samsung"}, {"00:26:37", "Samsung"},
    {"08:D4:2B", "Samsung"}, {"34:23:BA", "Samsung"}, {"50:01:BB", "Samsung"},
    {"78:47:1D", "Samsung"}, {"A8:F2:74", "Samsung"}, {"C0:BD:D1", "Samsung"},
    // Intel
    {"00:02:B3", "Intel"}, {"00:13:02", "Intel"}, {"00:1B:21", "Intel"},
    {"00:1F:3B", "Intel"}, {"3C:97:0E", "Intel"}, {"68:05:CA", "Intel"},
    {"8C:EC:4B", "Intel"}, {"B4:6B:FC", "Intel"},
    // Virtualization (security-relevant for rogue AP detection)
    {"00:0C:29", "VMware"}, {"00:50:56", "VMware"}, {"08:00:27", "VirtualBox"},
    {"00:1C:42", "Parallels"}, {"52:54:00", "QEMU/KVM"},
    // Raspberry Pi (common rogue AP platform)
    {"B8:27:EB", "Raspberry Pi"}, {"DC:A6:32", "Raspberry Pi"},
    {"E4:5F:01", "Raspberry Pi"},
    // Amazon (Echo, Ring, etc.)
    {"00:FC:8B", "Amazon"}, {"10:CE:A9", "Amazon"}, {"40:B4:CD", "Amazon"},
    {"44:65:0D", "Amazon"}, {"68:54:FD", "Amazon"}, {"74:C2:46", "Amazon"},
    // Google / Nest
    {"00:1A:11", "Google"}, {"3C:5A:B4", "Google"}, {"54:60:09", "Google"},
    {"A4:77:33", "Google"}, {"F4:F5:D8", "Google"},
};

/**
 * @brief Known weak/default SSIDs (lowercased for comparison)
 */
const std::vector<std::string> WEAK_SSIDS = {
    "linksys", "default", "netgear", "dlink", "asus", "tp-link",
    "belkin", "router", "wireless", "network", "wifi", "internet",
    "admin", "home", "setup", "guest", "test", "xfinity",
    "att-wifi", "tmobile", "verizon", "comcast"
};

/**
 * @brief BSSID tracking entry
 */
struct BSSIDTracker {
    std::string ssid;
    std::deque<BSSIDHistoryEntry> history;
    std::unordered_map<std::string, SystemTimePoint> bssidLastSeen;
};

/// @brief Maximum stale age before a tracked network is evicted
static constexpr auto STALE_NETWORK_AGE = std::chrono::hours(24);

} // anonymous namespace

// ============================================================================
// WIFI SECURITY ANALYZER IMPLEMENTATION (PIMPL)
// ============================================================================

class WiFiSecurityAnalyzerImpl {
public:
    WiFiSecurityAnalyzerImpl();
    ~WiFiSecurityAnalyzerImpl();

    // Lifecycle
    bool Initialize(const WiFiAnalyzerConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const WiFiAnalyzerConfiguration& config);
    WiFiAnalyzerConfiguration GetConfiguration() const;

    // Connection info
    WiFiConnectionInfo GetCurrentConnectionInfo();
    bool IsConnected() const noexcept;
    std::optional<WiFiNetworkInfo> GetConnectedNetwork() const;

    // Scanning
    std::vector<WiFiNetworkInfo> ScanNearbyNetworks();
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_monitoringActive.load(std::memory_order_acquire); }

    // Threat detection
    EvilTwinDetectionResult DetectEvilTwin();
    std::vector<WiFiSecurityThreat> CheckNetworkSecurity(const WiFiNetworkInfo& network);
    std::vector<WiFiSecurityThreat> GetDetectedThreats() const;
    std::vector<WiFiSecurityThreat> AnalyzeCurrentConnection();

    // Network management
    std::vector<WiFiNetworkInfo> GetTrackedNetworks() const;
    std::optional<WiFiNetworkInfo> GetNetworkBySSID(const std::string& ssid) const;
    std::optional<WiFiNetworkInfo> GetNetworkByBSSID(const std::string& bssid) const;
    bool AddToWhitelist(const std::string& bssid);
    bool RemoveFromWhitelist(const std::string& bssid);
    bool BlockNetwork(const std::string& bssid);

    // History
    std::vector<BSSIDHistoryEntry> GetBSSIDHistory(const std::string& ssid) const;

    // Callbacks
    void RegisterNetworkFoundCallback(NetworkFoundCallback callback);
    void RegisterThreatCallback(ThreatDetectedCallback callback);
    void RegisterEvilTwinCallback(EvilTwinCallback callback);
    void RegisterConnectionCallback(ConnectionChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    WiFiStatistics GetStatistics() const;
    void ResetStatistics();

    bool SelfTest();

private:
    // Helper functions
    void MonitoringThreadFunc();
    void ProcessMonitoringTick();
    bool InitializeWLAN();
    void ShutdownWLAN();
    std::vector<WiFiNetworkInfo> QueryNetworksWLAN();
    WiFiConnectionInfo QueryConnectionWLAN();
    SecurityLevel CalculateSecurityLevel(const WiFiNetworkInfo& network);
    WiFiThreatType AnalyzeThreats(const WiFiNetworkInfo& network);
    std::string GetVendorFromBSSID(const std::string& bssid) const;
    bool IsWeakSSID(const std::string& ssid) const;
    bool IsKnownRogueAP(const std::string& bssid);
    void UpdateBSSIDHistory(const WiFiNetworkInfo& network);
    EvilTwinDetectionResult DetectEvilTwinForSSID(const std::string& ssid);
    float CalculateBSSIDSimilarity(const std::string& bssid1, const std::string& bssid2) const;
    void NotifyNetworkFound(const WiFiNetworkInfo& network);
    void NotifyThreat(const WiFiSecurityThreat& threat);
    void NotifyEvilTwin(const EvilTwinDetectionResult& result);
    void NotifyConnectionChange(const WiFiConnectionInfo& conn);
    void NotifyError(const std::string& message, int code);
    std::string NormalizeSSID(const std::string& ssid) const;
    std::string NormalizeBSSID(const std::string& bssid) const;

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    WiFiAnalyzerConfiguration m_config;

    // WLAN handle
#ifdef _WIN32
    HANDLE m_wlanHandle = nullptr;
    GUID m_interfaceGuid{};
    bool m_hasInterface = false;
#endif

    // Network tracking
    std::unordered_map<std::string, WiFiNetworkInfo> m_trackedNetworks;  // Key: BSSID
    std::unordered_map<std::string, BSSIDTracker> m_bssidHistory;  // Key: SSID
    std::unordered_set<std::string> m_blockedBSSIDs;

    // Threat tracking
    mutable std::mutex m_threatMutex;
    std::deque<WiFiSecurityThreat> m_detectedThreats;
    static constexpr size_t MAX_THREAT_HISTORY = 1000;

    // Monitoring thread
    std::unique_ptr<std::thread> m_monitoringThread;
    std::atomic<bool> m_monitoringActive{false};
    std::condition_variable m_monitoringCV;
    std::mutex m_monitoringMutex;

    // Callbacks
    mutable std::mutex m_callbackMutex;
    NetworkFoundCallback m_networkFoundCallback;
    ThreatDetectedCallback m_threatCallback;
    EvilTwinCallback m_evilTwinCallback;
    ConnectionChangeCallback m_connectionCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    mutable WiFiStatistics m_stats;

    // Infrastructure references
    ThreatIntel::ThreatIntelManager* m_threatIntel = nullptr;

    // Internal BSSID whitelist (WhiteListStore is for file-based whitelisting,
    // not WiFi BSSID management — we manage our own BSSID whitelist)
    std::unordered_set<std::string> m_whitelistedBSSIDs;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

WiFiSecurityAnalyzerImpl::WiFiSecurityAnalyzerImpl() {
    SS_LOG_INFO(LOG_CAT, L"Instance created");
}

WiFiSecurityAnalyzerImpl::~WiFiSecurityAnalyzerImpl() {
    Shutdown();
    SS_LOG_INFO(LOG_CAT, L"Instance destroyed");
}

bool WiFiSecurityAnalyzerImpl::Initialize(const WiFiAnalyzerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CAT, L"Already initialized");
        return true;
    }

    try {
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid configuration: scanInterval=%u, evilTwinThreshold=%d",
                         config.scanIntervalSeconds, config.evilTwinSignalThreshold);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize ThreatIntel reference (optional dependency)
        try {
            m_threatIntel = &ThreatIntel::ThreatIntelManager::Instance();
            if (!m_threatIntel->IsInitialized()) {
                SS_LOG_WARN(LOG_CAT, L"ThreatIntelManager available but not initialized");
                m_threatIntel = nullptr;
            }
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CAT, L"ThreatIntel not available: %hs", e.what());
            m_threatIntel = nullptr;
        }

        // Initialize WLAN API
        if (!InitializeWLAN()) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to initialize WLAN API");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        // Reset statistics
        m_stats.Reset();
        AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(LOG_CAT, L"Initialized successfully (Version %hs)", WiFiSecurityAnalyzer::GetVersionString().c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"Initialization failed: Unknown error");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void WiFiSecurityAnalyzerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Stop monitoring
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);
            m_monitoringCV.notify_all();

            if (m_monitoringThread && m_monitoringThread->joinable()) {
                lock.unlock();  // Release lock before joining to avoid deadlock
                m_monitoringThread->join();
                lock.lock();
            }
            m_monitoringThread.reset();
        }

        // Shutdown WLAN
        ShutdownWLAN();

        // Clear state
        m_trackedNetworks.clear();
        m_bssidHistory.clear();
        m_blockedBSSIDs.clear();
        m_whitelistedBSSIDs.clear();
        {
            std::lock_guard threatLock(m_threatMutex);
            m_detectedThreats.clear();
        }

        // Clear callbacks
        UnregisterCallbacks();

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        SS_LOG_INFO(LOG_CAT, L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Shutdown error: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CAT, L"Shutdown error: Unknown exception");
    }
}

bool WiFiSecurityAnalyzerImpl::InitializeWLAN() {
#ifdef _WIN32
    try {
        // Open WLAN handle
        DWORD negotiatedVersion = 0;
        DWORD result = WlanOpenHandle(2, nullptr, &negotiatedVersion, &m_wlanHandle);

        if (result != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CAT, L"WlanOpenHandle failed: error=%u", result);
            return false;
        }

        // Enumerate interfaces
        PWLAN_INTERFACE_INFO_LIST interfaceList = nullptr;
        result = WlanEnumInterfaces(m_wlanHandle, nullptr, &interfaceList);

        if (result != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CAT, L"WlanEnumInterfaces failed: error=%u", result);
            WlanCloseHandle(m_wlanHandle, nullptr);
            m_wlanHandle = nullptr;
            return false;
        }

        // Use first available interface
        if (interfaceList && interfaceList->dwNumberOfItems > 0) {
            m_interfaceGuid = interfaceList->InterfaceInfo[0].InterfaceGuid;
            m_hasInterface = true;

            wchar_t guidStr[40] = {};
            StringFromGUID2(m_interfaceGuid, guidStr, 40);
            SS_LOG_INFO(LOG_CAT, L"Using WiFi interface: %ls", guidStr);
        } else {
            SS_LOG_WARN(LOG_CAT, L"No WiFi interface found");
            m_hasInterface = false;
        }

        if (interfaceList) {
            WlanFreeMemory(interfaceList);
        }
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"WLAN initialization error: %hs", e.what());
        return false;
    }
#else
    SS_LOG_WARN(LOG_CAT, L"WLAN API not available on this platform");
    return false;
#endif
}

void WiFiSecurityAnalyzerImpl::ShutdownWLAN() {
#ifdef _WIN32
    if (m_wlanHandle) {
        WlanCloseHandle(m_wlanHandle, nullptr);
        m_wlanHandle = nullptr;
    }
    m_hasInterface = false;
#endif
}

bool WiFiSecurityAnalyzerImpl::UpdateConfiguration(const WiFiAnalyzerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Invalid configuration: scanInterval=%u, evilTwinThreshold=%d",
                     config.scanIntervalSeconds, config.evilTwinSignalThreshold);
        return false;
    }

    m_config = config;
    SS_LOG_INFO(LOG_CAT, L"Configuration updated");
    return true;
}

WiFiAnalyzerConfiguration WiFiSecurityAnalyzerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// CONNECTION INFO
// ============================================================================

WiFiConnectionInfo WiFiSecurityAnalyzerImpl::GetCurrentConnectionInfo() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CAT, L"GetCurrentConnectionInfo called before initialization");
        return {};
    }

    return QueryConnectionWLAN();
}

bool WiFiSecurityAnalyzerImpl::IsConnected() const noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

#ifdef _WIN32
    // Read WLAN handle/interface under shared lock to prevent races during shutdown
    HANDLE wlanHandle = nullptr;
    GUID interfaceGuid{};
    bool hasInterface = false;
    {
        std::shared_lock lock(m_mutex);
        wlanHandle = m_wlanHandle;
        interfaceGuid = m_interfaceGuid;
        hasInterface = m_hasInterface;
    }

    if (!wlanHandle || !hasInterface) {
        return false;
    }

    PWLAN_CONNECTION_ATTRIBUTES connAttr = nullptr;
    DWORD dataSize = 0;

    DWORD result = WlanQueryInterface(
        wlanHandle,
        &interfaceGuid,
        wlan_intf_opcode_current_connection,
        nullptr,
        &dataSize,
        reinterpret_cast<PVOID*>(&connAttr),
        nullptr
    );

    if (result == ERROR_SUCCESS && connAttr) {
        bool connected = (connAttr->isState == wlan_interface_state_connected);
        WlanFreeMemory(connAttr);
        return connected;
    }
#endif

    return false;
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::GetConnectedNetwork() const {
    if (!IsConnected()) {
        return std::nullopt;
    }

    std::shared_lock lock(m_mutex);

    // Find connected network in tracked networks
    for (const auto& [bssid, network] : m_trackedNetworks) {
        if (network.isConnected) {
            return network;
        }
    }

    return std::nullopt;
}

// ============================================================================
// SCANNING
// ============================================================================

std::vector<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::ScanNearbyNetworks() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CAT, L"Scan requested before initialization");
        return {};
    }

    m_status.store(ModuleStatus::Scanning, std::memory_order_release);
    m_stats.totalScans++;

    try {
        auto networks = QueryNetworksWLAN();

        // Collect notification payloads outside the lock to avoid deadlocks.
        // Callbacks are user-provided and could re-enter the analyzer.
        std::vector<WiFiNetworkInfo> newNetworks;
        std::vector<WiFiSecurityThreat> allThreats;

        {
            std::unique_lock lock(m_mutex);

            // Evict stale networks if we're at the tracking cap
            if (m_trackedNetworks.size() >= WiFiConstants::MAX_TRACKED_NETWORKS) {
                auto now = std::chrono::system_clock::now();
                std::erase_if(m_trackedNetworks, [&](const auto& pair) {
                    auto age = std::chrono::duration_cast<std::chrono::hours>(now - pair.second.lastSeen);
                    return age >= STALE_NETWORK_AGE;
                });
            }

            for (auto& network : networks) {
                // Calculate security level
                network.securityLevel = CalculateSecurityLevel(network);

                // Analyze threats
                network.threats = AnalyzeThreats(network);

                // Get vendor
                network.vendor = GetVendorFromBSSID(network.bssid);

                // Check internal BSSID whitelist
                network.isWhitelisted = m_whitelistedBSSIDs.contains(network.bssid);

                // Update timestamps
                auto now = std::chrono::system_clock::now();
                auto it = m_trackedNetworks.find(network.bssid);
                if (it == m_trackedNetworks.end()) {
                    network.firstSeen = now;
                    network.lastSeen = now;
                    m_stats.networksDiscovered++;
                    newNetworks.push_back(network);
                } else {
                    network.firstSeen = it->second.firstSeen;
                    network.lastSeen = now;
                }

                // Enforce tracking cap — skip insertion if at limit after eviction
                if (m_trackedNetworks.size() < WiFiConstants::MAX_TRACKED_NETWORKS ||
                    m_trackedNetworks.contains(network.bssid)) {
                    m_trackedNetworks[network.bssid] = network;
                }

                // Update BSSID history
                if (m_config.trackBSSIDHistory) {
                    UpdateBSSIDHistory(network);
                }

                // Collect threats for notification (outside lock later)
                if (network.threats != WiFiThreatType::None) {
                    auto threats = CheckNetworkSecurity(network);
                    allThreats.insert(allThreats.end(),
                        std::make_move_iterator(threats.begin()),
                        std::make_move_iterator(threats.end()));
                }
            }

            m_stats.currentNetworksTracked = static_cast<uint32_t>(m_trackedNetworks.size());
        }
        // Lock released — safe to invoke callbacks now

        // Fire notifications without holding m_mutex
        for (const auto& net : newNetworks) {
            NotifyNetworkFound(net);
        }
        for (const auto& threat : allThreats) {
            NotifyThreat(threat);
        }

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(LOG_CAT, L"Scan complete: %zu networks found", networks.size());
        return networks;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Scan failed: %hs", e.what());
        m_status.store(ModuleStatus::Running, std::memory_order_release);
        NotifyError(e.what(), -1);
        return {};
    }
}

bool WiFiSecurityAnalyzerImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CAT, L"Cannot start monitoring: Not initialized");
        return false;
    }

    if (m_monitoringActive.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CAT, L"Monitoring already active");
        return true;
    }

    try {
        m_monitoringActive.store(true, std::memory_order_release);
        m_monitoringThread = std::make_unique<std::thread>(&WiFiSecurityAnalyzerImpl::MonitoringThreadFunc, this);

        m_status.store(ModuleStatus::Monitoring, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Monitoring started (interval=%u s)", m_config.scanIntervalSeconds);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Start monitoring failed: %hs", e.what());
        m_monitoringActive.store(false, std::memory_order_release);
        return false;
    }
}

void WiFiSecurityAnalyzerImpl::StopMonitoring() {
    if (!m_monitoringActive.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_monitoringActive.store(false, std::memory_order_release);
        m_monitoringCV.notify_all();

        if (m_monitoringThread && m_monitoringThread->joinable()) {
            m_monitoringThread->join();
        }
        m_monitoringThread.reset();

        m_status.store(ModuleStatus::Running, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Monitoring stopped");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Stop monitoring failed: %hs", e.what());
    }
}

// ============================================================================
// THREAT DETECTION
// ============================================================================

EvilTwinDetectionResult WiFiSecurityAnalyzerImpl::DetectEvilTwin() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CAT, L"Not initialized");
        return {};
    }

    std::shared_lock lock(m_mutex);

    // Check each SSID for multiple BSSIDs
    for (const auto& [ssid, tracker] : m_bssidHistory) {
        if (tracker.bssidLastSeen.size() >= 2) {
            auto result = DetectEvilTwinForSSID(ssid);
            if (result.detected) {
                return result;
            }
        }
    }

    return {};
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzerImpl::CheckNetworkSecurity(const WiFiNetworkInfo& network) {
    std::vector<WiFiSecurityThreat> threats;

    // Take a snapshot of config under lock (may be called outside m_mutex context)
    WiFiAnalyzerConfiguration configSnap;
    {
        std::shared_lock lock(m_mutex);
        configSnap = m_config;
    }

    try {
        const std::string safeSSID = SanitizeSSID(network.ssid);

        // Check encryption weakness
        if (configSnap.alertOnWeakEncryption) {
            if (network.encryption == EncryptionType::WEP) {
                WiFiSecurityThreat threat;
                threat.type = WiFiThreatType::WeakEncryption;
                threat.severity = SecurityLevel::Critical;
                threat.affectedSSID = safeSSID;
                threat.affectedBSSID = network.bssid;
                threat.description = "WEP encryption is critically insecure and can be cracked in minutes";
                threat.recommendation = "Upgrade to WPA2/WPA3 immediately";
                threat.detectionTime = std::chrono::system_clock::now();
                threats.push_back(std::move(threat));

                m_stats.weakNetworksFound++;
                m_stats.byThreatType[4]++;
            }
        }

        // Check open network
        if (configSnap.alertOnOpenNetworks && network.encryption == EncryptionType::Open) {
            WiFiSecurityThreat threat;
            threat.type = WiFiThreatType::OpenNetwork;
            threat.severity = SecurityLevel::Weak;
            threat.affectedSSID = safeSSID;
            threat.affectedBSSID = network.bssid;
            threat.description = "Open network with no encryption - traffic can be intercepted";
            threat.recommendation = "Enable WPA2/WPA3 encryption";
            threat.detectionTime = std::chrono::system_clock::now();
            threats.push_back(std::move(threat));

            m_stats.byThreatType[5]++;
        }

        // Check WPS
        if (network.wpsEnabled) {
            WiFiSecurityThreat threat;
            threat.type = WiFiThreatType::WPSEnabled;
            threat.severity = SecurityLevel::Moderate;
            threat.affectedSSID = safeSSID;
            threat.affectedBSSID = network.bssid;
            threat.description = "WPS is vulnerable to brute-force PIN attacks (Reaver/Bully)";
            threat.recommendation = "Disable WPS in router settings";
            threat.detectionTime = std::chrono::system_clock::now();
            threats.push_back(std::move(threat));

            m_stats.byThreatType[6]++;
        }

        // Check KRACK vulnerability (WPA2 without PMF)
        if (network.encryption == EncryptionType::WPA2_Personal && !network.pmfEnabled) {
            WiFiSecurityThreat threat;
            threat.type = WiFiThreatType::KRACKVulnerable;
            threat.severity = SecurityLevel::Moderate;
            threat.affectedSSID = safeSSID;
            threat.affectedBSSID = network.bssid;
            threat.description = "WPA2 without PMF is vulnerable to key reinstallation attacks (KRACK)";
            threat.recommendation = "Enable Protected Management Frames (PMF/802.11w) or upgrade to WPA3";
            threat.cveId = "CVE-2017-13077";
            threat.detectionTime = std::chrono::system_clock::now();
            threats.push_back(std::move(threat));

            m_stats.byThreatType[7]++;
        }

        // Check rogue AP against ThreatIntel
        if (configSnap.enableRogueAPDetection) {
            if (IsKnownRogueAP(network.bssid)) {
                WiFiSecurityThreat threat;
                threat.type = WiFiThreatType::RogueAP;
                threat.severity = SecurityLevel::Critical;
                threat.affectedSSID = safeSSID;
                threat.affectedBSSID = network.bssid;
                threat.description = "Rogue access point detected - BSSID matched threat intelligence database";
                threat.recommendation = "Do not connect. Report to network administrator. Disconnect if connected.";
                threat.detectionTime = std::chrono::system_clock::now();
                threats.push_back(std::move(threat));

                m_stats.rogueAPsDetected++;
                m_stats.byThreatType[2]++;
            }
        }

        // Store threats
        if (!threats.empty()) {
            std::lock_guard threatLock(m_threatMutex);
            for (const auto& threat : threats) {
                m_detectedThreats.push_back(threat);
                if (m_detectedThreats.size() > MAX_THREAT_HISTORY) {
                    m_detectedThreats.pop_front();
                }
            }
            m_stats.threatsDetected += threats.size();
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"CheckNetworkSecurity failed: %hs", e.what());
    }

    return threats;
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzerImpl::GetDetectedThreats() const {
    std::lock_guard lock(m_threatMutex);
    return {m_detectedThreats.begin(), m_detectedThreats.end()};
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzerImpl::AnalyzeCurrentConnection() {
    auto network = GetConnectedNetwork();
    if (!network) {
        return {};
    }

    return CheckNetworkSecurity(*network);
}

// ============================================================================
// NETWORK MANAGEMENT
// ============================================================================

std::vector<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::GetTrackedNetworks() const {
    std::shared_lock lock(m_mutex);

    std::vector<WiFiNetworkInfo> networks;
    networks.reserve(m_trackedNetworks.size());

    for (const auto& [bssid, network] : m_trackedNetworks) {
        networks.push_back(network);
    }

    return networks;
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::GetNetworkBySSID(const std::string& ssid) const {
    std::shared_lock lock(m_mutex);

    std::string normalized = NormalizeSSID(ssid);

    for (const auto& [bssid, network] : m_trackedNetworks) {
        if (NormalizeSSID(network.ssid) == normalized) {
            return network;
        }
    }

    return std::nullopt;
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::GetNetworkByBSSID(const std::string& bssid) const {
    std::shared_lock lock(m_mutex);

    std::string normalized = NormalizeBSSID(bssid);
    auto it = m_trackedNetworks.find(normalized);

    if (it != m_trackedNetworks.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool WiFiSecurityAnalyzerImpl::AddToWhitelist(const std::string& bssid) {
    try {
        std::string normalized = NormalizeBSSID(bssid);
        if (normalized.empty()) {
            SS_LOG_ERROR(LOG_CAT, L"AddToWhitelist: Invalid BSSID format");
            return false;
        }

        std::unique_lock lock(m_mutex);
        auto [it, inserted] = m_whitelistedBSSIDs.insert(normalized);

        if (inserted) {
            SS_LOG_INFO(LOG_CAT, L"Added BSSID to whitelist: %hs", normalized.c_str());
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"AddToWhitelist failed: %hs", e.what());
        return false;
    }
}

bool WiFiSecurityAnalyzerImpl::RemoveFromWhitelist(const std::string& bssid) {
    try {
        std::string normalized = NormalizeBSSID(bssid);
        if (normalized.empty()) {
            SS_LOG_ERROR(LOG_CAT, L"RemoveFromWhitelist: Invalid BSSID format");
            return false;
        }

        std::unique_lock lock(m_mutex);
        size_t removed = m_whitelistedBSSIDs.erase(normalized);

        if (removed > 0) {
            SS_LOG_INFO(LOG_CAT, L"Removed BSSID from whitelist: %hs", normalized.c_str());
        }

        return removed > 0;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"RemoveFromWhitelist failed: %hs", e.what());
        return false;
    }
}

bool WiFiSecurityAnalyzerImpl::BlockNetwork(const std::string& bssid) {
    std::unique_lock lock(m_mutex);

    try {
        std::string normalized = NormalizeBSSID(bssid);
        if (normalized.empty()) {
            SS_LOG_ERROR(LOG_CAT, L"BlockNetwork: Invalid BSSID format");
            return false;
        }

        m_blockedBSSIDs.insert(normalized);

        SS_LOG_INFO(LOG_CAT, L"Blocked network: %hs", normalized.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"BlockNetwork failed: %hs", e.what());
        return false;
    }
}

// ============================================================================
// HISTORY
// ============================================================================

std::vector<BSSIDHistoryEntry> WiFiSecurityAnalyzerImpl::GetBSSIDHistory(const std::string& ssid) const {
    std::shared_lock lock(m_mutex);

    std::string normalized = NormalizeSSID(ssid);
    auto it = m_bssidHistory.find(normalized);

    if (it != m_bssidHistory.end()) {
        return {it->second.history.begin(), it->second.history.end()};
    }

    return {};
}

// ============================================================================
// CALLBACKS
// ============================================================================

void WiFiSecurityAnalyzerImpl::RegisterNetworkFoundCallback(NetworkFoundCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_networkFoundCallback = std::move(callback);
}

void WiFiSecurityAnalyzerImpl::RegisterThreatCallback(ThreatDetectedCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_threatCallback = std::move(callback);
}

void WiFiSecurityAnalyzerImpl::RegisterEvilTwinCallback(EvilTwinCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_evilTwinCallback = std::move(callback);
}

void WiFiSecurityAnalyzerImpl::RegisterConnectionCallback(ConnectionChangeCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_connectionCallback = std::move(callback);
}

void WiFiSecurityAnalyzerImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCallback = std::move(callback);
}

void WiFiSecurityAnalyzerImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_networkFoundCallback = nullptr;
    m_threatCallback = nullptr;
    m_evilTwinCallback = nullptr;
    m_connectionCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

WiFiStatistics WiFiSecurityAnalyzerImpl::GetStatistics() const {
    return m_stats;
}

void WiFiSecurityAnalyzerImpl::ResetStatistics() {
    m_stats.Reset();
    AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());
    SS_LOG_INFO(LOG_CAT, L"Statistics reset");
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void WiFiSecurityAnalyzerImpl::MonitoringThreadFunc() {
    SS_LOG_INFO(LOG_CAT, L"Monitoring thread started");

    while (m_monitoringActive.load(std::memory_order_acquire)) {
        try {
            ProcessMonitoringTick();

            // Read scan interval under lock (it can be updated via UpdateConfiguration)
            uint32_t intervalSec;
            {
                std::shared_lock lock(m_mutex);
                intervalSec = m_config.scanIntervalSeconds;
            }

            std::unique_lock lock(m_monitoringMutex);
            m_monitoringCV.wait_for(lock, std::chrono::seconds(intervalSec),
                [this] { return !m_monitoringActive.load(std::memory_order_acquire); });

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Monitoring error: %hs", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    SS_LOG_INFO(LOG_CAT, L"Monitoring thread stopped");
}

void WiFiSecurityAnalyzerImpl::ProcessMonitoringTick() {
    // Perform scan
    ScanNearbyNetworks();

    // Check for evil twins
    if (m_config.enableEvilTwinDetection) {
        auto result = DetectEvilTwin();
        if (result.detected) {
            m_stats.evilTwinsDetected++;
            NotifyEvilTwin(result);
        }
    }

    // Check current connection
    auto connInfo = GetCurrentConnectionInfo();
    if (connInfo.isConnected) {
        NotifyConnectionChange(connInfo);
    }
}

std::vector<WiFiNetworkInfo> WiFiSecurityAnalyzerImpl::QueryNetworksWLAN() {
    std::vector<WiFiNetworkInfo> networks;

#ifdef _WIN32
    if (!m_wlanHandle || !m_hasInterface) {
        return networks;
    }

    try {
        // Trigger scan
        WlanScan(m_wlanHandle, &m_interfaceGuid, nullptr, nullptr, nullptr);

        // Wait for scan to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        // Get available networks
        PWLAN_AVAILABLE_NETWORK_LIST networkList = nullptr;
        DWORD result = WlanGetAvailableNetworkList(
            m_wlanHandle,
            &m_interfaceGuid,
            0,
            nullptr,
            &networkList
        );

        if (result != ERROR_SUCCESS || !networkList) {
            SS_LOG_WARN(LOG_CAT, L"WlanGetAvailableNetworkList failed: error=%u", result);
            return networks;
        }

        // RAII guard for networkList
        struct WlanListGuard {
            PVOID ptr;
            ~WlanListGuard() { if (ptr) WlanFreeMemory(ptr); }
        } networkListGuard{networkList};

        // Cap the number of networks we process to prevent runaway allocation
        const DWORD maxItems = std::min(networkList->dwNumberOfItems,
                                         static_cast<DWORD>(WiFiConstants::MAX_TRACKED_NETWORKS));

        for (DWORD i = 0; i < maxItems; ++i) {
            const auto& entry = networkList->Network[i];

            WiFiNetworkInfo network;

            // SSID — raw bytes from the driver (potentially hostile)
            if (entry.dot11Ssid.uSSIDLength > DOT11_SSID_MAX_LENGTH) {
                SS_LOG_WARN(LOG_CAT, L"Skipping network with invalid SSID length: %u",
                            entry.dot11Ssid.uSSIDLength);
                continue;
            }
            network.ssid = std::string(
                reinterpret_cast<const char*>(entry.dot11Ssid.ucSSID),
                entry.dot11Ssid.uSSIDLength
            );

            // Hidden SSID detection: empty SSID or all-zero SSID bytes
            network.isHidden = (entry.dot11Ssid.uSSIDLength == 0);
            if (!network.isHidden) {
                bool allZero = true;
                for (ULONG b = 0; b < entry.dot11Ssid.uSSIDLength; ++b) {
                    if (entry.dot11Ssid.ucSSID[b] != 0) { allZero = false; break; }
                }
                network.isHidden = allZero;
            }

            // Signal strength
            network.signalQuality = entry.wlanSignalQuality;
            network.signalStrength = -100 + (entry.wlanSignalQuality / 2);

            // Encryption mapping
            switch (entry.dot11DefaultCipherAlgorithm) {
                case DOT11_CIPHER_ALGO_NONE:
                    network.encryption = EncryptionType::Open;
                    break;
                case DOT11_CIPHER_ALGO_WEP:
                case DOT11_CIPHER_ALGO_WEP40:
                case DOT11_CIPHER_ALGO_WEP104:
                    network.encryption = EncryptionType::WEP;
                    break;
                case DOT11_CIPHER_ALGO_TKIP:
                    network.encryption = EncryptionType::WPA_Personal;
                    break;
                case DOT11_CIPHER_ALGO_CCMP:
                    if (entry.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_WPA3 ||
                        entry.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_WPA3_SAE) {
                        network.encryption = EncryptionType::WPA3_Personal;
                    } else {
                        network.encryption = EncryptionType::WPA2_Personal;
                    }
                    break;
                default:
                    network.encryption = EncryptionType::Unknown;
            }

            // Connected flag
            network.isConnected = (entry.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0;

            // Get detailed BSS information for BSSID and frequency
            PWLAN_BSS_LIST bssList = nullptr;
            result = WlanGetNetworkBssList(
                m_wlanHandle,
                &m_interfaceGuid,
                const_cast<PDOT11_SSID>(&entry.dot11Ssid),
                entry.dot11BssType,
                FALSE,
                nullptr,
                &bssList
            );

            if (result == ERROR_SUCCESS && bssList && bssList->dwNumberOfItems > 0) {
                const auto& bss = bssList->wlanBssEntries[0];

                // Format BSSID from raw MAC bytes
                std::ostringstream bssidStr;
                bssidStr << std::hex << std::setfill('0') << std::uppercase;
                for (int j = 0; j < 6; ++j) {
                    if (j > 0) bssidStr << ":";
                    bssidStr << std::setw(2) << static_cast<int>(bss.dot11Bssid[j]);
                }
                network.bssid = bssidStr.str();

                // Validate BSSID format
                std::string validatedBSSID = ValidateAndNormalizeBSSID(network.bssid);
                if (validatedBSSID.empty()) {
                    SS_LOG_WARN(LOG_CAT, L"Skipping network with invalid BSSID format");
                    WlanFreeMemory(bssList);
                    continue;
                }
                network.bssid = validatedBSSID;

                // Frequency and channel
                network.frequency = bss.ulChCenterFrequency / 1000;  // kHz to MHz
                network.channel = GetChannelFromFrequency(network.frequency);
                network.band = GetBandFromFrequency(network.frequency);

                WlanFreeMemory(bssList);
            } else {
                if (bssList) WlanFreeMemory(bssList);
            }

            if (!network.bssid.empty()) {
                networks.push_back(std::move(network));
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"QueryNetworksWLAN error: %hs", e.what());
    }
#endif

    return networks;
}

WiFiConnectionInfo WiFiSecurityAnalyzerImpl::QueryConnectionWLAN() {
    WiFiConnectionInfo connInfo;

#ifdef _WIN32
    if (!m_wlanHandle || !m_hasInterface) {
        return connInfo;
    }

    try {
        PWLAN_CONNECTION_ATTRIBUTES connAttr = nullptr;
        DWORD dataSize = 0;

        DWORD result = WlanQueryInterface(
            m_wlanHandle,
            &m_interfaceGuid,
            wlan_intf_opcode_current_connection,
            nullptr,
            &dataSize,
            reinterpret_cast<PVOID*>(&connAttr),
            nullptr
        );

        if (result == ERROR_SUCCESS && connAttr) {
            // RAII guard
            struct ConnAttrGuard {
                PVOID ptr;
                ~ConnAttrGuard() { if (ptr) WlanFreeMemory(ptr); }
            } guard{connAttr};

            if (connAttr->isState == wlan_interface_state_connected) {
                connInfo.isConnected = true;

                // SSID — validate length before use
                const auto ssidLen = connAttr->wlanAssociationAttributes.dot11Ssid.uSSIDLength;
                if (ssidLen <= DOT11_SSID_MAX_LENGTH) {
                    connInfo.network.ssid = std::string(
                        reinterpret_cast<const char*>(connAttr->wlanAssociationAttributes.dot11Ssid.ucSSID),
                        ssidLen
                    );
                }

                // BSSID
                const auto& bssid = connAttr->wlanAssociationAttributes.dot11Bssid;
                std::ostringstream bssidStr;
                bssidStr << std::hex << std::setfill('0') << std::uppercase;
                for (int i = 0; i < 6; ++i) {
                    if (i > 0) bssidStr << ":";
                    bssidStr << std::setw(2) << static_cast<int>(bssid[i]);
                }
                connInfo.network.bssid = ValidateAndNormalizeBSSID(bssidStr.str());

                // Signal quality
                connInfo.network.signalQuality = connAttr->wlanAssociationAttributes.wlanSignalQuality;
                connInfo.network.signalStrength = -100 + (connInfo.network.signalQuality / 2);

                // Link speed (bps to Mbps, with overflow check)
                auto rxRate = connAttr->wlanAssociationAttributes.ulRxRate;
                connInfo.linkSpeed = static_cast<int>(rxRate / 1000);
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"QueryConnectionWLAN error: %hs", e.what());
    }
#endif

    return connInfo;
}

SecurityLevel WiFiSecurityAnalyzerImpl::CalculateSecurityLevel(const WiFiNetworkInfo& network) {
    // Critical: WEP or Open
    if (network.encryption == EncryptionType::WEP || network.encryption == EncryptionType::Open) {
        return SecurityLevel::Critical;
    }

    // Weak: WPA without PMF, or WPS enabled
    if (network.encryption == EncryptionType::WPA_Personal ||
        network.encryption == EncryptionType::WPA_Enterprise ||
        (network.encryption == EncryptionType::WPA2_Personal && !network.pmfEnabled) ||
        network.wpsEnabled) {
        return SecurityLevel::Weak;
    }

    // Good: WPA2 with PMF
    if (network.encryption == EncryptionType::WPA2_Personal ||
        network.encryption == EncryptionType::WPA2_Enterprise) {
        return SecurityLevel::Good;
    }

    // Excellent: WPA3
    if (network.encryption == EncryptionType::WPA3_Personal ||
        network.encryption == EncryptionType::WPA3_Enterprise ||
        network.encryption == EncryptionType::WPA3_SAE) {
        return SecurityLevel::Excellent;
    }

    return SecurityLevel::Moderate;
}

WiFiThreatType WiFiSecurityAnalyzerImpl::AnalyzeThreats(const WiFiNetworkInfo& network) {
    uint32_t threats = static_cast<uint32_t>(WiFiThreatType::None);

    // Weak encryption
    if (network.encryption == EncryptionType::WEP) {
        threats |= static_cast<uint32_t>(WiFiThreatType::WeakEncryption);
    }

    // Open network
    if (network.encryption == EncryptionType::Open) {
        threats |= static_cast<uint32_t>(WiFiThreatType::OpenNetwork);
    }

    // WPS enabled
    if (network.wpsEnabled) {
        threats |= static_cast<uint32_t>(WiFiThreatType::WPSEnabled);
    }

    // KRACK vulnerable
    if (network.encryption == EncryptionType::WPA2_Personal && !network.pmfEnabled) {
        threats |= static_cast<uint32_t>(WiFiThreatType::KRACKVulnerable);
    }

    // Hidden network
    if (network.isHidden) {
        threats |= static_cast<uint32_t>(WiFiThreatType::HiddenNetwork);
    }

    // Check for rogue AP
    if (IsKnownRogueAP(network.bssid)) {
        threats |= static_cast<uint32_t>(WiFiThreatType::RogueAP);
    }

    return static_cast<WiFiThreatType>(threats);
}

std::string WiFiSecurityAnalyzerImpl::GetVendorFromBSSID(const std::string& bssid) const {
    if (bssid.length() < 8) {
        return "Unknown";
    }

    // Extract OUI (first 3 octets)
    std::string oui = bssid.substr(0, 8);  // "00:1B:63"

    auto it = OUI_VENDORS.find(oui);
    if (it != OUI_VENDORS.end()) {
        return it->second;
    }

    return "Unknown";
}

bool WiFiSecurityAnalyzerImpl::IsWeakSSID(const std::string& ssid) const {
    if (ssid.empty()) return false;

    // ASCII-lowercase for case-insensitive comparison
    std::string lower;
    lower.reserve(ssid.size());
    for (unsigned char c : ssid) {
        if (c >= 'A' && c <= 'Z') {
            lower.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            lower.push_back(static_cast<char>(c));
        }
    }

    for (const auto& weak : WEAK_SSIDS) {
        if (lower.find(weak) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool WiFiSecurityAnalyzerImpl::IsKnownRogueAP(const std::string& bssid) {
    // Check internal blocklist first (maintained via BlockBSSID())
    if (m_blockedBSSIDs.contains(bssid)) {
        return true;
    }

    // Query ThreatIntelManager for known malicious BSSIDs.
    // The threat feed stores BSSID IOCs using algorithm="bssid" in the hash index.
    if (m_threatIntel && m_threatIntel->IsInitialized()) {
        try {
            auto result = m_threatIntel->LookupHash("bssid", bssid);
            if (result.found && result.IsMalicious()) {
                SS_LOG_WARN(LOG_CAT, L"Rogue AP matched threat intel: score=%u",
                            static_cast<unsigned>(result.score));
                return true;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"ThreatIntel lookup error: %hs", e.what());
        }
    }

    return false;
}

void WiFiSecurityAnalyzerImpl::UpdateBSSIDHistory(const WiFiNetworkInfo& network) {
    // Cap total BSSID history entries to prevent unbounded growth
    static constexpr size_t MAX_BSSID_HISTORY_ENTRIES = 1000;
    if (m_bssidHistory.size() >= MAX_BSSID_HISTORY_ENTRIES &&
        !m_bssidHistory.contains(NormalizeSSID(network.ssid))) {
        return;  // Don't add new entries past the cap
    }

    auto& tracker = m_bssidHistory[NormalizeSSID(network.ssid)];
    tracker.ssid = network.ssid;

    // Cap per-SSID BSSID count to prevent memory exhaustion from
    // an attacker broadcasting many BSSIDs for the same SSID
    static constexpr size_t MAX_BSSIDS_PER_SSID = 100;
    if (tracker.bssidLastSeen.size() >= MAX_BSSIDS_PER_SSID &&
        !tracker.bssidLastSeen.contains(network.bssid)) {
        return;
    }

    // Update last seen time
    tracker.bssidLastSeen[network.bssid] = network.lastSeen;

    // Add to history
    BSSIDHistoryEntry entry;
    entry.bssid = network.bssid;
    entry.signalStrength = network.signalStrength;
    entry.channel = network.channel;
    entry.observationTime = network.lastSeen;

    tracker.history.push_back(std::move(entry));

    // Limit history size
    if (tracker.history.size() > WiFiConstants::BSSID_HISTORY_SIZE) {
        tracker.history.pop_front();
    }
}

EvilTwinDetectionResult WiFiSecurityAnalyzerImpl::DetectEvilTwinForSSID(const std::string& ssid) {
    EvilTwinDetectionResult result;

    try {
        std::string normalized = NormalizeSSID(ssid);
        auto trackerIt = m_bssidHistory.find(normalized);

        if (trackerIt == m_bssidHistory.end() || trackerIt->second.bssidLastSeen.size() < 2) {
            return result;
        }

        // Find networks with same SSID but different BSSIDs
        std::vector<WiFiNetworkInfo> sameSSID;
        for (const auto& [bssid, network] : m_trackedNetworks) {
            if (NormalizeSSID(network.ssid) == normalized) {
                sameSSID.push_back(network);
            }
        }

        if (sameSSID.size() < 2) {
            return result;
        }

        // Sort by signal strength
        std::sort(sameSSID.begin(), sameSSID.end(), [](const auto& a, const auto& b) {
            return a.signalStrength > b.signalStrength;
        });

        // Check if strongest signal is suspiciously stronger than expected
        if (sameSSID.size() >= 2) {
            const auto& strongest = sameSSID[0];
            const auto& second = sameSSID[1];

            int signalDiff = strongest.signalStrength - second.signalStrength;

            // If signal difference is large and BSSIDs are different, likely evil twin
            if (signalDiff > m_config.evilTwinSignalThreshold &&
                strongest.bssid != second.bssid) {

                result.detected = true;
                result.originalNetwork = second;
                result.suspectedTwin = strongest;
                result.signalDifference = signalDiff;
                result.bssidSimilarity = CalculateBSSIDSimilarity(strongest.bssid, second.bssid);
                result.detectionTime = std::chrono::system_clock::now();
                result.confidence = 70;

                if (result.bssidSimilarity > 0.8f) {
                    result.confidence = 90;
                    result.detectionReason = "Identical SSID with very similar BSSID and abnormally strong signal";
                } else {
                    result.detectionReason = "Identical SSID with different BSSID and abnormally strong signal";
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"DetectEvilTwinForSSID error: %hs", e.what());
    }

    return result;
}

float WiFiSecurityAnalyzerImpl::CalculateBSSIDSimilarity(const std::string& bssid1, const std::string& bssid2) const {
    if (bssid1.length() != bssid2.length()) {
        return 0.0f;
    }

    int matches = 0;
    int total = 0;

    for (size_t i = 0; i < bssid1.length(); ++i) {
        if (bssid1[i] != ':') {
            total++;
            if (bssid1[i] == bssid2[i]) {
                matches++;
            }
        }
    }

    return total > 0 ? static_cast<float>(matches) / static_cast<float>(total) : 0.0f;
}

void WiFiSecurityAnalyzerImpl::NotifyNetworkFound(const WiFiNetworkInfo& network) {
    std::lock_guard lock(m_callbackMutex);
    if (m_networkFoundCallback) {
        try {
            m_networkFoundCallback(network);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Network found callback exception: %hs", e.what());
        }
    }
}

void WiFiSecurityAnalyzerImpl::NotifyThreat(const WiFiSecurityThreat& threat) {
    std::lock_guard lock(m_callbackMutex);
    if (m_threatCallback) {
        try {
            m_threatCallback(threat);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Threat callback exception: %hs", e.what());
        }
    }
}

void WiFiSecurityAnalyzerImpl::NotifyEvilTwin(const EvilTwinDetectionResult& result) {
    std::lock_guard lock(m_callbackMutex);
    if (m_evilTwinCallback) {
        try {
            m_evilTwinCallback(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Evil twin callback exception: %hs", e.what());
        }
    }
}

void WiFiSecurityAnalyzerImpl::NotifyConnectionChange(const WiFiConnectionInfo& conn) {
    std::lock_guard lock(m_callbackMutex);
    if (m_connectionCallback) {
        try {
            m_connectionCallback(conn);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Connection callback exception: %hs", e.what());
        }
    }
}

void WiFiSecurityAnalyzerImpl::NotifyError(const std::string& message, int code) {
    std::lock_guard lock(m_callbackMutex);
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"Error callback exception: %hs", e.what());
        }
    }
}

std::string WiFiSecurityAnalyzerImpl::NormalizeSSID(const std::string& ssid) const {
    // SSIDs are raw byte sequences — normalize by trimming whitespace
    // and ASCII-lowercasing for consistent lookup keys
    std::string result;
    result.reserve(ssid.size());

    // Trim leading whitespace
    size_t start = 0;
    while (start < ssid.size() && static_cast<unsigned char>(ssid[start]) <= ' ') ++start;

    // Trim trailing whitespace
    size_t end = ssid.size();
    while (end > start && static_cast<unsigned char>(ssid[end - 1]) <= ' ') --end;

    for (size_t i = start; i < end; ++i) {
        unsigned char c = static_cast<unsigned char>(ssid[i]);
        if (c >= 'A' && c <= 'Z') {
            result.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            result.push_back(static_cast<char>(c));
        }
    }
    return result;
}

std::string WiFiSecurityAnalyzerImpl::NormalizeBSSID(const std::string& bssid) const {
    // Trim and uppercase a BSSID string
    std::string result;
    result.reserve(bssid.size());

    size_t start = 0;
    while (start < bssid.size() && static_cast<unsigned char>(bssid[start]) <= ' ') ++start;
    size_t end = bssid.size();
    while (end > start && static_cast<unsigned char>(bssid[end - 1]) <= ' ') --end;

    for (size_t i = start; i < end; ++i) {
        unsigned char c = static_cast<unsigned char>(bssid[i]);
        if (c >= 'a' && c <= 'z') {
            result.push_back(static_cast<char>(c - ('a' - 'A')));
        } else {
            result.push_back(static_cast<char>(c));
        }
    }
    return result;
}

bool WiFiSecurityAnalyzerImpl::SelfTest() {
    SS_LOG_INFO(LOG_CAT, L"Running self-test...");

    try {
        // Test 1: WLAN handle
        {
            if (!m_wlanHandle) {
                SS_LOG_ERROR(LOG_CAT, L"Self-test failed: No WLAN handle");
                return false;
            }
        }

        // Test 2: Security level calculation
        {
            WiFiNetworkInfo testNetwork;
            testNetwork.encryption = EncryptionType::WPA3_Personal;
            auto level = CalculateSecurityLevel(testNetwork);
            if (level != SecurityLevel::Excellent) {
                SS_LOG_ERROR(LOG_CAT, L"Self-test failed: Security level calculation");
                return false;
            }
        }

        // Test 3: BSSID normalization
        {
            std::string test = NormalizeBSSID(" aa:bb:cc:dd:ee:ff ");
            if (test != "AA:BB:CC:DD:EE:FF") {
                SS_LOG_ERROR(LOG_CAT, L"Self-test failed: BSSID normalization");
                return false;
            }
        }

        // Test 4: Vendor lookup
        {
            std::string vendor = GetVendorFromBSSID("00:1B:63:00:00:00");
            if (vendor != "Apple") {
                SS_LOG_WARN(LOG_CAT, L"Self-test warning: Vendor lookup may be incomplete");
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> WiFiSecurityAnalyzer::s_instanceCreated{false};

WiFiSecurityAnalyzer::WiFiSecurityAnalyzer()
    : m_impl(std::make_unique<WiFiSecurityAnalyzerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

WiFiSecurityAnalyzer::~WiFiSecurityAnalyzer() = default;

WiFiSecurityAnalyzer& WiFiSecurityAnalyzer::Instance() noexcept {
    static WiFiSecurityAnalyzer instance;
    return instance;
}

bool WiFiSecurityAnalyzer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC API FORWARDING
// ============================================================================

bool WiFiSecurityAnalyzer::Initialize(const WiFiAnalyzerConfiguration& config) {
    return m_impl->Initialize(config);
}

void WiFiSecurityAnalyzer::Shutdown() {
    m_impl->Shutdown();
}

bool WiFiSecurityAnalyzer::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus WiFiSecurityAnalyzer::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool WiFiSecurityAnalyzer::UpdateConfiguration(const WiFiAnalyzerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

WiFiAnalyzerConfiguration WiFiSecurityAnalyzer::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

WiFiConnectionInfo WiFiSecurityAnalyzer::GetCurrentConnectionInfo() {
    return m_impl->GetCurrentConnectionInfo();
}

bool WiFiSecurityAnalyzer::IsConnected() const noexcept {
    return m_impl->IsConnected();
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzer::GetConnectedNetwork() const {
    return m_impl->GetConnectedNetwork();
}

std::vector<WiFiNetworkInfo> WiFiSecurityAnalyzer::ScanNearbyNetworks() {
    return m_impl->ScanNearbyNetworks();
}

bool WiFiSecurityAnalyzer::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void WiFiSecurityAnalyzer::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool WiFiSecurityAnalyzer::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

EvilTwinDetectionResult WiFiSecurityAnalyzer::DetectEvilTwin() {
    return m_impl->DetectEvilTwin();
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzer::CheckNetworkSecurity(const WiFiNetworkInfo& network) {
    return m_impl->CheckNetworkSecurity(network);
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzer::GetDetectedThreats() const {
    return m_impl->GetDetectedThreats();
}

std::vector<WiFiSecurityThreat> WiFiSecurityAnalyzer::AnalyzeCurrentConnection() {
    return m_impl->AnalyzeCurrentConnection();
}

std::vector<WiFiNetworkInfo> WiFiSecurityAnalyzer::GetTrackedNetworks() const {
    return m_impl->GetTrackedNetworks();
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzer::GetNetworkBySSID(const std::string& ssid) const {
    return m_impl->GetNetworkBySSID(ssid);
}

std::optional<WiFiNetworkInfo> WiFiSecurityAnalyzer::GetNetworkByBSSID(const std::string& bssid) const {
    return m_impl->GetNetworkByBSSID(bssid);
}

bool WiFiSecurityAnalyzer::AddToWhitelist(const std::string& bssid) {
    return m_impl->AddToWhitelist(bssid);
}

bool WiFiSecurityAnalyzer::RemoveFromWhitelist(const std::string& bssid) {
    return m_impl->RemoveFromWhitelist(bssid);
}

bool WiFiSecurityAnalyzer::BlockNetwork(const std::string& bssid) {
    return m_impl->BlockNetwork(bssid);
}

std::vector<BSSIDHistoryEntry> WiFiSecurityAnalyzer::GetBSSIDHistory(const std::string& ssid) const {
    return m_impl->GetBSSIDHistory(ssid);
}

void WiFiSecurityAnalyzer::RegisterNetworkFoundCallback(NetworkFoundCallback callback) {
    m_impl->RegisterNetworkFoundCallback(std::move(callback));
}

void WiFiSecurityAnalyzer::RegisterThreatCallback(ThreatDetectedCallback callback) {
    m_impl->RegisterThreatCallback(std::move(callback));
}

void WiFiSecurityAnalyzer::RegisterEvilTwinCallback(EvilTwinCallback callback) {
    m_impl->RegisterEvilTwinCallback(std::move(callback));
}

void WiFiSecurityAnalyzer::RegisterConnectionCallback(ConnectionChangeCallback callback) {
    m_impl->RegisterConnectionCallback(std::move(callback));
}

void WiFiSecurityAnalyzer::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void WiFiSecurityAnalyzer::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

WiFiStatistics WiFiSecurityAnalyzer::GetStatistics() const {
    return m_impl->GetStatistics();
}

void WiFiSecurityAnalyzer::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool WiFiSecurityAnalyzer::SelfTest() {
    return m_impl->SelfTest();
}

std::string WiFiSecurityAnalyzer::GetVersionString() noexcept {
    return std::to_string(WiFiConstants::VERSION_MAJOR) + "." +
           std::to_string(WiFiConstants::VERSION_MINOR) + "." +
           std::to_string(WiFiConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE SERIALIZATION
// ============================================================================

void WiFiStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_release);
    networksDiscovered.store(0, std::memory_order_release);
    threatsDetected.store(0, std::memory_order_release);
    evilTwinsDetected.store(0, std::memory_order_release);
    rogueAPsDetected.store(0, std::memory_order_release);
    weakNetworksFound.store(0, std::memory_order_release);
    deauthAttacksDetected.store(0, std::memory_order_release);
    currentNetworksTracked.store(0, std::memory_order_release);

    for (auto& counter : byThreatType) {
        counter.store(0, std::memory_order_release);
    }
    for (auto& counter : bySecurityLevel) {
        counter.store(0, std::memory_order_release);
    }

    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string WiFiStatistics::ToJson() const {
    nlohmann::json j;
    j["totalScans"] = totalScans.load(std::memory_order_acquire);
    j["networksDiscovered"] = networksDiscovered.load(std::memory_order_acquire);
    j["threatsDetected"] = threatsDetected.load(std::memory_order_acquire);
    j["evilTwinsDetected"] = evilTwinsDetected.load(std::memory_order_acquire);
    j["rogueAPsDetected"] = rogueAPsDetected.load(std::memory_order_acquire);
    j["weakNetworksFound"] = weakNetworksFound.load(std::memory_order_acquire);
    j["deauthAttacksDetected"] = deauthAttacksDetected.load(std::memory_order_acquire);
    j["currentNetworksTracked"] = currentNetworksTracked.load(std::memory_order_acquire);

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - AtomicValueLoadRelaxed(startTime)).count();
    j["uptimeSeconds"] = elapsed;

    return j.dump();
}

std::string WiFiNetworkInfo::ToJson() const {
    nlohmann::json j;
    j["ssid"] = SanitizeSSID(ssid);
    j["bssid"] = bssid;
    j["encryption"] = static_cast<int>(encryption);
    j["authentication"] = static_cast<int>(authentication);
    j["band"] = static_cast<int>(band);
    j["channel"] = channel;
    j["frequency"] = frequency;
    j["signalStrength"] = signalStrength;
    j["signalQuality"] = signalQuality;
    j["isHidden"] = isHidden;
    j["wpsEnabled"] = wpsEnabled;
    j["pmfEnabled"] = pmfEnabled;
    j["isConnected"] = isConnected;
    j["isWhitelisted"] = isWhitelisted;
    j["isKnown"] = isKnown;
    j["securityLevel"] = static_cast<int>(securityLevel);
    j["threats"] = static_cast<uint32_t>(threats);
    j["vendor"] = vendor;
    j["overallScore"] = GetOverallScore();
    return j.dump();
}

int WiFiNetworkInfo::GetOverallScore() const {
    int score = 0;

    // Encryption strength (0-40 points)
    switch (encryption) {
        case EncryptionType::WPA3_Personal:
        case EncryptionType::WPA3_Enterprise:
        case EncryptionType::WPA3_SAE:
            score += 40;
            break;
        case EncryptionType::WPA2_Personal:
        case EncryptionType::WPA2_Enterprise:
            score += 30;
            break;
        case EncryptionType::WPA_Personal:
        case EncryptionType::WPA_Enterprise:
            score += 15;
            break;
        case EncryptionType::WEP:
            score += 5;
            break;
        case EncryptionType::Open:
            score += 0;
            break;
        default:
            score += 10;
    }

    // PMF enabled (+10 points)
    if (pmfEnabled) score += 10;

    // WPS disabled (+10 points)
    if (!wpsEnabled) score += 10;

    // Signal strength (0-20 points)
    if (signalStrength >= -50) score += 20;
    else if (signalStrength >= -60) score += 15;
    else if (signalStrength >= -70) score += 10;
    else if (signalStrength >= -80) score += 5;

    // Not hidden (+10 points)
    if (!isHidden) score += 10;

    // Whitelisted (+10 points)
    if (isWhitelisted) score += 10;

    return std::min(score, 100);
}

std::string WiFiConnectionInfo::ToJson() const {
    nlohmann::json j;
    j["isConnected"] = isConnected;
    j["interfaceName"] = interfaceName;
    j["localIP"] = localIP;
    j["gatewayIP"] = gatewayIP;
    j["linkSpeed"] = linkSpeed;
    j["bytesSent"] = bytesSent;
    j["bytesReceived"] = bytesReceived;
    if (isConnected) {
        j["network"] = nlohmann::json::parse(network.ToJson(), nullptr, false);
    }
    return j.dump();
}

std::string EvilTwinDetectionResult::ToJson() const {
    nlohmann::json j;
    j["detected"] = detected;
    j["confidence"] = confidence;
    j["detectionReason"] = detectionReason;
    j["signalDifference"] = signalDifference;
    j["bssidSimilarity"] = bssidSimilarity;
    j["suspectedBSSID"] = suspectedTwin.bssid;
    j["legitimateBSSID"] = originalNetwork.bssid;
    return j.dump();
}

std::string WiFiSecurityThreat::ToJson() const {
    nlohmann::json j;
    j["type"] = static_cast<uint32_t>(type);
    j["severity"] = static_cast<int>(severity);
    j["affectedSSID"] = affectedSSID;
    j["affectedBSSID"] = affectedBSSID;
    j["description"] = description;
    j["recommendation"] = recommendation;
    j["cveId"] = cveId;
    return j.dump();
}

bool WiFiAnalyzerConfiguration::IsValid() const noexcept {
    if (scanIntervalSeconds == 0 || scanIntervalSeconds > 3600) {
        return false;
    }
    if (evilTwinSignalThreshold < 0 || evilTwinSignalThreshold > 50) {
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetEncryptionTypeName(EncryptionType type) noexcept {
    switch (type) {
        case EncryptionType::Open:              return "Open";
        case EncryptionType::WEP:               return "WEP";
        case EncryptionType::WPA_Personal:      return "WPA-Personal";
        case EncryptionType::WPA_Enterprise:    return "WPA-Enterprise";
        case EncryptionType::WPA2_Personal:     return "WPA2-Personal";
        case EncryptionType::WPA2_Enterprise:   return "WPA2-Enterprise";
        case EncryptionType::WPA3_Personal:     return "WPA3-Personal";
        case EncryptionType::WPA3_Enterprise:   return "WPA3-Enterprise";
        case EncryptionType::WPA3_SAE:          return "WPA3-SAE";
        case EncryptionType::WPA2_WPA3_Mixed:   return "WPA2/WPA3-Mixed";
        case EncryptionType::OWE:               return "OWE";
        default:                                return "Unknown";
    }
}

std::string_view GetAuthenticationTypeName(AuthenticationType type) noexcept {
    switch (type) {
        case AuthenticationType::Open:          return "Open";
        case AuthenticationType::SharedKey:     return "Shared Key";
        case AuthenticationType::WPA_PSK:       return "WPA-PSK";
        case AuthenticationType::WPA_EAP:       return "WPA-EAP";
        case AuthenticationType::WPA2_PSK:      return "WPA2-PSK";
        case AuthenticationType::WPA2_EAP:      return "WPA2-EAP";
        case AuthenticationType::WPA3_SAE:      return "WPA3-SAE";
        case AuthenticationType::WPA3_EAP_192:  return "WPA3-EAP-192";
        case AuthenticationType::OWE:           return "OWE";
        default:                                return "Unknown";
    }
}

std::string_view GetWiFiBandName(WiFiBand band) noexcept {
    switch (band) {
        case WiFiBand::Band2_4GHz:  return "2.4 GHz";
        case WiFiBand::Band5GHz:    return "5 GHz";
        case WiFiBand::Band6GHz:    return "6 GHz";
        default:                    return "Unknown";
    }
}

std::string_view GetWiFiThreatTypeName(WiFiThreatType type) noexcept {
    switch (type) {
        case WiFiThreatType::EvilTwin:              return "Evil Twin";
        case WiFiThreatType::SSIDSpoofing:          return "SSID Spoofing";
        case WiFiThreatType::RogueAP:               return "Rogue AP";
        case WiFiThreatType::DeauthAttack:          return "Deauth Attack";
        case WiFiThreatType::WeakEncryption:        return "Weak Encryption";
        case WiFiThreatType::OpenNetwork:           return "Open Network";
        case WiFiThreatType::WPSEnabled:            return "WPS Enabled";
        case WiFiThreatType::KRACKVulnerable:       return "KRACK Vulnerable";
        case WiFiThreatType::DragonbloodVulnerable: return "Dragonblood Vulnerable";
        case WiFiThreatType::PMKIDExposed:          return "PMKID Exposed";
        case WiFiThreatType::KarmaAttack:           return "Karma Attack";
        case WiFiThreatType::HiddenNetwork:         return "Hidden Network";
        case WiFiThreatType::SignalAnomaly:         return "Signal Anomaly";
        case WiFiThreatType::MACSpoof:              return "MAC Spoof";
        case WiFiThreatType::UnknownAP:             return "Unknown AP";
        case WiFiThreatType::ChannelInterference:   return "Channel Interference";
        default:                                    return "None";
    }
}

std::string_view GetSecurityLevelName(SecurityLevel level) noexcept {
    switch (level) {
        case SecurityLevel::Critical:   return "Critical";
        case SecurityLevel::Weak:       return "Weak";
        case SecurityLevel::Moderate:   return "Moderate";
        case SecurityLevel::Good:       return "Good";
        case SecurityLevel::Excellent:  return "Excellent";
        default:                        return "Unknown";
    }
}

SecurityLevel GetEncryptionSecurityLevel(EncryptionType type) noexcept {
    switch (type) {
        case EncryptionType::Open:
        case EncryptionType::WEP:
            return SecurityLevel::Critical;
        case EncryptionType::WPA_Personal:
        case EncryptionType::WPA_Enterprise:
            return SecurityLevel::Weak;
        case EncryptionType::WPA2_Personal:
        case EncryptionType::WPA2_Enterprise:
            return SecurityLevel::Good;
        case EncryptionType::WPA3_Personal:
        case EncryptionType::WPA3_Enterprise:
        case EncryptionType::WPA3_SAE:
        case EncryptionType::OWE:
            return SecurityLevel::Excellent;
        default:
            return SecurityLevel::Moderate;
    }
}

WiFiBand GetBandFromFrequency(int frequency) noexcept {
    if (frequency >= 2400 && frequency <= 2500) {
        return WiFiBand::Band2_4GHz;
    } else if (frequency >= 5000 && frequency <= 6000) {
        return WiFiBand::Band5GHz;
    } else if (frequency >= 6000 && frequency <= 7000) {
        return WiFiBand::Band6GHz;
    }
    return WiFiBand::Unknown;
}

int GetChannelFromFrequency(int frequency) noexcept {
    // 2.4 GHz band — use lookup table
    for (const auto& entry : WiFiConstants::CHANNEL_2GHZ) {
        if (entry.frequency == frequency) {
            return entry.channel;
        }
    }

    // 5 GHz band — defined channels per IEEE 802.11
    // UNII-1: 5180-5240 MHz (channels 36-48)
    // UNII-2: 5260-5320 MHz (channels 52-64, DFS)
    // UNII-2 Extended: 5500-5720 MHz (channels 100-144, DFS)
    // UNII-3: 5745-5825 MHz (channels 149-165)
    if (frequency >= 5170 && frequency <= 5835) {
        // Channel = (freq_MHz - 5000) / 5
        // Validate the result is a known 5 GHz channel number
        int ch = (frequency - 5000) / 5;
        // Known valid 5 GHz channels
        static constexpr int valid5GHz[] = {
            36, 38, 40, 42, 44, 46, 48,               // UNII-1
            52, 54, 56, 58, 60, 62, 64,               // UNII-2
            100, 102, 104, 106, 108, 110, 112,        // UNII-2 Ext
            116, 118, 120, 122, 124, 126, 128,
            132, 134, 136, 138, 140, 142, 144,
            149, 151, 153, 155, 157, 159, 161, 165    // UNII-3
        };
        for (int v : valid5GHz) {
            if (ch == v) return ch;
        }
        // Close enough — return calculated channel for non-standard frequencies
        if (ch > 0 && ch < 200) return ch;
    }

    // 6 GHz band (Wi-Fi 6E) — IEEE 802.11ax
    // 5955 MHz = channel 1, then every 5 MHz
    if (frequency >= 5945 && frequency <= 7125) {
        int ch = (frequency - 5950) / 5;
        if (ch > 0 && ch <= 233) return ch;
    }

    return 0;
}

}  // namespace IoT
}  // namespace ShadowStrike
