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

#include "pch.h"
#include "TelemetryCollector.hpp"

#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

#include <algorithm>
#include <deque>
#include <thread>
#include <condition_variable>
#include <regex>
#include <cstdio>
#include <ctime>
#include <sddl.h>
#include <shlobj.h>

namespace ShadowStrike {
namespace Communication {

using Utils::StringUtils::ToWide;
using Utils::StringUtils::ToNarrow;

// ============================================================================
// HELPERS
// ============================================================================

static std::string GenerateEventId() {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "EVT-%llX-%04llX",
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static std::string GenerateBatchId() {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "BAT-%llX-%04llX",
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
                    out += hex;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string SystemTimeToIso8601(SystemTimePoint tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf{};
    gmtime_s(&tmBuf, &tt);
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday,
                  tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);
    return buf;
}

static uint64_t NowEpochMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// ============================================================================
// PII SCRUBBING
// ============================================================================

// Pre-compiled regex patterns for PII detection
static const std::regex& GetEmailRegex() {
    static const std::regex re(R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
                               std::regex::optimize);
    return re;
}

static const std::regex& GetIpv4Regex() {
    static const std::regex re(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
                               std::regex::optimize);
    return re;
}

static const std::regex& GetWindowsPathRegex() {
    static const std::regex re(R"(C:\\Users\\[^\\]+)",
                               std::regex::optimize | std::regex::icase);
    return re;
}

static const std::regex& GetSidRegex() {
    static const std::regex re(R"(S-\d+-\d+-(\d+-){1,14}\d+)",
                               std::regex::optimize);
    return re;
}

std::string ScrubPII(const std::string& data) {
    std::string result = data;

    // Remove email addresses
    result = std::regex_replace(result, GetEmailRegex(), "[EMAIL_REDACTED]");

    // Anonymize IPv4 — keep first two octets for regional analysis
    // std::regex_replace doesn't accept lambda callbacks, use regex_iterator
    {
        std::string ipResult;
        ipResult.reserve(result.size());
        const auto& ipRe = GetIpv4Regex();
        auto itBegin = std::sregex_iterator(result.begin(), result.end(), ipRe);
        auto itEnd = std::sregex_iterator();
        size_t lastPos = 0;
        for (auto it = itBegin; it != itEnd; ++it) {
            const std::smatch& m = *it;
            ipResult.append(result, lastPos, static_cast<size_t>(m.position()) - lastPos);
            const std::string ip = m.str();
            auto dot1 = ip.find('.');
            auto dot2 = (dot1 != std::string::npos) ? ip.find('.', dot1 + 1) : std::string::npos;
            if (dot1 != std::string::npos && dot2 != std::string::npos) {
                ipResult.append(ip, 0, dot2);
                ipResult.append(".x.x");
            } else {
                ipResult.append("[IP_REDACTED]");
            }
            lastPos = static_cast<size_t>(m.position()) + m.length();
        }
        ipResult.append(result, lastPos, result.size() - lastPos);
        result = std::move(ipResult);
    }

    // Normalize user profile paths
    result = std::regex_replace(result, GetWindowsPathRegex(), "C:\\Users\\[USER]");

    // Remove Windows SIDs
    result = std::regex_replace(result, GetSidRegex(), "[SID_REDACTED]");

    return result;
}

std::string HashSensitiveData(const std::string& data) {
    Utils::CryptoUtils::Hasher hasher(Utils::CryptoUtils::Algorithm::SHA256);
    Utils::CryptoUtils::Error err;
    if (!hasher.Init(&err)) return "[HASH_ERROR]";
    if (!hasher.Update(data.data(), data.size(), &err)) return "[HASH_ERROR]";
    std::string hex;
    if (!hasher.FinalHex(hex, false, &err)) return "[HASH_ERROR]";
    return hex;
}

std::string GenerateAnonymousMachineId() {
    // Combine hardware-stable identifiers and hash them
    // MachineGuid from registry + volume serial → SHA256 → hex
    std::string composite;

    // Read MachineGuid (stable across reinstalls on same hardware)
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t guid[128]{};
        DWORD guidSize = sizeof(guid);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                             reinterpret_cast<LPBYTE>(guid), &guidSize) == ERROR_SUCCESS &&
            type == REG_SZ) {
            composite += ToNarrow(std::wstring_view(guid, guidSize / sizeof(wchar_t)));
        }
        RegCloseKey(hKey);
    }

    // Volume serial number of system drive
    DWORD volumeSerial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &volumeSerial,
                               nullptr, nullptr, nullptr, 0)) {
        char vBuf[32]{};
        std::snprintf(vBuf, sizeof(vBuf), "VOL-%08lX", volumeSerial);
        composite += vBuf;
    }

    // Add a salt to prevent rainbow table attacks
    composite += "ShadowStrike-Telemetry-Salt-2026";

    return HashSensitiveData(composite);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class TelemetryCollectorImpl {
public:
    TelemetryCollectorImpl() = default;
    ~TelemetryCollectorImpl() { Shutdown(); }

    // Lifecycle
    bool Initialize(const TelemetryConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    TelemetryModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const TelemetryConfiguration& config);
    TelemetryConfiguration GetConfiguration() const;

    // Event recording
    void RecordEventSimple(const std::string& type, const std::string& data);
    void RecordEventFull(const TelemetryEvent& event);
    void RecordDetection(const DetectionEventData& detection);
    void RecordHealth(const HealthEventData& health);
    void RecordPerformance(const PerformanceEventData& perf);
    void RecordCrash(const CrashEventData& crash);
    void RecordCustom(const std::string& subtype, const std::map<std::string, std::string>& data);

    // Submission
    void Flush();
    void FlushAsync();
    bool SubmitImmediate(const TelemetryEvent& event);
    size_t GetQueueSize() const noexcept;
    bool IsSubmitting() const noexcept;

    // Consent
    void SetConsentLevel(ConsentLevel level);
    ConsentLevel GetConsentLevel() const noexcept;
    bool IsConsented() const noexcept;
    bool RequestConsent(ConsentLevel requestedLevel);

    // Anonymization
    std::string Anonymize(const std::string& data, AnonymizationLevel level);
    std::string AnonymizePath(const fs::path& path);
    void SetAnonymizationLevel(AnonymizationLevel level);
    std::string GetAnonymousMachineId() const;

    // History
    std::vector<TelemetryEvent> GetPendingEvents(size_t limit);
    std::vector<TelemetryBatch> GetRecentBatches(size_t limit);
    void ClearQueue();
    void OptOut();

    // Callbacks
    void RegisterEventCallback(EventCallback cb);
    void RegisterBatchCallback(BatchCallback cb);
    void RegisterConsentCallback(ConsentCallback cb);
    void RegisterErrorCallback(TelemetryErrorCallback cb);
    void UnregisterCallbacks();

    // Statistics
    TelemetryStatisticsSnapshot GetStatistics() const noexcept;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal
    void FlushLoop();
    void HealthCollectorLoop();
    TelemetryBatch BuildBatch(std::vector<TelemetryEvent>& events);
    bool SubmitBatch(TelemetryBatch& batch);
    void EnqueueEvent(TelemetryEvent event);
    void AnonymizeEvent(TelemetryEvent& event);
    bool IsEventAllowedByConsent(TelemetryEventType type) const;
    void PersistOfflineQueue();
    void LoadOfflineQueue();
    void NotifyEventCb(const TelemetryEvent& event);
    void NotifyBatchCb(const TelemetryBatch& batch);
    void NotifyError(const std::string& msg, int code);

    // Config
    TelemetryConfiguration m_config;
    mutable std::shared_mutex m_configMutex;

    // State
    std::atomic<TelemetryModuleStatus> m_status{TelemetryModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_submitting{false};

    // Consent
    std::atomic<ConsentLevel> m_consentLevel{ConsentLevel::None};

    // Event queue
    std::deque<TelemetryEvent> m_eventQueue;
    mutable std::shared_mutex m_queueMutex;
    std::condition_variable_any m_queueCv;

    // Batch history
    std::deque<TelemetryBatch> m_batchHistory;
    mutable std::shared_mutex m_batchMutex;
    static constexpr size_t MAX_BATCH_HISTORY = 50;

    // Threads
    std::thread m_flushThread;
    std::thread m_healthThread;
    std::mutex m_flushStopMutex;
    std::condition_variable m_flushStopCv;
    std::mutex m_healthStopMutex;
    std::condition_variable m_healthStopCv;

    // Machine ID (computed once)
    std::string m_machineId;
    std::once_flag m_machineIdOnce;

    // Offline queue path
    fs::path m_offlineQueuePath;

    // Callbacks
    EventCallback m_eventCb;
    BatchCallback m_batchCb;
    ConsentCallback m_consentCb;
    TelemetryErrorCallback m_errorCb;
    mutable std::mutex m_callbackMutex;

    // Statistics
    TelemetryStatistics m_stats;
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool TelemetryCollectorImpl::Initialize(const TelemetryConfiguration& config) {
    TelemetryModuleStatus expected = TelemetryModuleStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, TelemetryModuleStatus::Initializing,
                                          std::memory_order_acq_rel)) {
        SS_LOG_WARN("Telemetry", "Already initialized (status={})",
                    static_cast<int>(expected));
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR("Telemetry", "Invalid configuration");
        m_status.store(TelemetryModuleStatus::Error, std::memory_order_release);
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    m_consentLevel.store(config.consentLevel, std::memory_order_release);
    m_stats.Reset();

    // Offline queue directory
    wchar_t appData[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, appData) == S_OK ||
        GetEnvironmentVariableW(L"ProgramData", appData, MAX_PATH) > 0) {
        m_offlineQueuePath = fs::path(appData) / L"ShadowStrike" / L"telemetry_queue.json";
        Utils::FileUtils::Error fsErr;
        Utils::FileUtils::CreateDirectories(
            m_offlineQueuePath.parent_path().wstring(), &fsErr);
    }

    // Load any persisted offline events
    LoadOfflineQueue();

    m_running.store(true, std::memory_order_release);
    m_flushThread = std::thread([this] { FlushLoop(); });

    if (config.includeHealth) {
        m_healthThread = std::thread([this] { HealthCollectorLoop(); });
    }

    m_initialized.store(true, std::memory_order_release);
    m_status.store(TelemetryModuleStatus::Running, std::memory_order_release);

    SS_LOG_INFO("Telemetry", "Initialized — consent={}, anon={}, batch={}, flush={}h, endpoint={}",
                std::string(GetConsentLevelName(config.consentLevel)),
                std::string(GetAnonymizationLevelName(config.anonymizationLevel)),
                config.batchSize, config.flushIntervalHours,
                config.endpoint);
    return true;
}

void TelemetryCollectorImpl::Shutdown() {
    if (!m_running.exchange(false, std::memory_order_acq_rel))
        return;

    m_status.store(TelemetryModuleStatus::Stopping, std::memory_order_release);

    // Wake flush thread
    {
        std::unique_lock lock(m_flushStopMutex);
        m_flushStopCv.notify_all();
    }

    // Wake health thread
    {
        std::unique_lock lock(m_healthStopMutex);
        m_healthStopCv.notify_all();
    }

    if (m_flushThread.joinable())
        m_flushThread.join();
    if (m_healthThread.joinable())
        m_healthThread.join();

    // Persist remaining events to disk for offline submission on next launch
    PersistOfflineQueue();

    m_status.store(TelemetryModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO("Telemetry", "Shutdown complete — {} events persisted to offline queue",
                m_eventQueue.size());
}

bool TelemetryCollectorImpl::UpdateConfiguration(const TelemetryConfiguration& config) {
    if (!m_initialized.load(std::memory_order_acquire)) return false;
    if (!config.IsValid()) {
        SS_LOG_WARN("Telemetry", "Rejected invalid configuration update");
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    m_consentLevel.store(config.consentLevel, std::memory_order_release);
    SS_LOG_INFO("Telemetry", "Configuration updated — consent={}, batch={}",
                std::string(GetConsentLevelName(config.consentLevel)),
                config.batchSize);
    return true;
}

TelemetryConfiguration TelemetryCollectorImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// FLUSH THREAD
// ============================================================================

void TelemetryCollectorImpl::FlushLoop() {
    SS_LOG_DEBUG("Telemetry", "Flush thread started");

    while (m_running.load(std::memory_order_acquire)) {
        uint32_t intervalHours = 0;
        {
            std::shared_lock lock(m_configMutex);
            intervalHours = m_config.flushIntervalHours;
        }
        if (intervalHours == 0) intervalHours = 24;

        {
            std::unique_lock lock(m_flushStopMutex);
            m_flushStopCv.wait_for(lock, std::chrono::hours(intervalHours), [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }

        if (!m_running.load(std::memory_order_acquire))
            break;

        Flush();
    }

    SS_LOG_DEBUG("Telemetry", "Flush thread stopped");
}

// ============================================================================
// HEALTH COLLECTOR THREAD
// ============================================================================

void TelemetryCollectorImpl::HealthCollectorLoop() {
    SS_LOG_DEBUG("Telemetry", "Health collector started");

    while (m_running.load(std::memory_order_acquire)) {
        {
            std::unique_lock lock(m_healthStopMutex);
            m_healthStopCv.wait_for(lock, std::chrono::minutes(5), [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }

        if (!m_running.load(std::memory_order_acquire))
            break;

        bool includeHealth = false;
        {
            std::shared_lock lock(m_configMutex);
            includeHealth = m_config.includeHealth;
        }

        if (!includeHealth) continue;

        // Collect health metrics
        HealthEventData health;

        // CPU usage via performance counter
        FILETIME idleTime{}, kernelTime{}, userTime{};
        if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            static FILETIME prevIdle{}, prevKernel{}, prevUser{};
            static bool s_hasPrev = false;
            const auto toULL = [](FILETIME ft) -> uint64_t {
                return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            };
            if (s_hasPrev) {
                const uint64_t idle = toULL(idleTime) - toULL(prevIdle);
                const uint64_t kernel = toULL(kernelTime) - toULL(prevKernel);
                const uint64_t user = toULL(userTime) - toULL(prevUser);
                const uint64_t total = kernel + user;
                if (total > 0) {
                    health.cpuUsage = 100.0 * (1.0 - static_cast<double>(idle) / static_cast<double>(total));
                    if (health.cpuUsage < 0.0) health.cpuUsage = 0.0;
                    if (health.cpuUsage > 100.0) health.cpuUsage = 100.0;
                }
            }
            prevIdle = idleTime;
            prevKernel = kernelTime;
            prevUser = userTime;
            s_hasPrev = true;
        }

        // Memory usage
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(GetCurrentProcess(),
                                  reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                                  sizeof(pmc))) {
            health.memoryUsageMB = pmc.WorkingSetSize / (1024 * 1024);
        }

        // Uptime
        health.uptimeSeconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - m_stats.startTime).count());

        RecordHealth(health);
    }

    SS_LOG_DEBUG("Telemetry", "Health collector stopped");
}

// ============================================================================
// EVENT RECORDING
// ============================================================================

void TelemetryCollectorImpl::EnqueueEvent(TelemetryEvent event) {
    if (event.eventId.empty())
        event.eventId = GenerateEventId();
    if (event.timestamp == 0)
        event.timestamp = NowEpochMs();
    if (event.systemTime == SystemTimePoint{})
        event.systemTime = std::chrono::system_clock::now();

    // Machine ID
    std::call_once(m_machineIdOnce, [this] {
        m_machineId = GenerateAnonymousMachineId();
    });
    event.machineId = m_machineId;

    // Product version
    event.productVersion = "3.0.0";

    // OS version
    if (event.osVersion.empty()) {
        static std::string s_osVersion = [] {
            OSVERSIONINFOEXW osvi{};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            // RtlGetVersion doesn't lie about version
            using RtlGetVersionFn = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW);
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll) {
                auto pRtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
                    GetProcAddress(ntdll, "RtlGetVersion"));
                if (pRtlGetVersion) {
                    pRtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osvi));
                }
            }
            char buf[64]{};
            std::snprintf(buf, sizeof(buf), "Windows %lu.%lu.%lu",
                          osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            return std::string(buf);
        }();
        event.osVersion = s_osVersion;
    }

    // Consent check
    if (!IsEventAllowedByConsent(event.eventType)) {
        m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Anonymize
    AnonymizeEvent(event);

    // Enqueue — read config BEFORE acquiring queue lock to prevent deadlock
    // (Flush acquires configMutex then queueMutex, so we must not do the reverse)
    size_t maxQueue = 0;
    {
        std::shared_lock cLock(m_configMutex);
        maxQueue = m_config.maxQueueSize;
    }
    {
        std::unique_lock lock(m_queueMutex);
        if (m_eventQueue.size() >= maxQueue) {
            m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_DEBUG("Telemetry", "Queue full ({}) — dropping event {}",
                         m_eventQueue.size(), event.eventId);
            return;
        }
        m_eventQueue.push_back(std::move(event));
        m_queueCv.notify_one();
    }

    m_stats.eventsRecorded.fetch_add(1, std::memory_order_relaxed);
}

void TelemetryCollectorImpl::RecordEventSimple(const std::string& type, const std::string& data) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Custom;
    event.subtype = type;
    event.payloadJson = data;
    EnqueueEvent(std::move(event));
}

void TelemetryCollectorImpl::RecordEventFull(const TelemetryEvent& event) {
    EnqueueEvent(event);
}

void TelemetryCollectorImpl::RecordDetection(const DetectionEventData& detection) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Detection;
    event.subtype = "detection";
    event.payloadJson = detection.ToJson();

    const auto idx = static_cast<size_t>(TelemetryEventType::Detection);
    if (idx < m_stats.byEventType.size())
        m_stats.byEventType[idx].fetch_add(1, std::memory_order_relaxed);

    EnqueueEvent(std::move(event));
}

void TelemetryCollectorImpl::RecordHealth(const HealthEventData& health) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Health;
    event.subtype = "health";
    event.payloadJson = health.ToJson();

    const auto idx = static_cast<size_t>(TelemetryEventType::Health);
    if (idx < m_stats.byEventType.size())
        m_stats.byEventType[idx].fetch_add(1, std::memory_order_relaxed);

    EnqueueEvent(std::move(event));
}

void TelemetryCollectorImpl::RecordPerformance(const PerformanceEventData& perf) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Performance;
    event.subtype = "performance";
    event.payloadJson = perf.ToJson();

    const auto idx = static_cast<size_t>(TelemetryEventType::Performance);
    if (idx < m_stats.byEventType.size())
        m_stats.byEventType[idx].fetch_add(1, std::memory_order_relaxed);

    EnqueueEvent(std::move(event));
}

void TelemetryCollectorImpl::RecordCrash(const CrashEventData& crash) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Crash;
    event.subtype = "crash";
    event.payloadJson = crash.ToJson();

    const auto idx = static_cast<size_t>(TelemetryEventType::Crash);
    if (idx < m_stats.byEventType.size())
        m_stats.byEventType[idx].fetch_add(1, std::memory_order_relaxed);

    EnqueueEvent(std::move(event));
}

void TelemetryCollectorImpl::RecordCustom(const std::string& subtype,
                                           const std::map<std::string, std::string>& data) {
    TelemetryEvent event;
    event.eventType = TelemetryEventType::Custom;
    event.subtype = subtype;

    std::string json = "{";
    bool first = true;
    for (const auto& [k, v] : data) {
        if (!first) json += ",";
        json += "\"" + JsonEscape(k) + "\":\"" + JsonEscape(v) + "\"";
        first = false;
    }
    json += "}";
    event.payloadJson = json;

    const auto idx = static_cast<size_t>(TelemetryEventType::Custom);
    if (idx < m_stats.byEventType.size())
        m_stats.byEventType[idx].fetch_add(1, std::memory_order_relaxed);

    EnqueueEvent(std::move(event));
}

// ============================================================================
// ANONYMIZATION
// ============================================================================

void TelemetryCollectorImpl::AnonymizeEvent(TelemetryEvent& event) {
    AnonymizationLevel level;
    {
        std::shared_lock lock(m_configMutex);
        level = m_config.anonymizationLevel;
    }

    if (level == AnonymizationLevel::None) return;

    const auto start = Clock::now();

    // Scrub payload JSON
    if (!event.payloadJson.empty()) {
        event.payloadJson = ScrubPII(event.payloadJson);
    }

    if (level >= AnonymizationLevel::Standard) {
        // Hash the machine ID (already hashed from GenerateAnonymousMachineId,
        // but truncate for minimization)
        if (event.machineId.length() > 16) {
            event.machineId = event.machineId.substr(0, 16);
        }
    }

    if (level >= AnonymizationLevel::Strict) {
        // Remove subtype detail, just keep event type
        event.subtype.clear();
    }

    event.isAnonymized = true;
    event.anonymizationLevel = level;

    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - start).count();
    m_stats.anonymizationTime.fetch_add(static_cast<uint64_t>(elapsed),
                                         std::memory_order_relaxed);
}

std::string TelemetryCollectorImpl::Anonymize(const std::string& data,
                                               AnonymizationLevel level) {
    if (level == AnonymizationLevel::None) return data;

    std::string result = ScrubPII(data);

    if (level >= AnonymizationLevel::Strict) {
        result = HashSensitiveData(result);
    }

    return result;
}

std::string TelemetryCollectorImpl::AnonymizePath(const fs::path& path) {
    std::string pathStr = ToNarrow(path.wstring());
    return std::regex_replace(pathStr, GetWindowsPathRegex(), "C:\\Users\\[USER]");
}

void TelemetryCollectorImpl::SetAnonymizationLevel(AnonymizationLevel level) {
    std::unique_lock lock(m_configMutex);
    m_config.anonymizationLevel = level;
}

std::string TelemetryCollectorImpl::GetAnonymousMachineId() const {
    // Thread-safe lazy initialization via call_once in EnqueueEvent
    // For direct access, generate fresh if not yet computed
    if (m_machineId.empty()) {
        return GenerateAnonymousMachineId();
    }
    return m_machineId;
}

// ============================================================================
// CONSENT
// ============================================================================

bool TelemetryCollectorImpl::IsEventAllowedByConsent(TelemetryEventType type) const {
    const auto consent = m_consentLevel.load(std::memory_order_acquire);

    if (consent == ConsentLevel::None) return false;

    if (consent == ConsentLevel::Required) {
        // Only crash reports and critical errors
        return type == TelemetryEventType::Crash ||
               type == TelemetryEventType::Error;
    }

    if (consent == ConsentLevel::Basic) {
        // Detection, scan, update, health, crash, error — no performance or custom
        return type != TelemetryEventType::Performance &&
               type != TelemetryEventType::Custom &&
               type != TelemetryEventType::Feedback;
    }

    // Full consent — everything
    return true;
}

void TelemetryCollectorImpl::SetConsentLevel(ConsentLevel level) {
    const auto old = m_consentLevel.exchange(level, std::memory_order_acq_rel);
    {
        std::unique_lock lock(m_configMutex);
        m_config.consentLevel = level;
    }

    if (old != level) {
        SS_LOG_INFO("Telemetry", "Consent level changed: {} -> {}",
                    std::string(GetConsentLevelName(old)),
                    std::string(GetConsentLevelName(level)));
    }

    // If opted out, clear queue
    if (level == ConsentLevel::None) {
        ClearQueue();
    }
}

ConsentLevel TelemetryCollectorImpl::GetConsentLevel() const noexcept {
    return m_consentLevel.load(std::memory_order_acquire);
}

bool TelemetryCollectorImpl::IsConsented() const noexcept {
    return m_consentLevel.load(std::memory_order_acquire) != ConsentLevel::None;
}

bool TelemetryCollectorImpl::RequestConsent(ConsentLevel requestedLevel) {
    ConsentCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_consentCb;
    }
    if (!cb) {
        SS_LOG_WARN("Telemetry", "No consent callback registered");
        return false;
    }

    bool granted = false;
    try {
        granted = cb(requestedLevel);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR("Telemetry", "Consent callback threw: {}", ex.what());
        return false;
    }

    if (granted) {
        SetConsentLevel(requestedLevel);
    }

    return granted;
}

// ============================================================================
// SUBMISSION
// ============================================================================

void TelemetryCollectorImpl::Flush() {
    if (!m_initialized.load(std::memory_order_acquire)) return;
    if (!IsConsented()) return;

    bool expected = false;
    if (!m_submitting.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;  // Already flushing

    m_status.store(TelemetryModuleStatus::Submitting, std::memory_order_release);

    size_t batchSize = 0;
    {
        std::shared_lock lock(m_configMutex);
        batchSize = m_config.batchSize;
    }
    if (batchSize == 0) batchSize = TelemetryConstants::DEFAULT_BATCH_SIZE;

    size_t totalSubmitted = 0;
    size_t totalFailed = 0;

    while (m_running.load(std::memory_order_acquire)) {
        std::vector<TelemetryEvent> batchEvents;
        {
            std::unique_lock lock(m_queueMutex);
            if (m_eventQueue.empty()) break;

            const size_t count = std::min(batchSize, m_eventQueue.size());
            batchEvents.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                batchEvents.push_back(std::move(m_eventQueue.front()));
                m_eventQueue.pop_front();
            }
        }

        if (batchEvents.empty()) break;

        auto batch = BuildBatch(batchEvents);
        if (SubmitBatch(batch)) {
            totalSubmitted += batch.events.size();
            m_stats.batchesSubmitted.fetch_add(1, std::memory_order_relaxed);
            m_stats.eventsSubmitted.fetch_add(
                static_cast<uint64_t>(batch.events.size()), std::memory_order_relaxed);

            NotifyBatchCb(batch);
        } else {
            totalFailed += batch.events.size();
            m_stats.batchesFailed.fetch_add(1, std::memory_order_relaxed);
            m_stats.eventsFailed.fetch_add(
                static_cast<uint64_t>(batch.events.size()), std::memory_order_relaxed);

            // Re-queue failed events for retry
            {
                std::unique_lock lock(m_queueMutex);
                for (auto& evt : batch.events) {
                    if (evt.retryCount < TelemetryConstants::MAX_RETRY_ATTEMPTS) {
                        evt.retryCount++;
                        evt.status = SubmissionStatus::Retrying;
                        m_eventQueue.push_back(std::move(evt));
                        m_stats.retryAttempts.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        evt.status = SubmissionStatus::Failed;
                        m_stats.eventsFailed.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        }

        // Record batch in history
        {
            std::unique_lock lock(m_batchMutex);
            m_batchHistory.push_back(std::move(batch));
            while (m_batchHistory.size() > MAX_BATCH_HISTORY)
                m_batchHistory.pop_front();
        }
    }

    m_submitting.store(false, std::memory_order_release);
    if (m_running.load(std::memory_order_acquire))
        m_status.store(TelemetryModuleStatus::Running, std::memory_order_release);

    SS_LOG_INFO("Telemetry", "Flush complete — submitted={}, failed={}",
                totalSubmitted, totalFailed);
}

void TelemetryCollectorImpl::FlushAsync() {
    // Signal the flush thread to wake up
    std::unique_lock lock(m_flushStopMutex);
    m_flushStopCv.notify_one();
}

bool TelemetryCollectorImpl::SubmitImmediate(const TelemetryEvent& event) {
    if (!IsConsented()) return false;

    TelemetryEvent copy = event;
    if (copy.eventId.empty())
        copy.eventId = GenerateEventId();
    AnonymizeEvent(copy);

    std::vector<TelemetryEvent> single;
    single.push_back(std::move(copy));
    auto batch = BuildBatch(single);
    return SubmitBatch(batch);
}

TelemetryBatch TelemetryCollectorImpl::BuildBatch(std::vector<TelemetryEvent>& events) {
    TelemetryBatch batch;
    batch.batchId = GenerateBatchId();
    batch.createdTime = std::chrono::system_clock::now();
    batch.status = SubmissionStatus::Pending;

    size_t totalSize = 0;
    for (auto& evt : events) {
        totalSize += evt.payloadJson.size() + evt.eventId.size() + 128;
        evt.status = SubmissionStatus::InProgress;
    }
    batch.events = std::move(events);
    batch.totalSize = totalSize;

    return batch;
}

bool TelemetryCollectorImpl::SubmitBatch(TelemetryBatch& batch) {
    std::string endpoint;
    std::string apiKey;
    {
        std::shared_lock lock(m_configMutex);
        endpoint = m_config.endpoint;
        apiKey = m_config.apiKey;
    }

    if (endpoint.empty()) {
        SS_LOG_DEBUG("Telemetry", "No endpoint configured — batch {} skipped", batch.batchId);
        batch.status = SubmissionStatus::Submitted;
        batch.submittedTime = std::chrono::system_clock::now();
        for (auto& evt : batch.events)
            evt.status = SubmissionStatus::Submitted;
        return true;
    }

    // Build JSON payload
    std::string payload = "{\"batchId\":\"" + JsonEscape(batch.batchId) + "\",";
    payload += "\"timestamp\":\"" + SystemTimeToIso8601(batch.createdTime) + "\",";
    payload += "\"events\":[";
    for (size_t i = 0; i < batch.events.size(); ++i) {
        if (i > 0) payload += ",";
        payload += batch.events[i].ToJson();
    }
    payload += "]}";

    // Submit via HTTP POST
    std::vector<uint8_t> postData(payload.begin(), payload.end());
    std::vector<uint8_t> response;

    Utils::NetworkUtils::HttpRequestOptions opts;
    opts.method = L"POST";
    opts.contentType = L"application/json";
    opts.timeoutMs = 30000;
    if (!apiKey.empty()) {
        opts.headers.push_back({L"Authorization", ToWide("Bearer " + apiKey)});
    }
    opts.headers.push_back({L"X-ShadowStrike-Version", L"3.0.0"});

    Utils::NetworkUtils::Error netErr;
    bool ok = Utils::NetworkUtils::HttpPost(
        ToWide(endpoint), postData, response, opts, &netErr);

    if (ok) {
        batch.status = SubmissionStatus::Submitted;
        batch.submittedTime = std::chrono::system_clock::now();
        m_stats.bytesSubmitted.fetch_add(
            static_cast<uint64_t>(postData.size()), std::memory_order_relaxed);

        for (auto& evt : batch.events)
            evt.status = SubmissionStatus::Submitted;

        SS_LOG_DEBUG("Telemetry", "Batch {} submitted ({} events, {} bytes)",
                     batch.batchId, batch.events.size(), postData.size());
    } else {
        batch.status = SubmissionStatus::Failed;
        SS_LOG_WARN("Telemetry", "Batch {} submission failed: {}",
                    batch.batchId, ToNarrow(netErr.message));
        NotifyError("Batch submission failed: " + ToNarrow(netErr.message), netErr.win32);
    }

    return ok;
}

size_t TelemetryCollectorImpl::GetQueueSize() const noexcept {
    std::shared_lock lock(m_queueMutex);
    return m_eventQueue.size();
}

bool TelemetryCollectorImpl::IsSubmitting() const noexcept {
    return m_submitting.load(std::memory_order_acquire);
}

// ============================================================================
// OFFLINE QUEUE PERSISTENCE
// ============================================================================

void TelemetryCollectorImpl::PersistOfflineQueue() {
    bool offlineEnabled = false;
    {
        std::shared_lock lock(m_configMutex);
        offlineEnabled = m_config.enableOfflineQueue;
    }
    if (!offlineEnabled || m_offlineQueuePath.empty()) return;

    std::shared_lock lock(m_queueMutex);
    if (m_eventQueue.empty()) return;

    // Cap persisted events to prevent disk bloat
    constexpr size_t MAX_PERSIST = 500;
    const size_t count = std::min(m_eventQueue.size(), MAX_PERSIST);

    std::string json = "[";
    for (size_t i = 0; i < count; ++i) {
        if (i > 0) json += ",";
        json += m_eventQueue[i].ToJson();
    }
    json += "]";

    Utils::FileUtils::Error fsErr;
    if (!Utils::FileUtils::WriteAllTextUtf8Atomic(
            m_offlineQueuePath.wstring(), json, &fsErr)) {
        SS_LOG_WARN("Telemetry", "Failed to persist offline queue: {}",
                    ToNarrow(fsErr.message));
    } else {
        SS_LOG_DEBUG("Telemetry", "Persisted {} events to offline queue", count);
    }
}

void TelemetryCollectorImpl::LoadOfflineQueue() {
    bool offlineEnabled = false;
    {
        std::shared_lock lock(m_configMutex);
        offlineEnabled = m_config.enableOfflineQueue;
    }
    if (!offlineEnabled || m_offlineQueuePath.empty()) return;

    if (!fs::exists(m_offlineQueuePath)) return;

    std::string content;
    Utils::FileUtils::Error fsErr;
    if (!Utils::FileUtils::ReadAllTextUtf8(m_offlineQueuePath.wstring(), content, &fsErr)) {
        SS_LOG_WARN("Telemetry", "Failed to load offline queue: {}",
                    ToNarrow(fsErr.message));
        return;
    }

    // Delete the file after reading to prevent duplicate processing
    Utils::FileUtils::RemoveFile(m_offlineQueuePath.wstring(), &fsErr);

    if (content.empty() || content[0] != '[') return;

    // Lightweight JSON array parsing — track string context to handle braces in values
    size_t restored = 0;
    size_t depth = 0;
    size_t objStart = std::string::npos;
    bool inString = false;

    for (size_t i = 0; i < content.size(); ++i) {
        const char c = content[i];

        // Handle escape sequences inside strings
        if (inString) {
            if (c == '\\') {
                ++i;  // Skip escaped character
                continue;
            }
            if (c == '"') {
                inString = false;
            }
            continue;
        }

        // Outside of strings
        if (c == '"') {
            inString = true;
        } else if (c == '{') {
            if (depth == 0) objStart = i;
            depth++;
        } else if (c == '}') {
            if (depth > 0) depth--;
            if (depth == 0 && objStart != std::string::npos) {
                // Found a complete event object — re-enqueue as raw JSON event
                TelemetryEvent event;
                event.eventId = GenerateEventId();
                event.eventType = TelemetryEventType::Custom;
                event.subtype = "restored_offline";
                event.payloadJson = content.substr(objStart, i - objStart + 1);
                event.timestamp = NowEpochMs();
                event.systemTime = std::chrono::system_clock::now();
                event.status = SubmissionStatus::Pending;

                std::unique_lock lock(m_queueMutex);
                m_eventQueue.push_back(std::move(event));
                restored++;
                objStart = std::string::npos;
            }
        }
    }

    if (restored > 0) {
        SS_LOG_INFO("Telemetry", "Restored {} events from offline queue", restored);
    }
}

// ============================================================================
// HISTORY QUERIES
// ============================================================================

std::vector<TelemetryEvent> TelemetryCollectorImpl::GetPendingEvents(size_t limit) {
    if (limit == 0) limit = 100;

    std::shared_lock lock(m_queueMutex);
    std::vector<TelemetryEvent> result;
    result.reserve(std::min(limit, m_eventQueue.size()));

    for (size_t i = 0; i < m_eventQueue.size() && result.size() < limit; ++i) {
        result.push_back(m_eventQueue[i]);
    }
    return result;
}

std::vector<TelemetryBatch> TelemetryCollectorImpl::GetRecentBatches(size_t limit) {
    if (limit == 0) limit = 10;

    std::shared_lock lock(m_batchMutex);
    std::vector<TelemetryBatch> result;
    result.reserve(std::min(limit, m_batchHistory.size()));

    size_t start = (m_batchHistory.size() > limit) ? (m_batchHistory.size() - limit) : 0;
    for (size_t i = start; i < m_batchHistory.size(); ++i) {
        result.push_back(m_batchHistory[i]);
    }
    std::reverse(result.begin(), result.end());
    return result;
}

void TelemetryCollectorImpl::ClearQueue() {
    {
        std::unique_lock lock(m_queueMutex);
        m_eventQueue.clear();
    }

    // Remove offline queue file
    if (!m_offlineQueuePath.empty() && fs::exists(m_offlineQueuePath)) {
        Utils::FileUtils::Error fsErr;
        Utils::FileUtils::RemoveFile(m_offlineQueuePath.wstring(), &fsErr);
    }

    SS_LOG_DEBUG("Telemetry", "Queue cleared");
}

void TelemetryCollectorImpl::OptOut() {
    SetConsentLevel(ConsentLevel::None);
    ClearQueue();

    {
        std::unique_lock lock(m_batchMutex);
        m_batchHistory.clear();
    }

    ResetStatistics();
    SS_LOG_INFO("Telemetry", "User opted out — all telemetry data cleared");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void TelemetryCollectorImpl::RegisterEventCallback(EventCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_eventCb = std::move(cb);
}

void TelemetryCollectorImpl::RegisterBatchCallback(BatchCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_batchCb = std::move(cb);
}

void TelemetryCollectorImpl::RegisterConsentCallback(ConsentCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_consentCb = std::move(cb);
}

void TelemetryCollectorImpl::RegisterErrorCallback(TelemetryErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCb = std::move(cb);
}

void TelemetryCollectorImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_eventCb = nullptr;
    m_batchCb = nullptr;
    m_consentCb = nullptr;
    m_errorCb = nullptr;
}

void TelemetryCollectorImpl::NotifyEventCb(const TelemetryEvent& event) {
    EventCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_eventCb;
    }
    if (cb) {
        try { cb(event); }
        catch (const std::exception& ex) {
            SS_LOG_ERROR("Telemetry", "Event callback threw: {}", ex.what());
        }
    }
}

void TelemetryCollectorImpl::NotifyBatchCb(const TelemetryBatch& batch) {
    BatchCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_batchCb;
    }
    if (cb) {
        try { cb(batch); }
        catch (const std::exception& ex) {
            SS_LOG_ERROR("Telemetry", "Batch callback threw: {}", ex.what());
        }
    }
}

void TelemetryCollectorImpl::NotifyError(const std::string& msg, int code) {
    TelemetryErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCb;
    }
    if (cb) {
        try { cb(msg, code); }
        catch (...) {}
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

TelemetryStatisticsSnapshot TelemetryCollectorImpl::GetStatistics() const noexcept {
    return m_stats.TakeSnapshot();
}

void TelemetryCollectorImpl::ResetStatistics() {
    m_stats.Reset();
    SS_LOG_DEBUG("Telemetry", "Statistics reset");
}

bool TelemetryCollectorImpl::SelfTest() {
    SS_LOG_INFO("Telemetry", "Running self-test...");

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR("Telemetry", "Self-test failed: not initialized");
        return false;
    }

    if (!m_flushThread.joinable()) {
        SS_LOG_ERROR("Telemetry", "Self-test failed: flush thread not running");
        return false;
    }

    // Test anonymization pipeline
    const std::string testInput = "test@example.com accessed 192.168.1.100 from C:\\Users\\admin\\Desktop";
    const std::string scrubbed = ScrubPII(testInput);
    if (scrubbed.find("test@example.com") != std::string::npos) {
        SS_LOG_ERROR("Telemetry", "Self-test failed: PII scrubbing did not remove email");
        return false;
    }
    if (scrubbed.find("192.168.1.100") != std::string::npos) {
        SS_LOG_ERROR("Telemetry", "Self-test failed: PII scrubbing did not anonymize IP");
        return false;
    }
    if (scrubbed.find("\\admin\\") != std::string::npos) {
        SS_LOG_ERROR("Telemetry", "Self-test failed: PII scrubbing did not normalize path");
        return false;
    }

    // Test machine ID generation
    const auto id = GenerateAnonymousMachineId();
    if (id.empty() || id == "[HASH_ERROR]") {
        SS_LOG_ERROR("Telemetry", "Self-test failed: machine ID generation failed");
        return false;
    }

    SS_LOG_INFO("Telemetry", "Self-test passed");
    return true;
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> TelemetryCollector::s_instanceCreated{false};

TelemetryCollector::TelemetryCollector()
    : m_impl(std::make_unique<TelemetryCollectorImpl>()) {}

TelemetryCollector::~TelemetryCollector() = default;

TelemetryCollector& TelemetryCollector::Instance() noexcept {
    static TelemetryCollector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool TelemetryCollector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// FORWARDING — LIFECYCLE
// ============================================================================

bool TelemetryCollector::Initialize(const TelemetryConfiguration& config) {
    return m_impl->Initialize(config);
}

void TelemetryCollector::Shutdown() {
    m_impl->Shutdown();
}

bool TelemetryCollector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

TelemetryModuleStatus TelemetryCollector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool TelemetryCollector::UpdateConfiguration(const TelemetryConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

TelemetryConfiguration TelemetryCollector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// FORWARDING — EVENT RECORDING
// ============================================================================

void TelemetryCollector::RecordEvent(const std::string& type, const std::string& data) {
    m_impl->RecordEventSimple(type, data);
}

void TelemetryCollector::RecordEvent(const TelemetryEvent& event) {
    m_impl->RecordEventFull(event);
}

void TelemetryCollector::RecordDetection(const DetectionEventData& detection) {
    m_impl->RecordDetection(detection);
}

void TelemetryCollector::RecordHealth(const HealthEventData& health) {
    m_impl->RecordHealth(health);
}

void TelemetryCollector::RecordPerformance(const PerformanceEventData& perf) {
    m_impl->RecordPerformance(perf);
}

void TelemetryCollector::RecordCrash(const CrashEventData& crash) {
    m_impl->RecordCrash(crash);
}

void TelemetryCollector::RecordCustom(const std::string& subtype,
                                       const std::map<std::string, std::string>& data) {
    m_impl->RecordCustom(subtype, data);
}

// ============================================================================
// FORWARDING — SUBMISSION
// ============================================================================

void TelemetryCollector::Flush() {
    m_impl->Flush();
}

void TelemetryCollector::FlushAsync() {
    m_impl->FlushAsync();
}

bool TelemetryCollector::SubmitImmediate(const TelemetryEvent& event) {
    return m_impl->SubmitImmediate(event);
}

size_t TelemetryCollector::GetQueueSize() const noexcept {
    return m_impl->GetQueueSize();
}

bool TelemetryCollector::IsSubmitting() const noexcept {
    return m_impl->IsSubmitting();
}

// ============================================================================
// FORWARDING — CONSENT
// ============================================================================

void TelemetryCollector::SetConsentLevel(ConsentLevel level) {
    m_impl->SetConsentLevel(level);
}

ConsentLevel TelemetryCollector::GetConsentLevel() const noexcept {
    return m_impl->GetConsentLevel();
}

bool TelemetryCollector::IsConsented() const noexcept {
    return m_impl->IsConsented();
}

bool TelemetryCollector::RequestConsent(ConsentLevel requestedLevel) {
    return m_impl->RequestConsent(requestedLevel);
}

// ============================================================================
// FORWARDING — ANONYMIZATION
// ============================================================================

std::string TelemetryCollector::Anonymize(const std::string& data,
                                           AnonymizationLevel level) {
    return m_impl->Anonymize(data, level);
}

std::string TelemetryCollector::AnonymizePath(const fs::path& path) {
    return m_impl->AnonymizePath(path);
}

void TelemetryCollector::SetAnonymizationLevel(AnonymizationLevel level) {
    m_impl->SetAnonymizationLevel(level);
}

std::string TelemetryCollector::GetAnonymousMachineId() const {
    return m_impl->GetAnonymousMachineId();
}

// ============================================================================
// FORWARDING — HISTORY & MANAGEMENT
// ============================================================================

std::vector<TelemetryEvent> TelemetryCollector::GetPendingEvents(size_t limit) {
    return m_impl->GetPendingEvents(limit);
}

std::vector<TelemetryBatch> TelemetryCollector::GetRecentBatches(size_t limit) {
    return m_impl->GetRecentBatches(limit);
}

void TelemetryCollector::ClearQueue() {
    m_impl->ClearQueue();
}

void TelemetryCollector::OptOut() {
    m_impl->OptOut();
}

// ============================================================================
// FORWARDING — CALLBACKS
// ============================================================================

void TelemetryCollector::RegisterEventCallback(EventCallback callback) {
    m_impl->RegisterEventCallback(std::move(callback));
}

void TelemetryCollector::RegisterBatchCallback(BatchCallback callback) {
    m_impl->RegisterBatchCallback(std::move(callback));
}

void TelemetryCollector::RegisterConsentCallback(ConsentCallback callback) {
    m_impl->RegisterConsentCallback(std::move(callback));
}

void TelemetryCollector::RegisterErrorCallback(TelemetryErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void TelemetryCollector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ============================================================================
// FORWARDING — STATISTICS
// ============================================================================

TelemetryStatisticsSnapshot TelemetryCollector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void TelemetryCollector::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool TelemetryCollector::SelfTest() {
    return m_impl->SelfTest();
}

std::string TelemetryCollector::GetVersionString() noexcept {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  TelemetryConstants::VERSION_MAJOR,
                  TelemetryConstants::VERSION_MINOR,
                  TelemetryConstants::VERSION_PATCH);
    return buf;
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

std::string TelemetryEvent::ToJson() const {
    std::string j = "{";
    j += "\"eventId\":\"" + JsonEscape(eventId) + "\",";
    j += "\"eventType\":\"" + std::string(GetEventTypeName(eventType)) + "\",";
    j += "\"subtype\":\"" + JsonEscape(subtype) + "\",";
    j += "\"timestamp\":" + std::to_string(timestamp) + ",";
    j += "\"systemTime\":\"" + SystemTimeToIso8601(systemTime) + "\",";
    j += "\"machineId\":\"" + JsonEscape(machineId) + "\",";
    j += "\"productVersion\":\"" + JsonEscape(productVersion) + "\",";
    j += "\"osVersion\":\"" + JsonEscape(osVersion) + "\",";
    j += "\"isAnonymized\":" + std::string(isAnonymized ? "true" : "false") + ",";
    j += "\"anonymizationLevel\":\"" + std::string(GetAnonymizationLevelName(anonymizationLevel)) + "\",";
    j += "\"status\":\"" + std::string(GetSubmissionStatusName(status)) + "\",";
    j += "\"retryCount\":" + std::to_string(retryCount) + ",";
    j += "\"payload\":" + (payloadJson.empty() ? "null" : payloadJson);
    j += "}";
    return j;
}

std::string DetectionEventData::ToJson() const {
    std::string j = "{";
    j += "\"threatName\":\"" + JsonEscape(threatName) + "\",";
    j += "\"threatType\":\"" + JsonEscape(threatType) + "\",";
    j += "\"fileHash\":\"" + JsonEscape(fileHash) + "\",";
    j += "\"fileSize\":" + std::to_string(fileSize) + ",";
    j += "\"detectionMethod\":\"" + JsonEscape(detectionMethod) + "\",";
    j += "\"actionTaken\":\"" + JsonEscape(actionTaken) + "\",";
    j += "\"detectionTime\":" + std::to_string(detectionTime) + ",";
    j += "\"signatureVersion\":\"" + JsonEscape(signatureVersion) + "\",";
    j += "\"fpProbability\":" + std::to_string(fpProbability);
    j += "}";
    return j;
}

std::string HealthEventData::ToJson() const {
    std::string j = "{";
    j += "\"cpuUsage\":" + std::to_string(cpuUsage) + ",";
    j += "\"memoryUsageMB\":" + std::to_string(memoryUsageMB) + ",";
    j += "\"diskUsageMB\":" + std::to_string(diskUsageMB) + ",";
    j += "\"uptimeSeconds\":" + std::to_string(uptimeSeconds) + ",";
    j += "\"scanQueueSize\":" + std::to_string(scanQueueSize) + ",";
    j += "\"activeScans\":" + std::to_string(activeScans) + ",";
    j += "\"errorCount\":" + std::to_string(errorCount) + ",";
    j += "\"moduleHealth\":{";
    bool first = true;
    for (const auto& [k, v] : moduleHealth) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":\"" + JsonEscape(v) + "\"";
        first = false;
    }
    j += "}}";
    return j;
}

std::string PerformanceEventData::ToJson() const {
    std::string j = "{";
    j += "\"metricName\":\"" + JsonEscape(metricName) + "\",";
    j += "\"value\":" + std::to_string(value) + ",";
    j += "\"unit\":\"" + JsonEscape(unit) + "\",";
    j += "\"durationMs\":" + std::to_string(durationMs) + ",";
    j += "\"context\":{";
    bool first = true;
    for (const auto& [k, v] : context) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":\"" + JsonEscape(v) + "\"";
        first = false;
    }
    j += "}}";
    return j;
}

std::string CrashEventData::ToJson() const {
    std::string j = "{";
    j += "\"exceptionType\":\"" + JsonEscape(exceptionType) + "\",";
    j += "\"exceptionMessage\":\"" + JsonEscape(exceptionMessage) + "\",";
    j += "\"stackTrace\":\"" + JsonEscape(stackTrace) + "\",";
    j += "\"moduleName\":\"" + JsonEscape(moduleName) + "\",";
    j += "\"functionName\":\"" + JsonEscape(functionName) + "\",";
    j += "\"threadId\":" + std::to_string(threadId) + ",";
    j += "\"isCritical\":" + std::string(isCritical ? "true" : "false") + ",";
    j += "\"minidumpHash\":\"" + JsonEscape(minidumpHash) + "\"";
    j += "}";
    return j;
}

std::string TelemetryBatch::ToJson() const {
    std::string j = "{";
    j += "\"batchId\":\"" + JsonEscape(batchId) + "\",";
    j += "\"createdTime\":\"" + SystemTimeToIso8601(createdTime) + "\",";
    if (submittedTime)
        j += "\"submittedTime\":\"" + SystemTimeToIso8601(*submittedTime) + "\",";
    j += "\"status\":\"" + std::string(GetSubmissionStatusName(status)) + "\",";
    j += "\"retryCount\":" + std::to_string(retryCount) + ",";
    j += "\"totalSize\":" + std::to_string(totalSize) + ",";
    j += "\"compressedSize\":" + std::to_string(compressedSize) + ",";
    j += "\"eventCount\":" + std::to_string(events.size());
    j += "}";
    return j;
}

bool TelemetryConfiguration::IsValid() const noexcept {
    if (batchSize == 0 || batchSize > 1000) return false;
    if (maxQueueSize == 0 || maxQueueSize > 100000) return false;
    if (flushIntervalHours == 0 || flushIntervalHours > 168) return false;
    if (maxRetryAttempts > 20) return false;
    if (!endpoint.empty()) {
        // Basic endpoint validation
        if (endpoint.find("://") == std::string::npos) return false;
        if (endpoint.find("..") != std::string::npos) return false;
    }
    return true;
}

// ============================================================================
// STATISTICS
// ============================================================================

void TelemetryStatistics::Reset() noexcept {
    eventsRecorded.store(0, std::memory_order_relaxed);
    eventsSubmitted.store(0, std::memory_order_relaxed);
    eventsFailed.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    batchesSubmitted.store(0, std::memory_order_relaxed);
    batchesFailed.store(0, std::memory_order_relaxed);
    bytesSubmitted.store(0, std::memory_order_relaxed);
    retryAttempts.store(0, std::memory_order_relaxed);
    anonymizationTime.store(0, std::memory_order_relaxed);
    for (auto& a : byEventType) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

TelemetryStatisticsSnapshot TelemetryStatistics::TakeSnapshot() const noexcept {
    TelemetryStatisticsSnapshot snap;
    snap.eventsRecorded = eventsRecorded.load(std::memory_order_relaxed);
    snap.eventsSubmitted = eventsSubmitted.load(std::memory_order_relaxed);
    snap.eventsFailed = eventsFailed.load(std::memory_order_relaxed);
    snap.eventsDropped = eventsDropped.load(std::memory_order_relaxed);
    snap.batchesSubmitted = batchesSubmitted.load(std::memory_order_relaxed);
    snap.batchesFailed = batchesFailed.load(std::memory_order_relaxed);
    snap.bytesSubmitted = bytesSubmitted.load(std::memory_order_relaxed);
    snap.retryAttempts = retryAttempts.load(std::memory_order_relaxed);
    snap.anonymizationTime = anonymizationTime.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byEventType.size(); ++i)
        snap.byEventType[i] = byEventType[i].load(std::memory_order_relaxed);
    snap.uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    return snap;
}

std::string TelemetryStatisticsSnapshot::ToJson() const {
    std::string j = "{";
    j += "\"eventsRecorded\":" + std::to_string(eventsRecorded) + ",";
    j += "\"eventsSubmitted\":" + std::to_string(eventsSubmitted) + ",";
    j += "\"eventsFailed\":" + std::to_string(eventsFailed) + ",";
    j += "\"eventsDropped\":" + std::to_string(eventsDropped) + ",";
    j += "\"batchesSubmitted\":" + std::to_string(batchesSubmitted) + ",";
    j += "\"batchesFailed\":" + std::to_string(batchesFailed) + ",";
    j += "\"bytesSubmitted\":" + std::to_string(bytesSubmitted) + ",";
    j += "\"retryAttempts\":" + std::to_string(retryAttempts) + ",";
    j += "\"anonymizationTimeUs\":" + std::to_string(anonymizationTime) + ",";
    j += "\"uptimeSeconds\":" + std::to_string(uptimeSeconds) + ",";
    j += "\"byEventType\":[";
    for (size_t i = 0; i < byEventType.size(); ++i) {
        if (i > 0) j += ",";
        j += std::to_string(byEventType[i]);
    }
    j += "]}";
    return j;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetEventTypeName(TelemetryEventType type) noexcept {
    switch (type) {
        case TelemetryEventType::Detection:     return "Detection";
        case TelemetryEventType::Scan:          return "Scan";
        case TelemetryEventType::Update:        return "Update";
        case TelemetryEventType::Crash:         return "Crash";
        case TelemetryEventType::Error:         return "Error";
        case TelemetryEventType::Health:        return "Health";
        case TelemetryEventType::Performance:   return "Performance";
        case TelemetryEventType::Configuration: return "Configuration";
        case TelemetryEventType::License:       return "License";
        case TelemetryEventType::Feedback:      return "Feedback";
        case TelemetryEventType::Sample:        return "Sample";
        case TelemetryEventType::Custom:        return "Custom";
        default:                                return "Unknown";
    }
}

std::string_view GetConsentLevelName(ConsentLevel level) noexcept {
    switch (level) {
        case ConsentLevel::None:     return "None";
        case ConsentLevel::Required: return "Required";
        case ConsentLevel::Basic:    return "Basic";
        case ConsentLevel::Full:     return "Full";
        default:                     return "Unknown";
    }
}

std::string_view GetAnonymizationLevelName(AnonymizationLevel level) noexcept {
    switch (level) {
        case AnonymizationLevel::None:     return "None";
        case AnonymizationLevel::Basic:    return "Basic";
        case AnonymizationLevel::Standard: return "Standard";
        case AnonymizationLevel::Strict:   return "Strict";
        default:                           return "Unknown";
    }
}

std::string_view GetSubmissionStatusName(SubmissionStatus status) noexcept {
    switch (status) {
        case SubmissionStatus::Pending:    return "Pending";
        case SubmissionStatus::InProgress: return "InProgress";
        case SubmissionStatus::Submitted:  return "Submitted";
        case SubmissionStatus::Failed:     return "Failed";
        case SubmissionStatus::Retrying:   return "Retrying";
        case SubmissionStatus::Expired:    return "Expired";
        default:                           return "Unknown";
    }
}

}  // namespace Communication
}  // namespace ShadowStrike

