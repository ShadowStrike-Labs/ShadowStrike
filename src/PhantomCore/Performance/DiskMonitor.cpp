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
 * ShadowStrike NGAV - DISK MONITORING MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file DiskMonitor.cpp
 * @brief Implementation of the enterprise disk monitoring engine.
 *
 * Thread model:
 *   - One dedicated monitor thread runs MonitorLoop().
 *   - m_configMutex  guards m_config (shared reads, exclusive writes).
 *   - m_dataMutex    guards published results (shared reads, exclusive writes).
 *   - m_cbMutex      guards callback vectors (snapshot-then-invoke pattern).
 *   - m_processTracking / m_prevDriveSpace are monitor-thread-private.
 *   - InternalStats members are std::atomic — no lock needed.
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "DiskMonitor.hpp"
#include "../Utils/Logger.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <string>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <cmath>

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CAT = L"DiskMonitor";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> DiskMonitor::s_instanceCreated{false};

// ============================================================================
// ANONYMOUS HELPERS
// ============================================================================
namespace {

// ---------- JSON escaping (narrow) ----------
[[nodiscard]] std::string EscapeJsonNarrow(const std::string& s) {
    std::ostringstream o;
    for (const char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20u) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                      << static_cast<unsigned>(static_cast<unsigned char>(c));
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// ---------- Wide → UTF-8 ----------
[[nodiscard]] std::string WToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        out.data(), needed, nullptr, nullptr);
    return out;
}

// ---------- RAII HANDLE wrapper ----------
struct HandleDeleter {
    using pointer = HANDLE;
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h);
        }
    }
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

[[nodiscard]] UniqueHandle WrapHandle(HANDLE h) noexcept {
    return UniqueHandle((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
}

// ---------- Safe average ----------
[[nodiscard]] double SafeAverage(const std::deque<double>& samples) noexcept {
    if (samples.empty()) return 0.0;
    const double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    return sum / static_cast<double>(samples.size());
}

// ---------- Window size in samples ----------
[[nodiscard]] size_t WindowSamples(uint32_t windowSec, uint32_t intervalMs) noexcept {
    if (intervalMs == 0) return 1;
    const size_t n = static_cast<size_t>(windowSec) * 1000u / intervalMs;
    return (n < 1) ? 1 : n;
}

} // anonymous namespace

// ============================================================================
// STRUCTURE JSON SERIALIZATION
// ============================================================================

std::string ProcessDiskUsage::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"processId\":" << processId << ","
      << "\"processName\":\"" << EscapeJsonNarrow(WToUtf8(processName)) << "\","
      << "\"readBytesPerSec\":" << readBytesPerSec << ","
      << "\"writeBytesPerSec\":" << writeBytesPerSec << ","
      << "\"readOpsPerSec\":" << readOpsPerSec << ","
      << "\"writeOpsPerSec\":" << writeOpsPerSec << ","
      << "\"otherOpsPerSec\":" << otherOpsPerSec << ","
      << "\"totalReadBytes\":" << totalReadBytes << ","
      << "\"totalWriteBytes\":" << totalWriteBytes << ","
      << "\"highWriteRate\":" << (highWriteRate ? "true" : "false") << ","
      << "\"highFileEnumeration\":" << (highFileEnumeration ? "true" : "false")
      << "}";
    return o.str();
}

std::string RansomwareAlert::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"processId\":" << processId << ","
      << "\"processName\":\"" << EscapeJsonNarrow(WToUtf8(processName)) << "\","
      << "\"sustainedWriteBytesPerSec\":" << sustainedWriteBytesPerSec << ","
      << "\"sustainedDurationSamples\":" << sustainedDurationSamples << ","
      << "\"totalBytesWrittenDuringWindow\":" << totalBytesWrittenDuringWindow
      << "}";
    return o.str();
}

std::string FileEnumAlert::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"processId\":" << processId << ","
      << "\"processName\":\"" << EscapeJsonNarrow(WToUtf8(processName)) << "\","
      << "\"sustainedOtherOpsPerSec\":" << sustainedOtherOpsPerSec << ","
      << "\"sustainedDurationSamples\":" << sustainedDurationSamples
      << "}";
    return o.str();
}

std::string DriveInfo::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"mountPoint\":\"" << EscapeJsonNarrow(WToUtf8(mountPoint)) << "\","
      << "\"volumeName\":\"" << EscapeJsonNarrow(WToUtf8(volumeName)) << "\","
      << "\"fileSystem\":\"" << EscapeJsonNarrow(WToUtf8(fileSystem)) << "\","
      << "\"totalBytes\":" << totalBytes << ","
      << "\"freeBytes\":" << freeBytes << ","
      << "\"availableBytes\":" << availableBytes << ","
      << "\"usagePercent\":" << usagePercent << ","
      << "\"freeBytesDeltaPerSec\":" << freeBytesDeltaPerSec << ","
      << "\"isSystemDrive\":" << (isSystemDrive ? "true" : "false")
      << "}";
    return o.str();
}

std::string DiskGlobalStats::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"totalReadBytesPerSec\":" << totalReadBytesPerSec << ","
      << "\"totalWriteBytesPerSec\":" << totalWriteBytesPerSec << ","
      << "\"totalReadOpsPerSec\":" << totalReadOpsPerSec << ","
      << "\"totalWriteOpsPerSec\":" << totalWriteOpsPerSec << ","
      << "\"activeProcesses\":" << activeProcesses
      << "}";
    return o.str();
}

bool DiskMonitorConfig::IsValid() const noexcept {
    if (pollingIntervalMs < DiskConstants::MIN_POLLING_INTERVAL_MS ||
        pollingIntervalMs > DiskConstants::MAX_POLLING_INTERVAL_MS)
        return false;
    if (ransomwareSustainedWindowSec < DiskConstants::MIN_SUSTAINED_WINDOW_SEC ||
        ransomwareSustainedWindowSec > DiskConstants::MAX_SUSTAINED_WINDOW_SEC)
        return false;
    if (ransomwareWriteThresholdBps == 0)
        return false;
    if (maxTrackedProcesses == 0 || maxTrackedProcesses > 100000)
        return false;
    if (lowSpaceThresholdPercent < 0.0 || lowSpaceThresholdPercent > 100.0)
        return false;
    return true;
}

std::string DiskMonitorModuleStats::ToJson() const {
    std::ostringstream o;
    o << "{"
      << "\"cyclesCompleted\":" << cyclesCompleted << ","
      << "\"alertsTriggered\":" << alertsTriggered << ","
      << "\"errorsEncountered\":" << errorsEncountered << ","
      << "\"processesTracked\":" << processesTracked << ","
      << "\"ransomwareAlertsTriggered\":" << ransomwareAlertsTriggered << ","
      << "\"fileEnumAlertsTriggered\":" << fileEnumAlertsTriggered << ","
      << "\"uptimeSeconds\":" << uptimeSeconds
      << "}";
    return o.str();
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class DiskMonitorImpl {
public:
    DiskMonitorImpl() = default;
    ~DiskMonitorImpl() { Shutdown(); }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize(const DiskMonitorConfig& config) {
        std::unique_lock cfgLock(m_configMutex);
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CAT, L"Initialize called on already-initialized DiskMonitor");
            return true;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid DiskMonitorConfig: polling=%u ms, sustained=%u s, threshold=%llu B/s",
                         config.pollingIntervalMs, config.ransomwareSustainedWindowSec,
                         static_cast<unsigned long long>(config.ransomwareWriteThresholdBps));
            return false;
        }

        m_config = config;
        m_selfPid = ::GetCurrentProcessId();
        m_stats.Reset();

        m_initialized.store(true, std::memory_order_release);
        m_running.store(true, std::memory_order_release);

        if (m_config.enabled) {
            m_thread = std::thread(&DiskMonitorImpl::MonitorLoop, this);
        }

        SS_LOG_INFO(LOG_CAT, L"Initialized: interval=%u ms, ransomware threshold=%llu B/s "
                    L"sustained over %u s, self PID=%u",
                    m_config.pollingIntervalMs,
                    static_cast<unsigned long long>(m_config.ransomwareWriteThresholdBps),
                    m_config.ransomwareSustainedWindowSec,
                    m_selfPid);
        return true;
    }

    void Shutdown() noexcept {
        {
            std::unique_lock cfgLock(m_configMutex);
            if (!m_initialized.load(std::memory_order_acquire)) return;
            m_running.store(false, std::memory_order_release);
        }

        // Wake the monitor thread immediately if it is parked in the
        // interval wait; otherwise Shutdown() blocks for up to
        // pollingIntervalMs (60s worst case) which is unacceptable for
        // service shutdown and ETW-orchestrated reconfiguration.
        {
            std::lock_guard cvLock(m_shutdownMutex);
        }
        m_shutdownCv.notify_all();

        if (m_thread.joinable()) {
            m_thread.join();
        }

        {
            std::unique_lock cbLock(m_cbMutex);
            m_highIoCallbacks.clear();
            m_lowSpaceCallbacks.clear();
            m_ransomwareCallbacks.clear();
            m_fileEnumCallbacks.clear();
        }

        {
            std::unique_lock dataLock(m_dataMutex);
            m_processUsage.clear();
            m_globalStats = {};
            m_drives.clear();
        }

        m_processTracking.clear();
        m_prevDriveSpace.clear();
        m_lastProcessUpdate = {};
        m_lastDriveUpdate   = {};
        m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(LOG_CAT, L"Shutdown complete. Cycles=%llu, errors=%llu",
                    static_cast<unsigned long long>(m_stats.cyclesCompleted.load(std::memory_order_relaxed)),
                    static_cast<unsigned long long>(m_stats.errorsEncountered.load(std::memory_order_relaxed)));
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void UpdateConfig(const DiskMonitorConfig& config) {
        if (!config.IsValid()) {
            SS_LOG_WARN(LOG_CAT, L"UpdateConfig rejected: invalid config");
            return;
        }
        std::unique_lock lock(m_configMutex);
        m_config = config;
        SS_LOG_DEBUG(LOG_CAT, L"Config updated: interval=%u ms", config.pollingIntervalMs);
    }

    [[nodiscard]] DiskMonitorConfig GetConfig() const {
        std::shared_lock lock(m_configMutex);
        return m_config;
    }

    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitorLoop() {
        SS_LOG_INFO(LOG_CAT, L"Monitor thread started (tid=%u)", ::GetCurrentThreadId());

        while (m_running.load(std::memory_order_acquire)) {
            const auto cycleStart = Clock::now();

            // Snapshot config under lock to avoid holding it during work
            DiskMonitorConfig cfg;
            {
                std::shared_lock lock(m_configMutex);
                cfg = m_config;
            }

            if (!cfg.enabled) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            try {
                if (cfg.enableProcessMonitoring) {
                    UpdateProcessStats(cfg);
                }
                if (cfg.enableDriveSpaceMonitoring) {
                    UpdateDriveInfo(cfg);
                }
                m_stats.cyclesCompleted.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& ex) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_ERROR(LOG_CAT, L"MonitorLoop exception: %hs", ex.what());
            } catch (...) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_ERROR(LOG_CAT, L"MonitorLoop: unknown exception");
            }

            const auto cycleEnd = Clock::now();
            const auto elapsed  = std::chrono::duration_cast<std::chrono::milliseconds>(cycleEnd - cycleStart);
            if (elapsed.count() < static_cast<long long>(cfg.pollingIntervalMs)) {
                const auto waitMs = std::chrono::milliseconds(
                    cfg.pollingIntervalMs - static_cast<uint32_t>(elapsed.count()));
                std::unique_lock cvLock(m_shutdownMutex);
                m_shutdownCv.wait_for(cvLock, waitMs, [this]() {
                    return !m_running.load(std::memory_order_acquire);
                });
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Monitor thread exiting");
    }

    // ========================================================================
    // PROCESS I/O COLLECTION
    // ========================================================================

    void UpdateProcessStats(const DiskMonitorConfig& cfg) {
        // --- Dynamic PID enumeration ---
        std::vector<DWORD> pidBuf(2048);
        DWORD bytesReturned = 0;

        while (true) {
            if (!::EnumProcesses(pidBuf.data(),
                                 static_cast<DWORD>(pidBuf.size() * sizeof(DWORD)),
                                 &bytesReturned)) {
                SS_LOG_LAST_ERROR(LOG_CAT, L"EnumProcesses failed");
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            const DWORD count = bytesReturned / sizeof(DWORD);
            if (count < pidBuf.size()) {
                pidBuf.resize(count);
                break;
            }
            if (pidBuf.size() >= 65536) {
                pidBuf.resize(count);
                SS_LOG_WARN(LOG_CAT, L"Process count exceeds 65536, capping enumeration");
                break;
            }
            pidBuf.resize(pidBuf.size() * 2);
        }

        // --- Time delta ---
        const auto now = Clock::now();
        double deltaTime = 0.0;
        if (m_lastProcessUpdate != TimePoint{}) {
            deltaTime = std::chrono::duration<double>(now - m_lastProcessUpdate).count();
        }
        m_lastProcessUpdate = now;
        if (deltaTime < 0.001) deltaTime = 1.0;

        const size_t writeWin = WindowSamples(cfg.ransomwareSustainedWindowSec, cfg.pollingIntervalMs);
        const size_t enumWin  = WindowSamples(cfg.fileEnumSustainedWindowSec, cfg.pollingIntervalMs);

        std::unordered_map<uint32_t, ProcessDiskUsage> currentUsage;
        DiskGlobalStats global{};
        global.timestamp = now;

        const std::unordered_set<DWORD> alivePids(pidBuf.begin(), pidBuf.end());

        for (const DWORD pid : pidBuf) {
            if (pid == 0) continue; // Idle process

            // PROCESS_QUERY_LIMITED_INFORMATION is sufficient for
            // GetProcessIoCounters and QueryFullProcessImageNameW and works
            // against protected and elevated processes that reject the
            // legacy PROCESS_QUERY_INFORMATION | PROCESS_VM_READ pair.
            // Refusing those processes would create an evasion window:
            // ransomware running as SYSTEM or under a PPL parent would not
            // be sampled at all and would never reach the sustained-write
            // detector. See MSDN: "Process Security and Access Rights".
            auto hProc = WrapHandle(
                ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProc) continue;

            IO_COUNTERS ioCtrs{};
            if (!::GetProcessIoCounters(hProc.get(), &ioCtrs)) continue;

            // --- Build ProcessDiskUsage ---
            ProcessDiskUsage usage{};
            usage.processId = pid;

            WCHAR nameBuf[MAX_PATH] = L"<unknown>";
            DWORD nameLen = static_cast<DWORD>(std::size(nameBuf));
            if (::QueryFullProcessImageNameW(hProc.get(), 0, nameBuf, &nameLen)
                && nameLen > 0) {
                std::wstring_view full(nameBuf, nameLen);
                const auto slash = full.find_last_of(L"\\/");
                if (slash != std::wstring_view::npos) {
                    const auto base = full.substr(slash + 1);
                    // base is a view into nameBuf; copy before overwriting.
                    std::wstring copy(base);
                    std::fill(std::begin(nameBuf), std::end(nameBuf), L'\0');
                    const size_t n =
                        std::min(copy.size(), std::size(nameBuf) - 1);
                    std::copy_n(copy.begin(), n, std::begin(nameBuf));
                }
            }
            usage.processName    = nameBuf;
            usage.totalReadBytes  = ioCtrs.ReadTransferCount;
            usage.totalWriteBytes = ioCtrs.WriteTransferCount;

            // --- Tracking data (monitor-thread-private) ---
            auto& trk = m_processTracking[pid];
            trk.lastSeen = now;

            // PID-reuse detection: name changed → reset tracking
            if (!trk.processName.empty() && trk.processName != usage.processName) {
                SS_LOG_DEBUG(LOG_CAT, L"PID %u reused: was '%ls', now '%ls'",
                             pid, trk.processName.c_str(), usage.processName.c_str());
                trk = ProcessTrackingData{};
                trk.lastSeen = now;
            }
            trk.processName = usage.processName;

            // --- Delta computation ---
            // On the very first observation of a PID we have no prior
            // counters, so subtracting from zero produces a value equal to
            // the process's lifetime I/O. With deltaTime fenced to a
            // minimum of 1.0s, that fabricated rate would seed the
            // sustained-write sliding window and could trigger a
            // ransomware alert on a long-lived legitimate process the
            // first time DiskMonitor sees it after start-up or after a
            // configuration reload. Suppress rate computation for this
            // cycle, snapshot the counters, and wait for the next pass.
            const auto& prev = trk.prevCounters;
            uint64_t dRead = 0, dWrite = 0, dRdOps = 0, dWrOps = 0, dOther = 0;
            if (!trk.firstSample) {
                dRead  = (ioCtrs.ReadTransferCount  >= prev.readBytes)
                       ? (ioCtrs.ReadTransferCount  - prev.readBytes)  : 0;
                dWrite = (ioCtrs.WriteTransferCount >= prev.writeBytes)
                       ? (ioCtrs.WriteTransferCount - prev.writeBytes) : 0;
                dRdOps = (ioCtrs.ReadOperationCount  >= prev.readOps)
                       ? (ioCtrs.ReadOperationCount  - prev.readOps)   : 0;
                dWrOps = (ioCtrs.WriteOperationCount >= prev.writeOps)
                       ? (ioCtrs.WriteOperationCount - prev.writeOps)  : 0;
                dOther = (ioCtrs.OtherOperationCount >= prev.otherOps)
                       ? (ioCtrs.OtherOperationCount - prev.otherOps)  : 0;
            }

            usage.readBytesPerSec  = static_cast<double>(dRead)  / deltaTime;
            usage.writeBytesPerSec = static_cast<double>(dWrite) / deltaTime;
            usage.readOpsPerSec    = static_cast<double>(dRdOps) / deltaTime;
            usage.writeOpsPerSec   = static_cast<double>(dWrOps) / deltaTime;
            usage.otherOpsPerSec   = static_cast<double>(dOther) / deltaTime;

            // Store raw counters for next cycle
            trk.prevCounters.readBytes  = ioCtrs.ReadTransferCount;
            trk.prevCounters.writeBytes = ioCtrs.WriteTransferCount;
            trk.prevCounters.readOps    = ioCtrs.ReadOperationCount;
            trk.prevCounters.writeOps   = ioCtrs.WriteOperationCount;
            trk.prevCounters.otherOps   = ioCtrs.OtherOperationCount;

            if (trk.firstSample) {
                trk.firstSample = false;
                // No rates available this cycle — skip detector feeds and
                // global accumulation so a freshly observed PID cannot
                // perturb statistics with a fabricated lifetime spike.
                continue;
            }

            // --- Sustained write (ransomware) detection ---
            trk.writeRateSamples.push_back(usage.writeBytesPerSec);
            while (trk.writeRateSamples.size() > writeWin) trk.writeRateSamples.pop_front();

            const bool canAlertThisProcess = (pid != m_selfPid) || cfg.enableSelfMonitoring;

            if (canAlertThisProcess && trk.writeRateSamples.size() >= writeWin) {
                const double avgWrite = SafeAverage(trk.writeRateSamples);
                if (avgWrite > static_cast<double>(cfg.ransomwareWriteThresholdBps)) {
                    usage.highWriteRate = true;
                    NotifyHighIo(usage);

                    if (!trk.ransomwareAlerted) {
                        trk.ransomwareAlerted = true;
                        RansomwareAlert alert{};
                        alert.processId                     = pid;
                        alert.processName                   = usage.processName;
                        alert.sustainedWriteBytesPerSec     = avgWrite;
                        alert.sustainedDurationSamples      = static_cast<uint32_t>(writeWin);
                        alert.totalBytesWrittenDuringWindow =
                            static_cast<uint64_t>(avgWrite * deltaTime * static_cast<double>(writeWin));
                        alert.detectedAt                    = now;
                        NotifyRansomware(alert);
                        SS_LOG_WARN(LOG_CAT,
                            L"RANSOMWARE ALERT: PID %u (%ls) sustained write %.2f MB/s for %u samples",
                            pid, usage.processName.c_str(),
                            avgWrite / (1024.0 * 1024.0),
                            static_cast<unsigned>(writeWin));
                    }
                } else {
                    trk.ransomwareAlerted = false;
                }
            }

            // --- Sustained file enumeration detection ---
            trk.otherOpsSamples.push_back(usage.otherOpsPerSec);
            while (trk.otherOpsSamples.size() > enumWin) trk.otherOpsSamples.pop_front();

            if (canAlertThisProcess && trk.otherOpsSamples.size() >= enumWin) {
                const double avgOps = SafeAverage(trk.otherOpsSamples);
                if (avgOps > static_cast<double>(cfg.fileEnumThresholdOpsPerSec)) {
                    usage.highFileEnumeration = true;

                    if (!trk.fileEnumAlerted) {
                        trk.fileEnumAlerted = true;
                        FileEnumAlert alert{};
                        alert.processId                = pid;
                        alert.processName              = usage.processName;
                        alert.sustainedOtherOpsPerSec  = avgOps;
                        alert.sustainedDurationSamples = static_cast<uint32_t>(enumWin);
                        alert.detectedAt               = now;
                        NotifyFileEnum(alert);
                        SS_LOG_WARN(LOG_CAT,
                            L"FILE ENUM ALERT: PID %u (%ls) sustained %.0f other-ops/s for %u samples",
                            pid, usage.processName.c_str(), avgOps,
                            static_cast<unsigned>(enumWin));
                    }
                } else {
                    trk.fileEnumAlerted = false;
                }
            }

            // --- Accumulate ---
            if (usage.readBytesPerSec > 0.0 || usage.writeBytesPerSec > 0.0 ||
                usage.otherOpsPerSec > 0.0) {
                currentUsage[pid] = usage;
                global.totalReadBytesPerSec  += usage.readBytesPerSec;
                global.totalWriteBytesPerSec += usage.writeBytesPerSec;
                global.totalReadOpsPerSec    += usage.readOpsPerSec;
                global.totalWriteOpsPerSec   += usage.writeOpsPerSec;
                global.activeProcesses++;
            }
        }

        // --- Dead process cleanup ---
        for (auto it = m_processTracking.begin(); it != m_processTracking.end();) {
            if (alivePids.find(it->first) == alivePids.end()) {
                it = m_processTracking.erase(it);
            } else {
                ++it;
            }
        }

        // --- Self-protection: cap tracked processes ---
        if (m_processTracking.size() > cfg.maxTrackedProcesses) {
            SS_LOG_WARN(LOG_CAT, L"Tracked process count %zu exceeds cap %zu, evicting stale entries",
                        m_processTracking.size(), cfg.maxTrackedProcesses);
            // Evict entries with oldest lastSeen
            std::vector<std::pair<uint32_t, TimePoint>> entries;
            entries.reserve(m_processTracking.size());
            for (const auto& [pid, data] : m_processTracking) {
                entries.emplace_back(pid, data.lastSeen);
            }
            std::sort(entries.begin(), entries.end(),
                      [](const auto& a, const auto& b) { return a.second < b.second; });
            const size_t toRemove = m_processTracking.size() - cfg.maxTrackedProcesses;
            for (size_t i = 0; i < toRemove && i < entries.size(); ++i) {
                m_processTracking.erase(entries[i].first);
            }
        }

        // --- Publish results ---
        {
            std::unique_lock lock(m_dataMutex);
            m_processUsage = std::move(currentUsage);
            m_globalStats  = global;
        }

        m_stats.processesTracked.store(
            static_cast<uint64_t>(m_processTracking.size()), std::memory_order_relaxed);
    }

    // ========================================================================
    // DRIVE SPACE MONITORING
    // ========================================================================

    void UpdateDriveInfo(const DiskMonitorConfig& cfg) {
        const DWORD driveMask = ::GetLogicalDrives();
        if (driveMask == 0) {
            SS_LOG_LAST_ERROR(LOG_CAT, L"GetLogicalDrives failed");
            m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto now = Clock::now();
        double driveDelta = 0.0;
        if (m_lastDriveUpdate != TimePoint{}) {
            driveDelta = std::chrono::duration<double>(now - m_lastDriveUpdate).count();
        }
        m_lastDriveUpdate = now;

        WCHAR winDir[MAX_PATH]{};
        std::wstring systemDrive;
        if (::GetWindowsDirectoryW(winDir, MAX_PATH)) {
            systemDrive = std::wstring(winDir).substr(0, 3);
        }

        std::vector<DriveInfo> results;

        for (int i = 0; i < 26; ++i) {
            if (!(driveMask & (1u << i))) continue;

            std::wstring mp = L"A:\\";
            mp[0] = static_cast<wchar_t>(L'A' + i);

            if (::GetDriveTypeW(mp.c_str()) != DRIVE_FIXED) continue;

            DriveInfo info{};
            info.mountPoint   = mp;
            info.isSystemDrive = (mp == systemDrive);

            WCHAR volName[MAX_PATH + 1]{};
            WCHAR fsName[MAX_PATH + 1]{};
            if (::GetVolumeInformationW(mp.c_str(), volName, MAX_PATH,
                                        nullptr, nullptr, nullptr, fsName, MAX_PATH)) {
                info.volumeName = volName;
                info.fileSystem = fsName;
            }

            ULARGE_INTEGER freeBytesAvail{}, totalBytes{}, totalFree{};
            if (::GetDiskFreeSpaceExW(mp.c_str(), &freeBytesAvail, &totalBytes, &totalFree)) {
                info.availableBytes = freeBytesAvail.QuadPart;
                info.totalBytes     = totalBytes.QuadPart;
                info.freeBytes      = totalFree.QuadPart;

                if (info.totalBytes > 0) {
                    info.usagePercent = 100.0 *
                        (1.0 - static_cast<double>(info.availableBytes) /
                               static_cast<double>(info.totalBytes));
                }

                // Drive space consumption rate
                auto prevIt = m_prevDriveSpace.find(mp);
                if (prevIt != m_prevDriveSpace.end() && driveDelta > 0.001) {
                    const int64_t delta = static_cast<int64_t>(info.freeBytes) -
                                          static_cast<int64_t>(prevIt->second.freeBytes);
                    info.freeBytesDeltaPerSec = static_cast<double>(delta) / driveDelta;
                }
                m_prevDriveSpace[mp] = DriveSpaceSnapshot{info.freeBytes, now};

                // Low-space alerting
                if (info.usagePercent > cfg.lowSpaceThresholdPercent ||
                    info.availableBytes < cfg.lowSpaceThresholdBytes) {
                    NotifyLowSpace(info);
                }
            }

            results.push_back(std::move(info));
        }

        std::unique_lock lock(m_dataMutex);
        m_drives = std::move(results);
    }

    // ========================================================================
    // DATA ACCESSORS
    // ========================================================================

    [[nodiscard]] std::optional<ProcessDiskUsage> GetProcessUsage(uint32_t pid) const {
        std::shared_lock lock(m_dataMutex);
        auto it = m_processUsage.find(pid);
        if (it != m_processUsage.end()) return it->second;
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ProcessDiskUsage> GetTopConsumers(size_t count) const {
        DiskMonitorConfig cfg;
        {
            std::shared_lock cfgLock(m_configMutex);
            cfg = m_config;
        }

        std::shared_lock lock(m_dataMutex);
        std::vector<ProcessDiskUsage> vec;
        vec.reserve(m_processUsage.size());
        for (const auto& [pid, usage] : m_processUsage) {
            if (!cfg.enableSelfMonitoring && pid == m_selfPid) continue;
            vec.push_back(usage);
        }

        std::sort(vec.begin(), vec.end(), [](const ProcessDiskUsage& a, const ProcessDiskUsage& b) {
            return (a.readBytesPerSec + a.writeBytesPerSec) >
                   (b.readBytesPerSec + b.writeBytesPerSec);
        });

        if (vec.size() > count) vec.resize(count);
        return vec;
    }

    [[nodiscard]] DiskGlobalStats GetGlobalStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_globalStats;
    }

    [[nodiscard]] std::vector<DriveInfo> GetDriveInfo() const {
        std::shared_lock lock(m_dataMutex);
        return m_drives;
    }

    [[nodiscard]] std::optional<ProcessDiskUsage> GetSelfIoUsage() const {
        return GetProcessUsage(m_selfPid);
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    void RegisterHighIoCallback(HighIoCallback cb) {
        if (!cb) return;
        std::unique_lock lock(m_cbMutex);
        m_highIoCallbacks.push_back(std::move(cb));
    }

    void RegisterLowSpaceCallback(LowSpaceCallback cb) {
        if (!cb) return;
        std::unique_lock lock(m_cbMutex);
        m_lowSpaceCallbacks.push_back(std::move(cb));
    }

    void RegisterRansomwareCallback(RansomwareCallback cb) {
        if (!cb) return;
        std::unique_lock lock(m_cbMutex);
        m_ransomwareCallbacks.push_back(std::move(cb));
    }

    void RegisterFileEnumCallback(FileEnumCallback cb) {
        if (!cb) return;
        std::unique_lock lock(m_cbMutex);
        m_fileEnumCallbacks.push_back(std::move(cb));
    }

    void UnregisterCallbacks() noexcept {
        std::unique_lock lock(m_cbMutex);
        m_highIoCallbacks.clear();
        m_lowSpaceCallbacks.clear();
        m_ransomwareCallbacks.clear();
        m_fileEnumCallbacks.clear();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] DiskMonitorModuleStats GetModuleStats() const {
        return m_stats.Snapshot();
    }

    [[nodiscard]] bool SelfTest() {
        bool ok = true;

        // 1. Can we read our own I/O counters?
        {
            auto h = WrapHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ::GetCurrentProcessId()));
            IO_COUNTERS ioc{};
            if (!h || !::GetProcessIoCounters(h.get(), &ioc)) {
                SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: cannot read own I/O counters");
                ok = false;
            }
        }

        // 2. Can we enumerate processes?
        {
            DWORD pids[16]{};
            DWORD ret = 0;
            if (!::EnumProcesses(pids, sizeof(pids), &ret)) {
                SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL: EnumProcesses failed");
                ok = false;
            }
        }

        // 3. Can we query disk space on the system drive?
        {
            WCHAR winDir[MAX_PATH]{};
            if (::GetWindowsDirectoryW(winDir, MAX_PATH)) {
                std::wstring root = std::wstring(winDir).substr(0, 3);
                ULARGE_INTEGER fa{}, tb{}, tf{};
                if (!::GetDiskFreeSpaceExW(root.c_str(), &fa, &tb, &tf)) {
                    SS_LOG_WARN(LOG_CAT, L"SelfTest WARN: GetDiskFreeSpaceExW on %ls failed", root.c_str());
                }
            }
        }

        SS_LOG_INFO(LOG_CAT, L"SelfTest result: %ls", ok ? L"PASSED" : L"FAILED");
        return ok;
    }

private:
    // ========================================================================
    // INTERNAL TYPES
    // ========================================================================

    struct ProcessTrackingData {
        DiskIoCounters     prevCounters{};
        std::deque<double> writeRateSamples;
        std::deque<double> otherOpsSamples;
        bool               ransomwareAlerted = false;
        bool               fileEnumAlerted   = false;
        bool               firstSample       = true;   // suppress lifetime-counter spike on first observation
        TimePoint          lastSeen;
        std::wstring       processName;
    };

    struct DriveSpaceSnapshot {
        uint64_t  freeBytes = 0;
        TimePoint timestamp;
    };

    struct InternalStats {
        std::atomic<uint64_t> cyclesCompleted{0};
        std::atomic<uint64_t> alertsTriggered{0};
        std::atomic<uint64_t> errorsEncountered{0};
        std::atomic<uint64_t> processesTracked{0};
        std::atomic<uint64_t> ransomwareAlerts{0};
        std::atomic<uint64_t> fileEnumAlerts{0};
        TimePoint startTime = Clock::now();

        void Reset() noexcept {
            cyclesCompleted  = 0;
            alertsTriggered  = 0;
            errorsEncountered = 0;
            processesTracked = 0;
            ransomwareAlerts = 0;
            fileEnumAlerts   = 0;
            startTime        = Clock::now();
        }

        [[nodiscard]] DiskMonitorModuleStats Snapshot() const {
            DiskMonitorModuleStats s{};
            s.cyclesCompleted           = cyclesCompleted.load(std::memory_order_relaxed);
            s.alertsTriggered           = alertsTriggered.load(std::memory_order_relaxed);
            s.errorsEncountered         = errorsEncountered.load(std::memory_order_relaxed);
            s.processesTracked          = processesTracked.load(std::memory_order_relaxed);
            s.ransomwareAlertsTriggered = ransomwareAlerts.load(std::memory_order_relaxed);
            s.fileEnumAlertsTriggered   = fileEnumAlerts.load(std::memory_order_relaxed);
            s.uptimeSeconds = std::chrono::duration<double>(Clock::now() - startTime).count();
            return s;
        }
    };

    // ========================================================================
    // CALLBACK NOTIFICATION (snapshot-then-invoke to avoid deadlock)
    // ========================================================================

    void NotifyHighIo(const ProcessDiskUsage& usage) {
        std::vector<HighIoCallback> cbs;
        {
            std::shared_lock lock(m_cbMutex);
            cbs = m_highIoCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(usage); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"HighIo callback threw: %hs", ex.what());
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
        }
        m_stats.alertsTriggered.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyLowSpace(const DriveInfo& info) {
        std::vector<LowSpaceCallback> cbs;
        {
            std::shared_lock lock(m_cbMutex);
            cbs = m_lowSpaceCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(info); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"LowSpace callback threw: %hs", ex.what());
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
        }
        m_stats.alertsTriggered.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyRansomware(const RansomwareAlert& alert) {
        std::vector<RansomwareCallback> cbs;
        {
            std::shared_lock lock(m_cbMutex);
            cbs = m_ransomwareCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(alert); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"Ransomware callback threw: %hs", ex.what());
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
        }
        m_stats.ransomwareAlerts.fetch_add(1, std::memory_order_relaxed);
        m_stats.alertsTriggered.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyFileEnum(const FileEnumAlert& alert) {
        std::vector<FileEnumCallback> cbs;
        {
            std::shared_lock lock(m_cbMutex);
            cbs = m_fileEnumCallbacks;
        }
        for (const auto& cb : cbs) {
            try { cb(alert); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"FileEnum callback threw: %hs", ex.what());
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...) {
                m_stats.errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            }
        }
        m_stats.fileEnumAlerts.fetch_add(1, std::memory_order_relaxed);
        m_stats.alertsTriggered.fetch_add(1, std::memory_order_relaxed);
    }

    // ========================================================================
    // SYNCHRONIZATION
    // ========================================================================
    mutable std::shared_mutex m_configMutex;  // guards m_config
    mutable std::shared_mutex m_dataMutex;    // guards published results
    mutable std::shared_mutex m_cbMutex;      // guards callback vectors

    // ========================================================================
    // STATE
    // ========================================================================
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::thread       m_thread;
    std::mutex                m_shutdownMutex;
    std::condition_variable   m_shutdownCv;
    DiskMonitorConfig m_config;               // protected by m_configMutex
    InternalStats     m_stats;
    uint32_t          m_selfPid = 0;

    // ========================================================================
    // TRACKING DATA (monitor thread only — no lock needed)
    // ========================================================================
    std::unordered_map<uint32_t, ProcessTrackingData>  m_processTracking;
    TimePoint                                          m_lastProcessUpdate;
    std::unordered_map<std::wstring, DriveSpaceSnapshot> m_prevDriveSpace;
    TimePoint                                          m_lastDriveUpdate;

    // ========================================================================
    // PUBLISHED DATA (protected by m_dataMutex)
    // ========================================================================
    std::unordered_map<uint32_t, ProcessDiskUsage> m_processUsage;
    DiskGlobalStats                                m_globalStats;
    std::vector<DriveInfo>                         m_drives;

    // ========================================================================
    // CALLBACKS (protected by m_cbMutex)
    // ========================================================================
    std::vector<HighIoCallback>     m_highIoCallbacks;
    std::vector<LowSpaceCallback>   m_lowSpaceCallbacks;
    std::vector<RansomwareCallback> m_ransomwareCallbacks;
    std::vector<FileEnumCallback>   m_fileEnumCallbacks;
};

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

DiskMonitor& DiskMonitor::Instance() noexcept {
    static DiskMonitor instance;
    return instance;
}

DiskMonitor::DiskMonitor()
    : m_impl(std::make_unique<DiskMonitorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

DiskMonitor::~DiskMonitor() {
    if (m_impl) m_impl->Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

bool DiskMonitor::Initialize(const DiskMonitorConfig& config) {
    return m_impl->Initialize(config);
}

void DiskMonitor::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool DiskMonitor::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void DiskMonitor::UpdateConfig(const DiskMonitorConfig& config) {
    m_impl->UpdateConfig(config);
}

DiskMonitorConfig DiskMonitor::GetConfig() const {
    return m_impl->GetConfig();
}

std::optional<ProcessDiskUsage> DiskMonitor::GetProcessUsage(uint32_t pid) const {
    return m_impl->GetProcessUsage(pid);
}

std::vector<ProcessDiskUsage> DiskMonitor::GetTopConsumers(size_t count) const {
    return m_impl->GetTopConsumers(count);
}

DiskGlobalStats DiskMonitor::GetGlobalStats() const {
    return m_impl->GetGlobalStats();
}

std::vector<DriveInfo> DiskMonitor::GetDriveInfo() const {
    return m_impl->GetDriveInfo();
}

std::optional<ProcessDiskUsage> DiskMonitor::GetSelfIoUsage() const {
    return m_impl->GetSelfIoUsage();
}

void DiskMonitor::RegisterHighIoCallback(HighIoCallback callback) {
    m_impl->RegisterHighIoCallback(std::move(callback));
}

void DiskMonitor::RegisterLowSpaceCallback(LowSpaceCallback callback) {
    m_impl->RegisterLowSpaceCallback(std::move(callback));
}

void DiskMonitor::RegisterRansomwareCallback(RansomwareCallback callback) {
    m_impl->RegisterRansomwareCallback(std::move(callback));
}

void DiskMonitor::RegisterFileEnumCallback(FileEnumCallback callback) {
    m_impl->RegisterFileEnumCallback(std::move(callback));
}

void DiskMonitor::UnregisterCallbacks() noexcept {
    m_impl->UnregisterCallbacks();
}

DiskMonitorModuleStats DiskMonitor::GetModuleStats() const {
    return m_impl->GetModuleStats();
}

bool DiskMonitor::SelfTest() {
    return m_impl->SelfTest();
}

std::string DiskMonitor::GetVersionString() noexcept {
    return "4.0.0";
}

} // namespace Performance
} // namespace ShadowStrike
