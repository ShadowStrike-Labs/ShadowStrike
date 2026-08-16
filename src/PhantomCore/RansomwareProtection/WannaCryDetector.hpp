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
 * ShadowStrike Ransomware Detection - WANNACRY FAMILY DETECTOR
 * ============================================================================
 *
 * @file WannaCryDetector.hpp
 * @brief Enterprise-grade detection module for WannaCry ransomware worm,
 *        EternalBlue exploitation, and derivative variants (NotPetya,
 *        BadRabbit, EternalRocks).
 *
 * DETECTION CAPABILITIES:
 * - EternalBlue (MS17-010) multi-stage exploit pattern matching
 * - DoublePulsar backdoor detection
 * - SMB port 445 scan rate detection (sliding window per-process)
 * - Kill-switch domain detection and DNS blocking
 * - File artifact scanning (.WNCRY, support files)
 * - Mutex detection (Global\MsWinZonesCacheCounterMutex0)
 * - Service creation monitoring (mssecsvc2.0)
 * - Registry persistence indicators
 * - Multi-variant: WannaCry 1/2, NotPetya, BadRabbit, EternalRocks
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"

namespace ShadowStrike::Ransomware {
    class WannaCryDetectorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

namespace WannaCryConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 2;
    inline constexpr uint32_t VERSION_PATCH = 0;
    inline constexpr const wchar_t* WNCRY_EXTENSION = L".WNCRY";
    inline constexpr const wchar_t* SUPPORT_FILES[] = {
        L"c.wnry", L"r.wnry", L"s.wnry", L"t.wnry", L"u.wnry",
        L"msg\\", L"TaskData\\", L"@WanaDecryptor@.exe"
    };
    inline constexpr const char* KNOWN_KILL_SWITCHES[] = {
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com"
    };
    inline constexpr uint16_t SMB_PORT = 445;
    inline constexpr uint16_t SMB_SCAN_THRESHOLD = 10;
    inline constexpr uint32_t SMB_SCAN_WINDOW_SECS = 5;
    inline constexpr size_t MAX_CACHED_DETECTIONS = 4096;
    inline constexpr uint32_t CACHE_TTL_SECS = 300;
    inline constexpr size_t MAX_SCAN_DEPTH = 5;
    inline constexpr size_t MAX_SCAN_FILES = 10000;
    inline constexpr size_t MAX_MEMORY_SCAN_BYTES = 64 * 1024 * 1024;
    inline constexpr const wchar_t* WANNACRY_MUTEX = L"Global\\MsWinZonesCacheCounterMutex0";
    inline constexpr const wchar_t* WANNACRY_SERVICE_NAME = L"mssecsvc2.0";
    inline constexpr size_t MAX_TRACKED_PIDS = 10000;
    inline constexpr size_t MAX_EVENTS_PER_PID = 1000;
    inline constexpr uint32_t KERNEL_MSG_BLOCK_PROCESS = 0x30;
    inline constexpr uint32_t KERNEL_MSG_NETWORK_ISOLATION = 0x31;
    inline constexpr size_t MAX_CALLBACKS = 16;
}

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

enum class WannaCryVariant : uint8_t {
    Unknown = 0, WannaCry1 = 1, WannaCry2 = 2, WannaCryNoKill = 3,
    WannaCryMod = 4, NotPetya = 5, BadRabbit = 6, EternalRocks = 7
};

enum class WannaCryPhase : uint8_t {
    Unknown = 0, InitialDrop = 1, KillSwitchCheck = 2, ServiceCreation = 3,
    Propagation = 4, Encryption = 5, RansomDisplay = 6, MBROverwrite = 7
};

enum class DetectionConfidence : uint8_t {
    None = 0, Low = 1, Medium = 2, High = 3, Confirmed = 4
};

#ifndef SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
#define SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
enum class ModuleStatus : uint8_t {
    Uninitialized = 0, Initializing = 1, Running = 2, Degraded = 3,
    Paused = 4, Stopping = 5, Stopped = 6, Error = 7
};
#endif

struct WannaCryDetectionResult {
    bool detected = false;
    WannaCryVariant variant = WannaCryVariant::Unknown;
    WannaCryPhase phase = WannaCryPhase::Unknown;
    DetectionConfidence confidence = DetectionConfidence::None;
    uint32_t pid = 0;
    std::wstring processName;
    std::vector<std::string> indicators;
    std::vector<std::wstring> artifactsFound;
    bool killSwitchQueried = false;
    std::string killSwitchDomain;
    bool smbExploitDetected = false;
    bool mutexDetected = false;
    bool serviceDetected = false;
    bool mbrThreatDetected = false;
    uint32_t hostsScanned = 0;
    uint32_t hostsInfected = 0;
    uint32_t filesEncrypted = 0;
    uint32_t smbConnectionCount = 0;
    SystemTimePoint detectionTime;
    [[nodiscard]] std::string ToJson() const;
};

struct EternalBlueIndicator {
    std::string sourceIP;
    std::string destIP;
    SystemTimePoint timestamp;
    bool signatureMatched = false;
    uint8_t exploitStage = 0;

    /// @brief INTENT: policy asked for this exploit to be blocked (blockSMBExploit).
    /// Records what was requested, never what happened.
    bool blockRequested = false;

    /// @brief OUTCOME: the exploit attempt was actually prevented from reaching the target.
    ///
    /// DEFAULT FALSE IS THE CONTRACT. AnalyzeSMBTraffic is a pure inspector: it receives
    /// a std::span<const uint8_t>, so it cannot alter or drop the packet, and it holds no
    /// transport that could reset the connection. It therefore must never set this true.
    /// A caller that genuinely drops the frame (a WFP callout acting on the [[nodiscard]]
    /// return value) is the only thing entitled to set it, and no such caller exists yet.
    bool wasBlocked = false;
};

struct SMBConnectionEvent {
    uint32_t pid = 0;
    std::string sourceIP;
    std::string destIP;
    uint16_t destPort = 0;
    TimePoint timestamp = Clock::now();
};

struct DnsQueryEvent {
    uint32_t pid = 0;
    std::string domain;
    TimePoint timestamp = Clock::now();
};

struct ServiceEvent {
    uint32_t pid = 0;
    std::wstring serviceName;
    std::wstring binaryPath;
    TimePoint timestamp = Clock::now();
};

struct RegistryEvent {
    uint32_t pid = 0;
    std::wstring keyPath;
    std::wstring valueName;
    TimePoint timestamp = Clock::now();
};

struct WannaCryDetectorConfiguration {
    bool enabled = true;
    bool monitorSMB = true;
    bool monitorKillSwitch = true;
    bool monitorArtifacts = true;
    bool monitorPropagation = true;
    bool monitorMutex = true;
    bool monitorServices = true;
    bool monitorRegistry = true;
    bool blockKillSwitchDns = true;
    DetectionConfidence minAlertConfidence = DetectionConfidence::Medium;
    bool autoTerminate = true;
    bool blockSMBExploit = true;
    bool networkIsolation = false;
    bool verboseLogging = false;
    uint16_t smbScanThreshold = WannaCryConstants::SMB_SCAN_THRESHOLD;
    uint32_t smbScanWindowSecs = WannaCryConstants::SMB_SCAN_WINDOW_SECS;
    uint32_t cacheTTLSecs = WannaCryConstants::CACHE_TTL_SECS;
    [[nodiscard]] bool IsValid() const noexcept;
};

struct WannaCryStatistics {
    std::atomic<uint64_t> totalDetections{0};
    std::array<std::atomic<uint64_t>, 8> byVariant{};
    /// @brief EternalBlue signature matches observed. This is a DETECTION count.
    std::atomic<uint64_t> smbExploitsDetected{0};

    /// @brief EternalBlue attempts genuinely prevented from reaching the target.
    ///
    /// HAS NO PRODUCER TODAY, DELIBERATELY. Nothing in this build drops an SMB frame,
    /// so this reads 0 and that zero is accurate rather than misleading. It is kept
    /// because it is the correct counter for a real packet-dropping path; deleting it
    /// would remove the place that path must report to. Read it against
    /// smbExploitsDetected: the difference IS the unclosed enforcement gap, which is
    /// why no separate "requested but not performed" counter is needed here.
    std::atomic<uint64_t> smbExploitsBlocked{0};
    std::atomic<uint64_t> killSwitchQueries{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> hostsProtected{0};
    std::atomic<uint64_t> smbScansDetected{0};
    std::atomic<uint64_t> mutexDetections{0};
    std::atomic<uint64_t> serviceDetections{0};
    TimePoint startTime = Clock::now();

    WannaCryStatistics() noexcept = default;

    WannaCryStatistics(const WannaCryStatistics& o) noexcept : startTime(o.startTime) {
        totalDetections.store(o.totalDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t i = 0; i < byVariant.size(); ++i)
            byVariant[i].store(o.byVariant[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        smbExploitsDetected.store(o.smbExploitsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        smbExploitsBlocked.store(o.smbExploitsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        killSwitchQueries.store(o.killSwitchQueries.load(std::memory_order_relaxed), std::memory_order_relaxed);
        processesTerminated.store(o.processesTerminated.load(std::memory_order_relaxed), std::memory_order_relaxed);
        hostsProtected.store(o.hostsProtected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        smbScansDetected.store(o.smbScansDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        mutexDetections.store(o.mutexDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
        serviceDetections.store(o.serviceDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    }

    WannaCryStatistics& operator=(const WannaCryStatistics& o) noexcept {
        if (this != &o) {
            totalDetections.store(o.totalDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            for (size_t i = 0; i < byVariant.size(); ++i)
                byVariant[i].store(o.byVariant[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
            smbExploitsDetected.store(o.smbExploitsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            smbExploitsBlocked.store(o.smbExploitsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
            killSwitchQueries.store(o.killSwitchQueries.load(std::memory_order_relaxed), std::memory_order_relaxed);
            processesTerminated.store(o.processesTerminated.load(std::memory_order_relaxed), std::memory_order_relaxed);
            hostsProtected.store(o.hostsProtected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            smbScansDetected.store(o.smbScansDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            mutexDetections.store(o.mutexDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            serviceDetections.store(o.serviceDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            startTime = o.startTime;
        }
        return *this;
    }

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/// @brief Copyable, non-atomic snapshot for public API — no atomic fields leaked.
struct WannaCryStatisticsSnapshot {
    uint64_t totalDetections{0};
    std::array<uint64_t, 8> byVariant{};
    uint64_t smbExploitsDetected{0};
    uint64_t smbExploitsBlocked{0};
    uint64_t killSwitchQueries{0};
    uint64_t processesTerminated{0};
    uint64_t hostsProtected{0};
    uint64_t smbScansDetected{0};
    uint64_t mutexDetections{0};
    uint64_t serviceDetections{0};
    int64_t  uptimeSeconds{0};
    [[nodiscard]] std::string ToJson() const;
};

using WannaCryDetectionCallback = std::function<void(const WannaCryDetectionResult&)>;
using EternalBlueCallback = std::function<void(const EternalBlueIndicator&)>;
using SMBScanCallback = std::function<void(uint32_t pid, uint32_t connectionCount)>;

class WannaCryDetector final {
public:
    [[nodiscard]] static WannaCryDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    WannaCryDetector(const WannaCryDetector&) = delete;
    WannaCryDetector& operator=(const WannaCryDetector&) = delete;
    WannaCryDetector(WannaCryDetector&&) = delete;
    WannaCryDetector& operator=(WannaCryDetector&&) = delete;

    [[nodiscard]] bool Initialize(const WannaCryDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;

    [[nodiscard]] bool Detect(uint32_t pid);
    [[nodiscard]] WannaCryDetectionResult DetectEx(uint32_t pid);
    [[nodiscard]] bool IsWannaCryArtifact(std::wstring_view filePath) const;
    [[nodiscard]] bool IsKillSwitchDomain(std::string_view domain) const;
    [[nodiscard]] bool AnalyzeSMBTraffic(std::span<const uint8_t> packet,
                                         std::string_view sourceIP,
                                         std::string_view destIP);
    [[nodiscard]] bool CheckKnownHash(const Hash256& hash) const;
    [[nodiscard]] std::vector<std::wstring> ScanForArtifacts(std::wstring_view directory);
    [[nodiscard]] bool CheckMutex() const;
    [[nodiscard]] bool CheckServiceInstallation() const;
    [[nodiscard]] bool CheckRegistryIndicators() const;

    void OnNetworkConnection(const SMBConnectionEvent& event);
    void OnDnsQuery(const DnsQueryEvent& event);
    void OnServiceCreated(const ServiceEvent& event);
    void OnRegistryModified(const RegistryEvent& event);
    void OnProcessCreated(uint32_t pid, std::wstring_view processPath,
                          std::wstring_view commandLine);

    [[nodiscard]] bool IsSystemVulnerable() const;
    [[nodiscard]] bool IsPatchInstalled() const;
    [[nodiscard]] std::string GetSMBVersionInfo() const;

    void AddKillSwitchDomain(std::string_view domain);
    void AddKnownHash(const Hash256& hash);
    void UpdatePatternsFromThreatIntel();
    void RegisterWithRansomwareDetector();

    void SetDetectionCallback(WannaCryDetectionCallback callback);
    void SetEternalBlueCallback(EternalBlueCallback callback);
    void SetSMBScanCallback(SMBScanCallback callback);

    [[nodiscard]] WannaCryStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

    // ── Kernel Bridge ─────────────────────────────────────────────────────
    /// @brief Called from kernel process creation callback to detect WannaCry executables.
    void OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                               std::wstring_view commandLine, bool isCreate);
    /// @brief Called from kernel image load callback to detect WannaCry DLLs/payloads.
    void OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                           uint64_t imageBase, size_t imageSize);
    /// @brief Request kernel to block a process via IPC.
    [[nodiscard]] bool RequestKernelProcessBlock(uint32_t processId,
                                                 const std::wstring& reason);

    // ── Cross-Module Wiring ───────────────────────────────────────────────
    /// @brief Report WannaCry detection to AlertSystem for SOC visibility.
    void ReportThreatToAlertSystem(const WannaCryDetectionResult& result);
    /// @brief Report detection telemetry to TelemetryCollector.
    void ReportDetectionTelemetry(const WannaCryDetectionResult& result);
    /// @brief Report threat indicators to BehaviorAnalyzer for correlation.
    void ReportThreatToBehaviorAnalyzer(const WannaCryDetectionResult& result);

private:
    WannaCryDetector();
    ~WannaCryDetector();
    std::unique_ptr<WannaCryDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

[[nodiscard]] std::string_view GetWannaCryVariantName(WannaCryVariant variant) noexcept;
[[nodiscard]] std::string_view GetWannaCryPhaseName(WannaCryPhase phase) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

#define SS_DETECT_WANNACRY(pid) \
    ::ShadowStrike::Ransomware::WannaCryDetector::Instance().Detect(pid)

#define SS_IS_VULNERABLE_TO_ETERNALBLUE() \
    ::ShadowStrike::Ransomware::WannaCryDetector::Instance().IsSystemVulnerable()

