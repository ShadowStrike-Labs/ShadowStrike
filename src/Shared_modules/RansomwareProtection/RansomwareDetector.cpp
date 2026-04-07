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
 * ShadowStrike Ransomware Protection - DETECTOR ORCHESTRATOR IMPLEMENTATION
 * ============================================================================
 *
 * @file RansomwareDetector.cpp
 * @brief Enterprise-grade ransomware detection orchestrator with full
 *        subsystem wiring, kernel event routing, and emergency response.
 *
 * SUBSYSTEM WIRING:
 * =================
 * Sibling modules (BackupProtector, FileBackupManager, HoneypotManager,
 * LockyDetector, WannaCryDetector, RansomwareDecryptor, ShadowCopyProtector,
 * VolumeSnapshotService) are integrated via callback injection.
 * Application startup code initialises each module independently, then
 * wires response callbacks into this orchestrator. Sub-detectors feed
 * indicators into OnSubDetectorIndicator(). This compile-firewall design
 * avoids ModuleStatus enum collision between independently-defined headers.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "RansomwareDetector.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Core/Process/ProcessKiller.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <numeric>
#include <random>
#include <filesystem>
#include <deque>

#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// ANONYMOUS NAMESPACE UTILITIES
// ============================================================================

namespace {

    const std::unordered_set<std::wstring> COMPRESSED_EXTENSIONS = {
        L".zip", L".rar", L".7z", L".gz", L".tar", L".bz2", L".xz",
        L".jpg", L".jpeg", L".png", L".gif", L".webp", L".mp3", L".mp4",
        L".avi", L".mkv", L".mov", L".pdf", L".docx", L".xlsx", L".pptx"
    };

    const std::unordered_map<std::wstring, RansomwareFamily> KNOWN_EXTENSIONS = {
        {L".wncry",     RansomwareFamily::WannaCry},
        {L".locky",     RansomwareFamily::Locky},
        {L".encrypted", RansomwareFamily::CryptoLocker},
        {L".vvv",       RansomwareFamily::TeslaCrypt},
        {L".cerber",    RansomwareFamily::Cerber},
        {L".cerber2",   RansomwareFamily::Cerber},
        {L".cerber3",   RansomwareFamily::Cerber},
        {L".ryuk",      RansomwareFamily::Ryuk},
        {L".revil",     RansomwareFamily::REvil},
        {L".lockbit",   RansomwareFamily::LockBit},
        {L".hive",      RansomwareFamily::Hive},
        {L".play",      RansomwareFamily::Play},
        {L".clop",      RansomwareFamily::Clop},
        {L".maze",      RansomwareFamily::Maze}
    };

    void PruneTimestamps(std::vector<TimePoint>& timestamps, uint32_t windowSecs) {
        auto cutoff = Clock::now() - std::chrono::seconds(windowSecs);
        std::erase_if(timestamps, [&](const TimePoint& tp) { return tp < cutoff; });
    }

    std::wstring NormalizeExtension(std::wstring_view path) {
        fs::path p(path);
        std::wstring ext = p.extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        return ext;
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class RansomwareDetectorImpl final {
public:
    RansomwareDetectorImpl() = default;
    ~RansomwareDetectorImpl() = default;

    RansomwareDetectorImpl(const RansomwareDetectorImpl&) = delete;
    RansomwareDetectorImpl& operator=(const RansomwareDetectorImpl&) = delete;
    RansomwareDetectorImpl(RansomwareDetectorImpl&&) = delete;
    RansomwareDetectorImpl& operator=(RansomwareDetectorImpl&&) = delete;

    // Module state
    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    RansomwareDetectorConfiguration m_config;
    DetectionStatistics m_stats;

    // Process tracking (unique_ptr avoids IOStats copy/move issues)
    std::unordered_map<uint32_t, std::unique_ptr<IOStats>> m_processStats;
    mutable std::shared_mutex m_statsMutex;

    // Honeypot registry
    std::unordered_set<std::wstring> m_honeypots;
    mutable std::shared_mutex m_honeypotMutex;

    // Whitelists
    std::unordered_set<uint32_t> m_whitelistedPids;
    mutable std::shared_mutex m_whitelistMutex;

    // Recovery PIDs (decryptor I/O exempt from detection)
    std::unordered_set<uint32_t> m_recoveryPids;
    mutable std::shared_mutex m_recoveryMutex;

    // Callbacks (copied out before invocation to prevent deadlock)
    DetectionCallback          m_detectionCallback;
    BlockCallback              m_blockCallback;
    PreWriteCallback           m_preWriteCallback;
    EmergencyBackupCallback    m_emergencyBackupCb;
    EmergencySnapshotCallback  m_emergencySnapshotCb;
    LockdownCallback           m_lockdownCb;
    RecoveryCallback           m_recoveryCb;
    mutable std::mutex         m_callbackMutex;

    // Detection ring buffer
    std::deque<DetectionEvent> m_recentDetections;
    mutable std::shared_mutex m_detectionsMutex;

    // Family signatures
    std::unordered_map<RansomwareFamily, FamilySignature> m_familySignatures;
    mutable std::shared_mutex m_signaturesMutex;

    // Containment & response-once
    std::atomic<bool>  m_containmentMode{false};
    std::unordered_set<uint32_t> m_respondedPids;
    mutable std::mutex m_responseMutex;

    std::atomic<uint64_t> m_nextEventId{1};

    // === HELPERS ===

    IOStats& GetOrCreateStats(uint32_t pid) {
        {
            std::shared_lock lk(m_statsMutex);
            auto it = m_processStats.find(pid);
            if (it != m_processStats.end()) return *it->second;
        }
        std::unique_lock lk(m_statsMutex);
        auto it = m_processStats.find(pid);
        if (it != m_processStats.end()) return *it->second;

        auto ptr = std::make_unique<IOStats>();
        ptr->pid = pid;
        ptr->firstActivity = Clock::now();
        ptr->lastActivity  = ptr->firstActivity;
        try {
            ptr->processName = Utils::ProcessUtils::GetProcessName(pid).value_or(L"Unknown");
        } catch (...) {
            ptr->processName = L"Unknown";
        }
        auto& ref = *ptr;
        m_processStats.emplace(pid, std::move(ptr));
        if (m_processStats.size() > RansomwareConstants::MAX_TRACKED_PROCESSES)
            CleanupOldStats();
        return ref;
    }

    void CleanupOldStats() {
        auto expiry = Clock::now() - std::chrono::seconds(RansomwareConstants::STATS_RETENTION_SECS);
        for (auto it = m_processStats.begin(); it != m_processStats.end(); ) {
            // Lock each IOStats to safely read lastActivity (non-atomic)
            bool expired;
            { std::lock_guard lk(it->second->mutex); expired = it->second->lastActivity < expiry; }
            expired ? it = m_processStats.erase(it) : ++it;
        }
    }

    void UpdateWriteStats(IOStats& s, size_t bytes, bool isHighEntropy) {
        std::lock_guard lk(s.mutex);
        auto now = Clock::now();
        s.lastActivity = now;
        s.writeCount.fetch_add(1, std::memory_order_relaxed);
        s.bytesWritten.fetch_add(bytes, std::memory_order_relaxed);
        s.writeTimestamps.push_back(now);
        if (isHighEntropy) {
            s.highEntropyWrites.fetch_add(1, std::memory_order_relaxed);
            s.encryptedBytesWritten.fetch_add(bytes, std::memory_order_relaxed);
        }
        PruneTimestamps(s.writeTimestamps, m_config.rateWindowSecs);
    }

    void UpdateRenameStats(IOStats& s, std::wstring_view oldExt, std::wstring_view newExt) {
        std::lock_guard lk(s.mutex);
        s.renameCount.fetch_add(1, std::memory_order_relaxed);
        s.lastActivity = Clock::now();
        s.renameTimestamps.push_back(Clock::now());
        if (!oldExt.empty()) s.originalExtensions.emplace(oldExt);
        if (!newExt.empty()) s.newExtensions.emplace(newExt);
        PruneTimestamps(s.renameTimestamps, m_config.rateWindowSecs);
    }

    void UpdateDeleteStats(IOStats& s) {
        std::lock_guard lk(s.mutex);
        s.deleteCount.fetch_add(1, std::memory_order_relaxed);
        s.lastActivity = Clock::now();
        s.deleteTimestamps.push_back(Clock::now());
        PruneTimestamps(s.deleteTimestamps, m_config.rateWindowSecs);
    }

    void RecordDetection(const DetectionEvent& event) {
        std::unique_lock lk(m_detectionsMutex);
        m_recentDetections.push_back(event);
        while (m_recentDetections.size() > RansomwareConstants::MAX_RECENT_DETECTIONS)
            m_recentDetections.pop_front();
    }

    void FireDetectionCallback(const DetectionEvent& event) noexcept {
        DetectionCallback cb;
        { std::lock_guard lk(m_callbackMutex); cb = m_detectionCallback; }
        if (cb) {
            try { cb(event); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"RansomwareDetector", L"Detection callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_ERROR(L"RansomwareDetector", L"Detection callback threw unknown exception");
            }
        }

        // ── Direct AlertSystem wiring (fallback even if callback not set) ──
        try {
            using namespace Communication;
            if (AlertSystem::HasInstance() &&
                event.verdict >= DetectionVerdict::Suspicious) {
                auto severity = AlertSeverity::Medium;
                if (event.verdict >= DetectionVerdict::ConfirmedRansom)
                    severity = AlertSeverity::Emergency;
                else if (event.verdict >= DetectionVerdict::PossibleRansom)
                    severity = AlertSeverity::Critical;

                std::string subject = "Ransomware " +
                    std::string(GetVerdictName(event.verdict)) +
                    " (PID " + std::to_string(event.pid) + ")";
                (void)AlertSystem::Instance().RaiseAlert(
                    severity, AlertType::ThreatDetection,
                    subject, event.ToJson(), "RansomwareDetector");
            }
        } catch (...) {}

        // ── Direct TelemetryCollector wiring ──
        try {
            using namespace Communication;
            if (TelemetryCollector::HasInstance()) {
                std::map<std::string, std::string> data;
                data["pid"] = std::to_string(event.pid);
                data["verdict"] = std::string(GetVerdictName(event.verdict));
                data["action"] = std::string(GetActionName(event.action));
                data["family"] = std::string(GetFamilyName(event.family));
                data["confidence"] = std::to_string(event.confidence);
                data["entropy"] = std::to_string(
                    event.entropyResult ? event.entropyResult->shannonEntropy : 0.0);
                data["techniques"] = std::to_string(event.detectionFlags);
                TelemetryCollector::Instance().RecordCustom("ransomware_detection", data);
            }
        } catch (...) {}
    }

    void FireBlockCallback(uint32_t pid, const std::wstring& reason) noexcept {
        BlockCallback cb;
        { std::lock_guard lk(m_callbackMutex); cb = m_blockCallback; }
        if (!cb) return;
        try { cb(pid, reason); }
        catch (...) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Block callback threw for PID %u", pid);
        }
    }

    bool IsRecoveryPid(uint32_t pid) const {
        std::shared_lock lk(m_recoveryMutex);
        return m_recoveryPids.count(pid) > 0;
    }

    bool MarkRespondedOnce(uint32_t pid) {
        std::lock_guard lk(m_responseMutex);
        return m_respondedPids.insert(pid).second;
    }

    void ExecuteResponsePipeline(uint32_t pid, DetectionEvent& event) {
        if (!MarkRespondedOnce(pid)) return;
        event.action = DetectionAction::BlockAndKill;
        m_stats.operationsBlocked.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_FATAL(L"RansomwareDetector",
            L"=== RANSOMWARE CONFIRMED === PID %u  confidence=%.2f  family=%u",
            pid, event.confidence, static_cast<unsigned>(event.family));

        // 0. Request kernel process block via IPC (fastest path)
        try {
            using namespace Communication;
            if (IPCManager::HasInstance() && IPCManager::Instance().IsFilterPortConnected()) {
#pragma pack(push, 1)
                struct { uint32_t msgType; uint32_t pid; } blockReq{0x30, pid};
#pragma pack(pop)
                (void)IPCManager::Instance().SendToKernel(&blockReq, sizeof(blockReq));
            }
        } catch (...) {}

        // 1. Terminate process tree via ProcessKiller
        auto killResult = Core::Process::ProcessKiller::TerminateTree(pid);
        if (killResult == Core::Process::KillResult::Success ||
            killResult == Core::Process::KillResult::AlreadyDead) {
            m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"RansomwareDetector", L"Process tree %u terminated", pid);
        } else {
            SS_LOG_ERROR(L"RansomwareDetector",
                L"Failed to terminate PID %u (result=%u)", pid, static_cast<unsigned>(killResult));
        }

        // 2. Emergency backup
        { EmergencyBackupCallback cb;
          { std::lock_guard lk(m_callbackMutex); cb = m_emergencyBackupCb; }
          if (cb) { try { cb(pid); } catch (...) {
              SS_LOG_ERROR(L"RansomwareDetector", L"Emergency backup callback threw for PID %u", pid);
          }}
        }

        // 3. Emergency volume snapshot
        { EmergencySnapshotCallback cb;
          { std::lock_guard lk(m_callbackMutex); cb = m_emergencySnapshotCb; }
          if (cb) { try { cb(); } catch (...) {
              SS_LOG_ERROR(L"RansomwareDetector", L"Emergency snapshot callback threw");
          }}
        }

        // 4. Enter containment (lockdown)
        if (!m_containmentMode.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"RansomwareDetector", L"Entering ransomware containment mode");
            LockdownCallback cb;
            { std::lock_guard lk(m_callbackMutex); cb = m_lockdownCb; }
            if (cb) { try { cb(); } catch (...) {} }
        }

        // 5. Trigger decryptor recovery
        { RecoveryCallback cb;
          { std::lock_guard lk(m_callbackMutex); cb = m_recoveryCb; }
          if (cb) { try { cb(pid, event.family); } catch (...) {
              SS_LOG_ERROR(L"RansomwareDetector", L"Recovery callback threw for PID %u", pid);
          }}
        }

        // 6. Fire external callbacks
        FireDetectionCallback(event);
        FireBlockCallback(pid, L"Ransomware activity confirmed — full response executed");
        RecordDetection(event);
    }

    double ComputeConfidence(uint16_t flags) const {
        double score = 0.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::HoneypotAccess))    score += 40.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::KnownFamily))       score += 30.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::EntropyAnalysis))    score += 15.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::RapidWrites))        score += 10.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::MassRename))         score += 15.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::MassDelete))         score += 10.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::ExtensionChange))    score += 10.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::VssDestruction))     score += 25.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::RansomNote))         score += 20.0;
        if (flags & static_cast<uint16_t>(DetectionTechnique::C2Communication))    score += 15.0;
        return std::clamp(score / 100.0, 0.0, 1.0);
    }

    double GetWriteRateUnsafe(const IOStats& s) const {
        if (s.writeTimestamps.empty()) return 0.0;
        return static_cast<double>(s.writeTimestamps.size()) / static_cast<double>(m_config.rateWindowSecs);
    }
    double GetRenameRateUnsafe(const IOStats& s) const {
        if (s.renameTimestamps.empty()) return 0.0;
        return static_cast<double>(s.renameTimestamps.size()) / static_cast<double>(m_config.rateWindowSecs);
    }
    double GetDeleteRateUnsafe(const IOStats& s) const {
        if (s.deleteTimestamps.empty()) return 0.0;
        return static_cast<double>(s.deleteTimestamps.size()) / static_cast<double>(m_config.rateWindowSecs);
    }
};

// ============================================================================
// IOStats CONSTRUCTORS
// ============================================================================

IOStats::IOStats() noexcept
    : pid(0), firstActivity(Clock::now()), lastActivity(firstActivity),
      riskLevel(ProcessRiskLevel::Unknown), detectionFlags(0),
      confidenceScore(0.0), isBlocked(false)
{}

IOStats::IOStats(const IOStats& o)
    : pid(o.pid)
{
    // Lock source FIRST to prevent data races on ALL non-atomic fields
    std::lock_guard lk(o.mutex);

    // Copy non-atomic fields under lock
    processName         = o.processName;
    riskLevel           = o.riskLevel;
    detectionFlags      = o.detectionFlags;
    confidenceScore     = o.confidenceScore;
    isBlocked           = o.isBlocked;
    affectedExtensions  = o.affectedExtensions;
    originalExtensions  = o.originalExtensions;
    newExtensions       = o.newExtensions;
    affectedDirectories = o.affectedDirectories;
    firstActivity       = o.firstActivity;
    lastActivity        = o.lastActivity;
    writeTimestamps     = o.writeTimestamps;
    renameTimestamps    = o.renameTimestamps;
    deleteTimestamps    = o.deleteTimestamps;

    // Atomics: relaxed load is safe even without the lock
    writeCount.store(o.writeCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    renameCount.store(o.renameCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    deleteCount.store(o.deleteCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    highEntropyWrites.store(o.highEntropyWrites.load(std::memory_order_relaxed), std::memory_order_relaxed);
    bytesWritten.store(o.bytesWritten.load(std::memory_order_relaxed), std::memory_order_relaxed);
    encryptedBytesWritten.store(o.encryptedBytesWritten.load(std::memory_order_relaxed), std::memory_order_relaxed);
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> RansomwareDetector::s_instanceCreated{false};

RansomwareDetector& RansomwareDetector::Instance() noexcept {
    static RansomwareDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool RansomwareDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

RansomwareDetector::RansomwareDetector()
    : m_impl(std::make_unique<RansomwareDetectorImpl>())
{
    SS_LOG_INFO(L"RansomwareDetector", L"Instance created");
}

RansomwareDetector::~RansomwareDetector() {
    try { Shutdown(); } catch (...) {}
}

bool RansomwareDetector::Initialize(const RansomwareDetectorConfiguration& config) {
    try {
        std::unique_lock lk(m_impl->m_mutex);
        auto st = m_impl->m_status.load(std::memory_order_acquire);
        if (st != ModuleStatus::Uninitialized && st != ModuleStatus::Stopped) {
            SS_LOG_WARN(L"RansomwareDetector", L"Already initialized (status=%u)", static_cast<unsigned>(st));
            return false;
        }
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Invalid configuration supplied");
            return false;
        }
        m_impl->m_status.store(ModuleStatus::Initializing, std::memory_order_release);
        m_impl->m_config = config;
        m_impl->m_stats.Reset();
        m_impl->m_recentDetections.clear();
        m_impl->m_respondedPids.clear();
        m_impl->m_containmentMode.store(false, std::memory_order_release);

        // Seed default family signatures from known extensions
        {
            std::unique_lock sl(m_impl->m_signaturesMutex);
            for (const auto& [ext, fam] : KNOWN_EXTENSIONS) {
                auto& sig = m_impl->m_familySignatures[fam];
                sig.family = fam;
                sig.extensions.push_back(ext);
            }
        }

        m_impl->m_status.store(ModuleStatus::Running, std::memory_order_release);
        SS_LOG_INFO(L"RansomwareDetector", L"Initialized (v%hs)", GetVersionString().c_str());
        return true;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"Init failed: %hs", ex.what());
        m_impl->m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_FATAL(L"RansomwareDetector", L"Init failed (unknown exception)");
        m_impl->m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void RansomwareDetector::Shutdown() {
    try {
        std::unique_lock lk(m_impl->m_mutex);
        auto st = m_impl->m_status.load(std::memory_order_acquire);
        if (st == ModuleStatus::Uninitialized || st == ModuleStatus::Stopped) return;
        m_impl->m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        { std::unique_lock sl(m_impl->m_statsMutex); m_impl->m_processStats.clear(); }
        { std::unique_lock hl(m_impl->m_honeypotMutex); m_impl->m_honeypots.clear(); }
        { std::unique_lock dl(m_impl->m_detectionsMutex); m_impl->m_recentDetections.clear(); }
        {
            std::lock_guard cl(m_impl->m_callbackMutex);
            m_impl->m_detectionCallback = nullptr; m_impl->m_blockCallback = nullptr;
            m_impl->m_preWriteCallback = nullptr; m_impl->m_emergencyBackupCb = nullptr;
            m_impl->m_emergencySnapshotCb = nullptr; m_impl->m_lockdownCb = nullptr;
            m_impl->m_recoveryCb = nullptr;
        }
        { std::lock_guard rl(m_impl->m_responseMutex); m_impl->m_respondedPids.clear(); }
        m_impl->m_containmentMode.store(false, std::memory_order_release);
        m_impl->m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(L"RansomwareDetector", L"Shutdown complete");
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"Shutdown error: %hs", ex.what());
    }
}

bool RansomwareDetector::IsInitialized() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire) == ModuleStatus::Running;
}

ModuleStatus RansomwareDetector::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// WRITE ANALYSIS
// ============================================================================

bool RansomwareDetector::AnalyzeWrite(uint32_t pid,
                                      const std::vector<uint8_t>& buffer,
                                      const std::wstring& filePath) {
    return AnalyzeWrite(pid, std::span<const uint8_t>(buffer), filePath);
}

bool RansomwareDetector::AnalyzeWrite(uint32_t pid,
                                      std::span<const uint8_t> buffer,
                                      std::wstring_view filePath) {
    auto result = AnalyzeWriteEx(pid, buffer, filePath);
    return result.action == DetectionAction::Block ||
           result.action == DetectionAction::BlockAndKill;
}

DetectionEvent RansomwareDetector::AnalyzeWriteEx(uint32_t pid,
                                                  std::span<const uint8_t> buffer,
                                                  std::wstring_view filePath) {
    DetectionEvent event;
    event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.filePath = filePath;
    event.operationType = FileOperationType::Write;

    try {
        if (!IsInitialized()) return event;
        if (IsProcessWhitelisted(pid)) return event;
        if (m_impl->IsRecoveryPid(pid)) return event;

        IOStats& stats = m_impl->GetOrCreateStats(pid);
        m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

        // 1. Honeypot check
        if (IsHoneypot(filePath)) {
            OnHoneypotTouched(pid, std::wstring(filePath));
            event.verdict = DetectionVerdict::Honeypot;
            event.action = DetectionAction::BlockAndKill;
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::HoneypotAccess);
            event.confidence = 1.0;
            return event;
        }

        // 2. Entropy analysis
        bool isHighEntropy = false;
        if (m_impl->m_config.enableEntropyAnalysis && !buffer.empty()) {
            if (!IsCompressedType(filePath)) {
                auto entropy = AnalyzeEntropy(buffer);
                event.entropyResult = entropy;
                if (entropy.isEncrypted) {
                    isHighEntropy = true;
                    event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::EntropyAnalysis);
                }
            }
        }

        // 3. Update stats
        m_impl->UpdateWriteStats(stats, buffer.size(), isHighEntropy);

        // 4. Rate analysis (read under stats lock)
        if (m_impl->m_config.enableRateMonitoring) {
            std::lock_guard lk(stats.mutex);
            if (m_impl->GetWriteRateUnsafe(stats) > m_impl->m_config.maxWritesPerSecond)
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::RapidWrites);
        }

        // 5. Known extension check
        std::wstring ext = NormalizeExtension(filePath);
        if (KNOWN_EXTENSIONS.count(ext)) {
            event.family = KNOWN_EXTENSIONS.at(ext);
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::KnownFamily);
        }

        // 6. Protected path bonus
        if (IsProtectedPath(filePath) && isHighEntropy)
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::DirectoryTraversal);

        // 7. Compute confidence from composite flags
        event.confidence = m_impl->ComputeConfidence(event.detectionFlags);

        // 8. Determine verdict and action
        if (event.confidence >= RansomwareConstants::MIN_KILL_CONFIDENCE) {
            event.verdict = DetectionVerdict::ConfirmedRansom;
            if (m_impl->m_config.enableAutoBlock)
                m_impl->ExecuteResponsePipeline(pid, event);
        } else if (event.confidence >= RansomwareConstants::MIN_BLOCK_CONFIDENCE) {
            event.verdict = DetectionVerdict::PossibleRansom;
            if (m_impl->m_config.enableAutoBlock) {
                event.action = DetectionAction::Block;
                stats.isBlocked = true;
                m_impl->m_stats.operationsBlocked.fetch_add(1, std::memory_order_relaxed);
                m_impl->FireDetectionCallback(event);
                m_impl->FireBlockCallback(pid, L"High-confidence ransomware indicators");
                m_impl->RecordDetection(event);
            }
        } else if (event.confidence >= RansomwareConstants::MIN_ALERT_CONFIDENCE) {
            event.verdict = DetectionVerdict::Suspicious;
            event.action = DetectionAction::AllowWithBackup;
            m_impl->FireDetectionCallback(event);
            m_impl->RecordDetection(event);
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"AnalyzeWriteEx failed: %hs", ex.what());
    }
    return event;
}

// ============================================================================
// RENAME ANALYSIS
// ============================================================================

bool RansomwareDetector::AnalyzeRename(uint32_t pid,
                                       const std::wstring& oldPath,
                                       const std::wstring& newPath) {
    auto result = AnalyzeRenameEx(pid, oldPath, newPath);
    return result.action == DetectionAction::Block || result.action == DetectionAction::BlockAndKill;
}

DetectionEvent RansomwareDetector::AnalyzeRenameEx(uint32_t pid,
                                                   std::wstring_view oldPath,
                                                   std::wstring_view newPath) {
    DetectionEvent event;
    event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.filePath = newPath;
    event.operationType = FileOperationType::Rename;

    try {
        if (!IsInitialized()) return event;
        if (IsProcessWhitelisted(pid)) return event;
        if (m_impl->IsRecoveryPid(pid)) return event;

        IOStats& stats = m_impl->GetOrCreateStats(pid);
        m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

        std::wstring extOld = NormalizeExtension(oldPath);
        std::wstring extNew = NormalizeExtension(newPath);
        m_impl->UpdateRenameStats(stats, extOld, extNew);

        // Extension change detection
        if (extOld != extNew) {
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::ExtensionChange);
            if (KNOWN_EXTENSIONS.count(extNew)) {
                event.family = KNOWN_EXTENSIONS.at(extNew);
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::KnownFamily);
            }
        }

        // Mass rename detection
        {
            std::lock_guard lk(stats.mutex);
            if (m_impl->GetRenameRateUnsafe(stats) > m_impl->m_config.maxRenamesPerSecond)
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::MassRename);
        }

        event.confidence = m_impl->ComputeConfidence(event.detectionFlags);

        if (event.confidence >= RansomwareConstants::MIN_KILL_CONFIDENCE) {
            event.verdict = DetectionVerdict::ConfirmedRansom;
            if (m_impl->m_config.enableAutoBlock)
                m_impl->ExecuteResponsePipeline(pid, event);
        } else if (event.confidence >= RansomwareConstants::MIN_BLOCK_CONFIDENCE) {
            event.verdict = DetectionVerdict::PossibleRansom;
            if (m_impl->m_config.enableAutoBlock) {
                event.action = DetectionAction::Block;
                m_impl->m_stats.operationsBlocked.fetch_add(1, std::memory_order_relaxed);
                m_impl->FireDetectionCallback(event);
                m_impl->FireBlockCallback(pid, L"Ransomware extension or mass rename");
                m_impl->RecordDetection(event);
            }
        } else if (event.confidence >= RansomwareConstants::MIN_ALERT_CONFIDENCE) {
            event.verdict = DetectionVerdict::Suspicious;
            m_impl->FireDetectionCallback(event);
            m_impl->RecordDetection(event);
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"AnalyzeRenameEx failed: %hs", ex.what());
    }
    return event;
}

// ============================================================================
// DELETE ANALYSIS
// ============================================================================

bool RansomwareDetector::AnalyzeDelete(uint32_t pid, std::wstring_view filePath) {
    auto r = AnalyzeDeleteEx(pid, filePath);
    return r.action == DetectionAction::Block || r.action == DetectionAction::BlockAndKill;
}

DetectionEvent RansomwareDetector::AnalyzeDeleteEx(uint32_t pid, std::wstring_view filePath) {
    DetectionEvent event;
    event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.filePath = filePath;
    event.operationType = FileOperationType::Delete;

    try {
        if (!IsInitialized()) return event;
        if (IsProcessWhitelisted(pid)) return event;
        if (m_impl->IsRecoveryPid(pid)) return event;

        IOStats& stats = m_impl->GetOrCreateStats(pid);
        m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);
        m_impl->UpdateDeleteStats(stats);

        {
            std::lock_guard lk(stats.mutex);
            if (m_impl->GetDeleteRateUnsafe(stats) > RansomwareConstants::MAX_DELETES_PER_SECOND)
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::MassDelete);
        }

        if (IsProtectedPath(filePath))
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::BackupDeletion);

        event.confidence = m_impl->ComputeConfidence(event.detectionFlags);

        if (event.confidence >= RansomwareConstants::MIN_BLOCK_CONFIDENCE) {
            event.verdict = DetectionVerdict::PossibleRansom;
            if (m_impl->m_config.enableAutoBlock) {
                event.action = DetectionAction::Block;
                m_impl->m_stats.operationsBlocked.fetch_add(1, std::memory_order_relaxed);
                m_impl->FireDetectionCallback(event);
                m_impl->FireBlockCallback(pid, L"Mass file deletion detected");
                m_impl->RecordDetection(event);
            }
        } else if (event.confidence >= RansomwareConstants::MIN_ALERT_CONFIDENCE) {
            event.verdict = DetectionVerdict::Suspicious;
            m_impl->FireDetectionCallback(event);
            m_impl->RecordDetection(event);
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"AnalyzeDeleteEx failed: %hs", ex.what());
    }
    return event;
}

// ============================================================================
// HONEYPOT INTEGRATION
// ============================================================================

void RansomwareDetector::OnHoneypotTouched(uint32_t pid, const std::wstring& filePath) {
    try {
        SS_LOG_FATAL(L"RansomwareDetector",
            L"HONEYPOT TOUCHED by PID %u - File: %ls", pid, filePath.c_str());
        m_impl->m_stats.honeypotTriggers.fetch_add(1, std::memory_order_relaxed);

        // Immediate process tree kill via ProcessKiller (RAII, no raw HANDLEs)
        if (m_impl->m_config.enableProcessKill) {
            auto result = Core::Process::ProcessKiller::TerminateTree(pid);
            if (result == Core::Process::KillResult::Success ||
                result == Core::Process::KillResult::AlreadyDead) {
                m_impl->m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(L"RansomwareDetector", L"Process tree %u terminated (honeypot)", pid);
            } else {
                SS_LOG_ERROR(L"RansomwareDetector",
                    L"Failed to terminate PID %u after honeypot touch (result=%u)",
                    pid, static_cast<unsigned>(result));
            }
        }

        DetectionEvent event;
        event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = std::chrono::system_clock::now();
        event.pid = pid;
        event.filePath = filePath;
        event.verdict = DetectionVerdict::Honeypot;
        event.action = DetectionAction::BlockAndKill;
        event.detectionFlags = static_cast<uint16_t>(DetectionTechnique::HoneypotAccess);
        event.confidence = 1.0;

        // Trigger full response pipeline (backup, snapshot, lockdown)
        m_impl->ExecuteResponsePipeline(pid, event);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"OnHoneypotTouched failed: %hs", ex.what());
    }
}

void RansomwareDetector::RegisterHoneypot(std::wstring_view filePath) {
    std::unique_lock lk(m_impl->m_honeypotMutex);
    m_impl->m_honeypots.emplace(filePath);
}

void RansomwareDetector::UnregisterHoneypot(std::wstring_view filePath) {
    std::unique_lock lk(m_impl->m_honeypotMutex);
    m_impl->m_honeypots.erase(std::wstring(filePath));
}

bool RansomwareDetector::IsHoneypot(std::wstring_view filePath) const {
    std::shared_lock lk(m_impl->m_honeypotMutex);
    return m_impl->m_honeypots.count(std::wstring(filePath)) > 0;
}

// ============================================================================
// KERNEL EVENT HANDLERS
// ============================================================================

void RansomwareDetector::OnProcessCreated(uint32_t pid,
                                          std::wstring_view imagePath,
                                          std::wstring_view commandLine) {
    if (!IsInitialized()) return;
    if (IsProcessWhitelisted(pid)) return;

    m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

    // Route event to detection callback for sub-detectors to consume.
    // BackupProtector and ShadowCopyProtector are wired externally and consume
    // process events directly from the kernel. Here we track the process and
    // fire the detection callback so external listeners can correlate.
    auto& stats = m_impl->GetOrCreateStats(pid);
    try { stats.processName = std::wstring(imagePath); } catch (...) {}

    SS_LOG_DEBUG(L"RansomwareDetector",
        L"Process created: PID=%u path=%ls", pid,
        std::wstring(imagePath).c_str());
}

void RansomwareDetector::OnNetworkEvent(uint32_t pid,
                                        std::string_view srcIP,
                                        std::string_view dstIP,
                                        uint16_t dstPort,
                                        std::span<const uint8_t> payload) {
    if (!IsInitialized()) return;
    if (IsProcessWhitelisted(pid)) return;
    m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

    // SMB (port 445) and C2 indicators feed sub-detector score.
    // Sub-detectors call OnSubDetectorIndicator() with weighted scores.
    // Log the event for forensic tracing.
    if (dstPort == 445 && !payload.empty()) {
        SS_LOG_DEBUG(L"RansomwareDetector",
            L"SMB traffic from PID %u to port 445 (%zu bytes)", pid, payload.size());
    }
}

void RansomwareDetector::OnRegistryEvent(uint32_t pid,
                                         std::wstring_view keyPath,
                                         std::wstring_view valueName,
                                         uint32_t operation) {
    if (!IsInitialized()) return;
    if (IsProcessWhitelisted(pid)) return;
    m_impl->m_stats.totalOperations.fetch_add(1, std::memory_order_relaxed);

    // Registry persistence and service install events are routed here.
    // Sub-detectors (LockyDetector, WannaCryDetector) call back via
    // OnSubDetectorIndicator() with specific scores.
    SS_LOG_DEBUG(L"RansomwareDetector",
        L"Registry event: PID=%u key=%ls op=%u", pid,
        std::wstring(keyPath).c_str(), operation);
}

void RansomwareDetector::OnSubDetectorIndicator(uint32_t pid, double score,
                                                RansomwareFamily family,
                                                std::wstring_view detail) {
    if (!IsInitialized()) return;
    if (IsProcessWhitelisted(pid)) return;
    if (m_impl->IsRecoveryPid(pid)) return;

    IOStats& stats = m_impl->GetOrCreateStats(pid);
    stats.confidenceScore += score;

    SS_LOG_INFO(L"RansomwareDetector",
        L"Sub-detector indicator: PID=%u score=+%.1f total=%.1f detail=%ls",
        pid, score, stats.confidenceScore, std::wstring(detail).c_str());

    // Check accumulated score against thresholds
    if (stats.confidenceScore >= RansomwareConstants::BLOCK_SCORE_THRESHOLD) {
        DetectionEvent event;
        event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = std::chrono::system_clock::now();
        event.pid = pid;
        event.processName = stats.processName;
        event.family = family;
        event.confidence = std::clamp(stats.confidenceScore / 100.0, 0.0, 1.0);
        event.verdict = DetectionVerdict::ConfirmedRansom;
        event.details = detail;
        m_impl->ExecuteResponsePipeline(pid, event);
    } else if (stats.confidenceScore >= RansomwareConstants::ALERT_SCORE_THRESHOLD) {
        DetectionEvent event;
        event.eventId = m_impl->m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = std::chrono::system_clock::now();
        event.pid = pid;
        event.family = family;
        event.confidence = std::clamp(stats.confidenceScore / 100.0, 0.0, 1.0);
        event.verdict = DetectionVerdict::Suspicious;
        event.action = DetectionAction::AllowWithBackup;
        event.details = detail;
        m_impl->FireDetectionCallback(event);
        m_impl->RecordDetection(event);
    }
}

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

std::optional<IOStats> RansomwareDetector::GetProcessStats(uint32_t pid) const {
    std::shared_lock lk(m_impl->m_statsMutex);
    auto it = m_impl->m_processStats.find(pid);
    if (it != m_impl->m_processStats.end())
        return std::optional<IOStats>{std::in_place, *it->second};
    return std::nullopt;
}

std::vector<uint32_t> RansomwareDetector::GetTrackedProcesses() const {
    std::vector<uint32_t> pids;
    std::shared_lock lk(m_impl->m_statsMutex);
    pids.reserve(m_impl->m_processStats.size());
    for (const auto& [p, _] : m_impl->m_processStats) pids.push_back(p);
    return pids;
}

std::vector<uint32_t> RansomwareDetector::GetHighRiskProcesses() const {
    std::vector<uint32_t> result;
    std::shared_lock lk(m_impl->m_statsMutex);
    for (const auto& [p, s] : m_impl->m_processStats) {
        if (s->highEntropyWrites.load(std::memory_order_relaxed) >= 3 ||
            s->isBlocked || s->confidenceScore >= RansomwareConstants::ALERT_SCORE_THRESHOLD)
            result.push_back(p);
    }
    return result;
}

void RansomwareDetector::ClearProcessStats(uint32_t pid) {
    std::unique_lock lk(m_impl->m_statsMutex);
    m_impl->m_processStats.erase(pid);
}

void RansomwareDetector::WhitelistProcess(uint32_t pid) {
    std::unique_lock lk(m_impl->m_whitelistMutex);
    m_impl->m_whitelistedPids.insert(pid);
}

void RansomwareDetector::UnwhitelistProcess(uint32_t pid) {
    std::unique_lock lk(m_impl->m_whitelistMutex);
    m_impl->m_whitelistedPids.erase(pid);
}

bool RansomwareDetector::IsProcessWhitelisted(uint32_t pid) const {
    std::shared_lock lk(m_impl->m_whitelistMutex);
    return m_impl->m_whitelistedPids.count(pid) > 0;
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

double RansomwareDetector::CalculateEntropy(std::span<const uint8_t> buffer) {
    if (buffer.empty()) return 0.0;
    std::array<uint64_t, 256> counts{};
    for (uint8_t b : buffer) counts[b]++;
    double entropy = 0.0;
    double total = static_cast<double>(buffer.size());
    for (uint64_t c : counts) {
        if (c > 0) {
            double p = static_cast<double>(c) / total;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

EntropyResult RansomwareDetector::AnalyzeEntropy(std::span<const uint8_t> buffer) {
    EntropyResult result;
    try {
        if (buffer.size() < RansomwareConstants::MIN_ENTROPY_BUFFER_SIZE) return result;
        size_t sampleSize = std::min(buffer.size(), RansomwareConstants::ENTROPY_SAMPLE_SIZE);
        auto sample = buffer.subspan(0, sampleSize);

        // Shannon entropy
        result.shannonEntropy = CalculateEntropy(sample);

        // Chi-squared test
        std::array<uint64_t, 256> counts{};
        for (uint8_t b : sample) counts[b]++;
        double expected = static_cast<double>(sampleSize) / 256.0;
        for (uint64_t c : counts) {
            double diff = static_cast<double>(c) - expected;
            result.chiSquared += (diff * diff) / expected;
        }

        // Monte Carlo Pi approximation
        size_t inside = 0;
        size_t pairs = sampleSize / 2;
        for (size_t i = 0; i < pairs; ++i) {
            double x = static_cast<double>(sample[i*2])   / 255.0;
            double y = static_cast<double>(sample[i*2+1]) / 255.0;
            if (x*x + y*y <= 1.0) ++inside;
        }
        result.monteCarloPi = (pairs > 0) ? 4.0 * static_cast<double>(inside) / static_cast<double>(pairs) : 0.0;

        // Arithmetic mean
        uint64_t sum = 0;
        for (uint8_t b : sample) sum += b;
        result.arithmeticMean = static_cast<double>(sum) / static_cast<double>(sampleSize);

        // Determination
        if (result.shannonEntropy > RansomwareConstants::ENTROPY_THRESHOLD &&
            std::abs(result.monteCarloPi - 3.14159) < RansomwareConstants::PI_DEVIATION_THRESHOLD) {
            result.isEncrypted = true;
            result.confidence = 0.9;
        } else if (result.shannonEntropy > RansomwareConstants::MIN_SUSPICION_ENTROPY) {
            result.isEncrypted = true;
            result.confidence = 0.6;
        }
    } catch (...) { /* safe fallback */ }
    return result;
}

bool RansomwareDetector::IsEncrypted(std::span<const uint8_t> buffer) {
    return AnalyzeEntropy(buffer).isEncrypted;
}

// ============================================================================
// FAMILY IDENTIFICATION
// ============================================================================

RansomwareFamily RansomwareDetector::IdentifyFamily(uint32_t pid) const {
    std::shared_lock lk(m_impl->m_statsMutex);
    auto it = m_impl->m_processStats.find(pid);
    if (it == m_impl->m_processStats.end()) return RansomwareFamily::Unknown;

    std::lock_guard sl(it->second->mutex);
    for (const auto& ext : it->second->newExtensions) {
        auto fit = KNOWN_EXTENSIONS.find(ext);
        if (fit != KNOWN_EXTENSIONS.end()) return fit->second;
    }
    return RansomwareFamily::Unknown;
}

RansomwareFamily RansomwareDetector::IdentifyFamilyFromExtension(std::wstring_view ext) const {
    std::wstring lower(ext);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    auto it = KNOWN_EXTENSIONS.find(lower);
    return (it != KNOWN_EXTENSIONS.end()) ? it->second : RansomwareFamily::Unknown;
}

std::optional<FamilySignature> RansomwareDetector::GetFamilySignature(RansomwareFamily family) const {
    std::shared_lock lk(m_impl->m_signaturesMutex);
    auto it = m_impl->m_familySignatures.find(family);
    if (it != m_impl->m_familySignatures.end()) return it->second;
    return std::nullopt;
}

void RansomwareDetector::RegisterFamilySignature(const FamilySignature& sig) {
    std::unique_lock lk(m_impl->m_signaturesMutex);
    if (m_impl->m_familySignatures.size() >= RansomwareConstants::MAX_FAMILY_SIGNATURES) {
        SS_LOG_WARN(L"RansomwareDetector", L"Family signature limit reached");
        return;
    }
    m_impl->m_familySignatures[sig.family] = sig;
}

// ============================================================================
// CONTAINMENT MODE
// ============================================================================

void RansomwareDetector::EnterContainmentMode() {
    if (!m_impl->m_containmentMode.exchange(true, std::memory_order_acq_rel)) {
        SS_LOG_WARN(L"RansomwareDetector", L"Entering containment mode");
        LockdownCallback cb;
        { std::lock_guard lk(m_impl->m_callbackMutex); cb = m_impl->m_lockdownCb; }
        if (cb) { try { cb(); } catch (...) {} }
    }
}

void RansomwareDetector::ExitContainmentMode() {
    if (m_impl->m_containmentMode.exchange(false, std::memory_order_acq_rel)) {
        SS_LOG_INFO(L"RansomwareDetector", L"Exiting containment mode");
    }
}

bool RansomwareDetector::IsInContainmentMode() const noexcept {
    return m_impl->m_containmentMode.load(std::memory_order_acquire);
}

void RansomwareDetector::RegisterRecoveryProcess(uint32_t pid) {
    std::unique_lock lk(m_impl->m_recoveryMutex);
    m_impl->m_recoveryPids.insert(pid);
    SS_LOG_INFO(L"RansomwareDetector", L"Registered recovery process PID %u", pid);
}

void RansomwareDetector::UnregisterRecoveryProcess(uint32_t pid) {
    std::unique_lock lk(m_impl->m_recoveryMutex);
    m_impl->m_recoveryPids.erase(pid);
}

bool RansomwareDetector::IsRecoveryProcess(uint32_t pid) const {
    return m_impl->IsRecoveryPid(pid);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void RansomwareDetector::SetDetectionCallback(DetectionCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_detectionCallback = std::move(cb);
}
void RansomwareDetector::SetBlockCallback(BlockCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_blockCallback = std::move(cb);
}
void RansomwareDetector::SetPreWriteCallback(PreWriteCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_preWriteCallback = std::move(cb);
}
void RansomwareDetector::SetEmergencyBackupCallback(EmergencyBackupCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_emergencyBackupCb = std::move(cb);
}
void RansomwareDetector::SetEmergencySnapshotCallback(EmergencySnapshotCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_emergencySnapshotCb = std::move(cb);
}
void RansomwareDetector::SetLockdownCallback(LockdownCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_lockdownCb = std::move(cb);
}
void RansomwareDetector::SetRecoveryCallback(RecoveryCallback cb) {
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_recoveryCb = std::move(cb);
}

// ============================================================================
// STATISTICS
// ============================================================================

DetectionStatisticsSnapshot RansomwareDetector::GetStatistics() const {
    DetectionStatisticsSnapshot snap;
    snap.totalOperations    = m_impl->m_stats.totalOperations.load(std::memory_order_relaxed);
    snap.operationsBlocked  = m_impl->m_stats.operationsBlocked.load(std::memory_order_relaxed);
    snap.processesTerminated = m_impl->m_stats.processesTerminated.load(std::memory_order_relaxed);
    snap.honeypotTriggers   = m_impl->m_stats.honeypotTriggers.load(std::memory_order_relaxed);
    snap.highEntropyWrites  = m_impl->m_stats.highEntropyWrites.load(std::memory_order_relaxed);
    snap.filesBackedUp      = m_impl->m_stats.filesBackedUp.load(std::memory_order_relaxed);
    snap.filesRestored      = m_impl->m_stats.filesRestored.load(std::memory_order_relaxed);
    snap.falsePositives     = m_impl->m_stats.falsePositives.load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.detectionsByFamily.size(); ++i)
        snap.detectionsByFamily[i] = m_impl->m_stats.detectionsByFamily[i].load(std::memory_order_relaxed);
    // startTime is non-atomic — protect with module mutex to avoid data race with ResetStatistics
    {
        std::shared_lock lk(m_impl->m_mutex);
        auto elapsed = Clock::now() - m_impl->m_stats.startTime;
        snap.uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    }
    return snap;
}

void RansomwareDetector::ResetStatistics() {
    // Hold module mutex to synchronize non-atomic startTime write with GetStatistics read
    std::unique_lock lk(m_impl->m_mutex);
    m_impl->m_stats.Reset();
}

std::vector<DetectionEvent> RansomwareDetector::GetRecentDetections(size_t maxCount) const {
    std::shared_lock lk(m_impl->m_detectionsMutex);
    std::vector<DetectionEvent> result;
    size_t count = std::min(maxCount, m_impl->m_recentDetections.size());
    result.reserve(count);
    auto it = m_impl->m_recentDetections.rbegin();
    for (size_t i = 0; i < count && it != m_impl->m_recentDetections.rend(); ++i, ++it)
        result.push_back(*it);
    return result;
}

void DetectionStatistics::Reset() noexcept {
    totalOperations = 0;
    operationsBlocked = 0;
    processesTerminated = 0;
    honeypotTriggers = 0;
    highEntropyWrites = 0;
    filesBackedUp = 0;
    filesRestored = 0;
    falsePositives = 0;
    for (auto& c : detectionsByFamily) c.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

// ============================================================================
// UTILITY
// ============================================================================

bool RansomwareDetector::IsCompressedType(std::wstring_view filePath) const {
    try {
        std::wstring ext = NormalizeExtension(filePath);
        return COMPRESSED_EXTENSIONS.count(ext) > 0;
    } catch (...) { return false; }
}

bool RansomwareDetector::IsProtectedPath(std::wstring_view filePath) const {
    std::shared_lock lk(m_impl->m_mutex);
    for (const auto& dir : m_impl->m_config.protectedDirectories) {
        if (filePath.size() >= dir.size() &&
            _wcsnicmp(filePath.data(), dir.data(), dir.size()) == 0)
            return true;
    }
    return false;
}

void RansomwareDetector::ReportFalsePositive(uint64_t eventId, const std::string& reason) {
    m_impl->m_stats.falsePositives.fetch_add(1, std::memory_order_relaxed);
    SS_LOG_WARN(L"RansomwareDetector",
        L"False positive reported: eventId=%llu reason=%hs", eventId, reason.c_str());

    // Remove the PID from responded set so it can be re-evaluated
    std::unique_lock dl(m_impl->m_detectionsMutex);
    for (auto& det : m_impl->m_recentDetections) {
        if (det.eventId == eventId) {
            std::lock_guard rl(m_impl->m_responseMutex);
            m_impl->m_respondedPids.erase(det.pid);
            break;
        }
    }
}

bool RansomwareDetector::SelfTest() {
    try {
        SS_LOG_INFO(L"RansomwareDetector", L"Running self-test...");

        // Test 1: Low entropy
        std::vector<uint8_t> low(1024, 0);
        if (CalculateEntropy(low) > 1.0) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Self-test FAILED: low entropy check");
            return false;
        }

        // Test 2: High entropy
        std::vector<uint8_t> high(1024);
        std::mt19937 gen(42);
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : high) b = static_cast<uint8_t>(dis(gen));
        if (CalculateEntropy(high) < 7.0) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Self-test FAILED: high entropy check");
            return false;
        }

        // Test 3: Extension check
        if (!IsCompressedType(L"test.zip")) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Self-test FAILED: extension check");
            return false;
        }

        // Test 4: Family identification
        if (IdentifyFamilyFromExtension(L".locky") != RansomwareFamily::Locky) {
            SS_LOG_ERROR(L"RansomwareDetector", L"Self-test FAILED: family ID check");
            return false;
        }

        SS_LOG_INFO(L"RansomwareDetector", L"Self-test PASSED");
        return true;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"Self-test exception: %hs", ex.what());
        return false;
    }
}

std::string RansomwareDetector::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << RansomwareConstants::VERSION_MAJOR << "."
        << RansomwareConstants::VERSION_MINOR << "."
        << RansomwareConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// IOStats METHODS (deadlock-safe)
// ============================================================================

double IOStats::GetWriteRate() const {
    std::lock_guard lk(mutex);
    if (writeTimestamps.empty()) return 0.0;
    return static_cast<double>(writeTimestamps.size())
         / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS);
}

double IOStats::GetRenameRate() const {
    std::lock_guard lk(mutex);
    if (renameTimestamps.empty()) return 0.0;
    return static_cast<double>(renameTimestamps.size())
         / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS);
}

void IOStats::Reset() noexcept {
    std::lock_guard lk(mutex);
    writeCount = 0; renameCount = 0; deleteCount = 0;
    highEntropyWrites = 0; bytesWritten = 0; encryptedBytesWritten = 0;
    writeTimestamps.clear(); renameTimestamps.clear(); deleteTimestamps.clear();
    affectedExtensions.clear(); originalExtensions.clear(); newExtensions.clear();
    affectedDirectories.clear();
    confidenceScore = 0.0;
    isBlocked = false;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool RansomwareDetectorConfiguration::IsValid() const noexcept {
    if (entropyThreshold < 0.0 || entropyThreshold > 8.0) return false;
    if (maxWritesPerSecond == 0) return false;
    if (maxRenamesPerSecond == 0) return false;
    if (rateWindowSecs == 0) return false;
    if (minBlockConfidence < 0.0 || minBlockConfidence > 1.0) return false;
    return true;
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string EntropyResult::ToJson() const {
    nlohmann::json j;
    j["shannonEntropy"] = shannonEntropy;
    j["chiSquared"] = chiSquared;
    j["arithmeticMean"] = arithmeticMean;
    j["monteCarloPi"] = monteCarloPi;
    j["serialCorrelation"] = serialCorrelation;
    j["isEncrypted"] = isEncrypted;
    j["confidence"] = confidence;
    return j.dump();
}

std::string IOStats::ToJson() const {
    std::lock_guard lk(mutex);
    nlohmann::json j;
    j["pid"] = pid;
    j["processName"] = std::string(processName.begin(), processName.end());
    j["writeCount"] = writeCount.load(std::memory_order_relaxed);
    j["renameCount"] = renameCount.load(std::memory_order_relaxed);
    j["deleteCount"] = deleteCount.load(std::memory_order_relaxed);
    j["highEntropyWrites"] = highEntropyWrites.load(std::memory_order_relaxed);
    j["bytesWritten"] = bytesWritten.load(std::memory_order_relaxed);
    // Inline rate computation to avoid deadlock (GetWriteRate also locks mutex)
    j["writeRate"] = writeTimestamps.empty() ? 0.0
        : static_cast<double>(writeTimestamps.size()) / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS);
    j["renameRate"] = renameTimestamps.empty() ? 0.0
        : static_cast<double>(renameTimestamps.size()) / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS);
    j["confidenceScore"] = confidenceScore;
    j["isBlocked"] = isBlocked;
    return j.dump();
}

std::string DetectionEvent::ToJson() const {
    nlohmann::json j;
    j["eventId"] = eventId;
    j["pid"] = pid;
    j["filePath"] = std::string(filePath.begin(), filePath.end());
    j["verdict"] = static_cast<int>(verdict);
    j["action"] = static_cast<int>(action);
    j["detectionFlags"] = detectionFlags;
    j["family"] = static_cast<int>(family);
    j["confidence"] = confidence;
    if (entropyResult) j["entropy"] = nlohmann::json::parse(entropyResult->ToJson());
    if (!details.empty()) j["details"] = std::string(details.begin(), details.end());
    return j.dump();
}

std::string DetectionStatistics::ToJson() const {
    nlohmann::json j;
    j["totalOperations"] = totalOperations.load();
    j["operationsBlocked"] = operationsBlocked.load();
    j["processesTerminated"] = processesTerminated.load();
    j["honeypotTriggers"] = honeypotTriggers.load();
    j["highEntropyWrites"] = highEntropyWrites.load();
    j["filesBackedUp"] = filesBackedUp.load();
    j["filesRestored"] = filesRestored.load();
    j["falsePositives"] = falsePositives.load();
    return j.dump();
}

std::string DetectionStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["totalOperations"] = totalOperations;
    j["operationsBlocked"] = operationsBlocked;
    j["processesTerminated"] = processesTerminated;
    j["honeypotTriggers"] = honeypotTriggers;
    j["highEntropyWrites"] = highEntropyWrites;
    j["filesBackedUp"] = filesBackedUp;
    j["filesRestored"] = filesRestored;
    j["falsePositives"] = falsePositives;
    j["uptimeSeconds"] = uptimeSeconds;
    return j.dump();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVerdictName(DetectionVerdict v) noexcept {
    switch (v) {
        case DetectionVerdict::Clean:           return "Clean";
        case DetectionVerdict::Suspicious:       return "Suspicious";
        case DetectionVerdict::PossibleRansom:   return "PossibleRansom";
        case DetectionVerdict::ConfirmedRansom:  return "ConfirmedRansom";
        case DetectionVerdict::Honeypot:         return "Honeypot";
        default: return "Unknown";
    }
}

std::string_view GetActionName(DetectionAction a) noexcept {
    switch (a) {
        case DetectionAction::Allow:           return "Allow";
        case DetectionAction::AllowWithBackup:  return "AllowWithBackup";
        case DetectionAction::Block:            return "Block";
        case DetectionAction::BlockAndKill:     return "BlockAndKill";
        case DetectionAction::Quarantine:       return "Quarantine";
        default: return "Unknown";
    }
}

std::string_view GetTechniqueName(DetectionTechnique t) noexcept {
    switch (t) {
        case DetectionTechnique::None:                return "None";
        case DetectionTechnique::EntropyAnalysis:     return "EntropyAnalysis";
        case DetectionTechnique::RapidWrites:         return "RapidWrites";
        case DetectionTechnique::MassRename:          return "MassRename";
        case DetectionTechnique::MassDelete:          return "MassDelete";
        case DetectionTechnique::ExtensionChange:     return "ExtensionChange";
        case DetectionTechnique::HoneypotAccess:      return "HoneypotAccess";
        case DetectionTechnique::KnownFamily:         return "KnownFamily";
        case DetectionTechnique::RansomNote:          return "RansomNote";
        case DetectionTechnique::VssDestruction:      return "VssDestruction";
        case DetectionTechnique::BackupDeletion:      return "BackupDeletion";
        case DetectionTechnique::MagicCorruption:     return "MagicCorruption";
        case DetectionTechnique::DirectoryTraversal:  return "DirectoryTraversal";
        case DetectionTechnique::C2Communication:     return "C2Communication";
        case DetectionTechnique::ProcessHollowing:    return "ProcessHollowing";
        case DetectionTechnique::PrivilegeEscalation: return "PrivilegeEscalation";
        default: return "Unknown";
    }
}

std::string_view GetFamilyName(RansomwareFamily f) noexcept {
    switch (f) {
        case RansomwareFamily::Unknown:      return "Unknown";
        case RansomwareFamily::WannaCry:     return "WannaCry";
        case RansomwareFamily::Locky:        return "Locky";
        case RansomwareFamily::CryptoLocker: return "CryptoLocker";
        case RansomwareFamily::TeslaCrypt:   return "TeslaCrypt";
        case RansomwareFamily::Cerber:       return "Cerber";
        case RansomwareFamily::Petya:        return "Petya";
        case RansomwareFamily::NotPetya:     return "NotPetya";
        case RansomwareFamily::Ryuk:         return "Ryuk";
        case RansomwareFamily::REvil:        return "REvil";
        case RansomwareFamily::Conti:        return "Conti";
        case RansomwareFamily::LockBit:      return "LockBit";
        case RansomwareFamily::BlackCat:     return "BlackCat";
        case RansomwareFamily::Hive:         return "Hive";
        case RansomwareFamily::BlackBasta:   return "BlackBasta";
        case RansomwareFamily::Royal:        return "Royal";
        case RansomwareFamily::Play:         return "Play";
        case RansomwareFamily::Clop:         return "Clop";
        case RansomwareFamily::Maze:         return "Maze";
        case RansomwareFamily::Ragnar:       return "Ragnar";
        case RansomwareFamily::Custom:       return "Custom";
        default: return "Unknown";
    }
}

std::string_view GetRiskLevelName(ProcessRiskLevel l) noexcept {
    switch (l) {
        case ProcessRiskLevel::Unknown:  return "Unknown";
        case ProcessRiskLevel::Safe:     return "Safe";
        case ProcessRiskLevel::Low:      return "Low";
        case ProcessRiskLevel::Medium:   return "Medium";
        case ProcessRiskLevel::High:     return "High";
        case ProcessRiskLevel::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetOperationTypeName(FileOperationType t) noexcept {
    switch (t) {
        case FileOperationType::Unknown:     return "Unknown";
        case FileOperationType::Create:      return "Create";
        case FileOperationType::Write:       return "Write";
        case FileOperationType::Rename:      return "Rename";
        case FileOperationType::Delete:      return "Delete";
        case FileOperationType::SetInfo:     return "SetInfo";
        case FileOperationType::SetSecurity: return "SetSecurity";
        default: return "Unknown";
    }
}

std::string FormatDetectionFlags(uint16_t flags) {
    if (flags == 0) return "None";
    std::string result;
    for (uint16_t bit = 1; bit != 0; bit <<= 1) {
        if (flags & bit) {
            if (!result.empty()) result += " | ";
            result += std::string(GetTechniqueName(static_cast<DetectionTechnique>(bit)));
        }
    }
    return result;
}

double CalculateConfidence(double entropy, uint32_t writeRate, uint32_t renameRate,
                           bool honeypotTriggered, bool knownFamily) {
    double score = 0.0;
    if (entropy > RansomwareConstants::ENTROPY_THRESHOLD)  score += 0.25;
    if (writeRate > RansomwareConstants::MAX_WRITES_PER_SECOND) score += 0.15;
    if (renameRate > RansomwareConstants::MAX_RENAMES_PER_SECOND) score += 0.15;
    if (honeypotTriggered) score += 0.35;
    if (knownFamily) score += 0.10;
    return std::clamp(score, 0.0, 1.0);
}

// ============================================================================
// KERNEL BRIDGE
// ============================================================================

void RansomwareDetector::OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                                                std::wstring_view commandLine, bool isCreate) {
    try {
        if (!IsInitialized()) return;
        if (isCreate) {
            OnProcessCreated(processId, imagePath, commandLine);
        } else {
            ClearProcessStats(processId);
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"OnKernelProcessNotify error: %hs", ex.what());
    } catch (...) {}
}

void RansomwareDetector::OnKernelImageLoad(uint32_t /*processId*/, std::wstring_view /*imagePath*/,
                                            uint64_t /*imageBase*/, size_t /*imageSize*/) {
    // RansomwareDetector operates on file I/O patterns, not image loads.
    // This is a no-op passthrough for kernel bridge API uniformity.
}

bool RansomwareDetector::RequestKernelProcessBlock(uint32_t processId, const std::wstring& reason) {
    try {
        using namespace Communication;
        if (!IPCManager::HasInstance() || !IPCManager::Instance().IsFilterPortConnected()) {
            SS_LOG_DEBUG(L"RansomwareDetector", L"Kernel IPC not available for process block PID=%u", processId);
            return false;
        }
#pragma pack(push, 1)
        struct KernelBlockRequest {
            uint32_t messageType;
            uint32_t processId;
            wchar_t  reason[256];
        };
#pragma pack(pop)
        KernelBlockRequest req{};
        req.messageType = 0x30;
        req.processId = processId;
        wcsncpy_s(req.reason, _countof(req.reason), reason.c_str(), _TRUNCATE);
        req.reason[_countof(req.reason) - 1] = L'\0';

        bool result = IPCManager::Instance().SendToKernel(&req, sizeof(req));
        if (result)
            SS_LOG_INFO(L"RansomwareDetector", L"Kernel block requested for PID=%u", processId);
        return result;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"RequestKernelProcessBlock error: %hs", ex.what());
        return false;
    }
}

// ============================================================================
// CROSS-MODULE WIRING (Public Delegating Methods)
// ============================================================================

void RansomwareDetector::ReportThreatToAlertSystem(const DetectionEvent& event) {
    try {
        using namespace Communication;
        if (!AlertSystem::HasInstance()) return;

        auto severity = AlertSeverity::High;
        if (event.verdict >= DetectionVerdict::ConfirmedRansom)
            severity = AlertSeverity::Emergency;
        else if (event.verdict >= DetectionVerdict::PossibleRansom)
            severity = AlertSeverity::Critical;

        std::string subject = "Ransomware " +
            std::string(GetVerdictName(event.verdict)) +
            " — " + std::string(GetFamilyName(event.family)) +
            " (PID " + std::to_string(event.pid) + ")";

        (void)AlertSystem::Instance().RaiseAlert(
            severity, AlertType::ThreatDetection,
            subject, event.ToJson(), "RansomwareDetector");
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"AlertSystem report failed: %hs", ex.what());
    }
}

void RansomwareDetector::ReportDetectionTelemetry(const DetectionEvent& event) {
    try {
        using namespace Communication;
        if (!TelemetryCollector::HasInstance()) return;

        std::map<std::string, std::string> data;
        data["pid"] = std::to_string(event.pid);
        data["verdict"] = std::string(GetVerdictName(event.verdict));
        data["action"] = std::string(GetActionName(event.action));
        data["family"] = std::string(GetFamilyName(event.family));
        data["confidence"] = std::to_string(event.confidence);
        data["entropy"] = std::to_string(
            event.entropyResult ? event.entropyResult->shannonEntropy : 0.0);
        data["event_id"] = std::to_string(event.eventId);

        TelemetryCollector::Instance().RecordCustom("ransomware_detection", data);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"RansomwareDetector", L"Telemetry report failed: %hs", ex.what());
    }
}

} // namespace Ransomware
} // namespace ShadowStrike
