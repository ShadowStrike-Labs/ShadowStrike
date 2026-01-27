/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file RansomwareDetector.cpp
 * @brief Implementation of behavioral ransomware detection engine
 *
 * Implements sophisticated detection logic including:
 * - Shannon entropy analysis for encryption detection
 * - Sliding window rate limiting for I/O operations
 * - Honeypot (canary file) monitoring
 * - Process risk scoring
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern via RansomwareDetectorImpl
 * - Thread-safe statistics with atomic counters
 * - Lock-free detection where possible
 * - High-performance entropy calculation
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
#include "RansomwareDetector.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <algorithm>
#include <execution>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <numeric>
#include <random>
#include <filesystem>

// Third-party JSON library
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

    /// @brief Compressed file extensions (high entropy naturally)
    const std::unordered_set<std::wstring> COMPRESSED_EXTENSIONS = {
        L".zip", L".rar", L".7z", L".gz", L".tar", L".bz2", L".xz",
        L".jpg", L".jpeg", L".png", L".gif", L".webp", L".mp3", L".mp4",
        L".avi", L".mkv", L".mov", L".pdf", L".docx", L".xlsx", L".pptx"
    };

    /// @brief Known ransomware extensions
    const std::unordered_map<std::wstring, RansomwareFamily> KNOWN_EXTENSIONS = {
        {L".wncry", RansomwareFamily::WannaCry},
        {L".locky", RansomwareFamily::Locky},
        {L".encrypted", RansomwareFamily::CryptoLocker},
        {L".vvv", RansomwareFamily::TeslaCrypt},
        {L".cerber", RansomwareFamily::Cerber},
        {L".cerber2", RansomwareFamily::Cerber},
        {L".cerber3", RansomwareFamily::Cerber},
        {L".ryuk", RansomwareFamily::Ryuk},
        {L".revil", RansomwareFamily::REvil},
        {L".lockbit", RansomwareFamily::LockBit},
        {L".hive", RansomwareFamily::Hive},
        {L".play", RansomwareFamily::Play},
        {L".clop", RansomwareFamily::Clop},
        {L".maze", RansomwareFamily::Maze}
    };

    /// @brief Check if time is within window
    bool IsWithinWindow(TimePoint time, uint32_t windowSecs) {
        auto now = Clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - time).count();
        return diff <= windowSecs;
    }

    /// @brief Clean old timestamps from vector
    void PruneTimestamps(std::vector<TimePoint>& timestamps, uint32_t windowSecs) {
        auto now = Clock::now();
        auto cutoff = now - std::chrono::seconds(windowSecs);

        // Remove timestamps older than window
        auto it = std::remove_if(timestamps.begin(), timestamps.end(),
            [&cutoff](const TimePoint& tp) {
                return tp < cutoff;
            });

        timestamps.erase(it, timestamps.end());
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

/**
 * @class RansomwareDetectorImpl
 * @brief Implementation details for RansomwareDetector
 */
class RansomwareDetectorImpl final {
public:
    RansomwareDetectorImpl() = default;
    ~RansomwareDetectorImpl() = default;

    // Non-copyable, non-movable
    RansomwareDetectorImpl(const RansomwareDetectorImpl&) = delete;
    RansomwareDetectorImpl& operator=(const RansomwareDetectorImpl&) = delete;
    RansomwareDetectorImpl(RansomwareDetectorImpl&&) = delete;
    RansomwareDetectorImpl& operator=(RansomwareDetectorImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    RansomwareDetectorConfiguration m_config;
    DetectionStatistics m_stats;

    // Process tracking
    std::unordered_map<uint32_t, IOStats> m_processStats;
    mutable std::shared_mutex m_statsMutex;

    // Honeypot registry
    std::unordered_set<std::wstring> m_honeypots;
    mutable std::shared_mutex m_honeypotMutex;

    // Whitelists
    std::unordered_set<uint32_t> m_whitelistedPids;
    mutable std::shared_mutex m_whitelistMutex;

    // Callbacks
    DetectionCallback m_detectionCallback;
    BlockCallback m_blockCallback;
    PreWriteCallback m_preWriteCallback;
    mutable std::mutex m_callbackMutex;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Get or create stats for process
     */
    IOStats& GetStatsForProcess(uint32_t pid) {
        // Upgradeable lock pattern not available in std::shared_mutex
        // So we try read first, then write if needed

        {
            std::shared_lock lock(m_statsMutex);
            auto it = m_processStats.find(pid);
            if (it != m_processStats.end()) {
                return it->second;
            }
        }

        // Create new stats
        std::unique_lock lock(m_statsMutex);

        // Double check
        auto it = m_processStats.find(pid);
        if (it != m_processStats.end()) {
            return it->second;
        }

        // Initialize new stats
        IOStats stats;
        stats.pid = pid;
        stats.firstActivity = Clock::now();
        stats.lastActivity = stats.firstActivity;

        // Try to get process name
        try {
            stats.processName = Utils::ProcessUtils::GetProcessName(pid);
        } catch (...) {
            stats.processName = L"Unknown";
        }

        auto result = m_processStats.emplace(pid, std::move(stats));

        // Cleanup old stats if too many
        if (m_processStats.size() > RansomwareConstants::MAX_TRACKED_PROCESSES) {
            CleanupOldStats();
        }

        return result.first->second;
    }

    /**
     * @brief Cleanup old process stats
     */
    void CleanupOldStats() {
        auto now = Clock::now();
        auto expiration = std::chrono::seconds(RansomwareConstants::STATS_RETENTION_SECS);

        for (auto it = m_processStats.begin(); it != m_processStats.end(); ) {
            if (now - it->second.lastActivity > expiration) {
                it = m_processStats.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Update write statistics
     */
    void UpdateWriteStats(IOStats& stats, size_t bytes, bool isHighEntropy) {
        std::lock_guard lock(stats.mutex);

        auto now = Clock::now();
        stats.lastActivity = now;

        stats.writeCount++;
        stats.bytesWritten += bytes;
        stats.writeTimestamps.push_back(now);

        if (isHighEntropy) {
            stats.highEntropyWrites++;
            stats.encryptedBytesWritten += bytes;
        }

        // Prune old timestamps
        PruneTimestamps(stats.writeTimestamps, m_config.rateWindowSecs);
    }

    /**
     * @brief Fire detection callback
     */
    void FireDetectionCallback(const DetectionEvent& event) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            if (m_detectionCallback) {
                m_detectionCallback(event);
            }
        } catch (const std::exception& ex) {
            Utils::Logger::Error("RansomwareDetector: Detection callback failed: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("RansomwareDetector: Detection callback failed");
        }
    }

    /**
     * @brief Fire block callback
     */
    void FireBlockCallback(uint32_t pid, const std::wstring& reason) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            if (m_blockCallback) {
                m_blockCallback(pid, reason);
            }
        } catch (...) {
            Utils::Logger::Error("RansomwareDetector: Block callback failed");
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
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
    Utils::Logger::Info("RansomwareDetector: Instance created");
}

RansomwareDetector::~RansomwareDetector() {
    try {
        Shutdown();
        Utils::Logger::Info("RansomwareDetector: Instance destroyed");
    } catch (...) {
        // Destructors must not throw
    }
}

bool RansomwareDetector::Initialize(const RansomwareDetectorConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            Utils::Logger::Warn("RansomwareDetector: Already initialized");
            return false;
        }

        if (!config.IsValid()) {
            Utils::Logger::Error("RansomwareDetector: Invalid configuration");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;
        m_impl->m_config = config;

        // Reset statistics
        m_impl->m_stats.Reset();

        // Load protected paths (stub)
        // In real implementation, this would load from config or system profile

        m_impl->m_status = ModuleStatus::Running;

        Utils::Logger::Info("RansomwareDetector: Initialized successfully (v{})",
                           GetVersionString());
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: Initialization failed: {}", ex.what());
        m_impl->m_status = ModuleStatus::Error;
        return false;
    } catch (...) {
        Utils::Logger::Critical("RansomwareDetector: Initialization failed (unknown exception)");
        m_impl->m_status = ModuleStatus::Error;
        return false;
    }
}

void RansomwareDetector::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;

        // Clear tracking data
        {
            std::unique_lock statsLock(m_impl->m_statsMutex);
            m_impl->m_processStats.clear();
        }

        // Clear callbacks
        {
            std::lock_guard cbLock(m_impl->m_callbackMutex);
            m_impl->m_detectionCallback = nullptr;
            m_impl->m_blockCallback = nullptr;
            m_impl->m_preWriteCallback = nullptr;
        }

        m_impl->m_status = ModuleStatus::Stopped;
        Utils::Logger::Info("RansomwareDetector: Shutdown complete");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: Shutdown error: {}", ex.what());
    } catch (...) {
        Utils::Logger::Critical("RansomwareDetector: Shutdown failed");
    }
}

bool RansomwareDetector::IsInitialized() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus RansomwareDetector::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
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
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.filePath = filePath;
    event.operationType = FileOperationType::Write;

    try {
        if (!IsInitialized()) return event;

        // Check if whitelisted
        if (IsProcessWhitelisted(pid)) {
            event.verdict = DetectionVerdict::Clean;
            return event;
        }

        // Get stats
        IOStats& stats = m_impl->GetStatsForProcess(pid);

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
            // Skip compressed files from entropy check
            if (!IsCompressedType(filePath)) {
                auto entropy = AnalyzeEntropy(buffer);
                event.entropyResult = entropy;

                if (entropy.isEncrypted) {
                    isHighEntropy = true;
                    event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::EntropyAnalysis);
                }
            }
        }

        // Update stats
        m_impl->UpdateWriteStats(stats, buffer.size(), isHighEntropy);
        m_impl->m_stats.totalOperations++;

        // 3. Rate analysis
        if (m_impl->m_config.enableRateMonitoring) {
            double writeRate = stats.GetWriteRate();
            if (writeRate > m_impl->m_config.maxWritesPerSecond) {
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::RapidWrites);
            }
        }

        // 4. Determine Verdict
        if ((event.detectionFlags & static_cast<uint16_t>(DetectionTechnique::RapidWrites)) &&
            (event.detectionFlags & static_cast<uint16_t>(DetectionTechnique::EntropyAnalysis))) {

            // Rapid high-entropy writes = Ransomware
            event.verdict = DetectionVerdict::PossibleRansom;
            event.confidence = 0.8;

            // Should we block?
            if (event.confidence >= m_impl->m_config.minBlockConfidence &&
                m_impl->m_config.enableAutoBlock) {
                event.action = DetectionAction::BlockAndKill;
                stats.isBlocked = true;

                m_impl->m_stats.operationsBlocked++;
                m_impl->m_stats.highEntropyWrites++;

                // Fire detection callback
                m_impl->FireDetectionCallback(event);

                // Fire block callback
                m_impl->FireBlockCallback(pid, L"Rapid high-entropy writes detected");

                Utils::Logger::Warn("RansomwareDetector: Blocked ransomware activity in PID {}", pid);
            }
        }

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: AnalyzeWriteEx failed: {}", ex.what());
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
    return result.action == DetectionAction::Block ||
           result.action == DetectionAction::BlockAndKill;
}

DetectionEvent RansomwareDetector::AnalyzeRenameEx(uint32_t pid,
                                                   std::wstring_view oldPath,
                                                   std::wstring_view newPath) {
    DetectionEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.pid = pid;
    event.filePath = newPath;
    event.operationType = FileOperationType::Rename;

    try {
        if (!IsInitialized()) return event;

        IOStats& stats = m_impl->GetStatsForProcess(pid);

        {
            std::lock_guard lock(stats.mutex);
            stats.renameCount++;
            stats.renameTimestamps.push_back(Clock::now());
            PruneTimestamps(stats.renameTimestamps, m_impl->m_config.rateWindowSecs);
        }

        // Check for extension change
        fs::path pOld(oldPath);
        fs::path pNew(newPath);

        std::wstring extOld = pOld.extension().wstring();
        std::wstring extNew = pNew.extension().wstring();

        // Normalize extensions
        std::transform(extOld.begin(), extOld.end(), extOld.begin(), ::towlower);
        std::transform(extNew.begin(), extNew.end(), extNew.begin(), ::towlower);

        if (extOld != extNew) {
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::ExtensionChange);

            // Check against known ransomware extensions
            if (KNOWN_EXTENSIONS.count(extNew)) {
                event.family = KNOWN_EXTENSIONS.at(extNew);
                event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::KnownFamily);
                event.verdict = DetectionVerdict::ConfirmedRansom;
                event.confidence = 1.0;
                event.action = DetectionAction::BlockAndKill;

                Utils::Logger::Critical("RansomwareDetector: Known ransomware extension {} detected (PID {})",
                                      std::string(extNew.begin(), extNew.end()), pid);
            }
        }

        // Check rename rate
        if (stats.GetRenameRate() > m_impl->m_config.maxRenamesPerSecond) {
            event.detectionFlags |= static_cast<uint16_t>(DetectionTechnique::MassRename);

            if (event.verdict != DetectionVerdict::ConfirmedRansom) {
                event.verdict = DetectionVerdict::Suspicious;
                event.confidence = 0.6;
            }
        }

        if (event.action == DetectionAction::BlockAndKill && m_impl->m_config.enableAutoBlock) {
            m_impl->m_stats.operationsBlocked++;
            m_impl->FireDetectionCallback(event);
            m_impl->FireBlockCallback(pid, L"Ransomware extension or mass rename detected");
        }

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: AnalyzeRenameEx failed: {}", ex.what());
    }

    return event;
}

// ============================================================================
// HONEYPOT INTEGRATION
// ============================================================================

void RansomwareDetector::OnHoneypotTouched(uint32_t pid, const std::wstring& filePath) {
    try {
        Utils::Logger::Critical("RansomwareDetector: HONEYPOT TOUCHED by PID {} - File: {}",
                              pid, std::string(filePath.begin(), filePath.end()));

        m_impl->m_stats.honeypotTriggers++;

        // Terminate process immediately if configured
        if (m_impl->m_config.enableProcessKill) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                TerminateProcess(hProcess, 1);
                CloseHandle(hProcess);
                m_impl->m_stats.processesTerminated++;
                Utils::Logger::Info("RansomwareDetector: Process {} terminated", pid);
            }
        }

        // Record detection
        DetectionEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.pid = pid;
        event.filePath = filePath;
        event.verdict = DetectionVerdict::Honeypot;
        event.action = DetectionAction::BlockAndKill;

        m_impl->FireDetectionCallback(event);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: OnHoneypotTouched failed: {}", ex.what());
    }
}

void RansomwareDetector::RegisterHoneypot(std::wstring_view filePath) {
    try {
        std::unique_lock lock(m_impl->m_honeypotMutex);
        m_impl->m_honeypots.insert(std::wstring(filePath));
    } catch (...) {}
}

void RansomwareDetector::UnregisterHoneypot(std::wstring_view filePath) {
    try {
        std::unique_lock lock(m_impl->m_honeypotMutex);
        m_impl->m_honeypots.erase(std::wstring(filePath));
    } catch (...) {}
}

bool RansomwareDetector::IsHoneypot(std::wstring_view filePath) const {
    try {
        std::shared_lock lock(m_impl->m_honeypotMutex);
        return m_impl->m_honeypots.count(std::wstring(filePath)) > 0;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

std::optional<IOStats> RansomwareDetector::GetProcessStats(uint32_t pid) const {
    try {
        std::shared_lock lock(m_impl->m_statsMutex);
        auto it = m_impl->m_processStats.find(pid);
        if (it != m_impl->m_processStats.end()) {
            return it->second;
        }
    } catch (...) {}
    return std::nullopt;
}

std::vector<uint32_t> RansomwareDetector::GetTrackedProcesses() const {
    std::vector<uint32_t> pids;
    try {
        std::shared_lock lock(m_impl->m_statsMutex);
        for (const auto& [pid, stats] : m_impl->m_processStats) {
            pids.push_back(pid);
        }
    } catch (...) {}
    return pids;
}

void RansomwareDetector::WhitelistProcess(uint32_t pid) {
    try {
        std::unique_lock lock(m_impl->m_whitelistMutex);
        m_impl->m_whitelistedPids.insert(pid);
    } catch (...) {}
}

void RansomwareDetector::UnwhitelistProcess(uint32_t pid) {
    try {
        std::unique_lock lock(m_impl->m_whitelistMutex);
        m_impl->m_whitelistedPids.erase(pid);
    } catch (...) {}
}

bool RansomwareDetector::IsProcessWhitelisted(uint32_t pid) const {
    try {
        std::shared_lock lock(m_impl->m_whitelistMutex);
        return m_impl->m_whitelistedPids.count(pid) > 0;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

double RansomwareDetector::CalculateEntropy(std::span<const uint8_t> buffer) {
    if (buffer.empty()) return 0.0;

    std::array<uint64_t, 256> counts{};
    for (uint8_t byte : buffer) {
        counts[byte]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(buffer.size());

    for (uint64_t count : counts) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

EntropyResult RansomwareDetector::AnalyzeEntropy(std::span<const uint8_t> buffer) {
    EntropyResult result;

    try {
        if (buffer.size() < RansomwareConstants::MIN_ENTROPY_BUFFER_SIZE) {
            return result;
        }

        // Limit sample size for performance
        size_t sampleSize = std::min(buffer.size(), RansomwareConstants::ENTROPY_SAMPLE_SIZE);
        std::span<const uint8_t> sample = buffer.subspan(0, sampleSize);

        // Shannon Entropy
        result.shannonEntropy = CalculateEntropy(sample);

        // Chi-squared test
        std::array<uint64_t, 256> counts{};
        for (uint8_t byte : sample) counts[byte]++;

        double expected = static_cast<double>(sampleSize) / 256.0;
        for (uint64_t count : counts) {
            double diff = static_cast<double>(count) - expected;
            result.chiSquared += (diff * diff) / expected;
        }

        // Monte Carlo Pi
        // (Simplified approximation for speed)
        size_t inside = 0;
        for (size_t i = 0; i < sampleSize / 2; i++) {
            double x = static_cast<double>(sample[i*2]) / 255.0;
            double y = static_cast<double>(sample[i*2+1]) / 255.0;
            if (x*x + y*y <= 1.0) inside++;
        }
        result.monteCarloPi = 4.0 * static_cast<double>(inside) / (sampleSize / 2);

        // Determination
        if (result.shannonEntropy > RansomwareConstants::ENTROPY_THRESHOLD &&
            std::abs(result.monteCarloPi - 3.14159) < RansomwareConstants::PI_DEVIATION_THRESHOLD) {
            result.isEncrypted = true;
            result.confidence = 0.9;
        } else if (result.shannonEntropy > RansomwareConstants::MIN_SUSPICION_ENTROPY) {
            result.isEncrypted = true;
            result.confidence = 0.6;
        }

    } catch (...) {
        // Fallback to safe default
    }

    return result;
}

bool RansomwareDetector::IsEncrypted(std::span<const uint8_t> buffer) {
    auto result = AnalyzeEntropy(buffer);
    return result.isEncrypted;
}

// ============================================================================
// UTILITY
// ============================================================================

bool RansomwareDetector::IsCompressedType(std::wstring_view filePath) const {
    try {
        fs::path p(filePath);
        std::wstring ext = p.extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        return COMPRESSED_EXTENSIONS.count(ext) > 0;
    } catch (...) {
        return false;
    }
}

bool RansomwareDetector::SelfTest() {
    try {
        Utils::Logger::Info("RansomwareDetector: Running self-test...");

        // Test 1: Entropy Calculation
        {
            // Low entropy buffer (all zeros)
            std::vector<uint8_t> lowEntropy(1024, 0);
            if (CalculateEntropy(lowEntropy) > 1.0) {
                Utils::Logger::Error("RansomwareDetector: Self-test failed (Low entropy check)");
                return false;
            }

            // High entropy buffer (random)
            std::vector<uint8_t> highEntropy(1024);
            std::mt19937 gen(42); // Deterministic seed
            std::uniform_int_distribution<> dis(0, 255);
            for (auto& b : highEntropy) b = static_cast<uint8_t>(dis(gen));

            double h = CalculateEntropy(highEntropy);
            if (h < 7.0) {
                Utils::Logger::Error("RansomwareDetector: Self-test failed (High entropy check: {})", h);
                return false;
            }
        }

        // Test 2: Extension Check
        {
            if (!IsCompressedType(L"test.zip")) {
                Utils::Logger::Error("RansomwareDetector: Self-test failed (Extension check)");
                return false;
            }
        }

        Utils::Logger::Info("RansomwareDetector: Self-test PASSED");
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("RansomwareDetector: Self-test failed: {}", ex.what());
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
// CALLBACKS
// ============================================================================

void RansomwareDetector::SetDetectionCallback(DetectionCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_detectionCallback = std::move(callback);
}

void RansomwareDetector::SetBlockCallback(BlockCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_blockCallback = std::move(callback);
}

void RansomwareDetector::SetPreWriteCallback(PreWriteCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_preWriteCallback = std::move(callback);
}

// ============================================================================
// IOStats Implementation
// ============================================================================

double IOStats::GetWriteRate() const {
    std::lock_guard lock(mutex);
    if (writeTimestamps.empty()) return 0.0;

    auto duration = RansomwareConstants::RATE_WINDOW_SECS;
    return static_cast<double>(writeTimestamps.size()) / static_cast<double>(duration);
}

double IOStats::GetRenameRate() const {
    std::lock_guard lock(mutex);
    if (renameTimestamps.empty()) return 0.0;

    auto duration = RansomwareConstants::RATE_WINDOW_SECS;
    return static_cast<double>(renameTimestamps.size()) / static_cast<double>(duration);
}

void IOStats::Reset() noexcept {
    std::lock_guard lock(mutex);
    writeCount = 0;
    renameCount = 0;
    deleteCount = 0;
    highEntropyWrites = 0;
    bytesWritten = 0;
    encryptedBytesWritten = 0;
    writeTimestamps.clear();
    renameTimestamps.clear();
    deleteTimestamps.clear();
    affectedExtensions.clear();
    isBlocked = false;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool RansomwareDetectorConfiguration::IsValid() const noexcept {
    if (entropyThreshold < 0.0 || entropyThreshold > 8.0) return false;
    if (maxWritesPerSecond == 0) return false;
    return true;
}

// ============================================================================
// STATISTICS
// ============================================================================

DetectionStatistics RansomwareDetector::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void RansomwareDetector::ResetStatistics() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
}

void DetectionStatistics::Reset() noexcept {
    totalOperations = 0;
    operationsBlocked = 0;
    processesTerminated = 0;
    honeypotTriggers = 0;
    highEntropyWrites = 0;
    falsePositives = 0;
    startTime = Clock::now();
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string EntropyResult::ToJson() const {
    nlohmann::json j;
    j["shannonEntropy"] = shannonEntropy;
    j["chiSquared"] = chiSquared;
    j["monteCarloPi"] = monteCarloPi;
    j["isEncrypted"] = isEncrypted;
    j["confidence"] = confidence;
    return j.dump();
}

std::string IOStats::ToJson() const {
    std::lock_guard lock(mutex);
    nlohmann::json j;
    j["pid"] = pid;
    j["processName"] = std::string(processName.begin(), processName.end());
    j["writeCount"] = writeCount.load();
    j["renameCount"] = renameCount.load();
    j["highEntropyWrites"] = highEntropyWrites.load();
    j["writeRate"] = GetWriteRate();
    return j.dump();
}

std::string DetectionEvent::ToJson() const {
    nlohmann::json j;
    j["pid"] = pid;
    j["filePath"] = std::string(filePath.begin(), filePath.end());
    j["verdict"] = static_cast<int>(verdict);
    j["action"] = static_cast<int>(action);
    j["confidence"] = confidence;
    if (entropyResult) {
        j["entropy"] = nlohmann::json::parse(entropyResult->ToJson());
    }
    return j.dump();
}

std::string DetectionStatistics::ToJson() const {
    nlohmann::json j;
    j["totalOperations"] = totalOperations.load();
    j["operationsBlocked"] = operationsBlocked.load();
    j["processesTerminated"] = processesTerminated.load();
    j["honeypotTriggers"] = honeypotTriggers.load();
    j["highEntropyWrites"] = highEntropyWrites.load();
    return j.dump();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVerdictName(DetectionVerdict verdict) noexcept {
    switch (verdict) {
        case DetectionVerdict::Clean: return "Clean";
        case DetectionVerdict::Suspicious: return "Suspicious";
        case DetectionVerdict::PossibleRansom: return "PossibleRansom";
        case DetectionVerdict::ConfirmedRansom: return "ConfirmedRansom";
        case DetectionVerdict::Honeypot: return "Honeypot";
        default: return "Unknown";
    }
}

std::string_view GetActionName(DetectionAction action) noexcept {
    switch (action) {
        case DetectionAction::Allow: return "Allow";
        case DetectionAction::AllowWithBackup: return "AllowWithBackup";
        case DetectionAction::Block: return "Block";
        case DetectionAction::BlockAndKill: return "BlockAndKill";
        case DetectionAction::Quarantine: return "Quarantine";
        default: return "Unknown";
    }
}

} // namespace Ransomware
} // namespace ShadowStrike
