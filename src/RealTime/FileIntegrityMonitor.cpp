/**
 * ============================================================================
 * ShadowStrike Real-Time - FILE INTEGRITY MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file FileIntegrityMonitor.cpp
 * @brief Implementation of the File Integrity Monitor (The Surveyor)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "FileIntegrityMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ThreadPool.hpp"

#include <algorithm>
#include <mutex>
#include <fstream>
#include <sstream>
#include <thread>
#include <future>
#include <map>
#include <set>

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

    /// @brief Generate unique event ID
    uint64_t GenerateEventId() {
        static std::atomic<uint64_t> idCounter{1};
        return idCounter.fetch_add(1);
    }

    /// @brief Convert file time to system_clock
    std::chrono::system_clock::time_point FileTimeToSystemClock(const FILETIME& ft) {
        ULARGE_INTEGER ull;
        ull.LowPart = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;

        // Windows epoch starts 1601-01-01, Unix 1970-01-01
        // Difference is 116444736000000000 100-nanosecond intervals
        // 100ns ticks to seconds: / 10,000,000

        constexpr uint64_t WINDOWS_EPOCH_DIFF = 116444736000000000ULL;
        if (ull.QuadPart < WINDOWS_EPOCH_DIFF) return std::chrono::system_clock::time_point{};

        uint64_t unixTimeMs = (ull.QuadPart - WINDOWS_EPOCH_DIFF) / 10000;
        return std::chrono::system_clock::time_point(std::chrono::milliseconds(unixTimeMs));
    }

    /// @brief Calculate file hash (wrapper)
    std::string CalculateHash(const std::wstring& path, HashAlgorithm algo) {
        // In a real implementation, this calls HashStore or CryptoUtils
        // Stub implementation
        return "SHA256_HASH_PLACEHOLDER_" + Utils::StringUtils::WideToUtf8(path);
    }

} // anonymous namespace

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

const char* FileChangeTypeToString(FileChangeType type) noexcept {
    switch (type) {
        case FileChangeType::Created: return "Created";
        case FileChangeType::Deleted: return "Deleted";
        case FileChangeType::Modified: return "Modified";
        case FileChangeType::Renamed: return "Renamed";
        case FileChangeType::PermissionsChanged: return "PermissionsChanged";
        case FileChangeType::AttributesChanged: return "AttributesChanged";
        default: return "Unknown";
    }
}

const char* FileCategoryToString(FileCategory category) noexcept {
    switch (category) {
        case FileCategory::SystemDLL: return "SystemDLL";
        case FileCategory::SystemExecutable: return "SystemExecutable";
        case FileCategory::ConfigurationFile: return "ConfigurationFile";
        case FileCategory::Driver: return "Driver";
        default: return "Other";
    }
}

const char* FileChangeToMitre(FileChangeType type) noexcept {
    switch (type) {
        case FileChangeType::Modified: return "T1565"; // Data Manipulation
        case FileChangeType::Deleted: return "T1070";  // Indicator Removal
        case FileChangeType::Renamed: return "T1036";  // Masquerading
        case FileChangeType::PermissionsChanged: return "T1222"; // File Permissions Modification
        default: return "";
    }
}

std::wstring NormalizeFilePath(const std::wstring& path) noexcept {
    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);
    if (!normalized.empty() && normalized.back() == L'\\') {
        normalized.pop_back();
    }
    return normalized;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct FileIntegrityMonitor::Impl {
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------

    // Configuration & State
    FIMConfig config;
    FIMStats stats;
    std::atomic<bool> isRunning{false};
    std::atomic<bool> isInitialized{false};

    // Resources
    std::shared_ptr<Utils::ThreadPool> threadPool;
    HashStore::HashStore* hashStore = nullptr;
    Whitelist::WhiteListStore* whitelist = nullptr;

    // Baselines
    mutable std::shared_mutex baselineMutex;
    std::unordered_map<std::wstring, FileBaseline> baselines; // Key is normalized path

    // Rules
    mutable std::shared_mutex ruleMutex;
    std::vector<MonitoringRule> rules;

    // Monitoring
    mutable std::shared_mutex monitorMutex;
    std::set<std::wstring> monitoredDirectories;
    std::unique_ptr<std::thread> monitorThread;
    std::atomic<bool> stopMonitorThread{false};
    std::unique_ptr<std::thread> verificationThread;
    std::atomic<bool> stopVerificationThread{false};

    // Changes
    mutable std::mutex queueMutex;
    std::vector<FileChangeEvent> changeQueue;

    // Callbacks
    mutable std::shared_mutex callbackMutex;
    std::map<uint64_t, FileChangeCallback> changeCallbacks;
    std::map<uint64_t, ViolationCallback> violationCallbacks;
    std::map<uint64_t, VerificationCallback> verificationCallbacks;
    std::map<uint64_t, RestoreCallback> restoreCallbacks;
    std::atomic<uint64_t> nextCallbackId{1};

    // -------------------------------------------------------------------------
    // Implementation Methods
    // -------------------------------------------------------------------------

    Impl() {
        stats.Reset();
    }

    bool Initialize(std::shared_ptr<Utils::ThreadPool> tp, const FIMConfig& cfg) {
        if (isInitialized) return false;

        threadPool = tp;
        config = cfg;

        // Load default rules if needed
        if (rules.empty()) {
            MonitoringRule sysRule;
            sysRule.ruleId = "WIN-SYS-001";
            sysRule.name = L"System32 Critical";
            sysRule.pathPattern = L"C:\\Windows\\System32\\*.dll";
            sysRule.category = FileCategory::SystemDLL;
            sysRule.isCritical = true;
            rules.push_back(sysRule);
        }

        isInitialized = true;
        Utils::Logger::Info("FileIntegrityMonitor initialized");
        return true;
    }

    void Shutdown() {
        if (!isInitialized) return;
        Stop();

        isInitialized = false;
        Utils::Logger::Info("FileIntegrityMonitor shutdown");
    }

    void Start() {
        if (!isInitialized || isRunning) return;

        isRunning = true;
        stopMonitorThread = false;
        stopVerificationThread = false;

        // Start threads
        if (config.realTimeMonitoring) {
            monitorThread = std::make_unique<std::thread>(&Impl::DirectoryMonitorLoop, this);
        }

        if (config.scheduledVerification) {
            verificationThread = std::make_unique<std::thread>(&Impl::VerificationLoop, this);
        }

        Utils::Logger::Info("FileIntegrityMonitor started");
    }

    void Stop() {
        if (!isRunning) return;

        isRunning = false;
        stopMonitorThread = true;
        stopVerificationThread = true;

        if (monitorThread && monitorThread->joinable()) monitorThread->join();
        if (verificationThread && verificationThread->joinable()) verificationThread->join();

        Utils::Logger::Info("FileIntegrityMonitor stopped");
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    bool CreateBaseline(const std::wstring& filePath) {
        std::wstring normPath = NormalizeFilePath(filePath);

        if (!std::filesystem::exists(filePath)) {
            return false;
        }

        FileBaseline baseline;
        baseline.path = filePath;
        baseline.normalizedPath = normPath;
        baseline.baselineTime = std::chrono::system_clock::now();
        baseline.hashSHA256 = CalculateHash(filePath, HashAlgorithm::SHA256);

        // Attributes
        std::error_code ec;
        auto status = std::filesystem::status(filePath, ec);
        if (!ec) {
            baseline.attributes.size = std::filesystem::file_size(filePath, ec);
            // Times would need WinAPI GetFileTime
        }

        {
            std::unique_lock lock(baselineMutex);
            baselines[normPath] = baseline;
        }

        stats.baselinesCreated++;
        stats.monitoredFiles = baselines.size();
        return true;
    }

    VerificationResult VerifyIntegrity(const std::wstring& filePath) {
        VerificationResult result;
        result.filePath = filePath;

        std::wstring normPath = NormalizeFilePath(filePath);
        std::shared_lock lock(baselineMutex);

        auto it = baselines.find(normPath);
        if (it == baselines.end()) {
            result.status = VerificationStatus::NoBaseline;
            result.hasBaseline = false;
            return result;
        }

        result.hasBaseline = true;
        result.expectedHash = it->second.hashSHA256;

        // Check existence
        if (!std::filesystem::exists(filePath)) {
            result.status = VerificationStatus::NotFound;
            result.violations.push_back(FileChangeType::Deleted);
            stats.verificationsFailed++;
            return result;
        }

        // Calculate current hash
        std::string currentHash = CalculateHash(filePath, HashAlgorithm::SHA256);
        result.currentHash = currentHash;

        if (currentHash != it->second.hashSHA256) {
            result.status = VerificationStatus::Violated;
            result.hashMatches = false;
            result.violations.push_back(FileChangeType::Modified);
            stats.violations++;

            // Notify violation
            NotifyViolation(it->second, currentHash);
        } else {
            result.status = VerificationStatus::Verified;
            stats.verificationsPassed++;
        }

        stats.verificationsPerformed++;

        // Update last verification time (needs const_cast or mutable logic, strictly baselines map is guarded)
        // Ideally we update the baseline's lastVerification field, but we hold a shared lock here.
        // For simplicity in this implementation, we skip updating the record during read.

        return result;
    }

    void NotifyViolation(const FileBaseline& baseline, const std::string& actualHash) {
        IntegrityViolation violation;
        violation.violationId = GenerateEventId();
        violation.timestamp = std::chrono::system_clock::now();
        violation.filePath = baseline.path;
        violation.category = baseline.category;
        violation.violationType = FileChangeType::Modified; // Simplified
        violation.expectedHash = baseline.hashSHA256;
        violation.actualHash = actualHash;
        violation.severity = 90.0; // High

        std::shared_lock lock(callbackMutex);
        for (const auto& [id, cb] : violationCallbacks) {
            try { cb(violation); } catch (...) {}
        }
    }

    // -------------------------------------------------------------------------
    // Threads
    // -------------------------------------------------------------------------

    void DirectoryMonitorLoop() {
        while (!stopMonitorThread) {
            // Simulate monitoring loop (in real world uses ReadDirectoryChangesW)
            std::this_thread::sleep_for(std::chrono::milliseconds(config.debounceMs));

            // Process queue
            ProcessChangeQueue();
        }
    }

    void VerificationLoop() {
        while (!stopVerificationThread) {
            // Periodic verification
            VerifyAll();

            // Sleep for interval
            for (uint32_t i = 0; i < config.verifyIntervalSec && !stopVerificationThread; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void ProcessChangeQueue() {
        std::vector<FileChangeEvent> events;
        {
            std::unique_lock lock(queueMutex);
            if (changeQueue.empty()) return;
            events = std::move(changeQueue);
            changeQueue.clear();
        }

        for (const auto& evt : events) {
            // Notify callbacks
            std::shared_lock lock(callbackMutex);
            for (const auto& [id, cb] : changeCallbacks) {
                try { cb(evt); } catch (...) {}
            }
        }
    }

    BatchVerificationResult VerifyAll() {
        BatchVerificationResult batch;
        batch.startTime = std::chrono::system_clock::now();

        std::vector<std::wstring> paths;
        {
            std::shared_lock lock(baselineMutex);
            for (const auto& kv : baselines) {
                paths.push_back(kv.second.path);
            }
        }

        batch.totalFiles = paths.size();

        for (const auto& path : paths) {
            if (stopVerificationThread) break;
            VerificationResult res = VerifyIntegrity(path);
            batch.results.push_back(res);

            if (res.status == VerificationStatus::Verified) batch.verifiedOK++;
            else if (res.status == VerificationStatus::Violated) batch.violations++;
            else if (res.status == VerificationStatus::NotFound) batch.notFound++;
            else batch.errors++;
        }

        batch.endTime = std::chrono::system_clock::now();
        return batch;
    }
};

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

FileIntegrityMonitor& FileIntegrityMonitor::Instance() {
    static FileIntegrityMonitor instance;
    return instance;
}

FileIntegrityMonitor::FileIntegrityMonitor() : m_impl(std::make_unique<Impl>()) {}
FileIntegrityMonitor::~FileIntegrityMonitor() = default;

bool FileIntegrityMonitor::Initialize() {
    return m_impl->Initialize(nullptr, FIMConfig::CreateDefault());
}

bool FileIntegrityMonitor::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return m_impl->Initialize(threadPool, FIMConfig::CreateDefault());
}

bool FileIntegrityMonitor::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool, const FIMConfig& config) {
    return m_impl->Initialize(threadPool, config);
}

void FileIntegrityMonitor::Shutdown() {
    m_impl->Shutdown();
}

void FileIntegrityMonitor::StartMonitoring() {
    m_impl->Start();
}

void FileIntegrityMonitor::StopMonitoring() {
    m_impl->Stop();
}

bool FileIntegrityMonitor::IsMonitoring() const noexcept {
    return m_impl->isRunning;
}

void FileIntegrityMonitor::UpdateConfig(const FIMConfig& config) {
    m_impl->config = config;
}

FIMConfig FileIntegrityMonitor::GetConfig() const {
    return m_impl->config;
}

// Baselines
bool FileIntegrityMonitor::CreateBaseline(const std::wstring& filePath) {
    return m_impl->CreateBaseline(filePath);
}

size_t FileIntegrityMonitor::CreateBaselines(const std::wstring& directoryPath, bool recursive) {
    size_t count = 0;
    try {
        if (!std::filesystem::exists(directoryPath)) return 0;

        auto options = recursive ?
            std::filesystem::recursive_directory_iterator(directoryPath) :
            std::filesystem::recursive_directory_iterator(); // Invalid for non-recursive, handling below

        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    if (m_impl->CreateBaseline(entry.path().wstring())) count++;
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    if (m_impl->CreateBaseline(entry.path().wstring())) count++;
                }
            }
        }
    } catch (...) {}
    return count;
}

bool FileIntegrityMonitor::UpdateBaseline(const std::wstring& filePath) {
    return m_impl->CreateBaseline(filePath); // Re-create essentially updates
}

bool FileIntegrityMonitor::DeleteBaseline(const std::wstring& filePath) {
    std::wstring norm = NormalizeFilePath(filePath);
    std::unique_lock lock(m_impl->baselineMutex);
    return m_impl->baselines.erase(norm) > 0;
}

std::optional<FileBaseline> FileIntegrityMonitor::GetBaseline(const std::wstring& filePath) const {
    std::wstring norm = NormalizeFilePath(filePath);
    std::shared_lock lock(m_impl->baselineMutex);
    auto it = m_impl->baselines.find(norm);
    if (it != m_impl->baselines.end()) return it->second;
    return std::nullopt;
}

std::vector<FileBaseline> FileIntegrityMonitor::GetAllBaselines() const {
    std::shared_lock lock(m_impl->baselineMutex);
    std::vector<FileBaseline> result;
    result.reserve(m_impl->baselines.size());
    for (const auto& kv : m_impl->baselines) result.push_back(kv.second);
    return result;
}

std::vector<FileBaseline> FileIntegrityMonitor::GetBaselinesByCategory(FileCategory category) const {
    std::shared_lock lock(m_impl->baselineMutex);
    std::vector<FileBaseline> result;
    for (const auto& kv : m_impl->baselines) {
        if (kv.second.category == category) result.push_back(kv.second);
    }
    return result;
}

// Verification
VerificationResult FileIntegrityMonitor::VerifyIntegrity(const std::wstring& filePath) {
    return m_impl->VerifyIntegrity(filePath);
}

BatchVerificationResult FileIntegrityMonitor::VerifyAll() {
    return m_impl->VerifyAll();
}

// Callbacks
uint64_t FileIntegrityMonitor::RegisterViolationCallback(ViolationCallback callback) {
    std::unique_lock lock(m_impl->callbackMutex);
    uint64_t id = m_impl->nextCallbackId++;
    m_impl->violationCallbacks[id] = std::move(callback);
    return id;
}

bool FileIntegrityMonitor::UnregisterViolationCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->callbackMutex);
    return m_impl->violationCallbacks.erase(callbackId) > 0;
}

// Stubs for other interface methods to ensure linking
bool FileIntegrityMonitor::ImportBaselines(const std::wstring& filePath) { return false; }
bool FileIntegrityMonitor::ExportBaselines(const std::wstring& filePath) const { return false; }
size_t FileIntegrityMonitor::CreateSystemBaselines() { return 0; }
BatchVerificationResult FileIntegrityMonitor::VerifyDirectory(const std::wstring& directoryPath, bool recursive) { return BatchVerificationResult{}; }
BatchVerificationResult FileIntegrityMonitor::VerifyByCategory(FileCategory category) { return BatchVerificationResult{}; }
bool FileIntegrityMonitor::QuickVerify(const std::wstring& filePath) { return false; }
FIMAction FileIntegrityMonitor::OnFileChanged(const FileChangeEvent& event) { return FIMAction::LogOnly; }
void FileIntegrityMonitor::OnFileChanged(const std::wstring& filePath, FileChangeType changeType, uint32_t processId) {}
std::vector<FileChangeEvent> FileIntegrityMonitor::GetRecentChanges(size_t count) const { return {}; }
std::vector<FileChangeEvent> FileIntegrityMonitor::GetFileChanges(const std::wstring& filePath) const { return {}; }
bool FileIntegrityMonitor::RestoreFile(const std::wstring& filePath) { return false; }
bool FileIntegrityMonitor::RestoreFile(const std::wstring& filePath, uint32_t version) { return false; }
size_t FileIntegrityMonitor::RestoreAllViolations() { return 0; }
std::vector<IntegrityViolation> FileIntegrityMonitor::GetViolations() const { return {}; }
std::vector<IntegrityViolation> FileIntegrityMonitor::GetUnresolvedViolations() const { return {}; }
void FileIntegrityMonitor::ResolveViolation(uint64_t violationId) {}
bool FileIntegrityMonitor::AddRule(const MonitoringRule& rule) { return false; }
bool FileIntegrityMonitor::RemoveRule(const std::string& ruleId) { return false; }
void FileIntegrityMonitor::SetRuleEnabled(const std::string& ruleId, bool enabled) {}
std::optional<MonitoringRule> FileIntegrityMonitor::GetRule(const std::string& ruleId) const { return std::nullopt; }
std::vector<MonitoringRule> FileIntegrityMonitor::GetRules() const { return {}; }
bool FileIntegrityMonitor::LoadRulesFromFile(const std::wstring& filePath) { return false; }
bool FileIntegrityMonitor::SaveRulesToFile(const std::wstring& filePath) const { return false; }
bool FileIntegrityMonitor::AddMonitoredDirectory(const std::wstring& directoryPath, bool recursive) { return false; }
void FileIntegrityMonitor::RemoveMonitoredDirectory(const std::wstring& directoryPath) {}
std::vector<std::wstring> FileIntegrityMonitor::GetMonitoredDirectories() const { return {}; }
bool FileIntegrityMonitor::IsFileMonitored(const std::wstring& filePath) const { return false; }
FileCategory FileIntegrityMonitor::GetFileCategory(const std::wstring& filePath) const { return FileCategory::Unknown; }
std::string FileIntegrityMonitor::CalculateFileHash(const std::wstring& filePath, HashAlgorithm algorithm) const { return ""; }
std::optional<FileAttributes> FileIntegrityMonitor::GetFileAttributes(const std::wstring& filePath) const { return std::nullopt; }
std::optional<FileSignatureInfo> FileIntegrityMonitor::GetFileSignature(const std::wstring& filePath) const { return std::nullopt; }
FIMStats FileIntegrityMonitor::GetStats() const { return m_impl->stats; }
void FileIntegrityMonitor::ResetStats() { m_impl->stats.Reset(); }
bool FileIntegrityMonitor::GenerateComplianceReport(const std::wstring& outputPath, const std::vector<std::string>& complianceTags) const { return false; }
std::vector<FileChangeEvent> FileIntegrityMonitor::GetAuditLog(std::chrono::system_clock::time_point startTime, std::chrono::system_clock::time_point endTime) const { return {}; }
uint64_t FileIntegrityMonitor::RegisterChangeCallback(FileChangeCallback callback) { return 0; }
bool FileIntegrityMonitor::UnregisterChangeCallback(uint64_t callbackId) { return false; }
uint64_t FileIntegrityMonitor::RegisterVerificationCallback(VerificationCallback callback) { return 0; }
bool FileIntegrityMonitor::UnregisterVerificationCallback(uint64_t callbackId) { return false; }
uint64_t FileIntegrityMonitor::RegisterRestoreCallback(RestoreCallback callback) { return 0; }
bool FileIntegrityMonitor::UnregisterRestoreCallback(uint64_t callbackId) { return false; }
void FileIntegrityMonitor::SetHashStore(HashStore::HashStore* store) { m_impl->hashStore = store; }
void FileIntegrityMonitor::SetDatabaseManager(Database::DatabaseManager* manager) {}
void FileIntegrityMonitor::SetFileBackupManager(Backup::FileBackupManager* manager) {}

} // namespace RealTime
} // namespace ShadowStrike
