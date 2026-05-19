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
 * ShadowStrike NGAV - INCREMENTAL BACKUP MODULE
 * ============================================================================
 *
 * @file IncrementalBackup.cpp
 * @brief Implementation of enterprise-grade incremental backup engine with
 *        deduplication, compression, and content-defined chunking.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "IncrementalBackup.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CompressionUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <execution>
#include <random>
#include <thread>
#include <future>
#include <condition_variable>
#include <limits>
#include <winioctl.h>

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// ANONYMOUS NAMESPACE - HELPERS AND CONSTANTS
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"IncrementalBackup";

    /// Maximum file size for single-pass in-memory processing (256 MB).
    /// Files exceeding this are skipped with a warning; streaming support
    /// would be required for multi-gigabyte backup targets.
    constexpr size_t MAX_SINGLE_FILE_SIZE = 256ULL * 1024 * 1024;

    /// Magic bytes for dedup index file: "SSDI"
    constexpr uint32_t DEDUP_INDEX_MAGIC = 0x49445353;
    constexpr uint32_t DEDUP_INDEX_VERSION = 1;

    /// Maximum dedup index entries to prevent unbounded growth
    constexpr size_t MAX_DEDUP_INDEX_ENTRIES = 16 * 1024 * 1024;

    /// Maximum completed sync results to retain in memory
    constexpr size_t MAX_COMPLETED_RESULTS = 256;
    constexpr size_t MAX_SYNC_FILE_ENUMERATION = 10'000'000;

    // Gear hash table for FastCDC (deterministic LCG generation)
    constexpr std::array<uint64_t, 256> GEAR_MATRIX = []() {
        std::array<uint64_t, 256> matrix{};
        uint64_t seed = 0x931e88d9f964a781;
        for (size_t i = 0; i < 256; i++) {
            seed = (seed * 6364136223846793005ULL) + 1442695040888963407ULL;
            matrix[i] = seed;
        }
        return matrix;
    }();

    /// Custom hash for std::array<uint8_t,32> map keys.
    /// Input is already a cryptographic digest; FNV-1a over leading 16 bytes
    /// gives excellent bucket distribution.
    struct ArrayHash {
        size_t operator()(const std::array<uint8_t, 32>& a) const noexcept {
            uint64_t h = 0xcbf29ce484222325ULL;
            for (size_t i = 0; i < 16; ++i) {
                h ^= a[i];
                h *= 0x100000001b3ULL;
            }
            return static_cast<size_t>(h);
        }
    };

    std::string BytesToHex(const std::array<uint8_t, 32>& bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t b : bytes) {
            oss << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    }

    std::string BytesToHex(const uint8_t* data, size_t size) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < size; ++i) {
            oss << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream oss;
        for (char c : s) {
            switch (c) {
                case '"':  oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b";  break;
                case '\f': oss << "\\f";  break;
                case '\n': oss << "\\n";  break;
                case '\r': oss << "\\r";  break;
                case '\t': oss << "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << static_cast<int>(c);
                    } else {
                        oss << c;
                    }
            }
        }
        return oss.str();
    }

    /// Maps our CompressionAlgorithm enum to the Windows Compression API
    /// algorithm enum provided by CompressionUtils.
    Utils::CompressionUtils::Algorithm
    MapToWindowsCompression(CompressionAlgorithm alg) noexcept {
        switch (alg) {
            case CompressionAlgorithm::LZ4:
            case CompressionAlgorithm::Brotli:
                return Utils::CompressionUtils::Algorithm::XpressHuff;
            case CompressionAlgorithm::LZ4HC:
            case CompressionAlgorithm::ZSTD:
            case CompressionAlgorithm::LZMA:
                return Utils::CompressionUtils::Algorithm::Lzms;
            default:
                return Utils::CompressionUtils::Algorithm::XpressHuff;
        }
    }

    /// Generates a cryptographically random sync ID using Windows BCryptGenRandom.
    std::string GenerateSecureSyncId() noexcept {
        std::array<uint8_t, 16> buf{};
        NTSTATUS status = BCryptGenRandom(
            nullptr, buf.data(), static_cast<ULONG>(buf.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"GenerateSecureSyncId: BCryptGenRandom failed status=0x%08X",
                static_cast<unsigned>(status));
            return {};
        }
        return BytesToHex(buf.data(), buf.size());
    }

    /// Normalises a volume path to the \\.\X: device form.
    std::wstring NormalizeVolumePath(const std::wstring& path) noexcept {
        if (path.size() >= 4 && path.substr(0, 4) == L"\\\\.\\") {
            return path;
        }
        std::wstring vol = L"\\\\.\\";
        if (!path.empty()) {
            vol += path[0];
            vol += L':';
        }
        return vol;
    }

    [[nodiscard]] bool IsValidDosVolumePath(const std::wstring& path) noexcept {
        if (path.size() == 6 && path.substr(0, 4) == L"\\\\.\\" &&
            path[5] == L':' && ((path[4] >= L'A' && path[4] <= L'Z') ||
                                (path[4] >= L'a' && path[4] <= L'z'))) {
            return true;
        }
        if ((path.size() == 2 || path.size() == 3) &&
            ((path[0] >= L'A' && path[0] <= L'Z') ||
             (path[0] >= L'a' && path[0] <= L'z')) &&
            path[1] == L':' &&
            (path.size() == 2 || path[2] == L'\\')) {
            return true;
        }
        return false;
    }

    [[nodiscard]] uint64_t SaturatingAddU64(uint64_t lhs, uint64_t rhs) noexcept {
        if (rhs > (std::numeric_limits<uint64_t>::max)() - lhs) {
            return (std::numeric_limits<uint64_t>::max)();
        }
        return lhs + rhs;
    }

    [[nodiscard]] bool PathContainsOrEquals(const fs::path& parent, const fs::path& child) {
        const std::wstring parentNative = parent.native();
        const std::wstring childNative = child.native();
        if (_wcsicmp(parentNative.c_str(), childNative.c_str()) == 0) {
            return true;
        }
        if (childNative.size() <= parentNative.size()) {
            return false;
        }
        if (_wcsnicmp(childNative.c_str(), parentNative.c_str(), parentNative.size()) != 0) {
            return false;
        }
        wchar_t boundary = childNative[parentNative.size()];
        return boundary == L'\\' || boundary == L'/';
    }

}  // anonymous namespace

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> IncrementalBackup::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetChunkingAlgorithmName(ChunkingAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case ChunkingAlgorithm::Fixed:     return "Fixed";
        case ChunkingAlgorithm::RabinKarp: return "RabinKarp";
        case ChunkingAlgorithm::Buzhash:   return "Buzhash";
        case ChunkingAlgorithm::FastCDC:   return "FastCDC";
        case ChunkingAlgorithm::Gear:      return "Gear";
        default:                           return "Unknown";
    }
}

[[nodiscard]] std::string_view GetCompressionAlgorithmName(CompressionAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case CompressionAlgorithm::None:   return "None";
        case CompressionAlgorithm::LZ4:    return "LZ4";
        case CompressionAlgorithm::LZ4HC:  return "LZ4HC";
        case CompressionAlgorithm::ZSTD:   return "ZSTD";
        case CompressionAlgorithm::LZMA:   return "LZMA";
        case CompressionAlgorithm::Brotli: return "Brotli";
        default:                           return "Unknown";
    }
}

[[nodiscard]] std::string_view GetChunkHashAlgorithmName(ChunkHashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case ChunkHashAlgorithm::XXHash64:  return "XXHash64";
        case ChunkHashAlgorithm::XXHash128: return "XXHash128";
        case ChunkHashAlgorithm::SHA256:    return "SHA256";
        case ChunkHashAlgorithm::BLAKE3:    return "BLAKE3";
        case ChunkHashAlgorithm::CityHash:  return "CityHash";
        default:                            return "Unknown";
    }
}

[[nodiscard]] std::string_view GetChangeTypeName(ChangeType type) noexcept {
    switch (type) {
        case ChangeType::None:     return "None";
        case ChangeType::Added:    return "Added";
        case ChangeType::Modified: return "Modified";
        case ChangeType::Deleted:  return "Deleted";
        case ChangeType::Renamed:  return "Renamed";
        case ChangeType::Metadata: return "Metadata";
        default:                   return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSyncStatusName(SyncStatus status) noexcept {
    switch (status) {
        case SyncStatus::Pending:       return "Pending";
        case SyncStatus::Scanning:      return "Scanning";
        case SyncStatus::Chunking:      return "Chunking";
        case SyncStatus::Deduplicating: return "Deduplicating";
        case SyncStatus::Compressing:   return "Compressing";
        case SyncStatus::Writing:       return "Writing";
        case SyncStatus::Completed:     return "Completed";
        case SyncStatus::Failed:        return "Failed";
        case SyncStatus::Cancelled:     return "Cancelled";
        default:                        return "Unknown";
    }
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

std::string ChunkDescriptor::GetHashHex() const {
    return BytesToHex(hash);
}

std::string ChunkDescriptor::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"hash\":\"" << GetHashHex() << "\","
        << "\"offset\":" << offset << ","
        << "\"originalSize\":" << originalSize << ","
        << "\"compressedSize\":" << compressedSize << ","
        << "\"compression\":\"" << GetCompressionAlgorithmName(compression) << "\","
        << "\"isDeduplicated\":" << (isDeduplicated ? "true" : "false")
        << "}";
    return oss.str();
}

std::string FileChangeRecord::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"path\":\"" << EscapeJson(path.string()) << "\","
        << "\"type\":\"" << GetChangeTypeName(changeType) << "\","
        << "\"size\":" << size << ","
        << "\"bytesChanged\":" << bytesChanged
        << "}";
    return oss.str();
}

std::string SyncResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"syncId\":\"" << syncId << "\","
        << "\"status\":\"" << GetSyncStatusName(status) << "\","
        << "\"durationSecs\":" << duration.count() << ","
        << "\"filesScanned\":" << filesScanned << ","
        << "\"filesChanged\":" << filesChanged << ","
        << "\"bytesScanned\":" << bytesScanned << ","
        << "\"bytesChanged\":" << bytesChanged << ","
        << "\"bytesAfterDedup\":" << bytesAfterDedup << ","
        << "\"dedupRatio\":" << dedupRatio << ","
        << "\"compressionRatio\":" << compressionRatio
        << "}";
    return oss.str();
}

std::string SyncProgress::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"syncId\":\"" << syncId << "\","
        << "\"status\":\"" << GetSyncStatusName(status) << "\","
        << "\"phase\":\"" << phase << "\","
        << "\"percentComplete\":" << percentComplete << ","
        << "\"filesProcessed\":" << filesProcessed << ","
        << "\"totalFiles\":" << totalFiles
        << "}";
    return oss.str();
}

bool ChunkingOptions::IsValid() const noexcept {
    return minChunkSize > 0 &&
           maxChunkSize >= minChunkSize &&
           avgChunkSize >= minChunkSize &&
           avgChunkSize <= maxChunkSize &&
           maxChunkSize <= static_cast<size_t>(UINT32_MAX);
}

void IncrementalStatistics::Reset() noexcept {
    totalSyncs = 0;
    successfulSyncs = 0;
    failedSyncs = 0;
    totalBytesProcessed = 0;
    totalBytesStored = 0;
    totalChunksCreated = 0;
    totalChunksDeduplicated = 0;
    bytesSavedByDedup = 0;
    bytesSavedByCompression = 0;
    uniqueChunks = 0;
    duplicateChunks = 0;
    for (auto& counter : byCompression) {
        counter.store(0, std::memory_order_relaxed);
    }
    startTime.store(Clock::now(), std::memory_order_relaxed);
}

std::string IncrementalStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalSyncs\":" << totalSyncs.load() << ","
        << "\"successfulSyncs\":" << successfulSyncs.load() << ","
        << "\"failedSyncs\":" << failedSyncs.load() << ","
        << "\"totalBytesProcessed\":" << totalBytesProcessed.load() << ","
        << "\"totalBytesStored\":" << totalBytesStored.load() << ","
        << "\"dedupSavingsBytes\":" << bytesSavedByDedup.load() << ","
        << "\"compressionSavingsBytes\":" << bytesSavedByCompression.load()
        << "}";
    return oss.str();
}

bool IncrementalConfiguration::IsValid() const noexcept {
    return chunkingOptions.IsValid() && bufferSize > 0 && threadCount > 0;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class IncrementalBackupImpl {
public:
    IncrementalBackupImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating IncrementalBackup implementation");
    }

    ~IncrementalBackupImpl() noexcept {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const IncrementalConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing IncrementalBackup");
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        try {
            if (!config.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration: check chunking/buffer/thread params");
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                return false;
            }

            m_config = config;

            if (m_config.enableDedup && !m_config.dedupIndexPath.empty()) {
                loadDedupIndex();
            } else if (m_config.enableDedup) {
                SS_LOG_INFO(LOG_CATEGORY, L"Using in-memory deduplication index");
            }

            m_initialized.store(true, std::memory_order_release);
            m_status.store(ModuleStatus::Ready, std::memory_order_release);
            m_stats.startTime.store(Clock::now(), std::memory_order_relaxed);

            SS_LOG_INFO(LOG_CATEGORY, L"IncrementalBackup initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }
    }

    void Shutdown() noexcept {
        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down IncrementalBackup");
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Step 1: Signal all active syncs to cancel (shared lock is sufficient
        // because we only write to atomic cancelFlag).
        {
            std::shared_lock lock(m_mutex);
            for (auto& [id, ctx] : m_activeSyncs) {
                ctx->cancelFlag.store(true, std::memory_order_release);
            }
        }

        // Step 2: Collect sync context pointers and join their worker threads
        // WITHOUT holding the main mutex (the workers may need it to finish).
        std::vector<std::shared_ptr<SyncContext>> toJoin;
        {
            std::shared_lock lock(m_mutex);
            toJoin.reserve(m_activeSyncs.size());
            for (auto& [id, ctx] : m_activeSyncs) {
                toJoin.push_back(ctx);
            }
        }
        for (auto& ctx : toJoin) {
            if (ctx->worker.joinable()) {
                ctx->worker.join();
            }
        }

        // Step 3: All worker threads are done. Take exclusive lock for cleanup.
        std::unique_lock lock(m_mutex);

        if (m_config.enableDedup && !m_config.dedupIndexPath.empty()) {
            saveDedupIndex();
        }

        m_activeSyncs.clear();
        m_completedSyncs.clear();
        m_dedupIndex.clear();
        m_chunkCache.clear();

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"IncrementalBackup shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const IncrementalConfiguration& config) noexcept {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"UpdateConfiguration: invalid config rejected");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        return true;
    }

    [[nodiscard]] IncrementalConfiguration GetConfiguration() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // SYNC OPERATIONS
    // ========================================================================

    [[nodiscard]] std::string StartSync(
        const fs::path& source,
        const fs::path& vault,
        const ChunkingOptions& options
    ) noexcept {
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"StartSync called before initialization");
            return "";
        }
        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Stopping) {
            SS_LOG_WARN(LOG_CATEGORY, L"StartSync rejected: module is shutting down");
            return "";
        }

        try {
            if (!options.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"StartSync rejected: invalid chunking options");
                return "";
            }
            std::error_code ec;
            if (source.empty() || !fs::exists(source, ec) || ec) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"StartSync rejected: source does not exist: %ls",
                    source.c_str());
                return "";
            }
            if (vault.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"StartSync rejected: vault path is empty");
                return "";
            }
            fs::path canonicalSource = fs::weakly_canonical(source, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"StartSync rejected: cannot canonicalize source %ls (%hs)",
                    source.c_str(), ec.message().c_str());
                return "";
            }
            ec.clear();
            fs::path canonicalVault = fs::weakly_canonical(vault, ec);
            if (ec) {
                canonicalVault = fs::absolute(vault, ec);
            }
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"StartSync rejected: cannot canonicalize vault %ls (%hs)",
                    vault.c_str(), ec.message().c_str());
                return "";
            }
            if (PathContainsOrEquals(canonicalSource, canonicalVault) ||
                PathContainsOrEquals(canonicalVault, canonicalSource)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"StartSync rejected: source and vault paths overlap");
                return "";
            }

            std::string syncId = GenerateSecureSyncId();
            if (syncId.empty()) {
                return "";
            }
            auto context = std::make_shared<SyncContext>();
            context->syncId = syncId;
            context->sourcePath = canonicalSource;
            context->vaultPath = canonicalVault;
            context->chunkingOptions = options;
            context->startTime = Clock::now();
            context->progress.syncId = syncId;
            context->progress.status = SyncStatus::Pending;
            context->progress.phase = "Initializing";

            {
                std::unique_lock lock(m_mutex);
                m_activeSyncs[syncId] = context;
            }

            // Launch worker thread; captured shared_ptr keeps context alive.
            try {
                context->worker = std::thread([this, context]() {
                    runSync(context);
                });
            } catch (const std::exception& ex) {
                std::unique_lock lock(m_mutex);
                m_activeSyncs.erase(syncId);
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"StartSync: failed to create worker thread: %hs",
                    ex.what());
                return "";
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Started sync %hs: %ls -> %ls",
                syncId.c_str(), source.c_str(), vault.c_str());

            return syncId;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to start sync: %hs", ex.what());
            return "";
        }
    }

    [[nodiscard]] bool CancelSync(const std::string& syncId) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSyncs.find(syncId);
        if (it != m_activeSyncs.end()) {
            it->second->cancelFlag.store(true, std::memory_order_release);
            {
                std::lock_guard stateLock(it->second->stateMutex);
                it->second->progress.status = SyncStatus::Cancelled;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Cancelling sync %hs", syncId.c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] bool PauseSync(const std::string& syncId) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSyncs.find(syncId);
        if (it != m_activeSyncs.end()) {
            it->second->pauseFlag.store(true, std::memory_order_release);
            {
                std::lock_guard stateLock(it->second->stateMutex);
                it->second->progress.status = SyncStatus::Pending;
                it->second->progress.phase = "Paused";
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Paused sync %hs", syncId.c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] bool ResumeSync(const std::string& syncId) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSyncs.find(syncId);
        if (it != m_activeSyncs.end()) {
            it->second->pauseFlag.store(false, std::memory_order_release);
            it->second->pauseCv.notify_one();
            SS_LOG_INFO(LOG_CATEGORY, L"Resumed sync %hs", syncId.c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] std::optional<SyncProgress> GetProgress(const std::string& syncId) noexcept {
        std::shared_ptr<SyncContext> ctx;
        {
            std::shared_lock lock(m_mutex);
            auto it = m_activeSyncs.find(syncId);
            if (it != m_activeSyncs.end()) {
                ctx = it->second;
            }
        }
        if (ctx) {
            std::lock_guard stateLock(ctx->stateMutex);
            return ctx->progress;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SyncResult> GetResult(const std::string& syncId) noexcept {
        std::shared_ptr<SyncContext> active;
        {
            std::shared_lock lock(m_mutex);
            auto ait = m_activeSyncs.find(syncId);
            if (ait != m_activeSyncs.end()) {
                active = ait->second;
            } else {
                auto cit = m_completedSyncs.find(syncId);
                if (cit != m_completedSyncs.end()) {
                    return cit->second;
                }
            }
        }

        // Check active syncs first (might still be running or just completed)
        if (active) {
            std::lock_guard stateLock(active->stateMutex);
            if (active->progress.status == SyncStatus::Completed ||
                active->progress.status == SyncStatus::Failed ||
                active->progress.status == SyncStatus::Cancelled) {
                return active->result;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    // ========================================================================
    // CHANGE DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<FileChangeRecord> ScanForChanges(
        const fs::path& source,
        const fs::path& baselinePath
    ) noexcept {
        std::vector<FileChangeRecord> changes;
        try {
            std::error_code ec;
            if (!fs::exists(source, ec) || ec) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ScanForChanges: source path does not exist: %ls",
                    source.c_str());
                return changes;
            }

            // Build a map of baseline files (path → size + time)
            std::unordered_map<std::string, std::pair<uint64_t, fs::file_time_type>> baseline;
            if (!baselinePath.empty() && fs::is_directory(baselinePath, ec) && !ec) {
                for (const auto& entry : fs::recursive_directory_iterator(
                         baselinePath, fs::directory_options::skip_permission_denied, ec)) {
                    if (ec) { ec.clear(); continue; }
                    if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }
                    auto rel = fs::relative(entry.path(), baselinePath, ec);
                    if (ec) { ec.clear(); continue; }
                    baseline[rel.string()] = {
                        entry.file_size(ec),
                        entry.last_write_time(ec)
                    };
                }
            }

            // Scan current source
            for (const auto& entry : fs::recursive_directory_iterator(
                     source, fs::directory_options::skip_permission_denied, ec)) {
                if (ec) { ec.clear(); continue; }
                if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }

                // Reject symlinks to prevent traversal attacks
                if (entry.is_symlink(ec)) { ec.clear(); continue; }

                auto relPath = fs::relative(entry.path(), source, ec);
                if (ec) { ec.clear(); continue; }

                FileChangeRecord record;
                record.path = entry.path();
                record.size = entry.file_size(ec);
                if (ec) { ec.clear(); record.size = 0; }

                auto it = baseline.find(relPath.string());
                if (it == baseline.end()) {
                    record.changeType = ChangeType::Added;
                    record.bytesChanged = record.size;
                } else {
                    auto baseTime = it->second.second;
                    auto curTime = entry.last_write_time(ec);
                    if (ec) { ec.clear(); }
                    if (record.size != it->second.first || curTime != baseTime) {
                        record.changeType = ChangeType::Modified;
                        record.previousSize = it->second.first;
                        record.bytesChanged = record.size;
                    } else {
                        continue; // Unchanged
                    }
                    baseline.erase(it);
                }
                changes.push_back(std::move(record));
            }

            // Remaining baseline entries are deleted files
            for (const auto& [relStr, info] : baseline) {
                FileChangeRecord record;
                record.path = baselinePath / relStr;
                record.changeType = ChangeType::Deleted;
                record.previousSize = info.first;
                changes.push_back(std::move(record));
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanForChanges exception: %hs", ex.what());
        }
        return changes;
    }

    [[nodiscard]] std::vector<FileChangeRecord> GetUSNChanges(
        const std::wstring& volumePath,
        uint64_t fromUSN
    ) noexcept {
        std::vector<FileChangeRecord> changes;
#ifdef _WIN32
        try {
            if (!IsValidDosVolumePath(volumePath)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"GetUSNChanges: invalid DOS volume path: %ls",
                    volumePath.c_str());
                return changes;
            }
            std::wstring devPath = NormalizeVolumePath(volumePath);
            HANDLE hVolume = CreateFileW(
                devPath.c_str(),
                FILE_READ_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);

            if (hVolume == INVALID_HANDLE_VALUE) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"GetUSNChanges: cannot open volume %ls (error %u)",
                    devPath.c_str(), GetLastError());
                return changes;
            }

            // RAII guard for the volume handle
            struct HandleGuard {
                HANDLE h;
                ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
            } guard{hVolume};

            // Query journal metadata
            USN_JOURNAL_DATA_V0 journalData{};
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL,
                    nullptr, 0, &journalData, sizeof(journalData),
                    &bytesReturned, nullptr)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"GetUSNChanges: FSCTL_QUERY_USN_JOURNAL failed (error %u)",
                    GetLastError());
                return changes;
            }

            // Read USN records since fromUSN
            READ_USN_JOURNAL_DATA_V0 readData{};
            readData.StartUsn = static_cast<USN>(fromUSN);
            readData.ReasonMask = USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
                                  USN_REASON_DATA_TRUNCATION | USN_REASON_FILE_CREATE |
                                  USN_REASON_FILE_DELETE | USN_REASON_RENAME_NEW_NAME;
            readData.UsnJournalID = journalData.UsnJournalID;

            constexpr DWORD BUF_SIZE = 64 * 1024;
            std::vector<uint8_t> buffer(BUF_SIZE);

            while (true) {
                if (!DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL,
                        &readData, sizeof(readData),
                        buffer.data(), BUF_SIZE,
                        &bytesReturned, nullptr)) {
                    break;
                }
                if (bytesReturned <= sizeof(USN)) break;

                auto* recordPtr = reinterpret_cast<USN_RECORD_V2*>(
                    buffer.data() + sizeof(USN));
                DWORD remaining = bytesReturned - sizeof(USN);

                while (remaining > 0 && recordPtr->RecordLength > 0 &&
                       recordPtr->RecordLength <= remaining) {
                    const DWORD fileNameEnd =
                        static_cast<DWORD>(recordPtr->FileNameOffset) +
                        static_cast<DWORD>(recordPtr->FileNameLength);
                    if (recordPtr->FileNameOffset < sizeof(USN_RECORD_V2) ||
                        fileNameEnd > recordPtr->RecordLength ||
                        (recordPtr->FileNameLength % sizeof(wchar_t)) != 0) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"GetUSNChanges: malformed USN record skipped");
                        break;
                    }

                    FileChangeRecord rec;
                    std::wstring fname(
                        reinterpret_cast<const wchar_t*>(
                            reinterpret_cast<const uint8_t*>(recordPtr) +
                            recordPtr->FileNameOffset),
                        recordPtr->FileNameLength / sizeof(wchar_t));
                    rec.path = fname;

                    if (recordPtr->Reason & USN_REASON_FILE_CREATE)
                        rec.changeType = ChangeType::Added;
                    else if (recordPtr->Reason & USN_REASON_FILE_DELETE)
                        rec.changeType = ChangeType::Deleted;
                    else if (recordPtr->Reason & USN_REASON_RENAME_NEW_NAME)
                        rec.changeType = ChangeType::Renamed;
                    else
                        rec.changeType = ChangeType::Modified;

                    changes.push_back(std::move(rec));

                    remaining -= recordPtr->RecordLength;
                    recordPtr = reinterpret_cast<USN_RECORD_V2*>(
                        reinterpret_cast<uint8_t*>(recordPtr) +
                        recordPtr->RecordLength);
                }

                // Advance the start USN for next iteration
                readData.StartUsn = *reinterpret_cast<USN*>(buffer.data());
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetUSNChanges exception: %hs", ex.what());
        }
#else
        SS_LOG_WARN(LOG_CATEGORY, L"GetUSNChanges: not supported on this platform");
#endif
        return changes;
    }

    [[nodiscard]] FileChangeRecord CompareFiles(
        const fs::path& oldFile,
        const fs::path& newFile
    ) noexcept {
        FileChangeRecord record;
        record.path = newFile;

        try {
            std::error_code ec;
            bool oldExists = fs::exists(oldFile, ec);
            if (ec) { ec.clear(); oldExists = false; }
            bool newExists = fs::exists(newFile, ec);
            if (ec) { ec.clear(); newExists = false; }

            if (!oldExists && newExists) {
                record.changeType = ChangeType::Added;
                record.size = fs::file_size(newFile, ec);
                record.bytesChanged = record.size;
                return record;
            }
            if (oldExists && !newExists) {
                record.changeType = ChangeType::Deleted;
                record.previousSize = fs::file_size(oldFile, ec);
                return record;
            }
            if (!oldExists && !newExists) {
                record.changeType = ChangeType::None;
                return record;
            }

            record.size = fs::file_size(newFile, ec);
            record.previousSize = fs::file_size(oldFile, ec);

            if (record.size != record.previousSize) {
                record.changeType = ChangeType::Modified;
                record.bytesChanged = record.size;
                return record;
            }

            // Same size: compare content hashes
            auto hashFile = [](const fs::path& p) -> std::string {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                if (!hasher.Init()) return "";
                std::ifstream ifs(p, std::ios::binary);
                if (!ifs) return "";
                constexpr size_t BUF = 1024 * 1024;
                std::vector<uint8_t> buf(BUF);
                while (ifs) {
                    ifs.read(reinterpret_cast<char*>(buf.data()),
                             static_cast<std::streamsize>(BUF));
                    auto n = static_cast<size_t>(ifs.gcount());
                    if (n > 0 && !hasher.Update(buf.data(), n)) return "";
                }
                std::string hex;
                if (!hasher.FinalHex(hex)) return "";
                return hex;
            };

            record.contentHash = hashFile(newFile);
            record.previousContentHash = hashFile(oldFile);

            if (record.contentHash.empty() || record.previousContentHash.empty() ||
                record.contentHash != record.previousContentHash) {
                record.changeType = ChangeType::Modified;
                record.bytesChanged = record.size;
            } else {
                record.changeType = ChangeType::None;
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CompareFiles exception: %hs", ex.what());
            record.changeType = ChangeType::Modified;
        }
        return record;
    }

    // ========================================================================
    // CHUNKING
    // ========================================================================

    [[nodiscard]] std::vector<ChunkDescriptor> ChunkData(
        std::span<const uint8_t> data,
        const ChunkingOptions& options
    ) noexcept {
        std::vector<ChunkDescriptor> chunks;

        try {
            if (!options.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ChunkData rejected invalid chunking options");
                return chunks;
            }
            std::vector<size_t> boundaries;

            if (options.algorithm == ChunkingAlgorithm::Fixed) {
                size_t offset = 0;
                while (offset < data.size()) {
                    const size_t remaining = data.size() - offset;
                    size_t next = offset + std::min(options.avgChunkSize, remaining);
                    boundaries.push_back(next);
                    offset = next;
                }
            } else {
                boundaries = FindChunkBoundaries(data, options);
            }

            chunks.reserve(boundaries.size());
            size_t offset = 0;

            for (size_t boundary : boundaries) {
                if (boundary <= offset) continue;

                size_t size = boundary - offset;
                auto chunkSpan = data.subspan(offset, size);

                ChunkDescriptor chunk;
                chunk.offset = offset;
                chunk.originalSize = static_cast<uint32_t>(
                    std::min(size, static_cast<size_t>(UINT32_MAX)));
                chunk.hash = computeChunkHash(chunkSpan, options.hashAlgorithm);

                chunks.push_back(chunk);
                offset = boundary;
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ChunkData exception: %hs", ex.what());
        }

        return chunks;
    }

    // ========================================================================
    // DEDUPLICATION
    // ========================================================================

    [[nodiscard]] bool AddChunkToIndex(const ChunkDescriptor& chunk) noexcept {
        std::unique_lock lock(m_dedupMutex);

        if (m_dedupIndex.size() >= MAX_DEDUP_INDEX_ENTRIES) {
            SS_LOG_WARN(LOG_CATEGORY, L"Dedup index at capacity (%zu entries)", MAX_DEDUP_INDEX_ENTRIES);
            return false;
        }

        DedupIndexEntry entry;
        entry.hash = chunk.hash;
        entry.storageOffset = chunk.storageOffset;
        entry.size = chunk.originalSize;
        entry.refCount = 1;
        entry.lastAccessed = std::chrono::system_clock::now();

        // try_emplace does NOT overwrite existing entries, preserving accumulated refCounts.
        auto [it, inserted] = m_dedupIndex.try_emplace(chunk.hash, entry);
        if (!inserted) {
            it->second.refCount++;
            it->second.lastAccessed = std::chrono::system_clock::now();
        } else {
            m_stats.uniqueChunks.fetch_add(1, std::memory_order_relaxed);
        }

        return true;
    }

    [[nodiscard]] bool ChunkExists(const std::array<uint8_t, 32>& hash) noexcept {
        std::shared_lock lock(m_dedupMutex);
        return m_dedupIndex.count(hash) > 0;
    }

    [[nodiscard]] std::optional<DedupIndexEntry> GetChunkFromIndex(
        const std::array<uint8_t, 32>& hash
    ) noexcept {
        std::shared_lock lock(m_dedupMutex);
        auto it = m_dedupIndex.find(hash);
        if (it != m_dedupIndex.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] double GetDedupRatio() const noexcept {
        uint64_t total = m_stats.totalBytesProcessed.load(std::memory_order_relaxed);
        uint64_t saved = m_stats.bytesSavedByDedup.load(std::memory_order_relaxed);
        if (total == 0) return 1.0;
        if (saved >= total) return static_cast<double>(total);
        return static_cast<double>(total) / static_cast<double>(total - saved);
    }

    [[nodiscard]] bool CompactIndex() noexcept {
        std::unique_lock lock(m_dedupMutex);
        SS_LOG_INFO(LOG_CATEGORY, L"Compacting dedup index (%zu entries)", m_dedupIndex.size());

        size_t removed = 0;
        for (auto it = m_dedupIndex.begin(); it != m_dedupIndex.end(); ) {
            if (it->second.refCount == 0) {
                it = m_dedupIndex.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Compact complete: removed %zu unreferenced entries", removed);
        return true;
    }

    // ========================================================================
    // COMPRESSION
    // ========================================================================

    [[nodiscard]] std::vector<uint8_t> CompressChunk(
        std::span<const uint8_t> data,
        CompressionAlgorithm algorithm
    ) noexcept {
        if (algorithm == CompressionAlgorithm::None || data.empty()) {
            return {data.begin(), data.end()};
        }

        auto winAlg = MapToWindowsCompression(algorithm);
        std::vector<uint8_t> compressed;

        if (Utils::CompressionUtils::CompressBuffer(
                winAlg, data.data(), data.size(), compressed)) {
            // Only use compressed form if it's actually smaller
            if (compressed.size() < data.size()) {
                return compressed;
            }
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Compression failed for %zu byte chunk, storing uncompressed",
                data.size());
        }

        return {data.begin(), data.end()};
    }

    [[nodiscard]] std::vector<uint8_t> DecompressChunk(
        std::span<const uint8_t> data,
        CompressionAlgorithm algorithm,
        size_t originalSize
    ) noexcept {
        if (algorithm == CompressionAlgorithm::None || data.empty()) {
            return {data.begin(), data.end()};
        }

        auto winAlg = MapToWindowsCompression(algorithm);
        std::vector<uint8_t> decompressed;

        if (Utils::CompressionUtils::DecompressBuffer(
                winAlg, data.data(), data.size(), decompressed, originalSize)) {
            return decompressed;
        }

        SS_LOG_ERROR(LOG_CATEGORY,
            L"Decompression failed: %zu bytes compressed, expected %zu original",
            data.size(), originalSize);
        return {};
    }

    // ========================================================================
    // HASHING
    // ========================================================================

    [[nodiscard]] std::array<uint8_t, 32> computeChunkHash(
        std::span<const uint8_t> data,
        ChunkHashAlgorithm algorithm
    ) noexcept {
        (void)algorithm;
        std::array<uint8_t, 32> hash{};

        // Use SHA-256 via the existing BCrypt-backed Hasher for all chunk hash
        // algorithms. SHA-256 produces a 32-byte digest that maps directly to
        // our hash array. Future work can integrate xxHash/BLAKE3 native libs.
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
        if (!hasher.Init()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"computeChunkHash: Hasher::Init failed");
            return hash;
        }
        if (!hasher.Update(data.data(), data.size())) {
            SS_LOG_ERROR(LOG_CATEGORY, L"computeChunkHash: Hasher::Update failed");
            return hash;
        }

        std::vector<uint8_t> digest;
        if (!hasher.Final(digest)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"computeChunkHash: Hasher::Final failed");
            return hash;
        }

        size_t copyLen = std::min(digest.size(), hash.size());
        std::memcpy(hash.data(), digest.data(), copyLen);
        return hash;
    }

    // ========================================================================
    // CHUNK BOUNDARY DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<size_t> FindChunkBoundaries(
        std::span<const uint8_t> data,
        const ChunkingOptions& options
    ) noexcept {
        std::vector<size_t> boundaries;

        if (data.empty()) return boundaries;
        if (data.size() <= options.minChunkSize) {
            boundaries.push_back(data.size());
            return boundaries;
        }

        size_t pos = 0;
        while (pos < data.size()) {
            size_t remaining = data.size() - pos;
            if (remaining <= options.minChunkSize) {
                boundaries.push_back(data.size());
                break;
            }

            size_t searchStart = pos + options.minChunkSize;
            size_t searchEnd = std::min(pos + options.maxChunkSize, data.size());

            // Normalised FastCDC: two masks for better average chunk size targeting
            uint64_t fingerprint = 0;
            size_t cutPoint = searchEnd;
            size_t midpoint = pos + options.avgChunkSize;

            uint64_t maskS = (1ULL << 15) - 1;  // strict mask (smaller chunks)
            uint64_t maskL = (1ULL << 13) - 1;  // lenient mask (larger chunks)
            if (options.avgChunkSize >= 65536) {
                maskS = (1ULL << 16) - 1;
                maskL = (1ULL << 14) - 1;
            }

            bool found = false;
            for (size_t i = searchStart; i < searchEnd; ++i) {
                fingerprint = (fingerprint << 1) + GEAR_MATRIX[data[i]];
                uint64_t mask = (i < midpoint) ? maskS : maskL;
                if ((fingerprint & mask) == 0) {
                    cutPoint = i + 1;
                    found = true;
                    break;
                }
            }

            boundaries.push_back(cutPoint);
            pos = cutPoint;
        }

        return boundaries;
    }

    // ========================================================================
    // SETTER METHODS
    // ========================================================================

    void SetChunkingAlgorithm(ChunkingAlgorithm algorithm) noexcept {
        std::unique_lock lock(m_mutex);
        m_config.chunkingOptions.algorithm = algorithm;
    }

    void SetCompressionAlgorithm(CompressionAlgorithm algorithm) noexcept {
        std::unique_lock lock(m_mutex);
        m_config.compression = algorithm;
    }

    void SetCompressionLevel(int level) noexcept {
        std::unique_lock lock(m_mutex);
        m_config.compressionLevel = std::clamp(level, 0, 9);
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    void RegisterProgressCallback(ProgressCallback cb) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_progressCallback = std::move(cb);
    }

    void RegisterCompletionCallback(CompletionCallback cb) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_completionCallback = std::move(cb);
    }

    void RegisterChunkCallback(ChunkCallback cb) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_chunkCallback = std::move(cb);
    }

    void RegisterChangeCallback(ChangeCallback cb) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_changeCallback = std::move(cb);
    }

    void RegisterErrorCallback(ErrorCallback cb) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_errorCallback = std::move(cb);
    }

    void UnregisterCallbacks() noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_progressCallback = nullptr;
        m_completionCallback = nullptr;
        m_chunkCallback = nullptr;
        m_changeCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] IncrementalStatistics GetStatistics() const noexcept {
        return m_stats;  // Uses the copy constructor we added to IncrementalStatistics
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // SYNC CONTEXT
    // ========================================================================

    struct SyncContext {
        std::string syncId;
        fs::path sourcePath;
        fs::path vaultPath;
        ChunkingOptions chunkingOptions;
        TimePoint startTime;
        std::atomic<bool> cancelFlag{false};
        std::atomic<bool> pauseFlag{false};
        std::mutex pauseMutex;
        std::condition_variable pauseCv;
        std::mutex stateMutex;
        SyncProgress progress;
        SyncResult result;
        std::thread worker;
    };

    // ========================================================================
    // SYNC EXECUTION
    // ========================================================================

    void runSync(std::shared_ptr<SyncContext> ctx) noexcept {
        {
            std::lock_guard stateLock(ctx->stateMutex);
            ctx->progress.status = SyncStatus::Scanning;
        }
        notifyProgress(ctx);

        try {
            // Ensure vault chunk directory exists
            std::error_code ec;
            fs::path chunkDir = ctx->vaultPath / "chunks";
            fs::create_directories(chunkDir, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot create vault chunk dir: %ls (%hs)",
                    chunkDir.c_str(), ec.message().c_str());
                {
                    std::lock_guard stateLock(ctx->stateMutex);
                    ctx->progress.status = SyncStatus::Failed;
                    ctx->result.status = SyncStatus::Failed;
                    ctx->result.errors.push_back("Cannot create vault directory: " + ec.message());
                }
                m_stats.failedSyncs.fetch_add(1, std::memory_order_relaxed);
                finishSync(ctx);
                return;
            }

            // 1. Scan files (skip symlinks and permission-denied entries)
            std::vector<fs::path> files;
            for (const auto& entry : fs::recursive_directory_iterator(
                     ctx->sourcePath,
                     fs::directory_options::skip_permission_denied, ec)) {
                if (ctx->cancelFlag.load(std::memory_order_acquire)) break;
                if (ec) { ec.clear(); continue; }
                if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }
                if (entry.is_symlink(ec)) { ec.clear(); continue; }
                if (files.size() >= MAX_SYNC_FILE_ENUMERATION) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Sync file enumeration limit reached (%zu)",
                        MAX_SYNC_FILE_ENUMERATION);
                    break;
                }
                files.push_back(entry.path());
            }

            {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->progress.totalFiles = files.size();
                ctx->progress.phase = "Processing files";
            }

            // 2. Process each file
            for (const auto& file : files) {
                if (ctx->cancelFlag.load(std::memory_order_acquire)) break;

                // Pause support
                waitIfPaused(ctx);
                if (ctx->cancelFlag.load(std::memory_order_acquire)) break;

                {
                    std::lock_guard stateLock(ctx->stateMutex);
                    ctx->progress.currentFile = file;
                    ctx->progress.status = SyncStatus::Chunking;
                }
                notifyProgress(ctx);

                processFile(file, ctx);

                {
                    std::lock_guard stateLock(ctx->stateMutex);
                    ctx->progress.filesProcessed++;
                    if (ctx->progress.totalFiles > 0) {
                        ctx->progress.percentComplete = static_cast<int>(
                            (ctx->progress.filesProcessed * 100) / ctx->progress.totalFiles);
                    }
                }
            }

            if (ctx->cancelFlag.load(std::memory_order_acquire)) {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->progress.status = SyncStatus::Cancelled;
                ctx->result.status = SyncStatus::Cancelled;
            } else {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->progress.status = SyncStatus::Completed;
                ctx->result.status = SyncStatus::Completed;
                m_stats.successfulSyncs.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Sync %hs failed: %hs",
                ctx->syncId.c_str(), ex.what());
            {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->progress.status = SyncStatus::Failed;
                ctx->result.status = SyncStatus::Failed;
                ctx->result.errors.push_back(ex.what());
            }
            m_stats.failedSyncs.fetch_add(1, std::memory_order_relaxed);
        }

        m_stats.totalSyncs.fetch_add(1, std::memory_order_relaxed);
        finishSync(ctx);
    }

    void finishSync(std::shared_ptr<SyncContext> ctx) noexcept {
        SyncResult resultSnapshot;
        {
            std::lock_guard stateLock(ctx->stateMutex);
            ctx->result.endTime = std::chrono::system_clock::now();
            auto elapsed = Clock::now() - ctx->startTime;
            ctx->result.duration = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
            ctx->result.syncId = ctx->syncId;

            // Compute dedup and compression ratios
            if (ctx->result.bytesScanned > 0) {
                const uint64_t globalSaved =
                    m_stats.bytesSavedByDedup.load(std::memory_order_relaxed);
                const uint64_t afterDedup = (globalSaved >= ctx->result.bytesScanned)
                    ? 0
                    : (ctx->result.bytesScanned - globalSaved);
                ctx->result.bytesAfterDedup = afterDedup;
                ctx->result.dedupRatio = static_cast<double>(ctx->result.bytesScanned) /
                    static_cast<double>(std::max(afterDedup, uint64_t{1}));
                if (ctx->result.bytesStored > 0) {
                    ctx->result.compressionRatio = static_cast<double>(afterDedup) /
                        static_cast<double>(ctx->result.bytesStored);
                }
            }
            resultSnapshot = ctx->result;
        }

        notifyProgress(ctx);

        // Notify completion callback
        {
            std::shared_lock lock(m_callbackMutex);
            if (m_completionCallback) {
                try {
                    m_completionCallback(resultSnapshot);
                } catch (const std::exception& ex) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Completion callback threw: %hs", ex.what());
                } catch (...) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Completion callback threw unknown exception");
                }
            }
        }

        // Move result to completed history, then detach and erase the finished
        // worker from activeSyncs so its std::thread handle is reclaimed.
        // This thread is about to return; all member accesses above are done.
        {
            std::unique_lock lock(m_mutex);
            m_completedSyncs[ctx->syncId] = resultSnapshot;
            if (m_completedSyncs.size() > MAX_COMPLETED_RESULTS) {
                m_completedSyncs.erase(m_completedSyncs.begin());
            }

            // The worker thread (us) is about to exit.  Detach so the
            // std::thread destructor won't call std::terminate, then remove
            // the entry from m_activeSyncs to reclaim memory.
            auto it = m_activeSyncs.find(ctx->syncId);
            if (it != m_activeSyncs.end()) {
                if (it->second->worker.joinable()) {
                    it->second->worker.detach();
                }
                m_activeSyncs.erase(it);
            }
        }
    }

    void processFile(const fs::path& file, std::shared_ptr<SyncContext> ctx) noexcept {
        try {
            std::ifstream ifs(file, std::ios::binary);
            if (!ifs) {
                SS_LOG_WARN(LOG_CATEGORY, L"Cannot open file for backup: %ls", file.c_str());
                notifyError("Cannot open file: " + file.string(), -1);
                return;
            }

            ifs.seekg(0, std::ios::end);
            auto pos = ifs.tellg();
            if (pos == static_cast<std::streampos>(-1) || pos < 0) {
                SS_LOG_WARN(LOG_CATEGORY, L"Cannot determine file size: %ls", file.c_str());
                return;
            }
            auto fileSize = static_cast<size_t>(pos);
            ifs.seekg(0, std::ios::beg);

            if (fileSize == 0) return;

            if (fileSize > MAX_SINGLE_FILE_SIZE) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"File exceeds single-pass limit (%zu > %zu bytes), skipping: %ls",
                    fileSize, MAX_SINGLE_FILE_SIZE, file.c_str());
                notifyError("File too large for single-pass backup: " + file.string(), -2);
                return;
            }

            std::vector<uint8_t> buffer;
            try {
                buffer.resize(fileSize);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Memory allocation failed for %zu bytes: %ls", fileSize, file.c_str());
                return;
            }

            ifs.read(reinterpret_cast<char*>(buffer.data()),
                     static_cast<std::streamsize>(fileSize));
            size_t bytesRead = static_cast<size_t>(ifs.gcount());
            if (bytesRead == 0) return;
            if (bytesRead != fileSize) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Short read while processing %ls: expected %zu bytes, read %zu",
                    file.c_str(), fileSize, bytesRead);
                notifyError("Short read while processing file: " + file.string(), -3);
                return;
            }

            {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->result.bytesScanned = SaturatingAddU64(
                    ctx->result.bytesScanned, static_cast<uint64_t>(bytesRead));
                ctx->result.filesScanned = SaturatingAddU64(ctx->result.filesScanned, 1);
            }
            m_stats.totalBytesProcessed.fetch_add(bytesRead, std::memory_order_relaxed);

            auto chunks = ChunkData(
                std::span<const uint8_t>(buffer.data(), bytesRead),
                ctx->chunkingOptions);
            {
                std::lock_guard stateLock(ctx->stateMutex);
                ctx->result.chunksCreated = SaturatingAddU64(
                    ctx->result.chunksCreated, static_cast<uint64_t>(chunks.size()));
            }
            m_stats.totalChunksCreated.fetch_add(chunks.size(), std::memory_order_relaxed);

            // Read configured compression algorithm
            CompressionAlgorithm compAlg;
            {
                std::shared_lock lock(m_mutex);
                compAlg = m_config.compression;
            }

            for (auto& chunk : chunks) {
                if (ctx->cancelFlag.load(std::memory_order_acquire)) break;

                if (ChunkExists(chunk.hash)) {
                    chunk.isDeduplicated = true;
                    {
                        std::lock_guard stateLock(ctx->stateMutex);
                        ctx->result.chunksDeduplicated =
                            SaturatingAddU64(ctx->result.chunksDeduplicated, 1);
                    }
                    m_stats.totalChunksDeduplicated.fetch_add(1, std::memory_order_relaxed);
                    m_stats.bytesSavedByDedup.fetch_add(chunk.originalSize, std::memory_order_relaxed);
                    m_stats.duplicateChunks.fetch_add(1, std::memory_order_relaxed);

                    // Increment reference count on existing chunk
                    {
                        std::unique_lock dlock(m_dedupMutex);
                        auto dit = m_dedupIndex.find(chunk.hash);
                        if (dit != m_dedupIndex.end()) {
                            dit->second.refCount++;
                        }
                    }
                } else {
                    // Compress and store the chunk
                    auto chunkSpan = std::span<const uint8_t>(
                        buffer.data() + chunk.offset, chunk.originalSize);

                    auto compressed = CompressChunk(chunkSpan, compAlg);

                    chunk.compressedSize = static_cast<uint32_t>(
                        std::min(compressed.size(), static_cast<size_t>(UINT32_MAX)));
                    chunk.compression = compAlg;

                    // Write chunk to vault before advertising it in the dedup index.
                    if (!writeChunkToVault(chunk, compressed, ctx->vaultPath)) {
                        notifyError("Failed to persist backup chunk for file: " + file.string(), -4);
                        continue;
                    }

                    if (!AddChunkToIndex(chunk)) {
                        notifyError("Failed to index backup chunk for file: " + file.string(), -5);
                        continue;
                    }

                    {
                        std::lock_guard stateLock(ctx->stateMutex);
                        ctx->result.bytesStored = SaturatingAddU64(
                            ctx->result.bytesStored, chunk.compressedSize);
                    }
                    m_stats.totalBytesStored.fetch_add(chunk.compressedSize, std::memory_order_relaxed);

                    if (chunk.originalSize > chunk.compressedSize) {
                        m_stats.bytesSavedByCompression.fetch_add(
                            chunk.originalSize - chunk.compressedSize,
                            std::memory_order_relaxed);
                    }

                    auto algIdx = static_cast<size_t>(compAlg);
                    if (algIdx < m_stats.byCompression.size()) {
                        m_stats.byCompression[algIdx].fetch_add(
                            chunk.compressedSize, std::memory_order_relaxed);
                    }

                    // Notify chunk callback
                    {
                        std::shared_lock lock(m_callbackMutex);
                        if (m_chunkCallback) {
                            try {
                                m_chunkCallback(chunk);
                            } catch (const std::exception& ex) {
                                SS_LOG_WARN(LOG_CATEGORY,
                                    L"Chunk callback threw: %hs", ex.what());
                            } catch (...) {
                                SS_LOG_WARN(LOG_CATEGORY,
                                    L"Chunk callback threw unknown exception");
                            }
                        }
                    }
                }
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Error processing file %ls: %hs",
                file.c_str(), ex.what());
            notifyError("Error processing " + file.string() + ": " + ex.what(), -1);
        }
    }

    // ========================================================================
    // VAULT I/O
    // ========================================================================

    [[nodiscard]] bool writeChunkToVault(
        const ChunkDescriptor& chunk,
        const std::vector<uint8_t>& data,
        const fs::path& vaultPath
    ) noexcept {
        try {
            std::string hashHex = chunk.GetHashHex();
            // Two-level directory structure to avoid filesystem hotspots
            fs::path subdir = vaultPath / "chunks" / hashHex.substr(0, 2);
            std::error_code ec;
            fs::create_directories(subdir, ec);
            if (ec) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot create chunk subdir: %hs", ec.message().c_str());
                return false;
            }

            fs::path chunkPath = subdir / hashHex;
            if (fs::exists(chunkPath, ec)) return true;  // Content-addressable: already stored

            std::ofstream ofs(chunkPath, std::ios::binary);
            if (!ofs) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot create chunk file: %ls", chunkPath.c_str());
                return false;
            }
            ofs.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
            ofs.flush();
            if (!ofs) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to write complete chunk file: %ls",
                    chunkPath.c_str());
                return false;
            }
            return true;
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"writeChunkToVault exception: %hs", ex.what());
            return false;
        }
    }

    // ========================================================================
    // DEDUP INDEX PERSISTENCE
    // ========================================================================

    void loadDedupIndex() noexcept {
        try {
            std::ifstream ifs(m_config.dedupIndexPath, std::ios::binary);
            if (!ifs) {
                SS_LOG_INFO(LOG_CATEGORY, L"No existing dedup index at %ls, starting fresh",
                    m_config.dedupIndexPath.c_str());
                return;
            }

            uint32_t magic = 0, version = 0, count = 0;
            ifs.read(reinterpret_cast<char*>(&magic), sizeof(magic));
            ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
            ifs.read(reinterpret_cast<char*>(&count), sizeof(count));
            if (!ifs) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Dedup index header is truncated: %ls",
                    m_config.dedupIndexPath.c_str());
                return;
            }

            if (magic != DEDUP_INDEX_MAGIC || version != DEDUP_INDEX_VERSION) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Dedup index magic/version mismatch (magic=0x%08X ver=%u), ignoring",
                    magic, version);
                return;
            }

            if (count > MAX_DEDUP_INDEX_ENTRIES) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Dedup index claims %u entries (cap %zu), truncating",
                    count, MAX_DEDUP_INDEX_ENTRIES);
                count = static_cast<uint32_t>(MAX_DEDUP_INDEX_ENTRIES);
            }

            m_dedupIndex.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                DedupIndexEntry entry;
                ifs.read(reinterpret_cast<char*>(entry.hash.data()), entry.hash.size());
                ifs.read(reinterpret_cast<char*>(&entry.storageOffset), sizeof(entry.storageOffset));
                ifs.read(reinterpret_cast<char*>(&entry.size), sizeof(entry.size));
                ifs.read(reinterpret_cast<char*>(&entry.refCount), sizeof(entry.refCount));
                if (!ifs) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Dedup index truncated at entry %u/%u", i, count);
                    break;
                }
                m_dedupIndex[entry.hash] = entry;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu dedup index entries from %ls",
                m_dedupIndex.size(), m_config.dedupIndexPath.c_str());

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"loadDedupIndex failed: %hs", ex.what());
        }
    }

    void saveDedupIndex() noexcept {
        try {
            std::ofstream ofs(m_config.dedupIndexPath, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot write dedup index to %ls",
                    m_config.dedupIndexPath.c_str());
                return;
            }

            uint32_t magic = DEDUP_INDEX_MAGIC;
            uint32_t version = DEDUP_INDEX_VERSION;
            auto count = static_cast<uint32_t>(
                std::min(m_dedupIndex.size(), static_cast<size_t>(UINT32_MAX)));

            ofs.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
            ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
            ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));

            for (const auto& [hash, entry] : m_dedupIndex) {
                ofs.write(reinterpret_cast<const char*>(entry.hash.data()), entry.hash.size());
                ofs.write(reinterpret_cast<const char*>(&entry.storageOffset), sizeof(entry.storageOffset));
                ofs.write(reinterpret_cast<const char*>(&entry.size), sizeof(entry.size));
                ofs.write(reinterpret_cast<const char*>(&entry.refCount), sizeof(entry.refCount));
                if (!ofs) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Failed while writing dedup index entry to %ls",
                        m_config.dedupIndexPath.c_str());
                    return;
                }
            }
            ofs.flush();
            if (!ofs) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to flush dedup index to %ls",
                    m_config.dedupIndexPath.c_str());
                return;
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Saved %u dedup index entries to %ls",
                count, m_config.dedupIndexPath.c_str());

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"saveDedupIndex failed: %hs", ex.what());
        }
    }

    // ========================================================================
    // NOTIFICATION HELPERS
    // ========================================================================

    void notifyProgress(std::shared_ptr<SyncContext> ctx) noexcept {
        SyncProgress snapshot;
        {
            std::lock_guard stateLock(ctx->stateMutex);
            snapshot = ctx->progress;
        }
        std::shared_lock lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(snapshot); }
            catch (const std::exception& ex) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Progress callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Progress callback threw unknown exception");
            }
        }
    }

    void notifyError(const std::string& msg, int code) noexcept {
        std::shared_lock lock(m_callbackMutex);
        if (m_errorCallback) {
            try { m_errorCallback(msg, code); }
            catch (const std::exception& ex) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Error callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Error callback threw unknown exception");
            }
        }
    }

    void waitIfPaused(std::shared_ptr<SyncContext> ctx) noexcept {
        if (ctx->pauseFlag.load(std::memory_order_acquire)) {
            std::unique_lock lock(ctx->pauseMutex);
            ctx->pauseCv.wait(lock, [&ctx]() {
                return !ctx->pauseFlag.load(std::memory_order_acquire) ||
                        ctx->cancelFlag.load(std::memory_order_acquire);
            });
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_dedupMutex;
    mutable std::shared_mutex m_callbackMutex;

    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;

    IncrementalConfiguration m_config;
    IncrementalStatistics m_stats;

    std::unordered_map<std::string, std::shared_ptr<SyncContext>> m_activeSyncs;
    std::unordered_map<std::string, SyncResult> m_completedSyncs;

    std::unordered_map<std::array<uint8_t, 32>, DedupIndexEntry, ArrayHash> m_dedupIndex;
    std::unordered_map<std::array<uint8_t, 32>, std::vector<uint8_t>, ArrayHash> m_chunkCache;

    ProgressCallback m_progressCallback;
    CompletionCallback m_completionCallback;
    ChunkCallback m_chunkCallback;
    ChangeCallback m_changeCallback;
    ErrorCallback m_errorCallback;
};

// ============================================================================
// PUBLIC FACADE IMPLEMENTATION
// ============================================================================

IncrementalBackup& IncrementalBackup::Instance() noexcept {
    static IncrementalBackup instance;
    return instance;
}

bool IncrementalBackup::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

IncrementalBackup::IncrementalBackup()
    : m_impl(std::make_unique<IncrementalBackupImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

IncrementalBackup::~IncrementalBackup() = default;

bool IncrementalBackup::Initialize(const IncrementalConfiguration& config) {
    return m_impl->Initialize(config);
}

void IncrementalBackup::Shutdown() {
    m_impl->Shutdown();
}

bool IncrementalBackup::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus IncrementalBackup::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool IncrementalBackup::UpdateConfiguration(const IncrementalConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

IncrementalConfiguration IncrementalBackup::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

std::string IncrementalBackup::StartSync(
    const fs::path& source,
    const fs::path& vault,
    const ChunkingOptions& options) {
    return m_impl->StartSync(source, vault, options);
}

bool IncrementalBackup::Sync(const std::wstring& source, const std::wstring& vault) {
    ChunkingOptions options;
    auto id = m_impl->StartSync(source, vault, options);
    if (id.empty()) return false;

    // Block until sync completes, polling at reasonable intervals.
    while (true) {
        auto progress = m_impl->GetProgress(id);
        if (!progress.has_value()) {
            // Sync finished and was moved to completed results
            break;
        }
        auto s = progress->status;
        if (s == SyncStatus::Completed || s == SyncStatus::Failed || s == SyncStatus::Cancelled) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    auto result = m_impl->GetResult(id);
    return result.has_value() && result->status == SyncStatus::Completed;
}

bool IncrementalBackup::CancelSync(const std::string& syncId) {
    return m_impl->CancelSync(syncId);
}

bool IncrementalBackup::PauseSync(const std::string& syncId) {
    return m_impl->PauseSync(syncId);
}

bool IncrementalBackup::ResumeSync(const std::string& syncId) {
    return m_impl->ResumeSync(syncId);
}

std::optional<SyncProgress> IncrementalBackup::GetProgress(const std::string& syncId) {
    return m_impl->GetProgress(syncId);
}

std::optional<SyncResult> IncrementalBackup::GetResult(const std::string& syncId) {
    return m_impl->GetResult(syncId);
}

std::vector<FileChangeRecord> IncrementalBackup::ScanForChanges(
    const fs::path& source,
    const fs::path& baselinePath) {
    return m_impl->ScanForChanges(source, baselinePath);
}

std::vector<FileChangeRecord> IncrementalBackup::GetUSNChanges(
    const std::wstring& volumePath,
    uint64_t fromUSN) {
    return m_impl->GetUSNChanges(volumePath, fromUSN);
}

FileChangeRecord IncrementalBackup::CompareFiles(
    const fs::path& oldFile,
    const fs::path& newFile) {
    return m_impl->CompareFiles(oldFile, newFile);
}

std::vector<ChunkDescriptor> IncrementalBackup::ChunkData(
    std::span<const uint8_t> data,
    const ChunkingOptions& options) {
    return m_impl->ChunkData(data, options);
}

std::vector<ChunkDescriptor> IncrementalBackup::ChunkFile(
    const fs::path& filePath,
    const ChunkingOptions& options) {
    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return {};
    auto fileSize = fs::file_size(filePath, ec);
    if (ec || fileSize == 0) return {};

    if (fileSize > MAX_SINGLE_FILE_SIZE) {
        SS_LOG_WARN(LOG_CATEGORY, L"ChunkFile: file exceeds size limit (%llu bytes): %ls",
            static_cast<unsigned long long>(fileSize), filePath.c_str());
        return {};
    }

    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs) return {};

    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
    ifs.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(fileSize));
    auto bytesRead = static_cast<size_t>(ifs.gcount());
    if (bytesRead == 0) return {};

    return ChunkData(std::span<const uint8_t>(buffer.data(), bytesRead), options);
}

bool IncrementalBackup::AddChunkToIndex(const ChunkDescriptor& chunk) {
    return m_impl->AddChunkToIndex(chunk);
}

bool IncrementalBackup::ChunkExists(const std::array<uint8_t, 32>& hash) {
    return m_impl->ChunkExists(hash);
}

std::optional<DedupIndexEntry> IncrementalBackup::GetChunkFromIndex(
    const std::array<uint8_t, 32>& hash) {
    return m_impl->GetChunkFromIndex(hash);
}

double IncrementalBackup::GetDedupRatio() const noexcept {
    return m_impl->GetDedupRatio();
}

bool IncrementalBackup::CompactIndex() {
    return m_impl->CompactIndex();
}

std::vector<uint8_t> IncrementalBackup::CompressChunk(
    std::span<const uint8_t> data,
    CompressionAlgorithm algorithm) {
    return m_impl->CompressChunk(data, algorithm);
}

std::vector<uint8_t> IncrementalBackup::DecompressChunk(
    std::span<const uint8_t> data,
    CompressionAlgorithm algorithm,
    size_t originalSize) {
    return m_impl->DecompressChunk(data, algorithm, originalSize);
}

void IncrementalBackup::SetChunkingAlgorithm(ChunkingAlgorithm algorithm) {
    m_impl->SetChunkingAlgorithm(algorithm);
}

void IncrementalBackup::SetCompressionAlgorithm(CompressionAlgorithm algorithm) {
    m_impl->SetCompressionAlgorithm(algorithm);
}

void IncrementalBackup::SetCompressionLevel(int level) {
    m_impl->SetCompressionLevel(level);
}

void IncrementalBackup::RegisterProgressCallback(ProgressCallback callback) {
    m_impl->RegisterProgressCallback(std::move(callback));
}

void IncrementalBackup::RegisterCompletionCallback(CompletionCallback callback) {
    m_impl->RegisterCompletionCallback(std::move(callback));
}

void IncrementalBackup::RegisterChunkCallback(ChunkCallback callback) {
    m_impl->RegisterChunkCallback(std::move(callback));
}

void IncrementalBackup::RegisterChangeCallback(ChangeCallback callback) {
    m_impl->RegisterChangeCallback(std::move(callback));
}

void IncrementalBackup::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void IncrementalBackup::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

IncrementalStatistics IncrementalBackup::GetStatistics() const {
    return m_impl->GetStatistics();
}

void IncrementalBackup::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool IncrementalBackup::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

    // Test chunking
    constexpr size_t testSize = 1024 * 1024;
    std::vector<uint8_t> testData(testSize);
    std::mt19937 gen(12345);
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    for (auto& b : testData) b = static_cast<uint8_t>(dist(gen));

    ChunkingOptions opts;
    auto chunks = ChunkData(testData, opts);

    if (chunks.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Chunking returned no chunks");
        return false;
    }

    // Verify chunk coverage
    size_t totalChunkBytes = 0;
    for (const auto& c : chunks) totalChunkBytes += c.originalSize;
    if (totalChunkBytes != testSize) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Self-test FAILED: Chunk coverage mismatch (%zu vs %zu)",
            totalChunkBytes, testSize);
        return false;
    }

    // Test dedup
    if (!AddChunkToIndex(chunks[0])) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: AddChunkToIndex returned false");
        return false;
    }
    if (!ChunkExists(chunks[0].hash)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Chunk not found after insert");
        return false;
    }

    // Test compression round-trip
    auto span = std::span<const uint8_t>(testData.data(), 4096);
    auto compressed = CompressChunk(span, CompressionAlgorithm::ZSTD);
    if (compressed.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Compression returned empty");
        return false;
    }

    SS_LOG_INFO(LOG_CATEGORY, L"Self-test PASSED (%zu chunks, %zu bytes compressed to %zu)",
        chunks.size(), span.size(), compressed.size());
    return true;
}

std::string IncrementalBackup::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// FREE FUNCTION IMPLEMENTATIONS
// ============================================================================

uint64_t RabinFingerprint(std::span<const uint8_t> data) {
    uint64_t fp = 0;
    for (uint8_t byte : data) {
        fp = (fp << 1) ^ (fp >> 63) ^
             (static_cast<uint64_t>(byte) * IncrementalConstants::RABIN_POLYNOMIAL);
    }
    return fp;
}

std::array<uint8_t, 32> CalculateChunkHash(
    std::span<const uint8_t> data,
    ChunkHashAlgorithm /*algorithm*/) {

    std::array<uint8_t, 32> hash{};
    Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
    if (!hasher.Init()) return hash;
    if (!hasher.Update(data.data(), data.size())) return hash;
    std::vector<uint8_t> digest;
    if (!hasher.Final(digest)) return hash;
    size_t copyLen = std::min(digest.size(), hash.size());
    std::memcpy(hash.data(), digest.data(), copyLen);
    return hash;
}

std::vector<size_t> FindChunkBoundaries(
    std::span<const uint8_t> data,
    const ChunkingOptions& options) {

    std::vector<size_t> boundaries;
    if (data.empty()) return boundaries;
    if (data.size() <= options.minChunkSize) {
        boundaries.push_back(data.size());
        return boundaries;
    }

    size_t pos = 0;
    while (pos < data.size()) {
        size_t remaining = data.size() - pos;
        if (remaining <= options.minChunkSize) {
            boundaries.push_back(data.size());
            break;
        }

        size_t searchStart = pos + options.minChunkSize;
        size_t searchEnd = std::min(pos + options.maxChunkSize, data.size());
        size_t midpoint = pos + options.avgChunkSize;

        uint64_t fingerprint = 0;
        size_t cutPoint = searchEnd;

        uint64_t maskS = (1ULL << 15) - 1;
        uint64_t maskL = (1ULL << 13) - 1;
        if (options.avgChunkSize >= 65536) {
            maskS = (1ULL << 16) - 1;
            maskL = (1ULL << 14) - 1;
        }

        for (size_t i = searchStart; i < searchEnd; ++i) {
            fingerprint = (fingerprint << 1) + GEAR_MATRIX[data[i]];
            uint64_t mask = (i < midpoint) ? maskS : maskL;
            if ((fingerprint & mask) == 0) {
                cutPoint = i + 1;
                break;
            }
        }

        boundaries.push_back(cutPoint);
        pos = cutPoint;
    }

    return boundaries;
}

}  // namespace Backup
}  // namespace ShadowStrike
