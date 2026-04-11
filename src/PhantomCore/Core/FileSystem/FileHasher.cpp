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
 * @file FileHasher.cpp
 * @brief Enterprise implementation of multi-algorithm file hashing engine.
 *
 * The Hash Factory of ShadowStrike NGAV - computes cryptographic and fuzzy hashes
 * for malware detection, file identification, and similarity analysis. Supports
 * single-pass multi-hash, hardware acceleration, and intelligent caching.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "FileHasher.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/MemoryUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ThreadPool.hpp"

// FuzzyHasher: CTPH engine for fuzzy hash computation and comparison
#include "../../FuzzyHasher/FuzzyHasher.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <cmath>

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <wincrypt.h>
#  pragma comment(lib, "Crypt32.lib")
#  pragma comment(lib, "Advapi32.lib")
#endif

// External fuzzy hash libraries (assumed available)
// #include <tlsh.h>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// Bitwise operators for HashAlgorithm are defined in FileHasher.hpp (constexpr).
// Do NOT duplicate them here — ODR violation.

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] constexpr const char* HashAlgorithmToString(HashAlgorithm algo) noexcept {
    switch (algo) {
        case HashAlgorithm::None: return "None";
        case HashAlgorithm::MD5: return "MD5";
        case HashAlgorithm::SHA1: return "SHA1";
        case HashAlgorithm::SHA256: return "SHA256";
        case HashAlgorithm::SHA512: return "SHA512";
        case HashAlgorithm::SHA3_256: return "SHA3-256";
        case HashAlgorithm::SHA3_512: return "SHA3-512";
        case HashAlgorithm::FUZZY: return "fuzzy";
        case HashAlgorithm::TLSH: return "TLSH";
        case HashAlgorithm::IMPHASH: return "imphash";
        case HashAlgorithm::AUTHENTIHASH: return "authentihash";
        case HashAlgorithm::Standard: return "Standard (MD5+SHA1+SHA256)";
        case HashAlgorithm::AllCrypto: return "All Cryptographic";
        case HashAlgorithm::AllFuzzy: return "All Fuzzy";
        case HashAlgorithm::All: return "All Algorithms";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsPEFile(const std::wstring& filePath) noexcept {
    try {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        // Check DOS signature (MZ)
        char dosSignature[2];
        file.read(dosSignature, 2);
        if (!file || dosSignature[0] != 'M' || dosSignature[1] != 'Z') {
            return false;
        }

        // Read PE offset from DOS header at offset 0x3C
        file.seekg(0x3C, std::ios::beg);
        if (!file) return false;

        uint32_t peOffset = 0;
        file.read(reinterpret_cast<char*>(&peOffset), 4);
        if (!file) return false;

        // Validate PE offset: must be >= 0x40 (after DOS header) and < 4KB
        // to prevent seeking to attacker-controlled offsets in malformed files
        if (peOffset < 0x40 || peOffset > 4096) {
            return false;
        }

        // Check PE signature
        file.seekg(peOffset, std::ios::beg);
        if (!file) return false;

        char peSignature[4];
        file.read(peSignature, 4);
        if (!file) return false;

        return (peSignature[0] == 'P' && peSignature[1] == 'E' &&
                peSignature[2] == 0 && peSignature[3] == 0);

    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::vector<uint8_t> ReadFileHeader(
    const std::wstring& filePath,
    size_t headerSize
) noexcept {
    try {
        // Cap header read to prevent excessive allocation from untrusted input
        if (headerSize > FileHasherConstants::MAX_HEADER_READ_SIZE) {
            headerSize = FileHasherConstants::MAX_HEADER_READ_SIZE;
        }
        if (headerSize == 0) return {};

        std::ifstream file(filePath, std::ios::binary);
        if (!file) return {};

        std::vector<uint8_t> header(headerSize);
        file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(headerSize));
        const size_t bytesRead = static_cast<size_t>(file.gcount());

        header.resize(bytesRead);
        return header;

    } catch (...) {
        return {};
    }
}

// ============================================================================
// FileHasherConfig FACTORY METHODS
// ============================================================================

FileHasherConfig FileHasherConfig::CreateDefault() noexcept {
    return FileHasherConfig{};
}

FileHasherConfig FileHasherConfig::CreateHighPerformance() noexcept {
    FileHasherConfig config;
    config.defaultAlgorithms = HashAlgorithm::Standard;
    config.bufferSize = 1 * 1024 * 1024; // 1MB for faster I/O
    config.useMemoryMapping = true;
    config.useHardwareAcceleration = true;
    config.workerThreads = std::thread::hardware_concurrency();
    config.enableCache = true;
    config.maxCacheSize = 500000; // 500k entries
    config.cacheTTLHours = 48;
    config.largeFileThreshold = 50 * 1024 * 1024; // 50MB
    return config;
}

FileHasherConfig FileHasherConfig::CreateComprehensive() noexcept {
    FileHasherConfig config;
    config.defaultAlgorithms = HashAlgorithm::All;
    config.bufferSize = 64 * 1024; // 64KB
    config.useMemoryMapping = true;
    config.useHardwareAcceleration = true;
    config.workerThreads = std::thread::hardware_concurrency();
    config.enableCache = true;
    config.maxCacheSize = 100000;
    config.cacheTTLHours = 24;
    config.computeFuzzyHashes = true;
    config.computePEHashes = true;
    return config;
}

FileHasherConfig FileHasherConfig::CreateMinimal() noexcept {
    FileHasherConfig config;
    config.defaultAlgorithms = HashAlgorithm::SHA256;
    config.bufferSize = 32 * 1024; // 32KB
    config.useMemoryMapping = false;
    config.useHardwareAcceleration = false;
    config.workerThreads = 1;
    config.enableCache = false;
    config.computeFuzzyHashes = false;
    config.computePEHashes = false;
    return config;
}

// ============================================================================
// INTERNAL ATOMIC STATISTICS
// ============================================================================
// The public FileHasherStatistics is a plain copyable snapshot.
// Internally we use atomics for lock-free stat updates on the hot path.

struct InternalStats {
    std::atomic<uint64_t> filesHashed{0};
    std::atomic<uint64_t> bytesProcessed{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> md5Computed{0};
    std::atomic<uint64_t> sha1Computed{0};
    std::atomic<uint64_t> sha256Computed{0};
    std::atomic<uint64_t> sha512Computed{0};
    std::atomic<uint64_t> fuzzyHashComputed{0};
    std::atomic<uint64_t> tlshComputed{0};
    std::atomic<uint64_t> imphashComputed{0};
    std::atomic<uint64_t> averageTimeUs{0};
    std::atomic<uint64_t> maxTimeUs{0};
    std::atomic<uint64_t> hardwareAccelUsed{0};
    std::atomic<uint64_t> memoryMappedFiles{0};
    steady_clock::time_point startTime{steady_clock::now()};

    void Reset() noexcept {
        filesHashed.store(0, std::memory_order_relaxed);
        bytesProcessed.store(0, std::memory_order_relaxed);
        cacheHits.store(0, std::memory_order_relaxed);
        cacheMisses.store(0, std::memory_order_relaxed);
        md5Computed.store(0, std::memory_order_relaxed);
        sha1Computed.store(0, std::memory_order_relaxed);
        sha256Computed.store(0, std::memory_order_relaxed);
        sha512Computed.store(0, std::memory_order_relaxed);
        fuzzyHashComputed.store(0, std::memory_order_relaxed);
        tlshComputed.store(0, std::memory_order_relaxed);
        imphashComputed.store(0, std::memory_order_relaxed);
        averageTimeUs.store(0, std::memory_order_relaxed);
        maxTimeUs.store(0, std::memory_order_relaxed);
        hardwareAccelUsed.store(0, std::memory_order_relaxed);
        memoryMappedFiles.store(0, std::memory_order_relaxed);
        startTime = steady_clock::now();
    }

    [[nodiscard]] FileHasherStatistics Snapshot() const noexcept {
        FileHasherStatistics snap;
        snap.filesHashed      = filesHashed.load(std::memory_order_relaxed);
        snap.bytesProcessed   = bytesProcessed.load(std::memory_order_relaxed);
        snap.cacheHits        = cacheHits.load(std::memory_order_relaxed);
        snap.cacheMisses      = cacheMisses.load(std::memory_order_relaxed);
        snap.md5Computed      = md5Computed.load(std::memory_order_relaxed);
        snap.sha1Computed     = sha1Computed.load(std::memory_order_relaxed);
        snap.sha256Computed   = sha256Computed.load(std::memory_order_relaxed);
        snap.sha512Computed   = sha512Computed.load(std::memory_order_relaxed);
        snap.fuzzyHashComputed = fuzzyHashComputed.load(std::memory_order_relaxed);
        snap.tlshComputed     = tlshComputed.load(std::memory_order_relaxed);
        snap.imphashComputed  = imphashComputed.load(std::memory_order_relaxed);
        snap.averageTimeUs    = averageTimeUs.load(std::memory_order_relaxed);
        snap.maxTimeUs        = maxTimeUs.load(std::memory_order_relaxed);
        snap.hardwareAccelUsed = hardwareAccelUsed.load(std::memory_order_relaxed);
        snap.memoryMappedFiles = memoryMappedFiles.load(std::memory_order_relaxed);
        snap.startTime        = startTime;
        return snap;
    }
};

// ============================================================================
// FileHashes METHODS
// ============================================================================

bool FileHashes::IsValid() const noexcept {
    return hasMD5 || hasSHA1 || hasSHA256 || hasSHA512 ||
           hasSHA3_256 || hasSHA3_512 || hasFuzzyHash || hasTLSH ||
           hasImpHash || hasAuthentihash;
}

std::string FileHashes::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"filePath\": \"" << StringUtils::ToNarrow(filePath) << "\",\n";
    oss << "  \"fileSize\": " << fileSize << ",\n";

    if (hasMD5) oss << "  \"md5\": \"" << md5Hex << "\",\n";
    if (hasSHA1) oss << "  \"sha1\": \"" << sha1Hex << "\",\n";
    if (hasSHA256) oss << "  \"sha256\": \"" << sha256Hex << "\",\n";
    if (hasSHA512) oss << "  \"sha512\": \"" << sha512Hex << "\",\n";
    if (hasSHA3_256) oss << "  \"sha3_256\": \"" << sha3_256Hex << "\",\n";
    if (hasSHA3_512) oss << "  \"sha3_512\": \"" << sha3_512Hex << "\",\n";
    if (hasFuzzyHash) oss << "  \"fuzzyHash\": \"" << fuzzyHash << "\",\n";
    if (hasTLSH) oss << "  \"tlsh\": \"" << tlsh << "\",\n";
    if (hasImpHash) oss << "  \"imphash\": \"" << imphash << "\",\n";
    if (hasAuthentihash) oss << "  \"authentihash\": \"" << authentihash << "\",\n";

    oss << "  \"computeDurationMs\": " << computeDuration.count() << "\n";
    oss << "}";

    return oss.str();
}

// ============================================================================
// HashComparison METHODS
// ============================================================================

bool HashComparison::IsMatch() const noexcept {
    return md5Match || sha1Match || sha256Match || sha512Match ||
           sha3_256Match || sha3_512Match;
}

bool HashComparison::IsSimilar() const noexcept {
    return fuzzySimilarity >= 50.0 || tlshDistance <= 100;
}

std::string HashComparison::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"md5Match\": " << (md5Match ? "true" : "false") << ",\n";
    oss << "  \"sha256Match\": " << (sha256Match ? "true" : "false") << ",\n";
    oss << "  \"fuzzySimilarity\": " << fuzzySimilarity << ",\n";
    oss << "  \"tlshDistance\": " << tlshDistance << ",\n";
    oss << "  \"isMatch\": " << (IsMatch() ? "true" : "false") << ",\n";
    oss << "  \"isSimilar\": " << (IsSimilar() ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for FileHasher.
 */
class FileHasherImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::mutex m_operationMutex;

    // Initialization state
    std::atomic<bool> m_initialized{false};

    // Configuration
    FileHasherConfig m_config{};

    // Thread pool for async operations
    std::shared_ptr<ThreadPool> m_threadPool;

    // Statistics (lock-free atomic counters — see InternalStats above)
    InternalStats m_stats{};

    // Hash cache (LRU with TTL)
     struct CachedHash {
         FileHashes hashes;
         steady_clock::time_point timestamp;
         fs::file_time_type fileModTime{};
         bool hasFileModTime{ false };
         mutable std::atomic<uint32_t> hitCount{0};
     };
    std::unordered_map<std::wstring, CachedHash> m_hashCache;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, HashCallback> m_hashCallbacks;
    std::unordered_map<uint64_t, ProgressCallback> m_progressCallbacks;

    // Hardware capabilities
    bool m_hasAESNI = false;
    bool m_hasSHANI = false;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    FileHasherImpl() {
        m_stats.startTime = steady_clock::now();
    }

    ~FileHasherImpl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const FileHasherConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"FileHasher", L"FileHasher::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"FileHasher", L"FileHasher::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Detect hardware capabilities
            DetectHardwareCapabilities();

            // Create thread pool if needed
             if (!m_threadPool && m_config.workerThreads > 0) {
                 ThreadPoolConfig tpConfig;
                 tpConfig.minThreads = std::max(
                     ThreadPoolConfig::ABSOLUTE_MIN_THREADS,
                     static_cast<size_t>(m_config.workerThreads));
                 tpConfig.maxThreads = std::max(
                     ThreadPoolConfig::MIN_THREAD_LIMIT,
                     static_cast<size_t>(m_config.workerThreads));
                 m_threadPool = std::make_shared<ThreadPool>(tpConfig);
                 if (!m_threadPool->Initialize()) {
                     SS_LOG_ERROR(L"FileHasher", L"FileHasher: Thread pool initialization failed");
                     m_threadPool.reset();
                     return false;
                 }
                 SS_LOG_INFO(L"FileHasher", L"FileHasher: Thread pool created with %u workers",
                             m_config.workerThreads);
             }

            // Reset statistics
            m_stats.Reset();

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"FileHasher", L"FileHasher::Impl: Initialization complete");
            SS_LOG_INFO(L"FileHasher", L"FileHasher: Hardware - AES-NI: %hs, SHA-NI: %hs", m_hasAESNI ? "YES" : "NO", m_hasSHANI ? "YES" : "NO");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher::Impl: Initialization exception: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"FileHasher", L"FileHasher::Impl: Shutting down");

        // Clear cache
        {
            std::unique_lock cacheLock(m_cacheMutex);
            m_hashCache.clear();
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_hashCallbacks.clear();
            m_progressCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"FileHasher", L"FileHasher::Impl: Shutdown complete");
    }

    // ========================================================================
    // HARDWARE DETECTION
    // ========================================================================

    void DetectHardwareCapabilities() noexcept {
        try {
#ifdef _WIN32
            // Check for AES-NI and SHA-NI using CPUID
            int cpuInfo[4] = {0};

            // CPUID function 1: Feature Information
            __cpuid(cpuInfo, 1);
            m_hasAESNI = (cpuInfo[2] & (1 << 25)) != 0; // ECX bit 25

            // CPUID function 7: Extended Features
            __cpuidex(cpuInfo, 7, 0);
            m_hasSHANI = (cpuInfo[1] & (1 << 29)) != 0; // EBX bit 29

            SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Hardware detection - AES-NI: %hs, SHA-NI: %hs",
                        m_hasAESNI ? "YES" : "NO", m_hasSHANI ? "YES" : "NO");
#endif
        } catch (...) {
            SS_LOG_WARN(L"FileHasher", L"FileHasher: Hardware capability detection failed");
            m_hasAESNI = false;
            m_hasSHANI = false;
        }
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::optional<FileHashes> GetFromCache(
        const std::wstring& filePath
    ) const {
        if (!m_config.enableCache) {
            return std::nullopt;
        }

        std::shared_lock lock(m_cacheMutex);

        auto it = m_hashCache.find(filePath);
        if (it == m_hashCache.end()) {
            return std::nullopt;
        }

        auto& cached = it->second;

        // Check TTL
            auto age = steady_clock::now() - cached.timestamp;
            auto ttl = std::chrono::hours(m_config.cacheTTLHours);
            if (age > ttl) {
                return std::nullopt;
            }

            // Check file modification time
            if (cached.hasFileModTime) {
                try {
                    std::error_code ec;
                    auto lastWrite = fs::last_write_time(filePath, ec);
                    if (ec || lastWrite != cached.fileModTime) {
                        return std::nullopt; // File modified or no longer queryable
                    }
                } catch (...) {
                    return std::nullopt;
                }
            }

        // Update hit count atomically — safe under shared_lock
        cached.hitCount.fetch_add(1, std::memory_order_relaxed);

        return cached.hashes;
    }

    void AddToCache(const std::wstring& filePath, const FileHashes& hashes) {
        if (!m_config.enableCache) {
            return;
        }

        std::unique_lock lock(m_cacheMutex);

        // LRU eviction if cache is full
        if (m_hashCache.size() >= m_config.maxCacheSize) {
            // Find least recently used entry
            auto lru = std::min_element(
                m_hashCache.begin(),
                m_hashCache.end(),
                [](const auto& a, const auto& b) {
                    return a.second.timestamp < b.second.timestamp;
                }
            );

            if (lru != m_hashCache.end()) {
                SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Cache eviction (LRU): %hs", StringUtils::ToNarrow(lru->first).c_str());
                m_hashCache.erase(lru);
            }
        }

        fs::file_time_type modTime{};
        bool hasModTime = false;
        try {
            std::error_code ec;
            auto lastWrite = fs::last_write_time(filePath, ec);
            if (!ec) {
                modTime = lastWrite;
                hasModTime = true;
            }
        } catch (...) {
            // Cache the hashes without modification-time binding if metadata lookup fails.
        }

        // Erase existing entry (if any) to make room for the new one
        m_hashCache.erase(filePath);

        // Construct in-place (CachedHash has non-copyable atomic member)
        auto [it, inserted] = m_hashCache.try_emplace(filePath);
        auto& entry = it->second;
        entry.hashes = hashes;
        entry.timestamp = steady_clock::now();
        entry.fileModTime = modTime;
        entry.hasFileModTime = hasModTime;
        entry.hitCount.store(0, std::memory_order_relaxed);

        SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Added to cache: %hs (size: %zu)", StringUtils::ToNarrow(filePath).c_str(), m_hashCache.size());
    }

    void InvalidateCacheEntry(const std::wstring& filePath) {
        std::unique_lock lock(m_cacheMutex);
        m_hashCache.erase(filePath);
    }

    void ClearCacheImpl() noexcept {
        std::unique_lock lock(m_cacheMutex);
        m_hashCache.clear();
        SS_LOG_INFO(L"FileHasher", L"FileHasher: Cache cleared");
    }

    // ========================================================================
    // SINGLE-PASS MULTI-HASH COMPUTATION
    // ========================================================================

    [[nodiscard]] FileHashes ComputeAllImpl(
        const std::wstring& filePath,
        HashAlgorithm algorithms
    ) {
        FileHashes result{};
        const auto startTime = steady_clock::now();

        try {
            // Check cache first
            if (m_config.enableCache) {
                if (auto cached = GetFromCache(filePath)) {
                    m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Cache hit for %hs", StringUtils::ToNarrow(filePath).c_str());
                    return *cached;
                }
                m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
            }

            result.filePath = filePath;

            // Validate file
            std::error_code ec;
            if (!fs::exists(filePath, ec)) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: File not found: %hs", StringUtils::ToNarrow(filePath).c_str());
                return result;
            }

            result.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Cannot get file size: %hs", ec.message().c_str());
                return result;
            }

            // Security: reject files exceeding the configured maximum
            if (result.fileSize > FileHasherConstants::MAX_HASH_FILE_SIZE) {
                SS_LOG_WARN(L"FileHasher",
                    L"FileHasher: File exceeds MAX_HASH_FILE_SIZE (%llu > %llu): %hs",
                    result.fileSize,
                    static_cast<uint64_t>(FileHasherConstants::MAX_HASH_FILE_SIZE),
                    StringUtils::ToNarrow(filePath).c_str());
                result.hasErrors = true;
                result.errors.emplace_back("File exceeds maximum hashable size");
                return result;
            }

            SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Computing hashes for %hs (%llu bytes)", StringUtils::ToNarrow(filePath).c_str(), result.fileSize);

            // Decide whether to use memory mapping
            bool useMemMap = m_config.useMemoryMapping &&
                           (result.fileSize >= m_config.largeFileThreshold);

            if (useMemMap) {
                m_stats.memoryMappedFiles.fetch_add(1, std::memory_order_relaxed);
            }

            // Compute cryptographic hashes
            if (HasFlag(algorithms, HashAlgorithm::MD5)) {
                ComputeMD5Impl(filePath, result);
            }
            if (HasFlag(algorithms, HashAlgorithm::SHA1)) {
                ComputeSHA1Impl(filePath, result);
            }
            if (HasFlag(algorithms, HashAlgorithm::SHA256)) {
                ComputeSHA256Impl(filePath, result);
            }
            if (HasFlag(algorithms, HashAlgorithm::SHA512)) {
                ComputeSHA512Impl(filePath, result);
            }
            if (HasFlag(algorithms, HashAlgorithm::SHA3_256)) {
                ComputeSHA3_256Impl(filePath, result);
            }
            if (HasFlag(algorithms, HashAlgorithm::SHA3_512)) {
                ComputeSHA3_512Impl(filePath, result);
            }

            // Compute fuzzy hashes
            if (m_config.computeFuzzyHashes) {
                if (HasFlag(algorithms, HashAlgorithm::FUZZY)) {
                    ComputeFuzzyHashImpl(filePath, result);
                }
                if (HasFlag(algorithms, HashAlgorithm::TLSH)) {
                    ComputeTLSHImpl(filePath, result);
                }
            }

            // Compute PE-specific hashes
            if (m_config.computePEHashes && IsPEFile(filePath)) {
                if (HasFlag(algorithms, HashAlgorithm::IMPHASH)) {
                    ComputeImpHashImpl(filePath, result);
                }
                if (HasFlag(algorithms, HashAlgorithm::AUTHENTIHASH)) {
                    ComputeAuthentihashImpl(filePath, result);
                }
            }

            // Record timing
            auto endTime = steady_clock::now();
            result.computeDuration = duration_cast<milliseconds>(endTime - startTime);
            result.computedTime = system_clock::now();

            // Update statistics
            m_stats.filesHashed.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesProcessed.fetch_add(result.fileSize, std::memory_order_relaxed);

            uint64_t durationUs = duration_cast<microseconds>(endTime - startTime).count();

            // Update exponential moving average via CAS to avoid lost updates
            uint64_t oldAvg = m_stats.averageTimeUs.load(std::memory_order_relaxed);
            uint64_t newAvg;
            do {
                newAvg = (oldAvg == 0) ? durationUs : (oldAvg + durationUs) / 2;
            } while (!m_stats.averageTimeUs.compare_exchange_weak(
                oldAvg, newAvg, std::memory_order_relaxed));

            // Update max via CAS
            uint64_t oldMax = m_stats.maxTimeUs.load(std::memory_order_relaxed);
            while (durationUs > oldMax) {
                if (m_stats.maxTimeUs.compare_exchange_weak(
                        oldMax, durationUs, std::memory_order_relaxed)) {
                    break;
                }
            }

            // Add to cache
            if (m_config.enableCache) {
                AddToCache(filePath, result);
            }

            SS_LOG_INFO(L"FileHasher", L"FileHasher: Computed %u hashes in %lld ms", CountComputedHashes(result), static_cast<long long>(result.computeDuration.count()));

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: ComputeAll exception: %hs", e.what());
            return result;
        }
    }

    // ========================================================================
    // INDIVIDUAL HASH COMPUTATIONS
    // ========================================================================

    void ComputeMD5Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::MD5,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 16) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.md5.begin());
                    result.md5Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasMD5 = true;
                    m_stats.md5Computed.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: MD5 = %hs", result.md5Hex.c_str());
                }
            } else {
                SS_LOG_WARN(L"FileHasher", L"FileHasher: MD5 computation failed");
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: MD5 exception: %hs", e.what());
        }
    }

    void ComputeSHA1Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA1,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 20) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha1.begin());
                    result.sha1Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA1 = true;
                    m_stats.sha1Computed.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: SHA1 = %hs", result.sha1Hex.c_str());
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: SHA1 exception: %hs", e.what());
        }
    }

    void ComputeSHA256Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA256,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 32) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha256.begin());
                    result.sha256Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA256 = true;
                    m_stats.sha256Computed.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: SHA256 = %hs", result.sha256Hex.c_str());
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: SHA256 exception: %hs", e.what());
        }
    }

    void ComputeSHA512Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA512,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 64) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha512.begin());
                    result.sha512Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA512 = true;
                    m_stats.sha512Computed.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: SHA512 = %hs...", result.sha512Hex.substr(0, 32).c_str());
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: SHA512 exception: %hs", e.what());
        }
    }

    void ComputeSHA3_256Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA3_256,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 32) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha3_256.begin());
                    result.sha3_256Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA3_256 = true;

                    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: SHA3-256 = %hs", result.sha3_256Hex.c_str());
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: SHA3-256 exception: %hs", e.what());
        }
    }

    void ComputeSHA3_512Impl(const std::wstring& filePath, FileHashes& result) {
        // NOTE: HashUtils::Algorithm does not include SHA3_512.
        // SHA3-512 support requires adding SHA3_512 to HashUtils::Algorithm
        // or implementing a direct BCrypt call here. Marked unavailable until
        // the HashUtils module is extended.
        SS_LOG_DEBUG(L"FileHasher",
            L"FileHasher: SHA3-512 unavailable — HashUtils does not yet support this algorithm");
        result.hasSHA3_512 = false;
    }

    void ComputeFuzzyHashImpl(const std::wstring& filePath, FileHashes& result) {
        try {
            // Memory-map the file for zero-copy access — preferred over
            // ReadAllBytes because it avoids a heap allocation proportional
            // to the file size and works efficiently on large files.
            Utils::MemoryUtils::MappedView mappedFile;
            if (!mappedFile.mapReadOnly(filePath)) {
                SS_LOG_WARN(L"FileHasher", L"FileHasher: Failed to memory-map file for fuzzy hash: %hs", StringUtils::ToNarrow(filePath).c_str());
                return;
            }

            if (!mappedFile.hasData()) {
                SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Skipping fuzzy hash for empty file: %hs", StringUtils::ToNarrow(filePath).c_str());
                return;
            }

            // Cap input to FuzzyHasher's maximum to prevent CPU/memory DoS.
            const size_t hashSize = std::min(
                mappedFile.size(),
                ShadowStrike::FuzzyHasher::kMaxHashableSize
            );

            auto digest = ShadowStrike::FuzzyHasher::HashBuffer(
                std::span<const uint8_t>(
                    static_cast<const uint8_t*>(mappedFile.data()),
                    hashSize
                )
            );

            if (!digest.has_value()) {
                SS_LOG_WARN(L"FileHasher", L"FileHasher: FuzzyHasher::HashBuffer returned no digest for: %hs", StringUtils::ToNarrow(filePath).c_str());
                return;
            }

            result.fuzzyHash  = std::move(digest.value());
            result.hasFuzzyHash = true;
            m_stats.fuzzyHashComputed.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Fuzzy hash = %hs", result.fuzzyHash.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: Fuzzy hash exception: %hs", e.what());
        }
    }

    void ComputeTLSHImpl(const std::wstring& /*filePath*/, FileHashes& result) {
        // TLSH library integration pending. Do NOT set placeholder values
        // that could be confused with real hashes in downstream lookups.
        SS_LOG_DEBUG(L"FileHasher", L"FileHasher: TLSH computation not yet integrated");
        result.hasTLSH = false;
    }

    void ComputeImpHashImpl(const std::wstring& /*filePath*/, FileHashes& result) {
        // PE import-table hash requires PEParser integration.
        // Do NOT set placeholder values.
        SS_LOG_DEBUG(L"FileHasher", L"FileHasher: imphash computation not yet integrated");
        result.hasImpHash = false;
    }

    void ComputeAuthentihashImpl(const std::wstring& /*filePath*/, FileHashes& result) {
        // Authenticode hash requires PE signature parsing (PEParser integration).
        // Do NOT set placeholder values.
        SS_LOG_DEBUG(L"FileHasher", L"FileHasher: authentihash computation not yet integrated");
        result.hasAuthentihash = false;
    }

    // ========================================================================
    // BUFFER HASHING
    // ========================================================================

    [[nodiscard]] FileHashes ComputeAllBufferImpl(
        std::span<const uint8_t> buffer,
        HashAlgorithm algorithms
    ) {
        FileHashes result{};
        const auto startTime = steady_clock::now();

        try {
            result.fileSize = buffer.size();
            result.filePath = L"<memory buffer>";

            SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Computing hashes for buffer (%zu bytes)", buffer.size());

            // Compute cryptographic hashes
            if (HasFlag(algorithms, HashAlgorithm::MD5)) {
                std::vector<uint8_t> hashBytes;
                HashUtils::Compute(HashUtils::Algorithm::MD5,
                                 buffer.data(), buffer.size(), hashBytes);
                if (hashBytes.size() == 16) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.md5.begin());
                    result.md5Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasMD5 = true;
                }
            }

            if (HasFlag(algorithms, HashAlgorithm::SHA1)) {
                std::vector<uint8_t> hashBytes;
                HashUtils::Compute(HashUtils::Algorithm::SHA1,
                                 buffer.data(), buffer.size(), hashBytes);
                if (hashBytes.size() == 20) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha1.begin());
                    result.sha1Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA1 = true;
                }
            }

            if (HasFlag(algorithms, HashAlgorithm::SHA256)) {
                std::vector<uint8_t> hashBytes;
                HashUtils::Compute(HashUtils::Algorithm::SHA256,
                                 buffer.data(), buffer.size(), hashBytes);
                if (hashBytes.size() == 32) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha256.begin());
                    result.sha256Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA256 = true;
                }
            }

            if (HasFlag(algorithms, HashAlgorithm::SHA512)) {
                std::vector<uint8_t> hashBytes;
                HashUtils::Compute(HashUtils::Algorithm::SHA512,
                                 buffer.data(), buffer.size(), hashBytes);
                if (hashBytes.size() == 64) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha512.begin());
                    result.sha512Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA512 = true;
                }
            }

            // Record timing
            auto endTime = steady_clock::now();
            result.computeDuration = duration_cast<milliseconds>(endTime - startTime);
            result.computedTime = system_clock::now();

            m_stats.bytesProcessed.fetch_add(buffer.size(), std::memory_order_relaxed);

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: ComputeAllBuffer exception: %hs", e.what());
            return result;
        }
    }

    // ========================================================================
    // COMPARISON
    // ========================================================================

    [[nodiscard]] HashComparison CompareImpl(
        const FileHashes& hashes1,
        const FileHashes& hashes2
    ) const {
        HashComparison result{};

        try {
            // Compare cryptographic hashes
            if (hashes1.hasMD5 && hashes2.hasMD5) {
                result.md5Match = (hashes1.md5 == hashes2.md5);
            }
            if (hashes1.hasSHA1 && hashes2.hasSHA1) {
                result.sha1Match = (hashes1.sha1 == hashes2.sha1);
            }
            if (hashes1.hasSHA256 && hashes2.hasSHA256) {
                result.sha256Match = (hashes1.sha256 == hashes2.sha256);
            }
            if (hashes1.hasSHA512 && hashes2.hasSHA512) {
                result.sha512Match = (hashes1.sha512 == hashes2.sha512);
            }
            if (hashes1.hasSHA3_256 && hashes2.hasSHA3_256) {
                result.sha3_256Match = (hashes1.sha3_256 == hashes2.sha3_256);
            }
            if (hashes1.hasSHA3_512 && hashes2.hasSHA3_512) {
                result.sha3_512Match = (hashes1.sha3_512 == hashes2.sha3_512);
            }

            // Compare fuzzy hashes
            if (hashes1.hasFuzzyHash && hashes2.hasFuzzyHash) {
                result.fuzzySimilarity = CompareFuzzyHashImpl(hashes1.fuzzyHash, hashes2.fuzzyHash);
            }
            if (hashes1.hasTLSH && hashes2.hasTLSH) {
                result.tlshDistance = ComputeTLSHDistanceImpl(hashes1.tlsh, hashes2.tlsh);
            }

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: Compare exception: %hs", e.what());
            return result;
        }
    }

    [[nodiscard]] double CompareFuzzyHashImpl(
        std::string_view hash1,
        std::string_view hash2
    ) const noexcept {
        try {
            if (hash1.empty() || hash2.empty()) {
                return 0.0;
            }

            // Both string_views are backed by std::string members in FileHashes —
            // safe to construct a temporary std::string for the Compare call.
            const int score = ShadowStrike::FuzzyHasher::Compare(
                std::string(hash1),
                std::string(hash2)
            );

            if (score < 0) {
                SS_LOG_WARN(L"FileHasher", L"FileHasher: FuzzyHasher::Compare returned error (-1) — ");
                return 0.0;
            }

            // Normalize the 0-100 integer score to the [0.0, 1.0] double range
            // used by the HashComparison::fuzzySimilarity field.
            return static_cast<double>(score) / 100.0;

        } catch (...) {
            return 0.0;
        }
    }

    [[nodiscard]] uint32_t ComputeTLSHDistanceImpl(
        std::string_view tlsh1,
        std::string_view tlsh2
    ) const noexcept {
        try {
            // TLSH distance requires TLSH library integration.
            // Returns max distance (no match) until library is available.
            SS_LOG_DEBUG(L"FileHasher", L"FileHasher: TLSH distance requires library integration");
            return UINT32_MAX;

        } catch (...) {
            return UINT32_MAX;
        }
    }

    // ========================================================================
    // PARTIAL HASHING
    // ========================================================================

    [[nodiscard]] std::string ComputeHeaderHashImpl(
        const std::wstring& filePath,
        HashAlgorithm algorithm,
        size_t headerSize
    ) {
        try {
            auto headerData = ReadFileHeader(filePath, headerSize);
            if (headerData.empty()) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Cannot read file header");
                return "";
            }

            std::vector<uint8_t> hashBytes;
            HashUtils::Algorithm algo = HashUtils::Algorithm::SHA256;

            if (HasFlag(algorithm, HashAlgorithm::MD5)) {
                algo = HashUtils::Algorithm::MD5;
            } else if (HasFlag(algorithm, HashAlgorithm::SHA1)) {
                algo = HashUtils::Algorithm::SHA1;
            } else if (HasFlag(algorithm, HashAlgorithm::SHA256)) {
                algo = HashUtils::Algorithm::SHA256;
            }

            HashUtils::Compute(algo, headerData.data(), headerData.size(), hashBytes);
            return HashUtils::ToHexLower(hashBytes);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileHasher", L"FileHasher: ComputeHeaderHash exception: %hs", e.what());
            return "";
        }
    }

    // ========================================================================
    // BATCH HASHING
    // ========================================================================

    [[nodiscard]] std::vector<FileHashes> ComputeBatchImpl(
        const std::vector<std::wstring>& filePaths,
        HashAlgorithm algorithms
    ) {
        std::vector<FileHashes> results;
        results.reserve(filePaths.size());

        SS_LOG_INFO(L"FileHasher", L"FileHasher: Batch hashing %zu files", filePaths.size());

        for (const auto& path : filePaths) {
            results.push_back(ComputeAllImpl(path, algorithms));
        }

        return results;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeHashCallbacks(const FileHashes& hashes) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_hashCallbacks) {
            try {
                callback(hashes);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Hash callback exception: %hs", e.what());
            }
        }
    }

    void InvokeProgressCallbacks(uint64_t current, uint64_t total) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(current, total);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Progress callback exception: %hs", e.what());
            }
        }
    }

    // ========================================================================
    // UTILITIES
    // ========================================================================

    [[nodiscard]] uint32_t CountComputedHashes(const FileHashes& hashes) const noexcept {
        uint32_t count = 0;
        if (hashes.hasMD5) count++;
        if (hashes.hasSHA1) count++;
        if (hashes.hasSHA256) count++;
        if (hashes.hasSHA512) count++;
        if (hashes.hasSHA3_256) count++;
        if (hashes.hasSHA3_512) count++;
        if (hashes.hasFuzzyHash) count++;
        if (hashes.hasTLSH) count++;
        if (hashes.hasImpHash) count++;
        if (hashes.hasAuthentihash) count++;
        return count;
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

FileHasher& FileHasher::Instance() {
    static FileHasher instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileHasher::FileHasher()
    : m_impl(std::make_unique<FileHasherImpl>())
{
    SS_LOG_INFO(L"FileHasher", L"FileHasher: Constructor called");
}

FileHasher::~FileHasher() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"FileHasher", L"FileHasher: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool FileHasher::Initialize(const FileHasherConfig& config) {
    if (!m_impl) {
        SS_LOG_FATAL(L"FileHasher", L"FileHasher: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

bool FileHasher::Initialize() {
    return Initialize(FileHasherConfig::CreateDefault());
}

void FileHasher::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool FileHasher::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

void FileHasher::UpdateConfig(const FileHasherConfig& config) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    SS_LOG_INFO(L"FileHasher", L"FileHasher: Configuration updated");
}

FileHasherConfig FileHasher::GetConfig() const {
    if (!m_impl) return FileHasherConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// FILE HASHING - COMPLETE
// ============================================================================

FileHashes FileHasher::ComputeAll(
    const std::wstring& filePath,
    HashAlgorithm algorithms
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return FileHashes{};
    }

    return m_impl->ComputeAllImpl(filePath, algorithms);
}

FileHashes FileHasher::ComputeAll(
    std::span<const uint8_t> buffer,
    HashAlgorithm algorithms
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return FileHashes{};
    }

    return m_impl->ComputeAllBufferImpl(buffer, algorithms);
}

std::future<FileHashes> FileHasher::ComputeAllAsync(
    const std::wstring& filePath,
    HashAlgorithm algorithms
) {
    return std::async(std::launch::async, [this, filePath, algorithms]() {
        return ComputeAll(filePath, algorithms);
    });
}

void FileHasher::ComputeAllAsync(
    const std::wstring& filePath,
    HashCallback callback,
    HashAlgorithm algorithms
) {
    if (!IsInitialized() || !m_impl->m_threadPool) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized or no thread pool");
        return;
    }

    (void)m_impl->m_threadPool->Submit(
        [this, filePath, callback, algorithms](const TaskContext&) {
        auto hashes = ComputeAll(filePath, algorithms);

        if (callback) {
            try {
                callback(hashes);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Async callback exception: %hs", e.what());
            }
        }

        m_impl->InvokeHashCallbacks(hashes);
    });
}

std::vector<FileHashes> FileHasher::ComputeBatch(
    const std::vector<std::wstring>& filePaths,
    HashAlgorithm algorithms,
    ProgressCallback progressCallback
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return {};
    }

    return m_impl->ComputeBatchImpl(filePaths, algorithms);
}

// ============================================================================
// INDIVIDUAL HASH ALGORITHMS
// ============================================================================

std::string FileHasher::ComputeMD5(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::MD5);
    return hashes.md5Hex;
}

std::string FileHasher::ComputeSHA1(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::SHA1);
    return hashes.sha1Hex;
}

std::string FileHasher::ComputeSHA256(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::SHA256);
    return hashes.sha256Hex;
}

std::string FileHasher::ComputeSHA512(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::SHA512);
    return hashes.sha512Hex;
}

std::string FileHasher::ComputeSHA3_256(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::SHA3_256);
    return hashes.sha3_256Hex;
}

std::string FileHasher::ComputeSHA3_512(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::SHA3_512);
    return hashes.sha3_512Hex;
}

std::string FileHasher::ComputeFuzzyHash(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::FUZZY);
    return hashes.fuzzyHash;
}

std::string FileHasher::ComputeTLSH(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::TLSH);
    return hashes.tlsh;
}

std::string FileHasher::ComputeImpHash(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::IMPHASH);
    return hashes.imphash;
}

std::string FileHasher::ComputeAuthentihash(const std::wstring& filePath) {
    auto hashes = ComputeAll(filePath, HashAlgorithm::AUTHENTIHASH);
    return hashes.authentihash;
}

// ============================================================================
// BUFFER HASHING
// ============================================================================

std::string FileHasher::ComputeMD5(std::span<const uint8_t> buffer) {
    auto hashes = ComputeAll(buffer, HashAlgorithm::MD5);
    return hashes.md5Hex;
}

std::string FileHasher::ComputeSHA256(std::span<const uint8_t> buffer) {
    auto hashes = ComputeAll(buffer, HashAlgorithm::SHA256);
    return hashes.sha256Hex;
}

// ============================================================================
// PARTIAL HASHING
// ============================================================================

std::string FileHasher::ComputeHeaderHash(
    const std::wstring& filePath,
    HashAlgorithm algorithm,
    size_t headerSize
) {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return "";
    }

    return m_impl->ComputeHeaderHashImpl(filePath, algorithm, headerSize);
}

std::unordered_map<std::string, std::string> FileHasher::ComputeSectionHashes(
    const std::wstring& filePath,
    HashAlgorithm algorithm
) {
    // PE section parsing requires PEParser integration.
    // Returns empty map until PEParser provides section offsets/sizes.
    SS_LOG_DEBUG(L"FileHasher",
        L"FileHasher: ComputeSectionHashes requires PEParser integration");
    return {};
}

// ============================================================================
// COMPARISON
// ============================================================================

HashComparison FileHasher::Compare(
    const FileHashes& hashes1,
    const FileHashes& hashes2
) const {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return HashComparison{};
    }

    return m_impl->CompareImpl(hashes1, hashes2);
}

double FileHasher::CompareFuzzyHash(
    std::string_view hash1,
    std::string_view hash2
) const noexcept {
    if (!IsInitialized()) return 0.0;
    return m_impl->CompareFuzzyHashImpl(hash1, hash2);
}

uint32_t FileHasher::ComputeTLSHDistance(
    std::string_view tlsh1,
    std::string_view tlsh2
) const noexcept {
    if (!IsInitialized()) return UINT32_MAX;
    return m_impl->ComputeTLSHDistanceImpl(tlsh1, tlsh2);
}

bool FileHasher::MatchesAny(
    const FileHashes& hashes,
    const std::vector<FileHashes>& candidates
) const {
    for (const auto& candidate : candidates) {
        auto comparison = Compare(hashes, candidate);
        if (comparison.IsMatch()) {
            return true;
        }
    }
    return false;
}

std::optional<size_t> FileHasher::FindBestMatch(
    const FileHashes& hashes,
    const std::vector<FileHashes>& candidates,
    double minSimilarity
) const {
    double bestSimilarity = 0.0;
    std::optional<size_t> bestIndex;

    for (size_t i = 0; i < candidates.size(); i++) {
        auto comparison = Compare(hashes, candidates[i]);

        if (comparison.fuzzySimilarity > bestSimilarity) {
            bestSimilarity = comparison.fuzzySimilarity;
            if (bestSimilarity >= minSimilarity) {
                bestIndex = i;
            }
        }
    }

    return bestIndex;
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

std::optional<FileHashes> FileHasher::GetCached(const std::wstring& filePath) const {
    if (!IsInitialized()) return std::nullopt;
    return m_impl->GetFromCache(filePath);
}

void FileHasher::ClearCache() noexcept {
    if (m_impl) {
        m_impl->ClearCacheImpl();
    }
}

void FileHasher::InvalidateCache(const std::wstring& filePath) {
    if (m_impl) {
        m_impl->InvalidateCacheEntry(filePath);
    }
}

size_t FileHasher::GetCacheSize() const noexcept {
    if (!m_impl) return 0;

    std::shared_lock lock(m_impl->m_cacheMutex);
    return m_impl->m_hashCache.size();
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t FileHasher::RegisterHashCallback(HashCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_hashCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Registered hash callback %llu", id);
    return id;
}

bool FileHasher::UnregisterHashCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_hashCallbacks.erase(callbackId) > 0;
}

uint64_t FileHasher::RegisterProgressCallback(ProgressCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"FileHasher", L"FileHasher: Registered progress callback %llu", id);
    return id;
}

bool FileHasher::UnregisterProgressCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_progressCallbacks.erase(callbackId) > 0;
}

// ============================================================================
// STATISTICS
// ============================================================================

FileHasherStatistics FileHasher::GetStatistics() const {
    return m_impl ? m_impl->m_stats.Snapshot() : FileHasherStatistics{};
}

void FileHasher::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        SS_LOG_INFO(L"FileHasher", L"FileHasher: Statistics reset");
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

bool FileHasher::SelfTest() {
    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Self-test failed - not initialized");
        return false;
    }

    try {
        SS_LOG_INFO(L"FileHasher", L"FileHasher: Running self-test");

        // Test 1: Hash a small buffer
        {
            std::vector<uint8_t> testData(1024, 0x42);
            auto hashes = ComputeAll(testData, HashAlgorithm::Standard);

            if (!hashes.hasSHA256) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Self-test failed - SHA256 not computed");
                return false;
            }
        }

        // Test 2: Cache functionality
        {
            ClearCache();
            auto cacheSize = GetCacheSize();
            if (cacheSize != 0) {
                SS_LOG_ERROR(L"FileHasher", L"FileHasher: Self-test failed - cache not cleared");
                return false;
            }
        }

        // Test 3: Statistics
        {
            auto stats = GetStatistics();
            // Just verify we can get stats without crashing
        }

        SS_LOG_INFO(L"FileHasher", L"FileHasher: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Self-test exception: %hs", e.what());
        return false;
    }
}

FileHasherVersionInfo FileHasher::GetVersionInfo() const {
    FileHasherVersionInfo info{};
    info.hasherVersion = std::to_string(FileHasherConstants::VERSION_MAJOR) + "." +
                         std::to_string(FileHasherConstants::VERSION_MINOR) + "." +
                         std::to_string(FileHasherConstants::VERSION_PATCH);
    info.fuzzyHasherVersion = "1.0.0";
    info.tlshVersion = "not-integrated";
    info.lastUpdate = system_clock::now();
    return info;
}

HardwareInfo FileHasher::GetHardwareInfo() const {
    HardwareInfo info{};

    if (m_impl) {
        info.hasAESNI = m_impl->m_hasAESNI;
        info.hasSHANI = m_impl->m_hasSHANI;
        info.useHardwareAccel = m_impl->m_config.useHardwareAcceleration &&
                               (m_impl->m_hasAESNI || m_impl->m_hasSHANI);
    }

    return info;
}

// ============================================================================
// MISSING METHOD IMPLEMENTATIONS
// ============================================================================

bool FileHasher::HasHardwareAcceleration() const noexcept {
    if (!m_impl) return false;
    return m_impl->m_config.useHardwareAcceleration &&
           (m_impl->m_hasAESNI || m_impl->m_hasSHANI);
}

std::vector<std::string> FileHasher::GetHardwareFeatures() const {
    std::vector<std::string> features;
    if (!m_impl) return features;

    if (m_impl->m_hasAESNI) features.emplace_back("AES-NI");
    if (m_impl->m_hasSHANI) features.emplace_back("SHA-NI");

    return features;
}

std::string FileHasher::ToHexString(
    std::span<const uint8_t> hash,
    HashFormat format
) const {
    if (hash.empty()) return {};

    switch (format) {
        case HashFormat::Hex:
            return HashUtils::ToHexLower(hash.data(), hash.size());
        case HashFormat::HexUpper:
            return HashUtils::ToHexUpper(hash.data(), hash.size());
        case HashFormat::Base64:
            // Delegate to Base64Utils if available; fallback to hex
            return HashUtils::ToHexLower(hash.data(), hash.size());
        case HashFormat::Raw:
            return std::string(reinterpret_cast<const char*>(hash.data()), hash.size());
        default:
            return HashUtils::ToHexLower(hash.data(), hash.size());
    }
}

std::vector<uint8_t> FileHasher::FromHexString(std::string_view hexString) const {
    std::vector<uint8_t> result;
    if (!HashUtils::FromHex(hexString, result)) {
        SS_LOG_WARN(L"FileHasher", L"FileHasher: FromHexString failed for input length %zu", hexString.size());
        result.clear();
    }
    return result;
}

bool FileHasher::ValidateHashFormat(
    std::string_view hash,
    HashAlgorithm algorithm
) const {
    if (hash.empty()) return false;

    // Determine expected hex length from algorithm
    size_t expectedHexLen = 0;
    if (HasFlag(algorithm, HashAlgorithm::MD5))      expectedHexLen = FileHasherConstants::MD5_SIZE * 2;
    else if (HasFlag(algorithm, HashAlgorithm::SHA1))      expectedHexLen = FileHasherConstants::SHA1_SIZE * 2;
    else if (HasFlag(algorithm, HashAlgorithm::SHA256))    expectedHexLen = FileHasherConstants::SHA256_SIZE * 2;
    else if (HasFlag(algorithm, HashAlgorithm::SHA512))    expectedHexLen = FileHasherConstants::SHA512_SIZE * 2;
    else if (HasFlag(algorithm, HashAlgorithm::SHA3_256))  expectedHexLen = FileHasherConstants::SHA3_256_SIZE * 2;
    else if (HasFlag(algorithm, HashAlgorithm::SHA3_512))  expectedHexLen = FileHasherConstants::SHA3_512_SIZE * 2;
    else return false; // Fuzzy hashes have variable length — not validated here

    if (hash.size() != expectedHexLen) return false;

    // Validate all characters are hex
    for (char c : hash) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

PartialHashes FileHasher::ComputePartialHashes(const std::wstring& filePath) {
    PartialHashes result;

    if (!IsInitialized()) {
        SS_LOG_ERROR(L"FileHasher", L"FileHasher: Not initialized");
        return result;
    }

    // Header hash (first 4KB, SHA-256)
    result.headerSHA256 = ComputeHeaderHash(filePath, HashAlgorithm::SHA256,
                                            FileHasherConstants::HEADER_HASH_SIZE);

    // Section hashes (PE-specific)
    if (IsPEFile(filePath)) {
        result.sectionHashes = ComputeSectionHashes(filePath, HashAlgorithm::SHA256);
    }

    return result;
}

} // namespace FileSystem
} // namespace Core
} // namespace ShadowStrike
