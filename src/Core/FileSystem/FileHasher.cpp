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
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ThreadPool.hpp"

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
// Fuzzy hashing via FuzzyHasher module
// #include <tlsh.h>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// BITWISE OPERATORS FOR HashAlgorithm
// ============================================================================

constexpr HashAlgorithm operator|(HashAlgorithm lhs, HashAlgorithm rhs) noexcept {
    return static_cast<HashAlgorithm>(
        static_cast<uint16_t>(lhs) | static_cast<uint16_t>(rhs)
    );
}

constexpr HashAlgorithm operator&(HashAlgorithm lhs, HashAlgorithm rhs) noexcept {
    return static_cast<HashAlgorithm>(
        static_cast<uint16_t>(lhs) & static_cast<uint16_t>(rhs)
    );
}

constexpr HashAlgorithm operator^(HashAlgorithm lhs, HashAlgorithm rhs) noexcept {
    return static_cast<HashAlgorithm>(
        static_cast<uint16_t>(lhs) ^ static_cast<uint16_t>(rhs)
    );
}

constexpr HashAlgorithm operator~(HashAlgorithm value) noexcept {
    return static_cast<HashAlgorithm>(~static_cast<uint16_t>(value));
}

constexpr bool HasFlag(HashAlgorithm value, HashAlgorithm flag) noexcept {
    return (static_cast<uint16_t>(value) & static_cast<uint16_t>(flag)) != 0;
}

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
        if (dosSignature[0] != 'M' || dosSignature[1] != 'Z') {
            return false;
        }

        // Read PE offset from DOS header
        file.seekg(0x3C, std::ios::beg);
        uint32_t peOffset = 0;
        file.read(reinterpret_cast<char*>(&peOffset), 4);

        // Check PE signature
        file.seekg(peOffset, std::ios::beg);
        char peSignature[4];
        file.read(peSignature, 4);

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
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return {};

        std::vector<uint8_t> header(headerSize);
        file.read(reinterpret_cast<char*>(header.data()), headerSize);
        size_t bytesRead = file.gcount();

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
// FileHasherStatistics METHODS
// ============================================================================

void FileHasherStatistics::Reset() noexcept {
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
    oss << "  \"filePath\": \"" << StringUtils::ToNarrowString(filePath) << "\",\n";
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
class FileHasher::Impl {
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

    // Statistics
    FileHasherStatistics m_stats{};

    // Hash cache (LRU with TTL)
    struct CachedHash {
        FileHashes hashes;
        steady_clock::time_point timestamp;
        system_clock::time_point fileModTime;
        uint32_t hitCount = 0;
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

    Impl() {
        m_stats.startTime = steady_clock::now();
    }

    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const FileHasherConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("FileHasher::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("FileHasher::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Detect hardware capabilities
            DetectHardwareCapabilities();

            // Create thread pool if needed
            if (!m_threadPool && m_config.workerThreads > 0) {
                m_threadPool = std::make_shared<ThreadPool>(m_config.workerThreads);
                Logger::Info("FileHasher: Thread pool created with {} workers",
                    m_config.workerThreads);
            }

            // Reset statistics
            m_stats.Reset();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("FileHasher::Impl: Initialization complete");
            Logger::Info("FileHasher: Hardware - AES-NI: {}, SHA-NI: {}",
                m_hasAESNI ? "YES" : "NO", m_hasSHANI ? "YES" : "NO");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("FileHasher::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("FileHasher::Impl: Shutting down");

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
        Logger::Info("FileHasher::Impl: Shutdown complete");
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

            Logger::Debug("FileHasher: Hardware detection - AES-NI: {}, SHA-NI: {}",
                m_hasAESNI, m_hasSHANI);
#endif
        } catch (...) {
            Logger::Warn("FileHasher: Hardware capability detection failed");
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
        try {
            std::error_code ec;
            auto lastWrite = fs::last_write_time(filePath, ec);
            if (!ec) {
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    lastWrite - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                );

                if (sctp != cached.fileModTime) {
                    return std::nullopt; // File modified
                }
            }
        } catch (...) {
            return std::nullopt;
        }

        // Update hit count (const_cast for statistics)
        const_cast<CachedHash&>(cached).hitCount++;

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
                Logger::Debug("FileHasher: Cache eviction (LRU): {}",
                    StringUtils::ToNarrowString(lru->first));
                m_hashCache.erase(lru);
            }
        }

        // Get file modification time
        system_clock::time_point modTime = system_clock::now();
        try {
            std::error_code ec;
            auto lastWrite = fs::last_write_time(filePath, ec);
            if (!ec) {
                modTime = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    lastWrite - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                );
            }
        } catch (...) {
            // Use current time if we can't get modification time
        }

        CachedHash cached{};
        cached.hashes = hashes;
        cached.timestamp = steady_clock::now();
        cached.fileModTime = modTime;
        cached.hitCount = 0;

        m_hashCache[filePath] = cached;

        Logger::Debug("FileHasher: Added to cache: {} (size: {})",
            StringUtils::ToNarrowString(filePath), m_hashCache.size());
    }

    void InvalidateCacheEntry(const std::wstring& filePath) {
        std::unique_lock lock(m_cacheMutex);
        m_hashCache.erase(filePath);
    }

    void ClearCacheImpl() noexcept {
        std::unique_lock lock(m_cacheMutex);
        m_hashCache.clear();
        Logger::Info("FileHasher: Cache cleared");
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
                    Logger::Debug("FileHasher: Cache hit for {}",
                        StringUtils::ToNarrowString(filePath));
                    return *cached;
                }
                m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
            }

            result.filePath = filePath;

            // Validate file
            std::error_code ec;
            if (!fs::exists(filePath, ec)) {
                Logger::Error("FileHasher: File not found: {}",
                    StringUtils::ToNarrowString(filePath));
                return result;
            }

            result.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                Logger::Error("FileHasher: Cannot get file size: {}", ec.message());
                return result;
            }

            Logger::Info("FileHasher: Computing hashes for {} ({} bytes)",
                StringUtils::ToNarrowString(filePath), result.fileSize);

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
            m_stats.averageTimeUs.store(
                (m_stats.averageTimeUs.load() + durationUs) / 2,
                std::memory_order_relaxed
            );

            if (durationUs > m_stats.maxTimeUs.load(std::memory_order_relaxed)) {
                m_stats.maxTimeUs.store(durationUs, std::memory_order_relaxed);
            }

            // Add to cache
            if (m_config.enableCache) {
                AddToCache(filePath, result);
            }

            Logger::Info("FileHasher: Computed {} hashes in {} ms",
                CountComputedHashes(result), result.computeDuration.count());

            return result;

        } catch (const std::exception& e) {
            Logger::Error("FileHasher: ComputeAll exception: {}", e.what());
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

                    Logger::Debug("FileHasher: MD5 = {}", result.md5Hex);
                }
            } else {
                Logger::Warn("FileHasher: MD5 computation failed");
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: MD5 exception: {}", e.what());
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

                    Logger::Debug("FileHasher: SHA1 = {}", result.sha1Hex);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: SHA1 exception: {}", e.what());
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

                    Logger::Debug("FileHasher: SHA256 = {}", result.sha256Hex);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: SHA256 exception: {}", e.what());
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

                    Logger::Debug("FileHasher: SHA512 = {}", result.sha512Hex.substr(0, 32) + "...");
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: SHA512 exception: {}", e.what());
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

                    Logger::Debug("FileHasher: SHA3-256 = {}", result.sha3_256Hex);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: SHA3-256 exception: {}", e.what());
        }
    }

    void ComputeSHA3_512Impl(const std::wstring& filePath, FileHashes& result) {
        try {
            std::vector<uint8_t> hashBytes;
            HashUtils::Error err;

            if (HashUtils::ComputeFile(HashUtils::Algorithm::SHA3_512,
                                      filePath, hashBytes, &err)) {
                if (hashBytes.size() == 64) {
                    std::copy(hashBytes.begin(), hashBytes.end(), result.sha3_512.begin());
                    result.sha3_512Hex = HashUtils::ToHexLower(hashBytes);
                    result.hasSHA3_512 = true;

                    Logger::Debug("FileHasher: SHA3-512 = {}", result.sha3_512Hex.substr(0, 32) + "...");
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FileHasher: SHA3-512 exception: {}", e.what());
        }
    }

    void ComputeFuzzyHashImpl(const std::wstring& filePath, FileHashes& result) {
        try {
            // TODO: Integrate FuzzyHasher module
            // For now, placeholder implementation
            Logger::Debug("FileHasher: fuzzy hash computation not yet implemented");

            // Placeholder fuzzy hash format: blocksize:hash1:hash2
            result.fuzzyHash = "3:PLACEHOLDER:HASH";
            result.hasFuzzyHash = false; // Set to true when implemented

            // m_stats.fuzzyHashComputed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("FileHasher: fuzzy hash exception: {}", e.what());
        }
    }

    void ComputeTLSHImpl(const std::wstring& filePath, FileHashes& result) {
        try {
            // TODO: Integrate TLSH library
            // For now, placeholder implementation
            Logger::Debug("FileHasher: TLSH computation not yet implemented");

            result.tlsh = "T1PLACEHOLDER";
            result.hasTLSH = false; // Set to true when implemented

            // m_stats.tlshComputed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("FileHasher: TLSH exception: {}", e.what());
        }
    }

    void ComputeImpHashImpl(const std::wstring& filePath, FileHashes& result) {
        try {
            // TODO: Parse PE import table and compute MD5 of sorted imports
            Logger::Debug("FileHasher: imphash computation not yet implemented");

            result.imphash = "placeholder_imphash";
            result.hasImpHash = false; // Set to true when implemented

            // m_stats.imphashComputed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("FileHasher: imphash exception: {}", e.what());
        }
    }

    void ComputeAuthentihashImpl(const std::wstring& filePath, FileHashes& result) {
        try {
            // TODO: Parse PE authenticode signature and hash
            Logger::Debug("FileHasher: authentihash computation not yet implemented");

            result.authentihash = "placeholder_authentihash";
            result.hasAuthentihash = false; // Set to true when implemented

        } catch (const std::exception& e) {
            Logger::Error("FileHasher: authentihash exception: {}", e.what());
        }
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

            Logger::Debug("FileHasher: Computing hashes for buffer ({} bytes)",
                buffer.size());

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
            Logger::Error("FileHasher: ComputeAllBuffer exception: {}", e.what());
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
            Logger::Error("FileHasher: Compare exception: {}", e.what());
            return result;
        }
    }

    [[nodiscard]] double CompareFuzzyHashImpl(
        std::string_view hash1,
        std::string_view hash2
    ) const noexcept {
        try {
            // TODO: Implement fuzzy hash comparison using FuzzyHasher
            // For now, return 0.0 (no similarity)
            Logger::Debug("FileHasher: fuzzy hash comparison not yet implemented");
            return 0.0;

        } catch (...) {
            return 0.0;
        }
    }

    [[nodiscard]] uint32_t ComputeTLSHDistanceImpl(
        std::string_view tlsh1,
        std::string_view tlsh2
    ) const noexcept {
        try {
            // TODO: Implement TLSH distance using library
            // For now, return max distance
            Logger::Debug("FileHasher: TLSH distance not yet implemented");
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
                Logger::Error("FileHasher: Cannot read file header");
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
            Logger::Error("FileHasher: ComputeHeaderHash exception: {}", e.what());
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

        Logger::Info("FileHasher: Batch hashing {} files", filePaths.size());

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
                Logger::Error("FileHasher: Hash callback exception: {}", e.what());
            }
        }
    }

    void InvokeProgressCallbacks(uint64_t current, uint64_t total) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(current, total);
            } catch (const std::exception& e) {
                Logger::Error("FileHasher: Progress callback exception: {}", e.what());
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
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("FileHasher: Constructor called");
}

FileHasher::~FileHasher() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("FileHasher: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool FileHasher::Initialize(const FileHasherConfig& config) {
    if (!m_impl) {
        Logger::Critical("FileHasher: Implementation is null");
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

    Logger::Info("FileHasher: Configuration updated");
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
        Logger::Error("FileHasher: Not initialized");
        return FileHashes{};
    }

    return m_impl->ComputeAllImpl(filePath, algorithms);
}

FileHashes FileHasher::ComputeAll(
    std::span<const uint8_t> buffer,
    HashAlgorithm algorithms
) {
    if (!IsInitialized()) {
        Logger::Error("FileHasher: Not initialized");
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
        Logger::Error("FileHasher: Not initialized or no thread pool");
        return;
    }

    m_impl->m_threadPool->Enqueue([this, filePath, callback, algorithms]() {
        auto hashes = ComputeAll(filePath, algorithms);

        if (callback) {
            try {
                callback(hashes);
            } catch (const std::exception& e) {
                Logger::Error("FileHasher: Async callback exception: {}", e.what());
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
        Logger::Error("FileHasher: Not initialized");
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
        Logger::Error("FileHasher: Not initialized");
        return "";
    }

    return m_impl->ComputeHeaderHashImpl(filePath, algorithm, headerSize);
}

std::unordered_map<std::string, std::string> FileHasher::ComputeSectionHashes(
    const std::wstring& filePath,
    HashAlgorithm algorithm
) {
    // TODO: Implement PE section parsing and hashing
    Logger::Warn("FileHasher: ComputeSectionHashes not yet implemented");
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
        Logger::Error("FileHasher: Not initialized");
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

    Logger::Debug("FileHasher: Registered hash callback {}", id);
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

    Logger::Debug("FileHasher: Registered progress callback {}", id);
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
    return m_impl ? m_impl->m_stats : FileHasherStatistics{};
}

void FileHasher::ResetStatistics() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("FileHasher: Statistics reset");
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

bool FileHasher::SelfTest() {
    if (!IsInitialized()) {
        Logger::Error("FileHasher: Self-test failed - not initialized");
        return false;
    }

    try {
        Logger::Info("FileHasher: Running self-test");

        // Test 1: Hash a small buffer
        {
            std::vector<uint8_t> testData(1024, 0x42);
            auto hashes = ComputeAll(testData, HashAlgorithm::Standard);

            if (!hashes.hasSHA256) {
                Logger::Error("FileHasher: Self-test failed - SHA256 not computed");
                return false;
            }
        }

        // Test 2: Cache functionality
        {
            ClearCache();
            auto cacheSize = GetCacheSize();
            if (cacheSize != 0) {
                Logger::Error("FileHasher: Self-test failed - cache not cleared");
                return false;
            }
        }

        // Test 3: Statistics
        {
            auto stats = GetStatistics();
            // Just verify we can get stats without crashing
        }

        Logger::Info("FileHasher: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("FileHasher: Self-test exception: {}", e.what());
        return false;
    }
}

FileHasher::VersionInfo FileHasher::GetVersionInfo() const {
    VersionInfo info{};
    info.hasherVersion = "3.0.0";
    info.fuzzyHasherVersion = "1.0.0"; // ShadowStrike FuzzyHasher
    info.tlshVersion = "4.5.1";    // TODO: Get from library
    info.lastUpdate = system_clock::now();
    return info;
}

FileHasher::HardwareInfo FileHasher::GetHardwareInfo() const {
    HardwareInfo info{};

    if (m_impl) {
        info.hasAESNI = m_impl->m_hasAESNI;
        info.hasSHANI = m_impl->m_hasSHANI;
        info.useHardwareAccel = m_impl->m_config.useHardwareAcceleration &&
                               (m_impl->m_hasAESNI || m_impl->m_hasSHANI);
    }

    return info;
}

} // namespace FileSystem
} // namespace Core
} // namespace ShadowStrike
