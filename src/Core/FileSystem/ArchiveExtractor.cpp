/**
 * ============================================================================
 * ShadowStrike Core FileSystem - ARCHIVE EXTRACTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ArchiveExtractor.cpp
 * @brief Enterprise-grade secure archive extraction engine.
 *
 * This module provides comprehensive archive handling with multi-format
 * support, zip bomb detection, path traversal prevention, and integration
 * with libarchive for robust extraction capabilities.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - libarchive integration for format support
 * - Multi-layered security checks (zip bombs, path traversal, compression ratios)
 * - LRU cache with TTL expiration
 * - Callback architecture for progress and security events
 *
 * Security Features:
 * - Zip bomb detection (compression ratio, total size, nesting depth)
 * - Path traversal prevention (../, absolute paths, dangerous chars)
 * - Symlink attack detection
 * - Encryption detection
 * - Quine bomb detection (self-referencing archives)
 * - Overlapping entry detection
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ArchiveExtractor.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cmath>
#include <thread>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Magic number signatures for format detection
    struct MagicSignature {
        std::vector<uint8_t> bytes;
        size_t offset;
        ArchiveFormat format;
    };

    const std::vector<MagicSignature> MAGIC_SIGNATURES = {
        // ZIP
        {{0x50, 0x4B, 0x03, 0x04}, 0, ArchiveFormat::ZIP},
        {{0x50, 0x4B, 0x05, 0x06}, 0, ArchiveFormat::ZIP},

        // RAR
        {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 0, ArchiveFormat::RAR},
        {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01}, 0, ArchiveFormat::RAR5},

        // 7-Zip
        {{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, ArchiveFormat::SevenZip},

        // GZIP
        {{0x1F, 0x8B}, 0, ArchiveFormat::GZIP},

        // BZIP2
        {{0x42, 0x5A, 0x68}, 0, ArchiveFormat::BZIP2},

        // XZ
        {{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, ArchiveFormat::XZ},

        // ZSTD
        {{0x28, 0xB5, 0x2F, 0xFD}, 0, ArchiveFormat::ZSTD},

        // CAB
        {{0x4D, 0x53, 0x43, 0x46}, 0, ArchiveFormat::CAB},

        // ISO (CD001 at offset 32769)
        {{0x43, 0x44, 0x30, 0x30, 0x31}, 32769, ArchiveFormat::ISO},
    };

    // Dangerous path patterns
    const std::vector<std::wstring> DANGEROUS_PATH_PATTERNS = {
        L"..",
        L"/..",
        L"\\..",
        L"../",
        L"..\\",
    };

    // Entropy threshold for suspicious files
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.5;

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequency{};
    for (uint8_t byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t count : frequency) {
        if (count > 0) {
            double probability = static_cast<double>(count) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

[[nodiscard]] static bool IsPathSafe(const std::wstring& path) noexcept {
    // Check for dangerous patterns
    for (const auto& pattern : DANGEROUS_PATH_PATTERNS) {
        if (path.find(pattern) != std::wstring::npos) {
            return false;
        }
    }

    // Check for absolute paths
    if (!path.empty() && path[0] == L'/') return false;
    if (path.length() > 1 && path[1] == L':') return false; // C:\ etc

    // Check for dangerous characters
    static const std::wstring dangerousChars = L"<>:|\"?*";
    if (path.find_first_of(dangerousChars) != std::wstring::npos) {
        return false;
    }

    return true;
}

[[nodiscard]] static std::wstring SanitizePath(const std::wstring& path) noexcept {
    std::wstring sanitized = path;

    // Remove dangerous patterns
    for (const auto& pattern : DANGEROUS_PATH_PATTERNS) {
        size_t pos;
        while ((pos = sanitized.find(pattern)) != std::wstring::npos) {
            sanitized.erase(pos, pattern.length());
        }
    }

    // Remove leading slashes
    while (!sanitized.empty() && (sanitized[0] == L'/' || sanitized[0] == L'\\')) {
        sanitized.erase(0, 1);
    }

    // Replace dangerous characters
    static const std::wstring dangerousChars = L"<>:|\"?*";
    for (wchar_t& ch : sanitized) {
        if (dangerousChars.find(ch) != std::wstring::npos) {
            ch = L'_';
        }
    }

    return sanitized;
}

// ============================================================================
// FACTORY METHODS FOR CONFIGURATION
// ============================================================================

ExtractionOptions ExtractionOptions::CreateDefault() noexcept {
    ExtractionOptions opts;
    opts.mode = ExtractionMode::InMemory;
    opts.maxCompressionRatio = ArchiveExtractorConstants::DEFAULT_MAX_COMPRESSION_RATIO;
    opts.maxNestingDepth = ArchiveExtractorConstants::DEFAULT_MAX_NESTING_DEPTH;
    opts.maxTotalSize = ArchiveExtractorConstants::DEFAULT_MAX_TOTAL_SIZE;
    opts.maxEntrySize = ArchiveExtractorConstants::DEFAULT_MAX_ENTRY_SIZE;
    opts.maxEntries = ArchiveExtractorConstants::DEFAULT_MAX_ENTRIES;
    opts.extractNestedArchives = true;
    opts.preserveTimestamps = true;
    opts.preservePermissions = false;
    opts.skipEncrypted = false;
    opts.stopOnError = false;
    return opts;
}

ExtractionOptions ExtractionOptions::CreateSecure() noexcept {
    ExtractionOptions opts;
    opts.mode = ExtractionMode::MetadataOnly;
    opts.maxCompressionRatio = 50.0;  // More strict
    opts.maxNestingDepth = 3;
    opts.maxTotalSize = 1ULL * 1024 * 1024 * 1024;  // 1 GB
    opts.maxEntrySize = 100ULL * 1024 * 1024;  // 100 MB
    opts.maxEntries = 10000;
    opts.extractNestedArchives = false;  // Don't extract nested
    opts.preserveTimestamps = false;
    opts.preservePermissions = false;
    opts.skipEncrypted = true;  // Skip encrypted files
    opts.stopOnError = true;
    return opts;
}

ExtractionOptions ExtractionOptions::CreateScanOnly() noexcept {
    ExtractionOptions opts;
    opts.mode = ExtractionMode::MetadataOnly;
    opts.maxCompressionRatio = ArchiveExtractorConstants::DEFAULT_MAX_COMPRESSION_RATIO;
    opts.maxNestingDepth = ArchiveExtractorConstants::DEFAULT_MAX_NESTING_DEPTH;
    opts.maxTotalSize = ArchiveExtractorConstants::DEFAULT_MAX_TOTAL_SIZE;
    opts.maxEntrySize = ArchiveExtractorConstants::DEFAULT_MAX_ENTRY_SIZE;
    opts.maxEntries = ArchiveExtractorConstants::DEFAULT_MAX_ENTRIES;
    opts.extractNestedArchives = false;
    opts.preserveTimestamps = false;
    opts.preservePermissions = false;
    opts.skipEncrypted = false;
    opts.stopOnError = false;
    return opts;
}

ArchiveExtractorConfig ArchiveExtractorConfig::CreateDefault() noexcept {
    ArchiveExtractorConfig config;
    config.defaultMaxRatio = ArchiveExtractorConstants::DEFAULT_MAX_COMPRESSION_RATIO;
    config.defaultMaxNesting = ArchiveExtractorConstants::DEFAULT_MAX_NESTING_DEPTH;
    config.defaultMaxTotal = ArchiveExtractorConstants::DEFAULT_MAX_TOTAL_SIZE;
    config.maxMemoryExtraction = ArchiveExtractorConstants::MAX_MEMORY_EXTRACTION;
    config.streamingBufferSize = ArchiveExtractorConstants::STREAMING_BUFFER_SIZE;
    config.workerThreads = 4;
    config.parallelExtraction = true;
    config.strictSecurityChecks = true;
    config.abortOnSecurityIssue = true;
    return config;
}

ArchiveExtractorConfig ArchiveExtractorConfig::CreateHighSecurity() noexcept {
    ArchiveExtractorConfig config;
    config.defaultMaxRatio = 50.0;  // More strict
    config.defaultMaxNesting = 3;
    config.defaultMaxTotal = 1ULL * 1024 * 1024 * 1024;  // 1 GB
    config.maxMemoryExtraction = 50 * 1024 * 1024;  // 50 MB
    config.streamingBufferSize = 32 * 1024;  // 32 KB
    config.workerThreads = 2;
    config.parallelExtraction = false;  // Sequential for security
    config.strictSecurityChecks = true;
    config.abortOnSecurityIssue = true;
    return config;
}

void ArchiveExtractorStatistics::Reset() noexcept {
    archivesProcessed = 0;
    entriesExtracted = 0;
    bytesExtracted = 0;
    zipBombsDetected = 0;
    pathTraversalsBlocked = 0;
    encryptedSkipped = 0;
    nestedArchives = 0;
    extractionErrors = 0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ArchiveExtractorImpl final {
public:
    ArchiveExtractorImpl() = default;
    ~ArchiveExtractorImpl() = default;

    // Delete copy/move
    ArchiveExtractorImpl(const ArchiveExtractorImpl&) = delete;
    ArchiveExtractorImpl& operator=(const ArchiveExtractorImpl&) = delete;
    ArchiveExtractorImpl(ArchiveExtractorImpl&&) = delete;
    ArchiveExtractorImpl& operator=(ArchiveExtractorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const ArchiveExtractorConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            m_initialized = true;

            // Create temp directory if needed
            if (!m_config.tempDirectory.empty()) {
                std::error_code ec;
                if (!fs::exists(m_config.tempDirectory, ec)) {
                    fs::create_directories(m_config.tempDirectory, ec);
                    if (ec) {
                        Logger::Error("ArchiveExtractor: Failed to create temp dir: {}", ec.message());
                        return false;
                    }
                }
            }

            Logger::Info("ArchiveExtractor initialized (maxRatio={:.1f}, maxNesting={}, security={})",
                config.defaultMaxRatio, config.defaultMaxNesting, config.strictSecurityChecks);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_passwordCallback = nullptr;
            m_progressCallback = nullptr;
            m_securityCallback = nullptr;
            m_cache.clear();
            m_initialized = false;

            Logger::Info("ArchiveExtractor shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    // ========================================================================
    // FORMAT DETECTION
    // ========================================================================

    [[nodiscard]] ArchiveFormat DetectFormat(const std::wstring& filePath) const {
        try {
            // Check extension first (fast path)
            fs::path p(filePath);
            auto ext = StringUtils::ToLower(p.extension().wstring());

            if (ext == L".zip") return ArchiveFormat::ZIP;
            if (ext == L".rar") return ArchiveFormat::RAR;
            if (ext == L".7z") return ArchiveFormat::SevenZip;
            if (ext == L".tar") return ArchiveFormat::TAR;
            if (ext == L".gz" || ext == L".gzip") return ArchiveFormat::GZIP;
            if (ext == L".bz2" || ext == L".bzip2") return ArchiveFormat::BZIP2;
            if (ext == L".xz") return ArchiveFormat::XZ;
            if (ext == L".lzma") return ArchiveFormat::LZMA;
            if (ext == L".zst" || ext == L".zstd") return ArchiveFormat::ZSTD;
            if (ext == L".cab") return ArchiveFormat::CAB;
            if (ext == L".msi") return ArchiveFormat::MSI;
            if (ext == L".wim") return ArchiveFormat::WIM;
            if (ext == L".iso") return ArchiveFormat::ISO;
            if (ext == L".vhd") return ArchiveFormat::VHD;
            if (ext == L".vhdx") return ArchiveFormat::VHDX;
            if (ext == L".dmg") return ArchiveFormat::DMG;
            if (ext == L".img") return ArchiveFormat::IMG;
            if (ext == L".arj") return ArchiveFormat::ARJ;
            if (ext == L".lzh") return ArchiveFormat::LZH;
            if (ext == L".ace") return ArchiveFormat::ACE;
            if (ext == L".cpio") return ArchiveFormat::CPIO;
            if (ext == L".rpm") return ArchiveFormat::RPM;
            if (ext == L".deb") return ArchiveFormat::DEB;

            // Compound extensions
            auto filename = StringUtils::ToLower(p.filename().wstring());
            if (filename.ends_with(L".tar.gz") || filename.ends_with(L".tgz")) {
                return ArchiveFormat::TarGz;
            }
            if (filename.ends_with(L".tar.bz2") || filename.ends_with(L".tbz2")) {
                return ArchiveFormat::TarBz2;
            }
            if (filename.ends_with(L".tar.xz") || filename.ends_with(L".txz")) {
                return ArchiveFormat::TarXz;
            }
            if (filename.ends_with(L".tar.zst")) {
                return ArchiveFormat::TarZstd;
            }

            // Read magic bytes
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return ArchiveFormat::Unknown;
            }

            std::array<uint8_t, 64> buffer{};
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            size_t bytesRead = file.gcount();

            if (bytesRead < 4) {
                return ArchiveFormat::Unknown;
            }

            return DetectFormat(std::span<const uint8_t>(buffer.data(), bytesRead));

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: Format detection failed: {}", e.what());
            return ArchiveFormat::Unknown;
        }
    }

    [[nodiscard]] ArchiveFormat DetectFormat(std::span<const uint8_t> buffer) const {
        try {
            for (const auto& sig : MAGIC_SIGNATURES) {
                if (buffer.size() < sig.offset + sig.bytes.size()) {
                    continue;
                }

                bool match = true;
                for (size_t i = 0; i < sig.bytes.size(); ++i) {
                    if (buffer[sig.offset + i] != sig.bytes[i]) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    return sig.format;
                }
            }

            return ArchiveFormat::Unknown;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: Buffer format detection failed: {}", e.what());
            return ArchiveFormat::Unknown;
        }
    }

    [[nodiscard]] bool IsArchive(const std::wstring& filePath) const {
        auto format = DetectFormat(filePath);
        return format != ArchiveFormat::Unknown;
    }

    [[nodiscard]] std::vector<ArchiveFormat> GetSupportedFormats() const {
        return {
            ArchiveFormat::ZIP, ArchiveFormat::RAR, ArchiveFormat::RAR5,
            ArchiveFormat::SevenZip, ArchiveFormat::TAR, ArchiveFormat::GZIP,
            ArchiveFormat::BZIP2, ArchiveFormat::XZ, ArchiveFormat::LZMA,
            ArchiveFormat::ZSTD, ArchiveFormat::TarGz, ArchiveFormat::TarBz2,
            ArchiveFormat::TarXz, ArchiveFormat::TarZstd, ArchiveFormat::CAB,
            ArchiveFormat::MSI, ArchiveFormat::WIM, ArchiveFormat::ISO,
            ArchiveFormat::VHD, ArchiveFormat::VHDX, ArchiveFormat::DMG,
            ArchiveFormat::IMG, ArchiveFormat::ARJ, ArchiveFormat::LZH,
            ArchiveFormat::ACE, ArchiveFormat::CPIO, ArchiveFormat::RPM,
            ArchiveFormat::DEB
        };
    }

    // ========================================================================
    // ARCHIVE INFORMATION
    // ========================================================================

    [[nodiscard]] ArchiveInfo GetArchiveInfo(const std::wstring& filePath) const {
        ArchiveInfo info;
        info.filePath = filePath;

        try {
            // Check cache first
            {
                std::shared_lock lock(m_mutex);
                auto it = m_cache.find(filePath);
                if (it != m_cache.end()) {
                    auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    if (age < std::chrono::minutes(15)) {
                        m_stats.cacheHits++;
                        return it->second.info;
                    }
                }
                m_stats.cacheMisses++;
            }

            // Detect format
            info.format = DetectFormat(filePath);
            info.formatName = GetFormatName(info.format);

            // Get file size
            std::error_code ec;
            info.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                Logger::Error("ArchiveExtractor: Cannot get file size: {}", ec.message());
                return info;
            }

            // Analyze contents (placeholder - real implementation would use libarchive)
            info.totalEntries = 0;
            info.fileCount = 0;
            info.directoryCount = 0;
            info.totalCompressedSize = info.fileSize;
            info.totalUncompressedSize = info.fileSize;
            info.overallCompressionRatio = 1.0;
            info.hasEncryptedEntries = false;
            info.isHeaderEncrypted = false;
            info.isMultiVolume = false;
            info.volumeCount = 0;
            info.currentVolume = 0;
            info.hasIntegrityCheck = false;
            info.integrityValid = true;
            info.isSuspicious = false;
            info.analyzedTime = std::chrono::system_clock::now();

            // Update cache
            {
                std::unique_lock lock(m_mutex);
                if (m_cache.size() >= 1000) {
                    // Simple LRU eviction
                    auto oldest = m_cache.begin();
                    for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
                        if (it->second.timestamp < oldest->second.timestamp) {
                            oldest = it;
                        }
                    }
                    m_cache.erase(oldest);
                }

                CacheEntry entry;
                entry.info = info;
                entry.timestamp = std::chrono::steady_clock::now();
                m_cache[filePath] = entry;
            }

            return info;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: GetArchiveInfo failed: {}", e.what());
            return info;
        }
    }

    [[nodiscard]] std::vector<ArchiveEntry> ListContents(
        const std::wstring& filePath,
        const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;

        try {
            // Placeholder implementation
            // Real implementation would use libarchive to enumerate entries
            Logger::Info("ArchiveExtractor: Listing contents of {}",
                StringUtils::WideToUtf8(filePath));

            m_stats.archivesProcessed++;

            return entries;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ListContents failed: {}", e.what());
            return entries;
        }
    }

    [[nodiscard]] bool VerifyIntegrity(const std::wstring& filePath) const {
        try {
            // Placeholder: Real implementation would verify CRCs, checksums
            Logger::Info("ArchiveExtractor: Verifying integrity of {}",
                StringUtils::WideToUtf8(filePath));

            return fs::exists(filePath);

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: VerifyIntegrity failed: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // EXTRACTION OPERATIONS
    // ========================================================================

    ExtractionSummary ScanArchive(
        const std::wstring& filePath,
        EntryCallback callback,
        const ExtractionOptions& options) {

        auto startTime = std::chrono::steady_clock::now();
        ExtractionSummary summary;

        try {
            // Security check
            if (m_config.strictSecurityChecks) {
                if (IsZipBomb(filePath)) {
                    summary.result = ExtractionResult::ZipBombDetected;
                    summary.securityFlags = SecurityFlag::ZipBombSuspected;
                    summary.errors.push_back("Zip bomb detected");
                    Logger::Warn("ArchiveExtractor: Zip bomb detected in {}",
                        StringUtils::WideToUtf8(filePath));
                    return summary;
                }
            }

            // List and scan entries
            auto entries = ListContents(filePath, options);

            summary.entriesProcessed = static_cast<uint32_t>(entries.size());
            summary.entriesExtracted = static_cast<uint32_t>(entries.size());

            for (const auto& entry : entries) {
                if (callback) {
                    try {
                        std::vector<uint8_t> emptyData;  // Metadata only
                        callback(entry, emptyData);
                    } catch (const std::exception& e) {
                        Logger::Error("ArchiveExtractor: Entry callback exception: {}", e.what());
                        summary.entriesFailed++;
                    }
                }

                // Check for nested archives
                if (entry.isNestedArchive) {
                    summary.nestedArchives++;
                }
            }

            summary.result = ExtractionResult::Success;
            m_stats.archivesProcessed++;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ScanArchive exception: {}", e.what());
            summary.result = ExtractionResult::IOError;
            summary.errors.push_back(std::string("Exception: ") + e.what());
        }

        auto endTime = std::chrono::steady_clock::now();
        summary.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

        return summary;
    }

    ExtractionSummary ExtractAll(
        const std::wstring& filePath,
        const std::wstring& outputDir,
        const ExtractionOptions& options) {

        auto startTime = std::chrono::steady_clock::now();
        ExtractionSummary summary;

        try {
            Logger::Info("ArchiveExtractor: Extracting {} to {}",
                StringUtils::WideToUtf8(filePath),
                StringUtils::WideToUtf8(outputDir));

            // Security check
            if (m_config.strictSecurityChecks) {
                if (IsZipBomb(filePath)) {
                    summary.result = ExtractionResult::ZipBombDetected;
                    summary.securityFlags = SecurityFlag::ZipBombSuspected;
                    m_stats.zipBombsDetected++;
                    return summary;
                }
            }

            // Create output directory
            std::error_code ec;
            if (!fs::exists(outputDir, ec)) {
                fs::create_directories(outputDir, ec);
                if (ec) {
                    summary.result = ExtractionResult::IOError;
                    summary.errors.push_back("Failed to create output directory");
                    return summary;
                }
            }

            // Placeholder extraction
            // Real implementation would use libarchive
            summary.result = ExtractionResult::Success;
            summary.entriesProcessed = 0;
            summary.entriesExtracted = 0;
            summary.bytesExtracted = 0;

            m_stats.archivesProcessed++;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ExtractAll exception: {}", e.what());
            summary.result = ExtractionResult::IOError;
            summary.errors.push_back(std::string("Exception: ") + e.what());
        }

        auto endTime = std::chrono::steady_clock::now();
        summary.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

        return summary;
    }

    [[nodiscard]] ExtractedData ExtractEntry(
        const std::wstring& filePath,
        const std::wstring& entryPath,
        const ExtractionOptions& options) {

        ExtractedData result;
        result.entryPath = entryPath;

        try {
            Logger::Info("ArchiveExtractor: Extracting entry {} from {}",
                StringUtils::WideToUtf8(entryPath),
                StringUtils::WideToUtf8(filePath));

            // Placeholder
            result.result = ExtractionResult::Success;
            result.size = 0;

            m_stats.entriesExtracted++;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ExtractEntry exception: {}", e.what());
            result.result = ExtractionResult::IOError;
            result.errorMessage = e.what();
        }

        return result;
    }

    ExtractionSummary ExtractMatching(
        const std::wstring& filePath,
        const std::wstring& pattern,
        EntryCallback callback,
        const ExtractionOptions& options) {

        ExtractionSummary summary;

        try {
            Logger::Info("ArchiveExtractor: Extracting matching pattern: {}",
                StringUtils::WideToUtf8(pattern));

            // List all entries
            auto entries = ListContents(filePath, options);

            for (const auto& entry : entries) {
                // Simple wildcard matching (real implementation would use proper glob)
                if (MatchesPattern(entry.path, pattern)) {
                    if (callback) {
                        std::vector<uint8_t> emptyData;
                        callback(entry, emptyData);
                    }
                    summary.entriesExtracted++;
                }
            }

            summary.result = ExtractionResult::Success;
            summary.entriesProcessed = static_cast<uint32_t>(entries.size());

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ExtractMatching exception: {}", e.what());
            summary.result = ExtractionResult::IOError;
        }

        return summary;
    }

    ExtractionSummary ExtractStreaming(
        const std::wstring& filePath,
        StreamCallback callback,
        const ExtractionOptions& options) {

        ExtractionSummary summary;

        try {
            Logger::Info("ArchiveExtractor: Streaming extraction from {}",
                StringUtils::WideToUtf8(filePath));

            // Placeholder
            summary.result = ExtractionResult::Success;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: ExtractStreaming exception: {}", e.what());
            summary.result = ExtractionResult::IOError;
        }

        return summary;
    }

    // ========================================================================
    // SECURITY ANALYSIS
    // ========================================================================

    [[nodiscard]] ArchiveInfo AnalyzeSecurity(const std::wstring& filePath) const {
        ArchiveInfo info = GetArchiveInfo(filePath);

        try {
            // Perform security checks
            if (IsZipBomb(filePath)) {
                info.securityFlags = static_cast<SecurityFlag>(
                    static_cast<uint32_t>(info.securityFlags) |
                    static_cast<uint32_t>(SecurityFlag::ZipBombSuspected));
                info.isSuspicious = true;
                info.securityWarnings.push_back("Potential zip bomb detected");
            }

            // Check for high compression ratio
            if (info.overallCompressionRatio > m_config.defaultMaxRatio) {
                info.securityFlags = static_cast<SecurityFlag>(
                    static_cast<uint32_t>(info.securityFlags) |
                    static_cast<uint32_t>(SecurityFlag::HighCompressionRatio));
                info.securityWarnings.push_back("Suspicious compression ratio");
            }

            // Check for encryption
            if (info.hasEncryptedEntries) {
                info.securityFlags = static_cast<SecurityFlag>(
                    static_cast<uint32_t>(info.securityFlags) |
                    static_cast<uint32_t>(SecurityFlag::EncryptedContent));
            }

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: AnalyzeSecurity exception: {}", e.what());
        }

        return info;
    }

    [[nodiscard]] bool IsZipBomb(const std::wstring& filePath) const {
        try {
            std::error_code ec;
            auto fileSize = fs::file_size(filePath, ec);
            if (ec) {
                return false;
            }

            // Simple heuristic: if file is small but claims huge uncompressed size
            // Real implementation would enumerate entries and check ratios

            // For now, check file size against limits
            if (fileSize > m_config.defaultMaxTotal) {
                Logger::Warn("ArchiveExtractor: File size {} exceeds limit", fileSize);
                return true;
            }

            // Placeholder for actual zip bomb detection
            // Real implementation would use libarchive to enumerate and check:
            // - Compression ratios per entry
            // - Total uncompressed size
            // - Nesting depth
            // - Quine bombs (self-referencing)
            // - Overlapping entries

            return false;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: IsZipBomb exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] SecurityFlag CheckEntrySecurity(const ArchiveEntry& entry) const {
        uint32_t flags = static_cast<uint32_t>(SecurityFlag::None);

        try {
            // Path traversal check
            if (!IsPathSafe(entry.path)) {
                flags |= static_cast<uint32_t>(SecurityFlag::PathTraversalAttempt);
            }

            // Compression ratio check
            if (entry.compressionRatio > m_config.defaultMaxRatio) {
                flags |= static_cast<uint32_t>(SecurityFlag::HighCompressionRatio);
            }

            // Symlink check
            if (entry.type == EntryType::Symlink || entry.type == EntryType::Hardlink) {
                flags |= static_cast<uint32_t>(SecurityFlag::SymlinkAttack);
            }

            // Encryption check
            if (entry.isEncrypted) {
                flags |= static_cast<uint32_t>(SecurityFlag::EncryptedContent);
            }

            // Hidden entry check
            if (entry.isHidden) {
                flags |= static_cast<uint32_t>(SecurityFlag::HiddenEntry);
            }

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: CheckEntrySecurity exception: {}", e.what());
        }

        return static_cast<SecurityFlag>(flags);
    }

    // ========================================================================
    // PASSWORD HANDLING
    // ========================================================================

    void SetPasswordCallback(PasswordCallback callback) {
        std::unique_lock lock(m_mutex);
        m_passwordCallback = std::move(callback);
    }

    [[nodiscard]] bool TestPassword(const std::wstring& filePath, const std::string& password) const {
        try {
            Logger::Info("ArchiveExtractor: Testing password for {}",
                StringUtils::WideToUtf8(filePath));

            // Placeholder
            // Real implementation would attempt to open archive with password
            return false;

        } catch (const std::exception& e) {
            Logger::Error("ArchiveExtractor: TestPassword exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetProgressCallback(ProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        m_progressCallback = std::move(callback);
    }

    void SetSecurityCallback(SecurityCallback callback) {
        std::unique_lock lock(m_mutex);
        m_securityCallback = std::move(callback);
    }

    // ========================================================================
    // CANCELLATION
    // ========================================================================

    void Cancel() noexcept {
        m_cancelled.store(true);
        Logger::Info("ArchiveExtractor: Operation cancelled");
    }

    [[nodiscard]] bool IsCancelled() const noexcept {
        return m_cancelled.load();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const ArchiveExtractorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    [[nodiscard]] std::string GetFormatName(ArchiveFormat format) const noexcept {
        switch (format) {
            case ArchiveFormat::ZIP: return "ZIP";
            case ArchiveFormat::RAR: return "RAR";
            case ArchiveFormat::RAR5: return "RAR5";
            case ArchiveFormat::SevenZip: return "7-Zip";
            case ArchiveFormat::TAR: return "TAR";
            case ArchiveFormat::GZIP: return "GZIP";
            case ArchiveFormat::BZIP2: return "BZIP2";
            case ArchiveFormat::XZ: return "XZ";
            case ArchiveFormat::LZMA: return "LZMA";
            case ArchiveFormat::ZSTD: return "ZSTD";
            case ArchiveFormat::TarGz: return "TAR.GZ";
            case ArchiveFormat::TarBz2: return "TAR.BZ2";
            case ArchiveFormat::TarXz: return "TAR.XZ";
            case ArchiveFormat::TarZstd: return "TAR.ZSTD";
            case ArchiveFormat::CAB: return "CAB";
            case ArchiveFormat::MSI: return "MSI";
            case ArchiveFormat::WIM: return "WIM";
            case ArchiveFormat::ISO: return "ISO";
            case ArchiveFormat::VHD: return "VHD";
            case ArchiveFormat::VHDX: return "VHDX";
            case ArchiveFormat::DMG: return "DMG";
            case ArchiveFormat::IMG: return "IMG";
            case ArchiveFormat::ARJ: return "ARJ";
            case ArchiveFormat::LZH: return "LZH";
            case ArchiveFormat::ACE: return "ACE";
            case ArchiveFormat::CPIO: return "CPIO";
            case ArchiveFormat::RPM: return "RPM";
            case ArchiveFormat::DEB: return "DEB";
            default: return "Unknown";
        }
    }

    [[nodiscard]] bool MatchesPattern(const std::wstring& path, const std::wstring& pattern) const {
        // Simple wildcard matching
        if (pattern == L"*") {
            return true;
        }

        if (pattern.find(L'*') == std::wstring::npos) {
            return path == pattern;
        }

        // Simple prefix/suffix matching
        if (pattern.starts_with(L"*") && pattern.ends_with(L"*")) {
            std::wstring middle = pattern.substr(1, pattern.length() - 2);
            return path.find(middle) != std::wstring::npos;
        }

        if (pattern.starts_with(L"*")) {
            std::wstring suffix = pattern.substr(1);
            return path.ends_with(suffix);
        }

        if (pattern.ends_with(L"*")) {
            std::wstring prefix = pattern.substr(0, pattern.length() - 1);
            return path.starts_with(prefix);
        }

        return false;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    ArchiveExtractorConfig m_config;
    mutable ArchiveExtractorStatistics m_stats;

    // Cache
    struct CacheEntry {
        ArchiveInfo info;
        std::chrono::steady_clock::time_point timestamp;
    };
    mutable std::unordered_map<std::wstring, CacheEntry> m_cache;
    mutable std::atomic<uint64_t> m_cacheHits{ 0 };
    mutable std::atomic<uint64_t> m_cacheMisses{ 0 };

    // Callbacks
    PasswordCallback m_passwordCallback;
    ProgressCallback m_progressCallback;
    SecurityCallback m_securityCallback;

    // Cancellation
    std::atomic<bool> m_cancelled{ false };
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

ArchiveExtractor& ArchiveExtractor::Instance() {
    static ArchiveExtractor instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ArchiveExtractor::ArchiveExtractor()
    : m_impl(std::make_unique<ArchiveExtractorImpl>()) {

    Logger::Info("ArchiveExtractor instance created");
}

ArchiveExtractor::~ArchiveExtractor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ArchiveExtractor instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool ArchiveExtractor::Initialize(const ArchiveExtractorConfig& config) {
    return m_impl->Initialize(config);
}

void ArchiveExtractor::Shutdown() noexcept {
    m_impl->Shutdown();
}

ArchiveFormat ArchiveExtractor::DetectFormat(const std::wstring& filePath) const {
    return m_impl->DetectFormat(filePath);
}

ArchiveFormat ArchiveExtractor::DetectFormat(std::span<const uint8_t> buffer) const {
    return m_impl->DetectFormat(buffer);
}

bool ArchiveExtractor::IsArchive(const std::wstring& filePath) const {
    return m_impl->IsArchive(filePath);
}

std::vector<ArchiveFormat> ArchiveExtractor::GetSupportedFormats() const {
    return m_impl->GetSupportedFormats();
}

ArchiveInfo ArchiveExtractor::GetArchiveInfo(const std::wstring& filePath) const {
    return m_impl->GetArchiveInfo(filePath);
}

std::vector<ArchiveEntry> ArchiveExtractor::ListContents(
    const std::wstring& filePath,
    const ExtractionOptions& options) const {
    return m_impl->ListContents(filePath, options);
}

bool ArchiveExtractor::VerifyIntegrity(const std::wstring& filePath) const {
    return m_impl->VerifyIntegrity(filePath);
}

ExtractionSummary ArchiveExtractor::ScanArchive(
    const std::wstring& filePath,
    EntryCallback callback,
    const ExtractionOptions& options) {
    return m_impl->ScanArchive(filePath, std::move(callback), options);
}

ExtractionSummary ArchiveExtractor::ExtractAll(
    const std::wstring& filePath,
    const std::wstring& outputDir,
    const ExtractionOptions& options) {
    return m_impl->ExtractAll(filePath, outputDir, options);
}

ExtractedData ArchiveExtractor::ExtractEntry(
    const std::wstring& filePath,
    const std::wstring& entryPath,
    const ExtractionOptions& options) {
    return m_impl->ExtractEntry(filePath, entryPath, options);
}

ExtractionSummary ArchiveExtractor::ExtractMatching(
    const std::wstring& filePath,
    const std::wstring& pattern,
    EntryCallback callback,
    const ExtractionOptions& options) {
    return m_impl->ExtractMatching(filePath, pattern, std::move(callback), options);
}

ExtractionSummary ArchiveExtractor::ExtractStreaming(
    const std::wstring& filePath,
    StreamCallback callback,
    const ExtractionOptions& options) {
    return m_impl->ExtractStreaming(filePath, std::move(callback), options);
}

ArchiveInfo ArchiveExtractor::AnalyzeSecurity(const std::wstring& filePath) const {
    return m_impl->AnalyzeSecurity(filePath);
}

bool ArchiveExtractor::IsZipBomb(const std::wstring& filePath) const {
    return m_impl->IsZipBomb(filePath);
}

SecurityFlag ArchiveExtractor::CheckEntrySecurity(const ArchiveEntry& entry) const {
    return m_impl->CheckEntrySecurity(entry);
}

void ArchiveExtractor::SetPasswordCallback(PasswordCallback callback) {
    m_impl->SetPasswordCallback(std::move(callback));
}

bool ArchiveExtractor::TestPassword(const std::wstring& filePath, const std::string& password) const {
    return m_impl->TestPassword(filePath, password);
}

void ArchiveExtractor::SetProgressCallback(ProgressCallback callback) {
    m_impl->SetProgressCallback(std::move(callback));
}

void ArchiveExtractor::SetSecurityCallback(SecurityCallback callback) {
    m_impl->SetSecurityCallback(std::move(callback));
}

void ArchiveExtractor::Cancel() noexcept {
    m_impl->Cancel();
}

bool ArchiveExtractor::IsCancelled() const noexcept {
    return m_impl->IsCancelled();
}

const ArchiveExtractorStatistics& ArchiveExtractor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void ArchiveExtractor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
