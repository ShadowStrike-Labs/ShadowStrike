/**
 * ============================================================================
 * ShadowStrike Core FileSystem - MEDIA FILE SCANNER (The Deep Screen)
 * ============================================================================
 *
 * @file MediaFileScanner.hpp
 * @brief Enterprise-grade media file security analysis engine.
 *
 * This module provides comprehensive security analysis of media files including
 * steganography detection, exploit identification in malformed media, and
 * hidden payload extraction.
 *
 * Key Capabilities:
 * =================
 * 1. STEGANOGRAPHY DETECTION
 *    - LSB (Least Significant Bit) analysis
 *    - DCT coefficient analysis (JPEG)
 *    - EOF appended data detection
 *    - Palette-based hiding
 *
 * 2. EXPLOIT DETECTION
 *    - Malformed header detection
 *    - Buffer overflow triggers
 *    - Codec vulnerabilities
 *    - CVE pattern matching
 *
 * 3. METADATA ANALYSIS
 *    - EXIF extraction
 *    - Hidden comments
 *    - GPS/location data
 *    - Thumbnail analysis
 *
 * 4. PAYLOAD EXTRACTION
 *    - Embedded executables
 *    - Appended archives
 *    - Polyglot files
 *    - Script injection
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see FileTypeAnalyzer.hpp for format detection
 * @see PatternStore.hpp for exploit patterns
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class MediaFileScannerImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum MediaType
 * @brief Type of media file.
 */
enum class MediaType : uint8_t {
    Unknown = 0,
    JPEG = 1,
    PNG = 2,
    GIF = 3,
    BMP = 4,
    TIFF = 5,
    WebP = 6,
    ICO = 7,
    MP3 = 20,
    WAV = 21,
    FLAC = 22,
    OGG = 23,
    MP4 = 40,
    AVI = 41,
    MKV = 42,
    MOV = 43
};

/**
 * @enum StegoTechnique
 * @brief Detected steganography technique.
 */
enum class StegoTechnique : uint8_t {
    None = 0,
    LSB = 1,                       // Least significant bit
    DCT = 2,                       // DCT coefficients
    Palette = 3,                   // Palette manipulation
    EOF = 4,                       // End of file appended
    Metadata = 5,                  // Hidden in metadata
    AlphaChannel = 6               // Alpha channel hiding
};

/**
 * @enum MediaThreatType
 * @brief Type of media threat.
 */
enum class MediaThreatType : uint8_t {
    None = 0,
    Steganography = 1,
    MalformedHeader = 2,
    BufferOverflow = 3,
    EmbeddedExecutable = 4,
    AppendedArchive = 5,
    Polyglot = 6,
    ScriptInjection = 7,
    CVEExploit = 8
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct MediaMetadata
 * @brief Extracted media metadata.
 */
struct alignas(128) MediaMetadata {
    // Image properties
    uint32_t width{ 0 };
    uint32_t height{ 0 };
    uint32_t bitDepth{ 0 };
    std::string colorSpace;

    // EXIF data
    std::string cameraMake;
    std::string cameraModel;
    std::chrono::system_clock::time_point dateTime;
    double latitude{ 0.0 };
    double longitude{ 0.0 };
    bool hasGPS{ false };

    // Comments
    std::vector<std::string> comments;

    // Thumbnail
    bool hasThumbnail{ false };
    std::vector<uint8_t> thumbnail;
};

/**
 * @struct StegoAnalysis
 * @brief Steganography analysis result.
 */
struct alignas(64) StegoAnalysis {
    bool stegoDetected{ false };
    StegoTechnique technique{ StegoTechnique::None };
    double confidence{ 0.0 };
    uint64_t estimatedPayloadSize{ 0 };

    std::vector<uint8_t> extractedData;
    std::string analysisDetails;
};

/**
 * @struct MediaThreat
 * @brief Detected media threat.
 */
struct alignas(64) MediaThreat {
    MediaThreatType type{ MediaThreatType::None };
    uint8_t severity{ 0 };
    std::string description;
    std::string cveId;
    uint32_t offset{ 0 };
};

/**
 * @struct MediaScanResult
 * @brief Complete media scan result.
 */
struct alignas(256) MediaScanResult {
    std::wstring filePath;
    MediaType mediaType{ MediaType::Unknown };
    uint64_t fileSize{ 0 };

    // Analysis results
    bool isValid{ false };
    bool isSuspicious{ false };
    bool isMalicious{ false };
    uint8_t riskScore{ 0 };

    // Metadata
    MediaMetadata metadata;

    // Steganography
    StegoAnalysis stego;

    // Threats
    std::vector<MediaThreat> threats;

    // Hidden content
    bool hasAppendedData{ false };
    uint64_t appendedDataSize{ 0 };
    std::vector<uint8_t> appendedData;

    std::chrono::milliseconds scanDuration{ 0 };
};

/**
 * @struct MediaFileScannerConfig
 * @brief Configuration for media scanner.
 */
struct alignas(32) MediaFileScannerConfig {
    bool detectSteganography{ true };
    bool detectExploits{ true };
    bool extractMetadata{ true };
    bool analyzeAppendedData{ true };

    static MediaFileScannerConfig CreateDefault() noexcept;
    static MediaFileScannerConfig CreateDeep() noexcept;
};

/**
 * @struct MediaFileScannerStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) MediaFileScannerStatistics {
    std::atomic<uint64_t> filesScanned{ 0 };
    std::atomic<uint64_t> stegoDetected{ 0 };
    std::atomic<uint64_t> exploitsDetected{ 0 };
    std::atomic<uint64_t> maliciousFiles{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class MediaFileScanner
 * @brief Enterprise-grade media security scanner.
 */
class MediaFileScanner {
public:
    static MediaFileScanner& Instance();

    bool Initialize(const MediaFileScannerConfig& config);
    void Shutdown() noexcept;

    /**
     * @brief Performs full media scan.
     */
    [[nodiscard]] MediaScanResult Scan(const std::wstring& filePath);

    /**
     * @brief Scans for steganography only.
     */
    [[nodiscard]] StegoAnalysis DetectSteganography(const std::wstring& filePath) const;

    /**
     * @brief Extracts metadata.
     */
    [[nodiscard]] MediaMetadata ExtractMetadata(const std::wstring& filePath) const;

    /**
     * @brief Checks for appended data.
     */
    [[nodiscard]] bool HasAppendedData(const std::wstring& filePath) const;

    /**
     * @brief Extracts appended data.
     */
    [[nodiscard]] std::vector<uint8_t> ExtractAppendedData(const std::wstring& filePath) const;

    [[nodiscard]] const MediaFileScannerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    MediaFileScanner();
    ~MediaFileScanner();

    MediaFileScanner(const MediaFileScanner&) = delete;
    MediaFileScanner& operator=(const MediaFileScanner&) = delete;

    std::unique_ptr<MediaFileScannerImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
