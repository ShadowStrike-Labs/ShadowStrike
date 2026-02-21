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
 * @file MediaFileScanner.cpp
 * @brief Enterprise implementation of media file security analysis engine.
 *
 * The Deep Screen of ShadowStrike NGAV - detects steganography, exploits,
 * and hidden payloads in media files (images, audio, video). Protects against
 * malformed media attacks, embedded executables, and covert data exfiltration.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "MediaFileScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "FileHasher.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <array>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// MAGIC NUMBER CONSTANTS
// ============================================================================

namespace MagicNumbers {
    // Image formats
    constexpr uint8_t JPEG_SOI[2] = { 0xFF, 0xD8 };
    constexpr uint8_t JPEG_EOI[2] = { 0xFF, 0xD9 };
    constexpr uint8_t PNG_SIGNATURE[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    constexpr uint8_t GIF_87A[6] = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }; // GIF87a
    constexpr uint8_t GIF_89A[6] = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 }; // GIF89a
    constexpr uint8_t BMP_SIGNATURE[2] = { 0x42, 0x4D }; // BM

    // Audio formats
    constexpr uint8_t RIFF[4] = { 0x52, 0x49, 0x46, 0x46 }; // WAV
    constexpr uint8_t WAVE[4] = { 0x57, 0x41, 0x56, 0x45 };
    constexpr uint8_t ID3[3] = { 0x49, 0x44, 0x33 }; // MP3

    // Video formats
    constexpr uint8_t FTYP[4] = { 0x66, 0x74, 0x79, 0x70 }; // MP4
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] constexpr const char* MediaTypeToString(MediaType type) noexcept {
    switch (type) {
        case MediaType::Unknown: return "Unknown";
        case MediaType::JPEG: return "JPEG";
        case MediaType::PNG: return "PNG";
        case MediaType::GIF: return "GIF";
        case MediaType::BMP: return "BMP";
        case MediaType::TIFF: return "TIFF";
        case MediaType::WebP: return "WebP";
        case MediaType::ICO: return "ICO";
        case MediaType::MP3: return "MP3";
        case MediaType::WAV: return "WAV";
        case MediaType::FLAC: return "FLAC";
        case MediaType::OGG: return "OGG";
        case MediaType::MP4: return "MP4";
        case MediaType::AVI: return "AVI";
        case MediaType::MKV: return "MKV";
        case MediaType::MOV: return "MOV";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* StegoTechniqueToString(StegoTechnique tech) noexcept {
    switch (tech) {
        case StegoTechnique::None: return "None";
        case StegoTechnique::LSB: return "Least Significant Bit";
        case StegoTechnique::DCT: return "DCT Coefficients";
        case StegoTechnique::Palette: return "Palette Manipulation";
        case StegoTechnique::EOF: return "End-of-File Appended";
        case StegoTechnique::Metadata: return "Metadata Hiding";
        case StegoTechnique::AlphaChannel: return "Alpha Channel Hiding";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* MediaThreatTypeToString(MediaThreatType type) noexcept {
    switch (type) {
        case MediaThreatType::None: return "None";
        case MediaThreatType::Steganography: return "Steganography";
        case MediaThreatType::MalformedHeader: return "Malformed Header";
        case MediaThreatType::BufferOverflow: return "Buffer Overflow Trigger";
        case MediaThreatType::EmbeddedExecutable: return "Embedded Executable";
        case MediaThreatType::AppendedArchive: return "Appended Archive";
        case MediaThreatType::Polyglot: return "Polyglot File";
        case MediaThreatType::ScriptInjection: return "Script Injection";
        case MediaThreatType::CVEExploit: return "CVE Exploit";
        default: return "Unknown";
    }
}

// ============================================================================
// MediaFileScannerConfig FACTORY METHODS
// ============================================================================

MediaFileScannerConfig MediaFileScannerConfig::CreateDefault() noexcept {
    return MediaFileScannerConfig{};
}

MediaFileScannerConfig MediaFileScannerConfig::CreateDeep() noexcept {
    MediaFileScannerConfig config;
    config.detectSteganography = true;
    config.detectExploits = true;
    config.extractMetadata = true;
    config.analyzeAppendedData = true;
    return config;
}

// ============================================================================
// MediaFileScannerStatistics METHODS
// ============================================================================

void MediaFileScannerStatistics::Reset() noexcept {
    filesScanned.store(0, std::memory_order_relaxed);
    stegoDetected.store(0, std::memory_order_relaxed);
    exploitsDetected.store(0, std::memory_order_relaxed);
    maliciousFiles.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for MediaFileScanner.
 */
class MediaFileScanner::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::mutex m_operationMutex;

    // Initialization state
    std::atomic<bool> m_initialized{false};

    // Configuration
    MediaFileScannerConfig m_config{};

    // Statistics
    MediaFileScannerStatistics m_stats{};

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const MediaFileScannerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("MediaFileScanner::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("MediaFileScanner::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("MediaFileScanner::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("MediaFileScanner::Impl: Shutting down");

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("MediaFileScanner::Impl: Shutdown complete");
    }

    // ========================================================================
    // FORMAT DETECTION
    // ========================================================================

    [[nodiscard]] MediaType DetectMediaType(const std::wstring& filePath) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                Logger::Warn("MediaFileScanner: Cannot open file for type detection");
                return MediaType::Unknown;
            }

            std::array<uint8_t, 16> header{};
            file.read(reinterpret_cast<char*>(header.data()), header.size());
            size_t bytesRead = file.gcount();

            if (bytesRead < 2) {
                return MediaType::Unknown;
            }

            // JPEG detection
            if (header[0] == MagicNumbers::JPEG_SOI[0] &&
                header[1] == MagicNumbers::JPEG_SOI[1]) {
                return MediaType::JPEG;
            }

            // PNG detection
            if (bytesRead >= 8 && std::equal(
                MagicNumbers::PNG_SIGNATURE,
                MagicNumbers::PNG_SIGNATURE + 8,
                header.begin())) {
                return MediaType::PNG;
            }

            // GIF detection
            if (bytesRead >= 6) {
                if (std::equal(MagicNumbers::GIF_87A, MagicNumbers::GIF_87A + 6, header.begin()) ||
                    std::equal(MagicNumbers::GIF_89A, MagicNumbers::GIF_89A + 6, header.begin())) {
                    return MediaType::GIF;
                }
            }

            // BMP detection
            if (header[0] == MagicNumbers::BMP_SIGNATURE[0] &&
                header[1] == MagicNumbers::BMP_SIGNATURE[1]) {
                return MediaType::BMP;
            }

            // WAV detection (RIFF...WAVE)
            if (bytesRead >= 12) {
                if (std::equal(MagicNumbers::RIFF, MagicNumbers::RIFF + 4, header.begin())) {
                    std::array<uint8_t, 4> wave{};
                    file.seekg(8, std::ios::beg);
                    file.read(reinterpret_cast<char*>(wave.data()), 4);
                    if (std::equal(MagicNumbers::WAVE, MagicNumbers::WAVE + 4, wave.begin())) {
                        return MediaType::WAV;
                    }
                }
            }

            // MP3 detection (ID3 tag)
            if (bytesRead >= 3 && std::equal(
                MagicNumbers::ID3, MagicNumbers::ID3 + 3, header.begin())) {
                return MediaType::MP3;
            }

            // MP4 detection (ftyp)
            if (bytesRead >= 12) {
                std::array<uint8_t, 4> ftyp{};
                file.seekg(4, std::ios::beg);
                file.read(reinterpret_cast<char*>(ftyp.data()), 4);
                if (std::equal(MagicNumbers::FTYP, MagicNumbers::FTYP + 4, ftyp.begin())) {
                    return MediaType::MP4;
                }
            }

            Logger::Debug("MediaFileScanner: Unknown media type");
            return MediaType::Unknown;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Type detection exception: {}", e.what());
            return MediaType::Unknown;
        }
    }

    // ========================================================================
    // FULL SCAN IMPLEMENTATION
    // ========================================================================

    [[nodiscard]] MediaScanResult ScanImpl(const std::wstring& filePath) {
        MediaScanResult result{};
        const auto scanStart = steady_clock::now();

        try {
            result.filePath = filePath;

            // Validate file
            std::error_code ec;
            if (!fs::exists(filePath, ec)) {
                Logger::Error("MediaFileScanner: File not found: {}",
                    StringUtils::ToNarrowString(filePath));
                return result;
            }

            result.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                Logger::Error("MediaFileScanner: Cannot get file size: {}", ec.message());
                return result;
            }

            Logger::Info("MediaFileScanner: Scanning {} ({} bytes)",
                StringUtils::ToNarrowString(filePath), result.fileSize);

            // Detect media type
            result.mediaType = DetectMediaType(filePath);
            if (result.mediaType == MediaType::Unknown) {
                Logger::Warn("MediaFileScanner: Unknown media type, limited analysis");
            }

            // Validate format
            result.isValid = ValidateFormat(filePath, result.mediaType);

            // Extract metadata
            if (m_config.extractMetadata) {
                result.metadata = ExtractMetadataImpl(filePath, result.mediaType);
            }

            // Detect steganography
            if (m_config.detectSteganography) {
                result.stego = DetectSteganographyImpl(filePath, result.mediaType);
                if (result.stego.stegoDetected) {
                    result.isSuspicious = true;
                    result.riskScore += 40;

                    MediaThreat threat{};
                    threat.type = MediaThreatType::Steganography;
                    threat.severity = 7;
                    threat.description = std::format("Steganography detected: {}",
                        StegoTechniqueToString(result.stego.technique));
                    result.threats.push_back(threat);
                }
            }

            // Detect exploits
            if (m_config.detectExploits) {
                DetectExploits(filePath, result);
            }

            // Analyze appended data
            if (m_config.analyzeAppendedData) {
                AnalyzeAppendedData(filePath, result);
            }

            // Calculate final risk score
            if (result.riskScore >= 80) {
                result.isMalicious = true;
            } else if (result.riskScore >= 40) {
                result.isSuspicious = true;
            }

            // Update statistics
            m_stats.filesScanned.fetch_add(1, std::memory_order_relaxed);
            if (result.stego.stegoDetected) {
                m_stats.stegoDetected.fetch_add(1, std::memory_order_relaxed);
            }
            if (!result.threats.empty()) {
                m_stats.exploitsDetected.fetch_add(result.threats.size(), std::memory_order_relaxed);
            }
            if (result.isMalicious) {
                m_stats.maliciousFiles.fetch_add(1, std::memory_order_relaxed);
            }

            result.scanDuration = duration_cast<milliseconds>(steady_clock::now() - scanStart);

            Logger::Info("MediaFileScanner: Scan complete - Risk: {}, Threats: {}, Duration: {} ms",
                result.riskScore, result.threats.size(), result.scanDuration.count());

            return result;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Scan exception: {}", e.what());
            return result;
        }
    }

    // ========================================================================
    // FORMAT VALIDATION
    // ========================================================================

    [[nodiscard]] bool ValidateFormat(const std::wstring& filePath, MediaType type) const {
        try {
            switch (type) {
                case MediaType::JPEG:
                    return ValidateJPEG(filePath);
                case MediaType::PNG:
                    return ValidatePNG(filePath);
                case MediaType::GIF:
                    return ValidateGIF(filePath);
                default:
                    return true; // Unknown formats pass
            }
        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Format validation exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ValidateJPEG(const std::wstring& filePath) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            // Check SOI marker
            uint8_t soi[2];
            file.read(reinterpret_cast<char*>(soi), 2);
            if (soi[0] != 0xFF || soi[1] != 0xD8) {
                Logger::Warn("MediaFileScanner: Invalid JPEG SOI marker");
                return false;
            }

            // Check EOI marker
            file.seekg(-2, std::ios::end);
            uint8_t eoi[2];
            file.read(reinterpret_cast<char*>(eoi), 2);
            if (eoi[0] != 0xFF || eoi[1] != 0xD9) {
                Logger::Warn("MediaFileScanner: JPEG missing EOI marker (possible appended data)");
                return false;
            }

            return true;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: JPEG validation exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ValidatePNG(const std::wstring& filePath) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            // Check PNG signature
            std::array<uint8_t, 8> signature{};
            file.read(reinterpret_cast<char*>(signature.data()), 8);
            if (!std::equal(MagicNumbers::PNG_SIGNATURE,
                           MagicNumbers::PNG_SIGNATURE + 8,
                           signature.begin())) {
                Logger::Warn("MediaFileScanner: Invalid PNG signature");
                return false;
            }

            // Check for IHDR chunk
            std::array<char, 4> chunkType{};
            file.seekg(12, std::ios::beg);
            file.read(chunkType.data(), 4);
            if (std::string(chunkType.data(), 4) != "IHDR") {
                Logger::Warn("MediaFileScanner: PNG missing IHDR chunk");
                return false;
            }

            return true;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: PNG validation exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ValidateGIF(const std::wstring& filePath) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            // Check GIF signature
            std::array<uint8_t, 6> signature{};
            file.read(reinterpret_cast<char*>(signature.data()), 6);

            bool validGIF87a = std::equal(MagicNumbers::GIF_87A,
                                         MagicNumbers::GIF_87A + 6,
                                         signature.begin());
            bool validGIF89a = std::equal(MagicNumbers::GIF_89A,
                                         MagicNumbers::GIF_89A + 6,
                                         signature.begin());

            if (!validGIF87a && !validGIF89a) {
                Logger::Warn("MediaFileScanner: Invalid GIF signature");
                return false;
            }

            return true;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: GIF validation exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // STEGANOGRAPHY DETECTION
    // ========================================================================

    [[nodiscard]] StegoAnalysis DetectSteganographyImpl(
        const std::wstring& filePath,
        MediaType type
    ) const {
        StegoAnalysis result{};

        try {
            Logger::Debug("MediaFileScanner: Analyzing for steganography");

            // LSB analysis
            auto lsbResult = DetectLSBStego(filePath, type);
            if (lsbResult.confidence > result.confidence) {
                result = lsbResult;
            }

            // EOF appended data check
            auto eofResult = DetectEOFStego(filePath, type);
            if (eofResult.confidence > result.confidence) {
                result = eofResult;
            }

            // Metadata hiding
            auto metadataResult = DetectMetadataStego(filePath);
            if (metadataResult.confidence > result.confidence) {
                result = metadataResult;
            }

            result.stegoDetected = (result.confidence >= 0.6);

            if (result.stegoDetected) {
                Logger::Warn("MediaFileScanner: Steganography detected - Technique: {}, Confidence: {:.2f}",
                    StegoTechniqueToString(result.technique), result.confidence);
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Steganography detection exception: {}", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectLSBStego(
        const std::wstring& filePath,
        MediaType type
    ) const {
        StegoAnalysis result{};

        try {
            // Only applicable to image formats
            if (type != MediaType::PNG && type != MediaType::BMP) {
                return result;
            }

            std::ifstream file(filePath, std::ios::binary);
            if (!file) return result;

            // Read file into buffer
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

            if (data.size() < 1024) {
                return result; // Too small
            }

            // Chi-square test on LSBs
            std::array<uint64_t, 2> lsbCounts{};
            size_t samplesAnalyzed = std::min(data.size(), size_t(100000));

            for (size_t i = 0; i < samplesAnalyzed; i++) {
                lsbCounts[data[i] & 0x01]++;
            }

            // Expected distribution: 50/50
            double expected = samplesAnalyzed / 2.0;
            double chiSquare = 0.0;
            for (auto count : lsbCounts) {
                double diff = count - expected;
                chiSquare += (diff * diff) / expected;
            }

            // Chi-square critical value for 1 degree of freedom at 95% confidence: 3.841
            if (chiSquare < 3.841) {
                // LSBs are too uniform - possible steganography
                result.technique = StegoTechnique::LSB;
                result.confidence = 0.7;
                result.analysisDetails = std::format("Chi-square: {:.2f} (uniform LSBs)", chiSquare);

                Logger::Debug("MediaFileScanner: LSB analysis - Chi-square: {:.2f}", chiSquare);
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: LSB analysis exception: {}", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectEOFStego(
        const std::wstring& filePath,
        MediaType type
    ) const {
        StegoAnalysis result{};

        try {
            // Check for data after EOF marker
            if (type == MediaType::JPEG) {
                std::ifstream file(filePath, std::ios::binary);
                if (!file) return result;

                // Find EOI marker (0xFF 0xD9)
                file.seekg(0, std::ios::end);
                size_t fileSize = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<uint8_t> data(fileSize);
                file.read(reinterpret_cast<char*>(data.data()), fileSize);

                // Search for last EOI
                size_t eoiPos = 0;
                for (size_t i = 0; i < fileSize - 1; i++) {
                    if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                        eoiPos = i + 2;
                    }
                }

                if (eoiPos > 0 && eoiPos < fileSize) {
                    size_t appendedSize = fileSize - eoiPos;
                    if (appendedSize > 10) { // Ignore padding bytes
                        result.technique = StegoTechnique::EOF;
                        result.confidence = 0.9;
                        result.estimatedPayloadSize = appendedSize;
                        result.extractedData = std::vector<uint8_t>(
                            data.begin() + eoiPos,
                            data.end()
                        );
                        result.analysisDetails = std::format("{} bytes after JPEG EOI", appendedSize);

                        Logger::Warn("MediaFileScanner: EOF steganography detected - {} bytes appended",
                            appendedSize);
                    }
                }
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: EOF analysis exception: {}", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectMetadataStego(const std::wstring& filePath) const {
        StegoAnalysis result{};

        try {
            // Check for suspiciously large metadata
            auto metadata = ExtractMetadataImpl(filePath, MediaType::Unknown);

            size_t totalMetadataSize = 0;
            for (const auto& comment : metadata.comments) {
                totalMetadataSize += comment.size();
            }

            if (totalMetadataSize > 10000) { // >10KB metadata is suspicious
                result.technique = StegoTechnique::Metadata;
                result.confidence = 0.65;
                result.estimatedPayloadSize = totalMetadataSize;
                result.analysisDetails = std::format("{} bytes in metadata", totalMetadataSize);

                Logger::Warn("MediaFileScanner: Large metadata detected - {} bytes",
                    totalMetadataSize);
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Metadata analysis exception: {}", e.what());
            return result;
        }
    }

    // ========================================================================
    // METADATA EXTRACTION
    // ========================================================================

    [[nodiscard]] MediaMetadata ExtractMetadataImpl(
        const std::wstring& filePath,
        MediaType type
    ) const {
        MediaMetadata metadata{};

        try {
            switch (type) {
                case MediaType::JPEG:
                    return ExtractJPEGMetadata(filePath);
                case MediaType::PNG:
                    return ExtractPNGMetadata(filePath);
                default:
                    return metadata;
            }
        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Metadata extraction exception: {}", e.what());
            return metadata;
        }
    }

    [[nodiscard]] MediaMetadata ExtractJPEGMetadata(const std::wstring& filePath) const {
        MediaMetadata metadata{};

        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return metadata;

            // TODO: Full EXIF parsing would go here
            // For now, basic placeholder implementation

            // Read first 1KB to check for EXIF marker
            std::array<uint8_t, 1024> buffer{};
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

            // Look for "Exif" marker
            for (size_t i = 0; i < buffer.size() - 4; i++) {
                if (buffer[i] == 'E' && buffer[i+1] == 'x' &&
                    buffer[i+2] == 'i' && buffer[i+3] == 'f') {
                    metadata.comments.push_back("EXIF data present");
                    Logger::Debug("MediaFileScanner: JPEG has EXIF data");
                    break;
                }
            }

            return metadata;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: JPEG metadata exception: {}", e.what());
            return metadata;
        }
    }

    [[nodiscard]] MediaMetadata ExtractPNGMetadata(const std::wstring& filePath) const {
        MediaMetadata metadata{};

        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return metadata;

            // Skip PNG signature
            file.seekg(8, std::ios::beg);

            // Read IHDR chunk to get dimensions
            uint32_t chunkLength;
            file.read(reinterpret_cast<char*>(&chunkLength), 4);
            chunkLength = _byteswap_ulong(chunkLength); // Network to host byte order

            std::array<char, 4> chunkType{};
            file.read(chunkType.data(), 4);

            if (std::string(chunkType.data(), 4) == "IHDR") {
                uint32_t width, height;
                file.read(reinterpret_cast<char*>(&width), 4);
                file.read(reinterpret_cast<char*>(&height), 4);

                metadata.width = _byteswap_ulong(width);
                metadata.height = _byteswap_ulong(height);

                uint8_t bitDepth;
                file.read(reinterpret_cast<char*>(&bitDepth), 1);
                metadata.bitDepth = bitDepth;

                Logger::Debug("MediaFileScanner: PNG dimensions: {}x{}, depth: {}",
                    metadata.width, metadata.height, metadata.bitDepth);
            }

            return metadata;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: PNG metadata exception: {}", e.what());
            return metadata;
        }
    }

    // ========================================================================
    // EXPLOIT DETECTION
    // ========================================================================

    void DetectExploits(const std::wstring& filePath, MediaScanResult& result) {
        try {
            // Check for malformed headers
            if (!result.isValid) {
                MediaThreat threat{};
                threat.type = MediaThreatType::MalformedHeader;
                threat.severity = 6;
                threat.description = "Malformed media header detected";
                result.threats.push_back(threat);
                result.riskScore += 30;
            }

            // Check for embedded executables
            if (HasEmbeddedExecutable(filePath)) {
                MediaThreat threat{};
                threat.type = MediaThreatType::EmbeddedExecutable;
                threat.severity = 9;
                threat.description = "Embedded executable detected (PE/ELF signature)";
                result.threats.push_back(threat);
                result.riskScore += 50;
                result.isMalicious = true;
            }

            // Check for polyglot files
            if (IsPolyglot(filePath, result.mediaType)) {
                MediaThreat threat{};
                threat.type = MediaThreatType::Polyglot;
                threat.severity = 8;
                threat.description = "Polyglot file detected (valid as multiple formats)";
                result.threats.push_back(threat);
                result.riskScore += 40;
            }

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Exploit detection exception: {}", e.what());
        }
    }

    [[nodiscard]] bool HasEmbeddedExecutable(const std::wstring& filePath) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

            if (data.size() < 100) return false;

            // Search for PE signature (MZ...PE)
            for (size_t i = 0; i < data.size() - 64; i++) {
                if (data[i] == 'M' && data[i + 1] == 'Z') {
                    // Check for PE signature within reasonable offset
                    if (i + 0x40 < data.size()) {
                        uint32_t peOffset = *reinterpret_cast<uint32_t*>(&data[i + 0x3C]);
                        if (peOffset < data.size() - 4 && peOffset < 1024) {
                            if (data[i + peOffset] == 'P' && data[i + peOffset + 1] == 'E') {
                                Logger::Warn("MediaFileScanner: PE signature found at offset {}", i);
                                return true;
                            }
                        }
                    }
                }
            }

            // Search for ELF signature
            const uint8_t ELF_MAGIC[4] = { 0x7F, 'E', 'L', 'F' };
            for (size_t i = 0; i < data.size() - 4; i++) {
                if (std::equal(ELF_MAGIC, ELF_MAGIC + 4, data.begin() + i)) {
                    Logger::Warn("MediaFileScanner: ELF signature found at offset {}", i);
                    return true;
                }
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Embedded executable check exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsPolyglot(const std::wstring& filePath, MediaType primaryType) const {
        try {
            // A file is a polyglot if it's valid as multiple formats
            std::vector<MediaType> detectedTypes;

            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            std::array<uint8_t, 16> header{};
            file.read(reinterpret_cast<char*>(header.data()), header.size());

            // Check multiple signatures
            if (header[0] == 0xFF && header[1] == 0xD8) {
                detectedTypes.push_back(MediaType::JPEG);
            }
            if (std::equal(MagicNumbers::PNG_SIGNATURE,
                          MagicNumbers::PNG_SIGNATURE + 8, header.begin())) {
                detectedTypes.push_back(MediaType::PNG);
            }
            if (header[0] == 'B' && header[1] == 'M') {
                detectedTypes.push_back(MediaType::BMP);
            }

            if (detectedTypes.size() > 1) {
                Logger::Warn("MediaFileScanner: Polyglot detected - {} valid formats",
                    detectedTypes.size());
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Polyglot check exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // APPENDED DATA ANALYSIS
    // ========================================================================

    void AnalyzeAppendedData(const std::wstring& filePath, MediaScanResult& result) {
        try {
            if (result.mediaType == MediaType::JPEG) {
                AnalyzeJPEGAppendedData(filePath, result);
            }
        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: Appended data analysis exception: {}", e.what());
        }
    }

    void AnalyzeJPEGAppendedData(const std::wstring& filePath, MediaScanResult& result) {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return;

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

            // Find last EOI marker
            size_t eoiPos = 0;
            for (size_t i = 0; i < data.size() - 1; i++) {
                if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                    eoiPos = i + 2;
                }
            }

            if (eoiPos > 0 && eoiPos < data.size()) {
                size_t appendedSize = data.size() - eoiPos;
                if (appendedSize > 10) {
                    result.hasAppendedData = true;
                    result.appendedDataSize = appendedSize;
                    result.appendedData = std::vector<uint8_t>(
                        data.begin() + eoiPos,
                        data.end()
                    );

                    // Check if appended data is an archive
                    if (IsArchiveSignature(result.appendedData)) {
                        MediaThreat threat{};
                        threat.type = MediaThreatType::AppendedArchive;
                        threat.severity = 8;
                        threat.description = std::format("Appended archive detected ({} bytes)",
                            appendedSize);
                        threat.offset = static_cast<uint32_t>(eoiPos);
                        result.threats.push_back(threat);
                        result.riskScore += 35;
                    }

                    Logger::Warn("MediaFileScanner: JPEG has {} bytes of appended data",
                        appendedSize);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: JPEG appended data exception: {}", e.what());
        }
    }

    [[nodiscard]] bool IsArchiveSignature(const std::vector<uint8_t>& data) const {
        if (data.size() < 4) return false;

        // ZIP: PK\x03\x04
        if (data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04) {
            return true;
        }

        // RAR: Rar!
        if (data.size() >= 7 && data[0] == 'R' && data[1] == 'a' && data[2] == 'r' && data[3] == '!') {
            return true;
        }

        // 7z: 7z\xBC\xAF\x27\x1C
        if (data.size() >= 6 && data[0] == '7' && data[1] == 'z' && data[2] == 0xBC) {
            return true;
        }

        return false;
    }

    // ========================================================================
    // APPENDED DATA EXTRACTION
    // ========================================================================

    [[nodiscard]] bool HasAppendedDataImpl(const std::wstring& filePath) const {
        try {
            auto mediaType = DetectMediaType(filePath);

            if (mediaType == MediaType::JPEG) {
                std::ifstream file(filePath, std::ios::binary);
                if (!file) return false;

                file.seekg(0, std::ios::end);
                size_t fileSize = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<uint8_t> data(fileSize);
                file.read(reinterpret_cast<char*>(data.data()), fileSize);

                // Find last EOI
                size_t eoiPos = 0;
                for (size_t i = 0; i < fileSize - 1; i++) {
                    if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                        eoiPos = i + 2;
                    }
                }

                if (eoiPos > 0 && eoiPos < fileSize) {
                    return (fileSize - eoiPos) > 10;
                }
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: HasAppendedData exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<uint8_t> ExtractAppendedDataImpl(const std::wstring& filePath) const {
        try {
            auto mediaType = DetectMediaType(filePath);

            if (mediaType == MediaType::JPEG) {
                std::ifstream file(filePath, std::ios::binary);
                if (!file) return {};

                std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());

                // Find last EOI
                size_t eoiPos = 0;
                for (size_t i = 0; i < data.size() - 1; i++) {
                    if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                        eoiPos = i + 2;
                    }
                }

                if (eoiPos > 0 && eoiPos < data.size()) {
                    size_t appendedSize = data.size() - eoiPos;
                    if (appendedSize > 10) {
                        Logger::Info("MediaFileScanner: Extracted {} bytes of appended data",
                            appendedSize);
                        return std::vector<uint8_t>(data.begin() + eoiPos, data.end());
                    }
                }
            }

            return {};

        } catch (const std::exception& e) {
            Logger::Error("MediaFileScanner: ExtractAppendedData exception: {}", e.what());
            return {};
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

MediaFileScanner& MediaFileScanner::Instance() {
    static MediaFileScanner instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

MediaFileScanner::MediaFileScanner()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("MediaFileScanner: Constructor called");
}

MediaFileScanner::~MediaFileScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("MediaFileScanner: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool MediaFileScanner::Initialize(const MediaFileScannerConfig& config) {
    if (!m_impl) {
        Logger::Critical("MediaFileScanner: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void MediaFileScanner::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// SCANNING OPERATIONS
// ============================================================================

MediaScanResult MediaFileScanner::Scan(const std::wstring& filePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("MediaFileScanner: Not initialized");
        return MediaScanResult{};
    }

    return m_impl->ScanImpl(filePath);
}

StegoAnalysis MediaFileScanner::DetectSteganography(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("MediaFileScanner: Not initialized");
        return StegoAnalysis{};
    }

    auto mediaType = m_impl->DetectMediaType(filePath);
    return m_impl->DetectSteganographyImpl(filePath, mediaType);
}

MediaMetadata MediaFileScanner::ExtractMetadata(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("MediaFileScanner: Not initialized");
        return MediaMetadata{};
    }

    auto mediaType = m_impl->DetectMediaType(filePath);
    return m_impl->ExtractMetadataImpl(filePath, mediaType);
}

bool MediaFileScanner::HasAppendedData(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("MediaFileScanner: Not initialized");
        return false;
    }

    return m_impl->HasAppendedDataImpl(filePath);
}

std::vector<uint8_t> MediaFileScanner::ExtractAppendedData(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("MediaFileScanner: Not initialized");
        return {};
    }

    return m_impl->ExtractAppendedDataImpl(filePath);
}

// ============================================================================
// STATISTICS
// ============================================================================

const MediaFileScannerStatistics& MediaFileScanner::GetStatistics() const noexcept {
    static MediaFileScannerStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void MediaFileScanner::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("MediaFileScanner: Statistics reset");
    }
}

} // namespace FileSystem
} // namespace Core
} // namespace ShadowStrike
