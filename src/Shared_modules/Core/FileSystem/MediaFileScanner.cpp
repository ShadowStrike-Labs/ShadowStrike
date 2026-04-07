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

    // TIFF formats
    constexpr uint8_t TIFF_LE[4] = { 0x49, 0x49, 0x2A, 0x00 }; // Little-endian (II*\0)
    constexpr uint8_t TIFF_BE[4] = { 0x4D, 0x4D, 0x00, 0x2A }; // Big-endian (MM\0*)

    // WebP (RIFF container subtype)
    constexpr uint8_t WEBP[4] = { 0x57, 0x45, 0x42, 0x50 };
}

// ============================================================================
// PORTABLE SAFE INTEGER READERS (no unaligned access UB)
// ============================================================================

namespace SafeRead {
    [[nodiscard]] inline constexpr uint16_t U16BE(const uint8_t* p) noexcept {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(p[0]) << 8) | p[1]);
    }
    [[nodiscard]] inline constexpr uint16_t U16LE(const uint8_t* p) noexcept {
        return static_cast<uint16_t>(
            p[0] | (static_cast<uint16_t>(p[1]) << 8));
    }
    [[nodiscard]] inline constexpr uint32_t U32BE(const uint8_t* p) noexcept {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8)  |
               static_cast<uint32_t>(p[3]);
    }
    [[nodiscard]] inline constexpr uint32_t U32LE(const uint8_t* p) noexcept {
        return static_cast<uint32_t>(p[0])        |
               (static_cast<uint32_t>(p[1]) << 8)  |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }
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
        case StegoTechnique::EOFAppended: return "End-of-File Appended";
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

class MediaFileScannerImpl final {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================
    mutable std::shared_mutex m_configMutex;
    std::atomic<bool> m_initialized{false};
    MediaFileScannerConfig m_config{};
    MediaFileScannerStatistics m_stats{};

    // Size/depth limits
    static constexpr uint64_t MAX_SCAN_FILE_SIZE      = 100ULL * 1024 * 1024;
    static constexpr uint64_t MAX_APPENDED_EXTRACT     = 10ULL * 1024 * 1024;
    static constexpr size_t   HEADER_PEEK_SIZE         = 4096;
    static constexpr size_t   MIN_APPENDED_THRESHOLD   = 16;
    static constexpr size_t   SUSPICIOUS_META_SIZE     = 10000;
    static constexpr uint8_t  MAX_RISK_SCORE           = 100;
    static constexpr size_t   MAX_EXIF_IFD_ENTRIES     = 200;
    static constexpr int      MAX_IFD_CHAIN_DEPTH      = 8;

    MediaFileScannerImpl() = default;
    ~MediaFileScannerImpl() = default;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const MediaFileScannerConfig& config) {
        std::unique_lock lock(m_configMutex);
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"MediaFileScanner", L"Already initialized");
            return true;
        }
        try {
            SS_LOG_INFO(L"MediaFileScanner", L"Initializing media file scanner");
            m_config = config;
            m_stats.Reset();
            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"MediaFileScanner", L"Initialization complete");
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner", L"Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);
        if (!m_initialized.load(std::memory_order_acquire)) return;
        SS_LOG_INFO(L"MediaFileScanner", L"Shutting down media file scanner");
        m_initialized.store(false, std::memory_order_release);
    }

    // ========================================================================
    // FILE I/O HELPERS
    // ========================================================================

    [[nodiscard]] std::vector<uint8_t> ReadFileCapped(
        const std::wstring& filePath, uint64_t maxBytes
    ) const {
        try {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file) return {};
            const auto pos = file.tellg();
            if (pos < 0) return {};
            const auto fileSize = static_cast<uint64_t>(pos);
            if (fileSize == 0) return {};
            if (fileSize > maxBytes) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"File exceeds scan size limit (%llu > %llu bytes)",
                    fileSize, maxBytes);
                return {};
            }
            file.seekg(0, std::ios::beg);
            std::vector<uint8_t> data(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(data.data()),
                      static_cast<std::streamsize>(fileSize));
            if (static_cast<uint64_t>(file.gcount()) != fileSize) {
                data.resize(static_cast<size_t>(file.gcount()));
            }
            return data;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner", L"ReadFileCapped exception: %hs", e.what());
            return {};
        }
    }

    [[nodiscard]] std::vector<uint8_t> ReadFileHeader(
        const std::wstring& filePath, size_t headerSize
    ) const {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return {};
            std::vector<uint8_t> data(headerSize);
            file.read(reinterpret_cast<char*>(data.data()),
                      static_cast<std::streamsize>(headerSize));
            data.resize(static_cast<size_t>(file.gcount()));
            return data;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner", L"ReadFileHeader exception: %hs", e.what());
            return {};
        }
    }

    // ========================================================================
    // JPEG EOI FINDER (single implementation, used everywhere)
    // ========================================================================

    [[nodiscard]] std::optional<size_t> FindJpegLastEoi(
        const std::vector<uint8_t>& data
    ) const noexcept {
        if (data.size() < 4) return std::nullopt;
        std::optional<size_t> lastEoi;
        for (size_t i = 0; i + 1 < data.size(); ++i) {
            if (data[i] == 0xFF && data[i + 1] == 0xD9) {
                lastEoi = i + 2;
            }
        }
        return lastEoi;
    }

    // ========================================================================
    // RISK SCORE (clamped to prevent uint8_t overflow)
    // ========================================================================

    static void AddRisk(MediaScanResult& result, uint8_t points) noexcept {
        uint16_t total = static_cast<uint16_t>(result.riskScore) + points;
        result.riskScore = static_cast<uint8_t>(
            std::min<uint16_t>(total, MAX_RISK_SCORE));
    }

    // ========================================================================
    // FORMAT DETECTION
    // ========================================================================

    [[nodiscard]] MediaType DetectMediaType(const std::wstring& filePath) const {
        try {
            auto header = ReadFileHeader(filePath, 16);
            return DetectMediaTypeFromData(header);
        } catch (...) {
            return MediaType::Unknown;
        }
    }

    [[nodiscard]] MediaType DetectMediaTypeFromData(
        const std::vector<uint8_t>& h
    ) const noexcept {
        if (h.size() < 2) return MediaType::Unknown;

        if (h[0] == 0xFF && h[1] == 0xD8)
            return MediaType::JPEG;

        if (h.size() >= 8 &&
            std::equal(MagicNumbers::PNG_SIGNATURE,
                       MagicNumbers::PNG_SIGNATURE + 8, h.begin()))
            return MediaType::PNG;

        if (h.size() >= 6 &&
            (std::equal(MagicNumbers::GIF_87A, MagicNumbers::GIF_87A + 6, h.begin()) ||
             std::equal(MagicNumbers::GIF_89A, MagicNumbers::GIF_89A + 6, h.begin())))
            return MediaType::GIF;

        if (h[0] == 0x42 && h[1] == 0x4D)
            return MediaType::BMP;

        if (h.size() >= 4 &&
            (std::equal(MagicNumbers::TIFF_LE, MagicNumbers::TIFF_LE + 4, h.begin()) ||
             std::equal(MagicNumbers::TIFF_BE, MagicNumbers::TIFF_BE + 4, h.begin())))
            return MediaType::TIFF;

        if (h.size() >= 12 &&
            std::equal(MagicNumbers::RIFF, MagicNumbers::RIFF + 4, h.begin())) {
            if (std::equal(MagicNumbers::WAVE, MagicNumbers::WAVE + 4, h.begin() + 8))
                return MediaType::WAV;
            if (std::equal(MagicNumbers::WEBP, MagicNumbers::WEBP + 4, h.begin() + 8))
                return MediaType::WebP;
        }

        if (h.size() >= 3 &&
            std::equal(MagicNumbers::ID3, MagicNumbers::ID3 + 3, h.begin()))
            return MediaType::MP3;

        if (h.size() >= 8 &&
            std::equal(MagicNumbers::FTYP, MagicNumbers::FTYP + 4, h.begin() + 4))
            return MediaType::MP4;

        return MediaType::Unknown;
    }

    // ========================================================================
    // FORMAT VALIDATION
    // ========================================================================

    [[nodiscard]] bool ValidateFormat(
        const std::vector<uint8_t>& data, MediaType type
    ) const {
        try {
            switch (type) {
                case MediaType::JPEG: return ValidateJPEG(data);
                case MediaType::PNG:  return ValidatePNG(data);
                case MediaType::GIF:  return ValidateGIF(data);
                case MediaType::BMP:  return ValidateBMP(data);
                case MediaType::TIFF: return ValidateTIFF(data);
                default: return true;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Format validation exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ValidateJPEG(const std::vector<uint8_t>& data) const {
        if (data.size() < 4) return false;
        if (data[0] != 0xFF || data[1] != 0xD8) {
            SS_LOG_WARN(L"MediaFileScanner", L"Invalid JPEG SOI marker");
            return false;
        }
        // Walk marker segments to validate structure
        size_t pos = 2;
        bool foundSOS = false;
        while (pos + 1 < data.size()) {
            if (data[pos] != 0xFF) {
                if (foundSOS) break;
                SS_LOG_WARN(L"MediaFileScanner",
                    L"JPEG: unexpected byte 0x%02X at offset %zu",
                    data[pos], pos);
                return false;
            }
            while (pos + 1 < data.size() && data[pos + 1] == 0xFF) ++pos;
            if (pos + 1 >= data.size()) break;
            uint8_t marker = data[pos + 1];
            pos += 2;
            if (marker == 0xD9) return true;
            if (marker == 0xDA) { foundSOS = true; break; }
            if (marker == 0x00) continue;
            // RST markers (standalone, no length)
            if (marker >= 0xD0 && marker <= 0xD7) continue;
            if (pos + 1 >= data.size()) return false;
            uint16_t segLen = SafeRead::U16BE(&data[pos]);
            if (segLen < 2) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"JPEG: invalid segment length %u at offset %zu", segLen, pos);
                return false;
            }
            if (pos + segLen > data.size()) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"JPEG: segment overflows file at offset %zu", pos);
                return false;
            }
            pos += segLen;
        }
        if (foundSOS) {
            return FindJpegLastEoi(data).has_value();
        }
        return false;
    }

    [[nodiscard]] bool ValidatePNG(const std::vector<uint8_t>& data) const {
        if (data.size() < 29) return false;
        if (!std::equal(MagicNumbers::PNG_SIGNATURE,
                       MagicNumbers::PNG_SIGNATURE + 8, data.begin())) {
            SS_LOG_WARN(L"MediaFileScanner", L"Invalid PNG signature");
            return false;
        }
        if (data[12] != 'I' || data[13] != 'H' ||
            data[14] != 'D' || data[15] != 'R') {
            SS_LOG_WARN(L"MediaFileScanner", L"PNG missing IHDR chunk");
            return false;
        }
        uint32_t ihdrLen = SafeRead::U32BE(&data[8]);
        if (ihdrLen != 13) {
            SS_LOG_WARN(L"MediaFileScanner",
                L"PNG: invalid IHDR length %u", ihdrLen);
            return false;
        }
        uint32_t width  = SafeRead::U32BE(&data[16]);
        uint32_t height = SafeRead::U32BE(&data[20]);
        if (width == 0 || height == 0 || width > 100000 || height > 100000) {
            SS_LOG_WARN(L"MediaFileScanner",
                L"PNG: suspicious dimensions %ux%u", width, height);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ValidateGIF(const std::vector<uint8_t>& data) const {
        if (data.size() < 13) return false;
        bool v87 = std::equal(MagicNumbers::GIF_87A,
                              MagicNumbers::GIF_87A + 6, data.begin());
        bool v89 = std::equal(MagicNumbers::GIF_89A,
                              MagicNumbers::GIF_89A + 6, data.begin());
        if (!v87 && !v89) {
            SS_LOG_WARN(L"MediaFileScanner", L"Invalid GIF signature");
            return false;
        }
        uint16_t w = SafeRead::U16LE(&data[6]);
        uint16_t h = SafeRead::U16LE(&data[8]);
        if (w == 0 || h == 0) {
            SS_LOG_WARN(L"MediaFileScanner", L"GIF: zero dimensions");
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ValidateBMP(const std::vector<uint8_t>& data) const {
        if (data.size() < 26) return false;
        if (data[0] != 0x42 || data[1] != 0x4D) {
            SS_LOG_WARN(L"MediaFileScanner", L"Invalid BMP signature");
            return false;
        }
        uint32_t dataOffset = SafeRead::U32LE(&data[10]);
        uint32_t dibSize    = SafeRead::U32LE(&data[14]);
        if (dataOffset > data.size()) {
            SS_LOG_WARN(L"MediaFileScanner",
                L"BMP: data offset %u exceeds file size %zu",
                dataOffset, data.size());
            return false;
        }
        if (dibSize >= 40 && data.size() >= 30) {
            int32_t w = static_cast<int32_t>(SafeRead::U32LE(&data[18]));
            int32_t h = static_cast<int32_t>(SafeRead::U32LE(&data[22]));
            uint16_t bpp = SafeRead::U16LE(&data[28]);
            if (w <= 0 || w > 100000) {
                SS_LOG_WARN(L"MediaFileScanner", L"BMP: suspicious width %d", w);
                return false;
            }
            int32_t ah = (h < 0) ? -h : h;
            if (ah <= 0 || ah > 100000) {
                SS_LOG_WARN(L"MediaFileScanner", L"BMP: suspicious height %d", h);
                return false;
            }
            // Integer overflow check on pixel data size
            uint64_t pixelSize = static_cast<uint64_t>(w) *
                                 static_cast<uint64_t>(ah) *
                                 ((bpp > 0) ? ((bpp + 7u) / 8u) : 1u);
            if (pixelSize > 4ULL * 1024 * 1024 * 1024) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"BMP: pixel data exceeds 4GB (%llu bytes)", pixelSize);
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool ValidateTIFF(const std::vector<uint8_t>& data) const {
        if (data.size() < 8) return false;
        bool le = (data[0] == 0x49 && data[1] == 0x49);
        bool be = (data[0] == 0x4D && data[1] == 0x4D);
        if (!le && !be) return false;
        uint16_t magic = le ? SafeRead::U16LE(&data[2])
                            : SafeRead::U16BE(&data[2]);
        if (magic != 42) {
            SS_LOG_WARN(L"MediaFileScanner", L"TIFF: invalid magic %u", magic);
            return false;
        }
        uint32_t ifdOff = le ? SafeRead::U32LE(&data[4])
                             : SafeRead::U32BE(&data[4]);
        if (ifdOff >= data.size() || ifdOff < 8) {
            SS_LOG_WARN(L"MediaFileScanner",
                L"TIFF: invalid IFD offset %u", ifdOff);
            return false;
        }
        // Walk IFD chain with depth limit (detect directory chain attacks)
        uint32_t cur = ifdOff;
        int depth = 0;
        while (cur != 0 && depth < MAX_IFD_CHAIN_DEPTH) {
            if (cur + 2 > data.size()) break;
            uint16_t n = le ? SafeRead::U16LE(&data[cur])
                            : SafeRead::U16BE(&data[cur]);
            if (n > MAX_EXIF_IFD_ENTRIES) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"TIFF: excessive IFD entries %u at depth %d", n, depth);
                return false;
            }
            size_t nextOff = static_cast<size_t>(cur) + 2 +
                             static_cast<size_t>(n) * 12;
            if (nextOff + 4 > data.size()) break;
            cur = le ? SafeRead::U32LE(&data[nextOff])
                     : SafeRead::U32BE(&data[nextOff]);
            ++depth;
        }
        if (depth >= MAX_IFD_CHAIN_DEPTH) {
            SS_LOG_WARN(L"MediaFileScanner",
                L"TIFF: IFD chain depth limit reached (possible attack)");
            return false;
        }
        return true;
    }

    // ========================================================================
    // FULL SCAN IMPLEMENTATION
    // ========================================================================

    [[nodiscard]] MediaScanResult ScanImpl(const std::wstring& filePath) {
        MediaScanResult result{};
        const auto scanStart = steady_clock::now();
        try {
            result.filePath = filePath;

            std::error_code ec;
            if (!fs::exists(filePath, ec)) {
                SS_LOG_ERROR(L"MediaFileScanner", L"File not found");
                return result;
            }
            result.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_ERROR(L"MediaFileScanner",
                    L"Cannot get file size: %hs", ec.message().c_str());
                return result;
            }

            // Read file (capped at limit)
            auto data = ReadFileCapped(filePath, MAX_SCAN_FILE_SIZE);
            bool fullData = !data.empty() && (data.size() == result.fileSize);
            if (data.empty()) {
                data = ReadFileHeader(filePath, HEADER_PEEK_SIZE);
                if (data.empty()) {
                    SS_LOG_ERROR(L"MediaFileScanner", L"Cannot read file");
                    return result;
                }
                SS_LOG_WARN(L"MediaFileScanner",
                    L"File too large (%llu bytes), header-only analysis",
                    result.fileSize);
            }

            // Snapshot config under shared lock
            MediaFileScannerConfig cfg;
            {
                std::shared_lock lock(m_configMutex);
                cfg = m_config;
            }

            result.mediaType = DetectMediaTypeFromData(data);
            if (result.mediaType == MediaType::Unknown) {
                SS_LOG_DEBUG(L"MediaFileScanner",
                    L"Unknown media type, limited analysis");
            }

            result.isValid = ValidateFormat(data, result.mediaType);

            if (cfg.extractMetadata)
                result.metadata = ParseMetadata(data, result.mediaType);

            if (cfg.detectSteganography && fullData) {
                result.stego = AnalyzeSteganography(data, result.mediaType);
                if (result.stego.stegoDetected) {
                    result.isSuspicious = true;
                    AddRisk(result, 40);
                    MediaThreat threat{};
                    threat.type = MediaThreatType::Steganography;
                    threat.severity = 7;
                    threat.description = std::format(
                        "Steganography detected: {}",
                        StegoTechniqueToString(result.stego.technique));
                    result.threats.push_back(std::move(threat));
                }
            }

            if (cfg.detectExploits)
                DetectExploits(data, filePath, result);

            if (cfg.analyzeAppendedData && fullData)
                AnalyzeAppendedData(data, result);

            if (result.riskScore >= 80) {
                result.isMalicious = true;
            } else if (result.riskScore >= 40) {
                result.isSuspicious = true;
            }

            m_stats.filesScanned.fetch_add(1, std::memory_order_relaxed);
            if (result.stego.stegoDetected)
                m_stats.stegoDetected.fetch_add(1, std::memory_order_relaxed);
            if (!result.threats.empty())
                m_stats.exploitsDetected.fetch_add(
                    static_cast<uint64_t>(result.threats.size()),
                    std::memory_order_relaxed);
            if (result.isMalicious)
                m_stats.maliciousFiles.fetch_add(1, std::memory_order_relaxed);

            result.scanDuration = duration_cast<milliseconds>(
                steady_clock::now() - scanStart);

            SS_LOG_INFO(L"MediaFileScanner",
                L"Scan complete - Risk: %u, Threats: %zu, Duration: %lld ms",
                static_cast<unsigned>(result.riskScore),
                result.threats.size(),
                static_cast<long long>(result.scanDuration.count()));

            return result;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Scan exception: %hs", e.what());
            result.scanDuration = duration_cast<milliseconds>(
                steady_clock::now() - scanStart);
            return result;
        }
    }

    // ========================================================================
    // STEGANOGRAPHY DETECTION
    // ========================================================================

    [[nodiscard]] StegoAnalysis AnalyzeSteganography(
        const std::vector<uint8_t>& data, MediaType type
    ) const {
        StegoAnalysis best{};
        try {
            auto tryBetter = [&](StegoAnalysis&& c) {
                if (c.confidence > best.confidence)
                    best = std::move(c);
            };
            tryBetter(DetectLSBStego(data, type));
            tryBetter(DetectEOFStego(data, type));
            tryBetter(DetectMetadataStego(data));
            if (type == MediaType::JPEG)
                tryBetter(DetectDctStego(data));

            best.stegoDetected = (best.confidence >= 0.6);
            if (best.stegoDetected) {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"Steganography detected - Technique: %hs, Confidence: %.2f",
                    StegoTechniqueToString(best.technique), best.confidence);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Steganography analysis exception: %hs", e.what());
        }
        return best;
    }

    [[nodiscard]] StegoAnalysis DetectLSBStego(
        const std::vector<uint8_t>& data, MediaType type
    ) const {
        StegoAnalysis result{};
        if (type != MediaType::PNG && type != MediaType::BMP)
            return result;
        if (data.size() < 1024)
            return result;

        try {
            // Skip header to reach pixel data region
            size_t dataStart = 0;
            if (type == MediaType::PNG && data.size() > 128) {
                dataStart = std::min<size_t>(128, data.size() / 4);
            } else if (type == MediaType::BMP && data.size() >= 14) {
                dataStart = SafeRead::U32LE(&data[10]);
                if (dataStart >= data.size()) dataStart = 0;
            }

            const size_t analysisEnd = std::min(
                data.size(), dataStart + 100000);
            if (analysisEnd <= dataStart + 256) return result;

            // Pairs of Values (PoV) chi-square test:
            // For each pair (2k, 2k+1), natural images have imbalanced
            // counts; LSB steganography equalizes them.
            std::array<uint64_t, 256> histogram{};
            size_t totalSamples = 0;
            for (size_t i = dataStart; i < analysisEnd; ++i) {
                histogram[data[i]]++;
                ++totalSamples;
            }

            double chiSquare = 0.0;
            size_t pairsAnalyzed = 0;
            for (size_t k = 0; k < 128; ++k) {
                uint64_t c0 = histogram[2 * k];
                uint64_t c1 = histogram[2 * k + 1];
                double expected = (c0 + c1) / 2.0;
                if (expected > 5.0) {
                    double d0 = static_cast<double>(c0) - expected;
                    double d1 = static_cast<double>(c1) - expected;
                    chiSquare += (d0 * d0) / expected + (d1 * d1) / expected;
                    ++pairsAnalyzed;
                }
            }

            if (pairsAnalyzed < 10) return result;

            double normalized = chiSquare / static_cast<double>(pairsAnalyzed);

            if (normalized < 1.0) {
                result.technique = StegoTechnique::LSB;
                result.confidence = std::min(0.95, 0.9 - normalized * 0.2);
                result.analysisDetails = std::format(
                    "PoV chi-square: {:.2f} (normalized: {:.4f}, {} pairs)",
                    chiSquare, normalized, pairsAnalyzed);
            } else if (normalized < 2.0) {
                result.technique = StegoTechnique::LSB;
                result.confidence = 0.5;
                result.analysisDetails = std::format(
                    "PoV chi-square marginal: {:.4f}", normalized);
            }
            return result;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"LSB analysis exception: %hs", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectEOFStego(
        const std::vector<uint8_t>& data, MediaType type
    ) const {
        StegoAnalysis result{};
        try {
            if (type != MediaType::JPEG) return result;
            auto eoiOpt = FindJpegLastEoi(data);
            if (!eoiOpt.has_value()) return result;
            size_t eoiPos = *eoiOpt;
            if (eoiPos >= data.size()) return result;

            size_t appendedSize = data.size() - eoiPos;
            if (appendedSize <= MIN_APPENDED_THRESHOLD) return result;

            result.technique = StegoTechnique::EOFAppended;
            result.confidence = 0.9;
            result.estimatedPayloadSize = appendedSize;
            result.analysisDetails = std::format(
                "{} bytes after JPEG EOI marker", appendedSize);

            size_t extractSize = std::min(
                appendedSize, static_cast<size_t>(MAX_APPENDED_EXTRACT));
            result.extractedData.assign(
                data.begin() + eoiPos,
                data.begin() + eoiPos + extractSize);

            SS_LOG_WARN(L"MediaFileScanner",
                L"EOF steganography: %zu bytes appended after JPEG EOI",
                appendedSize);
            return result;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"EOF stego analysis exception: %hs", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectMetadataStego(
        const std::vector<uint8_t>& data
    ) const {
        StegoAnalysis result{};
        try {
            size_t totalMetaSize = 0;

            // JPEG APP/COM marker metadata
            if (data.size() >= 4 && data[0] == 0xFF && data[1] == 0xD8) {
                size_t pos = 2;
                while (pos + 3 < data.size()) {
                    if (data[pos] != 0xFF) break;
                    uint8_t marker = data[pos + 1];
                    if (marker == 0xDA || marker == 0xD9) break;
                    if (marker == 0x00 ||
                        (marker >= 0xD0 && marker <= 0xD7)) {
                        pos += 2;
                        continue;
                    }
                    uint16_t segLen = SafeRead::U16BE(&data[pos + 2]);
                    if (segLen < 2 || pos + 2 + segLen > data.size()) break;
                    if ((marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE)
                        totalMetaSize += segLen;
                    pos += 2 + segLen;
                }
            }

            // PNG text chunks
            if (data.size() >= 8 &&
                std::equal(MagicNumbers::PNG_SIGNATURE,
                           MagicNumbers::PNG_SIGNATURE + 8, data.begin())) {
                size_t pos = 8;
                while (pos + 12 <= data.size()) {
                    uint32_t chunkLen = SafeRead::U32BE(&data[pos]);
                    if (chunkLen > data.size() - pos - 12) break;
                    std::string ct(reinterpret_cast<const char*>(
                        &data[pos + 4]), 4);
                    if (ct == "tEXt" || ct == "zTXt" || ct == "iTXt")
                        totalMetaSize += chunkLen;
                    if (ct == "IEND") break;
                    pos += 12 + chunkLen;
                }
            }

            if (totalMetaSize > SUSPICIOUS_META_SIZE) {
                result.technique = StegoTechnique::Metadata;
                result.confidence = std::min(0.85,
                    0.55 + static_cast<double>(totalMetaSize -
                        SUSPICIOUS_META_SIZE) / 100000.0);
                result.estimatedPayloadSize = totalMetaSize;
                result.analysisDetails = std::format(
                    "{} bytes in metadata segments", totalMetaSize);
                SS_LOG_WARN(L"MediaFileScanner",
                    L"Large metadata: %zu bytes", totalMetaSize);
            }
            return result;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Metadata stego analysis exception: %hs", e.what());
            return result;
        }
    }

    [[nodiscard]] StegoAnalysis DetectDctStego(
        const std::vector<uint8_t>& data
    ) const {
        StegoAnalysis result{};
        try {
            if (data.size() < 100) return result;

            // Find SOS marker to locate entropy-coded data
            size_t sosPos = 0;
            for (size_t i = 2; i + 3 < data.size(); ++i) {
                if (data[i] == 0xFF && data[i + 1] == 0xDA) {
                    uint16_t hdrLen = SafeRead::U16BE(&data[i + 2]);
                    if (i + 2 + hdrLen < data.size())
                        sosPos = i + 2 + hdrLen;
                    break;
                }
            }
            if (sosPos == 0 || sosPos >= data.size()) return result;

            // Analyze byte distribution in entropy-coded segment.
            // JSteg-like tools modify LSBs of Huffman codes, creating
            // anomalous uniformity in even/odd byte-value pairs.
            std::array<uint64_t, 256> histogram{};
            size_t entropySamples = 0;
            size_t analyzeEnd = std::min(data.size(), sosPos + 200000);

            for (size_t i = sosPos; i < analyzeEnd; ++i) {
                if (data[i] == 0xFF && i + 1 < analyzeEnd) {
                    if (data[i + 1] == 0x00) { ++i; continue; }
                    if (data[i + 1] == 0xD9) break;
                    if (data[i + 1] >= 0xD0 && data[i + 1] <= 0xD7) {
                        ++i; continue;
                    }
                }
                histogram[data[i]]++;
                ++entropySamples;
            }
            if (entropySamples < 1000) return result;

            // Entropy and LSB balance analysis
            double entropy = 0.0;
            for (auto count : histogram) {
                if (count == 0) continue;
                double p = static_cast<double>(count) /
                           static_cast<double>(entropySamples);
                entropy -= p * std::log2(p);
            }

            uint64_t lsb0 = 0, lsb1 = 0;
            for (size_t i = 0; i < 256; i += 2) {
                lsb0 += histogram[i];
                lsb1 += histogram[i + 1];
            }
            double lsbRatio = (entropySamples > 0)
                ? static_cast<double>(std::min(lsb0, lsb1)) /
                  static_cast<double>(std::max(lsb0, lsb1))
                : 0.0;

            // Suspiciously balanced LSBs in entropy data
            if (lsbRatio > 0.98 && entropy > 7.0) {
                result.technique = StegoTechnique::DCT;
                result.confidence = std::min(
                    0.90, 0.65 + (lsbRatio - 0.98) * 5.0);
                result.analysisDetails = std::format(
                    "DCT entropy: {:.3f} bits, LSB ratio: {:.4f} ({} samples)",
                    entropy, lsbRatio, entropySamples);
                SS_LOG_WARN(L"MediaFileScanner",
                    L"DCT stego indicator - LSB ratio: %.4f, entropy: %.3f",
                    lsbRatio, entropy);
            }
            return result;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"DCT stego analysis exception: %hs", e.what());
            return result;
        }
    }

    // ========================================================================
    // METADATA EXTRACTION
    // ========================================================================

    [[nodiscard]] MediaMetadata ParseMetadata(
        const std::vector<uint8_t>& data, MediaType type
    ) const {
        try {
            switch (type) {
                case MediaType::JPEG: return ExtractJPEGMetadata(data);
                case MediaType::PNG:  return ExtractPNGMetadata(data);
                case MediaType::BMP:  return ExtractBMPMetadata(data);
                case MediaType::TIFF: return ExtractTIFFMetadata(data);
                default: return {};
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Metadata extraction exception: %hs", e.what());
            return {};
        }
    }

    // ----- EXIF parser infrastructure -----

    struct ExifReader {
        const uint8_t* base;
        size_t tiffStart;
        size_t maxLen;
        bool bigEndian;

        [[nodiscard]] bool valid(size_t off, size_t len) const noexcept {
            size_t abs = tiffStart + off;
            return (abs + len <= maxLen) && (abs + len >= abs);
        }
        [[nodiscard]] uint16_t u16(size_t off) const noexcept {
            size_t abs = tiffStart + off;
            if (abs + 2 > maxLen) return 0;
            return bigEndian ? SafeRead::U16BE(base + abs)
                             : SafeRead::U16LE(base + abs);
        }
        [[nodiscard]] uint32_t u32(size_t off) const noexcept {
            size_t abs = tiffStart + off;
            if (abs + 4 > maxLen) return 0;
            return bigEndian ? SafeRead::U32BE(base + abs)
                             : SafeRead::U32LE(base + abs);
        }
        [[nodiscard]] std::string readAscii(
            size_t off, size_t len
        ) const {
            if (!valid(off, len) || len == 0) return {};
            size_t abs = tiffStart + off;
            size_t safeLen = std::min(len, size_t(2048));
            std::string s(reinterpret_cast<const char*>(base + abs), safeLen);
            while (!s.empty() && (s.back() == '\0' || s.back() < ' '))
                s.pop_back();
            return s;
        }
    };

    void ParseExifIfd(const ExifReader& reader, uint32_t ifdOffset,
                      MediaMetadata& meta, int depth) const {
        if (depth > MAX_IFD_CHAIN_DEPTH || ifdOffset == 0) return;
        if (!reader.valid(ifdOffset, 2)) return;

        uint16_t entryCount = reader.u16(ifdOffset);
        if (entryCount > MAX_EXIF_IFD_ENTRIES) return;

        static constexpr size_t typeSizes[] =
            { 0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8 };

        for (uint16_t i = 0; i < entryCount; ++i) {
            size_t eOff = static_cast<size_t>(ifdOffset) + 2 +
                          static_cast<size_t>(i) * 12;
            if (!reader.valid(static_cast<uint32_t>(eOff), 12)) return;

            uint16_t tag   = reader.u16(static_cast<uint32_t>(eOff));
            uint16_t type  = reader.u16(static_cast<uint32_t>(eOff + 2));
            uint32_t count = reader.u32(static_cast<uint32_t>(eOff + 4));

            if (type == 0 || type > 12) continue;

            size_t valueSize = static_cast<size_t>(count) * typeSizes[type];
            if (count > 0 && valueSize / count != typeSizes[type]) continue;
            if (valueSize > 1024 * 1024) continue;

            uint32_t valOff;
            if (valueSize <= 4) {
                valOff = static_cast<uint32_t>(eOff + 8 - reader.tiffStart);
            } else {
                valOff = reader.u32(static_cast<uint32_t>(eOff + 8));
            }

            switch (tag) {
                case 0x0100: // ImageWidth
                    meta.width = (type == 3) ? reader.u16(valOff)
                                             : reader.u32(valOff);
                    break;
                case 0x0101: // ImageHeight
                    meta.height = (type == 3) ? reader.u16(valOff)
                                              : reader.u32(valOff);
                    break;
                case 0x0102: // BitsPerSample
                    if (type == 3) meta.bitDepth = reader.u16(valOff);
                    break;
                case 0x010F: // Make
                    if (type == 2)
                        meta.cameraMake = reader.readAscii(valOff, count);
                    break;
                case 0x0110: // Model
                    if (type == 2)
                        meta.cameraModel = reader.readAscii(valOff, count);
                    break;
                case 0x010E: // ImageDescription
                case 0x9286: { // UserComment
                    if (type == 2 || type == 7) {
                        auto txt = reader.readAscii(
                            valOff, std::min<size_t>(count, 2048));
                        if (!txt.empty())
                            meta.comments.push_back(std::move(txt));
                    }
                    break;
                }
                case 0x0201: // JPEGInterchangeFormat (thumbnail offset)
                    if (reader.u32(valOff) > 0) meta.hasThumbnail = true;
                    break;
                case 0x8825: // GPS IFD
                    meta.hasGPS = true;
                    break;
                case 0x8769: // EXIF sub-IFD
                    ParseExifIfd(reader, reader.u32(valOff), meta, depth + 1);
                    break;
            }
        }

        // Follow IFD chain
        size_t nextOff = static_cast<size_t>(ifdOffset) + 2 +
                         static_cast<size_t>(entryCount) * 12;
        if (reader.valid(static_cast<uint32_t>(nextOff), 4)) {
            uint32_t nextIfd = reader.u32(static_cast<uint32_t>(nextOff));
            if (nextIfd > 0)
                ParseExifIfd(reader, nextIfd, meta, depth + 1);
        }
    }

    [[nodiscard]] MediaMetadata ExtractJPEGMetadata(
        const std::vector<uint8_t>& data
    ) const {
        MediaMetadata metadata{};
        if (data.size() < 4) return metadata;

        // Walk markers for APP1 (EXIF), COM, and SOF
        size_t pos = 2;
        while (pos + 3 < data.size()) {
            if (data[pos] != 0xFF) break;
            uint8_t marker = data[pos + 1];
            if (marker == 0xDA || marker == 0xD9) break;
            if (marker == 0x00 ||
                (marker >= 0xD0 && marker <= 0xD7)) {
                pos += 2;
                continue;
            }
            if (pos + 3 >= data.size()) break;
            uint16_t segLen = SafeRead::U16BE(&data[pos + 2]);
            if (segLen < 2 || pos + 2 + segLen > data.size()) break;

            // APP1 — EXIF
            if (marker == 0xE1 && segLen > 10) {
                const uint8_t* seg = &data[pos + 4];
                size_t segDataLen = segLen - 2;
                if (segDataLen > 8 &&
                    seg[0] == 'E' && seg[1] == 'x' &&
                    seg[2] == 'i' && seg[3] == 'f' &&
                    seg[4] == 0   && seg[5] == 0) {
                    size_t tiffLen = segDataLen - 6;
                    if (tiffLen >= 8) {
                        bool be = (seg[6] == 'M' && seg[7] == 'M');
                        ExifReader reader{};
                        reader.base = seg;
                        reader.tiffStart = 6;
                        reader.maxLen = segDataLen;
                        reader.bigEndian = be;
                        uint32_t ifd0 = reader.u32(4);
                        if (ifd0 > 0 && ifd0 < tiffLen)
                            ParseExifIfd(reader, ifd0, metadata, 0);
                    }
                }
            }

            // COM — comment
            if (marker == 0xFE && segLen > 2) {
                size_t cLen = std::min<size_t>(segLen - 2, 4096);
                std::string comment(
                    reinterpret_cast<const char*>(&data[pos + 4]), cLen);
                while (!comment.empty() &&
                       (comment.back() == '\0' || comment.back() < ' '))
                    comment.pop_back();
                if (!comment.empty())
                    metadata.comments.push_back(std::move(comment));
            }

            // SOF — dimensions
            if ((marker >= 0xC0 && marker <= 0xCF) &&
                marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
                if (segLen >= 7) {
                    metadata.bitDepth = data[pos + 4];
                    metadata.height = SafeRead::U16BE(&data[pos + 5]);
                    metadata.width  = SafeRead::U16BE(&data[pos + 7]);
                }
            }

            pos += 2 + segLen;
        }
        return metadata;
    }

    [[nodiscard]] MediaMetadata ExtractPNGMetadata(
        const std::vector<uint8_t>& data
    ) const {
        MediaMetadata metadata{};
        if (data.size() < 29) return metadata;

        metadata.width    = SafeRead::U32BE(&data[16]);
        metadata.height   = SafeRead::U32BE(&data[20]);
        metadata.bitDepth = data[24];

        size_t pos = 8;
        while (pos + 12 <= data.size()) {
            uint32_t chunkLen = SafeRead::U32BE(&data[pos]);
            if (chunkLen > data.size() - pos - 12) break;
            std::string ct(
                reinterpret_cast<const char*>(&data[pos + 4]), 4);
            if (ct == "tEXt" && chunkLen > 0 && chunkLen <= 65535) {
                size_t start = pos + 8;
                size_t len = std::min<size_t>(chunkLen, 4096);
                std::string text(
                    reinterpret_cast<const char*>(&data[start]), len);
                metadata.comments.push_back(std::move(text));
            }
            if (ct == "IEND") break;
            pos += 12 + chunkLen;
        }

        SS_LOG_DEBUG(L"MediaFileScanner", L"PNG: %ux%u, depth %u",
            metadata.width, metadata.height, metadata.bitDepth);
        return metadata;
    }

    [[nodiscard]] MediaMetadata ExtractBMPMetadata(
        const std::vector<uint8_t>& data
    ) const {
        MediaMetadata metadata{};
        if (data.size() < 30) return metadata;
        uint32_t dibSize = SafeRead::U32LE(&data[14]);
        if (dibSize >= 40) {
            metadata.width = SafeRead::U32LE(&data[18]);
            int32_t h = static_cast<int32_t>(SafeRead::U32LE(&data[22]));
            metadata.height = static_cast<uint32_t>(h < 0 ? -h : h);
            metadata.bitDepth = SafeRead::U16LE(&data[28]);
        }
        return metadata;
    }

    [[nodiscard]] MediaMetadata ExtractTIFFMetadata(
        const std::vector<uint8_t>& data
    ) const {
        MediaMetadata metadata{};
        if (data.size() < 8) return metadata;
        bool le = (data[0] == 0x49);
        auto u16at = [&](size_t off) -> uint16_t {
            if (off + 2 > data.size()) return 0;
            return le ? SafeRead::U16LE(&data[off])
                      : SafeRead::U16BE(&data[off]);
        };
        auto u32at = [&](size_t off) -> uint32_t {
            if (off + 4 > data.size()) return 0;
            return le ? SafeRead::U32LE(&data[off])
                      : SafeRead::U32BE(&data[off]);
        };
        uint32_t ifdOff = u32at(4);
        if (ifdOff + 2 > data.size()) return metadata;
        uint16_t entries = u16at(ifdOff);
        if (entries > MAX_EXIF_IFD_ENTRIES) return metadata;
        for (uint16_t i = 0; i < entries; ++i) {
            size_t eOff = static_cast<size_t>(ifdOff) + 2 +
                          static_cast<size_t>(i) * 12;
            if (eOff + 12 > data.size()) break;
            uint16_t tag  = u16at(eOff);
            uint16_t type = u16at(eOff + 2);
            switch (tag) {
                case 0x0100:
                    metadata.width = (type == 3) ? u16at(eOff + 8)
                                                 : u32at(eOff + 8);
                    break;
                case 0x0101:
                    metadata.height = (type == 3) ? u16at(eOff + 8)
                                                  : u32at(eOff + 8);
                    break;
                case 0x0102:
                    metadata.bitDepth = u16at(eOff + 8);
                    break;
            }
        }
        return metadata;
    }

    // ========================================================================
    // EXPLOIT DETECTION
    // ========================================================================

    void DetectExploits(const std::vector<uint8_t>& data,
                        const std::wstring& filePath,
                        MediaScanResult& result) {
        try {
            if (!result.isValid) {
                MediaThreat threat{};
                threat.type = MediaThreatType::MalformedHeader;
                threat.severity = 6;
                threat.description = "Malformed media header detected";
                result.threats.push_back(std::move(threat));
                AddRisk(result, 30);
            }

            auto peOff = FindEmbeddedExecutable(data);
            if (peOff.has_value()) {
                MediaThreat threat{};
                threat.type = MediaThreatType::EmbeddedExecutable;
                threat.severity = 9;
                threat.description = std::format(
                    "Embedded executable at offset {}", *peOff);
                threat.offset = static_cast<uint32_t>(*peOff);
                result.threats.push_back(std::move(threat));
                AddRisk(result, 50);
                result.isMalicious = true;
            }

            auto polyResult = DetectPolyglot(data, result.mediaType);
            if (!polyResult.empty()) {
                MediaThreat threat{};
                threat.type = MediaThreatType::Polyglot;
                threat.severity = 8;
                threat.description = std::format(
                    "Polyglot file: {}", polyResult);
                result.threats.push_back(std::move(threat));
                AddRisk(result, 40);
            }

            DetectScriptInjection(data, filePath, result);

            if (result.mediaType == MediaType::TIFF)
                DetectTiffAttacks(data, result);

            DetectMaliciousExif(data, result);
            DetectExtensionMismatch(filePath, data, result);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Exploit detection exception: %hs", e.what());
        }
    }

    [[nodiscard]] std::optional<size_t> FindEmbeddedExecutable(
        const std::vector<uint8_t>& data
    ) const {
        if (data.size() < 64) return std::nullopt;

        // Skip first 2 bytes (media magic) to avoid false positives
        for (size_t i = 2; i + 64 <= data.size(); ++i) {
            // PE: MZ header
            if (data[i] == 'M' && data[i + 1] == 'Z') {
                if (i + 0x3F < data.size()) {
                    uint32_t peOff = SafeRead::U32LE(&data[i + 0x3C]);
                    if (peOff < 1024 && i + peOff + 3 < data.size()) {
                        if (data[i + peOff] == 'P' &&
                            data[i + peOff + 1] == 'E' &&
                            data[i + peOff + 2] == 0 &&
                            data[i + peOff + 3] == 0) {
                            SS_LOG_WARN(L"MediaFileScanner",
                                L"PE signature at offset %zu", i);
                            return i;
                        }
                    }
                }
            }
            // ELF
            if (i + 3 < data.size() &&
                data[i] == 0x7F && data[i + 1] == 'E' &&
                data[i + 2] == 'L' && data[i + 3] == 'F') {
                SS_LOG_WARN(L"MediaFileScanner",
                    L"ELF signature at offset %zu", i);
                return i;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string DetectPolyglot(
        const std::vector<uint8_t>& data, MediaType primaryType
    ) const {
        if (data.size() < 16) return {};

        // JPEG+ZIP: ZIP signature after JPEG EOI
        if (primaryType == MediaType::JPEG) {
            auto eoiOpt = FindJpegLastEoi(data);
            if (eoiOpt.has_value() && *eoiOpt + 3 < data.size()) {
                size_t off = *eoiOpt;
                if (data[off] == 'P' && data[off + 1] == 'K' &&
                    data[off + 2] == 0x03 && data[off + 3] == 0x04) {
                    return "JPEG+ZIP polyglot";
                }
            }
        }

        // PNG+HTML: HTML after IEND chunk
        if (primaryType == MediaType::PNG) {
            size_t pos = 8;
            while (pos + 12 <= data.size()) {
                uint32_t cLen = SafeRead::U32BE(&data[pos]);
                if (cLen > data.size() - pos - 12) break;
                std::string ct(
                    reinterpret_cast<const char*>(&data[pos + 4]), 4);
                pos += 12 + cLen;
                if (ct == "IEND" && pos + 15 < data.size()) {
                    std::string tail(
                        reinterpret_cast<const char*>(&data[pos]),
                        std::min<size_t>(data.size() - pos, 1024));
                    if (tail.find("<html") != std::string::npos ||
                        tail.find("<HTML") != std::string::npos ||
                        tail.find("<script") != std::string::npos) {
                        return "PNG+HTML polyglot";
                    }
                    break;
                }
            }
        }

        // BMP+PE: PE at BMP pixel data offset
        if (primaryType == MediaType::BMP && data.size() >= 0x40) {
            uint32_t dataOff = SafeRead::U32LE(&data[10]);
            if (dataOff + 0x40 < data.size() &&
                data[dataOff] == 'M' && data[dataOff + 1] == 'Z') {
                uint32_t peOff = SafeRead::U32LE(&data[dataOff + 0x3C]);
                if (peOff < 1024 && dataOff + peOff + 3 < data.size() &&
                    data[dataOff + peOff] == 'P' &&
                    data[dataOff + peOff + 1] == 'E') {
                    return "BMP+PE polyglot";
                }
            }
        }

        // Generic: ZIP in second half of any image file
        if (primaryType != MediaType::Unknown && data.size() > 32) {
            size_t half = data.size() / 2;
            for (size_t i = std::max<size_t>(16, half);
                 i + 3 < data.size(); ++i) {
                if (data[i] == 'P' && data[i + 1] == 'K' &&
                    data[i + 2] == 0x03 && data[i + 3] == 0x04) {
                    return std::format(
                        "Image+ZIP polyglot (ZIP at offset {})", i);
                }
            }
        }
        return {};
    }

    void DetectScriptInjection(const std::vector<uint8_t>& data,
                               const std::wstring& filePath,
                               MediaScanResult& result) {
        if (data.size() < 5) return;

        // Heuristic: is the file text-based?
        bool textBased = true;
        size_t checkLen = std::min<size_t>(data.size(), 256);
        for (size_t i = 0; i < checkLen; ++i) {
            uint8_t c = data[i];
            if (c < 0x09 ||
                (c > 0x0D && c < 0x20 && c != 0x1B)) {
                textBased = false;
                break;
            }
        }
        if (!textBased) return;

        std::string content(
            reinterpret_cast<const char*>(data.data()),
            std::min<size_t>(data.size(), 32768));

        // SVG with embedded JavaScript
        bool isSvg = (content.find("<svg") != std::string::npos ||
                      content.find("<SVG") != std::string::npos);
        if (isSvg) {
            static const char* scriptPatterns[] = {
                "<script", "javascript:", "onload=", "onerror=",
                "onmouseover=", "onclick=", "onfocus=", "eval(",
                "document.cookie", "XMLHttpRequest", "fetch(",
                "String.fromCharCode"
            };
            for (const auto* pat : scriptPatterns) {
                if (content.find(pat) != std::string::npos) {
                    MediaThreat threat{};
                    threat.type = MediaThreatType::ScriptInjection;
                    threat.severity = 9;
                    threat.description =
                        "SVG with embedded JavaScript/event handlers";
                    result.threats.push_back(std::move(threat));
                    AddRisk(result, 50);
                    result.isMalicious = true;
                    SS_LOG_WARN(L"MediaFileScanner",
                        L"SVG script injection detected");
                    break;
                }
            }
        }

        // HTA disguised as image
        if (content.find("<HTA:APPLICATION") != std::string::npos ||
            content.find("<hta:application") != std::string::npos ||
            content.find("mshta") != std::string::npos) {
            MediaThreat threat{};
            threat.type = MediaThreatType::ScriptInjection;
            threat.severity = 10;
            threat.description =
                "HTA application disguised as media file";
            result.threats.push_back(std::move(threat));
            AddRisk(result, 50);
            result.isMalicious = true;
            SS_LOG_WARN(L"MediaFileScanner",
                L"HTA disguise detected");
        }
    }

    void DetectMaliciousExif(const std::vector<uint8_t>& data,
                             MediaScanResult& result) {
        if (result.metadata.comments.empty()) return;
        static const char* malPatterns[] = {
            "cmd.exe", "powershell", "cmd /c", "/bin/sh", "/bin/bash",
            "wget ", "curl ", "certutil", "bitsadmin",
            "<?php", "eval(", "exec(", "system(",
            "<script", "javascript:", "vbscript:",
            "base64_decode", "gzinflate",
            "rundll32", "regsvr32", "mshta",
            "WScript.Shell", "ActiveXObject"
        };
        for (const auto& comment : result.metadata.comments) {
            for (const auto* pat : malPatterns) {
                if (comment.find(pat) != std::string::npos) {
                    MediaThreat threat{};
                    threat.type = MediaThreatType::ScriptInjection;
                    threat.severity = 9;
                    threat.description = std::format(
                        "Malicious content in metadata: '{}' pattern",
                        pat);
                    result.threats.push_back(std::move(threat));
                    AddRisk(result, 45);
                    result.isMalicious = true;
                    SS_LOG_WARN(L"MediaFileScanner",
                        L"Malicious EXIF content: '%hs' in metadata",
                        pat);
                    return;
                }
            }
        }
    }

    void DetectTiffAttacks(const std::vector<uint8_t>& data,
                           MediaScanResult& result) {
        if (data.size() < 8) return;
        bool le = (data[0] == 0x49);
        auto u16at = [&](size_t off) -> uint16_t {
            if (off + 2 > data.size()) return 0;
            return le ? SafeRead::U16LE(&data[off])
                      : SafeRead::U16BE(&data[off]);
        };
        auto u32at = [&](size_t off) -> uint32_t {
            if (off + 4 > data.size()) return 0;
            return le ? SafeRead::U32LE(&data[off])
                      : SafeRead::U32BE(&data[off]);
        };

        std::vector<uint32_t> visited;
        uint32_t cur = u32at(4);
        int depth = 0;
        while (cur != 0 && depth < MAX_IFD_CHAIN_DEPTH) {
            if (std::find(visited.begin(), visited.end(), cur) !=
                visited.end()) {
                MediaThreat threat{};
                threat.type = MediaThreatType::CVEExploit;
                threat.severity = 8;
                threat.description =
                    "TIFF: circular IFD chain (DoS/exploit attempt)";
                threat.offset = cur;
                result.threats.push_back(std::move(threat));
                AddRisk(result, 40);
                SS_LOG_WARN(L"MediaFileScanner",
                    L"TIFF circular IFD at offset %u", cur);
                return;
            }
            visited.push_back(cur);
            if (cur + 2 > data.size()) break;
            uint16_t n = u16at(cur);
            if (n > MAX_EXIF_IFD_ENTRIES) break;

            for (uint16_t i = 0; i < n; ++i) {
                size_t eOff = static_cast<size_t>(cur) + 2 +
                              static_cast<size_t>(i) * 12;
                if (eOff + 12 > data.size()) break;
                uint16_t type = u16at(eOff + 2);
                uint32_t count = u32at(eOff + 4);
                if (type > 0 && type <= 12) {
                    static constexpr size_t ts[] =
                        { 0,1,1,2,4,8,1,1,2,4,8,4,8 };
                    size_t valSize =
                        static_cast<size_t>(count) * ts[type];
                    if (valSize > 4) {
                        uint32_t valOff = u32at(eOff + 8);
                        if (static_cast<size_t>(valOff) + valSize >
                            data.size()) {
                            MediaThreat threat{};
                            threat.type = MediaThreatType::BufferOverflow;
                            threat.severity = 7;
                            threat.description = std::format(
                                "TIFF: IFD entry points outside file "
                                "(offset {} + {} bytes)", valOff, valSize);
                            threat.offset = static_cast<uint32_t>(eOff);
                            result.threats.push_back(std::move(threat));
                            AddRisk(result, 30);
                        }
                    }
                }
            }

            size_t nextOff = static_cast<size_t>(cur) + 2 +
                             static_cast<size_t>(n) * 12;
            if (nextOff + 4 > data.size()) break;
            cur = u32at(nextOff);
            ++depth;
        }
    }

    void DetectExtensionMismatch(const std::wstring& filePath,
                                 const std::vector<uint8_t>& data,
                                 MediaScanResult& result) {
        try {
            auto ext = fs::path(filePath).extension().wstring();
            if (ext.empty()) return;
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

            MediaType claimed = MediaType::Unknown;
            if (ext == L".jpg" || ext == L".jpeg") claimed = MediaType::JPEG;
            else if (ext == L".png")  claimed = MediaType::PNG;
            else if (ext == L".gif")  claimed = MediaType::GIF;
            else if (ext == L".bmp")  claimed = MediaType::BMP;
            else if (ext == L".tiff" || ext == L".tif") claimed = MediaType::TIFF;
            else if (ext == L".webp") claimed = MediaType::WebP;
            else if (ext == L".ico")  claimed = MediaType::ICO;
            else if (ext == L".mp3")  claimed = MediaType::MP3;
            else if (ext == L".wav")  claimed = MediaType::WAV;
            else if (ext == L".mp4")  claimed = MediaType::MP4;
            else return;

            MediaType actual = DetectMediaTypeFromData(data);
            if (claimed != MediaType::Unknown &&
                actual != MediaType::Unknown && claimed != actual) {
                MediaThreat threat{};
                threat.type = MediaThreatType::MalformedHeader;
                threat.severity = 7;
                threat.description = std::format(
                    "Extension mismatch: claims {} but magic indicates {}",
                    MediaTypeToString(claimed), MediaTypeToString(actual));
                result.threats.push_back(std::move(threat));
                AddRisk(result, 25);
                SS_LOG_WARN(L"MediaFileScanner",
                    L"Extension mismatch: ext=%hs, magic=%hs",
                    MediaTypeToString(claimed), MediaTypeToString(actual));
            }
        } catch (...) {
            // Extension check is best-effort
        }
    }

    // ========================================================================
    // APPENDED DATA ANALYSIS
    // ========================================================================

    void AnalyzeAppendedData(const std::vector<uint8_t>& data,
                             MediaScanResult& result) {
        try {
            std::optional<size_t> endOfContent;
            if (result.mediaType == MediaType::JPEG) {
                endOfContent = FindJpegLastEoi(data);
            } else if (result.mediaType == MediaType::PNG) {
                size_t pos = 8;
                while (pos + 12 <= data.size()) {
                    uint32_t cLen = SafeRead::U32BE(&data[pos]);
                    if (cLen > data.size() - pos - 12) break;
                    std::string ct(
                        reinterpret_cast<const char*>(&data[pos + 4]), 4);
                    pos += 12 + cLen;
                    if (ct == "IEND") {
                        endOfContent = pos;
                        break;
                    }
                }
            }

            if (!endOfContent.has_value() ||
                *endOfContent >= data.size()) return;

            size_t appSize = data.size() - *endOfContent;
            if (appSize <= MIN_APPENDED_THRESHOLD) return;

            result.hasAppendedData = true;
            result.appendedDataSize = appSize;

            size_t extractSize = std::min(
                appSize, static_cast<size_t>(MAX_APPENDED_EXTRACT));
            result.appendedData.assign(
                data.begin() + *endOfContent,
                data.begin() + *endOfContent + extractSize);

            if (IsArchiveSignature(
                    &data[*endOfContent], appSize)) {
                MediaThreat threat{};
                threat.type = MediaThreatType::AppendedArchive;
                threat.severity = 8;
                threat.description = std::format(
                    "Appended archive ({} bytes)", appSize);
                threat.offset = static_cast<uint32_t>(*endOfContent);
                result.threats.push_back(std::move(threat));
                AddRisk(result, 35);
            }

            SS_LOG_WARN(L"MediaFileScanner",
                L"Appended data: %zu bytes after content end", appSize);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"Appended data analysis exception: %hs", e.what());
        }
    }

    [[nodiscard]] bool IsArchiveSignature(
        const uint8_t* p, size_t size
    ) const noexcept {
        if (size < 4) return false;
        if (p[0] == 'P' && p[1] == 'K' &&
            p[2] == 0x03 && p[3] == 0x04)
            return true;
        if (size >= 7 && p[0] == 'R' && p[1] == 'a' &&
            p[2] == 'r' && p[3] == '!')
            return true;
        if (size >= 6 && p[0] == '7' && p[1] == 'z' &&
            p[2] == 0xBC && p[3] == 0xAF)
            return true;
        if (p[0] == 0x1F && p[1] == 0x8B)
            return true;
        return false;
    }

    // ========================================================================
    // STANDALONE API WRAPPERS (read file, delegate to data-based methods)
    // ========================================================================

    [[nodiscard]] StegoAnalysis DetectSteganographyImpl(
        const std::wstring& filePath, MediaType type
    ) const {
        auto data = ReadFileCapped(filePath, MAX_SCAN_FILE_SIZE);
        if (data.empty()) return {};
        return AnalyzeSteganography(data, type);
    }

    [[nodiscard]] MediaMetadata ExtractMetadataImpl(
        const std::wstring& filePath, MediaType type
    ) const {
        auto data = ReadFileCapped(filePath, MAX_SCAN_FILE_SIZE);
        if (data.empty()) return {};
        return ParseMetadata(data, type);
    }

    [[nodiscard]] bool HasAppendedDataImpl(
        const std::wstring& filePath
    ) const {
        try {
            auto data = ReadFileCapped(filePath, MAX_SCAN_FILE_SIZE);
            if (data.empty()) return false;
            auto type = DetectMediaTypeFromData(data);
            if (type == MediaType::JPEG) {
                auto eoi = FindJpegLastEoi(data);
                if (eoi.has_value() && *eoi < data.size())
                    return (data.size() - *eoi) > MIN_APPENDED_THRESHOLD;
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::vector<uint8_t> ExtractAppendedDataImpl(
        const std::wstring& filePath
    ) const {
        try {
            auto data = ReadFileCapped(filePath, MAX_SCAN_FILE_SIZE);
            if (data.empty()) return {};
            auto type = DetectMediaTypeFromData(data);
            if (type == MediaType::JPEG) {
                auto eoi = FindJpegLastEoi(data);
                if (eoi.has_value() && *eoi < data.size()) {
                    size_t appSize = data.size() - *eoi;
                    if (appSize > MIN_APPENDED_THRESHOLD) {
                        size_t cap = std::min(
                            appSize,
                            static_cast<size_t>(MAX_APPENDED_EXTRACT));
                        SS_LOG_INFO(L"MediaFileScanner",
                            L"Extracted %zu bytes of appended data",
                            cap);
                        return std::vector<uint8_t>(
                            data.begin() + *eoi,
                            data.begin() + *eoi + cap);
                    }
                }
            }
            return {};
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MediaFileScanner",
                L"ExtractAppendedData exception: %hs", e.what());
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
    : m_impl(std::make_unique<MediaFileScannerImpl>())
{
    SS_LOG_INFO(L"MediaFileScanner", L"MediaFileScanner: Constructor called");
}

MediaFileScanner::~MediaFileScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"MediaFileScanner", L"MediaFileScanner: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool MediaFileScanner::Initialize(const MediaFileScannerConfig& config) {
    if (!m_impl) {
        SS_LOG_FATAL(L"MediaFileScanner", L"Implementation pointer is null");
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
        SS_LOG_ERROR(L"MediaFileScanner", L"MediaFileScanner: Not initialized");
        return MediaScanResult{};
    }

    return m_impl->ScanImpl(filePath);
}

StegoAnalysis MediaFileScanner::DetectSteganography(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"MediaFileScanner", L"MediaFileScanner: Not initialized");
        return StegoAnalysis{};
    }

    auto mediaType = m_impl->DetectMediaType(filePath);
    return m_impl->DetectSteganographyImpl(filePath, mediaType);
}

MediaMetadata MediaFileScanner::ExtractMetadata(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"MediaFileScanner", L"MediaFileScanner: Not initialized");
        return MediaMetadata{};
    }

    auto mediaType = m_impl->DetectMediaType(filePath);
    return m_impl->ExtractMetadataImpl(filePath, mediaType);
}

bool MediaFileScanner::HasAppendedData(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"MediaFileScanner", L"MediaFileScanner: Not initialized");
        return false;
    }

    return m_impl->HasAppendedDataImpl(filePath);
}

std::vector<uint8_t> MediaFileScanner::ExtractAppendedData(const std::wstring& filePath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"MediaFileScanner", L"MediaFileScanner: Not initialized");
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
        SS_LOG_INFO(L"MediaFileScanner", L"MediaFileScanner: Statistics reset");
    }
}

} // namespace FileSystem
} // namespace Core
} // namespace ShadowStrike
