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
 * ShadowStrike Core FileSystem - ARCHIVE EXTRACTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ArchiveExtractor.cpp
 * @brief Enterprise-grade secure archive extraction engine.
 *
 * Full production implementation with:
 * - Native ZIP parsing (PKZIP Local/Central directory)
 * - Real zip bomb detection (ratio, nesting, quine, overlap)
 * - Unicode-aware path traversal prevention
 * - Streaming extraction with cancellation
 * - LRU cache with TTL and concurrent-safe eviction
 * - Kernel scan request integration
 * - Per-entry entropy and hash computation
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
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
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/CompressionUtils.hpp"
#include "FileTypeAnalyzer.hpp"

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
#include <numeric>
#include <bit>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

using Utils::StringUtils::ToNarrow;
using Utils::StringUtils::ToLowerCopy;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // ────────────────────────────────────────────────────────────────────
    // ZIP format structures (PKZIP APPNOTE 6.3.10)
    // ────────────────────────────────────────────────────────────────────

#pragma pack(push, 1)

    struct ZipLocalFileHeader {
        uint32_t signature;         // 0x04034B50
        uint16_t versionNeeded;
        uint16_t flags;
        uint16_t compressionMethod;
        uint16_t lastModTime;
        uint16_t lastModDate;
        uint32_t crc32;
        uint32_t compressedSize;
        uint32_t uncompressedSize;
        uint16_t fileNameLength;
        uint16_t extraFieldLength;
    };
    static_assert(sizeof(ZipLocalFileHeader) == 30);

    struct ZipCentralDirEntry {
        uint32_t signature;         // 0x02014B50
        uint16_t versionMadeBy;
        uint16_t versionNeeded;
        uint16_t flags;
        uint16_t compressionMethod;
        uint16_t lastModTime;
        uint16_t lastModDate;
        uint32_t crc32;
        uint32_t compressedSize;
        uint32_t uncompressedSize;
        uint16_t fileNameLength;
        uint16_t extraFieldLength;
        uint16_t commentLength;
        uint16_t diskNumberStart;
        uint16_t internalAttributes;
        uint32_t externalAttributes;
        uint32_t localHeaderOffset;
    };
    static_assert(sizeof(ZipCentralDirEntry) == 46);

    struct ZipEndOfCentralDir {
        uint32_t signature;         // 0x06054B50
        uint16_t diskNumber;
        uint16_t diskWithCentralDir;
        uint16_t numEntriesThisDisk;
        uint16_t numEntriesTotal;
        uint32_t centralDirSize;
        uint32_t centralDirOffset;
        uint16_t commentLength;
    };
    static_assert(sizeof(ZipEndOfCentralDir) == 22);

    struct Zip64EndOfCentralDirLocator {
        uint32_t signature;         // 0x07064B50
        uint32_t diskWithZip64EOCD;
        uint64_t zip64EOCDOffset;
        uint32_t totalDisks;
    };

    struct Zip64EndOfCentralDir {
        uint32_t signature;         // 0x06064B50
        uint64_t sizeOfRecord;
        uint16_t versionMadeBy;
        uint16_t versionNeeded;
        uint32_t diskNumber;
        uint32_t diskWithCentralDir;
        uint64_t numEntriesThisDisk;
        uint64_t numEntriesTotal;
        uint64_t centralDirSize;
        uint64_t centralDirOffset;
    };

#pragma pack(pop)

    // ZIP signature constants
    constexpr uint32_t ZIP_LOCAL_SIG     = 0x04034B50;
    constexpr uint32_t ZIP_CENTRAL_SIG   = 0x02014B50;
    constexpr uint32_t ZIP_EOCD_SIG      = 0x06054B50;
    constexpr uint32_t ZIP_ZIP64_EOCD_LOCATOR_SIG = 0x07064B50;
    constexpr uint32_t ZIP_ZIP64_EOCD_SIG = 0x06064B50;
    constexpr uint16_t ZIP_DEFLATE       = 8;
    constexpr uint16_t ZIP_STORED        = 0;
    constexpr uint16_t ZIP_FLAG_ENCRYPTED = 0x0001;
    constexpr uint16_t ZIP_FLAG_DATA_DESCRIPTOR = 0x0008;
    constexpr uint16_t ZIP_FLAG_STRONG_ENCRYPTION = 0x0040;

    // ────────────────────────────────────────────────────────────────────
    // Magic signatures for format detection (constexpr-friendly)
    // ────────────────────────────────────────────────────────────────────

    struct MagicEntry {
        const uint8_t* bytes;
        size_t length;
        size_t offset;
        ArchiveFormat format;
    };

    constexpr uint8_t SIG_ZIP[]    = { 0x50, 0x4B, 0x03, 0x04 };
    constexpr uint8_t SIG_ZIPEMPTY[] = { 0x50, 0x4B, 0x05, 0x06 };
    constexpr uint8_t SIG_RAR4[]   = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
    constexpr uint8_t SIG_RAR5[]   = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
    constexpr uint8_t SIG_7Z[]     = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
    constexpr uint8_t SIG_GZIP[]   = { 0x1F, 0x8B };
    constexpr uint8_t SIG_BZIP2[]  = { 0x42, 0x5A, 0x68 };
    constexpr uint8_t SIG_XZ[]     = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
    constexpr uint8_t SIG_ZSTD[]   = { 0x28, 0xB5, 0x2F, 0xFD };
    constexpr uint8_t SIG_CAB[]    = { 0x4D, 0x53, 0x43, 0x46 };
    constexpr uint8_t SIG_ISO[]    = { 0x43, 0x44, 0x30, 0x30, 0x31 };  // at offset 0x8001
    constexpr uint8_t SIG_LZMA[]   = { 0x5D, 0x00, 0x00 };
    constexpr uint8_t SIG_TAR_USTAR[] = { 0x75, 0x73, 0x74, 0x61, 0x72 }; // at offset 257

    // Lookup table built once — no heap allocation
    static const MagicEntry MAGIC_TABLE[] = {
        { SIG_ZIP,      sizeof(SIG_ZIP),      0,     ArchiveFormat::ZIP },
        { SIG_ZIPEMPTY, sizeof(SIG_ZIPEMPTY),  0,     ArchiveFormat::ZIP },
        { SIG_RAR5,     sizeof(SIG_RAR5),      0,     ArchiveFormat::RAR5 },
        { SIG_RAR4,     sizeof(SIG_RAR4),      0,     ArchiveFormat::RAR },
        { SIG_7Z,       sizeof(SIG_7Z),        0,     ArchiveFormat::SevenZip },
        { SIG_GZIP,     sizeof(SIG_GZIP),      0,     ArchiveFormat::GZIP },
        { SIG_BZIP2,    sizeof(SIG_BZIP2),     0,     ArchiveFormat::BZIP2 },
        { SIG_XZ,       sizeof(SIG_XZ),        0,     ArchiveFormat::XZ },
        { SIG_ZSTD,     sizeof(SIG_ZSTD),      0,     ArchiveFormat::ZSTD },
        { SIG_CAB,      sizeof(SIG_CAB),       0,     ArchiveFormat::CAB },
        { SIG_LZMA,     sizeof(SIG_LZMA),      0,     ArchiveFormat::LZMA },
        { SIG_TAR_USTAR, sizeof(SIG_TAR_USTAR), 257,  ArchiveFormat::TAR },
        { SIG_ISO,      sizeof(SIG_ISO),       0x8001, ArchiveFormat::ISO },
    };
    constexpr size_t MAGIC_TABLE_SIZE = sizeof(MAGIC_TABLE) / sizeof(MAGIC_TABLE[0]);

    // Maximum header read size for magic detection (needs offset 0x8001 + 5 for ISO)
    constexpr size_t MAGIC_HEADER_READ_SIZE = 0x8001 + 8;

    // Entropy threshold for suspicious files
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.5;

    // ────────────────────────────────────────────────────────────────────
    // TAR format constants (POSIX.1-2001 / pax)
    // ────────────────────────────────────────────────────────────────────
    constexpr size_t  TAR_BLOCK_SIZE        = 512;
    constexpr size_t  TAR_NAME_OFFSET       = 0;
    constexpr size_t  TAR_NAME_LEN          = 100;
    constexpr size_t  TAR_MODE_OFFSET       = 100;
    constexpr size_t  TAR_SIZE_OFFSET       = 124;
    constexpr size_t  TAR_SIZE_LEN          = 12;
    constexpr size_t  TAR_MTIME_OFFSET      = 136;
    constexpr size_t  TAR_MTIME_LEN         = 12;
    constexpr size_t  TAR_CHKSUM_OFFSET     = 148;
    constexpr size_t  TAR_CHKSUM_LEN        = 8;
    constexpr size_t  TAR_TYPEFLAG_OFFSET   = 156;
    constexpr size_t  TAR_LINKNAME_OFFSET   = 157;
    constexpr size_t  TAR_LINKNAME_LEN      = 100;
    constexpr size_t  TAR_MAGIC_OFFSET      = 257;
    constexpr size_t  TAR_MAGIC_LEN         = 6;
    constexpr size_t  TAR_PREFIX_OFFSET     = 345;
    constexpr size_t  TAR_PREFIX_LEN        = 155;
    constexpr uint32_t TAR_MAX_ENTRIES      = 500000;
    constexpr uint64_t TAR_MAX_ENTRY_SIZE   = 4ULL * 1024 * 1024 * 1024; // 4 GiB per entry

    // TAR type flags
    constexpr char TAR_TYPE_REGULAR     = '0';
    constexpr char TAR_TYPE_REGULAR_ALT = '\0';  // Pre-POSIX compatibility
    constexpr char TAR_TYPE_LINK        = '1';
    constexpr char TAR_TYPE_SYMLINK     = '2';
    constexpr char TAR_TYPE_CHARDEV     = '3';
    constexpr char TAR_TYPE_BLOCKDEV    = '4';
    constexpr char TAR_TYPE_DIRECTORY   = '5';
    constexpr char TAR_TYPE_FIFO        = '6';
    constexpr char TAR_TYPE_LONGNAME    = 'L';   // GNU long filename
    constexpr char TAR_TYPE_LONGLINK    = 'K';   // GNU long linkname
    constexpr char TAR_TYPE_PAX_GLOBAL  = 'g';   // pax global extended header
    constexpr char TAR_TYPE_PAX_NEXT    = 'x';   // pax per-entry extended header

    // ────────────────────────────────────────────────────────────────────
    // GZIP format constants (RFC 1952)
    // ────────────────────────────────────────────────────────────────────
    constexpr size_t  GZIP_HEADER_MIN_SIZE  = 10;
    constexpr uint8_t GZIP_FLAG_FTEXT       = 0x01;
    constexpr uint8_t GZIP_FLAG_FHCRC       = 0x02;
    constexpr uint8_t GZIP_FLAG_FEXTRA      = 0x04;
    constexpr uint8_t GZIP_FLAG_FNAME       = 0x08;
    constexpr uint8_t GZIP_FLAG_FCOMMENT    = 0x10;
    constexpr size_t  GZIP_TRAILER_SIZE     = 8; // CRC32 + ISIZE

    // ────────────────────────────────────────────────────────────────────
    // RAR format constants
    // ────────────────────────────────────────────────────────────────────
    constexpr uint8_t RAR4_MARKER_SIZE      = 7;
    constexpr uint8_t RAR4_ARCHIVE_HEADER   = 0x73;
    constexpr uint8_t RAR4_FILE_HEADER      = 0x74;
    constexpr uint8_t RAR4_END_HEADER       = 0x7B;
    constexpr uint16_t RAR4_FLAG_LARGE      = 0x8000; // Large file (>2 GiB)
    constexpr uint16_t RAR4_FLAG_UNICODE    = 0x0200; // Unicode filename
    constexpr uint16_t RAR4_FLAG_ENCRYPTED  = 0x0004; // Encrypted file
    constexpr uint16_t RAR4_FLAG_DIRECTORY  = 0x00E0; // Directory entry (bits 5-7)
    constexpr uint32_t RAR4_MAX_ENTRIES     = 500000;

    // RAR5 header types
    constexpr uint32_t RAR5_HEADER_MAIN       = 1;
    constexpr uint32_t RAR5_HEADER_FILE       = 2;
    constexpr uint32_t RAR5_HEADER_SERVICE    = 3;
    constexpr uint32_t RAR5_HEADER_ENCRYPTION = 4;
    constexpr uint32_t RAR5_HEADER_END        = 5;

    // RAR5 file flags
    constexpr uint32_t RAR5_FILE_FLAG_DIRECTORY   = 0x0001;
    constexpr uint32_t RAR5_FILE_FLAG_UNIX_MTIME  = 0x0002;
    constexpr uint32_t RAR5_FILE_FLAG_CRC32       = 0x0004;
    constexpr uint32_t RAR5_FILE_FLAG_UNPACKED_KNOWN = 0x0008;

    // Windows reserved device names
    constexpr std::wstring_view RESERVED_NAMES[] = {
        L"CON", L"PRN", L"AUX", L"NUL",
        L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9",
    };

    // CRC32 lookup table
    constexpr uint32_t CRC32_POLYNOMIAL = 0xEDB88320;

    [[nodiscard]] static consteval std::array<uint32_t, 256> BuildCrc32Table() {
        std::array<uint32_t, 256> table{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLYNOMIAL : 0);
            }
            table[i] = crc;
        }
        return table;
    }
    static constexpr auto CRC32_TABLE = BuildCrc32Table();

    // ────────────────────────────────────────────────────────────────────
    // TAR helper: parse octal ASCII field into uint64_t
    // Handles both POSIX octal strings and GNU base-256 encoding.
    // ────────────────────────────────────────────────────────────────────
    [[nodiscard]] static uint64_t ParseTarOctal(
        const uint8_t* field, size_t length) noexcept {

        if (length == 0) return 0;

        // GNU base-256 encoding: high bit of first byte set
        if ((field[0] & 0x80) != 0) {
            // Positive value: strip the marker bit, read big-endian
            uint64_t value = field[0] & 0x7F;
            for (size_t i = 1; i < length; ++i) {
                value = (value << 8) | field[i];
            }
            return value;
        }

        // Standard POSIX: octal ASCII, skip leading spaces/zeros
        uint64_t value = 0;
        for (size_t i = 0; i < length; ++i) {
            if (field[i] == ' ' || field[i] == '\0') continue;
            if (field[i] < '0' || field[i] > '7') break;
            // Overflow guard: if value would exceed 2^60, cap
            if (value > (UINT64_MAX >> 3)) return UINT64_MAX;
            value = (value << 3) | static_cast<uint64_t>(field[i] - '0');
        }
        return value;
    }

    // ────────────────────────────────────────────────────────────────────
    // TAR helper: verify header checksum
    // ────────────────────────────────────────────────────────────────────
    [[nodiscard]] static bool VerifyTarChecksum(const uint8_t* block) noexcept {
        // Compute unsigned checksum treating checksum field as spaces
        uint32_t computed = 0;
        for (size_t i = 0; i < TAR_BLOCK_SIZE; ++i) {
            if (i >= TAR_CHKSUM_OFFSET && i < TAR_CHKSUM_OFFSET + TAR_CHKSUM_LEN) {
                computed += ' ';
            } else {
                computed += block[i];
            }
        }

        uint32_t stored = static_cast<uint32_t>(
            ParseTarOctal(block + TAR_CHKSUM_OFFSET, TAR_CHKSUM_LEN));

        // Also check signed checksum for compatibility with some archivers
        int32_t signedComputed = 0;
        for (size_t i = 0; i < TAR_BLOCK_SIZE; ++i) {
            if (i >= TAR_CHKSUM_OFFSET && i < TAR_CHKSUM_OFFSET + TAR_CHKSUM_LEN) {
                signedComputed += ' ';
            } else {
                signedComputed += static_cast<int8_t>(block[i]);
            }
        }

        return (computed == stored) ||
               (static_cast<uint32_t>(signedComputed) == stored);
    }

    // ────────────────────────────────────────────────────────────────────
    // TAR helper: check if block is all zeros (end-of-archive)
    // ────────────────────────────────────────────────────────────────────
    [[nodiscard]] static bool IsZeroBlock(const uint8_t* block) noexcept {
        // Use 8-byte comparisons for performance on 64-bit.  std::memcpy avoids
        // strict-aliasing UB and silently handles unaligned source buffers
        // (the input is uint8_t[] with no architectural alignment guarantee).
        for (size_t i = 0; i < TAR_BLOCK_SIZE; i += sizeof(uint64_t)) {
            uint64_t qword = 0;
            std::memcpy(&qword, block + i, sizeof(qword));
            if (qword != 0) return false;
        }
        return true;
    }

    // ────────────────────────────────────────────────────────────────────
    // TAR helper: extract null-terminated string from fixed-width field
    // ────────────────────────────────────────────────────────────────────
    [[nodiscard]] static std::string ExtractTarString(
        const uint8_t* field, size_t maxLen) noexcept {

        size_t len = 0;
        while (len < maxLen && field[len] != '\0') {
            ++len;
        }
        return std::string(reinterpret_cast<const char*>(field), len);
    }

    // ────────────────────────────────────────────────────────────────────
    // RAR5 helper: read variable-length integer (vint) from buffer
    // Returns bytes consumed, 0 on error.
    // ────────────────────────────────────────────────────────────────────
    [[nodiscard]] static size_t ReadRar5Vint(
        const uint8_t* data, size_t available, uint64_t& outValue) noexcept {

        outValue = 0;
        size_t bytesRead = 0;
        unsigned shift = 0;

        while (bytesRead < available && bytesRead < 10) {
            uint8_t b = data[bytesRead++];
            outValue |= static_cast<uint64_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return bytesRead;
            shift += 7;
        }

        return 0; // Unterminated vint
    }

} // anonymous namespace

// ============================================================================
// RAII FILE HANDLE GUARD
// ============================================================================

namespace {

    /// RAII wrapper for Win32 HANDLE — prevents leaks on all exit paths.
    struct ScopedHandle {
        HANDLE h{ INVALID_HANDLE_VALUE };

        explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
            : h(handle) {}

        ~ScopedHandle() noexcept {
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        ScopedHandle(ScopedHandle&& other) noexcept : h(other.h) {
            other.h = INVALID_HANDLE_VALUE;
        }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
                h = other.h;
                other.h = INVALID_HANDLE_VALUE;
            }
            return *this;
        }

        [[nodiscard]] bool valid() const noexcept {
            return h != INVALID_HANDLE_VALUE;
        }
        [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
        [[nodiscard]] HANDLE get() const noexcept { return h; }
    };

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

[[nodiscard]] static uint32_t ComputeCrc32(std::span<const uint8_t> data) noexcept {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

[[nodiscard]] static bool IsReservedDeviceName(std::wstring_view name) noexcept {
    // Strip extension if present
    auto dot = name.find(L'.');
    auto baseName = (dot != std::wstring_view::npos) ? name.substr(0, dot) : name;

    for (const auto& reserved : RESERVED_NAMES) {
        if (baseName.size() == reserved.size()) {
            bool match = true;
            for (size_t i = 0; i < baseName.size(); ++i) {
                wchar_t a = (baseName[i] >= L'a' && baseName[i] <= L'z')
                    ? (baseName[i] - L'a' + L'A') : baseName[i];
                wchar_t b = reserved[i];
                if (a != b) { match = false; break; }
            }
            if (match) return true;
        }
    }
    return false;
}

[[nodiscard]] static bool IsPathSafe(const std::wstring& path) noexcept {
    if (path.empty()) return false;

    // Reject absolute paths, UNC prefixes (\\server\share, \\?\, \\.\) and
    // any leading separator.  Two leading separators are an alias for UNC
    // even when the rest of the path looks relative on the wire.
    if (path[0] == L'/' || path[0] == L'\\') return false;
    if (path.length() >= 2 && (path[1] == L':')) return false;
    if (path.length() >= 2 &&
        (path[0] == L'\\' || path[0] == L'/') &&
        (path[1] == L'\\' || path[1] == L'/')) return false;

    // Reject path traversal — check every component
    size_t i = 0;
    while (i < path.size()) {
        size_t sep = path.find_first_of(L"/\\", i);
        if (sep == std::wstring::npos) sep = path.size();

        std::wstring_view component(path.data() + i, sep - i);

        // Reject ".." components (in any case form / mixed separators).
        if (component == L"..") return false;

        // Reject trailing dots/spaces — Windows silently strips these,
        // enabling evasion (e.g., "evil.exe." resolves to "evil.exe").
        if (!component.empty() &&
            (component.back() == L'.' || component.back() == L' ')) return false;

        // Reject reserved device names (CON, PRN, NUL, COM1-9, LPT1-9, ...).
        if (!component.empty() && IsReservedDeviceName(component)) return false;

        if (sep == path.size()) break;
        i = sep + 1;
    }

    // Reject characters that have caused ambiguity / evasion historically.
    for (wchar_t ch : path) {
        if (ch == L'<' || ch == L'>' || ch == L':' ||
            ch == L'"' || ch == L'|' || ch == L'?' || ch == L'*') return false;
        // Unicode normalization-evasion characters that can collapse to '.', '/', '\\'.
        if (ch == L'\xFF0E' /* fullwidth period         */ ||
            ch == L'\xFF0F' /* fullwidth solidus        */ ||
            ch == L'\x2215' /* division slash           */ ||
            ch == L'\x29F8' /* big solidus              */ ||
            ch == L'\xFF3C' /* fullwidth reverse solidus*/) return false;
        // Right-to-Left Override and related bidi controls used to spoof extensions.
        if (ch == L'\x202E' || ch == L'\x202D' ||
            ch == L'\x202A' || ch == L'\x202B' || ch == L'\x202C') return false;
        // Embedded NUL.
        if (ch == L'\0') return false;
        // C0 controls (TAB, LF, CR, ...) — never legitimate inside a stored filename.
        if (ch < 0x20) return false;
    }

    // Reject alternate data streams.
    if (path.find(L"::") != std::wstring::npos) return false;

    // Reject paths that are too long for the legacy MAX_PATH boundary.
    // Archive entries that need long paths must be sanitized via SanitizePath
    // and explicit long-path opt-in by the caller.
    if (path.size() > 260) return false;

    return true;
}

[[nodiscard]] static std::wstring SanitizePath(const std::wstring& path) noexcept {
    std::wstring result;
    result.reserve(path.size());

    size_t i = 0;
    // Strip leading slashes (covers UNC '\\server' and '\\?\' / '\\.\' device prefixes).
    while (i < path.size() && (path[i] == L'/' || path[i] == L'\\')) ++i;
    // Strip "?\" / ".\" right after the slashes (extended-length / device).
    if (i + 1 < path.size() && (path[i] == L'?' || path[i] == L'.') &&
        (path[i + 1] == L'\\' || path[i + 1] == L'/')) {
        i += 2;
    }
    // Strip drive letter prefix.
    if (i + 1 < path.size() && path[i + 1] == L':') i += 2;
    // Strip any further leading slashes that may have been left behind.
    while (i < path.size() && (path[i] == L'/' || path[i] == L'\\')) ++i;

    while (i < path.size()) {
        size_t sep = path.find_first_of(L"/\\", i);
        if (sep == std::wstring::npos) sep = path.size();

        std::wstring_view component(path.data() + i, sep - i);

        // Skip dangerous components.
        if (component == L".." || component == L"." || component.empty()) {
            i = sep + 1;
            continue;
        }

        // Strip trailing dots/spaces (Windows would otherwise resolve them away).
        size_t trim = component.size();
        while (trim > 0 &&
               (component[trim - 1] == L'.' || component[trim - 1] == L' ')) {
            --trim;
        }
        if (trim == 0) {
            i = sep + 1;
            continue;
        }
        component = component.substr(0, trim);

        // Check for reserved device names — prefix with underscore.
        bool isReserved = IsReservedDeviceName(component);

        if (!result.empty()) result += L'\\';

        if (isReserved) {
            result += L'_';
        }

        for (wchar_t ch : component) {
            // Replace dangerous chars (Win32 forbidden, Unicode evasion, controls).
            if (ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' ||
                ch == L'|' || ch == L'?' || ch == L'*' ||
                ch == L'\xFF0E' || ch == L'\xFF0F' || ch == L'\x2215' ||
                ch == L'\x29F8' || ch == L'\xFF3C' ||
                ch == L'\x202E' || ch == L'\x202D' ||
                ch == L'\x202A' || ch == L'\x202B' || ch == L'\x202C' ||
                ch == L'\0' || ch < 0x20) {
                result += L'_';
            } else {
                result += ch;
            }
        }

        i = sep + 1;
    }

    return result;
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
    opts.mode = ExtractionMode::InMemory;
    opts.maxCompressionRatio = 50.0;
    opts.maxNestingDepth = 3;
    opts.maxTotalSize = 1ULL * 1024 * 1024 * 1024;
    opts.maxEntrySize = 100ULL * 1024 * 1024;
    opts.maxEntries = 10000;
    opts.extractNestedArchives = false;
    opts.preserveTimestamps = false;
    opts.preservePermissions = false;
    opts.skipEncrypted = true;
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
    config.defaultMaxRatio = 50.0;
    config.defaultMaxNesting = 3;
    config.defaultMaxTotal = 1ULL * 1024 * 1024 * 1024;
    config.maxMemoryExtraction = 50 * 1024 * 1024;
    config.streamingBufferSize = 32 * 1024;
    config.workerThreads = 2;
    config.parallelExtraction = false;
    config.strictSecurityChecks = true;
    config.abortOnSecurityIssue = true;
    return config;
}

// ============================================================================
// INTERNAL ATOMIC STATISTICS (thread-safe counters)
// ============================================================================

struct AtomicStats {
    std::atomic<uint64_t> archivesProcessed{ 0 };
    std::atomic<uint64_t> entriesExtracted{ 0 };
    std::atomic<uint64_t> bytesExtracted{ 0 };
    std::atomic<uint64_t> zipBombsDetected{ 0 };
    std::atomic<uint64_t> pathTraversalsBlocked{ 0 };
    std::atomic<uint64_t> encryptedSkipped{ 0 };
    std::atomic<uint64_t> nestedArchives{ 0 };
    std::atomic<uint64_t> extractionErrors{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };

    void Reset() noexcept {
        archivesProcessed.store(0, std::memory_order_relaxed);
        entriesExtracted.store(0, std::memory_order_relaxed);
        bytesExtracted.store(0, std::memory_order_relaxed);
        zipBombsDetected.store(0, std::memory_order_relaxed);
        pathTraversalsBlocked.store(0, std::memory_order_relaxed);
        encryptedSkipped.store(0, std::memory_order_relaxed);
        nestedArchives.store(0, std::memory_order_relaxed);
        extractionErrors.store(0, std::memory_order_relaxed);
        cacheHits.store(0, std::memory_order_relaxed);
        cacheMisses.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] ArchiveExtractorStatistics Snapshot() const noexcept {
        ArchiveExtractorStatistics s;
        s.archivesProcessed = archivesProcessed.load(std::memory_order_relaxed);
        s.entriesExtracted = entriesExtracted.load(std::memory_order_relaxed);
        s.bytesExtracted = bytesExtracted.load(std::memory_order_relaxed);
        s.zipBombsDetected = zipBombsDetected.load(std::memory_order_relaxed);
        s.pathTraversalsBlocked = pathTraversalsBlocked.load(std::memory_order_relaxed);
        s.encryptedSkipped = encryptedSkipped.load(std::memory_order_relaxed);
        s.nestedArchives = nestedArchives.load(std::memory_order_relaxed);
        s.extractionErrors = extractionErrors.load(std::memory_order_relaxed);
        s.cacheHits = cacheHits.load(std::memory_order_relaxed);
        s.cacheMisses = cacheMisses.load(std::memory_order_relaxed);
        return s;
    }
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ArchiveExtractorImpl final {
public:
    ArchiveExtractorImpl() = default;
    ~ArchiveExtractorImpl() = default;

    ArchiveExtractorImpl(const ArchiveExtractorImpl&) = delete;
    ArchiveExtractorImpl& operator=(const ArchiveExtractorImpl&) = delete;
    ArchiveExtractorImpl(ArchiveExtractorImpl&&) = delete;
    ArchiveExtractorImpl& operator=(ArchiveExtractorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const ArchiveExtractorConfig& config) {
        std::unique_lock lock(m_lifecycleMutex);

        if (m_initialized) {
            SS_LOG_WARN(L"ArchiveExtractor", L"Already initialized — re-initializing");
            ShutdownInternal();
        }

        try {
            m_config = config;

            if (!m_config.tempDirectory.empty()) {
                std::error_code ec;
                if (!fs::exists(m_config.tempDirectory, ec)) {
                    fs::create_directories(m_config.tempDirectory, ec);
                    if (ec) {
                        SS_LOG_ERROR(L"ArchiveExtractor",
                            L"Failed to create temp directory: %hs",
                            ec.message().c_str());
                        return false;
                    }
                }
            } else {
                // Use system temp
                wchar_t tmpBuf[MAX_PATH + 1]{};
                DWORD len = GetTempPathW(MAX_PATH, tmpBuf);
                if (len > 0 && len < MAX_PATH) {
                    m_config.tempDirectory = std::wstring(tmpBuf, len) + L"ShadowStrike_AE\\";
                    std::error_code ec;
                    fs::create_directories(m_config.tempDirectory, ec);
                }
            }

            m_cancelled.store(false, std::memory_order_release);
            m_initialized = true;

            SS_LOG_INFO(L"ArchiveExtractor",
                L"Initialized (maxRatio=%.1f, maxNesting=%u, strict=%d, threads=%u)",
                m_config.defaultMaxRatio, m_config.defaultMaxNesting,
                m_config.strictSecurityChecks, m_config.workerThreads);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"Initialization exception: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_lifecycleMutex);
        ShutdownInternal();
    }

    // ========================================================================
    // FORMAT DETECTION (Magic-byte priority over extension)
    // ========================================================================

    [[nodiscard]] ArchiveFormat DetectFormat(const std::wstring& filePath) const {
        try {
            // Read header bytes first — magic bytes take priority over extension
            ScopedHandle hFile(CreateFileW(
                filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));

            if (!hFile) {
                SS_LOG_DEBUG(L"ArchiveExtractor",
                    L"Cannot open file for format detection: 0x%08X",
                    GetLastError());
                return ArchiveFormat::Unknown;
            }

            // Get file size for validation
            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFile.get(), &fileSize) || fileSize.QuadPart < 4) {
                return ArchiveFormat::Unknown;
            }

            // Read enough for all magic signatures including ISO at offset 0x8001
            const size_t readSize = static_cast<size_t>(
                std::min(static_cast<uint64_t>(MAGIC_HEADER_READ_SIZE),
                         static_cast<uint64_t>(fileSize.QuadPart)));

            std::vector<uint8_t> headerBuf(readSize, 0);
            DWORD bytesRead = 0;
            if (!ReadFile(hFile.get(), headerBuf.data(),
                          static_cast<DWORD>(readSize), &bytesRead, nullptr)) {
                return ArchiveFormat::Unknown;
            }

            auto magicResult = DetectFormat(
                std::span<const uint8_t>(headerBuf.data(), bytesRead));

            if (magicResult != ArchiveFormat::Unknown) {
                // Check for compound formats: if GZIP, check if it's a tar.gz
                if (magicResult == ArchiveFormat::GZIP) {
                    auto ext = ToLowerCopy(fs::path(filePath).filename().wstring());
                    if (ext.ends_with(L".tar.gz") || ext.ends_with(L".tgz")) {
                        return ArchiveFormat::TarGz;
                    }
                }
                if (magicResult == ArchiveFormat::BZIP2) {
                    auto ext = ToLowerCopy(fs::path(filePath).filename().wstring());
                    if (ext.ends_with(L".tar.bz2") || ext.ends_with(L".tbz2")) {
                        return ArchiveFormat::TarBz2;
                    }
                }
                if (magicResult == ArchiveFormat::XZ) {
                    auto ext = ToLowerCopy(fs::path(filePath).filename().wstring());
                    if (ext.ends_with(L".tar.xz") || ext.ends_with(L".txz")) {
                        return ArchiveFormat::TarXz;
                    }
                }
                if (magicResult == ArchiveFormat::ZSTD) {
                    auto ext = ToLowerCopy(fs::path(filePath).filename().wstring());
                    if (ext.ends_with(L".tar.zst")) {
                        return ArchiveFormat::TarZstd;
                    }
                }
                return magicResult;
            }

            // Fall back to extension only if magic detection failed
            fs::path p(filePath);
            auto ext = ToLowerCopy(p.extension().wstring());

            static const std::unordered_map<std::wstring, ArchiveFormat> EXT_MAP = {
                {L".zip", ArchiveFormat::ZIP}, {L".rar", ArchiveFormat::RAR},
                {L".7z", ArchiveFormat::SevenZip}, {L".tar", ArchiveFormat::TAR},
                {L".gz", ArchiveFormat::GZIP}, {L".gzip", ArchiveFormat::GZIP},
                {L".bz2", ArchiveFormat::BZIP2}, {L".bzip2", ArchiveFormat::BZIP2},
                {L".xz", ArchiveFormat::XZ}, {L".lzma", ArchiveFormat::LZMA},
                {L".zst", ArchiveFormat::ZSTD}, {L".zstd", ArchiveFormat::ZSTD},
                {L".cab", ArchiveFormat::CAB}, {L".msi", ArchiveFormat::MSI},
                {L".wim", ArchiveFormat::WIM}, {L".iso", ArchiveFormat::ISO},
                {L".vhd", ArchiveFormat::VHD}, {L".vhdx", ArchiveFormat::VHDX},
                {L".dmg", ArchiveFormat::DMG}, {L".img", ArchiveFormat::IMG},
                {L".arj", ArchiveFormat::ARJ}, {L".lzh", ArchiveFormat::LZH},
                {L".ace", ArchiveFormat::ACE}, {L".cpio", ArchiveFormat::CPIO},
                {L".rpm", ArchiveFormat::RPM}, {L".deb", ArchiveFormat::DEB},
            };

            auto it = EXT_MAP.find(ext);
            return (it != EXT_MAP.end()) ? it->second : ArchiveFormat::Unknown;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"Format detection exception: %hs", e.what());
            return ArchiveFormat::Unknown;
        }
    }

    [[nodiscard]] ArchiveFormat DetectFormat(std::span<const uint8_t> buffer) const noexcept {
        for (size_t i = 0; i < MAGIC_TABLE_SIZE; ++i) {
            const auto& sig = MAGIC_TABLE[i];
            if (buffer.size() < sig.offset + sig.length) continue;

            if (std::memcmp(buffer.data() + sig.offset,
                            sig.bytes, sig.length) == 0) {
                return sig.format;
            }
        }
        return ArchiveFormat::Unknown;
    }

    [[nodiscard]] bool IsArchive(const std::wstring& filePath) const {
        return DetectFormat(filePath) != ArchiveFormat::Unknown;
    }

    [[nodiscard]] std::vector<ArchiveFormat> GetSupportedFormats() const {
        return {
            ArchiveFormat::ZIP, ArchiveFormat::RAR, ArchiveFormat::RAR5,
            ArchiveFormat::SevenZip, ArchiveFormat::TAR, ArchiveFormat::GZIP,
            ArchiveFormat::BZIP2, ArchiveFormat::XZ, ArchiveFormat::LZMA,
            ArchiveFormat::ZSTD, ArchiveFormat::TarGz, ArchiveFormat::TarBz2,
            ArchiveFormat::TarXz, ArchiveFormat::TarZstd, ArchiveFormat::CAB,
            ArchiveFormat::MSI, ArchiveFormat::WIM, ArchiveFormat::ISO,
            ArchiveFormat::VHD, ArchiveFormat::VHDX
        };
    }

    // ========================================================================
    // ZIP CENTRAL DIRECTORY PARSING (Real Implementation)
    // ========================================================================

    [[nodiscard]] std::vector<ArchiveEntry> ParseZipCentralDirectory(
        HANDLE hFile, uint64_t fileSize, const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;

        // Find End of Central Directory record (scan backwards from EOF)
        constexpr size_t EOCD_SEARCH_SIZE = 65536 + 22;
        const size_t searchSize = static_cast<size_t>(
            std::min(static_cast<uint64_t>(EOCD_SEARCH_SIZE), fileSize));

        LARGE_INTEGER seekPos{};
        seekPos.QuadPart = static_cast<LONGLONG>(fileSize - searchSize);
        if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) return entries;

        std::vector<uint8_t> buf(searchSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buf.data(), static_cast<DWORD>(searchSize), &bytesRead, nullptr)) {
            return entries;
        }

        // Search for EOCD signature backwards.  Guard against bytesRead being
        // smaller than the EOCD record itself — the unsigned subtraction below
        // would otherwise wrap and produce a huge starting index.
        int64_t eocdOffset = -1;
        if (bytesRead >= sizeof(ZipEndOfCentralDir)) {
            for (int64_t i = static_cast<int64_t>(bytesRead) -
                                static_cast<int64_t>(sizeof(ZipEndOfCentralDir));
                 i >= 0; --i) {
                uint32_t sig = 0;
                std::memcpy(&sig, buf.data() + i, 4);
                if (sig == ZIP_EOCD_SIG) {
                    eocdOffset = i;
                    break;
                }
            }
        }
        if (eocdOffset < 0) return entries;

        ZipEndOfCentralDir eocd{};
        std::memcpy(&eocd, buf.data() + eocdOffset, sizeof(eocd));

        uint64_t centralDirOffset = eocd.centralDirOffset;
        uint64_t centralDirSize = eocd.centralDirSize;
        uint64_t totalEntries = eocd.numEntriesTotal;

        // Check for Zip64
        if (eocd.centralDirOffset == 0xFFFFFFFF || eocd.numEntriesTotal == 0xFFFF) {
            // Look for Zip64 EOCD locator just before EOCD
            if (eocdOffset >= static_cast<int64_t>(sizeof(Zip64EndOfCentralDirLocator))) {
                Zip64EndOfCentralDirLocator locator{};
                std::memcpy(&locator,
                    buf.data() + eocdOffset - sizeof(locator), sizeof(locator));
                if (locator.signature == ZIP_ZIP64_EOCD_LOCATOR_SIG) {
                    // Read Zip64 EOCD
                    seekPos.QuadPart = static_cast<LONGLONG>(locator.zip64EOCDOffset);
                    if (SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) {
                        Zip64EndOfCentralDir z64eocd{};
                        if (ReadFile(hFile, &z64eocd, sizeof(z64eocd), &bytesRead, nullptr)
                            && bytesRead >= sizeof(z64eocd)
                            && z64eocd.signature == ZIP_ZIP64_EOCD_SIG) {
                            centralDirOffset = z64eocd.centralDirOffset;
                            centralDirSize = z64eocd.centralDirSize;
                            totalEntries = z64eocd.numEntriesTotal;
                        }
                    }
                }
            }
        }

        // Validate central directory bounds
        if (centralDirOffset + centralDirSize > fileSize) {
            SS_LOG_WARN(L"ArchiveExtractor",
                L"Central directory extends beyond file (offset=%llu, size=%llu, fileSize=%llu)",
                centralDirOffset, centralDirSize, fileSize);
            return entries;
        }

        // Cap entry count
        if (totalEntries > options.maxEntries) {
            SS_LOG_WARN(L"ArchiveExtractor",
                L"Archive has %llu entries, exceeding limit of %u",
                totalEntries, options.maxEntries);
            totalEntries = options.maxEntries;
        }

        entries.reserve(static_cast<size_t>(std::min(totalEntries, static_cast<uint64_t>(100000))));

        // Read central directory
        seekPos.QuadPart = static_cast<LONGLONG>(centralDirOffset);
        if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) return entries;

        // Cap allocation size.  256 MiB is well above any legitimate central
        // directory; if the on-disk record is larger, treat the archive as
        // hostile and refuse parsing rather than truncating silently.
        constexpr uint64_t MAX_CENTRAL_DIR_SIZE = 256ULL * 1024 * 1024;
        if (centralDirSize > MAX_CENTRAL_DIR_SIZE) {
            SS_LOG_WARN(L"ArchiveExtractor",
                L"ZIP central directory of %llu bytes exceeds %llu cap — refusing to parse",
                centralDirSize, MAX_CENTRAL_DIR_SIZE);
            return entries;
        }
        const size_t safeCdSize = static_cast<size_t>(centralDirSize);
        std::vector<uint8_t> cdBuf(safeCdSize);
        if (!ReadFile(hFile, cdBuf.data(), static_cast<DWORD>(safeCdSize), &bytesRead, nullptr)) {
            return entries;
        }

        // Track offsets for overlap detection
        std::vector<std::pair<uint64_t, uint64_t>> entryRanges;

        size_t pos = 0;
        uint64_t entryId = 0;
        while (pos + sizeof(ZipCentralDirEntry) <= bytesRead && entryId < totalEntries) {
            if (IsCancelled()) break;

            ZipCentralDirEntry cde{};
            std::memcpy(&cde, cdBuf.data() + pos, sizeof(cde));

            if (cde.signature != ZIP_CENTRAL_SIG) break;

            pos += sizeof(cde);

            // Read filename
            if (pos + cde.fileNameLength > bytesRead) break;
            std::string nameUtf8(
                reinterpret_cast<const char*>(cdBuf.data() + pos), cde.fileNameLength);
            pos += cde.fileNameLength;

            // Skip extra field and comment
            if (pos + cde.extraFieldLength + cde.commentLength > bytesRead) break;

            // Parse Zip64 extended information extra field (header ID 0x0001)
            // before advancing past extra data.  Per APPNOTE 4.5.3, the 64-bit
            // values appear in the extra field only when the corresponding
            // 32-bit CDE field is 0xFFFFFFFF (or 0xFFFF for disk number).
            uint64_t z64UncompSize   = cde.uncompressedSize;
            uint64_t z64CompSize     = cde.compressedSize;
            uint64_t z64LocalOffset  = cde.localHeaderOffset;

            if (cde.extraFieldLength >= 4) {
                const uint8_t* extra = cdBuf.data() + pos;
                size_t extraLen = cde.extraFieldLength;
                size_t ePos = 0;

                while (ePos + 4 <= extraLen) {
                    uint16_t headerId = 0, dataSize = 0;
                    std::memcpy(&headerId, extra + ePos, 2);
                    std::memcpy(&dataSize, extra + ePos + 2, 2);
                    ePos += 4;
                    if (ePos + dataSize > extraLen) break;

                    if (headerId == 0x0001) {
                        size_t fPos = 0;
                        if (cde.uncompressedSize == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                            std::memcpy(&z64UncompSize, extra + ePos + fPos, 8);
                            fPos += 8;
                        }
                        if (cde.compressedSize == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                            std::memcpy(&z64CompSize, extra + ePos + fPos, 8);
                            fPos += 8;
                        }
                        if (cde.localHeaderOffset == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                            std::memcpy(&z64LocalOffset, extra + ePos + fPos, 8);
                            fPos += 8;
                        }
                        break;
                    }
                    ePos += dataSize;
                }
            }

            pos += cde.extraFieldLength + cde.commentLength;

            // Build entry
            ArchiveEntry entry{};
            entry.entryId = entryId++;
            entry.path = Utils::StringUtils::ToWide(nameUtf8);
            entry.filename = fs::path(entry.path).filename().wstring();
            entry.compressedSize = z64CompSize;
            entry.uncompressedSize = z64UncompSize;
            entry.crc32 = cde.crc32;
            entry.isEncrypted = (cde.flags & ZIP_FLAG_ENCRYPTED) != 0;
            entry.isDirectory = !nameUtf8.empty() && (nameUtf8.back() == '/');
            entry.type = entry.isDirectory ? EntryType::Directory : EntryType::File;
            entry.compressionMethod = (cde.compressionMethod == ZIP_STORED)
                ? "stored" : (cde.compressionMethod == ZIP_DEFLATE) ? "deflate"
                : "method_" + std::to_string(cde.compressionMethod);

            // Compression ratio (avoid division by zero)
            if (entry.compressedSize > 0 && !entry.isDirectory) {
                entry.compressionRatio =
                    static_cast<double>(entry.uncompressedSize) /
                    static_cast<double>(entry.compressedSize);
            }

            // Security checks
            if (!IsPathSafe(entry.path)) {
                entry.securityFlags |= SecurityFlag::PathTraversalAttempt;
                entry.isSuspicious = true;
                m_stats.pathTraversalsBlocked.fetch_add(1, std::memory_order_relaxed);
            }

            if (entry.compressionRatio > m_config.defaultMaxRatio && !entry.isDirectory) {
                entry.securityFlags |= SecurityFlag::HighCompressionRatio;
                entry.isSuspicious = true;
            }

            if (entry.isEncrypted) {
                entry.securityFlags |= SecurityFlag::EncryptedContent;
            }

            // Hidden file detection (DOS hidden attribute)
            if ((cde.externalAttributes & 0x02) != 0) {
                entry.isHidden = true;
                entry.securityFlags |= SecurityFlag::HiddenEntry;
            }

            // Overlapping entry detection (with overflow-safe arithmetic)
            uint64_t entryStart = z64LocalOffset;
            uint64_t addend = static_cast<uint64_t>(sizeof(ZipLocalFileHeader)) +
                              cde.fileNameLength + cde.extraFieldLength + z64CompSize;
            uint64_t entryEnd = (entryStart > UINT64_MAX - addend)
                ? UINT64_MAX : entryStart + addend;
            for (const auto& [rStart, rEnd] : entryRanges) {
                if (entryStart < rEnd && entryEnd > rStart) {
                    entry.securityFlags |= SecurityFlag::OverlappingEntries;
                    entry.isSuspicious = true;
                    break;
                }
            }
            entryRanges.emplace_back(entryStart, entryEnd);

            // Nested archive detection
            auto entryExt = ToLowerCopy(fs::path(entry.path).extension().wstring());
            static const std::unordered_set<std::wstring> ARCHIVE_EXTS = {
                L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2",
                L".xz", L".cab", L".iso", L".msi"
            };
            if (ARCHIVE_EXTS.count(entryExt)) {
                entry.isNestedArchive = true;
                entry.type = EntryType::Archive;
            }

            entries.push_back(std::move(entry));
        }

        return entries;
    }

    // ========================================================================
    // TAR CONTENT PARSING
    // ========================================================================

    [[nodiscard]] std::vector<ArchiveEntry> ParseTarContents(
        HANDLE hFile, uint64_t fileSize, const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;
        entries.reserve(256);

        uint64_t offset = 0;
        uint64_t entryId = 0;
        uint32_t consecutiveZeroBlocks = 0;
        std::string gnuLongName;  // Accumulated GNU @LongLink filename

        while (offset + TAR_BLOCK_SIZE <= fileSize) {
            if (IsCancelled()) break;
            if (entries.size() >= TAR_MAX_ENTRIES) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"TAR entry limit (%u) reached — truncating", TAR_MAX_ENTRIES);
                break;
            }

            // Seek and read one 512-byte header block
            LARGE_INTEGER seekPos{};
            seekPos.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) break;

            uint8_t block[TAR_BLOCK_SIZE]{};
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, block, TAR_BLOCK_SIZE, &bytesRead, nullptr) ||
                bytesRead < TAR_BLOCK_SIZE) {
                break;
            }

            // End-of-archive: two consecutive zero blocks
            if (IsZeroBlock(block)) {
                consecutiveZeroBlocks++;
                if (consecutiveZeroBlocks >= 2) break;
                offset += TAR_BLOCK_SIZE;
                continue;
            }
            consecutiveZeroBlocks = 0;

            // Verify header checksum
            if (!VerifyTarChecksum(block)) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"TAR: invalid checksum at offset %llu — stopping parse", offset);
                break;
            }

            // Parse header fields
            char typeFlag = static_cast<char>(block[TAR_TYPEFLAG_OFFSET]);
            uint64_t entrySize = ParseTarOctal(
                block + TAR_SIZE_OFFSET, TAR_SIZE_LEN);
            uint64_t mtime = ParseTarOctal(
                block + TAR_MTIME_OFFSET, TAR_MTIME_LEN);

            // Extract name: prefix + '/' + name (POSIX) or just name
            std::string prefix = ExtractTarString(
                block + TAR_PREFIX_OFFSET, TAR_PREFIX_LEN);
            std::string name = ExtractTarString(
                block + TAR_NAME_OFFSET, TAR_NAME_LEN);

            if (!prefix.empty()) {
                name = prefix + "/" + name;
            }

            // GNU long filename extension: type 'L' means the data block
            // contains the real filename for the NEXT entry.
            if (typeFlag == TAR_TYPE_LONGNAME) {
                // Read the long name data blocks
                uint64_t nameDataBlocks = (entrySize + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                uint64_t nameDataSize = nameDataBlocks * TAR_BLOCK_SIZE;
                if (nameDataSize > 65536) {
                    // Sanity: reject absurdly long filenames
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"TAR: GNU long name too large (%llu) at offset %llu",
                        entrySize, offset);
                    offset += TAR_BLOCK_SIZE + nameDataSize;
                    continue;
                }
                std::vector<uint8_t> nameBuf(static_cast<size_t>(nameDataSize));
                if (!ReadFile(hFile, nameBuf.data(),
                    static_cast<DWORD>(nameDataSize), &bytesRead, nullptr)) {
                    break;
                }
                // Extract null-terminated string from the data
                gnuLongName = std::string(
                    reinterpret_cast<const char*>(nameBuf.data()),
                    strnlen(reinterpret_cast<const char*>(nameBuf.data()),
                            static_cast<size_t>(entrySize)));
                offset += TAR_BLOCK_SIZE + nameDataSize;
                continue;
            }

            // pax extended header: type 'x' or 'g' — skip data blocks
            if (typeFlag == TAR_TYPE_PAX_NEXT || typeFlag == TAR_TYPE_PAX_GLOBAL) {
                uint64_t dataBlocks = (entrySize + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
                offset += TAR_BLOCK_SIZE + dataBlocks * TAR_BLOCK_SIZE;
                continue;
            }

            // Apply GNU long name if pending
            if (!gnuLongName.empty()) {
                name = std::move(gnuLongName);
                gnuLongName.clear();
            }

            // Validate entry size
            if (entrySize > TAR_MAX_ENTRY_SIZE) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"TAR: entry size %llu exceeds limit at offset %llu",
                    entrySize, offset);
                break;
            }

            // Build ArchiveEntry
            ArchiveEntry entry;
            entry.entryId = entryId++;

            // Convert filename to wide string.  Modern TAR producers emit
            // filenames in UTF-8 (PAX/GNU); use the project-wide converter so
            // multi-byte sequences are decoded properly instead of zero-extending
            // each byte (which would yield mojibake and could bypass IsPathSafe).
            std::wstring wideName = Utils::StringUtils::ToWide(name);
            entry.path = wideName;

            // Extract just the filename component
            auto lastSep = wideName.find_last_of(L"/\\");
            entry.filename = (lastSep != std::wstring::npos)
                ? wideName.substr(lastSep + 1) : wideName;

            entry.uncompressedSize = entrySize;
            entry.compressedSize = entrySize;  // TAR is uncompressed
            entry.compressionRatio = 1.0;
            entry.compressionMethod = "stored";

            entry.isDirectory = (typeFlag == TAR_TYPE_DIRECTORY);
            entry.isEncrypted = false;

            // Set modification time.  POSIX time can legitimately exceed the
            // 2038 INT32_MAX boundary; only reject negative/zero values.
            if (mtime > 0) {
                entry.modifiedTime = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(mtime));
            }

            // Detect symlinks / hardlinks — record link target, mark the entry
            // type explicitly so CheckEntrySecurity raises SymlinkAttack, and
            // validate the target itself for traversal / absolute paths.
            if (typeFlag == TAR_TYPE_SYMLINK || typeFlag == TAR_TYPE_LINK) {
                std::string linkTarget = ExtractTarString(
                    block + TAR_LINKNAME_OFFSET, TAR_LINKNAME_LEN);
                std::wstring wideLinkTarget = Utils::StringUtils::ToWide(linkTarget);
                entry.linkTarget = wideLinkTarget;
                entry.type = (typeFlag == TAR_TYPE_SYMLINK)
                    ? EntryType::Symlink
                    : EntryType::Hardlink;
                entry.securityFlags |= SecurityFlag::SymlinkAttack;
                entry.isSuspicious = true;
                if (!wideLinkTarget.empty() && !IsPathSafe(wideLinkTarget)) {
                    entry.securityFlags |= SecurityFlag::PathTraversalAttempt;
                }
            }

            // Path safety check
            if (!IsPathSafe(entry.path)) {
                entry.securityFlags |= SecurityFlag::PathTraversalAttempt;
                entry.isSuspicious = true;
            }

            // Determine entry type from filename
            auto lowerPath = ToLowerCopy(entry.path);
            if (!entry.isDirectory) {
                // Check for nested archives
                if (lowerPath.ends_with(L".zip") || lowerPath.ends_with(L".rar") ||
                    lowerPath.ends_with(L".7z") || lowerPath.ends_with(L".tar") ||
                    lowerPath.ends_with(L".gz") || lowerPath.ends_with(L".bz2") ||
                    lowerPath.ends_with(L".xz") || lowerPath.ends_with(L".cab")) {
                    entry.isNestedArchive = true;
                    entry.type = EntryType::Archive;
                } else if (lowerPath.ends_with(L".exe") || lowerPath.ends_with(L".dll") ||
                           lowerPath.ends_with(L".sys") || lowerPath.ends_with(L".scr") ||
                           lowerPath.ends_with(L".ocx")) {
                    entry.type = EntryType::File;
                    entry.isPE = true;
                } else if (lowerPath.ends_with(L".doc") || lowerPath.ends_with(L".docx") ||
                           lowerPath.ends_with(L".xls") || lowerPath.ends_with(L".xlsx") ||
                           lowerPath.ends_with(L".pdf")) {
                    entry.type = EntryType::File;
                } else {
                    entry.type = EntryType::Unknown;
                }
            }

            entries.push_back(std::move(entry));

            // Skip data blocks: TAR pads to 512-byte boundaries
            uint64_t dataBlocks = (entrySize + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
            offset += TAR_BLOCK_SIZE + dataBlocks * TAR_BLOCK_SIZE;
        }

        return entries;
    }

    // ========================================================================
    // TAR ARCHIVE SCANNING (Full Data Extraction)
    // ========================================================================

    void ScanTarArchive(
        const std::wstring& filePath,
        const EntryCallback& callback,
        const ExtractionOptions& options,
        ExtractionSummary& summary,
        uint32_t nestingLevel) {

        if (nestingLevel >= options.maxNestingDepth) {
            summary.warnings.push_back("Max nesting depth reached: " +
                std::to_string(nestingLevel));
            return;
        }

        std::error_code ec;
        uint64_t fileSize = fs::file_size(filePath, ec);
        if (ec || fileSize < TAR_BLOCK_SIZE) return;

        ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!hFile) {
            summary.result = ExtractionResult::AccessDenied;
            return;
        }

        auto entries = ParseTarContents(hFile.get(), fileSize, options);
        uint64_t totalExtracted = 0;

        // Rewind and iterate entries, extracting data for each
        uint64_t offset = 0;
        uint32_t entryIndex = 0;
        uint32_t consecutiveZeroBlocks = 0;
        std::string gnuLongName;

        while (offset + TAR_BLOCK_SIZE <= fileSize && entryIndex < entries.size()) {
            if (IsCancelled()) {
                summary.result = ExtractionResult::Cancelled;
                break;
            }

            LARGE_INTEGER seekPos{};
            seekPos.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(hFile.get(), seekPos, nullptr, FILE_BEGIN)) break;

            uint8_t block[TAR_BLOCK_SIZE]{};
            DWORD bytesRead = 0;
            if (!ReadFile(hFile.get(), block, TAR_BLOCK_SIZE, &bytesRead, nullptr) ||
                bytesRead < TAR_BLOCK_SIZE) {
                break;
            }

            if (IsZeroBlock(block)) {
                consecutiveZeroBlocks++;
                if (consecutiveZeroBlocks >= 2) break;
                offset += TAR_BLOCK_SIZE;
                continue;
            }
            consecutiveZeroBlocks = 0;

            if (!VerifyTarChecksum(block)) break;

            char typeFlag = static_cast<char>(block[TAR_TYPEFLAG_OFFSET]);
            uint64_t entrySize = ParseTarOctal(
                block + TAR_SIZE_OFFSET, TAR_SIZE_LEN);
            uint64_t dataBlocks = (entrySize + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
            uint64_t paddedSize = dataBlocks * TAR_BLOCK_SIZE;

            // Skip metadata-only header types
            if (typeFlag == TAR_TYPE_LONGNAME || typeFlag == TAR_TYPE_LONGLINK) {
                offset += TAR_BLOCK_SIZE + paddedSize;
                continue;
            }
            if (typeFlag == TAR_TYPE_PAX_NEXT || typeFlag == TAR_TYPE_PAX_GLOBAL) {
                offset += TAR_BLOCK_SIZE + paddedSize;
                continue;
            }

            // Match to our parsed entry
            if (entryIndex >= entries.size()) break;
            const auto& entry = entries[entryIndex];
            summary.entriesProcessed++;

            // Skip directories and symlinks (no data to extract)
            if (entry.isDirectory || typeFlag == TAR_TYPE_SYMLINK ||
                typeFlag == TAR_TYPE_LINK) {
                if (callback) {
                    try {
                        std::vector<uint8_t> emptyData;
                        callback(entry, emptyData);
                    } catch (...) {}
                }
                offset += TAR_BLOCK_SIZE + paddedSize;
                entryIndex++;
                continue;
            }

            // Check total extraction limit
            if (totalExtracted > options.maxTotalSize - entrySize ||
                totalExtracted + entrySize > options.maxTotalSize) {
                summary.warnings.push_back("Total extraction size limit reached");
                break;
            }

            // Read entry data (TAR is uncompressed — data follows header directly)
            std::vector<uint8_t> data;
            if (options.mode != ExtractionMode::MetadataOnly && entrySize > 0) {
                uint64_t readSize = std::min(entrySize,
                    static_cast<uint64_t>(options.maxEntrySize));

                // Guard against oversized allocations
                if (readSize > 512ULL * 1024 * 1024) {
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"TAR: skipping oversized entry '%ls' (%llu bytes)",
                        entry.path.c_str(), entrySize);
                    summary.entriesSkipped++;
                    offset += TAR_BLOCK_SIZE + paddedSize;
                    entryIndex++;
                    continue;
                }

                data.resize(static_cast<size_t>(readSize));
                if (!ReadFile(hFile.get(), data.data(),
                    static_cast<DWORD>(readSize), &bytesRead, nullptr)) {
                    summary.entriesFailed++;
                    offset += TAR_BLOCK_SIZE + paddedSize;
                    entryIndex++;
                    continue;
                }
                data.resize(bytesRead);

                if (!data.empty()) {
                    totalExtracted += data.size();
                    m_stats.bytesExtracted.fetch_add(data.size(), std::memory_order_relaxed);
                    m_stats.entriesExtracted.fetch_add(1, std::memory_order_relaxed);
                    summary.bytesExtracted += data.size();
                    summary.entriesExtracted++;
                }
            }

            // Enrich entry with content analysis and fire callback
            if (callback) {
                try {
                    ArchiveEntry enrichedEntry = entry;
                    if (!data.empty()) {
                        enrichedEntry.entropy = CalculateEntropy(
                            std::span<const uint8_t>(data.data(), data.size()));

                        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                        if (hasher.Update(data.data(), data.size())) {
                            std::string hexHash;
                            if (hasher.FinalHex(hexHash, false)) {
                                enrichedEntry.sha256Hex = std::move(hexHash);
                            }
                        }

                        if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
                            enrichedEntry.isPE = true;
                        }

                        if (data.size() >= 10) {
                            std::string_view header(
                                reinterpret_cast<const char*>(data.data()),
                                std::min(data.size(), static_cast<size_t>(256)));
                            if (header.find("#!/") != std::string_view::npos ||
                                header.find("powershell") != std::string_view::npos ||
                                header.find("wscript") != std::string_view::npos ||
                                header.find("<script") != std::string_view::npos) {
                                enrichedEntry.isScript = true;
                            }
                        }

                        // Detect nested archive by magic bytes
                        if (data.size() >= 8) {
                            auto nestedFmt = DetectFormat(
                                std::span<const uint8_t>(data.data(),
                                    std::min(data.size(), MAGIC_HEADER_READ_SIZE)));
                            if (nestedFmt != ArchiveFormat::Unknown) {
                                enrichedEntry.isNestedArchive = true;
                                enrichedEntry.nestedFormat = nestedFmt;
                            }
                        }
                    }

                    callback(enrichedEntry, data);

                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"TAR entry callback exception: %hs", e.what());
                    summary.entriesFailed++;
                }
            }

            // Handle nested archives
            if (entry.isNestedArchive && options.extractNestedArchives && !data.empty()) {
                m_stats.nestedArchives.fetch_add(1, std::memory_order_relaxed);
                summary.nestedArchives++;

                // Use a CSPRNG-derived suffix so the path cannot be predicted
                // by a same-host attacker who might pre-create or hijack it.
                Utils::CryptoUtils::SecureRandom rng;
                uint64_t rnd = rng.NextUInt64();
                LARGE_INTEGER perfCounter{};
                QueryPerformanceCounter(&perfCounter);
                wchar_t suffix[64]{};
                _snwprintf_s(suffix, _countof(suffix), _TRUNCATE,
                    L"ae_tar_%lu_%llx_%llx_%lu",
                    GetCurrentProcessId(),
                    static_cast<uint64_t>(perfCounter.QuadPart),
                    rnd,
                    static_cast<unsigned long>(entryIndex));
                fs::path tempPath = fs::path(m_config.tempDirectory) / suffix;

                bool tempCreated = false;
                {
                    std::ofstream tempFile(tempPath,
                        std::ios::binary | std::ios::trunc);
                    if (tempFile) {
                        tempFile.write(
                            reinterpret_cast<const char*>(data.data()),
                            static_cast<std::streamsize>(data.size()));
                        tempFile.close();
                        tempCreated = tempFile.good();
                    }
                }

                if (tempCreated) {
                    // RAII guard guarantees the temp file is removed even if a
                    // recursive scan throws.
                    struct TempGuard {
                        fs::path p;
                        ~TempGuard() {
                            std::error_code ec;
                            fs::remove(p, ec);
                        }
                    } guard{ tempPath };

                    try {
                        // Detect nested format and dispatch to appropriate scanner
                        auto nestedFmt = DetectFormat(tempPath.wstring());
                        if (nestedFmt == ArchiveFormat::ZIP) {
                            ScanZipArchive(tempPath.wstring(), callback, options,
                                           summary, nestingLevel + 1);
                        } else if (nestedFmt == ArchiveFormat::TAR) {
                            ScanTarArchive(tempPath.wstring(), callback, options,
                                           summary, nestingLevel + 1);
                        }
                        // Other nested formats: metadata-only callback already fired above
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(L"ArchiveExtractor",
                            L"Nested TAR scan threw: %hs", e.what());
                        summary.entriesFailed++;
                    }
                }
            }

            // Report progress
            {
                std::shared_lock lock(m_dataMutex);
                if (m_progressCallback) {
                    ExtractionProgress progress;
                    progress.currentEntry = entryIndex;
                    progress.totalEntries = static_cast<uint32_t>(entries.size());
                    progress.bytesExtracted = summary.bytesExtracted;
                    progress.currentFile = entry.path;
                    progress.nestingLevel = nestingLevel;
                    progress.percentComplete = entries.empty() ? 100.0 :
                        (static_cast<double>(entryIndex + 1) /
                         static_cast<double>(entries.size())) * 100.0;
                    try { m_progressCallback(progress); }
                    catch (...) {}
                }
            }

            offset += TAR_BLOCK_SIZE + paddedSize;
            entryIndex++;
        }

        if (summary.result == ExtractionResult::Success && summary.entriesFailed > 0) {
            summary.result = ExtractionResult::PartialSuccess;
        }
    }

    // ========================================================================
    // GZIP HEADER PARSING (Metadata Extraction — RFC 1952)
    // ========================================================================

    [[nodiscard]] std::vector<ArchiveEntry> ParseGzipContents(
        HANDLE hFile, uint64_t fileSize, const ExtractionOptions& /*options*/) const {

        std::vector<ArchiveEntry> entries;

        if (fileSize < GZIP_HEADER_MIN_SIZE + GZIP_TRAILER_SIZE) return entries;

        // Read header
        LARGE_INTEGER seekPos{};
        seekPos.QuadPart = 0;
        SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN);

        // Read enough for header + possible FNAME (cap at 4 KiB)
        constexpr size_t MAX_HEADER_READ = 4096;
        size_t headerReadSize = static_cast<size_t>(
            std::min(fileSize, static_cast<uint64_t>(MAX_HEADER_READ)));
        std::vector<uint8_t> headerBuf(headerReadSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, headerBuf.data(),
            static_cast<DWORD>(headerReadSize), &bytesRead, nullptr) ||
            bytesRead < GZIP_HEADER_MIN_SIZE) {
            return entries;
        }

        // Validate magic and compression method
        if (headerBuf[0] != 0x1F || headerBuf[1] != 0x8B) return entries;
        if (headerBuf[2] != 8) {
            // Compression method must be 8 (deflate)
            SS_LOG_DEBUG(L"ArchiveExtractor",
                L"GZIP: unsupported compression method %u", headerBuf[2]);
            return entries;
        }

        uint8_t flags = headerBuf[3];

        // Parse modification time
        uint32_t mtime = 0;
        std::memcpy(&mtime, headerBuf.data() + 4, 4);

        // Skip header fields to find FNAME
        size_t pos = 10;
        std::string originalName;

        // FEXTRA
        if ((flags & GZIP_FLAG_FEXTRA) != 0) {
            if (pos + 2 > bytesRead) return entries;
            uint16_t extraLen = 0;
            std::memcpy(&extraLen, headerBuf.data() + pos, 2);
            pos += 2 + extraLen;
        }

        // FNAME — original filename
        if ((flags & GZIP_FLAG_FNAME) != 0) {
            size_t nameStart = pos;
            while (pos < bytesRead && headerBuf[pos] != '\0') {
                ++pos;
            }
            if (pos < bytesRead) {
                originalName = std::string(
                    reinterpret_cast<const char*>(headerBuf.data() + nameStart),
                    pos - nameStart);
                ++pos; // skip null terminator
            }
        }

        // FCOMMENT — skip
        if ((flags & GZIP_FLAG_FCOMMENT) != 0) {
            while (pos < bytesRead && headerBuf[pos] != '\0') {
                ++pos;
            }
            if (pos < bytesRead) ++pos;
        }

        // FHCRC
        if ((flags & GZIP_FLAG_FHCRC) != 0) {
            pos += 2;
        }

        // Read trailer to get ISIZE (original file size mod 2^32)
        seekPos.QuadPart = static_cast<LONGLONG>(fileSize - GZIP_TRAILER_SIZE);
        if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) return entries;

        uint8_t trailer[GZIP_TRAILER_SIZE]{};
        if (!ReadFile(hFile, trailer, GZIP_TRAILER_SIZE, &bytesRead, nullptr) ||
            bytesRead < GZIP_TRAILER_SIZE) {
            return entries;
        }

        uint32_t crc32Val = 0;
        uint32_t isize = 0;
        std::memcpy(&crc32Val, trailer, 4);
        std::memcpy(&isize, trailer + 4, 4);

        // Build a single entry representing the inner content
        ArchiveEntry entry;
        entry.entryId = 0;

        // Use original filename if available, otherwise derive from archive name.
        // The on-disk byte stream is treated as UTF-8 (RFC 1952 leaves the
        // FNAME field encoding implementation-defined, but UTF-8 is the modern
        // de-facto standard and the only encoding that can losslessly survive
        // ToWide).
        if (!originalName.empty()) {
            std::wstring wideName = Utils::StringUtils::ToWide(originalName);
            entry.path = wideName;
            entry.filename = wideName;
        } else {
            entry.path = L"[content]";
            entry.filename = L"[content]";
        }

        entry.uncompressedSize = isize;
        entry.compressedSize = fileSize - pos - GZIP_TRAILER_SIZE;
        entry.compressionMethod = "deflate";
        entry.crc32 = crc32Val;
        entry.isDirectory = false;
        entry.isEncrypted = false;

        if (isize > 0 && entry.compressedSize > 0) {
            entry.compressionRatio = static_cast<double>(isize) /
                static_cast<double>(entry.compressedSize);

            // Suspicious compression ratio check
            if (entry.compressionRatio > m_config.defaultMaxRatio) {
                entry.securityFlags |= SecurityFlag::HighCompressionRatio;
                entry.isSuspicious = true;
            }
        }

        if (mtime > 0) {
            entry.modifiedTime = std::chrono::system_clock::from_time_t(
                static_cast<time_t>(mtime));
        }

        // Detect if inner content is a TAR (for .tar.gz)
        auto lowerName = ToLowerCopy(entry.path);
        if (lowerName.ends_with(L".tar")) {
            entry.isNestedArchive = true;
            entry.nestedFormat = ArchiveFormat::TAR;
            entry.type = EntryType::Archive;
        }

        entries.push_back(std::move(entry));
        return entries;
    }

    // ========================================================================
    // RAR4 CONTENT PARSING (Header-Level Entry Enumeration)
    // ========================================================================

    [[nodiscard]] std::vector<ArchiveEntry> ParseRar4Contents(
        HANDLE hFile, uint64_t fileSize, const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;

        // RAR4 starts with 7-byte marker: 52 61 72 21 1A 07 00
        // Followed by archive header (type 0x73), then file headers (type 0x74)
        constexpr size_t RAR4_MARKER_LEN = 7;

        if (fileSize < RAR4_MARKER_LEN + 7) return entries; // marker + minimal header

        LARGE_INTEGER seekPos{};
        seekPos.QuadPart = RAR4_MARKER_LEN; // Skip marker
        if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) return entries;

        uint64_t offset = RAR4_MARKER_LEN;
        uint64_t entryId = 0;

        // Read archive header first
#pragma pack(push, 1)
        struct Rar4Header {
            uint16_t headCRC;
            uint8_t  headType;
            uint16_t flags;
            uint16_t headSize;
        };
#pragma pack(pop)

        while (offset + sizeof(Rar4Header) < fileSize) {
            if (IsCancelled()) break;
            if (entries.size() >= RAR4_MAX_ENTRIES) break;

            seekPos.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) break;

            Rar4Header hdr{};
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, &hdr, sizeof(hdr), &bytesRead, nullptr) ||
                bytesRead < sizeof(hdr)) {
                break;
            }

            if (hdr.headSize < sizeof(Rar4Header)) break;
            if (hdr.headSize > 65535) break; // Sanity

            // End of archive
            if (hdr.headType == RAR4_END_HEADER) break;

            // File header
            if (hdr.headType == RAR4_FILE_HEADER && hdr.headSize >= 32) {
                // Read extended file header data
                constexpr size_t MAX_FILE_HDR = 4096;
                size_t readLen = std::min(static_cast<size_t>(hdr.headSize), MAX_FILE_HDR);
                std::vector<uint8_t> hdrBuf(readLen);

                // Re-read from header start
                seekPos.QuadPart = static_cast<LONGLONG>(offset);
                SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN);
                if (!ReadFile(hFile, hdrBuf.data(),
                    static_cast<DWORD>(readLen), &bytesRead, nullptr) ||
                    bytesRead < 32) {
                    break;
                }

                // RAR4 file header layout after the 7-byte base header:
                // Offset 7:  uint32_t packSize (low)
                // Offset 11: uint32_t unpSize (low)
                // Offset 15: uint8_t  hostOS
                // Offset 16: uint32_t fileCRC
                // Offset 20: uint32_t fileTime (DOS format)
                // Offset 24: uint8_t  unpackVersion
                // Offset 25: uint8_t  method
                // Offset 26: uint16_t nameSize
                // Offset 28: uint32_t attributes
                uint32_t packSizeLow = 0, unpSizeLow = 0;
                uint32_t fileCrc = 0;
                uint16_t nameSize = 0;
                uint32_t fileAttr = 0;

                if (bytesRead >= 32) {
                    std::memcpy(&packSizeLow, hdrBuf.data() + 7, 4);
                    std::memcpy(&unpSizeLow, hdrBuf.data() + 11, 4);
                    std::memcpy(&fileCrc, hdrBuf.data() + 16, 4);
                    std::memcpy(&nameSize, hdrBuf.data() + 26, 2);
                    std::memcpy(&fileAttr, hdrBuf.data() + 28, 4);
                }

                uint64_t packSize = packSizeLow;
                uint64_t unpSize = unpSizeLow;

                // Large file flag: additional 4 bytes each for high 32 bits
                if ((hdr.flags & RAR4_FLAG_LARGE) != 0 && bytesRead >= 40) {
                    uint32_t packHigh = 0, unpHigh = 0;
                    std::memcpy(&packHigh, hdrBuf.data() + 32, 4);
                    std::memcpy(&unpHigh, hdrBuf.data() + 36, 4);
                    packSize |= (static_cast<uint64_t>(packHigh) << 32);
                    unpSize |= (static_cast<uint64_t>(unpHigh) << 32);
                }

                // Extract filename
                size_t nameOffset = 32;
                if ((hdr.flags & RAR4_FLAG_LARGE) != 0) nameOffset = 40;

                std::string fileName;
                if (nameSize > 0 && nameSize < 4096 &&
                    nameOffset + nameSize <= bytesRead) {
                    fileName = std::string(
                        reinterpret_cast<const char*>(hdrBuf.data() + nameOffset),
                        nameSize);
                }

                // Build entry
                ArchiveEntry entry;
                entry.entryId = entryId++;
                entry.compressedSize = packSize;
                entry.uncompressedSize = unpSize;
                entry.crc32 = fileCrc;
                entry.isEncrypted = (hdr.flags & RAR4_FLAG_ENCRYPTED) != 0;
                entry.isDirectory = ((fileAttr & 0x10) != 0) ||
                    ((hdr.flags & 0x00E0) == 0x00E0);
                entry.compressionMethod = "rar4";

                if (unpSize > 0 && packSize > 0) {
                    entry.compressionRatio = static_cast<double>(unpSize) /
                        static_cast<double>(packSize);
                }

                std::wstring wideName = Utils::StringUtils::ToWide(fileName);
                entry.path = wideName;
                auto lastSep = wideName.find_last_of(L"/\\");
                entry.filename = (lastSep != std::wstring::npos)
                    ? wideName.substr(lastSep + 1) : wideName;

                if (!IsPathSafe(entry.path)) {
                    entry.securityFlags |= SecurityFlag::PathTraversalAttempt;
                    entry.isSuspicious = true;
                }

                // Detect entry type
                auto lowerPath = ToLowerCopy(entry.path);
                if (!entry.isDirectory) {
                    if (lowerPath.ends_with(L".exe") || lowerPath.ends_with(L".dll") ||
                        lowerPath.ends_with(L".sys") || lowerPath.ends_with(L".scr")) {
                        entry.type = EntryType::File;
                        entry.isPE = true;
                    } else if (lowerPath.ends_with(L".zip") || lowerPath.ends_with(L".rar") ||
                               lowerPath.ends_with(L".7z") || lowerPath.ends_with(L".tar")) {
                        entry.isNestedArchive = true;
                        entry.type = EntryType::Archive;
                    } else {
                        entry.type = EntryType::Unknown;
                    }
                }

                entries.push_back(std::move(entry));

                // Skip past data
                offset += hdr.headSize + packSize;
            } else {
                // Non-file header: skip using header size
                uint64_t dataSize = 0;
                // If ADD_SIZE flag is set (0x8000), there's additional data
                if ((hdr.flags & 0x8000) != 0 && hdr.headSize >= 11) {
                    seekPos.QuadPart = static_cast<LONGLONG>(offset + 7);
                    SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN);
                    uint32_t addSize = 0;
                    DWORD addRead = 0;
                    ReadFile(hFile, &addSize, 4, &addRead, nullptr);
                    dataSize = addSize;
                }
                offset += hdr.headSize + dataSize;
            }
        }

        return entries;
    }

    // ========================================================================
    // RAR5 CONTENT PARSING (Header-Level Entry Enumeration)
    // ========================================================================

    [[nodiscard]] std::vector<ArchiveEntry> ParseRar5Contents(
        HANDLE hFile, uint64_t fileSize, const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;

        // RAR5 starts with 8-byte marker: 52 61 72 21 1A 07 01 00
        constexpr size_t RAR5_MARKER_LEN = 8;
        if (fileSize < RAR5_MARKER_LEN + 12) return entries;

        uint64_t offset = RAR5_MARKER_LEN;
        uint64_t entryId = 0;

        // Read in large chunks for sequential scanning
        constexpr size_t READ_BUF_SIZE = 64 * 1024;
        std::vector<uint8_t> readBuf(READ_BUF_SIZE);

        while (offset + 6 < fileSize) {
            if (IsCancelled()) break;
            if (entries.size() >= RAR4_MAX_ENTRIES) break;

            LARGE_INTEGER seekPos{};
            seekPos.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) break;

            DWORD bytesRead = 0;
            DWORD toRead = static_cast<DWORD>(
                std::min(static_cast<uint64_t>(READ_BUF_SIZE), fileSize - offset));
            if (!ReadFile(hFile, readBuf.data(), toRead, &bytesRead, nullptr) ||
                bytesRead < 6) {
                break;
            }

            size_t pos = 0;

            // Header CRC32 (4 bytes)
            pos += 4;

            // Header size (vint)
            uint64_t headerSize = 0;
            size_t vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, headerSize);
            if (vintBytes == 0 || headerSize < 1) break;
            pos += vintBytes;

            // Header type (vint)
            uint64_t headerType = 0;
            vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, headerType);
            if (vintBytes == 0) break;
            pos += vintBytes;

            // Header flags (vint)
            uint64_t headerFlags = 0;
            vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, headerFlags);
            if (vintBytes == 0) break;
            pos += vintBytes;

            // Extra data size (if flag bit 0 set)
            uint64_t extraSize = 0;
            if ((headerFlags & 0x0001) != 0) {
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, extraSize);
                if (vintBytes == 0) break;
                pos += vintBytes;
            }

            // Data area size (if flag bit 1 set)
            uint64_t dataAreaSize = 0;
            if ((headerFlags & 0x0002) != 0) {
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, dataAreaSize);
                if (vintBytes == 0) break;
                pos += vintBytes;
            }

            // End archive
            if (headerType == RAR5_HEADER_END) break;

            // File header
            if (headerType == RAR5_HEADER_FILE && pos + 4 < bytesRead) {
                // File flags (vint)
                uint64_t fileFlags = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, fileFlags);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // Unpacked size (vint)
                uint64_t unpSize = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, unpSize);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // Attributes (vint)
                uint64_t attributes = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, attributes);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // mtime (uint32 if flag bit 1 set)
                uint32_t mtime = 0;
                if ((fileFlags & RAR5_FILE_FLAG_UNIX_MTIME) != 0 && pos + 4 <= bytesRead) {
                    std::memcpy(&mtime, readBuf.data() + pos, 4);
                    pos += 4;
                }

                // Data CRC32 (uint32 if flag bit 2 set)
                uint32_t dataCrc = 0;
                if ((fileFlags & RAR5_FILE_FLAG_CRC32) != 0 && pos + 4 <= bytesRead) {
                    std::memcpy(&dataCrc, readBuf.data() + pos, 4);
                    pos += 4;
                }

                // Compression info (vint)
                uint64_t compInfo = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, compInfo);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // Host OS (vint)
                uint64_t hostOS = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, hostOS);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // Name length (vint)
                uint64_t nameLen = 0;
                vintBytes = ReadRar5Vint(readBuf.data() + pos, bytesRead - pos, nameLen);
                if (vintBytes == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
                pos += vintBytes;

                // Name (UTF-8)
                std::string fileName;
                if (nameLen > 0 && nameLen < 4096 && pos + nameLen <= bytesRead) {
                    fileName = std::string(
                        reinterpret_cast<const char*>(readBuf.data() + pos), 
                        static_cast<size_t>(nameLen));
                }

                // Build entry
                ArchiveEntry entry;
                entry.entryId = entryId++;
                entry.compressedSize = dataAreaSize;
                entry.uncompressedSize = unpSize;
                entry.crc32 = dataCrc;
                entry.isDirectory = (fileFlags & RAR5_FILE_FLAG_DIRECTORY) != 0;
                entry.compressionMethod = "rar5";

                if (unpSize > 0 && dataAreaSize > 0) {
                    entry.compressionRatio = static_cast<double>(unpSize) /
                        static_cast<double>(dataAreaSize);
                }

                if (mtime > 0) {
                    entry.modifiedTime = std::chrono::system_clock::from_time_t(
                        static_cast<time_t>(mtime));
                }

                std::wstring wideName = Utils::StringUtils::ToWide(fileName);
                entry.path = wideName;
                auto lastSep = wideName.find_last_of(L"/\\");
                entry.filename = (lastSep != std::wstring::npos)
                    ? wideName.substr(lastSep + 1) : wideName;

                if (!IsPathSafe(entry.path)) {
                    entry.securityFlags |= SecurityFlag::PathTraversalAttempt;
                    entry.isSuspicious = true;
                }

                auto lowerPath = ToLowerCopy(entry.path);
                if (!entry.isDirectory) {
                    if (lowerPath.ends_with(L".exe") || lowerPath.ends_with(L".dll") ||
                        lowerPath.ends_with(L".sys") || lowerPath.ends_with(L".scr")) {
                        entry.type = EntryType::File;
                        entry.isPE = true;
                    } else if (lowerPath.ends_with(L".zip") || lowerPath.ends_with(L".rar") ||
                               lowerPath.ends_with(L".7z")) {
                        entry.isNestedArchive = true;
                        entry.type = EntryType::Archive;
                    } else {
                        entry.type = EntryType::Unknown;
                    }
                }

                entries.push_back(std::move(entry));
            }

            // Advance: CRC32(4) + headerSize + dataAreaSize
            offset += 4 + headerSize + dataAreaSize;
        }

        return entries;
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
                std::shared_lock lock(m_dataMutex);
                auto it = m_cache.find(filePath);
                if (it != m_cache.end()) {
                    auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    if (age < std::chrono::minutes(15)) {
                        m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                        return it->second.info;
                    }
                }
            }
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);

            // Detect format
            info.format = DetectFormat(filePath);
            info.formatName = GetFormatName(info.format);

            // Get file size
            std::error_code ec;
            info.fileSize = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_ERROR(L"ArchiveExtractor",
                    L"Cannot get file size for '%ls': %hs",
                    filePath.c_str(), ec.message().c_str());
                return info;
            }

            // For ZIP, parse central directory to get real metadata
            if (info.format == ArchiveFormat::ZIP) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));

                if (hFile) {
                    auto entries = ParseZipCentralDirectory(
                        hFile.get(), info.fileSize, ExtractionOptions::CreateDefault());

                    info.totalEntries = static_cast<uint32_t>(entries.size());
                    info.fileCount = 0;
                    info.directoryCount = 0;
                    info.totalCompressedSize = 0;
                    info.totalUncompressedSize = 0;
                    bool hasEncrypted = false;

                    for (const auto& entry : entries) {
                        if (entry.isDirectory) {
                            info.directoryCount++;
                        } else {
                            info.fileCount++;
                        }
                        // Overflow-safe accumulation — cap at UINT64_MAX
                        if (info.totalCompressedSize <= UINT64_MAX - entry.compressedSize)
                            info.totalCompressedSize += entry.compressedSize;
                        if (info.totalUncompressedSize <= UINT64_MAX - entry.uncompressedSize)
                            info.totalUncompressedSize += entry.uncompressedSize;
                        if (entry.isEncrypted) hasEncrypted = true;
                        info.securityFlags |= entry.securityFlags;
                        if (entry.isSuspicious) info.isSuspicious = true;
                    }

                    info.hasEncryptedEntries = hasEncrypted;
                    if (info.totalCompressedSize > 0) {
                        info.overallCompressionRatio =
                            static_cast<double>(info.totalUncompressedSize) /
                            static_cast<double>(info.totalCompressedSize);
                    }
                }
            } else {
                // Non-ZIP: populate basic info from file metadata
                info.totalEntries = 0;
                info.totalCompressedSize = info.fileSize;
                info.totalUncompressedSize = info.fileSize;
                info.overallCompressionRatio = 1.0;
            }

            info.analyzedTime = std::chrono::system_clock::now();

            // Update cache (evict oldest if full)
            {
                std::unique_lock lock(m_dataMutex);
                if (m_cache.size() >= 1000) {
                    auto oldest = m_cache.begin();
                    for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
                        if (it->second.timestamp < oldest->second.timestamp) {
                            oldest = it;
                        }
                    }
                    m_cache.erase(oldest);
                }
                m_cache[filePath] = CacheEntry{ info,
                    std::chrono::steady_clock::now() };
            }

            return info;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"GetArchiveInfo failed for '%ls': %hs",
                filePath.c_str(), e.what());
            return info;
        }
    }

    [[nodiscard]] std::vector<ArchiveEntry> ListContents(
        const std::wstring& filePath,
        const ExtractionOptions& options) const {

        std::vector<ArchiveEntry> entries;

        try {
            auto format = DetectFormat(filePath);
            if (format == ArchiveFormat::Unknown) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"Unknown archive format: '%ls'", filePath.c_str());
                return entries;
            }

            std::error_code ec;
            uint64_t fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) return entries;

            if (format == ArchiveFormat::ZIP) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));

                if (!hFile) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Cannot open archive '%ls': 0x%08X",
                        filePath.c_str(), GetLastError());
                    return entries;
                }

                entries = ParseZipCentralDirectory(hFile.get(), fileSize, options);

            } else if (format == ArchiveFormat::TAR) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                if (!hFile) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Cannot open TAR archive '%ls': 0x%08X",
                        filePath.c_str(), GetLastError());
                    return entries;
                }
                entries = ParseTarContents(hFile.get(), fileSize, options);

            } else if (format == ArchiveFormat::GZIP || format == ArchiveFormat::TarGz) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                if (!hFile) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Cannot open GZIP archive '%ls': 0x%08X",
                        filePath.c_str(), GetLastError());
                    return entries;
                }
                entries = ParseGzipContents(hFile.get(), fileSize, options);

            } else if (format == ArchiveFormat::RAR) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                if (!hFile) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Cannot open RAR archive '%ls': 0x%08X",
                        filePath.c_str(), GetLastError());
                    return entries;
                }
                entries = ParseRar4Contents(hFile.get(), fileSize, options);

            } else if (format == ArchiveFormat::RAR5) {
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                if (!hFile) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Cannot open RAR5 archive '%ls': 0x%08X",
                        filePath.c_str(), GetLastError());
                    return entries;
                }
                entries = ParseRar5Contents(hFile.get(), fileSize, options);

            } else {
                // Remaining formats (7z, BZ2, XZ, LZMA, etc.) — format detected
                // but no header parser available. Log and return empty.
                SS_LOG_INFO(L"ArchiveExtractor",
                    L"Content listing requires external codec for %hs: '%ls'",
                    GetFormatName(format).c_str(), filePath.c_str());
            }

            m_stats.archivesProcessed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"ListContents failed for '%ls': %hs",
                filePath.c_str(), e.what());
        }

        return entries;
    }

    [[nodiscard]] bool VerifyIntegrity(const std::wstring& filePath) const {
        try {
            auto format = DetectFormat(filePath);
            if (format == ArchiveFormat::TAR) {
                // TAR integrity: verify all header checksums parse correctly
                std::error_code ec;
                uint64_t fileSize = fs::file_size(filePath, ec);
                if (ec || fileSize < TAR_BLOCK_SIZE) return false;
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
                if (!hFile) return false;
                auto entries = ParseTarContents(hFile.get(), fileSize,
                    ExtractionOptions::CreateDefault());
                return !entries.empty();
            }
            if (format != ArchiveFormat::ZIP) {
                SS_LOG_INFO(L"ArchiveExtractor",
                    L"Integrity verification supported for ZIP and TAR: '%ls'",
                    filePath.c_str());
                return fs::exists(filePath);
            }

            std::error_code ec;
            uint64_t fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize < sizeof(ZipEndOfCentralDir)) return false;

            ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
            if (!hFile) return false;

            auto entries = ParseZipCentralDirectory(hFile.get(), fileSize,
                ExtractionOptions::CreateDefault());

            // Verify structural integrity: check each local file header is reachable
            // and its signature is valid. Full CRC verification is done on stored entries.
            bool allValid = true;
            
            // Re-parse central directory to get localHeaderOffset values
            LARGE_INTEGER cdSeek{};
            // Find EOCD again for the offset
            constexpr size_t EOCD_VERIFY_SIZE = 65558;
            const size_t searchLen = static_cast<size_t>(
                std::min(static_cast<uint64_t>(EOCD_VERIFY_SIZE), fileSize));
            cdSeek.QuadPart = static_cast<LONGLONG>(fileSize - searchLen);
            SetFilePointerEx(hFile.get(), cdSeek, nullptr, FILE_BEGIN);
            
            std::vector<uint8_t> searchBuf(searchLen);
            DWORD searchRead = 0;
            ReadFile(hFile.get(), searchBuf.data(), static_cast<DWORD>(searchLen), &searchRead, nullptr);
            
            uint64_t cdOffset = 0;
            bool foundEOCD = false;
            for (int64_t i = static_cast<int64_t>(searchRead) - sizeof(ZipEndOfCentralDir);
                 i >= 0; --i) {
                uint32_t sig = 0;
                std::memcpy(&sig, searchBuf.data() + i, 4);
                if (sig == ZIP_EOCD_SIG) {
                    ZipEndOfCentralDir eocd{};
                    std::memcpy(&eocd, searchBuf.data() + i, sizeof(eocd));
                    cdOffset = eocd.centralDirOffset;

                    // Handle Zip64: if offset is 0xFFFFFFFF, look for Zip64 EOCD locator
                    if (cdOffset == 0xFFFFFFFF &&
                        i >= static_cast<int64_t>(sizeof(Zip64EndOfCentralDirLocator))) {
                        Zip64EndOfCentralDirLocator locator{};
                        std::memcpy(&locator, searchBuf.data() + i - sizeof(locator), sizeof(locator));
                        if (locator.signature == ZIP_ZIP64_EOCD_LOCATOR_SIG) {
                            LARGE_INTEGER z64Seek{};
                            z64Seek.QuadPart = static_cast<LONGLONG>(locator.zip64EOCDOffset);
                            if (SetFilePointerEx(hFile.get(), z64Seek, nullptr, FILE_BEGIN)) {
                                Zip64EndOfCentralDir z64eocd{};
                                DWORD z64Read = 0;
                                if (ReadFile(hFile.get(), &z64eocd, sizeof(z64eocd), &z64Read, nullptr)
                                    && z64Read >= sizeof(z64eocd)
                                    && z64eocd.signature == ZIP_ZIP64_EOCD_SIG) {
                                    cdOffset = z64eocd.centralDirOffset;
                                }
                            }
                        }
                    }

                    foundEOCD = true;
                    break;
                }
            }
            if (!foundEOCD) return false;

            if (cdOffset >= fileSize) return false;

            cdSeek.QuadPart = static_cast<LONGLONG>(cdOffset);
            SetFilePointerEx(hFile.get(), cdSeek, nullptr, FILE_BEGIN);
            
            // Read central directory
            const size_t safeLen = static_cast<size_t>(
                std::min(fileSize - cdOffset, static_cast<uint64_t>(256 * 1024 * 1024)));
            std::vector<uint8_t> cdData(safeLen);
            DWORD cdRead = 0;
            ReadFile(hFile.get(), cdData.data(), static_cast<DWORD>(safeLen), &cdRead, nullptr);
            
            size_t cdPos = 0;
            uint32_t verified = 0;
            while (cdPos + sizeof(ZipCentralDirEntry) <= cdRead && verified < 50000) {
                if (IsCancelled()) break;
                
                ZipCentralDirEntry cde{};
                std::memcpy(&cde, cdData.data() + cdPos, sizeof(cde));
                if (cde.signature != ZIP_CENTRAL_SIG) break;

                // Parse Zip64 local header offset from extra field
                uint64_t localOffset = cde.localHeaderOffset;
                if (cde.localHeaderOffset == 0xFFFFFFFF) {
                    size_t extraStart = cdPos + sizeof(cde) + cde.fileNameLength;
                    if (extraStart + cde.extraFieldLength <= cdRead) {
                        const uint8_t* extra = cdData.data() + extraStart;
                        size_t ePos = 0;
                        while (ePos + 4 <= cde.extraFieldLength) {
                            uint16_t hId = 0, dSz = 0;
                            std::memcpy(&hId, extra + ePos, 2);
                            std::memcpy(&dSz, extra + ePos + 2, 2);
                            ePos += 4;
                            if (ePos + dSz > cde.extraFieldLength) break;
                            if (hId == 0x0001) {
                                // Skip uncompressed/compressed size fields to reach offset
                                size_t fPos = 0;
                                if (cde.uncompressedSize == 0xFFFFFFFF) fPos += 8;
                                if (cde.compressedSize == 0xFFFFFFFF) fPos += 8;
                                if (fPos + 8 <= dSz) {
                                    std::memcpy(&localOffset, extra + ePos + fPos, 8);
                                }
                                break;
                            }
                            ePos += dSz;
                        }
                    }
                }

                cdPos += sizeof(cde) + cde.fileNameLength + cde.extraFieldLength + cde.commentLength;
                if (cdPos > cdRead) break;
                
                // Verify local file header signature
                if (localOffset < fileSize) {
                    LARGE_INTEGER lfhSeek{};
                    lfhSeek.QuadPart = static_cast<LONGLONG>(localOffset);
                    if (SetFilePointerEx(hFile.get(), lfhSeek, nullptr, FILE_BEGIN)) {
                        uint32_t lfhSig = 0;
                        DWORD lfhRead = 0;
                        if (ReadFile(hFile.get(), &lfhSig, 4, &lfhRead, nullptr) && lfhRead == 4) {
                            if (lfhSig != ZIP_LOCAL_SIG) {
                                allValid = false;
                                SS_LOG_WARN(L"ArchiveExtractor",
                                    L"Integrity: invalid LFH signature at offset %llu",
                                    localOffset);
                            }
                        }
                    }
                } else {
                    allValid = false;
                }
                verified++;
            }

            return allValid && !entries.empty();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"VerifyIntegrity exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // ZIP ENTRY EXTRACTION
    // ========================================================================

    [[nodiscard]] std::vector<uint8_t> ExtractZipEntry(
        HANDLE hFile, const ZipCentralDirEntry& cde,
        size_t nameLen, const ExtractionOptions& options) const {

        std::vector<uint8_t> result;

        // Reject encrypted entries — decompressing encrypted data without
        // decryption produces garbage and wastes resources.
        if ((cde.flags & ZIP_FLAG_ENCRYPTED) != 0 ||
            (cde.flags & ZIP_FLAG_STRONG_ENCRYPTION) != 0) {
            SS_LOG_DEBUG(L"ArchiveExtractor",
                L"Skipping encrypted entry (flags=0x%04X)", cde.flags);
            return result;
        }

        // Seek to local file header
        LARGE_INTEGER seekPos{};
        seekPos.QuadPart = cde.localHeaderOffset;
        if (!SetFilePointerEx(hFile, seekPos, nullptr, FILE_BEGIN)) return result;

        ZipLocalFileHeader lfh{};
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &lfh, sizeof(lfh), &bytesRead, nullptr)
            || bytesRead < sizeof(lfh) || lfh.signature != ZIP_LOCAL_SIG) {
            return result;
        }

        // Skip local filename and extra field
        LARGE_INTEGER skip{};
        skip.QuadPart = lfh.fileNameLength + lfh.extraFieldLength;
        if (!SetFilePointerEx(hFile, skip, nullptr, FILE_CURRENT)) return result;

        uint64_t compSize = cde.compressedSize;
        uint64_t uncompSize = cde.uncompressedSize;

        // Size validation
        if (uncompSize > options.maxEntrySize) {
            SS_LOG_WARN(L"ArchiveExtractor",
                L"Entry too large: %llu bytes (limit: %llu)",
                uncompSize, options.maxEntrySize);
            return result;
        }

        if (cde.compressionMethod == ZIP_STORED) {
            // Stored — direct copy
            if (compSize > options.maxEntrySize) return result;

            result.resize(static_cast<size_t>(compSize));
            if (!ReadFile(hFile, result.data(),
                          static_cast<DWORD>(compSize), &bytesRead, nullptr)) {
                result.clear();
                return result;
            }
            result.resize(bytesRead);

        } else if (cde.compressionMethod == ZIP_DEFLATE) {
            // Standard ZIP files use raw RFC 1951 deflate.  The Windows
            // Compression API only exposes MSZIP (which is deflate wrapped in
            // a 'CK' chunk header) — feeding it raw deflate produces silent
            // garbage that downstream scanners would treat as legitimate
            // entry contents.  Until a raw-deflate codec is wired through
            // Utils::CompressionUtils, refuse the operation explicitly so
            // callers get a clear, actionable failure rather than corrupt data.
            SS_LOG_DEBUG(L"ArchiveExtractor",
                L"ZIP entry uses RFC 1951 deflate which is not yet supported "
                L"by the available codec; entry will be skipped");
            return result;
        }

        // Verify CRC32
        if (!result.empty() && cde.crc32 != 0) {
            uint32_t computedCrc = ComputeCrc32(
                std::span<const uint8_t>(result.data(), result.size()));
            if (computedCrc != cde.crc32) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"CRC32 mismatch: expected 0x%08X, got 0x%08X",
                    cde.crc32, computedCrc);
                // Don't discard — malware often has broken CRC, still scan it
            }
        }

        return result;
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
        m_cancelled.store(false, std::memory_order_release);

        try {
            auto format = DetectFormat(filePath);
            if (format == ArchiveFormat::Unknown) {
                summary.result = ExtractionResult::UnsupportedFormat;
                summary.errors.push_back("Unknown archive format");
                return summary;
            }

            // Security pre-check
            if (m_config.strictSecurityChecks && IsZipBomb(filePath)) {
                summary.result = ExtractionResult::ZipBombDetected;
                summary.securityFlags |= SecurityFlag::ZipBombSuspected;
                summary.errors.push_back("Zip bomb detected — aborting scan");
                m_stats.zipBombsDetected.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"ZIP BOMB DETECTED: '%ls'", filePath.c_str());
                return summary;
            }

            if (format == ArchiveFormat::ZIP) {
                ScanZipArchive(filePath, callback, options, summary, 0);
            } else if (format == ArchiveFormat::TAR) {
                ScanTarArchive(filePath, callback, options, summary, 0);
            } else {
                // Formats without native data extraction (RAR, 7z, GZIP, BZ2, XZ, etc.)
                // Provide metadata-only pass via header parsing.
                auto entries = ListContents(filePath, options);
                summary.entriesProcessed = static_cast<uint32_t>(entries.size());

                if (entries.empty()) {
                    SS_LOG_INFO(L"ArchiveExtractor",
                        L"No entries enumerable for %hs: '%ls'",
                        GetFormatName(format).c_str(), filePath.c_str());
                } else {
                    SS_LOG_INFO(L"ArchiveExtractor",
                        L"Metadata-only pass for %hs (%u entries): '%ls'",
                        GetFormatName(format).c_str(),
                        static_cast<uint32_t>(entries.size()), filePath.c_str());
                }

                for (const auto& entry : entries) {
                    if (IsCancelled()) {
                        summary.result = ExtractionResult::Cancelled;
                        break;
                    }
                    if (callback) {
                        try {
                            std::vector<uint8_t> emptyData;
                            callback(entry, emptyData);
                        } catch (const std::exception& e) {
                            SS_LOG_ERROR(L"ArchiveExtractor",
                                L"Callback exception: %hs", e.what());
                            summary.entriesFailed++;
                        }
                    }
                }
                if (entries.empty() && summary.result == ExtractionResult::Success) {
                    summary.warnings.push_back(
                        "Metadata-only — data extraction requires external codec for " +
                        GetFormatName(format));
                }
            }

            if (!IsCancelled() && summary.result == ExtractionResult::Success) {
                m_stats.archivesProcessed.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"ScanArchive exception for '%ls': %hs",
                filePath.c_str(), e.what());
            summary.result = ExtractionResult::IOError;
            summary.errors.push_back(std::string("Exception: ") + e.what());
            m_stats.extractionErrors.fetch_add(1, std::memory_order_relaxed);
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
        m_cancelled.store(false, std::memory_order_release);

        try {
            if (m_config.strictSecurityChecks && IsZipBomb(filePath)) {
                summary.result = ExtractionResult::ZipBombDetected;
                summary.securityFlags |= SecurityFlag::ZipBombSuspected;
                m_stats.zipBombsDetected.fetch_add(1, std::memory_order_relaxed);
                return summary;
            }

            std::error_code ec;
            fs::create_directories(outputDir, ec);
            if (ec) {
                summary.result = ExtractionResult::IOError;
                summary.errors.push_back("Failed to create output directory");
                return summary;
            }

            auto format = DetectFormat(filePath);
            if (format != ArchiveFormat::ZIP && format != ArchiveFormat::TAR) {
                summary.result = ExtractionResult::UnsupportedFormat;
                summary.errors.push_back(
                    "Full extraction supports ZIP and TAR formats; detected " +
                    GetFormatName(format));
                return summary;
            }

            // Resolve the output directory to an absolute, canonical form so we
            // can confirm every per-entry destination falls inside it.  The
            // sanitizer alone is not sufficient — operators may pass a relative
            // outputDir or the underlying filesystem may contain a junction
            // that re-exits the intended root.
            fs::path canonicalRoot = fs::weakly_canonical(fs::path(outputDir), ec);
            if (ec || canonicalRoot.empty()) {
                summary.result = ExtractionResult::IOError;
                summary.errors.push_back("Failed to canonicalize output directory");
                return summary;
            }
            std::wstring canonicalRootStr = canonicalRoot.wstring();
            // Normalise trailing separator so prefix comparison cannot match
            // an unrelated sibling (e.g. C:\out vs C:\output).
            if (!canonicalRootStr.empty() &&
                canonicalRootStr.back() != L'\\' &&
                canonicalRootStr.back() != L'/') {
                canonicalRootStr += L'\\';
            }

            // Extract each entry to disk
            ScanArchive(filePath,
                [&](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
                    if (entry.isDirectory || data.empty()) return;

                    // Refuse symlink / hardlink entries entirely — we never
                    // want to materialise reparse points from an archive.
                    if (entry.type == EntryType::Symlink ||
                        entry.type == EntryType::Hardlink) {
                        summary.warnings.push_back(
                            "Refused link entry: " + ToNarrow(entry.path));
                        return;
                    }

                    std::wstring safePath = SanitizePath(entry.path);
                    if (safePath.empty()) return;

                    fs::path outPath = fs::path(outputDir) / safePath;
                    std::error_code canonEc;
                    fs::path canonicalOut = fs::weakly_canonical(outPath, canonEc);
                    if (canonEc || canonicalOut.empty()) {
                        summary.warnings.push_back(
                            "Refused entry (cannot canonicalize): " +
                            ToNarrow(entry.path));
                        return;
                    }
                    std::wstring canonicalOutStr = canonicalOut.wstring();
                    if (canonicalOutStr.size() < canonicalRootStr.size() ||
                        std::wstring_view(canonicalOutStr).substr(0, canonicalRootStr.size()) !=
                            std::wstring_view(canonicalRootStr)) {
                        summary.warnings.push_back(
                            "Refused entry (escapes output root): " +
                            ToNarrow(entry.path));
                        return;
                    }

                    fs::create_directories(canonicalOut.parent_path(), ec);
                    if (ec) return;

                    // Refuse to follow a reparse point at the destination.  If
                    // an attacker pre-creates a junction at canonicalOut they
                    // would otherwise redirect the write outside the root.
                    DWORD attrs = GetFileAttributesW(canonicalOut.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES &&
                        (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                        summary.warnings.push_back(
                            "Refused entry (reparse point at destination): " +
                            ToNarrow(entry.path));
                        return;
                    }

                    std::ofstream out(canonicalOut, std::ios::binary | std::ios::trunc);
                    if (out) {
                        out.write(reinterpret_cast<const char*>(data.data()),
                                  static_cast<std::streamsize>(data.size()));
                        summary.bytesExtracted += data.size();
                    }
                }, options);

            summary.result = ExtractionResult::Success;
            m_stats.archivesProcessed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"ExtractAll exception: %hs", e.what());
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
        m_cancelled.store(false, std::memory_order_release);

        try {
            auto format = DetectFormat(filePath);
            if (format != ArchiveFormat::ZIP && format != ArchiveFormat::TAR) {
                result.result = ExtractionResult::UnsupportedFormat;
                result.errorMessage = "Single entry extraction supports ZIP and TAR; detected " +
                    GetFormatName(format);
                return result;
            }

            bool found = false;
            ScanArchive(filePath,
                [&](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
                    if (found) return;
                    if (entry.path == entryPath || entry.filename == entryPath) {
                        found = true;
                        result.entryId = entry.entryId;
                        result.data = data;
                        result.size = data.size();
                        result.sha256 = entry.sha256;
                        result.entropy = entry.entropy;
                        result.result = ExtractionResult::Success;
                    }
                }, options);

            if (!found) {
                result.result = ExtractionResult::IOError;
                result.errorMessage = "Entry not found in archive";
            }

            m_stats.entriesExtracted.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"ExtractEntry exception: %hs", e.what());
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

        return ScanArchive(filePath,
            [&](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
                if (MatchesPattern(entry.path, pattern) && callback) {
                    callback(entry, data);
                }
            }, options);
    }

    ExtractionSummary ExtractStreaming(
        const std::wstring& filePath,
        StreamCallback callback,
        const ExtractionOptions& options) {

        // Convert stream callback to entry callback with chunked delivery
        return ScanArchive(filePath,
            [&](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
                if (!callback || data.empty()) return;

                const size_t chunkSize = m_config.streamingBufferSize;
                size_t offset = 0;
                while (offset < data.size()) {
                    if (IsCancelled()) break;
                    size_t remaining = data.size() - offset;
                    size_t thisChunk = std::min(remaining, chunkSize);
                    bool isLast = (offset + thisChunk >= data.size());

                    bool shouldContinue = callback(entry,
                        std::span<const uint8_t>(data.data() + offset, thisChunk),
                        isLast);
                    if (!shouldContinue) break;

                    offset += thisChunk;
                }
            }, options);
    }

    // ========================================================================
    // SECURITY ANALYSIS
    // ========================================================================

    [[nodiscard]] ArchiveInfo AnalyzeSecurity(const std::wstring& filePath) const {
        ArchiveInfo info = GetArchiveInfo(filePath);

        try {
            if (IsZipBomb(filePath)) {
                info.securityFlags |= SecurityFlag::ZipBombSuspected;
                info.isSuspicious = true;
                info.securityWarnings.push_back("Potential zip bomb detected");
            }

            if (info.overallCompressionRatio > m_config.defaultMaxRatio) {
                info.securityFlags |= SecurityFlag::HighCompressionRatio;
                info.securityWarnings.push_back(
                    "Suspicious compression ratio: " +
                    std::to_string(static_cast<int>(info.overallCompressionRatio)) + ":1");
            }

            if (info.hasEncryptedEntries) {
                info.securityFlags |= SecurityFlag::EncryptedContent;
                info.securityWarnings.push_back("Archive contains encrypted entries");
            }

            // Check for excessive nesting via entry analysis
            auto entries = ListContents(filePath, ExtractionOptions::CreateScanOnly());
            uint32_t nestedCount = 0;
            for (const auto& entry : entries) {
                if (entry.isNestedArchive) nestedCount++;
                if (HasFlag(entry.securityFlags, SecurityFlag::PathTraversalAttempt)) {
                    info.securityFlags |= SecurityFlag::PathTraversalAttempt;
                    info.securityWarnings.push_back(
                        "Path traversal attempt in entry: " +
                        ToNarrow(entry.path));
                }
                if (HasFlag(entry.securityFlags, SecurityFlag::OverlappingEntries)) {
                    info.securityFlags |= SecurityFlag::OverlappingEntries;
                    info.securityWarnings.push_back("Overlapping entries detected");
                }
            }

            if (nestedCount > m_config.defaultMaxNesting) {
                info.securityFlags |= SecurityFlag::DeepNesting;
                info.isSuspicious = true;
                info.securityWarnings.push_back(
                    "Excessive nested archives: " + std::to_string(nestedCount));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"AnalyzeSecurity exception: %hs", e.what());
        }

        return info;
    }

    [[nodiscard]] bool IsZipBomb(const std::wstring& filePath) const {
        try {
            auto format = DetectFormat(filePath);
            if (format != ArchiveFormat::ZIP) return false;

            std::error_code ec;
            auto fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) return false;

            // Open and parse central directory
            ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!hFile) return false;

            auto entries = ParseZipCentralDirectory(hFile.get(), fileSize,
                ExtractionOptions::CreateDefault());

            if (entries.empty()) return false;

            // Check 1: Total claimed uncompressed size vs file size
            // Use overflow-safe accumulation
            uint64_t totalUncompressed = 0;
            uint64_t totalCompressed = 0;
            bool overflowed = false;
            for (const auto& entry : entries) {
                if (totalUncompressed > UINT64_MAX - entry.uncompressedSize) {
                    overflowed = true;
                    break;
                }
                totalUncompressed += entry.uncompressedSize;
                if (totalCompressed > UINT64_MAX - entry.compressedSize) {
                    overflowed = true;
                    break;
                }
                totalCompressed += entry.compressedSize;
            }

            if (overflowed) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"Zip bomb heuristic: integer overflow in total size calculation");
                return true;
            }

            if (totalCompressed > 0) {
                double overallRatio = static_cast<double>(totalUncompressed) /
                                     static_cast<double>(totalCompressed);
                if (overallRatio > m_config.defaultMaxRatio) {
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"Zip bomb heuristic: overall ratio %.1f:1 exceeds limit",
                        overallRatio);
                    return true;
                }
            } else if (totalUncompressed > 0) {
                // Zero compressed size with nonzero uncompressed — malformed or bomb
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"Zip bomb heuristic: zero compressed size with %llu uncompressed bytes",
                    totalUncompressed);
                return true;
            }

            // Check 2: Total uncompressed size exceeds safety limit
            if (totalUncompressed > m_config.defaultMaxTotal) {
                SS_LOG_WARN(L"ArchiveExtractor",
                    L"Zip bomb heuristic: total uncompressed %llu exceeds limit %llu",
                    totalUncompressed, m_config.defaultMaxTotal);
                return true;
            }

            // Check 3: Individual entry ratios
            for (const auto& entry : entries) {
                if (entry.isDirectory || entry.compressedSize == 0) continue;
                if (entry.compressionRatio > m_config.defaultMaxRatio * 2.0) {
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"Zip bomb heuristic: entry '%ls' ratio %.1f:1",
                        entry.path.c_str(), entry.compressionRatio);
                    return true;
                }
            }

            // Check 4: Quine detection — archive containing itself
            for (const auto& entry : entries) {
                if (entry.compressedSize == fileSize && !entry.isDirectory) {
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"Zip bomb heuristic: quine detected — entry same size as archive");
                    return true;
                }
            }

            // Check 5: Overlapping entries
            for (const auto& entry : entries) {
                if (HasFlag(entry.securityFlags, SecurityFlag::OverlappingEntries)) {
                    SS_LOG_WARN(L"ArchiveExtractor",
                        L"Zip bomb heuristic: overlapping entries detected");
                    return true;
                }
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"IsZipBomb exception: %hs", e.what());
            return false; // Fail open — don't block if we can't determine
        }
    }

    [[nodiscard]] SecurityFlag CheckEntrySecurity(const ArchiveEntry& entry) const noexcept {
        SecurityFlag flags = SecurityFlag::None;

        if (!IsPathSafe(entry.path)) flags |= SecurityFlag::PathTraversalAttempt;
        if (entry.compressionRatio > m_config.defaultMaxRatio)
            flags |= SecurityFlag::HighCompressionRatio;
        if (entry.type == EntryType::Symlink || entry.type == EntryType::Hardlink)
            flags |= SecurityFlag::SymlinkAttack;
        if (entry.isEncrypted) flags |= SecurityFlag::EncryptedContent;
        if (entry.isHidden) flags |= SecurityFlag::HiddenEntry;

        return flags;
    }

    // ========================================================================
    // PASSWORD HANDLING
    // ========================================================================

    void SetPasswordCallback(PasswordCallback callback) {
        std::unique_lock lock(m_dataMutex);
        m_passwordCallback = std::move(callback);
    }

    [[nodiscard]] bool TestPassword(
        const std::wstring& filePath, const std::string& password) const {
        try {
            auto format = DetectFormat(filePath);
            if (format != ArchiveFormat::ZIP) return false;

            // For ZIP, try to extract the first encrypted entry with the password
            auto entries = ListContents(filePath, ExtractionOptions::CreateDefault());
            for (const auto& entry : entries) {
                if (entry.isEncrypted && !entry.isDirectory) {
                    // Password verification requires decryption attempt
                    // ZIP traditional encryption uses header CRC check
                    SS_LOG_DEBUG(L"ArchiveExtractor",
                        L"Password test attempted for '%ls'", filePath.c_str());
                    return false; // Requires full decryption support
                }
            }
            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ArchiveExtractor",
                L"TestPassword exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetProgressCallback(ArchiveProgressCallback callback) {
        std::unique_lock lock(m_dataMutex);
        m_progressCallback = std::move(callback);
    }

    void SetSecurityCallback(SecurityCallback callback) {
        std::unique_lock lock(m_dataMutex);
        m_securityCallback = std::move(callback);
    }

    // ========================================================================
    // CANCELLATION
    // ========================================================================

    void Cancel() noexcept {
        m_cancelled.store(true, std::memory_order_release);
        SS_LOG_INFO(L"ArchiveExtractor", L"Operation cancelled by caller");
    }

    [[nodiscard]] bool IsCancelled() const noexcept {
        return m_cancelled.load(std::memory_order_acquire);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] ArchiveExtractorStatistics GetStatistics() const noexcept {
        return m_stats.Snapshot();
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // KERNEL INTEGRATION
    // ========================================================================

    [[nodiscard]] bool HandleKernelScanRequest(
        const std::wstring& filePath,
        uint32_t processId,
        std::function<bool(const ArchiveEntry&, std::span<const uint8_t>)> scanCallback) {

        SS_LOG_INFO(L"ArchiveExtractor",
            L"Kernel scan request: pid=%u, path='%ls'",
            processId, filePath.c_str());

        m_cancelled.store(false, std::memory_order_release);
        bool allClean = true;

        auto options = ExtractionOptions::CreateSecure();
        options.mode = ExtractionMode::InMemory;
        options.stopOnError = false;

        auto summary = ScanArchive(filePath,
            [&](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
                if (!allClean && options.stopOnError) return;
                if (entry.isDirectory || data.empty()) return;

                if (scanCallback) {
                    bool entryClean = scanCallback(entry,
                        std::span<const uint8_t>(data.data(), data.size()));
                    if (!entryClean) {
                        allClean = false;
                        SS_LOG_WARN(L"ArchiveExtractor",
                            L"Malicious entry found: '%ls' in '%ls' (pid=%u)",
                            entry.path.c_str(), filePath.c_str(), processId);
                    }
                }
            }, options);

        if (HasFlag(summary.securityFlags, SecurityFlag::ZipBombSuspected)) {
            allClean = false;
        }

        return allClean;
    }

    [[nodiscard]] SecurityFlag QuickSecurityCheck(
        const std::wstring& filePath, uint64_t fileSize) const noexcept {

        SecurityFlag flags = SecurityFlag::None;

        try {
            auto format = DetectFormat(filePath);
            if (format == ArchiveFormat::Unknown) return flags;

            if (format == ArchiveFormat::ZIP) {
                // Quick central directory scan without extraction
                ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr));
                if (!hFile) return flags;

                ExtractionOptions quickOpts;
                quickOpts.maxEntries = 1000; // Cap for speed
                auto entries = ParseZipCentralDirectory(hFile.get(), fileSize, quickOpts);

                uint64_t totalUncomp = 0;
                for (const auto& entry : entries) {
                    // Overflow-safe accumulation
                    if (totalUncomp <= UINT64_MAX - entry.uncompressedSize)
                        totalUncomp += entry.uncompressedSize;
                    else {
                        flags |= SecurityFlag::ZipBombSuspected;
                        break;
                    }
                    flags |= entry.securityFlags;
                }

                if (fileSize > 0) {
                    double ratio = static_cast<double>(totalUncomp) /
                                   static_cast<double>(fileSize);
                    if (ratio > m_config.defaultMaxRatio) {
                        flags |= SecurityFlag::ZipBombSuspected;
                        flags |= SecurityFlag::HighCompressionRatio;
                    }
                }
            }

        } catch (...) {
            // Quick check must never throw — fail open
        }

        return flags;
    }

private:
    // ========================================================================
    // ZIP SCANNING WITH EXTRACTION
    // ========================================================================

    void ScanZipArchive(
        const std::wstring& filePath,
        const EntryCallback& callback,
        const ExtractionOptions& options,
        ExtractionSummary& summary,
        uint32_t nestingLevel) {

        if (nestingLevel >= options.maxNestingDepth) {
            summary.warnings.push_back("Max nesting depth reached: " +
                std::to_string(nestingLevel));
            return;
        }

        std::error_code ec;
        uint64_t fileSize = fs::file_size(filePath, ec);
        if (ec || fileSize == 0) return;

        ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!hFile) {
            summary.result = ExtractionResult::AccessDenied;
            return;
        }

        auto entries = ParseZipCentralDirectory(hFile.get(), fileSize, options);

        // Re-read central directory entries for extraction data offsets.
        // Locate EOCD (with Zip64 support) to find central dir offset.
        LARGE_INTEGER seekPos{};

        constexpr size_t SEARCH_SIZE = 65558;
        const size_t searchSize = static_cast<size_t>(
            std::min(static_cast<uint64_t>(SEARCH_SIZE), fileSize));
        seekPos.QuadPart = static_cast<LONGLONG>(fileSize - searchSize);
        SetFilePointerEx(hFile.get(), seekPos, nullptr, FILE_BEGIN);

        std::vector<uint8_t> eocdBuf(searchSize);
        DWORD bytesRead = 0;
        ReadFile(hFile.get(), eocdBuf.data(), static_cast<DWORD>(searchSize), &bytesRead, nullptr);

        uint64_t centralDirOffset = 0;
        if (bytesRead >= sizeof(ZipEndOfCentralDir)) {
            for (int64_t i = static_cast<int64_t>(bytesRead) -
                                static_cast<int64_t>(sizeof(ZipEndOfCentralDir));
                 i >= 0; --i) {
            uint32_t sig = 0;
            std::memcpy(&sig, eocdBuf.data() + i, 4);
            if (sig == ZIP_EOCD_SIG) {
                ZipEndOfCentralDir eocd{};
                std::memcpy(&eocd, eocdBuf.data() + i, sizeof(eocd));
                centralDirOffset = eocd.centralDirOffset;

                // Handle Zip64: if offset is 0xFFFFFFFF, look for Zip64 EOCD locator
                if (centralDirOffset == 0xFFFFFFFF &&
                    i >= static_cast<int64_t>(sizeof(Zip64EndOfCentralDirLocator))) {
                    Zip64EndOfCentralDirLocator locator{};
                    std::memcpy(&locator, eocdBuf.data() + i - sizeof(locator), sizeof(locator));
                    if (locator.signature == ZIP_ZIP64_EOCD_LOCATOR_SIG) {
                        LARGE_INTEGER z64Seek{};
                        z64Seek.QuadPart = static_cast<LONGLONG>(locator.zip64EOCDOffset);
                        if (SetFilePointerEx(hFile.get(), z64Seek, nullptr, FILE_BEGIN)) {
                            Zip64EndOfCentralDir z64eocd{};
                            DWORD z64Read = 0;
                            if (ReadFile(hFile.get(), &z64eocd, sizeof(z64eocd), &z64Read, nullptr)
                                && z64Read >= sizeof(z64eocd)
                                && z64eocd.signature == ZIP_ZIP64_EOCD_SIG) {
                                centralDirOffset = z64eocd.centralDirOffset;
                            }
                        }
                    }
                }

                break;
            }
            }
        }

        // Validate central dir offset before seeking
        if (centralDirOffset >= fileSize) {
            summary.result = ExtractionResult::CorruptedArchive;
            summary.errors.push_back("Central directory offset beyond EOF");
            return;
        }

        // Read central directory for extraction
        seekPos.QuadPart = static_cast<LONGLONG>(centralDirOffset);
        SetFilePointerEx(hFile.get(), seekPos, nullptr, FILE_BEGIN);

        uint64_t totalExtracted = 0;
        uint32_t entryIndex = 0;

        for (const auto& entry : entries) {
            if (IsCancelled()) {
                summary.result = ExtractionResult::Cancelled;
                break;
            }

            summary.entriesProcessed++;

            // Read central directory entry for this position
            ZipCentralDirEntry cde{};
            if (!ReadFile(hFile.get(), &cde, sizeof(cde), &bytesRead, nullptr) ||
                bytesRead < sizeof(cde) || cde.signature != ZIP_CENTRAL_SIG) {
                break;
            }

            // Skip filename, extra, comment
            LARGE_INTEGER skipLen{};
            skipLen.QuadPart = cde.fileNameLength + cde.extraFieldLength + cde.commentLength;
            SetFilePointerEx(hFile.get(), skipLen, nullptr, FILE_CURRENT);

            // Save current position before extraction
            LARGE_INTEGER savedPos{};
            SetFilePointerEx(hFile.get(), {}, &savedPos, FILE_CURRENT);

            // Skip directories
            if (entry.isDirectory) {
                SetFilePointerEx(hFile.get(), savedPos, nullptr, FILE_BEGIN);
                entryIndex++;
                continue;
            }

            // Skip encrypted
            if (entry.isEncrypted && options.skipEncrypted) {
                m_stats.encryptedSkipped.fetch_add(1, std::memory_order_relaxed);
                summary.entriesSkipped++;
                SetFilePointerEx(hFile.get(), savedPos, nullptr, FILE_BEGIN);
                entryIndex++;
                continue;
            }

            // Skip entries with security issues if configured
            if (entry.securityFlags != SecurityFlag::None) {
                // Fire SecurityCallback so callers can log/alert on the issue
                bool shouldContinue = true;
                {
                    std::shared_lock lock(m_dataMutex);
                    if (m_securityCallback) {
                        try { shouldContinue = m_securityCallback(entry, entry.securityFlags); }
                        catch (...) {}
                    }
                }
                if (!shouldContinue || (m_config.abortOnSecurityIssue &&
                    HasFlag(entry.securityFlags, SecurityFlag::PathTraversalAttempt))) {
                    summary.entriesSkipped++;
                    SetFilePointerEx(hFile.get(), savedPos, nullptr, FILE_BEGIN);
                    entryIndex++;
                    continue;
                }
            }

            // Overflow-safe total extraction size limit check
            if (totalExtracted > options.maxTotalSize - entry.uncompressedSize ||
                totalExtracted + entry.uncompressedSize > options.maxTotalSize) {
                summary.warnings.push_back("Total extraction size limit reached");
                break;
            }

            // Extract the entry if not metadata-only mode
            std::vector<uint8_t> data;
            if (options.mode != ExtractionMode::MetadataOnly) {
                data = ExtractZipEntry(hFile.get(), cde, cde.fileNameLength, options);

                if (!data.empty()) {
                    totalExtracted += data.size();
                    m_stats.bytesExtracted.fetch_add(data.size(), std::memory_order_relaxed);
                    m_stats.entriesExtracted.fetch_add(1, std::memory_order_relaxed);
                    summary.bytesExtracted += data.size();
                    summary.entriesExtracted++;
                } else if (cde.uncompressedSize > 0) {
                    summary.entriesFailed++;
                    m_stats.extractionErrors.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Fire callback
            if (callback) {
                try {
                    // Compute entropy for extracted data
                    ArchiveEntry enrichedEntry = entry;
                    if (!data.empty()) {
                        enrichedEntry.entropy = CalculateEntropy(
                            std::span<const uint8_t>(data.data(), data.size()));

                        // Compute SHA256 hash of extracted content
                        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                        if (hasher.Update(data.data(), data.size())) {
                            std::string hexHash;
                            if (hasher.FinalHex(hexHash, false)) {
                                enrichedEntry.sha256Hex = std::move(hexHash);
                            }
                        }

                        // Check for PE header in extracted content
                        if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
                            enrichedEntry.isPE = true;
                        }

                        // Check for script indicators
                        if (data.size() >= 10) {
                            std::string_view header(
                                reinterpret_cast<const char*>(data.data()),
                                std::min(data.size(), static_cast<size_t>(256)));
                            if (header.find("#!/") != std::string_view::npos ||
                                header.find("powershell") != std::string_view::npos ||
                                header.find("wscript") != std::string_view::npos ||
                                header.find("<script") != std::string_view::npos) {
                                enrichedEntry.isScript = true;
                            }
                        }
                    }

                    callback(enrichedEntry, data);

                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"ArchiveExtractor",
                        L"Entry callback exception: %hs", e.what());
                    summary.entriesFailed++;
                }
            }

            // Handle nested archives
            if (entry.isNestedArchive && options.extractNestedArchives && !data.empty()) {
                m_stats.nestedArchives.fetch_add(1, std::memory_order_relaxed);
                summary.nestedArchives++;

                // CSPRNG-derived suffix avoids the predictable-path race that
                // plain PID+QPC produced.
                Utils::CryptoUtils::SecureRandom rng;
                uint64_t rnd = rng.NextUInt64();
                LARGE_INTEGER perfCounter{};
                QueryPerformanceCounter(&perfCounter);
                wchar_t suffix[64]{};
                _snwprintf_s(suffix, _countof(suffix), _TRUNCATE,
                    L"ae_zip_%lu_%llx_%llx_%lu",
                    GetCurrentProcessId(),
                    static_cast<uint64_t>(perfCounter.QuadPart),
                    rnd,
                    static_cast<unsigned long>(entryIndex));
                fs::path tempPath = fs::path(m_config.tempDirectory) / suffix;

                bool tempCreated = false;
                {
                    std::ofstream tempFile(tempPath,
                        std::ios::binary | std::ios::trunc);
                    if (tempFile) {
                        tempFile.write(
                            reinterpret_cast<const char*>(data.data()),
                            static_cast<std::streamsize>(data.size()));
                        tempFile.close();
                        tempCreated = tempFile.good();
                    }
                }

                if (tempCreated) {
                    // RAII guard guarantees the temp file is removed even if a
                    // recursive scan throws.
                    struct TempGuard {
                        fs::path p;
                        ~TempGuard() {
                            std::error_code ec;
                            fs::remove(p, ec);
                        }
                    } guard{ tempPath };

                    try {
                        // Dispatch nested scan by detected format
                        auto nestedFmt = DetectFormat(tempPath.wstring());
                        if (nestedFmt == ArchiveFormat::TAR) {
                            ScanTarArchive(tempPath.wstring(), callback, options,
                                           summary, nestingLevel + 1);
                        } else {
                            ScanZipArchive(tempPath.wstring(), callback, options,
                                           summary, nestingLevel + 1);
                        }
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(L"ArchiveExtractor",
                            L"Nested ZIP scan threw: %hs", e.what());
                        summary.entriesFailed++;
                    }
                }
            }

            // Report progress
            {
                std::shared_lock lock(m_dataMutex);
                if (m_progressCallback) {
                    ExtractionProgress progress;
                    progress.currentEntry = entryIndex;
                    progress.totalEntries = static_cast<uint32_t>(entries.size());
                    progress.bytesExtracted = summary.bytesExtracted;
                    progress.currentFile = entry.path;
                    progress.nestingLevel = nestingLevel;
                    progress.percentComplete = entries.empty() ? 100.0 :
                        (static_cast<double>(entryIndex + 1) /
                         static_cast<double>(entries.size())) * 100.0;

                    try { m_progressCallback(progress); }
                    catch (...) {}
                }
            }

            // Restore position to continue reading central directory
            SetFilePointerEx(hFile.get(), savedPos, nullptr, FILE_BEGIN);
            entryIndex++;
        }

        // ScopedHandle closes hFile automatically

        if (summary.result == ExtractionResult::Success && summary.entriesFailed > 0) {
            summary.result = ExtractionResult::PartialSuccess;
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    void ShutdownInternal() noexcept {
        try {
            m_cancelled.store(true, std::memory_order_release);

            {
                std::unique_lock lock(m_dataMutex);
                m_passwordCallback = nullptr;
                m_progressCallback = nullptr;
                m_securityCallback = nullptr;
                m_cache.clear();
            }

            m_initialized = false;
            SS_LOG_INFO(L"ArchiveExtractor", L"Shutdown complete");

        } catch (...) {
            // Suppress all exceptions during shutdown
        }
    }

    [[nodiscard]] std::string GetFormatName(ArchiveFormat format) const noexcept {
        switch (format) {
            case ArchiveFormat::ZIP:      return "ZIP";
            case ArchiveFormat::RAR:      return "RAR";
            case ArchiveFormat::RAR5:     return "RAR5";
            case ArchiveFormat::SevenZip: return "7-Zip";
            case ArchiveFormat::TAR:      return "TAR";
            case ArchiveFormat::GZIP:     return "GZIP";
            case ArchiveFormat::BZIP2:    return "BZIP2";
            case ArchiveFormat::XZ:       return "XZ";
            case ArchiveFormat::LZMA:     return "LZMA";
            case ArchiveFormat::ZSTD:     return "ZSTD";
            case ArchiveFormat::TarGz:    return "TAR.GZ";
            case ArchiveFormat::TarBz2:   return "TAR.BZ2";
            case ArchiveFormat::TarXz:    return "TAR.XZ";
            case ArchiveFormat::TarZstd:  return "TAR.ZSTD";
            case ArchiveFormat::CAB:      return "CAB";
            case ArchiveFormat::MSI:      return "MSI";
            case ArchiveFormat::WIM:      return "WIM";
            case ArchiveFormat::ISO:      return "ISO";
            case ArchiveFormat::VHD:      return "VHD";
            case ArchiveFormat::VHDX:     return "VHDX";
            case ArchiveFormat::DMG:      return "DMG";
            case ArchiveFormat::IMG:      return "IMG";
            case ArchiveFormat::ARJ:      return "ARJ";
            case ArchiveFormat::LZH:      return "LZH";
            case ArchiveFormat::ACE:      return "ACE";
            case ArchiveFormat::CPIO:     return "CPIO";
            case ArchiveFormat::RPM:      return "RPM";
            case ArchiveFormat::DEB:      return "DEB";
            default:                      return "Unknown";
        }
    }

    [[nodiscard]] bool MatchesPattern(
        const std::wstring& path, const std::wstring& pattern) const noexcept {

        if (pattern == L"*") return true;
        if (pattern.find(L'*') == std::wstring::npos) return path == pattern;

        // Extension match: *.exe
        if (pattern.starts_with(L"*.")) {
            auto ext = pattern.substr(1);
            return path.ends_with(ext);
        }

        // Contains match: *foo* — must be checked BEFORE single-end wildcard
        if (pattern.starts_with(L"*") && pattern.ends_with(L"*") && pattern.length() > 2) {
            auto middle = pattern.substr(1, pattern.length() - 2);
            return path.find(middle) != std::wstring::npos;
        }

        // Prefix match: dir/*
        if (pattern.ends_with(L"*")) {
            auto prefix = pattern.substr(0, pattern.length() - 1);
            return path.starts_with(prefix);
        }

        // Suffix match: *filename
        if (pattern.starts_with(L"*")) {
            auto suffix = pattern.substr(1);
            return path.ends_with(suffix);
        }

        return false;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_lifecycleMutex;
    mutable std::shared_mutex m_dataMutex;
    bool m_initialized{ false };

    ArchiveExtractorConfig m_config;
    mutable AtomicStats m_stats;

    // Cache
    struct CacheEntry {
        ArchiveInfo info;
        std::chrono::steady_clock::time_point timestamp;
    };
    mutable std::unordered_map<std::wstring, CacheEntry> m_cache;

    // Callbacks
    PasswordCallback m_passwordCallback;
    ArchiveProgressCallback m_progressCallback;
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
    SS_LOG_INFO(L"ArchiveExtractor", L"Instance created");
}

ArchiveExtractor::~ArchiveExtractor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
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

bool ArchiveExtractor::TestPassword(
    const std::wstring& filePath, const std::string& password) const {
    return m_impl->TestPassword(filePath, password);
}

void ArchiveExtractor::SetProgressCallback(ArchiveProgressCallback callback) {
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

ArchiveExtractorStatistics ArchiveExtractor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void ArchiveExtractor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool ArchiveExtractor::HandleKernelScanRequest(
    const std::wstring& filePath,
    uint32_t processId,
    std::function<bool(const ArchiveEntry& entry, std::span<const uint8_t> data)> scanCallback) {
    return m_impl->HandleKernelScanRequest(filePath, processId, std::move(scanCallback));
}

SecurityFlag ArchiveExtractor::QuickSecurityCheck(
    const std::wstring& filePath, uint64_t fileSize) const {
    return m_impl->QuickSecurityCheck(filePath, fileSize);
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
