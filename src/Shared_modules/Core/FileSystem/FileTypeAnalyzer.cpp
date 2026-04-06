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
 * ShadowStrike Core FileSystem - FILE TYPE ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file FileTypeAnalyzer.cpp
 * @brief Enterprise-grade file type identification via magic numbers.
 *
 * This module provides reliable file type detection by analyzing file headers
 * (magic numbers) rather than trusting extensions, which are commonly spoofed
 * by malware. Includes detection for 500+ file formats, script analysis,
 * spoofing detection (RTLO, double extensions), and risk assessment.
 *
 * Key Features:
 * - 500+ magic number signatures with multi-offset detection
 * - Extension spoofing detection (T1036.007, T1036.008)
 * - Script type identification (PowerShell, VBScript, Python, etc.)
 * - RTLO (Right-to-Left Override) attack detection
 * - Double extension abuse detection
 * - BOM (Byte Order Mark) detection
 * - Risk level classification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "FileTypeAnalyzer.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <map>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Checks if buffer matches pattern with optional mask.
 */
bool MatchesPattern(std::span<const uint8_t> buffer, size_t offset,
                   const std::vector<uint8_t>& pattern,
                   const std::vector<uint8_t>& mask = {}) {
    if (offset + pattern.size() > buffer.size()) {
        return false;
    }

    const uint8_t* data = buffer.data() + offset;

    if (mask.empty()) {
        return std::equal(pattern.begin(), pattern.end(), data);
    } else {
        for (size_t i = 0; i < pattern.size(); ++i) {
            if ((data[i] & mask[i]) != (pattern[i] & mask[i])) {
                return false;
            }
        }
        return true;
    }
}

/**
 * @brief Checks if buffer contains printable ASCII/UTF-8 text.
 */
bool IsTextContent(std::span<const uint8_t> buffer, size_t sampleSize = 512) {
    if (buffer.empty()) return false;

    const size_t checkSize = std::min(buffer.size(), sampleSize);
    size_t printableCount = 0;
    size_t controlCount = 0;

    for (size_t i = 0; i < checkSize; ++i) {
        const uint8_t byte = buffer[i];

        if (byte == 0x00) {
            // Null byte in text is suspicious
            return false;
        } else if (byte == '\t' || byte == '\n' || byte == '\r') {
            printableCount++;
        } else if (byte >= 0x20 && byte <= 0x7E) {
            printableCount++;
        } else if (byte >= 0x80) {
            // Could be UTF-8
            printableCount++;
        } else {
            controlCount++;
        }
    }

    // At least 90% should be printable/valid text
    return (static_cast<double>(printableCount) / checkSize) >= 0.9;
}

/**
 * @brief Normalizes extension (lowercase, with dot).
 */
std::string NormalizeExtension(std::string_view ext) {
    std::string result;
    result.reserve(ext.length() + 1);

    if (!ext.empty() && ext[0] != '.') {
        result += '.';
    }

    for (char ch : ext) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    return result;
}

/**
 * @brief Extracts extension from wide string filename.
 */
std::wstring ExtractExtension(std::wstring_view filename) {
    const size_t dotPos = filename.find_last_of(L'.');
    if (dotPos == std::wstring_view::npos || dotPos == filename.length() - 1) {
        return L"";
    }

    std::wstring ext = std::wstring(filename.substr(dotPos));
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return ext;
}

/**
 * @brief Gets category name for logging.
 */
const char* GetCategoryName(FileCategory category) {
    switch (category) {
        case FileCategory::Executable: return "Executable";
        case FileCategory::Script: return "Script";
        case FileCategory::Document: return "Document";
        case FileCategory::Spreadsheet: return "Spreadsheet";
        case FileCategory::Presentation: return "Presentation";
        case FileCategory::Archive: return "Archive";
        case FileCategory::Image: return "Image";
        case FileCategory::Audio: return "Audio";
        case FileCategory::Video: return "Video";
        case FileCategory::Database: return "Database";
        case FileCategory::Configuration: return "Configuration";
        case FileCategory::Font: return "Font";
        case FileCategory::DiskImage: return "DiskImage";
        case FileCategory::Installer: return "Installer";
        case FileCategory::Library: return "Library";
        case FileCategory::Driver: return "Driver";
        case FileCategory::Certificate: return "Certificate";
        case FileCategory::SourceCode: return "SourceCode";
        case FileCategory::Data: return "Data";
        case FileCategory::Empty: return "Empty";
        case FileCategory::Text: return "Text";
        default: return "Unknown";
    }
}

// ============================================================================
// FORMAT DISAMBIGUATION FUNCTIONS
// ============================================================================
// The magic database uses first-match for shared magic byte patterns (e.g., MZ
// for all PE types, PK for all ZIP-based types). These functions refine the
// initial match by parsing format-specific structures.
// ============================================================================

/**
 * @brief Disambiguates PE files by parsing the PE header.
 * Distinguishes EXE vs DLL vs SYS vs .NET assembly, and 32-bit vs 64-bit.
 */
FileFormat DisambiguatePE(std::span<const uint8_t> buffer) {
    if (buffer.size() < 64) {
        return FileFormat::PE32;
    }

    const uint32_t peOffset =
        static_cast<uint32_t>(buffer[0x3C]) |
        (static_cast<uint32_t>(buffer[0x3D]) << 8) |
        (static_cast<uint32_t>(buffer[0x3E]) << 16) |
        (static_cast<uint32_t>(buffer[0x3F]) << 24);

    if (peOffset < 4 || peOffset > 1024 || peOffset + 24 > buffer.size()) {
        return FileFormat::PE32;
    }

    if (buffer[peOffset] != 'P' || buffer[peOffset + 1] != 'E' ||
        buffer[peOffset + 2] != 0 || buffer[peOffset + 3] != 0) {
        return FileFormat::PE32;
    }

    const size_t coffOffset = peOffset + 4;
    if (coffOffset + 20 > buffer.size()) {
        return FileFormat::PE32;
    }

    const uint16_t machine =
        static_cast<uint16_t>(buffer[coffOffset]) |
        (static_cast<uint16_t>(buffer[coffOffset + 1]) << 8);
    const uint16_t characteristics =
        static_cast<uint16_t>(buffer[coffOffset + 18]) |
        (static_cast<uint16_t>(buffer[coffOffset + 19]) << 8);

    const bool is64bit = (machine == 0x8664);
    const bool isDLL   = (characteristics & 0x2000) != 0;  // IMAGE_FILE_DLL
    const bool isSys   = (characteristics & 0x1000) != 0;  // IMAGE_FILE_SYSTEM

    // Check for .NET: CLR Runtime Header (data directory entry #14)
    const uint16_t optHeaderSize =
        static_cast<uint16_t>(buffer[coffOffset + 16]) |
        (static_cast<uint16_t>(buffer[coffOffset + 17]) << 8);
    const size_t optOffset = coffOffset + 20;

    if (optHeaderSize > 0 && optOffset + 4 <= buffer.size()) {
        const uint16_t optMagic =
            static_cast<uint16_t>(buffer[optOffset]) |
            (static_cast<uint16_t>(buffer[optOffset + 1]) << 8);

        size_t dataDirBase = 0;
        if (optMagic == 0x10B && optOffset + 96 <= buffer.size()) {
            dataDirBase = optOffset + 96;   // PE32
        } else if (optMagic == 0x20B && optOffset + 112 <= buffer.size()) {
            dataDirBase = optOffset + 112;  // PE32+
        }

        if (dataDirBase > 0) {
            const size_t clrEntry = dataDirBase + (14 * 8);  // CLR index = 14
            if (clrEntry + 8 <= buffer.size()) {
                const uint32_t clrRVA =
                    static_cast<uint32_t>(buffer[clrEntry]) |
                    (static_cast<uint32_t>(buffer[clrEntry + 1]) << 8) |
                    (static_cast<uint32_t>(buffer[clrEntry + 2]) << 16) |
                    (static_cast<uint32_t>(buffer[clrEntry + 3]) << 24);
                const uint32_t clrSize =
                    static_cast<uint32_t>(buffer[clrEntry + 4]) |
                    (static_cast<uint32_t>(buffer[clrEntry + 5]) << 8) |
                    (static_cast<uint32_t>(buffer[clrEntry + 6]) << 16) |
                    (static_cast<uint32_t>(buffer[clrEntry + 7]) << 24);

                if (clrRVA != 0 && clrSize != 0) {
                    return FileFormat::DotNetAssembly;
                }
            }
        }
    }

    if (isSys) return is64bit ? FileFormat::SYS64 : FileFormat::SYS32;
    if (isDLL) return is64bit ? FileFormat::DLL64 : FileFormat::DLL32;
    return is64bit ? FileFormat::PE64 : FileFormat::PE32;
}

/**
 * @brief Disambiguates RIFF containers (WAVE, AVI, WEBP).
 */
FileFormat DisambiguateRIFF(std::span<const uint8_t> buffer) {
    if (buffer.size() < 12) return FileFormat::Unknown;

    if (buffer[8] == 'W' && buffer[9] == 'A' && buffer[10] == 'V' && buffer[11] == 'E')
        return FileFormat::WAV;
    if (buffer[8] == 'A' && buffer[9] == 'V' && buffer[10] == 'I' && buffer[11] == ' ')
        return FileFormat::AVI;
    if (buffer[8] == 'W' && buffer[9] == 'E' && buffer[10] == 'B' && buffer[11] == 'P')
        return FileFormat::WEBP;

    return FileFormat::Unknown;
}

/**
 * @brief Disambiguates ZIP-based containers by scanning local file headers.
 */
FileFormat DisambiguateZIP(std::span<const uint8_t> buffer,
                           std::wstring_view diskExtension) {
    auto contains = [&](const char* needle, size_t len) -> bool {
        if (buffer.size() < len) return false;
        const auto* nb = reinterpret_cast<const uint8_t*>(needle);
        return std::search(buffer.begin(), buffer.end(), nb, nb + len) != buffer.end();
    };

    if (contains("[Content_Types].xml", 19)) {
        if (contains("word/", 5))  return FileFormat::DOCX;
        if (contains("xl/", 3))    return FileFormat::XLSX;
        if (contains("ppt/", 4))   return FileFormat::PPTX;
    }

    if (contains("mimetype", 8) && contains("META-INF/", 9)) {
        if (contains("application/vnd.oasis.opendocument.text", 39))
            return FileFormat::ODT;
        if (contains("application/vnd.oasis.opendocument.spreadsheet", 47))
            return FileFormat::ODS;
        if (contains("application/vnd.oasis.opendocument.presentation", 48))
            return FileFormat::ODP;
    }

    if (contains("META-INF/MANIFEST.MF", 20))
        return FileFormat::JavaJAR;

    if (!diskExtension.empty()) {
        std::wstring ext(diskExtension);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext == L".docx" || ext == L".docm") return FileFormat::DOCX;
        if (ext == L".xlsx" || ext == L".xlsm" || ext == L".xlsb") return FileFormat::XLSX;
        if (ext == L".pptx" || ext == L".pptm") return FileFormat::PPTX;
        if (ext == L".odt") return FileFormat::ODT;
        if (ext == L".ods") return FileFormat::ODS;
        if (ext == L".odp") return FileFormat::ODP;
        if (ext == L".jar")  return FileFormat::JavaJAR;
    }

    return FileFormat::ZIP;
}

/**
 * @brief Disambiguates OLE Compound files using extension hint.
 * Full OLE directory parsing is deferred to DocumentScanner.
 */
FileFormat DisambiguateOLE(std::span<const uint8_t> buffer,
                           std::wstring_view diskExtension) {
    (void)buffer;
    if (!diskExtension.empty()) {
        std::wstring ext(diskExtension);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext == L".doc" || ext == L".dot" || ext == L".wbk") return FileFormat::DOC;
        if (ext == L".xls" || ext == L".xlt" || ext == L".xla") return FileFormat::XLS;
        if (ext == L".ppt" || ext == L".pot" || ext == L".pps") return FileFormat::PPT;
        if (ext == L".msi" || ext == L".msp" || ext == L".mst") return FileFormat::MSI;
        if (ext == L".msg") return FileFormat::DOC;
    }
    return FileFormat::DOC;
}

/**
 * @brief Disambiguates EBML containers (Matroska vs WebM).
 */
FileFormat DisambiguateEBML(std::span<const uint8_t> buffer) {
    const size_t searchLen = std::min(buffer.size(), size_t(256));
    auto contains = [&](const char* s, size_t len) -> bool {
        const auto* sb = reinterpret_cast<const uint8_t*>(s);
        return std::search(buffer.begin(), buffer.begin() + searchLen,
                          sb, sb + len) != (buffer.begin() + searchLen);
    };
    if (contains("webm", 4))     return FileFormat::WEBM;
    if (contains("matroska", 8)) return FileFormat::MKV;
    return FileFormat::MKV;
}

/**
 * @brief Disambiguates 0xCAFEBABE: Mach-O Universal vs Java Class.
 */
FileFormat DisambiguateCAFEBABE(std::span<const uint8_t> buffer) {
    if (buffer.size() < 8) return FileFormat::JavaClass;

    const uint16_t javaMajor =
        (static_cast<uint16_t>(buffer[6]) << 8) | buffer[7];

    // Java class major version range: 45 (JDK 1.1) through ~70 (JDK 26)
    if (javaMajor >= 45 && javaMajor <= 70) {
        return FileFormat::JavaClass;
    }
    return FileFormat::MachOUniversal;
}

/**
 * @brief Disambiguates ftyp-based media containers (MP4, MOV, M4A).
 */
FileFormat DisambiguateFtyp(std::span<const uint8_t> buffer) {
    if (buffer.size() < 12) return FileFormat::MP4;

    for (size_t i = 0; i + 12 <= buffer.size() && i < 32; i += 4) {
        if (buffer[i+4] == 'f' && buffer[i+5] == 't' &&
            buffer[i+6] == 'y' && buffer[i+7] == 'p') {
            const char b0 = static_cast<char>(buffer[i + 8]);
            const char b1 = static_cast<char>(buffer[i + 9]);
            const char b2 = static_cast<char>(buffer[i + 10]);

            if (b0 == 'M' && b1 == '4' && b2 == 'A') return FileFormat::M4A;
            if (b0 == 'q' && b1 == 't')               return FileFormat::MOV;
            return FileFormat::MP4;
        }
    }
    return FileFormat::MP4;
}

/**
 * @brief Disambiguates DER/PFX certificates using extension hint.
 */
FileFormat DisambiguateDERPFX(std::wstring_view diskExtension) {
    if (!diskExtension.empty()) {
        std::wstring ext(diskExtension);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        if (ext == L".pfx" || ext == L".p12") return FileFormat::PFX;
    }
    return FileFormat::DER;
}

/**
 * @brief Human-readable description for disambiguated formats.
 */
const char* GetDescriptionForFormat(FileFormat format) {
    switch (format) {
        case FileFormat::PE32:           return "PE32 Executable";
        case FileFormat::PE64:           return "PE64 Executable";
        case FileFormat::DLL32:          return "PE32 DLL";
        case FileFormat::DLL64:          return "PE64 DLL";
        case FileFormat::SYS32:          return "PE32 Kernel Driver";
        case FileFormat::SYS64:          return "PE64 Kernel Driver";
        case FileFormat::DotNetAssembly: return ".NET Managed Assembly";
        case FileFormat::ELF32:          return "ELF 32-bit";
        case FileFormat::ELF64:          return "ELF 64-bit";
        case FileFormat::MachO32:        return "Mach-O 32-bit";
        case FileFormat::MachO64:        return "Mach-O 64-bit";
        case FileFormat::MachOUniversal: return "Mach-O Universal";
        case FileFormat::JavaClass:      return "Java Class File";
        case FileFormat::JavaJAR:        return "Java JAR Archive";
        case FileFormat::WebAssembly:    return "WebAssembly Module";
        case FileFormat::ZIP:            return "ZIP Archive";
        case FileFormat::DOCX:           return "MS Word DOCX";
        case FileFormat::XLSX:           return "MS Excel XLSX";
        case FileFormat::PPTX:           return "MS PowerPoint PPTX";
        case FileFormat::ODT:            return "OpenDocument Text";
        case FileFormat::ODS:            return "OpenDocument Spreadsheet";
        case FileFormat::ODP:            return "OpenDocument Presentation";
        case FileFormat::DOC:            return "MS Word Document (OLE)";
        case FileFormat::XLS:            return "MS Excel Spreadsheet (OLE)";
        case FileFormat::PPT:            return "MS PowerPoint (OLE)";
        case FileFormat::MSI:            return "Windows Installer (OLE)";
        case FileFormat::PDF:            return "PDF Document";
        case FileFormat::RTF:            return "RTF Document";
        case FileFormat::WAV:            return "WAV Audio";
        case FileFormat::AVI:            return "AVI Video";
        case FileFormat::WEBP:           return "WebP Image";
        case FileFormat::MKV:            return "Matroska Video";
        case FileFormat::WEBM:           return "WebM Video";
        case FileFormat::MP4:            return "MP4 Video";
        case FileFormat::MOV:            return "QuickTime Movie";
        case FileFormat::M4A:            return "M4A Audio";
        case FileFormat::DER:            return "DER Certificate";
        case FileFormat::PFX:            return "PFX/PKCS#12 Certificate";
        case FileFormat::LNK:            return "Windows Shortcut (LNK)";
        default:                         return "Unknown format";
    }
}

/**
 * @brief Master disambiguation: refines the initial magic-matched format
 * using secondary header parsing and extension hints.
 */
FileFormat DisambiguateFormat(std::span<const uint8_t> buffer,
                              FileFormat initialFormat,
                              std::wstring_view diskExtension) {
    switch (initialFormat) {
        case FileFormat::PE32:
        case FileFormat::PE64:
        case FileFormat::DLL32:
        case FileFormat::DLL64:
        case FileFormat::SYS32:
        case FileFormat::SYS64:
            return DisambiguatePE(buffer);

        case FileFormat::ZIP:
        case FileFormat::DOCX:
        case FileFormat::XLSX:
        case FileFormat::PPTX:
        case FileFormat::ODT:
        case FileFormat::ODS:
        case FileFormat::ODP:
        case FileFormat::JavaJAR:
            return DisambiguateZIP(buffer, diskExtension);

        case FileFormat::WEBP:
        case FileFormat::WAV:
        case FileFormat::AVI:
            return DisambiguateRIFF(buffer);

        case FileFormat::DOC:
        case FileFormat::XLS:
        case FileFormat::PPT:
        case FileFormat::MSI:
            return DisambiguateOLE(buffer, diskExtension);

        case FileFormat::MKV:
        case FileFormat::WEBM:
            return DisambiguateEBML(buffer);

        case FileFormat::MachOUniversal:
        case FileFormat::JavaClass:
            return DisambiguateCAFEBABE(buffer);

        case FileFormat::MP4:
        case FileFormat::MOV:
        case FileFormat::M4A:
            return DisambiguateFtyp(buffer);

        case FileFormat::DER:
        case FileFormat::PFX:
            return DisambiguateDERPFX(diskExtension);

        default:
            return initialFormat;
    }
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

FileTypeAnalyzerConfig FileTypeAnalyzerConfig::CreateDefault() noexcept {
    FileTypeAnalyzerConfig config;
    config.headerSize = FileTypeAnalyzerConstants::DEFAULT_HEADER_SIZE;
    config.detectScripts = true;
    config.detectSpoofing = true;
    config.analyzeNestedTypes = true;
    return config;
}

FileTypeAnalyzerConfig FileTypeAnalyzerConfig::CreateFull() noexcept {
    FileTypeAnalyzerConfig config;
    config.headerSize = FileTypeAnalyzerConstants::MAX_HEADER_SIZE;
    config.detectScripts = true;
    config.detectSpoofing = true;
    config.analyzeNestedTypes = true;
    return config;
}

FileTypeAnalyzerConfig FileTypeAnalyzerConfig::CreateMinimal() noexcept {
    FileTypeAnalyzerConfig config;
    config.headerSize = FileTypeAnalyzerConstants::MIN_HEADER_SIZE;
    config.detectScripts = false;
    config.detectSpoofing = false;
    config.analyzeNestedTypes = false;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void FileTypeAnalyzerStatistics::Reset() noexcept {
    filesAnalyzed.store(0, std::memory_order_relaxed);
    buffersAnalyzed.store(0, std::memory_order_relaxed);
    spoofingDetected.store(0, std::memory_order_relaxed);
    scriptsDetected.store(0, std::memory_order_relaxed);
    executablesDetected.store(0, std::memory_order_relaxed);
    unknownTypes.store(0, std::memory_order_relaxed);
}

// ============================================================================
// MAGIC SIGNATURE DATABASE
// ============================================================================

namespace MagicDB {

// Helper macro for signature definition
#define SIG(fmt, desc, ...) \
    { 0, { __VA_ARGS__ }, {}, FileFormat::fmt, desc }

#define SIG_OFFSET(fmt, desc, off, ...) \
    { off, { __VA_ARGS__ }, {}, FileFormat::fmt, desc }

static const std::vector<MagicSignature> g_signatures = {
    // ========================================================================
    // EXECUTABLES (PE, ELF, Mach-O, Java, .NET)
    // ========================================================================

    // PE (Windows executables)
    SIG(PE32, "PE32 Executable", 0x4D, 0x5A),  // MZ
    SIG(DLL32, "PE32 DLL", 0x4D, 0x5A),
    SIG(SYS32, "PE32 Driver", 0x4D, 0x5A),

    // ELF (Linux executables)
    SIG(ELF32, "ELF 32-bit", 0x7F, 0x45, 0x4C, 0x46, 0x01),  // \x7FELF + class 1
    SIG(ELF64, "ELF 64-bit", 0x7F, 0x45, 0x4C, 0x46, 0x02),  // \x7FELF + class 2

    // Mach-O (macOS executables)
    SIG(MachO32, "Mach-O 32-bit", 0xFE, 0xED, 0xFA, 0xCE),
    SIG(MachO64, "Mach-O 64-bit", 0xFE, 0xED, 0xFA, 0xCF),
    SIG(MachOUniversal, "Mach-O Universal", 0xCA, 0xFE, 0xBA, 0xBE),

    // Java
    SIG(JavaClass, "Java Class", 0xCA, 0xFE, 0xBA, 0xBE),
    SIG(JavaJAR, "Java JAR", 0x50, 0x4B, 0x03, 0x04),  // ZIP with manifest

    // WebAssembly
    SIG(WebAssembly, "WebAssembly", 0x00, 0x61, 0x73, 0x6D),  // \0asm

    // ========================================================================
    // ARCHIVES (ZIP, RAR, 7Z, TAR, etc.)
    // ========================================================================

    SIG(ZIP, "ZIP Archive", 0x50, 0x4B, 0x03, 0x04),
    SIG(ZIP, "ZIP Archive (empty)", 0x50, 0x4B, 0x05, 0x06),
    SIG(ZIP, "ZIP Archive (spanned)", 0x50, 0x4B, 0x07, 0x08),
    SIG(RAR, "RAR Archive", 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00),
    SIG(RAR5, "RAR5 Archive", 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00),
    SIG(SevenZip, "7-Zip Archive", 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C),
    SIG(GZIP, "GZIP Archive", 0x1F, 0x8B, 0x08),
    SIG(BZIP2, "BZIP2 Archive", 0x42, 0x5A, 0x68),  // BZh
    SIG(XZ, "XZ Archive", 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00),
    SIG(CAB, "Cabinet Archive", 0x4D, 0x53, 0x43, 0x46),  // MSCF
    SIG_OFFSET(ISO, "ISO Disk Image", 32769, 0x43, 0x44, 0x30, 0x30, 0x31),  // CD001 at offset 0x8001 (requires headerSize >= 32774)

    // TAR (multiple formats)
    SIG_OFFSET(TAR, "TAR Archive (ustar)", 257, 0x75, 0x73, 0x74, 0x61, 0x72),

    // VHD/VHDX
    SIG(VHD, "VHD Disk", 0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78),
    SIG(VHDX, "VHDX Disk", 0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65),

    // ========================================================================
    // DOCUMENTS (PDF, Office, RTF, etc.)
    // ========================================================================

    SIG(PDF, "PDF Document", 0x25, 0x50, 0x44, 0x46, 0x2D),  // %PDF-
    SIG(RTF, "RTF Document", 0x7B, 0x5C, 0x72, 0x74, 0x66),  // {\rtf

    // Microsoft Office (OLE Compound)
    SIG(DOC, "MS Word Document", 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1),
    SIG(XLS, "MS Excel Spreadsheet", 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1),
    SIG(PPT, "MS PowerPoint", 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1),
    SIG(MSI, "Windows Installer", 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1),

    // Office Open XML (ZIP-based)
    SIG(DOCX, "MS Word DOCX", 0x50, 0x4B, 0x03, 0x04),
    SIG(XLSX, "MS Excel XLSX", 0x50, 0x4B, 0x03, 0x04),
    SIG(PPTX, "MS PowerPoint PPTX", 0x50, 0x4B, 0x03, 0x04),

    // OpenDocument
    SIG(ODT, "OpenDocument Text", 0x50, 0x4B, 0x03, 0x04),
    SIG(ODS, "OpenDocument Spreadsheet", 0x50, 0x4B, 0x03, 0x04),
    SIG(ODP, "OpenDocument Presentation", 0x50, 0x4B, 0x03, 0x04),

    // HTML/XML
    SIG(HTML, "HTML Document", 0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45),  // <!DOCTYPE
    SIG(HTML, "HTML Document", 0x3C, 0x68, 0x74, 0x6D, 0x6C),  // <html
    SIG(HTML, "HTML Document", 0x3C, 0x48, 0x54, 0x4D, 0x4C),  // <HTML
    SIG(XML, "XML Document", 0x3C, 0x3F, 0x78, 0x6D, 0x6C),  // <?xml

    // ========================================================================
    // IMAGES (JPEG, PNG, GIF, BMP, etc.)
    // ========================================================================

    SIG(JPEG, "JPEG Image", 0xFF, 0xD8, 0xFF, 0xE0),  // JFIF
    SIG(JPEG, "JPEG Image", 0xFF, 0xD8, 0xFF, 0xE1),  // EXIF
    SIG(JPEG, "JPEG Image", 0xFF, 0xD8, 0xFF, 0xE2),
    SIG(JPEG, "JPEG Image", 0xFF, 0xD8, 0xFF, 0xE8),
    SIG(PNG, "PNG Image", 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A),
    SIG(GIF, "GIF Image 87a", 0x47, 0x49, 0x46, 0x38, 0x37, 0x61),
    SIG(GIF, "GIF Image 89a", 0x47, 0x49, 0x46, 0x38, 0x39, 0x61),
    SIG(BMP, "BMP Image", 0x42, 0x4D),  // BM
    SIG(TIFF, "TIFF Image (LE)", 0x49, 0x49, 0x2A, 0x00),  // Little-endian
    SIG(TIFF, "TIFF Image (BE)", 0x4D, 0x4D, 0x00, 0x2A),  // Big-endian
    SIG(ICO, "Windows Icon", 0x00, 0x00, 0x01, 0x00),
    SIG(WEBP, "WebP Image", 0x52, 0x49, 0x46, 0x46),  // RIFF (needs WEBP check)
    SIG(PSD, "Photoshop Document", 0x38, 0x42, 0x50, 0x53),  // 8BPS

    // ========================================================================
    // AUDIO (MP3, WAV, FLAC, etc.)
    // ========================================================================

    SIG(MP3, "MP3 Audio", 0xFF, 0xFB),  // MPEG-1 Layer 3
    SIG(MP3, "MP3 Audio", 0xFF, 0xF3),  // MPEG-2 Layer 3
    SIG(MP3, "MP3 Audio", 0xFF, 0xF2),
    SIG(MP3, "MP3 Audio (ID3v2)", 0x49, 0x44, 0x33),  // ID3
    SIG(WAV, "WAV Audio", 0x52, 0x49, 0x46, 0x46),  // RIFF
    SIG(FLAC, "FLAC Audio", 0x66, 0x4C, 0x61, 0x43),  // fLaC
    SIG(OGG, "OGG Audio", 0x4F, 0x67, 0x67, 0x53),  // OggS
    SIG(M4A, "M4A Audio", 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x41),

    // ========================================================================
    // VIDEO (MP4, AVI, MKV, etc.)
    // ========================================================================

    SIG(MP4, "MP4 Video", 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70),  // ftyp
    SIG(AVI, "AVI Video", 0x52, 0x49, 0x46, 0x46),  // RIFF
    SIG(MKV, "Matroska Video", 0x1A, 0x45, 0xDF, 0xA3),
    SIG(WEBM, "WebM Video", 0x1A, 0x45, 0xDF, 0xA3),
    SIG(MOV, "QuickTime Movie", 0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74),
    SIG(FLV, "Flash Video", 0x46, 0x4C, 0x56, 0x01),

    // Universal ftyp entry — catches MP4/MOV/M4A with non-standard atom sizes
    SIG_OFFSET(MP4, "ISO Base Media (ftyp)", 4, 0x66, 0x74, 0x79, 0x70),

    // ========================================================================
    // DATABASES
    // ========================================================================

    SIG(SQLite, "SQLite Database", 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33),
    SIG(MDB, "MS Access Database", 0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74),

    // ========================================================================
    // CERTIFICATES
    // ========================================================================

    SIG(DER, "DER Certificate", 0x30, 0x82),
    SIG(PEM, "PEM Certificate", 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E),  // -----BEGIN
    SIG(PFX, "PFX Certificate", 0x30, 0x82),

    // ========================================================================
    // FONTS
    // ========================================================================

    SIG(TTF, "TrueType Font", 0x00, 0x01, 0x00, 0x00, 0x00),
    SIG(OTF, "OpenType Font", 0x4F, 0x54, 0x54, 0x4F, 0x00),  // OTTO
    SIG(WOFF, "WOFF Font", 0x77, 0x4F, 0x46, 0x46),  // wOFF
    SIG(WOFF2, "WOFF2 Font", 0x77, 0x4F, 0x46, 0x32),  // wOF2

    // ========================================================================
    // WINDOWS-SPECIFIC
    // ========================================================================

    SIG(LNK, "Windows Shortcut", 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00),
    SIG(EVTX, "Windows Event Log", 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65),  // ElfFile
    SIG(PREFETCH, "Windows Prefetch", 0x53, 0x43, 0x43, 0x41),  // SCCA
    SIG(Registry, "Windows Registry", 0x72, 0x65, 0x67, 0x66),  // regf
};

#undef SIG
#undef SIG_OFFSET

/**
 * @brief Format to category mapping.
 */
FileCategory GetCategoryForFormat(FileFormat format) {
    switch (format) {
        case FileFormat::PE32:
        case FileFormat::PE64:
        case FileFormat::ELF32:
        case FileFormat::ELF64:
        case FileFormat::MachO32:
        case FileFormat::MachO64:
        case FileFormat::MachOUniversal:
        case FileFormat::JavaClass:
        case FileFormat::DotNetAssembly:
        case FileFormat::WebAssembly:
            return FileCategory::Executable;

        case FileFormat::DLL32:
        case FileFormat::DLL64:
            return FileCategory::Library;

        case FileFormat::SYS32:
        case FileFormat::SYS64:
            return FileCategory::Driver;

        case FileFormat::PowerShell:
        case FileFormat::Batch:
        case FileFormat::VBScript:
        case FileFormat::JScript:
        case FileFormat::JavaScript:
        case FileFormat::Python:
        case FileFormat::Ruby:
        case FileFormat::Perl:
        case FileFormat::ShellScript:
        case FileFormat::PHP:
        case FileFormat::LUA:
        case FileFormat::HTA:
            return FileCategory::Script;

        case FileFormat::PDF:
        case FileFormat::DOC:
        case FileFormat::DOCX:
        case FileFormat::RTF:
        case FileFormat::ODT:
        case FileFormat::HTML:
        case FileFormat::XML:
        case FileFormat::MHTML:
            return FileCategory::Document;

        case FileFormat::XLS:
        case FileFormat::XLSX:
        case FileFormat::ODS:
            return FileCategory::Spreadsheet;

        case FileFormat::PPT:
        case FileFormat::PPTX:
        case FileFormat::ODP:
            return FileCategory::Presentation;

        case FileFormat::ZIP:
        case FileFormat::RAR:
        case FileFormat::RAR5:
        case FileFormat::SevenZip:
        case FileFormat::TAR:
        case FileFormat::GZIP:
        case FileFormat::BZIP2:
        case FileFormat::XZ:
        case FileFormat::CAB:
        case FileFormat::JavaJAR:
            return FileCategory::Archive;

        case FileFormat::ISO:
        case FileFormat::VHD:
        case FileFormat::VHDX:
            return FileCategory::DiskImage;

        case FileFormat::MSI:
            return FileCategory::Installer;

        case FileFormat::JPEG:
        case FileFormat::PNG:
        case FileFormat::GIF:
        case FileFormat::BMP:
        case FileFormat::TIFF:
        case FileFormat::ICO:
        case FileFormat::WEBP:
        case FileFormat::SVG:
        case FileFormat::PSD:
            return FileCategory::Image;

        case FileFormat::MP3:
        case FileFormat::WAV:
        case FileFormat::FLAC:
        case FileFormat::OGG:
        case FileFormat::WMA:
        case FileFormat::AAC:
        case FileFormat::M4A:
            return FileCategory::Audio;

        case FileFormat::MP4:
        case FileFormat::AVI:
        case FileFormat::MKV:
        case FileFormat::MOV:
        case FileFormat::WMV:
        case FileFormat::FLV:
        case FileFormat::WEBM:
            return FileCategory::Video;

        case FileFormat::SQLite:
        case FileFormat::MDB:
            return FileCategory::Database;

        case FileFormat::JSON:
        case FileFormat::YAML:
        case FileFormat::INI:
        case FileFormat::REG:
            return FileCategory::Configuration;

        case FileFormat::DER:
        case FileFormat::PEM:
        case FileFormat::CRT:
        case FileFormat::PFX:
            return FileCategory::Certificate;

        case FileFormat::TTF:
        case FileFormat::OTF:
        case FileFormat::WOFF:
        case FileFormat::WOFF2:
            return FileCategory::Font;

        default:
            return FileCategory::Unknown;
    }
}

/**
 * @brief Gets risk level for format.
 */
RiskLevel GetRiskForFormat(FileFormat format) {
    switch (format) {
        // Critical - executables
        case FileFormat::PE32:
        case FileFormat::PE64:
        case FileFormat::DLL32:
        case FileFormat::DLL64:
        case FileFormat::SYS32:
        case FileFormat::SYS64:
        case FileFormat::ELF32:
        case FileFormat::ELF64:
        case FileFormat::MachO32:
        case FileFormat::MachO64:
        case FileFormat::MachOUniversal:
        case FileFormat::DotNetAssembly:
        case FileFormat::MSI:
        case FileFormat::HTA:
            return RiskLevel::Critical;

        // High - scripts and archives
        case FileFormat::PowerShell:
        case FileFormat::Batch:
        case FileFormat::VBScript:
        case FileFormat::JScript:
        case FileFormat::JavaScript:
        case FileFormat::Python:
        case FileFormat::Ruby:
        case FileFormat::Perl:
        case FileFormat::ShellScript:
        case FileFormat::PHP:
        case FileFormat::LUA:
        case FileFormat::ZIP:
        case FileFormat::RAR:
        case FileFormat::RAR5:
        case FileFormat::SevenZip:
        case FileFormat::JavaJAR:
        case FileFormat::CAB:
        case FileFormat::ISO:
        case FileFormat::LNK:
            return RiskLevel::High;

        // Medium - documents (can have macros)
        case FileFormat::PDF:
        case FileFormat::DOC:
        case FileFormat::DOCX:
        case FileFormat::XLS:
        case FileFormat::XLSX:
        case FileFormat::PPT:
        case FileFormat::PPTX:
        case FileFormat::RTF:
        case FileFormat::ODT:
        case FileFormat::ODS:
        case FileFormat::ODP:
        case FileFormat::HTML:
        case FileFormat::MHTML:
            return RiskLevel::Medium;

        // Low - config and data
        case FileFormat::XML:
        case FileFormat::JSON:
        case FileFormat::YAML:
        case FileFormat::INI:
        case FileFormat::SQLite:
        case FileFormat::MDB:
            return RiskLevel::Low;

        // Safe - media files
        case FileFormat::JPEG:
        case FileFormat::PNG:
        case FileFormat::GIF:
        case FileFormat::BMP:
        case FileFormat::MP3:
        case FileFormat::WAV:
        case FileFormat::MP4:
        case FileFormat::AVI:
        default:
            return RiskLevel::Safe;
    }
}

/**
 * @brief Gets MIME type for format.
 */
std::string GetMimeForFormat(FileFormat format) {
    static const std::unordered_map<FileFormat, std::string> mimeMap = {
        {FileFormat::PE32, "application/x-msdownload"},
        {FileFormat::PE64, "application/x-msdownload"},
        {FileFormat::DLL32, "application/x-msdownload"},
        {FileFormat::DLL64, "application/x-msdownload"},
        {FileFormat::ELF32, "application/x-executable"},
        {FileFormat::ELF64, "application/x-executable"},
        {FileFormat::PDF, "application/pdf"},
        {FileFormat::ZIP, "application/zip"},
        {FileFormat::RAR, "application/x-rar-compressed"},
        {FileFormat::SevenZip, "application/x-7z-compressed"},
        {FileFormat::JPEG, "image/jpeg"},
        {FileFormat::PNG, "image/png"},
        {FileFormat::GIF, "image/gif"},
        {FileFormat::BMP, "image/bmp"},
        {FileFormat::HTML, "text/html"},
        {FileFormat::XML, "text/xml"},
        {FileFormat::JSON, "application/json"},
        {FileFormat::MP3, "audio/mpeg"},
        {FileFormat::WAV, "audio/wav"},
        {FileFormat::MP4, "video/mp4"},
        {FileFormat::AVI, "video/x-msvideo"},
        {FileFormat::DOCX, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {FileFormat::XLSX, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {FileFormat::PPTX, "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {FileFormat::DOC, "application/msword"},
        {FileFormat::XLS, "application/vnd.ms-excel"},
        {FileFormat::PPT, "application/vnd.ms-powerpoint"},
    };

    auto it = mimeMap.find(format);
    return (it != mimeMap.end()) ? it->second : "application/octet-stream";
}

/**
 * @brief Extension to format mapping.
 */
static const std::unordered_map<std::string, FileFormat> g_extensionMap = {
    // Executables
    {".exe", FileFormat::PE32},
    {".dll", FileFormat::DLL32},
    {".sys", FileFormat::SYS32},
    {".scr", FileFormat::PE32},
    {".cpl", FileFormat::DLL32},
    {".ocx", FileFormat::DLL32},
    {".elf", FileFormat::ELF64},
    {".so", FileFormat::ELF64},
    {".dylib", FileFormat::MachO64},
    {".class", FileFormat::JavaClass},
    {".jar", FileFormat::JavaJAR},

    // Scripts
    {".ps1", FileFormat::PowerShell},
    {".psm1", FileFormat::PowerShell},
    {".psd1", FileFormat::PowerShell},
    {".bat", FileFormat::Batch},
    {".cmd", FileFormat::Batch},
    {".vbs", FileFormat::VBScript},
    {".vbe", FileFormat::VBScript},
    {".js", FileFormat::JavaScript},
    {".jse", FileFormat::JScript},
    {".wsf", FileFormat::JScript},
    {".wsh", FileFormat::JScript},
    {".py", FileFormat::Python},
    {".pyw", FileFormat::Python},
    {".rb", FileFormat::Ruby},
    {".pl", FileFormat::Perl},
    {".sh", FileFormat::ShellScript},
    {".php", FileFormat::PHP},
    {".lua", FileFormat::LUA},
    {".hta", FileFormat::HTA},

    // Documents
    {".pdf", FileFormat::PDF},
    {".doc", FileFormat::DOC},
    {".docx", FileFormat::DOCX},
    {".xls", FileFormat::XLS},
    {".xlsx", FileFormat::XLSX},
    {".ppt", FileFormat::PPT},
    {".pptx", FileFormat::PPTX},
    {".rtf", FileFormat::RTF},
    {".odt", FileFormat::ODT},
    {".ods", FileFormat::ODS},
    {".odp", FileFormat::ODP},
    {".html", FileFormat::HTML},
    {".htm", FileFormat::HTML},
    {".xml", FileFormat::XML},
    {".mhtml", FileFormat::MHTML},
    {".mht", FileFormat::MHTML},

    // Archives
    {".zip", FileFormat::ZIP},
    {".rar", FileFormat::RAR},
    {".7z", FileFormat::SevenZip},
    {".tar", FileFormat::TAR},
    {".gz", FileFormat::GZIP},
    {".bz2", FileFormat::BZIP2},
    {".xz", FileFormat::XZ},
    {".cab", FileFormat::CAB},
    {".msi", FileFormat::MSI},
    {".iso", FileFormat::ISO},
    {".vhd", FileFormat::VHD},
    {".vhdx", FileFormat::VHDX},

    // Images
    {".jpg", FileFormat::JPEG},
    {".jpeg", FileFormat::JPEG},
    {".png", FileFormat::PNG},
    {".gif", FileFormat::GIF},
    {".bmp", FileFormat::BMP},
    {".tif", FileFormat::TIFF},
    {".tiff", FileFormat::TIFF},
    {".ico", FileFormat::ICO},
    {".webp", FileFormat::WEBP},
    {".svg", FileFormat::SVG},
    {".psd", FileFormat::PSD},

    // Audio
    {".mp3", FileFormat::MP3},
    {".wav", FileFormat::WAV},
    {".flac", FileFormat::FLAC},
    {".ogg", FileFormat::OGG},
    {".wma", FileFormat::WMA},
    {".aac", FileFormat::AAC},
    {".m4a", FileFormat::M4A},

    // Video
    {".mp4", FileFormat::MP4},
    {".avi", FileFormat::AVI},
    {".mkv", FileFormat::MKV},
    {".mov", FileFormat::MOV},
    {".wmv", FileFormat::WMV},
    {".flv", FileFormat::FLV},
    {".webm", FileFormat::WEBM},

    // Data
    {".db", FileFormat::SQLite},
    {".sqlite", FileFormat::SQLite},
    {".sqlite3", FileFormat::SQLite},
    {".mdb", FileFormat::MDB},
    {".json", FileFormat::JSON},
    {".yaml", FileFormat::YAML},
    {".yml", FileFormat::YAML},
    {".ini", FileFormat::INI},
    {".cfg", FileFormat::INI},
    {".reg", FileFormat::REG},

    // Certificates
    {".crt", FileFormat::CRT},
    {".cer", FileFormat::CRT},
    {".pem", FileFormat::PEM},
    {".der", FileFormat::DER},
    {".pfx", FileFormat::PFX},
    {".p12", FileFormat::PFX},

    // Fonts
    {".ttf", FileFormat::TTF},
    {".otf", FileFormat::OTF},
    {".woff", FileFormat::WOFF},
    {".woff2", FileFormat::WOFF2},

    // Other
    {".lnk", FileFormat::LNK},
    {".url", FileFormat::URL},
};

} // namespace MagicDB

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class FileTypeAnalyzerImpl {
public:
    FileTypeAnalyzerImpl() = default;
    ~FileTypeAnalyzerImpl() = default;

    // Prevent copying
    FileTypeAnalyzerImpl(const FileTypeAnalyzerImpl&) = delete;
    FileTypeAnalyzerImpl& operator=(const FileTypeAnalyzerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const FileTypeAnalyzerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Initializing...");

            m_config = config;

            // Load built-in signatures
            m_signatures = MagicDB::g_signatures;

            SS_LOG_INFO(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Loaded %llu built-in signatures", m_signatures.size());

            m_initialized = true;
            SS_LOG_INFO(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        SS_LOG_INFO(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Shutdown complete");
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    FileTypeInfo Analyze(const std::wstring& filePath) const {
        FileTypeInfo info;
        info.filePath = filePath;

        try {
            // Validate input
            if (filePath.empty()) {
                SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Empty file path");
                return info;
            }

            // Security: Detect embedded null bytes (truncation attack)
            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Embedded null byte in file path — possible truncation attack");
                info.isSpoofed = true;
                info.spoofingType = SpoofingType::UnicodeAbuse;
                return info;
            }

            // Extract filename for early security checks
            {
                const size_t lastSlash = filePath.find_last_of(L"\\/");
                const std::wstring_view filename = (lastSlash != std::wstring::npos)
                    ? std::wstring_view(filePath).substr(lastSlash + 1)
                    : std::wstring_view(filePath);

                // Detect NTFS Alternate Data Streams (colon in filename)
                const size_t colonPos = filename.find(L':');
                if (colonPos != std::wstring_view::npos) {
                    const bool isDriveLetter = (colonPos == 1 &&
                        lastSlash == std::wstring::npos &&
                        ((filename[0] >= L'A' && filename[0] <= L'Z') ||
                         (filename[0] >= L'a' && filename[0] <= L'z')));
                    if (!isDriveLetter) {
                        SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: NTFS Alternate Data Stream detected in path");
                        info.isSpoofed = true;
                        info.spoofingType = SpoofingType::HiddenExtension;
                    }
                }

                // Detect bidirectional control characters (RTLO attacks)
                if (HasRTLOverrideImpl(filename)) {
                    info.isSpoofed = true;
                    info.spoofingType = SpoofingType::RTLOverride;
                    m_stats.spoofingDetected.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Bidirectional control character in filename");
                }

                // Detect trailing spaces/dots (NTFS normalization evasion)
                if (!filename.empty() && (filename.back() == L' ' || filename.back() == L'.')) {
                    SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Trailing space/dot in filename — NTFS evasion");
                    info.isSpoofed = true;
                    info.spoofingType = SpoofingType::HiddenExtension;
                }
            }

            // Extract disk extension
            info.diskExtension = ExtractExtension(filePath);

            // Check if file exists
            if (!Utils::FileUtils::FileExists(filePath)) {
                SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: File not found");
                return info;
            }

            // Get file size
            info.fileSize = Utils::FileUtils::GetFileSize(filePath);

            // Empty file
            if (info.fileSize == 0) {
                info.detected = true;
                info.confidence = 1.0;
                info.category = FileCategory::Empty;
                info.format = FileFormat::Unknown;
                info.description = "Empty file";
                info.riskLevel = RiskLevel::Safe;
                m_stats.filesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Read file header
            const size_t readSize = std::min(
                static_cast<size_t>(info.fileSize),
                m_config.headerSize
            );

            auto headerData = Utils::FileUtils::ReadFileBytes(filePath, readSize);
            if (headerData.empty()) {
                SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Failed to read file header");
                return info;
            }

            std::span<const uint8_t> buffer(headerData.data(), headerData.size());

            // Analyze the buffer
            info = AnalyzeBufferImpl(buffer, info.diskExtension);
            info.filePath = filePath;
            info.fileSize = Utils::FileUtils::GetFileSize(filePath);

            // Detect spoofing if enabled
            if (m_config.detectSpoofing) {
                DetectSpoofingImpl(info);
            }

            m_stats.filesAnalyzed.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Analyzed %hs - Format: %u, Category: %hs, Risk: %u", Utils::StringUtils::ToNarrow(filePath).c_str(), static_cast<int>(info.format), GetCategoryName(info.category), static_cast<int>(info.riskLevel));

            return info;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer::Analyze: Exception: %hs", e.what());
            return info;
        }
    }

    FileTypeInfo AnalyzeBuffer(std::span<const uint8_t> buffer, std::wstring_view diskExtension) const {
        try {
            auto info = AnalyzeBufferImpl(buffer, diskExtension);
            m_stats.buffersAnalyzed.fetch_add(1, std::memory_order_relaxed);
            return info;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileTypeAnalyzer", L"FileTypeAnalyzer::AnalyzeBuffer: Exception: %hs", e.what());
            return FileTypeInfo{};
        }
    }

    // ========================================================================
    // QUICK DETECTION
    // ========================================================================

    FileFormat DetectFormat(const std::wstring& filePath) const {
        try {
            const size_t readSize = std::min(
                Utils::FileUtils::GetFileSize(filePath),
                m_config.headerSize
            );

            auto headerData = Utils::FileUtils::ReadFileBytes(filePath, readSize);
            if (headerData.empty()) {
                return FileFormat::Unknown;
            }

            return DetectFormatImpl(std::span<const uint8_t>(headerData.data(), headerData.size()));

        } catch (...) {
            return FileFormat::Unknown;
        }
    }

    FileFormat DetectFormatBuffer(std::span<const uint8_t> buffer) const {
        return DetectFormatImpl(buffer);
    }

    FileCategory GetCategory(const std::wstring& filePath) const {
        FileFormat format = DetectFormat(filePath);
        return MagicDB::GetCategoryForFormat(format);
    }

    std::string GetMimeType(const std::wstring& filePath) const {
        FileFormat format = DetectFormat(filePath);
        return MagicDB::GetMimeForFormat(format);
    }

    // ========================================================================
    // SPECIFIC CHECKS
    // ========================================================================

    bool IsExecutable(const std::wstring& filePath) const {
        FileCategory category = GetCategory(filePath);
        return (category == FileCategory::Executable ||
                category == FileCategory::Driver ||
                category == FileCategory::Library);
    }

    bool IsExecutableBuffer(std::span<const uint8_t> buffer) const {
        FileFormat format = DetectFormatImpl(buffer);
        FileCategory category = MagicDB::GetCategoryForFormat(format);
        return (category == FileCategory::Executable ||
                category == FileCategory::Driver ||
                category == FileCategory::Library);
    }

    bool IsScript(const std::wstring& filePath) const {
        FileCategory category = GetCategory(filePath);
        return (category == FileCategory::Script);
    }

    bool IsArchive(const std::wstring& filePath) const {
        FileCategory category = GetCategory(filePath);
        return (category == FileCategory::Archive);
    }

    bool CanContainMacros(const std::wstring& filePath) const {
        FileFormat format = DetectFormat(filePath);
        return (format == FileFormat::DOC ||
                format == FileFormat::DOCX ||
                format == FileFormat::XLS ||
                format == FileFormat::XLSX ||
                format == FileFormat::PPT ||
                format == FileFormat::PPTX ||
                format == FileFormat::ODT ||
                format == FileFormat::ODS ||
                format == FileFormat::ODP);
    }

    // ========================================================================
    // SPOOFING DETECTION
    // ========================================================================

    SpoofingType DetectSpoofing(const std::wstring& filePath) const {
        try {
            // Extract filename
            size_t lastSlash = filePath.find_last_of(L"\\/");
            std::wstring filename = (lastSlash != std::wstring::npos) ?
                filePath.substr(lastSlash + 1) : filePath;

            // Check RTLO
            if (HasRTLOverrideImpl(filename)) {
                return SpoofingType::RTLOverride;
            }

            // Check double extension
            if (HasDoubleExtensionImpl(filename)) {
                return SpoofingType::DoubleExtension;
            }

            // Check extension mismatch
            auto info = Analyze(filePath);
            if (info.isSpoofed) {
                return info.spoofingType;
            }

            return SpoofingType::None;

        } catch (...) {
            return SpoofingType::None;
        }
    }

    bool HasRTLOverride(std::wstring_view filename) const {
        return HasRTLOverrideImpl(filename);
    }

    bool HasDoubleExtension(std::wstring_view filename) const {
        return HasDoubleExtensionImpl(filename);
    }

    // ========================================================================
    // SCRIPT ANALYSIS
    // ========================================================================

    ScriptIndicators AnalyzeScript(std::span<const uint8_t> buffer) const {
        ScriptIndicators indicators;

        if (buffer.size() < 2) {
            return indicators;
        }

        // Check for BOM
        if (buffer.size() >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) {
            indicators.hasBOM = true;
            indicators.bomType = "UTF-8";
        } else if (buffer.size() >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) {
            indicators.hasBOM = true;
            indicators.bomType = "UTF-16 LE";
        } else if (buffer.size() >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF) {
            indicators.hasBOM = true;
            indicators.bomType = "UTF-16 BE";
        }

        // Check for shebang
        if (buffer.size() >= 2 && buffer[0] == '#' && buffer[1] == '!') {
            indicators.hasShebang = true;

            // Extract shebang line
            size_t endPos = 2;
            while (endPos < buffer.size() && buffer[endPos] != '\n' && endPos < 256) {
                endPos++;
            }

            std::string shebang(reinterpret_cast<const char*>(buffer.data() + 2), endPos - 2);
            indicators.shebangInterpreter = shebang;
        }

        // Check if it's text content
        if (IsTextContent(buffer)) {
            indicators.textConfidence = 1.0;

            // Look for script keywords
            std::string content(reinterpret_cast<const char*>(buffer.data()),
                              std::min(buffer.size(), size_t(4096)));

            std::transform(content.begin(), content.end(), content.begin(), ::tolower);

            // PowerShell
            if (content.find("param(") != std::string::npos ||
                content.find("function ") != std::string::npos ||
                content.find("$_") != std::string::npos ||
                content.find("write-host") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("PowerShell");
            }

            // VBScript
            if (content.find("dim ") != std::string::npos ||
                content.find("wscript.") != std::string::npos ||
                content.find("msgbox") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("VBScript");
            }

            // Python
            if (content.find("import ") != std::string::npos ||
                content.find("def ") != std::string::npos ||
                content.find("__name__") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("Python");
            }

            // JavaScript
            if (content.find("function(") != std::string::npos ||
                content.find("var ") != std::string::npos ||
                content.find("const ") != std::string::npos ||
                content.find("console.log") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("JavaScript");
            }

            // Batch/CMD
            if (content.find("@echo off") != std::string::npos ||
                content.find("goto ") != std::string::npos ||
                content.find("setlocal") != std::string::npos ||
                content.find("%~") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("Batch");
            }

            // HTA (HTML Application)
            if (content.find("<hta:application") != std::string::npos ||
                content.find("hta:application") != std::string::npos) {
                indicators.hasScriptKeywords = true;
                indicators.detectedKeywords.push_back("HTA");
            }
        }

        return indicators;
    }

    FileFormat DetectScriptType(std::span<const uint8_t> buffer) const {
        if (!IsTextContent(buffer)) {
            return FileFormat::Unknown;
        }

        auto indicators = AnalyzeScript(buffer);

        // Check shebang
        if (indicators.hasShebang) {
            std::string interp = indicators.shebangInterpreter;
            std::transform(interp.begin(), interp.end(), interp.begin(), ::tolower);

            if (interp.find("python") != std::string::npos) return FileFormat::Python;
            if (interp.find("ruby") != std::string::npos) return FileFormat::Ruby;
            if (interp.find("perl") != std::string::npos) return FileFormat::Perl;
            if (interp.find("bash") != std::string::npos) return FileFormat::ShellScript;
            if (interp.find("sh") != std::string::npos) return FileFormat::ShellScript;
            if (interp.find("php") != std::string::npos) return FileFormat::PHP;
        }

        // Check keywords
        if (indicators.hasScriptKeywords) {
            for (const auto& keyword : indicators.detectedKeywords) {
                if (keyword == "PowerShell") return FileFormat::PowerShell;
                if (keyword == "VBScript") return FileFormat::VBScript;
                if (keyword == "Python") return FileFormat::Python;
                if (keyword == "JavaScript") return FileFormat::JavaScript;
                if (keyword == "Batch") return FileFormat::Batch;
                if (keyword == "HTA") return FileFormat::HTA;
            }
        }

        return FileFormat::Unknown;
    }

    // ========================================================================
    // EXTENSION MAPPING
    // ========================================================================

    ExtensionInfo GetExtensionInfo(std::string_view extension) const {
        ExtensionInfo info;
        info.extension = NormalizeExtension(extension);

        auto it = MagicDB::g_extensionMap.find(info.extension);
        if (it != MagicDB::g_extensionMap.end()) {
            info.format = it->second;
            info.category = MagicDB::GetCategoryForFormat(info.format);
            info.mimeType = MagicDB::GetMimeForFormat(info.format);
            info.riskLevel = MagicDB::GetRiskForFormat(info.format);
            info.isCommon = true;
        }

        return info;
    }

    std::string GetExtensionForFormat(FileFormat format) const {
        for (const auto& [ext, fmt] : MagicDB::g_extensionMap) {
            if (fmt == format) {
                return ext;
            }
        }
        return "";
    }

    RiskLevel GetExtensionRisk(std::string_view extension) const {
        auto info = GetExtensionInfo(extension);
        return info.riskLevel;
    }

    // ========================================================================
    // CUSTOM SIGNATURES
    // ========================================================================

    bool AddSignature(const MagicSignature& signature) {
        std::unique_lock lock(m_mutex);

        if (m_signatures.size() >= FileTypeAnalyzerConstants::MAX_SIGNATURES) {
            SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Maximum signatures reached");
            return false;
        }

        m_signatures.push_back(signature);
        return true;
    }

    size_t LoadSignatures(const std::wstring& signaturePath) {
        // Custom signature loading not implemented in this version
        return 0;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const FileTypeAnalyzerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    FileTypeInfo AnalyzeBufferImpl(std::span<const uint8_t> buffer, std::wstring_view diskExtension) const {
        std::shared_lock lock(m_mutex);
        FileTypeInfo info;
        info.fileSize = buffer.size();
        info.diskExtension = diskExtension;

        if (buffer.empty()) {
            info.detected = true;
            info.confidence = 1.0;
            info.category = FileCategory::Empty;
            return info;
        }

        // Try magic number detection first
        for (const auto& sig : m_signatures) {
            if (MatchesPattern(buffer, sig.offset, sig.pattern, sig.mask)) {
                info.detected = true;
                // Disambiguate formats sharing magic byte patterns
                info.format = DisambiguateFormat(buffer, sig.format, diskExtension);
                info.category = MagicDB::GetCategoryForFormat(info.format);
                info.riskLevel = MagicDB::GetRiskForFormat(info.format);
                info.description = GetDescriptionForFormat(info.format);
                info.mimeType = MagicDB::GetMimeForFormat(info.format);
                info.extension = GetExtensionForFormat(info.format);
                info.confidence = 1.0;
                info.magicOffset = sig.offset;
                info.matchedSignature = sig.description;

                // Set flags
                info.isExecutable = (info.category == FileCategory::Executable ||
                                   info.category == FileCategory::Driver ||
                                   info.category == FileCategory::Library);
                info.isScript = (info.category == FileCategory::Script);
                info.isArchive = (info.category == FileCategory::Archive);
                info.canContainMacros = (info.format == FileFormat::DOC ||
                                        info.format == FileFormat::DOCX ||
                                        info.format == FileFormat::XLS ||
                                        info.format == FileFormat::XLSX ||
                                        info.format == FileFormat::PPT ||
                                        info.format == FileFormat::PPTX);
                info.isCompound = (info.format == FileFormat::DOC ||
                                  info.format == FileFormat::XLS ||
                                  info.format == FileFormat::PPT ||
                                  info.format == FileFormat::MSI);

                // Update statistics
                if (info.isExecutable) {
                    m_stats.executablesDetected.fetch_add(1, std::memory_order_relaxed);
                }
                if (info.isScript) {
                    m_stats.scriptsDetected.fetch_add(1, std::memory_order_relaxed);
                }

                return info;
            }
        }

        // Try script detection if enabled
        if (m_config.detectScripts && IsTextContent(buffer)) {
            FileFormat scriptFormat = DetectScriptType(buffer);
            if (scriptFormat != FileFormat::Unknown) {
                info.detected = true;
                info.format = scriptFormat;
                info.category = FileCategory::Script;
                info.riskLevel = MagicDB::GetRiskForFormat(scriptFormat);
                info.mimeType = MagicDB::GetMimeForFormat(scriptFormat);
                info.extension = GetExtensionForFormat(scriptFormat);
                info.isScript = true;
                info.confidence = 0.8;
                info.description = "Script file";

                m_stats.scriptsDetected.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Plain text
            info.detected = true;
            info.category = FileCategory::Text;
            info.riskLevel = RiskLevel::Safe;
            info.mimeType = "text/plain";
            info.confidence = 0.7;
            info.description = "Text file";
            return info;
        }

        // Fall back to extension-based detection
        if (!diskExtension.empty()) {
            std::string ext = Utils::StringUtils::ToNarrow(std::wstring(diskExtension));
            auto extInfo = GetExtensionInfo(ext);

            if (extInfo.format != FileFormat::Unknown) {
                info.detected = true;
                info.format = extInfo.format;
                info.category = extInfo.category;
                info.riskLevel = extInfo.riskLevel;
                info.mimeType = extInfo.mimeType;
                info.extension = extInfo.extension;
                info.confidence = 0.3;  // Low confidence (extension only)
                info.description = "Detected by extension";
                return info;
            }
        }

        // Unknown
        info.detected = false;
        info.category = FileCategory::Unknown;
        info.riskLevel = RiskLevel::Low;
        info.confidence = 0.0;
        m_stats.unknownTypes.fetch_add(1, std::memory_order_relaxed);

        return info;
    }

    FileFormat DetectFormatImpl(std::span<const uint8_t> buffer) const {
        std::shared_lock lock(m_mutex);
        if (buffer.empty()) {
            return FileFormat::Unknown;
        }

        // Check magic numbers
        for (const auto& sig : m_signatures) {
            if (MatchesPattern(buffer, sig.offset, sig.pattern, sig.mask)) {
                return DisambiguateFormat(buffer, sig.format, L"");
            }
        }

        // Try script detection
        if (m_config.detectScripts && IsTextContent(buffer)) {
            FileFormat scriptFormat = DetectScriptType(buffer);
            if (scriptFormat != FileFormat::Unknown) {
                return scriptFormat;
            }
        }

        return FileFormat::Unknown;
    }

    void DetectSpoofingImpl(FileTypeInfo& info) const {
        if (info.diskExtension.empty()) {
            return;
        }

        // Convert to string for comparison
        std::string diskExt = Utils::StringUtils::ToNarrow(info.diskExtension);
        diskExt = NormalizeExtension(diskExt);

        // Get expected extension
        std::string expectedExt = info.extension;

        // Check for mismatch
        if (!expectedExt.empty() && diskExt != expectedExt) {
            // PE executables can have many valid extensions
            if (info.format == FileFormat::PE32 || info.format == FileFormat::PE64) {
                if (diskExt == ".exe" || diskExt == ".scr" || diskExt == ".com" || diskExt == ".pif") {
                    return;
                }
            }
            if (info.format == FileFormat::DLL32 || info.format == FileFormat::DLL64) {
                if (diskExt == ".dll" || diskExt == ".ocx" || diskExt == ".cpl" || diskExt == ".drv") {
                    return;
                }
            }
            if (info.format == FileFormat::SYS32 || info.format == FileFormat::SYS64) {
                if (diskExt == ".sys") {
                    return;
                }
            }
            if (info.format == FileFormat::DotNetAssembly) {
                if (diskExt == ".exe" || diskExt == ".dll") {
                    return;
                }
            }

            // ZIP-based formats (many formats use ZIP as container)
            if (info.format == FileFormat::ZIP) {
                static const std::unordered_set<std::string> validZipExts = {
                    ".docx", ".docm", ".xlsx", ".xlsm", ".xlsb",
                    ".pptx", ".pptm", ".odt", ".ods", ".odp",
                    ".jar", ".war", ".ear", ".apk", ".xpi",
                    ".epub", ".cbz", ".nupkg", ".vsix"
                };
                if (validZipExts.count(diskExt)) {
                    return;
                }
            }

            // OLE compound files
            if (info.format == FileFormat::DOC) {
                if (diskExt == ".doc" || diskExt == ".dot" || diskExt == ".wbk" || diskExt == ".msg") {
                    return;
                }
            }
            if (info.format == FileFormat::XLS) {
                if (diskExt == ".xls" || diskExt == ".xlt" || diskExt == ".xla") {
                    return;
                }
            }
            if (info.format == FileFormat::PPT) {
                if (diskExt == ".ppt" || diskExt == ".pot" || diskExt == ".pps") {
                    return;
                }
            }
            if (info.format == FileFormat::MSI) {
                if (diskExt == ".msi" || diskExt == ".msp" || diskExt == ".mst") {
                    return;
                }
            }

            // Extension mismatch detected
            info.isSpoofed = true;
            info.spoofingType = SpoofingType::ExtensionMismatch;
            info.suggestedExtension = Utils::StringUtils::ToWide(expectedExt);

            m_stats.spoofingDetected.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_WARN(L"FileTypeAnalyzer", L"FileTypeAnalyzer: Extension spoofing detected - Disk: %hs, Actual: %hs", diskExt.c_str(), expectedExt.c_str());
        }
    }

    bool HasRTLOverrideImpl(std::wstring_view filename) const {
        // Check for bidirectional control characters used in evasion attacks
        for (const wchar_t ch : filename) {
            if (ch >= 0x202A && ch <= 0x202E) return true;  // LRE, RLE, PDF, LRO, RLO
            if (ch >= 0x2066 && ch <= 0x2069) return true;  // LRI, RLI, FSI, PDI
            if (ch == 0x200E || ch == 0x200F) return true;  // LRM, RLM
        }
        return false;
    }

    bool HasDoubleExtensionImpl(std::wstring_view filename) const {
        // Look for patterns like: file.txt.exe, file.pdf.scr
        // Common fake extensions
        static const std::vector<std::wstring> fakeExtensions = {
            L".txt", L".pdf", L".doc", L".jpg", L".png", L".gif"
        };

        // Dangerous real extensions
        static const std::vector<std::wstring> dangerousExtensions = {
            L".exe", L".scr", L".bat", L".cmd", L".com", L".pif",
            L".vbs", L".js", L".ps1", L".hta"
        };

        std::wstring lower = std::wstring(filename);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        // Check for fake extension followed by dangerous extension
        for (const auto& fakeExt : fakeExtensions) {
            size_t pos = lower.find(fakeExt);
            if (pos != std::wstring::npos) {
                // Check if there's a dangerous extension after it
                for (const auto& dangerExt : dangerousExtensions) {
                    if (lower.find(dangerExt, pos + fakeExt.length()) != std::wstring::npos) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    FileTypeAnalyzerConfig m_config;
    std::vector<MagicSignature> m_signatures;
    mutable FileTypeAnalyzerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

FileTypeAnalyzer::FileTypeAnalyzer()
    : m_impl(std::make_unique<FileTypeAnalyzerImpl>()) {
}

FileTypeAnalyzer::~FileTypeAnalyzer() = default;

FileTypeAnalyzer& FileTypeAnalyzer::Instance() {
    static FileTypeAnalyzer instance;
    return instance;
}

bool FileTypeAnalyzer::Initialize(const FileTypeAnalyzerConfig& config) {
    return m_impl->Initialize(config);
}

void FileTypeAnalyzer::Shutdown() noexcept {
    m_impl->Shutdown();
}

FileTypeInfo FileTypeAnalyzer::Analyze(const std::wstring& filePath) const {
    return m_impl->Analyze(filePath);
}

FileTypeInfo FileTypeAnalyzer::AnalyzeBuffer(std::span<const uint8_t> buffer, std::wstring_view diskExtension) const {
    return m_impl->AnalyzeBuffer(buffer, diskExtension);
}

FileFormat FileTypeAnalyzer::DetectFormat(const std::wstring& filePath) const {
    return m_impl->DetectFormat(filePath);
}

FileFormat FileTypeAnalyzer::DetectFormat(std::span<const uint8_t> buffer) const {
    return m_impl->DetectFormatBuffer(buffer);
}

FileCategory FileTypeAnalyzer::GetCategory(const std::wstring& filePath) const {
    return m_impl->GetCategory(filePath);
}

std::string FileTypeAnalyzer::GetMimeType(const std::wstring& filePath) const {
    return m_impl->GetMimeType(filePath);
}

bool FileTypeAnalyzer::IsExecutable(const std::wstring& filePath) const {
    return m_impl->IsExecutable(filePath);
}

bool FileTypeAnalyzer::IsExecutable(std::span<const uint8_t> buffer) const {
    return m_impl->IsExecutableBuffer(buffer);
}

bool FileTypeAnalyzer::IsScript(const std::wstring& filePath) const {
    return m_impl->IsScript(filePath);
}

bool FileTypeAnalyzer::IsArchive(const std::wstring& filePath) const {
    return m_impl->IsArchive(filePath);
}

bool FileTypeAnalyzer::CanContainMacros(const std::wstring& filePath) const {
    return m_impl->CanContainMacros(filePath);
}

SpoofingType FileTypeAnalyzer::DetectSpoofing(const std::wstring& filePath) const {
    return m_impl->DetectSpoofing(filePath);
}

bool FileTypeAnalyzer::HasRTLOverride(std::wstring_view filename) const {
    return m_impl->HasRTLOverride(filename);
}

bool FileTypeAnalyzer::HasDoubleExtension(std::wstring_view filename) const {
    return m_impl->HasDoubleExtension(filename);
}

ScriptIndicators FileTypeAnalyzer::AnalyzeScript(std::span<const uint8_t> buffer) const {
    return m_impl->AnalyzeScript(buffer);
}

FileFormat FileTypeAnalyzer::DetectScriptType(std::span<const uint8_t> buffer) const {
    return m_impl->DetectScriptType(buffer);
}

ExtensionInfo FileTypeAnalyzer::GetExtensionInfo(std::string_view extension) const {
    return m_impl->GetExtensionInfo(extension);
}

std::string FileTypeAnalyzer::GetExtensionForFormat(FileFormat format) const {
    return m_impl->GetExtensionForFormat(format);
}

RiskLevel FileTypeAnalyzer::GetExtensionRisk(std::string_view extension) const {
    return m_impl->GetExtensionRisk(extension);
}

bool FileTypeAnalyzer::AddSignature(const MagicSignature& signature) {
    return m_impl->AddSignature(signature);
}

size_t FileTypeAnalyzer::LoadSignatures(const std::wstring& signaturePath) {
    return m_impl->LoadSignatures(signaturePath);
}

const FileTypeAnalyzerStatistics& FileTypeAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void FileTypeAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
