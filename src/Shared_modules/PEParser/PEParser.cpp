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
 * @file PEParser.cpp
 * @brief Enterprise-grade PE parser implementation.
 *
 * This implementation provides:
 * - Complete bounds checking on all reads
 * - Integer overflow protection
 * - Anti-loop protection for malicious structures
 * - Comprehensive anomaly detection
 * - Memory-mapped I/O for performance
 *
 * @copyright ShadowStrike Security Suite
 */

#include "PEParser.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/StringUtils.hpp"

#include <chrono>
#include <unordered_set>
#include <algorithm>
#include <cmath>

namespace ShadowStrike {
namespace PEParser {

// ============================================================================
// Implementation Class (PIMPL)
// ============================================================================

class PEParserImpl {
public:
    PEParserImpl() = default;
    ~PEParserImpl() { Reset(); }

    // Non-copyable
    PEParserImpl(const PEParserImpl&) = delete;
    PEParserImpl& operator=(const PEParserImpl&) = delete;

    // ========================================================================
    // State
    // ========================================================================

    bool m_parsed = false;
    PEInfo m_info;
    SafeReader m_reader;

    // Memory-mapped file (if parsing from file)
    Utils::MemoryUtils::MappedView m_mappedFile;

    // Raw headers for address translation
    std::vector<SectionHeader> m_rawSections;
    size_t m_ntHeaderOffset = 0;
    size_t m_optionalHeaderOffset = 0;
    size_t m_sectionTableOffset = 0;

    // ========================================================================
    // Core Parsing
    // ========================================================================

    [[nodiscard]] bool ParseInternal(PEError* err) noexcept {
        auto startTime = std::chrono::high_resolution_clock::now();

        m_info = PEInfo();
        m_info.fileSize = m_reader.Size();

        // Step 1: Validate and parse DOS header
        int32_t lfanew;
        auto dosResult = ValidateDosHeader(m_reader, lfanew, err);
        if (dosResult != ValidationResult::Valid) {
            return false;
        }

        m_ntHeaderOffset = static_cast<size_t>(lfanew);

        // Step 2: Validate and parse NT headers
        FileHeader fileHeader;
        auto ntResult = ValidateNtHeaders(m_reader, m_ntHeaderOffset,
                                           m_info.is64Bit, fileHeader, err);
        if (ntResult != ValidationResult::Valid) {
            return false;
        }

        m_info.machine = fileHeader.Machine;
        m_info.machineString = PEParser::MachineToString(fileHeader.Machine);
        m_info.timeDateStamp = fileHeader.TimeDateStamp;

        // Check file characteristics
        m_info.isDLL = (fileHeader.Characteristics & FileCharacteristics::DLL) != 0;

        // Step 3: Parse optional header
        m_optionalHeaderOffset = m_ntHeaderOffset + sizeof(uint32_t) + sizeof(FileHeader);

        if (m_info.is64Bit) {
            OptionalHeader64 opt64;
            auto optResult = ValidateOptionalHeader64(m_reader, m_optionalHeaderOffset,
                                                       fileHeader.SizeOfOptionalHeader,
                                                       opt64, err);
            if (optResult != ValidationResult::Valid) {
                return false;
            }

            m_info.imageBase = opt64.ImageBase;
            m_info.entryPointRva = opt64.AddressOfEntryPoint;
            m_info.sizeOfImage = opt64.SizeOfImage;
            m_info.sizeOfHeaders = opt64.SizeOfHeaders;
            m_info.checksum = opt64.CheckSum;
            m_info.subsystem = opt64.Subsystem;
            m_info.dllCharacteristics = opt64.DllCharacteristics;
            m_info.fileAlignment = opt64.FileAlignment;
            m_info.sectionAlignment = opt64.SectionAlignment;
            m_info.majorLinkerVersion = opt64.MajorLinkerVersion;
            m_info.minorLinkerVersion = opt64.MinorLinkerVersion;
            m_info.majorOsVersion = opt64.MajorOperatingSystemVersion;
            m_info.minorOsVersion = opt64.MinorOperatingSystemVersion;

            // Parse data directories
            ParseDataDirectories64(opt64, fileHeader.SizeOfOptionalHeader);
        } else {
            OptionalHeader32 opt32;
            auto optResult = ValidateOptionalHeader32(m_reader, m_optionalHeaderOffset,
                                                       fileHeader.SizeOfOptionalHeader,
                                                       opt32, err);
            if (optResult != ValidationResult::Valid) {
                return false;
            }

            m_info.imageBase = opt32.ImageBase;
            m_info.entryPointRva = opt32.AddressOfEntryPoint;
            m_info.sizeOfImage = opt32.SizeOfImage;
            m_info.sizeOfHeaders = opt32.SizeOfHeaders;
            m_info.checksum = opt32.CheckSum;
            m_info.subsystem = opt32.Subsystem;
            m_info.dllCharacteristics = opt32.DllCharacteristics;
            m_info.fileAlignment = opt32.FileAlignment;
            m_info.sectionAlignment = opt32.SectionAlignment;
            m_info.majorLinkerVersion = opt32.MajorLinkerVersion;
            m_info.minorLinkerVersion = opt32.MinorLinkerVersion;
            m_info.majorOsVersion = opt32.MajorOperatingSystemVersion;
            m_info.minorOsVersion = opt32.MinorOperatingSystemVersion;

            // Parse data directories
            ParseDataDirectories32(opt32, fileHeader.SizeOfOptionalHeader);
        }

        // Check for driver
        m_info.isDriver = (m_info.subsystem == Subsystem::NATIVE);

        // Step 4: Parse section table
        m_sectionTableOffset = m_optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;

        if (!ParseSections(fileHeader.NumberOfSections, err)) {
            return false;
        }

        // Step 5: Analyze entry point
        AnalyzeEntryPoint();

        // Step 6: Check for .NET
        if (m_info.dataDirectories[DataDirectory::COM_DESCRIPTOR].present) {
            m_info.isDotNet = true;
        }

        // Step 7: Check for Authenticode signature (validate WIN_CERTIFICATE, not just presence)
        if (m_info.dataDirectories[DataDirectory::SECURITY].present) {
            const auto& secDir = m_info.dataDirectories[DataDirectory::SECURITY];
            // SECURITY directory uses a file offset (not an RVA) — PE spec exception
            const uint32_t certFileOffset = secDir.rva;
            if (certFileOffset != 0 && secDir.size >= 8u &&
                m_reader.ValidateRange(certFileOffset, secDir.size)) {
                // WIN_CERTIFICATE: dwLength(4), wRevision(2), wCertificateType(2)
                uint32_t dwLength   = 0;
                uint16_t wRevision  = 0;
                uint16_t wCertType  = 0;
                if (m_reader.Read(certFileOffset,     dwLength) &&
                    m_reader.Read(certFileOffset + 4, wRevision) &&
                    m_reader.Read(certFileOffset + 6, wCertType) &&
                    wRevision  == 0x0200u &&   // WIN_CERT_REVISION_2_0
                    wCertType  == 0x0002u &&   // WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    dwLength   >= 8u &&
                    dwLength   <= secDir.size) {
                    m_info.isSigned = true;
                }
            }
        }

        // Step 8: Detect overlay
        DetectOverlay();

        // Step 9: Detect anomalies
        DetectAnomalies();

        // Calculate parsing time
        auto endTime = std::chrono::high_resolution_clock::now();
        m_info.parseTimeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - startTime).count();

        m_info.valid = true;
        m_parsed = true;
        return true;
    }

    // ========================================================================
    // Data Directory Parsing
    // ========================================================================

    void ParseDataDirectories32(const OptionalHeader32& opt, uint16_t headerSize) noexcept {
        size_t ddOffset = m_optionalHeaderOffset + sizeof(OptionalHeader32);
        size_t ddCount = opt.NumberOfRvaAndSizes;
        if (ddCount > DataDirectory::MAX_ENTRIES) {
            ddCount = DataDirectory::MAX_ENTRIES;
        }

        // Check if header has space for data directories
        size_t ddEnd;
        if (!SafeMath::SafeAdd(sizeof(OptionalHeader32),
                               ddCount * sizeof(DataDirectoryEntry), ddEnd)) {
            return;
        }
        if (ddEnd > headerSize) {
            ddCount = (headerSize - sizeof(OptionalHeader32)) / sizeof(DataDirectoryEntry);
        }

        for (size_t i = 0; i < ddCount && i < DataDirectory::MAX_ENTRIES; ++i) {
            DataDirectoryEntry entry;
            if (m_reader.Read(ddOffset + i * sizeof(DataDirectoryEntry), entry)) {
                m_info.dataDirectories[i].rva = entry.VirtualAddress;
                m_info.dataDirectories[i].size = entry.Size;
                m_info.dataDirectories[i].present = (entry.VirtualAddress != 0 || entry.Size != 0);
            }
        }

        // Compute file offsets for present directories
        for (size_t i = 0; i < DataDirectory::MAX_ENTRIES; ++i) {
            if (m_info.dataDirectories[i].present && m_info.dataDirectories[i].rva != 0) {
                m_info.dataDirectories[i].fileOffset = RvaToOffsetInternal(
                    m_info.dataDirectories[i].rva);
            }
        }
    }

    void ParseDataDirectories64(const OptionalHeader64& opt, uint16_t headerSize) noexcept {
        size_t ddOffset = m_optionalHeaderOffset + sizeof(OptionalHeader64);
        size_t ddCount = opt.NumberOfRvaAndSizes;
        if (ddCount > DataDirectory::MAX_ENTRIES) {
            ddCount = DataDirectory::MAX_ENTRIES;
        }

        size_t ddEnd;
        if (!SafeMath::SafeAdd(sizeof(OptionalHeader64),
                               ddCount * sizeof(DataDirectoryEntry), ddEnd)) {
            return;
        }
        if (ddEnd > headerSize) {
            ddCount = (headerSize - sizeof(OptionalHeader64)) / sizeof(DataDirectoryEntry);
        }

        for (size_t i = 0; i < ddCount && i < DataDirectory::MAX_ENTRIES; ++i) {
            DataDirectoryEntry entry;
            if (m_reader.Read(ddOffset + i * sizeof(DataDirectoryEntry), entry)) {
                m_info.dataDirectories[i].rva = entry.VirtualAddress;
                m_info.dataDirectories[i].size = entry.Size;
                m_info.dataDirectories[i].present = (entry.VirtualAddress != 0 || entry.Size != 0);
            }
        }

        for (size_t i = 0; i < DataDirectory::MAX_ENTRIES; ++i) {
            if (m_info.dataDirectories[i].present && m_info.dataDirectories[i].rva != 0) {
                m_info.dataDirectories[i].fileOffset = RvaToOffsetInternal(
                    m_info.dataDirectories[i].rva);
            }
        }
    }

    // ========================================================================
    // Section Parsing
    // ========================================================================

    [[nodiscard]] bool ParseSections(uint16_t numberOfSections, PEError* err) noexcept {
        if (numberOfSections == 0) {
            return true;  // Valid but unusual
        }

        // Validate section table doesn't overflow
        size_t tableSize;
        if (!SafeMath::SafeMul(static_cast<size_t>(numberOfSections),
                               sizeof(SectionHeader), tableSize)) {
            if (err) {
                err->Set(ValidationResult::SectionTableOverflow,
                         L"Section table size overflow",
                         m_sectionTableOffset);
            }
            return false;
        }

        if (!m_reader.ValidateRange(m_sectionTableOffset, tableSize)) {
            if (err) {
                err->Set(ValidationResult::SectionTableOutOfBounds,
                         L"Section table extends beyond file",
                         m_sectionTableOffset);
            }
            return false;
        }

        m_rawSections.reserve(numberOfSections);
        m_info.sections.reserve(numberOfSections);

        for (uint16_t i = 0; i < numberOfSections; ++i) {
            size_t offset = m_sectionTableOffset + i * sizeof(SectionHeader);

            SectionHeader header;
            if (!m_reader.Read(offset, header)) {
                if (err) {
                    err->Set(ValidationResult::SectionTableOutOfBounds,
                             L"Cannot read section header",
                             offset);
                }
                return false;
            }

            m_rawSections.push_back(header);

            SectionInfo info;

            // Validate section (alignment anomalies are collected into info.anomalies)
            auto valResult = ValidateSectionHeader(header, m_reader.Size(),
                                                    m_info.sizeOfImage,
                                                    m_info.fileAlignment, i, err,
                                                    &info.anomalies);
            // Don't fail on section validation errors; anomalies are recorded above

            // Extract name (handle non-null-terminated 8-char names)
            std::string name;
            if (m_reader.ReadFixedString(offset, 8, name)) {
                info.name = name;
            }

            info.virtualAddress = header.VirtualAddress;
            info.virtualSize = header.VirtualSize;
            info.rawAddress = header.PointerToRawData;
            info.rawSize = header.SizeOfRawData;
            info.characteristics = header.Characteristics;

            // Compute flags
            info.isExecutable = (header.Characteristics & SectionCharacteristics::MEM_EXECUTE) != 0;
            info.isWritable = (header.Characteristics & SectionCharacteristics::MEM_WRITE) != 0;
            info.isReadable = (header.Characteristics & SectionCharacteristics::MEM_READ) != 0;
            info.hasCode = (header.Characteristics & SectionCharacteristics::CNT_CODE) != 0;
            info.hasInitializedData = (header.Characteristics & SectionCharacteristics::CNT_INITIALIZED_DATA) != 0;
            info.hasUninitializedData = (header.Characteristics & SectionCharacteristics::CNT_UNINITIALIZED_DATA) != 0;

            // Check for W+X
            if (info.isExecutable && info.isWritable) {
                info.anomalies.emplace_back(AnomalyType::SectionWritableExecutable,
                                            L"Section is both writable and executable");
            }

            m_info.sections.push_back(std::move(info));
        }

        // Check for overlapping sections
        std::vector<std::pair<size_t, size_t>> overlaps;
        if (CheckSectionOverlaps(m_rawSections, overlaps)) {
            for (const auto& [i, j] : overlaps) {
                m_info.anomalies.emplace_back(AnomalyType::UnusualSectionOrder,
                                              L"Sections overlap in file");
            }
        }

        return true;
    }

    // ========================================================================
    // Entry Point Analysis
    // ========================================================================

    void AnalyzeEntryPoint() noexcept {
        if (m_info.entryPointRva == 0) {
            // Zero entry point can be valid for DLLs
            if (!m_info.isDLL) {
                m_info.anomalies.emplace_back(AnomalyType::EntryPointZero,
                                              L"Entry point is zero");
            }
            return;
        }

        // Find section containing entry point
        for (size_t i = 0; i < m_info.sections.size(); ++i) {
            const auto& sec = m_info.sections[i];
            uint32_t secStart = sec.virtualAddress;
            uint32_t secSize = sec.virtualSize;
            if (secSize == 0) {
                secSize = sec.rawSize;
            }

            if (m_info.entryPointRva >= secStart &&
                m_info.entryPointRva < secStart + secSize) {
                m_info.entryPointSectionIndex = i;
                m_info.entryPointInExecutableSection = sec.isExecutable;

                // Check for suspicious entry point location
                if (i == m_info.sections.size() - 1) {
                    m_info.anomalies.emplace_back(AnomalyType::EntryPointInLastSection,
                                                  L"Entry point in last section (packer indicator)");
                }

                if (sec.isWritable) {
                    m_info.anomalies.emplace_back(AnomalyType::EntryPointInWritableSection,
                                                  L"Entry point in writable section");
                }

                if (!sec.isExecutable) {
                    m_info.anomalies.emplace_back(AnomalyType::EntryPointInNonExecutable,
                                                  L"Entry point in non-executable section");
                }

                return;
            }
        }

        // Entry point not in any section
        if (m_info.entryPointRva < m_info.sizeOfHeaders) {
            m_info.anomalies.emplace_back(AnomalyType::EntryPointInHeader,
                                          L"Entry point in PE header");
        } else {
            m_info.anomalies.emplace_back(AnomalyType::EntryPointOutsideFile,
                                          L"Entry point outside all sections");
        }
    }

    // ========================================================================
    // Overlay Detection
    // ========================================================================

    void DetectOverlay() noexcept {
        if (m_info.sections.empty()) {
            return;
        }

        // Find the end of the last section
        size_t lastSectionEnd = 0;
        for (const auto& sec : m_info.sections) {
            size_t secEnd;
            if (SafeMath::SafeAdd(static_cast<size_t>(sec.rawAddress),
                                   static_cast<size_t>(sec.rawSize), secEnd)) {
                if (secEnd > lastSectionEnd) {
                    lastSectionEnd = secEnd;
                }
            }
        }

        // Check if there's data after the last section
        if (lastSectionEnd < m_info.fileSize) {
            m_info.overlayOffset = lastSectionEnd;
            m_info.overlaySize = m_info.fileSize - lastSectionEnd;

            if (m_info.overlaySize > 0) {
                m_info.anomalies.emplace_back(AnomalyType::OverlayPresent,
                                              L"File has overlay data");
            }
        }
    }

    // ========================================================================
    // Anomaly Detection
    // ========================================================================

    void DetectAnomalies() noexcept {
        // Timestamp anomalies
        if (m_info.timeDateStamp == 0) {
            m_info.anomalies.emplace_back(AnomalyType::TimestampZero,
                                          L"Timestamp is zero");
        } else {
            // Check for future timestamp (more than 1 day in future)
            auto now = std::chrono::system_clock::now();
            auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            if (m_info.timeDateStamp > nowEpoch + 86400) {
                m_info.anomalies.emplace_back(AnomalyType::TimestampInFuture,
                                              L"Timestamp is in the future");
            }
            // Check for very old timestamp (before 1995)
            if (m_info.timeDateStamp < 788918400) {  // 1995-01-01
                m_info.anomalies.emplace_back(AnomalyType::TimestampVeryOld,
                                              L"Timestamp is suspiciously old");
            }
        }

        // Security feature checks
        if ((m_info.dllCharacteristics & DllCharacteristics::DYNAMIC_BASE) == 0) {
            m_info.anomalies.emplace_back(AnomalyType::NoASLR,
                                          L"ASLR not enabled");
        }

        if ((m_info.dllCharacteristics & DllCharacteristics::NX_COMPAT) == 0) {
            m_info.anomalies.emplace_back(AnomalyType::NoDEP,
                                          L"DEP/NX not enabled");
        }

        if ((m_info.dllCharacteristics & DllCharacteristics::NO_SEH) == 0 &&
            (m_info.dllCharacteristics & DllCharacteristics::GUARD_CF) == 0) {
            // Not necessarily bad, but notable for modern binaries
        }

        // NoCFG: Control Flow Guard absent on binaries compiled after 2014-01-01
        // (the year Microsoft shipped GUARD_CF support). Exclude .NET — the CLR
        // provides its own control-flow model.
        static constexpr uint32_t kCFGEpoch = 1388534400u;  // 2014-01-01 UTC
        if (!m_info.isDotNet &&
            m_info.timeDateStamp > kCFGEpoch &&
            (m_info.dllCharacteristics & DllCharacteristics::GUARD_CF) == 0) {
            m_info.anomalies.emplace_back(
                AnomalyType::NoCFG,
                L"Control Flow Guard (GUARD_CF) not enabled on modern binary (post-2014)");
        }

        // NoSEH: For user-mode executables (not DLL / driver / .NET), the absence
        // of NO_SEH means SEH handlers are present and could be exploited via
        // traditional SEH-overwrite techniques if CFG/SEHOP is also absent.
        if (!m_info.isDLL && !m_info.isDriver && !m_info.isDotNet &&
            (m_info.dllCharacteristics & DllCharacteristics::NO_SEH) == 0) {
            m_info.anomalies.emplace_back(
                AnomalyType::NoSEH,
                L"NO_SEH flag not set; executable may contain exploitable SEH handlers");
        }

        // Checksum check
        if (m_info.checksum == 0 && m_info.isDriver) {
            m_info.anomalies.emplace_back(AnomalyType::WeakChecksum,
                                          L"Driver has no checksum");
        }

        // Section name checks
        for (const auto& sec : m_info.sections) {
            if (sec.name.empty()) {
                m_info.anomalies.emplace_back(AnomalyType::SectionNameEmpty,
                                              L"Section has empty name");
            } else {
                // Check for non-printable characters
                bool hasNonPrintable = false;
                for (char c : sec.name) {
                    if (c != '\0' && (c < 0x20 || c > 0x7E)) {
                        hasNonPrintable = true;
                        break;
                    }
                }
                if (hasNonPrintable) {
                    m_info.anomalies.emplace_back(AnomalyType::SectionNameNonPrintable,
                                                  L"Section has non-printable characters in name");
                }
            }
        }

        // Check for no imports (suspicious for most executables)
        if (!m_info.dataDirectories[DataDirectory::IMPORT].present && !m_info.isDLL) {
            m_info.anomalies.emplace_back(AnomalyType::NoImports,
                                          L"No import table");
        }
    }

    // ========================================================================
    // Address Translation
    // ========================================================================

    [[nodiscard]] std::optional<size_t> RvaToOffsetInternal(uint32_t rva) const noexcept {
        if (rva == 0) {
            return std::nullopt;
        }

        // Check if RVA is in headers
        if (rva < m_info.sizeOfHeaders) {
            return static_cast<size_t>(rva);
        }

        // Find section containing RVA
        for (const auto& sec : m_rawSections) {
            uint32_t secVa = sec.VirtualAddress;
            uint32_t secVSize = sec.VirtualSize;
            if (secVSize == 0) {
                secVSize = sec.SizeOfRawData;
            }

            if (rva >= secVa && rva < secVa + secVSize) {
                // Calculate offset within section
                uint32_t sectionOffset = rva - secVa;

                // Check if within raw data
                if (sectionOffset < sec.SizeOfRawData) {
                    size_t fileOffset;
                    if (SafeMath::SafeAdd(static_cast<size_t>(sec.PointerToRawData),
                                           static_cast<size_t>(sectionOffset), fileOffset)) {
                        if (fileOffset < m_reader.Size()) {
                            return fileOffset;
                        }
                    }
                }
                return std::nullopt;  // RVA in virtual-only portion
            }
        }

        return std::nullopt;
    }

    // ========================================================================
    // Import Parsing
    // ========================================================================

    [[nodiscard]] bool ParseImportsInternal(std::vector<ImportInfo>& out, PEError* err) noexcept {
        out.clear();

        const auto& importDir = m_info.dataDirectories[DataDirectory::IMPORT];
        if (!importDir.present || importDir.rva == 0) {
            return true;  // No imports is valid
        }

        auto importOffset = RvaToOffsetInternal(importDir.rva);
        if (!importOffset) {
            if (err) {
                err->Set(ValidationResult::ImportDirectoryInvalid,
                         L"Import directory RVA does not resolve to valid offset",
                         0);
            }
            return false;
        }

        // Anti-loop protection
        std::unordered_set<size_t> visitedDescriptors;
        size_t descriptorCount = 0;

        size_t offset = *importOffset;

        while (descriptorCount < Limits::MAX_IMPORT_DESCRIPTORS) {
            // Loop detection
            if (visitedDescriptors.count(offset)) {
                m_info.anomalies.emplace_back(AnomalyType::DelayLoadSuspicious,
                                              L"Circular import descriptor chain");
                break;
            }
            visitedDescriptors.insert(offset);

            ImportDescriptor desc;
            if (!m_reader.Read(offset, desc)) {
                break;  // End of table or read error
            }

            // Check for null terminator
            if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0) {
                break;
            }

            ImportInfo import;
            import.originalFirstThunk = desc.OriginalFirstThunk;
            import.firstThunk = desc.FirstThunk;

            // Parse DLL name
            if (desc.Name != 0) {
                auto nameOffset = RvaToOffsetInternal(desc.Name);
                if (nameOffset) {
                    std::string_view name;
                    if (m_reader.ReadString(*nameOffset, Limits::MAX_DLL_NAME, name)) {
                        import.dllName = Utils::StringUtils::ToWide(std::string(name));
                    }
                }
            }

            // Parse imported functions
            uint32_t thunkRva = desc.OriginalFirstThunk;
            if (thunkRva == 0) {
                thunkRva = desc.FirstThunk;  // Fallback to IAT
            }

            if (thunkRva != 0) {
                ParseImportThunks(thunkRva, desc.FirstThunk, import.functions);
            }

            out.push_back(std::move(import));

            offset += sizeof(ImportDescriptor);
            ++descriptorCount;
        }

        return true;
    }

    void ParseImportThunks(uint32_t intRva, uint32_t iatRva,
                           std::vector<ImportFunctionInfo>& out) noexcept {
        auto thunkOffset = RvaToOffsetInternal(intRva);
        if (!thunkOffset) return;

        size_t funcCount = 0;
        size_t offset = *thunkOffset;
        uint32_t iatOffset = iatRva;

        while (funcCount < Limits::MAX_IMPORTS_PER_DLL) {
            ImportFunctionInfo func;
            func.iatRva = iatOffset;

            if (m_info.is64Bit) {
                uint64_t thunk;
                if (!m_reader.Read(offset, thunk) || thunk == 0) break;

                if (thunk & ORDINAL_FLAG64) {
                    func.byOrdinal = true;
                    func.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                } else {
                    auto hintNameOffset = RvaToOffsetInternal(static_cast<uint32_t>(thunk));
                    if (hintNameOffset) {
                        uint16_t hint;
                        if (m_reader.Read(*hintNameOffset, hint)) {
                            func.hint = hint;
                            std::string_view name;
                            if (m_reader.ReadString(*hintNameOffset + 2,
                                                    Limits::MAX_FUNCTION_NAME, name)) {
                                func.name = std::string(name);
                            }
                        }
                    }
                }

                offset += sizeof(uint64_t);
                iatOffset += sizeof(uint64_t);
            } else {
                uint32_t thunk;
                if (!m_reader.Read(offset, thunk) || thunk == 0) break;

                if (thunk & ORDINAL_FLAG32) {
                    func.byOrdinal = true;
                    func.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                } else {
                    auto hintNameOffset = RvaToOffsetInternal(thunk);
                    if (hintNameOffset) {
                        uint16_t hint;
                        if (m_reader.Read(*hintNameOffset, hint)) {
                            func.hint = hint;
                            std::string_view name;
                            if (m_reader.ReadString(*hintNameOffset + 2,
                                                    Limits::MAX_FUNCTION_NAME, name)) {
                                func.name = std::string(name);
                            }
                        }
                    }
                }

                offset += sizeof(uint32_t);
                iatOffset += sizeof(uint32_t);
            }

            out.push_back(std::move(func));
            ++funcCount;
        }
    }

    // ========================================================================
    // Export Parsing
    // ========================================================================

    [[nodiscard]] bool ParseExportsInternal(ExportDirectoryInfo& out, PEError* err) noexcept {
        out = ExportDirectoryInfo();

        const auto& exportDir = m_info.dataDirectories[DataDirectory::EXPORT];
        if (!exportDir.present || exportDir.rva == 0) {
            return true;
        }

        auto exportOffset = RvaToOffsetInternal(exportDir.rva);
        if (!exportOffset) {
            if (err) {
                err->Set(ValidationResult::ExportDirectoryInvalid,
                         L"Export directory RVA invalid", 0);
            }
            return false;
        }

        ExportDirectory dir;
        if (!m_reader.Read(*exportOffset, dir)) {
            if (err) {
                err->Set(ValidationResult::ExportDirectoryOutOfBounds,
                         L"Cannot read export directory", *exportOffset);
            }
            return false;
        }

        out.ordinalBase = dir.Base;
        out.numberOfFunctions = dir.NumberOfFunctions;
        out.numberOfNames = dir.NumberOfNames;

        // Parse DLL name
        if (dir.Name != 0) {
            auto nameOffset = RvaToOffsetInternal(dir.Name);
            if (nameOffset) {
                std::string_view name;
                if (m_reader.ReadString(*nameOffset, Limits::MAX_DLL_NAME, name)) {
                    out.dllName = Utils::StringUtils::ToWide(std::string(name));
                }
            }
        }

        // Validate counts
        if (dir.NumberOfFunctions > Limits::MAX_EXPORTS) {
            if (err) {
                err->Set(ValidationResult::ExportCountExceeded,
                         L"Export count exceeds limit", 0);
            }
            return false;
        }

        // Get table offsets
        auto eatOffset = RvaToOffsetInternal(dir.AddressOfFunctions);
        auto nptOffset = RvaToOffsetInternal(dir.AddressOfNames);
        auto ordOffset = RvaToOffsetInternal(dir.AddressOfNameOrdinals);

        if (!eatOffset) return true;  // No exports

        // Build a fixed-size EAT indexed 0..(NumberOfFunctions-1).
        // ordIndex values from the Name-Ordinal table are 0-based indices into
        // this full array, NOT indices into a compacted vector.  Building a
        // compacted vector first and then using ordIndex as an index into it
        // produces wrong name→ordinal associations.
        std::vector<ExportInfo> eat(dir.NumberOfFunctions);
        for (uint32_t i = 0; i < dir.NumberOfFunctions; ++i) {
            eat[i].ordinal = dir.Base + i;

            uint32_t funcRva;
            if (!m_reader.Read(*eatOffset + i * sizeof(uint32_t), funcRva)) {
                continue;
            }
            if (funcRva == 0) continue;  // Empty EAT slot

            eat[i].rva = funcRva;

            // Forwarder: RVA falls within the export directory bounds
            if (funcRva >= exportDir.rva && funcRva < exportDir.rva + exportDir.size) {
                eat[i].isForwarder = true;
                auto fwdOffset = RvaToOffsetInternal(funcRva);
                if (fwdOffset) {
                    std::string_view fwdName;
                    if (m_reader.ReadString(*fwdOffset, Limits::MAX_DLL_NAME, fwdName)) {
                        eat[i].forwarderName = std::string(fwdName);
                    }
                }
            }
        }

        // Match export names using the raw EAT index (ordIndex is a 0-based
        // index into the full EAT, validated against NumberOfFunctions).
        if (nptOffset && ordOffset && dir.NumberOfNames > 0) {
            for (uint32_t i = 0; i < dir.NumberOfNames && i < Limits::MAX_EXPORTS; ++i) {
                uint32_t nameRva;
                uint16_t ordIndex;

                if (!m_reader.Read(*nptOffset + i * sizeof(uint32_t), nameRva)) continue;
                if (!m_reader.Read(*ordOffset + i * sizeof(uint16_t), ordIndex)) continue;

                if (static_cast<uint32_t>(ordIndex) < dir.NumberOfFunctions) {
                    auto nameOffset = RvaToOffsetInternal(nameRva);
                    if (nameOffset) {
                        std::string_view name;
                        if (m_reader.ReadString(*nameOffset, Limits::MAX_FUNCTION_NAME, name)) {
                            eat[ordIndex].name    = std::string(name);
                            eat[ordIndex].byName  = true;
                        }
                    }
                }
            }
        }

        // Prune empty EAT slots and move into output
        out.exports.reserve(dir.NumberOfFunctions);
        for (auto& exp : eat) {
            if (exp.rva != 0) {
                out.exports.push_back(std::move(exp));
            }
        }

        return true;
    }

    // ========================================================================
    // TLS Parsing
    // ========================================================================

    [[nodiscard]] bool ParseTLSInternal(TLSInfo& out, PEError* err) noexcept {
        out = TLSInfo();

        const auto& tlsDir = m_info.dataDirectories[DataDirectory::TLS];
        if (!tlsDir.present || tlsDir.rva == 0) {
            return true;
        }

        auto tlsOffset = RvaToOffsetInternal(tlsDir.rva);
        if (!tlsOffset) {
            if (err) {
                err->Set(ValidationResult::TLSDirectoryInvalid,
                         L"TLS directory RVA invalid", 0);
            }
            return false;
        }

        if (m_info.is64Bit) {
            TLSDirectory64 tls;
            if (!m_reader.Read(*tlsOffset, tls)) {
                if (err) {
                    err->Set(ValidationResult::TLSDirectoryOutOfBounds,
                             L"Cannot read TLS directory", *tlsOffset);
                }
                return false;
            }

            out.startAddressOfRawData = tls.StartAddressOfRawData;
            out.endAddressOfRawData = tls.EndAddressOfRawData;
            out.addressOfIndex = tls.AddressOfIndex;
            out.addressOfCallbacks = tls.AddressOfCallBacks;
            out.sizeOfZeroFill = tls.SizeOfZeroFill;
            out.characteristics = tls.Characteristics;

            // Parse callbacks
            if (tls.AddressOfCallBacks != 0) {
                // Convert VA to RVA; validate the subtraction does not exceed 32 bits
                // before casting.  On a 64-bit PE imageBase can be large, and a crafted
                // file could produce callbacksRva > UINT32_MAX causing silent truncation.
                if (tls.AddressOfCallBacks >= m_info.imageBase) {
                    const uint64_t callbacksRva = tls.AddressOfCallBacks - m_info.imageBase;
                    if (callbacksRva > static_cast<uint64_t>(UINT32_MAX)) {
                        SS_LOG_WARNING(L"PEParser",
                            L"TLS callback VA exceeds 32-bit RVA range; skipping callbacks");
                        m_info.anomalies.emplace_back(AnomalyType::TLSCallbackPresent,
                            L"TLS callback address produces RVA > UINT32_MAX — possible crafted PE");
                    } else {
                        auto cbOffset = RvaToOffsetInternal(static_cast<uint32_t>(callbacksRva));
                        if (cbOffset) {
                            size_t offset = *cbOffset;
                            for (size_t i = 0; i < Limits::MAX_TLS_CALLBACKS; ++i) {
                                uint64_t callback;
                                if (!m_reader.Read(offset, callback) || callback == 0) break;
                                out.callbacks.push_back(callback);
                                offset += sizeof(uint64_t);
                            }
                        }
                    }
                }
            }
        } else {
            TLSDirectory32 tls;
            if (!m_reader.Read(*tlsOffset, tls)) {
                if (err) {
                    err->Set(ValidationResult::TLSDirectoryOutOfBounds,
                             L"Cannot read TLS directory", *tlsOffset);
                }
                return false;
            }

            out.startAddressOfRawData = tls.StartAddressOfRawData;
            out.endAddressOfRawData = tls.EndAddressOfRawData;
            out.addressOfIndex = tls.AddressOfIndex;
            out.addressOfCallbacks = tls.AddressOfCallBacks;
            out.sizeOfZeroFill = tls.SizeOfZeroFill;
            out.characteristics = tls.Characteristics;

            if (tls.AddressOfCallBacks != 0) {
                if (tls.AddressOfCallBacks >= m_info.imageBase) {
                    uint32_t callbacksRva = tls.AddressOfCallBacks -
                                            static_cast<uint32_t>(m_info.imageBase);
                    auto cbOffset = RvaToOffsetInternal(callbacksRva);
                    if (cbOffset) {
                        size_t offset = *cbOffset;
                        for (size_t i = 0; i < Limits::MAX_TLS_CALLBACKS; ++i) {
                            uint32_t callback;
                            if (!m_reader.Read(offset, callback) || callback == 0) break;
                            out.callbacks.push_back(callback);
                            offset += sizeof(uint32_t);
                        }
                    }
                }
            }
        }

        // Flag TLS callbacks as anomaly
        if (!out.callbacks.empty()) {
            m_info.anomalies.emplace_back(AnomalyType::TLSCallbackPresent,
                                          L"TLS callbacks present");
        }

        return true;
    }

    // ========================================================================
    // Relocation Parsing
    // ========================================================================

    [[nodiscard]] bool ParseRelocationsInternal(std::vector<RelocationBlock>& out,
                                                 PEError* err) noexcept {
        out.clear();

        const auto& relocDir = m_info.dataDirectories[DataDirectory::BASERELOC];
        if (!relocDir.present || relocDir.rva == 0 || relocDir.size == 0) {
            return true;
        }

        auto relocOffset = RvaToOffsetInternal(relocDir.rva);
        if (!relocOffset) {
            if (err) {
                err->Set(ValidationResult::RelocDirectoryInvalid,
                         L"Relocation directory RVA invalid", 0);
            }
            return false;
        }

        std::unordered_set<size_t> visitedBlocks;
        size_t offset = *relocOffset;
        size_t endOffset = *relocOffset + relocDir.size;
        size_t blockCount = 0;
        size_t totalEntries = 0;

        while (offset < endOffset && blockCount < Limits::MAX_RELOCATION_BLOCKS) {
            if (visitedBlocks.count(offset)) {
                break;  // Loop detected
            }
            visitedBlocks.insert(offset);

            BaseRelocation block;
            if (!m_reader.Read(offset, block)) break;

            // Validate block size
            if (block.SizeOfBlock < sizeof(BaseRelocation)) break;
            if (block.SizeOfBlock > relocDir.size) break;

            RelocationBlock relocBlock;
            relocBlock.pageRva = block.VirtualAddress;

            // Calculate number of entries
            size_t entriesSize = block.SizeOfBlock - sizeof(BaseRelocation);
            size_t numEntries = entriesSize / sizeof(uint16_t);

            size_t entryOffset = offset + sizeof(BaseRelocation);
            for (size_t i = 0; i < numEntries && totalEntries < Limits::MAX_RELOCATIONS; ++i) {
                uint16_t entry;
                if (!m_reader.Read(entryOffset + i * sizeof(uint16_t), entry)) break;

                uint16_t type = entry >> 12;
                uint16_t off = entry & 0x0FFF;

                if (type != RelocationType::RELOC_ABSOLUTE) {  // Skip padding
                    RelocationEntry reloc;
                    reloc.rva = block.VirtualAddress + off;
                    reloc.type = type;
                    relocBlock.entries.push_back(reloc);
                    ++totalEntries;
                }
            }

            out.push_back(std::move(relocBlock));
            offset += block.SizeOfBlock;
            ++blockCount;
        }

        return true;
    }

    // ========================================================================
    // Debug Directory Parsing
    // ========================================================================

    [[nodiscard]] bool ParseDebugInfoInternal(std::vector<DebugInfo>& out,
                                               PEError* err) noexcept {
        out.clear();

        const auto& debugDir = m_info.dataDirectories[DataDirectory::DEBUG];
        if (!debugDir.present || debugDir.rva == 0 || debugDir.size == 0) {
            return true;
        }

        auto debugOffset = RvaToOffsetInternal(debugDir.rva);
        if (!debugOffset) {
            if (err) {
                err->Set(ValidationResult::DebugDirectoryInvalid,
                         L"Debug directory RVA invalid", 0);
            }
            return false;
        }

        size_t numEntries = debugDir.size / sizeof(DebugDirectory);
        if (numEntries > Limits::MAX_DEBUG_ENTRIES) {
            numEntries = Limits::MAX_DEBUG_ENTRIES;
        }

        for (size_t i = 0; i < numEntries; ++i) {
            DebugDirectory entry;
            if (!m_reader.Read(*debugOffset + i * sizeof(DebugDirectory), entry)) break;

            DebugInfo info;
            info.type = entry.Type;
            info.timestamp = entry.TimeDateStamp;
            info.majorVersion = entry.MajorVersion;
            info.minorVersion = entry.MinorVersion;
            info.sizeOfData = entry.SizeOfData;
            info.addressOfRawData = entry.AddressOfRawData;
            info.pointerToRawData = entry.PointerToRawData;

            // Parse CodeView info if present
            if (entry.Type == DebugType::CODEVIEW && entry.PointerToRawData != 0) {
                ParseCodeViewInfo(entry.PointerToRawData, entry.SizeOfData, info);
            }

            out.push_back(std::move(info));
        }

        return true;
    }

    void ParseCodeViewInfo(uint32_t offset, uint32_t size, DebugInfo& info) noexcept {
        if (size < 24) return;  // Minimum CV info size

        uint32_t signature;
        if (!m_reader.Read(offset, signature)) return;

        // RSDS signature for PDB 7.0
        if (signature == 0x53445352) {  // "RSDS"
            // Read GUID
            if (m_reader.ReadBytes(offset + 4, info.pdbGuid.data(), 16)) {
                // Read age
                m_reader.Read(offset + 20, info.pdbAge);

                // Read PDB path and sanitize before storing.
                // Paths from hostile PEs can be UNC paths (\\server\share) that
                // trigger outbound SMB auth, excessively long, or embed control chars.
                std::string_view path;
                if (m_reader.ReadString(offset + 24, size - 24, path)) {
                    // 1. Reject UNC paths entirely to prevent outbound SMB auth
                    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\') {
                        info.pdbPath.clear();
                    } else {
                        // 2. Limit to MAX_PATH characters
                        const size_t maxLen = std::min(path.size(), static_cast<size_t>(MAX_PATH));
                        std::string sanitized;
                        sanitized.reserve(maxLen);
                        for (size_t k = 0; k < maxLen; ++k) {
                            const unsigned char c = static_cast<unsigned char>(path[k]);
                            // 3. Strip null bytes and control characters (0x00-0x1F, DEL 0x7F)
                            if (c >= 0x20u && c != 0x7Fu) {
                                sanitized += static_cast<char>(c);
                            }
                        }
                        info.pdbPath = std::move(sanitized);
                    }
                }
            }
        }
    }

    // ========================================================================
    // Rich Header Parsing
    // ========================================================================

    [[nodiscard]] bool ParseRichHeaderInternal(RichHeaderInfo& out, PEError* err) noexcept {
        out = RichHeaderInfo();

        // Rich header is between DOS stub and PE signature
        // Search for "Rich" signature backwards from e_lfanew
        if (m_ntHeaderOffset < 8) {
            return true;  // Not enough space
        }

        // Search for "Rich" signature
        // Cap the search window to 4 KB past the DOS header.  The Rich header
        // lives in the DOS stub, which is never more than a few KB in practice.
        // Without this cap an attacker can set e_lfanew = MAX_LFANEW (256 MB)
        // and force 256M loop iterations — a complete CPU stall.
        const size_t kMaxRichSearchBytes = 4096;
        size_t searchEnd = std::min(m_ntHeaderOffset, sizeof(DosHeader) + kMaxRichSearchBytes);
        size_t searchStart = sizeof(DosHeader);

        std::optional<size_t> richOffset;
        for (size_t i = searchEnd; i >= searchStart + 4; --i) {
            uint32_t val;
            if (m_reader.Read(i - 4, val) && val == RichHeader::RICH_SIGNATURE) {
                richOffset = i - 4;
                break;
            }
        }

        if (!richOffset) {
            return true;  // No Rich header
        }

        // Read XOR key (immediately after "Rich")
        uint32_t xorKey;
        if (!m_reader.Read(*richOffset + 4, xorKey)) {
            return true;
        }

        out.present = true;
        out.checksum = xorKey;

        // Search backwards for "DanS" signature (XOR'd)
        std::optional<size_t> dansOffset;
        for (size_t i = *richOffset; i >= searchStart + 4; i -= 4) {
            uint32_t val;
            if (m_reader.Read(i - 4, val) && (val ^ xorKey) == RichHeader::DANS_SIGNATURE) {
                dansOffset = i - 4;
                break;
            }
        }

        if (!dansOffset) {
            out.present = false;
            return true;
        }

        out.offset = *dansOffset;
        out.size = *richOffset + 8 - *dansOffset;

        // Parse entries
        size_t entryOffset = *dansOffset + 16;  // Skip DanS + 3 padding DWORDs
        while (entryOffset < *richOffset && out.entries.size() < Limits::MAX_RICH_ENTRIES) {
            uint32_t id, count;
            if (!m_reader.Read(entryOffset, id) ||
                !m_reader.Read(entryOffset + 4, count)) {
                break;
            }

            id ^= xorKey;
            count ^= xorKey;

            if (id == 0 && count == 0) break;

            RichEntry entry;
            entry.buildId = static_cast<uint16_t>(id >> 16);
            entry.productId = static_cast<uint16_t>(id & 0xFFFF);
            entry.useCount = count;

            out.entries.push_back(entry);
            entryOffset += 8;
        }

        return true;
    }

    // ========================================================================
    // Entropy Calculation
    // ========================================================================

    [[nodiscard]] double CalculateSectionEntropyInternal(size_t sectionIndex) const noexcept {
        if (sectionIndex >= m_info.sections.size()) {
            return -1.0;
        }

        const auto& sec = m_info.sections[sectionIndex];
        if (sec.rawSize == 0 || sec.rawAddress == 0) {
            return 0.0;
        }

        if (!m_reader.ValidateRange(sec.rawAddress, sec.rawSize)) {
            return -1.0;
        }

        // Count byte frequencies using a single bounds-checked ReadArray call.
        // The original byte-by-byte loop performed O(rawSize) individual bounds
        // checks — for a 512 MB section that is 512 M checks.  ReadArray does
        // one check and returns a zero-copy span.
        std::array<size_t, 256> freq = {};
        std::span<const uint8_t> secData;
        if (!m_reader.ReadArray<uint8_t>(sec.rawAddress, sec.rawSize, secData)) {
            return -1.0;
        }
        for (const uint8_t byte : secData) {
            ++freq[byte];
        }

        // Calculate Shannon entropy
        double entropy = 0.0;
        double total = static_cast<double>(sec.rawSize);

        for (size_t count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / total;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    // ========================================================================
    // Resource Directory Parsing (Recursive)
    // ========================================================================

    // Recursively parses one level of the resource tree.
    //
    // Parameters:
    //   out               – accumulator for leaf ResourceEntry records
    //   rsrcBase          – file offset of the resource section start
    //   rsrcSize          – size of the resource section in the file
    //   dirOffsetFromBase – offset of *this* directory from rsrcBase
    //   typeId/nameId/langId – IDs accumulated from ancestor levels
    //   nameIsStringEntry – true when the parent name-level entry had a string name
    //   nameStringOffset  – offset from rsrcBase to the UNICODE name string
    //   depth             – current depth (0=type, 1=name, 2=language)
    //   maxDepth          – caller-supplied recursion cap
    //   visited           – set of already-processed dir offsets for loop detection
    void ParseResourceDirectoryLevel(
            std::vector<ResourceEntry>& out,
            size_t        rsrcBase,
            uint32_t      rsrcSize,
            uint32_t      dirOffsetFromBase,
            uint32_t      typeId,
            uint32_t      nameId,
            uint32_t      langId,
            bool          nameIsStringEntry,
            uint32_t      nameStringOffset,
            uint32_t      depth,
            uint32_t      maxDepth,
            std::unordered_set<uint32_t>& visited) noexcept {

        if (depth >= maxDepth) {
            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                L"Resource tree depth limit exceeded");
            return;
        }

        if (out.size() >= Limits::MAX_TOTAL_RESOURCES) return;

        // Loop detection: offsets are relative to section base (uint32_t).
        if (!visited.insert(dirOffsetFromBase).second) {
            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                L"Circular reference detected in resource directory");
            return;
        }

        size_t rsrcEnd;
        if (!SafeMath::SafeAdd(rsrcBase, static_cast<size_t>(rsrcSize), rsrcEnd)) return;

        size_t dirFileOffset;
        if (!SafeMath::SafeAdd(rsrcBase, static_cast<size_t>(dirOffsetFromBase), dirFileOffset))
            return;

        if (dirFileOffset + sizeof(ResourceDirectory) > rsrcEnd) {
            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                L"Resource directory offset is outside the resource section");
            return;
        }

        ResourceDirectory dir;
        if (!m_reader.Read(dirFileOffset, dir)) return;

        uint32_t numEntries;
        if (!SafeMath::SafeAdd(static_cast<uint32_t>(dir.NumberOfNamedEntries),
                               static_cast<uint32_t>(dir.NumberOfIdEntries), numEntries)) {
            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                L"Resource directory entry count overflow");
            return;
        }

        if (numEntries > static_cast<uint32_t>(Limits::MAX_RESOURCE_ENTRIES)) {
            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                L"Resource directory entry count exceeds limit; truncating");
            numEntries = static_cast<uint32_t>(Limits::MAX_RESOURCE_ENTRIES);
        }

        const size_t entryTableBase = dirFileOffset + sizeof(ResourceDirectory);

        for (uint32_t i = 0;
             i < numEntries && out.size() < Limits::MAX_TOTAL_RESOURCES;
             ++i) {

            size_t stride, entryFileOffset;
            if (!SafeMath::SafeMul(static_cast<size_t>(i), sizeof(ResourceDirectoryEntry), stride) ||
                !SafeMath::SafeAdd(entryTableBase, stride, entryFileOffset)) break;

            if (entryFileOffset + sizeof(ResourceDirectoryEntry) > rsrcEnd) break;

            ResourceDirectoryEntry entry;
            if (!m_reader.Read(entryFileOffset, entry)) break;

            // Decode via explicit bit masks for portability (bitfield layout
            // of anonymous union structs is implementation-defined).
            const bool     entryNameIsString    = (entry.Name       >> 31) != 0;
            const uint32_t entryNameOffsetOrId  = entry.Name        & 0x7FFFFFFFu;
            const bool     entryDataIsDir       = (entry.OffsetToData >> 31) != 0;
            const uint32_t entryDirOrDataOffset = entry.OffsetToData & 0x7FFFFFFFu;

            // Propagate IDs down based on the current depth level.
            uint32_t curType          = typeId;
            uint32_t curName          = nameId;
            uint32_t curLang          = langId;
            bool     curNameIsString  = nameIsStringEntry;
            uint32_t curNameStrOffset = nameStringOffset;

            if (depth == 0) {
                // Type level — types are almost always integer IDs (RT_*)
                curType = entryNameIsString ? 0u : (entryNameOffsetOrId & 0xFFFFu);
            } else if (depth == 1) {
                // Name level — may be string or integer
                curNameIsString  = entryNameIsString;
                if (entryNameIsString) {
                    curName          = 0;
                    curNameStrOffset = entryNameOffsetOrId;  // offset from section base
                } else {
                    curName          = entryNameOffsetOrId & 0xFFFFu;
                    curNameStrOffset = 0;
                }
            } else if (depth == 2) {
                // Language level — always integer ID
                curLang = entryNameIsString ? 0u : (entryNameOffsetOrId & 0xFFFFu);
            }

            if (entryDataIsDir) {
                ParseResourceDirectoryLevel(out, rsrcBase, rsrcSize, entryDirOrDataOffset,
                                            curType, curName, curLang,
                                            curNameIsString, curNameStrOffset,
                                            depth + 1, maxDepth, visited);
            } else {
                // Leaf node: entryDirOrDataOffset is offset from section base to
                // a ResourceDataEntry struct.
                size_t dataEntryFileOffset;
                if (!SafeMath::SafeAdd(rsrcBase,
                                       static_cast<size_t>(entryDirOrDataOffset),
                                       dataEntryFileOffset)) continue;

                if (dataEntryFileOffset + sizeof(ResourceDataEntry) > rsrcEnd) {
                    m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                        L"Resource data entry is outside the resource section bounds");
                    continue;
                }

                ResourceDataEntry dataEntry;
                if (!m_reader.Read(dataEntryFileOffset, dataEntry)) continue;

                if (dataEntry.Size > 0x1000000u) {  // > 16 MB
                    m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                        L"Resource data entry has suspiciously large size (>16 MB)");
                }

                ResourceEntry resEntry;
                resEntry.type         = curType;
                resEntry.name         = curName;
                resEntry.language     = curLang;
                resEntry.codePage     = dataEntry.CodePage;
                resEntry.size         = dataEntry.Size;
                resEntry.nameIsString = curNameIsString;

                // dataEntry.OffsetToData is an RVA — convert to file offset.
                if (dataEntry.OffsetToData != 0) {
                    auto dataFileOpt = RvaToOffsetInternal(dataEntry.OffsetToData);
                    if (dataFileOpt) {
                        resEntry.offset = static_cast<uint32_t>(*dataFileOpt & 0xFFFFFFFFu);
                        if (!m_reader.ValidateRange(*dataFileOpt, dataEntry.Size)) {
                            m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                                L"Resource data extends beyond file boundary");
                        }
                    } else {
                        m_info.anomalies.emplace_back(AnomalyType::ResourceSizeAnomaly,
                            L"Resource data RVA cannot be resolved to a file offset");
                    }
                }

                // Resolve Unicode string name when the name-level entry was string-typed.
                // The name string is a WORD length followed by a WORD array (UTF-16LE).
                if (curNameIsString && curNameStrOffset != 0) {
                    size_t nameStrFileOffset;
                    if (SafeMath::SafeAdd(rsrcBase,
                                          static_cast<size_t>(curNameStrOffset),
                                          nameStrFileOffset)) {
                        uint16_t nameLen = 0;
                        if (m_reader.Read(nameStrFileOffset, nameLen) &&
                            nameLen > 0 && nameLen <= 256) {
                            std::wstring nameStr;
                            nameStr.reserve(nameLen);
                            bool nameOk = true;
                            for (uint16_t k = 0; k < nameLen && nameOk; ++k) {
                                size_t chOffset;
                                uint16_t ch = 0;
                                if (!SafeMath::SafeAdd(nameStrFileOffset + 2u,
                                                       static_cast<size_t>(k) * 2u,
                                                       chOffset) ||
                                    !m_reader.Read(chOffset, ch)) {
                                    nameOk = false;
                                } else {
                                    nameStr += static_cast<wchar_t>(ch);
                                }
                            }
                            if (nameOk) {
                                resEntry.nameString = std::move(nameStr);
                            }
                        }
                    }
                }

                out.push_back(std::move(resEntry));
            }
        }
    }

    [[nodiscard]] bool ParseResourcesInternal(std::vector<ResourceEntry>& out,
                                              uint32_t maxDepth,
                                              PEError* err) noexcept {
        out.clear();

        const auto& rsrcDir = m_info.dataDirectories[DataDirectory::RESOURCE];
        if (!rsrcDir.present || rsrcDir.rva == 0 || rsrcDir.size == 0) {
            return true;  // No resource directory — valid
        }

        if (maxDepth == 0) maxDepth = 1;
        if (maxDepth > Limits::MAX_RESOURCE_DEPTH) maxDepth = Limits::MAX_RESOURCE_DEPTH;

        auto rsrcBaseOpt = RvaToOffsetInternal(rsrcDir.rva);
        if (!rsrcBaseOpt) {
            if (err) {
                err->Set(ValidationResult::ResourceDirectoryInvalid,
                         L"Resource section RVA cannot be resolved to a file offset", 0);
            }
            SS_LOG_ERROR(L"PEParser",
                L"Resource directory RVA 0x%08X is invalid", rsrcDir.rva);
            return false;
        }

        const size_t rsrcBase = *rsrcBaseOpt;

        size_t rsrcEnd;
        if (!SafeMath::SafeAdd(rsrcBase, static_cast<size_t>(rsrcDir.size), rsrcEnd) ||
            rsrcEnd > m_reader.Size()) {
            if (err) {
                err->Set(ValidationResult::ResourceDirectoryOutOfBounds,
                         L"Resource section extends beyond end of file", rsrcBase);
            }
            return false;
        }

        std::unordered_set<uint32_t> visited;
        visited.reserve(64);

        // Root directory is at offset 0 from the section base.
        ParseResourceDirectoryLevel(out, rsrcBase, rsrcDir.size,
                                    0u,          // dirOffsetFromBase = 0
                                    0u, 0u, 0u,  // typeId, nameId, langId
                                    false, 0u,   // nameIsStringEntry, nameStringOffset
                                    0u, maxDepth, visited);
        return true;
    }

    // ========================================================================
    // Reset
    // ========================================================================

    void Reset() noexcept {
        m_parsed = false;
        m_info = PEInfo();
        m_reader = SafeReader();
        m_mappedFile.close();
        m_rawSections.clear();
        m_ntHeaderOffset = 0;
        m_optionalHeaderOffset = 0;
        m_sectionTableOffset = 0;
    }
};

// ============================================================================
// PEParser Public Interface Implementation
// ============================================================================

PEParser::PEParser() noexcept
    : m_impl(std::make_unique<PEParserImpl>())
{}

PEParser::~PEParser() = default;

PEParser::PEParser(PEParser&&) noexcept = default;
PEParser& PEParser::operator=(PEParser&&) noexcept = default;

bool PEParser::ParseFile(const std::wstring& path, PEInfo& out, PEError* err) noexcept {
    m_impl->Reset();

    // Validate path before touching the filesystem
    if (path.empty()) {
        if (err) err->Set(ValidationResult::NullPointer, L"Empty path provided", 0);
        return false;
    }
    if (path.size() > MAX_PATH) {
        if (err) err->Set(ValidationResult::UnknownError, L"Path length exceeds MAX_PATH", 0);
        return false;
    }
    // Reject device paths (\\?\ and \\.\) — these bypass normal path processing
    if (path.size() >= 4 &&
        path[0] == L'\\' && path[1] == L'\\' &&
        (path[2] == L'?' || path[2] == L'.') &&
        path[3] == L'\\') {
        if (err) err->Set(ValidationResult::UnknownError, L"Device paths are not permitted", 0);
        SS_LOG_ERROR(L"PEParser", L"Rejected device path: %ls", path.c_str());
        return false;
    }

    // Memory map the file
    if (!m_impl->m_mappedFile.mapReadOnly(path)) {
        // Capture GetLastError() BEFORE err->Set(), which may call OS functions
        const uint32_t lastErr = static_cast<uint32_t>(GetLastError());
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"Failed to open or map file",
                     0);
            err->win32Error = lastErr;
        }
        SS_LOG_ERROR(L"PEParser", L"Failed to map file: %ls", path.c_str());
        return false;
    }

    // Handle empty files
    if (!m_impl->m_mappedFile.hasData()) {
        if (err) {
            err->Set(ValidationResult::FileTooSmall,
                     L"File is empty",
                     0);
        }
        return false;
    }

    m_impl->m_reader = SafeReader(
        static_cast<const uint8_t*>(m_impl->m_mappedFile.data()),
        m_impl->m_mappedFile.size()
    );

    if (!m_impl->ParseInternal(err)) {
        out = PEInfo();
        return false;
    }

    out = m_impl->m_info;
    return true;
}

bool PEParser::ParseBuffer(const uint8_t* data, size_t size, PEInfo& out, PEError* err) noexcept {
    m_impl->Reset();

    if (data == nullptr || size == 0) {
        if (err) {
            err->Set(ValidationResult::NullPointer,
                     L"Null or empty buffer provided",
                     0);
        }
        return false;
    }

    m_impl->m_reader = SafeReader(data, size);

    if (!m_impl->ParseInternal(err)) {
        out = PEInfo();
        return false;
    }

    out = m_impl->m_info;
    return true;
}

bool PEParser::ParseBuffer(std::span<const uint8_t> data, PEInfo& out, PEError* err) noexcept {
    return ParseBuffer(data.data(), data.size(), out, err);
}

bool PEParser::ParseImports(std::vector<ImportInfo>& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseImportsInternal(out, err);
}

bool PEParser::ParseExports(ExportDirectoryInfo& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseExportsInternal(out, err);
}

bool PEParser::ParseTLS(TLSInfo& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseTLSInternal(out, err);
}

bool PEParser::ParseResources(std::vector<ResourceEntry>& out, uint32_t maxDepth, PEError* err) noexcept {
    out.clear();

    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }

    return m_impl->ParseResourcesInternal(out, maxDepth, err);
}

bool PEParser::ParseRelocations(std::vector<RelocationBlock>& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseRelocationsInternal(out, err);
}

bool PEParser::ParseDebugInfo(std::vector<DebugInfo>& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseDebugInfoInternal(out, err);
}

bool PEParser::ParseRichHeader(RichHeaderInfo& out, PEError* err) noexcept {
    if (!m_impl->m_parsed) {
        if (err) {
            err->Set(ValidationResult::UnknownError,
                     L"No PE file has been parsed",
                     0);
        }
        return false;
    }
    return m_impl->ParseRichHeaderInternal(out, err);
}

std::optional<size_t> PEParser::RvaToOffset(uint32_t rva) const noexcept {
    if (!m_impl->m_parsed) return std::nullopt;
    return m_impl->RvaToOffsetInternal(rva);
}

std::optional<uint32_t> PEParser::OffsetToRva(size_t offset) const noexcept {
    if (!m_impl->m_parsed) return std::nullopt;

    // Check if in headers
    if (offset < m_impl->m_info.sizeOfHeaders) {
        return static_cast<uint32_t>(offset);
    }

    // Find section containing offset
    for (const auto& sec : m_impl->m_rawSections) {
        if (sec.SizeOfRawData == 0) continue;

        size_t secStart = sec.PointerToRawData;
        size_t secEnd;
        if (!SafeMath::SafeAdd(secStart, static_cast<size_t>(sec.SizeOfRawData), secEnd)) {
            continue;
        }

        if (offset >= secStart && offset < secEnd) {
            size_t secOffset = offset - secStart;
            uint32_t rva;
            if (!SafeMath::SafeAdd(sec.VirtualAddress, static_cast<uint32_t>(secOffset), rva)) {
                continue;
            }
            return rva;
        }
    }

    return std::nullopt;
}

bool PEParser::IsValidRva(uint32_t rva) const noexcept {
    return RvaToOffset(rva).has_value();
}

std::optional<size_t> PEParser::GetSectionByRva(uint32_t rva) const noexcept {
    if (!m_impl->m_parsed) return std::nullopt;

    for (size_t i = 0; i < m_impl->m_info.sections.size(); ++i) {
        const auto& sec = m_impl->m_info.sections[i];
        const uint32_t secSize = sec.virtualSize ? sec.virtualSize : sec.rawSize;
        uint32_t secEnd;
        // Guard against virtualAddress + secSize wrapping to near-zero
        if (!SafeMath::SafeAdd(sec.virtualAddress, secSize, secEnd)) {
            continue;  // Overflow — skip this section
        }
        if (rva >= sec.virtualAddress && rva < secEnd) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<size_t> PEParser::GetSectionByName(std::string_view name) const noexcept {
    if (!m_impl->m_parsed) return std::nullopt;

    for (size_t i = 0; i < m_impl->m_info.sections.size(); ++i) {
        if (m_impl->m_info.sections[i].name == name) {
            return i;
        }
    }
    return std::nullopt;
}

bool PEParser::ValidatePE(std::vector<ValidationResult>& issues) const noexcept {
    issues.clear();

    if (!m_impl->m_parsed) {
        issues.push_back(ValidationResult::UnknownError);
        return false;
    }

    // Collect all section validation issues
    for (size_t i = 0; i < m_impl->m_rawSections.size(); ++i) {
        auto result = ValidateSectionHeader(
            m_impl->m_rawSections[i],
            m_impl->m_reader.Size(),
            m_impl->m_info.sizeOfImage,
            m_impl->m_info.fileAlignment,
            i,
            nullptr
        );
        if (result != ValidationResult::Valid) {
            issues.push_back(result);
        }
    }

    // Check section overlaps
    std::vector<std::pair<size_t, size_t>> overlaps;
    if (CheckSectionOverlaps(m_impl->m_rawSections, overlaps)) {
        issues.push_back(ValidationResult::SectionOverlap);
    }

    return issues.empty();
}

bool PEParser::HasAnomaly(AnomalyType type) const noexcept {
    if (!m_impl->m_parsed) return false;

    for (const auto& anomaly : m_impl->m_info.anomalies) {
        if (anomaly.type == type) return true;
    }
    return false;
}

const SafeReader* PEParser::GetReader() const noexcept {
    return m_impl->m_parsed ? &m_impl->m_reader : nullptr;
}

const PEInfo* PEParser::GetInfo() const noexcept {
    return m_impl->m_parsed ? &m_impl->m_info : nullptr;
}

bool PEParser::IsParsed() const noexcept {
    return m_impl->m_parsed;
}

void PEParser::Reset() noexcept {
    m_impl->Reset();
}

double PEParser::CalculateSectionEntropy(size_t sectionIndex) const noexcept {
    if (!m_impl->m_parsed) return -1.0;
    return m_impl->CalculateSectionEntropyInternal(sectionIndex);
}

bool PEParser::VerifyChecksum() const noexcept {
    if (!m_impl->m_parsed) return false;

    // A stored checksum of zero means "not set" — treat as passing.
    if (m_impl->m_info.checksum == 0) return true;

    const size_t fileSize = m_impl->m_reader.Size();
    if (fileSize == 0) return false;

    // The CheckSum field in the optional header is at a fixed offset of 64 bytes
    // from the start of the optional header in BOTH PE32 and PE32+ (confirmed
    // by counting struct member sizes).  It occupies 4 bytes = two 16-bit words.
    static constexpr size_t kChecksumFieldOffset = 64;
    const size_t checksumByteOffset = m_impl->m_optionalHeaderOffset + kChecksumFieldOffset;

    // The field must be word-aligned and fully within the file.
    if ((checksumByteOffset & 1u) != 0 || checksumByteOffset + 4u > fileSize) {
        SS_LOG_ERROR(L"PEParser",
            L"Checksum field offset 0x%zX is misaligned or out of bounds",
            checksumByteOffset);
        return false;
    }

    // Obtain the file as a contiguous span of 16-bit words.  One ReadArray call
    // does a single bounds check instead of one per word.
    const size_t wordCount = fileSize / 2;
    std::span<const uint16_t> words;
    if (!m_impl->m_reader.ReadArray<uint16_t>(0, wordCount, words)) {
        return false;
    }

    // The two words that constitute the stored checksum field must be skipped.
    const size_t skipWord0 = checksumByteOffset / 2;
    const size_t skipWord1 = skipWord0 + 1;

    // Microsoft fold-and-add algorithm (equivalent to MapFileAndCheckSumW):
    //   accumulator += word; accumulator = (hi16 + lo16);
    uint32_t acc = 0;
    for (size_t i = 0; i < wordCount; ++i) {
        if (i == skipWord0 || i == skipWord1) continue;
        acc += words[i];
        acc = (acc >> 16) + (acc & 0xFFFFu);
    }

    // Trailing odd byte (if file size is not a multiple of 2): pad with 0x00.
    if (fileSize & 1u) {
        uint8_t lastByte = 0;
        if (m_impl->m_reader.ReadByte(fileSize - 1, lastByte)) {
            acc += static_cast<uint16_t>(lastByte);
            acc = (acc >> 16) + (acc & 0xFFFFu);
        }
    }

    // Final fold, then add file size.
    acc  = (acc & 0xFFFFu) + (acc >> 16);
    acc += static_cast<uint32_t>(fileSize);
    acc  = (acc & 0xFFFFu) + (acc >> 16);

    const uint32_t computed = acc & 0xFFFFu;
    return computed == m_impl->m_info.checksum;
}

std::wstring PEParser::MachineToString(uint16_t machine) noexcept {
    switch (machine) {
        case Machine::UNKNOWN:   return L"Unknown";
        case Machine::I386:      return L"Intel 386";
        case Machine::AMD64:     return L"AMD64 (x64)";
        case Machine::ARM:       return L"ARM";
        case Machine::ARMNT:     return L"ARM Thumb-2";
        case Machine::ARM64:     return L"ARM64";
        case Machine::IA64:      return L"Intel Itanium";
        case Machine::THUMB:     return L"ARM Thumb";
        case Machine::POWERPC:   return L"PowerPC";
        case Machine::MIPS16:    return L"MIPS16";
        case Machine::ALPHA:     return L"Alpha";
        case Machine::ALPHA64:   return L"Alpha64";
        case Machine::SH3:       return L"Hitachi SH3";
        case Machine::SH4:       return L"Hitachi SH4";
        case Machine::EBC:       return L"EFI Byte Code";
        default:                 return L"Unknown (" + std::to_wstring(machine) + L")";
    }
}

std::wstring PEParser::SubsystemToString(uint16_t subsystem) noexcept {
    switch (subsystem) {
        case Subsystem::UNKNOWN:                  return L"Unknown";
        case Subsystem::NATIVE:                   return L"Native (Driver)";
        case Subsystem::WINDOWS_GUI:              return L"Windows GUI";
        case Subsystem::WINDOWS_CUI:              return L"Windows Console";
        case Subsystem::OS2_CUI:                  return L"OS/2 Console";
        case Subsystem::POSIX_CUI:                return L"POSIX Console";
        case Subsystem::NATIVE_WINDOWS:           return L"Native Windows";
        case Subsystem::WINDOWS_CE_GUI:           return L"Windows CE GUI";
        case Subsystem::EFI_APPLICATION:          return L"EFI Application";
        case Subsystem::EFI_BOOT_SERVICE_DRIVER:  return L"EFI Boot Driver";
        case Subsystem::EFI_RUNTIME_DRIVER:       return L"EFI Runtime Driver";
        case Subsystem::EFI_ROM:                  return L"EFI ROM";
        case Subsystem::XBOX:                     return L"Xbox";
        case Subsystem::WINDOWS_BOOT_APPLICATION: return L"Windows Boot Application";
        default:                                  return L"Unknown (" + std::to_wstring(subsystem) + L")";
    }
}

} // namespace PEParser
} // namespace ShadowStrike
