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
 * ShadowStrike PhantomCortex - REAL-TIME FEATURE EXTRACTION ENGINE
 * ============================================================================
 *
 * @file FeatureExtractor.cpp
 * @brief Production implementation of ML feature extraction for ONNX inference.
 *
 * Converts raw telemetry (PE bytes, API sequences, memory dumps, network flows,
 * emulation traces) into fixed-size float vectors whose encoding is identical
 * to the Python training pipeline. Any divergence will silently degrade
 * detection accuracy.
 *
 * FEATURE VECTOR LAYOUT (EMBER-aligned for PE):
 * ──────────────────────────────────────────────
 * [  0 – 255 ] ByteHistogram            256
 * [256 – 511 ] ByteEntropyHistogram      256
 * [512 – 615 ] StringExtractor           104
 * [616 – 625 ] GeneralFileInfo            10
 * [626 – 687 ] HeaderFileInfo             62
 * [688 – 942 ] SectionInfo               255
 * [943 –2222 ] ImportsInfo              1280
 * [2223–2350 ] ExportsInfo               128
 * [2351–2380 ] DataDirectories            30
 *                                      ─────
 *                                       2381
 *
 * SECURITY: All buffer accesses are bounds-checked via SafeReader. Malformed
 * PE files, truncated traces, and adversarial inputs return std::nullopt
 * without undefined behavior.
 *
 * THREAD SAFETY: All extraction methods are stateless w.r.t. Impl (read-only
 * lookup tables). Concurrent calls are safe after Initialize().
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * ============================================================================
 */

#include"pch.h"

#include "FeatureExtractor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/HashUtils.hpp"
#include "../PEParser/PETypes.hpp"
#include "../PEParser/PEConstants.hpp"
#include "../PEParser/SafeReader.hpp"

#include <cmath>
#include <cstring>
#include <numeric>
#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>

namespace ShadowStrike {
namespace AI {

// ============================================================================
// Anonymous Namespace — Internal Constants & Helpers
// ============================================================================

namespace {

constexpr wchar_t kLogCategory[] = L"FeatureExtractor";

// --- PE Feature Group Offsets ---
constexpr size_t kByteHistOffset       = 0;
constexpr size_t kByteHistSize         = 256;
constexpr size_t kByteEntropyOffset    = 256;
constexpr size_t kByteEntropySize      = 256;
constexpr size_t kStringOffset         = 512;
constexpr size_t kStringSize           = 104;
constexpr size_t kGeneralInfoOffset    = 616;
constexpr size_t kGeneralInfoSize      = 10;
constexpr size_t kHeaderInfoOffset     = 626;
constexpr size_t kHeaderInfoSize       = 62;
constexpr size_t kSectionInfoOffset    = 688;
constexpr size_t kSectionInfoSize      = 255;
constexpr size_t kImportsInfoOffset    = 943;
constexpr size_t kImportsInfoSize      = 1280;
constexpr size_t kExportsInfoOffset    = 2223;
constexpr size_t kExportsInfoSize      = 128;
constexpr size_t kDataDirOffset        = 2351;
constexpr size_t kDataDirSize          = 30;

// --- Byte-Entropy Histogram Parameters ---
constexpr size_t kEntropyWindowSize    = 2048;
constexpr size_t kEntropyWindowStep    = 1024;
constexpr size_t kEntropyBins          = 16;
constexpr size_t kByteGroups           = 16;

// --- String Extraction ---
constexpr size_t kMinStringLength      = 5;
constexpr size_t kMaxStringsCollected  = 100000;

// --- Import/Export Hashing ---
constexpr size_t kImportBins           = 1280;
constexpr size_t kExportBins           = 128;

// --- Section Feature Extraction ---
constexpr size_t kMaxSectionsForFeatures = 10;
constexpr size_t kFeaturesPerSection     = 10;
constexpr size_t kSectionAggregateStart  = 100;
constexpr size_t kNumKnownSectionNames   = 17;

// --- Behavioral ---
constexpr size_t kBehavioralCalls      = 128;
constexpr size_t kFeaturesPerCall      = 4;

// --- Memory ---
constexpr size_t kMemCompressedBins    = 32;
constexpr size_t kMemBigramFeatures    = 100;
constexpr size_t kMemBlockEntropyStats = 8;
constexpr size_t kMemBlockSize         = 256;

// --- Network ---
constexpr size_t kProtocolOneHotSize   = 6;

// --- Emulation ---
constexpr size_t kOpcodeCategories     = 16;
constexpr size_t kMemAccessTypes       = 4;
constexpr size_t kTopAPIs              = 100;
constexpr size_t kEflagsBits           = 8;
constexpr size_t kNgramFeatures        = 128;
constexpr size_t kTemporalFeatures     = 128;

// Known suspicious strings for PE string analysis.
// Indices 12..91 of the string feature vector.
constexpr const char* kSuspiciousStrings[] = {
    "cmd.exe", "powershell", "WScript", "CreateRemoteThread",
    "VirtualAlloc", "WriteProcessMemory", "NtProtectVirtualMemory",
    "VirtualProtect", "VirtualAllocEx", "NtWriteVirtualMemory",
    "NtMapViewOfSection", "RtlCreateUserThread", "QueueUserAPC",
    "SetWindowsHookEx", "NtQueueApcThread", "LoadLibrary",
    "GetProcAddress", "OpenProcess", "ReadProcessMemory",
    "NtReadVirtualMemory", "CreateProcess", "ShellExecute",
    "WinExec", "URLDownloadToFile", "InternetOpen",
    "HttpSendRequest", "WSAStartup", "connect",
    "send", "recv", "socket",
    "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx",
    "CreateService", "StartService", "ChangeServiceConfig",
    "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtAllocateVirtualMemory",
    "RtlMoveMemory", "CryptEncrypt", "CryptDecrypt",
    "CryptGenKey", "CryptAcquireContext", "BCryptEncrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter", "GetSystemTime",
    "FindFirstFile", "FindNextFile", "DeleteFile",
    "MoveFileEx", "CopyFile", "CreateFile",
    "WriteFile", "ReadFile", "SetFilePointer",
    "GetTempPath", "GetEnvironmentVariable", "ExpandEnvironmentStrings",
    "GetModuleHandle", "GetModuleFileName", "GetCurrentProcess",
    "NtClose", "CloseHandle", "TerminateProcess",
    "ExitProcess", "SuspendThread", "ResumeThread",
    "CreateThread", "NtCreateThreadEx", "RtlAdjustPrivilege",
    "NtSetInformationThread", "SetThreadContext", "GetThreadContext",
    "Wow64SetThreadContext", "EnumProcesses"
};
constexpr size_t kNumSuspiciousStrings = sizeof(kSuspiciousStrings) / sizeof(kSuspiciousStrings[0]);
static_assert(kNumSuspiciousStrings <= 80, "Suspicious string list must fit within 80 feature slots");

// Known section names for presence flags.
constexpr const char* kKnownSectionNames[] = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc",
    ".bss", ".idata", ".edata", ".pdata",
    "UPX0", "UPX1", ".ndata", ".aspack", ".adata",
    "CODE", "DATA", "BSS"
};
static_assert(sizeof(kKnownSectionNames) / sizeof(kKnownSectionNames[0]) == kNumKnownSectionNames,
              "Section name count mismatch");

// ============================================================================
// MurmurHash3 — 32-bit finalizer for feature hashing (import/export bins).
// Must match Python training pipeline exactly.
// ============================================================================

[[nodiscard]] uint32_t MurmurHash3_x86_32(const void* key, size_t len, uint32_t seed) noexcept {
    const auto* data = static_cast<const uint8_t*>(key);
    const size_t nblocks = len / 4;

    uint32_t h1 = seed;
    constexpr uint32_t c1 = 0xCC9E2D51;
    constexpr uint32_t c2 = 0x1B873593;

    // Process in safe way — read via memcpy to avoid alignment issues
    for (size_t i = 0; i < nblocks; ++i) {
        uint32_t k1;
        std::memcpy(&k1, data + i * 4, sizeof(uint32_t));

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xE6546B64;
    }

    const uint8_t* tail = data + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3: k1 ^= static_cast<uint32_t>(tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= static_cast<uint32_t>(tail[1]) << 8;  [[fallthrough]];
        case 1: k1 ^= static_cast<uint32_t>(tail[0]);
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    h1 ^= static_cast<uint32_t>(len);
    // fmix32
    h1 ^= h1 >> 16;
    h1 *= 0x85EBCA6B;
    h1 ^= h1 >> 13;
    h1 *= 0xC2B2AE35;
    h1 ^= h1 >> 16;

    return h1;
}

// ============================================================================
// Shannon Entropy
// ============================================================================

[[nodiscard]] float ComputeShannonEntropy(const uint8_t* data, size_t len) noexcept {
    if (len == 0) return 0.0f;

    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < len; ++i) {
        ++counts[data[i]];
    }

    double entropy = 0.0;
    const double invLen = 1.0 / static_cast<double>(len);
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            const double p = static_cast<double>(counts[i]) * invLen;
            entropy -= p * std::log2(p);
        }
    }
    return static_cast<float>(entropy);
}

// ============================================================================
// Safe log-scaling
// ============================================================================

[[nodiscard]] inline float SafeLog1p(float x) noexcept {
    return (x > 0.0f) ? std::log1p(x) : 0.0f;
}

[[nodiscard]] inline float SafeLog(double x) noexcept {
    return (x > 0.0) ? static_cast<float>(std::log(x)) : 0.0f;
}

// ============================================================================
// Case-insensitive substring search
// ============================================================================

[[nodiscard]] bool ContainsCaseInsensitive(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.size() > haystack.size()) return false;
    auto toLower = [](char c) -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    };
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (toLower(haystack[i + j]) != toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// RVA-to-file-offset conversion
// ============================================================================

struct SectionLocator {
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t pointerToRawData;
    uint32_t sizeOfRawData;
};

[[nodiscard]] std::optional<size_t> RvaToFileOffset(
    uint32_t rva,
    std::span<const SectionLocator> sections) noexcept
{
    for (const auto& s : sections) {
        if (rva >= s.virtualAddress && (rva - s.virtualAddress) < s.virtualSize) {
            uint32_t delta = rva - s.virtualAddress;
            if (delta < s.sizeOfRawData) {
                return static_cast<size_t>(s.pointerToRawData) + delta;
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

}  // anonymous namespace

// ============================================================================
// Impl Definition
// ============================================================================

struct FeatureExtractor::Impl {
    bool initialized = false;

    std::vector<std::string> suspiciousStrings;

    // Pre-computed FNV-1a hashes of known section names for O(1) lookup.
    std::unordered_set<uint32_t> knownSectionHashes;

    // Maps section-name string to its index in the presence-flag vector.
    std::unordered_map<uint32_t, size_t> sectionNameToIndex;
};

// ============================================================================
// Singleton
// ============================================================================

FeatureExtractor& FeatureExtractor::Instance() noexcept {
    static FeatureExtractor instance;
    return instance;
}

// ============================================================================
// Initialize
// ============================================================================

bool FeatureExtractor::Initialize() noexcept {
    std::lock_guard<std::mutex> lock(m_initMutex);

    if (m_impl && m_impl->initialized) {
        return true;
    }

    try {
        auto impl = std::make_unique<Impl>();

        // Populate suspicious string list.
        impl->suspiciousStrings.reserve(kNumSuspiciousStrings);
        for (size_t i = 0; i < kNumSuspiciousStrings; ++i) {
            impl->suspiciousStrings.emplace_back(kSuspiciousStrings[i]);
        }

        // Build section-name hash maps.
        for (size_t i = 0; i < kNumKnownSectionNames; ++i) {
            const char* name = kKnownSectionNames[i];
            uint32_t h = Utils::HashUtils::Fnv1a32(name, std::strlen(name));
            impl->knownSectionHashes.insert(h);
            impl->sectionNameToIndex[h] = i;
        }

        impl->initialized = true;
        m_impl = std::move(impl);

        SS_LOG_INFO(kLogCategory,
                    L"Initialized — suspicious_strings=%zu, known_sections=%zu",
                    kNumSuspiciousStrings, kNumKnownSectionNames);
        return true;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"Initialization failed: allocation error");
        return false;
    }
}

// ============================================================================
// ExtractPEFeatures  (2381 features, EMBER-aligned)
// ============================================================================

std::optional<std::vector<float>> FeatureExtractor::ExtractPEFeatures(
    std::span<const uint8_t> fileBytes) noexcept
{
    if (!m_impl || !m_impl->initialized) {
        SS_LOG_ERROR(kLogCategory, L"ExtractPEFeatures called before Initialize()");
        return std::nullopt;
    }

    if (fileBytes.empty() || fileBytes.size() > CortexConstants::MAX_PE_FILE_SIZE) {
        SS_LOG_WARN(kLogCategory, L"PE file rejected: size=%zu (max=%zu)",
                    fileBytes.size(), CortexConstants::MAX_PE_FILE_SIZE);
        return std::nullopt;
    }

    PEParser::SafeReader reader(fileBytes);
    const size_t fileSize = fileBytes.size();

    // ---- Validate DOS header ----
    PEParser::DosHeader dosHeader{};
    if (!reader.Read(0, dosHeader)) {
        SS_LOG_WARN(kLogCategory, L"PE too small for DOS header");
        return std::nullopt;
    }
    if (dosHeader.e_magic != PEParser::DOS_SIGNATURE) {
        SS_LOG_WARN(kLogCategory, L"Invalid DOS signature: 0x%04X", dosHeader.e_magic);
        return std::nullopt;
    }
    if (dosHeader.e_lfanew < PEParser::MIN_LFANEW || dosHeader.e_lfanew > PEParser::MAX_LFANEW) {
        SS_LOG_WARN(kLogCategory, L"Invalid e_lfanew: 0x%08X", dosHeader.e_lfanew);
        return std::nullopt;
    }
    const size_t peOffset = static_cast<size_t>(dosHeader.e_lfanew);

    // ---- Validate PE signature ----
    uint32_t peSignature = 0;
    if (!reader.ReadU32LE(peOffset, peSignature) || peSignature != PEParser::NT_SIGNATURE) {
        SS_LOG_WARN(kLogCategory, L"Invalid PE signature at offset 0x%zX", peOffset);
        return std::nullopt;
    }

    // ---- Parse COFF header ----
    const size_t coffOffset = peOffset + 4;
    PEParser::FileHeader coffHeader{};
    if (!reader.Read(coffOffset, coffHeader)) {
        SS_LOG_WARN(kLogCategory, L"Truncated COFF header");
        return std::nullopt;
    }
    if (coffHeader.NumberOfSections > PEParser::Limits::MAX_SECTIONS) {
        SS_LOG_WARN(kLogCategory, L"Section count exceeds limit: %u", coffHeader.NumberOfSections);
        return std::nullopt;
    }

    // ---- Parse Optional header ----
    const size_t optOffset = coffOffset + sizeof(PEParser::FileHeader);
    uint16_t optMagic = 0;
    if (!reader.ReadU16LE(optOffset, optMagic)) {
        SS_LOG_WARN(kLogCategory, L"Cannot read optional header magic");
        return std::nullopt;
    }

    const bool isPE64 = (optMagic == PEParser::PE64_MAGIC);
    const bool isPE32 = (optMagic == PEParser::PE32_MAGIC);
    if (!isPE32 && !isPE64) {
        SS_LOG_WARN(kLogCategory, L"Unknown optional header magic: 0x%04X", optMagic);
        return std::nullopt;
    }

    // Read full optional headers.
    PEParser::OptionalHeader32 opt32{};
    PEParser::OptionalHeader64 opt64{};
    uint32_t numberOfRvaAndSizes = 0;
    uint16_t dllCharacteristics = 0;
    uint16_t subsystem = 0;
    uint32_t sizeOfImage = 0;
    uint64_t imageBase = 0;
    size_t dataDirectoriesOffset = 0;

    if (isPE32) {
        if (!reader.Read(optOffset, opt32)) {
            SS_LOG_WARN(kLogCategory, L"Truncated PE32 optional header");
            return std::nullopt;
        }
        numberOfRvaAndSizes = opt32.NumberOfRvaAndSizes;
        dllCharacteristics = opt32.DllCharacteristics;
        subsystem = opt32.Subsystem;
        sizeOfImage = opt32.SizeOfImage;
        imageBase = opt32.ImageBase;
        dataDirectoriesOffset = optOffset + sizeof(PEParser::OptionalHeader32);
    } else {
        if (!reader.Read(optOffset, opt64)) {
            SS_LOG_WARN(kLogCategory, L"Truncated PE64 optional header");
            return std::nullopt;
        }
        numberOfRvaAndSizes = opt64.NumberOfRvaAndSizes;
        dllCharacteristics = opt64.DllCharacteristics;
        subsystem = opt64.Subsystem;
        sizeOfImage = opt64.SizeOfImage;
        imageBase = opt64.ImageBase;
        dataDirectoriesOffset = optOffset + sizeof(PEParser::OptionalHeader64);
    }

    if (numberOfRvaAndSizes > PEParser::DataDirectory::MAX_ENTRIES) {
        numberOfRvaAndSizes = PEParser::DataDirectory::MAX_ENTRIES;
    }

    // ---- Read data directories ----
    std::array<PEParser::DataDirectoryEntry, 16> dataDirs{};
    for (uint32_t i = 0; i < numberOfRvaAndSizes && i < 16; ++i) {
        if (!reader.Read(dataDirectoriesOffset + i * sizeof(PEParser::DataDirectoryEntry), dataDirs[i])) {
            break;
        }
    }

    // ---- Parse section headers ----
    const size_t sectionTableOffset = optOffset + coffHeader.SizeOfOptionalHeader;
    const uint16_t numSections = coffHeader.NumberOfSections;

    struct SectionEntry {
        std::string name;
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t pointerToRawData;
        uint32_t sizeOfRawData;
        uint32_t characteristics;
        float entropy;
    };

    std::vector<SectionEntry> sections;
    sections.reserve(numSections);
    std::vector<SectionLocator> sectionLocators;
    sectionLocators.reserve(numSections);

    for (uint16_t i = 0; i < numSections; ++i) {
        PEParser::SectionHeader sh{};
        if (!reader.Read(sectionTableOffset + i * sizeof(PEParser::SectionHeader), sh)) {
            break;
        }
        SectionEntry entry;
        entry.name.assign(reinterpret_cast<const char*>(sh.Name),
                          strnlen(reinterpret_cast<const char*>(sh.Name), 8));
        entry.virtualAddress = sh.VirtualAddress;
        entry.virtualSize = sh.VirtualSize;
        entry.pointerToRawData = sh.PointerToRawData;
        entry.sizeOfRawData = sh.SizeOfRawData;
        entry.characteristics = sh.Characteristics;

        // Compute section entropy.
        if (sh.SizeOfRawData > 0 &&
            sh.PointerToRawData < fileSize &&
            sh.SizeOfRawData <= fileSize - sh.PointerToRawData) {
            entry.entropy = ComputeShannonEntropy(
                fileBytes.data() + sh.PointerToRawData, sh.SizeOfRawData);
        } else {
            entry.entropy = 0.0f;
        }

        sections.push_back(std::move(entry));
        sectionLocators.push_back({sh.VirtualAddress, sh.VirtualSize,
                                   sh.PointerToRawData, sh.SizeOfRawData});
    }

    // ========================================================================
    // Allocate and zero-fill feature vector.
    // ========================================================================
    std::vector<float> features(CortexConstants::STATIC_FEATURE_COUNT, 0.0f);

    // ====================================================================
    // GROUP 1: ByteHistogram (256 features, indices 0-255)
    // ====================================================================
    {
        std::array<size_t, 256> counts{};
        for (size_t i = 0; i < fileSize; ++i) {
            ++counts[fileBytes[i]];
        }
        const float invTotal = (fileSize > 0) ? 1.0f / static_cast<float>(fileSize) : 0.0f;
        for (size_t i = 0; i < 256; ++i) {
            features[kByteHistOffset + i] = static_cast<float>(counts[i]) * invTotal;
        }
    }

    // ====================================================================
    // GROUP 2: ByteEntropyHistogram (256 features, indices 256-511)
    // ====================================================================
    {
        std::array<double, kEntropyBins * kByteGroups> jointHist{};
        size_t windowCount = 0;

        for (size_t offset = 0; offset + kEntropyWindowSize <= fileSize;
             offset += kEntropyWindowStep)
        {
            const uint8_t* window = fileBytes.data() + offset;
            const float windowEntropy = ComputeShannonEntropy(window, kEntropyWindowSize);

            // Quantize entropy to bin [0, kEntropyBins-1].
            // Entropy range is [0.0, 8.0]; clamp before quantizing.
            float clampedEntropy = std::clamp(windowEntropy, 0.0f, 8.0f);
            size_t entropyBin = static_cast<size_t>(clampedEntropy * (kEntropyBins / 8.0f));
            if (entropyBin >= kEntropyBins) entropyBin = kEntropyBins - 1;

            // Count byte frequencies in 16 groups within this window.
            std::array<size_t, kByteGroups> groupCounts{};
            for (size_t i = 0; i < kEntropyWindowSize; ++i) {
                groupCounts[window[i] >> 4]++;
            }

            for (size_t g = 0; g < kByteGroups; ++g) {
                jointHist[entropyBin * kByteGroups + g] +=
                    static_cast<double>(groupCounts[g]);
            }
            ++windowCount;
        }

        // Normalize to sum = 1.0
        double totalSum = 0.0;
        for (auto v : jointHist) totalSum += v;
        const double invSum = (totalSum > 0.0) ? 1.0 / totalSum : 0.0;
        for (size_t i = 0; i < kEntropyBins * kByteGroups; ++i) {
            features[kByteEntropyOffset + i] = static_cast<float>(jointHist[i] * invSum);
        }
    }

    // ====================================================================
    // GROUP 3: StringExtractor (104 features, indices 512-615)
    // ====================================================================
    {
        float* sf = &features[kStringOffset];

        // Extract printable ASCII strings of length >= 5.
        std::vector<std::string> extractedStrings;
        extractedStrings.reserve(4096);

        size_t currentRunStart = 0;
        bool inRun = false;

        for (size_t i = 0; i < fileSize && extractedStrings.size() < kMaxStringsCollected; ++i) {
            const uint8_t b = fileBytes[i];
            const bool printable = (b >= 0x20 && b <= 0x7E);
            if (printable) {
                if (!inRun) {
                    currentRunStart = i;
                    inRun = true;
                }
            } else {
                if (inRun) {
                    size_t runLen = i - currentRunStart;
                    if (runLen >= kMinStringLength) {
                        extractedStrings.emplace_back(
                            reinterpret_cast<const char*>(fileBytes.data() + currentRunStart),
                            runLen);
                    }
                    inRun = false;
                }
            }
        }
        // Handle trailing run.
        if (inRun) {
            size_t runLen = fileSize - currentRunStart;
            if (runLen >= kMinStringLength && extractedStrings.size() < kMaxStringsCollected) {
                extractedStrings.emplace_back(
                    reinterpret_cast<const char*>(fileBytes.data() + currentRunStart),
                    runLen);
            }
        }

        size_t idx = 0;
        // [0] numStrings
        sf[idx++] = static_cast<float>(extractedStrings.size());

        // [1] avgStringLength
        {
            double sumLen = 0.0;
            for (const auto& s : extractedStrings) sumLen += static_cast<double>(s.size());
            sf[idx++] = extractedStrings.empty() ? 0.0f
                        : static_cast<float>(sumLen / static_cast<double>(extractedStrings.size()));
        }

        // [2] numURLs
        size_t numURLs = 0;
        // [3] numPaths
        size_t numPaths = 0;
        // [4] numRegistryKeys
        size_t numRegistryKeys = 0;
        // [5] numIPAddresses
        size_t numIPAddresses = 0;
        // [6] numMZHeaders
        size_t numMZHeaders = 0;

        for (const auto& s : extractedStrings) {
            if (s.find("http://") != std::string::npos ||
                s.find("https://") != std::string::npos ||
                s.find("ftp://") != std::string::npos) {
                ++numURLs;
            }
            if (s.find(":\\") != std::string::npos || s.find("/") != std::string::npos) {
                ++numPaths;
            }
            if (s.find("HKLM") != std::string::npos || s.find("HKCU") != std::string::npos ||
                s.find("HKCR") != std::string::npos || s.find("HKU") != std::string::npos ||
                s.find("HKCC") != std::string::npos) {
                ++numRegistryKeys;
            }
            if (s.find("MZ") != std::string::npos) {
                ++numMZHeaders;
            }
            // Simple IP-address heuristic: \d+\.\d+\.\d+\.\d+
            for (size_t p = 0; p < s.size(); ++p) {
                if (s[p] >= '0' && s[p] <= '9') {
                    size_t q = p;
                    bool valid = true;
                    for (int seg = 0; seg < 4 && valid; ++seg) {
                        if (q >= s.size() || s[q] < '0' || s[q] > '9') { valid = false; break; }
                        while (q < s.size() && s[q] >= '0' && s[q] <= '9') ++q;
                        if (seg < 3) {
                            if (q >= s.size() || s[q] != '.') { valid = false; break; }
                            ++q;
                        }
                    }
                    if (valid && q > p) {
                        // Ensure we matched exactly 4 segments.
                        size_t dots = 0;
                        for (size_t k = p; k < q; ++k) {
                            if (s[k] == '.') ++dots;
                        }
                        if (dots == 3) {
                            ++numIPAddresses;
                            p = q - 1; // skip past this match
                        }
                    }
                }
            }
        }
        sf[idx++] = static_cast<float>(numURLs);
        sf[idx++] = static_cast<float>(numPaths);
        sf[idx++] = static_cast<float>(numRegistryKeys);
        sf[idx++] = static_cast<float>(numIPAddresses);
        sf[idx++] = static_cast<float>(numMZHeaders);

        // [7-11] String length histogram: 5 buckets (5-10, 10-20, 20-50, 50-100, 100+)
        std::array<size_t, 5> lenBuckets{};
        for (const auto& s : extractedStrings) {
            size_t len = s.size();
            if      (len < 10)  lenBuckets[0]++;
            else if (len < 20)  lenBuckets[1]++;
            else if (len < 50)  lenBuckets[2]++;
            else if (len < 100) lenBuckets[3]++;
            else                lenBuckets[4]++;
        }
        for (size_t i = 0; i < 5; ++i) {
            sf[idx++] = static_cast<float>(lenBuckets[i]);
        }

        // [12..12+kNumSuspiciousStrings-1] Suspicious string counts
        for (size_t si = 0; si < kNumSuspiciousStrings; ++si) {
            size_t count = 0;
            const auto& needle = m_impl->suspiciousStrings[si];
            for (const auto& s : extractedStrings) {
                if (ContainsCaseInsensitive(s, needle)) {
                    ++count;
                }
            }
            sf[idx++] = static_cast<float>(count);
        }

        // String entropy (average Shannon entropy of all extracted strings)
        {
            double totalEntropy = 0.0;
            for (const auto& s : extractedStrings) {
                totalEntropy += ComputeShannonEntropy(
                    reinterpret_cast<const uint8_t*>(s.data()), s.size());
            }
            sf[idx++] = extractedStrings.empty() ? 0.0f
                        : static_cast<float>(totalEntropy / static_cast<double>(extractedStrings.size()));
        }

        // printableRatio (total printable bytes / file size)
        {
            size_t printableCount = 0;
            for (size_t i = 0; i < fileSize; ++i) {
                if (fileBytes[i] >= 0x20 && fileBytes[i] <= 0x7E) ++printableCount;
            }
            sf[idx++] = (fileSize > 0) ? static_cast<float>(printableCount) / static_cast<float>(fileSize) : 0.0f;
        }
        // Remaining features already zero-padded.
    }

    // ====================================================================
    // GROUP 4: GeneralFileInfo (10 features, indices 616-625)
    // ====================================================================
    {
        float* gf = &features[kGeneralInfoOffset];
        size_t idx = 0;

        // [0] fileSize (log-scaled)
        gf[idx++] = SafeLog(static_cast<double>(fileSize));

        // [1] hasDebug
        gf[idx++] = (dataDirs[PEParser::DataDirectory::DEBUG].Size > 0) ? 1.0f : 0.0f;

        // [2] numExports
        gf[idx++] = static_cast<float>(
            (dataDirs[PEParser::DataDirectory::EXPORT].Size >= sizeof(PEParser::ExportDirectory))
            ? 1.0f : 0.0f);

        // [3] numImports — count import descriptors
        {
            uint32_t importCount = 0;
            if (dataDirs[PEParser::DataDirectory::IMPORT].VirtualAddress != 0 &&
                dataDirs[PEParser::DataDirectory::IMPORT].Size >= sizeof(PEParser::ImportDescriptor))
            {
                auto importFileOff = RvaToFileOffset(
                    dataDirs[PEParser::DataDirectory::IMPORT].VirtualAddress,
                    sectionLocators);
                if (importFileOff.has_value()) {
                    size_t off = importFileOff.value();
                    for (uint32_t d = 0; d < PEParser::Limits::MAX_IMPORT_DESCRIPTORS; ++d) {
                        PEParser::ImportDescriptor desc{};
                        if (!reader.Read(off + d * sizeof(PEParser::ImportDescriptor), desc)) break;
                        if (desc.Name == 0 && desc.FirstThunk == 0) break;
                        ++importCount;
                    }
                }
            }
            gf[idx++] = static_cast<float>(importCount);
        }

        // [4] hasRelocations
        gf[idx++] = (dataDirs[PEParser::DataDirectory::BASERELOC].Size > 0) ? 1.0f : 0.0f;

        // [5] hasResources
        gf[idx++] = (dataDirs[PEParser::DataDirectory::RESOURCE].Size > 0) ? 1.0f : 0.0f;

        // [6] hasSignature (Authenticode)
        gf[idx++] = (dataDirs[PEParser::DataDirectory::SECURITY].Size > 0) ? 1.0f : 0.0f;

        // [7] hasTLS
        gf[idx++] = (dataDirs[PEParser::DataDirectory::TLS].Size > 0) ? 1.0f : 0.0f;

        // [8] numSymbols
        gf[idx++] = static_cast<float>(coffHeader.NumberOfSymbols);

        // [9] virtualSize (SizeOfImage)
        gf[idx++] = SafeLog(static_cast<double>(sizeOfImage));
    }

    // ====================================================================
    // GROUP 5: HeaderFileInfo (62 features, indices 626-687)
    // ====================================================================
    {
        float* hf = &features[kHeaderInfoOffset];
        size_t idx = 0;

        // COFF header fields
        hf[idx++] = static_cast<float>(coffHeader.Machine);
        hf[idx++] = static_cast<float>(coffHeader.NumberOfSections);
        hf[idx++] = static_cast<float>(coffHeader.TimeDateStamp);
        hf[idx++] = static_cast<float>(coffHeader.PointerToSymbolTable);
        hf[idx++] = static_cast<float>(coffHeader.NumberOfSymbols);
        hf[idx++] = static_cast<float>(coffHeader.SizeOfOptionalHeader);

        // COFF Characteristics — expand 16 bits
        for (int bit = 0; bit < 16; ++bit) {
            hf[idx++] = (coffHeader.Characteristics & (1u << bit)) ? 1.0f : 0.0f;
        }

        // Optional header fields
        if (isPE32) {
            hf[idx++] = static_cast<float>(opt32.MajorLinkerVersion);
            hf[idx++] = static_cast<float>(opt32.MinorLinkerVersion);
            hf[idx++] = SafeLog(static_cast<double>(opt32.SizeOfCode));
            hf[idx++] = SafeLog(static_cast<double>(opt32.SizeOfInitializedData));
            hf[idx++] = SafeLog(static_cast<double>(opt32.SizeOfUninitializedData));
            hf[idx++] = SafeLog(static_cast<double>(opt32.AddressOfEntryPoint));
            hf[idx++] = SafeLog(static_cast<double>(opt32.BaseOfCode));
            hf[idx++] = SafeLog(static_cast<double>(opt32.ImageBase));
            hf[idx++] = SafeLog(static_cast<double>(opt32.SectionAlignment));
            hf[idx++] = SafeLog(static_cast<double>(opt32.FileAlignment));
            hf[idx++] = static_cast<float>(opt32.MajorOperatingSystemVersion);
            hf[idx++] = static_cast<float>(opt32.MinorOperatingSystemVersion);
            hf[idx++] = static_cast<float>(opt32.MajorImageVersion);
            hf[idx++] = static_cast<float>(opt32.MinorImageVersion);
            hf[idx++] = static_cast<float>(opt32.MajorSubsystemVersion);
            hf[idx++] = static_cast<float>(opt32.MinorSubsystemVersion);
            hf[idx++] = SafeLog(static_cast<double>(opt32.SizeOfImage));
            hf[idx++] = SafeLog(static_cast<double>(opt32.SizeOfHeaders));
            hf[idx++] = static_cast<float>(opt32.CheckSum);
            hf[idx++] = static_cast<float>(opt32.Subsystem);
        } else {
            hf[idx++] = static_cast<float>(opt64.MajorLinkerVersion);
            hf[idx++] = static_cast<float>(opt64.MinorLinkerVersion);
            hf[idx++] = SafeLog(static_cast<double>(opt64.SizeOfCode));
            hf[idx++] = SafeLog(static_cast<double>(opt64.SizeOfInitializedData));
            hf[idx++] = SafeLog(static_cast<double>(opt64.SizeOfUninitializedData));
            hf[idx++] = SafeLog(static_cast<double>(opt64.AddressOfEntryPoint));
            hf[idx++] = SafeLog(static_cast<double>(opt64.BaseOfCode));
            hf[idx++] = SafeLog(static_cast<double>(opt64.ImageBase));
            hf[idx++] = SafeLog(static_cast<double>(opt64.SectionAlignment));
            hf[idx++] = SafeLog(static_cast<double>(opt64.FileAlignment));
            hf[idx++] = static_cast<float>(opt64.MajorOperatingSystemVersion);
            hf[idx++] = static_cast<float>(opt64.MinorOperatingSystemVersion);
            hf[idx++] = static_cast<float>(opt64.MajorImageVersion);
            hf[idx++] = static_cast<float>(opt64.MinorImageVersion);
            hf[idx++] = static_cast<float>(opt64.MajorSubsystemVersion);
            hf[idx++] = static_cast<float>(opt64.MinorSubsystemVersion);
            hf[idx++] = SafeLog(static_cast<double>(opt64.SizeOfImage));
            hf[idx++] = SafeLog(static_cast<double>(opt64.SizeOfHeaders));
            hf[idx++] = static_cast<float>(opt64.CheckSum);
            hf[idx++] = static_cast<float>(opt64.Subsystem);
        }

        // DllCharacteristics — expand 16 bits (only 11 meaningful but encode all)
        for (int bit = 0; bit < 16; ++bit) {
            hf[idx++] = (dllCharacteristics & (1u << bit)) ? 1.0f : 0.0f;
        }

        // isPE32 / isPE64 flag
        hf[idx++] = isPE64 ? 1.0f : 0.0f;

        // Remaining slots in the 62-feature group are zero-padded.
    }

    // ====================================================================
    // GROUP 6: SectionInfo (255 features, indices 688-942)
    // ====================================================================
    {
        float* secf = &features[kSectionInfoOffset];

        // Per-section features (up to 10 sections × 10 features each).
        const size_t secCount = std::min<size_t>(sections.size(), kMaxSectionsForFeatures);
        for (size_t s = 0; s < secCount; ++s) {
            const auto& sec = sections[s];
            size_t base = s * kFeaturesPerSection;

            // [0] name hash
            uint32_t nameHash = Utils::HashUtils::Fnv1a32(sec.name.data(), sec.name.size());
            secf[base + 0] = static_cast<float>(nameHash) / static_cast<float>(UINT32_MAX);

            // [1] size (log-scaled)
            secf[base + 1] = SafeLog(static_cast<double>(sec.sizeOfRawData));

            // [2] virtualSize (log-scaled)
            secf[base + 2] = SafeLog(static_cast<double>(sec.virtualSize));

            // [3] virtualAddress (log-scaled)
            secf[base + 3] = SafeLog(static_cast<double>(sec.virtualAddress));

            // [4] entropy
            secf[base + 4] = sec.entropy;

            // [5-9] characteristics bits: CODE, INITIALIZED_DATA, UNINIT_DATA, EXECUTE, WRITE
            secf[base + 5] = (sec.characteristics & PEParser::SectionCharacteristics::CNT_CODE) ? 1.0f : 0.0f;
            secf[base + 6] = (sec.characteristics & PEParser::SectionCharacteristics::CNT_INITIALIZED_DATA) ? 1.0f : 0.0f;
            secf[base + 7] = (sec.characteristics & PEParser::SectionCharacteristics::CNT_UNINITIALIZED_DATA) ? 1.0f : 0.0f;
            secf[base + 8] = (sec.characteristics & PEParser::SectionCharacteristics::MEM_EXECUTE) ? 1.0f : 0.0f;
            secf[base + 9] = (sec.characteristics & PEParser::SectionCharacteristics::MEM_WRITE) ? 1.0f : 0.0f;
        }

        // Aggregate statistics starting at offset 100.
        const size_t aggBase = kSectionAggregateStart;
        secf[aggBase + 0] = static_cast<float>(sections.size());

        if (!sections.empty()) {
            float maxEnt = -1.0f, minEnt = 9.0f, sumEnt = 0.0f;
            for (const auto& sec : sections) {
                if (sec.entropy > maxEnt) maxEnt = sec.entropy;
                if (sec.entropy < minEnt) minEnt = sec.entropy;
                sumEnt += sec.entropy;
            }
            const float meanEnt = sumEnt / static_cast<float>(sections.size());

            secf[aggBase + 1] = maxEnt;
            secf[aggBase + 2] = minEnt;
            secf[aggBase + 3] = meanEnt;

            // Std deviation of entropy.
            float sumSqDiff = 0.0f;
            for (const auto& sec : sections) {
                float diff = sec.entropy - meanEnt;
                sumSqDiff += diff * diff;
            }
            secf[aggBase + 4] = std::sqrt(sumSqDiff / static_cast<float>(sections.size()));
        }

        // Section-name presence flags (17 flags starting at aggBase + 5).
        for (const auto& sec : sections) {
            uint32_t nameHash = Utils::HashUtils::Fnv1a32(sec.name.data(), sec.name.size());
            auto it = m_impl->sectionNameToIndex.find(nameHash);
            if (it != m_impl->sectionNameToIndex.end()) {
                secf[aggBase + 5 + it->second] = 1.0f;
            }
        }
        // Remaining features in 255-slot group are zero-padded.
    }

    // ====================================================================
    // GROUP 7: ImportsInfo (1280 features, indices 943-2222)
    // ====================================================================
    {
        float* impf = &features[kImportsInfoOffset];

        if (dataDirs[PEParser::DataDirectory::IMPORT].VirtualAddress != 0 &&
            dataDirs[PEParser::DataDirectory::IMPORT].Size >= sizeof(PEParser::ImportDescriptor))
        {
            auto importFileOff = RvaToFileOffset(
                dataDirs[PEParser::DataDirectory::IMPORT].VirtualAddress,
                sectionLocators);

            if (importFileOff.has_value()) {
                size_t off = importFileOff.value();
                size_t totalImports = 0;

                for (uint32_t d = 0; d < PEParser::Limits::MAX_IMPORT_DESCRIPTORS; ++d) {
                    PEParser::ImportDescriptor desc{};
                    if (!reader.Read(off + d * sizeof(PEParser::ImportDescriptor), desc)) break;
                    if (desc.Name == 0 && desc.FirstThunk == 0) break;

                    // Read DLL name.
                    std::string dllName;
                    auto dllNameOff = RvaToFileOffset(desc.Name, sectionLocators);
                    if (dllNameOff.has_value()) {
                        std::string_view sv;
                        if (reader.ReadString(dllNameOff.value(), PEParser::Limits::MAX_DLL_NAME, sv)) {
                            dllName = sv;
                            // Convert DLL name to lowercase for consistent hashing.
                            for (char& c : dllName) {
                                if (c >= 'A' && c <= 'Z') c += 32;
                            }
                        }
                    }

                    // Walk the thunk table.
                    uint32_t thunkRva = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk : desc.FirstThunk;
                    if (thunkRva == 0) continue;
                    auto thunkFileOff = RvaToFileOffset(thunkRva, sectionLocators);
                    if (!thunkFileOff.has_value()) continue;

                    size_t tOff = thunkFileOff.value();
                    for (uint32_t t = 0; t < PEParser::Limits::MAX_IMPORTS_PER_DLL; ++t) {
                        if (isPE64) {
                            uint64_t thunkVal = 0;
                            if (!reader.ReadU64LE(tOff + t * 8, thunkVal)) break;
                            if (thunkVal == 0) break;
                            if (thunkVal & PEParser::ORDINAL_FLAG64) {
                                // Ordinal import — hash DLL name + ordinal.
                                uint16_t ordinal = static_cast<uint16_t>(thunkVal & 0xFFFF);
                                std::string combined = dllName + ":" + std::to_string(ordinal);
                                uint32_t h = MurmurHash3_x86_32(combined.data(), combined.size(), 0);
                                impf[h % kImportBins] += 1.0f;
                            } else {
                                uint32_t hintNameRva = static_cast<uint32_t>(thunkVal);
                                auto nameOff = RvaToFileOffset(hintNameRva, sectionLocators);
                                if (nameOff.has_value()) {
                                    std::string_view funcName;
                                    // Skip the 2-byte Hint field.
                                    if (reader.ReadString(nameOff.value() + 2, PEParser::Limits::MAX_FUNCTION_NAME, funcName)) {
                                        std::string combined = dllName + ":" + std::string(funcName);
                                        uint32_t h = MurmurHash3_x86_32(combined.data(), combined.size(), 0);
                                        impf[h % kImportBins] += 1.0f;
                                    }
                                }
                            }
                        } else {
                            uint32_t thunkVal = 0;
                            if (!reader.ReadU32LE(tOff + t * 4, thunkVal)) break;
                            if (thunkVal == 0) break;
                            if (thunkVal & PEParser::ORDINAL_FLAG32) {
                                uint16_t ordinal = static_cast<uint16_t>(thunkVal & 0xFFFF);
                                std::string combined = dllName + ":" + std::to_string(ordinal);
                                uint32_t h = MurmurHash3_x86_32(combined.data(), combined.size(), 0);
                                impf[h % kImportBins] += 1.0f;
                            } else {
                                auto nameOff = RvaToFileOffset(thunkVal, sectionLocators);
                                if (nameOff.has_value()) {
                                    std::string_view funcName;
                                    if (reader.ReadString(nameOff.value() + 2, PEParser::Limits::MAX_FUNCTION_NAME, funcName)) {
                                        std::string combined = dllName + ":" + std::string(funcName);
                                        uint32_t h = MurmurHash3_x86_32(combined.data(), combined.size(), 0);
                                        impf[h % kImportBins] += 1.0f;
                                    }
                                }
                            }
                        }
                        ++totalImports;
                        if (totalImports >= PEParser::Limits::MAX_IMPORTS_PER_DLL * PEParser::Limits::MAX_IMPORT_DESCRIPTORS) break;
                    }
                }

                // Normalize import histogram.
                float maxVal = 0.0f;
                for (size_t i = 0; i < kImportBins; ++i) {
                    if (impf[i] > maxVal) maxVal = impf[i];
                }
                if (maxVal > 0.0f) {
                    const float invMax = 1.0f / maxVal;
                    for (size_t i = 0; i < kImportBins; ++i) {
                        impf[i] *= invMax;
                    }
                }
            }
        }
    }

    // ====================================================================
    // GROUP 8: ExportsInfo (128 features, indices 2223-2350)
    // ====================================================================
    {
        float* expf = &features[kExportsInfoOffset];

        if (dataDirs[PEParser::DataDirectory::EXPORT].VirtualAddress != 0 &&
            dataDirs[PEParser::DataDirectory::EXPORT].Size >= sizeof(PEParser::ExportDirectory))
        {
            auto exportFileOff = RvaToFileOffset(
                dataDirs[PEParser::DataDirectory::EXPORT].VirtualAddress,
                sectionLocators);

            if (exportFileOff.has_value()) {
                PEParser::ExportDirectory exportDir{};
                if (reader.Read(exportFileOff.value(), exportDir)) {
                    const uint32_t numNames = std::min<uint32_t>(
                        exportDir.NumberOfNames,
                        static_cast<uint32_t>(PEParser::Limits::MAX_EXPORTS));
                    const uint32_t numFunctions = std::min<uint32_t>(
                        exportDir.NumberOfFunctions,
                        static_cast<uint32_t>(PEParser::Limits::MAX_EXPORTS));

                    // Hash export names into bins [0..125].
                    if (exportDir.AddressOfNames != 0) {
                        auto namesTableOff = RvaToFileOffset(exportDir.AddressOfNames, sectionLocators);
                        if (namesTableOff.has_value()) {
                            for (uint32_t i = 0; i < numNames; ++i) {
                                uint32_t nameRva = 0;
                                if (!reader.ReadU32LE(namesTableOff.value() + i * 4, nameRva)) break;
                                auto nameOff = RvaToFileOffset(nameRva, sectionLocators);
                                if (nameOff.has_value()) {
                                    std::string_view funcName;
                                    if (reader.ReadString(nameOff.value(), PEParser::Limits::MAX_FUNCTION_NAME, funcName)) {
                                        uint32_t h = MurmurHash3_x86_32(funcName.data(), funcName.size(), 0);
                                        expf[h % (kExportBins - 2)] += 1.0f;
                                    }
                                }
                            }
                        }
                    }

                    // [126] export count
                    expf[kExportBins - 2] = static_cast<float>(numFunctions);

                    // [127] has ordinal-only exports (functions without names)
                    expf[kExportBins - 1] = (numFunctions > numNames) ? 1.0f : 0.0f;

                    // Normalize hash bins.
                    float maxVal = 0.0f;
                    for (size_t i = 0; i < kExportBins - 2; ++i) {
                        if (expf[i] > maxVal) maxVal = expf[i];
                    }
                    if (maxVal > 0.0f) {
                        const float invMax = 1.0f / maxVal;
                        for (size_t i = 0; i < kExportBins - 2; ++i) {
                            expf[i] *= invMax;
                        }
                    }
                }
            }
        }
    }

    // ====================================================================
    // GROUP 9: DataDirectories (30 features, indices 2351-2380)
    // ====================================================================
    {
        float* ddf = &features[kDataDirOffset];
        const float invFileSize = (fileSize > 0) ? 1.0f / static_cast<float>(fileSize) : 0.0f;

        for (uint32_t i = 0; i < 15 && i < numberOfRvaAndSizes; ++i) {
            ddf[i * 2 + 0] = SafeLog(static_cast<double>(dataDirs[i].VirtualAddress));
            ddf[i * 2 + 1] = static_cast<float>(dataDirs[i].Size) * invFileSize;
        }
    }

    return features;
}

// ============================================================================
// ExtractBehavioralFeatures  (512 features)
// ============================================================================

std::optional<std::vector<float>> FeatureExtractor::ExtractBehavioralFeatures(
    std::span<const APICallRecord> apiCalls) noexcept
{
    if (!m_impl || !m_impl->initialized) {
        SS_LOG_ERROR(kLogCategory, L"ExtractBehavioralFeatures called before Initialize()");
        return std::nullopt;
    }

    if (apiCalls.empty()) {
        SS_LOG_WARN(kLogCategory, L"Empty API call sequence");
        return std::nullopt;
    }

    // Truncate to most recent MAX_API_SEQUENCE_LENGTH calls.
    if (apiCalls.size() > CortexConstants::MAX_API_SEQUENCE_LENGTH) {
        apiCalls = apiCalls.last(CortexConstants::MAX_API_SEQUENCE_LENGTH);
    }

    std::vector<float> features(CortexConstants::BEHAVIORAL_FEATURE_COUNT, 0.0f);

    // Take the most recent kBehavioralCalls (128) calls for the feature vector.
    // If more than 128, take the last 128.
    const size_t startIdx = (apiCalls.size() > kBehavioralCalls)
                            ? apiCalls.size() - kBehavioralCalls
                            : 0;
    const size_t count = std::min<size_t>(apiCalls.size(), kBehavioralCalls);

    constexpr float kHashNorm = 1.0f / static_cast<float>(UINT32_MAX);
    constexpr float kRetValScale = 1.0f / static_cast<float>(INT32_MAX);

    for (size_t i = 0; i < count; ++i) {
        const auto& call = apiCalls[startIdx + i];
        const size_t base = i * kFeaturesPerCall;

        // [0] apiNameHash normalized to [0,1]
        features[base + 0] = static_cast<float>(call.apiNameHash) * kHashNorm;

        // [1] argSummaryHash normalized to [0,1]
        features[base + 1] = static_cast<float>(call.argSummaryHash) * kHashNorm;

        // [2] returnValue normalized to [-1,1]
        features[base + 2] = std::clamp(
            static_cast<float>(call.returnValue) * kRetValScale, -1.0f, 1.0f);

        // [3] timestampDeltaMs log-scaled
        features[base + 3] = SafeLog1p(call.timestampDeltaMs);
    }

    return features;
}

// ============================================================================
// ExtractMemoryFeatures  (256 features)
// ============================================================================

std::optional<std::vector<float>> FeatureExtractor::ExtractMemoryFeatures(
    const MemoryRegionInfo& region) noexcept
{
    if (!m_impl || !m_impl->initialized) {
        SS_LOG_ERROR(kLogCategory, L"ExtractMemoryFeatures called before Initialize()");
        return std::nullopt;
    }

    if (region.data.empty()) {
        SS_LOG_WARN(kLogCategory, L"Empty memory region");
        return std::nullopt;
    }

    if (region.data.size() > CortexConstants::MAX_MEMORY_REGION_SIZE) {
        SS_LOG_WARN(kLogCategory, L"Memory region exceeds limit: %zu bytes", region.data.size());
        return std::nullopt;
    }

    const uint8_t* data = region.data.data();
    const size_t dataSize = region.data.size();

    std::vector<float> features(CortexConstants::MEMORY_FEATURE_COUNT, 0.0f);
    size_t idx = 0;

    // ---- Byte histogram (full 256-bin), compressed to 32 bins ----
    {
        std::array<size_t, 256> counts{};
        for (size_t i = 0; i < dataSize; ++i) {
            ++counts[data[i]];
        }
        const float invSize = 1.0f / static_cast<float>(dataSize);
        for (size_t bin = 0; bin < kMemCompressedBins; ++bin) {
            float sum = 0.0f;
            for (size_t j = 0; j < 8; ++j) {
                sum += static_cast<float>(counts[bin * 8 + j]) * invSize;
            }
            features[idx++] = sum / 8.0f;
        }
    }

    // ---- Shannon entropy ----
    features[idx++] = ComputeShannonEntropy(data, dataSize);

    // ---- Instruction density (heuristic: count common x86 opcode first bytes) ----
    {
        // Common single-byte x86 opcode prefixes that begin valid instructions.
        static constexpr bool kValidOpcodes[256] = {
            // 0x00-0x0F: ADD, OR
            1,1,1,1,1,1,0,0, 1,1,1,1,1,1,0,0,
            // 0x10-0x1F: ADC, SBB
            1,1,1,1,1,1,0,0, 1,1,1,1,1,1,0,0,
            // 0x20-0x2F: AND, SUB
            1,1,1,1,1,1,0,0, 1,1,1,1,1,1,0,0,
            // 0x30-0x3F: XOR, CMP
            1,1,1,1,1,1,0,0, 1,1,1,1,1,1,0,0,
            // 0x40-0x4F: INC/DEC (32-bit) or REX (64-bit)
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0x50-0x5F: PUSH/POP
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0x60-0x6F: PUSHAD/POPAD/BOUND/ARPL/PUSH/IMUL/PUSH/IMUL/INS/OUTS
            1,1,1,1,0,0,0,0, 1,1,1,1,1,1,1,1,
            // 0x70-0x7F: Jcc short
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0x80-0x8F: group 1 / MOV / LEA / POP
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0x90-0x9F: NOP/XCHG/CBW/CWD/CALL/WAIT/PUSHF/POPF/SAHF/LAHF
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0xA0-0xAF: MOV/MOVS/CMPS/STOS/LODS/SCAS
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0xB0-0xBF: MOV imm
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0xC0-0xCF: shifts/RET/LES/LDS/MOV/ENTER/LEAVE/RET/INT/INTO/IRET
            1,1,1,1,0,0,1,1, 1,1,1,1,1,1,1,1,
            // 0xD0-0xDF: shifts/AAM/AAD/XLAT/FPU
            1,1,1,1,0,0,0,0, 1,1,1,1,1,1,1,1,
            // 0xE0-0xEF: LOOP/JCXZ/IN/OUT/CALL/JMP
            1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
            // 0xF0-0xFF: LOCK/REPNE/REP/HLT/CMC/group3/CLC/STC/CLI/STI/CLD/STD/group4/group5
            1,0,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
        };

        size_t validCount = 0;
        for (size_t i = 0; i < dataSize; ++i) {
            if (kValidOpcodes[data[i]]) ++validCount;
        }
        features[idx++] = static_cast<float>(validCount) / static_cast<float>(dataSize);
    }

    // ---- NOP sled score ----
    {
        size_t maxNopRun = 0;
        size_t currentNopRun = 0;
        for (size_t i = 0; i < dataSize; ++i) {
            if (data[i] == 0x90) {
                ++currentNopRun;
                if (currentNopRun > maxNopRun) maxNopRun = currentNopRun;
            } else {
                currentNopRun = 0;
            }
        }
        features[idx++] = static_cast<float>(maxNopRun) / static_cast<float>(dataSize);
    }

    // ---- Null byte ratio ----
    {
        size_t nullCount = 0;
        for (size_t i = 0; i < dataSize; ++i) {
            if (data[i] == 0x00) ++nullCount;
        }
        features[idx++] = static_cast<float>(nullCount) / static_cast<float>(dataSize);
    }

    // ---- Printable char ratio ----
    {
        size_t printable = 0;
        for (size_t i = 0; i < dataSize; ++i) {
            if (data[i] >= 0x20 && data[i] <= 0x7E) ++printable;
        }
        features[idx++] = static_cast<float>(printable) / static_cast<float>(dataSize);
    }

    // ---- Alignment pattern score ----
    {
        // Measure how often 4-byte-aligned addresses contain non-zero values.
        size_t alignedNonZero = 0;
        size_t alignedCount = 0;
        for (size_t i = 0; i < dataSize; i += 4) {
            ++alignedCount;
            if (data[i] != 0x00) ++alignedNonZero;
        }
        features[idx++] = (alignedCount > 0)
            ? static_cast<float>(alignedNonZero) / static_cast<float>(alignedCount)
            : 0.0f;
    }

    // ---- ROP gadget density (0xC3=RET, 0xCB=RETF, 0xC2=RET imm16) ----
    {
        size_t gadgetCount = 0;
        for (size_t i = 0; i < dataSize; ++i) {
            if (data[i] == 0xC3 || data[i] == 0xCB || data[i] == 0xC2) {
                ++gadgetCount;
            }
        }
        features[idx++] = static_cast<float>(gadgetCount) / static_cast<float>(dataSize);
    }

    // ---- Compression ratio estimate (byte repetition) ----
    {
        std::array<size_t, 256> counts{};
        for (size_t i = 0; i < dataSize; ++i) ++counts[data[i]];
        size_t uniqueBytes = 0;
        for (auto c : counts) {
            if (c > 0) ++uniqueBytes;
        }
        features[idx++] = static_cast<float>(uniqueBytes) / 256.0f;
    }

    // ---- Protection flags (4 bits: R, W, X, G) ----
    {
        // Windows protection constants:
        // PAGE_READONLY=0x02, PAGE_READWRITE=0x04, PAGE_EXECUTE=0x10
        // PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40, PAGE_GUARD=0x100
        uint32_t prot = region.protection;
        bool r = (prot & 0x02) || (prot & 0x04) || (prot & 0x20) || (prot & 0x40);
        bool w = (prot & 0x04) || (prot & 0x08) || (prot & 0x40) || (prot & 0x80);
        bool x = (prot & 0x10) || (prot & 0x20) || (prot & 0x40) || (prot & 0x80);
        bool g = (prot & 0x100) != 0;
        features[idx++] = r ? 1.0f : 0.0f;
        features[idx++] = w ? 1.0f : 0.0f;
        features[idx++] = x ? 1.0f : 0.0f;
        features[idx++] = g ? 1.0f : 0.0f;
    }

    // ---- Top 100 bigram frequencies ----
    {
        // Count all bigrams, then pick top 100 by frequency.
        // For performance, use a flat 65536-entry array.
        if (dataSize >= 2) {
            std::vector<uint32_t> bigramCounts(65536, 0);
            for (size_t i = 0; i + 1 < dataSize; ++i) {
                uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
                ++bigramCounts[bigram];
            }

            // Partial sort to find top 100.
            std::vector<std::pair<uint32_t, uint16_t>> indexed;
            indexed.reserve(65536);
            for (uint32_t i = 0; i < 65536; ++i) {
                if (bigramCounts[i] > 0) {
                    indexed.push_back({bigramCounts[i], static_cast<uint16_t>(i)});
                }
            }

            const size_t topN = std::min<size_t>(indexed.size(), kMemBigramFeatures);
            std::partial_sort(indexed.begin(), indexed.begin() + topN, indexed.end(),
                [](const auto& a, const auto& b) { return a.first > b.first; });

            const float invBigrams = 1.0f / static_cast<float>(dataSize - 1);
            for (size_t i = 0; i < topN; ++i) {
                features[idx + i] = static_cast<float>(indexed[i].first) * invBigrams;
            }
        }
        idx += kMemBigramFeatures;
    }

    // ---- Block entropy statistics (256-byte blocks) ----
    {
        const size_t numBlocks = dataSize / kMemBlockSize;
        if (numBlocks > 0) {
            std::vector<float> blockEntropies;
            blockEntropies.reserve(numBlocks);
            for (size_t b = 0; b < numBlocks; ++b) {
                blockEntropies.push_back(ComputeShannonEntropy(
                    data + b * kMemBlockSize, kMemBlockSize));
            }

            float minE = blockEntropies[0], maxE = blockEntropies[0];
            double sumE = 0.0;
            for (float e : blockEntropies) {
                if (e < minE) minE = e;
                if (e > maxE) maxE = e;
                sumE += e;
            }
            const float meanE = static_cast<float>(sumE / blockEntropies.size());

            double varSum = 0.0;
            for (float e : blockEntropies) {
                double d = e - meanE;
                varSum += d * d;
            }
            const float stdE = static_cast<float>(std::sqrt(varSum / blockEntropies.size()));

            // Quartiles via sorted copy.
            std::sort(blockEntropies.begin(), blockEntropies.end());
            float q25 = blockEntropies[blockEntropies.size() / 4];
            float median = blockEntropies[blockEntropies.size() / 2];
            float q75 = blockEntropies[blockEntropies.size() * 3 / 4];

            features[idx + 0] = minE;
            features[idx + 1] = maxE;
            features[idx + 2] = meanE;
            features[idx + 3] = stdE;
            features[idx + 4] = q25;
            features[idx + 5] = median;
            features[idx + 6] = q75;
            features[idx + 7] = maxE - minE; // range
        }
        idx += kMemBlockEntropyStats;
    }

    // Remaining features are zero-padded to MEMORY_FEATURE_COUNT.
    return features;
}

// ============================================================================
// ExtractNetworkFeatures  (128 features)
// ============================================================================

std::optional<std::vector<float>> FeatureExtractor::ExtractNetworkFeatures(
    const NetworkFlowInfo& flow) noexcept
{
    if (!m_impl || !m_impl->initialized) {
        SS_LOG_ERROR(kLogCategory, L"ExtractNetworkFeatures called before Initialize()");
        return std::nullopt;
    }

    std::vector<float> features(CortexConstants::NETWORK_FEATURE_COUNT, 0.0f);
    size_t idx = 0;

    // ---- Address encoding ----
    features[idx++] = static_cast<float>(flow.srcIPv4) / static_cast<float>(UINT32_MAX);
    features[idx++] = static_cast<float>(flow.dstIPv4) / static_cast<float>(UINT32_MAX);
    features[idx++] = static_cast<float>(flow.srcPort) / 65535.0f;
    features[idx++] = static_cast<float>(flow.dstPort) / 65535.0f;

    // ---- Protocol one-hot (TCP=6, UDP=17, DNS=53port, HTTP=80, HTTPS=443, Other) ----
    {
        size_t protoIdx = 5; // default: Other
        if (flow.protocol == 6)  protoIdx = 0; // TCP
        else if (flow.protocol == 17) protoIdx = 1; // UDP

        // Refine by port for application-layer protocols.
        if (flow.dstPort == 53 || flow.srcPort == 53) protoIdx = 2; // DNS
        else if (flow.dstPort == 80 || flow.srcPort == 80) protoIdx = 3; // HTTP
        else if (flow.dstPort == 443 || flow.srcPort == 443) protoIdx = 4; // HTTPS

        for (size_t i = 0; i < kProtocolOneHotSize; ++i) {
            features[idx++] = (i == protoIdx) ? 1.0f : 0.0f;
        }
    }

    // ---- Volume features (log-scaled) ----
    features[idx++] = SafeLog1p(static_cast<float>(flow.bytesSent));
    features[idx++] = SafeLog1p(static_cast<float>(flow.bytesReceived));
    features[idx++] = SafeLog1p(static_cast<float>(flow.packetsSent));
    features[idx++] = SafeLog1p(static_cast<float>(flow.packetsReceived));

    // Byte ratio (sent / total)
    {
        const double totalBytes = static_cast<double>(flow.bytesSent) + static_cast<double>(flow.bytesReceived);
        features[idx++] = (totalBytes > 0.0)
            ? static_cast<float>(static_cast<double>(flow.bytesSent) / totalBytes)
            : 0.0f;
    }
    // Packet ratio (sent / total)
    {
        const double totalPackets = static_cast<double>(flow.packetsSent) + static_cast<double>(flow.packetsReceived);
        features[idx++] = (totalPackets > 0.0)
            ? static_cast<float>(static_cast<double>(flow.packetsSent) / totalPackets)
            : 0.0f;
    }

    // Average bytes per packet (sent direction).
    features[idx++] = (flow.packetsSent > 0)
        ? SafeLog1p(static_cast<float>(flow.bytesSent) / static_cast<float>(flow.packetsSent))
        : 0.0f;
    // Average bytes per packet (recv direction).
    features[idx++] = (flow.packetsReceived > 0)
        ? SafeLog1p(static_cast<float>(flow.bytesReceived) / static_cast<float>(flow.packetsReceived))
        : 0.0f;

    // ---- Timing features ----
    features[idx++] = SafeLog1p(flow.durationMs);
    features[idx++] = SafeLog1p(flow.avgInterArrivalMs);
    features[idx++] = SafeLog1p(flow.stdInterArrivalMs);
    features[idx++] = SafeLog1p(flow.minInterArrivalMs);
    features[idx++] = SafeLog1p(flow.maxInterArrivalMs);

    // ---- TLS / DNS fingerprinting ----
    features[idx++] = static_cast<float>(flow.ja3Hash) / static_cast<float>(UINT32_MAX);
    features[idx++] = static_cast<float>(flow.ja3sHash) / static_cast<float>(UINT32_MAX);
    features[idx++] = static_cast<float>(flow.dnsQueryHash) / static_cast<float>(UINT32_MAX);
    features[idx++] = SafeLog1p(static_cast<float>(flow.dnsQueryCount));
    features[idx++] = static_cast<float>(flow.tlsVersion) / 65535.0f;

    // ---- Payload statistics ----
    features[idx++] = flow.payloadEntropy;
    features[idx++] = static_cast<float>(flow.uniquePayloadBytes) / 256.0f;

    // ---- Beaconing regularity ----
    // Coefficient of variation of inter-arrival times.
    // Low CV = regular beaconing pattern.
    {
        float beaconScore = 0.0f;
        if (flow.avgInterArrivalMs > 0.0f) {
            beaconScore = flow.stdInterArrivalMs / flow.avgInterArrivalMs;
            beaconScore = std::clamp(beaconScore, 0.0f, 10.0f) / 10.0f;
        }
        features[idx++] = beaconScore;

        // Regularity metric: 1 - CV (capped)
        features[idx++] = 1.0f - beaconScore;

        // Max-to-min ratio of inter-arrival times.
        float interArrivalRange = flow.maxInterArrivalMs - flow.minInterArrivalMs;
        features[idx++] = SafeLog1p(interArrivalRange);
    }

    // ---- Packets-per-second ----
    features[idx++] = (flow.durationMs > 0.0f)
        ? SafeLog1p(static_cast<float>(
            (static_cast<double>(flow.packetsSent) + static_cast<double>(flow.packetsReceived))
            * 1000.0 / static_cast<double>(flow.durationMs)))
        : 0.0f;

    // ---- Bytes-per-second ----
    features[idx++] = (flow.durationMs > 0.0f)
        ? SafeLog1p(static_cast<float>(
            (static_cast<double>(flow.bytesSent) + static_cast<double>(flow.bytesReceived))
            * 1000.0 / static_cast<double>(flow.durationMs)))
        : 0.0f;

    // Remaining features are zero-padded to NETWORK_FEATURE_COUNT.
    return features;
}

// ============================================================================
// ExtractEmulationFeatures  (384 features)
// ============================================================================

std::optional<std::vector<float>> FeatureExtractor::ExtractEmulationFeatures(
    std::span<const EmulationEvent> events) noexcept
{
    if (!m_impl || !m_impl->initialized) {
        SS_LOG_ERROR(kLogCategory, L"ExtractEmulationFeatures called before Initialize()");
        return std::nullopt;
    }

    if (events.empty()) {
        SS_LOG_WARN(kLogCategory, L"Empty emulation trace");
        return std::nullopt;
    }

    std::vector<float> features(CortexConstants::EMULATION_FEATURE_COUNT, 0.0f);
    size_t idx = 0;
    const size_t numEvents = events.size();
    const float invEvents = 1.0f / static_cast<float>(numEvents);

    // ---- Opcode category histogram (16 categories) ----
    {
        std::array<uint32_t, kOpcodeCategories> opHist{};
        for (const auto& ev : events) {
            uint16_t cat = ev.opcodeCategory;
            if (cat < kOpcodeCategories) ++opHist[cat];
        }
        for (size_t i = 0; i < kOpcodeCategories; ++i) {
            features[idx++] = static_cast<float>(opHist[i]) * invEvents;
        }
    }

    // ---- Memory access pattern histogram (4 types) ----
    {
        std::array<uint32_t, kMemAccessTypes> memHist{};
        for (const auto& ev : events) {
            uint8_t t = ev.memoryAccessType;
            if (t < kMemAccessTypes) ++memHist[t];
        }
        for (size_t i = 0; i < kMemAccessTypes; ++i) {
            features[idx++] = static_cast<float>(memHist[i]) * invEvents;
        }
    }

    // ---- API call frequency histogram (top 100 APIs by ID) ----
    {
        std::unordered_map<uint16_t, uint32_t> apiCounts;
        for (const auto& ev : events) {
            if (ev.apiCallId != 0) {
                ++apiCounts[ev.apiCallId];
            }
        }

        std::vector<std::pair<uint32_t, uint16_t>> sorted;
        sorted.reserve(apiCounts.size());
        for (const auto& [id, cnt] : apiCounts) {
            sorted.push_back({cnt, id});
        }
        std::partial_sort(sorted.begin(),
                          sorted.begin() + std::min<size_t>(sorted.size(), kTopAPIs),
                          sorted.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });

        const size_t topN = std::min<size_t>(sorted.size(), kTopAPIs);
        for (size_t i = 0; i < topN; ++i) {
            features[idx + i] = static_cast<float>(sorted[i].first) * invEvents;
        }
        idx += kTopAPIs;
    }

    // ---- EFLAGS change histogram (8 bits) ----
    {
        std::array<uint32_t, kEflagsBits> efHist{};
        for (const auto& ev : events) {
            for (size_t bit = 0; bit < kEflagsBits; ++bit) {
                if (ev.eflagsChange & (1u << bit)) ++efHist[bit];
            }
        }
        for (size_t i = 0; i < kEflagsBits; ++i) {
            features[idx++] = static_cast<float>(efHist[i]) * invEvents;
        }
    }

    // ---- Sequence n-grams: opcode category bigrams + trigrams ----
    {
        // Build bigram and trigram histograms using feature hashing into
        // kNgramFeatures (128) bins. First 64 for bigrams, last 64 for trigrams.
        constexpr size_t kBigramBins = 64;
        constexpr size_t kTrigramBins = 64;

        if (numEvents >= 2) {
            for (size_t i = 0; i + 1 < numEvents; ++i) {
                uint16_t a = events[i].opcodeCategory % kOpcodeCategories;
                uint16_t b = events[i + 1].opcodeCategory % kOpcodeCategories;
                uint32_t bigramKey = (static_cast<uint32_t>(a) << 16) | b;
                uint32_t h = MurmurHash3_x86_32(&bigramKey, sizeof(bigramKey), 42);
                features[idx + h % kBigramBins] += invEvents;
            }
        }
        idx += kBigramBins;

        if (numEvents >= 3) {
            for (size_t i = 0; i + 2 < numEvents; ++i) {
                uint16_t a = events[i].opcodeCategory % kOpcodeCategories;
                uint16_t b = events[i + 1].opcodeCategory % kOpcodeCategories;
                uint16_t c = events[i + 2].opcodeCategory % kOpcodeCategories;
                uint64_t trigramKey = (static_cast<uint64_t>(a) << 32)
                                    | (static_cast<uint64_t>(b) << 16) | c;
                uint32_t h = MurmurHash3_x86_32(&trigramKey, sizeof(trigramKey), 42);
                features[idx + h % kTrigramBins] += invEvents;
            }
        }
        idx += kTrigramBins;
    }

    // ---- Temporal features: instruction mix over time windows ----
    {
        // Divide the trace into kTemporalFeatures (128) windows and encode
        // the dominant opcode category fraction per window.
        const size_t windowSize = std::max<size_t>(1, numEvents / kTemporalFeatures);

        for (size_t w = 0; w < kTemporalFeatures; ++w) {
            const size_t wStart = w * windowSize;
            if (wStart >= numEvents) break;
            const size_t wEnd = std::min(wStart + windowSize, numEvents);
            const size_t wLen = wEnd - wStart;

            std::array<uint32_t, kOpcodeCategories> localHist{};
            for (size_t i = wStart; i < wEnd; ++i) {
                uint16_t cat = events[i].opcodeCategory;
                if (cat < kOpcodeCategories) ++localHist[cat];
            }

            // Dominant category fraction as the feature.
            uint32_t maxCount = *std::max_element(localHist.begin(), localHist.end());
            features[idx + w] = static_cast<float>(maxCount) / static_cast<float>(wLen);
        }
        idx += kTemporalFeatures;
    }

    // Remaining features are zero-padded to EMULATION_FEATURE_COUNT.
    return features;
}

}  // namespace AI
}  // namespace ShadowStrike
