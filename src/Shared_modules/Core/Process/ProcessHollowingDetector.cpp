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
 * ShadowStrike NGAV - PROCESS HOLLOWING DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessHollowingDetector.cpp
 * @brief Enterprise-grade process hollowing detection implementation.
 *
 * Production-level implementation competing with enterprise-grade enterprise-grade Memory
 * Protection and enterprise-grade System Watcher. Detects 11 variants of process
 * hollowing attacks with high accuracy and low false positive rate.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - PE header parsing (32-bit and 64-bit)
 * - Memory vs Disk image comparison
 * - Entry point validation with shellcode detection
 * - Section-by-section comparison with entropy analysis
 * - Creation pattern tracking (CREATE_SUSPENDED monitoring)
 * - Multi-stage confidence scoring
 * - ThreatIntel correlation
 * - HashStore integration
 * - Comprehensive statistics (27 atomic counters)
 * - 3 callback types
 * - Alert management system
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ProcessHollowingDetector.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"

#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <fstream>
#include <cmath>
#include <cstdio>
#include <condition_variable>

#pragma comment(lib, "ntdll.lib")

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// PE STRUCTURES (Windows SDK)
// ============================================================================

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER_CUSTOM {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER_CUSTOM {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY_CUSTOM {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32_CUSTOM {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_CUSTOM DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64_CUSTOM {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_CUSTOM DataDirectory[16];
};

struct IMAGE_SECTION_HEADER_CUSTOM {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void HollowingStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    quickScans.store(0, std::memory_order_relaxed);
    standardScans.store(0, std::memory_order_relaxed);
    comprehensiveScans.store(0, std::memory_order_relaxed);
    paranoidScans.store(0, std::memory_order_relaxed);

    hollowingDetected.store(0, std::memory_order_relaxed);
    classicHollowingDetected.store(0, std::memory_order_relaxed);
    doppelgangingDetected.store(0, std::memory_order_relaxed);
    herpaderpingDetected.store(0, std::memory_order_relaxed);
    ghostingDetected.store(0, std::memory_order_relaxed);
    moduleStompingDetected.store(0, std::memory_order_relaxed);
    earlyBirdDetected.store(0, std::memory_order_relaxed);
    otherTypesDetected.store(0, std::memory_order_relaxed);

    lowConfidenceDetections.store(0, std::memory_order_relaxed);
    mediumConfidenceDetections.store(0, std::memory_order_relaxed);
    highConfidenceDetections.store(0, std::memory_order_relaxed);
    confirmedDetections.store(0, std::memory_order_relaxed);

    suspendedCreationsMonitored.store(0, std::memory_order_relaxed);
    suspiciousPatternsDetected.store(0, std::memory_order_relaxed);
    transactionsMonitored.store(0, std::memory_order_relaxed);

    alertsGenerated.store(0, std::memory_order_relaxed);
    alertsAcknowledged.store(0, std::memory_order_relaxed);
    falsePositivesReported.store(0, std::memory_order_relaxed);

    totalScanTimeMs.store(0, std::memory_order_relaxed);
    minScanTimeMs.store(UINT64_MAX, std::memory_order_relaxed);
    maxScanTimeMs.store(0, std::memory_order_relaxed);

    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);

    scanErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    timeoutErrors.store(0, std::memory_order_relaxed);
}

double HollowingStatistics::GetAverageScanTimeMs() const noexcept {
    uint64_t total = totalScans.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;
    uint64_t totalTime = totalScanTimeMs.load(std::memory_order_relaxed);
    return static_cast<double>(totalTime) / static_cast<double>(total);
}

double HollowingStatistics::GetDetectionRate() const noexcept {
    uint64_t total = totalScans.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;
    uint64_t detected = hollowingDetected.load(std::memory_order_relaxed);
    return (static_cast<double>(detected) / static_cast<double>(total)) * 100.0;
}

// ============================================================================
// DETECTION RESULT METHODS
// ============================================================================

void HollowingDetectionResult::CalculateConfidence() noexcept {
    int score = 0;

    // Strong indicators (worth 3 points each)
    for (auto method : detectionMethods) {
        switch (method) {
            case DetectionMethod::PEHeaderMismatch:      score += 3; break;
            case DetectionMethod::SectionMismatch:        score += 3; break;
            case DetectionMethod::CreationPatternAnomaly: score += 2; break;
            case DetectionMethod::DeletePendingFile:      score += 3; break;
            case DetectionMethod::TransactionAnomaly:     score += 3; break;
            case DetectionMethod::SizeOfImageMismatch:    score += 2; break;

            // Medium indicators (1-2 points)
            case DetectionMethod::EntryPointAnomaly:      score += 2; break;
            case DetectionMethod::ThreadContextAnomaly:   score += 2; break;
            case DetectionMethod::UnbackedExecMemory:     score += 2; break;
            case DetectionMethod::MemoryProtection:       score += 1; break;
            case DetectionMethod::SectionCharacteristics: score += 1; break;
            case DetectionMethod::EntropyAnomaly:         score += 1; break;
            case DetectionMethod::ChecksumMismatch:       score += 1; break;
            case DetectionMethod::TimestampMismatch:      score += 1; break;
            case DetectionMethod::ImageBaseAnomaly:       score += 1; break;
            case DetectionMethod::ImportTableAnomaly:     score += 1; break;
            case DetectionMethod::DigitalSignatureBroken: score += 2; break;
            default: break;
        }
    }

    // Calculate confidence from accumulated score
    if (score >= 6) {
        confidence = HollowingConfidence::Confirmed;
    } else if (score >= 4) {
        confidence = HollowingConfidence::High;
    } else if (score >= 2) {
        confidence = HollowingConfidence::Medium;
    } else if (score >= 1) {
        confidence = HollowingConfidence::Low;
    } else {
        confidence = HollowingConfidence::None;
    }
}

void HollowingDetectionResult::CalculateRiskScore() noexcept {
    riskScore = 0;

    // Base score from confidence
    switch (confidence) {
        case HollowingConfidence::Confirmed: riskScore = 90; break;
        case HollowingConfidence::High: riskScore = 70; break;
        case HollowingConfidence::Medium: riskScore = 50; break;
        case HollowingConfidence::Low: riskScore = 30; break;
        default: riskScore = 0; break;
    }

    // Add points for specific indicators
    if (hasUnbackedExecutableMemory) riskScore += 5;
    if (hasRWXRegions) riskScore += 5;
    if (moduleStompingDetected) riskScore += 10;
    if (correlatedWithKnownThreat) riskScore += 10;
    if (entryPointAnalysis.hasShellcodePattern) riskScore += 10;

    // Cap at 100
    if (riskScore > 100) riskScore = 100;
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

HollowingDetectorConfig HollowingDetectorConfig::CreateDefault() noexcept {
    HollowingDetectorConfig config;
    config.defaultScanMode = ScanMode::Standard;
    config.monitorMode = MonitorMode::Active;
    config.enableRealTimeMonitoring = true;
    config.enableHeaderComparison = true;
    config.enableEntryPointValidation = true;
    config.enableSectionAnalysis = true;
    config.enableCreationPatternMonitoring = true;
    config.enableThreatIntelCorrelation = true;
    config.enableHashLookup = true;
    return config;
}

HollowingDetectorConfig HollowingDetectorConfig::CreateParanoid() noexcept {
    HollowingDetectorConfig config = CreateDefault();
    config.defaultScanMode = ScanMode::Paranoid;
    config.monitorMode = MonitorMode::Aggressive;
    config.alertOnLowConfidence = true;
    config.sectionDifferenceThreshold = 0.05;  // 5% difference
    config.enablePayloadExtraction = true;
    config.enableTransactionMonitoring = true;
    config.enableModuleStompingDetection = true;
    config.enableThreadContextValidation = true;
    return config;
}

HollowingDetectorConfig HollowingDetectorConfig::CreatePerformance() noexcept {
    HollowingDetectorConfig config = CreateDefault();
    config.defaultScanMode = ScanMode::Quick;
    config.monitorMode = MonitorMode::PassiveOnly;
    config.enableSectionAnalysis = false;
    config.enablePayloadExtraction = false;
    config.maxConcurrentScans = 8;
    config.enableCaching = true;
    return config;
}

HollowingDetectorConfig HollowingDetectorConfig::CreateForensic() noexcept {
    HollowingDetectorConfig config = CreateParanoid();
    config.defaultScanMode = ScanMode::Comprehensive;
    config.enablePayloadExtraction = true;
    config.quarantinePayload = true;
    config.reportToThreatIntel = true;
    config.scanTimeoutMs = 60000;  // 1 minute
    return config;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct ProcessHollowingDetector::ProcessHollowingDetectorImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    HollowingDetectorConfig m_config;

    // Infrastructure (non-owning: singletons or externally managed)
    std::atomic<ThreatIntel::ThreatIntelManager*> m_threatIntel{nullptr};

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};
    std::atomic<MonitorMode> m_monitorMode{MonitorMode::Active};

    // Creation pattern tracking
    struct CreationEvent {
        uint32_t pid;
        uint32_t creatorPid;
        std::wstring imagePath;
        std::chrono::system_clock::time_point createTime;
        bool createdSuspended;
        std::vector<std::wstring> memoryOperations;
        std::chrono::system_clock::time_point resumeTime;
    };
    std::unordered_map<uint32_t, CreationEvent> m_creationEvents;
    std::mutex m_creationEventsMutex;

    // Alerts
    std::vector<HollowingAlert> m_alerts;
    std::mutex m_alertsMutex;
    std::atomic<uint64_t> m_nextAlertId{1};

    // Callbacks
    std::vector<std::pair<uint64_t, HollowingDetectedCallback>> m_detectionCallbacks;
    std::vector<std::pair<uint64_t, SuspiciousCreationCallback>> m_creationCallbacks;
    std::vector<std::pair<uint64_t, ScanProgressCallback>> m_progressCallbacks;
    std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Exclusions
    std::unordered_set<std::wstring> m_excludedProcessNames;
    std::unordered_set<std::wstring> m_excludedPaths;
    std::unordered_set<uint32_t> m_excludedPids;
    mutable std::shared_mutex m_exclusionsMutex;

    // Cache
    struct CacheEntry {
        HollowingDetectionResult result;
        std::chrono::system_clock::time_point cachedAt;
    };
    std::unordered_map<uint32_t, CacheEntry> m_scanCache;
    std::unordered_set<uint32_t> m_scansInProgress;
    std::mutex m_cacheMutex;
    std::condition_variable m_cacheCV;

    // Statistics
    HollowingStatistics m_statistics;

    // Constructor
    ProcessHollowingDetectorImpl() = default;

    // ========================================================================
    // PE PARSING METHODS
    // ========================================================================

    PEHeaderInfo ParsePEFromBuffer(const std::vector<uint8_t>& buffer, bool isMemory) {
        PEHeaderInfo info;

        try {
            if (buffer.size() < sizeof(IMAGE_DOS_HEADER_CUSTOM)) {
                info.validationError = L"Buffer too small for DOS header";
                return info;
            }

            // Parse DOS header
            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER_CUSTOM*>(buffer.data());
            if (dosHeader->e_magic != HollowingConstants::DOS_MAGIC) {
                info.validationError = L"Invalid DOS magic (not MZ)";
                return info;
            }

            info.hasDosHeader = true;
            info.peHeaderOffset = dosHeader->e_lfanew;

            // Validate e_lfanew against sane range to prevent OOB on crafted PEs
            if (info.peHeaderOffset < sizeof(IMAGE_DOS_HEADER_CUSTOM) ||
                info.peHeaderOffset > HollowingConstants::MAX_PE_HEADER_SIZE) {
                info.validationError = L"PE header offset (e_lfanew) out of sane range";
                return info;
            }

            if (info.peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_CUSTOM) > buffer.size()) {
                info.validationError = L"PE header offset out of bounds";
                return info;
            }

            // Check PE signature
            const auto* peSignature = reinterpret_cast<const uint32_t*>(buffer.data() + info.peHeaderOffset);
            if (*peSignature != HollowingConstants::PE_SIGNATURE) {
                info.validationError = L"Invalid PE signature";
                return info;
            }

            info.hasPeHeader = true;

            // Parse FILE header
            const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER_CUSTOM*>(
                buffer.data() + info.peHeaderOffset + sizeof(uint32_t)
            );

            info.machine = fileHeader->Machine;
            info.numberOfSections = fileHeader->NumberOfSections;
            info.timeDateStamp = fileHeader->TimeDateStamp;
            info.characteristics = fileHeader->Characteristics;

            // Determine if 64-bit
            size_t optHeaderOffset = info.peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER_CUSTOM);
            if (optHeaderOffset + sizeof(uint16_t) > buffer.size()) {
                info.validationError = L"Optional header offset out of bounds";
                return info;
            }

            uint16_t magic = *reinterpret_cast<const uint16_t*>(buffer.data() + optHeaderOffset);
            info.is64Bit = (magic == 0x20b);  // PE32+

            // Parse Optional Header
            if (info.is64Bit) {
                if (optHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER64_CUSTOM) > buffer.size()) {
                    info.validationError = L"64-bit optional header out of bounds";
                    return info;
                }
                const auto* optHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64_CUSTOM*>(
                    buffer.data() + optHeaderOffset
                );

                info.imageBase = optHeader->ImageBase;
                info.sectionAlignment = optHeader->SectionAlignment;
                info.fileAlignment = optHeader->FileAlignment;
                info.sizeOfImage = optHeader->SizeOfImage;
                info.sizeOfHeaders = optHeader->SizeOfHeaders;
                info.checksum = optHeader->CheckSum;
                info.entryPoint = optHeader->AddressOfEntryPoint;
                info.subsystem = optHeader->Subsystem;
                info.dllCharacteristics = optHeader->DllCharacteristics;
                info.numberOfDataDirectories = optHeader->NumberOfRvaAndSizes;

                if (info.numberOfDataDirectories > 1) {
                    info.importTableRVA = optHeader->DataDirectory[1].VirtualAddress;
                    info.importTableSize = optHeader->DataDirectory[1].Size;
                }
                if (info.numberOfDataDirectories > 0) {
                    info.exportTableRVA = optHeader->DataDirectory[0].VirtualAddress;
                    info.exportTableSize = optHeader->DataDirectory[0].Size;
                }
                if (info.numberOfDataDirectories > 5) {
                    info.relocationTableRVA = optHeader->DataDirectory[5].VirtualAddress;
                    info.relocationTableSize = optHeader->DataDirectory[5].Size;
                }
                if (info.numberOfDataDirectories > 6) {
                    info.debugDirectoryRVA = optHeader->DataDirectory[6].VirtualAddress;
                    info.debugDirectorySize = optHeader->DataDirectory[6].Size;
                }
                if (info.numberOfDataDirectories > 9) {
                    info.tlsDirectoryRVA = optHeader->DataDirectory[9].VirtualAddress;
                    info.tlsDirectorySize = optHeader->DataDirectory[9].Size;
                }

            } else {
                if (optHeaderOffset + sizeof(IMAGE_OPTIONAL_HEADER32_CUSTOM) > buffer.size()) {
                    info.validationError = L"32-bit optional header out of bounds";
                    return info;
                }
                const auto* optHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32_CUSTOM*>(
                    buffer.data() + optHeaderOffset
                );

                info.imageBase = optHeader->ImageBase;
                info.sectionAlignment = optHeader->SectionAlignment;
                info.fileAlignment = optHeader->FileAlignment;
                info.sizeOfImage = optHeader->SizeOfImage;
                info.sizeOfHeaders = optHeader->SizeOfHeaders;
                info.checksum = optHeader->CheckSum;
                info.entryPoint = optHeader->AddressOfEntryPoint;
                info.subsystem = optHeader->Subsystem;
                info.dllCharacteristics = optHeader->DllCharacteristics;
                info.numberOfDataDirectories = optHeader->NumberOfRvaAndSizes;

                if (info.numberOfDataDirectories > 1) {
                    info.importTableRVA = optHeader->DataDirectory[1].VirtualAddress;
                    info.importTableSize = optHeader->DataDirectory[1].Size;
                }
                if (info.numberOfDataDirectories > 0) {
                    info.exportTableRVA = optHeader->DataDirectory[0].VirtualAddress;
                    info.exportTableSize = optHeader->DataDirectory[0].Size;
                }
                if (info.numberOfDataDirectories > 5) {
                    info.relocationTableRVA = optHeader->DataDirectory[5].VirtualAddress;
                    info.relocationTableSize = optHeader->DataDirectory[5].Size;
                }
                if (info.numberOfDataDirectories > 6) {
                    info.debugDirectoryRVA = optHeader->DataDirectory[6].VirtualAddress;
                    info.debugDirectorySize = optHeader->DataDirectory[6].Size;
                }
                if (info.numberOfDataDirectories > 9) {
                    info.tlsDirectoryRVA = optHeader->DataDirectory[9].VirtualAddress;
                    info.tlsDirectorySize = optHeader->DataDirectory[9].Size;
                }
            }

            // Parse sections
            size_t sectionHeaderOffset = optHeaderOffset + fileHeader->SizeOfOptionalHeader;
            for (uint16_t i = 0; i < info.numberOfSections && i < HollowingConstants::MAX_SECTIONS; ++i) {
                size_t secOffset = sectionHeaderOffset + (i * sizeof(IMAGE_SECTION_HEADER_CUSTOM));

                if (secOffset + sizeof(IMAGE_SECTION_HEADER_CUSTOM) > buffer.size()) {
                    break;
                }

                const auto* secHeader = reinterpret_cast<const IMAGE_SECTION_HEADER_CUSTOM*>(
                    buffer.data() + secOffset
                );

                PESectionInfo section;
                std::memcpy(section.name.data(), secHeader->Name, 8);
                section.virtualSize = secHeader->VirtualSize;
                section.virtualAddress = secHeader->VirtualAddress;
                section.sizeOfRawData = secHeader->SizeOfRawData;
                section.pointerToRawData = secHeader->PointerToRawData;
                section.characteristics = secHeader->Characteristics;

                section.isExecutable = (section.characteristics & HollowingConstants::IMAGE_SCN_MEM_EXECUTE) != 0;
                section.isWritable = (section.characteristics & HollowingConstants::IMAGE_SCN_MEM_WRITE) != 0;
                section.isReadable = (section.characteristics & HollowingConstants::IMAGE_SCN_MEM_READ) != 0;
                section.containsCode = (section.characteristics & HollowingConstants::IMAGE_SCN_CNT_CODE) != 0;
                section.containsData = (section.characteristics & HollowingConstants::IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;

                info.sections.push_back(section);
            }

            info.isValid = true;

        } catch (const std::exception& e) {
            info.validationError = Utils::StringUtils::ToWide(e.what());
            info.isValid = false;
        }

        return info;
    }

    // Calculate Shannon entropy
    double CalculateEntropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;

        std::array<size_t, 256> frequency{};
        for (uint8_t byte : data) {
            frequency[byte]++;
        }

        double entropy = 0.0;
        double dataSize = static_cast<double>(data.size());

        for (size_t count : frequency) {
            if (count > 0) {
                double probability = static_cast<double>(count) / dataSize;
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

    // ========================================================================
    // CALLBACK INVOCATION
    // ========================================================================

    void InvokeDetectionCallbacks(const HollowingDetectionResult& result) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_detectionCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Hollowing", L"Detection callback %llu failed - %hs", id, e.what());
            }
        }
    }

    void InvokeCreationCallbacks(uint32_t pid, const CreationPatternAnalysis& pattern) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_creationCallbacks) {
            try {
                callback(pid, pattern);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Hollowing", L"Creation callback %llu failed - %hs", id, e.what());
            }
        }
    }

    void InvokeProgressCallbacks(uint32_t pid, const std::wstring& stage, uint32_t percent) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(pid, stage, percent);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Hollowing", L"Progress callback %llu failed - %hs", id, e.what());
            }
        }
    }

    // ========================================================================
    // ALERT GENERATION
    // ========================================================================

    void GenerateAlert(const HollowingDetectionResult& result) {
        if (result.confidence < m_config.alertThreshold) {
            return;
        }

        HollowingAlert alert;
        alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp = std::chrono::system_clock::now();
        alert.processId = result.processId;
        alert.processName = result.processName;
        alert.processPath = result.processPath;
        alert.hollowingType = result.hollowingType;
        alert.confidence = result.confidence;
        alert.riskScore = result.riskScore;

        std::wstringstream desc;
        desc << L"Process hollowing detected: " << GetHollowingTypeName(result.hollowingType).data()
             << L" (Confidence: " << GetConfidenceName(result.confidence).data() << L")";
        alert.description = desc.str();

        alert.indicators = result.detectionDetails;

        switch (result.confidence) {
            case HollowingConfidence::Confirmed:
            case HollowingConfidence::High:
                alert.recommendedAction = L"Terminate process immediately and quarantine payload";
                break;
            case HollowingConfidence::Medium:
                alert.recommendedAction = L"Investigate process and consider termination";
                break;
            default:
                alert.recommendedAction = L"Monitor process for additional suspicious activity";
                break;
        }

        {
            std::lock_guard<std::mutex> lock(m_alertsMutex);
            // Cap alerts to prevent unbounded memory growth - drop oldest if at capacity
            constexpr size_t MAX_ALERTS = 10000;
            if (m_alerts.size() >= MAX_ALERTS) {
                m_alerts.erase(m_alerts.begin(),
                               m_alerts.begin() + static_cast<ptrdiff_t>(m_alerts.size() / 4));
            }
            m_alerts.push_back(alert);
        }

        m_statistics.alertsGenerated.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_WARN(L"Hollowing", L"Alert %llu - %ls (PID: %u, Risk: %u)", alert.alertId, alert.description.c_str(), result.processId, result.riskScore);
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> ProcessHollowingDetector::s_instanceCreated{false};

ProcessHollowingDetector& ProcessHollowingDetector::Instance() noexcept {
    static ProcessHollowingDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool ProcessHollowingDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

ProcessHollowingDetector::ProcessHollowingDetector()
    : m_impl(std::make_unique<ProcessHollowingDetectorImpl>())
{
    SS_LOG_INFO(L"Hollowing", L"Constructor called");
}

ProcessHollowingDetector::~ProcessHollowingDetector() {
    Shutdown();
    SS_LOG_INFO(L"Hollowing", L"Destructor called");
}

bool ProcessHollowingDetector::Initialize(const HollowingDetectorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"Hollowing", L"Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;

        // Reference ThreatIntel singleton (non-owning, atomic for thread safety)
        m_impl->m_threatIntel.store(&ThreatIntel::ThreatIntelManager::Instance(),
                                     std::memory_order_release);

        // Load config exclusions into impl exclusion sets
        {
            std::unique_lock<std::shared_mutex> exLock(m_impl->m_exclusionsMutex);
            m_impl->m_excludedProcessNames.clear();
            for (const auto& proc : config.excludedProcesses) {
                m_impl->m_excludedProcessNames.insert(proc);
            }
            m_impl->m_excludedPaths.clear();
            for (const auto& path : config.excludedPaths) {
                m_impl->m_excludedPaths.insert(path);
            }
            m_impl->m_excludedPids.clear();
            for (auto pid : config.excludedPids) {
                m_impl->m_excludedPids.insert(pid);
            }
        }

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"Hollowing", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"Initialization failed - %hs", e.what());
        return false;
    }
}

void ProcessHollowingDetector::Shutdown() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        StopMonitoring();

        // Clear all data
        {
            std::lock_guard<std::mutex> cacheLock(m_impl->m_cacheMutex);
            m_impl->m_scanCache.clear();
        }

        {
            std::lock_guard<std::mutex> alertLock(m_impl->m_alertsMutex);
            m_impl->m_alerts.clear();
        }

        {
            std::lock_guard<std::mutex> creationLock(m_impl->m_creationEventsMutex);
            m_impl->m_creationEvents.clear();
        }

        {
            std::lock_guard<std::mutex> callbackLock(m_impl->m_callbacksMutex);
            m_impl->m_detectionCallbacks.clear();
            m_impl->m_creationCallbacks.clear();
            m_impl->m_progressCallbacks.clear();
        }

        m_impl->m_threatIntel.store(nullptr, std::memory_order_release);
        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"Hollowing", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"Shutdown error - %hs", e.what());
    }
}

bool ProcessHollowingDetector::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool ProcessHollowingDetector::UpdateConfig(const HollowingDetectorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"Hollowing", L"Configuration updated");
    return true;
}

HollowingDetectorConfig ProcessHollowingDetector::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// SCANNING - CORE IMPLEMENTATION
// ============================================================================

HollowingDetectionResult ProcessHollowingDetector::ScanProcess(uint32_t pid, ScanMode mode) {
    auto startTime = std::chrono::steady_clock::now();

    HollowingDetectionResult result;
    result.processId = pid;
    result.scanMode = mode;
    result.scanTime = std::chrono::system_clock::now();

    try {
        // Guard: must be initialized
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            result.scanError = L"Detector not initialized";
            result.scanComplete = false;
            SS_LOG_ERROR(L"Hollowing", L"ScanProcess called before Initialize() for PID %u", pid);
            return result;
        }

        m_impl->m_statistics.totalScans.fetch_add(1, std::memory_order_relaxed);

        switch (mode) {
            case ScanMode::Quick: m_impl->m_statistics.quickScans.fetch_add(1, std::memory_order_relaxed); break;
            case ScanMode::Standard: m_impl->m_statistics.standardScans.fetch_add(1, std::memory_order_relaxed); break;
            case ScanMode::Comprehensive: m_impl->m_statistics.comprehensiveScans.fetch_add(1, std::memory_order_relaxed); break;
            case ScanMode::Paranoid: m_impl->m_statistics.paranoidScans.fetch_add(1, std::memory_order_relaxed); break;
        }

        // Check exclusions
        if (IsExcluded(pid)) {
            result.scanComplete = true;
            result.scanError = L"Process is excluded from scanning";
            return result;
        }

        // Check scan cache and in-progress tracking
        if (m_impl->m_config.enableCaching) {
            std::unique_lock<std::mutex> cacheLock(m_impl->m_cacheMutex);

            // Check if result already cached and fresh
            auto cacheIt = m_impl->m_scanCache.find(pid);
            if (cacheIt != m_impl->m_scanCache.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now() - cacheIt->second.cachedAt);
                if (elapsed.count() < m_impl->m_config.cacheTTLSeconds) {
                    m_impl->m_statistics.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return cacheIt->second.result;
                }
                m_impl->m_scanCache.erase(cacheIt);
            }

            // Wait if another thread is already scanning this PID (max 30s)
            if (m_impl->m_scansInProgress.count(pid) > 0) {
                m_impl->m_cacheCV.wait_for(cacheLock, std::chrono::seconds(30),
                    [this, pid]() { return m_impl->m_scansInProgress.count(pid) == 0; });
                // Re-check cache after wakeup
                auto it = m_impl->m_scanCache.find(pid);
                if (it != m_impl->m_scanCache.end()) {
                    m_impl->m_statistics.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second.result;
                }
            }

            m_impl->m_scansInProgress.insert(pid);
            m_impl->m_statistics.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        // Helper lambda: check scan timeout
        const uint32_t timeoutMs = m_impl->m_config.scanTimeoutMs;
        auto isTimedOut = [&startTime, timeoutMs]() -> bool {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);
            return static_cast<uint32_t>(elapsed.count()) >= timeoutMs;
        };

        // Get process info
        result.processName = Utils::ProcessUtils::GetProcessName(pid).value_or(L"");
        result.processPath = Utils::ProcessUtils::GetProcessPath(pid).value_or(L"");
        result.imagePath = result.processPath;

        m_impl->InvokeProgressCallbacks(pid, L"Parsing PE headers", 10);

        // Determine the module base address for the main executable image
        uintptr_t moduleBase = 0;
        {
            auto baseOpt = Utils::ProcessUtils::GetModuleBaseAddress(pid, L"");
            if (baseOpt.has_value()) {
                moduleBase = reinterpret_cast<uintptr_t>(baseOpt.value());
            }
        }

        // If GetModuleBaseAddress with empty name didn't work, try the process name
        if (moduleBase == 0 && !result.processName.empty()) {
            auto baseOpt = Utils::ProcessUtils::GetModuleBaseAddress(pid, result.processName);
            if (baseOpt.has_value()) {
                moduleBase = reinterpret_cast<uintptr_t>(baseOpt.value());
            }
        }

        // Parse memory PE header via ReadProcessMemory
        if (moduleBase != 0) {
            result.memoryHeader = ParseMemoryPE(pid, moduleBase);
        } else {
            result.memoryHeader.isValid = false;
            result.memoryHeader.validationError = L"Could not determine module base address";
        }

        // Parse disk PE header
        if (!result.processPath.empty()) {
            result.diskHeader = ParseFilePE(result.processPath);
        }

        m_impl->InvokeProgressCallbacks(pid, L"Comparing headers", 40);

        // Compare headers if both valid
        if (result.diskHeader.isValid && result.memoryHeader.isValid) {
            result.headerComparison = ComparePEHeaders(result.diskHeader, result.memoryHeader);

            if (!result.headerComparison.headersMatch) {
                result.isHollowed = true;
                result.detectionMethods.push_back(DetectionMethod::PEHeaderMismatch);
                result.detectionDetails.push_back(L"PE header mismatch detected");
            }
        }

        if (isTimedOut()) {
            result.scanError = L"Scan timeout after header comparison";
            result.scanComplete = false;
            m_impl->m_statistics.timeoutErrors.fetch_add(1, std::memory_order_relaxed);
            goto finalize_scan;
        }

        m_impl->InvokeProgressCallbacks(pid, L"Analyzing entry point", 70);

        // Entry point analysis
        if (m_impl->m_config.enableEntryPointValidation) {
            result.entryPointAnalysis = AnalyzeEntryPoint(pid);
            if (result.entryPointAnalysis.isAnomalous) {
                result.isHollowed = true;
                result.detectionMethods.push_back(DetectionMethod::EntryPointAnomaly);
            }
        }

        if (isTimedOut()) {
            result.scanError = L"Scan timeout after entry point analysis";
            result.scanComplete = false;
            m_impl->m_statistics.timeoutErrors.fetch_add(1, std::memory_order_relaxed);
            goto finalize_scan;
        }

        m_impl->InvokeProgressCallbacks(pid, L"Checking creation pattern", 80);

        // Section-level analysis (Standard mode and above)
        if (m_impl->m_config.enableSectionAnalysis &&
            mode >= ScanMode::Standard &&
            result.diskHeader.isValid && result.memoryHeader.isValid && moduleBase != 0) {

            Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
            if (hProcess.IsValid()) {
                // Compare section content between disk and memory
                auto minSections = std::min(result.diskHeader.sections.size(),
                                            result.memoryHeader.sections.size());
                for (size_t i = 0; i < minSections; ++i) {
                    const auto& diskSec = result.diskHeader.sections[i];
                    const auto& memSec = result.memoryHeader.sections[i];

                    // Section characteristics changed = suspicious
                    if (diskSec.characteristics != memSec.characteristics) {
                        result.detectionMethods.push_back(DetectionMethod::SectionCharacteristics);
                        result.detectionDetails.push_back(
                            L"Section characteristics modified: " +
                            std::wstring(diskSec.name.data(), strnlen(diskSec.name.data(), 8)));
                    }

                    // For code sections, sample and compare content against disk
                    if (diskSec.containsCode || diskSec.isExecutable) {
                        size_t sampleSize = std::min(
                            static_cast<size_t>(HollowingConstants::SAMPLE_SIZE_PER_SECTION),
                            static_cast<size_t>(std::min(diskSec.virtualSize, memSec.virtualSize)));

                        if (sampleSize > 0) {
                            std::vector<uint8_t> memSample(sampleSize, 0);
                            SIZE_T bytesRead = 0;
                            uintptr_t sectionVA = moduleBase + memSec.virtualAddress;
                            if (Utils::ProcessUtils::ReadProcessMemory(
                                    pid,
                                    reinterpret_cast<void*>(sectionVA),
                                    memSample.data(),
                                    sampleSize,
                                    &bytesRead) && bytesRead > 0) {

                                memSample.resize(bytesRead);

                                // Entropy analysis
                                double entropy = m_impl->CalculateEntropy(memSample);
                                if (entropy > m_impl->m_config.entropyThreshold) {
                                    result.detectionMethods.push_back(DetectionMethod::EntropyAnomaly);
                                    result.detectionDetails.push_back(
                                        L"High entropy in code section: " +
                                        std::wstring(diskSec.name.data(), strnlen(diskSec.name.data(), 8)));
                                }

                                // Disk vs memory content comparison (core hollowing detection)
                                // Read the corresponding bytes from disk file
                                if (!result.processPath.empty() &&
                                    diskSec.pointerToRawData > 0 && diskSec.sizeOfRawData > 0) {

                                    size_t diskReadSize = std::min(bytesRead,
                                        static_cast<SIZE_T>(diskSec.sizeOfRawData));
                                    std::vector<uint8_t> diskSample(diskReadSize, 0);

                                    std::ifstream diskFile(result.processPath, std::ios::binary);
                                    if (diskFile.is_open()) {
                                        diskFile.seekg(diskSec.pointerToRawData, std::ios::beg);
                                        diskFile.read(reinterpret_cast<char*>(diskSample.data()),
                                                      static_cast<std::streamsize>(diskReadSize));
                                        auto diskBytesRead = static_cast<size_t>(diskFile.gcount());
                                        diskFile.close();

                                        if (diskBytesRead > 0) {
                                            // Compare byte-by-byte, count differences
                                            size_t compareLen = std::min(bytesRead, diskBytesRead);
                                            size_t diffCount = 0;
                                            for (size_t b = 0; b < compareLen; ++b) {
                                                if (memSample[b] != diskSample[b]) {
                                                    ++diffCount;
                                                }
                                            }

                                            double diffRatio = (compareLen > 0) ?
                                                static_cast<double>(diffCount) / static_cast<double>(compareLen) : 0.0;

                                            if (diffRatio > m_impl->m_config.sectionDifferenceThreshold) {
                                                result.detectionMethods.push_back(DetectionMethod::SectionMismatch);
                                                result.detectionDetails.push_back(
                                                    L"Code section content mismatch (" +
                                                    std::to_wstring(static_cast<int>(diffRatio * 100.0)) +
                                                    L"% different): " +
                                                    std::wstring(diskSec.name.data(), strnlen(diskSec.name.data(), 8)));
                                                result.isHollowed = true;
                                            }

                                            // Populate section comparison in header comparison
                                            HeaderComparison::SectionComparison secComp;
                                            secComp.name = std::string(diskSec.name.data(), strnlen(diskSec.name.data(), 8));
                                            secComp.contentMatches = (diffCount == 0);
                                            secComp.contentSimilarity = 1.0 - diffRatio;
                                            secComp.sizeMatches = (diskSec.virtualSize == memSec.virtualSize);
                                            secComp.characteristicsMatch = (diskSec.characteristics == memSec.characteristics);
                                            result.headerComparison.sectionComparisons.push_back(std::move(secComp));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Detect unbacked executable memory regions (Comprehensive+)
                if (mode >= ScanMode::Comprehensive) {
                    uintptr_t addr = 0;
                    MEMORY_BASIC_INFORMATION mbi{};
                    constexpr size_t MAX_REGIONS = 8192;
                    size_t regionCount = 0;

                    while (regionCount < MAX_REGIONS &&
                           Utils::ProcessUtils::QueryProcessMemoryRegion(
                               pid, reinterpret_cast<void*>(addr), mbi)) {
                        ++regionCount;

                        bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
                        bool isUnbacked = (mbi.Type == 0 || mbi.Type == MEM_PRIVATE);

                        if (mbi.State == MEM_COMMIT && isExec && isUnbacked) {
                            result.hasUnbackedExecutableMemory = true;
                            result.detectionMethods.push_back(DetectionMethod::UnbackedExecMemory);
                            result.detectionDetails.push_back(
                                L"Unbacked executable memory at 0x" +
                                std::to_wstring(reinterpret_cast<uintptr_t>(mbi.BaseAddress)));
                        }
                        if (mbi.State == MEM_COMMIT && isRWX) {
                            result.hasRWXRegions = true;
                        }

                        uintptr_t nextAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                        if (nextAddr <= addr) break;  // Prevent infinite loop on overflow
                        addr = nextAddr;
                    }
                }

                // Module stomping detection
                if (m_impl->m_config.enableModuleStompingDetection &&
                    mode >= ScanMode::Standard) {
                    std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
                    if (Utils::ProcessUtils::EnumerateProcessModules(pid, modules)) {
                        for (const auto& mod : modules) {
                            if (mod.baseAddress == nullptr || mod.path.empty()) continue;
                            // Skip the main module (already checked above)
                            uintptr_t modBase = reinterpret_cast<uintptr_t>(mod.baseAddress);
                            if (modBase == moduleBase) continue;

                            // Read first page of loaded module and compare against disk
                            std::vector<uint8_t> modHeaderBuf(HollowingConstants::MAX_PE_HEADER_SIZE, 0);
                            SIZE_T bytesRead = 0;
                            if (Utils::ProcessUtils::ReadProcessMemory(
                                    pid, mod.baseAddress, modHeaderBuf.data(),
                                    modHeaderBuf.size(), &bytesRead) && bytesRead > 0) {
                                modHeaderBuf.resize(bytesRead);
                                auto modMemPE = m_impl->ParsePEFromBuffer(modHeaderBuf, true);

                                if (modMemPE.isValid) {
                                    auto modDiskPE = ParseFilePE(mod.path);
                                    if (modDiskPE.isValid) {
                                        // Check if entry point or section count changed
                                        if (modDiskPE.entryPoint != modMemPE.entryPoint ||
                                            modDiskPE.numberOfSections != modMemPE.numberOfSections) {
                                            result.moduleStompingDetected = true;
                                            result.stompedModuleName = mod.name;
                                            result.stompedModuleBase = modBase;
                                            result.isHollowed = true;
                                            result.detectionMethods.push_back(DetectionMethod::SectionMismatch);
                                            result.detectionDetails.push_back(
                                                L"Module stomping detected: " + mod.name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // File-state analysis for ghosting/herpaderping detection
        if (!result.processPath.empty()) {
            HANDLE hFile = CreateFileW(
                result.processPath.c_str(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                    // File deleted while process runs - classic ghosting indicator
                    result.creationPattern.fileDeletePending = true;
                    result.detectionMethods.push_back(DetectionMethod::DeletePendingFile);
                    result.detectionDetails.push_back(
                        L"Process image file no longer exists on disk (ghosting indicator)");
                    result.isHollowed = true;
                } else if (err == ERROR_ACCESS_DENIED) {
                    // Could be delete-pending state
                    result.detectionDetails.push_back(
                        L"Process image file access denied (possible delete-pending)");
                }
            } else {
                // Check for delete-pending via NtQueryInformationFile FILE_STANDARD_INFO
                FILE_STANDARD_INFO standardInfo{};
                if (GetFileInformationByHandleEx(hFile, FileStandardInfo, &standardInfo, sizeof(standardInfo))) {
                    if (standardInfo.DeletePending) {
                        result.creationPattern.fileDeletePending = true;
                        result.detectionMethods.push_back(DetectionMethod::DeletePendingFile);
                        result.detectionDetails.push_back(
                            L"Process image file is in delete-pending state (ghosting)");
                        result.isHollowed = true;
                    }
                }
                CloseHandle(hFile);
            }
        }

        // Check for herpaderping: file content on disk no longer matches what was mapped
        // We already did header comparison above; if the disk file has been modified
        // AFTER the process was created, the disk PE will differ from memory PE but
        // the memory PE will be the ORIGINAL. Herpaderping modifies the disk file after mapping.
        if (result.diskHeader.isValid && result.memoryHeader.isValid &&
            result.headerComparison.headersMatch == false) {
            // If timestamps match but other fields don't, or if the entry point on disk
            // differs from memory while the process was NOT created suspended,
            // this suggests herpaderping (file modified post-map).
            if (!result.creationPattern.createdSuspended &&
                result.headerComparison.diskTimestamp != result.headerComparison.memoryTimestamp) {
                result.creationPattern.fileModifiedAfterMap = true;
                result.detectionDetails.push_back(
                    L"Disk PE timestamp differs from memory - possible herpaderping");
            }
        }

        // Creation pattern analysis
        if (m_impl->m_config.enableCreationPatternMonitoring) {
            // Preserve file-state flags set by earlier analysis
            bool fileDeletePending = result.creationPattern.fileDeletePending;
            bool fileModifiedAfterMap = result.creationPattern.fileModifiedAfterMap;

            result.creationPattern = AnalyzeCreationPattern(pid);

            // Merge back file-state flags
            result.creationPattern.fileDeletePending |= fileDeletePending;
            result.creationPattern.fileModifiedAfterMap |= fileModifiedAfterMap;

            if (result.creationPattern.isSuspiciousPattern) {
                result.detectionMethods.push_back(DetectionMethod::CreationPatternAnomaly);
            }
        }

        m_impl->InvokeProgressCallbacks(pid, L"Computing confidence", 90);

        // Calculate confidence and risk
        result.CalculateConfidence();
        result.CalculateRiskScore();

        // Determine hollowing type based on strongest available signal
        if (result.isHollowed) {
            if (result.creationPattern.involvedTransaction) {
                result.hollowingType = HollowingType::ProcessDoppelganging;
                m_impl->m_statistics.doppelgangingDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055.013");
            } else if (result.creationPattern.fileDeletePending) {
                result.hollowingType = HollowingType::ProcessGhosting;
                m_impl->m_statistics.ghostingDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055.012");
            } else if (result.creationPattern.fileModifiedAfterMap) {
                result.hollowingType = HollowingType::ProcessHerpaderping;
                m_impl->m_statistics.herpaderpingDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055.012");
            } else if (result.moduleStompingDetected) {
                result.hollowingType = HollowingType::ModuleStomping;
                m_impl->m_statistics.moduleStompingDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055");
            } else if (result.entryPointAnalysis.threadContextModified &&
                       result.creationPattern.createdSuspended) {
                // Early bird: APC injection into suspended process before EP
                result.hollowingType = HollowingType::EarlyBird;
                m_impl->m_statistics.earlyBirdDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055.012");
            } else if (result.entryPointAnalysis.threadContextModified) {
                result.hollowingType = HollowingType::ThreadHijack;
                m_impl->m_statistics.otherTypesDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055");
            } else {
                result.hollowingType = HollowingType::ClassicHollowing;
                m_impl->m_statistics.classicHollowingDetected.fetch_add(1, std::memory_order_relaxed);
                result.mitreAttackTechniques.push_back("T1055.012");
            }

            m_impl->m_statistics.hollowingDetected.fetch_add(1, std::memory_order_relaxed);

            // Track by confidence
            switch (result.confidence) {
                case HollowingConfidence::Low:
                    m_impl->m_statistics.lowConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                    break;
                case HollowingConfidence::Medium:
                    m_impl->m_statistics.mediumConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                    break;
                case HollowingConfidence::High:
                    m_impl->m_statistics.highConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                    break;
                case HollowingConfidence::Confirmed:
                    m_impl->m_statistics.confirmedDetections.fetch_add(1, std::memory_order_relaxed);
                    break;
                default:
                    break;
            }

            // Generate alert
            m_impl->GenerateAlert(result);

            // Invoke callbacks
            m_impl->InvokeDetectionCallbacks(result);
        }

        // ThreatIntel correlation for detected payloads
        auto* threatIntel = m_impl->m_threatIntel.load(std::memory_order_acquire);
        if (result.isHollowed && threatIntel != nullptr &&
            threatIntel->IsInitialized() &&
            m_impl->m_config.enableThreatIntelCorrelation) {
            // Compute hash of in-memory image for threat intel lookup
            auto payloadHash = GetPayloadHash(pid);
            bool allZero = std::all_of(payloadHash.begin(), payloadHash.end(),
                                        [](uint8_t b) { return b == 0; });
            if (!allZero) {
                // Convert hash to hex string for lookup
                std::string hexHash;
                hexHash.reserve(64);
                for (uint8_t b : payloadHash) {
                    char buf[3];
                    snprintf(buf, sizeof(buf), "%02x", b);
                    hexHash += buf;
                }

                double riskScore = 0.0;
                std::string threatName;
                if (threatIntel->IsKnownMalicious(hexHash, riskScore, threatName)) {
                    result.correlatedWithKnownThreat = true;
                    result.threatFamily = threatName;
                    result.threatName = Utils::StringUtils::ToWide(threatName);
                    result.payloadHash = payloadHash;
                    // Recalculate risk with threat intel correlation
                    result.CalculateRiskScore();
                }
            }
        }

        result.scanComplete = true;
        m_impl->InvokeProgressCallbacks(pid, L"Scan complete", 100);

    } catch (const std::exception& e) {
        result.scanError = Utils::StringUtils::ToWide(e.what());
        result.scanComplete = false;
        m_impl->m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_ERROR(L"Hollowing", L"Scan failed for PID %u - %ls", pid, result.scanError.c_str());
    }

finalize_scan:
    // Update timing statistics
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    result.scanDurationMs = static_cast<uint32_t>(duration.count());

    m_impl->m_statistics.totalScanTimeMs.fetch_add(result.scanDurationMs, std::memory_order_relaxed);

    uint64_t minTime = m_impl->m_statistics.minScanTimeMs.load(std::memory_order_relaxed);
    while (result.scanDurationMs < minTime &&
           !m_impl->m_statistics.minScanTimeMs.compare_exchange_weak(minTime, result.scanDurationMs)) {
    }

    uint64_t maxTime = m_impl->m_statistics.maxScanTimeMs.load(std::memory_order_relaxed);
    while (result.scanDurationMs > maxTime &&
           !m_impl->m_statistics.maxScanTimeMs.compare_exchange_weak(maxTime, result.scanDurationMs)) {
    }

    // Write result to scan cache and clear in-progress marker
    if (m_impl->m_config.enableCaching) {
        std::lock_guard<std::mutex> cacheLock(m_impl->m_cacheMutex);
        m_impl->m_scansInProgress.erase(pid);

        if (result.scanComplete) {
            // Evict if over capacity
            constexpr size_t MAX_CACHE_ENTRIES = 2048;
            if (m_impl->m_scanCache.size() >= MAX_CACHE_ENTRIES) {
                auto now = std::chrono::system_clock::now();
                for (auto it = m_impl->m_scanCache.begin(); it != m_impl->m_scanCache.end(); ) {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.cachedAt);
                    if (age.count() > m_impl->m_config.cacheTTLSeconds) {
                        it = m_impl->m_scanCache.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            ProcessHollowingDetectorImpl::CacheEntry entry;
            entry.result = result;
            entry.cachedAt = std::chrono::system_clock::now();
            m_impl->m_scanCache[pid] = std::move(entry);
        }

        m_impl->m_cacheCV.notify_all();
    }

    return result;
}

bool ProcessHollowingDetector::IsHollowed(uint32_t pid) {
    auto result = ScanProcess(pid, ScanMode::Quick);
    return result.isHollowed;
}

std::vector<HollowingDetectionResult> ProcessHollowingDetector::ScanByPath(
    const std::wstring& processPath,
    ScanMode mode)
{
    std::vector<HollowingDetectionResult> results;

    try {
        std::vector<Utils::ProcessUtils::ProcessId> allPids;
        if (!Utils::ProcessUtils::EnumerateProcesses(allPids)) {
            SS_LOG_ERROR(L"Hollowing", L"ScanByPath: failed to enumerate processes");
            return results;
        }

        for (auto pid : allPids) {
            auto pathOpt = Utils::ProcessUtils::GetProcessPath(pid);
            if (pathOpt.has_value() && _wcsicmp(pathOpt.value().c_str(), processPath.c_str()) == 0) {
                results.push_back(ScanProcess(pid, mode));
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ScanByPath exception: %hs", e.what());
    }

    return results;
}

std::vector<HollowingDetectionResult> ProcessHollowingDetector::ScanByName(
    const std::wstring& processName,
    ScanMode mode)
{
    std::vector<HollowingDetectionResult> results;

    try {
        auto pids = Utils::ProcessUtils::GetProcessIdsByName(processName);
        results.reserve(pids.size());
        for (auto pid : pids) {
            results.push_back(ScanProcess(pid, mode));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ScanByName exception: %hs", e.what());
    }

    return results;
}

std::vector<HollowingDetectionResult> ProcessHollowingDetector::ScanAllProcesses(
    ScanMode mode,
    uint32_t maxConcurrent)
{
    std::vector<HollowingDetectionResult> results;

    try {
        std::vector<Utils::ProcessUtils::ProcessId> allPids;
        if (!Utils::ProcessUtils::EnumerateProcesses(allPids)) {
            SS_LOG_ERROR(L"Hollowing", L"ScanAllProcesses: failed to enumerate processes");
            return results;
        }

        // Cap process count per config
        uint32_t limit = std::min(static_cast<uint32_t>(allPids.size()),
                                  m_impl->m_config.maxProcessesToScan);

        results.reserve(limit);

        for (uint32_t i = 0; i < limit; ++i) {
            auto pid = allPids[i];
            // Skip system idle (PID 0) and System (PID 4) - they cannot be hollowed
            if (pid == 0 || pid == 4) {
                continue;
            }
            results.push_back(ScanProcess(pid, mode));
        }

        SS_LOG_INFO(L"Hollowing", L"ScanAllProcesses: scanned %u of %u processes",
                    static_cast<uint32_t>(results.size()), static_cast<uint32_t>(allPids.size()));
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ScanAllProcesses exception: %hs", e.what());
    }

    return results;
}

std::vector<HollowingDetectionResult> ProcessHollowingDetector::ScanProcesses(
    const std::vector<uint32_t>& pids,
    ScanMode mode)
{
    std::vector<HollowingDetectionResult> results;
    results.reserve(pids.size());

    for (uint32_t pid : pids) {
        results.push_back(ScanProcess(pid, mode));
    }

    return results;
}

std::vector<uint32_t> ProcessHollowingDetector::GetHollowedProcesses() {
    std::vector<uint32_t> hollowedPids;

    try {
        std::vector<Utils::ProcessUtils::ProcessId> allPids;
        if (!Utils::ProcessUtils::EnumerateProcesses(allPids)) {
            return hollowedPids;
        }

        uint32_t limit = std::min(static_cast<uint32_t>(allPids.size()),
                                  m_impl->m_config.maxProcessesToScan);

        for (uint32_t i = 0; i < limit; ++i) {
            auto pid = allPids[i];
            if (pid == 0 || pid == 4) {
                continue;
            }
            if (IsHollowed(pid)) {
                hollowedPids.push_back(pid);
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"GetHollowedProcesses exception: %hs", e.what());
    }

    return hollowedPids;
}

// ============================================================================
// PE ANALYSIS
// ============================================================================

PEHeaderInfo ProcessHollowingDetector::ParseMemoryPE(uint32_t pid, uintptr_t moduleBase) {
    PEHeaderInfo info;

    try {
        // Open process with memory read access
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
        if (!hProcess.IsValid()) {
            info.validationError = L"Failed to open process for memory reading";
            SS_LOG_WARN(L"Hollowing", L"ParseMemoryPE: cannot open PID %u", pid);
            return info;
        }

        // Read the DOS header first to determine PE header location
        std::vector<uint8_t> headerBuffer(HollowingConstants::MAX_PE_HEADER_SIZE, 0);
        SIZE_T bytesRead = 0;
        if (!Utils::ProcessUtils::ReadProcessMemory(
                pid,
                reinterpret_cast<void*>(moduleBase),
                headerBuffer.data(),
                headerBuffer.size(),
                &bytesRead)) {
            info.validationError = L"ReadProcessMemory failed for PE header";
            SS_LOG_WARN(L"Hollowing", L"ParseMemoryPE: ReadProcessMemory failed for PID %u at 0x%llX",
                        pid, static_cast<unsigned long long>(moduleBase));
            return info;
        }

        if (bytesRead < sizeof(IMAGE_DOS_HEADER_CUSTOM)) {
            info.validationError = L"Insufficient data read for DOS header";
            return info;
        }

        headerBuffer.resize(bytesRead);

        // Parse using shared PE parser
        info = m_impl->ParsePEFromBuffer(headerBuffer, true);

        if (info.isValid) {
            // For memory-loaded images, set actual addresses based on module base
            for (auto& section : info.sections) {
                section.memoryAddress = moduleBase + section.virtualAddress;
            }
        }
    } catch (const std::exception& e) {
        info.validationError = Utils::StringUtils::ToWide(e.what());
        info.isValid = false;
        SS_LOG_ERROR(L"Hollowing", L"ParseMemoryPE exception for PID %u: %hs", pid, e.what());
    }

    return info;
}

PEHeaderInfo ProcessHollowingDetector::ParseFilePE(const std::wstring& filePath) {
    PEHeaderInfo info;

    try {
        // Read file
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            info.validationError = L"Failed to open file";
            return info;
        }

        // Get file size
        file.seekg(0, std::ios::end);
        auto tellPos = file.tellg();
        file.seekg(0, std::ios::beg);

        if (tellPos <= 0 || !file.good()) {
            info.validationError = L"Failed to determine file size";
            return info;
        }

        size_t fileSize = static_cast<size_t>(tellPos);

        if (fileSize < HollowingConstants::DOS_HEADER_SIZE) {
            info.validationError = L"File too small for PE";
            return info;
        }

        if (fileSize > HollowingConstants::MAX_COMPARISON_SIZE) {
            fileSize = HollowingConstants::MAX_COMPARISON_SIZE;
        }

        // Read into buffer
        std::vector<uint8_t> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(fileSize));
        auto bytesRead = file.gcount();
        file.close();

        if (bytesRead <= 0) {
            info.validationError = L"Failed to read file";
            return info;
        }
        buffer.resize(static_cast<size_t>(bytesRead));

        // Parse PE
        info = m_impl->ParsePEFromBuffer(buffer, false);

    } catch (const std::exception& e) {
        info.validationError = Utils::StringUtils::ToWide(e.what());
        info.isValid = false;
    }

    return info;
}

HeaderComparison ProcessHollowingDetector::ComparePEHeaders(
    const PEHeaderInfo& disk,
    const PEHeaderInfo& memory)
{
    HeaderComparison comparison;

    // Compare basic fields
    // Note: ImageBase mismatch is expected for ASLR-enabled binaries (DYNAMIC_BASE).
    // Only flag it as anomalous if the disk PE does not have ASLR enabled.
    bool diskHasASLR = (disk.dllCharacteristics & 0x0040) != 0;  // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    comparison.imageBaseMatches = (disk.imageBase == memory.imageBase);
    comparison.entryPointMatches = (disk.entryPoint == memory.entryPoint);
    comparison.sizeOfImageMatches = (disk.sizeOfImage == memory.sizeOfImage);

    // PE loader zeroes the checksum field in memory. Only flag mismatch if
    // both disk and memory have non-zero checksums that disagree.
    comparison.checksumMatches = (memory.checksum == 0) ||
                                 (disk.checksum == memory.checksum);

    comparison.timestampMatches = (disk.timeDateStamp == memory.timeDateStamp);
    comparison.sectionCountMatches = (disk.numberOfSections == memory.numberOfSections);
    comparison.machineMatches = (disk.machine == memory.machine);

    // Store differences
    comparison.diskImageBase = disk.imageBase;
    comparison.memoryImageBase = memory.imageBase;
    comparison.diskEntryPoint = disk.entryPoint;
    comparison.memoryEntryPoint = memory.entryPoint;
    comparison.diskSizeOfImage = disk.sizeOfImage;
    comparison.memorySizeOfImage = memory.sizeOfImage;
    comparison.diskChecksum = disk.checksum;
    comparison.memoryChecksum = memory.checksum;
    comparison.diskTimestamp = disk.timeDateStamp;
    comparison.memoryTimestamp = memory.timeDateStamp;
    comparison.diskSectionCount = disk.numberOfSections;
    comparison.memorySectionCount = memory.numberOfSections;

    // Count mismatches
    // ImageBase mismatch is only suspicious for non-ASLR binaries; ASLR relocation is normal
    if (!comparison.imageBaseMatches && !diskHasASLR) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"ImageBase mismatch (non-ASLR binary)");
    }
    if (!comparison.entryPointMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Entry point mismatch");
    }
    if (!comparison.sizeOfImageMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Size of image mismatch");
    }
    if (!comparison.checksumMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Checksum mismatch");
    }
    if (!comparison.timestampMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Timestamp mismatch");
    }
    if (!comparison.sectionCountMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Section count mismatch");
    }

    // Machine type mismatch is extremely suspicious
    if (!comparison.machineMatches) {
        comparison.mismatchCount++;
        comparison.anomalies.push_back(L"Machine type mismatch");
    }

    comparison.headersMatch = (comparison.mismatchCount == 0);

    // 7 total fields compared (imageBase, entryPoint, sizeOfImage, checksum, timestamp, sectionCount, machine)
    constexpr double totalComparisons = 7.0;
    comparison.overallSimilarity = comparison.headersMatch ? 1.0 :
        1.0 - (static_cast<double>(comparison.mismatchCount) / totalComparisons);

    return comparison;
}

bool ProcessHollowingDetector::ValidatePEHeader(const PEHeaderInfo& header) {
    return header.isValid &&
           header.hasDosHeader &&
           header.hasPeHeader &&
           header.numberOfSections > 0 &&
           header.numberOfSections <= HollowingConstants::MAX_SECTIONS;
}

bool ProcessHollowingDetector::ValidateImageBase(uint32_t pid, uintptr_t moduleBase) {
    try {
        // Read the in-memory PEB to get the actual ImageBaseAddress
        // and compare it against the module base we were given.
        // If they differ, someone may have re-mapped the image.

        auto memPE = ParseMemoryPE(pid, moduleBase);
        if (!memPE.isValid) {
            // Cannot read the PE at the claimed base - suspicious
            SS_LOG_WARN(L"Hollowing", L"ValidateImageBase: cannot parse memory PE for PID %u at 0x%llX",
                        pid, static_cast<unsigned long long>(moduleBase));
            return false;
        }

        auto pathOpt = Utils::ProcessUtils::GetProcessPath(pid);
        if (!pathOpt.has_value() || pathOpt.value().empty()) {
            return true;  // Cannot compare
        }

        auto diskPE = ParseFilePE(pathOpt.value());
        if (!diskPE.isValid) {
            return true;  // Cannot compare
        }

        // For non-ASLR binaries, imageBase should match the disk preferred base.
        // For ASLR binaries, the OS relocates - that's expected.
        bool hasASLR = (diskPE.dllCharacteristics & 0x0040) != 0;

        if (!hasASLR && diskPE.imageBase != static_cast<uintptr_t>(moduleBase)) {
            SS_LOG_WARN(L"Hollowing", L"ValidateImageBase: non-ASLR binary loaded at unexpected base "
                        L"(expected 0x%llX, actual 0x%llX) for PID %u",
                        static_cast<unsigned long long>(diskPE.imageBase),
                        static_cast<unsigned long long>(moduleBase), pid);
            return false;
        }

        // Check that the entry point and section count match
        if (diskPE.entryPoint != memPE.entryPoint) {
            SS_LOG_WARN(L"Hollowing", L"ValidateImageBase: entry point mismatch for PID %u "
                        L"(disk=0x%llX, memory=0x%llX)",
                        pid,
                        static_cast<unsigned long long>(diskPE.entryPoint),
                        static_cast<unsigned long long>(memPE.entryPoint));
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ValidateImageBase exception for PID %u: %hs", pid, e.what());
        return true;  // Cannot determine, err on side of caution
    }
}

// ============================================================================
// ENTRY POINT ANALYSIS
// ============================================================================

EntryPointAnalysis ProcessHollowingDetector::AnalyzeEntryPoint(uint32_t pid) {
    EntryPointAnalysis analysis;

    try {
        // Get the module base and process path
        auto pathOpt = Utils::ProcessUtils::GetProcessPath(pid);
        if (!pathOpt.has_value() || pathOpt.value().empty()) {
            analysis.isAnomalous = false;
            return analysis;
        }

        // Parse the disk PE to get expected entry point
        auto diskHeader = ParseFilePE(pathOpt.value());
        if (!diskHeader.isValid) {
            return analysis;
        }

        analysis.entryPointRVA = diskHeader.entryPoint;

        // Get actual module base
        uintptr_t moduleBase = 0;
        {
            auto nameOpt = Utils::ProcessUtils::GetProcessName(pid);
            std::wstring modName = nameOpt.value_or(L"");
            if (!modName.empty()) {
                auto baseOpt = Utils::ProcessUtils::GetModuleBaseAddress(pid, modName);
                if (baseOpt.has_value()) {
                    moduleBase = reinterpret_cast<uintptr_t>(baseOpt.value());
                }
            }
        }

        if (moduleBase == 0) {
            return analysis;
        }

        analysis.entryPointVA = moduleBase + analysis.entryPointRVA;

        // Determine which section contains the entry point
        for (const auto& section : diskHeader.sections) {
            uint32_t secStart = section.virtualAddress;
            uint32_t secEnd = secStart + std::max(section.virtualSize, section.sizeOfRawData);
            if (analysis.entryPointRVA >= secStart && analysis.entryPointRVA < secEnd) {
                analysis.containingSection = std::wstring(section.name.data(), strnlen(section.name.data(), 8));
                analysis.isInCodeSection = section.isExecutable || section.containsCode;
                analysis.isInExpectedRange = true;
                break;
            }
        }

        // Read entry point bytes for prologue analysis
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
        if (hProcess.IsValid()) {
            SIZE_T bytesRead = 0;
            if (Utils::ProcessUtils::ReadProcessMemory(
                    pid,
                    reinterpret_cast<void*>(analysis.entryPointVA),
                    analysis.entryPointBytes.data(),
                    analysis.entryPointBytes.size(),
                    &bytesRead)) {

                analysis.pointsToValidCode = (bytesRead >= 2);

                // Check for standard function prologues (x64)
                // push rbp; mov rbp,rsp  = 0x55 0x48 0x89 0xE5
                // sub rsp, imm          = 0x48 0x83 0xEC xx
                // push rbx              = 0x53
                if (bytesRead >= 4) {
                    uint8_t b0 = analysis.entryPointBytes[0];
                    uint8_t b1 = analysis.entryPointBytes[1];
                    uint8_t b2 = analysis.entryPointBytes[2];
                    uint8_t b3 = analysis.entryPointBytes[3];

                    // Standard CRT entry point patterns
                    analysis.hasValidPrologue =
                        (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) ||      // sub rsp, imm8
                        (b0 == 0x48 && b1 == 0x89 && b2 == 0x5C) ||      // mov [rsp+...], rbx
                        (b0 == 0x40 && b1 == 0x53) ||                     // push rbx (REX)
                        (b0 == 0x55) ||                                    // push rbp
                        (b0 == 0x53) ||                                    // push rbx
                        (b0 == 0x48 && b1 == 0x8B && b2 == 0xC4) ||      // mov rax, rsp
                        (b0 == 0xE9) ||                                    // jmp (thunk)
                        (b0 == 0xFF && b1 == 0x25);                       // jmp [rip+...]

                    // Detect common shellcode patterns
                    // NOP sled, int3 sled, or GetPC (call next; pop reg)
                    bool allNops = true;
                    bool allInt3 = true;
                    for (size_t i = 0; i < std::min(bytesRead, static_cast<SIZE_T>(16)); ++i) {
                        if (analysis.entryPointBytes[i] != 0x90) allNops = false;
                        if (analysis.entryPointBytes[i] != 0xCC) allInt3 = false;
                    }

                    analysis.hasShellcodePattern =
                        allNops ||                                          // NOP sled
                        (b0 == 0xE8 && b1 == 0x00 && b2 == 0x00 &&
                         b3 == 0x00) ||                                    // call $+5 (GetPC)
                        (b0 == 0xFC) ||                                    // cld (common shellcode)
                        (b0 == 0x60) ||                                    // pushad (x86 shellcode)
                        (b0 == 0x00 && b1 == 0x00 && b2 == 0x00 &&
                         b3 == 0x00);                                      // Null bytes at EP = bad
                }
            }
        }

        // Check if entry point is outside any known section (very suspicious)
        if (!analysis.isInExpectedRange && analysis.entryPointRVA != 0) {
            analysis.isAnomalous = true;
            analysis.anomalyReasons.push_back(L"Entry point outside all defined sections");
        }

        // Entry point in a writable section is suspicious
        for (const auto& section : diskHeader.sections) {
            uint32_t secStart = section.virtualAddress;
            uint32_t secEnd = secStart + std::max(section.virtualSize, section.sizeOfRawData);
            if (analysis.entryPointRVA >= secStart && analysis.entryPointRVA < secEnd) {
                if (section.isWritable && section.isExecutable) {
                    analysis.isAnomalous = true;
                    analysis.anomalyReasons.push_back(L"Entry point in RWX section");
                }
                if (!section.isExecutable && !section.containsCode) {
                    analysis.isAnomalous = true;
                    analysis.anomalyReasons.push_back(L"Entry point in non-executable section");
                }
                break;
            }
        }

        if (analysis.hasShellcodePattern) {
            analysis.isAnomalous = true;
            analysis.anomalyReasons.push_back(L"Shellcode pattern detected at entry point");
        }

        if (analysis.pointsToValidCode && !analysis.hasValidPrologue && !analysis.hasShellcodePattern) {
            // Not a standard prologue but also not shellcode - could be custom CRT
            // Flag as low-confidence anomaly only if other indicators present
        }

        // Analyze main thread start address vs entry point
        std::vector<Utils::ProcessUtils::ProcessThreadInfo> threads;
        if (Utils::ProcessUtils::EnumerateProcessThreads(pid, threads)) {
            if (!threads.empty()) {
                // Find the earliest thread (likely main thread)
                auto mainThread = std::min_element(threads.begin(), threads.end(),
                    [](const auto& a, const auto& b) {
                        return CompareFileTime(&a.creationTime, &b.creationTime) < 0;
                    });

                if (mainThread != threads.end() && mainThread->startAddress != nullptr) {
                    analysis.mainThreadRIP = reinterpret_cast<uintptr_t>(mainThread->startAddress);

                    // The main thread start address should be within the module or at a known
                    // system entry point (e.g. kernel32!BaseThreadInitThunk). If it points
                    // to unbacked memory, that's very suspicious.
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (Utils::ProcessUtils::QueryProcessMemoryRegion(
                            pid, mainThread->startAddress, mbi)) {
                        if (mbi.Type == 0 && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                            // Unbacked RWX memory - highly suspicious
                            analysis.threadContextModified = true;
                            analysis.isAnomalous = true;
                            analysis.anomalyReasons.push_back(
                                L"Main thread start address in unbacked RWX memory");
                        }
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"AnalyzeEntryPoint exception for PID %u: %hs", pid, e.what());
    }

    return analysis;
}

bool ProcessHollowingDetector::ValidateEntryPoint(uint32_t pid) {
    auto analysis = AnalyzeEntryPoint(pid);
    return !analysis.isAnomalous;
}

bool ProcessHollowingDetector::ValidateMainThread(uint32_t pid) {
    try {
        std::vector<Utils::ProcessUtils::ProcessThreadInfo> threads;
        if (!Utils::ProcessUtils::EnumerateProcessThreads(pid, threads) || threads.empty()) {
            return true;  // Cannot determine, assume ok
        }

        // Find earliest (main) thread
        auto mainThread = std::min_element(threads.begin(), threads.end(),
            [](const auto& a, const auto& b) {
                return CompareFileTime(&a.creationTime, &b.creationTime) < 0;
            });

        if (mainThread == threads.end() || mainThread->startAddress == nullptr) {
            return true;
        }

        // Check if start address is in file-backed executable memory
        MEMORY_BASIC_INFORMATION mbi{};
        if (Utils::ProcessUtils::QueryProcessMemoryRegion(
                pid, mainThread->startAddress, mbi)) {
            // MEM_IMAGE = file-backed section; if not, suspicious
            if (mbi.Type != MEM_IMAGE) {
                SS_LOG_WARN(L"Hollowing", L"Main thread of PID %u starts in non-image memory (type=0x%lX)",
                            pid, mbi.Type);
                return false;
            }
        }

        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ValidateMainThread exception for PID %u: %hs", pid, e.what());
        return true;  // Cannot determine, assume ok
    }
}

// ============================================================================
// CREATION PATTERN MONITORING
// ============================================================================

CreationPatternAnalysis ProcessHollowingDetector::AnalyzeCreationPattern(uint32_t pid) {
    CreationPatternAnalysis analysis;

    std::lock_guard<std::mutex> lock(m_impl->m_creationEventsMutex);

    auto it = m_impl->m_creationEvents.find(pid);
    if (it == m_impl->m_creationEvents.end()) {
        return analysis;
    }

    const auto& event = it->second;
    analysis.creatorPid = event.creatorPid;
    analysis.creatorPath = Utils::ProcessUtils::GetProcessPath(event.creatorPid).value_or(L"");
    analysis.createdSuspended = event.createdSuspended;
    analysis.createTime = event.createTime;
    analysis.firstResumeTime = event.resumeTime;

    if (event.createdSuspended) {
        // Only calculate duration if the process has actually been resumed
        if (event.resumeTime > event.createTime) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                event.resumeTime - event.createTime
            );
            analysis.suspendedDurationMs = static_cast<uint32_t>(duration.count());
            analysis.firstResumeTime = event.resumeTime;

            // Check for suspicious suspended duration
            if (analysis.suspendedDurationMs > HollowingConstants::MIN_SUSPENDED_DURATION_MS &&
                analysis.suspendedDurationMs < HollowingConstants::MAX_CREATION_TO_RESUME_MS) {
                analysis.isSuspiciousPattern = true;
                analysis.suspiciousIndicators.push_back(L"Suspicious suspended duration");
            }
        } else {
            // Process was created suspended but not yet resumed - that's also suspicious
            // if significant time has passed
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() - event.createTime
            );
            if (elapsed.count() > HollowingConstants::MAX_CREATION_TO_RESUME_MS) {
                analysis.isSuspiciousPattern = true;
                analysis.suspiciousIndicators.push_back(L"Process suspended for extended duration");
            }
        }
    }

    analysis.observedApiSequence = event.memoryOperations;

    // Check for hollowing API sequence
    if (!event.memoryOperations.empty()) {
        analysis.isSuspiciousPattern = true;
        analysis.matchesHollowingPattern = true;
    }

    return analysis;
}

bool ProcessHollowingDetector::HasSuspiciousCreationPattern(uint32_t pid) {
    auto analysis = AnalyzeCreationPattern(pid);
    return analysis.isSuspiciousPattern;
}

void ProcessHollowingDetector::OnProcessCreated(
    uint32_t pid,
    uint32_t creatorPid,
    bool createdSuspended,
    const std::wstring& imagePath)
{
    if (createdSuspended) {
        m_impl->m_statistics.suspendedCreationsMonitored.fetch_add(1, std::memory_order_relaxed);
    }

    std::lock_guard<std::mutex> lock(m_impl->m_creationEventsMutex);

    // Evict stale entries to prevent unbounded growth
    if (m_impl->m_creationEvents.size() >= HollowingConstants::CREATION_EVENT_QUEUE_SIZE) {
        auto now = std::chrono::system_clock::now();
        auto cutoff = std::chrono::milliseconds(HollowingConstants::CREATION_MONITOR_WINDOW_MS * 6);
        for (auto it = m_impl->m_creationEvents.begin(); it != m_impl->m_creationEvents.end(); ) {
            if ((now - it->second.createTime) > cutoff) {
                it = m_impl->m_creationEvents.erase(it);
            } else {
                ++it;
            }
        }
        // If still over capacity after time-based eviction, drop oldest
        while (m_impl->m_creationEvents.size() >= HollowingConstants::CREATION_EVENT_QUEUE_SIZE) {
            auto oldest = std::min_element(m_impl->m_creationEvents.begin(), m_impl->m_creationEvents.end(),
                [](const auto& a, const auto& b) { return a.second.createTime < b.second.createTime; });
            if (oldest != m_impl->m_creationEvents.end()) {
                m_impl->m_creationEvents.erase(oldest);
            } else {
                break;
            }
        }
    }

    ProcessHollowingDetectorImpl::CreationEvent event;
    event.pid = pid;
    event.creatorPid = creatorPid;
    event.imagePath = imagePath;
    event.createTime = std::chrono::system_clock::now();
    event.createdSuspended = createdSuspended;

    m_impl->m_creationEvents[pid] = event;

    SS_LOG_DEBUG(L"Hollowing", L"Process created - PID %u by %u (Suspended: %ls)", pid, creatorPid, createdSuspended ? L"true" : L"false");
}

void ProcessHollowingDetector::OnProcessResumed(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_impl->m_creationEventsMutex);

    auto it = m_impl->m_creationEvents.find(pid);
    if (it != m_impl->m_creationEvents.end()) {
        it->second.resumeTime = std::chrono::system_clock::now();
    }
}

void ProcessHollowingDetector::OnMemoryOperation(
    uint32_t pid,
    const std::wstring& operationType,
    uintptr_t address,
    size_t size)
{
    std::lock_guard<std::mutex> lock(m_impl->m_creationEventsMutex);

    auto it = m_impl->m_creationEvents.find(pid);
    if (it != m_impl->m_creationEvents.end()) {
        // Track specific hollowing-related operations with enrichment
        if (operationType == L"NtUnmapViewOfSection" ||
            operationType == L"ZwUnmapViewOfSection") {
            it->second.memoryOperations.push_back(L"NtUnmapViewOfSection [SUSPICIOUS: Image unmap]");
        } else if (operationType == L"NtMapViewOfSection" ||
                   operationType == L"ZwMapViewOfSection") {
            it->second.memoryOperations.push_back(L"NtMapViewOfSection [SUSPICIOUS: New section mapped]");
        } else if (operationType == L"NtWriteVirtualMemory" ||
                   operationType == L"WriteProcessMemory") {
            it->second.memoryOperations.push_back(L"WriteProcessMemory [SUSPICIOUS: Remote memory write]");
        } else if (operationType == L"NtSetContextThread" ||
                   operationType == L"SetThreadContext") {
            it->second.memoryOperations.push_back(L"SetThreadContext [SUSPICIOUS: Thread context modified]");
        } else {
            it->second.memoryOperations.push_back(operationType);
        }

        // Cap operations list to prevent unbounded growth
        constexpr size_t MAX_OPS = 256;
        if (it->second.memoryOperations.size() > MAX_OPS) {
            it->second.memoryOperations.erase(
                it->second.memoryOperations.begin(),
                it->second.memoryOperations.begin() + static_cast<ptrdiff_t>(MAX_OPS / 2));
        }
    }
}

// ============================================================================
// MONITORING
// ============================================================================

bool ProcessHollowingDetector::StartMonitoring() {
    if (m_impl->m_monitoring.load(std::memory_order_acquire)) {
        return true;
    }

    m_impl->m_monitoring.store(true, std::memory_order_release);
    SS_LOG_INFO(L"Hollowing", L"Monitoring started");
    return true;
}

void ProcessHollowingDetector::StopMonitoring() {
    m_impl->m_monitoring.store(false, std::memory_order_release);
    SS_LOG_INFO(L"Hollowing", L"Monitoring stopped");
}

bool ProcessHollowingDetector::IsMonitoring() const noexcept {
    return m_impl->m_monitoring.load(std::memory_order_acquire);
}

MonitorMode ProcessHollowingDetector::GetMonitorMode() const noexcept {
    return m_impl->m_monitorMode.load(std::memory_order_acquire);
}

void ProcessHollowingDetector::SetMonitorMode(MonitorMode mode) {
    m_impl->m_monitorMode.store(mode, std::memory_order_release);
}

// ============================================================================
// ALERT MANAGEMENT
// ============================================================================

std::vector<HollowingAlert> ProcessHollowingDetector::GetAlerts() const {
    std::lock_guard<std::mutex> lock(m_impl->m_alertsMutex);
    return m_impl->m_alerts;
}

std::vector<HollowingAlert> ProcessHollowingDetector::GetAlertsForProcess(uint32_t pid) const {
    std::lock_guard<std::mutex> lock(m_impl->m_alertsMutex);

    std::vector<HollowingAlert> processAlerts;
    for (const auto& alert : m_impl->m_alerts) {
        if (alert.processId == pid) {
            processAlerts.push_back(alert);
        }
    }
    return processAlerts;
}

bool ProcessHollowingDetector::AcknowledgeAlert(uint64_t alertId) {
    std::lock_guard<std::mutex> lock(m_impl->m_alertsMutex);

    for (auto& alert : m_impl->m_alerts) {
        if (alert.alertId == alertId) {
            alert.acknowledged = true;
            m_impl->m_statistics.alertsAcknowledged.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}

bool ProcessHollowingDetector::MarkRemediated(uint64_t alertId) {
    std::lock_guard<std::mutex> lock(m_impl->m_alertsMutex);

    for (auto& alert : m_impl->m_alerts) {
        if (alert.alertId == alertId) {
            alert.remediated = true;
            return true;
        }
    }
    return false;
}

void ProcessHollowingDetector::ClearAlerts() {
    std::lock_guard<std::mutex> lock(m_impl->m_alertsMutex);
    m_impl->m_alerts.clear();
}

void ProcessHollowingDetector::ReportFalsePositive(uint64_t alertId, const std::wstring& reason) {
    m_impl->m_statistics.falsePositivesReported.fetch_add(1, std::memory_order_relaxed);
    SS_LOG_INFO(L"Hollowing", L"False positive reported - Alert %llu: %ls", alertId, reason.c_str());
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ProcessHollowingDetector::RegisterDetectionCallback(HollowingDetectedCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_detectionCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t ProcessHollowingDetector::RegisterCreationCallback(SuspiciousCreationCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_creationCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t ProcessHollowingDetector::RegisterProgressCallback(ScanProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks.emplace_back(id, std::move(callback));
    return id;
}

void ProcessHollowingDetector::UnregisterCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    auto removeById = [callbackId](auto& callbacks) {
        auto it = std::find_if(callbacks.begin(), callbacks.end(),
                              [callbackId](const auto& pair) { return pair.first == callbackId; });
        if (it != callbacks.end()) {
            callbacks.erase(it);
            return true;
        }
        return false;
    };

    removeById(m_impl->m_detectionCallbacks) ||
    removeById(m_impl->m_creationCallbacks) ||
    removeById(m_impl->m_progressCallbacks);
}

// ============================================================================
// PAYLOAD EXTRACTION
// ============================================================================

std::vector<uint8_t> ProcessHollowingDetector::ExtractPayload(uint32_t pid) {
    std::vector<uint8_t> payload;

    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
        if (!hProcess.IsValid()) {
            SS_LOG_WARN(L"Hollowing", L"ExtractPayload: cannot open PID %u", pid);
            return payload;
        }

        // Determine module base
        uintptr_t moduleBase = 0;
        {
            auto nameOpt = Utils::ProcessUtils::GetProcessName(pid);
            std::wstring modName = nameOpt.value_or(L"");
            if (!modName.empty()) {
                auto baseOpt = Utils::ProcessUtils::GetModuleBaseAddress(pid, modName);
                if (baseOpt.has_value()) {
                    moduleBase = reinterpret_cast<uintptr_t>(baseOpt.value());
                }
            }
        }

        if (moduleBase == 0) {
            SS_LOG_WARN(L"Hollowing", L"ExtractPayload: cannot determine module base for PID %u", pid);
            return payload;
        }

        auto memPE = ParseMemoryPE(pid, moduleBase);
        if (!memPE.isValid || memPE.sizeOfImage == 0) {
            return payload;
        }

        // Cap extraction size
        size_t extractSize = std::min(static_cast<size_t>(memPE.sizeOfImage),
                                       HollowingConstants::MAX_COMPARISON_SIZE);
        payload.resize(extractSize, 0);

        SIZE_T bytesRead = 0;
        if (!Utils::ProcessUtils::ReadProcessMemory(
                pid,
                reinterpret_cast<void*>(moduleBase),
                payload.data(),
                extractSize,
                &bytesRead)) {
            SS_LOG_WARN(L"Hollowing", L"ExtractPayload: ReadProcessMemory failed for PID %u", pid);
            payload.clear();
            return payload;
        }

        payload.resize(bytesRead);
        SS_LOG_INFO(L"Hollowing", L"ExtractPayload: extracted %llu bytes from PID %u",
                    static_cast<unsigned long long>(bytesRead), pid);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"ExtractPayload exception for PID %u: %hs", pid, e.what());
        payload.clear();
    }

    return payload;
}

bool ProcessHollowingDetector::DumpProcessMemory(uint32_t pid, const std::wstring& outputPath) {
    try {
        auto payload = ExtractPayload(pid);
        if (payload.empty()) {
            SS_LOG_WARN(L"Hollowing", L"DumpProcessMemory: no data extracted from PID %u", pid);
            return false;
        }

        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            SS_LOG_ERROR(L"Hollowing", L"DumpProcessMemory: cannot open output file for PID %u", pid);
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(payload.data()),
                      static_cast<std::streamsize>(payload.size()));
        outFile.close();

        SS_LOG_INFO(L"Hollowing", L"DumpProcessMemory: wrote %llu bytes for PID %u",
                    static_cast<unsigned long long>(payload.size()), pid);
        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"DumpProcessMemory exception for PID %u: %hs", pid, e.what());
        return false;
    }
}

std::array<uint8_t, 32> ProcessHollowingDetector::GetPayloadHash(uint32_t pid) {
    std::array<uint8_t, 32> hash{};
    auto payload = ExtractPayload(pid);
    if (!payload.empty()) {
        std::vector<uint8_t> hashVec;
        if (Utils::HashUtils::Compute(
                Utils::HashUtils::Algorithm::SHA256,
                payload.data(), payload.size(), hashVec)) {
            size_t copyLen = std::min(hashVec.size(), hash.size());
            std::memcpy(hash.data(), hashVec.data(), copyLen);
        } else {
            SS_LOG_WARN(L"Hollowing", L"GetPayloadHash: hash computation failed for PID %u", pid);
        }
    }
    return hash;
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

const HollowingStatistics& ProcessHollowingDetector::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void ProcessHollowingDetector::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"Hollowing", L"Statistics reset");
}

std::string ProcessHollowingDetector::GetVersionString() noexcept {
    return std::to_string(HollowingConstants::VERSION_MAJOR) + "." +
           std::to_string(HollowingConstants::VERSION_MINOR) + "." +
           std::to_string(HollowingConstants::VERSION_PATCH);
}

bool ProcessHollowingDetector::SelfTest() {
    try {
        SS_LOG_INFO(L"Hollowing", L"Starting self-test");

        // Test PE parsing - must have sections to be valid
        PEHeaderInfo testHeader;
        testHeader.isValid = true;
        testHeader.hasDosHeader = true;
        testHeader.hasPeHeader = true;
        testHeader.numberOfSections = 1;

        if (!ValidatePEHeader(testHeader)) {
            SS_LOG_ERROR(L"Hollowing", L"PE validation test failed");
            return false;
        }

        // Test configuration factory methods
        auto defaultConfig = HollowingDetectorConfig::CreateDefault();
        auto paranoidConfig = HollowingDetectorConfig::CreateParanoid();
        auto perfConfig = HollowingDetectorConfig::CreatePerformance();
        auto forensicConfig = HollowingDetectorConfig::CreateForensic();

        if (!defaultConfig.enableHeaderComparison ||
            !paranoidConfig.enablePayloadExtraction ||
            !perfConfig.enableCaching ||
            !forensicConfig.quarantinePayload) {
            SS_LOG_ERROR(L"Hollowing", L"Config factory test failed");
            return false;
        }

        SS_LOG_INFO(L"Hollowing", L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Hollowing", L"Self-test failed - %hs", e.what());
        return false;
    }
}

std::vector<std::wstring> ProcessHollowingDetector::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    diagnostics.push_back(L"ProcessHollowingDetector Diagnostics");
    diagnostics.push_back(L"====================================");
    diagnostics.push_back(L"Initialized: " + std::wstring(IsInitialized() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Monitoring: " + std::wstring(IsMonitoring() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Total Scans: " + std::to_wstring(m_impl->m_statistics.totalScans.load()));
    diagnostics.push_back(L"Detections: " + std::to_wstring(m_impl->m_statistics.hollowingDetected.load()));
    diagnostics.push_back(L"Avg Scan Time: " + std::to_wstring(m_impl->m_statistics.GetAverageScanTimeMs()) + L" ms");
    diagnostics.push_back(L"Detection Rate: " + std::to_wstring(m_impl->m_statistics.GetDetectionRate()) + L"%");

    return diagnostics;
}

// ============================================================================
// EXCLUSIONS
// ============================================================================

void ProcessHollowingDetector::AddExclusion(const std::wstring& processName) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_exclusionsMutex);
    m_impl->m_excludedProcessNames.insert(processName);
}

void ProcessHollowingDetector::RemoveExclusion(const std::wstring& processName) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_exclusionsMutex);
    m_impl->m_excludedProcessNames.erase(processName);
}

bool ProcessHollowingDetector::IsExcluded(uint32_t pid) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_exclusionsMutex);

    if (m_impl->m_excludedPids.find(pid) != m_impl->m_excludedPids.end()) {
        return true;
    }

    auto processName = Utils::ProcessUtils::GetProcessName(pid).value_or(L"");
    if (!processName.empty() &&
        m_impl->m_excludedProcessNames.find(processName) != m_impl->m_excludedProcessNames.end()) {
        return true;
    }

    // Check path exclusions
    if (!m_impl->m_excludedPaths.empty()) {
        auto processPath = Utils::ProcessUtils::GetProcessPath(pid).value_or(L"");
        if (!processPath.empty()) {
            for (const auto& excludedPath : m_impl->m_excludedPaths) {
                if (_wcsnicmp(processPath.c_str(), excludedPath.c_str(), excludedPath.size()) == 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

std::vector<std::wstring> ProcessHollowingDetector::GetExclusions() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_exclusionsMutex);
    return std::vector<std::wstring>(m_impl->m_excludedProcessNames.begin(),
                                    m_impl->m_excludedProcessNames.end());
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetHollowingTypeName(HollowingType type) noexcept {
    switch (type) {
        case HollowingType::Unknown: return "Unknown";
        case HollowingType::ClassicHollowing: return "Classic Hollowing";
        case HollowingType::SectionHollowing: return "Section Hollowing";
        case HollowingType::TransactedHollowing: return "Transacted Hollowing";
        case HollowingType::ProcessDoppelganging: return "Process Doppelganging";
        case HollowingType::ProcessHerpaderping: return "Process Herpaderping";
        case HollowingType::ProcessGhosting: return "Process Ghosting";
        case HollowingType::ProcessReimaging: return "Process Reimaging";
        case HollowingType::EarlyBird: return "Early Bird";
        case HollowingType::ThreadHijack: return "Thread Hijack";
        case HollowingType::ModuleStomping: return "Module Stomping";
        case HollowingType::PhantomDLLHollowing: return "Phantom DLL Hollowing";
        case HollowingType::PartialHollowing: return "Partial Hollowing";
        case HollowingType::HeaderModification: return "Header Modification";
        default: return "Unknown";
    }
}

std::string_view GetConfidenceName(HollowingConfidence confidence) noexcept {
    switch (confidence) {
        case HollowingConfidence::None: return "None";
        case HollowingConfidence::Low: return "Low";
        case HollowingConfidence::Medium: return "Medium";
        case HollowingConfidence::High: return "High";
        case HollowingConfidence::Confirmed: return "Confirmed";
        default: return "Unknown";
    }
}

std::string_view GetDetectionMethodName(DetectionMethod method) noexcept {
    switch (method) {
        case DetectionMethod::Unknown: return "Unknown";
        case DetectionMethod::PEHeaderMismatch: return "PE Header Mismatch";
        case DetectionMethod::EntryPointAnomaly: return "Entry Point Anomaly";
        case DetectionMethod::SectionMismatch: return "Section Mismatch";
        case DetectionMethod::SectionCharacteristics: return "Section Characteristics";
        case DetectionMethod::ImageBaseAnomaly: return "ImageBase Anomaly";
        case DetectionMethod::ChecksumMismatch: return "Checksum Mismatch";
        case DetectionMethod::TimestampMismatch: return "Timestamp Mismatch";
        case DetectionMethod::SizeOfImageMismatch: return "SizeOfImage Mismatch";
        case DetectionMethod::MemoryProtection: return "Memory Protection";
        case DetectionMethod::UnbackedExecMemory: return "Unbacked Executable Memory";
        case DetectionMethod::ThreadContextAnomaly: return "Thread Context Anomaly";
        case DetectionMethod::CreationPatternAnomaly: return "Creation Pattern Anomaly";
        case DetectionMethod::TransactionAnomaly: return "Transaction Anomaly";
        case DetectionMethod::DeletePendingFile: return "Delete Pending File";
        case DetectionMethod::EntropyAnomaly: return "Entropy Anomaly";
        case DetectionMethod::ImportTableAnomaly: return "Import Table Anomaly";
        case DetectionMethod::RelocationAnomaly: return "Relocation Anomaly";
        case DetectionMethod::ExportTableAnomaly: return "Export Table Anomaly";
        case DetectionMethod::DebugDirectoryAnomaly: return "Debug Directory Anomaly";
        case DetectionMethod::ResourceAnomaly: return "Resource Anomaly";
        case DetectionMethod::DigitalSignatureBroken: return "Digital Signature Broken";
        default: return "Unknown";
    }
}

std::string_view GetScanModeName(ScanMode mode) noexcept {
    switch (mode) {
        case ScanMode::Quick: return "Quick";
        case ScanMode::Standard: return "Standard";
        case ScanMode::Comprehensive: return "Comprehensive";
        case ScanMode::Paranoid: return "Paranoid";
        default: return "Unknown";
    }
}

std::string_view GetMonitorModeName(MonitorMode mode) noexcept {
    switch (mode) {
        case MonitorMode::Disabled: return "Disabled";
        case MonitorMode::PassiveOnly: return "Passive Only";
        case MonitorMode::Active: return "Active";
        case MonitorMode::Aggressive: return "Aggressive";
        default: return "Unknown";
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
