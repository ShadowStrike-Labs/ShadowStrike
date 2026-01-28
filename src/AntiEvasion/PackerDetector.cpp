/**
 * @file PackerDetector.cpp
 * @brief Enterprise-grade detection of executable packers, protectors, and crypters
 *
 * ShadowStrike AntiEvasion - Packer Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection and identification of 500+ packers,
 * protectors, crypters, and obfuscators used to evade static analysis.
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (SignatureStore, PatternStore, HashStore)
 */

#include "pch.h"
#include "PackerDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <execution>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <queue>
#include <sstream>
#include <format>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include"../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"

namespace fs = std::filesystem;

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get display name for packer type
     */
    [[nodiscard]] const wchar_t* PackerTypeToString(PackerType type) noexcept {
        switch (type) {
            // Compression packers
        case PackerType::UPX: return L"UPX";
        case PackerType::UPX_Modified: return L"UPX (Modified)";
        case PackerType::UPX_Scrambled: return L"UPX (Scrambled)";
        case PackerType::ASPack: return L"ASPack";
        case PackerType::ASPack_v1: return L"ASPack v1.x";
        case PackerType::ASPack_v2: return L"ASPack v2.x";
        case PackerType::PECompact: return L"PECompact";
        case PackerType::PECompact_v1: return L"PECompact v1.x";
        case PackerType::PECompact_v2: return L"PECompact v2.x";
        case PackerType::PECompact_v3: return L"PECompact v3.x";
        case PackerType::MPRESS: return L"MPRESS";
        case PackerType::MPRESS_v1: return L"MPRESS v1.x";
        case PackerType::MPRESS_v2: return L"MPRESS v2.x";
        case PackerType::Petite: return L"Petite";
        case PackerType::Petite_v1: return L"Petite v1.x";
        case PackerType::Petite_v2: return L"Petite v2.x";
        case PackerType::FSG: return L"FSG";
        case PackerType::FSG_v1: return L"FSG v1.x";
        case PackerType::FSG_v2: return L"FSG v2.x";
        case PackerType::MEW: return L"MEW";
        case PackerType::MEW_v10: return L"MEW v10";
        case PackerType::MEW_v11: return L"MEW v11";
        case PackerType::NsPack: return L"NsPack";
        case PackerType::NsPack_v2: return L"NsPack v2.x";
        case PackerType::NsPack_v3: return L"NsPack v3.x";
        case PackerType::Upack: return L"Upack";
        case PackerType::WinUpack: return L"WinUpack";
        case PackerType::kkrunchy: return L"kkrunchy";
        case PackerType::RLPack: return L"RLPack";

            // Protectors
        case PackerType::Themida: return L"Themida";
        case PackerType::Themida_v1: return L"Themida v1.x";
        case PackerType::Themida_v2: return L"Themida v2.x";
        case PackerType::Themida_v3: return L"Themida v3.x";
        case PackerType::WinLicense: return L"WinLicense";
        case PackerType::VMProtect: return L"VMProtect";
        case PackerType::VMProtect_v1: return L"VMProtect v1.x";
        case PackerType::VMProtect_v2: return L"VMProtect v2.x";
        case PackerType::VMProtect_v3: return L"VMProtect v3.x";
        case PackerType::Enigma: return L"Enigma Protector";
        case PackerType::Enigma_v1: return L"Enigma v1.x";
        case PackerType::Enigma_v4: return L"Enigma v4.x";
        case PackerType::Enigma_v6: return L"Enigma v6.x";
        case PackerType::Enigma_v7: return L"Enigma v7.x";
        case PackerType::ASProtect: return L"ASProtect";
        case PackerType::ASProtect_v1: return L"ASProtect v1.x";
        case PackerType::ASProtect_v2: return L"ASProtect v2.x";
        case PackerType::Armadillo: return L"Armadillo";
        case PackerType::Obsidium: return L"Obsidium";
        case PackerType::PELock: return L"PELock";
        case PackerType::CodeVirtualizer: return L"Code Virtualizer";

            // Crypters
        case PackerType::PESpin: return L"PESpin";
        case PackerType::tElock: return L"tElock";
        case PackerType::YodaCrypter: return L"Yoda's Crypter";
        case PackerType::YodaProtector: return L"Yoda's Protector";

            // .NET Protectors
        case PackerType::ConfuserEx: return L"ConfuserEx";
        case PackerType::DotNetReactor: return L".NET Reactor";
        case PackerType::Eazfuscator: return L"Eazfuscator.NET";
        case PackerType::Dotfuscator: return L"Dotfuscator";
        case PackerType::SmartAssembly: return L"SmartAssembly";

            // Installers
        case PackerType::NSIS: return L"NSIS";
        case PackerType::InnoSetup: return L"Inno Setup";
        case PackerType::InstallShield: return L"InstallShield";

            // SFX Archives
        case PackerType::SevenZip_SFX: return L"7-Zip SFX";
        case PackerType::WinRAR_SFX: return L"WinRAR SFX";
        case PackerType::WinZip_SFX: return L"WinZip SFX";

            // Malware-specific
        case PackerType::Emotet_Packer: return L"Emotet Packer";
        case PackerType::Trickbot_Packer: return L"TrickBot Packer";
        case PackerType::Dridex_Packer: return L"Dridex Packer";
        case PackerType::QakBot_Packer: return L"QakBot Packer";
        case PackerType::Cobalt_Strike_Beacon: return L"Cobalt Strike Beacon";

        case PackerType::Custom_Packer: return L"Custom Packer";
        default: return L"Unknown";
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class PackerDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Infrastructure stores
        std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;
        std::shared_ptr<PatternStore::PatternStore> m_patternStore;
        std::shared_ptr<HashStore::HashStore> m_hashStore;

        /// @brief Detection callback
        PackerDetectionCallback m_detectionCallback;

        /// @brief Statistics
        PackerDetector::Statistics m_stats;

        /// @brief Result cache
        struct CacheEntry {
            PackingInfo result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<std::wstring, CacheEntry> m_resultCache;

        /// @brief Custom EP signatures
        struct CustomEPSignature {
            std::wstring packerName;
            std::vector<uint8_t> signature;
            PackerType type;
        };
        std::vector<CustomEPSignature> m_customEPSignatures;

        /// @brief Custom section patterns
        std::unordered_map<std::string, PackerType> m_customSectionPatterns;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(PackerError* err) noexcept;
        void Shutdown() noexcept;

        // Entropy calculation
        [[nodiscard]] static double CalculateEntropy(const uint8_t* buffer, size_t size) noexcept;

        // PE parsing helpers
        [[nodiscard]] bool IsPEFile(const uint8_t* buffer, size_t size) const noexcept;
        [[nodiscard]] bool ParsePEHeaders(const uint8_t* buffer, size_t size, IMAGE_DOS_HEADER*& dosHeader, IMAGE_NT_HEADERS*& ntHeaders) const noexcept;

        /**
         * @brief Convert RVA to File Offset
         */
        [[nodiscard]] uint32_t RvaToOffset(
            uint32_t rva,
            IMAGE_NT_HEADERS* ntHeaders,
            const uint8_t* buffer,
            size_t size
        ) const noexcept;

        // Section analysis
        [[nodiscard]] bool IsSectionNamePackerMatch(std::string_view sectionName, std::string& matchedPacker) const noexcept;

        // Import analysis
        [[nodiscard]] bool HasMinimalImports(size_t importCount) const noexcept;

        // Installer detection
        [[nodiscard]] bool IsInstallerSection(std::string_view sectionName) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool PackerDetector::Impl::Initialize(PackerError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(L"AntiEvasion", L"PackerDetector: Initializing...");

            // Infrastructure stores are optional (can be set later)
            // No strict dependency on them for initialization

            SS_LOG_INFO(L"AntiEvasion", L"PackerDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"PackerDetector initialization failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"PackerDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void PackerDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            SS_LOG_INFO(L"AntiEvasion", L"PackerDetector: Shutting down...");

            // Clear caches
            m_resultCache.clear();
            m_customEPSignatures.clear();
            m_customSectionPatterns.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            SS_LOG_INFO(L"AntiEvasion", L"PackerDetector: Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"PackerDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: HELPER METHODS
    // ========================================================================

    double PackerDetector::Impl::CalculateEntropy(const uint8_t* buffer, size_t size) noexcept {
        if (!buffer || size == 0) {
            return 0.0;
        }

        try {
            // Count byte frequencies
            std::array<uint64_t, 256> counts{};
            for (size_t i = 0; i < size; ++i) {
                counts[buffer[i]]++;
            }

            // Calculate Shannon entropy
            double entropy = 0.0;
            for (size_t i = 0; i < 256; ++i) {
                if (counts[i] > 0) {
                    const double p = static_cast<double>(counts[i]) / size;
                    entropy -= p * std::log2(p);
                }
            }

            return entropy;
        }
        catch (...) {
            return 0.0;
        }
    }

    bool PackerDetector::Impl::IsPEFile(const uint8_t* buffer, size_t size) const noexcept {
        if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        if (dosHeader->e_lfanew < 0 || static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size) {
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);
        return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
    }

    bool PackerDetector::Impl::ParsePEHeaders(
        const uint8_t* buffer,
        size_t size,
        IMAGE_DOS_HEADER*& dosHeader,
        IMAGE_NT_HEADERS*& ntHeaders
    ) const noexcept {
        if (!IsPEFile(buffer, size)) {
            return false;
        }

        dosHeader = const_cast<IMAGE_DOS_HEADER*>(reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer));
        ntHeaders = const_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew));

        return true;
    }

    uint32_t PackerDetector::Impl::RvaToOffset(
        uint32_t rva,
        IMAGE_NT_HEADERS* ntHeaders,
        const uint8_t* buffer,
        size_t size
    ) const noexcept {
        if (rva == 0 || !ntHeaders || !buffer) return 0;

        const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        const WORD numSections = ntHeaders->FileHeader.NumberOfSections;

        for (WORD i = 0; i < numSections; ++i) {
            // Check if RVA is within this section's virtual range
            if (rva >= sectionHeader[i].VirtualAddress &&
                rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {

                // Calculate offset
                uint32_t offset = sectionHeader[i].PointerToRawData + (rva - sectionHeader[i].VirtualAddress);

                // Validate bounds
                if (offset >= size) return 0;

                return offset;
            }
        }
        return 0;
    }

    bool PackerDetector::Impl::IsSectionNamePackerMatch(
        std::string_view sectionName,
        std::string& matchedPacker
    ) const noexcept {
        // Convert to lowercase for comparison
        std::string lowerName(sectionName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        // Check against known packer sections
        for (const auto& packerSection : PackerConstants::KNOWN_PACKER_SECTIONS) {
            if (lowerName.find(packerSection) != std::string::npos) {
                matchedPacker = std::string(packerSection);
                return true;
            }
        }

        // Check custom patterns
        {
            std::shared_lock lock(m_mutex);
            auto it = m_customSectionPatterns.find(lowerName);
            if (it != m_customSectionPatterns.end()) {
                matchedPacker = lowerName;
                return true;
            }
        }

        return false;
    }

    bool PackerDetector::Impl::HasMinimalImports(size_t importCount) const noexcept {
        return importCount < PackerConstants::SUSPICIOUS_LOW_IMPORT_COUNT;
    }

    bool PackerDetector::Impl::IsInstallerSection(std::string_view sectionName) const noexcept {
        std::string lowerName(sectionName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        for (const auto& installerSection : PackerConstants::INSTALLER_SECTIONS) {
            if (lowerName.find(installerSection) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    PackerDetector::PackerDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    PackerDetector::PackerDetector(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_signatureStore = std::move(sigStore);
    }

    PackerDetector::PackerDetector(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore,
        std::shared_ptr<PatternStore::PatternStore> patternStore,
        std::shared_ptr<HashStore::HashStore> hashStore
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_signatureStore = std::move(sigStore);
        m_impl->m_patternStore = std::move(patternStore);
        m_impl->m_hashStore = std::move(hashStore);
    }

    PackerDetector::~PackerDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    PackerDetector::PackerDetector(PackerDetector&&) noexcept = default;
    PackerDetector& PackerDetector::operator=(PackerDetector&&) noexcept = default;

    bool PackerDetector::Initialize(PackerError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void PackerDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool PackerDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    PackingInfo PackerDetector::AnalyzeFile(
        const std::wstring& filePath,
        const PackerAnalysisConfig& config,
        PackerError* err
    ) noexcept {
        PackingInfo result;
        result.filePath = filePath;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Check cache first
            if (config.enableCaching) {
                std::shared_lock lock(m_impl->m_mutex);
                auto it = m_impl->m_resultCache.find(filePath);

                if (it != m_impl->m_resultCache.end()) {
                    const auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    const auto maxAge = std::chrono::seconds(config.cacheTtlSeconds);

                    if (age < maxAge) {
                        m_impl->m_stats.cacheHits++;
                        result = it->second.result;
                        result.fromCache = true;
                        return result;
                    }
                }
                m_impl->m_stats.cacheMisses++;
            }

            // Check if file exists
            if (!fs::exists(filePath)) {
                if (err) {
                    err->win32Code = ERROR_FILE_NOT_FOUND;
                    err->message = L"File not found";
                    err->context = filePath;
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            // Check file size
            const auto fileSize = fs::file_size(filePath);
            result.fileSize = fileSize;

            if (fileSize > config.maxFileSize) {
                if (err) {
                    err->win32Code = ERROR_FILE_TOO_LARGE;
                    err->message = L"File too large";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            // Read file into memory
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                if (err) {
                    err->win32Code = ERROR_OPEN_FAILED;
                    err->message = L"Failed to open file";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                if (err) {
                    err->win32Code = ERROR_READ_FAULT;
                    err->message = L"Failed to read file";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            // Compute SHA256 hash
            result.sha256Hash = Utils::HashUtils::Compute(Utils::HashUtils::Algorithm::SHA256, buffer.data(), buffer.size(), nullptr);

            // Perform analysis
            AnalyzeFileInternal(buffer.data(), buffer.size(), filePath, config, result);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
            m_impl->m_stats.bytesAnalyzed += fileSize;

            if (result.isPacked) {
                m_impl->m_stats.packedFilesDetected++;
            }

            // Update cache
            if (config.enableCaching) {
                UpdateCache(filePath, result);
            }

            return result;
        }
        catch (const fs::filesystem_error& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeFile filesystem error [%d]: %ls", e.code().value(), Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = static_cast<DWORD>(e.code().value());
                err->message = L"Filesystem error";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeFile failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"AnalyzeFile: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    PackingInfo PackerDetector::AnalyzeBuffer(
        const uint8_t* buffer,
        size_t size,
        const PackerAnalysisConfig& config,
        PackerError* err
    ) noexcept {
        PackingInfo result;
        result.fileSize = size;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            if (!buffer || size == 0) {
                if (err) {
                    err->win32Code = ERROR_INVALID_PARAMETER;
                    err->message = L"Invalid buffer";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Compute SHA256 hash
            result.sha256Hash = Utils::HashUtils::Compute(Utils::HashUtils::Algorithm::SHA256,buffer, size);

            // Perform analysis
            AnalyzeFileInternal(buffer, size, L"[Memory Buffer]", config, result);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
            m_impl->m_stats.bytesAnalyzed += size;

            if (result.isPacked) {
                m_impl->m_stats.packedFilesDetected++;
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeBuffer failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    // ========================================================================
    // BATCH ANALYSIS
    // ========================================================================

    PackerBatchResult PackerDetector::AnalyzeFiles(
        const std::vector<std::wstring>& filePaths,
        const PackerAnalysisConfig& config,
        PackerProgressCallback progressCallback,
        PackerError* err
    ) noexcept {
        PackerBatchResult batchResult;
        batchResult.startTime = std::chrono::system_clock::now();
        batchResult.totalFiles = static_cast<uint32_t>(filePaths.size());

        for (size_t i = 0; i < filePaths.size(); ++i) {
            const auto& filePath = filePaths[i];

            if (progressCallback) {
                try {
                    progressCallback(filePath, static_cast<uint32_t>(i), batchResult.totalFiles);
                }
                catch (...) {
                    // Swallow callback exceptions
                }
            }

            auto result = AnalyzeFile(filePath, config, err);

            if (result.analysisComplete) {
                batchResult.results.push_back(std::move(result));

                if (result.isPacked) {
                    batchResult.packedFiles++;
                    batchResult.packerDistribution[result.primaryPacker]++;
                    batchResult.categoryDistribution[result.packerCategory]++;
                }

                if (result.isInstaller) {
                    batchResult.installerFiles++;
                }
            }
            else {
                batchResult.failedFiles++;
            }
        }

        batchResult.endTime = std::chrono::system_clock::now();
        batchResult.totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            batchResult.endTime - batchResult.startTime).count();

        return batchResult;
    }

    PackerBatchResult PackerDetector::AnalyzeDirectory(
        const std::wstring& directoryPath,
        bool recursive,
        const PackerAnalysisConfig& config,
        PackerProgressCallback progressCallback,
        PackerError* err
    ) noexcept {
        PackerBatchResult batchResult;

        try {
            if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
                if (err) {
                    err->win32Code = ERROR_PATH_NOT_FOUND;
                    err->message = L"Directory not found";
                }
                return batchResult;
            }

            std::vector<std::wstring> filePaths;

            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
                    if (entry.is_regular_file()) {
                        filePaths.push_back(entry.path().wstring());
                    }
                }
            }
            else {
                for (const auto& entry : fs::directory_iterator(directoryPath)) {
                    if (entry.is_regular_file()) {
                        filePaths.push_back(entry.path().wstring());
                    }
                }
            }

            return AnalyzeFiles(filePaths, config, progressCallback, err);
        }
        catch (const fs::filesystem_error& e) {
            if (err) {
                err->win32Code = static_cast<DWORD>(e.code().value());
                err->message = L"Directory enumeration failed";
            }
            return batchResult;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return batchResult;
        }
    }

    // ========================================================================
    // SPECIFIC ANALYSIS METHODS
    // ========================================================================

    double PackerDetector::CalculateEntropy(
        const uint8_t* buffer,
        size_t size
    ) noexcept {
        return Impl::CalculateEntropy(buffer, size);
    }

    double PackerDetector::CalculateSectionEntropy(
        const std::wstring& filePath,
        uint32_t sectionOffset,
        uint32_t sectionSize,
        PackerError* err
    ) noexcept {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                if (err) {
                    err->win32Code = ERROR_OPEN_FAILED;
                    err->message = L"Failed to open file";
                }
                return 0.0;
            }

            file.seekg(sectionOffset);
            std::vector<uint8_t> buffer(sectionSize);
            file.read(reinterpret_cast<char*>(buffer.data()), sectionSize);

            if (!file) {
                if (err) {
                    err->win32Code = ERROR_READ_FAULT;
                    err->message = L"Failed to read section";
                }
                return 0.0;
            }

            return CalculateEntropy(buffer.data(), buffer.size());
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CalculateSectionEntropy failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Section entropy calculation failed";
            }
            return 0.0;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return 0.0;
        }
    }

    bool PackerDetector::AnalyzeSections(
        const std::wstring& filePath,
        std::vector<SectionInfo>& outSections,
        PackerError* err
    ) noexcept {
        try {
            outSections.clear();

            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return false;
            }

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                return false;
            }

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            // Parse sections
            const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            const WORD numSections = ntHeaders->FileHeader.NumberOfSections;

            for (WORD i = 0; i < numSections && i < PackerConstants::MAX_SECTIONS; ++i) {
                SectionInfo section;
                section.name = std::string(reinterpret_cast<const char*>(sectionHeader[i].Name), 8);
                // Remove null padding
                section.name = section.name.c_str();

                section.virtualAddress = sectionHeader[i].VirtualAddress;
                section.virtualSize = sectionHeader[i].Misc.VirtualSize;
                section.rawSize = sectionHeader[i].SizeOfRawData;
                section.rawDataPointer = sectionHeader[i].PointerToRawData;
                section.characteristics = sectionHeader[i].Characteristics;

                section.isExecutable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.isWritable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                section.isReadable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;

                // Calculate section entropy
                if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= fileSize) {
                    const uint8_t* sectionData = buffer.data() + sectionHeader[i].PointerToRawData;
                    section.entropy = CalculateEntropy(sectionData, sectionHeader[i].SizeOfRawData);
                    section.hasHighEntropy = (section.entropy >= PackerConstants::HIGH_SECTION_ENTROPY);
                }

                // Check for empty section
                section.isEmpty = (section.virtualSize > 0 && section.rawSize == 0);

                // Check for packer section name
                std::string matchedPacker;
                if (m_impl->IsSectionNamePackerMatch(section.name, matchedPacker)) {
                    section.isPackerSection = true;
                    section.matchedPackerName = matchedPacker;
                }

                // Detect anomalies
                if (section.isExecutable && section.isWritable) {
                    section.anomalies.push_back(L"Section is both executable and writable");
                }

                if (section.hasHighEntropy && section.isExecutable) {
                    section.anomalies.push_back(L"High entropy in executable section");
                }

                if (section.virtualSize > 0 && section.rawSize == 0) {
                    section.anomalies.push_back(L"Virtual section (no raw data)");
                }

                outSections.push_back(section);
            }

            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeSections failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Section analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::AnalyzeImports(
        const std::wstring& filePath,
        ImportInfo& outImports,
        PackerError* err
    ) noexcept {
        try {
            outImports = ImportInfo{};

            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return false;
            }

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                return false;
            }

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            // Get import directory
            const DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (importRVA == 0) {
                // No imports
                outImports.hasMinimalImports = true;
                outImports.valid = true;
                return true;
            }

            const uint32_t importOffset = m_impl->RvaToOffset(importRVA, ntHeaders, buffer.data(), buffer.size());
            if (importOffset == 0 || importOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buffer.size()) {
                outImports.valid = false;
                return false;
            }

            const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + importOffset);

            while (importDesc->Name != 0 && outImports.dllCount < PackerConstants::MAX_IMPORTS) {
                // Get DLL name
                const uint32_t nameOffset = m_impl->RvaToOffset(importDesc->Name, ntHeaders, buffer.data(), buffer.size());
                if (nameOffset != 0 && nameOffset < buffer.size()) {
                    std::string dllName(reinterpret_cast<const char*>(buffer.data() + nameOffset));
                    outImports.dlls.push_back(dllName);

                    std::string lowerDll = dllName;
                    std::transform(lowerDll.begin(), lowerDll.end(), lowerDll.begin(), ::tolower);

                    if (lowerDll == "kernel32.dll" || lowerDll == "kernelbase.dll") {
                        // We'll inspect functions later if needed
                    }
                }

                // Process imports
                uint32_t thunkRVA = (importDesc->OriginalFirstThunk != 0) ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
                uint32_t thunkOffset = m_impl->RvaToOffset(thunkRVA, ntHeaders, buffer.data(), buffer.size());

                if (thunkOffset != 0 && thunkOffset < buffer.size()) {
                    bool is64Bit = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

                    while (true) {
                        bool isOrdinal = false;
                        uint64_t functionNameRVA = 0;

                        if (is64Bit) {
                            if (thunkOffset + sizeof(uint64_t) > buffer.size()) break;
                            uint64_t thunkData = *reinterpret_cast<const uint64_t*>(buffer.data() + thunkOffset);
                            if (thunkData == 0) break;

                            isOrdinal = (thunkData & 0x8000000000000000ULL) != 0;
                            functionNameRVA = thunkData & 0x7FFFFFFF;
                            thunkOffset += sizeof(uint64_t);
                        } else {
                            if (thunkOffset + sizeof(uint32_t) > buffer.size()) break;
                            uint32_t thunkData = *reinterpret_cast<const uint32_t*>(buffer.data() + thunkOffset);
                            if (thunkData == 0) break;

                            isOrdinal = (thunkData & 0x80000000) != 0;
                            functionNameRVA = thunkData & 0x7FFFFFFF;
                            thunkOffset += sizeof(uint32_t);
                        }

                        outImports.totalImports++;

                        if (!isOrdinal && functionNameRVA != 0) {
                            uint32_t nameOffset = m_impl->RvaToOffset(static_cast<uint32_t>(functionNameRVA), ntHeaders, buffer.data(), buffer.size());
                            if (nameOffset != 0 && nameOffset + 2 < buffer.size()) {
                                // Skip hint (2 bytes)
                                std::string funcName(reinterpret_cast<const char*>(buffer.data() + nameOffset + 2));

                                if (funcName == "GetProcAddress") outImports.hasGetProcAddress = true;
                                else if (funcName == "LoadLibraryA" || funcName == "LoadLibraryW" || funcName == "LoadLibraryExA" || funcName == "LoadLibraryExW") outImports.hasLoadLibrary = true;
                                else if (funcName.find("VirtualAlloc") != std::string::npos || funcName.find("VirtualProtect") != std::string::npos) outImports.hasVirtualMemoryAPIs = true;
                                else if (funcName == "ExitProcess") outImports.anomalies.push_back(L"Explicit ExitProcess import");
                                else if (funcName == "IsDebuggerPresent") outImports.anomalies.push_back(L"IsDebuggerPresent import");
                            }
                        }

                        if (outImports.totalImports >= PackerConstants::MAX_IMPORTS) break;
                    }
                }

                outImports.dllCount++;
                importDesc++;

                // Safety bound check for next descriptor
                if (reinterpret_cast<const uint8_t*>(importDesc) + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buffer.data() + buffer.size()) break;
            }

            outImports.hasMinimalImports = m_impl->HasMinimalImports(outImports.totalImports);
            outImports.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeImports failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Import analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::AnalyzeOverlay(
        const std::wstring& filePath,
        OverlayInfo& outOverlay,
        PackerError* err
    ) noexcept {
        try {
            outOverlay = OverlayInfo{};

            // Read file
            const auto fileSize = fs::file_size(filePath);

            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return false;
            }

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                return false;
            }

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            // Calculate overlay offset (after last section)
            const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            uint64_t maxSectionEnd = 0;

            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                const uint64_t sectionEnd = sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData;
                if (sectionEnd > maxSectionEnd) {
                    maxSectionEnd = sectionEnd;
                }
            }

            if (maxSectionEnd < fileSize) {
                outOverlay.hasOverlay = true;
                outOverlay.offset = maxSectionEnd;
                outOverlay.size = fileSize - maxSectionEnd;
                outOverlay.percentageOfFile = (static_cast<double>(outOverlay.size) / fileSize) * 100.0;

                // Calculate overlay entropy
                if (outOverlay.size <= PackerConstants::MAX_OVERLAY_SIZE) {
                    outOverlay.entropy = CalculateEntropy(buffer.data() + maxSectionEnd, outOverlay.size);
                    outOverlay.isCompressed = (outOverlay.entropy >= PackerConstants::MIN_COMPRESSED_ENTROPY);
                    outOverlay.isEncrypted = (outOverlay.entropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);
                }

                // Copy magic bytes
                const size_t magicSize = std::min<size_t>(16, outOverlay.size);
                std::memcpy(outOverlay.magicBytes.data(), buffer.data() + maxSectionEnd, magicSize);

                outOverlay.valid = true;
            }

            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeOverlay failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Overlay analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::AnalyzeEntryPoint(
        const std::wstring& filePath,
        EntryPointInfo& outEP,
        PackerError* err
    ) noexcept {
        try {
            outEP = EntryPointInfo{};

            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return false;
            }

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                return false;
            }

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            outEP.rva = ntHeaders->OptionalHeader.AddressOfEntryPoint;

            // Find containing section
            const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                if (outEP.rva >= sectionHeader[i].VirtualAddress &&
                    outEP.rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                    outEP.isInValidSection = true;
                    outEP.containingSection = std::string(reinterpret_cast<const char*>(sectionHeader[i].Name), 8);
                    outEP.containingSection = outEP.containingSection.c_str();

                    // Calculate file offset
                    const uint32_t offset = outEP.rva - sectionHeader[i].VirtualAddress;
                    outEP.fileOffset = sectionHeader[i].PointerToRawData + offset;

                    // Check if outside .text/CODE section
                    std::string lowerSection(outEP.containingSection);
                    std::transform(lowerSection.begin(), lowerSection.end(), lowerSection.begin(), ::tolower);
                    outEP.isOutsideCodeSection = (lowerSection.find(".text") == std::string::npos &&
                        lowerSection.find("code") == std::string::npos);

                    break;
                }
            }

            // Read EP bytes for signature matching
            if (outEP.fileOffset + PackerConstants::EP_SIGNATURE_SIZE <= fileSize) {
                outEP.epBytes.resize(PackerConstants::EP_SIGNATURE_SIZE);
                std::memcpy(outEP.epBytes.data(), buffer.data() + outEP.fileOffset, PackerConstants::EP_SIGNATURE_SIZE);
            }

            outEP.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeEntryPoint failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Entry point analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    std::optional<PackerMatch> PackerDetector::MatchEPSignature(
        const uint8_t* epBytes,
        size_t size,
        PackerError* err
    ) noexcept {
        try {
            if (!epBytes || size == 0) {
                return std::nullopt;
            }

            // UPX signature: 60 E8 ?? ?? ?? ?? (PUSHAD; CALL)
            if (size >= 6 && epBytes[0] == 0x60 && epBytes[1] == 0xE8) {
                return PackerMatchBuilder()
                    .Type(PackerType::UPX)
                    .Method(DetectionMethod::EPSignature)
                    .Confidence(0.95)
                    .Name(L"UPX")
                    .Pattern(L"60 E8 ?? ?? ?? ??")
                    .Build();
            }

            // ASPack signature: 60 E8 03 00 00 00
            if (size >= 6 && epBytes[0] == 0x60 && epBytes[1] == 0xE8 &&
                epBytes[2] == 0x03 && epBytes[3] == 0x00 && epBytes[4] == 0x00 && epBytes[5] == 0x00) {
                return PackerMatchBuilder()
                    .Type(PackerType::ASPack)
                    .Method(DetectionMethod::EPSignature)
                    .Confidence(0.9)
                    .Name(L"ASPack")
                    .Pattern(L"60 E8 03 00 00 00")
                    .Build();
            }

            // FSG signature: 87 25 ?? ?? ?? ?? 61 (XCHG [dword], ESP; POPAD)
            if (size >= 7 && epBytes[0] == 0x87 && epBytes[1] == 0x25 && epBytes[6] == 0x61) {
                return PackerMatchBuilder()
                    .Type(PackerType::FSG)
                    .Method(DetectionMethod::EPSignature)
                    .Confidence(0.9)
                    .Name(L"FSG")
                    .Pattern(L"87 25 ?? ?? ?? ?? 61")
                    .Build();
            }

            // PECompact signature: EB 06 68 ?? ?? ?? ??
            if (size >= 7 && epBytes[0] == 0xEB && epBytes[1] == 0x06 && epBytes[2] == 0x68) {
                return PackerMatchBuilder()
                    .Type(PackerType::PECompact)
                    .Method(DetectionMethod::EPSignature)
                    .Confidence(0.85)
                    .Name(L"PECompact")
                    .Pattern(L"EB 06 68 ?? ?? ?? ??")
                    .Build();
            }

            // Check custom signatures
            {
                std::shared_lock lock(m_impl->m_mutex);
                for (const auto& customSig : m_impl->m_customEPSignatures) {
                    if (size >= customSig.signature.size()) {
                        bool match = true;
                        for (size_t i = 0; i < customSig.signature.size(); ++i) {
                            if (customSig.signature[i] != 0xFF && customSig.signature[i] != epBytes[i]) {
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            return PackerMatchBuilder()
                                .Type(customSig.type)
                                .Method(DetectionMethod::EPSignature)
                                .Confidence(0.8)
                                .Name(customSig.packerName)
                                .Pattern(L"Custom")
                                .Build();
                        }
                    }
                }
            }

            return std::nullopt;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"MatchEPSignature failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"EP signature matching failed";
            }
            return std::nullopt;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return std::nullopt;
        }
    }

    bool PackerDetector::VerifySignature(
        const std::wstring& filePath,
        SignatureInfo& outSignature,
        PackerError* err
    ) noexcept {
        try {
            outSignature = SignatureInfo{};
            ShadowStrike::Utils::pe_sig_utils::SignatureInfo verifyResult;
            // Use PE signature verifier from Utils
              m_sigVerifier.VerifyPESignature(filePath, verifyResult,nullptr);

            outSignature.hasSignature = verifyResult.isSigned;
            outSignature.isValid = verifyResult.isVerified;
            outSignature.signerName = verifyResult.signerName;
            outSignature.issuerName = verifyResult.issuerName;
            outSignature.valid = true;

            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"VerifySignature failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Signature verification failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::AnalyzeRichHeader(
        const std::wstring& filePath,
        RichHeaderInfo& outRichHeader,
        PackerError* err
    ) noexcept {
        try {
            outRichHeader = RichHeaderInfo{};

            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            // Read DOS header and stub
            IMAGE_DOS_HEADER dosHeader{};
            file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= sizeof(IMAGE_DOS_HEADER)) {
                return false;
            }

            // Read space between DOS header and NT headers
            const size_t stubSize = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
            if (stubSize < sizeof(DWORD) * 4) return false;

            std::vector<uint8_t> stub(stubSize);
            file.read(reinterpret_cast<char*>(stub.data()), stubSize);

            // Scan for "Rich" signature (0x68636952)
            const uint32_t RICH_SIGNATURE = 0x68636952;
            const uint32_t DANS_SIGNATURE = 0x536E6144; // "DanS"

            // Search for "Rich"
            int richOffset = -1;
            for (size_t i = 0; i < stub.size() - 4; ++i) {
                if (*reinterpret_cast<const uint32_t*>(stub.data() + i) == RICH_SIGNATURE) {
                    richOffset = static_cast<int>(i);
                    break;
                }
            }

            if (richOffset == -1 || richOffset + 8 > stub.size()) {
                outRichHeader.hasRichHeader = false;
                outRichHeader.valid = true;
                return true;
            }

            outRichHeader.hasRichHeader = true;
            uint32_t xorKey = *reinterpret_cast<const uint32_t*>(stub.data() + richOffset + 4);
            outRichHeader.checksum = xorKey;

            // Search backwards for "DanS"
            int dansOffset = -1;
            for (int i = richOffset - 4; i >= 0; i -= 4) {
                if ((*reinterpret_cast<const uint32_t*>(stub.data() + i) ^ xorKey) == DANS_SIGNATURE) {
                    dansOffset = i;
                    break;
                }
            }

            if (dansOffset == -1) {
                outRichHeader.isCorrupted = true;
                outRichHeader.valid = true;
                return true;
            }

            // Parse entries
            const uint8_t* start = stub.data() + dansOffset + 16; // Skip DanS + padding
            const uint8_t* end = stub.data() + richOffset;

            for (const uint8_t* ptr = start; ptr < end; ptr += 8) {
                uint32_t entryKey = *reinterpret_cast<const uint32_t*>(ptr) ^ xorKey;
                uint32_t entryCount = *reinterpret_cast<const uint32_t*>(ptr + 4) ^ xorKey;

                uint16_t prodId = (entryKey >> 16) & 0xFFFF;
                uint16_t buildId = entryKey & 0xFFFF;

                RichHeaderInfo::CompilerEntry entry;
                entry.productId = prodId;
                entry.buildNumber = buildId;
                entry.useCount = entryCount;

                // Identify common Visual Studio versions
                if (prodId == 0x0104) entry.description = L"Visual Studio 2015 C++";
                else if (prodId == 0x0103) entry.description = L"Visual Studio 2015 C++";
                else if (prodId == 0x0102) entry.description = L"Visual Studio 2013 C++";
                else if (prodId == 0x0101) entry.description = L"Visual Studio 2013 C++";
                else if (prodId == 0x0100) entry.description = L"Visual Studio 2012 C++";
                else entry.description = std::format(L"ProdID: {:04X}, Build: {:04X}", prodId, buildId);

                outRichHeader.entries.push_back(entry);

                // Heuristic for compiler detection
                if (entry.description.find(L"Visual Studio") != std::wstring::npos) {
                    outRichHeader.detectedCompiler = entry.description;
                }
            }

            outRichHeader.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeRichHeader failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Rich header analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::AnalyzeResources(
        const std::wstring& filePath,
        ResourceInfo& outResources,
        PackerError* err
    ) noexcept {
        try {
            outResources = ResourceInfo{};

            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) return false;

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            // Get resource directory
            const DWORD resourceRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            const DWORD resourceSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

            if (resourceRVA == 0 || resourceSize == 0) {
                // No resources
                outResources.valid = true;
                return true;
            }

            const uint32_t resourceOffset = m_impl->RvaToOffset(resourceRVA, ntHeaders, buffer.data(), buffer.size());
            if (resourceOffset == 0 || resourceOffset >= buffer.size()) {
                return false;
            }

            const uint8_t* resourceBase = buffer.data() + resourceOffset;
            const auto* rootDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resourceBase);

            // Level 1: Types
            size_t numTypes = rootDir->NumberOfNamedEntries + rootDir->NumberOfIdEntries;
            const auto* typeEntries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(rootDir + 1);

            for (size_t i = 0; i < numTypes; ++i) {
                if (!typeEntries[i].DataIsDirectory) continue;

                // Check for suspicious resource types (often used by packers/droppers)
                if (!typeEntries[i].NameIsString) {
                    uint16_t typeId = typeEntries[i].Id;
                    // RT_RCDATA (10) is commonly used for payloads
                    // RT_BITMAP (2), RT_ICON (3) are common but huge sizes might be suspicious
                }

                // Level 2: Names/IDs
                const auto* typeDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resourceBase + (typeEntries[i].OffsetToDirectory & 0x7FFFFFFF));
                size_t numNames = typeDir->NumberOfNamedEntries + typeDir->NumberOfIdEntries;
                const auto* nameEntries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(typeDir + 1);

                for (size_t j = 0; j < numNames; ++j) {
                    if (!nameEntries[j].DataIsDirectory) continue;

                    // Level 3: Languages
                    const auto* nameDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resourceBase + (nameEntries[j].OffsetToDirectory & 0x7FFFFFFF));
                    size_t numLangs = nameDir->NumberOfNamedEntries + nameDir->NumberOfIdEntries;
                    const auto* langEntries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(nameDir + 1);

                    for (size_t k = 0; k < numLangs; ++k) {
                        if (langEntries[k].DataIsDirectory) continue; // Should be data entry

                        const auto* dataEntry = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(resourceBase + langEntries[k].OffsetToData);

                        uint32_t dataRVA = dataEntry->OffsetToData;
                        uint32_t size = dataEntry->Size;

                        if (size > 0) {
                            uint32_t dataOffset = m_impl->RvaToOffset(dataRVA, ntHeaders, buffer.data(), buffer.size());

                            if (dataOffset != 0 && dataOffset + size <= buffer.size()) {
                                outResources.count++;
                                outResources.totalSize += size;
                                if (size > outResources.largestResourceSize) {
                                    outResources.largestResourceSize = size;
                                }

                                // Calculate entropy for resources > 1KB
                                if (size > 1024) {
                                    double entropy = m_impl->CalculateEntropy(buffer.data() + dataOffset, size);
                                    if (entropy > PackerConstants::HIGH_SECTION_ENTROPY) {
                                        outResources.highEntropyCount++;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (outResources.count > 0) {
                // Simplified avg entropy (not weighted) - for a real implementation, weight by size would be better
                // But we didn't store individual entropies to save memory.
                // We can flag high entropy resources ratio
                if (static_cast<double>(outResources.highEntropyCount) / outResources.count > 0.5) {
                    outResources.averageEntropy = 7.0; // Estimate high
                } else {
                    outResources.averageEntropy = 5.0; // Estimate medium
                }
            }

            outResources.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeResources failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Resource analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::ScanWithYARA(
        const std::wstring& filePath,
        std::vector<PackerMatch>& outMatches,
        PackerError* err
    ) noexcept {
        try {
            outMatches.clear();

            if (!m_impl->m_signatureStore) {
                // Not configured
                return false;
            }

            SignatureStore::ScanOptions options;
            options.enableYaraScan = true;
            options.enableHashLookup = false;
            options.enablePatternScan = false;

            auto scanResult = m_impl->m_signatureStore->ScanFile(filePath, options);

            if (scanResult.HasDetections()) {
                for (const auto& yaraMatch : scanResult.yaraMatches) {
                    PackerMatch match;
                    match.packerType = PackerType::Custom_Packer; // YARA rules can set tags to refine this
                    match.method = DetectionMethod::YARARule;
                    match.confidence = 1.0;
                    match.packerName = Utils::StringUtils::ToWide(yaraMatch.ruleName);

                    // Parse tags/meta to fill in details if available
                    for (const auto& tag : yaraMatch.tags) {
                        if (tag == "packer") match.category = PackerCategory::Custom;
                        else if (tag == "crypter") match.category = PackerCategory::Crypter;
                        // Map other tags to types if needed
                    }

                    match.detectionTime = std::chrono::system_clock::now();
                    outMatches.push_back(match);
                }
                return true;
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"ScanWithYARA failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"YARA scanning failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::GenerateUnpackingHints(
        const PackingInfo& packingInfo,
        UnpackingHints& outHints,
        PackerError* err
    ) noexcept {
        try {
            outHints = UnpackingHints{};

            if (!packingInfo.isPacked) {
                return false;
            }

            // Generate hints based on detected packer
            switch (packingInfo.primaryPacker) {
            case PackerType::UPX:
            case PackerType::UPX_Modified:
            case PackerType::UPX_Scrambled:
                outHints.suggestedTool = L"UPX -d";
                outHints.compressionAlgorithm = L"LZMA/NRV";
                outHints.complexityRating = 2;
                break;

            case PackerType::Themida:
            case PackerType::VMProtect:
            case PackerType::CodeVirtualizer:
                outHints.antiUnpackingTechniques.push_back(L"VM-based protection");
                outHints.antiUnpackingTechniques.push_back(L"Anti-debugging");
                outHints.complexityRating = 9;
                break;

            case PackerType::ASPack:
                outHints.suggestedTool = L"ASPack Unpacker";
                outHints.complexityRating = 3;
                break;

            default:
                outHints.complexityRating = 5;
                break;
            }

            if (packingInfo.hasMultipleLayers) {
                outHints.hasMultipleLayers = true;
                outHints.estimatedLayerCount = packingInfo.layerCount;
                outHints.complexityRating += 2;
            }

            outHints.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"GenerateUnpackingHints failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Hint generation failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::IsInstaller(
        const std::wstring& filePath,
        std::wstring& installerType,
        PackerError* err
    ) noexcept {
        try {
            std::vector<SectionInfo> sections;
            if (!AnalyzeSections(filePath, sections, err)) {
                return false;
            }

            for (const auto& section : sections) {
                if (m_impl->IsInstallerSection(section.name)) {
                    // Determine installer type from section name
                    std::string lowerName(section.name);
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                    if (lowerName.find("nsis") != std::string::npos || lowerName.find("ndata") != std::string::npos) {
                        installerType = L"NSIS";
                    }
                    else if (lowerName.find("inno") != std::string::npos) {
                        installerType = L"Inno Setup";
                    }
                    else if (lowerName.find(".is") != std::string::npos) {
                        installerType = L"InstallShield";
                    }
                    else {
                        installerType = L"Generic Installer";
                    }

                    return true;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"IsInstaller failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Installer detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool PackerDetector::IsDotNetAssembly(
        const std::wstring& filePath,
        PackerError* err
    ) noexcept {
        try {
            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                return false;
            }

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                return false;
            }

            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), dosHeader, ntHeaders)) {
                return false;
            }

            // Check for .NET metadata directory (CLR Runtime Header)
            const DWORD clrRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
            return (clrRVA != 0);
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"IsDotNetAssembly failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L".NET detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    // ========================================================================
    // REAL-TIME DETECTION
    // ========================================================================

    void PackerDetector::SetDetectionCallback(PackerDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void PackerDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    std::optional<PackingInfo> PackerDetector::GetCachedResult(
        const std::wstring& filePath
    ) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(filePath);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void PackerDetector::InvalidateCache(const std::wstring& filePath) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(filePath);
    }

    void PackerDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t PackerDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    void PackerDetector::UpdateCache(
        const std::wstring& filePath,
        const PackingInfo& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit
            if (m_impl->m_resultCache.size() >= PackerConstants::MAX_CACHE_ENTRIES) {
                // Remove oldest entry
                auto oldest = m_impl->m_resultCache.begin();
                for (auto it = m_impl->m_resultCache.begin(); it != m_impl->m_resultCache.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                m_impl->m_resultCache.erase(oldest);
            }

            Impl::CacheEntry entry;
            entry.result = result;
            entry.timestamp = std::chrono::steady_clock::now();

            m_impl->m_resultCache[filePath] = std::move(entry);
        }
        catch (...) {
            // Cache update failure is non-fatal
        }
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void PackerDetector::SetSignatureStore(std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_signatureStore = std::move(sigStore);
    }

    void PackerDetector::SetPatternStore(std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_patternStore = std::move(patternStore);
    }

    void PackerDetector::SetHashStore(std::shared_ptr<HashStore::HashStore> hashStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_hashStore = std::move(hashStore);
    }

    void PackerDetector::AddCustomEPSignature(
        std::wstring_view packerName,
        const std::vector<uint8_t>& signature,
        PackerType type
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);

        Impl::CustomEPSignature custom;
        custom.packerName = packerName;
        custom.signature = signature;
        custom.type = type;

        m_impl->m_customEPSignatures.push_back(std::move(custom));
    }

    void PackerDetector::AddCustomSectionPattern(
        std::string_view sectionName,
        PackerType type
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customSectionPatterns[std::string(sectionName)] = type;
    }

    void PackerDetector::ClearCustomPatterns() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customEPSignatures.clear();
        m_impl->m_customSectionPatterns.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const PackerDetector::Statistics& PackerDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void PackerDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    void PackerDetector::AnalyzeFileInternal(
        const uint8_t* buffer,
        size_t size,
        const std::wstring& filePath,
        const PackerAnalysisConfig& config,
        PackingInfo& result
    ) noexcept {
        // Entropy analysis
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableEntropyAnalysis)) {
            AnalyzeEntropyDistribution(buffer, size, result);
        }

        // PE structure analysis
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableSectionAnalysis)) {
            AnalyzePEStructure(buffer, size, result);
        }

        // Entry point signature matching
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableEPSignature) && !filePath.empty()) {
            EntryPointInfo epInfo;
            if (AnalyzeEntryPoint(filePath, epInfo, nullptr)) {
                result.entryPointInfo = epInfo;

                if (!epInfo.epBytes.empty()) {
                    auto epMatch = MatchEPSignature(epInfo.epBytes.data(), epInfo.epBytes.size(), nullptr);
                    if (epMatch) {
                        AddMatch(result, std::move(*epMatch));
                    }
                }
            }
        }

        // Import analysis
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableImportAnalysis) && !filePath.empty()) {
            AnalyzeImports(filePath, result.importInfo, nullptr);
        }

        // Overlay analysis
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableOverlayAnalysis) && !filePath.empty()) {
            AnalyzeOverlay(filePath, result.overlayInfo, nullptr);
        }

        // Signature verification
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableSignatureVerification) && !filePath.empty()) {
            VerifySignature(filePath, result.signatureInfo, nullptr);
        }

        // Check if installer
        if (!filePath.empty()) {
            std::wstring installerType;
            if (IsInstaller(filePath, installerType, nullptr)) {
                result.isInstaller = true;

                if (config.treatInstallersAsBenign) {
                    m_impl->m_stats.installersDetected++;
                    // Don't flag as packed if it's an installer
                    DeterminePackingVerdict(result);
                    return;
                }
            }
        }

        // Check if .NET assembly
        if (!filePath.empty() && IsDotNetAssembly(filePath, nullptr)) {
            result.isDotNetAssembly = true;
        }

        // Signature matching
        MatchPackerSignatures(buffer, size, result);

        // Heuristic analysis
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableHeuristicAnalysis)) {
            PerformHeuristicAnalysis(buffer, size, result);
        }

        // YARA scanning
        if (HasFlag(config.flags, PackerAnalysisFlags::EnableYARAScanning) && !filePath.empty()) {
            std::vector<PackerMatch> yaraMatches;
            if (ScanWithYARA(filePath, yaraMatches, nullptr)) {
                for (auto& match : yaraMatches) {
                    AddMatch(result, std::move(match));
                }
            }
        }

        // Unpacking hints
        if (HasFlag(config.flags, PackerAnalysisFlags::IncludeUnpackingHints)) {
            GenerateUnpackingHints(result, result.unpackingHints, nullptr);
        }

        // Final verdict
        DeterminePackingVerdict(result);
    }

    void PackerDetector::AnalyzeEntropyDistribution(
        const uint8_t* buffer,
        size_t size,
        PackingInfo& result
    ) noexcept {
        try {
            // Calculate overall file entropy
            result.fileEntropy = CalculateEntropy(buffer, size);

            result.entropyIndicatesCompression = (result.fileEntropy >= PackerConstants::MIN_COMPRESSED_ENTROPY);
            result.entropyIndicatesEncryption = (result.fileEntropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);

            if (result.entropyIndicatesEncryption) {
                result.indicators.push_back(L"Very high entropy (likely encrypted)");
            }
            else if (result.entropyIndicatesCompression) {
                result.indicators.push_back(L"High entropy (likely compressed)");
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeEntropyDistribution: Exception");
        }
    }

    void PackerDetector::AnalyzePEStructure(
        const uint8_t* buffer,
        size_t size,
        PackingInfo& result
    ) noexcept {
        try {
            IMAGE_DOS_HEADER* dosHeader = nullptr;
            IMAGE_NT_HEADERS* ntHeaders = nullptr;

            if (!m_impl->ParsePEHeaders(buffer, size, dosHeader, ntHeaders)) {
                return;
            }

            // Parse sections
            const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            const WORD numSections = ntHeaders->FileHeader.NumberOfSections;

            result.sectionCount = numSections;

            for (WORD i = 0; i < numSections && i < PackerConstants::MAX_SECTIONS; ++i) {
                SectionInfo section;
                section.name = std::string(reinterpret_cast<const char*>(sectionHeader[i].Name), 8);
                section.name = section.name.c_str();

                section.virtualAddress = sectionHeader[i].VirtualAddress;
                section.virtualSize = sectionHeader[i].Misc.VirtualSize;
                section.rawSize = sectionHeader[i].SizeOfRawData;
                section.rawDataPointer = sectionHeader[i].PointerToRawData;
                section.characteristics = sectionHeader[i].Characteristics;

                section.isExecutable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.isWritable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                section.isReadable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;

                if (section.isExecutable) {
                    result.executableSectionCount++;
                }

                if (section.isWritable) {
                    result.writableSectionCount++;
                }

                // Calculate section entropy
                if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= size) {
                    const uint8_t* sectionData = buffer + sectionHeader[i].PointerToRawData;
                    section.entropy = CalculateEntropy(sectionData, sectionHeader[i].SizeOfRawData);
                    section.hasHighEntropy = (section.entropy >= PackerConstants::HIGH_SECTION_ENTROPY);

                    if (section.hasHighEntropy) {
                        result.highEntropySectionCount++;
                    }

                    // Track max entropy section
                    if (section.entropy > result.maxSectionEntropy) {
                        result.maxSectionEntropy = section.entropy;
                        result.maxEntropySectionName = section.name;
                    }
                }

                // Check for packer section name
                std::string matchedPacker;
                if (m_impl->IsSectionNamePackerMatch(section.name, matchedPacker)) {
                    section.isPackerSection = true;
                    section.matchedPackerName = matchedPacker;
                    result.packerSectionMatches++;

                    // Create match from section name
                    PackerType type = PackerType::Unknown;

                    if (matchedPacker.find("upx") != std::string::npos) {
                        type = PackerType::UPX;
                    }
                    else if (matchedPacker.find("aspack") != std::string::npos) {
                        type = PackerType::ASPack;
                    }
                    else if (matchedPacker.find("pec") != std::string::npos) {
                        type = PackerType::PECompact;
                    }
                    else if (matchedPacker.find("themida") != std::string::npos || matchedPacker.find("winlicen") != std::string::npos) {
                        type = PackerType::Themida;
                    }
                    else if (matchedPacker.find("vmp") != std::string::npos) {
                        type = PackerType::VMProtect;
                    }

                    if (type != PackerType::Unknown) {
                        auto match = PackerMatchBuilder()
                            .Type(type)
                            .Method(DetectionMethod::SectionName)
                            .Confidence(0.9)
                            .Name(PackerTypeToString(type))
                            .Pattern(Utils::StringUtils::ToWide(matchedPacker))
                            .Build();

                        AddMatch(result, std::move(match));
                    }
                }

                // Detect anomalies
                if (section.isExecutable && section.isWritable) {
                    section.anomalies.push_back(L"Writable executable section");
                    result.hasWritableCodeSections = true;
                }

                result.sections.push_back(section);
            }

            // Calculate average section entropy
            if (!result.sections.empty()) {
                double totalEntropy = 0.0;
                for (const auto& sec : result.sections) {
                    totalEntropy += sec.entropy;
                }
                result.averageSectionEntropy = totalEntropy / result.sections.size();
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzePEStructure: Exception");
        }
    }

    void PackerDetector::MatchPackerSignatures(
        const uint8_t* buffer,
        size_t size,
        PackingInfo& result
    ) noexcept {
        try {
            // Section name-based detection is handled in AnalyzePEStructure.
            // This method integrates with PatternStore for byte signature scanning.

            if (!m_impl->m_patternStore || !m_impl->m_patternStore->IsInitialized()) {
                return;
            }

            // Configure scan options
            ShadowStrike::PatternStore::QueryOptions options;
            options.maxResults = 5; // Limit matches to avoid noise
            options.earylexit = false;

            // Scan the buffer using PatternStore (Aho-Corasick / SIMD)
            // We use a span to avoid copying
            auto matches = m_impl->m_patternStore->Scan(std::span<const uint8_t>(buffer, size), options);

            for (const auto& match : matches) {
                // Map PatternStore detection to PackerMatch
                PackerMatch pm;
                pm.packerType = PackerType::Custom_Packer; // Default, can be refined based on tags
                pm.packerName = Utils::StringUtils::ToWide(match.signatureName);
                pm.confidence = 0.95; // Byte signatures are usually high confidence
                pm.method = DetectionMethod::HashMatch; // Or BytePattern
                pm.matchLocation = match.offset;
                pm.details = L"Matched pattern: " + Utils::StringUtils::ToWide(match.signatureName);
                pm.detectionTime = std::chrono::system_clock::now();

                // Attempt to determine category from tags if available in PatternStore results
                // (Assuming PatternStore might return tags or we infer from name)
                if (pm.packerName.find(L"UPX") != std::wstring::npos) {
                    pm.packerType = PackerType::UPX;
                    pm.category = PackerCategory::Compression;
                }
                else if (pm.packerName.find(L"Themida") != std::wstring::npos) {
                    pm.packerType = PackerType::Themida;
                    pm.category = PackerCategory::Protector;
                }

                AddMatch(result, std::move(pm));
            }
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"MatchPackerSignatures exception: %ls", Utils::StringUtils::ToWide(e.what()).c_str());
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"MatchPackerSignatures: Unknown exception");
        }
    }

    void PackerDetector::PerformHeuristicAnalysis(
        const uint8_t* buffer,
        size_t size,
        PackingInfo& result
    ) noexcept {
        try {
            // Heuristic 1: High entropy + minimal imports
            if (result.fileEntropy >= PackerConstants::HIGH_SECTION_ENTROPY &&
                result.importInfo.hasMinimalImports) {
                result.indicators.push_back(L"High entropy with minimal imports");
            }

            // Heuristic 2: Entry point outside .text section
            if (result.entryPointInfo.isOutsideCodeSection) {
                result.epOutsideCodeSection = true;
                result.indicators.push_back(L"Entry point outside code section");
            }

            // Heuristic 3: Large overlay
            if (result.overlayInfo.hasOverlay &&
                result.overlayInfo.percentageOfFile >= PackerConstants::SUSPICIOUS_OVERLAY_PERCENTAGE) {
                result.indicators.push_back(std::format(L"Large overlay ({:.1f}% of file)", result.overlayInfo.percentageOfFile));
            }

            // Heuristic 4: Multiple high-entropy sections
            if (result.highEntropySectionCount >= 2) {
                result.indicators.push_back(L"Multiple high-entropy sections");
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"PerformHeuristicAnalysis: Exception");
        }
    }

    void PackerDetector::DeterminePackingVerdict(PackingInfo& result) noexcept {
        try {
            // Calculate confidence based on matches
            double totalConfidence = 0.0;
            size_t matchCount = result.packerMatches.size();

            for (const auto& match : result.packerMatches) {
                totalConfidence += match.confidence;
            }

            if (matchCount > 0) {
                result.packingConfidence = totalConfidence / matchCount;
                result.isPacked = (result.packingConfidence >= PackerConstants::MIN_PACKING_CONFIDENCE);

                // Set primary packer (highest confidence)
                const auto* bestMatch = result.GetBestMatch();
                if (bestMatch) {
                    result.primaryPacker = bestMatch->packerType;
                    result.packerName = bestMatch->packerName;
                    result.packerVersion = bestMatch->version;
                    result.packerCategory = bestMatch->category;
                    result.severity = bestMatch->severity;
                }
            }
            else if (!result.indicators.empty()) {
                // Heuristic-based verdict
                const size_t indicatorCount = result.indicators.size();
                result.packingConfidence = std::min(0.3 + (indicatorCount * 0.1), 0.8);
                result.isPacked = (indicatorCount >= 2);
                result.primaryPacker = PackerType::Custom_Packer;
                result.packerName = L"Unknown Packer (Heuristic)";
                result.packerCategory = PackerCategory::Custom;
                result.severity = PackerSeverity::Medium;
            }

            // Update statistics based on category
            if (result.isPacked) {
                const auto catIdx = static_cast<uint32_t>(result.packerCategory);
                if (catIdx < 16) {
                    m_impl->m_stats.categoryDetections[catIdx]++;
                }

                if (result.packerCategory == PackerCategory::Crypter) {
                    m_impl->m_stats.cryptersDetected++;
                }
                else if (result.packerCategory == PackerCategory::Protector || result.packerCategory == PackerCategory::VMProtection) {
                    m_impl->m_stats.protectorsDetected++;
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"DeterminePackingVerdict: Exception");
        }
    }

    void PackerDetector::AddMatch(
        PackingInfo& result,
        PackerMatch match
    ) noexcept {
        // Invoke callback if set
        if (m_impl->m_detectionCallback) {
            try {
                m_impl->m_detectionCallback(result.filePath, match);
            }
            catch (...) {
                // Swallow callback exceptions
            }
        }

        result.packerMatches.push_back(std::move(match));
    }

} // namespace ShadowStrike::AntiEvasion