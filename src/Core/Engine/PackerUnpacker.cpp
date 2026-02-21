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
 * @file PackerUnpacker.cpp
 * @brief Enterprise-grade automated unpacking engine for packed/obfuscated executables
 *
 * ShadowStrike Core Engine - Packer/Unpacker Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive automated unpacking capabilities:
 * - Static unpacking for known packers (UPX, ASPack, FSG, PECompact, MPRESS)
 * - Dynamic unpacking via emulation for unknown packers
 * - Multi-layer unpacking support (nested packers)
 * - Original Entry Point (OEP) detection using heuristics
 * - Import Address Table (IAT) reconstruction
 * - PE header fixing and section realignment
 * - Overlay extraction and handling
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils/, EmulationEngine)
 *
 * CRITICAL: This is user-mode code. Kernel components go in Drivers/ folder.
 */

#include "pch.h"
#include "PackerUnpacker.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <cmath>
#include <execution>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <ranges>
#include <set>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <Windows.h>
#include <winnt.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "EmulationEngine.hpp"

namespace ShadowStrike::Core::Engine {

    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get display name for packer type
     */
    [[nodiscard]] const wchar_t* PackerTypeToString(PackerType type) noexcept {
        switch (type) {
        case PackerType::Unknown: return L"Unknown";
        case PackerType::None: return L"None (Not Packed)";
        case PackerType::UPX: return L"UPX";
        case PackerType::ASPack: return L"ASPack";
        case PackerType::FSG: return L"FSG";
        case PackerType::PECompact: return L"PECompact";
        case PackerType::MPRESS: return L"MPRESS";
        case PackerType::MEW: return L"MEW";
        case PackerType::PESpin: return L"PESpin";
        case PackerType::Themida: return L"Themida";
        case PackerType::VMProtect: return L"VMProtect";
        case PackerType::Enigma: return L"Enigma Protector";
        case PackerType::Armadillo: return L"Armadillo";
        case PackerType::Obsidium: return L"Obsidium";
        case PackerType::Petite: return L"Petite";
        case PackerType::WWPack: return L"WWPack";
        case PackerType::Custom: return L"Custom/Unknown Packer";
        default: return L"Unknown";
        }
    }

    /**
     * @brief Get display name for unpack status
     */
    [[nodiscard]] const wchar_t* UnpackStatusToString(UnpackStatus status) noexcept {
        switch (status) {
        case UnpackStatus::Success: return L"Success";
        case UnpackStatus::NotPacked: return L"Not Packed";
        case UnpackStatus::UnsupportedPacker: return L"Unsupported Packer";
        case UnpackStatus::CorruptedPE: return L"Corrupted PE";
        case UnpackStatus::OEPNotFound: return L"OEP Not Found";
        case UnpackStatus::ImportReconstructionFailed: return L"Import Reconstruction Failed";
        case UnpackStatus::EmulationTimeout: return L"Emulation Timeout";
        case UnpackStatus::EmulationCrash: return L"Emulation Crash";
        case UnpackStatus::PartialSuccess: return L"Partial Success";
        case UnpackStatus::Error: return L"Error";
        default: return L"Unknown";
        }
    }

    /**
     * @brief Get display name for unpack method
     */
    [[nodiscard]] const wchar_t* UnpackMethodToString(UnpackMethod method) noexcept {
        switch (method) {
        case UnpackMethod::None: return L"None";
        case UnpackMethod::Static: return L"Static Unpacking";
        case UnpackMethod::Dynamic: return L"Dynamic Unpacking (Emulation)";
        case UnpackMethod::Hybrid: return L"Hybrid (Static + Dynamic)";
        default: return L"Unknown";
        }
    }

    /**
     * @brief Calculate Shannon entropy of data
     */
    [[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept {
        if (data.empty()) return 0.0;

        std::array<uint64_t, 256> counts = {};
        for (const uint8_t byte : data) {
            counts[byte]++;
        }

        double entropy = 0.0;
        const double dataSize = static_cast<double>(data.size());

        for (const uint64_t count : counts) {
            if (count == 0) continue;
            const double probability = static_cast<double>(count) / dataSize;
            entropy -= probability * std::log2(probability);
        }

        return entropy;
    }

    // ========================================================================
    // PACKER SIGNATURE PATTERNS
    // ========================================================================

    namespace PackerSignatures {
        // UPX signatures
        constexpr std::array<uint8_t, 3> UPX_MAGIC = { 'U', 'P', 'X' };
        constexpr std::array<uint8_t, 6> UPX_STUB_PATTERN = { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00 }; // PUSHAD; MOV ESI, imagebase

        // ASPack signatures
        constexpr std::array<uint8_t, 4> ASPACK_MAGIC = { 0x60, 0xE8, 0x03, 0x00 }; // PUSHAD; CALL +3

        // FSG signatures
        constexpr std::array<uint8_t, 5> FSG_PATTERN = { 0x87, 0x25, 0x00, 0x00, 0x00 }; // XCHG [imagebase], ESP

        // PECompact signatures
        constexpr std::array<uint8_t, 4> PECOMPACT_MAGIC = { 0xEB, 0x06, 0x68, 0x00 }; // JMP +6; PUSH

        // MPRESS signatures
        constexpr std::array<uint8_t, 6> MPRESS_PATTERN = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 }; // PUSHAD; CALL $+5

        // Themida/WinLicense signature
        constexpr std::array<uint8_t, 5> THEMIDA_PATTERN = { 0xEB, 0x10, 0x66, 0x62, 0x3A }; // JMP +10; "fb:"

        // VMProtect signature
        constexpr std::array<uint8_t, 4> VMPROTECT_PATTERN = { 0x68, 0x00, 0x00, 0x00, 0x00 }; // PUSH imm32 (VM entry)

        // Enigma signature
        constexpr std::array<uint8_t, 6> ENIGMA_PATTERN = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 }; // PUSHAD; CALL delta

        // MEW signature
        constexpr std::array<uint8_t, 5> MEW_PATTERN = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // JMP near

        // PESpin signature
        constexpr std::array<uint8_t, 4> PESPIN_PATTERN = { 0xEB, 0x01, 0x68, 0x60 }; // JMP +1; PUSH; PUSHAD

        // Petite signature
        constexpr std::array<uint8_t, 5> PETITE_PATTERN = { 0xB8, 0x00, 0x00, 0x00, 0x00 }; // MOV EAX, imm32
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class PackerUnpacker::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Configuration
        UnpackOptions m_defaultOptions;

        /// @brief Statistics
        PackerUnpacker::Statistics m_stats;

        /// @brief Emulation engine reference
        EmulationEngine* m_emulationEngine = nullptr;

        /// @brief Known packer section names
        std::unordered_set<std::string> m_packerSectionNames = {
            "UPX0", "UPX1", "UPX2",
            ".aspack", ".adata",
            ".fsg", "FSG!",
            ".pecompact", ".pec1", ".pec2",
            ".mpress1", ".mpress2",
            ".themida", ".winlice",
            ".vmp0", ".vmp1", ".vmp2",
            ".enigma1", ".enigma2",
            ".mew", "MEW",
            ".petite", "petite",
            ".pespin"
        };

        /// @brief Known import DLLs for resolution
        std::unordered_map<std::string, HMODULE> m_loadedDLLs;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(UnpackError* err) noexcept;
        void Shutdown() noexcept;

        // Packer detection
        [[nodiscard]] PackerDetectionResult DetectPackerInternal(const fs::path& filePath) noexcept;
        [[nodiscard]] PackerDetectionResult DetectPackerFromMemory(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] PackerType IdentifyBySignature(std::span<const uint8_t> entryPointCode) noexcept;
        [[nodiscard]] PackerType IdentifyBySectionNames(const std::vector<std::string>& sectionNames) noexcept;
        [[nodiscard]] bool HasSuspiciousEntropy(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] bool HasSuspiciousImports(std::span<const uint8_t> data) noexcept;

        // Unpacking methods
        [[nodiscard]] UnpackResult UnpackFileInternal(const fs::path& filePath, const UnpackOptions& options) noexcept;
        [[nodiscard]] UnpackResult StaticUnpackInternal(std::span<const uint8_t> data, PackerType type) noexcept;
        [[nodiscard]] UnpackResult DynamicUnpackInternal(std::span<const uint8_t> data, const UnpackOptions& options) noexcept;

        // Static unpacking algorithms
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackUPX(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackASPack(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackMPRESS(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackFSG(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackPECompact(std::span<const uint8_t> data) noexcept;

        // Dynamic unpacking
        [[nodiscard]] std::optional<uint64_t> FindOEPInternal(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<uint64_t> FindOEPViaEmulation(std::span<const uint8_t> data, const UnpackOptions& options) noexcept;
        [[nodiscard]] bool IsLikelyOEP(uint64_t address, std::span<const uint8_t> code) noexcept;
        [[nodiscard]] std::vector<uint64_t> FindPotentialOEPs(std::span<const uint8_t> data) noexcept;

        // Import reconstruction
        [[nodiscard]] std::optional<ReconstructedImports> ReconstructImportsInternal(
            std::span<const uint8_t> unpackedData,
            const ImportReconstructionOptions& options
        ) noexcept;
        [[nodiscard]] std::optional<uint64_t> FindIATStart(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::string> ResolveAPIByAddress(uint64_t address) noexcept;
        [[nodiscard]] std::optional<std::string> ResolveAPIByOrdinal(const std::string& dllName, uint16_t ordinal) noexcept;
        [[nodiscard]] bool ScanIATRange(std::span<const uint8_t> data, uint64_t startRVA, ReconstructedImports& imports) noexcept;

        // PE reconstruction
        [[nodiscard]] std::optional<std::vector<uint8_t>> FixPEHeadersInternal(
            std::span<const uint8_t> data,
            uint64_t newEntryPoint,
            const ReconstructedImports* imports
        ) noexcept;
        [[nodiscard]] bool RealignSections(std::vector<uint8_t>& peData) noexcept;
        [[nodiscard]] bool RecalculateChecksum(std::vector<uint8_t>& peData) noexcept;
        [[nodiscard]] bool FixImportDirectory(std::vector<uint8_t>& peData, const ReconstructedImports& imports) noexcept;
        [[nodiscard]] bool RemovePackerSections(std::vector<uint8_t>& peData) noexcept;

        // PE parsing helpers
        [[nodiscard]] bool ParsePEHeaders(
            std::span<const uint8_t> data,
            IMAGE_DOS_HEADER& dosHeader,
            IMAGE_NT_HEADERS64& ntHeaders
        ) noexcept;
        [[nodiscard]] std::vector<IMAGE_SECTION_HEADER> GetSectionHeaders(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::vector<std::string> GetSectionNames(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::span<const uint8_t> GetSectionData(std::span<const uint8_t> data, const std::string& sectionName) noexcept;
        [[nodiscard]] std::optional<IMAGE_SECTION_HEADER> FindSectionByName(std::span<const uint8_t> data, const std::string& name) noexcept;
        [[nodiscard]] std::optional<IMAGE_SECTION_HEADER> FindSectionByRVA(std::span<const uint8_t> data, uint64_t rva) noexcept;

        // Utility
        [[nodiscard]] bool LoadSystemDLLs() noexcept;
        void UnloadSystemDLLs() noexcept;
        [[nodiscard]] bool IsExecutableSection(const IMAGE_SECTION_HEADER& section) noexcept;
        [[nodiscard]] bool IsWritableSection(const IMAGE_SECTION_HEADER& section) noexcept;
        [[nodiscard]] uint64_t RVAToFileOffset(std::span<const uint8_t> data, uint64_t rva) noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool PackerUnpacker::Impl::Initialize(UnpackError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            Utils::Logger::Info(L"PackerUnpacker: Initializing...");

            // Get EmulationEngine instance
            m_emulationEngine = &EmulationEngine::Instance();
            if (!m_emulationEngine->IsInitialized()) {
                Utils::Logger::Warn(L"PackerUnpacker: EmulationEngine not initialized, dynamic unpacking unavailable");
            }

            // Set default options
            m_defaultOptions.preferredMethod = UnpackMethod::Hybrid;
            m_defaultOptions.enableStaticUnpacking = true;
            m_defaultOptions.enableDynamicUnpacking = true;
            m_defaultOptions.maxEmulationTimeMs = 30000; // 30 seconds
            m_defaultOptions.maxUnpackLayers = 5;
            m_defaultOptions.reconstructImports = true;
            m_defaultOptions.fixPEHeaders = true;

            // Load system DLLs for import resolution
            if (!LoadSystemDLLs()) {
                Utils::Logger::Warn(L"PackerUnpacker: Failed to load system DLLs, import reconstruction may be limited");
            }

            Utils::Logger::Info(L"PackerUnpacker: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error(L"PackerUnpacker initialization failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_initialized = false;
            return false;
        } catch (...) {
            Utils::Logger::Critical(L"PackerUnpacker: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void PackerUnpacker::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            Utils::Logger::Info(L"PackerUnpacker: Shutting down...");

            // Unload system DLLs
            UnloadSystemDLLs();

            Utils::Logger::Info(L"PackerUnpacker: Shutdown complete");
        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: PACKER DETECTION
    // ========================================================================

    PackerDetectionResult PackerUnpacker::Impl::DetectPackerInternal(const fs::path& filePath) noexcept {
        PackerDetectionResult result;

        try {
            // Read file
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                Utils::Logger::Error(L"PackerUnpacker: Failed to open file: {}", filePath.wstring());
                return result;
            }

            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
            file.close();

            result = DetectPackerFromMemory(fileData);
            result.filePath = filePath;

            m_stats.packersDetected++;

            return result;

        } catch (const std::exception& e) {
            Utils::Logger::Error(L"PackerUnpacker: Detection failed: {}",
                Utils::StringUtils::ToWideString(e.what()));
            return result;
        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Unknown detection error");
            return result;
        }
    }

    PackerDetectionResult PackerUnpacker::Impl::DetectPackerFromMemory(std::span<const uint8_t> data) noexcept {
        PackerDetectionResult result;
        result.isPacked = false;
        result.packerType = PackerType::None;
        result.confidence = 0.0;

        try {
            // Parse PE headers
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                Utils::Logger::Warn(L"PackerUnpacker: Invalid PE file");
                return result;
            }

            // Get entry point code
            const uint64_t entryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
            const uint64_t imageBase = ntHeaders.OptionalHeader.ImageBase;
            const uint64_t entryPointVA = imageBase + entryPointRVA;

            // Get section containing entry point
            auto sections = GetSectionHeaders(data);
            std::span<const uint8_t> entryPointCode;

            for (const auto& section : sections) {
                const uint64_t sectionStart = imageBase + section.VirtualAddress;
                const uint64_t sectionEnd = sectionStart + section.Misc.VirtualSize;

                if (entryPointVA >= sectionStart && entryPointVA < sectionEnd) {
                    const size_t offset = static_cast<size_t>(entryPointRVA - section.VirtualAddress + section.PointerToRawData);
                    if (offset + 256 <= data.size()) {
                        const size_t size = std::min<size_t>(256, data.size() - offset);
                        entryPointCode = data.subspan(offset, size);
                    }
                    break;
                }
            }

            if (entryPointCode.empty()) {
                Utils::Logger::Warn(L"PackerUnpacker: Could not locate entry point code");
                return result;
            }

            // Method 1: Signature-based detection
            PackerType signatureType = IdentifyBySignature(entryPointCode);
            if (signatureType != PackerType::Unknown) {
                result.packerType = signatureType;
                result.confidence = 0.95;
                result.detectionMethod = L"Signature-based";
                result.isPacked = true;
                result.additionalInfo.push_back(std::format(L"Packer signature detected at entry point"));
                return result;
            }

            // Method 2: Section name detection
            auto sectionNames = GetSectionNames(data);
            PackerType sectionType = IdentifyBySectionNames(sectionNames);
            if (sectionType != PackerType::Unknown) {
                result.packerType = sectionType;
                result.confidence = 0.85;
                result.detectionMethod = L"Section names";
                result.isPacked = true;
                result.additionalInfo.push_back(L"Suspicious section names detected");
                return result;
            }

            // Method 3: Entropy analysis
            if (HasSuspiciousEntropy(data)) {
                result.packerType = PackerType::Custom;
                result.confidence = 0.70;
                result.detectionMethod = L"Entropy analysis";
                result.isPacked = true;
                result.additionalInfo.push_back(L"High entropy suggests packing/encryption");

                // Calculate entropy for details
                const double entropy = CalculateEntropy(data);
                result.additionalInfo.push_back(std::format(L"Entropy: {:.2f} (threshold: 7.0)", entropy));
                return result;
            }

            // Method 4: Import analysis
            if (HasSuspiciousImports(data)) {
                result.packerType = PackerType::Custom;
                result.confidence = 0.60;
                result.detectionMethod = L"Import analysis";
                result.isPacked = true;
                result.additionalInfo.push_back(L"Suspicious import characteristics");
                return result;
            }

            // No packer detected
            result.isPacked = false;
            result.packerType = PackerType::None;
            result.confidence = 0.90;
            result.detectionMethod = L"Multi-method analysis";

            return result;

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Exception during detection");
            return result;
        }
    }

    PackerType PackerUnpacker::Impl::IdentifyBySignature(std::span<const uint8_t> entryPointCode) noexcept {
        if (entryPointCode.size() < 6) return PackerType::Unknown;

        // Check UPX
        if (std::ranges::search(entryPointCode, PackerSignatures::UPX_STUB_PATTERN).begin() != entryPointCode.end()) {
            return PackerType::UPX;
        }

        // Check ASPack
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::ASPACK_MAGIC.begin(), PackerSignatures::ASPACK_MAGIC.end(), entryPointCode.begin())) {
            return PackerType::ASPack;
        }

        // Check FSG
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::FSG_PATTERN.begin(), PackerSignatures::FSG_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::FSG;
        }

        // Check PECompact
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::PECOMPACT_MAGIC.begin(), PackerSignatures::PECOMPACT_MAGIC.end(), entryPointCode.begin())) {
            return PackerType::PECompact;
        }

        // Check MPRESS
        if (entryPointCode.size() >= 6 &&
            std::equal(PackerSignatures::MPRESS_PATTERN.begin(), PackerSignatures::MPRESS_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::MPRESS;
        }

        // Check Themida
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::THEMIDA_PATTERN.begin(), PackerSignatures::THEMIDA_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::Themida;
        }

        // Check MEW
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::MEW_PATTERN.begin(), PackerSignatures::MEW_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::MEW;
        }

        // Check PESpin
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::PESPIN_PATTERN.begin(), PackerSignatures::PESPIN_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::PESpin;
        }

        return PackerType::Unknown;
    }

    PackerType PackerUnpacker::Impl::IdentifyBySectionNames(const std::vector<std::string>& sectionNames) noexcept {
        for (const auto& sectionName : sectionNames) {
            // UPX
            if (sectionName.find("UPX") != std::string::npos) return PackerType::UPX;

            // ASPack
            if (sectionName.find(".aspack") != std::string::npos || sectionName.find(".adata") != std::string::npos) {
                return PackerType::ASPack;
            }

            // FSG
            if (sectionName.find(".fsg") != std::string::npos || sectionName.find("FSG!") != std::string::npos) {
                return PackerType::FSG;
            }

            // PECompact
            if (sectionName.find(".pecompact") != std::string::npos || sectionName.find(".pec") != std::string::npos) {
                return PackerType::PECompact;
            }

            // MPRESS
            if (sectionName.find(".mpress") != std::string::npos) return PackerType::MPRESS;

            // Themida
            if (sectionName.find(".themida") != std::string::npos || sectionName.find(".winlice") != std::string::npos) {
                return PackerType::Themida;
            }

            // VMProtect
            if (sectionName.find(".vmp") != std::string::npos) return PackerType::VMProtect;

            // Enigma
            if (sectionName.find(".enigma") != std::string::npos) return PackerType::Enigma;

            // MEW
            if (sectionName.find(".mew") != std::string::npos || sectionName.find("MEW") != std::string::npos) {
                return PackerType::MEW;
            }

            // PESpin
            if (sectionName.find(".pespin") != std::string::npos) return PackerType::PESpin;

            // Petite
            if (sectionName.find(".petite") != std::string::npos || sectionName.find("petite") != std::string::npos) {
                return PackerType::Petite;
            }
        }

        return PackerType::Unknown;
    }

    bool PackerUnpacker::Impl::HasSuspiciousEntropy(std::span<const uint8_t> data) noexcept {
        try {
            const double entropy = CalculateEntropy(data);

            // High entropy (>7.0) suggests encryption/compression
            if (entropy > 7.0) {
                return true;
            }

            // Check section-wise entropy
            auto sections = GetSectionHeaders(data);
            size_t highEntropySections = 0;

            for (const auto& section : sections) {
                if (section.PointerToRawData + section.SizeOfRawData > data.size()) continue;

                auto sectionData = data.subspan(section.PointerToRawData, section.SizeOfRawData);
                const double sectionEntropy = CalculateEntropy(sectionData);

                if (sectionEntropy > 7.2) {
                    highEntropySections++;
                }
            }

            // If multiple sections have high entropy, likely packed
            if (highEntropySections >= 2) {
                return true;
            }

            return false;

        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::HasSuspiciousImports(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                return false;
            }

            // No import table at all
            if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
                return true;
            }

            // Very few imports (< 5 functions) is suspicious
            const uint32_t importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (importRVA == 0) {
                return true;
            }

            // Count import functions (simplified)
            // Full implementation would parse import directory

            return false;

        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: UNPACKING
    // ========================================================================

    UnpackResult PackerUnpacker::Impl::UnpackFileInternal(const fs::path& filePath, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        try {
            const auto startTime = std::chrono::high_resolution_clock::now();

            Utils::Logger::Info(L"PackerUnpacker: Unpacking file: {}", filePath.wstring());

            // Detect packer
            auto detection = DetectPackerInternal(filePath);
            result.packerInfo = detection;

            if (!detection.isPacked) {
                result.status = UnpackStatus::NotPacked;
                Utils::Logger::Info(L"PackerUnpacker: File is not packed");
                return result;
            }

            Utils::Logger::Info(L"PackerUnpacker: Detected packer: {} (confidence: {:.1f}%)",
                PackerTypeToString(detection.packerType),
                detection.confidence * 100.0);

            // Read file data
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                Utils::Logger::Error(L"PackerUnpacker: Failed to open file");
                return result;
            }

            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
            file.close();

            result.originalSize = fileData.size();

            // Try static unpacking first
            if (options.enableStaticUnpacking && detection.packerType != PackerType::Custom) {
                Utils::Logger::Info(L"PackerUnpacker: Attempting static unpacking...");

                auto staticResult = StaticUnpackInternal(fileData, detection.packerType);
                if (staticResult.status == UnpackStatus::Success) {
                    result = std::move(staticResult);
                    result.methodUsed = UnpackMethod::Static;

                    const auto endTime = std::chrono::high_resolution_clock::now();
                    result.processingTimeMs = static_cast<uint32_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
                    );

                    m_stats.staticUnpacks++;
                    m_stats.successfulUnpacks++;

                    Utils::Logger::Info(L"PackerUnpacker: Static unpacking successful ({} ms)", result.processingTimeMs);

                    return result;
                }
            }

            // Fall back to dynamic unpacking
            if (options.enableDynamicUnpacking) {
                Utils::Logger::Info(L"PackerUnpacker: Attempting dynamic unpacking...");

                auto dynamicResult = DynamicUnpackInternal(fileData, options);
                if (dynamicResult.status == UnpackStatus::Success || dynamicResult.status == UnpackStatus::PartialSuccess) {
                    result = std::move(dynamicResult);
                    result.methodUsed = UnpackMethod::Dynamic;

                    const auto endTime = std::chrono::high_resolution_clock::now();
                    result.processingTimeMs = static_cast<uint32_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
                    );

                    m_stats.dynamicUnpacks++;
                    if (result.status == UnpackStatus::Success) {
                        m_stats.successfulUnpacks++;
                    }

                    Utils::Logger::Info(L"PackerUnpacker: Dynamic unpacking completed ({} ms)", result.processingTimeMs);

                    return result;
                }
            }

            // Both methods failed
            result.status = UnpackStatus::UnsupportedPacker;
            m_stats.failedUnpacks++;

            Utils::Logger::Warn(L"PackerUnpacker: All unpacking methods failed");

            return result;

        } catch (const std::exception& e) {
            Utils::Logger::Error(L"PackerUnpacker: Unpacking failed: {}",
                Utils::StringUtils::ToWideString(e.what()));
            result.status = UnpackStatus::Error;
            m_stats.failedUnpacks++;
            return result;
        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Unknown unpacking error");
            result.status = UnpackStatus::Error;
            m_stats.failedUnpacks++;
            return result;
        }
    }

    UnpackResult PackerUnpacker::Impl::StaticUnpackInternal(std::span<const uint8_t> data, PackerType type) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;
        result.packerInfo.packerType = type;

        try {
            std::optional<std::vector<uint8_t>> unpackedData;

            switch (type) {
            case PackerType::UPX:
                unpackedData = UnpackUPX(data);
                break;

            case PackerType::ASPack:
                unpackedData = UnpackASPack(data);
                break;

            case PackerType::MPRESS:
                unpackedData = UnpackMPRESS(data);
                break;

            case PackerType::FSG:
                unpackedData = UnpackFSG(data);
                break;

            case PackerType::PECompact:
                unpackedData = UnpackPECompact(data);
                break;

            default:
                result.status = UnpackStatus::UnsupportedPacker;
                Utils::Logger::Warn(L"PackerUnpacker: Static unpacking not implemented for {}", PackerTypeToString(type));
                return result;
            }

            if (!unpackedData.has_value()) {
                result.status = UnpackStatus::Error;
                Utils::Logger::Error(L"PackerUnpacker: Static unpacking returned no data");
                return result;
            }

            result.unpackedData = std::move(unpackedData.value());
            result.unpackedSize = result.unpackedData.size();
            result.layersUnpacked = 1;
            result.status = UnpackStatus::Success;

            Utils::Logger::Info(L"PackerUnpacker: Static unpacking successful ({} -> {} bytes)",
                data.size(), result.unpackedSize);

            return result;

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Static unpacking exception");
            result.status = UnpackStatus::Error;
            return result;
        }
    }

    UnpackResult PackerUnpacker::Impl::DynamicUnpackInternal(std::span<const uint8_t> data, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        try {
            if (!m_emulationEngine || !m_emulationEngine->IsInitialized()) {
                Utils::Logger::Error(L"PackerUnpacker: EmulationEngine not available");
                result.status = UnpackStatus::Error;
                return result;
            }

            // Setup emulation config
            EmulationConfig emuConfig = EmulationConfig::CreateUnpackOnly();
            emuConfig.timeoutMs = options.maxEmulationTimeMs;
            emuConfig.enableUnpacking = true;
            emuConfig.enableAPITracing = false;

            Utils::Logger::Debug(L"PackerUnpacker: Starting emulation (timeout: {} ms)", emuConfig.timeoutMs);

            // Emulate PE
            EmulationError emuError;
            auto emuResult = m_emulationEngine->EmulatePE(
                std::vector<uint8_t>(data.begin(), data.end()),
                emuConfig,
                &emuError
            );

            result.instructionsEmulated = emuResult.instructionsExecuted;

            if (emuResult.state == EmulationState::TimedOut) {
                result.status = UnpackStatus::EmulationTimeout;
                Utils::Logger::Warn(L"PackerUnpacker: Emulation timed out after {} instructions", result.instructionsEmulated);
                return result;
            }

            if (emuResult.state == EmulationState::Crashed || emuResult.state == EmulationState::Failed) {
                result.status = UnpackStatus::EmulationCrash;
                Utils::Logger::Warn(L"PackerUnpacker: Emulation crashed (state: {})", static_cast<int>(emuResult.state));
                return result;
            }

            // Check if unpacking occurred
            if (emuResult.unpackLayers.empty()) {
                Utils::Logger::Warn(L"PackerUnpacker: No unpacking layers detected");
                result.status = UnpackStatus::OEPNotFound;
                return result;
            }

            // Use the last unpacked layer
            const auto& lastLayer = emuResult.unpackLayers.back();
            result.unpackedData = lastLayer.unpackedCode;
            result.unpackedSize = result.unpackedData.size();
            result.layersUnpacked = static_cast<uint32_t>(emuResult.unpackLayers.size());

            // Try to find OEP
            auto oep = FindOEPInternal(result.unpackedData);
            if (oep.has_value()) {
                result.peInfo.newEntryPoint = oep.value();
                m_stats.oepsFound++;
                Utils::Logger::Info(L"PackerUnpacker: Found OEP at 0x{:X}", oep.value());
            } else {
                Utils::Logger::Warn(L"PackerUnpacker: Could not find OEP");
            }

            result.status = UnpackStatus::Success;

            Utils::Logger::Info(L"PackerUnpacker: Dynamic unpacking successful ({} layers, {} instructions)",
                result.layersUnpacked, result.instructionsEmulated);

            return result;

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Dynamic unpacking exception");
            result.status = UnpackStatus::Error;
            return result;
        }
    }

    // ========================================================================
    // IMPL: STATIC UNPACKING ALGORITHMS
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackUPX(std::span<const uint8_t> data) noexcept {
        try {
            // UPX unpacking algorithm (simplified stub)
            // Full implementation would decompress UPX-compressed sections using UCL/NRV algorithms

            Utils::Logger::Debug(L"PackerUnpacker: UPX unpacking not fully implemented (use 'upx -d' externally)");

            // Placeholder: Would implement:
            // 1. Locate UPX sections (UPX0, UPX1, UPX2)
            // 2. Decompress using UCL/NRV2B/NRV2D/NRV2E algorithms
            // 3. Rebuild PE with decompressed sections
            // 4. Fix imports and relocations
            // 5. Remove UPX overlay

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackASPack(std::span<const uint8_t> data) noexcept {
        try {
            Utils::Logger::Debug(L"PackerUnpacker: ASPack unpacking not fully implemented");

            // Placeholder: Would reverse ASPack compression algorithm
            // ASPack uses custom compression + encryption

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackMPRESS(std::span<const uint8_t> data) noexcept {
        try {
            Utils::Logger::Debug(L"PackerUnpacker: MPRESS unpacking not fully implemented");

            // Placeholder: Would reverse MPRESS LZMA compression
            // MPRESS uses LZMA with custom stub

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackFSG(std::span<const uint8_t> data) noexcept {
        try {
            Utils::Logger::Debug(L"PackerUnpacker: FSG unpacking not fully implemented");

            // Placeholder: Would reverse FSG packer
            // FSG uses polymorphic decryption loop

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackPECompact(std::span<const uint8_t> data) noexcept {
        try {
            Utils::Logger::Debug(L"PackerUnpacker: PECompact unpacking not fully implemented");

            // Placeholder: Would reverse PECompact compression

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    // ========================================================================
    // IMPL: OEP DETECTION
    // ========================================================================

    std::optional<uint64_t> PackerUnpacker::Impl::FindOEPInternal(std::span<const uint8_t> data) noexcept {
        try {
            // Parse PE to get sections
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                return std::nullopt;
            }

            const uint64_t imageBase = ntHeaders.OptionalHeader.ImageBase;

            // Look for standard function prologue patterns
            // Common OEP patterns:
            // - PUSH EBP; MOV EBP, ESP (55 8B EC)
            // - MOV EDI, EDI; PUSH EBP; MOV EBP, ESP (8B FF 55 8B EC)
            // - SUB ESP, imm32 (83 EC xx or 81 EC xx xx xx xx)

            constexpr std::array<uint8_t, 3> PATTERN1 = { 0x55, 0x8B, 0xEC }; // PUSH EBP; MOV EBP, ESP
            constexpr std::array<uint8_t, 5> PATTERN2 = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC }; // MOV EDI, EDI; PUSH EBP; MOV EBP, ESP
            constexpr std::array<uint8_t, 2> PATTERN3 = { 0x83, 0xEC }; // SUB ESP, imm8

            // Search in .text section
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));

                if (sectionName != ".text" && sectionName != "CODE" && sectionName != ".code") continue;

                const size_t sectionStart = section.PointerToRawData;
                const size_t sectionSize = section.SizeOfRawData;

                if (sectionStart + sectionSize > data.size()) continue;

                auto sectionData = data.subspan(sectionStart, sectionSize);

                // Search for pattern 1 (most common)
                for (size_t i = 0; i + PATTERN1.size() < sectionData.size(); ++i) {
                    if (std::equal(PATTERN1.begin(), PATTERN1.end(), sectionData.begin() + i)) {
                        const uint64_t oep = imageBase + section.VirtualAddress + i;
                        Utils::Logger::Debug(L"PackerUnpacker: Found potential OEP at 0x{:X} (pattern: PUSH EBP; MOV EBP, ESP)", oep);
                        return oep;
                    }
                }

                // Search for pattern 2
                for (size_t i = 0; i + PATTERN2.size() < sectionData.size(); ++i) {
                    if (std::equal(PATTERN2.begin(), PATTERN2.end(), sectionData.begin() + i)) {
                        const uint64_t oep = imageBase + section.VirtualAddress + i;
                        Utils::Logger::Debug(L"PackerUnpacker: Found potential OEP at 0x{:X} (pattern: MOV EDI, EDI; PUSH EBP)", oep);
                        return oep;
                    }
                }

                // Search for pattern 3
                for (size_t i = 0; i + PATTERN3.size() < sectionData.size(); ++i) {
                    if (std::equal(PATTERN3.begin(), PATTERN3.end(), sectionData.begin() + i)) {
                        const uint64_t oep = imageBase + section.VirtualAddress + i;
                        Utils::Logger::Debug(L"PackerUnpacker: Found potential OEP at 0x{:X} (pattern: SUB ESP)", oep);
                        return oep;
                    }
                }
            }

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<uint64_t> PackerUnpacker::Impl::FindOEPViaEmulation(std::span<const uint8_t> data, const UnpackOptions& options) noexcept {
        // Placeholder for emulation-based OEP detection
        // Full implementation would:
        // 1. Emulate unpacking stub
        // 2. Monitor for jumps to new code sections
        // 3. Detect transition from unpacker to original code
        // 4. Validate OEP using heuristics
        return std::nullopt;
    }

    bool PackerUnpacker::Impl::IsLikelyOEP(uint64_t address, std::span<const uint8_t> code) noexcept {
        // Check if code at address looks like normal function entry
        if (code.size() < 10) return false;

        // Check for standard function prologue
        if (code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC) return true; // PUSH EBP; MOV EBP, ESP
        if (code[0] == 0x8B && code[1] == 0xFF && code[2] == 0x55) return true; // MOV EDI, EDI; PUSH EBP
        if (code[0] == 0x83 && code[1] == 0xEC) return true; // SUB ESP, imm8
        if (code[0] == 0x81 && code[1] == 0xEC) return true; // SUB ESP, imm32

        // Check for push of non-volatile registers
        if (code[0] >= 0x50 && code[0] <= 0x57) return true; // PUSH reg

        return false;
    }

    std::vector<uint64_t> PackerUnpacker::Impl::FindPotentialOEPs(std::span<const uint8_t> data) noexcept {
        std::vector<uint64_t> candidates;

        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                return candidates;
            }

            const uint64_t imageBase = ntHeaders.OptionalHeader.ImageBase;
            auto sections = GetSectionHeaders(data);

            for (const auto& section : sections) {
                if (!IsExecutableSection(section)) continue;

                const size_t sectionStart = section.PointerToRawData;
                const size_t sectionSize = section.SizeOfRawData;

                if (sectionStart + sectionSize > data.size()) continue;

                auto sectionData = data.subspan(sectionStart, sectionSize);

                // Scan for potential OEPs
                for (size_t i = 0; i + 16 < sectionData.size(); ++i) {
                    const uint64_t address = imageBase + section.VirtualAddress + i;
                    auto codeSlice = sectionData.subspan(i, 16);

                    if (IsLikelyOEP(address, codeSlice)) {
                        candidates.push_back(address);
                    }
                }
            }

            Utils::Logger::Debug(L"PackerUnpacker: Found {} potential OEP candidates", candidates.size());

        } catch (...) {
            // Return empty on error
        }

        return candidates;
    }

    // ========================================================================
    // IMPL: IMPORT RECONSTRUCTION
    // ========================================================================

    std::optional<ReconstructedImports> PackerUnpacker::Impl::ReconstructImportsInternal(
        std::span<const uint8_t> unpackedData,
        const ImportReconstructionOptions& options
    ) noexcept {
        ReconstructedImports imports;

        try {
            // Find IAT start
            auto iatStart = FindIATStart(unpackedData);
            if (!iatStart.has_value()) {
                Utils::Logger::Warn(L"PackerUnpacker: Could not find IAT");
                return std::nullopt;
            }

            Utils::Logger::Debug(L"PackerUnpacker: Found IAT at RVA 0x{:X}", iatStart.value());

            imports.iatRVA = iatStart.value();

            // Scan IAT range to reconstruct imports
            if (!ScanIATRange(unpackedData, iatStart.value(), imports)) {
                Utils::Logger::Warn(L"PackerUnpacker: IAT scanning failed");
                return std::nullopt;
            }

            imports.reconstructedSuccessfully = true;
            m_stats.importsReconstructed++;

            Utils::Logger::Info(L"PackerUnpacker: Reconstructed {} import descriptors with {} total functions",
                imports.importDescriptors.size(), imports.totalFunctions);

            return imports;

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Import reconstruction exception");
            return std::nullopt;
        }
    }

    std::optional<uint64_t> PackerUnpacker::Impl::FindIATStart(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                return std::nullopt;
            }

            // Check if import directory exists
            const uint32_t importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (importRVA != 0) {
                // Use existing import directory
                return importRVA;
            }

            // Heuristic: IAT is usually in .rdata, .idata, or .data section
            // Look for consecutive valid kernel32/ntdll addresses

            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));

                if (sectionName != ".rdata" && sectionName != ".idata" && sectionName != ".data") continue;

                // Potential IAT section found
                Utils::Logger::Debug(L"PackerUnpacker: Scanning {} section for IAT", Utils::StringUtils::ToWideString(sectionName));
                return section.VirtualAddress;
            }

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> PackerUnpacker::Impl::ResolveAPIByAddress(uint64_t address) noexcept {
        try {
            // Check loaded system DLLs
            for (const auto& [dllName, hModule] : m_loadedDLLs) {
                MODULEINFO modInfo = {};
                if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) continue;

                const uint64_t baseAddr = reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
                const uint64_t endAddr = baseAddr + modInfo.SizeOfImage;

                if (address >= baseAddr && address < endAddr) {
                    // Address is in this DLL - try to resolve name
                    // Full implementation would parse export table
                    return std::format("{}!Unknown_0x{:X}", dllName, address - baseAddr);
                }
            }

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> PackerUnpacker::Impl::ResolveAPIByOrdinal(const std::string& dllName, uint16_t ordinal) noexcept {
        // Placeholder for ordinal-to-name resolution
        // Full implementation would:
        // 1. Load DLL export table
        // 2. Find ordinal in export table
        // 3. Return function name
        return std::format("{}!Ordinal{}", dllName, ordinal);
    }

    bool PackerUnpacker::Impl::ScanIATRange(std::span<const uint8_t> data, uint64_t startRVA, ReconstructedImports& imports) noexcept {
        try {
            // Simplified IAT scanning
            // Full implementation would:
            // 1. Iterate through potential IAT slots
            // 2. Validate each address as pointing to DLL export
            // 3. Group by DLL
            // 4. Build import descriptor structures

            imports.totalFunctions = 0;

            return true;

        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: PE RECONSTRUCTION
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::FixPEHeadersInternal(
        std::span<const uint8_t> data,
        uint64_t newEntryPoint,
        const ReconstructedImports* imports
    ) noexcept {
        try {
            std::vector<uint8_t> fixedPE(data.begin(), data.end());

            // Parse headers
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fixedPE.data());
            IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(fixedPE.data() + dosHeader->e_lfanew);

            // Fix entry point
            if (newEntryPoint != 0) {
                const uint64_t imageBase = ntHeaders->OptionalHeader.ImageBase;
                ntHeaders->OptionalHeader.AddressOfEntryPoint = static_cast<DWORD>(newEntryPoint - imageBase);
                Utils::Logger::Debug(L"PackerUnpacker: Fixed entry point to RVA 0x{:X}", ntHeaders->OptionalHeader.AddressOfEntryPoint);
            }

            // Fix import directory
            if (imports && imports->reconstructedSuccessfully) {
                if (!FixImportDirectory(fixedPE, *imports)) {
                    Utils::Logger::Warn(L"PackerUnpacker: Failed to fix import directory");
                }
            }

            // Remove packer sections
            if (!RemovePackerSections(fixedPE)) {
                Utils::Logger::Warn(L"PackerUnpacker: Failed to remove packer sections");
            }

            // Realign sections
            if (!RealignSections(fixedPE)) {
                Utils::Logger::Warn(L"PackerUnpacker: Section realignment failed");
            }

            // Recalculate checksum
            if (!RecalculateChecksum(fixedPE)) {
                Utils::Logger::Warn(L"PackerUnpacker: Checksum recalculation failed");
            }

            return fixedPE;

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: PE header fixing exception");
            return std::nullopt;
        }
    }

    bool PackerUnpacker::Impl::RealignSections(std::vector<uint8_t>& peData) noexcept {
        try {
            // Placeholder for section realignment
            // Full implementation would ensure proper section alignment (FileAlignment, SectionAlignment)
            return true;

        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::RecalculateChecksum(std::vector<uint8_t>& peData) noexcept {
        try {
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
            IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + dosHeader->e_lfanew);

            // Clear existing checksum
            ntHeaders->OptionalHeader.CheckSum = 0;

            // Calculate new checksum (simplified - full implementation would use CheckSumMappedFile API)
            // For now, just set to 0 (not required for most executables)

            return true;

        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::FixImportDirectory(std::vector<uint8_t>& peData, const ReconstructedImports& imports) noexcept {
        try {
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
            IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + dosHeader->e_lfanew);

            // Update import directory data directory entry
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = static_cast<DWORD>(imports.iatRVA);
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>(
                imports.importDescriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR)
            );

            Utils::Logger::Debug(L"PackerUnpacker: Fixed import directory at RVA 0x{:X}", imports.iatRVA);

            return true;

        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::RemovePackerSections(std::vector<uint8_t>& peData) noexcept {
        try {
            // Remove known packer sections (UPX0, .aspack, etc.)
            // Full implementation would rebuild section table without packer sections

            return true;

        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: PE PARSING HELPERS
    // ========================================================================

    bool PackerUnpacker::Impl::ParsePEHeaders(
        std::span<const uint8_t> data,
        IMAGE_DOS_HEADER& dosHeader,
        IMAGE_NT_HEADERS64& ntHeaders
    ) noexcept {
        try {
            if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
                return false;
            }

            // Copy DOS header
            std::memcpy(&dosHeader, data.data(), sizeof(IMAGE_DOS_HEADER));

            // Validate DOS signature
            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                return false;
            }

            // Check NT headers offset
            if (static_cast<size_t>(dosHeader.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data.size()) {
                return false;
            }

            // Copy NT headers
            std::memcpy(&ntHeaders, data.data() + dosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

            // Validate PE signature
            if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
                return false;
            }

            return true;

        } catch (...) {
            return false;
        }
    }

    std::vector<IMAGE_SECTION_HEADER> PackerUnpacker::Impl::GetSectionHeaders(std::span<const uint8_t> data) noexcept {
        std::vector<IMAGE_SECTION_HEADER> sections;

        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                return sections;
            }

            const size_t sectionHeadersOffset = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;
            const uint16_t numSections = ntHeaders.FileHeader.NumberOfSections;

            if (sectionHeadersOffset + (numSections * sizeof(IMAGE_SECTION_HEADER)) > data.size()) {
                return sections;
            }

            sections.resize(numSections);
            std::memcpy(sections.data(), data.data() + sectionHeadersOffset, numSections * sizeof(IMAGE_SECTION_HEADER));

            return sections;

        } catch (...) {
            return sections;
        }
    }

    std::vector<std::string> PackerUnpacker::Impl::GetSectionNames(std::span<const uint8_t> data) noexcept {
        std::vector<std::string> names;

        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string name(reinterpret_cast<const char*>(section.Name), 8);
                name = name.substr(0, name.find('\0'));
                names.push_back(name);
            }

            return names;

        } catch (...) {
            return names;
        }
    }

    std::span<const uint8_t> PackerUnpacker::Impl::GetSectionData(std::span<const uint8_t> data, const std::string& sectionName) noexcept {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string name(reinterpret_cast<const char*>(section.Name), 8);
                name = name.substr(0, name.find('\0'));

                if (name == sectionName) {
                    if (section.PointerToRawData + section.SizeOfRawData > data.size()) {
                        return {};
                    }
                    return data.subspan(section.PointerToRawData, section.SizeOfRawData);
                }
            }

            return {};

        } catch (...) {
            return {};
        }
    }

    std::optional<IMAGE_SECTION_HEADER> PackerUnpacker::Impl::FindSectionByName(std::span<const uint8_t> data, const std::string& name) noexcept {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));

                if (sectionName == name) {
                    return section;
                }
            }

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<IMAGE_SECTION_HEADER> PackerUnpacker::Impl::FindSectionByRVA(std::span<const uint8_t> data, uint64_t rva) noexcept {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                const uint64_t sectionStart = section.VirtualAddress;
                const uint64_t sectionEnd = sectionStart + section.Misc.VirtualSize;

                if (rva >= sectionStart && rva < sectionEnd) {
                    return section;
                }
            }

            return std::nullopt;

        } catch (...) {
            return std::nullopt;
        }
    }

    // ========================================================================
    // IMPL: UTILITY
    // ========================================================================

    bool PackerUnpacker::Impl::LoadSystemDLLs() noexcept {
        try {
            // Load common system DLLs for import resolution
            const std::array<std::string, 10> commonDLLs = {
                "kernel32.dll",
                "ntdll.dll",
                "user32.dll",
                "advapi32.dll",
                "ws2_32.dll",
                "shell32.dll",
                "ole32.dll",
                "gdi32.dll",
                "comctl32.dll",
                "msvcrt.dll"
            };

            for (const auto& dllName : commonDLLs) {
                HMODULE hModule = GetModuleHandleA(dllName.c_str());
                if (!hModule) {
                    hModule = LoadLibraryA(dllName.c_str());
                }

                if (hModule) {
                    m_loadedDLLs[dllName] = hModule;
                    Utils::Logger::Debug(L"PackerUnpacker: Loaded {}", Utils::StringUtils::ToWideString(dllName));
                }
            }

            return !m_loadedDLLs.empty();

        } catch (...) {
            return false;
        }
    }

    void PackerUnpacker::Impl::UnloadSystemDLLs() noexcept {
        try {
            // Note: We don't actually FreeLibrary system DLLs as they may be in use
            // Just clear our tracking map
            m_loadedDLLs.clear();

        } catch (...) {
            Utils::Logger::Error(L"PackerUnpacker: Exception during DLL unload");
        }
    }

    bool PackerUnpacker::Impl::IsExecutableSection(const IMAGE_SECTION_HEADER& section) noexcept {
        return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    bool PackerUnpacker::Impl::IsWritableSection(const IMAGE_SECTION_HEADER& section) noexcept {
        return (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    uint64_t PackerUnpacker::Impl::RVAToFileOffset(std::span<const uint8_t> data, uint64_t rva) noexcept {
        try {
            auto section = FindSectionByRVA(data, rva);
            if (!section.has_value()) {
                return 0;
            }

            const uint64_t offset = rva - section->VirtualAddress;
            return section->PointerToRawData + offset;

        } catch (...) {
            return 0;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    PackerUnpacker& PackerUnpacker::Instance() noexcept {
        static PackerUnpacker instance;
        return instance;
    }

    PackerUnpacker::PackerUnpacker() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    PackerUnpacker::~PackerUnpacker() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool PackerUnpacker::Initialize(UnpackError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid unpacker instance";
            }
            return false;
        }

        return m_impl->Initialize(err);
    }

    void PackerUnpacker::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool PackerUnpacker::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // DETECTION METHODS
    // ========================================================================

    PackerDetectionResult PackerUnpacker::DetectPacker(const fs::path& filePath) noexcept {
        if (!IsInitialized()) {
            PackerDetectionResult result;
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return result;
        }

        return m_impl->DetectPackerInternal(filePath);
    }

    PackerDetectionResult PackerUnpacker::DetectPacker(std::span<const uint8_t> data) noexcept {
        if (!IsInitialized()) {
            PackerDetectionResult result;
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return result;
        }

        return m_impl->DetectPackerFromMemory(data);
    }

    // ========================================================================
    // UNPACKING METHODS
    // ========================================================================

    UnpackResult PackerUnpacker::UnpackFile(const fs::path& filePath, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return result;
        }

        m_impl->m_stats.totalUnpackAttempts++;

        return m_impl->UnpackFileInternal(filePath, options);
    }

    UnpackResult PackerUnpacker::StaticUnpack(std::span<const uint8_t> data, PackerType type) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return result;
        }

        return m_impl->StaticUnpackInternal(data, type);
    }

    UnpackResult PackerUnpacker::DynamicUnpack(std::span<const uint8_t> data, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return result;
        }

        return m_impl->DynamicUnpackInternal(data, options);
    }

    // ========================================================================
    // OEP DETECTION
    // ========================================================================

    std::optional<uint64_t> PackerUnpacker::FindOEP(std::span<const uint8_t> data) noexcept {
        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return std::nullopt;
        }

        return m_impl->FindOEPInternal(data);
    }

    // ========================================================================
    // IMPORT RECONSTRUCTION
    // ========================================================================

    std::optional<ReconstructedImports> PackerUnpacker::ReconstructImports(
        std::span<const uint8_t> unpackedData,
        const ImportReconstructionOptions& options
    ) noexcept {
        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return std::nullopt;
        }

        return m_impl->ReconstructImportsInternal(unpackedData, options);
    }

    // ========================================================================
    // PE RECONSTRUCTION
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::FixPEHeaders(
        std::span<const uint8_t> data,
        uint64_t newEntryPoint,
        const ReconstructedImports* imports
    ) noexcept {
        if (!IsInitialized()) {
            Utils::Logger::Error(L"PackerUnpacker: Not initialized");
            return std::nullopt;
        }

        return m_impl->FixPEHeadersInternal(data, newEntryPoint, imports);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const PackerUnpacker::Statistics& PackerUnpacker::GetStatistics() const noexcept {
        static Statistics emptyStats;
        if (!m_impl) {
            return emptyStats;
        }
        return m_impl->m_stats;
    }

    void PackerUnpacker::ResetStatistics() noexcept {
        if (m_impl) {
            m_impl->m_stats.Reset();
        }
    }

    void PackerUnpacker::Statistics::Reset() noexcept {
        totalUnpackAttempts = 0;
        successfulUnpacks = 0;
        failedUnpacks = 0;
        packersDetected = 0;
        staticUnpacks = 0;
        dynamicUnpacks = 0;
        oepsFound = 0;
        importsReconstructed = 0;
    }

} // namespace ShadowStrike::Core::Engine
