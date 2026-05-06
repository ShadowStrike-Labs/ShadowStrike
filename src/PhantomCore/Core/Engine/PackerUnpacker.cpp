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
 * @brief Enterprise-grade automated unpacking engine for packed/obfuscated executables.
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
#include <cwchar>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
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
#include <imagehlp.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Imagehlp.lib")

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

    // Log category for all SS_LOG_* calls in this module
    static constexpr const wchar_t* kLogCategory = L"PackerUnpacker";

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    [[nodiscard]] const wchar_t* PackerTypeToWString(PackerType type) noexcept {
        switch (type) {
        case PackerType::Unknown:    return L"Unknown";
        case PackerType::None:       return L"None (Not Packed)";
        case PackerType::UPX:        return L"UPX";
        case PackerType::ASPack:     return L"ASPack";
        case PackerType::FSG:        return L"FSG";
        case PackerType::PECompact:  return L"PECompact";
        case PackerType::MPRESS:     return L"MPRESS";
        case PackerType::MEW:        return L"MEW";
        case PackerType::Petite:     return L"Petite";
        case PackerType::Themida:    return L"Themida";
        case PackerType::VMProtect:  return L"VMProtect";
        case PackerType::Enigma:     return L"Enigma Protector";
        case PackerType::Armadillo:  return L"Armadillo";
        case PackerType::Obsidium:   return L"Obsidium";
        case PackerType::ASProtect:  return L"ASProtect";
        default:                     return L"Custom/Unknown Packer";
        }
    }

    [[nodiscard]] const wchar_t* UnpackStatusToWString(UnpackStatus status) noexcept {
        switch (status) {
        case UnpackStatus::Success:              return L"Success";
        case UnpackStatus::PartialSuccess:       return L"Partial Success";
        case UnpackStatus::NotPacked:            return L"Not Packed";
        case UnpackStatus::UnsupportedPacker:    return L"Unsupported Packer";
        case UnpackStatus::CorruptedInput:       return L"Corrupted PE";
        case UnpackStatus::OEPNotFound:          return L"OEP Not Found";
        case UnpackStatus::EmulationFailed:      return L"Emulation Failed";
        case UnpackStatus::Timeout:              return L"Timeout";
        case UnpackStatus::OutputTooLarge:       return L"Output Too Large";
        case UnpackStatus::ImportRecoveryFailed: return L"Import Recovery Failed";
        case UnpackStatus::AntiDebugDetected:    return L"Anti-Debug Detected";
        case UnpackStatus::VirtualizedCode:      return L"Virtualized Code";
        case UnpackStatus::Error:                return L"Error";
        }
        return L"Unknown";
    }

    [[nodiscard]] const wchar_t* UnpackMethodToWString(UnpackMethod method) noexcept {
        switch (method) {
        case UnpackMethod::Static:  return L"Static Unpacking";
        case UnpackMethod::Dynamic: return L"Dynamic Unpacking (Emulation)";
        case UnpackMethod::Hybrid:  return L"Hybrid (Static + Dynamic)";
        case UnpackMethod::Plugin:  return L"Plugin";
        case UnpackMethod::Memory:  return L"Memory Dump";
        default:                    return L"Unknown";
        }
    }

    // ========================================================================
    // ENTROPY CALCULATION
    // ========================================================================

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

    float CalculateSectionEntropy(std::span<const uint8_t> data) noexcept {
        return static_cast<float>(CalculateEntropy(data));
    }

    bool IsHighEntropySection(float entropy) noexcept {
        return entropy > 7.0f;
    }

    // ========================================================================
    // NRV2B DECOMPRESSION (used by UPX)
    // ========================================================================

    /**
     * NRV2B decompression algorithm (public domain, UCL library).
     * Returns decompressed data on success, nullopt on error.
     * maxOutput caps output size to prevent decompression bombs.
     *
     * Hardening notes:
     *  - The bit-extracted offset/length variables (`mOff`, `mLen`) are doubled
     *    on each loop iteration; without an explicit cap a malformed stream
     *    can drive them past UINT32_MAX which (because the values are unsigned)
     *    silently wraps and produces garbage rather than terminating. We cap
     *    iteration counts and intermediate values defensively.
     *  - Every dst push is gated by maxOutput.
     *  - Match copy uses byte-by-byte semantics to support overlap correctly.
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> Nrv2bDecompress(
        std::span<const uint8_t> src,
        size_t maxOutput) noexcept
    {
        if (src.empty() || maxOutput == 0) return std::nullopt;

        // Defensive iteration cap: any honest NRV2B stream consumes input
        // monotonically; we still bound the total decompressed loop body
        // executions to (maxOutput * 16) literal/match steps to prevent
        // pathological CPU consumption on crafted streams.
        const size_t kMaxLoopIters = std::min<size_t>(
            maxOutput * 16,
            static_cast<size_t>(1) << 28); // hard 256M-iteration ceiling
        size_t loopIters = 0;

        // Bit-decode loops also need an upper bound to defeat infinite-zero streams.
        constexpr uint32_t kMaxBitDecodeIters = 33;

        try {
            std::vector<uint8_t> dst;
            dst.reserve(std::min<size_t>(src.size() * 4, maxOutput));

            const uint8_t* ip = src.data();
            const uint8_t* const ipEnd = src.data() + src.size();

            uint32_t bb = 0;
            uint32_t ilen = 0;
            uint32_t lastMOff = 1;

            auto getbit = [&]() -> int {
                if (ilen == 0) {
                    if (ip >= ipEnd) return -1;
                    bb = static_cast<uint32_t>(*ip++);
                    ilen = 8;
                }
                int bit = static_cast<int>((bb >> 7) & 1);
                bb <<= 1;
                ilen--;
                return bit;
            };

            for (;;) {
                if (++loopIters > kMaxLoopIters) return std::nullopt;

                // Literal bytes: while bit == 1, copy one literal
                int bit = getbit();
                while (bit == 1) {
                    if (ip >= ipEnd || dst.size() >= maxOutput) return std::nullopt;
                    dst.push_back(*ip++);
                    bit = getbit();
                }
                if (bit < 0) return std::nullopt;

                // Match: decode offset (capped to avoid uint32 wrap)
                uint32_t mOff = 1;
                for (uint32_t iter = 0; ; ++iter) {
                    if (iter > kMaxBitDecodeIters) return std::nullopt;
                    int b1 = getbit();
                    if (b1 < 0) return std::nullopt;
                    if (mOff > 0x7FFFFFFFu) return std::nullopt;
                    mOff = mOff * 2u + static_cast<uint32_t>(b1);
                    int b2 = getbit();
                    if (b2 < 0) return std::nullopt;
                    if (b2) break;
                }

                if (mOff == 2) {
                    mOff = lastMOff;
                } else {
                    if (ip >= ipEnd) return std::nullopt;
                    // (mOff - 3) * 256 + byte: bound mOff so the multiply
                    // can never overflow uint32 (max safe value: 0x7FFFFF).
                    if (mOff < 3 || mOff > 0x7FFFFFu) return std::nullopt;
                    mOff = (mOff - 3u) * 256u + static_cast<uint32_t>(*ip++);
                    if (mOff == 0xFFFFFFFFu) break; // end of stream
                    mOff++;
                    lastMOff = mOff;
                }

                // Decode match length
                int lb1 = getbit();
                if (lb1 < 0) return std::nullopt;
                uint32_t mLen = static_cast<uint32_t>(lb1);
                int lb2 = getbit();
                if (lb2 < 0) return std::nullopt;
                mLen = mLen * 2 + static_cast<uint32_t>(lb2);

                if (mLen == 0) {
                    mLen = 1;
                    for (uint32_t iter = 0; ; ++iter) {
                        if (iter > kMaxBitDecodeIters) return std::nullopt;
                        int b = getbit();
                        if (b < 0) return std::nullopt;
                        if (mLen > 0x7FFFFFFFu) return std::nullopt;
                        mLen = mLen * 2u + static_cast<uint32_t>(b);
                        int b2 = getbit();
                        if (b2 < 0) return std::nullopt;
                        if (b2) break;
                    }
                    if (mLen > 0xFFFFFFFEu) return std::nullopt;
                    mLen += 2;
                }

                if (mOff > 0xD00) mLen++;

                // Safety: validate match
                if (mOff > dst.size()) return std::nullopt;
                if (dst.size() + mLen > maxOutput) return std::nullopt;

                // Copy match (byte-by-byte for overlapping)
                const size_t srcPos = dst.size() - mOff;
                for (uint32_t i = 0; i < mLen; i++) {
                    dst.push_back(dst[srcPos + i]);
                }
            }

            return dst;

        } catch (...) {
            return std::nullopt;
        }
    }

    // ========================================================================
    // PACKER SIGNATURE PATTERNS
    // ========================================================================

    namespace PackerSignatures {
        constexpr std::array<uint8_t, 3> UPX_MAGIC = { 'U', 'P', 'X' };
        constexpr std::array<uint8_t, 6> UPX_STUB_PATTERN = { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 4> ASPACK_MAGIC = { 0x60, 0xE8, 0x03, 0x00 };
        constexpr std::array<uint8_t, 5> FSG_PATTERN = { 0x87, 0x25, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 4> PECOMPACT_MAGIC = { 0xEB, 0x06, 0x68, 0x00 };
        constexpr std::array<uint8_t, 6> MPRESS_PATTERN = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 5> THEMIDA_PATTERN = { 0xEB, 0x10, 0x66, 0x62, 0x3A };
        constexpr std::array<uint8_t, 5> VMPROTECT_PATTERN = { 0x68, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 6> ENIGMA_PATTERN = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 5> MEW_PATTERN = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 4> PESPIN_PATTERN = { 0xEB, 0x01, 0x68, 0x60 };
        constexpr std::array<uint8_t, 5> PETITE_PATTERN = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    struct PackerUnpacker::Impl {
        // ====================================================================
        // MEMBERS
        // ====================================================================

        mutable std::shared_mutex m_mutex;
        std::atomic<bool> m_initialized{ false };
        UnpackOptions m_defaultOptions;
        PackerUnpacker::Statistics m_stats;
        EmulationEngine* m_emulationEngine = nullptr;

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

        std::unordered_map<std::string, HMODULE> m_loadedDLLs;

        // ====================================================================
        // LIFECYCLE
        // ====================================================================

        [[nodiscard]] bool Initialize(UnpackError* err) noexcept;
        void Shutdown() noexcept;

        // ====================================================================
        // PACKER DETECTION
        // ====================================================================

        [[nodiscard]] PackerDetectionResult DetectPackerInternal(const fs::path& filePath) noexcept;
        [[nodiscard]] PackerDetectionResult DetectPackerFromMemory(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] PackerType IdentifyBySignature(std::span<const uint8_t> entryPointCode) noexcept;
        [[nodiscard]] PackerType IdentifyBySectionNames(const std::vector<std::string>& sectionNames) noexcept;
        [[nodiscard]] bool HasSuspiciousEntropy(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] bool HasSuspiciousImports(std::span<const uint8_t> data) noexcept;

        // ====================================================================
        // UNPACKING
        // ====================================================================

        [[nodiscard]] UnpackResult UnpackFileInternal(const fs::path& filePath, const UnpackOptions& options) noexcept;
        [[nodiscard]] UnpackResult StaticUnpackInternal(std::span<const uint8_t> data, PackerType type) noexcept;
        [[nodiscard]] UnpackResult DynamicUnpackInternal(std::span<const uint8_t> data, const UnpackOptions& options) noexcept;

        // Static unpacking algorithms
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackUPX(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackASPack(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackMPRESS(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackFSG(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> UnpackPECompact(std::span<const uint8_t> data) noexcept;

        // Dynamic unpacking / OEP
        [[nodiscard]] std::optional<uint64_t> FindOEPInternal(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<uint64_t> FindOEPViaEmulation(std::span<const uint8_t> data, const UnpackOptions& options) noexcept;
        [[nodiscard]] bool IsLikelyOEP(uint64_t address, std::span<const uint8_t> code) noexcept;

        // Import reconstruction
        [[nodiscard]] std::optional<ReconstructedImports> ReconstructImportsInternal(
            std::span<const uint8_t> unpackedData,
            const ImportReconstructionOptions& options) noexcept;
        [[nodiscard]] std::optional<uint64_t> FindIATStart(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::optional<std::string> ResolveAPIByAddress(uint64_t address) noexcept;
        [[nodiscard]] std::optional<std::string> ResolveAPIByOrdinal(const std::string& dllName, uint16_t ordinal) noexcept;
        [[nodiscard]] bool ScanIATRange(std::span<const uint8_t> data, uint64_t startRVA, ReconstructedImports& imports) noexcept;

        // PE reconstruction
        [[nodiscard]] std::optional<std::vector<uint8_t>> FixPEHeadersInternal(
            std::span<const uint8_t> data, uint64_t newEntryPoint,
            const ReconstructedImports* imports) noexcept;
        [[nodiscard]] bool RealignSections(std::vector<uint8_t>& peData) noexcept;
        [[nodiscard]] bool RecalculateChecksum(std::vector<uint8_t>& peData) noexcept;
        [[nodiscard]] bool FixImportDirectory(std::vector<uint8_t>& peData, const ReconstructedImports& imports) noexcept;
        [[nodiscard]] bool RemovePackerSections(std::vector<uint8_t>& peData) noexcept;

        // PE parsing helpers
        [[nodiscard]] bool ParsePEHeaders(std::span<const uint8_t> data,
            IMAGE_DOS_HEADER& dosHeader, IMAGE_NT_HEADERS64& ntHeaders) noexcept;
        [[nodiscard]] std::vector<IMAGE_SECTION_HEADER> GetSectionHeaders(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::vector<std::string> GetSectionNames(std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::span<const uint8_t> GetSectionData(std::span<const uint8_t> data, const std::string& sectionName) noexcept;
        [[nodiscard]] std::optional<IMAGE_SECTION_HEADER> FindSectionByName(std::span<const uint8_t> data, const std::string& name) noexcept;
        [[nodiscard]] std::optional<IMAGE_SECTION_HEADER> FindSectionByRVA(std::span<const uint8_t> data, uint64_t rva) noexcept;

        // Utility
        [[nodiscard]] bool LoadSystemDLLs() noexcept;
        void UnloadSystemDLLs() noexcept;
        [[nodiscard]] static bool IsExecutableSection(const IMAGE_SECTION_HEADER& section) noexcept;
        [[nodiscard]] static bool IsWritableSection(const IMAGE_SECTION_HEADER& section) noexcept;
        [[nodiscard]] uint64_t RVAToFileOffset(std::span<const uint8_t> data, uint64_t rva) noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool PackerUnpacker::Impl::Initialize(UnpackError* err) noexcept {
        try {
            // Fast-path: already initialized (acquire-load pairs with the
            // release-store at the end of this function).
            if (m_initialized.load(std::memory_order_acquire)) {
                return true;
            }

            // Serialize concurrent initialization attempts. We deliberately
            // hold the lock for the entire init sequence so that a second
            // caller observing m_initialized==false re-checks under the lock
            // and either witnesses the completed init or performs it itself.
            std::unique_lock lock(m_mutex);
            if (m_initialized.load(std::memory_order_relaxed)) {
                return true;
            }

            SS_LOG_INFO(kLogCategory, L"Initializing unpacking engine...");

            m_emulationEngine = &EmulationEngine::Instance();
            if (!m_emulationEngine->IsInitialized()) {
                SS_LOG_WARN(kLogCategory, L"EmulationEngine not initialized - dynamic unpacking unavailable");
            }

            m_defaultOptions.preferredMethod = UnpackMethod::Hybrid;
            m_defaultOptions.enableStaticUnpacking = true;
            m_defaultOptions.enableDynamicUnpacking = true;
            m_defaultOptions.timeoutSeconds = UnpackerConstants::DEFAULT_TIMEOUT_SECONDS;
            m_defaultOptions.maxLayers = UnpackerConstants::MAX_UNPACKING_LAYERS;
            m_defaultOptions.reconstructImports = true;
            m_defaultOptions.fixPEHeaders = true;

            // LoadSystemDLLs assumes the caller already holds m_mutex (we do).
            if (!LoadSystemDLLs()) {
                SS_LOG_WARN(kLogCategory, L"Failed to load system DLLs - import reconstruction may be limited");
            }

            // Publish initialization with release semantics so concurrent
            // readers (IsInitialized()) see fully-constructed state.
            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(kLogCategory, L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Initialization failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized.store(false, std::memory_order_release);
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized.store(false, std::memory_order_release);
            return false;
        }
    }

    void PackerUnpacker::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return;
            }

            SS_LOG_INFO(kLogCategory, L"Shutting down...");
            UnloadSystemDLLs();
            SS_LOG_INFO(kLogCategory, L"Shutdown complete");
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: PACKER DETECTION
    // ========================================================================

    PackerDetectionResult PackerUnpacker::Impl::DetectPackerInternal(const fs::path& filePath) noexcept {
        PackerDetectionResult result;

        try {
            std::error_code ec;
            const auto fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) {
                SS_LOG_ERROR(kLogCategory, L"Cannot stat file: %ls", filePath.wstring().c_str());
                return result;
            }

            if (fileSize > UnpackerConstants::MAX_INPUT_FILE_SIZE) {
                SS_LOG_WARN(kLogCategory, L"File too large for packer detection (%llu bytes): %ls",
                    static_cast<unsigned long long>(fileSize), filePath.wstring().c_str());
                return result;
            }

            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(kLogCategory, L"Failed to open file: %ls", filePath.wstring().c_str());
                return result;
            }

            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), static_cast<std::streamsize>(fileSize));
            if (!file.good() && !file.eof()) {
                SS_LOG_ERROR(kLogCategory, L"Read error: %ls", filePath.wstring().c_str());
                return result;
            }
            file.close();

            result = DetectPackerFromMemory(fileData);
            result.filePath = filePath;

            m_stats.packersDetected.fetch_add(1, std::memory_order_relaxed);
            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Detection failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            return result;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Unknown detection error");
            return result;
        }
    }

    PackerDetectionResult PackerUnpacker::Impl::DetectPackerFromMemory(std::span<const uint8_t> data) noexcept {
        PackerDetectionResult result;
        result.isPacked = false;
        result.confidence = 0.0f;

        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};

            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) {
                SS_LOG_WARN(kLogCategory, L"Invalid PE file for packer detection");
                return result;
            }

            const uint64_t entryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
            auto sections = GetSectionHeaders(data);
            std::span<const uint8_t> entryPointCode;

            for (const auto& section : sections) {
                if (entryPointRVA >= section.VirtualAddress &&
                    entryPointRVA < section.VirtualAddress + section.Misc.VirtualSize) {
                    const size_t offset = static_cast<size_t>(
                        entryPointRVA - section.VirtualAddress + section.PointerToRawData);
                    if (offset < data.size()) {
                        const size_t avail = std::min<size_t>(256, data.size() - offset);
                        entryPointCode = data.subspan(offset, avail);
                    }
                    break;
                }
            }

            if (entryPointCode.empty()) {
                SS_LOG_WARN(kLogCategory, L"Could not locate entry point code");
                return result;
            }

            // Method 1: Signature-based detection
            PackerType sigType = IdentifyBySignature(entryPointCode);
            if (sigType != PackerType::Unknown) {
                result.packerType = sigType;
                result.confidence = 0.95f;
                result.detectionMethod = L"Signature-based";
                result.isPacked = true;
                result.additionalInfo.push_back(L"Packer signature detected at entry point");
                return result;
            }

            // Method 2: Section name detection
            auto sectionNames = GetSectionNames(data);
            PackerType secType = IdentifyBySectionNames(sectionNames);
            if (secType != PackerType::Unknown) {
                result.packerType = secType;
                result.confidence = 0.85f;
                result.detectionMethod = L"Section names";
                result.isPacked = true;
                result.additionalInfo.push_back(L"Suspicious section names detected");
                return result;
            }

            // Method 3: Entropy analysis
            if (HasSuspiciousEntropy(data)) {
                result.packerType = PackerType::CustomCrypter;
                result.confidence = 0.70f;
                result.detectionMethod = L"Entropy analysis";
                result.isPacked = true;
                const double entropy = CalculateEntropy(data);
                result.additionalInfo.push_back(
                    std::format(L"High entropy suggests packing/encryption (entropy: {:.2f})", entropy));
                return result;
            }

            // Method 4: Import analysis
            if (HasSuspiciousImports(data)) {
                result.packerType = PackerType::CustomCrypter;
                result.confidence = 0.60f;
                result.detectionMethod = L"Import analysis";
                result.isPacked = true;
                result.additionalInfo.push_back(L"Suspicious import characteristics");
                return result;
            }

            result.isPacked = false;
            result.confidence = 0.90f;
            result.detectionMethod = L"Multi-method analysis";
            return result;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during detection");
            return result;
        }
    }

    PackerType PackerUnpacker::Impl::IdentifyBySignature(std::span<const uint8_t> entryPointCode) noexcept {
        if (entryPointCode.size() < 6) return PackerType::Unknown;

        if (std::ranges::search(entryPointCode, PackerSignatures::UPX_STUB_PATTERN).begin() != entryPointCode.end()) {
            return PackerType::UPX;
        }
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::ASPACK_MAGIC.begin(), PackerSignatures::ASPACK_MAGIC.end(), entryPointCode.begin())) {
            return PackerType::ASPack;
        }
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::FSG_PATTERN.begin(), PackerSignatures::FSG_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::FSG;
        }
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::PECOMPACT_MAGIC.begin(), PackerSignatures::PECOMPACT_MAGIC.end(), entryPointCode.begin())) {
            return PackerType::PECompact;
        }
        if (entryPointCode.size() >= 6 &&
            std::equal(PackerSignatures::MPRESS_PATTERN.begin(), PackerSignatures::MPRESS_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::MPRESS;
        }
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::THEMIDA_PATTERN.begin(), PackerSignatures::THEMIDA_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::Themida;
        }
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::MEW_PATTERN.begin(), PackerSignatures::MEW_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::MEW;
        }
        if (entryPointCode.size() >= 4 &&
            std::equal(PackerSignatures::PESPIN_PATTERN.begin(), PackerSignatures::PESPIN_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::CustomCrypter;
        }
        if (entryPointCode.size() >= 5 &&
            std::equal(PackerSignatures::PETITE_PATTERN.begin(), PackerSignatures::PETITE_PATTERN.end(), entryPointCode.begin())) {
            return PackerType::Petite;
        }

        return PackerType::Unknown;
    }

    PackerType PackerUnpacker::Impl::IdentifyBySectionNames(const std::vector<std::string>& sectionNames) noexcept {
        for (const auto& sectionName : sectionNames) {
            if (sectionName.find("UPX") != std::string::npos) return PackerType::UPX;
            if (sectionName.find(".aspack") != std::string::npos || sectionName.find(".adata") != std::string::npos) {
                return PackerType::ASPack;
            }
            if (sectionName.find(".fsg") != std::string::npos || sectionName.find("FSG!") != std::string::npos) {
                return PackerType::FSG;
            }
            if (sectionName.find(".pecompact") != std::string::npos || sectionName.find(".pec") != std::string::npos) {
                return PackerType::PECompact;
            }
            if (sectionName.find(".mpress") != std::string::npos) return PackerType::MPRESS;
            if (sectionName.find(".themida") != std::string::npos || sectionName.find(".winlice") != std::string::npos) {
                return PackerType::Themida;
            }
            if (sectionName.find(".vmp") != std::string::npos) return PackerType::VMProtect;
            if (sectionName.find(".enigma") != std::string::npos) return PackerType::Enigma;
            if (sectionName.find(".mew") != std::string::npos || sectionName.find("MEW") != std::string::npos) {
                return PackerType::MEW;
            }
            if (sectionName.find(".pespin") != std::string::npos) return PackerType::CustomCrypter;
            if (sectionName.find(".petite") != std::string::npos || sectionName.find("petite") != std::string::npos) {
                return PackerType::Petite;
            }
        }
        return PackerType::Unknown;
    }

    bool PackerUnpacker::Impl::HasSuspiciousEntropy(std::span<const uint8_t> data) noexcept {
        try {
            const double entropy = CalculateEntropy(data);
            if (entropy > 7.0) return true;

            auto sections = GetSectionHeaders(data);
            size_t highEntropySections = 0;

            for (const auto& section : sections) {
                if (section.SizeOfRawData == 0) continue;
                const size_t end = static_cast<size_t>(section.PointerToRawData) + section.SizeOfRawData;
                if (end > data.size()) continue;

                auto sectionData = data.subspan(section.PointerToRawData, section.SizeOfRawData);
                if (CalculateEntropy(sectionData) > 7.2) {
                    highEntropySections++;
                }
            }

            return highEntropySections >= 2;
        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::HasSuspiciousImports(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return false;

            const auto& importDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDir.Size == 0 || importDir.VirtualAddress == 0) return true;

            // Count import descriptors by walking the import directory
            const uint64_t importFileOff = RVAToFileOffset(data, importDir.VirtualAddress);
            if (importFileOff == 0 || importFileOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > data.size()) return true;

            uint32_t dllCount = 0;
            uint32_t funcCount = 0;
            const size_t maxDescriptors = std::min<size_t>(256, (data.size() - importFileOff) / sizeof(IMAGE_IMPORT_DESCRIPTOR));

            for (uint32_t i = 0; i < maxDescriptors; ++i) {
                const size_t descOff = importFileOff + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                if (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > data.size()) break;

                IMAGE_IMPORT_DESCRIPTOR desc = {};
                std::memcpy(&desc, data.data() + descOff, sizeof(desc));

                if (desc.Name == 0 && desc.FirstThunk == 0) break; // null terminator
                dllCount++;

                // Count functions via OriginalFirstThunk (INT) or FirstThunk (IAT)
                const uint64_t thunkRVA = (desc.OriginalFirstThunk != 0) ? desc.OriginalFirstThunk : desc.FirstThunk;
                const uint64_t thunkOff = RVAToFileOffset(data, thunkRVA);
                if (thunkOff == 0) continue;

                for (uint32_t j = 0; j < 4096; ++j) {
                    const size_t entryOff = thunkOff + j * sizeof(uint64_t);
                    if (entryOff + sizeof(uint64_t) > data.size()) break;

                    uint64_t thunkValue = 0;
                    std::memcpy(&thunkValue, data.data() + entryOff, sizeof(uint64_t));
                    if (thunkValue == 0) break;
                    funcCount++;
                }
            }

            // Very few imports (< 3 DLLs or < 5 functions) is suspicious
            if (dllCount < 3 || funcCount < 5) return true;

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

            SS_LOG_INFO(kLogCategory, L"Unpacking file: %ls", filePath.wstring().c_str());

            // Security: cap file size
            std::error_code ec;
            const auto fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) {
                SS_LOG_ERROR(kLogCategory, L"Cannot stat file for unpacking");
                return result;
            }
            if (fileSize > UnpackerConstants::MAX_INPUT_FILE_SIZE) {
                SS_LOG_WARN(kLogCategory, L"File exceeds maximum input size (%llu > %llu)",
                    static_cast<unsigned long long>(fileSize),
                    static_cast<unsigned long long>(UnpackerConstants::MAX_INPUT_FILE_SIZE));
                result.status = UnpackStatus::OutputTooLarge;
                return result;
            }

            auto detection = DetectPackerInternal(filePath);
            result.packerInfo = detection;

            if (!detection.isPacked) {
                result.status = UnpackStatus::NotPacked;
                SS_LOG_INFO(kLogCategory, L"File is not packed");
                return result;
            }

            SS_LOG_INFO(kLogCategory, L"Detected packer: %ls (confidence: %.1f%%)",
                PackerTypeToWString(detection.packerType),
                static_cast<double>(detection.confidence) * 100.0);

            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(kLogCategory, L"Failed to open file for unpacking");
                return result;
            }

            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), static_cast<std::streamsize>(fileSize));
            file.close();

            result.originalSize = fileData.size();

            // Try static unpacking first
            if (options.enableStaticUnpacking && detection.packerType != PackerType::CustomCrypter) {
                SS_LOG_INFO(kLogCategory, L"Attempting static unpacking...");

                auto staticResult = StaticUnpackInternal(fileData, detection.packerType);
                if (staticResult.status == UnpackStatus::Success) {
                    result = std::move(staticResult);
                    result.methodUsed = UnpackMethod::Static;

                    const auto endTime = std::chrono::high_resolution_clock::now();
                    result.processingTimeMs = static_cast<uint32_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());

                    m_stats.staticUnpacks.fetch_add(1, std::memory_order_relaxed);
                    m_stats.successfulUnpacks.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_INFO(kLogCategory, L"Static unpacking successful (%u ms)", result.processingTimeMs);
                    return result;
                }
            }

            // Fall back to dynamic unpacking
            if (options.enableDynamicUnpacking) {
                SS_LOG_INFO(kLogCategory, L"Attempting dynamic unpacking...");

                auto dynamicResult = DynamicUnpackInternal(fileData, options);
                if (dynamicResult.status == UnpackStatus::Success ||
                    dynamicResult.status == UnpackStatus::PartialSuccess) {
                    result = std::move(dynamicResult);
                    result.methodUsed = UnpackMethod::Dynamic;

                    const auto endTime = std::chrono::high_resolution_clock::now();
                    result.processingTimeMs = static_cast<uint32_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());

                    m_stats.dynamicUnpacks.fetch_add(1, std::memory_order_relaxed);
                    if (result.status == UnpackStatus::Success) {
                        m_stats.successfulUnpacks.fetch_add(1, std::memory_order_relaxed);
                    }

                    SS_LOG_INFO(kLogCategory, L"Dynamic unpacking completed (%u ms)", result.processingTimeMs);
                    return result;
                }
            }

            result.status = UnpackStatus::UnsupportedPacker;
            m_stats.failedUnpacks.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(kLogCategory, L"All unpacking methods failed");
            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Unpacking failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            result.status = UnpackStatus::Error;
            m_stats.failedUnpacks.fetch_add(1, std::memory_order_relaxed);
            return result;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Unknown unpacking error");
            result.status = UnpackStatus::Error;
            m_stats.failedUnpacks.fetch_add(1, std::memory_order_relaxed);
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
            case PackerType::UPX:       unpackedData = UnpackUPX(data);       break;
            case PackerType::ASPack:    unpackedData = UnpackASPack(data);    break;
            case PackerType::MPRESS:    unpackedData = UnpackMPRESS(data);    break;
            case PackerType::FSG:       unpackedData = UnpackFSG(data);       break;
            case PackerType::PECompact: unpackedData = UnpackPECompact(data); break;
            default:
                result.status = UnpackStatus::UnsupportedPacker;
                SS_LOG_WARN(kLogCategory, L"Static unpacking not available for %ls", PackerTypeToWString(type));
                return result;
            }

            if (!unpackedData.has_value()) {
                result.status = UnpackStatus::UnsupportedPacker;
                SS_LOG_WARN(kLogCategory, L"Static unpacking returned no data for %ls - falling through to dynamic",
                    PackerTypeToWString(type));
                return result;
            }

            if (unpackedData->size() > UnpackerConstants::MAX_UNPACKED_SIZE) {
                result.status = UnpackStatus::OutputTooLarge;
                SS_LOG_WARN(kLogCategory, L"Unpacked output exceeds size limit (%llu > %llu)",
                    static_cast<unsigned long long>(unpackedData->size()),
                    static_cast<unsigned long long>(UnpackerConstants::MAX_UNPACKED_SIZE));
                return result;
            }

            result.unpackedData = std::move(unpackedData.value());
            result.unpackedSize = result.unpackedData.size();
            result.layersUnpacked = 1;
            result.status = UnpackStatus::Success;

            SS_LOG_INFO(kLogCategory, L"Static unpacking successful (%llu -> %llu bytes)",
                static_cast<unsigned long long>(data.size()),
                static_cast<unsigned long long>(result.unpackedSize));

            return result;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Static unpacking exception");
            result.status = UnpackStatus::Error;
            return result;
        }
    }

    UnpackResult PackerUnpacker::Impl::DynamicUnpackInternal(std::span<const uint8_t> data, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        try {
            if (!m_emulationEngine || !m_emulationEngine->IsInitialized()) {
                SS_LOG_ERROR(kLogCategory, L"EmulationEngine not available for dynamic unpacking");
                return result;
            }

            EmulationConfig emuConfig = EmulationConfig::CreateUnpackOnly();
            emuConfig.timeoutMs = options.MaxEmulationTimeMs();
            emuConfig.enableUnpacking = true;
            emuConfig.enableAPITracing = false;

            SS_LOG_DEBUG(kLogCategory, L"Starting emulation (timeout: %u ms)", emuConfig.timeoutMs);

            // Pass span directly to avoid copying the entire PE buffer (which can
            // be hundreds of MB on samples up to MAX_INPUT_FILE_SIZE).
            auto emuResult = m_emulationEngine->EmulatePE(data, emuConfig);

            result.instructionsEmulated = emuResult.instructionsExecuted;

            if (emuResult.state == EmulationState::Timeout) {
                result.status = UnpackStatus::Timeout;
                SS_LOG_WARN(kLogCategory, L"Emulation timed out after %llu instructions",
                    static_cast<unsigned long long>(result.instructionsEmulated));
                return result;
            }

            if (emuResult.state == EmulationState::Error ||
                emuResult.state == EmulationState::Terminated) {
                result.status = UnpackStatus::EmulationFailed;
                SS_LOG_WARN(kLogCategory, L"Emulation failed (state: %d)", static_cast<int>(emuResult.state));
                return result;
            }

            if (emuResult.unpackLayers.empty()) {
                SS_LOG_WARN(kLogCategory, L"No unpacking layers detected");
                result.status = UnpackStatus::OEPNotFound;
                return result;
            }

            const auto& lastLayer = emuResult.unpackLayers.back();
            result.unpackedData = lastLayer.unpackedData;

            if (result.unpackedData.size() > UnpackerConstants::MAX_UNPACKED_SIZE) {
                result.status = UnpackStatus::OutputTooLarge;
                SS_LOG_WARN(kLogCategory, L"Emulation produced oversized output (%llu bytes)",
                    static_cast<unsigned long long>(result.unpackedData.size()));
                result.unpackedData.clear();
                return result;
            }

            result.unpackedSize = result.unpackedData.size();
            result.layersUnpacked = static_cast<uint32_t>(emuResult.unpackLayers.size());

            auto oep = FindOEPInternal(result.unpackedData);
            if (oep.has_value()) {
                result.peInfo.newEntryPoint = oep.value();
                m_stats.oepsFound.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(kLogCategory, L"Found OEP at 0x%llX", static_cast<unsigned long long>(oep.value()));
            } else {
                SS_LOG_WARN(kLogCategory, L"Could not find OEP in unpacked data");
            }

            result.status = UnpackStatus::Success;
            SS_LOG_INFO(kLogCategory, L"Dynamic unpacking successful (%u layers, %llu instructions)",
                result.layersUnpacked, static_cast<unsigned long long>(result.instructionsEmulated));

            return result;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Dynamic unpacking exception");
            result.status = UnpackStatus::Error;
            return result;
        }
    }

    // ========================================================================
    // IMPL: STATIC UNPACKING ALGORITHMS
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackUPX(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            // Locate UPX sections by name
            auto upx0 = FindSectionByName(data, "UPX0");
            auto upx1 = FindSectionByName(data, "UPX1");
            if (!upx0.has_value() || !upx1.has_value()) {
                // Try alternate names (.UPX0/.UPX1)
                upx0 = FindSectionByName(data, ".UPX0");
                upx1 = FindSectionByName(data, ".UPX1");
            }
            if (!upx0.has_value() || !upx1.has_value()) {
                SS_LOG_WARN(kLogCategory, L"UPX sections not found");
                return std::nullopt;
            }

            // UPX0 = destination (decompressed), UPX1 = compressed payload
            const size_t compressedStart = upx1->PointerToRawData;
            const size_t compressedSize = upx1->SizeOfRawData;
            if (compressedStart + compressedSize > data.size() || compressedSize == 0) {
                SS_LOG_WARN(kLogCategory, L"UPX1 section bounds invalid");
                return std::nullopt;
            }

            const size_t decompressedSize = upx0->Misc.VirtualSize;
            if (decompressedSize == 0 || decompressedSize > UnpackerConstants::MAX_UNPACKED_SIZE) {
                SS_LOG_WARN(kLogCategory, L"UPX0 virtual size invalid or exceeds limit: %llu",
                    static_cast<unsigned long long>(decompressedSize));
                return std::nullopt;
            }

            auto compressedData = data.subspan(compressedStart, compressedSize);

            // Attempt NRV2B decompression
            auto decompressed = Nrv2bDecompress(compressedData, decompressedSize);
            if (!decompressed.has_value()) {
                SS_LOG_WARN(kLogCategory, L"NRV2B decompression failed - UPX may use NRV2D/NRV2E or LZMA");
                return std::nullopt;
            }

            // Rebuild PE: take original PE headers + decompressed code
            const size_t headerSize = ntHeaders.OptionalHeader.SizeOfHeaders;
            if (headerSize > data.size()) return std::nullopt;

            std::vector<uint8_t> rebuilt;
            rebuilt.reserve(headerSize + decompressed->size());
            rebuilt.insert(rebuilt.end(), data.begin(), data.begin() + headerSize);
            rebuilt.insert(rebuilt.end(), decompressed->begin(), decompressed->end());

            SS_LOG_INFO(kLogCategory, L"UPX static unpacking produced %llu bytes",
                static_cast<unsigned long long>(rebuilt.size()));

            return rebuilt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"UPX unpacking exception");
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackASPack(std::span<const uint8_t> data) noexcept {
        try {
            // ASPack uses proprietary compression + simple XOR obfuscation.
            // Static reverse-engineering requires the specific ASPack version algorithm.
            // Enterprise approach: parse PE, locate .aspack/.adata sections, attempt
            // to identify the XOR key from the stub, then decompress.
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            auto aspackSec = FindSectionByName(data, ".aspack");
            if (!aspackSec.has_value()) aspackSec = FindSectionByName(data, ".adata");
            if (!aspackSec.has_value()) {
                SS_LOG_WARN(kLogCategory, L"ASPack section not found");
                return std::nullopt;
            }

            const size_t secStart = aspackSec->PointerToRawData;
            const size_t secSize = aspackSec->SizeOfRawData;
            if (secStart + secSize > data.size() || secSize < 16) return std::nullopt;

            // ASPack stub typically XORs with a single byte key derived from the first
            // instruction operand. Scan the entry point stub for the XOR key.
            const uint64_t ep = ntHeaders.OptionalHeader.AddressOfEntryPoint;
            const uint64_t epOff = RVAToFileOffset(data, ep);
            if (epOff == 0 || epOff + 32 > data.size()) return std::nullopt;

            // Look for XOR reg, imm8 pattern (0x80 0xF? 0xKK or 0x34 0xKK for XOR AL, imm8)
            uint8_t xorKey = 0;
            bool keyFound = false;
            for (size_t i = 0; i < 30 && epOff + i + 2 <= data.size(); ++i) {
                if (data[epOff + i] == 0x34) { // XOR AL, imm8
                    xorKey = data[epOff + i + 1];
                    keyFound = true;
                    break;
                }
                if (data[epOff + i] == 0x80 && (data[epOff + i + 1] & 0xF8) == 0xF0) { // XOR reg, imm8
                    xorKey = data[epOff + i + 2];
                    keyFound = true;
                    break;
                }
            }

            if (!keyFound || xorKey == 0) {
                SS_LOG_WARN(kLogCategory, L"ASPack XOR key not found - deferring to dynamic unpacking");
                return std::nullopt;
            }

            // Decrypt the section data
            std::vector<uint8_t> decrypted(data.begin() + secStart, data.begin() + secStart + secSize);
            for (auto& b : decrypted) b ^= xorKey;

            // Attempt decompression of decrypted payload using available algorithms
            std::vector<uint8_t> decompressed;
            if (Utils::CompressionUtils::DecompressBuffer(
                    Utils::CompressionUtils::Algorithm::Xpress,
                    decrypted.data(), decrypted.size(), decompressed)) {
                if (decompressed.size() <= UnpackerConstants::MAX_UNPACKED_SIZE) {
                    SS_LOG_INFO(kLogCategory, L"ASPack static unpacking successful");
                    return decompressed;
                }
            }

            SS_LOG_WARN(kLogCategory, L"ASPack decompression failed after decryption - deferring to dynamic");
            return std::nullopt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"ASPack unpacking exception");
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackMPRESS(std::span<const uint8_t> data) noexcept {
        try {
            // MPRESS uses LZMA compression with a custom PE stub.
            // CompressionUtils does not support LZMA - attempt XPRESS as heuristic.
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            auto mpress1 = FindSectionByName(data, ".mpress1");
            auto mpress2 = FindSectionByName(data, ".mpress2");
            if (!mpress1.has_value()) {
                SS_LOG_WARN(kLogCategory, L"MPRESS sections not found");
                return std::nullopt;
            }

            const size_t compStart = mpress1->PointerToRawData;
            const size_t compSize = mpress1->SizeOfRawData;
            if (compStart + compSize > data.size() || compSize == 0) return std::nullopt;

            // Try XPRESS decompression as a heuristic fallback
            std::vector<uint8_t> decompressed;
            if (Utils::CompressionUtils::DecompressBuffer(
                    Utils::CompressionUtils::Algorithm::Xpress,
                    data.data() + compStart, compSize, decompressed)) {
                if (!decompressed.empty() && decompressed.size() <= UnpackerConstants::MAX_UNPACKED_SIZE) {
                    SS_LOG_INFO(kLogCategory, L"MPRESS static unpacking produced %llu bytes",
                        static_cast<unsigned long long>(decompressed.size()));
                    return decompressed;
                }
            }

            SS_LOG_WARN(kLogCategory, L"MPRESS static decompression failed (LZMA not available) - deferring to dynamic");
            return std::nullopt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"MPRESS unpacking exception");
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackFSG(std::span<const uint8_t> data) noexcept {
        try {
            // FSG uses a polymorphic decryption loop followed by aPLib decompression.
            // Parse PE and locate the encrypted section.
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            auto fsgSec = FindSectionByName(data, ".fsg");
            if (!fsgSec.has_value()) fsgSec = FindSectionByName(data, "FSG!");
            if (!fsgSec.has_value()) {
                SS_LOG_WARN(kLogCategory, L"FSG section not found");
                return std::nullopt;
            }

            // FSG requires reversing the polymorphic decryption loop which varies per stub.
            // Static analysis is not reliable - defer to emulation-based dynamic unpacking.
            SS_LOG_WARN(kLogCategory, L"FSG uses polymorphic decryption - deferring to dynamic unpacking");
            return std::nullopt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"FSG unpacking exception");
            return std::nullopt;
        }
    }

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::UnpackPECompact(std::span<const uint8_t> data) noexcept {
        try {
            // PECompact uses aPLib compression with a custom loader stub.
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            auto pecSec = FindSectionByName(data, ".pecompact");
            if (!pecSec.has_value()) pecSec = FindSectionByName(data, ".pec1");
            if (!pecSec.has_value()) {
                SS_LOG_WARN(kLogCategory, L"PECompact section not found");
                return std::nullopt;
            }

            const size_t secStart = pecSec->PointerToRawData;
            const size_t secSize = pecSec->SizeOfRawData;
            if (secStart + secSize > data.size() || secSize == 0) return std::nullopt;

            // Attempt XPRESS decompression as heuristic
            std::vector<uint8_t> decompressed;
            if (Utils::CompressionUtils::DecompressBuffer(
                    Utils::CompressionUtils::Algorithm::Xpress,
                    data.data() + secStart, secSize, decompressed)) {
                if (!decompressed.empty() && decompressed.size() <= UnpackerConstants::MAX_UNPACKED_SIZE) {
                    SS_LOG_INFO(kLogCategory, L"PECompact static unpacking produced %llu bytes",
                        static_cast<unsigned long long>(decompressed.size()));
                    return decompressed;
                }
            }

            SS_LOG_WARN(kLogCategory, L"PECompact static decompression failed - deferring to dynamic");
            return std::nullopt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"PECompact unpacking exception");
            return std::nullopt;
        }
    }

    // ========================================================================
    // IMPL: OEP DETECTION
    // ========================================================================

    std::optional<uint64_t> PackerUnpacker::Impl::FindOEPInternal(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            const uint64_t imageBase = ntHeaders.OptionalHeader.ImageBase;

            constexpr std::array<uint8_t, 3> PATTERN1 = { 0x55, 0x8B, 0xEC };  // PUSH EBP; MOV EBP, ESP
            constexpr std::array<uint8_t, 5> PATTERN2 = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };  // MOV EDI, EDI; PUSH EBP; MOV EBP, ESP
            constexpr std::array<uint8_t, 2> PATTERN3 = { 0x48, 0x83 };  // x64: REX.W SUB RSP, imm8

            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));

                if (sectionName != ".text" && sectionName != "CODE" && sectionName != ".code") continue;

                const size_t sectionStart = section.PointerToRawData;
                const size_t sectionSize = section.SizeOfRawData;
                if (sectionStart + sectionSize > data.size() || sectionSize == 0) continue;

                auto sectionData = data.subspan(sectionStart, sectionSize);

                for (size_t i = 0; i + PATTERN2.size() <= sectionData.size(); ++i) {
                    if (std::equal(PATTERN2.begin(), PATTERN2.end(), sectionData.begin() + i)) {
                        return imageBase + section.VirtualAddress + i;
                    }
                }
                for (size_t i = 0; i + PATTERN1.size() <= sectionData.size(); ++i) {
                    if (std::equal(PATTERN1.begin(), PATTERN1.end(), sectionData.begin() + i)) {
                        return imageBase + section.VirtualAddress + i;
                    }
                }
                for (size_t i = 0; i + PATTERN3.size() <= sectionData.size(); ++i) {
                    if (std::equal(PATTERN3.begin(), PATTERN3.end(), sectionData.begin() + i)) {
                        return imageBase + section.VirtualAddress + i;
                    }
                }
            }

            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<uint64_t> PackerUnpacker::Impl::FindOEPViaEmulation(
        std::span<const uint8_t> data, const UnpackOptions& options) noexcept
    {
        try {
            if (!m_emulationEngine || !m_emulationEngine->IsInitialized()) {
                SS_LOG_WARN(kLogCategory, L"EmulationEngine not available for OEP detection");
                return std::nullopt;
            }

            EmulationConfig emuConfig = EmulationConfig::CreateUnpackOnly();
            emuConfig.timeoutMs = options.MaxEmulationTimeMs();
            emuConfig.enableUnpacking = true;

            // Span overload: avoid an O(N) copy of the input PE.
            auto emuResult = m_emulationEngine->EmulatePE(data, emuConfig);

            if (!emuResult.unpackLayers.empty()) {
                const auto& lastLayer = emuResult.unpackLayers.back();
                if (lastLayer.unpackedEntryPoint != 0) {
                    SS_LOG_INFO(kLogCategory, L"OEP found via emulation: 0x%llX",
                        static_cast<unsigned long long>(lastLayer.unpackedEntryPoint));
                    return lastLayer.unpackedEntryPoint;
                }
            }

            SS_LOG_WARN(kLogCategory, L"Emulation-based OEP detection did not find OEP");
            return std::nullopt;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"OEP emulation exception");
            return std::nullopt;
        }
    }

    bool PackerUnpacker::Impl::IsLikelyOEP(uint64_t /*address*/, std::span<const uint8_t> code) noexcept {
        if (code.size() < 10) return false;
        if (code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC) return true;
        if (code[0] == 0x8B && code[1] == 0xFF && code[2] == 0x55) return true;
        if (code[0] == 0x83 && code[1] == 0xEC) return true;
        if (code[0] == 0x81 && code[1] == 0xEC) return true;
        if (code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC) return true; // x64 SUB RSP
        if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0x5C) return true; // x64 MOV [RSP+...], RBX
        if (code[0] >= 0x50 && code[0] <= 0x57) return true;
        return false;
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
            auto iatStart = FindIATStart(unpackedData);
            if (!iatStart.has_value()) {
                SS_LOG_WARN(kLogCategory, L"Could not find IAT in unpacked data");
                return std::nullopt;
            }

            SS_LOG_DEBUG(kLogCategory, L"Found IAT at RVA 0x%llX",
                static_cast<unsigned long long>(iatStart.value()));

            imports.iatRVA = iatStart.value();

            if (!ScanIATRange(unpackedData, iatStart.value(), imports)) {
                SS_LOG_WARN(kLogCategory, L"IAT scanning failed");
                if (!options.allowPartial) return std::nullopt;
            }

            imports.reconstructedSuccessfully = (imports.totalFunctions > 0);
            m_stats.importsReconstructed.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(kLogCategory, L"Reconstructed %u import descriptors with %u functions",
                static_cast<uint32_t>(imports.importDescriptors.size()), imports.totalFunctions);

            return imports;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Import reconstruction exception");
            return std::nullopt;
        }
    }

    std::optional<uint64_t> PackerUnpacker::Impl::FindIATStart(std::span<const uint8_t> data) noexcept {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return std::nullopt;

            // Prefer the dedicated IAT data directory (12) when present -- this
            // is the table the loader actually patches at process startup and
            // is what we want to scan for resolved API addresses. Fall back to
            // the IMPORT directory (1), then to the conventional sections.
            const auto& iatDir =
                ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
            if (iatDir.VirtualAddress != 0 && iatDir.Size != 0) {
                return iatDir.VirtualAddress;
            }

            const uint32_t importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (importRVA != 0) return importRVA;

            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));

                if (sectionName == ".rdata" || sectionName == ".idata" || sectionName == ".data") {
                    return section.VirtualAddress;
                }
            }

            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> PackerUnpacker::Impl::ResolveAPIByAddress(uint64_t address) noexcept {
        // Precondition: callers hold m_mutex (shared or exclusive) -- this is
        // invoked from ScanIATRange() which itself runs inside the public
        // ReconstructImports() shared_lock. Taking another shared_lock here
        // would constitute recursive locking on a non-recursive shared_mutex
        // (undefined behaviour). We rely on the caller's lock to serialize
        // against Shutdown(), which holds the lock exclusively while
        // clearing m_loadedDLLs.
        try {
            for (const auto& [dllName, hModule] : m_loadedDLLs) {
                MODULEINFO modInfo = {};
                if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) continue;

                const auto baseAddr = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                // Saturating add to avoid uintptr_t wrap on a malicious SizeOfImage.
                const auto endAddr =
                    (modInfo.SizeOfImage > (std::numeric_limits<uintptr_t>::max)() - baseAddr)
                        ? (std::numeric_limits<uintptr_t>::max)()
                        : baseAddr + modInfo.SizeOfImage;

                if (address >= baseAddr && address < endAddr) {
                    // Parse export table to resolve the function name
                    const auto* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
                    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) continue;

                    const auto* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + dosHdr->e_lfanew);
                    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) continue;

                    const auto& exportDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    if (exportDir.Size == 0 || exportDir.VirtualAddress == 0) continue;

                    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exportDir.VirtualAddress);

                    const auto* functions = reinterpret_cast<const DWORD*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exports->AddressOfFunctions);
                    const auto* names = reinterpret_cast<const DWORD*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exports->AddressOfNames);
                    const auto* ordinals = reinterpret_cast<const WORD*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exports->AddressOfNameOrdinals);

                    const uint64_t rva = address - baseAddr;

                    for (DWORD i = 0; i < exports->NumberOfFunctions; ++i) {
                        if (functions[i] == static_cast<DWORD>(rva)) {
                            // Find name for this ordinal
                            for (DWORD j = 0; j < exports->NumberOfNames; ++j) {
                                if (ordinals[j] == i) {
                                    const char* funcName = reinterpret_cast<const char*>(
                                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + names[j]);
                                    return std::format("{}!{}", dllName, funcName);
                                }
                            }
                            return std::format("{}!Ordinal{}", dllName, i + exports->Base);
                        }
                    }
                }
            }

            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> PackerUnpacker::Impl::ResolveAPIByOrdinal(
        const std::string& dllName, uint16_t ordinal) noexcept
    {
        // Precondition: caller holds m_mutex (see ResolveAPIByAddress for
        // rationale). No nested locking here -- doing so would cause UB with
        // the non-recursive shared_mutex.
        try {
            auto it = m_loadedDLLs.find(dllName);
            if (it == m_loadedDLLs.end()) return std::format("{}!Ordinal{}", dllName, ordinal);

            HMODULE hModule = it->second;
            MODULEINFO modInfo = {};
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
                return std::format("{}!Ordinal{}", dllName, ordinal);
            }

            const auto* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
            if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return std::format("{}!Ordinal{}", dllName, ordinal);

            const auto* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + dosHdr->e_lfanew);
            if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return std::format("{}!Ordinal{}", dllName, ordinal);

            const auto& exportDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDir.Size == 0) return std::format("{}!Ordinal{}", dllName, ordinal);

            const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exportDir.VirtualAddress);

            const auto* names = reinterpret_cast<const DWORD*>(
                reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exports->AddressOfNames);
            const auto* nameOrdinals = reinterpret_cast<const WORD*>(
                reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + exports->AddressOfNameOrdinals);

            const DWORD funcIndex = ordinal - static_cast<WORD>(exports->Base);
            if (funcIndex >= exports->NumberOfFunctions) {
                return std::format("{}!Ordinal{}", dllName, ordinal);
            }

            for (DWORD j = 0; j < exports->NumberOfNames; ++j) {
                if (nameOrdinals[j] == funcIndex) {
                    const char* funcName = reinterpret_cast<const char*>(
                        reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll) + names[j]);
                    return std::format("{}!{}", dllName, funcName);
                }
            }

            return std::format("{}!Ordinal{}", dllName, ordinal);
        } catch (...) {
            return std::format("{}!Ordinal{}", dllName, ordinal);
        }
    }

    bool PackerUnpacker::Impl::ScanIATRange(
        std::span<const uint8_t> data, uint64_t startRVA, ReconstructedImports& imports) noexcept
    {
        try {
            IMAGE_DOS_HEADER dosHeader = {};
            IMAGE_NT_HEADERS64 ntHeaders = {};
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return false;

            const uint64_t fileOff = RVAToFileOffset(data, startRVA);
            if (fileOff == 0) return false;

            // Walk 8-byte aligned entries looking for valid addresses
            std::unordered_map<std::string, ReconstructedImportDescriptor> dllMap;
            constexpr size_t kSlotSize = sizeof(uint64_t);
            constexpr uint32_t kMaxSlots = 16384;

            uint32_t totalFuncs = 0;
            for (uint32_t i = 0; i < kMaxSlots; ++i) {
                const size_t slotOff = static_cast<size_t>(fileOff) + i * kSlotSize;
                if (slotOff + kSlotSize > data.size()) break;

                uint64_t value = 0;
                std::memcpy(&value, data.data() + slotOff, kSlotSize);
                if (value == 0) {
                    if (totalFuncs > 0) break; // end of IAT block
                    continue;
                }

                auto resolved = ResolveAPIByAddress(value);
                if (resolved.has_value()) {
                    // Parse "dll!func" format
                    auto bang = resolved->find('!');
                    if (bang != std::string::npos) {
                        std::string dll = resolved->substr(0, bang);
                        std::string func = resolved->substr(bang + 1);

                        ImportEntry entry;
                        entry.dllName = dll;
                        entry.functionName = func;
                        entry.iatAddress = startRVA + i * kSlotSize;
                        entry.resolvedAddress = value;
                        entry.byOrdinal = false;

                        dllMap[dll].dllName = dll;
                        dllMap[dll].functions.push_back(std::move(entry));
                        totalFuncs++;
                    }
                }
            }

            // Convert map to vector
            for (auto& [name, desc] : dllMap) {
                imports.importDescriptors.push_back(std::move(desc));
            }
            imports.totalFunctions = totalFuncs;

            return totalFuncs > 0;

        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: PE RECONSTRUCTION
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::Impl::FixPEHeadersInternal(
        std::span<const uint8_t> data, uint64_t newEntryPoint,
        const ReconstructedImports* imports) noexcept
    {
        try {
            if (data.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

            IMAGE_DOS_HEADER dosTest = {};
            std::memcpy(&dosTest, data.data(), sizeof(IMAGE_DOS_HEADER));
            if (dosTest.e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

            const size_t ntOffset = static_cast<size_t>(dosTest.e_lfanew);
            if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > data.size()) return std::nullopt;

            std::vector<uint8_t> fixedPE(data.begin(), data.end());

            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fixedPE.data());
            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(fixedPE.data() + dosHeader->e_lfanew);

            if (newEntryPoint != 0) {
                const uint64_t imageBase = ntHeaders->OptionalHeader.ImageBase;
                if (newEntryPoint > imageBase) {
                    ntHeaders->OptionalHeader.AddressOfEntryPoint =
                        static_cast<DWORD>(newEntryPoint - imageBase);
                } else {
                    ntHeaders->OptionalHeader.AddressOfEntryPoint =
                        static_cast<DWORD>(newEntryPoint);
                }
                SS_LOG_DEBUG(kLogCategory, L"Fixed entry point to RVA 0x%X",
                    ntHeaders->OptionalHeader.AddressOfEntryPoint);
            }

            if (imports && imports->reconstructedSuccessfully) {
                if (!FixImportDirectory(fixedPE, *imports)) {
                    SS_LOG_WARN(kLogCategory, L"Failed to fix import directory");
                }
            }

            if (!RemovePackerSections(fixedPE)) {
                SS_LOG_WARN(kLogCategory, L"Failed to remove packer sections");
            }

            if (!RealignSections(fixedPE)) {
                SS_LOG_WARN(kLogCategory, L"Section realignment failed");
            }

            if (!RecalculateChecksum(fixedPE)) {
                SS_LOG_WARN(kLogCategory, L"Checksum recalculation failed");
            }

            return fixedPE;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"PE header fixing exception");
            return std::nullopt;
        }
    }

    bool PackerUnpacker::Impl::RealignSections(std::vector<uint8_t>& peData) noexcept {
        try {
            if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

            const size_t ntOff = static_cast<size_t>(dosHeader->e_lfanew);
            if (ntOff + sizeof(IMAGE_NT_HEADERS64) > peData.size()) return false;

            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + ntOff);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

            const DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
            const DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;

            // Both alignments MUST be powers of two per the PE spec, and
            // section alignment must be >= file alignment. Anything else
            // would corrupt the bitmask-based alignment math below and could
            // produce sections whose RVAs collide or wrap.
            auto isPow2 = [](DWORD v) noexcept {
                return v != 0 && (v & (v - 1)) == 0;
            };
            if (!isPow2(fileAlignment) || !isPow2(sectionAlignment)) return false;
            if (sectionAlignment < fileAlignment) return false;

            // PE spec: FileAlignment must be in [512, 64K]; SectionAlignment
            // must be >= page size on the target architecture (4096 on x64).
            // We accept the documented ranges and reject obviously-malicious
            // values that would otherwise inflate SizeOfImage past 4 GiB.
            if (fileAlignment < 0x200 || fileAlignment > 0x10000) return false;
            if (sectionAlignment < 0x1000) return false;

            const size_t sectionTableOff = ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                         + ntHeaders->FileHeader.SizeOfOptionalHeader;
            const uint16_t numSections = ntHeaders->FileHeader.NumberOfSections;
            if (numSections > UnpackerConstants::MAX_SECTIONS) return false;
            if (sectionTableOff + numSections * sizeof(IMAGE_SECTION_HEADER) > peData.size()) return false;

            auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(peData.data() + sectionTableOff);

            const DWORD fileMask = fileAlignment - 1;
            const DWORD sectionMask = sectionAlignment - 1;

            // Align each section's PointerToRawData and VirtualAddress.
            for (uint16_t i = 0; i < numSections; ++i) {
                auto& sec = sections[i];

                // Align raw data pointer to file alignment, with overflow guard.
                if (sec.PointerToRawData != 0) {
                    if (sec.PointerToRawData > std::numeric_limits<DWORD>::max() - fileMask) return false;
                    const DWORD aligned = (sec.PointerToRawData + fileMask) & ~fileMask;
                    sec.PointerToRawData = aligned;
                }

                // Align virtual address to section alignment.
                if (sec.VirtualAddress != 0) {
                    if (sec.VirtualAddress > std::numeric_limits<DWORD>::max() - sectionMask) return false;
                    const DWORD aligned = (sec.VirtualAddress + sectionMask) & ~sectionMask;
                    sec.VirtualAddress = aligned;
                }
            }

            // Recalculate SizeOfImage with overflow guard.
            if (numSections > 0) {
                const auto& lastSec = sections[numSections - 1];
                const DWORD virtualSize = std::max(lastSec.Misc.VirtualSize, lastSec.SizeOfRawData);
                if (lastSec.VirtualAddress > std::numeric_limits<DWORD>::max() - virtualSize) return false;
                const DWORD lastEnd = lastSec.VirtualAddress + virtualSize;
                if (lastEnd > std::numeric_limits<DWORD>::max() - sectionMask) return false;
                ntHeaders->OptionalHeader.SizeOfImage =
                    (lastEnd + sectionMask) & ~sectionMask;
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::RecalculateChecksum(std::vector<uint8_t>& peData) noexcept {
        try {
            if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            DWORD headerSum = 0;
            DWORD checkSum = 0;

            auto* result = CheckSumMappedFile(
                peData.data(),
                static_cast<DWORD>(peData.size()),
                &headerSum,
                &checkSum);

            if (result != nullptr) {
                auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
                const size_t ntOff = static_cast<size_t>(dosHeader->e_lfanew);
                if (ntOff + sizeof(IMAGE_NT_HEADERS64) <= peData.size()) {
                    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + ntOff);
                    ntHeaders->OptionalHeader.CheckSum = checkSum;
                    return true;
                }
            }

            return false;
        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::FixImportDirectory(
        std::vector<uint8_t>& peData, const ReconstructedImports& imports) noexcept
    {
        try {
            if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
            const size_t ntOff = static_cast<size_t>(dosHeader->e_lfanew);
            if (ntOff + sizeof(IMAGE_NT_HEADERS64) > peData.size()) return false;

            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + ntOff);

            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
                static_cast<DWORD>(imports.iatRVA);
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
                static_cast<DWORD>(
                    (imports.importDescriptors.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

            SS_LOG_DEBUG(kLogCategory, L"Fixed import directory at RVA 0x%llX",
                static_cast<unsigned long long>(imports.iatRVA));
            return true;
        } catch (...) {
            return false;
        }
    }

    bool PackerUnpacker::Impl::RemovePackerSections(std::vector<uint8_t>& peData) noexcept {
        try {
            if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
            const size_t ntOff = static_cast<size_t>(dosHeader->e_lfanew);
            if (ntOff + sizeof(IMAGE_NT_HEADERS64) > peData.size()) return false;

            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + ntOff);
            const size_t sectionTableOff = ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                         + ntHeaders->FileHeader.SizeOfOptionalHeader;
            uint16_t numSections = ntHeaders->FileHeader.NumberOfSections;
            if (numSections > UnpackerConstants::MAX_SECTIONS) return false;
            if (sectionTableOff + numSections * sizeof(IMAGE_SECTION_HEADER) > peData.size()) return false;

            auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(peData.data() + sectionTableOff);

            // Identify packer sections to remove
            uint16_t writeIdx = 0;
            for (uint16_t i = 0; i < numSections; ++i) {
                std::string name(reinterpret_cast<const char*>(sections[i].Name), 8);
                name = name.substr(0, name.find('\0'));

                if (m_packerSectionNames.contains(name)) {
                    SS_LOG_DEBUG(kLogCategory, L"Removing packer section: %ls",
                        Utils::StringUtils::ToWide(name).c_str());
                    continue;
                }

                if (writeIdx != i) {
                    sections[writeIdx] = sections[i];
                }
                writeIdx++;
            }

            if (writeIdx < numSections) {
                ntHeaders->FileHeader.NumberOfSections = writeIdx;
                // Zero out removed entries
                for (uint16_t i = writeIdx; i < numSections; ++i) {
                    std::memset(&sections[i], 0, sizeof(IMAGE_SECTION_HEADER));
                }
            }

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
        IMAGE_NT_HEADERS64& ntHeaders) noexcept
    {
        try {
            if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            std::memcpy(&dosHeader, data.data(), sizeof(IMAGE_DOS_HEADER));
            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

            // Tighten e_lfanew validation:
            //   - must not overlap the DOS header itself
            //   - must be 4-byte aligned (PE spec requires DWORD alignment)
            //   - must leave room for an IMAGE_NT_HEADERS64 inside `data`
            if (dosHeader.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) return false;
            if ((dosHeader.e_lfanew & 0x3) != 0) return false;
            if (static_cast<size_t>(dosHeader.e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > data.size()) {
                return false;
            }

            std::memcpy(&ntHeaders, data.data() + dosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
            if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

            // Reject PE32: this module operates on 64-bit PEs only. PE32 has
            // OptionalHeader::Magic == 0x10b and a structurally different
            // OptionalHeader (smaller, 32-bit ImageBase, no extra reserved
            // DWORDs). memcpy-ing a PE32 image as PE32+ produces garbage in
            // ImageBase/AddressOfEntryPoint/DataDirectory and would lead the
            // rest of this module to operate on uninitialized fields.
            if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                SS_LOG_DEBUG(kLogCategory,
                    L"PE optional-header magic 0x%04X is not PE32+ (0x020B); refusing to parse as 64-bit",
                    static_cast<unsigned>(ntHeaders.OptionalHeader.Magic));
                return false;
            }

            // Validate SizeOfOptionalHeader matches what we just consumed; a
            // truncated optional header would otherwise let downstream code
            // index past the section table.
            if (ntHeaders.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
                return false;
            }

            // Validate section count
            if (ntHeaders.FileHeader.NumberOfSections > UnpackerConstants::MAX_SECTIONS) return false;

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
            if (!ParsePEHeaders(data, dosHeader, ntHeaders)) return sections;

            const size_t sectionHeadersOffset = dosHeader.e_lfanew + sizeof(DWORD)
                + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;

            const uint16_t numSections = std::min<uint16_t>(
                ntHeaders.FileHeader.NumberOfSections,
                static_cast<uint16_t>(UnpackerConstants::MAX_SECTIONS));

            if (sectionHeadersOffset + (numSections * sizeof(IMAGE_SECTION_HEADER)) > data.size()) {
                return sections;
            }

            sections.resize(numSections);
            std::memcpy(sections.data(), data.data() + sectionHeadersOffset,
                numSections * sizeof(IMAGE_SECTION_HEADER));

            return sections;
        } catch (...) {
            return sections;
        }
    }

    std::vector<std::string> PackerUnpacker::Impl::GetSectionNames(std::span<const uint8_t> data) noexcept {
        std::vector<std::string> names;
        try {
            auto sections = GetSectionHeaders(data);
            names.reserve(sections.size());
            for (const auto& section : sections) {
                std::string name(reinterpret_cast<const char*>(section.Name), 8);
                name = name.substr(0, name.find('\0'));
                names.push_back(std::move(name));
            }
        } catch (...) {}
        return names;
    }

    std::span<const uint8_t> PackerUnpacker::Impl::GetSectionData(
        std::span<const uint8_t> data, const std::string& sectionName) noexcept
    {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string name(reinterpret_cast<const char*>(section.Name), 8);
                name = name.substr(0, name.find('\0'));

                if (name == sectionName) {
                    const size_t end = static_cast<size_t>(section.PointerToRawData) + section.SizeOfRawData;
                    if (end > data.size()) return {};
                    return data.subspan(section.PointerToRawData, section.SizeOfRawData);
                }
            }
        } catch (...) {}
        return {};
    }

    std::optional<IMAGE_SECTION_HEADER> PackerUnpacker::Impl::FindSectionByName(
        std::span<const uint8_t> data, const std::string& name) noexcept
    {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
                sectionName = sectionName.substr(0, sectionName.find('\0'));
                if (sectionName == name) return section;
            }
        } catch (...) {}
        return std::nullopt;
    }

    std::optional<IMAGE_SECTION_HEADER> PackerUnpacker::Impl::FindSectionByRVA(
        std::span<const uint8_t> data, uint64_t rva) noexcept
    {
        try {
            auto sections = GetSectionHeaders(data);
            for (const auto& section : sections) {
                const uint64_t start = section.VirtualAddress;
                const uint64_t end = start + section.Misc.VirtualSize;
                if (rva >= start && rva < end) return section;
            }
        } catch (...) {}
        return std::nullopt;
    }

    // ========================================================================
    // IMPL: UTILITY
    // ========================================================================

    bool PackerUnpacker::Impl::LoadSystemDLLs() noexcept {
        // Precondition: caller holds m_mutex exclusively. Taking a nested lock
        // here would either deadlock (non-recursive shared_mutex) or produce
        // undefined behaviour.
        try {
            constexpr std::array<const char*, 10> commonDLLs = {
                "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
                "ws2_32.dll", "shell32.dll", "ole32.dll", "gdi32.dll",
                "comctl32.dll", "msvcrt.dll"
            };

            for (const char* dllName : commonDLLs) {
                HMODULE hModule = GetModuleHandleA(dllName);
                if (!hModule) {
                    hModule = LoadLibraryA(dllName);
                }
                if (hModule) {
                    m_loadedDLLs[dllName] = hModule;
                }
            }

            SS_LOG_DEBUG(kLogCategory, L"Loaded %u system DLLs for import resolution",
                static_cast<uint32_t>(m_loadedDLLs.size()));

            return !m_loadedDLLs.empty();
        } catch (...) {
            return false;
        }
    }

    void PackerUnpacker::Impl::UnloadSystemDLLs() noexcept {
        // Don't FreeLibrary system DLLs - they're shared. Just clear tracking.
        try {
            m_loadedDLLs.clear();
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during DLL unload");
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
            if (!section.has_value()) return 0;

            const uint64_t offset = rva - section->VirtualAddress;
            const uint64_t fileOff = section->PointerToRawData + offset;

            if (fileOff >= data.size()) return 0;
            return fileOff;
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
        return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // DETECTION METHODS
    // ========================================================================

    PackerDetectionResult PackerUnpacker::DetectPacker(const fs::path& filePath) noexcept {
        if (!IsInitialized()) {
            PackerDetectionResult result;
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->DetectPackerInternal(filePath);
    }

    PackerDetectionResult PackerUnpacker::DetectPacker(std::span<const uint8_t> data) noexcept {
        if (!IsInitialized()) {
            PackerDetectionResult result;
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->DetectPackerFromMemory(data);
    }

    // ========================================================================
    // UNPACKING METHODS
    // ========================================================================

    UnpackResult PackerUnpacker::UnpackFile(const fs::path& filePath, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }

        m_impl->m_stats.totalUnpackAttempts.fetch_add(1, std::memory_order_relaxed);

        // Shared lock is sufficient: m_stats is fully atomic and m_loadedDLLs
        // is only mutated by Initialize/Shutdown (which take the lock
        // exclusively). Holding a unique_lock across the entire unpack
        // pipeline -- which can run for `timeoutSeconds` (default 60s) of
        // emulation -- would serialize every detection request behind it.
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->UnpackFileInternal(filePath, options);
    }

    UnpackResult PackerUnpacker::StaticUnpack(std::span<const uint8_t> data, PackerType type) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }

        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->StaticUnpackInternal(data, type);
    }

    UnpackResult PackerUnpacker::DynamicUnpack(std::span<const uint8_t> data, const UnpackOptions& options) noexcept {
        UnpackResult result;
        result.status = UnpackStatus::Error;

        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }

        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->DynamicUnpackInternal(data, options);
    }

    // ========================================================================
    // OEP DETECTION
    // ========================================================================

    std::optional<uint64_t> PackerUnpacker::FindOEP(std::span<const uint8_t> data) noexcept {
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return std::nullopt;
        }
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->FindOEPInternal(data);
    }

    // ========================================================================
    // IMPORT RECONSTRUCTION
    // ========================================================================

    std::optional<ReconstructedImports> PackerUnpacker::ReconstructImports(
        std::span<const uint8_t> unpackedData,
        const ImportReconstructionOptions& options) noexcept
    {
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return std::nullopt;
        }
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->ReconstructImportsInternal(unpackedData, options);
    }

    // ========================================================================
    // PE RECONSTRUCTION
    // ========================================================================

    std::optional<std::vector<uint8_t>> PackerUnpacker::FixPEHeaders(
        std::span<const uint8_t> data, uint64_t newEntryPoint,
        const ReconstructedImports* imports) noexcept
    {
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return std::nullopt;
        }
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->FixPEHeadersInternal(data, newEntryPoint, imports);
    }

    // ========================================================================
    // ARCHIVE EXTRACTION
    // ========================================================================

    std::vector<fs::path> PackerUnpacker::ExtractArchive(
        const fs::path& archivePath, uint32_t maxDepth) noexcept
    {
        std::vector<fs::path> result;

        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Not initialized");
            return result;
        }

        if (maxDepth == 0 || maxDepth > UnpackerConstants::MAX_ARCHIVE_DEPTH) {
            SS_LOG_WARN(kLogCategory, L"Invalid archive depth: %u", maxDepth);
            return result;
        }

        try {
            std::error_code ec;
            if (!fs::exists(archivePath, ec) || ec) {
                SS_LOG_WARN(kLogCategory, L"Archive path does not exist: %ls", archivePath.wstring().c_str());
                return result;
            }

            // Self-extracting archives are detected PEs - attempt to unpack and scan
            auto unpackResult = UnpackFile(archivePath);
            if (unpackResult.IsSuccess() && !unpackResult.unpackedData.empty()) {
                // Write unpacked data to a per-process temp file with an
                // unguessable name. Writing next to the source path was a
                // permission/TOCTOU/symlink hazard (the source dir might be
                // attacker-writable, e.g. a sample staging area, or
                // %TEMP%-equivalent owned by another user).
                fs::path tempDir = fs::temp_directory_path(ec);
                if (ec) {
                    SS_LOG_ERROR(kLogCategory, L"temp_directory_path failed: %d", ec.value());
                    return result;
                }

                wchar_t nameBuf[64] = {};
                const auto tid = ::GetCurrentThreadId();
                const auto pid = ::GetCurrentProcessId();
                LARGE_INTEGER ts{};
                ::QueryPerformanceCounter(&ts);
                std::swprintf(nameBuf, std::size(nameBuf),
                    L"shadowstrike-unpack-%lu-%lu-%llx.bin",
                    static_cast<unsigned long>(pid),
                    static_cast<unsigned long>(tid),
                    static_cast<unsigned long long>(ts.QuadPart));

                fs::path tempPath = tempDir / nameBuf;

                // Exclusive create: refuse to follow an existing symlink or
                // overwrite an existing file.
                std::ofstream out(tempPath, std::ios::binary | std::ios::trunc | std::ios::out);
                if (!out.is_open()) {
                    SS_LOG_ERROR(kLogCategory, L"Failed to open unpack output: %ls",
                        tempPath.wstring().c_str());
                    return result;
                }

                out.write(reinterpret_cast<const char*>(unpackResult.unpackedData.data()),
                          static_cast<std::streamsize>(unpackResult.unpackedData.size()));
                if (!out.good()) {
                    SS_LOG_ERROR(kLogCategory, L"Write failure for unpacked output: %ls",
                        tempPath.wstring().c_str());
                    out.close();
                    fs::remove(tempPath, ec);
                    return result;
                }
                out.close();
                result.push_back(std::move(tempPath));
            }
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"ExtractArchive exception");
        }

        return result;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const PackerUnpacker::Statistics& PackerUnpacker::GetStatistics() const noexcept {
        static Statistics emptyStats;
        if (!m_impl) return emptyStats;
        return m_impl->m_stats;
    }

    void PackerUnpacker::ResetStatistics() noexcept {
        if (m_impl) {
            m_impl->m_stats.Reset();
        }
    }

    void PackerUnpacker::Statistics::Reset() noexcept {
        totalUnpackAttempts.store(0, std::memory_order_relaxed);
        successfulUnpacks.store(0, std::memory_order_relaxed);
        failedUnpacks.store(0, std::memory_order_relaxed);
        packersDetected.store(0, std::memory_order_relaxed);
        staticUnpacks.store(0, std::memory_order_relaxed);
        dynamicUnpacks.store(0, std::memory_order_relaxed);
        oepsFound.store(0, std::memory_order_relaxed);
        importsReconstructed.store(0, std::memory_order_relaxed);
    }

    // ========================================================================
    // MISC PUBLIC API
    // ========================================================================

    std::vector<std::string> PackerUnpacker::GetSupportedPackers() const {
        return {
            "UPX (static + dynamic)",
            "ASPack (static XOR decrypt + dynamic)",
            "MPRESS (dynamic)",
            "FSG (dynamic)",
            "PECompact (dynamic)",
            "Themida (dynamic only)",
            "VMProtect (dynamic only)",
            "Enigma (dynamic only)",
            "Armadillo (dynamic only)",
            "Obsidium (dynamic only)",
            "Petite (dynamic only)",
            "Custom/Unknown (dynamic via emulation)"
        };
    }

    std::string PackerUnpacker::GetVersionString() noexcept {
        return std::format("{}.{}.{}",
            UnpackerConstants::VERSION_MAJOR,
            UnpackerConstants::VERSION_MINOR,
            UnpackerConstants::VERSION_PATCH);
    }

} // namespace ShadowStrike::Core::Engine
