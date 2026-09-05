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
 * @file PolymorphicDetector.cpp
 * @brief Enterprise-grade polymorphic/metamorphic malware detection engine
 *
 * ShadowStrike Core Engine - Polymorphic Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive polymorphic/metamorphic malware detection:
 * - Code normalization (register renaming, junk removal, instruction substitution)
 * - Dead code elimination and control flow deobfuscation
 * - Polymorphic engine detection (Mistfall, MtE, DAME, VCL, TPE, EPC, SMEG, etc.)
 * - Decryption loop detection with XOR/ADD/SUB key extraction
 * - Fuzzy matching using CTPH and TLSH algorithms
 * - Mutation pattern classification (register swap, instruction substitution, etc.)
 * - Metamorphic code analysis with semantic equivalence detection
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils/)
 */

#include "pch.h"
#include "PolymorphicDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../FuzzyHasher/FuzzyHasher.hpp"
#include "../../PEParser/PEParser.hpp"

// ============================================================================
// EXTERNAL LIBRARY INCLUDES
// ============================================================================

#include <tlsh/tlsh.h>

// TLSH headers define VERSION_MAJOR/MINOR/PATCH macros that collide
// with our PolyConstants namespace members. Undefine them.
#ifdef VERSION_MAJOR
#  undef VERSION_MAJOR
#endif
#ifdef VERSION_MINOR
#  undef VERSION_MINOR
#endif
#ifdef VERSION_PATCH
#  undef VERSION_PATCH
#endif

namespace ShadowStrike::Core::Engine {

    namespace fs = std::filesystem;

    // ========================================================================
    // ANONYMOUS NAMESPACE - INTERNAL HELPERS
    // ========================================================================

    namespace {

        constexpr const wchar_t* kLogCategory = L"PolyDetector";

        /// Maximum number of decryption loops to report per sample
        constexpr size_t kMaxDecryptionLoops = 64;

        /// Maximum normalization cache entries before eviction
        constexpr size_t kMaxCacheEntries = 4096;

        /// Maximum per-entry payload size eligible for the normalization
        /// cache. Inputs larger than this are still normalized but their
        /// output is not retained, to bound worst-case cache memory usage.
        /// Worst-case cache memory: kMaxCacheEntries * kMaxCacheEntryBytes
        /// = 4096 * 1 MiB = 4 GiB upper bound (typical usage <50 MiB).
        constexpr size_t kMaxCacheEntryBytes = 1ULL * 1024ULL * 1024ULL;

        /// Maximum concurrent in-flight async analyses. Hardens against
        /// thread-exhaustion DoS via repeated AnalyzeAsync invocations.
        constexpr uint32_t kMaxAsyncInFlight = 32;

        /// Heuristic engine score threshold for Custom classification
        constexpr int kHeuristicScoreThreshold = 50;

        [[nodiscard]] const wchar_t* PolyEngineTypeToWStr(PolyEngineType type) noexcept {
            switch (type) {
            case PolyEngineType::Unknown:       return L"Unknown";
            case PolyEngineType::Mistfall:      return L"Mistfall";
            case PolyEngineType::EPC:           return L"EPC";
            case PolyEngineType::SMEG:          return L"SMEG";
            case PolyEngineType::Dark_Avenger:  return L"Dark Avenger MtE";
            case PolyEngineType::One_Half:      return L"One Half";
            case PolyEngineType::IDEA:          return L"IDEA";
            case PolyEngineType::TPE:           return L"TPE";
            case PolyEngineType::MtE:           return L"MtE";
            case PolyEngineType::NED:           return L"NED";
            case PolyEngineType::DAME:          return L"DAME";
            case PolyEngineType::VCL:           return L"VCL";
            case PolyEngineType::Phalcon_Skism: return L"Phalcon/Skism";
            case PolyEngineType::Custom:        return L"Custom";
            default:                            return L"Unknown";
            }
        }

        /// Check if an x86/x64 opcode byte typically has a ModRM byte following it
        [[nodiscard]] bool OpcodeHasModRM(uint8_t opcode) noexcept {
            // Common opcodes that use ModRM: 00-03, 08-0B, 10-13, 18-1B,
            // 20-23, 28-2B, 30-33, 38-3B, 80-8F, C0-C1, D0-D3, F6-F7,
            // 69, 6B, 88-8B, C4-C5, C6-C7
            if ((opcode & 0xFC) <= 0x3C && (opcode & 0x04) == 0) return true;
            if (opcode >= 0x80 && opcode <= 0x8F) return true;
            if (opcode >= 0x88 && opcode <= 0x8B) return true;
            if (opcode == 0xC0 || opcode == 0xC1) return true;
            if (opcode >= 0xD0 && opcode <= 0xD3) return true;
            if (opcode == 0xF6 || opcode == 0xF7) return true;
            if (opcode == 0x69 || opcode == 0x6B) return true;
            if (opcode == 0xC6 || opcode == 0xC7) return true;
            return false;
        }

        /// Check if current time exceeds deadline
        [[nodiscard]] bool IsTimedOut(
            const std::chrono::steady_clock::time_point& deadline) noexcept {
            return std::chrono::steady_clock::now() >= deadline;
        }

    } // anonymous namespace

    // ========================================================================
    // POLYMORPHIC ENGINE SIGNATURES
    // ========================================================================

    namespace PolySignatures {
        constexpr std::array<uint8_t, 6> MISTFALL_SIG = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 4> MTE_SIG      = { 0xE8, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 5> DAME_SIG     = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 3> VCL_SIG      = { 0xEB, 0x06, 0x00 };
        constexpr std::array<uint8_t, 4> TPE_SIG      = { 0x60, 0xBE, 0x00, 0x00 };
        constexpr std::array<uint8_t, 5> EPC_SIG      = { 0x87, 0x25, 0x00, 0x00, 0x00 };
        constexpr std::array<uint8_t, 6> SMEG_SIG     = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83 };
        // NED: PUSH reg; MOV reg, imm32; XOR [reg], key pattern
        constexpr std::array<uint8_t, 3> NED_SIG      = { 0x56, 0xBE, 0x00 };
        // Phalcon/Skism G2 marker
        constexpr std::array<uint8_t, 4> PS_SIG       = { 0x9C, 0x60, 0xE8, 0x00 };
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class PolymorphicDetectorImpl {
    public:
        // ====================================================================
        // STATE
        // ====================================================================

        mutable std::shared_mutex m_mutex;
        mutable std::mutex             m_initMutex;        ///< Serializes Initialize/Shutdown
        std::atomic<bool>              m_initialized{false};
        std::atomic<PolyDetectorStatus> m_status{PolyDetectorStatus::Uninitialized};
        PolymorphicConfiguration       m_config;
        PolyStatistics                 m_stats;

        /// Tracks the number of in-flight async analyses to bound concurrency
        /// and to allow Shutdown() to wait for outstanding work to drain.
        std::atomic<uint32_t>          m_asyncInFlight{0};

        // Engine signature patterns
        struct EnginePattern {
            std::vector<uint8_t> signature;
            PolyEngineType       type;
            std::string          description;
            double               confidence;
        };
        std::vector<EnginePattern> m_enginePatterns;

        // Known junk instruction patterns (byte sequences)
        std::vector<std::vector<uint8_t>> m_junkPatterns;

        // Callbacks
        mutable std::shared_mutex m_callbackMutex;
        FuzzyMatchCallback m_fuzzyMatchCallback;
        ErrorCallback      m_errorCallback;

        // Normalization cache
        struct NormCacheEntry {
            std::vector<uint8_t>              normalizedCode;
            std::chrono::steady_clock::time_point timestamp;
        };
        mutable std::shared_mutex m_cacheMutex;
        std::unordered_map<std::string, NormCacheEntry> m_normCache;

        // ====================================================================
        // CONSTRUCTION
        // ====================================================================

        PolymorphicDetectorImpl() = default;
        ~PolymorphicDetectorImpl() = default;

        // ====================================================================
        // INITIALIZATION
        // ====================================================================

        [[nodiscard]] bool Initialize(const PolymorphicConfiguration& config) noexcept;
        void Shutdown() noexcept;
        void InitializeEnginePatterns() noexcept;
        void InitializeJunkPatterns() noexcept;

        // ====================================================================
        // CORE ANALYSIS
        // ====================================================================

        [[nodiscard]] PolyResult AnalyzeInternal(
            std::span<const uint8_t> code,
            const PolyAnalysisOptions& options,
            PolyBufferKind kind = PolyBufferKind::MachineCode) noexcept;

        // ====================================================================
        // NORMALIZATION
        // ====================================================================

        [[nodiscard]] NormalizationResult NormalizeCodeInternal(
            std::span<const uint8_t> code, NormalizationLevel level) noexcept;
        [[nodiscard]] std::vector<uint8_t> RemoveJunkCodeInternal(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] std::vector<uint8_t> NormalizeRegistersInternal(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] std::vector<uint8_t> SubstituteInstructions(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] std::vector<uint8_t> EliminateDeadCode(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] std::vector<uint8_t> SimplifyControlFlow(
            std::span<const uint8_t> code) noexcept;

        // ====================================================================
        // ENGINE DETECTION
        // ====================================================================

        [[nodiscard]] PolyEngineType DetectEngineInternal(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] PolyEngineType IdentifyBySignature(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] PolyEngineType IdentifyByHeuristics(
            std::span<const uint8_t> code) noexcept;

        // ====================================================================
        // MUTATION DETECTION
        // ====================================================================

        [[nodiscard]] std::set<MutationType> DetectMutationsInternal(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectRegisterSwap(std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectInstructionSubstitution(std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectJunkInsertion(std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectCodeReordering(std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectLoopUnrolling(std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectEncryption(std::span<const uint8_t> code) noexcept;

        // ====================================================================
        // DECRYPTION LOOP DETECTION
        // ====================================================================

        [[nodiscard]] std::vector<DecryptionLoopInfo> FindDecryptionLoopsInternal(
            std::span<const uint8_t> code) noexcept;
        [[nodiscard]] bool DetectXORLoop(
            std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept;
        [[nodiscard]] bool DetectADDLoop(
            std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept;
        [[nodiscard]] bool DetectSUBLoop(
            std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept;
        [[nodiscard]] bool DetectLoopTerminator(
            std::span<const uint8_t> code, size_t startOffset, size_t maxScan) noexcept;
        [[nodiscard]] std::optional<std::vector<uint8_t>> ExtractKeyFromLoop(
            std::span<const uint8_t> code, size_t loopStart, size_t loopEnd) noexcept;

        // ====================================================================
        // FUZZY MATCHING
        // ====================================================================

        [[nodiscard]] std::vector<FuzzyHashMatch> FuzzyMatchInternal(
            std::span<const uint8_t> normalizedCode, uint32_t threshold) noexcept;
        [[nodiscard]] std::string CalculateFuzzyHashInternal(
            std::span<const uint8_t> data) noexcept;
        [[nodiscard]] std::string CalculateTLSHInternal(
            std::span<const uint8_t> data) noexcept;
        [[nodiscard]] uint32_t CompareFuzzyHashInternal(
            const std::string& h1, const std::string& h2) noexcept;
        [[nodiscard]] uint32_t CompareTLSHInternal(
            const std::string& h1, const std::string& h2) noexcept;

        // ====================================================================
        // SCORING
        // ====================================================================

        [[nodiscard]] PolymorphicDetectionConfidence CalculateConfidence(
            const PolyResult& result) noexcept;

        // ====================================================================
        // UTILITY
        // ====================================================================

        [[nodiscard]] bool IsJunkInstruction(
            std::span<const uint8_t> code, size_t offset) noexcept;
        [[nodiscard]] bool IsDeadCode(
            std::span<const uint8_t> code, size_t offset, size_t prevInstrLen) noexcept;
        [[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept;
        void EvictStaleCacheEntries() noexcept;
        void NotifyError(const std::string& msg, int code) noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool PolymorphicDetectorImpl::Initialize(const PolymorphicConfiguration& config) noexcept {
        try {
            // Serialize Initialize against concurrent Initialize/Shutdown so
            // no caller observes a half-constructed detector.
            std::lock_guard<std::mutex> initGuard(m_initMutex);

            if (m_initialized.load(std::memory_order_acquire)) {
                return true;
            }

            m_status.store(PolyDetectorStatus::Initializing, std::memory_order_release);
            SS_LOG_INFO(kLogCategory, L"Initializing polymorphic detector v%u.%u.%u",
                PolyConstants::VERSION_MAJOR, PolyConstants::VERSION_MINOR, PolyConstants::VERSION_PATCH);

            {
                std::unique_lock lock(m_mutex);
                m_config = config;
                // m_stats.startTime is non-atomic — must be written under
                // a lock that excludes any other writer/reader.
                m_stats.startTime = Clock::now();
            }

            InitializeEnginePatterns();
            InitializeJunkPatterns();

            SS_LOG_INFO(kLogCategory, L"Loaded %zu engine patterns, %zu junk patterns",
                m_enginePatterns.size(), m_junkPatterns.size());

            m_status.store(PolyDetectorStatus::Running, std::memory_order_release);
            // Publish the "initialized" flag last so any concurrent observer
            // that sees true is guaranteed to see fully-populated state.
            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(kLogCategory, L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Initialization failed: %hs", e.what());
            m_initialized.store(false, std::memory_order_release);
            m_status.store(PolyDetectorStatus::Error, std::memory_order_release);
            NotifyError(std::string("Init failed: ") + e.what(), ERROR_INTERNAL_ERROR);
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Initialization failed: unknown exception");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(PolyDetectorStatus::Error, std::memory_order_release);
            NotifyError("Init failed: unknown exception", ERROR_INTERNAL_ERROR);
            return false;
        }
    }

    void PolymorphicDetectorImpl::Shutdown() noexcept {
        try {
            std::lock_guard<std::mutex> initGuard(m_initMutex);

            if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
                return;
            }

            m_status.store(PolyDetectorStatus::Stopping, std::memory_order_release);
            SS_LOG_INFO(kLogCategory, L"Shutting down...");

            // Drain in-flight async analyses before tearing down state to
            // eliminate any use-after-free window for detached worker
            // threads. Bounded wait (kMaxAsyncInFlight is small).
            constexpr auto kDrainTimeout  = std::chrono::seconds(10);
            constexpr auto kDrainPollStep = std::chrono::milliseconds(5);
            const auto drainDeadline = Clock::now() + kDrainTimeout;
            while (m_asyncInFlight.load(std::memory_order_acquire) > 0) {
                if (Clock::now() >= drainDeadline) {
                    SS_LOG_WARN(kLogCategory,
                        L"Async drain timeout, %u worker(s) still in flight",
                        m_asyncInFlight.load(std::memory_order_relaxed));
                    break;
                }
                std::this_thread::sleep_for(kDrainPollStep);
            }

            {
                std::unique_lock lock(m_mutex);
                m_enginePatterns.clear();
                m_enginePatterns.shrink_to_fit();
                m_junkPatterns.clear();
                m_junkPatterns.shrink_to_fit();
            }

            {
                std::unique_lock cacheLock(m_cacheMutex);
                m_normCache.clear();
            }

            {
                std::unique_lock cbLock(m_callbackMutex);
                m_fuzzyMatchCallback = nullptr;
                m_errorCallback = nullptr;
            }

            m_status.store(PolyDetectorStatus::Stopped, std::memory_order_release);
            SS_LOG_INFO(kLogCategory, L"Shutdown complete");

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during shutdown");
            m_status.store(PolyDetectorStatus::Error, std::memory_order_release);
        }
    }

    void PolymorphicDetectorImpl::InitializeEnginePatterns() noexcept {
        try {
            std::unique_lock lock(m_mutex);
            m_enginePatterns.clear();
            m_enginePatterns.reserve(16);

            auto addPattern = [this](auto& sig, PolyEngineType t, const char* desc, double conf) {
                EnginePattern ep;
                ep.signature.assign(sig.begin(), sig.end());
                ep.type = t;
                ep.description = desc;
                ep.confidence = conf;
                m_enginePatterns.push_back(std::move(ep));
            };

            addPattern(PolySignatures::MISTFALL_SIG, PolyEngineType::Mistfall,
                "Mistfall polymorphic engine", 0.95);
            addPattern(PolySignatures::MTE_SIG, PolyEngineType::MtE,
                "Mutation Engine (MtE)", 0.90);
            addPattern(PolySignatures::DAME_SIG, PolyEngineType::DAME,
                "Dark Angel's Multiple Encryptor", 0.90);
            addPattern(PolySignatures::VCL_SIG, PolyEngineType::VCL,
                "Virus Creation Laboratory", 0.85);
            addPattern(PolySignatures::TPE_SIG, PolyEngineType::TPE,
                "Trident Polymorphic Engine", 0.90);
            addPattern(PolySignatures::EPC_SIG, PolyEngineType::EPC,
                "Encrypted PE Compressor", 0.85);
            addPattern(PolySignatures::SMEG_SIG, PolyEngineType::SMEG,
                "Simulated Metamorphic Encryption Generator", 0.92);
            addPattern(PolySignatures::NED_SIG, PolyEngineType::NED,
                "NuKE Encryption Device", 0.88);
            addPattern(PolySignatures::PS_SIG, PolyEngineType::Phalcon_Skism,
                "Phalcon/Skism G2", 0.87);

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Failed to initialize engine patterns");
        }
    }

    void PolymorphicDetectorImpl::InitializeJunkPatterns() noexcept {
        try {
            std::unique_lock lock(m_mutex);
            m_junkPatterns.clear();
            m_junkPatterns.reserve(16);

            m_junkPatterns.push_back({0x90});                    // NOP
            m_junkPatterns.push_back({0x87, 0xC0});              // XCHG EAX, EAX
            m_junkPatterns.push_back({0x8B, 0xC0});              // MOV EAX, EAX
            m_junkPatterns.push_back({0x8B, 0xC9});              // MOV ECX, ECX
            m_junkPatterns.push_back({0x8B, 0xD2});              // MOV EDX, EDX
            m_junkPatterns.push_back({0x8B, 0xDB});              // MOV EBX, EBX
            m_junkPatterns.push_back({0x8B, 0xED});              // MOV EBP, EBP
            m_junkPatterns.push_back({0x8B, 0xF6});              // MOV ESI, ESI
            m_junkPatterns.push_back({0x8B, 0xFF});              // MOV EDI, EDI
            m_junkPatterns.push_back({0xEB, 0x00});              // JMP $+0
            m_junkPatterns.push_back({0x0F, 0x1F, 0x00});        // NOP dword [rax] (multi-byte NOP)
            m_junkPatterns.push_back({0x0F, 0x1F, 0x40, 0x00});  // NOP dword [rax+0]
            m_junkPatterns.push_back({0x66, 0x90});              // 2-byte NOP (XCHG AX, AX)
            m_junkPatterns.push_back({0x87, 0xC9});              // XCHG ECX, ECX
            m_junkPatterns.push_back({0x87, 0xD2});              // XCHG EDX, EDX

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Failed to initialize junk patterns");
        }
    }

    // ========================================================================
    // IMPL: CORE ANALYSIS
    // ========================================================================

    PolyResult PolymorphicDetectorImpl::AnalyzeInternal(
        std::span<const uint8_t> code,
        const PolyAnalysisOptions& options,
        PolyBufferKind kind) noexcept {

        PolyResult result;

        try {
            if (code.empty() || code.size() < PolyConstants::MIN_CODE_SIZE) {
                return result;
            }

            if (code.size() > PolyConstants::MAX_CODE_SIZE) {
                SS_LOG_WARN(kLogCategory,
                    L"Code size %zu exceeds max %zu, truncating analysis window",
                    code.size(), PolyConstants::MAX_CODE_SIZE);
                code = code.subspan(0, PolyConstants::MAX_CODE_SIZE);
            }

            m_status.store(PolyDetectorStatus::Analyzing, std::memory_order_release);
            const auto startTime = Clock::now();
            const auto deadline  = startTime +
                std::chrono::milliseconds(options.maxAnalysisTimeMs);

            // ================================================================
            // OPAQUE DATA: PRODUCE THE SIMILARITY HALF, MAKE NO CODE JUDGEMENT
            // ================================================================
            //
            // Steps 1, 2 and 4 below all ask x86 questions - which engine stub
            // is this, which junk instructions were inserted, where are the
            // decryptor loops. On a buffer that is not machine code every one of
            // them is a category error, and because x86 decodes almost any byte
            // sequence they answer with noise rather than with silence. That is
            // what produced Polymorphic.Generic on Prefetch, task XML, a text log
            // and a SQLite database in 1.0.109 while no executable was flagged.
            //
            // The similarity hashes are NOT skipped. TLSH and the fuzzy digest
            // are content hashes with no notion of instructions, so they remain
            // meaningful for any file, and ScanEngine publishes result.fuzzyHash
            // to downstream consumers for every scanned file. Dropping them here
            // would trade one defect for a capability loss.
            //
            // Normalisation IS skipped, deliberately: NormalizeCodeInternal
            // rewrites instruction sequences, so normalising a document before
            // hashing it produces a digest of a transformation that means
            // nothing. The hash is therefore taken over the raw bytes, which is
            // the correct input for content similarity on a non-code file.
            //
            // The fuzzy SUSPICION screen is also skipped. FuzzyMatchInternal
            // does not consult a family database - it asks
            // FuzzyHasher::IsSuspiciousDigest about the digest and, on a hit,
            // synthesises a match named Suspicious.FuzzyHash.Poly with family
            // "Polymorphic". Step 5 then sets isPolymorphic from a non-empty
            // match list and copies that family into threatFamily. That is the
            // second FP mechanism and the field output distinguishes the two: the
            // Prefetch, log and database detections were reported
            // Polymorphic.Generic, with threatFamily empty, while the two
            // scheduled-task XML files were reported as plain Polymorphic -
            // exactly the name this path produces. Both arms are code judgements
            // about a digest of code, so both are skipped here.
            //
            // The digest itself is still computed and returned above; only the
            // suspicion verdict drawn from it is withheld.
            if (kind == PolyBufferKind::OpaqueData) {
                if (options.enableFuzzyMatching) {
                    result.fuzzyHash = CalculateFuzzyHashInternal(code);
                    result.tlshHash  = CalculateTLSHInternal(code);
                }

                result.codeAnalysisPerformed = false;

                const auto opaqueEnd = Clock::now();
                result.analysisTimeMs = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        opaqueEnd - startTime).count());

                m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
                m_status.store(PolyDetectorStatus::Running, std::memory_order_release);
                return result;
            }

            result.codeAnalysisPerformed = true;

            // Step 1: Detect polymorphic engine
            result.engineType = DetectEngineInternal(code);
            if (result.engineType != PolyEngineType::Unknown) {
                result.isPolymorphic = true;
                result.engineName = std::string(GetPolyEngineTypeName(result.engineType));
                const auto idx = static_cast<size_t>(result.engineType);
                if (idx < m_stats.byEngineType.size()) {
                    m_stats.byEngineType[idx].fetch_add(1, std::memory_order_relaxed);
                }
            }

            if (IsTimedOut(deadline)) goto finish;

            // Step 2: Detect mutations
            {
                auto mutations = DetectMutationsInternal(code);
                if (!mutations.empty()) {
                    result.mutations = std::move(mutations);
                    result.isPolymorphic = true;
                }
            }

            if (IsTimedOut(deadline)) goto finish;

            // Step 3: Normalize code
            if (options.normalizationLevel != NormalizationLevel::None) {
                auto normResult = NormalizeCodeInternal(code, options.normalizationLevel);
                result.normalizedBody = std::move(normResult.normalizedCode);
                result.normalizationInfo = std::move(normResult);
                m_stats.normalizationOperations.fetch_add(1, std::memory_order_relaxed);
            }

            if (IsTimedOut(deadline)) goto finish;

            // Step 4: Find decryption loops
            if (options.detectDecryptionLoops) {
                result.decryptionLoops = FindDecryptionLoopsInternal(code);
                if (!result.decryptionLoops.empty()) {
                    result.isPolymorphic = true;
                    m_stats.decryptionLoopsFound.fetch_add(
                        result.decryptionLoops.size(), std::memory_order_relaxed);
                }
            }

            if (IsTimedOut(deadline)) goto finish;

            // Step 5: Fuzzy matching
            if (options.enableFuzzyMatching) {
                std::span<const uint8_t> hashInput = result.normalizedBody.empty()
                    ? code
                    : std::span<const uint8_t>(result.normalizedBody);

                result.fuzzyHash = CalculateFuzzyHashInternal(hashInput);
                result.tlshHash  = CalculateTLSHInternal(hashInput);

                auto matches = FuzzyMatchInternal(hashInput, options.fuzzyThreshold);
                if (!matches.empty()) {
                    result.fuzzyMatches = std::move(matches);
                    result.isPolymorphic = true;
                    if (!result.fuzzyMatches.empty()) {
                        result.threatFamily = result.fuzzyMatches.front().familyName;
                    }
                }
            }

            // Step 6: Determine metamorphic classification
            if (!result.mutations.empty()) {
                const bool hasComplexMutations =
                    result.mutations.contains(MutationType::CodeReorder) ||
                    result.mutations.contains(MutationType::LoopUnroll) ||
                    result.mutations.contains(MutationType::Compression);

                if (hasComplexMutations && result.mutations.size() >= 2) {
                    result.isMetamorphic = true;
                }
            }

            // Step 7: Calculate confidence
            result.confidence = CalculateConfidence(result);

        finish:
            const auto endTime = Clock::now();
            result.analysisTimeMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    endTime - startTime).count());

            m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
            if (result.isPolymorphic) {
                m_stats.polymorphicDetected.fetch_add(1, std::memory_order_relaxed);
            }
            if (result.isMetamorphic) {
                m_stats.metamorphicDetected.fetch_add(1, std::memory_order_relaxed);
            }

            m_status.store(PolyDetectorStatus::Running, std::memory_order_release);

            SS_LOG_INFO(kLogCategory,
                L"Analysis completed in %u ms (poly=%d, meta=%d, engine=%ls)",
                result.analysisTimeMs,
                static_cast<int>(result.isPolymorphic),
                static_cast<int>(result.isMetamorphic),
                PolyEngineTypeToWStr(result.engineType));

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory, L"Analysis failed: %hs", e.what());
            m_status.store(PolyDetectorStatus::Running, std::memory_order_release);
            return result;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Analysis failed: unknown exception");
            m_status.store(PolyDetectorStatus::Running, std::memory_order_release);
            return result;
        }
    }

    // ========================================================================
    // IMPL: CODE NORMALIZATION
    // ========================================================================

    NormalizationResult PolymorphicDetectorImpl::NormalizeCodeInternal(
        std::span<const uint8_t> code, NormalizationLevel level) noexcept {

        NormalizationResult result;
        result.originalSize = code.size();

        try {
            if (code.empty()) return result;

            const auto startTime = Clock::now();

            // Build cache key: SHA-256 hex of input + level. SHA-256 is
            // collision-resistant and the only hash here we trust as a key.
            // If hashing fails (BCrypt unavailable etc.) we skip caching.
            std::string cacheKey;
            bool cacheable = (code.size() <= kMaxCacheEntryBytes);
            if (cacheable) {
                if (!Utils::HashUtils::ComputeHex(
                        Utils::HashUtils::Algorithm::SHA256,
                        code.data(), code.size(), cacheKey)) {
                    cacheable = false;
                    cacheKey.clear();
                } else {
                    cacheKey += '_';
                    cacheKey += std::to_string(static_cast<int>(level));
                }
            }

            // Check cache (read lock)
            if (cacheable) {
                std::shared_lock cacheLock(m_cacheMutex);
                auto it = m_normCache.find(cacheKey);
                if (it != m_normCache.end()) {
                    result.normalizedCode = it->second.normalizedCode;
                    result.normalizedSize = result.normalizedCode.size();
                    if (result.originalSize > 0) {
                        result.reductionRatio = 1.0f -
                            static_cast<float>(result.normalizedSize) /
                            static_cast<float>(result.originalSize);
                    }
                    result.processingTimeMs = 0;
                    SS_LOG_DEBUG(kLogCategory, L"Normalization cache hit");
                    return result;
                }
            }

            std::vector<uint8_t> normalized(code.begin(), code.end());
            uint32_t totalRemoved = 0;

            for (uint32_t pass = 0; pass < PolyConstants::MAX_NORMALIZATION_PASSES; ++pass) {
                const size_t prevSize = normalized.size();

                // Level 1: Basic - Remove junk code (NOPs, self-moves, etc.)
                if (level >= NormalizationLevel::Basic) {
                    normalized = RemoveJunkCodeInternal(normalized);
                }

                // Level 2: Standard - Register normalization + instruction substitution
                if (level >= NormalizationLevel::Standard) {
                    normalized = NormalizeRegistersInternal(normalized);
                    normalized = SubstituteInstructions(normalized);
                }

                // Level 3: Aggressive - Dead code elimination
                if (level >= NormalizationLevel::Aggressive) {
                    normalized = EliminateDeadCode(normalized);
                }

                // Level 4: Full - Control flow simplification
                if (level >= NormalizationLevel::Full) {
                    normalized = SimplifyControlFlow(normalized);
                }

                result.passesPerformed = pass + 1;
                totalRemoved += static_cast<uint32_t>(prevSize - normalized.size());

                // Converged if no further reduction
                if (normalized.size() == prevSize) break;
            }

            result.normalizedCode = std::move(normalized);
            result.normalizedSize = result.normalizedCode.size();
            result.instructionsRemoved = totalRemoved;
            if (result.originalSize > 0) {
                result.reductionRatio = 1.0f -
                    static_cast<float>(result.normalizedSize) /
                    static_cast<float>(result.originalSize);
            }

            m_stats.junkCodeRemoved.fetch_add(totalRemoved, std::memory_order_relaxed);

            // Update cache (write lock) — only when input was cacheable.
            if (cacheable) {
                std::unique_lock cacheLock(m_cacheMutex);
                if (m_normCache.size() >= kMaxCacheEntries) {
                    EvictStaleCacheEntries();
                }
                NormCacheEntry entry;
                entry.normalizedCode = result.normalizedCode;
                entry.timestamp = Clock::now();
                m_normCache[std::move(cacheKey)] = std::move(entry);
            }

            const auto endTime = Clock::now();
            result.processingTimeMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    endTime - startTime).count());

            SS_LOG_DEBUG(kLogCategory,
                L"Normalized %zu -> %zu bytes (%.1f%% reduction, %u passes, %u ms)",
                result.originalSize, result.normalizedSize,
                result.reductionRatio * 100.0f,
                result.passesPerformed, result.processingTimeMs);

            return result;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during code normalization");
            return result;
        }
    }

    std::vector<uint8_t> PolymorphicDetectorImpl::RemoveJunkCodeInternal(
        std::span<const uint8_t> code) noexcept {
        try {
            std::vector<uint8_t> cleaned;
            cleaned.reserve(code.size());

            for (size_t i = 0; i < code.size(); ++i) {
                if (IsJunkInstruction(code, i)) {
                    // Determine junk instruction length and skip it
                    // Single byte NOPs
                    if (code[i] == 0x90) continue;

                    // 2-byte patterns
                    if (i + 1 < code.size()) {
                        uint8_t b0 = code[i], b1 = code[i + 1];
                        if ((b0 == 0xEB && b1 == 0x00) ||          // JMP $+0
                            (b0 == 0x87 && (b1 & 0xC7) == 0xC0 && ((b1 >> 3) & 7) == (b1 & 7)) || // XCHG same reg
                            (b0 == 0x8B && (b1 & 0xC7) == 0xC0 && ((b1 >> 3) & 7) == (b1 & 7)) || // MOV same reg
                            (b0 == 0x66 && b1 == 0x90)) {          // 2-byte NOP
                            ++i;
                            continue;
                        }
                    }

                    // 3-byte NOP (0F 1F 00)
                    if (i + 2 < code.size() &&
                        code[i] == 0x0F && code[i + 1] == 0x1F && code[i + 2] == 0x00) {
                        i += 2;
                        continue;
                    }

                    // 4-byte NOP (0F 1F 40 00)
                    if (i + 3 < code.size() &&
                        code[i] == 0x0F && code[i + 1] == 0x1F &&
                        code[i + 2] == 0x40 && code[i + 3] == 0x00) {
                        i += 3;
                        continue;
                    }
                }

                cleaned.push_back(code[i]);
            }

            return cleaned;

        } catch (...) {
            return std::vector<uint8_t>(code.begin(), code.end());
        }
    }

    std::vector<uint8_t> PolymorphicDetectorImpl::NormalizeRegistersInternal(
        std::span<const uint8_t> code) noexcept {
        try {
            std::vector<uint8_t> normalized(code.begin(), code.end());

            for (size_t i = 0; i < normalized.size(); ++i) {
                const uint8_t byte = normalized[i];

                // REX prefix (0x40-0x4F): normalize R/X/B extension bits
                // Keep W bit (64-bit operand size) but zero register extension bits
                if ((byte & 0xF0) == 0x40 && i + 1 < normalized.size()) {
                    normalized[i] = byte & 0x48; // Preserve 0100W000
                    ++i; // Skip to opcode byte

                    if (i >= normalized.size()) break;
                    const uint8_t opcode = normalized[i];

                    // If opcode has ModRM, normalize the register fields
                    if (OpcodeHasModRM(opcode) && i + 1 < normalized.size()) {
                        ++i;
                        uint8_t modrm = normalized[i];
                        uint8_t mod = modrm & 0xC0;

                        // Normalize: zero out reg and rm fields, keep mod
                        // This maps all register variants to the same canonical form
                        normalized[i] = mod;

                        // If mod != 11b (register-direct), there may be SIB/disp bytes
                        // Skip them without modifying
                        if (mod == 0x00) {
                            uint8_t rm = modrm & 0x07;
                            if (rm == 0x04 && i + 1 < normalized.size()) { // SIB follows
                                ++i;
                                normalized[i] = normalized[i] & 0xC0; // Normalize SIB reg fields
                            } else if (rm == 0x05 && i + 4 < normalized.size()) {
                                i += 4; // RIP-relative disp32
                            }
                        } else if (mod == 0x40) {
                            uint8_t rm = modrm & 0x07;
                            if (rm == 0x04 && i + 1 < normalized.size()) ++i; // SIB
                            if (i + 1 < normalized.size()) ++i; // disp8
                        } else if (mod == 0x80) {
                            uint8_t rm = modrm & 0x07;
                            if (rm == 0x04 && i + 1 < normalized.size()) ++i; // SIB
                            if (i + 4 < normalized.size()) i += 4; // disp32
                        }
                    }
                    continue;
                }

                // PUSH r64 (50+rd) / POP r64 (58+rd): normalize register bits
                if ((byte >= 0x50 && byte <= 0x57) || (byte >= 0x58 && byte <= 0x5F)) {
                    normalized[i] = byte & 0xF8; // Zero register bits
                    continue;
                }

                // Non-REX ModRM instructions: normalize if opcode has ModRM
                if (OpcodeHasModRM(byte) && i + 1 < normalized.size()) {
                    ++i;
                    uint8_t modrm = normalized[i];
                    uint8_t mod = modrm & 0xC0;
                    normalized[i] = mod; // Keep mod, zero reg/rm
                }
            }

            return normalized;

        } catch (...) {
            return std::vector<uint8_t>(code.begin(), code.end());
        }
    }

    std::vector<uint8_t> PolymorphicDetectorImpl::SubstituteInstructions(
        std::span<const uint8_t> code) noexcept {
        try {
            std::vector<uint8_t> result;
            result.reserve(code.size());

            for (size_t i = 0; i < code.size(); ++i) {
                // MOV reg, 0 (B8+rd 00 00 00 00) → canonical XOR reg, reg (31 C0+mod)
                if (i + 4 < code.size() &&
                    (code[i] & 0xF8) == 0xB8 &&
                    code[i + 1] == 0 && code[i + 2] == 0 &&
                    code[i + 3] == 0 && code[i + 4] == 0) {
                    result.push_back(0x31);
                    result.push_back(0xC0); // XOR EAX, EAX (canonical)
                    i += 4;
                    continue;
                }

                // SUB reg, imm8 (83 /5 xx) → canonical ADD reg, -imm8.
                // Safe negation via two's-complement on unsigned domain to
                // avoid UB when imm == INT8_MIN (signed overflow on `-imm`).
                if (i + 2 < code.size() &&
                    code[i] == 0x83 && (code[i + 1] & 0x38) == 0x28) {
                    const uint8_t imm = code[i + 2];
                    const uint8_t neg = static_cast<uint8_t>(
                        (0u - static_cast<unsigned>(imm)) & 0xFFu);
                    result.push_back(0x83);
                    result.push_back(static_cast<uint8_t>(
                        (code[i + 1] & 0xC7) | 0x00)); // ADD /0
                    result.push_back(neg);
                    i += 2;
                    continue;
                }

                // LEA reg, [reg+imm] → canonical ADD reg, imm
                // Pattern: 8D 40+mod disp (LEA EAX, [EAX+disp8])
                if (i + 2 < code.size() && code[i] == 0x8D) {
                    uint8_t modrm = code[i + 1];
                    uint8_t mod = (modrm >> 6) & 3;
                    uint8_t reg = (modrm >> 3) & 7;
                    uint8_t rm  = modrm & 7;

                    // LEA reg, [reg+disp8] where reg == rm → ADD reg, disp8
                    if (mod == 1 && reg == rm && rm != 4 && i + 2 < code.size()) {
                        result.push_back(0x83);
                        result.push_back(0xC0 | reg); // ADD reg, imm8
                        result.push_back(code[i + 2]);
                        i += 2;
                        continue;
                    }
                }

                result.push_back(code[i]);
            }

            return result;

        } catch (...) {
            return std::vector<uint8_t>(code.begin(), code.end());
        }
    }

    std::vector<uint8_t> PolymorphicDetectorImpl::EliminateDeadCode(
        std::span<const uint8_t> code) noexcept {
        try {
            if (code.size() < 2) return std::vector<uint8_t>(code.begin(), code.end());

            std::vector<uint8_t> cleaned;
            cleaned.reserve(code.size());

            bool afterUnconditionalTransfer = false;

            for (size_t i = 0; i < code.size(); ++i) {
                const uint8_t b = code[i];

                // Track unconditional transfers
                if (b == 0xC3 || b == 0xCB) {
                    // RET / RETF
                    cleaned.push_back(b);
                    afterUnconditionalTransfer = true;
                    continue;
                }

                if (b == 0xC2 || b == 0xCA) {
                    // RET imm16 / RETF imm16
                    cleaned.push_back(b);
                    if (i + 2 < code.size()) {
                        cleaned.push_back(code[i + 1]);
                        cleaned.push_back(code[i + 2]);
                        i += 2;
                    }
                    afterUnconditionalTransfer = true;
                    continue;
                }

                if (b == 0xE9 && i + 4 < code.size()) {
                    // JMP near rel32
                    cleaned.push_back(b);
                    for (int j = 1; j <= 4; ++j)
                        cleaned.push_back(code[i + j]);
                    i += 4;
                    afterUnconditionalTransfer = true;
                    continue;
                }

                if (b == 0xEB && i + 1 < code.size()) {
                    // JMP short rel8
                    cleaned.push_back(b);
                    cleaned.push_back(code[i + 1]);
                    i += 1;
                    afterUnconditionalTransfer = true;
                    continue;
                }

                // Any label-like target resets dead code state
                // Heuristic: conditional jumps / calls can be targets
                if ((b & 0xF0) == 0x70 || // Jcc short
                    b == 0xE8 ||           // CALL
                    b == 0xFF ||           // indirect CALL/JMP
                    b == 0xCC) {           // INT3 (breakpoint, potential boundary)
                    afterUnconditionalTransfer = false;
                }

                if (afterUnconditionalTransfer) {
                    // Skip dead byte
                    continue;
                }

                cleaned.push_back(b);
            }

            return cleaned;

        } catch (...) {
            return std::vector<uint8_t>(code.begin(), code.end());
        }
    }

    std::vector<uint8_t> PolymorphicDetectorImpl::SimplifyControlFlow(
        std::span<const uint8_t> code) noexcept {
        try {
            std::vector<uint8_t> simplified(code.begin(), code.end());

            // Pass 1: Remove JMP $+0 (EB 00) - jump to next instruction
            for (size_t i = 0; i + 1 < simplified.size(); ) {
                if (simplified[i] == 0xEB && simplified[i + 1] == 0x00) {
                    simplified.erase(simplified.begin() + static_cast<ptrdiff_t>(i),
                                     simplified.begin() + static_cast<ptrdiff_t>(i + 2));
                    // Don't advance i - recheck this position
                } else {
                    ++i;
                }
            }

            // Pass 2: Collapse short JMP chains (JMP A → JMP B becomes JMP B).
            // All target arithmetic must run in signed (ptrdiff_t) space —
            // a naive `static_cast<size_t>(int8_t)` of a negative rel8 wraps
            // to a huge value and can produce an OOB read on `simplified[target]`.
            for (ptrdiff_t i = 0; i + 1 < static_cast<ptrdiff_t>(simplified.size()); ++i) {
                if (simplified[static_cast<size_t>(i)] != 0xEB) continue;

                const int8_t rel8 = static_cast<int8_t>(
                    simplified[static_cast<size_t>(i + 1)]);
                const ptrdiff_t target = i + 2 + static_cast<ptrdiff_t>(rel8);
                const ptrdiff_t simSize = static_cast<ptrdiff_t>(simplified.size());

                // Reject negative or out-of-range targets BEFORE any indexed read.
                if (target < 0 || target + 1 >= simSize) continue;

                if (simplified[static_cast<size_t>(target)] != 0xEB) continue;

                const int8_t rel8_2 = static_cast<int8_t>(
                    simplified[static_cast<size_t>(target + 1)]);
                const ptrdiff_t newTarget =
                    target + 2 + static_cast<ptrdiff_t>(rel8_2) - (i + 2);

                if (newTarget >= -128 && newTarget <= 127) {
                    simplified[static_cast<size_t>(i + 1)] =
                        static_cast<uint8_t>(static_cast<int8_t>(newTarget));
                }
            }

            return simplified;

        } catch (...) {
            return std::vector<uint8_t>(code.begin(), code.end());
        }
    }

    // ========================================================================
    // IMPL: ENGINE DETECTION
    // ========================================================================

    PolyEngineType PolymorphicDetectorImpl::DetectEngineInternal(
        std::span<const uint8_t> code) noexcept {
        try {
            auto sig = IdentifyBySignature(code);
            if (sig != PolyEngineType::Unknown) return sig;

            auto heur = IdentifyByHeuristics(code);
            if (heur != PolyEngineType::Unknown) return heur;

            return PolyEngineType::Unknown;
        } catch (...) {
            return PolyEngineType::Unknown;
        }
    }

    PolyEngineType PolymorphicDetectorImpl::IdentifyBySignature(
        std::span<const uint8_t> code) noexcept {
        try {
            std::shared_lock lock(m_mutex);

            for (const auto& pattern : m_enginePatterns) {
                if (code.size() < pattern.signature.size()) continue;

                const size_t searchLimit = std::min<size_t>(4096, code.size());

                for (size_t i = 0; i + pattern.signature.size() <= searchLimit; ++i) {
                    bool match = true;
                    for (size_t j = 0; j < pattern.signature.size(); ++j) {
                        // Wildcard: 0x00 in signature matches any byte
                        if (pattern.signature[j] != 0x00 &&
                            code[i + j] != pattern.signature[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        SS_LOG_DEBUG(kLogCategory,
                            L"Engine signature match: %ls at offset %zu",
                            PolyEngineTypeToWStr(pattern.type), i);
                        return pattern.type;
                    }
                }
            }

            return PolyEngineType::Unknown;
        } catch (...) {
            return PolyEngineType::Unknown;
        }
    }

    PolyEngineType PolymorphicDetectorImpl::IdentifyByHeuristics(
        std::span<const uint8_t> code) noexcept {
        try {
            int score = 0;

            const double entropy = CalculateEntropy(code);
            if (entropy >= 7.0) score += 20;

            auto loops = FindDecryptionLoopsInternal(code);
            if (!loops.empty()) score += 30;

            size_t junkCount = 0;
            const size_t sampleSize = std::min<size_t>(512, code.size());
            for (size_t i = 0; i < sampleSize; ++i) {
                if (IsJunkInstruction(code, i)) ++junkCount;
            }
            if (junkCount >= 20) score += 25;

            if (DetectRegisterSwap(code)) score += 15;

            if (score >= kHeuristicScoreThreshold) {
                SS_LOG_DEBUG(kLogCategory,
                    L"Heuristic engine detection: score=%d (Custom)", score);
                return PolyEngineType::Custom;
            }

            return PolyEngineType::Unknown;
        } catch (...) {
            return PolyEngineType::Unknown;
        }
    }

    // ========================================================================
    // IMPL: MUTATION DETECTION
    // ========================================================================

    std::set<MutationType> PolymorphicDetectorImpl::DetectMutationsInternal(
        std::span<const uint8_t> code) noexcept {
        std::set<MutationType> mutations;
        try {
            if (DetectRegisterSwap(code))
                mutations.insert(MutationType::RegisterSwap);

            if (DetectInstructionSubstitution(code))
                mutations.insert(MutationType::InstructionSub);

            if (DetectJunkInsertion(code))
                mutations.insert(MutationType::JunkInsertion);

            if (DetectCodeReordering(code))
                mutations.insert(MutationType::CodeReorder);

            if (DetectLoopUnrolling(code))
                mutations.insert(MutationType::LoopUnroll);

            if (DetectEncryption(code))
                mutations.insert(MutationType::Encryption);

            if (mutations.size() >= 3)
                mutations.insert(MutationType::Combined);

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during mutation detection");
        }
        return mutations;
    }

    bool PolymorphicDetectorImpl::DetectRegisterSwap(
        std::span<const uint8_t> code) noexcept {
        try {
            size_t xchgCount = 0;
            size_t movSwapCount = 0;

            for (size_t i = 0; i + 1 < code.size(); ++i) {
                // XCHG r32, r32 (87 ModRM with mod=11)
                if (code[i] == 0x87 && (code[i + 1] & 0xC0) == 0xC0) {
                    // Exclude XCHG same register (nop)
                    uint8_t reg1 = (code[i + 1] >> 3) & 7;
                    uint8_t reg2 = code[i + 1] & 7;
                    if (reg1 != reg2) ++xchgCount;
                }

                // 3-instruction MOV swap: MOV tmp,A; MOV A,B; MOV B,tmp
                if (i + 5 < code.size() &&
                    code[i] == 0x8B && code[i + 2] == 0x8B && code[i + 4] == 0x8B) {
                    ++movSwapCount;
                }
            }

            return (xchgCount >= 3) || (movSwapCount >= 2);
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectInstructionSubstitution(
        std::span<const uint8_t> code) noexcept {
        try {
            size_t subCount = 0;

            for (size_t i = 0; i + 2 < code.size(); ++i) {
                // XOR reg, reg (instead of MOV reg, 0)
                if (code[i] == 0x31 && (code[i + 1] & 0xC0) == 0xC0)
                    ++subCount;

                // SUB with negative immediate (instead of ADD)
                if (code[i] == 0x83 && (code[i + 1] & 0x38) == 0x28)
                    ++subCount;

                // LEA used for arithmetic (instead of ADD)
                if (code[i] == 0x8D && (code[i + 1] & 0xC0) != 0xC0)
                    ++subCount;

                // NEG + ADD (instead of SUB)
                if (code[i] == 0xF7 && (code[i + 1] & 0x38) == 0x18)
                    ++subCount;
            }

            return (subCount >= 5);
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectJunkInsertion(
        std::span<const uint8_t> code) noexcept {
        try {
            size_t junkCount = 0;
            const size_t sampleSize = std::min<size_t>(512, code.size());

            for (size_t i = 0; i < sampleSize; ++i) {
                if (IsJunkInstruction(code, i)) ++junkCount;
            }

            return (sampleSize > 0) &&
                   (static_cast<double>(junkCount) / static_cast<double>(sampleSize)) >= 0.10;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectCodeReordering(
        std::span<const uint8_t> code) noexcept {
        try {
            size_t jumpCount = 0;

            for (size_t i = 0; i + 1 < code.size(); ++i) {
                if (code[i] == 0xEB) ++jumpCount;
                if (code[i] == 0xE9) ++jumpCount;
                if ((code[i] & 0xF0) == 0x70) ++jumpCount;
                // 2-byte Jcc (0F 80-8F)
                if (code[i] == 0x0F && (code[i + 1] & 0xF0) == 0x80) ++jumpCount;
            }

            return (code.size() > 0) &&
                   (static_cast<double>(jumpCount) / static_cast<double>(code.size())) >= 0.05;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectLoopUnrolling(
        std::span<const uint8_t> code) noexcept {
        try {
            // Detect repeated instruction sequences using rolling hash
            constexpr size_t kSeqLen = 8;
            if (code.size() < kSeqLen * 4) return false;

            const size_t limit = std::min<size_t>(code.size() - kSeqLen, 4096);
            std::unordered_map<uint64_t, uint32_t> hashCounts;
            hashCounts.reserve(limit);

            for (size_t i = 0; i < limit; ++i) {
                uint64_t h = Utils::HashUtils::Fnv1a64(&code[i], kSeqLen);
                if (++hashCounts[h] >= 4) return true;
            }

            return false;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectEncryption(
        std::span<const uint8_t> code) noexcept {
        try {
            const double entropy = CalculateEntropy(code);
            if (entropy < 7.2) return false;

            auto loops = FindDecryptionLoopsInternal(code);
            return !loops.empty();
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: DECRYPTION LOOP DETECTION
    // ========================================================================

    std::vector<DecryptionLoopInfo> PolymorphicDetectorImpl::FindDecryptionLoopsInternal(
        std::span<const uint8_t> code) noexcept {
        std::vector<DecryptionLoopInfo> loops;
        try {
            if (code.size() < 16) return loops;

            for (size_t i = 0; i + 16 < code.size(); ++i) {
                if (loops.size() >= kMaxDecryptionLoops) break;

                DecryptionLoopInfo info;

                if (DetectXORLoop(code, i, info)) {
                    loops.push_back(std::move(info));
                    i += 16;
                    continue;
                }
                if (DetectADDLoop(code, i, info)) {
                    loops.push_back(std::move(info));
                    i += 16;
                    continue;
                }
                if (DetectSUBLoop(code, i, info)) {
                    loops.push_back(std::move(info));
                    i += 16;
                    continue;
                }
            }
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during decryption loop detection");
        }
        return loops;
    }

    bool PolymorphicDetectorImpl::DetectLoopTerminator(
        std::span<const uint8_t> code, size_t startOffset, size_t maxScan) noexcept {
        try {
            const size_t limit = std::min(startOffset + maxScan, code.size());
            for (size_t i = startOffset; i < limit; ++i) {
                if (code[i] == 0xE2) return true;            // LOOP
                if (code[i] == 0x75) return true;            // JNZ
                if (code[i] == 0x74) return true;            // JZ
                if (i + 1 < limit && code[i] == 0xEB &&
                    static_cast<int8_t>(code[i + 1]) < 0) return true; // JMP backward
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectXORLoop(
        std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept {
        try {
            if (offset + 10 >= code.size()) return false;

            bool hasXOR = false;
            size_t xorOffset = offset;

            for (size_t i = offset; i < offset + 8 && i + 2 < code.size(); ++i) {
                // XOR byte ptr [reg+off], imm8 (80 /6)
                if (code[i] == 0x80 && (code[i + 1] & 0x38) == 0x30) {
                    hasXOR = true; xorOffset = i; break;
                }
                // XOR dword ptr [reg+off], imm32 (81 /6)
                if (code[i] == 0x81 && (code[i + 1] & 0x38) == 0x30) {
                    hasXOR = true; xorOffset = i; break;
                }
                // XOR [reg], reg (30 or 31)
                if (code[i] == 0x30 || code[i] == 0x31) {
                    hasXOR = true; xorOffset = i; break;
                }
            }

            if (!hasXOR) return false;
            if (!DetectLoopTerminator(code, xorOffset, 12)) return false;

            out.loopStart = offset;
            out.loopEnd   = xorOffset + 10;
            out.algorithm = "XOR";

            auto key = ExtractKeyFromLoop(code, offset, out.loopEnd);
            if (key.has_value()) {
                out.xorKey = std::move(*key);
            }

            SS_LOG_DEBUG(kLogCategory,
                L"XOR decryption loop at offset %llu", static_cast<unsigned long long>(offset));
            return true;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectADDLoop(
        std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept {
        try {
            if (offset + 10 >= code.size()) return false;

            bool hasADD = false;
            for (size_t i = offset; i < offset + 8 && i + 2 < code.size(); ++i) {
                if (code[i] == 0x80 && (code[i + 1] & 0x38) == 0x00) {
                    hasADD = true; break;
                }
                if (code[i] == 0x00 || code[i] == 0x01) {
                    hasADD = true; break;
                }
            }

            if (!hasADD) return false;
            if (!DetectLoopTerminator(code, offset, 12)) return false;

            out.loopStart = offset;
            out.loopEnd   = offset + 10;
            out.algorithm = "ADD";

            auto key = ExtractKeyFromLoop(code, offset, out.loopEnd);
            if (key.has_value()) out.xorKey = std::move(*key);

            return true;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::DetectSUBLoop(
        std::span<const uint8_t> code, size_t offset, DecryptionLoopInfo& out) noexcept {
        try {
            if (offset + 10 >= code.size()) return false;

            bool hasSUB = false;
            for (size_t i = offset; i < offset + 8 && i + 2 < code.size(); ++i) {
                if (code[i] == 0x80 && (code[i + 1] & 0x38) == 0x28) {
                    hasSUB = true; break;
                }
                if (code[i] == 0x28 || code[i] == 0x29) {
                    hasSUB = true; break;
                }
            }

            if (!hasSUB) return false;
            if (!DetectLoopTerminator(code, offset, 12)) return false;

            out.loopStart = offset;
            out.loopEnd   = offset + 10;
            out.algorithm = "SUB";

            auto key = ExtractKeyFromLoop(code, offset, out.loopEnd);
            if (key.has_value()) out.xorKey = std::move(*key);

            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<std::vector<uint8_t>> PolymorphicDetectorImpl::ExtractKeyFromLoop(
        std::span<const uint8_t> code, size_t loopStart, size_t loopEnd) noexcept {
        try {
            const size_t limit = std::min(loopEnd, code.size());
            std::vector<uint8_t> key;

            for (size_t i = loopStart; i + 2 < limit; ++i) {
                // Immediate byte after 80 xx (XOR/ADD/SUB byte ptr, imm8)
                if (code[i] == 0x80 && i + 2 < limit) {
                    key.push_back(code[i + 2]);
                    return key;
                }
                // Immediate dword after 81 xx (XOR/ADD/SUB dword ptr, imm32)
                if (code[i] == 0x81 && i + 6 < limit) {
                    for (size_t j = 0; j < 4; ++j)
                        key.push_back(code[i + 2 + j]);
                    return key;
                }
            }

            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    // ========================================================================
    // IMPL: FUZZY MATCHING
    // ========================================================================

    std::vector<FuzzyHashMatch> PolymorphicDetectorImpl::FuzzyMatchInternal(
        std::span<const uint8_t> normalizedCode, uint32_t threshold) noexcept {
        std::vector<FuzzyHashMatch> matches;
        try {
            if (normalizedCode.empty()) return matches;

            // Compute CTPH fuzzy hash
            auto fuzzyOpt = ShadowStrike::FuzzyHasher::HashBuffer(normalizedCode);
            if (!fuzzyOpt.has_value() || fuzzyOpt->empty()) {
                SS_LOG_DEBUG(kLogCategory,
                    L"Fuzzy hash computation returned empty for %zu bytes",
                    normalizedCode.size());
                return matches;
            }

            const std::string& computedHash = *fuzzyOpt;

            // Architecture note: The PolymorphicDetector computes fuzzy hashes for
            // normalized code. Database-backed matching against known malware families
            // is orchestrated by the caller (ScanEngine / ThreatDetector) which holds
            // references to HashStore, PatternStore, and ThreatIntelLookup instances.
            //
            // The caller invokes CalculateFuzzyHash() and CompareFuzzyHash() against
            // their own databases. This method uses the FuzzyHasher's internal
            // batch-compare facility against any signatures loaded at startup.
            //
            // When FuzzyHasher has been primed with known hashes via its import API,
            // IsSuspiciousDigest provides a fast pre-screen.
            if (ShadowStrike::FuzzyHasher::IsSuspiciousDigest(computedHash)) {
                FuzzyHashMatch suspiciousMatch;
                suspiciousMatch.score       = threshold;
                suspiciousMatch.matchedHash = computedHash;
                suspiciousMatch.threatName  = "Suspicious.FuzzyHash.Poly";
                suspiciousMatch.familyName  = "Polymorphic";
                matches.push_back(std::move(suspiciousMatch));
            }

            if (!matches.empty()) {
                m_stats.fuzzyMatches.fetch_add(
                    matches.size(), std::memory_order_relaxed);

                // Snapshot the callback under the shared lock then invoke it
                // OUTSIDE the lock to avoid deadlock if the callback itself
                // (or any code it invokes) calls UnregisterCallbacks() which
                // acquires the same mutex exclusively.
                FuzzyMatchCallback cbCopy;
                {
                    std::shared_lock cbLock(m_callbackMutex);
                    cbCopy = m_fuzzyMatchCallback;
                }
                if (cbCopy) {
                    for (const auto& m : matches) {
                        try { cbCopy(m); } catch (...) {
                            SS_LOG_ERROR(kLogCategory,
                                L"Fuzzy-match callback threw");
                        }
                    }
                }
            }

            return matches;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(kLogCategory, L"Fuzzy match error: %hs", ex.what());
            return matches;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Fuzzy match unknown error");
            return matches;
        }
    }

    std::string PolymorphicDetectorImpl::CalculateFuzzyHashInternal(
        std::span<const uint8_t> data) noexcept {
        try {
            if (data.empty()) return {};

            constexpr size_t kMaxFuzzyInput = 256ULL * 1024ULL * 1024ULL;
            const size_t hashSize = std::min(data.size(), kMaxFuzzyInput);

            char result[ShadowStrike::FuzzyHasher::kMaxResultLength]{};
            if (ShadowStrike::FuzzyHasher::HashBufferRaw(
                    data.data(), static_cast<uint32_t>(hashSize), result) == 0) {
                return std::string(result);
            }

            return {};
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during fuzzy hash calculation");
            return {};
        }
    }

    std::string PolymorphicDetectorImpl::CalculateTLSHInternal(
        std::span<const uint8_t> data) noexcept {
        try {
            if (data.empty() || data.size() < 50) return {};

            Tlsh tlsh;
            tlsh.update(data.data(), static_cast<unsigned int>(
                std::min<size_t>(data.size(), UINT_MAX)));
            tlsh.final();

            // tlsh.getHash() returns const char* and may be NULL when the
            // implementation has insufficient input variance. Constructing
            // std::string from NULL is UB.
            const char* hash = tlsh.getHash();
            return (hash != nullptr) ? std::string(hash) : std::string{};
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during TLSH calculation");
            return {};
        }
    }

    uint32_t PolymorphicDetectorImpl::CompareFuzzyHashInternal(
        const std::string& h1, const std::string& h2) noexcept {
        try {
            if (h1.empty() || h2.empty()) return 0;
            const int sim = ShadowStrike::FuzzyHasher::Compare(h1.c_str(), h2.c_str());
            return (sim >= 0) ? static_cast<uint32_t>(sim) : 0;
        } catch (...) {
            return 0;
        }
    }

    uint32_t PolymorphicDetectorImpl::CompareTLSHInternal(
        const std::string& h1, const std::string& h2) noexcept {
        try {
            if (h1.empty() || h2.empty()) return 0;

            Tlsh t1, t2;
            t1.fromTlshStr(h1.c_str());
            t2.fromTlshStr(h2.c_str());

            const int distance = t1.totalDiff(&t2);
            const int similarity = std::max(0, 100 - (distance / 6));
            return static_cast<uint32_t>(similarity);
        } catch (...) {
            return 0;
        }
    }

    // ========================================================================
    // IMPL: CONFIDENCE SCORING
    // ========================================================================

    PolymorphicDetectionConfidence PolymorphicDetectorImpl::CalculateConfidence(
        const PolyResult& result) noexcept {
        try {
            int score = 0;

            // Known engine → high signal
            if (result.engineType != PolyEngineType::Unknown) {
                score += (result.engineType == PolyEngineType::Custom) ? 20 : 40;
            }

            // Each mutation type adds confidence
            score += static_cast<int>(result.mutations.size()) * 15;

            // Decryption loops are strong indicators
            score += static_cast<int>(result.decryptionLoops.size()) * 20;

            // Fuzzy matches add high confidence
            for (const auto& m : result.fuzzyMatches) {
                score += static_cast<int>(m.score / 3);
            }

            // Metamorphic classification
            if (result.isMetamorphic) score += 25;

            if (score >= 90) return PolymorphicDetectionConfidence::Certain;
            if (score >= 60) return PolymorphicDetectionConfidence::High;
            if (score >= 40) return PolymorphicDetectionConfidence::Medium;
            if (score >= 20) return PolymorphicDetectionConfidence::Low;
            return PolymorphicDetectionConfidence::None;
        } catch (...) {
            return PolymorphicDetectionConfidence::None;
        }
    }

    // ========================================================================
    // IMPL: UTILITY
    // ========================================================================

    bool PolymorphicDetectorImpl::IsJunkInstruction(
        std::span<const uint8_t> code, size_t offset) noexcept {
        try {
            if (offset >= code.size()) return false;

            std::shared_lock lock(m_mutex);
            for (const auto& pattern : m_junkPatterns) {
                if (offset + pattern.size() > code.size()) continue;

                bool match = true;
                for (size_t i = 0; i < pattern.size(); ++i) {
                    if (code[offset + i] != pattern[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }

            return false;
        } catch (...) {
            return false;
        }
    }

    bool PolymorphicDetectorImpl::IsDeadCode(
        std::span<const uint8_t> code, size_t offset,
        size_t prevInstrLen) noexcept {
        try {
            if (offset == 0 || offset >= code.size()) return false;

            // Check if previous instruction was an unconditional transfer
            if (prevInstrLen > 0 && offset >= prevInstrLen) {
                size_t prevStart = offset - prevInstrLen;
                uint8_t prevByte = code[prevStart];

                // RET (C3), RETF (CB)
                if (prevByte == 0xC3 || prevByte == 0xCB) return true;

                // RET imm16 (C2 xx xx), RETF imm16 (CA xx xx)
                if ((prevByte == 0xC2 || prevByte == 0xCA) && prevInstrLen == 3)
                    return true;

                // JMP short (EB rel8) - only if jumping away
                if (prevByte == 0xEB && prevInstrLen == 2) {
                    int8_t rel = static_cast<int8_t>(code[prevStart + 1]);
                    if (rel != 0) return true; // Not JMP $+0
                }

                // JMP near (E9 rel32)
                if (prevByte == 0xE9 && prevInstrLen == 5)
                    return true;
            }

            return false;
        } catch (...) {
            return false;
        }
    }

    double PolymorphicDetectorImpl::CalculateEntropy(
        std::span<const uint8_t> data) noexcept {
        try {
            if (data.empty()) return 0.0;

            std::array<uint64_t, 256> counts{};
            for (const uint8_t byte : data) {
                counts[byte]++;
            }

            double entropy = 0.0;
            const double dataSize = static_cast<double>(data.size());

            for (const uint64_t count : counts) {
                if (count == 0) continue;
                const double p = static_cast<double>(count) / dataSize;
                entropy -= p * std::log2(p);
            }

            return entropy;
        } catch (...) {
            return 0.0;
        }
    }

    void PolymorphicDetectorImpl::EvictStaleCacheEntries() noexcept {
        // Caller must hold unique_lock on m_cacheMutex
        try {
            if (m_normCache.size() < kMaxCacheEntries / 2) return;

            const auto cutoff = Clock::now() - std::chrono::seconds(
                m_config.cacheTtlSeconds > 0 ? m_config.cacheTtlSeconds : 3600u);

            for (auto it = m_normCache.begin(); it != m_normCache.end(); ) {
                if (it->second.timestamp < cutoff) {
                    it = m_normCache.erase(it);
                } else {
                    ++it;
                }
            }

            SS_LOG_DEBUG(kLogCategory,
                L"Cache eviction complete, %zu entries remaining", m_normCache.size());

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during cache eviction");
        }
    }

    void PolymorphicDetectorImpl::NotifyError(const std::string& msg, int code) noexcept {
        try {
            // Snapshot then release the lock before invoking the callback —
            // the callback may legally call UnregisterCallbacks() which
            // acquires m_callbackMutex exclusively, deadlocking otherwise.
            ErrorCallback cbCopy;
            {
                std::shared_lock cbLock(m_callbackMutex);
                cbCopy = m_errorCallback;
            }
            if (cbCopy) {
                try { cbCopy(msg, code); } catch (...) {}
            }
        } catch (...) {}
    }

    // ========================================================================
    // STATIC MEMBER DEFINITIONS
    // ========================================================================

    std::atomic<bool> PolymorphicDetector::s_instanceCreated{false};

    // ========================================================================
    // PUBLIC API: SINGLETON & LIFECYCLE
    // ========================================================================

    PolymorphicDetector& PolymorphicDetector::Instance() noexcept {
        static PolymorphicDetector instance;
        s_instanceCreated.store(true, std::memory_order_release);
        return instance;
    }

    bool PolymorphicDetector::HasInstance() noexcept {
        return s_instanceCreated.load(std::memory_order_acquire);
    }

    PolymorphicDetector::PolymorphicDetector()
        : m_impl(std::make_unique<PolymorphicDetectorImpl>()) {
    }

    PolymorphicDetector::~PolymorphicDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool PolymorphicDetector::Initialize(const PolymorphicConfiguration& config) {
        if (!m_impl) {
            SS_LOG_ERROR(kLogCategory, L"Detector instance is null");
            return false;
        }
        if (!config.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Invalid configuration");
            return false;
        }
        return m_impl->Initialize(config);
    }

    void PolymorphicDetector::Shutdown() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool PolymorphicDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
    }

    PolyDetectorStatus PolymorphicDetector::GetStatus() const noexcept {
        if (!m_impl) return PolyDetectorStatus::Error;
        return m_impl->m_status.load(std::memory_order_acquire);
    }

    // ========================================================================
    // PUBLIC API: ANALYSIS
    // ========================================================================

    PolyResult PolymorphicDetector::Analyze(const std::vector<uint8_t>& code) {
        return Analyze(std::span<const uint8_t>(code));
    }

    PolyResult PolymorphicDetector::Analyze(
        std::span<const uint8_t> code, const PolyAnalysisOptions& options) {
        PolyResult result;
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"Analyze called before initialization");
            return result;
        }
        if (!options.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Invalid analysis options");
            return result;
        }
        return m_impl->AnalyzeInternal(code, options);
    }

    PolyResult PolymorphicDetector::AnalyzeFile(
        const fs::path& filePath, const PolyAnalysisOptions& options) {
        PolyResult result;

        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"AnalyzeFile called before initialization");
            return result;
        }

        try {
            std::error_code ec;
            if (!fs::exists(filePath, ec) || ec) {
                SS_LOG_ERROR(kLogCategory, L"File does not exist: %ls",
                    filePath.c_str());
                return result;
            }

            const auto fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) {
                SS_LOG_ERROR(kLogCategory, L"Cannot read file size: %ls",
                    filePath.c_str());
                return result;
            }

            // ================================================================
            // LOCATE THE CODE. DO NOT ASSUME THE FILE IS CODE.
            // ================================================================
            //
            // This function used to read up to MAX_CODE_SIZE bytes from offset 0
            // and hand them to AnalyzeInternal, whose parameter is named `code`,
            // with no PE parse and no type check. Everything this class detects
            // is x86: the junk patterns are x86 opcodes, DetectEngineInternal
            // matches x86 engine stubs, FindDecryptionLoopsInternal looks for
            // x86 decryptor loops. So every non-executable file on the machine
            // was judged as code, and because x86 decodes nearly any byte
            // sequence the answers tracked byte frequency rather than intent.
            //
            // 1.0.109 measured the consequence exactly: fourteen detections, all
            // false, none executable - five Prefetch files, two scheduled-task
            // XML files, MpCmdRun.log and Microsoft.LocalContent.db reported
            // Polymorphic.Generic or Polymorphic. Only blocked=0 kept it
            // harmless.
            //
            // THE PE ARM IS STRICTLY STRONGER THAN WHAT IT REPLACES, so this is a
            // precision fix and not a narrowing:
            //   * the analysed bytes are the executable section rather than the
            //     whole image, so a decryptor loop in .text is no longer searched
            //     for across icons, string tables and overlay data, and the junk
            //     ratio is measured over instructions instead of over resources.
            //     Diluting the signal with non-code bytes lowered confidence on
            //     real packers.
            //   * the PE is parsed from the FILE, not from a 16 MB prefix of it.
            //     The old code read at most MAX_CODE_SIZE and treated that as the
            //     whole file, so no PE larger than 16 MB could be parsed at all -
            //     found by this module's own guard suite against a 64 MB binary.
            //   * only the code section is read, instead of up to 16 MB of every
            //     file scanned. For a typical executable that is a large
            //     reduction in I/O on the scan path.
            //
            // NOTHING COVERS RAW ON-DISK SHELLCODE FROM HERE, AND IT DOES NOT
            // NEED TO - three modules own that independently, each with named
            // families rather than generic scoring:
            //   * ZeroDayDetector::DetectShellcode - eight signature families
            //     (Meterpreter reverse_tcp, Cobalt Strike beacon, x86 bind and
            //     reverse shells, egg hunter, x64 syscall stub, ws2_32
            //     download-and-execute) plus IsPotentialShellcode, running on the
            //     same file as ScanEngine stage 9.
            //   * MemoryScanner::AnalyzeForShellcode - NOP sled, GetPC, API
            //     hashing, syscall and lea-rip indicators.
            //   * MemoryProtection::ScanForShellcode - NOP sled, encoder stub,
            //     position-independent code, plus the kernel's own
            //     SHELLCODE_DETECTION_EVENT.
            // A file with no PE header also still passes through the hash, threat
            // intel and YARA/pattern stages, which are content matches and do not
            // care whether the bytes are code. So no detection is given up here;
            // the wrong analyser stops guessing.
            uint64_t readOffset = 0;
            size_t   readSize   = 0;
            PolyBufferKind kind = PolyBufferKind::OpaqueData;

            PEParser::PEParser peParser;
            PEParser::PEInfo peInfo;
            if (peParser.ParseFile(filePath.wstring(), peInfo, nullptr)) {
                // First executable section that is genuinely present in the file.
                // rawAddress and rawSize are file offsets and a section header can
                // describe more than the file holds - a truncated or deliberately
                // malformed image - so both are bounded against the real size
                // rather than trusted.
                for (const auto& sec : peInfo.sections) {
                    if (!sec.isExecutable || sec.rawSize == 0) {
                        continue;
                    }
                    if (static_cast<uint64_t>(sec.rawAddress) >= fileSize) {
                        continue;
                    }
                    const uint64_t avail = fileSize - sec.rawAddress;
                    const uint64_t want  = std::min<uint64_t>(sec.rawSize, avail);
                    if (want < PolyConstants::MIN_CODE_SIZE) {
                        continue;
                    }
                    readOffset = sec.rawAddress;
                    readSize   = static_cast<size_t>(
                        std::min<uint64_t>(want, PolyConstants::MAX_CODE_SIZE));
                    kind = PolyBufferKind::MachineCode;
                    break;
                }

                if (kind != PolyBufferKind::MachineCode) {
                    // A parsed PE with no usable executable section: malformed, or
                    // pure resource data. Treated as opaque rather than falling
                    // back to the whole file, which is the defect described above.
                    SS_LOG_DEBUG(kLogCategory,
                        L"PE has no usable executable section, code analysis not "
                        L"applicable: %ls", filePath.c_str());
                }
            }

            if (kind == PolyBufferKind::OpaqueData) {
                readOffset = 0;
                readSize   = static_cast<size_t>(
                    std::min<uintmax_t>(fileSize, PolyConstants::MAX_CODE_SIZE));
                SS_LOG_DEBUG(kLogCategory,
                    L"Not machine code, similarity hashes only: %ls",
                    filePath.c_str());
            }

            std::vector<uint8_t> fileData(readSize);
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                SS_LOG_ERROR(kLogCategory, L"Failed to open file: %ls",
                    filePath.c_str());
                return result;
            }

            if (readOffset != 0) {
                file.seekg(static_cast<std::streamoff>(readOffset), std::ios::beg);
                if (!file) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Failed to seek to code section at offset %llu: %ls",
                        static_cast<unsigned long long>(readOffset),
                        filePath.c_str());
                    return result;
                }
            }

            file.read(reinterpret_cast<char*>(fileData.data()),
                       static_cast<std::streamsize>(readSize));
            const auto bytesRead = static_cast<size_t>(file.gcount());
            fileData.resize(bytesRead);

            PolyResult analyzed = m_impl->AnalyzeInternal(fileData, options, kind);

            // Record WHICH bytes were judged. Without this a caller cannot tell
            // an executable section from a data section, and neither can a guard.
            analyzed.analyzedOffset = readOffset;
            analyzed.analyzedSize   = static_cast<uint32_t>(
                std::min<size_t>(bytesRead, 0xFFFFFFFFu));

            return analyzed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCategory,
                L"AnalyzeFile exception for %ls: %hs",
                filePath.c_str(), e.what());
            return result;
        }
    }

    void PolymorphicDetector::AnalyzeAsync(
        std::span<const uint8_t> code,
        AnalysisCallback callback,
        const PolyAnalysisOptions& options) {

        if (!IsInitialized() || !callback) {
            if (callback) {
                callback(PolyResult{});
            }
            return;
        }

        // Bound concurrency to defend against thread-exhaustion DoS via a
        // flood of AnalyzeAsync() calls. Reject when at capacity rather
        // than silently queuing — caller learns the result immediately.
        const uint32_t inflight =
            m_impl->m_asyncInFlight.load(std::memory_order_acquire);
        if (inflight >= kMaxAsyncInFlight) {
            SS_LOG_WARN(kLogCategory,
                L"AnalyzeAsync rejected: %u in-flight (cap %u)",
                inflight, kMaxAsyncInFlight);
            try { callback(PolyResult{}); } catch (...) {}
            return;
        }

        auto codeCopy = std::make_shared<std::vector<uint8_t>>(code.begin(), code.end());
        auto optsCopy = options;
        auto implPtr  = m_impl.get();

        // Increment BEFORE spawning so Shutdown() observes the in-flight
        // worker even if the OS schedules the new thread later.
        m_impl->m_asyncInFlight.fetch_add(1, std::memory_order_acq_rel);

        try {
            std::thread([codeCopy, callback, optsCopy, implPtr]() {
                try {
                    auto result = implPtr->AnalyzeInternal(*codeCopy, optsCopy);
                    try { callback(result); } catch (...) {
                        SS_LOG_ERROR(kLogCategory, L"Async callback threw");
                    }
                } catch (...) {
                    SS_LOG_ERROR(kLogCategory, L"Async analysis thread exception");
                    try { callback(PolyResult{}); } catch (...) {}
                }
                implPtr->m_asyncInFlight.fetch_sub(1, std::memory_order_acq_rel);
            }).detach();
        } catch (...) {
            // std::thread ctor can throw resource_unavailable_try_again.
            // Roll back the counter and surface failure to the caller.
            m_impl->m_asyncInFlight.fetch_sub(1, std::memory_order_acq_rel);
            SS_LOG_ERROR(kLogCategory, L"Failed to spawn async analysis thread");
            try { callback(PolyResult{}); } catch (...) {}
        }
    }

    // ========================================================================
    // PUBLIC API: NORMALIZATION
    // ========================================================================

    std::vector<uint8_t> PolymorphicDetector::NormalizeInstructions(
        const std::vector<uint8_t>& input) {
        if (!IsInitialized()) return input;
        auto result = m_impl->NormalizeCodeInternal(input, NormalizationLevel::Standard);
        return std::move(result.normalizedCode);
    }

    NormalizationResult PolymorphicDetector::NormalizeCode(
        std::span<const uint8_t> code, NormalizationLevel level) {
        NormalizationResult result;
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory, L"NormalizeCode called before initialization");
            return result;
        }
        return m_impl->NormalizeCodeInternal(code, level);
    }

    std::vector<uint8_t> PolymorphicDetector::RemoveJunkCode(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) return std::vector<uint8_t>(code.begin(), code.end());
        return m_impl->RemoveJunkCodeInternal(code);
    }

    std::vector<uint8_t> PolymorphicDetector::NormalizeRegisters(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) return std::vector<uint8_t>(code.begin(), code.end());
        return m_impl->NormalizeRegistersInternal(code);
    }

    // ========================================================================
    // PUBLIC API: ENGINE DETECTION
    // ========================================================================

    std::optional<PolyEngineType> PolymorphicDetector::DetectEngine(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) return std::nullopt;
        auto result = m_impl->DetectEngineInternal(code);
        if (result == PolyEngineType::Unknown) return std::nullopt;
        return result;
    }

    std::string PolymorphicDetector::GetEngineName(PolyEngineType engine) const {
        return std::string(GetPolyEngineTypeName(engine));
    }

    std::set<MutationType> PolymorphicDetector::DetectMutations(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) return {};
        return m_impl->DetectMutationsInternal(code);
    }

    // ========================================================================
    // PUBLIC API: DECRYPTION
    // ========================================================================

    std::vector<DecryptionLoopInfo> PolymorphicDetector::FindDecryptionLoops(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory,
                L"FindDecryptionLoops called before initialization");
            return {};
        }
        return m_impl->FindDecryptionLoopsInternal(code);
    }

    std::optional<std::vector<uint8_t>> PolymorphicDetector::ExtractXORKey(
        std::span<const uint8_t> code) {
        if (!IsInitialized()) return std::nullopt;

        auto loops = m_impl->FindDecryptionLoopsInternal(code);
        for (const auto& loop : loops) {
            if (loop.algorithm == "XOR" && loop.xorKey.has_value()) {
                return loop.xorKey;
            }
        }
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> PolymorphicDetector::DecryptPayload(
        std::span<const uint8_t> encryptedData,
        const std::vector<uint8_t>& key) {
        if (!IsInitialized()) return std::nullopt;
        if (key.empty() || encryptedData.empty()) return std::nullopt;

        try {
            std::vector<uint8_t> decrypted(encryptedData.begin(), encryptedData.end());
            for (size_t i = 0; i < decrypted.size(); ++i) {
                decrypted[i] ^= key[i % key.size()];
            }
            return decrypted;
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Exception during payload decryption");
            return std::nullopt;
        }
    }

    // ========================================================================
    // PUBLIC API: FUZZY MATCHING
    // ========================================================================

    std::vector<FuzzyHashMatch> PolymorphicDetector::FuzzyMatch(
        std::span<const uint8_t> normalizedCode) {
        if (!IsInitialized()) {
            SS_LOG_ERROR(kLogCategory,
                L"FuzzyMatch called before initialization");
            return {};
        }
        return m_impl->FuzzyMatchInternal(
            normalizedCode,
            m_impl->m_config.defaultOptions.fuzzyThreshold);
    }

    std::string PolymorphicDetector::CalculateFuzzyHash(
        std::span<const uint8_t> data) {
        if (!IsInitialized()) return {};
        return m_impl->CalculateFuzzyHashInternal(data);
    }

    std::string PolymorphicDetector::CalculateTLSH(
        std::span<const uint8_t> data) {
        if (!IsInitialized()) return {};
        return m_impl->CalculateTLSHInternal(data);
    }

    uint32_t PolymorphicDetector::CompareFuzzyHash(
        const std::string& hash1, const std::string& hash2) {
        if (!IsInitialized()) return 0;
        return m_impl->CompareFuzzyHashInternal(hash1, hash2);
    }

    // ========================================================================
    // PUBLIC API: CALLBACKS
    // ========================================================================

    void PolymorphicDetector::RegisterFuzzyMatchCallback(FuzzyMatchCallback callback) {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_fuzzyMatchCallback = std::move(callback);
    }

    void PolymorphicDetector::RegisterErrorCallback(ErrorCallback callback) {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_errorCallback = std::move(callback);
    }

    void PolymorphicDetector::UnregisterCallbacks() {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_fuzzyMatchCallback = nullptr;
        m_impl->m_errorCallback = nullptr;
    }

    // ========================================================================
    // PUBLIC API: STATISTICS & DIAGNOSTICS
    // ========================================================================

    const PolyStatistics& PolymorphicDetector::GetStatistics() const noexcept {
        static PolyStatistics empty;
        if (!m_impl) return empty;
        return m_impl->m_stats;
    }

    void PolymorphicDetector::ResetStatistics() {
        if (m_impl) {
            // PolyStatistics::startTime is a non-atomic TimePoint; the
            // counters are atomic. Take the impl write-lock so concurrent
            // readers/writers of startTime never observe a torn value.
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_stats.Reset();
        }
    }

    bool PolymorphicDetector::SelfTest() {
        if (!IsInitialized()) return false;

        try {
            // Test 1: Entropy calculation
            std::vector<uint8_t> highEntropy(256);
            std::iota(highEntropy.begin(), highEntropy.end(), uint8_t(0));
            double e = m_impl->CalculateEntropy(highEntropy);
            if (e < 7.99 || e > 8.01) return false;

            // Test 2: Zero entropy
            std::vector<uint8_t> zeroEntropy(256, 0xAA);
            e = m_impl->CalculateEntropy(zeroEntropy);
            if (e > 0.01) return false;

            // Test 3: Junk code removal
            std::vector<uint8_t> junkCode = {0x90, 0x90, 0xEB, 0x00, 0xCC};
            auto cleaned = m_impl->RemoveJunkCodeInternal(junkCode);
            if (cleaned.size() >= junkCode.size()) return false;

            // Test 4: Fuzzy hash computation
            std::vector<uint8_t> testData(512, 0x41);
            auto hash = m_impl->CalculateFuzzyHashInternal(testData);
            // Hash may be empty if FuzzyHasher needs more data, so just verify no crash

            SS_LOG_INFO(kLogCategory, L"Self-test passed");
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed with exception");
            return false;
        }
    }

    std::string PolymorphicDetector::GetVersionString() noexcept {
        try {
            std::ostringstream oss;
            oss << "PolymorphicDetector v"
                << PolyConstants::VERSION_MAJOR << '.'
                << PolyConstants::VERSION_MINOR << '.'
                << PolyConstants::VERSION_PATCH;
            return oss.str();
        } catch (...) {
            return "PolymorphicDetector v?.?.?";
        }
    }

    // ========================================================================
    // STRUCT METHODS: ToJson
    // ========================================================================

    std::string DecryptionLoopInfo::ToJson() const {
        std::ostringstream j;
        j << "{\"loopStart\":" << loopStart
          << ",\"loopEnd\":" << loopEnd
          << ",\"iterations\":" << iterations
          << ",\"algorithm\":\"" << algorithm << '"'
          << ",\"decryptedStart\":" << decryptedStart
          << ",\"decryptedSize\":" << decryptedSize;
        if (xorKey.has_value()) {
            j << ",\"keyLength\":" << xorKey->size();
        }
        j << '}';
        return j.str();
    }

    std::string JunkCodeRegion::ToJson() const {
        std::ostringstream j;
        j << "{\"start\":" << startOffset
          << ",\"end\":" << endOffset
          << ",\"size\":" << size
          << ",\"type\":\"" << patternType << "\"}";
        return j.str();
    }

    std::string NormalizationResult::ToJson() const {
        std::ostringstream j;
        j << "{\"originalSize\":" << originalSize
          << ",\"normalizedSize\":" << normalizedSize
          << ",\"reductionRatio\":" << reductionRatio
          << ",\"instructionsRemoved\":" << instructionsRemoved
          << ",\"passes\":" << passesPerformed
          << ",\"processingTimeMs\":" << processingTimeMs
          << ",\"junkRegions\":" << junkRegions.size()
          << '}';
        return j.str();
    }

    std::string FuzzyHashMatch::ToJson() const {
        std::ostringstream j;
        j << "{\"score\":" << score
          << ",\"threatName\":\"" << threatName << '"'
          << ",\"familyName\":\"" << familyName << '"'
          << ",\"variant\":\"" << variant << '"'
          << ",\"matchedHash\":\"" << matchedHash.substr(0, 32) << "...\"}";
        return j.str();
    }

    std::string PolyResult::ToJson() const {
        std::ostringstream j;
        j << "{\"isPolymorphic\":" << (isPolymorphic ? "true" : "false")
          << ",\"isMetamorphic\":" << (isMetamorphic ? "true" : "false")
          << ",\"engineName\":\"" << engineName << '"'
          << ",\"confidence\":" << static_cast<int>(confidence)
          << ",\"mutations\":" << mutations.size()
          << ",\"decryptionLoops\":" << decryptionLoops.size()
          << ",\"fuzzyMatches\":" << fuzzyMatches.size()
          << ",\"analysisTimeMs\":" << analysisTimeMs;
        if (!fuzzyHash.empty())
            j << ",\"fuzzyHash\":\"" << fuzzyHash.substr(0, 32) << "...\"";
        if (!tlshHash.empty())
            j << ",\"tlshHash\":\"" << tlshHash.substr(0, 32) << "...\"";
        if (!threatFamily.empty())
            j << ",\"threatFamily\":\"" << threatFamily << '"';
        j << '}';
        return j.str();
    }

    // ========================================================================
    // STRUCT METHODS: IsValid / Reset
    // ========================================================================

    bool PolyAnalysisOptions::IsValid() const noexcept {
        if (fuzzyThreshold > 100) return false;
        if (maxAnalysisTimeMs == 0 || maxAnalysisTimeMs > 300000) return false;
        return true;
    }

    bool PolymorphicConfiguration::IsValid() const noexcept {
        if (!defaultOptions.IsValid()) return false;
        if (workerThreads == 0 || workerThreads > 64) return false;
        if (enableCaching && cacheTtlSeconds == 0) return false;
        return true;
    }

    void PolyStatistics::Reset() noexcept {
        totalAnalyses.store(0, std::memory_order_relaxed);
        polymorphicDetected.store(0, std::memory_order_relaxed);
        metamorphicDetected.store(0, std::memory_order_relaxed);
        fuzzyMatches.store(0, std::memory_order_relaxed);
        decryptionLoopsFound.store(0, std::memory_order_relaxed);
        normalizationOperations.store(0, std::memory_order_relaxed);
        junkCodeRemoved.store(0, std::memory_order_relaxed);
        for (auto& a : byEngineType) {
            a.store(0, std::memory_order_relaxed);
        }
        startTime = Clock::now();
    }

    std::string PolyStatistics::ToJson() const {
        std::ostringstream j;
        j << "{\"totalAnalyses\":" << totalAnalyses.load(std::memory_order_relaxed)
          << ",\"polymorphicDetected\":" << polymorphicDetected.load(std::memory_order_relaxed)
          << ",\"metamorphicDetected\":" << metamorphicDetected.load(std::memory_order_relaxed)
          << ",\"fuzzyMatches\":" << fuzzyMatches.load(std::memory_order_relaxed)
          << ",\"decryptionLoopsFound\":" << decryptionLoopsFound.load(std::memory_order_relaxed)
          << ",\"normalizationOps\":" << normalizationOperations.load(std::memory_order_relaxed)
          << ",\"junkCodeRemoved\":" << junkCodeRemoved.load(std::memory_order_relaxed)
          << '}';
        return j.str();
    }

    // ========================================================================
    // FREE FUNCTIONS
    // ========================================================================

    std::string_view GetPolyEngineTypeName(PolyEngineType engine) noexcept {
        switch (engine) {
        case PolyEngineType::Unknown:       return "Unknown";
        case PolyEngineType::Mistfall:      return "Mistfall";
        case PolyEngineType::EPC:           return "EPC";
        case PolyEngineType::SMEG:          return "SMEG";
        case PolyEngineType::Dark_Avenger:  return "Dark_Avenger";
        case PolyEngineType::One_Half:      return "One_Half";
        case PolyEngineType::IDEA:          return "IDEA";
        case PolyEngineType::TPE:           return "TPE";
        case PolyEngineType::MtE:           return "MtE";
        case PolyEngineType::NED:           return "NED";
        case PolyEngineType::DAME:          return "DAME";
        case PolyEngineType::VCL:           return "VCL";
        case PolyEngineType::Phalcon_Skism: return "Phalcon_Skism";
        case PolyEngineType::Custom:        return "Custom";
        default:                            return "Unknown";
        }
    }

    std::string_view GetMutationTypeName(MutationType mutation) noexcept {
        switch (mutation) {
        case MutationType::None:            return "None";
        case MutationType::RegisterSwap:    return "RegisterSwap";
        case MutationType::InstructionSub:  return "InstructionSub";
        case MutationType::JunkInsertion:   return "JunkInsertion";
        case MutationType::CodeReorder:     return "CodeReorder";
        case MutationType::LoopUnroll:      return "LoopUnroll";
        case MutationType::Encryption:      return "Encryption";
        case MutationType::Compression:     return "Compression";
        case MutationType::Combined:        return "Combined";
        default:                            return "Unknown";
        }
    }

    std::string_view GetNormalizationLevelName(NormalizationLevel level) noexcept {
        switch (level) {
        case NormalizationLevel::None:       return "None";
        case NormalizationLevel::Basic:      return "Basic";
        case NormalizationLevel::Standard:   return "Standard";
        case NormalizationLevel::Aggressive: return "Aggressive";
        case NormalizationLevel::Full:       return "Full";
        default:                             return "Unknown";
        }
    }

    std::string_view GetPolymorphicDetectionConfidenceName(PolymorphicDetectionConfidence confidence) noexcept {
        switch (confidence) {
        case PolymorphicDetectionConfidence::None:    return "None";
        case PolymorphicDetectionConfidence::Low:     return "Low";
        case PolymorphicDetectionConfidence::Medium:  return "Medium";
        case PolymorphicDetectionConfidence::High:    return "High";
        case PolymorphicDetectionConfidence::Certain: return "Certain";
        default:                           return "Unknown";
        }
    }

    bool IsPotentiallyPolymorphic(std::span<const uint8_t> code) {
        if (code.size() < PolyConstants::MIN_CODE_SIZE) return false;

        // Quick entropy check - polymorphic code tends to have high entropy
        float entropy = GetCodeEntropy(code);
        if (entropy >= 6.5f) return true;

        // Quick junk code check in first 256 bytes
        size_t nopCount = 0;
        const size_t checkLen = std::min<size_t>(256, code.size());
        for (size_t i = 0; i < checkLen; ++i) {
            if (code[i] == 0x90) ++nopCount;
        }
        if (checkLen > 0 && (static_cast<float>(nopCount) / static_cast<float>(checkLen)) > 0.15f)
            return true;

        // Quick XOR loop check
        for (size_t i = 0; i + 4 < checkLen; ++i) {
            if ((code[i] == 0x80 && (code[i + 1] & 0x38) == 0x30) ||
                code[i] == 0x30 || code[i] == 0x31) {
                // Found XOR instruction, check for loop nearby
                for (size_t j = i + 1; j < std::min(i + 10, checkLen); ++j) {
                    if (code[j] == 0xE2 || code[j] == 0x75) return true;
                }
            }
        }

        return false;
    }

    float GetCodeEntropy(std::span<const uint8_t> code) {
        if (code.empty()) return 0.0f;

        std::array<uint64_t, 256> counts{};
        for (const uint8_t b : code) {
            counts[b]++;
        }

        double entropy = 0.0;
        const double n = static_cast<double>(code.size());
        for (const uint64_t c : counts) {
            if (c == 0) continue;
            const double p = static_cast<double>(c) / n;
            entropy -= p * std::log2(p);
        }
        return static_cast<float>(entropy);
    }

} // namespace ShadowStrike::Core::Engine
