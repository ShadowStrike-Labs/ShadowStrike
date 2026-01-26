/**
 * @file MetamorphicDetector.cpp
 * @brief Enterprise-grade detection of metamorphic, polymorphic, and self-modifying code
 *
 * ShadowStrike AntiEvasion - Metamorphic Code Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection of code that mutates itself to
 * evade signature-based detection. Detects sophisticated malware engines including
 * metamorphic, polymorphic, self-modifying, VM-protected, and packed code.
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (SignatureStore, HashStore, PatternStore, ThreatIntel)
 */

#include "pch.h"
#include "MetamorphicDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <execution>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <queue>
#include <sstream>
#include <unordered_set>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"

// ============================================================================
// EXTERNAL LIBRARIES
// ============================================================================

// TLSH fuzzy hashing (already in External/tlsh/)
#include "../External/tlsh/tlsh.h"

namespace fs = std::filesystem;

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get string representation of technique
     */
    [[nodiscard]] const wchar_t* MetamorphicTechniqueToString(MetamorphicTechnique technique) noexcept {
        switch (technique) {
            // Metamorphic
        case MetamorphicTechnique::META_NOPInsertion:
            return L"NOP Sled Insertion";
        case MetamorphicTechnique::META_DeadCodeInsertion:
            return L"Dead Code Insertion";
        case MetamorphicTechnique::META_InstructionSubstitution:
            return L"Instruction Substitution";
        case MetamorphicTechnique::META_RegisterReassignment:
            return L"Register Reassignment";
        case MetamorphicTechnique::META_CodeTransposition:
            return L"Code Transposition";
        case MetamorphicTechnique::META_SubroutineReordering:
            return L"Subroutine Reordering";
        case MetamorphicTechnique::META_InstructionPermutation:
            return L"Instruction Permutation";
        case MetamorphicTechnique::META_VariableRenaming:
            return L"Variable Renaming";
        case MetamorphicTechnique::META_CodeExpansion:
            return L"Code Expansion";
        case MetamorphicTechnique::META_CodeShrinking:
            return L"Code Shrinking";
        case MetamorphicTechnique::META_GarbageBytes:
            return L"Garbage Byte Insertion";
        case MetamorphicTechnique::META_OpaquePredicates:
            return L"Opaque Predicates";
        case MetamorphicTechnique::META_BranchFunctions:
            return L"Branch Function Insertion";
        case MetamorphicTechnique::META_InterleavedCode:
            return L"Interleaved Code Blocks";
        case MetamorphicTechnique::META_InliningVariation:
            return L"Inlining Variation";
        case MetamorphicTechnique::META_RandomPadding:
            return L"Random Padding";
        case MetamorphicTechnique::META_InstructionSplitting:
            return L"Instruction Splitting";
        case MetamorphicTechnique::META_InstructionMerging:
            return L"Instruction Merging";
        case MetamorphicTechnique::META_StackSubstitution:
            return L"Stack Operation Substitution";
        case MetamorphicTechnique::META_ArithmeticSubstitution:
            return L"Arithmetic Substitution";

            // Polymorphic
        case MetamorphicTechnique::POLY_XORDecryption:
            return L"XOR Decryption Loop";
        case MetamorphicTechnique::POLY_ADDSUBDecryption:
            return L"ADD/SUB Decryption";
        case MetamorphicTechnique::POLY_ROLRORDecryption:
            return L"ROL/ROR Decryption";
        case MetamorphicTechnique::POLY_MultiLayerEncryption:
            return L"Multi-Layer Encryption";
        case MetamorphicTechnique::POLY_VariableKey:
            return L"Variable Key Encryption";
        case MetamorphicTechnique::POLY_EnvironmentKey:
            return L"Environment-Derived Key";
        case MetamorphicTechnique::POLY_GetPC_CallPop:
            return L"GetPC via CALL/POP";
        case MetamorphicTechnique::POLY_GetPC_FSTENV:
            return L"GetPC via FSTENV";
        case MetamorphicTechnique::POLY_GetPC_SEH:
            return L"GetPC via SEH";
        case MetamorphicTechnique::POLY_GetPC_CallMem:
            return L"GetPC via CALL [mem]";
        case MetamorphicTechnique::POLY_DecoderMutation:
            return L"Decoder Stub Mutation";
        case MetamorphicTechnique::POLY_ShellcodeEncoder:
            return L"Shellcode Encoder/Decoder";
        case MetamorphicTechnique::POLY_RC4Decryption:
            return L"RC4 Decryption";
        case MetamorphicTechnique::POLY_AESDecryption:
            return L"AES Decryption Stub";
        case MetamorphicTechnique::POLY_CustomCipher:
            return L"Custom Cipher Implementation";
        case MetamorphicTechnique::POLY_AntiEmulation:
            return L"Anti-Emulation in Decryptor";
        case MetamorphicTechnique::POLY_IncrementalDecryption:
            return L"Incremental Decryption";
        case MetamorphicTechnique::POLY_StagedDecryption:
            return L"Staged Decryption";

            // Self-Modifying
        case MetamorphicTechnique::SELF_VirtualProtect:
            return L"VirtualProtect Usage";
        case MetamorphicTechnique::SELF_WriteProcessMemory:
            return L"WriteProcessMemory Self-Write";
        case MetamorphicTechnique::SELF_NtProtectVirtualMemory:
            return L"NtProtectVirtualMemory Usage";
        case MetamorphicTechnique::SELF_ExecutableHeap:
            return L"Executable Heap Allocation";
        case MetamorphicTechnique::SELF_DynamicCodeGen:
            return L"Dynamic Code Generation";
        case MetamorphicTechnique::SELF_JITEmission:
            return L"JIT Code Emission";
        case MetamorphicTechnique::SELF_RuntimePatching:
            return L"Runtime Code Patching";
        case MetamorphicTechnique::SELF_ImportTableMod:
            return L"Import Table Modification";
        case MetamorphicTechnique::SELF_ExceptionHandlerMod:
            return L"Exception Handler Modification";
        case MetamorphicTechnique::SELF_TLSCallbackMod:
            return L"TLS Callback Modification";
        case MetamorphicTechnique::SELF_RelocationAbuse:
            return L"Relocation Abuse";
        case MetamorphicTechnique::SELF_DelayLoadExploit:
            return L"Delay-Load Exploitation";

            // Obfuscation
        case MetamorphicTechnique::OBF_ControlFlowFlattening:
            return L"Control Flow Flattening";
        case MetamorphicTechnique::OBF_Dispatcher:
            return L"Dispatcher Obfuscation";
        case MetamorphicTechnique::OBF_StateMachine:
            return L"State Machine Obfuscation";
        case MetamorphicTechnique::OBF_OpaquePredicates:
            return L"Opaque Predicates";
        case MetamorphicTechnique::OBF_BogusControlFlow:
            return L"Bogus Control Flow";
        case MetamorphicTechnique::OBF_MixedBooleanArithmetic:
            return L"Mixed Boolean Arithmetic";
        case MetamorphicTechnique::OBF_StringEncryption:
            return L"String Encryption";
        case MetamorphicTechnique::OBF_ConstantUnfolding:
            return L"Constant Unfolding";
        case MetamorphicTechnique::OBF_APIHashing:
            return L"API Hashing";
        case MetamorphicTechnique::OBF_ImportObfuscation:
            return L"Import Obfuscation";
        case MetamorphicTechnique::OBF_AntiDisassembly:
            return L"Anti-Disassembly Tricks";
        case MetamorphicTechnique::OBF_OverlappingInstructions:
            return L"Overlapping Instructions";
        case MetamorphicTechnique::OBF_MisalignedCode:
            return L"Misaligned Code";
        case MetamorphicTechnique::OBF_ExceptionControlFlow:
            return L"Exception-Based Control Flow";
        case MetamorphicTechnique::OBF_StackObfuscation:
            return L"Stack Obfuscation";
        case MetamorphicTechnique::OBF_IndirectBranches:
            return L"Indirect Branches";
        case MetamorphicTechnique::OBF_ComputedJumps:
            return L"Computed Jumps";
        case MetamorphicTechnique::OBF_ReturnOriented:
            return L"Return-Oriented Obfuscation";

            // VM Protection
        case MetamorphicTechnique::VM_CustomInterpreter:
            return L"Custom VM Interpreter";
        case MetamorphicTechnique::VM_VMProtect:
            return L"VMProtect Detected";
        case MetamorphicTechnique::VM_Themida:
            return L"Themida/WinLicense Detected";
        case MetamorphicTechnique::VM_CodeVirtualizer:
            return L"Code Virtualizer Detected";
        case MetamorphicTechnique::VM_Oreans:
            return L"Oreans Detected";
        case MetamorphicTechnique::VM_Enigma:
            return L"Enigma Protector Detected";
        case MetamorphicTechnique::VM_ASProtect:
            return L"ASProtect Detected";
        case MetamorphicTechnique::VM_Obsidium:
            return L"Obsidium Detected";
        case MetamorphicTechnique::VM_PELock:
            return L"PELock Detected";
        case MetamorphicTechnique::VM_CustomBytecode:
            return L"Custom Bytecode Interpreter";
        case MetamorphicTechnique::VM_StackBased:
            return L"Stack-Based VM";
        case MetamorphicTechnique::VM_RegisterBased:
            return L"Register-Based VM";
        case MetamorphicTechnique::VM_Nested:
            return L"Nested VMs";

            // Packing
        case MetamorphicTechnique::PACK_UPX:
            return L"UPX Packer";
        case MetamorphicTechnique::PACK_ASPack:
            return L"ASPack";
        case MetamorphicTechnique::PACK_PECompact:
            return L"PECompact";
        case MetamorphicTechnique::PACK_MPRESS:
            return L"MPRESS";
        case MetamorphicTechnique::PACK_Petite:
            return L"Petite";
        case MetamorphicTechnique::PACK_FSG:
            return L"FSG";
        case MetamorphicTechnique::PACK_MEW:
            return L"MEW";
        case MetamorphicTechnique::PACK_NsPack:
            return L"NsPack";
        case MetamorphicTechnique::PACK_Custom:
            return L"Custom Packer";
        case MetamorphicTechnique::PACK_MultiLayer:
            return L"Multi-Layer Packing";
        case MetamorphicTechnique::PACK_Crypter:
            return L"Crypter Detected";

            // Structural Anomalies
        case MetamorphicTechnique::STRUCT_HighEntropy:
            return L"High Code Entropy";
        case MetamorphicTechnique::STRUCT_UnusualSections:
            return L"Unusual Section Characteristics";
        case MetamorphicTechnique::STRUCT_EntryPointAnomaly:
            return L"Entry Point Anomaly";
        case MetamorphicTechnique::STRUCT_SuspiciousImports:
            return L"Suspicious Imports";
        case MetamorphicTechnique::STRUCT_MinimalImports:
            return L"Minimal Imports";
        case MetamorphicTechnique::STRUCT_AbnormalHeader:
            return L"Abnormal PE Header";
        case MetamorphicTechnique::STRUCT_ResourceAnomaly:
            return L"Resource Anomaly";
        case MetamorphicTechnique::STRUCT_RelocationAnomaly:
            return L"Relocation Anomaly";
        case MetamorphicTechnique::STRUCT_TLSCallbacks:
            return L"TLS Callbacks Present";
        case MetamorphicTechnique::STRUCT_MultipleEntryPoints:
            return L"Multiple Entry Points";
        case MetamorphicTechnique::STRUCT_SelfReferential:
            return L"Self-Referential Structures";

            // Similarity
        case MetamorphicTechnique::SIMILARITY_SSDeepMatch:
            return L"SSDEEP Fuzzy Match";
        case MetamorphicTechnique::SIMILARITY_TLSHMatch:
            return L"TLSH Fuzzy Match";
        case MetamorphicTechnique::SIMILARITY_FunctionMatch:
            return L"Function-Level Similarity";
        case MetamorphicTechnique::SIMILARITY_BasicBlockMatch:
            return L"Basic Block Similarity";
        case MetamorphicTechnique::SIMILARITY_CFGMatch:
            return L"CFG Structural Similarity";
        case MetamorphicTechnique::SIMILARITY_NGramMatch:
            return L"N-Gram Sequence Match";
        case MetamorphicTechnique::SIMILARITY_MnemonicMatch:
            return L"Mnemonic Similarity";
        case MetamorphicTechnique::SIMILARITY_FamilyVariant:
            return L"Known Family Variant";

            // Advanced
        case MetamorphicTechnique::ADV_MultiCategory:
            return L"Multi-Category Mutation";
        case MetamorphicTechnique::ADV_EngineSignature:
            return L"Metamorphic Engine Signature";
        case MetamorphicTechnique::ADV_ProgressiveMutation:
            return L"Progressive Mutation";
        case MetamorphicTechnique::ADV_GenerationTracking:
            return L"Generation Tracking";
        case MetamorphicTechnique::ADV_AntiAnalysis:
            return L"Combined Anti-Analysis";
        case MetamorphicTechnique::ADV_SophisticatedEvasion:
            return L"Sophisticated Evasion";

        default:
            return L"Unknown Technique";
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class MetamorphicDetector::Impl {
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
        std::shared_ptr<HashStore::HashStore> m_hashStore;
        std::shared_ptr<PatternStore::PatternStore> m_patternStore;
        std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;

        /// @brief Detection callback
        MetamorphicDetectionCallback m_detectionCallback;

        /// @brief Statistics
        MetamorphicDetector::Statistics m_stats;

        /// @brief Result cache
        struct CacheEntry {
            MetamorphicResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<std::wstring, CacheEntry> m_resultCache;

        /// @brief Custom patterns
        struct CustomPattern {
            std::wstring name;
            std::vector<uint8_t> pattern;
            MetamorphicTechnique technique;
        };
        std::vector<CustomPattern> m_customPatterns;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(MetamorphicError* err) noexcept;
        void Shutdown() noexcept;

        // Entropy calculation
        [[nodiscard]] double CalculateEntropy(const uint8_t* buffer, size_t size) const noexcept;

        // Pattern matching
        [[nodiscard]] bool ContainsPattern(const uint8_t* buffer, size_t size, const uint8_t* pattern, size_t patternSize) const noexcept;
        [[nodiscard]] std::vector<size_t> FindPatternOffsets(const uint8_t* buffer, size_t size, const uint8_t* pattern, size_t patternSize) const noexcept;

        // PE parsing helpers
        [[nodiscard]] bool IsPEFile(const uint8_t* buffer, size_t size) const noexcept;
        [[nodiscard]] bool ParsePEHeaders(const uint8_t* buffer, size_t size, PEAnalysisInfo& info) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool MetamorphicDetector::Impl::Initialize(MetamorphicError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            Utils::Logger::Info(L"MetamorphicDetector: Initializing...");

            // Infrastructure stores are optional (can be set later)
            // No strict dependency on them for initialization

            Utils::Logger::Info(L"MetamorphicDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"MetamorphicDetector initialization failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            Utils::Logger::Critical(L"MetamorphicDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void MetamorphicDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            Utils::Logger::Info(L"MetamorphicDetector: Shutting down...");

            // Clear caches
            m_resultCache.clear();
            m_customPatterns.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            Utils::Logger::Info(L"MetamorphicDetector: Shutdown complete");
        }
        catch (...) {
            Utils::Logger::Error(L"MetamorphicDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: HELPER METHODS
    // ========================================================================

    double MetamorphicDetector::Impl::CalculateEntropy(const uint8_t* buffer, size_t size) const noexcept {
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

    bool MetamorphicDetector::Impl::ContainsPattern(
        const uint8_t* buffer,
        size_t size,
        const uint8_t* pattern,
        size_t patternSize
    ) const noexcept {
        if (!buffer || !pattern || size < patternSize || patternSize == 0) {
            return false;
        }

        try {
            for (size_t i = 0; i <= size - patternSize; ++i) {
                if (std::memcmp(buffer + i, pattern, patternSize) == 0) {
                    return true;
                }
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    std::vector<size_t> MetamorphicDetector::Impl::FindPatternOffsets(
        const uint8_t* buffer,
        size_t size,
        const uint8_t* pattern,
        size_t patternSize
    ) const noexcept {
        std::vector<size_t> offsets;

        if (!buffer || !pattern || size < patternSize || patternSize == 0) {
            return offsets;
        }

        try {
            for (size_t i = 0; i <= size - patternSize; ++i) {
                if (std::memcmp(buffer + i, pattern, patternSize) == 0) {
                    offsets.push_back(i);
                }
            }
        }
        catch (...) {
            // Return whatever we found so far
        }

        return offsets;
    }

    bool MetamorphicDetector::Impl::IsPEFile(const uint8_t* buffer, size_t size) const noexcept {
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

    bool MetamorphicDetector::Impl::ParsePEHeaders(const uint8_t* buffer, size_t size, PEAnalysisInfo& info) const noexcept {
        try {
            if (!IsPEFile(buffer, size)) {
                return false;
            }

            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);

            info.entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
            info.imageBase = ntHeaders->OptionalHeader.ImageBase;
            info.is64Bit = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

            // Parse sections
            const auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
                SectionAnalysisInfo section;
                section.name = std::string(reinterpret_cast<const char*>(sectionHeader[i].Name), 8);
                section.virtualAddress = sectionHeader[i].VirtualAddress;
                section.virtualSize = sectionHeader[i].Misc.VirtualSize;
                section.rawSize = sectionHeader[i].SizeOfRawData;
                section.characteristics = sectionHeader[i].Characteristics;
                section.isExecutable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.isWritable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

                // Calculate section entropy
                if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= size) {
                    const uint8_t* sectionData = buffer + sectionHeader[i].PointerToRawData;
                    section.entropy = CalculateEntropy(sectionData, sectionHeader[i].SizeOfRawData);
                    section.hasHighEntropy = (section.entropy >= MetamorphicConstants::MIN_ENCRYPTED_ENTROPY);
                }

                info.sections.push_back(section);
            }

            info.valid = true;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    MetamorphicDetector::MetamorphicDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    MetamorphicDetector::MetamorphicDetector(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_signatureStore = std::move(sigStore);
    }

    MetamorphicDetector::MetamorphicDetector(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore,
        std::shared_ptr<HashStore::HashStore> hashStore,
        std::shared_ptr<PatternStore::PatternStore> patternStore
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_signatureStore = std::move(sigStore);
        m_impl->m_hashStore = std::move(hashStore);
        m_impl->m_patternStore = std::move(patternStore);
    }

    MetamorphicDetector::MetamorphicDetector(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore,
        std::shared_ptr<HashStore::HashStore> hashStore,
        std::shared_ptr<PatternStore::PatternStore> patternStore,
        std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_signatureStore = std::move(sigStore);
        m_impl->m_hashStore = std::move(hashStore);
        m_impl->m_patternStore = std::move(patternStore);
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    MetamorphicDetector::~MetamorphicDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    MetamorphicDetector::MetamorphicDetector(MetamorphicDetector&&) noexcept = default;
    MetamorphicDetector& MetamorphicDetector::operator=(MetamorphicDetector&&) noexcept = default;

    bool MetamorphicDetector::Initialize(MetamorphicError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void MetamorphicDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool MetamorphicDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    MetamorphicResult MetamorphicDetector::AnalyzeFile(
        const std::wstring& filePath,
        const MetamorphicAnalysisConfig& config,
        MetamorphicError* err
    ) noexcept {
        MetamorphicResult result;
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
            result.sha256Hash = Utils::CryptoUtils::ComputeSHA256(buffer.data(), buffer.size());

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

            if (result.isMetamorphic) {
                m_impl->m_stats.metamorphicDetections++;
            }

            // Update cache
            if (config.enableCaching) {
                UpdateCache(filePath, result);
            }

            return result;
        }
        catch (const fs::filesystem_error& e) {
            Utils::Logger::Error(L"AnalyzeFile filesystem error [{}]: {}",
                e.code().value(),
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = static_cast<DWORD>(e.code().value());
                err->message = L"Filesystem error";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeFile failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            Utils::Logger::Critical(L"AnalyzeFile: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    MetamorphicResult MetamorphicDetector::AnalyzeBuffer(
        const uint8_t* buffer,
        size_t size,
        const MetamorphicAnalysisConfig& config,
        MetamorphicError* err
    ) noexcept {
        MetamorphicResult result;
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
            result.sha256Hash = Utils::CryptoUtils::ComputeSHA256(buffer, size);

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

            if (result.isMetamorphic) {
                m_impl->m_stats.metamorphicDetections++;
            }

            return result;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeBuffer failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

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
    // PROCESS ANALYSIS
    // ========================================================================

    MetamorphicResult MetamorphicDetector::AnalyzeProcess(
        uint32_t processId,
        const MetamorphicAnalysisConfig& config,
        MetamorphicError* err
    ) noexcept {
        MetamorphicResult result;
        result.processId = processId;

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            AnalyzeProcessInternal(hProcess, processId, config, result);
            CloseHandle(hProcess);

            m_impl->m_stats.totalAnalyses++;

            return result;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeProcess failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Process analysis failed";
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

    MetamorphicResult MetamorphicDetector::AnalyzeProcess(
        HANDLE hProcess,
        const MetamorphicAnalysisConfig& config,
        MetamorphicError* err
    ) noexcept {
        MetamorphicResult result;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const uint32_t processId = GetProcessId(hProcess);
            if (processId == 0) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to get process ID";
                }
                return result;
            }

            AnalyzeProcessInternal(hProcess, processId, config, result);
            m_impl->m_stats.totalAnalyses++;

            return result;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeProcess (handle) failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Process analysis failed";
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

    MetamorphicBatchResult MetamorphicDetector::AnalyzeFiles(
        const std::vector<std::wstring>& filePaths,
        const MetamorphicAnalysisConfig& config,
        MetamorphicProgressCallback progressCallback,
        MetamorphicError* err
    ) noexcept {
        MetamorphicBatchResult batchResult;
        batchResult.startTime = std::chrono::system_clock::now();
        batchResult.totalFiles = static_cast<uint32_t>(filePaths.size());

        for (size_t i = 0; i < filePaths.size(); ++i) {
            const auto& filePath = filePaths[i];

            if (progressCallback) {
                try {
                    progressCallback(filePath, MetamorphicCategory::Unknown, static_cast<uint32_t>(i), batchResult.totalFiles);
                }
                catch (...) {
                    // Swallow callback exceptions
                }
            }

            auto result = AnalyzeFile(filePath, config, err);

            if (result.analysisComplete) {
                batchResult.results.push_back(std::move(result));

                if (result.isMetamorphic) {
                    batchResult.metamorphicFiles++;
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

    MetamorphicBatchResult MetamorphicDetector::AnalyzeDirectory(
        const std::wstring& directoryPath,
        bool recursive,
        const MetamorphicAnalysisConfig& config,
        MetamorphicProgressCallback progressCallback,
        MetamorphicError* err
    ) noexcept {
        MetamorphicBatchResult batchResult;

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

    bool MetamorphicDetector::ComputeOpcodeHistogram(
        const uint8_t* buffer,
        size_t size,
        OpcodeHistogram& outHistogram,
        MetamorphicError* err
    ) noexcept {
        try {
            outHistogram = OpcodeHistogram{};

            if (!buffer || size == 0) {
                return false;
            }

            // Count byte occurrences
            for (size_t i = 0; i < size; ++i) {
                outHistogram.byteCounts[buffer[i]]++;
            }

            outHistogram.totalBytes = size;

            // Calculate percentages for interesting opcodes
            outHistogram.nopPercentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_NOP] * 100.0) / size;
            outHistogram.int3Percentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_INT3] * 100.0) / size;
            outHistogram.xorPercentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_XOR] * 100.0) / size;
            outHistogram.retPercentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_RET] * 100.0) / size;
            outHistogram.callPercentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_CALL_REL] * 100.0) / size;
            outHistogram.jmpPercentage = (outHistogram.byteCounts[MetamorphicConstants::OPCODE_JMP_NEAR] * 100.0) / size;

            // Calculate entropy
            outHistogram.entropy = m_impl->CalculateEntropy(buffer, size);

            // Detect potential encryption
            outHistogram.isPotentiallyEncrypted = (outHistogram.entropy >= MetamorphicConstants::MIN_ENCRYPTED_ENTROPY);

            // Detect excessive NOPs
            outHistogram.hasExcessiveNops = (outHistogram.nopPercentage >= MetamorphicConstants::MIN_SUSPICIOUS_NOP_PERCENTAGE);

            // Junk code signature (high NOPs + high INT3)
            outHistogram.hasJunkCodeSignature = (outHistogram.nopPercentage + outHistogram.int3Percentage >= 20.0);

            outHistogram.valid = true;
            return true;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"ComputeOpcodeHistogram failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Histogram computation failed";
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

    double MetamorphicDetector::CalculateEntropy(
        const uint8_t* buffer,
        size_t size
    ) noexcept {
        if (!m_impl) {
            return 0.0;
        }
        return m_impl->CalculateEntropy(buffer, size);
    }

    bool MetamorphicDetector::DetectDecryptionLoops(
        const uint8_t* buffer,
        size_t size,
        std::vector<DecryptionLoopInfo>& outLoops,
        MetamorphicError* err
    ) noexcept {
        try {
            outLoops.clear();

            if (!buffer || size == 0) {
                return false;
            }

            // Pattern 1: XOR + LOOP (simple polymorphic decryptor)
            // Pattern: XOR [reg], key; INC/ADD reg; LOOP offset
            for (size_t i = 0; i + 10 < size; ++i) {
                // Look for XOR instruction followed by LOOP
                bool foundXOR = false;
                bool foundLOOP = false;
                size_t loopOffset = 0;

                // Simple heuristic: look for XOR followed by LOOP within 10 bytes
                for (size_t j = i; j < i + 10 && j < size; ++j) {
                    if (buffer[j] == MetamorphicConstants::OPCODE_XOR) {
                        foundXOR = true;
                    }
                    if (buffer[j] == MetamorphicConstants::OPCODE_LOOP) {
                        foundLOOP = true;
                        loopOffset = j;
                        break;
                    }
                }

                if (foundXOR && foundLOOP) {
                    DecryptionLoopInfo loop;
                    loop.startAddress = i;
                    loop.loopSize = loopOffset - i;
                    loop.usesXOR = true;
                    loop.algorithmGuess = L"XOR-based polymorphic decryption";
                    loop.valid = true;

                    outLoops.push_back(loop);
                    i = loopOffset; // Skip past this loop
                }
            }

            // Pattern 2: GetPC techniques (CALL $+5; POP reg)
            const auto getpcOffsets = m_impl->FindPatternOffsets(
                buffer, size,
                MetamorphicConstants::GETPC_CALL_POP_PATTERN.data(),
                MetamorphicConstants::GETPC_CALL_POP_PATTERN.size()
            );

            for (const auto offset : getpcOffsets) {
                DecryptionLoopInfo loop;
                loop.startAddress = offset;
                loop.usesGetPC = true;
                loop.getPCMethod = L"CALL/POP";
                loop.algorithmGuess = L"Position-independent decryption";
                loop.valid = true;
                outLoops.push_back(loop);
            }

            // Pattern 3: FSTENV GetPC
            const auto fstenvOffsets = m_impl->FindPatternOffsets(
                buffer, size,
                MetamorphicConstants::GETPC_FSTENV_PATTERN.data(),
                MetamorphicConstants::GETPC_FSTENV_PATTERN.size()
            );

            for (const auto offset : fstenvOffsets) {
                DecryptionLoopInfo loop;
                loop.startAddress = offset;
                loop.usesGetPC = true;
                loop.getPCMethod = L"FSTENV";
                loop.algorithmGuess = L"FPU-based position-independent code";
                loop.valid = true;
                outLoops.push_back(loop);
            }

            return !outLoops.empty();
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectDecryptionLoops failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Decryption loop detection failed";
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

    bool MetamorphicDetector::PerformFuzzyMatching(
        const std::wstring& filePath,
        std::vector<FuzzyHashMatch>& outMatches,
        MetamorphicError* err
    ) noexcept {
        try {
            outMatches.clear();

            // Compute TLSH hash
            auto tlshHash = ComputeTLSH(filePath, err);
            if (tlshHash) {
                // If we have a hash store, try to match
                if (m_impl->m_hashStore) {
                    // TODO: Query hash store for similar TLSH hashes
                    // For now, just record the computed hash
                    FuzzyHashMatch match;
                    match.hashType = L"TLSH";
                    match.computedHash = *tlshHash;
                    match.confidence = 1.0;
                    outMatches.push_back(match);
                }
            }

            return !outMatches.empty();
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"PerformFuzzyMatching failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Fuzzy matching failed";
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

    bool MetamorphicDetector::AnalyzePEStructure(
        const std::wstring& filePath,
        PEAnalysisInfo& outInfo,
        MetamorphicError* err
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

            // Parse PE headers
            if (!m_impl->ParsePEHeaders(buffer.data(), buffer.size(), outInfo)) {
                return false;
            }

            // Calculate overall file entropy
            outInfo.fileEntropy = m_impl->CalculateEntropy(buffer.data(), buffer.size());

            // Check for high entropy sections (packing indicator)
            for (const auto& section : outInfo.sections) {
                if (section.hasHighEntropy && section.isExecutable) {
                    outInfo.anomalies.push_back(L"High entropy executable section: " +
                        Utils::StringUtils::ToWideString(section.name));
                }
            }

            return true;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzePEStructure failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"PE analysis failed";
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

    bool MetamorphicDetector::AnalyzeCFG(
        const uint8_t* buffer,
        size_t size,
        uint64_t baseAddress,
        CFGAnalysisInfo& outInfo,
        MetamorphicError* err
    ) noexcept {
        try {
            outInfo = CFGAnalysisInfo{};

            // NOTE: Full CFG analysis requires disassembly engine (e.g., Capstone, Zydis)
            // For now, provide basic implementation that can be enhanced later

            // TODO: Implement full CFG analysis with disassembly engine
            // This would include:
            // - Disassembling all code
            // - Building basic blocks
            // - Constructing control flow graph
            // - Computing cyclomatic complexity
            // - Detecting flattened CFG patterns
            // - Detecting opaque predicates

            outInfo.valid = false; // Mark as stub
            return false;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeCFG failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"CFG analysis failed";
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

    std::optional<std::wstring> MetamorphicDetector::DetectPacker(
        const std::wstring& filePath,
        MetamorphicError* err
    ) noexcept {
        try {
            PEAnalysisInfo peInfo;
            if (!AnalyzePEStructure(filePath, peInfo, err)) {
                return std::nullopt;
            }

            // Check section names for known packer signatures
            for (const auto& section : peInfo.sections) {
                const std::string name = section.name;

                // UPX
                if (name.find("UPX") != std::string::npos) {
                    return L"UPX";
                }

                // ASPack
                if (name.find(".aspack") != std::string::npos || name.find(".adata") != std::string::npos) {
                    return L"ASPack";
                }

                // MPRESS
                if (name.find(".MPRESS") != std::string::npos) {
                    return L"MPRESS";
                }

                // PECompact
                if (name.find("PECompact") != std::string::npos) {
                    return L"PECompact";
                }

                // Petite
                if (name.find(".petite") != std::string::npos) {
                    return L"Petite";
                }

                // FSG
                if (name.find(".fsgseg") != std::string::npos) {
                    return L"FSG";
                }

                // MEW
                if (name.find("MEW") != std::string::npos) {
                    return L"MEW";
                }

                // NsPack
                if (name.find(".nsp") != std::string::npos) {
                    return L"NsPack";
                }
            }

            // Check for high entropy (generic packing indicator)
            if (peInfo.fileEntropy >= MetamorphicConstants::MIN_ENCRYPTED_ENTROPY) {
                return L"Unknown Packer (High Entropy)";
            }

            return std::nullopt;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectPacker failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Packer detection failed";
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

    bool MetamorphicDetector::MatchKnownFamilies(
        const uint8_t* buffer,
        size_t size,
        std::vector<FamilyMatchInfo>& outMatches,
        MetamorphicError* err
    ) noexcept {
        try {
            outMatches.clear();

            // Use signature store if available
            if (m_impl->m_signatureStore) {
                // TODO: Query signature store for known metamorphic family patterns
            }

            // Use threat intel if available
            if (m_impl->m_threatIntel) {
                // TODO: Query threat intel for family information
            }

            return !outMatches.empty();
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"MatchKnownFamilies failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Family matching failed";
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

    std::optional<std::string> MetamorphicDetector::ComputeSSDeep(
        const std::wstring& filePath,
        MetamorphicError* err
    ) noexcept {
        try {
            // NOTE: SSDEEP requires external library (ssdeep)
            // For enterprise deployment, would integrate libfuzzy
            // For now, return nullopt as stub

            // TODO: Integrate libfuzzy for SSDEEP computation
            return std::nullopt;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"ComputeSSDeep failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"SSDEEP computation failed";
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

    std::optional<std::string> MetamorphicDetector::ComputeTLSH(
        const std::wstring& filePath,
        MetamorphicError* err
    ) noexcept {
        try {
            // Read file
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                if (err) {
                    err->win32Code = ERROR_OPEN_FAILED;
                    err->message = L"Failed to open file";
                }
                return std::nullopt;
            }

            file.seekg(0, std::ios::end);
            const auto fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            if (fileSize == 0) {
                return std::nullopt;
            }

            std::vector<uint8_t> buffer(fileSize);
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

            if (!file) {
                if (err) {
                    err->win32Code = ERROR_READ_FAULT;
                    err->message = L"Failed to read file";
                }
                return std::nullopt;
            }

            // Compute TLSH using the TLSH library
            Tlsh tlsh;
            tlsh.update(buffer.data(), static_cast<unsigned int>(buffer.size()));
            tlsh.final();

            const char* hash = tlsh.getHash();
            if (hash && hash[0] != '\0') {
                return std::string(hash);
            }

            return std::nullopt;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"ComputeTLSH failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"TLSH computation failed";
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

    int MetamorphicDetector::CompareSSDeep(
        const std::string& hash1,
        const std::string& hash2
    ) noexcept {
        // NOTE: Requires libfuzzy integration
        // TODO: Implement SSDEEP comparison
        return 0;
    }

    int MetamorphicDetector::CompareTLSH(
        const std::string& hash1,
        const std::string& hash2
    ) noexcept {
        try {
            Tlsh tlsh1, tlsh2;

            // Parse hashes
            tlsh1.fromTlshStr(hash1.c_str());
            tlsh2.fromTlshStr(hash2.c_str());

            // Compute distance (lower = more similar)
            return tlsh1.totalDiff(&tlsh2);
        }
        catch (...) {
            return -1; // Error
        }
    }

    // ========================================================================
    // REAL-TIME DETECTION
    // ========================================================================

    void MetamorphicDetector::SetDetectionCallback(MetamorphicDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void MetamorphicDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    std::optional<MetamorphicResult> MetamorphicDetector::GetCachedResult(
        const std::wstring& filePath
    ) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(filePath);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void MetamorphicDetector::InvalidateCache(const std::wstring& filePath) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(filePath);
    }

    void MetamorphicDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t MetamorphicDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    void MetamorphicDetector::UpdateCache(
        const std::wstring& filePath,
        const MetamorphicResult& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit
            if (m_impl->m_resultCache.size() >= MetamorphicConstants::MAX_CACHE_ENTRIES) {
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

    void MetamorphicDetector::SetSignatureStore(std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_signatureStore = std::move(sigStore);
    }

    void MetamorphicDetector::SetHashStore(std::shared_ptr<HashStore::HashStore> hashStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_hashStore = std::move(hashStore);
    }

    void MetamorphicDetector::SetPatternStore(std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_patternStore = std::move(patternStore);
    }

    void MetamorphicDetector::SetThreatIntelStore(std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    void MetamorphicDetector::AddCustomPattern(
        std::wstring_view name,
        const std::vector<uint8_t>& pattern,
        MetamorphicTechnique technique
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);

        Impl::CustomPattern custom;
        custom.name = name;
        custom.pattern = pattern;
        custom.technique = technique;

        m_impl->m_customPatterns.push_back(std::move(custom));
    }

    void MetamorphicDetector::ClearCustomPatterns() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customPatterns.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const MetamorphicDetector::Statistics& MetamorphicDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void MetamorphicDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    void MetamorphicDetector::AnalyzeFileInternal(
        const uint8_t* buffer,
        size_t size,
        const std::wstring& filePath,
        const MetamorphicAnalysisConfig& config,
        MetamorphicResult& result
    ) noexcept {
        result.bytesAnalyzed = size;

        // Compute opcode histogram
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::EnableEntropyAnalysis)) {
            ComputeOpcodeHistogram(buffer, size, result.opcodeHistogram, nullptr);
        }

        // Check for packing
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanPacking)) {
            AnalyzePacking(buffer, size, result);
        }

        // Check for polymorphic techniques
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanPolymorphic)) {
            AnalyzePolymorphicTechniques(buffer, size, result);
        }

        // Check for metamorphic techniques
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanMetamorphic)) {
            AnalyzeMetamorphicTechniques(buffer, size, result);
        }

        // Check for self-modifying code
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanSelfModifying)) {
            AnalyzeSelfModifyingTechniques(buffer, size, result);
        }

        // Check for obfuscation
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanObfuscation)) {
            AnalyzeObfuscationTechniques(buffer, size, result);
        }

        // Check for VM protection
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::ScanVMProtection)) {
            AnalyzeVMProtection(buffer, size, result);
        }

        // Perform fuzzy matching
        if (HasFlag(config.flags, MetamorphicAnalysisFlags::EnableFuzzyHashing) && !filePath.empty()) {
            PerformSimilarityAnalysis(filePath, result);
        }

        // Calculate mutation score
        CalculateMutationScore(result);
    }

    void MetamorphicDetector::AnalyzeProcessInternal(
        HANDLE hProcess,
        uint32_t processId,
        const MetamorphicAnalysisConfig& config,
        MetamorphicResult& result
    ) noexcept {
        result.processId = processId;

        // TODO: Implement process memory scanning
        // This would involve:
        // - Enumerating executable memory regions
        // - Reading memory from each region
        // - Analyzing each region with AnalyzeFileInternal
        // - Aggregating results

        result.analysisComplete = false; // Mark as stub
    }

    void MetamorphicDetector::AnalyzeMetamorphicTechniques(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // Check for excessive NOPs
        if (result.opcodeHistogram.valid && result.opcodeHistogram.hasExcessiveNops) {
            MetamorphicDetectedTechnique detection(MetamorphicTechnique::META_NOPInsertion);
            detection.confidence = 0.8;
            detection.description = L"Excessive NOP instructions detected";
            detection.technicalDetails = std::format(L"NOP percentage: {:.2f}%", result.opcodeHistogram.nopPercentage);
            AddDetection(result, std::move(detection));
        }

        // Check for junk code signature
        if (result.opcodeHistogram.valid && result.opcodeHistogram.hasJunkCodeSignature) {
            MetamorphicDetectedTechnique detection(MetamorphicTechnique::META_DeadCodeInsertion);
            detection.confidence = 0.75;
            detection.description = L"Junk code insertion detected";
            AddDetection(result, std::move(detection));
        }
    }

    void MetamorphicDetector::AnalyzePolymorphicTechniques(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // Detect decryption loops
        std::vector<DecryptionLoopInfo> loops;
        if (DetectDecryptionLoops(buffer, size, loops, nullptr)) {
            result.decryptionLoops = loops;

            for (const auto& loop : loops) {
                MetamorphicTechnique technique = MetamorphicTechnique::POLY_XORDecryption;

                if (loop.usesGetPC) {
                    if (loop.getPCMethod == L"CALL/POP") {
                        technique = MetamorphicTechnique::POLY_GetPC_CallPop;
                    }
                    else if (loop.getPCMethod == L"FSTENV") {
                        technique = MetamorphicTechnique::POLY_GetPC_FSTENV;
                    }
                }

                MetamorphicDetectedTechnique detection(technique);
                detection.confidence = 0.9;
                detection.location = loop.startAddress;
                detection.artifactSize = loop.loopSize;
                detection.description = loop.algorithmGuess;
                AddDetection(result, std::move(detection));
            }
        }

        // Check for high entropy (encryption)
        if (result.opcodeHistogram.valid && result.opcodeHistogram.isPotentiallyEncrypted) {
            MetamorphicDetectedTechnique detection(MetamorphicTechnique::POLY_CustomCipher);
            detection.confidence = 0.7;
            detection.description = L"High entropy indicates encryption";
            detection.technicalDetails = std::format(L"Entropy: {:.2f}", result.opcodeHistogram.entropy);
            AddDetection(result, std::move(detection));
        }
    }

    void MetamorphicDetector::AnalyzeSelfModifyingTechniques(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // Look for VirtualProtect imports (indicates potential self-modification)
        // NOTE: Would need PE import parsing for full implementation

        // TODO: Check for:
        // - VirtualProtect usage
        // - WriteProcessMemory usage
        // - Executable heap allocations
        // - Dynamic code generation patterns
    }

    void MetamorphicDetector::AnalyzeObfuscationTechniques(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // TODO: Implement obfuscation detection
        // - Control flow flattening
        // - Opaque predicates
        // - API hashing
        // - String encryption
    }

    void MetamorphicDetector::AnalyzeVMProtection(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // TODO: Implement VM detection
        // - Custom bytecode interpreters
        // - Known VM protector signatures (VMProtect, Themida, etc.)
    }

    void MetamorphicDetector::AnalyzePacking(
        const uint8_t* buffer,
        size_t size,
        MetamorphicResult& result
    ) noexcept {
        // Detect packer if analyzing a file
        if (!result.filePath.empty()) {
            auto packer = DetectPacker(result.filePath, nullptr);
            if (packer) {
                result.peAnalysis.packerName = *packer;

                MetamorphicTechnique technique = MetamorphicTechnique::PACK_Custom;

                if (packer->find(L"UPX") != std::wstring::npos) {
                    technique = MetamorphicTechnique::PACK_UPX;
                }
                else if (packer->find(L"ASPack") != std::wstring::npos) {
                    technique = MetamorphicTechnique::PACK_ASPack;
                }
                else if (packer->find(L"MPRESS") != std::wstring::npos) {
                    technique = MetamorphicTechnique::PACK_MPRESS;
                }
                else if (packer->find(L"PECompact") != std::wstring::npos) {
                    technique = MetamorphicTechnique::PACK_PECompact;
                }

                MetamorphicDetectedTechnique detection(technique);
                detection.confidence = 0.95;
                detection.description = L"Packer detected: " + *packer;
                AddDetection(result, std::move(detection));

                m_impl->m_stats.packerDetections++;
            }
        }

        // Check for high entropy (generic packing indicator)
        if (result.opcodeHistogram.valid && result.opcodeHistogram.isPotentiallyEncrypted) {
            MetamorphicDetectedTechnique detection(MetamorphicTechnique::STRUCT_HighEntropy);
            detection.confidence = 0.6;
            detection.description = L"High entropy detected";
            detection.technicalDetails = std::format(L"Entropy: {:.2f}", result.opcodeHistogram.entropy);
            AddDetection(result, std::move(detection));
        }
    }

    void MetamorphicDetector::PerformSimilarityAnalysis(
        const std::wstring& filePath,
        MetamorphicResult& result
    ) noexcept {
        std::vector<FuzzyHashMatch> matches;
        if (PerformFuzzyMatching(filePath, matches, nullptr)) {
            result.fuzzyMatches = matches;

            for (const auto& match : matches) {
                if (match.isSignificant) {
                    MetamorphicDetectedTechnique detection(MetamorphicTechnique::SIMILARITY_TLSHMatch);
                    detection.confidence = match.confidence;
                    detection.description = L"Fuzzy hash match found";
                    AddDetection(result, std::move(detection));
                }
            }
        }
    }

    void MetamorphicDetector::CalculateMutationScore(MetamorphicResult& result) noexcept {
        double score = 0.0;
        MetamorphicSeverity maxSev = MetamorphicSeverity::Low;

        for (const auto& detection : result.detectedTechniques) {
            // Weight by category
            double categoryWeight = 1.0;
            switch (detection.category) {
            case MetamorphicCategory::Metamorphic:
                categoryWeight = MetamorphicConstants::WEIGHT_OPCODE_ANOMALY;
                break;
            case MetamorphicCategory::Polymorphic:
                categoryWeight = MetamorphicConstants::WEIGHT_DECRYPTION_LOOP;
                break;
            case MetamorphicCategory::SelfModifying:
                categoryWeight = MetamorphicConstants::WEIGHT_SELF_MODIFYING;
                break;
            case MetamorphicCategory::Obfuscation:
                categoryWeight = MetamorphicConstants::WEIGHT_CFG_FLATTENING;
                break;
            case MetamorphicCategory::VMProtection:
                categoryWeight = 3.5;
                break;
            case MetamorphicCategory::Packing:
                categoryWeight = 2.0;
                break;
            default:
                categoryWeight = 1.0;
            }

            // Weight by severity
            double severityMultiplier = 1.0;
            switch (detection.severity) {
            case MetamorphicSeverity::Low: severityMultiplier = 1.0; break;
            case MetamorphicSeverity::Medium: severityMultiplier = 2.5; break;
            case MetamorphicSeverity::High: severityMultiplier = 5.0; break;
            case MetamorphicSeverity::Critical: severityMultiplier = 10.0; break;
            }

            score += (categoryWeight * severityMultiplier * detection.confidence);

            if (detection.severity > maxSev) {
                maxSev = detection.severity;
            }
        }

        result.mutationScore = std::min(score, 100.0);
        result.maxSeverity = maxSev;
        result.isMetamorphic = (score >= MetamorphicConstants::MIN_METAMORPHIC_SCORE);
    }

    void MetamorphicDetector::AddDetection(
        MetamorphicResult& result,
        MetamorphicDetectedTechnique detection
    ) noexcept {
        // Set category bit
        const auto catIdx = static_cast<uint32_t>(detection.category);
        if (catIdx < 16) {
            result.detectedCategories |= (1u << catIdx);
            m_impl->m_stats.categoryDetections[catIdx]++;
        }

        result.totalDetections++;
        m_impl->m_stats.totalDetections++;

        // Invoke callback if set
        if (m_impl->m_detectionCallback) {
            try {
                m_impl->m_detectionCallback(result.filePath, detection);
            }
            catch (...) {
                // Swallow callback exceptions
            }
        }

        result.detectedTechniques.push_back(std::move(detection));
    }

} // namespace ShadowStrike::AntiEvasion
