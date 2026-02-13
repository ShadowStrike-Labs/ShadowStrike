/**
 * @file MetamorphicDetector.hpp
 * @brief Enterprise-grade detection of metamorphic, polymorphic, and self-modifying code
 *
 * ShadowStrike AntiEvasion - Metamorphic Code Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module provides comprehensive detection of code that mutates itself to
 * evade signature-based detection. It detects sophisticated malware engines
 * including:
 *
 * METAMORPHIC DETECTION:
 * - Opcode histogram analysis (statistical anomaly detection)
 * - Control Flow Graph (CFG) analysis and flattening detection
 * - Dead code and junk instruction insertion detection
 * - Instruction substitution patterns (equivalent instruction sequences)
 * - Register reassignment/renaming detection
 * - Code transposition/reordering detection
 * - Subroutine reordering and permutation
 * - Variable renaming and data structure mutation
 *
 * POLYMORPHIC DETECTION:
 * - Decryption loop/stub identification
 * - GetPC (Get Program Counter) techniques detection
 * - Encryption layer analysis
 * - Variable key detection
 * - Shellcode decoder patterns
 * - Custom encoder/decoder detection
 * - Anti-emulation triggers in decryptors
 *
 * SELF-MODIFYING CODE:
 * - Runtime code generation detection
 * - JIT compilation artifacts
 * - VirtualProtect/VirtualAlloc pattern analysis
 * - WriteProcessMemory self-modification
 * - Executable heap detection
 * - Dynamic code patching
 *
 * CODE OBFUSCATION:
 * - Opaque predicates detection
 * - Control flow flattening
 * - Virtual machine (VM) based obfuscation
 * - Code virtualization detection
 * - Mixed boolean-arithmetic (MBA) expressions
 * - Stack-based obfuscation
 * - Anti-disassembly tricks
 *
 * SIMILARITY ANALYSIS:
 * - Fuzzy hashing (CTPH, TLSH, LZJD, Nilsimsa)
 * - Function-level similarity
 * - Basic block similarity
 * - Structural similarity (CFG/PDG comparison)
 * - N-gram analysis
 * - Mnemonic sequence matching
 *
 * ============================================================================
 * KNOWN MALWARE FAMILY DETECTION
 * ============================================================================
 *
 * Detects engines from known metamorphic malware families:
 * - Simile (W32/Simile) - Advanced metamorphic techniques
 * - Zmist (Z0mbie.Mistfall) - Entry point obscuration
 * - Regswap - Register reassignment
 * - Evol - Evolutionary mutation
 * - MetaPHOR - Full metamorphism
 * - Win32.Polip - Polymorphic infector
 * - Virut - Polymorphic file infector
 * - Sality - Polymorphic virus
 * - Conficker - Polymorphic worm
 * - ZeuS/Zbot - Polymorphic banking trojan
 * - Emotet - Polymorphic loader
 * - TrickBot - Modular polymorphic trojan
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - File analysis (1MB): < 100ms
 * - Process memory scan: < 200ms
 * - Fuzzy hash computation: < 50ms
 * - CFG extraction (100KB code): < 150ms
 * - Opcode histogram: < 20ms
 * - Batch analysis (100 files): < 5 seconds
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - SignatureStore - Pattern matching for known engines
 * - HashStore - CTPH/TLSH fuzzy matching
 * - PatternStore - Aho-Corasick for decoder patterns
 * - ProcessUtils - Memory reading for process analysis
 * - ThreatIntel - Family correlation and reputation
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1027: Obfuscated Files or Information
 * - T1027.001: Binary Padding
 * - T1027.002: Software Packing
 * - T1027.003: Steganography
 * - T1027.004: Compile After Delivery
 * - T1027.005: Indicator Removal from Tools
 * - T1140: Deobfuscate/Decode Files or Information
 * - T1620: Reflective Code Loading
 *
 * ============================================================================
 * ACADEMIC REFERENCES
 * ============================================================================
 *
 * - "Hunting for Metamorphic Engines" - Szor & Ferrie (Virus Bulletin 2001)
 * - "Metamorphism in Practice" - Igor Muttik (Virus Bulletin 2000)
 * - "The Art of Computer Virus Research and Defense" - Peter Szor
 * - "Analysis of Machine Code Similarity" - Kornblum (Digital Investigation 2006)
 *
 * ============================================================================
 */

#pragma once

 // ============================================================================
 // STANDARD LIBRARY INCLUDES
 // ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <bitset>
#include <span>
#include <variant>
#include <tuple>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"

// Forward declarations
namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace MetamorphicConstants {

            // ========================================================================
            // RESOURCE LIMITS
            // ========================================================================

            /// @brief Maximum file size to analyze (100 MB)
            inline constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;

            /// @brief Maximum code section size for detailed analysis (10 MB)
            inline constexpr size_t MAX_CODE_SECTION_SIZE = 10 * 1024 * 1024;

            /// @brief Maximum basic blocks to analyze per function
            inline constexpr size_t MAX_BASIC_BLOCKS_PER_FUNCTION = 10000;

            /// @brief Maximum functions to analyze
            inline constexpr size_t MAX_FUNCTIONS_TO_ANALYZE = 50000;

            /// @brief Maximum instructions to disassemble
            inline constexpr size_t MAX_INSTRUCTIONS = 10000000;

            /// @brief Default scan timeout (milliseconds)
            inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 60000;

            /// @brief Memory buffer size for process scanning
            inline constexpr size_t PROCESS_SCAN_BUFFER_SIZE = 4 * 1024 * 1024;

            /// @brief Cache entry TTL (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 300;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 4096;

            // ========================================================================
            // DETECTION THRESHOLDS
            // ========================================================================

            /// @brief Minimum entropy for encrypted/compressed code (7.0 typical for encryption)
            inline constexpr double MIN_ENCRYPTED_ENTROPY = 6.5;

            /// @brief Maximum entropy indicating truly random (limit for structured data)
            inline constexpr double MAX_STRUCTURED_ENTROPY = 7.9;

            /// @brief Minimum NOP percentage indicating junk code insertion
            /// FP FIX: Raised from 15% to 25% - legitimate code alignment can have 20%
            /// Visual C++ Release builds with /O2 can have 18-22% NOP for alignment
            inline constexpr double MIN_SUSPICIOUS_NOP_PERCENTAGE = 25.0;

            /// @brief Minimum dead code percentage for metamorphic detection
            inline constexpr double MIN_SUSPICIOUS_DEAD_CODE_PERCENTAGE = 20.0;

            /// @brief Minimum instruction substitution ratio
            inline constexpr double MIN_SUBSTITUTION_RATIO = 0.1;

            /// @brief Maximum legitimate decryption loop size
            inline constexpr size_t MAX_DECRYPTION_LOOP_SIZE = 512;

            /// @brief Minimum metamorphic score for classification (0-100)
            inline constexpr double MIN_METAMORPHIC_SCORE = 50.0;

            /// @brief High metamorphic score threshold
            inline constexpr double HIGH_METAMORPHIC_THRESHOLD = 75.0;

            /// @brief Critical metamorphic score threshold
            inline constexpr double CRITICAL_METAMORPHIC_THRESHOLD = 90.0;

            /// @brief Fuzzy hash similarity threshold for variant matching (0-100)
            inline constexpr int FUZZY_SIMILARITY_THRESHOLD = 30;

            /// @brief TLSH distance threshold (lower = more similar)
            inline constexpr int TLSH_DISTANCE_THRESHOLD = 150;

            // ========================================================================
            // SCORING WEIGHTS
            // ========================================================================

            /// @brief Weight for opcode anomalies
            inline constexpr double WEIGHT_OPCODE_ANOMALY = 2.0;

            /// @brief Weight for decryption loop detection
            inline constexpr double WEIGHT_DECRYPTION_LOOP = 3.0;

            /// @brief Weight for GetPC techniques
            inline constexpr double WEIGHT_GETPC_TECHNIQUE = 2.5;

            /// @brief Weight for instruction substitution
            inline constexpr double WEIGHT_INSTRUCTION_SUBSTITUTION = 2.0;

            /// @brief Weight for dead code insertion
            inline constexpr double WEIGHT_DEAD_CODE = 1.5;

            /// @brief Weight for CFG flattening
            inline constexpr double WEIGHT_CFG_FLATTENING = 3.0;

            /// @brief Weight for register reassignment
            inline constexpr double WEIGHT_REGISTER_REASSIGNMENT = 1.8;

            /// @brief Weight for code transposition
            inline constexpr double WEIGHT_CODE_TRANSPOSITION = 2.2;

            /// @brief Weight for self-modifying code
            inline constexpr double WEIGHT_SELF_MODIFYING = 3.5;

            /// @brief Weight for known family match
            inline constexpr double WEIGHT_FAMILY_MATCH = 4.0;

            /// @brief Weight for fuzzy hash match
            inline constexpr double WEIGHT_FUZZY_MATCH = 3.0;

            // ========================================================================
            // X86/X64 OPCODE CONSTANTS
            // ========================================================================

            /// @brief NOP opcode
            inline constexpr uint8_t OPCODE_NOP = 0x90;

            /// @brief INT3 opcode (breakpoint)
            inline constexpr uint8_t OPCODE_INT3 = 0xCC;

            /// @brief RET opcode
            inline constexpr uint8_t OPCODE_RET = 0xC3;

            /// @brief RETN opcode
            inline constexpr uint8_t OPCODE_RETN = 0xC2;

            /// @brief CALL relative opcode
            inline constexpr uint8_t OPCODE_CALL_REL = 0xE8;

            /// @brief JMP relative short opcode
            inline constexpr uint8_t OPCODE_JMP_SHORT = 0xEB;

            /// @brief JMP relative near opcode
            inline constexpr uint8_t OPCODE_JMP_NEAR = 0xE9;

            /// @brief XOR opcode (common in decryption)
            inline constexpr uint8_t OPCODE_XOR = 0x31; // XOR r/m32, r32

            /// @brief LOOP opcode
            inline constexpr uint8_t OPCODE_LOOP = 0xE2;

            /// @brief Two-byte opcode prefix
            inline constexpr uint8_t OPCODE_TWO_BYTE_PREFIX = 0x0F;

            // ========================================================================
            // KNOWN METAMORPHIC ENGINE PATTERNS
            // ========================================================================

            /// @brief Known metamorphic engine names for family identification
            inline constexpr std::array<std::wstring_view, 24> KNOWN_METAMORPHIC_FAMILIES = { {
                L"Simile", L"Zmist", L"Regswap", L"Evol", L"MetaPHOR",
                L"Win32.Polip", L"Virut", L"Sality", L"Conficker", L"Ramnit",
                L"ZeuS", L"Zbot", L"SpyEye", L"Citadel", L"Carberp",
                L"Emotet", L"TrickBot", L"Dridex", L"QakBot", L"IcedID",
                L"Ursnif", L"Gozi", L"Nymaim", L"Hancitor"
            } };

            /// @brief Common GetPC techniques (patterns for detection)
            /// CALL $+5; POP reg pattern
            inline constexpr std::array<uint8_t, 6> GETPC_CALL_POP_PATTERN = {
                0xE8, 0x00, 0x00, 0x00, 0x00,  // CALL $+5
                0x58                            // POP EAX (or other reg: 0x59=ECX, 0x5A=EDX, etc.)
            };

            /// @brief FSTENV GetPC pattern
            inline constexpr std::array<uint8_t, 5> GETPC_FSTENV_PATTERN = {
                0xD9, 0x74, 0x24, 0xF4,  // FSTENV [ESP-0Ch]
                0x5B                     // POP EBX (get FPU IP)
            };

        } // namespace MetamorphicConstants

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Categories of metamorphic/polymorphic techniques
         */
        enum class MetamorphicCategory : uint8_t {
            /// @brief Classic metamorphic (code mutation)
            Metamorphic = 0,

            /// @brief Polymorphic (encryption-based)
            Polymorphic = 1,

            /// @brief Self-modifying at runtime
            SelfModifying = 2,

            /// @brief Code obfuscation
            Obfuscation = 3,

            /// @brief Virtual machine based protection
            VMProtection = 4,

            /// @brief Packing/compression
            Packing = 5,

            /// @brief Code generation/JIT
            CodeGeneration = 6,

            /// @brief Instruction-level mutation
            InstructionMutation = 7,

            /// @brief Control flow mutation
            ControlFlowMutation = 8,

            /// @brief Data mutation
            DataMutation = 9,

            /// @brief Combined techniques
            Combined = 10,

            /// @brief Unknown
            Unknown = 255
        };

        /**
         * @brief Specific metamorphic technique identifiers
         */
        enum class MetamorphicTechnique : uint16_t {
            /// @brief No technique detected
            None = 0,

            // ========================================================================
            // METAMORPHIC TECHNIQUES (1-50)
            // ========================================================================

            /// @brief Excessive NOP insertion
            META_NOPInsertion = 1,

            /// @brief Dead code/junk instruction insertion
            META_DeadCodeInsertion = 2,

            /// @brief Equivalent instruction substitution
            META_InstructionSubstitution = 3,

            /// @brief Register reassignment/renaming
            META_RegisterReassignment = 4,

            /// @brief Code transposition (reordering)
            META_CodeTransposition = 5,

            /// @brief Subroutine reordering
            META_SubroutineReordering = 6,

            /// @brief Instruction permutation
            META_InstructionPermutation = 7,

            /// @brief Variable/data renaming
            META_VariableRenaming = 8,

            /// @brief Code expansion (single to multiple instructions)
            META_CodeExpansion = 9,

            /// @brief Code shrinking (multiple to single)
            META_CodeShrinking = 10,

            /// @brief Garbage byte insertion
            META_GarbageBytes = 11,

            /// @brief Opaque predicates
            META_OpaquePredicates = 12,

            /// @brief Branch function insertion
            META_BranchFunctions = 13,

            /// @brief Interleaved code blocks
            META_InterleavedCode = 14,

            /// @brief Subroutine inlining variation
            META_InliningVariation = 15,

            /// @brief Random padding
            META_RandomPadding = 16,

            /// @brief Instruction splitting
            META_InstructionSplitting = 17,

            /// @brief Instruction merging
            META_InstructionMerging = 18,

            /// @brief Stack operation substitution
            META_StackSubstitution = 19,

            /// @brief Arithmetic substitution
            META_ArithmeticSubstitution = 20,

            // ========================================================================
            // POLYMORPHIC TECHNIQUES (51-100)
            // ========================================================================

            /// @brief XOR-based decryption loop
            POLY_XORDecryption = 51,

            /// @brief ADD/SUB based decryption
            POLY_ADDSUBDecryption = 52,

            /// @brief ROL/ROR based decryption
            POLY_ROLRORDecryption = 53,

            /// @brief Multi-layer encryption
            POLY_MultiLayerEncryption = 54,

            /// @brief Variable key encryption
            POLY_VariableKey = 55,

            /// @brief Key derivation from environment
            POLY_EnvironmentKey = 56,

            /// @brief GetPC via CALL/POP
            POLY_GetPC_CallPop = 57,

            /// @brief GetPC via FSTENV
            POLY_GetPC_FSTENV = 58,

            /// @brief GetPC via SEH
            POLY_GetPC_SEH = 59,

            /// @brief GetPC via CALL [mem]
            POLY_GetPC_CallMem = 60,

            /// @brief Decoder stub mutation
            POLY_DecoderMutation = 61,

            /// @brief Shellcode encoder/decoder
            POLY_ShellcodeEncoder = 62,

            /// @brief RC4 decryption
            POLY_RC4Decryption = 63,

            /// @brief AES decryption stub
            POLY_AESDecryption = 64,

            /// @brief Custom cipher implementation
            POLY_CustomCipher = 65,

            /// @brief Anti-emulation in decryptor
            POLY_AntiEmulation = 66,

            /// @brief Incremental decryption
            POLY_IncrementalDecryption = 67,

            /// @brief Staged decryption
            POLY_StagedDecryption = 68,

            // ========================================================================
            // SELF-MODIFYING TECHNIQUES (101-130)
            // ========================================================================

            /// @brief VirtualProtect for code modification
            SELF_VirtualProtect = 101,

            /// @brief WriteProcessMemory self-write
            SELF_WriteProcessMemory = 102,

            /// @brief NtProtectVirtualMemory usage
            SELF_NtProtectVirtualMemory = 103,

            /// @brief Executable heap allocation
            SELF_ExecutableHeap = 104,

            /// @brief Dynamic code generation
            SELF_DynamicCodeGen = 105,

            /// @brief JIT-style code emission
            SELF_JITEmission = 106,

            /// @brief Runtime patching
            SELF_RuntimePatching = 107,

            /// @brief Import table modification
            SELF_ImportTableMod = 108,

            /// @brief Exception handler modification
            SELF_ExceptionHandlerMod = 109,

            /// @brief TLS callback modification
            SELF_TLSCallbackMod = 110,

            /// @brief Relocation abuse
            SELF_RelocationAbuse = 111,

            /// @brief Delay-load exploitation
            SELF_DelayLoadExploit = 112,

            // ========================================================================
            // OBFUSCATION TECHNIQUES (131-170)
            // ========================================================================

            /// @brief Control flow flattening
            OBF_ControlFlowFlattening = 131,

            /// @brief Dispatcher-based obfuscation
            OBF_Dispatcher = 132,

            /// @brief State machine obfuscation
            OBF_StateMachine = 133,

            /// @brief Opaque predicates (always true/false)
            OBF_OpaquePredicates = 134,

            /// @brief Bogus control flow
            OBF_BogusControlFlow = 135,

            /// @brief Mixed boolean-arithmetic (MBA)
            OBF_MixedBooleanArithmetic = 136,

            /// @brief String encryption
            OBF_StringEncryption = 137,

            /// @brief Constant unfolding
            OBF_ConstantUnfolding = 138,

            /// @brief API obfuscation (hash-based)
            OBF_APIHashing = 139,

            /// @brief Import obfuscation
            OBF_ImportObfuscation = 140,

            /// @brief Anti-disassembly tricks
            OBF_AntiDisassembly = 141,

            /// @brief Overlapping instructions
            OBF_OverlappingInstructions = 142,

            /// @brief Misaligned code
            OBF_MisalignedCode = 143,

            /// @brief Exception-based control flow
            OBF_ExceptionControlFlow = 144,

            /// @brief Stack-based obfuscation
            OBF_StackObfuscation = 145,

            /// @brief Indirect branches
            OBF_IndirectBranches = 146,

            /// @brief Computed jumps
            OBF_ComputedJumps = 147,

            /// @brief Return-oriented obfuscation
            OBF_ReturnOriented = 148,

            // ========================================================================
            // VM PROTECTION TECHNIQUES (171-200)
            // ========================================================================

            /// @brief Custom VM interpreter detected
            VM_CustomInterpreter = 171,

            /// @brief VMProtect signatures
            VM_VMProtect = 172,

            /// @brief Themida/WinLicense signatures
            VM_Themida = 173,

            /// @brief Code Virtualizer signatures
            VM_CodeVirtualizer = 174,

            /// @brief Oreans Code Virtualizer
            VM_Oreans = 175,

            /// @brief Enigma Protector VM
            VM_Enigma = 176,

            /// @brief ASProtect VM
            VM_ASProtect = 177,

            /// @brief Obsidium VM
            VM_Obsidium = 178,

            /// @brief PELock VM
            VM_PELock = 179,

            /// @brief Custom bytecode interpreter
            VM_CustomBytecode = 180,

            /// @brief Stack-based VM
            VM_StackBased = 181,

            /// @brief Register-based VM
            VM_RegisterBased = 182,

            /// @brief Multiple VMs nested
            VM_Nested = 183,

            // ========================================================================
            // PACKING TECHNIQUES (201-230)
            // ========================================================================

            /// @brief UPX packing
            PACK_UPX = 201,

            /// @brief ASPack
            PACK_ASPack = 202,

            /// @brief PECompact
            PACK_PECompact = 203,

            /// @brief MPRESS
            PACK_MPRESS = 204,

            /// @brief Petite
            PACK_Petite = 205,

            /// @brief FSG
            PACK_FSG = 206,

            /// @brief MEW
            PACK_MEW = 207,

            /// @brief NsPack
            PACK_NsPack = 208,

            /// @brief Custom packer detected
            PACK_Custom = 209,

            /// @brief Multi-layer packing
            PACK_MultiLayer = 210,

            /// @brief Crypter detected
            PACK_Crypter = 211,

            // ========================================================================
            // STRUCTURAL ANOMALIES (231-260)
            // ========================================================================

            /// @brief High code entropy
            STRUCT_HighEntropy = 231,

            /// @brief Unusual section characteristics
            STRUCT_UnusualSections = 232,

            /// @brief Entry point outside code section
            STRUCT_EntryPointAnomaly = 233,

            /// @brief Suspicious import table
            STRUCT_SuspiciousImports = 234,

            /// @brief Minimal imports (LoadLibrary/GetProcAddress only)
            STRUCT_MinimalImports = 235,

            /// @brief Abnormal PE header
            STRUCT_AbnormalHeader = 236,

            /// @brief Resource section anomalies
            STRUCT_ResourceAnomaly = 237,

            /// @brief Relocation anomalies
            STRUCT_RelocationAnomaly = 238,

            /// @brief TLS callback presence
            STRUCT_TLSCallbacks = 239,

            /// @brief Multiple entry points
            STRUCT_MultipleEntryPoints = 240,

            /// @brief Self-referential structures
            STRUCT_SelfReferential = 241,

            // ========================================================================
            // SIMILARITY INDICATORS (261-280)
            // ========================================================================

            /// @brief Fuzzy hash match found
            SIMILARITY_FuzzyMatch = 261,

            /// @brief TLSH fuzzy match found
            SIMILARITY_TLSHMatch = 262,

            /// @brief Function-level similarity
            SIMILARITY_FunctionMatch = 263,

            /// @brief Basic block similarity
            SIMILARITY_BasicBlockMatch = 264,

            /// @brief CFG structure similarity
            SIMILARITY_CFGMatch = 265,

            /// @brief N-gram sequence match
            SIMILARITY_NGramMatch = 266,

            /// @brief Mnemonic sequence similarity
            SIMILARITY_MnemonicMatch = 267,

            /// @brief Known family variant
            SIMILARITY_FamilyVariant = 268,

            // ========================================================================
            // ADVANCED/COMBINED (281-300)
            // ========================================================================

            /// @brief Multiple metamorphic categories
            ADV_MultiCategory = 281,

            /// @brief Engine signature detected
            ADV_EngineSignature = 282,

            /// @brief Progressive mutation detected
            ADV_ProgressiveMutation = 283,

            /// @brief Generation tracking detected
            ADV_GenerationTracking = 284,

            /// @brief Anti-analysis combined
            ADV_AntiAnalysis = 285,

            /// @brief Sophisticated evasion
            ADV_SophisticatedEvasion = 286,

            /// @brief Maximum technique ID
            _MaxTechniqueId = 300
        };

        /**
         * @brief Severity level of detected technique
         */
        enum class MetamorphicSeverity : uint8_t {
            /// @brief Informational (may be legitimate)
            Low = 0,

            /// @brief Suspicious (warrants investigation)
            Medium = 1,

            /// @brief High confidence malicious
            High = 2,

            /// @brief Critical (known malware technique)
            Critical = 3
        };

        /**
         * @brief Analysis depth level
         */
        enum class MetamorphicAnalysisDepth : uint8_t {
            /// @brief Quick scan (entropy, basic patterns)
            Quick = 0,

            /// @brief Standard (adds opcode analysis)
            Standard = 1,

            /// @brief Deep (full CFG analysis)
            Deep = 2,

            /// @brief Comprehensive (all techniques)
            Comprehensive = 3
        };

        /**
         * @brief Analysis flags for selective scanning
         */
        enum class MetamorphicAnalysisFlags : uint32_t {
            None = 0,

            // Category flags
            ScanMetamorphic = 1 << 0,
            ScanPolymorphic = 1 << 1,
            ScanSelfModifying = 1 << 2,
            ScanObfuscation = 1 << 3,
            ScanVMProtection = 1 << 4,
            ScanPacking = 1 << 5,
            ScanStructuralAnomalies = 1 << 6,
            ScanSimilarity = 1 << 7,

            // Analysis flags
            EnableDisassembly = 1 << 12,
            EnableCFGAnalysis = 1 << 13,
            EnableEntropyAnalysis = 1 << 14,
            EnableFuzzyHashing = 1 << 15,
            EnableFamilyMatching = 1 << 16,

            // Behavior flags
            EnableCaching = 1 << 20,
            EnableParallelScan = 1 << 21,
            StopOnFirstDetection = 1 << 22,
            IncludeRawData = 1 << 23,

            // Presets
            QuickScan = EnableEntropyAnalysis | ScanPacking | ScanStructuralAnomalies | EnableCaching,
            StandardScan = QuickScan | ScanPolymorphic | ScanMetamorphic | EnableDisassembly,
            DeepScan = StandardScan | EnableCFGAnalysis | ScanObfuscation | ScanVMProtection |
            EnableFuzzyHashing,
            ComprehensiveScan = 0x00FF | 0x00FF0000 | EnableCaching | EnableParallelScan,

            Default = StandardScan
        };

        // Bitwise operators
        inline constexpr MetamorphicAnalysisFlags operator|(MetamorphicAnalysisFlags a, MetamorphicAnalysisFlags b) noexcept {
            return static_cast<MetamorphicAnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr MetamorphicAnalysisFlags operator&(MetamorphicAnalysisFlags a, MetamorphicAnalysisFlags b) noexcept {
            return static_cast<MetamorphicAnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr bool HasFlag(MetamorphicAnalysisFlags flags, MetamorphicAnalysisFlags flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Get string representation of category
         */
        [[nodiscard]] constexpr const char* MetamorphicCategoryToString(MetamorphicCategory category) noexcept {
            switch (category) {
            case MetamorphicCategory::Metamorphic:        return "Metamorphic";
            case MetamorphicCategory::Polymorphic:        return "Polymorphic";
            case MetamorphicCategory::SelfModifying:      return "Self-Modifying";
            case MetamorphicCategory::Obfuscation:        return "Obfuscation";
            case MetamorphicCategory::VMProtection:       return "VM Protection";
            case MetamorphicCategory::Packing:            return "Packing";
            case MetamorphicCategory::CodeGeneration:     return "Code Generation";
            case MetamorphicCategory::InstructionMutation: return "Instruction Mutation";
            case MetamorphicCategory::ControlFlowMutation: return "Control Flow Mutation";
            case MetamorphicCategory::DataMutation:       return "Data Mutation";
            case MetamorphicCategory::Combined:           return "Combined";
            default:                                      return "Unknown";
            }
        }

        /**
         * @brief Get string representation of technique
         */
        [[nodiscard]] const wchar_t* MetamorphicTechniqueToString(MetamorphicTechnique technique) noexcept;

        /**
         * @brief Get MITRE ATT&CK ID for technique
         */
        [[nodiscard]] constexpr const char* MetamorphicTechniqueToMitreId(MetamorphicTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            // Binary padding
            if (id == 1 || id == 11 || id == 16) return "T1027.001";

            // Software packing
            if (id >= 201 && id <= 230) return "T1027.002";

            // Obfuscation general
            if ((id >= 1 && id <= 50) || (id >= 131 && id <= 170)) return "T1027";

            // Deobfuscate/decode
            if (id >= 51 && id <= 100) return "T1140";

            // Reflective loading
            if (id >= 101 && id <= 130) return "T1620";

            return "T1027";
        }

        /**
         * @brief Get category for technique
         */
        [[nodiscard]] constexpr MetamorphicCategory GetTechniqueCategory(MetamorphicTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            if (id >= 1 && id <= 50)    return MetamorphicCategory::Metamorphic;
            if (id >= 51 && id <= 100)  return MetamorphicCategory::Polymorphic;
            if (id >= 101 && id <= 130) return MetamorphicCategory::SelfModifying;
            if (id >= 131 && id <= 170) return MetamorphicCategory::Obfuscation;
            if (id >= 171 && id <= 200) return MetamorphicCategory::VMProtection;
            if (id >= 201 && id <= 230) return MetamorphicCategory::Packing;
            if (id >= 231 && id <= 260) return MetamorphicCategory::Obfuscation;
            if (id >= 261 && id <= 280) return MetamorphicCategory::Combined;
            if (id >= 281 && id <= 300) return MetamorphicCategory::Combined;

            return MetamorphicCategory::Unknown;
        }

        /**
         * @brief Get default severity for technique
         */
        [[nodiscard]] constexpr MetamorphicSeverity GetDefaultTechniqueSeverity(MetamorphicTechnique technique) noexcept {
            switch (technique) {
                // Critical
            case MetamorphicTechnique::POLY_GetPC_CallPop:
            case MetamorphicTechnique::POLY_GetPC_FSTENV:
            case MetamorphicTechnique::POLY_DecoderMutation:
            case MetamorphicTechnique::POLY_ShellcodeEncoder:
            case MetamorphicTechnique::SELF_WriteProcessMemory:
            case MetamorphicTechnique::VM_CustomInterpreter:
            case MetamorphicTechnique::ADV_EngineSignature:
            case MetamorphicTechnique::SIMILARITY_FamilyVariant:
                return MetamorphicSeverity::Critical;

                // High
            case MetamorphicTechnique::META_RegisterReassignment:
            case MetamorphicTechnique::META_CodeTransposition:
            case MetamorphicTechnique::POLY_XORDecryption:
            case MetamorphicTechnique::POLY_MultiLayerEncryption:
            case MetamorphicTechnique::OBF_ControlFlowFlattening:
            case MetamorphicTechnique::OBF_APIHashing:
            case MetamorphicTechnique::STRUCT_HighEntropy:
            case MetamorphicTechnique::STRUCT_MinimalImports:
                return MetamorphicSeverity::High;

                // Medium
            case MetamorphicTechnique::META_NOPInsertion:
            case MetamorphicTechnique::META_DeadCodeInsertion:
            case MetamorphicTechnique::META_InstructionSubstitution:
            case MetamorphicTechnique::OBF_StringEncryption:
            case MetamorphicTechnique::PACK_UPX:
            case MetamorphicTechnique::PACK_ASPack:
                return MetamorphicSeverity::Medium;

                // Low (potentially legitimate)
            default:
                return MetamorphicSeverity::Low;
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Error information
         */
        struct MetamorphicError {
            DWORD win32Code = ERROR_SUCCESS;
            std::wstring message;
            std::wstring context;

            [[nodiscard]] bool HasError() const noexcept { return win32Code != ERROR_SUCCESS; }
            void Clear() noexcept { win32Code = ERROR_SUCCESS; message.clear(); context.clear(); }
        };

        /**
         * @brief Detected technique detail
         */
        struct MetamorphicDetectedTechnique {
            /// @brief Technique identifier
            MetamorphicTechnique technique = MetamorphicTechnique::None;

            /// @brief Category
            MetamorphicCategory category = MetamorphicCategory::Unknown;

            /// @brief Severity
            MetamorphicSeverity severity = MetamorphicSeverity::Low;

            /// @brief Confidence (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Weight for scoring
            double weight = 1.0;

            /// @brief Location in file/memory (RVA or offset)
            uint64_t location = 0;

            /// @brief Size of the detected artifact
            size_t artifactSize = 0;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details
            std::wstring technicalDetails;

            /// @brief MITRE ATT&CK ID
            std::string mitreId;

            /// @brief Raw data sample (limited)
            std::vector<uint8_t> rawData;

            /// @brief Detection timestamp
            std::chrono::system_clock::time_point detectionTime;

            MetamorphicDetectedTechnique() = default;
            explicit MetamorphicDetectedTechnique(MetamorphicTechnique tech) noexcept
                : technique(tech)
                , category(GetTechniqueCategory(tech))
                , severity(GetDefaultTechniqueSeverity(tech))
                , mitreId(MetamorphicTechniqueToMitreId(tech))
                , detectionTime(std::chrono::system_clock::now())
            {
            }
        };

        /**
         * @brief Opcode histogram statistics
         */
        struct OpcodeHistogram {
            /// @brief Count of each byte value (0-255)
            std::array<uint64_t, 256> byteCounts{};

            /// @brief Total bytes analyzed
            uint64_t totalBytes = 0;

            /// @brief Percentage of NOP instructions
            double nopPercentage = 0.0;

            /// @brief Percentage of INT3 instructions
            double int3Percentage = 0.0;

            /// @brief Percentage of XOR instructions
            double xorPercentage = 0.0;

            /// @brief Percentage of RET instructions
            double retPercentage = 0.0;

            /// @brief Percentage of CALL instructions
            double callPercentage = 0.0;

            /// @brief Percentage of JMP instructions
            double jmpPercentage = 0.0;

            /// @brief Overall entropy (0.0 - 8.0)
            double entropy = 0.0;

            /// @brief Chi-squared statistic
            double chiSquared = 0.0;

            /// @brief Indicates potential encryption
            bool isPotentiallyEncrypted = false;

            /// @brief Indicates excessive NOPs
            bool hasExcessiveNops = false;

            /// @brief Indicates junk code
            bool hasJunkCodeSignature = false;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Basic block representation
         */
        struct BasicBlock {
            /// @brief Start address (RVA)
            uint64_t startAddress = 0;

            /// @brief End address (RVA)
            uint64_t endAddress = 0;

            /// @brief Size in bytes
            size_t size = 0;

            /// @brief Number of instructions
            size_t instructionCount = 0;

            /// @brief Successor block addresses
            std::vector<uint64_t> successors;

            /// @brief Predecessor block addresses
            std::vector<uint64_t> predecessors;

            /// @brief Block type (normal, conditional, unconditional, call, return)
            uint8_t blockType = 0;

            /// @brief Block flags
            uint32_t flags = 0;
        };

        /**
         * @brief Function representation for CFG analysis
         */
        struct FunctionInfo {
            /// @brief Function start address (RVA)
            uint64_t entryPoint = 0;

            /// @brief Function size (estimated)
            size_t size = 0;

            /// @brief Number of basic blocks
            size_t basicBlockCount = 0;

            /// @brief Basic blocks in this function
            std::vector<BasicBlock> basicBlocks;

            /// @brief Cyclomatic complexity
            uint32_t cyclomaticComplexity = 0;

            /// @brief Number of edges in CFG
            uint32_t edgeCount = 0;

            /// @brief Is flattened CFG detected
            bool isFlattenedCFG = false;

            /// @brief Contains opaque predicates
            bool hasOpaquePredicates = false;

            /// @brief Contains dead code
            bool hasDeadCode = false;

            /// @brief Hash of function structure (for similarity)
            uint64_t structuralHash = 0;
        };

        /**
         * @brief Control Flow Graph analysis results
         */
        struct CFGAnalysisInfo {
            /// @brief Total functions analyzed
            size_t functionCount = 0;

            /// @brief Total basic blocks
            size_t totalBasicBlocks = 0;

            /// @brief Total edges
            size_t totalEdges = 0;

            /// @brief Functions with high complexity
            size_t highComplexityFunctions = 0;

            /// @brief Functions with flattened CFG
            size_t flattenedFunctions = 0;

            /// @brief Functions with opaque predicates
            size_t opaquePredicateFunctions = 0;

            /// @brief Functions with dead code
            size_t deadCodeFunctions = 0;

            /// @brief Anomalies detected
            std::vector<std::wstring> anomalies;

            /// @brief Branch density
            double branchDensity = 0.0;

            /// @brief Indirect branch density
            double indirectBranchDensity = 0.0;

            /// @brief Has unusual control flow
            bool hasUnusualFlow = false;

            /// @brief Is flattened CFG
            bool isFlattened = false;

            /// @brief Average cyclomatic complexity
            double averageComplexity = 0.0;

            /// @brief Total cyclomatic complexity (sum)
            uint32_t cyclomaticComplexity = 0;

            /// @brief Function details (limited)
            std::vector<FunctionInfo> functions;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Decryption loop detection results
         */
        struct DecryptionLoopInfo {
            /// @brief Loop start address
            uint64_t startAddress = 0;

            /// @brief Loop size in bytes
            size_t loopSize = 0;

            /// @brief Estimated key size
            size_t keySize = 0;

            /// @brief Estimated encrypted data size
            size_t encryptedDataSize = 0;

            /// @brief Encryption algorithm guess
            std::wstring algorithmGuess;

            /// @brief Uses XOR
            bool usesXOR = false;

            /// @brief Uses ADD/SUB
            bool usesAddSub = false;

            /// @brief Uses ROL/ROR
            bool usesRotation = false;

            /// @brief Uses GetPC technique
            bool usesGetPC = false;

            /// @brief GetPC method
            std::wstring getPCMethod;

            /// @brief Multi-layer encryption
            bool isMultiLayer = false;

            /// @brief Layer count (if multi-layer)
            uint32_t layerCount = 1;

            /// @brief Raw loop bytes
            std::vector<uint8_t> loopBytes;

            /// @brief Valid detection
            bool valid = false;
        };

        /**
         * @brief Fuzzy hash match information
         */
        struct FuzzyHashMatch {
            /// @brief Hash type (CTPH, TLSH)
            std::wstring hashType;

            /// @brief Computed hash value
            std::wstring computedHash;

            /// @brief Matched hash from database (empty if no match)
            std::wstring matchedHash;

            /// @brief Similarity score (fuzzy: 0-100, TLSH: distance where lower=better)
            int similarityScore = 0;

            /// @brief Matched malware family name (from HashStore/SignatureStore)
            std::wstring malwareFamily;

            /// @brief Matched family name (alias for backward compatibility)
            std::wstring familyName;

            /// @brief Matched variant name
            std::wstring variantName;

            /// @brief Match confidence (0.0-1.0)
            double confidence = 0.0;

            /// @brief Is significant match (threat level >= Medium)
            bool isSignificant = false;

            /// @brief Threat level from signature database
            SignatureStore::ThreatLevel threatLevel = SignatureStore::ThreatLevel::Info;
        };

        /**
         * @brief PE section analysis
         */
        struct SectionAnalysisInfo {
            /// @brief Section name
            std::string name;

            /// @brief Virtual address
            uint32_t virtualAddress = 0;

            /// @brief Virtual size
            uint32_t virtualSize = 0;

            /// @brief Raw size
            uint32_t rawSize = 0;

            /// @brief Raw address (file offset / PointerToRawData)
            uint32_t rawAddress = 0;

            /// @brief Characteristics
            uint32_t characteristics = 0;

            /// @brief Section entropy
            double entropy = 0.0;

            /// @brief Is executable
            bool isExecutable = false;

            /// @brief Is writable
            bool isWritable = false;

            /// @brief Has code (based on characteristics)
            bool hasCode = false;

            /// @brief Has high entropy
            bool hasHighEntropy = false;

            /// @brief Is packed
            bool isPacked = false;

            /// @brief Anomalies detected
            std::vector<std::wstring> anomalies;
        };

        /**
         * @brief Overall PE analysis
         */
        struct PEAnalysisInfo {
            /// @brief Entry point RVA
            uint32_t entryPointRVA = 0;

            /// @brief Image base
            uint64_t imageBase = 0;

            /// @brief Is 64-bit
            bool is64Bit = false;

            /// @brief Has valid signature
            bool hasValidSignature = false;

            /// @brief Is .NET assembly
            bool isDotNet = false;

            /// @brief Has TLS callbacks
            bool hasTLSCallbacks = false;

            /// @brief TLS callback addresses
            std::vector<uint64_t> tlsCallbacks;

            /// @brief Import count
            size_t importCount = 0;

            /// @brief Export count
            size_t exportCount = 0;

            /// @brief Has minimal imports
            bool hasMinimalImports = false;

            /// @brief Has suspicious imports
            bool hasSuspiciousImports = false;

            /// @brief Sections
            std::vector<SectionAnalysisInfo> sections;

            /// @brief Overall file entropy
            double fileEntropy = 0.0;

            /// @brief Packer detected
            std::wstring packerName;

            /// @brief Compiler/linker detected
            std::wstring compilerName;

            /// @brief Anomalies
            std::vector<std::wstring> anomalies;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Known family match
         */
        struct FamilyMatchInfo {
            /// @brief Family name
            std::wstring familyName;

            /// @brief Variant/version
            std::wstring variant;

            /// @brief Match confidence (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Match method
            std::wstring matchMethod;

            /// @brief Matched pattern/signature
            std::wstring matchedPattern;

            /// @brief Known behaviors
            std::vector<std::wstring> knownBehaviors;

            /// @brief References
            std::vector<std::wstring> references;
        };

        /**
         * @brief Analysis configuration
         */
        struct MetamorphicAnalysisConfig {
            /// @brief Analysis depth
            MetamorphicAnalysisDepth depth = MetamorphicAnalysisDepth::Standard;

            /// @brief Analysis flags
            MetamorphicAnalysisFlags flags = MetamorphicAnalysisFlags::Default;

            /// @brief Timeout in milliseconds
            uint32_t timeoutMs = MetamorphicConstants::DEFAULT_SCAN_TIMEOUT_MS;

            /// @brief Maximum file size to analyze
            size_t maxFileSize = MetamorphicConstants::MAX_FILE_SIZE;

            /// @brief Maximum instructions to disassemble
            size_t maxInstructions = MetamorphicConstants::MAX_INSTRUCTIONS;

            /// @brief Enable caching
            bool enableCaching = true;

            /// @brief Cache TTL
            uint32_t cacheTtlSeconds = MetamorphicConstants::RESULT_CACHE_TTL_SECONDS;

            /// @brief Minimum confidence threshold
            double minConfidenceThreshold = 0.5;

            /// @brief Include raw data in results
            bool includeRawData = false;

            /// @brief Maximum raw data size
            size_t maxRawDataSize = 256;

            /// @brief Fuzzy hash similarity threshold
            int fuzzyThreshold = MetamorphicConstants::FUZZY_SIMILARITY_THRESHOLD;

            /// @brief TLSH distance threshold
            int tlshThreshold = MetamorphicConstants::TLSH_DISTANCE_THRESHOLD;

            /// @brief Custom patterns to search
            std::vector<std::vector<uint8_t>> customPatterns;
        };

        /**
         * @brief Comprehensive analysis result
         */
        struct MetamorphicResult {
            // ========================================================================
            // IDENTIFICATION
            // ========================================================================

            /// @brief File path analyzed
            std::wstring filePath;

            /// @brief Process ID (if process analysis)
            uint32_t processId = 0;

            /// @brief File hash (SHA256)
            std::string sha256Hash;

            /// @brief File size
            size_t fileSize = 0;

            // ========================================================================
            // DETECTION SUMMARY
            // ========================================================================

            /// @brief Is metamorphic/polymorphic detected
            bool isMetamorphic = false;

            /// @brief Mutation score (0.0 - 100.0)
            double mutationScore = 0.0;

            /// @brief Highest severity
            MetamorphicSeverity maxSeverity = MetamorphicSeverity::Low;

            /// @brief Total detections
            uint32_t totalDetections = 0;

            /// @brief Categories detected (bitfield)
            uint32_t detectedCategories = 0;

            /// @brief Identified malware family (if matched)
            std::wstring familyName;

            /// @brief Variant name
            std::wstring variantName;

            // ========================================================================
            // DETAILED FINDINGS
            // ========================================================================

            /// @brief All detected techniques
            std::vector<MetamorphicDetectedTechnique> detectedTechniques;

            /// @brief Opcode histogram
            OpcodeHistogram opcodeHistogram;

            /// @brief CFG analysis
            CFGAnalysisInfo cfgAnalysis;

            /// @brief Decryption loops found
            std::vector<DecryptionLoopInfo> decryptionLoops;

            /// @brief Fuzzy hash matches
            std::vector<FuzzyHashMatch> fuzzyMatches;

            /// @brief PE analysis
            PEAnalysisInfo peAnalysis;

            /// @brief Family matches
            std::vector<FamilyMatchInfo> familyMatches;

            // ========================================================================
            // INDICATORS
            // ========================================================================

            /// @brief String indicators (suspicious strings found)
            std::vector<std::wstring> stringIndicators;

            /// @brief Behavioral indicators
            std::vector<std::wstring> behavioralIndicators;

            /// @brief Structural indicators
            std::vector<std::wstring> structuralIndicators;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /// @brief Bytes analyzed
            uint64_t bytesAnalyzed = 0;

            /// @brief Instructions disassembled
            uint64_t instructionsAnalyzed = 0;

            /// @brief Functions analyzed
            uint32_t functionsAnalyzed = 0;

            /// @brief Patterns checked
            uint32_t patternsChecked = 0;

            // ========================================================================
            // TIMING & METADATA
            // ========================================================================

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime;

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime;

            /// @brief Duration in milliseconds
            uint64_t analysisDurationMs = 0;

            /// @brief Configuration used
            MetamorphicAnalysisConfig config;

            /// @brief Errors encountered
            std::vector<MetamorphicError> errors;

            /// @brief Analysis completed
            bool analysisComplete = false;

            /// @brief From cache
            bool fromCache = false;

            // ========================================================================
            // FUZZY HASHING RESULTS
            // ========================================================================

            /// @brief CTPH fuzzy hash
            std::string fuzzyHash;

            /// @brief TLSH fuzzy hash
            std::string tlshHash;

            /// @brief N-gram profile (top N-grams by frequency)
            std::vector<uint64_t> ngramProfile;

            /// @brief Similarity analysis completed
            bool similarityAnalysisComplete = false;

            // ========================================================================
            // METHODS
            // ========================================================================

            [[nodiscard]] bool HasCategory(MetamorphicCategory category) const noexcept {
                return (detectedCategories & (1u << static_cast<uint32_t>(category))) != 0;
            }

            [[nodiscard]] bool HasTechnique(MetamorphicTechnique technique) const noexcept {
                for (const auto& det : detectedTechniques) {
                    if (det.technique == technique) return true;
                }
                return false;
            }

            [[nodiscard]] size_t GetCategoryCount(MetamorphicCategory category) const noexcept {
                size_t count = 0;
                for (const auto& det : detectedTechniques) {
                    if (det.category == category) ++count;
                }
                return count;
            }

            void Clear() noexcept {
                filePath.clear();
                processId = 0;
                sha256Hash.clear();
                fileSize = 0;
                isMetamorphic = false;
                mutationScore = 0.0;
                maxSeverity = MetamorphicSeverity::Low;
                totalDetections = 0;
                detectedCategories = 0;
                familyName.clear();
                variantName.clear();
                detectedTechniques.clear();
                opcodeHistogram = {};
                cfgAnalysis = {};
                decryptionLoops.clear();
                fuzzyMatches.clear();
                peAnalysis = {};
                familyMatches.clear();
                stringIndicators.clear();
                behavioralIndicators.clear();
                structuralIndicators.clear();
                bytesAnalyzed = 0;
                instructionsAnalyzed = 0;
                functionsAnalyzed = 0;
                patternsChecked = 0;
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                config = {};
                errors.clear();
                analysisComplete = false;
                fromCache = false;
            }
        };

        /**
         * @brief Batch analysis result
         */
        struct MetamorphicBatchResult {
            std::vector<MetamorphicResult> results;
            uint32_t totalFiles = 0;
            uint32_t metamorphicFiles = 0;
            uint32_t failedFiles = 0;
            uint64_t totalDurationMs = 0;
            std::chrono::system_clock::time_point startTime;
            std::chrono::system_clock::time_point endTime;
        };

        /**
         * @brief Progress callback
         */
        using MetamorphicProgressCallback = std::function<void(
            const std::wstring& currentFile,
            MetamorphicCategory currentCategory,
            uint32_t techniquesChecked,
            uint32_t totalTechniques
            )>;

        /**
         * @brief Detection callback
         */
        using MetamorphicDetectionCallback = std::function<void(
            const std::wstring& file,
            const MetamorphicDetectedTechnique& detection
            )>;

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade metamorphic and polymorphic code detector
         *
         * Detects code mutation engines used by advanced malware to evade
         * signature-based detection. Thread-safe for concurrent analysis.
         *
         * Usage example:
         * @code
         *     auto detector = std::make_unique<MetamorphicDetector>();
         *     if (!detector->Initialize()) {
         *         // Handle failure
         *     }
         *
         *     MetamorphicAnalysisConfig config;
         *     config.depth = MetamorphicAnalysisDepth::Deep;
         *
         *     auto result = detector->AnalyzeFile(L"C:\\suspect.exe", config);
         *     if (result.isMetamorphic) {
         *         std::wcout << L"Mutation score: " << result.mutationScore << L"%\n";
         *         if (!result.familyName.empty()) {
         *             std::wcout << L"Family: " << result.familyName << L"\n";
         *         }
         *     }
         * @endcode
         */
        class MetamorphicDetector {
        public:
            // ========================================================================
            // CONSTRUCTION & LIFECYCLE
            // ========================================================================

            /**
             * @brief Default constructor
             */
            MetamorphicDetector() noexcept;

            /**
             * @brief Constructor with signature store
             * @param sigStore Signature store for pattern matching
             */
            explicit MetamorphicDetector(
                std::shared_ptr<ShadowStrike::SignatureStore::SignatureStore> sigStore
            ) noexcept;

            /**
             * @brief Constructor with all stores
             * @param sigStore Signature store
             * @param hashStore Hash store for fuzzy matching
             * @param patternStore Pattern store for decoder detection
             */
            MetamorphicDetector(
                std::shared_ptr<ShadowStrike::SignatureStore::SignatureStore> sigStore,
                std::shared_ptr<ShadowStrike::HashStore::HashStore> hashStore,
                std::shared_ptr<ShadowStrike::PatternStore::PatternStore> patternStore
            ) noexcept;

            /**
             * @brief Constructor with threat intel
             */
            MetamorphicDetector(
                std::shared_ptr<ShadowStrike::SignatureStore::SignatureStore> sigStore,
                std::shared_ptr<ShadowStrike::HashStore::HashStore> hashStore,
                std::shared_ptr<ShadowStrike::PatternStore::PatternStore> patternStore,
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Destructor
             */
            ~MetamorphicDetector();

            // Non-copyable, movable
            MetamorphicDetector(const MetamorphicDetector&) = delete;
            MetamorphicDetector& operator=(const MetamorphicDetector&) = delete;
            MetamorphicDetector(MetamorphicDetector&&) noexcept;
            MetamorphicDetector& operator=(MetamorphicDetector&&) noexcept;

            // ========================================================================
            // INITIALIZATION
            // ========================================================================

            /**
             * @brief Initialize the detector
             */
            [[nodiscard]] bool Initialize(MetamorphicError* err = nullptr) noexcept;

            /**
             * @brief Shutdown
             */
            void Shutdown() noexcept;

            /**
             * @brief Check if initialized
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            // ========================================================================
            // FILE ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze file for metamorphic properties
             */
            [[nodiscard]] MetamorphicResult AnalyzeFile(
                const std::wstring& filePath,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze buffer for metamorphic properties
             */
            [[nodiscard]] MetamorphicResult AnalyzeBuffer(
                const uint8_t* buffer,
                size_t size,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicError* err = nullptr
            ) noexcept;

            // ========================================================================
            // PROCESS ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze process memory for metamorphic code
             */
            [[nodiscard]] MetamorphicResult AnalyzeProcess(
                uint32_t processId,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze process using handle
             */
            [[nodiscard]] MetamorphicResult AnalyzeProcess(
                HANDLE hProcess,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicError* err = nullptr
            ) noexcept;

            // ========================================================================
            // BATCH ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze multiple files
             */
            [[nodiscard]] MetamorphicBatchResult AnalyzeFiles(
                const std::vector<std::wstring>& filePaths,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicProgressCallback progressCallback = nullptr,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze directory
             */
            [[nodiscard]] MetamorphicBatchResult AnalyzeDirectory(
                const std::wstring& directoryPath,
                bool recursive,
                const MetamorphicAnalysisConfig& config = MetamorphicAnalysisConfig{},
                MetamorphicProgressCallback progressCallback = nullptr,
                MetamorphicError* err = nullptr
            ) noexcept;

            // ========================================================================
            // SPECIFIC ANALYSIS METHODS
            // ========================================================================

            /**
             * @brief Compute opcode histogram
             */
            [[nodiscard]] bool ComputeOpcodeHistogram(
                const uint8_t* buffer,
                size_t size,
                OpcodeHistogram& outHistogram,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Calculate entropy
             */
            [[nodiscard]] double CalculateEntropy(
                const uint8_t* buffer,
                size_t size
            ) noexcept;

            /**
             * @brief Detect decryption loops
             */
            [[nodiscard]] bool DetectDecryptionLoops(
                const uint8_t* buffer,
                size_t size,
                std::vector<DecryptionLoopInfo>& outLoops,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Perform fuzzy hash matching
             */
            [[nodiscard]] bool PerformFuzzyMatching(
                const std::wstring& filePath,
                std::vector<FuzzyHashMatch>& outMatches,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze PE structure
             */
            [[nodiscard]] bool AnalyzePEStructure(
                const std::wstring& filePath,
                PEAnalysisInfo& outInfo,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze Control Flow Graph
             */
            [[nodiscard]] bool AnalyzeCFG(
                const uint8_t* buffer,
                size_t size,
                uint64_t baseAddress,
                CFGAnalysisInfo& outInfo,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect packer/protector
             */
            [[nodiscard]] std::optional<std::wstring> DetectPacker(
                const std::wstring& filePath,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Match against known families
             */
            [[nodiscard]] bool MatchKnownFamilies(
                const uint8_t* buffer,
                size_t size,
                std::vector<FamilyMatchInfo>& outMatches,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Compute fuzzy hash
             */
            [[nodiscard]] std::optional<std::string> ComputeFuzzyHash(
                const std::wstring& filePath,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Compute TLSH hash
             */
            [[nodiscard]] std::optional<std::string> ComputeTLSH(
                const std::wstring& filePath,
                MetamorphicError* err = nullptr
            ) noexcept;

            /**
             * @brief Compare fuzzy hashes
             */
            [[nodiscard]] int CompareFuzzyHash(
                const std::string& hash1,
                const std::string& hash2
            ) noexcept;

            /**
             * @brief Compare TLSH hashes
             */
            [[nodiscard]] int CompareTLSH(
                const std::string& hash1,
                const std::string& hash2
            ) noexcept;

            // ========================================================================
            // REAL-TIME DETECTION
            // ========================================================================

            /**
             * @brief Set detection callback
             */
            void SetDetectionCallback(MetamorphicDetectionCallback callback) noexcept;

            /**
             * @brief Clear detection callback
             */
            void ClearDetectionCallback() noexcept;

            // ========================================================================
            // CACHING
            // ========================================================================

            /**
             * @brief Get cached result
             */
            [[nodiscard]] std::optional<MetamorphicResult> GetCachedResult(
                const std::wstring& filePath
            ) const noexcept;

            /**
             * @brief Invalidate cache entry
             */
            void InvalidateCache(const std::wstring& filePath) noexcept;

            /**
             * @brief Clear all cache
             */
            void ClearCache() noexcept;

            /**
             * @brief Get cache size
             */
            [[nodiscard]] size_t GetCacheSize() const noexcept;

            // ========================================================================
            // CONFIGURATION
            // ========================================================================

            /**
             * @brief Set signature store
             */
            void SetSignatureStore(std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept;

            /**
             * @brief Set hash store
             */
            void SetHashStore(std::shared_ptr<HashStore::HashStore> hashStore) noexcept;

            /**
             * @brief Set pattern store
             */
            void SetPatternStore(std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept;

            /**
             * @brief Set threat intel store
             */
            void SetThreatIntelStore(std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel) noexcept;

            /**
             * @brief Add custom detection pattern
             */
            void AddCustomPattern(
                std::wstring_view name,
                const std::vector<uint8_t>& pattern,
                MetamorphicTechnique technique
            ) noexcept;

            /**
             * @brief Clear custom patterns
             */
            void ClearCustomPatterns() noexcept;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            struct Statistics {
                std::atomic<uint64_t> totalAnalyses{ 0 };
                std::atomic<uint64_t> detections{ 0 };
                std::atomic<uint64_t> metamorphicDetections{ 0 };
                std::atomic<uint64_t> polymorphicDetections{ 0 };
                std::atomic<uint64_t> packerDetections{ 0 };
                std::atomic<uint64_t> familyMatches{ 0 };
                std::atomic<uint64_t> cacheHits{ 0 };
                std::atomic<uint64_t> cacheMisses{ 0 };
                std::atomic<uint64_t> analysisErrors{ 0 };
                std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };
                std::atomic<uint64_t> bytesAnalyzed{ 0 };
                std::array<std::atomic<uint64_t>, 16> categoryDetections{};

                void Reset() noexcept {
                    totalAnalyses = 0;
                    metamorphicDetections = 0;
                    polymorphicDetections = 0;
                    packerDetections = 0;
                    familyMatches = 0;
                    cacheHits = 0;
                    cacheMisses = 0;
                    analysisErrors = 0;
                    totalAnalysisTimeUs = 0;
                    bytesAnalyzed = 0;
                    for (auto& cat : categoryDetections) cat = 0;
                }
            };

            [[nodiscard]] const Statistics& GetStatistics() const noexcept;
            void ResetStatistics() noexcept;

        private:
            class Impl;
            std::unique_ptr<Impl> m_impl;

            void AnalyzeFileInternal(
                const uint8_t* buffer,
                size_t size,
                const std::wstring& filePath,
                const MetamorphicAnalysisConfig& config,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzeProcessInternal(
                HANDLE hProcess,
                uint32_t processId,
                const MetamorphicAnalysisConfig& config,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzeMetamorphicTechniques(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzePolymorphicTechniques(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzeSelfModifyingTechniques(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzeObfuscationTechniques(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzeVMProtection(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void AnalyzePacking(
                const uint8_t* buffer,
                size_t size,
                MetamorphicResult& result
            ) noexcept;

            void PerformSimilarityAnalysis(
                const std::wstring& filePath,
                MetamorphicResult& result
            ) noexcept;

            void CalculateMutationScore(MetamorphicResult& result) noexcept;

            void AddDetection(
                MetamorphicResult& result,
                MetamorphicDetectedTechnique detection
            ) noexcept;

            void UpdateCache(
                const std::wstring& filePath,
                const MetamorphicResult& result
            ) noexcept;
        };

        /**
         * @brief Builder for detections
         */
        class MetamorphicDetectionBuilder {
        public:
            MetamorphicDetectionBuilder() = default;

            MetamorphicDetectionBuilder& Technique(MetamorphicTechnique tech) noexcept {
                m_detection.technique = tech;
                m_detection.category = GetTechniqueCategory(tech);
                m_detection.severity = GetDefaultTechniqueSeverity(tech);
                m_detection.mitreId = MetamorphicTechniqueToMitreId(tech);
                return *this;
            }

            MetamorphicDetectionBuilder& Confidence(double conf) noexcept {
                m_detection.confidence = conf;
                return *this;
            }

            MetamorphicDetectionBuilder& Location(uint64_t loc) noexcept {
                m_detection.location = loc;
                return *this;
            }

            MetamorphicDetectionBuilder& ArtifactSize(size_t size) noexcept {
                m_detection.artifactSize = size;
                return *this;
            }

            MetamorphicDetectionBuilder& Description(std::wstring_view desc) noexcept {
                m_detection.description = desc;
                return *this;
            }

            MetamorphicDetectionBuilder& TechnicalDetails(std::wstring_view details) noexcept {
                m_detection.technicalDetails = details;
                return *this;
            }

            MetamorphicDetectionBuilder& Severity(MetamorphicSeverity sev) noexcept {
                m_detection.severity = sev;
                return *this;
            }

            MetamorphicDetectionBuilder& RawData(const uint8_t* data, size_t size) noexcept {
                if (data && size > 0) {
                    m_detection.rawData.assign(data, data + size);
                }
                return *this;
            }

            [[nodiscard]] MetamorphicDetectedTechnique Build() noexcept {
                m_detection.detectionTime = std::chrono::system_clock::now();
                return std::move(m_detection);
            }

        private:
            MetamorphicDetectedTechnique m_detection;
        };

    } // namespace AntiEvasion
} // namespace ShadowStrike