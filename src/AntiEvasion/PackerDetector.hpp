/**
 * @file PackerDetector.hpp
 * @brief Enterprise-grade detection of executable packers, protectors, and crypters
 *
 * ShadowStrike AntiEvasion - Packer Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module provides comprehensive detection and identification of executable
 * packers, protectors, crypters, and obfuscators used to evade static analysis.
 * It combines multiple detection techniques for high-accuracy identification:
 *
 * ENTROPY ANALYSIS:
 * - Shannon entropy calculation (section-level and file-level)
 * - Entropy distribution analysis
 * - Chi-squared randomness testing
 * - Kolmogorov-Smirnov distribution test
 * - Compressed vs encrypted differentiation
 *
 * PE STRUCTURAL ANALYSIS:
 * - Section name pattern matching (200+ known packer sections)
 * - Entry point location analysis (outside code section detection)
 * - Section characteristics anomalies
 * - Import table analysis (minimal imports pattern)
 * - Resource section analysis
 * - Overlay detection and analysis
 * - TLS callback detection
 * - Rich header analysis
 * - Debug directory stripping
 * - Relocation anomalies
 *
 * SIGNATURE-BASED DETECTION:
 * - Entry point signature matching (500+ packers)
 * - YARA rule scanning
 * - Byte pattern recognition
 * - Structural signature matching
 * - Version-specific detection
 *
 * HEURISTIC ANALYSIS:
 * - Stub/loader code detection
 * - Decompression routine identification
 * - Decryption loop patterns
 * - Anti-unpacking techniques
 * - Self-modifying code indicators
 *
 * CODE ANALYSIS:
 * - Import Address Table (IAT) reconstruction hints
 * - Original Entry Point (OEP) estimation
 * - Unpacking stub identification
 * - API resolution patterns (GetProcAddress chains)
 *
 * ============================================================================
 * SUPPORTED PACKERS (500+)
 * ============================================================================
 *
 * COMPRESSION PACKERS:
 * - UPX (Ultimate Packer for eXecutables) - All versions
 * - ASPack - v1.x to v2.x
 * - PECompact - v1.x to v3.x
 * - MPRESS - v1.x to v2.x
 * - Petite - v1.x to v2.x
 * - FSG (Fast Small Good) - v1.x to v2.x
 * - MEW - v10, v11
 * - NsPack - v2.x to v3.x
 * - Upack - v0.3x to v0.4x
 * - WinUpack - v0.3x
 * - kkrunchy - v0.23
 * - RLPack - v1.x
 * - JDPack
 * - BeRoEXEPacker
 * - CExe
 *
 * PROTECTORS:
 * - Themida/WinLicense - v1.x to v3.x
 * - VMProtect - v1.x to v3.x
 * - Enigma Protector - v1.x to v7.x
 * - ASProtect - v1.x to v2.x
 * - Armadillo - v1.x to v9.x
 * - ExeCryptor - v1.x to v2.x
 * - Obsidium - v1.x to v1.6.x
 * - PELock - v1.x to v2.x
 * - StarForce - v3.x to v5.x
 * - SecuROM - v4.x to v8.x
 * - SafeDisc - v1.x to v4.x
 * - Code Virtualizer - v1.x to v3.x
 * - EXECryptor - v2.x
 * - Safengine - v2.x
 * - ACProtect - v1.x to v2.x
 *
 * CRYPTERS:
 * - UPX Scrambler
 * - PESpin - v0.x to v1.x
 * - Yoda's Crypter
 * - Yoda's Protector
 * - tElock - v0.x to v1.x
 * - PECrypt32
 * - Private crypters (heuristic detection)
 *
 * .NET PROTECTORS:
 * - ConfuserEx - v0.x to v1.x
 * - .NET Reactor - v4.x to v6.x
 * - Eazfuscator.NET
 * - Dotfuscator
 * - SmartAssembly
 * - Agile.NET (CliSecure)
 * - Babel.NET
 * - Crypto Obfuscator
 * - MaxtoCode
 * - CodeVeil
 * - Spices.Net
 * - Goliath.NET
 * - ILProtector
 *
 * INSTALLERS (for differentiation):
 * - NSIS (Nullsoft Scriptable Install System)
 * - Inno Setup
 * - InstallShield
 * - WiX
 * - Advanced Installer
 * - Setup Factory
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - File analysis (1MB): < 50ms
 * - Entropy calculation: < 10ms per MB
 * - Signature matching: < 20ms
 * - Full detection pipeline: < 100ms
 * - Batch analysis (100 files): < 3 seconds
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - SignatureStore - YARA rules and byte patterns
 * - PatternStore - Entry point signatures
 * - PE_sig_verf - Authenticode validation
 * - HashStore - Known packer hash database
 * - ThreatIntel - Packer correlation with malware families
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1027.002: Software Packing
 * - T1027.005: Indicator Removal from Tools
 * - T1480: Execution Guardrails (protector checks)
 * - T1140: Deobfuscate/Decode Files or Information
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
#include "../Utils/PE_sig_verf.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"

// ============================================================================
// ASSEMBLY FUNCTION DECLARATIONS (PackerDetector_x64.asm)
// ============================================================================
// These functions provide low-level detection capabilities that cannot be
// reliably implemented in C++ due to compiler optimizations.
// ============================================================================

extern "C" {
    // ========================================================================
    // TIMING-BASED DETECTION
    // ========================================================================
    
    /// @brief Get current RDTSC timestamp value
    /// @return 64-bit timestamp (EDX:EAX combined)
    uint64_t GetRDTSCValue() noexcept;
    
    /// @brief Get serializing RDTSCP timestamp value with processor ID
    /// @param processorId Optional pointer to store processor ID (can be NULL)
    /// @return 64-bit timestamp
    uint64_t GetRDTSCPValue(uint32_t* processorId) noexcept;
    
    /// @brief Measure RDTSC delta for unpacker stub timing analysis
    /// @param code Pointer to code to measure
    /// @param size Size of code region
    /// @param startTime Pointer to store start timestamp
    /// @param endTime Pointer to store end timestamp
    /// @return Delta (end - start)
    uint64_t MeasureUnpackStubTiming(const uint8_t* code, size_t size,
        uint64_t* startTime, uint64_t* endTime) noexcept;
    
    /// @brief Measure timing of instruction sequence
    /// @param iterations Number of iterations
    /// @return Average cycles per iteration
    uint64_t MeasureInstructionSequence(size_t iterations) noexcept;
    
    /// @brief Detect timing anomalies indicating VM/debugging
    /// @param threshold Threshold for anomaly detection (cycles)
    /// @return 1 if anomaly detected, 0 otherwise
    uint64_t DetectTimingAnomaly(uint64_t threshold) noexcept;
    
    // ========================================================================
    // DEBUG REGISTER MONITORING
    // ========================================================================
    
    /// @brief Read all debug registers
    /// @param registers Pointer to 8-element uint64_t array
    /// @return 1 if successful, 0 if failed
    uint64_t GetDebugRegistersForUnpacker(uint64_t* registers) noexcept;
    
    /// @brief Check for active hardware breakpoints
    /// @param dr7Value Pointer to DR7 value
    /// @return Number of active breakpoints (0-4)
    uint64_t CheckHardwareBreakpointTraps(const uint64_t* dr7Value) noexcept;
    
    /// @brief Read individual debug registers (SEH-safe)
    uint64_t ReadDR0() noexcept;
    uint64_t ReadDR1() noexcept;
    uint64_t ReadDR2() noexcept;
    uint64_t ReadDR3() noexcept;
    uint64_t ReadDR6() noexcept;
    uint64_t ReadDR7() noexcept;
    
    // ========================================================================
    // ANTI-UNPACKING DETECTION
    // ========================================================================
    
    /// @brief Detect RDTSC-based anti-debugging in unpacker
    /// @param sampleCount Number of samples to take
    /// @param samples Pointer to array for samples
    /// @return 1 if anti-debug detected, 0 otherwise
    uint64_t DetectRDTSCAntiDebug(size_t sampleCount, uint64_t* samples) noexcept;
    
    /// @brief SIMD-accelerated scan for anti-debugging opcodes
    /// @param buffer Code buffer
    /// @param size Buffer size
    /// @param flags Pointer to result flags (bit 0=INT2D, bit 1=INT3, etc.)
    /// @return Total count of anti-debug opcodes found
    uint64_t ScanForAntiDebugOpcodes(const uint8_t* buffer, size_t size,
        uint32_t* flags) noexcept;
    
    /// @brief Individual opcode scanners
    /// @return Offset if found, -1 if not found
    int64_t ScanForInt2DOpcode(const uint8_t* buffer, size_t size) noexcept;
    int64_t ScanForRDTSCOpcode(const uint8_t* buffer, size_t size) noexcept;
    int64_t ScanForCPUIDOpcode(const uint8_t* buffer, size_t size) noexcept;
    
    // ========================================================================
    // CODE ANALYSIS
    // ========================================================================
    
    /// @brief Check if code page is writable (SMC indicator)
    /// @param address Address to check
    /// @return 1 if writable, 0 if not
    uint64_t CheckCodePageWritability(const void* address) noexcept;
    
    /// @brief Scan for self-modifying code patterns
    /// @param buffer Code buffer
    /// @param size Buffer size
    /// @return Count of SMC patterns found
    uint64_t ScanForSMCPatterns(const uint8_t* buffer, size_t size) noexcept;
    
    /// @brief Scan for XOR decryption loop patterns
    /// @param buffer Code buffer
    /// @param size Buffer size
    /// @return Count of XOR decryption patterns found
    uint64_t ScanForXORDecryptionLoop(const uint8_t* buffer, size_t size) noexcept;
    
    /// @brief Scan for API hashing patterns (ROL/ROR + XOR)
    /// @param buffer Code buffer
    /// @param size Buffer size
    /// @return Count of API hashing patterns found
    uint64_t ScanForAPIHashingPattern(const uint8_t* buffer, size_t size) noexcept;
    
    // ========================================================================
    // SIMD-ACCELERATED SCANNING
    // ========================================================================
    
    /// @brief Fast SIMD scan for a specific byte value
    /// @param buffer Buffer to search
    /// @param size Buffer size
    /// @param byteValue Byte to find
    /// @return Offset of first occurrence, -1 if not found
    int64_t SIMDScanForByte(const uint8_t* buffer, size_t size, uint8_t byteValue) noexcept;
    
    /// @brief Fast SIMD scan for a 2-byte word value
    /// @param buffer Buffer to search
    /// @param size Buffer size
    /// @param wordValue Word to find
    /// @return Offset of first occurrence, -1 if not found
    int64_t SIMDScanForWord(const uint8_t* buffer, size_t size, uint16_t wordValue) noexcept;
    
    /// @brief Fast scan for a multi-byte pattern
    /// @param buffer Buffer to search
    /// @param bufferSize Buffer size
    /// @param pattern Pattern to find
    /// @param patternSize Pattern size
    /// @return Offset of first occurrence, -1 if not found
    int64_t SIMDScanForPattern(const uint8_t* buffer, size_t bufferSize,
        const uint8_t* pattern, size_t patternSize) noexcept;
}

// Forward declarations
namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace PackerConstants {

            // ========================================================================
            // RESOURCE LIMITS
            // ========================================================================

            /// @brief Maximum file size to analyze (500 MB)
            inline constexpr size_t MAX_FILE_SIZE = 500 * 1024 * 1024;

            /// @brief Maximum overlay size to analyze (100 MB)
            inline constexpr size_t MAX_OVERLAY_SIZE = 100 * 1024 * 1024;

            /// @brief Maximum sections to analyze
            inline constexpr size_t MAX_SECTIONS = 256;

            /// @brief Maximum imports to enumerate
            inline constexpr size_t MAX_IMPORTS = 100000;

            /// @brief Maximum exports to enumerate
            inline constexpr size_t MAX_EXPORTS = 100000;

            /// @brief Default scan timeout (milliseconds)
            inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;

            /// @brief Cache TTL (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 600;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 8192;

            // ========================================================================
            // ENTROPY THRESHOLDS
            // ========================================================================

            /// @brief Minimum entropy for compressed data
            inline constexpr double MIN_COMPRESSED_ENTROPY = 6.0;

            /// @brief Minimum entropy for encrypted data
            inline constexpr double MIN_ENCRYPTED_ENTROPY = 7.0;

            /// @brief Maximum entropy (theoretical limit is 8.0)
            inline constexpr double MAX_THEORETICAL_ENTROPY = 8.0;

            /// @brief High entropy threshold for section analysis
            inline constexpr double HIGH_SECTION_ENTROPY = 6.5;

            /// @brief Very high entropy threshold (likely encrypted)
            inline constexpr double VERY_HIGH_ENTROPY = 7.5;

            /// @brief Normal code section entropy range (lower bound)
            inline constexpr double NORMAL_CODE_ENTROPY_MIN = 4.0;

            /// @brief Normal code section entropy range (upper bound)
            inline constexpr double NORMAL_CODE_ENTROPY_MAX = 6.5;

            /// @brief Normal data section entropy range (upper bound)
            inline constexpr double NORMAL_DATA_ENTROPY_MAX = 5.5;

            // ========================================================================
            // DETECTION THRESHOLDS
            // ========================================================================

            /// @brief Minimum packing confidence to report (0.0 - 1.0)
            inline constexpr double MIN_PACKING_CONFIDENCE = 0.3;

            /// @brief High confidence threshold
            inline constexpr double HIGH_CONFIDENCE_THRESHOLD = 0.75;

            /// @brief Definite packing threshold
            inline constexpr double DEFINITE_PACKING_THRESHOLD = 0.9;

            /// @brief Minimum imports for normal executable
            inline constexpr size_t MIN_NORMAL_IMPORTS = 5;

            /// @brief Suspicious import count (very few)
            inline constexpr size_t SUSPICIOUS_LOW_IMPORT_COUNT = 3;

            /// @brief Entry point stub size for signature matching
            inline constexpr size_t EP_SIGNATURE_SIZE = 256;

            /// @brief Overlay threshold percentage of file size
            inline constexpr double SUSPICIOUS_OVERLAY_PERCENTAGE = 50.0;

            // ========================================================================
            // SCORING WEIGHTS
            // ========================================================================

            /// @brief Weight for entropy analysis
            inline constexpr double WEIGHT_ENTROPY = 2.0;

            /// @brief Weight for section anomalies
            inline constexpr double WEIGHT_SECTION_ANOMALIES = 1.5;

            /// @brief Weight for EP signature match
            inline constexpr double WEIGHT_EP_SIGNATURE = 3.0;

            /// @brief Weight for import anomalies
            inline constexpr double WEIGHT_IMPORT_ANOMALIES = 1.5;

            /// @brief Weight for YARA match
            inline constexpr double WEIGHT_YARA_MATCH = 2.5;

            /// @brief Weight for overlay presence
            inline constexpr double WEIGHT_OVERLAY = 1.0;

            /// @brief Weight for structural anomalies
            inline constexpr double WEIGHT_STRUCTURAL = 1.5;

            /// @brief Weight for code signature absence
            inline constexpr double WEIGHT_NO_SIGNATURE = 0.5;

            // ========================================================================
            // KNOWN SECTION NAMES
            // ========================================================================

            /// @brief Known packer section names (lowercase for comparison)
            inline constexpr std::array<std::string_view, 64> KNOWN_PACKER_SECTIONS = { {
                    // UPX
                    "upx0", "upx1", "upx2", ".upx", ".upx0", ".upx1", ".upx2",
                    // ASPack
                    ".aspack", ".adata", ".asdata",
                    // PECompact
                    ".pec1", ".pec2", "pec1", "pec2", ".pec",
                    // Themida/WinLicense
                    ".themida", ".winlicen", ".vmp0", ".vmp1", ".vmp2",
                    // VMProtect
                    ".vmp", ".vmp0", ".vmp1", ".vmp2",
                    // Enigma
                    ".enigma1", ".enigma2", ".enig",
                    // Armadillo
                    ".armd", ".arma",
                    // ASProtect
                    ".aspr", ".asprdata",
                    // Petite
                    ".petite",
                    // FSG
                    ".fsg",
                    // MEW
                    ".mew",
                    // NsPack
                    ".nsp0", ".nsp1", ".nsp2", ".nspack",
                    // tElock
                    ".tlock",
                    // PESpin
                    ".pespin",
                    // Yoda
                    ".yoda", ".yP",
                    // Obsidium
                    ".obs", ".obsd",
                    // PELock
                    ".plock",
                    // MPRESS
                    ".mpress1", ".mpress2",
                    // kkrunchy
                    ".kkrunchy",
                    // RLPack
                    ".rl", ".rlpack",
                    // Upack
                    ".upack", ".rsrc",
                    // Generic suspicious
                    ".packed", ".crypted", ".encrypt", ".protect", ".stub"
                } };

            /// @brief Known installer section names (for differentiation)
            inline constexpr std::array<std::string_view, 16> INSTALLER_SECTIONS = { {
                ".ndata",      // NSIS
                ".nsis",       // NSIS
                ".inno",       // Inno Setup
                ".is",         // InstallShield
                ".setup",      // Generic
                ".inst",       // Generic
                ".msi",        // Windows Installer
                "CODE",        // Delphi/Inno
                "DATA",        // Delphi/Inno
                "BSS",         // Delphi/Inno
                ".idata",      // Import data
                ".tls",        // TLS
                ".CRT",        // C Runtime
                ".gfids",      // Control Flow Guard
                ".00cfg",      // CFG
                ".retplne"     // Retpoline
            } };

            /// @brief Suspicious executable-writable section names
            inline constexpr std::array<std::string_view, 8> SUSPICIOUS_RWX_SECTIONS = { {
                ".text", ".code", "CODE", ".rdata", ".data", ".bss", ".rsrc", ".reloc"
            } };

        } // namespace PackerConstants

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Packer family categories
         */
        enum class PackerCategory : uint8_t {
            /// @brief Unknown/unidentified
            Unknown = 0,

            /// @brief Pure compression (UPX, ASPack)
            Compression = 1,

            /// @brief Commercial protector (Themida, VMProtect)
            Protector = 2,

            /// @brief Encryption-focused (crypters)
            Crypter = 3,

            /// @brief .NET obfuscator/protector
            DotNetProtector = 4,

            /// @brief Installer/SFX archive
            Installer = 5,

            /// @brief VM-based protection
            VMProtection = 6,

            /// @brief Custom/private packer
            Custom = 7,

            /// @brief Malware-specific packer
            MalwarePacker = 8,

            /// @brief Legitimate software protection
            LegitimateProtection = 9,

            /// @brief Self-extracting archive
            SFXArchive = 10,

            /// @brief Combined (multiple layers)
            MultiLayer = 11
        };

        /**
         * @brief Specific packer identifiers
         */
        enum class PackerType : uint16_t {
            /// @brief Unknown packer
            Unknown = 0,

            // ========================================================================
            // COMPRESSION PACKERS (1-100)
            // ========================================================================

            /// @brief UPX (all versions)
            UPX = 1,
            UPX_Modified = 2,
            UPX_Scrambled = 3,

            /// @brief ASPack
            ASPack = 10,
            ASPack_v1 = 11,
            ASPack_v2 = 12,

            /// @brief PECompact
            PECompact = 20,
            PECompact_v1 = 21,
            PECompact_v2 = 22,
            PECompact_v3 = 23,

            /// @brief MPRESS
            MPRESS = 30,
            MPRESS_v1 = 31,
            MPRESS_v2 = 32,

            /// @brief Petite
            Petite = 40,
            Petite_v1 = 41,
            Petite_v2 = 42,

            /// @brief FSG
            FSG = 50,
            FSG_v1 = 51,
            FSG_v2 = 52,

            /// @brief MEW
            MEW = 60,
            MEW_v10 = 61,
            MEW_v11 = 62,

            /// @brief NsPack
            NsPack = 70,
            NsPack_v2 = 71,
            NsPack_v3 = 72,

            /// @brief Upack/WinUpack
            Upack = 80,
            WinUpack = 81,

            /// @brief Other compression packers
            kkrunchy = 90,
            RLPack = 91,
            JDPack = 92,
            BeRoEXEPacker = 93,
            CExe = 94,
            Packman = 95,
            PEPack = 96,
            WWPack32 = 97,

            // ========================================================================
            // PROTECTORS (101-200)
            // ========================================================================

            /// @brief Themida/WinLicense
            Themida = 101,
            Themida_v1 = 102,
            Themida_v2 = 103,
            Themida_v3 = 104,
            WinLicense = 105,

            /// @brief VMProtect
            VMProtect = 110,
            VMProtect_v1 = 111,
            VMProtect_v2 = 112,
            VMProtect_v3 = 113,

            /// @brief Enigma Protector
            Enigma = 120,
            Enigma_v1 = 121,
            Enigma_v4 = 122,
            Enigma_v6 = 123,
            Enigma_v7 = 124,

            /// @brief ASProtect
            ASProtect = 130,
            ASProtect_v1 = 131,
            ASProtect_v2 = 132,
            ASProtect_SKE = 133,

            /// @brief Armadillo
            Armadillo = 140,
            Armadillo_v3 = 141,
            Armadillo_v4 = 142,
            Armadillo_v9 = 143,

            /// @brief Obsidium
            Obsidium = 150,
            Obsidium_v1 = 151,

            /// @brief PELock
            PELock = 160,
            PELock_v1 = 161,
            PELock_v2 = 162,

            /// @brief Code Virtualizer
            CodeVirtualizer = 170,
            CodeVirtualizer_v1 = 171,
            CodeVirtualizer_v2 = 172,
            CodeVirtualizer_v3 = 173,

            /// @brief ExeCryptor
            ExeCryptor = 180,
            ExeCryptor_v2 = 181,

            /// @brief Other protectors
            Safengine = 190,
            ACProtect = 191,
            EXEShield = 192,
            SVKProtector = 193,
            PCGuard = 194,
            AntiCrack = 195,

            // ========================================================================
            // GAME/DRM PROTECTORS (201-250)
            // ========================================================================

            /// @brief StarForce
            StarForce = 201,
            StarForce_v3 = 202,
            StarForce_v5 = 203,

            /// @brief SecuROM
            SecuROM = 210,
            SecuROM_v4 = 211,
            SecuROM_v7 = 212,
            SecuROM_v8 = 213,

            /// @brief SafeDisc
            SafeDisc = 220,
            SafeDisc_v2 = 221,
            SafeDisc_v4 = 222,

            /// @brief Denuvo
            Denuvo = 230,

            /// @brief Other DRM
            SolidShield = 240,
            TagESProtect = 241,
            CDilla = 242,

            // ========================================================================
            // CRYPTERS (251-300)
            // ========================================================================

            /// @brief PESpin
            PESpin = 251,
            PESpin_v0 = 252,
            PESpin_v1 = 253,

            /// @brief tElock
            tElock = 260,
            tElock_v0 = 261,
            tElock_v1 = 262,

            /// @brief Yoda
            YodaCrypter = 270,
            YodaProtector = 271,

            /// @brief Other crypters
            PECrypt32 = 280,
            Morphine = 281,
            Neolite = 282,
            EXECryptor = 283,
            SDProtector = 284,
            PE_Armor = 285,
            PolyCrypt = 286,
            PEX = 287,
            CrypKey = 288,

            // ========================================================================
            // .NET PROTECTORS (301-350)
            // ========================================================================

            /// @brief ConfuserEx
            ConfuserEx = 301,
            ConfuserEx_v0 = 302,
            ConfuserEx_v1 = 303,
            Confuser = 304,

            /// @brief .NET Reactor
            DotNetReactor = 310,
            DotNetReactor_v4 = 311,
            DotNetReactor_v5 = 312,
            DotNetReactor_v6 = 313,

            /// @brief Other .NET protectors
            Eazfuscator = 320,
            Dotfuscator = 321,
            SmartAssembly = 322,
            AgileNET = 323,
            BabelNET = 324,
            CryptoObfuscator = 325,
            MaxtoCode = 326,
            CodeVeil = 327,
            SpicesNET = 328,
            GoliathNET = 329,
            ILProtector = 330,
            Phoenix_Protector = 331,
            DeepSea = 332,
            Xenocode = 333,

            // ========================================================================
            // INSTALLERS (351-400)
            // ========================================================================

            /// @brief NSIS
            NSIS = 351,
            NSIS_v2 = 352,
            NSIS_v3 = 353,

            /// @brief Inno Setup
            InnoSetup = 360,
            InnoSetup_v5 = 361,
            InnoSetup_v6 = 362,

            /// @brief InstallShield
            InstallShield = 370,

            /// @brief Other installers
            WiX = 380,
            AdvancedInstaller = 381,
            SetupFactory = 382,
            CreateInstall = 383,
            InstallAware = 384,
            Wise = 385,
            Ghost_Installer = 386,

            // ========================================================================
            // SFX ARCHIVES (401-420)
            // ========================================================================

            /// @brief 7-Zip SFX
            SevenZip_SFX = 401,

            /// @brief WinRAR SFX
            WinRAR_SFX = 402,

            /// @brief WinZip SFX
            WinZip_SFX = 403,

            /// @brief Other SFX
            Zip_SFX = 404,
            CAB_SFX = 405,
            ARJ_SFX = 406,

            // ========================================================================
            // MALWARE-SPECIFIC PACKERS (421-500)
            // ========================================================================

            /// @brief Malware-associated packers
            CrypterX = 421,
            NJCrypter = 422,
            DarkComet_Stub = 423,
            Andromeda_Loader = 424,
            SmokeLoader_Packer = 425,
            Emotet_Packer = 426,
            Trickbot_Packer = 427,
            Dridex_Packer = 428,
            QakBot_Packer = 429,
            IcedID_Packer = 430,
            BazarLoader_Packer = 431,
            Ryuk_Packer = 432,
            Conti_Packer = 433,
            Cobalt_Strike_Beacon = 434,

            /// @brief Custom/private packers
            Custom_Packer = 499,

            /// @brief Maximum packer ID
            _MaxPackerId = 500
        };

        /**
         * @brief Detection method used
         */
        enum class DetectionMethod : uint8_t {
            /// @brief Unknown method
            Unknown = 0,

            /// @brief Entry point signature match
            EPSignature = 1,

            /// @brief Section name match
            SectionName = 2,

            /// @brief YARA rule match
            YARARule = 3,

            /// @brief Entropy analysis
            EntropyAnalysis = 4,

            /// @brief Import analysis
            ImportAnalysis = 5,

            /// @brief Structural analysis
            StructuralAnalysis = 6,

            /// @brief Heuristic detection
            Heuristic = 7,

            /// @brief String analysis
            StringAnalysis = 8,

            /// @brief Hash match (known sample)
            HashMatch = 9,

            /// @brief Overlay analysis
            OverlayAnalysis = 10,

            /// @brief Rich header analysis
            RichHeaderAnalysis = 11,

            /// @brief Resource analysis
            ResourceAnalysis = 12,

            /// @brief Multiple methods combined
            Combined = 255
        };

        /**
         * @brief Severity/impact level
         */
        enum class PackerSeverity : uint8_t {
            /// @brief Benign (legitimate software)
            Benign = 0,

            /// @brief Low (common packers, installers)
            Low = 1,

            /// @brief Medium (commercial protectors)
            Medium = 2,

            /// @brief High (crypters, suspicious)
            High = 3,

            /// @brief Critical (malware-specific packers)
            Critical = 4
        };

        /**
         * @brief Analysis depth level
         */
        enum class PackerAnalysisDepth : uint8_t {
            /// @brief Quick (entropy + EP signature)
            Quick = 0,

            /// @brief Standard (+ sections + imports)
            Standard = 1,

            /// @brief Deep (+ YARA + heuristics)
            Deep = 2,

            /// @brief Comprehensive (all techniques)
            Comprehensive = 3
        };

        /**
         * @brief Analysis flags
         */
        enum class PackerAnalysisFlags : uint32_t {
            None = 0,

            // Detection techniques
            EnableEntropyAnalysis = 1 << 0,
            EnableSectionAnalysis = 1 << 1,
            EnableEPSignature = 1 << 2,
            EnableYARAScanning = 1 << 3,
            EnableImportAnalysis = 1 << 4,
            EnableOverlayAnalysis = 1 << 5,
            EnableResourceAnalysis = 1 << 6,
            EnableRichHeaderAnalysis = 1 << 7,
            EnableStringAnalysis = 1 << 8,
            EnableHeuristicAnalysis = 1 << 9,
            EnableSignatureVerification = 1 << 10,

            // Behavior flags
            EnableCaching = 1 << 16,
            EnableParallelScan = 1 << 17,
            StopOnFirstMatch = 1 << 18,
            IncludeLayerAnalysis = 1 << 19,
            IncludeUnpackingHints = 1 << 20,
            IncludeRawData = 1 << 21,

            // Presets
            QuickScan = EnableEntropyAnalysis | EnableSectionAnalysis | EnableEPSignature | EnableCaching,
            StandardScan = QuickScan | EnableImportAnalysis | EnableOverlayAnalysis | EnableSignatureVerification,
            DeepScan = StandardScan | EnableYARAScanning | EnableResourceAnalysis | EnableHeuristicAnalysis,
            ComprehensiveScan = 0x07FF | EnableCaching | EnableParallelScan | IncludeLayerAnalysis | IncludeUnpackingHints,

            Default = StandardScan
        };

        // Bitwise operators
        inline constexpr PackerAnalysisFlags operator|(PackerAnalysisFlags a, PackerAnalysisFlags b) noexcept {
            return static_cast<PackerAnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr PackerAnalysisFlags operator&(PackerAnalysisFlags a, PackerAnalysisFlags b) noexcept {
            return static_cast<PackerAnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr bool HasFlag(PackerAnalysisFlags flags, PackerAnalysisFlags flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Get string name for packer category
         */
        [[nodiscard]] constexpr const char* PackerCategoryToString(PackerCategory category) noexcept {
            switch (category) {
            case PackerCategory::Compression:        return "Compression Packer";
            case PackerCategory::Protector:          return "Protector";
            case PackerCategory::Crypter:            return "Crypter";
            case PackerCategory::DotNetProtector:    return ".NET Protector";
            case PackerCategory::Installer:          return "Installer";
            case PackerCategory::VMProtection:       return "VM Protection";
            case PackerCategory::Custom:             return "Custom Packer";
            case PackerCategory::MalwarePacker:      return "Malware Packer";
            case PackerCategory::LegitimateProtection: return "Legitimate Protection";
            case PackerCategory::SFXArchive:         return "SFX Archive";
            case PackerCategory::MultiLayer:         return "Multi-Layer";
            default:                                 return "Unknown";
            }
        }

        /**
         * @brief Get display name for packer type
         */
        [[nodiscard]] const wchar_t* PackerTypeToString(PackerType type) noexcept;

        /**
         * @brief Get MITRE ATT&CK ID for packer
         */
        [[nodiscard]] constexpr const char* PackerTypeToMitreId(PackerType type) noexcept {
            const auto id = static_cast<uint16_t>(type);

            // Malware-specific packers
            if (id >= 421 && id <= 500) return "T1027.002";

            // Crypters
            if (id >= 251 && id <= 300) return "T1027.002";

            // Protectors
            if (id >= 101 && id <= 250) return "T1027.002";

            // Compression
            if (id >= 1 && id <= 100) return "T1027.002";

            return "T1027.002";
        }

        /**
         * @brief Get category for packer type
         */
        [[nodiscard]] constexpr PackerCategory GetPackerCategory(PackerType type) noexcept {
            const auto id = static_cast<uint16_t>(type);

            if (id >= 1 && id <= 100)   return PackerCategory::Compression;
            if (id >= 101 && id <= 200) return PackerCategory::Protector;
            if (id >= 201 && id <= 250) return PackerCategory::LegitimateProtection;
            if (id >= 251 && id <= 300) return PackerCategory::Crypter;
            if (id >= 301 && id <= 350) return PackerCategory::DotNetProtector;
            if (id >= 351 && id <= 400) return PackerCategory::Installer;
            if (id >= 401 && id <= 420) return PackerCategory::SFXArchive;
            if (id >= 421 && id <= 500) return PackerCategory::MalwarePacker;

            return PackerCategory::Unknown;
        }

        /**
         * @brief Get default severity for packer type
         */
        [[nodiscard]] constexpr PackerSeverity GetPackerSeverity(PackerType type) noexcept {
            const auto id = static_cast<uint16_t>(type);

            // Malware-specific packers
            if (id >= 421 && id <= 500) return PackerSeverity::Critical;

            // Crypters
            if (id >= 251 && id <= 300) return PackerSeverity::High;

            // VM Protection
            if (type == PackerType::VMProtect || type == PackerType::Themida ||
                type == PackerType::CodeVirtualizer) {
                return PackerSeverity::Medium;
            }

            // Commercial protectors
            if (id >= 101 && id <= 200) return PackerSeverity::Medium;

            // Installers
            if (id >= 351 && id <= 400) return PackerSeverity::Benign;

            // SFX Archives
            if (id >= 401 && id <= 420) return PackerSeverity::Low;

            // Common compression packers
            if (id >= 1 && id <= 100) return PackerSeverity::Low;

            return PackerSeverity::Low;
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Error information
         */
        struct PackerError {
            DWORD win32Code = ERROR_SUCCESS;
            std::wstring message;
            std::wstring context;

            [[nodiscard]] bool HasError() const noexcept { return win32Code != ERROR_SUCCESS; }
            void Clear() noexcept { win32Code = ERROR_SUCCESS; message.clear(); context.clear(); }
        };

        /**
         * @brief Section analysis information
         */
        struct SectionInfo {
            /// @brief Section name (may be truncated to 8 chars)
            std::string name;

            /// @brief Virtual address
            uint32_t virtualAddress = 0;

            /// @brief Virtual size
            uint32_t virtualSize = 0;

            /// @brief Raw (file) size
            uint32_t rawSize = 0;

            /// @brief Raw data pointer
            uint32_t rawDataPointer = 0;

            /// @brief Section characteristics
            uint32_t characteristics = 0;

            /// @brief Section entropy
            double entropy = 0.0;

            /// @brief Is executable
            bool isExecutable = false;

            /// @brief Is writable
            bool isWritable = false;

            /// @brief Is readable
            bool isReadable = false;

            /// @brief Has high entropy
            bool hasHighEntropy = false;

            /// @brief Is empty (virtualSize > 0, rawSize == 0)
            bool isEmpty = false;

            /// @brief Name matches known packer
            bool isPackerSection = false;

            /// @brief Matched packer name (if isPackerSection)
            std::string matchedPackerName;

            /// @brief Anomalies detected
            std::vector<std::wstring> anomalies;
        };

        /**
         * @brief Import analysis information
         */
        struct ImportInfo {
            /// @brief Total import count
            size_t totalImports = 0;

            /// @brief Total DLL count
            size_t dllCount = 0;

            /// @brief Has GetProcAddress
            bool hasGetProcAddress = false;

            /// @brief Has LoadLibraryA/W
            bool hasLoadLibrary = false;

            /// @brief Has VirtualAlloc/VirtualProtect
            bool hasVirtualMemoryAPIs = false;

            /// @brief Has minimal imports (packing indicator)
            bool hasMinimalImports = false;

            /// @brief Imported DLLs
            std::vector<std::string> dlls;

            /// @brief Suspicious imports
            std::vector<std::wstring> suspiciousImports;

            /// @brief Import anomalies
            std::vector<std::wstring> anomalies;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Overlay analysis information
         */
        struct OverlayInfo {
            /// @brief Has overlay data
            bool hasOverlay = false;

            /// @brief Overlay offset
            uint64_t offset = 0;

            /// @brief Overlay size
            size_t size = 0;

            /// @brief Overlay entropy
            double entropy = 0.0;

            /// @brief Overlay percentage of file
            double percentageOfFile = 0.0;

            /// @brief Detected format (if recognizable)
            std::wstring detectedFormat;

            /// @brief Is compressed
            bool isCompressed = false;

            /// @brief Is encrypted
            bool isEncrypted = false;

            /// @brief Magic bytes (first 16 bytes)
            std::array<uint8_t, 16> magicBytes{};

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Entry point analysis information
         */
        struct EntryPointInfo {
            /// @brief Entry point RVA
            uint32_t rva = 0;

            /// @brief Entry point file offset
            uint32_t fileOffset = 0;

            /// @brief Entry point is in a valid section
            bool isInValidSection = false;

            /// @brief Section containing EP
            std::string containingSection;

            /// @brief EP is outside code section
            bool isOutsideCodeSection = false;

            /// @brief First bytes at EP (for signature matching)
            std::vector<uint8_t> epBytes;

            /// @brief Matched EP signature
            std::wstring matchedSignature;

            /// @brief Matched packer from EP
            PackerType matchedPacker = PackerType::Unknown;

            /// @brief Match confidence
            double matchConfidence = 0.0;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Digital signature information
         */
        struct SignatureInfo {
            /// @brief Has Authenticode signature
            bool hasSignature = false;

            /// @brief Signature is valid
            bool isValid = false;

            /// @brief Is self-signed
            bool isSelfSigned = false;

            /// @brief Certificate has been revoked
            bool isRevoked = false;

            /// @brief Signer name
            std::wstring signerName;

            /// @brief Issuer name
            std::wstring issuerName;

            /// @brief Certificate thumbprint (SHA1)
            std::string thumbprint;

            /// @brief Signing time
            std::chrono::system_clock::time_point signingTime;

            /// @brief Certificate expiry
            std::chrono::system_clock::time_point expiryTime;

            /// @brief Verification errors
            std::vector<std::wstring> errors;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Rich header analysis information
         */
        struct RichHeaderInfo {
            /// @brief Has Rich header
            bool hasRichHeader = false;

            /// @brief Rich header checksum
            uint32_t checksum = 0;

            /// @brief Compiler entries
            struct CompilerEntry {
                uint16_t buildNumber;
                uint16_t productId;
                uint32_t useCount;
                std::wstring description;
            };
            std::vector<CompilerEntry> entries;

            /// @brief Detected compiler/linker
            std::wstring detectedCompiler;

            /// @brief Is Rich header corrupted
            bool isCorrupted = false;

            /// @brief Is Rich header zeroed/stripped
            bool isStripped = false;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Detection match information
         */
        struct PackerMatch {
            /// @brief Detected packer type
            PackerType packerType = PackerType::Unknown;

            /// @brief Packer category
            PackerCategory category = PackerCategory::Unknown;

            /// @brief Detection method
            DetectionMethod method = DetectionMethod::Unknown;

            /// @brief Match confidence (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Packer display name
            std::wstring packerName;

            /// @brief Packer version (if detected)
            std::wstring version;

            /// @brief Severity
            PackerSeverity severity = PackerSeverity::Low;

            /// @brief MITRE ATT&CK ID
            std::string mitreId;

            /// @brief Matched pattern/signature (for debugging)
            std::wstring matchedPattern;

            /// @brief Location of match (offset/RVA)
            uint64_t matchLocation = 0;

            /// @brief Additional details
            std::wstring details;

            /// @brief Detection time
            std::chrono::system_clock::time_point detectionTime;
        };

        /**
         * @brief Unpacking hints for analysis
         */
        struct UnpackingHints {
            /// @brief Estimated Original Entry Point (OEP) RVA
            uint32_t estimatedOEP = 0;

            /// @brief OEP estimation method
            std::wstring oepMethod;

            /// @brief Suggested unpacking tool
            std::wstring suggestedTool;

            /// @brief Anti-unpacking techniques detected
            std::vector<std::wstring> antiUnpackingTechniques;

            /// @brief IAT reconstruction needed
            bool needsIATReconstruction = false;

            /// @brief Estimated original size
            size_t estimatedOriginalSize = 0;

            /// @brief Compression algorithm guess
            std::wstring compressionAlgorithm;

            /// @brief Encryption algorithm guess
            std::wstring encryptionAlgorithm;

            /// @brief Multiple layers detected
            bool hasMultipleLayers = false;

            /// @brief Estimated layer count
            uint32_t estimatedLayerCount = 1;

            /// @brief Unpacking complexity (1-10)
            uint32_t complexityRating = 1;

            /// @brief Additional notes
            std::vector<std::wstring> notes;

            /// @brief Valid hints
            bool valid = false;
        };

        /**
         * @brief Analysis configuration
         */
        struct PackerAnalysisConfig {
            /// @brief Analysis depth
            PackerAnalysisDepth depth = PackerAnalysisDepth::Standard;

            /// @brief Analysis flags
            PackerAnalysisFlags flags = PackerAnalysisFlags::Default;

            /// @brief Timeout in milliseconds
            uint32_t timeoutMs = PackerConstants::DEFAULT_SCAN_TIMEOUT_MS;

            /// @brief Maximum file size
            size_t maxFileSize = PackerConstants::MAX_FILE_SIZE;

            /// @brief Enable caching
            bool enableCaching = true;

            /// @brief Cache TTL
            uint32_t cacheTtlSeconds = PackerConstants::RESULT_CACHE_TTL_SECONDS;

            /// @brief Minimum confidence threshold
            double minConfidenceThreshold = PackerConstants::MIN_PACKING_CONFIDENCE;

            /// @brief Include raw data in results
            bool includeRawData = false;

            /// @brief Maximum raw data size
            size_t maxRawDataSize = 256;

            /// @brief Custom EP signatures to check
            std::vector<std::pair<std::wstring, std::vector<uint8_t>>> customSignatures;

            /// @brief Treat installers as benign
            bool treatInstallersAsBenign = true;
        };

        /**
         * @brief Resource analysis information
         */
        struct ResourceInfo {
            /// @brief Total number of resources
            size_t count = 0;

            /// @brief Number of resources with high entropy
            size_t highEntropyCount = 0;

            /// @brief Total size of all resources
            size_t totalSize = 0;

            /// @brief Largest resource size
            size_t largestResourceSize = 0;

            /// @brief Average entropy of resources
            double averageEntropy = 0.0;

            /// @brief Detected resource languages
            std::vector<uint16_t> languages;

            /// @brief Suspicious resource names/types
            std::vector<std::wstring> suspiciousResources;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Comprehensive packer detection result
         */
        struct PackingInfo {
            // ========================================================================
            // IDENTIFICATION
            // ========================================================================

            /// @brief File path analyzed
            std::wstring filePath;

            /// @brief File size
            size_t fileSize = 0;

            /// @brief SHA256 hash
            std::string sha256Hash;

            // ========================================================================
            // DETECTION SUMMARY
            // ========================================================================

            /// @brief Is file packed
            bool isPacked = false;

            /// @brief Overall packing confidence (0.0 - 1.0)
            double packingConfidence = 0.0;

            /// @brief Primary detected packer
            PackerType primaryPacker = PackerType::Unknown;

            /// @brief Primary packer name
            std::wstring packerName;

            /// @brief Primary packer version
            std::wstring packerVersion;

            /// @brief Primary packer category
            PackerCategory packerCategory = PackerCategory::Unknown;

            /// @brief Severity assessment
            PackerSeverity severity = PackerSeverity::Low;

            /// @brief Is installer (differentiation)
            bool isInstaller = false;

            /// @brief Is SFX archive
            bool isSFXArchive = false;

            /// @brief Is .NET assembly
            bool isDotNetAssembly = false;

            /// @brief Has multiple packing layers
            bool hasMultipleLayers = false;

            /// @brief Number of packing layers detected
            uint32_t layerCount = 1;

            // ========================================================================
            // DETAILED FINDINGS
            // ========================================================================

            /// @brief All packer matches (may be multiple)
            std::vector<PackerMatch> packerMatches;

            /// @brief Section analysis results
            std::vector<SectionInfo> sections;

            /// @brief Import analysis
            ImportInfo importInfo;

            /// @brief Overlay analysis
            OverlayInfo overlayInfo;

            /// @brief Entry point analysis
            EntryPointInfo entryPointInfo;

            /// @brief Digital signature info
            SignatureInfo signatureInfo;

            /// @brief Rich header analysis
            RichHeaderInfo richHeaderInfo;

            /// @brief Resource analysis
            ResourceInfo resourceInfo;

            /// @brief Unpacking hints
            UnpackingHints unpackingHints;

            // ========================================================================
            // ENTROPY METRICS
            // ========================================================================

            /// @brief Overall file entropy (0.0 - 8.0)
            double fileEntropy = 0.0;

            /// @brief Chi-squared distribution score
            double chiSquared = 0.0;

            /// @brief Monte Carlo Pi approximation error
            double monteCarloPiError = 0.0;

            /// @brief Code section entropy
            double codeSectionEntropy = 0.0;

            /// @brief Data section entropy
            double dataSectionEntropy = 0.0;

            /// @brief Highest section entropy
            double maxSectionEntropy = 0.0;

            /// @brief Section with highest entropy
            std::string maxEntropySectionName;

            /// @brief Average section entropy
            double averageSectionEntropy = 0.0;

            /// @brief Entropy indicates compression
            bool entropyIndicatesCompression = false;

            /// @brief Entropy indicates encryption
            bool entropyIndicatesEncryption = false;

            // ========================================================================
            // ANOMALIES & INDICATORS
            // ========================================================================

            /// @brief Entry point outside code section
            bool epOutsideCodeSection = false;

            /// @brief Has non-standard sections
            bool hasNonStandardSections = false;

            /// @brief Has writable code sections
            bool hasWritableCodeSections = false;

            /// @brief Has minimal imports
            bool hasMinimalImports = false;

            /// @brief Has suspicious characteristics
            bool hasSuspiciousCharacteristics = false;

            /// @brief All detected anomalies
            std::vector<std::wstring> anomalies;

            /// @brief All detection indicators
            std::vector<std::wstring> indicators;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /// @brief Total sections
            uint32_t sectionCount = 0;

            /// @brief Executable sections
            uint32_t executableSectionCount = 0;

            /// @brief Writable sections
            uint32_t writableSectionCount = 0;

            /// @brief High entropy sections
            uint32_t highEntropySectionCount = 0;

            /// @brief Packer section matches
            uint32_t packerSectionMatches = 0;

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
            PackerAnalysisConfig config;

            /// @brief Errors encountered
            std::vector<PackerError> errors;

            /// @brief Analysis completed
            bool analysisComplete = false;

            /// @brief From cache
            bool fromCache = false;

            // ========================================================================
            // METHODS
            // ========================================================================

            [[nodiscard]] bool HasMatch(PackerType type) const noexcept {
                for (const auto& match : packerMatches) {
                    if (match.packerType == type) return true;
                }
                return false;
            }

            [[nodiscard]] bool HasCategory(PackerCategory category) const noexcept {
                for (const auto& match : packerMatches) {
                    if (match.category == category) return true;
                }
                return false;
            }

            [[nodiscard]] const PackerMatch* GetBestMatch() const noexcept {
                const PackerMatch* best = nullptr;
                double bestConfidence = 0.0;
                for (const auto& match : packerMatches) {
                    if (match.confidence > bestConfidence) {
                        bestConfidence = match.confidence;
                        best = &match;
                    }
                }
                return best;
            }

            void Clear() noexcept {
                filePath.clear();
                fileSize = 0;
                sha256Hash.clear();
                isPacked = false;
                packingConfidence = 0.0;
                primaryPacker = PackerType::Unknown;
                packerName.clear();
                packerVersion.clear();
                packerCategory = PackerCategory::Unknown;
                severity = PackerSeverity::Low;
                isInstaller = false;
                isSFXArchive = false;
                isDotNetAssembly = false;
                hasMultipleLayers = false;
                layerCount = 1;
                packerMatches.clear();
                sections.clear();
                importInfo = {};
                overlayInfo = {};
                entryPointInfo = {};
                signatureInfo = {};
                richHeaderInfo = {};
                resourceInfo = {};
                unpackingHints = {};
                fileEntropy = 0.0;
                codeSectionEntropy = 0.0;
                dataSectionEntropy = 0.0;
                maxSectionEntropy = 0.0;
                maxEntropySectionName.clear();
                averageSectionEntropy = 0.0;
                entropyIndicatesCompression = false;
                entropyIndicatesEncryption = false;
                epOutsideCodeSection = false;
                hasNonStandardSections = false;
                hasWritableCodeSections = false;
                hasMinimalImports = false;
                hasSuspiciousCharacteristics = false;
                anomalies.clear();
                indicators.clear();
                sectionCount = 0;
                executableSectionCount = 0;
                writableSectionCount = 0;
                highEntropySectionCount = 0;
                packerSectionMatches = 0;
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
        struct PackerBatchResult {
            std::vector<PackingInfo> results;
            uint32_t totalFiles = 0;
            uint32_t packedFiles = 0;
            uint32_t installerFiles = 0;
            uint32_t failedFiles = 0;
            uint64_t totalDurationMs = 0;
            std::chrono::system_clock::time_point startTime;
            std::chrono::system_clock::time_point endTime;

            /// @brief Packer distribution
            std::unordered_map<PackerType, uint32_t> packerDistribution;

            /// @brief Category distribution
            std::unordered_map<PackerCategory, uint32_t> categoryDistribution;
        };

        /**
         * @brief Progress callback
         */
        using PackerProgressCallback = std::function<void(
            const std::wstring& currentFile,
            uint32_t filesProcessed,
            uint32_t totalFiles
            )>;

        /**
         * @brief Detection callback (real-time)
         */
        using PackerDetectionCallback = std::function<void(
            const std::wstring& file,
            const PackerMatch& match
            )>;

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade packer detection engine
         *
         * Detects and identifies 500+ packers, protectors, and crypters with
         * high accuracy. Thread-safe for concurrent analysis.
         *
         * Usage example:
         * @code
         *     auto detector = std::make_unique<PackerDetector>();
         *     if (!detector->Initialize()) {
         *         // Handle failure
         *     }
         *
         *     PackerAnalysisConfig config;
         *     config.depth = PackerAnalysisDepth::Deep;
         *
         *     auto result = detector->AnalyzeFile(L"C:\\suspect.exe", config);
         *     if (result.isPacked) {
         *         std::wcout << L"Packer: " << result.packerName << L"\n";
         *         std::wcout << L"Confidence: " << result.packingConfidence * 100 << L"%\n";
         *     }
         * @endcode
         */
        class PackerDetector {
        public:
            // ========================================================================
            // CONSTRUCTION & LIFECYCLE
            // ========================================================================

            /**
             * @brief Default constructor
             */
            PackerDetector() noexcept;

            /**
             * @brief Constructor with signature store
             */
            explicit PackerDetector(
                std::shared_ptr<SignatureStore::SignatureStore> sigStore
            ) noexcept;

            /**
             * @brief Constructor with all stores
             */
            PackerDetector(
                std::shared_ptr<SignatureStore::SignatureStore> sigStore,
                std::shared_ptr<PatternStore::PatternStore> patternStore,
                std::shared_ptr<HashStore::HashStore> hashStore
            ) noexcept;

            /**
             * @brief Destructor
             */
            ~PackerDetector();

            // Non-copyable, movable
            PackerDetector(const PackerDetector&) = delete;
            PackerDetector& operator=(const PackerDetector&) = delete;
            PackerDetector(PackerDetector&&) noexcept;
            PackerDetector& operator=(PackerDetector&&) noexcept;

            // ========================================================================
            // INITIALIZATION
            // ========================================================================

            /**
             * @brief Initialize the detector
             */
            [[nodiscard]] bool Initialize(PackerError* err = nullptr) noexcept;

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
             * @brief Analyze file for packing
             */
            [[nodiscard]] PackingInfo AnalyzeFile(
                const std::wstring& filePath,
                const PackerAnalysisConfig& config = PackerAnalysisConfig{},
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze buffer for packing
             */
            [[nodiscard]] PackingInfo AnalyzeBuffer(
                const uint8_t* buffer,
                size_t size,
                const PackerAnalysisConfig& config = PackerAnalysisConfig{},
                PackerError* err = nullptr
            ) noexcept;

            // ========================================================================
            // BATCH ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze multiple files
             */
            [[nodiscard]] PackerBatchResult AnalyzeFiles(
                const std::vector<std::wstring>& filePaths,
                const PackerAnalysisConfig& config = PackerAnalysisConfig{},
                PackerProgressCallback progressCallback = nullptr,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze directory
             */
            [[nodiscard]] PackerBatchResult AnalyzeDirectory(
                const std::wstring& directoryPath,
                bool recursive,
                const PackerAnalysisConfig& config = PackerAnalysisConfig{},
                PackerProgressCallback progressCallback = nullptr,
                PackerError* err = nullptr
            ) noexcept;

            // ========================================================================
            // SPECIFIC ANALYSIS METHODS
            // ========================================================================

            /**
             * @brief Calculate Shannon entropy
             */
            [[nodiscard]] static double CalculateEntropy(
                const uint8_t* buffer,
                size_t size
            ) noexcept;

            /**
             * @brief Calculate entropy for file section
             */
            [[nodiscard]] double CalculateSectionEntropy(
                const std::wstring& filePath,
                uint32_t sectionOffset,
                uint32_t sectionSize,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze PE sections
             */
            [[nodiscard]] bool AnalyzeSections(
                const std::wstring& filePath,
                std::vector<SectionInfo>& outSections,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze PE imports
             */
            [[nodiscard]] bool AnalyzeImports(
                const std::wstring& filePath,
                ImportInfo& outImports,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze PE overlay
             */
            [[nodiscard]] bool AnalyzeOverlay(
                const std::wstring& filePath,
                OverlayInfo& outOverlay,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze entry point
             */
            [[nodiscard]] bool AnalyzeEntryPoint(
                const std::wstring& filePath,
                EntryPointInfo& outEP,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Match entry point signature
             */
            [[nodiscard]] std::optional<PackerMatch> MatchEPSignature(
                const uint8_t* epBytes,
                size_t size,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Verify digital signature
             */
            [[nodiscard]] bool VerifySignature(
                const std::wstring& filePath,
                SignatureInfo& outSignature,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze Rich header
             */
            [[nodiscard]] bool AnalyzeRichHeader(
                const std::wstring& filePath,
                RichHeaderInfo& outRichHeader,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze PE resources
             */
            [[nodiscard]] bool AnalyzeResources(
                const std::wstring& filePath,
                ResourceInfo& outResources,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Scan with YARA rules
             */
            [[nodiscard]] bool ScanWithYARA(
                const std::wstring& filePath,
                std::vector<PackerMatch>& outMatches,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Generate unpacking hints
             */
            [[nodiscard]] bool GenerateUnpackingHints(
                const PackingInfo& packingInfo,
                UnpackingHints& outHints,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Check if file is installer
             */
            [[nodiscard]] bool IsInstaller(
                const std::wstring& filePath,
                std::wstring& installerType,
                PackerError* err = nullptr
            ) noexcept;

            /**
             * @brief Check if file is .NET assembly
             */
            [[nodiscard]] bool IsDotNetAssembly(
                const std::wstring& filePath,
                PackerError* err = nullptr
            ) noexcept;

            // ========================================================================
            // REAL-TIME DETECTION
            // ========================================================================

            /**
             * @brief Set detection callback
             */
            void SetDetectionCallback(PackerDetectionCallback callback) noexcept;

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
            [[nodiscard]] std::optional<PackingInfo> GetCachedResult(
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
             * @brief Set pattern store
             */
            void SetPatternStore(std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept;

            /**
             * @brief Set hash store
             */
            void SetHashStore(std::shared_ptr<HashStore::HashStore> hashStore) noexcept;

            /**
             * @brief Add custom EP signature
             */
            void AddCustomEPSignature(
                std::wstring_view packerName,
                const std::vector<uint8_t>& signature,
                PackerType type = PackerType::Custom_Packer
            ) noexcept;

            /**
             * @brief Add custom section name pattern
             */
            void AddCustomSectionPattern(
                std::string_view sectionName,
                PackerType type
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
                std::atomic<uint64_t> packedFilesDetected{ 0 };
                std::atomic<uint64_t> installersDetected{ 0 };
                std::atomic<uint64_t> cryptersDetected{ 0 };
                std::atomic<uint64_t> protectorsDetected{ 0 };
                std::atomic<uint64_t> cacheHits{ 0 };
                std::atomic<uint64_t> cacheMisses{ 0 };
                std::atomic<uint64_t> analysisErrors{ 0 };
                std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };
                std::atomic<uint64_t> bytesAnalyzed{ 0 };
                std::array<std::atomic<uint64_t>, 16> categoryDetections{};

                void Reset() noexcept {
                    totalAnalyses = 0;
                    packedFilesDetected = 0;
                    installersDetected = 0;
                    cryptersDetected = 0;
                    protectorsDetected = 0;
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
                const PackerAnalysisConfig& config,
                PackingInfo& result
            ) noexcept;

            void AnalyzeEntropyDistribution(
                const uint8_t* buffer,
                size_t size,
                PackingInfo& result
            ) noexcept;

            void AnalyzePEStructure(
                const uint8_t* buffer,
                size_t size,
                PackingInfo& result
            ) noexcept;

            void MatchPackerSignatures(
                const uint8_t* buffer,
                size_t size,
                PackingInfo& result
            ) noexcept;

            void PerformHeuristicAnalysis(
                const uint8_t* buffer,
                size_t size,
                PackingInfo& result
            ) noexcept;

            void DeterminePackingVerdict(PackingInfo& result) noexcept;

            void AddMatch(PackingInfo& result, PackerMatch match) noexcept;

            void UpdateCache(
                const std::wstring& filePath,
                const PackingInfo& result
            ) noexcept;

            Utils::pe_sig_utils::PEFileSignatureVerifier m_sigVerifier;
        };

        /**
         * @brief Builder for packer matches
         */
        class PackerMatchBuilder {
        public:
            PackerMatchBuilder() = default;

            PackerMatchBuilder& Type(PackerType type) noexcept {
                m_match.packerType = type;
                m_match.category = GetPackerCategory(type);
                m_match.severity = GetPackerSeverity(type);
                m_match.mitreId = PackerTypeToMitreId(type);
                return *this;
            }

            PackerMatchBuilder& Method(DetectionMethod method) noexcept {
                m_match.method = method;
                return *this;
            }

            PackerMatchBuilder& Confidence(double conf) noexcept {
                m_match.confidence = conf;
                return *this;
            }

            PackerMatchBuilder& Name(std::wstring_view name) noexcept {
                m_match.packerName = name;
                return *this;
            }

            PackerMatchBuilder& Version(std::wstring_view version) noexcept {
                m_match.version = version;
                return *this;
            }

            PackerMatchBuilder& Pattern(std::wstring_view pattern) noexcept {
                m_match.matchedPattern = pattern;
                return *this;
            }

            PackerMatchBuilder& Location(uint64_t loc) noexcept {
                m_match.matchLocation = loc;
                return *this;
            }

            PackerMatchBuilder& Details(std::wstring_view details) noexcept {
                m_match.details = details;
                return *this;
            }

            [[nodiscard]] PackerMatch Build() noexcept {
                m_match.detectionTime = std::chrono::system_clock::now();
                return std::move(m_match);
            }

        private:
            PackerMatch m_match;
        };

    } // namespace AntiEvasion
} // namespace ShadowStrike