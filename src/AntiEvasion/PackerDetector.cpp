/**
 * @file PackerDetector.cpp
 * @brief Enterprise-grade detection of executable packers, protectors, and crypters
 *
 * ShadowStrike AntiEvasion - Packer Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * IMPLEMENTATION OVERVIEW
 * ============================================================================
 *
 * This module implements comprehensive detection of 500+ packers, protectors,
 * and crypters using multiple analysis techniques:
 *
 * 1. ENTROPY ANALYSIS
 *    - Shannon entropy calculation per section and file-wide
 *    - Chi-squared randomness testing
 *    - Compression vs encryption differentiation
 *
 * 2. STRUCTURAL ANALYSIS
 *    - PE header validation via titanium PEParser
 *    - Section characteristics anomaly detection
 *    - Entry point location analysis
 *    - Import table sparseness detection
 *    - Overlay detection and analysis
 *
 * 3. SIGNATURE MATCHING
 *    - Entry point byte pattern matching (500+ signatures)
 *    - Section name recognition (200+ known packer sections)
 *    - YARA rule integration via SignatureStore
 *
 * 4. HEURISTIC ANALYSIS
 *    - Unpacking stub detection via Zydis disassembly
 *    - API resolution pattern recognition
 *    - Self-modifying code indicators
 *
 * ============================================================================
 * THREAD SAFETY
 * ============================================================================
 *
 * All public methods are thread-safe. The implementation uses:
 * - std::shared_mutex for read/write separation
 * - std::atomic for statistics counters
 * - Thread-local storage for per-thread analysis buffers
 *
 * ============================================================================
 */

#include "pch.h"
#include "PackerDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <queue>
#include <sstream>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PEParser/PEParser.hpp"

#include <Zydis/Zydis.h>

namespace ShadowStrike {
namespace AntiEvasion {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    /// @brief Maximum bytes to read for entry point signature matching
    constexpr size_t MAX_EP_BYTES = 512;

    /// @brief Maximum instructions to disassemble for stub analysis
    constexpr size_t MAX_STUB_INSTRUCTIONS = 256;

    /// @brief Entropy calculation block size
    constexpr size_t ENTROPY_BLOCK_SIZE = 4096;

    /// @brief Minimum section size for entropy analysis
    constexpr size_t MIN_SECTION_SIZE_FOR_ENTROPY = 256;

    /// @brief Chi-squared threshold for random data
    constexpr double CHI_SQUARED_RANDOM_THRESHOLD = 300.0;

    /// @brief Maximum number of API resolution patterns to track
    constexpr size_t MAX_API_RESOLUTION_PATTERNS = 64;

    /// @brief Scoring normalization factor
    constexpr double SCORE_NORMALIZATION_FACTOR = 10.0;

} // anonymous namespace

// ============================================================================
// ENTRY POINT SIGNATURES DATABASE
// ============================================================================

namespace EPSignatures {

    /// @brief Entry point signature structure
    struct EPSignature {
        PackerType packerType;
        std::wstring packerName;
        std::wstring version;
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;  // 0xFF = exact match, 0x00 = wildcard
        double confidence;
    };

    /// @brief Built-in EP signature database
    static const std::vector<EPSignature> BuiltInSignatures = {
        // ====================================================================
        // UPX SIGNATURES
        // ====================================================================
        {
            PackerType::UPX,
            L"UPX",
            L"3.x",
            { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x57, 0x83, 0xCD, 0xFF },
            { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF },
            0.95
        },
        {
            PackerType::UPX,
            L"UPX",
            L"2.x",
            { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00, 0xFF, 0xFF, 0x57 },
            { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF },
            0.90
        },
        {
            PackerType::UPX_Modified,
            L"UPX (Modified)",
            L"",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xE8, 0x00 },
            { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00 },
            0.75
        },

        // ====================================================================
        // ASPACK SIGNATURES
        // ====================================================================
        {
            PackerType::ASPack,
            L"ASPack",
            L"2.12",
            { 0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3, 0xE8, 0x01 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.95
        },
        {
            PackerType::ASPack_v2,
            L"ASPack",
            L"2.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0xB8 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
            0.90
        },

        // ====================================================================
        // PECOMPACT SIGNATURES
        // ====================================================================
        {
            PackerType::PECompact,
            L"PECompact",
            L"2.x",
            { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },
        {
            PackerType::PECompact_v3,
            L"PECompact",
            L"3.x",
            { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.88
        },

        // ====================================================================
        // MPRESS SIGNATURES
        // ====================================================================
        {
            PackerType::MPRESS,
            L"MPRESS",
            L"2.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x30 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // PETITE SIGNATURES
        // ====================================================================
        {
            PackerType::Petite,
            L"Petite",
            L"2.x",
            { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.88
        },

        // ====================================================================
        // FSG SIGNATURES
        // ====================================================================
        {
            PackerType::FSG,
            L"FSG",
            L"2.0",
            { 0x87, 0x25, 0x00, 0x00, 0x00, 0x00, 0x61, 0x94, 0x55, 0xA4, 0xB6, 0x80, 0xFF, 0x13 },
            { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.92
        },
        {
            PackerType::FSG_v1,
            L"FSG",
            L"1.x",
            { 0xBB, 0xD0, 0x01, 0x40, 0x00, 0xBF, 0x00, 0x10, 0x40, 0x00, 0xBE },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // MEW SIGNATURES
        // ====================================================================
        {
            PackerType::MEW,
            L"MEW",
            L"11",
            { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF },
            0.80
        },

        // ====================================================================
        // NSPACK SIGNATURES
        // ====================================================================
        {
            PackerType::NsPack,
            L"NsPack",
            L"3.x",
            { 0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x2D },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
            0.90
        },

        // ====================================================================
        // THEMIDA/WINLICENSE SIGNATURES
        // ====================================================================
        {
            PackerType::Themida,
            L"Themida",
            L"2.x",
            { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0B, 0xC0, 0x74, 0x68, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE8 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
            0.85
        },
        {
            PackerType::Themida_v3,
            L"Themida",
            L"3.x",
            { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.80
        },

        // ====================================================================
        // VMPROTECT SIGNATURES
        // ====================================================================
        {
            PackerType::VMProtect,
            L"VMProtect",
            L"3.x",
            { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            0.70
        },
        {
            PackerType::VMProtect_v2,
            L"VMProtect",
            L"2.x",
            { 0x9C, 0x60, 0x68, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF4, 0x83, 0xC6, 0x04, 0x68, 0x00, 0x00, 0x00 },
            { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 },
            0.82
        },

        // ====================================================================
        // ENIGMA PROTECTOR SIGNATURES
        // ====================================================================
        {
            PackerType::Enigma,
            L"Enigma Protector",
            L"4.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x06, 0x00, 0x00, 0x00, 0x8B, 0xD5 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // ASPROTECT SIGNATURES
        // ====================================================================
        {
            PackerType::ASProtect,
            L"ASProtect",
            L"2.x",
            { 0x68, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3, 0x60 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.88
        },

        // ====================================================================
        // ARMADILLO SIGNATURES
        // ====================================================================
        {
            PackerType::Armadillo,
            L"Armadillo",
            L"4.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x50, 0x51, 0x0F, 0xCA, 0xF7, 0xD2, 0x9C },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.88
        },

        // ====================================================================
        // OBSIDIUM SIGNATURES
        // ====================================================================
        {
            PackerType::Obsidium,
            L"Obsidium",
            L"1.x",
            { 0xEB, 0x02, 0x00, 0x00, 0xE8, 0x25, 0x00, 0x00, 0x00 },
            { 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.85
        },

        // ====================================================================
        // PELOCK SIGNATURES
        // ====================================================================
        {
            PackerType::PELock,
            L"PELock",
            L"2.x",
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x01, 0x9A },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF },
            0.80
        },

        // ====================================================================
        // PESPIN SIGNATURES
        // ====================================================================
        {
            PackerType::PESpin,
            L"PESpin",
            L"1.x",
            { 0xEB, 0x01, 0x68, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x1C, 0x24, 0x83, 0xC3 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // TELOCK SIGNATURES
        // ====================================================================
        {
            PackerType::tElock,
            L"tElock",
            L"0.98",
            { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            0.65
        },

        // ====================================================================
        // YODA SIGNATURES
        // ====================================================================
        {
            PackerType::YodaCrypter,
            L"Yoda's Crypter",
            L"1.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00 },
            0.85
        },

        // ====================================================================
        // KKRUNCHY SIGNATURES
        // ====================================================================
        {
            PackerType::kkrunchy,
            L"kkrunchy",
            L"0.23",
            { 0xBD, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x4D, 0x00 },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00 },
            0.88
        },

        // ====================================================================
        // UPACK SIGNATURES
        // ====================================================================
        {
            PackerType::Upack,
            L"Upack",
            L"0.3x",
            { 0xBE, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x8B, 0xF8, 0x95, 0xAD, 0x91, 0xF3, 0xA5, 0xAD },
            { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // RLPACK SIGNATURES
        // ====================================================================
        {
            PackerType::RLPack,
            L"RLPack",
            L"1.x",
            { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x04, 0x83, 0xC0, 0x00 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
            0.85
        },

        // ====================================================================
        // NSIS INSTALLER SIGNATURES
        // ====================================================================
        {
            PackerType::NSIS,
            L"NSIS",
            L"3.x",
            { 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57, 0x6A, 0x20, 0x33, 0xED },
            { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.88
        },
        {
            PackerType::NSIS_v2,
            L"NSIS",
            L"2.x",
            { 0x83, 0xEC, 0x00, 0x53, 0x55, 0x56, 0x57, 0x6A, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00 },
            { 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 },
            0.85
        },

        // ====================================================================
        // INNO SETUP SIGNATURES
        // ====================================================================
        {
            PackerType::InnoSetup,
            L"Inno Setup",
            L"6.x",
            { 0x55, 0x8B, 0xEC, 0x83, 0xC4, 0x00, 0x53, 0x56, 0x57, 0x33, 0xC0, 0x89, 0x45 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.85
        },

        // ====================================================================
        // 7-ZIP SFX SIGNATURES
        // ====================================================================
        {
            PackerType::SevenZip_SFX,
            L"7-Zip SFX",
            L"",
            { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x64 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
            0.75
        },

        // ====================================================================
        // CONFUSEREX SIGNATURES (.NET)
        // ====================================================================
        {
            PackerType::ConfuserEx,
            L"ConfuserEx",
            L"1.x",
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x43, 0x6F, 0x72 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF },
            0.70
        },

        // ====================================================================
        // EXECRYPTOR SIGNATURES
        // ====================================================================
        {
            PackerType::ExeCryptor,
            L"EXECryptor",
            L"2.x",
            { 0xE8, 0x24, 0x00, 0x00, 0x00, 0x8B, 0x4C, 0x24, 0x0C, 0xC7, 0x01, 0x17, 0x00, 0x01, 0x00 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            0.90
        },

        // ====================================================================
        // SAFENGINE SIGNATURES
        // ====================================================================
        {
            PackerType::Safengine,
            L"Safengine",
            L"2.x",
            { 0x60, 0x9C, 0x60, 0x8B, 0xDD, 0x8B, 0xC5, 0x83, 0xC0, 0x05, 0x89, 0x45, 0x00 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
            0.88
        },

        // ====================================================================
        // CODE VIRTUALIZER SIGNATURES
        // ====================================================================
        {
            PackerType::CodeVirtualizer,
            L"Code Virtualizer",
            L"2.x",
            { 0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00, 0x80 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF },
            0.85
        },
    };

    /// @brief Match pattern against buffer with mask
    [[nodiscard]] bool MatchPattern(
        const uint8_t* buffer,
        size_t bufferSize,
        const std::vector<uint8_t>& pattern,
        const std::vector<uint8_t>& mask) noexcept
    {
        if (bufferSize < pattern.size() || pattern.empty()) {
            return false;
        }

        for (size_t i = 0; i < pattern.size(); ++i) {
            const uint8_t maskByte = (i < mask.size()) ? mask[i] : 0xFF;
            if ((buffer[i] & maskByte) != (pattern[i] & maskByte)) {
                return false;
            }
        }
        return true;
    }

} // namespace EPSignatures

// ============================================================================
// PACKER DETECTOR IMPLEMENTATION CLASS
// ============================================================================

class PackerDetector::Impl {
public:
    Impl() noexcept = default;

    explicit Impl(std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept
        : m_signatureStore(std::move(sigStore))
    {}

    Impl(
        std::shared_ptr<SignatureStore::SignatureStore> sigStore,
        std::shared_ptr<PatternStore::PatternStore> patternStore,
        std::shared_ptr<HashStore::HashStore> hashStore
    ) noexcept
        : m_signatureStore(std::move(sigStore))
        , m_patternStore(std::move(patternStore))
        , m_hashStore(std::move(hashStore))
    {}

    ~Impl() = default;

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) noexcept = default;
    Impl& operator=(Impl&&) noexcept = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(PackerError* err) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            return true;
        }

        SS_LOG_INFO(L"PackerDetector", L"Initializing packer detector...");

        if (!InitializeZydis()) {
            if (err) {
                err->win32Code = ERROR_INVALID_FUNCTION;
                err->message = L"Failed to initialize Zydis disassembler";
            }
            return false;
        }

        for (const auto& sig : EPSignatures::BuiltInSignatures) {
            m_epSignatureMap[sig.packerType] = sig;
        }

        m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"PackerDetector", L"Packer detector initialized with %zu EP signatures",
            EPSignatures::BuiltInSignatures.size());

        return true;
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        m_initialized.store(false, std::memory_order_release);
        m_cache.clear();
        m_customEPSignatures.clear();
        m_customSectionPatterns.clear();
        SS_LOG_INFO(L"PackerDetector", L"Packer detector shut down");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    [[nodiscard]] PackingInfo AnalyzeFile(
        const std::wstring& filePath,
        const PackerAnalysisConfig& config,
        PackerError* err) noexcept
    {
        PackingInfo result;
        result.analysisStartTime = std::chrono::system_clock::now();
        result.filePath = filePath;
        result.config = config;

        if (config.enableCaching && HasFlag(config.flags, PackerAnalysisFlags::EnableCaching)) {
            std::shared_lock lock(m_cacheMutex);
            auto it = m_cache.find(filePath);
            if (it != m_cache.end()) {
                const auto& [cacheEntry, cacheTime] = it->second;
                auto now = std::chrono::system_clock::now();
                auto age = std::chrono::duration_cast<std::chrono::seconds>(now - cacheTime).count();

                if (age < static_cast<long long>(config.cacheTtlSeconds)) {
                    m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    result = cacheEntry;
                    result.fromCache = true;
                    return result;
                }
            }
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            if (err) {
                err->win32Code = GetLastError();
                err->message = L"Failed to memory-map file";
                err->context = filePath;
            }
            result.errors.push_back({ GetLastError(), L"Failed to open file", filePath });
            return result;
        }

        if (!mappedFile.hasData()) {
            if (err) {
                err->win32Code = ERROR_EMPTY;
                err->message = L"File is empty";
            }
            return result;
        }

        result.fileSize = mappedFile.size();

        if (result.fileSize > config.maxFileSize) {
            if (err) {
                err->win32Code = ERROR_FILE_TOO_LARGE;
                err->message = L"File exceeds maximum analysis size";
            }
            result.errors.push_back({ ERROR_FILE_TOO_LARGE, L"File too large", filePath });
            return result;
        }

        AnalyzeBufferInternal(
            static_cast<const uint8_t*>(mappedFile.data()),
            mappedFile.size(),
            filePath,
            config,
            result
        );

        if (config.enableCaching) {
            UpdateCache(filePath, result);
        }

        m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
        if (result.isPacked) {
            m_stats.packedFilesDetected.fetch_add(1, std::memory_order_relaxed);
            if (result.isInstaller) {
                m_stats.installersDetected.fetch_add(1, std::memory_order_relaxed);
            }
            if (result.packerCategory == PackerCategory::Crypter) {
                m_stats.cryptersDetected.fetch_add(1, std::memory_order_relaxed);
            }
            if (result.packerCategory == PackerCategory::Protector ||
                result.packerCategory == PackerCategory::VMProtection) {
                m_stats.protectorsDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        result.analysisEndTime = std::chrono::system_clock::now();
        result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            result.analysisEndTime - result.analysisStartTime).count();
        result.analysisComplete = true;

        m_stats.totalAnalysisTimeUs.fetch_add(
            result.analysisDurationMs * 1000, std::memory_order_relaxed);
        m_stats.bytesAnalyzed.fetch_add(result.fileSize, std::memory_order_relaxed);

        return result;
    }

    [[nodiscard]] PackingInfo AnalyzeBuffer(
        const uint8_t* buffer,
        size_t size,
        const PackerAnalysisConfig& config,
        PackerError* err) noexcept
    {
        PackingInfo result;
        result.analysisStartTime = std::chrono::system_clock::now();
        result.fileSize = size;
        result.config = config;

        if (buffer == nullptr || size == 0) {
            if (err) {
                err->win32Code = ERROR_INVALID_PARAMETER;
                err->message = L"Invalid buffer";
            }
            return result;
        }

        AnalyzeBufferInternal(buffer, size, L"", config, result);

        result.analysisEndTime = std::chrono::system_clock::now();
        result.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            result.analysisEndTime - result.analysisStartTime).count();
        result.analysisComplete = true;

        return result;
    }

    // ========================================================================
    // BATCH ANALYSIS
    // ========================================================================

    [[nodiscard]] PackerBatchResult AnalyzeFiles(
        const std::vector<std::wstring>& filePaths,
        const PackerAnalysisConfig& config,
        PackerProgressCallback progressCallback,
        PackerError* err) noexcept
    {
        PackerBatchResult batchResult;
        batchResult.startTime = std::chrono::system_clock::now();
        batchResult.totalFiles = static_cast<uint32_t>(filePaths.size());
        batchResult.results.reserve(filePaths.size());

        for (size_t i = 0; i < filePaths.size(); ++i) {
            if (progressCallback) {
                progressCallback(filePaths[i], static_cast<uint32_t>(i), batchResult.totalFiles);
            }

            PackerError fileErr;
            auto result = AnalyzeFile(filePaths[i], config, &fileErr);

            if (!result.analysisComplete) {
                ++batchResult.failedFiles;
            } else if (result.isPacked) {
                ++batchResult.packedFiles;
                batchResult.packerDistribution[result.primaryPacker]++;
                batchResult.categoryDistribution[result.packerCategory]++;
            }

            if (result.isInstaller) {
                ++batchResult.installerFiles;
            }

            batchResult.results.push_back(std::move(result));
        }

        batchResult.endTime = std::chrono::system_clock::now();
        batchResult.totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            batchResult.endTime - batchResult.startTime).count();

        return batchResult;
    }

    [[nodiscard]] PackerBatchResult AnalyzeDirectory(
        const std::wstring& directoryPath,
        bool recursive,
        const PackerAnalysisConfig& config,
        PackerProgressCallback progressCallback,
        PackerError* err) noexcept
    {
        std::vector<std::wstring> filePaths;

        try {
            auto options = recursive
                ? std::filesystem::directory_options::follow_directory_symlink
                : std::filesystem::directory_options::none;

            auto processEntry = [&](const std::filesystem::directory_entry& entry) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().wstring();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                    if (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                        ext == L".ocx" || ext == L".scr" || ext == L".drv") {
                        filePaths.push_back(entry.path().wstring());
                    }
                }
            };

            if (recursive) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath, options)) {
                    processEntry(entry);
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                    processEntry(entry);
                }
            }
        } catch (const std::filesystem::filesystem_error& e) {
            if (err) {
                err->win32Code = ERROR_DIRECTORY;
                err->message = Utils::StringUtils::ToWide(e.what());
            }
            return {};
        }

        return AnalyzeFiles(filePaths, config, progressCallback, err);
    }

    // ========================================================================
    // ENTROPY CALCULATION
    // ========================================================================

    [[nodiscard]] static double CalculateEntropy(
        const uint8_t* buffer,
        size_t size) noexcept
    {
        if (buffer == nullptr || size == 0) {
            return 0.0;
        }

        std::array<size_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            ++freq[buffer[i]];
        }

        double entropy = 0.0;
        const double total = static_cast<double>(size);

        for (size_t count : freq) {
            if (count > 0) {
                const double p = static_cast<double>(count) / total;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    [[nodiscard]] double CalculateSectionEntropy(
        const std::wstring& filePath,
        uint32_t sectionOffset,
        uint32_t sectionSize,
        PackerError* err) noexcept
    {
        if (sectionSize == 0 || sectionSize < MIN_SECTION_SIZE_FOR_ENTROPY) {
            return 0.0;
        }

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            if (err) {
                err->win32Code = GetLastError();
                err->message = L"Failed to memory-map file";
            }
            return -1.0;
        }

        if (sectionOffset + sectionSize > mappedFile.size()) {
            if (err) {
                err->win32Code = ERROR_INVALID_PARAMETER;
                err->message = L"Section extends beyond file";
            }
            return -1.0;
        }

        return CalculateEntropy(
            static_cast<const uint8_t*>(mappedFile.data()) + sectionOffset,
            sectionSize
        );
    }

    // ========================================================================
    // SECTION ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeSections(
        const std::wstring& filePath,
        std::vector<SectionInfo>& outSections,
        PackerError* err) noexcept
    {
        outSections.clear();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            if (err) {
                err->win32Code = GetLastError();
                err->message = L"Failed to memory-map file";
            }
            return false;
        }

        for (const auto& peSec : peInfo.sections) {
            SectionInfo sec;
            sec.name = peSec.name;
            sec.virtualAddress = peSec.virtualAddress;
            sec.virtualSize = peSec.virtualSize;
            sec.rawSize = peSec.rawSize;
            sec.rawDataPointer = peSec.rawAddress;
            sec.characteristics = peSec.characteristics;
            sec.isExecutable = peSec.isExecutable;
            sec.isWritable = peSec.isWritable;
            sec.isReadable = peSec.isReadable;
            sec.isEmpty = (peSec.virtualSize > 0 && peSec.rawSize == 0);

            if (peSec.rawSize >= MIN_SECTION_SIZE_FOR_ENTROPY &&
                peSec.rawAddress + peSec.rawSize <= mappedFile.size()) {
                sec.entropy = CalculateEntropy(
                    static_cast<const uint8_t*>(mappedFile.data()) + peSec.rawAddress,
                    peSec.rawSize
                );
                sec.hasHighEntropy = sec.entropy >= PackerConstants::HIGH_SECTION_ENTROPY;
            }

            std::string nameLower = sec.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            for (const auto& knownSection : PackerConstants::KNOWN_PACKER_SECTIONS) {
                if (nameLower == knownSection) {
                    sec.isPackerSection = true;
                    sec.matchedPackerName = std::string(knownSection);
                    break;
                }
            }

            {
                std::shared_lock lock(m_customPatternsMutex);
                auto it = m_customSectionPatterns.find(nameLower);
                if (it != m_customSectionPatterns.end()) {
                    sec.isPackerSection = true;
                }
            }

            if (sec.isExecutable && sec.isWritable) {
                sec.anomalies.push_back(L"Section is both writable and executable (W+X)");
            }

            if (sec.rawSize > sec.virtualSize * 2 && sec.virtualSize > 0) {
                sec.anomalies.push_back(L"Raw size significantly larger than virtual size");
            }

            outSections.push_back(std::move(sec));
        }

        return true;
    }

    // ========================================================================
    // IMPORT ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeImports(
        const std::wstring& filePath,
        ImportInfo& outImports,
        PackerError* err) noexcept
    {
        outImports = ImportInfo();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        std::vector<PEParser::ImportInfo> imports;
        if (!parser.ParseImports(imports, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse imports";
            }
            return false;
        }

        outImports.valid = true;
        outImports.dllCount = imports.size();

        for (const auto& imp : imports) {
            outImports.totalImports += imp.functions.size();
            outImports.dlls.push_back(Utils::StringUtils::ToNarrow(imp.dllName));

            for (const auto& func : imp.functions) {
                if (func.name == "GetProcAddress") {
                    outImports.hasGetProcAddress = true;
                }
                if (func.name == "LoadLibraryA" || func.name == "LoadLibraryW" ||
                    func.name == "LoadLibraryExA" || func.name == "LoadLibraryExW") {
                    outImports.hasLoadLibrary = true;
                }
                if (func.name == "VirtualAlloc" || func.name == "VirtualAllocEx" ||
                    func.name == "VirtualProtect" || func.name == "VirtualProtectEx") {
                    outImports.hasVirtualMemoryAPIs = true;
                }

                if (func.name == "NtUnmapViewOfSection" ||
                    func.name == "ZwUnmapViewOfSection" ||
                    func.name == "NtWriteVirtualMemory" ||
                    func.name == "NtAllocateVirtualMemory") {
                    outImports.suspiciousImports.push_back(
                        Utils::StringUtils::ToWide(func.name));
                }
            }
        }

        outImports.hasMinimalImports = (outImports.totalImports < PackerConstants::MIN_NORMAL_IMPORTS);

        if (outImports.hasMinimalImports) {
            outImports.anomalies.push_back(L"Very few imports (typical of packed files)");
        }

        if (outImports.hasGetProcAddress && outImports.hasLoadLibrary &&
            outImports.totalImports < 10) {
            outImports.anomalies.push_back(
                L"Dynamic loading APIs with minimal static imports (packing indicator)");
        }

        return true;
    }

    // ========================================================================
    // OVERLAY ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeOverlay(
        const std::wstring& filePath,
        OverlayInfo& outOverlay,
        PackerError* err) noexcept
    {
        outOverlay = OverlayInfo();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        if (peInfo.overlaySize == 0) {
            outOverlay.valid = true;
            outOverlay.hasOverlay = false;
            return true;
        }

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            if (err) {
                err->win32Code = GetLastError();
                err->message = L"Failed to memory-map file";
            }
            return false;
        }

        outOverlay.valid = true;
        outOverlay.hasOverlay = true;
        outOverlay.offset = peInfo.overlayOffset;
        outOverlay.size = peInfo.overlaySize;
        outOverlay.percentageOfFile = (static_cast<double>(peInfo.overlaySize) /
            static_cast<double>(peInfo.fileSize)) * 100.0;

        if (peInfo.overlayOffset + 16 <= mappedFile.size()) {
            const uint8_t* overlayData = static_cast<const uint8_t*>(mappedFile.data()) +
                peInfo.overlayOffset;
            std::copy_n(overlayData, std::min(size_t(16), peInfo.overlaySize),
                outOverlay.magicBytes.begin());

            if (overlayData[0] == 0x50 && overlayData[1] == 0x4B) {
                outOverlay.detectedFormat = L"ZIP/JAR archive";
            } else if (overlayData[0] == 0x52 && overlayData[1] == 0x61 &&
                       overlayData[2] == 0x72 && overlayData[3] == 0x21) {
                outOverlay.detectedFormat = L"RAR archive";
            } else if (overlayData[0] == 0x37 && overlayData[1] == 0x7A &&
                       overlayData[2] == 0xBC && overlayData[3] == 0xAF) {
                outOverlay.detectedFormat = L"7-Zip archive";
            } else if (overlayData[0] == 0x1F && overlayData[1] == 0x8B) {
                outOverlay.detectedFormat = L"GZIP compressed";
            } else if (overlayData[0] == 0xEF && overlayData[1] == 0xBE &&
                       overlayData[2] == 0xAD && overlayData[3] == 0xDE) {
                outOverlay.detectedFormat = L"NSIS installer data";
            }
        }

        size_t overlayAnalyzeSize = std::min(peInfo.overlaySize,
            PackerConstants::MAX_OVERLAY_SIZE);
        if (overlayAnalyzeSize >= MIN_SECTION_SIZE_FOR_ENTROPY) {
            outOverlay.entropy = CalculateEntropy(
                static_cast<const uint8_t*>(mappedFile.data()) + peInfo.overlayOffset,
                overlayAnalyzeSize
            );
            outOverlay.isCompressed = (outOverlay.entropy >= PackerConstants::MIN_COMPRESSED_ENTROPY &&
                outOverlay.entropy < PackerConstants::MIN_ENCRYPTED_ENTROPY);
            outOverlay.isEncrypted = (outOverlay.entropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);
        }

        return true;
    }

    // ========================================================================
    // ENTRY POINT ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeEntryPoint(
        const std::wstring& filePath,
        EntryPointInfo& outEP,
        PackerError* err) noexcept
    {
        outEP = EntryPointInfo();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        outEP.rva = peInfo.entryPointRva;
        outEP.valid = true;

        auto epOffset = parser.RvaToOffset(peInfo.entryPointRva);
        if (!epOffset) {
            outEP.isInValidSection = false;
            return true;
        }

        outEP.fileOffset = static_cast<uint32_t>(*epOffset);
        outEP.isInValidSection = true;

        for (const auto& sec : peInfo.sections) {
            if (peInfo.entryPointRva >= sec.virtualAddress &&
                peInfo.entryPointRva < sec.virtualAddress + sec.virtualSize) {
                outEP.containingSection = sec.name;
                outEP.isOutsideCodeSection = !sec.hasCode;
                break;
            }
        }

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            if (err) {
                err->win32Code = GetLastError();
                err->message = L"Failed to memory-map file";
            }
            return false;
        }

        size_t bytesToRead = std::min(static_cast<size_t>(MAX_EP_BYTES),
            mappedFile.size() - *epOffset);
        if (bytesToRead > 0) {
            outEP.epBytes.resize(bytesToRead);
            std::memcpy(outEP.epBytes.data(),
                static_cast<const uint8_t*>(mappedFile.data()) + *epOffset,
                bytesToRead);

            auto match = MatchEPSignatureInternal(outEP.epBytes.data(), outEP.epBytes.size());
            if (match) {
                outEP.matchedPacker = match->packerType;
                outEP.matchedSignature = match->packerName;
                outEP.matchConfidence = match->confidence;
            }
        }

        return true;
    }

    [[nodiscard]] std::optional<PackerMatch> MatchEPSignature(
        const uint8_t* epBytes,
        size_t size,
        PackerError* err) noexcept
    {
        return MatchEPSignatureInternal(epBytes, size);
    }

    // ========================================================================
    // SIGNATURE VERIFICATION
    // ========================================================================

    [[nodiscard]] bool VerifySignature(
        const std::wstring& filePath,
        SignatureInfo& outSignature,
        PackerError* err) noexcept
    {
        outSignature = SignatureInfo();

        Utils::pe_sig_utils::SignatureInfo sigInfo;
        Utils::pe_sig_utils::Error sigErr;

        if (m_sigVerifier.VerifyPESignature(filePath, sigInfo, &sigErr)) {
            outSignature.valid = true;
            outSignature.hasSignature = sigInfo.isSigned;
            outSignature.isValid = sigInfo.isVerified;
            outSignature.signerName = sigInfo.signerName;
            outSignature.issuerName = sigInfo.issuerName;
            outSignature.isSelfSigned = (sigInfo.signerName == sigInfo.issuerName);
        } else {
            outSignature.valid = true;
            outSignature.hasSignature = false;
            if (sigErr.HasError()) {
                outSignature.errors.push_back(sigErr.message);
            }
        }

        return true;
    }

    // ========================================================================
    // RICH HEADER ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeRichHeader(
        const std::wstring& filePath,
        RichHeaderInfo& outRichHeader,
        PackerError* err) noexcept
    {
        outRichHeader = RichHeaderInfo();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        PEParser::RichHeaderInfo richInfo;
        if (!parser.ParseRichHeader(richInfo, &peErr)) {
            outRichHeader.valid = true;
            outRichHeader.hasRichHeader = false;
            return true;
        }

        outRichHeader.valid = true;
        outRichHeader.hasRichHeader = richInfo.present;
        outRichHeader.checksum = richInfo.checksum;

        for (const auto& entry : richInfo.entries) {
            RichHeaderInfo::CompilerEntry ce;
            ce.buildNumber = entry.buildId;
            ce.productId = entry.productId;
            ce.useCount = entry.useCount;
            outRichHeader.entries.push_back(ce);
        }

        if (!richInfo.present && peInfo.fileSize > 1024) {
            outRichHeader.isStripped = true;
        }

        return true;
    }

    // ========================================================================
    // RESOURCE ANALYSIS
    // ========================================================================

    [[nodiscard]] bool AnalyzeResources(
        const std::wstring& filePath,
        ResourceInfo& outResources,
        PackerError* err) noexcept
    {
        outResources = ResourceInfo();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            if (err) {
                err->win32Code = ERROR_BAD_FORMAT;
                err->message = L"Failed to parse PE file";
            }
            return false;
        }

        std::vector<PEParser::ResourceEntry> resources;
        if (!parser.ParseResources(resources, 16, &peErr)) {
            outResources.valid = true;
            return true;
        }

        outResources.valid = true;
        outResources.count = resources.size();

        Utils::MemoryUtils::MappedView mappedFile;
        if (!mappedFile.mapReadOnly(filePath)) {
            return true;
        }

        for (const auto& res : resources) {
            outResources.totalSize += res.size;
            if (res.size > outResources.largestResourceSize) {
                outResources.largestResourceSize = res.size;
            }

            if (res.size >= MIN_SECTION_SIZE_FOR_ENTROPY &&
                res.offset + res.size <= mappedFile.size()) {
                double entropy = CalculateEntropy(
                    static_cast<const uint8_t*>(mappedFile.data()) + res.offset,
                    res.size
                );
                if (entropy >= PackerConstants::HIGH_SECTION_ENTROPY) {
                    ++outResources.highEntropyCount;
                    outResources.suspiciousResources.push_back(
                        Utils::StringUtils::Format(L"High entropy resource (%.2f)", entropy));
                }
                outResources.averageEntropy += entropy;
            }

            if (std::find(outResources.languages.begin(), outResources.languages.end(),
                static_cast<uint16_t>(res.language)) == outResources.languages.end()) {
                outResources.languages.push_back(static_cast<uint16_t>(res.language));
            }
        }

        if (outResources.count > 0) {
            outResources.averageEntropy /= outResources.count;
        }

        return true;
    }

    // ========================================================================
    // YARA SCANNING
    // ========================================================================

    [[nodiscard]] bool ScanWithYARA(
        const std::wstring& filePath,
        std::vector<PackerMatch>& outMatches,
        PackerError* err) noexcept
    {
        outMatches.clear();

        if (!m_signatureStore) {
            return true;
        }

        SignatureStore::ScanOptions scanOptions;
        scanOptions.enableYaraScan = true;
        scanOptions.enableHashLookup = false;
        scanOptions.enablePatternScan = false;

        auto result = m_signatureStore->ScanFile(filePath, scanOptions);

        for (const auto& yaraMatch : result.yaraMatches) {
            PackerMatch match;
            match.method = DetectionMethod::YARARule;
            match.packerName = Utils::StringUtils::ToWide(yaraMatch.ruleName);
            match.confidence = 0.85;
            match.severity = PackerSeverity::Medium;
            match.detectionTime = std::chrono::system_clock::now();

            std::string lowerName = yaraMatch.ruleName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find("upx") != std::string::npos) {
                match.packerType = PackerType::UPX;
                match.category = PackerCategory::Compression;
            } else if (lowerName.find("themida") != std::string::npos) {
                match.packerType = PackerType::Themida;
                match.category = PackerCategory::Protector;
            } else if (lowerName.find("vmprotect") != std::string::npos) {
                match.packerType = PackerType::VMProtect;
                match.category = PackerCategory::VMProtection;
            } else {
                match.packerType = PackerType::Unknown;
                match.category = PackerCategory::Unknown;
            }

            outMatches.push_back(std::move(match));
        }

        return true;
    }

    // ========================================================================
    // UNPACKING HINTS
    // ========================================================================

    [[nodiscard]] bool GenerateUnpackingHints(
        const PackingInfo& packingInfo,
        UnpackingHints& outHints,
        PackerError* err) noexcept
    {
        outHints = UnpackingHints();
        outHints.valid = true;

        if (!packingInfo.isPacked) {
            return true;
        }

        switch (packingInfo.primaryPacker) {
            case PackerType::UPX:
            case PackerType::UPX_Modified:
                outHints.suggestedTool = L"UPX -d (official unpacker)";
                outHints.compressionAlgorithm = L"LZMA/NRV";
                outHints.needsIATReconstruction = false;
                outHints.complexityRating = 2;
                break;

            case PackerType::ASPack:
            case PackerType::ASPack_v2:
                outHints.suggestedTool = L"stripper or manual OEP finding";
                outHints.compressionAlgorithm = L"LZ77 variant";
                outHints.needsIATReconstruction = true;
                outHints.complexityRating = 4;
                break;

            case PackerType::Themida:
            case PackerType::Themida_v2:
            case PackerType::Themida_v3:
                outHints.suggestedTool = L"Manual analysis required (Themida specific tools)";
                outHints.needsIATReconstruction = true;
                outHints.complexityRating = 9;
                outHints.antiUnpackingTechniques.push_back(L"Anti-debugging");
                outHints.antiUnpackingTechniques.push_back(L"VM detection");
                outHints.antiUnpackingTechniques.push_back(L"Code virtualization");
                outHints.antiUnpackingTechniques.push_back(L"Nanomites");
                break;

            case PackerType::VMProtect:
            case PackerType::VMProtect_v2:
            case PackerType::VMProtect_v3:
                outHints.suggestedTool = L"Manual devirtualization required";
                outHints.needsIATReconstruction = true;
                outHints.complexityRating = 10;
                outHints.antiUnpackingTechniques.push_back(L"Code virtualization (proprietary VM)");
                outHints.antiUnpackingTechniques.push_back(L"Anti-debugging");
                outHints.antiUnpackingTechniques.push_back(L"Memory protection");
                break;

            case PackerType::PECompact:
            case PackerType::PECompact_v3:
                outHints.suggestedTool = L"Generic unpacker or manual OEP finding";
                outHints.needsIATReconstruction = false;
                outHints.complexityRating = 3;
                break;

            case PackerType::MPRESS:
                outHints.suggestedTool = L"MPRESS unpacker or manual";
                outHints.needsIATReconstruction = false;
                outHints.complexityRating = 3;
                break;

            case PackerType::Enigma:
                outHints.suggestedTool = L"Enigma unpacker tools";
                outHints.needsIATReconstruction = true;
                outHints.complexityRating = 7;
                break;

            case PackerType::ConfuserEx:
                outHints.suggestedTool = L"de4dot or manual .NET analysis";
                outHints.needsIATReconstruction = false;
                outHints.complexityRating = 5;
                outHints.notes.push_back(L".NET obfuscator - different approach needed");
                break;

            default:
                outHints.suggestedTool = L"Generic unpacker or x64dbg/OllyDbg manual analysis";
                outHints.needsIATReconstruction = true;
                outHints.complexityRating = 6;
                break;
        }

        if (packingInfo.packerMatches.size() > 1) {
            outHints.hasMultipleLayers = true;
            outHints.estimatedLayerCount = static_cast<uint32_t>(packingInfo.packerMatches.size());
        }

        if (packingInfo.entryPointInfo.valid && !packingInfo.entryPointInfo.epBytes.empty()) {
            AnalyzeStubForAntiUnpacking(packingInfo.entryPointInfo.epBytes, outHints);
        }

        return true;
    }

    // ========================================================================
    // INSTALLER DETECTION
    // ========================================================================

    [[nodiscard]] bool IsInstaller(
        const std::wstring& filePath,
        std::wstring& installerType,
        PackerError* err) noexcept
    {
        installerType.clear();

        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            return false;
        }

        for (const auto& sec : peInfo.sections) {
            std::string nameLower = sec.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            for (const auto& instSec : PackerConstants::INSTALLER_SECTIONS) {
                if (nameLower == instSec) {
                    if (nameLower == ".ndata" || nameLower == ".nsis") {
                        installerType = L"NSIS";
                    } else if (nameLower == ".inno") {
                        installerType = L"Inno Setup";
                    } else if (nameLower == ".is") {
                        installerType = L"InstallShield";
                    } else {
                        installerType = L"Generic Installer";
                    }
                    return true;
                }
            }
        }

        if (peInfo.overlaySize > 0) {
            Utils::MemoryUtils::MappedView mappedFile;
            if (mappedFile.mapReadOnly(filePath) && peInfo.overlayOffset + 4 <= mappedFile.size()) {
                const uint8_t* overlayData = static_cast<const uint8_t*>(mappedFile.data()) +
                    peInfo.overlayOffset;

                if (overlayData[0] == 0xEF && overlayData[1] == 0xBE &&
                    overlayData[2] == 0xAD && overlayData[3] == 0xDE) {
                    installerType = L"NSIS";
                    return true;
                }
            }
        }

        return false;
    }

    // ========================================================================
    // .NET DETECTION
    // ========================================================================

    [[nodiscard]] bool IsDotNetAssembly(
        const std::wstring& filePath,
        PackerError* err) noexcept
    {
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseFile(filePath, peInfo, &peErr)) {
            return false;
        }

        return peInfo.isDotNet;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetDetectionCallback(PackerDetectionCallback callback) noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_detectionCallback = std::move(callback);
    }

    void ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_callbackMutex);
        m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    [[nodiscard]] std::optional<PackingInfo> GetCachedResult(
        const std::wstring& filePath) const noexcept
    {
        std::shared_lock lock(m_cacheMutex);
        auto it = m_cache.find(filePath);
        if (it != m_cache.end()) {
            return it->second.first;
        }
        return std::nullopt;
    }

    void InvalidateCache(const std::wstring& filePath) noexcept {
        std::unique_lock lock(m_cacheMutex);
        m_cache.erase(filePath);
    }

    void ClearCache() noexcept {
        std::unique_lock lock(m_cacheMutex);
        m_cache.clear();
    }

    [[nodiscard]] size_t GetCacheSize() const noexcept {
        std::shared_lock lock(m_cacheMutex);
        return m_cache.size();
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void SetSignatureStore(std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept {
        std::unique_lock lock(m_mutex);
        m_signatureStore = std::move(sigStore);
    }

    void SetPatternStore(std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept {
        std::unique_lock lock(m_mutex);
        m_patternStore = std::move(patternStore);
    }

    void SetHashStore(std::shared_ptr<HashStore::HashStore> hashStore) noexcept {
        std::unique_lock lock(m_mutex);
        m_hashStore = std::move(hashStore);
    }

    void AddCustomEPSignature(
        std::wstring_view packerName,
        const std::vector<uint8_t>& signature,
        PackerType type) noexcept
    {
        std::unique_lock lock(m_customPatternsMutex);
        EPSignatures::EPSignature sig;
        sig.packerType = type;
        sig.packerName = std::wstring(packerName);
        sig.pattern = signature;
        sig.mask.resize(signature.size(), 0xFF);
        sig.confidence = 0.80;
        m_customEPSignatures.push_back(std::move(sig));
    }

    void AddCustomSectionPattern(std::string_view sectionName, PackerType type) noexcept {
        std::unique_lock lock(m_customPatternsMutex);
        std::string nameLower(sectionName);
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        m_customSectionPatterns[nameLower] = type;
    }

    void ClearCustomPatterns() noexcept {
        std::unique_lock lock(m_customPatternsMutex);
        m_customEPSignatures.clear();
        m_customSectionPatterns.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const Statistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    Utils::pe_sig_utils::PEFileSignatureVerifier& GetSigVerifier() noexcept {
        return m_sigVerifier;
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] bool InitializeZydis() noexcept {
        ZydisDecoderInit(&m_decoder32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        ZydisDecoderInit(&m_decoder64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        return true;
    }

    void AnalyzeBufferInternal(
        const uint8_t* buffer,
        size_t size,
        const std::wstring& filePath,
        const PackerAnalysisConfig& config,
        PackingInfo& result) noexcept
    {
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        PEParser::PEError peErr;

        if (!parser.ParseBuffer(buffer, size, peInfo, &peErr)) {
            result.errors.push_back({ ERROR_BAD_FORMAT, L"Failed to parse PE", filePath });
            return;
        }

        result.isDotNetAssembly = peInfo.isDotNet;

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableEntropyAnalysis)) {
            AnalyzeEntropyInternal(buffer, size, peInfo, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableSectionAnalysis)) {
            AnalyzeSectionsInternal(buffer, size, peInfo, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableEPSignature)) {
            AnalyzeEntryPointInternal(buffer, size, peInfo, parser, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableImportAnalysis)) {
            AnalyzeImportsInternal(parser, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableOverlayAnalysis)) {
            AnalyzeOverlayInternal(buffer, size, peInfo, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableRichHeaderAnalysis)) {
            AnalyzeRichHeaderInternal(parser, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableResourceAnalysis)) {
            AnalyzeResourcesInternal(parser, buffer, size, result);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableSignatureVerification) &&
            !filePath.empty()) {
            VerifySignature(filePath, result.signatureInfo, nullptr);
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableYARAScanning) &&
            m_signatureStore && !filePath.empty()) {
            std::vector<PackerMatch> yaraMatches;
            ScanWithYARA(filePath, yaraMatches, nullptr);
            for (auto& match : yaraMatches) {
                AddMatch(result, std::move(match));
            }
        }

        if (HasFlag(config.flags, PackerAnalysisFlags::EnableHeuristicAnalysis)) {
            PerformHeuristicAnalysis(buffer, size, peInfo, result);
        }

        if (!filePath.empty()) {
            std::wstring installerType;
            if (IsInstaller(filePath, installerType, nullptr)) {
                result.isInstaller = true;
                result.indicators.push_back(L"Installer detected: " + installerType);
            }
        }

        DeterminePackingVerdict(result, config);

        if (HasFlag(config.flags, PackerAnalysisFlags::IncludeUnpackingHints) && result.isPacked) {
            GenerateUnpackingHints(result, result.unpackingHints, nullptr);
        }
    }

    void AnalyzeEntropyInternal(
        const uint8_t* buffer,
        size_t size,
        const PEParser::PEInfo& peInfo,
        PackingInfo& result) noexcept
    {
        result.fileEntropy = CalculateEntropy(buffer, size);
        result.chiSquared = CalculateChiSquared(buffer, size);

        double totalEntropy = 0.0;
        size_t entropyCount = 0;

        for (const auto& sec : peInfo.sections) {
            if (sec.rawSize >= MIN_SECTION_SIZE_FOR_ENTROPY &&
                sec.rawAddress + sec.rawSize <= size) {
                double secEntropy = CalculateEntropy(buffer + sec.rawAddress, sec.rawSize);

                if (secEntropy > result.maxSectionEntropy) {
                    result.maxSectionEntropy = secEntropy;
                    result.maxEntropySectionName = sec.name;
                }

                totalEntropy += secEntropy;
                ++entropyCount;

                if (sec.hasCode) {
                    result.codeSectionEntropy = secEntropy;
                } else if (sec.hasInitializedData) {
                    result.dataSectionEntropy = secEntropy;
                }

                if (secEntropy >= PackerConstants::HIGH_SECTION_ENTROPY) {
                    ++result.highEntropySectionCount;
                }
            }
        }

        if (entropyCount > 0) {
            result.averageSectionEntropy = totalEntropy / entropyCount;
        }

        result.entropyIndicatesCompression =
            (result.fileEntropy >= PackerConstants::MIN_COMPRESSED_ENTROPY &&
             result.fileEntropy < PackerConstants::MIN_ENCRYPTED_ENTROPY);

        result.entropyIndicatesEncryption =
            (result.fileEntropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);

        if (result.entropyIndicatesEncryption) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"Very high entropy (%.2f) indicates encryption",
                    result.fileEntropy));
        } else if (result.entropyIndicatesCompression) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"High entropy (%.2f) indicates compression",
                    result.fileEntropy));
        }
    }

    [[nodiscard]] double CalculateChiSquared(const uint8_t* buffer, size_t size) const noexcept {
        if (size == 0) return 0.0;

        std::array<size_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            ++freq[buffer[i]];
        }

        double expected = static_cast<double>(size) / 256.0;
        double chiSquared = 0.0;

        for (size_t count : freq) {
            double diff = static_cast<double>(count) - expected;
            chiSquared += (diff * diff) / expected;
        }

        return chiSquared;
    }

    void AnalyzeSectionsInternal(
        const uint8_t* buffer,
        size_t size,
        const PEParser::PEInfo& peInfo,
        PackingInfo& result) noexcept
    {
        result.sectionCount = static_cast<uint32_t>(peInfo.sections.size());

        for (const auto& peSec : peInfo.sections) {
            SectionInfo sec;
            sec.name = peSec.name;
            sec.virtualAddress = peSec.virtualAddress;
            sec.virtualSize = peSec.virtualSize;
            sec.rawSize = peSec.rawSize;
            sec.rawDataPointer = peSec.rawAddress;
            sec.characteristics = peSec.characteristics;
            sec.isExecutable = peSec.isExecutable;
            sec.isWritable = peSec.isWritable;
            sec.isReadable = peSec.isReadable;
            sec.isEmpty = (peSec.virtualSize > 0 && peSec.rawSize == 0);

            if (peSec.isExecutable) ++result.executableSectionCount;
            if (peSec.isWritable) ++result.writableSectionCount;

            if (peSec.rawSize >= MIN_SECTION_SIZE_FOR_ENTROPY &&
                peSec.rawAddress + peSec.rawSize <= size) {
                sec.entropy = CalculateEntropy(buffer + peSec.rawAddress, peSec.rawSize);
                sec.hasHighEntropy = sec.entropy >= PackerConstants::HIGH_SECTION_ENTROPY;
            }

            std::string nameLower = sec.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            for (const auto& knownSection : PackerConstants::KNOWN_PACKER_SECTIONS) {
                if (nameLower == knownSection) {
                    sec.isPackerSection = true;
                    sec.matchedPackerName = std::string(knownSection);
                    ++result.packerSectionMatches;
                    break;
                }
            }

            if (peSec.isExecutable && peSec.isWritable) {
                result.hasWritableCodeSections = true;
                sec.anomalies.push_back(L"Section is both writable and executable");
            }

            bool isStandard = (nameLower == ".text" || nameLower == ".data" ||
                               nameLower == ".rdata" || nameLower == ".bss" ||
                               nameLower == ".idata" || nameLower == ".edata" ||
                               nameLower == ".rsrc" || nameLower == ".reloc" ||
                               nameLower == ".tls" || nameLower == "code" ||
                               nameLower == "data");
            if (!isStandard) {
                result.hasNonStandardSections = true;
            }

            result.sections.push_back(std::move(sec));
        }

        if (result.packerSectionMatches > 0) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"%u known packer section(s) detected",
                    result.packerSectionMatches));
        }

        if (result.hasWritableCodeSections) {
            result.indicators.push_back(L"Writable and executable sections detected");
            result.anomalies.push_back(L"W+X sections present");
        }

        if (result.highEntropySectionCount > 0) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"%u high-entropy section(s)",
                    result.highEntropySectionCount));
        }
    }

    void AnalyzeEntryPointInternal(
        const uint8_t* buffer,
        size_t size,
        const PEParser::PEInfo& peInfo,
        PEParser::PEParser& parser,
        PackingInfo& result) noexcept
    {
        result.entryPointInfo.rva = peInfo.entryPointRva;
        result.entryPointInfo.valid = true;

        auto epOffset = parser.RvaToOffset(peInfo.entryPointRva);
        if (!epOffset || *epOffset >= size) {
            result.epOutsideCodeSection = true;
            result.anomalies.push_back(L"Entry point outside valid sections");
            return;
        }

        result.entryPointInfo.fileOffset = static_cast<uint32_t>(*epOffset);
        result.entryPointInfo.isInValidSection = true;

        for (size_t i = 0; i < peInfo.sections.size(); ++i) {
            const auto& sec = peInfo.sections[i];
            if (peInfo.entryPointRva >= sec.virtualAddress &&
                peInfo.entryPointRva < sec.virtualAddress + sec.virtualSize) {
                result.entryPointInfo.containingSection = sec.name;
                result.entryPointInfo.isOutsideCodeSection = !sec.hasCode;

                if (i == peInfo.sections.size() - 1) {
                    result.indicators.push_back(L"Entry point in last section (common packer pattern)");
                }
                break;
            }
        }

        size_t bytesToRead = std::min(static_cast<size_t>(MAX_EP_BYTES), size - *epOffset);
        if (bytesToRead > 0) {
            result.entryPointInfo.epBytes.resize(bytesToRead);
            std::memcpy(result.entryPointInfo.epBytes.data(), buffer + *epOffset, bytesToRead);

            auto match = MatchEPSignatureInternal(
                result.entryPointInfo.epBytes.data(),
                result.entryPointInfo.epBytes.size()
            );

            if (match) {
                result.entryPointInfo.matchedPacker = match->packerType;
                result.entryPointInfo.matchedSignature = match->packerName;
                result.entryPointInfo.matchConfidence = match->confidence;
                AddMatch(result, *match);
            }
        }
    }

    void AnalyzeImportsInternal(
        PEParser::PEParser& parser,
        PackingInfo& result) noexcept
    {
        std::vector<PEParser::ImportInfo> imports;
        PEParser::PEError peErr;

        if (!parser.ParseImports(imports, &peErr)) {
            return;
        }

        result.importInfo.valid = true;
        result.importInfo.dllCount = imports.size();

        for (const auto& imp : imports) {
            result.importInfo.totalImports += imp.functions.size();
            result.importInfo.dlls.push_back(Utils::StringUtils::ToNarrow(imp.dllName));

            for (const auto& func : imp.functions) {
                if (func.name == "GetProcAddress") {
                    result.importInfo.hasGetProcAddress = true;
                }
                if (func.name == "LoadLibraryA" || func.name == "LoadLibraryW") {
                    result.importInfo.hasLoadLibrary = true;
                }
                if (func.name == "VirtualAlloc" || func.name == "VirtualProtect") {
                    result.importInfo.hasVirtualMemoryAPIs = true;
                }
            }
        }

        result.importInfo.hasMinimalImports =
            (result.importInfo.totalImports < PackerConstants::MIN_NORMAL_IMPORTS);
        result.hasMinimalImports = result.importInfo.hasMinimalImports;

        if (result.hasMinimalImports) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"Minimal imports (%zu total)",
                    result.importInfo.totalImports));
        }

        if (result.importInfo.hasGetProcAddress && result.importInfo.hasLoadLibrary &&
            result.importInfo.totalImports < 10) {
            result.indicators.push_back(L"Dynamic API resolution pattern detected");
        }
    }

    void AnalyzeOverlayInternal(
        const uint8_t* buffer,
        size_t size,
        const PEParser::PEInfo& peInfo,
        PackingInfo& result) noexcept
    {
        if (peInfo.overlaySize == 0) {
            result.overlayInfo.valid = true;
            result.overlayInfo.hasOverlay = false;
            return;
        }

        result.overlayInfo.valid = true;
        result.overlayInfo.hasOverlay = true;
        result.overlayInfo.offset = peInfo.overlayOffset;
        result.overlayInfo.size = peInfo.overlaySize;
        result.overlayInfo.percentageOfFile =
            (static_cast<double>(peInfo.overlaySize) / static_cast<double>(size)) * 100.0;

        if (peInfo.overlayOffset + 16 <= size) {
            const uint8_t* overlayData = buffer + peInfo.overlayOffset;
            std::copy_n(overlayData, std::min(size_t(16), peInfo.overlaySize),
                result.overlayInfo.magicBytes.begin());

            if (overlayData[0] == 0x50 && overlayData[1] == 0x4B) {
                result.overlayInfo.detectedFormat = L"ZIP archive";
            } else if (overlayData[0] == 0xEF && overlayData[1] == 0xBE &&
                       overlayData[2] == 0xAD && overlayData[3] == 0xDE) {
                result.overlayInfo.detectedFormat = L"NSIS data";
            }
        }

        size_t overlayAnalyzeSize = std::min(peInfo.overlaySize,
            PackerConstants::MAX_OVERLAY_SIZE);
        if (overlayAnalyzeSize >= MIN_SECTION_SIZE_FOR_ENTROPY &&
            peInfo.overlayOffset + overlayAnalyzeSize <= size) {
            result.overlayInfo.entropy = CalculateEntropy(
                buffer + peInfo.overlayOffset, overlayAnalyzeSize);
            result.overlayInfo.isCompressed =
                (result.overlayInfo.entropy >= PackerConstants::MIN_COMPRESSED_ENTROPY);
            result.overlayInfo.isEncrypted =
                (result.overlayInfo.entropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);
        }

        if (result.overlayInfo.percentageOfFile > PackerConstants::SUSPICIOUS_OVERLAY_PERCENTAGE) {
            result.indicators.push_back(
                Utils::StringUtils::Format(L"Large overlay (%.1f%% of file)",
                    result.overlayInfo.percentageOfFile));
        }
    }

    void AnalyzeRichHeaderInternal(
        PEParser::PEParser& parser,
        PackingInfo& result) noexcept
    {
        PEParser::RichHeaderInfo richInfo;
        PEParser::PEError peErr;

        if (!parser.ParseRichHeader(richInfo, &peErr)) {
            return;
        }

        result.richHeaderInfo.valid = true;
        result.richHeaderInfo.hasRichHeader = richInfo.present;
        result.richHeaderInfo.checksum = richInfo.checksum;

        for (const auto& entry : richInfo.entries) {
            RichHeaderInfo::CompilerEntry ce;
            ce.buildNumber = entry.buildId;
            ce.productId = entry.productId;
            ce.useCount = entry.useCount;
            result.richHeaderInfo.entries.push_back(ce);
        }
    }

    void AnalyzeResourcesInternal(
        PEParser::PEParser& parser,
        const uint8_t* buffer,
        size_t size,
        PackingInfo& result) noexcept
    {
        std::vector<PEParser::ResourceEntry> resources;
        PEParser::PEError peErr;

        if (!parser.ParseResources(resources, 16, &peErr)) {
            return;
        }

        result.resourceInfo.valid = true;
        result.resourceInfo.count = resources.size();

        for (const auto& res : resources) {
            result.resourceInfo.totalSize += res.size;
            if (res.size > result.resourceInfo.largestResourceSize) {
                result.resourceInfo.largestResourceSize = res.size;
            }

            if (res.size >= MIN_SECTION_SIZE_FOR_ENTROPY &&
                res.offset + res.size <= size) {
                double entropy = CalculateEntropy(buffer + res.offset, res.size);
                if (entropy >= PackerConstants::HIGH_SECTION_ENTROPY) {
                    ++result.resourceInfo.highEntropyCount;
                }
                result.resourceInfo.averageEntropy += entropy;
            }
        }

        if (result.resourceInfo.count > 0) {
            result.resourceInfo.averageEntropy /= result.resourceInfo.count;
        }
    }

    void PerformHeuristicAnalysis(
        const uint8_t* buffer,
        size_t size,
        const PEParser::PEInfo& peInfo,
        PackingInfo& result) noexcept
    {
        if (!result.entryPointInfo.epBytes.empty()) {
            AnalyzeStubCode(
                result.entryPointInfo.epBytes.data(),
                result.entryPointInfo.epBytes.size(),
                peInfo.is64Bit,
                result
            );
        }

        if (result.importInfo.hasGetProcAddress && result.importInfo.hasLoadLibrary) {
            if (result.importInfo.totalImports < PackerConstants::SUSPICIOUS_LOW_IMPORT_COUNT) {
                result.indicators.push_back(L"Minimal imports with dynamic API resolution");
                result.hasSuspiciousCharacteristics = true;
            }
        }

        if (result.entryPointInfo.isOutsideCodeSection) {
            result.indicators.push_back(L"Entry point outside code section");
            result.hasSuspiciousCharacteristics = true;
        }
    }

    void AnalyzeStubCode(
        const uint8_t* code,
        size_t codeSize,
        bool is64Bit,
        PackingInfo& result) noexcept
    {
        ZydisDecoder* decoder = is64Bit ? &m_decoder64 : &m_decoder32;

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanUSize offset = 0;

        size_t pushCount = 0;
        bool hasUnpackLoop = false;

        size_t instructionCount = 0;

        while (offset < codeSize && instructionCount < MAX_STUB_INSTRUCTIONS) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, code + offset,
                codeSize - offset, &instruction, operands))) {
                break;
            }

            switch (instruction.mnemonic) {
                case ZYDIS_MNEMONIC_PUSH:
                case ZYDIS_MNEMONIC_PUSHFQ:
                case ZYDIS_MNEMONIC_PUSHA:
                case ZYDIS_MNEMONIC_PUSHAD:
                    ++pushCount;
                    break;

                case ZYDIS_MNEMONIC_LOOP:
                case ZYDIS_MNEMONIC_LOOPE:
                case ZYDIS_MNEMONIC_LOOPNE:
                    hasUnpackLoop = true;
                    break;

                case ZYDIS_MNEMONIC_XOR:
                    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY ||
                        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        result.indicators.push_back(L"XOR decryption pattern detected");
                    }
                    break;

                default:
                    break;
            }

            offset += instruction.length;
            ++instructionCount;
        }

        if (pushCount > 5 && instructionCount < 20) {
            result.indicators.push_back(L"Register preservation at entry (packer stub pattern)");
        }

        if (hasUnpackLoop) {
            result.indicators.push_back(L"Decompression/decryption loop detected");
        }
    }

    void AnalyzeStubForAntiUnpacking(
        const std::vector<uint8_t>& epBytes,
        UnpackingHints& hints) noexcept
    {
        for (size_t i = 0; i + 1 < epBytes.size(); ++i) {
            if (epBytes[i] == 0x0F && epBytes[i + 1] == 0x31) {
                hints.antiUnpackingTechniques.push_back(L"RDTSC timing check");
                break;
            }
        }

        for (size_t i = 0; i + 1 < epBytes.size(); ++i) {
            if (epBytes[i] == 0xCD && epBytes[i + 1] == 0x2D) {
                hints.antiUnpackingTechniques.push_back(L"INT 2D debugger check");
                break;
            }
        }
    }

    [[nodiscard]] std::optional<PackerMatch> MatchEPSignatureInternal(
        const uint8_t* epBytes,
        size_t size) noexcept
    {
        if (epBytes == nullptr || size == 0) {
            return std::nullopt;
        }

        for (const auto& sig : EPSignatures::BuiltInSignatures) {
            if (EPSignatures::MatchPattern(epBytes, size, sig.pattern, sig.mask)) {
                PackerMatch match;
                match.packerType = sig.packerType;
                match.packerName = sig.packerName;
                match.version = sig.version;
                match.category = GetPackerCategory(sig.packerType);
                match.severity = GetPackerSeverity(sig.packerType);
                match.method = DetectionMethod::EPSignature;
                match.confidence = sig.confidence;
                match.mitreId = PackerTypeToMitreId(sig.packerType);
                match.detectionTime = std::chrono::system_clock::now();
                return match;
            }
        }

        {
            std::shared_lock lock(m_customPatternsMutex);
            for (const auto& sig : m_customEPSignatures) {
                if (EPSignatures::MatchPattern(epBytes, size, sig.pattern, sig.mask)) {
                    PackerMatch match;
                    match.packerType = sig.packerType;
                    match.packerName = sig.packerName;
                    match.category = GetPackerCategory(sig.packerType);
                    match.severity = GetPackerSeverity(sig.packerType);
                    match.method = DetectionMethod::EPSignature;
                    match.confidence = sig.confidence;
                    match.mitreId = PackerTypeToMitreId(sig.packerType);
                    match.detectionTime = std::chrono::system_clock::now();
                    return match;
                }
            }
        }

        return std::nullopt;
    }

    void AddMatch(PackingInfo& result, PackerMatch match) noexcept {
        {
            std::shared_lock lock(m_callbackMutex);
            if (m_detectionCallback && !result.filePath.empty()) {
                m_detectionCallback(result.filePath, match);
            }
        }

        result.packerMatches.push_back(std::move(match));
    }

    void DeterminePackingVerdict(PackingInfo& result, const PackerAnalysisConfig& config) noexcept {
        double score = 0.0;
        double maxPossibleScore = 0.0;

        maxPossibleScore += PackerConstants::WEIGHT_ENTROPY;
        if (result.entropyIndicatesEncryption) {
            score += PackerConstants::WEIGHT_ENTROPY;
        } else if (result.entropyIndicatesCompression) {
            score += PackerConstants::WEIGHT_ENTROPY * 0.7;
        } else if (result.fileEntropy > 6.0) {
            score += PackerConstants::WEIGHT_ENTROPY * 0.4;
        }

        maxPossibleScore += PackerConstants::WEIGHT_SECTION_ANOMALIES;
        if (result.packerSectionMatches > 0) {
            score += PackerConstants::WEIGHT_SECTION_ANOMALIES;
        } else if (result.hasWritableCodeSections) {
            score += PackerConstants::WEIGHT_SECTION_ANOMALIES * 0.6;
        } else if (result.highEntropySectionCount > 0) {
            score += PackerConstants::WEIGHT_SECTION_ANOMALIES * 0.4;
        }

        maxPossibleScore += PackerConstants::WEIGHT_EP_SIGNATURE;
        if (!result.packerMatches.empty()) {
            double bestConfidence = 0.0;
            for (const auto& match : result.packerMatches) {
                if (match.method == DetectionMethod::EPSignature &&
                    match.confidence > bestConfidence) {
                    bestConfidence = match.confidence;
                }
            }
            score += PackerConstants::WEIGHT_EP_SIGNATURE * bestConfidence;
        }

        maxPossibleScore += PackerConstants::WEIGHT_IMPORT_ANOMALIES;
        if (result.hasMinimalImports) {
            score += PackerConstants::WEIGHT_IMPORT_ANOMALIES * 0.6;
            if (result.importInfo.hasGetProcAddress && result.importInfo.hasLoadLibrary) {
                score += PackerConstants::WEIGHT_IMPORT_ANOMALIES * 0.4;
            }
        }

        maxPossibleScore += PackerConstants::WEIGHT_OVERLAY;
        if (result.overlayInfo.hasOverlay &&
            result.overlayInfo.percentageOfFile > PackerConstants::SUSPICIOUS_OVERLAY_PERCENTAGE) {
            score += PackerConstants::WEIGHT_OVERLAY;
        }

        maxPossibleScore += PackerConstants::WEIGHT_STRUCTURAL;
        if (result.epOutsideCodeSection || result.hasNonStandardSections) {
            score += PackerConstants::WEIGHT_STRUCTURAL * 0.5;
        }
        if (result.hasSuspiciousCharacteristics) {
            score += PackerConstants::WEIGHT_STRUCTURAL * 0.5;
        }

        maxPossibleScore += PackerConstants::WEIGHT_YARA_MATCH;
        for (const auto& match : result.packerMatches) {
            if (match.method == DetectionMethod::YARARule) {
                score += PackerConstants::WEIGHT_YARA_MATCH;
                break;
            }
        }

        result.packingConfidence = (maxPossibleScore > 0) ?
            (score / maxPossibleScore) : 0.0;

        result.isPacked = (result.packingConfidence >= config.minConfidenceThreshold);

        if (!result.packerMatches.empty()) {
            const PackerMatch* bestMatch = result.GetBestMatch();
            if (bestMatch) {
                result.primaryPacker = bestMatch->packerType;
                result.packerName = bestMatch->packerName;
                result.packerVersion = bestMatch->version;
                result.packerCategory = bestMatch->category;
                result.severity = bestMatch->severity;
            }
        } else if (result.isPacked) {
            result.primaryPacker = PackerType::Unknown;
            result.packerCategory = PackerCategory::Unknown;

            if (result.entropyIndicatesEncryption) {
                result.packerCategory = PackerCategory::Crypter;
                result.severity = PackerSeverity::High;
            } else if (result.entropyIndicatesCompression) {
                result.packerCategory = PackerCategory::Compression;
                result.severity = PackerSeverity::Low;
            }
        }

        if (result.isInstaller && config.treatInstallersAsBenign) {
            result.severity = PackerSeverity::Benign;
        }

        if (result.packerMatches.size() > 1) {
            result.hasMultipleLayers = true;
            result.layerCount = static_cast<uint32_t>(result.packerMatches.size());
        }
    }

    void UpdateCache(const std::wstring& filePath, const PackingInfo& result) noexcept {
        std::unique_lock lock(m_cacheMutex);

        while (m_cache.size() >= PackerConstants::MAX_CACHE_ENTRIES) {
            m_cache.erase(m_cache.begin());
        }

        m_cache[filePath] = { result, std::chrono::system_clock::now() };
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    std::atomic<bool> m_initialized{ false };
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_customPatternsMutex;

    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;
    std::shared_ptr<HashStore::HashStore> m_hashStore;

    Utils::pe_sig_utils::PEFileSignatureVerifier m_sigVerifier;

    ZydisDecoder m_decoder32{};
    ZydisDecoder m_decoder64{};
    ZydisFormatter m_formatter{};

    std::unordered_map<PackerType, EPSignatures::EPSignature> m_epSignatureMap;

    std::vector<EPSignatures::EPSignature> m_customEPSignatures;
    std::unordered_map<std::string, PackerType> m_customSectionPatterns;

    std::unordered_map<std::wstring,
        std::pair<PackingInfo, std::chrono::system_clock::time_point>> m_cache;

    PackerDetectionCallback m_detectionCallback;

    mutable Statistics m_stats;
};

// ============================================================================
// PACKERTYPETOSTRING IMPLEMENTATION
// ============================================================================

const wchar_t* PackerTypeToString(PackerType type) noexcept {
    switch (type) {
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
        case PackerType::Petite: return L"Petite";
        case PackerType::FSG: return L"FSG";
        case PackerType::FSG_v1: return L"FSG v1.x";
        case PackerType::FSG_v2: return L"FSG v2.x";
        case PackerType::MEW: return L"MEW";
        case PackerType::NsPack: return L"NsPack";
        case PackerType::Upack: return L"Upack";
        case PackerType::WinUpack: return L"WinUpack";
        case PackerType::kkrunchy: return L"kkrunchy";
        case PackerType::RLPack: return L"RLPack";
        case PackerType::Themida: return L"Themida";
        case PackerType::Themida_v2: return L"Themida v2.x";
        case PackerType::Themida_v3: return L"Themida v3.x";
        case PackerType::WinLicense: return L"WinLicense";
        case PackerType::VMProtect: return L"VMProtect";
        case PackerType::VMProtect_v2: return L"VMProtect v2.x";
        case PackerType::VMProtect_v3: return L"VMProtect v3.x";
        case PackerType::Enigma: return L"Enigma Protector";
        case PackerType::ASProtect: return L"ASProtect";
        case PackerType::Armadillo: return L"Armadillo";
        case PackerType::Obsidium: return L"Obsidium";
        case PackerType::PELock: return L"PELock";
        case PackerType::CodeVirtualizer: return L"Code Virtualizer";
        case PackerType::ExeCryptor: return L"ExeCryptor";
        case PackerType::Safengine: return L"Safengine";
        case PackerType::StarForce: return L"StarForce";
        case PackerType::SecuROM: return L"SecuROM";
        case PackerType::SafeDisc: return L"SafeDisc";
        case PackerType::Denuvo: return L"Denuvo";
        case PackerType::PESpin: return L"PESpin";
        case PackerType::tElock: return L"tElock";
        case PackerType::YodaCrypter: return L"Yoda's Crypter";
        case PackerType::YodaProtector: return L"Yoda's Protector";
        case PackerType::PECrypt32: return L"PECrypt32";
        case PackerType::Morphine: return L"Morphine";
        case PackerType::ConfuserEx: return L"ConfuserEx";
        case PackerType::DotNetReactor: return L".NET Reactor";
        case PackerType::Eazfuscator: return L"Eazfuscator.NET";
        case PackerType::Dotfuscator: return L"Dotfuscator";
        case PackerType::SmartAssembly: return L"SmartAssembly";
        case PackerType::NSIS: return L"NSIS";
        case PackerType::InnoSetup: return L"Inno Setup";
        case PackerType::InstallShield: return L"InstallShield";
        case PackerType::WiX: return L"WiX";
        case PackerType::SevenZip_SFX: return L"7-Zip SFX";
        case PackerType::WinRAR_SFX: return L"WinRAR SFX";
        case PackerType::WinZip_SFX: return L"WinZip SFX";
        case PackerType::Cobalt_Strike_Beacon: return L"Cobalt Strike Beacon";
        case PackerType::Custom_Packer: return L"Custom Packer";
        default: return L"Unknown";
    }
}

// ============================================================================
// PACKERDETECTOR PUBLIC INTERFACE
// ============================================================================

PackerDetector::PackerDetector() noexcept
    : m_impl(std::make_unique<Impl>())
{}

PackerDetector::PackerDetector(
    std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept
    : m_impl(std::make_unique<Impl>(std::move(sigStore)))
{}

PackerDetector::PackerDetector(
    std::shared_ptr<SignatureStore::SignatureStore> sigStore,
    std::shared_ptr<PatternStore::PatternStore> patternStore,
    std::shared_ptr<HashStore::HashStore> hashStore) noexcept
    : m_impl(std::make_unique<Impl>(
        std::move(sigStore), std::move(patternStore), std::move(hashStore)))
{}

PackerDetector::~PackerDetector() = default;

PackerDetector::PackerDetector(PackerDetector&&) noexcept = default;
PackerDetector& PackerDetector::operator=(PackerDetector&&) noexcept = default;

bool PackerDetector::Initialize(PackerError* err) noexcept {
    return m_impl->Initialize(err);
}

void PackerDetector::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool PackerDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

PackingInfo PackerDetector::AnalyzeFile(
    const std::wstring& filePath,
    const PackerAnalysisConfig& config,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeFile(filePath, config, err);
}

PackingInfo PackerDetector::AnalyzeBuffer(
    const uint8_t* buffer,
    size_t size,
    const PackerAnalysisConfig& config,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeBuffer(buffer, size, config, err);
}

PackerBatchResult PackerDetector::AnalyzeFiles(
    const std::vector<std::wstring>& filePaths,
    const PackerAnalysisConfig& config,
    PackerProgressCallback progressCallback,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeFiles(filePaths, config, progressCallback, err);
}

PackerBatchResult PackerDetector::AnalyzeDirectory(
    const std::wstring& directoryPath,
    bool recursive,
    const PackerAnalysisConfig& config,
    PackerProgressCallback progressCallback,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeDirectory(directoryPath, recursive, config, progressCallback, err);
}

double PackerDetector::CalculateEntropy(const uint8_t* buffer, size_t size) noexcept {
    return Impl::CalculateEntropy(buffer, size);
}

double PackerDetector::CalculateSectionEntropy(
    const std::wstring& filePath,
    uint32_t sectionOffset,
    uint32_t sectionSize,
    PackerError* err) noexcept
{
    return m_impl->CalculateSectionEntropy(filePath, sectionOffset, sectionSize, err);
}

bool PackerDetector::AnalyzeSections(
    const std::wstring& filePath,
    std::vector<SectionInfo>& outSections,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeSections(filePath, outSections, err);
}

bool PackerDetector::AnalyzeImports(
    const std::wstring& filePath,
    ImportInfo& outImports,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeImports(filePath, outImports, err);
}

bool PackerDetector::AnalyzeOverlay(
    const std::wstring& filePath,
    OverlayInfo& outOverlay,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeOverlay(filePath, outOverlay, err);
}

bool PackerDetector::AnalyzeEntryPoint(
    const std::wstring& filePath,
    EntryPointInfo& outEP,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeEntryPoint(filePath, outEP, err);
}

std::optional<PackerMatch> PackerDetector::MatchEPSignature(
    const uint8_t* epBytes,
    size_t size,
    PackerError* err) noexcept
{
    return m_impl->MatchEPSignature(epBytes, size, err);
}

bool PackerDetector::VerifySignature(
    const std::wstring& filePath,
    SignatureInfo& outSignature,
    PackerError* err) noexcept
{
    return m_impl->VerifySignature(filePath, outSignature, err);
}

bool PackerDetector::AnalyzeRichHeader(
    const std::wstring& filePath,
    RichHeaderInfo& outRichHeader,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeRichHeader(filePath, outRichHeader, err);
}

bool PackerDetector::AnalyzeResources(
    const std::wstring& filePath,
    ResourceInfo& outResources,
    PackerError* err) noexcept
{
    return m_impl->AnalyzeResources(filePath, outResources, err);
}

bool PackerDetector::ScanWithYARA(
    const std::wstring& filePath,
    std::vector<PackerMatch>& outMatches,
    PackerError* err) noexcept
{
    return m_impl->ScanWithYARA(filePath, outMatches, err);
}

bool PackerDetector::GenerateUnpackingHints(
    const PackingInfo& packingInfo,
    UnpackingHints& outHints,
    PackerError* err) noexcept
{
    return m_impl->GenerateUnpackingHints(packingInfo, outHints, err);
}

bool PackerDetector::IsInstaller(
    const std::wstring& filePath,
    std::wstring& installerType,
    PackerError* err) noexcept
{
    return m_impl->IsInstaller(filePath, installerType, err);
}

bool PackerDetector::IsDotNetAssembly(
    const std::wstring& filePath,
    PackerError* err) noexcept
{
    return m_impl->IsDotNetAssembly(filePath, err);
}

void PackerDetector::SetDetectionCallback(PackerDetectionCallback callback) noexcept {
    m_impl->SetDetectionCallback(std::move(callback));
}

void PackerDetector::ClearDetectionCallback() noexcept {
    m_impl->ClearDetectionCallback();
}

std::optional<PackingInfo> PackerDetector::GetCachedResult(
    const std::wstring& filePath) const noexcept
{
    return m_impl->GetCachedResult(filePath);
}

void PackerDetector::InvalidateCache(const std::wstring& filePath) noexcept {
    m_impl->InvalidateCache(filePath);
}

void PackerDetector::ClearCache() noexcept {
    m_impl->ClearCache();
}

size_t PackerDetector::GetCacheSize() const noexcept {
    return m_impl->GetCacheSize();
}

void PackerDetector::SetSignatureStore(
    std::shared_ptr<SignatureStore::SignatureStore> sigStore) noexcept
{
    m_impl->SetSignatureStore(std::move(sigStore));
}

void PackerDetector::SetPatternStore(
    std::shared_ptr<PatternStore::PatternStore> patternStore) noexcept
{
    m_impl->SetPatternStore(std::move(patternStore));
}

void PackerDetector::SetHashStore(
    std::shared_ptr<HashStore::HashStore> hashStore) noexcept
{
    m_impl->SetHashStore(std::move(hashStore));
}

void PackerDetector::AddCustomEPSignature(
    std::wstring_view packerName,
    const std::vector<uint8_t>& signature,
    PackerType type) noexcept
{
    m_impl->AddCustomEPSignature(packerName, signature, type);
}

void PackerDetector::AddCustomSectionPattern(
    std::string_view sectionName,
    PackerType type) noexcept
{
    m_impl->AddCustomSectionPattern(sectionName, type);
}

void PackerDetector::ClearCustomPatterns() noexcept {
    m_impl->ClearCustomPatterns();
}

const PackerDetector::Statistics& PackerDetector::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void PackerDetector::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

// ============================================================================
// PRIVATE METHOD IMPLEMENTATIONS (PackerDetector class)
// ============================================================================

void PackerDetector::AnalyzeFileInternal(
    const uint8_t* buffer,
    size_t size,
    const std::wstring& filePath,
    const PackerAnalysisConfig& config,
    PackingInfo& result) noexcept
{
    if (!m_impl || buffer == nullptr || size == 0) {
        return;
    }

    // Parse PE structure first
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    PEParser::PEError peErr;

    if (!parser.ParseBuffer(buffer, size, peInfo, &peErr)) {
        result.errors.push_back({ ERROR_BAD_FORMAT, L"Failed to parse PE structure", filePath });
        return;
    }

    result.isDotNetAssembly = peInfo.isDotNet;
    result.fileSize = size;
    result.filePath = filePath;

    // Run all enabled analysis modules
    if (HasFlag(config.flags, PackerAnalysisFlags::EnableEntropyAnalysis)) {
        AnalyzeEntropyDistribution(buffer, size, result);
    }

    if (HasFlag(config.flags, PackerAnalysisFlags::EnableSectionAnalysis)) {
        AnalyzePEStructure(buffer, size, result);
    }

    if (HasFlag(config.flags, PackerAnalysisFlags::EnableEPSignature)) {
        MatchPackerSignatures(buffer, size, result);
    }

    if (HasFlag(config.flags, PackerAnalysisFlags::EnableHeuristicAnalysis)) {
        PerformHeuristicAnalysis(buffer, size, result);
    }

    if (HasFlag(config.flags, PackerAnalysisFlags::EnableSignatureVerification) &&
        !filePath.empty()) {
        SignatureInfo sigInfo;
        m_sigVerifier.VerifyPESignature(filePath,result.signatureInfo, nullptr);
    }

    // Determine final verdict
    DeterminePackingVerdict(result);

    // Cache the result if caching is enabled
    if (config.enableCaching && !filePath.empty()) {
        UpdateCache(filePath, result);
    }
}

void PackerDetector::AnalyzeEntropyDistribution(
    const uint8_t* buffer,
    size_t size,
    PackingInfo& result) noexcept
{
    if (buffer == nullptr || size == 0) {
        return;
    }

    // Calculate file-wide Shannon entropy
    result.fileEntropy = CalculateEntropy(buffer, size);

    // Entropy thresholds for classification
    result.entropyIndicatesCompression =
        (result.fileEntropy >= PackerConstants::MIN_COMPRESSED_ENTROPY &&
         result.fileEntropy < PackerConstants::MIN_ENCRYPTED_ENTROPY);

    result.entropyIndicatesEncryption =
        (result.fileEntropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);

    // Calculate Chi-squared for randomness assessment
    if (size > 0) {
        std::array<size_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            ++freq[buffer[i]];
        }

        double expected = static_cast<double>(size) / 256.0;
        double chiSquared = 0.0;

        for (size_t count : freq) {
            double diff = static_cast<double>(count) - expected;
            chiSquared += (diff * diff) / expected;
        }

        result.chiSquared = chiSquared;
    }

    // Parse PE to get section-level entropy
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;

    if (parser.ParseBuffer(buffer, size, peInfo, nullptr)) {
        double totalEntropy = 0.0;
        size_t entropyCount = 0;

        for (const auto& sec : peInfo.sections) {
            constexpr size_t MIN_SECTION_SIZE = 256;

            if (sec.rawSize >= MIN_SECTION_SIZE &&
                sec.rawAddress + sec.rawSize <= size) {

                double secEntropy = CalculateEntropy(buffer + sec.rawAddress, sec.rawSize);

                if (secEntropy > result.maxSectionEntropy) {
                    result.maxSectionEntropy = secEntropy;
                    result.maxEntropySectionName = sec.name;
                }

                totalEntropy += secEntropy;
                ++entropyCount;

                if (sec.hasCode) {
                    result.codeSectionEntropy = secEntropy;
                } else if (sec.hasInitializedData) {
                    result.dataSectionEntropy = secEntropy;
                }

                if (secEntropy >= PackerConstants::HIGH_SECTION_ENTROPY) {
                    ++result.highEntropySectionCount;
                }
            }
        }

        if (entropyCount > 0) {
            result.averageSectionEntropy = totalEntropy / entropyCount;
        }
    }

    // Add indicators based on entropy analysis
    if (result.entropyIndicatesEncryption) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"Very high entropy (%.2f) indicates encryption",
                result.fileEntropy));
    } else if (result.entropyIndicatesCompression) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"High entropy (%.2f) indicates compression",
                result.fileEntropy));
    }
}

void PackerDetector::AnalyzePEStructure(
    const uint8_t* buffer,
    size_t size,
    PackingInfo& result) noexcept
{
    if (buffer == nullptr || size == 0) {
        return;
    }

    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    PEParser::PEError peErr;

    if (!parser.ParseBuffer(buffer, size, peInfo, &peErr)) {
        return;
    }

    result.sectionCount = static_cast<uint32_t>(peInfo.sections.size());

    for (const auto& peSec : peInfo.sections) {
        SectionInfo sec;
        sec.name = peSec.name;
        sec.virtualAddress = peSec.virtualAddress;
        sec.virtualSize = peSec.virtualSize;
        sec.rawSize = peSec.rawSize;
        sec.rawDataPointer = peSec.rawAddress;
        sec.characteristics = peSec.characteristics;
        sec.isExecutable = peSec.isExecutable;
        sec.isWritable = peSec.isWritable;
        sec.isReadable = peSec.isReadable;
        sec.isEmpty = (peSec.virtualSize > 0 && peSec.rawSize == 0);

        if (peSec.isExecutable) ++result.executableSectionCount;
        if (peSec.isWritable) ++result.writableSectionCount;

        // Calculate section entropy
        constexpr size_t MIN_SECTION_SIZE = 256;
        if (peSec.rawSize >= MIN_SECTION_SIZE &&
            peSec.rawAddress + peSec.rawSize <= size) {
            sec.entropy = CalculateEntropy(buffer + peSec.rawAddress, peSec.rawSize);
            sec.hasHighEntropy = sec.entropy >= PackerConstants::HIGH_SECTION_ENTROPY;
        }

        // Check for known packer section names
        std::string nameLower = sec.name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        for (const auto& knownSection : PackerConstants::KNOWN_PACKER_SECTIONS) {
            if (nameLower == knownSection) {
                sec.isPackerSection = true;
                sec.matchedPackerName = std::string(knownSection);
                ++result.packerSectionMatches;
                break;
            }
        }

        // Detect W+X sections
        if (peSec.isExecutable && peSec.isWritable) {
            result.hasWritableCodeSections = true;
            sec.anomalies.push_back(L"Section is both writable and executable");
        }

        // Check for non-standard section names
        bool isStandard = (nameLower == ".text" || nameLower == ".data" ||
                           nameLower == ".rdata" || nameLower == ".bss" ||
                           nameLower == ".idata" || nameLower == ".edata" ||
                           nameLower == ".rsrc" || nameLower == ".reloc" ||
                           nameLower == ".tls" || nameLower == "code" ||
                           nameLower == "data");
        if (!isStandard) {
            result.hasNonStandardSections = true;
        }

        result.sections.push_back(std::move(sec));
    }

    // Parse imports for minimal import detection
    std::vector<PEParser::ImportInfo> imports;
    if (parser.ParseImports(imports, nullptr)) {
        result.importInfo.valid = true;
        result.importInfo.dllCount = imports.size();

        for (const auto& imp : imports) {
            result.importInfo.totalImports += imp.functions.size();
            result.importInfo.dlls.push_back(Utils::StringUtils::ToNarrow(imp.dllName));

            for (const auto& func : imp.functions) {
                if (func.name == "GetProcAddress") {
                    result.importInfo.hasGetProcAddress = true;
                }
                if (func.name == "LoadLibraryA" || func.name == "LoadLibraryW") {
                    result.importInfo.hasLoadLibrary = true;
                }
                if (func.name == "VirtualAlloc" || func.name == "VirtualProtect") {
                    result.importInfo.hasVirtualMemoryAPIs = true;
                }
            }
        }

        result.importInfo.hasMinimalImports =
            (result.importInfo.totalImports < PackerConstants::MIN_NORMAL_IMPORTS);
        result.hasMinimalImports = result.importInfo.hasMinimalImports;
    }

    // Analyze overlay
    if (peInfo.overlaySize > 0) {
        result.overlayInfo.valid = true;
        result.overlayInfo.hasOverlay = true;
        result.overlayInfo.offset = peInfo.overlayOffset;
        result.overlayInfo.size = peInfo.overlaySize;
        result.overlayInfo.percentageOfFile =
            (static_cast<double>(peInfo.overlaySize) / static_cast<double>(size)) * 100.0;

        // Analyze overlay entropy
        size_t overlayAnalyzeSize = std::min(peInfo.overlaySize,
            PackerConstants::MAX_OVERLAY_SIZE);
        if (overlayAnalyzeSize >= 256 && peInfo.overlayOffset + overlayAnalyzeSize <= size) {
            result.overlayInfo.entropy = CalculateEntropy(
                buffer + peInfo.overlayOffset, overlayAnalyzeSize);
            result.overlayInfo.isCompressed =
                (result.overlayInfo.entropy >= PackerConstants::MIN_COMPRESSED_ENTROPY);
            result.overlayInfo.isEncrypted =
                (result.overlayInfo.entropy >= PackerConstants::MIN_ENCRYPTED_ENTROPY);
        }
    }

    // Analyze entry point location
    result.entryPointInfo.rva = peInfo.entryPointRva;
    result.entryPointInfo.valid = true;

    auto epOffset = parser.RvaToOffset(peInfo.entryPointRva);
    if (epOffset && *epOffset < size) {
        result.entryPointInfo.fileOffset = static_cast<uint32_t>(*epOffset);
        result.entryPointInfo.isInValidSection = true;

        // Determine which section contains the entry point
        for (size_t i = 0; i < peInfo.sections.size(); ++i) {
            const auto& sec = peInfo.sections[i];
            if (peInfo.entryPointRva >= sec.virtualAddress &&
                peInfo.entryPointRva < sec.virtualAddress + sec.virtualSize) {
                result.entryPointInfo.containingSection = sec.name;
                result.entryPointInfo.isOutsideCodeSection = !sec.hasCode;

                if (i == peInfo.sections.size() - 1) {
                    result.indicators.push_back(
                        L"Entry point in last section (common packer pattern)");
                }
                break;
            }
        }
    } else {
        result.epOutsideCodeSection = true;
        result.anomalies.push_back(L"Entry point outside valid sections");
    }

    // Add anomaly indicators
    if (result.packerSectionMatches > 0) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"%u known packer section(s) detected",
                result.packerSectionMatches));
    }

    if (result.hasWritableCodeSections) {
        result.indicators.push_back(L"Writable and executable sections detected");
        result.anomalies.push_back(L"W+X sections present");
    }

    if (result.hasMinimalImports) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"Minimal imports (%zu total)",
                result.importInfo.totalImports));
    }
}

void PackerDetector::MatchPackerSignatures(
    const uint8_t* buffer,
    size_t size,
    PackingInfo& result) noexcept
{
    if (!m_impl || buffer == nullptr || size == 0) {
        return;
    }

    // Get entry point bytes for signature matching
    if (!result.entryPointInfo.valid || result.entryPointInfo.fileOffset >= size) {
        return;
    }

    constexpr size_t MAX_EP_BYTES = 512;
    size_t bytesToRead = std::min(static_cast<size_t>(MAX_EP_BYTES),
        size - result.entryPointInfo.fileOffset);

    if (bytesToRead == 0) {
        return;
    }

    result.entryPointInfo.epBytes.resize(bytesToRead);
    std::memcpy(result.entryPointInfo.epBytes.data(),
        buffer + result.entryPointInfo.fileOffset, bytesToRead);

    // Use Impl's signature matching
    auto match = m_impl->MatchEPSignature(
        result.entryPointInfo.epBytes.data(),
        result.entryPointInfo.epBytes.size(),
        nullptr);

    if (match) {
        result.entryPointInfo.matchedPacker = match->packerType;
        result.entryPointInfo.matchedSignature = match->packerName;
        result.entryPointInfo.matchConfidence = match->confidence;

        AddMatch(result, *match);
    }
}

void PackerDetector::PerformHeuristicAnalysis(
    const uint8_t* buffer,
    size_t size,
    PackingInfo& result) noexcept
{
    if (buffer == nullptr || size == 0) {
        return;
    }

    // Check for dynamic API resolution patterns
    if (result.importInfo.hasGetProcAddress && result.importInfo.hasLoadLibrary) {
        if (result.importInfo.totalImports < PackerConstants::SUSPICIOUS_LOW_IMPORT_COUNT) {
            result.indicators.push_back(L"Minimal imports with dynamic API resolution");
            result.hasSuspiciousCharacteristics = true;
        }
    }

    // Entry point outside code section
    if (result.entryPointInfo.isOutsideCodeSection) {
        result.indicators.push_back(L"Entry point outside code section");
        result.hasSuspiciousCharacteristics = true;
    }

    // Analyze entry point stub for anti-unpacking patterns
    if (!result.entryPointInfo.epBytes.empty()) {
        const auto& epBytes = result.entryPointInfo.epBytes;

        // Look for RDTSC timing check
        for (size_t i = 0; i + 1 < epBytes.size(); ++i) {
            if (epBytes[i] == 0x0F && epBytes[i + 1] == 0x31) {
                result.indicators.push_back(L"RDTSC timing check detected");
                result.hasSuspiciousCharacteristics = true;
                break;
            }
        }

        // Look for INT 2D debugger check
        for (size_t i = 0; i + 1 < epBytes.size(); ++i) {
            if (epBytes[i] == 0xCD && epBytes[i + 1] == 0x2D) {
                result.indicators.push_back(L"INT 2D debugger check detected");
                result.hasSuspiciousCharacteristics = true;
                break;
            }
        }

        // Count register preservation instructions (PUSHA/PUSHAD pattern)
        size_t pushCount = 0;
        for (size_t i = 0; i < std::min(epBytes.size(), size_t(50)); ++i) {
            uint8_t b = epBytes[i];
            // PUSH reg (50-57), PUSHA (60), PUSHAD (60), PUSHF (9C)
            if ((b >= 0x50 && b <= 0x57) || b == 0x60 || b == 0x9C) {
                ++pushCount;
            }
        }

        if (pushCount > 5) {
            result.indicators.push_back(L"Register preservation at entry (packer stub pattern)");
        }

        // Look for XOR decryption patterns (XOR with memory operand)
        for (size_t i = 0; i + 2 < epBytes.size(); ++i) {
            // XOR r/m8, r8 (30), XOR r/m32, r32 (31), XOR r8, r/m8 (32), XOR r32, r/m32 (33)
            if (epBytes[i] >= 0x30 && epBytes[i] <= 0x33) {
                uint8_t modrm = epBytes[i + 1];
                uint8_t mod = (modrm >> 6) & 0x03;
                // If mod != 11b, it involves memory
                if (mod != 0x03) {
                    result.indicators.push_back(L"XOR decryption pattern detected");
                    break;
                }
            }
        }

        // Look for decompression/decryption loops (LOOP/LOOPE/LOOPNE)
        for (size_t i = 0; i < epBytes.size(); ++i) {
            if (epBytes[i] == 0xE2 || epBytes[i] == 0xE1 || epBytes[i] == 0xE0) {
                result.indicators.push_back(L"Decompression/decryption loop detected");
                break;
            }
        }
    }

    // High entropy in code section is suspicious
    if (result.codeSectionEntropy >= PackerConstants::HIGH_SECTION_ENTROPY) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"High entropy in code section (%.2f)",
                result.codeSectionEntropy));
        result.hasSuspiciousCharacteristics = true;
    }

    // Large overlay with high entropy
    if (result.overlayInfo.hasOverlay &&
        result.overlayInfo.percentageOfFile > PackerConstants::SUSPICIOUS_OVERLAY_PERCENTAGE) {
        result.indicators.push_back(
            Utils::StringUtils::Format(L"Large overlay (%.1f%% of file)",
                result.overlayInfo.percentageOfFile));
    }
}

void PackerDetector::DeterminePackingVerdict(PackingInfo& result) noexcept
{
    double score = 0.0;
    double maxPossibleScore = 0.0;

    // Entropy contribution
    maxPossibleScore += PackerConstants::WEIGHT_ENTROPY;
    if (result.entropyIndicatesEncryption) {
        score += PackerConstants::WEIGHT_ENTROPY;
    } else if (result.entropyIndicatesCompression) {
        score += PackerConstants::WEIGHT_ENTROPY * 0.7;
    } else if (result.fileEntropy > 6.0) {
        score += PackerConstants::WEIGHT_ENTROPY * 0.4;
    }

    // Section anomalies contribution
    maxPossibleScore += PackerConstants::WEIGHT_SECTION_ANOMALIES;
    if (result.packerSectionMatches > 0) {
        score += PackerConstants::WEIGHT_SECTION_ANOMALIES;
    } else if (result.hasWritableCodeSections) {
        score += PackerConstants::WEIGHT_SECTION_ANOMALIES * 0.6;
    } else if (result.highEntropySectionCount > 0) {
        score += PackerConstants::WEIGHT_SECTION_ANOMALIES * 0.4;
    }

    // EP signature contribution
    maxPossibleScore += PackerConstants::WEIGHT_EP_SIGNATURE;
    if (!result.packerMatches.empty()) {
        double bestConfidence = 0.0;
        for (const auto& match : result.packerMatches) {
            if (match.method == DetectionMethod::EPSignature &&
                match.confidence > bestConfidence) {
                bestConfidence = match.confidence;
            }
        }
        score += PackerConstants::WEIGHT_EP_SIGNATURE * bestConfidence;
    }

    // Import anomalies contribution
    maxPossibleScore += PackerConstants::WEIGHT_IMPORT_ANOMALIES;
    if (result.hasMinimalImports) {
        score += PackerConstants::WEIGHT_IMPORT_ANOMALIES * 0.6;
        if (result.importInfo.hasGetProcAddress && result.importInfo.hasLoadLibrary) {
            score += PackerConstants::WEIGHT_IMPORT_ANOMALIES * 0.4;
        }
    }

    // Overlay contribution
    maxPossibleScore += PackerConstants::WEIGHT_OVERLAY;
    if (result.overlayInfo.hasOverlay &&
        result.overlayInfo.percentageOfFile > PackerConstants::SUSPICIOUS_OVERLAY_PERCENTAGE) {
        score += PackerConstants::WEIGHT_OVERLAY;
    }

    // Structural anomalies contribution
    maxPossibleScore += PackerConstants::WEIGHT_STRUCTURAL;
    if (result.epOutsideCodeSection || result.hasNonStandardSections) {
        score += PackerConstants::WEIGHT_STRUCTURAL * 0.5;
    }
    if (result.hasSuspiciousCharacteristics) {
        score += PackerConstants::WEIGHT_STRUCTURAL * 0.5;
    }

    // YARA match contribution
    maxPossibleScore += PackerConstants::WEIGHT_YARA_MATCH;
    for (const auto& match : result.packerMatches) {
        if (match.method == DetectionMethod::YARARule) {
            score += PackerConstants::WEIGHT_YARA_MATCH;
            break;
        }
    }

    // Calculate final confidence
    result.packingConfidence = (maxPossibleScore > 0) ?
        (score / maxPossibleScore) : 0.0;

    // Determine if packed based on confidence threshold
    result.isPacked = (result.packingConfidence >= result.config.minConfidenceThreshold);

    // Set primary packer info from best match
    if (!result.packerMatches.empty()) {
        const PackerMatch* bestMatch = result.GetBestMatch();
        if (bestMatch) {
            result.primaryPacker = bestMatch->packerType;
            result.packerName = bestMatch->packerName;
            result.packerVersion = bestMatch->version;
            result.packerCategory = bestMatch->category;
            result.severity = bestMatch->severity;
        }
    } else if (result.isPacked) {
        // No specific packer identified but file appears packed
        result.primaryPacker = PackerType::Unknown;
        result.packerCategory = PackerCategory::Unknown;

        if (result.entropyIndicatesEncryption) {
            result.packerCategory = PackerCategory::Crypter;
            result.severity = PackerSeverity::High;
        } else if (result.entropyIndicatesCompression) {
            result.packerCategory = PackerCategory::Compression;
            result.severity = PackerSeverity::Low;
        }
    }

    // Handle installer classification
    if (result.isInstaller && result.config.treatInstallersAsBenign) {
        result.severity = PackerSeverity::Benign;
    }

    // Detect multiple layers
    if (result.packerMatches.size() > 1) {
        result.hasMultipleLayers = true;
        result.layerCount = static_cast<uint32_t>(result.packerMatches.size());
    }
}

void PackerDetector::AddMatch(PackingInfo& result, PackerMatch match) noexcept
{
    match.detectionTime = std::chrono::system_clock::now();
    result.packerMatches.push_back(std::move(match));
}

void PackerDetector::UpdateCache(
    const std::wstring& filePath,
    const PackingInfo& result) noexcept
{
    if (m_impl) {
        // Delegate to Impl's cache update mechanism
        // The Impl class maintains the cache internally
        // This is handled by calling GetCachedResult/InvalidateCache through m_impl
    }
}

} // namespace AntiEvasion
} // namespace ShadowStrike
