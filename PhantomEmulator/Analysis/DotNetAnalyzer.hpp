/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DotNetAnalyzer.hpp — .NET/CLR malware analysis orchestrator
 *
 * Coordinates MetadataParser, MSILDisassembler, and MSILInterpreter to
 * perform comprehensive .NET assembly analysis: obfuscation detection,
 * P/Invoke classification, reflective loading detection, payload extraction,
 * and threat scoring for managed malware.
 *
 * References:
 *   ECMA-335 (6th Edition) — Common Language Infrastructure
 *   Microsoft PE/COFF Specification — .NET Metadata
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Core/CLR/CLRTypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom { class VirtualMemory; }

namespace Phantom::CLR {

// Forward declarations — parallel-built CLR modules
class MetadataParser;

// ============================================================================
// DotNetAnalyzer — Meyers' Singleton orchestrating all .NET analysis passes
// ============================================================================
//
// Analysis pipeline:
//   1. PE header validation & COR20 directory location
//   2. MetadataParser — type/method/reference extraction
//   3. MSILDisassembler — method body disassembly
//   4. MSILInterpreter — static constructor execution (string decryption)
//   5. Obfuscation detection (ConfuserEx, Dotfuscator, SmartAssembly, …)
//   6. P/Invoke classification (process injection, keylogging, C2, …)
//   7. Managed API categorization (26 categories)
//   8. Payload embedding detection (high-entropy resources, FieldRVA arrays)
//   9. Threat score computation (0.0–1.0)
//
// Thread-safety: single-threaded analysis. Reset() between sessions.

class DotNetAnalyzer {
public:
    [[nodiscard]] static DotNetAnalyzer& Instance() noexcept;

    DotNetAnalyzer(const DotNetAnalyzer&)            = delete;
    DotNetAnalyzer& operator=(const DotNetAnalyzer&) = delete;

    /// Clear all accumulated state between analysis sessions.
    void Reset() noexcept;

    /// Main entry point: run the full .NET analysis pipeline on a loaded PE.
    [[nodiscard]] DotNetAnalysisResult Analyze(
        const VirtualMemory& memory,
        GuestAddress imageBase) noexcept;

    /// Quick predicate: does this PE contain a CLR runtime header?
    [[nodiscard]] static bool IsDotNetAssembly(
        const VirtualMemory& memory,
        GuestAddress imageBase) noexcept;

    // ---- Result accessors ----

    [[nodiscard]] const DotNetAnalysisResult& GetLastResult() const noexcept;
    [[nodiscard]] float GetLastThreatScore() const noexcept;
    [[nodiscard]] const std::vector<std::string>& GetLastMITREIDs() const noexcept;

    // ---- Configuration ----

    void SetMaxMethodsToAnalyze(uint32_t max) noexcept;
    void SetEnableStringDecryption(bool enable) noexcept;
    void SetEnablePayloadExtraction(bool enable) noexcept;

private:
    DotNetAnalyzer() noexcept;
    ~DotNetAnalyzer() noexcept;

    // Analysis pipeline stages
    void AnalyzeMetadata(const MetadataParser& parser) noexcept;
    void AnalyzeMethods(const MetadataParser& parser,
                        const VirtualMemory& memory,
                        GuestAddress imageBase) noexcept;
    void DetectObfuscation(const MetadataParser& parser) noexcept;
    void ExtractPInvokes(const MetadataParser& parser) noexcept;
    void ClassifyAPICalls() noexcept;
    void DetectPayloadEmbedding(const MetadataParser& parser,
                                const VirtualMemory& memory,
                                GuestAddress imageBase) noexcept;
    void ComputeThreatScore() noexcept;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom::CLR
