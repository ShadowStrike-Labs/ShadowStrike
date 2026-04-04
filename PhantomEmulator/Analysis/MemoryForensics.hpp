/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// Forward declarations — defined in Core/Memory/
class VirtualMemory;
class MemoryTracker;

// ============================================================================
// Types of Suspicious Memory Patterns
// ============================================================================

enum class MemoryFinding : uint8_t {
    ShellcodeNopSled,
    ShellcodeDecoderStub,
    ShellcodeEggHunter,
    ShellcodeEncodedPayload,
    PEHeaderInMemory,
    PEDOSStub,
    PEImportTable,
    PEExportTable,
    HeapSprayPattern,
    HeapSprayNopRun,
    ROPGadgetChain,
    StackPivotDetected,
    CodeCaveUsed,
    HollowedProcess,
    ReflectiveDLLStub,
    SelfModifyingCode,
    WriteExecuteTransition,
    HighEntropyRegion,
    XOREncodedBlock,
    Base64EncodedBlock,
    SuspiciousStringTable,
    StackShellcode,
    TrampolineCode,
    IATPatchDetected,
};

// ============================================================================
// Finding Detail — one per detected suspicious artifact
// ============================================================================

struct MemoryFindingDetail {
    MemoryFinding           type;
    GuestAddress            address       = 0;
    GuestSize               size          = 0;
    float                   confidence    = 0.0f;   // 0.0–1.0
    double                  entropy       = 0.0;    // Shannon entropy if applicable
    std::string             description;
    std::vector<uint8_t>    sample;                 // First N bytes of the finding
    uint32_t                sampleMaxSize = 256;
};

// ============================================================================
// Region Analysis Result
// ============================================================================

struct RegionAnalysis {
    GuestAddress base               = 0;
    GuestSize    size               = 0;
    MemProt      protection         = MemProt::None;
    double       entropy            = 0.0;
    bool         containsPE         = false;
    bool         containsShellcode  = false;
    bool         isWrittenThenExecuted = false;
    uint32_t     findingCount       = 0;
};

// ============================================================================
// Extracted Payload — carved from guest memory for downstream analysis
// ============================================================================

struct ExtractedPayload {
    std::vector<uint8_t>    data;
    GuestAddress            sourceAddress   = 0;
    GuestSize               originalSize    = 0;
    std::string             description;
    double                  entropy         = 0.0;
    bool                    isPE            = false;
    bool                    isShellcode     = false;
};

// ============================================================================
// Memory Forensics Engine
// ============================================================================
// Deep analysis of guest virtual memory during and after emulation.
// Detects shellcode, PE injection, heap sprays, ROP chains, stack pivots,
// code caves, process hollowing, reflective DLL loading, W→X transitions,
// entropy anomalies, and XOR/Base64 encoded payloads.
//
// Thread-safe: All public methods are safe to call from any thread.
// PIMPL: Implementation details hidden for ABI stability.

class MemoryForensics {
public:
    explicit MemoryForensics(const EmulationConfig& config) noexcept;
    ~MemoryForensics() noexcept;

    MemoryForensics(const MemoryForensics&)            = delete;
    MemoryForensics& operator=(const MemoryForensics&) = delete;
    MemoryForensics(MemoryForensics&&)                 = delete;
    MemoryForensics& operator=(MemoryForensics&&)      = delete;

    // === Full Memory Scan ===

    /// Scan all allocated guest memory for suspicious patterns.
    void ScanAll(const VirtualMemory& memory,
                 const MemoryTracker& tracker) noexcept;

    /// Scan a specific region.
    void ScanRegion(const VirtualMemory& memory,
                    GuestAddress base,
                    GuestSize size) noexcept;

    // === Event-Driven Analysis ===

    void OnWXTransition(const VirtualMemory& memory,
                        GuestAddress page) noexcept;

    void OnProtectionChange(GuestAddress base, GuestSize size,
                            MemProt oldProt, MemProt newProt) noexcept;

    void OnAllocation(GuestAddress base, GuestSize size,
                      MemProt prot) noexcept;

    void OnStackPivot(GuestAddress oldRSP, GuestAddress newRSP) noexcept;

    // === Results ===

    [[nodiscard]] const std::vector<MemoryFindingDetail>&
    GetFindings() const noexcept;

    [[nodiscard]] uint32_t GetFindingCount() const noexcept;

    [[nodiscard]] std::vector<const MemoryFindingDetail*>
    GetFindingsByType(MemoryFinding type) const noexcept;

    // === Payload Extraction ===

    [[nodiscard]] const std::vector<ExtractedPayload>&
    GetExtractedPayloads() const noexcept;

    void ExtractPayload(const VirtualMemory& memory,
                        GuestAddress base,
                        GuestSize size,
                        const std::string& desc) noexcept;

    // === Entropy Analysis ===

    [[nodiscard]] static double CalculateEntropy(
        const uint8_t* data, size_t size) noexcept;

    [[nodiscard]] static double CalculateEntropy(ByteSpan data) noexcept;

    // === Region Analysis ===

    [[nodiscard]] std::vector<RegionAnalysis> AnalyzeAllRegions(
        const VirtualMemory& memory,
        const MemoryTracker& tracker) const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
