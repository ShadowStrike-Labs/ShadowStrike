/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MemoryScanAccel — SIMD-accelerated memory analysis for emulation
 *
 * Provides high-speed page entropy scanning, shellcode pattern detection,
 * ROP gadget discovery, and packed region identification. Uses AVX2/SSE4.2
 * intrinsics for pattern matching with scalar fallbacks.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace Phantom {

// Forward declarations
class VirtualMemory;

// ============================================================================
// Page Entropy Map — entropy value per page
// ============================================================================

struct PageEntropyEntry {
    GuestAddress pageAddress = 0;
    double entropy = 0.0;
    MemProt protection = MemProt::None;
    bool isHighEntropy = false;     // > 7.0
    bool isEncrypted = false;       // > 7.5
    bool wasWritten = false;        // W→X candidate
};

// ============================================================================
// Shellcode Detection Results
// ============================================================================

enum class ShellcodePattern : uint8_t {
    NopSled,            // Long NOP sequences (0x90, multi-byte NOPs)
    GetPCStub,          // call $+5; pop reg (classic GetPC)
    EggHunter,          // NtAccessCheckAndAuditAlarm / similar syscall scanner
    StackPivot,         // XCHG ESP,reg or MOV ESP,reg
    APIHashLookup,      // ROR+ADD hash loop (API hashing)
    PEBWalk,            // FS:[0x30] / GS:[0x60] access for PEB
    SyscallStub,        // Direct SYSCALL/INT 0x2E
    EncoderStub,        // XOR/SUB/ADD decoder loop
    HeapSpray,          // Repeated pattern filling memory
    RetSled,            // Sequence of RET instructions
    JmpTrampoline,      // JMP to computed address
    WoW64Gate,          // Far JMP to 0x33 segment (Heaven's Gate)
};

struct ShellcodeMatch {
    ShellcodePattern pattern;
    GuestAddress address = 0;
    GuestSize size = 0;
    float confidence = 0.0f;
    const char* description = nullptr;  // Static string
};

// ============================================================================
// ROP Gadget
// ============================================================================

struct ROPGadget {
    GuestAddress address = 0;
    uint8_t length = 0;              // Gadget instruction bytes
    uint8_t instructionCount = 0;    // Number of instructions in gadget
    const char* description = nullptr; // e.g., "pop rdi; ret"
    bool isUseful = false;           // Commonly used in ROP chains
};

// ============================================================================
// Packed Region Detection
// ============================================================================

struct PackedRegion {
    GuestAddress base = 0;
    GuestSize size = 0;
    double avgEntropy = 0.0;
    bool hasWriteExecute = false;    // W→X transition observed
    bool hasDecoderLoop = false;     // Self-decoding loop detected
    const char* likelyPacker = nullptr;  // "UPX", "Themida", etc. (static string)
};

// ============================================================================
// Memory Scan Results
// ============================================================================

struct MemoryScanResult {
    std::vector<PageEntropyEntry> entropyMap;
    std::vector<ShellcodeMatch> shellcodeMatches;
    std::vector<ROPGadget> ropGadgets;
    std::vector<PackedRegion> packedRegions;

    uint32_t totalPagesScanned = 0;
    uint32_t highEntropyPages = 0;
    uint32_t executablePages = 0;
    uint32_t rwxPages = 0;
    double overallEntropy = 0.0;

    bool hasShellcode = false;
    bool hasPacking = false;
    bool hasROPChain = false;
};

// ============================================================================
// Memory Scanning Accelerator
// ============================================================================

class MemoryScanAccel {
public:
    explicit MemoryScanAccel() noexcept;
    ~MemoryScanAccel() noexcept;

    MemoryScanAccel(const MemoryScanAccel&) = delete;
    MemoryScanAccel& operator=(const MemoryScanAccel&) = delete;
    MemoryScanAccel(MemoryScanAccel&&) noexcept;
    MemoryScanAccel& operator=(MemoryScanAccel&&) noexcept;

    // === Full Memory Scan ===

    // Scan all allocated pages in guest memory
    [[nodiscard]] MemoryScanResult ScanAll(VirtualMemory& memory) const noexcept;

    // === Individual Scan Types ===

    // Calculate entropy for every allocated page
    [[nodiscard]] std::vector<PageEntropyEntry> ScanPageEntropy(
        VirtualMemory& memory) const noexcept;

    // Detect shellcode patterns in a memory region
    [[nodiscard]] std::vector<ShellcodeMatch> DetectShellcode(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    // Find ROP gadgets ending in RET/JMP/CALL in executable regions
    [[nodiscard]] std::vector<ROPGadget> FindROPGadgets(
        ByteSpan execRegion, GuestAddress baseAddr,
        uint32_t maxGadgetLength = 6) const noexcept;

    // Identify packed/encrypted memory regions
    [[nodiscard]] std::vector<PackedRegion> DetectPackedRegions(
        VirtualMemory& memory,
        double entropyThreshold = 7.0) const noexcept;

    // === SIMD-Accelerated Primitives ===

    // Fast page entropy (256-bin histogram → Shannon entropy)
    [[nodiscard]] double PageEntropy(ByteSpan page) const noexcept;

    // Detect NOP sled (0x90, multi-byte NOPs like 0F 1F xx)
    [[nodiscard]] std::optional<GuestAddress> FindNopSled(
        ByteSpan data, GuestAddress base,
        uint32_t minLength = 16) const noexcept;

    // Detect GetPC stub: E8 00 00 00 00 (call $+5) followed by 58-5F (pop reg)
    [[nodiscard]] std::vector<GuestAddress> FindGetPCStubs(
        ByteSpan data, GuestAddress base) const noexcept;

    // Fast byte sequence search (SIMD-accelerated)
    [[nodiscard]] std::vector<size_t> FindAllOccurrences(
        ByteSpan data, ByteSpan pattern) const noexcept;

    // Detect PEB access patterns (FS:[0x30] in 32-bit, GS:[0x60] in 64-bit)
    [[nodiscard]] std::vector<GuestAddress> FindPEBAccess(
        ByteSpan data, GuestAddress base, bool is64Bit = true) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
