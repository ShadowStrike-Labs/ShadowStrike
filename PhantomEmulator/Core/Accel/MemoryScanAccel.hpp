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

/**
 * @brief Entropy and protection metadata for one guest page.
 *
 * Thread safety: immutable value returned by MemoryScanAccel. Addresses are
 * guest virtual page bases; implementation caps enumeration at guest memory max.
 */
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

/**
 * @brief Shellcode heuristic categories emitted by DetectShellcode().
 */
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

/**
 * @brief Shellcode heuristic match with bounded static description metadata.
 *
 * Failure contract: only returned when the match fits within the scanned span;
 * address arithmetic saturates instead of wrapping.
 */
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

/**
 * @brief Compact ROP gadget descriptor discovered in executable guest memory.
 */
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

/**
 * @brief Consecutive high-entropy guest pages likely produced by packing/encryption.
 */
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

/**
 * @brief Aggregate scan result for all mapped guest pages.
 *
 * Vectors are bounded by implementation caps to prevent guest-controlled memory
 * layouts from causing unbounded allocations.
 */
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

/**
 * @brief Bounded SIMD-assisted memory scanner for shellcode, ROP, and packers.
 *
 * Inputs are caller-owned byte spans or VirtualMemory instances. Public APIs are
 * noexcept and return empty/default results on invalid input or allocation-cap
 * reservation failure. Thread safety: immutable after construction; concurrent
 * calls are safe when VirtualMemory is externally used according to its contract.
 * IRQL: user-mode only.
 */
class MemoryScanAccel {
public:
    /**
     * @brief Detects host SIMD capabilities.
     *
     * Failure contract: allocation failure leaves the accelerator in a safe
     * scalar/default state where public APIs return empty/default results as needed.
     */
    explicit MemoryScanAccel() noexcept;
    ~MemoryScanAccel() noexcept;

    MemoryScanAccel(const MemoryScanAccel&) = delete;
    MemoryScanAccel& operator=(const MemoryScanAccel&) = delete;
    MemoryScanAccel(MemoryScanAccel&&) noexcept;
    MemoryScanAccel& operator=(MemoryScanAccel&&) noexcept;

    /**
     * @brief Scans guest memory for entropy, shellcode, ROP gadgets, and packed regions.
     * @param memory Guest virtual memory manager to scan via safe read APIs.
     * @return Bounded aggregate result.
     */
    [[nodiscard]] MemoryScanResult ScanAll(VirtualMemory& memory) const noexcept;

    /**
     * @brief Calculates entropy metadata for mapped guest pages.
     * @param memory Guest virtual memory manager to scan.
     * @return Bounded page entropy vector.
     */
    [[nodiscard]] std::vector<PageEntropyEntry> ScanPageEntropy(
        VirtualMemory& memory) const noexcept;

    /**
     * @brief Detects common shellcode patterns in a caller-provided byte span.
     * @param data Readable bytes to scan; non-empty null spans are rejected.
     * @param baseAddr Guest address corresponding to data[0].
     * @return Bounded shellcode match vector.
     */
    [[nodiscard]] std::vector<ShellcodeMatch> DetectShellcode(
        ByteSpan data, GuestAddress baseAddr) const noexcept;

    /**
     * @brief Finds useful RET-terminated ROP gadgets in executable bytes.
     * @param execRegion Readable executable bytes.
     * @param baseAddr Guest address corresponding to execRegion[0].
     * @param maxGadgetLength Maximum bytes before RET to inspect; capped internally.
     * @return Bounded gadget vector.
     */
    [[nodiscard]] std::vector<ROPGadget> FindROPGadgets(
        ByteSpan execRegion, GuestAddress baseAddr,
        uint32_t maxGadgetLength = 6) const noexcept;

    /**
     * @brief Groups consecutive high-entropy guest pages into packed regions.
     * @param memory Guest virtual memory manager to scan.
     * @param entropyThreshold Threshold in [0, 8]; invalid values return empty.
     * @return Bounded packed-region vector.
     */
    [[nodiscard]] std::vector<PackedRegion> DetectPackedRegions(
        VirtualMemory& memory,
        double entropyThreshold = 7.0) const noexcept;

    /**
     * @brief Computes Shannon entropy over a capped byte span.
     * @param page Readable bytes; empty input returns 0.
     * @return Entropy in [0, 8] for byte distributions.
     */
    [[nodiscard]] double PageEntropy(ByteSpan page) const noexcept;

    /**
     * @brief Finds the first single-byte or multi-byte NOP sled.
     * @param data Readable bytes to scan.
     * @param base Guest address corresponding to data[0].
     * @param minLength Minimum sled length; zero is invalid.
     * @return Guest address of first sled, or nullopt.
     */
    [[nodiscard]] std::optional<GuestAddress> FindNopSled(
        ByteSpan data, GuestAddress base,
        uint32_t minLength = 16) const noexcept;

    /**
     * @brief Finds CALL-next-instruction/POP GetPC stubs.
     * @param data Readable bytes to scan.
     * @param base Guest address corresponding to data[0].
     * @return Bounded list of guest addresses.
     */
    [[nodiscard]] std::vector<GuestAddress> FindGetPCStubs(
        ByteSpan data, GuestAddress base) const noexcept;

    /**
     * @brief Finds all bounded occurrences of a byte pattern.
     * @param data Readable search buffer.
     * @param pattern Readable non-empty pattern.
     * @return Bounded offsets relative to data[0].
     */
    [[nodiscard]] std::vector<size_t> FindAllOccurrences(
        ByteSpan data, ByteSpan pattern) const noexcept;

    /**
     * @brief Detects x86/x64 PEB access idioms.
     * @param data Readable bytes to scan.
     * @param base Guest address corresponding to data[0].
     * @param is64Bit Selects GS:[0x60] x64 patterns when true, FS:[0x30] x86 otherwise.
     * @return Bounded list of guest addresses.
     */
    [[nodiscard]] std::vector<GuestAddress> FindPEBAccess(
        ByteSpan data, GuestAddress base, bool is64Bit = true) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
