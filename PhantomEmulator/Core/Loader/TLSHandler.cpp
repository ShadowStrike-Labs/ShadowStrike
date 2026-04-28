/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TLSHandler.cpp — PE Thread Local Storage directory handler
 *
 * TLS callbacks are a favorite malware anti-analysis vector: they execute
 * before the entry point, allowing early decryption, environment checks,
 * and anti-debug traps. This handler faithfully processes TLS directories
 * for both PE32 and PE64 images, initializes per-thread TLS data, and
 * invokes callbacks through the PhantomEmulator CPU loop with full
 * instruction limits and fault detection.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "TLSHandler.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

namespace Phantom {

// ============================================================================
// Sentinel address: if a TLS callback returns to this address,
// the CPU will stop execution (APICallTrap or breakpoint).
// Chosen from high unmapped region that is unlikely to be a real address.
// ============================================================================
static constexpr GuestAddress kTLSReturnSentinel = 0xDEAD'C0DE'FEED'0001ULL;
static constexpr GuestAddress kTLSReturnSentinel32 = 0xDEADFEE1UL;

// Maximum template data size — cap to prevent absurd allocations
static constexpr uint64_t kMaxTLSTemplateSize = 16ULL * 1024 * 1024; // 16 MB

// Maximum zero-fill size
static constexpr uint32_t kMaxTLSZeroFill = 16 * 1024 * 1024; // 16 MB

// Instructions budget per callback (configurable, but cap at sane default)
static constexpr uint64_t kDefaultCallbackInsnLimit = 5'000'000;

namespace {

[[nodiscard]] bool AddGuestAddress(GuestAddress base, GuestAddress offset, GuestAddress& out) noexcept {
    if (offset > (std::numeric_limits<GuestAddress>::max)() - base) {
        return false;
    }
    out = base + offset;
    return true;
}

[[nodiscard]] bool RangeSize(GuestAddress begin, GuestAddress end, uint64_t& out) noexcept {
    if (end < begin) {
        return false;
    }
    out = end - begin;
    return true;
}

[[nodiscard]] bool ToU32(GuestAddress value, uint32_t& out) noexcept {
    if (value > (std::numeric_limits<uint32_t>::max)()) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

class BreakpointGuard {
public:
    BreakpointGuard(CPU& cpu, GuestAddress address) noexcept
        : m_cpu(cpu), m_address(address) {
        m_cpu.AddBreakpoint(m_address);
    }

    ~BreakpointGuard() noexcept {
        m_cpu.RemoveBreakpoint(m_address);
    }

    BreakpointGuard(const BreakpointGuard&) = delete;
    BreakpointGuard& operator=(const BreakpointGuard&) = delete;

private:
    CPU& m_cpu;
    GuestAddress m_address;
};

} // namespace

// ============================================================================
// Parse — Read and validate TLS directory
// ============================================================================

TLSInfo TLSHandler::Parse(
    GuestAddress   imageBase,
    uint32_t       tlsDirRVA,
    uint32_t       tlsDirSize,
    VirtualMemory& memory,
    bool           is64Bit) noexcept
{
    TLSInfo info{};

    if (tlsDirRVA == 0) {
        return info; // No TLS directory
    }

    // Validate minimum directory size
    const uint32_t minSize = is64Bit
        ? static_cast<uint32_t>(sizeof(PE::TLSDirectory64))
        : static_cast<uint32_t>(sizeof(PE::TLSDirectory32));

    if (tlsDirSize < minSize) {
        return info; // Directory too small — treat as absent
    }

    GuestAddress tlsDirAddr = 0;
    if (!AddGuestAddress(imageBase, tlsDirRVA, tlsDirAddr)) {
        return info;
    }

    if (is64Bit) {
        info = Parse64(imageBase, tlsDirAddr, memory);
    } else {
        info = Parse32(imageBase, tlsDirAddr, memory);
    }

    return info;
}

// ============================================================================
// Parse32 — Read PE32 TLS directory
// ============================================================================

TLSInfo TLSHandler::Parse32(
    [[maybe_unused]] GuestAddress imageBase,
    GuestAddress   tlsDirAddr,
    VirtualMemory& memory) noexcept
{
    TLSInfo info{};

    PE::TLSDirectory32 dir{};
    ErrorCode err = memory.ReadValue(tlsDirAddr, dir);
    if (err != ErrorCode::Success) {
        return info;
    }

    info.rawDataStart     = dir.StartAddressOfRawData;
    info.rawDataEnd       = dir.EndAddressOfRawData;
    info.indexAddress      = dir.AddressOfIndex;
    info.callbacksAddress  = dir.AddressOfCallBacks;
    info.zeroFillSize      = dir.SizeOfZeroFill;

    // Validate template data range
    uint64_t templateSize = 0;
    if (!RangeSize(info.rawDataStart, info.rawDataEnd, templateSize)) {
        return info; // Invalid range
    }

    if (templateSize > kMaxTLSTemplateSize) {
        return info; // Suspiciously large
    }

    if (info.zeroFillSize > kMaxTLSZeroFill) {
        return info;
    }

    // Read callback array
    if (info.callbacksAddress != 0) {
        err = ReadCallbackArray32(memory, info.callbacksAddress, info.callbacks);
        if (err != ErrorCode::Success) {
            info.callbacks.clear();
            return info;
        }
    }

    info.present = true;
    return info;
}

// ============================================================================
// Parse64 — Read PE64 TLS directory
// ============================================================================

TLSInfo TLSHandler::Parse64(
    [[maybe_unused]] GuestAddress imageBase,
    GuestAddress   tlsDirAddr,
    VirtualMemory& memory) noexcept
{
    TLSInfo info{};

    PE::TLSDirectory64 dir{};
    ErrorCode err = memory.ReadValue(tlsDirAddr, dir);
    if (err != ErrorCode::Success) {
        return info;
    }

    info.rawDataStart     = dir.StartAddressOfRawData;
    info.rawDataEnd       = dir.EndAddressOfRawData;
    info.indexAddress      = dir.AddressOfIndex;
    info.callbacksAddress  = dir.AddressOfCallBacks;
    info.zeroFillSize      = dir.SizeOfZeroFill;

    // Validate template data range
    uint64_t templateSize = 0;
    if (!RangeSize(info.rawDataStart, info.rawDataEnd, templateSize)) {
        return info;
    }

    if (templateSize > kMaxTLSTemplateSize) {
        return info;
    }

    if (info.zeroFillSize > kMaxTLSZeroFill) {
        return info;
    }

    // Read callback array
    if (info.callbacksAddress != 0) {
        err = ReadCallbackArray64(memory, info.callbacksAddress, info.callbacks);
        if (err != ErrorCode::Success) {
            info.callbacks.clear();
            return info;
        }
    }

    info.present = true;
    return info;
}

// ============================================================================
// ReadCallbackArray32 — Read null-terminated uint32 pointer array
// ============================================================================

ErrorCode TLSHandler::ReadCallbackArray32(
    VirtualMemory&             memory,
    GuestAddress               callbacksVA,
    std::vector<GuestAddress>& out) noexcept
{
    try {
        out.clear();
        out.reserve(8); // Typical TLS callback count is 1-3
    } catch (const std::bad_alloc&) {
        out.clear();
        return ErrorCode::OutOfMemory;
    }

    for (uint32_t i = 0; i < PE::kMaxTLSCallbacks; ++i) {
        GuestAddress entryAddress = 0;
        if (!AddGuestAddress(callbacksVA, static_cast<GuestAddress>(i) * sizeof(uint32_t), entryAddress)) {
            return ErrorCode::InvalidAddress;
        }

        uint32_t ptr = 0;
        ErrorCode err = memory.ReadU32(entryAddress, ptr);
        if (err != ErrorCode::Success) {
            return err;
        }

        if (ptr == 0) {
            return ErrorCode::Success; // Null terminator
        }

        try {
            out.push_back(static_cast<GuestAddress>(ptr));
        } catch (const std::bad_alloc&) {
            out.clear();
            return ErrorCode::OutOfMemory;
        }
    }

    return ErrorCode::MalformedPE;
}

// ============================================================================
// ReadCallbackArray64 — Read null-terminated uint64 pointer array
// ============================================================================

ErrorCode TLSHandler::ReadCallbackArray64(
    VirtualMemory&             memory,
    GuestAddress               callbacksVA,
    std::vector<GuestAddress>& out) noexcept
{
    try {
        out.clear();
        out.reserve(8);
    } catch (const std::bad_alloc&) {
        out.clear();
        return ErrorCode::OutOfMemory;
    }

    for (uint32_t i = 0; i < PE::kMaxTLSCallbacks; ++i) {
        GuestAddress entryAddress = 0;
        if (!AddGuestAddress(callbacksVA, static_cast<GuestAddress>(i) * sizeof(uint64_t), entryAddress)) {
            return ErrorCode::InvalidAddress;
        }

        uint64_t ptr = 0;
        ErrorCode err = memory.ReadU64(entryAddress, ptr);
        if (err != ErrorCode::Success) {
            return err;
        }

        if (ptr == 0) {
            return ErrorCode::Success;
        }

        try {
            out.push_back(ptr);
        } catch (const std::bad_alloc&) {
            out.clear();
            return ErrorCode::OutOfMemory;
        }
    }

    return ErrorCode::MalformedPE;
}

// ============================================================================
// InitializeTLSData — Copy template + zero-fill for a thread
// ============================================================================

ErrorCode TLSHandler::InitializeTLSData(
    const TLSInfo& info,
    VirtualMemory& memory,
    GuestAddress   tlsDataDest,
    uint32_t       tlsIndex) noexcept
{
    if (!info.present) {
        return ErrorCode::Success; // Nothing to initialize
    }

    // -----------------------------------------------------------------------
    // 1. Copy template data from rawDataStart to destination
    // -----------------------------------------------------------------------
    uint64_t templateSize64 = 0;
    if (!RangeSize(info.rawDataStart, info.rawDataEnd, templateSize64)) {
        return ErrorCode::MalformedPE;
    }

    if (templateSize64 > kMaxTLSTemplateSize || info.zeroFillSize > kMaxTLSZeroFill) {
        return ErrorCode::MalformedPE;
    }

    GuestAddress tlsDataEnd = 0;
    if (!AddGuestAddress(tlsDataDest, templateSize64, tlsDataEnd) ||
        !AddGuestAddress(tlsDataEnd, info.zeroFillSize, tlsDataEnd)) {
        return ErrorCode::InvalidAddress;
    }

    if (templateSize64 > 0) {
        const auto templateSize = static_cast<uint32_t>(templateSize64);

        // Copy byte-by-byte through VirtualMemory (page-boundary safe).
        // For larger templates, copy in page-aligned chunks to reduce overhead.
        static constexpr uint32_t kCopyChunkSize = 4096;
        uint32_t copied = 0;

        while (copied < templateSize) {
            const uint32_t remaining = templateSize - copied;
            const uint32_t chunk = (remaining < kCopyChunkSize) ? remaining : kCopyChunkSize;
            GuestAddress src = 0;
            GuestAddress dst = 0;
            if (!AddGuestAddress(info.rawDataStart, copied, src) ||
                !AddGuestAddress(tlsDataDest, copied, dst)) {
                return ErrorCode::InvalidAddress;
            }

            // Read from TLS template source
            std::array<uint8_t, kCopyChunkSize> buf{};
            ErrorCode err = memory.Read(src, buf.data(), chunk);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            // Write to destination
            err = memory.Write(dst, buf.data(), chunk);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            copied += chunk;
        }
    }

    // -----------------------------------------------------------------------
    // 2. Zero-fill area after template data
    // -----------------------------------------------------------------------
    if (info.zeroFillSize > 0) {
        GuestAddress zeroStart = 0;
        if (!AddGuestAddress(tlsDataDest, templateSize64, zeroStart)) {
            return ErrorCode::InvalidAddress;
        }

        static constexpr uint32_t kZeroChunkSize = 4096;
        std::array<uint8_t, kZeroChunkSize> zeroBuf{};

        uint32_t zeroed = 0;
        while (zeroed < info.zeroFillSize) {
            const uint32_t remaining = info.zeroFillSize - zeroed;
            const uint32_t chunk = (remaining < kZeroChunkSize) ? remaining : kZeroChunkSize;
            GuestAddress dst = 0;
            if (!AddGuestAddress(zeroStart, zeroed, dst)) {
                return ErrorCode::InvalidAddress;
            }

            ErrorCode err = memory.Write(dst, zeroBuf.data(), chunk);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            zeroed += chunk;
        }
    }

    // -----------------------------------------------------------------------
    // 3. Write TLS index to the index variable
    // -----------------------------------------------------------------------
    if (info.indexAddress != 0) {
        ErrorCode err = memory.WriteU32(info.indexAddress, tlsIndex);
        if (err != ErrorCode::Success) {
            return ErrorCode::TLSCallbackFail;
        }
    }

    return ErrorCode::Success;
}

// ============================================================================
// ExecuteCallbacks — Invoke TLS callbacks through the CPU emulator
// ============================================================================

ErrorCode TLSHandler::ExecuteCallbacks(
    const TLSInfo&       info,
    CPU&                 cpu,
    VirtualMemory&       memory,
    GuestAddress         imageBase,
    uint32_t             reason,
    const EmulationConfig& config) noexcept
{
    if (!info.present || info.callbacks.empty()) {
        return ErrorCode::Success;
    }

    const bool is64Bit = (config.cpuMode == CPUMode::Long64);

    // Determine instruction budget per callback
    const uint64_t insnLimit = (config.maxInstructions > 0)
        ? ((config.maxInstructions < kDefaultCallbackInsnLimit)
            ? config.maxInstructions
            : kDefaultCallbackInsnLimit)
        : kDefaultCallbackInsnLimit;

    // Determine sentinel return address
    const GuestAddress sentinel = is64Bit
        ? kTLSReturnSentinel
        : kTLSReturnSentinel32;

    // Set up a breakpoint at the sentinel so the CPU stops when the callback
    // returns to it. We'll clear it when done.
    BreakpointGuard breakpoint(cpu, sentinel);

    for (const GuestAddress callbackAddr : info.callbacks) {
        if (callbackAddr == 0) {
            continue;
        }

        // Save instruction count before this callback
        const uint64_t startInsn = cpu.State().instructionCount;

        // -------------------------------------------------------------------
        // Set up calling convention
        // -------------------------------------------------------------------
        CPUState& state = cpu.State();
        uint32_t callback32 = 0;

        if (is64Bit) {
            // Microsoft x64 calling convention:
            //   RCX = hinstDLL (imageBase)
            //   RDX = fdwReason
            //   R8  = lpvReserved (0)
            state.SetReg64(GPR::RCX, imageBase);
            state.SetReg64(GPR::RDX, static_cast<uint64_t>(reason));
            state.SetReg64(GPR::R8,  0);

            // Push return address (sentinel) onto the stack
            const uint64_t rsp = state.RSP();
            if (rsp < 40) {
                return ErrorCode::StackUnderflow;
            }
            const uint64_t newRsp = rsp - 40;
            state.SetReg64(GPR::RSP, newRsp);

            ErrorCode err = memory.WriteU64(newRsp, sentinel);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

        } else {
            uint32_t imageBase32 = 0;
            if (!ToU32(imageBase, imageBase32) || !ToU32(callbackAddr, callback32)) {
                return ErrorCode::InvalidAddress;
            }

            // cdecl / stdcall (TLS callbacks use stdcall):
            //   Push in reverse order: lpvReserved, fdwReason, hinstDLL
            //   Then push return address
            uint32_t esp = state.GetReg32(GPR::RSP);
            if (esp < 16) {
                return ErrorCode::StackUnderflow;
            }

            // Push lpvReserved = 0
            esp -= 4;
            ErrorCode err = memory.WriteU32(static_cast<GuestAddress>(esp), 0);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            // Push fdwReason
            esp -= 4;
            err = memory.WriteU32(static_cast<GuestAddress>(esp), reason);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            // Push hinstDLL (imageBase, truncated to 32 bits for PE32)
            esp -= 4;
            err = memory.WriteU32(static_cast<GuestAddress>(esp), imageBase32);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            // Push sentinel return address
            esp -= 4;
            err = memory.WriteU32(
                static_cast<GuestAddress>(esp),
                static_cast<uint32_t>(sentinel));
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            state.SetReg32(GPR::RSP, esp);
        }

        // Set RIP to callback entry
        cpu.State().SetRIP(is64Bit ? callbackAddr : static_cast<GuestAddress>(callback32));

        // -------------------------------------------------------------------
        // Execute the callback with a limited instruction budget
        // -------------------------------------------------------------------
        EmulationConfig callbackConfig = config;
        callbackConfig.maxInstructions = insnLimit;

        ExecutionResult execResult = cpu.Execute(memory, nullptr, callbackConfig);

        // Check for execution faults
        switch (execResult.reason) {
        case StopReason::Breakpoint:
            // Hit sentinel — callback returned normally
            break;
        case StopReason::InstructionLimit:
            // Callback ran too long — possible infinite loop / anti-analysis
            return ErrorCode::TLSCallbackFail;
        case StopReason::AccessViolation:
        case StopReason::InvalidInstruction:
        case StopReason::StackOverflow:
        case StopReason::Crashed:
            return ErrorCode::TLSCallbackFail;
        case StopReason::ExitProcess:
            // Callback called ExitProcess — malware behavior, not an error per se
            return ErrorCode::Success;
        case StopReason::APICallTrap:
            // Hit an API hook — this is normal during callback execution
            break;
        default:
            // Any other stop reason — treat as unexpected
            if (execResult.errorCode != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }
            break;
        }

        // Guard: if the callback consumed the entire budget without hitting
        // the sentinel, something is wrong
        const uint64_t endInsn = cpu.State().instructionCount;
        const uint64_t consumed = (endInsn >= startInsn) ? (endInsn - startInsn) : 0;
        if (consumed >= insnLimit &&
            execResult.reason != StopReason::Breakpoint)
        {
            return ErrorCode::TLSCallbackFail;
        }
    }

    return ErrorCode::Success;
}

} // namespace Phantom
