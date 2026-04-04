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

#include <cstdint>
#include <cstring>

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

    const GuestAddress tlsDirAddr = imageBase + tlsDirRVA;

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
    if (info.rawDataEnd < info.rawDataStart) {
        return info; // Invalid range
    }

    const uint64_t templateSize = info.rawDataEnd - info.rawDataStart;
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
    if (info.rawDataEnd < info.rawDataStart) {
        return info;
    }

    const uint64_t templateSize = info.rawDataEnd - info.rawDataStart;
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
    out.clear();
    out.reserve(8); // Typical TLS callback count is 1-3

    for (uint32_t i = 0; i < PE::kMaxTLSCallbacks; ++i) {
        uint32_t ptr = 0;
        ErrorCode err = memory.ReadU32(
            callbacksVA + static_cast<GuestAddress>(i) * sizeof(uint32_t), ptr);
        if (err != ErrorCode::Success) {
            return err;
        }

        if (ptr == 0) {
            break; // Null terminator
        }

        out.push_back(static_cast<GuestAddress>(ptr));
    }

    return ErrorCode::Success;
}

// ============================================================================
// ReadCallbackArray64 — Read null-terminated uint64 pointer array
// ============================================================================

ErrorCode TLSHandler::ReadCallbackArray64(
    VirtualMemory&             memory,
    GuestAddress               callbacksVA,
    std::vector<GuestAddress>& out) noexcept
{
    out.clear();
    out.reserve(8);

    for (uint32_t i = 0; i < PE::kMaxTLSCallbacks; ++i) {
        uint64_t ptr = 0;
        ErrorCode err = memory.ReadU64(
            callbacksVA + static_cast<GuestAddress>(i) * sizeof(uint64_t), ptr);
        if (err != ErrorCode::Success) {
            return err;
        }

        if (ptr == 0) {
            break;
        }

        out.push_back(ptr);
    }

    return ErrorCode::Success;
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
    if (info.rawDataEnd > info.rawDataStart) {
        const auto templateSize = static_cast<uint32_t>(info.rawDataEnd - info.rawDataStart);

        if (templateSize > kMaxTLSTemplateSize) {
            return ErrorCode::MalformedPE;
        }

        // Copy byte-by-byte through VirtualMemory (page-boundary safe).
        // For larger templates, copy in page-aligned chunks to reduce overhead.
        static constexpr uint32_t kCopyChunkSize = 4096;
        uint32_t copied = 0;

        while (copied < templateSize) {
            const uint32_t remaining = templateSize - copied;
            const uint32_t chunk = (remaining < kCopyChunkSize) ? remaining : kCopyChunkSize;

            // Read from TLS template source
            uint8_t buf[kCopyChunkSize];
            ErrorCode err = memory.Read(
                info.rawDataStart + copied, buf, chunk);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            // Write to destination
            err = memory.Write(tlsDataDest + copied, buf, chunk);
            if (err != ErrorCode::Success) {
                return ErrorCode::TLSCallbackFail;
            }

            copied += chunk;
        }
    }

    // -----------------------------------------------------------------------
    // 2. Zero-fill area after template data
    // -----------------------------------------------------------------------
    if (info.zeroFillSize > 0 && info.zeroFillSize <= kMaxTLSZeroFill) {
        const uint64_t templateSize = info.rawDataEnd - info.rawDataStart;
        const GuestAddress zeroStart = tlsDataDest + templateSize;

        static constexpr uint32_t kZeroChunkSize = 4096;
        uint8_t zeroBuf[kZeroChunkSize];
        std::memset(zeroBuf, 0, sizeof(zeroBuf));

        uint32_t zeroed = 0;
        while (zeroed < info.zeroFillSize) {
            const uint32_t remaining = info.zeroFillSize - zeroed;
            const uint32_t chunk = (remaining < kZeroChunkSize) ? remaining : kZeroChunkSize;

            ErrorCode err = memory.Write(zeroStart + zeroed, zeroBuf, chunk);
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
    cpu.AddBreakpoint(sentinel);

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
            const uint64_t newRsp = rsp - 8;
            state.SetReg64(GPR::RSP, newRsp);

            ErrorCode err = memory.WriteU64(newRsp, sentinel);
            if (err != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }

            // Allocate shadow space (32 bytes) per Microsoft x64 ABI
            state.SetReg64(GPR::RSP, newRsp - 32);

        } else {
            // cdecl / stdcall (TLS callbacks use stdcall):
            //   Push in reverse order: lpvReserved, fdwReason, hinstDLL
            //   Then push return address
            uint32_t esp = state.GetReg32(GPR::RSP);

            // Push lpvReserved = 0
            esp -= 4;
            ErrorCode err = memory.WriteU32(static_cast<GuestAddress>(esp), 0);
            if (err != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }

            // Push fdwReason
            esp -= 4;
            err = memory.WriteU32(static_cast<GuestAddress>(esp), reason);
            if (err != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }

            // Push hinstDLL (imageBase, truncated to 32 bits for PE32)
            esp -= 4;
            err = memory.WriteU32(
                static_cast<GuestAddress>(esp),
                static_cast<uint32_t>(imageBase));
            if (err != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }

            // Push sentinel return address
            esp -= 4;
            err = memory.WriteU32(
                static_cast<GuestAddress>(esp),
                static_cast<uint32_t>(sentinel));
            if (err != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }

            state.SetReg32(GPR::RSP, esp);
        }

        // Set RIP to callback entry
        cpu.State().SetRIP(callbackAddr);

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
            cpu.RemoveBreakpoint(sentinel);
            return ErrorCode::TLSCallbackFail;
        case StopReason::AccessViolation:
        case StopReason::InvalidInstruction:
        case StopReason::StackOverflow:
        case StopReason::Crashed:
            cpu.RemoveBreakpoint(sentinel);
            return ErrorCode::TLSCallbackFail;
        case StopReason::ExitProcess:
            // Callback called ExitProcess — malware behavior, not an error per se
            cpu.RemoveBreakpoint(sentinel);
            return ErrorCode::Success;
        case StopReason::APICallTrap:
            // Hit an API hook — this is normal during callback execution
            break;
        default:
            // Any other stop reason — treat as unexpected
            if (execResult.errorCode != ErrorCode::Success) {
                cpu.RemoveBreakpoint(sentinel);
                return ErrorCode::TLSCallbackFail;
            }
            break;
        }

        // Guard: if the callback consumed the entire budget without hitting
        // the sentinel, something is wrong
        const uint64_t consumed = cpu.State().instructionCount - startInsn;
        if (consumed >= insnLimit &&
            execResult.reason != StopReason::Breakpoint)
        {
            cpu.RemoveBreakpoint(sentinel);
            return ErrorCode::TLSCallbackFail;
        }
    }

    cpu.RemoveBreakpoint(sentinel);
    return ErrorCode::Success;
}

} // namespace Phantom
