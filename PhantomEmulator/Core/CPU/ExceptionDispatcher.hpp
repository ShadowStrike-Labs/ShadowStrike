/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ExceptionDispatcher.hpp — SEH/VEH exception dispatch engine
 *
 * Models the Windows Structured/Vectored Exception Handling dispatch
 * mechanism inside the emulated process. Builds guest-space exception
 * records, walks handler chains for behavioral analysis, and detects
 * SEH/VEH-based anti-analysis and control-flow obfuscation techniques
 * commonly employed by malware.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"
#include <cstdint>
#include <memory>

namespace Phantom {

// Forward declarations — full definitions only needed in the .cpp
class CPUState;
class VirtualMemory;

// ============================================================================
// ExceptionDispatcher — SEH/VEH Exception Dispatch Engine
// ============================================================================
// Thread-safe via internal mutex. Owns no guest resources — operates on
// CPUState and VirtualMemory provided at each dispatch call.
//
// Design:
//   - Builds EXCEPTION_RECORD + CONTEXT on the guest stack for fidelity
//   - Walks VEH list and SEH chain for behavioral analysis
//   - Does NOT re-enter the CPU loop to execute handlers; instead uses
//     heuristics for common anti-debug patterns (VEH for INT3 / single-step)
//   - Caps all chain walks and handler counts to prevent runaway loops
//   - Tracks abuse indicators as behavioral IOCs

class ExceptionDispatcher {
public:
    ExceptionDispatcher() noexcept;
    ~ExceptionDispatcher() noexcept;

    // Non-copyable (owns implementation state)
    ExceptionDispatcher(const ExceptionDispatcher&) = delete;
    ExceptionDispatcher& operator=(const ExceptionDispatcher&) = delete;

    // Movable
    ExceptionDispatcher(ExceptionDispatcher&&) noexcept;
    ExceptionDispatcher& operator=(ExceptionDispatcher&&) noexcept;

    // === VEH Management ===

    // Register a Vectored Exception Handler at a guest code address.
    // If `first` is true, the handler is inserted at the front of the list.
    void AddVEH(GuestAddress handler, bool first) noexcept;

    // Remove a previously registered VEH handler.
    void RemoveVEH(GuestAddress handler) noexcept;

    // === Exception Dispatch ===

    // Dispatch an exception through the VEH → SEH chain.
    // Builds guest-space records, walks handlers for analysis, and returns
    // true if the exception was (heuristically) handled, false if unhandled.
    [[nodiscard]] bool DispatchException(
        CPUState& cpu, VirtualMemory& mem,
        uint32_t exceptionCode, GuestAddress faultAddress,
        bool isContinuable, uint32_t numParams = 0,
        const uint64_t* params = nullptr) noexcept;

    // Dispatch from an emulator ErrorCode.
    // Maps the ErrorCode to the appropriate NT exception code and parameters,
    // then delegates to DispatchException.
    [[nodiscard]] bool DispatchFromError(
        CPUState& cpu, VirtualMemory& mem,
        ErrorCode error, GuestAddress faultAddress) noexcept;

    // === Diagnostics ===

    [[nodiscard]] uint32_t GetExceptionsDispatched() const noexcept;

    // Walk the SEH chain in guest memory and return its depth.
    [[nodiscard]] uint32_t GetSEHChainDepth(CPUState& cpu, VirtualMemory& mem) const noexcept;

    // Returns true if any SEH/VEH abuse pattern has been detected.
    [[nodiscard]] bool DetectedSEHAbuse() const noexcept;

    // Reset all state (VEH list, counters, abuse flags).
    void Reset() noexcept;

    // ========================================================================
    // Windows NT Exception Codes (self-contained — no windows.h)
    // ========================================================================

    static constexpr uint32_t EXCEPTION_ACCESS_VIOLATION     = 0xC0000005;
    static constexpr uint32_t EXCEPTION_BREAKPOINT           = 0x80000003;
    static constexpr uint32_t EXCEPTION_SINGLE_STEP          = 0x80000004;
    static constexpr uint32_t EXCEPTION_INT_DIVIDE_BY_ZERO   = 0xC0000094;
    static constexpr uint32_t EXCEPTION_STACK_OVERFLOW       = 0xC00000FD;
    static constexpr uint32_t EXCEPTION_GUARD_PAGE           = 0x80000001;
    static constexpr uint32_t EXCEPTION_PRIV_INSTRUCTION     = 0xC0000096;
    static constexpr uint32_t EXCEPTION_ILLEGAL_INSTRUCTION  = 0xC000001D;
    static constexpr uint32_t EXCEPTION_NONCONTINUABLE       = 0xC0000025;
    static constexpr uint32_t EXCEPTION_INT_OVERFLOW         = 0xC0000095;

    // ========================================================================
    // Handler Disposition Return Values
    // ========================================================================

    static constexpr int32_t EXCEPTION_CONTINUE_EXECUTION = -1;
    static constexpr int32_t EXCEPTION_CONTINUE_SEARCH    =  0;
    static constexpr int32_t EXCEPTION_EXECUTE_HANDLER    =  1;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
