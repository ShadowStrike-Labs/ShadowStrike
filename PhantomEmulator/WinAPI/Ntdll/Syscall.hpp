/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Syscall.hpp — NT syscall dispatch and direct-syscall detection
 *
 * Maps syscall numbers (EAX at SYSCALL/SYSENTER/INT 0x2E) to the same
 * handler functions used by the named Nt* API hooks.  Detects when a
 * syscall originates from outside the emulated ntdll code region — a
 * hallmark of direct-syscall toolkits (Cobalt Strike, Brute Ratel,
 * Sliver, SysWhispers, etc.) that bypass usermode API hooks.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace Phantom {

class APIDispatcher;
class VirtualMemory;
class CPUState;
class HandleTable;

namespace WinAPI::Ntdll {

// ============================================================================
// SyscallDispatcher — Syscall-number-to-handler routing + detection
// ============================================================================

class SyscallDispatcher {
public:
    SyscallDispatcher() noexcept;

    void Initialize(APIDispatcher& dispatcher) noexcept;

    [[nodiscard]] bool Dispatch(CPUState& cpu, VirtualMemory& mem,
                                HandleTable& handles, const EmulationConfig& config,
                                ThreadLocalState& tls) noexcept;

    [[nodiscard]] bool IsKnown(uint32_t syscallNumber) const noexcept;

    [[nodiscard]] uint32_t GetTotalSyscalls()     const noexcept;
    [[nodiscard]] uint32_t GetUnknownSyscalls()   const noexcept;
    [[nodiscard]] uint32_t GetDirectSyscallCount() const noexcept;

    [[nodiscard]] const std::vector<uint32_t>& GetUnknownNumbers() const noexcept;

    // Write byte-exact x64/x86 ntdll syscall stubs into guest memory.
    // Returns the total number of bytes written.
    [[nodiscard]] uint32_t WriteSyscallStubs(VirtualMemory& mem,
                                             GuestAddress ntdllBase) noexcept;

    void SetNtdllRegion(GuestAddress base, GuestSize size) noexcept;

    static constexpr uint32_t kMaxSyscallNumber = 512;
    static constexpr uint32_t kStubSizeX64      = 24;
    static constexpr uint32_t kStubSizeX86      = 16;

private:
    std::array<APIHandlerFn, kMaxSyscallNumber> m_handlers{};

    uint32_t m_totalCalls   = 0;
    uint32_t m_unknownCalls = 0;
    uint32_t m_directCalls  = 0;

    std::vector<uint32_t> m_unknownNumbers;
    static constexpr uint32_t kMaxUnknownTracked = 256;

    [[nodiscard]] bool IsFromNtdll(GuestAddress returnAddr) const noexcept;

    GuestAddress m_ntdllBase = 0;
    GuestSize    m_ntdllSize = 0;
};

// Free-standing registration helper (matches NtMemory / NtFile pattern).
void RegisterSyscall(APIDispatcher& dispatcher) noexcept;

} // namespace WinAPI::Ntdll
} // namespace Phantom
